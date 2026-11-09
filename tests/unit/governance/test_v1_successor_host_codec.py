"""Isolated, credential-free codec regressions; runtime seams are nonaccepting.

Each child uses the exact immutable legacy guard and actual stdlib codec source.
Only fixed runtime/path pins and the bootstrap flag are synthetic in these public
tests. They do not execute a launcher, use a key, or establish host acceptance.
"""

from __future__ import annotations

import importlib.machinery
import json
import subprocess
import sys
from pathlib import Path

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parents[3]
SITE = Path(jsonschema.__file__).resolve().parents[1]
IDNA_SPEC = importlib.machinery.PathFinder.find_spec("idna", [str(SITE)])

CHILD = r"""
import ast, codecs, encodings, hashlib, importlib.machinery, json, shutil, ssl, sys
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from importlib.machinery import ModuleSpec
from pathlib import Path
from types import ModuleType, SimpleNamespace
from threading import Barrier

root, site, idna_init, temporary, mode = sys.argv[1:]
root, site, temporary = Path(root), Path(site), Path(temporary)
sys.path.extend((str(root / "src"), str(root), str(site)))
from scripts import v1_successor_host as host

# Public, synthetic runtime seams; never a real bootstrap/acceptance claim.
source = temporary / "stdlib/Lib/encodings/idna.py"
source.parent.mkdir(parents=True)
source.write_bytes((Path(encodings.__path__[0]) / "idna.py").read_bytes())
original = source.read_bytes()
host._IDNA_CODEC_SOURCE = source
host._IDNA_CODEC_SIZE = len(original)
host._IDNA_CODEC_SHA256 = host.core.content_digest(original)
host._idna_runtime_matches = lambda: mode != "wrong-runtime"
assert "encodings.idna" not in sys.modules

collision = temporary / "collision-site"
(collision / "idna").mkdir(parents=True)
shutil.copyfile(idna_init, collision / "idna/__init__.py")
if mode == "sentinel-collision":
    # Host dependencies were imported before installing the synthetic guard.
    # Discard only optional third-party module entries in this isolated child,
    # then make any execution of the collision package observable and fatal.
    marker = temporary / "third-party-idna-executed"
    sentinel = (
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n"
        "raise AssertionError('third-party idna must not execute')\n"
    )
    (collision / "idna/__init__.py").write_text(sentinel, encoding="utf-8")
    for name in tuple(sys.modules):
        if name == "idna" or name.startswith("idna."):
            del sys.modules[name]
    sys.path.insert(0, str(collision))
legacy_source = (root / "scripts/v1_s1_governance.py").read_bytes()
assert hashlib.sha256(legacy_source).hexdigest() == (
    "420546b238e775b6739b45e059e2857a56b4053a4a6bcef4cfc2d352d4162f0b"
)
tree = ast.parse(legacy_source)
guard_node = next(
    node for node in tree.body
    if isinstance(node, ast.ClassDef) and node.name == "_GovernanceRuntimeImportGuard"
)
imports = next(
    node.value for node in tree.body
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
    and node.target.id == "_RUNTIME_TOP_LEVEL_IMPORTS"
)
assert (
    isinstance(imports, ast.Call) and isinstance(imports.func, ast.Name)
    and imports.func.id == "frozenset"
)
namespace = {
    "__name__": "synthetic_exact_legacy_guard", "Path": Path, "ModuleSpec": ModuleSpec,
    "ModuleType": ModuleType, "Sequence": Sequence, "importlib": importlib,
    "_RUNTIME_TOP_LEVEL_IMPORTS": frozenset(ast.literal_eval(imports.args[0])),
}
exec(
    compile(
        ast.get_source_segment(legacy_source.decode(), guard_node),
        "<exact legacy guard>", "exec", dont_inherit=True,
    ),
    namespace,
)
guard_type = namespace["_GovernanceRuntimeImportGuard"]
guard = guard_type(collision)
legacy = SimpleNamespace(
    _main_has_active_runtime_bootstrap=lambda: mode != "wrong-bootstrap",
    _BOOTSTRAPPED_RUNTIME_GUARD=guard, _GovernanceRuntimeImportGuard=guard_type,
)
if mode == "preloaded-module":
    import encodings.idna
elif mode == "preloaded-parent":
    encodings.idna = object()
elif mode == "changed-source":
    source.write_bytes(original[:-1] + bytes((original[-1] ^ 1,)))
elif mode == "execution-failure":
    # Synthetic authenticated-source failure to exercise publication rollback.
    source.write_bytes(original + b"\nraise RuntimeError('synthetic codec execution failure')\n")
    host._IDNA_CODEC_SIZE = source.stat().st_size
    host._IDNA_CODEC_SHA256 = host.core.content_digest(source.read_bytes())
elif mode == "symlink":
    target = source.with_name("idna-real.py")
    source.rename(target)
    try:
        source.symlink_to(target)
    except OSError:
        print(json.dumps({"fixture_capability_unavailable":"symlink"}))
        raise SystemExit(76)

probe = importlib.machinery.PathFinder.find_spec("encodings.idna", [str(collision)])
assert probe is not None and Path(probe.origin) == collision / "idna/__init__.py"
sys.meta_path.insert(0, guard)
if mode == "guard-not-first":
    sys.meta_path.insert(0, object())
elif mode == "duplicate-guard":
    sys.meta_path.append(guard)
before = tuple(sys.meta_path)
try:
    if mode == "negative-cache":
        try:
            "api.github.com".encode("idna")
        except LookupError:
            pass
        else:
            raise AssertionError("exact legacy guard no longer reproduces the codec failure")
    if mode in {"positive", "changed-after-load", "concurrent", "sentinel-collision"}:
        try:
            guard.find_spec("encodings.idna", encodings.__path__)
        except ImportError:
            pass
        else:
            raise AssertionError("exact legacy guard collision did not reproduce")
        if mode == "concurrent":
            gate = Barrier(5)

            def prepare_once():
                gate.wait(timeout=10)
                host._prepare_authenticated_idna_codec(legacy)
                return sys.modules["encodings.idna"]

            with ThreadPoolExecutor(max_workers=4) as pool:
                # The main thread holds the real module RLock until all four
                # callers are ready. They must serialize one first publication.
                with host._IDNA_CODEC_LOCK:
                    futures = [pool.submit(prepare_once) for _ in range(4)]
                    gate.wait(timeout=10)
                    assert not any(future.done() for future in futures)
                loaded_modules = [future.result(timeout=20) for future in futures]
            assert all(module is loaded_modules[0] for module in loaded_modules)
        else:
            host._prepare_authenticated_idna_codec(legacy)
        loaded = sys.modules["encodings.idna"]
        if mode == "sentinel-collision":
            assert not marker.exists()
            assert not any(
                name == "idna" or name.startswith("idna.") for name in sys.modules
            )
        assert encodings.idna is loaded and loaded.__file__ == str(source)
        assert loaded.__cached__ is None
        assert "api.github.com".encode("idna") == b"api.github.com"
        assert "b\u00fccher.example".encode("idna") == b"xn--bcher-kva.example"
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        tls = context.wrap_bio(ssl.MemoryBIO(), ssl.MemoryBIO(), server_hostname="api.github.com")
        assert tls.server_hostname == "api.github.com"
        assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
        host._prepare_authenticated_idna_codec(legacy)
        assert sys.modules["encodings.idna"] is loaded
        if mode == "changed-after-load":
            source.write_bytes(original[:-1] + bytes((original[-1] ^ 1,)))
            try:
                host._prepare_authenticated_idna_codec(legacy)
            except host.HostError:
                pass
            else:
                raise AssertionError("changed source was admitted on reuse")
    else:
        try:
            host._prepare_authenticated_idna_codec(legacy)
        except host.HostError:
            pass
        else:
            raise AssertionError("invalid codec preparation was admitted")
        if mode not in {"preloaded-module", "preloaded-parent"}:
            assert "encodings.idna" not in sys.modules and "idna" not in vars(encodings)
    assert len(sys.meta_path) == len(before)
    assert all(current is previous for current, previous in zip(sys.meta_path, before, strict=True))
    assert not tuple((temporary / "stdlib").rglob("*.pyc"))
    print(json.dumps({
        "mode": mode, "result": "expected_nonaccepting_behavior", "guard_unchanged": True,
        "network_used": False, "credentials_used": False, "acceptance": "none",
    }))
finally:
    sys.meta_path[:] = [
        finder for finder in sys.meta_path
        if finder is not guard and hasattr(finder, "find_spec")
    ]
"""


@pytest.mark.parametrize(
    "mode",
    [
        "positive",
        "concurrent",
        "sentinel-collision",
        "changed-source",
        "changed-after-load",
        "execution-failure",
        "wrong-bootstrap",
        "wrong-runtime",
        "preloaded-module",
        "preloaded-parent",
        "negative-cache",
        "guard-not-first",
        "duplicate-guard",
        "symlink",
    ],
)
def test_authenticated_codec_under_exact_legacy_guard(tmp_path: Path, mode: str) -> None:
    assert IDNA_SPEC is not None and IDNA_SPEC.origin is not None
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            "-B",
            "-c",
            CHILD,
            str(ROOT),
            str(SITE),
            IDNA_SPEC.origin,
            str(tmp_path),
            mode,
        ],
        capture_output=True,
        check=False,
        timeout=45,
    )
    if mode == "symlink" and completed.returncode == 76:
        pytest.skip("Host does not permit creating the synthetic symlink fixture")
    assert completed.returncode == 0, (completed.stdout, completed.stderr)
    assert json.loads(completed.stdout) == {
        "mode": mode,
        "result": "expected_nonaccepting_behavior",
        "guard_unchanged": True,
        "network_used": False,
        "credentials_used": False,
        "acceptance": "none",
    }
