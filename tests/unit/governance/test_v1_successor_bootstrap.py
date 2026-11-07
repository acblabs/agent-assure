"""Bootstrap boundary tests, with explicit test-only signature verification seams.

The loader tests run in isolated subprocesses and execute the actual legacy
loader against tiny synthetic approved modules. They do not claim a frozen
runtime or real maintainer approval; real SSHSIG behavior is covered by the
ephemeral-key I/O tests. No test imports a candidate module before approval.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import v1_s1_governance as legacy  # noqa: E402, I001


LOADER_PROGRAM = r"""
import builtins
import importlib.util
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

source, root, scenario = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
# A governed full-suite subprocess may use the independent frozen base Python.
# Admit the test's authenticated dependency tree explicitly, never repo source.
site = source.parent.parent / ".venv" / "Lib" / "site-packages"
if site.is_dir() and str(site) not in sys.path:
    sys.path.append(str(site))
spec = importlib.util.spec_from_file_location("legacy_under_bootstrap_test", source)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
events = []
builtins._bootstrap_test_events = events
fixed = {path for _, path in module._SUCCESSOR_MODULE_FILES} | {
    "scripts/v1_s1_governance.py", "scripts/v1_s1_governance.ps1",
    "docs/governance/v1/sprint2/s1-successor-acceptance.schema.json",
    "docs/governance/v1/sprint2/s1-successor-host.schema.json",
    "docs/governance/v1/sprint2/delivery-forecast.schema.json",
    *("docs/governance/v1/delivery-forecast." + name for name in (
        "aggregation-registry.json", "aggregation-registry.schema.json",
        "estimation-catalog.json", "estimation-catalog.schema.json")),
    "scripts/v1_architecture_governance.py",
    *("docs/governance/v1/sprint2/" + name + ".schema.json"
      for name in ("architecture-package", "support-policy", "s1-successor-protocol",
                   "wire-contract-inventory", "occurrence-graph-expectations")),
}
source_by_path = {}
for name, path in module._SUCCESSOR_MODULE_FILES:
    code = "import builtins\nbuiltins._bootstrap_test_events.append('exec:' + __name__)\n"
    if path == module._SUCCESSOR_MODULE_FILES[0][1] and scenario == "cached-bytecode":
        code += "builtins._bootstrap_test_mutate()\n"
    source_by_path[path] = code.encode()
for path in sorted(fixed):
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(source_by_path.get(path, b"{}\n"))
rows = [{"path": path, "size_bytes": len((root/path).read_bytes()),
         "sha256": module.raw_digest((root/path).read_bytes())} for path in sorted(fixed)]
now = datetime.now(UTC)
trust = {"person_id": "acblabs", "public_key": module.MAINTAINER_PUBLIC_KEY,
         "key_id": module.MAINTAINER_KEY_FINGERPRINT,
         "mode": "maintainer_development", "independence": "NO_INDEPENDENT_REVIEW",
         "competence_scopes": ["planning_governance:s1_successor", "schema_compatibility"],
         "valid_from_utc": (now - timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
         "valid_until_utc": (now + timedelta(days=1)).isoformat().replace("+00:00", "Z")}
claim = {"format": "agent-assure-s1-successor-host-bootstrap/3",
         "implementation_inventory": rows, "trust": trust}
envelope = {"profile": "openssh-sshsig-ed25519/v1", "namespace": module.SIGNATURE_NAMESPACE,
            "signer_person_id": "acblabs", "key_id": module.MAINTAINER_KEY_FINGERPRINT,
            "signature": "test-only-verifier-seam"}
document = {"claim": claim, "signature_envelope": envelope}
if scenario == "unknown-inventory":
    rows[-1] = {**rows[-1], "path": "scripts/unrecognized.py"}
elif scenario == "duplicate-inventory":
    rows[-1] = dict(rows[0])
elif scenario == "missing-inventory":
    rows.pop()
elif scenario == "boolean-size":
    rows[-1]["size_bytes"] = True
elif scenario == "extra-row-field":
    rows[-1]["authenticated"] = True
elif scenario == "late-file-tamper":
    (root / rows[-1]["path"]).write_bytes(b"changed after claim\n")
elif scenario == "root-person":
    envelope["signer_person_id"] = "attacker"
elif scenario == "root-key":
    envelope["key_id"] = "attacker-key"
elif scenario == "namespace":
    envelope["namespace"] = "another-purpose"
elif scenario == "profile":
    envelope["profile"] = "unrecognized-signature"
elif scenario == "extra-signature-field":
    envelope["verified"] = True
elif scenario == "extra-document-field":
    document["verified"] = True
elif scenario == "trust-future":
    trust["valid_from_utc"] = (now + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
elif scenario == "trust-expired":
    trust["valid_until_utc"] = (now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z")
elif scenario == "trust-excessive":
    trust["valid_until_utc"] = (now + timedelta(days=31)).isoformat().replace("+00:00", "Z")
elif scenario == "trust-person":
    trust["person_id"] = "attacker"
elif scenario == "trust-key":
    trust["public_key"] = "unapproved-key"
elif scenario == "trust-fingerprint":
    trust["key_id"] = "wrong-fingerprint"
elif scenario == "trust-mode":
    trust["mode"] = "qualified_admission"
elif scenario == "trust-independence":
    trust["independence"] = "fabricated_independent_review"
elif scenario == "trust-missing-competence":
    trust["competence_scopes"] = ["planning_governance:s1_successor"]

expected_payload = b"agent-assure:s1-successor-host-bootstrap/v3\0" + module.canonical_bytes(claim)
def test_only_signature_verifier(**arguments):
    # Exact arguments are checked; an imported JSON "verified" flag is never used.
    assert arguments == {"signature_base64": "test-only-verifier-seam",
                          "payload": expected_payload, "signer_person_id": "acblabs",
                          "public_key": module.MAINTAINER_PUBLIC_KEY}
    events.append("signature")
    if scenario == "invalid-signature":
        raise module.GovernanceError("test verifier rejected signature")
module._verify_sshsig = test_only_signature_verifier
original_read = module._successor_read_input
def recorded_read(*arguments):
    raw = original_read(*arguments)
    events.append("read:" + arguments[1])
    return raw
module._successor_read_input = recorded_read

def mutate_later_source():
    (root / module._SUCCESSOR_MODULE_FILES[-1][1]).write_bytes(
        b"raise RuntimeError('unverified reread executed')\n")
builtins._bootstrap_test_mutate = mutate_later_source
before_path = list(sys.path)
try:
    loaded = module._successor_load_modules(root, document)
except Exception as error:
    result = {"accepted": False, "error_type": type(error).__name__,
              "events": events, "path_unchanged": before_path == sys.path}
else:
    result = {"accepted": True, "events": events,
              "loaded_name": loaded.__name__, "path_unchanged": before_path == sys.path,
              "scripts_path": sys.modules["scripts"].__path__,
              "agent_assure_path": sys.modules["agent_assure"].__path__,
              "legacy_shared": sys.modules["scripts.v1_s1_governance"] is module,
              "module_files": [sys.modules[name].__file__
                               for name,_ in module._SUCCESSOR_MODULE_FILES],
              "fixed_count": len(fixed), "module_count": len(module._SUCCESSOR_MODULE_FILES)}
print(json.dumps(result))
"""


def run_loader(tmp_path: Path, scenario: str) -> dict[str, Any]:
    executable = sys.executable
    if getattr(subprocess, "_agent_assure_s1_post_r2_launch_guard", None) is not None:
        executable = str(legacy._FROZEN_PYTHON_EXECUTABLE)
    completed = subprocess.run(
        [
            executable,
            "-I",
            "-B",
            "-c",
            LOADER_PROGRAM,
            str(ROOT / "scripts/v1_s1_governance.py"),
            str(tmp_path),
            scenario,
        ],
        cwd=tmp_path,
        capture_output=True,
        check=False,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", errors="replace")
    assert not completed.stderr
    return json.loads(completed.stdout)


def test_fixed_modules_and_schemas_are_all_authenticated_before_any_execution(
    tmp_path: Path,
) -> None:
    result = run_loader(tmp_path, "valid")
    assert result["accepted"] is True
    events = result["events"]
    assert events[0] == "signature"
    first_exec = next(index for index, event in enumerate(events) if event.startswith("exec:"))
    assert len(events[1:first_exec]) == result["fixed_count"]
    assert all(event.startswith("read:") for event in events[1:first_exec])
    assert len(events[first_exec:]) == result["module_count"]
    assert all(event.startswith("exec:") for event in events[first_exec:])
    assert result["loaded_name"] == "scripts.v1_successor_host"
    assert result["path_unchanged"] is True
    assert result["scripts_path"] == result["agent_assure_path"] == []
    assert result["legacy_shared"] is True
    assert not list(tmp_path.rglob("*.pyc"))


@pytest.mark.parametrize(
    "scenario",
    [
        "unknown-inventory",
        "duplicate-inventory",
        "missing-inventory",
        "boolean-size",
        "extra-row-field",
        "late-file-tamper",
        "root-person",
        "root-key",
        "namespace",
        "profile",
        "extra-signature-field",
        "extra-document-field",
        "invalid-signature",
        "trust-future",
        "trust-expired",
        "trust-excessive",
        "trust-person",
        "trust-key",
        "trust-fingerprint",
        "trust-mode",
        "trust-independence",
        "trust-missing-competence",
    ],
)
def test_bad_root_or_any_inventory_binding_executes_no_candidate_code(
    tmp_path: Path,
    scenario: str,
) -> None:
    result = run_loader(tmp_path, scenario)
    assert result["accepted"] is False
    assert result["error_type"] == "GovernanceError"
    assert result["path_unchanged"] is True
    assert not any(event.startswith("exec:") for event in result["events"])
    if scenario in {
        "root-person",
        "root-key",
        "namespace",
        "profile",
        "extra-signature-field",
        "extra-document-field",
    }:
        assert result["events"] == []
    else:
        assert result["events"][0] == "signature"


def test_loader_executes_cached_verified_bytes_after_later_disk_mutation(tmp_path: Path) -> None:
    result = run_loader(tmp_path, "cached-bytecode")
    assert result["accepted"] is True
    assert result["events"][-1] == "exec:scripts.v1_successor_host"
    assert (
        (tmp_path / "scripts/v1_successor_host.py").read_bytes().startswith(b"raise RuntimeError")
    )
    assert result["path_unchanged"] is True


def test_bootstrap_input_exact_byte_limit_is_accepted_and_larger_input_rejected(
    tmp_path: Path,
) -> None:
    path = tmp_path / "bounded.json"
    payload = b"x" * (4 * 1024 * 1024)
    path.write_bytes(payload)
    assert legacy._successor_read_input(tmp_path, "bounded.json") == payload
    path.write_bytes(payload + b"x")
    with pytest.raises(legacy.GovernanceError, match="bounded regular"):
        legacy._successor_read_input(tmp_path, "bounded.json")


def test_bootstrap_input_replacement_between_validation_and_open_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "input.json"
    path.write_bytes(b"original")
    original_open = os.open
    switched = False

    def racing_open(candidate: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        nonlocal switched
        if Path(candidate) == path and not switched:
            switched = True
            path.rename(tmp_path / "original.json")
            path.write_bytes(b"replaced")
        return original_open(candidate, flags, *args, **kwargs)

    monkeypatch.setattr(legacy.os, "open", racing_open)
    with pytest.raises(legacy.GovernanceError, match="changed before opening"):
        legacy._successor_read_input(tmp_path, "input.json")
    assert switched


def test_bootstrap_input_symlink_swap_is_rejected_before_reading_external_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "input.json"
    target = tmp_path / "outside.json"
    path.write_bytes(b"original")
    target.write_bytes(b"outside private bytes")
    probe = tmp_path / "probe-link"
    try:
        probe.symlink_to(target)
    except OSError:
        pytest.skip("host does not permit test symlink creation")
    probe.unlink()
    original_open = os.open
    switched = False

    def racing_open(candidate: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        nonlocal switched
        if Path(candidate) == path and not switched:
            switched = True
            path.unlink()
            path.symlink_to(target)
        return original_open(candidate, flags, *args, **kwargs)

    monkeypatch.setattr(legacy.os, "open", racing_open)
    with pytest.raises((legacy.GovernanceError, OSError)):
        legacy._successor_read_input(tmp_path, "input.json")
    assert switched
    assert target.read_bytes() == b"outside private bytes"


@pytest.mark.parametrize(
    "relative", ["../escape.json", "/absolute.json", "C:/escape.json", "bad\\alias.json"]
)
def test_bootstrap_input_scope_cannot_escape_root(tmp_path: Path, relative: str) -> None:
    with pytest.raises((legacy.GovernanceError, ValueError, OSError)):
        legacy._successor_read_input(tmp_path, relative)


def test_successor_parser_is_connected_to_guarded_handler_without_token_values() -> None:
    args = legacy._parser().parse_args(
        [
            "successor",
            "--bootstrap",
            ".tmp/bootstrap.json",
            "--request",
            ".tmp/request.json",
            "--ci-token-environment",
            "SUCCESSOR_TEST_TOKEN",
        ]
    )
    assert args.handler is legacy.successor_host_command
    assert args.ci_token_environment == "SUCCESSOR_TEST_TOKEN"
    with pytest.raises(legacy.GovernanceError, match="frozen runtime"):
        args.handler(args)


def test_accepting_successor_main_rejects_unbootstrapped_direct_invocation(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert (
        legacy.main(
            ["successor", "--bootstrap", ".tmp/absent.json", "--request", ".tmp/absent.json"]
        )
        == 2
    )
    assert "require successful frozen runtime bootstrap" in capsys.readouterr().err
