"""Check-collector boundaries; synthetic execution is not host acceptance proof."""

from __future__ import annotations

import ast
import ctypes
import json
import os
import subprocess
import sys
import time
from contextlib import ExitStack
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import rfc8785

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import v1_successor_checks as checks  # noqa: E402

OID = "a" * 40
DIGEST = "sha256:" + "a" * 64
SIMPLE_BOOTSTRAP = (
    "exec("
    + repr(
        'import runpy,sys\nverified_inventory = "retained"\n'
        'sys.argv = ["pytest", *pytest_arguments]\n'
        'runpy.run_module("pytest", run_name="__main__", alter_sys=True)\n'
    )
    + ")"
)


def _program(payload: bytes) -> ast.Module:
    wrapper = ast.parse(payload.decode())
    expression = wrapper.body[0]
    assert isinstance(expression, ast.Expr) and isinstance(expression.value, ast.Call)
    argument = expression.value.args[0]
    assert isinstance(argument, ast.Constant) and type(argument.value) is str
    return ast.parse(argument.value)


def test_expansion_runs_every_make_check_without_source_mutation() -> None:
    rows = checks.make_check_expansion()
    ids = [row.check_id for row in rows]
    assert len(ids) == len(set(ids))
    assert {
        "ruff-check",
        "ruff-format",
        "mypy",
        "dependency-locks",
        "docs-alignment",
        "claim-boundary",
        "examples-parity",
        "reproduction-index",
        "build",
        "schema-force-includes",
        "frozen-schemas",
        "tagged-schema-immutability",
        "schema-staging",
        "architecture-draft",
        "successor-specific",
    } == set(ids)
    assert all((row.module is None) != (row.script is None) for row in rows)
    assert all("--write" not in row.arguments for row in rows)
    build = next(row for row in rows if row.check_id == "build")
    assert "--no-isolation" in build.arguments and "{generated}/build" in build.arguments
    assert not any("clean_dist" in (row.script or "") for row in rows)


@pytest.mark.parametrize("spec", checks.make_check_expansion(), ids=lambda spec: spec.check_id)
def test_ast_transform_preserves_every_pre_dispatch_statement(spec: checks.CheckSpec) -> None:
    transformed = checks.transform_bootstrap(SIMPLE_BOOTSTRAP, spec, ("fixed-argument",))
    before = _program(SIMPLE_BOOTSTRAP.encode())
    after = _program(transformed)
    assert [ast.dump(node) for node in before.body[:-2]] == [
        ast.dump(node) for node in after.body[: len(before.body) - 2]
    ]
    assert len(after.body) == len(before.body) + (5 if spec.module == "ruff" else 0)
    assignment = after.body[-2]
    assert isinstance(assignment, ast.Assign)
    assert isinstance(assignment.value, ast.List)
    assert assignment.value.elts[1].value == "fixed-argument"  # type: ignore[attr-defined]
    dispatch = after.body[-1]
    assert isinstance(dispatch, ast.Expr) and isinstance(dispatch.value, ast.Call)
    assert isinstance(dispatch.value.func, ast.Attribute)
    assert dispatch.value.func.attr == ("run_module" if spec.module else "run_path")


@pytest.mark.parametrize(
    "payload",
    [
        "print('not a verifier')",
        "exec('x=1');exec('y=2')",
        "exec(code)",
        "exec(source='text')",
        "__import__('os').system('bad')",
        "exec(3)",
    ],
)
def test_nonconstant_or_multi_statement_wrapper_is_rejected(payload: str) -> None:
    with pytest.raises(checks.CheckError):
        checks.transform_bootstrap(payload, checks.make_check_expansion()[0], ())


@pytest.mark.parametrize(
    "tail",
    [
        'sys.argv=["pytest",*pytest_arguments]\nrunpy.run_module("other",run_name="__main__",alter_sys=True)',
        'sys.argv=["pytest",*pytest_arguments]\nrunpy.run_module("pytest",run_name="__main__")',
        'sys.argv=["pytest",*pytest_arguments]\nrunpy.run_module("pytest",run_name="__main__",alter_sys=True)\nextra=1',
        'sys.argv=["pytest",*other_arguments]\nrunpy.run_module("pytest",run_name="__main__",alter_sys=True)',
    ],
)
def test_upstream_dispatch_drift_blocks_execution(tail: str) -> None:
    with pytest.raises(checks.CheckError, match="dispatch changed"):
        checks.transform_bootstrap("exec(" + repr(tail) + ")", checks.make_check_expansion()[0], ())


def test_no_arbitrary_module_or_script_is_admitted() -> None:
    for spec in (
        checks.CheckSpec("x", "os", None, ()),
        checks.CheckSpec("ruff-check", "ruff", None, ("--config", "attacker.toml")),
    ):
        with pytest.raises(checks.CheckError, match="outside"):
            checks.transform_bootstrap(SIMPLE_BOOTSTRAP, spec, ())


def test_actual_authenticated_bootstrap_has_the_expected_dispatch_shape(tmp_path: Path) -> None:
    from scripts import v1_s1_governance as legacy

    encoded = legacy._post_r2_pytest_bootstrap_source(
        tmp_path, basetemp=tmp_path / "process/pytest", process_temp=tmp_path / "process"
    )
    transformed = checks.transform_bootstrap(encoded, checks.make_check_expansion()[0], ())
    original, result = _program(encoded.encode()), _program(transformed)
    assert len(original.body) > 50
    assert [ast.dump(node) for node in original.body[:-2]] == [
        ast.dump(node) for node in result.body[: len(original.body) - 2]
    ]


def test_successor_pytest_recipe_enforces_socket_guard_without_plugin_autoload(
    tmp_path: Path,
) -> None:
    import pytest_socket

    # Isolated Python receives only the same installed test packages as this
    # process. No site initialization, entry-point autoload or inherited pytest
    # settings can supply a plugin omitted from the registered recipe.
    packages = Path(pytest.__file__).resolve().parent.parent
    assert Path(pytest_socket.__file__).resolve().is_relative_to(packages)
    project = tmp_path / "recipe-project"
    project.mkdir()
    (project / "pyproject.toml").write_text("[tool.pytest.ini_options]\n", encoding="utf-8")
    guarded_test = (
        "import os, socket\n"
        "import pytest\n"
        "from pytest_socket import SocketBlockedError\n"
        "def test_socket_constructor_is_blocked():\n"
        "    assert os.environ['PYTEST_DISABLE_PLUGIN_AUTOLOAD'] == '1'\n"
        "    assert 'PYTEST_PLUGINS' not in os.environ\n"
        "    assert 'PYTEST_ADDOPTS' not in os.environ\n"
        "    with pytest.raises(SocketBlockedError):\n"
        "        socket.socket()\n"
    )
    for relative in (
        "tests/unit/governance/test_socket_guard.py",
        "tests/integration/test_v1_s1_historical_check.py",
    ):
        target = project / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(guarded_test, encoding="utf-8")
    spec = next(
        row for row in checks.make_check_expansion() if row.check_id == "successor-specific"
    )
    # The original dispatch loads the plugin; transform_bootstrap replaces the
    # entire argv. The replacement must retain its own explicit plugin loading.
    encoded = (
        "exec("
        + repr(
            "import runpy,sys\n"
            f"sys.path.append({str(packages)!r})\n"
            "pytest_arguments = ['-p', 'pytest_socket']\n"
            'sys.argv = ["pytest", *pytest_arguments]\n'
            'runpy.run_module("pytest", run_name="__main__", alter_sys=True)\n'
        )
        + ")"
    )
    environment = {
        key: os.environ[key]
        for key in ("SYSTEMROOT", "WINDIR", "SYSTEMDRIVE", "TEMP", "TMP")
        if key in os.environ
    }
    environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    for missing_plugin in (True, False):
        arguments = list(spec.arguments)
        if missing_plugin:
            for index in range(len(arguments) - 1):
                if arguments[index : index + 2] == ["-p", "pytest_socket"]:
                    del arguments[index : index + 2]
                    break
        label = "missing-plugin" if missing_plugin else "registered-recipe"
        arguments = [
            value.format(root=str(project), basetemp=str(tmp_path / (label + "-pytest")))
            for value in arguments
        ]
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                "-B",
                "-X",
                "pycache_prefix=" + str(tmp_path / (label + "-cache")),
                "-",
            ],
            input=checks.transform_bootstrap(encoded, spec, arguments),
            cwd=project,
            env=environment,
            capture_output=True,
            timeout=30,
            check=False,
        )
        if missing_plugin:
            assert result.returncode == 4, (result.stdout, result.stderr)
            assert b"unrecognized arguments: --disable-socket" in result.stderr
        else:
            assert result.returncode == 0, (result.stdout, result.stderr)
            assert b"2 passed" in result.stdout


class SuccessfulBackend:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def execute(self, spec: checks.CheckSpec) -> checks.CommandResult:
        self.calls.append(spec.check_id)
        moment = datetime(2026, 11, 7, tzinfo=UTC) + timedelta(seconds=len(self.calls))
        stamp = moment.isoformat().replace("+00:00", "Z")
        return checks.CommandResult(
            spec.check_id,
            stamp,
            stamp,
            0,
            b"ok\n",
            b"",
            {"spec": checks._spec_record(spec), "authenticated": "synthetic-test"},
        )


def test_collection_retains_every_raw_stream_and_binds_native_capture() -> None:
    backend = SuccessfulBackend()
    result = checks.collect_local_checks(
        backend,
        native_v4_evidence_digest=DIGEST,
        makefile_digest=DIGEST,
        canonical_bytes=rfc8785.dumps,
    )
    assert backend.calls == [row.check_id for row in checks.make_check_expansion()]
    assert len(result.raw_streams) == len(backend.calls) * 2
    assert {row["id"] for row in result.payload["checks"]} == {
        "make check schema-check",
        "successor_specific_unit_and_integration_checks",
    }
    assert result.child_records[-1]["native_v4_evidence_digest"] == DIGEST
    assert rfc8785.dumps(result.child_records[-1])  # No self-referential aggregate graph.
    assert all(row["exit_code"] == 0 for row in result.payload["checks"])
    records = {name: value for name, value in result.raw_streams}
    for row in result.child_records[:-1]:
        for stream in ("stdout", "stderr"):
            metadata = row[stream]
            assert checks._digest(records[metadata["file_name"]]) == metadata["sha256"]


def test_failures_retain_diagnostics_without_passing_payload() -> None:
    class Failed(SuccessfulBackend):
        def execute(self, spec: checks.CheckSpec) -> checks.CommandResult:
            result = super().execute(spec)
            return checks.CommandResult(
                result.check_id,
                result.started_at_utc,
                result.completed_at_utc,
                1,
                b"failure\n",
                b"diagnostic",
                result.command_record,
            )

    with pytest.raises(checks.LocalCheckFailure) as caught:
        checks.collect_local_checks(
            Failed(),
            native_v4_evidence_digest=DIGEST,
            makefile_digest=DIGEST,
            canonical_bytes=rfc8785.dumps,
        )
    assert len(caught.value.child_records) == 1
    assert caught.value.child_records[0]["exit_code"] == 1
    assert caught.value.raw_streams[0][1] == b"failure\n"
    assert not hasattr(caught.value, "payload")


@pytest.mark.parametrize(
    "mutation", ["reverse-time", "nonutc-time", "wrong-recipe", "bool-exit", "oversized"]
)
def test_backend_cannot_substitute_chronology_recipe_or_work_limits(mutation: str) -> None:
    class Mutated(SuccessfulBackend):
        def execute(self, spec: checks.CheckSpec) -> checks.CommandResult:
            result = super().execute(spec)
            values = dict(result.__dict__)
            if mutation == "reverse-time":
                values["completed_at_utc"] = "2026-11-06T00:00:00Z"
            elif mutation == "nonutc-time":
                values["started_at_utc"] = "2026-11-07T00:00:00+00:00"
            elif mutation == "wrong-recipe":
                values["command_record"] = {"spec": {"id": spec.check_id}}
            elif mutation == "bool-exit":
                values["exit_code"] = False
            else:
                values["stdout"] = b"x" * (spec.max_stream_bytes + 1)
            return checks.CommandResult(**values)

    with pytest.raises(checks.CheckError):
        checks.collect_local_checks(
            Mutated(),
            native_v4_evidence_digest=DIGEST,
            makefile_digest=DIGEST,
            canonical_bytes=rfc8785.dumps,
        )


@pytest.mark.parametrize("digest", ["", "sha256:abc", "a" * 64, DIGEST + "\n"])
def test_unbound_native_or_makefile_reference_rejected(digest: str) -> None:
    backend = SuccessfulBackend()
    with pytest.raises(checks.CheckError):
        checks.collect_local_checks(
            backend,
            native_v4_evidence_digest=digest,
            makefile_digest=DIGEST,
            canonical_bytes=rfc8785.dumps,
        )
    with pytest.raises(checks.CheckError):
        checks.collect_local_checks(
            backend,
            native_v4_evidence_digest=DIGEST,
            makefile_digest=digest,
            canonical_bytes=rfc8785.dumps,
        )
    assert not backend.calls


def test_changed_makefile_changes_the_human_adopted_expansion_identity() -> None:
    first = checks.expansion_projection(DIGEST)
    second = checks.expansion_projection("sha256:" + "b" * 64)
    assert first["commands"] == second["commands"]
    assert checks._digest(rfc8785.dumps(first)) != checks._digest(rfc8785.dumps(second))


def test_current_default_makefile_matches_independent_check_expansion() -> None:
    payload = (ROOT / "Makefile").read_bytes()
    assert checks.validate_makefile_projection(payload) == checks._digest(payload)


@pytest.mark.parametrize(
    "mutation", ["new-dependency", "dropped-command", "duplicate", "include", "oneshell"]
)
def test_makefile_cannot_silently_change_the_execution_graph(mutation: str) -> None:
    payload = (ROOT / "Makefile").read_bytes()
    if mutation == "new-dependency":
        payload = payload.replace(
            b"check: lint type", b"check: new-unexecuted-control lint type", 1
        )
    elif mutation == "dropped-command":
        payload = payload.replace(b"\t$(PYTHON) scripts/check_frozen_schemas.py\n", b"", 1)
    elif mutation == "duplicate":
        payload += b"\ncheck: weakened\n"
    elif mutation == "include":
        payload += b"\ninclude .tmp/unreviewed.mk\n"
    else:
        payload += b"\n.ONESHELL:\n"
    with pytest.raises(checks.CheckError):
        checks.validate_makefile_projection(payload)


def test_frozen_backend_refuses_ordinary_developer_execution(tmp_path: Path) -> None:
    class Ordinary:
        @staticmethod
        def _main_has_active_runtime_bootstrap() -> bool:
            return False

    with pytest.raises(checks.CheckError, match="frozen"):
        checks.FrozenCheckBackend(Ordinary(), tmp_path, OID, tmp_path / "output")
    assert not (tmp_path / "output").exists()


class FakeLegacy:
    """Trusted low-level seam only; cannot establish production host authority."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.clean = True
        self.surface_version = 0
        self.runtime_version = 0
        self.calls: list[str] = []

    def _main_has_active_runtime_bootstrap(self) -> bool:
        return True

    def _resolve_repository_path_without_links(
        self, root: Path, value: Path, *, owner: str
    ) -> Path:
        assert root == self.root and owner
        return value.resolve()

    def _post_v2_control_git_metadata_preflight(self, root: Path) -> None:
        assert root == self.root
        self.calls.append("metadata")

    def _post_v2_control_repository_state(self, root: Path) -> dict[str, Any]:
        assert root == self.root
        return {"head_commit": OID, "clean": self.clean}

    def _post_r2_test_surface_evidence(
        self, root: Path, *, result_commit: str, legacy_v3_policy: bool
    ) -> dict[str, Any]:
        assert root == self.root and result_commit == OID
        assert legacy_v3_policy is False
        return {"format": "agent-assure-s1-post-r2-test-surface/2", "version": self.surface_version}

    def _post_r2_test_runtime_evidence(self, root: Path) -> dict[str, Any]:
        assert root == self.root
        return {"version": self.runtime_version}

    def _read_commit_blob(self, root: Path, commit: str, path: str, *, owner: str) -> bytes:
        assert root == self.root and commit == OID and path == "Makefile"
        assert owner == "successor reviewed Makefile"
        return (ROOT / "Makefile").read_bytes()

    def _allocate_post_r2_run_paths(self, root: Path) -> tuple[Path, Path]:
        assert root == self.root
        process = root / ".tmp/process"
        process.mkdir(parents=True)
        return process / "pytest", process

    def _prepare_post_r2_descendant_runtime(self, root: Path, **kwargs: Any) -> dict[str, Any]:
        assert root == self.root and kwargs
        self.calls.append("prepare")
        return {"descendant": "fixture"}

    def _post_r2_pytest_bootstrap_source(self, root: Path, **kwargs: Any) -> str:
        assert root == self.root and kwargs
        return SIMPLE_BOOTSTRAP

    def _post_r2_pytest_argv(self, root: Path, **kwargs: Any) -> list[str]:
        assert root == self.root and kwargs
        return [sys.executable, "-I", "-S", "-B", "-"]

    def _post_r2_subprocess_environment(
        self, root: Path, basetemp: Path, **kwargs: Any
    ) -> dict[str, str]:
        assert root == self.root and basetemp and kwargs
        return {"PATH": "synthetic"}

    def _verify_post_r2_descendant_runtime(self, root: Path, **kwargs: Any) -> dict[str, Any]:
        assert root == self.root and kwargs
        self.calls.append("verify-runtime")
        return {"descendant": "fixture"}

    def _cleanup_post_r2_process_temp(self, process: Path) -> None:
        assert process.parent == self.root / ".tmp"
        self.calls.append("cleanup")
        process.rmdir()


@pytest.fixture
def native_ruff_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    binary = tmp_path / ".venv/Scripts/ruff.exe"
    binary.parent.mkdir(parents=True)
    raw = b"synthetic test-only pinned executable bytes"
    binary.write_bytes(raw)
    monkeypatch.setattr(
        checks,
        "RUFF_BINARY_IDENTITY",
        {
            "relative_path": ".venv/Scripts/ruff.exe",
            "size_bytes": len(raw),
            "sha256": checks._digest(raw),
        },
    )
    return binary


def test_actual_backend_runs_bound_bootstrap_and_rechecks_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_ruff_fixture: Path
) -> None:
    legacy = FakeLegacy(tmp_path)
    seen: list[dict[str, Any]] = []

    def execute(argv: Any, **kwargs: Any) -> tuple[int, bytes, bytes]:
        seen.append({"argv": argv, **kwargs})
        return 0, b"real-recipe", b""

    monkeypatch.setattr(checks, "run_bounded", execute)
    backend = checks.FrozenCheckBackend(
        legacy, tmp_path, OID, tmp_path / ".tmp/s1-acceptance/v3-checks-fixture"
    )
    result = backend.execute(checks.make_check_expansion()[0])
    assert result.stdout == b"real-recipe"
    assert result.command_record["native_tool"] == checks.RUFF_BINARY_IDENTITY
    assert native_ruff_fixture.is_file()
    assert len(seen) == 1 and b"run_module('ruff'" in seen[0]["payload"]
    assert legacy.calls.count("verify-runtime") == 2 and legacy.calls[-1] == "cleanup"
    with pytest.raises(checks.CheckError, match="reuse"):
        backend.execute(checks.make_check_expansion()[0])


@pytest.mark.parametrize("change", ["surface", "runtime", "clean"])
def test_backend_never_accepts_changed_source_or_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str, native_ruff_fixture: Path
) -> None:
    legacy = FakeLegacy(tmp_path)

    def execute(*args: Any, **kwargs: Any) -> tuple[int, bytes, bytes]:
        if change == "surface":
            legacy.surface_version += 1
        elif change == "runtime":
            legacy.runtime_version += 1
        else:
            legacy.clean = False
        return 0, b"producer said success", b""

    monkeypatch.setattr(checks, "run_bounded", execute)
    backend = checks.FrozenCheckBackend(
        legacy, tmp_path, OID, tmp_path / ".tmp/s1-acceptance/v3-checks-fixture"
    )
    with pytest.raises(checks.CheckError):
        backend.execute(checks.make_check_expansion()[0])
    assert legacy.calls[-1] == "cleanup"


def test_native_binary_identity_is_human_reviewed_and_authenticates_exact_bytes(
    tmp_path: Path, native_ruff_fixture: Path
) -> None:
    assert checks.expansion_projection(DIGEST)["native_tool_identities"] == {
        "ruff": checks.RUFF_BINARY_IDENTITY
    }
    assert checks.validate_ruff_binary(tmp_path) == checks.RUFF_BINARY_IDENTITY
    native_ruff_fixture.write_bytes(b"x" * native_ruff_fixture.stat().st_size)
    with pytest.raises(checks.CheckError, match="byte identity"):
        checks.validate_ruff_binary(tmp_path)


def test_changed_native_binary_stops_before_any_check_execution(
    tmp_path: Path, native_ruff_fixture: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = checks.FrozenCheckBackend(
        FakeLegacy(tmp_path), tmp_path, OID, tmp_path / ".tmp/s1-acceptance/v3-checks-fixture"
    )
    native_ruff_fixture.write_bytes(b"changed")

    def unexpected(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("unverified Ruff binary reached child execution")

    monkeypatch.setattr(checks, "run_bounded", unexpected)
    with pytest.raises(checks.CheckError):
        backend.execute(checks.make_check_expansion()[0])


def test_native_tool_lease_prevents_windows_replacement_during_execution(
    tmp_path: Path, native_ruff_fixture: Path
) -> None:
    with ExitStack() as leases:
        checks.validate_ruff_binary(tmp_path, leases=leases)
        if os.name == "nt":
            with pytest.raises(PermissionError):
                native_ruff_fixture.write_bytes(b"replacement")
            with pytest.raises(PermissionError):
                native_ruff_fixture.unlink()
        checks.validate_ruff_binary(tmp_path, leases=leases)


@pytest.mark.parametrize("fallback", [False, True])
def test_ruff_dispatch_rejects_fallback_locations_and_fixes_verified_resolution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fallback: bool
) -> None:
    module = ModuleType("ruff")
    expected = tmp_path / str(checks.RUFF_BINARY_IDENTITY["relative_path"])
    calls: list[bool] = []

    def find() -> str:
        calls.append(True)
        return str(tmp_path / "untrusted/ruff.exe" if fallback or len(calls) > 1 else expected)

    module.find_ruff_bin = find  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "ruff", module)
    program = _program(
        checks.transform_bootstrap(SIMPLE_BOOTSTRAP, checks.make_check_expansion()[0], ())
    )
    guard = ast.Module(body=program.body[2:-2], type_ignores=[])
    namespace = {"repository_root": tmp_path}
    if fallback:
        with pytest.raises(RuntimeError, match="frozen binary identity"):
            exec(compile(guard, "reviewed-native-dispatch-guard", "exec"), namespace)
    else:
        exec(compile(guard, "reviewed-native-dispatch-guard", "exec"), namespace)
        assert module.find_ruff_bin() == str(expected)  # type: ignore[attr-defined]
        assert module.find_ruff_bin() == str(expected)  # type: ignore[attr-defined]
    assert calls == [True]


@pytest.mark.parametrize("timeout,cap", [(True, 1), (0, 1), (7201, 1), (1, True), (1, 0)])
def test_execution_limits_have_strict_integer_types(timeout: Any, cap: Any, tmp_path: Path) -> None:
    with pytest.raises(checks.CheckError, match="limits"):
        checks.run_bounded(
            [sys.executable],
            cwd=tmp_path,
            environment=os.environ,
            payload=b"",
            timeout_seconds=timeout,
            max_stream_bytes=cap,
        )


def test_absolute_executable_required(tmp_path: Path) -> None:
    with pytest.raises(checks.CheckError, match="absolute"):
        checks.run_bounded(
            ["python"],
            cwd=tmp_path,
            environment=os.environ,
            payload=b"",
            timeout_seconds=1,
            max_stream_bytes=1024,
        )


def test_real_bounded_process_returns_exact_streams(tmp_path: Path) -> None:
    code = "import sys;sys.stdout.buffer.write(b'abc');sys.stderr.buffer.write(b'xyz')"
    result = checks.run_bounded(
        [sys.executable, "-B", "-c", code],
        cwd=tmp_path,
        environment=os.environ,
        payload=b"",
        timeout_seconds=10,
        max_stream_bytes=1024,
    )
    assert result == (0, b"abc", b"xyz")


def test_real_output_limit_is_nonpassing_and_preserves_bounded_prefix(tmp_path: Path) -> None:
    with pytest.raises(checks.ProcessLimitError) as caught:
        checks.run_bounded(
            [sys.executable, "-B", "-c", "print('x'*200000)"],
            cwd=tmp_path,
            environment=os.environ,
            payload=b"",
            timeout_seconds=10,
            max_stream_bytes=1024,
        )
    assert len(caught.value.stdout) == 1024
    assert len(caught.value.stderr) <= 1024


def test_real_timeout_preserves_diagnostic_and_kills_process(tmp_path: Path) -> None:
    started = time.monotonic()
    with pytest.raises(checks.ProcessLimitError) as caught:
        checks.run_bounded(
            [sys.executable, "-B", "-c", "import time;print('started',flush=True);time.sleep(30)"],
            cwd=tmp_path,
            environment=os.environ,
            payload=b"",
            timeout_seconds=1,
            max_stream_bytes=1024,
        )
    assert time.monotonic() - started < 10
    assert b"started" in caught.value.stdout


def _running(pid: int) -> bool:
    if os.name == "nt":
        from ctypes import wintypes

        api = ctypes.WinDLL("kernel32", use_last_error=True)
        api.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        api.OpenProcess.restype = wintypes.HANDLE
        api.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        api.WaitForSingleObject.restype = wintypes.DWORD
        api.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = api.OpenProcess(0x00100000, False, pid)
        if not handle:
            error = ctypes.get_last_error()
            if error == 87:  # ERROR_INVALID_PARAMETER: the PID no longer exists.
                return False
            raise ctypes.WinError(error)
        try:
            wait_status = int(api.WaitForSingleObject(handle, 0))
            if wait_status == 0xFFFFFFFF:
                raise ctypes.WinError(ctypes.get_last_error())
            assert wait_status in (0, 0x102)
            return wait_status == 0x102
        finally:
            api.CloseHandle(handle)
    try:
        status = Path(f"/proc/{pid}/stat")
        try:
            # The process name is parenthesized and may itself contain spaces.
            state = status.read_text().rsplit(")", 1)[1].split()[0]
            if state == "Z":
                return False
        except FileNotFoundError:
            # /proc may be unavailable, or the process may have just been reaped.
            pass
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def _wait_until_stopped(pid: int, *, timeout_seconds: float = 5) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while _running(pid):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.01, remaining))
    return True


def test_termination_probe_rejects_a_live_process_and_accepts_its_exit() -> None:
    process = subprocess.Popen(
        [sys.executable, "-B", "-c", "import time;time.sleep(30)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        assert not _wait_until_stopped(process.pid, timeout_seconds=0.05)
    finally:
        process.kill()
        process.wait(timeout=5)
    assert _wait_until_stopped(process.pid)


def test_descendant_is_killed_even_after_successful_parent_exit(tmp_path: Path) -> None:
    pid_file = tmp_path / "descendant.pid"
    code = (
        "import subprocess,sys;from pathlib import Path;"
        "p=subprocess.Popen([sys.executable,'-B','-c','import time;time.sleep(30)'],"
        "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);"
        f"Path({str(pid_file)!r}).write_text(str(p.pid));print('parent done')"
    )
    result = checks.run_bounded(
        [sys.executable, "-B", "-c", code],
        cwd=tmp_path,
        environment=os.environ,
        payload=b"",
        timeout_seconds=10,
        max_stream_bytes=1024,
    )
    pid = int(pid_file.read_text())
    try:
        assert result[0] == 0 and b"parent done" in result[1]
        # SIGKILL and Windows job close request termination; process state can
        # remain live briefly while the kernel completes that request.
        assert _wait_until_stopped(pid), "bounded runner left a live descendant"
    finally:
        if _running(pid):
            # Clean up only this test's own exact child, never a path/shell tree.
            subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "import os,signal,sys;os.kill(int(sys.argv[1]),9)",
                    str(pid),
                ],
                check=False,
                capture_output=True,
            )


def test_expansion_contains_no_secret_environment_or_raw_source() -> None:
    encoded = json.dumps(checks.expansion_projection(DIGEST))
    assert "Authorization" not in encoded and "GH_TOKEN" not in encoded
    assert "Agent_Assure_Implementation_Roadmap.md" not in encoded
