"""Authenticated, bounded expansion of the successor's local check graph.

Only the frozen S1 launcher may construct ``FrozenCheckBackend``. The reviewed
expansion preserves the old full-venv, source-inventory and recursive launch
guard; it replaces only an AST-verified pytest dispatch tail. It neither signs
evidence nor treats ordinary developer commands as accepted execution proof.
"""

from __future__ import annotations

import ast
import ctypes
import hashlib
import json
import os
import re
import signal
import subprocess
import threading
import time
from collections.abc import Mapping, Sequence
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, cast

from agent_assure.rooted_io import open_rooted_bounded_file

# Ruff's Python package dispatches a native binary outside site-packages.
# Bind that separately; it is not covered by the legacy package inventory.
RUFF_BINARY_IDENTITY: dict[str, Any] = {
    "relative_path": ".venv/Scripts/ruff.exe",
    "size_bytes": 32_307_712,
    "sha256": "sha256:58a216e513161b3b13bd318cc4098fadbc28723afb7c74072d58d8b79e519d48",
}


class CheckError(ValueError):
    """A failed, incomplete, changed, or unsafe check invocation."""


class ProcessLimitError(CheckError):
    """Bounded diagnostic streams from a killed, nonpassing process."""

    def __init__(self, message: str, stdout: bytes, stderr: bytes) -> None:
        super().__init__(message)
        self.stdout, self.stderr = stdout, stderr


class LocalCheckFailure(CheckError):
    """Diagnostic-only children retained without a passing aggregate payload."""

    def __init__(
        self,
        check_id: str,
        records: Sequence[dict[str, Any]],
        streams: Sequence[tuple[str, bytes]],
        expansion_digest: str,
    ) -> None:
        super().__init__(f"local check did not complete successfully: {check_id}")
        self.child_records = tuple(records)
        self.raw_streams = tuple(streams)
        self.expansion_digest = expansion_digest


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _utc() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class CheckSpec:
    check_id: str
    module: str | None
    script: str | None
    arguments: tuple[str, ...]
    timeout_seconds: int = 900
    max_stream_bytes: int = 16 * 1024 * 1024


@dataclass(frozen=True)
class CommandResult:
    check_id: str
    started_at_utc: str
    completed_at_utc: str
    exit_code: int
    stdout: bytes
    stderr: bytes
    command_record: Mapping[str, Any]


@dataclass(frozen=True)
class LocalCheckCollection:
    payload: dict[str, Any]
    child_records: tuple[dict[str, Any], ...]
    raw_streams: tuple[tuple[str, bytes], ...]
    expansion_digest: str


class CheckBackend(Protocol):
    def execute(self, spec: CheckSpec) -> CommandResult: ...


def make_check_expansion() -> tuple[CheckSpec, ...]:
    """The fixed expansion; placeholders are substituted by the trusted backend.

    Full pytest is supplied by validated native-v4 capture. Fresh private build
    and schema output replaces Makefile's distribution cleanup/staging mutation.
    Cache suppression and no-isolation build prevent changes outside owned temp.
    """
    return (
        CheckSpec("ruff-check", "ruff", None, ("check", "--no-cache", ".")),
        CheckSpec("ruff-format", "ruff", None, ("format", "--check", "--no-cache", ".")),
        CheckSpec(
            "mypy",
            "mypy",
            None,
            ("--no-incremental", "--cache-dir", "{temp}/mypy-cache", "src", "scripts"),
        ),
        CheckSpec("dependency-locks", None, "scripts/check_dependency_lock_freshness.py", ()),
        CheckSpec("docs-alignment", None, "scripts/check_docs_alignment.py", ()),
        CheckSpec("claim-boundary", None, "scripts/check_claim_boundaries.py", ()),
        CheckSpec("examples-parity", None, "scripts/check_packaged_examples.py", ()),
        CheckSpec(
            "reproduction-index",
            None,
            "scripts/update_process_equivalence_reproduction_index.py",
            (),
        ),
        CheckSpec("build", "build", None, ("--no-isolation", "--outdir", "{generated}/build")),
        CheckSpec(
            "schema-force-includes", None, "scripts/sync_schema_force_includes.py", ("--check",)
        ),
        CheckSpec("frozen-schemas", None, "scripts/check_frozen_schemas.py", ()),
        CheckSpec(
            "tagged-schema-immutability", None, "scripts/check_tagged_schema_immutability.py", ()
        ),
        CheckSpec(
            "schema-staging",
            None,
            "scripts/check_schema_staging.py",
            ("--out", "{generated}/schema-staging"),
        ),
        CheckSpec("architecture-draft", None, "scripts/v1_architecture_governance.py", ("check",)),
        CheckSpec(
            "successor-specific",
            "pytest",
            None,
            (
                "-p",
                "no:cacheprovider",
                "-c",
                "{root}/pyproject.toml",
                "--rootdir={root}",
                "--confcutdir={root}",
                "-o",
                "addopts=",
                "-o",
                "pythonpath=src",
                "-o",
                "norecursedirs=__pycache__",
                "-o",
                "python_files=test_*.py *_test.py",
                "-o",
                "python_classes=Test",
                "-o",
                "python_functions=test",
                "--import-mode=importlib",
                "--strict-config",
                "--strict-markers",
                "--disable-socket",
                "{root}/tests/unit/governance",
                "{root}/tests/integration/test_v1_s1_historical_check.py",
                "--basetemp",
                "{basetemp}",
            ),
            1800,
        ),
    )


def _spec_record(spec: CheckSpec) -> dict[str, Any]:
    return {
        "id": spec.check_id,
        "module": spec.module,
        "script": spec.script,
        "arguments": list(spec.arguments),
        "timeout_seconds": spec.timeout_seconds,
        "max_stream_bytes": spec.max_stream_bytes,
        "windows_job_memory_limit_bytes": 2 * 1024 * 1024 * 1024,
        "windows_job_active_process_limit": 128,
        "windows_start_policy": "suspended_before_job_assignment",
    }


_MAKE_TARGETS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "check": (
        (
            "lint",
            "type",
            "dependency-lock-freshness",
            "test",
            "docs-align",
            "claim-boundary",
            "examples-parity",
            "reproduction-index-check",
            "build",
            "v1-architecture-check",
        ),
        (),
    ),
    "lint": (
        (),
        (
            "$(PYTHON) -m ruff check .",
            "$(PYTHON) -m ruff format --check $(RUFF_FORMAT_CHECK_PATHS)",
        ),
    ),
    "type": ((), ("$(PYTHON) -m mypy src scripts",)),
    "dependency-lock-freshness": ((), ("$(PYTHON) scripts/check_dependency_lock_freshness.py",)),
    "test": ((), ("$(PYTHON) -m pytest",)),
    "docs-align": ((), ("$(PYTHON) scripts/check_docs_alignment.py",)),
    "claim-boundary": ((), ("$(PYTHON) scripts/check_claim_boundaries.py",)),
    "examples-parity": ((), ("$(PYTHON) scripts/check_packaged_examples.py",)),
    "reproduction-index-check": (
        (),
        ("$(PYTHON) scripts/update_process_equivalence_reproduction_index.py",),
    ),
    "clean-dist": ((), ("$(PYTHON) scripts/clean_dist.py",)),
    "build": (("clean-dist",), ("$(PYTHON) -m build --no-isolation",)),
    "v1-architecture-check": ((), ("$(PYTHON) scripts/v1_architecture_governance.py check",)),
    "schema-check": (
        (),
        (
            "$(PYTHON) scripts/sync_schema_force_includes.py --check",
            "$(PYTHON) scripts/check_frozen_schemas.py",
            "$(PYTHON) scripts/check_tagged_schema_immutability.py",
            "$(PYTHON) scripts/check_schema_staging.py",
        ),
    ),
}


def validate_makefile_projection(payload: bytes) -> str:
    """Verify the full relevant default graph without evaluating Make syntax."""
    if type(payload) is not bytes or len(payload) > 256 * 1024:
        raise CheckError("bounded Makefile bytes required")
    try:
        source = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CheckError("Makefile must be UTF-8") from exc
    observed: dict[str, tuple[tuple[str, ...], list[str]]] = {}
    current: str | None = None
    for line in source.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if (
            re.match(
                r"(?:-?include|sinclude|define|endef|ifeq|ifneq|ifdef|ifndef|else|endif|override|export)\b",
                stripped,
            )
            or "$(eval" in stripped
            or re.match(
                r"(?:\.ONESHELL|\.RECIPEPREFIX|\.SHELLFLAGS|SHELL)\s*[:?+!]?=|\.ONESHELL\s*:",
                stripped,
            )
        ):
            raise CheckError("unsupported Makefile interpretation change")
        if line.startswith("\t"):
            if current in observed:
                observed[current][1].append(line[1:].strip())
            continue
        matched = re.fullmatch(r"([A-Za-z][A-Za-z0-9_-]*):\s*(.*)", line)
        current = matched[1] if matched else None
        if current in _MAKE_TARGETS:
            if current in observed:
                raise CheckError("duplicate required Makefile target")
            assert matched is not None
            observed[current] = (tuple(matched[2].split()), [])
    projected = {
        key: (dependencies, tuple(recipes)) for key, (dependencies, recipes) in observed.items()
    }
    if projected != _MAKE_TARGETS:
        raise CheckError("Makefile graph differs from the reviewed full-check expansion")
    return _digest(payload)


def expansion_projection(makefile_digest: str) -> dict[str, Any]:
    if re.fullmatch(r"sha256:[0-9a-f]{64}", makefile_digest) is None:
        raise CheckError("exact Makefile digest required")
    return {
        "format": "agent-assure-s1-local-check-expansion/3",
        "makefile_sha256": makefile_digest,
        "commands": [_spec_record(spec) for spec in make_check_expansion()],
        "native_tool_identities": {"ruff": dict(RUFF_BINARY_IDENTITY)},
        "full_pytest": "separately_source_validated_native_v4_capture",
        "clean_dist": "replaced_by_fresh_owned_build_output_no_deletion",
        "schema_staging": "fresh_owned_output_same_exporter_no_released_schema_mutation",
        "cache_policy": "disabled_or_fresh_process_private_cache",
        "equivalence_status": "requires_exact_human_adopted_expansion_digest",
        "makefile_projection": {
            key: {"dependencies": list(value[0]), "recipes": list(value[1])}
            for key, value in _MAKE_TARGETS.items()
        },
    }


_PYTEST_TAIL = ast.parse(
    'sys.argv = ["pytest", *pytest_arguments]\n'
    'runpy.run_module("pytest", run_name="__main__", alter_sys=True)\n'
).body


def transform_bootstrap(encoded: str, spec: CheckSpec, arguments: Sequence[str]) -> bytes:
    """Replace exactly the reviewed two-node dispatch, preserving the verifier.

    This is an AST transformation of authenticated repository code, never an
    evaluator for captured content. The wrapper must be precisely one
    exec(Constant[str]) and both old dispatch nodes must match independently
    authored AST fingerprints. Any upstream bootstrap drift blocks execution.
    """
    if spec not in make_check_expansion():
        raise CheckError("command is outside the reviewed expansion")
    try:
        wrapper = ast.parse(encoded)
        expression = wrapper.body[0] if len(wrapper.body) == 1 else None
        call = expression.value if isinstance(expression, ast.Expr) else None
        if not (
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Name)
            and call.func.id == "exec"
            and len(call.args) == 1
            and not call.keywords
            and isinstance(call.args[0], ast.Constant)
            and type(call.args[0].value) is str
        ):
            raise CheckError("unexpected authenticated bootstrap wrapper")
        program = ast.parse(call.args[0].value)
        if len(program.body) < 2 or [
            ast.dump(node, include_attributes=False) for node in program.body[-2:]
        ] != [ast.dump(node, include_attributes=False) for node in _PYTEST_TAIL]:
            raise CheckError("authenticated bootstrap dispatch changed")
        target = spec.module if spec.module is not None else spec.script
        new_tail: list[ast.stmt] = [
            ast.Assign(
                targets=[
                    ast.Attribute(
                        value=ast.Name(id="sys", ctx=ast.Load()), attr="argv", ctx=ast.Store()
                    )
                ],
                value=ast.List(
                    elts=[ast.Constant(target), *(ast.Constant(arg) for arg in arguments)],
                    ctx=ast.Load(),
                ),
            ),
        ]
        if spec.module == "ruff":
            # Resolve through the authenticated package once, reject fallback
            # locations, then make its __main__ dispatch use the leased binary.
            relative = RUFF_BINARY_IDENTITY["relative_path"]
            guard = ast.parse(
                "import ruff as _successor_ruff\n"
                "from pathlib import Path as _successor_Path\n"
                f"_successor_ruff_binary = repository_root / {relative!r}\n"
                "if _successor_Path(_successor_ruff.find_ruff_bin()).resolve() "
                "!= _successor_ruff_binary.resolve():\n"
                "    raise RuntimeError('Ruff resolved outside its frozen binary identity')\n"
                "_successor_ruff.find_ruff_bin = lambda: str(_successor_ruff_binary)\n"
            ).body
            new_tail = [*guard, *new_tail]
        dispatch: ast.stmt
        if spec.module is not None:
            dispatch = ast.Expr(
                value=ast.Call(
                    func=ast.Attribute(
                        value=ast.Name(id="runpy", ctx=ast.Load()),
                        attr="run_module",
                        ctx=ast.Load(),
                    ),
                    args=[ast.Constant(spec.module)],
                    keywords=[
                        ast.keyword(arg="run_name", value=ast.Constant("__main__")),
                        ast.keyword(arg="alter_sys", value=ast.Constant(True)),
                    ],
                )
            )
        else:
            dispatch = ast.parse(
                f"runpy.run_path(str(repository_root / {spec.script!r}), run_name='__main__')"
            ).body[0]
        program.body[-2:] = [*new_tail, dispatch]
        ast.fix_missing_locations(program)
        return ("exec(" + repr(ast.unparse(program)) + ")").encode("utf-8")
    except CheckError:
        raise
    except (SyntaxError, ValueError, TypeError) as exc:
        raise CheckError("unsupported authenticated bootstrap syntax") from exc


class _WindowsJob:
    """Kill-on-close native job; no taskkill/PATH helper or weaker fallback."""

    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        from ctypes import wintypes

        class BasicLimit(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_int64),
                ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class IoCounters(ctypes.Structure):
            _fields_ = [
                (name, ctypes.c_uint64)
                for name in (
                    "ReadOperationCount",
                    "WriteOperationCount",
                    "OtherOperationCount",
                    "ReadTransferCount",
                    "WriteTransferCount",
                    "OtherTransferCount",
                )
            ]

        class ExtendedLimit(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", BasicLimit),
                ("IoInfo", IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        api = cast(Any, ctypes).WinDLL("kernel32", use_last_error=True)
        api.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        api.CreateJobObjectW.restype = wintypes.HANDLE
        api.SetInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        api.SetInformationJobObject.restype = wintypes.BOOL
        api.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        api.AssignProcessToJobObject.restype = wintypes.BOOL
        api.CloseHandle.argtypes = [wintypes.HANDLE]
        api.CloseHandle.restype = wintypes.BOOL
        self.api, self.handle = api, api.CreateJobObjectW(None, None)
        if not self.handle:
            raise CheckError("native child containment unavailable")
        info = ExtendedLimit()
        # Kill on close, cap total committed job memory and simultaneous
        # processes. These are Windows-qualified bounds, not POSIX claims.
        info.BasicLimitInformation.LimitFlags = 0x2000 | 0x200 | 0x8
        info.BasicLimitInformation.ActiveProcessLimit = 128
        info.JobMemoryLimit = 2 * 1024 * 1024 * 1024
        if not api.SetInformationJobObject(self.handle, 9, ctypes.byref(info), ctypes.sizeof(info)):
            self.close()
            raise CheckError("native child containment policy failed")
        if not api.AssignProcessToJobObject(self.handle, int(cast(Any, process)._handle)):
            self.close()
            raise CheckError("native child containment assignment failed")
        # Creation is suspended, so no child can spawn outside the job between
        # CreateProcess and assignment. Resume the assigned process only now.
        ntdll = cast(Any, ctypes).WinDLL("ntdll", use_last_error=True)
        ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]
        ntdll.NtResumeProcess.restype = ctypes.c_long
        if ntdll.NtResumeProcess(int(cast(Any, process)._handle)) != 0:
            self.close()
            raise CheckError("native contained process resume failed")

    def close(self) -> None:
        if self.handle:
            self.api.CloseHandle(self.handle)
            self.handle = None


def run_bounded(
    argv: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    payload: bytes,
    timeout_seconds: int,
    max_stream_bytes: int,
) -> tuple[int, bytes, bytes]:
    """Run with caller-supplied environment, bounded pipes and descendant kill."""
    if (
        type(timeout_seconds) is not int
        or not 1 <= timeout_seconds <= 7200
        or type(max_stream_bytes) is not int
        or not 1 <= max_stream_bytes <= 64 * 1024 * 1024
    ):
        raise CheckError("invalid process work limits")
    if not argv or not Path(argv[0]).is_absolute() or type(payload) is not bytes:
        raise CheckError("absolute fixed executable and byte payload required")
    options: dict[str, Any] = {
        "stdin": subprocess.PIPE,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "cwd": cwd,
        "env": dict(environment),
        "shell": False,
        "close_fds": True,
    }
    if os.name == "nt":
        options["creationflags"] = cast(Any, subprocess).CREATE_NEW_PROCESS_GROUP | 0x4
    else:
        options["start_new_session"] = True
    process = subprocess.Popen(list(argv), **options)
    job: _WindowsJob | None = None
    exceeded = threading.Event()
    errors: list[BaseException] = []
    streams = [bytearray(), bytearray()]

    def read(index: int, handle: Any) -> None:
        try:
            while chunk := handle.read(65536):
                if len(streams[index]) + len(chunk) > max_stream_bytes:
                    streams[index].extend(chunk[: max_stream_bytes - len(streams[index])])
                    exceeded.set()
                    return
                streams[index].extend(chunk)
        except (OSError, ValueError) as exc:
            errors.append(exc)

    def write() -> None:
        try:
            assert process.stdin is not None
            process.stdin.write(payload)
            process.stdin.close()
        except (BrokenPipeError, OSError, ValueError):
            # A failed child can close stdin early; its exit code remains failure.
            pass

    threads: list[threading.Thread] = []

    def stop() -> None:
        if job is not None:
            job.close()
        elif os.name != "nt":
            try:
                cast(Any, os).killpg(process.pid, cast(Any, signal).SIGKILL)
            except ProcessLookupError:
                pass
        elif process.poll() is None:
            process.kill()

    try:
        if os.name == "nt":
            job = _WindowsJob(process)
        assert process.stdout is not None and process.stderr is not None
        threads = [
            threading.Thread(target=read, args=(0, process.stdout), daemon=True),
            threading.Thread(target=read, args=(1, process.stderr), daemon=True),
            threading.Thread(target=write, daemon=True),
        ]
        for thread in threads:
            thread.start()
        deadline = time.monotonic() + timeout_seconds
        limit_failure = False
        while process.poll() is None:
            if exceeded.is_set() or errors or time.monotonic() >= deadline:
                limit_failure = True
                stop()
                break
            try:
                process.wait(timeout=min(0.05, max(0.001, deadline - time.monotonic())))
            except subprocess.TimeoutExpired:
                continue
        # A successful parent may have left descendants holding pipes or running.
        # Close the job/session before accepting terminal evidence.
        stop()
        for thread in threads:
            thread.join(timeout=5)
        if (
            limit_failure
            or any(thread.is_alive() for thread in threads)
            or exceeded.is_set()
            or errors
        ):
            raise ProcessLimitError(
                "incomplete or excessive local check streams", bytes(streams[0]), bytes(streams[1])
            )
        return process.returncode, bytes(streams[0]), bytes(streams[1])
    finally:
        stop()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        for thread in threads:
            thread.join(timeout=5)
        for handle in (process.stdin, process.stdout, process.stderr):
            if handle is not None and not any(thread.is_alive() for thread in threads):
                handle.close()


def validate_ruff_binary(root: Path, *, leases: ExitStack | None = None) -> dict[str, Any]:
    """Authenticate the fixed native tool, optionally retaining its path lease."""
    if leases is None:
        with ExitStack() as owned:
            return validate_ruff_binary(root, leases=owned)
    identity = dict(RUFF_BINARY_IDENTITY)
    try:
        descriptor = leases.enter_context(
            open_rooted_bounded_file(
                root,
                str(identity["relative_path"]),
                max_bytes=int(identity["size_bytes"]),
                label="frozen Ruff executable",
            )
        )
        raw = descriptor.contents.data
        if len(raw) != identity["size_bytes"] or _digest(raw) != identity["sha256"]:
            raise CheckError("frozen Ruff executable byte identity changed")
        return identity
    except OSError as exc:
        raise CheckError("frozen Ruff executable is missing, linked, or changed") from exc


class FrozenCheckBackend:
    """Actual backend admitted only inside the authenticated legacy launcher."""

    def __init__(
        self, legacy: Any, repository_root: Path, result_commit: str, generated_root: Path
    ) -> None:
        if not legacy._main_has_active_runtime_bootstrap():
            raise CheckError("local capture requires the frozen S1 runtime bootstrap")
        self.legacy, self.root = legacy, repository_root.resolve()
        self._executed: set[str] = set()
        self.result_commit = result_commit
        if re.fullmatch(r"[0-9a-f]{40}", result_commit) is None:
            raise CheckError("exact result commit required")
        self.generated_root = legacy._resolve_repository_path_without_links(
            self.root, generated_root, owner="successor local generated output"
        )
        expected_parent = self.root / ".tmp/s1-acceptance"
        if (
            self.generated_root.parent != expected_parent
            or re.fullmatch(r"v3-checks-[a-z0-9][a-z0-9-]{0,63}", self.generated_root.name) is None
            or self.generated_root.exists()
            or self.generated_root.is_symlink()
        ):
            raise CheckError("fresh confined successor output required")
        self._state()
        makefile = legacy._read_commit_blob(
            self.root, result_commit, "Makefile", owner="successor reviewed Makefile"
        )
        self.makefile_digest = validate_makefile_projection(makefile)
        expected_parent.mkdir(parents=True, exist_ok=True)
        self.generated_root.mkdir(mode=0o700, exist_ok=False)

    def _state(self) -> dict[str, Any]:
        self.legacy._post_v2_control_git_metadata_preflight(self.root)
        state = self.legacy._post_v2_control_repository_state(self.root)
        if state.get("head_commit") != self.result_commit or state.get("clean") is not True:
            raise CheckError("local checks require clean exact R3")
        return cast(dict[str, Any], state)

    def execute(self, spec: CheckSpec) -> CommandResult:
        if spec not in make_check_expansion():
            raise CheckError("unregistered local command")
        if spec.check_id in self._executed:
            raise CheckError("a check backend cannot reuse an executed command/output")
        self._executed.add(spec.check_id)
        # The rooted descriptor pins every ancestor. On the qualified Windows
        # host its open handle denies writes/deletion for the complete child
        # execution interval, eliminating hash-then-execute replacement races.
        with ExitStack() as leases:
            native = (
                validate_ruff_binary(self.root, leases=leases) if spec.module == "ruff" else None
            )
            result = self._execute_authenticated(spec, native)
            if native is not None:
                validate_ruff_binary(self.root, leases=leases)
            return result

    def _execute_authenticated(
        self, spec: CheckSpec, native: Mapping[str, Any] | None
    ) -> CommandResult:
        legacy, root = self.legacy, self.root
        initial_state = self._state()
        surface = legacy._post_r2_test_surface_evidence(
            root, result_commit=self.result_commit, legacy_v3_policy=False
        )
        if surface.get("format") != "agent-assure-s1-post-r2-test-surface/2":
            raise CheckError("local checks require the hardened v4 test surface")
        runtime = legacy._post_r2_test_runtime_evidence(root)
        basetemp, process_temp = legacy._allocate_post_r2_run_paths(root)
        try:
            descendant = legacy._prepare_post_r2_descendant_runtime(
                root, basetemp=basetemp, process_temp=process_temp
            )
            arguments = tuple(
                arg.replace("{root}", str(root))
                .replace("{temp}", str(process_temp))
                .replace("{generated}", str(self.generated_root))
                .replace("{basetemp}", str(basetemp))
                for arg in spec.arguments
            )
            encoded = legacy._post_r2_pytest_bootstrap_source(
                root, basetemp=basetemp, process_temp=process_temp, legacy_v3_policy=False
            )
            bootstrap = transform_bootstrap(encoded, spec, arguments)
            argv = legacy._post_r2_pytest_argv(
                root, basetemp=basetemp, process_temp=process_temp, test_surface=surface
            )
            environment = legacy._post_r2_subprocess_environment(
                root, basetemp, process_temp=process_temp, legacy_v3_policy=False
            )
            if (
                basetemp.exists()
                or (basetemp / "python-bytecode-cache").exists()
                or legacy._verify_post_r2_descendant_runtime(
                    root,
                    basetemp=basetemp,
                    process_temp=process_temp,
                    require_empty_user_temp=True,
                    legacy_v3_policy=False,
                )
                != descendant
            ):
                raise CheckError("fresh process runtime changed before local check")
            started = _utc()
            outcome = "completed"
            try:
                exit_code, stdout, stderr = run_bounded(
                    argv,
                    cwd=root,
                    environment=environment,
                    payload=bootstrap,
                    timeout_seconds=spec.timeout_seconds,
                    max_stream_bytes=spec.max_stream_bytes,
                )
            except ProcessLimitError as exc:
                exit_code, stdout, stderr = -1, exc.stdout, exc.stderr
                outcome = "resource_or_pipe_limit_exceeded"
            completed = _utc()
            if (
                self._state() != initial_state
                or legacy._post_r2_test_surface_evidence(
                    root, result_commit=self.result_commit, legacy_v3_policy=False
                )
                != surface
                or legacy._post_r2_test_runtime_evidence(root) != runtime
                or legacy._verify_post_r2_descendant_runtime(
                    root,
                    basetemp=basetemp,
                    process_temp=process_temp,
                    require_empty_user_temp=False,
                    legacy_v3_policy=False,
                )
                != descendant
                or (basetemp / "python-bytecode-cache").exists()
            ):
                raise CheckError(
                    "source, runtime, repository, or bytecode changed during local check"
                )
            return CommandResult(
                spec.check_id,
                started,
                completed,
                exit_code,
                stdout,
                stderr,
                {
                    "spec": _spec_record(spec),
                    "native_tool": dict(native) if native is not None else None,
                    "argv": argv,
                    "working_directory": str(root),
                    "bootstrap_sha256": _digest(bootstrap),
                    "bootstrap_size_bytes": len(bootstrap),
                    "bootstrap_transform": "exact_ast_two_node_pytest_dispatch_substitution/v1",
                    "repository_test_surface": surface,
                    "test_runtime": runtime,
                    "descendant_runtime": descendant,
                    "environment_digest": _digest(json.dumps(environment, sort_keys=True).encode()),
                    "sanitized_environment": dict(environment),
                    "execution_outcome": outcome,
                    "native_job_memory_limit_bytes": 2 * 1024 * 1024 * 1024,
                    "native_job_active_process_limit": 128,
                    "descendant_containment": "windows_suspended_assignment_kill_on_close/v1",
                },
            )
        finally:
            legacy._cleanup_post_r2_process_temp(process_temp)


def collect_local_checks(
    backend: CheckBackend,
    *,
    native_v4_evidence_digest: str,
    makefile_digest: str,
    canonical_bytes: Any,
) -> LocalCheckCollection:
    """Execute every fixed check and return exact source records plus raw logs.

    The caller validates the native source before AND after this collection and
    adopts the returned expansion digest in its signed policy. Failure raises;
    partial child records never become a passing aggregate.
    """
    if re.fullmatch(r"sha256:[0-9a-f]{64}", native_v4_evidence_digest) is None:
        raise CheckError("validated native-v4 reference required")
    expansion = expansion_projection(makefile_digest)
    if isinstance(backend, FrozenCheckBackend) and backend.makefile_digest != makefile_digest:
        raise CheckError("local expansion was bound to another Makefile")
    expansion_digest = _digest(
        b"agent-assure:s1-local-check-expansion/v3\x00" + canonical_bytes(expansion)
    )
    records: list[dict[str, Any]] = []
    streams: list[tuple[str, bytes]] = []
    previous_end: datetime | None = None
    for index, spec in enumerate(make_check_expansion()):
        result = backend.execute(spec)
        if type(result) is not CommandResult or result.check_id != spec.check_id:
            raise CheckError("local backend substituted a command result")
        if dict(result.command_record).get("spec") != _spec_record(spec):
            raise CheckError("local backend substituted a command recipe")

        def instant(value: str) -> datetime:
            if (
                type(value) is not str
                or re.fullmatch(
                    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z",
                    value,
                )
                is None
            ):
                raise CheckError("local check requires canonical UTC observations")
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError as exc:
                raise CheckError("invalid local check observation time") from exc

        start, end = instant(result.started_at_utc), instant(result.completed_at_utc)
        if start > end or (previous_end is not None and start < previous_end):
            raise CheckError("local check chronology is inconsistent")
        previous_end = end
        if (
            type(result.exit_code) is not int
            or type(result.stdout) is not bytes
            or type(result.stderr) is not bytes
            or max(len(result.stdout), len(result.stderr)) > spec.max_stream_bytes
        ):
            raise CheckError(f"local check did not complete successfully: {spec.check_id}")
        stdout_name, stderr_name = f"child-{index:02d}.stdout.bin", f"child-{index:02d}.stderr.bin"
        record = {
            "id": spec.check_id,
            "started_at_utc": result.started_at_utc,
            "completed_at_utc": result.completed_at_utc,
            "exit_code": result.exit_code,
            "command": dict(result.command_record),
            "stdout": {
                "file_name": stdout_name,
                "size_bytes": len(result.stdout),
                "sha256": _digest(result.stdout),
            },
            "stderr": {
                "file_name": stderr_name,
                "size_bytes": len(result.stderr),
                "sha256": _digest(result.stderr),
            },
        }
        records.append(record)
        streams.extend(((stdout_name, result.stdout), (stderr_name, result.stderr)))
        if result.exit_code != 0:
            raise LocalCheckFailure(spec.check_id, records, streams, expansion_digest)
    aggregate = {
        "format": "agent-assure-s1-local-check-ledger/3",
        "expansion": expansion,
        "expansion_digest": expansion_digest,
        "native_v4_evidence_digest": native_v4_evidence_digest,
        "children": list(records),
    }
    aggregate_digest = _digest(
        b"agent-assure:s1-local-check-ledger/v3\x00" + canonical_bytes(aggregate)
    )
    successor = records[-1]
    payload = {
        "checks": [
            {
                "id": "make check schema-check",
                "started_at_utc": records[0]["started_at_utc"],
                "completed_at_utc": records[-1]["completed_at_utc"],
                "exit_code": 0,
                "output_digest": aggregate_digest,
            },
            {
                "id": "successor_specific_unit_and_integration_checks",
                "started_at_utc": successor["started_at_utc"],
                "completed_at_utc": successor["completed_at_utc"],
                "exit_code": 0,
                "output_digest": _digest(canonical_bytes(successor)),
            },
        ]
    }
    records.append(aggregate)
    return LocalCheckCollection(payload, tuple(records), tuple(streams), expansion_digest)
