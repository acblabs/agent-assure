from __future__ import annotations

import argparse
import base64
import configparser
import csv
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import venv
import zipfile
import zlib
from contextlib import ExitStack
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent_assure.io_limits import (  # noqa: E402
    open_directory_at,
    read_file_bounded,
    read_file_bounded_at,
)
from agent_assure.rooted_io import RootedDirectoryDescriptor  # noqa: E402
from scripts.check_wheel_contents import (  # noqa: E402
    inspect_sdist,
    inspect_wheel,
    validate_distribution_directory,
    validate_distribution_identity,
    validate_distribution_payload_equivalence,
    validate_wheel_archive_equivalence,
)
from scripts.example_resource_manifest import (  # noqa: E402
    EVIDENCE_SENSITIVITY_REQUIRED_RESOURCE_PATHS,
    PROCESS_EQUIVALENCE_BENCHMARK_REQUIRED_RESOURCE_PATHS,
)
from scripts.schema_versions import SCHEMA_ROOT, frozen_schema_versions  # noqa: E402

DIST = ROOT / "dist"
LOCKFILE = ROOT / "requirements.lock"
COMMAND_TIMEOUT_SECONDS = 600
MAX_LOCKFILE_BYTES = 16 * 1024 * 1024
MAX_DISTRIBUTION_BYTES = 128 * 1024 * 1024
MAX_ENVIRONMENT_MEMBERS = 100_000
MAX_ENVIRONMENT_MEMBER_BYTES = 128 * 1024 * 1024
MAX_ENVIRONMENT_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
_WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_MAX_INLINE_PYTHON_ASSERTION_CHARS = 16_000


@dataclass(frozen=True)
class DistributionSnapshot:
    """Exact validated bytes retained outside artifact-controlled filesystem state."""

    name: str
    data: bytes
    sha256: str


@dataclass(frozen=True)
class TreeFile:
    size: int
    sha256: str


@dataclass(frozen=True)
class TreeSnapshot:
    directories: frozenset[str]
    files: dict[str, TreeFile]
    links: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class EnvironmentLayout:
    purelib: str
    scripts: str


@dataclass(frozen=True)
class PinnedDirectory:
    relative_path: str
    lease: RootedDirectoryDescriptor


class _CaseSensitiveConfigParser(configparser.ConfigParser):
    def optionxform(self, optionstr: str) -> str:
        return optionstr


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    try:
        wheel, sdist = validate_distribution_directory(args.dist)
        wheel_snapshot = capture_file_snapshot(
            wheel,
            max_bytes=MAX_DISTRIBUTION_BYTES,
            label="wheel distribution",
        )
        sdist_snapshot = capture_file_snapshot(
            sdist,
            max_bytes=MAX_DISTRIBUTION_BYTES,
            label="source distribution",
        )
        lock_snapshot = capture_file_snapshot(
            args.lockfile,
            max_bytes=MAX_LOCKFILE_BYTES,
            label="dependency lockfile",
        )
        with tempfile.TemporaryDirectory(prefix="agent-assure-wheel-smoke-") as temp:
            temp_dir = Path(temp)
            wheel_phase = temp_dir / "wheel-phase"
            sdist_phase = temp_dir / "sdist-phase"
            build_phase = temp_dir / "build-phase"
            venv_dir = wheel_phase / "venv"
            sdist_venv_dir = sdist_phase / "venv"
            build_venv_dir = build_phase / "venv"
            wheelhouse = temp_dir / "wheelhouse"
            sdist_wheelhouse = temp_dir / "sdist-wheelhouse"
            verified_dir = temp_dir / "verified-distributions"
            wheel_artifact_dir = temp_dir / "wheel-artifact"
            sdist_artifact_dir = temp_dir / "sdist-artifact"
            built_wheel_dir = temp_dir / "built-sdist-wheel"
            lock_dir = temp_dir / "lock"
            manifest_dir = temp_dir / "verified-payload-manifest"
            outputs_dir = temp_dir / "outputs"
            private_directories = (
                wheel_phase,
                sdist_phase,
                build_phase,
                wheelhouse,
                sdist_wheelhouse,
                verified_dir,
                wheel_artifact_dir,
                sdist_artifact_dir,
                built_wheel_dir,
                lock_dir,
                manifest_dir,
                outputs_dir,
            )
            for private_directory in private_directories:
                create_private_directory(private_directory)

            schema_dir = outputs_dir / "schemas"
            sdist_schema_dir = outputs_dir / "schemas-sdist"
            flagship_dir = outputs_dir / "flagship"
            assurance_demo_dir = outputs_dir / "assure-the-assurance"
            sensitivity_demo_dir = outputs_dir / "evidence-sensitivity"
            sensitivity_reversed_dir = outputs_dir / "evidence-reversed"
            verified_wheel = materialize_snapshot(
                wheel_snapshot,
                verified_dir,
                prepared=True,
            )
            verified_sdist = materialize_snapshot(
                sdist_snapshot,
                verified_dir,
                prepared=True,
            )
            wheel_missing, wheel_forbidden = inspect_wheel(verified_wheel)
            sdist_missing, sdist_forbidden = inspect_sdist(verified_sdist)
            if wheel_missing or wheel_forbidden or sdist_missing or sdist_forbidden:
                raise ValueError(
                    "distribution content verification failed before smoke installation"
                )
            validate_distribution_identity(verified_wheel, verified_sdist)
            payload_manifest = validate_distribution_payload_equivalence(
                verified_wheel,
                verified_sdist,
            )
            payload_manifest_snapshot = distribution_payload_manifest_snapshot(payload_manifest)
            verified_payload_manifest = materialize_snapshot(
                payload_manifest_snapshot,
                manifest_dir,
                prepared=True,
            )
            expected_version = verified_wheel.name.split("-", 2)[1]
            verified_lockfile = materialize_snapshot(lock_snapshot, lock_dir, prepared=True)
            wheel_artifact = materialize_snapshot(
                wheel_snapshot,
                wheel_artifact_dir,
                prepared=True,
            )
            sdist_artifact = materialize_snapshot(
                sdist_snapshot,
                sdist_artifact_dir,
                prepared=True,
            )
            build_wheelhouse(wheelhouse, verified_lockfile, prepared=True)
            build_wheelhouse(sdist_wheelhouse, verified_lockfile, prepared=True)
            create_virtualenv(venv_dir)
            create_virtualenv(sdist_venv_dir)
            create_virtualenv(build_venv_dir)
            python = venv_python(venv_dir)
            sdist_python = venv_python(sdist_venv_dir)
            build_python = venv_python(build_venv_dir)
            agent_assure = venv_executable(venv_dir, "agent-assure")
            sdist_agent_assure = venv_executable(sdist_venv_dir, "agent-assure")
            install_locked_dependencies(
                python,
                wheelhouse,
                verified_lockfile,
                cwd=temp_dir,
            )
            install_locked_dependencies(
                sdist_python,
                sdist_wheelhouse,
                verified_lockfile,
                cwd=temp_dir,
            )
            install_locked_dependencies(
                build_python,
                sdist_wheelhouse,
                verified_lockfile,
                cwd=temp_dir,
            )
            wheel_layout = query_environment_layout(python, venv_dir, cwd=temp_dir)
            sdist_layout = query_environment_layout(
                sdist_python,
                sdist_venv_dir,
                cwd=temp_dir,
            )
            expected_venv_links = _expected_virtualenv_directory_links()
            wheel_baseline = capture_tree_snapshot(
                wheel_phase,
                label="wheel environment",
                allowed_directory_links=expected_venv_links,
            )
            sdist_baseline = capture_tree_snapshot(
                sdist_phase,
                label="sdist environment",
                allowed_directory_links=expected_venv_links,
            )
            build_baseline = capture_tree_snapshot(
                build_phase,
                label="build environment",
                allowed_directory_links=expected_venv_links,
            )
            protected_roots = {
                "verified distributions": (
                    verified_dir,
                    capture_tree_snapshot(verified_dir, label="verified distributions"),
                ),
                "wheel artifact": (
                    wheel_artifact_dir,
                    capture_tree_snapshot(wheel_artifact_dir, label="wheel artifact"),
                ),
                "sdist artifact": (
                    sdist_artifact_dir,
                    capture_tree_snapshot(sdist_artifact_dir, label="sdist artifact"),
                ),
                "dependency lock": (
                    lock_dir,
                    capture_tree_snapshot(lock_dir, label="dependency lock"),
                ),
                "payload manifest": (
                    manifest_dir,
                    capture_tree_snapshot(manifest_dir, label="payload manifest"),
                ),
                "wheel dependency cache": (
                    wheelhouse,
                    capture_tree_snapshot(wheelhouse, label="wheel dependency cache"),
                ),
                "sdist dependency cache": (
                    sdist_wheelhouse,
                    capture_tree_snapshot(sdist_wheelhouse, label="sdist dependency cache"),
                ),
                "smoke outputs": (
                    outputs_dir,
                    capture_tree_snapshot(outputs_dir, label="smoke outputs"),
                ),
            }

            with ExitStack() as pin_stack:
                pinned = tuple(
                    pin_private_directory(temp_dir, path.name, pin_stack)
                    for path in private_directories
                )
                built_wheel = build_sdist_wheel(
                    build_python,
                    sdist_wheelhouse,
                    sdist_artifact,
                    built_wheel_dir,
                    expected_snapshot=sdist_snapshot,
                    cwd=temp_dir,
                )
                built_wheel_snapshot = capture_file_snapshot(
                    built_wheel,
                    max_bytes=MAX_DISTRIBUTION_BYTES,
                    label="independently built sdist wheel",
                )
                built_wheel.chmod(stat.S_IREAD)
                built_missing, built_forbidden = inspect_wheel(built_wheel)
                if built_missing or built_forbidden:
                    raise ValueError("independently built sdist wheel content verification failed")
                validate_distribution_identity(built_wheel, verified_sdist)
                validate_wheel_archive_equivalence(verified_wheel, built_wheel)
                assert_tree_snapshot_unchanged(
                    build_phase,
                    build_baseline,
                    label="build environment",
                )
                assert_tree_snapshot_unchanged(
                    wheel_phase,
                    wheel_baseline,
                    label="wheel environment",
                )
                assert_tree_snapshot_unchanged(
                    sdist_phase,
                    sdist_baseline,
                    label="sdist environment",
                )
                for protected_label, (
                    protected_root,
                    protected_snapshot,
                ) in protected_roots.items():
                    assert_tree_snapshot_unchanged(
                        protected_root,
                        protected_snapshot,
                        label=protected_label,
                    )
                for directory_pin in pinned:
                    assert_pinned_directory(temp_dir, directory_pin)

                install_exact_distribution(
                    python,
                    wheelhouse,
                    wheel_artifact,
                    expected_snapshot=wheel_snapshot,
                    cwd=temp_dir,
                )
                wheel_installed = capture_tree_snapshot(
                    wheel_phase,
                    label="installed wheel environment",
                    allowed_directory_links=wheel_baseline.links,
                )
                validate_project_install_delta(
                    wheel_baseline,
                    wheel_installed,
                    environment_root=wheel_phase,
                    layout=EnvironmentLayout(
                        purelib=_portable_join("venv", wheel_layout.purelib),
                        scripts=_portable_join("venv", wheel_layout.scripts),
                    ),
                    wheel=wheel_artifact,
                    wheel_snapshot=wheel_snapshot,
                    label="published wheel install",
                )
                assert_tree_snapshot_unchanged(
                    sdist_phase,
                    sdist_baseline,
                    label="sdist environment",
                )
                install_exact_distribution(
                    sdist_python,
                    sdist_wheelhouse,
                    built_wheel,
                    expected_snapshot=built_wheel_snapshot,
                    cwd=temp_dir,
                )
                sdist_installed = capture_tree_snapshot(
                    sdist_phase,
                    label="installed sdist-built-wheel environment",
                    allowed_directory_links=sdist_baseline.links,
                )
                validate_project_install_delta(
                    sdist_baseline,
                    sdist_installed,
                    environment_root=sdist_phase,
                    layout=EnvironmentLayout(
                        purelib=_portable_join("venv", sdist_layout.purelib),
                        scripts=_portable_join("venv", sdist_layout.scripts),
                    ),
                    wheel=built_wheel,
                    wheel_snapshot=built_wheel_snapshot,
                    label="sdist-built wheel install",
                )
                assert_tree_snapshot_unchanged(
                    wheel_phase,
                    wheel_installed,
                    label="installed wheel environment",
                )
                for directory_pin in pinned:
                    assert_pinned_directory(temp_dir, directory_pin)
            run(
                [
                    str(python),
                    "-c",
                    _installed_package_payload_assertion(
                        verified_payload_manifest,
                        payload_manifest_snapshot,
                    ),
                ],
                cwd=temp_dir,
            )
            assert_snapshot_unchanged(verified_payload_manifest, payload_manifest_snapshot)
            run(
                [
                    str(python),
                    "-c",
                    _wheel_import_assertion(venv_dir),
                ],
                cwd=temp_dir,
            )
            run(
                [
                    str(python),
                    "-c",
                    _packaged_example_assertion(),
                ],
                cwd=temp_dir,
            )
            run(
                [
                    str(python),
                    "-c",
                    _packaged_schema_resource_assertion(),
                ],
                cwd=temp_dir,
            )
            run(
                [
                    str(python),
                    "-c",
                    _installed_wheel_campaign_assertion(),
                ],
                cwd=temp_dir,
            )
            run(
                [
                    str(python),
                    "-c",
                    _demo_network_guard_assertion(),
                ],
                cwd=temp_dir,
            )
            run(
                [
                    sys.executable,
                    "-c",
                    _direct_wheel_zip_import_assertion(wheel_artifact),
                ],
                cwd=temp_dir,
                extra_env=_guarded_demo_env(temp_dir),
            )
            assert_snapshot_unchanged(wheel_artifact, wheel_snapshot)
            run(
                [str(agent_assure), "--version"],
                cwd=temp_dir,
                required_stdout_fragments=(expected_version,),
            )
            run(
                [str(agent_assure), "controls", "mutate", "--help"],
                cwd=temp_dir,
            )
            run(
                [str(agent_assure), "schema", "export", "--out", str(schema_dir)],
                cwd=temp_dir,
            )
            run(
                [
                    str(agent_assure),
                    "demo",
                    "flagship",
                    "--out",
                    str(flagship_dir),
                    "--clean",
                ],
                cwd=temp_dir,
                extra_env=_guarded_demo_env(temp_dir),
            )
            run(
                [
                    str(agent_assure),
                    "demo",
                    "assure-the-assurance",
                    "--out",
                    str(assurance_demo_dir),
                    "--clean",
                ],
                cwd=temp_dir,
                extra_env=_guarded_demo_env(temp_dir),
            )
            first_summary = (assurance_demo_dir / "demo-summary.json").read_bytes()
            run(
                [
                    str(python),
                    "-c",
                    _installed_assurance_demo_assertion(assurance_demo_dir),
                ],
                cwd=temp_dir,
                extra_env=_guarded_demo_env(temp_dir),
            )
            run(
                [
                    str(agent_assure),
                    "demo",
                    "assure-the-assurance",
                    "--out",
                    str(assurance_demo_dir),
                    "--no-clean",
                    "--format",
                    "json",
                    "--strict",
                ],
                cwd=temp_dir,
                expected_exit_codes=(1,),
                required_stdout_fragments=(
                    '"status": "success"',
                    '"underlying_exit_code": 1',
                ),
                extra_env=_guarded_demo_env(temp_dir),
            )
            if (assurance_demo_dir / "demo-summary.json").read_bytes() != first_summary:
                raise RuntimeError(
                    "assure-the-assurance demo was not deterministic across clean and "
                    "no-clean installed-wheel runs"
                )
            run(
                [
                    str(agent_assure),
                    "demo",
                    "evidence-sensitivity",
                    "--out",
                    str(sensitivity_demo_dir),
                    "--clean",
                    "--format",
                    "json",
                ],
                cwd=temp_dir,
                required_stdout_fragments=(
                    '"status": "success"',
                    '"underlying_exit_code": 1',
                ),
                extra_env=_guarded_demo_env(temp_dir),
            )
            first_sensitivity_summary = (sensitivity_demo_dir / "demo-summary.json").read_bytes()
            run(
                [
                    str(python),
                    "-c",
                    _installed_evidence_sensitivity_demo_assertion(sensitivity_demo_dir),
                ],
                cwd=temp_dir,
                extra_env=_guarded_demo_env(temp_dir),
            )
            sensitivity_example_dir = sensitivity_demo_dir / "example" / "evidence_sensitivity"
            run(
                [
                    str(agent_assure),
                    "rag",
                    "sensitivity",
                    "--suite",
                    str(sensitivity_example_dir / "evidence_reversed_suite.yaml"),
                    "--baseline-corpus",
                    str(sensitivity_example_dir / "corpora" / "policy_a"),
                    "--counterfactual-corpus",
                    str(sensitivity_example_dir / "corpora" / "policy_b"),
                    "--knowledge-contract",
                    str(sensitivity_example_dir / "knowledge-contract.yaml"),
                    "--expected-relation",
                    "decision_flip",
                    "--out",
                    str(sensitivity_reversed_dir),
                ],
                cwd=temp_dir,
                expected_exit_codes=(1,),
                required_stdout_fragments=(
                    "controlled evidence sensitivity state: evidence_insensitive",
                    "gate effect: block",
                    "outcome classification: wrong_direction_flip",
                    "wrong direction relative to the authority contract",
                    "expected relation: decision_flip",
                    "observed relation: decision_flip",
                    "decision inertia detected: false",
                ),
                extra_env=_guarded_demo_env(temp_dir),
            )
            run(
                [
                    str(python),
                    "-c",
                    _installed_evidence_reversed_assertion(sensitivity_reversed_dir),
                ],
                cwd=temp_dir,
                extra_env=_guarded_demo_env(temp_dir),
            )
            run(
                [
                    str(agent_assure),
                    "demo",
                    "evidence-sensitivity",
                    "--out",
                    str(sensitivity_demo_dir),
                    "--no-clean",
                    "--format",
                    "json",
                    "--strict",
                ],
                cwd=temp_dir,
                expected_exit_codes=(1,),
                required_stdout_fragments=(
                    '"status": "success"',
                    '"underlying_exit_code": 1',
                ),
                extra_env=_guarded_demo_env(temp_dir),
            )
            if (
                sensitivity_demo_dir / "demo-summary.json"
            ).read_bytes() != first_sensitivity_summary:
                raise RuntimeError(
                    "evidence-sensitivity demo was not deterministic across clean and "
                    "no-clean installed-wheel runs"
                )
            assert_tree_snapshot_unchanged(
                wheel_phase,
                wheel_installed,
                label="installed wheel environment",
            )
            assert_tree_snapshot_unchanged(
                sdist_phase,
                sdist_installed,
                label="installed sdist-built-wheel environment",
            )
            run(
                [
                    str(sdist_python),
                    "-c",
                    _installed_package_payload_assertion(
                        verified_payload_manifest,
                        payload_manifest_snapshot,
                    ),
                ],
                cwd=temp_dir,
            )
            assert_tree_snapshot_unchanged(
                wheel_phase,
                wheel_installed,
                label="installed wheel environment",
            )
            assert_tree_snapshot_unchanged(
                sdist_phase,
                sdist_installed,
                label="installed sdist-built-wheel environment",
            )
            assert_snapshot_unchanged(verified_payload_manifest, payload_manifest_snapshot)
            run(
                [str(sdist_python), "-c", _wheel_import_assertion(sdist_venv_dir)],
                cwd=temp_dir,
            )
            run([str(sdist_python), "-c", _packaged_example_assertion()], cwd=temp_dir)
            run(
                [str(sdist_python), "-c", _packaged_schema_resource_assertion()],
                cwd=temp_dir,
            )
            run(
                [str(sdist_python), "-c", _installed_wheel_campaign_assertion()],
                cwd=temp_dir,
            )
            run(
                [str(sdist_agent_assure), "--version"],
                cwd=temp_dir,
                required_stdout_fragments=(expected_version,),
            )
            run(
                [str(sdist_agent_assure), "controls", "mutate", "--help"],
                cwd=temp_dir,
            )
            run(
                [
                    str(sdist_agent_assure),
                    "schema",
                    "export",
                    "--out",
                    str(sdist_schema_dir),
                ],
                cwd=temp_dir,
            )
            assert_tree_snapshot_unchanged(
                wheel_phase,
                wheel_installed,
                label="installed wheel environment",
            )
            assert_tree_snapshot_unchanged(
                sdist_phase,
                sdist_installed,
                label="installed sdist-built-wheel environment",
            )
    except (
        OSError,
        RuntimeError,
        tarfile.TarError,
        UnicodeError,
        ValueError,
        zipfile.BadZipFile,
    ) as exc:
        print(f"wheel-smoke: {exc}", file=sys.stderr)
        return 1

    print(f"distribution-smoke: ok ({wheel.name}, {sdist.name})")
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Independently install and smoke test the local wheel and sdist."
    )
    parser.add_argument(
        "--dist",
        type=Path,
        default=DIST,
        help="Directory containing exactly one built wheel and sdist. Defaults to dist/.",
    )
    parser.add_argument(
        "--lockfile",
        type=Path,
        default=LOCKFILE,
        help="Hash-locked dependency file used to populate the local wheelhouse.",
    )
    return parser.parse_args(argv)


def find_single_wheel(dist_dir: Path) -> Path:
    wheels = sorted(dist_dir.glob("*.whl"))
    if len(wheels) != 1:
        wheel_list = ", ".join(wheel.name for wheel in wheels) or "none"
        raise ValueError(f"expected exactly one wheel in {dist_dir}, found {wheel_list}")
    return wheels[0]


def find_single_sdist(dist_dir: Path) -> Path:
    sdists = sorted(dist_dir.glob("*.tar.gz"))
    if len(sdists) != 1:
        sdist_list = ", ".join(sdist.name for sdist in sdists) or "none"
        raise ValueError(f"expected exactly one sdist in {dist_dir}, found {sdist_list}")
    return sdists[0]


def capture_file_snapshot(
    path: Path,
    *,
    max_bytes: int,
    label: str,
) -> DistributionSnapshot:
    contents = read_file_bounded(path, max_bytes=max_bytes, label=label)
    return DistributionSnapshot(
        name=path.name,
        data=contents.data,
        sha256=contents.sha256,
    )


def create_private_directory(path: Path) -> None:
    """Create one trusted directory exclusively and reject link-like results."""
    path.mkdir(mode=0o700, parents=False, exist_ok=False)
    _require_regular_directory(path, label="private directory")


def _require_regular_directory(path: Path, *, label: str) -> os.stat_result:
    metadata = os.lstat(path)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or bool(getattr(metadata, "st_file_attributes", 0) & _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT)
    ):
        raise ValueError(f"{label} is not a regular directory: {path}")
    return metadata


def pin_private_directory(
    root: Path,
    relative_path: str,
    stack: ExitStack,
) -> PinnedDirectory:
    lease = stack.enter_context(
        open_directory_at(root, relative_path, label="smoke-test private directory")
    )
    return PinnedDirectory(relative_path=relative_path, lease=lease)


def assert_pinned_directory(root: Path, pinned: PinnedDirectory) -> None:
    with open_directory_at(
        root,
        pinned.relative_path,
        label="smoke-test private directory",
    ) as current:
        if (current.device, current.inode) != (pinned.lease.device, pinned.lease.inode):
            raise ValueError(
                "smoke-test private directory identity changed: " + pinned.relative_path
            )


def materialize_snapshot(
    snapshot: DistributionSnapshot,
    directory: Path,
    *,
    prepared: bool = False,
) -> Path:
    if prepared:
        _require_regular_directory(directory, label="snapshot destination")
    else:
        create_private_directory(directory)
    destination = directory / snapshot.name
    with destination.open("xb") as handle:
        handle.write(snapshot.data)
        handle.flush()
        os.fsync(handle.fileno())
    destination.chmod(stat.S_IREAD)
    assert_snapshot_unchanged(destination, snapshot)
    return destination


def assert_snapshot_unchanged(path: Path, snapshot: DistributionSnapshot) -> None:
    if path.name != snapshot.name:
        raise ValueError("distribution snapshot filename changed")
    try:
        contents = read_file_bounded(
            path,
            max_bytes=len(snapshot.data),
            label="materialized distribution snapshot",
        )
    except (OSError, ValueError) as exc:
        raise ValueError(f"materialized distribution bytes changed: {path}") from exc
    if (
        contents.size != len(snapshot.data)
        or contents.sha256 != snapshot.sha256
        or contents.data != snapshot.data
    ):
        raise ValueError(f"materialized distribution bytes changed: {path}")


def _expected_virtualenv_directory_links() -> dict[str, str]:
    """Return the exact directory alias created by CPython's venv implementation."""
    if sys.maxsize > 2**32 and os.name == "posix" and sys.platform != "darwin":
        return {"venv/lib64": "lib"}
    return {}


def _link_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def capture_tree_snapshot(
    root: Path,
    *,
    label: str,
    allowed_directory_links: dict[str, str] | None = None,
) -> TreeSnapshot:
    """Capture a bounded, race-resistant regular-file tree manifest."""
    _require_regular_directory(root, label=label)
    allowed_links = dict(allowed_directory_links or {})
    unsupported_links = set(allowed_links) - {"venv/lib64"}
    if unsupported_links or any(target != "lib" for target in allowed_links.values()):
        raise ValueError(f"{label} declares an unsupported allowed directory link")
    directories: set[str] = set()
    files: dict[str, TreeFile] = {}
    links: dict[str, str] = {}
    portable_names: dict[str, str] = {}
    pending = [Path(".")]
    member_count = 0
    total = 0
    while pending:
        relative_directory = pending.pop()
        directory = root if relative_directory == Path(".") else root / relative_directory
        _require_regular_directory(directory, label=label)
        entries: list[os.DirEntry[str]] = []
        with os.scandir(directory) as scanned:
            for entry in scanned:
                member_count += 1
                if member_count > MAX_ENVIRONMENT_MEMBERS:
                    raise ValueError(
                        f"{label} contains more than {MAX_ENVIRONMENT_MEMBERS} entries"
                    )
                entries.append(entry)
        for entry in sorted(entries, key=lambda item: item.name, reverse=True):
            relative = (
                Path(entry.name)
                if relative_directory == Path(".")
                else relative_directory / entry.name
            )
            portable = relative.as_posix()
            collision_key = portable.casefold()
            previous = portable_names.get(collision_key)
            if previous is not None:
                raise ValueError(f"{label} has a portable path collision: {previous}, {portable}")
            portable_names[collision_key] = portable
            metadata = entry.stat(follow_symlinks=False)
            is_reparse = bool(
                getattr(metadata, "st_file_attributes", 0) & _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT
            )
            is_symlink = entry.is_symlink() or stat.S_ISLNK(metadata.st_mode)
            if is_symlink or is_reparse:
                expected_target = allowed_links.get(portable)
                if (
                    expected_target is not None
                    and os.name == "posix"
                    and entry.is_symlink()
                    and stat.S_ISLNK(metadata.st_mode)
                    and not is_reparse
                ):
                    target = os.readlink(entry.path)
                    current = os.lstat(entry.path)
                    if _link_identity(current) != _link_identity(metadata):
                        raise ValueError(f"{label} link changed while it was inspected: {portable}")
                    if target != expected_target:
                        raise ValueError(
                            f"{label} contains an unexpected directory link target: "
                            f"{portable} -> {target!r}"
                        )
                    _require_regular_directory(
                        root / relative.parent / target,
                        label=f"{label} directory link target",
                    )
                    links[portable] = target
                    continue
                raise ValueError(f"{label} contains a link or reparse point: {portable}")
            if stat.S_ISDIR(metadata.st_mode):
                directories.add(portable)
                pending.append(relative)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError(f"{label} contains a non-regular file: {portable}")
            contents = read_file_bounded_at(
                root,
                relative,
                max_bytes=MAX_ENVIRONMENT_MEMBER_BYTES,
                label=f"{label} file",
            )
            total += contents.size
            if total > MAX_ENVIRONMENT_TOTAL_BYTES:
                raise ValueError(
                    f"{label} exceeds the {MAX_ENVIRONMENT_TOTAL_BYTES}-byte aggregate limit"
                )
            files[portable] = TreeFile(size=contents.size, sha256=contents.sha256)
    return TreeSnapshot(directories=frozenset(directories), files=files, links=links)


def assert_tree_snapshot_unchanged(root: Path, expected: TreeSnapshot, *, label: str) -> None:
    actual = capture_tree_snapshot(
        root,
        label=label,
        allowed_directory_links=expected.links,
    )
    if actual != expected:
        missing = sorted(set(expected.files) - set(actual.files))
        unexpected = sorted(set(actual.files) - set(expected.files))
        drifted = sorted(
            name
            for name in set(expected.files) & set(actual.files)
            if expected.files[name] != actual.files[name]
        )
        raise ValueError(
            f"{label} changed; missing={missing}, unexpected={unexpected}, drifted={drifted}"
        )


def distribution_payload_manifest_snapshot(
    manifest: dict[str, str],
) -> DistributionSnapshot:
    data = (
        json.dumps(manifest, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return DistributionSnapshot(
        name="wheel-payload-manifest.json",
        data=data,
        sha256=hashlib.sha256(data).hexdigest(),
    )


def build_wheelhouse(wheelhouse: Path, lockfile: Path, *, prepared: bool = False) -> None:
    if prepared:
        _require_regular_directory(wheelhouse, label="dependency wheelhouse")
        if any(wheelhouse.iterdir()):
            raise ValueError(f"prepared dependency wheelhouse is not empty: {wheelhouse}")
    else:
        create_private_directory(wheelhouse)
    run(
        [
            sys.executable,
            "-m",
            "pip",
            "download",
            "--disable-pip-version-check",
            "--no-cache-dir",
            "--require-hashes",
            "--no-deps",
            "--only-binary",
            ":all:",
            "--dest",
            str(wheelhouse),
            "-r",
            str(lockfile),
        ]
    )


def create_virtualenv(venv_dir: Path) -> None:
    venv.EnvBuilder(with_pip=True, system_site_packages=False).create(venv_dir)


def install_locked_dependencies(
    python: Path,
    wheelhouse: Path,
    lockfile: Path,
    *,
    cwd: Path,
) -> None:
    run(
        [
            str(python),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-cache-dir",
            "--no-index",
            "--find-links",
            str(wheelhouse),
            "--require-hashes",
            "--no-deps",
            "--no-compile",
            "-r",
            str(lockfile),
        ],
        cwd=cwd,
    )


def build_sdist_wheel(
    python: Path,
    wheelhouse: Path,
    sdist: Path,
    output_dir: Path,
    *,
    expected_snapshot: DistributionSnapshot,
    cwd: Path,
) -> Path:
    assert_snapshot_unchanged(sdist, expected_snapshot)
    _require_regular_directory(output_dir, label="sdist wheel output")
    if any(output_dir.iterdir()):
        raise ValueError(f"sdist wheel output is not empty: {output_dir}")
    try:
        run(
            [
                str(python),
                "-m",
                "pip",
                "wheel",
                "--disable-pip-version-check",
                "--no-cache-dir",
                "--no-index",
                "--find-links",
                str(wheelhouse),
                "--no-deps",
                "--no-build-isolation",
                "--wheel-dir",
                str(output_dir),
                str(sdist),
            ],
            cwd=cwd,
        )
    finally:
        assert_snapshot_unchanged(sdist, expected_snapshot)
    wheels = tuple(output_dir.glob("*.whl"))
    if len(wheels) != 1 or any(path != wheels[0] for path in output_dir.iterdir()):
        raise ValueError("sdist build must produce exactly one wheel and no side files")
    _require_regular_directory(output_dir, label="sdist wheel output")
    return wheels[0]


def query_environment_layout(python: Path, venv_dir: Path, *, cwd: Path) -> EnvironmentLayout:
    env = {**os.environ, "PYTHONNOUSERSITE": "1", "PYTHONSAFEPATH": "1"}
    env.pop("PYTHONPATH", None)
    result = subprocess.run(
        [
            str(python),
            "-I",
            "-c",
            (
                "import json,sysconfig; "
                "print(json.dumps({key: sysconfig.get_path(key) "
                "for key in ('purelib', 'scripts')}, sort_keys=True))"
            ),
        ],
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=COMMAND_TIMEOUT_SECONDS,
    )
    if result.returncode != 0:
        raise RuntimeError("failed to query isolated install layout: " + result.stderr.strip())
    value = json.loads(result.stdout)
    if not isinstance(value, dict) or set(value) != {"purelib", "scripts"}:
        raise ValueError("isolated install layout response is malformed")
    root = venv_dir.resolve(strict=True)
    relative: dict[str, str] = {}
    for key in ("purelib", "scripts"):
        raw_path = value[key]
        if not isinstance(raw_path, str):
            raise ValueError("isolated install layout paths must be strings")
        path = Path(raw_path).resolve(strict=True)
        try:
            relative[key] = path.relative_to(root).as_posix()
        except ValueError as exc:
            raise ValueError(f"isolated {key} path escapes its virtual environment") from exc
    return EnvironmentLayout(purelib=relative["purelib"], scripts=relative["scripts"])


def validate_project_install_delta(
    before: TreeSnapshot,
    after: TreeSnapshot,
    *,
    environment_root: Path,
    layout: EnvironmentLayout,
    wheel: Path,
    wheel_snapshot: DistributionSnapshot,
    label: str,
) -> None:
    """Require the complete venv delta to be exactly one validated wheel install."""
    if before.links != after.links:
        raise ValueError(f"{label} changed virtualenv directory links")
    removed_files = sorted(set(before.files) - set(after.files))
    modified_files = sorted(
        name
        for name in set(before.files) & set(after.files)
        if before.files[name] != after.files[name]
    )
    if removed_files or modified_files:
        raise ValueError(
            f"{label} modified the dependency environment; "
            f"removed={removed_files}, modified={modified_files}"
        )

    with zipfile.ZipFile(wheel) as archive:
        regular_infos = {info.filename: info for info in archive.infolist() if not info.is_dir()}
        records = [name for name in regular_infos if name.endswith(".dist-info/RECORD")]
        if len(records) != 1:
            raise ValueError("validated wheel must contain exactly one RECORD")
        archive_record = records[0]
        dist_info = archive_record.rsplit("/", 1)[0]
        exact_files: dict[str, bytes] = {}
        expected_directories: set[str] = set()
        for info in archive.infolist():
            installed_name = _portable_join(layout.purelib, info.filename.rstrip("/"))
            if info.is_dir():
                expected_directories.add(installed_name)
            elif info.filename != archive_record:
                exact_files[installed_name] = archive.read(info)
        entry_points = _wheel_console_scripts(archive, dist_info)

    dist_info_root = _portable_join(layout.purelib, dist_info)
    installed_record = _portable_join(layout.purelib, archive_record)
    generated_files = {
        _portable_join(dist_info_root, "INSTALLER"),
        _portable_join(dist_info_root, "REQUESTED"),
        _portable_join(dist_info_root, "direct_url.json"),
        installed_record,
        *(
            _portable_join(layout.scripts, f"{name}.exe" if os.name == "nt" else name)
            for name in entry_points
        ),
    }
    expected_files = set(exact_files) | generated_files
    added_files = set(after.files) - set(before.files)
    if added_files != expected_files:
        raise ValueError(
            f"{label} full install inventory mismatch; "
            f"missing={sorted(expected_files - added_files)}, "
            f"unexpected={sorted(added_files - expected_files)}"
        )

    for name, payload in exact_files.items():
        expected = TreeFile(size=len(payload), sha256=hashlib.sha256(payload).hexdigest())
        if after.files[name] != expected:
            raise ValueError(f"{label} installed wheel byte drift: {name}")
    _require_installed_bytes(
        environment_root,
        _portable_join(dist_info_root, "INSTALLER"),
        b"pip\n",
        label=label,
    )
    _require_installed_bytes(
        environment_root,
        _portable_join(dist_info_root, "REQUESTED"),
        b"",
        label=label,
    )
    direct_url_path = _portable_join(dist_info_root, "direct_url.json")
    direct_url = json.loads(
        read_file_bounded_at(
            environment_root,
            Path(*PurePosixPath(direct_url_path).parts),
            max_bytes=1024 * 1024,
            label=f"{label} direct_url.json",
        ).data
    )
    expected_direct_url = {
        "archive_info": {
            "hash": f"sha256={wheel_snapshot.sha256}",
            "hashes": {"sha256": wheel_snapshot.sha256},
        },
        "url": wheel.resolve(strict=True).as_uri(),
    }
    if direct_url != expected_direct_url:
        raise ValueError(f"{label} direct_url.json does not bind the exact installed wheel")
    _validate_installed_record(
        environment_root,
        layout,
        installed_record,
        expected_files,
        after,
        label=label,
    )

    for file_name in expected_files:
        path = PurePosixPath(file_name)
        for parent in path.parents:
            rendered = parent.as_posix()
            if rendered != ".":
                expected_directories.add(rendered)
    added_directories = set(after.directories) - set(before.directories)
    required_added_directories = expected_directories - set(before.directories)
    if added_directories != required_added_directories:
        raise ValueError(
            f"{label} directory inventory mismatch; "
            f"missing={sorted(required_added_directories - added_directories)}, "
            f"unexpected={sorted(added_directories - required_added_directories)}"
        )
    if not set(before.directories).issubset(after.directories):
        raise ValueError(f"{label} removed dependency environment directories")


def _portable_join(*parts: str) -> str:
    return PurePosixPath(*parts).as_posix()


def _wheel_console_scripts(archive: zipfile.ZipFile, dist_info: str) -> tuple[str, ...]:
    path = f"{dist_info}/entry_points.txt"
    if path not in archive.namelist():
        return ()
    parser = _CaseSensitiveConfigParser(interpolation=None, strict=True)
    parser.read_string(archive.read(path).decode("utf-8"))
    if not parser.has_section("console_scripts"):
        return ()
    names = tuple(sorted(name.strip() for name, _value in parser.items("console_scripts")))
    if any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name) for name in names):
        raise ValueError("wheel declares a non-portable console script name")
    return names


def _require_installed_bytes(
    root: Path,
    relative_name: str,
    expected: bytes,
    *,
    label: str,
) -> None:
    actual = read_file_bounded_at(
        root,
        Path(*PurePosixPath(relative_name).parts),
        max_bytes=max(len(expected), 1),
        label=f"{label} generated install file",
    ).data
    if actual != expected:
        raise ValueError(f"{label} generated install bytes differ: {relative_name}")


def _validate_installed_record(
    root: Path,
    layout: EnvironmentLayout,
    record_name: str,
    expected_files: set[str],
    snapshot: TreeSnapshot,
    *,
    label: str,
) -> None:
    payload = read_file_bounded_at(
        root,
        Path(*PurePosixPath(record_name).parts),
        max_bytes=4 * 1024 * 1024,
        label=f"{label} installed RECORD",
    ).data
    try:
        rows = list(csv.reader(io.StringIO(payload.decode("utf-8"))))
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} installed RECORD is not UTF-8") from exc
    records: dict[str, tuple[str, str]] = {}
    for row in rows:
        if len(row) != 3 or not row[0]:
            raise ValueError(f"{label} installed RECORD contains a malformed row")
        resolved = _resolve_record_path(root, layout, row[0])
        if resolved in records:
            raise ValueError(f"{label} installed RECORD contains a duplicate path: {resolved}")
        records[resolved] = (row[1], row[2])
    if set(records) != expected_files:
        raise ValueError(
            f"{label} installed RECORD inventory mismatch; "
            f"missing={sorted(expected_files - set(records))}, "
            f"unexpected={sorted(set(records) - expected_files)}"
        )
    for name, (digest_text, size_text) in records.items():
        if name == record_name:
            if digest_text or size_text:
                raise ValueError(f"{label} installed RECORD self-entry must be unhashed")
            continue
        file_info = snapshot.files[name]
        if size_text != str(file_info.size) or not digest_text.startswith("sha256="):
            raise ValueError(f"{label} installed RECORD size/hash contract failed: {name}")
        encoded = base64.urlsafe_b64encode(bytes.fromhex(file_info.sha256)).rstrip(b"=").decode()
        if digest_text.removeprefix("sha256=") != encoded:
            raise ValueError(f"{label} installed RECORD digest mismatch: {name}")


def _resolve_record_path(root: Path, layout: EnvironmentLayout, name: str) -> str:
    if chr(92) in name:
        raise ValueError("installed RECORD paths must use portable separators")
    path = PurePosixPath(name)
    if path.is_absolute():
        raise ValueError("installed RECORD contains an absolute path")
    purelib = root.joinpath(*PurePosixPath(layout.purelib).parts)
    candidate = purelib.joinpath(*path.parts).resolve(strict=False)
    try:
        return candidate.relative_to(root.resolve(strict=True)).as_posix()
    except ValueError as exc:
        raise ValueError("installed RECORD path escapes the virtual environment") from exc


def install_exact_distribution(
    python: Path,
    wheelhouse: Path,
    artifact: Path,
    *,
    expected_snapshot: DistributionSnapshot,
    cwd: Path,
) -> None:
    assert_snapshot_unchanged(artifact, expected_snapshot)
    command = [
        str(python),
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
        "--no-cache-dir",
        "--no-deps",
        "--no-compile",
    ]
    command.extend(
        [
            "--no-index",
            "--find-links",
            str(wheelhouse),
            str(artifact),
        ]
    )
    try:
        run(command, cwd=cwd)
    finally:
        assert_snapshot_unchanged(artifact, expected_snapshot)


def venv_python(venv_dir: Path) -> Path:
    return venv_executable(venv_dir, "python")


def venv_executable(venv_dir: Path, name: str) -> Path:
    script_dir = "Scripts" if os.name == "nt" else "bin"
    suffix = ".exe" if os.name == "nt" else ""
    return venv_dir / script_dir / f"{name}{suffix}"


def run(
    args: list[str],
    *,
    cwd: Path = ROOT,
    expected_exit_codes: tuple[int, ...] = (0,),
    required_stdout_fragments: tuple[str, ...] = (),
    extra_env: dict[str, str] | None = None,
) -> None:
    env = {**os.environ, "PIP_DISABLE_PIP_VERSION_CHECK": "1"}
    env.pop("PYTHONPATH", None)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONNOUSERSITE"] = "1"
    env["PYTHONSAFEPATH"] = "1"
    if extra_env is not None:
        env.update(extra_env)
    try:
        result = subprocess.run(
            args,
            cwd=cwd,
            env=env,
            text=True,
            capture_output=True,
            check=False,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        command = " ".join(args)
        raise RuntimeError(
            f"command exceeded {COMMAND_TIMEOUT_SECONDS} seconds: {command}"
        ) from exc
    stdout_matches = all(fragment in result.stdout for fragment in required_stdout_fragments)
    if result.returncode in expected_exit_codes and stdout_matches:
        return
    command = " ".join(args)
    details = "\n".join(
        part
        for part in (
            (
                f"command returned exit {result.returncode}; expected one of "
                f"{list(expected_exit_codes)}: {command}"
            ),
            (
                "command stdout omitted required fragments: " + ", ".join(required_stdout_fragments)
                if not stdout_matches
                else ""
            ),
            result.stdout.strip(),
            result.stderr.strip(),
        )
        if part
    )
    raise RuntimeError(details)


def _wheel_import_assertion(venv_dir: Path) -> str:
    expected_prefix = str(venv_dir.resolve())
    return (
        "from pathlib import Path; "
        "import agent_assure; "
        f"expected = Path({expected_prefix!r}); "
        "actual = Path(agent_assure.__file__).resolve(); "
        "actual.relative_to(expected)"
    )


def _installed_package_payload_assertion(
    manifest_path: Path,
    manifest_snapshot: DistributionSnapshot,
) -> str:
    """Return a race-resistant installed-package inventory and digest assertion."""
    resolved_manifest = str(manifest_path.resolve())
    return f"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys

MAX_MEMBERS = {10_000}
MAX_MEMBER_BYTES = {32 * 1024 * 1024}
MAX_TOTAL_BYTES = {256 * 1024 * 1024}
WINDOWS_REPARSE_POINT = 0x400
manifest_path = Path({resolved_manifest!r})
manifest_data = manifest_path.read_bytes()
if len(manifest_data) != {len(manifest_snapshot.data)}:
    raise AssertionError("trusted wheel payload manifest size changed")
if hashlib.sha256(manifest_data).hexdigest() != {manifest_snapshot.sha256!r}:
    raise AssertionError("trusted wheel payload manifest digest changed")
expected = json.loads(manifest_data)
if not isinstance(expected, dict) or not expected:
    raise AssertionError("trusted wheel payload manifest must be a non-empty object")
for name, digest in expected.items():
    if (
        not isinstance(name, str)
        or not name.startswith("agent_assure/")
        or chr(92) in name
        or any(part in ("", ".", "..") for part in name.split("/"))
    ):
        raise AssertionError(f"invalid trusted wheel payload path: {{name!r}}")
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise AssertionError(f"invalid trusted wheel payload digest: {{name}}")

spec = importlib.util.find_spec("agent_assure")
if spec is None or spec.origin is None or spec.submodule_search_locations is None:
    raise AssertionError("installed agent_assure package cannot be located")
locations = tuple(spec.submodule_search_locations)
if len(locations) != 1:
    raise AssertionError("installed agent_assure package must have one search location")
root = Path(locations[0])
origin = Path(spec.origin)
if origin.name != "__init__.py" or origin.parent.resolve(strict=True) != root.resolve(strict=True):
    raise AssertionError("installed agent_assure package has an unexpected import origin")
try:
    root.resolve(strict=True).relative_to(Path(sys.prefix).resolve(strict=True))
except ValueError as exc:
    raise AssertionError(
        "installed agent_assure package is outside the isolated environment"
    ) from exc

def is_reparse(metadata):
    return bool(getattr(metadata, "st_file_attributes", 0) & WINDOWS_REPARSE_POINT)

def identity(metadata):
    return (
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        getattr(metadata, "st_file_attributes", 0),
    )

def same_identity(left, right):
    if identity(left) != identity(right):
        return False
    left_file_id = (left.st_dev, left.st_ino)
    right_file_id = (right.st_dev, right.st_ino)
    return 0 in (*left_file_id, *right_file_id) or left_file_id == right_file_id

root_metadata = os.lstat(root)
if (
    not stat.S_ISDIR(root_metadata.st_mode)
    or stat.S_ISLNK(root_metadata.st_mode)
    or is_reparse(root_metadata)
):
    raise AssertionError("installed agent_assure package root is not a regular directory")

actual = {{}}
pending = [root]
member_count = 0
total_bytes = 0
while pending:
    directory = pending.pop()
    entries = []
    with os.scandir(directory) as scanned:
        for entry in scanned:
            member_count += 1
            if member_count > MAX_MEMBERS:
                raise AssertionError("installed agent_assure package has too many entries")
            entries.append(entry)
    for entry in sorted(entries, key=lambda item: item.name, reverse=True):
        metadata = entry.stat(follow_symlinks=False)
        relative = Path(entry.path).relative_to(root)
        relative_parts = relative.parts
        if entry.is_symlink() or stat.S_ISLNK(metadata.st_mode) or is_reparse(metadata):
            raise AssertionError(
                f"installed package contains a link or reparse point: {{relative}}"
            )
        if stat.S_ISDIR(metadata.st_mode):
            pending.append(Path(entry.path))
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise AssertionError(f"installed package contains a non-regular file: {{relative}}")
        if "__pycache__" in relative_parts or entry.name.endswith(".pyc"):
            continue
        wheel_name = "agent_assure/" + relative.as_posix()
        if wheel_name not in expected:
            raise AssertionError(f"installed package contains an unexpected file: {{wheel_name}}")
        if metadata.st_size > MAX_MEMBER_BYTES:
            raise AssertionError(f"installed package file exceeds the size limit: {{wheel_name}}")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(entry.path, flags)
        try:
            opened_metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened_metadata.st_mode)
                or is_reparse(opened_metadata)
                or not same_identity(opened_metadata, metadata)
            ):
                raise AssertionError(f"installed package file changed before read: {{wheel_name}}")
            digest = hashlib.sha256()
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                while True:
                    chunk = handle.read(1024 * 1024)
                    if not chunk:
                        break
                    total_bytes += len(chunk)
                    if total_bytes > MAX_TOTAL_BYTES:
                        raise AssertionError("installed package exceeds the aggregate size limit")
                    digest.update(chunk)
            final_metadata = os.fstat(descriptor)
            if not same_identity(final_metadata, opened_metadata):
                raise AssertionError(f"installed package file changed during read: {{wheel_name}}")
        finally:
            os.close(descriptor)
        latest_metadata = os.stat(entry.path, follow_symlinks=False)
        if not same_identity(latest_metadata, metadata):
            raise AssertionError(f"installed package file changed after read: {{wheel_name}}")
        actual[wheel_name] = digest.hexdigest()

missing = sorted(set(expected) - set(actual))
unexpected = sorted(set(actual) - set(expected))
if missing or unexpected:
    raise AssertionError(
        f"installed package inventory mismatch; missing={{missing}}, unexpected={{unexpected}}"
    )
drifted = sorted(name for name in expected if actual[name] != expected[name])
if drifted:
    raise AssertionError(f"installed package payload digest mismatch: {{drifted}}")
"""


def _direct_wheel_zip_import_assertion(wheel: Path) -> str:
    wheel_path = str(wheel.resolve())
    return (
        "import sys; "
        f"wheel = {wheel_path!r}; "
        "sys.path.insert(0, wheel); "
        "import agent_assure; "
        "assert wheel in agent_assure.__file__; "
        "from agent_assure.cli.main import app; "
        "assert app is not None; "
        "from agent_assure.mutation.catalog import registered_operators; "
        "from agent_assure.mutation.campaign import build_core_catalog; "
        "operators = registered_operators(); "
        "assert len(operators) == 7; "
        "catalog = build_core_catalog(operators); "
        "assert catalog.catalog_id == 'core/v1'; "
        "assert len(catalog.operators) == 7"
    )


def _packaged_example_assertion() -> str:
    required = (
        "prior_auth_synthetic/suite.yaml",
        "prior_auth_synthetic/variants/baseline.yaml",
        "prior_auth_synthetic/variants/candidate_evidence_normalization.yaml",
        "prior_auth_synthetic/fixtures/shared/requests/shared-source-multi-claim.json",
        "expense_approval_minimal/suite.yaml",
        "expense_approval_minimal/variants/baseline.yaml",
        "expense_approval_minimal/variants/candidate_provider_policy.yaml",
        "expense_approval_minimal/fixtures/shared/requests/exp-001.json",
        "streaming_process_regression/suite.yaml",
        "streaming_process_regression/events/candidate_retry_burst.jsonl",
        *(
            f"evidence_sensitivity/{relative_path}"
            for relative_path in EVIDENCE_SENSITIVITY_REQUIRED_RESOURCE_PATHS
        ),
        "process_equivalence_reproduction_index.json",
    )
    # The exact benchmark inventory contains hundreds of repetitive paths.
    # Transport it losslessly in compressed form so the Windows CreateProcess
    # command line remains well below its platform limit.
    encoded_benchmark_inventory = base64.b85encode(
        zlib.compress(
            json.dumps(
                PROCESS_EQUIVALENCE_BENCHMARK_REQUIRED_RESOURCE_PATHS,
                ensure_ascii=True,
                separators=(",", ":"),
            ).encode("utf-8"),
            level=9,
        )
    ).decode("ascii")
    assertion = (
        "import base64,json,zlib; from importlib.resources import files; "
        f"required = {required!r}; "
        "benchmark = json.loads(zlib.decompress(base64.b85decode("
        f"{encoded_benchmark_inventory!r})).decode('utf-8')); "
        "required += tuple('process_equivalence_benchmark_v0_2/' + name "
        "for name in benchmark); "
        "root = files('agent_assure.examples'); "
        "missing = [name for name in required if not root.joinpath(name).is_file()]; "
        "raise SystemExit('missing packaged examples: ' + ', '.join(missing) if missing else 0)"
    )
    if len(assertion) > _MAX_INLINE_PYTHON_ASSERTION_CHARS:
        raise ValueError("packaged-example assertion exceeds the safe inline command bound")
    return assertion


def _packaged_schema_resource_assertion() -> str:
    required = _frozen_schema_resource_paths()
    return (
        "from importlib.resources import files; "
        f"required = {required!r}; "
        "root = files('agent_assure.schema_resources'); "
        "missing = [name for name in required if not root.joinpath(name).is_file()]; "
        "raise SystemExit('missing packaged schema resources: ' + ', '.join(missing) "
        "if missing else 0)"
    )


def _installed_wheel_campaign_assertion() -> str:
    """Return an offline core-catalog campaign exercised only from installed code."""
    return """
from copy import deepcopy
import socket
import sys

_connect_probe = socket.socket()
_connect_ex_probe = socket.socket()
_blocked_network_events = []

def reject_network_helper(*_args, **_kwargs):
    _blocked_network_events.append("socket-helper")
    raise AssertionError("mutation campaign attempted network access")

def reject_socket_audit_event(event, _args):
    if event.startswith("socket."):
        _blocked_network_events.append(event)
        raise AssertionError("mutation campaign attempted network access")

socket.create_connection = reject_network_helper
socket.getaddrinfo = reject_network_helper
sys.addaudithook(reject_socket_audit_event)

for probe, operation in (
    (_connect_probe, "connect"),
    (_connect_ex_probe, "connect_ex"),
):
    try:
        getattr(probe, operation)(("127.0.0.1", 9))
    except AssertionError:
        pass
    else:
        raise AssertionError(f"raw socket {operation} bypassed the network guard")
    finally:
        probe.close()

assert len(_blocked_network_events) == 2
_guard_probe_event_count = len(_blocked_network_events)

from agent_assure.fixtures.loader import compiled_suite_digest
from agent_assure.mutation.campaign import execute_mutation_campaign
from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.schema.expectation import Expectation
from agent_assure.schema.provenance import Provenance
from agent_assure.schema.run import (
    AgentRunRecord,
    ClaimEvidenceLink,
    EvidenceItem,
    EvidenceRef,
    RunSet,
)
from agent_assure.schema.suite import CompiledSuite, SuiteCase, SuiteDefaults

suite = CompiledSuite(
    suite_id="installed-wheel-campaign",
    suite_version="1.0.0",
    cases=(
        SuiteCase(
            case_id="case-a",
            title="Installed wheel campaign",
            expectation_id="expectation-a",
        ),
    ),
    resolved_expectations=(
        Expectation(
            expectation_id="expectation-a",
            case_id="case-a",
            material_claim_ids=("claim-a",),
            forbidden_tools=("blocked-tool",),
            required_human_review=True,
        ),
    ),
    defaults=SuiteDefaults(
        runner_id="installed.wheel",
        allowed_tools=("safe-tool",),
    ),
    source_digest="a" * 64,
)
fixture_digest = "b" * 64
runset = RunSet(
    runset_id="installed-wheel-campaign-runset",
    privacy_profile_id=PRIVACY_PROFILE_ID,
    privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
    suite_id=suite.suite_id,
    suite_version=suite.suite_version,
    suite_digest=compiled_suite_digest(suite),
    fixture_manifest_digest=fixture_digest,
    runs=(
        AgentRunRecord(
            run_id="run-a",
            case_id="case-a",
            pipeline_id="installed.wheel",
            recommendation="approve",
            outcome="approved",
            input_summary="synthetic fixture input",
            output_summary="synthetic fixture output",
            tools=("safe-tool",),
            evidence_refs=(
                EvidenceRef(
                    ref_id="evidence-a",
                    source_id="source-a",
                    claim_ids=("claim-a",),
                ),
            ),
            evidence_items=(
                EvidenceItem(
                    ref_id="evidence-a",
                    source_id="source-a",
                    content_digest="c" * 64,
                ),
            ),
            claim_evidence_links=(
                ClaimEvidenceLink(
                    claim_id="claim-a",
                    evidence_ref_id="evidence-a",
                ),
            ),
            human_review_required=True,
            human_review_performed=True,
            provenance=Provenance(fixture_manifest_digest=fixture_digest),
        ),
    ),
)
source = runset.model_dump(mode="json")
source_snapshot = deepcopy(source)
kwargs = {
    "seed": 17,
    "generated_at": "2026-07-29T00:00:00Z",
}
first = execute_mutation_campaign(suite, source, **kwargs)
second = execute_mutation_campaign(suite, source, **kwargs)

assert source == source_snapshot
assert first.catalog.catalog_id == "core/v1"
assert len(first.catalog.operators) == 7
canonical_order = tuple(item.descriptor.operator_id for item in first.catalog.operators)
assert canonical_order == tuple(sorted(canonical_order))
assert first.campaign.canonical_operator_order == canonical_order
assert first.campaign.selected_operator_order == canonical_order
assert first.campaign.executed_operator_order == canonical_order
assert first.campaign.pending_operator_order == ()
assert len(first.campaign.operator_results) == 7
assert all(item.result.state.value == "caught" for item in first.campaign.operator_results)
assert first.campaign.campaign_digest == second.campaign.campaign_digest
assert len(_blocked_network_events) == _guard_probe_event_count
"""


def _demo_network_guard_assertion() -> str:
    probe = (
        "import socket; "
        "socket.socket(socket.AF_INET, socket.SOCK_DGRAM)."
        "sendto(b'agent-assure-offline-probe', ('127.0.0.1', 9))"
    )
    expected = "network access is disabled for agent-assure demo subprocesses"
    return (
        "from pathlib import Path; "
        "import os, subprocess, sys; "
        "from agent_assure.demo.common import demo_subprocess_env; "
        "out = Path.cwd() / 'network-guard-check'; "
        "out.mkdir(parents=True, exist_ok=True); "
        "env = demo_subprocess_env(out, env=os.environ.copy()); "
        f"result = subprocess.run([sys.executable, '-c', {probe!r}], "
        "cwd=out, env=env, text=True, capture_output=True, check=False); "
        f"expected = {expected!r}; "
        "raise SystemExit(0 if result.returncode != 0 and expected in result.stderr "
        "else 'demo network guard did not block UDP sendto')"
    )


def _guarded_demo_env(temp_dir: Path) -> dict[str, str]:
    guard_dir = temp_dir / "network-guard-check" / ".runtime"
    if not (guard_dir / "sitecustomize.py").is_file():
        raise RuntimeError("installed-wheel demo network guard was not created")
    return {
        "PYTHONPATH": str(guard_dir),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONSAFEPATH": "1",
        "AGENT_ASSURE_DEMO_NETWORK_DISABLED": "1",
    }


def _installed_assurance_demo_assertion(out_dir: Path) -> str:
    root = str(out_dir.resolve())
    return f"""
import hashlib
import json
from pathlib import Path

from agent_assure.reporting.campaign import validate_mutation_campaign_artifact_generation
from agent_assure.schema.validation import validate_artifact

root = Path({root!r})
summary = json.loads((root / "demo-summary.json").read_text(encoding="utf-8"))
expected = {{
    "demo": "assure-the-assurance",
    "status": "success",
    "underlying_exit_code": 1,
    "ordinary_baseline_state": "pass",
    "strong_mutation_state": "caught",
    "weakened_mutation_state": "survived",
    "control_efficacy_gate_state": "fail",
    "required_survivor_count": 1,
    "critical_survivor_count": 1,
    "unrelated_failure_counted_as_detection": False,
    "unrelated_failure_detector_state": "survived",
}}
assert {{key: summary[key] for key in expected}} == expected
assert str(root) not in json.dumps(summary)
artifacts = summary["artifacts"]
assert all(not Path(relative).is_absolute() for relative in artifacts.values())
assert all((root / relative).exists() for relative in artifacts.values())
for name, expected_digest in summary["artifact_sha256"].items():
    actual = hashlib.sha256((root / artifacts[name]).read_bytes()).hexdigest()
    assert actual == expected_digest
validate_mutation_campaign_artifact_generation(
    (root / artifacts["strong_campaign_generation"]).parent
)
validate_mutation_campaign_artifact_generation(
    (root / artifacts["weakened_campaign_generation"]).parent
)
assert validate_artifact(
    root / artifacts["control_efficacy_report"], "control-efficacy-report"
) == "pydantic+jsonschema"
assert validate_artifact(
    root / artifacts["evidence_packet"], "evidence-packet"
) == "pydantic+jsonschema"
commands = {{item["name"]: item for item in summary["commands"]}}
assert commands["ci-gate-efficacy-packet"]["actual_exit_code"] == 1
assert all(item["matched"] is True for item in commands.values())
"""


def _installed_evidence_sensitivity_demo_assertion(out_dir: Path) -> str:
    root = str(out_dir.resolve())
    return f"""
import json
from pathlib import Path

from agent_assure.rag.sensitivity import load_sensitivity_report
from agent_assure.schema.common import GateState
from agent_assure.schema.sensitivity import (
    DetectorTestStatus,
    EvidenceSensitivityGateEffect,
    EvidenceSensitivityReasonCode,
    EvidenceSensitivityState,
    RAGSensitivityDecision,
)

root = Path({root!r})
summary = json.loads((root / "demo-summary.json").read_text(encoding="utf-8"))
assert summary["demo"] == "evidence-sensitivity"
assert summary["status"] == "success"
assert summary["underlying_exit_code"] == 1
assert summary["expected_behavior_observed"] is True
assert "not a causal guarantee" in summary["notice"]
assert str(root) not in json.dumps(summary)
artifacts = summary["artifacts"]
assert all(not Path(relative).is_absolute() for relative in artifacts.values())
assert all((root / relative).is_file() for relative in artifacts.values())

responsive = load_sensitivity_report(root / artifacts["responsive_report"])
inertial = load_sensitivity_report(root / artifacts["inertial_report"])
assert responsive.state is EvidenceSensitivityState.responsive
assert responsive.gate_effect is EvidenceSensitivityGateEffect.pass_
assert responsive.endpoint_value is True
assert responsive.baseline_arm.decision is RAGSensitivityDecision.approve
assert responsive.counterfactual_arm.decision is RAGSensitivityDecision.deny
assert inertial.state is EvidenceSensitivityState.evidence_insensitive
assert inertial.gate_effect is EvidenceSensitivityGateEffect.block
assert inertial.endpoint_value is False
assert inertial.baseline_arm.decision is RAGSensitivityDecision.approve
assert inertial.counterfactual_arm.decision is RAGSensitivityDecision.approve
assert inertial.reason_codes == (
    EvidenceSensitivityReasonCode.expected_response_missing,
)
assert inertial.decision_inertia_finding.detected is True
assert inertial.detector_test_status is DetectorTestStatus.synthetic_detector_contract_test
assert inertial.baseline_arm.evaluation_state is GateState.pass_
assert inertial.counterfactual_arm.evaluation_state is GateState.pass_
assert inertial.baseline_arm.governing_evidence_supported is True
assert inertial.counterfactual_arm.governing_evidence_supported is True
assert inertial.baseline_arm.evidence_link_present is True
assert inertial.counterfactual_arm.evidence_link_present is True
commands = {{item["name"]: item for item in summary["commands"]}}
assert commands["responsive-sensitivity"]["actual_exit_code"] == 0
assert commands["evidence-inertial-sensitivity"]["actual_exit_code"] == 1
assert all(item["matched"] is True for item in commands.values())
"""


def _installed_evidence_reversed_assertion(out_dir: Path) -> str:
    root = str(out_dir.resolve())
    return f"""
from pathlib import Path

from agent_assure.rag.sensitivity import load_sensitivity_report
from agent_assure.reporting.packet import load_comparison_summary
from agent_assure.schema.common import GateState
from agent_assure.schema.sensitivity import (
    EvidenceSensitivityGateEffect,
    EvidenceSensitivityObservedRelation,
    EvidenceSensitivityOutcomeClassification,
    EvidenceSensitivityReasonCode,
    EvidenceSensitivityState,
    RAGSensitivityDecision,
)
from agent_assure.sensitivity_comparison import derive_sensitivity_comparison

root = Path({root!r})
for name in (
    "comparison-summary.json",
    "evidence-sensitivity.json",
    "evidence-sensitivity.md",
    "evidence-sensitivity.html",
):
    assert (root / name).is_file(), name
report = load_sensitivity_report(root / "evidence-sensitivity.json")
comparison = load_comparison_summary(root / "comparison-summary.json")
assert comparison == derive_sensitivity_comparison(report)
assert comparison.baseline_runset_digest == report.baseline_arm.runset_digest
assert comparison.candidate_runset_digest == report.counterfactual_arm.runset_digest
assert report.state is EvidenceSensitivityState.evidence_insensitive
assert report.gate_effect is EvidenceSensitivityGateEffect.block
assert report.verdict_bearing is True
assert report.endpoint_value is False
assert report.observed_relation is EvidenceSensitivityObservedRelation.decision_flip
assert (
    report.outcome_classification
    is EvidenceSensitivityOutcomeClassification.wrong_direction_flip
)
assert "wrong direction relative to the authority contract" in report.outcome_message
assert report.baseline_arm.decision is RAGSensitivityDecision.deny
assert report.counterfactual_arm.decision is RAGSensitivityDecision.approve
assert report.baseline_arm.evaluation_state is GateState.pass_
assert report.counterfactual_arm.evaluation_state is GateState.pass_
assert report.baseline_arm.governing_evidence_supported is True
assert report.counterfactual_arm.governing_evidence_supported is True
assert report.baseline_arm.evidence_link_present is True
assert report.counterfactual_arm.evidence_link_present is True
assert report.decision_inertia_finding.detected is False
assert report.reason_codes == (EvidenceSensitivityReasonCode.expected_response_missing,)
for name in ("evidence-sensitivity.md", "evidence-sensitivity.html"):
    rendered = (root / name).read_text(encoding="utf-8")
    assert "wrong_direction_flip" in rendered
    assert "wrong direction relative to the authority contract" in rendered
    assert "Expected decision_flip; observed decision_flip." not in rendered
"""


def _frozen_schema_resource_paths(
    *,
    schema_root: Path = SCHEMA_ROOT,
    schema_versions: tuple[str, ...] | None = None,
) -> tuple[str, ...]:
    versions = schema_versions or frozen_schema_versions(schema_root)
    paths: list[str] = []
    for version in versions:
        version_dir = schema_root / version
        paths.extend(f"{version}/{path.name}" for path in sorted(version_dir.glob("*.schema.json")))
    return tuple(paths)


if __name__ == "__main__":
    raise SystemExit(main())
