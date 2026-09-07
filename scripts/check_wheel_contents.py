from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import os
import re
import stat
import struct
import sys
import tarfile
import unicodedata
import zipfile
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import IO

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent_assure.privacy.distribution import (  # noqa: E402
    validate_distribution_member_privacy,
    validate_zip_metadata_absent,
)
from scripts.example_resource_manifest import (  # noqa: E402
    EVIDENCE_SENSITIVITY_REQUIRED_RESOURCE_PATHS,
    PROCESS_EQUIVALENCE_BENCHMARK_REQUIRED_RESOURCE_PATHS,
)
from scripts.schema_versions import (  # noqa: E402
    SCHEMA_ROOT,
    frozen_schema_versions,
    schema_resource_archive_paths,
)

DIST = ROOT / "dist"

MAX_DISTRIBUTION_BYTES = 128 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 10_000
MAX_ARCHIVE_MEMBER_BYTES = 32 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 256 * 1024 * 1024
MAX_METADATA_BYTES = 1024 * 1024
MAX_DISTRIBUTION_ENTRIES = 4
MAX_ZIP_CENTRAL_DIRECTORY_BYTES = 16 * 1024 * 1024
MAX_TAR_EXTENDED_HEADER_BYTES = 1024 * 1024
MAX_TAR_EXTENDED_HEADER_TOTAL_BYTES = 8 * 1024 * 1024
MAX_TAR_RAW_MEMBERS = (2 * MAX_ARCHIVE_MEMBERS) + 32
MAX_DISTRIBUTION_PRIVACY_SCAN_LINES = 1_000_000
MAX_DISTRIBUTION_PYTHON_MEMBER_BYTES = 4 * 1024 * 1024
MAX_DISTRIBUTION_PYTHON_MEMBER_LINES = 50_000
MAX_DISTRIBUTION_PYTHON_MEMBER_TOKENS = 400_000
REVIEWED_BINARY_ASSET_SHA256 = {
    "docs/assets/flagship-evidence-diff.png": (
        "9e94351162d69fb8790756a662721ed58a89b38f98f3f6ada174c44f071987a7"
    ),
}
# Tests that exercise high-confidence credential detectors may contain inert
# synthetic literals. Any exception is exact-byte-bound: changing even one byte
# restores the normal scan until a reviewer updates this inventory.
SDIST_SENSITIVE_FIXTURE_SHA256 = {
    "tests/integration/test_controls_mutate_cli.py": (
        "0548fc9f0b5f2c6337a437400174c99dbd73a5e836a1e2b2f9c5b34b05526f5a"
    ),
    "tests/integration/test_external_pilot_cli.py": (
        "516045453990d9bc9912e537670d7f3409254128ef2201408b0562cb67efa42c"
    ),
    "tests/integration/test_stream_cli.py": (
        "676ae69422330a62a867c20fa57bdc08887304f05bcb90ba9fe528ebc0d5f716"
    ),
    "tests/unit/test_otel_cli.py": (
        "08eeed8dcd68fd1b7fc65ea7a4d2ce087dab774af9be1d4fb4d48029fb8ed6c5"
    ),
    "tests/unit/test_pilot_bundle.py": (
        "45bd555e918f35f5ac8a592f7016f72e0fce390e9f7c7cf71d459f6a518ef8b4"
    ),
    "tests/unit/authoring/test_yaml_loader.py": (
        "ad351d179f95321c6f53a9bd3998295e96fad0086463d8c4d79297f6dd8e813f"
    ),
    "tests/unit/evaluation/test_live_runner.py": (
        "52cc7f5ac77d60c8150cfbc70b70e846a4b1e4d206ed004e7955b5b96a81ecf0"
    ),
    "tests/unit/mutation/test_campaign.py": (
        "00675c6263cd18e6e24f7969f755347426b0a022ef66a1b9a007dfce028d9b59"
    ),
    "tests/unit/mutation/test_execution.py": (
        "14c5ceda011304a69e91884f54266cc8a5723212b32e6d991d450c815d6cb83e"
    ),
    "tests/unit/privacy/test_hmac_and_redaction.py": (
        "0fab0e1372db920c0aa670cd6e8735526d07a264f081a602445bc950439182d4"
    ),
    "tests/unit/rag/test_repeated_live_workflow.py": (
        "9297fd8250cd6e774254b68142aae202342a4b7c5432bfd3b6873c0366e0c3c6"
    ),
    "tests/unit/release/test_wheel_content_checks.py": (
        "ccfb4cf2dfe16c85f274477535af1d55649b357e28b8e69a1f50d26f21ab8312"
    ),
    "tests/unit/schema/test_pilot_evidence.py": (
        "8ff25b5e57c682307418f70d200eda19c19ad7ecefee96a99abd26b44974c037"
    ),
}
_WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_WINDOWS_FORBIDDEN_FILENAME_CHARACTERS = frozenset('<>"|?*')
_WINDOWS_RESERVED_NAMES = {
    "aux",
    "clock$",
    "con",
    "nul",
    "prn",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}
_MULTIPLE_USE_CORE_METADATA_FIELDS = frozenset(
    {
        "classifier",
        "dynamic",
        "import-name",
        "import-namespace",
        "license-file",
        "obsoletes",
        "obsoletes-dist",
        "platform",
        "project-url",
        "provides",
        "provides-dist",
        "provides-extra",
        "requires",
        "requires-dist",
        "requires-external",
        "supported-platform",
    }
)
_ZIP_END_OF_CENTRAL_DIRECTORY_SIGNATURE = b"PK\x05\x06"
_ZIP_CENTRAL_DIRECTORY_SIGNATURE = b"PK\x01\x02"
_ZIP_END_OF_CENTRAL_DIRECTORY_SIZE = 22
_ZIP_MAX_COMMENT_BYTES = (1 << 16) - 1
_ZIP_CENTRAL_DIRECTORY_HEADER_SIZE = 46
_TAR_EXTENDED_HEADER_TYPES = frozenset(
    {
        tarfile.GNUTYPE_LONGNAME,
        tarfile.GNUTYPE_LONGLINK,
        tarfile.XHDTYPE,
        tarfile.XGLTYPE,
        tarfile.SOLARIS_XHDTYPE,
    }
)
_TAR_PAX_HEADER_TYPES = frozenset(
    {
        tarfile.XHDTYPE,
        tarfile.XGLTYPE,
        tarfile.SOLARIS_XHDTYPE,
    }
)


class _BoundedTarInfo(tarfile.TarInfo):
    """Apply limits to raw tar headers before tarfile consumes their payloads."""

    def _proc_member(self, archive: tarfile.TarFile) -> tarfile.TarInfo | None:
        raw_member_count = int(archive.__dict__.get("_agent_assure_raw_member_count", 0)) + 1
        archive.__dict__["_agent_assure_raw_member_count"] = raw_member_count
        if raw_member_count > MAX_TAR_RAW_MEMBERS:
            raise ValueError(f"sdist contains more than {MAX_TAR_RAW_MEMBERS} raw tar members")
        if self.type == tarfile.GNUTYPE_SPARSE:
            raise ValueError("sdist GNU sparse members are not supported")
        if self.type in _TAR_EXTENDED_HEADER_TYPES:
            if self.size < 0 or self.size > MAX_TAR_EXTENDED_HEADER_BYTES:
                raise ValueError(
                    f"sdist extended header exceeds the {MAX_TAR_EXTENDED_HEADER_BYTES}-byte limit"
                )
            extended_total = (
                int(archive.__dict__.get("_agent_assure_extended_header_bytes", 0)) + self.size
            )
            archive.__dict__["_agent_assure_extended_header_bytes"] = extended_total
            if extended_total > MAX_TAR_EXTENDED_HEADER_TOTAL_BYTES:
                raise ValueError(
                    "sdist extended headers exceed the aggregate "
                    f"{MAX_TAR_EXTENDED_HEADER_TOTAL_BYTES}-byte limit"
                )
            if self.type in _TAR_PAX_HEADER_TYPES:
                payload_offset = archive.fileobj.tell()
                padded_size = ((self.size + tarfile.BLOCKSIZE - 1) // tarfile.BLOCKSIZE) * (
                    tarfile.BLOCKSIZE
                )
                payload = archive.fileobj.read(padded_size)
                if len(payload) != padded_size:
                    raise tarfile.ReadError("truncated sdist PAX extended header")
                archive.fileobj.seek(payload_offset)
                if b"GNU.sparse." in payload[: self.size]:
                    raise ValueError("sdist GNU sparse PAX extensions are not supported")
        # This pre-allocation hook is stable across supported Python versions but
        # intentionally omitted from typeshed because it is a stdlib-private API.
        return super()._proc_member(archive)  # type: ignore[misc,no-any-return]


BASE_REQUIRED_ARCHIVE_PATHS = (
    "agent_assure/__init__.py",
    "agent_assure/cli/main.py",
    "agent_assure/cli/rag_cmd.py",
    "agent_assure/cli/study_cmd.py",
    "agent_assure/demo/evidence_sensitivity.py",
    "agent_assure/live/config.py",
    "agent_assure/live/runner.py",
    "agent_assure/mutation/campaign.py",
    "agent_assure/mutation/introduction_snapshots.json",
    "agent_assure/reporting/campaign.py",
    "agent_assure/reporting/sensitivity.py",
    "agent_assure/reporting/study.py",
    "agent_assure/rag/repeated_sensitivity.py",
    "agent_assure/rag/sensitivity.py",
    "agent_assure/schema/benchmark.py",
    "agent_assure/schema/campaign.py",
    "agent_assure/schema/pilot.py",
    "agent_assure/schema/sensitivity.py",
    "agent_assure/schema/study.py",
    "agent_assure/statistics/binomial_intervals.py",
    "agent_assure/study/__init__.py",
    "agent_assure/study/analysis.py",
    "agent_assure/study/readiness.py",
    "agent_assure/examples/",
    "agent_assure/examples/prior_auth_synthetic/",
    "agent_assure/examples/prior_auth_synthetic/suite.yaml",
    "agent_assure/examples/prior_auth_synthetic/variants/baseline.yaml",
    ("agent_assure/examples/prior_auth_synthetic/variants/candidate_evidence_normalization.yaml"),
    (
        "agent_assure/examples/prior_auth_synthetic/fixtures/shared/requests/"
        "shared-source-multi-claim.json"
    ),
    (
        "agent_assure/examples/prior_auth_synthetic/fixtures/shared/model_outputs/"
        "shared-source-multi-claim.json"
    ),
    (
        "agent_assure/examples/prior_auth_synthetic/fixtures/shared/tool_outputs/"
        "shared-source-multi-claim.json"
    ),
    ("agent_assure/examples/prior_auth_synthetic/fixtures/rag/counterfactual_query_families.json"),
    "agent_assure/examples/expense_approval_minimal/",
    "agent_assure/examples/expense_approval_minimal/suite.yaml",
    "agent_assure/examples/expense_approval_minimal/variants/baseline.yaml",
    "agent_assure/examples/expense_approval_minimal/variants/candidate_provider_policy.yaml",
    "agent_assure/examples/expense_approval_minimal/fixtures/shared/requests/exp-001.json",
    "agent_assure/examples/expense_approval_minimal/fixtures/shared/model_outputs/exp-001.json",
    "agent_assure/examples/expense_approval_minimal/fixtures/shared/tool_outputs/exp-001.json",
    "agent_assure/examples/langgraph_expense_assurance/",
    "agent_assure/examples/langgraph_expense_assurance/__init__.py",
    "agent_assure/examples/langgraph_expense_assurance/README.md",
    "agent_assure/examples/langgraph_expense_assurance/runner.py",
    "agent_assure/examples/langgraph_expense_assurance/suite.yaml",
    "agent_assure/examples/adk_process_assurance/",
    "agent_assure/examples/adk_process_assurance/__init__.py",
    "agent_assure/examples/adk_process_assurance/README.md",
    "agent_assure/examples/adk_process_assurance/runner.py",
    "agent_assure/examples/adk_process_assurance/suite.yaml",
    "agent_assure/examples/process_measurement_cases/",
    "agent_assure/examples/process_measurement_cases/README.md",
    "agent_assure/examples/process_measurement_cases/runner.py",
    "agent_assure/examples/process_measurement_cases/suite.yaml",
    "agent_assure/examples/process_measurement_cases/variants/baseline.yaml",
    ("agent_assure/examples/process_measurement_cases/variants/candidate_process_regressions.yaml"),
    (
        "agent_assure/examples/process_measurement_cases/fixtures/shared/requests/"
        "same-output-human-review-bypassed.json"
    ),
    (
        "agent_assure/examples/process_measurement_cases/fixtures/shared/model_outputs/"
        "same-output-provider-boundary.json"
    ),
    (
        "agent_assure/examples/process_measurement_cases/fixtures/shared/tool_outputs/"
        "same-output-missing-evidence.json"
    ),
    "agent_assure/examples/streaming_process_regression/",
    "agent_assure/examples/streaming_process_regression/README.md",
    "agent_assure/examples/streaming_process_regression/suite.yaml",
    "agent_assure/examples/streaming_process_regression/events/baseline.jsonl",
    ("agent_assure/examples/streaming_process_regression/events/candidate_evidence_removed.jsonl"),
    ("agent_assure/examples/streaming_process_regression/events/candidate_review_bypassed.jsonl"),
    ("agent_assure/examples/streaming_process_regression/events/candidate_retry_burst.jsonl"),
    "agent_assure/examples/evidence_sensitivity/",
    *(
        f"agent_assure/examples/evidence_sensitivity/{relative_path}"
        for relative_path in EVIDENCE_SENSITIVITY_REQUIRED_RESOURCE_PATHS
    ),
    "agent_assure/examples/process_equivalence_benchmark_v0_2/",
    *(
        f"agent_assure/examples/process_equivalence_benchmark_v0_2/{relative_path}"
        for relative_path in PROCESS_EQUIVALENCE_BENCHMARK_REQUIRED_RESOURCE_PATHS
    ),
    "agent_assure/examples/process_equivalence_reproduction_index.json",
    "agent_assure/schema_resources/__init__.py",
    "agent_assure/mappings/nist_ai_rmf.yaml",
    "agent_assure/mappings/owasp_llm_top_10_2025.yaml",
    "agent_assure/mappings/iso_iec_42001.yaml",
    "agent_assure/mappings/mitre_atlas_2026_06.yaml",
)

FORBIDDEN_ARCHIVE_PREFIXES = (
    "schemas/",
    "agent_assure/schema_resources/unreleased/",
    ".tmp/",
    "dist/",
    "build/",
    ".pytest_cache/",
    ".mypy_cache/",
    ".ruff_cache/",
)

FORBIDDEN_ARCHIVE_SEGMENTS = ("__pycache__",)

FORBIDDEN_ARCHIVE_SUFFIXES = (".pyc",)

FORBIDDEN_SDIST_PREFIXES = (
    "schemas/unreleased/",
    ".tmp/",
    "dist/",
    "build/",
    ".pytest_cache/",
    ".mypy_cache/",
    ".ruff_cache/",
)

FORBIDDEN_SDIST_EXACT_PATHS = ("schemas/unreleased",)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    try:
        validate_distribution_directory(
            args.dist,
            allow_signature_bundles=args.allow_signature_bundles,
        )
        wheel = find_single_wheel(args.dist)
        sdist = find_single_sdist(args.dist)
        missing, forbidden = inspect_wheel(wheel)
        sdist_missing, sdist_forbidden = inspect_sdist(sdist)
        validate_distribution_identity(wheel, sdist)
        validate_distribution_payload_equivalence(wheel, sdist)
    except (OSError, tarfile.TarError, UnicodeError, ValueError, zipfile.BadZipFile) as exc:
        print(f"wheel-contents: {exc}", file=sys.stderr)
        return 1

    failures = []
    if missing:
        failures.append("missing required paths:\n" + "\n".join(f"  - {path}" for path in missing))
    if forbidden:
        failures.append(
            "forbidden paths present:\n" + "\n".join(f"  - {path}" for path in forbidden)
        )
    if sdist_forbidden:
        failures.append(
            "forbidden sdist paths present:\n"
            + "\n".join(f"  - {path}" for path in sdist_forbidden)
        )
    if sdist_missing:
        failures.append(
            "missing required sdist paths:\n" + "\n".join(f"  - {path}" for path in sdist_missing)
        )
    if failures:
        print(f"wheel-contents: {wheel}", file=sys.stderr)
        print(f"sdist-contents: {sdist}", file=sys.stderr)
        print("\n".join(failures), file=sys.stderr)
        return 1

    print(f"wheel-contents: ok ({wheel.name}, {sdist.name})")
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify built wheel archive contents.")
    parser.add_argument(
        "--dist",
        type=Path,
        default=DIST,
        help="Directory containing exactly one built wheel and sdist. Defaults to dist/.",
    )
    parser.add_argument(
        "--allow-signature-bundles",
        action="store_true",
        help="Allow and require one .bundle sidecar for each wheel and sdist.",
    )
    return parser.parse_args(argv)


def validate_distribution_directory(
    dist_dir: Path,
    *,
    allow_signature_bundles: bool = False,
) -> tuple[Path, Path]:
    try:
        directory_metadata = os.lstat(dist_dir)
    except FileNotFoundError as exc:
        raise ValueError(f"distribution path is not a regular directory: {dist_dir}") from exc
    if (
        not stat.S_ISDIR(directory_metadata.st_mode)
        or stat.S_ISLNK(directory_metadata.st_mode)
        or bool(
            getattr(directory_metadata, "st_file_attributes", 0)
            & _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT
        )
    ):
        raise ValueError(f"distribution path is not a regular directory: {dist_dir}")
    entries_list: list[Path] = []
    with os.scandir(dist_dir) as scanned:
        for entry in scanned:
            if len(entries_list) >= MAX_DISTRIBUTION_ENTRIES:
                raise ValueError(
                    f"distribution directory contains more than {MAX_DISTRIBUTION_ENTRIES} entries"
                )
            entries_list.append(Path(entry.path))
    entries = tuple(sorted(entries_list, key=lambda path: path.name))
    metadata_by_path = {path: os.lstat(path) for path in entries}
    oversized = [
        path.name
        for path, metadata in metadata_by_path.items()
        if metadata.st_size > MAX_DISTRIBUTION_BYTES
    ]
    if oversized:
        raise ValueError("distribution directory contains oversized files: " + ", ".join(oversized))
    unsafe = [
        path.name
        for path, metadata in metadata_by_path.items()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or bool(
                getattr(metadata, "st_file_attributes", 0) & _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT
            )
        )
    ]
    if unsafe:
        raise ValueError(
            "distribution directory contains non-regular entries: " + ", ".join(unsafe)
        )
    wheels = tuple(path for path in entries if path.suffix == ".whl")
    sdists = tuple(path for path in entries if path.name.endswith(".tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise ValueError(
            "expected exactly one wheel and one source distribution in "
            f"{dist_dir}; found {len(wheels)} wheel(s) and {len(sdists)} sdist(s)"
        )
    distributions = (wheels[0], sdists[0])
    allowed = set(distributions)
    if allow_signature_bundles:
        bundles = tuple(path.with_name(f"{path.name}.bundle") for path in distributions)
        missing_bundles = [path.name for path in bundles if path not in entries]
        if missing_bundles:
            raise ValueError(
                "missing distribution signature bundle(s): " + ", ".join(missing_bundles)
            )
        allowed.update(bundles)
    unexpected = [path.name for path in entries if path not in allowed]
    if unexpected:
        raise ValueError("unexpected distribution directory entries: " + ", ".join(unexpected))
    return distributions


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
        raise ValueError(
            f"expected exactly one source distribution in {dist_dir}, found {sdist_list}"
        )
    return sdists[0]


def _validate_archive_file(path: Path, *, label: str) -> int:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError as exc:
        raise ValueError(f"{label} is not a regular file: {path}") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or bool(getattr(metadata, "st_file_attributes", 0) & _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT)
    ):
        raise ValueError(f"{label} is not a regular file: {path}")
    if metadata.st_size > MAX_DISTRIBUTION_BYTES:
        raise ValueError(f"{label} exceeds {MAX_DISTRIBUTION_BYTES} bytes: {path}")
    return metadata.st_size


def _read_exact(handle: IO[bytes], size: int, *, label: str) -> bytes:
    payload = handle.read(size)
    if len(payload) != size:
        raise ValueError(f"truncated {label}")
    return payload


def _preflight_zip_archive(path: Path) -> None:
    """Validate bounded ZIP directory structure before ZipFile allocates ZipInfo objects."""
    file_size = _validate_archive_file(path, label="wheel")
    if file_size < _ZIP_END_OF_CENTRAL_DIRECTORY_SIZE:
        raise zipfile.BadZipFile("wheel is too small to contain a ZIP directory")
    tail_size = min(
        file_size,
        _ZIP_END_OF_CENTRAL_DIRECTORY_SIZE + _ZIP_MAX_COMMENT_BYTES,
    )
    with path.open("rb") as handle:
        handle.seek(file_size - tail_size)
        tail = _read_exact(handle, tail_size, label="wheel ZIP directory tail")
    search_end = len(tail)
    eocd: tuple[bytes, int, int, int, int, int, int, int] | None = None
    eocd_tail_offset = -1
    while search_end:
        candidate = tail.rfind(
            _ZIP_END_OF_CENTRAL_DIRECTORY_SIGNATURE,
            0,
            search_end,
        )
        if candidate < 0:
            break
        if candidate + _ZIP_END_OF_CENTRAL_DIRECTORY_SIZE <= len(tail):
            parsed = struct.unpack(
                "<4s4H2LH",
                tail[candidate : candidate + _ZIP_END_OF_CENTRAL_DIRECTORY_SIZE],
            )
            if candidate + _ZIP_END_OF_CENTRAL_DIRECTORY_SIZE + parsed[-1] == len(tail):
                eocd = parsed
                eocd_tail_offset = candidate
                break
        search_end = candidate
    if eocd is None:
        raise zipfile.BadZipFile("wheel has no valid end-of-central-directory record")
    (
        _signature,
        disk_number,
        central_directory_disk,
        disk_entry_count,
        total_entry_count,
        central_directory_size,
        central_directory_offset,
        comment_size,
    ) = eocd
    if comment_size:
        raise ValueError("wheel archive comments are not supported")
    if disk_number != 0 or central_directory_disk != 0 or disk_entry_count != total_entry_count:
        raise ValueError("wheel multi-disk ZIP archives are not supported")
    if (
        total_entry_count == 0xFFFF
        or central_directory_size == 0xFFFFFFFF
        or central_directory_offset == 0xFFFFFFFF
    ):
        raise ValueError("wheel ZIP64 central directories are not supported")
    if total_entry_count > MAX_ARCHIVE_MEMBERS:
        raise ValueError(
            f"wheel advertises {total_entry_count} members; maximum is {MAX_ARCHIVE_MEMBERS}"
        )
    if central_directory_size > MAX_ZIP_CENTRAL_DIRECTORY_BYTES:
        raise ValueError(
            f"wheel central directory exceeds the {MAX_ZIP_CENTRAL_DIRECTORY_BYTES}-byte limit"
        )
    eocd_offset = file_size - tail_size + eocd_tail_offset
    if central_directory_offset + central_directory_size > eocd_offset:
        raise zipfile.BadZipFile("wheel central directory overlaps its end record")
    with path.open("rb") as handle:
        handle.seek(central_directory_offset)
        remaining = central_directory_size
        for entry_index in range(total_entry_count):
            if remaining < _ZIP_CENTRAL_DIRECTORY_HEADER_SIZE:
                raise zipfile.BadZipFile(
                    f"wheel central directory is truncated at entry {entry_index + 1}"
                )
            header = _read_exact(
                handle,
                _ZIP_CENTRAL_DIRECTORY_HEADER_SIZE,
                label="wheel central-directory header",
            )
            parsed_header = struct.unpack("<4s6H3L5H2L", header)
            if parsed_header[0] != _ZIP_CENTRAL_DIRECTORY_SIGNATURE:
                raise zipfile.BadZipFile(f"invalid wheel central-directory entry {entry_index + 1}")
            if parsed_header[13] != 0:
                raise ValueError("wheel central-directory entry refers to another disk")
            if parsed_header[11] or parsed_header[12]:
                raise ValueError("wheel member extra fields and comments are not supported")
            variable_size = sum(parsed_header[index] for index in (10, 11, 12))
            entry_size = _ZIP_CENTRAL_DIRECTORY_HEADER_SIZE + variable_size
            if entry_size > remaining:
                raise zipfile.BadZipFile(
                    f"wheel central-directory entry {entry_index + 1} is truncated"
                )
            handle.seek(variable_size, os.SEEK_CUR)
            remaining -= entry_size
        if remaining:
            raise zipfile.BadZipFile(
                "wheel central directory contains bytes outside its advertised entries"
            )


def inspect_wheel(wheel: Path) -> tuple[list[str], list[str]]:
    _preflight_zip_archive(wheel)
    with zipfile.ZipFile(wheel) as archive:
        names, regular_names, unsafe = _inspect_zip_members(archive)
        _validate_wheel_record(archive, regular_names)
        if not unsafe:
            _validate_wheel_privacy(archive, regular_names)
    required_paths = required_archive_paths()
    missing = [
        required
        for required in required_paths
        if not _archive_contains(names, regular_names, required)
    ]
    forbidden = [*unsafe, *(name for name in names if _is_forbidden_archive_path(name))]
    return missing, forbidden


def inspect_sdist(sdist: Path) -> tuple[list[str], list[str]]:
    _validate_archive_file(sdist, label="sdist")
    with tarfile.open(sdist, "r:gz", tarinfo=_BoundedTarInfo) as archive:
        names, regular_names, unsafe = _inspect_tar_members(archive)
    if not unsafe:
        _validate_sdist_privacy(sdist)
    stripped_names = tuple(sorted(_strip_sdist_root(name) for name in names))
    stripped_regular_names = frozenset(_strip_sdist_root(name) for name in regular_names)
    missing = [
        required
        for required in required_sdist_paths()
        if not _archive_contains(stripped_names, stripped_regular_names, required)
    ]
    forbidden = [*unsafe, *(name for name in names if _is_forbidden_sdist_path(name))]
    return missing, forbidden


def _validate_wheel_privacy(
    archive: zipfile.ZipFile,
    regular_names: frozenset[str],
) -> None:
    remaining_lines = MAX_DISTRIBUTION_PRIVACY_SCAN_LINES
    for name in sorted(regular_names):
        data = _read_zip_member_bytes(archive, archive.getinfo(name))
        scanned_lines = validate_distribution_member_privacy(
            name,
            data,
            max_structural_scan_lines=remaining_lines,
            max_python_member_bytes=MAX_DISTRIBUTION_PYTHON_MEMBER_BYTES,
            max_python_member_lines=MAX_DISTRIBUTION_PYTHON_MEMBER_LINES,
            max_python_member_tokens=MAX_DISTRIBUTION_PYTHON_MEMBER_TOKENS,
            strict_python_source=name.startswith("agent_assure/"),
        )
        remaining_lines -= scanned_lines


def _validate_sdist_privacy(sdist: Path) -> None:
    remaining_lines = MAX_DISTRIBUTION_PRIVACY_SCAN_LINES
    expanded_bytes = 0
    with tarfile.open(sdist, "r:gz", tarinfo=_BoundedTarInfo) as archive:
        for member_count, member in enumerate(archive, start=1):
            if member_count > MAX_ARCHIVE_MEMBERS:
                raise ValueError(f"sdist contains more than {MAX_ARCHIVE_MEMBERS} members")
            if not member.isfile():
                continue
            if member.size > MAX_ARCHIVE_MEMBER_BYTES:
                raise ValueError(
                    f"{member.name} exceeds the {MAX_ARCHIVE_MEMBER_BYTES}-byte member limit"
                )
            expanded_bytes += member.size
            if expanded_bytes > MAX_ARCHIVE_TOTAL_BYTES:
                raise ValueError(f"sdist expands to more than {MAX_ARCHIVE_TOTAL_BYTES} bytes")
            data = _read_tar_member_bytes(archive, member)
            name = _strip_sdist_root(member.name)
            expected_fixture_digest = SDIST_SENSITIVE_FIXTURE_SHA256.get(name)
            allow_sensitive_fixture = (
                expected_fixture_digest is not None
                and hashlib.sha256(data).hexdigest() == expected_fixture_digest
            )
            scanned_lines = validate_distribution_member_privacy(
                name,
                data,
                max_structural_scan_lines=remaining_lines,
                max_python_member_bytes=MAX_DISTRIBUTION_PYTHON_MEMBER_BYTES,
                max_python_member_lines=MAX_DISTRIBUTION_PYTHON_MEMBER_LINES,
                max_python_member_tokens=MAX_DISTRIBUTION_PYTHON_MEMBER_TOKENS,
                strict_python_source=name.startswith("src/agent_assure/"),
                reviewed_binary_assets=REVIEWED_BINARY_ASSET_SHA256,
                allow_sensitive_fixture=allow_sensitive_fixture,
            )
            remaining_lines -= scanned_lines


def required_archive_paths(
    *,
    schema_root: Path = SCHEMA_ROOT,
    schema_versions: tuple[str, ...] | None = None,
) -> tuple[str, ...]:
    versions = schema_versions or frozen_schema_versions(schema_root)
    schema_dirs = tuple(f"agent_assure/schema_resources/{version}/" for version in versions)
    schema_paths = schema_resource_archive_paths(
        schema_root=schema_root,
        schema_versions=versions,
    )
    return (*BASE_REQUIRED_ARCHIVE_PATHS, *schema_dirs, *schema_paths)


def required_sdist_paths(
    *,
    schema_root: Path = SCHEMA_ROOT,
    schema_versions: tuple[str, ...] | None = None,
) -> tuple[str, ...]:
    """Return source-tree paths that must back every required installed resource."""
    versions = schema_versions or frozen_schema_versions(schema_root)
    required = required_archive_paths(
        schema_root=schema_root,
        schema_versions=versions,
    )
    generated_schema_prefixes = tuple(
        f"agent_assure/schema_resources/{version}/" for version in versions
    )
    mapped: list[str] = ["LICENSE", "README.md", "pyproject.toml"]
    for path in required:
        if path.startswith(generated_schema_prefixes):
            mapped.append("schemas/" + path.removeprefix("agent_assure/schema_resources/"))
        elif path.startswith("agent_assure/mappings/"):
            mapped.append("mappings/" + path.removeprefix("agent_assure/mappings/"))
        else:
            mapped.append("src/" + path)
    return tuple(dict.fromkeys(mapped))


def validate_distribution_identity(wheel: Path, sdist: Path) -> None:
    """Require archive names and embedded metadata to identify one release."""
    _preflight_zip_archive(wheel)
    _validate_archive_file(sdist, label="sdist")
    wheel_filename = _wheel_filename_identity(wheel)
    sdist_filename = _sdist_filename_identity(sdist)
    wheel_metadata = _wheel_metadata_identity(wheel)
    sdist_metadata = _sdist_metadata_identity(sdist)
    wheel_layout = _wheel_layout_identity(wheel)
    sdist_layout = _sdist_layout_identity(sdist)
    identities = (
        wheel_filename,
        sdist_filename,
        wheel_metadata,
        sdist_metadata,
        wheel_layout,
        sdist_layout,
    )
    if len(set(identities)) != 1:
        rendered = ", ".join(f"{name}=={version}" for name, version in identities)
        raise ValueError(f"wheel and sdist project identity/version mismatch: {rendered}")
    if wheel_filename[0] != "agent-assure":
        raise ValueError("distribution project name must be agent-assure, got " + wheel_filename[0])
    _require_wheel_record(wheel)


def validate_distribution_payload_equivalence(
    wheel: Path,
    sdist: Path,
    *,
    schema_root: Path = SCHEMA_ROOT,
    schema_versions: tuple[str, ...] | None = None,
) -> dict[str, str]:
    """Bind every installable wheel byte to its intended sdist source byte.

    Distribution metadata is intentionally excluded: wheel ``.dist-info`` files
    are build-backend products covered by the wheel RECORD and release identity
    checks. Everything else in the wheel must be the exact mapped counterpart of
    a regular source file in the sdist.
    """
    versions = frozenset(schema_versions or frozen_schema_versions(schema_root))
    _preflight_zip_archive(wheel)
    _validate_archive_file(sdist, label="sdist")
    with (
        zipfile.ZipFile(wheel) as wheel_archive,
        tarfile.open(sdist, "r:gz", tarinfo=_BoundedTarInfo) as sdist_archive,
    ):
        wheel_names, wheel_regular_names, wheel_unsafe = _inspect_zip_members(wheel_archive)
        _validate_wheel_record(wheel_archive, wheel_regular_names)
        sdist_names, sdist_regular_names, sdist_unsafe = _inspect_tar_members(sdist_archive)
        archive_findings = [
            *wheel_unsafe,
            *(name for name in wheel_names if _is_forbidden_archive_path(name)),
            *sdist_unsafe,
            *(name for name in sdist_names if _is_forbidden_sdist_path(name)),
        ]
        if archive_findings:
            raise ValueError(
                "distribution payload equivalence requires safe archives: "
                + "; ".join(archive_findings)
            )

        wheel_members = {
            name: wheel_archive.getinfo(name)
            for name in wheel_regular_names
            if not _is_top_level_dist_info_path(name)
        }
        intended_sources: dict[str, str] = {}
        source_names: dict[str, str] = {}
        portable_sources: dict[str, str] = {}
        for source_name in sorted(sdist_regular_names):
            stripped_name = _strip_sdist_root(source_name)
            wheel_name = _intended_wheel_payload_path(
                stripped_name,
                schema_versions=versions,
            )
            if wheel_name is None:
                continue
            previous_source = source_names.get(wheel_name)
            if previous_source is not None:
                raise ValueError(
                    "multiple sdist sources map to wheel payload path "
                    f"{wheel_name}: {previous_source}, {source_name}"
                )
            portable_key = _portable_collision_key(wheel_name)
            previous_portable_source = portable_sources.get(portable_key)
            if previous_portable_source is not None:
                raise ValueError(
                    "sdist sources have a portable collision after wheel mapping: "
                    f"{previous_portable_source}, {source_name}"
                )
            source_names[wheel_name] = source_name
            portable_sources[portable_key] = source_name
            intended_sources[wheel_name] = source_name

        expected_paths = set(intended_sources)
        actual_paths = set(wheel_members)
        missing = sorted(expected_paths - actual_paths)
        unexpected = sorted(actual_paths - expected_paths)
        if missing or unexpected:
            raise ValueError(
                "wheel/sdist payload inventory mismatch; "
                f"missing from wheel={missing}, unexpected in wheel={unexpected}"
            )

        sdist_payloads = _read_mapped_sdist_payloads(
            sdist,
            schema_versions=versions,
        )
        if set(sdist_payloads) != expected_paths:
            raise ValueError("sdist payload changed between validation and bounded materialization")
        manifest: dict[str, str] = {}
        for wheel_name in sorted(expected_paths):
            wheel_info = wheel_members[wheel_name]
            sdist_payload = sdist_payloads[wheel_name]
            if wheel_info.file_size != len(sdist_payload):
                raise ValueError(f"wheel/sdist payload size differs: {wheel_name}")
            wheel_payload = _read_zip_member_bytes(wheel_archive, wheel_info)
            if wheel_payload != sdist_payload:
                raise ValueError(f"wheel/sdist payload bytes differ: {wheel_name}")
            manifest[wheel_name] = hashlib.sha256(wheel_payload).hexdigest()
    return manifest


def validate_wheel_archive_equivalence(
    reference_wheel: Path,
    candidate_wheel: Path,
) -> dict[str, str]:
    """Require an independently built wheel to reproduce every archive member byte."""
    _preflight_zip_archive(reference_wheel)
    _preflight_zip_archive(candidate_wheel)
    manifests: list[dict[str, bytes]] = []
    for label, wheel in (("reference", reference_wheel), ("candidate", candidate_wheel)):
        with zipfile.ZipFile(wheel) as archive:
            names, regular_names, unsafe = _inspect_zip_members(archive)
            _validate_wheel_record(archive, regular_names)
            findings = [
                *unsafe,
                *(name for name in names if _is_forbidden_archive_path(name)),
            ]
            if findings:
                raise ValueError(
                    f"{label} wheel is unsafe for archive equivalence: " + "; ".join(findings)
                )
            manifests.append(
                {
                    name: _read_zip_member_bytes(archive, archive.getinfo(name))
                    for name in sorted(regular_names)
                }
            )
    reference_payloads, candidate_payloads = manifests
    missing = sorted(set(reference_payloads) - set(candidate_payloads))
    unexpected = sorted(set(candidate_payloads) - set(reference_payloads))
    if missing or unexpected:
        raise ValueError(
            "independently built wheel inventory mismatch; "
            f"missing={missing}, unexpected={unexpected}"
        )
    drifted = sorted(
        name for name in reference_payloads if reference_payloads[name] != candidate_payloads[name]
    )
    if drifted:
        raise ValueError(f"independently built wheel member bytes differ: {drifted}")
    return {
        name: hashlib.sha256(payload).hexdigest() for name, payload in reference_payloads.items()
    }


def _is_top_level_dist_info_path(name: str) -> bool:
    parts = name.split("/", 1)
    return len(parts) == 2 and parts[0].endswith(".dist-info")


def _intended_wheel_payload_path(
    source_name: str,
    *,
    schema_versions: frozenset[str],
) -> str | None:
    package_prefix = "src/agent_assure/"
    if source_name.startswith(package_prefix):
        return "agent_assure/" + source_name.removeprefix(package_prefix)
    mappings_prefix = "mappings/"
    if source_name.startswith(mappings_prefix):
        return "agent_assure/mappings/" + source_name.removeprefix(mappings_prefix)
    parts = source_name.split("/")
    if len(parts) >= 3 and parts[0] == "schemas":
        if parts[1] not in schema_versions:
            raise ValueError(
                f"sdist contains an unexpected non-frozen schema source: {source_name}"
            )
        return "agent_assure/schema_resources/" + "/".join(parts[1:])
    return None


def _read_zip_member_bytes(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
    with archive.open(info) as handle:
        payload = _read_exact(handle, info.file_size, label=f"wheel member {info.filename}")
        if handle.read(1):
            raise ValueError(f"wheel member exceeds its advertised size: {info.filename}")
    return payload


def _read_tar_member_bytes(archive: tarfile.TarFile, member: tarfile.TarInfo) -> bytes:
    extracted = archive.extractfile(member)
    if extracted is None:
        raise ValueError(f"sdist member cannot be read: {member.name}")
    with extracted:
        payload = _read_exact(extracted, member.size, label=f"sdist member {member.name}")
        if extracted.read(1):
            raise ValueError(f"sdist member exceeds its advertised size: {member.name}")
    return payload


def _read_mapped_sdist_payloads(
    sdist: Path,
    *,
    schema_versions: frozenset[str],
) -> dict[str, bytes]:
    """Materialize mapped sdist members once, in physical archive order."""
    payloads: dict[str, bytes] = {}
    portable_sources: dict[str, str] = {}
    total = 0
    with tarfile.open(sdist, "r:gz", tarinfo=_BoundedTarInfo) as archive:
        for member_count, member in enumerate(archive, start=1):
            if member_count > MAX_ARCHIVE_MEMBERS:
                raise ValueError(f"sdist contains more than {MAX_ARCHIVE_MEMBERS} members")
            if member.size > MAX_ARCHIVE_MEMBER_BYTES:
                raise ValueError(
                    f"{member.name} exceeds the {MAX_ARCHIVE_MEMBER_BYTES}-byte member limit"
                )
            total += member.size
            if total > MAX_ARCHIVE_TOTAL_BYTES:
                raise ValueError(f"sdist expands to more than {MAX_ARCHIVE_TOTAL_BYTES} bytes")
            if not member.isfile():
                continue
            wheel_name = _intended_wheel_payload_path(
                _strip_sdist_root(member.name),
                schema_versions=schema_versions,
            )
            if wheel_name is None:
                continue
            portable_key = _portable_collision_key(wheel_name)
            if wheel_name in payloads or portable_key in portable_sources:
                raise ValueError(
                    "sdist sources collide after wheel mapping: "
                    f"{portable_sources.get(portable_key, wheel_name)}, {member.name}"
                )
            payloads[wheel_name] = _read_tar_member_bytes(archive, member)
            portable_sources[portable_key] = member.name
    return payloads


def _archive_contains(
    names: tuple[str, ...],
    regular_names: frozenset[str],
    required: str,
) -> bool:
    if required.endswith("/"):
        return any(name.startswith(required) for name in names)
    return required in regular_names


def _inspect_zip_members(
    archive: zipfile.ZipFile,
) -> tuple[tuple[str, ...], frozenset[str], list[str]]:
    validate_zip_metadata_absent(archive)
    infos = archive.infolist()
    if len(infos) > MAX_ARCHIVE_MEMBERS:
        raise ValueError(f"wheel contains {len(infos)} members; maximum is {MAX_ARCHIVE_MEMBERS}")
    names: list[str] = []
    regular_names: set[str] = set()
    unsafe: list[str] = []
    seen: dict[str, str] = {}
    total = 0
    for info in infos:
        name = info.filename
        names.append(name)
        issue = _portable_archive_member_error(name)
        if issue is not None:
            unsafe.append(f"{name} ({issue})")
        collision_key = _portable_collision_key(name)
        previous = seen.get(collision_key)
        if previous is not None:
            unsafe.append(f"{name} (duplicate or portable-path collision with {previous})")
        else:
            seen[collision_key] = name
        if info.file_size > MAX_ARCHIVE_MEMBER_BYTES:
            raise ValueError(f"{name} exceeds the {MAX_ARCHIVE_MEMBER_BYTES}-byte member limit")
        total += info.file_size
        mode = (info.external_attr >> 16) & 0xFFFF
        member_type = stat.S_IFMT(mode)
        if member_type not in (0, stat.S_IFREG, stat.S_IFDIR):
            unsafe.append(f"{name} (wheel member is not a regular file or directory)")
        elif info.is_dir():
            if member_type == stat.S_IFREG:
                unsafe.append(f"{name} (directory name is encoded as a regular file)")
        elif member_type == stat.S_IFDIR:
            unsafe.append(f"{name} (file name is encoded as a directory)")
        else:
            regular_names.add(name)
    unsafe.extend(_archive_file_descendant_errors(names, regular_names))
    if total > MAX_ARCHIVE_TOTAL_BYTES:
        raise ValueError(f"wheel expands to {total} bytes; maximum is {MAX_ARCHIVE_TOTAL_BYTES}")
    return tuple(sorted(names)), frozenset(regular_names), unsafe


def _inspect_tar_members(
    archive: tarfile.TarFile,
) -> tuple[tuple[str, ...], frozenset[str], list[str]]:
    if archive.pax_headers:
        raise ValueError("sdist global PAX metadata is not supported")
    names: list[str] = []
    regular_names: set[str] = set()
    unsafe: list[str] = []
    seen: dict[str, str] = {}
    total = 0
    roots: set[str] = set()
    for member_count, member in enumerate(archive, start=1):
        if member_count > MAX_ARCHIVE_MEMBERS:
            raise ValueError(f"sdist contains more than {MAX_ARCHIVE_MEMBERS} members")
        if member.isfile() or member.isdir():
            _validate_tar_member_metadata(member)
        name = member.name
        names.append(name)
        issue = _portable_archive_member_error(name)
        if issue is not None:
            unsafe.append(f"{name} ({issue})")
        parts = name.split("/")
        if parts and parts[0] not in ("", ".", ".."):
            roots.add(parts[0])
        collision_key = _portable_collision_key(name)
        previous = seen.get(collision_key)
        if previous is not None:
            unsafe.append(f"{name} (duplicate or portable-path collision with {previous})")
        else:
            seen[collision_key] = name
        if not (member.isfile() or member.isdir()):
            unsafe.append(f"{name} (sdist member is not a regular file or directory)")
        elif member.isfile():
            regular_names.add(name)
        if member.size > MAX_ARCHIVE_MEMBER_BYTES:
            raise ValueError(f"{name} exceeds the {MAX_ARCHIVE_MEMBER_BYTES}-byte member limit")
        total += member.size
    unsafe.extend(_archive_file_descendant_errors(names, regular_names))
    if len(roots) != 1:
        unsafe.append("<archive> (sdist members must share exactly one top-level directory)")
    if total > MAX_ARCHIVE_TOTAL_BYTES:
        raise ValueError(f"sdist expands to {total} bytes; maximum is {MAX_ARCHIVE_TOTAL_BYTES}")
    return tuple(sorted(names)), frozenset(regular_names), unsafe


def _validate_tar_member_metadata(member: tarfile.TarInfo) -> None:
    if member.uname or member.gname or member.linkname:
        raise ValueError("sdist member identity and link metadata must be empty")
    if member.pax_headers not in ({}, {"path": member.name}):
        raise ValueError("sdist member PAX metadata must be an exact path record")


def _portable_archive_member_error(name: str) -> str | None:
    if not name:
        return "empty archive member name"
    if "\x00" in name or any(ord(character) < 32 or ord(character) == 127 for character in name):
        return "control character in archive member name"
    if "\\" in name:
        return "backslash is not a portable archive separator"
    if name.startswith("/") or re.match(r"^[A-Za-z]:", name):
        return "absolute archive member path"
    if unicodedata.normalize("NFC", name) != name:
        return "archive member path is not NFC-normalized"
    portable_name = name[:-1] if name.endswith("/") else name
    parts = portable_name.split("/")
    if any(part in ("", ".", "..") for part in parts):
        return "archive member path contains an empty, dot, or parent segment"
    for part in parts:
        if part.rstrip(" .") != part:
            return "archive member path has a Windows-ambiguous suffix"
        stem = part.split(".", 1)[0].casefold()
        if stem in _WINDOWS_RESERVED_NAMES:
            return "archive member path uses a Windows reserved name"
        if any(character in _WINDOWS_FORBIDDEN_FILENAME_CHARACTERS for character in part):
            return "archive member path contains a Windows-forbidden character"
        if ":" in part:
            return "archive member path contains a colon"
    return None


def _portable_collision_key(name: str) -> str:
    return unicodedata.normalize("NFC", name.rstrip("/")).casefold()


def _archive_file_descendant_errors(
    names: list[str],
    regular_names: set[str],
) -> list[str]:
    regular_by_key = {_portable_collision_key(name): name for name in sorted(regular_names)}
    findings: list[str] = []
    for name in sorted(names):
        key = _portable_collision_key(name)
        parts = key.split("/")
        for part_count in range(1, len(parts)):
            parent_key = "/".join(parts[:part_count])
            parent = regular_by_key.get(parent_key)
            if parent is not None:
                findings.append(f"{name} (archive member descends from regular file {parent})")
                break
    return findings


def _wheel_filename_identity(path: Path) -> tuple[str, str]:
    stem = path.name.removesuffix(".whl")
    parts = stem.split("-")
    if len(parts) < 5 or not parts[0] or not parts[1]:
        raise ValueError(f"invalid wheel filename: {path.name}")
    return _normalize_project_name(parts[0]), parts[1]


def _sdist_filename_identity(path: Path) -> tuple[str, str]:
    stem = path.name.removesuffix(".tar.gz")
    try:
        name, version = stem.rsplit("-", 1)
    except ValueError as exc:
        raise ValueError(f"invalid sdist filename: {path.name}") from exc
    if not name or not version:
        raise ValueError(f"invalid sdist filename: {path.name}")
    return _normalize_project_name(name), version


def _wheel_metadata_identity(path: Path) -> tuple[str, str]:
    with zipfile.ZipFile(path) as archive:
        candidates = [
            info for info in archive.infolist() if info.filename.endswith(".dist-info/METADATA")
        ]
        if len(candidates) != 1:
            raise ValueError("wheel must contain exactly one .dist-info/METADATA file")
        if candidates[0].file_size > MAX_METADATA_BYTES:
            raise ValueError(f"wheel METADATA exceeds {MAX_METADATA_BYTES} bytes")
        payload = archive.read(candidates[0])
    return _metadata_identity(payload, label="wheel METADATA")


def _sdist_metadata_identity(path: Path) -> tuple[str, str]:
    with tarfile.open(path, "r:gz", tarinfo=_BoundedTarInfo) as archive:
        candidates = [
            member
            for member in archive
            if member.name.count("/") == 1 and member.name.endswith("/PKG-INFO")
        ]
        if len(candidates) != 1 or not candidates[0].isfile():
            raise ValueError("sdist must contain exactly one regular top-level PKG-INFO file")
        extracted = archive.extractfile(candidates[0])
        if extracted is None:
            raise ValueError("sdist PKG-INFO cannot be read")
        payload = extracted.read(MAX_METADATA_BYTES + 1)
    return _metadata_identity(payload, label="sdist PKG-INFO")


def _wheel_layout_identity(path: Path) -> tuple[str, str]:
    with zipfile.ZipFile(path) as archive:
        candidates = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
    if len(candidates) != 1:
        raise ValueError("wheel must contain exactly one .dist-info/METADATA file")
    dist_info = candidates[0].rsplit("/", 1)[0]
    if "/" in dist_info or not dist_info.endswith(".dist-info"):
        raise ValueError("wheel METADATA must be inside one top-level .dist-info directory")
    return _distribution_stem_identity(
        dist_info.removesuffix(".dist-info"),
        label="wheel .dist-info directory",
    )


def _sdist_layout_identity(path: Path) -> tuple[str, str]:
    with tarfile.open(path, "r:gz", tarinfo=_BoundedTarInfo) as archive:
        candidates = [
            member.name.split("/", 1)[0]
            for member in archive
            if member.name.count("/") == 1 and member.name.endswith("/PKG-INFO")
        ]
    if len(candidates) != 1:
        raise ValueError("sdist must contain exactly one top-level PKG-INFO file")
    return _distribution_stem_identity(candidates[0], label="sdist top-level directory")


def _distribution_stem_identity(stem: str, *, label: str) -> tuple[str, str]:
    try:
        name, version = stem.rsplit("-", 1)
    except ValueError as exc:
        raise ValueError(f"invalid {label}: {stem}") from exc
    if not name or not version:
        raise ValueError(f"invalid {label}: {stem}")
    return _normalize_project_name(name), version


def _require_wheel_record(path: Path) -> None:
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
    metadata = [name for name in names if name.endswith(".dist-info/METADATA")]
    records = [name for name in names if name.endswith(".dist-info/RECORD")]
    if len(records) != 1:
        raise ValueError("wheel must contain exactly one .dist-info/RECORD file")
    if len(metadata) != 1 or records[0].rsplit("/", 1)[0] != metadata[0].rsplit("/", 1)[0]:
        raise ValueError("wheel RECORD and METADATA must share one .dist-info directory")


def _metadata_identity(payload: bytes, *, label: str) -> tuple[str, str]:
    if len(payload) > MAX_METADATA_BYTES:
        raise ValueError(f"{label} exceeds {MAX_METADATA_BYTES} bytes")
    try:
        message = BytesParser(policy=policy.strict).parsebytes(payload)
    except Exception as exc:
        raise ValueError(f"{label} is malformed Core Metadata") from exc
    fields: dict[str, list[str]] = {}
    display_names: dict[str, str] = {}
    for field_name, value in message.raw_items():
        normalized_field = field_name.casefold()
        display_names.setdefault(normalized_field, field_name)
        fields.setdefault(normalized_field, []).append(value)
    duplicate_single_use = sorted(
        display_names[field_name]
        for field_name, values in fields.items()
        if len(values) > 1 and field_name not in _MULTIPLE_USE_CORE_METADATA_FIELDS
    )
    if duplicate_single_use:
        raise ValueError(
            f"{label} contains duplicate single-use Core Metadata fields: "
            + ", ".join(duplicate_single_use)
        )
    required: dict[str, str] = {}
    for field_name in ("metadata-version", "name", "version"):
        values = fields.get(field_name, [])
        if len(values) != 1 or not values[0].strip():
            raise ValueError(f"{label} must contain exactly one non-empty {field_name} field")
        required[field_name] = values[0].strip()
    name = required["name"]
    version = required["version"]
    return _normalize_project_name(name), version


def _normalize_project_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).casefold()


def _validate_wheel_record(
    archive: zipfile.ZipFile,
    regular_names: frozenset[str],
) -> None:
    candidates = [name for name in regular_names if name.endswith(".dist-info/RECORD")]
    # Small unit-level content probes intentionally omit packaging metadata. A real
    # distribution reaches this path with RECORD, which is then validated exactly.
    if not candidates:
        return
    if len(candidates) != 1:
        raise ValueError("wheel must contain exactly one .dist-info/RECORD file")
    record_name = candidates[0]
    record_info = archive.getinfo(record_name)
    if record_info.file_size > MAX_METADATA_BYTES:
        raise ValueError(f"wheel RECORD exceeds {MAX_METADATA_BYTES} bytes")
    payload = archive.read(record_name)
    try:
        rows = list(csv.reader(io.StringIO(payload.decode("utf-8"))))
    except UnicodeDecodeError as exc:
        raise ValueError("wheel RECORD must be UTF-8") from exc
    records: dict[str, tuple[str, str]] = {}
    for row in rows:
        if len(row) != 3 or not row[0]:
            raise ValueError("wheel RECORD rows must contain path, hash, and size")
        if row[0] in records:
            raise ValueError(f"wheel RECORD contains duplicate path: {row[0]}")
        records[row[0]] = (row[1], row[2])
    files = set(regular_names)
    if set(records) != files:
        missing = sorted(files - set(records))
        extra = sorted(set(records) - files)
        raise ValueError(f"wheel RECORD inventory mismatch; missing={missing}, extra={extra}")
    for name in sorted(files):
        digest_text, size_text = records[name]
        data = archive.read(name)
        if name == record_name:
            if digest_text or size_text:
                raise ValueError("wheel RECORD entry must omit its own hash and size")
            continue
        signature_entry = name in {
            f"{record_name.removesuffix('/RECORD')}/RECORD.jws",
            f"{record_name.removesuffix('/RECORD')}/RECORD.p7s",
        }
        if signature_entry and not digest_text and not size_text:
            continue
        if not size_text:
            raise ValueError(f"wheel RECORD requires size: {name}")
        if size_text != str(len(data)):
            raise ValueError(f"wheel RECORD size mismatch: {name}")
        if not digest_text.startswith("sha256="):
            raise ValueError(f"wheel RECORD requires sha256 digest: {name}")
        expected = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        if digest_text.removeprefix("sha256=") != expected:
            raise ValueError(f"wheel RECORD digest mismatch: {name}")


def _is_forbidden_archive_path(name: str) -> bool:
    if any(name.startswith(prefix) for prefix in FORBIDDEN_ARCHIVE_PREFIXES):
        return True
    if any(segment in name.split("/") for segment in FORBIDDEN_ARCHIVE_SEGMENTS):
        return True
    return any(name.endswith(suffix) for suffix in FORBIDDEN_ARCHIVE_SUFFIXES)


def _is_forbidden_sdist_path(name: str) -> bool:
    normalized = _strip_sdist_root(name)
    if normalized in FORBIDDEN_SDIST_EXACT_PATHS:
        return True
    if any(normalized.startswith(prefix) for prefix in FORBIDDEN_SDIST_PREFIXES):
        return True
    if any(segment in normalized.split("/") for segment in FORBIDDEN_ARCHIVE_SEGMENTS):
        return True
    return any(normalized.endswith(suffix) for suffix in FORBIDDEN_ARCHIVE_SUFFIXES)


def _strip_sdist_root(name: str) -> str:
    parts = name.split("/", 1)
    if len(parts) == 1:
        return name
    return parts[1]


if __name__ == "__main__":
    raise SystemExit(main())
