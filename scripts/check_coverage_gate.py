from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
from decimal import Decimal, InvalidOperation
from pathlib import Path

import coverage
from coverage import CoverageData
from coverage.exceptions import CoverageException

MAX_COVERAGE_DATABASE_BYTES = 64 * 1024 * 1024
MAX_COVERAGE_ARTIFACT_NAME_CHARS = 128
MAX_CRITICAL_COVERAGE_PREFIXES = 32
MAX_COVERAGE_PREFIX_CHARS = 256
SOURCE_COVERAGE_PREFIX = "src/agent_assure/"
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Fail closed on incomplete coverage shards or inadequate branch coverage."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    inventory = commands.add_parser("inventory")
    inventory.add_argument("--artifact-dir", required=True, type=Path)
    inventory.add_argument("--expected", action="append", required=True)

    branches = commands.add_parser("branches")
    branches.add_argument("--report", required=True, type=Path)
    branches.add_argument("--fail-under", required=True)
    branches.add_argument(
        "--critical-prefix",
        action="append",
        default=[],
        metavar="DIRECTORY/=PERCENT",
        help="Require an aggregate pure-branch floor for one critical source directory.",
    )
    return parser


def _validated_expected_names(expected_names: list[str]) -> tuple[str, ...]:
    if len(expected_names) != len(set(expected_names)):
        raise ValueError("expected coverage artifact names must be unique")
    for name in expected_names:
        if (
            len(name) > MAX_COVERAGE_ARTIFACT_NAME_CHARS
            or re.fullmatch(r"\.coverage\.[A-Za-z0-9][A-Za-z0-9_.-]*", name) is None
        ):
            raise ValueError("expected coverage artifact name is invalid")
    return tuple(expected_names)


def _normalized_source_path(raw_path: str) -> str:
    normalized = raw_path.replace("\\", "/")
    parts = normalized.split("/")
    if (
        not normalized.startswith(SOURCE_COVERAGE_PREFIX)
        or normalized.startswith("/")
        or ":" in normalized
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise ValueError("coverage path is not confined to the agent_assure source package")
    return normalized


def _coverage_database_digest(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_COVERAGE_DATABASE_BYTES:
                raise ValueError("coverage database exceeds the byte limit")
            digest.update(chunk)
    if size == 0:
        raise ValueError("coverage database is empty")
    return digest.hexdigest(), size


def _expected_source_files() -> set[str]:
    source_root = REPOSITORY_ROOT / "src" / "agent_assure"
    if not source_root.is_dir():
        raise ValueError("agent_assure source package is absent")
    expected = {
        path.relative_to(REPOSITORY_ROOT).as_posix()
        for path in source_root.rglob("*.py")
        if path.is_file() and not path.is_symlink()
    }
    if not expected:
        raise ValueError("agent_assure source package contains no Python files")
    return expected


def _validate_coverage_database(
    path: Path,
    *,
    expected_source_files: set[str],
) -> dict[str, object]:
    if path.is_symlink():
        raise ValueError("coverage artifact must not be a symlink")
    try:
        mode = path.stat(follow_symlinks=False).st_mode
    except OSError as exc:
        raise ValueError("coverage artifact cannot be inspected") from exc
    if not stat.S_ISREG(mode):
        raise ValueError("coverage artifact is not a regular file")

    digest_before, size_before = _coverage_database_digest(path)
    data = CoverageData(basename=str(path))
    try:
        data.read()
    except CoverageException as exc:
        raise ValueError("coverage database is unreadable") from exc
    digest_after, size_after = _coverage_database_digest(path)
    if (digest_after, size_after) != (digest_before, size_before):
        raise ValueError("coverage database changed while it was being validated")
    try:
        if not data.has_arcs():
            raise ValueError("coverage database was not recorded in branch mode")
        measured_files = data.measured_files()
        if not measured_files:
            raise ValueError("coverage database contains no measured files")
        if any(not isinstance(filename, str) for filename in measured_files):
            raise ValueError("coverage database contains a non-string measured path")
        normalized_files = {_normalized_source_path(filename) for filename in measured_files}
        if len(normalized_files) != len(measured_files):
            raise ValueError("coverage database contains colliding normalized paths")
        if normalized_files != expected_source_files:
            raise ValueError(
                "coverage database measured-file inventory does not match the source package"
            )
        arc_count = sum(len(data.arcs(filename) or ()) for filename in measured_files)
    except (CoverageException, TypeError, AttributeError) as exc:
        raise ValueError("coverage database cannot be queried") from exc
    if arc_count == 0:
        raise ValueError("coverage database contains no measured branch arcs")
    return {
        "arc_count": arc_count,
        "bytes": size_before,
        "file_count": len(measured_files),
        "sha256": digest_before,
    }


def _check_inventory(directory: Path, expected_names: list[str]) -> tuple[bool, dict[str, object]]:
    expected_names_tuple = _validated_expected_names(expected_names)
    if directory.is_symlink():
        raise ValueError("coverage artifact directory must not be a symlink")
    try:
        directory_mode = directory.stat(follow_symlinks=False).st_mode
    except OSError as exc:
        raise ValueError("coverage artifact directory is absent or invalid") from exc
    if not stat.S_ISDIR(directory_mode):
        raise ValueError("coverage artifact directory is absent or invalid")
    entries = tuple(directory.iterdir())
    if any(
        entry.is_symlink() or not stat.S_ISREG(entry.stat(follow_symlinks=False).st_mode)
        for entry in entries
    ):
        raise ValueError("coverage artifact directory contains a non-file entry")
    expected = set(expected_names_tuple)
    actual = {entry.name for entry in entries}
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    ready = not missing and not unexpected
    result: dict[str, object] = {
        "actual_count": len(actual),
        "expected_count": len(expected),
        "missing": missing,
        "unexpected": unexpected,
    }
    if not ready:
        return False, result
    expected_source_files = _expected_source_files()
    result["databases"] = {
        name: _validate_coverage_database(
            directory / name,
            expected_source_files=expected_source_files,
        )
        for name in sorted(expected_names_tuple)
    }
    return True, result


def _required_decimal(raw: str) -> Decimal:
    try:
        value = Decimal(raw)
    except InvalidOperation as exc:
        raise ValueError("coverage threshold must be numeric") from exc
    if not value.is_finite() or value < 0 or value > 100:
        raise ValueError("coverage threshold must be finite and between 0 and 100")
    return value


def _required_count(totals: dict[str, object], key: str) -> int:
    value = totals.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"coverage report field {key!r} must be a non-negative integer")
    return value


def _critical_prefix_specs(raw_specs: list[str]) -> tuple[tuple[str, Decimal], ...]:
    if len(raw_specs) > MAX_CRITICAL_COVERAGE_PREFIXES:
        raise ValueError("too many critical coverage prefixes")
    parsed: list[tuple[str, Decimal]] = []
    seen: set[str] = set()
    for raw_spec in raw_specs:
        raw_prefix, separator, raw_threshold = raw_spec.rpartition("=")
        prefix = raw_prefix.replace("\\", "/")
        if (
            separator != "="
            or not prefix.endswith("/")
            or len(prefix) > MAX_COVERAGE_PREFIX_CHARS
            or not prefix.startswith(SOURCE_COVERAGE_PREFIX)
            or ":" in prefix
            or any(part in {"", ".", ".."} for part in prefix[:-1].split("/"))
        ):
            raise ValueError(
                "critical coverage prefix must be a bounded relative directory ending in '/'"
            )
        if prefix in seen:
            raise ValueError("critical coverage prefixes must be unique")
        seen.add(prefix)
        parsed.append((prefix, _required_decimal(raw_threshold)))
    return tuple(parsed)


def _validated_branch_files(
    payload: dict[str, object],
) -> dict[str, tuple[int, int]]:
    meta = payload.get("meta")
    if (
        not isinstance(meta, dict)
        or meta.get("branch_coverage") is not True
        or meta.get("format") != 3
        or meta.get("version") != coverage.__version__
    ):
        raise ValueError("coverage report metadata is absent or incompatible")
    raw_files = payload.get("files")
    if not isinstance(raw_files, dict) or not raw_files:
        raise ValueError("coverage report does not contain nonempty file coverage")

    normalized_files: dict[str, tuple[int, int]] = {}
    for raw_path, details in raw_files.items():
        normalized_path = _normalized_source_path(str(raw_path))
        if normalized_path in normalized_files:
            raise ValueError("coverage report contains colliding normalized paths")
        if not isinstance(details, dict) or not isinstance(details.get("summary"), dict):
            raise ValueError("coverage file entry does not contain an object-valued summary")
        summary: dict[str, object] = details["summary"]
        covered = _required_count(summary, "covered_branches")
        total = _required_count(summary, "num_branches")
        if covered > total:
            raise ValueError("coverage file branch counts are inconsistent")
        normalized_files[normalized_path] = (covered, total)
    if set(normalized_files) != _expected_source_files():
        raise ValueError("coverage report file inventory does not match the source package")
    return normalized_files


def _critical_branch_results(
    files: dict[str, tuple[int, int]],
    specs: tuple[tuple[str, Decimal], ...],
) -> tuple[bool, list[dict[str, object]]]:
    if not specs:
        return True, []
    results: list[dict[str, object]] = []
    ready = True
    for prefix, threshold in specs:
        covered = 0
        total = 0
        matched = 0
        for path, (file_covered, file_total) in files.items():
            if not path.startswith(prefix):
                continue
            covered += file_covered
            total += file_total
            matched += 1
        if matched == 0 or total == 0 or covered > total:
            raise ValueError(f"critical coverage prefix has no valid branch data: {prefix}")
        percent = Decimal(covered) * Decimal(100) / Decimal(total)
        prefix_ready = percent >= threshold
        ready = ready and prefix_ready
        results.append(
            {
                "branches_covered": covered,
                "branches_total": total,
                "fail_under": str(threshold),
                "file_count": matched,
                "percent_branches_covered": str(percent.quantize(Decimal("0.01"))),
                "prefix": prefix,
                "ready": prefix_ready,
            }
        )
    return ready, results


def _check_branches(
    report_path: Path,
    raw_threshold: str,
    raw_critical_prefixes: list[str],
) -> tuple[bool, dict[str, object]]:
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("totals"), dict):
        raise ValueError("coverage report does not contain an object-valued totals field")
    totals: dict[str, object] = payload["totals"]
    covered = _required_count(totals, "covered_branches")
    total = _required_count(totals, "num_branches")
    if total == 0 or covered > total:
        raise ValueError("coverage branch counts are inconsistent")
    files = _validated_branch_files(payload)
    if (
        sum(file_covered for file_covered, _ in files.values()) != covered
        or sum(file_total for _, file_total in files.values()) != total
    ):
        raise ValueError("coverage report totals do not reconcile with its file summaries")
    threshold = _required_decimal(raw_threshold)
    percent = Decimal(covered) * Decimal(100) / Decimal(total)
    critical_ready, critical_results = _critical_branch_results(
        files,
        _critical_prefix_specs(raw_critical_prefixes),
    )
    ready = percent >= threshold and critical_ready
    return ready, {
        "branches_covered": covered,
        "branches_total": total,
        "critical_prefixes": critical_results,
        "fail_under": str(threshold),
        "file_count": len(files),
        "percent_branches_covered": str(percent.quantize(Decimal("0.01"))),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "inventory":
            ready, result = _check_inventory(args.artifact_dir, args.expected)
        else:
            ready, result = _check_branches(
                args.report,
                args.fail_under,
                args.critical_prefix,
            )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        result = {
            "failure_category": exc.__class__.__name__,
            "ready": False,
        }
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 2
    result["ready"] = ready
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if ready else 1


if __name__ == "__main__":
    raise SystemExit(main())
