from __future__ import annotations

import argparse
import json
from decimal import Decimal, InvalidOperation
from pathlib import Path


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
    return parser


def _check_inventory(directory: Path, expected_names: list[str]) -> tuple[bool, dict[str, object]]:
    if len(expected_names) != len(set(expected_names)):
        raise ValueError("expected coverage artifact names must be unique")
    if not directory.is_dir():
        raise ValueError("coverage artifact directory is absent or invalid")
    entries = tuple(directory.iterdir())
    if any(not entry.is_file() for entry in entries):
        raise ValueError("coverage artifact directory contains a non-file entry")
    expected = set(expected_names)
    actual = {entry.name for entry in entries}
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    ready = not missing and not unexpected
    return ready, {
        "actual_count": len(actual),
        "expected_count": len(expected),
        "missing": missing,
        "unexpected": unexpected,
    }


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


def _check_branches(report_path: Path, raw_threshold: str) -> tuple[bool, dict[str, object]]:
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("totals"), dict):
        raise ValueError("coverage report does not contain an object-valued totals field")
    totals: dict[str, object] = payload["totals"]
    covered = _required_count(totals, "covered_branches")
    total = _required_count(totals, "num_branches")
    if total == 0 or covered > total:
        raise ValueError("coverage branch counts are inconsistent")
    threshold = _required_decimal(raw_threshold)
    percent = Decimal(covered) * Decimal(100) / Decimal(total)
    ready = percent >= threshold
    return ready, {
        "branches_covered": covered,
        "branches_total": total,
        "fail_under": str(threshold),
        "percent_branches_covered": str(percent.quantize(Decimal("0.01"))),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "inventory":
            ready, result = _check_inventory(args.artifact_dir, args.expected)
        else:
            ready, result = _check_branches(args.report, args.fail_under)
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
