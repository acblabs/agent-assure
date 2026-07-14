from __future__ import annotations

import hashlib
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOP_LEVEL_EXAMPLES = ROOT / "examples"
PACKAGED_EXAMPLES = ROOT / "src" / "agent_assure" / "examples"

EXAMPLE_RESOURCE_SETS = (
    "prior_auth_synthetic",
    "expense_approval_minimal",
    "langgraph_expense_assurance",
    "process_measurement_cases",
    "streaming_process_regression",
)

MIRRORED_RESOURCE_PATHS = (
    Path("README.md"),
    Path("suite.yaml"),
    Path("rag_suite.yaml"),
    Path("fixtures"),
    Path("events"),
    Path("variants"),
)


@dataclass(frozen=True)
class ExampleDrift:
    example: str
    relative_path: Path
    message: str


def main() -> int:
    drift = compare_packaged_examples(TOP_LEVEL_EXAMPLES, PACKAGED_EXAMPLES)
    if drift:
        for finding in drift:
            print(_format_drift(finding), file=sys.stderr)
        return 1
    print("packaged-examples: ok")
    return 0


def compare_packaged_examples(
    top_level_examples: Path,
    packaged_examples: Path,
) -> list[ExampleDrift]:
    findings: list[ExampleDrift] = []
    for example in EXAMPLE_RESOURCE_SETS:
        top_root = top_level_examples / example
        packaged_root = packaged_examples / example
        top_files = _mirrored_files(top_root)
        packaged_files = _mirrored_files(packaged_root)
        relative_paths = sorted(
            set(top_files) | set(packaged_files),
            key=lambda path: path.as_posix(),
        )
        for relative_path in relative_paths:
            top_path = top_files.get(relative_path)
            packaged_path = packaged_files.get(relative_path)
            if top_path is None:
                findings.append(
                    ExampleDrift(
                        example=example,
                        relative_path=relative_path,
                        message="packaged example has no top-level counterpart",
                    )
                )
                continue
            if packaged_path is None:
                findings.append(
                    ExampleDrift(
                        example=example,
                        relative_path=relative_path,
                        message="top-level example is missing from packaged resources",
                    )
                )
                continue
            if _sha256(top_path) != _sha256(packaged_path):
                findings.append(
                    ExampleDrift(
                        example=example,
                        relative_path=relative_path,
                        message="top-level and packaged example files differ",
                    )
                )
    return findings


def _mirrored_files(root: Path) -> dict[Path, Path]:
    files: dict[Path, Path] = {}
    for resource_path in MIRRORED_RESOURCE_PATHS:
        path = root / resource_path
        if not path.exists():
            continue
        if path.is_file():
            files[resource_path] = path
            continue
        for child in sorted(path.rglob("*")):
            if child.is_file():
                files[child.relative_to(root)] = child
    return files


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _format_drift(drift: ExampleDrift) -> str:
    return (
        "packaged-examples: "
        f"{drift.example}/{drift.relative_path.as_posix()}: {drift.message}"
    )


if __name__ == "__main__":
    raise SystemExit(main())
