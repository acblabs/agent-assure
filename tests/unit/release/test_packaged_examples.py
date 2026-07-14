from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from check_packaged_examples import compare_packaged_examples  # noqa: E402


def test_packaged_examples_match_when_mirrored_resources_match(tmp_path: Path) -> None:
    top_level, packaged = _write_example_pair(tmp_path, content="same")

    drift = compare_packaged_examples(top_level, packaged)

    assert drift == []


def test_packaged_examples_report_content_drift(tmp_path: Path) -> None:
    top_level, packaged = _write_example_pair(tmp_path, content="top-level")
    (
        packaged
        / "prior_auth_synthetic"
        / "fixtures"
        / "shared"
        / "requests"
        / "case.json"
    ).write_text("packaged\n", encoding="utf-8")

    drift = compare_packaged_examples(top_level, packaged)

    assert len(drift) == 1
    assert drift[0].example == "prior_auth_synthetic"
    assert drift[0].relative_path.as_posix() == "fixtures/shared/requests/case.json"
    assert "differ" in drift[0].message


def test_packaged_examples_report_missing_resource(tmp_path: Path) -> None:
    top_level, packaged = _write_example_pair(tmp_path, content="same")
    (
        packaged
        / "expense_approval_minimal"
        / "variants"
        / "baseline.yaml"
    ).unlink()

    drift = compare_packaged_examples(top_level, packaged)

    assert len(drift) == 1
    assert drift[0].example == "expense_approval_minimal"
    assert drift[0].relative_path.as_posix() == "variants/baseline.yaml"
    assert "missing from packaged resources" in drift[0].message


def _write_example_pair(tmp_path: Path, *, content: str) -> tuple[Path, Path]:
    top_level = tmp_path / "examples"
    packaged = tmp_path / "src" / "agent_assure" / "examples"
    for root in (top_level, packaged):
        for example in (
            "prior_auth_synthetic",
            "expense_approval_minimal",
            "langgraph_expense_assurance",
            "process_measurement_cases",
            "streaming_process_regression",
        ):
            example_root = root / example
            (example_root / "fixtures" / "shared" / "requests").mkdir(parents=True)
            (example_root / "events").mkdir(parents=True)
            (example_root / "variants").mkdir(parents=True)
            (example_root / "README.md").write_text("# Example\n", encoding="utf-8")
            (example_root / "suite.yaml").write_text(
                f"suite_id: {example}\n",
                encoding="utf-8",
            )
            (example_root / "variants" / "baseline.yaml").write_text(
                "variant_id: baseline\n",
                encoding="utf-8",
            )
            (example_root / "fixtures" / "shared" / "requests" / "case.json").write_text(
                f"{content}\n",
                encoding="utf-8",
            )
            (example_root / "events" / "baseline.jsonl").write_text(
                f"{content}\n",
                encoding="utf-8",
            )
    return top_level, packaged
