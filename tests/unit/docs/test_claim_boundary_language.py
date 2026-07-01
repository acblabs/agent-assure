from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import scripts.check_claim_boundaries as claim_boundaries  # noqa: E402


def test_claim_boundary_rejects_iso_pass_language() -> None:
    violations = claim_boundaries.find_claim_boundary_violations(
        "ISO 42001: PASS",
        path=Path("README.md"),
    )

    assert [violation.label for violation in violations] == ["ISO pass"]


def test_claim_boundary_allows_reviewed_limitation_phrase() -> None:
    violations = claim_boundaries.find_claim_boundary_violations(
        "This is not a compliance attestation",
        path=Path("README.md"),
    )

    assert violations == []


def test_claim_boundary_allows_markdown_decorated_limitation_phrase() -> None:
    violations = claim_boundaries.find_claim_boundary_violations(
        "- **This report is not a compliance attestation.**",
        path=Path("docs/report.md"),
    )

    assert violations == []


def test_claim_boundary_allows_html_limitation_paragraph() -> None:
    violations = claim_boundaries.find_claim_boundary_violations(
        "<h2>Claim Boundary</h2>\n<p>This report is not a compliance attestation.</p>",
        path=Path("tests/golden/reports/evidence-diff.html"),
    )

    assert violations == []


def test_claim_boundary_rejects_roi_impact() -> None:
    violations = claim_boundaries.find_claim_boundary_violations(
        "ROI impact",
        path=Path("README.md"),
    )

    assert [violation.label for violation in violations] == ["ROI"]


def test_claim_boundary_allows_measured_usage_delta() -> None:
    violations = claim_boundaries.find_claim_boundary_violations(
        "Measured usage delta",
        path=Path("README.md"),
    )

    assert violations == []


def test_claim_boundary_sentence_splitter_ignores_version_dots() -> None:
    violations = claim_boundaries.find_claim_boundary_violations(
        "In v0.2.0 the release note says ROI impact.",
        path=Path("docs/release.md"),
    )

    assert violations[0].sentence == "In v0.2.0 the release note says ROI impact."


def test_claim_boundary_splits_adjacent_markdown_list_items() -> None:
    violations = claim_boundaries.find_claim_boundary_violations(
        "- System is compliant\n"
        "- This is not a compliance attestation.",
        path=Path("docs/list.md"),
    )

    assert len(violations) == 1
    assert violations[0].sentence == "- System is compliant"


def test_default_scan_paths_include_docs_prose(tmp_path: Path) -> None:
    readme = tmp_path / "README.md"
    docs = tmp_path / "docs"
    nested = docs / "nested"
    readme.write_text("# Project\n", encoding="utf-8")
    nested.mkdir(parents=True)
    doc = nested / "claim.md"
    doc.write_text("ROI impact", encoding="utf-8")

    paths = claim_boundaries.default_scan_paths(tmp_path)

    assert readme in paths
    assert doc in paths
