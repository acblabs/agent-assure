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


def test_claim_boundary_allows_project_limitation_phrase() -> None:
    violations = claim_boundaries.find_claim_boundary_violations(
        "This project is not a compliance attestation.",
        path=Path("README.md"),
    )

    assert violations == []


def test_claim_boundary_allows_markdown_decorated_limitation_phrase() -> None:
    violations = claim_boundaries.find_claim_boundary_violations(
        "- **This report is not a compliance attestation.**",
        path=Path("docs/report.md"),
    )

    assert violations == []


def test_claim_boundary_allows_control_report_required_limitation() -> None:
    violations = claim_boundaries.find_claim_boundary_violations(
        "This report maps observed `agent-assure` evidence to selected framework concepts "
        "for human review. It is not a compliance attestation, certification, audit "
        "opinion, legal conclusion, regulatory conclusion, or safety claim.",
        path=Path("tests/golden/reports/control-coverage-report.md"),
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


def test_claim_boundary_rejects_lowercase_roi() -> None:
    violations = claim_boundaries.find_claim_boundary_violations(
        "roi impact",
        path=Path("README.md"),
    )

    assert [violation.label for violation in violations] == ["ROI"]


def test_claim_boundary_allows_measured_usage_delta() -> None:
    violations = claim_boundaries.find_claim_boundary_violations(
        "Measured usage delta",
        path=Path("README.md"),
    )

    assert violations == []


def test_claim_boundary_rejects_business_savings() -> None:
    violations = claim_boundaries.find_claim_boundary_violations(
        "Business savings from agent process controls",
        path=Path("README.md"),
    )

    assert [violation.label for violation in violations] == ["business savings"]


def test_claim_boundary_rejects_control_report_overclaim_terms() -> None:
    violations = claim_boundaries.find_claim_boundary_violations(
        "Compliance scorecard. ATLAS validation report. Adversary emulation report.",
        path=Path("docs/report.md"),
    )

    assert [violation.label for violation in violations] == [
        "compliance scorecard",
        "ATLAS validation report",
        "adversary emulation report",
    ]


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


def test_default_scan_paths_use_fixed_release_facing_scope(tmp_path: Path) -> None:
    readme = tmp_path / "README.md"
    changelog = tmp_path / "CHANGELOG.md"
    docs = tmp_path / "docs"
    post_dir = docs / "posts"
    assets_dir = docs / "assets"
    social_dir = docs / "social"
    release_notes_dir = docs / "release_notes"
    hidden_demo_dir = tmp_path / ".tmp" / "demo" / "flagship"
    golden_dir = tmp_path / "tests" / "golden" / "reports"
    readme.write_text("# Project\n", encoding="utf-8")
    changelog.write_text("Measured evidence\n", encoding="utf-8")
    docs.mkdir()
    (docs / "for_ai_leaders.md").write_text("Measured evidence\n", encoding="utf-8")
    (docs / "for_engineers.md").write_text("Measured evidence\n", encoding="utf-8")
    (docs / "what_this_measures.md").write_text("Measured evidence\n", encoding="utf-8")
    (docs / "demo_flagship.md").write_text("Measured evidence\n", encoding="utf-8")
    (docs / "demo_expense.md").write_text("Measured evidence\n", encoding="utf-8")
    (docs / "evidence_diff.md").write_text("Measured evidence\n", encoding="utf-8")
    (docs / "claim_boundary.md").write_text("Measured evidence\n", encoding="utf-8")
    post_dir.mkdir()
    post = post_dir / "output_equivalence_is_not_process_equivalence.md"
    post.write_text("Measured evidence\n", encoding="utf-8")
    assets_dir.mkdir()
    transcript = assets_dir / "flagship_demo_transcript.txt"
    transcript.write_text("Measured evidence\n", encoding="utf-8")
    social_dir.mkdir()
    video_script = social_dir / "demo_video_script.md"
    video_script.write_text("Measured evidence\n", encoding="utf-8")
    release_notes_dir.mkdir()
    release_note = release_notes_dir / "v0.1.0.md"
    release_note.write_text("Measured evidence\n", encoding="utf-8")
    hidden_demo_dir.mkdir(parents=True)
    stale_tmp_html = hidden_demo_dir / "evidence-diff.html"
    stale_tmp_html.write_text("ROI impact\n", encoding="utf-8")
    nested = docs / "nested"
    nested.mkdir()
    out_of_scope_doc = nested / "claim.md"
    out_of_scope_doc.write_text("ROI impact", encoding="utf-8")
    golden_dir.mkdir(parents=True)
    golden_html = golden_dir / "flagship-evidence-diff.html"
    golden_html.write_text("Measured evidence\n", encoding="utf-8")

    paths = claim_boundaries.default_scan_paths(tmp_path)

    assert readme in paths
    assert changelog in paths
    assert docs / "for_ai_leaders.md" in paths
    assert docs / "for_engineers.md" in paths
    assert release_note in paths
    assert post in paths
    assert transcript in paths
    assert video_script in paths
    assert golden_html in paths
    assert out_of_scope_doc not in paths
    assert stale_tmp_html not in paths
