from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[3]
MATRIX = ROOT / "docs" / "threat_coverage_matrix.yaml"
MITRE_ATLAS_IDS = ROOT / "tests" / "vectors" / "mitre_atlas" / "atlas_2026_06_ids.yaml"
MITRE_ATLAS_DOC = ROOT / "docs" / "governance_crosswalk_mitre_atlas.md"
ISO_IEC_42001_DOC = ROOT / "docs" / "governance_crosswalk_iso42001.md"
DOCS_INDEX = ROOT / "docs" / "index.md"
MKDOCS_CONFIG = ROOT / "mkdocs.yml"
VALID_MAPPING_STRENGTHS = {"direct", "partial", "adjacent", "gap", "not_applicable"}
CONTROL_MAPPING_STRENGTHS = {"direct", "partial", "adjacent", "not_applicable"}
UNCOVERED_MAPPING_STRENGTHS = {"gap", "not_applicable"}
VALID_OWASP_LLM_RISKS = {f"LLM{index:02d}" for index in range(1, 11)}
VALID_NIST_AI_RMF_FUNCTIONS = {"Govern", "Map", "Measure", "Manage"}
PUBLIC_GAP_LABELS = {
    "live-adapter-attestation": "live adapter producer verification",
    "safety-or-regulatory-certification": "safety or regulatory status",
}


def _load_matrix() -> dict[str, Any]:
    return yaml.safe_load(MATRIX.read_text(encoding="utf-8"))


def _load_atlas_ids() -> dict[str, Any]:
    return yaml.safe_load(MITRE_ATLAS_IDS.read_text(encoding="utf-8"))


def test_threat_coverage_matrix_pins_mitre_atlas_snapshot() -> None:
    matrix = _load_matrix()
    atlas_ids = _load_atlas_ids()
    snapshot = matrix["taxonomies"]["mitre_atlas_snapshot"]

    assert snapshot["name"] == "MITRE ATLAS"
    assert snapshot["release"] == atlas_ids["release"] == "2026.06"
    assert snapshot["release_date"] == atlas_ids["release_date"] == "2026-06-30"
    assert snapshot["artifact_modified_date"] == atlas_ids["artifact_modified_date"]
    assert snapshot["format_version"] == atlas_ids["format_version"] == "6.0.0"
    assert snapshot["source"] == atlas_ids["source"]


def test_mitre_atlas_vector_documents_offline_refresh_path() -> None:
    text = MITRE_ATLAS_IDS.read_text(encoding="utf-8")

    assert "derived from the pinned MITRE ATLAS YAML" in text
    assert "Refresh this file whenever docs/threat_coverage_matrix.yaml pins a new" in text
    assert "manifest release date" in text
    assert "YAML artifact modified date" in text


def test_governance_crosswalk_docs_are_linked_from_public_docs() -> None:
    index = DOCS_INDEX.read_text(encoding="utf-8")
    mkdocs = MKDOCS_CONFIG.read_text(encoding="utf-8")

    for crosswalk in (
        "governance_crosswalk_iso42001.md",
        "governance_crosswalk_mitre_atlas.md",
    ):
        assert crosswalk in index
        assert crosswalk in mkdocs


def test_evaluated_controls_have_mitre_atlas_crosswalks() -> None:
    matrix = _load_matrix()
    atlas_ids = _load_atlas_ids()
    controls = matrix["controls"]

    assert controls
    for control in controls:
        atlas = control.get("mitre_atlas")
        assert atlas, f"{control['id']} is missing MITRE ATLAS mapping"
        assert atlas["mapping_strength"] in CONTROL_MAPPING_STRENGTHS
        _assert_valid_atlas_references(
            atlas,
            atlas_ids,
            owner=control["id"],
        )


def test_other_taxonomy_tags_use_expected_shapes() -> None:
    matrix = _load_matrix()
    entries = matrix["controls"] + matrix["uncovered"]

    for entry in matrix["controls"]:
        assert entry["owasp_risks"], f"{entry['id']} is missing OWASP LLM risks"
        assert set(entry["owasp_risks"]).issubset(VALID_OWASP_LLM_RISKS)
        assert entry["iso_iec_42001_areas"], f"{entry['id']} is missing ISO areas"
        assert all(isinstance(area, str) and area.strip() for area in entry["iso_iec_42001_areas"])

    for entry in entries:
        assert entry["nist_ai_rmf"], f"{entry['id']} is missing NIST AI RMF functions"
        assert set(entry["nist_ai_rmf"]).issubset(VALID_NIST_AI_RMF_FUNCTIONS)


def test_prompt_injection_mapping_uses_current_atlas_prompt_techniques() -> None:
    matrix = _load_matrix()
    controls = {control["id"]: control for control in matrix["controls"]}
    atlas = controls["prompt_injection_control_boundary"]["mitre_atlas"]

    assert atlas["mapping_strength"] == "partial"
    assert "AML.T0051" in atlas["techniques"]
    assert "AML.T0051.000" in atlas["techniques"]
    assert "AML.T0051.001" in atlas["techniques"]
    assert "AML.T0051.002" in atlas["techniques"]
    assert "AML.T0093" in atlas["techniques"]


def test_live_openai_endpoint_allowlist_maps_only_endpoint_access_ids() -> None:
    matrix = _load_matrix()
    controls = {control["id"]: control for control in matrix["controls"]}
    atlas = controls["live_openai_endpoint_allowlist"]["mitre_atlas"]

    assert atlas["mapping_strength"] == "partial"
    assert atlas["tactics"] == ["AML.TA0000", "AML.TA0014"]
    assert atlas["techniques"] == ["AML.T0040", "AML.T0096"]


def test_uncovered_items_preserve_atlas_relevant_gaps() -> None:
    matrix = _load_matrix()
    atlas_ids = _load_atlas_ids()
    uncovered = {item["id"]: item for item in matrix["uncovered"]}

    assert uncovered["live-adapter-attestation"]["mitre_atlas"]["mapping_strength"] == "gap"
    assert "AML.T0010" in uncovered["live-adapter-attestation"]["mitre_atlas"]["techniques"]
    assert (
        uncovered["context-discovery-and-stakeholder-impact-mapping"]["mitre_atlas"][
            "mapping_strength"
        ]
        == "not_applicable"
    )
    assert (
        uncovered["context-discovery-and-stakeholder-impact-mapping"]["mitre_atlas"][
            "techniques"
        ]
        == []
    )
    assert (
        uncovered["safety-or-regulatory-certification"]["mitre_atlas"]["mapping_strength"]
        == "not_applicable"
    )
    assert uncovered["safety-or-regulatory-certification"]["mitre_atlas"]["techniques"] == []

    for item in uncovered.values():
        atlas = item["mitre_atlas"]
        assert atlas["mapping_strength"] in UNCOVERED_MAPPING_STRENGTHS
        _assert_valid_atlas_references(atlas, atlas_ids, owner=item["id"])


def test_mitre_atlas_crosswalk_doc_matches_yaml_source_of_truth() -> None:
    matrix = _load_matrix()
    atlas_ids = _load_atlas_ids()
    snapshot = matrix["taxonomies"]["mitre_atlas_snapshot"]
    doc = MITRE_ATLAS_DOC.read_text(encoding="utf-8")
    normalized_doc = " ".join(doc.split())

    assert f"- Source: `{snapshot['source']}`" in doc
    assert f"- ATLAS release: `{snapshot['release']}`" in doc
    assert f"- Release date: `{snapshot['release_date']}`" in doc
    assert f"- Artifact modified date: `{snapshot['artifact_modified_date']}`" in doc
    assert f"- Format version: `{snapshot['format_version']}`" in doc
    assert (
        "The release date comes from the ATLAS manifest entry for release "
        f"`{snapshot['release']}`."
    ) in doc
    assert "Tactics and techniques are listed as control-level unions." in doc
    assert "partially evaluated for one local boundary while remaining a gap" in normalized_doc
    assert "ATLAS is an adversary technique catalog" in doc
    assert "used for non-adversarial controls" in doc
    assert "not ATLAS technique emulations" in doc

    control_rows = [_format_control_row(control, atlas_ids) for control in matrix["controls"]]
    gap_rows = [_format_gap_row(item) for item in matrix["uncovered"]]

    assert _table_rows_after_heading(doc, "## Current Control Mapping") == control_rows
    assert _table_rows_after_heading(doc, "## Current Gaps") == gap_rows


def test_iso42001_crosswalk_doc_matches_yaml_source_of_truth() -> None:
    matrix = _load_matrix()
    doc = ISO_IEC_42001_DOC.read_text(encoding="utf-8")

    assert "reviewer-facing concept labels" in doc

    control_rows = [_format_iso_control_row(control) for control in matrix["controls"]]

    assert _table_rows_after_heading(doc, "## Current Control Mapping") == control_rows


def _assert_valid_atlas_references(
    atlas: dict[str, Any],
    atlas_ids: dict[str, Any],
    *,
    owner: str,
) -> None:
    tactics = atlas["tactics"]
    techniques = atlas["techniques"]

    assert atlas["mapping_strength"] in VALID_MAPPING_STRENGTHS
    if atlas["mapping_strength"] == "not_applicable":
        assert tactics == [], f"{owner} should not list ATLAS tactics"
        assert techniques == [], f"{owner} should not list ATLAS techniques"
        return

    assert tactics, f"{owner} is missing ATLAS tactics"
    assert techniques, f"{owner} is missing ATLAS techniques"
    for tactic in tactics:
        assert tactic in atlas_ids["tactics"], f"{owner} references unknown ATLAS tactic {tactic}"
    for technique in techniques:
        assert (
            technique in atlas_ids["techniques"]
        ), f"{owner} references unknown ATLAS technique {technique}"


def _format_control_row(control: dict[str, Any], atlas_ids: dict[str, Any]) -> str:
    atlas = control["mitre_atlas"]
    tactic_names = _format_names(atlas["tactics"], atlas_ids["tactics"])
    technique_names = _format_techniques(atlas["techniques"], atlas_ids["techniques"])
    return (
        f"| `{control['id']}` | `{atlas['mapping_strength']}` | "
        f"{tactic_names} | {technique_names} |"
    )


def _format_gap_row(item: dict[str, Any]) -> str:
    atlas = item["mitre_atlas"]
    techniques = _format_ids(atlas["techniques"])
    label = PUBLIC_GAP_LABELS.get(item["id"], item["id"])
    return f"| `{label}` | `{atlas['mapping_strength']}` | {techniques} |"


def _format_iso_control_row(control: dict[str, Any]) -> str:
    areas = "; ".join(control["iso_iec_42001_areas"])
    threats = _format_ids(control["project_threats"])
    return f"| `{control['id']}` | `{control['status']}` | {areas} | {threats} |"


def _format_names(ids: list[str], names: dict[str, str]) -> str:
    if not ids:
        return "None"
    return "; ".join(names[item] for item in ids)


def _format_techniques(ids: list[str], names: dict[str, str]) -> str:
    if not ids:
        return "None"
    return "; ".join(f"`{item}` {names[item]}" for item in ids)


def _format_ids(ids: list[str]) -> str:
    if not ids:
        return "None"
    return ", ".join(f"`{item}`" for item in ids)


def _table_rows_after_heading(doc: str, heading: str) -> list[str]:
    assert heading in doc
    section = doc.split(heading, maxsplit=1)[1]
    next_heading = section.find("\n## ")
    if next_heading != -1:
        section = section[:next_heading]
    return [line.strip() for line in section.splitlines() if line.startswith("| `")]
