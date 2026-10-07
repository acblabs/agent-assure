from __future__ import annotations

import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import agent_assure.atlas_catalog as atlas_catalog_module  # noqa: E402
import agent_assure.controls.coverage as coverage_module  # noqa: E402
import scripts.check_claim_boundaries as claim_boundaries  # noqa: E402
from agent_assure.atlas_catalog import (  # noqa: E402
    MITRE_ATLAS_2026_06_CATALOG_SHA256,
    load_mitre_atlas_2026_06_catalog,
)
from agent_assure.controls.coverage import (  # noqa: E402
    CLAIM_BOUNDARY,
    MITRE_ATLAS_BOUNDARY,
    FrameworkMapping,
    MappingControl,
    MappingRequirement,
    MappingRule,
    build_control_coverage_report,
    load_framework_mapping,
)
from agent_assure.privacy.detectors import (  # noqa: E402
    PRIVACY_PROFILE_DIGEST,
    PRIVACY_PROFILE_ID,
)
from agent_assure.reporting.controls import (  # noqa: E402
    render_control_coverage_markdown,
    write_control_coverage_report,
)
from agent_assure.schema.common import GateState, ReasonCode  # noqa: E402
from agent_assure.schema.controls import (  # noqa: E402
    ControlCoverageReport,
    ControlCoverageState,
    ControlFramework,
    _derive_control_coverage_report_id,
)
from agent_assure.schema.evaluation import EvaluationSummary, Finding  # noqa: E402
from agent_assure.schema.packet import EvidencePacket, PacketArtifactDigest  # noqa: E402


def test_nist_map_distinguishes_contradictory_evidence_and_digests() -> None:
    report = build_control_coverage_report(
        _packet_with_material_evidence_failure(),
        framework=ControlFramework.nist_ai_rmf,
        evidence_packet_digest="2" * 64,
    )

    measure_item = next(item for item in report.items if item.control_id == "MEASURE-2.x")

    assert report.evidence_packet_digest == "2" * 64
    assert len(report.mapping_digest) == 64
    assert measure_item.coverage_state is ControlCoverageState.contradictory_evidence_observed
    assert report.coverage_state_counts["contradictory_evidence_observed"] == 1
    assert CLAIM_BOUNDARY in report.limitations
    assert all(item.mapping_strength is None for item in report.items)
    assert all(not item.atlas_tactic_ids for item in report.items)
    assert all(not item.atlas_technique_ids for item in report.items)


def test_control_coverage_builder_rejects_unsafe_packet_copy() -> None:
    packet = _packet_with_material_evidence_failure()
    finding = packet.evaluation.findings[0]
    forged_evaluation = packet.evaluation.model_copy(
        update={"findings": (finding.model_copy(update={"state": GateState.pass_}),)}
    )
    forged_packet = packet.model_copy(update={"evaluation": forged_evaluation})

    with pytest.raises(
        ValidationError,
        match="finding-derived state|evaluation summaries must not carry pass-state findings",
    ):
        build_control_coverage_report(
            forged_packet,
            framework=ControlFramework.owasp_llm_top_10_2025,
            evidence_packet_digest="2" * 64,
        )


def test_control_coverage_reporting_rejects_archival_wire_before_output(
    tmp_path: Path,
) -> None:
    report = build_control_coverage_report(
        _green_packet(),
        framework=ControlFramework.nist_ai_rmf,
        evidence_packet_digest="2" * 64,
    )
    archival = ControlCoverageReport.model_validate(_historical_report_payload(report, "0.2.0"))
    output = tmp_path / "coverage"

    with pytest.raises(ValueError, match="frozen validation policy|archival-only"):
        render_control_coverage_markdown(archival)
    with pytest.raises(ValueError, match="frozen validation policy|archival-only"):
        write_control_coverage_report(archival, output)

    assert not output.exists()


def test_control_coverage_writer_revalidates_post_redaction_payload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = build_control_coverage_report(
        _green_packet(),
        framework=ControlFramework.nist_ai_rmf,
        evidence_packet_digest="2" * 64,
    )
    monkeypatch.setattr(
        "agent_assure.reporting.controls.redact_artifact_payload",
        lambda payload, **_kwargs: _historical_report_payload(
            ControlCoverageReport.model_validate(payload),
            "0.2.0",
        ),
    )
    output = tmp_path / "coverage"

    with pytest.raises(ValueError, match="frozen validation policy|archival-only"):
        write_control_coverage_report(report, output)

    assert not output.exists()


def test_mitre_map_includes_pinned_release_and_mapping_strength() -> None:
    loaded = load_framework_mapping(ControlFramework.mitre_atlas_2026_06)
    report = build_control_coverage_report(
        _packet_with_material_evidence_failure(),
        framework=ControlFramework.mitre_atlas_2026_06,
        evidence_packet_digest="2" * 64,
    )
    citation_item = next(item for item in report.items if item.control_id == "AML.T0067.000")

    assert loaded.mapping.framework_version == "2026.06"
    assert all(control.mapping_strength is not None for control in loaded.mapping.controls)
    assert citation_item.mapping_strength is not None
    assert citation_item.mapping_strength.value == "partial"
    assert citation_item.atlas_tactic_ids == ("AML.TA0007",)
    assert citation_item.atlas_technique_ids == ("AML.T0067.000",)
    assert MITRE_ATLAS_BOUNDARY in report.limitations


def test_control_evaluated_does_not_infer_green_pass_without_control_trace() -> None:
    report = build_control_coverage_report(
        _green_packet(),
        framework=ControlFramework.owasp_llm_top_10_2025,
        evidence_packet_digest="2" * 64,
    )
    prompt_item = next(item for item in report.items if item.control_id == "LLM01")
    evaluation = next(
        rule
        for rule in prompt_item.condition_evaluations
        if rule.rule_id == "prompt-boundary-evaluated"
    )

    assert prompt_item.coverage_state is ControlCoverageState.not_evaluated
    assert evaluation.signal == "control_evaluated"
    assert evaluation.condition == "prompt_injection_control_boundary"
    assert evaluation.observed is False
    assert evaluation.coverage_state is ControlCoverageState.not_evaluated
    assert "passing controls are not inferred" in evaluation.rationale


def test_unrelated_finding_does_not_observe_other_control_mappings() -> None:
    report = build_control_coverage_report(
        _packet_with_material_evidence_failure(),
        framework=ControlFramework.owasp_llm_top_10_2025,
        evidence_packet_digest="2" * 64,
    )
    prompt_item = next(item for item in report.items if item.control_id == "LLM01")
    claim_item = next(item for item in report.items if item.control_id == "LLM09")

    assert claim_item.coverage_state is ControlCoverageState.contradictory_evidence_observed
    assert prompt_item.coverage_state is ControlCoverageState.not_evaluated
    assert not any(rule.observed for rule in prompt_item.condition_evaluations)


def test_optional_control_without_trace_stays_not_evaluated() -> None:
    report = build_control_coverage_report(
        _packet_with_material_evidence_failure(),
        framework=ControlFramework.nist_ai_rmf,
        evidence_packet_digest="2" * 64,
    )
    review_item = next(item for item in report.items if item.control_id == "MANAGE-1.x")

    assert review_item.coverage_state is ControlCoverageState.not_evaluated
    assert all(not rule.observed for rule in review_item.condition_evaluations)


def test_observed_rule_refs_project_exactly_to_item_level_evidence() -> None:
    report = build_control_coverage_report(
        _green_packet(),
        framework=ControlFramework.nist_ai_rmf,
        evidence_packet_digest="2" * 64,
    )
    govern_item = next(item for item in report.items if item.control_id == "GOVERN-1.x")
    evaluation = govern_item.condition_evaluations[0]

    assert govern_item.coverage_state is ControlCoverageState.observed
    assert evaluation.observed is True
    assert len(evaluation.evidence_refs) == 2
    assert govern_item.evidence_refs == evaluation.evidence_refs

    measure_item = next(item for item in report.items if item.control_id == "MEASURE-2.x")
    partial = next(
        evaluation
        for evaluation in measure_item.condition_evaluations
        if evaluation.coverage_state is ControlCoverageState.partially_observed
    )
    assert measure_item.coverage_state is ControlCoverageState.partially_observed
    assert partial.observed is True
    assert measure_item.evidence_refs == partial.evidence_refs


def test_human_review_failure_contradicts_owasp_llm05() -> None:
    report = build_control_coverage_report(
        _packet_with_control_failure(
            control_id="human_review_required",
            reason_code=ReasonCode.REQUIRED_HUMAN_REVIEW_ABSENT,
        ),
        framework=ControlFramework.owasp_llm_top_10_2025,
        evidence_packet_digest="2" * 64,
    )
    review_item = next(item for item in report.items if item.control_id == "LLM05")

    assert review_item.coverage_state is ControlCoverageState.contradictory_evidence_observed


def test_tool_allowlist_failure_contradicts_nist_manage2() -> None:
    report = build_control_coverage_report(
        _packet_with_control_failure(
            control_id="tool_allowlist",
            reason_code=ReasonCode.FORBIDDEN_TOOL,
        ),
        framework=ControlFramework.nist_ai_rmf,
        evidence_packet_digest="2" * 64,
    )
    manage_item = next(item for item in report.items if item.control_id == "MANAGE-2.x")

    assert manage_item.coverage_state is ControlCoverageState.contradictory_evidence_observed


def test_provider_review_boundary_forbidden_provider_contradicts_nist_manage2() -> None:
    report = build_control_coverage_report(
        _packet_with_control_failure(
            control_id="provider_review_boundary",
            reason_code=ReasonCode.FORBIDDEN_PROVIDER,
        ),
        framework=ControlFramework.nist_ai_rmf,
        evidence_packet_digest="2" * 64,
    )
    manage_item = next(item for item in report.items if item.control_id == "MANAGE-2.x")

    assert manage_item.coverage_state is ControlCoverageState.contradictory_evidence_observed


def test_scope_boundaries_win_over_false_path_not_observed() -> None:
    report = build_control_coverage_report(
        _green_packet(),
        framework=ControlFramework.nist_ai_rmf,
        evidence_packet_digest="2" * 64,
    )
    map_item = next(item for item in report.items if item.control_id == "MAP-1.x")

    assert map_item.coverage_state is ControlCoverageState.out_of_scope
    assert map_item.condition_evaluations[0].observed is True


def test_all_framework_mappings_load_with_stable_digests() -> None:
    first = {framework: load_framework_mapping(framework) for framework in ControlFramework}
    second = {framework: load_framework_mapping(framework) for framework in ControlFramework}

    assert set(first) == set(ControlFramework)
    for framework, loaded in first.items():
        assert len(loaded.digest) == 64
        assert loaded.digest == second[framework].digest
        assert loaded.mapping.framework is framework


def test_framework_mapping_loader_rejects_duplicate_nested_yaml_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"""\
framework: nist-ai-rmf
framework_version: "1.0"
mapping_version: "duplicate-key-test"
source_review:
  reviewed_on: "2026-10-05"
  source_refs:
    - test
limitations:
  - test
controls:
  - id: GOVERN-1.x
    title: First title
    title: Shadowed title
    evidence_rules: []
"""
    monkeypatch.setattr(
        coverage_module,
        "_mapping_bytes",
        lambda _filename: (payload, "duplicate-key-test"),
    )

    with pytest.raises(ValueError, match=r"duplicate YAML mapping key.*title"):
        load_framework_mapping(ControlFramework.nist_ai_rmf)


def test_owasp_executable_map_includes_declared_2025_ids() -> None:
    loaded = load_framework_mapping(ControlFramework.owasp_llm_top_10_2025)
    expected = {f"LLM{index:02d}" for index in range(1, 11)}

    assert expected.issubset({control.id for control in loaded.mapping.controls})


def test_tool_integrity_controls_do_not_claim_owasp_llm07_evidence() -> None:
    loaded = load_framework_mapping(ControlFramework.owasp_llm_top_10_2025)
    llm07 = next(control for control in loaded.mapping.controls if control.id == "LLM07")

    assert llm07.evidence_rules == ()
    assert any("tool-integrity" in limitation for limitation in llm07.limitations)

    report = build_control_coverage_report(
        _green_packet(),
        framework=ControlFramework.owasp_llm_top_10_2025,
        evidence_packet_digest="2" * 64,
    )
    item = next(item for item in report.items if item.control_id == "LLM07")
    assert item.coverage_state is ControlCoverageState.not_observed
    assert item.condition_evaluations == ()


def test_mitre_atlas_mapping_ids_exist_in_production_pinned_catalog() -> None:
    loaded = load_framework_mapping(ControlFramework.mitre_atlas_2026_06)
    catalog = load_mitre_atlas_2026_06_catalog()

    assert catalog.digest == MITRE_ATLAS_2026_06_CATALOG_SHA256
    assert catalog.source.replace("\\", "/").endswith("mappings/mitre_atlas_2026_06_catalog.yaml")
    assert catalog.upstream_release_tag == "v2026.06"
    assert catalog.upstream_commit == "651dad90d3c007e797c89356fa1f4d8732f90c8d"
    assert catalog.upstream_asset_sha256 == (
        "b771de8b1489564b2838a709c7429849a9575dbd94073928817fe1a21661e70a"
    )
    assert catalog.release_announcement_tactic_count == 16
    assert catalog.release_announcement_technique_count == 104
    assert catalog.release_announcement_sub_technique_count == 69
    assert catalog.verified_tactic_count == len(catalog.tactic_ids) == 16
    assert catalog.verified_base_technique_count == 103
    assert catalog.verified_sub_technique_count == 70
    assert len(catalog.technique_ids) == 173
    assert catalog.technique_names["AML.T0051"] == "LLM Prompt Injection"
    with pytest.raises(TypeError):
        catalog.technique_names["AML.T0051"] = "mutable"  # type: ignore[index]
    assert "mappings/mitre_atlas_2026_06_catalog.yaml" in loaded.mapping.source_review.source_refs
    for control in loaded.mapping.controls:
        assert control.id in catalog.technique_ids
        assert set(control.atlas_tactic_ids).issubset(catalog.tactic_ids), control.id
        assert set(control.atlas_technique_ids).issubset(catalog.technique_ids), control.id


def test_mitre_atlas_production_catalog_fails_closed_on_digest_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    catalog_bytes = (ROOT / "mappings" / "mitre_atlas_2026_06_catalog.yaml").read_bytes()
    monkeypatch.setattr(
        atlas_catalog_module,
        "_catalog_bytes",
        lambda: (catalog_bytes + b"\n", "tampered-catalog"),
    )
    atlas_catalog_module.load_mitre_atlas_2026_06_catalog.cache_clear()
    try:
        with pytest.raises(ValueError, match="digest does not match"):
            atlas_catalog_module.load_mitre_atlas_2026_06_catalog()
    finally:
        atlas_catalog_module.load_mitre_atlas_2026_06_catalog.cache_clear()


def test_mitre_atlas_mapping_requires_strength_at_load_time() -> None:
    with pytest.raises(ValidationError, match="mapping_strength"):
        FrameworkMapping.model_validate(
            {
                "framework": "mitre-atlas-2026-06",
                "framework_version": "2026.06",
                "mapping_version": "test",
                "source_review": {
                    "reviewed_on": "2026-07-10",
                    "source_refs": ["mappings/mitre_atlas_2026_06_catalog.yaml"],
                },
                "limitations": ["test"],
                "controls": [
                    {
                        "id": "AML.T0051",
                        "title": "Missing strength",
                        "atlas_tactic_ids": ["AML.TA0004"],
                        "atlas_technique_ids": ["AML.T0051"],
                        "evidence_rules": [
                            {
                                "rule_id": "scope",
                                "requires": [{"signal": "scope_boundary"}],
                                "coverage_state_when_true": "out_of_scope",
                                "coverage_state_when_false": "not_observed",
                            }
                        ],
                    }
                ],
            }
        )


@pytest.mark.parametrize(
    ("field_name", "field_value"),
    (
        ("mapping_strength", "direct"),
        ("atlas_tactic_ids", ["AML.TA0004"]),
        ("atlas_technique_ids", ["AML.T0051"]),
    ),
)
def test_non_mitre_framework_mapping_rejects_mitre_only_metadata(
    field_name: str,
    field_value: object,
) -> None:
    control = {
        "id": "GOVERN-1.x",
        "title": "Governance",
        "evidence_rules": [],
        field_name: field_value,
    }

    with pytest.raises(ValidationError, match="non-MITRE"):
        FrameworkMapping.model_validate(
            {
                "framework": "nist-ai-rmf",
                "framework_version": "1.0",
                "mapping_version": "test",
                "source_review": {"reviewed_on": "2026-10-05", "source_refs": ["test"]},
                "limitations": ["test"],
                "controls": [control],
            }
        )


@pytest.mark.parametrize(
    ("framework", "wrong_version"),
    (
        ("nist-ai-rmf", "2026.06"),
        ("owasp-llm-top-10-2025", "1.0"),
        ("iso-iec-42001", "2025"),
        ("mitre-atlas-2026-06", "2023"),
    ),
)
def test_framework_mapping_rejects_cross_framework_version_metadata(
    framework: str,
    wrong_version: str,
) -> None:
    with pytest.raises(ValidationError, match="requires framework_version"):
        FrameworkMapping.model_validate(
            {
                "framework": framework,
                "framework_version": wrong_version,
                "mapping_version": "test",
                "source_review": {"reviewed_on": "2026-10-05", "source_refs": ["test"]},
                "limitations": ["test"],
                "controls": [],
            }
        )


@pytest.mark.parametrize(
    ("field_name", "field_value"),
    (
        ("id", "AML.T9999"),
        ("atlas_tactic_ids", ["AML.TA9999"]),
        ("atlas_technique_ids", ["AML.T9999"]),
    ),
)
def test_mitre_framework_mapping_rejects_ids_absent_from_pinned_catalog(
    field_name: str,
    field_value: object,
) -> None:
    control = {
        "id": "AML.T0051",
        "title": "Prompt injection",
        "mapping_strength": "partial",
        "atlas_tactic_ids": ["AML.TA0004"],
        "atlas_technique_ids": ["AML.T0051"],
        "evidence_rules": [],
    }
    control[field_name] = field_value

    with pytest.raises(ValidationError, match="pinned 2026.06 catalog"):
        FrameworkMapping.model_validate(
            {
                "framework": "mitre-atlas-2026-06",
                "framework_version": "2026.06",
                "mapping_version": "test",
                "source_review": {"reviewed_on": "2026-10-05", "source_refs": ["test"]},
                "limitations": ["test"],
                "controls": [control],
            }
        )


def test_mitre_framework_mapping_rejects_catalog_version_mismatch() -> None:
    with pytest.raises(ValidationError, match="framework_version '2026.06'"):
        FrameworkMapping.model_validate(
            {
                "framework": "mitre-atlas-2026-06",
                "framework_version": "2099.99",
                "mapping_version": "test",
                "source_review": {"reviewed_on": "2026-10-05", "source_refs": ["test"]},
                "limitations": ["test"],
                "controls": [
                    {
                        "id": "AML.T0051",
                        "title": "Prompt injection",
                        "mapping_strength": "partial",
                        "atlas_tactic_ids": ["AML.TA0004"],
                        "atlas_technique_ids": ["AML.T0051"],
                        "evidence_rules": [],
                    }
                ],
            }
        )


@pytest.mark.parametrize(
    "control",
    (
        {
            "id": "AML.T0051",
            "title": "LLM Prompt Injection",
            "mapping_strength": "partial",
            "atlas_tactic_ids": ["AML.TA0004"],
            "atlas_technique_ids": ["AML.T0099"],
            "evidence_rules": [],
        },
        {
            "id": "AML.T0051",
            "title": "LLM Prompt Injection",
            "mapping_strength": "not_applicable",
            "atlas_tactic_ids": ["AML.TA0004"],
            "atlas_technique_ids": ["AML.T0051"],
            "evidence_rules": [],
        },
        {
            "id": "AML.T0051",
            "title": "LLM Prompt Injection",
            "mapping_strength": "not_applicable",
            "atlas_tactic_ids": [],
            "atlas_technique_ids": ["AML.T0051", "AML.T0099"],
            "evidence_rules": [],
        },
    ),
)
def test_mitre_framework_mapping_rejects_internally_contradictory_metadata(
    control: dict[str, object],
) -> None:
    with pytest.raises(ValidationError, match="control_id|not_applicable"):
        FrameworkMapping.model_validate(
            {
                "framework": "mitre-atlas-2026-06",
                "framework_version": "2026.06",
                "mapping_version": "test",
                "source_review": {"reviewed_on": "2026-10-05", "source_refs": ["test"]},
                "limitations": ["test"],
                "controls": [control],
            }
        )


def test_mitre_not_applicable_mapping_retains_only_its_subject_identifier() -> None:
    mapping = FrameworkMapping.model_validate(
        {
            "framework": "mitre-atlas-2026-06",
            "framework_version": "2026.06",
            "mapping_version": "test",
            "source_review": {"reviewed_on": "2026-10-05", "source_refs": ["test"]},
            "limitations": ["test"],
            "controls": [
                {
                    "id": "AML.T0051",
                    "title": "LLM Prompt Injection",
                    "mapping_strength": "not_applicable",
                    "atlas_tactic_ids": [],
                    "atlas_technique_ids": ["AML.T0051"],
                    "evidence_rules": [],
                }
            ],
        }
    )

    assert mapping.controls[0].atlas_tactic_ids == ()
    assert mapping.controls[0].atlas_technique_ids == ("AML.T0051",)


def test_mitre_framework_mapping_rejects_title_that_mislabels_catalog_id() -> None:
    with pytest.raises(ValidationError, match="title must match the pinned catalog name"):
        FrameworkMapping.model_validate(
            {
                "framework": "mitre-atlas-2026-06",
                "framework_version": "2026.06",
                "mapping_version": "test",
                "source_review": {"reviewed_on": "2026-10-05", "source_refs": ["test"]},
                "limitations": ["test"],
                "controls": [
                    {
                        "id": "AML.T0051",
                        "title": "Certified safe",
                        "mapping_strength": "partial",
                        "atlas_tactic_ids": ["AML.TA0004"],
                        "atlas_technique_ids": ["AML.T0051"],
                        "evidence_rules": [],
                    }
                ],
            }
        )


def test_mapping_rule_rejects_empty_requires() -> None:
    with pytest.raises(ValidationError, match="at least one packet signal"):
        MappingRule.model_validate(
            {
                "rule_id": "empty",
                "requires": [],
                "coverage_state_when_true": "observed",
                "coverage_state_when_false": "not_observed",
            }
        )


@pytest.mark.parametrize("false_state", ("observed", "contradictory_evidence_observed"))
def test_mapping_rule_rejects_observation_claims_on_false_paths(false_state: str) -> None:
    with pytest.raises(ValidationError, match="unobserved control condition"):
        MappingRule.model_validate(
            {
                "rule_id": "false-path-contradiction",
                "requires": [{"signal": "scope_boundary"}],
                "coverage_state_when_true": "observed",
                "coverage_state_when_false": false_state,
            }
        )


@pytest.mark.parametrize("true_state", ("not_observed", "not_evaluated"))
def test_mapping_rule_rejects_absence_claims_on_true_paths(true_state: str) -> None:
    with pytest.raises(ValidationError, match="observed control condition"):
        MappingRule.model_validate(
            {
                "rule_id": "true-path-absence",
                "requires": [{"signal": "scope_boundary"}],
                "coverage_state_when_true": true_state,
                "coverage_state_when_false": "not_observed",
            }
        )


@pytest.mark.parametrize("true_state", ("out_of_scope", "not_applicable"))
@pytest.mark.parametrize("false_state", ("partially_observed", "conditionally_observed"))
def test_mapping_rule_preserves_legitimate_scoped_and_partial_states(
    true_state: str,
    false_state: str,
) -> None:
    rule = MappingRule.model_validate(
        {
            "rule_id": "legitimate-state-paths",
            "requires": [{"signal": "scope_boundary"}],
            "coverage_state_when_true": true_state,
            "coverage_state_when_false": false_state,
        }
    )

    assert rule.coverage_state_when_true.value == true_state
    assert rule.coverage_state_when_false.value == false_state


def test_mapping_rule_rejects_duplicate_signal_condition_requirements() -> None:
    with pytest.raises(ValidationError, match="signal and condition requirements must be unique"):
        MappingRule.model_validate(
            {
                "rule_id": "duplicate-requirement",
                "requires": [
                    {"signal": "artifact_digest_present", "condition": "evaluation-summary"},
                    {"signal": "artifact_digest_present", "condition": "evaluation-summary"},
                ],
                "coverage_state_when_true": "observed",
                "coverage_state_when_false": "not_observed",
            }
        )


def test_mapping_control_rejects_duplicate_rule_ids() -> None:
    rule = {
        "rule_id": "duplicate-rule",
        "requires": [{"signal": "scope_boundary"}],
        "coverage_state_when_true": "out_of_scope",
        "coverage_state_when_false": "not_observed",
    }

    with pytest.raises(ValidationError, match="rule_id values must be unique"):
        MappingControl.model_validate(
            {
                "id": "CONTROL-A",
                "title": "Duplicate rules",
                "evidence_rules": [rule, dict(rule)],
            }
        )


@pytest.mark.parametrize(
    ("field_name", "values"),
    (
        ("atlas_tactic_ids", ["AML.TA0001", "AML.TA0001"]),
        ("atlas_tactic_ids", ["AML.TA0002", "AML.TA0001"]),
        ("atlas_technique_ids", ["AML.T0001", "AML.T0001"]),
        ("atlas_technique_ids", ["AML.T0099", "AML.T0001"]),
    ),
)
def test_mapping_control_requires_canonical_atlas_ids(
    field_name: str,
    values: list[str],
) -> None:
    payload = {
        "id": "AML.TEST",
        "title": "Noncanonical ATLAS identifiers",
        "evidence_rules": [],
        field_name: values,
    }

    with pytest.raises(ValidationError, match="unique and lexicographically ordered"):
        MappingControl.model_validate(payload)


def test_framework_mapping_rejects_duplicate_control_ids() -> None:
    control = {
        "id": "CONTROL-A",
        "title": "Duplicate control",
        "evidence_rules": [],
    }

    with pytest.raises(ValidationError, match="control IDs must be unique"):
        FrameworkMapping.model_validate(
            {
                "framework": "nist-ai-rmf",
                "framework_version": "1.0",
                "mapping_version": "test",
                "source_review": {
                    "reviewed_on": "2026-10-05",
                    "source_refs": ["test"],
                },
                "limitations": ["test"],
                "controls": [control, dict(control)],
            }
        )


def test_rule_evaluation_rejects_true_result_without_evidence() -> None:
    rule = MappingRule.model_validate(
        {
            "rule_id": "missing-evidence",
            "requires": [{"signal": "scope_boundary"}],
            "coverage_state_when_true": "observed",
            "coverage_state_when_false": "not_observed",
        }
    )

    class EmptyEvidenceContext:
        @staticmethod
        def evaluate(_requirement: MappingRequirement) -> coverage_module.SignalResult:
            return coverage_module.SignalResult(
                observed=True,
                evidence_refs=(),
                rationale="Unsafe test context omitted evidence.",
            )

    with pytest.raises(ValidationError, match="requires at least one evidence reference"):
        coverage_module._evaluate_rule(rule, EmptyEvidenceContext())


def test_control_scoped_fail_warn_and_evaluated_signals_require_conditions() -> None:
    for signal in (
        "control_failure_observed",
        "control_warning_observed",
        "control_evaluated",
    ):
        with pytest.raises(ValidationError, match="requires a local control condition"):
            MappingRequirement.model_validate({"signal": signal})


def test_packaged_mapping_bytes_prefer_package_resource(monkeypatch: pytest.MonkeyPatch) -> None:
    packaged_payload = b"packaged mapping bytes"

    class PackageRoot:
        def joinpath(self, *_parts: str) -> PackageRoot:
            return self

        def read_bytes(self) -> bytes:
            return packaged_payload

    monkeypatch.setattr(
        coverage_module.resources,
        "files",
        lambda _package: PackageRoot(),
    )

    payload, source = coverage_module._mapping_bytes("nist_ai_rmf.yaml")

    assert payload == packaged_payload
    assert source == "agent_assure/mappings/nist_ai_rmf.yaml"


def test_mapping_bytes_allow_source_checkout_fallback_with_dev_marker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo_root = tmp_path / "agent-assure"
    mapping_path = repo_root / "mappings" / "nist_ai_rmf.yaml"
    package_marker = repo_root / "src" / "agent_assure" / "__init__.py"
    mapping_path.parent.mkdir(parents=True)
    package_marker.parent.mkdir(parents=True)
    mapping_path.write_bytes(b"framework: nist-ai-rmf\n")
    package_marker.write_text("", encoding="utf-8")
    (repo_root / "pyproject.toml").write_text(
        '[project]\nname = "agent-assure"\n',
        encoding="utf-8",
    )
    fake_module = repo_root / "src" / "agent_assure" / "controls" / "coverage.py"

    class MissingPackageRoot:
        def joinpath(self, *_parts: str) -> MissingPackageRoot:
            return self

        def read_bytes(self) -> bytes:
            raise FileNotFoundError("package mapping missing")

    monkeypatch.setattr(coverage_module, "__file__", str(fake_module))
    monkeypatch.setattr(
        coverage_module.resources,
        "files",
        lambda _package: MissingPackageRoot(),
    )

    payload, source = coverage_module._mapping_bytes("nist_ai_rmf.yaml")

    assert payload == b"framework: nist-ai-rmf\n"
    assert source == str(mapping_path)


def test_mapping_bytes_reject_shadow_path_without_dev_marker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shadow_root = tmp_path / "Lib"
    shadow_mapping = shadow_root / "mappings" / "nist_ai_rmf.yaml"
    shadow_mapping.parent.mkdir(parents=True)
    shadow_mapping.write_text("framework: shadow\n", encoding="utf-8")
    fake_module = shadow_root / "site-packages" / "agent_assure" / "controls" / "coverage.py"

    class MissingPackageRoot:
        def joinpath(self, *_parts: str) -> MissingPackageRoot:
            return self

        def read_bytes(self) -> bytes:
            raise FileNotFoundError("package mapping missing")

    monkeypatch.setattr(coverage_module, "__file__", str(fake_module))
    monkeypatch.setattr(
        coverage_module.resources,
        "files",
        lambda _package: MissingPackageRoot(),
    )

    with pytest.raises(FileNotFoundError, match="built-in mapping file not found"):
        coverage_module._mapping_bytes("nist_ai_rmf.yaml")


def test_rendered_control_report_passes_claim_boundary_linter() -> None:
    report = build_control_coverage_report(
        _packet_with_material_evidence_failure(),
        framework=ControlFramework.mitre_atlas_2026_06,
        evidence_packet_digest="2" * 64,
    )
    markdown = render_control_coverage_markdown(report)

    violations = claim_boundaries.find_claim_boundary_violations(
        markdown,
        path=Path("tests/golden/reports/control-coverage-report.md"),
    )

    assert violations == []
    assert "compliance scorecard" not in markdown.lower()
    assert "certification report" not in markdown.lower()


def _green_packet(*, include_artifact_digest: bool = True) -> EvidencePacket:
    summary = EvaluationSummary(
        artifact_kind="evaluation-summary",
        runset_id="candidate-runset",
        runset_digest="a" * 64,
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.pass_,
        findings=(),
    )
    artifact_digests = (
        PacketArtifactDigest(
            artifact_kind="packet-artifact-digest",
            role="evaluation-summary",
            sha256="1" * 64,
        ),
    )
    packet = EvidencePacket(
        artifact_kind="evidence-packet",
        packet_id="packet-control-map-green-test",
        interpretation=("Review candidate findings before interpreting mappings.",),
        evaluation=summary,
        artifact_digests=artifact_digests,
        limitations=("fixture evidence only",),
    )
    return packet if include_artifact_digest else packet.model_copy(update={"artifact_digests": ()})


def _packet_with_control_failure(
    *,
    control_id: str,
    reason_code: ReasonCode,
) -> EvidencePacket:
    finding = Finding(
        finding_id=f"finding-{control_id}",
        case_id="case-control-map",
        control_id=control_id,
        target=control_id,
        state=GateState.fail,
        reason_code=reason_code,
        message=f"fixture-declared failure for {control_id}",
    )
    summary = EvaluationSummary(
        artifact_kind="evaluation-summary",
        runset_id="candidate-runset",
        runset_digest="a" * 64,
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.fail,
        findings=(finding,),
    )
    return EvidencePacket(
        artifact_kind="evidence-packet",
        packet_id=f"packet-{control_id}",
        interpretation=("Review candidate findings before interpreting mappings.",),
        evaluation=summary,
        artifact_digests=(
            PacketArtifactDigest(
                artifact_kind="packet-artifact-digest",
                role="evaluation-summary",
                sha256="1" * 64,
            ),
        ),
        limitations=("fixture evidence only",),
    )


def _rewrite_schema_version(value: object, schema_version: str) -> object:
    if isinstance(value, dict):
        return {
            str(key): (
                schema_version
                if key == "schema_version"
                else _rewrite_schema_version(nested, schema_version)
            )
            for key, nested in value.items()
        }
    if isinstance(value, list):
        return [_rewrite_schema_version(item, schema_version) for item in value]
    return value


def _historical_report_payload(
    report: ControlCoverageReport,
    schema_version: str,
) -> dict[str, object]:
    payload = _rewrite_schema_version(report.model_dump(mode="json"), schema_version)
    assert isinstance(payload, dict)
    payload["report_id"] = _derive_control_coverage_report_id(
        framework=report.framework,
        framework_version=report.framework_version,
        mapping_digest=report.mapping_digest,
        evidence_packet_digest=report.evidence_packet_digest,
        item_states=tuple((item.control_id, item.coverage_state) for item in report.items),
        schema_version=schema_version,
    )
    return payload


def _packet_with_material_evidence_failure() -> EvidencePacket:
    finding = Finding(
        finding_id="finding-material-evidence",
        case_id="shared-source-multi-claim",
        control_id="material_claims_have_evidence",
        target="claim:claim-duration",
        state=GateState.fail,
        reason_code=ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
        message="fixture-declared material claim has no evidence link",
    )
    summary = EvaluationSummary(
        artifact_kind="evaluation-summary",
        runset_id="candidate-runset",
        runset_digest="a" * 64,
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.fail,
        findings=(finding,),
    )
    return EvidencePacket(
        artifact_kind="evidence-packet",
        packet_id="packet-control-map-test",
        interpretation=("Review candidate findings before interpreting mappings.",),
        evaluation=summary,
        artifact_digests=(
            PacketArtifactDigest(
                artifact_kind="packet-artifact-digest",
                role="evaluation-summary",
                sha256="1" * 64,
            ),
        ),
        limitations=("fixture evidence only",),
    )
