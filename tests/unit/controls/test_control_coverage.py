from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import agent_assure.controls.coverage as coverage_module  # noqa: E402
import scripts.check_claim_boundaries as claim_boundaries  # noqa: E402
from agent_assure.controls.coverage import (  # noqa: E402
    CLAIM_BOUNDARY,
    MITRE_ATLAS_BOUNDARY,
    FrameworkMapping,
    MappingRequirement,
    MappingRule,
    build_control_coverage_report,
    load_framework_mapping,
)
from agent_assure.reporting.controls import render_control_coverage_markdown  # noqa: E402
from agent_assure.schema.common import GateState, ReasonCode  # noqa: E402
from agent_assure.schema.controls import ControlCoverageState, ControlFramework  # noqa: E402
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


def test_partial_and_rule_refs_do_not_promote_to_item_level_evidence() -> None:
    report = build_control_coverage_report(
        _green_packet(include_artifact_digest=False),
        framework=ControlFramework.nist_ai_rmf,
        evidence_packet_digest="2" * 64,
    )
    govern_item = next(item for item in report.items if item.control_id == "GOVERN-1.x")
    evaluation = govern_item.condition_evaluations[0]

    assert govern_item.coverage_state is ControlCoverageState.not_observed
    assert govern_item.evidence_refs == ()
    assert evaluation.observed is False
    assert len(evaluation.evidence_refs) == 1


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
    first = {
        framework: load_framework_mapping(framework)
        for framework in ControlFramework
    }
    second = {
        framework: load_framework_mapping(framework)
        for framework in ControlFramework
    }

    assert set(first) == set(ControlFramework)
    for framework, loaded in first.items():
        assert len(loaded.digest) == 64
        assert loaded.digest == second[framework].digest
        assert loaded.mapping.framework is framework


def test_owasp_executable_map_includes_declared_2025_ids() -> None:
    loaded = load_framework_mapping(ControlFramework.owasp_llm_top_10_2025)
    expected = {f"LLM{index:02d}" for index in range(1, 11)}

    assert expected.issubset({control.id for control in loaded.mapping.controls})


def test_mitre_atlas_mapping_ids_exist_in_pinned_vector_catalog() -> None:
    loaded = load_framework_mapping(ControlFramework.mitre_atlas_2026_06)
    catalog = yaml.safe_load(
        (ROOT / "tests" / "vectors" / "mitre_atlas" / "atlas_2026_06_ids.yaml").read_text(
            encoding="utf-8"
        )
    )
    tactics = set(catalog["tactics"])
    techniques = set(catalog["techniques"])

    for control in loaded.mapping.controls:
        assert set(control.atlas_tactic_ids).issubset(tactics), control.id
        assert set(control.atlas_technique_ids).issubset(techniques), control.id


def test_mitre_atlas_mapping_requires_strength_at_load_time() -> None:
    with pytest.raises(ValidationError, match="mapping_strength"):
        FrameworkMapping.model_validate(
            {
                "framework": "mitre-atlas-2026-06",
                "framework_version": "2026.06",
                "mapping_version": "test",
                "source_review": {
                    "reviewed_on": "2026-07-10",
                    "source_refs": ["tests/vectors/mitre_atlas/atlas_2026_06_ids.yaml"],
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


def test_mapping_rule_rejects_false_path_contradictory_evidence() -> None:
    with pytest.raises(ValidationError, match="true mapping paths"):
        MappingRule.model_validate(
            {
                "rule_id": "false-path-contradiction",
                "requires": [{"signal": "scope_boundary"}],
                "coverage_state_when_true": "observed",
                "coverage_state_when_false": "contradictory_evidence_observed",
            }
        )


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
    fake_module = (
        shadow_root
        / "site-packages"
        / "agent_assure"
        / "controls"
        / "coverage.py"
    )

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
        state=GateState.pass_,
        findings=(),
    )
    artifact_digests = (
        (
            PacketArtifactDigest(
                artifact_kind="packet-artifact-digest",
                role="evaluation-summary",
                sha256="1" * 64,
            ),
        )
        if include_artifact_digest
        else ()
    )
    return EvidencePacket(
        artifact_kind="evidence-packet",
        packet_id="packet-control-map-green-test",
        interpretation=("Review candidate findings before interpreting mappings.",),
        evaluation=summary,
        artifact_digests=artifact_digests,
        limitations=("fixture evidence only",),
    )


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
