from __future__ import annotations

import json
from copy import deepcopy
from datetime import date
from pathlib import Path
from typing import Any, cast

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

import agent_assure.reporting.efficacy as efficacy_reporting
from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.controls import efficacy as control_efficacy
from agent_assure.controls.efficacy import (
    build_control_efficacy_report,
    evaluate_control_efficacy_gate,
    load_threat_applicability_manifest,
)
from agent_assure.fixtures.loader import compiled_suite_digest
from agent_assure.mutation.campaign import execute_mutation_campaign
from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.reporting.efficacy import (
    load_control_efficacy_report,
    render_control_efficacy_markdown,
    write_control_efficacy_report,
)
from agent_assure.schema.campaign import (
    AssuranceMutationCampaign,
    MutationCampaignCompletion,
    MutationCampaignMode,
    MutationCampaignOperatorResult,
)
from agent_assure.schema.common import GateState
from agent_assure.schema.efficacy import (
    CONTROL_EFFICACY_GATE_REASON_ORDER,
    MAX_CATALOG_THREAT_REFERENCES,
    ControlEfficacyGateFinding,
    ControlEfficacyGateProfile,
    ControlEfficacyGateReason,
    ControlEfficacyReport,
    ControlEfficacySemanticState,
    ExactRate,
    ExactRateState,
    OperatorEfficacyOutcome,
    ThreatApplicabilityManifest,
    ThreatScopeSemanticState,
)
from agent_assure.schema.expectation import Expectation
from agent_assure.schema.mutation import (
    HUMAN_REVIEW_SUFFICIENCY_LIMITATION,
    STOCHASTIC_SUFFICIENCY_LIMITATION,
    AssuranceMutationResult,
    EvidenceEvaluationBasis,
    GateEffect,
    MutationResultState,
)
from agent_assure.schema.provenance import Provenance
from agent_assure.schema.run import (
    AgentRunRecord,
    ClaimEvidenceLink,
    EvidenceItem,
    EvidenceRef,
    RunSet,
)
from agent_assure.schema.suite import CompiledSuite, SuiteCase, SuiteDefaults

_GENERATED_AT = "2026-08-08T00:00:00Z"
_EVALUATION_DATE = date(2026, 8, 8)
_DROP_OPERATOR = "drop-material-evidence-link"


def test_exact_rate_represents_zero_denominator_as_undefined() -> None:
    rate = ExactRate.from_counts(0, 0)

    assert rate.model_dump(mode="json") == {
        "numerator": 0,
        "denominator": 0,
        "state": "undefined_zero_denominator",
    }
    with pytest.raises(ValidationError, match="state does not match"):
        ExactRate(numerator=0, denominator=0, state=ExactRateState.defined)
    with pytest.raises(ValidationError, match="cannot exceed"):
        ExactRate(numerator=2, denominator=1, state=ExactRateState.defined)


@pytest.mark.parametrize(
    "payload",
    (
        {"numerator": 0, "denominator": 0, "state": "defined"},
        {"numerator": 1, "denominator": 0, "state": "undefined_zero_denominator"},
        {"numerator": 0, "denominator": 1, "state": "undefined_zero_denominator"},
    ),
)
def test_exact_rate_json_schema_rejects_expressible_state_inconsistencies(
    payload: dict[str, object],
) -> None:
    validator = Draft202012Validator(ExactRate.model_json_schema(mode="validation"))

    assert list(validator.iter_errors(payload))


@pytest.mark.parametrize(
    "payload",
    (
        {"numerator": 0, "denominator": 0, "state": "undefined_zero_denominator"},
        {"numerator": 1, "denominator": 2, "state": "defined"},
    ),
)
def test_exact_rate_json_schema_accepts_valid_denominator_states(
    payload: dict[str, object],
) -> None:
    Draft202012Validator(ExactRate.model_json_schema(mode="validation")).validate(payload)


def test_report_has_exact_metrics_all_independence_strata_and_no_false_independence() -> None:
    execution = _campaign(operator_ids=(_DROP_OPERATOR,))
    report = build_control_efficacy_report(
        execution.campaign,
        execution.catalog,
        _manifest(critical=True),
        required_operator_ids=(_DROP_OPERATOR,),
    )

    assert report.catalog_kill_rate == ExactRate.from_counts(1, 1)
    assert report.caught_operator_count == 1
    assert report.invalid_subject_count == 0
    assert tuple(item.stratum for item in report.kill_rate_by_independence_class) == (
        "external_preexisting",
        "third_party_contributed",
        "first_party_precontrol",
        "first_party_postcontrol",
        "unknown",
    )
    postcontrol = report.kill_rate_by_independence_class[3]
    assert postcontrol.state_counts.caught == 1
    assert postcontrol.independent_challenge_eligible is False
    assert report.challenged_threat_category_count == 1
    assert report.independently_challenged_threat_category_count == 0
    assert report.semantic_state is (ControlEfficacySemanticState.all_evaluated_applicable_caught)


def test_required_critical_survivor_blocks_separately_from_semantic_state() -> None:
    execution = _campaign()
    campaign = _replace_result_state(
        execution.campaign,
        operator_id=_DROP_OPERATOR,
        state=MutationResultState.survived,
    )
    report = build_control_efficacy_report(
        campaign,
        execution.catalog,
        _manifest(critical=True),
        required_operator_ids=(_DROP_OPERATOR,),
    )
    profile = _profile()

    decision = evaluate_control_efficacy_gate(report, profile)

    assert report.catalog_kill_rate == ExactRate.from_counts(6, 7)
    assert report.required_survivor_operator_ids == (_DROP_OPERATOR,)
    assert report.critical_survivor_operator_ids == (_DROP_OPERATOR,)
    assert report.semantic_state is ControlEfficacySemanticState.survivor_observed
    assert decision.state.value == "fail"
    assert tuple(item.reason_code for item in decision.findings) == (
        ControlEfficacyGateReason.required_operator_survived,
        ControlEfficacyGateReason.critical_operator_survived,
        ControlEfficacyGateReason.unscoped_catalog_threat_reference,
    )
    assert report.semantic_state is ControlEfficacySemanticState.survivor_observed


@pytest.mark.parametrize(
    "field_name",
    (
        "surviving_required_operator",
        "surviving_critical_operator",
        "invalid_or_error_operator",
        "unevaluated_required_operator",
    ),
)
@pytest.mark.parametrize(
    "effect",
    (GateEffect.review, GateEffect.informational, GateEffect.ignore),
)
def test_non_bypassable_policy_floors_reject_permissive_profiles(
    field_name: str,
    effect: GateEffect,
) -> None:
    with pytest.raises(ValidationError, match="block"):
        ControlEfficacyGateProfile(
            required_catalog="core/v1",
            required_operators=(_DROP_OPERATOR,),
            **{field_name: effect},
        )


def test_non_bypassable_policy_floors_are_exported_as_json_schema_constants() -> None:
    properties = ControlEfficacyGateProfile.model_json_schema()["properties"]

    assert properties["surviving_required_operator"]["const"] == "block"
    assert properties["surviving_critical_operator"]["const"] == "block"
    assert properties["invalid_or_error_operator"]["const"] == "block"
    assert properties["unevaluated_required_operator"]["const"] == "block"


def test_survivor_finding_cannot_be_constructed_with_a_permissive_effect() -> None:
    with pytest.raises(ValidationError, match="survivor findings must block"):
        ControlEfficacyGateFinding(
            reason_code=ControlEfficacyGateReason.required_operator_survived,
            effect=GateEffect.ignore,
            operator_ids=(_DROP_OPERATOR,),
        )


def test_required_not_evaluated_finding_cannot_be_permissive() -> None:
    with pytest.raises(ValidationError, match="not-evaluated findings must block"):
        ControlEfficacyGateFinding(
            reason_code=ControlEfficacyGateReason.required_operator_not_evaluated,
            effect=GateEffect.ignore,
            operator_ids=(_DROP_OPERATOR,),
        )


@pytest.mark.parametrize(
    "effect",
    (GateEffect.review, GateEffect.informational, GateEffect.ignore),
)
def test_invalid_or_error_finding_cannot_be_permissive(effect: GateEffect) -> None:
    with pytest.raises(ValidationError, match="invalid/error findings must block"):
        ControlEfficacyGateFinding(
            reason_code=ControlEfficacyGateReason.invalid_or_error_operator,
            effect=effect,
            operator_ids=(_DROP_OPERATOR,),
        )


def test_optional_survivor_is_an_explicit_review_finding() -> None:
    execution = _campaign()
    optional_operator = next(
        entry.operator_id
        for entry in execution.campaign.operator_results
        if entry.operator_id != _DROP_OPERATOR
    )
    campaign = _replace_result_state(
        execution.campaign,
        operator_id=optional_operator,
        state=MutationResultState.survived,
    )
    report = build_control_efficacy_report(
        campaign,
        execution.catalog,
        _manifest(critical=False),
        required_operator_ids=(_DROP_OPERATOR,),
    )

    decision = evaluate_control_efficacy_gate(report, _profile())
    finding = next(
        item
        for item in decision.findings
        if item.reason_code is ControlEfficacyGateReason.applicable_operator_survived
    )

    assert report.semantic_state is ControlEfficacySemanticState.survivor_observed
    assert finding.operator_ids == (optional_operator,)
    assert finding.effect is GateEffect.review
    assert decision.state is GateState.warn


def test_survivor_policy_floor_defends_against_unvalidated_profile_copy() -> None:
    execution = _campaign()
    campaign = _replace_result_state(
        execution.campaign,
        operator_id=_DROP_OPERATOR,
        state=MutationResultState.survived,
    )
    report = build_control_efficacy_report(
        campaign,
        execution.catalog,
        _manifest(critical=True),
        required_operator_ids=(_DROP_OPERATOR,),
    )
    bypassed_profile = _profile().model_copy(
        update={
            "surviving_required_operator": GateEffect.ignore,
            "surviving_critical_operator": GateEffect.ignore,
        }
    )

    with pytest.raises(ValidationError, match="block"):
        evaluate_control_efficacy_gate(report, bypassed_profile)


def test_invalid_subject_is_separate_outside_kill_denominator_and_coverage() -> None:
    execution = _campaign(operator_ids=(_DROP_OPERATOR,))
    campaign = _replace_result_state(
        execution.campaign,
        operator_id=_DROP_OPERATOR,
        state=MutationResultState.invalid_subject,
    )
    report = build_control_efficacy_report(
        campaign,
        execution.catalog,
        _manifest(critical=True),
        required_operator_ids=(_DROP_OPERATOR,),
    )
    decision = evaluate_control_efficacy_gate(report, _profile())

    assert report.invalid_subject_count == 1
    assert report.invalid_operator_count == 0
    assert report.execution_error_count == 0
    assert report.applicable_operator_count == 0
    assert report.catalog_kill_rate == ExactRate.from_counts(0, 0)
    assert report.challenged_threat_category_count == 0
    assert report.critical_uncovered_threat_ids == ("AML.T0067.000",)
    assert decision.state.value == "fail"
    reasons = tuple(item.reason_code for item in decision.findings)
    assert ControlEfficacyGateReason.invalid_or_error_operator in reasons
    assert ControlEfficacyGateReason.required_operator_not_evaluated in reasons
    assert reasons.index(ControlEfficacyGateReason.invalid_or_error_operator) < reasons.index(
        ControlEfficacyGateReason.required_operator_not_evaluated
    )


def test_invalid_or_error_policy_floor_defends_against_unvalidated_profile_copy() -> None:
    execution = _campaign(operator_ids=(_DROP_OPERATOR,))
    campaign = _replace_result_state(
        execution.campaign,
        operator_id=_DROP_OPERATOR,
        state=MutationResultState.invalid_subject,
    )
    report = build_control_efficacy_report(
        campaign,
        execution.catalog,
        _manifest(critical=True),
        required_operator_ids=(_DROP_OPERATOR,),
    )
    bypassed_profile = _profile().model_copy(
        update={"invalid_or_error_operator": GateEffect.ignore}
    )

    with pytest.raises(ValidationError, match="block"):
        evaluate_control_efficacy_gate(report, bypassed_profile)


@pytest.mark.parametrize(
    ("basis", "limitation"),
    (
        (
            EvidenceEvaluationBasis.stochastic,
            STOCHASTIC_SUFFICIENCY_LIMITATION,
        ),
        (
            EvidenceEvaluationBasis.human_reviewed,
            HUMAN_REVIEW_SUFFICIENCY_LIMITATION,
        ),
    ),
)
@pytest.mark.parametrize(
    "state",
    (MutationResultState.caught, MutationResultState.survived),
)
def test_non_deterministic_mutation_evidence_cannot_become_an_efficacy_verdict(
    basis: EvidenceEvaluationBasis,
    limitation: str,
    state: MutationResultState,
) -> None:
    execution = _campaign(operator_ids=(_DROP_OPERATOR,))
    campaign = execution.campaign
    if state is MutationResultState.survived:
        campaign = _replace_result_state(
            campaign,
            operator_id=_DROP_OPERATOR,
            state=state,
        )
    campaign = _replace_result_evaluation_basis(
        campaign,
        operator_id=_DROP_OPERATOR,
        basis=basis,
        limitation=limitation,
    )

    with pytest.raises(ValueError, match="requires deterministic verdict-bearing"):
        build_control_efficacy_report(
            campaign,
            execution.catalog,
            _manifest(critical=False),
            required_operator_ids=(_DROP_OPERATOR,),
        )


def test_pending_required_operator_blocks_and_is_excluded_from_kill_rate() -> None:
    execution = _campaign()
    first_operator_id = execution.campaign.selected_operator_order[0]
    campaign_with_survivor = _replace_result_state(
        execution.campaign,
        operator_id=first_operator_id,
        state=MutationResultState.survived,
    )
    payload = campaign_with_survivor.model_dump(mode="python", exclude={"campaign_digest"})
    payload.update(
        {
            "mode": MutationCampaignMode.fail_fast,
            "completion": MutationCampaignCompletion.stopped_early,
            "executed_operator_order": (first_operator_id,),
            "pending_operator_order": campaign_with_survivor.selected_operator_order[1:],
            "operator_results": (campaign_with_survivor.operator_results[0],),
        }
    )
    campaign = AssuranceMutationCampaign.build(**payload)
    required_operator_id = campaign.pending_operator_order[0]

    report = build_control_efficacy_report(
        campaign,
        execution.catalog,
        _manifest(critical=False),
        required_operator_ids=(required_operator_id,),
    )
    profile = ControlEfficacyGateProfile(
        required_catalog=report.catalog_id,
        required_operators=(required_operator_id,),
    )
    decision = evaluate_control_efficacy_gate(report, profile)

    assert required_operator_id in report.pending_operator_ids
    assert report.required_not_evaluated_operator_ids == (required_operator_id,)
    assert report.catalog_kill_rate == ExactRate.from_counts(0, 1)
    assert report.semantic_state is ControlEfficacySemanticState.survivor_observed
    assert decision.state is GateState.fail
    assert ControlEfficacyGateReason.required_operator_not_evaluated in {
        finding.reason_code for finding in decision.findings
    }


def test_manifest_not_applicable_accountability_and_unknown_visibility() -> None:
    with pytest.raises(ValidationError, match="rationale and owner"):
        ThreatApplicabilityManifest.build(
            threat_source={"name": "test-source", "version": "1"},
            present_control_ids=(),
            items=(
                {
                    "threat_id": "not-applicable-threat",
                    "applicability": "not_applicable",
                    "critical": False,
                    "reviewed_at": "2026-08-08",
                },
            ),
            limitations=("fixture",),
        )

    with pytest.raises(ValidationError, match="rationale and owner"):
        ThreatApplicabilityManifest.build(
            threat_source={"name": "test-source", "version": "1"},
            present_control_ids=(),
            items=(
                {
                    "threat_id": "not-applicable-threat",
                    "applicability": "not_applicable",
                    "critical": False,
                    "rationale": "   ",
                    "owner": "test-owner",
                    "reviewed_at": "2026-08-08",
                },
            ),
            limitations=("fixture",),
        )

    execution = _campaign(operator_ids=(_DROP_OPERATOR,))
    manifest = ThreatApplicabilityManifest.build(
        threat_source={"name": "test-source", "version": "1"},
        present_control_ids=("material_claims_have_evidence",),
        items=(
            {
                "threat_id": "AML.T0067.000",
                "applicability": "applicable",
                "critical": False,
                "reviewed_at": "2026-08-08",
            },
            {
                "threat_id": "unknown-threat",
                "applicability": "unknown",
                "critical": True,
                "reviewed_at": "2026-08-08",
            },
        ),
        limitations=("fixture",),
    )
    report = build_control_efficacy_report(
        execution.campaign,
        execution.catalog,
        manifest,
        required_operator_ids=(_DROP_OPERATOR,),
    )

    assert report.unknown_applicability_count == 1
    assert report.unknown_applicability_threat_ids == ("unknown-threat",)
    assert report.threat_scope_state.value == "unknown_applicability"


def test_gate_finding_carries_full_unscoped_catalog_residual() -> None:
    threat_ids = tuple(f"threat-{index:04d}" for index in range(MAX_CATALOG_THREAT_REFERENCES))

    finding = ControlEfficacyGateFinding(
        reason_code=ControlEfficacyGateReason.unscoped_catalog_threat_reference,
        effect=GateEffect.review,
        threat_ids=threat_ids,
    )

    assert finding.threat_ids == threat_ids
    with pytest.raises(ValidationError, match="at most"):
        ControlEfficacyGateFinding(
            reason_code=ControlEfficacyGateReason.unscoped_catalog_threat_reference,
            effect=GateEffect.review,
            threat_ids=(*threat_ids, "threat-overflow"),
        )


def test_catalog_threat_references_absent_from_manifest_are_explicit_scope_gaps() -> None:
    execution = _campaign(operator_ids=(_DROP_OPERATOR,))

    report = build_control_efficacy_report(
        execution.campaign,
        execution.catalog,
        _manifest(critical=False),
        required_operator_ids=(_DROP_OPERATOR,),
    )

    outcome = report.operator_outcomes[0]
    assert outcome.catalog_threat_ids == (
        "AML.T0067.000",
        "material-claim-link-regression",
    )
    assert outcome.threat_ids == ("AML.T0067.000",)
    assert outcome.unscoped_catalog_threat_ids == ("material-claim-link-regression",)
    assert report.unscoped_catalog_threat_count == 1
    assert report.unscoped_catalog_threat_ids == ("material-claim-link-regression",)
    assert report.threat_scope_state is ThreatScopeSemanticState.unscoped_catalog_references
    assert "Catalog threat references absent from manifest: `1`" in (
        render_control_efficacy_markdown(report)
    )

    default_decision = evaluate_control_efficacy_gate(report, _profile())
    assert default_decision.state is GateState.warn
    assert tuple(item.reason_code for item in default_decision.findings) == (
        ControlEfficacyGateReason.unscoped_catalog_threat_reference,
    )
    assert default_decision.findings[0].effect is GateEffect.review
    assert default_decision.findings[0].threat_ids == ("material-claim-link-regression",)

    informational_profile = ControlEfficacyGateProfile(
        required_catalog=report.catalog_id,
        required_operators=report.required_operator_ids,
        unscoped_catalog_threat_reference=GateEffect.informational,
    )
    informational_decision = evaluate_control_efficacy_gate(
        report,
        informational_profile,
    )
    assert informational_decision.state is GateState.pass_
    assert informational_decision.findings[0].reason_code is (
        ControlEfficacyGateReason.unscoped_catalog_threat_reference
    )
    assert informational_decision.findings[0].effect is GateEffect.informational

    forged_payload = report.model_dump(mode="json")
    forged_payload["unscoped_catalog_threat_count"] = 0
    forged_payload["unscoped_catalog_threat_ids"] = []
    _refresh_report_digest(forged_payload)
    with pytest.raises(ValidationError, match="unscoped catalog threat IDs"):
        type(report).model_validate(forged_payload)


def test_declared_unchallenged_threat_is_an_ordinary_scope_gap() -> None:
    execution = _campaign(operator_ids=(_DROP_OPERATOR,))
    manifest = ThreatApplicabilityManifest.build(
        threat_source={"name": "mitre-atlas", "version": "2026.06"},
        present_control_ids=("material_claims_have_evidence",),
        items=(
            {
                "threat_id": "AML.T0067.000",
                "applicability": "applicable",
                "critical": False,
                "reviewed_at": "2026-08-08",
            },
            {
                "threat_id": "declared-but-unchallenged",
                "applicability": "applicable",
                "critical": False,
                "reviewed_at": "2026-08-08",
            },
            {
                "threat_id": "material-claim-link-regression",
                "applicability": "not_applicable",
                "critical": False,
                "rationale": "Project-local category is outside this authored scope.",
                "owner": "test-owner",
                "reviewed_at": "2026-08-08",
            },
        ),
        limitations=("Synthetic fixture scope only.",),
    )

    report = build_control_efficacy_report(
        execution.campaign,
        execution.catalog,
        manifest,
        required_operator_ids=(_DROP_OPERATOR,),
    )

    assert report.unscoped_catalog_threat_count == 0
    assert report.challenged_threat_category_count == 1
    assert report.applicable_threat_category_count == 2
    assert report.threat_scope_state is ThreatScopeSemanticState.gap_observed
    decision = evaluate_control_efficacy_gate(report, _profile())
    assert decision.state is GateState.warn
    assert decision.findings == (
        ControlEfficacyGateFinding(
            reason_code=ControlEfficacyGateReason.applicable_threat_uncovered,
            effect=GateEffect.review,
            threat_ids=("declared-but-unchallenged",),
        ),
    )


def test_unscoped_scope_and_gate_values_are_exported_in_json_schema() -> None:
    report_schema = ControlEfficacyReport.model_json_schema()
    scope_values = report_schema["$defs"]["ThreatScopeSemanticState"]["enum"]
    profile_schema = ControlEfficacyGateProfile.model_json_schema()
    reason_schema = ControlEfficacyGateFinding.model_json_schema()

    assert "unscoped_catalog_references" in scope_values
    assert profile_schema["properties"]["unscoped_catalog_threat_reference"]["default"] == "review"
    assert (
        "UNSCOPED_CATALOG_THREAT_REFERENCE"
        in (reason_schema["$defs"]["ControlEfficacyGateReason"]["enum"])
    )


def test_critical_uncovered_threat_is_a_configurable_review_finding() -> None:
    execution = _campaign(operator_ids=(_DROP_OPERATOR,))
    manifest = ThreatApplicabilityManifest.build(
        threat_source={"name": "mitre-atlas", "version": "2026.06"},
        present_control_ids=("material_claims_have_evidence",),
        items=(
            {
                "threat_id": "AML.T0067.000",
                "applicability": "applicable",
                "critical": False,
                "reviewed_at": "2026-08-08",
            },
            {
                "threat_id": "material-claim-link-regression",
                "applicability": "applicable",
                "critical": False,
                "reviewed_at": "2026-08-08",
            },
            {
                "threat_id": "unmapped-critical-threat",
                "applicability": "applicable",
                "critical": True,
                "reviewed_at": "2026-08-08",
            },
        ),
        limitations=("Synthetic fixture scope only.",),
    )
    report = build_control_efficacy_report(
        execution.campaign,
        execution.catalog,
        manifest,
        required_operator_ids=(_DROP_OPERATOR,),
    )

    default_profile = _profile()
    default_decision = evaluate_control_efficacy_gate(report, default_profile)

    assert report.critical_uncovered_threat_count == 1
    assert report.critical_uncovered_threat_ids == ("unmapped-critical-threat",)
    assert report.threat_scope_state is ThreatScopeSemanticState.critical_gap_observed
    assert default_decision.state is GateState.warn
    assert tuple(item.reason_code for item in default_decision.findings) == (
        ControlEfficacyGateReason.critical_threat_uncovered,
    )
    assert default_decision.findings[0].effect is GateEffect.review

    blocking = evaluate_control_efficacy_gate(
        report,
        default_profile.model_copy(update={"critical_threat_uncovered": GateEffect.block}),
    )
    ignored = evaluate_control_efficacy_gate(
        report,
        default_profile.model_copy(update={"critical_threat_uncovered": GateEffect.ignore}),
    )
    assert blocking.state is GateState.fail
    assert ignored.state is GateState.pass_


def test_gate_reason_order_and_critical_gap_default_are_explicit_schema_contracts() -> None:
    assert CONTROL_EFFICACY_GATE_REASON_ORDER == (
        ControlEfficacyGateReason.required_operator_survived,
        ControlEfficacyGateReason.critical_operator_survived,
        ControlEfficacyGateReason.applicable_operator_survived,
        ControlEfficacyGateReason.critical_threat_uncovered,
        ControlEfficacyGateReason.applicable_threat_uncovered,
        ControlEfficacyGateReason.invalid_or_error_operator,
        ControlEfficacyGateReason.required_operator_not_evaluated,
        ControlEfficacyGateReason.unknown_threat_applicability,
        ControlEfficacyGateReason.unscoped_catalog_threat_reference,
    )
    assert set(CONTROL_EFFICACY_GATE_REASON_ORDER) == set(ControlEfficacyGateReason)
    assert tuple(ControlEfficacySemanticState) == (
        ControlEfficacySemanticState.survivor_observed,
        ControlEfficacySemanticState.indeterminate,
        ControlEfficacySemanticState.not_evaluated,
        ControlEfficacySemanticState.all_evaluated_applicable_caught,
    )
    assert tuple(ThreatScopeSemanticState) == (
        ThreatScopeSemanticState.critical_gap_observed,
        ThreatScopeSemanticState.unknown_applicability,
        ThreatScopeSemanticState.unscoped_catalog_references,
        ThreatScopeSemanticState.not_evaluated,
        ThreatScopeSemanticState.gap_observed,
        ThreatScopeSemanticState.all_applicable_challenged,
    )
    properties = ControlEfficacyGateProfile.model_json_schema()["properties"]
    assert properties["surviving_applicable_operator"]["default"] == "review"
    assert properties["critical_threat_uncovered"]["default"] == "review"
    assert properties["applicable_threat_uncovered"]["default"] == "review"


def test_manifest_loader_accepts_exact_authoring_and_persisted_forms(tmp_path: Path) -> None:
    authored_path = tmp_path / "manifest.yaml"
    authored_path.write_text(
        """\
threat_source:
  name: mitre-atlas
  version: "2026.06"
present_control_ids:
  - material_claims_have_evidence
items:
  - threat_id: AML.T0067.000
    applicability: applicable
    critical: true
    reviewed_at: "2026-08-08"
limitations:
  - Fixture scope only.
""",
        encoding="utf-8",
    )

    authored = load_threat_applicability_manifest(authored_path)
    persisted_path = tmp_path / "persisted.yaml"
    persisted_path.write_text(
        json.dumps(authored.model_dump(mode="json")),
        encoding="utf-8",
    )

    assert load_threat_applicability_manifest(persisted_path) == authored

    mixed_path = tmp_path / "mixed.yaml"
    mixed_path.write_text(
        authored_path.read_text(encoding="utf-8") + "report_digest: " + "a" * 64 + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="exactly the authored or persisted"):
        load_threat_applicability_manifest(mixed_path)

    duplicate_path = tmp_path / "duplicate.yaml"
    duplicate_path.write_text("threat_source: {}\nthreat_source: {}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate YAML mapping key"):
        load_threat_applicability_manifest(duplicate_path)


def test_manifest_loader_rejects_symbolic_link(tmp_path: Path) -> None:
    target_path = tmp_path / "manifest-target.json"
    target_path.write_text(
        json.dumps(_manifest(critical=False).model_dump(mode="json")),
        encoding="utf-8",
    )
    linked_path = tmp_path / "linked-manifest.yaml"
    try:
        linked_path.symlink_to(target_path)
    except OSError as exc:
        pytest.skip(f"symbolic links are unavailable: {exc}")
    with pytest.raises(ValueError, match="must be a regular file"):
        load_threat_applicability_manifest(linked_path)


def test_outcome_rejects_inapplicable_applicability_for_error_state() -> None:
    with pytest.raises(ValidationError, match="reserved for inapplicable outcomes"):
        OperatorEfficacyOutcome(
            operator_id="test-operator",
            invariant_family="test-family",
            independence_class="unknown",
            applicability="inapplicable",
            state="execution_error",
            required=False,
            catalog_threat_ids=("test-threat",),
            unscoped_catalog_threat_ids=("test-threat",),
            target_control_ids=("test-control",),
        )


def test_report_digest_rejects_recomputed_inconsistent_metrics() -> None:
    execution = _campaign(operator_ids=(_DROP_OPERATOR,))
    report = build_control_efficacy_report(
        execution.campaign,
        execution.catalog,
        _manifest(critical=False),
        required_operator_ids=(_DROP_OPERATOR,),
    )
    payload = report.model_dump(mode="json")
    payload["caught_operator_count"] = 0
    payload["report_digest"] = sha256_hexdigest(
        {key: value for key, value in payload.items() if key != "report_digest"}
    )

    with pytest.raises(ValidationError, match="top-level operator counts"):
        type(report).model_validate(payload)


def test_report_rejects_noncanonical_challenger_order() -> None:
    execution = _campaign()
    manifest = ThreatApplicabilityManifest.build(
        threat_source={"name": "test-source", "version": "1"},
        present_control_ids=("human_review_required", "tool_allowlist"),
        items=(
            {
                "threat_id": "AML.T0053",
                "applicability": "applicable",
                "critical": False,
                "reviewed_at": "2026-08-08",
            },
        ),
        limitations=("Synthetic fixture scope only.",),
    )
    report = build_control_efficacy_report(
        execution.campaign,
        execution.catalog,
        manifest,
        required_operator_ids=(_DROP_OPERATOR,),
    )
    expected_challengers = (
        "bypass-required-human-review",
        "inject-forbidden-tool",
    )
    assert report.threat_coverage[0].challenging_operator_ids == expected_challengers

    payload = report.model_dump(mode="json")
    coverage_payload = cast(list[dict[str, Any]], payload["threat_coverage"])
    coverage_payload[0]["challenging_operator_ids"] = list(reversed(expected_challengers))
    _refresh_report_digest(payload)

    with pytest.raises(
        ValidationError,
        match="challenging operator IDs must be unique and canonically sorted",
    ):
        type(report).model_validate(payload)


def test_threat_projection_canonicalizes_challengers_locally() -> None:
    execution = _campaign()
    manifest = ThreatApplicabilityManifest.build(
        threat_source={"name": "test-source", "version": "1"},
        present_control_ids=("human_review_required", "tool_allowlist"),
        items=(
            {
                "threat_id": "AML.T0053",
                "applicability": "applicable",
                "critical": False,
                "reviewed_at": "2026-08-08",
            },
        ),
        limitations=("Synthetic fixture scope only.",),
    )
    report = build_control_efficacy_report(
        execution.campaign,
        execution.catalog,
        manifest,
        required_operator_ids=(_DROP_OPERATOR,),
    )
    reversed_outcomes = tuple(reversed(report.operator_outcomes))

    coverage = control_efficacy._threat_coverage_projection(
        manifest.items,
        reversed_outcomes,
    )

    assert coverage[0].challenging_operator_ids == (
        "bypass-required-human-review",
        "inject-forbidden-tool",
    )
    report.model_copy(
        update={
            "operator_outcomes": reversed_outcomes,
            "threat_coverage": coverage,
        }
    )._validate_threat_projection()


def test_report_builder_rejects_bypassed_noncanonical_campaign_result_order() -> None:
    execution = _campaign()
    reversed_campaign = execution.campaign.model_copy(
        update={
            "operator_results": tuple(reversed(execution.campaign.operator_results)),
        }
    )

    with pytest.raises(
        ValidationError,
        match="operator outcomes and pending IDs must partition selection",
    ):
        build_control_efficacy_report(
            reversed_campaign,
            execution.catalog,
            _manifest(critical=False),
            required_operator_ids=(_DROP_OPERATOR,),
        )


def test_report_rejects_omitted_zero_count_invariant_family_stratum() -> None:
    execution = _campaign(operator_ids=(_DROP_OPERATOR,))
    report = build_control_efficacy_report(
        execution.campaign,
        execution.catalog,
        _manifest(critical=False),
        required_operator_ids=(_DROP_OPERATOR,),
    )
    payload = report.model_dump(mode="json")
    payload["kill_rate_by_invariant_family"] = [
        item
        for item in payload["kill_rate_by_invariant_family"]
        if item["stratum"] != "human-review-routing"
    ]
    _refresh_report_digest(payload)

    with pytest.raises(ValidationError, match="all canonical invariant-family strata"):
        type(report).model_validate(payload)


def test_bounded_deterministic_render_and_round_trip(tmp_path: Path) -> None:
    execution = _campaign(operator_ids=(_DROP_OPERATOR,))
    report = build_control_efficacy_report(
        execution.campaign,
        execution.catalog,
        _manifest(critical=True),
        required_operator_ids=(_DROP_OPERATOR,),
    )
    profile = _profile()
    decision = evaluate_control_efficacy_gate(report, profile)

    first = render_control_efficacy_markdown(
        report,
        gate_decision=decision,
        gate_profile=profile,
    )
    second = render_control_efficacy_markdown(
        report,
        gate_decision=decision,
        gate_profile=profile,
    )
    paths = write_control_efficacy_report(
        report,
        tmp_path,
        gate_decision=decision,
        gate_profile=profile,
    )

    assert first == second
    assert "first_party_postcontrol" in first
    assert "Invalid subject" in first
    assert "not safety" in first
    assert "Canonical catalog operators: `7`" in first
    assert "Selected operators: `1`" in first
    assert "Completed selected operators: `1`" in first
    assert paths.markdown.read_text(encoding="utf-8") == first
    assert load_control_efficacy_report(paths.report) == report

    forged_report = report.model_copy(update={"caught_operator_count": 0})
    with pytest.raises(ValidationError):
        render_control_efficacy_markdown(
            forged_report,
            gate_decision=decision,
            gate_profile=profile,
        )

    with pytest.raises(ValueError, match="must be supplied together"):
        render_control_efficacy_markdown(report, gate_decision=decision)

    forged_payload = decision.model_dump(mode="json")
    forged_payload["state"] = "pass"
    forged_payload["findings"][0]["effect"] = "ignore"
    forged_decision = type(decision).model_validate(forged_payload)
    with pytest.raises(ValueError, match="exactly match"):
        render_control_efficacy_markdown(
            report,
            gate_decision=forged_decision,
            gate_profile=profile,
        )


def test_schema_valid_report_renders_an_explicit_bounded_view(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    execution = _campaign(operator_ids=(_DROP_OPERATOR,))
    report = build_control_efficacy_report(
        execution.campaign,
        execution.catalog,
        _manifest(critical=False),
        required_operator_ids=(_DROP_OPERATOR,),
    )
    monkeypatch.setattr(efficacy_reporting, "MAX_RENDERED_EFFICACY_MARKDOWN_CHARS", 2_000)

    rendered = render_control_efficacy_markdown(report)

    assert len(rendered) <= 2_000
    assert "## Bounded Markdown Notice" in rendered
    assert "validated JSON report remains authoritative" in rendered
    assert report.report_digest in rendered


def test_bounded_markdown_truncation_is_deterministic_and_line_complete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lines = [f"review-line-{index:03d}" for index in range(100)]
    monkeypatch.setattr(efficacy_reporting, "MAX_RENDERED_EFFICACY_MARKDOWN_CHARS", 400)

    first = efficacy_reporting._bounded_markdown(lines, report_digest="a" * 64)
    second = efficacy_reporting._bounded_markdown(lines, report_digest="a" * 64)

    assert first == second
    assert len(first) <= 400
    assert "## Bounded Markdown Notice" in first
    omitted = int(first.split("- Omitted Markdown lines: `", 1)[1].split("`", 1)[0])
    visible = sum(f"{line}\n" in first for line in lines)
    assert omitted == len(lines) - visible


def _manifest(*, critical: bool) -> ThreatApplicabilityManifest:
    return ThreatApplicabilityManifest.build(
        threat_source={"name": "mitre-atlas", "version": "2026.06"},
        present_control_ids=("material_claims_have_evidence",),
        items=(
            {
                "threat_id": "AML.T0067.000",
                "applicability": "applicable",
                "critical": critical,
                "rationale": "Synthetic fixture threat is in scope.",
                "owner": "test-owner",
                "reviewed_at": "2026-08-08",
            },
        ),
        limitations=("Synthetic fixture scope only.",),
    )


def _profile() -> ControlEfficacyGateProfile:
    return ControlEfficacyGateProfile(
        required_catalog="core/v1",
        required_operators=(_DROP_OPERATOR,),
    )


def _campaign(*, operator_ids: tuple[str, ...] = ()) -> Any:
    suite, source = _fixture()
    return execute_mutation_campaign(
        suite,
        source,
        seed=7331,
        generated_at=_GENERATED_AT,
        operator_ids=operator_ids,
        evaluation_date=_EVALUATION_DATE,
    )


def _replace_result_state(
    campaign: AssuranceMutationCampaign,
    *,
    operator_id: str,
    state: MutationResultState,
) -> AssuranceMutationCampaign:
    entries = []
    for entry in campaign.operator_results:
        if entry.operator_id != operator_id:
            entries.append(entry)
            continue
        result_payload = entry.result.model_dump(mode="python", exclude={"result_digest"})
        result_payload.update(
            {
                "state": state,
                "matched_finding_ids": (),
                "observed_findings": (),
            }
        )
        if state in {
            MutationResultState.invalid_subject,
            MutationResultState.inapplicable,
        }:
            result_payload.update(
                {
                    "mutated_digest": None,
                    "expected_finding_target_digest": None,
                    "changed_paths": (),
                    "diagnostic_code": (
                        "operator_target_not_evaluable"
                        if state is MutationResultState.invalid_subject
                        else None
                    ),
                }
            )
        result = AssuranceMutationResult.build(**result_payload)
        entry_payload = entry.model_dump(mode="python")
        entry_payload.update(
            {
                "result": result,
                "applicability": (
                    "not_evaluated"
                    if state is MutationResultState.invalid_subject
                    else (
                        "inapplicable"
                        if state is MutationResultState.inapplicable
                        else "applicable"
                    )
                ),
                "prohibited_substitute_finding_ids": (),
            }
        )
        entries.append(MutationCampaignOperatorResult.model_validate(entry_payload))
    campaign_payload = campaign.model_dump(mode="python", exclude={"campaign_digest"})
    campaign_payload["operator_results"] = tuple(entries)
    return AssuranceMutationCampaign.build(**campaign_payload)


def _replace_result_evaluation_basis(
    campaign: AssuranceMutationCampaign,
    *,
    operator_id: str,
    basis: EvidenceEvaluationBasis,
    limitation: str,
) -> AssuranceMutationCampaign:
    entries = []
    for entry in campaign.operator_results:
        if entry.operator_id != operator_id:
            entries.append(entry)
            continue
        result_payload = entry.result.model_dump(mode="python", exclude={"result_digest"})
        result_payload.update(
            {
                "evaluator_evaluation_basis": basis,
                "evaluator_protocol_digest": "e" * 64,
                "limitations": (*entry.result.limitations, limitation),
            }
        )
        result = AssuranceMutationResult.build(**result_payload)
        entry_payload = entry.model_dump(mode="python")
        entry_payload["result"] = result
        entries.append(MutationCampaignOperatorResult.model_validate(entry_payload))
    campaign_payload = campaign.model_dump(mode="python", exclude={"campaign_digest"})
    campaign_payload["operator_results"] = tuple(entries)
    return AssuranceMutationCampaign.build(**campaign_payload)


def _fixture() -> tuple[CompiledSuite, dict[str, object]]:
    expectation = Expectation(
        expectation_id="expectation-case-a",
        case_id="case-a",
        material_claim_ids=("claim-a",),
        forbidden_tools=("blocked-tool",),
        required_human_review=True,
    )
    suite = CompiledSuite(
        suite_id="control-efficacy-test-suite",
        suite_version="1.0.0",
        defaults=SuiteDefaults(
            runner_id="control.efficacy.tests",
            allowed_tools=("safe-tool",),
        ),
        cases=(
            SuiteCase(
                case_id="case-a",
                title="Control efficacy test case",
                expectation_id=expectation.expectation_id,
            ),
        ),
        resolved_expectations=(expectation,),
        source_digest="a" * 64,
    )
    fixture_digest = "c" * 64
    runset = RunSet(
        runset_id="control-efficacy-test-runset",
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        suite_id=suite.suite_id,
        suite_version=suite.suite_version,
        suite_digest=compiled_suite_digest(suite),
        fixture_manifest_digest=fixture_digest,
        runs=(
            AgentRunRecord(
                run_id="run-case-a",
                case_id="case-a",
                pipeline_id="control.efficacy.tests",
                recommendation="approve",
                outcome="approved",
                input_summary="synthetic input",
                output_summary="synthetic output",
                tools=("safe-tool",),
                evidence_refs=(
                    EvidenceRef(
                        ref_id="evidence-a",
                        source_id="source-a",
                        claim_ids=("claim-a",),
                    ),
                ),
                evidence_items=(
                    EvidenceItem(
                        ref_id="evidence-a",
                        source_id="source-a",
                        content_digest="d" * 64,
                    ),
                ),
                claim_evidence_links=(
                    ClaimEvidenceLink(
                        claim_id="claim-a",
                        evidence_ref_id="evidence-a",
                    ),
                ),
                human_review_required=True,
                human_review_performed=True,
                provenance=Provenance(fixture_manifest_digest=fixture_digest),
            ),
        ),
    )
    return suite, cast(dict[str, object], runset.model_dump(mode="json"))


def _refresh_report_digest(payload: dict[str, Any]) -> None:
    projection = deepcopy(payload)
    projection.pop("report_digest", None)
    payload["report_digest"] = sha256_hexdigest(projection)
