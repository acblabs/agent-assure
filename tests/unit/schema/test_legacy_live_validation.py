from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import ValidationError
from typer.testing import CliRunner

from agent_assure.authoring.compiler import compile_suite
from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.cli.main import app
from agent_assure.fixtures.loader import compiled_suite_digest
from agent_assure.live.drift import build_live_drift_report
from agent_assure.live.statistics import evaluate_live_runset
from agent_assure.live.trajectory import build_live_trajectory_report
from agent_assure.schema import validation as artifact_validation
from agent_assure.schema.common import ExecutionMode
from agent_assure.schema.live import (
    LiveComparisonReport,
    LiveDriftReport,
    LiveEvaluationReport,
    LiveRate,
    LiveTrajectoryReport,
    RareEventUpperBound,
    StatisticalInvariantResult,
    TrajectoryPathSummary,
)
from agent_assure.schema.validation import (
    ArchivalOnlyArtifactError,
    validate_artifact_payload,
)
from tests.unit.evaluation.test_live_statistics import (
    SUITE,
    RunSet,
    _drift_plan,
    _protocol,
    _record,
    _trajectory_plan,
)
from tests.unit.schema.test_evidence_identifier_defense import (
    _live_evaluation_report_payload,
)
from tests.unit.schema.test_validation_security import _v065_live_comparison_payload

LEGACY_LIVE_VERSIONS = ("0.6.0", "0.6.1", "0.6.2", "0.6.3", "0.6.4", "0.6.5")
PRE_V06_LIVE_VERSIONS = ("0.1.0", "0.2.0", "0.3.1", "0.4.3", "0.5.0")


@pytest.mark.parametrize(
    "schema_version",
    PRE_V06_LIVE_VERSIONS[1:] + LEGACY_LIVE_VERSIONS,
)
@pytest.mark.parametrize("status", ("not_evaluated", "not_applicable"))
def test_current_claim_evidence_applicability_statuses_reject_legacy_paths(
    schema_version: str,
    status: str,
) -> None:
    payload = {
        "artifact_kind": "trajectory-path-summary",
        "schema_version": schema_version,
        "observation_id": "observation-legacy",
        "run_id": "run-legacy",
        "case_id": "case-legacy",
        "repetition_index": 0,
        "cluster_id": "cluster-legacy",
        "terminal_state": "verdict",
        "states": ["start", "verdict"],
        "transition_count": 1,
        "tool_count": 0,
        "claim_count": 0,
        "evidence_ref_count": 0,
        "claim_evidence_link_count": 0,
        "policy_result_count": 0,
        "claim_evidence_complete": False,
        "claim_evidence_status": status,
    }

    with pytest.raises(ValidationError, match="current-schema-only"):
        TrajectoryPathSummary.model_validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(TrajectoryPathSummary.model_json_schema()).validate(payload)


@pytest.mark.parametrize(
    ("artifact_kind", "schema_versions"),
    (
        ("live-protocol-record", PRE_V06_LIVE_VERSIONS),
        ("live-evaluation-report", PRE_V06_LIVE_VERSIONS),
        ("live-comparison-report", PRE_V06_LIVE_VERSIONS),
        ("live-drift-report", PRE_V06_LIVE_VERSIONS[1:] + LEGACY_LIVE_VERSIONS),
        ("live-trajectory-report", PRE_V06_LIVE_VERSIONS[1:] + LEGACY_LIVE_VERSIONS),
    ),
)
def test_public_validator_rejects_archival_only_live_roots_without_complete_replay(
    artifact_kind: str,
    schema_versions: tuple[str, ...],
) -> None:
    for schema_version in schema_versions:
        payload = {
            "artifact_kind": artifact_kind,
            "schema_version": schema_version,
        }

        with pytest.raises(ArchivalOnlyArtifactError, match="archival-only"):
            validate_artifact_payload(payload, artifact_kind)


@pytest.mark.parametrize("artifact_kind", ("live-drift-report", "live-trajectory-report"))
def test_current_live_drift_and_trajectory_are_not_misclassified_as_archival(
    artifact_kind: str,
) -> None:
    # Current evidence proceeds to ordinary schema/model validation. A missing
    # body is invalid, but importantly not for the archival-only trust reason.
    payload = {
        "artifact_kind": artifact_kind,
        "schema_version": "0.6.6",
    }

    with pytest.raises(JsonSchemaValidationError) as exc_info:
        validate_artifact_payload(payload, artifact_kind)
    assert not isinstance(exc_info.value, ArchivalOnlyArtifactError)


def test_mismatched_artifact_identity_is_malformed_not_archival() -> None:
    payload = {
        "artifact_kind": "run-set",
        "schema_version": "0.5.0",
    }

    with pytest.raises(JsonSchemaValidationError) as exc_info:
        validate_artifact_payload(payload, "live-evaluation-report")
    assert not isinstance(exc_info.value, ArchivalOnlyArtifactError)


@pytest.mark.parametrize("schema_version", LEGACY_LIVE_VERSIONS)
@pytest.mark.parametrize("artifact_kind", ("live-drift-report", "live-trajectory-report"))
def test_v06_source_unbound_monitoring_roots_are_archival_only(
    schema_version: str,
    artifact_kind: str,
) -> None:
    payload = {
        "artifact_kind": artifact_kind,
        "schema_version": schema_version,
    }

    with pytest.raises(ArchivalOnlyArtifactError, match="archival-only"):
        validate_artifact_payload(payload, artifact_kind)


def _valid_historical_bound(
    schema_version: str,
    *,
    exposure: int = 2,
) -> dict[str, Any]:
    upper_rate = "1.497866" if exposure == 2 else "2.995732"
    return {
        "artifact_kind": "rare-event-upper-bound",
        "schema_version": schema_version,
        "endpoint_id": "critical-event",
        "label": "Critical event",
        "observed_events": 0,
        "exposure": exposure,
        "exposure_unit": "observation",
        "event_rate": "0.000000",
        "upper_count_bound": "2.995732",
        "upper_rate_bound": upper_rate,
        "confidence_level": "0.950000",
        "analysis_method": "poisson_upper_bound",
        "zero_events": True,
    }


def _valid_historical_correlation(
    schema_version: str,
    *,
    count: int,
) -> dict[str, Any]:
    hardened = schema_version in {"0.6.3", "0.6.4", "0.6.5"}
    return {
        "artifact_kind": "cluster-correlation-summary",
        "schema_version": schema_version,
        "endpoint_id": "critical-event",
        "label": "Critical event",
        "cluster_count": count,
        "observation_count": count,
        "planned_intraclass_correlation": "0.000000",
        "uncertainty_method": "not_evaluated",
        "bootstrap_iterations": 0,
        "confirmatory_use": "disabled",
        "confirmatory_interval_uses_planned_icc": not hardened,
    }


def _valid_historical_invariant(
    schema_version: str,
    *,
    denominator: int = 2,
) -> dict[str, Any]:
    return {
        "artifact_kind": "statistical-invariant-result",
        "schema_version": schema_version,
        "endpoint_id": "critical-event",
        "label": "Critical event",
        "endpoint_kind": "critical_event_rate",
        "role": "primary",
        "interpretation": "exploratory",
        "analysis_method": "poisson_upper_bound",
        "prerequisite_status": "exploratory",
        "multiplicity_method": "single_endpoint",
        "adjusted_alpha": "0.050000",
        "numerator": 0,
        "denominator": denominator,
        "cluster_count": denominator,
        "rate": "0.000000",
        "reason_codes": ["RAW_SENSITIVE_CONTENT"],
        "rare_event_bound": _valid_historical_bound(
            schema_version,
            exposure=denominator,
        ),
        "cluster_correlation": _valid_historical_correlation(
            schema_version,
            count=denominator,
        ),
    }


def _valid_historical_evaluation(schema_version: str) -> dict[str, Any]:
    payload = _live_evaluation_report_payload(
        schema_version,
        nested_schema_version=schema_version,
    )
    payload["exploratory"] = True
    for summary in (payload["overall"], *payload["groups"]):
        summary["exclusion_rate"]["exploratory"] = True
        summary["expectation_pass_rate"]["exploratory"] = True
    return payload


def _reconciled_historical_evaluation(schema_version: str) -> dict[str, Any]:
    payload = _valid_historical_evaluation(schema_version)
    source = payload["observations"][0]
    observation_specs = (
        ("cluster-a", "pass", []),
        ("cluster-a", "pass", []),
        ("cluster-a", "fail", ["RAW_SENSITIVE_CONTENT"]),
        ("cluster-b", "pass", []),
    )
    observations: list[dict[str, Any]] = []
    for index, (cluster_id, state, reason_codes) in enumerate(observation_specs):
        observation = deepcopy(source)
        observation.update(
            {
                "observation_id": f"observation-{index + 1}",
                "run_id": f"run-{index + 1}",
                "case_id": f"case-{index + 1}",
                "repetition_index": index,
                "schedule_index": index,
                "randomization_block_id": f"block-{index + 1}",
                "prompt_digest": format(index + 10, "x") * 64,
                "cluster_id": cluster_id,
                "state": state,
                "reason_codes": reason_codes,
            }
        )
        observations.append(observation)
    payload["observations"] = observations
    payload["state"] = "fail"

    def set_rate(
        rate: dict[str, Any],
        *,
        label: str,
        numerator: int,
        pooled: str,
        cluster_mean: str,
    ) -> None:
        rate.update(
            {
                "label": label,
                "numerator": numerator,
                "denominator": 4,
                "cluster_count": 2,
                "effective_n": "4.000000",
                "design_effect": "1.000000",
                "largest_cluster_size": 3,
                "largest_cluster_design_effect": "1.000000",
                "largest_cluster_effective_n": "4.000000",
                "assumed_intraclass_correlation": "0.000000",
                "exploratory": True,
                "rate": pooled,
                "cluster_mean_rate": cluster_mean,
                "interval_center_value": cluster_mean,
                "ci_lower": cluster_mean,
                "ci_upper": cluster_mean,
            }
        )

    for summary in (payload["overall"], *payload["groups"]):
        summary.update(
            {
                "observations": 4,
                "included_observations": 4,
                "excluded_observations": 0,
                "cluster_count": 2,
                "effective_n": "4.000000",
                "design_effect": "1.000000",
            }
        )
        set_rate(
            summary["exclusion_rate"],
            label="exclusion",
            numerator=0,
            pooled="0.000000",
            cluster_mean="0.000000",
        )
        set_rate(
            summary["expectation_pass_rate"],
            label="expectation_pass",
            numerator=3,
            pooled="0.750000",
            cluster_mean="0.833333",
        )
        reason_rate = deepcopy(summary["expectation_pass_rate"])
        set_rate(
            reason_rate,
            label="reason_code:RAW_SENSITIVE_CONTENT",
            numerator=1,
            pooled="0.250000",
            cluster_mean="0.166667",
        )
        summary["reason_code_rates"] = [reason_rate]
    return payload


def _valid_historical_comparison(schema_version: str) -> dict[str, Any]:
    payload = deepcopy(_v065_live_comparison_payload())
    payload["schema_version"] = schema_version
    payload["suite_version"] = schema_version
    payload["baseline_pass_rate"]["schema_version"] = schema_version
    payload["candidate_pass_rate"]["schema_version"] = schema_version
    return payload


def _structurally_valid_impossible_pre_v06_live_roots() -> tuple[tuple[str, dict[str, Any]], ...]:
    protocol: dict[str, Any] = {
        "artifact_kind": "live-protocol-record",
        "schema_version": "0.5.0",
        "protocol_id": "archival-protocol",
        "suite_id": "suite-1",
        "suite_version": "1.0.0",
        "suite_digest": "0" * 64,
        "non_inferiority_margin": "0.050000",
        # The frozen schema admits this contradictory design arithmetic.
        "planned_observations": 999,
        "planned_clusters": 1,
        "planned_observations_per_cluster": "1.000000",
        "assumed_intraclass_correlation": "0.000000",
        "design_effect": "1.000000",
        "planned_effective_n": "1.000000",
        "sample_size_rationale": "structural-only regression fixture",
        "planned_repetitions": 1,
        "randomization_seed": 1,
        "max_requests": 1,
        "max_total_cost_usd": "1.000000",
        "max_cost_per_observation_usd": "1.000000",
        "exclusion_policy": "none",
        "tool_schema_digest": "1" * 64,
        "policy_bundle_digest": "2" * 64,
        "analysis_digest": "3" * 64,
        "approved_data_boundary": "synthetic",
    }

    evaluation = _relabel_tree(_valid_historical_evaluation("0.6.0"), "0.5.0")
    for field_name in ("configuration_digest", "exploratory", "suite_digest"):
        evaluation.pop(field_name, None)
    evaluation["observations"] = []
    for summary in (evaluation["overall"], *evaluation["groups"]):
        summary.update(observations=999, included_observations=999)

    comparison = _valid_historical_comparison("0.5.0")
    comparison.update(
        pass_rate_difference="1.000000",
        difference_ci_lower="1.000000",
        difference_ci_upper="1.000000",
        state="pass",
    )

    return (
        ("live-protocol-record", protocol),
        ("live-evaluation-report", evaluation),
        ("live-comparison-report", comparison),
    )


def test_structurally_valid_pre_v06_live_decisions_are_archival_only() -> None:
    for artifact_kind, payload in _structurally_valid_impossible_pre_v06_live_roots():
        # Preserve the frozen bytes as an interoperability resource and prove
        # that the regression fixture is structurally admitted there.
        assert (
            artifact_validation._validate_legacy_frozen_schema(payload, artifact_kind)
            == "frozen-jsonschema"
        )

        # The assurance API must never turn that shape-only result into plain
        # validity for a decision-bearing consumer.
        with pytest.raises(ArchivalOnlyArtifactError, match="archival-only"):
            validate_artifact_payload(payload, artifact_kind)


def test_validate_cli_fails_closed_for_structurally_valid_archival_live_decision(
    tmp_path: Path,
) -> None:
    _, payload = _structurally_valid_impossible_pre_v06_live_roots()[-1]
    path = tmp_path / "archival-live-comparison.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    result = CliRunner().invoke(
        app,
        ["validate", str(path), "--kind", "live-comparison-report"],
    )

    assert result.exit_code == 2
    assert "archival-only" in result.output
    assert "valid live-comparison-report:" not in result.output


@pytest.mark.parametrize("schema_version", LEGACY_LIVE_VERSIONS)
def test_v06_protocols_require_semantic_projection(schema_version: str) -> None:
    _, source = _structurally_valid_impossible_pre_v06_live_roots()[0]
    impossible = deepcopy(source)
    impossible["schema_version"] = schema_version

    # The immutable historical schema admits this contradictory arithmetic,
    # so a shape-only result would falsely certify the protocol.
    assert (
        artifact_validation._validate_legacy_frozen_schema(
            impossible,
            "live-protocol-record",
        )
        == "frozen-jsonschema"
    )
    with pytest.raises(ValueError, match="failed model validation"):
        validate_artifact_payload(impossible, "live-protocol-record")

    valid = deepcopy(impossible)
    valid["planned_observations"] = 1
    assert (
        validate_artifact_payload(valid, "live-protocol-record")
        == "frozen-jsonschema+semantic-replay"
    )


@pytest.mark.parametrize("schema_version", LEGACY_LIVE_VERSIONS)
def test_v06_protocol_semantic_replay_rejects_unsupported_required_review_state(
    schema_version: str,
) -> None:
    compiled = compile_suite(SUITE)
    current = _protocol(
        compiled,
        observations=1,
        clusters=1,
        repetitions=1,
        trajectory_analysis_plan=_trajectory_plan(),
    ).model_dump(mode="json")
    historical = _relabel_tree(current, schema_version)
    required_review = historical["trajectory_analysis_plan"]["invariants"][0]
    required_review["required_state"] = "redaction_check"

    # Frozen schemas and direct compatibility models preserve the historical
    # vocabulary, but the public assurance boundary may accept only settings
    # for which its semantic replay has an implemented evaluator.
    assert (
        artifact_validation._validate_legacy_frozen_schema(
            historical,
            "live-protocol-record",
        )
        == "frozen-jsonschema"
    )
    with pytest.raises(ValueError, match="cannot be semantically replayed"):
        validate_artifact_payload(historical, "live-protocol-record")

    required_review["required_state"] = "human_review"
    assert (
        validate_artifact_payload(historical, "live-protocol-record")
        == "frozen-jsonschema+semantic-replay"
    )


@pytest.mark.parametrize("schema_version", LEGACY_LIVE_VERSIONS)
@pytest.mark.parametrize(
    "ordering_variable",
    ("release_sequence", "provider_version_window"),
)
def test_v06_protocol_semantic_replay_rejects_unimplemented_drift_ordering(
    schema_version: str,
    ordering_variable: str,
) -> None:
    compiled = compile_suite(SUITE)
    current = _protocol(
        compiled,
        observations=1,
        clusters=1,
        repetitions=1,
        drift_monitoring_plan=_drift_plan(minimum_windows=2),
    ).model_dump(mode="json")
    historical = _relabel_tree(current, schema_version)
    historical["drift_monitoring_plan"]["ordering_variable"] = ordering_variable

    # The historical enum is immutable, but these modes have no authenticated
    # ordering-key implementation and therefore cannot receive assurance-valid
    # semantic replay.
    assert (
        artifact_validation._validate_legacy_frozen_schema(
            historical,
            "live-protocol-record",
        )
        == "frozen-jsonschema"
    )
    with pytest.raises(ValueError, match="has no authenticated ordering-key implementation"):
        validate_artifact_payload(historical, "live-protocol-record")

    historical["drift_monitoring_plan"]["ordering_variable"] = "window_index"
    assert (
        validate_artifact_payload(historical, "live-protocol-record")
        == "frozen-jsonschema+semantic-replay"
    )


@pytest.mark.parametrize("schema_version", LEGACY_LIVE_VERSIONS)
def test_validate_cli_rejects_impossible_v06_protocol_arithmetic(
    schema_version: str,
    tmp_path: Path,
) -> None:
    _, source = _structurally_valid_impossible_pre_v06_live_roots()[0]
    payload = deepcopy(source)
    payload["schema_version"] = schema_version
    path = tmp_path / f"impossible-live-protocol-{schema_version}.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    result = CliRunner().invoke(
        app,
        ["validate", str(path), "--kind", "live-protocol-record"],
    )

    assert result.exit_code == 2
    assert "model validation" in result.output
    assert "valid live-protocol-record:" not in result.output


@pytest.mark.parametrize("schema_version", LEGACY_LIVE_VERSIONS)
def test_historical_poisson_bound_preserves_real_result_and_rejects_impossible_counts(
    schema_version: str,
) -> None:
    valid = _valid_historical_bound(schema_version)
    RareEventUpperBound.model_validate(valid)

    impossible = deepcopy(valid)
    impossible.update(
        observed_events=5,
        exposure=1,
        event_rate="0.000000",
        upper_count_bound="0.000000",
        upper_rate_bound="0.000000",
        zero_events=True,
    )
    with pytest.raises(ValidationError, match="observed_events cannot exceed exposure"):
        RareEventUpperBound.model_validate(impossible)


@pytest.mark.parametrize("schema_version", LEGACY_LIVE_VERSIONS)
def test_historical_live_rate_and_invariant_reject_count_rate_contradictions(
    schema_version: str,
) -> None:
    comparison = _valid_historical_comparison(schema_version)
    valid_rate = comparison["baseline_pass_rate"]
    LiveRate.model_validate(valid_rate)
    invalid_rate = deepcopy(valid_rate)
    invalid_rate["rate"] = "1.000000"
    with pytest.raises(ValidationError, match="does not match numerator/denominator"):
        LiveRate.model_validate(invalid_rate)

    valid_invariant = _valid_historical_invariant(schema_version)
    StatisticalInvariantResult.model_validate(valid_invariant)
    invalid_invariant = deepcopy(valid_invariant)
    invalid_invariant.update(numerator=0, denominator=1, cluster_count=1, rate="1.000000")
    invalid_invariant["rare_event_bound"] = _valid_historical_bound(
        schema_version,
        exposure=1,
    )
    invalid_invariant["cluster_correlation"] = _valid_historical_correlation(
        schema_version,
        count=1,
    )
    with pytest.raises(ValidationError, match="rate does not match numerator/denominator"):
        StatisticalInvariantResult.model_validate(invalid_invariant)

    understated_adjustment = deepcopy(valid_invariant)
    understated_adjustment["adjusted_alpha"] = "0.025000"
    with pytest.raises(ValidationError, match="confidence does not match endpoint alpha"):
        StatisticalInvariantResult.model_validate(understated_adjustment)


@pytest.mark.parametrize("schema_version", LEGACY_LIVE_VERSIONS)
def test_frozen_historical_evaluation_rejects_failed_observation_persisted_as_pass(
    schema_version: str,
) -> None:
    payload = _valid_historical_evaluation(schema_version)
    assert (
        validate_artifact_payload(payload, "live-evaluation-report")
        == "frozen-jsonschema+semantic-replay"
    )

    payload["observations"][0]["state"] = "fail"
    for summary in (payload["overall"], *payload["groups"]):
        pass_rate = summary["expectation_pass_rate"]
        pass_rate["numerator"] = 0
        for field_name in (
            "rate",
            "cluster_mean_rate",
            "interval_center_value",
            "ci_lower",
            "ci_upper",
        ):
            pass_rate[field_name] = "0.000000"
    payload["state"] = "pass"

    with pytest.raises(ValidationError, match="report state is impossible"):
        LiveEvaluationReport.model_validate(payload)
    with pytest.raises(ValueError, match="failed model validation"):
        validate_artifact_payload(payload, "live-evaluation-report")


def test_frozen_v065_evaluation_rejects_impossible_nested_poisson_evidence() -> None:
    payload = _valid_historical_evaluation("0.6.5")
    payload["statistical_invariants"] = [_valid_historical_invariant("0.6.5", denominator=1)]
    payload["statistical_invariants"][0].update(
        numerator=5,
        denominator=1,
        cluster_count=1,
        rate="0.000000",
    )
    bound = payload["statistical_invariants"][0]["rare_event_bound"]
    bound.update(observed_events=5, exposure=1, event_rate="0.000000", zero_events=True)

    with pytest.raises(ValidationError):
        LiveEvaluationReport.model_validate(payload)
    with pytest.raises(ValueError, match="failed model validation"):
        validate_artifact_payload(payload, "live-evaluation-report")


@pytest.mark.parametrize("schema_version", LEGACY_LIVE_VERSIONS)
def test_historical_report_reconciles_derivable_summary_statistics(
    schema_version: str,
) -> None:
    payload = _reconciled_historical_evaluation(schema_version)

    LiveEvaluationReport.model_validate(payload)
    assert (
        validate_artifact_payload(payload, "live-evaluation-report")
        == "frozen-jsonschema+semantic-replay"
    )

    mutations = []

    wrong_count = deepcopy(payload)
    wrong_count["overall"]["observations"] = 3
    mutations.append(wrong_count)

    wrong_pass_rate = deepcopy(payload)
    wrong_pass_rate["overall"]["expectation_pass_rate"].update(
        {
            "numerator": 4,
            "rate": "1.000000",
            "cluster_mean_rate": "1.000000",
            "interval_center_value": "1.000000",
            "ci_lower": "1.000000",
            "ci_upper": "1.000000",
        }
    )
    mutations.append(wrong_pass_rate)

    wrong_cluster_mean = deepcopy(payload)
    wrong_cluster_mean["overall"]["expectation_pass_rate"].update(
        {
            "cluster_mean_rate": "0.750000",
            "interval_center_value": "0.750000",
            "ci_lower": "0.750000",
            "ci_upper": "0.750000",
        }
    )
    mutations.append(wrong_cluster_mean)

    wrong_largest_cluster = deepcopy(payload)
    wrong_largest_cluster["overall"]["expectation_pass_rate"]["largest_cluster_size"] = 2
    mutations.append(wrong_largest_cluster)

    wrong_reason_rate = deepcopy(payload)
    wrong_reason_rate["overall"]["reason_code_rates"][0].update(
        {
            "numerator": 2,
            "rate": "0.500000",
            "cluster_mean_rate": "0.333333",
            "interval_center_value": "0.333333",
            "ci_lower": "0.333333",
            "ci_upper": "0.333333",
        }
    )
    mutations.append(wrong_reason_rate)

    for mutation in mutations:
        with pytest.raises(
            ValidationError,
            match="does not match observations|embedded observations|observation-derived",
        ):
            LiveEvaluationReport.model_validate(mutation)
        with pytest.raises(ValueError, match="failed model validation"):
            validate_artifact_payload(mutation, "live-evaluation-report")


@pytest.mark.parametrize("schema_version", LEGACY_LIVE_VERSIONS)
@pytest.mark.parametrize("mutation", ("missing", "duplicate", "extra", "wrong-id"))
def test_historical_report_requires_exact_group_projection(
    schema_version: str,
    mutation: str,
) -> None:
    payload = _reconciled_historical_evaluation(schema_version)
    group = deepcopy(payload["groups"][0])
    if mutation == "missing":
        payload["groups"] = []
    elif mutation == "duplicate":
        payload["groups"] = [group, deepcopy(group)]
    elif mutation == "extra":
        extra = deepcopy(group)
        extra["group_id"] = "provider=extra|model=extra|adapter=extra|pipeline=extra"
        payload["groups"] = [group, extra]
    else:
        payload["groups"][0]["group_id"] = "forged-group"

    with pytest.raises(
        ValidationError,
        match=(
            "group summaries contain|group summaries do not match observation groups|"
            "duplicate group_id"
        ),
    ):
        LiveEvaluationReport.model_validate(payload)
    with pytest.raises(ValueError, match="failed model validation"):
        validate_artifact_payload(payload, "live-evaluation-report")


@pytest.mark.parametrize("schema_version", LEGACY_LIVE_VERSIONS)
def test_frozen_historical_comparison_preserves_valid_result_and_rejects_forged_pass(
    schema_version: str,
) -> None:
    payload = _valid_historical_comparison(schema_version)
    LiveComparisonReport.model_validate(payload)
    assert (
        validate_artifact_payload(payload, "live-comparison-report")
        == "frozen-jsonschema+semantic-replay"
    )

    baseline = payload["baseline_pass_rate"]
    candidate = payload["candidate_pass_rate"]
    baseline["numerator"] = 1
    candidate["numerator"] = 0
    for field_name in (
        "rate",
        "cluster_mean_rate",
        "interval_center_value",
        "ci_lower",
        "ci_upper",
    ):
        baseline[field_name] = "1.000000"
        candidate[field_name] = "0.000000"
    payload.update(
        pass_rate_difference="1.000000",
        difference_ci_lower="1.000000",
        difference_ci_upper="1.000000",
        state="pass",
    )

    with pytest.raises(ValidationError):
        LiveComparisonReport.model_validate(payload)
    with pytest.raises(ValueError, match="failed model validation"):
        validate_artifact_payload(payload, "live-comparison-report")


def test_v065_forged_randomization_result_cannot_disagree_with_comparison() -> None:
    payload = _valid_historical_comparison("0.6.5")
    payload.update(
        analysis_method="paired_cluster_permutation_exact",
        state="pass",
        randomization_tests=[
            {
                "artifact_kind": "paired-randomization-test-result",
                "schema_version": "0.6.5",
                "endpoint_id": "primary",
                "label": "Primary",
                "interpretation": "exploratory",
                "analysis_method": "paired_cluster_permutation_exact",
                "prerequisite_status": "exploratory",
                "exchangeability_assumption": "baseline_candidate_relabeling",
                "compared_clusters": 1,
                "observed_difference": "-1.000000",
                "non_inferiority_margin": "0.000000",
                "p_value": "1.000000",
                "adjusted_p_value": "1.000000",
                "exhaustive": True,
                "resamples": 2,
            }
        ],
    )
    with pytest.raises(ValidationError):
        LiveComparisonReport.model_validate(payload)
    with pytest.raises(ValueError, match="failed model validation"):
        validate_artifact_payload(payload, "live-comparison-report")


@pytest.mark.parametrize(
    ("model", "payload"),
    (
        (RareEventUpperBound, _valid_historical_bound("0.6.5")),
        (LiveRate, _valid_historical_comparison("0.6.5")["baseline_pass_rate"]),
        (StatisticalInvariantResult, _valid_historical_invariant("0.6.5")),
        (LiveEvaluationReport, _valid_historical_evaluation("0.6.5")),
        (LiveComparisonReport, _valid_historical_comparison("0.6.5")),
    ),
)
def test_direct_live_models_reject_pre_v06_schema_version(
    model: type[Any],
    payload: dict[str, Any],
) -> None:
    downgraded = deepcopy(payload)
    downgraded["schema_version"] = "0.5.0"
    with pytest.raises(ValidationError, match="not supported by the live artifact contract"):
        model.model_validate(downgraded)


def _relabel_tree(value: Any, schema_version: str) -> Any:
    if isinstance(value, dict):
        projected = {key: _relabel_tree(item, schema_version) for key, item in value.items()}
        if "schema_version" in projected:
            projected["schema_version"] = schema_version
        return projected
    if isinstance(value, list):
        return [_relabel_tree(item, schema_version) for item in value]
    return value


def _v065_drift_and_trajectory_payloads() -> tuple[dict[str, Any], dict[str, Any]]:
    compiled = compile_suite(SUITE)
    drift_protocol = _protocol(
        compiled,
        observations=1,
        clusters=1,
        repetitions=1,
        drift_monitoring_plan=_drift_plan(minimum_windows=2),
    )
    drift_protocol_digest = sha256_hexdigest(drift_protocol)
    reports = []
    for index in range(2):
        runset = RunSet(
            artifact_kind="run-set",
            runset_id=f"legacy-drift-window-{index}",
            suite_id=compiled.suite_id,
            suite_version=compiled.suite_version,
            suite_digest=compiled_suite_digest(compiled),
            fixture_manifest_digest="4" * 64,
            execution_mode=ExecutionMode.live,
            protocol_id=drift_protocol.protocol_id,
            protocol_digest=drift_protocol_digest,
            runs=(_record(repetition_index=0, linked=bool(index)),),
        )
        reports.append(evaluate_live_runset(compiled, runset, protocol=drift_protocol))
    drift = _relabel_tree(
        build_live_drift_report(tuple(reports), protocol=drift_protocol).model_dump(mode="json"),
        "0.6.5",
    )
    for key in (
        "derivation_contract",
        "source_evaluation_digests",
        "protocol",
        "drift_plan",
    ):
        drift.pop(key, None)

    trajectory_protocol = _protocol(
        compiled,
        observations=1,
        clusters=1,
        repetitions=1,
    )
    trajectory_protocol_digest = sha256_hexdigest(trajectory_protocol)
    trajectory_runset = RunSet(
        artifact_kind="run-set",
        runset_id="legacy-trajectory",
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=compiled_suite_digest(compiled),
        fixture_manifest_digest="4" * 64,
        execution_mode=ExecutionMode.live,
        protocol_id=trajectory_protocol.protocol_id,
        protocol_digest=trajectory_protocol_digest,
        runs=(_record(repetition_index=0, linked=True),),
    )
    evaluation = evaluate_live_runset(
        compiled,
        trajectory_runset,
        protocol=trajectory_protocol,
    )
    trajectory = _relabel_tree(
        build_live_trajectory_report(
            trajectory_runset,
            evaluation,
            protocol=trajectory_protocol,
        ).model_dump(mode="json"),
        "0.6.5",
    )
    for key in (
        "derivation_contract",
        "source_runset_digest",
        "source_evaluation_digest",
        "protocol",
        "trajectory_plan",
        "operational_events",
    ):
        trajectory.pop(key, None)
    for path in trajectory["paths"]:
        for key in (
            "approval_outcome",
            "claim_evidence_complete",
            "claim_evidence_status",
            "attempt_count",
            "retry_count",
            "rate_limit_event_count",
            "runtime_failed",
            "malformed_output",
        ):
            path.pop(key, None)
    for invariant in trajectory["invariants"]:
        invariant.pop("unobservable_observations", None)
        invariant.pop("unobservable_observation_ids", None)
    # The historical derivation counted every persisted path as history-check
    # exposure. Reconstruct that contract rather than inheriting the current
    # builder's applicability-aware prerequisite status.
    for check in trajectory["history_dependent_checks"]:
        check["prerequisite_status"] = "met"
    return drift, trajectory


def test_historical_drift_and_trajectory_downgrade_cannot_erase_evidence() -> None:
    drift, trajectory = _v065_drift_and_trajectory_payloads()
    with pytest.raises(ArchivalOnlyArtifactError, match="archival-only"):
        validate_artifact_payload(drift, "live-drift-report")
    with pytest.raises(ArchivalOnlyArtifactError, match="archival-only"):
        validate_artifact_payload(trajectory, "live-trajectory-report")

    empty_drift = deepcopy(drift)
    empty_drift.update(windows=[], diagnostics=[], monitoring_status="valid")
    empty_drift["comparability"].update(
        status="pass",
        compared_windows=0,
        failures=[],
    )
    with pytest.raises(ArchivalOnlyArtifactError, match="archival-only"):
        validate_artifact_payload(empty_drift, "live-drift-report")

    erased_diagnostics = deepcopy(drift)
    erased_diagnostics["diagnostics"] = []
    for window in erased_diagnostics["windows"]:
        window["metrics"] = []
    with pytest.raises(ArchivalOnlyArtifactError, match="archival-only"):
        validate_artifact_payload(erased_diagnostics, "live-drift-report")

    empty_trajectory = deepcopy(trajectory)
    empty_trajectory.update(
        observations=999,
        included_observations=999,
        excluded_observations=0,
        paths=[],
        transitions=[],
        invariants=[],
        history_dependent_checks=[],
        event_processes=[],
        interpretation="confirmatory",
        trajectory_status="valid",
        transition_assumption_status="met",
    )
    with pytest.raises(ArchivalOnlyArtifactError, match="archival-only"):
        validate_artifact_payload(empty_trajectory, "live-trajectory-report")

    erased_history = deepcopy(trajectory)
    erased_history["history_dependent_checks"] = []
    with pytest.raises(ArchivalOnlyArtifactError, match="archival-only"):
        validate_artifact_payload(erased_history, "live-trajectory-report")


@pytest.mark.parametrize("schema_version", LEGACY_LIVE_VERSIONS)
def test_historical_drift_downgrade_replays_recoverable_diagnostics_and_trust(
    schema_version: str,
) -> None:
    drift, _ = _v065_drift_and_trajectory_payloads()
    drift = _relabel_tree(drift, schema_version)

    forged_slope = deepcopy(drift)
    forged_slope["diagnostics"][0]["slope_per_window"] = "999999.000000"
    with pytest.raises(ValidationError, match="slope does not match"):
        LiveDriftReport.model_validate(forged_slope)
    with pytest.raises(ArchivalOnlyArtifactError, match="archival-only"):
        validate_artifact_payload(forged_slope, "live-drift-report")

    forged_protocol_comparability = deepcopy(drift)
    forged_protocol_comparability["windows"][0]["protocol_digest"] = "9" * 64
    with pytest.raises(ValidationError, match="comparability flags do not match"):
        LiveDriftReport.model_validate(forged_protocol_comparability)

    forged_validity = deepcopy(drift)
    forged_validity["interpretation"] = "confirmatory"
    forged_validity["monitoring_status"] = "valid"
    for diagnostic in forged_validity["diagnostics"]:
        diagnostic["interpretation"] = "confirmatory"
    with pytest.raises(ValidationError, match="accepted only as exploratory"):
        LiveDriftReport.model_validate(forged_validity)
    with pytest.raises(ArchivalOnlyArtifactError, match="archival-only"):
        validate_artifact_payload(forged_validity, "live-drift-report")


@pytest.mark.parametrize("schema_version", LEGACY_LIVE_VERSIONS)
def test_historical_trajectory_downgrade_cannot_suppress_recoverable_governance_findings(
    schema_version: str,
) -> None:
    _, trajectory = _v065_drift_and_trajectory_payloads()
    trajectory = _relabel_tree(trajectory, schema_version)

    suppressed_review = deepcopy(trajectory)
    suppressed_review["paths"][0]["human_review_required"] = True
    with pytest.raises(ValidationError, match="suppresses a recoverable historical finding"):
        LiveTrajectoryReport.model_validate(suppressed_review)
    with pytest.raises(ArchivalOnlyArtifactError, match="archival-only"):
        validate_artifact_payload(suppressed_review, "live-trajectory-report")

    forged_validity = deepcopy(trajectory)
    forged_validity["interpretation"] = "confirmatory"
    forged_validity["trajectory_status"] = "valid"
    for invariant in forged_validity["invariants"]:
        invariant["interpretation"] = "confirmatory"
    for process in forged_validity["event_processes"]:
        process["prerequisite_status"] = "met"
    with pytest.raises(ValidationError, match="accepted only as exploratory"):
        LiveTrajectoryReport.model_validate(forged_validity)
    with pytest.raises(ArchivalOnlyArtifactError, match="archival-only"):
        validate_artifact_payload(forged_validity, "live-trajectory-report")


@pytest.mark.parametrize("schema_version", LEGACY_LIVE_VERSIONS)
def test_every_v06_historical_root_rejects_empty_downgraded_decisions(
    schema_version: str,
) -> None:
    drift, trajectory = _v065_drift_and_trajectory_payloads()
    empty_drift = deepcopy(drift)
    empty_drift.update(windows=[], diagnostics=[], monitoring_status="valid")
    empty_drift["comparability"].update(
        status="pass",
        compared_windows=0,
        failures=[],
    )
    empty_drift = _relabel_tree(empty_drift, schema_version)

    empty_trajectory = deepcopy(trajectory)
    empty_trajectory.update(
        observations=999,
        included_observations=999,
        excluded_observations=0,
        paths=[],
        transitions=[],
        invariants=[],
        history_dependent_checks=[],
        event_processes=[],
        interpretation="confirmatory",
        trajectory_status="valid",
        transition_assumption_status="met",
    )
    empty_trajectory = _relabel_tree(empty_trajectory, schema_version)

    with pytest.raises(ValidationError):
        LiveDriftReport.model_validate(empty_drift)
    with pytest.raises(ValidationError):
        LiveTrajectoryReport.model_validate(empty_trajectory)
    with pytest.raises(ValueError):
        validate_artifact_payload(empty_drift, "live-drift-report")
    with pytest.raises(ValueError):
        validate_artifact_payload(empty_trajectory, "live-trajectory-report")

    mixed_nested_version = "0.6.4" if schema_version == "0.6.5" else "0.6.5"
    mixed_drift = _relabel_tree(drift, schema_version)
    mixed_drift["comparability"]["schema_version"] = mixed_nested_version
    with pytest.raises(ValidationError, match="schema_version must match"):
        LiveDriftReport.model_validate(mixed_drift)
    with pytest.raises((ValueError, JsonSchemaValidationError)):
        validate_artifact_payload(mixed_drift, "live-drift-report")

    mixed_trajectory = _relabel_tree(trajectory, schema_version)
    mixed_trajectory["paths"][0]["schema_version"] = mixed_nested_version
    with pytest.raises(ValidationError, match="schema_version must match"):
        LiveTrajectoryReport.model_validate(mixed_trajectory)
    with pytest.raises((ValueError, JsonSchemaValidationError)):
        validate_artifact_payload(mixed_trajectory, "live-trajectory-report")
