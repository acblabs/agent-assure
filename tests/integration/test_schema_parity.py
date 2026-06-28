from __future__ import annotations

import json

import pytest
from jsonschema import Draft202012Validator
from jsonschema import ValidationError as JsonSchemaValidationError
from pydantic import ValidationError as PydanticValidationError

from agent_assure.authoring.compiler import compile_suite
from agent_assure.schema.export import SCHEMA_MODELS
from agent_assure.schema.validation import validate_artifact


def test_valid_artifacts_match_pydantic_and_jsonschema(tmp_path) -> None:  # type: ignore[no-untyped-def]
    compiled = compile_suite(__import__("pathlib").Path("examples/prior_auth_synthetic/suite.yaml"))
    payload = compiled.model_dump(mode="json")
    model = SCHEMA_MODELS["compiled-suite"]
    model.model_validate(payload)
    Draft202012Validator(model.model_json_schema(mode="validation")).validate(payload)
    path = tmp_path / "compiled.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert validate_artifact(path, "compiled-suite") == "pydantic+jsonschema"


def test_live_protocol_artifact_matches_pydantic_and_jsonschema(tmp_path) -> None:  # type: ignore[no-untyped-def]
    payload = {
        "artifact_kind": "live-protocol-record",
        "schema_version": "0.2.0",
        "protocol_id": "protocol-live-001",
        "suite_id": "expense-approval-minimal",
        "suite_version": "0.1.0",
        "suite_digest": "0" * 64,
        "baseline_mode": "concurrent_paired",
        "hypothesis_family": "governance_control_non_inferiority",
        "primary_endpoint": "expectation_pass_rate",
        "analysis_method": "paired_cluster_t_interval",
        "baseline_group_id": "overall",
        "candidate_group_id": "overall",
        "confidence_level": "0.950000",
        "non_inferiority_margin": "0.050000",
        "cluster_by": "case_id",
        "planned_observations": 6,
        "planned_clusters": 3,
        "planned_observations_per_cluster": "2.000000",
        "assumed_intraclass_correlation": "0.200000",
        "design_effect": "1.200000",
        "planned_effective_n": "5.000000",
        "sample_size_rationale": "schema parity fixture",
        "planned_repetitions": 2,
        "randomization_seed": 17,
        "randomization_blocking": "balanced_case_blocks",
        "max_requests": 6,
        "max_total_cost_usd": "10.000000",
        "max_cost_per_observation_usd": "1.000000",
        "max_retries": 2,
        "retry_initial_backoff_seconds": "1.000000",
        "retry_max_backoff_seconds": "8.000000",
        "exclusion_policy": "only pre-provider configuration exclusions are allowed",
        "allowed_exclusion_reasons": ["budget_exhausted"],
        "max_exclusion_rate": "0.000000",
        "provider_version_capture": ["resolved_model", "provider_api_version", "provider_sdk"],
        "stopping_rules": ["stop on sensitive persistence"],
        "tool_schema_digest": "2" * 64,
        "policy_bundle_digest": "3" * 64,
        "analysis_digest": "1" * 64,
        "advanced_analysis_plan": {
            "artifact_kind": "advanced-analysis-plan",
            "schema_version": "0.2.0",
            "multiplicity_method": "single_endpoint",
            "familywise_alpha": "0.050000",
            "observed_icc_confirmatory_use": "disabled",
            "endpoints": [
                {
                    "artifact_kind": "statistical-endpoint-plan",
                    "schema_version": "0.2.0",
                    "endpoint_id": "expectation-pass",
                    "label": "Expectation pass rate",
                    "endpoint_kind": "expectation_pass_rate",
                    "role": "primary",
                    "interpretation": "confirmatory",
                    "analysis_method": "hierarchical_binomial_summary",
                    "minimum_clusters": 3,
                    "minimum_observations": 6,
                    "exchangeability_assumption": "baseline_candidate_relabeling",
                },
                {
                    "artifact_kind": "statistical-endpoint-plan",
                    "schema_version": "0.2.0",
                    "endpoint_id": "critical-sensitive-content",
                    "label": "Critical sensitive-content events",
                    "endpoint_kind": "critical_event_rate",
                    "role": "secondary",
                    "interpretation": "exploratory",
                    "analysis_method": "poisson_upper_bound",
                    "reason_codes": ["RAW_SENSITIVE_CONTENT"],
                    "minimum_clusters": 1,
                    "minimum_observations": 1,
                },
            ],
        },
        "trajectory_analysis_plan": {
            "artifact_kind": "trajectory-analysis-plan",
            "schema_version": "0.2.0",
            "plan_id": "trajectory-schema-parity",
            "interpretation": "exploratory",
            "analysis_methods": [
                "observable_transition_profile",
                "sequence_invariant_check",
                "event_process_summary",
                "burst_window_count",
            ],
            "minimum_observations": 1,
            "minimum_transition_support": 1,
            "minimum_event_count": 3,
            "minimum_event_exposure": 1,
            "burst_window_seconds": 60,
            "burst_count_threshold": 3,
            "invariants": [
                {
                    "artifact_kind": "trajectory-invariant-plan",
                    "schema_version": "0.2.0",
                    "invariant_id": "claim-evidence-before-approval",
                    "label": "Approval verdicts retain explicit claim evidence links",
                    "invariant_type": "claim_evidence_before_approval",
                    "category": "governance_control_failure",
                    "interpretation": "exploratory",
                }
            ],
        },
        "approved_data_boundary": "synthetic local prompts only",
        "safety_limits": ["stop if sensitive content is persisted"],
    }
    model = SCHEMA_MODELS["live-protocol-record"]
    model.model_validate(payload)
    Draft202012Validator(model.model_json_schema(mode="validation")).validate(payload)
    path = tmp_path / "live-protocol.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert validate_artifact(path, "live-protocol-record") == "pydantic+jsonschema"


def test_live_drift_report_matches_pydantic_and_jsonschema(tmp_path) -> None:  # type: ignore[no-untyped-def]
    metric = {
        "artifact_kind": "drift-window-metric",
        "schema_version": "0.2.0",
        "metric": "expectation_pass_rate",
        "label": "Expectation pass rate",
        "value": "0.750000",
        "numerator": 3,
        "denominator": 4,
        "source": "pooled_rate",
    }
    payload = {
        "artifact_kind": "live-drift-report",
        "schema_version": "0.2.0",
        "report_id": "live-drift-schema-parity",
        "protocol_id": "protocol-live-001",
        "protocol_digest": "1" * 64,
        "drift_plan_id": "drift-plan-001",
        "suite_id": "expense-approval-minimal",
        "suite_version": "0.1.0",
        "ordering_variable": "window_index",
        "interpretation": "exploratory",
        "state": "not_evaluated",
        "monitoring_status": "exploratory",
        "comparability": {
            "artifact_kind": "drift-comparability-result",
            "schema_version": "0.2.0",
            "status": "pass",
            "compared_windows": 2,
            "suite_matches": True,
            "baseline_mode_matches": True,
            "analysis_method_matches": True,
            "protocol_digest_matches": True,
            "material_fields_match": True,
            "tool_schema_digest_matches": True,
            "policy_bundle_digest_matches": True,
            "reference_protocol_digest": "1" * 64,
            "suite_id": "expense-approval-minimal",
            "suite_version": "0.1.0",
            "baseline_mode": "concurrent_paired",
            "analysis_method": "paired_cluster_t_interval",
        },
        "windows": [
            {
                "artifact_kind": "drift-window-summary",
                "schema_version": "0.2.0",
                "window_id": "window-0000",
                "window_index": 0,
                "runset_id": "runset-window-0",
                "suite_id": "expense-approval-minimal",
                "suite_version": "0.1.0",
                "protocol_id": "protocol-live-001",
                "protocol_digest": "1" * 64,
                "baseline_mode": "concurrent_paired",
                "analysis_method": "paired_cluster_t_interval",
                "observations": 4,
                "included_observations": 4,
                "excluded_observations": 0,
                "provider_version_unknown": False,
                "provider_version_keys": [
                    "provider=static|model=model|resolved=model-2026|api=2026|sdk=sdk|region=unknown"
                ],
                "tool_schema_digests": ["2" * 64],
                "policy_bundle_digests": ["3" * 64],
                "metrics": [metric],
            },
            {
                "artifact_kind": "drift-window-summary",
                "schema_version": "0.2.0",
                "window_id": "window-0001",
                "window_index": 1,
                "runset_id": "runset-window-1",
                "suite_id": "expense-approval-minimal",
                "suite_version": "0.1.0",
                "protocol_id": "protocol-live-001",
                "protocol_digest": "1" * 64,
                "baseline_mode": "concurrent_paired",
                "analysis_method": "paired_cluster_t_interval",
                "observations": 4,
                "included_observations": 4,
                "excluded_observations": 0,
                "provider_version_unknown": False,
                "provider_version_keys": [
                    "provider=static|model=model|resolved=model-2026|api=2026|sdk=sdk|region=unknown"
                ],
                "tool_schema_digests": ["2" * 64],
                "policy_bundle_digests": ["3" * 64],
                "metrics": [metric],
            },
        ],
        "diagnostics": [
            {
                "artifact_kind": "drift-metric-diagnostic",
                "schema_version": "0.2.0",
                "metric": "expectation_pass_rate",
                "label": "Expectation pass rate",
                "interpretation": "exploratory",
                "analysis_methods": ["descriptive_trend", "state_space_ewma"],
                "prerequisite_status": "met",
                "windows": 2,
                "observations": 8,
                "missing_windows": 0,
                "first_value": "0.750000",
                "last_value": "0.750000",
                "mean_value": "0.750000",
                "slope_per_window": "0.000000",
                "max_step_change": "0.000000",
                "stationarity_signal": "none",
                "dependence_signal": "none",
                "state_estimate": {
                    "artifact_kind": "drift-state-estimate",
                    "schema_version": "0.2.0",
                    "state_name": "governance_health",
                    "metric": "expectation_pass_rate",
                    "label": "Expectation pass rate",
                    "prerequisite_status": "met",
                    "smoothing_alpha": "0.300000",
                    "latest_level": "0.750000",
                    "latest_drift_per_window": "0.000000",
                    "innovation_variance": "0.000000",
                },
            }
        ],
    }
    model = SCHEMA_MODELS["live-drift-report"]
    model.model_validate(payload)
    Draft202012Validator(model.model_json_schema(mode="validation")).validate(payload)
    path = tmp_path / "live-drift.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert validate_artifact(path, "live-drift-report") == "pydantic+jsonschema"


def test_live_trajectory_report_matches_pydantic_and_jsonschema(tmp_path) -> None:  # type: ignore[no-untyped-def]
    payload = {
        "artifact_kind": "live-trajectory-report",
        "schema_version": "0.2.0",
        "report_id": "live-trajectory-schema-parity",
        "runset_id": "runset-live-trajectory",
        "evaluation_report_id": "runset-live-trajectory:live-evaluation-report",
        "protocol_id": "protocol-live-001",
        "protocol_digest": "1" * 64,
        "trajectory_plan_id": "trajectory-plan-001",
        "suite_id": "expense-approval-minimal",
        "suite_version": "0.1.0",
        "interpretation": "exploratory",
        "state": "not_evaluated",
        "trajectory_status": "exploratory",
        "transition_assumption": "canonical_observable_order",
        "transition_assumption_status": "met",
        "observations": 1,
        "included_observations": 1,
        "excluded_observations": 0,
        "paths": [
            {
                "artifact_kind": "trajectory-path-summary",
                "schema_version": "0.2.0",
                "observation_id": "obs-live-0",
                "run_id": "run-live-0",
                "case_id": "exp-001",
                "repetition_index": 0,
                "cluster_id": "exp-001",
                "terminal_state": "verdict",
                "states": [
                    "start",
                    "request_assembly",
                    "provider_call",
                    "tool_call",
                    "evidence_check",
                    "verdict",
                ],
                "transition_count": 5,
                "tool_count": 2,
                "claim_count": 1,
                "evidence_ref_count": 1,
                "claim_evidence_link_count": 1,
                "policy_result_count": 0,
                "human_review_required": False,
                "human_review_performed": False,
                "has_ordered_timestamps": True,
            }
        ],
        "transitions": [
            {
                "artifact_kind": "trajectory-transition-summary",
                "schema_version": "0.2.0",
                "from_state": "provider_call",
                "to_state": "tool_call",
                "count": 1,
                "from_state_count": 1,
                "conditional_frequency": "1.000000",
                "prerequisite_status": "met",
            }
        ],
        "invariants": [
            {
                "artifact_kind": "trajectory-invariant-result",
                "schema_version": "0.2.0",
                "invariant_id": "claim-evidence-before-approval",
                "label": "Approval verdicts retain explicit claim evidence links",
                "invariant_type": "claim_evidence_before_approval",
                "category": "governance_control_failure",
                "interpretation": "exploratory",
                "prerequisite_status": "met",
                "affected_observations": 0,
                "evaluated_observations": 1,
                "state": "not_evaluated",
            }
        ],
        "history_dependent_checks": [
            {
                "artifact_kind": "history-dependent-trajectory-check",
                "schema_version": "0.2.0",
                "check_id": "claim-evidence-history",
                "dependency": "approval eligibility depends on complete claim evidence links",
                "prerequisite_status": "met",
                "affected_observations": 0,
            }
        ],
        "event_processes": [
            {
                "artifact_kind": "operational-event-process-summary",
                "schema_version": "0.2.0",
                "event_type": "retry",
                "observed_events": 0,
                "exposure": 1,
                "exposure_unit": "observation",
                "event_rate": "0.000000",
                "analysis_method": "burst_window_count",
                "prerequisite_status": "exploratory",
                "timestamped_events": 0,
                "missing_timestamp_events": 0,
                "max_events_in_burst_window": 0,
                "burst_window_seconds": 60,
                "burst_signal": "none",
            }
        ],
    }
    model = SCHEMA_MODELS["live-trajectory-report"]
    model.model_validate(payload)
    Draft202012Validator(model.model_json_schema(mode="validation")).validate(payload)
    path = tmp_path / "live-trajectory.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert validate_artifact(path, "live-trajectory-report") == "pydantic+jsonschema"


def test_emergency_process_record_matches_pydantic_and_jsonschema(tmp_path) -> None:  # type: ignore[no-untyped-def]
    payload = {
        "artifact_kind": "emergency-process-record",
        "schema_version": "0.2.0",
        "emergency_id": "emergency-001",
        "failure_kind": "nonzero_exit",
        "process_kind": "external_script",
        "command_digest": "1" * 64,
        "executable_name": "python",
        "script_name": "adapter.py",
        "working_directory_digest": "2" * 64,
        "observation_id": "obs-001",
        "run_id": "run-001",
        "case_id": "case-001",
        "adapter_id": "external-script",
        "duration_ms": 42,
        "timeout_seconds": 10,
        "exit_code": 7,
        "stdout_bytes": 0,
        "stderr_bytes": 13,
        "stderr_summary": "redacted stderr",
        "safe_error_code": "external_script_nonzero_exit",
        "safe_error_message": "external script exited with code 7",
        "local_debug_reference": "debug-001",
        "traceparent": "00-11111111111111111111111111111111-2222222222222222-01",
    }
    model = SCHEMA_MODELS["emergency-process-record"]
    model.model_validate(payload)
    Draft202012Validator(model.model_json_schema(mode="validation")).validate(payload)
    path = tmp_path / "emergency.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert validate_artifact(path, "emergency-process-record") == "pydantic+jsonschema"


def test_invalid_artifact_rejected_by_both_validators() -> None:
    payload = {
        "artifact_kind": "compiled-suite",
        "schema_version": "0.2.0",
        "suite_id": "demo",
        "suite_version": "0.1.0",
        "cases": [],
        "resolved_expectations": [],
        "source_digest": "0" * 64,
        "extra": "nope",
    }
    model = SCHEMA_MODELS["compiled-suite"]
    with pytest.raises(PydanticValidationError):
        model.model_validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(model.model_json_schema(mode="validation")).validate(payload)
