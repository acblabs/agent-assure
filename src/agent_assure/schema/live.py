from __future__ import annotations

from decimal import Decimal
from typing import Literal

from pydantic import Field, model_validator
from pydantic.functional_validators import field_validator

from agent_assure.schema.base import PersistedArtifact
from agent_assure.schema.common import (
    DigestHex,
    GateState,
    ReasonCode,
    coerce_enum,
    coerce_tuple,
    decimal_string,
)
from agent_assure.schema.evaluation import Finding

DecimalString = str
SignedDecimalString = str

AnalysisMethod = Literal[
    "paired_cluster_t_interval",
    "paired_cluster_bootstrap_percentile",
    "paired_cluster_permutation_exact",
    "paired_cluster_permutation_monte_carlo",
    "fixed_reference_cluster_t_interval",
    "cluster_t_interval",
    "exploratory",
]

EndpointAnalysisMethod = Literal[
    "cluster_t_interval",
    "cluster_bootstrap_percentile",
    "poisson_upper_bound",
    "hierarchical_binomial_summary",
    "beta_binomial_cluster_summary",
    "descriptive_rate",
]
EndpointKind = Literal[
    "expectation_pass_rate",
    "reason_code_rate",
    "critical_event_rate",
    "exclusion_rate",
    "outcome_rate",
]
EndpointInterpretation = Literal["confirmatory", "exploratory"]
EndpointRole = Literal["primary", "secondary", "diagnostic"]
EndpointPrerequisiteStatus = Literal["met", "exploratory", "invalid"]
MultiplicityMethod = Literal["none", "single_endpoint", "bonferroni"]
ObservedIccUse = Literal["disabled", "large_cluster_threshold", "external_review"]
DriftMetric = Literal[
    "expectation_pass_rate",
    "reason_code_rate",
    "exclusion_rate",
    "retry_rate",
    "rate_limit_rate",
    "latency_p50_ms",
    "cost_total_usd",
]
DriftAnalysisMethod = Literal[
    "descriptive_trend",
    "lag1_autocorrelation",
    "ar1_summary",
    "state_space_ewma",
]
DriftInterpretation = Literal["confirmatory", "exploratory"]
DriftComparabilityStatus = Literal["pass", "exploratory", "invalid"]
DriftMonitoringStatus = Literal["valid", "exploratory", "invalid"]
DriftOrderingVariable = Literal[
    "window_index",
    "window_start_utc",
    "release_sequence",
    "provider_version_window",
]
DriftStationaritySignal = Literal["none", "review", "invalid"]
TrajectoryState = Literal[
    "start",
    "request_assembly",
    "provider_call",
    "tool_call",
    "evidence_check",
    "policy_check",
    "redaction_check",
    "human_review",
    "verdict",
    "excluded",
    "emergency",
]
TrajectoryAnalysisMethod = Literal[
    "observable_transition_profile",
    "sequence_invariant_check",
    "event_process_summary",
    "burst_window_count",
]
TrajectoryInterpretation = Literal["exploratory", "confirmatory"]
TrajectoryPrerequisiteStatus = Literal["met", "exploratory", "invalid"]
TrajectoryInvariantCategory = Literal[
    "governance_control_failure",
    "operational_reliability_warning",
]
TrajectoryInvariantType = Literal[
    "forbidden_state",
    "required_review_for_approval",
    "claim_evidence_before_approval",
    "attempt_retry_consistency",
]
OperationalEventType = Literal[
    "retry",
    "rate_limit",
    "exclusion",
    "runtime_failure",
    "malformed_output",
    "emergency_process",
    "budget_stop",
]
OperationalBurstSignal = Literal["none", "review", "invalid"]


def _decimal(value: str | int) -> Decimal:
    return Decimal(str(value))


def _decimal_string(value: Decimal) -> str:
    return decimal_string(value)


class StatisticalEndpointPlan(PersistedArtifact):
    artifact_kind: Literal["statistical-endpoint-plan"] = "statistical-endpoint-plan"
    endpoint_id: str = Field(min_length=1)
    label: str = Field(min_length=1)
    endpoint_kind: EndpointKind
    role: EndpointRole = "secondary"
    interpretation: EndpointInterpretation = "exploratory"
    analysis_method: EndpointAnalysisMethod = "descriptive_rate"
    reason_codes: tuple[ReasonCode, ...] = ()
    outcome: str | None = None
    minimum_clusters: int = Field(default=30, ge=1)
    minimum_observations: int = Field(default=1, ge=1)
    minimum_events: int = Field(default=0, ge=0)
    exposure_unit: str = Field(default="observation", min_length=1)
    family_id: str | None = Field(default=None, min_length=1)
    hierarchy_rank: int | None = Field(default=None, ge=1)
    exchangeability_assumption: Literal[
        "not_applicable",
        "baseline_candidate_relabeling",
    ] = "not_applicable"

    @field_validator("reason_codes", mode="before")
    @classmethod
    def _coerce_reason_codes(cls, value: object) -> object:
        if isinstance(value, list | tuple):
            return tuple(coerce_enum(ReasonCode, item) for item in value)
        return value

    @model_validator(mode="after")
    def _validate_endpoint(self) -> StatisticalEndpointPlan:
        if self.endpoint_kind in {"reason_code_rate", "critical_event_rate"}:
            if not self.reason_codes:
                raise ValueError(
                    "reason_code_rate and critical_event_rate endpoints require reason_codes"
                )
        elif self.reason_codes:
            raise ValueError("reason_codes are only valid for reason-code endpoints")
        if self.endpoint_kind == "outcome_rate" and not self.outcome:
            raise ValueError("outcome_rate endpoints require outcome")
        if self.endpoint_kind != "outcome_rate" and self.outcome is not None:
            raise ValueError("outcome is only valid for outcome_rate endpoints")
        if self.analysis_method == "poisson_upper_bound" and self.endpoint_kind not in {
            "critical_event_rate",
            "reason_code_rate",
            "exclusion_rate",
        }:
            raise ValueError(
                "poisson_upper_bound requires a critical-event, reason-code, or exclusion endpoint"
            )
        return self


class AdvancedAnalysisPlan(PersistedArtifact):
    artifact_kind: Literal["advanced-analysis-plan"] = "advanced-analysis-plan"
    multiplicity_method: MultiplicityMethod = "none"
    familywise_alpha: DecimalString = Field(default="0.050000", pattern=r"^0\.[0-9]{6}$")
    observed_icc_confirmatory_use: ObservedIccUse = "disabled"
    observed_icc_large_cluster_threshold: int | None = Field(default=None, ge=30)
    endpoints: tuple[StatisticalEndpointPlan, ...] = Field(min_length=1)

    @field_validator("endpoints", mode="before")
    @classmethod
    def _coerce_endpoints(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_plan(self) -> AdvancedAnalysisPlan:
        endpoint_ids = [endpoint.endpoint_id for endpoint in self.endpoints]
        if len(endpoint_ids) != len(set(endpoint_ids)):
            raise ValueError("advanced analysis endpoint_id values must be unique")
        primary_count = sum(1 for endpoint in self.endpoints if endpoint.role == "primary")
        if primary_count != 1:
            raise ValueError("advanced analysis plan requires exactly one primary endpoint")
        confirmatory = tuple(
            endpoint for endpoint in self.endpoints if endpoint.interpretation == "confirmatory"
        )
        if self.observed_icc_confirmatory_use == "large_cluster_threshold":
            if self.observed_icc_large_cluster_threshold is None:
                raise ValueError(
                    "large_cluster_threshold observed ICC use requires "
                    "observed_icc_large_cluster_threshold"
                )
        elif self.observed_icc_large_cluster_threshold is not None:
            raise ValueError(
                "observed_icc_large_cluster_threshold is only valid for "
                "large_cluster_threshold observed ICC use"
            )
        if not confirmatory:
            return self
        if len(confirmatory) == 1 and self.multiplicity_method == "none":
            raise ValueError(
                "a confirmatory endpoint requires single_endpoint or bonferroni "
                "multiplicity_method"
            )
        if len(confirmatory) > 1 and self.multiplicity_method != "bonferroni":
            raise ValueError(
                "multiple confirmatory endpoints require bonferroni multiplicity_method"
            )
        if any(endpoint.hierarchy_rank is not None for endpoint in confirmatory):
            raise ValueError(
                "hierarchy_rank is reserved for a future fixed-sequence method"
            )
        return self


class DriftMetricPlan(PersistedArtifact):
    artifact_kind: Literal["drift-metric-plan"] = "drift-metric-plan"
    metric: DriftMetric
    label: str = Field(min_length=1)
    interpretation: DriftInterpretation = "exploratory"
    analysis_methods: tuple[DriftAnalysisMethod, ...] = ("descriptive_trend",)
    reason_codes: tuple[ReasonCode, ...] = ()
    minimum_windows: int = Field(default=6, ge=2)
    minimum_dependence_windows: int = Field(default=8, ge=8)
    minimum_state_space_windows: int = Field(default=6, ge=6)
    minimum_observations_per_window: int = Field(default=1, ge=1)
    slope_review_threshold: DecimalString = Field(
        default="0.050000",
        pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    step_review_threshold: DecimalString = Field(
        default="0.100000",
        pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    autocorrelation_review_threshold: DecimalString = Field(
        default="0.500000",
        pattern=r"^(0|1)\.[0-9]{6}$",
    )
    ar1_review_threshold: DecimalString = Field(
        default="0.500000",
        pattern=r"^(0|1)\.[0-9]{6}$",
    )
    state_space_alpha: DecimalString = Field(
        default="0.300000",
        pattern=r"^(0|1)\.[0-9]{6}$",
    )

    @field_validator("analysis_methods", mode="before")
    @classmethod
    def _coerce_analysis_methods(cls, value: object) -> object:
        return coerce_tuple(value)

    @field_validator("reason_codes", mode="before")
    @classmethod
    def _coerce_reason_codes(cls, value: object) -> object:
        if isinstance(value, list | tuple):
            return tuple(coerce_enum(ReasonCode, item) for item in value)
        return value

    @model_validator(mode="after")
    def _validate_metric_plan(self) -> DriftMetricPlan:
        if len(self.analysis_methods) != len(set(self.analysis_methods)):
            raise ValueError("drift analysis_methods values must be unique")
        if self.metric == "reason_code_rate":
            if not self.reason_codes:
                raise ValueError("reason_code_rate drift metrics require reason_codes")
        elif self.reason_codes:
            raise ValueError("reason_codes are only valid for reason_code_rate drift metrics")
        alpha = _decimal(self.state_space_alpha)
        if alpha <= Decimal("0") or alpha > Decimal("1"):
            raise ValueError("state_space_alpha must be greater than 0 and no more than 1")
        return self


class DriftMonitoringPlan(PersistedArtifact):
    artifact_kind: Literal["drift-monitoring-plan"] = "drift-monitoring-plan"
    plan_id: str = Field(min_length=1)
    interpretation: DriftInterpretation = "exploratory"
    ordering_variable: DriftOrderingVariable = "window_index"
    comparability_mode: Literal["strict_protocol_digest", "material_fields"] = (
        "strict_protocol_digest"
    )
    allow_bounded_sensitivity_on_comparability_failure: bool = False
    drift_hypothesis: str | None = Field(default=None, min_length=1)
    metrics: tuple[DriftMetricPlan, ...] = Field(min_length=1)
    known_provider_version_unknowns: tuple[str, ...] = ()

    @field_validator("metrics", "known_provider_version_unknowns", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_monitoring_plan(self) -> DriftMonitoringPlan:
        metric_keys = [
            (metric.metric, tuple(reason.value for reason in metric.reason_codes))
            for metric in self.metrics
        ]
        if len(metric_keys) != len(set(metric_keys)):
            raise ValueError("drift monitoring metrics must be unique by metric and reason codes")
        confirmatory_metrics = [
            metric for metric in self.metrics if metric.interpretation == "confirmatory"
        ]
        if self.interpretation == "confirmatory" or confirmatory_metrics:
            if self.drift_hypothesis is None:
                raise ValueError(
                    "confirmatory drift monitoring requires a predeclared drift_hypothesis"
                )
            if self.interpretation != "confirmatory":
                raise ValueError(
                    "confirmatory drift metrics require a confirmatory monitoring plan"
                )
        return self


class TrajectoryInvariantPlan(PersistedArtifact):
    artifact_kind: Literal["trajectory-invariant-plan"] = "trajectory-invariant-plan"
    invariant_id: str = Field(min_length=1)
    label: str = Field(min_length=1)
    invariant_type: TrajectoryInvariantType
    category: TrajectoryInvariantCategory = "governance_control_failure"
    interpretation: TrajectoryInterpretation = "exploratory"
    forbidden_states: tuple[TrajectoryState, ...] = ()
    required_state: TrajectoryState | None = None
    before_state: TrajectoryState | None = None
    minimum_observations: int = Field(default=1, ge=1)

    @field_validator("forbidden_states", mode="before")
    @classmethod
    def _coerce_forbidden_states(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_invariant(self) -> TrajectoryInvariantPlan:
        if self.invariant_type == "forbidden_state":
            if not self.forbidden_states:
                raise ValueError("forbidden_state invariants require forbidden_states")
        elif self.forbidden_states:
            raise ValueError("forbidden_states are only valid for forbidden_state invariants")
        if self.invariant_type == "required_review_for_approval":
            if self.required_state is None:
                raise ValueError(
                    "required_review_for_approval invariants require required_state"
                )
            if self.before_state is not None:
                raise ValueError(
                    "required_review_for_approval does not support measured ordering; "
                    "before_state is reserved for future ordered event data"
                )
        elif self.required_state is not None or self.before_state is not None:
            raise ValueError(
                "required_state and before_state are only valid for "
                "required_review_for_approval invariants"
            )
        return self


class TrajectoryAnalysisPlan(PersistedArtifact):
    artifact_kind: Literal["trajectory-analysis-plan"] = "trajectory-analysis-plan"
    plan_id: str = Field(min_length=1)
    interpretation: TrajectoryInterpretation = "exploratory"
    analysis_methods: tuple[TrajectoryAnalysisMethod, ...] = (
        "observable_transition_profile",
        "sequence_invariant_check",
        "event_process_summary",
        "burst_window_count",
    )
    minimum_observations: int = Field(default=1, ge=1)
    minimum_transition_support: int = Field(default=1, ge=1)
    minimum_event_count: int = Field(default=3, ge=0)
    minimum_event_exposure: int = Field(default=1, ge=1)
    burst_window_seconds: int = Field(default=60, ge=1)
    burst_count_threshold: int = Field(default=3, ge=2)
    invariants: tuple[TrajectoryInvariantPlan, ...] = ()

    @field_validator("analysis_methods", "invariants", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_plan(self) -> TrajectoryAnalysisPlan:
        if len(self.analysis_methods) != len(set(self.analysis_methods)):
            raise ValueError("trajectory analysis_methods values must be unique")
        invariant_ids = [invariant.invariant_id for invariant in self.invariants]
        if len(invariant_ids) != len(set(invariant_ids)):
            raise ValueError("trajectory invariant_id values must be unique")
        if (
            self.interpretation == "confirmatory"
            and "sequence_invariant_check" not in self.analysis_methods
        ):
            raise ValueError(
                "confirmatory trajectory plans must include sequence_invariant_check"
            )
        return self


class RareEventUpperBound(PersistedArtifact):
    artifact_kind: Literal["rare-event-upper-bound"] = "rare-event-upper-bound"
    endpoint_id: str = Field(min_length=1)
    label: str = Field(min_length=1)
    observed_events: int = Field(ge=0)
    exposure: int = Field(ge=0)
    exposure_unit: str = Field(min_length=1)
    event_rate: DecimalString = Field(pattern=r"^(0|1)\.[0-9]{6}$")
    upper_count_bound: DecimalString = Field(pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$")
    upper_rate_bound: DecimalString = Field(pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$")
    confidence_level: Literal["0.950000"] = "0.950000"
    interval_sidedness: Literal["one_sided_upper"] = "one_sided_upper"
    analysis_method: Literal["poisson_upper_bound"] = "poisson_upper_bound"
    zero_events: bool = False
    limitations: tuple[str, ...] = ()

    @field_validator("limitations", mode="before")
    @classmethod
    def _coerce_limitations(cls, value: object) -> object:
        return coerce_tuple(value)


class ClusterCorrelationSummary(PersistedArtifact):
    artifact_kind: Literal["cluster-correlation-summary"] = "cluster-correlation-summary"
    endpoint_id: str = Field(min_length=1)
    label: str = Field(min_length=1)
    cluster_count: int = Field(ge=0)
    observation_count: int = Field(ge=0)
    planned_intraclass_correlation: DecimalString = Field(pattern=r"^0\.[0-9]{6}$")
    observed_intraclass_correlation: SignedDecimalString | None = Field(
        default=None,
        pattern=r"^-?(0|1)\.[0-9]{6}$",
    )
    uncertainty_method: Literal[
        "cluster_bootstrap_percentile",
        "not_evaluated",
    ] = "not_evaluated"
    ci_lower: SignedDecimalString | None = Field(default=None, pattern=r"^-?(0|1)\.[0-9]{6}$")
    ci_upper: SignedDecimalString | None = Field(default=None, pattern=r"^-?(0|1)\.[0-9]{6}$")
    bootstrap_iterations: int = Field(default=0, ge=0)
    confirmatory_use: Literal[
        "disabled",
        "eligible_large_cluster_threshold",
        "eligible_external_review",
    ] = "disabled"
    confirmatory_interval_uses_planned_icc: bool = True
    limitations: tuple[str, ...] = ()

    @field_validator("limitations", mode="before")
    @classmethod
    def _coerce_limitations(cls, value: object) -> object:
        return coerce_tuple(value)


class StatisticalInvariantResult(PersistedArtifact):
    artifact_kind: Literal["statistical-invariant-result"] = "statistical-invariant-result"
    endpoint_id: str = Field(min_length=1)
    label: str = Field(min_length=1)
    endpoint_kind: EndpointKind
    role: EndpointRole
    interpretation: EndpointInterpretation
    analysis_method: EndpointAnalysisMethod
    prerequisite_status: EndpointPrerequisiteStatus
    multiplicity_method: MultiplicityMethod
    adjusted_alpha: DecimalString = Field(pattern=r"^0\.[0-9]{6}$")
    numerator: int = Field(ge=0)
    denominator: int = Field(ge=0)
    cluster_count: int = Field(ge=0)
    rate: DecimalString = Field(pattern=r"^(0|1)\.[0-9]{6}$")
    reason_codes: tuple[ReasonCode, ...] = ()
    outcome: str | None = None
    rare_event_bound: RareEventUpperBound | None = None
    cluster_correlation: ClusterCorrelationSummary | None = None
    limitations: tuple[str, ...] = ()

    @field_validator("reason_codes", mode="before")
    @classmethod
    def _coerce_reason_codes(cls, value: object) -> object:
        if isinstance(value, list | tuple):
            return tuple(coerce_enum(ReasonCode, item) for item in value)
        return value

    @field_validator("limitations", mode="before")
    @classmethod
    def _coerce_limitations(cls, value: object) -> object:
        return coerce_tuple(value)


class PairedRandomizationTestResult(PersistedArtifact):
    artifact_kind: Literal["paired-randomization-test-result"] = (
        "paired-randomization-test-result"
    )
    endpoint_id: str = Field(min_length=1)
    label: str = Field(min_length=1)
    interpretation: EndpointInterpretation
    analysis_method: Literal[
        "paired_cluster_permutation_exact",
        "paired_cluster_permutation_monte_carlo",
    ]
    prerequisite_status: EndpointPrerequisiteStatus
    exchangeability_assumption: Literal[
        "baseline_candidate_relabeling",
        "not_applicable",
    ]
    compared_clusters: int = Field(ge=0)
    observed_difference: SignedDecimalString = Field(pattern=r"^-?(0|1)\.[0-9]{6}$")
    non_inferiority_margin: DecimalString = Field(pattern=r"^0\.[0-9]{6}$")
    p_value: DecimalString | None = Field(default=None, pattern=r"^(0|1)\.[0-9]{6}$")
    adjusted_p_value: DecimalString | None = Field(default=None, pattern=r"^(0|1)\.[0-9]{6}$")
    exhaustive: bool = False
    resamples: int = Field(ge=0)
    seed: str | None = None
    limitations: tuple[str, ...] = ()

    @field_validator("limitations", mode="before")
    @classmethod
    def _coerce_limitations(cls, value: object) -> object:
        return coerce_tuple(value)


class LiveProtocolRecord(PersistedArtifact):
    artifact_kind: Literal["live-protocol-record"] = "live-protocol-record"
    protocol_id: str = Field(min_length=1)
    suite_id: str = Field(min_length=1)
    suite_version: str = Field(min_length=1)
    suite_digest: DigestHex
    baseline_mode: Literal["concurrent_paired", "fixed_reference"] = "concurrent_paired"
    hypothesis_family: Literal[
        "governance_control_non_inferiority",
        "provider_model_comparison",
        "regression_detection",
    ] = "governance_control_non_inferiority"
    primary_endpoint: Literal["expectation_pass_rate", "reason_code_rate"] = (
        "expectation_pass_rate"
    )
    analysis_method: AnalysisMethod = "paired_cluster_t_interval"
    baseline_group_id: str = "overall"
    candidate_group_id: str = "overall"
    fixed_reference_pass_rate: DecimalString | None = Field(
        default=None,
        pattern=r"^(0|1)\.[0-9]{6}$",
    )
    confidence_level: Literal["0.950000"] = "0.950000"
    non_inferiority_margin: DecimalString = Field(pattern=r"^0\.[0-9]{6}$")
    cluster_by: Literal["case_id", "source_group_id"] = "case_id"
    planned_observations: int = Field(ge=1)
    planned_clusters: int = Field(ge=1)
    planned_observations_per_cluster: DecimalString = Field(
        pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    assumed_intraclass_correlation: DecimalString = Field(pattern=r"^0\.[0-9]{6}$")
    design_effect: DecimalString = Field(pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$")
    planned_effective_n: DecimalString = Field(pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$")
    sample_size_rationale: str = Field(min_length=1)
    planned_repetitions: int = Field(ge=1)
    randomization_seed: int = Field(ge=0)
    randomization_blocking: Literal["balanced_case_blocks"] = "balanced_case_blocks"
    max_requests: int = Field(ge=1)
    max_total_cost_usd: DecimalString = Field(pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$")
    max_cost_per_observation_usd: DecimalString = Field(
        pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    max_generated_tokens: int | None = Field(default=None, ge=1)
    max_total_tokens: int | None = Field(default=None, ge=1)
    max_retries: int = Field(default=2, ge=0)
    retry_initial_backoff_seconds: DecimalString = Field(
        default="1.000000",
        pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    retry_max_backoff_seconds: DecimalString = Field(
        default="8.000000",
        pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    requests_per_minute: int | None = Field(default=None, ge=1)
    tokens_per_minute: int | None = Field(default=None, ge=1)
    max_rate_limit_events: int = Field(default=0, ge=0)
    exclusion_policy: str = Field(min_length=1)
    allowed_exclusion_reasons: tuple[str, ...] = ()
    max_exclusion_rate: DecimalString = Field(default="0.000000", pattern=r"^0\.[0-9]{6}$")
    provider_version_capture: tuple[str, ...] = ()
    stopping_rules: tuple[str, ...] = ()
    tool_schema_digest: DigestHex
    policy_bundle_digest: DigestHex
    analysis_digest: DigestHex
    advanced_analysis_plan: AdvancedAnalysisPlan | None = None
    drift_monitoring_plan: DriftMonitoringPlan | None = None
    trajectory_analysis_plan: TrajectoryAnalysisPlan | None = None
    approved_data_boundary: str = Field(min_length=1)
    safety_limits: tuple[str, ...] = ()

    @field_validator(
        "allowed_exclusion_reasons",
        "provider_version_capture",
        "stopping_rules",
        "safety_limits",
        mode="before",
    )
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_protocol_plan(self) -> LiveProtocolRecord:
        if self.baseline_mode == "fixed_reference" and self.fixed_reference_pass_rate is None:
            raise ValueError("fixed_reference baseline_mode requires fixed_reference_pass_rate")
        if self.baseline_mode == "concurrent_paired" and self.fixed_reference_pass_rate is not None:
            raise ValueError(
                "concurrent_paired baseline_mode must not set fixed_reference_pass_rate"
            )
        if (
            self.baseline_mode == "fixed_reference"
            and self.analysis_method not in {"fixed_reference_cluster_t_interval", "exploratory"}
        ):
            raise ValueError(
                "fixed_reference baseline_mode requires fixed_reference_cluster_t_interval analysis"
            )
        if (
            self.baseline_mode == "concurrent_paired"
            and self.analysis_method
            not in {
                "paired_cluster_t_interval",
                "paired_cluster_bootstrap_percentile",
                "paired_cluster_permutation_exact",
                "paired_cluster_permutation_monte_carlo",
                "exploratory",
            }
        ):
            raise ValueError(
                "concurrent_paired baseline_mode requires a paired cluster analysis"
            )
        planned_mean = _decimal(self.planned_observations) / _decimal(self.planned_clusters)
        if self.planned_observations_per_cluster != _decimal_string(planned_mean):
            raise ValueError(
                "planned_observations_per_cluster must equal planned_observations / "
                "planned_clusters"
            )
        cluster_size = _decimal(self.planned_observations_per_cluster)
        rho = _decimal(self.assumed_intraclass_correlation)
        design_effect = Decimal("1") + (cluster_size - Decimal("1")) * rho
        if self.design_effect != _decimal_string(design_effect):
            raise ValueError("design_effect must equal 1 + (m - 1) * rho")
        effective_n = _decimal(self.planned_observations) / design_effect
        if self.planned_effective_n != _decimal_string(effective_n):
            raise ValueError("planned_effective_n must equal planned_observations / design_effect")
        if self.analysis_method in {
            "paired_cluster_permutation_exact",
            "paired_cluster_permutation_monte_carlo",
        }:
            if self.baseline_mode != "concurrent_paired":
                raise ValueError(
                    "paired permutation methods require concurrent_paired baseline_mode"
                )
            if self.advanced_analysis_plan is None:
                raise ValueError("paired permutation methods require advanced_analysis_plan")
        if self.advanced_analysis_plan is not None:
            self._validate_advanced_analysis_plan()
        return self

    def _validate_advanced_analysis_plan(self) -> None:
        if self.advanced_analysis_plan is None:
            raise ValueError("advanced_analysis_plan is required for advanced analysis")
        if self.analysis_method in {
            "paired_cluster_permutation_exact",
            "paired_cluster_permutation_monte_carlo",
        }:
            primary = next(
                endpoint
                for endpoint in self.advanced_analysis_plan.endpoints
                if endpoint.role == "primary"
            )
            if primary.exchangeability_assumption != "baseline_candidate_relabeling":
                raise ValueError(
                    "paired permutation primary analysis requires a predeclared "
                    "baseline_candidate_relabeling exchangeability assumption"
                )
            if primary.endpoint_kind != "expectation_pass_rate":
                raise ValueError(
                    "paired permutation comparison currently supports only an "
                    "expectation_pass_rate primary endpoint"
                )
        for endpoint in self.advanced_analysis_plan.endpoints:
            if (
                endpoint.interpretation == "confirmatory"
                and endpoint.minimum_clusters > self.planned_clusters
            ):
                raise ValueError(
                    "confirmatory endpoint minimum_clusters cannot exceed planned_clusters"
                )
            if endpoint.role == "primary" and endpoint.endpoint_kind != self.primary_endpoint:
                raise ValueError("primary advanced endpoint must match primary_endpoint")


class LiveRate(PersistedArtifact):
    artifact_kind: Literal["live-rate"] = "live-rate"
    label: str = Field(min_length=1)
    numerator: int = Field(ge=0)
    denominator: int = Field(ge=0)
    cluster_count: int = Field(ge=0)
    effective_n: DecimalString = Field(pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$")
    design_effect: DecimalString = Field(pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$")
    largest_cluster_size: int = Field(ge=0)
    largest_cluster_design_effect: DecimalString = Field(
        pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    largest_cluster_effective_n: DecimalString = Field(
        pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    assumed_intraclass_correlation: DecimalString = Field(pattern=r"^0\.[0-9]{6}$")
    analysis_method: str = Field(min_length=1)
    exploratory: bool = False
    rate: DecimalString = Field(pattern=r"^(0|1)\.[0-9]{6}$")
    cluster_mean_rate: DecimalString = Field(pattern=r"^(0|1)\.[0-9]{6}$")
    interval_center: Literal["cluster_mean_rate", "pooled_rate"] = "cluster_mean_rate"
    interval_center_value: DecimalString = Field(pattern=r"^(0|1)\.[0-9]{6}$")
    confidence_level: Literal["0.950000"] = "0.950000"
    ci_lower: DecimalString = Field(pattern=r"^(0|1)\.[0-9]{6}$")
    ci_upper: DecimalString = Field(pattern=r"^(0|1)\.[0-9]{6}$")


class LiveDistribution(PersistedArtifact):
    artifact_kind: Literal["live-distribution"] = "live-distribution"
    metric: Literal["latency_ms", "estimated_cost_usd"]
    count: int = Field(ge=0)
    min: DecimalString | None = Field(default=None, pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$")
    p50: DecimalString | None = Field(default=None, pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$")
    p95: DecimalString | None = Field(default=None, pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$")
    max: DecimalString | None = Field(default=None, pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$")
    mean: DecimalString | None = Field(default=None, pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$")
    total: DecimalString | None = Field(default=None, pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$")


class LiveObservationResult(PersistedArtifact):
    artifact_kind: Literal["live-observation-result"] = "live-observation-result"
    observation_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    case_id: str = Field(min_length=1)
    repetition_index: int = Field(ge=0)
    provider: str | None = None
    model: str | None = None
    resolved_model: str | None = None
    provider_api_version: str | None = None
    provider_sdk: str | None = None
    provider_region: str | None = None
    adapter_id: str | None = None
    pipeline_id: str = Field(min_length=1)
    cluster_id: str = Field(min_length=1)
    source_group_id: str | None = None
    started_at_utc: str | None = None
    completed_at_utc: str | None = None
    observation_status: Literal["included", "excluded"] = "included"
    exclusion_reason: str | None = None
    attempt_count: int | None = Field(default=None, ge=1)
    retry_count: int | None = Field(default=None, ge=0)
    rate_limit_events: int | None = Field(default=None, ge=0)
    tool_schema_digest: DigestHex
    policy_bundle_digest: DigestHex
    state: GateState
    reason_codes: tuple[ReasonCode, ...] = ()
    findings: tuple[Finding, ...] = ()

    @field_validator("state", mode="before")
    @classmethod
    def _coerce_state(cls, value: object) -> GateState:
        return coerce_enum(GateState, value)

    @field_validator("reason_codes", mode="before")
    @classmethod
    def _coerce_reason_codes(cls, value: object) -> object:
        if isinstance(value, list | tuple):
            return tuple(coerce_enum(ReasonCode, item) for item in value)
        return value

    @field_validator("findings", mode="before")
    @classmethod
    def _coerce_findings(cls, value: object) -> object:
        return coerce_tuple(value)


class LiveGroupSummary(PersistedArtifact):
    artifact_kind: Literal["live-group-summary"] = "live-group-summary"
    group_id: str = Field(min_length=1)
    provider: str | None = None
    model: str | None = None
    adapter_id: str | None = None
    pipeline_id: str = Field(min_length=1)
    observations: int = Field(ge=0)
    included_observations: int = Field(ge=0)
    excluded_observations: int = Field(ge=0)
    cluster_count: int = Field(ge=0)
    effective_n: DecimalString = Field(pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$")
    design_effect: DecimalString = Field(pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$")
    exclusion_rate: LiveRate
    expectation_pass_rate: LiveRate
    outcome_rates: tuple[LiveRate, ...] = ()
    reason_code_rates: tuple[LiveRate, ...] = ()
    latency_ms: LiveDistribution
    estimated_cost_usd: LiveDistribution

    @field_validator("outcome_rates", "reason_code_rates", mode="before")
    @classmethod
    def _coerce_rates(cls, value: object) -> object:
        return coerce_tuple(value)


class LiveEvaluationReport(PersistedArtifact):
    artifact_kind: Literal["live-evaluation-report"] = "live-evaluation-report"
    runset_id: str = Field(min_length=1)
    suite_id: str = Field(min_length=1)
    suite_version: str = Field(min_length=1)
    protocol_id: str | None = None
    protocol_digest: DigestHex | None = None
    baseline_mode: Literal["concurrent_paired", "fixed_reference"] | None = None
    analysis_method: str = Field(default="cluster_t_interval", min_length=1)
    cluster_by: Literal["case_id", "source_group_id"] = "case_id"
    planned_repetitions: int | None = Field(default=None, ge=1)
    planned_observations: int | None = Field(default=None, ge=1)
    planned_clusters: int | None = Field(default=None, ge=1)
    completion_status: Literal["complete", "incomplete"] = "complete"
    stop_reasons: tuple[str, ...] = ()
    budget_exceeded: bool = False
    state: GateState
    confidence_level: Literal["0.950000"] = "0.950000"
    observations: tuple[LiveObservationResult, ...]
    overall: LiveGroupSummary
    groups: tuple[LiveGroupSummary, ...]
    statistical_invariants: tuple[StatisticalInvariantResult, ...] = ()
    limitations: tuple[str, ...] = (
        "live evaluation is time-bound to the declared provider, model, adapter, "
        "configuration, and execution window",
        "aggregate rates do not certify safety, compliance, clinical validity, or provider "
        "superiority in general",
        "design-effect and effective-n fields are planning and sensitivity metadata; "
        "cluster intervals use the declared empirical cluster-rate method",
    )

    @field_validator(
        "observations",
        "groups",
        "statistical_invariants",
        "limitations",
        "stop_reasons",
        mode="before",
    )
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @field_validator("state", mode="before")
    @classmethod
    def _coerce_state(cls, value: object) -> GateState:
        return coerce_enum(GateState, value)


class LiveComparisonReport(PersistedArtifact):
    artifact_kind: Literal["live-comparison-report"] = "live-comparison-report"
    baseline_runset_id: str = Field(min_length=1)
    candidate_runset_id: str = Field(min_length=1)
    suite_id: str = Field(min_length=1)
    suite_version: str = Field(min_length=1)
    baseline_group_id: str = Field(min_length=1)
    candidate_group_id: str = Field(min_length=1)
    protocol_id: str = Field(min_length=1)
    protocol_digest: DigestHex
    baseline_mode: Literal["concurrent_paired", "fixed_reference"]
    analysis_method: str = Field(min_length=1)
    exploratory: bool = False
    state: GateState
    confidence_level: Literal["0.950000"] = "0.950000"
    non_inferiority_margin: DecimalString = Field(pattern=r"^0\.[0-9]{6}$")
    baseline_pass_rate: LiveRate
    candidate_pass_rate: LiveRate
    pass_rate_difference: SignedDecimalString = Field(pattern=r"^-?(0|1)\.[0-9]{6}$")
    difference_ci_lower: SignedDecimalString = Field(pattern=r"^-?(0|1)\.[0-9]{6}$")
    difference_ci_upper: SignedDecimalString = Field(pattern=r"^-?(0|1)\.[0-9]{6}$")
    compared_clusters: int = Field(ge=0)
    effective_n: DecimalString = Field(pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$")
    fixed_reference_pass_rate: DecimalString | None = Field(
        default=None,
        pattern=r"^(0|1)\.[0-9]{6}$",
    )
    latency_p50_difference_ms: DecimalString | None = Field(
        default=None,
        pattern=r"^-?(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    cost_total_difference_usd: DecimalString | None = Field(
        default=None,
        pattern=r"^-?(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    randomization_tests: tuple[PairedRandomizationTestResult, ...] = ()
    limitations: tuple[str, ...] = (
        "live comparison intervals are descriptive unless the protocol predeclares the "
        "comparison as confirmatory",
    )

    @field_validator("state", mode="before")
    @classmethod
    def _coerce_state(cls, value: object) -> GateState:
        return coerce_enum(GateState, value)

    @field_validator("randomization_tests", "limitations", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)


class DriftWindowMetric(PersistedArtifact):
    artifact_kind: Literal["drift-window-metric"] = "drift-window-metric"
    metric: DriftMetric
    label: str = Field(min_length=1)
    reason_codes: tuple[ReasonCode, ...] = ()
    value: DecimalString | None = Field(
        default=None,
        pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    numerator: int | None = Field(default=None, ge=0)
    denominator: int | None = Field(default=None, ge=0)
    source: Literal[
        "pooled_rate",
        "observation_rate",
        "distribution_p50",
        "distribution_total",
        "reason_code_rate",
    ]

    @field_validator("reason_codes", mode="before")
    @classmethod
    def _coerce_reason_codes(cls, value: object) -> object:
        if isinstance(value, list | tuple):
            return tuple(coerce_enum(ReasonCode, item) for item in value)
        return value


class DriftWindowSummary(PersistedArtifact):
    artifact_kind: Literal["drift-window-summary"] = "drift-window-summary"
    window_id: str = Field(min_length=1)
    window_index: int = Field(ge=0)
    runset_id: str = Field(min_length=1)
    suite_id: str = Field(min_length=1)
    suite_version: str = Field(min_length=1)
    protocol_id: str | None = None
    protocol_digest: DigestHex | None = None
    baseline_mode: Literal["concurrent_paired", "fixed_reference"] | None = None
    analysis_method: str = Field(min_length=1)
    observation_window_start_utc: str | None = None
    observation_window_end_utc: str | None = None
    observations: int = Field(ge=0)
    included_observations: int = Field(ge=0)
    excluded_observations: int = Field(ge=0)
    provider_version_unknown: bool = False
    provider_version_keys: tuple[str, ...] = ()
    tool_schema_digests: tuple[DigestHex, ...] = ()
    policy_bundle_digests: tuple[DigestHex, ...] = ()
    metrics: tuple[DriftWindowMetric, ...] = ()

    @field_validator(
        "provider_version_keys",
        "tool_schema_digests",
        "policy_bundle_digests",
        "metrics",
        mode="before",
    )
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)


class DriftComparabilityResult(PersistedArtifact):
    artifact_kind: Literal["drift-comparability-result"] = "drift-comparability-result"
    status: DriftComparabilityStatus
    compared_windows: int = Field(ge=0)
    suite_matches: bool
    baseline_mode_matches: bool
    analysis_method_matches: bool
    protocol_digest_matches: bool
    material_fields_match: bool
    tool_schema_digest_matches: bool
    policy_bundle_digest_matches: bool
    reference_protocol_digest: DigestHex | None = None
    suite_id: str | None = None
    suite_version: str | None = None
    baseline_mode: str | None = None
    analysis_method: str | None = None
    failures: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()

    @field_validator("failures", "limitations", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)


class DriftStateEstimate(PersistedArtifact):
    artifact_kind: Literal["drift-state-estimate"] = "drift-state-estimate"
    state_name: Literal["governance_health", "control_reliability", "drift_state"]
    metric: DriftMetric
    label: str = Field(min_length=1)
    prerequisite_status: EndpointPrerequisiteStatus
    smoothing_alpha: DecimalString = Field(pattern=r"^(0|1)\.[0-9]{6}$")
    latest_level: DecimalString | None = Field(
        default=None,
        pattern=r"^-?(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    latest_drift_per_window: DecimalString | None = Field(
        default=None,
        pattern=r"^-?(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    innovation_variance: DecimalString | None = Field(
        default=None,
        pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    limitations: tuple[str, ...] = ()

    @field_validator("limitations", mode="before")
    @classmethod
    def _coerce_limitations(cls, value: object) -> object:
        return coerce_tuple(value)


class DriftMetricDiagnostic(PersistedArtifact):
    artifact_kind: Literal["drift-metric-diagnostic"] = "drift-metric-diagnostic"
    metric: DriftMetric
    label: str = Field(min_length=1)
    reason_codes: tuple[ReasonCode, ...] = ()
    interpretation: DriftInterpretation
    analysis_methods: tuple[DriftAnalysisMethod, ...]
    prerequisite_status: EndpointPrerequisiteStatus
    windows: int = Field(ge=0)
    observations: int = Field(ge=0)
    missing_windows: int = Field(ge=0)
    first_value: DecimalString | None = Field(
        default=None,
        pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    last_value: DecimalString | None = Field(
        default=None,
        pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    mean_value: DecimalString | None = Field(
        default=None,
        pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    slope_per_window: DecimalString | None = Field(
        default=None,
        pattern=r"^-?(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    max_step_change: DecimalString | None = Field(
        default=None,
        pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    lag1_autocorrelation: SignedDecimalString | None = Field(
        default=None,
        pattern=r"^-?(0|1)\.[0-9]{6}$",
    )
    ar1_phi: SignedDecimalString | None = Field(
        default=None,
        pattern=r"^-?(0|1)\.[0-9]{6}$",
    )
    ar1_intercept: DecimalString | None = Field(
        default=None,
        pattern=r"^-?(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    ar1_innovation_variance: DecimalString | None = Field(
        default=None,
        pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    stationarity_signal: DriftStationaritySignal = "none"
    dependence_signal: DriftStationaritySignal = "none"
    review_reasons: tuple[str, ...] = ()
    state_estimate: DriftStateEstimate | None = None
    limitations: tuple[str, ...] = ()

    @field_validator("reason_codes", mode="before")
    @classmethod
    def _coerce_reason_codes(cls, value: object) -> object:
        if isinstance(value, list | tuple):
            return tuple(coerce_enum(ReasonCode, item) for item in value)
        return value

    @field_validator(
        "analysis_methods",
        "review_reasons",
        "limitations",
        mode="before",
    )
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)


class LiveDriftReport(PersistedArtifact):
    artifact_kind: Literal["live-drift-report"] = "live-drift-report"
    report_id: str = Field(min_length=1)
    protocol_id: str | None = None
    protocol_digest: DigestHex | None = None
    drift_plan_id: str | None = None
    suite_id: str = Field(min_length=1)
    suite_version: str = Field(min_length=1)
    ordering_variable: DriftOrderingVariable = "window_index"
    interpretation: DriftInterpretation = "exploratory"
    state: GateState = GateState.not_evaluated
    monitoring_status: DriftMonitoringStatus
    observation_window_start_utc: str | None = None
    observation_window_end_utc: str | None = None
    comparability: DriftComparabilityResult
    windows: tuple[DriftWindowSummary, ...]
    diagnostics: tuple[DriftMetricDiagnostic, ...]
    limitations: tuple[str, ...] = (
        "cross-window monitoring is a review signal and is not a release-verdict gate",
        "stationarity or drift signals do not establish safety, compliance, clinical "
        "validity, provider quality, or model intent",
        "latent-state summaries describe governance health, control reliability, or drift "
        "state from observable records only",
    )

    @field_validator("state", mode="before")
    @classmethod
    def _coerce_state(cls, value: object) -> GateState:
        return coerce_enum(GateState, value)

    @field_validator("windows", "diagnostics", "limitations", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)


class TrajectoryPathSummary(PersistedArtifact):
    artifact_kind: Literal["trajectory-path-summary"] = "trajectory-path-summary"
    observation_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    case_id: str = Field(min_length=1)
    repetition_index: int = Field(ge=0)
    cluster_id: str = Field(min_length=1)
    terminal_state: TrajectoryState
    states: tuple[TrajectoryState, ...] = Field(min_length=2)
    transition_count: int = Field(ge=1)
    tool_count: int = Field(ge=0)
    claim_count: int = Field(ge=0)
    evidence_ref_count: int = Field(ge=0)
    claim_evidence_link_count: int = Field(ge=0)
    policy_result_count: int = Field(ge=0)
    human_review_required: bool = False
    human_review_performed: bool = False
    has_ordered_timestamps: bool = False
    limitations: tuple[str, ...] = ()

    @field_validator("states", "limitations", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)


class TrajectoryTransitionSummary(PersistedArtifact):
    artifact_kind: Literal["trajectory-transition-summary"] = (
        "trajectory-transition-summary"
    )
    from_state: TrajectoryState
    to_state: TrajectoryState
    count: int = Field(ge=0)
    from_state_count: int = Field(ge=0)
    conditional_frequency: DecimalString = Field(pattern=r"^(0|1)\.[0-9]{6}$")
    prerequisite_status: TrajectoryPrerequisiteStatus
    limitations: tuple[str, ...] = ()

    @field_validator("limitations", mode="before")
    @classmethod
    def _coerce_limitations(cls, value: object) -> object:
        return coerce_tuple(value)


class TrajectoryInvariantResult(PersistedArtifact):
    artifact_kind: Literal["trajectory-invariant-result"] = "trajectory-invariant-result"
    invariant_id: str = Field(min_length=1)
    label: str = Field(min_length=1)
    invariant_type: TrajectoryInvariantType
    category: TrajectoryInvariantCategory
    interpretation: TrajectoryInterpretation
    prerequisite_status: TrajectoryPrerequisiteStatus
    affected_observations: int = Field(ge=0)
    evaluated_observations: int = Field(ge=0)
    affected_observation_ids: tuple[str, ...] = ()
    state: GateState = GateState.not_evaluated
    limitations: tuple[str, ...] = ()

    @field_validator("state", mode="before")
    @classmethod
    def _coerce_state(cls, value: object) -> GateState:
        return coerce_enum(GateState, value)

    @field_validator("affected_observation_ids", "limitations", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)


class HistoryDependentTrajectoryCheck(PersistedArtifact):
    artifact_kind: Literal["history-dependent-trajectory-check"] = (
        "history-dependent-trajectory-check"
    )
    check_id: str = Field(min_length=1)
    dependency: str = Field(min_length=1)
    prerequisite_status: TrajectoryPrerequisiteStatus
    affected_observations: int = Field(ge=0)
    affected_observation_ids: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()

    @field_validator("affected_observation_ids", "limitations", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)


class OperationalEventProcessSummary(PersistedArtifact):
    artifact_kind: Literal["operational-event-process-summary"] = (
        "operational-event-process-summary"
    )
    event_type: OperationalEventType
    observed_events: int = Field(ge=0)
    exposure: int = Field(ge=0)
    exposure_unit: str = Field(default="observation", min_length=1)
    event_rate: DecimalString = Field(pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$")
    analysis_method: Literal[
        "poisson_rate",
        "renewal_gap_summary",
        "burst_window_count",
    ]
    prerequisite_status: TrajectoryPrerequisiteStatus
    timestamped_events: int = Field(ge=0)
    missing_timestamp_events: int = Field(ge=0)
    observation_window_seconds: DecimalString | None = Field(
        default=None,
        pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    mean_interarrival_seconds: DecimalString | None = Field(
        default=None,
        pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    max_events_in_burst_window: int = Field(ge=0)
    burst_window_seconds: int = Field(ge=1)
    burst_signal: OperationalBurstSignal = "none"
    limitations: tuple[str, ...] = ()

    @field_validator("limitations", mode="before")
    @classmethod
    def _coerce_limitations(cls, value: object) -> object:
        return coerce_tuple(value)


class LiveTrajectoryReport(PersistedArtifact):
    artifact_kind: Literal["live-trajectory-report"] = "live-trajectory-report"
    report_id: str = Field(min_length=1)
    runset_id: str = Field(min_length=1)
    evaluation_report_id: str = Field(min_length=1)
    protocol_id: str | None = None
    protocol_digest: DigestHex | None = None
    trajectory_plan_id: str | None = None
    suite_id: str = Field(min_length=1)
    suite_version: str = Field(min_length=1)
    interpretation: TrajectoryInterpretation = "exploratory"
    state: GateState = GateState.not_evaluated
    trajectory_status: Literal["valid", "exploratory", "invalid"]
    transition_assumption: Literal["canonical_observable_order"] = (
        "canonical_observable_order"
    )
    transition_assumption_status: TrajectoryPrerequisiteStatus
    observations: int = Field(ge=0)
    included_observations: int = Field(ge=0)
    excluded_observations: int = Field(ge=0)
    paths: tuple[TrajectoryPathSummary, ...]
    transitions: tuple[TrajectoryTransitionSummary, ...]
    invariants: tuple[TrajectoryInvariantResult, ...]
    history_dependent_checks: tuple[HistoryDependentTrajectoryCheck, ...]
    event_processes: tuple[OperationalEventProcessSummary, ...]
    limitations: tuple[str, ...] = (
        "trajectory analysis is derived from privacy-filtered structured artifacts",
        "trajectory and event-process outputs are review signals and are not "
        "release-verdict gates",
        "path coverage over observed records is not proof that unsafe paths are impossible",
    )

    @field_validator("state", mode="before")
    @classmethod
    def _coerce_state(cls, value: object) -> GateState:
        return coerce_enum(GateState, value)

    @field_validator(
        "paths",
        "transitions",
        "invariants",
        "history_dependent_checks",
        "event_processes",
        "limitations",
        mode="before",
    )
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)
