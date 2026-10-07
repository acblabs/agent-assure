from __future__ import annotations

from datetime import datetime
from decimal import ROUND_CEILING, ROUND_FLOOR, Decimal
from itertools import pairwise
from typing import Literal

from agent_assure._decimal_context import live_decimal_context, with_live_decimal_context
from agent_assure.io_limits import MAX_PERSISTED_OBSERVATIONS
from agent_assure.live.primitives import mean_decimal, parse_timestamp, signed_unit_decimal_string
from agent_assure.schema.base import SCHEMA_VERSION
from agent_assure.schema.common import GateState, decimal_string
from agent_assure.schema.live import (
    ClusterCorrelationSummary,
    DriftMetricDiagnostic,
    DriftWindowSummary,
    LiveComparisonReport,
    LiveDistribution,
    LiveDriftReport,
    LiveEvaluationReport,
    LiveGroupSummary,
    LiveObservationResult,
    LiveRate,
    LiveTrajectoryReport,
    PairedRandomizationTestResult,
    RareEventUpperBound,
    StatisticalInvariantResult,
)

LEGACY_LIVE_SCHEMA_VERSIONS = frozenset({"0.6.0", "0.6.1", "0.6.2", "0.6.3", "0.6.4", "0.6.5"})
_POST_BINDING_HARDENING_VERSIONS = frozenset({"0.6.3", "0.6.4", "0.6.5"})
_SIX_PLACES = Decimal("0.000001")
_HALF_SIX_PLACES = Decimal("0.0000005")
_POISSON_ROOT_TOLERANCE = Decimal("0.000000000001")
_POISSON_CDF_TOLERANCE = Decimal("1e-30")
_MAX_BOUND_INTEGER_DIGITS = 6
_LEGACY_ICC_BOOTSTRAP_ITERATIONS = 1_000
_LEGACY_MAX_EXACT_PERMUTATION_CLUSTERS = 20
_LEGACY_MONTE_CARLO_RESAMPLES = 10_001
_PAIRED_RANDOMIZATION_METHODS = frozenset(
    {
        "paired_cluster_permutation_exact",
        "paired_cluster_permutation_monte_carlo",
    }
)
_CONCURRENT_COMPARISON_METHODS = frozenset(
    {
        "paired_cluster_t_interval",
        "paired_cluster_bootstrap_percentile",
        *_PAIRED_RANDOMIZATION_METHODS,
        "exploratory",
    }
)
_FIXED_REFERENCE_COMPARISON_METHODS = frozenset(
    {"fixed_reference_cluster_t_interval", "exploratory"}
)
_RARE_EVENT_ENDPOINT_KINDS = frozenset(
    {"critical_event_rate", "reason_code_rate", "exclusion_rate"}
)
_BUDGET_STOP_REASONS = frozenset(
    {
        "budget_exhausted",
        "cost_budget_exhausted_before_attempt",
        "cost_budget_exceeded_after_response",
        "generated_token_budget_exhausted_before_attempt",
        "generated_token_budget_exceeded_after_response",
        "token_budget_exhausted_before_attempt",
        "token_budget_exceeded_after_response",
        "token_budget_exhausted",
        "generated_token_budget_exhausted",
    }
)


def _legacy_version(artifact: object, *, owner: str) -> str | None:
    version = getattr(artifact, "schema_version", None)
    if version == SCHEMA_VERSION:
        return None
    if version not in LEGACY_LIVE_SCHEMA_VERSIONS:
        raise ValueError(
            f"{owner} schema_version {version!r} is not supported by the live artifact contract"
        )
    return str(version)


def _require_nested_version(artifact: object, version: str, *, owner: str) -> None:
    if getattr(artifact, "schema_version", None) != version:
        raise ValueError(f"{owner} schema_version must match its historical parent")


@with_live_decimal_context
def _rate_string(numerator: int, denominator: int) -> str:
    if denominator == 0:
        raise ValueError("rate is undefined for a zero denominator")
    return decimal_string(Decimal(numerator) / Decimal(denominator))


def _bounded_nonnegative_decimal(value: str, *, owner: str) -> Decimal:
    whole = value.split(".", maxsplit=1)[0]
    if len(whole) > _MAX_BOUND_INTEGER_DIGITS:
        raise ValueError(f"{owner} exceeds the bounded historical Poisson domain")
    return Decimal(value)


def _poisson_cdf(events: int, rate: Decimal) -> Decimal:
    with live_decimal_context(precision=max(50, len(str(events)) + 30)):
        projected_rate = +rate
        term = (-projected_rate).exp()
        total = term
        for index in range(1, events + 1):
            term *= projected_rate / Decimal(index)
            total += term
        return +total


@with_live_decimal_context
def _require_poisson_rounding_cell(bound: RareEventUpperBound) -> None:
    count = _bounded_nonnegative_decimal(
        bound.upper_count_bound,
        owner="historical rare-event upper_count_bound",
    )
    rate = _bounded_nonnegative_decimal(
        bound.upper_rate_bound,
        owner="historical rare-event upper_rate_bound",
    )
    exposure = Decimal(bound.exposure)
    lower = max(
        Decimal("0"),
        count - _HALF_SIX_PLACES,
        (rate - _HALF_SIX_PLACES) * exposure,
    )
    upper = min(
        count + _HALF_SIX_PLACES,
        (rate + _HALF_SIX_PLACES) * exposure,
    )
    if lower > upper:
        raise ValueError("historical rare-event upper count and rate bounds are inconsistent")

    alpha = Decimal("1") - Decimal(bound.confidence_level)
    lower_cdf = _poisson_cdf(
        bound.observed_events,
        max(Decimal("0"), lower - _POISSON_ROOT_TOLERANCE),
    )
    upper_cdf = _poisson_cdf(
        bound.observed_events,
        upper + _POISSON_ROOT_TOLERANCE,
    )
    if lower_cdf + _POISSON_CDF_TOLERANCE < alpha or upper_cdf - _POISSON_CDF_TOLERANCE > alpha:
        raise ValueError("historical rare-event bounds do not enclose the exact Poisson root")


def validate_legacy_rare_event_bound(bound: RareEventUpperBound) -> None:
    version = _legacy_version(bound, owner="rare-event bound")
    if version is None:
        return
    if bound.analysis_method != "poisson_upper_bound":
        raise ValueError("historical rare-event bounds require poisson_upper_bound")
    if not 0 < bound.exposure <= MAX_PERSISTED_OBSERVATIONS:
        raise ValueError("historical rare-event exposure is outside the supported domain")
    if bound.observed_events > bound.exposure:
        raise ValueError("historical rare-event observed_events cannot exceed exposure")
    if bound.event_rate != _rate_string(bound.observed_events, bound.exposure):
        raise ValueError("historical rare-event event_rate does not match counts")
    if bound.zero_events is not (bound.observed_events == 0):
        raise ValueError("historical rare-event zero_events does not match observed_events")
    confidence = Decimal(bound.confidence_level)
    if not Decimal("0") < confidence < Decimal("1"):
        raise ValueError("historical rare-event confidence_level must be between zero and one")
    _require_poisson_rounding_cell(bound)


@with_live_decimal_context
def validate_legacy_live_rate(rate: LiveRate) -> None:
    version = _legacy_version(rate, owner="live rate")
    if version is None:
        return
    if rate.denominator == 0:
        point_values = {
            rate.rate,
            rate.cluster_mean_rate,
            rate.interval_center_value,
            rate.ci_lower,
            rate.ci_upper,
        }
        common = (
            rate.numerator == 0
            and rate.cluster_count == 0
            and rate.effective_n == "0.000000"
            and rate.design_effect == "1.000000"
            and rate.largest_cluster_size == 0
            and rate.largest_cluster_design_effect == "1.000000"
            and rate.largest_cluster_effective_n == "0.000000"
        )
        fixed_reference = (
            rate.analysis_method == "fixed_reference"
            and not rate.exploratory
            and rate.interval_center == "pooled_rate"
            and len(point_values) == 1
        )
        early_empty_rate = (
            version not in _POST_BINDING_HARDENING_VERSIONS
            and rate.analysis_method != "fixed_reference"
            and rate.exploratory
            and rate.interval_center == "cluster_mean_rate"
            and point_values == {"0.000000"}
        )
        if not common or not (fixed_reference or early_empty_rate):
            raise ValueError("historical zero-denominator live rate is inconsistent")
        return

    if rate.denominator > MAX_PERSISTED_OBSERVATIONS:
        raise ValueError("historical live rate denominator exceeds the persisted observation cap")
    if rate.numerator > rate.denominator:
        raise ValueError("historical live rate numerator cannot exceed denominator")
    if not 0 < rate.cluster_count <= rate.denominator:
        raise ValueError("historical live rate cluster_count is inconsistent")
    if rate.rate != _rate_string(rate.numerator, rate.denominator):
        raise ValueError("historical live rate does not match numerator/denominator")
    minimum_largest = (rate.denominator + rate.cluster_count - 1) // rate.cluster_count
    maximum_largest = rate.denominator - rate.cluster_count + 1
    if not minimum_largest <= rate.largest_cluster_size <= maximum_largest:
        raise ValueError("historical live rate largest_cluster_size is impossible")

    rho = Decimal(rate.assumed_intraclass_correlation)
    mean_cluster_size = Decimal(rate.denominator) / Decimal(rate.cluster_count)
    expected_design_effect = Decimal("1") + (mean_cluster_size - Decimal("1")) * rho
    if rate.design_effect != decimal_string(expected_design_effect):
        raise ValueError(
            "historical live rate effective sample sizes and design effects do not match"
        )
    if rate.effective_n != decimal_string(Decimal(rate.denominator) / expected_design_effect):
        raise ValueError(
            "historical live rate effective sample sizes and design effects do not match"
        )
    largest_design_effect = Decimal("1") + (Decimal(rate.largest_cluster_size) - Decimal("1")) * rho
    if rate.largest_cluster_design_effect != decimal_string(largest_design_effect):
        raise ValueError(
            "historical live rate effective sample sizes and design effects do not match"
        )
    if rate.largest_cluster_effective_n != decimal_string(
        Decimal(rate.denominator) / largest_design_effect
    ):
        raise ValueError(
            "historical live rate effective sample sizes and design effects do not match"
        )
    expected_center = (
        rate.cluster_mean_rate if rate.interval_center == "cluster_mean_rate" else rate.rate
    )
    if rate.interval_center_value != expected_center:
        raise ValueError("historical live rate interval center is inconsistent")
    if Decimal(rate.ci_lower) > Decimal(rate.ci_upper):
        raise ValueError("historical live rate confidence interval is reversed")
    if (
        rate.cluster_count < 30
        or rate.analysis_method.startswith("exploratory_")
        or (
            rate.analysis_method == "descriptive_cluster_bootstrap_percentile"
            and rate.cluster_count < 50
        )
    ) and not rate.exploratory:
        raise ValueError("historical live rate understates exploratory status")


@with_live_decimal_context
def validate_legacy_live_distribution(distribution: LiveDistribution) -> None:
    version = _legacy_version(distribution, owner="live distribution")
    if version is None:
        return
    statistics = (
        distribution.min,
        distribution.p50,
        distribution.p95,
        distribution.max,
        distribution.mean,
        distribution.total,
    )
    if distribution.count == 0:
        if any(value is not None for value in statistics):
            raise ValueError("historical zero-count distribution carries statistics")
        return
    if distribution.count > MAX_PERSISTED_OBSERVATIONS or any(
        value is None for value in statistics
    ):
        raise ValueError("historical positive-count distribution is incomplete")
    minimum, p50, p95, maximum, mean, total = (
        Decimal(value) for value in statistics if value is not None
    )
    if not minimum <= p50 <= p95 <= maximum or not minimum <= mean <= maximum:
        raise ValueError("historical live distribution statistics are not ordered")
    tolerance = _HALF_SIX_PLACES * Decimal(distribution.count + 1)
    if abs(total - mean * Decimal(distribution.count)) > tolerance:
        raise ValueError("historical live distribution total and mean are inconsistent")


def validate_legacy_cluster_correlation(summary: ClusterCorrelationSummary) -> None:
    version = _legacy_version(summary, owner="cluster correlation")
    if version is None:
        return
    if summary.cluster_count > summary.observation_count:
        raise ValueError("historical correlation cluster_count exceeds observation_count")
    if (summary.ci_lower is None) is not (summary.ci_upper is None):
        raise ValueError("historical correlation interval endpoints must be jointly present")
    if (
        summary.ci_lower is not None
        and summary.ci_upper is not None
        and Decimal(summary.ci_lower) > Decimal(summary.ci_upper)
    ):
        raise ValueError("historical correlation interval endpoints are reversed")
    if summary.uncertainty_method == "not_evaluated":
        if summary.ci_lower is not None or summary.bootstrap_iterations != 0:
            raise ValueError("historical unevaluated correlation carries an interval")
    elif (
        summary.observed_intraclass_correlation is None
        or summary.ci_lower is None
        or summary.bootstrap_iterations != _LEGACY_ICC_BOOTSTRAP_ITERATIONS
    ):
        raise ValueError("historical correlation bootstrap metadata is inconsistent")
    if version in _POST_BINDING_HARDENING_VERSIONS and (
        summary.confirmatory_use != "disabled" or summary.confirmatory_interval_uses_planned_icc
    ):
        raise ValueError("historical correlation overstates confirmatory use")


def validate_legacy_statistical_invariant(invariant: StatisticalInvariantResult) -> None:
    version = _legacy_version(invariant, owner="statistical invariant")
    if version is None:
        return
    if not 0 < invariant.denominator <= MAX_PERSISTED_OBSERVATIONS:
        raise ValueError("historical invariant denominator is outside the supported domain")
    if invariant.numerator > invariant.denominator:
        raise ValueError("historical invariant numerator cannot exceed denominator")
    if not 0 < invariant.cluster_count <= invariant.denominator:
        raise ValueError("historical invariant cluster_count is inconsistent")
    if invariant.rate != _rate_string(invariant.numerator, invariant.denominator):
        raise ValueError("historical invariant rate does not match numerator/denominator")
    adjusted_alpha = Decimal(invariant.adjusted_alpha)
    if not Decimal("0") < adjusted_alpha < Decimal("1"):
        raise ValueError("historical invariant adjusted_alpha must be between zero and one")
    if version in _POST_BINDING_HARDENING_VERSIONS and (
        invariant.interpretation != "exploratory" or invariant.prerequisite_status == "met"
    ):
        raise ValueError("historical invariant overstates inferential eligibility")

    reason_endpoint = invariant.endpoint_kind in {"reason_code_rate", "critical_event_rate"}
    if reason_endpoint != bool(invariant.reason_codes):
        raise ValueError("historical invariant reason_codes do not match endpoint_kind")
    outcome_endpoint = invariant.endpoint_kind == "outcome_rate"
    if outcome_endpoint != (invariant.outcome is not None):
        raise ValueError("historical invariant outcome does not match endpoint_kind")
    if invariant.analysis_method == "poisson_upper_bound":
        if invariant.endpoint_kind not in _RARE_EVENT_ENDPOINT_KINDS:
            raise ValueError("historical Poisson analysis is invalid for this endpoint kind")
        bound = invariant.rare_event_bound
        if bound is None:
            raise ValueError("historical Poisson invariant requires a rare-event bound")
        _require_nested_version(bound, version, owner="historical rare-event bound")
        if bound.endpoint_id != invariant.endpoint_id or bound.label != invariant.label:
            raise ValueError("historical rare-event bound identity does not match its endpoint")
        if bound.observed_events != invariant.numerator or bound.exposure != invariant.denominator:
            raise ValueError("historical rare-event bound counts do not match its endpoint")
        expected_adjusted_confidence = decimal_string(Decimal("1") - adjusted_alpha)
        if bound.confidence_level != expected_adjusted_confidence:
            raise ValueError("historical rare-event confidence does not match endpoint alpha")
    elif invariant.rare_event_bound is not None:
        raise ValueError("historical non-Poisson invariant cannot carry a rare-event bound")

    correlation = invariant.cluster_correlation
    if correlation is None:
        raise ValueError("historical invariant requires its cluster-correlation summary")
    _require_nested_version(correlation, version, owner="historical cluster correlation")
    if correlation.endpoint_id != invariant.endpoint_id or correlation.label != invariant.label:
        raise ValueError("historical cluster-correlation identity does not match its endpoint")
    if (
        correlation.cluster_count != invariant.cluster_count
        or correlation.observation_count != invariant.denominator
    ):
        raise ValueError("historical cluster-correlation counts do not match its endpoint")


@with_live_decimal_context
def _require_half_even_probability_lattice(
    value: str,
    *,
    resamples: int,
    owner: str,
) -> None:
    projected = Decimal(value)
    lower = max(Decimal("0"), projected - _HALF_SIX_PLACES) * Decimal(resamples)
    upper = min(Decimal("1"), projected + _HALF_SIX_PLACES) * Decimal(resamples)
    minimum_count = int(lower.to_integral_value(rounding=ROUND_CEILING))
    maximum_count = int(upper.to_integral_value(rounding=ROUND_FLOOR))
    if max(1, minimum_count) > min(resamples, maximum_count):
        raise ValueError(f"{owner} p_value is not on the historical resampling lattice")


def validate_legacy_randomization_test(result: PairedRandomizationTestResult) -> None:
    version = _legacy_version(result, owner="paired randomization result")
    if version is None:
        return
    if version in _POST_BINDING_HARDENING_VERSIONS and (
        result.interpretation != "exploratory" or result.prerequisite_status == "met"
    ):
        raise ValueError("historical randomization result overstates inferential eligibility")
    if (result.p_value is None) is not (result.adjusted_p_value is None):
        raise ValueError("historical randomization p-value fields must be jointly present")
    if result.p_value is None or result.adjusted_p_value is None:
        if result.resamples != 0 or result.exhaustive:
            raise ValueError("historical unevaluated randomization result claims resampling")
        return
    if Decimal(result.adjusted_p_value) < Decimal(result.p_value):
        raise ValueError("historical adjusted_p_value cannot be below p_value")
    if result.compared_clusters == 0 or result.resamples == 0:
        raise ValueError("historical evaluated randomization requires clusters and resamples")
    if result.prerequisite_status == "invalid":
        raise ValueError("historical invalid randomization prerequisites cannot carry a p-value")
    if result.exchangeability_assumption != "baseline_candidate_relabeling":
        raise ValueError("historical evaluated randomization requires exchangeability")
    if result.analysis_method == "paired_cluster_permutation_exact":
        if (
            result.compared_clusters > _LEGACY_MAX_EXACT_PERMUTATION_CLUSTERS
            or not result.exhaustive
            or result.seed is not None
            or result.resamples != 1 << result.compared_clusters
        ):
            raise ValueError("historical exact randomization metadata is inconsistent")
    elif (
        result.exhaustive
        or result.seed is None
        or result.resamples != _LEGACY_MONTE_CARLO_RESAMPLES
    ):
        raise ValueError("historical Monte Carlo randomization metadata is inconsistent")
    _require_half_even_probability_lattice(
        result.p_value,
        resamples=result.resamples,
        owner="historical randomization result",
    )


def _validate_summary(summary: LiveGroupSummary, version: str, *, owner: str) -> None:
    _require_nested_version(summary, version, owner=owner)
    rates = (
        summary.exclusion_rate,
        summary.expectation_pass_rate,
        *summary.outcome_rates,
        *summary.reason_code_rates,
    )
    for index, rate in enumerate(rates):
        _require_nested_version(rate, version, owner=f"{owner} rate[{index}]")
        validate_legacy_live_rate(rate)
    for distribution_name, distribution in (
        ("latency_ms", summary.latency_ms),
        ("estimated_cost_usd", summary.estimated_cost_usd),
    ):
        _require_nested_version(
            distribution,
            version,
            owner=f"{owner} {distribution_name}",
        )
        validate_legacy_live_distribution(distribution)
    if summary.cluster_count != summary.expectation_pass_rate.cluster_count:
        raise ValueError(f"{owner} cluster_count does not match expectation_pass_rate")
    if (
        summary.effective_n != summary.expectation_pass_rate.effective_n
        or summary.design_effect != summary.expectation_pass_rate.design_effect
    ):
        raise ValueError(f"{owner} design metadata does not match expectation_pass_rate")


def _historical_group_id(observation: LiveObservationResult) -> str:
    """Reproduce the group identifier emitted by every v0.6.0-v0.6.5 writer."""

    return "|".join(
        (
            f"provider={observation.provider or 'unknown'}",
            f"model={observation.model or 'unknown'}",
            f"adapter={observation.adapter_id or 'unknown'}",
            f"pipeline={observation.pipeline_id or 'unknown'}",
        )
    )


def _historical_summary_identity(
    observations: tuple[LiveObservationResult, ...],
    *,
    overall: bool,
) -> dict[str, str | None]:
    fields = ("provider", "model", "adapter_id", "pipeline_id")
    if not observations:
        return {field: None for field in fields}
    if not overall:
        first = observations[0]
        return {field: getattr(first, field) for field in fields}
    identity: dict[str, str | None] = {}
    for field in fields:
        values = {getattr(observation, field) for observation in observations}
        identity[field] = next(iter(values)) if len(values) == 1 else None
    return identity


@with_live_decimal_context
def _require_observation_derived_rate(
    rate: LiveRate,
    *,
    label: str,
    values: tuple[tuple[LiveObservationResult, bool], ...],
    owner: str,
) -> None:
    denominator = len(values)
    numerator = sum(selected for _, selected in values)
    clustered: dict[str, list[int]] = {}
    for observation, selected in values:
        counts = clustered.setdefault(observation.cluster_id, [0, 0])
        counts[0] += int(selected)
        counts[1] += 1

    cluster_count = len(clustered)
    largest_cluster_size = max((counts[1] for counts in clustered.values()), default=0)
    if denominator:
        pooled_rate = _rate_string(numerator, denominator)
        cluster_mean_rate = decimal_string(
            sum(
                (Decimal(counts[0]) / Decimal(counts[1]) for counts in clustered.values()),
                Decimal("0"),
            )
            / Decimal(cluster_count)
        )
    else:
        pooled_rate = "0.000000"
        cluster_mean_rate = "0.000000"

    expected = {
        "label": label,
        "numerator": numerator,
        "denominator": denominator,
        "rate": pooled_rate,
        "cluster_count": cluster_count,
        "largest_cluster_size": largest_cluster_size,
        "cluster_mean_rate": cluster_mean_rate,
    }
    mismatches = [field for field, value in expected.items() if getattr(rate, field) != value]
    if mismatches:
        raise ValueError(
            f"{owner} does not match observation-derived {label} sufficient statistics: "
            f"{', '.join(mismatches)}"
        )


def _require_observation_derived_summary(
    summary: LiveGroupSummary,
    observations: tuple[LiveObservationResult, ...],
    *,
    owner: str,
    overall: bool,
) -> None:
    """Verify the historical summary fields recoverable from embedded observations.

    Historical observations do not persist the complete source RunSet. Outcome
    rates, latency/cost distributions, confidence-interval kernels, and protocol
    assumptions therefore remain non-confirmatory compatibility evidence. Counts,
    grouping, pooled rates, cluster means, and reason-code rates are fully
    recoverable and must agree exactly.
    """

    included = tuple(
        observation for observation in observations if observation.observation_status == "included"
    )
    excluded_count = len(observations) - len(included)
    expected_counts = {
        "observations": len(observations),
        "included_observations": len(included),
        "excluded_observations": excluded_count,
    }
    count_mismatches = [
        field for field, value in expected_counts.items() if getattr(summary, field) != value
    ]
    if count_mismatches:
        raise ValueError(
            f"{owner} counts do not match embedded observations: {', '.join(count_mismatches)}"
        )

    identity = _historical_summary_identity(observations, overall=overall)
    expected_identity = {
        "provider": identity["provider"],
        "model": identity["model"],
        "adapter_id": identity["adapter_id"],
        "pipeline_id": identity["pipeline_id"] or summary.group_id,
    }
    identity_mismatches = [
        field for field, value in expected_identity.items() if getattr(summary, field) != value
    ]
    if identity_mismatches:
        raise ValueError(
            f"{owner} identity does not match embedded observations: "
            f"{', '.join(identity_mismatches)}"
        )

    _require_observation_derived_rate(
        summary.exclusion_rate,
        label="exclusion",
        values=tuple(
            (observation, observation.observation_status == "excluded")
            for observation in observations
        ),
        owner=f"{owner} exclusion_rate",
    )
    _require_observation_derived_rate(
        summary.expectation_pass_rate,
        label="expectation_pass",
        values=tuple(
            (observation, observation.state is GateState.pass_) for observation in included
        ),
        owner=f"{owner} expectation_pass_rate",
    )

    expected_reason_codes = sorted(
        {reason_code.value for observation in included for reason_code in observation.reason_codes}
    )
    rates_by_label: dict[str, LiveRate] = {}
    for rate in summary.reason_code_rates:
        if rate.label in rates_by_label:
            raise ValueError(f"{owner} contains duplicate reason-code rate labels")
        rates_by_label[rate.label] = rate
    expected_labels = {f"reason_code:{reason_code}" for reason_code in expected_reason_codes}
    if set(rates_by_label) != expected_labels:
        raise ValueError(f"{owner} reason-code rate labels do not match embedded observations")
    for reason_code in expected_reason_codes:
        label = f"reason_code:{reason_code}"
        _require_observation_derived_rate(
            rates_by_label[label],
            label=label,
            values=tuple(
                (
                    observation,
                    any(item.value == reason_code for item in observation.reason_codes),
                )
                for observation in included
            ),
            owner=f"{owner} {label}",
        )


def _invariant_population(
    report: LiveEvaluationReport,
    invariant: StatisticalInvariantResult,
) -> tuple[LiveObservationResult, ...]:
    if invariant.endpoint_kind == "exclusion_rate":
        return tuple(report.observations)
    return tuple(
        observation
        for observation in report.observations
        if observation.observation_status == "included"
    )


def _require_report_invariant_derivation(
    report: LiveEvaluationReport,
    invariant: StatisticalInvariantResult,
    *,
    owner: str,
) -> None:
    population = _invariant_population(report, invariant)
    if invariant.denominator != len(population):
        raise ValueError(f"{owner} denominator does not match report observations")
    expected_clusters = len({observation.cluster_id for observation in population})
    if invariant.cluster_count != expected_clusters:
        raise ValueError(f"{owner} cluster_count does not match report observations")

    expected_numerator: int | None = None
    if invariant.endpoint_kind == "expectation_pass_rate":
        expected_numerator = sum(observation.state is GateState.pass_ for observation in population)
    elif invariant.endpoint_kind == "exclusion_rate":
        expected_numerator = sum(
            observation.observation_status == "excluded" for observation in population
        )
    elif invariant.endpoint_kind in {"reason_code_rate", "critical_event_rate"}:
        reason_codes = set(invariant.reason_codes)
        expected_numerator = sum(
            bool(reason_codes.intersection(observation.reason_codes)) for observation in population
        )
    if expected_numerator is not None and invariant.numerator != expected_numerator:
        raise ValueError(f"{owner} numerator does not match report observations")


def _base_report_state(report: LiveEvaluationReport) -> GateState:
    included = tuple(
        observation
        for observation in report.observations
        if observation.observation_status == "included"
    )
    if not included:
        return GateState.not_evaluated
    if any(observation.state is GateState.fail for observation in included):
        return GateState.fail
    if report.stop_reasons:
        return GateState.not_evaluated
    if any(observation.state is GateState.warn for observation in included):
        return GateState.warn
    if any(observation.state is GateState.not_evaluated for observation in included):
        return GateState.not_evaluated
    return GateState.pass_


def _validate_report_state(report: LiveEvaluationReport, version: str) -> None:
    included_count = sum(
        observation.observation_status == "included" for observation in report.observations
    )
    if included_count == 0:
        if version in _POST_BINDING_HARDENING_VERSIONS:
            raise ValueError(
                "historical report could not be produced without included observations"
            )
        if report.state is not GateState.not_evaluated:
            raise ValueError("historical empty report must be not_evaluated")
        return

    base_state = _base_report_state(report)
    exclusion_rate = Decimal(report.overall.exclusion_rate.rate)
    allowed_states = {base_state}
    if exclusion_rate > Decimal("0"):
        allowed_states.add(GateState.fail)
    if report.state not in allowed_states:
        raise ValueError("historical report state is impossible from observation-derived evidence")


def validate_legacy_live_evaluation_report(report: LiveEvaluationReport) -> None:
    version = _legacy_version(report, owner="live evaluation report")
    if version is None:
        return
    if not report.exploratory:
        raise ValueError("historical live evaluation reports must be exploratory")
    if report.stop_reasons and report.completion_status != "incomplete":
        raise ValueError("historical stopped live evaluation must be incomplete")
    expected_budget_exceeded = bool(_BUDGET_STOP_REASONS.intersection(report.stop_reasons))
    if report.budget_exceeded is not expected_budget_exceeded:
        raise ValueError("historical budget_exceeded does not match stop_reasons")

    for index, observation in enumerate(report.observations):
        _require_nested_version(
            observation,
            version,
            owner=f"historical observation[{index}]",
        )
    _validate_summary(report.overall, version, owner="historical overall summary")
    for index, group in enumerate(report.groups):
        _validate_summary(group, version, owner=f"historical group[{index}]")

    if report.overall.group_id != "overall":
        raise ValueError("historical overall summary must use group_id 'overall'")
    _require_observation_derived_summary(
        report.overall,
        tuple(report.observations),
        owner="historical overall summary",
        overall=True,
    )
    grouped_observations: dict[str, list[LiveObservationResult]] = {}
    for observation in report.observations:
        grouped_observations.setdefault(_historical_group_id(observation), []).append(observation)
    expected_group_ids = sorted(grouped_observations)
    actual_group_ids = [group.group_id for group in report.groups]
    if actual_group_ids != expected_group_ids:
        raise ValueError(
            "historical group summaries contain missing, duplicate, extra, or out-of-order "
            "group identifiers"
        )
    for group in report.groups:
        _require_observation_derived_summary(
            group,
            tuple(grouped_observations[group.group_id]),
            owner=f"historical group {group.group_id!r}",
            overall=False,
        )

    endpoint_ids: set[str] = set()
    multiplicity_methods: set[str] = set()
    primary_count = 0
    for index, invariant in enumerate(report.statistical_invariants):
        owner = f"historical statistical_invariants[{index}]"
        _require_nested_version(invariant, version, owner=owner)
        if invariant.endpoint_id in endpoint_ids:
            raise ValueError("historical live evaluation endpoint_id values must be unique")
        endpoint_ids.add(invariant.endpoint_id)
        multiplicity_methods.add(invariant.multiplicity_method)
        primary_count += invariant.role == "primary"
        _require_report_invariant_derivation(report, invariant, owner=owner)
    if report.statistical_invariants and primary_count != 1:
        raise ValueError("historical live evaluation requires exactly one primary invariant")
    if len(multiplicity_methods) > 1:
        raise ValueError("historical live evaluation invariants disagree on multiplicity")
    _validate_report_state(report, version)


@with_live_decimal_context
def _difference_matches(persisted: str, expected: Decimal) -> bool:
    return abs(Decimal(persisted) - expected) <= Decimal("0.000002")


def _validate_comparison_state(report: LiveComparisonReport, *, decision: Decimal) -> None:
    if report.state not in {GateState.fail, GateState.not_evaluated}:
        raise ValueError("historical exploratory comparison cannot claim pass or warn")
    boundary = -Decimal(report.non_inferiority_margin)
    lower = decision - _HALF_SIX_PLACES
    upper = decision + _HALF_SIX_PLACES
    nonzero_margin = Decimal(report.non_inferiority_margin) != Decimal("0")
    definitely_breached = upper < boundary or (nonzero_margin and upper <= boundary)
    definitely_not_breached = lower >= boundary if not nonzero_margin else lower > boundary
    if definitely_breached and report.state is not GateState.fail:
        raise ValueError("historical comparison state understates a non-inferiority breach")
    if definitely_not_breached and report.state is not GateState.not_evaluated:
        raise ValueError("historical comparison state claims an impossible breach")


@with_live_decimal_context
def validate_legacy_live_comparison_report(report: LiveComparisonReport) -> None:
    version = _legacy_version(report, owner="live comparison report")
    if version is None:
        return
    if not report.exploratory:
        raise ValueError("historical live comparisons must be exploratory")
    _require_nested_version(
        report.baseline_pass_rate,
        version,
        owner="historical baseline_pass_rate",
    )
    _require_nested_version(
        report.candidate_pass_rate,
        version,
        owner="historical candidate_pass_rate",
    )
    validate_legacy_live_rate(report.baseline_pass_rate)
    validate_legacy_live_rate(report.candidate_pass_rate)

    fixed_reference = report.baseline_mode == "fixed_reference"
    allowed_methods = (
        _FIXED_REFERENCE_COMPARISON_METHODS if fixed_reference else _CONCURRENT_COMPARISON_METHODS
    )
    if report.analysis_method not in allowed_methods:
        raise ValueError("historical baseline_mode and comparison method are inconsistent")
    expected_baseline_label = (
        "fixed_reference_expectation_pass" if fixed_reference else "expectation_pass"
    )
    if report.baseline_pass_rate.label != expected_baseline_label:
        raise ValueError("historical baseline rate label is inconsistent")
    if report.candidate_pass_rate.label != "expectation_pass":
        raise ValueError("historical candidate rate label is inconsistent")
    if fixed_reference:
        if report.fixed_reference_pass_rate != report.baseline_pass_rate.rate:
            raise ValueError("historical fixed reference does not match baseline rate")
    elif report.fixed_reference_pass_rate is not None:
        raise ValueError("historical concurrent comparison carries a fixed reference")

    if Decimal(report.difference_ci_lower) > Decimal(report.difference_ci_upper):
        raise ValueError("historical comparison confidence interval is reversed")
    if report.compared_clusters == 0:
        expected_difference = Decimal(report.candidate_pass_rate.rate) - Decimal(
            report.baseline_pass_rate.rate
        )
        if not _difference_matches(report.pass_rate_difference, expected_difference):
            raise ValueError("historical incomplete comparison difference is inconsistent")
        if not (
            report.difference_ci_lower == report.difference_ci_upper == report.pass_rate_difference
        ):
            raise ValueError("historical incomplete comparison interval must be a point")
        if report.effective_n != "0.000000" or report.randomization_tests:
            raise ValueError("historical zero-cluster comparison metadata is inconsistent")
        if report.state is not GateState.not_evaluated:
            raise ValueError("historical zero-cluster comparison must be not_evaluated")
        return

    if fixed_reference:
        if report.compared_clusters != report.candidate_pass_rate.cluster_count:
            raise ValueError("historical compared_clusters does not match candidate arm")
    elif report.compared_clusters != report.baseline_pass_rate.cluster_count or (
        report.compared_clusters != report.candidate_pass_rate.cluster_count
    ):
        raise ValueError("historical compared_clusters does not match paired arms")
    expected_difference = Decimal(report.candidate_pass_rate.cluster_mean_rate) - Decimal(
        report.baseline_pass_rate.cluster_mean_rate
    )
    if not _difference_matches(report.pass_rate_difference, expected_difference):
        raise ValueError("historical pass-rate difference is not candidate minus baseline")
    expected_effective_n = (
        Decimal(report.candidate_pass_rate.effective_n)
        if fixed_reference
        else min(
            Decimal(report.baseline_pass_rate.effective_n),
            Decimal(report.candidate_pass_rate.effective_n),
        )
    )
    if report.effective_n != decimal_string(expected_effective_n):
        raise ValueError("historical comparison effective_n is inconsistent with its arms")

    is_randomization = report.analysis_method in _PAIRED_RANDOMIZATION_METHODS
    expected_tests = int(is_randomization)
    if len(report.randomization_tests) != expected_tests:
        raise ValueError("historical randomization test cardinality is inconsistent")
    for test in report.randomization_tests:
        _require_nested_version(test, version, owner="historical randomization test")
        if (
            test.analysis_method != report.analysis_method
            or test.compared_clusters != report.compared_clusters
            or test.observed_difference != report.pass_rate_difference
            or test.non_inferiority_margin != report.non_inferiority_margin
        ):
            raise ValueError("historical randomization test does not match comparison")
    decision = (
        Decimal(report.pass_rate_difference)
        if is_randomization
        else Decimal(report.difference_ci_lower)
    )
    _validate_comparison_state(report, decision=decision)


def _historical_drift_series(
    diagnostic: DriftMetricDiagnostic,
    windows: tuple[DriftWindowSummary, ...],
) -> tuple[tuple[int, Decimal, int], ...]:
    rows: list[tuple[int, Decimal, int]] = []
    for window in windows:
        metric = next(
            (
                item
                for item in window.metrics
                if item.metric == diagnostic.metric and item.reason_codes == diagnostic.reason_codes
            ),
            None,
        )
        if metric is not None and metric.value is not None:
            rows.append((window.window_index, Decimal(metric.value), metric.denominator or 0))
    return tuple(rows)


@with_live_decimal_context
def _historical_drift_slope(values: tuple[tuple[int, Decimal, int], ...]) -> Decimal | None:
    """Replay the unweighted slope emitted by the v0.6.0-v0.6.5 writers."""

    if len(values) < 2:
        return None
    xs = tuple(Decimal(index) for index, _, _ in values)
    ys = tuple(value for _, value, _ in values)
    mean_x = mean_decimal(xs)
    mean_y = mean_decimal(ys)
    denominator = sum((value - mean_x) ** 2 for value in xs)
    if denominator == 0:
        return None
    return sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys, strict=True)) / denominator


@with_live_decimal_context
def _historical_lag1(values: tuple[Decimal, ...]) -> Decimal | None:
    if len(values) < 3:
        return None
    mean_value = mean_decimal(values)
    denominator = sum((value - mean_value) ** 2 for value in values)
    if denominator == 0:
        return None
    return (
        sum((left - mean_value) * (right - mean_value) for left, right in pairwise(values))
        / denominator
    )


@with_live_decimal_context
def _historical_ar1(
    values: tuple[Decimal, ...],
) -> tuple[Decimal | None, Decimal | None, Decimal | None]:
    if len(values) < 4:
        return None, None, None
    previous = values[:-1]
    current = values[1:]
    mean_previous = mean_decimal(previous)
    mean_current = mean_decimal(current)
    denominator = sum((value - mean_previous) ** 2 for value in previous)
    if denominator == 0:
        return None, None, None
    phi = (
        sum(
            (left - mean_previous) * (right - mean_current)
            for left, right in zip(previous, current, strict=True)
        )
        / denominator
    )
    phi = max(Decimal("-1"), min(Decimal("1"), phi))
    intercept = mean_current - phi * mean_previous
    residuals = tuple(
        right - (intercept + phi * left) for left, right in zip(previous, current, strict=True)
    )
    variance = mean_decimal(tuple(value * value for value in residuals))
    return phi, intercept, variance


def _historical_timestamp_bound(
    values: tuple[str, ...],
    *,
    pick: Literal["min", "max"],
) -> str | None:
    if not values:
        return None
    parsed: list[tuple[datetime, str]] = []
    for value in values:
        timestamp = parse_timestamp(value)
        if timestamp is None:
            return None
        parsed.append((timestamp, value))
    selected = min(parsed) if pick == "min" else max(parsed)
    return selected[1]


@with_live_decimal_context
def _validate_historical_state_estimate(
    diagnostic: DriftMetricDiagnostic,
    values: tuple[Decimal, ...],
) -> None:
    state = diagnostic.state_estimate
    if state is None:
        if len(values) < 6:
            return
        return
    if len(values) < 2:
        raise ValueError("historical EWMA state estimate has insufficient source windows")
    alpha = Decimal(state.smoothing_alpha)
    level = values[0]
    previous_level = level
    previous_smoothed = level
    residuals: list[Decimal] = []
    for value in values[1:]:
        residuals.append(value - previous_level)
        previous_smoothed = level
        level = alpha * value + (Decimal("1") - alpha) * level
        previous_level = level
    expected = (
        decimal_string(level),
        decimal_string(level - previous_smoothed),
        decimal_string(mean_decimal(tuple(value * value for value in residuals))),
    )
    actual = (
        state.latest_level,
        state.latest_drift_per_window,
        state.innovation_variance,
    )
    if actual != expected:
        raise ValueError("historical EWMA state estimate does not match window metrics")


@with_live_decimal_context
def validate_legacy_live_drift_report(report: LiveDriftReport) -> None:
    """Validate every historical drift conclusion recoverable from embedded evidence.

    Historical drift reports did not bind their plan or source reports. They are
    therefore accepted only as exploratory/internal-consistency evidence; claims
    that depend on the missing plan remain intentionally ineligible for ``valid``.
    """

    version = _legacy_version(report, owner="live drift report")
    if version is None:
        return
    if report.interpretation != "exploratory" or any(
        diagnostic.interpretation != "exploratory" for diagnostic in report.diagnostics
    ):
        raise ValueError("historical live drift reports are accepted only as exploratory")
    if report.monitoring_status == "valid":
        raise ValueError("historical live drift reports cannot claim valid monitoring")

    comparability = report.comparability
    windows = report.windows
    suite_matches = len({(item.suite_id, item.suite_version) for item in windows}) == 1 and all(
        item.suite_id == report.suite_id and item.suite_version == report.suite_version
        for item in windows
    )
    baseline_mode_matches = len({item.baseline_mode for item in windows}) == 1 and all(
        item.baseline_mode == comparability.baseline_mode for item in windows
    )
    analysis_method_matches = len({item.analysis_method for item in windows}) == 1 and all(
        item.analysis_method == comparability.analysis_method for item in windows
    )
    configuration_digest_matches = len({item.configuration_digest for item in windows}) == 1
    protocol_digest_matches = report.protocol_digest is not None and all(
        item.protocol_digest == report.protocol_digest for item in windows
    )
    expected_flags = (
        suite_matches,
        baseline_mode_matches,
        analysis_method_matches,
        configuration_digest_matches,
        protocol_digest_matches,
    )
    actual_flags = (
        comparability.suite_matches,
        comparability.baseline_mode_matches,
        comparability.analysis_method_matches,
        comparability.configuration_digest_matches,
        comparability.protocol_digest_matches,
    )
    if actual_flags != expected_flags:
        raise ValueError("historical drift comparability flags do not match source windows")
    if (
        comparability.reference_protocol_digest != report.protocol_digest
        or comparability.suite_id != report.suite_id
        or comparability.suite_version != report.suite_version
    ):
        raise ValueError("historical drift comparability reference does not match its report")
    if comparability.tool_schema_digest_matches and (
        not windows
        or any(len(item.tool_schema_digests) != 1 for item in windows)
        or len({item.tool_schema_digests for item in windows}) != 1
    ):
        raise ValueError("historical tool-schema comparability is not supported by its windows")
    if comparability.policy_bundle_digest_matches and (
        not windows
        or any(len(item.policy_bundle_digests) != 1 for item in windows)
        or len({item.policy_bundle_digests for item in windows}) != 1
    ):
        raise ValueError("historical policy-bundle comparability is not supported by its windows")
    if comparability.status == "pass" and not all(
        (*expected_flags, comparability.material_fields_match)
    ):
        raise ValueError("historical passing comparability is contradicted by its windows")

    starts = tuple(
        item.observation_window_start_utc
        for item in windows
        if item.observation_window_start_utc is not None
    )
    ends = tuple(
        item.observation_window_end_utc
        for item in windows
        if item.observation_window_end_utc is not None
    )
    if report.observation_window_start_utc != _historical_timestamp_bound(starts, pick="min"):
        raise ValueError("historical drift start timestamp does not match its windows")
    if report.observation_window_end_utc != _historical_timestamp_bound(ends, pick="max"):
        raise ValueError("historical drift end timestamp does not match its windows")

    for diagnostic in report.diagnostics:
        rows = _historical_drift_series(diagnostic, windows)
        values = tuple(value for _, value, _ in rows)
        slope = _historical_drift_slope(rows)
        expected_slope = decimal_string(slope) if slope is not None else None
        if diagnostic.slope_per_window != expected_slope:
            raise ValueError("historical drift slope does not match window metrics")
        if len(values) < 8 and any(
            item is not None
            for item in (
                diagnostic.lag1_autocorrelation,
                diagnostic.ar1_phi,
                diagnostic.ar1_intercept,
                diagnostic.ar1_innovation_variance,
            )
        ):
            raise ValueError("historical dependence statistics have insufficient windows")
        if diagnostic.lag1_autocorrelation is not None:
            lag1 = _historical_lag1(values)
            expected_lag1 = signed_unit_decimal_string(lag1) if lag1 is not None else None
            if diagnostic.lag1_autocorrelation != expected_lag1:
                raise ValueError("historical lag-1 statistic does not match window metrics")
        if diagnostic.ar1_phi is not None:
            phi, intercept, variance = _historical_ar1(values)
            expected_ar1 = (
                signed_unit_decimal_string(phi) if phi is not None else None,
                decimal_string(intercept) if intercept is not None else None,
                decimal_string(variance) if variance is not None else None,
            )
            actual_ar1 = (
                diagnostic.ar1_phi,
                diagnostic.ar1_intercept,
                diagnostic.ar1_innovation_variance,
            )
            if actual_ar1 != expected_ar1:
                raise ValueError("historical AR(1) statistics do not match window metrics")
        _validate_historical_state_estimate(diagnostic, values)
        if comparability.status == "invalid" or len(rows) < 2:
            if diagnostic.prerequisite_status != "invalid":
                raise ValueError("historical drift prerequisite status is overstated")
        elif diagnostic.prerequisite_status == "met" and any(
            denominator < 1 for _, _, denominator in rows
        ):
            raise ValueError("historical drift met prerequisites lack observations")

    expected_status = "invalid" if comparability.status == "invalid" else "exploratory"
    if report.monitoring_status != expected_status:
        raise ValueError("historical drift monitoring status overstates unbound evidence")


def _require_affected_superset(
    actual: tuple[str, ...],
    required: set[str],
    *,
    owner: str,
) -> None:
    if not required <= set(actual):
        raise ValueError(f"{owner} suppresses a recoverable historical finding")


def validate_legacy_live_trajectory_report(report: LiveTrajectoryReport) -> None:
    """Apply conservative replay to the facts retained by historical trajectories."""

    version = _legacy_version(report, owner="live trajectory report")
    if version is None:
        return
    if report.interpretation != "exploratory" or any(
        invariant.interpretation != "exploratory" for invariant in report.invariants
    ):
        raise ValueError("historical live trajectories are accepted only as exploratory")
    if report.trajectory_status == "valid":
        raise ValueError("historical live trajectories cannot claim valid status")
    if report.evaluation_report_id != f"{report.runset_id}:live-evaluation-report":
        raise ValueError("historical trajectory evaluation identity does not match its RunSet")

    missing_review = {
        path.observation_id
        for path in report.paths
        if path.human_review_required
        and not path.human_review_performed
        and "human_review" not in path.states
    }
    incomplete_claim_evidence = {
        path.observation_id
        for path in report.paths
        if path.claim_count > path.claim_evidence_link_count
    }
    emergency_paths = {path.observation_id for path in report.paths if "emergency" in path.states}
    checks = {item.check_id: item for item in report.history_dependent_checks}
    _require_affected_superset(
        checks["review-required-history"].affected_observation_ids,
        missing_review,
        owner="historical review-required history check",
    )
    _require_affected_superset(
        checks["claim-evidence-history"].affected_observation_ids,
        incomplete_claim_evidence,
        owner="historical claim-evidence history check",
    )
    for invariant in report.invariants:
        required: set[str] = set()
        if invariant.invariant_type == "required_review_for_approval":
            required = missing_review
        elif invariant.invariant_type == "claim_evidence_before_approval":
            required = incomplete_claim_evidence
        elif invariant.invariant_type == "forbidden_state":
            required = emergency_paths
        _require_affected_superset(
            invariant.affected_observation_ids,
            required,
            owner=f"historical trajectory invariant {invariant.invariant_id!r}",
        )

    processes = {item.event_type: item for item in report.event_processes}
    if processes["exclusion"].observed_events != report.excluded_observations:
        raise ValueError("historical exclusion events do not match excluded paths")
    if processes["emergency_process"].observed_events < len(emergency_paths):
        raise ValueError("historical emergency event process suppresses observed emergency paths")


__all__ = [
    "LEGACY_LIVE_SCHEMA_VERSIONS",
    "validate_legacy_cluster_correlation",
    "validate_legacy_live_comparison_report",
    "validate_legacy_live_drift_report",
    "validate_legacy_live_distribution",
    "validate_legacy_live_evaluation_report",
    "validate_legacy_live_rate",
    "validate_legacy_live_trajectory_report",
    "validate_legacy_randomization_test",
    "validate_legacy_rare_event_bound",
    "validate_legacy_statistical_invariant",
]
