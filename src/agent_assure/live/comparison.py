from __future__ import annotations

import json
from collections import defaultdict
from decimal import Decimal
from pathlib import Path

from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.live.intervals import difference_bootstrap_interval, difference_t_interval
from agent_assure.schema.common import GateState
from agent_assure.schema.live import (
    LiveComparisonReport,
    LiveEvaluationReport,
    LiveGroupSummary,
    LiveProtocolRecord,
    LiveRate,
)


def load_live_evaluation_report(path: Path) -> LiveEvaluationReport:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return LiveEvaluationReport.model_validate(payload)


def compare_live_reports(
    baseline: LiveEvaluationReport,
    candidate: LiveEvaluationReport,
    *,
    protocol: LiveProtocolRecord,
) -> LiveComparisonReport:
    _verify_report_binding(baseline, candidate, protocol)
    baseline_group = _group(baseline, protocol.baseline_group_id)
    candidate_group = _group(candidate, protocol.candidate_group_id)
    if protocol.baseline_mode == "fixed_reference":
        difference, lower, upper, compared_clusters = _fixed_reference_difference(
            candidate,
            protocol,
        )
        baseline_rate = _fixed_reference_rate(protocol)
    else:
        difference, lower, upper, compared_clusters = _paired_cluster_difference(
            baseline,
            candidate,
            protocol,
        )
        baseline_rate = baseline_group.expectation_pass_rate
    margin = Decimal(protocol.non_inferiority_margin)
    exploratory = _comparison_exploratory(protocol, compared_clusters)
    state = _comparison_state(lower, margin, compared_clusters, exploratory)
    return LiveComparisonReport(
        artifact_kind="live-comparison-report",
        baseline_runset_id=baseline.runset_id,
        candidate_runset_id=candidate.runset_id,
        suite_id=baseline.suite_id,
        suite_version=baseline.suite_version,
        baseline_group_id=protocol.baseline_group_id,
        candidate_group_id=protocol.candidate_group_id,
        protocol_id=protocol.protocol_id,
        protocol_digest=sha256_hexdigest(protocol.model_dump(mode="json")),
        baseline_mode=protocol.baseline_mode,
        analysis_method=protocol.analysis_method,
        exploratory=exploratory,
        state=state,
        confidence_level=candidate.confidence_level,
        non_inferiority_margin=_decimal(margin),
        baseline_pass_rate=baseline_rate,
        candidate_pass_rate=candidate_group.expectation_pass_rate,
        pass_rate_difference=_signed_decimal(difference),
        difference_ci_lower=_signed_decimal(lower),
        difference_ci_upper=_signed_decimal(upper),
        compared_clusters=compared_clusters,
        effective_n=_comparison_effective_n(baseline_group, candidate_group, protocol),
        fixed_reference_pass_rate=protocol.fixed_reference_pass_rate,
        latency_p50_difference_ms=_difference(
            candidate_group.latency_ms.p50,
            baseline_group.latency_ms.p50,
        ),
        cost_total_difference_usd=_difference(
            candidate_group.estimated_cost_usd.total,
            baseline_group.estimated_cost_usd.total,
        ),
        limitations=_comparison_limitations(
            protocol,
            compared_clusters,
            exploratory,
            difference,
            lower,
            upper,
        ),
    )


def _verify_report_binding(
    baseline: LiveEvaluationReport,
    candidate: LiveEvaluationReport,
    protocol: LiveProtocolRecord,
) -> None:
    if baseline.suite_id != candidate.suite_id:
        raise ValueError("live reports reference different suite_id values")
    if baseline.suite_version != candidate.suite_version:
        raise ValueError("live reports reference different suite_version values")
    protocol_digest = sha256_hexdigest(protocol.model_dump(mode="json"))
    for label, report in (("baseline", baseline), ("candidate", candidate)):
        if report.protocol_id != protocol.protocol_id or report.protocol_digest != protocol_digest:
            raise ValueError(f"{label} live report protocol binding does not match protocol")


def _paired_cluster_difference(
    baseline: LiveEvaluationReport,
    candidate: LiveEvaluationReport,
    protocol: LiveProtocolRecord,
) -> tuple[Decimal, Decimal, Decimal, int]:
    baseline_rates = _cluster_pass_rates(baseline, protocol.baseline_group_id)
    candidate_rates = _cluster_pass_rates(candidate, protocol.candidate_group_id)
    _validate_paired_cluster_sets(baseline_rates, candidate_rates)
    common_clusters = sorted(baseline_rates)
    differences = tuple(
        candidate_rates[cluster] - baseline_rates[cluster] for cluster in common_clusters
    )
    if protocol.analysis_method == "paired_cluster_bootstrap_percentile":
        return _bootstrap_difference_interval(differences, protocol)
    return _difference_interval(differences, protocol.confidence_level)


def _fixed_reference_difference(
    candidate: LiveEvaluationReport,
    protocol: LiveProtocolRecord,
) -> tuple[Decimal, Decimal, Decimal, int]:
    if protocol.fixed_reference_pass_rate is None:
        raise ValueError("fixed_reference protocol requires fixed_reference_pass_rate")
    reference = Decimal(protocol.fixed_reference_pass_rate)
    candidate_rates = _cluster_pass_rates(candidate, protocol.candidate_group_id)
    differences = tuple(rate - reference for rate in candidate_rates.values())
    return _difference_interval(differences, protocol.confidence_level)


def _difference_interval(
    differences: tuple[Decimal, ...],
    confidence_level: str,
) -> tuple[Decimal, Decimal, Decimal, int]:
    return difference_t_interval(differences, confidence_level)


def _bootstrap_difference_interval(
    differences: tuple[Decimal, ...],
    protocol: LiveProtocolRecord,
) -> tuple[Decimal, Decimal, Decimal, int]:
    return difference_bootstrap_interval(
        differences,
        confidence_level=protocol.confidence_level,
        seed=f"{protocol.protocol_id}:{protocol.analysis_digest}:paired_cluster_bootstrap",
    )


def _validate_paired_cluster_sets(
    baseline_rates: dict[str, Decimal],
    candidate_rates: dict[str, Decimal],
) -> None:
    baseline_only = sorted(set(baseline_rates) - set(candidate_rates))
    candidate_only = sorted(set(candidate_rates) - set(baseline_rates))
    if baseline_only or candidate_only:
        raise ValueError(
            "paired live comparison requires identical included cluster sets; "
            f"baseline_only={baseline_only or []}; candidate_only={candidate_only or []}"
        )


def _cluster_pass_rates(report: LiveEvaluationReport, group_id: str) -> dict[str, Decimal]:
    group = _group(report, group_id)
    if group.group_id == "overall":
        group_observations = report.observations
    else:
        group_observations = tuple(
            observation
            for observation in report.observations
            if _observation_group_id(observation) == group_id
        )
    counts: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for observation in group_observations:
        if observation.observation_status != "included":
            continue
        counts[observation.cluster_id][0] += int(observation.state is GateState.pass_)
        counts[observation.cluster_id][1] += 1
    return {
        cluster_id: Decimal(values[0]) / Decimal(values[1])
        for cluster_id, values in counts.items()
        if values[1] > 0
    }


def _observation_group_id(observation: object) -> str:
    provider = getattr(observation, "provider", None) or "unknown"
    model = getattr(observation, "model", None) or "unknown"
    adapter = getattr(observation, "adapter_id", None) or "unknown"
    pipeline = getattr(observation, "pipeline_id", None) or "unknown"
    return f"provider={provider}|model={model}|adapter={adapter}|pipeline={pipeline}"


def _fixed_reference_rate(protocol: LiveProtocolRecord) -> LiveRate:
    rate = protocol.fixed_reference_pass_rate or "0.000000"
    return LiveRate(
        artifact_kind="live-rate",
        label="fixed_reference_expectation_pass",
        numerator=0,
        denominator=0,
        cluster_count=0,
        effective_n="0.000000",
        design_effect="1.000000",
        largest_cluster_size=0,
        largest_cluster_design_effect="1.000000",
        largest_cluster_effective_n="0.000000",
        assumed_intraclass_correlation=protocol.assumed_intraclass_correlation,
        analysis_method="fixed_reference",
        exploratory=False,
        rate=rate,
        cluster_mean_rate=rate,
        interval_center="pooled_rate",
        interval_center_value=rate,
        confidence_level=protocol.confidence_level,
        ci_lower=rate,
        ci_upper=rate,
    )


def _group(report: LiveEvaluationReport, group_id: str) -> LiveGroupSummary:
    if group_id == "overall":
        return report.overall
    for group in report.groups:
        if group.group_id == group_id:
            return group
    known = ", ".join(["overall", *(group.group_id for group in report.groups)])
    raise KeyError(f"unknown live group {group_id!r}; expected one of: {known}")


def _difference(candidate: str | None, baseline: str | None) -> str | None:
    if candidate is None or baseline is None:
        return None
    return _signed_decimal(Decimal(candidate) - Decimal(baseline))


def _decimal(value: Decimal) -> str:
    quantized = value.quantize(Decimal("0.000001"))
    if quantized == Decimal("-0.000000"):
        quantized = Decimal("0.000000")
    return f"{quantized:f}"


def _signed_decimal(value: Decimal) -> str:
    return _decimal(max(Decimal("-1"), min(Decimal("1"), value)))


def _comparison_state(
    lower: Decimal,
    margin: Decimal,
    compared_clusters: int,
    exploratory: bool,
) -> GateState:
    if compared_clusters == 0:
        return GateState.not_evaluated
    if lower < -margin:
        return GateState.fail
    if exploratory:
        return GateState.not_evaluated
    return GateState.pass_


def _comparison_exploratory(protocol: LiveProtocolRecord, compared_clusters: int) -> bool:
    if compared_clusters < 30:
        return True
    if protocol.analysis_method == "exploratory":
        return True
    if (
        protocol.analysis_method == "paired_cluster_bootstrap_percentile"
        and compared_clusters < 50
    ):
        return True
    return False


def _comparison_effective_n(
    baseline_group: LiveGroupSummary,
    candidate_group: LiveGroupSummary,
    protocol: LiveProtocolRecord,
) -> str:
    if protocol.baseline_mode == "fixed_reference":
        return candidate_group.effective_n
    return _decimal(
        min(
            Decimal(baseline_group.effective_n),
            Decimal(candidate_group.effective_n),
        )
    )


def _comparison_limitations(
    protocol: LiveProtocolRecord,
    compared_clusters: int,
    exploratory: bool,
    difference: Decimal,
    lower: Decimal,
    upper: Decimal,
) -> tuple[str, ...]:
    limitations = [
        "live comparison intervals are descriptive unless the protocol predeclares the "
        "comparison as confirmatory",
    ]
    if compared_clusters > 1 and lower == upper == difference:
        limitations.append(
            "all compared cluster differences were identical; the empirical difference "
            "interval collapsed to zero width and should be interpreted as a degenerate "
            "descriptive interval"
        )
    if exploratory:
        if compared_clusters < 30:
            limitations.append(
                "fewer than 30 compared clusters makes this comparison exploratory"
            )
        elif protocol.analysis_method == "paired_cluster_bootstrap_percentile":
            limitations.append(
                "paired cluster percentile bootstrap requires at least 50 compared clusters "
                "for confirmatory interpretation"
            )
    return tuple(limitations)
