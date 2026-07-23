from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol

from agent_assure.evaluation.evaluator import EvaluationReport
from agent_assure.schema.common import GateState, ReasonCode
from agent_assure.schema.evaluation import Finding


class FindingSelectorLike(Protocol):
    @property
    def control_id(self) -> str: ...

    @property
    def reason_code(self) -> ReasonCode: ...

    @property
    def target(self) -> str | None: ...


class RequiredFindingAlternativesLike(Protocol):
    @property
    def any_of(self) -> tuple[FindingSelectorLike, ...]: ...


class DetectionContractLike(Protocol):
    @property
    def required_findings(self) -> RequiredFindingAlternativesLike: ...

    @property
    def prohibited_substitutes(self) -> tuple[FindingSelectorLike, ...]: ...

    @property
    def expected_gate_effect(self) -> object: ...

    @property
    def secondary_findings_allowed(self) -> bool: ...


@dataclass(frozen=True)
class DetectionAssessment:
    state: str
    observed_findings: tuple[Finding, ...]
    matched_finding_ids: tuple[str, ...]
    limitations: tuple[str, ...]


def assess_expected_detection(
    source_report: EvaluationReport,
    candidate_report: EvaluationReport,
    contract: DetectionContractLike,
    *,
    expected_target: str,
) -> DetectionAssessment:
    """Classify only newly introduced findings against a normative contract."""
    source_findings, source_conflict = _canonical_findings(
        source_report.candidate_vs_expectations.findings
    )
    candidate_findings, candidate_conflict = _canonical_findings(
        candidate_report.candidate_vs_expectations.findings
    )
    source_by_id = {finding.finding_id: finding for finding in source_findings}
    candidate_by_id = {finding.finding_id: finding for finding in candidate_findings}
    cross_report_conflict = any(
        _finding_identity(source_finding) != _finding_identity(candidate_by_id[finding_id])
        for finding_id, source_finding in source_by_id.items()
        if finding_id in candidate_by_id
    )
    source_failed_ids, source_failed_projection_conflict = _gate_projection_ids(
        source_report.failed_controls,
        source_by_id,
        projection="failed",
    )
    source_warning_ids, source_warning_projection_conflict = _gate_projection_ids(
        source_report.warning_controls,
        source_by_id,
        projection="warning",
    )
    failed_ids, failed_projection_conflict = _gate_projection_ids(
        candidate_report.failed_controls,
        candidate_by_id,
        projection="failed",
    )
    warning_ids, warning_projection_conflict = _gate_projection_ids(
        candidate_report.warning_controls,
        candidate_by_id,
        projection="warning",
    )
    source_projection_overlap_conflict = _projection_overlap_is_invalid(
        source_failed_ids,
        source_warning_ids,
        source_by_id,
    )
    projection_overlap_conflict = _projection_overlap_is_invalid(
        failed_ids,
        warning_ids,
        candidate_by_id,
    )
    observed = tuple(
        finding
        for finding in candidate_findings
        if finding.finding_id not in source_by_id
    )
    if source_conflict or candidate_conflict or cross_report_conflict:
        return DetectionAssessment(
            state="invalid_operator",
            observed_findings=observed,
            matched_finding_ids=(),
            limitations=(
                "The evaluator reused a finding ID for conflicting semantic findings.",
            ),
        )
    if (
        source_failed_projection_conflict
        or source_warning_projection_conflict
        or source_projection_overlap_conflict
        or failed_projection_conflict
        or warning_projection_conflict
        or projection_overlap_conflict
    ):
        return DetectionAssessment(
            state="invalid_operator",
            observed_findings=observed,
            matched_finding_ids=(),
            limitations=(
                "The evaluator gate projections were inconsistent with candidate findings.",
            ),
        )
    required_matches = tuple(
        finding
        for finding in observed
        if finding.target == expected_target
        and any(
            _matches_selector(finding, selector)
            for selector in contract.required_findings.any_of
        )
    )
    prohibited = tuple(
        finding
        for finding in observed
        if any(
            _matches_selector(finding, selector)
            for selector in contract.prohibited_substitutes
        )
    )
    secondary = tuple(
        finding
        for finding in observed
        if finding not in required_matches and finding not in prohibited
    )
    if prohibited:
        return DetectionAssessment(
            state="invalid_operator",
            observed_findings=observed,
            matched_finding_ids=(),
            limitations=(
                "The mutation introduced a prohibited substitute finding, so its "
                "detector outcome is confounded.",
            ),
        )
    if secondary and not contract.secondary_findings_allowed:
        return DetectionAssessment(
            state="invalid_operator",
            observed_findings=observed,
            matched_finding_ids=(),
            limitations=(
                "The mutation introduced secondary findings that its detector contract forbids.",
            ),
        )
    if not required_matches:
        return DetectionAssessment(
            state="survived",
            observed_findings=observed,
            matched_finding_ids=(),
            limitations=(
                "The normative expected detector was not newly observed for the selected target.",
            ),
        )
    effect = _gate_effect_value(contract.expected_gate_effect)
    if effect not in {"block", "review", "informational", "ignore"}:
        return DetectionAssessment(
            state="invalid_operator",
            observed_findings=observed,
            matched_finding_ids=(),
            limitations=("The detector contract declared an unsupported gate effect.",),
        )
    effect_matches = tuple(
        finding
        for finding in required_matches
        if _has_gate_effect(
            finding.finding_id,
            effect=effect,
            failed_ids=failed_ids,
            warning_ids=warning_ids,
        )
    )
    if not effect_matches:
        return DetectionAssessment(
            state="survived",
            observed_findings=observed,
            matched_finding_ids=(),
            limitations=(
                "The normative detector was observed but did not produce its "
                f"declared {effect} gate effect.",
            ),
        )
    return DetectionAssessment(
        state="caught",
        observed_findings=observed,
        matched_finding_ids=tuple(finding.finding_id for finding in effect_matches),
        limitations=(
            "Detection is scoped to this deterministic operator, subject, suite, and gate profile.",
        ),
    )


def _matches_selector(finding: Finding, selector: FindingSelectorLike) -> bool:
    return (
        finding.control_id == selector.control_id
        and finding.reason_code is selector.reason_code
        and (selector.target is None or finding.target == selector.target)
    )


def _gate_effect_value(effect: object) -> str:
    value = getattr(effect, "value", effect)
    return str(value)


def _canonical_findings(findings: tuple[Finding, ...]) -> tuple[tuple[Finding, ...], bool]:
    by_id: dict[str, Finding] = {}
    conflict = False
    for finding in findings:
        existing = by_id.get(finding.finding_id)
        if existing is None:
            by_id[finding.finding_id] = finding
            continue
        if (
            _finding_identity(existing) != _finding_identity(finding)
            or existing.state is not finding.state
        ):
            conflict = True
        by_id[finding.finding_id] = min(existing, finding, key=_finding_order_key)
    return tuple(by_id[finding_id] for finding_id in sorted(by_id)), conflict


def _gate_projection_ids(
    findings: tuple[Finding, ...],
    candidate_by_id: dict[str, Finding],
    *,
    projection: Literal["failed", "warning"],
) -> tuple[frozenset[str], bool]:
    canonical, conflict = _canonical_findings(findings)
    for finding in canonical:
        candidate = candidate_by_id.get(finding.finding_id)
        if candidate is None or (
            _finding_identity(candidate) != _finding_identity(finding)
            or candidate.state is not finding.state
        ):
            conflict = True
        # Projection membership carries the active gate profile's decision. A
        # blocking projection may therefore contain fail, fail-on-warn, or
        # fail-on-not-evaluated states, but never pass. The warning projection
        # admits warnings and nonblocking failures only.
        if projection == "failed" and finding.state is GateState.pass_:
            conflict = True
        if projection == "warning" and finding.state not in {
            GateState.fail,
            GateState.warn,
        }:
            conflict = True
    return frozenset(finding.finding_id for finding in canonical), conflict


def _projection_overlap_is_invalid(
    failed_ids: frozenset[str],
    warning_ids: frozenset[str],
    candidate_by_id: dict[str, Finding],
) -> bool:
    # A warning can also be blocking under a fail-on-warn gate profile. A failed
    # finding cannot simultaneously be the report's nonblocking warning projection.
    return any(
        finding_id not in candidate_by_id
        or candidate_by_id[finding_id].state is not GateState.warn
        for finding_id in failed_ids & warning_ids
    )


def _finding_identity(finding: Finding) -> tuple[str, str, ReasonCode, str]:
    return (
        finding.case_id,
        finding.control_id,
        finding.reason_code,
        finding.target,
    )


def _finding_order_key(finding: Finding) -> tuple[str, str, str, str, str, str, str]:
    return (
        finding.finding_id,
        finding.case_id,
        finding.control_id,
        finding.reason_code.value,
        finding.target,
        finding.state.value,
        finding.message,
    )


def _has_gate_effect(
    finding_id: str,
    *,
    effect: str,
    failed_ids: frozenset[str],
    warning_ids: frozenset[str],
) -> bool:
    """Interpret v1 gate effects against EvaluationReport projections.

    Informational and ignored findings both have no gate projection in v1. Their
    semantic labels remain distinct for consumers, but neither may block or route
    review. Review is warning-only; block is authoritative failed membership.
    """
    if effect == "block":
        return finding_id in failed_ids
    if effect == "review":
        return finding_id in warning_ids and finding_id not in failed_ids
    if effect in {"informational", "ignore"}:
        return finding_id not in failed_ids and finding_id not in warning_ids
    return False
