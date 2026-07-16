from __future__ import annotations

from dataclasses import dataclass

from agent_assure.schema.common import ComparisonClassification, GateState
from agent_assure.schema.comparison import ComparisonSummary
from agent_assure.schema.evaluation import EvaluationSummary
from agent_assure.schema.packet import EvidencePacket
from agent_assure.schema.run import AgentRunRecord, RunSet


@dataclass(frozen=True)
class MissingEvidenceLinkDiff:
    case_id: str
    claim_id: str
    baseline_evidence_refs: tuple[str, ...]
    candidate_evidence_refs: tuple[str, ...]


@dataclass(frozen=True)
class ReportVerdict:
    headline: str
    sentence: str


@dataclass(frozen=True)
class ProcessAffectedSummary:
    case_ids: tuple[str, ...]
    total_cases: int
    missing_link_count: int
    baseline_link_count: int
    unscoped_finding_count: int


@dataclass(frozen=True)
class EvidenceDiffPresentation:
    baseline_summary: EvaluationSummary
    candidate_summary: EvaluationSummary
    visible_state: str
    missing_links: tuple[MissingEvidenceLinkDiff, ...]
    ci_gate_result: str
    process_state: str
    affected_summary: ProcessAffectedSummary
    verdict: ReportVerdict


def build_evidence_diff_presentation(
    *,
    baseline: RunSet,
    candidate: RunSet,
    comparison_summary: ComparisonSummary,
    baseline_summary: EvaluationSummary | None,
    candidate_summary: EvaluationSummary | None,
    packet: EvidencePacket | None,
) -> EvidenceDiffPresentation:
    resolved_baseline_summary = _baseline_summary(comparison_summary, baseline_summary)
    resolved_candidate_summary = _candidate_summary(
        comparison_summary,
        candidate_summary,
        packet,
    )
    _validate_evidence_diff_inputs(
        baseline=baseline,
        candidate=candidate,
        comparison_summary=comparison_summary,
        baseline_summary=baseline_summary,
        candidate_summary=candidate_summary,
        packet=packet,
    )
    visible_state = _visible_output_equivalence(baseline, candidate)
    missing_links = _missing_evidence_link_diffs(baseline, candidate)
    ci_gate_result = _ci_gate_result(packet, resolved_candidate_summary, comparison_summary)
    process_state = _process_regression_state(
        resolved_candidate_summary,
        comparison_summary,
    )
    affected_summary = _process_affected_summary(
        baseline,
        candidate,
        resolved_candidate_summary,
        missing_links,
    )
    verdict = _report_verdict(
        visible_state=visible_state,
        process_state=process_state,
        ci_gate_result=ci_gate_result,
        comparison_summary=comparison_summary,
        affected_summary=affected_summary,
    )
    return EvidenceDiffPresentation(
        baseline_summary=resolved_baseline_summary,
        candidate_summary=resolved_candidate_summary,
        visible_state=visible_state,
        missing_links=missing_links,
        ci_gate_result=ci_gate_result,
        process_state=process_state,
        affected_summary=affected_summary,
        verdict=verdict,
    )


def _validate_evidence_diff_inputs(
    *,
    baseline: RunSet,
    candidate: RunSet,
    comparison_summary: ComparisonSummary,
    baseline_summary: EvaluationSummary | None,
    candidate_summary: EvaluationSummary | None,
    packet: EvidencePacket | None,
) -> None:
    errors: list[str] = []
    _require_equal(
        errors,
        "baseline.runset_id",
        baseline.runset_id,
        "comparison.baseline_runset_id",
        comparison_summary.baseline_runset_id,
    )
    _require_equal(
        errors,
        "candidate.runset_id",
        candidate.runset_id,
        "comparison.candidate_runset_id",
        comparison_summary.candidate_runset_id,
    )
    _require_privacy_profile_equal(
        errors,
        "baseline",
        baseline.privacy_profile_id,
        baseline.privacy_profile_digest,
        "candidate",
        candidate.privacy_profile_id,
        candidate.privacy_profile_digest,
    )
    _require_privacy_profile_equal(
        errors,
        "baseline",
        baseline.privacy_profile_id,
        baseline.privacy_profile_digest,
        "comparison",
        comparison_summary.privacy_profile_id,
        comparison_summary.privacy_profile_digest,
    )
    _require_no_duplicate_cases(errors, "baseline", baseline)
    _require_no_duplicate_cases(errors, "candidate", candidate)
    if baseline_summary is not None:
        _require_privacy_profile_equal(
            errors,
            "baseline_summary",
            baseline_summary.privacy_profile_id,
            baseline_summary.privacy_profile_digest,
            "comparison",
            comparison_summary.privacy_profile_id,
            comparison_summary.privacy_profile_digest,
        )
        _require_equal(
            errors,
            "baseline_summary.runset_id",
            baseline_summary.runset_id,
            "baseline.runset_id",
            baseline.runset_id,
        )
        _require_state_equal(
            errors,
            "baseline_summary.state",
            baseline_summary.state,
            "comparison.baseline_state",
            comparison_summary.baseline_state,
        )
    if candidate_summary is not None:
        _require_privacy_profile_equal(
            errors,
            "candidate_summary",
            candidate_summary.privacy_profile_id,
            candidate_summary.privacy_profile_digest,
            "comparison",
            comparison_summary.privacy_profile_id,
            comparison_summary.privacy_profile_digest,
        )
        _require_equal(
            errors,
            "candidate_summary.runset_id",
            candidate_summary.runset_id,
            "candidate.runset_id",
            candidate.runset_id,
        )
        _require_state_equal(
            errors,
            "candidate_summary.state",
            candidate_summary.state,
            "comparison.candidate_state",
            comparison_summary.candidate_state,
        )
    if packet is not None:
        _require_privacy_profile_equal(
            errors,
            "packet.evaluation",
            packet.evaluation.privacy_profile_id,
            packet.evaluation.privacy_profile_digest,
            "comparison",
            comparison_summary.privacy_profile_id,
            comparison_summary.privacy_profile_digest,
        )
        _require_equal(
            errors,
            "packet.evaluation.runset_id",
            packet.evaluation.runset_id,
            "candidate.runset_id",
            candidate.runset_id,
        )
        _require_state_equal(
            errors,
            "packet.evaluation.state",
            packet.evaluation.state,
            "comparison.candidate_state",
            comparison_summary.candidate_state,
        )
        if candidate_summary is not None and not _same_evaluation_summary(
            packet.evaluation,
            candidate_summary,
        ):
            errors.append("packet.evaluation does not match candidate summary")
        if packet.comparison is not None and not _same_comparison_summary(
            packet.comparison,
            comparison_summary,
        ):
            errors.append("packet.comparison does not match comparison summary")
    if errors:
        raise ValueError(
            "evidence-diff artifact inputs are inconsistent: " + "; ".join(errors)
        )


def _require_equal(
    errors: list[str],
    left_label: str,
    left_value: object,
    right_label: str,
    right_value: object,
) -> None:
    if left_value != right_value:
        errors.append(f"{left_label}={left_value!r} does not match {right_label}={right_value!r}")


def _require_privacy_profile_equal(
    errors: list[str],
    left_label: str,
    left_id: str | None,
    left_digest: str | None,
    right_label: str,
    right_id: str | None,
    right_digest: str | None,
) -> None:
    left = (left_id, left_digest)
    right = (right_id, right_digest)
    if left != right:
        errors.append(
            f"{left_label}.privacy_profile={left!r} does not match "
            f"{right_label}.privacy_profile={right!r}"
        )


def _require_state_equal(
    errors: list[str],
    left_label: str,
    left_value: GateState,
    right_label: str,
    right_value: GateState,
) -> None:
    if left_value != right_value:
        errors.append(
            f"{left_label}={left_value.value!r} does not match "
            f"{right_label}={right_value.value!r}"
        )


def _require_no_duplicate_cases(errors: list[str], label: str, runset: RunSet) -> None:
    duplicates = _duplicate_case_ids(runset)
    if duplicates:
        errors.append(f"{label} run set has duplicate case_id values: {', '.join(duplicates)}")


def _duplicate_case_ids(runset: RunSet) -> tuple[str, ...]:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for run in runset.runs:
        if run.case_id in seen:
            duplicates.add(run.case_id)
        seen.add(run.case_id)
    return tuple(sorted(duplicates))


def _same_evaluation_summary(left: EvaluationSummary, right: EvaluationSummary) -> bool:
    return _without_environment(left) == _without_environment(right)


def _same_comparison_summary(left: ComparisonSummary, right: ComparisonSummary) -> bool:
    return _without_environment(left) == _without_environment(right)


def _without_environment(model: EvaluationSummary | ComparisonSummary) -> dict[str, object]:
    return model.model_dump(mode="json", exclude={"environment"})


def _baseline_summary(
    comparison_summary: ComparisonSummary,
    baseline_summary: EvaluationSummary | None,
) -> EvaluationSummary:
    if baseline_summary is not None:
        return baseline_summary
    return EvaluationSummary(
        runset_id=comparison_summary.baseline_runset_id,
        privacy_profile_id=comparison_summary.privacy_profile_id,
        privacy_profile_digest=comparison_summary.privacy_profile_digest,
        state=comparison_summary.baseline_state,
    )


def _candidate_summary(
    comparison_summary: ComparisonSummary,
    candidate_summary: EvaluationSummary | None,
    packet: EvidencePacket | None,
) -> EvaluationSummary:
    if candidate_summary is not None:
        return candidate_summary
    if (
        packet is not None
        and packet.evaluation.runset_id == comparison_summary.candidate_runset_id
    ):
        return packet.evaluation
    return EvaluationSummary(
        runset_id=comparison_summary.candidate_runset_id,
        privacy_profile_id=comparison_summary.privacy_profile_id,
        privacy_profile_digest=comparison_summary.privacy_profile_digest,
        state=comparison_summary.candidate_state,
    )


def _report_verdict(
    *,
    visible_state: str,
    process_state: str,
    ci_gate_result: str,
    comparison_summary: ComparisonSummary,
    affected_summary: ProcessAffectedSummary,
) -> ReportVerdict:
    if (
        visible_state == GateState.not_evaluated.value
        or comparison_summary.classification is ComparisonClassification.not_evaluated
    ):
        return ReportVerdict(
            headline="Evidence Diff Not Evaluated",
            sentence=(
                "This artifact did not have enough evaluated baseline and "
                "candidate evidence to classify the change."
            ),
        )
    if visible_state == "changed":
        return ReportVerdict(
            headline="Decision Fields Changed",
            sentence=(
                "The candidate changed visible recommendation or outcome fields; "
                "process evidence should be reviewed before release."
            ),
        )
    if process_state in {"caught", "observed"}:
        affected = len(affected_summary.case_ids)
        link_count = affected_summary.missing_link_count
        if ci_gate_result == "blocked":
            headline = "CI Gate Blocked Candidate Regression"
            gate_phrase = "the CI gate blocked the candidate as designed"
        elif ci_gate_result == "not provided":
            headline = "Process Regression Detected"
            gate_phrase = "no evidence packet was provided for a CI-gate result"
        else:
            headline = "Process Regression Detected"
            gate_phrase = "the CI gate did not block this artifact"
        if link_count:
            sentence = (
                "Decision fields were preserved, but the candidate dropped "
                f"{link_count} required material-claim evidence link"
                f"{'' if link_count == 1 else 's'} across {affected} process-affected "
                f"case{'' if affected == 1 else 's'}; {gate_phrase}."
            )
        else:
            scope_phrase = _process_finding_scope_phrase(affected_summary)
            sentence = (
                "Decision fields were preserved, but process invariant findings were "
                f"recorded {scope_phrase}; {gate_phrase}."
            )
        return ReportVerdict(headline=headline, sentence=sentence)
    if ci_gate_result == "not provided":
        return ReportVerdict(
            headline="Evidence Diff Ready For Review",
            sentence=(
                "Decision fields were preserved and no process regression was "
                "observed, but no evidence packet was provided for a CI-gate result."
            ),
        )
    return ReportVerdict(
        headline="No Process Regression Detected",
        sentence=(
            "Decision fields were preserved and no candidate process invariant "
            "regression was observed in this artifact."
        ),
    )


def _process_affected_summary(
    baseline: RunSet,
    candidate: RunSet,
    candidate_summary: EvaluationSummary,
    missing_links: tuple[MissingEvidenceLinkDiff, ...],
) -> ProcessAffectedSummary:
    affected_case_ids = {
        finding.case_id for finding in candidate_summary.findings if finding.case_id
    }
    unscoped_finding_count = sum(
        1 for finding in candidate_summary.findings if not finding.case_id
    )
    affected_case_ids.update(diff.case_id for diff in missing_links)
    total_cases = len(
        {run.case_id for run in baseline.runs} | {run.case_id for run in candidate.runs}
    )
    baseline_link_count = sum(len(_linked_claim_evidence(run)) for run in baseline.runs)
    return ProcessAffectedSummary(
        case_ids=tuple(sorted(affected_case_ids)),
        total_cases=total_cases,
        missing_link_count=len(missing_links),
        baseline_link_count=baseline_link_count,
        unscoped_finding_count=unscoped_finding_count,
    )


def _process_finding_scope_phrase(summary: ProcessAffectedSummary) -> str:
    affected = len(summary.case_ids)
    unscoped = summary.unscoped_finding_count
    if affected and unscoped:
        return (
            f"across {affected} process-affected case"
            f"{'' if affected == 1 else 's'} plus {unscoped} unscoped "
            f"finding{'' if unscoped == 1 else 's'}"
        )
    if affected:
        return (
            f"across {affected} process-affected case"
            f"{'' if affected == 1 else 's'}"
        )
    if unscoped:
        return (
            f"without case IDs ({unscoped} unscoped finding"
            f"{'' if unscoped == 1 else 's'})"
        )
    return "without process-affected case IDs"


def _visible_output_equivalence(baseline: RunSet, candidate: RunSet) -> str:
    baseline_case_ids = {run.case_id for run in baseline.runs}
    candidate_case_ids = {run.case_id for run in candidate.runs}
    if not baseline_case_ids and not candidate_case_ids:
        return GateState.not_evaluated.value
    if baseline_case_ids != candidate_case_ids:
        return "changed"
    pairs = _paired_runs(baseline, candidate)
    if not pairs:
        return GateState.not_evaluated.value
    if all(_visible_output(base) == _visible_output(cand) for base, cand in pairs):
        return "preserved"
    return "changed"


def _paired_runs(
    baseline: RunSet,
    candidate: RunSet,
) -> tuple[tuple[AgentRunRecord, AgentRunRecord], ...]:
    candidate_by_case = {run.case_id: run for run in candidate.runs}
    return tuple(
        (run, candidate_by_case[run.case_id])
        for run in baseline.runs
        if run.case_id in candidate_by_case
    )


def _visible_output(run: AgentRunRecord) -> tuple[str, str]:
    return run.recommendation, run.outcome


def _visible_output_state(
    baseline: AgentRunRecord | None,
    candidate: AgentRunRecord | None,
) -> str:
    if baseline is None or candidate is None:
        return "changed"
    if _visible_output(baseline) == _visible_output(candidate):
        return "preserved"
    return "changed"


def _missing_evidence_link_diffs(
    baseline: RunSet,
    candidate: RunSet,
) -> tuple[MissingEvidenceLinkDiff, ...]:
    missing: list[MissingEvidenceLinkDiff] = []
    for base, cand in _paired_runs(baseline, candidate):
        baseline_links = _linked_claim_evidence(base)
        candidate_links = _linked_claim_evidence(cand)
        for claim_id in sorted(set(baseline_links) - set(candidate_links)):
            missing.append(
                MissingEvidenceLinkDiff(
                    case_id=base.case_id,
                    claim_id=claim_id,
                    baseline_evidence_refs=baseline_links[claim_id],
                    candidate_evidence_refs=candidate_links.get(claim_id, ()),
                )
            )
    return tuple(missing)


def _linked_claim_evidence(run: AgentRunRecord) -> dict[str, tuple[str, ...]]:
    links: dict[str, set[str]] = {}
    present_items = {item.ref_id for item in run.evidence_items}
    for link in run.claim_evidence_links:
        if link.evidence_ref_id in present_items:
            links.setdefault(link.claim_id, set()).add(link.evidence_ref_id)
    return {claim_id: tuple(sorted(refs)) for claim_id, refs in sorted(links.items())}


def _process_regression_state(
    candidate_summary: EvaluationSummary,
    comparison_summary: ComparisonSummary,
) -> str:
    if (
        candidate_summary.state is GateState.fail
        or comparison_summary.classification is ComparisonClassification.new_failure
    ):
        return "caught"
    if candidate_summary.findings:
        return "observed"
    return "not observed"


def _ci_gate_result(
    packet: EvidencePacket | None,
    candidate_summary: EvaluationSummary,
    comparison_summary: ComparisonSummary,
) -> str:
    if packet is None:
        return "not provided"
    if (
        packet.evaluation.state is GateState.fail
        or candidate_summary.state is GateState.fail
        or comparison_summary.classification
        in {
            ComparisonClassification.new_failure,
            ComparisonClassification.invalid_comparison,
        }
    ):
        return "blocked"
    return "not blocked"
