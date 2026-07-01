from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from html import escape
from pathlib import Path, PurePosixPath, PureWindowsPath

from agent_assure.privacy.redaction import redact_text
from agent_assure.schema.common import ComparisonClassification, GateState
from agent_assure.schema.comparison import ComparisonSummary
from agent_assure.schema.evaluation import EvaluationSummary, Finding
from agent_assure.schema.packet import EvidencePacket
from agent_assure.schema.run import AgentRunRecord, RunSet

THESIS_TITLE = "Output equivalence is not process equivalence"
MAX_INLINE_ITEMS = 4
MAX_INLINE_VALUE_CHARS = 96
CLAIM_BOUNDARY_SENTENCES = (
    "This report is not a compliance attestation.",
    "This artifact does not certify safety.",
)
DISPLAY_SAFETY_NOTE = (
    "Display note: external URLs and sensitive-looking values may be redacted in this HTML; "
    "source artifacts remain unchanged."
)

PathValue = str | Path
_EXTERNAL_URL_PATTERN = re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE)


@dataclass(frozen=True)
class MissingEvidenceLinkDiff:
    case_id: str
    claim_id: str
    baseline_evidence_refs: tuple[str, ...]
    candidate_evidence_refs: tuple[str, ...]


def write_evidence_diff_html(
    *,
    baseline: RunSet,
    candidate: RunSet,
    comparison_summary: ComparisonSummary,
    out: Path,
    baseline_summary: EvaluationSummary | None = None,
    candidate_summary: EvaluationSummary | None = None,
    packet: EvidencePacket | None = None,
    title: str = THESIS_TITLE,
    artifact_paths: Mapping[str, PathValue] | None = None,
) -> Path:
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        render_evidence_diff_html(
            baseline=baseline,
            candidate=candidate,
            comparison_summary=comparison_summary,
            baseline_summary=baseline_summary,
            candidate_summary=candidate_summary,
            packet=packet,
            title=title,
            artifact_paths=artifact_paths,
        ),
        encoding="utf-8",
        newline="\n",
    )
    return out


def render_evidence_diff_html(
    *,
    baseline: RunSet,
    candidate: RunSet,
    comparison_summary: ComparisonSummary,
    baseline_summary: EvaluationSummary | None = None,
    candidate_summary: EvaluationSummary | None = None,
    packet: EvidencePacket | None = None,
    title: str = THESIS_TITLE,
    artifact_paths: Mapping[str, PathValue] | None = None,
) -> str:
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

    return "\n".join(
        (
            "<!doctype html>",
            '<html lang="en">',
            "<head>",
            '<meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            f"<title>{_h(_document_title(title))}</title>",
            "<style>",
            _css(),
            "</style>",
            "</head>",
            "<body>",
            "<main>",
            f"<h1>{_h(THESIS_TITLE)}</h1>",
            _subtitle(title),
            _punchline_section(
                visible_state=visible_state,
                candidate_summary=resolved_candidate_summary,
                comparison_summary=comparison_summary,
                ci_gate_result=ci_gate_result,
                missing_links=missing_links,
            ),
            _claim_boundary_section(),
            _final_output_section(
                baseline,
                candidate,
                visible_state,
                resolved_baseline_summary,
                resolved_candidate_summary,
            ),
            _process_evidence_section("baseline-process", "Baseline Process Evidence", baseline),
            _process_evidence_section(
                "candidate-process",
                "Candidate Process Evidence",
                candidate,
            ),
            _missing_evidence_section(missing_links),
            _findings_section(resolved_candidate_summary.findings),
            _comparison_section(comparison_summary),
            _fixture_equivalence_section(comparison_summary),
            _ci_gate_section(ci_gate_result, packet),
            _artifact_paths_section(artifact_paths),
            _artifact_digests_section(packet),
            "</main>",
            "</body>",
            "</html>",
            "",
        )
    )


def _document_title(title: str) -> str:
    if title == THESIS_TITLE:
        return THESIS_TITLE
    return f"{title} - {THESIS_TITLE}"


def _subtitle(title: str) -> str:
    if title == THESIS_TITLE:
        return ""
    return f'<p class="subtitle">{_h(title)}</p>'


def _punchline_section(
    *,
    visible_state: str,
    candidate_summary: EvaluationSummary,
    comparison_summary: ComparisonSummary,
    ci_gate_result: str,
    missing_links: tuple[MissingEvidenceLinkDiff, ...],
) -> str:
    process_state = _process_regression_state(candidate_summary, comparison_summary)
    missing_summary = _missing_link_summary(missing_links)
    return "\n".join(
        (
            '<section class="hero" aria-labelledby="review-punchline">',
            '<h2 id="review-punchline">Review Punchline</h2>',
            '<div class="signal-grid">',
            _signal("Final-output equivalence", visible_state),
            _signal("Process regression", process_state),
            _signal("CI gate result", ci_gate_result),
            "</div>",
            f"<p>{_h(missing_summary)}</p>",
            "</section>",
        )
    )


def _claim_boundary_section() -> str:
    limitation_lines = "\n\n".join(
        f"<p>{_h(sentence)}</p>"
        for sentence in (*CLAIM_BOUNDARY_SENTENCES, DISPLAY_SAFETY_NOTE)
    )
    return "\n".join(
        (
            '<section aria-labelledby="claim-boundary">',
            '<h2 id="claim-boundary">Claim Boundary</h2>',
            "",
            limitation_lines,
            "",
            "</section>",
        )
    )


def _final_output_section(
    baseline: RunSet,
    candidate: RunSet,
    visible_state: str,
    baseline_summary: EvaluationSummary,
    candidate_summary: EvaluationSummary,
) -> str:
    rows = "\n".join(_visible_output_rows(baseline, candidate))
    return "\n".join(
        (
            '<section aria-labelledby="final-output-comparison">',
            '<h2 id="final-output-comparison">Final-Output Comparison</h2>',
            "<dl>",
            _detail("Visible output equivalence", visible_state),
            _detail("Case coverage", _case_coverage(baseline, candidate)),
            _detail("Baseline evaluation state", baseline_summary.state.value),
            _detail("Candidate evaluation state", candidate_summary.state.value),
            "</dl>",
            "<table>",
            "<thead><tr>"
            "<th>Case</th><th>Baseline recommendation</th><th>Candidate recommendation</th>"
            "<th>Baseline outcome</th><th>Candidate outcome</th><th>Equivalence</th>"
            "</tr></thead>",
            f"<tbody>{rows}</tbody>",
            "</table>",
            "</section>",
        )
    )


def _process_evidence_section(section_id: str, heading: str, runset: RunSet) -> str:
    rows = "\n".join(_process_evidence_row(run) for run in sorted(runset.runs, key=_case_key))
    body = rows or '<tr><td colspan="8" class="empty">No runs were recorded.</td></tr>'
    return "\n".join(
        (
            f'<section aria-labelledby="{_h(section_id)}">',
            f'<h2 id="{_h(section_id)}">{_h(heading)}</h2>',
            "<table>",
            "<thead><tr>"
            "<th>Case</th><th>Claims</th><th>Evidence refs</th><th>Linked claims</th>"
            "<th>Policy states</th><th>Human review</th><th>Provider/model</th><th>Tools</th>"
            "</tr></thead>",
            f"<tbody>{body}</tbody>",
            "</table>",
            "</section>",
        )
    )


def _missing_evidence_section(missing_links: tuple[MissingEvidenceLinkDiff, ...]) -> str:
    rows = "\n".join(_missing_link_row(diff) for diff in missing_links)
    body = (
        rows
        if rows
        else '<tr><td colspan="4" class="empty">No missing evidence links were observed.</td></tr>'
    )
    return "\n".join(
        (
            '<section aria-labelledby="missing-evidence-link-diff">',
            '<h2 id="missing-evidence-link-diff">Missing Evidence Link Diff</h2>',
            "<table>",
            "<thead><tr>"
            "<th>Case</th><th>Claim</th><th>Baseline evidence refs</th>"
            "<th>Candidate evidence refs</th>"
            "</tr></thead>",
            f"<tbody>{body}</tbody>",
            "</table>",
            "</section>",
        )
    )


def _findings_section(findings: tuple[Finding, ...]) -> str:
    rows = "\n".join(_finding_row(finding) for finding in findings)
    body = (
        rows
        if rows
        else (
            '<tr><td colspan="6" class="empty">'
            "No process invariant findings were recorded.</td></tr>"
        )
    )
    return "\n".join(
        (
            '<section aria-labelledby="process-invariant-findings">',
            '<h2 id="process-invariant-findings">Process Invariant Findings</h2>',
            "<table>",
            "<thead><tr><th>Case</th><th>Control</th><th>Target</th>"
            "<th>Reason code</th><th>State</th><th>Message</th></tr></thead>",
            f"<tbody>{body}</tbody>",
            "</table>",
            "</section>",
        )
    )


def _comparison_section(comparison_summary: ComparisonSummary) -> str:
    return "\n".join(
        (
            '<section aria-labelledby="comparison-classification">',
            '<h2 id="comparison-classification">Comparison Classification</h2>',
            "<dl>",
            _detail("Classification", comparison_summary.classification.value),
            _detail("Baseline state", comparison_summary.baseline_state.value),
            _detail("Candidate state", comparison_summary.candidate_state.value),
            _detail(
                "Provenance changes",
                _summarized_values(comparison_summary.provenance_changes, empty="none"),
            ),
            _detail(
                "Verdict findings",
                _summarized_values(comparison_summary.verdict_findings, empty="none"),
            ),
            "</dl>",
            "</section>",
        )
    )


def _fixture_equivalence_section(comparison_summary: ComparisonSummary) -> str:
    return "\n".join(
        (
            '<section aria-labelledby="fixture-equivalence-state">',
            '<h2 id="fixture-equivalence-state">Fixture-Equivalence State</h2>',
            "<dl>",
            _detail("State", comparison_summary.fixture_equivalence_state.value),
            _detail(
                "Review note",
                _fixture_equivalence_note(comparison_summary.fixture_equivalence_state),
            ),
            "</dl>",
            "</section>",
        )
    )


def _ci_gate_section(ci_gate_result: str, packet: EvidencePacket | None) -> str:
    packet_id = packet.packet_id if packet is not None else "not provided"
    limitations = _summarized_values(packet.limitations if packet is not None else (), empty="none")
    return "\n".join(
        (
            '<section aria-labelledby="ci-gate-result">',
            '<h2 id="ci-gate-result">CI Gate Result</h2>',
            "<dl>",
            _detail("Result", ci_gate_result),
            _detail("Evidence packet", packet_id),
            _detail("Packet limitations", limitations),
            "</dl>",
            "</section>",
        )
    )


def _artifact_paths_section(artifact_paths: Mapping[str, PathValue] | None) -> str:
    rows = "\n".join(
        _artifact_path_row(label, value)
        for label, value in sorted((artifact_paths or {}).items(), key=lambda item: item[0])
        if str(value)
    )
    body = rows or '<tr><td colspan="2" class="empty">No artifact paths were provided.</td></tr>'
    return "\n".join(
        (
            '<section aria-labelledby="artifact-paths">',
            '<h2 id="artifact-paths">Artifact Paths</h2>',
            "<table>",
            "<thead><tr><th>Artifact</th><th>Path</th></tr></thead>",
            f"<tbody>{body}</tbody>",
            "</table>",
            "</section>",
        )
    )


def _artifact_digests_section(packet: EvidencePacket | None) -> str:
    rows = "\n".join(_artifact_digest_rows(packet))
    body = rows or (
        '<tr><td colspan="3" class="empty">'
        "No packet artifact digests were provided.</td></tr>"
    )
    return "\n".join(
        (
            '<section aria-labelledby="artifact-digests">',
            '<h2 id="artifact-digests">Artifact Digests</h2>',
            "<table>",
            "<thead><tr><th>Role</th><th>Path</th><th>SHA-256</th></tr></thead>",
            f"<tbody>{body}</tbody>",
            "</table>",
            "</section>",
        )
    )


def _css() -> str:
    return """
:root {
  color-scheme: light;
  font-family: Arial, Helvetica, sans-serif;
  line-height: 1.45;
}
* {
  box-sizing: border-box;
}
body {
  margin: 0;
  color: #17212b;
  background: #fbfcfd;
}
main {
  max-width: 1180px;
  margin: 0 auto;
  padding: 28px 20px 48px;
}
h1, h2 {
  color: #101820;
  letter-spacing: 0;
}
h1 {
  font-size: 34px;
  margin: 0 0 8px;
}
h2 {
  font-size: 19px;
  margin: 0 0 12px;
}
.subtitle {
  margin: 0 0 20px;
  color: #4d5b6a;
}
section {
  padding: 22px 0;
  border-top: 1px solid #d8e0e8;
}
.hero {
  border-top: 0;
  padding-top: 14px;
}
.signal-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 12px;
  margin: 0 0 14px;
}
.signal {
  min-height: 86px;
  padding: 14px;
  border: 1px solid #cbd5df;
  border-radius: 6px;
  background: #ffffff;
}
.signal-label {
  display: block;
  margin-bottom: 8px;
  color: #516171;
  font-size: 13px;
}
.signal-value {
  display: block;
  font-size: 21px;
  font-weight: 700;
}
dl {
  display: grid;
  grid-template-columns: minmax(180px, 280px) 1fr;
  gap: 8px 16px;
  margin: 0 0 16px;
}
dt {
  font-weight: 700;
}
dd {
  margin: 0;
}
table {
  width: 100%;
  border-collapse: collapse;
  table-layout: fixed;
}
th, td {
  padding: 8px 10px;
  border: 1px solid #d8e0e8;
  text-align: left;
  vertical-align: top;
  overflow-wrap: anywhere;
}
th {
  background: #eef3f7;
}
code {
  font-family: Consolas, Monaco, monospace;
  font-size: 0.92em;
}
.state-good {
  color: #12613a;
  font-weight: 700;
}
.state-bad {
  color: #982626;
  font-weight: 700;
}
.state-warn {
  color: #805000;
  font-weight: 700;
}
.state-expected {
  color: #0f5e73;
  font-weight: 700;
}
.empty {
  color: #667789;
}
@media (max-width: 760px) {
  .signal-grid,
  dl {
    grid-template-columns: 1fr;
  }
}
""".strip()


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
    _require_no_duplicate_cases(errors, "baseline", baseline)
    _require_no_duplicate_cases(errors, "candidate", candidate)
    if baseline_summary is not None:
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
    left_value: str,
    right_label: str,
    right_value: str,
) -> None:
    if left_value != right_value:
        errors.append(f"{left_label}={left_value!r} does not match {right_label}={right_value!r}")


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
        state=comparison_summary.candidate_state,
    )


def _signal(label: str, value: str) -> str:
    return (
        '<div class="signal">'
        f'<span class="signal-label">{_h(label)}</span>'
        f'<span class="signal-value {_state_class(value)}">{_h(value)}</span>'
        "</div>"
    )


def _detail(label: str, value: str) -> str:
    return f"<dt>{_h(label)}</dt><dd>{_h(value)}</dd>"


def _visible_output_rows(baseline: RunSet, candidate: RunSet) -> tuple[str, ...]:
    baseline_by_case = {run.case_id: run for run in baseline.runs}
    candidate_by_case = {run.case_id: run for run in candidate.runs}
    rows: list[str] = []
    for case_id in sorted(set(baseline_by_case) | set(candidate_by_case)):
        rows.append(
            _visible_output_row(
                case_id,
                baseline_by_case.get(case_id),
                candidate_by_case.get(case_id),
            )
        )
    return tuple(rows)


def _visible_output_row(
    case_id: str,
    baseline: AgentRunRecord | None,
    candidate: AgentRunRecord | None,
) -> str:
    if baseline is None or candidate is None:
        state = "changed"
    elif _visible_output(baseline) == _visible_output(candidate):
        state = "preserved"
    else:
        state = "changed"
    return (
        "<tr>"
        f"<td>{_h(case_id)}</td>"
        f"<td>{_h(baseline.recommendation if baseline else '<missing>')}</td>"
        f"<td>{_h(candidate.recommendation if candidate else '<missing>')}</td>"
        f"<td>{_h(baseline.outcome if baseline else '<missing>')}</td>"
        f"<td>{_h(candidate.outcome if candidate else '<missing>')}</td>"
        f'<td class="{_state_class(state)}">{_h(state)}</td>'
        "</tr>"
    )


def _process_evidence_row(run: AgentRunRecord) -> str:
    linked_claim_ids = tuple(_linked_claim_evidence(run))
    policy_states = tuple(
        f"{policy.policy_id}:{policy.state.value}" for policy in run.policy_results
    )
    provider_model = " / ".join(
        value
        for value in (run.provider, run.resolved_model or run.model)
        if value is not None and value
    )
    return (
        "<tr>"
        f"<td>{_h(run.case_id)}</td>"
        f"<td>{_inline_values(_claim_ids(run))}</td>"
        f"<td>{_inline_values(tuple(ref.ref_id for ref in run.evidence_refs))}</td>"
        f"<td>{_inline_values(linked_claim_ids)}</td>"
        f"<td>{_inline_values(policy_states)}</td>"
        f"<td>{_h(_human_review_state(run))}</td>"
        f"<td>{_h(provider_model or 'not recorded')}</td>"
        f"<td>{_inline_values(run.tools)}</td>"
        "</tr>"
    )


def _finding_row(finding: Finding) -> str:
    return (
        "<tr>"
        f"<td>{_h(finding.case_id)}</td>"
        f"<td>{_h(finding.control_id)}</td>"
        f"<td>{_h(finding.target)}</td>"
        f"<td>{_h(finding.reason_code.value)}</td>"
        f'<td class="{_state_class(finding.state.value)}">{_h(finding.state.value)}</td>'
        f"<td>{_h(finding.message)}</td>"
        "</tr>"
    )


def _missing_link_row(diff: MissingEvidenceLinkDiff) -> str:
    return (
        "<tr>"
        f"<td>{_h(diff.case_id)}</td>"
        f"<td>{_h(diff.claim_id)}</td>"
        f"<td>{_inline_values(diff.baseline_evidence_refs)}</td>"
        f"<td>{_inline_values(diff.candidate_evidence_refs)}</td>"
        "</tr>"
    )


def _artifact_path_row(label: str, value: PathValue) -> str:
    return f"<tr><td>{_h(label)}</td><td><code>{_h(_path_value(value))}</code></td></tr>"


def _artifact_digest_rows(packet: EvidencePacket | None) -> tuple[str, ...]:
    if packet is None:
        return ()
    rows: list[str] = []
    rows.extend(
        _artifact_digest_row(digest.role, "packet artifact digest", digest.sha256)
        for digest in packet.artifact_digests
    )
    if packet.release_manifest is not None:
        rows.extend(
            _artifact_digest_row(artifact.role, artifact.path, artifact.sha256)
            for artifact in packet.release_manifest.artifacts
        )
    return tuple(rows)


def _artifact_digest_row(role: str, path: str, sha256: str) -> str:
    return (
        "<tr>"
        f"<td>{_h(role)}</td>"
        f"<td><code>{_h(_path_value(path))}</code></td>"
        f"<td><code>{_h(sha256)}</code></td>"
        "</tr>"
    )


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
    for ref in run.evidence_refs:
        for claim_id in ref.claim_ids:
            links.setdefault(claim_id, set()).add(ref.ref_id)
    for link in run.claim_evidence_links:
        links.setdefault(link.claim_id, set()).add(link.evidence_ref_id)
    return {claim_id: tuple(sorted(refs)) for claim_id, refs in sorted(links.items())}


def _claim_ids(run: AgentRunRecord) -> tuple[str, ...]:
    claims = {claim.claim_id for claim in run.claims}
    claims.update(_linked_claim_evidence(run))
    return tuple(sorted(claims))


def _case_coverage(baseline: RunSet, candidate: RunSet) -> str:
    baseline_case_ids = {run.case_id for run in baseline.runs}
    candidate_case_ids = {run.case_id for run in candidate.runs}
    missing = sorted(baseline_case_ids - candidate_case_ids)
    extra = sorted(candidate_case_ids - baseline_case_ids)
    if not missing and not extra:
        return "same case IDs"
    parts: list[str] = []
    if missing:
        parts.append("missing candidate cases: " + ", ".join(missing))
    if extra:
        parts.append("extra candidate cases: " + ", ".join(extra))
    return "; ".join(parts)


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


def _missing_link_summary(missing_links: tuple[MissingEvidenceLinkDiff, ...]) -> str:
    if not missing_links:
        return "No baseline evidence links were missing from the candidate run set."
    claims = ", ".join(diff.claim_id for diff in missing_links[:4])
    extra = len(missing_links) - 4
    suffix = f", plus {extra} more" if extra > 0 else ""
    return (
        f"Candidate is missing {len(missing_links)} baseline evidence link"
        f"{'' if len(missing_links) == 1 else 's'}: {claims}{suffix}."
    )


def _fixture_equivalence_note(state: GateState) -> str:
    if state is GateState.pass_:
        return "Baseline and candidate fixture material remained equivalent for comparison."
    if state is GateState.fail:
        return "Fixture material changed in a way that can affect comparison."
    return "Fixture equivalence was not evaluated for this artifact."


def _human_review_state(run: AgentRunRecord) -> str:
    if run.human_review_required and run.human_review_performed:
        return "required and performed"
    if run.human_review_required:
        return "required"
    if run.human_review_performed:
        return "performed"
    return "not required"


def _inline_values(values: tuple[str, ...], *, empty: str = "none") -> str:
    if not values:
        return f'<span class="empty">{_h(empty)}</span>'
    return ", ".join(f"<code>{_h(value)}</code>" for value in values)


def _summarized_values(values: tuple[str, ...], *, empty: str) -> str:
    if not values:
        return empty
    shown = tuple(_truncate_value(value) for value in values[:MAX_INLINE_ITEMS])
    prefix = f"{len(values)} item" if len(values) == 1 else f"{len(values)} items"
    if len(values) <= MAX_INLINE_ITEMS:
        return f"{prefix}: " + "; ".join(shown)
    return f"{prefix}; first {len(shown)} shown: " + "; ".join(shown)


def _truncate_value(value: str) -> str:
    normalized = " ".join(value.split())
    if len(normalized) <= MAX_INLINE_VALUE_CHARS:
        return normalized
    return normalized[: MAX_INLINE_VALUE_CHARS - 1].rstrip() + "..."


def _state_class(state: str) -> str:
    if state in {GateState.pass_.value, "preserved", "not blocked"}:
        return "state-good"
    if state in {"caught", "blocked"}:
        return "state-expected"
    if state in {GateState.fail.value, "changed"}:
        return "state-bad"
    if state in {GateState.warn.value, "observed"}:
        return "state-warn"
    return ""


def _case_key(run: AgentRunRecord) -> str:
    return run.case_id


def _path_value(value: PathValue) -> str:
    if isinstance(value, Path):
        if value.is_absolute():
            return f"<absolute-path:{value.name or 'artifact'}>"
        return value.as_posix()
    if _looks_like_absolute_path(value):
        return f"<absolute-path:{_path_name(value)}>"
    return value


def _looks_like_absolute_path(value: str) -> bool:
    return PureWindowsPath(value).is_absolute() or PurePosixPath(value).is_absolute()


def _path_name(value: str) -> str:
    windows = PureWindowsPath(value)
    if windows.is_absolute() and windows.name:
        return windows.name
    posix = PurePosixPath(value)
    if posix.name:
        return posix.name
    return "artifact"


def _h(value: object) -> str:
    redacted = redact_text(str(value))
    without_external_urls = _EXTERNAL_URL_PATTERN.sub("[URL]", redacted)
    return escape(without_external_urls, quote=True)
