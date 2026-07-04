from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from html import escape
from pathlib import Path, PurePosixPath, PureWindowsPath

from agent_assure.privacy.redaction import redact_text
from agent_assure.schema.common import ComparisonClassification, GateState, ReasonCode
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

    return "\n".join(
        (
            "<!doctype html>",
            '<html lang="en">',
            "<head>",
            '<meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            f"<title>{_h(_document_title(verdict.headline, title))}</title>",
            "<style>",
            _css(),
            "</style>",
            "</head>",
            "<body>",
            "<main>",
            _verdict_section(
                verdict=verdict,
                title=title,
                visible_state=visible_state,
                process_state=process_state,
                ci_gate_result=ci_gate_result,
                affected_summary=affected_summary,
            ),
            _key_finding_section(missing_links),
            _claim_boundary_section(),
            _final_output_section(
                baseline,
                candidate,
                visible_state,
                resolved_baseline_summary,
                resolved_candidate_summary,
            ),
            _process_diff_section(
                baseline,
                candidate,
                visible_state,
                resolved_candidate_summary,
                missing_links,
                affected_summary,
            ),
            _process_evidence_section(
                "baseline-process",
                "Full Baseline Process Evidence",
                baseline,
                section_class="technical-detail",
            ),
            _process_evidence_section(
                "candidate-process",
                "Full Candidate Process Evidence",
                candidate,
                section_class="technical-detail",
            ),
            _missing_evidence_section(missing_links),
            _findings_section(resolved_candidate_summary.findings, missing_links),
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


def _document_title(headline: str, title: str) -> str:
    parts = [headline]
    if title != THESIS_TITLE:
        parts.append(title)
    parts.append("Agent Assure")
    return " - ".join(parts)


def _report_label(title: str) -> str:
    if title == THESIS_TITLE:
        return ""
    return f'<p class="report-label">{_h(title)}</p>'


def _verdict_section(
    *,
    verdict: ReportVerdict,
    title: str,
    visible_state: str,
    process_state: str,
    ci_gate_result: str,
    affected_summary: ProcessAffectedSummary,
) -> str:
    affected_value = _process_scope_value(affected_summary)
    affected_note = _process_scope_note(affected_summary)
    return "\n".join(
        (
            '<section class="hero" aria-labelledby="report-verdict">',
            '<p class="eyebrow">agent-assure evidence diff</p>',
            f'<h1 id="report-verdict">{_h(verdict.headline)}</h1>',
            f'<p class="subtitle">{_h(THESIS_TITLE)}</p>',
            _report_label(title),
            f'<p class="verdict-sentence">{_h(verdict.sentence)}</p>',
            '<div class="signal-grid">',
            _signal("Decision fields", visible_state, "recommendation and outcome"),
            _signal("Process regression", process_state, "process invariant layer"),
            _signal(
                "Process scope",
                affected_value,
                affected_note,
                state="failed invariant"
                if affected_summary.missing_link_count
                else "observed"
                if affected_summary.case_ids or affected_summary.unscoped_finding_count
                else "not observed",
            ),
            _signal("CI gate", ci_gate_result, "control response"),
            "</div>",
            (
                '<p class="status-legend">'
                "Blue control states mean the gate caught or blocked candidate risk; "
                "red states mark the underlying regression."
                "</p>"
            ),
            "</section>",
        )
    )


def _key_finding_section(missing_links: tuple[MissingEvidenceLinkDiff, ...]) -> str:
    if not missing_links:
        return "\n".join(
            (
                '<section class="key-finding key-finding-clear" aria-labelledby="key-finding">',
                '<h2 id="key-finding">Key Finding</h2>',
                '<p>No material claim link regression was detected.</p>',
                "</section>",
            )
        )
    rows = "\n".join(_key_finding_row(diff) for diff in missing_links)
    return "\n".join(
        (
            '<section class="key-finding" aria-labelledby="key-finding">',
            '<div class="section-heading-row">',
            '<h2 id="key-finding">Key Finding</h2>',
            _regression_badge(len(missing_links)),
            "</div>",
            (
                "<p>"
                "The candidate preserved the visible decision fields but dropped a "
                "required material-claim evidence link. This is a link-level "
                "regression: the source evidence may still be present for another claim."
                "</p>"
            ),
            '<div class="table-wrap">',
            "<table>",
            "<thead><tr>"
            "<th>Case</th><th>Material claim</th><th>Baseline link</th>"
            "<th>Candidate link</th><th>Reason</th>"
            "</tr></thead>",
            f"<tbody>{rows}</tbody>",
            "</table>",
            "</div>",
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
            '<section class="claim-boundary" aria-labelledby="claim-boundary">',
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
            '<section class="decision-section" aria-labelledby="decision-field-comparison">',
            '<h2 id="decision-field-comparison">Decision-Field Comparison</h2>',
            '<dl class="summary-grid">',
            _detail("Decision fields (recommendation, outcome)", visible_state),
            _detail("Case coverage", _case_coverage(baseline, candidate)),
            _detail("Baseline evaluation state", baseline_summary.state.value),
            _detail("Candidate evaluation state", candidate_summary.state.value),
            "</dl>",
            '<div class="table-wrap">',
            '<table class="wide-table">',
            "<thead><tr>"
            "<th>Case</th><th>Baseline recommendation</th><th>Candidate recommendation</th>"
            "<th>Baseline outcome</th><th>Candidate outcome</th><th>Decision fields</th>"
            "</tr></thead>",
            f"<tbody>{rows}</tbody>",
            "</table>",
            "</div>",
            "</section>",
        )
    )


def _process_diff_section(
    baseline: RunSet,
    candidate: RunSet,
    visible_state: str,
    candidate_summary: EvaluationSummary,
    missing_links: tuple[MissingEvidenceLinkDiff, ...],
    affected_summary: ProcessAffectedSummary,
) -> str:
    rows = "\n".join(
        _process_diff_rows(
            baseline,
            candidate,
            visible_state,
            candidate_summary,
            missing_links,
        )
    )
    body = rows or '<tr><td colspan="6" class="empty">No runs were recorded.</td></tr>'
    return "\n".join(
        (
            '<section class="process-diff-section" aria-labelledby="process-evidence-diff">',
            '<h2 id="process-evidence-diff">Process Evidence Diff</h2>',
            (
                "<p class=\"section-note\">"
                "Process-affected cases are sourced from candidate findings and missing "
                "material-claim evidence links, not from preserved decision fields."
                f"{_unscoped_finding_note(affected_summary)}"
                "</p>"
            ),
            '<div class="table-wrap">',
            '<table class="process-diff-table wide-table">',
            "<thead><tr>"
            "<th>Case</th><th>Process status</th><th>Decision fields</th>"
            "<th>Changed fields</th><th>Process findings</th><th>Claim-evidence links</th>"
            "</tr></thead>",
            f"<tbody>{body}</tbody>",
            "</table>",
            "</div>",
            "</section>",
        )
    )


def _process_evidence_section(
    section_id: str,
    heading: str,
    runset: RunSet,
    *,
    section_class: str = "",
) -> str:
    rows = "\n".join(_process_evidence_row(run) for run in sorted(runset.runs, key=_case_key))
    body = rows or '<tr><td colspan="8" class="empty">No runs were recorded.</td></tr>'
    class_attr = f' class="{_h(section_class)}"' if section_class else ""
    return "\n".join(
        (
            f'<section{class_attr} aria-labelledby="{_h(section_id)}">',
            f'<h2 id="{_h(section_id)}">{_h(heading)}</h2>',
            '<div class="table-wrap">',
            '<table class="process-evidence-table wide-table">',
            "<thead><tr>"
            "<th>Case</th><th>Claims</th><th>Evidence refs</th><th>Linked claims</th>"
            "<th>Policy states</th><th>Human review</th><th>Provider/model</th><th>Tools</th>"
            "</tr></thead>",
            f"<tbody>{body}</tbody>",
            "</table>",
            "</div>",
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
            (
                '<section class="missing-link-section technical-detail" '
                'aria-labelledby="missing-evidence-link-diff">'
            ),
            '<div class="section-heading-row">',
            '<h2 id="missing-evidence-link-diff">Missing Evidence Link Diff</h2>',
            "</div>",
            '<div class="table-wrap">',
            "<table>",
            "<thead><tr>"
            "<th>Case</th><th>Claim</th><th>Baseline evidence refs</th>"
            "<th>Candidate evidence refs</th>"
            "</tr></thead>",
            f"<tbody>{body}</tbody>",
            "</table>",
            "</div>",
            "</section>",
        )
    )


def _findings_section(
    findings: tuple[Finding, ...],
    missing_links: tuple[MissingEvidenceLinkDiff, ...],
) -> str:
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
            '<section class="findings-section" aria-labelledby="process-invariant-findings">',
            '<div class="section-heading-row">',
            '<h2 id="process-invariant-findings">Process Invariant Findings</h2>',
            "</div>",
            '<div class="table-wrap">',
            '<table class="wide-table">',
            "<thead><tr><th>Case</th><th>Control</th><th>Target</th>"
            "<th>Reason code</th><th>State</th><th>Message</th></tr></thead>",
            f"<tbody>{body}</tbody>",
            "</table>",
            "</div>",
            "</section>",
        )
    )


def _comparison_section(comparison_summary: ComparisonSummary) -> str:
    return "\n".join(
        (
            '<section aria-labelledby="comparison-classification">',
            '<h2 id="comparison-classification">Comparison Classification</h2>',
            '<dl class="summary-grid">',
            _detail("Classification", comparison_summary.classification.value),
            _detail("Baseline state", comparison_summary.baseline_state.value),
            _detail("Candidate state", comparison_summary.candidate_state.value),
            _detail_html(
                "Provenance changes",
                _summarized_values_html(comparison_summary.provenance_changes, empty="none"),
            ),
            _detail_html(
                "Verdict findings",
                _summarized_values_html(comparison_summary.verdict_findings, empty="none"),
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
            '<dl class="summary-grid">',
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
    limitations = _summarized_values_html(
        packet.limitations if packet is not None else (),
        empty="none",
    )
    return "\n".join(
        (
            '<section class="ci-gate-section" aria-labelledby="ci-gate-result">',
            '<h2 id="ci-gate-result">CI Gate Result</h2>',
            '<dl class="summary-grid">',
            _detail("Result", ci_gate_result),
            _detail("Evidence packet", packet_id),
            _detail_html("Packet limitations", limitations),
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
            '<section class="appendix-section" aria-labelledby="artifact-paths">',
            '<h2 id="artifact-paths">Artifact Paths</h2>',
            '<div class="table-wrap">',
            "<table>",
            "<thead><tr><th>Artifact</th><th>Path</th></tr></thead>",
            f"<tbody>{body}</tbody>",
            "</table>",
            "</div>",
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
            '<section class="appendix-section" aria-labelledby="artifact-digests">',
            '<h2 id="artifact-digests">Artifact Digests</h2>',
            '<div class="table-wrap">',
            "<table>",
            "<thead><tr><th>Role</th><th>Path</th><th>SHA-256</th></tr></thead>",
            f"<tbody>{body}</tbody>",
            "</table>",
            "</div>",
            "</section>",
        )
    )


def _css() -> str:
    return """
:root {
  color-scheme: light;
  --bg: #f6f8fb;
  --panel: #ffffff;
  --panel-muted: #f8fafc;
  --text: #14202b;
  --muted: #566575;
  --subtle: #748292;
  --border: #d8e1eb;
  --border-strong: #b8c6d6;
  --slate: #263445;
  --green: #12613a;
  --green-bg: #e8f6ee;
  --green-border: #9dd7b4;
  --red: #982626;
  --red-bg: #fdecec;
  --red-border: #efb4b4;
  --amber: #805000;
  --amber-bg: #fff5db;
  --amber-border: #e7c66d;
  --blue: #0f5e73;
  --blue-bg: #e7f5f8;
  --blue-border: #9ecfd9;
  --shadow: 0 12px 28px rgba(20, 32, 43, 0.08);
  font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
  line-height: 1.45;
}
* {
  box-sizing: border-box;
}
body {
  margin: 0;
  color: var(--text);
  background: var(--bg);
}
main {
  max-width: 1240px;
  margin: 0 auto;
  padding: 30px 22px 56px;
}
h1, h2 {
  color: #0f1720;
  letter-spacing: 0;
}
h1 {
  max-width: 920px;
  font-size: 42px;
  line-height: 1.08;
  margin: 0 0 10px;
}
h2 {
  font-size: 20px;
  line-height: 1.2;
  margin: 0 0 14px;
}
.eyebrow {
  margin: 0 0 10px;
  color: var(--blue);
  font-size: 12px;
  font-weight: 800;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}
.subtitle {
  max-width: 780px;
  margin: 0 0 8px;
  color: var(--muted);
  font-size: 18px;
  font-weight: 650;
}
.report-label {
  margin: 0 0 14px;
  color: var(--subtle);
}
.verdict-sentence {
  max-width: 900px;
  margin: 18px 0 22px;
  color: #263445;
  font-size: 18px;
}
section {
  padding: 28px 0;
  border-top: 1px solid var(--border);
}
.hero {
  border-top: 0;
  padding: 8px 0 30px;
}
.signal-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 14px;
  margin: 0 0 14px;
}
.signal {
  min-height: 118px;
  padding: 16px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--panel);
  box-shadow: var(--shadow);
}
.signal-label {
  display: block;
  margin-bottom: 10px;
  color: var(--muted);
  font-size: 13px;
  font-weight: 700;
}
.signal-value {
  display: inline-block;
  margin-bottom: 10px;
  font-size: 20px;
  font-weight: 800;
}
.signal-note {
  display: block;
  color: var(--subtle);
  font-size: 12px;
}
.status-legend,
.section-note {
  margin: 8px 0 0;
  color: var(--muted);
  font-size: 14px;
}
.key-finding,
.claim-boundary,
.findings-section,
.ci-gate-section {
  margin: 0 0 6px;
  padding: 22px;
  border: 1px solid var(--border);
  border-left: 6px solid var(--red);
  border-radius: 8px;
  background: var(--panel);
  box-shadow: 0 8px 22px rgba(20, 32, 43, 0.05);
}
.key-finding-clear {
  border-left-color: var(--green);
}
.claim-boundary {
  border-left-color: var(--slate);
  background: var(--panel-muted);
}
.ci-gate-section {
  border-left-color: var(--blue);
}
.section-heading-row {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 10px;
  margin-bottom: 12px;
}
.section-heading-row h2 {
  margin: 0;
}
.regression-badge {
  display: inline-flex;
  align-items: center;
  min-height: 28px;
  padding: 4px 10px;
  border: 1px solid var(--red-border);
  border-radius: 8px;
  color: var(--red);
  background: var(--red-bg);
  font-size: 12px;
  font-weight: 800;
}
.table-wrap {
  width: 100%;
  overflow-x: auto;
}
.summary-grid,
dl {
  display: grid;
  grid-template-columns: minmax(180px, 280px) 1fr;
  gap: 8px 16px;
  margin: 0 0 16px;
}
dt {
  color: var(--muted);
  font-weight: 750;
}
dd {
  margin: 0;
}
table {
  width: 100%;
  border-collapse: separate;
  border-spacing: 0;
  table-layout: auto;
  border: 1px solid var(--border);
  border-radius: 8px;
  overflow: hidden;
  background: var(--panel);
}
th, td {
  padding: 11px 12px;
  border-bottom: 1px solid var(--border);
  text-align: left;
  vertical-align: top;
  overflow-wrap: anywhere;
}
td + td,
th + th {
  border-left: 1px solid var(--border);
}
th {
  color: #253244;
  background: #edf3f8;
  font-size: 12px;
  font-weight: 800;
  text-transform: uppercase;
}
tbody tr:nth-child(even) td {
  background: #fbfdff;
}
tbody tr:last-child td {
  border-bottom: 0;
}
.process-row-unchanged td {
  background: #fbfdff;
}
.process-row-affected td,
.process-row-changed td {
  background: #fff8f8;
}
.process-diff-table td {
  min-width: 140px;
}
.wide-table {
  min-width: 760px;
}
.process-diff-table {
  min-width: 1040px;
}
.process-evidence-table {
  min-width: 1120px;
}
.cell-value {
  min-width: 0;
}
code {
  display: inline-block;
  margin: 1px 0;
  padding: 1px 5px;
  border: 1px solid #dbe3ec;
  border-radius: 5px;
  color: #1d2b3a;
  background: #f4f7fa;
  font-family: Consolas, Monaco, monospace;
  font-size: 0.92em;
}
.state-good {
  color: var(--green);
  background: var(--green-bg);
  border-color: var(--green-border);
}
.state-bad {
  color: var(--red);
  background: var(--red-bg);
  border-color: var(--red-border);
}
.state-warn {
  color: var(--amber);
  background: var(--amber-bg);
  border-color: var(--amber-border);
}
.state-expected {
  color: var(--blue);
  background: var(--blue-bg);
  border-color: var(--blue-border);
}
.state-good,
.state-bad,
.state-warn,
.state-expected {
  padding: 3px 9px;
  border: 1px solid;
  border-radius: 8px;
  font-weight: 800;
  white-space: nowrap;
}
.diff-pair {
  display: grid;
  grid-template-columns: 84px 1fr;
  gap: 4px 10px;
}
.diff-label {
  color: var(--muted);
  font-weight: 800;
}
.diff-removed {
  display: inline-flex;
  align-items: baseline;
  gap: 4px;
  margin: 1px 0;
  padding: 2px 6px;
  border: 1px solid var(--red-border);
  border-radius: 5px;
  color: var(--red);
  background: var(--red-bg);
}
.diff-removed-token {
  text-decoration: line-through;
  text-decoration-thickness: 1px;
}
.diff-removed .empty {
  color: var(--red);
}
.diff-marker {
  font-weight: 900;
  text-decoration: none;
}
.value-list {
  margin: 6px 0 0;
  padding-left: 18px;
}
.value-count {
  color: var(--muted);
  font-weight: 700;
}
.technical-detail,
.appendix-section {
  color: #253244;
}
.technical-detail h2,
.appendix-section h2 {
  color: #253244;
}
.empty {
  color: var(--subtle);
}
@media (max-width: 1120px) {
  .signal-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}
@media (max-width: 760px) {
  main {
    padding: 22px 14px 42px;
  }
  h1 {
    font-size: 31px;
  }
  .signal-grid,
  dl {
    grid-template-columns: 1fr;
  }
  .key-finding,
  .claim-boundary,
  .findings-section,
  .ci-gate-section {
    padding: 18px;
  }
}
@media print {
  body {
    background: #ffffff;
  }
  main {
    max-width: none;
    padding: 0;
  }
  section,
  .signal,
  .key-finding,
  .claim-boundary,
  .findings-section,
  .ci-gate-section {
    break-inside: avoid;
    box-shadow: none;
  }
  .table-wrap {
    overflow: visible;
  }
  table {
    min-width: 0;
  }
  th {
    overflow-wrap: normal;
    word-break: normal;
    hyphens: none;
  }
  .wide-table {
    min-width: 0;
  }
  .process-diff-table,
  .process-evidence-table {
    min-width: 0;
    border: 0;
    background: transparent;
  }
  .process-diff-table thead,
  .process-evidence-table thead {
    display: none;
  }
  .process-diff-table,
  .process-diff-table tbody,
  .process-diff-table tr,
  .process-diff-table td,
  .process-evidence-table,
  .process-evidence-table tbody,
  .process-evidence-table tr,
  .process-evidence-table td {
    display: block;
  }
  .process-diff-table tr,
  .process-evidence-table tr {
    margin: 0 0 12px;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: var(--panel);
    break-inside: avoid;
  }
  .process-diff-table td,
  .process-evidence-table td {
    display: grid;
    grid-template-columns: 132px minmax(0, 1fr);
    gap: 8px;
    min-width: 0;
    padding: 8px 10px;
    border-bottom: 1px solid var(--border);
    overflow-wrap: normal;
    word-break: normal;
  }
  .process-diff-table td + td,
  .process-evidence-table td + td {
    border-left: 0;
  }
  .process-diff-table td:last-child,
  .process-evidence-table td:last-child {
    border-bottom: 0;
  }
  .process-diff-table td::before,
  .process-evidence-table td::before {
    content: attr(data-label);
    color: var(--muted);
    font-weight: 800;
  }
  .process-diff-table .cell-value,
  .process-evidence-table .cell-value {
    min-width: 0;
    overflow-wrap: normal;
    word-break: normal;
  }
  .process-diff-table code,
  .process-evidence-table code,
  .process-diff-table .state-good,
  .process-diff-table .state-bad,
  .process-diff-table .state-warn,
  .process-diff-table .state-expected,
  .process-evidence-table .state-good,
  .process-evidence-table .state-bad,
  .process-evidence-table .state-warn,
  .process-evidence-table .state-expected {
    white-space: nowrap;
    overflow-wrap: normal;
    word-break: normal;
  }
  .process-diff-table .diff-pair {
    grid-template-columns: 78px minmax(0, 1fr);
  }
  .appendix-section code {
    white-space: normal;
    overflow-wrap: anywhere;
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


def _process_scope_value(summary: ProcessAffectedSummary) -> str:
    case_count = len(summary.case_ids)
    value = f"{case_count} of {summary.total_cases} cases"
    if summary.unscoped_finding_count:
        value += f" + {summary.unscoped_finding_count} unscoped"
    return value


def _process_scope_note(summary: ProcessAffectedSummary) -> str:
    parts = ["findings or missing links by case"]
    if summary.missing_link_count:
        baseline = ""
        if summary.baseline_link_count:
            baseline = (
                f" of {summary.baseline_link_count} baseline claim "
                f"link{'' if summary.baseline_link_count == 1 else 's'}"
            )
        count = summary.missing_link_count
        parts.append(
            f"{count} missing material-claim link{'' if count == 1 else 's'}{baseline}"
        )
    if summary.unscoped_finding_count:
        count = summary.unscoped_finding_count
        parts.append(f"{count} finding{'' if count == 1 else 's'} without case ID")
    return "; ".join(parts)


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


def _unscoped_finding_note(summary: ProcessAffectedSummary) -> str:
    if not summary.unscoped_finding_count:
        return ""
    count = summary.unscoped_finding_count
    verb = "does" if count == 1 else "do"
    be = "is" if count == 1 else "are"
    return (
        f" {count} process finding{'' if count == 1 else 's'} "
        f"{verb} not include a case ID and {be} shown as unscoped in "
        "Process Invariant Findings."
    )


def _signal(
    label: str,
    value: str,
    note: str,
    *,
    state: str | None = None,
) -> str:
    state_class = _state_class(state or value)
    return (
        '<div class="signal">'
        f'<span class="signal-label">{_h(label)}</span>'
        f'<span class="signal-value {state_class}">{_h(value)}</span>'
        f'<span class="signal-note">{_h(note)}</span>'
        "</div>"
    )


def _detail(label: str, value: str) -> str:
    return f"<dt>{_h(label)}</dt><dd>{_h(value)}</dd>"


def _detail_html(label: str, value_html: str) -> str:
    return f"<dt>{_h(label)}</dt><dd>{value_html}</dd>"


def _regression_badge(count: int) -> str:
    noun = "regression" if count == 1 else "regressions"
    return f'<span class="regression-badge">{_h(count)} material claim link {noun}</span>'


def _key_finding_row(diff: MissingEvidenceLinkDiff) -> str:
    return (
        "<tr>"
        f"<td>{_h(diff.case_id)}</td>"
        f"<td><code>{_h(diff.claim_id)}</code></td>"
        f"<td>{_link_expression(diff.claim_id, diff.baseline_evidence_refs)}</td>"
        f"<td>{_link_expression(diff.claim_id, diff.candidate_evidence_refs)}</td>"
        f"<td><code>{_h(ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE.value)}</code></td>"
        "</tr>"
    )


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
    state = _visible_output_state(baseline, candidate)
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


def _process_diff_rows(
    baseline: RunSet,
    candidate: RunSet,
    visible_state: str,
    candidate_summary: EvaluationSummary,
    missing_links: tuple[MissingEvidenceLinkDiff, ...],
) -> tuple[str, ...]:
    baseline_by_case = {run.case_id: run for run in baseline.runs}
    candidate_by_case = {run.case_id: run for run in candidate.runs}
    findings_by_case: dict[str, list[Finding]] = {}
    for finding in candidate_summary.findings:
        findings_by_case.setdefault(finding.case_id, []).append(finding)
    missing_by_case: dict[str, list[MissingEvidenceLinkDiff]] = {}
    for diff in missing_links:
        missing_by_case.setdefault(diff.case_id, []).append(diff)
    rows: list[str] = []
    for case_id in sorted(set(baseline_by_case) | set(candidate_by_case)):
        baseline_run = baseline_by_case.get(case_id)
        candidate_run = candidate_by_case.get(case_id)
        rows.append(
            _process_diff_row(
                case_id=case_id,
                baseline=baseline_run,
                candidate=candidate_run,
                visible_state=_visible_output_state(baseline_run, candidate_run)
                if visible_state != GateState.not_evaluated.value
                else visible_state,
                findings=tuple(findings_by_case.get(case_id, ())),
                missing_links=tuple(missing_by_case.get(case_id, ())),
            )
        )
    return tuple(rows)


def _process_diff_row(
    *,
    case_id: str,
    baseline: AgentRunRecord | None,
    candidate: AgentRunRecord | None,
    visible_state: str,
    findings: tuple[Finding, ...],
    missing_links: tuple[MissingEvidenceLinkDiff, ...],
) -> str:
    status = _process_diff_status(baseline, candidate, findings, missing_links)
    changed_fields = _process_changed_fields(baseline, candidate)
    row_class = {
        "failed invariant": "process-row-affected",
        "changed": "process-row-changed",
    }.get(status, "process-row-unchanged")
    claim_link_state = (
        _regression_badge(len(missing_links))
        if missing_links
        else '<span class="state-good">no regression</span>'
    )
    if findings:
        reason_codes = tuple(finding.reason_code.value for finding in findings)
        claim_link_state += "<br>" + _inline_values(reason_codes)
    return "".join(
        (
            f'<tr class="{_h(row_class)}">',
            _process_diff_cell("Case", _h(case_id)),
            _process_diff_cell("Process status", _status_badge(status)),
            _process_diff_cell("Decision fields", _status_badge(visible_state)),
            _process_diff_cell("Changed fields", _inline_values(changed_fields)),
            _process_diff_cell("Process findings", claim_link_state),
            _process_diff_cell(
                "Claim-evidence links",
                _evidence_chain_comparison(baseline, candidate, missing_links),
            ),
            "</tr>",
        )
    )


def _process_diff_cell(label: str, value_html: str) -> str:
    return _labeled_cell(label, value_html)


def _labeled_cell(label: str, value_html: str) -> str:
    return f'<td data-label="{_h(label)}"><div class="cell-value">{value_html}</div></td>'


def _status_badge(state: str) -> str:
    return f'<span class="{_state_class(state)}">{_h(state)}</span>'


def _process_diff_status(
    baseline: AgentRunRecord | None,
    candidate: AgentRunRecord | None,
    findings: tuple[Finding, ...],
    missing_links: tuple[MissingEvidenceLinkDiff, ...],
) -> str:
    if findings or missing_links:
        return "failed invariant"
    if baseline is None or candidate is None:
        return "changed"
    if _process_signature(baseline) != _process_signature(candidate):
        return "changed"
    return "unchanged"


def _evidence_chain_comparison(
    baseline: AgentRunRecord | None,
    candidate: AgentRunRecord | None,
    missing_links: tuple[MissingEvidenceLinkDiff, ...],
) -> str:
    return (
        '<div class="diff-pair">'
        '<span class="diff-label">Baseline</span>'
        f"<span>{_claim_link_summary(baseline)}</span>"
        '<span class="diff-label">Candidate</span>'
        f"<span>{_claim_link_summary(candidate, removed=missing_links)}</span>"
        "</div>"
    )


def _claim_link_summary(
    run: AgentRunRecord | None,
    *,
    removed: tuple[MissingEvidenceLinkDiff, ...] = (),
) -> str:
    if run is None:
        return '<span class="empty">missing run</span>'
    pieces = [
        _removed_link_expression(diff.claim_id)
        for diff in sorted(removed, key=lambda item: item.claim_id)
    ]
    pieces.extend(
        _link_expression(claim_id, refs)
        for claim_id, refs in _linked_claim_evidence(run).items()
        if claim_id not in {diff.claim_id for diff in removed}
    )
    if not pieces:
        return '<span class="empty">none</span>'
    return "; ".join(pieces)


def _link_expression(claim_id: str, evidence_refs: tuple[str, ...]) -> str:
    return f"<code>{_h(claim_id)}</code> -&gt; {_inline_values(evidence_refs)}"


def _removed_link_expression(claim_id: str) -> str:
    return (
        '<span class="diff-removed">'
        '<span class="diff-marker">-</span> '
        f'<span class="diff-removed-token"><code>{_h(claim_id)}</code></span>'
        ' <span>-&gt;</span> <span class="empty">none</span>'
        "</span>"
    )


def _process_signature(run: AgentRunRecord) -> tuple[object, ...]:
    return (
        _claim_ids(run),
        tuple(ref.ref_id for ref in run.evidence_refs),
        tuple(_linked_claim_evidence(run).items()),
        _policy_states(run),
        _human_review_state(run),
        _provider_model(run),
        run.tools,
    )


def _process_changed_fields(
    baseline: AgentRunRecord | None,
    candidate: AgentRunRecord | None,
) -> tuple[str, ...]:
    if baseline is None or candidate is None:
        return ("case coverage",)
    changed: list[str] = []
    if _claim_ids(baseline) != _claim_ids(candidate):
        changed.append("claims")
    if tuple(ref.ref_id for ref in baseline.evidence_refs) != tuple(
        ref.ref_id for ref in candidate.evidence_refs
    ):
        changed.append("evidence refs")
    if _linked_claim_evidence(baseline) != _linked_claim_evidence(candidate):
        changed.append("claim-evidence links")
    if _policy_states(baseline) != _policy_states(candidate):
        changed.append("policy states")
    if _human_review_state(baseline) != _human_review_state(candidate):
        changed.append("human review")
    if _provider_model(baseline) != _provider_model(candidate):
        changed.append("provider/model")
    if baseline.tools != candidate.tools:
        changed.append("tools")
    return tuple(changed)


def _process_evidence_row(run: AgentRunRecord) -> str:
    linked_claim_ids = tuple(_linked_claim_evidence(run))
    return "".join(
        (
            "<tr>",
            _labeled_cell("Case", _h(run.case_id)),
            _labeled_cell("Claims", _inline_values(_claim_ids(run))),
            _labeled_cell(
                "Evidence refs",
                _inline_values(tuple(ref.ref_id for ref in run.evidence_refs)),
            ),
            _labeled_cell("Linked claims", _inline_values(linked_claim_ids)),
            _labeled_cell("Policy states", _inline_values(_policy_states(run))),
            _labeled_cell("Human review", _h(_human_review_state(run))),
            _labeled_cell("Provider/model", _h(_provider_model(run) or "not recorded")),
            _labeled_cell("Tools", _inline_values(run.tools)),
            "</tr>",
        )
    )


def _finding_row(finding: Finding) -> str:
    return (
        "<tr>"
        f"<td>{_h(finding.case_id or 'unscoped')}</td>"
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
    present_refs = {ref.ref_id for ref in run.evidence_refs}
    for link in run.claim_evidence_links:
        if link.evidence_ref_id in present_refs:
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


def _policy_states(run: AgentRunRecord) -> tuple[str, ...]:
    return tuple(f"{policy.policy_id}:{policy.state.value}" for policy in run.policy_results)


def _provider_model(run: AgentRunRecord) -> str:
    return " / ".join(
        value
        for value in (run.provider, run.resolved_model or run.model)
        if value is not None and value
    )


def _inline_values(values: tuple[str, ...], *, empty: str = "none") -> str:
    if not values:
        return f'<span class="empty">{_h(empty)}</span>'
    return ", ".join(f"<code>{_h(value)}</code>" for value in values)


def _summarized_values_html(values: tuple[str, ...], *, empty: str) -> str:
    if not values:
        return f'<span class="empty">{_h(empty)}</span>'
    shown = tuple(_truncate_value(value) for value in values[:MAX_INLINE_ITEMS])
    prefix = f"{len(values)} item" if len(values) == 1 else f"{len(values)} items"
    if len(values) > MAX_INLINE_ITEMS:
        prefix = f"{prefix}; first {len(shown)} shown"
    items = "".join(f"<li>{_h(value)}</li>" for value in shown)
    return f'<span class="value-count">{_h(prefix)}</span><ul class="value-list">{items}</ul>'


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
    boundary = max(
        normalized.rfind(separator, 0, MAX_INLINE_VALUE_CHARS)
        for separator in (" ", ";", ",")
    )
    if boundary >= MAX_INLINE_VALUE_CHARS // 2:
        return normalized[:boundary].rstrip() + " ..."
    return normalized


def _state_class(state: str) -> str:
    if state in {
        GateState.pass_.value,
        "preserved",
        "not blocked",
        "not observed",
        "unchanged",
    }:
        return "state-good"
    if state in {"caught", "blocked"}:
        return "state-expected"
    if state in {GateState.fail.value, "changed", "failed invariant"}:
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
