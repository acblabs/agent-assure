from __future__ import annotations

import re
from collections.abc import Mapping
from html import escape
from pathlib import Path, PurePosixPath, PureWindowsPath

from agent_assure.privacy.redaction import redact_text
from agent_assure.reporting.evidence_diff_style import evidence_diff_css as _css
from agent_assure.reporting.evidence_diff_view import (
    MissingEvidenceLinkDiff,
    ProcessAffectedSummary,
    ReportVerdict,
    _linked_claim_evidence,
    _paired_runs,
    _process_finding_scope_phrase,
    _visible_output_state,
    build_evidence_diff_presentation,
)
from agent_assure.schema.common import GateState, ReasonCode
from agent_assure.schema.comparison import ComparisonSummary
from agent_assure.schema.evaluation import EvaluationSummary, Finding
from agent_assure.schema.packet import EvidencePacket
from agent_assure.schema.run import AgentRunRecord, RunSet
from agent_assure.usage.aggregation import format_usage_delta

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
    presentation = build_evidence_diff_presentation(
        baseline=baseline,
        candidate=candidate,
        comparison_summary=comparison_summary,
        baseline_summary=baseline_summary,
        candidate_summary=candidate_summary,
        packet=packet,
    )
    resolved_baseline_summary = presentation.baseline_summary
    resolved_candidate_summary = presentation.candidate_summary
    visible_state = presentation.visible_state
    missing_links = presentation.missing_links
    ci_gate_result = presentation.ci_gate_result
    process_state = presentation.process_state
    affected_summary = presentation.affected_summary
    verdict = presentation.verdict

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
                baseline=baseline,
                candidate=candidate,
                visible_state=visible_state,
                process_state=process_state,
                ci_gate_result=ci_gate_result,
                candidate_summary=resolved_candidate_summary,
                missing_links=missing_links,
                affected_summary=affected_summary,
            ),
            _process_diff_section(
                baseline,
                candidate,
                visible_state,
                resolved_candidate_summary,
                missing_links,
                affected_summary,
            ),
            _decision_review_page(
                baseline,
                candidate,
                visible_state,
                resolved_baseline_summary,
                resolved_candidate_summary,
                missing_links,
            ),
            _technical_evidence_page(baseline, candidate, missing_links),
            _evidence_packet_page(
                baseline,
                candidate,
                comparison_summary,
                ci_gate_result,
                packet,
                artifact_paths,
            ),
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


def _page(page_class: str, page_number: int, *children: str) -> str:
    return "\n".join(
        (
            f'<article class="page {_h(page_class)}">',
            *children,
            _page_footer(page_number),
            "</article>",
        )
    )


def _page_footer(page_number: int) -> str:
    return (
        '<footer class="page-footer">'
        "<span>Agent Assure Evidence Diff &middot; generated locally "
        "&middot; evidence packet available</span>"
        f'<span class="page-number">{_h(page_number)} / 5</span>'
        "</footer>"
    )


def _hero_headline(
    verdict: ReportVerdict,
    visible_state: str,
    ci_gate_result: str,
    missing_links: tuple[MissingEvidenceLinkDiff, ...],
) -> str:
    if visible_state == "preserved" and missing_links and ci_gate_result == "blocked":
        return "Same approval. Broken evidence trail. CI blocked."
    return verdict.headline


def _hero_subheading(
    visible_state: str,
    missing_links: tuple[MissingEvidenceLinkDiff, ...],
) -> str:
    if visible_state == "preserved" and missing_links:
        return (
            "The candidate agent preserved the visible decision, but lost the "
            "material-claim evidence link required for governance review."
        )
    return (
        "Agent Assure compares visible decisions against the process evidence "
        "needed for traceability, review, and release confidence."
    )


def _signal_card(
    label: str,
    value: str,
    state: str,
    note: str,
    tone: str,
) -> str:
    return (
        f'<div class="signal signal-{_h(tone)}">'
        f'<span class="signal-icon" aria-hidden="true">{_status_icon(tone)}</span>'
        f'<span class="signal-label">{_h(label)}</span>'
        f'<span class="signal-value">{_h(value)}</span>'
        f'<span class="signal-state">{_h(state)}</span>'
        f'<span class="signal-note">{_h(note)}</span>'
        "</div>"
    )


def _status_icon(tone: str) -> str:
    if tone == "good":
        return "&#10003;"
    if tone == "bad":
        return "&#10005;"
    if tone == "expected":
        return "&#9632;"
    return "!"


def _hero_meta(verdict: ReportVerdict, title: str) -> str:
    return (
        '<div class="hero-meta">'
        '<span>Gate classification</span>'
        f'<strong>{_h(verdict.headline)}</strong>'
        '<span>Core thesis</span>'
        f'<strong>{_h(THESIS_TITLE)}</strong>'
        "</div>"
        + _report_label(title)
    )


def _executive_extract(
    *,
    visible_state: str,
    ci_gate_result: str,
    finding: Finding | None,
    missing_links: tuple[MissingEvidenceLinkDiff, ...],
    affected_summary: ProcessAffectedSummary,
) -> str:
    return "\n".join(
        (
            '<div class="hero-summary-row">',
            '<section class="executive-extract" aria-labelledby="executive-extract">',
            '<h2 id="executive-extract">Executive TL;DR</h2>',
            "<ul>",
            (
                "<li><strong>Decision drift:</strong> "
                f"{_h(_decision_drift_summary(visible_state))}</li>"
            ),
            (
                "<li><strong>Process regression:</strong> "
                f"{_h(_process_regression_summary(finding, missing_links))}</li>"
            ),
            (
                "<li><strong>Process scope:</strong> "
                f"{_h(_executive_process_scope_summary(affected_summary))}</li>"
            ),
            (
                "<li><strong>Release action:</strong> "
                f"{_h(_release_action_summary(ci_gate_result))}</li>"
            ),
            "</ul>",
            "</section>",
            '<section class="trust-boundary-note" aria-labelledby="trust-boundary">',
            '<h2 id="trust-boundary">Trust Boundary</h2>',
            "<p>Local deterministic evidence for human review.</p>",
            f"<p>{_h(CLAIM_BOUNDARY_SENTENCES[0])} {_h(CLAIM_BOUNDARY_SENTENCES[1])}</p>",
            "</section>",
            "</div>",
        )
    )


def _decision_drift_summary(visible_state: str) -> str:
    if visible_state == "preserved":
        return "none observed in recommendation/outcome fields."
    if visible_state == GateState.not_evaluated.value:
        return "not evaluated for this artifact."
    return "visible decision fields changed."


def _process_regression_summary(
    finding: Finding | None,
    missing_links: tuple[MissingEvidenceLinkDiff, ...],
) -> str:
    if missing_links:
        claim = missing_links[0].claim_id
        control = _finding_control(finding)
        return f"{claim} lost its required evidence link ({control})."
    if finding is not None:
        return f"{finding.control_id} reported {finding.state.value}."
    return "none observed."


def _release_action_summary(ci_gate_result: str) -> str:
    if ci_gate_result == "blocked":
        return "candidate regression caught and blocked in CI before release."
    if ci_gate_result == "not blocked":
        return "candidate was not blocked by the CI gate."
    return f"CI gate result: {ci_gate_result}."


def _executive_process_scope_summary(summary: ProcessAffectedSummary) -> str:
    summary_text = f"{_process_scope_value(summary)}; {_process_scope_note(summary)}"
    if summary.unscoped_finding_count:
        summary_text += f"; findings recorded {_process_finding_scope_phrase(summary)}"
    return summary_text


def _decision_delta_value(baseline: RunSet, candidate: RunSet) -> str:
    pairs = _paired_runs(baseline, candidate)
    if not pairs:
        return "not evaluated"
    changed = sum(
        int(base.recommendation != cand.recommendation)
        + int(base.outcome != cand.outcome)
        for base, cand in pairs
    )
    noun = "field" if changed == 1 else "fields"
    return f"{changed} decision {noun} changed"


def _decision_delta_state(baseline: RunSet, candidate: RunSet) -> str:
    pairs = _paired_runs(baseline, candidate)
    if not pairs:
        return GateState.not_evaluated.value
    if _decision_delta_value(baseline, candidate).startswith("0 "):
        return "no drift"
    return "changed"


def _decision_delta_note(baseline: RunSet, candidate: RunSet) -> str:
    pairs = _paired_runs(baseline, candidate)
    if not pairs:
        return "recommendation/outcome fields were not paired"
    case_count = len(pairs)
    noun = "case" if case_count == 1 else "cases"
    return f"recommendation/outcome across {case_count} {noun}"


def _decision_delta_tone(baseline: RunSet, candidate: RunSet) -> str:
    return "good" if _decision_delta_state(baseline, candidate) == "no drift" else "bad"


def _evidence_invariant_value(
    missing_links: tuple[MissingEvidenceLinkDiff, ...],
    process_state: str,
) -> str:
    if missing_links:
        return _missing_link_card_value(missing_links)
    if process_state in {"caught", "observed"}:
        return "failed"
    return "not observed"


def _evidence_invariant_state(
    missing_links: tuple[MissingEvidenceLinkDiff, ...],
    process_state: str,
) -> str:
    if missing_links or process_state in {"caught", "observed"}:
        return "failed invariant"
    return process_state


def _evidence_invariant_tone(state: str) -> str:
    if state == "failed invariant":
        return "bad"
    if state in {"not observed", "not evaluated"}:
        return "good"
    return "warn"


def _evidence_invariant_note(finding: Finding | None) -> str:
    control = _finding_control(finding)
    return f"control: {control}"


def _decision_output_value(baseline: RunSet, candidate: RunSet) -> str:
    pairs = _paired_runs(baseline, candidate)
    if not pairs:
        return "not evaluated"
    base, cand = pairs[0]
    if base.recommendation == base.outcome == cand.recommendation == cand.outcome:
        return f"{base.outcome} → {cand.outcome}"
    return f"{base.recommendation}/{base.outcome} → {cand.recommendation}/{cand.outcome}"


def _missing_link_card_value(missing_links: tuple[MissingEvidenceLinkDiff, ...]) -> str:
    if not missing_links:
        return "none observed"
    first = missing_links[0]
    return f"{first.claim_id} → none"


def _primary_finding(summary: EvaluationSummary) -> Finding | None:
    return summary.findings[0] if summary.findings else None


def _finding_control(finding: Finding | None) -> str:
    return finding.control_id if finding is not None else "process invariant layer"


def _verdict_section(
    *,
    verdict: ReportVerdict,
    title: str,
    baseline: RunSet,
    candidate: RunSet,
    visible_state: str,
    process_state: str,
    ci_gate_result: str,
    candidate_summary: EvaluationSummary,
    missing_links: tuple[MissingEvidenceLinkDiff, ...],
    affected_summary: ProcessAffectedSummary,
) -> str:
    headline = _hero_headline(verdict, visible_state, ci_gate_result, missing_links)
    gate_value = (
        "blocked as designed" if ci_gate_result == "blocked" else ci_gate_result
    )
    finding = _primary_finding(candidate_summary)
    subheading = _hero_subheading(visible_state, missing_links)
    evidence_state = _evidence_invariant_state(missing_links, process_state)
    return _page(
        "hero-page",
        1,
        "\n".join(
            (
                '<section class="hero" aria-labelledby="report-verdict">',
                '<div class="hero-copy">',
                '<p class="eyebrow">Agent Assure Evidence Diff</p>',
                f'<h1 id="report-verdict">{_h(headline)}</h1>',
                f'<p class="subtitle">{_h(subheading)}</p>',
                _hero_meta(verdict, title),
                "</div>",
                '<div class="signal-grid">',
                _signal_card(
                    "Decision output",
                    _decision_output_value(baseline, candidate),
                    visible_state,
                    "recommendation and outcome stayed aligned",
                    "good" if visible_state == "preserved" else "bad",
                ),
                _signal_card(
                    "Decision-field delta",
                    _decision_delta_value(baseline, candidate),
                    _decision_delta_state(baseline, candidate),
                    _decision_delta_note(baseline, candidate),
                    _decision_delta_tone(baseline, candidate),
                ),
                _signal_card(
                    "Evidence invariant",
                    _evidence_invariant_value(missing_links, process_state),
                    evidence_state,
                    _evidence_invariant_note(finding),
                    _evidence_invariant_tone(evidence_state),
                ),
                _signal_card(
                    "CI gate",
                    gate_value,
                    "blocked" if ci_gate_result == "blocked" else ci_gate_result,
                    "candidate release stopped before merge",
                    "expected" if ci_gate_result == "blocked" else "warn",
                ),
                "</div>",
                _executive_extract(
                    visible_state=visible_state,
                    ci_gate_result=ci_gate_result,
                    finding=finding,
                    missing_links=missing_links,
                    affected_summary=affected_summary,
                ),
                "</section>",
            )
        ),
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
            '<table class="key-finding-table">',
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
    return _page(
        "diff-page",
        2,
        "\n".join(
            (
                '<section class="process-diff-section" aria-labelledby="process-evidence-diff">',
                '<p class="eyebrow">The diff that matters</p>',
                '<h2 id="process-evidence-diff">Process Evidence Diff</h2>',
                (
                    "<p class=\"section-lede\">"
                    "Same final approval, different governed path. Agent Assure compares "
                    "the process evidence around the decision, not just the visible answer."
                    "</p>"
                ),
                _evidence_link_diagram(missing_links, ci_gate_state="candidate blocked"),
                _key_finding_section(missing_links),
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
        ),
    )


def _evidence_link_diagram(
    missing_links: tuple[MissingEvidenceLinkDiff, ...],
    *,
    ci_gate_state: str,
) -> str:
    if missing_links:
        diff = missing_links[0]
        baseline_value = _inline_values(diff.baseline_evidence_refs)
        candidate_value = '<span class="empty">none</span>'
        claim = _h(diff.claim_id)
    else:
        baseline_value = '<span class="empty">none observed</span>'
        candidate_value = '<span class="empty">none observed</span>'
        claim = "material-claim"
    return "\n".join(
        (
            (
                '<div class="evidence-diagram" '
                'aria-label="Baseline and candidate evidence-link comparison">'
            ),
            '<div class="diagram-row diagram-row-good">',
            '<div class="diagram-label">Baseline Process</div>',
            (
                '<div class="diagram-chain">'
                f'<code>{claim}</code><span class="diagram-arrow">→</span>{baseline_value}'
                "</div>"
            ),
            (
                '<div class="diagram-state"><span aria-hidden="true">&#10003;</span> '
                "material claim has evidence</div>"
            ),
            "</div>",
            '<div class="diagram-row diagram-row-bad">',
            '<div class="diagram-label">Candidate Process</div>',
            (
                '<div class="diagram-chain">'
                f'<code>{claim}</code><span class="diagram-arrow">→</span>{candidate_value}'
                "</div>"
            ),
            (
                '<div class="diagram-state"><span aria-hidden="true">&#10005;</span> '
                "material claim evidence link missing</div>"
            ),
            "</div>",
            '<div class="diagram-row diagram-row-gate">',
            '<div class="diagram-label">CI Gate</div>',
            (
                '<div class="diagram-chain"><strong>control response</strong>'
                '<span class="diagram-arrow">→</span><code>blocked</code></div>'
            ),
            (
                '<div class="diagram-state"><span aria-hidden="true">&#9632;</span> '
                f"{_h(ci_gate_state)}</div>"
            ),
            "</div>",
            "</div>",
        )
    )


def _decision_review_page(
    baseline: RunSet,
    candidate: RunSet,
    visible_state: str,
    baseline_summary: EvaluationSummary,
    candidate_summary: EvaluationSummary,
    missing_links: tuple[MissingEvidenceLinkDiff, ...],
) -> str:
    return _page(
        "decision-page",
        3,
        "\n".join(
            (
                '<section class="page-intro" aria-labelledby="decision-review">',
                '<p class="eyebrow">Decision preserved, process failed</p>',
                '<h2 id="decision-review">Visible Output Stayed Stable</h2>',
                (
                    '<p class="section-lede">'
                    "The business decision did not change. The governance evidence "
                    "around that decision did."
                    "</p>"
                ),
                "</section>",
                _final_output_section(
                    baseline,
                    candidate,
                    visible_state,
                    baseline_summary,
                    candidate_summary,
                ),
                _findings_section(candidate_summary.findings, missing_links),
            )
        ),
    )


def _technical_evidence_page(
    baseline: RunSet,
    candidate: RunSet,
    missing_links: tuple[MissingEvidenceLinkDiff, ...],
) -> str:
    return _page(
        "technical-page",
        4,
        "\n".join(
            (
                '<section class="page-intro" aria-labelledby="technical-evidence">',
                '<p class="eyebrow">Technical appendix</p>',
                '<h2 id="technical-evidence">Before and After Traceability Detail</h2>',
                (
                    '<p class="section-lede">'
                    "Engineers can inspect claim IDs, evidence refs and sources, linked "
                    "evidence, policy states, provider/model fields, tool names, operational "
                    "counters, and measured usage summaries used in the run."
                    "</p>"
                ),
                "</section>",
                _missing_evidence_section(missing_links),
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
            )
        ),
    )


def _evidence_packet_page(
    baseline: RunSet,
    candidate: RunSet,
    comparison_summary: ComparisonSummary,
    ci_gate_result: str,
    packet: EvidencePacket | None,
    artifact_paths: Mapping[str, PathValue] | None,
) -> str:
    return _page(
        "packet-page",
        5,
        "\n".join(
            (
                '<section class="page-intro" aria-labelledby="packet-proof">',
                '<p class="eyebrow">Evidence packet appendix</p>',
                '<h2 id="packet-proof">Release Proofs for Review</h2>',
                (
                    '<p class="section-lede">'
                    "Fixture equivalence, artifact paths, and SHA-256 digests make the "
                    "blocking decision reproducible without exposing local machine paths."
                    "</p>"
                ),
                "</section>",
                '<div class="packet-grid">',
                _comparison_section(comparison_summary, baseline, candidate),
                _fixture_equivalence_section(comparison_summary),
                _ci_gate_section(ci_gate_result, packet),
                _claim_boundary_section(),
                "</div>",
                _artifact_paths_section(artifact_paths),
                _artifact_digests_section(packet),
            )
        ),
    )


def _process_evidence_section(
    section_id: str,
    heading: str,
    runset: RunSet,
    *,
    section_class: str = "",
) -> str:
    rows = "\n".join(_process_evidence_row(run) for run in sorted(runset.runs, key=_case_key))
    body = rows or '<tr><td colspan="10" class="empty">No runs were recorded.</td></tr>'
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
            "<th>Operational metrics</th><th>Measured usage</th>"
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


def _comparison_section(
    comparison_summary: ComparisonSummary,
    baseline: RunSet,
    candidate: RunSet,
) -> str:
    retrieval_corpus_digest_html = _retrieval_corpus_digest_html(baseline, candidate)
    retrieval_corpus_digest_detail = (
        ()
        if retrieval_corpus_digest_html is None
        else (
            _detail_html(
                "Retrieval corpus digest",
                retrieval_corpus_digest_html,
            ),
        )
    )
    usage_delta_detail = (
        ()
        if comparison_summary.usage_delta is None
        else (
            _detail(
                "Measured usage delta",
                format_usage_delta(comparison_summary.usage_delta),
            ),
        )
    )
    return "\n".join(
        (
            '<section aria-labelledby="comparison-classification">',
            '<h2 id="comparison-classification">Comparison Classification</h2>',
            '<dl class="summary-grid">',
            _detail("Classification", comparison_summary.classification.value),
            _detail("Baseline state", comparison_summary.baseline_state.value),
            _detail("Candidate state", comparison_summary.candidate_state.value),
            *retrieval_corpus_digest_detail,
            *usage_delta_detail,
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


def _retrieval_corpus_digest_html(baseline: RunSet, candidate: RunSet) -> str | None:
    pairs = _paired_runs(baseline, candidate)
    if not pairs:
        if _has_retrieval_corpus_digest(baseline) or _has_retrieval_corpus_digest(candidate):
            return _h(GateState.not_evaluated.value)
        return None
    observed_pairs = tuple(
        (
            base.case_id,
            base.provenance.retrieval_corpus_digest,
            cand.provenance.retrieval_corpus_digest,
        )
        for base, cand in pairs
        if base.provenance.retrieval_corpus_digest is not None
        or cand.provenance.retrieval_corpus_digest is not None
    )
    if not observed_pairs:
        return None
    changed = tuple(
        (case_id, baseline_digest, candidate_digest)
        for case_id, baseline_digest, candidate_digest in observed_pairs
        if baseline_digest != candidate_digest
    )
    if not changed:
        digest = observed_pairs[0][1] or observed_pairs[0][2] or "not recorded"
        case_count = len(observed_pairs)
        noun = "case" if case_count == 1 else "cases"
        return (
            '<span class="state-good">unchanged</span> '
            f'<span class="empty">across {_h(case_count)} {_h(noun)}</span><br>'
            f"<code>{_h(digest)}</code>"
        )
    values = tuple(
        _retrieval_corpus_digest_change_item(case_id, baseline_digest, candidate_digest)
        for case_id, baseline_digest, candidate_digest in changed
    )
    return (
        '<span class="state-bad">changed</span><br>'
        + _summarized_html_items(values, empty="none")
    )


def _retrieval_corpus_digest_change_item(
    case_id: str,
    baseline_digest: str | None,
    candidate_digest: str | None,
) -> str:
    return (
        f"<code>{_h(case_id)}</code>: baseline "
        f"{_digest_value_html(baseline_digest)} candidate "
        f"{_digest_value_html(candidate_digest)}"
    )


def _digest_value_html(digest: str | None) -> str:
    if digest is None:
        return '<span class="empty">&lt;unset&gt;</span>'
    return f"<code>{_h(digest)}</code>"


def _has_retrieval_corpus_digest(runset: RunSet) -> bool:
    return any(run.provenance.retrieval_corpus_digest is not None for run in runset.runs)


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
    return "".join(
        (
            "<tr>",
            _labeled_cell("Case", _h(diff.case_id)),
            _labeled_cell("Material claim", f"<code>{_h(diff.claim_id)}</code>"),
            _labeled_cell(
                "Baseline link",
                _link_expression(diff.claim_id, diff.baseline_evidence_refs),
            ),
            _labeled_cell(
                "Candidate link",
                _link_expression(diff.claim_id, diff.candidate_evidence_refs),
            ),
            _labeled_cell(
                "Reason",
                (
                    '<code class="wrap-token">'
                    f"{_h(ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE.value)}</code>"
                ),
            ),
            "</tr>",
        )
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
        f"<td>{_status_badge(state)}</td>"
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
    return f"<code>{_h(claim_id)}</code> → {_inline_values(evidence_refs)}"


def _removed_link_expression(claim_id: str) -> str:
    return (
        '<span class="diff-removed">'
        '<span class="diff-marker">-</span> '
        f'<span class="diff-removed-token"><code>{_h(claim_id)}</code></span>'
        ' <span>→</span> <span class="empty">none</span>'
        "</span>"
    )


def _process_signature(run: AgentRunRecord) -> tuple[object, ...]:
    return (
        _claim_ids(run),
        _evidence_ref_signature(run),
        tuple(_linked_claim_evidence(run).items()),
        _policy_states(run),
        _human_review_state(run),
        _provider_model(run),
        run.tools,
        _operational_metrics_signature(run),
        _usage_summary_signature(run),
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
    if _evidence_ref_signature(baseline) != _evidence_ref_signature(candidate):
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
    if _operational_metrics_signature(baseline) != _operational_metrics_signature(candidate):
        changed.append("operational counters")
    if _usage_summary_signature(baseline) != _usage_summary_signature(candidate):
        changed.append("measured usage")
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
                _inline_values(_evidence_ref_display_values(run)),
            ),
            _labeled_cell("Linked claims", _inline_values(linked_claim_ids)),
            _labeled_cell("Policy states", _inline_values(_policy_states(run))),
            _labeled_cell("Human review", _h(_human_review_state(run))),
            _labeled_cell("Provider/model", _h(_provider_model(run) or "not recorded")),
            _labeled_cell("Tools", _inline_values(run.tools)),
            _labeled_cell("Operational metrics", _h(_operational_metrics_display(run))),
            _labeled_cell("Measured usage", _h(_usage_summary_display(run))),
            "</tr>",
        )
    )


def _finding_row(finding: Finding) -> str:
    return (
        "<tr>"
        f"<td>{_h(finding.case_id or 'unscoped')}</td>"
        f"<td>{_h(finding.control_id)}</td>"
        f"<td>{_h(finding.target)}</td>"
        f'<td><code class="wrap-token">{_h(finding.reason_code.value)}</code></td>'
        f"<td>{_status_badge(finding.state.value)}</td>"
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


def _evidence_ref_signature(run: AgentRunRecord) -> tuple[tuple[str, str], ...]:
    return tuple(sorted((ref.ref_id, ref.source_id) for ref in run.evidence_refs))


def _evidence_ref_display_values(run: AgentRunRecord) -> tuple[str, ...]:
    return tuple(f"{ref.ref_id} source={ref.source_id}" for ref in run.evidence_refs)


def _operational_metrics_signature(run: AgentRunRecord) -> tuple[int | None, ...]:
    return (
        run.attempt_count,
        run.retry_count,
        run.rate_limit_events,
        run.latency_ms,
    )


def _usage_summary_signature(run: AgentRunRecord) -> dict[str, object] | None:
    if run.usage_summary is None:
        return None
    return run.usage_summary.model_dump(mode="json")


def _operational_metrics_display(run: AgentRunRecord) -> str:
    values = {
        "attempts": run.attempt_count,
        "retries": run.retry_count,
        "rate_limits": run.rate_limit_events,
        "latency_ms": run.latency_ms,
    }
    observed = [f"{name}={value}" for name, value in values.items() if value is not None]
    if not observed:
        return "not recorded"
    return "; ".join(observed)


def _usage_summary_display(run: AgentRunRecord) -> str:
    summary = run.usage_summary
    if summary is None:
        return "not observed"
    values = (
        f"tokens={_observed_int(summary.total_tokens)}",
        f"tools={_observed_int(summary.total_tool_calls)}",
        f"retries={_observed_int(summary.total_retries)}",
        f"latency_ms={_observed_int(summary.total_latency_ms)}",
        f"cost_micro_usd={_observed_int(summary.estimated_cost_microusd)}",
    )
    return "; ".join(values)


def _observed_int(value: int | None) -> str:
    if value is None:
        return "not_observed"
    return str(value)


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


def _summarized_html_items(values: tuple[str, ...], *, empty: str) -> str:
    if not values:
        return f'<span class="empty">{_h(empty)}</span>'
    shown = values[:MAX_INLINE_ITEMS]
    prefix = f"{len(values)} item" if len(values) == 1 else f"{len(values)} items"
    if len(values) > MAX_INLINE_ITEMS:
        prefix = f"{prefix}; first {len(shown)} shown"
    items = "".join(f"<li>{value}</li>" for value in shown)
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
    polished_display = without_external_urls.replace("->", "→")
    return escape(polished_display, quote=True)
