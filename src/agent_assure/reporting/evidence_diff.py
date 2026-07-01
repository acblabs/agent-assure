from __future__ import annotations

from html import escape
from pathlib import Path

from agent_assure.privacy.redaction import redact_text
from agent_assure.schema.common import GateState
from agent_assure.schema.comparison import ComparisonSummary
from agent_assure.schema.evaluation import EvaluationSummary, Finding
from agent_assure.schema.packet import EvidencePacket
from agent_assure.schema.run import AgentRunRecord, RunSet

CLAIM_BOUNDARY_SENTENCES = (
    "This report is not a compliance attestation.",
    "This artifact does not certify safety.",
)


def write_evidence_diff_html(
    *,
    baseline: RunSet,
    candidate: RunSet,
    baseline_summary: EvaluationSummary,
    candidate_summary: EvaluationSummary,
    comparison_summary: ComparisonSummary,
    out: Path,
    packet: EvidencePacket | None = None,
    title: str = "agent-assure evidence diff",
) -> Path:
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        render_evidence_diff_html(
            baseline=baseline,
            candidate=candidate,
            baseline_summary=baseline_summary,
            candidate_summary=candidate_summary,
            comparison_summary=comparison_summary,
            packet=packet,
            title=title,
        ),
        encoding="utf-8",
        newline="\n",
    )
    return out


def render_evidence_diff_html(
    *,
    baseline: RunSet,
    candidate: RunSet,
    baseline_summary: EvaluationSummary,
    candidate_summary: EvaluationSummary,
    comparison_summary: ComparisonSummary,
    packet: EvidencePacket | None = None,
    title: str = "agent-assure evidence diff",
) -> str:
    visible_state = _visible_output_equivalence(baseline, candidate)
    findings = tuple(candidate_summary.findings)
    missing_claims = _missing_claim_links(baseline, candidate)
    rows = "\n".join(_visible_output_rows(baseline, candidate))
    finding_rows = "\n".join(_finding_row(finding) for finding in findings)
    missing_rows = "\n".join(
        _missing_claim_row(case_id, claim_id) for case_id, claim_id in missing_claims
    )
    digest_rows = "\n".join(
        _digest_row(digest.role, digest.sha256)
        for digest in (packet.artifact_digests if packet else ())
    )

    return "\n".join(
        (
            "<!doctype html>",
            '<html lang="en">',
            "<head>",
            '<meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            f"<title>{_h(title)}</title>",
            "<style>",
            _css(),
            "</style>",
            "</head>",
            "<body>",
            "<main>",
            f"<h1>{_h(title)}</h1>",
            '<section aria-labelledby="boundary">',
            '<h2 id="boundary">Claim Boundary</h2>',
            "".join(f"<p>{_h(sentence)}</p>" for sentence in CLAIM_BOUNDARY_SENTENCES),
            "</section>",
            '<section aria-labelledby="summary">',
            '<h2 id="summary">Summary</h2>',
            "<dl>",
            _detail("Baseline run set", baseline.runset_id),
            _detail("Candidate run set", candidate.runset_id),
            _detail("Visible output equivalence", visible_state),
            _detail("Case coverage", _case_coverage(baseline, candidate)),
            _detail("Baseline state", baseline_summary.state.value),
            _detail("Candidate state", candidate_summary.state.value),
            _detail("Comparison classification", comparison_summary.classification.value),
            _detail("Fixture equivalence", comparison_summary.fixture_equivalence_state.value),
            _detail("Evidence packet", packet.packet_id if packet else "not provided"),
            "</dl>",
            "</section>",
            '<section aria-labelledby="visible-output">',
            '<h2 id="visible-output">Visible Final Output</h2>',
            "<table>",
            "<thead><tr>"
            "<th>Case</th><th>Baseline recommendation</th><th>Candidate recommendation</th>"
            "<th>Baseline outcome</th><th>Candidate outcome</th><th>Equivalence</th>"
            "</tr></thead>",
            f"<tbody>{rows}</tbody>",
            "</table>",
            "</section>",
            '<section aria-labelledby="process-regression">',
            '<h2 id="process-regression">Process Regression Findings</h2>',
            _findings_table(finding_rows),
            "</section>",
            '<section aria-labelledby="missing-evidence">',
            '<h2 id="missing-evidence">Missing Evidence Links</h2>',
            _missing_claims_table(missing_rows),
            "</section>",
            '<section aria-labelledby="digests">',
            '<h2 id="digests">Packet Artifact Digests</h2>',
            _digests_table(digest_rows),
            "</section>",
            "</main>",
            "</body>",
            "</html>",
            "",
        )
    )


def _css() -> str:
    return """
:root {
  color-scheme: light;
  font-family: Arial, Helvetica, sans-serif;
  line-height: 1.45;
}
body {
  margin: 0;
  color: #1f2933;
  background: #f7f8fa;
}
main {
  max-width: 1100px;
  margin: 0 auto;
  padding: 32px 20px 48px;
}
h1, h2 {
  color: #102030;
  letter-spacing: 0;
}
h1 {
  font-size: 32px;
  margin: 0 0 24px;
}
h2 {
  font-size: 19px;
  margin: 0 0 12px;
}
section {
  margin: 0 0 22px;
  padding: 18px;
  background: #ffffff;
  border: 1px solid #d7dde4;
  border-radius: 6px;
}
dl {
  display: grid;
  grid-template-columns: minmax(180px, 260px) 1fr;
  gap: 8px 16px;
  margin: 0;
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
  border: 1px solid #d7dde4;
  text-align: left;
  vertical-align: top;
  overflow-wrap: anywhere;
}
th {
  background: #eef2f6;
}
.state-pass {
  color: #166534;
  font-weight: 700;
}
.state-fail {
  color: #991b1b;
  font-weight: 700;
}
.empty {
  color: #5f6b7a;
}
""".strip()


def _detail(label: str, value: str) -> str:
    return f"<dt>{_h(label)}</dt><dd>{_h(value)}</dd>"


def _findings_table(rows: str) -> str:
    if not rows:
        return '<p class="empty">No candidate findings were recorded.</p>'
    return (
        "<table>"
        "<thead><tr><th>Case</th><th>Control</th><th>Target</th>"
        "<th>Reason code</th><th>State</th></tr></thead>"
        f"<tbody>{rows}</tbody>"
        "</table>"
    )


def _missing_claims_table(rows: str) -> str:
    if not rows:
        return '<p class="empty">No missing claim evidence links were observed.</p>'
    return (
        "<table>"
        "<thead><tr><th>Case</th><th>Claim missing an evidence link</th></tr></thead>"
        f"<tbody>{rows}</tbody>"
        "</table>"
    )


def _digests_table(rows: str) -> str:
    if not rows:
        return '<p class="empty">No packet artifact digests were provided.</p>'
    return (
        "<table>"
        "<thead><tr><th>Role</th><th>SHA-256</th></tr></thead>"
        f"<tbody>{rows}</tbody>"
        "</table>"
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
        f"<td class=\"{_state_class(state)}\">{_h(state)}</td>"
        "</tr>"
    )


def _finding_row(finding: Finding) -> str:
    return (
        "<tr>"
        f"<td>{_h(finding.case_id)}</td>"
        f"<td>{_h(finding.control_id)}</td>"
        f"<td>{_h(finding.target)}</td>"
        f"<td>{_h(finding.reason_code.value)}</td>"
        f"<td class=\"{_state_class(finding.state.value)}\">{_h(finding.state.value)}</td>"
        "</tr>"
    )


def _missing_claim_row(case_id: str, claim_id: str) -> str:
    return f"<tr><td>{_h(case_id)}</td><td>{_h(claim_id)}</td></tr>"


def _digest_row(role: str, sha256: str) -> str:
    return f"<tr><td>{_h(role)}</td><td>{_h(sha256)}</td></tr>"


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


def _missing_claim_links(baseline: RunSet, candidate: RunSet) -> tuple[tuple[str, str], ...]:
    missing: list[tuple[str, str]] = []
    for base, cand in _paired_runs(baseline, candidate):
        baseline_claims = _linked_claim_ids(base)
        candidate_claims = _linked_claim_ids(cand)
        for claim_id in sorted(baseline_claims - candidate_claims):
            missing.append((base.case_id, claim_id))
    return tuple(missing)


def _linked_claim_ids(run: AgentRunRecord) -> set[str]:
    return {link.claim_id for link in run.claim_evidence_links}


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


def _state_class(state: str) -> str:
    if state == GateState.pass_.value or state == "preserved":
        return "state-pass"
    if state == GateState.fail.value or state == "changed":
        return "state-fail"
    return ""


def _h(value: str) -> str:
    return escape(redact_text(value), quote=True)
