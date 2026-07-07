from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from agent_assure.authoring.compiler import compile_suite  # noqa: E402
from agent_assure.compare.runsets import compare_runsets  # noqa: E402
from agent_assure.evaluation.evaluator import evaluate_runset  # noqa: E402
from agent_assure.runner.fixture_runner import load_variant_config, run_suite  # noqa: E402
from agent_assure.schema.common import (  # noqa: E402
    ComparisonClassification,
    GateState,
    ReasonCode,
)
from agent_assure.schema.export import SCHEMA_MODELS  # noqa: E402
from agent_assure.schema.run import AgentRunRecord  # noqa: E402

PUBLIC_DOCS = [
    ROOT / "README.md",
    ROOT / "FEATURES.md",
    ROOT / "CHANGELOG.md",
    ROOT / "docs" / "showcase.md",
    ROOT / "docs" / "limitations.md",
    ROOT / "docs" / "live_mode_roadmap.md",
    ROOT / "docs" / "measurement" / "executive_one_pager.md",
    ROOT / "docs" / "measurement" / "experiment_protocol.md",
    ROOT / "docs" / "measurement" / "measurement_brief_abstract.md",
    ROOT / "docs" / "measurement" / "nist_agentic_measurement_use_case.md",
    ROOT / "docs" / "standards" / "freshness_checklist.md",
    ROOT / "docs" / "standards" / "otel_contribution_candidate.md",
    ROOT / "docs" / "standards" / "otel_genai_gap_analysis.md",
    ROOT / "paper" / "invariant_based_change_control.md",
    ROOT / "paper" / "invariant_based_change_control_abstract.md",
    ROOT / "paper" / "reproducibility_appendix.md",
]

CURRENT_TERMINOLOGY_DOCS = (
    Path("README.md"),
    Path("docs/index.md"),
    Path("docs/evidence_diff.md"),
    Path("docs/demo_flagship.md"),
    Path("docs/showcase.md"),
    Path("docs/social/demo_video_script.md"),
    Path("docs/release_evidence.md"),
    Path("docs/release_pypi.md"),
)

DEPRECATED_REPORT_TERMINOLOGY_PATTERNS = (
    re.compile(r"\bfinal[- ]output equivalence\b", re.IGNORECASE),
    re.compile(r"\bvisible output equivalence\b", re.IGNORECASE),
    re.compile(r"\bFinal-Output Comparison\b"),
    re.compile(r"\bVisible output equivalence\b"),
)

FORBIDDEN_POSITIVE_PATTERNS = [
    re.compile(r"\bNIST[- ]endorsed\b", re.IGNORECASE),
    re.compile(r"\bOpenTelemetry[- ]native\b", re.IGNORECASE),
    re.compile(
        r"\bcertif(?:y|ies|ied|ication)\s+(?:regulatory\s+)?(?:safety|compliance)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\bclinical(?:ly)? validated\b", re.IGNORECASE),
    re.compile(r"\bregulatory compliance certified\b", re.IGNORECASE),
]

COUNTERFACTUAL_RAG_FORBIDDEN_PATTERNS = (
    re.compile(r"\bsemantic equivalence (?:is|was) proven\b", re.IGNORECASE),
    re.compile(r"\bautomatically proves? semantic equivalence\b", re.IGNORECASE),
    re.compile(r"\bcertifies semantic equivalence\b", re.IGNORECASE),
)

REQUIRED_LIVE_PROTOCOL_SECTIONS = (
    "## Scope",
    "## Experimental Unit",
    "## Baseline Handling",
    "## Hypotheses",
    "## Endpoints",
    "## Advanced Statistical Endpoint Plans",
    "## Cross-Window Monitoring",
    "## Trajectory and Event Processes",
    "## Sample-Size Plan",
    "## Confidence-Interval Method",
    "## Interim Looks and Stopping Rules",
    "## Retry and Exclusion Rules",
    "## Provider-Version Capture",
    "## Rate-Limit Handling",
    "## Cost Budgets",
    "## Live-Run Ethics and Safety Limits",
    "## Machine-Readable Protocol Record",
    "## Required Artifacts Before Execution",
    "## Interpretation Boundary",
)

REQUIRED_CLAIM_IDS = {
    "offline-fixture-mode",
    "strict-schemas",
    "json-schema-parity",
    "yaml-lexeme-preservation",
    "canonical-digests",
    "hmac-sensitive-correlation",
    "privacy-redaction",
    "otel-span-plan-preview",
    "flagship-showcase-demo",
    "publishable-review-artifacts",
    "standards-freshness-review",
    "live-statistical-protocol",
    "live-stochastic-evaluation",
    "live-advanced-statistics",
    "live-drift-monitoring",
    "live-trajectory-analysis",
}

FLAGSHIP_README_DIAGRAM_HEADING = "### Flagship regression at a glance"
FLAGSHIP_SUITE = Path("examples/prior_auth_synthetic/suite.yaml")
FLAGSHIP_BASELINE_VARIANT = Path("examples/prior_auth_synthetic/variants/baseline.yaml")
FLAGSHIP_CANDIDATE_VARIANT = Path(
    "examples/prior_auth_synthetic/variants/candidate_evidence_normalization.yaml"
)
FLAGSHIP_CASE_ID = "shared-source-multi-claim"
FLAGSHIP_README_DIAGRAM_REQUIRED_EDGES = (
    (
        r'\bEquiv\b\["Fixture equivalence: pass"\]\s*-->\s*'
        r'\bCompare\b\["Baseline-to-candidate comparison"\]'
    ),
    r"\bPass\b\s*-->\s*\bCompare\b",
    r"\bFail\b\s*-->\s*\bCompare\b",
    r"\bTension\b\s*-->\s*\bCompare\b",
    r"\bCompare\b\s*-->\s*\bNewFailure\b",
)


@dataclass(frozen=True)
class FlagshipShowcaseFacts:
    baseline_recommendation: str
    baseline_outcome: str
    candidate_recommendation: str
    candidate_outcome: str
    missing_claim_id: str
    baseline_state: GateState
    candidate_state: GateState
    candidate_reason_code: ReasonCode
    classification: ComparisonClassification
    fixture_equivalence_state: GateState


def main() -> int:
    failures: list[str] = []
    failures.extend(_check_public_docs_exist())
    failures.extend(_check_forbidden_claims())
    failures.extend(_check_deprecated_report_terminology())
    failures.extend(_check_changelog())
    failures.extend(_check_claim_traceability())
    failures.extend(_check_schema_reference())
    failures.extend(_check_reason_codes())
    failures.extend(_check_flagship_readme_diagram())
    failures.extend(_check_counterfactual_rag_boundary())
    failures.extend(_check_otel_mapping())
    failures.extend(_check_live_protocol())
    failures.extend(_check_standards_freshness())
    if failures:
        for failure in failures:
            print(f"docs-alignment: {failure}", file=sys.stderr)
        return 1
    print("docs-alignment: ok")
    return 0


def _check_public_docs_exist() -> list[str]:
    return [
        f"missing required document: {path.relative_to(ROOT)}"
        for path in PUBLIC_DOCS
        if not path.exists()
    ]


def _check_forbidden_claims() -> list[str]:
    failures: list[str] = []
    for path in PUBLIC_DOCS:
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        for pattern in FORBIDDEN_POSITIVE_PATTERNS:
            if pattern.search(text):
                failures.append(
                    f"forbidden positive claim in {path.relative_to(ROOT)}: {pattern.pattern}"
                )
    return failures


def _check_deprecated_report_terminology() -> list[str]:
    failures: list[str] = []
    for relative_path in CURRENT_TERMINOLOGY_DOCS:
        path = ROOT / relative_path
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        for pattern in DEPRECATED_REPORT_TERMINOLOGY_PATTERNS:
            if pattern.search(text):
                failures.append(
                    "deprecated report terminology in "
                    f"{relative_path.as_posix()}: {pattern.pattern}"
                )
    return failures


def _check_changelog() -> list[str]:
    changelog = ROOT / "CHANGELOG.md"
    if "## Unreleased" not in changelog.read_text(encoding="utf-8"):
        return ["CHANGELOG.md must contain an Unreleased section"]
    return []


def _check_claim_traceability() -> list[str]:
    yaml_path = ROOT / "docs" / "claims_traceability_matrix.yaml"
    md_path = ROOT / "docs" / "claims_traceability_matrix.md"
    failures: list[str] = []
    if not yaml_path.exists():
        return ["missing docs/claims_traceability_matrix.yaml"]
    if not md_path.exists():
        failures.append("missing docs/claims_traceability_matrix.md")
    text = yaml_path.read_text(encoding="utf-8")
    for claim_id in REQUIRED_CLAIM_IDS:
        if f"id: {claim_id}" not in text:
            failures.append(f"claim traceability missing id: {claim_id}")
    return failures


def _check_schema_reference() -> list[str]:
    path = ROOT / "docs" / "schema_reference.md"
    if not path.exists():
        return ["missing docs/schema_reference.md"]
    text = path.read_text(encoding="utf-8")
    return [
        f"schema reference missing artifact kind: {kind}"
        for kind in sorted(SCHEMA_MODELS)
        if f"`{kind}`" not in text
    ]


def _check_reason_codes() -> list[str]:
    path = ROOT / "docs" / "reason_code_registry.md"
    if not path.exists():
        return ["missing docs/reason_code_registry.md"]
    text = path.read_text(encoding="utf-8")
    return [
        f"reason-code registry missing: {reason.value}"
        for reason in ReasonCode
        if f"`{reason.value}`" not in text
    ]


def _check_flagship_readme_diagram() -> list[str]:
    path = ROOT / "README.md"
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8")
    section = _markdown_heading_content(text, FLAGSHIP_README_DIAGRAM_HEADING)
    if section is None:
        return ["README.md missing flagship regression diagram section"]
    diagram = _first_fenced_block(section, "mermaid")
    if diagram is None:
        return ["README.md flagship regression section missing mermaid diagram"]

    try:
        required_snippets = _flagship_readme_diagram_required_snippets()
    except Exception as exc:
        return [f"could not derive flagship showcase facts for README diagram: {exc}"]

    failures = [
        f"README.md flagship diagram missing expected fact: {snippet}"
        for snippet in required_snippets
        if snippet not in diagram
    ]
    failures.extend(
        f"README.md flagship diagram missing expected causal edge: {pattern}"
        for pattern in FLAGSHIP_README_DIAGRAM_REQUIRED_EDGES
        if re.search(pattern, diagram) is None
    )
    if re.search(r"\bCompare\b\s*-->\s*\bEquiv\b", diagram):
        failures.append(
            "README.md flagship diagram must show fixture equivalence gating "
            "comparison, not comparison producing fixture equivalence"
        )
    return failures


def _check_counterfactual_rag_boundary() -> list[str]:
    path = ROOT / "docs" / "demo_rag.md"
    if not path.exists():
        return ["missing docs/demo_rag.md"]
    text = path.read_text(encoding="utf-8")
    normalized_text = re.sub(r"\s+", " ", text)
    failures: list[str] = []
    for needle in (
        "fixture author declares",
        "query digests",
        "required-ref coverage tracks only",
        "does not prove semantic equivalence",
    ):
        if needle not in normalized_text:
            failures.append(f"RAG demo docs missing counterfactual boundary: {needle}")
    failures.extend(
        f"RAG demo docs overclaim counterfactual capability: {pattern.pattern}"
        for pattern in COUNTERFACTUAL_RAG_FORBIDDEN_PATTERNS
        if pattern.search(normalized_text)
    )
    return failures


def _flagship_readme_diagram_required_snippets() -> tuple[str, ...]:
    facts = _derive_flagship_showcase_facts()
    return (
        (
            "Baseline output<br/>"
            f"recommendation={facts.baseline_recommendation}<br/>"
            f"outcome={facts.baseline_outcome}"
        ),
        (
            "Candidate output<br/>"
            f"recommendation={facts.candidate_recommendation}<br/>"
            f"outcome={facts.candidate_outcome}"
        ),
        "Visible answer unchanged",
        f"Baseline evidence<br/>{facts.missing_claim_id} linked",
        f"Candidate evidence<br/>{facts.missing_claim_id} missing link",
        f"Baseline evaluation: {facts.baseline_state.value}",
        f"Candidate evaluation: {facts.candidate_state.value}",
        facts.candidate_reason_code.value,
        "Output unchanged<br/>but governance invariant regressed",
        f"Classification: {facts.classification.value}",
        f"Fixture equivalence: {facts.fixture_equivalence_state.value}",
    )


def _derive_flagship_showcase_facts() -> FlagshipShowcaseFacts:
    suite_path = ROOT / FLAGSHIP_SUITE
    baseline_variant_path = ROOT / FLAGSHIP_BASELINE_VARIANT
    candidate_variant_path = ROOT / FLAGSHIP_CANDIDATE_VARIANT
    compiled = compile_suite(suite_path)
    baseline = run_suite(
        compiled,
        load_variant_config(baseline_variant_path),
        suite_path.parent,
    )
    candidate = run_suite(
        compiled,
        load_variant_config(candidate_variant_path),
        suite_path.parent,
    )
    baseline_report = evaluate_runset(compiled, baseline)
    candidate_report = evaluate_runset(compiled, candidate)
    comparison_report = compare_runsets(compiled, baseline, candidate)
    baseline_run = _run_by_case(baseline.runs, FLAGSHIP_CASE_ID)
    candidate_run = _run_by_case(candidate.runs, FLAGSHIP_CASE_ID)

    if (
        baseline_run.recommendation != candidate_run.recommendation
        or baseline_run.outcome != candidate_run.outcome
    ):
        raise ValueError("flagship visible output is no longer unchanged")

    baseline_claim_ids = _claim_ids(baseline_run)
    candidate_claim_ids = _claim_ids(candidate_run)
    missing_claim_ids = baseline_claim_ids - candidate_claim_ids
    if len(missing_claim_ids) != 1:
        raise ValueError(
            "flagship candidate must drop exactly one baseline evidence claim; "
            f"found {sorted(missing_claim_ids)}"
        )
    missing_claim_id = next(iter(missing_claim_ids))

    candidate_findings = candidate_report.candidate_vs_expectations.findings
    if len(candidate_findings) != 1:
        raise ValueError(
            "flagship candidate must produce exactly one finding; "
            f"found {len(candidate_findings)}"
        )
    finding = candidate_findings[0]
    if finding.target != f"claim:{missing_claim_id}":
        raise ValueError(
            "flagship candidate finding target does not match the missing claim: "
            f"{finding.target}"
        )

    return FlagshipShowcaseFacts(
        baseline_recommendation=baseline_run.recommendation,
        baseline_outcome=baseline_run.outcome,
        candidate_recommendation=candidate_run.recommendation,
        candidate_outcome=candidate_run.outcome,
        missing_claim_id=missing_claim_id,
        baseline_state=baseline_report.candidate_vs_expectations.state,
        candidate_state=candidate_report.candidate_vs_expectations.state,
        candidate_reason_code=finding.reason_code,
        classification=comparison_report.comparison_summary.classification,
        fixture_equivalence_state=(
            comparison_report.comparison_summary.fixture_equivalence_state
        ),
    )


def _run_by_case(
    runs: tuple[AgentRunRecord, ...],
    case_id: str,
) -> AgentRunRecord:
    for run in runs:
        if run.case_id == case_id:
            return run
    raise ValueError(f"flagship run set missing case: {case_id}")


def _claim_ids(run: AgentRunRecord) -> set[str]:
    return {claim_id for ref in run.evidence_refs for claim_id in ref.claim_ids}


def _check_otel_mapping() -> list[str]:
    docs = ROOT / "docs" / "otel_alignment.md"
    matrix = ROOT / "compat" / "otel_mapping_matrix.yaml"
    lock = ROOT / "compat" / "otel_genai_semconv.lock"
    failures: list[str] = []
    for path in (docs, matrix, lock):
        if not path.exists():
            failures.append(f"missing OTel alignment artifact: {path.relative_to(ROOT)}")
    if matrix.exists() and docs.exists():
        matrix_text = matrix.read_text(encoding="utf-8")
        docs_text = docs.read_text(encoding="utf-8")
        for attr in (
            "gen_ai.provider.name",
            "gen_ai.request.model",
            "gen_ai.tool.name",
            "agent_assure.operation.name",
            "agent_assure.run_id",
        ):
            if attr not in matrix_text or attr not in docs_text:
                failures.append(f"OTel mapping missing documented attribute: {attr}")
        if (
            "gen_ai.operation.name" not in matrix_text
            or "gen_ai.operation.name" not in docs_text
        ):
            failures.append("OTel docs must document gen_ai.operation.name as not emitted")
    return failures


def _check_live_protocol() -> list[str]:
    protocol = ROOT / "docs" / "measurement" / "experiment_protocol.md"
    roadmap = ROOT / "docs" / "live_mode_roadmap.md"
    failures: list[str] = []
    if not protocol.exists():
        return failures
    protocol_text = protocol.read_text(encoding="utf-8")
    has_status = "Protocol status:" in protocol_text and "statistical protocol" in protocol_text
    if not has_status:
        failures.append("live statistical protocol missing status line")
    failures.extend(
        _check_required_markdown_sections(
            protocol_text,
            REQUIRED_LIVE_PROTOCOL_SECTIONS,
            document_name="live statistical protocol",
            min_content_chars=80,
        )
    )
    for needle in (
        "DEFF = 1 + (m - 1) * rho",
        "effective_n = planned_observations / DEFF",
        "`confidence_level = 0.950000`",
        "tool-schema digest",
        "policy-bundle digest",
        "tokens-per-minute cap",
        "fewer than 30",
        "at least 50",
    ):
        if needle not in protocol_text:
            failures.append(f"live statistical protocol missing required content: {needle}")
    if roadmap.exists():
        roadmap_text = roadmap.read_text(encoding="utf-8")
        if "docs/measurement/experiment_protocol.md" not in roadmap_text:
            failures.append("live roadmap missing protocol document link")
    return failures


def _check_required_markdown_sections(
    text: str,
    sections: tuple[str, ...],
    *,
    document_name: str,
    min_content_chars: int,
) -> list[str]:
    failures: list[str] = []
    for section in sections:
        content = _markdown_section_content(text, section)
        if content is None:
            failures.append(f"{document_name} missing section: {section}")
            continue
        compact_content = re.sub(r"\s+", "", content)
        if len(compact_content) < min_content_chars:
            failures.append(f"{document_name} section is too short: {section}")
    return failures


def _markdown_section_content(text: str, section: str) -> str | None:
    headings = _markdown_level2_headings(text)
    section_index = next(
        (index for index, heading in enumerate(headings) if heading[0] == section),
        None,
    )
    if section_index is None:
        return None
    content_start = headings[section_index][2]
    content_end = (
        headings[section_index + 1][1]
        if section_index + 1 < len(headings)
        else len(text)
    )
    return text[content_start:content_end].strip()


def _markdown_heading_content(text: str, heading: str) -> str | None:
    headings = _markdown_headings(text)
    section_index = next(
        (index for index, current in enumerate(headings) if current[0] == heading),
        None,
    )
    if section_index is None:
        return None
    _, _, content_start, level = headings[section_index]
    content_end = len(text)
    for _, heading_start, _, next_level in headings[section_index + 1 :]:
        if next_level <= level:
            content_end = heading_start
            break
    return text[content_start:content_end].strip()


def _first_fenced_block(text: str, info_string: str) -> str | None:
    pattern = re.compile(
        rf"^[ \t]*```{re.escape(info_string)}[ \t]*\r?\n"
        r"(.*?)"
        r"^[ \t]*```[ \t]*$",
        re.MULTILINE | re.DOTALL,
    )
    match = pattern.search(text)
    return match.group(1).strip() if match else None


def _markdown_level2_headings(text: str) -> list[tuple[str, int, int]]:
    return [
        (heading, heading_start, content_start)
        for heading, heading_start, content_start, level in _markdown_headings(text)
        if level == 2
    ]


def _markdown_headings(text: str) -> list[tuple[str, int, int, int]]:
    headings: list[tuple[str, int, int, int]] = []
    in_fence = False
    fence_char = ""
    fence_len = 0
    offset = 0
    for line in text.splitlines(keepends=True):
        stripped_line = line.rstrip("\r\n")
        fence = re.match(r"^[ \t]{0,3}([`~]{3,})", stripped_line)
        if fence:
            marker = fence.group(1)
            if not in_fence:
                in_fence = True
                fence_char = marker[0]
                fence_len = len(marker)
            elif marker[0] == fence_char and len(marker) >= fence_len:
                in_fence = False
                fence_char = ""
                fence_len = 0
            offset += len(line)
            continue
        if not in_fence:
            heading = re.match(r"^(#{1,6})\s+\S", stripped_line)
            if heading:
                headings.append(
                    (
                        stripped_line.strip(),
                        offset,
                        offset + len(line),
                        len(heading.group(1)),
                    )
                )
        offset += len(line)
    return headings


def _check_standards_freshness() -> list[str]:
    checklist = ROOT / "docs" / "standards" / "freshness_checklist.md"
    gap = ROOT / "docs" / "standards" / "otel_genai_gap_analysis.md"
    candidate = ROOT / "docs" / "standards" / "otel_contribution_candidate.md"
    lock = ROOT / "compat" / "otel_genai_semconv.lock"
    failures: list[str] = []
    if not checklist.exists():
        return ["missing docs/standards/freshness_checklist.md"]
    checklist_text = checklist.read_text(encoding="utf-8")
    for needle in (
        "Freshness status: complete",
        "Last manual review:",
        "compat/otel_genai_semconv.lock",
        "compat/otel_mapping_matrix.yaml",
        "OpenTelemetry GenAI",
    ):
        if needle not in checklist_text:
            failures.append(f"standards freshness checklist missing: {needle}")
    if "placeholder" in checklist_text.lower():
        failures.append("standards freshness checklist still contains placeholder language")
    if lock.exists():
        lock_text = lock.read_text(encoding="utf-8")
        for pattern in (r"commit:\s*(\S+)", r"checksum:\s*(\S+)"):
            match = re.search(pattern, lock_text)
            if match and match.group(1) not in checklist_text:
                failures.append(
                    "standards freshness checklist does not cite "
                    f"lock value: {match.group(1)}"
                )
    if candidate.exists():
        candidate_text = candidate.read_text(encoding="utf-8")
        if "Candidate status: deferred" not in candidate_text:
            failures.append("OTel contribution candidate must state deferred status")
    if gap.exists():
        gap_text = gap.read_text(encoding="utf-8")
        if "Freshness status: complete" not in gap_text:
            failures.append("OTel gap analysis must state freshness status")
        if "Current readiness: defer upstream contribution" not in gap_text:
            failures.append("OTel gap analysis must defer upstream contribution")
    return failures


if __name__ == "__main__":
    raise SystemExit(main())
