from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from agent_assure.schema.common import ReasonCode  # noqa: E402
from agent_assure.schema.export import SCHEMA_MODELS  # noqa: E402

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


def main() -> int:
    failures: list[str] = []
    failures.extend(_check_public_docs_exist())
    failures.extend(_check_forbidden_claims())
    failures.extend(_check_changelog())
    failures.extend(_check_claim_traceability())
    failures.extend(_check_schema_reference())
    failures.extend(_check_reason_codes())
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


def _markdown_level2_headings(text: str) -> list[tuple[str, int, int]]:
    headings: list[tuple[str, int, int]] = []
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
        if not in_fence and re.match(r"^##\s+\S", stripped_line):
            headings.append((stripped_line.strip(), offset, offset + len(line)))
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
