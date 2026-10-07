from __future__ import annotations

import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, get_args
from urllib.parse import unquote, urlsplit

import yaml


class _UniqueKeySafeLoader(yaml.SafeLoader):  # type: ignore[misc]
    """Safe YAML loader that rejects duplicate keys at every mapping depth."""


def _construct_unique_mapping(
    loader: _UniqueKeySafeLoader,
    node: yaml.nodes.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable mapping key",
                key_node.start_mark,
            ) from exc
        if duplicate:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.release_metadata import (  # noqa: E402
    ChangelogRelease,
    check_citation_release,
    check_readme_action_source,
    check_readme_release,
    parse_changelog,
    readme_release_action_pin,
)

SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from agent_assure.authoring.compiler import compile_suite  # noqa: E402
from agent_assure.compare.runsets import compare_runsets  # noqa: E402
from agent_assure.evaluation.evaluator import evaluate_runset  # noqa: E402
from agent_assure.onboarding.diagnostics import bounded_text  # noqa: E402
from agent_assure.policies.evidence import claim_finding_target  # noqa: E402
from agent_assure.runner.fixture_runner import load_variant_config, run_suite  # noqa: E402
from agent_assure.schema.common import (  # noqa: E402
    ComparisonClassification,
    GateState,
    ReasonCode,
)
from agent_assure.schema.efficacy import ControlEfficacyGateReason  # noqa: E402
from agent_assure.schema.export import SCHEMA_MODELS  # noqa: E402
from agent_assure.schema.live import ClaimEvidenceStatus  # noqa: E402
from agent_assure.schema.run import AgentRunRecord  # noqa: E402
from agent_assure.schema.sensitivity import EvidenceSensitivityReasonCode  # noqa: E402

PUBLIC_DOCS = [
    ROOT / "README.md",
    ROOT / "FEATURES.md",
    ROOT / "CHANGELOG.md",
    ROOT / "SECURITY.md",
    ROOT / "docs" / "showcase.md",
    ROOT / "docs" / "limitations.md",
    ROOT / "docs" / "live_mode_roadmap.md",
    ROOT / "docs" / "security_release_containment.md",
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

CLAIM_EVIDENCE_STATUS_DOCS = (
    Path("docs/schema_reference.md"),
    Path("docs/cli_contract.md"),
    Path("docs/live_calibration.md"),
    Path("CHANGELOG.md"),
    Path("docs/release_notes/v0.7.0.md"),
)
EXPECTED_CLAIM_EVIDENCE_STATUSES = (
    "not_evaluated",
    "not_applicable",
    "complete",
    "incomplete",
    "unobservable",
)

REQUIRED_SECURITY_CONTAINMENT_SECTIONS = (
    "## Authority Boundary",
    "## Intake Clock and Response Objectives",
    "## Activation and Severity",
    "## Roles and Independence",
    "## Containment Before Acceptance",
    "## Approval and Expiry",
    "## Monitoring and Reevaluation",
    "## Customer and Advisory Coordination",
    "## Escalation and Safe Failure",
    "## Evidence and Audit Record",
    "## Closure",
    "## Operator Checklist",
)

SECURITY_RISK_RECORD_SCHEMA = "agent-assure/security-correction-risk-acceptance/v1"
SECURITY_INTAKE_POLICY_ID = "agent-assure/security-vulnerability-intake/v1"
SECURITY_INTAKE_POLICY_REVISION = "v1"
SECURITY_INTAKE_CLOCK_BASIS = "earliest_report_receipt_or_internal_detection"
SECURITY_INTAKE_OBJECTIVES = {
    "critical": {
        "primary_page_delivery_minutes": 5,
        "fallback_page_after_no_ack_minutes": 15,
        "acknowledgement_minutes": 60,
        "initial_assessment_minutes": 240,
        "containment_or_safe_state_minutes": 240,
    },
    "high": {
        "acknowledgement_minutes": 240,
        "initial_assessment_minutes": 1440,
        "containment_or_safe_state_minutes": 1440,
    },
}
NON_AUTHORIZING_ACTIONS = (
    "merge",
    "tag_creation",
    "signing",
    "github_release",
    "testpypi_publication",
    "pypi_publication",
    "release_gate_exception",
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

MARKDOWN_INLINE_IMAGE_PATTERN = re.compile(
    r"!\[[^\]\r\n]*\]\(\s*"
    r"(?:<(?P<angle_target>[^>\r\n]+)>|(?P<plain_target>[^\s)\r\n]+))",
)
HTML_IMAGE_PATTERN = re.compile(
    r"""<img\b[^>]*?\bsrc\s*=\s*"""
    r"""(?:"(?P<double_quoted_target>[^"]*)"|'(?P<single_quoted_target>[^']*)'|"""
    r"""(?P<unquoted_target>[^\s>]+))""",
    re.IGNORECASE | re.DOTALL,
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
    failures.extend(_check_readme_local_image_assets())
    failures.extend(_check_forbidden_claims())
    failures.extend(_check_deprecated_report_terminology())
    failures.extend(_check_changelog())
    failures.extend(_check_citation_version())
    failures.extend(_check_readme_release_pins())
    failures.extend(_check_claim_traceability())
    failures.extend(_check_schema_reference())
    failures.extend(_check_claim_evidence_status_docs())
    failures.extend(_check_reason_codes())
    failures.extend(_check_flagship_readme_diagram())
    failures.extend(_check_counterfactual_rag_boundary())
    failures.extend(_check_otel_mapping())
    failures.extend(_check_live_protocol())
    failures.extend(_check_security_release_containment())
    failures.extend(_check_standards_freshness())
    if failures:
        for failure in failures:
            print(f"docs-alignment: {bounded_text(failure)}", file=sys.stderr)
        return 1
    print("docs-alignment: ok")
    return 0


def _check_public_docs_exist() -> list[str]:
    return [
        f"missing required document: {path.relative_to(ROOT)}"
        for path in PUBLIC_DOCS
        if not path.exists()
    ]


def _check_readme_local_image_assets() -> list[str]:
    readme = ROOT / "README.md"
    if not readme.exists():
        return []

    repository_root = ROOT.resolve()
    local_assets: dict[str, Path] = {}
    failures: list[str] = []
    for target in _readme_image_targets(readme.read_text(encoding="utf-8")):
        parsed = urlsplit(target)
        if parsed.scheme or parsed.netloc or target.startswith("/") or not parsed.path:
            continue
        display_target = unquote(parsed.path).replace("\\", "/")
        asset_path = (readme.parent / unquote(parsed.path)).resolve()
        if not asset_path.is_relative_to(repository_root):
            failures.append(f"README.md image asset points outside repository: {display_target}")
            continue
        local_assets[display_target] = asset_path

    existing_assets: dict[str, Path] = {}
    for display_target, asset_path in sorted(local_assets.items()):
        if not asset_path.is_file():
            failures.append(f"README.md image asset does not exist: {display_target}")
        else:
            existing_assets[display_target] = asset_path

    if not existing_assets:
        return failures

    try:
        tracked_paths = _git_tracked_paths(ROOT)
    except RuntimeError as exc:
        failures.append(f"could not inspect Git-tracked README image assets: {exc}")
        return failures
    if tracked_paths is None:
        return failures

    for display_target, asset_path in sorted(existing_assets.items()):
        repository_path = asset_path.relative_to(repository_root).as_posix()
        if repository_path not in tracked_paths:
            failures.append(f"README.md image asset is not tracked by Git: {display_target}")
    return failures


def _readme_image_targets(text: str) -> tuple[str, ...]:
    searchable_text = _without_fenced_code(text)
    targets: list[str] = []
    for match in MARKDOWN_INLINE_IMAGE_PATTERN.finditer(searchable_text):
        target = match.group("angle_target") or match.group("plain_target")
        if target:
            targets.append(target.strip())
    for match in HTML_IMAGE_PATTERN.finditer(searchable_text):
        target = (
            match.group("double_quoted_target")
            or match.group("single_quoted_target")
            or match.group("unquoted_target")
        )
        if target:
            targets.append(target.strip())
    return tuple(dict.fromkeys(targets))


def _without_fenced_code(text: str) -> str:
    lines: list[str] = []
    in_fence = False
    fence_char = ""
    fence_len = 0
    for line in text.splitlines(keepends=True):
        fence = re.match(r"^[ \t]{0,3}([`~]{3,})", line)
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
            lines.append("\n" if line.endswith(("\n", "\r")) else "")
            continue
        lines.append(line if not in_fence else ("\n" if line.endswith(("\n", "\r")) else ""))
    return "".join(lines)


def _git_tracked_paths(repository_root: Path) -> set[str] | None:
    if not (repository_root / ".git").exists():
        return None
    try:
        completed = subprocess.run(
            ["git", "-C", str(repository_root), "ls-files", "-z"],
            check=False,
            capture_output=True,
        )
    except OSError as exc:
        raise RuntimeError(f"git ls-files could not start: {exc}") from exc
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(detail or f"git ls-files exited {completed.returncode}")
    return {
        path.decode("utf-8", errors="surrogateescape")
        for path in completed.stdout.split(b"\0")
        if path
    }


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
    text = changelog.read_text(encoding="utf-8")
    try:
        parse_changelog(text, source="CHANGELOG.md")
    except ValueError as exc:
        return [str(exc)]
    return []


def _check_citation_version() -> list[str]:
    citation = ROOT / "CITATION.cff"
    text = citation.read_text(encoding="utf-8")
    latest = _latest_changelog_release((ROOT / "CHANGELOG.md").read_text(encoding="utf-8"))
    if latest is None:
        return []
    failures = check_citation_release(text, expected=latest)
    if failures:
        return failures
    try:
        parsed = yaml.load(text, Loader=_UniqueKeySafeLoader)
    except yaml.YAMLError as exc:
        return [f"CITATION.cff semantic YAML validation failed: {bounded_text(exc)}"]
    if not isinstance(parsed, dict):
        return ["CITATION.cff semantic YAML root must be a mapping"]

    semantic_version = parsed.get("version")
    semantic_date = parsed.get("date-released")
    semantic_failures: list[str] = []
    if not isinstance(semantic_version, str) or semantic_version != latest.version:
        semantic_failures.append(
            "CITATION.cff semantic version does not match latest released version "
            f"{latest.version!r}"
        )
    if str(semantic_date) != latest.date_text:
        semantic_failures.append(
            "CITATION.cff semantic date-released does not match latest release date "
            f"{latest.date_text!r}"
        )
    return semantic_failures


def _check_readme_release_pins() -> list[str]:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    latest = _latest_changelog_release((ROOT / "CHANGELOG.md").read_text(encoding="utf-8"))
    if latest is None:
        return []
    failures = check_readme_release(readme, expected=latest)
    if not failures:
        action_pin = readme_release_action_pin(readme)
        failures.extend(
            check_readme_action_source(
                ROOT,
                release_version=latest.version,
                pinned_commit=action_pin.commit_sha,
            )
        )
    return failures


def _latest_changelog_release(text: str) -> ChangelogRelease | None:
    try:
        changelog = parse_changelog(text, source="CHANGELOG.md")
    except ValueError:
        return None
    return changelog.latest_release


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
        for reason in (
            *ReasonCode,
            *ControlEfficacyGateReason,
            *EvidenceSensitivityReasonCode,
        )
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


def _check_claim_evidence_status_docs() -> list[str]:
    schema_statuses = tuple(get_args(ClaimEvidenceStatus))
    failures: list[str] = []
    if schema_statuses != EXPECTED_CLAIM_EVIDENCE_STATUSES:
        failures.append(
            "ClaimEvidenceStatus schema domain drifted from the five-state public contract: "
            f"{schema_statuses!r}"
        )
    for relative_path in CLAIM_EVIDENCE_STATUS_DOCS:
        path = ROOT / relative_path
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            failures.append(f"could not read {relative_path.as_posix()}: {bounded_text(exc)}")
            continue
        failures.extend(
            _check_claim_evidence_status_doc_text(
                text,
                document_name=relative_path.as_posix(),
            )
        )
    return failures


def _check_claim_evidence_status_doc_text(
    text: str,
    *,
    document_name: str,
) -> list[str]:
    normalized = " ".join(text.split()).casefold()
    required_semantics = (
        (
            "excluded paths are `not_evaluated`",
            ("excluded paths are `not_evaluated`",),
        ),
        (
            "included non-approval paths are `not_applicable`",
            (
                "included non-approval paths are `not_applicable`",
                "included non-approvals are `not_applicable`",
            ),
        ),
    )
    failures = [
        f"{document_name} must state claim-evidence applicability: {description}"
        for description, alternatives in required_semantics
        if not any(alternative in normalized for alternative in alternatives)
    ]
    included_approval_contracts = (
        "only included approval paths may be `complete`, `incomplete`, or `unobservable`",
        "only included approvals may be `complete`, `incomplete`, or `unobservable`",
    )
    if not any(contract in normalized for contract in included_approval_contracts):
        failures.append(
            f"{document_name} must state claim-evidence applicability: only included "
            "approvals may be `complete`, `incomplete`, or `unobservable`"
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
            f"flagship candidate must produce exactly one finding; found {len(candidate_findings)}"
        )
    finding = candidate_findings[0]
    if finding.target != claim_finding_target(missing_claim_id):
        raise ValueError(
            f"flagship candidate finding target does not match the missing claim: {finding.target}"
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
        fixture_equivalence_state=(comparison_report.comparison_summary.fixture_equivalence_state),
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
        if "gen_ai.operation.name" not in matrix_text or "gen_ai.operation.name" not in docs_text:
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


def _check_security_release_containment() -> list[str]:
    security_policy = ROOT / "SECURITY.md"
    document = ROOT / "docs" / "security_release_containment.md"
    template = ROOT / "docs" / "templates" / "security_release_risk_acceptance.yaml"
    integrations = {
        ROOT / "SECURITY.md": "docs/security_release_containment.md",
        ROOT / "docs" / "release_pypi.md": "security_release_containment.md",
        ROOT / "docs" / "release_notes" / "v0.7.0.md": "../security_release_containment.md",
        ROOT / "docs" / "index.md": "security_release_containment.md",
        ROOT / "README.md": "docs/security_release_containment.md",
        ROOT / "mkdocs.yml": "security_release_containment.md",
    }
    failures: list[str] = []

    for path in (document, template, *integrations):
        if not path.is_file():
            failures.append(
                f"security containment governance missing file: {path.relative_to(ROOT).as_posix()}"
            )

    if security_policy.is_file():
        failures.extend(
            _check_security_intake_policy_text(
                security_policy.read_text(encoding="utf-8"),
                document_name="public security policy",
            )
        )

    if document.is_file():
        document_text = document.read_text(encoding="utf-8")
        failures.extend(
            _check_required_markdown_sections(
                document_text,
                REQUIRED_SECURITY_CONTAINMENT_SECTIONS,
                document_name="security correction containment policy",
                min_content_chars=120,
            )
        )
        normalized_document = " ".join(document_text.split())
        for required_text in (
            "It does not authorize a merge, tag, signature, package upload, "
            "GitHub Release, TestPyPI publication, PyPI publication, or an exception "
            "to any release gate.",
            "The accountable owner and independent approver must use distinct human identities",
            "expires automatically at the recorded UTC timestamp",
            "Loss of observability is a control failure",
            "A decision not to notify is itself a named, approved, time-stamped decision",
            "fail closed: treat the acceptance as inactive",
            "Do not commit vulnerability details, customer exposure, exploit material, "
            "personal data, credentials, or a completed acceptance record",
            "Store the digest only in a separate append-only audit event",
            "neither its own digest nor an identifier for the later audit event",
            "the record never points forward to that event",
            "it must not parse, normalize, or reserialize them",
        ):
            if required_text not in normalized_document:
                failures.append(
                    "security correction containment policy missing required boundary: "
                    f"{required_text}"
                )
        for duration in ("24 hours", "72 hours", "7 calendar days"):
            if duration not in document_text:
                failures.append(
                    f"security correction containment policy missing maximum window: {duration}"
                )
        failures.extend(
            _check_security_intake_policy_text(
                document_text,
                document_name="security correction containment policy",
            )
        )

    for path, required_link in integrations.items():
        if path.is_file() and required_link not in path.read_text(encoding="utf-8"):
            failures.append(
                "security containment governance is not linked from "
                f"{path.relative_to(ROOT).as_posix()}"
            )

    if template.is_file():
        try:
            payload = yaml.safe_load(template.read_text(encoding="utf-8"))
        except (UnicodeError, yaml.YAMLError) as exc:
            failures.append(f"security risk-acceptance template is invalid YAML: {exc}")
        else:
            failures.extend(_check_security_risk_acceptance_template(payload))

    return failures


def _check_security_intake_policy_text(text: str, *, document_name: str) -> list[str]:
    failures: list[str] = []
    normalized = " ".join(text.split())
    critical_row = (
        "| Critical | Immediate; confirm delivery within 5 elapsed minutes | "
        "Within 1 elapsed hour | Within 4 elapsed hours | Verified containment, "
        "verified no supported exposure, or safe-state entry within 4 elapsed hours |"
    )
    high_row = (
        "| High | Immediate | Within 4 elapsed hours | Within 24 elapsed hours | "
        "Verified containment, verified no supported exposure, or safe-state entry "
        "within 24 elapsed hours |"
    )
    for required_text in (
        SECURITY_INTAKE_POLICY_ID,
        "report_received_at_utc",
        "internally_detected_at_utc",
        "elapsed UTC time",
        "must not reset",
        "weekends",
        "holidays",
        critical_row,
        high_row,
        "severity-specific objectives take precedence over the general "
        "three- and seven-business-day targets",
        "24/7 primary security on-call",
        "independent fallback",
        "within 15 elapsed minutes",
        "same GitHub account, identity provider, or notification path",
        "unreferenced private process",
    ):
        if required_text not in normalized:
            failures.append(f"{document_name} missing intake control: {required_text}")
    return failures


def _check_security_risk_acceptance_template(payload: object) -> list[str]:
    failures: list[str] = []
    if not isinstance(payload, dict):
        return ["security risk-acceptance template must be a mapping"]

    if payload.get("record_schema") != SECURITY_RISK_RECORD_SCHEMA:
        failures.append("security risk-acceptance template has an unexpected record_schema")
    if payload.get("status") != "draft":
        failures.append("security risk-acceptance template must default to draft")

    intake_policy = payload.get("intake_policy")
    if not isinstance(intake_policy, dict):
        failures.append("security risk-acceptance template missing intake_policy")
    else:
        expected_policy_fields = {
            "policy_id": SECURITY_INTAKE_POLICY_ID,
            "policy_revision": SECURITY_INTAKE_POLICY_REVISION,
            "clock_basis": SECURITY_INTAKE_CLOCK_BASIS,
            "severity_specific_objectives_override_general_targets": True,
        }
        for key, expected in expected_policy_fields.items():
            if intake_policy.get(key) != expected:
                failures.append(
                    f"security risk-acceptance template has unexpected intake policy field: {key}"
                )
        for severity, expected_objectives in SECURITY_INTAKE_OBJECTIVES.items():
            actual_objectives = intake_policy.get(severity)
            if not isinstance(actual_objectives, dict):
                failures.append(
                    "security risk-acceptance template missing intake objective mapping: "
                    f"{severity}"
                )
                continue
            for objective, expected_value in expected_objectives.items():
                if actual_objectives.get(objective) != expected_value:
                    failures.append(
                        "security risk-acceptance template has unexpected intake objective: "
                        f"{severity}.{objective}"
                    )

    boundary = payload.get("authority_boundary")
    if not isinstance(boundary, dict):
        failures.append("security risk-acceptance template missing authority_boundary")
    else:
        if boundary.get("operational_risk_acceptance_only") is not True:
            failures.append("security risk-acceptance template must be operational-risk-only")
        for action in NON_AUTHORIZING_ACTIONS:
            if boundary.get(action) is not False:
                failures.append(
                    f"security risk-acceptance template must deny publication authority: {action}"
                )
        acknowledgement = boundary.get("acknowledgement")
        if (
            not isinstance(acknowledgement, str)
            or "no publication authority" not in acknowledgement
        ):
            failures.append(
                "security risk-acceptance template must acknowledge no publication authority"
            )

    required_mappings = {
        "incident_intake": (
            "source_channel",
            "report_received_at_utc",
            "internally_detected_at_utc",
            "clock_started_at_utc",
            "clock_start_basis",
            "critical_signal_detected_at_utc",
            "primary_page_sent_at_utc",
            "primary_page_delivery_confirmed_at_utc",
            "fallback_page_due_at_utc",
            "fallback_page_sent_at_utc",
            "human_acknowledgement_due_at_utc",
            "human_acknowledged_at_utc",
            "initial_assessment_due_at_utc",
            "initial_assessment_completed_at_utc",
            "containment_or_safe_state_due_at_utc",
            "containment_started_at_utc",
            "containment_verified_at_utc",
            "no_supported_deployment_affected_determined_at_utc",
            "safe_state_entered_at_utc",
            "objective_breach_detected_at_utc",
            "objective_breach_reason",
        ),
        "incident": (
            "incident_id",
            "severity",
            "severity_rationale",
            "exploitation_status",
        ),
        "release_context": (
            "supported_release",
            "affected_artifacts",
            "repository_commit",
            "unpublished_correction_identifier",
            "blocking_gates",
        ),
        "affected_scope": (
            "systems",
            "customer_or_tenant_cohorts",
            "assumptions",
            "unknowns",
        ),
        "risk_decision": (
            "decision",
            "residual_risk_statement",
            "safe_state_if_inactive",
            "risk_owner_attestation",
        ),
        "timing": (
            "approved_at_utc",
            "effective_at_utc",
            "expires_at_utc",
            "maximum_window_hours",
            "reevaluation_cadence_hours",
            "next_reevaluation_at_utc",
            "renewal_count",
        ),
        "coordination": (
            "affected_audiences",
            "cve_or_cna_plan",
            "customer_guidance_reference",
            "legal_review_reference",
            "privacy_review_reference",
            "regulatory_review_reference",
            "decisions",
        ),
        "approval": (
            "supporting_evidence_snapshot_reference",
            "supporting_evidence_snapshot_sha256",
            "accountable_owner_decision",
            "accountable_owner_signed_at_utc",
            "independent_approver_decision",
            "independent_approver_signed_at_utc",
        ),
        "audit": (
            "system_of_record_uri",
            "immutable_audit_log_reference",
            "record_snapshot_export_reference",
            "record_snapshot_media_type",
            "record_snapshot_byte_length",
            "record_snapshot_digest_algorithm",
            "record_snapshot_digest_stored_outside_record",
            "access_control_policy_reference",
            "retention_policy_reference",
        ),
        "escalation": (
            "contacts",
            "pvr_outage_detected_at_utc",
            "primary_delivery_failure_detected_at_utc",
            "primary_no_ack_detected_at_utc",
            "fallback_activated_at_utc",
            "fallback_acknowledged_at_utc",
            "executive_escalated_at_utc",
            "safe_state_ordered_at_utc",
            "revocation_triggers",
            "last_escalated_at_utc",
            "escalation_evidence_reference",
            "escalation_evidence_sha256",
        ),
        "closure": (
            "closed_at_utc",
            "outcome",
            "release_evidence_reference",
            "deployment_verification_reference",
            "lessons_learned_reference",
            "follow_up_actions",
        ),
    }
    for mapping_name, required_keys in required_mappings.items():
        value = payload.get(mapping_name)
        if not isinstance(value, dict):
            failures.append(f"security risk-acceptance template missing mapping: {mapping_name}")
            continue
        for key in required_keys:
            if key not in value:
                failures.append(
                    f"security risk-acceptance template missing field: {mapping_name}.{key}"
                )

    audit = payload.get("audit")
    if isinstance(audit, dict):
        if "record_snapshot_sha256" in audit:
            failures.append(
                "security risk-acceptance template must not contain a recursive "
                "record snapshot digest"
            )
        if "record_snapshot_external_digest_event_reference" in audit:
            failures.append(
                "security risk-acceptance template must not contain a forward "
                "record snapshot digest-event reference"
            )
        if audit.get("record_snapshot_digest_algorithm") != "sha256":
            failures.append(
                "security risk-acceptance template must pin the external record "
                "snapshot digest to sha256"
            )
        if audit.get("record_snapshot_digest_stored_outside_record") is not True:
            failures.append(
                "security risk-acceptance template must store the record snapshot "
                "digest outside the record"
            )

    roles = payload.get("roles")
    if not isinstance(roles, dict):
        failures.append("security risk-acceptance template missing roles")
    else:
        primary_on_call = roles.get("critical_intake_primary_on_call")
        fallback_on_call = roles.get("critical_intake_independent_fallback_on_call")
        owner = roles.get("accountable_incident_owner")
        approver = roles.get("independent_security_risk_approver")
        if not isinstance(primary_on_call, dict):
            failures.append("security risk-acceptance template missing primary intake on-call")
        else:
            for key in ("durable_role_reference", "private_routing_reference"):
                if key not in primary_on_call:
                    failures.append(
                        f"security risk-acceptance template missing primary on-call field: {key}"
                    )
            if primary_on_call.get("continuous_coverage_required") is not True:
                failures.append(
                    "security risk-acceptance template must require continuous primary coverage"
                )
        if not isinstance(fallback_on_call, dict):
            failures.append("security risk-acceptance template missing fallback intake on-call")
        else:
            for key in (
                "durable_role_reference",
                "private_routing_reference",
                "independent_route_attestation",
            ):
                if key not in fallback_on_call:
                    failures.append(
                        f"security risk-acceptance template missing fallback on-call field: {key}"
                    )
            if fallback_on_call.get("continuous_coverage_required") is not True:
                failures.append(
                    "security risk-acceptance template must require continuous fallback coverage"
                )
            if fallback_on_call.get("distinct_person_from_primary_required") is not True:
                failures.append(
                    "security risk-acceptance template must require a distinct fallback person"
                )
        if not isinstance(owner, dict) or "durable_identity" not in owner:
            failures.append("security risk-acceptance template missing accountable owner identity")
        if not isinstance(approver, dict):
            failures.append(
                "security risk-acceptance template missing independent security approver"
            )
        else:
            for key in (
                "durable_identity",
                "delegated_authority_reference",
                "independence_attestation",
            ):
                if key not in approver:
                    failures.append(
                        f"security risk-acceptance template missing approver field: {key}"
                    )
            if approver.get("distinct_person_required") is not True:
                failures.append(
                    "security risk-acceptance template must require a distinct approver"
                )

    repeated_entries = {
        "containment_controls": (
            "control_id",
            "covered_scope",
            "owner_identity",
            "status",
            "verification_method",
            "verifier_identity",
            "verifier_is_distinct_from_implementer",
            "verified_at_utc",
            "evidence_sha256",
            "failure_signal",
            "safe_state_action",
        ),
        "monitoring": (
            "monitor_id",
            "signal_source",
            "query_or_detector_revision",
            "alert_threshold",
            "owner_identity",
            "on_call_destination",
            "response_objective_minutes",
            "tested_at_utc",
            "test_evidence_sha256",
        ),
    }
    for list_name, required_keys in repeated_entries.items():
        entries = payload.get(list_name)
        if not isinstance(entries, list) or not entries or not isinstance(entries[0], dict):
            failures.append(f"security risk-acceptance template missing example entry: {list_name}")
            continue
        for key in required_keys:
            if key not in entries[0]:
                failures.append(
                    f"security risk-acceptance template missing repeated field: {list_name}.{key}"
                )

    if not isinstance(payload.get("reevaluations"), list):
        failures.append("security risk-acceptance template missing reevaluations list")

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
    content_end = headings[section_index + 1][1] if section_index + 1 < len(headings) else len(text)
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
                    f"standards freshness checklist does not cite lock value: {match.group(1)}"
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
