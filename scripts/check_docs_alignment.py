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
    ROOT / "docs" / "measurement" / "executive_one_pager.md",
    ROOT / "docs" / "standards" / "otel_genai_gap_analysis.md",
]

FORBIDDEN_POSITIVE_PATTERNS = [
    re.compile(r"\bNIST[- ]endorsed\b", re.IGNORECASE),
    re.compile(r"\bOpenTelemetry[- ]native\b", re.IGNORECASE),
    re.compile(r"\bcertif(?:ies|ied|ication) (?:safety|compliance)\b", re.IGNORECASE),
    re.compile(r"\bclinical(?:ly)? validated\b", re.IGNORECASE),
    re.compile(r"\bregulatory compliance certified\b", re.IGNORECASE),
]

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
            "gen_ai.operation.name",
            "gen_ai.provider.name",
            "gen_ai.request.model",
            "agent_assure.run_id",
        ):
            if attr not in matrix_text or attr not in docs_text:
                failures.append(f"OTel mapping missing documented attribute: {attr}")
    return failures


if __name__ == "__main__":
    raise SystemExit(main())
