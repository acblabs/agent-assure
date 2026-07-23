from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import cast

import yaml

from agent_assure.mutation import execution as mutation_execution
from agent_assure.schema.common import ReasonCode
from agent_assure.schema.mutation import (
    AssuranceMutationResult,
    EvidenceEvaluationBasis,
    MutationResultState,
)

ROOT = Path(__file__).resolve().parents[3]
DOCUMENT = ROOT / "docs" / "evidence_carrying_releases.md"
BEGIN_MARKER = "<!-- BEGIN: emitted-caught-evidence-descriptor -->"
END_MARKER = "<!-- END: emitted-caught-evidence-descriptor -->"

EVIDENCE_ID_PLACEHOLDER = "ev-control-efficacy-<result-digest-prefix-24-hex>"
EVIDENCE_DIGEST_PLACEHOLDER = "<evidence-digest-64-lowercase-hex>"
SOURCE_DIGEST_PLACEHOLDER = "<source-runset-digest-64-lowercase-hex>"
SUITE_DIGEST_PLACEHOLDER = "<compiled-suite-digest-64-lowercase-hex>"
EVALUATOR_IMPLEMENTATION_DIGEST_PLACEHOLDER = (
    "<evaluator-implementation-digest-64-lowercase-hex>"
)
GENERATED_AT_PLACEHOLDER = "<generated-at-rfc3339-timestamp>"
RESULT_ID_PLACEHOLDER = "mutation-result-<result-digest-prefix-24-hex>"
RESULT_DIGEST_PLACEHOLDER = "<mutation-result-digest-64-lowercase-hex>"


def test_caught_descriptor_example_tracks_the_producer_shape() -> None:
    """Keep the RFC example aligned with producer-owned values and fields."""
    result = cast(
        AssuranceMutationResult,
        SimpleNamespace(
            state=MutationResultState.caught,
            observed_findings=(
                SimpleNamespace(
                    reason_code=ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
                ),
            ),
            source_digest="a" * 64,
            result_digest="b" * 64,
            evaluator_method_id="assurance-mutation/core/v1",
            evaluator_implementation_digest="c" * 64,
            evaluator_implementation_version="0.6.0",
            evaluator_evaluation_basis=EvidenceEvaluationBasis.deterministic,
            evaluator_protocol_digest=None,
            evaluator_population_id="deterministic-fixture-v1",
            matched_finding_ids=("finding-material-claim-missing-evidence",),
            limitations=(
                "Detection is scoped to this deterministic operator, subject, suite, "
                "and gate profile.",
                "The finite operator does not represent every evidence-link failure.",
                "The operator challenges one deterministically selected material claim.",
            ),
        ),
    )

    descriptor = mutation_execution.build_evidence_descriptor(
        result,
        suite_digest="d" * 64,
        generated_at="2026-07-20T00:00:00Z",
    ).model_dump(mode="json")
    descriptor["evidence_id"] = EVIDENCE_ID_PLACEHOLDER
    descriptor["evidence_digest"] = EVIDENCE_DIGEST_PLACEHOLDER
    cast(dict[str, object], descriptor["subject"])["digest"] = (
        SOURCE_DIGEST_PLACEHOLDER
    )
    cast(dict[str, object], descriptor["scope"])["suite_digest"] = (
        SUITE_DIGEST_PLACEHOLDER
    )
    cast(dict[str, object], descriptor["method"])["implementation_digest"] = (
        EVALUATOR_IMPLEMENTATION_DIGEST_PLACEHOLDER
    )
    cast(dict[str, object], descriptor["validity"])["generated_at"] = (
        GENERATED_AT_PLACEHOLDER
    )
    dependency = cast(list[dict[str, object]], descriptor["dependencies"])[0]
    dependency["evidence_id"] = RESULT_ID_PLACEHOLDER
    dependency["digest"] = RESULT_DIGEST_PLACEHOLDER

    assert _documented_descriptor() == descriptor


def _documented_descriptor() -> dict[str, object]:
    document = DOCUMENT.read_text(encoding="utf-8")
    assert document.count(BEGIN_MARKER) == 1
    assert document.count(END_MARKER) == 1
    marked = document.split(BEGIN_MARKER, maxsplit=1)[1].split(
        END_MARKER,
        maxsplit=1,
    )[0]
    assert marked.count("```yaml") == 1
    fenced = marked.split("```yaml", maxsplit=1)[1].split("```", maxsplit=1)[0]
    payload = yaml.safe_load(fenced)
    assert isinstance(payload, dict)
    return cast(dict[str, object], payload)
