from __future__ import annotations

from pathlib import Path
from typing import cast

import yaml

from agent_assure.mutation import execution as mutation_execution
from agent_assure.schema.common import GateState, ReasonCode
from agent_assure.schema.mutation import (
    AssuranceMutationResult,
    EvidenceEvaluationBasis,
    MutationResultState,
    ObservedFinding,
    OperatorAuthorship,
    OperatorOrigin,
    OperatorProvenance,
    finding_target_digest,
)

ROOT = Path(__file__).resolve().parents[3]
DOCUMENT = ROOT / "docs" / "evidence_carrying_releases.md"
BEGIN_MARKER = "<!-- BEGIN: emitted-caught-evidence-descriptor -->"
END_MARKER = "<!-- END: emitted-caught-evidence-descriptor -->"

EVIDENCE_ID_PLACEHOLDER = "ev-control-efficacy-<result-digest-prefix-24-hex>"
EVIDENCE_DIGEST_PLACEHOLDER = "<evidence-digest-64-lowercase-hex>"
SOURCE_DIGEST_PLACEHOLDER = "<source-runset-digest-64-lowercase-hex>"
SUITE_DIGEST_PLACEHOLDER = "<compiled-suite-digest-64-lowercase-hex>"
EVALUATOR_IMPLEMENTATION_DIGEST_PLACEHOLDER = "<evaluator-implementation-digest-64-lowercase-hex>"
GATE_PROFILE_DIGEST_PLACEHOLDER = "<gate-profile-digest-64-lowercase-hex>"
WAIVER_SET_DIGEST_PLACEHOLDER = "<waiver-set-digest-64-lowercase-hex>"
EVALUATION_DATE_PLACEHOLDER = "<evaluation-date-yyyy-mm-dd>"
GENERATED_AT_PLACEHOLDER = "<generated-at-rfc3339-timestamp>"
RESULT_ID_PLACEHOLDER = "mutation-result-<result-digest-prefix-24-hex>"
RESULT_DIGEST_PLACEHOLDER = "<mutation-result-digest-64-lowercase-hex>"


def test_caught_descriptor_example_tracks_the_producer_shape() -> None:
    """Keep the RFC example aligned with producer-owned values and fields."""
    result = _caught_result()

    descriptor = mutation_execution.build_evidence_descriptor(
        result,
        suite_digest="d" * 64,
        generated_at="2026-07-20T00:00:00Z",
    ).model_dump(mode="json")
    descriptor["evidence_id"] = EVIDENCE_ID_PLACEHOLDER
    descriptor["evidence_digest"] = EVIDENCE_DIGEST_PLACEHOLDER
    cast(dict[str, object], descriptor["subject"])["digest"] = SOURCE_DIGEST_PLACEHOLDER
    cast(dict[str, object], descriptor["scope"])["suite_digest"] = SUITE_DIGEST_PLACEHOLDER
    cast(dict[str, object], descriptor["scope"])["gate_profile_digest"] = (
        GATE_PROFILE_DIGEST_PLACEHOLDER
    )
    cast(dict[str, object], descriptor["scope"])["waiver_set_digest"] = (
        WAIVER_SET_DIGEST_PLACEHOLDER
    )
    cast(dict[str, object], descriptor["scope"])["evaluation_date"] = EVALUATION_DATE_PLACEHOLDER
    cast(dict[str, object], descriptor["method"])["implementation_digest"] = (
        EVALUATOR_IMPLEMENTATION_DIGEST_PLACEHOLDER
    )
    cast(dict[str, object], descriptor["validity"])["generated_at"] = GENERATED_AT_PLACEHOLDER
    dependency = cast(list[dict[str, object]], descriptor["dependencies"])[0]
    dependency["evidence_id"] = RESULT_ID_PLACEHOLDER
    dependency["digest"] = RESULT_DIGEST_PLACEHOLDER

    documented = _documented_descriptor()
    producer = cast(dict[str, object], descriptor["producer"])
    documented_producer = cast(dict[str, object], documented["producer"])
    runtime_version = cast(str, producer["version"])
    documented_version = cast(str, documented_producer["version"])
    assert runtime_version.split("rc", maxsplit=1)[0] == documented_version
    producer["version"] = documented_version

    assert documented == descriptor


def _caught_result() -> AssuranceMutationResult:
    target_digest = finding_target_digest("claim:documentation-example")
    provenance = OperatorProvenance(
        operator_id="documentation-example-operator",
        operator_version="1.0.0",
        implementation_digest="0" * 64,
        implementation_components=(),
        introduction_components=(),
        origin=OperatorOrigin(
            kind="unknown",
            references=("Documentation-only validated fixture.",),
        ),
        target_controls=(),
        authorship=OperatorAuthorship(relationship_to_control_author="unknown"),
    )
    return AssuranceMutationResult.build(
        source_digest="a" * 64,
        mutated_digest="1" * 64,
        operator_id=provenance.operator_id,
        operator_version=provenance.operator_version,
        operator_digest="2" * 64,
        implementation_digest=provenance.implementation_digest,
        expected_detection_contract_digest="3" * 64,
        expected_finding_target_digest=target_digest,
        evaluator_method_id="assurance-mutation/core/v1",
        evaluator_implementation_digest="c" * 64,
        evaluator_implementation_version="0.6.1",
        evaluator_evaluation_basis=EvidenceEvaluationBasis.deterministic,
        evaluator_protocol_digest=None,
        evaluator_population_id="deterministic-fixture-v1",
        gate_profile_id="default",
        gate_profile_digest="e" * 64,
        waiver_set_digest="f" * 64,
        evaluation_date="2026-07-20",
        seed=17,
        changed_paths=("/runs/0/claim_evidence_links/0",),
        observed_findings=(
            ObservedFinding(
                finding_id="finding-material-claim-missing-evidence",
                control_id="material_claims_have_evidence",
                state=GateState.fail,
                reason_code=ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
                target_digest=target_digest,
            ),
        ),
        matched_finding_ids=("finding-material-claim-missing-evidence",),
        state=MutationResultState.caught,
        provenance=provenance,
        independence_class="unknown",
        diagnostic_code=None,
        limitations=(
            "Detection is scoped to this deterministic operator, subject, suite, and gate profile.",
            "The finite operator does not represent every evidence-link failure.",
            "The operator challenges one deterministically selected material claim.",
        ),
    )


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
