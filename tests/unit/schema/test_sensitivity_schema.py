from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import ValidationError

import agent_assure.schema.sensitivity as sensitivity_schema_module
from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.rag.sensitivity import execute_sensitivity_experiment
from agent_assure.schema.sensitivity import (
    REQUIRED_SENSITIVITY_LIMITATIONS,
    EvidenceSensitivityExpectedRelation,
    EvidenceSensitivityObservedRelation,
    EvidenceSensitivityOutcomeClassification,
    EvidenceSensitivityState,
    RAGSensitivityArmResult,
    RAGSensitivityCorpusEvidenceBinding,
    RAGSensitivityCorpusSnapshot,
    RAGSensitivityDecision,
    RAGSensitivityKnowledgeContract,
    RAGSensitivityProtocol,
    RAGSensitivityReport,
    RAGSensitivityRetrievedEvidence,
    derive_sensitivity_outcome_classification,
    derive_sensitivity_outcome_message,
    validate_exact_sensitivity_arm_runset_projection,
)

ROOT = Path(__file__).resolve().parents[3]
EXAMPLE = ROOT / "examples" / "evidence_sensitivity"


@pytest.fixture(scope="module")
def responsive_report() -> RAGSensitivityReport:
    return execute_sensitivity_experiment(
        suite_path=EXAMPLE / "responsive_suite.yaml",
        baseline_corpus_dir=EXAMPLE / "corpora" / "policy_a",
        counterfactual_corpus_dir=EXAMPLE / "corpora" / "policy_b",
        knowledge_contract_path=EXAMPLE / "knowledge-contract.yaml",
        expected_relation=EvidenceSensitivityExpectedRelation.decision_flip,
    ).report


@pytest.fixture(scope="module")
def inertial_report() -> RAGSensitivityReport:
    return execute_sensitivity_experiment(
        suite_path=EXAMPLE / "evidence_inertial_suite.yaml",
        baseline_corpus_dir=EXAMPLE / "corpora" / "policy_a",
        counterfactual_corpus_dir=EXAMPLE / "corpora" / "policy_b",
        knowledge_contract_path=EXAMPLE / "knowledge-contract.yaml",
        expected_relation=EvidenceSensitivityExpectedRelation.decision_flip,
    ).report


def test_report_rejects_forged_observed_relation(
    responsive_report: RAGSensitivityReport,
) -> None:
    payload = _without_report_digest(responsive_report)
    payload["observed_relation"] = "decision_same"

    with pytest.raises(
        ValidationError,
        match="observed relation must be derived from exact arm decision fields",
    ):
        RAGSensitivityReport.build(**payload)


@pytest.mark.parametrize(
    ("state", "relation", "classification"),
    (
        (
            EvidenceSensitivityState.responsive,
            EvidenceSensitivityObservedRelation.decision_flip,
            EvidenceSensitivityOutcomeClassification.expected_response_observed,
        ),
        (
            EvidenceSensitivityState.evidence_insensitive,
            EvidenceSensitivityObservedRelation.decision_same,
            EvidenceSensitivityOutcomeClassification.decision_inertia,
        ),
        (
            EvidenceSensitivityState.evidence_insensitive,
            EvidenceSensitivityObservedRelation.decision_flip,
            EvidenceSensitivityOutcomeClassification.wrong_direction_flip,
        ),
        (
            EvidenceSensitivityState.prerequisites_unmet,
            EvidenceSensitivityObservedRelation.incomparable,
            EvidenceSensitivityOutcomeClassification.incomparable_response,
        ),
        (
            EvidenceSensitivityState.prerequisites_unmet,
            EvidenceSensitivityObservedRelation.decision_flip,
            EvidenceSensitivityOutcomeClassification.not_evaluated,
        ),
        (
            EvidenceSensitivityState.confounded,
            EvidenceSensitivityObservedRelation.decision_same,
            EvidenceSensitivityOutcomeClassification.not_evaluated,
        ),
        (
            EvidenceSensitivityState.confounded,
            EvidenceSensitivityObservedRelation.incomparable,
            EvidenceSensitivityOutcomeClassification.not_evaluated,
        ),
    ),
)
def test_outcome_classification_is_a_total_typed_projection(
    state: EvidenceSensitivityState,
    relation: EvidenceSensitivityObservedRelation,
    classification: EvidenceSensitivityOutcomeClassification,
) -> None:
    assert derive_sensitivity_outcome_classification(state, relation) is classification


@pytest.mark.parametrize(
    ("state", "relation"),
    (
        (
            EvidenceSensitivityState.responsive,
            EvidenceSensitivityObservedRelation.decision_same,
        ),
        (
            EvidenceSensitivityState.evidence_insensitive,
            EvidenceSensitivityObservedRelation.incomparable,
        ),
    ),
)
def test_outcome_classification_rejects_impossible_verdict_relations(
    state: EvidenceSensitivityState,
    relation: EvidenceSensitivityObservedRelation,
) -> None:
    with pytest.raises(ValueError):
        derive_sensitivity_outcome_classification(state, relation)


def test_outcome_message_rejects_a_reversed_path_labeled_responsive() -> None:
    with pytest.raises(
        ValueError,
        match="state contradicts expected and observed decision paths",
    ):
        derive_sensitivity_outcome_message(
            classification=(EvidenceSensitivityOutcomeClassification.expected_response_observed),
            state=EvidenceSensitivityState.responsive,
            observed_relation=EvidenceSensitivityObservedRelation.decision_flip,
            baseline_expected_decision=RAGSensitivityDecision.approve,
            counterfactual_expected_decision=RAGSensitivityDecision.deny,
            baseline_observed_decision=RAGSensitivityDecision.deny,
            counterfactual_observed_decision=RAGSensitivityDecision.approve,
        )


def test_outcome_message_rejects_a_relation_detached_from_decisions() -> None:
    with pytest.raises(
        ValueError,
        match="observed relation contradicts directional decisions",
    ):
        derive_sensitivity_outcome_message(
            classification=EvidenceSensitivityOutcomeClassification.decision_inertia,
            state=EvidenceSensitivityState.evidence_insensitive,
            observed_relation=EvidenceSensitivityObservedRelation.decision_same,
            baseline_expected_decision=RAGSensitivityDecision.approve,
            counterfactual_expected_decision=RAGSensitivityDecision.deny,
            baseline_observed_decision=RAGSensitivityDecision.approve,
            counterfactual_observed_decision=RAGSensitivityDecision.deny,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("outcome_classification", "wrong_direction_flip"),
        ("outcome_message", "A misleading outcome summary."),
    ),
)
def test_report_rejects_forged_outcome_finding(
    responsive_report: RAGSensitivityReport,
    field: str,
    value: object,
) -> None:
    payload = _without_report_digest(responsive_report)
    payload[field] = value

    with pytest.raises(
        ValidationError,
        match="sensitivity outcome finding must be exactly derived from arm outputs and state",
    ):
        RAGSensitivityReport.build(**payload)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        (
            "endpoint_value",
            False,
            "expected-decision-response endpoint contradicts arm outputs",
        ),
        ("state", "evidence_insensitive", "sensitivity report state contradicts"),
        ("gate_effect", "block", "verdict-bearing sensitivity result fields are incoherent"),
    ),
)
def test_report_rejects_forged_verdict_fields(
    responsive_report: RAGSensitivityReport,
    field: str,
    value: object,
    message: str,
) -> None:
    payload = _without_report_digest(responsive_report)
    payload[field] = value

    with pytest.raises(ValidationError, match=message):
        RAGSensitivityReport.build(**payload)


def test_report_recomputes_authority_bound_evidence_link_presence(
    responsive_report: RAGSensitivityReport,
) -> None:
    payload = _without_report_digest(responsive_report)
    baseline = payload["baseline_arm"]
    assert isinstance(baseline, dict)
    baseline["evidence_link_present"] = False
    baseline["citation_presence_check"] = "fail"

    with pytest.raises(
        ValidationError,
        match="evidence-link presence must match the authority-bound claim links",
    ):
        RAGSensitivityReport.build(**payload)


@pytest.mark.parametrize(
    "identity_field",
    ("arm_id", "runset_id", "runset_digest", "evaluation_summary_digest"),
)
def test_report_rejects_reused_arm_execution_identity(
    responsive_report: RAGSensitivityReport,
    identity_field: str,
) -> None:
    payload = _without_report_digest(responsive_report)
    baseline = payload["baseline_arm"]
    counterfactual = payload["counterfactual_arm"]
    assert isinstance(baseline, dict)
    assert isinstance(counterfactual, dict)
    counterfactual[identity_field] = baseline[identity_field]

    with pytest.raises(
        ValidationError,
        match=(
            "sensitivity arm identities must derive from the protocol"
            if identity_field == "arm_id"
            else "exact evaluation summary must match"
            if identity_field == "evaluation_summary_digest"
            else "exact RunSet must match"
        ),
    ):
        RAGSensitivityReport.build(**payload)


def test_report_rejects_forged_baseline_evaluation_digest(
    responsive_report: RAGSensitivityReport,
) -> None:
    payload = _without_report_digest(responsive_report)
    baseline = payload["baseline_arm"]
    assert isinstance(baseline, dict)
    baseline["evaluation_summary_digest"] = "a" * 64

    with pytest.raises(
        ValidationError,
        match="baseline exact evaluation summary must match the sensitivity arm",
    ):
        RAGSensitivityReport.build(**payload)


@pytest.mark.parametrize("arm_field", ("baseline_arm", "counterfactual_arm"))
def test_report_rejects_arm_query_digest_detached_from_protocol(
    responsive_report: RAGSensitivityReport,
    arm_field: str,
) -> None:
    payload = _without_report_digest(responsive_report)
    arm = payload[arm_field]
    assert isinstance(arm, dict)
    arm["query_digest"] = "0" * 64

    with pytest.raises(
        ValidationError,
        match="both sensitivity arms must bind the protocol query digest",
    ):
        RAGSensitivityReport.build(**payload)


def test_report_rejects_retrieval_not_present_in_exact_corpus_evidence(
    responsive_report: RAGSensitivityReport,
) -> None:
    payload = _without_report_digest(responsive_report)
    baseline = payload["baseline_arm"]
    assert isinstance(baseline, dict)
    retrieved = baseline["retrieved_evidence"]
    assert isinstance(retrieved, list)
    invented = dict(retrieved[0])
    invented.update(
        {
            "rank": 2,
            "source_id": "invented-source",
            "ref_id": "invented-reference",
            "content_digest": "f" * 64,
        }
    )
    retrieved.append(invented)
    baseline["retrieved_evidence_digest"] = sha256_hexdigest(tuple(retrieved))

    with pytest.raises(
        ValidationError,
        match="retrieved evidence must be drawn from exact corpus evidence",
    ):
        RAGSensitivityReport.build(**payload)


def test_report_rejects_duplicate_retrieval_identity(
    responsive_report: RAGSensitivityReport,
) -> None:
    payload = _without_report_digest(responsive_report)
    baseline = payload["baseline_arm"]
    assert isinstance(baseline, dict)
    retrieved = baseline["retrieved_evidence"]
    assert isinstance(retrieved, list)
    duplicate = dict(retrieved[0])
    duplicate["rank"] = 2
    retrieved.append(duplicate)
    baseline["retrieved_evidence_digest"] = sha256_hexdigest(tuple(retrieved))

    with pytest.raises(
        ValidationError,
        match="retrieved evidence identities must be unique",
    ):
        RAGSensitivityReport.build(**payload)


def test_report_rejects_forged_retrieval_score(
    responsive_report: RAGSensitivityReport,
) -> None:
    payload = _without_report_digest(responsive_report)
    baseline = payload["baseline_arm"]
    assert isinstance(baseline, dict)
    retrieved = baseline["retrieved_evidence"]
    assert isinstance(retrieved, list)
    evidence = retrieved[0]
    assert isinstance(evidence, dict)
    evidence["overlap_score"] = cast(int, evidence["overlap_score"]) + 100
    baseline["retrieved_evidence_digest"] = sha256_hexdigest(tuple(retrieved))

    with pytest.raises(
        ValidationError,
        match="retrieval must exactly replay the authenticated request",
    ):
        RAGSensitivityReport.build(**payload)


def test_report_rejects_overfull_retrieval_with_invented_corpus_binding(
    responsive_report: RAGSensitivityReport,
) -> None:
    baseline = responsive_report.baseline_arm
    extra_binding = RAGSensitivityCorpusEvidenceBinding(
        source_id="secondary-policy-source",
        ref_id="secondary-policy-reference",
        content_digest="e" * 64,
        governing_decision=baseline.decision,
        governing_outcome=baseline.outcome,
    )
    corpus_evidence = tuple(
        sorted(
            (*baseline.corpus_evidence, extra_binding),
            key=lambda item: (item.source_id, item.ref_id),
        )
    )
    extra_retrieval = RAGSensitivityRetrievedEvidence(
        rank=2,
        source_id=extra_binding.source_id,
        ref_id=extra_binding.ref_id,
        content_digest=extra_binding.content_digest,
        overlap_score=1,
        governing_decision=extra_binding.governing_decision,
        governing_outcome=extra_binding.governing_outcome,
    )
    retrieved = (*baseline.retrieved_evidence, extra_retrieval)
    arm_payload = baseline.model_dump(mode="json")
    arm_payload.update(
        {
            "corpus_evidence": [item.model_dump(mode="json") for item in corpus_evidence],
            "evidence_set_digest": sha256_hexdigest(
                tuple(item.model_dump(mode="json") for item in corpus_evidence)
            ),
            "retrieved_evidence": [item.model_dump(mode="json") for item in retrieved],
            "retrieved_evidence_digest": sha256_hexdigest(
                tuple(item.model_dump(mode="json") for item in retrieved)
            ),
        }
    )
    overfull_arm = RAGSensitivityArmResult.model_validate(arm_payload)
    payload = _without_report_digest(responsive_report)
    payload["baseline_arm"] = overfull_arm

    with pytest.raises(
        ValidationError,
        match="corpus evidence must derive from the exact corpus snapshot",
    ):
        RAGSensitivityReport.build(**payload)


def test_protocol_rejects_request_payload_detached_from_digest(
    responsive_report: RAGSensitivityReport,
) -> None:
    payload = responsive_report.protocol.model_dump(
        mode="json",
        exclude={"protocol_digest"},
    )
    request = payload["request"]
    assert isinstance(request, dict)
    request["query"] = "forged retrieval query"

    with pytest.raises(
        ValidationError,
        match="request must derive from the exact fixture snapshot",
    ):
        RAGSensitivityProtocol.build(**payload)


def test_protocol_accepts_release_candidate_producer_version(
    responsive_report: RAGSensitivityReport,
) -> None:
    payload = responsive_report.protocol.model_dump(
        mode="json",
        exclude={"protocol_digest"},
    )
    payload["producer_version"] = "0.6.4rc1"
    difference_manifest = payload["controlled_difference_manifest"]
    assert isinstance(difference_manifest, dict)
    checks = difference_manifest["checks"]
    assert isinstance(checks, list)
    producer_check = next(item for item in checks if item["dimension"] == "producer_version")
    producer_check["baseline_value"] = "0.6.4rc1"
    producer_check["counterfactual_value"] = "0.6.4rc1"

    protocol = RAGSensitivityProtocol.build(**payload)

    assert protocol.producer_version == "0.6.4rc1"


def test_protocol_rejects_bundled_provenance_on_unreviewed_digests(
    responsive_report: RAGSensitivityReport,
) -> None:
    payload = responsive_report.protocol.model_dump(
        mode="json",
        exclude={"protocol_digest"},
    )
    payload["suite_digest"] = "f" * 64
    difference_manifest = payload["controlled_difference_manifest"]
    assert isinstance(difference_manifest, dict)
    checks = difference_manifest["checks"]
    assert isinstance(checks, list)
    suite_check = next(item for item in checks if item["dimension"] == "suite_digest")
    suite_check["baseline_value"] = "f" * 64
    suite_check["counterfactual_value"] = "f" * 64

    with pytest.raises(
        ValidationError,
        match="bundled synthetic provenance requires the exact reviewed input digests",
    ):
        RAGSensitivityProtocol.build(**payload)


def test_protocol_rejects_fixture_role_path_detached_from_fixture_id(
    responsive_report: RAGSensitivityReport,
) -> None:
    payload = responsive_report.protocol.model_dump(
        mode="json",
        exclude={"protocol_digest"},
    )
    snapshots = payload["fixture_snapshots"]
    fixture_manifest = payload["fixture_manifest"]
    assert isinstance(snapshots, list)
    assert isinstance(fixture_manifest, dict)
    entries = fixture_manifest["entries"]
    assert isinstance(entries, list)
    request_snapshot = snapshots[0]
    assert isinstance(request_snapshot, dict)
    original_path = request_snapshot["path"]
    alternate_path = "fixtures/responsive/requests/alternate-request.json"
    original_entry = next(item for item in entries if item["path"] == original_path)
    alternate_entry = dict(original_entry)
    alternate_entry["path"] = alternate_path
    entries.append(alternate_entry)
    request_snapshot["path"] = alternate_path
    payload["fixture_manifest_digest"] = sha256_hexdigest(fixture_manifest)

    with pytest.raises(
        ValidationError,
        match="snapshot roles must match the suite-selected fixture identity",
    ):
        RAGSensitivityProtocol.build(**payload)


def test_report_rejects_inertial_output_forged_as_responsive(
    inertial_report: RAGSensitivityReport,
) -> None:
    payload = _without_report_digest(inertial_report)
    counterfactual = payload["counterfactual_arm"]
    assert isinstance(counterfactual, dict)
    counterfactual["decision"] = "deny"
    counterfactual["outcome"] = "denied"
    counterfactual["expected_decision_match"] = True

    with pytest.raises(
        ValidationError,
        match="RunSet runtime and decision projection must match",
    ):
        RAGSensitivityReport.build(**payload)


@pytest.mark.parametrize(
    ("field", "forged_value"),
    (
        ("human_review_required", True),
        ("human_review_performed", True),
        ("provider_response_id", "forged-provider-response"),
    ),
)
def test_exact_runset_projection_rejects_false_security_metadata(
    responsive_report: RAGSensitivityReport,
    field: str,
    forged_value: object,
) -> None:
    runset = responsive_report.baseline_runset
    forged_run = runset.runs[0].model_copy(update={field: forged_value})
    forged_runset = runset.model_copy(update={"runs": (forged_run,)})

    with pytest.raises(
        ValueError,
        match="complete deterministic sensitivity projection",
    ):
        validate_exact_sensitivity_arm_runset_projection(
            label="baseline",
            arm=responsive_report.baseline_arm,
            runset=forged_runset,
            protocol=responsive_report.protocol,
            authority_contract=responsive_report.authority_contract,
        )


def test_snapshot_rejects_decoded_payload_detached_from_exact_content(
    responsive_report: RAGSensitivityReport,
) -> None:
    payload = responsive_report.baseline_corpus_snapshot.model_dump(
        mode="json",
        exclude={"snapshot_digest"},
    )
    documents = payload["documents"]
    assert isinstance(documents, list)
    document = documents[0]
    assert isinstance(document, dict)
    decoded = document["payload"]
    assert isinstance(decoded, dict)
    decoded["safe_summary"] = "forged decoded summary"

    with pytest.raises(
        ValidationError,
        match="decoded payload does not match exact content",
    ):
        RAGSensitivityCorpusSnapshot.build(**payload)


def test_snapshot_enforces_aggregate_utf8_byte_limit(
    responsive_report: RAGSensitivityReport,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = responsive_report.baseline_corpus_snapshot
    exact_bytes = len(snapshot.corpus_manifest_utf8.encode("utf-8")) + sum(
        len(document.content_utf8.encode("utf-8")) for document in snapshot.documents
    )
    monkeypatch.setattr(
        sensitivity_schema_module,
        "MAX_SENSITIVITY_CORPUS_BYTES",
        exact_bytes - 1,
    )

    with pytest.raises(
        ValidationError,
        match="aggregate UTF-8 byte limit",
    ):
        RAGSensitivityCorpusSnapshot.model_validate(snapshot.model_dump(mode="json"))


@pytest.mark.parametrize("field", ("assumptions", "limitations"))
def test_report_rejects_claim_context_detached_from_protocol(
    responsive_report: RAGSensitivityReport,
    field: str,
) -> None:
    payload = _without_report_digest(responsive_report)
    payload[field] = ["A forged top-level claim context."]

    with pytest.raises(
        ValidationError,
        match="report assumptions and limitations must exactly match the protocol",
    ):
        RAGSensitivityReport.build(**payload)


def test_protocol_requires_machine_enforced_claim_boundary(
    responsive_report: RAGSensitivityReport,
) -> None:
    payload = responsive_report.protocol.model_dump(
        mode="json",
        exclude={"protocol_digest"},
    )
    payload["limitations"] = ["This result proves general causal safety."]

    with pytest.raises(
        ValidationError,
        match="mandatory synthetic, non-prevalence, and non-causal limitations",
    ):
        RAGSensitivityProtocol.build(**payload)


def test_report_preserves_authority_contract_limitations(
    responsive_report: RAGSensitivityReport,
) -> None:
    protocol_payload = responsive_report.protocol.model_dump(
        mode="json",
        exclude={"protocol_digest"},
    )
    protocol_payload["limitations"] = list(REQUIRED_SENSITIVITY_LIMITATIONS)
    protocol = RAGSensitivityProtocol.build(**protocol_payload)
    report_payload = _without_report_digest(responsive_report)
    report_payload["protocol"] = protocol.model_dump(mode="json")
    report_payload["limitations"] = list(protocol.limitations)

    with pytest.raises(
        ValidationError,
        match="protocol limitations must preserve the authority-contract limitations",
    ):
        RAGSensitivityReport.build(**report_payload)


def test_authority_contract_requires_canonical_unambiguous_assignments(
    responsive_report: RAGSensitivityReport,
) -> None:
    payload = responsive_report.authority_contract.model_dump(
        mode="json",
        exclude={"knowledge_contract_digest"},
    )
    assignments = payload["assignments"]
    assert isinstance(assignments, list)
    payload["assignments"] = list(reversed(assignments))

    with pytest.raises(
        ValidationError,
        match="authority assignments must use canonical corpus-digest ordering",
    ):
        RAGSensitivityKnowledgeContract.build(**payload)


def test_persisted_report_self_digest_detects_payload_tampering(
    responsive_report: RAGSensitivityReport,
) -> None:
    payload = responsive_report.model_dump(mode="json")
    limitations = payload["limitations"]
    assert isinstance(limitations, list)
    limitations.append("Tampered after publication.")

    with pytest.raises(
        ValidationError,
        match="report_digest does not match the canonical artifact projection",
    ):
        RAGSensitivityReport.model_validate(payload)


def _without_report_digest(report: RAGSensitivityReport) -> dict[str, Any]:
    return report.model_dump(mode="json", exclude={"report_digest"})
