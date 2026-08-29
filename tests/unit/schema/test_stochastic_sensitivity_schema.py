from __future__ import annotations

import json
from hashlib import sha256
from typing import Literal, cast

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import ValidationError

from agent_assure.rag.sensitivity_statistics import plan_binary_paired_design
from agent_assure.schema.sensitivity import (
    RAGSensitivityAuthorityAssignment,
    RAGSensitivityCaseAuthorityBinding,
)
from agent_assure.schema.stochastic_sensitivity import (
    CaseClusterBinding,
    CouplingDescriptor,
    ExactBinomialTailExpression,
    PairedSensitivityObservation,
    RepeatedEvidenceSensitivityProtocol,
    SensitivityArmBinding,
    derive_coupling_classification,
)


def _digest(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def _arm(
    arm_id: Literal["baseline_evidence", "counterfactual_evidence"],
    *,
    configuration: str,
    corpus: str,
    **updates: object,
) -> SensitivityArmBinding:
    is_counterfactual = arm_id == "counterfactual_evidence"
    values: dict[str, object] = {
        "arm_id": arm_id,
        "configuration_digest": _digest(configuration),
        "corpus_digest": _digest(corpus),
        "expected_recommendation": "deny" if is_counterfactual else "approve",
        "expected_outcome": "denied" if is_counterfactual else "approved",
        "prompt_manifest_digest": _digest("prompt"),
        "case_manifest_digest": _digest("cases"),
        "knowledge_contract_digest": _digest("knowledge-contract"),
        "provider": "provider",
        "requested_model": "model",
        "adapter_id": "openai-chat-completions",
        "pipeline_id": "pipeline",
        "tool_schema_digest": _digest("tool-schema"),
        "policy_bundle_digest": _digest("policy-bundle"),
    }
    values.update(updates)
    return SensitivityArmBinding.model_validate(values)


def _live_coupling() -> CouplingDescriptor:
    return CouplingDescriptor(
        pairing_identity_verified=True,
        stochastic_dimensions=(
            "provider_sampling_randomness",
            "temporal_execution_order",
        ),
        shared=("case_identity",),
        intentionally_different=("governing_corpus_digest",),
        not_shared=(
            "provider_sampling_randomness",
            "temporal_execution_order",
        ),
        unknown=(),
        requested_provider_seed=True,
        classification="nominally_paired",
        variance_reduction_claim_permitted=False,
    )


def _protocol_payload() -> dict[str, object]:
    cases = tuple(f"case-{index:02d}" for index in range(8))
    baseline = _arm(
        "baseline_evidence",
        configuration="baseline-config",
        corpus="baseline-corpus",
    )
    counterfactual = _arm(
        "counterfactual_evidence",
        configuration="counterfactual-config",
        corpus="counterfactual-corpus",
    )
    return {
        "protocol_id": "repeated-study",
        "interpretation": "confirmatory",
        "execution_mode": "stochastic_live",
        "inferential_unit": "case_id",
        "cluster_by": "case_id",
        "baseline_arm": baseline,
        "counterfactual_arm": counterfactual,
        "planned_case_ids": cases,
        "planned_cluster_ids": cases,
        "case_cluster_bindings": tuple(
            CaseClusterBinding(case_id=case_id, cluster_id=case_id) for case_id in cases
        ),
        "case_authority_bindings": tuple(
            RAGSensitivityCaseAuthorityBinding(
                case_id=case_id,
                query_family_id="shared-query-family",
                assignments=tuple(
                    sorted(
                        (
                            RAGSensitivityAuthorityAssignment(
                                corpus_digest=baseline.corpus_digest,
                                expected_decision=baseline.expected_recommendation,
                                expected_outcome=baseline.expected_outcome,
                                governing_source_id=f"source-{case_id}",
                                governing_ref_id=f"ref-{case_id}",
                                governing_content_digest=_digest(f"baseline-content-{case_id}"),
                                claim_id=f"claim-{case_id}",
                            ),
                            RAGSensitivityAuthorityAssignment(
                                corpus_digest=counterfactual.corpus_digest,
                                expected_decision=counterfactual.expected_recommendation,
                                expected_outcome=counterfactual.expected_outcome,
                                governing_source_id=f"source-{case_id}",
                                governing_ref_id=f"ref-{case_id}",
                                governing_content_digest=_digest(
                                    f"counterfactual-content-{case_id}"
                                ),
                                claim_id=f"claim-{case_id}",
                            ),
                        ),
                        key=lambda item: item.corpus_digest,
                    )
                ),
            )
            for case_id in cases
        ),
        "repetitions_per_arm": 1,
        "planned_pairs": len(cases),
        "multiplicity_family": "evidence-sensitivity",
        "coupling": _live_coupling(),
        "design": plan_binary_paired_design(
            familywise_alpha="0.050000",
            desired_power="0.800000",
            null_response_rate="0.500000",
            alternative_response_rate="0.900000",
        ),
        "limitations": ("Scoped synthetic protocol.",),
    }


def test_confirmatory_protocol_rejects_unsupported_adapter_in_model_and_json_schema() -> None:
    payload = _protocol_payload()
    for arm_name in ("baseline_arm", "counterfactual_arm"):
        arm = cast(SensitivityArmBinding, payload[arm_name])
        payload[arm_name] = arm.model_copy(update={"adapter_id": "static-jsonl"})

    with pytest.raises(ValidationError, match="supported stochastic adapter"):
        RepeatedEvidenceSensitivityProtocol.build(**payload)

    valid = RepeatedEvidenceSensitivityProtocol.build(**_protocol_payload())
    serialized = valid.model_dump(mode="json")
    serialized["baseline_arm"]["adapter_id"] = "static-jsonl"
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(
            RepeatedEvidenceSensitivityProtocol.model_json_schema(mode="validation")
        ).validate(serialized)


def test_confirmatory_protocol_requires_exact_case_authority_coverage() -> None:
    payload = _protocol_payload()
    payload["case_authority_bindings"] = cast(
        tuple[RAGSensitivityCaseAuthorityBinding, ...],
        payload["case_authority_bindings"],
    )[:-1]

    with pytest.raises(ValidationError, match="exactly cover planned_case_ids"):
        RepeatedEvidenceSensitivityProtocol.build(**payload)


@pytest.mark.parametrize(
    ("pairing", "stochastic", "shared", "not_shared", "unknown", "expected"),
    [
        (
            True,
            ("retrieval_randomness",),
            ("retrieval_randomness",),
            (),
            (),
            "fully_coupled",
        ),
        (
            True,
            ("provider_sampling_randomness", "retrieval_randomness"),
            ("retrieval_randomness",),
            ("provider_sampling_randomness",),
            (),
            "partially_coupled",
        ),
        (
            True,
            ("provider_sampling_randomness",),
            (),
            ("provider_sampling_randomness",),
            (),
            "nominally_paired",
        ),
        (
            False,
            ("provider_sampling_randomness",),
            (),
            ("provider_sampling_randomness",),
            (),
            "unpaired",
        ),
        (
            True,
            ("provider_sampling_randomness",),
            (),
            (),
            ("provider_sampling_randomness",),
            "unknown",
        ),
    ],
)
def test_all_five_coupling_classifications(
    pairing: bool,
    stochastic: tuple[str, ...],
    shared: tuple[str, ...],
    not_shared: tuple[str, ...],
    unknown: tuple[str, ...],
    expected: str,
) -> None:
    assert (
        derive_coupling_classification(
            pairing_identity_verified=pairing,
            stochastic_dimensions=stochastic,
            shared=shared,
            intentionally_different=(),
            not_shared=not_shared,
            unknown=unknown,
        )
        == expected
    )


def test_intentionally_different_stochastic_dimension_is_unshared() -> None:
    values = {
        "pairing_identity_verified": True,
        "stochastic_dimensions": (
            "provider_sampling_randomness",
            "retrieval_randomness",
        ),
        "shared": ("provider_sampling_randomness",),
        "intentionally_different": ("retrieval_randomness",),
    }

    descriptor = CouplingDescriptor(**values, classification="partially_coupled")
    assert descriptor.classification == "partially_coupled"

    with pytest.raises(
        ValidationError,
        match="coupling classification does not match the declared conditions",
    ):
        CouplingDescriptor(**values, classification="fully_coupled")


def test_requested_seed_never_proves_provider_randomness_is_shared() -> None:
    payload = _protocol_payload()
    payload["coupling"] = CouplingDescriptor(
        pairing_identity_verified=True,
        stochastic_dimensions=(
            "provider_sampling_randomness",
            "temporal_execution_order",
        ),
        shared=("provider_sampling_randomness",),
        intentionally_different=("governing_corpus_digest",),
        not_shared=("temporal_execution_order",),
        requested_provider_seed=True,
        classification="partially_coupled",
        variance_reduction_claim_permitted=False,
    )
    with pytest.raises(ValidationError, match="shared provider randomness"):
        RepeatedEvidenceSensitivityProtocol.build(**payload)

    with pytest.raises(ValidationError, match="returned-metadata coupling evidence"):
        CouplingDescriptor(
            pairing_identity_verified=True,
            stochastic_dimensions=("provider_sampling_randomness",),
            shared=(),
            intentionally_different=("governing_corpus_digest",),
            not_shared=("provider_sampling_randomness",),
            provider_seed_sharing_evidence_digest=_digest("authored-claim"),
            classification="nominally_paired",
            variance_reduction_claim_permitted=False,
        )


def test_live_protocol_must_classify_provider_and_temporal_randomness() -> None:
    payload = _protocol_payload()
    payload["coupling"] = CouplingDescriptor(
        pairing_identity_verified=True,
        stochastic_dimensions=("provider_sampling_randomness",),
        shared=("case_identity",),
        intentionally_different=("governing_corpus_digest",),
        not_shared=("provider_sampling_randomness",),
        classification="nominally_paired",
        variance_reduction_claim_permitted=False,
    )
    with pytest.raises(ValidationError, match="temporal execution order"):
        RepeatedEvidenceSensitivityProtocol.build(**payload)


@pytest.mark.parametrize(
    "malformation",
    (
        "missing_temporal",
        "shared_provider",
        "shared_temporal",
        "seed_sharing_digest",
        "variance_reduction_claim",
    ),
)
def test_live_coupling_hardening_is_exported_to_json_schema(
    malformation: str,
) -> None:
    serialized = RepeatedEvidenceSensitivityProtocol.build(**_protocol_payload()).model_dump(
        mode="json"
    )
    validator = Draft202012Validator(
        RepeatedEvidenceSensitivityProtocol.model_json_schema(mode="validation")
    )
    validator.validate(serialized)
    coupling = cast(dict[str, object], serialized["coupling"])

    if malformation == "missing_temporal":
        coupling["stochastic_dimensions"] = ["provider_sampling_randomness"]
        coupling["not_shared"] = ["provider_sampling_randomness"]
    elif malformation == "shared_provider":
        coupling["shared"] = ["case_identity", "provider_sampling_randomness"]
        coupling["not_shared"] = ["temporal_execution_order"]
        coupling["classification"] = "partially_coupled"
    elif malformation == "shared_temporal":
        coupling["shared"] = ["case_identity", "temporal_execution_order"]
        coupling["not_shared"] = ["provider_sampling_randomness"]
        coupling["classification"] = "partially_coupled"
    elif malformation == "seed_sharing_digest":
        coupling["provider_seed_sharing_evidence_digest"] = _digest("authored-claim")
    else:
        coupling["variance_reduction_claim_permitted"] = True

    with pytest.raises(JsonSchemaValidationError):
        validator.validate(serialized)


@pytest.mark.parametrize("partition", ("intentionally_different", "not_shared"))
def test_fully_coupled_schema_rejects_unshared_stochastic_dimensions(
    partition: str,
) -> None:
    validator = Draft202012Validator(CouplingDescriptor.model_json_schema(mode="validation"))
    valid = {
        "pairing_identity_verified": True,
        "stochastic_dimensions": ["retrieval_randomness"],
        "shared": ["retrieval_randomness"],
        "intentionally_different": [],
        "not_shared": [],
        "unknown": [],
        "classification": "fully_coupled",
    }
    validator.validate(valid)
    malformed = {
        **valid,
        "shared": [],
        partition: ["retrieval_randomness"],
    }

    with pytest.raises(JsonSchemaValidationError):
        validator.validate(malformed)


@pytest.mark.parametrize(
    ("pairing_identity_verified", "classification"),
    ((False, "nominally_paired"), (True, "unpaired")),
)
def test_pairing_identity_and_unpaired_classification_are_bidirectional_in_schema(
    pairing_identity_verified: bool,
    classification: str,
) -> None:
    payload = {
        "pairing_identity_verified": pairing_identity_verified,
        "stochastic_dimensions": ["provider_sampling_randomness"],
        "shared": [],
        "intentionally_different": [],
        "not_shared": ["provider_sampling_randomness"],
        "unknown": [],
        "classification": classification,
    }

    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(CouplingDescriptor.model_json_schema(mode="validation")).validate(
            payload
        )


def test_protocol_rejects_unsupported_endpoint() -> None:
    protocol = RepeatedEvidenceSensitivityProtocol.build(**_protocol_payload())
    payload = protocol.model_dump(mode="json")
    payload["endpoint"] = "continuous_score"
    with pytest.raises(ValidationError):
        RepeatedEvidenceSensitivityProtocol.model_validate(payload)


def test_protocol_requires_authority_direction_not_merely_distinct_strings() -> None:
    payload = _protocol_payload()
    payload["counterfactual_arm"] = _arm(
        "counterfactual_evidence",
        configuration="counterfactual-config",
        corpus="counterfactual-corpus",
        expected_recommendation="escalate",
        expected_outcome="escalated",
    )
    with pytest.raises(ValidationError, match="one expected approve arm and one expected deny arm"):
        RepeatedEvidenceSensitivityProtocol.build(**payload)


def test_exact_p_value_expression_has_a_constant_small_serialized_bound() -> None:
    expression = ExactBinomialTailExpression(
        trials=10_000,
        threshold=9_999,
        probability_numerator=333_333,
    )

    serialized = json.dumps(expression.model_dump(mode="json"), separators=(",", ":"))
    assert len(serialized.encode("utf-8")) < 256


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("provider", "different-provider"),
        ("requested_model", "different-model"),
        ("prompt_manifest_digest", _digest("different-prompt")),
        ("tool_schema_digest", _digest("different-tool-schema")),
        ("policy_bundle_digest", _digest("different-policy")),
    ],
)
def test_protocol_rejects_every_undeclared_arm_identity_difference(
    field: str,
    value: str,
) -> None:
    payload = _protocol_payload()
    payload["counterfactual_arm"] = _arm(
        "counterfactual_evidence",
        configuration="counterfactual-config",
        corpus="counterfactual-corpus",
        **{field: value},
    )
    with pytest.raises(ValidationError, match="undeclared paired-arm identity"):
        RepeatedEvidenceSensitivityProtocol.build(**payload)


def test_case_cluster_bindings_are_required_and_frozen() -> None:
    payload = _protocol_payload()
    payload.pop("case_cluster_bindings")
    with pytest.raises(ValidationError, match="case_cluster_bindings"):
        RepeatedEvidenceSensitivityProtocol.build(**payload)

    payload = _protocol_payload()
    cases = payload["planned_case_ids"]
    assert isinstance(cases, tuple)
    payload["case_cluster_bindings"] = tuple(
        CaseClusterBinding(
            case_id=case_id,
            cluster_id=(cases[1] if index == 0 else cases[0] if index == 1 else case_id),
        )
        for index, case_id in enumerate(cases)
    )
    with pytest.raises(ValidationError, match="identity case-to-cluster mapping"):
        RepeatedEvidenceSensitivityProtocol.build(**payload)


def test_v1_rejects_unbalanced_cluster_case_composition() -> None:
    payload = _protocol_payload()
    cases = payload["planned_case_ids"]
    clusters = payload["planned_cluster_ids"]
    assert isinstance(cases, tuple)
    assert isinstance(clusters, tuple)
    extra_case = "case-08"
    payload["inferential_unit"] = "source_group_id"
    payload["cluster_by"] = "source_group_id"
    payload["planned_case_ids"] = (*cases, extra_case)
    payload["case_cluster_bindings"] = (
        *(CaseClusterBinding(case_id=case_id, cluster_id=case_id) for case_id in cases),
        CaseClusterBinding(case_id=extra_case, cluster_id=clusters[0]),
    )
    authority_bindings = cast(
        tuple[RAGSensitivityCaseAuthorityBinding, ...],
        payload["case_authority_bindings"],
    )
    payload["case_authority_bindings"] = (
        *authority_bindings,
        authority_bindings[0].model_copy(update={"case_id": extra_case}),
    )
    payload["planned_pairs"] = len(cases) + 1

    with pytest.raises(ValidationError, match="same number of cases"):
        RepeatedEvidenceSensitivityProtocol.build(**payload)


def test_protocol_self_digest_detects_tampering() -> None:
    protocol = RepeatedEvidenceSensitivityProtocol.build(**_protocol_payload())
    payload = protocol.model_dump(mode="json")
    payload["multiplicity_family"] = "post-hoc-family"
    with pytest.raises(ValidationError, match="protocol_digest"):
        RepeatedEvidenceSensitivityProtocol.model_validate(payload)


def test_design_commitment_detects_preanalysis_design_tampering() -> None:
    protocol = RepeatedEvidenceSensitivityProtocol.build(**_protocol_payload())
    payload = protocol.model_dump(mode="json")
    assert isinstance(payload["design"], dict)
    payload["design"]["monte_carlo_resamples"] = 2_000
    with pytest.raises(ValidationError, match="design_commitment_digest"):
        RepeatedEvidenceSensitivityProtocol.model_validate(
            payload,
            context={"skip_self_digest": True},
        )


def test_design_commitment_binds_both_exact_arm_configurations_and_direction() -> None:
    protocol = RepeatedEvidenceSensitivityProtocol.build(**_protocol_payload())
    for arm_field, nested_field, value in (
        ("baseline_arm", "configuration_digest", _digest("post-hoc-config")),
        ("counterfactual_arm", "expected_recommendation", "escalate"),
    ):
        payload = protocol.model_dump(mode="json")
        assert isinstance(payload[arm_field], dict)
        payload[arm_field][nested_field] = value
        if nested_field == "expected_recommendation":
            payload[arm_field]["expected_outcome"] = "escalated"
        with pytest.raises(ValidationError, match="design_commitment_digest|decision_flip"):
            RepeatedEvidenceSensitivityProtocol.model_validate(
                payload,
                context={"skip_self_digest": True},
            )


def test_endpoint_is_derived_from_structured_decisions_and_exact_sources() -> None:
    source_fields = {
        "baseline_run_id": "baseline-run",
        "baseline_run_digest": _digest("baseline-run"),
        "counterfactual_run_id": "counterfactual-run",
        "counterfactual_run_digest": _digest("counterfactual-run"),
    }
    with pytest.raises(ValidationError, match="exactly derived"):
        PairedSensitivityObservation(
            case_id="case-00",
            repetition_index=0,
            cluster_id="case-00",
            disposition="included",
            baseline_recommendation="approve",
            baseline_outcome="approved",
            counterfactual_recommendation="deny",
            counterfactual_outcome="denied",
            baseline_expected_recommendation="approve",
            baseline_expected_outcome="approved",
            counterfactual_expected_recommendation="deny",
            counterfactual_expected_outcome="denied",
            endpoint_value=0,
            **source_fields,
        )

    with pytest.raises(ValidationError, match="exact source run dependencies"):
        PairedSensitivityObservation(
            case_id="case-00",
            repetition_index=0,
            cluster_id="case-00",
            disposition="included",
            baseline_recommendation="approve",
            baseline_outcome="approved",
            counterfactual_recommendation="deny",
            counterfactual_outcome="denied",
            baseline_expected_recommendation="approve",
            baseline_expected_outcome="approved",
            counterfactual_expected_recommendation="deny",
            counterfactual_expected_outcome="denied",
            endpoint_value=1,
        )

    wrong_direction = PairedSensitivityObservation(
        case_id="case-00",
        repetition_index=0,
        cluster_id="case-00",
        disposition="included",
        baseline_recommendation="deny",
        baseline_outcome="denied",
        counterfactual_recommendation="approve",
        counterfactual_outcome="approved",
        baseline_expected_recommendation="approve",
        baseline_expected_outcome="approved",
        counterfactual_expected_recommendation="deny",
        counterfactual_expected_outcome="denied",
        endpoint_value=0,
        **source_fields,
    )
    assert wrong_direction.endpoint_value == 0
