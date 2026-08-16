from __future__ import annotations

import json
import time
import tracemalloc
from collections.abc import Callable, Mapping
from copy import deepcopy
from dataclasses import replace
from datetime import date
from pathlib import Path
from typing import Any, cast

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import ValidationError

from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.evaluation.evaluator import (
    EvaluationReport,
    evaluate_runset,
    runset_digest,
)
from agent_assure.fixtures.loader import compiled_suite_digest
from agent_assure.mutation import campaign as mutation_campaign
from agent_assure.mutation import execution as mutation_execution
from agent_assure.mutation.campaign import (
    MutationCampaignExecution,
    MutationCampaignSourceError,
    build_core_catalog,
    execute_mutation_campaign,
    mutation_campaign_exit_code,
)
from agent_assure.mutation.catalog import RegisteredOperator, registered_operators
from agent_assure.mutation.execution import (
    MutationEvaluatorBinding,
    MutationExecution,
    execute_mutation,
    mutation_gate_profile_digest,
    mutation_waiver_set_digest,
)
from agent_assure.mutation.operators import MutationTarget
from agent_assure.policies.base import DEFAULT_GATE_PROFILE
from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.reporting.campaign import write_mutation_campaign_artifacts
from agent_assure.schema.campaign import (
    CORE_MUTATION_CATALOG_ID,
    AssuranceMutationCampaign,
    AssuranceMutationCatalog,
    MutationApplicability,
    MutationCampaignCompletion,
    MutationCampaignMode,
    MutationCampaignOperatorResult,
)
from agent_assure.schema.common import GateState, ReasonCode
from agent_assure.schema.evaluation import Finding
from agent_assure.schema.expectation import Expectation
from agent_assure.schema.export import writer_json_schema
from agent_assure.schema.mutation import (
    AssuranceMutationOperator,
    AssuranceMutationResult,
    EvidenceEvaluationBasis,
    ExpectedDetectionContract,
    MutationResultState,
)
from agent_assure.schema.provenance import Provenance
from agent_assure.schema.run import (
    AgentRunRecord,
    ClaimEvidenceLink,
    EvidenceItem,
    EvidenceRef,
    RunSet,
)
from agent_assure.schema.suite import CompiledSuite, SuiteCase, SuiteDefaults
from agent_assure.schema.validation import validate_artifact_payload

_GENERATED_AT = "2026-07-20T00:00:00Z"
_EVALUATION_DATE = date(2026, 7, 20)
_CORE_OPERATOR_COUNT = 7
_CORE_CATASTROPHIC_RUNTIME_BUDGET_SECONDS = 30.0
_CORE_PEAK_MEMORY_BUDGET_BYTES = 128 * 1024 * 1024
_ROOT = Path(__file__).resolve().parents[3]


def test_catalog_digest_is_the_complete_serialized_projection() -> None:
    catalog = build_core_catalog()
    projection = catalog.model_dump(mode="json", exclude={"catalog_digest"})

    assert catalog.catalog_digest == sha256_hexdigest(projection)


@pytest.mark.parametrize(
    ("path", "replacement"),
    (
        pytest.param(("catalog_id",), "core/v2", id="catalog-id"),
        pytest.param(
            ("operators", 0, "descriptor", "operator_id"),
            "substituted-core-operator",
            id="operator-id",
        ),
        pytest.param(
            ("operators", 0, "descriptor", "operator_version"),
            "1.0.1",
            id="operator-version",
        ),
        pytest.param(
            ("operators", 0, "descriptor", "implementation_digest"),
            "0" * 64,
            id="implementation-digest",
        ),
        pytest.param(
            (
                "operators",
                0,
                "descriptor",
                "provenance",
                "implementation_components",
                0,
                "sha256",
            ),
            "0" * 64,
            id="implementation-component-manifest",
        ),
        pytest.param(
            (
                "operators",
                0,
                "descriptor",
                "expected_detection_contract",
                "contract_digest",
            ),
            "0" * 64,
            id="expected-contract-digest",
        ),
        pytest.param(
            (
                "operators",
                0,
                "descriptor",
                "provenance",
                "introduced_in_release",
            ),
            "9.9.9",
            id="operator-provenance",
        ),
        pytest.param(
            ("ordering_semantics",),
            "operator-id-reverse/v2",
            id="ordering-semantics",
        ),
    ),
)
def test_catalog_digest_projection_covers_required_identity_fields(
    path: tuple[str | int, ...],
    replacement: object,
) -> None:
    catalog = build_core_catalog()
    projection = catalog.model_dump(mode="json", exclude={"catalog_digest"})
    changed = deepcopy(projection)

    _replace_projection_value(changed, path, replacement)

    assert sha256_hexdigest(changed) != catalog.catalog_digest


def test_catalog_digest_projection_preserves_serialized_operator_order() -> None:
    catalog = build_core_catalog()
    projection = catalog.model_dump(mode="json", exclude={"catalog_digest"})
    changed = deepcopy(projection)
    operators = cast(list[object], changed["operators"])
    operators[0], operators[1] = operators[1], operators[0]

    assert sha256_hexdigest(changed) != catalog.catalog_digest


def test_core_catalog_is_closed_canonical_and_order_invariant() -> None:
    registered = registered_operators()

    forward = build_core_catalog(registered)
    reverse = build_core_catalog(reversed(registered))

    assert forward == reverse
    assert forward.catalog_id == CORE_MUTATION_CATALOG_ID
    assert len(forward.operators) == _CORE_OPERATOR_COUNT
    operator_ids = tuple(item.descriptor.operator_id for item in forward.operators)
    assert operator_ids == tuple(sorted(operator_ids))
    assert len({item.invariant_family for item in forward.operators}) >= 6
    assert all(item.stable for item in forward.operators)
    assert all(item.threat_source_references for item in forward.operators)
    assert validate_artifact_payload(
        forward.model_dump(mode="json"),
        "assurance-mutation-catalog",
    ) == ("pydantic+jsonschema")

    with pytest.raises(
        ValueError,
        match="exactly the registered core operator IDs",
    ):
        build_core_catalog(registered[:-1])


def test_core_catalog_json_schema_rejects_substituted_operator_identity() -> None:
    payload = build_core_catalog().model_dump(mode="json")
    operators = cast(list[dict[str, object]], payload["operators"])
    descriptor = cast(dict[str, object], operators[0]["descriptor"])
    descriptor["operator_id"] = "substituted-core-operator"

    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(writer_json_schema(AssuranceMutationCatalog)).validate(payload)


def test_frozen_v061_catalog_applies_self_digest_validation_after_shape() -> None:
    payload = _v061_evidence_root_payload(build_core_catalog().model_dump(mode="json"))

    assert validate_artifact_payload(payload, "assurance-mutation-catalog") == "frozen-jsonschema"

    payload["catalog_digest"] = "0" * 64
    frozen_schema = json.loads(
        (_ROOT / "schemas" / "v0.6.1" / "assurance-mutation-catalog.schema.json").read_text(
            encoding="utf-8"
        )
    )
    Draft202012Validator(frozen_schema).validate(payload)
    with pytest.raises(ValueError, match="failed model validation"):
        validate_artifact_payload(payload, "assurance-mutation-catalog")


def test_current_catalog_rejects_v060_label_on_current_nested_operator() -> None:
    payload = build_core_catalog().model_dump(mode="json")
    operators = cast(list[dict[str, Any]], payload["operators"])
    descriptor = cast(
        dict[str, Any],
        next(
            item["descriptor"]
            for item in operators
            if cast(dict[str, object], item["descriptor"])["operator_id"]
            == "inject-synthetic-sensitive-summary"
        ),
    )
    contract = cast(dict[str, Any], descriptor["expected_detection_contract"])
    contract["schema_version"] = "0.6.0"
    _refresh_self_digest(contract, "contract_digest")
    descriptor["schema_version"] = "0.6.0"
    _refresh_self_digest(descriptor, "operator_digest")
    _refresh_self_digest(payload, "catalog_digest")

    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(writer_json_schema(AssuranceMutationCatalog)).validate(payload)
    with pytest.raises(
        ValidationError,
        match="catalog and nested operator schema versions must match",
    ):
        AssuranceMutationCatalog.model_validate(payload)


def test_catalog_digest_changes_with_expected_detector_contract() -> None:
    registered = registered_operators()
    original = registered[0]
    original_contract = original.descriptor.expected_detection_contract
    contract_payload = original_contract.model_dump(
        mode="python",
        exclude={"contract_digest"},
    )
    contract_payload["expected_gate_effect"] = "review"
    changed_contract = ExpectedDetectionContract.build(**contract_payload)
    descriptor_payload = original.descriptor.model_dump(
        mode="python",
        exclude={"operator_digest"},
    )
    descriptor_payload["expected_detection_contract"] = changed_contract
    changed_descriptor = AssuranceMutationOperator.build(**descriptor_payload)
    changed_operator = replace(original, descriptor=changed_descriptor)
    changed_operators = (
        changed_operator,
        *(item for item in registered if item is not original),
    )

    baseline = build_core_catalog(registered)
    changed = build_core_catalog(changed_operators)

    assert (
        changed.operators[0].descriptor.expected_detection_contract.contract_digest
        != baseline.operators[0].descriptor.expected_detection_contract.contract_digest
    )
    assert changed.catalog_digest != baseline.catalog_digest


def test_full_core_campaign_is_replayable_isolated_and_normatively_caught() -> None:
    suite, source = _fixture()
    source_before = deepcopy(source)

    first = _campaign(suite, source, seed=7331)
    replay = _campaign(
        suite,
        deepcopy(source),
        seed=7331,
        catalog_operators=tuple(reversed(registered_operators())),
    )

    assert source == source_before
    assert first.catalog == replay.catalog
    assert first.campaign == replay.campaign
    assert first.campaign.campaign_digest == replay.campaign.campaign_digest
    assert len(first.operator_executions) == _CORE_OPERATOR_COUNT
    assert all(
        item.result.state is MutationResultState.caught for item in first.campaign.operator_results
    )
    assert all(
        item.result.source_digest == first.campaign.source_digest
        for item in first.campaign.operator_results
    )
    assert all(execution.mutated_payload != source for execution in first.operator_executions)
    assert mutation_campaign_exit_code(first.campaign) == 0

    serialized = first.campaign.model_dump(mode="json")
    field_names = _nested_field_names(serialized)
    assert not {
        "confidence_interval",
        "kill_rate",
        "safety_score",
        "universal_coverage",
    }.intersection(field_names)
    assert "not a safety score" in " ".join(serialized["limitations"]).lower()
    assert validate_artifact_payload(
        serialized,
        "assurance-mutation-campaign",
    ) == ("pydantic+jsonschema")


def test_default_omitting_campaign_projects_source_once_and_binds_digests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    suite, source = _fixture()
    source.pop("execution_mode")
    source.pop("completion_status")
    source.pop("stop_reasons")
    source_before = deepcopy(source)
    projected_source = RunSet.model_validate(source)
    expected_source_digest = runset_digest(projected_source)
    projection_calls = 0
    evaluator_digests: list[str] = []
    original_projection = mutation_campaign.validated_runset_projection

    def counting_projection(
        payload: Mapping[str, object],
    ) -> tuple[RunSet, dict[str, object]]:
        nonlocal projection_calls
        projection_calls += 1
        return original_projection(payload)

    def recording_evaluator(
        compiled: CompiledSuite,
        subject: RunSet,
    ) -> EvaluationReport:
        report = evaluate_runset(compiled, subject, today=_EVALUATION_DATE)
        assert report.runset_digest is not None
        evaluator_digests.append(report.runset_digest)
        return report

    monkeypatch.setattr(
        mutation_campaign,
        "validated_runset_projection",
        counting_projection,
    )

    execution = _campaign(
        suite,
        source,
        seed=17,
        operator_ids=("drop-material-evidence-link",),
        evaluator_binding=_bound_evaluator(recording_evaluator),
    )
    operator_execution = execution.operator_executions[0]
    result = operator_execution.result

    assert projection_calls == 1
    assert expected_source_digest != sha256_hexdigest(source)
    assert execution.campaign.source_digest == expected_source_digest
    assert execution.campaign.operator_results[0].result.source_digest == (expected_source_digest)
    assert result.source_digest == expected_source_digest
    assert operator_execution.evidence_descriptor.subject.digest == (expected_source_digest)
    assert operator_execution.mutated_payload is not None
    assert result.mutated_digest is not None
    assert result.mutated_digest == runset_digest(
        RunSet.model_validate(operator_execution.mutated_payload)
    )
    assert evaluator_digests == [expected_source_digest, result.mutated_digest]
    assert source == source_before


@pytest.mark.parametrize(
    "noncanonical_value",
    (1.25, ("tuple-is-not-json",)),
    ids=("float", "projection-equivalent-tuple"),
)
def test_campaign_rejects_noncanonical_source_before_operator_execution(
    monkeypatch: pytest.MonkeyPatch,
    noncanonical_value: object,
) -> None:
    suite, source = _fixture()
    sensitive_value = "Bearer campaign-preflight-secret-123456789"
    source["unexpected_value"] = noncanonical_value
    source["unexpected_context"] = sensitive_value

    def unexpected_execute(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("operator execution must not start")

    monkeypatch.setattr(
        mutation_campaign,
        "execute_mutation",
        unexpected_execute,
    )

    with pytest.raises(MutationCampaignSourceError) as captured:
        _campaign(
            suite,
            source,
            seed=17,
            operator_ids=("drop-material-evidence-link",),
        )

    assert str(captured.value) == (
        "mutation campaign source cannot establish a canonical JSON identity"
    )
    assert sensitive_value not in str(captured.value)


def test_campaign_rejects_schema_invalid_source_before_privacy_or_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    suite, source = _fixture()
    source.pop("suite_id")
    source_before = deepcopy(source)

    def unexpected_progress(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("campaign preflight must stop at RunSet projection")

    monkeypatch.setattr(
        mutation_campaign,
        "assert_runset_payload_safe_for_persistence",
        unexpected_progress,
    )
    monkeypatch.setattr(
        mutation_campaign,
        "sha256_hexdigest",
        unexpected_progress,
    )
    monkeypatch.setattr(
        mutation_campaign,
        "build_core_catalog",
        unexpected_progress,
    )
    monkeypatch.setattr(
        mutation_campaign,
        "execute_mutation",
        unexpected_progress,
    )

    with pytest.raises(MutationCampaignSourceError) as captured:
        _campaign(
            suite,
            source,
            seed=17,
            operator_ids=("drop-material-evidence-link",),
        )

    assert str(captured.value) == (
        "mutation campaign source failed RunSet validation and projection"
    )
    assert source == source_before


def test_campaign_rejects_sensitive_source_before_identity_or_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    suite, source = _fixture()
    sensitive_value = "Bearer campaign-preflight-secret-123456789"
    runs = cast(list[dict[str, object]], source["runs"])
    runs[0]["input_summary"] = sensitive_value
    source_before = deepcopy(source)

    def unexpected_progress(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("privacy preflight must stop campaign execution")

    monkeypatch.setattr(
        mutation_campaign,
        "sha256_hexdigest",
        unexpected_progress,
    )
    monkeypatch.setattr(
        mutation_campaign,
        "build_core_catalog",
        unexpected_progress,
    )
    monkeypatch.setattr(
        mutation_campaign,
        "execute_mutation",
        unexpected_progress,
    )

    with pytest.raises(MutationCampaignSourceError) as captured:
        _campaign(
            suite,
            source,
            seed=17,
            operator_ids=("drop-material-evidence-link",),
        )

    assert str(captured.value) == (
        "mutation campaign source failed the bound privacy-detector profile"
    )
    assert sensitive_value not in str(captured.value)
    assert source == source_before


@pytest.mark.parametrize(
    "tamper_mode",
    ("canonical-change", "noncanonical-change", "projection-equivalent-change"),
)
def test_campaign_detects_mutation_of_its_isolated_source_copy(
    monkeypatch: pytest.MonkeyPatch,
    tamper_mode: str,
) -> None:
    suite, source = _fixture()
    source_before = deepcopy(source)
    operator_id = "drop-material-evidence-link"
    expected_execution = execute_mutation(
        suite,
        source,
        operator_id=operator_id,
        seed=17,
        generated_at=_GENERATED_AT,
        evaluation_date=_EVALUATION_DATE,
    )

    def mutate_campaign_source(
        _suite: CompiledSuite,
        campaign_source: Mapping[str, object],
        **_kwargs: object,
    ) -> MutationExecution:
        source_mapping = cast(dict[str, object], campaign_source)
        runs = cast(list[dict[str, object]], campaign_source["runs"])
        if tamper_mode == "canonical-change":
            runs[0]["output_summary"] = "tampered campaign source"
        elif tamper_mode == "noncanonical-change":
            runs[0]["output_summary"] = 1.25
        else:
            # Tuple and list share a digest projection, but only list is JSON.
            source_mapping["runs"] = tuple(runs)
        return expected_execution

    monkeypatch.setattr(
        mutation_campaign,
        "execute_mutation",
        mutate_campaign_source,
    )

    with pytest.raises(
        RuntimeError,
        match="mutation campaign source changed during isolated execution",
    ):
        _campaign(
            suite,
            source,
            seed=17,
            operator_ids=(operator_id,),
        )

    assert source == source_before


def test_campaign_schema_rejects_recomputed_cross_source_binding() -> None:
    suite, source = _fixture()
    campaign = _campaign(suite, source, seed=17).campaign
    payload = campaign.model_dump(mode="python", exclude={"campaign_digest"})
    payload["source_digest"] = "f" * 64

    with pytest.raises(
        ValidationError,
        match="same source digest",
    ):
        AssuranceMutationCampaign.build(**payload)


def test_current_campaign_rejects_v060_labels_on_nested_contract_and_result() -> None:
    suite, source = _fixture()
    payload = _campaign(
        suite,
        source,
        seed=17,
        operator_ids=("inject-synthetic-sensitive-summary",),
    ).campaign.model_dump(mode="json")
    entries = cast(list[dict[str, Any]], payload["operator_results"])
    entry = entries[0]
    contract = cast(dict[str, Any], entry["expected_detection_contract"])
    result = cast(dict[str, Any], entry["result"])
    contract["schema_version"] = "0.6.0"
    _refresh_self_digest(contract, "contract_digest")
    result["schema_version"] = "0.6.0"
    result["expected_detection_contract_digest"] = contract["contract_digest"]
    _refresh_self_digest(result, "result_digest")
    _refresh_self_digest(payload, "campaign_digest")

    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(writer_json_schema(AssuranceMutationCampaign)).validate(payload)
    with pytest.raises(
        ValidationError,
        match="campaign and nested contract/result schema versions must match",
    ):
        AssuranceMutationCampaign.model_validate(payload)


def test_frozen_v061_campaign_applies_self_digest_validation_after_shape() -> None:
    suite, source = _fixture()
    payload = _v061_evidence_root_payload(
        _campaign(
            suite,
            source,
            seed=17,
            operator_ids=("inject-synthetic-sensitive-summary",),
        ).campaign.model_dump(mode="json")
    )

    assert validate_artifact_payload(payload, "assurance-mutation-campaign") == "frozen-jsonschema"

    payload["campaign_digest"] = "0" * 64
    frozen_schema = json.loads(
        (_ROOT / "schemas" / "v0.6.1" / "assurance-mutation-campaign.schema.json").read_text(
            encoding="utf-8"
        )
    )
    Draft202012Validator(frozen_schema).validate(payload)
    with pytest.raises(ValueError, match="failed model validation"):
        validate_artifact_payload(payload, "assurance-mutation-campaign")


def test_campaign_selected_operator_order_is_unique_and_canonical() -> None:
    suite, source = _fixture()
    campaign = _campaign(suite, source, seed=17).campaign
    first, second = campaign.selected_operator_order[:2]

    duplicate_payload = campaign.model_dump(
        mode="python",
        exclude={"campaign_digest"},
    )
    duplicate_payload["selected_operator_order"] = (first, first)
    with pytest.raises(ValidationError, match="selected operator IDs must be unique"):
        AssuranceMutationCampaign.build(**duplicate_payload)

    reordered_payload = campaign.model_dump(
        mode="python",
        exclude={"campaign_digest"},
    )
    reordered_payload["selected_operator_order"] = (second, first)
    with pytest.raises(
        ValidationError,
        match="selected operator order must be a canonical catalog subsequence",
    ):
        AssuranceMutationCampaign.build(**reordered_payload)


def test_campaign_writer_rejects_self_valid_expected_contract_not_in_catalog(
    tmp_path: Path,
) -> None:
    suite, source = _fixture()
    baseline = _campaign(
        suite,
        source,
        seed=17,
        operator_ids=("drop-material-evidence-link",),
    )
    original_entry = baseline.campaign.operator_results[0]
    contract_payload = original_entry.expected_detection_contract.model_dump(
        mode="python",
        exclude={"contract_digest"},
    )
    contract_payload["expected_gate_effect"] = "review"
    changed_contract = ExpectedDetectionContract.build(**contract_payload)
    result_payload = original_entry.result.model_dump(
        mode="python",
        exclude={"result_digest"},
    )
    result_payload["expected_detection_contract_digest"] = changed_contract.contract_digest
    changed_result = AssuranceMutationResult.build(**result_payload)
    changed_entry = MutationCampaignOperatorResult(
        operator_id=original_entry.operator_id,
        invariant_family=original_entry.invariant_family,
        seed=original_entry.seed,
        applicability=original_entry.applicability,
        expected_detection_contract=changed_contract,
        result=changed_result,
        prohibited_substitute_finding_ids=(original_entry.prohibited_substitute_finding_ids),
    )
    campaign_payload = baseline.campaign.model_dump(
        mode="python",
        exclude={"campaign_digest"},
    )
    campaign_payload["operator_results"] = (changed_entry,)
    changed_campaign = AssuranceMutationCampaign.build(**campaign_payload)
    altered_execution = MutationCampaignExecution(
        catalog=baseline.catalog,
        campaign=changed_campaign,
        operator_executions=baseline.operator_executions,
    )

    with pytest.raises(
        ValueError,
        match="expected detector does not match its catalog",
    ):
        write_mutation_campaign_artifacts(
            altered_execution,
            tmp_path / "altered-campaign",
        )


def test_campaign_writer_rejects_invariant_family_not_in_catalog(
    tmp_path: Path,
) -> None:
    suite, source = _fixture()
    baseline = _campaign(
        suite,
        source,
        seed=17,
        operator_ids=("drop-material-evidence-link",),
    )
    original_entry = baseline.campaign.operator_results[0]
    changed_entry = original_entry.model_copy(
        update={"invariant_family": "substituted-invariant-family"}
    )
    campaign_payload = baseline.campaign.model_dump(
        mode="python",
        exclude={"campaign_digest"},
    )
    campaign_payload["operator_results"] = (changed_entry,)
    changed_campaign = AssuranceMutationCampaign.build(**campaign_payload)
    altered_execution = MutationCampaignExecution(
        catalog=baseline.catalog,
        campaign=changed_campaign,
        operator_executions=baseline.operator_executions,
    )

    with pytest.raises(
        ValueError,
        match="invariant family does not match its catalog",
    ):
        write_mutation_campaign_artifacts(
            altered_execution,
            tmp_path / "altered-family-campaign",
        )


def test_filtered_campaign_preserves_the_full_campaign_operator_result() -> None:
    suite, source = _fixture()
    full = _campaign(suite, source, seed=29)
    selected_id = "skew-evidence-source-identity"

    filtered = _campaign(
        suite,
        source,
        seed=29,
        operator_ids=(selected_id,),
    )

    expected = next(
        item for item in full.campaign.operator_results if item.operator_id == selected_id
    )
    assert filtered.campaign.operator_results == (expected,)
    assert filtered.campaign.catalog_digest == full.campaign.catalog_digest


def test_full_report_continues_after_survivor_and_fail_fast_stops() -> None:
    suite, source = _fixture()
    weakened = _bound_evaluator(
        _without_detector(
            "human_review_required",
            ReasonCode.REQUIRED_HUMAN_REVIEW_ABSENT,
        )
    )

    full = _campaign(
        suite,
        source,
        seed=17,
        evaluator_binding=weakened,
    )
    fail_fast = _campaign(
        suite,
        source,
        seed=17,
        evaluator_binding=weakened,
        mode=MutationCampaignMode.fail_fast,
    )

    assert full.campaign.completion is MutationCampaignCompletion.complete
    assert len(full.campaign.operator_results) == _CORE_OPERATOR_COUNT
    assert full.campaign.operator_results[0].result.state is MutationResultState.survived
    assert all(
        item.result.state is MutationResultState.caught
        for item in full.campaign.operator_results[1:]
    )
    assert mutation_campaign_exit_code(full.campaign) == 1

    assert fail_fast.campaign.completion is MutationCampaignCompletion.stopped_early
    assert len(fail_fast.campaign.operator_results) == 1
    assert len(fail_fast.campaign.pending_operator_order) == _CORE_OPERATOR_COUNT - 1
    assert fail_fast.campaign.operator_results[0].result.state is (MutationResultState.survived)
    assert mutation_campaign_exit_code(fail_fast.campaign) == 1

    continued_payload = full.campaign.model_dump(
        mode="python",
        exclude={"campaign_digest"},
    )
    continued_payload["mode"] = MutationCampaignMode.fail_fast
    with pytest.raises(
        ValidationError,
        match="cannot continue after a stopping result",
    ):
        AssuranceMutationCampaign.build(**continued_payload)


def test_fail_fast_campaign_cannot_claim_early_stop_after_caught() -> None:
    suite, source = _fixture()
    full = _campaign(suite, source, seed=17)
    first_entry = full.campaign.operator_results[0]
    selected = full.campaign.selected_operator_order
    stopped_payload = full.campaign.model_dump(
        mode="python",
        exclude={"campaign_digest"},
    )
    stopped_payload.update(
        {
            "mode": MutationCampaignMode.fail_fast,
            "completion": MutationCampaignCompletion.stopped_early,
            "executed_operator_order": selected[:1],
            "pending_operator_order": selected[1:],
            "operator_results": (first_entry,),
        }
    )

    with pytest.raises(
        ValidationError,
        match="must end with a stopping result",
    ):
        AssuranceMutationCampaign.build(**stopped_payload)


def test_full_report_isolates_an_operator_execution_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    suite, source = _fixture()
    operators = {item.descriptor.operator_id: item for item in registered_operators()}
    failing_id = min(operators)
    original = operators[failing_id]

    def fail_resolver(*_args: object, **_kwargs: object) -> tuple[()]:
        raise RuntimeError("synthetic isolated resolver failure")

    operators[failing_id] = replace(original, resolve_targets=fail_resolver)
    monkeypatch.setattr(
        mutation_execution,
        "resolve_operator",
        lambda operator_id: operators.get(operator_id),
    )

    execution = _campaign(suite, source, seed=17)
    states = {item.operator_id: item.result.state for item in execution.campaign.operator_results}

    assert states[failing_id] is MutationResultState.execution_error
    assert all(
        state is MutationResultState.caught
        for operator_id, state in states.items()
        if operator_id != failing_id
    )
    assert execution.campaign.completion is MutationCampaignCompletion.complete
    assert mutation_campaign_exit_code(execution.campaign) == 4

    failing_entry = next(
        item for item in execution.campaign.operator_results if item.operator_id == failing_id
    )
    relabeled = failing_entry.model_dump(mode="python")
    relabeled["applicability"] = "applicable"
    with pytest.raises(
        ValidationError,
        match="applicability must match its canonical result projection",
    ):
        MutationCampaignOperatorResult.model_validate(relabeled)


def test_operator_source_mutation_has_not_evaluated_applicability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    suite, source = _fixture()
    source_before = deepcopy(source)
    operator_id = "drop-material-evidence-link"
    registered = next(
        item for item in registered_operators() if item.descriptor.operator_id == operator_id
    )

    def mutating_resolver(
        compiled: CompiledSuite,
        subject: RunSet,
        payload: Mapping[str, object],
    ) -> tuple[MutationTarget, ...]:
        targets = registered.resolve_targets(compiled, subject, payload)
        runs = cast(list[dict[str, object]], payload["runs"])
        runs[0]["input_summary"] = "operator-mutated-working-source"
        return targets

    invalid = replace(registered, resolve_targets=mutating_resolver)
    monkeypatch.setattr(
        mutation_execution,
        "resolve_operator",
        lambda _operator_id: invalid,
    )

    execution = _campaign(
        suite,
        source,
        seed=17,
        operator_ids=(operator_id,),
    )
    entry = execution.campaign.operator_results[0]

    assert entry.result.state is MutationResultState.invalid_operator
    assert entry.result.diagnostic_code == "operator_mutated_source"
    assert entry.applicability is MutationApplicability.not_evaluated
    assert source == source_before


def test_prohibited_substitute_is_explicit_and_never_counts_as_caught() -> None:
    suite, source = _fixture()

    def substitute_only_evaluator(
        compiled: CompiledSuite,
        subject: RunSet,
    ) -> EvaluationReport:
        report = evaluate_runset(compiled, subject)
        if subject.runs[0].human_review_required and subject.runs[0].human_review_performed:
            return report
        substitute = Finding(
            finding_id="finding-prohibited-runtime-substitute",
            case_id="case-a",
            control_id="runtime_success_required",
            target=subject.runs[0].run_id,
            state=GateState.fail,
            reason_code=ReasonCode.RUNTIME_FAILED,
            message="synthetic substitute only",
        )
        summary = report.candidate_vs_expectations.model_copy(update={"findings": (substitute,)})
        return report.model_copy(
            update={
                "candidate_vs_expectations": summary,
                "failed_controls": (substitute,),
                "warning_controls": (),
            }
        )

    execution = _campaign(
        suite,
        source,
        seed=17,
        operator_ids=("bypass-required-human-review",),
        evaluator_binding=_bound_evaluator(substitute_only_evaluator),
    )
    entry = execution.campaign.operator_results[0]

    assert entry.result.state is MutationResultState.invalid_operator
    assert entry.result.matched_finding_ids == ()
    assert entry.prohibited_substitute_finding_ids == ("finding-prohibited-runtime-substitute",)
    assert {
        (finding.control_id, finding.reason_code) for finding in entry.result.observed_findings
    } == {("runtime_success_required", ReasonCode.RUNTIME_FAILED)}

    incomplete_entry = entry.model_dump(mode="python")
    incomplete_entry["prohibited_substitute_finding_ids"] = ()
    with pytest.raises(
        ValidationError,
        match="identify every matching observed finding",
    ):
        MutationCampaignOperatorResult.model_validate(incomplete_entry)


def test_all_inapplicable_campaign_has_distinct_exit_state() -> None:
    suite, source = _fixture(required_human_review=False)

    execution = _campaign(
        suite,
        source,
        seed=17,
        operator_ids=("bypass-required-human-review",),
    )

    assert execution.campaign.operator_results[0].result.state is (MutationResultState.inapplicable)
    assert mutation_campaign_exit_code(execution.campaign) == 3


def test_mixed_caught_and_inapplicable_campaign_exits_successfully() -> None:
    suite, source = _fixture(required_human_review=False)

    execution = _campaign(
        suite,
        source,
        seed=17,
        operator_ids=(
            "drop-material-evidence-link",
            "bypass-required-human-review",
        ),
    )

    assert tuple(item.result.state for item in execution.campaign.operator_results) == (
        MutationResultState.inapplicable,
        MutationResultState.caught,
    )
    assert tuple(item.applicability for item in execution.campaign.operator_results) == (
        MutationApplicability.inapplicable,
        MutationApplicability.applicable,
    )
    # Exit 3 is reserved for a campaign where no selected challenge applies.
    assert mutation_campaign_exit_code(execution.campaign) == 0


def test_core_fixture_campaign_and_persistence_stay_within_catastrophic_runtime_budget(
    tmp_path: Path,
) -> None:
    suite, source = _fixture()
    source_inputs = (tmp_path / "suite.yaml", tmp_path / "runset.json")
    for source_input in source_inputs:
        source_input.write_text("bounded source identity", encoding="utf-8")
    # Catalog resource hashing is process-cached and belongs to bootstrap, not
    # per-campaign execution. Warm it before measuring the campaign budget.
    registered_operators()
    started = time.perf_counter()
    execution = _campaign(suite, source, seed=17)
    execution_elapsed = time.perf_counter() - started

    persistence_started = time.perf_counter()
    paths = write_mutation_campaign_artifacts(
        execution,
        tmp_path / "campaign",
        source_inputs=source_inputs,
    )
    persistence_elapsed = time.perf_counter() - persistence_started

    assert len(execution.campaign.operator_results) == _CORE_OPERATOR_COUNT
    assert paths.generation_manifest.is_file()
    assert len(paths.operator_artifacts) == _CORE_OPERATOR_COUNT
    assert execution_elapsed < _CORE_CATASTROPHIC_RUNTIME_BUDGET_SECONDS
    assert persistence_elapsed < _CORE_CATASTROPHIC_RUNTIME_BUDGET_SECONDS


def test_core_fixture_campaign_stays_within_peak_memory_budget() -> None:
    suite, source = _fixture()
    # Keep tracing out of the wall-clock assertion. Its allocation hooks
    # disproportionately slow canonical serialization on some supported
    # interpreters, while the alias-guard suite separately pins deterministic
    # filesystem-operation complexity.
    registered_operators()
    tracemalloc.start()
    try:
        execution = _campaign(suite, source, seed=17)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert len(execution.campaign.operator_results) == _CORE_OPERATOR_COUNT
    assert peak < _CORE_PEAK_MEMORY_BUDGET_BYTES


def _campaign(
    suite: CompiledSuite,
    source: dict[str, object],
    *,
    seed: int,
    mode: MutationCampaignMode = MutationCampaignMode.full_report,
    operator_ids: tuple[str, ...] = (),
    evaluator_binding: MutationEvaluatorBinding | None = None,
    catalog_operators: tuple[RegisteredOperator, ...] | None = None,
) -> MutationCampaignExecution:
    return execute_mutation_campaign(
        suite,
        source,
        seed=seed,
        generated_at=_GENERATED_AT,
        mode=mode,
        operator_ids=operator_ids,
        evaluator_binding=evaluator_binding,
        evaluation_date=_EVALUATION_DATE,
        catalog_operators=catalog_operators,
    )


def _fixture(
    *,
    required_human_review: bool = True,
) -> tuple[CompiledSuite, dict[str, object]]:
    expectation = Expectation(
        expectation_id="expectation-case-a",
        case_id="case-a",
        material_claim_ids=("claim-a",),
        forbidden_tools=("blocked-tool",),
        required_human_review=required_human_review,
    )
    suite = CompiledSuite(
        suite_id="mutation-campaign-test-suite",
        suite_version="1.0.0",
        defaults=SuiteDefaults(
            runner_id="mutation.campaign.tests",
            allowed_tools=("safe-tool",),
        ),
        cases=(
            SuiteCase(
                case_id="case-a",
                title="Mutation campaign test case",
                expectation_id=expectation.expectation_id,
            ),
        ),
        resolved_expectations=(expectation,),
        source_digest="a" * 64,
    )
    fixture_digest = "c" * 64
    runset = RunSet(
        runset_id="mutation-campaign-test-runset",
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        suite_id=suite.suite_id,
        suite_version=suite.suite_version,
        suite_digest=compiled_suite_digest(suite),
        fixture_manifest_digest=fixture_digest,
        runs=(
            AgentRunRecord(
                run_id="run-case-a",
                case_id="case-a",
                pipeline_id="mutation.campaign.tests",
                recommendation="approve",
                outcome="approved",
                input_summary="synthetic input",
                output_summary="synthetic output",
                tools=("safe-tool",),
                evidence_refs=(
                    EvidenceRef(
                        ref_id="evidence-a",
                        source_id="source-a",
                        claim_ids=("claim-a",),
                    ),
                ),
                evidence_items=(
                    EvidenceItem(
                        ref_id="evidence-a",
                        source_id="source-a",
                        content_digest="d" * 64,
                    ),
                ),
                claim_evidence_links=(
                    ClaimEvidenceLink(
                        claim_id="claim-a",
                        evidence_ref_id="evidence-a",
                    ),
                ),
                human_review_required=required_human_review,
                human_review_performed=required_human_review,
                provenance=Provenance(fixture_manifest_digest=fixture_digest),
            ),
        ),
    )
    return suite, cast(dict[str, object], runset.model_dump(mode="json"))


def _without_detector(
    control_id: str,
    reason_code: ReasonCode,
) -> Callable[[CompiledSuite, RunSet], EvaluationReport]:
    def evaluate_without_detector(
        suite: CompiledSuite,
        subject: RunSet,
    ) -> EvaluationReport:
        report = evaluate_runset(suite, subject)
        findings = tuple(
            finding
            for finding in report.candidate_vs_expectations.findings
            if not (finding.control_id == control_id and finding.reason_code is reason_code)
        )
        failed = tuple(
            finding
            for finding in report.failed_controls
            if not (finding.control_id == control_id and finding.reason_code is reason_code)
        )
        warnings = tuple(
            finding
            for finding in report.warning_controls
            if not (finding.control_id == control_id and finding.reason_code is reason_code)
        )
        summary = report.candidate_vs_expectations.model_copy(update={"findings": findings})
        return report.model_copy(
            update={
                "candidate_vs_expectations": summary,
                "failed_controls": failed,
                "warning_controls": warnings,
            }
        )

    return evaluate_without_detector


def _bound_evaluator(
    evaluator: Callable[[CompiledSuite, RunSet], EvaluationReport],
) -> MutationEvaluatorBinding:
    return MutationEvaluatorBinding(
        evaluator=evaluator,
        method_id="assurance-mutation/campaign-test-evaluator/v1",
        implementation_version="1.0.0",
        implementation_digest="e" * 64,
        evaluation_basis=EvidenceEvaluationBasis.deterministic,
        protocol_digest=None,
        population_id="deterministic-fixture-v1",
        gate_profile_id="default",
        gate_profile_digest=mutation_gate_profile_digest(DEFAULT_GATE_PROFILE),
        waiver_set_digest=mutation_waiver_set_digest(()),
        evaluation_date=_EVALUATION_DATE.isoformat(),
    )


def _nested_field_names(value: object) -> set[str]:
    if isinstance(value, dict):
        return {
            *value,
            *(nested for child in value.values() for nested in _nested_field_names(child)),
        }
    if isinstance(value, list):
        return {nested for child in value for nested in _nested_field_names(child)}
    return set()


def _replace_projection_value(
    payload: dict[str, Any],
    path: tuple[str | int, ...],
    replacement: object,
) -> None:
    cursor: Any = payload
    for segment in path[:-1]:
        cursor = cursor[segment]
    cursor[path[-1]] = replacement


def _refresh_self_digest(payload: dict[str, Any], digest_field: str) -> None:
    payload[digest_field] = sha256_hexdigest(
        {key: value for key, value in payload.items() if key != digest_field}
    )


_SELF_DIGEST_FIELDS = {
    "assurance-evidence-descriptor": "evidence_digest",
    "assurance-mutation-operator": "operator_digest",
    "assurance-mutation-result": "result_digest",
    "expected-detection-contract": "contract_digest",
    "assurance-mutation-catalog": "catalog_digest",
    "assurance-mutation-campaign": "campaign_digest",
}


def _v061_evidence_root_payload(value: object) -> dict[str, Any]:
    converted = _convert_v061_evidence_value(value)
    if not isinstance(converted, dict):
        raise TypeError("evidence root payload must be an object")
    return converted


def _convert_v061_evidence_value(value: object) -> object:
    if isinstance(value, list):
        return [_convert_v061_evidence_value(item) for item in value]
    if not isinstance(value, dict):
        return value

    payload = {str(key): _convert_v061_evidence_value(nested) for key, nested in value.items()}
    if payload.get("schema_version") in {"0.6.2", "0.6.3"}:
        payload["schema_version"] = "0.6.1"
    if payload.get("artifact_kind") == "assurance-mutation-operator":
        compatible_versions = payload.get("compatible_schema_versions")
        if isinstance(compatible_versions, list):
            payload["compatible_schema_versions"] = [
                version
                for version in compatible_versions
                if version not in {"0.6.2", "0.6.3"}
            ]
    expected_contract = payload.get("expected_detection_contract")
    result = payload.get("result")
    if isinstance(expected_contract, dict) and isinstance(result, dict):
        result["expected_detection_contract_digest"] = expected_contract.get("contract_digest")
        _refresh_self_digest(result, "result_digest")
    artifact_kind = payload.get("artifact_kind")
    digest_field = (
        _SELF_DIGEST_FIELDS.get(artifact_kind) if isinstance(artifact_kind, str) else None
    )
    if digest_field is not None:
        _refresh_self_digest(payload, digest_field)
    return payload


def test_campaign_payload_has_no_accidental_noncanonical_json_values() -> None:
    suite, source = _fixture()
    payload = _campaign(suite, source, seed=17).campaign.model_dump(mode="json")

    # This also catches accidental byte strings, enums, dates, or NaN-like
    # values escaping the persisted projection.
    assert json.loads(json.dumps(payload, allow_nan=False)) == payload
