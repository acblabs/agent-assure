from __future__ import annotations

import json
from collections.abc import Callable
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import ValidationError as PydanticValidationError

from agent_assure.reporting.controls import (
    render_control_coverage_markdown,
    write_control_coverage_report,
)
from agent_assure.schema import validation as artifact_validation
from agent_assure.schema.controls import (
    CLAIM_BOUNDARY,
    MITRE_ATLAS_BOUNDARY,
    ControlConditionEvaluation,
    ControlCoverageItem,
    ControlCoverageReport,
    ControlCoverageState,
    ControlEvidenceRef,
    ControlMappingStrength,
    _control_coverage_semantic_items,
    _derive_control_coverage_report_id,
)
from agent_assure.schema.export import writer_json_schema
from agent_assure.schema.validation import validate_artifact_payload

ROOT = Path(__file__).resolve().parents[3]
_HISTORICAL_REPORT_VERSIONS = (
    "0.4.3",
    "0.5.0",
    "0.6.0",
    "0.6.1",
    "0.6.2",
    "0.6.3",
    "0.6.4",
    "0.6.5",
)
PayloadMutation = Callable[[dict[str, Any]], None]
_NESTED_VERSION_PATHS = (
    pytest.param(("items", 0, "schema_version"), id="item"),
    pytest.param(
        ("items", 0, "evidence_refs", 0, "schema_version"),
        id="item-evidence",
    ),
    pytest.param(
        ("items", 0, "condition_evaluations", 0, "schema_version"),
        id="condition",
    ),
    pytest.param(
        (
            "items",
            0,
            "condition_evaluations",
            0,
            "evidence_refs",
            0,
            "schema_version",
        ),
        id="condition-evidence",
    ),
)


def _evidence_ref(schema_version: str, ref_id: str) -> dict[str, Any]:
    return {
        "artifact_kind": "control-evidence-ref",
        "schema_version": schema_version,
        "evidence_kind": "evaluation-summary",
        "evidence_id": ref_id,
        "field_path": "$.state",
        "evidence_digest": "3" * 64,
        "description": "Persisted test evidence.",
    }


def _report_payload(schema_version: str = "0.6.6") -> dict[str, Any]:
    condition_ref = _evidence_ref(schema_version, "condition-evidence")
    payload = {
        "artifact_kind": "control-coverage-report",
        "schema_version": schema_version,
        "report_id": "pending-derived-identity",
        "framework": "nist-ai-rmf",
        "framework_version": "1.0",
        "mapping_version": "1.0.0",
        "mapping_digest": "1" * 64,
        "evidence_packet_id": "packet-1",
        "evidence_packet_digest": "2" * 64,
        "coverage_state_counts": {"observed": 1, "not_observed": 1},
        "items": [
            {
                "artifact_kind": "control-coverage-item",
                "schema_version": schema_version,
                "control_id": "CONTROL-A",
                "title": "Observed control",
                "coverage_state": "observed",
                "evidence_refs": [deepcopy(condition_ref)],
                "condition_evaluations": [
                    {
                        "artifact_kind": "control-condition-evaluation",
                        "schema_version": schema_version,
                        "rule_id": "rule-a",
                        "signal": "control_evaluated",
                        "observed": True,
                        "coverage_state": "observed",
                        "evidence_refs": [condition_ref],
                        "rationale": "The required signal was observed.",
                    }
                ],
            },
            {
                "artifact_kind": "control-coverage-item",
                "schema_version": schema_version,
                "control_id": "CONTROL-B",
                "title": "Unobserved control",
                "coverage_state": "not_observed",
            },
        ],
        "limitations": [CLAIM_BOUNDARY, "Evidence mapping only."],
    }
    _refresh_report_id(payload)
    return payload


def _refresh_report_id(payload: dict[str, Any]) -> None:
    item_semantics = _control_coverage_semantic_items(payload["items"])
    payload["report_id"] = _derive_control_coverage_report_id(
        framework=payload["framework"],
        framework_version=payload["framework_version"],
        mapping_version=payload["mapping_version"],
        mapping_digest=payload["mapping_digest"],
        evidence_packet_id=payload["evidence_packet_id"],
        evidence_packet_digest=payload["evidence_packet_digest"],
        item_states=tuple(
            (
                (item.control_id, item.coverage_state)
                if isinstance(item, ControlCoverageItem)
                else (item["control_id"], item["coverage_state"])
            )
            for item in payload["items"]
        ),
        item_semantics=item_semantics,
        limitations=payload["limitations"],
        schema_version=payload["schema_version"],
    )


def _mitre_report_payload(schema_version: str = "0.6.6") -> dict[str, Any]:
    payload = _report_payload(schema_version)
    payload["framework"] = "mitre-atlas-2026-06"
    payload["framework_version"] = "2026.06"
    payload["limitations"] = [
        CLAIM_BOUNDARY,
        "Additional mapping limitation one.",
        "Additional mapping limitation two.",
        MITRE_ATLAS_BOUNDARY,
    ]
    payload["items"][0].update(
        {
            "control_id": "AML.T0051",
            "title": "LLM Prompt Injection",
            "mapping_strength": "partial",
            "atlas_tactic_ids": ["AML.TA0004"],
            "atlas_technique_ids": ["AML.T0051"],
        }
    )
    payload["items"][1].update(
        {
            "control_id": "AML.T0053",
            "title": "AI Agent Tool Invocation",
            "mapping_strength": "direct",
            "atlas_tactic_ids": ["AML.TA0005"],
            "atlas_technique_ids": ["AML.T0053"],
        }
    )
    _refresh_report_id(payload)
    return payload


_FRAMEWORK_VERSION_VALUES = (
    ("nist-ai-rmf", "1.0", "2026.06"),
    ("owasp-llm-top-10-2025", "2025", "1.0"),
    ("iso-iec-42001", "2023", "2025"),
    ("mitre-atlas-2026-06", "2026.06", "2023"),
)
_FRAMEWORK_VERSION_CASES = (
    pytest.param(*_FRAMEWORK_VERSION_VALUES[0], id="nist"),
    pytest.param(*_FRAMEWORK_VERSION_VALUES[1], id="owasp"),
    pytest.param(*_FRAMEWORK_VERSION_VALUES[2], id="iso"),
    pytest.param(*_FRAMEWORK_VERSION_VALUES[3], id="mitre"),
)


def _framework_report_payload(
    framework: str,
    framework_version: str,
    *,
    schema_version: str = "0.6.6",
) -> dict[str, Any]:
    payload = (
        _mitre_report_payload(schema_version)
        if framework == "mitre-atlas-2026-06"
        else _report_payload(schema_version)
    )
    payload["framework"] = framework
    payload["framework_version"] = framework_version
    _refresh_report_id(payload)
    return payload


def _unknown_count(payload: dict[str, Any]) -> None:
    payload["coverage_state_counts"]["unknown"] = 0


def _negative_count(payload: dict[str, Any]) -> None:
    payload["coverage_state_counts"]["observed"] = -1


def _wrong_count(payload: dict[str, Any]) -> None:
    payload["coverage_state_counts"]["observed"] = 2


def _missing_count(payload: dict[str, Any]) -> None:
    del payload["coverage_state_counts"]["not_observed"]


def _extra_zero_count(payload: dict[str, Any]) -> None:
    payload["coverage_state_counts"]["out_of_scope"] = 0


def _duplicate_control_id(payload: dict[str, Any]) -> None:
    payload["items"][1]["control_id"] = payload["items"][0]["control_id"]
    _refresh_report_id(payload)


def _contradictory_item_state(payload: dict[str, Any]) -> None:
    payload["items"][0]["coverage_state"] = "not_evaluated"
    payload["coverage_state_counts"] = {"not_evaluated": 1, "not_observed": 1}
    _refresh_report_id(payload)


def _missing_item_evidence_ref(payload: dict[str, Any]) -> None:
    payload["items"][0]["evidence_refs"] = []


def _extra_item_evidence_ref(payload: dict[str, Any]) -> None:
    schema_version = payload["schema_version"]
    payload["items"][0]["evidence_refs"].append(
        _evidence_ref(schema_version, "unprojected-evidence")
    )


def _duplicate_item_evidence_ref(payload: dict[str, Any]) -> None:
    payload["items"][0]["evidence_refs"].append(deepcopy(payload["items"][0]["evidence_refs"][0]))


def _reordered_item_evidence_refs(payload: dict[str, Any]) -> None:
    schema_version = payload["schema_version"]
    second_ref = _evidence_ref(schema_version, "condition-evidence-2")
    payload["items"][0]["condition_evaluations"].append(
        {
            "artifact_kind": "control-condition-evaluation",
            "schema_version": schema_version,
            "rule_id": "rule-a-2",
            "signal": "second_control_signal",
            "observed": True,
            "coverage_state": "observed",
            "evidence_refs": [deepcopy(second_ref)],
            "rationale": "A second required signal was observed.",
        }
    )
    first_ref = payload["items"][0]["evidence_refs"][0]
    payload["items"][0]["evidence_refs"] = [second_ref, first_ref]


def _false_path_contradiction(payload: dict[str, Any]) -> None:
    payload["items"][0]["condition_evaluations"][0]["observed"] = False
    payload["items"][0]["condition_evaluations"][0]["coverage_state"] = (
        "contradictory_evidence_observed"
    )
    payload["items"][0]["coverage_state"] = "contradictory_evidence_observed"
    payload["items"][0]["evidence_refs"] = []
    payload["coverage_state_counts"] = {
        "contradictory_evidence_observed": 1,
        "not_observed": 1,
    }
    _refresh_report_id(payload)


def _false_path_observed(payload: dict[str, Any]) -> None:
    evaluation = payload["items"][0]["condition_evaluations"][0]
    evaluation["observed"] = False
    evaluation["coverage_state"] = "observed"
    evaluation["evidence_refs"] = []
    payload["items"][0]["evidence_refs"] = []


def _true_path_not_observed(payload: dict[str, Any]) -> None:
    evaluation = payload["items"][0]["condition_evaluations"][0]
    evaluation["coverage_state"] = "not_observed"
    payload["items"][0]["coverage_state"] = "not_observed"
    payload["coverage_state_counts"] = {"not_observed": 2}
    _refresh_report_id(payload)


def _true_path_not_evaluated(payload: dict[str, Any]) -> None:
    evaluation = payload["items"][0]["condition_evaluations"][0]
    evaluation["coverage_state"] = "not_evaluated"
    payload["items"][0]["coverage_state"] = "not_evaluated"
    payload["coverage_state_counts"] = {"not_evaluated": 1, "not_observed": 1}
    _refresh_report_id(payload)


def _true_path_empty_evidence(payload: dict[str, Any]) -> None:
    payload["items"][0]["condition_evaluations"][0]["evidence_refs"] = []
    payload["items"][0]["evidence_refs"] = []


def _true_path_omitted_evidence(payload: dict[str, Any]) -> None:
    del payload["items"][0]["condition_evaluations"][0]["evidence_refs"]
    payload["items"][0]["evidence_refs"] = []


def _duplicate_condition_evidence_identity(payload: dict[str, Any]) -> None:
    evaluation = payload["items"][0]["condition_evaluations"][0]
    duplicate = deepcopy(evaluation["evidence_refs"][0])
    duplicate["description"] = "Different text cannot make the same evidence identity unique."
    evaluation["evidence_refs"].append(duplicate)


def _duplicate_condition_rule_id(payload: dict[str, Any]) -> None:
    evaluation = deepcopy(payload["items"][0]["condition_evaluations"][0])
    evaluation["rationale"] = "A distinct row cannot reuse the same mapping rule identity."
    payload["items"][0]["condition_evaluations"].append(evaluation)


def _duplicate_item_limitation(payload: dict[str, Any]) -> None:
    payload["items"][0]["limitations"] = ["Repeated limitation.", "Repeated limitation."]


def _duplicate_item_atlas_id(payload: dict[str, Any]) -> None:
    payload["items"][0]["atlas_tactic_ids"] = ["AML.TA0001", "AML.TA0001"]


def _unordered_item_atlas_ids(payload: dict[str, Any]) -> None:
    payload["items"][0]["atlas_technique_ids"] = ["AML.T0099", "AML.T0001"]


def _missing_claim_boundary(payload: dict[str, Any]) -> None:
    payload["limitations"].remove(CLAIM_BOUNDARY)


def _duplicate_claim_boundary(payload: dict[str, Any]) -> None:
    payload["limitations"].append(CLAIM_BOUNDARY)


def _misplaced_claim_boundary(payload: dict[str, Any]) -> None:
    payload["limitations"].remove(CLAIM_BOUNDARY)
    payload["limitations"].append(CLAIM_BOUNDARY)


def _forged_report_id(payload: dict[str, Any]) -> None:
    payload["report_id"] = "control-map-0000000000000000"


def _unexpected_mitre_boundary(payload: dict[str, Any]) -> None:
    payload["limitations"].append(MITRE_ATLAS_BOUNDARY)


def _non_mitre_mapping_strength(payload: dict[str, Any]) -> None:
    payload["items"][0]["mapping_strength"] = "direct"


def _non_mitre_atlas_tactic(payload: dict[str, Any]) -> None:
    payload["items"][0]["atlas_tactic_ids"] = ["AML.TA0004"]


def _non_mitre_atlas_technique(payload: dict[str, Any]) -> None:
    payload["items"][0]["atlas_technique_ids"] = ["AML.T0051"]


_SEMANTIC_MUTATIONS = (
    pytest.param(_unknown_count, id="unknown-count-state"),
    pytest.param(_negative_count, id="negative-count"),
    pytest.param(_wrong_count, id="wrong-count"),
    pytest.param(_missing_count, id="missing-count"),
    pytest.param(_extra_zero_count, id="extra-zero-count"),
    pytest.param(_duplicate_control_id, id="duplicate-control-id"),
    pytest.param(_contradictory_item_state, id="contradictory-item-state"),
    pytest.param(_missing_item_evidence_ref, id="missing-item-evidence-ref"),
    pytest.param(_extra_item_evidence_ref, id="extra-item-evidence-ref"),
    pytest.param(_duplicate_item_evidence_ref, id="duplicate-item-evidence-ref"),
    pytest.param(_reordered_item_evidence_refs, id="reordered-item-evidence-refs"),
    pytest.param(_false_path_contradiction, id="false-path-contradiction"),
    pytest.param(_false_path_observed, id="false-path-observed"),
    pytest.param(_true_path_not_observed, id="true-path-not-observed"),
    pytest.param(_true_path_not_evaluated, id="true-path-not-evaluated"),
    pytest.param(_true_path_empty_evidence, id="true-path-empty-evidence"),
    pytest.param(_true_path_omitted_evidence, id="true-path-omitted-evidence"),
    pytest.param(
        _duplicate_condition_evidence_identity,
        id="duplicate-condition-evidence-identity",
    ),
    pytest.param(_duplicate_condition_rule_id, id="duplicate-condition-rule-id"),
    pytest.param(_duplicate_item_limitation, id="duplicate-item-limitation"),
    pytest.param(_duplicate_item_atlas_id, id="duplicate-item-atlas-id"),
    pytest.param(_unordered_item_atlas_ids, id="unordered-item-atlas-ids"),
    pytest.param(_missing_claim_boundary, id="missing-claim-boundary"),
    pytest.param(_duplicate_claim_boundary, id="duplicate-claim-boundary"),
    pytest.param(_misplaced_claim_boundary, id="misplaced-claim-boundary"),
    pytest.param(_forged_report_id, id="forged-report-id"),
    pytest.param(_unexpected_mitre_boundary, id="unexpected-mitre-boundary"),
    pytest.param(_non_mitre_mapping_strength, id="non-mitre-mapping-strength"),
    pytest.param(_non_mitre_atlas_tactic, id="non-mitre-atlas-tactic"),
    pytest.param(_non_mitre_atlas_technique, id="non-mitre-atlas-technique"),
)


def _missing_mitre_boundary(payload: dict[str, Any]) -> None:
    payload["limitations"].remove(MITRE_ATLAS_BOUNDARY)


def _duplicate_mitre_boundary(payload: dict[str, Any]) -> None:
    payload["limitations"].append(MITRE_ATLAS_BOUNDARY)


def _missing_mitre_mapping_strength(payload: dict[str, Any]) -> None:
    del payload["items"][0]["mapping_strength"]


def _null_mitre_mapping_strength(payload: dict[str, Any]) -> None:
    payload["items"][0]["mapping_strength"] = None


def _unknown_mitre_control_id(payload: dict[str, Any]) -> None:
    payload["items"][0]["control_id"] = "AML.T9999"
    _refresh_report_id(payload)


def _unknown_mitre_tactic_id(payload: dict[str, Any]) -> None:
    payload["items"][0]["atlas_tactic_ids"] = ["AML.TA9999"]
    _refresh_report_id(payload)


def _unknown_mitre_technique_id(payload: dict[str, Any]) -> None:
    payload["items"][0]["atlas_technique_ids"] = ["AML.T9999"]
    _refresh_report_id(payload)


def _wrong_mitre_framework_version(payload: dict[str, Any]) -> None:
    payload["framework_version"] = "2099.99"
    _refresh_report_id(payload)


def _mislabeled_mitre_control(payload: dict[str, Any]) -> None:
    payload["items"][0]["title"] = "Certified safe"
    _refresh_report_id(payload)


def _mitre_control_missing_from_techniques(payload: dict[str, Any]) -> None:
    payload["items"][0]["atlas_technique_ids"] = ["AML.T0099"]
    _refresh_report_id(payload)


def _mitre_not_applicable_with_tactic(payload: dict[str, Any]) -> None:
    payload["items"][0]["mapping_strength"] = "not_applicable"
    payload["items"][0]["atlas_technique_ids"] = ["AML.T0051"]
    _refresh_report_id(payload)


def _mitre_not_applicable_with_crosswalk(payload: dict[str, Any]) -> None:
    payload["items"][0]["mapping_strength"] = "not_applicable"
    payload["items"][0]["atlas_tactic_ids"] = []
    payload["items"][0]["atlas_technique_ids"] = ["AML.T0051", "AML.T0099"]
    _refresh_report_id(payload)


_MITRE_SEMANTIC_MUTATIONS = (
    pytest.param(_missing_mitre_boundary, id="missing-mitre-boundary"),
    pytest.param(_duplicate_mitre_boundary, id="duplicate-mitre-boundary"),
    pytest.param(_missing_mitre_mapping_strength, id="missing-mitre-mapping-strength"),
    pytest.param(_null_mitre_mapping_strength, id="null-mitre-mapping-strength"),
    pytest.param(_unknown_mitre_control_id, id="unknown-mitre-control-id"),
    pytest.param(_unknown_mitre_tactic_id, id="unknown-mitre-tactic-id"),
    pytest.param(_unknown_mitre_technique_id, id="unknown-mitre-technique-id"),
    pytest.param(_wrong_mitre_framework_version, id="wrong-mitre-framework-version"),
    pytest.param(_mislabeled_mitre_control, id="mislabeled-control"),
    pytest.param(_mitre_control_missing_from_techniques, id="missing-self-technique-id"),
    pytest.param(_mitre_not_applicable_with_tactic, id="not-applicable-with-tactic"),
    pytest.param(_mitre_not_applicable_with_crosswalk, id="not-applicable-with-crosswalk"),
)


@pytest.mark.parametrize("mutation", _SEMANTIC_MUTATIONS)
def test_current_model_rejects_control_coverage_contradictions(
    mutation: PayloadMutation,
) -> None:
    payload = _report_payload()
    mutation(payload)

    with pytest.raises(PydanticValidationError):
        ControlCoverageReport.model_validate(payload)


@pytest.mark.parametrize("mutation", _SEMANTIC_MUTATIONS)
def test_current_public_validator_rejects_control_coverage_contradictions(
    mutation: PayloadMutation,
) -> None:
    payload = _report_payload()
    mutation(payload)

    with pytest.raises((JsonSchemaValidationError, ValueError)):
        validate_artifact_payload(payload, "control-coverage-report")


@pytest.mark.parametrize("schema_version", _HISTORICAL_REPORT_VERSIONS)
@pytest.mark.parametrize("mutation", _SEMANTIC_MUTATIONS)
def test_historical_public_validator_replays_control_coverage_semantics(
    schema_version: str,
    mutation: PayloadMutation,
) -> None:
    payload = _report_payload(schema_version)
    mutation(payload)

    assert (
        artifact_validation._validate_legacy_frozen_schema(
            payload,
            "control-coverage-report",
        )
        == "frozen-jsonschema"
    )
    with pytest.raises(ValueError):
        validate_artifact_payload(payload, "control-coverage-report")


@pytest.mark.parametrize("schema_version", _HISTORICAL_REPORT_VERSIONS)
def test_coherent_historical_control_coverage_remains_valid(schema_version: str) -> None:
    assert (
        validate_artifact_payload(
            _report_payload(schema_version),
            "control-coverage-report",
        )
        == "frozen-jsonschema+semantic-replay"
    )


@pytest.mark.parametrize(
    ("framework", "expected_version", "wrong_version"),
    _FRAMEWORK_VERSION_CASES,
)
def test_current_report_rejects_cross_framework_version_metadata(
    framework: str,
    expected_version: str,
    wrong_version: str,
) -> None:
    payload = _framework_report_payload(framework, expected_version)
    payload["framework_version"] = wrong_version
    _refresh_report_id(payload)

    with pytest.raises(PydanticValidationError, match="requires framework_version"):
        ControlCoverageReport.model_validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(writer_json_schema(ControlCoverageReport)).validate(payload)
    with pytest.raises((JsonSchemaValidationError, ValueError)):
        validate_artifact_payload(payload, "control-coverage-report")


@pytest.mark.parametrize("schema_version", _HISTORICAL_REPORT_VERSIONS)
@pytest.mark.parametrize(
    ("framework", "expected_version", "wrong_version"),
    _FRAMEWORK_VERSION_CASES,
)
def test_historical_public_validator_replays_framework_version_contract(
    schema_version: str,
    framework: str,
    expected_version: str,
    wrong_version: str,
) -> None:
    payload = _framework_report_payload(
        framework,
        expected_version,
        schema_version=schema_version,
    )
    payload["framework_version"] = wrong_version
    _refresh_report_id(payload)

    assert (
        artifact_validation._validate_legacy_frozen_schema(
            payload,
            "control-coverage-report",
        )
        == "frozen-jsonschema"
    )
    with pytest.raises(ValueError):
        validate_artifact_payload(payload, "control-coverage-report")


def _mutate_paired_evidence_ref(
    payload: dict[str, Any],
    field_name: str,
    value: object,
) -> None:
    payload["items"][0]["evidence_refs"][0][field_name] = value
    payload["items"][0]["condition_evaluations"][0]["evidence_refs"][0][field_name] = value


def _change_mapping_version(payload: dict[str, Any]) -> None:
    payload["mapping_version"] = "2.0.0"


def _change_evidence_packet_id(payload: dict[str, Any]) -> None:
    payload["evidence_packet_id"] = "packet-2"


def _change_item_title(payload: dict[str, Any]) -> None:
    payload["items"][0]["title"] = "Revised mapping title"


def _change_mapping_strength(payload: dict[str, Any]) -> None:
    payload["items"][0]["mapping_strength"] = "direct"


def _change_atlas_tactic_ids(payload: dict[str, Any]) -> None:
    payload["items"][0]["atlas_tactic_ids"] = ["AML.TA0005"]


def _change_atlas_technique_ids(payload: dict[str, Any]) -> None:
    payload["items"][0]["atlas_technique_ids"] = ["AML.T0051", "AML.T0051.000"]


def _change_evidence_kind(payload: dict[str, Any]) -> None:
    _mutate_paired_evidence_ref(payload, "evidence_kind", "evaluation-report")


def _change_evidence_id(payload: dict[str, Any]) -> None:
    _mutate_paired_evidence_ref(payload, "evidence_id", "revised-evidence")


def _change_evidence_field_path(payload: dict[str, Any]) -> None:
    _mutate_paired_evidence_ref(payload, "field_path", "$.findings[0].state")


def _change_evidence_digest(payload: dict[str, Any]) -> None:
    _mutate_paired_evidence_ref(payload, "evidence_digest", "4" * 64)


def _change_evidence_description(payload: dict[str, Any]) -> None:
    _mutate_paired_evidence_ref(payload, "description", "Revised evidence description.")


def _change_condition_rule_id(payload: dict[str, Any]) -> None:
    payload["items"][0]["condition_evaluations"][0]["rule_id"] = "rule-revised"


def _change_condition_signal(payload: dict[str, Any]) -> None:
    payload["items"][0]["condition_evaluations"][0]["signal"] = "control_passed"


def _change_condition(payload: dict[str, Any]) -> None:
    payload["items"][0]["condition_evaluations"][0]["condition"] = "candidate"


def _change_condition_observation(payload: dict[str, Any]) -> None:
    evaluation = payload["items"][0]["condition_evaluations"][0]
    evaluation["observed"] = False
    evaluation["coverage_state"] = "not_observed"
    evaluation["evidence_refs"] = []
    payload["items"][0]["coverage_state"] = "not_observed"
    payload["items"][0]["evidence_refs"] = []
    payload["coverage_state_counts"] = {"not_observed": 2}


def _change_condition_state(payload: dict[str, Any]) -> None:
    payload["items"][0]["condition_evaluations"][0]["coverage_state"] = "partially_observed"
    payload["items"][0]["coverage_state"] = "partially_observed"
    payload["coverage_state_counts"] = {"partially_observed": 1, "not_observed": 1}


def _change_condition_rationale(payload: dict[str, Any]) -> None:
    payload["items"][0]["condition_evaluations"][0]["rationale"] = (
        "Revised reviewer-visible rationale."
    )


def _change_item_limitations(payload: dict[str, Any]) -> None:
    payload["items"][0]["limitations"] = ["Revised item limitation."]


def _change_report_limitations(payload: dict[str, Any]) -> None:
    payload["limitations"].insert(1, "Revised report limitation.")


_CURRENT_IDENTITY_MUTATIONS = (
    pytest.param(_change_mapping_version, id="mapping-version"),
    pytest.param(_change_evidence_packet_id, id="evidence-packet-id"),
    pytest.param(_change_mapping_strength, id="mapping-strength"),
    pytest.param(_change_atlas_tactic_ids, id="atlas-tactic-ids"),
    pytest.param(_change_atlas_technique_ids, id="atlas-technique-ids"),
    pytest.param(_change_evidence_kind, id="evidence-kind"),
    pytest.param(_change_evidence_id, id="evidence-id"),
    pytest.param(_change_evidence_field_path, id="evidence-field-path"),
    pytest.param(_change_evidence_digest, id="evidence-digest"),
    pytest.param(_change_evidence_description, id="evidence-description"),
    pytest.param(_change_condition_rule_id, id="condition-rule-id"),
    pytest.param(_change_condition_signal, id="condition-signal"),
    pytest.param(_change_condition, id="condition"),
    pytest.param(_change_condition_observation, id="condition-observed"),
    pytest.param(_change_condition_state, id="condition-state"),
    pytest.param(_change_condition_rationale, id="condition-rationale"),
    pytest.param(_change_item_limitations, id="item-limitations"),
    pytest.param(_change_report_limitations, id="report-limitations"),
)

_HISTORICAL_IDENTITY_COMPATIBILITY_MUTATIONS = (
    pytest.param(_change_mapping_version, id="mapping-version"),
    pytest.param(_change_evidence_packet_id, id="evidence-packet-id"),
    pytest.param(_change_mapping_strength, id="mapping-strength"),
    pytest.param(_change_atlas_tactic_ids, id="atlas-tactic-ids"),
    pytest.param(_change_atlas_technique_ids, id="atlas-technique-ids"),
    pytest.param(_change_evidence_kind, id="evidence-kind"),
    pytest.param(_change_evidence_id, id="evidence-id"),
    pytest.param(_change_evidence_field_path, id="evidence-field-path"),
    pytest.param(_change_evidence_digest, id="evidence-digest"),
    pytest.param(_change_evidence_description, id="evidence-description"),
    pytest.param(_change_condition_rule_id, id="condition-rule-id"),
    pytest.param(_change_condition_signal, id="condition-signal"),
    pytest.param(_change_condition, id="condition"),
    pytest.param(_change_condition_rationale, id="condition-rationale"),
    pytest.param(_change_item_limitations, id="item-limitations"),
    pytest.param(_change_report_limitations, id="report-limitations"),
)


def test_current_identity_binds_non_mitre_reviewer_visible_title() -> None:
    payload = _report_payload()
    original_report_id = payload["report_id"]
    _change_item_title(payload)

    with pytest.raises(PydanticValidationError, match="report_id"):
        ControlCoverageReport.model_validate(payload)

    _refresh_report_id(payload)
    assert payload["report_id"] != original_report_id
    ControlCoverageReport.model_validate(payload)


def test_historical_non_mitre_identity_retains_published_title_projection() -> None:
    payload = _report_payload("0.6.5")
    legacy_report_id = payload["report_id"]
    _change_item_title(payload)

    parsed = ControlCoverageReport.model_validate(payload)

    assert parsed.report_id == legacy_report_id
    assert (
        validate_artifact_payload(payload, "control-coverage-report")
        == "frozen-jsonschema+semantic-replay"
    )


@pytest.mark.parametrize("mutation", _HISTORICAL_IDENTITY_COMPATIBILITY_MUTATIONS)
def test_historical_control_identity_retains_the_published_legacy_projection(
    mutation: PayloadMutation,
) -> None:
    payload = _mitre_report_payload("0.6.5")
    legacy_report_id = payload["report_id"]
    mutation(payload)

    parsed = ControlCoverageReport.model_validate(payload)

    assert parsed.report_id == legacy_report_id
    assert (
        validate_artifact_payload(payload, "control-coverage-report")
        == "frozen-jsonschema+semantic-replay"
    )


@pytest.mark.parametrize("mutation", _CURRENT_IDENTITY_MUTATIONS)
def test_current_identity_binds_reviewer_visible_mapping_semantics(
    mutation: PayloadMutation,
) -> None:
    payload = _mitre_report_payload()
    original_report_id = payload["report_id"]
    mutation(payload)

    with pytest.raises(PydanticValidationError, match="report_id"):
        ControlCoverageReport.model_validate(payload)

    _refresh_report_id(payload)
    assert payload["report_id"] != original_report_id
    ControlCoverageReport.model_validate(payload)


@pytest.mark.parametrize("mutation", _MITRE_SEMANTIC_MUTATIONS)
def test_current_model_and_public_validator_reject_mitre_contract_gaps(
    mutation: PayloadMutation,
) -> None:
    payload = _mitre_report_payload()
    mutation(payload)

    with pytest.raises(PydanticValidationError):
        ControlCoverageReport.model_validate(payload)
    with pytest.raises((JsonSchemaValidationError, ValueError)):
        validate_artifact_payload(payload, "control-coverage-report")


@pytest.mark.parametrize("schema_version", _HISTORICAL_REPORT_VERSIONS)
@pytest.mark.parametrize("mutation", _MITRE_SEMANTIC_MUTATIONS)
def test_historical_public_validator_replays_mitre_contract(
    schema_version: str,
    mutation: PayloadMutation,
) -> None:
    payload = _mitre_report_payload(schema_version)
    mutation(payload)

    assert (
        artifact_validation._validate_legacy_frozen_schema(
            payload,
            "control-coverage-report",
        )
        == "frozen-jsonschema"
    )
    with pytest.raises(ValueError):
        validate_artifact_payload(payload, "control-coverage-report")


@pytest.mark.parametrize("schema_version", ("0.4.3", "0.6.0", "0.6.5", "0.6.6"))
def test_additional_control_limitations_preserve_order(schema_version: str) -> None:
    payload = _report_payload(schema_version)
    payload["limitations"] = [
        CLAIM_BOUNDARY,
        "First additional limitation.",
        "Second additional limitation.",
    ]
    _refresh_report_id(payload)

    parsed = ControlCoverageReport.model_validate(payload)

    assert parsed.limitations == tuple(payload["limitations"])


@pytest.mark.parametrize("schema_version", ("0.4.3", "0.5.0"))
def test_pre_v060_optional_nested_identity_remains_compatible(schema_version: str) -> None:
    payload = _report_payload(schema_version)
    for item in payload["items"]:
        item.pop("artifact_kind", None)
        item.pop("schema_version", None)
        for ref in item.get("evidence_refs", []):
            ref.pop("artifact_kind", None)
            ref.pop("schema_version", None)
        for evaluation in item.get("condition_evaluations", []):
            evaluation.pop("artifact_kind", None)
            evaluation.pop("schema_version", None)
            for ref in evaluation.get("evidence_refs", []):
                ref.pop("artifact_kind", None)
                ref.pop("schema_version", None)

    assert (
        validate_artifact_payload(payload, "control-coverage-report")
        == "frozen-jsonschema+semantic-replay"
    )

    parsed = ControlCoverageReport.model_validate(payload)
    assert _all_nested_schema_versions(parsed) == {schema_version}


@pytest.mark.parametrize("schema_version", ("0.4.3", "0.5.0"))
@pytest.mark.parametrize("nested_path", _NESTED_VERSION_PATHS)
def test_pre_v060_partially_omitted_nested_version_inherits_report_version(
    schema_version: str,
    nested_path: tuple[str | int, ...],
) -> None:
    payload = _report_payload(schema_version)
    target: Any = payload
    for part in nested_path[:-1]:
        target = target[part]
    del target[nested_path[-1]]

    assert (
        validate_artifact_payload(payload, "control-coverage-report")
        == "frozen-jsonschema+semantic-replay"
    )
    parsed = ControlCoverageReport.model_validate(payload)
    assert _all_nested_schema_versions(parsed) == {schema_version}
    assert _resolve_path(parsed.model_dump(mode="json"), nested_path) == schema_version


@pytest.mark.parametrize("schema_version", ("0.4.3", "0.5.0"))
def test_historical_report_inherits_versions_omitted_on_nested_model_instances(
    schema_version: str,
) -> None:
    ref = ControlEvidenceRef(
        artifact_kind="control-evidence-ref",
        evidence_kind="evaluation-summary",
        evidence_id="nested-model-evidence",
        field_path="$.state",
        evidence_digest="3" * 64,
        description="Nested model evidence.",
    )
    evaluation = ControlConditionEvaluation(
        artifact_kind="control-condition-evaluation",
        rule_id="nested-model-rule",
        signal="control_evaluated",
        observed=True,
        coverage_state=ControlCoverageState.observed,
        evidence_refs=(ref,),
        rationale="The required signal was observed.",
    )
    item = ControlCoverageItem(
        artifact_kind="control-coverage-item",
        control_id="NESTED-MODEL",
        title="Nested model",
        coverage_state=ControlCoverageState.observed,
        evidence_refs=(ref,),
        condition_evaluations=(evaluation,),
    )
    payload = _report_payload(schema_version)
    payload["items"] = [item]
    payload["coverage_state_counts"] = {"observed": 1}
    _refresh_report_id(payload)

    parsed = ControlCoverageReport.model_validate(payload)

    assert "schema_version" not in item.model_fields_set
    assert "schema_version" not in evaluation.model_fields_set
    assert "schema_version" not in ref.model_fields_set
    assert _all_nested_schema_versions(parsed) == {schema_version}


@pytest.mark.parametrize("nested_path", _NESTED_VERSION_PATHS)
def test_current_model_rejects_incoherent_nested_versions(
    nested_path: tuple[str | int, ...],
) -> None:
    payload = _report_payload()
    target: Any = payload
    for part in nested_path[:-1]:
        target = target[part]
    target[nested_path[-1]] = "0.6.5"

    with pytest.raises(PydanticValidationError, match="schema versions must match"):
        ControlCoverageReport.model_validate(payload)
    with pytest.raises((JsonSchemaValidationError, ValueError)):
        validate_artifact_payload(payload, "control-coverage-report")


@pytest.mark.parametrize("schema_version", _HISTORICAL_REPORT_VERSIONS)
@pytest.mark.parametrize("nested_path", _NESTED_VERSION_PATHS)
def test_historical_public_validator_rejects_explicit_nested_version_mismatch(
    schema_version: str,
    nested_path: tuple[str | int, ...],
) -> None:
    payload = _report_payload(schema_version)
    target: Any = payload
    for part in nested_path[:-1]:
        target = target[part]
    target[nested_path[-1]] = _previous_schema_version(schema_version)

    if schema_version in {"0.4.3", "0.5.0", "0.6.0"}:
        assert (
            artifact_validation._validate_legacy_frozen_schema(
                payload,
                "control-coverage-report",
            )
            == "frozen-jsonschema"
        )
    else:
        with pytest.raises(JsonSchemaValidationError):
            artifact_validation._validate_legacy_frozen_schema(
                payload,
                "control-coverage-report",
            )
    with pytest.raises(PydanticValidationError, match="schema versions must match"):
        ControlCoverageReport.model_validate(payload)
    with pytest.raises((JsonSchemaValidationError, ValueError)):
        validate_artifact_payload(payload, "control-coverage-report")


def test_v060_public_validator_rejects_frozen_schema_valid_mixed_nested_versions() -> None:
    payload = _report_payload("0.6.0")
    payload["items"][0]["schema_version"] = "0.5.0"
    payload["items"][0]["evidence_refs"][0]["schema_version"] = "0.3.1"
    payload["items"][0]["condition_evaluations"][0]["schema_version"] = "0.4.3"
    payload["items"][0]["condition_evaluations"][0]["evidence_refs"][0]["schema_version"] = "0.2.0"

    assert (
        artifact_validation._validate_legacy_frozen_schema(
            payload,
            "control-coverage-report",
        )
        == "frozen-jsonschema"
    )
    with pytest.raises(PydanticValidationError, match="schema versions must match"):
        ControlCoverageReport.model_validate(payload)
    with pytest.raises(ValueError):
        validate_artifact_payload(payload, "control-coverage-report")


@pytest.mark.parametrize("schema_version", ("0.4.3", "0.5.0"))
def test_omitted_parent_version_does_not_mask_explicit_child_mismatch(
    schema_version: str,
) -> None:
    payload = _report_payload(schema_version)
    del payload["items"][0]["schema_version"]
    payload["items"][0]["condition_evaluations"][0]["schema_version"] = _previous_schema_version(
        schema_version
    )

    assert (
        artifact_validation._validate_legacy_frozen_schema(
            payload,
            "control-coverage-report",
        )
        == "frozen-jsonschema"
    )
    with pytest.raises(PydanticValidationError, match="schema versions must match"):
        ControlCoverageReport.model_validate(payload)
    with pytest.raises(ValueError):
        validate_artifact_payload(payload, "control-coverage-report")


def test_current_schema_closes_and_bounds_coverage_state_counts() -> None:
    schema = writer_json_schema(ControlCoverageReport)
    counts_schema = schema["properties"]["coverage_state_counts"]

    assert counts_schema["propertyNames"] == {"$ref": "#/$defs/ControlCoverageState"}
    assert counts_schema["additionalProperties"]["minimum"] == 0
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(_report_payload())
    for mutation in (_unknown_count, _negative_count):
        payload = _report_payload()
        mutation(payload)
        with pytest.raises(JsonSchemaValidationError):
            Draft202012Validator(schema).validate(payload)

    committed = json.loads(
        (ROOT / "schemas" / "v0.6.6" / "control-coverage-report.schema.json").read_text(
            encoding="utf-8"
        )
    )
    assert committed["properties"]["coverage_state_counts"] == counts_schema


def test_current_schema_mirrors_claim_boundary_and_mitre_contract() -> None:
    generated = writer_json_schema(ControlCoverageReport)
    committed = json.loads(
        (ROOT / "schemas" / "v0.6.6" / "control-coverage-report.schema.json").read_text(
            encoding="utf-8"
        )
    )

    for schema in (generated, committed):
        validator = Draft202012Validator(schema)
        Draft202012Validator.check_schema(schema)
        validator.validate(_report_payload())
        validator.validate(_mitre_report_payload())
        for mutation, payload_factory in (
            (_missing_claim_boundary, _report_payload),
            (_duplicate_claim_boundary, _report_payload),
            (_unexpected_mitre_boundary, _report_payload),
            (_missing_mitre_boundary, _mitre_report_payload),
            (_duplicate_mitre_boundary, _mitre_report_payload),
            (_missing_mitre_mapping_strength, _mitre_report_payload),
            (_null_mitre_mapping_strength, _mitre_report_payload),
            (_non_mitre_mapping_strength, _report_payload),
            (_non_mitre_atlas_tactic, _report_payload),
            (_non_mitre_atlas_technique, _report_payload),
            (_unknown_mitre_control_id, _mitre_report_payload),
            (_unknown_mitre_tactic_id, _mitre_report_payload),
            (_unknown_mitre_technique_id, _mitre_report_payload),
            (_wrong_mitre_framework_version, _mitre_report_payload),
            (_mislabeled_mitre_control, _mitre_report_payload),
            (_mitre_control_missing_from_techniques, _mitre_report_payload),
            (_mitre_not_applicable_with_tactic, _mitre_report_payload),
            (_mitre_not_applicable_with_crosswalk, _mitre_report_payload),
        ):
            payload = payload_factory()
            mutation(payload)
            with pytest.raises(JsonSchemaValidationError):
                validator.validate(payload)
        for framework, expected_version, wrong_version in _FRAMEWORK_VERSION_VALUES:
            payload = _framework_report_payload(framework, expected_version)
            payload["framework_version"] = wrong_version
            _refresh_report_id(payload)
            with pytest.raises(JsonSchemaValidationError):
                validator.validate(payload)


def _exact_duplicate_condition_evidence(payload: dict[str, Any]) -> None:
    evaluation = payload["items"][0]["condition_evaluations"][0]
    evaluation["evidence_refs"].append(deepcopy(evaluation["evidence_refs"][0]))


def _exact_duplicate_condition_evaluation(payload: dict[str, Any]) -> None:
    evaluations = payload["items"][0]["condition_evaluations"]
    evaluations.append(deepcopy(evaluations[0]))


@pytest.mark.parametrize(
    "mutation",
    (
        _false_path_observed,
        _false_path_contradiction,
        _true_path_not_observed,
        _true_path_not_evaluated,
        _true_path_empty_evidence,
        _true_path_omitted_evidence,
        _exact_duplicate_condition_evidence,
        _exact_duplicate_condition_evaluation,
        _duplicate_item_limitation,
        _duplicate_item_atlas_id,
    ),
)
def test_current_schema_expresses_condition_observation_invariants(
    mutation: PayloadMutation,
) -> None:
    schema = writer_json_schema(ControlCoverageReport)
    validator = Draft202012Validator(schema)
    Draft202012Validator.check_schema(schema)
    validator.validate(_report_payload())
    payload = _report_payload()
    mutation(payload)

    with pytest.raises(JsonSchemaValidationError):
        validator.validate(payload)


@pytest.mark.parametrize("bypass", ("model_copy", "model_construct"))
def test_renderer_revalidates_semantics_if_internal_code_bypasses_validation(
    bypass: str,
) -> None:
    report = ControlCoverageReport.model_validate(_report_payload())
    item = report.items[0]
    item_values = dict(item.__dict__)
    item_values.update(
        coverage_state=ControlCoverageState.not_evaluated,
        evidence_refs=(),
    )
    if bypass == "model_copy":
        contradictory_item = item.model_copy(
            update={
                "coverage_state": ControlCoverageState.not_evaluated,
                "evidence_refs": (),
            }
        )
    else:
        contradictory_item = ControlCoverageItem.model_construct(**item_values)
    report_values = dict(report.__dict__)
    report_values.update(
        items=(contradictory_item, report.items[1]),
        coverage_state_counts={ControlCoverageState.not_evaluated: 999},
    )
    if bypass == "model_copy":
        contradictory = report.model_copy(
            update={
                "items": report_values["items"],
                "coverage_state_counts": report_values["coverage_state_counts"],
            }
        )
    else:
        contradictory = ControlCoverageReport.model_construct(**report_values)

    with pytest.raises(ValueError):
        render_control_coverage_markdown(contradictory)


def test_renderer_renders_round_trip_validated_report() -> None:
    report = ControlCoverageReport.model_validate(_report_payload())

    markdown = render_control_coverage_markdown(report)

    assert markdown.count("This report maps observed") == 1
    assert "- `observed`: `1`" in markdown
    assert "- `not_observed`: `1`" in markdown
    assert "- State: `observed`" in markdown
    assert "`condition-evidence`" in markdown


@pytest.mark.parametrize("bypass", ("model_copy", "model_construct"))
@pytest.mark.parametrize(
    "invalid_semantics",
    (
        "false-observed",
        "false-contradictory",
        "true-not-observed",
        "true-not-evaluated",
        "true-empty-evidence",
        "duplicate-evidence-identity",
        "duplicate-rule-id",
    ),
)
def test_renderer_fails_closed_on_bypassed_condition_semantics(
    bypass: str,
    invalid_semantics: str,
) -> None:
    report = ControlCoverageReport.model_validate(_report_payload())
    item = report.items[0]
    original = item.condition_evaluations[0]
    updates: dict[str, Any] = {}
    if invalid_semantics == "false-observed":
        updates = {
            "observed": False,
            "coverage_state": ControlCoverageState.observed,
            "evidence_refs": (),
        }
    elif invalid_semantics == "false-contradictory":
        updates = {
            "observed": False,
            "coverage_state": ControlCoverageState.contradictory_evidence_observed,
            "evidence_refs": (),
        }
    elif invalid_semantics == "true-not-observed":
        updates = {"coverage_state": ControlCoverageState.not_observed}
    elif invalid_semantics == "true-not-evaluated":
        updates = {"coverage_state": ControlCoverageState.not_evaluated}
    elif invalid_semantics == "true-empty-evidence":
        updates = {"evidence_refs": ()}
    elif invalid_semantics == "duplicate-evidence-identity":
        ref = original.evidence_refs[0]
        updates = {
            "evidence_refs": (
                ref,
                ref.model_copy(update={"description": "Duplicate identity with distinct text."}),
            )
        }

    if bypass == "model_copy":
        evaluation = original.model_copy(update=updates)
    else:
        evaluation_values = dict(original.__dict__)
        evaluation_values.update(updates)
        evaluation = ControlConditionEvaluation.model_construct(**evaluation_values)
    evaluations = (evaluation,)
    if invalid_semantics == "duplicate-rule-id":
        duplicate = evaluation.model_copy(update={"rationale": "Duplicate rule identity."})
        evaluations = (evaluation, duplicate)
    if bypass == "model_copy":
        forged_item = item.model_copy(update={"condition_evaluations": evaluations})
        forged_report = report.model_copy(update={"items": (forged_item, report.items[1])})
    else:
        item_values = dict(item.__dict__)
        item_values["condition_evaluations"] = evaluations
        forged_item = ControlCoverageItem.model_construct(**item_values)
        report_values = dict(report.__dict__)
        report_values["items"] = (forged_item, report.items[1])
        forged_report = ControlCoverageReport.model_construct(**report_values)

    with pytest.raises(ValueError):
        render_control_coverage_markdown(forged_report)


@pytest.mark.parametrize("bypass", ("model_copy", "model_construct"))
@pytest.mark.parametrize(
    ("field_name", "forged_value"),
    (
        ("limitations", ("Repeated limitation.", "Repeated limitation.")),
        ("atlas_tactic_ids", ("AML.TA0001", "AML.TA0001")),
        ("atlas_technique_ids", ("AML.T0099", "AML.T0001")),
    ),
)
def test_renderer_fails_closed_on_bypassed_item_collection_semantics(
    bypass: str,
    field_name: str,
    forged_value: tuple[str, ...],
) -> None:
    report = ControlCoverageReport.model_validate(_report_payload())
    item = report.items[0]
    if bypass == "model_copy":
        forged_item = item.model_copy(update={field_name: forged_value})
        forged_report = report.model_copy(update={"items": (forged_item, report.items[1])})
    else:
        item_values = dict(item.__dict__)
        item_values[field_name] = forged_value
        forged_item = ControlCoverageItem.model_construct(**item_values)
        report_values = dict(report.__dict__)
        report_values["items"] = (forged_item, report.items[1])
        forged_report = ControlCoverageReport.model_construct(**report_values)

    with pytest.raises(ValueError):
        render_control_coverage_markdown(forged_report)


def test_renderer_rejects_bypassed_duplicate_and_missing_boundaries() -> None:
    report = ControlCoverageReport.model_validate(_report_payload())
    forged_report = report.model_copy(
        update={
            "limitations": (
                "First additional limitation.",
                "First additional limitation.",
                MITRE_ATLAS_BOUNDARY,
                "Second additional limitation.",
            )
        }
    )

    with pytest.raises(ValueError, match="limitations"):
        render_control_coverage_markdown(forged_report)


def test_renderer_rejects_bypassed_missing_mitre_boundary() -> None:
    report = ControlCoverageReport.model_validate(_mitre_report_payload())
    forged_report = report.model_copy(
        update={"limitations": ("Additional mapping limitation one.",)}
    )

    with pytest.raises(ValueError, match="limitations"):
        render_control_coverage_markdown(forged_report)


def test_renderer_fails_closed_on_forged_report_identity() -> None:
    report = ControlCoverageReport.model_validate(_report_payload())
    forged_report = report.model_copy(update={"report_id": "control-map-0000000000000000"})

    with pytest.raises(ValueError, match="report_id"):
        render_control_coverage_markdown(forged_report)


def test_writer_revalidates_unsafe_report_before_creating_output(tmp_path: Path) -> None:
    report = ControlCoverageReport.model_validate(_report_payload())
    forged_report = report.model_copy(
        update={"coverage_state_counts": {ControlCoverageState.observed: 999}}
    )
    output = tmp_path / "control-coverage"

    with pytest.raises(ValueError, match="coverage_state_counts"):
        write_control_coverage_report(forged_report, output)

    assert not output.exists()


def test_renderer_fails_closed_on_missing_mitre_mapping_strength() -> None:
    report = ControlCoverageReport.model_validate(_mitre_report_payload())
    forged_item = report.items[0].model_copy(update={"mapping_strength": None})
    forged_report = report.model_copy(update={"items": (forged_item, *report.items[1:])})

    with pytest.raises(ValueError, match="mapping_strength"):
        render_control_coverage_markdown(forged_report)


@pytest.mark.parametrize(
    ("field_name", "forged_value"),
    (
        ("mapping_strength", ControlMappingStrength.direct),
        ("atlas_tactic_ids", ("AML.TA0004",)),
        ("atlas_technique_ids", ("AML.T0051",)),
    ),
)
def test_renderer_rejects_non_mitre_items_with_mitre_only_metadata(
    field_name: str,
    forged_value: object,
) -> None:
    report = ControlCoverageReport.model_validate(_report_payload())
    forged_item = report.items[0].model_copy(update={field_name: forged_value})
    forged_report = report.model_copy(update={"items": (forged_item, report.items[1])})

    with pytest.raises(ValueError, match="non-MITRE"):
        render_control_coverage_markdown(forged_report)


def test_renderer_rejects_mitre_ids_absent_from_pinned_catalog() -> None:
    report = ControlCoverageReport.model_validate(_mitre_report_payload())
    forged_item = report.items[0].model_copy(update={"atlas_tactic_ids": ("AML.TA9999",)})
    forged_report = report.model_copy(update={"items": (forged_item, report.items[1])})

    with pytest.raises(ValueError, match="pinned 2026.06 catalog"):
        render_control_coverage_markdown(forged_report)


def _all_nested_schema_versions(report: ControlCoverageReport) -> set[str]:
    return {
        version
        for item in report.items
        for version in (
            item.schema_version,
            *(ref.schema_version for ref in item.evidence_refs),
            *(
                nested_version
                for evaluation in item.condition_evaluations
                for nested_version in (
                    evaluation.schema_version,
                    *(ref.schema_version for ref in evaluation.evidence_refs),
                )
            ),
        )
    }


def _resolve_path(value: Any, path: tuple[str | int, ...]) -> Any:
    for part in path:
        value = value[part]
    return value


def _previous_schema_version(schema_version: str) -> str:
    versions = ("0.3.1", *_HISTORICAL_REPORT_VERSIONS)
    return versions[versions.index(schema_version) - 1]
