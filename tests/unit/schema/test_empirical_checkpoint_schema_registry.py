from __future__ import annotations

from collections.abc import Callable
from importlib import import_module
from typing import cast

import pytest

import agent_assure.schema as public_schema
from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.schema.export import (
    CONTRACT_ARTIFACT_KINDS,
    SCHEMA_MODELS,
    persisted_identity_fields_for_kind,
    writer_json_schema,
)
from agent_assure.schema.stochastic_sensitivity import RepeatedEvidenceSensitivityProtocol
from agent_assure.schema.validation import validate_artifact_payload

EMPIRICAL_CHECKPOINT_ROOTS = {
    "external-pilot-evidence": "ExternalPilotEvidence",
    "external-pilot-input-manifest": "PilotInputManifest",
    "external-pilot-independence-review": "ExternalPilotIndependenceReviewReceipt",
    "process-equivalence-benchmark": "ProcessEquivalenceBenchmarkManifest",
    "real-model-study-execution-review": "StudyExecutionReviewReceipt",
    "real-model-study-manifest": "RealModelStudyManifest",
    "real-model-study-report": "RealModelStudyReport",
    "real-model-study-registration-review": "StudyRegistrationReviewReceipt",
    "real-model-study-statistical-method-review": "StudyStatisticalMethodReviewReceipt",
}


@pytest.mark.parametrize(
    ("artifact_kind", "public_name"),
    sorted(EMPIRICAL_CHECKPOINT_ROOTS.items()),
)
def test_empirical_checkpoint_roots_are_public_contract_models(
    artifact_kind: str,
    public_name: str,
) -> None:
    model = SCHEMA_MODELS[artifact_kind]

    assert model is getattr(public_schema, public_name)
    assert artifact_kind in CONTRACT_ARTIFACT_KINDS
    assert persisted_identity_fields_for_kind(artifact_kind) == (
        "artifact_kind",
        "schema_version",
        "schema_name",
        "contract_id",
        "contract_version",
    )


@pytest.mark.parametrize("artifact_kind", sorted(EMPIRICAL_CHECKPOINT_ROOTS))
def test_empirical_checkpoint_writer_schemas_pin_current_identity(artifact_kind: str) -> None:
    schema = writer_json_schema(SCHEMA_MODELS[artifact_kind])
    properties = cast(dict[str, dict[str, object]], schema["properties"])

    assert properties["artifact_kind"]["const"] == artifact_kind
    assert properties["schema_version"]["const"] == "0.6.6"
    assert properties["schema_name"]["const"] == artifact_kind


def test_frozen_v065_stochastic_protocol_replays_relational_validation() -> None:
    protocol_payload = cast(
        Callable[[], dict[str, object]],
        import_module("tests.unit.schema.test_stochastic_sensitivity_schema")._protocol_payload,
    )
    protocol = RepeatedEvidenceSensitivityProtocol.build(
        **protocol_payload(),
        schema_version="0.6.5",
    )
    payload = protocol.model_dump(mode="json")

    assert (
        validate_artifact_payload(payload, "repeated-evidence-sensitivity-protocol")
        == "frozen-jsonschema"
    )

    payload["planned_pairs"] = protocol.planned_pairs + 1
    payload["protocol_digest"] = sha256_hexdigest(
        {key: value for key, value in payload.items() if key != "protocol_digest"}
    )

    with pytest.raises(ValueError, match="failed model validation"):
        validate_artifact_payload(payload, "repeated-evidence-sensitivity-protocol")
