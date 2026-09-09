from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.controls.efficacy import build_control_efficacy_report
from agent_assure.schema.efficacy import (
    ControlEfficacyReport,
    ThreatApplicabilityManifest,
)
from agent_assure.schema.validation import validate_artifact_payload
from tests.unit.controls.test_control_efficacy import (
    _DROP_OPERATOR,
    _campaign,
    _manifest,
)

ROOT = Path(__file__).resolve().parents[3]


def test_frozen_v062_threat_manifest_replays_relational_validation() -> None:
    manifest = ThreatApplicabilityManifest.build(
        schema_version="0.6.2",
        threat_source={"name": "test-source", "version": "1"},
        present_control_ids=("control-a", "control-b"),
        items=(
            {
                "threat_id": "threat-a",
                "applicability": "applicable",
                "critical": True,
                "reviewed_at": "2026-08-08",
            },
        ),
        limitations=("Synthetic v0.6.2 replay fixture.",),
    )
    payload = manifest.model_dump(mode="json")

    assert (
        validate_artifact_payload(payload, "threat-applicability-manifest") == "frozen-jsonschema"
    )

    payload["present_control_ids"] = list(reversed(payload["present_control_ids"]))
    _rehash(payload, "manifest_digest")
    _frozen_validator("threat-applicability-manifest").validate(payload)

    with pytest.raises(ValueError, match="failed model validation"):
        validate_artifact_payload(payload, "threat-applicability-manifest")


def test_frozen_v062_control_efficacy_report_replays_relational_validation() -> None:
    execution = _campaign(operator_ids=(_DROP_OPERATOR,))
    current_manifest = _manifest(critical=True)
    manifest_values = current_manifest.model_dump(
        mode="json",
        exclude={"manifest_digest", "schema_version"},
    )
    legacy_manifest = ThreatApplicabilityManifest.build(
        **manifest_values,
        schema_version="0.6.2",
    )
    current_report = build_control_efficacy_report(
        execution.campaign,
        execution.catalog,
        legacy_manifest,
        required_operator_ids=(_DROP_OPERATOR,),
    )
    report_values = current_report.model_dump(
        mode="json",
        exclude={"report_digest", "schema_version"},
    )
    legacy_report = ControlEfficacyReport.build(
        **report_values,
        schema_version="0.6.2",
    )
    payload = legacy_report.model_dump(mode="json")

    assert validate_artifact_payload(payload, "control-efficacy-report") == "frozen-jsonschema"

    payload["caught_operator_count"] += 1
    _rehash(payload, "report_digest")
    _frozen_validator("control-efficacy-report").validate(payload)

    with pytest.raises(ValueError, match="failed model validation"):
        validate_artifact_payload(payload, "control-efficacy-report")


def _rehash(payload: dict[str, object], digest_field: str) -> None:
    payload[digest_field] = sha256_hexdigest(
        {key: value for key, value in payload.items() if key != digest_field}
    )


def _frozen_validator(artifact_kind: str) -> Draft202012Validator:
    schema = json.loads(
        (ROOT / "schemas" / "v0.6.2" / f"{artifact_kind}.schema.json").read_text(encoding="utf-8")
    )
    return Draft202012Validator(schema)
