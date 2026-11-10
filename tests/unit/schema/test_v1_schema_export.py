"""Writer selection and rejection evidence; no complete v1 set is claimed."""

from __future__ import annotations

import json
from pathlib import Path
from types import MappingProxyType
from typing import Any

import pytest
from typer.testing import CliRunner

from agent_assure.cli.main import app
from agent_assure.schema import export as schema_export
from agent_assure.schema.base import SCHEMA_VERSION
from agent_assure.schema.packet import EvidencePacket
from agent_assure.schema.v1_base import V1_SCHEMA_CONTRACT_IDS, V1_WRITER_SCHEMA_VERSION
from agent_assure.schema.v1_identity import SourceEventIdentity

ROOT = Path(__file__).resolve().parents[3]


def test_legacy_payload_bytes_match_frozen_resources_before_persistence() -> None:
    """Verify the byte producer independently of the native output boundary."""
    frozen = ROOT / "schemas/v0.6.6"
    expected = {path.name: path.read_bytes() for path in frozen.glob("*.schema.json")}
    assert len(expected) == 58
    for payloads in (
        schema_export._writer_schema_payloads(),
        schema_export._writer_schema_payloads(SCHEMA_VERSION),
    ):
        actual = {f"{kind}.schema.json": payload.encode("utf-8") for kind, payload in payloads}
        assert actual == expected


def test_default_and_explicit_legacy_exports_preserve_all_58_frozen_bytes(tmp_path: Path) -> None:
    frozen = ROOT / "schemas/v0.6.6"
    expected = {path.name: path.read_bytes() for path in frozen.glob("*.schema.json")}
    assert len(expected) == 58
    default = schema_export.export_json_schemas(tmp_path / "default")
    explicit = schema_export.export_json_schemas(
        tmp_path / "explicit", writer_schema_version=SCHEMA_VERSION
    )
    assert {path.name: path.read_bytes() for path in default} == expected
    assert {path.name: path.read_bytes() for path in explicit} == expected


def test_v1_inventory_matches_the_exact_accepted_contract_ids() -> None:
    inventory = json.loads(
        (ROOT / "docs/governance/v1/sprint2/wire-contract-inventory.json").read_bytes()
    )
    assert V1_WRITER_SCHEMA_VERSION == "1.0.0rc1"
    assert isinstance(V1_SCHEMA_CONTRACT_IDS, tuple)
    assert len(V1_SCHEMA_CONTRACT_IDS) == len(set(V1_SCHEMA_CONTRACT_IDS)) == 42
    assert V1_SCHEMA_CONTRACT_IDS == tuple(inventory["production_wire_schema_contract_ids"])


def test_v1_catalog_is_immutable_and_only_records_the_actual_implemented_model() -> None:
    assert isinstance(schema_export._V1_SCHEMA_MODELS, MappingProxyType)
    assert dict(schema_export._V1_SCHEMA_MODELS) == {
        "source-event-identity/v1": SourceEventIdentity,
    }


@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize(
    "catalog_case", ["partial", "unknown", "same_count_wrong_set", "wrong_root", "wrong_source"]
)
def test_v1_rejection_never_creates_or_changes_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, existing: bool, catalog_case: str
) -> None:
    catalog: dict[str, schema_export.SchemaModel] = {
        "source-event-identity/v1": SourceEventIdentity,
    }
    if catalog_case == "unknown":
        catalog["unknown-contract/v1"] = SourceEventIdentity
    elif catalog_case == "same_count_wrong_set":
        # One real model is reused only as an adversarial mapping value. No
        # placeholder production models or allegedly valid complete set exist.
        catalog = dict.fromkeys(V1_SCHEMA_CONTRACT_IDS[:-1], SourceEventIdentity)
        catalog["unknown-contract/v1"] = SourceEventIdentity
        assert len(catalog) == 42
    elif catalog_case == "wrong_root":
        catalog = {"approval-receipt/v1": SourceEventIdentity}
    elif catalog_case == "wrong_source":
        catalog = {"source-event-identity/v1": EvidencePacket}
    monkeypatch.setattr(schema_export, "_V1_SCHEMA_MODELS", MappingProxyType(catalog))
    destination = tmp_path / "schemas"
    if existing:
        destination.mkdir()
        (destination / "sentinel").write_bytes(b"retain exact bytes")
    with pytest.raises(schema_export.SchemaExportError):
        schema_export.export_json_schemas(
            destination, writer_schema_version=V1_WRITER_SCHEMA_VERSION
        )
    if existing:
        assert {path.name: path.read_bytes() for path in destination.iterdir()} == {
            "sentinel": b"retain exact bytes",
        }
    else:
        assert not destination.exists()


def test_source_identity_override_has_no_generic_root_envelope() -> None:
    schema = schema_export._v1_schema_for_contract("source-event-identity/v1", SourceEventIdentity)
    properties = schema["properties"]
    assert isinstance(properties, dict)
    assert set(properties) == {
        "identity_contract_id",
        "run_id",
        "producer_id",
        "producer_epoch",
        "event_id",
    }
    assert "artifact_kind" not in properties
    assert "schema_version" not in properties


@pytest.mark.parametrize(
    "version", ["0.6.5", "1.0.0", "1.0.0rc01", "", " 0.6.6", None, True, 1, b"0.6.6"]
)
def test_unknown_writer_versions_are_exactly_rejected_before_output(
    tmp_path: Path, version: Any
) -> None:
    destination = tmp_path / "schemas"
    with pytest.raises(schema_export.SchemaExportError, match="unsupported writer"):
        schema_export.export_json_schemas(destination, writer_schema_version=version)
    assert not destination.exists()


@pytest.mark.parametrize("version", ["1.0.0rc1", "unknown"])
def test_cli_reports_unavailable_writer_as_exit_2_without_output(
    tmp_path: Path, version: str
) -> None:
    destination = tmp_path / "schemas"
    result = CliRunner().invoke(
        app,
        ["schema", "export", "--out", str(destination), "--writer-schema-version", version],
    )
    assert result.exit_code == 2
    assert "Schema export unavailable" in result.output
    assert not destination.exists()
