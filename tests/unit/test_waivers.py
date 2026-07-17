from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_assure.authoring.yaml_nodes import MAX_YAML_DEPTH
from agent_assure.cli.waivers import load_waivers
from agent_assure.io_limits import MAX_JSON_DEPTH


def _waiver_payload() -> dict[str, str]:
    return {
        "waiver_id": "waiver-001",
        "owner": "owner@example.test",
        "rationale": "Temporary reviewed exception",
        "reason_code": "POLICY_FAILED",
        "finding_id": "finding-001",
        "artifact_digest": "a" * 64,
        "expires_on": "2030-01-01",
        "reviewer": "reviewer@example.test",
    }


def test_load_waivers_accepts_json_and_yaml_list_roots(tmp_path: Path) -> None:
    json_path = tmp_path / "waivers.json"
    yaml_path = tmp_path / "waivers.yaml"
    json_path.write_text(json.dumps([_waiver_payload()]), encoding="utf-8")
    yaml_path.write_text(
        "- " + json.dumps(_waiver_payload()) + "\n",
        encoding="utf-8",
    )

    assert load_waivers((json_path,))[0].waiver_id == "waiver-001"
    assert load_waivers((yaml_path,))[0].waiver_id == "waiver-001"


def test_load_waivers_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    path = tmp_path / "waiver.json"
    path.write_text('{"waiver_id":"first","waiver_id":"second"}', encoding="utf-8")

    with pytest.raises(ValueError, match="contains duplicate object keys"):
        load_waivers((path,))


def test_load_waivers_rejects_excessive_json_nesting(tmp_path: Path) -> None:
    path = tmp_path / "waiver.json"
    path.write_text("[" * (MAX_JSON_DEPTH + 1) + "]" * (MAX_JSON_DEPTH + 1))

    with pytest.raises(ValueError, match="exceeds maximum supported nesting depth"):
        load_waivers((path,))


def test_load_waivers_rejects_duplicate_yaml_keys(tmp_path: Path) -> None:
    path = tmp_path / "waiver.yaml"
    path.write_text("waiver_id: first\nwaiver_id: second\n", encoding="utf-8")

    with pytest.raises(ValueError, match="duplicate YAML mapping key"):
        load_waivers((path,))


def test_load_waivers_rejects_yaml_aliases(tmp_path: Path) -> None:
    path = tmp_path / "waiver.yaml"
    path.write_text("- &waiver {waiver_id: first}\n- *waiver\n", encoding="utf-8")

    with pytest.raises(ValueError, match="aliases are not supported"):
        load_waivers((path,))


def test_load_waivers_rejects_excessive_yaml_nesting(tmp_path: Path) -> None:
    path = tmp_path / "waiver.yaml"
    path.write_text("[" * (MAX_YAML_DEPTH + 1) + "null" + "]" * (MAX_YAML_DEPTH + 1))

    with pytest.raises(ValueError, match="exceeds maximum supported nesting depth"):
        load_waivers((path,))


def test_load_waivers_normalizes_unsupported_yaml_tag_error(tmp_path: Path) -> None:
    path = tmp_path / "waiver.yaml"
    path.write_text("waiver_id: !custom first\n", encoding="utf-8")

    with pytest.raises(ValueError, match="waiver YAML is invalid YAML"):
        load_waivers((path,))
