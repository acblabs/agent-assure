from __future__ import annotations

from pathlib import Path

import pytest

from agent_assure.io_limits import MAX_JSON_DEPTH
from agent_assure.live.adapters import StaticJsonlAdapter
from agent_assure.live.config import LiveAdapterConfig, load_live_run_config
from agent_assure.live.output_contract import (
    LiveOutputContractError,
    parse_live_structured_content,
)


def test_live_json_config_rejects_excessive_nesting(tmp_path: Path) -> None:
    config_path = tmp_path / "live.json"
    config_path.write_text(_over_depth_object(), encoding="utf-8")

    with pytest.raises(
        ValueError,
        match="live run config JSON exceeds maximum supported nesting depth",
    ):
        load_live_run_config(config_path)


def test_static_provider_jsonl_rejects_excessive_nesting(tmp_path: Path) -> None:
    responses = tmp_path / "responses.jsonl"
    responses.write_text(
        '{"case_id":"case-001","record":'
        + ("[" * MAX_JSON_DEPTH)
        + "0"
        + ("]" * MAX_JSON_DEPTH)
        + "}\n",
        encoding="utf-8",
    )
    config = LiveAdapterConfig(
        adapter_id="static-jsonl",
        provider="static-provider",
        model="static-model",
        response_jsonl_path=responses.name,
    )

    with pytest.raises(
        ValueError,
        match="static response JSON exceeds maximum supported nesting depth",
    ):
        StaticJsonlAdapter(config, base_dir=tmp_path)


def test_live_structured_provider_content_normalizes_depth_error() -> None:
    with pytest.raises(LiveOutputContractError, match="was not valid JSON") as raised:
        parse_live_structured_content(_over_depth_object())

    assert raised.value.__cause__ is not None
    assert "exceeds maximum supported nesting depth" in str(raised.value.__cause__)


def _over_depth_object() -> str:
    return '{"nested":' + ("[" * MAX_JSON_DEPTH) + "0" + ("]" * MAX_JSON_DEPTH) + "}"
