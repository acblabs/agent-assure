from __future__ import annotations

from pathlib import Path

import typer

from agent_assure.authoring.yaml_nodes import safe_load_yaml_text
from agent_assure.io_limits import MAX_CONFIG_TEXT_BYTES, loads_json_bounded, read_text_bounded
from agent_assure.policies.base import Waiver


def load_waivers(paths: tuple[Path, ...]) -> tuple[Waiver, ...]:
    waivers: list[Waiver] = []
    for path in paths:
        text = read_text_bounded(path, max_bytes=MAX_CONFIG_TEXT_BYTES, label="waiver file")
        if path.suffix.lower() == ".json":
            payload = loads_json_bounded(text, label="waiver JSON")
        else:
            payload = safe_load_yaml_text(text, label="waiver YAML")
        if isinstance(payload, dict) and "waivers" in payload:
            raw_waivers = payload["waivers"]
        else:
            raw_waivers = payload
        if isinstance(raw_waivers, dict):
            raw_waivers = [raw_waivers]
        if not isinstance(raw_waivers, list):
            raise typer.BadParameter(f"waiver file must contain an object or list: {path}")
        waivers.extend(Waiver.model_validate(item) for item in raw_waivers)
    return tuple(waivers)
