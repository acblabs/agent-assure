from __future__ import annotations

import json
from pathlib import Path

from agent_assure.authoring.yaml_nodes import load_yaml_nodes
from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.io_limits import load_json_bounded
from agent_assure.schema.suite import CompiledSuite


def load_compiled_suite(path: Path, *, expected_digest: str | None = None) -> CompiledSuite:
    payload = load_json_bounded(path)
    compiled = CompiledSuite.model_validate(payload)
    if expected_digest is not None:
        actual_digest = compiled_suite_digest(compiled)
        if actual_digest != expected_digest:
            raise ValueError(
                f"compiled suite digest mismatch: expected {expected_digest}, got {actual_digest}"
            )
    return compiled


def write_compiled_suite(compiled: CompiledSuite, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(compiled.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def compiled_suite_digest(compiled: CompiledSuite) -> str:
    return sha256_hexdigest(compiled.model_dump(mode="json"))


def verify_source_digest(compiled: CompiledSuite, source_yaml: Path) -> None:
    loaded = load_yaml_nodes(source_yaml)
    actual_digest = sha256_hexdigest(loaded.data)
    if actual_digest != compiled.source_digest:
        raise ValueError(
            f"suite source digest mismatch: expected {compiled.source_digest}, got {actual_digest}"
        )
