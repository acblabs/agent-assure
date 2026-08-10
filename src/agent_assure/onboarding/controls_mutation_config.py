from __future__ import annotations

from pathlib import Path
from typing import cast

from agent_assure.authoring.compiler import compile_loaded_suite
from agent_assure.authoring.yaml_nodes import MAX_YAML_BYTES, load_yaml_nodes_text
from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.fixtures.loader import compiled_suite_digest
from agent_assure.io_limits import (
    MAX_ARTIFACT_JSON_BYTES,
    BoundedFileContents,
    load_json_bytes_bounded,
)
from agent_assure.mutation.execution import validated_runset_projection
from agent_assure.onboarding.controls_mutation import (
    ControlsMutationInputBinding,
    ControlsMutationOnboardingConfig,
)
from agent_assure.onboarding.path_safety import (
    confined_config_input_file,
)
from agent_assure.onboarding.path_safety import (
    read_confined_file as _read_confined_file,
)
from agent_assure.onboarding.path_safety import (
    read_confined_file_snapshot as _read_confined_file_snapshot,
)
from agent_assure.schema.run import RunSet
from agent_assure.schema.suite import CompiledSuite
from agent_assure.schema.validation import (
    project_validated_artifact_payload,
    validate_loaded_artifact_payload,
)


def load_controls_mutation_config(path: Path) -> ControlsMutationOnboardingConfig:
    config, _contents = load_controls_mutation_config_snapshot(path)
    return config


def load_controls_mutation_config_snapshot(
    path: Path,
) -> tuple[ControlsMutationOnboardingConfig, BoundedFileContents]:
    """Load and hash one confined configuration from the same validated descriptor."""
    contents = _read_confined_file_snapshot(
        path,
        root=path.parent,
        max_bytes=MAX_YAML_BYTES,
        label="controls-mutation config",
    )
    return parse_controls_mutation_config(contents.data), contents


def parse_controls_mutation_config(data: bytes) -> ControlsMutationOnboardingConfig:
    """Parse bounded controls-mutation configuration bytes without another file read."""
    if len(data) > MAX_YAML_BYTES:
        raise ValueError("controls-mutation config exceeds maximum supported size")
    loaded = load_yaml_nodes_text(
        data.decode("utf-8"),
        label="controls-mutation config",
    )
    return ControlsMutationOnboardingConfig.model_validate(loaded.data)


def load_controls_mutation_input_binding(
    config: ControlsMutationOnboardingConfig,
    *,
    root: Path,
) -> ControlsMutationInputBinding:
    """Load and canonically identify the suite and RunSet named by configuration."""
    suite_path = confined_config_input_file(
        root,
        config.suite_path,
        label="configured suite",
    )
    runset_path = confined_config_input_file(
        root,
        config.runset_path,
        label="configured RunSet",
    )
    suite = load_suite(suite_path, root=root)
    runset, source_payload = load_runset_snapshot(runset_path, root=root)
    binding_errors = input_binding_errors(suite, runset)
    if binding_errors:
        raise ValueError("; ".join(binding_errors))
    _projected_runset, canonical_source = validated_runset_projection(source_payload)
    return ControlsMutationInputBinding(
        suite_path=suite_path,
        runset_path=runset_path,
        suite_digest=compiled_suite_digest(suite),
        source_digest=sha256_hexdigest(canonical_source),
    )


def load_suite(path: Path, *, root: Path) -> CompiledSuite:
    if path.suffix.lower() in {".yaml", ".yml"}:
        data = _read_confined_file(
            path,
            root=root,
            max_bytes=MAX_YAML_BYTES,
            label="suite YAML",
        )
        loaded = load_yaml_nodes_text(data.decode("utf-8"), label="suite YAML")
        return compile_loaded_suite(loaded, source_digest=sha256_hexdigest(loaded.data))
    payload = load_validated_json_snapshot(
        path,
        root=root,
        kind="compiled-suite",
        label="compiled suite JSON",
    )
    return project_validated_artifact_payload(
        payload,
        CompiledSuite,
        kind="compiled-suite",
    )


def load_runset_snapshot(path: Path, *, root: Path) -> tuple[RunSet, dict[str, object]]:
    payload = load_validated_json_snapshot(
        path,
        root=root,
        kind="run-set",
        label="RunSet JSON",
    )
    runset = project_validated_artifact_payload(payload, RunSet, kind="run-set")
    return runset, payload


def load_validated_json_snapshot(
    path: Path,
    *,
    root: Path,
    kind: str,
    label: str,
) -> dict[str, object]:
    data = _read_confined_file(
        path,
        root=root,
        max_bytes=MAX_ARTIFACT_JSON_BYTES,
        label=label,
    )
    payload = load_json_bytes_bounded(data, label=label)
    validate_loaded_artifact_payload(payload, kind)
    return cast(dict[str, object], payload)


def input_binding_errors(suite: CompiledSuite, runset: RunSet) -> tuple[str, ...]:
    errors = []
    if runset.suite_id != suite.suite_id:
        errors.append(f"RunSet suite_id {runset.suite_id!r} does not match {suite.suite_id!r}")
    if runset.suite_version != suite.suite_version:
        errors.append(
            f"RunSet suite_version {runset.suite_version!r} does not match {suite.suite_version!r}"
        )
    digest = compiled_suite_digest(suite)
    if runset.suite_digest != digest:
        errors.append("RunSet suite_digest does not match the compiled suite digest")
    return tuple(errors)
