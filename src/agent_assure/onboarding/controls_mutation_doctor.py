from __future__ import annotations

import os
from copy import deepcopy
from pathlib import Path

from agent_assure import __version__
from agent_assure.authoring.yaml_nodes import MAX_YAML_BYTES
from agent_assure.controls.efficacy import load_threat_applicability_manifest
from agent_assure.mutation.campaign import build_core_catalog
from agent_assure.mutation.catalog import (
    CatalogIntegrityError,
    RegisteredOperator,
    registered_operators,
)
from agent_assure.onboarding.controls_mutation import (
    ControlsMutationOnboardingConfig,
    DiagnosticStatus,
    DoctorCode,
    DoctorDiagnostic,
    DoctorReport,
    ScaffoldConflictError,
)
from agent_assure.onboarding.controls_mutation_config import (
    input_binding_errors as _input_binding_errors,
)
from agent_assure.onboarding.controls_mutation_config import (
    load_controls_mutation_config,
)
from agent_assure.onboarding.controls_mutation_config import (
    load_runset_snapshot as _load_runset_snapshot,
)
from agent_assure.onboarding.controls_mutation_config import (
    load_suite as _load_suite,
)
from agent_assure.onboarding.diagnostics import (
    bounded_error as _bounded_error,
)
from agent_assure.onboarding.diagnostics import (
    display_path as _display_path,
)
from agent_assure.onboarding.path_safety import (
    UnsafeDirectoryChainError,
    confined_config_input_file,
    require_regular_directory_chain,
)
from agent_assure.onboarding.path_safety import (
    is_regular_directory as _is_regular_directory,
)
from agent_assure.onboarding.path_safety import (
    is_safe_input_file as _is_safe_input_file,
)
from agent_assure.onboarding.path_safety import (
    path_entry_exists as _path_entry_exists,
)
from agent_assure.onboarding.path_safety import (
    read_confined_file as _read_confined_file,
)
from agent_assure.schema.campaign import CORE_MUTATION_CATALOG_ID
from agent_assure.schema.common import MACHINE_IDENTIFIER_SCHEMA_VERSION, ExecutionMode
from agent_assure.schema.efficacy import ThreatApplicabilityManifest
from agent_assure.schema.run import RunSet
from agent_assure.schema.suite import CompiledSuite

_DOCTOR_CODE_ORDER = (
    DoctorCode.CONFIG_PATH,
    DoctorCode.CONFIG_SCHEMA,
    DoctorCode.PACKAGE_VERSION,
    DoctorCode.SUITE_PATH,
    DoctorCode.RUNSET_PATH,
    DoctorCode.THREAT_MANIFEST_PATH,
    DoctorCode.THREAT_MANIFEST_SCHEMA,
    DoctorCode.OUTPUT_PATH,
    DoctorCode.SCHEMA_VERSIONS,
    DoctorCode.INPUT_BINDING,
    DoctorCode.CATALOG_IDENTITY,
    DoctorCode.OPERATOR_CONFIGURATION,
    DoctorCode.THREAT_SCOPE,
    DoctorCode.OPERATOR_APPLICABILITY,
    DoctorCode.OFFLINE_READINESS,
)


def diagnose_controls_mutate(config_path: Path) -> DoctorReport:
    """Perform a deterministic, read-only preflight for the offline workflow."""
    config_path = config_path.absolute()
    diagnostics: list[DoctorDiagnostic] = []
    config: ControlsMutationOnboardingConfig | None = None
    suite: CompiledSuite | None = None
    runset: RunSet | None = None
    source_payload: dict[str, object] | None = None
    manifest: ThreatApplicabilityManifest | None = None
    operators: tuple[RegisteredOperator, ...] | None = None
    inputs_bound = False
    resolved_paths: dict[str, Path] = {}

    if not _is_safe_input_file(config_path, root=config_path.parent):
        diagnostics.append(
            _fail(
                DoctorCode.CONFIG_PATH,
                "configuration is missing or is not a confined regular file: "
                f"{_display_path(config_path)}",
                "run 'agent-assure init controls-mutation --out-dir "
                f"{_display_path(config_path.parent)}'",
            )
        )
    else:
        diagnostics.append(
            _pass(
                DoctorCode.CONFIG_PATH,
                f"configuration path is readable: {_display_path(config_path)}",
            )
        )
        try:
            config = load_controls_mutation_config(config_path)
        except (OSError, TypeError, ValueError) as exc:
            diagnostics.append(
                _fail(
                    DoctorCode.CONFIG_SCHEMA,
                    f"configuration is invalid: {_bounded_error(exc)}",
                    "restore the generated configuration or fix the reported field",
                )
            )
        else:
            if config.schema_version != MACHINE_IDENTIFIER_SCHEMA_VERSION:
                diagnostics.append(
                    _fail(
                        DoctorCode.CONFIG_SCHEMA,
                        "configuration schema_version is unsupported: "
                        f"{config.schema_version}; expected {MACHINE_IDENTIFIER_SCHEMA_VERSION}",
                        "regenerate the scaffold with the installed agent-assure version",
                    )
                )
            else:
                diagnostics.append(
                    _pass(
                        DoctorCode.CONFIG_SCHEMA,
                        f"configuration schema_version is {config.schema_version}",
                    )
                )
    if config is None:
        if not any(item.code == DoctorCode.CONFIG_SCHEMA for item in diagnostics):
            diagnostics.append(
                _skip(
                    DoctorCode.CONFIG_SCHEMA,
                    "configuration path must be readable before schema validation",
                )
            )
        _append_skips(diagnostics, after=DoctorCode.CONFIG_SCHEMA)
        return _ordered_report(diagnostics)

    if config.package_version == __version__:
        diagnostics.append(
            _pass(
                DoctorCode.PACKAGE_VERSION, f"package version matches configuration: {__version__}"
            )
        )
    else:
        diagnostics.append(
            _fail(
                DoctorCode.PACKAGE_VERSION,
                "configuration requires agent-assure "
                f"{config.package_version}; installed {__version__}",
                "use the configured package version or regenerate into an empty directory",
            )
        )

    root = config_path.parent.absolute()
    path_fields = (
        (DoctorCode.SUITE_PATH, "suite", config.suite_path),
        (DoctorCode.RUNSET_PATH, "runset", config.runset_path),
        (
            DoctorCode.THREAT_MANIFEST_PATH,
            "threat applicability manifest",
            config.threat_applicability_manifest,
        ),
    )
    for code, label, relative in path_fields:
        candidate = root / Path(relative)
        try:
            candidate = confined_config_input_file(root, relative, label=label)
        except ValueError:
            diagnostics.append(
                _fail(
                    code,
                    f"{label} is missing or is not a confined regular file: "
                    f"{_display_path(candidate)}",
                    f"restore {relative} or update the configuration to a local regular file",
                )
            )
        else:
            diagnostics.append(_pass(code, f"{label} path is readable: {_display_path(candidate)}"))
            resolved_paths[code] = candidate

    threat_manifest_path = resolved_paths.get(DoctorCode.THREAT_MANIFEST_PATH)
    if threat_manifest_path is None:
        diagnostics.append(
            _skip(
                DoctorCode.THREAT_MANIFEST_SCHEMA,
                "threat applicability manifest path is unavailable",
            )
        )
    else:
        try:
            manifest = _load_threat_manifest(threat_manifest_path, root=root)
        except (OSError, TypeError, ValueError) as exc:
            diagnostics.append(
                _fail(
                    DoctorCode.THREAT_MANIFEST_SCHEMA,
                    f"threat applicability manifest is invalid: {_bounded_error(exc)}",
                    "restore the generated manifest or fix its authored v1 fields",
                )
            )
        else:
            diagnostics.append(
                _pass(
                    DoctorCode.THREAT_MANIFEST_SCHEMA,
                    "threat applicability manifest is valid and digest-addressed: "
                    f"{manifest.manifest_digest}",
                )
            )

    output_path = root / Path(config.output_dir)
    output_error = _output_path_error(output_path, root=root, inputs=tuple(resolved_paths.values()))
    if output_error is None:
        diagnostics.append(
            _pass(
                DoctorCode.OUTPUT_PATH,
                f"output path has a writable local parent: {_display_path(output_path)}",
            )
        )
    else:
        diagnostics.append(
            _fail(
                DoctorCode.OUTPUT_PATH,
                output_error,
                "choose a confined, writable output directory distinct from all inputs",
            )
        )

    suite_path = resolved_paths.get(DoctorCode.SUITE_PATH)
    runset_path = resolved_paths.get(DoctorCode.RUNSET_PATH)
    input_errors: list[str] = []
    if suite_path is not None:
        try:
            suite = _load_suite(suite_path, root=root)
        except (OSError, TypeError, ValueError) as exc:
            input_errors.append(f"suite: {_bounded_error(exc)}")
    if runset_path is not None:
        try:
            runset, source_payload = _load_runset_snapshot(runset_path, root=root)
        except (OSError, TypeError, ValueError) as exc:
            input_errors.append(f"runset: {_bounded_error(exc)}")
    if input_errors:
        diagnostics.append(
            _fail(
                DoctorCode.SCHEMA_VERSIONS,
                "input validation failed: " + "; ".join(input_errors),
                "regenerate or validate the suite and RunSet before mutation",
            )
        )
    elif suite is None or runset is None:
        diagnostics.append(_skip(DoctorCode.SCHEMA_VERSIONS, "input paths are unavailable"))
    elif (
        suite.schema_version != MACHINE_IDENTIFIER_SCHEMA_VERSION
        or runset.schema_version != MACHINE_IDENTIFIER_SCHEMA_VERSION
    ):
        diagnostics.append(
            _fail(
                DoctorCode.SCHEMA_VERSIONS,
                "suite and RunSet must use current schema_version "
                f"{MACHINE_IDENTIFIER_SCHEMA_VERSION}; got "
                f"{suite.schema_version} and {runset.schema_version}",
                "recompile/regenerate both inputs with the installed package",
            )
        )
    else:
        diagnostics.append(
            _pass(
                DoctorCode.SCHEMA_VERSIONS,
                f"suite and RunSet schema versions are {MACHINE_IDENTIFIER_SCHEMA_VERSION}",
            )
        )

    if suite is None or runset is None:
        diagnostics.append(
            _skip(DoctorCode.INPUT_BINDING, "validated suite and RunSet are required")
        )
    else:
        binding_errors = _input_binding_errors(suite, runset)
        if binding_errors:
            diagnostics.append(
                _fail(
                    DoctorCode.INPUT_BINDING,
                    "; ".join(binding_errors),
                    "use a RunSet produced for this exact compiled suite",
                )
            )
        else:
            diagnostics.append(
                _pass(DoctorCode.INPUT_BINDING, "RunSet is digest-bound to the suite")
            )
            inputs_bound = True

    try:
        operators = registered_operators()
        catalog = build_core_catalog(operators)
        catalog_error = None
        if catalog.catalog_id != config.catalog_id:
            catalog_error = (
                f"configured catalog {config.catalog_id!r} does not match {catalog.catalog_id!r}"
            )
        elif catalog.schema_version != MACHINE_IDENTIFIER_SCHEMA_VERSION:
            catalog_error = (
                f"catalog schema_version {catalog.schema_version} does not match "
                f"{MACHINE_IDENTIFIER_SCHEMA_VERSION}"
            )
    except (CatalogIntegrityError, OSError, TypeError, ValueError) as exc:
        catalog_error = f"built-in catalog identity could not be established: {_bounded_error(exc)}"
    if catalog_error is None:
        diagnostics.append(
            _pass(
                DoctorCode.CATALOG_IDENTITY,
                f"closed catalog identity is {CORE_MUTATION_CATALOG_ID}",
            )
        )
    else:
        diagnostics.append(
            _fail(
                DoctorCode.CATALOG_IDENTITY,
                catalog_error,
                "reinstall an intact agent-assure package and retain required_catalog: core/v1",
            )
        )

    operator_by_id = {item.descriptor.operator_id: item for item in operators or ()}
    unknown = sorted(set(config.operator_ids) - set(operator_by_id))
    if unknown:
        diagnostics.append(
            _fail(
                DoctorCode.OPERATOR_CONFIGURATION,
                "configuration references operators outside core/v1: " + ", ".join(unknown),
                "select operator IDs from the installed core/v1 catalog",
            )
        )
    else:
        diagnostics.append(
            _pass(
                DoctorCode.OPERATOR_CONFIGURATION,
                "configured operators are present and required operators are selected: "
                + ", ".join(config.operator_ids),
            )
        )

    if manifest is None:
        diagnostics.append(
            _skip(
                DoctorCode.THREAT_SCOPE,
                "a valid threat applicability manifest is required",
            )
        )
    elif catalog_error is not None or unknown:
        diagnostics.append(
            _skip(
                DoctorCode.THREAT_SCOPE,
                "validated catalog identity and configured operators are required",
            )
        )
    else:
        declared_threat_ids = {item.threat_id for item in manifest.items}
        configured_references = tuple(
            sorted(
                {
                    threat_id
                    for operator_id in config.operator_ids
                    for threat_id in operator_by_id[operator_id].threat_source_references
                }
            )
        )
        unscoped_references = tuple(
            threat_id for threat_id in configured_references if threat_id not in declared_threat_ids
        )
        if unscoped_references:
            diagnostics.append(
                _fail(
                    DoctorCode.THREAT_SCOPE,
                    "configured operators have unscoped catalog threat references: "
                    + ", ".join(unscoped_references),
                    "declare each reference in the threat applicability manifest "
                    "or remove the operator from this workflow",
                )
            )
        else:
            diagnostics.append(
                _pass(
                    DoctorCode.THREAT_SCOPE,
                    "all configured operator threat references are declared in the manifest: "
                    + ", ".join(configured_references),
                )
            )

    if (
        suite is None
        or runset is None
        or source_payload is None
        or not inputs_bound
        or unknown
        or catalog_error is not None
    ):
        diagnostics.append(
            _skip(
                DoctorCode.OPERATOR_APPLICABILITY,
                "validated, digest-bound inputs and known operators are required",
            )
        )
    else:
        applicability_errors = _operator_applicability_errors(
            suite,
            runset,
            source_payload,
            tuple(operator_by_id[item] for item in config.operator_ids),
        )
        if applicability_errors:
            diagnostics.append(
                _fail(
                    DoctorCode.OPERATOR_APPLICABILITY,
                    "; ".join(applicability_errors),
                    "satisfy each listed precondition or remove the operator from this workflow",
                )
            )
        else:
            diagnostics.append(
                _pass(
                    DoctorCode.OPERATOR_APPLICABILITY,
                    "every configured operator has at least one static target",
                )
            )

    blocking = [item.code for item in diagnostics if item.status is DiagnosticStatus.failed]
    if blocking:
        diagnostics.append(
            _fail(
                DoctorCode.OFFLINE_READINESS,
                "offline controls-mutate workflow is not ready; blocking diagnostics: "
                + ", ".join(blocking),
                "resolve the blocking diagnostics and rerun doctor",
            )
        )
    elif suite is None or runset is None:
        diagnostics.append(
            _skip(DoctorCode.OFFLINE_READINESS, "validated fixture inputs are required")
        )
    elif (
        suite.defaults.execution_mode is not ExecutionMode.fixture
        or runset.execution_mode is not ExecutionMode.fixture
    ):
        diagnostics.append(
            _fail(
                DoctorCode.OFFLINE_READINESS,
                "onboarding requires fixture-mode suite and RunSet inputs",
                "use deterministic fixture inputs; live/provider execution is not "
                "an offline workflow",
            )
        )
    else:
        diagnostics.append(
            _pass(
                DoctorCode.OFFLINE_READINESS,
                "workflow is fixture-only and requires no provider or network call",
            )
        )
    return _ordered_report(diagnostics)


def _output_path_error(path: Path, *, root: Path, inputs: tuple[Path, ...]) -> str | None:
    try:
        _require_regular_directory_chain(root.absolute())
        resolved_root = root.resolve(strict=True)
        if _path_entry_exists(path) and not _is_regular_directory(path):
            return "output path must be a regular directory: " + _display_path(path)
        candidate = path.resolve(strict=False)
        if not candidate.is_relative_to(resolved_root):
            return "output path escapes configuration directory: " + _display_path(path)
        for input_path in inputs:
            if candidate == input_path.resolve(strict=True):
                return "output path aliases an input: " + _display_path(path)
        parent = path if _path_entry_exists(path) else path.parent
        while not _path_entry_exists(parent) and parent != parent.parent:
            parent = parent.parent
        _require_regular_directory_chain(parent)
        if not os.access(parent, os.W_OK):
            return "output path has no writable local parent: " + _display_path(path)
    except (OSError, RuntimeError, ValueError) as exc:
        return f"output path could not be validated: {_bounded_error(exc)}"
    return None


def _load_threat_manifest(path: Path, *, root: Path) -> ThreatApplicabilityManifest:
    def _read_manifest(manifest_path: Path) -> bytes:
        return _read_confined_file(
            manifest_path,
            root=root,
            max_bytes=MAX_YAML_BYTES,
            label="threat applicability manifest",
        )

    return load_threat_applicability_manifest(
        path,
        reader=_read_manifest,
    )


def _require_regular_directory_chain(path: Path) -> None:
    try:
        require_regular_directory_chain(path)
    except UnsafeDirectoryChainError as exc:
        raise ScaffoldConflictError(str(exc)) from exc


def _operator_applicability_errors(
    suite: CompiledSuite,
    runset: RunSet,
    source_payload: dict[str, object],
    operators: tuple[RegisteredOperator, ...],
) -> tuple[str, ...]:
    errors: list[str] = []
    for operator in operators:
        operator_id = operator.descriptor.operator_id
        if runset.schema_version not in operator.descriptor.compatible_schema_versions:
            errors.append(
                f"{operator_id}: RunSet schema_version {runset.schema_version} is incompatible"
            )
            continue
        candidate_payload = deepcopy(source_payload)
        snapshot = deepcopy(candidate_payload)
        try:
            targets = operator.resolve_targets(suite, runset, candidate_payload)
        except Exception as exc:
            errors.append(f"{operator_id}: applicability check failed: {_bounded_error(exc)}")
            continue
        if candidate_payload != snapshot:
            errors.append(f"{operator_id}: applicability resolver modified its source")
            continue
        if not targets:
            prerequisites = ", ".join(
                precondition.summary for precondition in operator.descriptor.preconditions
            )
            errors.append(f"{operator_id}: no static target; prerequisites: {prerequisites}")
    return tuple(errors)


def _pass(code: str, message: str) -> DoctorDiagnostic:
    return DoctorDiagnostic(code=code, status=DiagnosticStatus.passed, message=message)


def _fail(code: str, message: str, action: str) -> DoctorDiagnostic:
    return DoctorDiagnostic(
        code=code,
        status=DiagnosticStatus.failed,
        message=message,
        action=action,
    )


def _skip(code: str, message: str) -> DoctorDiagnostic:
    return DoctorDiagnostic(code=code, status=DiagnosticStatus.skipped, message=message)


def _append_skips(diagnostics: list[DoctorDiagnostic], *, after: str) -> None:
    start = _DOCTOR_CODE_ORDER.index(after) + 1
    diagnostics.extend(
        _skip(code, "configuration must validate before this check")
        for code in _DOCTOR_CODE_ORDER[start:]
    )


def _ordered_report(diagnostics: list[DoctorDiagnostic]) -> DoctorReport:
    by_code: dict[str, DoctorDiagnostic] = {}
    for item in diagnostics:
        if item.code in by_code:
            raise RuntimeError(f"duplicate Doctor diagnostic code: {item.code}")
        by_code[item.code] = item
    ordered = tuple(by_code[code] for code in _DOCTOR_CODE_ORDER if code in by_code)
    return DoctorReport(diagnostics=ordered)
