from __future__ import annotations

import json
import os
import re
import tomllib
import uuid
from collections import defaultdict, deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path, PurePosixPath
from typing import cast
from urllib.parse import quote

from agent_assure import __version__
from agent_assure.artifact_io import file_sha256, write_text_atomic
from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.io_limits import BoundedFileContents, read_file_bounded_at
from agent_assure.schema.environment import EnvironmentInfo, InstalledPackage

JsonObject = dict[str, object]

CYCLONEDX_SCHEMA = "http://cyclonedx.org/schema/bom-1.5.schema.json"
SBOM_PROFILE = "agent-assure-release-build-environment-v0.2"
MAX_SBOM_BYTES = 16 * 1024 * 1024
MAX_PROJECT_METADATA_BYTES = 1024 * 1024
MAX_RELEASE_ARTIFACT_BYTES = 64 * 1024 * 1024

_PACKAGE_NAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
_NORMALIZED_PACKAGE_NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_REQUIREMENT_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
_LOCK_REQUIREMENT_RE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[A-Za-z0-9_,.-]+\])?"
    r"={2,3}([^;\\\s]+)(?:\s*;([^\\]*))?\s*\\?$"
)
_LOCK_HASH_RE = re.compile(r"^\s+--hash=sha256:([0-9a-fA-F]{64})\s*\\?$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_CONTROL_CHARACTER_RE = re.compile(r"[\x00-\x1f\x7f]")
_PEP508_MARKER_ENVIRONMENT_KEYS = frozenset(
    {
        "implementation_name",
        "implementation_version",
        "os_name",
        "platform_machine",
        "platform_python_implementation",
        "platform_system",
        "python_full_version",
        "python_version",
        "sys_platform",
    }
)
_UNSUPPORTED_PEP508_MARKER_VARIABLE_RE = re.compile(
    r"\b(?:dependency_groups|extra|extras|platform_release|platform_version)\b"
)


@dataclass(frozen=True)
class _LockedPackage:
    name: str
    version: str
    hashes: tuple[str, ...]
    parents: tuple[str, ...]
    marker: str | None


@dataclass(frozen=True)
class _LockEvidence:
    relative_path: str
    digest: str
    packages: Mapping[tuple[str, str], _LockedPackage]


@dataclass(frozen=True)
class _ProjectMetadata:
    name: str
    version: str
    runtime_roots: frozenset[str]
    optional_roots: frozenset[str]
    development_roots: frozenset[str]
    build_roots: frozenset[str]
    authors: tuple[str, ...]
    license_value: str | None
    license_is_expression: bool


def build_sbom(
    environment: EnvironmentInfo,
    *,
    project_name: str = "agent-assure",
    project_version: str = __version__,
    distribution_paths: tuple[Path, ...] = (),
    project_root: Path | None = None,
    package_license_expressions: Mapping[tuple[str, str], str] | None = None,
) -> JsonObject:
    project_pypi_name = _validated_pypi_name(project_name)
    project_ref = _package_ref(project_pypi_name, project_version)
    project_metadata = _load_project_metadata(
        project_root,
        expected_name=project_pypi_name,
        expected_version=project_version,
    )
    lock_evidence = _load_lock_evidence(environment, project_root=project_root)
    license_expressions = (
        dict(package_license_expressions)
        if package_license_expressions is not None
        else _installed_license_expressions()
    )
    installed_packages = _validated_installed_packages(
        environment.installed_packages,
        project_name=project_pypi_name,
    )
    installed_refs = {
        _pypi_name(package.name): _package_ref(_pypi_name(package.name), package.version)
        for package in installed_packages
    }
    lock_matches = _match_lock_packages(installed_packages, lock_evidence)
    graph = _dependency_graph(
        installed_refs=installed_refs,
        lock_matches=lock_matches,
        project_name=project_pypi_name,
    )
    scope_labels = _dependency_scopes(
        installed_names=frozenset(installed_refs),
        graph=graph,
        project_metadata=project_metadata,
        lock_evidence=lock_evidence,
    )
    package_components = [
        _package_component(
            package,
            lock_package=lock_matches.get((_pypi_name(package.name), package.version)),
            lock_path=lock_evidence.relative_path if lock_evidence is not None else None,
            scope_label=scope_labels.get(_pypi_name(package.name)),
            license_expression=license_expressions.get((_pypi_name(package.name), package.version)),
        )
        for package in installed_packages
    ]
    file_components = [
        _file_component(path, project_root=project_root)
        for path in sorted(
            distribution_paths,
            key=lambda item: _display_path(item, project_root),
        )
    ]
    payload: JsonObject = {
        "$schema": CYCLONEDX_SCHEMA,
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "lifecycles": [{"phase": "build"}],
            "tools": [
                {
                    "vendor": "ACB Labs",
                    "name": "agent-assure",
                    "version": __version__,
                }
            ],
            "component": _project_component(
                project_name=project_name,
                project_version=project_version,
                project_ref=project_ref,
                project_metadata=project_metadata,
            ),
            "properties": _metadata_properties(
                environment=environment,
                lock_evidence=lock_evidence,
                components=package_components,
            ),
        },
        "components": [*package_components, *file_components],
        "dependencies": _cyclonedx_dependencies(
            project_ref=project_ref,
            project_name=project_pypi_name,
            installed_refs=installed_refs,
            graph=graph,
            project_metadata=project_metadata,
            lock_evidence=lock_evidence,
        ),
        "compositions": [
            {
                "aggregate": "unknown",
                "assemblies": [project_ref],
                "dependencies": [project_ref],
            }
        ],
        "properties": [
            {
                "name": "agent-assure:vulnerability-analysis-status",
                "value": "not-performed",
            },
            {
                "name": "agent-assure:vulnerability-status",
                "value": "unknown",
            },
        ],
    }
    payload["serialNumber"] = _serial_number(payload)
    validate_sbom(payload)
    return payload


def write_sbom(sbom: JsonObject, path: Path) -> str:
    validate_sbom(sbom)
    path.parent.mkdir(parents=True, exist_ok=True)
    write_text_atomic(path, json.dumps(sbom, indent=2, sort_keys=True) + "\n")
    return file_sha256(path)


def load_and_validate_sbom(
    path: Path,
    *,
    artifact_root: Path | None = None,
    expected_environment: EnvironmentInfo | None = None,
    expected_distribution_paths: Sequence[Path] | None = None,
    expected_project_name: str = "agent-assure",
    expected_project_version: str = __version__,
) -> JsonObject:
    raw = _read_absolute_file_bounded(path, max_bytes=MAX_SBOM_BYTES, label="SBOM").data
    try:
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"SBOM is not strict UTF-8 JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("SBOM root must be an object")
    validate_sbom(
        payload,
        artifact_root=artifact_root,
        expected_environment=expected_environment,
        expected_distribution_paths=expected_distribution_paths,
        expected_project_name=expected_project_name,
        expected_project_version=expected_project_version,
    )
    return payload


def validate_sbom(
    sbom: Mapping[str, object],
    *,
    artifact_root: Path | None = None,
    expected_environment: EnvironmentInfo | None = None,
    expected_distribution_paths: Sequence[Path] | None = None,
    expected_project_name: str = "agent-assure",
    expected_project_version: str = __version__,
) -> None:
    """Validate security-relevant invariants of this generator's CDX profile.

    This is narrower than the complete upstream CycloneDX JSON Schema. The
    document names that schema for authoritative downstream validation.
    """

    if sbom.get("$schema") != CYCLONEDX_SCHEMA:
        raise ValueError("SBOM must identify the CycloneDX 1.5 JSON Schema")
    if sbom.get("bomFormat") != "CycloneDX" or sbom.get("specVersion") != "1.5":
        raise ValueError("SBOM must use CycloneDX 1.5")
    if sbom.get("version") != 1:
        raise ValueError("SBOM document version must be 1")
    metadata_value = sbom.get("metadata")
    if not isinstance(metadata_value, dict):
        raise ValueError("SBOM metadata must be an object")
    project_component = metadata_value.get("component")
    if not isinstance(project_component, dict):
        raise ValueError("SBOM metadata.component must be an object")
    project_ref = _required_string(project_component, "bom-ref", context="metadata.component")
    _validate_component(project_component, context="metadata.component")
    project_name = _validated_pypi_name(
        _required_string(project_component, "name", context="metadata.component")
    )
    project_version = _validated_version(
        _required_string(project_component, "version", context="metadata.component")
    )
    canonical_project_ref = _package_ref(project_name, project_version)
    if (
        project_ref != canonical_project_ref
        or project_component.get("purl") != canonical_project_ref
    ):
        raise ValueError("SBOM project bom-ref and purl must match its canonical package identity")
    metadata_properties = _properties_by_name(
        metadata_value.get("properties"), context="metadata.properties"
    )
    if metadata_properties.get("agent-assure:sbom-profile") != [SBOM_PROFILE]:
        raise ValueError("SBOM profile marker is missing or ambiguous")
    components_value = sbom.get("components")
    if not isinstance(components_value, list):
        raise ValueError("SBOM components must be an array")
    references = {project_ref}
    release_paths: dict[str, str] = {}
    component_properties_by_ref: dict[str, dict[str, list[str]]] = {}
    actual_package_refs: dict[tuple[str, str], str] = {}
    for index, component_value in enumerate(components_value):
        if not isinstance(component_value, dict):
            raise ValueError(f"components[{index}] must be an object")
        context = f"components[{index}]"
        _validate_component(component_value, context=context)
        component_ref = _required_string(component_value, "bom-ref", context=context)
        if component_ref in references:
            raise ValueError(f"duplicate SBOM bom-ref: {component_ref}")
        references.add(component_ref)
        component_properties = _properties_by_name(
            component_value.get("properties"), context=f"{context}.properties"
        )
        component_properties_by_ref[component_ref] = component_properties
        if component_value.get("type") == "library":
            package_name = _validated_pypi_name(
                _required_string(component_value, "name", context=context)
            )
            package_version = _validated_version(
                _required_string(component_value, "version", context=context)
            )
            coordinate = (package_name, package_version)
            if coordinate in actual_package_refs:
                raise ValueError(f"duplicate SBOM package coordinate: {coordinate}")
            actual_package_refs[coordinate] = component_ref
            canonical_ref = _package_ref(package_name, package_version)
            if component_ref != canonical_ref or component_value.get("purl") != canonical_ref:
                raise ValueError(
                    f"{context} bom-ref and purl must match its canonical package identity"
                )
        if component_value.get("type") == "file":
            paths = component_properties.get("agent-assure:release-path", [])
            if len(paths) != 1:
                raise ValueError(f"{context} must have exactly one release-path property")
            canonical_path = _validated_relative_path(paths[0])
            if (
                component_ref != f"file:{canonical_path}"
                or component_value.get("name") != PurePosixPath(canonical_path).name
            ):
                raise ValueError(f"{context} identity does not match its release path")
            release_paths[component_ref] = paths[0]

    dependencies_value = sbom.get("dependencies")
    if not isinstance(dependencies_value, list):
        raise ValueError("SBOM dependencies must be an array")
    dependency_refs: set[str] = set()
    dependency_graph: dict[str, list[str]] = {}
    for index, dependency_value in enumerate(dependencies_value):
        if not isinstance(dependency_value, dict):
            raise ValueError(f"dependencies[{index}] must be an object")
        ref = _required_string(dependency_value, "ref", context=f"dependencies[{index}]")
        if ref not in references:
            raise ValueError(f"dependency ref is not a component: {ref}")
        if ref in dependency_refs:
            raise ValueError(f"duplicate dependency entry: {ref}")
        dependency_refs.add(ref)
        depends_on = dependency_value.get("dependsOn", [])
        if not isinstance(depends_on, list) or not all(
            isinstance(item, str) and item for item in depends_on
        ):
            raise ValueError(f"dependencies[{index}].dependsOn must be a string array")
        if depends_on != sorted(set(depends_on)):
            raise ValueError(f"dependencies[{index}].dependsOn must be sorted and unique")
        if ref in depends_on:
            raise ValueError(f"dependency entry cannot depend on itself: {ref}")
        unknown = sorted(set(depends_on) - references)
        if unknown:
            raise ValueError(f"dependency entry references unknown components: {unknown}")
        dependency_graph[ref] = depends_on

    graph_status = metadata_properties.get("agent-assure:dependency-graph-status")
    if graph_status not in (
        ["unavailable"],
        ["digest-verified-pip-compile-annotations"],
    ):
        raise ValueError("SBOM dependency graph status is missing or unsupported")
    if project_ref not in dependency_refs:
        raise ValueError("SBOM dependency graph must contain the project root")
    direct_scope_labels = {
        "runtime-direct",
        "optional-direct",
        "development-direct",
        "build-direct",
    }
    direct_refs = {
        ref
        for ref, properties in component_properties_by_ref.items()
        if properties.get("agent-assure:dependency-scope", [None])[0] in direct_scope_labels
    }
    locked_refs = {
        ref
        for ref, properties in component_properties_by_ref.items()
        if properties.get("agent-assure:component-hash-evidence")
        == ["lockfile-approved-distribution-artifact-set"]
    }
    if graph_status == ["unavailable"]:
        if dependency_graph != {project_ref: []}:
            raise ValueError(
                "an unavailable SBOM dependency graph must contain only an empty project root"
            )
    else:
        expected_graph_refs = {project_ref, *locked_refs}
        if dependency_refs != expected_graph_refs:
            raise ValueError(
                "SBOM dependency graph must contain the project root and every "
                "lock-verified component"
            )
        if dependency_graph[project_ref] != sorted(direct_refs):
            raise ValueError("SBOM project dependency edges do not match direct dependency scopes")
        if any(
            child not in locked_refs
            for depends_on in dependency_graph.values()
            for child in depends_on
        ):
            raise ValueError("SBOM dependency edges must target lock-verified components")

    expected_compositions = [
        {
            "aggregate": "unknown",
            "assemblies": [project_ref],
            "dependencies": [project_ref],
        }
    ]
    if sbom.get("compositions") != expected_compositions:
        raise ValueError("SBOM composition must bind the project assembly and dependency root")

    if expected_environment is not None:
        expected_packages = _validated_installed_packages(
            expected_environment.installed_packages,
            project_name=project_name,
        )
        expected_package_refs = {
            (_pypi_name(package.name), package.version): _package_ref(
                _pypi_name(package.name), package.version
            )
            for package in expected_packages
        }
        if actual_package_refs != expected_package_refs:
            raise ValueError(
                "SBOM package components do not exactly match the trusted build environment"
            )
        if metadata_properties.get("agent-assure:python-version") != [
            expected_environment.python_version
        ]:
            raise ValueError("SBOM Python version does not match the trusted build environment")
        expected_lock_pair = (
            expected_environment.lockfile_path,
            expected_environment.lockfile_digest,
        )
        actual_lock_pair = (
            _singular_property(
                metadata_properties,
                "agent-assure:dependency-lock-path",
            ),
            _singular_property(
                metadata_properties,
                "agent-assure:dependency-lock-sha256",
            ),
        )
        if actual_lock_pair != expected_lock_pair:
            raise ValueError("SBOM lock evidence does not match the trusted build environment")
        if artifact_root is None:
            raise ValueError("artifact_root is required with a trusted build environment")
        if expected_distribution_paths is None:
            raise ValueError(
                "expected_distribution_paths are required with a trusted build environment"
            )
        expected_sbom = build_sbom(
            expected_environment,
            project_name=expected_project_name,
            project_version=expected_project_version,
            distribution_paths=tuple(expected_distribution_paths),
            project_root=artifact_root,
        )
        if dict(sbom) != expected_sbom:
            raise ValueError(
                "persisted SBOM does not exactly match reconstruction from trusted release inputs"
            )
    root_properties = _properties_by_name(sbom.get("properties"), context="properties")
    if root_properties.get("agent-assure:vulnerability-analysis-status") != ["not-performed"]:
        raise ValueError("SBOM must disclose that vulnerability analysis was not performed")
    if root_properties.get("agent-assure:vulnerability-status") != ["unknown"]:
        raise ValueError("SBOM vulnerability status must remain unknown without audit evidence")
    if "vulnerabilities" in sbom:
        raise ValueError("this SBOM profile cannot emit unauthenticated vulnerability assertions")
    serial = sbom.get("serialNumber")
    if not isinstance(serial, str):
        raise ValueError("SBOM serialNumber must be a string")
    unsigned = dict(sbom)
    unsigned.pop("serialNumber", None)
    if serial != _serial_number(unsigned):
        raise ValueError("SBOM serialNumber does not match its canonical content")
    if artifact_root is not None:
        _validate_local_evidence(
            sbom=sbom,
            metadata_properties=metadata_properties,
            release_paths=release_paths,
            artifact_root=artifact_root,
        )


def _package_component(
    package: InstalledPackage,
    *,
    lock_package: _LockedPackage | None,
    lock_path: str | None,
    scope_label: tuple[str, str] | None,
    license_expression: str | None,
) -> JsonObject:
    pypi_name = _validated_pypi_name(package.name)
    component: JsonObject = {
        "type": "library",
        "name": package.name,
        "version": package.version,
        "bom-ref": _package_ref(pypi_name, package.version),
        "purl": _package_ref(pypi_name, package.version),
    }
    properties: list[JsonObject] = []
    if scope_label is None:
        properties.append({"name": "agent-assure:dependency-scope-evidence", "value": "unknown"})
    else:
        scope, label = scope_label
        component["scope"] = scope
        properties.append({"name": "agent-assure:dependency-scope", "value": label})
        properties.append(
            {
                "name": "agent-assure:dependency-scope-evidence",
                "value": "digest-verified-lock-graph-and-pyproject",
            }
        )
    if lock_package is None:
        properties.append({"name": "agent-assure:component-hash-evidence", "value": "unknown"})
    else:
        component["hashes"] = [
            {"alg": "SHA-256", "content": digest} for digest in lock_package.hashes
        ]
        properties.extend(
            [
                {
                    "name": "agent-assure:component-hash-evidence",
                    "value": "lockfile-approved-distribution-artifact-set",
                },
                {
                    "name": "agent-assure:component-hash-installed-artifact",
                    "value": "not-identified",
                },
                {
                    "name": "agent-assure:component-hash-source",
                    "value": lock_path or "unknown",
                },
            ]
        )
    normalized_license = _validated_license_expression(license_expression)
    if normalized_license is None:
        properties.append({"name": "agent-assure:license-evidence", "value": "unknown"})
    else:
        component["licenses"] = [{"expression": normalized_license}]
        properties.append(
            {
                "name": "agent-assure:license-evidence",
                "value": "installed-core-metadata-license-expression",
            }
        )
    properties.append({"name": "agent-assure:supplier-evidence", "value": "unknown"})
    component["properties"] = _sorted_properties(properties)
    return component


def _project_component(
    *,
    project_name: str,
    project_version: str,
    project_ref: str,
    project_metadata: _ProjectMetadata | None,
) -> JsonObject:
    component: JsonObject = {
        "type": "application",
        "name": project_name,
        "version": project_version,
        "scope": "required",
        "bom-ref": project_ref,
        "purl": project_ref,
    }
    properties: list[JsonObject] = [{"name": "agent-assure:supplier-evidence", "value": "unknown"}]
    if project_metadata is None:
        properties.append({"name": "agent-assure:license-evidence", "value": "unknown"})
    else:
        if project_metadata.authors:
            component["author"] = ", ".join(project_metadata.authors)
        if project_metadata.license_value is None:
            properties.append({"name": "agent-assure:license-evidence", "value": "unknown"})
        elif project_metadata.license_is_expression:
            component["licenses"] = [{"expression": project_metadata.license_value}]
            properties.append(
                {"name": "agent-assure:license-evidence", "value": "pyproject-license-expression"}
            )
        else:
            component["licenses"] = [{"license": {"name": project_metadata.license_value}}]
            properties.append(
                {"name": "agent-assure:license-evidence", "value": "pyproject-license-text"}
            )
    component["properties"] = _sorted_properties(properties)
    return component


def _file_component(path: Path, *, project_root: Path | None) -> JsonObject:
    display_path = _display_path(path, project_root)
    if project_root is None:
        snapshot = _read_absolute_file_bounded(
            path,
            max_bytes=MAX_RELEASE_ARTIFACT_BYTES,
            label="distribution artifact",
        )
    else:
        snapshot = read_file_bounded_at(
            Path(os.path.abspath(project_root)),
            display_path,
            max_bytes=MAX_RELEASE_ARTIFACT_BYTES,
            label="distribution artifact",
        )
    return {
        "type": "file",
        "name": PurePosixPath(display_path).name,
        "scope": "required",
        "bom-ref": f"file:{display_path}",
        "properties": [
            {
                "name": "agent-assure:component-hash-evidence",
                "value": "exact-local-artifact-bytes",
            },
            {"name": "agent-assure:release-path", "value": display_path},
        ],
        "hashes": [{"alg": "SHA-256", "content": snapshot.sha256}],
    }


def _metadata_properties(
    *,
    environment: EnvironmentInfo,
    lock_evidence: _LockEvidence | None,
    components: Sequence[JsonObject],
) -> list[JsonObject]:
    license_known = sum("licenses" in component for component in components)
    hash_known = sum("hashes" in component for component in components)
    properties: list[JsonObject] = [
        {"name": "agent-assure:sbom-profile", "value": SBOM_PROFILE},
        {
            "name": "agent-assure:sbom-scope",
            "value": "local release build environment and exact built distribution files",
        },
        {"name": "agent-assure:python-version", "value": environment.python_version},
        {
            "name": "agent-assure:dependency-graph-status",
            "value": (
                "digest-verified-pip-compile-annotations"
                if lock_evidence is not None
                else "unavailable"
            ),
        },
        {
            "name": "agent-assure:component-hash-coverage",
            "value": f"{hash_known}/{len(components)}-environment-components",
        },
        {
            "name": "agent-assure:license-coverage",
            "value": f"{license_known}/{len(components)}-environment-components",
        },
        {"name": "agent-assure:supplier-data-status", "value": "unknown"},
    ]
    if lock_evidence is not None:
        properties.extend(
            [
                {"name": "agent-assure:dependency-lock-path", "value": lock_evidence.relative_path},
                {"name": "agent-assure:dependency-lock-sha256", "value": lock_evidence.digest},
                {
                    "name": "agent-assure:pep508-marker-environment",
                    "value": _serialized_marker_environment(environment),
                },
            ]
        )
    else:
        properties.append({"name": "agent-assure:dependency-lock-status", "value": "unavailable"})
    return _sorted_properties(properties)


def _serialized_marker_environment(environment: EnvironmentInfo) -> str:
    try:
        from packaging.markers import default_environment
        from packaging.version import InvalidVersion, Version
    except ImportError as exc:  # pragma: no cover - release lock includes packaging
        raise ValueError("packaging is required to capture the PEP 508 marker environment") from exc
    try:
        python_version = Version(environment.python_version)
    except InvalidVersion as exc:
        raise ValueError("environment Python version is not valid PEP 440") from exc
    if len(python_version.release) < 2:
        raise ValueError("environment Python version must include major and minor components")
    current = cast(Mapping[str, str], default_environment())
    missing_keys = sorted(_PEP508_MARKER_ENVIRONMENT_KEYS - current.keys())
    if missing_keys:
        raise ValueError(f"PEP 508 marker environment is incomplete: {missing_keys}")
    captured = {key: current[key] for key in _PEP508_MARKER_ENVIRONMENT_KEYS}
    normalized_python = str(python_version)
    captured["python_full_version"] = normalized_python
    captured["python_version"] = ".".join(str(part) for part in python_version.release[:2])
    if captured["implementation_name"] == "cpython":
        captured["implementation_version"] = normalized_python
    if any(
        not isinstance(value, str)
        or not value
        or len(value) > 512
        or _CONTROL_CHARACTER_RE.search(value)
        for value in captured.values()
    ):
        raise ValueError("PEP 508 marker environment contains an invalid value")
    return json.dumps(captured, sort_keys=True, separators=(",", ":"))


def _validated_installed_packages(
    packages: Sequence[InstalledPackage], *, project_name: str
) -> tuple[InstalledPackage, ...]:
    result: list[InstalledPackage] = []
    seen_names: set[str] = set()
    for package in packages:
        normalized = _validated_pypi_name(package.name)
        _validated_version(package.version)
        if normalized == project_name:
            continue
        if normalized in seen_names:
            raise ValueError(f"duplicate installed package name: {normalized}")
        seen_names.add(normalized)
        result.append(package)
    return tuple(sorted(result, key=lambda item: (_pypi_name(item.name), item.version, item.name)))


def _load_lock_evidence(
    environment: EnvironmentInfo, *, project_root: Path | None
) -> _LockEvidence | None:
    lock_path = environment.lockfile_path
    lock_digest = environment.lockfile_digest
    if lock_path is None and lock_digest is None:
        return None
    if lock_path is None or lock_digest is None:
        raise ValueError("environment lockfile path and digest must be present together")
    if project_root is None:
        raise ValueError("project_root is required to verify environment lockfile evidence")
    relative_path = _validated_relative_path(lock_path)
    root = Path(os.path.abspath(project_root))
    snapshot = read_file_bounded_at(
        root,
        relative_path,
        max_bytes=MAX_SBOM_BYTES,
        label="environment lockfile",
    )
    actual_digest = snapshot.sha256
    if actual_digest != lock_digest:
        raise ValueError("environment lockfile digest does not match local bytes")
    if not (
        PurePosixPath(relative_path).name.startswith("requirements")
        and PurePosixPath(relative_path).suffix in {".lock", ".txt"}
    ):
        return None
    return _LockEvidence(
        relative_path=relative_path,
        digest=actual_digest,
        packages=_parse_hashed_requirements_lock(
            snapshot.data,
            path_label=relative_path,
        ),
    )


def _parse_hashed_requirements_lock(
    raw: bytes, *, path_label: str
) -> Mapping[tuple[str, str], _LockedPackage]:
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError("dependency lock is not UTF-8") from exc
    records: dict[tuple[str, str], tuple[str, set[str], set[str], str | None]] = {}
    current: tuple[str, str] | None = None
    collecting_hashes = False
    collecting_via = False
    for line_number, line in enumerate(lines, start=1):
        requirement = _LOCK_REQUIREMENT_RE.fullmatch(line)
        if requirement is not None:
            name = requirement.group(1)
            normalized = _validated_pypi_name(name)
            version = requirement.group(2)
            _validated_version(version)
            current = (normalized, version)
            if current in records:
                raise ValueError(
                    f"duplicate dependency lock coordinate at {path_label}:{line_number}"
                )
            marker = requirement.group(3)
            records[current] = (
                name,
                set(),
                set(),
                _validated_lock_marker(marker) if marker is not None else None,
            )
            collecting_hashes = True
            collecting_via = False
            continue
        hash_match = _LOCK_HASH_RE.fullmatch(line)
        if hash_match is not None:
            if current is None or not collecting_hashes:
                raise ValueError(f"orphan dependency hash at {path_label}:{line_number}")
            records[current][1].add(hash_match.group(1).lower())
            collecting_via = False
            continue
        stripped = line.strip()
        if stripped == "# via":
            if current is None:
                raise ValueError(f"orphan dependency relationship at {path_label}:{line_number}")
            collecting_hashes = False
            collecting_via = True
            continue
        if stripped.startswith("# via "):
            if current is None:
                raise ValueError(f"orphan dependency relationship at {path_label}:{line_number}")
            collecting_hashes = False
            parent = _parent_package_name(stripped[len("# via ") :])
            if parent is not None:
                records[current][2].add(parent)
            collecting_via = False
            continue
        if collecting_via and stripped.startswith("#   "):
            parent = _parent_package_name(stripped[len("#   ") :])
            if parent is not None and current is not None:
                records[current][2].add(parent)
            continue
        if not stripped:
            current = None
            collecting_hashes = False
            collecting_via = False
            continue
        if stripped.startswith("#"):
            collecting_hashes = False
            collecting_via = False
            continue
        raise ValueError(f"unsupported dependency lock entry at {path_label}:{line_number}")
    if not records:
        raise ValueError("dependency lock contains no exact package pins")
    result: dict[tuple[str, str], _LockedPackage] = {}
    for coordinate, (name, hashes, parents, marker) in sorted(records.items()):
        if not hashes:
            raise ValueError(
                "dependency lock entry has no SHA-256 archive hashes: "
                f"{coordinate[0]}=={coordinate[1]}"
            )
        result[coordinate] = _LockedPackage(
            name=name,
            version=coordinate[1],
            hashes=tuple(sorted(hashes)),
            parents=tuple(sorted(parents)),
            marker=marker,
        )
    return result


def _validated_lock_marker(value: str) -> str:
    marker = value.strip()
    if not marker or len(marker) > 2048 or _CONTROL_CHARACTER_RE.search(marker):
        raise ValueError("dependency lock marker is empty or invalid")
    if _UNSUPPORTED_PEP508_MARKER_VARIABLE_RE.search(marker):
        raise ValueError("dependency lock marker uses an unsupported or volatile variable")
    try:
        from packaging.markers import InvalidMarker, Marker
    except ImportError as exc:  # pragma: no cover - release lock includes packaging
        raise ValueError("packaging is required to validate dependency lock markers") from exc
    try:
        Marker(marker)
    except InvalidMarker as exc:
        raise ValueError(f"dependency lock marker is invalid: {marker!r}") from exc
    return marker


def _validated_marker_environment(
    metadata_properties: Mapping[str, list[str]],
) -> Mapping[str, str]:
    serialized_values = metadata_properties.get("agent-assure:pep508-marker-environment", [])
    if len(serialized_values) != 1 or len(serialized_values[0]) > 8192:
        raise ValueError("PEP 508 marker environment must be singular and bounded")
    try:
        payload = json.loads(serialized_values[0], object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as exc:
        raise ValueError("PEP 508 marker environment is not valid JSON") from exc
    if not isinstance(payload, dict) or set(payload) != _PEP508_MARKER_ENVIRONMENT_KEYS:
        raise ValueError("PEP 508 marker environment has missing or unsupported fields")
    marker_environment: dict[str, str] = {}
    for key in sorted(_PEP508_MARKER_ENVIRONMENT_KEYS):
        value = payload[key]
        if (
            not isinstance(value, str)
            or not value
            or len(value) > 512
            or _CONTROL_CHARACTER_RE.search(value)
        ):
            raise ValueError("PEP 508 marker environment contains an invalid value")
        marker_environment[key] = value
    python_versions = metadata_properties.get("agent-assure:python-version", [])
    if len(python_versions) != 1:
        raise ValueError("SBOM Python version must be singular with lock evidence")
    try:
        from packaging.version import InvalidVersion, Version
    except ImportError as exc:  # pragma: no cover - release lock includes packaging
        raise ValueError(
            "packaging is required to validate the PEP 508 marker environment"
        ) from exc
    try:
        expected_python = Version(python_versions[0])
    except InvalidVersion as exc:
        raise ValueError("SBOM Python version is not valid PEP 440") from exc
    if len(expected_python.release) < 2:
        raise ValueError("SBOM Python version must include major and minor components")
    expected_minor = ".".join(str(part) for part in expected_python.release[:2])
    if (
        marker_environment["python_full_version"] != str(expected_python)
        or marker_environment["python_version"] != expected_minor
    ):
        raise ValueError("PEP 508 marker environment disagrees with the SBOM Python version")
    return marker_environment


def _lock_marker_applies(marker: str | None, environment: Mapping[str, str]) -> bool:
    if marker is None:
        return True
    try:
        from packaging.markers import InvalidMarker, Marker, UndefinedEnvironmentName
    except ImportError as exc:  # pragma: no cover - release lock includes packaging
        raise ValueError("packaging is required to evaluate dependency lock markers") from exc
    try:
        return Marker(marker).evaluate(environment=dict(environment))
    except (InvalidMarker, UndefinedEnvironmentName, KeyError) as exc:
        raise ValueError(f"dependency lock marker cannot be evaluated: {marker!r}") from exc


def _parent_package_name(value: str) -> str | None:
    candidate = value.strip()
    if not candidate or candidate.startswith("-"):
        return None
    candidate = candidate.split(" (", 1)[0]
    candidate = candidate.split("[", 1)[0]
    match = _REQUIREMENT_NAME_RE.match(candidate)
    if match is None:
        return None
    return _pypi_name(match.group(1))


def _match_lock_packages(
    installed_packages: Sequence[InstalledPackage],
    lock_evidence: _LockEvidence | None,
) -> dict[tuple[str, str], _LockedPackage]:
    if lock_evidence is None:
        return {}
    versions_by_name: dict[str, set[str]] = defaultdict(set)
    for name, version in lock_evidence.packages:
        versions_by_name[name].add(version)
    matches: dict[tuple[str, str], _LockedPackage] = {}
    for package in installed_packages:
        coordinate = (_pypi_name(package.name), package.version)
        match = lock_evidence.packages.get(coordinate)
        if match is not None:
            matches[coordinate] = match
            continue
        if coordinate[0] in versions_by_name:
            locked = ", ".join(sorted(versions_by_name[coordinate[0]]))
            raise ValueError(
                "installed package does not match verified lock: "
                f"{coordinate[0]}=={coordinate[1]} (locked: {locked})"
            )
    return matches


def _dependency_graph(
    *,
    installed_refs: Mapping[str, str],
    lock_matches: Mapping[tuple[str, str], _LockedPackage],
    project_name: str,
) -> Mapping[str, frozenset[str]]:
    children: dict[str, set[str]] = defaultdict(set)
    for (child_name, _version), package in lock_matches.items():
        for parent in package.parents:
            if parent == project_name:
                children[project_name].add(child_name)
            elif parent in installed_refs:
                children[parent].add(child_name)
    return {name: frozenset(values) for name, values in children.items()}


def _dependency_scopes(
    *,
    installed_names: frozenset[str],
    graph: Mapping[str, frozenset[str]],
    project_metadata: _ProjectMetadata | None,
    lock_evidence: _LockEvidence | None,
) -> Mapping[str, tuple[str, str]]:
    if project_metadata is None or lock_evidence is None:
        return {}
    runtime = _closure(project_metadata.runtime_roots & installed_names, graph)
    optional = _closure(project_metadata.optional_roots & installed_names, graph) - runtime
    development = _closure(project_metadata.development_roots & installed_names, graph)
    build = _closure(project_metadata.build_roots & installed_names, graph)
    result: dict[str, tuple[str, str]] = {}
    for name in installed_names:
        if name in runtime:
            label = (
                "runtime-direct" if name in project_metadata.runtime_roots else "runtime-transitive"
            )
            result[name] = ("required", label)
        elif name in optional:
            label = (
                "optional-direct"
                if name in project_metadata.optional_roots
                else "optional-transitive"
            )
            result[name] = ("optional", label)
        elif name in development:
            label = (
                "development-direct"
                if name in project_metadata.development_roots
                else "development-transitive"
            )
            result[name] = ("excluded", label)
        elif name in build:
            label = "build-direct" if name in project_metadata.build_roots else "build-transitive"
            result[name] = ("excluded", label)
        else:
            result[name] = ("excluded", "environment-only-unclassified")
    return result


def _closure(roots: frozenset[str], graph: Mapping[str, frozenset[str]]) -> set[str]:
    reached: set[str] = set()
    queue: deque[str] = deque(sorted(roots))
    while queue:
        current = queue.popleft()
        if current in reached:
            continue
        reached.add(current)
        queue.extend(sorted(graph.get(current, ())))
    return reached


def _cyclonedx_dependencies(
    *,
    project_ref: str,
    project_name: str,
    installed_refs: Mapping[str, str],
    graph: Mapping[str, frozenset[str]],
    project_metadata: _ProjectMetadata | None,
    lock_evidence: _LockEvidence | None,
) -> list[JsonObject]:
    if lock_evidence is None:
        return [{"ref": project_ref, "dependsOn": []}]
    direct_names: set[str] = set()
    if project_metadata is not None:
        direct_names.update(project_metadata.runtime_roots)
        direct_names.update(project_metadata.optional_roots)
        direct_names.update(project_metadata.development_roots)
        direct_names.update(project_metadata.build_roots)
    else:
        direct_names.update(graph.get(project_name, ()))
    dependencies: list[JsonObject] = [
        {
            "ref": project_ref,
            "dependsOn": sorted(
                installed_refs[name] for name in direct_names if name in installed_refs
            ),
        }
    ]
    locked_names = {coordinate[0] for coordinate in lock_evidence.packages}
    for name, ref in sorted(installed_refs.items(), key=lambda item: item[1]):
        if name not in locked_names:
            continue
        dependencies.append(
            {
                "ref": ref,
                "dependsOn": sorted(
                    installed_refs[child]
                    for child in graph.get(name, ())
                    if child in installed_refs
                ),
            }
        )
    return dependencies


def _load_project_metadata(
    project_root: Path | None, *, expected_name: str, expected_version: str
) -> _ProjectMetadata | None:
    if project_root is None:
        return None
    root = Path(os.path.abspath(project_root))
    try:
        snapshot = read_file_bounded_at(
            root,
            "pyproject.toml",
            max_bytes=MAX_PROJECT_METADATA_BYTES,
            label="project metadata",
        )
    except FileNotFoundError:
        return None
    try:
        payload = tomllib.loads(snapshot.data.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"pyproject.toml is invalid: {exc}") from exc
    project = payload.get("project")
    if not isinstance(project, dict):
        return None
    name = project.get("name")
    version = project.get("version")
    if not isinstance(name, str) or _pypi_name(name) != expected_name:
        raise ValueError("pyproject project name does not match the SBOM subject")
    if not isinstance(version, str) or version != expected_version:
        raise ValueError("pyproject project version does not match the SBOM subject")
    runtime = _requirement_names(project.get("dependencies"), context="project.dependencies")
    optional_table = project.get("optional-dependencies", {})
    if not isinstance(optional_table, dict):
        raise ValueError("project.optional-dependencies must be a table")
    development = _requirement_names(
        optional_table.get("dev", []), context="project.optional-dependencies.dev"
    )
    optional: set[str] = set()
    for group, requirements in optional_table.items():
        if group == "dev":
            continue
        optional.update(
            _requirement_names(requirements, context=f"project.optional-dependencies.{group}")
        )
    build_table = payload.get("build-system", {})
    if not isinstance(build_table, dict):
        raise ValueError("build-system must be a table")
    build = _requirement_names(build_table.get("requires", []), context="build-system.requires")
    authors_value = project.get("authors", [])
    if not isinstance(authors_value, list):
        raise ValueError("project.authors must be an array")
    authors: list[str] = []
    for item in authors_value:
        if not isinstance(item, dict):
            raise ValueError("project.authors entries must be tables")
        author_name = item.get("name")
        if isinstance(author_name, str) and _safe_metadata_text(author_name):
            authors.append(author_name.strip())
    license_value, license_is_expression = _project_license(project.get("license"))
    return _ProjectMetadata(
        name=name,
        version=version,
        runtime_roots=frozenset(runtime),
        optional_roots=frozenset(optional),
        development_roots=frozenset(development),
        build_roots=frozenset(build),
        authors=tuple(sorted(set(authors))),
        license_value=license_value,
        license_is_expression=license_is_expression,
    )


def _requirement_names(value: object, *, context: str) -> set[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{context} must be an array of strings")
    result: set[str] = set()
    for requirement in value:
        match = _REQUIREMENT_NAME_RE.match(requirement)
        if match is None:
            raise ValueError(f"cannot determine dependency name in {context}: {requirement!r}")
        result.add(_validated_pypi_name(match.group(1)))
    return result


def _project_license(value: object) -> tuple[str | None, bool]:
    if value is None:
        return None, False
    if isinstance(value, str):
        normalized = _safe_metadata_text(value)
        return (normalized, True) if normalized else (None, False)
    if not isinstance(value, dict):
        raise ValueError("project.license must be a string or table")
    text = value.get("text")
    if isinstance(text, str):
        normalized = _safe_metadata_text(text)
        return (normalized, False) if normalized else (None, False)
    return None, False


def _installed_license_expressions() -> dict[tuple[str, str], str]:
    result: dict[tuple[str, str], str] = {}
    conflicts: set[tuple[str, str]] = set()
    for distribution in metadata.distributions():
        try:
            metadata_get = getattr(distribution.metadata, "get", None)
            if not callable(metadata_get):
                continue
            name = metadata_get("Name")
            version = distribution.version
            expression = metadata_get("License-Expression")
        except (KeyError, ValueError):
            continue
        if not isinstance(name, str) or not isinstance(version, str):
            continue
        normalized_expression = _validated_license_expression(expression)
        if normalized_expression is None:
            continue
        try:
            coordinate = (_validated_pypi_name(name), version)
        except ValueError:
            continue
        previous = result.get(coordinate)
        if previous is not None and previous != normalized_expression:
            conflicts.add(coordinate)
        else:
            result[coordinate] = normalized_expression
    for coordinate in conflicts:
        result.pop(coordinate, None)
    return result


def _validated_license_expression(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    if not normalized or len(normalized) > 512 or _CONTROL_CHARACTER_RE.search(normalized):
        return None
    if normalized.lower() in {"unknown", "none", "n/a"}:
        return None
    return normalized


def _validate_component(component: Mapping[str, object], *, context: str) -> None:
    component_type = _required_string(component, "type", context=context)
    if component_type not in {"application", "library", "file"}:
        raise ValueError(f"{context}.type is unsupported by this SBOM profile")
    name = _required_string(component, "name", context=context)
    if _CONTROL_CHARACTER_RE.search(name):
        raise ValueError(f"{context}.name contains control characters")
    scope = component.get("scope")
    if scope is not None and scope not in {"required", "optional", "excluded"}:
        raise ValueError(f"{context}.scope is invalid")
    hashes = component.get("hashes")
    if hashes is not None:
        if not isinstance(hashes, list) or not hashes:
            raise ValueError(f"{context}.hashes must be a non-empty array")
        normalized: list[str] = []
        for index, hash_value in enumerate(hashes):
            if not isinstance(hash_value, dict):
                raise ValueError(f"{context}.hashes[{index}] must be an object")
            if hash_value.get("alg") != "SHA-256":
                raise ValueError(f"{context}.hashes[{index}] must use SHA-256")
            content = hash_value.get("content")
            if not isinstance(content, str) or _SHA256_RE.fullmatch(content) is None:
                raise ValueError(f"{context}.hashes[{index}] has an invalid digest")
            normalized.append(content)
        if normalized != sorted(set(normalized)):
            raise ValueError(f"{context}.hashes must be sorted and unique")
    _properties_by_name(component.get("properties"), context=f"{context}.properties")


def _validate_local_evidence(
    *,
    sbom: Mapping[str, object],
    metadata_properties: Mapping[str, list[str]],
    release_paths: Mapping[str, str],
    artifact_root: Path,
) -> None:
    root = Path(os.path.abspath(artifact_root))
    components = sbom.get("components")
    if not isinstance(components, list):
        raise ValueError("SBOM components must be an array")
    by_ref = {
        component["bom-ref"]: component
        for component in components
        if isinstance(component, dict) and isinstance(component.get("bom-ref"), str)
    }
    for component_ref, relative_path in release_paths.items():
        snapshot = read_file_bounded_at(
            root,
            _validated_relative_path(relative_path),
            max_bytes=MAX_RELEASE_ARTIFACT_BYTES,
            label="release artifact",
        )
        component = by_ref.get(component_ref)
        if not isinstance(component, dict):
            raise ValueError(f"release artifact component is missing: {component_ref}")
        hashes = component.get("hashes")
        if not isinstance(hashes, list):
            raise ValueError(f"release artifact hashes are missing: {relative_path}")
        expected = [
            item["content"]
            for item in hashes
            if isinstance(item, dict) and item.get("alg") == "SHA-256"
        ]
        if expected != [snapshot.sha256]:
            raise ValueError(f"release artifact digest mismatch: {relative_path}")
    lock_paths = metadata_properties.get("agent-assure:dependency-lock-path", [])
    lock_digests = metadata_properties.get("agent-assure:dependency-lock-sha256", [])
    if bool(lock_paths) != bool(lock_digests) or len(lock_paths) > 1 or len(lock_digests) > 1:
        raise ValueError("dependency lock path and digest evidence must be singular and paired")
    if lock_paths:
        if _SHA256_RE.fullmatch(lock_digests[0]) is None:
            raise ValueError("dependency lock digest is invalid")
        lock_snapshot = read_file_bounded_at(
            root,
            _validated_relative_path(lock_paths[0]),
            max_bytes=MAX_SBOM_BYTES,
            label="dependency lock",
        )
        if lock_snapshot.sha256 != lock_digests[0]:
            raise ValueError("dependency lock digest does not match local bytes")
        lock_evidence = _LockEvidence(
            relative_path=lock_paths[0],
            digest=lock_snapshot.sha256,
            packages=_parse_hashed_requirements_lock(
                lock_snapshot.data,
                path_label=lock_paths[0],
            ),
        )
        marker_environment = _validated_marker_environment(metadata_properties)
        metadata = sbom.get("metadata")
        if not isinstance(metadata, dict):
            raise ValueError("SBOM metadata must be an object")
        project_component = metadata.get("component")
        if not isinstance(project_component, dict):
            raise ValueError("SBOM metadata.component must be an object")
        project_name = _validated_pypi_name(
            _required_string(project_component, "name", context="metadata.component")
        )
        project_version = _validated_version(
            _required_string(project_component, "version", context="metadata.component")
        )
        project_ref = _required_string(
            project_component,
            "bom-ref",
            context="metadata.component",
        )
        project_metadata = _load_project_metadata(
            root,
            expected_name=project_name,
            expected_version=project_version,
        )
        installed_refs: dict[str, str] = {}
        lock_matches: dict[tuple[str, str], _LockedPackage] = {}
        for component in components:
            if not isinstance(component, dict) or component.get("type") != "library":
                continue
            name = _validated_pypi_name(
                _required_string(component, "name", context="library component")
            )
            version = _validated_version(
                _required_string(component, "version", context="library component")
            )
            ref = _required_string(component, "bom-ref", context="library component")
            if name in installed_refs:
                raise ValueError(f"duplicate installed package name in SBOM: {name}")
            installed_refs[name] = ref
            match = lock_evidence.packages.get((name, version))
            if match is not None:
                if not _lock_marker_applies(match.marker, marker_environment):
                    raise ValueError(
                        "SBOM component is inapplicable to the captured PEP 508 "
                        f"marker environment: {name}=={version}"
                    )
                lock_matches[(name, version)] = match
            elif any(locked_name == name for locked_name, _ in lock_evidence.packages):
                raise ValueError(
                    f"SBOM component version does not match verified lock: {name}=={version}"
                )
        if project_metadata is not None:
            applicable_direct_names = {
                name
                for (name, _), package in lock_evidence.packages.items()
                if project_name in package.parents
                and _lock_marker_applies(package.marker, marker_environment)
            }
            missing_runtime_locks = sorted(project_metadata.runtime_roots - applicable_direct_names)
            if missing_runtime_locks:
                raise ValueError(
                    "verified lock omits declared project runtime dependencies: "
                    f"{missing_runtime_locks}"
                )
            # Optional, development, and build roots are selected by a project-parent
            # annotation in this digest-verified lock profile. Runtime roots must
            # always have that direct binding, while marker-false pins remain outside
            # the active closure.
            direct_names = set(project_metadata.runtime_roots)
            direct_names.update(project_metadata.optional_roots)
            direct_names.update(project_metadata.development_roots)
            direct_names.update(project_metadata.build_roots)
            direct_names.intersection_update(applicable_direct_names)
            lock_children: dict[str, set[str]] = defaultdict(set)
            for (child_name, _), package in lock_evidence.packages.items():
                if not _lock_marker_applies(package.marker, marker_environment):
                    continue
                for parent in package.parents:
                    lock_children[parent].add(child_name)
            required_names = _closure(
                frozenset(direct_names),
                {name: frozenset(children) for name, children in lock_children.items()},
            )
            missing_names = sorted(required_names - installed_refs.keys())
            if missing_names:
                raise ValueError(
                    "SBOM omits project dependency components reachable in the verified "
                    f"lockfile: {missing_names}"
                )
        graph = _dependency_graph(
            installed_refs=installed_refs,
            lock_matches=lock_matches,
            project_name=project_name,
        )
        expected_dependencies = _cyclonedx_dependencies(
            project_ref=project_ref,
            project_name=project_name,
            installed_refs=installed_refs,
            graph=graph,
            project_metadata=project_metadata,
            lock_evidence=lock_evidence,
        )
        if sbom.get("dependencies") != expected_dependencies:
            raise ValueError(
                "SBOM dependency graph does not match the digest-verified local lockfile"
            )
        for component in components:
            if not isinstance(component, dict) or component.get("type") != "library":
                continue
            name = _validated_pypi_name(
                _required_string(component, "name", context="library component")
            )
            version = _validated_version(
                _required_string(component, "version", context="library component")
            )
            match = lock_matches.get((name, version))
            if match is None:
                continue
            expected_hashes = [{"alg": "SHA-256", "content": digest} for digest in match.hashes]
            if component.get("hashes") != expected_hashes:
                raise ValueError(
                    f"SBOM component hashes do not match the verified lockfile: {name}=={version}"
                )
            properties = _properties_by_name(
                component.get("properties"),
                context=f"library component {name!r}.properties",
            )
            if properties.get("agent-assure:component-hash-evidence") != [
                "lockfile-approved-distribution-artifact-set"
            ] or properties.get("agent-assure:component-hash-source") != [lock_paths[0]]:
                raise ValueError(
                    f"SBOM component hash provenance does not match the verified lockfile: {name}"
                )


def _read_absolute_file_bounded(path: Path, *, max_bytes: int, label: str) -> BoundedFileContents:
    absolute = Path(os.path.abspath(path))
    if not absolute.anchor:
        raise ValueError(f"{label} path must be absolute after normalization")
    root = Path(absolute.anchor)
    return read_file_bounded_at(
        root,
        absolute.relative_to(root),
        max_bytes=max_bytes,
        label=label,
    )


def _properties_by_name(value: object, *, context: str) -> dict[str, list[str]]:
    if not isinstance(value, list):
        raise ValueError(f"{context} must be an array")
    result: dict[str, list[str]] = defaultdict(list)
    for index, property_value in enumerate(value):
        if not isinstance(property_value, dict):
            raise ValueError(f"{context}[{index}] must be an object")
        name = property_value.get("name")
        property_text = property_value.get("value")
        if not isinstance(name, str) or not name or _CONTROL_CHARACTER_RE.search(name):
            raise ValueError(f"{context}[{index}].name is invalid")
        if not isinstance(property_text, str) or _CONTROL_CHARACTER_RE.search(property_text):
            raise ValueError(f"{context}[{index}].value is invalid")
        result[name].append(property_text)
    return dict(result)


def _singular_property(properties: Mapping[str, list[str]], name: str) -> str | None:
    values = properties.get(name, [])
    if len(values) > 1:
        raise ValueError(f"SBOM property must be singular: {name}")
    return values[0] if values else None


def _required_string(value: Mapping[str, object], key: str, *, context: str) -> str:
    field = value.get(key)
    if not isinstance(field, str) or not field:
        raise ValueError(f"{context}.{key} must be a non-empty string")
    return field


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> JsonObject:
    result: JsonObject = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _sorted_properties(properties: Sequence[JsonObject]) -> list[JsonObject]:
    return sorted(properties, key=lambda item: (str(item["name"]), str(item["value"])))


def _display_path(path: Path, project_root: Path | None) -> str:
    if project_root is None:
        return Path(os.path.abspath(path)).as_posix()
    absolute = Path(os.path.abspath(path))
    root = Path(os.path.abspath(project_root))
    try:
        return absolute.relative_to(root).as_posix()
    except ValueError as exc:
        raise ValueError(f"SBOM artifact path is outside project_root: {absolute}") from exc


def _validated_relative_path(value: str) -> str:
    if not value or chr(92) in value or _CONTROL_CHARACTER_RE.search(value):
        raise ValueError("evidence path must be a non-empty canonical POSIX path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("evidence path must be relative and must not traverse parents")
    if ":" in path.parts[0]:
        raise ValueError("evidence path must not contain a drive prefix")
    return path.as_posix()


def _validated_pypi_name(name: str) -> str:
    if not isinstance(name, str) or _PACKAGE_NAME_RE.fullmatch(name) is None:
        raise ValueError(f"invalid Python distribution name: {name!r}")
    normalized = _pypi_name(name)
    if _NORMALIZED_PACKAGE_NAME_RE.fullmatch(normalized) is None:
        raise ValueError(f"invalid normalized Python distribution name: {name!r}")
    return normalized


def _validated_version(version: str) -> str:
    if (
        not isinstance(version, str)
        or not version
        or len(version) > 256
        or _CONTROL_CHARACTER_RE.search(version)
    ):
        raise ValueError(f"invalid Python distribution version: {version!r}")
    return version


def _safe_metadata_text(value: str) -> str | None:
    normalized = value.strip()
    if not normalized or len(normalized) > 512 or _CONTROL_CHARACTER_RE.search(normalized):
        return None
    return normalized


def _package_ref(name: str, version: str) -> str:
    _validated_version(version)
    return f"pkg:pypi/{name}@{quote(version, safe='.-_~')}"


def _pypi_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _serial_number(payload: Mapping[str, object]) -> str:
    digest = sha256_hexdigest(dict(payload))
    return f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, f'agent-assure-sbom:{digest}')}"
