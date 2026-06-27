from __future__ import annotations

import json
import re
import uuid
from pathlib import Path

from agent_assure import __version__
from agent_assure.artifact_io import file_sha256
from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.schema.environment import EnvironmentInfo, InstalledPackage

JsonObject = dict[str, object]


def build_sbom(
    environment: EnvironmentInfo,
    *,
    project_name: str = "agent-assure",
    project_version: str = __version__,
    distribution_paths: tuple[Path, ...] = (),
    project_root: Path | None = None,
) -> JsonObject:
    project_pypi_name = _pypi_name(project_name)
    components = [
        _package_component(package)
        for package in environment.installed_packages
        if _pypi_name(package.name) != project_pypi_name
    ]
    components.extend(
        _file_component(path, project_root=project_root) for path in sorted(distribution_paths)
    )
    payload: JsonObject = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "tools": [
                {
                    "vendor": "ACB Labs",
                    "name": project_name,
                    "version": project_version,
                }
            ],
            "component": {
                "type": "application",
                "name": project_name,
                "version": project_version,
                "bom-ref": f"pkg:pypi/{_pypi_name(project_name)}@{project_version}",
                "purl": f"pkg:pypi/{_pypi_name(project_name)}@{project_version}",
            },
            "properties": [
                {
                    "name": "agent-assure:sbom-scope",
                    "value": "local release environment and built distribution files",
                },
                {
                    "name": "agent-assure:python-version",
                    "value": environment.python_version,
                },
            ],
        },
        "components": components,
    }
    payload["serialNumber"] = _serial_number(payload)
    return payload


def write_sbom(sbom: JsonObject, path: Path) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(sbom, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return file_sha256(path)


def _package_component(package: InstalledPackage) -> JsonObject:
    pypi_name = _pypi_name(package.name)
    return {
        "type": "library",
        "name": package.name,
        "version": package.version,
        "bom-ref": f"pkg:pypi/{pypi_name}@{package.version}",
        "purl": f"pkg:pypi/{pypi_name}@{package.version}",
    }


def _file_component(path: Path, *, project_root: Path | None) -> JsonObject:
    display_path = _display_path(path, project_root)
    return {
        "type": "file",
        "name": path.name,
        "bom-ref": f"file:{display_path}",
        "properties": [
            {
                "name": "agent-assure:release-path",
                "value": display_path,
            }
        ],
        "hashes": [
            {
                "alg": "SHA-256",
                "content": file_sha256(path),
            }
        ],
    }


def _display_path(path: Path, project_root: Path | None) -> str:
    if project_root is None:
        return path.as_posix()
    try:
        return path.resolve().relative_to(project_root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _pypi_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _serial_number(payload: JsonObject) -> str:
    digest = sha256_hexdigest(payload)
    return f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, f'agent-assure-sbom:{digest}')}"
