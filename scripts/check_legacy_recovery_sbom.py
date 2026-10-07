"""Validate the frozen v0.6.0 SBOM against its signed release manifest.

The v0.6.0 generator predates the current Agent Assure SBOM profile. This
standalone verifier intentionally uses only the Python standard library so the
recovery workflow can validate the historical bytes before installing code.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import uuid
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath

MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_ARTIFACT_BYTES = 128 * 1024 * 1024
MAX_COMPONENTS = 16_384
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_PACKAGE_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")


def validate_legacy_v060_release_sbom(
    *,
    sbom_path: Path,
    manifest_path: Path,
    artifact_root: Path,
    expected_version: str = "0.6.0",
) -> None:
    root = Path(os.path.abspath(artifact_root))
    manifest = _load_json(manifest_path, label="release manifest")
    if manifest.get("artifact_kind") != "release-artifact-manifest":
        raise ValueError("historical manifest has the wrong artifact_kind")
    if manifest.get("schema_version") != "0.6.0":
        raise ValueError("historical manifest must use schema_version 0.6.0")
    environment = manifest.get("environment")
    if not isinstance(environment, dict):
        raise ValueError("historical manifest environment must be an object")
    _require_exact_keys(
        environment,
        required={"artifact_kind", "schema_version", "platform", "python_version"},
        allowed={
            "artifact_kind",
            "schema_version",
            "platform",
            "python_version",
            "git_commit",
            "git_dirty",
            "lockfile_path",
            "lockfile_digest",
            "dependency_inventory_path",
            "dependency_inventory_digest",
            "installed_packages",
        },
        owner="historical environment",
    )
    if (
        environment.get("artifact_kind") != "environment-info"
        or environment.get("schema_version") != "0.6.0"
    ):
        raise ValueError("historical manifest environment identity is invalid")

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) > MAX_COMPONENTS:
        raise ValueError("historical manifest artifacts must be a bounded array")
    by_role: dict[str, Mapping[str, object]] = {}
    seen_paths: set[str] = set()
    for index, value in enumerate(artifacts):
        if not isinstance(value, dict):
            raise ValueError(f"historical manifest artifact[{index}] must be an object")
        role = _required_ascii(value, "role", owner=f"manifest artifact[{index}]")
        relative = _validated_relative_path(
            _required_ascii(value, "path", owner=f"manifest artifact[{index}]")
        )
        digest = _required_ascii(value, "sha256", owner=f"manifest artifact[{index}]")
        if _SHA256_RE.fullmatch(digest) is None:
            raise ValueError(f"manifest artifact[{index}] has an invalid SHA-256 digest")
        if role in by_role or relative in seen_paths:
            raise ValueError("historical manifest roles and paths must be unique")
        by_role[role] = value
        seen_paths.add(relative)

    sbom_artifact = _required_role(by_role, "sbom")
    sbom_relative = _validated_relative_path(str(sbom_artifact["path"]))
    expected_sbom_path = _path_at(root, sbom_relative)
    if Path(os.path.abspath(sbom_path)) != expected_sbom_path:
        raise ValueError("SBOM path does not match the historical manifest")
    sbom_bytes = _read_bytes(expected_sbom_path, max_bytes=MAX_JSON_BYTES, label="SBOM")
    if hashlib.sha256(sbom_bytes).hexdigest() != sbom_artifact["sha256"]:
        raise ValueError("historical SBOM digest does not match the release manifest")
    sbom = _loads_json(sbom_bytes, label="SBOM")

    distribution_paths: list[str] = []
    for role in ("python-wheel", "source-distribution"):
        artifact = _required_role(by_role, role)
        relative = _validated_relative_path(str(artifact["path"]))
        snapshot = _read_bytes(
            _path_at(root, relative),
            max_bytes=MAX_ARTIFACT_BYTES,
            label=role,
        )
        if hashlib.sha256(snapshot).hexdigest() != artifact["sha256"]:
            raise ValueError(f"historical {role} digest does not match the release manifest")
        distribution_paths.append(relative)

    expected = _expected_v060_sbom(
        environment,
        artifact_root=root,
        distribution_paths=tuple(sorted(distribution_paths)),
        project_name="agent-assure",
        project_version=expected_version,
    )
    if sbom != expected:
        raise ValueError(
            "historical SBOM does not exactly match its manifest environment and distributions"
        )


def _expected_v060_sbom(
    environment: Mapping[str, object],
    *,
    artifact_root: Path,
    distribution_paths: tuple[str, ...],
    project_name: str,
    project_version: str,
) -> dict[str, object]:
    python_version = _required_ascii(environment, "python_version", owner="environment")
    packages = environment.get("installed_packages", [])
    if not isinstance(packages, list) or len(packages) > MAX_COMPONENTS:
        raise ValueError("historical installed_packages must be a bounded array")
    project_normalized = _pypi_name(project_name)
    components: list[dict[str, object]] = []
    seen_names: set[str] = set()
    for index, package in enumerate(packages):
        if not isinstance(package, dict):
            raise ValueError(f"installed_packages[{index}] must be an object")
        if (
            package.get("artifact_kind") != "installed-package"
            or package.get("schema_version") != "0.6.0"
        ):
            raise ValueError(f"installed_packages[{index}] identity is invalid")
        name = _required_ascii(package, "name", owner=f"installed_packages[{index}]")
        version = _required_ascii(package, "version", owner=f"installed_packages[{index}]")
        normalized = _pypi_name(name)
        if normalized in seen_names:
            raise ValueError(f"duplicate normalized installed package name: {normalized}")
        seen_names.add(normalized)
        if normalized == project_normalized:
            continue
        ref = f"pkg:pypi/{normalized}@{version}"
        components.append(
            {
                "type": "library",
                "name": name,
                "version": version,
                "bom-ref": ref,
                "purl": ref,
            }
        )

    for relative in distribution_paths:
        path = _validated_relative_path(relative)
        snapshot = _read_bytes(
            _path_at(artifact_root, path),
            max_bytes=MAX_ARTIFACT_BYTES,
            label="distribution artifact",
        )
        components.append(
            {
                "type": "file",
                "name": PurePosixPath(path).name,
                "bom-ref": f"file:{path}",
                "properties": [
                    {"name": "agent-assure:release-path", "value": path},
                ],
                "hashes": [
                    {"alg": "SHA-256", "content": hashlib.sha256(snapshot).hexdigest()},
                ],
            }
        )
    project_ref = f"pkg:pypi/{project_normalized}@{project_version}"
    payload: dict[str, object] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "tools": [
                {"vendor": "ACB Labs", "name": project_name, "version": project_version},
            ],
            "component": {
                "type": "application",
                "name": project_name,
                "version": project_version,
                "bom-ref": project_ref,
                "purl": project_ref,
            },
            "properties": [
                {
                    "name": "agent-assure:sbom-scope",
                    "value": "local release environment and built distribution files",
                },
                {"name": "agent-assure:python-version", "value": python_version},
            ],
        },
        "components": components,
    }
    payload["serialNumber"] = _legacy_serial_number(payload)
    return payload


def _legacy_serial_number(payload: Mapping[str, object]) -> str:
    canonical = _canonical_ascii_json(payload)
    digest = hashlib.sha256(canonical).hexdigest()
    return f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, f'agent-assure-sbom:{digest}')}"


def _canonical_ascii_json(value: object) -> bytes:
    _require_ascii_tree(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _require_ascii_tree(value: object) -> None:
    if value is None or isinstance(value, bool | int):
        return
    if isinstance(value, str):
        if not value.isascii() or any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("historical SBOM canonical fields must be printable ASCII")
        return
    if isinstance(value, list | tuple):
        for item in value:
            _require_ascii_tree(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("historical SBOM object keys must be strings")
            _require_ascii_tree(key)
            _require_ascii_tree(item)
        return
    raise ValueError(f"unsupported historical SBOM value type: {type(value).__name__}")


def _required_role(by_role: Mapping[str, Mapping[str, object]], role: str) -> Mapping[str, object]:
    value = by_role.get(role)
    if value is None:
        raise ValueError(f"historical manifest is missing required role: {role}")
    return value


def _required_ascii(value: Mapping[str, object], key: str, *, owner: str) -> str:
    field = value.get(key)
    if (
        not isinstance(field, str)
        or not field
        or not field.isascii()
        or any(ord(char) < 32 or ord(char) == 127 for char in field)
    ):
        raise ValueError(f"{owner}.{key} must be non-empty printable ASCII")
    return field


def _require_exact_keys(
    value: Mapping[str, object],
    *,
    required: set[str],
    allowed: set[str],
    owner: str,
) -> None:
    missing = sorted(required - value.keys())
    unknown = sorted(value.keys() - allowed)
    if missing or unknown:
        raise ValueError(f"{owner} fields are invalid (missing={missing}; unknown={unknown})")


def _pypi_name(name: str) -> str:
    if _PACKAGE_RE.fullmatch(name) is None:
        raise ValueError(f"invalid historical Python package name: {name!r}")
    return re.sub(r"[-_.]+", "-", name).lower()


def _validated_relative_path(value: str) -> str:
    if not value or "\\" in value or not value.isascii():
        raise ValueError("historical artifact path must be canonical ASCII POSIX text")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("historical artifact path must be relative without traversal")
    if ":" in path.parts[0]:
        raise ValueError("historical artifact path must not contain a drive prefix")
    return path.as_posix()


def _path_at(root: Path, relative: str) -> Path:
    candidate = Path(os.path.abspath(root.joinpath(*PurePosixPath(relative).parts)))
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError("historical artifact path escapes artifact_root") from exc
    return candidate


def _read_bytes(path: Path, *, max_bytes: int, label: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file")
    with path.open("rb") as handle:
        data = handle.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError(f"{label} exceeds its byte limit")
    return data


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _loads_json(raw: bytes, *, label: str) -> dict[str, object]:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} root must be an object")
    return value


def _load_json(path: Path, *, label: str) -> dict[str, object]:
    return _loads_json(_read_bytes(path, max_bytes=MAX_JSON_BYTES, label=label), label=label)


def _bounded_error(exc: Exception) -> str:
    text = " ".join(str(exc).splitlines())
    return text[:500] if text else "validation failed"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sbom", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--expected-version", default="0.6.0")
    args = parser.parse_args(argv)
    try:
        validate_legacy_v060_release_sbom(
            sbom_path=args.sbom,
            manifest_path=args.manifest,
            artifact_root=args.artifact_root,
            expected_version=args.expected_version,
        )
    except (OSError, ValueError) as exc:
        print(f"legacy recovery SBOM validation failed: {_bounded_error(exc)}", file=sys.stderr)
        return 2
    print("legacy recovery SBOM validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
