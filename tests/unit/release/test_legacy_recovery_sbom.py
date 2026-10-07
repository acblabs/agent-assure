from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest

from scripts import check_legacy_recovery_sbom as legacy_sbom


def test_legacy_v060_sbom_is_rebuilt_from_manifest_and_distributions(tmp_path: Path) -> None:
    sbom_path, manifest_path = _write_release_fixture(tmp_path)

    legacy_sbom.validate_legacy_v060_release_sbom(
        sbom_path=sbom_path,
        manifest_path=manifest_path,
        artifact_root=tmp_path,
    )


@pytest.mark.parametrize("attack", ("package", "distribution", "purl"))
def test_legacy_v060_sbom_rejects_self_consistent_truncation_or_identity_forgery(
    tmp_path: Path,
    attack: str,
) -> None:
    sbom_path, manifest_path = _write_release_fixture(tmp_path)
    sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
    if attack == "package":
        sbom["components"] = [item for item in sbom["components"] if item.get("name") != "runtime"]
    elif attack == "distribution":
        sbom["components"] = [item for item in sbom["components"] if item.get("type") != "file"]
    else:
        runtime = next(item for item in sbom["components"] if item.get("name") == "runtime")
        runtime["purl"] = "pkg:pypi/forged@9.9"
    sbom.pop("serialNumber")
    sbom["serialNumber"] = legacy_sbom._legacy_serial_number(sbom)
    _write_json(sbom_path, sbom)

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    next(item for item in manifest["artifacts"] if item["role"] == "sbom")["sha256"] = _sha256(
        sbom_path
    )
    _write_json(manifest_path, manifest)

    with pytest.raises(ValueError, match="does not exactly match"):
        legacy_sbom.validate_legacy_v060_release_sbom(
            sbom_path=sbom_path,
            manifest_path=manifest_path,
            artifact_root=tmp_path,
        )


def test_legacy_v060_sbom_rejects_manifest_distribution_digest_drift(tmp_path: Path) -> None:
    sbom_path, manifest_path = _write_release_fixture(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    next(item for item in manifest["artifacts"] if item["role"] == "python-wheel")["sha256"] = (
        "f" * 64
    )
    _write_json(manifest_path, manifest)

    with pytest.raises(ValueError, match="python-wheel digest does not match"):
        legacy_sbom.validate_legacy_v060_release_sbom(
            sbom_path=sbom_path,
            manifest_path=manifest_path,
            artifact_root=tmp_path,
        )


def _write_release_fixture(root: Path) -> tuple[Path, Path]:
    release = root / ".tmp" / "release"
    dist = release / "dist"
    reports = release / "reports"
    dist.mkdir(parents=True)
    reports.mkdir(parents=True)
    wheel = dist / "agent_assure-0.6.0-py3-none-any.whl"
    sdist = dist / "agent_assure-0.6.0.tar.gz"
    wheel.write_bytes(b"wheel")
    sdist.write_bytes(b"sdist")
    environment = {
        "artifact_kind": "environment-info",
        "schema_version": "0.6.0",
        "platform": "test-platform",
        "python_version": "3.11.9",
        "git_commit": "a" * 40,
        "git_dirty": False,
        "lockfile_path": "requirements.lock",
        "lockfile_digest": "b" * 64,
        "dependency_inventory_path": ".tmp/release/dependency-inventory.json",
        "dependency_inventory_digest": "c" * 64,
        "installed_packages": [
            {
                "artifact_kind": "installed-package",
                "schema_version": "0.6.0",
                "name": "agent-assure",
                "version": "0.6.0",
            },
            {
                "artifact_kind": "installed-package",
                "schema_version": "0.6.0",
                "name": "runtime",
                "version": "1.0",
            },
        ],
    }
    paths = (
        ".tmp/release/dist/agent_assure-0.6.0-py3-none-any.whl",
        ".tmp/release/dist/agent_assure-0.6.0.tar.gz",
    )
    sbom = legacy_sbom._expected_v060_sbom(
        environment,
        artifact_root=root,
        distribution_paths=tuple(sorted(paths)),
        project_name="agent-assure",
        project_version="0.6.0",
    )
    sbom_path = release / "sbom.cdx.json"
    _write_json(sbom_path, sbom)
    manifest = {
        "artifact_kind": "release-artifact-manifest",
        "schema_version": "0.6.0",
        "manifest_id": "release-manifest-test",
        "artifacts": [
            _artifact("sbom", ".tmp/release/sbom.cdx.json", sbom_path),
            _artifact("python-wheel", paths[0], wheel),
            _artifact("source-distribution", paths[1], sdist),
        ],
        "environment": deepcopy(environment),
        "limitations": [
            "release artifact manifests record deterministic file digests only; "
            "they are not signatures or attestations"
        ],
    }
    manifest_path = reports / "release-artifact-manifest.json"
    _write_json(manifest_path, manifest)
    return sbom_path, manifest_path


def _artifact(role: str, relative: str, path: Path) -> dict[str, object]:
    return {
        "artifact_kind": "release-artifact",
        "schema_version": "0.6.0",
        "role": role,
        "path": relative,
        "sha256": _sha256(path),
    }


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
