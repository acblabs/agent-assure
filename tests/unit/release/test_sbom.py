from __future__ import annotations

from pathlib import Path

from agent_assure.reporting.sbom import build_sbom, write_sbom
from agent_assure.schema.environment import EnvironmentInfo, InstalledPackage


def test_sbom_is_deterministic_and_hashes_distribution_files(tmp_path: Path) -> None:
    wheel = tmp_path / "agent_assure-0.1.0-py3-none-any.whl"
    wheel.write_bytes(b"wheel-bytes")
    environment = EnvironmentInfo(
        artifact_kind="environment-info",
        platform="test-platform",
        python_version="3.11.0",
        installed_packages=(
            InstalledPackage(
                artifact_kind="installed-package",
                name="Typer",
                version="0.12.0",
            ),
            InstalledPackage(
                artifact_kind="installed-package",
                name="agent-assure",
                version="0.1.0",
            ),
            InstalledPackage(
                artifact_kind="installed-package",
                name="agent_assure",
                version="0.1.0",
            ),
        ),
    )

    first = build_sbom(environment, distribution_paths=(wheel,), project_root=tmp_path)
    second = build_sbom(environment, distribution_paths=(wheel,), project_root=tmp_path)
    digest = write_sbom(first, tmp_path / "sbom.cdx.json")

    assert first == second
    assert first["bomFormat"] == "CycloneDX"
    assert first["specVersion"] == "1.5"
    assert isinstance(first["serialNumber"], str)
    assert digest
    components = first["components"]
    assert isinstance(components, list)
    assert any(component.get("purl") == "pkg:pypi/typer@0.12.0" for component in components)
    assert not any(
        component.get("purl") == "pkg:pypi/agent-assure@0.1.0"
        for component in components
    )
    file_component = next(component for component in components if component.get("type") == "file")
    assert file_component["name"] == wheel.name
    assert file_component["hashes"] == [
        {
            "alg": "SHA-256",
            "content": "9ceb18f15662bb87e54af2f5953c0484d2ef76f5444d87913360b9ef87d7296d",
        }
    ]
