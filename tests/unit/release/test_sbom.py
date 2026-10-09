from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from agent_assure import __version__ as PROJECT_VERSION
from agent_assure.artifact_io import file_sha256
from agent_assure.reporting import sbom as sbom_module
from agent_assure.reporting.sbom import (
    CYCLONEDX_SCHEMA,
    build_sbom,
    load_and_validate_sbom,
    validate_sbom,
    write_sbom,
)
from agent_assure.schema.environment import EnvironmentInfo, InstalledPackage
from scripts.check_sbom import main as check_sbom_main


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
    assert first["$schema"] == CYCLONEDX_SCHEMA
    assert first["bomFormat"] == "CycloneDX"
    assert first["specVersion"] == "1.5"
    assert isinstance(first["serialNumber"], str)
    assert digest
    components = first["components"]
    assert isinstance(components, list)
    assert any(component.get("purl") == "pkg:pypi/typer@0.12.0" for component in components)
    assert not any(
        component.get("purl") == "pkg:pypi/agent-assure@0.1.0" for component in components
    )
    file_component = next(component for component in components if component.get("type") == "file")
    assert file_component["name"] == wheel.name
    assert file_component["hashes"] == [
        {
            "alg": "SHA-256",
            "content": "9ceb18f15662bb87e54af2f5953c0484d2ef76f5444d87913360b9ef87d7296d",
        }
    ]
    assert first["dependencies"] == [
        {"ref": f"pkg:pypi/agent-assure@{PROJECT_VERSION}", "dependsOn": []}
    ]
    assert first["properties"] == [
        {
            "name": "agent-assure:vulnerability-analysis-status",
            "value": "not-performed",
        },
        {"name": "agent-assure:vulnerability-status", "value": "unknown"},
    ]
    metadata = first["metadata"]
    assert metadata["lifecycles"] == [{"phase": "build"}]
    metadata_properties = _properties(metadata["properties"])
    assert metadata_properties["agent-assure:dependency-lock-status"] == "unavailable"
    typer = next(component for component in components if component.get("name") == "Typer")
    typer_properties = _properties(typer["properties"])
    assert typer_properties["agent-assure:component-hash-evidence"] == "unknown"
    assert typer_properties["agent-assure:supplier-evidence"] == "unknown"
    validate_sbom(first)


def test_sbom_derives_graph_hashes_scopes_and_license_evidence(tmp_path: Path) -> None:
    _write_project(tmp_path)
    lock = _write_lock(tmp_path)
    wheel = tmp_path / "dist" / "agent_assure-0.1.0-py3-none-any.whl"
    wheel.parent.mkdir()
    wheel.write_bytes(b"wheel-bytes")
    environment = _environment(lock)

    sbom = build_sbom(
        environment,
        project_version="0.1.0",
        distribution_paths=(wheel,),
        project_root=tmp_path,
        package_license_expressions={
            ("runtime", "1.0"): "Apache-2.0",
        },
    )

    root = sbom["metadata"]["component"]
    assert root["author"] == "ACB Labs"
    assert root["licenses"] == [{"license": {"name": "MIT"}}]
    assert _properties(root["properties"])["agent-assure:supplier-evidence"] == "unknown"
    runtime = _component(sbom, "runtime")
    transitive = _component(sbom, "transitive")
    optional = _component(sbom, "optional")
    devtool = _component(sbom, "devtool")
    builder = _component(sbom, "builder")
    bootstrap = _component(sbom, "bootstrap")
    runtime_scope = _properties(runtime["properties"])["agent-assure:dependency-scope"]
    assert (runtime["scope"], runtime_scope) == (
        "required",
        "runtime-direct",
    )
    assert transitive["scope"] == "required"
    assert optional["scope"] == "optional"
    assert devtool["scope"] == "excluded"
    assert builder["scope"] == "excluded"
    assert bootstrap["scope"] == "excluded"
    assert runtime["licenses"] == [{"expression": "Apache-2.0"}]
    assert runtime["hashes"] == [
        {"alg": "SHA-256", "content": "1" * 64},
        {"alg": "SHA-256", "content": "2" * 64},
    ]
    runtime_properties = _properties(runtime["properties"])
    assert runtime_properties["agent-assure:component-hash-installed-artifact"] == "not-identified"
    assert runtime_properties["agent-assure:component-hash-source"] == "requirements.lock"
    graph = {entry["ref"]: entry["dependsOn"] for entry in sbom["dependencies"]}
    root_ref = "pkg:pypi/agent-assure@0.1.0"
    assert graph[root_ref] == sorted(
        [runtime["bom-ref"], optional["bom-ref"], devtool["bom-ref"], builder["bom-ref"]]
    )
    assert graph[runtime["bom-ref"]] == [transitive["bom-ref"]]
    assert sbom["compositions"] == [
        {"aggregate": "unknown", "assemblies": [root_ref], "dependencies": [root_ref]}
    ]
    load_and_validate_sbom(_write_json(tmp_path / "sbom.cdx.json", sbom), artifact_root=tmp_path)


def test_sbom_rejects_lock_digest_drift(tmp_path: Path) -> None:
    _write_project(tmp_path)
    lock = _write_lock(tmp_path)
    environment = _environment(lock).model_copy(update={"lockfile_digest": "0" * 64})

    with pytest.raises(ValueError, match="lockfile digest does not match"):
        build_sbom(environment, project_version="0.1.0", project_root=tmp_path)


def test_sbom_rejects_installed_version_not_in_verified_lock(tmp_path: Path) -> None:
    _write_project(tmp_path)
    lock = _write_lock(tmp_path)
    environment = _environment(lock)
    packages = tuple(
        package.model_copy(update={"version": "9.0"}) if package.name == "runtime" else package
        for package in environment.installed_packages
    )

    with pytest.raises(ValueError, match="installed package does not match verified lock"):
        build_sbom(
            environment.model_copy(update={"installed_packages": packages}),
            project_version="0.1.0",
            project_root=tmp_path,
        )


def test_sbom_rejects_hashless_pip_compile_entry(tmp_path: Path) -> None:
    _write_project(tmp_path)
    lock = tmp_path / "requirements.lock"
    lock.write_text("runtime==1.0\n    # via agent-assure (pyproject.toml)\n", encoding="utf-8")

    with pytest.raises(ValueError, match="has no SHA-256 archive hashes"):
        build_sbom(_environment(lock), project_version="0.1.0", project_root=tmp_path)


def test_sbom_local_validation_detects_artifact_drift(tmp_path: Path) -> None:
    wheel = tmp_path / "agent_assure.whl"
    wheel.write_bytes(b"original")
    sbom = build_sbom(
        EnvironmentInfo(
            artifact_kind="environment-info",
            platform="test",
            python_version="3.11",
        ),
        distribution_paths=(wheel,),
        project_root=tmp_path,
    )
    sbom_path = _write_json(tmp_path / "sbom.cdx.json", sbom)
    wheel.write_bytes(b"drifted")

    with pytest.raises(ValueError, match="release artifact digest mismatch"):
        load_and_validate_sbom(sbom_path, artifact_root=tmp_path)


def test_sbom_validator_rejects_forged_vulnerability_status(tmp_path: Path) -> None:
    environment = EnvironmentInfo(
        artifact_kind="environment-info", platform="test", python_version="3.11"
    )
    sbom = build_sbom(environment)
    sbom["properties"][0]["value"] = "performed"

    with pytest.raises(ValueError, match="not performed"):
        write_sbom(sbom, tmp_path / "sbom.cdx.json")


@pytest.mark.parametrize("field", ("dependencies", "compositions"))
def test_sbom_validator_rejects_removed_graph_or_composition(field: str) -> None:
    sbom = build_sbom(
        EnvironmentInfo(
            artifact_kind="environment-info",
            platform="test",
            python_version="3.11",
        )
    )
    forged = deepcopy(sbom)
    if field == "dependencies":
        forged[field] = []
    else:
        forged.pop(field)
    forged.pop("serialNumber")
    forged["serialNumber"] = sbom_module._serial_number(forged)

    with pytest.raises(ValueError, match="dependency graph|composition"):
        validate_sbom(forged)


def test_sbom_local_validation_rederives_dependency_edges(tmp_path: Path) -> None:
    _write_project(tmp_path)
    lock = _write_lock(tmp_path)
    sbom = build_sbom(
        _environment(lock),
        project_version="0.1.0",
        project_root=tmp_path,
    )
    forged = deepcopy(sbom)
    runtime = _component(forged, "runtime")
    runtime_entry = next(
        entry for entry in forged["dependencies"] if entry["ref"] == runtime["bom-ref"]
    )
    runtime_entry["dependsOn"] = []
    forged.pop("serialNumber")
    forged["serialNumber"] = sbom_module._serial_number(forged)
    path = _write_json(tmp_path / "forged-sbom.cdx.json", forged)

    with pytest.raises(ValueError, match="does not match the digest-verified local lockfile"):
        load_and_validate_sbom(path, artifact_root=tmp_path)


def test_sbom_local_validation_allows_unselected_optional_and_inactive_marker_dependencies(
    tmp_path: Path,
) -> None:
    _write_project(tmp_path)
    lock = _write_lock(tmp_path)
    sbom = build_sbom(
        _environment(lock),
        project_version="0.1.0",
        project_root=tmp_path,
    )
    component_names = {
        component["name"] for component in sbom["components"] if component["type"] == "library"
    }

    assert {"inactive", "unselected"}.isdisjoint(component_names)
    load_and_validate_sbom(
        _write_json(tmp_path / "selected-environment-sbom.cdx.json", sbom),
        artifact_root=tmp_path,
    )


def test_sbom_local_validation_rejects_missing_marker_applicable_dependency(
    tmp_path: Path,
) -> None:
    _write_project(tmp_path)
    lock = _write_lock(tmp_path)
    lock.write_text(
        lock.read_text(encoding="utf-8")
        + "\n".join(
            [
                'active-marker==2.6 ; python_version >= "3.0" \\',
                f"    --hash=sha256:{'8' * 64}",
                "    # via runtime",
                "",
            ]
        ),
        encoding="utf-8",
    )
    sbom = build_sbom(
        _environment(lock),
        project_version="0.1.0",
        project_root=tmp_path,
    )

    with pytest.raises(ValueError, match="omits project dependency components"):
        load_and_validate_sbom(
            _write_json(tmp_path / "missing-active-marker-sbom.cdx.json", sbom),
            artifact_root=tmp_path,
        )


def test_sbom_rejects_invalid_dependency_lock_marker(tmp_path: Path) -> None:
    _write_project(tmp_path)
    lock = _write_lock(tmp_path)
    lock.write_text(
        lock.read_text(encoding="utf-8").replace(
            'python_version < "3.0"',
            'python_version ~~ "3.0"',
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="dependency lock marker is invalid"):
        build_sbom(
            _environment(lock),
            project_version="0.1.0",
            project_root=tmp_path,
        )


def test_sbom_rejects_volatile_dependency_lock_marker_variable(tmp_path: Path) -> None:
    _write_project(tmp_path)
    lock = _write_lock(tmp_path)
    lock.write_text(
        lock.read_text(encoding="utf-8").replace(
            'python_version < "3.0"',
            'platform_release == "untrusted-kernel"',
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="unsupported or volatile variable"):
        build_sbom(
            _environment(lock),
            project_version="0.1.0",
            project_root=tmp_path,
        )


def test_sbom_local_validation_rejects_runtime_root_missing_from_lock(
    tmp_path: Path,
) -> None:
    _write_project(tmp_path)
    project = tmp_path / "pyproject.toml"
    project.write_text(
        project.read_text(encoding="utf-8").replace(
            'dependencies = ["runtime>=1"]',
            'dependencies = ["runtime>=1", "missing-runtime>=1"]',
        ),
        encoding="utf-8",
    )
    lock = _write_lock(tmp_path)
    sbom = build_sbom(
        _environment(lock),
        project_version="0.1.0",
        project_root=tmp_path,
    )

    with pytest.raises(ValueError, match="lock omits declared project runtime dependencies"):
        load_and_validate_sbom(
            _write_json(tmp_path / "missing-runtime-lock-sbom.cdx.json", sbom),
            artifact_root=tmp_path,
        )


def test_sbom_local_validation_rejects_marker_inapplicable_runtime_root(
    tmp_path: Path,
) -> None:
    _write_project(tmp_path)
    lock = _write_lock(tmp_path)
    lock.write_text(
        lock.read_text(encoding="utf-8").replace(
            "runtime==1.0 \\",
            'runtime==1.0 ; python_version < "3.0" \\',
        ),
        encoding="utf-8",
    )
    lock.write_text(
        lock.read_text(encoding="utf-8")
        + "\n".join(
            [
                'runtime==2.0 ; python_version >= "3.0" \\',
                f"    --hash=sha256:{'9' * 64}",
                "    # via transitive-only-parent",
                "",
            ]
        ),
        encoding="utf-8",
    )
    environment = _environment(lock)
    environment = environment.model_copy(
        update={
            "installed_packages": tuple(
                package
                for package in environment.installed_packages
                if package.name not in {"runtime", "transitive"}
            )
        }
    )
    sbom = build_sbom(
        environment,
        project_version="0.1.0",
        project_root=tmp_path,
    )

    with pytest.raises(ValueError, match="lock omits declared project runtime dependencies"):
        load_and_validate_sbom(
            _write_json(tmp_path / "inactive-runtime-sbom.cdx.json", sbom),
            artifact_root=tmp_path,
        )


def test_sbom_rejects_installed_marker_inapplicable_lock_coordinate(
    tmp_path: Path,
) -> None:
    _write_project(tmp_path)
    lock = _write_lock(tmp_path)
    lock.write_text(
        lock.read_text(encoding="utf-8").replace(
            "runtime==1.0 \\",
            'runtime==1.0 ; python_version < "3.0" \\',
        )
        + "\n".join(
            [
                'runtime==2.0 ; python_version >= "3.0" \\',
                f"    --hash=sha256:{'9' * 64}",
                "    # via agent-assure (pyproject.toml)",
                "",
            ]
        ),
        encoding="utf-8",
    )
    sbom = build_sbom(
        _environment(lock),
        project_version="0.1.0",
        project_root=tmp_path,
    )

    with pytest.raises(ValueError, match="component is inapplicable"):
        load_and_validate_sbom(
            _write_json(tmp_path / "wrong-marker-coordinate-sbom.cdx.json", sbom),
            artifact_root=tmp_path,
        )


def test_sbom_trusted_validation_keeps_an_installed_marker_applicable_dependency(
    tmp_path: Path,
) -> None:
    _write_project(tmp_path)
    lock = _write_lock(tmp_path)
    lock.write_text(
        lock.read_text(encoding="utf-8")
        + "\n".join(
            [
                'conditional==2.6 ; python_version >= "3.0" \\',
                f"    --hash=sha256:{'8' * 64}",
                "    # via runtime",
                "",
            ]
        ),
        encoding="utf-8",
    )
    environment = _environment(lock)
    environment = environment.model_copy(
        update={
            "installed_packages": (
                *environment.installed_packages,
                InstalledPackage(
                    artifact_kind="installed-package",
                    name="conditional",
                    version="2.6",
                ),
            )
        }
    )
    sbom = build_sbom(
        environment,
        project_version="0.1.0",
        project_root=tmp_path,
    )
    conditional = _component(sbom, "conditional")

    assert conditional["scope"] == "required"
    assert conditional["hashes"] == [{"alg": "SHA-256", "content": "8" * 64}]
    load_and_validate_sbom(
        _write_json(tmp_path / "conditional-sbom.cdx.json", sbom),
        artifact_root=tmp_path,
        expected_environment=environment,
        expected_distribution_paths=(),
        expected_project_version="0.1.0",
    )

    forged = deepcopy(sbom)
    conditional_ref = conditional["bom-ref"]
    forged["components"] = [
        component for component in forged["components"] if component["bom-ref"] != conditional_ref
    ]
    forged["dependencies"] = [
        {
            **entry,
            "dependsOn": [ref for ref in entry["dependsOn"] if ref != conditional_ref],
        }
        for entry in forged["dependencies"]
        if entry["ref"] != conditional_ref
    ]
    forged.pop("serialNumber")
    forged["serialNumber"] = sbom_module._serial_number(forged)

    with pytest.raises(ValueError, match="trusted build environment"):
        validate_sbom(
            forged,
            artifact_root=tmp_path,
            expected_environment=environment,
            expected_distribution_paths=(),
            expected_project_version="0.1.0",
        )


def test_sbom_local_validation_rejects_removed_direct_component(tmp_path: Path) -> None:
    _write_project(tmp_path)
    lock = _write_lock(tmp_path)
    environment = _environment(lock)
    sbom = build_sbom(
        environment,
        project_version="0.1.0",
        project_root=tmp_path,
    )
    forged = deepcopy(sbom)
    runtime = _component(forged, "runtime")
    runtime_ref = runtime["bom-ref"]
    forged["components"] = [
        component for component in forged["components"] if component["bom-ref"] != runtime_ref
    ]
    forged["dependencies"] = [
        {
            **entry,
            "dependsOn": [ref for ref in entry["dependsOn"] if ref != runtime_ref],
        }
        for entry in forged["dependencies"]
        if entry["ref"] != runtime_ref
    ]
    forged.pop("serialNumber")
    forged["serialNumber"] = sbom_module._serial_number(forged)
    path = _write_json(tmp_path / "truncated-sbom.cdx.json", forged)

    with pytest.raises(ValueError, match="omits project dependency components"):
        load_and_validate_sbom(path, artifact_root=tmp_path)
    with pytest.raises(ValueError, match="trusted build environment"):
        validate_sbom(
            forged,
            artifact_root=tmp_path,
            expected_environment=environment,
            expected_distribution_paths=(),
            expected_project_version="0.1.0",
        )


def test_sbom_local_validation_rejects_removed_unconditional_transitive_component(
    tmp_path: Path,
) -> None:
    _write_project(tmp_path)
    lock = _write_lock(tmp_path)
    sbom = build_sbom(
        _environment(lock),
        project_version="0.1.0",
        project_root=tmp_path,
    )
    forged = deepcopy(sbom)
    transitive = _component(forged, "transitive")
    transitive_ref = transitive["bom-ref"]
    forged["components"] = [
        component for component in forged["components"] if component["bom-ref"] != transitive_ref
    ]
    forged["dependencies"] = [
        {
            **entry,
            "dependsOn": [ref for ref in entry["dependsOn"] if ref != transitive_ref],
        }
        for entry in forged["dependencies"]
        if entry["ref"] != transitive_ref
    ]
    forged.pop("serialNumber")
    forged["serialNumber"] = sbom_module._serial_number(forged)

    with pytest.raises(ValueError, match="omits project dependency components"):
        load_and_validate_sbom(
            _write_json(tmp_path / "truncated-transitive-sbom.cdx.json", forged),
            artifact_root=tmp_path,
        )


@pytest.mark.parametrize("attack", ("project-purl", "library-purl", "lock-hash"))
def test_sbom_rejects_forged_package_identity_or_lock_hash(
    tmp_path: Path,
    attack: str,
) -> None:
    _write_project(tmp_path)
    lock = _write_lock(tmp_path)
    environment = _environment(lock)
    sbom = build_sbom(
        environment,
        project_version="0.1.0",
        project_root=tmp_path,
    )
    forged = deepcopy(sbom)
    if attack == "project-purl":
        forged["metadata"]["component"]["purl"] = "pkg:pypi/forged@9.9"
    else:
        runtime = _component(forged, "runtime")
        if attack == "library-purl":
            runtime["purl"] = "pkg:pypi/forged@9.9"
        else:
            runtime["hashes"] = [{"alg": "SHA-256", "content": "f" * 64}]
    forged.pop("serialNumber")
    forged["serialNumber"] = sbom_module._serial_number(forged)

    with pytest.raises(ValueError, match="canonical package identity|verified lockfile"):
        validate_sbom(forged, artifact_root=tmp_path)


def test_sbom_trusted_reconstruction_requires_exact_distribution_components(
    tmp_path: Path,
) -> None:
    _write_project(tmp_path)
    lock = _write_lock(tmp_path)
    environment = _environment(lock)
    wheel = tmp_path / "dist" / "agent_assure-0.1.0-py3-none-any.whl"
    wheel.parent.mkdir()
    wheel.write_bytes(b"wheel")
    sbom = build_sbom(
        environment,
        project_version="0.1.0",
        distribution_paths=(wheel,),
        project_root=tmp_path,
    )
    forged = deepcopy(sbom)
    forged["components"] = [
        component for component in forged["components"] if component["type"] != "file"
    ]
    forged.pop("serialNumber")
    forged["serialNumber"] = sbom_module._serial_number(forged)

    with pytest.raises(ValueError, match="does not exactly match reconstruction"):
        validate_sbom(
            forged,
            artifact_root=tmp_path,
            expected_environment=environment,
            expected_distribution_paths=(wheel,),
            expected_project_version="0.1.0",
        )


def test_sbom_loader_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    path = tmp_path / "sbom.cdx.json"
    path.write_text('{"bomFormat":"CycloneDX","bomFormat":"CycloneDX"}', encoding="utf-8")

    with pytest.raises(ValueError, match="duplicate JSON object key"):
        load_and_validate_sbom(path)


def test_check_sbom_cli_verifies_local_evidence(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    wheel = tmp_path / "agent_assure.whl"
    wheel.write_bytes(b"wheel")
    sbom = build_sbom(
        EnvironmentInfo(artifact_kind="environment-info", platform="test", python_version="3.11"),
        distribution_paths=(wheel,),
        project_root=tmp_path,
    )
    path = _write_json(tmp_path / "sbom.cdx.json", sbom)

    assert check_sbom_main(["--sbom", str(path), "--artifact-root", str(tmp_path)]) == 0
    assert "SBOM validation passed" in capsys.readouterr().out
    wheel.write_bytes(b"tampered")
    assert check_sbom_main(["--sbom", str(path), "--artifact-root", str(tmp_path)]) == 2
    assert "digest mismatch" in capsys.readouterr().err


def test_check_sbom_cli_bounds_and_redacts_failures(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "sk-" + "a" * 48

    def fail_validation(_path: Path, *, artifact_root: Path | None = None) -> None:
        del artifact_root
        raise ValueError(f"first line\nAuthorization: Bearer {secret}" + "x" * 1_000)

    monkeypatch.setattr("scripts.check_sbom.load_and_validate_sbom", fail_validation)
    assert check_sbom_main(["--sbom", str(tmp_path / "unsafe.cdx.json")]) == 2
    error = capsys.readouterr().err
    assert secret not in error
    assert error.count("\n") == 1
    assert len(error) <= 600


def _write_project(root: Path) -> None:
    (root / "pyproject.toml").write_text(
        """
[build-system]
requires = ["builder>=1"]
build-backend = "builder.api"

[project]
name = "agent-assure"
version = "0.1.0"
dependencies = ["runtime>=1"]
license = { text = "MIT" }
authors = [{ name = "ACB Labs" }]

[project.optional-dependencies]
adapter = ["optional>=1"]
unselected = ["unselected>=1"]
dev = ["devtool>=1"]
""".lstrip(),
        encoding="utf-8",
    )


def _write_lock(root: Path) -> Path:
    lock = root / "requirements.lock"
    lock.write_text(
        "\n".join(
            [
                "runtime==1.0 \\",
                f"    --hash=sha256:{'2' * 64} \\",
                f"    --hash=sha256:{'1' * 64}",
                "    # via agent-assure (pyproject.toml)",
                "transitive==2.0 \\",
                f"    --hash=sha256:{'3' * 64}",
                "    # via runtime",
                'inactive==2.5 ; python_version < "3.0" \\',
                f"    --hash=sha256:{'7' * 64}",
                "    # via runtime",
                "optional==3.0 \\",
                f"    --hash=sha256:{'4' * 64}",
                "    # via agent-assure (pyproject.toml)",
                "devtool[test]==4.0 \\",
                f"    --hash=sha256:{'5' * 64}",
                "    # via agent-assure (pyproject.toml)",
                "builder==5.0 \\",
                f"    --hash=sha256:{'6' * 64}",
                "    # via agent-assure (pyproject.toml::build-system.requires)",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return lock


def _environment(lock: Path) -> EnvironmentInfo:
    packages = [
        ("runtime", "1.0"),
        ("transitive", "2.0"),
        ("optional", "3.0"),
        ("devtool", "4.0"),
        ("builder", "5.0"),
        ("bootstrap", "6.0"),
        ("agent-assure", "0.1.0"),
    ]
    return EnvironmentInfo(
        artifact_kind="environment-info",
        platform="test-platform",
        python_version="3.11.0",
        lockfile_path="requirements.lock",
        lockfile_digest=file_sha256(lock),
        installed_packages=tuple(
            InstalledPackage(
                artifact_kind="installed-package",
                name=name,
                version=version,
            )
            for name, version in packages
        ),
    )


def _component(sbom: dict[str, object], name: str) -> dict[str, object]:
    components = sbom["components"]
    assert isinstance(components, list)
    return next(component for component in components if component.get("name") == name)


def _properties(properties: object) -> dict[str, str]:
    assert isinstance(properties, list)
    return {entry["name"]: entry["value"] for entry in properties}


def _write_json(path: Path, payload: object) -> Path:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path
