from __future__ import annotations

import os
from pathlib import Path

import pytest

import agent_assure.reporting.environment as environment
from agent_assure.reporting.environment import (
    artifact_project_root,
    collect_environment,
    release_artifact,
    source_project_root,
)


def test_artifact_project_root_returns_common_ancestor_for_external_out_dir(
    tmp_path: Path,
) -> None:
    project_root = tmp_path / "project"
    external_out = tmp_path / "external-out"
    project_root.mkdir()
    external_out.mkdir()
    inputs = (
        project_root / "suite.compiled.json",
        project_root / "baseline.json",
        external_out / "reports",
    )

    root = artifact_project_root(inputs, default_root=project_root)

    for path in inputs:
        path.resolve().relative_to(root)


@pytest.mark.skipif(os.name != "nt", reason="Windows drive handling")
def test_artifact_project_root_rejects_cross_drive_artifacts() -> None:
    with pytest.raises(ValueError, match="common filesystem root"):
        artifact_project_root(
            (Path("C:/agent-assure/suite.json"), Path("Z:/agent-assure-out/report.json")),
            default_root=Path("C:/agent-assure"),
        )


def test_source_project_root_prefers_nested_git_root_inside_default(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    default_root = tmp_path / "parent"
    nested_root = default_root / "workspace"
    nested_root.mkdir(parents=True)
    source_paths = (
        nested_root / "suite.compiled.json",
        nested_root / "candidate.json",
    )
    for path in source_paths:
        path.write_text("{}\n", encoding="utf-8")

    def fake_git_toplevel(path: Path) -> Path | None:
        resolved = path.resolve()
        if _is_relative_to(resolved, nested_root.resolve()):
            return nested_root.resolve()
        if _is_relative_to(resolved, default_root.resolve()):
            return default_root.resolve()
        return None

    monkeypatch.setattr(environment, "_git_toplevel", fake_git_toplevel)

    root = source_project_root(source_paths, default_root=default_root)

    assert root == nested_root.resolve()


def test_environment_dependency_inventory_path_can_use_artifact_root(
    tmp_path: Path,
) -> None:
    project_root = tmp_path / "project"
    artifact_root = tmp_path
    out_dir = tmp_path / "outside"
    project_root.mkdir()
    out_dir.mkdir()
    lockfile = project_root / "requirements.lock"
    lockfile.write_text("locked\n", encoding="utf-8")
    dependency_inventory = out_dir / "dependency-inventory.json"
    dependency_inventory.write_text("{}\n", encoding="utf-8")

    environment = collect_environment(
        project_root=project_root,
        artifact_root=artifact_root,
        dependency_inventory_path=dependency_inventory,
        dependency_inventory_digest="a" * 64,
    )

    assert environment.lockfile_path == "requirements.lock"
    assert environment.dependency_inventory_path == "outside/dependency-inventory.json"


def test_release_artifact_rejects_paths_outside_project_root(tmp_path: Path) -> None:
    project_root = tmp_path / "project"
    outside_root = tmp_path / "outside"
    project_root.mkdir()
    outside_root.mkdir()
    external_artifact = outside_root / "artifact.json"
    external_artifact.write_text("{}\n", encoding="utf-8")

    with pytest.raises(ValueError, match="outside"):
        release_artifact("compiled-suite", external_artifact, project_root=project_root)


def test_environment_rejects_dependency_inventory_outside_project_root(
    tmp_path: Path,
) -> None:
    project_root = tmp_path / "project"
    outside_root = tmp_path / "outside"
    project_root.mkdir()
    outside_root.mkdir()
    dependency_inventory = outside_root / "dependency-inventory.json"
    dependency_inventory.write_text("{}\n", encoding="utf-8")

    with pytest.raises(ValueError, match="outside"):
        collect_environment(
            project_root=project_root,
            dependency_inventory_path=dependency_inventory,
            dependency_inventory_digest="a" * 64,
        )


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True
