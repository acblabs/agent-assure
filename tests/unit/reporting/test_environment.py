from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

import agent_assure.artifact_io as artifact_io
import agent_assure.reporting.environment as environment
from agent_assure.reporting.environment import (
    artifact_project_root,
    build_release_manifest,
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


def test_git_output_disables_repository_execution_hooks_and_unsafe_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["args"] = args
        captured["env"] = kwargs["env"]
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(artifact_io, "_resolve_git_executable", lambda: "/usr/bin/git")
    monkeypatch.setattr(artifact_io.subprocess, "run", fake_run)
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.fsmonitor")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "/tmp/attacker")
    monkeypatch.setenv("GIT_DIR", "/tmp/attacker-repository")
    monkeypatch.setenv("GIT_SSH_COMMAND", "/tmp/attacker-ssh")
    monkeypatch.setenv("git_dir", "/tmp/lowercase-attacker-repository")
    monkeypatch.setenv("GiT_WoRk_TrEe", "/tmp/mixed-case-work-tree")
    monkeypatch.setenv("git_replace_ref_base", "refs/attacker/")
    monkeypatch.setenv("git_config_count", "1")
    monkeypatch.setenv("gIt_CoNfIg_KeY_0", "core.hooksPath")

    assert artifact_io.git_output(
        tmp_path,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        allow_empty=True,
    ) == ""

    command = captured["args"]
    assert isinstance(command, list)
    assert "core.fsmonitor=false" in command
    assert any(str(part).startswith("core.hooksPath=") for part in command)
    git_environment = captured["env"]
    assert isinstance(git_environment, dict)
    assert "GIT_CONFIG_COUNT" not in git_environment
    assert "GIT_DIR" not in git_environment
    assert "GIT_SSH_COMMAND" not in git_environment
    assert not any(key.upper() == "GIT_DIR" for key in git_environment)
    assert not any(key.upper() == "GIT_WORK_TREE" for key in git_environment)
    assert not any(key.upper() == "GIT_REPLACE_REF_BASE" for key in git_environment)
    assert not any(
        key.upper().startswith("GIT_CONFIG_")
        and key.upper() not in {"GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM"}
        for key in git_environment
    )
    assert git_environment["GIT_TERMINAL_PROMPT"] == "0"
    assert git_environment["GIT_NO_REPLACE_OBJECTS"] == "1"


def test_git_output_rejects_unreviewed_commands(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unsupported read-only git command"):
        artifact_io.git_output(tmp_path, "log", "-1")


def test_release_manifest_rejects_duplicate_roles(tmp_path: Path) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    first.write_text("{}\n", encoding="utf-8")
    second.write_text("{}\n", encoding="utf-8")
    environment_info = collect_environment(project_root=tmp_path)
    artifacts = (
        release_artifact("evidence-packet", first, project_root=tmp_path),
        release_artifact("evidence-packet", second, project_root=tmp_path),
    )

    with pytest.raises(ValueError, match="duplicate release artifact role"):
        build_release_manifest(artifacts, environment=environment_info)


def test_collect_environment_records_a_clean_tree_as_false(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_git_output(
        _project_root: Path,
        *args: str,
        allow_empty: bool = False,
    ) -> str | None:
        if args == ("rev-parse", "HEAD"):
            return "a" * 40
        if args == ("status", "--porcelain") and allow_empty:
            return ""
        return None

    monkeypatch.setattr(environment, "git_output", fake_git_output)

    info = collect_environment(project_root=tmp_path)

    assert info.git_commit == "a" * 40
    assert info.git_dirty is False


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True
