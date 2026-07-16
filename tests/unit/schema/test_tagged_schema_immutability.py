from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from scripts.check_tagged_schema_immutability import (
    check_tagged_schema_immutability,
    main,
)

ROOT = Path(__file__).resolve().parents[3]


def test_schema_without_matching_release_tag_remains_mutable(tmp_path: Path) -> None:
    repo, schema_root = _init_repo(tmp_path, version="v0.5.0")

    result = check_tagged_schema_immutability(
        repo_root=repo,
        schema_root=schema_root,
    )

    assert result.failures == ()
    assert result.protected_releases == ()
    assert result.unprotected_versions == ("v0.5.0",)


def test_matching_release_tag_freezes_schema_directory(tmp_path: Path) -> None:
    repo, schema_root = _init_repo(tmp_path, version="v0.5.0")
    _git(repo, "tag", "v0.5.0")

    result = check_tagged_schema_immutability(
        repo_root=repo,
        schema_root=schema_root,
    )

    assert result.failures == ()
    assert result.protected_releases == ("v0.5.0 -> v0.5.0",)
    assert result.unprotected_versions == ()


def test_tagged_schema_reports_changed_removed_and_added_files(tmp_path: Path) -> None:
    repo, schema_root = _init_repo(tmp_path, version="v0.5.0")
    version_dir = schema_root / "v0.5.0"
    (version_dir / "removed.schema.json").write_text("{}\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "add second schema")
    _git(repo, "tag", "v0.5.0")

    (version_dir / "example.schema.json").write_text('{"changed":true}\n', encoding="utf-8")
    (version_dir / "removed.schema.json").unlink()
    (version_dir / "added.schema.json").write_text("{}\n", encoding="utf-8")

    result = check_tagged_schema_immutability(
        repo_root=repo,
        schema_root=schema_root,
    )

    assert result.failures == (
        "released schema removed since v0.5.0: "
        "schemas/v0.5.0/removed.schema.json",
        "released schema file added after v0.5.0: "
        "schemas/v0.5.0/added.schema.json",
        "released schema drift from v0.5.0: "
        "schemas/v0.5.0/example.schema.json",
    )


@pytest.mark.parametrize(
    ("release_tag", "schema_version"),
    [("v0.4.2", "v0.3.1"), ("v0.4.4", "v0.4.3")],
)
def test_package_only_release_tag_protects_mapped_schema_version(
    tmp_path: Path,
    release_tag: str,
    schema_version: str,
) -> None:
    repo, schema_root = _init_repo(tmp_path, version=schema_version)
    _git(repo, "tag", release_tag)

    result = check_tagged_schema_immutability(
        repo_root=repo,
        schema_root=schema_root,
    )

    assert result.failures == ()
    assert result.protected_releases == (f"{release_tag} -> {schema_version}",)
    assert result.unprotected_versions == ()


def test_v010_uses_its_v020_stabilization_baseline(tmp_path: Path) -> None:
    repo, schema_root = _init_repo(tmp_path, version="v0.1.0")
    version_dir = schema_root / "v0.2.0"
    version_dir.mkdir()
    (version_dir / "example.schema.json").write_text(
        '{"type":"object"}\n',
        encoding="utf-8",
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "stabilize old schema and add v0.2")
    _git(repo, "tag", "v0.2.0")

    result = check_tagged_schema_immutability(
        repo_root=repo,
        schema_root=schema_root,
    )

    assert result.failures == ()
    assert result.protected_releases == (
        "v0.2.0 -> v0.1.0",
        "v0.2.0 -> v0.2.0",
    )
    assert result.unprotected_versions == ()


def test_hash_comparison_applies_git_clean_filters(tmp_path: Path) -> None:
    repo, schema_root = _init_repo(tmp_path, version="v0.5.0")
    _git(repo, "tag", "v0.5.0")
    _git(repo, "config", "core.autocrlf", "true")
    schema = schema_root / "v0.5.0" / "example.schema.json"
    schema.write_bytes(b'{"type":"object"}\r\n')

    result = check_tagged_schema_immutability(
        repo_root=repo,
        schema_root=schema_root,
    )

    assert result.failures == ()


def test_non_git_source_tree_reports_unavailable_baseline(tmp_path: Path) -> None:
    schema_root = tmp_path / "schemas"
    version_dir = schema_root / "v0.5.0"
    version_dir.mkdir(parents=True)
    (version_dir / "example.schema.json").write_text("{}\n", encoding="utf-8")

    result = check_tagged_schema_immutability(
        repo_root=tmp_path,
        schema_root=schema_root,
    )

    assert result.failures == ()
    assert result.repository_available is False
    assert result.unprotected_versions == ("v0.5.0",)


def test_strict_mode_rejects_source_tree_without_release_tags(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    schema_root = tmp_path / "schemas"
    schema_root.mkdir()

    exit_code = main(
        [
            "--repo-root",
            str(tmp_path),
            "--schema-root",
            str(schema_root),
            "--require-release-tags",
        ]
    )

    assert exit_code == 1
    assert "a Git work tree with release tags is required" in capsys.readouterr().err


def test_strict_mode_rejects_missing_historical_tag_baseline(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo, schema_root = _init_repo(tmp_path, version="v0.4.3")
    _write_schema(schema_root, "v0.3.1")
    _write_schema(schema_root, "v0.5.0")
    _write_active_schema_version(repo, "0.5.0")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "add historical snapshot and active candidate")
    _git(repo, "tag", "v0.4.4")

    exit_code = main(
        [
            "--repo-root",
            str(repo),
            "--schema-root",
            str(schema_root),
            "--require-release-tags",
        ]
    )

    assert exit_code == 1
    assert (
        "released schema snapshots have no local tag baseline: v0.3.1"
        in capsys.readouterr().err
    )


def test_ci_uses_full_history_and_strict_tag_enforcement() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    job = workflow.split("  schema-immutability:\n", maxsplit=1)[1].split(
        "\n  langgraph-smoke:", maxsplit=1
    )[0]

    assert "fetch-depth: 0" in job
    assert (
        "python scripts/check_tagged_schema_immutability.py --require-release-tags" in job
    )


def _init_repo(tmp_path: Path, *, version: str) -> tuple[Path, Path]:
    repo = tmp_path / "repo"
    schema_root = repo / "schemas"
    version_dir = schema_root / version
    version_dir.mkdir(parents=True)
    (version_dir / "example.schema.json").write_text(
        '{"type":"object"}\n',
        encoding="utf-8",
    )
    _git(repo, "init")
    _git(repo, "config", "user.name", "Schema Test")
    _git(repo, "config", "user.email", "schema-test@example.invalid")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "schema snapshot")
    return repo, schema_root


def _write_schema(schema_root: Path, version: str) -> None:
    version_dir = schema_root / version
    version_dir.mkdir()
    (version_dir / "example.schema.json").write_text(
        '{"type":"object"}\n',
        encoding="utf-8",
    )


def _write_active_schema_version(repo: Path, version: str) -> None:
    schema_base = repo / "src" / "agent_assure" / "schema" / "base.py"
    schema_base.parent.mkdir(parents=True)
    schema_base.write_text(f'SCHEMA_VERSION = "{version}"\n', encoding="utf-8")


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
    )
