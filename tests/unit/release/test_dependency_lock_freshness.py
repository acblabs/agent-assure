from __future__ import annotations

from pathlib import Path

import scripts.check_dependency_lock_freshness as lock_freshness


def _write_project(root: Path, *, marker_digest: str | None) -> None:
    source = b"""\
[build-system]
requires = ["setuptools==75.0.0"]

[project]
name = "fixture"
requires-python = ">=3.11"
dependencies = ["pydantic==2.13.0"]

[project.optional-dependencies]
dev = ["pytest==9.0.0"]

[tool.coverage.run]
branch = true
"""
    source_path = root / "pyproject.toml"
    source_path.write_bytes(source)
    digest = lock_freshness.dependency_input_sha256(source_path)
    marker = marker_digest if marker_digest is not None else digest
    for lock_path in lock_freshness.LOCK_PATHS:
        (root / lock_path).write_text(
            f"# {lock_freshness.SOURCE_DIGEST_MARKER}: {marker}\nfixture==1.0\n",
            encoding="utf-8",
        )


def test_checked_in_dependency_locks_bind_current_pyproject() -> None:
    assert lock_freshness.dependency_lock_freshness_errors() == ()


def test_source_change_invalidates_every_lock_marker(tmp_path: Path) -> None:
    _write_project(tmp_path, marker_digest="a" * 64)

    failures = lock_freshness.dependency_lock_freshness_errors(tmp_path)

    assert len(failures) == len(lock_freshness.LOCK_PATHS)
    assert all("does not match the canonical pyproject" in failure for failure in failures)


def test_missing_marker_fails_closed(tmp_path: Path) -> None:
    _write_project(tmp_path, marker_digest=None)
    first_lock = tmp_path / lock_freshness.LOCK_PATHS[0]
    first_lock.write_text("fixture==1.0\n", encoding="utf-8")

    failures = lock_freshness.dependency_lock_freshness_errors(tmp_path)

    assert failures == (
        "requirements.lock: missing '# source-dependency-input-sha256: <sha256>' marker",
    )


def test_unrelated_tooling_change_does_not_stale_dependency_locks(tmp_path: Path) -> None:
    _write_project(tmp_path, marker_digest=None)
    source_path = tmp_path / "pyproject.toml"
    source_path.write_text(
        source_path.read_text(encoding="utf-8").replace(
            "branch = true",
            "branch = false",
        ),
        encoding="utf-8",
    )

    assert lock_freshness.dependency_lock_freshness_errors(tmp_path) == ()


def test_declared_dependency_change_stales_every_lock(tmp_path: Path) -> None:
    _write_project(tmp_path, marker_digest=None)
    source_path = tmp_path / "pyproject.toml"
    source_path.write_text(
        source_path.read_text(encoding="utf-8").replace(
            "pydantic==2.13.0",
            "pydantic==2.14.0",
        ),
        encoding="utf-8",
    )

    failures = lock_freshness.dependency_lock_freshness_errors(tmp_path)
    assert len(failures) == len(lock_freshness.LOCK_PATHS)
