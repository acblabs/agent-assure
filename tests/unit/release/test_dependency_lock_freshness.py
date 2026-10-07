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
dependencies = ["pydantic>=2.12,<3"]

[project.optional-dependencies]
dev = ["pytest==9.0.0"]

[tool.coverage.run]
branch = true
"""
    source_path = root / "pyproject.toml"
    source_path.write_bytes(source)
    digest = lock_freshness.dependency_input_sha256(source_path)
    marker = marker_digest if marker_digest is not None else digest
    constraints_path = root / lock_freshness.MINIMUM_RUNTIME_CONSTRAINTS_PATH
    constraints_path.write_text("Pydantic==2.12.0\n", encoding="utf-8")
    constraints_digest = lock_freshness.file_sha256(constraints_path)
    for lock_path in lock_freshness.LOCK_PATHS:
        lines = [f"# {lock_freshness.SOURCE_DIGEST_MARKER}: {marker}"]
        if lock_path == lock_freshness.MINIMUM_RUNTIME_LOCK_PATH:
            lines.append(
                f"# {lock_freshness.MINIMUM_CONSTRAINTS_DIGEST_MARKER}: {constraints_digest}"
            )
            lines.append("pydantic==2.12.0")
        lines.append("fixture==1.0")
        (root / lock_path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_constraints_and_refresh_marker(root: Path, contents: str) -> None:
    constraints_path = root / lock_freshness.MINIMUM_RUNTIME_CONSTRAINTS_PATH
    constraints_path.write_text(contents, encoding="utf-8")
    digest = lock_freshness.file_sha256(constraints_path)
    lock_path = root / lock_freshness.MINIMUM_RUNTIME_LOCK_PATH
    lock_text = lock_path.read_text(encoding="utf-8")
    marker_prefix = f"# {lock_freshness.MINIMUM_CONSTRAINTS_DIGEST_MARKER}: "
    lock_path.write_text(
        "\n".join(
            f"{marker_prefix}{digest}" if line.startswith(marker_prefix) else line
            for line in lock_text.splitlines()
        )
        + "\n",
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
            "pydantic>=2.12,<3",
            "pydantic>=2.12,<4",
        ),
        encoding="utf-8",
    )

    failures = lock_freshness.dependency_lock_freshness_errors(tmp_path)
    assert len(failures) == len(lock_freshness.LOCK_PATHS)


def test_minimum_constraint_change_stales_only_minimum_lock(tmp_path: Path) -> None:
    _write_project(tmp_path, marker_digest=None)
    constraints_path = tmp_path / lock_freshness.MINIMUM_RUNTIME_CONSTRAINTS_PATH
    constraints_path.write_text("pydantic==2.12\n", encoding="utf-8")

    failures = lock_freshness.dependency_lock_freshness_errors(tmp_path)

    assert len(failures) == 1
    assert failures[0].startswith("requirements-min.lock: minimum-runtime constraints marker")


def test_missing_minimum_constraints_fail_closed(tmp_path: Path) -> None:
    _write_project(tmp_path, marker_digest=None)
    (tmp_path / lock_freshness.MINIMUM_RUNTIME_CONSTRAINTS_PATH).unlink()

    failures = lock_freshness.dependency_lock_freshness_errors(tmp_path)

    assert failures == ("missing minimum-runtime constraints: requirements-min.constraints.txt",)


def test_minimum_profile_rejects_missing_runtime_constraint_with_fresh_marker(
    tmp_path: Path,
) -> None:
    _write_project(tmp_path, marker_digest=None)
    _write_constraints_and_refresh_marker(tmp_path, "# deliberately empty\n")

    failures = lock_freshness.dependency_lock_freshness_errors(tmp_path)

    assert any(
        "missing exact constraint(s) for runtime dependencies: pydantic" in failure
        for failure in failures
    )


def test_minimum_profile_rejects_extra_non_runtime_constraint_with_fresh_marker(
    tmp_path: Path,
) -> None:
    _write_project(tmp_path, marker_digest=None)
    _write_constraints_and_refresh_marker(
        tmp_path,
        "pydantic==2.12.0\nrich==13.0.0\n",
    )

    failures = lock_freshness.dependency_lock_freshness_errors(tmp_path)

    assert any("unexpected non-runtime constraint(s): rich" in failure for failure in failures)


def test_minimum_profile_rejects_constraint_that_does_not_equal_declared_floor(
    tmp_path: Path,
) -> None:
    _write_project(tmp_path, marker_digest=None)
    _write_constraints_and_refresh_marker(tmp_path, "pydantic==2.12.1\n")

    failures = lock_freshness.dependency_lock_freshness_errors(tmp_path)

    assert any(
        "pydantic pin 2.12.1 does not match declared runtime lower floor 2.12" in failure
        for failure in failures
    )


def test_minimum_profile_rejects_direct_lock_pin_drift(tmp_path: Path) -> None:
    _write_project(tmp_path, marker_digest=None)
    lock_path = tmp_path / lock_freshness.MINIMUM_RUNTIME_LOCK_PATH
    lock_path.write_text(
        lock_path.read_text(encoding="utf-8").replace(
            "pydantic==2.12.0",
            "pydantic==2.12.1",
        ),
        encoding="utf-8",
    )

    failures = lock_freshness.dependency_lock_freshness_errors(tmp_path)

    assert any(
        "pydantic direct pin 2.12.1 does not match minimum constraint 2.12" in failure
        for failure in failures
    )


def test_minimum_profile_rejects_duplicate_normalized_constraint_names(
    tmp_path: Path,
) -> None:
    _write_project(tmp_path, marker_digest=None)
    _write_constraints_and_refresh_marker(
        tmp_path,
        "Pydantic==2.12.0\npydantic==2.12\n",
    )

    failures = lock_freshness.dependency_lock_freshness_errors(tmp_path)

    assert any("duplicate normalized dependency name 'pydantic'" in failure for failure in failures)


def test_installed_minimum_verifier_requires_exact_direct_versions(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _write_project(tmp_path, marker_digest=None)
    monkeypatch.setattr(lock_freshness, "distribution_version", lambda _name: "2.12.1")

    failures = lock_freshness.installed_minimum_version_errors(tmp_path)

    assert failures == (
        "installed minimum profile: pydantic version 2.12.1 does not match exact minimum 2.12.0",
    )
