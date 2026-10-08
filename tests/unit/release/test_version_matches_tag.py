from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

import scripts.check_version_matches_tag as version_tag


def test_version_tag_check_accepts_matching_package_schema_and_frozen_dir(
    tmp_path: Path,
) -> None:
    pyproject, package_init, schema_base, schema_root = _write_version_files(
        tmp_path,
        project_version="1.2.3",
        package_version="1.2.3",
        package_schema_version="1.2.3",
        base_schema_version="1.2.3",
    )

    result = version_tag.main(
        [
            "v1.2.3",
            "--pyproject",
            str(pyproject),
            "--package-init",
            str(package_init),
            "--schema-base",
            str(schema_base),
            "--schema-root",
            str(schema_root),
        ]
    )

    assert result == 0


def test_version_tag_check_rejects_schema_version_mismatch(tmp_path: Path) -> None:
    pyproject, package_init, schema_base, schema_root = _write_version_files(
        tmp_path,
        project_version="1.2.3",
        package_version="1.2.3",
        package_schema_version="1.2.4",
        base_schema_version="1.2.3",
    )

    result = version_tag.main(
        [
            "v1.2.3",
            "--pyproject",
            str(pyproject),
            "--package-init",
            str(package_init),
            "--schema-base",
            str(schema_base),
            "--schema-root",
            str(schema_root),
        ]
    )

    assert result == 1


def test_version_tag_check_allows_release_candidate_with_base_schema(
    tmp_path: Path,
) -> None:
    pyproject, package_init, schema_base, schema_root = _write_version_files(
        tmp_path,
        project_version="1.2.3rc1",
        package_version="1.2.3rc1",
        package_schema_version="1.2.3",
        base_schema_version="1.2.3",
        schema_dir_version="1.2.3",
    )

    result = version_tag.main(
        [
            "v1.2.3rc1",
            "--pyproject",
            str(pyproject),
            "--package-init",
            str(package_init),
            "--schema-base",
            str(schema_base),
            "--schema-root",
            str(schema_root),
        ]
    )

    assert result == 0


def test_release_schema_version_maps_package_only_stable_and_candidate() -> None:
    assert version_tag.release_schema_version("0.7.0") == "0.6.6"
    assert version_tag.release_schema_version("0.7.0rc1") == "0.6.6"


def test_version_tag_check_rejects_release_candidate_when_stable_is_required(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    pyproject, package_init, schema_base, schema_root = _write_version_files(
        tmp_path,
        project_version="1.2.3rc1",
        package_version="1.2.3rc1",
        package_schema_version="1.2.3",
        base_schema_version="1.2.3",
        schema_dir_version="1.2.3",
    )

    result = version_tag.main(
        [
            "v1.2.3rc1",
            "--require-stable",
            "--pyproject",
            str(pyproject),
            "--package-init",
            str(package_init),
            "--schema-base",
            str(schema_base),
            "--schema-root",
            str(schema_root),
            "--security",
            str(tmp_path / "missing-security-policy.md"),
        ]
    )

    assert result == 1
    stderr = capsys.readouterr().err
    assert "production release requires a stable X.Y.Z version" in stderr
    assert "could not read security support policy" not in stderr


def test_version_tag_check_allows_package_release_with_unchanged_schema(
    tmp_path: Path,
) -> None:
    pyproject, package_init, schema_base, schema_root = _write_version_files(
        tmp_path,
        project_version="0.7.0",
        package_version="0.7.0",
        package_schema_version="0.6.6",
        base_schema_version="0.6.6",
        schema_dir_version="0.6.6",
    )

    result = version_tag.main(
        [
            "v0.7.0",
            "--pyproject",
            str(pyproject),
            "--package-init",
            str(package_init),
            "--schema-base",
            str(schema_base),
            "--schema-root",
            str(schema_root),
        ]
    )

    assert result == 0


def test_version_tag_check_rejects_missing_frozen_schema_dir(tmp_path: Path) -> None:
    pyproject, package_init, schema_base, schema_root = _write_version_files(
        tmp_path,
        project_version="1.2.3",
        package_version="1.2.3",
        package_schema_version="1.2.3",
        base_schema_version="1.2.3",
        create_schema_dir=False,
    )

    result = version_tag.main(
        [
            "v1.2.3",
            "--pyproject",
            str(pyproject),
            "--package-init",
            str(package_init),
            "--schema-base",
            str(schema_base),
            "--schema-root",
            str(schema_root),
        ]
    )

    assert result == 1


def test_stable_release_requires_truth_preserving_security_transition(
    tmp_path: Path,
) -> None:
    pyproject, package_init, schema_base, schema_root = _write_version_files(
        tmp_path,
        project_version="1.2.3",
        package_version="1.2.3",
        package_schema_version="1.2.3",
        base_schema_version="1.2.3",
    )
    security = _write_security_policy(
        tmp_path,
        release_version="1.2.3",
        predecessor_version="1.2.2",
    )
    collateral = _write_release_collateral(tmp_path, release_version="1.2.3")

    result = version_tag.main(
        [
            "v1.2.3",
            "--require-stable",
            "--pyproject",
            str(pyproject),
            "--package-init",
            str(package_init),
            "--schema-base",
            str(schema_base),
            "--schema-root",
            str(schema_root),
            "--security",
            str(security),
            *_release_collateral_args(collateral),
        ]
    )

    assert result == 0


@pytest.mark.parametrize(
    ("release_status", "predecessor_status", "expected_error"),
    (
        (
            "Unreleased candidate; supported only after publication",
            "Supported only until 1.2.3 is published; unsupported thereafter",
            "support row for 1.2.3 must be",
        ),
        (
            version_tag.SECURITY_RELEASE_TRANSITION_STATUS,
            "Current published stable",
            "support row for predecessor 1.2.2 must be",
        ),
    ),
)
def test_stable_release_rejects_stale_security_support_rows(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    release_status: str,
    predecessor_status: str,
    expected_error: str,
) -> None:
    pyproject, package_init, schema_base, schema_root = _write_version_files(
        tmp_path,
        project_version="1.2.3",
        package_version="1.2.3",
        package_schema_version="1.2.3",
        base_schema_version="1.2.3",
    )
    security = _write_security_policy(
        tmp_path,
        release_version="1.2.3",
        predecessor_version="1.2.2",
        release_status=release_status,
        predecessor_status=predecessor_status,
    )
    collateral = _write_release_collateral(tmp_path, release_version="1.2.3")

    result = version_tag.main(
        [
            "v1.2.3",
            "--require-stable",
            "--pyproject",
            str(pyproject),
            "--package-init",
            str(package_init),
            "--schema-base",
            str(schema_base),
            "--schema-root",
            str(schema_root),
            "--security",
            str(security),
            *_release_collateral_args(collateral),
        ]
    )

    assert result == 1
    assert expected_error in capsys.readouterr().err


def test_nonproduction_version_check_does_not_read_security_policy(
    tmp_path: Path,
) -> None:
    pyproject, package_init, schema_base, schema_root = _write_version_files(
        tmp_path,
        project_version="1.2.3",
        package_version="1.2.3",
        package_schema_version="1.2.3",
        base_schema_version="1.2.3",
    )

    result = version_tag.main(
        [
            "v1.2.3",
            "--pyproject",
            str(pyproject),
            "--package-init",
            str(package_init),
            "--schema-base",
            str(schema_base),
            "--schema-root",
            str(schema_root),
            "--security",
            str(tmp_path / "missing-security-policy.md"),
        ]
    )

    assert result == 0


def test_repository_security_policy_has_v070_prepublication_transition() -> None:
    assert (
        version_tag.check_security_support_transition(
            version_tag.SECURITY_POLICY,
            release_version="0.7.0",
        )
        == []
    )


def test_stable_preflight_is_stdlib_only_without_site_packages(tmp_path: Path) -> None:
    pyproject, package_init, schema_base, schema_root = _write_version_files(
        tmp_path,
        project_version="1.2.3",
        package_version="1.2.3",
        package_schema_version="1.2.3",
        base_schema_version="1.2.3",
    )
    security = _write_security_policy(
        tmp_path,
        release_version="1.2.3",
        predecessor_version="1.2.2",
    )
    collateral = _write_release_collateral(tmp_path, release_version="1.2.3")
    completed = subprocess.run(
        (
            sys.executable,
            "-S",
            str(version_tag.ROOT / "scripts" / "check_version_matches_tag.py"),
            "v1.2.3",
            "--require-stable",
            "--pyproject",
            str(pyproject),
            "--package-init",
            str(package_init),
            "--schema-base",
            str(schema_base),
            "--schema-root",
            str(schema_root),
            "--security",
            str(security),
            *_release_collateral_args(collateral),
        ),
        cwd=version_tag.ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "version-tag: ok (v1.2.3)"


def test_repository_stable_preflight_accepts_final_v070_release_collateral(
    capsys: pytest.CaptureFixture[str],
) -> None:
    result = version_tag.main(["v0.7.0", "--require-stable"])

    assert result == 0
    captured = capsys.readouterr()
    assert captured.out.strip() == "version-tag: ok (v0.7.0)"
    assert captured.err == ""


def test_stdlib_diagnostics_are_bounded_single_line_and_redacted() -> None:
    secret = "release-boundary-secret-value"

    diagnostic = version_tag.bounded_text(
        f"failed\npassword={secret} " + "x" * version_tag.MAX_DIAGNOSTIC_SCAN_CHARS
    )

    assert secret not in diagnostic
    assert version_tag.DIAGNOSTIC_REDACTION in diagnostic
    assert "\n" not in diagnostic
    assert len(diagnostic) <= version_tag.MAX_DIAGNOSTIC_CHARS


def test_stable_release_rejects_missing_security_policy(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    pyproject, package_init, schema_base, schema_root = _write_version_files(
        tmp_path,
        project_version="1.2.3",
        package_version="1.2.3",
        package_schema_version="1.2.3",
        base_schema_version="1.2.3",
    )
    collateral = _write_release_collateral(tmp_path, release_version="1.2.3")

    result = version_tag.main(
        [
            "v1.2.3",
            "--require-stable",
            "--pyproject",
            str(pyproject),
            "--package-init",
            str(package_init),
            "--schema-base",
            str(schema_base),
            "--schema-root",
            str(schema_root),
            "--security",
            str(tmp_path / "missing-security-policy.md"),
            *_release_collateral_args(collateral),
        ]
    )

    assert result == 1
    assert "could not read security support policy" in capsys.readouterr().err


def test_stable_release_rejects_duplicate_security_support_row(tmp_path: Path) -> None:
    security = _write_security_policy(
        tmp_path,
        release_version="1.2.3",
        predecessor_version="1.2.2",
    )
    security.write_text(
        security.read_text(encoding="utf-8").replace(
            "## Reporting",
            "| 1.2.3 | Supported upon publication; unsupported before publication |\n\n"
            "## Reporting",
        ),
        encoding="utf-8",
    )

    failures = version_tag.check_security_support_transition(
        security,
        release_version="1.2.3",
    )

    assert any("duplicate support rows for 1.2.3" in failure for failure in failures)


def test_release_runbook_requires_stable_support_transition_check() -> None:
    runbook = (version_tag.ROOT / "docs" / "release_pypi.md").read_text(encoding="utf-8")

    assert "0.7.0` **Supported upon publication;" in runbook
    assert "0.6.5` **Supported only until 0.7.0" in runbook
    assert "without claiming that v0.7.0 has\n   already been published" in runbook
    assert runbook.count("python scripts/check_version_matches_tag.py v0.7.0 --require-stable") == 3


def _write_version_files(
    tmp_path: Path,
    *,
    project_version: str,
    package_version: str,
    package_schema_version: str,
    base_schema_version: str,
    create_schema_dir: bool = True,
    schema_dir_version: str | None = None,
) -> tuple[Path, Path, Path, Path]:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        f"[project]\nversion = {project_version!r}\n",
        encoding="utf-8",
    )
    package_init = tmp_path / "__init__.py"
    package_init.write_text(
        f"__version__ = {package_version!r}\nSCHEMA_VERSION = {package_schema_version!r}\n",
        encoding="utf-8",
    )
    schema_base = tmp_path / "base.py"
    schema_base.write_text(
        f"SCHEMA_VERSION = {base_schema_version!r}\n",
        encoding="utf-8",
    )
    schema_root = tmp_path / "schemas"
    if create_schema_dir:
        (schema_root / f"v{schema_dir_version or project_version}").mkdir(parents=True)
    return pyproject, package_init, schema_base, schema_root


def _write_security_policy(
    tmp_path: Path,
    *,
    release_version: str,
    predecessor_version: str,
    release_status: str = version_tag.SECURITY_RELEASE_TRANSITION_STATUS,
    predecessor_status: str | None = None,
) -> Path:
    if predecessor_status is None:
        predecessor_status = (
            f"Supported only until {release_version} is published; unsupported thereafter"
        )
    security = tmp_path / "SECURITY.md"
    security.write_text(
        "# Security\n\n"
        "## Supported Versions\n\n"
        "| Version | Security-maintenance status |\n"
        "| --- | --- |\n"
        f"| {release_version} | {release_status} |\n"
        f"| {predecessor_version} | {predecessor_status} |\n\n"
        "## Reporting\n\nReport privately.\n",
        encoding="utf-8",
    )
    return security


def _write_release_collateral(
    tmp_path: Path,
    *,
    release_version: str,
    release_date: str = "2026-10-06",
) -> tuple[Path, Path, Path]:
    action = tmp_path / ".github" / "actions" / "agent-assure" / "action.yml"
    action.parent.mkdir(parents=True)
    action.write_text("name: frozen\n", encoding="utf-8")
    _run_test_git(tmp_path, "init", "-b", "main")
    _run_test_git(tmp_path, "config", "user.name", "Release Test")
    _run_test_git(tmp_path, "config", "user.email", "release-test@example.invalid")
    _run_test_git(tmp_path, "add", "--", ".github/actions/agent-assure/action.yml")
    _run_test_git(tmp_path, "commit", "-m", "freeze action")
    action_commit = _test_git_stdout(tmp_path, "rev-parse", "HEAD")

    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(
        "# Changelog\n\n"
        "## Unreleased\n\n"
        f"## {release_version} - {release_date}\n\n"
        "- Released.\n\n"
        "## 1.2.2 - 2026-10-05\n\n"
        "- Previous.\n",
        encoding="utf-8",
    )
    citation = tmp_path / "CITATION.cff"
    citation.write_text(
        f"cff-version: 1.2.0\nversion: {release_version}\ndate-released: {release_date}\n",
        encoding="utf-8",
    )
    readme = tmp_path / "README.md"
    readme.write_text(
        "## Integrate your agent\n\n"
        "### GitHub Actions example using the bundled fixture\n\n"
        "```yaml\n"
        f"- run: pip install agent-assure=={release_version}\n"
        f"# agent-assure v{release_version}\n"
        "- uses: acblabs/agent-assure/.github/actions/agent-assure@"
        f"{action_commit}\n"
        "```\n\n"
        "### Next section\n",
        encoding="utf-8",
    )
    _run_test_git(tmp_path, "add", "--all")
    _run_test_git(tmp_path, "commit", "-m", "final release collateral")
    return changelog, citation, readme


def _release_collateral_args(collateral: tuple[Path, Path, Path]) -> tuple[str, ...]:
    changelog, citation, readme = collateral
    return (
        "--changelog",
        str(changelog),
        "--citation",
        str(citation),
        "--readme",
        str(readme),
        "--repository-root",
        str(changelog.parent),
    )


def _run_test_git(root: Path, *arguments: str) -> None:
    subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )


def _test_git_stdout(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return completed.stdout.strip().lower()
