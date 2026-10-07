from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from scripts.check_security_maintenance_release import (
    SecurityMaintenanceReleaseError,
    check_security_maintenance_release,
)


def _git(root: Path, *arguments: str) -> None:
    subprocess.run(
        ("git", "-C", str(root), *arguments),
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _write(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def _repository(tmp_path: Path, *, release: str = "0.6.6") -> Path:
    root = tmp_path / "repository"
    root.mkdir()
    _git(root, "init")
    _git(root, "config", "user.name", "Maintenance Test")
    _git(root, "config", "user.email", "maintenance@example.invalid")
    _write(
        root / "pyproject.toml",
        '[project]\nname = "agent-assure-test"\nversion = "0.6.5"\n',
    )
    _write(root / "README.md", "Frozen release claim.\n")
    _write(root / "src" / "implementation.py", "VALUE = 1\n")
    _git(root, "add", "--all")
    _git(root, "commit", "-m", "base release")
    _git(root, "tag", "-a", "v0.6.5", "-m", "base release")

    _write(
        root / "pyproject.toml",
        f'[project]\nname = "agent-assure-test"\nversion = "{release}"\n',
    )
    _write(root / "CHANGELOG.md", f"Security correction {release}.\n")
    _write(
        root / "docs" / "release_notes" / f"v{release}.md",
        "# Security correction\n\nRelease profile: `security-maintenance`\n",
    )
    _write(root / "src" / "implementation.py", "VALUE = 2  # corrective change\n")
    _git(root, "add", "--all")
    _git(root, "commit", "-m", "security maintenance release")
    return root


def test_security_maintenance_guard_accepts_a_clean_next_patch(tmp_path: Path) -> None:
    root = _repository(tmp_path)

    changed = check_security_maintenance_release(
        root=root,
        expected_release="0.6.6",
        base_tag="v0.6.5",
    )

    assert "src/implementation.py" in changed
    assert "docs/release_notes/v0.6.6.md" in changed


@pytest.mark.parametrize(
    "protected_path",
    (
        "evidence/empirical/study.json",
        "docs/measurement/result.md",
        "paper/registered-result.md",
        "study/registration/frozen-study.json",
        "examples/process_equivalence_benchmark_v0_2/README.md",
    ),
)
def test_security_maintenance_guard_rejects_protected_claim_changes(
    tmp_path: Path,
    protected_path: str,
) -> None:
    root = _repository(tmp_path)
    _write(root / protected_path, "changed empirical claim\n")
    _git(root, "add", "--all")
    _git(root, "commit", "-m", "attempt claim change")

    with pytest.raises(
        SecurityMaintenanceReleaseError,
        match="changes protected claim surfaces",
    ):
        check_security_maintenance_release(
            root=root,
            expected_release="0.6.6",
            base_tag="v0.6.5",
        )


def test_security_maintenance_guard_allows_required_release_collateral(
    tmp_path: Path,
) -> None:
    root = _repository(tmp_path)
    collateral = {
        "README.md": "Published package pin: 0.6.6.\n",
        "schemas/v0.6.6/report.json": "{}\n",
        "tests/golden/reports/study.md": "Version-bound rendering.\n",
        "compat/v0.6.6.json": "{}\n",
    }
    for relative_path, value in collateral.items():
        _write(root / relative_path, value)
    _git(root, "add", "--all")
    _git(root, "commit", "-m", "refresh required release collateral")

    changed = check_security_maintenance_release(
        root=root,
        expected_release="0.6.6",
        base_tag="v0.6.5",
    )

    assert collateral.keys() <= set(changed)


def test_security_maintenance_guard_rejects_non_patch_release(tmp_path: Path) -> None:
    root = _repository(tmp_path, release="0.7.0")

    with pytest.raises(
        SecurityMaintenanceReleaseError,
        match="must be the next patch version",
    ):
        check_security_maintenance_release(
            root=root,
            expected_release="0.7.0",
            base_tag="v0.6.5",
        )


def test_security_maintenance_guard_rejects_dirty_worktree(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    _write(root / "uncommitted.txt", "not reviewed\n")

    with pytest.raises(
        SecurityMaintenanceReleaseError,
        match="clean committed worktree",
    ):
        check_security_maintenance_release(
            root=root,
            expected_release="0.6.6",
            base_tag="v0.6.5",
        )


@pytest.mark.parametrize(
    ("payload", "message"),
    (
        (
            b"Prefix Release profile: `security-maintenance`\n",
            "on an exact line",
        ),
        (b"\xff\n", "valid UTF-8"),
    ),
)
def test_security_maintenance_guard_rejects_malformed_release_note(
    tmp_path: Path,
    payload: bytes,
    message: str,
) -> None:
    root = _repository(tmp_path)
    note = root / "docs" / "release_notes" / "v0.6.6.md"
    note.write_bytes(payload)
    _git(root, "add", "--all")
    _git(root, "commit", "-m", "malform release note")

    with pytest.raises(SecurityMaintenanceReleaseError, match=message):
        check_security_maintenance_release(
            root=root,
            expected_release="0.6.6",
            base_tag="v0.6.5",
        )


def test_maintenance_checker_is_non_authorizing_and_disconnected_from_publication() -> None:
    root = Path(__file__).resolve().parents[3]
    makefile = (root / "Makefile").read_text(encoding="utf-8")
    workflow = (root / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    checker = (root / "scripts" / "check_security_maintenance_release.py").read_text(
        encoding="utf-8"
    )

    assert "release-security-maintenance-check" not in makefile
    assert "check_security_maintenance_release.py" not in makefile
    assert "security-maintenance" not in workflow
    assert "check_security_maintenance_release.py" not in workflow
    assert "make release-publish-check" in workflow
    assert "no publication authority granted" in checker
    assert "cannot replace the standard efficacy" in checker
