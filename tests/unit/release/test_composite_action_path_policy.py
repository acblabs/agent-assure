from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
VALIDATOR = ROOT / ".github" / "actions" / "agent-assure" / "validate_output_path.py"
ACTION = ROOT / ".github" / "actions" / "agent-assure" / "action.yml"


def _validate(candidate: Path | str, *roots: Path) -> subprocess.CompletedProcess[str]:
    command = [sys.executable, str(VALIDATOR), "--candidate", str(candidate)]
    for root in roots:
        command.extend(("--allowed-root", str(root)))
    return subprocess.run(command, check=False, capture_output=True, text=True)


@pytest.fixture
def action_roots(tmp_path: Path) -> tuple[Path, Path]:
    workspace = tmp_path / "workspace"
    runner_temp = tmp_path / "runner-temp"
    workspace.mkdir()
    runner_temp.mkdir()
    return workspace, runner_temp


@pytest.mark.parametrize("root_index", (0, 1), ids=("workspace", "runner-temp"))
def test_action_output_policy_accepts_children_of_either_approved_root(
    action_roots: tuple[Path, Path],
    root_index: int,
) -> None:
    selected_root = action_roots[root_index]

    result = _validate(selected_root / "new" / "reports", *action_roots)

    assert result.returncode == 0, result.stderr


def test_action_output_policy_rejects_an_outside_directory(
    tmp_path: Path,
    action_roots: tuple[Path, Path],
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()

    result = _validate(outside, *action_roots)

    assert result.returncode == 2
    assert "strictly below an approved root" in result.stderr


@pytest.mark.parametrize("root_index", (0, 1), ids=("workspace", "runner-temp"))
def test_action_output_policy_rejects_an_approved_root_itself(
    action_roots: tuple[Path, Path],
    root_index: int,
) -> None:
    result = _validate(action_roots[root_index], *action_roots)

    assert result.returncode == 2
    assert "strictly below an approved root" in result.stderr


def test_action_output_policy_rejects_a_filesystem_root(
    action_roots: tuple[Path, Path],
) -> None:
    filesystem_root = Path(action_roots[0].anchor)

    result = _validate(filesystem_root, *action_roots)

    assert result.returncode == 2
    assert "filesystem root" in result.stderr


def test_action_output_policy_rejects_lexical_parent_traversal(
    action_roots: tuple[Path, Path],
) -> None:
    workspace, runner_temp = action_roots
    traversing_path = f"{workspace}{Path('/nested/../reports')}"

    result = _validate(traversing_path, workspace, runner_temp)

    assert result.returncode == 2
    assert "parent traversal" in result.stderr


def test_action_output_policy_rejects_a_symlink_ancestor(
    action_roots: tuple[Path, Path],
) -> None:
    workspace, runner_temp = action_roots
    target = workspace / "real"
    target.mkdir()
    linked = workspace / "linked"
    try:
        linked.symlink_to(target, target_is_directory=True)
    except OSError as exc:
        if sys.platform != "win32":
            pytest.skip(f"directory symlinks are unavailable: {exc}")
        junction = subprocess.run(
            ("cmd.exe", "/d", "/c", "mklink", "/J", str(linked), str(target)),
            check=False,
            capture_output=True,
            text=True,
        )
        if junction.returncode != 0:
            pytest.skip(f"directory links are unavailable: {junction.stderr or exc}")

    result = _validate(linked / "reports", workspace, runner_temp)

    assert result.returncode == 2
    assert "linked or reparse-point ancestor" in result.stderr


def test_strict_action_policy_rejects_runner_temp_while_migration_policy_accepts_it(
    action_roots: tuple[Path, Path],
) -> None:
    workspace, runner_temp = action_roots
    output = runner_temp / "reports"

    migration_result = _validate(output, workspace, runner_temp)
    strict_result = _validate(output, workspace)

    assert migration_result.returncode == 0, migration_result.stderr
    assert strict_result.returncode == 2
    assert "strictly below an approved root" in strict_result.stderr


def test_action_revalidates_reports_directory_before_and_after_creation() -> None:
    action = ACTION.read_text(encoding="utf-8")

    invocation = 'validate_output_path "${AGENT_ASSURE_ACTION_OUT_DIR}/reports"'
    assert action.count(invocation) == 2
