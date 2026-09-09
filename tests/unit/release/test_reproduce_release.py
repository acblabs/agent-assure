from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import reproduce_release  # noqa: E402
from reproduce_release import (  # noqa: E402
    RELEASE_SOURCE_DATE_EPOCH,
    ReleaseCommand,
    _release_env,
    release_commands,
    run_release_commands,
)

from agent_assure.release_evidence import (  # noqa: E402
    LEGACY_CORE_RELEASE_ROLES,
    DigestReplayVerification,
)
from agent_assure.schema.release import ReleaseDigestReplay  # noqa: E402


def test_run_release_commands_writes_step_log(tmp_path: Path) -> None:
    command = ReleaseCommand(
        "sample-step",
        [sys.executable, "-c", "print('hello release log')"],
        expected_exit=0,
    )

    result = run_release_commands((command,), logs_dir=tmp_path / "logs")

    assert result == 0
    log_text = (tmp_path / "logs" / "sample-step.log").read_text(encoding="utf-8")
    assert "hello release log" in log_text
    assert "[exit 0]" in log_text


def test_run_release_commands_returns_unexpected_exit_and_keeps_log(tmp_path: Path) -> None:
    command = ReleaseCommand(
        "failing-step",
        [sys.executable, "-c", "print('bad exit'); raise SystemExit(5)"],
        expected_exit=0,
    )

    result = run_release_commands((command,), logs_dir=tmp_path / "logs")

    assert result == 5
    log_text = (tmp_path / "logs" / "failing-step.log").read_text(encoding="utf-8")
    assert "bad exit" in log_text
    assert "[exit 5]" in log_text


def test_release_commands_reject_external_suite(tmp_path: Path) -> None:
    with tempfile.TemporaryDirectory() as external_root:
        external_suite = Path(external_root) / "external.yaml"
        external_suite.write_text("suite_id: external\n", encoding="utf-8")

        try:
            release_commands(
                tmp_path / "release",
                suite=str(external_suite),
                baseline_variant="examples/prior_auth_synthetic/variants/baseline.yaml",
                candidate_variant=(
                    "examples/prior_auth_synthetic/variants/candidate_evidence_normalization.yaml"
                ),
                artifact_prefix="prior-auth",
            )
        except ValueError as exc:
            assert "suite must stay under the repository root" in str(exc)
        else:
            raise AssertionError("expected external suite to fail")


def test_release_commands_pin_ci_evaluation_date(tmp_path: Path) -> None:
    commands = release_commands(
        tmp_path / "release",
        suite="examples/prior_auth_synthetic/suite.yaml",
        baseline_variant="examples/prior_auth_synthetic/variants/baseline.yaml",
        candidate_variant=(
            "examples/prior_auth_synthetic/variants/candidate_evidence_normalization.yaml"
        ),
        artifact_prefix="prior-auth",
        release_today="2030-01-02",
    )

    ci_command = next(command.command for command in commands if command.name == "ci-gate")
    today_index = ci_command.index("--today")
    assert ci_command[today_index + 1] == "2030-01-02"
    assert ci_command.count("--allow-missing-efficacy-for-migration") == 1


def test_release_env_sets_default_source_date_epoch(monkeypatch) -> None:
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)

    env = _release_env()

    assert env["SOURCE_DATE_EPOCH"] == RELEASE_SOURCE_DATE_EPOCH


def test_release_workflows_share_reproduction_epoch() -> None:
    for workflow in (
        ROOT / ".github" / "workflows" / "release.yml",
        ROOT / ".github" / "workflows" / "evidence.yml",
        ROOT / ".github" / "workflows" / "publish-testpypi.yml",
    ):
        text = workflow.read_text(encoding="utf-8")
        assert f'SOURCE_DATE_EPOCH: "{RELEASE_SOURCE_DATE_EPOCH}"' in text


def test_expected_digest_replay_uses_historical_core_role_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = ReleaseDigestReplay(schema_version="0.6.2", artifacts=())
    generated = ReleaseDigestReplay(artifacts=())
    captured: dict[str, object] = {}

    monkeypatch.setattr(
        reproduce_release,
        "run_release_commands",
        lambda commands, *, logs_dir: 0,
    )
    monkeypatch.setattr(
        reproduce_release,
        "build_digest_replay",
        lambda artifacts, **kwargs: generated,
    )
    monkeypatch.setattr(
        reproduce_release,
        "write_digest_replay",
        lambda replay, path: None,
    )
    monkeypatch.setattr(
        reproduce_release,
        "load_digest_replay",
        lambda path: expected,
    )

    def fake_verify_digest_replay(
        replay: ReleaseDigestReplay,
        *,
        artifact_root: Path,
        required_roles: tuple[str, ...],
        require_current_commit: bool,
    ) -> DigestReplayVerification:
        captured["replay"] = replay
        captured["artifact_root"] = artifact_root
        captured["required_roles"] = required_roles
        captured["require_current_commit"] = require_current_commit
        return DigestReplayVerification(replay=replay, findings=())

    monkeypatch.setattr(
        reproduce_release,
        "verify_digest_replay",
        fake_verify_digest_replay,
    )

    exit_code = reproduce_release.main(
        [
            "--out",
            str(tmp_path / "release"),
            "--expected-digests",
            str(tmp_path / "expected.json"),
        ]
    )

    assert exit_code == 0
    assert captured["replay"] is expected
    assert captured["required_roles"] == LEGACY_CORE_RELEASE_ROLES
    assert captured["require_current_commit"] is True
