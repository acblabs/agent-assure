from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from agent_assure.cli.main import app
from agent_assure.release_evidence import (
    CORE_RELEASE_ROLES,
    build_digest_replay,
    verify_digest_replay,
    write_digest_replay,
)

RUNNER = CliRunner()


def test_release_digest_replay_verifies_core_artifacts(tmp_path: Path) -> None:
    artifacts = _write_core_artifacts(tmp_path)
    replay = build_digest_replay(artifacts, project_root=tmp_path, source_commit="abc123")

    verification = verify_digest_replay(
        replay,
        artifact_root=tmp_path,
        required_roles=CORE_RELEASE_ROLES,
    )

    assert verification.ok
    assert replay.source_commit == "abc123"
    assert [artifact.role for artifact in replay.artifacts] == list(CORE_RELEASE_ROLES)
    assert [
        artifact.digest_mode for artifact in replay.artifacts
    ] == [
        "raw-sha256",
        "raw-sha256",
        "replay-stable-json-sha256",
        "replay-stable-json-sha256",
    ]


def test_release_digest_replay_reports_modified_artifact(tmp_path: Path) -> None:
    artifacts = _write_core_artifacts(tmp_path)
    replay = build_digest_replay(artifacts, project_root=tmp_path)
    (tmp_path / "evidence-packet.json").write_text(
        json.dumps(
            {
                "artifact_kind": "evidence-packet",
                "evaluation": {"artifact_kind": "evaluation-summary", "state": "fail"},
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )

    verification = verify_digest_replay(
        replay,
        artifact_root=tmp_path,
        required_roles=CORE_RELEASE_ROLES,
    )

    assert not verification.ok
    finding = verification.findings[0]
    assert finding.role == "evidence-packet"
    assert finding.actual_sha256 is not None
    assert finding.actual_sha256 != finding.expected_sha256


def test_release_digest_replay_ignores_packet_environment_drift(tmp_path: Path) -> None:
    artifacts = _write_core_artifacts(tmp_path)
    replay = build_digest_replay(artifacts, project_root=tmp_path)
    packet_path = tmp_path / "evidence-packet.json"
    packet_path.write_text(
        json.dumps(
            {
                "artifact_kind": "evidence-packet",
                "schema_version": "0.1.0",
                "packet_id": "packet-demo",
                "interpretation": ["read candidate state first"],
                "evaluation": {
                    "artifact_kind": "evaluation-summary",
                    "schema_version": "0.1.0",
                    "runset_id": "candidate",
                    "state": "fail",
                    "environment": {"platform": "different"},
                },
                "environment": {"platform": "different"},
                "artifact_digests": [{"sha256": "1" * 64}],
                "limitations": ["deterministic fixture-mode evidence only"],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )

    verification = verify_digest_replay(
        replay,
        artifact_root=tmp_path,
        required_roles=CORE_RELEASE_ROLES,
    )

    assert verification.ok


def test_release_digest_replay_rejects_unexpected_digest_mode(tmp_path: Path) -> None:
    artifacts = _write_core_artifacts(tmp_path)
    replay = build_digest_replay(artifacts, project_root=tmp_path)
    tampered_artifact = replay.artifacts[0].model_copy(
        update={"digest_mode": "replay-stable-json-sha256"}
    )
    tampered = replay.model_copy(update={"artifacts": (tampered_artifact, *replay.artifacts[1:])})

    verification = verify_digest_replay(
        tampered,
        artifact_root=tmp_path,
        required_roles=CORE_RELEASE_ROLES,
    )

    assert not verification.ok
    assert verification.findings[0].role == "compiled-suite"
    assert "digest_mode mismatch" in verification.findings[0].message


def test_release_replay_cli_exits_nonzero_for_missing_required_role(tmp_path: Path) -> None:
    packet = tmp_path / "evidence-packet.json"
    packet.write_text('{"artifact_kind":"evidence-packet"}\n', encoding="utf-8", newline="\n")
    replay = build_digest_replay((("evidence-packet", packet),), project_root=tmp_path)
    replay_path = tmp_path / "release-digest-replay.json"
    write_digest_replay(replay, replay_path)

    result = RUNNER.invoke(
        app,
        ["release", "replay", str(replay_path), "--artifact-root", str(tmp_path)],
    )

    assert result.exit_code == 1
    payload = json.loads(result.output)
    missing_roles = {finding["role"] for finding in payload["findings"]}
    assert "compiled-suite" in missing_roles


def test_release_replay_cli_checks_expected_commit(tmp_path: Path) -> None:
    artifacts = _write_core_artifacts(tmp_path)
    replay = build_digest_replay(artifacts, project_root=tmp_path, source_commit="abc123")
    replay_path = tmp_path / "release-digest-replay.json"
    write_digest_replay(replay, replay_path)

    result = RUNNER.invoke(
        app,
        [
            "release",
            "replay",
            str(replay_path),
            "--artifact-root",
            str(tmp_path),
            "--expect-commit",
            "abc123",
        ],
    )

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["findings"][0]["role"] == "source-commit"
    assert "could not be determined" in payload["findings"][0]["message"]


def _write_core_artifacts(tmp_path: Path) -> tuple[tuple[str, Path], ...]:
    artifacts: list[tuple[str, Path]] = []
    for role in CORE_RELEASE_ROLES:
        path = tmp_path / f"{role}.json"
        payload: dict[str, object] = {"artifact_kind": role, "role": role}
        if role == "evidence-packet":
            payload = {
                "artifact_kind": "evidence-packet",
                "schema_version": "0.1.0",
                "packet_id": "packet-demo",
                "interpretation": ["read candidate state first"],
                "evaluation": {
                    "artifact_kind": "evaluation-summary",
                    "schema_version": "0.1.0",
                    "runset_id": "candidate",
                    "state": "fail",
                    "environment": {"platform": "original"},
                },
                "environment": {"platform": "original"},
                "artifact_digests": [{"sha256": "0" * 64}],
                "limitations": ["deterministic fixture-mode evidence only"],
            }
        if role == "release-artifact-manifest":
            payload["artifacts"] = []
        path.write_text(
            json.dumps(payload, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        artifacts.append((role, path))
    return tuple(artifacts)
