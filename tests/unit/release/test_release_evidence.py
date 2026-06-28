from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agent_assure import release_evidence
from agent_assure.cli.main import app
from agent_assure.release_evidence import (
    CORE_RELEASE_ROLES,
    build_digest_replay,
    verify_digest_replay,
    write_digest_replay,
)
from agent_assure.schema.release import ReleaseArtifact

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
    assert finding.actual is not None
    assert finding.actual != finding.expected


def test_release_digest_replay_ignores_packet_environment_drift(tmp_path: Path) -> None:
    artifacts = _write_core_artifacts(tmp_path)
    replay = build_digest_replay(artifacts, project_root=tmp_path)
    packet_path = tmp_path / "evidence-packet.json"
    packet_path.write_text(
        json.dumps(
            {
                "artifact_kind": "evidence-packet",
                "schema_version": "0.2.0",
                "packet_id": "packet-demo",
                "interpretation": ["read candidate state first"],
                "evaluation": {
                    "artifact_kind": "evaluation-summary",
                    "schema_version": "0.2.0",
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


def test_release_digest_replay_ignores_manifest_environment_and_id_drift(
    tmp_path: Path,
) -> None:
    artifacts = _write_core_artifacts(tmp_path)
    replay = build_digest_replay(artifacts, project_root=tmp_path)
    manifest = json.loads((tmp_path / "release-artifact-manifest.json").read_text())
    manifest["environment"] = {"platform": "changed"}
    manifest["manifest_id"] = "manifest-changed"
    _write_json(tmp_path / "release-artifact-manifest.json", manifest)

    verification = verify_digest_replay(
        replay,
        artifact_root=tmp_path,
        required_roles=CORE_RELEASE_ROLES,
    )

    assert verification.ok


def test_release_digest_replay_detects_manifest_recorded_digest_mismatch(
    tmp_path: Path,
) -> None:
    artifacts = _write_core_artifacts(tmp_path)
    replay = build_digest_replay(artifacts, project_root=tmp_path)
    manifest = json.loads((tmp_path / "release-artifact-manifest.json").read_text())
    manifest["artifacts"][0]["sha256"] = "f" * 64
    _write_json(tmp_path / "release-artifact-manifest.json", manifest)

    verification = verify_digest_replay(
        replay,
        artifact_root=tmp_path,
        required_roles=CORE_RELEASE_ROLES,
    )

    assert not verification.ok
    finding = verification.findings[0]
    assert finding.role == "release-artifact-manifest"
    assert "recorded digest mismatch" in finding.message


def test_release_digest_replay_detects_manifest_referenced_release_only_drift(
    tmp_path: Path,
) -> None:
    artifacts = _write_core_artifacts(tmp_path)
    _write_json(
        tmp_path / "sbom.cdx.json",
        {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []},
    )
    (tmp_path / "agent_assure-0.1.0-py3-none-any.whl").write_bytes(b"wheel-v1")
    manifest = json.loads((tmp_path / "release-artifact-manifest.json").read_text())
    manifest["artifacts"].extend(
        [
            _manifest_artifact("sbom", tmp_path / "sbom.cdx.json", tmp_path),
            _manifest_artifact(
                "python-wheel",
                tmp_path / "agent_assure-0.1.0-py3-none-any.whl",
                tmp_path,
            ),
        ]
    )
    _write_json(tmp_path / "release-artifact-manifest.json", manifest)
    replay = build_digest_replay(artifacts, project_root=tmp_path)
    _write_json(
        tmp_path / "sbom.cdx.json",
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [{"name": "local-drift"}],
        },
    )
    (tmp_path / "agent_assure-0.1.0-py3-none-any.whl").write_bytes(b"wheel-v2")

    verification = verify_digest_replay(
        replay,
        artifact_root=tmp_path,
        required_roles=CORE_RELEASE_ROLES,
    )

    assert not verification.ok
    finding = verification.findings[0]
    assert finding.role == "release-artifact-manifest"
    assert "recorded digest mismatch" in finding.message


def test_release_digest_replay_rejects_release_only_artifacts_as_top_level_replay(
    tmp_path: Path,
) -> None:
    sbom = tmp_path / "sbom.cdx.json"
    _write_json(sbom, {"bomFormat": "CycloneDX", "specVersion": "1.5"})

    with pytest.raises(ValueError, match="recorded but not replayed"):
        build_digest_replay((("sbom", sbom),), project_root=tmp_path)


def test_release_digest_replay_detects_manifest_raw_child_drift(tmp_path: Path) -> None:
    artifacts = _write_core_artifacts(tmp_path)
    replay = build_digest_replay(artifacts, project_root=tmp_path)
    _write_json(
        tmp_path / "candidate-runset.json",
        {"artifact_kind": "run-set", "runset_id": "candidate-changed"},
    )

    verification = verify_digest_replay(
        replay,
        artifact_root=tmp_path,
        required_roles=CORE_RELEASE_ROLES,
    )

    assert not verification.ok
    finding = verification.findings[0]
    assert finding.role == "release-artifact-manifest"
    assert finding.actual != finding.expected


def test_release_digest_replay_reports_missing_manifest_child(tmp_path: Path) -> None:
    artifacts = _write_core_artifacts(tmp_path)
    replay = build_digest_replay(artifacts, project_root=tmp_path)
    (tmp_path / "evaluation-summary.json").unlink()

    verification = verify_digest_replay(
        replay,
        artifact_root=tmp_path,
        required_roles=CORE_RELEASE_ROLES,
    )

    assert not verification.ok
    finding = verification.findings[0]
    assert finding.role == "release-artifact-manifest"
    assert "could not be replayed" in finding.message


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


def test_release_digest_replay_rejects_unknown_top_level_role(tmp_path: Path) -> None:
    artifacts = _write_core_artifacts(tmp_path)
    replay = build_digest_replay(artifacts, project_root=tmp_path)
    tampered_artifact = replay.artifacts[0].model_copy(update={"role": "unknown-role"})
    tampered = replay.model_copy(update={"artifacts": (tampered_artifact, *replay.artifacts[1:])})

    verification = verify_digest_replay(
        tampered,
        artifact_root=tmp_path,
        required_roles=CORE_RELEASE_ROLES,
    )

    assert not verification.ok
    assert any(
        "unknown release artifact role" in finding.message for finding in verification.findings
    )


def test_release_digest_replay_rejects_escaped_artifact_path(tmp_path: Path) -> None:
    artifacts = _write_core_artifacts(tmp_path)
    replay = build_digest_replay(artifacts, project_root=tmp_path)
    tampered_artifact = replay.artifacts[0].model_copy(update={"path": "../outside.json"})
    tampered = replay.model_copy(update={"artifacts": (tampered_artifact, *replay.artifacts[1:])})

    verification = verify_digest_replay(
        tampered,
        artifact_root=tmp_path,
        required_roles=CORE_RELEASE_ROLES,
    )

    assert not verification.ok
    assert "parent-directory segments are not allowed" in verification.findings[0].message


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


def test_release_replay_cli_checks_expected_commit_against_replay_file(
    tmp_path: Path,
) -> None:
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

    assert result.exit_code == 0


def test_release_replay_cli_reports_expected_commit_mismatch(tmp_path: Path) -> None:
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
            "def456",
        ],
    )

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["findings"][0]["role"] == "source-commit"
    assert payload["findings"][0]["expected"] == "def456"
    assert payload["findings"][0]["actual"] == "abc123"
    assert "source_commit mismatch" in payload["findings"][0]["message"]


def test_release_digest_replay_checks_expected_ref(tmp_path: Path) -> None:
    artifacts = _write_core_artifacts(tmp_path)
    replay = build_digest_replay(
        artifacts,
        project_root=tmp_path,
        source_commit="abc123",
        source_ref="refs/tags/v0.1.0",
    )

    matching = verify_digest_replay(
        replay,
        artifact_root=tmp_path,
        required_roles=CORE_RELEASE_ROLES,
        expect_ref="refs/tags/v0.1.0",
    )
    mismatched = verify_digest_replay(
        replay,
        artifact_root=tmp_path,
        required_roles=CORE_RELEASE_ROLES,
        expect_ref="refs/tags/v0.2.0",
    )

    assert matching.ok
    assert not mismatched.ok
    assert mismatched.findings[0].role == "source-ref"
    assert mismatched.findings[0].actual == "refs/tags/v0.1.0"


def test_release_digest_replay_requires_current_commit_against_replay_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifacts = _write_core_artifacts(tmp_path)
    replay = build_digest_replay(artifacts, project_root=tmp_path, source_commit="abc123")

    def fake_git_output(project_root: Path, *args: str) -> str:
        return "def456"

    monkeypatch.setattr(release_evidence, "git_output", fake_git_output)

    verification = verify_digest_replay(
        replay,
        artifact_root=tmp_path,
        required_roles=CORE_RELEASE_ROLES,
        expect_commit="abc123",
        require_current_commit=True,
    )

    assert not verification.ok
    assert len(verification.findings) == 1
    finding = verification.findings[0]
    assert finding.role == "source-commit"
    assert finding.expected == "abc123"
    assert finding.actual == "def456"
    assert "current checkout commit mismatch" in finding.message


def _write_core_artifacts(tmp_path: Path) -> tuple[tuple[str, Path], ...]:
    compiled = tmp_path / "compiled-suite.json"
    fixture_manifest = tmp_path / "fixture-manifest.json"
    candidate_runset = tmp_path / "candidate-runset.json"
    baseline_runset = tmp_path / "baseline-runset.json"
    evaluation_summary = tmp_path / "evaluation-summary.json"
    comparison_summary = tmp_path / "comparison-summary.json"
    dependency_inventory = tmp_path / "dependency-inventory.json"
    evidence_packet = tmp_path / "evidence-packet.json"
    release_manifest = tmp_path / "release-artifact-manifest.json"

    _write_json(compiled, {"artifact_kind": "compiled-suite", "suite_id": "demo"})
    _write_json(
        fixture_manifest,
        {"artifact_kind": "fixture-manifest", "suite_id": "demo", "entries": []},
    )
    _write_json(candidate_runset, {"artifact_kind": "run-set", "runset_id": "candidate"})
    _write_json(baseline_runset, {"artifact_kind": "run-set", "runset_id": "baseline"})
    _write_json(
        evaluation_summary,
        {
            "artifact_kind": "evaluation-summary",
            "schema_version": "0.2.0",
            "runset_id": "candidate",
            "state": "fail",
            "environment": {"platform": "original"},
        },
    )
    _write_json(
        comparison_summary,
        {
            "artifact_kind": "comparison-summary",
            "schema_version": "0.2.0",
            "baseline_runset_id": "baseline",
            "candidate_runset_id": "candidate",
            "classification": "new_failure",
            "environment": {"platform": "original"},
        },
    )
    _write_json(
        dependency_inventory,
        {
            "artifact_kind": "dependency-inventory",
            "components": [{"name": "agent-assure", "version": "0.1.0"}],
        },
    )
    manifest_payload = {
        "artifact_kind": "release-artifact-manifest",
        "schema_version": "0.2.0",
        "manifest_id": "manifest-original",
        "environment": {"platform": "original"},
        "artifacts": [
            _manifest_artifact("compiled-suite", compiled, tmp_path),
            _manifest_artifact("candidate-runset", candidate_runset, tmp_path),
            _manifest_artifact("evaluation-summary", evaluation_summary, tmp_path),
            _manifest_artifact("dependency-inventory", dependency_inventory, tmp_path),
            _manifest_artifact("baseline-runset", baseline_runset, tmp_path),
            _manifest_artifact("comparison-summary", comparison_summary, tmp_path),
        ],
    }
    _write_json(release_manifest, manifest_payload)
    _write_json(
        evidence_packet,
        {
            "artifact_kind": "evidence-packet",
            "schema_version": "0.2.0",
            "packet_id": "packet-demo",
            "interpretation": ["read candidate state first"],
            "evaluation": {
                "artifact_kind": "evaluation-summary",
                "schema_version": "0.2.0",
                "runset_id": "candidate",
                "state": "fail",
                "environment": {"platform": "original"},
            },
            "environment": {"platform": "original"},
            "release_manifest": manifest_payload,
            "artifact_digests": [{"sha256": "0" * 64}],
            "limitations": ["deterministic fixture-mode evidence only"],
        },
    )
    return (
        ("compiled-suite", compiled),
        ("fixture-manifest", fixture_manifest),
        ("evidence-packet", evidence_packet),
        ("release-artifact-manifest", release_manifest),
    )


def _manifest_artifact(role: str, path: Path, root: Path) -> dict[str, str]:
    return ReleaseArtifact(
        artifact_kind="release-artifact",
        role=role,
        path=path.resolve().relative_to(root.resolve()).as_posix(),
        sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
    ).model_dump(mode="json")


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
