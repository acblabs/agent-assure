from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import get_args

import pytest
from typer.testing import CliRunner

from agent_assure import release_evidence
from agent_assure.cli.main import app
from agent_assure.graph.builder import build_evidence_graph
from agent_assure.release_evidence import (
    CORE_RELEASE_ROLES,
    LEGACY_CORE_RELEASE_ROLES,
    build_digest_replay,
    core_release_roles_for_schema_version,
    verify_digest_replay,
    write_digest_replay,
)
from agent_assure.schema.base import SchemaVersion
from agent_assure.schema.graph import EvidenceGraphSubjectPayload
from agent_assure.schema.release import ReleaseArtifact, ReleaseDigestReplay
from agent_assure.schema.sensitivity import RAGSensitivityReport

RUNNER = CliRunner()
ROOT = Path(__file__).resolve().parents[3]


def test_sensitivity_bundle_manifest_roles_have_explicit_replay_contracts() -> None:
    expected_modes = {
        "compiled-suite": "raw-sha256",
        "fixture-manifest": "raw-sha256",
        "evidence-sensitivity-protocol": "raw-sha256",
        "baseline-corpus-snapshot": "raw-sha256",
        "counterfactual-corpus-snapshot": "raw-sha256",
        "baseline-runset": "raw-sha256",
        "candidate-runset": "raw-sha256",
        "baseline-evaluation-summary": "replay-stable-json-sha256",
        "evaluation-summary": "replay-stable-json-sha256",
        "comparison-summary": "replay-stable-json-sha256",
        "evidence-sensitivity-report": "replay-stable-json-sha256",
        "evidence-sensitivity-markdown": "raw-sha256",
        "evidence-sensitivity-html": "raw-sha256",
        "assurance-evidence-graph": "replay-stable-json-sha256",
        "statistical-sufficiency-report": "replay-stable-json-sha256",
        "stochastic-evidence-sensitivity-report": "replay-stable-json-sha256",
    }

    assert {
        role: release_evidence.digest_mode_for_role(role) for role in expected_modes
    } == expected_modes


def test_sensitivity_release_role_has_environment_stable_projection() -> None:
    path = ROOT / "tests" / "golden" / "reports" / "evidence-sensitivity-responsive.json"
    source = json.loads(path.read_text(encoding="utf-8"))

    projected = release_evidence._stable_json_projection(
        "evidence-sensitivity-report",
        path,
        ROOT,
    )

    baseline_arm = projected["baseline_arm"]
    counterfactual_arm = projected["counterfactual_arm"]
    assert isinstance(baseline_arm, dict)
    assert isinstance(counterfactual_arm, dict)
    assert "report_digest" not in projected
    assert projected["report_id"] == source["report_id"]
    assert "runset_digest" not in baseline_arm
    assert "evaluation_summary_digest" not in counterfactual_arm
    assert not _nested_key_exists(projected, "environment")


def test_sensitivity_stable_projection_does_not_drop_unrelated_nested_keys() -> None:
    payload: dict[str, object] = {
        "report_digest": "a" * 64,
        "report_id": "report-a",
        "baseline_arm": {"runset_digest": "b" * 64},
        "counterfactual_arm": {"evaluation_summary_digest": "c" * 64},
        "baseline_evaluation": {"environment": {"python": "3.14"}},
        "counterfactual_evaluation": {"runset_digest": "d" * 64},
        "semantic_extension": {"environment": "must-remain-bound"},
    }

    projected = release_evidence._stable_sensitivity_projection(payload)

    assert projected["semantic_extension"] == {"environment": "must-remain-bound"}


def test_packet_stable_projection_uses_sensitivity_projection() -> None:
    payload: dict[str, object] = {
        "artifact_kind": "evidence-packet",
        "evaluation": {"environment": {"platform": "volatile"}},
        "evidence_sensitivity": {
            "report_digest": "a" * 64,
            "report_id": "bound-report-id",
            "baseline_arm": {"evaluation_summary_digest": "b" * 64},
            "counterfactual_arm": {"runset_digest": "c" * 64},
            "baseline_evaluation": {"environment": {"platform": "volatile"}},
            "counterfactual_evaluation": {"runset_digest": "d" * 64},
            "population_claim": "none_bundled_synthetic_fixture_only",
        },
    }

    projected = release_evidence._stable_packet_projection(payload)

    sensitivity = projected["evidence_sensitivity"]
    assert isinstance(sensitivity, dict)
    assert "report_digest" not in sensitivity
    assert sensitivity["report_id"] == "bound-report-id"
    assert sensitivity["population_claim"] == "none_bundled_synthetic_fixture_only"


def test_sensitivity_release_replay_detects_report_identity_drift(tmp_path: Path) -> None:
    source = ROOT / "tests" / "golden" / "reports" / "evidence-sensitivity-responsive.json"
    report = RAGSensitivityReport.model_validate(json.loads(source.read_text(encoding="utf-8")))
    path = tmp_path / "evidence-sensitivity.json"
    _write_json(path, report.model_dump(mode="json"))
    replay = build_digest_replay(
        (("evidence-sensitivity-report", path),),
        project_root=tmp_path,
    )

    changed = report.model_dump(mode="json", exclude={"report_digest"})
    changed["report_id"] = "rag-sensitivity-identity-drift"
    drifted = RAGSensitivityReport.build(**changed)
    _write_json(path, drifted.model_dump(mode="json"))

    verification = verify_digest_replay(replay, artifact_root=tmp_path)

    assert not verification.ok
    finding = next(
        item for item in verification.findings if item.role == "evidence-sensitivity-report"
    )
    assert finding.actual is not None
    assert finding.actual != finding.expected


def test_graph_stable_projection_drops_sensitivity_report_source_digest() -> None:
    node: dict[str, object] = {
        "node_id": "evidence-a",
        "payload_digest": "a" * 64,
        "payload": {
            "payload_kind": "evidence",
            "evidence_type": "evidence_sensitivity",
            "source_digest": "b" * 64,
            "state": "supported",
        },
    }

    projected = release_evidence._stable_graph_node_projection(node)

    payload = projected["payload"]
    assert isinstance(payload, dict)
    assert "source_digest" not in payload
    assert payload["state"] == "supported"


def _nested_key_exists(value: object, key: str) -> bool:
    if isinstance(value, dict):
        return key in value or any(_nested_key_exists(item, key) for item in value.values())
    if isinstance(value, list):
        return any(_nested_key_exists(item, key) for item in value)
    return False


def test_load_digest_replay_projects_validated_v01_contract_to_typed_runtime(
    tmp_path: Path,
) -> None:
    path = tmp_path / "release-digest-replay.v0.1.0.json"
    _write_json(
        path,
        {
            "artifact_kind": "release-digest-replay",
            "schema_version": "0.1.0",
            "source_commit": "abc123",
            "artifacts": [
                {
                    "artifact_kind": "release-replay-artifact",
                    "schema_version": "0.1.0",
                    "role": "compiled-suite",
                    "path": "compiled-suite.json",
                    "sha256": "0" * 64,
                    "digest_mode": "raw-sha256",
                }
            ],
        },
    )

    replay = release_evidence.load_digest_replay(path)

    assert replay.schema_version == "0.2.0"
    assert replay.artifacts[0].schema_version == "0.2.0"
    assert replay.source_commit == "abc123"
    assert core_release_roles_for_schema_version(replay.schema_version) == LEGACY_CORE_RELEASE_ROLES


@pytest.mark.parametrize(
    "schema_version",
    ("0.2.0", "0.3.1", "0.4.3", "0.5.0", "0.6.0", "0.6.1", "0.6.2"),
)
def test_core_release_roles_preserve_historical_replay_contract(
    schema_version: str,
) -> None:
    assert core_release_roles_for_schema_version(schema_version) == LEGACY_CORE_RELEASE_ROLES


@pytest.mark.parametrize("schema_version", ("0.6.3", "0.6.4", "0.6.5", "0.6.6"))
def test_core_release_roles_require_graph_for_graph_era_schemas(schema_version: str) -> None:
    assert core_release_roles_for_schema_version(schema_version) == CORE_RELEASE_ROLES


def test_core_release_role_policy_covers_every_schema_version() -> None:
    assert set(release_evidence._CORE_RELEASE_ROLES_BY_SCHEMA_VERSION) == set(
        get_args(SchemaVersion)
    )


def test_core_release_roles_fail_closed_for_unmapped_schema() -> None:
    with pytest.raises(ValueError, match="no core release-role policy"):
        core_release_roles_for_schema_version("9.9.9")


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
    assert [artifact.digest_mode for artifact in replay.artifacts] == [
        "raw-sha256",
        "raw-sha256",
        "replay-stable-json-sha256",
        "replay-stable-json-sha256",
        "replay-stable-json-sha256",
    ]


def test_release_digest_replay_reports_modified_artifact(tmp_path: Path) -> None:
    artifacts = _write_core_artifacts(tmp_path)
    replay = build_digest_replay(artifacts, project_root=tmp_path)
    packet_path = tmp_path / "evidence-packet.json"
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    packet["limitations"] = ["modified deterministic fixture-mode evidence"]
    _write_json(packet_path, packet)

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
                    "environment": {
                        "platform": "different",
                        "python_version": "3.13",
                    },
                },
                "environment": {
                    "platform": "different",
                    "python_version": "3.13",
                },
                "artifact_digests": [
                    {
                        "role": "evaluation-summary",
                        "sha256": "1" * 64,
                    }
                ],
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
    manifest["environment"] = {
        "platform": "changed",
        "python_version": "3.13",
    }
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


def test_release_digest_replay_build_rejects_duplicate_roles(tmp_path: Path) -> None:
    artifacts = _write_core_artifacts(tmp_path)

    with pytest.raises(ValueError, match="duplicate release replay role"):
        build_digest_replay(
            (*artifacts, ("compiled-suite", tmp_path / "fixture-manifest.json")),
            project_root=tmp_path,
        )


def test_release_digest_replay_build_rejects_hardlink_path_aliases(
    tmp_path: Path,
) -> None:
    artifacts = dict(_write_core_artifacts(tmp_path))
    compiled = artifacts["compiled-suite"]
    compiled_alias = tmp_path / "compiled-suite-hardlink.json"
    try:
        compiled_alias.hardlink_to(compiled)
    except OSError as exc:
        pytest.skip(f"hardlinks unavailable: {exc}")

    with pytest.raises(ValueError, match="duplicate release replay path"):
        build_digest_replay(
            (
                ("compiled-suite", compiled),
                ("fixture-manifest", compiled_alias),
            ),
            project_root=tmp_path,
        )


def test_release_digest_replay_verification_rejects_duplicate_roles(
    tmp_path: Path,
) -> None:
    artifacts = _write_core_artifacts(tmp_path)
    replay = build_digest_replay(artifacts, project_root=tmp_path)
    duplicate = replay.artifacts[0].model_copy(update={"path": replay.artifacts[1].path})
    tampered = replay.model_copy(update={"artifacts": (*replay.artifacts, duplicate)})

    verification = verify_digest_replay(
        tampered,
        artifact_root=tmp_path,
        required_roles=CORE_RELEASE_ROLES,
    )

    assert not verification.ok
    assert any(
        "duplicate release replay role" in finding.message for finding in verification.findings
    )


def test_release_digest_replay_verification_rejects_resolved_path_aliases(
    tmp_path: Path,
) -> None:
    artifacts = _write_core_artifacts(tmp_path)
    replay = build_digest_replay(artifacts, project_root=tmp_path)
    fixture_artifact = replay.artifacts[1].model_copy(
        update={
            "path": "./compiled-suite.json",
            "sha256": replay.artifacts[0].sha256,
        }
    )
    tampered = replay.model_copy(
        update={"artifacts": (replay.artifacts[0], fixture_artifact, *replay.artifacts[2:])}
    )

    verification = verify_digest_replay(
        tampered,
        artifact_root=tmp_path,
        required_roles=CORE_RELEASE_ROLES,
    )

    assert not verification.ok
    assert any(
        "duplicate release replay path alias" in finding.message
        for finding in verification.findings
    )


def test_release_digest_replay_rejects_raw_role_contract_mismatch(
    tmp_path: Path,
) -> None:
    artifacts = _write_core_artifacts(tmp_path)
    replay = build_digest_replay(artifacts, project_root=tmp_path)
    compiled_path = dict(artifacts)["compiled-suite"]
    _write_json(
        compiled_path,
        {
            "artifact_kind": "fixture-manifest",
            "schema_version": "0.2.0",
            "suite_id": "demo",
            "suite_version": "0.1.0",
            "fixture_roots": [],
            "entries": [],
        },
    )
    tampered_compiled = replay.artifacts[0].model_copy(
        update={"sha256": hashlib.sha256(compiled_path.read_bytes()).hexdigest()}
    )
    tampered = replay.model_copy(update={"artifacts": (tampered_compiled, *replay.artifacts[1:])})

    verification = verify_digest_replay(
        tampered,
        artifact_root=tmp_path,
        required_roles=CORE_RELEASE_ROLES,
    )

    assert not verification.ok
    finding = next(finding for finding in verification.findings if finding.role == "compiled-suite")
    assert finding.actual is None
    assert "could not be replayed" in finding.message


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
    packet = dict(_write_core_artifacts(tmp_path))["evidence-packet"]
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


def test_release_replay_cli_accepts_v062_legacy_core_roles(tmp_path: Path) -> None:
    legacy_artifacts = tuple(
        artifact
        for artifact in _write_core_artifacts(tmp_path)
        if artifact[0] != "assurance-evidence-graph"
    )
    replay = build_digest_replay(legacy_artifacts, project_root=tmp_path)
    replay_path = tmp_path / "release-digest-replay.v0.6.2.json"
    _write_versioned_digest_replay(replay_path, replay, schema_version="0.6.2")

    result = RUNNER.invoke(
        app,
        ["release", "replay", str(replay_path), "--artifact-root", str(tmp_path)],
    )

    assert result.exit_code == 0, result.output


def test_release_replay_cli_requires_graph_for_current_schema(tmp_path: Path) -> None:
    legacy_artifacts = tuple(
        artifact
        for artifact in _write_core_artifacts(tmp_path)
        if artifact[0] != "assurance-evidence-graph"
    )
    replay = build_digest_replay(legacy_artifacts, project_root=tmp_path)
    replay_path = tmp_path / "release-digest-replay.json"
    write_digest_replay(replay, replay_path)

    result = RUNNER.invoke(
        app,
        ["release", "replay", str(replay_path), "--artifact-root", str(tmp_path)],
    )

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert {finding["role"] for finding in payload["findings"]} == {"assurance-evidence-graph"}


def test_release_replay_cli_rejects_missing_legacy_core_role(tmp_path: Path) -> None:
    incomplete_artifacts = tuple(
        artifact
        for artifact in _write_core_artifacts(tmp_path)
        if artifact[0] not in {"assurance-evidence-graph", "fixture-manifest"}
    )
    replay = build_digest_replay(incomplete_artifacts, project_root=tmp_path)
    replay_path = tmp_path / "release-digest-replay.v0.6.2.json"
    _write_versioned_digest_replay(replay_path, replay, schema_version="0.6.2")

    result = RUNNER.invoke(
        app,
        ["release", "replay", str(replay_path), "--artifact-root", str(tmp_path)],
    )

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert {finding["role"] for finding in payload["findings"]} == {"fixture-manifest"}


def test_release_replay_cli_adds_explicit_roles_to_versioned_core(
    tmp_path: Path,
) -> None:
    legacy_artifacts = tuple(
        artifact
        for artifact in _write_core_artifacts(tmp_path)
        if artifact[0] != "assurance-evidence-graph"
    )
    replay = build_digest_replay(legacy_artifacts, project_root=tmp_path)
    replay_path = tmp_path / "release-digest-replay.v0.6.2.json"
    _write_versioned_digest_replay(replay_path, replay, schema_version="0.6.2")

    result = RUNNER.invoke(
        app,
        [
            "release",
            "replay",
            str(replay_path),
            "--artifact-root",
            str(tmp_path),
            "--require-role",
            "assurance-evidence-graph",
        ],
    )

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert {finding["role"] for finding in payload["findings"]} == {"assurance-evidence-graph"}


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
    evidence_graph = tmp_path / "assurance-evidence-graph.json"
    evidence_packet = tmp_path / "evidence-packet.json"
    release_manifest = tmp_path / "release-artifact-manifest.json"

    _write_json(
        compiled,
        {
            "artifact_kind": "compiled-suite",
            "schema_version": "0.2.0",
            "suite_id": "demo",
            "suite_version": "0.1.0",
            "cases": [],
            "resolved_expectations": [],
            "source_digest": "0" * 64,
        },
    )
    _write_json(
        fixture_manifest,
        {
            "artifact_kind": "fixture-manifest",
            "schema_version": "0.2.0",
            "suite_id": "demo",
            "suite_version": "0.1.0",
            "fixture_roots": [],
            "entries": [],
        },
    )
    _write_json(
        candidate_runset,
        {
            "artifact_kind": "run-set",
            "schema_version": "0.2.0",
            "runset_id": "candidate",
            "suite_id": "demo",
            "suite_version": "0.1.0",
            "suite_digest": "0" * 64,
            "fixture_manifest_digest": "1" * 64,
            "runs": [],
        },
    )
    _write_json(
        baseline_runset,
        {
            "artifact_kind": "run-set",
            "schema_version": "0.2.0",
            "runset_id": "baseline",
            "suite_id": "demo",
            "suite_version": "0.1.0",
            "suite_digest": "0" * 64,
            "fixture_manifest_digest": "1" * 64,
            "runs": [],
        },
    )
    _write_json(
        evaluation_summary,
        {
            "artifact_kind": "evaluation-summary",
            "schema_version": "0.2.0",
            "runset_id": "candidate",
            "state": "fail",
            "environment": {
                "platform": "original",
                "python_version": "3.13",
            },
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
            "environment": {
                "platform": "original",
                "python_version": "3.13",
            },
        },
    )
    _write_json(
        dependency_inventory,
        {
            "artifact_kind": "dependency-inventory",
            "components": [{"name": "agent-assure", "version": "0.1.0"}],
        },
    )
    graph = build_evidence_graph(
        subject=EvidenceGraphSubjectPayload(
            subject_type="run_set",
            subject_id="release-replay-subject",
        )
    )
    _write_json(evidence_graph, graph.model_dump(mode="json"))
    manifest_payload: dict[str, object] = {
        "artifact_kind": "release-artifact-manifest",
        "schema_version": "0.2.0",
        "manifest_id": "manifest-original",
        "environment": {
            "platform": "original",
            "python_version": "3.13",
        },
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
                "environment": {
                    "platform": "original",
                    "python_version": "3.13",
                },
            },
            "environment": {
                "platform": "original",
                "python_version": "3.13",
            },
            "release_manifest": manifest_payload,
            "artifact_digests": [
                {
                    "role": "evaluation-summary",
                    "sha256": "0" * 64,
                }
            ],
            "limitations": ["deterministic fixture-mode evidence only"],
        },
    )
    return (
        ("compiled-suite", compiled),
        ("fixture-manifest", fixture_manifest),
        ("assurance-evidence-graph", evidence_graph),
        ("evidence-packet", evidence_packet),
        ("release-artifact-manifest", release_manifest),
    )


def _manifest_artifact(role: str, path: Path, root: Path) -> dict[str, str]:
    payload = ReleaseArtifact(
        artifact_kind="release-artifact",
        role=role,
        path=path.resolve().relative_to(root.resolve()).as_posix(),
        sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
    ).model_dump(mode="json")
    payload["schema_version"] = "0.2.0"
    return payload


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def _write_versioned_digest_replay(
    path: Path,
    replay: ReleaseDigestReplay,
    *,
    schema_version: str,
) -> None:
    payload = replay.model_dump(mode="json")
    payload["schema_version"] = schema_version
    for artifact in payload["artifacts"]:
        artifact["schema_version"] = schema_version
    _write_json(path, payload)
