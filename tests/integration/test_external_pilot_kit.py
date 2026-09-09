from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import date
from pathlib import Path
from types import SimpleNamespace

import pytest

import agent_assure.external_pilot_kit as pilot_kit
from agent_assure.external_pilot_kit import (
    CAPTURE_FILENAME,
    CONSENT_RECORD_FILENAME,
    EVIDENCE_FILENAME,
    ExternalPilotCapture,
    capture_external_pilot,
    finalize_external_pilot_capture,
)
from agent_assure.schema.pilot import (
    ExternalPilotEvidence,
    PilotAttemptStatus,
    PilotFrictionAssessmentState,
    PilotRemediationDisposition,
)
from tests.unit.test_pilot_bundle import _wheel_bytes

ROOT = Path(__file__).resolve().parents[2]
PARTICIPANT_INPUT = "agent-assure-pilot/participant-waiver.yaml"
PARTICIPANT_RATIONALE = "I am running this benign pilot to exercise the documented workflow."
SOURCE_REVISION = "a" * 40


@pytest.fixture(scope="session")
def built_wheel(tmp_path_factory: pytest.TempPathFactory) -> Path:
    distribution_root = tmp_path_factory.mktemp("external-pilot-distribution")
    subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--wheel",
            "--no-isolation",
            "--outdir",
            str(distribution_root),
            str(ROOT),
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    wheels = tuple(distribution_root.glob("agent_assure-*.whl"))
    assert len(wheels) == 1
    assert wheels[0].name == "agent_assure-0.6.6-py3-none-any.whl"
    return wheels[0]


def _git(root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _participant_repository(
    tmp_path: Path,
    *,
    pseudonym: str,
    rationale: str = PARTICIPANT_RATIONALE,
    expires_on: str = "2099-12-31",
) -> Path:
    repository = tmp_path / "participant-repository"
    repository.mkdir()
    _git(repository, "init", "--initial-branch=main")
    _git(repository, "config", "user.name", "External Pilot Test")
    _git(repository, "config", "user.email", "pilot-test@example.invalid")
    _git(repository, "config", "core.autocrlf", "false")
    template = (ROOT / "docs" / "templates" / "external_pilot_participant_waiver.yaml").read_text(
        encoding="utf-8"
    )
    authored = (
        template.replace("replace-participant-pseudonym", pseudonym)
        .replace("replace-with-a-short-benign-participant-rationale", rationale)
        .replace("2099-12-31", expires_on)
    )
    input_path = repository / PARTICIPANT_INPUT
    input_path.parent.mkdir()
    input_path.write_text(authored, encoding="utf-8", newline="\n")
    _git(repository, "add", PARTICIPANT_INPUT)
    _git(repository, "commit", "-m", "Add benign external pilot input")
    return repository


def _ci_environment(
    *,
    run_id: str,
    actor_id: str = "3003",
    actor: str = "external-pilot-user",
    triggering_actor: str | None = None,
) -> dict[str, str]:
    environment = {
        "AGENT_ASSURE_PILOT_PARENT_REPOSITORY": "acblabs/agent-assure",
        "AGENT_ASSURE_PILOT_REPOSITORY_IS_FORK": "true",
        "CI": "true",
        "GITHUB_ACTIONS": "true",
        "GITHUB_ACTOR": actor,
        "GITHUB_ACTOR_ID": actor_id,
        "GITHUB_REPOSITORY_ID": "1001",
        "GITHUB_REPOSITORY": "external-pilot-owner/agent-assure",
        "GITHUB_REPOSITORY_OWNER": "external-pilot-owner",
        "GITHUB_REPOSITORY_OWNER_ID": "2002",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_RUN_ID": run_id,
        "GITHUB_TRIGGERING_ACTOR": triggering_actor or actor,
        "PATH": os.environ.get("PATH", ""),
        "RUNNER_ARCH": "X64",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "Linux",
    }
    for name in ("COMSPEC", "PATHEXT", "SYSTEMROOT", "WINDIR"):
        if value := os.environ.get(name):
            environment[name] = value
    return environment


def _capture(
    tmp_path: Path,
    built_wheel: Path,
    *,
    pseudonym: str = "participant-ember-17",
    rationale: str = PARTICIPANT_RATIONALE,
    expires_on: str = "2099-12-31",
    temporary_storage_consent_granted: bool = True,
    environment: dict[str, str] | None = None,
) -> tuple[Path, ExternalPilotCapture]:
    repository = _participant_repository(
        tmp_path,
        pseudonym=pseudonym,
        rationale=rationale,
        expires_on=expires_on,
    )
    capture_root = tmp_path / "capture"
    capture = capture_external_pilot(
        capture_root=capture_root,
        participant_repository_root=repository,
        participant_input_repository_path=PARTICIPANT_INPUT,
        participant_input_template=(
            ROOT / "docs" / "templates" / "external_pilot_participant_waiver.yaml"
        ),
        wheel_path=built_wheel,
        source_revision=SOURCE_REVISION,
        participant_pseudonym=pseudonym,
        temporary_storage_consent_granted=temporary_storage_consent_granted,
        non_maintainer_control_attested=True,
        environment=environment or _ci_environment(run_id="4004"),
    )
    return capture_root, capture


def test_two_stage_kit_builds_a_mechanically_verified_completed_candidate(
    tmp_path: Path,
    built_wheel: Path,
) -> None:
    capture_root, capture = _capture(tmp_path, built_wheel)
    bundle_root = tmp_path / "candidate"

    evidence = finalize_external_pilot_capture(
        capture_root=capture_root,
        bundle_root=bundle_root,
        expected_source_revision=SOURCE_REVISION,
        capture_run_id="4004",
        capture_run_attempt="1",
        friction_assessment="no_friction_observed",
        friction_category="other",
        publication_consent_granted=True,
        non_maintainer_control_attested=True,
        environment=_ci_environment(run_id="5005"),
    )

    persisted = ExternalPilotEvidence.model_validate(
        json.loads((bundle_root / EVIDENCE_FILENAME).read_text(encoding="utf-8"))
    )
    assert persisted == evidence
    assert evidence.attempt_status is PilotAttemptStatus.completed
    assert evidence.qualifies_as_external_attempt is True
    assert evidence.friction_assessment is PilotFrictionAssessmentState.no_friction_observed
    assert evidence.publication.published_artifact_ids == tuple(
        item.artifact_id for item in evidence.artifacts
    )
    assert {item.path for item in evidence.artifacts} | {EVIDENCE_FILENAME} == {
        item.name for item in bundle_root.iterdir()
    }
    assert (capture_root / CAPTURE_FILENAME).is_file()
    assert (capture_root / built_wheel.name).read_bytes() == built_wheel.read_bytes()
    assert capture.temporary_storage_consent_granted is True
    assert capture.command.exit_code in {0, 1}
    assert "participant-waiver.yaml" not in {item.name for item in bundle_root.iterdir()}
    public_bytes = b"\n".join(path.read_bytes() for path in bundle_root.iterdir())
    private_bindings = {
        capture.capture_digest,
        capture.participant_repository_revision,
        *capture.ci_identity_digests.model_dump().values(),
    }
    assert all(binding.encode("ascii") not in public_bytes for binding in private_bindings)
    assert capture.opaque_pilot_binding.encode("ascii") in public_bytes
    assert b"participant_repository_revision" not in public_bytes
    assert b"ci_run_identity_digest" not in public_bytes
    assert b"finalization_ci_run_identity_digest" not in public_bytes
    consent = json.loads((bundle_root / CONSENT_RECORD_FILENAME).read_text(encoding="utf-8"))
    assert "prospectively authorizes" in consent["statement"]
    assert "does not claim the participant reviewed" in consent["statement"]
    assert consent["temporary_actions_storage_days"] == 14
    assert consent["temporary_actions_storage_access"] == (
        "participant_fork_repository_read_access"
    )
    assert consent["cross_stage_correlation"] == "shared_opaque_pilot_binding"
    assert consent["public_fork_correlation"] == ("committed_input_digests_can_match_public_bytes")
    assert "committed-input content and semantic digests" in consent["statement"]


def test_failed_attempt_requires_observed_friction_and_records_planned_follow_up(
    tmp_path: Path,
    built_wheel: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(pilot_kit, "_run_signature_command", lambda *args, **kwargs: 4)
    capture_root, capture = _capture(tmp_path, built_wheel)
    assert capture.command.exit_code == 4
    assert not any(item.role.value == "assurance_output" for item in capture.artifacts)

    with pytest.raises(ValueError, match="cannot claim no friction"):
        finalize_external_pilot_capture(
            capture_root=capture_root,
            bundle_root=tmp_path / "invalid-candidate",
            expected_source_revision=SOURCE_REVISION,
            capture_run_id="4004",
            capture_run_attempt="1",
            friction_assessment="no_friction_observed",
            friction_category="other",
            publication_consent_granted=True,
            non_maintainer_control_attested=True,
            environment=_ci_environment(run_id="5005"),
        )

    evidence = finalize_external_pilot_capture(
        capture_root=capture_root,
        bundle_root=tmp_path / "friction-candidate",
        expected_source_revision=SOURCE_REVISION,
        capture_run_id="4004",
        capture_run_attempt="1",
        friction_assessment="friction_observed",
        friction_category="runtime",
        publication_consent_granted=True,
        non_maintainer_control_attested=True,
        environment=_ci_environment(run_id="5005"),
    )
    assert evidence.attempt_status is PilotAttemptStatus.attempted
    assert evidence.friction_findings[0].category.value == "runtime"
    assert evidence.remediations[0].disposition is PilotRemediationDisposition.planned


def test_applied_remediation_refinalizes_without_mutating_the_planned_candidate(
    tmp_path: Path,
    built_wheel: Path,
) -> None:
    capture_root, _capture_record = _capture(tmp_path, built_wheel)
    planned_root = tmp_path / "planned-candidate"
    planned = finalize_external_pilot_capture(
        capture_root=capture_root,
        bundle_root=planned_root,
        expected_source_revision=SOURCE_REVISION,
        capture_run_id="4004",
        capture_run_attempt="1",
        friction_assessment="friction_observed",
        friction_category="documentation",
        remediation_disposition="planned",
        publication_consent_granted=True,
        non_maintainer_control_attested=True,
        environment=_ci_environment(run_id="5005"),
    )
    planned_bytes = {path.name: path.read_bytes() for path in planned_root.iterdir()}

    applied_root = tmp_path / "applied-candidate"
    applied = finalize_external_pilot_capture(
        capture_root=capture_root,
        bundle_root=applied_root,
        expected_source_revision=SOURCE_REVISION,
        capture_run_id="4004",
        capture_run_attempt="1",
        friction_assessment="friction_observed",
        friction_category="documentation",
        remediation_disposition="applied",
        remediation_source_revision="b" * 40,
        prior_candidate_evidence_digest=planned.pilot_evidence_digest,
        publication_consent_granted=True,
        non_maintainer_control_attested=True,
        environment=_ci_environment(run_id="6006"),
    )

    assert applied.remediations[0].disposition is PilotRemediationDisposition.applied
    remediation = json.loads((applied_root / "remediation-record.json").read_text("utf-8"))
    assert remediation["remediation_source_revision"] == "b" * 40
    assert remediation["prior_planned_candidate_evidence_digest"] == (planned.pilot_evidence_digest)
    assert {path.name: path.read_bytes() for path in planned_root.iterdir()} == planned_bytes


@pytest.mark.parametrize(
    ("source_revision", "prior_digest", "message"),
    (
        (None, "f" * 64, "full lowercase Git commit"),
        ("b" * 40, None, "prior planned candidate digest"),
        (SOURCE_REVISION, "f" * 64, "postdate the tested source"),
    ),
)
def test_applied_remediation_requires_complete_non_self_referential_bindings(
    tmp_path: Path,
    built_wheel: Path,
    source_revision: str | None,
    prior_digest: str | None,
    message: str,
) -> None:
    capture_root, _capture_record = _capture(tmp_path, built_wheel)

    with pytest.raises(ValueError, match=message):
        finalize_external_pilot_capture(
            capture_root=capture_root,
            bundle_root=tmp_path / "invalid-applied-candidate",
            expected_source_revision=SOURCE_REVISION,
            capture_run_id="4004",
            capture_run_attempt="1",
            friction_assessment="friction_observed",
            friction_category="documentation",
            remediation_disposition="applied",
            remediation_source_revision=source_revision,
            prior_candidate_evidence_digest=prior_digest,
            publication_consent_granted=True,
            non_maintainer_control_attested=True,
            environment=_ci_environment(run_id="5005"),
        )
    assert not (tmp_path / "invalid-applied-candidate").exists()


def test_finalization_fails_closed_without_consent_or_the_same_actor(
    tmp_path: Path,
    built_wheel: Path,
) -> None:
    capture_root, _capture_record = _capture(tmp_path, built_wheel)

    with pytest.raises(ValueError, match="consent was not granted"):
        finalize_external_pilot_capture(
            capture_root=capture_root,
            bundle_root=tmp_path / "without-consent",
            expected_source_revision=SOURCE_REVISION,
            capture_run_id="4004",
            capture_run_attempt="1",
            friction_assessment="no_friction_observed",
            friction_category="other",
            publication_consent_granted=False,
            non_maintainer_control_attested=True,
            environment=_ci_environment(run_id="5005"),
        )
    assert not (tmp_path / "without-consent").exists()

    with pytest.raises(ValueError, match="same fork owner and participant actor"):
        finalize_external_pilot_capture(
            capture_root=capture_root,
            bundle_root=tmp_path / "wrong-actor",
            expected_source_revision=SOURCE_REVISION,
            capture_run_id="4004",
            capture_run_attempt="1",
            friction_assessment="no_friction_observed",
            friction_category="other",
            publication_consent_granted=True,
            non_maintainer_control_attested=True,
            environment=_ci_environment(run_id="5005", actor_id="9999"),
        )
    assert not (tmp_path / "wrong-actor").exists()

    with pytest.raises(ValueError, match="pinned expected source revision"):
        finalize_external_pilot_capture(
            capture_root=capture_root,
            bundle_root=tmp_path / "wrong-source",
            expected_source_revision="b" * 40,
            capture_run_id="4004",
            capture_run_attempt="1",
            friction_assessment="no_friction_observed",
            friction_category="other",
            publication_consent_granted=True,
            non_maintainer_control_attested=True,
            environment=_ci_environment(run_id="5005"),
        )
    assert not (tmp_path / "wrong-source").exists()


def test_finalization_binds_the_captured_wheel_to_the_trusted_runtime(
    tmp_path: Path,
    built_wheel: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture_root, _capture_record = _capture(tmp_path, built_wheel)

    def reject_mismatch(_wheel_bytes: bytes) -> None:
        raise ValueError("captured wheel code differs from the trusted verifier")

    monkeypatch.setattr(
        pilot_kit,
        "_validate_running_agent_assure_code_matches_wheel",
        reject_mismatch,
    )
    with pytest.raises(ValueError, match="differs from the trusted verifier"):
        finalize_external_pilot_capture(
            capture_root=capture_root,
            bundle_root=tmp_path / "runtime-mismatch",
            expected_source_revision=SOURCE_REVISION,
            capture_run_id="4004",
            capture_run_attempt="1",
            friction_assessment="no_friction_observed",
            friction_category="other",
            publication_consent_granted=True,
            non_maintainer_control_attested=True,
            environment=_ci_environment(run_id="5005"),
        )
    assert not (tmp_path / "runtime-mismatch").exists()


def test_capture_fails_closed_without_temporary_storage_consent(
    tmp_path: Path,
    built_wheel: Path,
) -> None:
    with pytest.raises(ValueError, match="temporary capture storage consent was not granted"):
        _capture(
            tmp_path,
            built_wheel,
            temporary_storage_consent_granted=False,
        )
    assert not (tmp_path / "capture").exists()


def test_capture_rejects_a_valid_wheel_that_does_not_contain_the_running_code(
    tmp_path: Path,
) -> None:
    wheel = tmp_path / "agent_assure-0.6.6-py3-none-any.whl"
    wheel.write_bytes(_wheel_bytes())

    with pytest.raises(ValueError, match="code inventory does not match tested wheel"):
        _capture(tmp_path, wheel)
    assert not (tmp_path / "capture").exists()


def test_capture_rejects_a_privacy_invalid_wheel_before_creating_a_handoff(
    tmp_path: Path,
) -> None:
    wheel = tmp_path / "agent_assure-0.6.6-py3-none-any.whl"
    wheel.write_bytes(
        _wheel_bytes(extra_members={"agent_assure/leaked.py": b'api_key = "hunter2-value"\n'})
    )

    with pytest.raises(ValueError, match="privacy review"):
        _capture(tmp_path, wheel)
    assert not (tmp_path / "capture").exists()


def test_capture_rejects_a_rerun_triggered_by_a_different_actor(
    tmp_path: Path,
    built_wheel: Path,
) -> None:
    with pytest.raises(ValueError, match="original GitHub actor"):
        _capture(
            tmp_path,
            built_wheel,
            environment=_ci_environment(
                run_id="4004",
                actor="original-pilot-actor",
                triggering_actor="different-rerun-actor",
            ),
        )
    assert not (tmp_path / "capture").exists()


@pytest.mark.parametrize(
    "pseudonym",
    (
        "",
        "a" * 65,
        "participant with spaces",
        "replace-participant-pseudonym",
    ),
)
def test_capture_rejects_an_invalid_participant_pseudonym_early(
    tmp_path: Path,
    built_wheel: Path,
    pseudonym: str,
) -> None:
    with pytest.raises(ValueError, match="1-64 machine-identifier characters"):
        _capture(tmp_path, built_wheel, pseudonym=pseudonym)
    assert not (tmp_path / "capture").exists()


@pytest.mark.parametrize(
    "pseudonym",
    (
        "external-pilot-user",
        "EXTERNAL-PILOT-OWNER",
        "3003",
        "2002",
        "1001",
        "external-pilot-owner/agent-assure",
    ),
)
def test_capture_rejects_a_pseudonym_equal_to_a_known_ci_identifier(
    tmp_path: Path,
    built_wheel: Path,
    pseudonym: str,
) -> None:
    with pytest.raises(ValueError, match="must not equal a GitHub account"):
        _capture(tmp_path, built_wheel, pseudonym=pseudonym)
    assert not (tmp_path / "capture").exists()


@pytest.mark.parametrize(
    "rationale",
    (
        "   ",
        "replace-with-a-short-benign-participant-rationale",
        "x" * 257,
    ),
)
def test_capture_requires_a_bounded_participant_authored_rationale(
    tmp_path: Path,
    built_wheel: Path,
    rationale: str,
) -> None:
    with pytest.raises(ValueError, match="rationale must be participant-authored"):
        _capture(tmp_path, built_wheel, rationale=rationale)


def test_benign_participant_waiver_validator_rejects_an_empty_rationale() -> None:
    waiver = SimpleNamespace(
        waiver_id="external-pilot-participant-001",
        owner="participant-001",
        reviewer="participant-001",
        reason_code=SimpleNamespace(value="FORBIDDEN_TOOL"),
        finding_id="pilot-nonmatching-finding",
        artifact_digest="0" * 64,
        expires_on=date(2099, 12, 31),
        rationale="",
    )

    with pytest.raises(ValueError, match="rationale must be participant-authored"):
        pilot_kit._validate_benign_participant_waiver(
            (waiver,),
            participant_pseudonym="participant-001",
        )


def test_capture_requires_the_exact_fixed_benign_waiver_boundary(
    tmp_path: Path,
    built_wheel: Path,
) -> None:
    with pytest.raises(ValueError, match="documented benign non-matching boundary"):
        _capture(tmp_path, built_wheel, expires_on="2099-12-30")
