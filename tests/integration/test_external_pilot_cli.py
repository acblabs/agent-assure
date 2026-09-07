from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agent_assure.authoring.yaml_nodes import safe_load_yaml_text
from agent_assure.cli import release_cmd as release_cmd_module
from agent_assure.cli.main import app
from agent_assure.pilot_bundle import load_verified_external_pilot_bundle
from agent_assure.schema.pilot import (
    ExternalPilotEvidence,
    ExternalPilotIndependenceReviewReceipt,
    PilotArtifactRole,
    PilotInputManifest,
)
from tests.unit.schema.test_pilot_evidence import _values
from tests.unit.test_pilot_bundle import (
    EVIDENCE_NAME,
    RECEIPT_NAME,
    _write_bundle,
)

RUNNER = CliRunner()
ROOT = Path(__file__).resolve().parents[2]


def _write_json(path: Path, payload: object) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _write_evidence_template(
    path: Path,
    *,
    supplied_digest: str | None = None,
) -> None:
    payload = ExternalPilotEvidence.build(**_values()).model_dump(mode="json")
    if supplied_digest is not None:
        payload["pilot_evidence_digest"] = supplied_digest
    _write_json(path, payload)


def _write_review_template(
    path: Path,
    *,
    reviewer: str = "release-reviewer-001",
    rationale: str = "The reviewer did not execute or author the recorded pilot.",
    extra: dict[str, object] | None = None,
) -> None:
    values: dict[str, object] = {
        "receipt_id": "pilot-review-001",
        "reviewer_pseudonym": reviewer,
        "manual_approval_is_trust_root": True,
        "reviewer_independent_of_pilot_execution": True,
        "reviewer_independence_rationale": rationale,
        "environment_control_evidence_reviewed": True,
        "artifact_inventory_reviewed": True,
        "privacy_boundary_reviewed": True,
        "review_outcome": "approved_for_empirical_checkpoint",
        "reviewed_at": "2026-09-02T10:00:00Z",
        "tested_distribution_provenance_reviewed": True,
        "command_input_bindings_reviewed": True,
        "execution_time_input_content_digests_reviewed": True,
        "input_semantic_identities_reviewed": True,
        "complete_bundle_publication_consent_reviewed": True,
    }
    values.update(extra or {})
    _write_json(path, values)


def _review_arguments(root: Path, template: Path) -> list[str]:
    return [
        "release",
        "pilot",
        "review",
        "--bundle-root",
        str(root),
        "--evidence",
        EVIDENCE_NAME,
        "--template",
        str(template),
        "--out",
        RECEIPT_NAME,
    ]


def test_pilot_finalize_builds_self_digest_and_is_exactly_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    template = tmp_path / "pilot-template.json"
    output_directory = tmp_path / "pilot-bundle"
    output_directory.mkdir()
    output = output_directory / EVIDENCE_NAME
    _write_evidence_template(template, supplied_digest="f" * 64)
    arguments = [
        "release",
        "pilot",
        "finalize",
        "--template",
        str(template),
        "--out",
        str(output),
    ]

    first = RUNNER.invoke(app, arguments)
    first_bytes = output.read_bytes()
    second = RUNNER.invoke(app, arguments)

    assert first.exit_code == 0, first.output
    assert second.exit_code == 0, second.output
    assert output.read_bytes() == first_bytes
    evidence = ExternalPilotEvidence.model_validate_json(first_bytes)
    assert evidence.pilot_evidence_digest != "f" * 64
    assert not any(
        path.name.startswith(".agent-assure-finalize-") for path in output_directory.iterdir()
    )
    assert any(path.name.startswith(".agent-assure-finalize-") for path in tmp_path.iterdir())


def test_pilot_finalize_requires_explicit_output_at_parse_time(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    working_directory = tmp_path / "work"
    working_directory.mkdir()
    monkeypatch.chdir(working_directory)
    template = working_directory / "pilot-template.json"
    _write_evidence_template(template)
    monkeypatch.setattr(
        release_cmd_module,
        "_load_authoring_mapping",
        lambda *_args, **_kwargs: pytest.fail("command body must not run without --out"),
    )

    result = RUNNER.invoke(
        app,
        [
            "release",
            "pilot",
            "finalize",
            "--template",
            str(template),
        ],
    )

    assert result.exit_code == 2
    assert "Missing option '--out'" in result.output
    assert "external pilot evidence finalization failed" not in result.output
    assert not (working_directory / "external-pilot-evidence.json").exists()
    assert not any(path.name.startswith(".agent-assure-finalize-") for path in tmp_path.iterdir())


def test_pilot_finalize_refuses_an_explicit_lock_above_the_working_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    working_directory = tmp_path / "work"
    working_directory.mkdir()
    monkeypatch.chdir(working_directory)
    template = working_directory / "pilot-template.json"
    output = working_directory / "external-pilot-evidence.json"
    _write_evidence_template(template)

    result = RUNNER.invoke(
        app,
        [
            "release",
            "pilot",
            "finalize",
            "--template",
            str(template),
            "--out",
            str(output),
        ],
    )

    assert result.exit_code == 2
    assert "cannot be the current working directory or its ancestor" in result.output
    assert not output.exists()
    assert not any(path.name.startswith(".agent-assure-finalize-") for path in tmp_path.iterdir())


def test_documented_pilot_templates_are_directly_accepted(tmp_path: Path) -> None:
    evidence_output = tmp_path / "template-evidence.json"
    evidence_result = RUNNER.invoke(
        app,
        [
            "release",
            "pilot",
            "finalize",
            "--template",
            str(ROOT / "docs" / "templates" / "external_pilot_evidence.yaml"),
            "--out",
            str(evidence_output),
        ],
    )
    root = tmp_path / "bundle"
    _evidence, _receipt = _write_bundle(root)
    (root / RECEIPT_NAME).unlink()
    review_result = RUNNER.invoke(
        app,
        _review_arguments(
            root,
            ROOT / "docs" / "templates" / "external_pilot_independence_review.yaml",
        ),
    )
    input_template = ROOT / "docs" / "templates" / "external_pilot_input_manifest.yaml"
    input_values = safe_load_yaml_text(
        input_template.read_text(encoding="utf-8"),
        label="external pilot input manifest template",
    )
    input_manifest = PilotInputManifest.build(**input_values)

    assert evidence_result.exit_code == 0, evidence_result.output
    assert ExternalPilotEvidence.model_validate_json(evidence_output.read_bytes())
    assert review_result.exit_code == 0, review_result.output
    assert input_manifest.contract_id == "PilotInputManifest/v1"


def test_pilot_review_refuses_a_lock_above_the_working_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "bundle"
    _evidence, _receipt = _write_bundle(root)
    (root / RECEIPT_NAME).unlink()
    template = tmp_path / "review-template.json"
    _write_review_template(template)
    monkeypatch.chdir(root)

    result = RUNNER.invoke(app, _review_arguments(Path("."), template))

    assert result.exit_code == 2
    assert "cannot be the current working directory or its ancestor" in result.output
    assert not (root / RECEIPT_NAME).exists()
    assert not any(path.name.startswith(".agent-assure-finalize-") for path in tmp_path.iterdir())


def test_pilot_review_derives_bindings_validates_bundle_and_is_idempotent(
    tmp_path: Path,
) -> None:
    root = tmp_path / "bundle"
    evidence, _receipt = _write_bundle(root)
    (root / RECEIPT_NAME).unlink()
    first_template = tmp_path / "operator-a" / "review-template.json"
    second_template = tmp_path / "operator-b" / "review-template.json"
    first_template.parent.mkdir()
    second_template.parent.mkdir()
    _write_review_template(first_template)
    _write_review_template(second_template)

    first = RUNNER.invoke(app, _review_arguments(root, first_template))
    first_bytes = (root / RECEIPT_NAME).read_bytes()
    second = RUNNER.invoke(app, _review_arguments(root, second_template))

    assert first.exit_code == 0, first.output
    assert second.exit_code == 0, second.output
    assert (root / RECEIPT_NAME).read_bytes() == first_bytes
    receipt = ExternalPilotIndependenceReviewReceipt.model_validate_json(first_bytes)
    verified = load_verified_external_pilot_bundle(
        root,
        evidence_path=EVIDENCE_NAME,
        review_receipt_path=RECEIPT_NAME,
        expected_release=evidence.subject.implementation_version,
    )
    assert verified.review_receipt == receipt
    assert receipt.pilot_id == evidence.pilot_id
    assert receipt.pilot_evidence_digest == evidence.pilot_evidence_digest
    assert not any(path.name.startswith(".agent-assure-finalize-") for path in root.iterdir())
    assert not any(
        path.name.startswith(".agent-assure-finalize-") for path in first_template.parent.iterdir()
    )
    assert not any(
        path.name.startswith(".agent-assure-finalize-") for path in second_template.parent.iterdir()
    )
    assert any(path.name.startswith(".agent-assure-finalize-") for path in tmp_path.iterdir())


def test_pilot_review_rejects_changed_artifact_before_publishing_receipt(
    tmp_path: Path,
) -> None:
    root = tmp_path / "bundle"
    evidence, _receipt = _write_bundle(root)
    (root / RECEIPT_NAME).unlink()
    target = next(
        artifact
        for artifact in evidence.artifacts
        if artifact.role is PilotArtifactRole.environment_manifest
    )
    (root / target.path).write_bytes(b"changed")
    template = tmp_path / "review-template.json"
    _write_review_template(template)

    result = RUNNER.invoke(app, _review_arguments(root, template))

    assert result.exit_code == 2
    assert "digest mismatch" in result.output
    assert not (root / RECEIPT_NAME).exists()


def test_pilot_review_template_cannot_self_declare_derived_bindings(
    tmp_path: Path,
) -> None:
    root = tmp_path / "bundle"
    _evidence, _receipt = _write_bundle(root)
    (root / RECEIPT_NAME).unlink()
    template = tmp_path / "review-template.json"
    _write_review_template(template, extra={"pilot_id": "self-declared-pilot"})

    result = RUNNER.invoke(app, _review_arguments(root, template))

    assert result.exit_code == 2
    assert not (root / RECEIPT_NAME).exists()


def test_pilot_review_rejects_sensitive_attestation_without_echoing_it(
    tmp_path: Path,
) -> None:
    root = tmp_path / "bundle"
    _evidence, _receipt = _write_bundle(root)
    (root / RECEIPT_NAME).unlink()
    template = tmp_path / "review-template.json"
    secret = "sk-live-do-not-persist-123456"
    _write_review_template(template, rationale=f"api_key={secret}")

    result = RUNNER.invoke(app, _review_arguments(root, template))

    assert result.exit_code == 2
    assert secret not in result.output
    assert not (root / RECEIPT_NAME).exists()


def test_pilot_review_rejects_traversal_and_preserves_existing_receipt(
    tmp_path: Path,
) -> None:
    root = tmp_path / "bundle"
    _evidence, _receipt = _write_bundle(root)
    existing = (root / RECEIPT_NAME).read_bytes()
    template = tmp_path / "review-template.json"
    _write_review_template(template, reviewer="different-release-reviewer")

    conflict = RUNNER.invoke(app, _review_arguments(root, template))
    traversal = RUNNER.invoke(
        app,
        [
            *_review_arguments(root, template)[:-1],
            "../escaped-review.json",
        ],
    )

    assert conflict.exit_code == 2
    assert "different content" in conflict.output
    assert (root / RECEIPT_NAME).read_bytes() == existing
    assert traversal.exit_code == 2
    assert not (tmp_path / "escaped-review.json").exists()


def test_pilot_review_post_publish_failure_is_closed_and_exactly_retryable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "bundle"
    _evidence, _receipt = _write_bundle(root)
    (root / RECEIPT_NAME).unlink()
    template = tmp_path / "review-template.json"
    _write_review_template(template)
    original = release_cmd_module.load_verified_external_pilot_bundle

    def reject_verification(*_args: object, **_kwargs: object) -> object:
        raise ValueError("simulated post-publication verification failure")

    monkeypatch.setattr(
        release_cmd_module,
        "load_verified_external_pilot_bundle",
        reject_verification,
    )
    failed = RUNNER.invoke(app, _review_arguments(root, template))
    monkeypatch.setattr(
        release_cmd_module,
        "load_verified_external_pilot_bundle",
        original,
    )
    retried = RUNNER.invoke(app, _review_arguments(root, template))

    assert failed.exit_code == 2
    assert (root / RECEIPT_NAME).exists()
    assert retried.exit_code == 0, retried.output
