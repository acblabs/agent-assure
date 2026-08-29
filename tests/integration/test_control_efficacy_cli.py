from __future__ import annotations

import hashlib
import json
import os
from datetime import date
from pathlib import Path
from typing import Any, cast

import pytest
from jsonschema import Draft202012Validator
from typer.testing import CliRunner, Result

from agent_assure.artifact_io import file_sha256
from agent_assure.authoring.compiler import compile_suite
from agent_assure.cli import controls_cmd, packet_cmd
from agent_assure.cli.main import app
from agent_assure.fixtures.loader import compiled_suite_digest
from agent_assure.io_limits import load_json_bounded
from agent_assure.mutation.campaign import execute_mutation_campaign
from agent_assure.onboarding import path_safety as onboarding_path_safety
from agent_assure.onboarding.controls_mutation import scaffold_controls_mutation
from agent_assure.policies.base import GateProfile
from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.reporting.campaign import write_mutation_campaign_artifacts
from agent_assure.schema.base import SCHEMA_VERSION
from agent_assure.schema.common import GateState, Severity
from agent_assure.schema.evaluation import EvaluationSummary
from agent_assure.schema.validation import validate_artifact

RUNNER = CliRunner()
OPERATOR_ID = "drop-material-evidence-link"
GENERATED_AT = "2026-08-08T00:00:00Z"
EVALUATION_DATE = date(2026, 8, 8)


def test_controls_efficacy_public_cli_passes_and_reviews_unknown_scope(
    tmp_path: Path,
) -> None:
    workflow = tmp_path / "workflow"
    scaffold_controls_mutation(workflow)
    mutation = RUNNER.invoke(
        app,
        [
            "controls",
            "mutate",
            "--suite",
            str(workflow / "suite.yaml"),
            "--runset",
            str(workflow / "runset.json"),
            "--catalog",
            "core/v1",
            "--operator",
            OPERATOR_ID,
            "--out",
            str(workflow / "mutation-results"),
        ],
    )
    assert mutation.exit_code == 0, mutation.output

    passing_out = workflow / "efficacy-pass"
    passing = _invoke_efficacy(workflow, passing_out, terminal_width=32)

    assert passing.exit_code == 0, passing.output
    assert "control efficacy semantic state: all_evaluated_applicable_caught" in passing.output
    assert "control efficacy gate state: pass" in passing.output
    assert f"control efficacy report: {passing_out / 'control-efficacy-report.json'}" in (
        passing.output.splitlines()
    )
    assert f"control efficacy markdown: {passing_out / 'control-efficacy-report.md'}" in (
        passing.output.splitlines()
    )
    passing_report = _json(passing_out / "control-efficacy-report.json")
    assert (
        passing_report["campaign_digest"]
        == _json(workflow / "mutation-results" / "assurance-mutation-campaign.json")[
            "campaign_digest"
        ]
    )
    assert passing_report["catalog_kill_rate"] == {
        "denominator": 1,
        "numerator": 1,
        "state": "defined",
    }
    assert (
        validate_artifact(
            passing_out / "control-efficacy-report.json",
            "control-efficacy-report",
        )
        == "pydantic+jsonschema"
    )

    manifest_path = workflow / "threat-applicability.yaml"
    manifest_text = manifest_path.read_text(encoding="utf-8")
    assert manifest_text.count("applicability: applicable") == 2
    manifest_path.write_text(
        manifest_text.replace(
            "applicability: applicable",
            "applicability: unknown",
            1,
        ),
        encoding="utf-8",
        newline="\n",
    )
    review_out = workflow / "efficacy-review"
    review = _invoke_efficacy(workflow, review_out)

    assert review.exit_code == 0, review.output
    assert "control efficacy gate state: warn" in review.output
    review_report = _json(review_out / "control-efficacy-report.json")
    assert review_report["unknown_applicability_count"] == 1
    assert review_report["unknown_applicability_threat_ids"] == ["AML.T0067.000"]
    strict_review = RUNNER.invoke(
        app,
        [
            "ci",
            "gate",
            str(review_out / "control-efficacy-report.json"),
            "--efficacy-policy",
            str(workflow / "controls-mutation.yaml"),
            "--fail-on-warn",
        ],
    )
    assert strict_review.exit_code == 1, strict_review.output
    assert "gate_state:warn" in strict_review.output


def test_controls_efficacy_public_cli_and_ci_block_a_required_survivor(
    tmp_path: Path,
) -> None:
    workflow = tmp_path / "weakened-workflow"
    scaffold_controls_mutation(workflow)
    _write_weakened_campaign(workflow)
    report_dir = workflow / "efficacy"

    result = _invoke_efficacy(workflow, report_dir)

    assert result.exit_code == 1, result.output
    assert "control efficacy semantic state: survivor_observed" in result.output
    assert "control efficacy gate state: fail" in result.output
    report_path = report_dir / "control-efficacy-report.json"
    report = _json(report_path)
    assert report["required_survivor_count"] == 1
    assert report["required_survivor_operator_ids"] == [OPERATOR_ID]
    assert report["critical_survivor_count"] == 1
    assert report["catalog_kill_rate"] == {
        "denominator": 1,
        "numerator": 0,
        "state": "defined",
    }
    assert report_path.is_file()
    assert (report_dir / "control-efficacy-report.md").is_file()

    ci_gate = RUNNER.invoke(
        app,
        [
            "ci",
            "gate",
            str(report_path),
            "--efficacy-policy",
            str(workflow / "controls-mutation.yaml"),
        ],
        terminal_width=32,
    )
    assert ci_gate.exit_code == 1, ci_gate.output
    assert "ci gate fail: control-efficacy-report" in ci_gate.output
    assert "gate_state=fail" in ci_gate.output
    assert report["report_digest"] in ci_gate.output

    structural_gate = RUNNER.invoke(
        app,
        [
            "ci",
            "gate",
            str(report_path),
            "--efficacy-policy",
            str(workflow / "controls-mutation.yaml"),
            "--format",
            "json",
        ],
    )
    assert structural_gate.exit_code == 1, structural_gate.output
    structural_decision = json.loads(structural_gate.output)
    assert structural_decision["outcome"] == "fail"
    assert structural_decision["exit_code"] == 1
    assert structural_decision["reason_code"] == "REQUIRED_OPERATOR_SURVIVED"
    assert structural_decision["efficacy_evidence"] == "present"
    assert structural_decision["efficacy_verification"] == "strict"
    assert structural_decision["efficacy_required"] is True


def test_schema_export_registers_control_efficacy_contract_roots(tmp_path: Path) -> None:
    out = tmp_path / "schemas"

    result = RUNNER.invoke(app, ["schema", "export", "--out", str(out)])

    assert result.exit_code == 0, result.output
    for kind in ("control-efficacy-report", "threat-applicability-manifest"):
        path = out / f"{kind}.schema.json"
        assert path.is_file()
        schema = _json(path)
        Draft202012Validator.check_schema(schema)
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert schema["$id"] == (
            f"https://acblabs.github.io/agent-assure/schemas/v{SCHEMA_VERSION}/{kind}.schema.json"
        )
        required = cast(list[str], schema["required"])
        assert {
            "artifact_kind",
            "schema_version",
            "schema_name",
            "contract_id",
            "contract_version",
        }.issubset(required)


def test_packet_cli_binds_config_profile_and_ci_rejects_a_forged_embedded_pass(
    tmp_path: Path,
) -> None:
    workflow = tmp_path / "packet-workflow"
    scaffold_controls_mutation(workflow)
    _write_weakened_campaign(workflow)
    report_dir = workflow / "efficacy"
    efficacy = _invoke_efficacy(workflow, report_dir)
    assert efficacy.exit_code == 1, efficacy.output

    evaluation_path = workflow / "evaluation-summary.json"
    _write_json(
        evaluation_path,
        EvaluationSummary(
            runset_id="packet-efficacy-candidate",
            runset_digest=_control_efficacy_source_digest(
                report_dir / "control-efficacy-report.json"
            ),
            privacy_profile_id=PRIVACY_PROFILE_ID,
            privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
            state=GateState.pass_,
        ).model_dump(mode="json"),
    )
    report_path = report_dir / "control-efficacy-report.json"
    config_path = workflow / "controls-mutation.yaml"
    packet_path = workflow / "packet" / "evidence-packet.json"
    packet_build = _invoke_packet_build(
        evaluation_path,
        report_path,
        config_path,
        packet_path,
    )

    assert packet_build.exit_code == 0, packet_build.output
    packet = _json(packet_path)
    profile = cast(dict[str, Any], packet["control_efficacy_gate_profile"])
    assert profile["required_catalog"] == "core/v1"
    assert profile["required_operators"] == [OPERATOR_ID]
    assert profile["surviving_required_operator"] == "block"
    digests = cast(list[dict[str, Any]], packet["artifact_digests"])
    assert [item["role"] for item in digests] == [
        "evaluation-summary",
        "assurance-evidence-graph",
        "control-efficacy-report",
        "control-efficacy-onboarding-config",
    ]
    config_digest = next(
        item for item in digests if item["role"] == "control-efficacy-onboarding-config"
    )
    assert config_digest["sha256"] == file_sha256(config_path)
    manifest = cast(dict[str, Any], packet["release_manifest"])
    manifest_artifacts = cast(list[dict[str, Any]], manifest["artifacts"])
    assert "control-efficacy-onboarding-config" in {
        artifact["role"] for artifact in manifest_artifacts
    }

    original_gate = RUNNER.invoke(
        app,
        [
            "ci",
            "gate",
            str(packet_path),
            "--efficacy-policy",
            str(config_path),
            "--artifact-root",
            str(workflow),
        ],
    )
    assert original_gate.exit_code == 1, original_gate.output
    assert "gate_state=fail" in original_gate.output

    forged = json.loads(json.dumps(packet))
    forged["control_efficacy_gate"]["state"] = "pass"
    forged["control_efficacy_gate"]["findings"] = []
    forged_path = workflow / "forged-pass-packet.json"
    _write_json(forged_path, cast(dict[str, object], forged))
    forged_gate = RUNNER.invoke(
        app,
        [
            "ci",
            "gate",
            str(forged_path),
            "--efficacy-policy",
            str(config_path),
        ],
        terminal_width=240,
    )

    assert forged_gate.exit_code == 2, forged_gate.output
    assert "model validation" in forged_gate.output

    mismatched_config = workflow / "mismatched-controls-mutation.yaml"
    config_text = config_path.read_text(encoding="utf-8")
    config_text = config_text.replace(
        f"operator_ids:\n  - {OPERATOR_ID}\n",
        (f"operator_ids:\n  - {OPERATOR_ID}\n  - bypass-required-human-review\n"),
    ).replace(
        f"required_operators:\n    - {OPERATOR_ID}\n",
        "required_operators:\n    - bypass-required-human-review\n",
    )
    mismatched_config.write_text(config_text, encoding="utf-8", newline="\n")
    mismatched_packet = workflow / "mismatched-output" / "evidence-packet.json"
    mismatch = _invoke_packet_build(
        evaluation_path,
        report_path,
        mismatched_config,
        mismatched_packet,
    )

    assert mismatch.exit_code == 2, mismatch.output
    assert not mismatched_packet.exists()
    assert not mismatched_packet.parent.exists()


def test_packet_cli_hashes_and_manifests_the_exact_efficacy_snapshots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workflow = tmp_path / "snapshot-workflow"
    scaffold_controls_mutation(workflow)
    _write_weakened_campaign(workflow)
    report_dir = workflow / "efficacy"
    efficacy = _invoke_efficacy(workflow, report_dir)
    assert efficacy.exit_code == 1, efficacy.output

    evaluation_path = workflow / "evaluation-summary.json"
    _write_json(
        evaluation_path,
        EvaluationSummary(
            runset_id="snapshot-efficacy-candidate",
            runset_digest=_control_efficacy_source_digest(
                report_dir / "control-efficacy-report.json"
            ),
            privacy_profile_id=PRIVACY_PROFILE_ID,
            privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
            state=GateState.pass_,
        ).model_dump(mode="json"),
    )
    report_path = report_dir / "control-efficacy-report.json"
    config_path = workflow / "controls-mutation.yaml"
    packet_path = workflow / "packet" / "evidence-packet.json"
    original_bytes = {
        report_path.resolve(): report_path.read_bytes(),
        config_path.resolve(): config_path.read_bytes(),
    }
    original_reader = onboarding_path_safety.read_file_bounded_at
    read_counts = {path: 0 for path in original_bytes}

    def replace_after_snapshot(
        root: Path,
        relative_path: str | Path,
        **kwargs: Any,
    ) -> Any:
        contents = original_reader(root, relative_path, **kwargs)
        path = root / relative_path
        resolved = path.resolve()
        if resolved in original_bytes:
            read_counts[resolved] += 1
            path.write_bytes(b"replaced after snapshot\n")
        return contents

    monkeypatch.setattr(
        onboarding_path_safety,
        "read_file_bounded_at",
        replace_after_snapshot,
    )

    result = _invoke_packet_build(
        evaluation_path,
        report_path,
        config_path,
        packet_path,
    )

    assert result.exit_code == 0, result.output
    assert read_counts == {report_path.resolve(): 1, config_path.resolve(): 1}
    packet = _json(packet_path)
    expected_digests = {
        "control-efficacy-report": hashlib.sha256(
            original_bytes[report_path.resolve()]
        ).hexdigest(),
        "control-efficacy-onboarding-config": hashlib.sha256(
            original_bytes[config_path.resolve()]
        ).hexdigest(),
    }
    packet_digests = {
        item["role"]: item["sha256"]
        for item in cast(list[dict[str, Any]], packet["artifact_digests"])
        if item["role"] in expected_digests
    }
    assert packet_digests == expected_digests
    manifest = cast(dict[str, Any], packet["release_manifest"])
    manifest_digests = {
        item["role"]: item["sha256"]
        for item in cast(list[dict[str, Any]], manifest["artifacts"])
        if item["role"] in expected_digests
    }
    assert manifest_digests == expected_digests


def test_packet_cli_does_not_rebind_captured_report_path_after_symlink_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workflow = tmp_path / "snapshot-path-workflow"
    scaffold_controls_mutation(workflow)
    _write_weakened_campaign(workflow)
    report_dir = workflow / "efficacy"
    efficacy = _invoke_efficacy(workflow, report_dir)
    assert efficacy.exit_code == 1, efficacy.output

    evaluation_path = workflow / "evaluation-summary.json"
    _write_json(
        evaluation_path,
        EvaluationSummary(
            runset_id="snapshot-path-efficacy-candidate",
            runset_digest=_control_efficacy_source_digest(
                report_dir / "control-efficacy-report.json"
            ),
            privacy_profile_id=PRIVACY_PROFILE_ID,
            privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
            state=GateState.pass_,
        ).model_dump(mode="json"),
    )
    report_path = report_dir / "control-efficacy-report.json"
    config_path = workflow / "controls-mutation.yaml"
    packet_path = workflow / "packet" / "evidence-packet.json"
    peer_path = report_dir / "peer-report.json"
    peer_path.write_bytes(b"peer bytes must never select the manifest path\n")
    probe_path = report_dir / "symlink-capability-probe"
    try:
        probe_path.symlink_to(peer_path.name)
    except OSError as exc:
        pytest.skip(f"file symlinks unavailable: {exc}")
    finally:
        probe_path.unlink(missing_ok=True)

    original_report_bytes = report_path.read_bytes()
    preserved_path = report_dir / "captured-original-report.json"
    original_manifest_digest = packet_cmd._configured_threat_manifest_digest

    def swap_after_source_snapshots(*args: Any, **kwargs: Any) -> str:
        digest = original_manifest_digest(*args, **kwargs)
        report_path.replace(preserved_path)
        report_path.symlink_to(peer_path.name)
        return digest

    monkeypatch.setattr(
        packet_cmd,
        "_configured_threat_manifest_digest",
        swap_after_source_snapshots,
    )

    result = _invoke_packet_build(
        evaluation_path,
        report_path,
        config_path,
        packet_path,
    )

    assert result.exit_code == 0, result.output
    assert report_path.is_symlink()
    packet = _json(packet_path)
    manifest = cast(dict[str, Any], packet["release_manifest"])
    artifacts = {item["role"]: item for item in cast(list[dict[str, Any]], manifest["artifacts"])}
    report_artifact = artifacts["control-efficacy-report"]
    assert report_artifact["path"] == "efficacy/control-efficacy-report.json"
    assert report_artifact["path"] != "efficacy/peer-report.json"
    assert report_artifact["sha256"] == hashlib.sha256(original_report_bytes).hexdigest()


def test_packet_cli_never_resolves_efficacy_path_after_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workflow = tmp_path / "snapshot-resolve-workflow"
    scaffold_controls_mutation(workflow)
    _write_weakened_campaign(workflow)
    report_dir = workflow / "efficacy"
    efficacy = _invoke_efficacy(workflow, report_dir)
    assert efficacy.exit_code == 1, efficacy.output

    evaluation_path = workflow / "evaluation-summary.json"
    _write_json(
        evaluation_path,
        EvaluationSummary(
            runset_id="snapshot-resolve-efficacy-candidate",
            runset_digest=_control_efficacy_source_digest(
                report_dir / "control-efficacy-report.json"
            ),
            privacy_profile_id=PRIVACY_PROFILE_ID,
            privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
            state=GateState.pass_,
        ).model_dump(mode="json"),
    )
    report_path = report_dir / "control-efficacy-report.json"
    config_path = workflow / "controls-mutation.yaml"
    packet_path = workflow / "packet" / "evidence-packet.json"
    peer_path = report_dir / "resolve-peer-report.json"
    peer_path.write_bytes(b"peer bytes must never select the manifest path\n")

    armed = False
    original_manifest_digest = packet_cmd._configured_threat_manifest_digest
    path_type = type(report_path)
    original_resolve = path_type.resolve
    report_identity = os.path.normcase(os.path.abspath(report_path))
    peer_absolute = Path(os.path.abspath(peer_path))

    def arm_after_source_snapshots(*args: Any, **kwargs: Any) -> str:
        nonlocal armed
        digest = original_manifest_digest(*args, **kwargs)
        armed = True
        return digest

    def resolve_with_post_snapshot_rebind(
        path: Path,
        *,
        strict: bool = False,
    ) -> Path:
        if armed and os.path.normcase(os.path.abspath(path)) == report_identity:
            return peer_absolute
        return original_resolve(path, strict=strict)

    monkeypatch.setattr(
        packet_cmd,
        "_configured_threat_manifest_digest",
        arm_after_source_snapshots,
    )
    monkeypatch.setattr(path_type, "resolve", resolve_with_post_snapshot_rebind)

    result = _invoke_packet_build(
        evaluation_path,
        report_path,
        config_path,
        packet_path,
    )

    assert result.exit_code == 0, result.output
    packet = _json(packet_path)
    manifest = cast(dict[str, Any], packet["release_manifest"])
    artifacts = {item["role"]: item for item in cast(list[dict[str, Any]], manifest["artifacts"])}
    report_artifact = artifacts["control-efficacy-report"]
    assert report_artifact["path"] == "efficacy/control-efficacy-report.json"
    assert report_artifact["path"] != "efficacy/resolve-peer-report.json"


def test_packet_cli_rejects_config_with_stale_threat_manifest_before_outputs(
    tmp_path: Path,
) -> None:
    workflow = tmp_path / "stale-manifest-workflow"
    scaffold_controls_mutation(workflow)
    _run_mutation(workflow)
    report_dir = workflow / "efficacy"
    efficacy = _invoke_efficacy(workflow, report_dir)
    assert efficacy.exit_code == 0, efficacy.output

    manifest_path = workflow / "threat-applicability.yaml"
    manifest_text = manifest_path.read_text(encoding="utf-8")
    manifest_path.write_text(
        manifest_text.replace(
            "applicability: applicable",
            "applicability: unknown",
            1,
        ),
        encoding="utf-8",
        newline="\n",
    )
    evaluation_path = workflow / "evaluation-summary.json"
    _write_json(
        evaluation_path,
        EvaluationSummary(
            runset_id="stale-manifest-candidate",
            runset_digest=_control_efficacy_source_digest(
                report_dir / "control-efficacy-report.json"
            ),
            privacy_profile_id=PRIVACY_PROFILE_ID,
            privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
            state=GateState.pass_,
        ).model_dump(mode="json"),
    )
    packet_path = workflow / "packet" / "evidence-packet.json"

    result = _invoke_packet_build(
        evaluation_path,
        report_dir / "control-efficacy-report.json",
        workflow / "controls-mutation.yaml",
        packet_path,
    )

    assert result.exit_code == 2, result.output
    normalized_output = " ".join(result.output.split())
    assert "threat manifest does not match" in normalized_output
    assert "report scope" in normalized_output
    assert not packet_path.exists()
    assert not packet_path.parent.exists()


def test_packet_cli_rejects_hard_linked_control_efficacy_report(
    tmp_path: Path,
) -> None:
    workflow = tmp_path / "hard-linked-report-workflow"
    scaffold_controls_mutation(workflow)
    _run_mutation(workflow)
    report_dir = workflow / "efficacy"
    efficacy = _invoke_efficacy(workflow, report_dir)
    assert efficacy.exit_code == 0, efficacy.output

    report_path = report_dir / "control-efficacy-report.json"
    report_peer = report_dir / "control-efficacy-report-peer.json"
    try:
        os.link(report_path, report_peer)
    except OSError as exc:
        pytest.skip(f"hard links are unavailable: {exc}")

    evaluation_path = workflow / "evaluation-summary.json"
    _write_json(
        evaluation_path,
        EvaluationSummary(
            runset_id="hard-linked-report-candidate",
            runset_digest=_control_efficacy_source_digest(report_path),
            privacy_profile_id=PRIVACY_PROFILE_ID,
            privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
            state=GateState.pass_,
        ).model_dump(mode="json"),
    )
    packet_path = workflow / "packet" / "evidence-packet.json"

    result = _invoke_packet_build(
        evaluation_path,
        report_path,
        workflow / "controls-mutation.yaml",
        packet_path,
    )

    assert result.exit_code == 2, result.output
    assert "must be a confined, unlinked regular" in " ".join(result.output.split())
    assert not packet_path.exists()


def test_packet_cli_rejects_input_output_alias_before_any_write(tmp_path: Path) -> None:
    evaluation_path = tmp_path / "evaluation-summary.json"
    _write_json(
        evaluation_path,
        EvaluationSummary(
            runset_id="packet-alias-candidate",
            runset_digest=_fixture_runset_digest("packet-alias-candidate"),
            privacy_profile_id=PRIVACY_PROFILE_ID,
            privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
            state=GateState.pass_,
        ).model_dump(mode="json"),
    )
    source_bytes = evaluation_path.read_bytes()

    result = RUNNER.invoke(
        app,
        [
            "packet",
            "build",
            str(evaluation_path),
            "--out",
            str(evaluation_path),
        ],
    )

    assert result.exit_code == 2, result.output
    assert "packet input aliases an owned output path" in result.output
    assert evaluation_path.read_bytes() == source_bytes
    assert not (tmp_path / "evaluation-summary.md").exists()
    assert not (tmp_path / "release-artifact-manifest.json").exists()
    assert not (tmp_path / "dependency-inventory.json").exists()


def test_unsorted_multi_operator_config_runs_mutation_efficacy_and_packet(
    tmp_path: Path,
) -> None:
    workflow = tmp_path / "multi-operator-workflow"
    scaffold_controls_mutation(workflow)
    config_path = workflow / "controls-mutation.yaml"
    config_path.write_text(
        config_path.read_text(encoding="utf-8")
        .replace(
            "operator_ids:\n  - drop-material-evidence-link\n",
            (
                "operator_ids:\n"
                "  - replay-duplicate-case-observation\n"
                "  - drop-material-evidence-link\n"
            ),
        )
        .replace(
            "control_efficacy:\n",
            "control_efficacy:\n  profile_id: integration/custom-efficacy\n",
        ),
        encoding="utf-8",
        newline="\n",
    )
    manifest_path = workflow / "threat-applicability.yaml"
    manifest_path.write_text(
        manifest_path.read_text(encoding="utf-8")
        .replace(
            "  - threat_id: material-claim-link-regression\n",
            (
                "  - threat_id: invalid-structured-record\n"
                "    applicability: applicable\n"
                "    critical: false\n"
                "    rationale: Replay integrity is in scope for this integration.\n"
                "    owner: integration-test\n"
                '    reviewed_at: "2026-08-08"\n'
                "  - threat_id: material-claim-link-regression\n"
            ),
        )
        .replace(
            "declares two applicable threat references",
            "declares three applicable threat references",
        ),
        encoding="utf-8",
        newline="\n",
    )
    doctor = RUNNER.invoke(
        app,
        ["doctor", "controls-mutate", "--config", str(config_path)],
    )
    assert doctor.exit_code == 0, doctor.output

    mutation = RUNNER.invoke(
        app,
        [
            "controls",
            "mutate",
            "--suite",
            str(workflow / "suite.yaml"),
            "--runset",
            str(workflow / "runset.json"),
            "--catalog",
            "core/v1",
            "--operator",
            "replay-duplicate-case-observation",
            "--operator",
            OPERATOR_ID,
            "--out",
            str(workflow / "mutation-results"),
        ],
    )
    assert mutation.exit_code == 0, mutation.output
    campaign = _json(workflow / "mutation-results" / "assurance-mutation-campaign.json")
    assert campaign["selected_operator_order"] == [
        OPERATOR_ID,
        "replay-duplicate-case-observation",
    ]

    report_dir = workflow / "efficacy"
    efficacy = _invoke_efficacy(workflow, report_dir)
    assert efficacy.exit_code == 0, efficacy.output
    markdown = (report_dir / "control-efficacy-report.md").read_text(encoding="utf-8")
    assert "integration/custom-efficacy" in markdown

    evaluation_path = workflow / "evaluation-summary.json"
    _write_json(
        evaluation_path,
        EvaluationSummary(
            runset_id="multi-operator-candidate",
            runset_digest=_control_efficacy_source_digest(
                report_dir / "control-efficacy-report.json"
            ),
            privacy_profile_id=PRIVACY_PROFILE_ID,
            privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
            state=GateState.pass_,
        ).model_dump(mode="json"),
    )
    packet_path = workflow / "packet" / "evidence-packet.json"
    packet_build = _invoke_packet_build(
        evaluation_path,
        report_dir / "control-efficacy-report.json",
        config_path,
        packet_path,
    )

    assert packet_build.exit_code == 0, packet_build.output
    packet = _json(packet_path)
    profile = cast(dict[str, Any], packet["control_efficacy_gate_profile"])
    assert profile["profile_id"] == "integration/custom-efficacy"


def test_controls_efficacy_rejects_config_and_manifest_output_aliases(
    tmp_path: Path,
) -> None:
    workflow = tmp_path / "efficacy-alias-workflow"
    scaffold_controls_mutation(workflow)
    mutation = RUNNER.invoke(
        app,
        [
            "controls",
            "mutate",
            "--suite",
            str(workflow / "suite.yaml"),
            "--runset",
            str(workflow / "runset.json"),
            "--catalog",
            "core/v1",
            "--operator",
            OPERATOR_ID,
            "--out",
            str(workflow / "mutation-results"),
        ],
    )
    assert mutation.exit_code == 0, mutation.output

    config_alias = workflow / "control-efficacy-report.json"
    config_alias.write_bytes((workflow / "controls-mutation.yaml").read_bytes())
    original_config = config_alias.read_bytes()
    config_result = RUNNER.invoke(
        app,
        [
            "controls",
            "efficacy",
            "--config",
            str(config_alias),
            "--out",
            str(workflow),
        ],
        terminal_width=240,
    )
    assert config_result.exit_code == 2, config_result.output
    assert "input aliases an owned output path" in " ".join(config_result.output.split())
    assert config_alias.read_bytes() == original_config

    alias_dir = workflow / "manifest-alias"
    alias_dir.mkdir()
    manifest_alias = alias_dir / "control-efficacy-report.json"
    manifest_alias.write_bytes((workflow / "threat-applicability.yaml").read_bytes())
    original_manifest = manifest_alias.read_bytes()
    config_text = (workflow / "controls-mutation.yaml").read_text(encoding="utf-8")
    (workflow / "controls-mutation.yaml").write_text(
        config_text.replace(
            "threat_applicability_manifest: threat-applicability.yaml",
            ("threat_applicability_manifest: manifest-alias/control-efficacy-report.json"),
        ),
        encoding="utf-8",
        newline="\n",
    )
    manifest_result = _invoke_efficacy(workflow, alias_dir)

    assert manifest_result.exit_code == 2, manifest_result.output
    assert "input aliases an owned output path" in " ".join(manifest_result.output.split())
    assert manifest_alias.read_bytes() == original_manifest
    assert not (alias_dir / "control-efficacy-report.md").exists()


def test_controls_efficacy_missing_campaign_is_actionable_and_read_only(
    tmp_path: Path,
) -> None:
    workflow = tmp_path / "first-run"
    scaffold_controls_mutation(workflow)

    result = _invoke_efficacy(workflow, workflow / "efficacy")

    assert result.exit_code == 2, result.output
    assert "configured mutation campaign is missing" in result.output
    assert "agent-assure controls mutate" in result.output
    assert not (workflow / "mutation-results").exists()
    assert not (workflow / "efficacy").exists()


def test_controls_efficacy_confines_explicit_campaign_unless_opted_out(
    tmp_path: Path,
) -> None:
    configured = tmp_path / "configured"
    external = tmp_path / "external"
    scaffold_controls_mutation(configured)
    scaffold_controls_mutation(external)
    _run_mutation(external)
    confined_out = configured / "confined-efficacy"

    confined = RUNNER.invoke(
        app,
        [
            "controls",
            "efficacy",
            "--config",
            str(configured / "controls-mutation.yaml"),
            "--campaign",
            str(external / "mutation-results"),
            "--out",
            str(confined_out),
        ],
        terminal_width=240,
    )

    assert confined.exit_code == 2, confined.output
    assert "mutation campaign escapes its allowed root" in " ".join(confined.output.split())
    assert not confined_out.exists()

    allowed_out = configured / "external-efficacy"
    allowed = RUNNER.invoke(
        app,
        [
            "controls",
            "efficacy",
            "--config",
            str(configured / "controls-mutation.yaml"),
            "--campaign",
            str(external / "mutation-results"),
            "--allow-external-campaign",
            "--out",
            str(allowed_out),
        ],
        terminal_width=240,
    )

    assert allowed.exit_code == 0, allowed.output
    assert (allowed_out / "control-efficacy-report.json").is_file()


@pytest.mark.parametrize("mismatch", ("source", "suite"))
def test_controls_efficacy_rejects_cross_context_campaign_substitution(
    tmp_path: Path,
    mismatch: str,
) -> None:
    configured = tmp_path / "configured"
    substituted = tmp_path / "substituted"
    scaffold_controls_mutation(configured)
    scaffold_controls_mutation(substituted)
    runset_path = substituted / "runset.json"
    runset = _json(runset_path)
    if mismatch == "source":
        runset["runset_id"] = "substituted-runset-context"
    else:
        suite_path = substituted / "suite.yaml"
        suite_path.write_text(
            suite_path.read_text(encoding="utf-8").replace(
                "suite_id: controls-mutation-quickstart",
                "suite_id: controls-mutation-substituted",
            ),
            encoding="utf-8",
            newline="\n",
        )
        suite = compile_suite(suite_path)
        runset["suite_id"] = suite.suite_id
        runset["suite_digest"] = compiled_suite_digest(suite)
    _write_json(runset_path, cast(dict[str, object], runset))
    _run_mutation(substituted)
    report_dir = configured / "efficacy"

    result = RUNNER.invoke(
        app,
        [
            "controls",
            "efficacy",
            "--config",
            str(configured / "controls-mutation.yaml"),
            "--campaign",
            str(substituted / "mutation-results"),
            "--allow-external-campaign",
            "--out",
            str(report_dir),
        ],
        terminal_width=240,
    )

    assert result.exit_code == 2, result.output
    assert f"campaign {mismatch} digest does not match the configured" in " ".join(
        result.output.split()
    )
    assert not report_dir.exists()


@pytest.mark.parametrize("aliased_input", ("suite", "runset"))
def test_controls_efficacy_protects_configured_suite_and_runset_from_output_aliases(
    tmp_path: Path,
    aliased_input: str,
) -> None:
    workflow = tmp_path / f"{aliased_input}-alias-workflow"
    scaffold_controls_mutation(workflow)
    _run_mutation(workflow)
    alias_dir = workflow / f"{aliased_input}-alias"
    alias_dir.mkdir()
    alias = alias_dir / "control-efficacy-report.json"
    config_path = workflow / "controls-mutation.yaml"
    config_text = config_path.read_text(encoding="utf-8")
    if aliased_input == "suite":
        suite = compile_suite(workflow / "suite.yaml")
        _write_json(alias, cast(dict[str, object], suite.model_dump(mode="json")))
        config_text = config_text.replace(
            "suite_path: suite.yaml",
            "suite_path: suite-alias/control-efficacy-report.json",
        )
    else:
        alias.write_bytes((workflow / "runset.json").read_bytes())
        config_text = config_text.replace(
            "runset_path: runset.json",
            "runset_path: runset-alias/control-efficacy-report.json",
        )
    original = alias.read_bytes()
    config_path.write_text(config_text, encoding="utf-8", newline="\n")

    result = _invoke_efficacy(workflow, alias_dir)

    assert result.exit_code == 2, result.output
    assert "input aliases an owned output path" in " ".join(result.output.split())
    assert alias.read_bytes() == original
    assert not (alias_dir / "control-efficacy-report.md").exists()


def test_controls_efficacy_rejects_hard_linked_configured_manifest(
    tmp_path: Path,
) -> None:
    workflow = tmp_path / "hard-linked-manifest"
    scaffold_controls_mutation(workflow)
    _run_mutation(workflow)
    manifest = workflow / "threat-applicability.yaml"
    peer = workflow / "manifest-peer.yaml"
    manifest.replace(peer)
    try:
        os.link(peer, manifest)
    except OSError as exc:
        pytest.skip(f"hard links are unavailable: {exc}")
    report_dir = workflow / "efficacy"

    result = _invoke_efficacy(workflow, report_dir)

    assert result.exit_code == 2, result.output
    assert "configured threat applicability manifest must be a confined" in " ".join(
        result.output.split()
    )
    assert not report_dir.exists()


def test_controls_efficacy_rechecks_manifest_link_policy_at_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probe = tmp_path / "hard-link-probe"
    probe_peer = tmp_path / "hard-link-probe-peer"
    probe.write_bytes(b"probe\n")
    try:
        os.link(probe, probe_peer)
    except OSError as exc:
        pytest.skip(f"hard links are unavailable: {exc}")
    probe_peer.unlink()
    probe.unlink()

    workflow = tmp_path / "manifest-swap-at-read"
    scaffold_controls_mutation(workflow)
    _run_mutation(workflow)
    manifest = workflow / "threat-applicability.yaml"
    peer = workflow / "manifest-peer.yaml"
    real_binding_loader = controls_cmd.load_controls_mutation_input_binding

    def swap_manifest_after_preflight(*args: Any, **kwargs: Any) -> Any:
        binding = real_binding_loader(*args, **kwargs)
        manifest.replace(peer)
        os.link(peer, manifest)
        return binding

    monkeypatch.setattr(
        controls_cmd,
        "load_controls_mutation_input_binding",
        swap_manifest_after_preflight,
    )
    report_dir = workflow / "efficacy"

    result = _invoke_efficacy(workflow, report_dir)

    assert result.exit_code == 2, result.output
    assert "configured threat applicability manifest must be a confined" in " ".join(
        result.output.split()
    )
    assert not report_dir.exists()


def test_controls_efficacy_accepts_safe_lexical_dotdot_config_spelling(
    tmp_path: Path,
) -> None:
    workflow = tmp_path / "dotdot-workflow"
    scaffold_controls_mutation(workflow)
    _run_mutation(workflow)
    lexical_parent = tmp_path / "lexical-parent"
    lexical_parent.mkdir()
    config = lexical_parent / ".." / workflow.name / "controls-mutation.yaml"
    assert ".." in config.parts
    report_dir = workflow / "dotdot-efficacy"

    result = RUNNER.invoke(
        app,
        [
            "controls",
            "efficacy",
            "--config",
            str(config),
            "--out",
            str(report_dir),
        ],
        terminal_width=240,
    )

    assert result.exit_code == 0, result.output
    assert (report_dir / "control-efficacy-report.json").is_file()


def test_controls_efficacy_rejects_linked_configuration_parent(
    tmp_path: Path,
) -> None:
    workflow = tmp_path / "linked-parent-workflow"
    scaffold_controls_mutation(workflow)
    _run_mutation(workflow)
    linked_workflow = tmp_path / "linked-workflow"
    try:
        linked_workflow.symlink_to(workflow, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory links are unavailable: {exc}")
    report_dir = workflow / "linked-parent-efficacy"

    result = RUNNER.invoke(
        app,
        [
            "controls",
            "efficacy",
            "--config",
            str(linked_workflow / "controls-mutation.yaml"),
            "--out",
            str(report_dir),
        ],
        terminal_width=240,
    )

    assert result.exit_code == 2, result.output
    assert "controls-mutation config must be a confined, unlinked regular file" in (
        " ".join(result.output.split())
    )
    assert not report_dir.exists()


def _invoke_efficacy(
    workflow: Path,
    out: Path,
    *,
    terminal_width: int = 240,
) -> Result:
    return RUNNER.invoke(
        app,
        [
            "controls",
            "efficacy",
            "--config",
            str(workflow / "controls-mutation.yaml"),
            "--out",
            str(out),
        ],
        terminal_width=terminal_width,
    )


def _run_mutation(workflow: Path) -> None:
    result = RUNNER.invoke(
        app,
        [
            "controls",
            "mutate",
            "--suite",
            str(workflow / "suite.yaml"),
            "--runset",
            str(workflow / "runset.json"),
            "--catalog",
            "core/v1",
            "--operator",
            OPERATOR_ID,
            "--out",
            str(workflow / "mutation-results"),
        ],
        terminal_width=240,
    )
    assert result.exit_code == 0, result.output


def _invoke_packet_build(
    evaluation: Path,
    efficacy_report: Path,
    efficacy_config: Path,
    out: Path,
) -> Result:
    return RUNNER.invoke(
        app,
        [
            "packet",
            "build",
            str(evaluation),
            "--control-efficacy",
            str(efficacy_report),
            "--efficacy-config",
            str(efficacy_config),
            "--out",
            str(out),
        ],
        terminal_width=240,
    )


def _write_weakened_campaign(workflow: Path) -> None:
    suite = compile_suite(workflow / "suite.yaml")
    source_payload = load_json_bounded(
        workflow / "runset.json",
        label="weakened integration RunSet",
    )
    execution = execute_mutation_campaign(
        suite,
        source_payload,
        seed=0,
        generated_at=GENERATED_AT,
        operator_ids=(OPERATOR_ID,),
        gate_profile=GateProfile(
            profile_id="integration-deliberately-weakened",
            fail_severities=(Severity.info,),
        ),
        evaluation_date=EVALUATION_DATE,
    )
    assert execution.campaign.operator_results[0].result.state.value == "survived"
    write_mutation_campaign_artifacts(
        execution,
        workflow / "mutation-results",
        source_inputs=(workflow / "suite.yaml", workflow / "runset.json"),
    )


def _json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _fixture_runset_digest(runset_id: str) -> str:
    return hashlib.sha256(f"synthetic-runset:{runset_id}".encode()).hexdigest()


def _control_efficacy_source_digest(report_path: Path) -> str:
    return cast(str, _json(report_path)["source_digest"])


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
