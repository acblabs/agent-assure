from __future__ import annotations

import hashlib
import json
import os
import shutil
import threading
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest
import yaml
from typer.testing import CliRunner, Result

import agent_assure.rag.sensitivity as sensitivity_module
import agent_assure.reporting.sensitivity as sensitivity_reporting_module
from agent_assure.authoring.compiler import compile_suite
from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.ci import GateOutcome, gate_evidence_packet
from agent_assure.cli import rag_cmd as rag_cmd_module
from agent_assure.cli.main import app
from agent_assure.demo.evidence_sensitivity import (
    render_evidence_sensitivity_text,
    run_evidence_sensitivity_demo,
)
from agent_assure.fixtures.loader import compiled_suite_digest
from agent_assure.fixtures.manifest import (
    build_fixture_manifest,
    fixture_manifest_digest,
)
from agent_assure.privacy.detectors import MAX_PRIVACY_SCAN_CHARS
from agent_assure.rag.sensitivity import (
    SensitivityInputError,
    execute_sensitivity_experiment,
    load_knowledge_contract,
    load_sensitivity_corpus,
    load_sensitivity_report,
)
from agent_assure.release_evidence import build_digest_replay, verify_digest_replay
from agent_assure.reporting.graph import load_evidence_graph
from agent_assure.reporting.packet import (
    load_evidence_packet,
    packet_summary_files_binding_error,
)
from agent_assure.reporting.sensitivity import (
    SensitivityPrivacyError,
    render_sensitivity_html,
    write_sensitivity_execution_artifacts,
)
from agent_assure.rooted_io import RootedDirectoryDescriptor
from agent_assure.schema.common import GateState
from agent_assure.schema.comparison import ComparisonSummary
from agent_assure.schema.release import ReleaseArtifactManifest
from agent_assure.schema.sensitivity import (
    EvidenceSensitivityExpectedRelation,
    EvidenceSensitivityGateEffect,
    EvidenceSensitivityObservedRelation,
    EvidenceSensitivityOutcomeClassification,
    EvidenceSensitivityReasonCode,
    EvidenceSensitivityState,
    RAGSensitivityCorpusDocument,
    RAGSensitivityCorpusManifest,
    RAGSensitivityDecision,
    RAGSensitivityKnowledgeContract,
    RAGSensitivityReport,
    RAGSensitivitySyntheticDataAttestation,
    SyntheticDataProvenance,
)
from agent_assure.sensitivity_comparison import derive_sensitivity_comparison
from agent_assure.sensitivity_contract import (
    SENSITIVITY_HARNESS_NOTICE,
    SENSITIVITY_PROVENANCE_BINDING,
    SENSITIVITY_SUBJECT_EXECUTION_SCOPE,
    bundled_sensitivity_identity_set,
)

RUNNER = CliRunner()
ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "examples" / "evidence_sensitivity"
GOLDEN_REPORTS = ROOT / "tests" / "golden" / "reports"
OUTPUT_FILENAMES = {
    "baseline-corpus-snapshot.json",
    "baseline-evaluation-summary.json",
    "baseline.runset.json",
    "compiled-suite.json",
    "counterfactual-corpus-snapshot.json",
    "counterfactual-evaluation-summary.json",
    "counterfactual.runset.json",
    "comparison-summary.json",
    "evidence-sensitivity.html",
    "evidence-sensitivity.json",
    "evidence-sensitivity.md",
    "fixture-manifest.json",
    "protocol.json",
    "assurance-evidence-graph.json",
    "release-artifact-manifest.json",
    "evidence-packet.json",
    "evidence-packet.md",
}
MANIFEST_BOUND_FILES = {
    "compiled-suite": "compiled-suite.json",
    "fixture-manifest": "fixture-manifest.json",
    "evidence-sensitivity-protocol": "protocol.json",
    "baseline-corpus-snapshot": "baseline-corpus-snapshot.json",
    "counterfactual-corpus-snapshot": "counterfactual-corpus-snapshot.json",
    "baseline-runset": "baseline.runset.json",
    "candidate-runset": "counterfactual.runset.json",
    "baseline-evaluation-summary": "baseline-evaluation-summary.json",
    "evaluation-summary": "counterfactual-evaluation-summary.json",
    "comparison-summary": "comparison-summary.json",
    "evidence-sensitivity-report": "evidence-sensitivity.json",
    "evidence-sensitivity-markdown": "evidence-sensitivity.md",
    "evidence-sensitivity-html": "evidence-sensitivity.html",
    "assurance-evidence-graph": "assurance-evidence-graph.json",
}


def test_recorded_walkthrough_console_facts_match_actual_demo_summary(
    tmp_path: Path,
) -> None:
    walkthrough = (ROOT / "docs" / "assets" / "evidence_sensitivity_walkthrough.txt").read_text(
        encoding="utf-8"
    )
    expected = walkthrough.split("EXPECTED CONSOLE FACTS:\n\n", 1)[1].split(
        "\n\nThe wrapper returns",
        1,
    )[0]
    out = tmp_path / "walkthrough-demo"
    summary = run_evidence_sensitivity_demo(out, clean=True)

    assert summary == _json(out / "demo-summary.json")
    assert expected == render_evidence_sensitivity_text(summary)


def test_responsive_subject_emits_a_verdict_bearing_pass_and_renderings(
    tmp_path: Path,
) -> None:
    out = tmp_path / "responsive"
    result = _invoke_sensitivity(
        example=EXAMPLE,
        suite_name="responsive_suite.yaml",
        out=out,
    )

    assert result.exit_code == 0, result.output
    assert {path.name for path in out.iterdir()} == OUTPUT_FILENAMES
    report = load_sensitivity_report(out / "evidence-sensitivity.json")
    comparison = ComparisonSummary.model_validate(_json(out / "comparison-summary.json"))
    graph = load_evidence_graph(out / "assurance-evidence-graph.json")
    manifest = ReleaseArtifactManifest.model_validate(_json(out / "release-artifact-manifest.json"))
    packet = load_evidence_packet(out / "evidence-packet.json")
    assert packet.evaluation == report.counterfactual_evaluation
    assert packet.comparison == comparison
    assert packet.evidence_sensitivity == report
    assert packet.release_manifest == manifest
    assert {item.role: item.path for item in manifest.artifacts} == MANIFEST_BOUND_FILES
    assert all(
        item.sha256 == hashlib.sha256((out / item.path).read_bytes()).hexdigest()
        for item in manifest.artifacts
    )
    replay = build_digest_replay(
        tuple((item.role, out / item.path) for item in manifest.artifacts),
        project_root=out,
    )
    assert verify_digest_replay(replay, artifact_root=out).ok
    assert {item.role for item in packet.artifact_digests} == {
        "evaluation-summary",
        "comparison-summary",
        "evidence-sensitivity-report",
        "assurance-evidence-graph",
    }
    assert packet.evidence_graph_digest == graph.graph_digest
    assert packet_summary_files_binding_error(packet, artifact_root=out) is None
    packet_decision = gate_evidence_packet(
        packet,
        artifact_root=out,
        require_evidence_sensitivity=True,
        allow_missing_efficacy_for_migration=True,
    )
    assert packet_decision.outcome is GateOutcome.pass_
    assert packet_decision.exit_code == 0
    assert comparison == derive_sensitivity_comparison(report)
    assert comparison.baseline_runset_digest == report.baseline_arm.runset_digest
    assert comparison.candidate_runset_digest == report.counterfactual_arm.runset_digest
    assert comparison.environment is None
    assert report.state is EvidenceSensitivityState.responsive
    assert report.gate_effect is EvidenceSensitivityGateEffect.pass_
    assert report.verdict_bearing is True
    assert report.endpoint_value is True
    assert report.baseline_arm.decision is RAGSensitivityDecision.approve
    assert report.counterfactual_arm.decision is RAGSensitivityDecision.deny
    assert report.baseline_arm.evaluation_state is GateState.pass_
    assert report.counterfactual_arm.evaluation_state is GateState.pass_
    assert report.baseline_arm.evidence_link_present is True
    assert report.counterfactual_arm.evidence_link_present is True
    assert report.reason_codes == ()
    assert report.synthetic_data_provenance is SyntheticDataProvenance.bundled_digest_verified
    assert report.synthetic_data_attestation_digest is None
    assert report.protocol.synthetic_data_attestation is None
    assert report.population_claim == "none_bundled_synthetic_fixture_only"
    assert report.raw_content_persistence == "exact_corpus_and_fixture_utf8_embedded"
    assert report.subject_execution_scope == SENSITIVITY_SUBJECT_EXECUTION_SCOPE
    assert report.provenance_binding == SENSITIVITY_PROVENANCE_BINDING
    checks = report.protocol.controlled_difference_manifest.checks
    assert sum(item.basis == "protocol_fixed" for item in checks) == 13
    assert sum(item.basis == "arm_observed" for item in checks) == 8
    for role, arm, snapshot, runset in (
        (
            "baseline",
            report.baseline_arm,
            report.baseline_corpus_snapshot,
            report.baseline_runset,
        ),
        (
            "counterfactual",
            report.counterfactual_arm,
            report.counterfactual_corpus_snapshot,
            report.counterfactual_runset,
        ),
    ):
        binding = sha256_hexdigest(
            {
                "protocol_digest": report.protocol.protocol_digest,
                "arm_role": role,
                "subject_configuration_digest": (report.protocol.subject_configuration_digest),
                "corpus_snapshot_digest": snapshot.snapshot_digest,
            }
        )[:24]
        assert runset.runset_id == f"sensitivity-runset-{role}-{binding}"
        assert runset.runs[0].run_id == f"sensitivity-run-{role}-{binding}"
        assert arm.runset_id == runset.runset_id
    assert SENSITIVITY_HARNESS_NOTICE in result.output
    assert "controlled evidence sensitivity state: responsive" in result.output
    assert "assurance evidence graph:" in result.output
    assert "release artifact manifest:" in result.output
    assert "evidence packet:" in result.output
    assert "evidence packet markdown:" in result.output
    _assert_renderings(
        out,
        report.model_dump(mode="json"),
        golden_stem="evidence-sensitivity-responsive",
    )


def test_evidence_inertial_subject_blocks_while_citations_and_evaluations_pass(
    tmp_path: Path,
) -> None:
    out = tmp_path / "evidence-inertial"
    result = _invoke_sensitivity(
        example=EXAMPLE,
        suite_name="evidence_inertial_suite.yaml",
        out=out,
    )

    assert result.exit_code == 1, result.output
    report = load_sensitivity_report(out / "evidence-sensitivity.json")
    packet_decision = gate_evidence_packet(
        load_evidence_packet(out / "evidence-packet.json"),
        artifact_root=out,
        require_evidence_sensitivity=True,
        allow_missing_efficacy_for_migration=True,
    )
    assert packet_decision.outcome is GateOutcome.fail
    assert packet_decision.exit_code == 1
    assert report.state is EvidenceSensitivityState.evidence_insensitive
    assert report.gate_effect is EvidenceSensitivityGateEffect.block
    assert report.verdict_bearing is True
    assert report.endpoint_value is False
    assert report.baseline_arm.decision is RAGSensitivityDecision.approve
    assert report.counterfactual_arm.decision is RAGSensitivityDecision.approve
    assert report.baseline_arm.evaluation_state is GateState.pass_
    assert report.counterfactual_arm.evaluation_state is GateState.pass_
    assert report.baseline_arm.retrieval_succeeded is True
    assert report.counterfactual_arm.retrieval_succeeded is True
    assert report.baseline_arm.governing_evidence_supported is True
    assert report.counterfactual_arm.governing_evidence_supported is True
    assert report.baseline_arm.evidence_link_present is True
    assert report.counterfactual_arm.evidence_link_present is True
    assert report.decision_inertia_finding.detected is True
    assert report.reason_codes == (EvidenceSensitivityReasonCode.expected_response_missing,)
    assert SENSITIVITY_HARNESS_NOTICE in result.output
    assert "decision inertia detected: true" in result.output
    _assert_renderings(
        out,
        report.model_dump(mode="json"),
        golden_stem="evidence-sensitivity-inertial",
    )


def test_evidence_reversed_subject_blocks_on_wrong_decision_flip(
    tmp_path: Path,
) -> None:
    out = tmp_path / "evidence-reversed"
    result = _invoke_sensitivity(
        example=EXAMPLE,
        suite_name="evidence_reversed_suite.yaml",
        out=out,
    )

    assert result.exit_code == 1, result.output
    report = load_sensitivity_report(out / "evidence-sensitivity.json")
    packet_decision = gate_evidence_packet(
        load_evidence_packet(out / "evidence-packet.json"),
        artifact_root=out,
        require_evidence_sensitivity=True,
        allow_missing_efficacy_for_migration=True,
    )
    assert packet_decision.outcome is GateOutcome.fail
    assert packet_decision.exit_code == 1
    assert report.state is EvidenceSensitivityState.evidence_insensitive
    assert report.gate_effect is EvidenceSensitivityGateEffect.block
    assert report.verdict_bearing is True
    assert report.endpoint_value is False
    assert report.observed_relation is EvidenceSensitivityObservedRelation.decision_flip
    assert (
        report.outcome_classification
        is EvidenceSensitivityOutcomeClassification.wrong_direction_flip
    )
    assert report.outcome_message == (
        "Expected decisions (baseline -> counterfactual): approve -> deny; observed decisions: "
        "deny -> approve. The subject changed decision fields, but in the wrong direction "
        "relative to the authority contract."
    )
    assert report.baseline_arm.decision is RAGSensitivityDecision.deny
    assert report.counterfactual_arm.decision is RAGSensitivityDecision.approve
    assert report.baseline_arm.evaluation_state is GateState.pass_
    assert report.counterfactual_arm.evaluation_state is GateState.pass_
    assert report.baseline_arm.governing_evidence_supported is True
    assert report.counterfactual_arm.governing_evidence_supported is True
    assert report.baseline_arm.evidence_link_present is True
    assert report.counterfactual_arm.evidence_link_present is True
    assert report.decision_inertia_finding.detected is False
    assert report.reason_codes == (EvidenceSensitivityReasonCode.expected_response_missing,)
    assert SENSITIVITY_HARNESS_NOTICE in result.output
    markdown = (out / "evidence-sensitivity.md").read_text(encoding="utf-8")
    html = (out / "evidence-sensitivity.html").read_text(encoding="utf-8")
    for rendered in (markdown, html):
        assert "wrong_direction_flip" in rendered
        assert "Expected decisions (baseline -&gt; counterfactual)" in rendered or (
            "Expected decisions (baseline -> counterfactual)" in rendered
        )
        assert "observed decisions: deny -&gt; approve" in rendered or (
            "observed decisions: deny -> approve" in rendered
        )
        assert "wrong direction relative to the authority contract" in rendered
    assert "Expected decision_flip; observed decision_flip." not in html
    _assert_renderings(
        out,
        report.model_dump(mode="json"),
        golden_stem="evidence-sensitivity-reversed",
    )


def test_digest_mismatch_is_rejected_before_artifact_publication(tmp_path: Path) -> None:
    example = _copy_example(tmp_path)
    document = example / "corpora" / "policy_b" / "governing-policy.json"
    document.write_text(document.read_text(encoding="utf-8") + " ", encoding="utf-8")
    out = tmp_path / "digest-mismatch-output"

    result = _invoke_sensitivity(
        example=example,
        suite_name="responsive_suite.yaml",
        out=out,
    )

    assert result.exit_code == 2
    assert "sensitivity corpus is invalid or its digest does not match" in result.output
    assert not out.exists()


@pytest.mark.parametrize("error_type", (RuntimeError, TypeError, ValueError))
def test_accepted_input_internal_construction_fault_exits_four(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    error_type: type[Exception],
) -> None:
    out = tmp_path / "internal-construction-fault"

    def fail_after_input_acceptance(**_kwargs: object) -> None:
        raise error_type("fault injected after input acceptance")

    monkeypatch.setattr(
        rag_cmd_module,
        "execute_sensitivity_experiment",
        fail_after_input_acceptance,
    )

    result = _invoke_sensitivity(
        example=EXAMPLE,
        suite_name="responsive_suite.yaml",
        out=out,
    )

    assert result.exit_code == 4
    assert "evidence-sensitivity execution error" in result.output
    assert "invalid evidence-sensitivity input" not in result.output
    assert not out.exists()


def test_declared_experiment_input_fault_remains_exit_two(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    out = tmp_path / "declared-input-fault"

    def reject_input(**_kwargs: object) -> None:
        raise SensitivityInputError("declared sensitivity input fault")

    monkeypatch.setattr(rag_cmd_module, "execute_sensitivity_experiment", reject_input)

    result = _invoke_sensitivity(
        example=EXAMPLE,
        suite_name="responsive_suite.yaml",
        out=out,
    )

    assert result.exit_code == 2
    assert "invalid evidence-sensitivity input" in result.output
    assert "evidence-sensitivity execution error" not in result.output
    assert not out.exists()


def test_cli_path_validation_fault_remains_exit_two(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    out = tmp_path / "path-validation-fault"

    def reject_path(**_kwargs: object) -> None:
        raise ValueError("unsafe sensitivity path")

    def must_not_execute(**_kwargs: object) -> None:
        pytest.fail("experiment construction ran after path validation failed")

    monkeypatch.setattr(rag_cmd_module, "_ensure_output_does_not_alias_inputs", reject_path)
    monkeypatch.setattr(rag_cmd_module, "execute_sensitivity_experiment", must_not_execute)

    result = _invoke_sensitivity(
        example=EXAMPLE,
        suite_name="responsive_suite.yaml",
        out=out,
    )

    assert result.exit_code == 2
    assert "invalid evidence-sensitivity input" in result.output
    assert "evidence-sensitivity execution error" not in result.output
    assert not out.exists()


def test_unexpected_cli_path_validation_fault_exits_four(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    out = tmp_path / "unexpected-path-validation-fault"

    def fail_internally(**_kwargs: object) -> None:
        raise TypeError("unexpected path validator fault")

    def must_not_execute(**_kwargs: object) -> None:
        pytest.fail("experiment construction ran after path validation faulted")

    monkeypatch.setattr(
        rag_cmd_module,
        "_ensure_output_does_not_alias_inputs",
        fail_internally,
    )
    monkeypatch.setattr(rag_cmd_module, "execute_sensitivity_experiment", must_not_execute)

    result = _invoke_sensitivity(
        example=EXAMPLE,
        suite_name="responsive_suite.yaml",
        out=out,
    )

    assert result.exit_code == 4
    assert "evidence-sensitivity execution error: bounded internal error" in result.output
    assert "invalid evidence-sensitivity input" not in result.output
    assert not out.exists()


@pytest.mark.parametrize(
    ("limit_name", "limit"),
    (
        ("MAX_SENSITIVITY_CORPUS_INVENTORY_ENTRIES", 1),
        ("MAX_SENSITIVITY_CORPUS_DIRECTORIES", 0),
        ("MAX_SENSITIVITY_CORPUS_BYTES", 1),
    ),
)
def test_corpus_resource_limits_fail_before_artifact_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    limit_name: str,
    limit: int,
) -> None:
    monkeypatch.setattr(sensitivity_module, limit_name, limit)
    out = tmp_path / f"resource-limit-{limit_name}"

    result = _invoke_sensitivity(
        example=EXAMPLE,
        suite_name="responsive_suite.yaml",
        out=out,
    )

    assert result.exit_code == 2
    assert "sensitivity corpus is invalid" in result.output
    assert not out.exists()


def test_declared_256_document_corpora_publish_and_packet_embed(
    tmp_path: Path,
) -> None:
    example = _copy_example(tmp_path)
    _add_shared_non_governing_documents(example, count=255)
    for corpus_slug in ("policy_a", "policy_b"):
        manifest_text = (example / "corpora" / corpus_slug / "corpus-manifest.json").read_text(
            encoding="utf-8"
        )
        assert len(manifest_text) > MAX_PRIVACY_SCAN_CHARS
    out = tmp_path / "large-corpus-output"

    result = _invoke_sensitivity(
        example=example,
        suite_name="responsive_suite.yaml",
        out=out,
    )

    assert result.exit_code == 0, result.output
    report = load_sensitivity_report(out / "evidence-sensitivity.json")
    assert len(report.baseline_corpus_snapshot.documents) == 256
    assert len(report.counterfactual_corpus_snapshot.documents) == 256
    assert report.synthetic_data_provenance is SyntheticDataProvenance.operator_attested
    assert report.synthetic_data_attestation_digest is not None
    assert report.protocol.synthetic_data_attestation is not None
    assert report.population_claim == "none_operator_attested_synthetic_fixture_only"
    packet_dir = tmp_path / "large-corpus-packet"
    packet_dir.mkdir()
    packet_path = packet_dir / "evidence-packet.json"
    packet_result = RUNNER.invoke(
        app,
        [
            "packet",
            "build",
            str(out / "counterfactual-evaluation-summary.json"),
            "--evidence-sensitivity",
            str(out / "evidence-sensitivity.json"),
            "--out",
            str(packet_path),
        ],
    )
    assert packet_result.exit_code == 0, packet_result.output
    embedded = _json(packet_path)["evidence_sensitivity"]
    assert isinstance(embedded, dict)
    assert embedded["report_digest"] == report.report_digest
    baseline_snapshot = embedded["baseline_corpus_snapshot"]
    assert isinstance(baseline_snapshot, dict)
    assert baseline_snapshot["snapshot_digest"] == report.baseline_corpus_snapshot.snapshot_digest


def test_custom_sensitivity_inputs_require_an_exact_input_attestation(
    tmp_path: Path,
) -> None:
    example = _copy_example(tmp_path)
    _change_counterfactual_top_k(example, top_k=2)
    out = tmp_path / "missing-attestation-output"

    result = RUNNER.invoke(
        app,
        _sensitivity_cli_args(
            example=example,
            suite_name="responsive_suite.yaml",
            out=out,
        ),
    )

    assert result.exit_code == 2, result.output
    assert "custom sensitivity inputs require --synthetic-data-attestation" in result.output
    assert not out.exists()


def test_tampered_synthetic_data_attestation_is_rejected(
    tmp_path: Path,
) -> None:
    example = _copy_example(tmp_path)
    _change_counterfactual_top_k(example, top_k=2)
    attestation_args = _synthetic_data_attestation_args(
        example=example,
        suite_name="responsive_suite.yaml",
    )
    attestation_path = Path(attestation_args[-1])
    payload = _json(attestation_path)
    payload["attestation_id"] = "tampered-synthetic-data-attestation"
    _write_json(attestation_path, payload)
    out = tmp_path / "tampered-attestation-output"

    result = RUNNER.invoke(
        app,
        [
            *_sensitivity_cli_args(
                example=example,
                suite_name="responsive_suite.yaml",
                out=out,
            ),
            *attestation_args,
        ],
    )

    assert result.exit_code == 2, result.output
    assert "synthetic-data attestation is invalid" in result.output
    assert not out.exists()


def test_synthetic_data_attestation_must_bind_current_inputs(
    tmp_path: Path,
) -> None:
    example = _copy_example(tmp_path)
    _change_counterfactual_top_k(example, top_k=2)
    attestation_args = _synthetic_data_attestation_args(
        example=example,
        suite_name="responsive_suite.yaml",
    )
    _change_counterfactual_top_k(example, top_k=3)
    out = tmp_path / "stale-attestation-output"

    result = RUNNER.invoke(
        app,
        [
            *_sensitivity_cli_args(
                example=example,
                suite_name="responsive_suite.yaml",
                out=out,
            ),
            *attestation_args,
        ],
    )

    assert result.exit_code == 2, result.output
    assert "does not bind the exact sensitivity inputs" in result.output
    assert not out.exists()


def test_undeclared_retrieval_difference_is_confounded_and_non_verdict_bearing(
    tmp_path: Path,
) -> None:
    example = _copy_example(tmp_path)
    _change_counterfactual_top_k(example, top_k=2)
    out = tmp_path / "confounded-output"

    result = _invoke_sensitivity(
        example=example,
        suite_name="responsive_suite.yaml",
        out=out,
    )

    assert result.exit_code == 2, result.output
    report = load_sensitivity_report(out / "evidence-sensitivity.json")
    packet_decision = gate_evidence_packet(
        load_evidence_packet(out / "evidence-packet.json"),
        artifact_root=out,
        require_evidence_sensitivity=True,
        allow_missing_efficacy_for_migration=True,
    )
    assert packet_decision.outcome is GateOutcome.invalid
    assert packet_decision.exit_code == 2
    assert report.state is EvidenceSensitivityState.confounded
    assert report.gate_effect is EvidenceSensitivityGateEffect.non_verdict
    assert report.verdict_bearing is False
    assert report.endpoint_value is None
    assert report.protocol.controlled_difference_manifest.confounding_dimensions == (
        "retrieval_top_k",
    )
    assert EvidenceSensitivityReasonCode.confounded in report.reason_codes
    assert EvidenceSensitivityReasonCode.prerequisites_unmet in report.reason_codes
    assert report.synthetic_data_provenance is SyntheticDataProvenance.operator_attested
    assert report.synthetic_data_attestation_digest is not None


def test_non_governing_corpus_drift_is_confounded_and_non_verdict_bearing(
    tmp_path: Path,
) -> None:
    example = _copy_example(tmp_path)
    _add_non_governing_document(example, corpus_slug="policy_a")
    out = tmp_path / "distractor-confounded-output"

    result = _invoke_sensitivity(
        example=example,
        suite_name="responsive_suite.yaml",
        out=out,
    )

    assert result.exit_code == 2, result.output
    report = load_sensitivity_report(out / "evidence-sensitivity.json")
    assert report.state is EvidenceSensitivityState.confounded
    assert report.gate_effect is EvidenceSensitivityGateEffect.non_verdict
    assert report.verdict_bearing is False
    assert report.protocol.controlled_difference_manifest.confounding_dimensions == (
        "corpus_document_catalog_digest",
        "non_governing_evidence_digest",
    )


@pytest.mark.parametrize(
    ("scenario", "expected_reason"),
    (
        ("missing-link", EvidenceSensitivityReasonCode.evidence_link_not_present),
        ("missing-retrieval", EvidenceSensitivityReasonCode.evidence_not_retrieved),
    ),
)
def test_missing_evidence_prerequisites_are_non_verdict_bearing(
    tmp_path: Path,
    scenario: str,
    expected_reason: EvidenceSensitivityReasonCode,
) -> None:
    example = _copy_example(tmp_path)
    if scenario == "missing-link":
        subject_path = (
            example
            / "fixtures"
            / "responsive"
            / "model_outputs"
            / "synthetic-benefit-eligibility.json"
        )
        subject = _json(subject_path)
        subject["emit_evidence_links"] = False
        _write_json(subject_path, subject)
    else:
        request_path = (
            example / "fixtures" / "responsive" / "requests" / "synthetic-benefit-eligibility.json"
        )
        request = _json(request_path)
        request["query"] = "zebra quartz"
        _write_json(request_path, request)
    out = tmp_path / f"{scenario}-output"

    result = _invoke_sensitivity(
        example=example,
        suite_name="responsive_suite.yaml",
        out=out,
    )

    assert result.exit_code == 2, result.output
    report = load_sensitivity_report(out / "evidence-sensitivity.json")
    assert report.state is EvidenceSensitivityState.prerequisites_unmet
    assert report.gate_effect is EvidenceSensitivityGateEffect.non_verdict
    assert report.verdict_bearing is False
    assert report.endpoint_value is None
    assert expected_reason in report.reason_codes
    assert EvidenceSensitivityReasonCode.prerequisites_unmet in report.reason_codes


def test_invalid_authority_contract_is_rejected_before_publication(tmp_path: Path) -> None:
    example = _copy_example(tmp_path)
    contract_path = example / "knowledge-contract.yaml"
    contract_path.write_text(
        contract_path.read_text(encoding="utf-8").replace(
            "authority_level: authoritative",
            "authority_level: advisory",
        ),
        encoding="utf-8",
    )
    out = tmp_path / "invalid-authority-output"

    result = _invoke_sensitivity(
        example=example,
        suite_name="responsive_suite.yaml",
        out=out,
    )

    assert result.exit_code == 2
    assert "knowledge-authority contract is invalid" in result.output
    assert not out.exists()


def test_expected_relation_uses_a_closed_cli_vocabulary(tmp_path: Path) -> None:
    out = tmp_path / "invalid-relation-output"
    result = RUNNER.invoke(
        app,
        [
            "rag",
            "sensitivity",
            *_common_args(EXAMPLE),
            "--suite",
            str(EXAMPLE / "responsive_suite.yaml"),
            "--expected-relation",
            "decision_same",
            "--out",
            str(out),
        ],
    )

    assert result.exit_code == 2
    assert "decision_flip" in result.output
    assert not out.exists()


def test_snapshot_sidecar_destination_cannot_alias_a_suite_input(tmp_path: Path) -> None:
    out = tmp_path / "alias-output"
    out.mkdir()
    suite_alias = out / "baseline-corpus-snapshot.json"
    suite_alias.write_bytes((EXAMPLE / "responsive_suite.yaml").read_bytes())
    original = suite_alias.read_bytes()

    result = RUNNER.invoke(
        app,
        [
            "rag",
            "sensitivity",
            "--suite",
            str(suite_alias),
            *_common_args(EXAMPLE),
            "--expected-relation",
            "decision_flip",
            "--out",
            str(out),
        ],
    )

    assert result.exit_code == 2
    assert "input aliases an owned output artifact" in result.output
    assert suite_alias.read_bytes() == original
    assert tuple(out.iterdir()) == (suite_alias,)


def test_output_cannot_be_nested_in_an_authenticated_fixture_root(tmp_path: Path) -> None:
    example = _copy_example(tmp_path)
    out = example / "fixtures" / "responsive" / "generated-report"

    result = _invoke_sensitivity(
        example=example,
        suite_name="responsive_suite.yaml",
        out=out,
    )

    assert result.exit_code == 2, result.output
    assert "must not overlap a fixture root" in result.output
    assert not out.exists()


def test_output_refuses_a_packet_adjacent_artifact_namespace(tmp_path: Path) -> None:
    out = tmp_path / "mixed-output"
    out.mkdir()
    packet = out / "evidence-packet.json"
    packet.write_text("packet sentinel\n", encoding="utf-8")

    result = _invoke_sensitivity(
        example=EXAMPLE,
        suite_name="responsive_suite.yaml",
        out=out,
    )

    assert result.exit_code == 2, result.output
    assert "partial artifact generation" in result.output
    assert packet.read_text(encoding="utf-8") == "packet sentinel\n"
    assert tuple(out.iterdir()) == (packet,)


def test_exact_sensitivity_generation_can_be_republished_idempotently(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    out = tmp_path / "idempotent-output"

    first = _invoke_sensitivity(
        example=EXAMPLE,
        suite_name="responsive_suite.yaml",
        out=out,
    )
    assert first.exit_code == 0, first.output
    first_bytes = {path.name: path.read_bytes() for path in out.iterdir()}
    first_metadata = {
        path.name: (path.stat().st_ino, path.stat().st_mtime_ns) for path in out.iterdir()
    }

    def reject_rewrite(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("an exact existing generation must not be rewritten")

    monkeypatch.setattr(
        sensitivity_reporting_module,
        "_write_sensitivity_output_exclusive",
        reject_rewrite,
    )

    second = _invoke_sensitivity(
        example=EXAMPLE,
        suite_name="responsive_suite.yaml",
        out=out,
    )

    assert second.exit_code == 0, second.output
    assert {path.name: path.read_bytes() for path in out.iterdir()} == first_bytes
    assert {
        path.name: (path.stat().st_ino, path.stat().st_mtime_ns) for path in out.iterdir()
    } == first_metadata


def test_cli_and_html_strip_bidi_format_controls_from_display_text(tmp_path: Path) -> None:
    out = tmp_path / "bidi-\u202ereport"
    result = _invoke_sensitivity(
        example=EXAMPLE,
        suite_name="responsive_suite.yaml",
        out=out,
    )

    assert result.exit_code == 0, result.output
    assert "\u202e" not in result.output
    report = load_sensitivity_report(out / "evidence-sensitivity.json")
    unsafe_display = report.model_copy(
        update={"limitations": ("Synthetic \u202etxt.exe limitation",)}
    )
    rendered = render_sensitivity_html(unsafe_display)
    assert "\u202e" not in rendered
    assert "Synthetic txt.exe limitation" in rendered


def test_each_arm_recompiles_suite_and_reloads_bound_fixtures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = {"suite": 0, "manifest": 0, "fixture": 0, "authority": 0}
    original_suite = sensitivity_module._load_sensitivity_suite
    original_manifest = sensitivity_module.build_fixture_manifest
    original_fixture = sensitivity_module._load_bound_subject_fixture
    original_authority = sensitivity_module.load_knowledge_contract

    def load_suite(*args: Any, **kwargs: Any) -> Any:
        calls["suite"] += 1
        return original_suite(*args, **kwargs)

    def load_manifest(*args: Any, **kwargs: Any) -> Any:
        calls["manifest"] += 1
        return original_manifest(*args, **kwargs)

    def load_fixture(*args: Any, **kwargs: Any) -> Any:
        calls["fixture"] += 1
        return original_fixture(*args, **kwargs)

    def load_authority(*args: Any, **kwargs: Any) -> Any:
        calls["authority"] += 1
        return original_authority(*args, **kwargs)

    monkeypatch.setattr(sensitivity_module, "_load_sensitivity_suite", load_suite)
    monkeypatch.setattr(sensitivity_module, "build_fixture_manifest", load_manifest)
    monkeypatch.setattr(sensitivity_module, "_load_bound_subject_fixture", load_fixture)
    monkeypatch.setattr(sensitivity_module, "load_knowledge_contract", load_authority)

    artifacts = execute_sensitivity_experiment(
        suite_path=EXAMPLE / "responsive_suite.yaml",
        baseline_corpus_dir=EXAMPLE / "corpora" / "policy_a",
        counterfactual_corpus_dir=EXAMPLE / "corpora" / "policy_b",
        knowledge_contract_path=EXAMPLE / "knowledge-contract.yaml",
        expected_relation=EvidenceSensitivityExpectedRelation.decision_flip,
    )

    assert artifacts.report.state is EvidenceSensitivityState.responsive
    assert calls == {"suite": 2, "manifest": 1, "fixture": 2, "authority": 2}


def test_bundle_publisher_rejects_swapped_sidecars_before_publication(
    tmp_path: Path,
) -> None:
    artifacts = execute_sensitivity_experiment(
        suite_path=EXAMPLE / "responsive_suite.yaml",
        baseline_corpus_dir=EXAMPLE / "corpora" / "policy_a",
        counterfactual_corpus_dir=EXAMPLE / "corpora" / "policy_b",
        knowledge_contract_path=EXAMPLE / "knowledge-contract.yaml",
        expected_relation=EvidenceSensitivityExpectedRelation.decision_flip,
    )
    swapped = replace(
        artifacts,
        baseline_runset=artifacts.counterfactual_runset,
    )
    out = tmp_path / "swapped-sidecar-output"

    with pytest.raises(ValueError, match="nested executions must match"):
        write_sensitivity_execution_artifacts(swapped, out)

    assert not out.exists()


def test_bundle_publisher_retains_failed_private_stage_and_recovers_without_deleting_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifacts = execute_sensitivity_experiment(
        suite_path=EXAMPLE / "responsive_suite.yaml",
        baseline_corpus_dir=EXAMPLE / "corpora" / "policy_a",
        counterfactual_corpus_dir=EXAMPLE / "corpora" / "policy_b",
        knowledge_contract_path=EXAMPLE / "knowledge-contract.yaml",
        expected_relation=EvidenceSensitivityExpectedRelation.decision_flip,
    )
    out = tmp_path / "retained-stage-output"
    original_write = sensitivity_reporting_module._write_sensitivity_output_exclusive

    def fail_on_manifest(
        claim: object,
        name: str,
        payload: bytes,
    ) -> object:
        if name == "release-artifact-manifest.json":
            raise OSError("injected publication failure")
        return original_write(claim, name, payload)  # type: ignore[arg-type]

    monkeypatch.setattr(
        sensitivity_reporting_module,
        "_write_sensitivity_output_exclusive",
        fail_on_manifest,
    )

    with pytest.raises(OSError, match="private staging retained at") as raised:
        write_sensitivity_execution_artifacts(artifacts, out)

    assert not out.exists()
    assert isinstance(raised.value.__cause__, OSError)
    assert "injected publication failure" in str(raised.value.__cause__)
    abandoned = tuple(tmp_path.glob(".agent-assure-sensitivity-*.tmp"))
    assert len(abandoned) == 1
    abandoned_identity = os.lstat(abandoned[0])
    abandoned_names = tuple(sorted(item.name for item in abandoned[0].iterdir()))
    assert abandoned_names
    if os.name != "nt":
        assert abandoned_identity.st_mode & 0o777 == 0o700

    monkeypatch.setattr(
        sensitivity_reporting_module,
        "_write_sensitivity_output_exclusive",
        original_write,
    )
    published = write_sensitivity_execution_artifacts(artifacts, out)

    assert tuple(published) == sensitivity_reporting_module.SENSITIVITY_OUTPUT_FILENAMES
    assert {item.name for item in out.iterdir()} == set(
        sensitivity_reporting_module.SENSITIVITY_OUTPUT_FILENAMES
    )
    assert (os.lstat(abandoned[0]).st_dev, os.lstat(abandoned[0]).st_ino) == (
        abandoned_identity.st_dev,
        abandoned_identity.st_ino,
    )
    assert tuple(sorted(item.name for item in abandoned[0].iterdir())) == abandoned_names


def test_bundle_publisher_interrupt_leaves_only_a_nonadoptable_private_stage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifacts = execute_sensitivity_experiment(
        suite_path=EXAMPLE / "responsive_suite.yaml",
        baseline_corpus_dir=EXAMPLE / "corpora" / "policy_a",
        counterfactual_corpus_dir=EXAMPLE / "corpora" / "policy_b",
        knowledge_contract_path=EXAMPLE / "knowledge-contract.yaml",
        expected_relation=EvidenceSensitivityExpectedRelation.decision_flip,
    )
    out = tmp_path / "interrupt-output"
    original_write = sensitivity_reporting_module._write_sensitivity_output_exclusive
    calls = 0

    def interrupt_during_second_write(
        claim: object,
        name: str,
        payload: bytes,
    ) -> object:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise KeyboardInterrupt
        return original_write(claim, name, payload)  # type: ignore[arg-type]

    monkeypatch.setattr(
        sensitivity_reporting_module,
        "_write_sensitivity_output_exclusive",
        interrupt_during_second_write,
    )

    with pytest.raises(KeyboardInterrupt):
        write_sensitivity_execution_artifacts(artifacts, out)

    assert not out.exists()
    abandoned = tuple(tmp_path.glob(".agent-assure-sensitivity-*.tmp"))
    assert len(abandoned) == 1
    assert {item.name for item in abandoned[0].iterdir()} == {
        sensitivity_reporting_module.SENSITIVITY_OUTPUT_FILENAMES[0]
    }


@pytest.mark.skipif(os.name == "nt", reason="POSIX file-entry swap regression")
def test_bundle_publisher_rejects_staged_symlink_swap_without_touching_foreign_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifacts = execute_sensitivity_experiment(
        suite_path=EXAMPLE / "responsive_suite.yaml",
        baseline_corpus_dir=EXAMPLE / "corpora" / "policy_a",
        counterfactual_corpus_dir=EXAMPLE / "corpora" / "policy_b",
        knowledge_contract_path=EXAMPLE / "knowledge-contract.yaml",
        expected_relation=EvidenceSensitivityExpectedRelation.decision_flip,
    )
    out = tmp_path / "symlink-swap-output"
    foreign = tmp_path / "foreign-target.txt"
    foreign_bytes = b"foreign bytes must survive rollback\n"
    foreign.write_bytes(foreign_bytes)
    probe = tmp_path / "symlink-probe"
    try:
        probe.symlink_to(foreign)
    except OSError as exc:
        pytest.skip(f"file symlinks are unavailable: {exc}")
    probe.unlink()

    original_write = sensitivity_reporting_module._write_sensitivity_output_exclusive
    first_created: Any | None = None
    captured_claim: Any | None = None

    def swap_first_output_before_second_write(
        claim: object,
        name: str,
        payload: bytes,
    ) -> object:
        nonlocal first_created, captured_claim
        if first_created is None:
            first_created = original_write(  # type: ignore[arg-type]
                claim,
                name,
                payload,
            )
            captured_claim = claim
            return first_created
        if name == "fixture-manifest.json":
            first_created.path.unlink()
            first_created.path.symlink_to(foreign)
        return original_write(claim, name, payload)  # type: ignore[arg-type]

    monkeypatch.setattr(
        sensitivity_reporting_module,
        "_write_sensitivity_output_exclusive",
        swap_first_output_before_second_write,
    )

    with pytest.raises(OSError, match="private staging retained at"):
        write_sensitivity_execution_artifacts(artifacts, out)

    assert first_created is not None
    assert captured_claim is not None
    assert first_created.pin_descriptor is None
    assert captured_claim.closed
    assert first_created.path.is_symlink()
    assert foreign.read_bytes() == foreign_bytes


@pytest.mark.skipif(os.name == "nt", reason="POSIX parent-swap regression")
def test_bundle_publisher_rejects_parent_swap_after_anchored_acquisition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifacts = execute_sensitivity_experiment(
        suite_path=EXAMPLE / "responsive_suite.yaml",
        baseline_corpus_dir=EXAMPLE / "corpora" / "policy_a",
        counterfactual_corpus_dir=EXAMPLE / "corpora" / "policy_b",
        knowledge_contract_path=EXAMPLE / "knowledge-contract.yaml",
        expected_relation=EvidenceSensitivityExpectedRelation.decision_flip,
    )
    requested_parent = tmp_path / "requested-parent"
    moved_parent = tmp_path / "moved-parent"
    outside_parent = tmp_path / "outside-parent"
    requested_parent.mkdir()
    outside_parent.mkdir()
    out = requested_parent / "evidence"
    original_open = (
        sensitivity_reporting_module.open_or_create_rooted_directory_from_filesystem_root
    )
    swapped = False

    def swap_after_acquisition(
        directory: Path,
        *,
        label: str,
        mode: int = 0o700,
    ) -> RootedDirectoryDescriptor:
        nonlocal swapped
        lease = original_open(directory, label=label, mode=mode)
        if directory == requested_parent and not swapped:
            requested_parent.rename(moved_parent)
            requested_parent.symlink_to(outside_parent, target_is_directory=True)
            swapped = True
        return lease

    monkeypatch.setattr(
        sensitivity_reporting_module,
        "open_or_create_rooted_directory_from_filesystem_root",
        swap_after_acquisition,
    )

    with pytest.raises((OSError, ValueError), match="sensitivity output parent"):
        write_sensitivity_execution_artifacts(artifacts, out)

    assert swapped
    assert not (outside_parent / out.name).exists()
    assert not (moved_parent / out.name).exists()


def test_bundle_publisher_ignores_planted_stage_and_lock_entries_without_parent_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifacts = execute_sensitivity_experiment(
        suite_path=EXAMPLE / "responsive_suite.yaml",
        baseline_corpus_dir=EXAMPLE / "corpora" / "policy_a",
        counterfactual_corpus_dir=EXAMPLE / "corpora" / "policy_b",
        knowledge_contract_path=EXAMPLE / "knowledge-contract.yaml",
        expected_relation=EvidenceSensitivityExpectedRelation.decision_flip,
    )
    out = tmp_path / "retained-stage-cap-output"
    target_digest = hashlib.sha256(os.path.normcase(out.name).encode("utf-8")).hexdigest()[:16]
    retained_paths = tuple(
        tmp_path / f".agent-assure-sensitivity-{target_digest}-{index:032x}.tmp"
        for index in range(8)
    )
    for path in retained_paths:
        path.mkdir()
    planted_identities = tuple(
        (os.lstat(path).st_dev, os.lstat(path).st_ino) for path in retained_paths
    )
    lock_digest = hashlib.sha256(os.path.normcase(out.name).encode("utf-8")).hexdigest()[:32]
    planted_lock = tmp_path / f".agent-assure-sensitivity-lock-{lock_digest}.lock"
    planted_lock.mkdir()

    real_entry_names = sensitivity_reporting_module.RootedDirectoryDescriptor.entry_names

    def reject_parent_inventory_scan(
        lease: object,
        *,
        max_entries: int,
        label: str,
    ) -> tuple[str, ...]:
        if getattr(lease, "path", None) == tmp_path:
            pytest.fail("publication must not enumerate the shared output parent")
        return real_entry_names(lease, max_entries=max_entries, label=label)  # type: ignore[arg-type]

    monkeypatch.setattr(
        sensitivity_reporting_module.RootedDirectoryDescriptor,
        "entry_names",
        reject_parent_inventory_scan,
    )

    write_sensitivity_execution_artifacts(artifacts, out)
    adopted = write_sensitivity_execution_artifacts(artifacts, out)

    assert tuple(adopted) == sensitivity_reporting_module.SENSITIVITY_OUTPUT_FILENAMES
    assert len(tuple(tmp_path.glob(".agent-assure-sensitivity-*.tmp"))) == 8
    assert (
        tuple((os.lstat(path).st_dev, os.lstat(path).st_ino) for path in retained_paths)
        == planted_identities
    )
    assert planted_lock.is_dir()


def test_bundle_publisher_reopens_every_child_after_fsync_before_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifacts = execute_sensitivity_experiment(
        suite_path=EXAMPLE / "responsive_suite.yaml",
        baseline_corpus_dir=EXAMPLE / "corpora" / "policy_a",
        counterfactual_corpus_dir=EXAMPLE / "corpora" / "policy_b",
        knowledge_contract_path=EXAMPLE / "knowledge-contract.yaml",
        expected_relation=EvidenceSensitivityExpectedRelation.decision_flip,
    )
    out = tmp_path / "final-child-pin-output"
    foreign = tmp_path / "foreign.json"
    foreign_bytes = b'{"foreign":"must-not-commit"}\n'
    foreign.write_bytes(foreign_bytes)
    real_fsync = sensitivity_reporting_module._fsync_staged_sensitivity_generation
    planted: list[Path] = []

    def plant_hardlink_after_original_pins_close(
        claim: sensitivity_reporting_module.RootedDirectoryClaim,
    ) -> None:
        real_fsync(claim)
        victim = claim.path / "protocol.json"
        victim.unlink()
        os.link(foreign, victim)
        planted.append(victim)

    monkeypatch.setattr(
        sensitivity_reporting_module,
        "_fsync_staged_sensitivity_generation",
        plant_hardlink_after_original_pins_close,
    )

    with pytest.raises(OSError, match="private staging retained at"):
        write_sensitivity_execution_artifacts(artifacts, out)

    assert not out.exists()
    assert len(planted) == 1
    assert planted[0].samefile(foreign)
    assert foreign.read_bytes() == foreign_bytes


def test_bundle_publisher_detects_child_swap_after_final_validation_before_install(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifacts = execute_sensitivity_experiment(
        suite_path=EXAMPLE / "responsive_suite.yaml",
        baseline_corpus_dir=EXAMPLE / "corpora" / "policy_a",
        counterfactual_corpus_dir=EXAMPLE / "corpora" / "policy_b",
        knowledge_contract_path=EXAMPLE / "knowledge-contract.yaml",
        expected_relation=EvidenceSensitivityExpectedRelation.decision_flip,
    )
    out = tmp_path / "post-validation-child-swap-output"
    foreign_bytes = b'{"foreign":"swapped-after-final-validation"}\n'
    original_install = sensitivity_reporting_module.RootedDirectoryClaim.install_no_replace
    attempted: list[Path] = []

    def swap_child_then_install(
        claim: sensitivity_reporting_module.RootedDirectoryClaim,
        name: str | Path,
    ) -> None:
        victim = claim.path / "protocol.json"
        victim.unlink()
        victim.write_bytes(foreign_bytes)
        attempted.append(victim)
        original_install(claim, name)

    monkeypatch.setattr(
        sensitivity_reporting_module.RootedDirectoryClaim,
        "install_no_replace",
        swap_child_then_install,
    )

    with pytest.raises(
        OSError,
        match="generation committed; target retained despite post-commit validation failure",
    ):
        write_sensitivity_execution_artifacts(artifacts, out)

    assert len(attempted) == 1
    assert out.is_dir()
    assert (out / "protocol.json").read_bytes() == foreign_bytes


@pytest.mark.skipif(os.name == "nt", reason="POSIX permits renaming an installed open target")
def test_bundle_publisher_rejects_postcommit_target_name_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifacts = execute_sensitivity_experiment(
        suite_path=EXAMPLE / "responsive_suite.yaml",
        baseline_corpus_dir=EXAMPLE / "corpora" / "policy_a",
        counterfactual_corpus_dir=EXAMPLE / "corpora" / "policy_b",
        knowledge_contract_path=EXAMPLE / "knowledge-contract.yaml",
        expected_relation=EvidenceSensitivityExpectedRelation.decision_flip,
    )
    out = tmp_path / "postcommit-target-swap-output"
    committed_aside = tmp_path / "committed-generation-aside"
    original_after_commit = sensitivity_reporting_module._after_sensitivity_generation_commit
    committed_identity: tuple[int, int] | None = None
    decoy_snapshot: dict[str, bytes] = {}

    def swap_exact_decoy_after_durability(parent: object) -> None:
        nonlocal committed_identity
        original_after_commit(parent)  # type: ignore[arg-type]
        metadata = os.lstat(out)
        committed_identity = (metadata.st_dev, metadata.st_ino)
        out.rename(committed_aside)
        out.mkdir()
        for source in committed_aside.iterdir():
            data = source.read_bytes()
            (out / source.name).write_bytes(data)
            decoy_snapshot[source.name] = data

    monkeypatch.setattr(
        sensitivity_reporting_module,
        "_after_sensitivity_generation_commit",
        swap_exact_decoy_after_durability,
    )

    with pytest.raises(
        OSError,
        match="post-commit durability or exact-generation validation failure",
    ):
        write_sensitivity_execution_artifacts(artifacts, out)

    assert committed_identity is not None
    assert (os.lstat(committed_aside).st_dev, os.lstat(committed_aside).st_ino) == (
        committed_identity
    )
    assert (os.lstat(out).st_dev, os.lstat(out).st_ino) != committed_identity
    assert {path.name: path.read_bytes() for path in out.iterdir()} == decoy_snapshot
    assert set(decoy_snapshot) == set(sensitivity_reporting_module.SENSITIVITY_OUTPUT_FILENAMES)
    assert {path.name for path in committed_aside.iterdir()} == set(
        sensitivity_reporting_module.SENSITIVITY_OUTPUT_FILENAMES
    )


@pytest.mark.parametrize(
    "detail",
    ("must be a regular file", "opaque rooted reader failure"),
)
def test_existing_bundle_error_classification_does_not_parse_exception_text(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    detail: str,
) -> None:
    out = tmp_path / "existing-bundle"
    out.mkdir()
    for name in sensitivity_reporting_module.SENSITIVITY_OUTPUT_FILENAMES:
        (out / name).write_text("{}\n", encoding="utf-8")

    def fail_open(*_args: object, **_kwargs: object) -> object:
        raise ValueError(detail)

    monkeypatch.setattr(
        sensitivity_reporting_module.RootedDirectoryDescriptor,
        "open_file_bounded",
        fail_open,
    )
    with sensitivity_reporting_module.open_rooted_directory(
        tmp_path,
        ".",
        label="sensitivity output parent",
    ) as parent:
        with pytest.raises(
            sensitivity_reporting_module.SensitivityOutputConflictError,
            match="^existing sensitivity output cannot be safely verified$",
        ) as exc_info:
            sensitivity_reporting_module._open_existing_sensitivity_generation(parent, out)

    assert isinstance(exc_info.value.__cause__, ValueError)


def test_bundle_publisher_classifies_postrename_failure_as_committed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifacts = execute_sensitivity_experiment(
        suite_path=EXAMPLE / "responsive_suite.yaml",
        baseline_corpus_dir=EXAMPLE / "corpora" / "policy_a",
        counterfactual_corpus_dir=EXAMPLE / "corpora" / "policy_b",
        knowledge_contract_path=EXAMPLE / "knowledge-contract.yaml",
        expected_relation=EvidenceSensitivityExpectedRelation.decision_flip,
    )
    out = tmp_path / "postrename-failure-output"
    original_install = sensitivity_reporting_module.RootedDirectoryClaim.install_no_replace

    def fail_after_commit(
        claim: object,
        name: str | Path,
    ) -> None:
        original_install(claim, name)  # type: ignore[arg-type]
        raise OSError("injected post-commit identity failure")

    monkeypatch.setattr(
        sensitivity_reporting_module.RootedDirectoryClaim,
        "install_no_replace",
        fail_after_commit,
    )

    with pytest.raises(OSError, match="generation committed") as raised:
        write_sensitivity_execution_artifacts(artifacts, out)

    assert "private staging retained" not in str(raised.value)
    assert isinstance(raised.value.__cause__, OSError)
    assert "injected post-commit identity failure" in str(raised.value.__cause__)
    assert {item.name for item in out.iterdir()} == set(
        sensitivity_reporting_module.SENSITIVITY_OUTPUT_FILENAMES
    )
    assert not tuple(tmp_path.glob(".agent-assure-sensitivity-*.tmp"))

    monkeypatch.setattr(
        sensitivity_reporting_module.RootedDirectoryClaim,
        "install_no_replace",
        original_install,
    )
    adopted = write_sensitivity_execution_artifacts(artifacts, out)
    assert tuple(adopted) == sensitivity_reporting_module.SENSITIVITY_OUTPUT_FILENAMES


@pytest.mark.skipif(os.name != "nt", reason="Windows reparse swap regression")
def test_bundle_publisher_windows_staged_reparse_swap_is_blocked_or_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifacts = execute_sensitivity_experiment(
        suite_path=EXAMPLE / "responsive_suite.yaml",
        baseline_corpus_dir=EXAMPLE / "corpora" / "policy_a",
        counterfactual_corpus_dir=EXAMPLE / "corpora" / "policy_b",
        knowledge_contract_path=EXAMPLE / "knowledge-contract.yaml",
        expected_relation=EvidenceSensitivityExpectedRelation.decision_flip,
    )
    out = tmp_path / "windows-reparse-swap-output"
    foreign = tmp_path / "windows-foreign-target.txt"
    foreign_bytes = b"foreign bytes must survive staged validation\n"
    foreign.write_bytes(foreign_bytes)
    probe = tmp_path / "windows-symlink-probe"
    try:
        probe.symlink_to(foreign)
    except OSError as exc:
        pytest.skip(f"Windows file symlinks are unavailable: {exc}")
    probe.unlink()

    original_write = sensitivity_reporting_module._write_sensitivity_output_exclusive
    first_created: Any | None = None
    captured_claim: Any | None = None
    replacement_succeeded = False
    replacement_was_blocked = False

    def attempt_reparse_swap_before_second_write(
        claim: object,
        name: str,
        payload: bytes,
    ) -> object:
        nonlocal first_created, captured_claim
        nonlocal replacement_succeeded, replacement_was_blocked
        if first_created is None:
            first_created = original_write(  # type: ignore[arg-type]
                claim,
                name,
                payload,
            )
            captured_claim = claim
            return first_created
        if name == "fixture-manifest.json":
            try:
                first_created.path.unlink()
            except OSError:
                replacement_was_blocked = True
            else:
                first_created.path.symlink_to(foreign)
                replacement_succeeded = True
            if replacement_was_blocked:
                raise OSError("injected failure after Windows replacement attempt")
        return original_write(claim, name, payload)  # type: ignore[arg-type]

    monkeypatch.setattr(
        sensitivity_reporting_module,
        "_write_sensitivity_output_exclusive",
        attempt_reparse_swap_before_second_write,
    )

    with pytest.raises(OSError, match="private staging retained at") as raised:
        write_sensitivity_execution_artifacts(artifacts, out)

    assert first_created is not None
    assert captured_claim is not None
    assert first_created.pin_descriptor is None
    assert captured_claim.closed
    assert foreign.read_bytes() == foreign_bytes
    assert not out.exists()
    if replacement_was_blocked:
        assert isinstance(raised.value.__cause__, OSError)
        assert "injected failure after Windows replacement attempt" in str(raised.value.__cause__)
    else:
        assert replacement_succeeded
        assert first_created.path.is_symlink()


def test_bundle_publisher_never_clobbers_a_concurrently_created_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifacts = execute_sensitivity_experiment(
        suite_path=EXAMPLE / "responsive_suite.yaml",
        baseline_corpus_dir=EXAMPLE / "corpora" / "policy_a",
        counterfactual_corpus_dir=EXAMPLE / "corpora" / "policy_b",
        knowledge_contract_path=EXAMPLE / "knowledge-contract.yaml",
        expected_relation=EvidenceSensitivityExpectedRelation.decision_flip,
    )
    out = tmp_path / "race-output"
    original_install = sensitivity_reporting_module.RootedDirectoryClaim.install_no_replace
    foreign = b"concurrent writer owns these bytes\n"

    def race_at_commit(claim: object, name: str | Path) -> None:
        out.mkdir()
        (out / "protocol.json").write_bytes(foreign)
        original_install(claim, name)  # type: ignore[arg-type]

    monkeypatch.setattr(
        sensitivity_reporting_module.RootedDirectoryClaim,
        "install_no_replace",
        race_at_commit,
    )

    with pytest.raises(OSError, match="private staging retained at"):
        write_sensitivity_execution_artifacts(artifacts, out)

    assert (out / "protocol.json").read_bytes() == foreign
    assert {path.name for path in out.iterdir()} == {"protocol.json"}
    assert len(tuple(tmp_path.glob(".agent-assure-sensitivity-*.tmp"))) == 1


def test_bundle_publisher_adopts_exact_generation_that_wins_commit_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifacts = execute_sensitivity_experiment(
        suite_path=EXAMPLE / "responsive_suite.yaml",
        baseline_corpus_dir=EXAMPLE / "corpora" / "policy_a",
        counterfactual_corpus_dir=EXAMPLE / "corpora" / "policy_b",
        knowledge_contract_path=EXAMPLE / "knowledge-contract.yaml",
        expected_relation=EvidenceSensitivityExpectedRelation.decision_flip,
    )
    out = tmp_path / "exact-race-output"
    original_install = sensitivity_reporting_module.RootedDirectoryClaim.install_no_replace

    def commit_exact_generation_first(
        claim: sensitivity_reporting_module.RootedDirectoryClaim,
        name: str | Path,
    ) -> None:
        out.mkdir()
        for source in claim.path.iterdir():
            (out / source.name).write_bytes(source.read_bytes())
        original_install(claim, name)

    monkeypatch.setattr(
        sensitivity_reporting_module.RootedDirectoryClaim,
        "install_no_replace",
        commit_exact_generation_first,
    )

    adopted = write_sensitivity_execution_artifacts(artifacts, out)

    assert tuple(adopted) == sensitivity_reporting_module.SENSITIVITY_OUTPUT_FILENAMES
    assert {path.name for path in out.iterdir()} == set(
        sensitivity_reporting_module.SENSITIVITY_OUTPUT_FILENAMES
    )
    assert len(tuple(tmp_path.glob(".agent-assure-sensitivity-*.tmp"))) == 1


def test_bundle_publisher_late_failure_does_not_block_exact_generation_adoption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifacts = execute_sensitivity_experiment(
        suite_path=EXAMPLE / "responsive_suite.yaml",
        baseline_corpus_dir=EXAMPLE / "corpora" / "policy_a",
        counterfactual_corpus_dir=EXAMPLE / "corpora" / "policy_b",
        knowledge_contract_path=EXAMPLE / "knowledge-contract.yaml",
        expected_relation=EvidenceSensitivityExpectedRelation.decision_flip,
    )
    out = tmp_path / "late-failure-output"
    committed = threading.Event()
    release_late_failure = threading.Event()
    second_started = threading.Event()
    second_finished = threading.Event()
    first_errors: list[BaseException] = []
    second_errors: list[BaseException] = []
    second_result: list[dict[str, Path]] = []
    original_after_commit = sensitivity_reporting_module._after_sensitivity_generation_commit

    def fail_first_after_commit(parent: object) -> None:
        if not committed.is_set():
            committed.set()
            if not release_late_failure.wait(timeout=10):
                raise TimeoutError("test did not release injected late failure")
            raise OSError("injected post-commit failure")
        original_after_commit(parent)  # type: ignore[arg-type]

    monkeypatch.setattr(
        sensitivity_reporting_module,
        "_after_sensitivity_generation_commit",
        fail_first_after_commit,
    )

    def publish_first() -> None:
        try:
            write_sensitivity_execution_artifacts(artifacts, out)
        except BaseException as exc:
            first_errors.append(exc)

    def publish_second() -> None:
        second_started.set()
        try:
            second_result.append(write_sensitivity_execution_artifacts(artifacts, out))
        except BaseException as exc:
            second_errors.append(exc)
        finally:
            second_finished.set()

    first_thread = threading.Thread(target=publish_first)
    first_thread.start()
    assert committed.wait(timeout=10)
    assert out.is_dir()

    second_thread = threading.Thread(target=publish_second)
    second_thread.start()
    assert second_started.wait(timeout=10)
    assert second_finished.wait(timeout=10)

    release_late_failure.set()
    first_thread.join(timeout=10)
    second_thread.join(timeout=10)

    assert not first_thread.is_alive()
    assert not second_thread.is_alive()
    assert len(first_errors) == 1
    assert isinstance(first_errors[0], OSError)
    assert "post-commit" in str(first_errors[0])
    assert not second_errors
    assert len(second_result) == 1
    assert tuple(second_result[0]) == sensitivity_reporting_module.SENSITIVITY_OUTPUT_FILENAMES
    assert {path.name for path in out.iterdir()} == set(
        sensitivity_reporting_module.SENSITIVITY_OUTPUT_FILENAMES
    )


def test_packet_gate_rejects_corruption_of_any_manifest_bound_sidecar(
    tmp_path: Path,
) -> None:
    out = tmp_path / "bound-sidecar-output"
    result = _invoke_sensitivity(
        example=EXAMPLE,
        suite_name="responsive_suite.yaml",
        out=out,
    )
    assert result.exit_code == 0, result.output
    packet = load_evidence_packet(out / "evidence-packet.json")
    (out / "baseline.runset.json").write_text("{}\n", encoding="utf-8")

    binding_error = packet_summary_files_binding_error(packet, artifact_root=out)
    decision = gate_evidence_packet(
        packet,
        artifact_root=out,
        allow_missing_efficacy_for_migration=True,
    )

    assert binding_error is not None
    assert "baseline-runset source file digest does not match" in binding_error
    assert decision.outcome is GateOutcome.invalid
    assert decision.exit_code == 2


def test_bundle_publisher_refuses_pii_in_any_sidecar_before_publication(
    tmp_path: Path,
) -> None:
    artifacts = execute_sensitivity_experiment(
        suite_path=EXAMPLE / "responsive_suite.yaml",
        baseline_corpus_dir=EXAMPLE / "corpora" / "policy_a",
        counterfactual_corpus_dir=EXAMPLE / "corpora" / "policy_b",
        knowledge_contract_path=EXAMPLE / "knowledge-contract.yaml",
        expected_relation=EvidenceSensitivityExpectedRelation.decision_flip,
    )
    baseline_run = artifacts.baseline_runset.runs[0].model_copy(
        update={"input_summary": "request=123-45-6789"}
    )
    pii_runset = artifacts.baseline_runset.model_copy(update={"runs": (baseline_run,)})
    unsafe = replace(artifacts, baseline_runset=pii_runset)
    out = tmp_path / "pii-sidecar-output"

    with pytest.raises(
        SensitivityPrivacyError,
        match="baseline RunSet contains sensitive-looking content",
    ):
        write_sensitivity_execution_artifacts(unsafe, out)

    assert not out.exists()


def test_bundle_publisher_refuses_unicode_escaped_pii_in_corpus_content(
    tmp_path: Path,
) -> None:
    example = _copy_example(tmp_path)
    _replace_governing_summary(
        example,
        corpus_slug="policy_a",
        summary="Synthetic identifier 123-45-6789 must never be published.",
        unicode_escape_digits=True,
    )
    out = tmp_path / "escaped-pii-output"

    result = _invoke_sensitivity(
        example=example,
        suite_name="responsive_suite.yaml",
        out=out,
    )

    assert result.exit_code == 2, result.output
    assert "baseline corpus snapshot contains sensitive-looking content" in result.output
    assert "123-45-6789" not in result.output
    assert not out.exists()


def test_bundle_publisher_refuses_format_obfuscated_pii_in_corpus_content(
    tmp_path: Path,
) -> None:
    example = _copy_example(tmp_path)
    _replace_governing_summary(
        example,
        corpus_slug="policy_a",
        summary="Contact jane\u202e@example.com must never be published.",
        unicode_escape_digits=False,
    )
    out = tmp_path / "format-obfuscated-pii-output"

    result = _invoke_sensitivity(
        example=example,
        suite_name="responsive_suite.yaml",
        out=out,
    )

    assert result.exit_code == 2, result.output
    assert "baseline corpus snapshot contains sensitive-looking content" in result.output
    assert "jane" not in result.output
    assert "example.com" not in result.output
    assert not out.exists()


def test_bundle_publisher_refuses_sensitive_typed_path_with_escaped_manifest(
    tmp_path: Path,
) -> None:
    example = _copy_example(tmp_path)
    _replace_governing_path_with_escaped_manifest(
        example,
        corpus_slug="policy_a",
        new_name="123-45-6789.json",
    )
    out = tmp_path / "sensitive-path-output"

    result = _invoke_sensitivity(
        example=example,
        suite_name="responsive_suite.yaml",
        out=out,
    )

    assert result.exit_code == 2, result.output
    assert "baseline corpus snapshot contains sensitive-looking content" in result.output
    assert "123-45-6789" not in result.output
    assert not out.exists()


def test_report_recomputes_evaluation_from_the_exact_nested_runset(
    tmp_path: Path,
) -> None:
    artifacts = execute_sensitivity_experiment(
        suite_path=EXAMPLE / "responsive_suite.yaml",
        baseline_corpus_dir=EXAMPLE / "corpora" / "policy_a",
        counterfactual_corpus_dir=EXAMPLE / "corpora" / "policy_b",
        knowledge_contract_path=EXAMPLE / "knowledge-contract.yaml",
        expected_relation=EvidenceSensitivityExpectedRelation.decision_flip,
    )
    forged_run = artifacts.baseline_runset.runs[0].model_copy(update={"tools": ("different-tool",)})
    forged_runset = type(artifacts.baseline_runset).model_validate(
        {
            **artifacts.baseline_runset.model_dump(mode="json"),
            "runs": [forged_run.model_dump(mode="json")],
        }
    )
    forged_runset_digest = sha256_hexdigest(forged_runset.model_dump(mode="json"))
    forged_evaluation = type(artifacts.baseline_evaluation).model_validate(
        {
            **artifacts.baseline_evaluation.model_dump(mode="json"),
            "runset_digest": forged_runset_digest,
        }
    )
    forged_evaluation_digest = sha256_hexdigest(forged_evaluation.model_dump(mode="json"))
    report_payload = artifacts.report.model_dump(
        mode="json",
        exclude={"report_digest"},
    )
    baseline_arm = cast(dict[str, object], report_payload["baseline_arm"])
    baseline_arm["runset_digest"] = forged_runset_digest
    baseline_arm["evaluation_summary_digest"] = forged_evaluation_digest
    report_payload["baseline_runset"] = forged_runset.model_dump(mode="json")
    report_payload["baseline_evaluation"] = forged_evaluation.model_dump(mode="json")
    out = tmp_path / "forged-decision-output"

    with pytest.raises(
        ValueError,
        match="must equal a fresh evaluation",
    ):
        RAGSensitivityReport.build(**report_payload)

    assert not out.exists()


def test_report_rejects_runset_decision_detached_from_report_arm(
    tmp_path: Path,
) -> None:
    artifacts = execute_sensitivity_experiment(
        suite_path=EXAMPLE / "responsive_suite.yaml",
        baseline_corpus_dir=EXAMPLE / "corpora" / "policy_a",
        counterfactual_corpus_dir=EXAMPLE / "corpora" / "policy_b",
        knowledge_contract_path=EXAMPLE / "knowledge-contract.yaml",
        expected_relation=EvidenceSensitivityExpectedRelation.decision_flip,
    )
    forged_run = artifacts.baseline_runset.runs[0].model_copy(
        update={"recommendation": "deny", "outcome": "denied"}
    )
    forged_runset = type(artifacts.baseline_runset).model_validate(
        {
            **artifacts.baseline_runset.model_dump(mode="json"),
            "runs": [forged_run.model_dump(mode="json")],
        }
    )
    forged_runset_digest = sha256_hexdigest(forged_runset.model_dump(mode="json"))
    stale_passing_evaluation = type(artifacts.baseline_evaluation).model_validate(
        {
            **artifacts.baseline_evaluation.model_dump(mode="json"),
            "runset_digest": forged_runset_digest,
        }
    )
    stale_evaluation_digest = sha256_hexdigest(stale_passing_evaluation.model_dump(mode="json"))
    report_payload = artifacts.report.model_dump(
        mode="json",
        exclude={"report_digest"},
    )
    baseline_arm = cast(dict[str, object], report_payload["baseline_arm"])
    baseline_arm["runset_digest"] = forged_runset_digest
    baseline_arm["evaluation_summary_digest"] = stale_evaluation_digest
    report_payload["baseline_runset"] = forged_runset.model_dump(mode="json")
    report_payload["baseline_evaluation"] = stale_passing_evaluation.model_dump(mode="json")
    out = tmp_path / "stale-evaluation-output"

    with pytest.raises(ValueError, match="runtime and decision projection must match"):
        RAGSensitivityReport.build(**report_payload)

    assert not out.exists()


def test_offline_demo_succeeds_by_default_and_strict_mode_returns_block(
    tmp_path: Path,
) -> None:
    out = tmp_path / "demo"
    default_result = RUNNER.invoke(
        app,
        [
            "demo",
            "evidence-sensitivity",
            "--out",
            str(out),
            "--format",
            "json",
        ],
    )

    assert default_result.exit_code == 0, default_result.output
    summary = json.loads(default_result.output)
    assert summary == _json(out / "demo-summary.json")
    assert summary["status"] == "success"
    assert summary["underlying_exit_code"] == 1
    assert summary["expected_behavior_observed"] is True
    assert SENSITIVITY_HARNESS_NOTICE in summary["notice"]
    assert str(out) not in json.dumps(summary)
    experiments = cast(dict[str, dict[str, Any]], summary["experiments"])
    assert experiments["responsive"]["state"] == "responsive"
    assert experiments["evidence_inertial"]["state"] == "evidence_insensitive"
    assert experiments["evidence_inertial"]["evidence_prerequisites"] == "pass"
    assert experiments["evidence_inertial"]["arm_evaluations"] == "pass"
    assert experiments["evidence_inertial"]["decision_inertia"] is True

    strict_result = RUNNER.invoke(
        app,
        [
            "demo",
            "evidence-sensitivity",
            "--out",
            str(tmp_path / "strict-demo"),
            "--strict",
        ],
    )
    assert strict_result.exit_code == 1, strict_result.output
    assert "citations pass while controlled sensitivity blocks inertia" in strict_result.output


def test_public_and_packaged_examples_are_byte_identical() -> None:
    packaged = ROOT / "src" / "agent_assure" / "examples" / "evidence_sensitivity"
    public_files = {
        path.relative_to(EXAMPLE).as_posix(): path.read_bytes()
        for path in EXAMPLE.rglob("*")
        if path.is_file()
    }
    packaged_files = {
        path.relative_to(packaged).as_posix(): path.read_bytes()
        for path in packaged.rglob("*")
        if path.is_file()
    }
    assert packaged_files == public_files


def _invoke_sensitivity(*, example: Path, suite_name: str, out: Path) -> Result:
    return RUNNER.invoke(
        app,
        [
            *_sensitivity_cli_args(example=example, suite_name=suite_name, out=out),
            *_synthetic_data_attestation_args(
                example=example,
                suite_name=suite_name,
            ),
        ],
    )


def _sensitivity_cli_args(*, example: Path, suite_name: str, out: Path) -> list[str]:
    return [
        "rag",
        "sensitivity",
        "--suite",
        str(example / suite_name),
        *_common_args(example),
        "--expected-relation",
        "decision_flip",
        "--out",
        str(out),
    ]


def _synthetic_data_attestation_args(
    *,
    example: Path,
    suite_name: str,
) -> list[str]:
    try:
        suite_path = example / suite_name
        compiled = compile_suite(suite_path)
        suite_digest = compiled_suite_digest(compiled)
        manifest_digest = fixture_manifest_digest(
            build_fixture_manifest(compiled, suite_path.parent)
        )
        contract = load_knowledge_contract(example / "knowledge-contract.yaml")
        baseline = load_sensitivity_corpus(example / "corpora" / "policy_a")
        counterfactual = load_sensitivity_corpus(example / "corpora" / "policy_b")
    except (OSError, RuntimeError, TypeError, ValueError):
        # Invalid-input tests must reach the production loader that owns their
        # public error contract rather than fail while preparing test metadata.
        return []

    snapshot_identities = frozenset(
        {
            (
                baseline.manifest.corpus_digest,
                baseline.snapshot.snapshot_digest,
            ),
            (
                counterfactual.manifest.corpus_digest,
                counterfactual.snapshot.snapshot_digest,
            ),
        }
    )
    identity_set = bundled_sensitivity_identity_set(contract.schema_version)
    if (
        identity_set is not None
        and (suite_digest, manifest_digest) in identity_set.suite_identities
        and contract.knowledge_contract_digest == identity_set.knowledge_contract_digest
        and snapshot_identities == identity_set.corpus_snapshot_identities
    ):
        return []

    attestation = RAGSensitivitySyntheticDataAttestation.build(
        attestation_id="test-synthetic-data-attestation",
        suite_digest=suite_digest,
        fixture_manifest_digest=manifest_digest,
        knowledge_contract_digest=contract.knowledge_contract_digest,
        corpus_digests=tuple(
            sorted(
                (
                    baseline.manifest.corpus_digest,
                    counterfactual.manifest.corpus_digest,
                )
            )
        ),
        corpus_snapshot_digests=tuple(
            sorted(
                (
                    baseline.snapshot.snapshot_digest,
                    counterfactual.snapshot.snapshot_digest,
                )
            )
        ),
    )
    path = example / "synthetic-data-attestation.json"
    _write_json(path, attestation.model_dump(mode="json"))
    return ["--synthetic-data-attestation", str(path)]


def _common_args(example: Path) -> list[str]:
    return [
        "--baseline-corpus",
        str(example / "corpora" / "policy_a"),
        "--counterfactual-corpus",
        str(example / "corpora" / "policy_b"),
        "--knowledge-contract",
        str(example / "knowledge-contract.yaml"),
    ]


def _copy_example(tmp_path: Path) -> Path:
    destination = tmp_path / "example"
    shutil.copytree(EXAMPLE, destination)
    return destination


def _change_counterfactual_top_k(example: Path, *, top_k: int) -> None:
    manifest_path = example / "corpora" / "policy_b" / "corpus-manifest.json"
    manifest_payload = _json(manifest_path)
    old_digest = cast(str, manifest_payload.pop("corpus_digest"))
    manifest_payload["top_k"] = top_k
    manifest = RAGSensitivityCorpusManifest.build(**manifest_payload)
    _write_json(manifest_path, manifest.model_dump(mode="json"))

    contract_path = example / "knowledge-contract.yaml"
    contract_payload = yaml.safe_load(contract_path.read_text(encoding="utf-8"))
    assert isinstance(contract_payload, dict)
    contract_payload.pop("knowledge_contract_digest")
    assignments = cast(list[dict[str, object]], contract_payload["assignments"])
    for assignment in assignments:
        if assignment["corpus_digest"] == old_digest:
            assignment["corpus_digest"] = manifest.corpus_digest
    assignments.sort(key=lambda item: cast(str, item["corpus_digest"]))
    contract = RAGSensitivityKnowledgeContract.build(**contract_payload)
    contract_path.write_text(
        yaml.safe_dump(contract.model_dump(mode="json"), sort_keys=False),
        encoding="utf-8",
    )


def _add_non_governing_document(example: Path, *, corpus_slug: str) -> None:
    corpus_dir = example / "corpora" / corpus_slug
    document_path = corpus_dir / "synthetic-distractor.json"
    document_payload: dict[str, object] = {
        "governing_decision": "approve",
        "governing_outcome": "approved",
        "ref_id": "synthetic-distractor-reference",
        "retrieval_terms": ["quartz", "zebra"],
        "safe_summary": "A non-governing synthetic distractor.",
        "source_id": "synthetic-distractor-source",
        "title": "Synthetic distractor",
    }
    _write_json(document_path, document_payload)
    content_digest = hashlib.sha256(document_path.read_bytes()).hexdigest()

    manifest_path = corpus_dir / "corpus-manifest.json"
    manifest_payload = _json(manifest_path)
    old_digest = cast(str, manifest_payload.pop("corpus_digest"))
    documents = cast(list[dict[str, object]], manifest_payload["documents"])
    documents.append(
        RAGSensitivityCorpusDocument(
            path=document_path.name,
            source_id="synthetic-distractor-source",
            content_digest=content_digest,
        ).model_dump(mode="json")
    )
    documents.sort(key=lambda item: (cast(str, item["source_id"]), cast(str, item["path"])))
    manifest = RAGSensitivityCorpusManifest.build(**manifest_payload)
    _write_json(manifest_path, manifest.model_dump(mode="json"))
    _rewrite_contract_assignment(
        example,
        old_corpus_digest=old_digest,
        new_corpus_digest=manifest.corpus_digest,
    )


def _add_shared_non_governing_documents(example: Path, *, count: int) -> None:
    replacements: list[tuple[str, str]] = []
    for corpus_slug in ("policy_a", "policy_b"):
        corpus_dir = example / "corpora" / corpus_slug
        manifest_path = corpus_dir / "corpus-manifest.json"
        manifest_payload = _json(manifest_path)
        old_digest = cast(str, manifest_payload.pop("corpus_digest"))
        documents = cast(list[dict[str, object]], manifest_payload["documents"])
        for index in range(count):
            source_id = f"synthetic-distractor-source-{index:03d}"
            document_path = corpus_dir / f"synthetic-distractor-{index:03d}.json"
            document_payload: dict[str, object] = {
                "governing_decision": "approve",
                "governing_outcome": "approved",
                "ref_id": f"synthetic-distractor-reference-{index:03d}",
                "retrieval_terms": ["quartz", f"syntheticterm{index:03d}"],
                "safe_summary": f"Synthetic non-governing distractor {index:03d}.",
                "source_id": source_id,
                "title": f"Synthetic distractor {index:03d}",
            }
            _write_json(document_path, document_payload)
            documents.append(
                RAGSensitivityCorpusDocument(
                    path=document_path.name,
                    source_id=source_id,
                    content_digest=hashlib.sha256(document_path.read_bytes()).hexdigest(),
                ).model_dump(mode="json")
            )
        documents.sort(key=lambda item: (cast(str, item["source_id"]), cast(str, item["path"])))
        manifest = RAGSensitivityCorpusManifest.build(**manifest_payload)
        _write_json(manifest_path, manifest.model_dump(mode="json"))
        replacements.append((old_digest, manifest.corpus_digest))

    for old_digest, new_digest in replacements:
        _rewrite_contract_assignment(
            example,
            old_corpus_digest=old_digest,
            new_corpus_digest=new_digest,
        )


def _replace_governing_summary(
    example: Path,
    *,
    corpus_slug: str,
    summary: str,
    unicode_escape_digits: bool,
) -> None:
    corpus_dir = example / "corpora" / corpus_slug
    document_path = corpus_dir / "governing-policy.json"
    document_payload = _json(document_path)
    document_payload["safe_summary"] = summary
    document_text = json.dumps(document_payload, indent=2, sort_keys=True) + "\n"
    if unicode_escape_digits:
        escaped_summary = "".join(
            f"\\u{ord(character):04x}" if character.isdigit() else character
            for character in summary
        )
        document_text = document_text.replace(summary, escaped_summary)
    document_path.write_text(document_text, encoding="utf-8")
    content_digest = hashlib.sha256(document_path.read_bytes()).hexdigest()

    manifest_path = corpus_dir / "corpus-manifest.json"
    manifest_payload = _json(manifest_path)
    old_digest = cast(str, manifest_payload.pop("corpus_digest"))
    documents = cast(list[dict[str, object]], manifest_payload["documents"])
    governing_descriptor = next(item for item in documents if item["path"] == document_path.name)
    governing_descriptor["content_digest"] = content_digest
    manifest = RAGSensitivityCorpusManifest.build(**manifest_payload)
    _write_json(manifest_path, manifest.model_dump(mode="json"))
    _rewrite_contract_assignment(
        example,
        old_corpus_digest=old_digest,
        new_corpus_digest=manifest.corpus_digest,
        governing_content_digest=content_digest,
    )


def _replace_governing_path_with_escaped_manifest(
    example: Path,
    *,
    corpus_slug: str,
    new_name: str,
) -> None:
    corpus_dir = example / "corpora" / corpus_slug
    original_path = corpus_dir / "governing-policy.json"
    replacement_path = corpus_dir / new_name
    original_path.rename(replacement_path)

    manifest_path = corpus_dir / "corpus-manifest.json"
    manifest_payload = _json(manifest_path)
    old_digest = cast(str, manifest_payload.pop("corpus_digest"))
    documents = cast(list[dict[str, object]], manifest_payload["documents"])
    governing_descriptor = next(item for item in documents if item["path"] == original_path.name)
    governing_descriptor["path"] = replacement_path.name
    manifest = RAGSensitivityCorpusManifest.build(**manifest_payload)
    manifest_text = json.dumps(manifest.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"
    escaped_name = "".join(
        f"\\u{ord(character):04x}" if character.isdigit() else character for character in new_name
    )
    manifest_path.write_text(
        manifest_text.replace(new_name, escaped_name),
        encoding="utf-8",
    )
    _rewrite_contract_assignment(
        example,
        old_corpus_digest=old_digest,
        new_corpus_digest=manifest.corpus_digest,
    )


def _rewrite_contract_assignment(
    example: Path,
    *,
    old_corpus_digest: str,
    new_corpus_digest: str,
    governing_content_digest: str | None = None,
) -> None:
    contract_path = example / "knowledge-contract.yaml"
    contract_payload = yaml.safe_load(contract_path.read_text(encoding="utf-8"))
    assert isinstance(contract_payload, dict)
    contract_payload.pop("knowledge_contract_digest")
    assignments = cast(list[dict[str, object]], contract_payload["assignments"])
    assignment = next(item for item in assignments if item["corpus_digest"] == old_corpus_digest)
    assignment["corpus_digest"] = new_corpus_digest
    if governing_content_digest is not None:
        assignment["governing_content_digest"] = governing_content_digest
    assignments.sort(key=lambda item: cast(str, item["corpus_digest"]))
    contract = RAGSensitivityKnowledgeContract.build(**contract_payload)
    contract_path.write_text(
        yaml.safe_dump(contract.model_dump(mode="json"), sort_keys=False),
        encoding="utf-8",
    )


def _assert_renderings(
    out: Path,
    expected_json: dict[str, object],
    *,
    golden_stem: str,
) -> None:
    assert _json(out / "evidence-sensitivity.json") == expected_json
    markdown = (out / "evidence-sensitivity.md").read_text(encoding="utf-8")
    html = (out / "evidence-sensitivity.html").read_text(encoding="utf-8")
    assert markdown.startswith("# Controlled Evidence Sensitivity\n")
    assert "synthetic detector contract test" in markdown.lower()
    assert "not a causal guarantee" in markdown
    assert "does not estimate failure prevalence" in markdown
    assert "<title>Controlled Evidence Sensitivity</title>" in html
    assert "Synthetic detector contract test" in html
    assert "not a causal guarantee" in html
    assert "<script" not in html.lower()
    assert "https://" not in html.lower()
    assert "http://" not in html.lower()
    for suffix in ("json", "md", "html"):
        assert (out / f"evidence-sensitivity.{suffix}").read_bytes() == (
            GOLDEN_REPORTS / f"{golden_stem}.{suffix}"
        ).read_bytes()


def _json(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return {str(key): value for key, value in payload.items()}


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
