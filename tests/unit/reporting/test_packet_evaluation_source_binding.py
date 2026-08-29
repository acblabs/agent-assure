from __future__ import annotations

import hashlib
import json
from pathlib import Path

from agent_assure.authoring.compiler import compile_suite
from agent_assure.ci import (
    GateOutcome,
    gate_artifact,
    gate_evaluation_summary,
    gate_evidence_packet,
)
from agent_assure.compare.runsets import compare_runsets
from agent_assure.evaluation.evaluator import evaluate_runset, runset_digest
from agent_assure.fixtures.loader import compiled_suite_digest
from agent_assure.reporting.packet import (
    build_evidence_packet,
    packet_summary_files_binding_error,
)
from agent_assure.runner.fixture_runner import load_variant_config, run_suite
from agent_assure.schema.common import GateState
from agent_assure.schema.comparison import ComparisonSummary
from agent_assure.schema.environment import EnvironmentInfo
from agent_assure.schema.evaluation import EvaluationSummary
from agent_assure.schema.packet import EvidencePacket, PacketArtifactDigest
from agent_assure.schema.release import ReleaseArtifact, ReleaseArtifactManifest
from agent_assure.schema.run import RunSet
from agent_assure.schema.suite import CompiledSuite

SUITE_PATH = Path("examples/prior_auth_synthetic/suite.yaml")
BASELINE_VARIANT = Path("examples/prior_auth_synthetic/variants/baseline.yaml")
FAILING_VARIANT = Path("examples/prior_auth_synthetic/variants/candidate_smoke_fail.yaml")
EVIDENCE_VARIANT = Path(
    "examples/prior_auth_synthetic/variants/candidate_evidence_normalization.yaml"
)


def test_manifest_bound_candidate_and_suite_reproduce_nested_evaluation(
    tmp_path: Path,
) -> None:
    suite, candidate = _runset(BASELINE_VARIANT)
    evaluation = evaluate_runset(suite, candidate).candidate_vs_expectations
    packet = _write_bound_packet(tmp_path, suite, candidate, evaluation)

    assert packet_summary_files_binding_error(packet, artifact_root=tmp_path) is None
    decision = gate_evidence_packet(packet, artifact_root=tmp_path)
    assert decision.outcome is GateOutcome.pass_
    assert decision.exit_code == 0


def test_gate_rejects_candidate_substitution_even_when_summary_digest_is_rebound(
    tmp_path: Path,
) -> None:
    suite, weak_candidate = _runset(BASELINE_VARIANT)
    _, advertised_candidate = _runset(FAILING_VARIANT)
    weak_evaluation = evaluate_runset(suite, weak_candidate).candidate_vs_expectations
    assert weak_evaluation.state.value == "pass"
    assert evaluate_runset(suite, advertised_candidate).candidate_vs_expectations.state.value == (
        "fail"
    )
    forged_subject = weak_evaluation.model_copy(
        update={
            "runset_id": advertised_candidate.runset_id,
            "runset_digest": runset_digest(advertised_candidate),
        }
    )
    packet = _write_bound_packet(
        tmp_path,
        suite,
        advertised_candidate,
        forged_subject,
    )

    decision = gate_evidence_packet(packet, artifact_root=tmp_path)

    assert decision.outcome is GateOutcome.invalid
    assert decision.exit_code == 2
    assert "does not match independent evaluation" in decision.message


def test_gate_rejects_unauthenticated_fail_to_warn_rewrite(
    tmp_path: Path,
) -> None:
    suite, candidate = _runset(FAILING_VARIANT)
    evaluation = evaluate_runset(suite, candidate).candidate_vs_expectations
    assert evaluation.state is GateState.fail
    assert evaluation.findings
    forged = evaluation.model_copy(
        update={
            "state": GateState.warn,
            "findings": tuple(
                finding.model_copy(update={"state": GateState.warn})
                for finding in evaluation.findings
            ),
        }
    )
    packet = _write_bound_packet(tmp_path, suite, candidate, forged)

    decision = gate_evidence_packet(packet, artifact_root=tmp_path)

    assert decision.outcome is GateOutcome.invalid
    assert decision.exit_code == 2
    assert "does not match independent evaluation" in decision.message


def test_gate_rejects_suite_substitution_after_all_advertised_digests_are_rebound(
    tmp_path: Path,
) -> None:
    original_suite, original_candidate = _runset(BASELINE_VARIANT)
    original_evaluation = evaluate_runset(
        original_suite,
        original_candidate,
    ).candidate_vs_expectations
    strict_suite = _strict_suite(original_suite)
    rebound_candidate = original_candidate.model_copy(
        update={"suite_digest": compiled_suite_digest(strict_suite)}
    )
    rebound_evaluation = evaluate_runset(
        strict_suite,
        rebound_candidate,
    ).candidate_vs_expectations
    assert rebound_evaluation.state.value == "fail"
    forged_requirement_set = original_evaluation.model_copy(
        update={"runset_digest": runset_digest(rebound_candidate)}
    )
    packet = _write_bound_packet(
        tmp_path,
        strict_suite,
        rebound_candidate,
        forged_requirement_set,
    )

    decision = gate_evidence_packet(packet, artifact_root=tmp_path)

    assert decision.outcome is GateOutcome.invalid
    assert decision.exit_code == 2
    assert "replay_context suite_digest does not match" in decision.message


def test_manifest_bound_comparison_matches_both_exact_source_runsets(
    tmp_path: Path,
) -> None:
    suite, baseline = _runset(BASELINE_VARIANT)
    _, candidate = _runset(EVIDENCE_VARIANT)
    evaluation = evaluate_runset(suite, candidate).candidate_vs_expectations
    comparison = compare_runsets(suite, baseline, candidate).comparison_summary
    packet = _write_bound_packet(
        tmp_path,
        suite,
        candidate,
        evaluation,
        baseline=baseline,
        comparison=comparison,
    )

    assert packet_summary_files_binding_error(packet, artifact_root=tmp_path) is None
    assert gate_evidence_packet(packet, artifact_root=tmp_path).outcome is not GateOutcome.invalid


def test_gate_rejects_rebound_baseline_substitution_from_comparison_sources(
    tmp_path: Path,
) -> None:
    suite, comparison_baseline = _runset(BASELINE_VARIANT)
    _, candidate = _runset(EVIDENCE_VARIANT)
    _, advertised_baseline = _runset(FAILING_VARIANT)
    evaluation = evaluate_runset(suite, candidate).candidate_vs_expectations
    original = compare_runsets(suite, comparison_baseline, candidate).comparison_summary
    forged = original.model_copy(
        update={
            "baseline_runset_id": advertised_baseline.runset_id,
            "baseline_runset_digest": runset_digest(advertised_baseline),
        }
    )
    packet = _write_bound_packet(
        tmp_path,
        suite,
        candidate,
        evaluation,
        baseline=advertised_baseline,
        comparison=forged,
    )

    decision = gate_evidence_packet(packet, artifact_root=tmp_path)

    assert decision.outcome is GateOutcome.invalid
    assert decision.exit_code == 2
    assert "comparison" in decision.message
    assert "does not match independent comparison" in decision.message


def test_gate_rejects_baseline_source_role_without_nested_comparison(
    tmp_path: Path,
) -> None:
    suite, candidate = _runset(BASELINE_VARIANT)
    evaluation = evaluate_runset(suite, candidate).candidate_vs_expectations
    packet = _write_bound_packet(
        tmp_path,
        suite,
        candidate,
        evaluation,
        baseline=candidate,
    )

    decision = gate_evidence_packet(packet, artifact_root=tmp_path)

    assert decision.outcome is GateOutcome.invalid
    assert "baseline-runset requires a nested comparison" in decision.message


def test_gate_rejects_comparison_sources_without_baseline_role(
    tmp_path: Path,
) -> None:
    suite, baseline = _runset(BASELINE_VARIANT)
    _, candidate = _runset(EVIDENCE_VARIANT)
    evaluation = evaluate_runset(suite, candidate).candidate_vs_expectations
    comparison = compare_runsets(suite, baseline, candidate).comparison_summary
    packet = _write_bound_packet(
        tmp_path,
        suite,
        candidate,
        evaluation,
        baseline=baseline,
        comparison=comparison,
        advertise_baseline=False,
    )

    decision = gate_evidence_packet(packet, artifact_root=tmp_path)

    assert decision.outcome is GateOutcome.invalid
    assert "requires a baseline-runset" in decision.message


def test_current_evaluation_gate_rejects_missing_runset_digest() -> None:
    suite, candidate = _runset(BASELINE_VARIANT)
    evaluation = evaluate_runset(suite, candidate).candidate_vs_expectations.model_copy(
        update={"runset_digest": None}
    )

    decision = gate_evaluation_summary(evaluation)

    assert decision.outcome is GateOutcome.invalid
    assert decision.exit_code == 2
    assert "require an authenticated runset_digest" in decision.message


def test_library_gate_requires_root_for_manifest_bearing_packet(tmp_path: Path) -> None:
    suite, candidate = _runset(BASELINE_VARIANT)
    evaluation = evaluate_runset(suite, candidate).candidate_vs_expectations
    packet = _write_bound_packet(tmp_path, suite, candidate, evaluation)

    direct = gate_evidence_packet(packet)
    routed = gate_artifact(packet)

    for decision in (direct, routed):
        assert decision.outcome is GateOutcome.invalid
        assert decision.exit_code == 2
        assert "release-manifest-bearing evidence packet requires artifact_root" in decision.message


def _runset(variant_path: Path) -> tuple[CompiledSuite, RunSet]:
    suite = compile_suite(SUITE_PATH)
    return (
        suite,
        run_suite(
            suite,
            load_variant_config(variant_path),
            SUITE_PATH.parent,
        ),
    )


def _strict_suite(suite: CompiledSuite) -> CompiledSuite:
    payload = suite.model_dump(mode="json")
    first = suite.resolved_expectations[0].model_copy(
        update={
            "expected_recommendation": "never-match",
            "allowed_outcomes": (),
        }
    )
    payload["resolved_expectations"][0] = first.model_dump(mode="json")
    return CompiledSuite.model_validate(payload)


def _write_bound_packet(
    root: Path,
    suite: CompiledSuite,
    candidate: RunSet,
    evaluation: EvaluationSummary,
    *,
    baseline: RunSet | None = None,
    comparison: ComparisonSummary | None = None,
    advertise_baseline: bool | None = None,
) -> EvidencePacket:
    evaluation_path = root / "evaluation-summary.json"
    candidate_path = root / "candidate.runset.json"
    suite_path = root / "compiled-suite.json"
    _write_json(evaluation_path, evaluation.model_dump(mode="json"))
    _write_json(candidate_path, candidate.model_dump(mode="json"))
    _write_json(suite_path, suite.model_dump(mode="json"))
    evaluation_sha256 = _file_sha256(evaluation_path)
    artifacts = [
        ReleaseArtifact(
            role="compiled-suite",
            path=suite_path.name,
            sha256=_file_sha256(suite_path),
        ),
        ReleaseArtifact(
            role="candidate-runset",
            path=candidate_path.name,
            sha256=_file_sha256(candidate_path),
        ),
        ReleaseArtifact(
            role="evaluation-summary",
            path=evaluation_path.name,
            sha256=evaluation_sha256,
        ),
    ]
    digests = [
        PacketArtifactDigest(
            role="evaluation-summary",
            sha256=evaluation_sha256,
        )
    ]
    include_baseline = (
        baseline is not None if advertise_baseline is None else advertise_baseline
    )
    if include_baseline:
        assert baseline is not None
        baseline_path = root / "baseline.runset.json"
        _write_json(baseline_path, baseline.model_dump(mode="json"))
        artifacts.append(
            ReleaseArtifact(
                role="baseline-runset",
                path=baseline_path.name,
                sha256=_file_sha256(baseline_path),
            )
        )
    if comparison is not None:
        comparison_path = root / "comparison-summary.json"
        _write_json(comparison_path, comparison.model_dump(mode="json"))
        comparison_sha256 = _file_sha256(comparison_path)
        artifacts.append(
            ReleaseArtifact(
                role="comparison-summary",
                path=comparison_path.name,
                sha256=comparison_sha256,
            )
        )
        digests.append(
            PacketArtifactDigest(
                role="comparison-summary",
                sha256=comparison_sha256,
            )
        )
    manifest = ReleaseArtifactManifest(
        manifest_id="evaluation-source-binding-test",
        artifacts=tuple(artifacts),
        environment=EnvironmentInfo(platform="test", python_version="3.14"),
    )
    return build_evidence_packet(
        evaluation,
        comparison=comparison,
        release_manifest=manifest,
        artifact_digests=tuple(digests),
    )


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
