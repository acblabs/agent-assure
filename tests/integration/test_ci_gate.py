from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from click import unstyle
from typer.testing import CliRunner

import agent_assure.ci as ci_module
from agent_assure.artifact_io import file_sha256
from agent_assure.authoring.compiler import compile_suite
from agent_assure.ci import run_ci
from agent_assure.cli.main import app
from agent_assure.fixtures.loader import write_compiled_suite
from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.runner.fixture_runner import load_variant_config, run_suite, write_runset
from agent_assure.schema.common import ComparisonClassification, GateState
from agent_assure.schema.comparison import ComparisonSummary
from agent_assure.schema.environment import EnvironmentInfo
from agent_assure.schema.evaluation import EvaluationSummary
from agent_assure.schema.packet import EvidencePacket, PacketArtifactDigest
from agent_assure.schema.release import ReleaseArtifact, ReleaseArtifactManifest

RUNNER = CliRunner()
SUITE = Path("examples/prior_auth_synthetic/suite.yaml")
BASELINE = Path("examples/prior_auth_synthetic/variants/baseline.yaml")
EVIDENCE_CANDIDATE = Path(
    "examples/prior_auth_synthetic/variants/candidate_evidence_normalization.yaml"
)


def test_ci_refuses_a_filesystem_root_output_directory() -> None:
    filesystem_root = Path(Path.cwd().anchor)

    with pytest.raises(ValueError, match="filesystem root"):
        run_ci(
            Path("candidate.runset.json"),
            suite_path=Path("suite.compiled.json"),
            out_dir=filesystem_root,
        )


def test_ci_gate_passes_and_fails_evaluation_summaries(tmp_path: Path) -> None:
    passing = tmp_path / "pass.json"
    warning = tmp_path / "warn.json"
    failing = tmp_path / "fail.json"
    _write_json(
        passing,
        EvaluationSummary(
            artifact_kind="evaluation-summary",
            runset_id="baseline",
            privacy_profile_id=PRIVACY_PROFILE_ID,
            privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
            state=GateState.pass_,
        ).model_dump(mode="json"),
    )
    _write_json(
        warning,
        EvaluationSummary(
            artifact_kind="evaluation-summary",
            runset_id="candidate",
            privacy_profile_id=PRIVACY_PROFILE_ID,
            privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
            state=GateState.warn,
        ).model_dump(mode="json"),
    )
    _write_json(
        failing,
        EvaluationSummary(
            artifact_kind="evaluation-summary",
            runset_id="candidate",
            privacy_profile_id=PRIVACY_PROFILE_ID,
            privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
            state=GateState.fail,
        ).model_dump(mode="json"),
    )

    assert RUNNER.invoke(app, ["ci", "gate", str(passing)]).exit_code == 0
    assert RUNNER.invoke(app, ["ci", "gate", str(warning)]).exit_code == 0
    assert RUNNER.invoke(app, ["ci", "gate", str(warning), "--fail-on-warn"]).exit_code == 1
    assert RUNNER.invoke(app, ["ci", "gate", str(failing)]).exit_code == 1


def test_direct_evaluation_gate_revalidates_model_copy_tampering() -> None:
    summary = EvaluationSummary(
        artifact_kind="evaluation-summary",
        runset_id="candidate",
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.pass_,
    )
    tampered = summary.model_copy(update={"runset_id": ""})

    decision = ci_module.gate_evaluation_summary(tampered)

    assert decision.exit_code == 2
    assert decision.outcome.value == "invalid"
    assert "failed trusted model revalidation" in decision.message


@pytest.mark.parametrize(
    ("state", "expected_output"),
    (
        (
            GateState.warn,
            "ci gate review: evaluation-summary candidate state=warn",
        ),
        (
            GateState.not_evaluated,
            "ci gate not-evaluated: evaluation-summary candidate state=not_evaluated",
        ),
    ),
)
def test_ci_gate_nonblocking_state_stdout_uses_explicit_outcome_labels(
    tmp_path: Path,
    state: GateState,
    expected_output: str,
) -> None:
    summary_path = tmp_path / f"{state.value}.json"
    _write_json(
        summary_path,
        EvaluationSummary(
            artifact_kind="evaluation-summary",
            runset_id="candidate",
            privacy_profile_id=PRIVACY_PROFILE_ID,
            privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
            state=state,
        ).model_dump(mode="json"),
    )

    result = RUNNER.invoke(app, ["ci", "gate", str(summary_path)])

    assert result.exit_code == 0, result.output
    assert result.output.strip() == expected_output


@pytest.mark.parametrize(
    ("state", "expected_outcome"),
    (
        (GateState.pass_, "pass"),
        (GateState.warn, "review"),
        (GateState.not_evaluated, "not_evaluated"),
    ),
)
def test_ci_gate_json_output_exposes_every_nonblocking_outcome(
    tmp_path: Path,
    state: GateState,
    expected_outcome: str,
) -> None:
    summary_path = tmp_path / f"{state.value}.json"
    _write_json(
        summary_path,
        EvaluationSummary(
            artifact_kind="evaluation-summary",
            runset_id="machine-reader",
            privacy_profile_id=PRIVACY_PROFILE_ID,
            privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
            state=state,
        ).model_dump(mode="json"),
    )

    result = RUNNER.invoke(
        app,
        ["ci", "gate", str(summary_path), "--format", "json"],
    )

    assert result.exit_code == 0, result.output
    decision = json.loads(result.output)
    assert decision["outcome"] == expected_outcome
    assert decision["exit_code"] == 0
    assert decision["artifact_kind"] == "evaluation-summary"
    assert decision["artifact_path"] == str(summary_path)
    assert decision["reason_code"] is None
    assert decision["efficacy_evidence"] == "not_applicable"
    assert decision["efficacy_verification"] == "not_requested"
    assert decision["efficacy_required"] is False


def test_ci_gate_json_output_reports_invalid_artifact_load_structurally(
    tmp_path: Path,
) -> None:
    malformed = tmp_path / "malformed.json"
    malformed.write_text('{"artifact_kind":', encoding="utf-8", newline="\n")

    result = RUNNER.invoke(
        app,
        ["ci", "gate", str(malformed), "--format", "json"],
    )

    assert result.exit_code == 2, result.output
    decision = json.loads(result.output)
    assert decision["outcome"] == "invalid"
    assert decision["exit_code"] == 2
    assert decision["artifact_path"] == str(malformed)
    assert decision["efficacy_verification"] == "strict"
    assert decision["reason_code"] is None


def test_ci_gate_exits_two_for_invalid_comparison(tmp_path: Path) -> None:
    summary = ComparisonSummary(
        artifact_kind="comparison-summary",
        baseline_runset_id="baseline",
        candidate_runset_id="candidate",
        baseline_runset_digest="b" * 64,
        candidate_runset_digest="c" * 64,
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        classification=ComparisonClassification.invalid_comparison,
        fixture_equivalence_state=GateState.fail,
    )
    path = tmp_path / "comparison-summary.json"
    _write_json(path, summary.model_dump(mode="json"))

    result = RUNNER.invoke(app, ["ci", "gate", str(path)])

    assert result.exit_code == 2


def test_ci_gate_legacy_unbound_comparison_requires_explicit_compatibility(
    tmp_path: Path,
) -> None:
    packet = _legacy_unbound_comparison_packet()
    path = tmp_path / "legacy-comparison-packet.json"
    _write_json(path, packet.model_dump(mode="json"))
    assert packet.comparison is not None
    comparison_path = tmp_path / "legacy-comparison.json"
    _write_json(comparison_path, packet.comparison.model_dump(mode="json"))

    rejected = RUNNER.invoke(app, ["ci", "gate", str(path)])
    allowed = RUNNER.invoke(
        app,
        ["ci", "gate", str(path), "--allow-legacy-unbound-comparison"],
    )
    standalone_rejected = RUNNER.invoke(app, ["ci", "gate", str(comparison_path)])
    standalone_allowed = RUNNER.invoke(
        app,
        [
            "ci",
            "gate",
            str(comparison_path),
            "--allow-legacy-unbound-comparison",
        ],
    )

    assert rejected.exit_code == 2, rejected.output
    assert "without authenticated baseline and candidate RunSet digests" in rejected.output
    assert allowed.exit_code == 0, allowed.output
    assert "legacy_unbound_comparison=allowed" in allowed.output
    assert standalone_rejected.exit_code == 2, standalone_rejected.output
    assert (
        "without authenticated baseline and candidate RunSet digests" in standalone_rejected.output
    )
    assert standalone_allowed.exit_code == 0, standalone_allowed.output
    assert "legacy_unbound_comparison=allowed" in standalone_allowed.output


def test_legacy_unbound_comparison_option_is_rejected_outside_ci_gate() -> None:
    result = RUNNER.invoke(
        app,
        ["ci", "candidate.json", "--allow-legacy-unbound-comparison"],
    )

    assert result.exit_code == 2
    assert "--allow-legacy-unbound-comparison is only valid with ci gate" in unstyle(
        result.output
    )


def test_ci_gate_rejects_unused_legacy_unbound_comparison_override(tmp_path: Path) -> None:
    evaluation = EvaluationSummary(
        runset_id="bound-candidate",
        runset_digest="c" * 64,
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.pass_,
    )
    packet = EvidencePacket(
        packet_id="no-comparison",
        interpretation=("unused compatibility override regression",),
        evaluation=evaluation,
        artifact_digests=(PacketArtifactDigest(role="evaluation-summary", sha256="e" * 64),),
        limitations=("test fixture",),
    )
    comparison = ComparisonSummary(
        baseline_runset_id="baseline",
        candidate_runset_id=evaluation.runset_id,
        baseline_runset_digest="b" * 64,
        candidate_runset_digest=evaluation.runset_digest,
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        classification=ComparisonClassification.unchanged,
        fixture_equivalence_state=GateState.pass_,
        candidate_state=GateState.pass_,
    )
    packet_path = tmp_path / "no-comparison-packet.json"
    comparison_path = tmp_path / "bound-comparison.json"
    _write_json(packet_path, packet.model_dump(mode="json"))
    _write_json(comparison_path, comparison.model_dump(mode="json"))

    for path in (packet_path, comparison_path):
        result = RUNNER.invoke(
            app,
            ["ci", "gate", str(path), "--allow-legacy-unbound-comparison"],
        )
        assert result.exit_code == 2, result.output
        assert "has no legacy unbound comparison" in result.output
        assert "remove the unused compatibility override" in result.output


@pytest.mark.parametrize("root_kind", ("missing", "file"))
def test_ci_gate_json_structures_invalid_explicit_artifact_root(
    tmp_path: Path,
    root_kind: str,
) -> None:
    summary_path = tmp_path / "evaluation-summary.json"
    _write_json(
        summary_path,
        EvaluationSummary(
            runset_id="artifact-root-candidate",
            privacy_profile_id=PRIVACY_PROFILE_ID,
            privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
            state=GateState.pass_,
        ).model_dump(mode="json"),
    )
    artifact_root = tmp_path / root_kind
    if root_kind == "file":
        artifact_root.write_text("not a directory\n", encoding="utf-8")

    result = RUNNER.invoke(
        app,
        [
            "ci",
            "gate",
            str(summary_path),
            "--artifact-root",
            str(artifact_root),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 2, result.output
    decision = json.loads(result.output)
    assert decision["outcome"] == "invalid"
    assert decision["exit_code"] == 2
    assert decision["artifact_path"] == str(summary_path)
    expected = "does not exist" if root_kind == "missing" else "must be a directory"
    assert expected in decision["message"]


def test_ci_gate_rejects_artifact_root_for_non_packet(tmp_path: Path) -> None:
    summary_path = tmp_path / "evaluation-summary.json"
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    _write_json(
        summary_path,
        EvaluationSummary(
            runset_id="artifact-root-candidate",
            privacy_profile_id=PRIVACY_PROFILE_ID,
            privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
            state=GateState.pass_,
        ).model_dump(mode="json"),
    )

    result = RUNNER.invoke(
        app,
        ["ci", "gate", str(summary_path), "--artifact-root", str(artifact_root)],
    )

    assert result.exit_code == 2, result.output
    assert "--artifact-root is only valid when gating an evidence packet" in unstyle(result.output)


def test_ci_gate_text_sanitizes_terminal_controls_but_json_preserves_values(
    tmp_path: Path,
) -> None:
    hostile_packet_id = "trusted-packet\nFORGED-DECISION\x1b[31m"
    packet = EvidencePacket(
        packet_id=hostile_packet_id,
        interpretation=("terminal output safety regression",),
        evaluation=EvaluationSummary(
            runset_id="candidate",
            privacy_profile_id=PRIVACY_PROFILE_ID,
            privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
            state=GateState.pass_,
        ),
        artifact_digests=(PacketArtifactDigest(role="evaluation-summary", sha256="e" * 64),),
        limitations=("test fixture",),
    )
    path = tmp_path / "hostile-packet.json"
    _write_json(path, packet.model_dump(mode="json"))

    text_result = RUNNER.invoke(app, ["ci", "gate", str(path)])
    json_result = RUNNER.invoke(
        app,
        ["ci", "gate", str(path), "--format", "json"],
    )

    assert text_result.exit_code == 0, text_result.output
    assert text_result.output.count("\n") == 1
    assert "\x1b" not in text_result.output
    assert "FORGED-DECISION" in text_result.output
    assert json_result.exit_code == 0, json_result.output
    payload = json.loads(json_result.output)
    assert hostile_packet_id in payload["message"]
    assert "\\n" in json_result.output
    assert "\\u001b" in json_result.output


def test_ci_gate_infers_packet_local_producer_root_inside_git(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    out = repo / "sensitivity-output"
    example = Path("examples/evidence_sensitivity")
    produced = RUNNER.invoke(
        app,
        [
            "rag",
            "sensitivity",
            "--suite",
            str(example / "responsive_suite.yaml"),
            "--baseline-corpus",
            str(example / "corpora" / "policy_a"),
            "--counterfactual-corpus",
            str(example / "corpora" / "policy_b"),
            "--knowledge-contract",
            str(example / "knowledge-contract.yaml"),
            "--expected-relation",
            "decision_flip",
            "--out",
            str(out),
        ],
    )
    assert produced.exit_code == 0, produced.output
    _init_git_repo(repo)

    result = RUNNER.invoke(app, ["ci", "gate", str(out / "evidence-packet.json")])

    assert result.exit_code == 0, result.output


def test_ci_gate_falls_back_to_legacy_repo_relative_manifest_root(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    packet_path = repo / "packet-output" / "evidence-packet.json"
    _write_release_bound_packet(
        packet_path,
        manifest_relative_path="evidence/evaluation-summary.json",
        artifact_roots=(repo,),
    )
    _init_git_repo(repo)

    result = RUNNER.invoke(app, ["ci", "gate", str(packet_path)])

    assert result.exit_code == 0, result.output


def test_ci_gate_rejects_ambiguous_inferred_roots_and_honors_explicit_root(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    packet_dir = repo / "packet-output"
    packet_path = packet_dir / "evidence-packet.json"
    _write_release_bound_packet(
        packet_path,
        manifest_relative_path="evidence/evaluation-summary.json",
        artifact_roots=(packet_dir, repo),
    )
    _init_git_repo(repo)

    ambiguous = RUNNER.invoke(app, ["ci", "gate", str(packet_path)])
    explicit = RUNNER.invoke(
        app,
        ["ci", "gate", str(packet_path), "--artifact-root", str(packet_dir)],
    )

    assert ambiguous.exit_code == 2, ambiguous.output
    assert "artifact root is ambiguous" in ambiguous.output
    assert "--artifact-root" in unstyle(ambiguous.output)
    assert explicit.exit_code == 0, explicit.output


def test_ci_command_writes_reports_packet_manifest_and_diagnostics(tmp_path: Path) -> None:
    compiled_path, baseline_path, candidate_path = _write_inputs(tmp_path)
    out_dir = tmp_path / "ci-report"

    result = RUNNER.invoke(
        app,
        [
            "ci",
            str(candidate_path),
            "--suite",
            str(compiled_path),
            "--baseline",
            str(baseline_path),
            "--out-dir",
            str(out_dir),
            "--report-mode",
            "full",
        ],
    )

    assert result.exit_code == 1, result.output
    assert (out_dir / "evaluation-report.json").exists()
    assert (out_dir / "comparison-report.json").exists()
    assert (out_dir / "evidence-packet.json").exists()
    assert (out_dir / "evidence-packet.md").exists()
    graph_path = out_dir / "assurance-evidence-graph.json"
    assert graph_path.exists()
    assert (out_dir / "release-artifact-manifest.json").exists()
    assert (out_dir / "dependency-inventory.json").exists()
    diagnostics = json.loads((out_dir / "ci-diagnostics.json").read_text(encoding="utf-8"))
    assert diagnostics["exit_code"] == 1
    assert diagnostics["outcome"] == "fail"
    assert diagnostics["reason_code"] == "MATERIAL_CLAIM_MISSING_EVIDENCE"
    assert diagnostics["artifact_path"].endswith("evidence-packet.json")
    packet = json.loads((out_dir / "evidence-packet.json").read_text(encoding="utf-8"))
    graph = json.loads(graph_path.read_text(encoding="utf-8"))
    assert packet["environment"]["dependency_inventory_digest"]
    assert "python_executable" not in packet["environment"]
    assert packet["release_manifest"]["artifacts"]
    assert packet["evidence_graph_digest"] == graph["graph_digest"]
    graph_digest = next(
        item for item in packet["artifact_digests"] if item["role"] == "assurance-evidence-graph"
    )
    graph_manifest = next(
        item
        for item in packet["release_manifest"]["artifacts"]
        if item["role"] == "assurance-evidence-graph"
    )
    assert graph_digest["sha256"] == file_sha256(graph_path)
    assert graph_manifest["sha256"] == graph_digest["sha256"]
    assert graph_manifest["path"].endswith("assurance-evidence-graph.json")
    inventory = json.loads((out_dir / "dependency-inventory.json").read_text(encoding="utf-8"))
    assert inventory["artifact_kind"] == "dependency-inventory"
    assert inventory["format"] == "agent-assure-dependency-inventory-v0.1"


def test_run_ci_trusted_gate_rejects_summary_swap_after_creation_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    compiled_path, baseline_path, _candidate_path = _write_inputs(tmp_path)
    out_dir = tmp_path / "swap-after-summary-snapshot"
    original_release_artifact = ci_module.release_artifact
    swapped = False

    def swap_summary_after_snapshot(
        role: str,
        path: Path,
        *,
        project_root: Path,
    ) -> object:
        nonlocal swapped
        artifact = original_release_artifact(role, path, project_root=project_root)
        evaluation_path = out_dir / "evaluation-summary.json"
        if role == "compiled-suite" and not swapped and evaluation_path.exists():
            swapped = True
            replacement = EvaluationSummary(
                runset_id="post-snapshot-replacement",
                privacy_profile_id=PRIVACY_PROFILE_ID,
                privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
                state=GateState.pass_,
            )
            _write_json(evaluation_path, replacement.model_dump(mode="json"))
        return artifact

    monkeypatch.setattr(ci_module, "release_artifact", swap_summary_after_snapshot)

    result = run_ci(
        baseline_path,
        suite_path=compiled_path,
        out_dir=out_dir,
    )

    assert swapped
    assert result.decision.exit_code == 2
    assert result.decision.outcome.value == "invalid"
    assert "source file digest does not match release manifest" in result.decision.message
    assert result.decision.artifact_path == ""
    assert not (out_dir / "evidence-packet.json").exists()


def test_ci_packet_publication_rolls_back_graph_and_packet_on_late_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    compiled_path, baseline_path, _candidate_path = _write_inputs(tmp_path)
    out_dir = tmp_path / "late-packet-failure"

    def fail_markdown_write(*_args: object, **_kwargs: object) -> None:
        raise OSError("injected late CI packet failure")

    monkeypatch.setattr(
        ci_module,
        "write_evidence_packet_markdown",
        fail_markdown_write,
    )

    with pytest.raises(OSError, match="injected late CI packet failure"):
        run_ci(
            baseline_path,
            suite_path=compiled_path,
            out_dir=out_dir,
        )

    for filename in (
        "assurance-evidence-graph.json",
        "release-artifact-manifest.json",
        "evidence-packet.json",
        "evidence-packet.md",
    ):
        assert not (out_dir / filename).exists()


def test_successful_full_ci_json_output_exposes_structural_decision(tmp_path: Path) -> None:
    compiled_path, baseline_path, _candidate_path = _write_inputs(tmp_path)
    out_dir = tmp_path / "passing-ci-report"

    result = RUNNER.invoke(
        app,
        [
            "ci",
            str(baseline_path),
            "--suite",
            str(compiled_path),
            "--out-dir",
            str(out_dir),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0, result.output
    decision = json.loads(result.output)
    assert decision["outcome"] == "pass"
    assert decision["exit_code"] == 0
    assert decision["artifact_kind"] == "evidence-packet"
    assert decision["artifact_path"] == str(out_dir / "evidence-packet.json")
    assert decision["reason_code"] is None


def test_ci_command_removes_outputs_that_are_stale_for_the_next_run(
    tmp_path: Path,
) -> None:
    compiled_path, baseline_path, candidate_path = _write_inputs(tmp_path)
    out_dir = tmp_path / "reused-ci-report"

    failing = RUNNER.invoke(
        app,
        [
            "ci",
            str(candidate_path),
            "--suite",
            str(compiled_path),
            "--baseline",
            str(baseline_path),
            "--out-dir",
            str(out_dir),
            "--report-mode",
            "full",
        ],
    )
    assert failing.exit_code == 1, failing.output
    assert (out_dir / "comparison-report.json").exists()
    assert (out_dir / "ci-diagnostics.json").exists()

    passing = RUNNER.invoke(
        app,
        [
            "ci",
            str(baseline_path),
            "--suite",
            str(compiled_path),
            "--out-dir",
            str(out_dir),
            "--report-mode",
            "full",
        ],
    )

    assert passing.exit_code == 0, passing.output
    for stale_name in (
        "comparison-report.json",
        "comparison-summary.json",
        "comparison-report.md",
        "ci-diagnostics.json",
    ):
        assert not (out_dir / stale_name).exists()


def test_ci_command_refuses_a_linked_output_directory_without_deleting_stale_files(
    tmp_path: Path,
) -> None:
    compiled_path, baseline_path, _candidate_path = _write_inputs(tmp_path)
    real_out = tmp_path / "real-output"
    linked_out = tmp_path / "linked-output"
    real_out.mkdir()
    stale_diagnostics = real_out / "ci-diagnostics.json"
    stale_diagnostics.write_text("keep\n", encoding="utf-8")
    try:
        linked_out.symlink_to(real_out, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlinks unavailable: {exc}")

    result = RUNNER.invoke(
        app,
        [
            "ci",
            str(baseline_path),
            "--suite",
            str(compiled_path),
            "--out-dir",
            str(linked_out),
        ],
    )

    assert result.exit_code == 2, result.output
    assert stale_diagnostics.read_text(encoding="utf-8") == "keep\n"


def test_ci_command_refuses_an_input_at_an_owned_output_path(
    tmp_path: Path,
) -> None:
    compiled_path, baseline_path, _candidate_path = _write_inputs(tmp_path)
    out_dir = tmp_path / "aliased-ci-report"
    out_dir.mkdir()
    aliased_candidate = out_dir / "evaluation-report.json"
    aliased_candidate.write_bytes(baseline_path.read_bytes())
    original_digest = file_sha256(aliased_candidate)

    result = RUNNER.invoke(
        app,
        [
            "ci",
            str(aliased_candidate),
            "--suite",
            str(compiled_path),
            "--out-dir",
            str(out_dir),
        ],
    )

    assert result.exit_code == 2, result.output
    assert file_sha256(aliased_candidate) == original_digest


def test_ci_command_refuses_a_waiver_at_an_owned_output_path(
    tmp_path: Path,
) -> None:
    compiled_path, baseline_path, _candidate_path = _write_inputs(tmp_path)
    out_dir = tmp_path / "aliased-ci-waiver"
    out_dir.mkdir()
    aliased_waiver = out_dir / "ci-diagnostics.json"
    aliased_waiver.write_text("[]\n", encoding="utf-8")

    result = RUNNER.invoke(
        app,
        [
            "ci",
            str(baseline_path),
            "--suite",
            str(compiled_path),
            "--out-dir",
            str(out_dir),
            "--waiver",
            str(aliased_waiver),
        ],
    )

    assert result.exit_code == 2, result.output
    assert aliased_waiver.read_text(encoding="utf-8") == "[]\n"


@pytest.mark.parametrize(
    "env_var",
    (
        "AGENT_ASSURE_DEMO_EXPECTED_FAILURE",
        "AGENT_ASSURE_DEMO_NETWORK_DISABLED",
    ),
)
def test_demo_markers_do_not_affect_core_commands(tmp_path: Path, env_var: str) -> None:
    compiled_path, baseline_path, candidate_path = _write_inputs(tmp_path)
    env = {env_var: "1"}
    slug = env_var.lower()

    evaluate = RUNNER.invoke(
        app,
        [
            "evaluate",
            str(candidate_path),
            "--suite",
            str(compiled_path),
            "--out-dir",
            str(tmp_path / f"evaluate-report-{slug}"),
        ],
        env=env,
    )
    compare = RUNNER.invoke(
        app,
        [
            "compare",
            str(baseline_path),
            str(candidate_path),
            "--suite",
            str(compiled_path),
            "--out-dir",
            str(tmp_path / f"compare-report-{slug}"),
        ],
        env=env,
    )
    ci = RUNNER.invoke(
        app,
        [
            "ci",
            str(candidate_path),
            "--suite",
            str(compiled_path),
            "--baseline",
            str(baseline_path),
            "--out-dir",
            str(tmp_path / f"ci-report-with-demo-env-{slug}"),
            "--report-mode",
            "full",
        ],
        env=env,
    )
    failing_summary = tmp_path / f"failing-summary-{slug}.json"
    _write_json(
        failing_summary,
        EvaluationSummary(
            artifact_kind="evaluation-summary",
            runset_id="candidate",
            privacy_profile_id=PRIVACY_PROFILE_ID,
            privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
            state=GateState.fail,
        ).model_dump(mode="json"),
    )
    gate = RUNNER.invoke(app, ["ci", "gate", str(failing_summary)], env=env)

    assert evaluate.exit_code == 1, evaluate.output
    assert compare.exit_code == 1, compare.output
    assert ci.exit_code == 1, ci.output
    assert gate.exit_code == 1, gate.output


def test_core_commands_accept_out_dir_outside_cwd(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    compiled_path, baseline_path, candidate_path = _write_inputs(workspace)
    lockfile = workspace / "requirements.lock"
    lockfile.write_text("agent-assure-test-lock\n", encoding="utf-8")
    _init_git_repo(workspace)
    out_root = tmp_path / "external-output"

    evaluate_out = out_root / "evaluate"
    evaluate = RUNNER.invoke(
        app,
        [
            "evaluate",
            str(baseline_path),
            "--suite",
            str(compiled_path),
            "--out-dir",
            str(evaluate_out),
        ],
    )

    compare_out = out_root / "compare"
    compare = RUNNER.invoke(
        app,
        [
            "compare",
            str(baseline_path),
            str(candidate_path),
            "--suite",
            str(compiled_path),
            "--out-dir",
            str(compare_out),
        ],
    )

    ci_out = out_root / "ci"
    ci = RUNNER.invoke(
        app,
        [
            "ci",
            str(candidate_path),
            "--suite",
            str(compiled_path),
            "--baseline",
            str(baseline_path),
            "--out-dir",
            str(ci_out),
            "--report-mode",
            "full",
        ],
    )

    packet_summary = workspace / "evaluation-summary.json"
    packet_comparison = workspace / "comparison-summary.json"
    candidate_digest = "c" * 64
    _write_json(
        packet_summary,
        EvaluationSummary(
            artifact_kind="evaluation-summary",
            runset_id="candidate",
            runset_digest=candidate_digest,
            privacy_profile_id=PRIVACY_PROFILE_ID,
            privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
            state=GateState.pass_,
        ).model_dump(mode="json"),
    )
    _write_json(
        packet_comparison,
        ComparisonSummary(
            artifact_kind="comparison-summary",
            baseline_runset_id="baseline",
            candidate_runset_id="candidate",
            baseline_runset_digest="b" * 64,
            candidate_runset_digest=candidate_digest,
            privacy_profile_id=PRIVACY_PROFILE_ID,
            privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
            classification=ComparisonClassification.provenance_only_change,
            fixture_equivalence_state=GateState.pass_,
        ).model_dump(mode="json"),
    )
    packet_out = out_root / "packet" / "evidence-packet.json"
    packet = RUNNER.invoke(
        app,
        [
            "packet",
            "build",
            str(packet_summary),
            "--comparison",
            str(packet_comparison),
            "--out",
            str(packet_out),
        ],
    )

    assert evaluate.exit_code == 0, evaluate.output
    assert compare.exit_code == 1, compare.output
    assert ci.exit_code == 1, ci.output
    assert packet.exit_code == 0, packet.output
    for command_out in (evaluate_out, compare_out, ci_out, packet_out.parent):
        assert (command_out / "release-artifact-manifest.json").exists()
        manifest = json.loads(
            (command_out / "release-artifact-manifest.json").read_text(encoding="utf-8")
        )
        environment = manifest["environment"]
        assert environment["git_commit"]
        assert environment["lockfile_path"] == "requirements.lock"
        assert environment["lockfile_digest"] == file_sha256(lockfile)
        assert not Path(environment["dependency_inventory_path"]).is_absolute()
        assert all(not Path(artifact["path"]).is_absolute() for artifact in manifest["artifacts"])


def test_ci_fail_fast_stops_before_comparison_after_candidate_blocker(tmp_path: Path) -> None:
    compiled_path, baseline_path, candidate_path = _write_inputs(tmp_path)
    out_dir = tmp_path / "ci-report"

    result = RUNNER.invoke(
        app,
        [
            "ci",
            str(candidate_path),
            "--suite",
            str(compiled_path),
            "--baseline",
            str(baseline_path),
            "--out-dir",
            str(out_dir),
            "--report-mode",
            "fail-fast",
        ],
    )

    assert result.exit_code == 1, result.output
    assert (out_dir / "evaluation-summary.json").exists()
    assert not (out_dir / "comparison-summary.json").exists()
    summary = json.loads((out_dir / "evaluation-summary.json").read_text(encoding="utf-8"))
    assert len(summary["findings"]) == 1
    report = json.loads((out_dir / "evaluation-report.json").read_text(encoding="utf-8"))
    assert report["metrics"]["blocking_findings"] >= 1
    assert report["metrics"]["findings_by_reason"]["MATERIAL_CLAIM_MISSING_EVIDENCE"] == 1


def _legacy_unbound_comparison_packet() -> EvidencePacket:
    evaluation = EvaluationSummary(
        schema_version="0.6.3",
        runset_id="same-display-id",
        runset_digest="d" * 64,
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.pass_,
    )
    comparison = ComparisonSummary(
        schema_version="0.6.3",
        baseline_runset_id="baseline",
        candidate_runset_id=evaluation.runset_id,
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        classification=ComparisonClassification.unchanged,
        fixture_equivalence_state=GateState.pass_,
        candidate_state=GateState.pass_,
    )
    return EvidencePacket(
        schema_version="0.6.3",
        packet_id="legacy-id-only-comparison",
        interpretation=("legacy compatibility regression",),
        evaluation=evaluation,
        comparison=comparison,
        artifact_digests=(
            PacketArtifactDigest(
                schema_version="0.6.3",
                role="evaluation-summary",
                sha256="e" * 64,
            ),
            PacketArtifactDigest(
                schema_version="0.6.3",
                role="comparison-summary",
                sha256="f" * 64,
            ),
        ),
        limitations=("legacy comparison omits authenticated RunSet digests",),
    )


def _write_release_bound_packet(
    packet_path: Path,
    *,
    manifest_relative_path: str,
    artifact_roots: tuple[Path, ...],
) -> None:
    evaluation = EvaluationSummary(
        runset_id="root-inference-candidate",
        runset_digest="c" * 64,
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.pass_,
    )
    for artifact_root in artifact_roots:
        evaluation_path = artifact_root / Path(manifest_relative_path)
        evaluation_path.parent.mkdir(parents=True, exist_ok=True)
        _write_json(evaluation_path, evaluation.model_dump(mode="json"))
    evaluation_digest = file_sha256(artifact_roots[0] / Path(manifest_relative_path))
    manifest = ReleaseArtifactManifest(
        manifest_id="artifact-root-inference",
        artifacts=(
            ReleaseArtifact(
                role="evaluation-summary",
                path=manifest_relative_path,
                sha256=evaluation_digest,
            ),
        ),
        environment=EnvironmentInfo(platform="test", python_version="3.14"),
    )
    packet = EvidencePacket(
        packet_id="artifact-root-inference-packet",
        interpretation=("artifact root inference regression",),
        evaluation=evaluation,
        release_manifest=manifest,
        artifact_digests=(
            PacketArtifactDigest(
                role="evaluation-summary",
                sha256=evaluation_digest,
            ),
        ),
        limitations=("test fixture",),
    )
    packet_path.parent.mkdir(parents=True, exist_ok=True)
    _write_json(packet_path, packet.model_dump(mode="json"))


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8", newline="\n")


def _write_inputs(tmp_path: Path) -> tuple[Path, Path, Path]:
    compiled = compile_suite(SUITE)
    baseline = run_suite(compiled, load_variant_config(BASELINE), SUITE.parent)
    candidate = run_suite(compiled, load_variant_config(EVIDENCE_CANDIDATE), SUITE.parent)
    compiled_path = tmp_path / "suite.compiled.json"
    baseline_path = tmp_path / "baseline.json"
    candidate_path = tmp_path / "candidate.json"
    write_compiled_suite(compiled, compiled_path)
    write_runset(baseline, baseline_path)
    write_runset(candidate, candidate_path)
    return compiled_path, baseline_path, candidate_path


def _init_git_repo(path: Path) -> None:
    commands = (
        ("init",),
        ("config", "user.email", "agent-assure@example.test"),
        ("config", "user.name", "Agent Assure Tests"),
        ("add", "."),
        ("commit", "-m", "test provenance root"),
    )
    for command in commands:
        try:
            subprocess.run(
                ("git", *command),
                cwd=path,
                check=True,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError:
            pytest.skip("git is not available")
