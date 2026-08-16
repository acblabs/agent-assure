from __future__ import annotations

import socket
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import date
from pathlib import Path
from typing import Any, NoReturn, cast
from unittest.mock import patch

from agent_assure.artifact_io import file_sha256, write_text_atomic
from agent_assure.controls.efficacy import (
    build_control_efficacy_report,
    evaluate_control_efficacy_gate,
)
from agent_assure.demo.common import (
    DemoError,
    ExpectedCommandResult,
    artifact_path,
    copy_example_resource,
    prepare_output_dir,
    run_cli_command,
    write_json,
)
from agent_assure.evaluation.evaluator import EvaluationReport, evaluate_runset
from agent_assure.fixtures.loader import load_compiled_suite
from agent_assure.io_limits import load_json_bounded
from agent_assure.mutation.campaign import execute_mutation_campaign
from agent_assure.mutation.catalog import resolve_operator
from agent_assure.mutation.detection import DetectionAssessment, assess_expected_detection
from agent_assure.mutation.paths import apply_payload_changes
from agent_assure.mutation.selection import select_target
from agent_assure.policies.base import GateProfile
from agent_assure.reporting.campaign import (
    validate_mutation_campaign_artifact_generation,
    write_mutation_campaign_artifacts,
)
from agent_assure.reporting.efficacy import (
    render_control_efficacy_markdown,
    write_control_efficacy_report,
)
from agent_assure.reporting.environment import (
    build_release_manifest,
    release_artifact,
    write_release_manifest,
)
from agent_assure.reporting.graph import write_evidence_graph
from agent_assure.reporting.packet import (
    DEFAULT_PACKET_LIMITATIONS,
    build_evidence_packet,
    build_privacy_filtered_evidence_graph,
    load_evaluation_summary,
    load_evidence_packet,
    packet_artifact_digest,
    packet_summary_files_binding_error,
    write_evidence_packet,
)
from agent_assure.schema.common import GateState, ReasonCode, Severity
from agent_assure.schema.efficacy import (
    ControlEfficacyGateProfile,
    ThreatApplicability,
    ThreatApplicabilityItem,
    ThreatApplicabilityManifest,
    ThreatSourceIdentity,
)
from agent_assure.schema.environment import EnvironmentInfo
from agent_assure.schema.evaluation import Finding
from agent_assure.schema.mutation import MutationResultState
from agent_assure.schema.packet import EvidencePacket
from agent_assure.schema.run import RunSet

_OPERATOR_ID = "drop-material-evidence-link"
_GENERATED_AT = "2026-08-08T00:00:00Z"
_EVALUATION_DATE = date(2026, 8, 8)


def run_assure_the_assurance_demo(
    out_dir: Path,
    *,
    clean: bool,
) -> dict[str, object]:
    """Run a deterministic detector-of-detectors demonstration entirely offline."""
    with _offline_network_guard():
        return _run_assure_the_assurance_demo(out_dir, clean=clean)


def _run_assure_the_assurance_demo(
    out_dir: Path,
    *,
    clean: bool,
) -> dict[str, object]:
    root = prepare_output_dir(out_dir, clean=clean)
    _remove_stale_success_summary(root)
    example_dir = copy_example_resource(
        "prior_auth_synthetic",
        root / "example" / "prior_auth_synthetic",
        owner_root=root,
    )
    compiled_path = root / "prior-auth.compiled.json"
    fixture_manifest_path = root / "prior-auth.fixture-manifest.json"
    baseline_runset_path = root / "baseline.runset.json"
    baseline_report_dir = root / "baseline-report"
    mutation_root = root / "mutation-results"
    strong_dir = mutation_root / "strong-control"
    weakened_dir = mutation_root / "weakened-control"

    commands = _run_baseline_commands(
        root=root,
        example_dir=example_dir,
        compiled_path=compiled_path,
        fixture_manifest_path=fixture_manifest_path,
        baseline_runset_path=baseline_runset_path,
        baseline_report_dir=baseline_report_dir,
    )
    suite = load_compiled_suite(compiled_path)
    source_payload = load_json_bounded(
        baseline_runset_path,
        label="assure-the-assurance baseline RunSet",
    )
    runset = RunSet.model_validate(source_payload)
    baseline_summary = load_evaluation_summary(baseline_report_dir / "evaluation-summary.json")
    strong = execute_mutation_campaign(
        suite,
        source_payload,
        seed=0,
        generated_at=_GENERATED_AT,
        operator_ids=(_OPERATOR_ID,),
        evaluation_date=_EVALUATION_DATE,
    )
    weakened_profile = GateProfile(
        profile_id="demo-deliberately-weakened",
        fail_severities=(Severity.info,),
    )
    weakened = execute_mutation_campaign(
        suite,
        source_payload,
        seed=0,
        generated_at=_GENERATED_AT,
        operator_ids=(_OPERATOR_ID,),
        gate_profile=weakened_profile,
        evaluation_date=_EVALUATION_DATE,
    )
    source_inputs = (compiled_path, baseline_runset_path)
    strong_paths = write_mutation_campaign_artifacts(
        strong,
        strong_dir,
        source_inputs=source_inputs,
    )
    weakened_paths = write_mutation_campaign_artifacts(
        weakened,
        weakened_dir,
        source_inputs=source_inputs,
    )
    _validate_campaign_generation(strong_dir, label="strong-control")
    _validate_campaign_generation(weakened_dir, label="weakened-control")

    threat_manifest = _threat_manifest()
    efficacy = build_control_efficacy_report(
        weakened.campaign,
        weakened.catalog,
        threat_manifest,
        required_operator_ids=(_OPERATOR_ID,),
    )
    gate_profile = ControlEfficacyGateProfile(
        required_catalog="core/v1",
        required_operators=(_OPERATOR_ID,),
    )
    gate_decision = evaluate_control_efficacy_gate(efficacy, gate_profile)
    efficacy_config_path = write_json(
        root / "control-efficacy-config.json",
        cast(dict[str, object], gate_profile.model_dump(mode="json")),
    )
    efficacy_paths = write_control_efficacy_report(
        efficacy,
        root,
        gate_decision=gate_decision,
        gate_profile=gate_profile,
    )
    packet_limitations = DEFAULT_PACKET_LIMITATIONS
    packet_evidence_graph = build_privacy_filtered_evidence_graph(
        baseline_summary,
        control_efficacy=efficacy,
        control_efficacy_gate_profile=gate_profile,
        control_efficacy_gate=gate_decision,
        limitations=packet_limitations,
    )
    evidence_graph_path = root / "assurance-evidence-graph.json"
    write_evidence_graph(packet_evidence_graph, evidence_graph_path)
    mutation_evidence_graph = build_privacy_filtered_evidence_graph(
        baseline_summary,
        mutation_results=(
            strong.campaign.operator_results[0].result,
            weakened.campaign.operator_results[0].result,
        ),
        control_efficacy=efficacy,
        control_efficacy_gate_profile=gate_profile,
        control_efficacy_gate=gate_decision,
        limitations=packet_limitations,
    )
    mutation_evidence_graph_path = root / "mutation-evidence-graph.json"
    write_evidence_graph(
        mutation_evidence_graph,
        mutation_evidence_graph_path,
    )

    unrelated = _unrelated_failure_probes(
        suite=suite,
        runset=runset,
        source_payload=source_payload,
        source_digest=strong.campaign.source_digest,
    )
    reviewer_path = root / "reviewer-facing-report.md"
    write_text_atomic(
        reviewer_path,
        render_control_efficacy_markdown(
            efficacy,
            gate_decision=gate_decision,
            gate_profile=gate_profile,
        )
        + (
            "\n## Unrelated-Failure Rejection\n\n"
            "- Three synthetic blocking findings were presented to the normative "
            "detector matcher, changing only target, control, or reason in turn.\n"
            "- Detection state: "
            f"`{_combined_probe_state(unrelated)}`.\n"
            "- Matched normative finding count: "
            f"`{sum(len(item.matched_finding_ids) for item in unrelated.values())}`.\n"
            "- Result: the unrelated failure did not count as a kill.\n"
            "\n## Assurance Evidence Graph\n\n"
            f"- Packet-bound graph digest: {packet_evidence_graph.graph_digest}.\n"
            "- Mutation-enriched graph digest: "
            f"{mutation_evidence_graph.graph_digest}.\n"
            "- Mutation-enriched nodes / edges: "
            f"{len(mutation_evidence_graph.nodes)} / "
            f"{len(mutation_evidence_graph.edges)}.\n"
            "- Contradictions and limitations remain first-class findings.\n"
        ),
    )

    evaluation_summary_path = baseline_report_dir / "evaluation-summary.json"
    manifest_environment = baseline_summary.environment or EnvironmentInfo(
        platform="not-recorded",
        python_version="not-recorded",
    )
    release_manifest = build_release_manifest(
        (
            release_artifact(
                "evaluation-summary",
                evaluation_summary_path,
                project_root=root,
            ),
            release_artifact(
                "control-efficacy-report",
                efficacy_paths.report,
                project_root=root,
            ),
            release_artifact(
                "control-efficacy-gate-profile",
                efficacy_config_path,
                project_root=root,
            ),
            release_artifact(
                "assurance-evidence-graph",
                evidence_graph_path,
                project_root=root,
            ),
        ),
        environment=manifest_environment,
    )
    release_manifest_path = root / "release-artifact-manifest.json"
    write_release_manifest(release_manifest, release_manifest_path)
    packet = build_evidence_packet(
        baseline_summary,
        control_efficacy=efficacy,
        control_efficacy_gate_profile=gate_profile,
        control_efficacy_gate=gate_decision,
        environment=manifest_environment,
        release_manifest=release_manifest,
        artifact_digests=(
            packet_artifact_digest("evaluation-summary", evaluation_summary_path),
            packet_artifact_digest(
                "control-efficacy-report",
                efficacy_paths.report,
            ),
            packet_artifact_digest(
                "control-efficacy-gate-profile",
                efficacy_config_path,
            ),
            packet_artifact_digest(
                "assurance-evidence-graph",
                evidence_graph_path,
            ),
        ),
        evidence_graph_digest=packet_evidence_graph.graph_digest,
        limitations=packet_limitations,
    )
    packet_path = root / "evidence-packet.json"
    write_evidence_packet(packet, packet_path)
    persisted_packet = load_evidence_packet(packet_path)
    binding_error = packet_summary_files_binding_error(
        persisted_packet,
        artifact_root=root,
    )
    if binding_error is not None or persisted_packet != packet:
        raise DemoError(
            "persisted demo packet did not verify against its exact evidence graph binding"
        )
    packet = persisted_packet
    commands.append(
        run_cli_command(
            name="ci-gate-efficacy-packet",
            args=[
                "ci",
                "gate",
                str(packet_path),
                "--efficacy-policy",
                str(efficacy_config_path),
                "--allow-advisory-efficacy",
            ],
            out_dir=root,
            expected_exit_codes={1},
            cwd=root,
        )
    )

    summary = _build_summary(
        root=root,
        baseline_summary_state=baseline_summary.state,
        strong_state=strong.campaign.operator_results[0].result.state,
        weakened_state=weakened.campaign.operator_results[0].result.state,
        efficacy_report_path=efficacy_paths.report,
        efficacy_config_path=efficacy_config_path,
        evidence_graph_path=evidence_graph_path,
        evidence_graph_digest=packet_evidence_graph.graph_digest,
        mutation_evidence_graph_path=mutation_evidence_graph_path,
        mutation_evidence_graph_digest=mutation_evidence_graph.graph_digest,
        packet_path=packet_path,
        release_manifest_path=release_manifest_path,
        reviewer_path=reviewer_path,
        strong_manifest_path=strong_paths.generation_manifest,
        weakened_manifest_path=weakened_paths.generation_manifest,
        gate_state=gate_decision.state,
        required_survivors=efficacy.required_survivor_count,
        critical_survivors=efficacy.critical_survivor_count,
        unrelated=unrelated,
        packet=packet,
        commands=tuple(commands),
    )
    _assert_success(summary)
    write_json(root / "demo-summary.json", summary)
    return summary


def _remove_stale_success_summary(root: Path) -> None:
    """Remove the prior success signal before a no-clean rerun can fail."""
    summary_path = root / "demo-summary.json"
    if summary_path.is_symlink():
        summary_path.unlink()
        return
    if not summary_path.exists():
        return
    if not summary_path.is_file():
        raise DemoError("demo summary path exists and is not a regular file")
    summary_path.unlink()


def _validate_campaign_generation(path: Path, *, label: str) -> None:
    try:
        validate_mutation_campaign_artifact_generation(path)
    except (OSError, ValueError) as exc:
        raise DemoError(f"{label} mutation artifact generation is incomplete or invalid") from exc


def _network_blocked(*_args: object, **_kwargs: object) -> NoReturn:
    raise DemoError("network access is disabled for the assure-the-assurance demo")


class _OfflineSocket(socket.socket):
    def connect(self, address: object) -> NoReturn:
        _network_blocked(address)

    def connect_ex(self, address: object) -> NoReturn:
        _network_blocked(address)

    def bind(self, address: object) -> NoReturn:
        _network_blocked(address)

    def listen(self, backlog: int = 0) -> NoReturn:
        _network_blocked(backlog)

    def accept(self) -> NoReturn:
        _network_blocked()

    def send(self, *args: Any, **kwargs: Any) -> NoReturn:
        _network_blocked(*args, **kwargs)

    def sendall(self, *args: Any, **kwargs: Any) -> NoReturn:
        _network_blocked(*args, **kwargs)

    def sendto(self, *args: Any, **kwargs: Any) -> NoReturn:
        _network_blocked(*args, **kwargs)

    if hasattr(socket.socket, "sendmsg"):

        def sendmsg(self, *args: Any, **kwargs: Any) -> NoReturn:
            _network_blocked(*args, **kwargs)


@contextmanager
def _offline_network_guard() -> Iterator[None]:
    """Block outbound network primitives for the parent demo process as well."""
    with (
        patch.object(socket, "create_connection", _network_blocked),
        patch.object(socket, "create_server", _network_blocked),
        patch.object(socket, "getaddrinfo", _network_blocked),
        patch.object(socket, "gethostbyname", _network_blocked),
        patch.object(socket, "gethostbyname_ex", _network_blocked),
        patch.object(socket, "gethostbyaddr", _network_blocked),
        patch.object(socket, "getnameinfo", _network_blocked),
        patch.object(socket, "socket", _OfflineSocket),
    ):
        yield


def render_assure_the_assurance_text(summary: dict[str, object]) -> str:
    artifacts = cast(dict[str, str], summary["artifacts"])
    return "\n".join(
        (
            "agent-assure: who assures the assurance?",
            "",
            f"  ordinary baseline: {summary['ordinary_baseline_state']}",
            f"  strong control mutation: {summary['strong_mutation_state']}",
            f"  weakened control mutation: {summary['weakened_mutation_state']}",
            f"  efficacy gate: {summary['control_efficacy_gate_state']}",
            (
                "  required / critical survivors: "
                f"{summary['required_survivor_count']} / "
                f"{summary['critical_survivor_count']}"
            ),
            (
                "  unrelated failure counted as detection: "
                f"{summary['unrelated_failure_counted_as_detection']}"
            ),
            "",
            "Artifacts:",
            f"  {artifacts['mutation_results']}",
            f"  {artifacts['control_efficacy_report']}",
            f"  {artifacts['control_efficacy_config']}",
            f"  {artifacts['assurance_evidence_graph']}",
            f"  {artifacts['mutation_evidence_graph']}",
            f"  {artifacts['evidence_packet']}",
            f"  {artifacts['reviewer_facing_report']}",
            f"  {artifacts['summary']}",
            "",
            "Demo result: success; the weakened required control is blocked.",
        )
    )


def _run_baseline_commands(
    *,
    root: Path,
    example_dir: Path,
    compiled_path: Path,
    fixture_manifest_path: Path,
    baseline_runset_path: Path,
    baseline_report_dir: Path,
) -> list[ExpectedCommandResult]:
    suite_yaml = example_dir / "suite.yaml"
    baseline_variant = example_dir / "variants" / "baseline.yaml"
    return [
        run_cli_command(
            name="compile-suite",
            args=[
                "suite",
                "compile",
                str(suite_yaml),
                "--out",
                str(compiled_path),
                "--manifest",
                str(fixture_manifest_path),
            ],
            out_dir=root,
            expected_exit_codes={0},
            cwd=root,
        ),
        run_cli_command(
            name="run-baseline",
            args=[
                "suite",
                "run",
                str(compiled_path),
                "--variant",
                str(baseline_variant),
                "--manifest",
                str(fixture_manifest_path),
                "--out",
                str(baseline_runset_path),
            ],
            out_dir=root,
            expected_exit_codes={0},
            cwd=root,
        ),
        run_cli_command(
            name="evaluate-baseline",
            args=[
                "evaluate",
                str(baseline_runset_path),
                "--suite",
                str(compiled_path),
                "--out-dir",
                str(baseline_report_dir),
            ],
            out_dir=root,
            expected_exit_codes={0},
            cwd=root,
        ),
    ]


def _threat_manifest() -> ThreatApplicabilityManifest:
    return ThreatApplicabilityManifest.build(
        threat_source=ThreatSourceIdentity(
            name="mitre-atlas",
            version="2026.06",
        ),
        present_control_ids=("material_claims_have_evidence",),
        items=(
            ThreatApplicabilityItem(
                threat_id="AML.T0067.000",
                applicability=ThreatApplicability.applicable,
                critical=True,
                rationale="Synthetic evidence-link challenge is in demo scope.",
                owner="agent-assure-demo",
                reviewed_at="2026-08-08",
            ),
            ThreatApplicabilityItem(
                threat_id="material-claim-link-regression",
                applicability=ThreatApplicability.applicable,
                critical=False,
                rationale="The selected operator's project-local regression is in demo scope.",
                owner="agent-assure-demo",
                reviewed_at="2026-08-08",
            ),
        ),
        limitations=("This synthetic demo declares two applicable threat references.",),
    )


def _unrelated_failure_probes(
    *,
    suite: Any,
    runset: RunSet,
    source_payload: dict[str, object],
    source_digest: str,
) -> dict[str, DetectionAssessment]:
    operator = resolve_operator(_OPERATOR_ID)
    if operator is None:
        raise DemoError(f"bundled operator is missing: {_OPERATOR_ID}")
    targets = operator.resolve_targets(suite, runset, dict(source_payload))
    target = select_target(
        targets,
        source_digest=source_digest,
        operator_id=operator.descriptor.operator_id,
        operator_version=operator.descriptor.operator_version,
        seed=0,
    )
    if target is None:
        raise DemoError("bundled demo mutation has no applicable target")
    target = target.materialized(source_payload)
    source_report = evaluate_runset(suite, runset)
    candidate_payload = apply_payload_changes(source_payload, target.changes)
    candidate_report = evaluate_runset(suite, RunSet.model_validate(candidate_payload))
    contract = operator.descriptor.expected_detection_contract
    exact = assess_expected_detection(
        source_report,
        candidate_report,
        contract,
        expected_target=target.expected_finding_target,
    )
    if exact.state != MutationResultState.caught.value or len(exact.matched_finding_ids) != 1:
        raise DemoError("bundled demo detector did not establish its exact positive control")
    matched_id = exact.matched_finding_ids[0]
    matched = next(
        finding
        for finding in candidate_report.candidate_vs_expectations.findings
        if finding.finding_id == matched_id
    )
    variants = {
        "target_mismatch": matched.model_copy(update={"target": f"{matched.target}-unrelated"}),
        "control_mismatch": matched.model_copy(update={"control_id": "expected_recommendation"}),
        "reason_mismatch": matched.model_copy(
            update={"reason_code": ReasonCode.EXPECTED_OUTCOME_MISMATCH}
        ),
    }
    assessments = {
        dimension: assess_expected_detection(
            source_report,
            _replace_report_finding(candidate_report, matched_id, finding),
            contract,
            expected_target=target.expected_finding_target,
        )
        for dimension, finding in variants.items()
    }
    if any(
        assessment.state != MutationResultState.survived.value or assessment.matched_finding_ids
        for assessment in assessments.values()
    ):
        raise DemoError("unrelated-failure matcher isolation probe was not rejected")
    return assessments


def _replace_report_finding(
    report: EvaluationReport,
    finding_id: str,
    replacement: Finding,
) -> EvaluationReport:
    def replace(findings: tuple[Finding, ...]) -> tuple[Finding, ...]:
        return tuple(
            replacement if finding.finding_id == finding_id else finding for finding in findings
        )

    summary = report.candidate_vs_expectations.model_copy(
        update={"findings": replace(report.candidate_vs_expectations.findings)}
    )
    return report.model_copy(
        update={
            "candidate_vs_expectations": summary,
            "failed_controls": replace(report.failed_controls),
            "warning_controls": replace(report.warning_controls),
        }
    )


def _combined_probe_state(probes: dict[str, DetectionAssessment]) -> str:
    states = {assessment.state for assessment in probes.values()}
    if states == {MutationResultState.survived.value}:
        return MutationResultState.survived.value
    return ",".join(sorted(states))


def _build_summary(
    *,
    root: Path,
    baseline_summary_state: GateState,
    strong_state: MutationResultState,
    weakened_state: MutationResultState,
    efficacy_report_path: Path,
    efficacy_config_path: Path,
    evidence_graph_path: Path,
    evidence_graph_digest: str,
    mutation_evidence_graph_path: Path,
    mutation_evidence_graph_digest: str,
    packet_path: Path,
    release_manifest_path: Path,
    reviewer_path: Path,
    strong_manifest_path: Path,
    weakened_manifest_path: Path,
    gate_state: GateState,
    required_survivors: int,
    critical_survivors: int,
    unrelated: dict[str, DetectionAssessment],
    packet: EvidencePacket,
    commands: tuple[ExpectedCommandResult, ...],
) -> dict[str, object]:
    artifact_paths = {
        "control_efficacy_report": efficacy_report_path,
        "control_efficacy_config": efficacy_config_path,
        "assurance_evidence_graph": evidence_graph_path,
        "mutation_evidence_graph": mutation_evidence_graph_path,
        "evidence_packet": packet_path,
        "release_artifact_manifest": release_manifest_path,
        "reviewer_facing_report": reviewer_path,
        "strong_campaign_generation": strong_manifest_path,
        "weakened_campaign_generation": weakened_manifest_path,
    }
    return {
        "demo": "assure-the-assurance",
        "status": "success",
        "underlying_exit_code": 1,
        "ordinary_baseline_state": baseline_summary_state.value,
        "strong_mutation_state": strong_state.value,
        "weakened_mutation_state": weakened_state.value,
        "control_efficacy_gate_state": gate_state.value,
        "required_survivor_count": required_survivors,
        "critical_survivor_count": critical_survivors,
        "unrelated_failure_counted_as_detection": any(
            assessment.matched_finding_ids for assessment in unrelated.values()
        ),
        "unrelated_failure_detector_state": _combined_probe_state(unrelated),
        "unrelated_failure_probes": {
            dimension: {
                "detector_state": assessment.state,
                "matched_finding_count": len(assessment.matched_finding_ids),
            }
            for dimension, assessment in unrelated.items()
        },
        "packet_id": packet.packet_id,
        "evidence_graph_digest": evidence_graph_digest,
        "mutation_evidence_graph_digest": mutation_evidence_graph_digest,
        "artifacts": {
            "summary": artifact_path(root / "demo-summary.json", root=root),
            "mutation_results": artifact_path(root / "mutation-results", root=root),
            **{name: artifact_path(path, root=root) for name, path in artifact_paths.items()},
        },
        "artifact_sha256": {name: file_sha256(path) for name, path in artifact_paths.items()},
        "commands": [command.model_dump(root=root) for command in commands],
    }


def _assert_success(summary: dict[str, object]) -> None:
    expected = {
        "ordinary_baseline_state": GateState.pass_.value,
        "strong_mutation_state": MutationResultState.caught.value,
        "weakened_mutation_state": MutationResultState.survived.value,
        "control_efficacy_gate_state": GateState.fail.value,
        "required_survivor_count": 1,
        "critical_survivor_count": 1,
        "unrelated_failure_counted_as_detection": False,
        "unrelated_failure_detector_state": MutationResultState.survived.value,
    }
    mismatches = {
        key: (summary.get(key), value)
        for key, value in expected.items()
        if summary.get(key) != value
    }
    commands = cast(list[dict[str, object]], summary["commands"])
    if mismatches or not all(command.get("matched") is True for command in commands):
        raise DemoError("assure-the-assurance demo did not establish its expected facts")
