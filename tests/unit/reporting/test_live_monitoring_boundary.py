from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

import agent_assure.reporting.live as live_reporting
from agent_assure.authoring.compiler import compile_suite
from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.fixtures.loader import compiled_suite_digest
from agent_assure.live.comparison import compare_live_reports
from agent_assure.live.drift import build_live_drift_report
from agent_assure.live.statistics import evaluate_live_runset
from agent_assure.live.trajectory import build_live_trajectory_report
from agent_assure.reporting.live import (
    render_live_comparison_markdown,
    render_live_drift_markdown,
    render_live_evaluation_markdown,
    render_live_trajectory_markdown,
    write_live_comparison_json,
    write_live_comparison_markdown,
    write_live_drift_json,
    write_live_drift_markdown,
    write_live_evaluation_json,
    write_live_evaluation_markdown,
    write_live_trajectory_json,
    write_live_trajectory_markdown,
)
from agent_assure.schema.common import ExecutionMode, GateState
from agent_assure.schema.live import (
    LiveComparisonReport,
    LiveDriftReport,
    LiveEvaluationReport,
    LiveTrajectoryReport,
)
from tests.unit.evaluation.test_live_statistics import (
    SUITE,
    RunSet,
    _drift_plan,
    _protocol,
    _record,
)
from tests.unit.schema.test_legacy_live_validation import (
    _v065_drift_and_trajectory_payloads,
    _valid_historical_comparison,
    _valid_historical_evaluation,
)


@pytest.fixture(scope="module")
def current_monitoring_reports() -> tuple[LiveDriftReport, LiveTrajectoryReport]:
    compiled = compile_suite(SUITE)
    protocol = _protocol(
        compiled,
        observations=2,
        clusters=1,
        repetitions=2,
        drift_monitoring_plan=_drift_plan(minimum_windows=3),
    )
    protocol_digest = sha256_hexdigest(protocol)
    runset = RunSet(
        artifact_kind="run-set",
        runset_id="runset-reporting-boundary",
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=compiled_suite_digest(compiled),
        fixture_manifest_digest="4" * 64,
        execution_mode=ExecutionMode.live,
        protocol_id=protocol.protocol_id,
        protocol_digest=protocol_digest,
        runs=(
            _record(
                repetition_index=0,
                linked=True,
                started_at_utc="2026-06-27T00:00:00Z",
                completed_at_utc="2026-06-27T00:00:01Z",
            ),
            _record(
                repetition_index=1,
                linked=True,
                started_at_utc="2026-06-27T00:00:10Z",
                completed_at_utc="2026-06-27T00:00:11Z",
            ),
        ),
    )
    evaluation = evaluate_live_runset(compiled, runset, protocol=protocol)
    drift = build_live_drift_report((evaluation,), protocol=protocol)
    trajectory = build_live_trajectory_report(runset, evaluation, protocol=protocol)
    assert trajectory.trajectory_status == "invalid"
    return drift, trajectory


@pytest.fixture(scope="module")
def historical_monitoring_reports() -> tuple[LiveDriftReport, LiveTrajectoryReport]:
    drift_payload, trajectory_payload = _v065_drift_and_trajectory_payloads()
    return (
        LiveDriftReport.model_validate(drift_payload),
        LiveTrajectoryReport.model_validate(trajectory_payload),
    )


@pytest.fixture(scope="module")
def current_decision_reports() -> tuple[LiveEvaluationReport, LiveComparisonReport]:
    compiled = compile_suite(SUITE)
    protocol = _protocol(compiled, observations=1, clusters=1, repetitions=1)
    protocol_digest = sha256_hexdigest(protocol)

    def evaluation(runset_id: str, *, linked: bool) -> LiveEvaluationReport:
        runset = RunSet(
            artifact_kind="run-set",
            runset_id=runset_id,
            suite_id=compiled.suite_id,
            suite_version=compiled.suite_version,
            suite_digest=compiled_suite_digest(compiled),
            fixture_manifest_digest="4" * 64,
            execution_mode=ExecutionMode.live,
            protocol_id=protocol.protocol_id,
            protocol_digest=protocol_digest,
            runs=(_record(repetition_index=0, linked=linked),),
        )
        return evaluate_live_runset(compiled, runset, protocol=protocol)

    baseline = evaluation("reporting-boundary-baseline", linked=False)
    candidate = evaluation("reporting-boundary-candidate", linked=True)
    comparison = compare_live_reports(baseline, candidate, protocol=protocol)
    assert candidate.exploratory is True
    assert comparison.exploratory is True
    assert comparison.state is not GateState.pass_
    return candidate, comparison


@pytest.fixture(scope="module")
def historical_decision_reports() -> tuple[LiveEvaluationReport, LiveComparisonReport]:
    return (
        LiveEvaluationReport.model_validate(_valid_historical_evaluation("0.6.5")),
        LiveComparisonReport.model_validate(_valid_historical_comparison("0.6.5")),
    )


def _unsafe_variants(report: BaseModel, **changes: Any) -> tuple[BaseModel, BaseModel]:
    return (
        report.model_copy(update=changes),
        type(report).model_construct(**{**report.__dict__, **changes}),
    )


def test_evaluation_reporting_revalidates_unsafe_status_without_outputs(
    current_decision_reports: tuple[LiveEvaluationReport, LiveComparisonReport],
    tmp_path: Path,
) -> None:
    evaluation, _ = current_decision_reports
    for index, forged in enumerate(_unsafe_variants(evaluation, exploratory=False)):
        assert isinstance(forged, LiveEvaluationReport)
        with pytest.raises(ValidationError):
            render_live_evaluation_markdown(forged)

        json_dir = tmp_path / f"evaluation-json-{index}"
        with pytest.raises(ValidationError):
            write_live_evaluation_json(forged, json_dir)
        assert not json_dir.exists()

        markdown_dir = tmp_path / f"evaluation-markdown-{index}"
        with pytest.raises(ValidationError):
            write_live_evaluation_markdown(forged, markdown_dir)
        assert not markdown_dir.exists()


def test_comparison_reporting_revalidates_unsafe_state_without_outputs(
    current_decision_reports: tuple[LiveEvaluationReport, LiveComparisonReport],
    tmp_path: Path,
) -> None:
    _, comparison = current_decision_reports
    for index, forged in enumerate(_unsafe_variants(comparison, state=GateState.pass_)):
        assert isinstance(forged, LiveComparisonReport)
        with pytest.raises(ValidationError):
            render_live_comparison_markdown(forged)

        json_dir = tmp_path / f"comparison-json-{index}"
        with pytest.raises(ValidationError):
            write_live_comparison_json(forged, json_dir)
        assert not json_dir.exists()

        markdown_dir = tmp_path / f"comparison-markdown-{index}"
        with pytest.raises(ValidationError):
            write_live_comparison_markdown(forged, markdown_dir)
        assert not markdown_dir.exists()


def test_drift_reporting_rejects_unsafe_ordering_without_outputs(
    current_monitoring_reports: tuple[LiveDriftReport, LiveTrajectoryReport],
    tmp_path: Path,
) -> None:
    drift, _ = current_monitoring_reports
    for index, forged in enumerate(_unsafe_variants(drift, ordering_variable="release_sequence")):
        assert isinstance(forged, LiveDriftReport)
        with pytest.raises(ValueError, match="support.*only"):
            render_live_drift_markdown(forged)

        json_dir = tmp_path / f"drift-json-{index}"
        with pytest.raises(ValueError, match="support.*only"):
            write_live_drift_json(forged, json_dir)
        assert not json_dir.exists()

        markdown_dir = tmp_path / f"drift-markdown-{index}"
        with pytest.raises(ValueError, match="support.*only"):
            write_live_drift_markdown(forged, markdown_dir)
        assert not markdown_dir.exists()


def test_trajectory_reporting_revalidates_unsafe_status_without_outputs(
    current_monitoring_reports: tuple[LiveDriftReport, LiveTrajectoryReport],
    tmp_path: Path,
) -> None:
    _, trajectory = current_monitoring_reports
    for index, forged in enumerate(_unsafe_variants(trajectory, trajectory_status="valid")):
        assert isinstance(forged, LiveTrajectoryReport)
        with pytest.raises(ValidationError, match="trajectory status"):
            render_live_trajectory_markdown(forged)

        json_dir = tmp_path / f"trajectory-json-{index}"
        with pytest.raises(ValidationError, match="trajectory status"):
            write_live_trajectory_json(forged, json_dir)
        assert not json_dir.exists()

        markdown_dir = tmp_path / f"trajectory-markdown-{index}"
        with pytest.raises(ValidationError, match="trajectory status"):
            write_live_trajectory_markdown(forged, markdown_dir)
        assert not markdown_dir.exists()


def test_historical_live_reports_are_not_renderable_or_publishable(
    historical_decision_reports: tuple[LiveEvaluationReport, LiveComparisonReport],
    historical_monitoring_reports: tuple[LiveDriftReport, LiveTrajectoryReport],
    tmp_path: Path,
) -> None:
    historical_evaluation, historical_comparison = historical_decision_reports
    historical_drift, historical_trajectory = historical_monitoring_reports
    cases = (
        (
            render_live_evaluation_markdown,
            write_live_evaluation_markdown,
            historical_evaluation,
            "evaluation",
        ),
        (
            render_live_comparison_markdown,
            write_live_comparison_markdown,
            historical_comparison,
            "comparison",
        ),
        (
            render_live_drift_markdown,
            write_live_drift_markdown,
            historical_drift,
            "drift",
        ),
        (
            render_live_trajectory_markdown,
            write_live_trajectory_markdown,
            historical_trajectory,
            "trajectory",
        ),
    )

    for renderer, writer, report, label in cases:
        with pytest.raises(ValueError):
            renderer(report)
        output = tmp_path / f"historical-{label}-markdown-must-not-exist"
        with pytest.raises(ValueError):
            writer(report, output)
        assert not output.exists()


def test_historical_drift_unsupported_ordering_remains_explicit(
    historical_monitoring_reports: tuple[LiveDriftReport, LiveTrajectoryReport],
) -> None:
    historical_drift, _ = historical_monitoring_reports

    unsupported_payload = historical_drift.model_dump(mode="json")
    unsupported_payload["ordering_variable"] = "release_sequence"
    unsupported_historical = LiveDriftReport.model_validate(unsupported_payload)
    with pytest.raises(ValueError, match="drift reporting supports only"):
        render_live_drift_markdown(unsupported_historical)


def test_historical_monitoring_reporting_revalidates_unsafe_derived_fields(
    historical_monitoring_reports: tuple[LiveDriftReport, LiveTrajectoryReport],
) -> None:
    historical_drift, historical_trajectory = historical_monitoring_reports
    for forged in _unsafe_variants(historical_drift, monitoring_status="valid"):
        assert isinstance(forged, LiveDriftReport)
        with pytest.raises(ValidationError):
            render_live_drift_markdown(forged)
    for forged in _unsafe_variants(historical_trajectory, trajectory_status="valid"):
        assert isinstance(forged, LiveTrajectoryReport)
        with pytest.raises(ValidationError):
            render_live_trajectory_markdown(forged)


def test_historical_decision_reporting_revalidates_unsafe_derived_fields(
    historical_decision_reports: tuple[LiveEvaluationReport, LiveComparisonReport],
    tmp_path: Path,
) -> None:
    historical_evaluation, historical_comparison = historical_decision_reports
    for index, forged in enumerate(_unsafe_variants(historical_evaluation, exploratory=False)):
        assert isinstance(forged, LiveEvaluationReport)
        with pytest.raises(ValidationError):
            render_live_evaluation_markdown(forged)
        output = tmp_path / f"historical-evaluation-{index}"
        with pytest.raises(ValidationError):
            write_live_evaluation_json(forged, output)
        assert not output.exists()
    for index, forged in enumerate(_unsafe_variants(historical_comparison, state=GateState.pass_)):
        assert isinstance(forged, LiveComparisonReport)
        with pytest.raises(ValidationError):
            render_live_comparison_markdown(forged)
        output = tmp_path / f"historical-comparison-{index}"
        with pytest.raises(ValidationError):
            write_live_comparison_json(forged, output)
        assert not output.exists()


def test_historical_live_json_writers_reject_unrepresentable_public_wires(
    historical_decision_reports: tuple[LiveEvaluationReport, LiveComparisonReport],
    historical_monitoring_reports: tuple[LiveDriftReport, LiveTrajectoryReport],
    tmp_path: Path,
) -> None:
    evaluation, comparison = historical_decision_reports
    drift, trajectory = historical_monitoring_reports
    cases = (
        (write_live_evaluation_json, evaluation, "evaluation"),
        (write_live_comparison_json, comparison, "comparison"),
        (write_live_drift_json, drift, "drift"),
        (write_live_trajectory_json, trajectory, "trajectory"),
    )

    for writer, report, label in cases:
        output = tmp_path / f"historical-{label}-must-not-exist"
        with pytest.raises(ValueError):
            writer(report, output)
        assert not output.exists()


def test_live_evaluation_json_revalidates_after_real_redaction(
    current_decision_reports: tuple[LiveEvaluationReport, LiveComparisonReport],
    tmp_path: Path,
) -> None:
    evaluation, _ = current_decision_reports
    payload = evaluation.model_dump(mode="json")
    payload["suite_id"] = "alice@example.com"
    protocol = payload["protocol"]
    assert isinstance(protocol, dict)
    protocol["suite_id"] = "alice@example.com"
    payload["protocol_digest"] = sha256_hexdigest(protocol)
    sensitive_but_coherent = LiveEvaluationReport.model_validate(payload)
    output = tmp_path / "post-redaction-must-not-exist"

    with pytest.raises(ValidationError, match="protocol"):
        write_live_evaluation_json(sensitive_but_coherent, output)

    assert not output.exists()


def test_all_live_json_writers_revalidate_redacted_payload_before_output(
    current_decision_reports: tuple[LiveEvaluationReport, LiveComparisonReport],
    current_monitoring_reports: tuple[LiveDriftReport, LiveTrajectoryReport],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evaluation, comparison = current_decision_reports
    drift, trajectory = current_monitoring_reports

    def corrupt_after_redaction(value: Any, **_kwargs: Any) -> Any:
        corrupted = deepcopy(value)
        assert isinstance(corrupted, dict)
        corrupted["artifact_kind"] = "forged-after-redaction"
        return corrupted

    monkeypatch.setattr(live_reporting, "redact_artifact_payload", corrupt_after_redaction)
    cases = (
        (write_live_evaluation_json, evaluation, "evaluation"),
        (write_live_comparison_json, comparison, "comparison"),
        (write_live_drift_json, drift, "drift"),
        (write_live_trajectory_json, trajectory, "trajectory"),
    )
    for writer, report, label in cases:
        output = tmp_path / f"{label}-must-not-exist"
        with pytest.raises(ValidationError, match="artifact_kind"):
            writer(report, output)
        assert not output.exists()
