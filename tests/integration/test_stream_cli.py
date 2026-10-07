from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import Result
from typer.testing import CliRunner

from agent_assure.cli import stream_cmd
from agent_assure.cli.main import app
from agent_assure.schema.common import GateState, ReasonCode
from agent_assure.schema.stream import StreamIngestionDiagnostics, StreamRunRecord

RUNNER = CliRunner()
ROOT = Path(__file__).resolve().parents[2]
STREAMING_EXAMPLE = ROOT / "examples" / "streaming_process_regression"


def test_stream_cli_ingests_and_evaluates_same_output_process_regression(
    tmp_path: Path,
) -> None:
    events_path = tmp_path / "events.jsonl"
    stream_path = tmp_path / "stream-run.json"
    suite_path = tmp_path / "suite.yaml"
    report_dir = tmp_path / "report"
    suite_path.write_text(
        """
suite_id: streaming-process-regression
suite_version: 0.5.0
defaults:
  execution_mode: fixture
  runner_id: stream-jsonl
cases:
  - case_id: stream-case
    title: Streaming process regression
    expectation:
      expected_recommendation: approve
      required_evidence_refs:
        - ref-stream
      material_claim_ids:
        - claim-stream
""".lstrip(),
        encoding="utf-8",
    )
    _write_jsonl(
        events_path,
        [
            _event("evt-1", sequence_number=1, event_type="run_started"),
            _event(
                "evt-2",
                sequence_number=2,
                event_type="evidence_link_added",
                attrs={
                    "evidence_ref_id": "ref-stream",
                    "claim_id": "claim-stream",
                    "content_digest": "a" * 64,
                },
            ),
            _event(
                "evt-3",
                sequence_number=3,
                event_type="evidence_link_removed",
                attrs={"evidence_ref_id": "ref-stream", "claim_id": "claim-stream"},
            ),
            _event(
                "evt-4",
                sequence_number=4,
                event_type="run_completed",
                attrs={"recommendation": "approve", "outcome": "approved"},
            ),
        ],
    )

    ingest_result = RUNNER.invoke(
        app,
        [
            "stream",
            "ingest",
            str(events_path),
            "--sequence-scope",
            "global",
            "--out",
            str(stream_path),
        ],
    )

    assert ingest_result.exit_code == 0, ingest_result.output
    stream_run = StreamRunRecord.model_validate_json(stream_path.read_text(encoding="utf-8"))
    diagnostics = StreamIngestionDiagnostics.model_validate_json(
        (tmp_path / "stream-ingestion-diagnostics.json").read_text(encoding="utf-8")
    )
    assert stream_run.accepted_event_count == 4
    assert diagnostics.duplicate_event_count == 0

    evaluate_result = RUNNER.invoke(
        app,
        [
            "stream",
            "evaluate",
            str(stream_path),
            "--suite",
            str(suite_path),
            "--out-dir",
            str(report_dir),
        ],
    )

    assert evaluate_result.exit_code == 1, evaluate_result.output
    report = json.loads((report_dir / "evaluation-report.json").read_text(encoding="utf-8"))
    assert report["candidate_vs_expectations"]["state"] == GateState.fail.value
    reason_codes = {
        finding["reason_code"] for finding in report["candidate_vs_expectations"]["findings"]
    }
    assert ReasonCode.REQUIRED_SOURCE_MISSING.value in reason_codes
    assert ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE.value in reason_codes
    assert (report_dir / "stream-runset.json").exists()
    assert (report_dir / "stream-span-plans.json").exists()


def test_stream_cli_rejects_sensitive_privacy_filtered_attributes(tmp_path: Path) -> None:
    events_path = tmp_path / "events.jsonl"
    stream_path = tmp_path / "stream-run.json"
    _write_jsonl(
        events_path,
        [
            _event(
                "evt-sensitive",
                sequence_number=1,
                event_type="run_started",
                attrs={"source_id": "sk-proj-abcdefghijklmnopqrstuvwxyz"},
            ),
        ],
    )

    ingest_result = RUNNER.invoke(
        app,
        [
            "stream",
            "ingest",
            str(events_path),
            "--sequence-scope",
            "global",
            "--out",
            str(stream_path),
        ],
    )

    assert ingest_result.exit_code == 2
    assert "source_id" in ingest_result.output
    assert "non-sensitive" in ingest_result.output
    assert not stream_path.exists()


def test_stream_evaluate_invalid_input_does_not_create_output_directory(
    tmp_path: Path,
) -> None:
    stream_path = tmp_path / "invalid-stream-run.json"
    stream_path.write_text("{}\n", encoding="utf-8")
    report_dir = tmp_path / "report"

    result = RUNNER.invoke(
        app,
        [
            "stream",
            "evaluate",
            str(stream_path),
            "--suite",
            str(STREAMING_EXAMPLE / "suite.yaml"),
            "--out-dir",
            str(report_dir),
        ],
    )

    assert result.exit_code == 2
    assert not report_dir.exists()


def test_stream_evaluate_invalid_waiver_does_not_create_output_directory(
    tmp_path: Path,
) -> None:
    stream_path = _ingest_example_stream(tmp_path)
    waiver_path = tmp_path / "invalid-waiver.json"
    waiver_path.write_text('{"waivers": [}\n', encoding="utf-8")
    report_dir = tmp_path / "report"

    result = RUNNER.invoke(
        app,
        [
            "stream",
            "evaluate",
            str(stream_path),
            "--suite",
            str(STREAMING_EXAMPLE / "suite.yaml"),
            "--waiver",
            str(waiver_path),
            "--out-dir",
            str(report_dir),
        ],
    )

    assert result.exit_code == 2
    assert not report_dir.exists()


def test_stream_evaluate_late_render_failure_preserves_prior_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream_path = _ingest_example_stream(tmp_path)
    report_dir = tmp_path / "existing-report"
    initial = _evaluate_example_stream(stream_path, report_dir)
    assert initial.exit_code == 0, initial.output
    (report_dir / "unrelated.txt").write_bytes(b"preserve me\n")
    before = {entry.name: entry.read_bytes() for entry in report_dir.iterdir() if entry.is_file()}

    def fail_markdown_render(*_args: object, **_kwargs: object) -> Path:
        raise RuntimeError("injected late markdown failure")

    monkeypatch.setattr(stream_cmd, "write_evaluation_markdown", fail_markdown_render)

    failed_existing = _evaluate_example_stream(stream_path, report_dir)

    assert failed_existing.exit_code == 1
    assert isinstance(failed_existing.exception, RuntimeError)
    after = {entry.name: entry.read_bytes() for entry in report_dir.iterdir() if entry.is_file()}
    assert after == before

    absent_report_dir = tmp_path / "absent-report"
    failed_absent = _evaluate_example_stream(stream_path, absent_report_dir)

    assert failed_absent.exit_code == 1
    assert isinstance(failed_absent.exception, RuntimeError)
    assert not absent_report_dir.exists()


@pytest.mark.parametrize(
    ("scenario", "expected_exit", "expected_reason_codes"),
    (
        ("baseline", 0, set()),
        (
            "candidate_evidence_removed",
            1,
            {
                ReasonCode.REQUIRED_SOURCE_MISSING.value,
                ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE.value,
            },
        ),
        (
            "candidate_review_bypassed",
            1,
            {ReasonCode.REQUIRED_HUMAN_REVIEW_ABSENT.value},
        ),
        ("candidate_retry_burst", 0, set()),
    ),
)
def test_streaming_process_regression_examples_are_covered(
    tmp_path: Path,
    scenario: str,
    expected_exit: int,
    expected_reason_codes: set[str],
) -> None:
    events_path = STREAMING_EXAMPLE / "events" / f"{scenario}.jsonl"
    stream_path = tmp_path / scenario / "stream-run.json"
    report_dir = tmp_path / scenario / "report"

    ingest_result = RUNNER.invoke(
        app,
        [
            "stream",
            "ingest",
            str(events_path),
            "--sequence-scope",
            "global",
            "--out",
            str(stream_path),
        ],
    )

    assert ingest_result.exit_code == 0, ingest_result.output

    evaluate_result = RUNNER.invoke(
        app,
        [
            "stream",
            "evaluate",
            str(stream_path),
            "--suite",
            str(STREAMING_EXAMPLE / "suite.yaml"),
            "--out-dir",
            str(report_dir),
        ],
    )

    assert evaluate_result.exit_code == expected_exit, evaluate_result.output
    report = json.loads((report_dir / "evaluation-report.json").read_text(encoding="utf-8"))
    reason_codes = {
        finding["reason_code"] for finding in report["candidate_vs_expectations"]["findings"]
    }
    assert expected_reason_codes <= reason_codes
    if scenario == "candidate_retry_burst":
        runset = json.loads((report_dir / "stream-runset.json").read_text(encoding="utf-8"))
        retry_run = next(run for run in runset["runs"] if run["case_id"] == "stream-retry")
        assert retry_run["retry_count"] == 3
        assert retry_run["usage_summary"]["total_retries"] == 3
        assert retry_run["usage_summary"]["total_tokens"] == 18


def _write_jsonl(path: Path, events: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
        encoding="utf-8",
        newline="\n",
    )


def _ingest_example_stream(tmp_path: Path) -> Path:
    stream_path = tmp_path / "stream-run.json"
    result = RUNNER.invoke(
        app,
        [
            "stream",
            "ingest",
            str(STREAMING_EXAMPLE / "events" / "baseline.jsonl"),
            "--sequence-scope",
            "global",
            "--out",
            str(stream_path),
        ],
    )
    assert result.exit_code == 0, result.output
    return stream_path


def _evaluate_example_stream(stream_path: Path, report_dir: Path) -> Result:
    return RUNNER.invoke(
        app,
        [
            "stream",
            "evaluate",
            str(stream_path),
            "--suite",
            str(STREAMING_EXAMPLE / "suite.yaml"),
            "--out-dir",
            str(report_dir),
        ],
    )


def _event(
    event_id: str,
    *,
    sequence_number: int,
    event_type: str,
    attrs: dict[str, str] | None = None,
) -> dict[str, object]:
    return {
        "event_id": event_id,
        "run_id": "run-stream-001",
        "case_id": "stream-case",
        "sequence_number": sequence_number,
        "timestamp": f"2026-07-14T00:00:0{sequence_number}Z",
        "event_type": event_type,
        "privacy_filtered_attributes": attrs or {},
    }
