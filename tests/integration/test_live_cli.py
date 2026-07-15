from __future__ import annotations

import json
from pathlib import Path

import yaml
from typer.testing import CliRunner

from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.cli.main import app
from agent_assure.schema.common import GateState
from agent_assure.schema.live import (
    LiveDriftReport,
    LiveEvaluationReport,
    LiveProtocolRecord,
    LiveTrajectoryReport,
)
from agent_assure.schema.run import RunSet

SUITE = Path("examples/expense_approval_minimal/suite.yaml")
RUNNER = CliRunner()


def test_live_cli_static_adapter_runs_and_reports_repeated_observations(tmp_path: Path) -> None:
    compiled_path = tmp_path / "expense.compiled.json"
    runset_path = tmp_path / "expense.live.json"
    report_dir = tmp_path / "live-report"
    drift_dir = tmp_path / "live-drift"
    trajectory_dir = tmp_path / "live-trajectory"
    prompt_path = tmp_path / "prompt-exp-001.txt"
    responses_path = tmp_path / "responses.jsonl"
    config_path = tmp_path / "live.yaml"
    protocol_path = tmp_path / "protocol.json"
    prompt_path.write_text("Return a structured expense approval record.", encoding="utf-8")
    _write_jsonl(
        responses_path,
        [
            _response(repetition_index=0, linked=True),
            _response(repetition_index=1, linked=False),
        ],
    )
    assert (
        RUNNER.invoke(
            app,
            ["suite", "compile", str(SUITE), "--out", str(compiled_path)],
        ).exit_code
        == 0
    )
    compiled_payload = json.loads(compiled_path.read_text(encoding="utf-8"))
    suite_digest = sha256_hexdigest(compiled_payload)
    protocol = LiveProtocolRecord.model_validate(_protocol_payload(suite_digest))
    protocol_path.write_text(
        json.dumps(protocol.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    protocol_digest = sha256_hexdigest(protocol)
    config_path.write_text(
        yaml.safe_dump(
            {
                "variant_id": "static-live",
                "pipeline_id": "expense-live",
                "tool_schema_digest": "7" * 64,
                "policy_bundle_digest": "8" * 64,
                "repetitions": 2,
                "randomization_seed": 17,
                "max_requests": 2,
                "max_total_cost_usd": "10.000000",
                "max_cost_per_observation_usd": "1.000000",
                "max_retries": 0,
                "protocol_id": protocol.protocol_id,
                "protocol_digest": protocol_digest,
                "adapter": {
                    "adapter_id": "static-jsonl",
                    "provider": "static-provider",
                    "model": "static-model",
                    "api_version": "2026-06-27",
                    "sdk_name": "static-sdk",
                    "sdk_version": "1.0.0",
                    "response_jsonl_path": responses_path.name,
                },
                "cases": [
                    {
                        "case_id": "exp-001",
                        "prompt_path": prompt_path.name,
                        "input_summary": "expense request",
                    }
                ],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    run_result = RUNNER.invoke(
        app,
        [
            "live",
            "run",
            str(compiled_path),
            "--config",
            str(config_path),
            "--protocol",
            str(protocol_path),
            "--out",
            str(runset_path),
        ],
    )
    assert run_result.exit_code == 0, run_result.output
    runset = RunSet.model_validate_json(runset_path.read_text(encoding="utf-8"))
    assert runset.execution_mode.value == "live"
    assert len(runset.runs) == 2
    assert {run.repetition_index for run in runset.runs} == {0, 1}

    evaluate_result = RUNNER.invoke(
        app,
        [
            "live",
            "evaluate",
            str(runset_path),
            "--suite",
            str(compiled_path),
            "--protocol",
            str(protocol_path),
            "--out-dir",
            str(report_dir),
        ],
    )
    assert evaluate_result.exit_code == 1, evaluate_result.output
    report = LiveEvaluationReport.model_validate_json(
        (report_dir / "live-evaluation-report.json").read_text(encoding="utf-8")
    )
    assert report.state is GateState.fail
    assert report.overall.expectation_pass_rate.rate == "0.500000"
    assert report.overall.expectation_pass_rate.effective_n == "1.666667"
    assert (report_dir / "live-evaluation-report.md").exists()

    drift_result = RUNNER.invoke(
        app,
        [
            "live",
            "drift",
            str(report_dir / "live-evaluation-report.json"),
            str(report_dir / "live-evaluation-report.json"),
            "--protocol",
            str(protocol_path),
            "--out-dir",
            str(drift_dir),
        ],
    )
    assert drift_result.exit_code == 0, drift_result.output
    drift_report = LiveDriftReport.model_validate_json(
        (drift_dir / "live-drift-report.json").read_text(encoding="utf-8")
    )
    assert drift_report.state is GateState.not_evaluated
    assert drift_report.comparability.status == "pass"
    assert (drift_dir / "live-drift-report.md").exists()

    trajectory_result = RUNNER.invoke(
        app,
        [
            "live",
            "trajectory",
            str(runset_path),
            "--report",
            str(report_dir / "live-evaluation-report.json"),
            "--protocol",
            str(protocol_path),
            "--out-dir",
            str(trajectory_dir),
        ],
    )
    assert trajectory_result.exit_code == 0, trajectory_result.output
    trajectory_report = LiveTrajectoryReport.model_validate_json(
        (trajectory_dir / "live-trajectory-report.json").read_text(encoding="utf-8")
    )
    assert trajectory_report.state is GateState.not_evaluated
    assert trajectory_report.trajectory_status == "exploratory"
    assert any(
        invariant.invariant_id == "claim-evidence-before-approval"
        and invariant.affected_observations == 1
        and invariant.state is GateState.fail
        for invariant in trajectory_report.invariants
    )
    assert (trajectory_dir / "live-trajectory-report.md").exists()


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text(
        "\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n",
        encoding="utf-8",
    )


def _response(*, repetition_index: int, linked: bool) -> dict[str, object]:
    record: dict[str, object] = {
        "recommendation": "approve",
        "outcome": "approve",
        "output_summary": "receipt-backed approval",
        "tools": ["expense_policy_check", "receipt_check"],
        "evidence_refs": [
            {
                "artifact_kind": "evidence-ref",
                "ref_id": "ref-receipt-exp-001",
                "source_id": "receipt-exp-001",
                "claim_ids": ["claim-receipt-present"],
            }
        ],
        "evidence_items": [
            {
                "artifact_kind": "evidence-item",
                "ref_id": "ref-receipt-exp-001",
                "source_id": "receipt-exp-001",
                "content_digest": "8" * 64,
            }
        ],
        "claims": [
            {
                "artifact_kind": "claim-record",
                "claim_id": "claim-receipt-present",
            }
        ],
        "policy_results": [
            {
                "artifact_kind": "policy-result",
                "policy_id": "provider-selection",
                "state": "pass",
                "reason_codes": [],
                "severity": "info",
                "message": "provider policy evaluated",
            }
        ],
    }
    if linked:
        record["claim_evidence_links"] = [
            {
                "artifact_kind": "claim-evidence-link",
                "claim_id": "claim-receipt-present",
                "evidence_ref_id": "ref-receipt-exp-001",
            }
        ]
    return {
        "case_id": "exp-001",
        "repetition_index": repetition_index,
        "record": record,
        "provider": "static-provider",
        "model": "static-model",
        "resolved_model": "static-model-2026-06-27",
        "prompt_tokens": 12,
        "completion_tokens": 18,
        "total_tokens": 30,
        "estimated_cost_usd": "0.001000",
    }


def _protocol_payload(suite_digest: str) -> dict[str, object]:
    return {
        "artifact_kind": "live-protocol-record",
        "schema_version": "0.2.0",
        "protocol_id": "protocol-cli-live",
        "suite_id": "expense-approval-minimal",
        "suite_version": "0.1.0",
        "suite_digest": suite_digest,
        "baseline_mode": "concurrent_paired",
        "hypothesis_family": "governance_control_non_inferiority",
        "primary_endpoint": "expectation_pass_rate",
        "analysis_method": "paired_cluster_t_interval",
        "baseline_group_id": "overall",
        "candidate_group_id": "overall",
        "confidence_level": "0.950000",
        "non_inferiority_margin": "0.050000",
        "cluster_by": "case_id",
        "planned_observations": 2,
        "planned_clusters": 1,
        "planned_observations_per_cluster": "2.000000",
        "assumed_intraclass_correlation": "0.200000",
        "design_effect": "1.200000",
        "planned_effective_n": "1.666667",
        "sample_size_rationale": "integration test protocol fixture",
        "planned_repetitions": 2,
        "randomization_seed": 17,
        "randomization_blocking": "balanced_case_blocks",
        "max_requests": 2,
        "max_total_cost_usd": "10.000000",
        "max_cost_per_observation_usd": "1.000000",
        "max_retries": 0,
        "exclusion_policy": "only pre-provider local configuration exclusions are allowed",
        "allowed_exclusion_reasons": ["budget_exhausted", "token_budget_exhausted"],
        "max_exclusion_rate": "0.000000",
        "provider_version_capture": ["resolved_model", "provider_api_version", "provider_sdk"],
        "stopping_rules": ["stop on sensitive persistence"],
        "tool_schema_digest": "7" * 64,
        "policy_bundle_digest": "8" * 64,
        "analysis_digest": "6" * 64,
        "approved_data_boundary": "synthetic local prompts",
        "safety_limits": ["no raw sensitive content"],
    }
