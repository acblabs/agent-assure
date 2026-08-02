from __future__ import annotations

import json
from pathlib import Path

import pytest
import typer

from agent_assure.cli.otel_cmd import _load_headers, _span_plans_from_path, export, preview
from agent_assure.io_limits import MAX_JSON_DEPTH


def test_otel_preview_reports_over_depth_json_as_bad_parameter(tmp_path: Path) -> None:
    path = tmp_path / "record.json"
    path.write_text("[" * (MAX_JSON_DEPTH + 1) + "]" * (MAX_JSON_DEPTH + 1))

    with pytest.raises(typer.BadParameter, match="exceeds maximum supported nesting depth"):
        preview(path, out=None)


def test_otel_header_values_load_from_environment_and_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OTEL_TEST_TOKEN", "Bearer environment-secret")
    token_path = tmp_path / "token.txt"
    token_path.write_text("Bearer file-secret\n", encoding="utf-8")

    headers = _load_headers(
        ["Authorization=OTEL_TEST_TOKEN"],
        [f"X-Collector-Token={token_path}"],
    )

    assert [(header.name, header.value) for header in headers] == [
        ("Authorization", "Bearer environment-secret"),
        ("X-Collector-Token", "Bearer file-secret"),
    ]


def test_otel_export_rejects_direct_header_secret_before_reading_input() -> None:
    with pytest.raises(typer.BadParameter, match="exposes secrets in process arguments"):
        export(Path("not-read.json"), header=["Authorization=Bearer secret"])


def test_otel_export_rejects_sensitive_external_run_record(tmp_path: Path) -> None:
    path = tmp_path / "run.json"
    path.write_text(
        json.dumps(
            {
                "artifact_kind": "agent-run-record",
                "schema_version": "0.6.1",
                "run_id": "jane@example.com",
                "case_id": "case-001",
                "pipeline_id": "pipeline",
                "recommendation": "approve",
                "outcome": "approve",
                "input_summary": "safe",
                "output_summary": "safe",
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="run_id"):
        _span_plans_from_path(path)


def test_otel_export_rejects_sensitive_precomputed_span_plan(tmp_path: Path) -> None:
    path = tmp_path / "span-plan.json"
    path.write_text(
        json.dumps(
            {
                "artifact_kind": "span-plan",
                "schema_version": "0.6.1",
                "span_name": "agent_assure.run",
                "attributes": [
                    {
                        "artifact_kind": "span-attribute",
                        "schema_version": "0.6.1",
                        "key": "agent_assure.run_id",
                        "value": "jane@example.com",
                    }
                ],
                "semconv_commit": "commit",
                "semconv_checksum": "0" * 64,
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="sensitive-looking content"):
        _span_plans_from_path(path)


def test_otel_export_command_rejects_sensitive_attribute_label_value_pair(
    tmp_path: Path,
) -> None:
    path = tmp_path / "span-plan.json"
    path.write_text(
        json.dumps(
            {
                "artifact_kind": "span-plan",
                "schema_version": "0.6.1",
                "span_name": "agent_assure.run",
                "attributes": [
                    {
                        "artifact_kind": "span-attribute",
                        "schema_version": "0.6.1",
                        "key": "patient.ssn",
                        "value": 123456789,
                    }
                ],
                "semconv_commit": "commit",
                "semconv_checksum": "0" * 64,
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(typer.BadParameter, match=r"attributes\[0\]\.key_value"):
        export(path, protocol="console")
