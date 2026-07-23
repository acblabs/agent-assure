from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Annotated, Literal, cast

import typer
from rich.console import Console

from agent_assure.artifact_io import write_text_atomic
from agent_assure.io_limits import (
    MAX_ARTIFACT_JSON_BYTES,
    load_json_bounded,
    read_text_bounded,
)
from agent_assure.privacy.redaction import assert_runset_payload_safe_for_persistence
from agent_assure.schema.run import AgentRunRecord, RunSet
from agent_assure.schema.telemetry import MAX_OTEL_SPANS_PER_EXPORT, SpanPlan
from agent_assure.telemetry.otel_mapping import run_record_to_span_plan
from agent_assure.telemetry.otel_sdk import (
    MAX_OTEL_HEADER_VALUE_CHARS,
    OpenTelemetryExportError,
    OpenTelemetryUnavailable,
    OTelExportConfig,
    OTelHeader,
    emit_span_plans,
)
from agent_assure.telemetry.privacy_filter import assert_span_plan_safe_for_export

app = typer.Typer(help="OpenTelemetry-aligned preview utilities.")
console = Console()
OTelProtocol = Literal["otlp-http", "console"]


@app.command("preview")
def preview(
    path: Annotated[Path, typer.Argument(exists=True, readable=True)],
    out: Annotated[
        Path | None,
        typer.Option("--out", help="Optional span-plan JSON output path."),
    ] = None,
) -> None:
    try:
        record = AgentRunRecord.model_validate(
            load_json_bounded(
                path,
                max_bytes=MAX_ARTIFACT_JSON_BYTES,
                label="OTel preview input",
            )
        )
        span_plan = run_record_to_span_plan(record)
    except (TypeError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    payload = json.dumps(span_plan.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"
    if out is None:
        console.print(payload)
        return
    write_text_atomic(out, payload)
    console.print(f"span plan: {out}")


@app.command("export")
def export(
    path: Annotated[Path, typer.Argument(exists=True, readable=True)],
    protocol: Annotated[
        str,
        typer.Option("--protocol", help="Exporter protocol: otlp-http or console."),
    ] = "otlp-http",
    endpoint: Annotated[
        str | None,
        typer.Option("--endpoint", help="Required HTTPS OTLP endpoint for otlp-http."),
    ] = None,
    allowed_endpoint_host: Annotated[
        list[str] | None,
        typer.Option(
            "--allowed-endpoint-host",
            help="Allowed OTLP endpoint host. Repeat for each trusted collector host.",
        ),
    ] = None,
    service_name: Annotated[
        str,
        typer.Option("--service-name", help="OpenTelemetry service.name resource value."),
    ] = "agent-assure",
    timeout_seconds: Annotated[
        int,
        typer.Option("--timeout-seconds", help="OTLP export timeout."),
    ] = 10,
    header: Annotated[
        list[str] | None,
        typer.Option(
            "--header",
            help="Disabled: use --header-env or --header-file so secrets do not enter argv.",
        ),
    ] = None,
    header_env: Annotated[
        list[str] | None,
        typer.Option(
            "--header-env",
            help="OTLP header as NAME=ENV_VAR; reads the value from the process environment.",
        ),
    ] = None,
    header_file: Annotated[
        list[str] | None,
        typer.Option(
            "--header-file",
            help="OTLP header as NAME=PATH; reads a bounded value from a protected file.",
        ),
    ] = None,
) -> None:
    try:
        if header:
            raise ValueError(
                "--header is disabled because it exposes secrets in process arguments; "
                "use --header-env NAME=ENV_VAR or --header-file NAME=PATH"
            )
        plans = _span_plans_from_path(path)
        config = OTelExportConfig(
            protocol=_parse_protocol(protocol),
            endpoint=endpoint,
            allowed_endpoint_hosts=tuple(allowed_endpoint_host or ()),
            service_name=service_name,
            timeout_seconds=timeout_seconds,
            headers=_load_headers(header_env or [], header_file or []),
        )
        result = emit_span_plans(plans, config)
    except (OpenTelemetryExportError, OpenTelemetryUnavailable) as exc:
        raise typer.BadParameter(str(exc)) from exc
    except (TypeError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    console.print(
        "otel export: "
        f"spans={result.span_count} protocol={result.protocol} "
        f"endpoint={result.endpoint or 'none'}"
    )


def _span_plans_from_path(path: Path) -> tuple[SpanPlan, ...]:
    payload = load_json_bounded(path)
    if not isinstance(payload, dict):
        raise ValueError("OTel export input must be a JSON object")
    artifact_kind = payload.get("artifact_kind")
    if artifact_kind == "agent-run-record":
        assert_runset_payload_safe_for_persistence(payload)
        return (run_record_to_span_plan(AgentRunRecord.model_validate(payload)),)
    if artifact_kind == "run-set":
        assert_runset_payload_safe_for_persistence(payload)
        runset = RunSet.model_validate(payload)
        if len(runset.runs) > MAX_OTEL_SPANS_PER_EXPORT:
            raise ValueError(
                f"RunSet exceeds OpenTelemetry span limit of {MAX_OTEL_SPANS_PER_EXPORT}"
            )
        return tuple(run_record_to_span_plan(record) for record in runset.runs)
    if artifact_kind == "span-plan":
        plan = SpanPlan.model_validate(payload)
        assert_span_plan_safe_for_export(plan)
        return (plan,)
    raise ValueError(
        "OTel export input artifact_kind must be agent-run-record, run-set, or span-plan"
    )


def _load_headers(
    environment_references: list[str],
    file_references: list[str],
) -> tuple[OTelHeader, ...]:
    headers: list[OTelHeader] = []
    for reference in environment_references:
        name, variable_name = _parse_header_reference(reference, source="environment")
        if variable_name not in os.environ:
            raise ValueError(f"OTLP header environment variable is not set: {variable_name}")
        headers.append(OTelHeader(name=name, value=os.environ[variable_name]))
    for reference in file_references:
        name, path_text = _parse_header_reference(reference, source="file")
        value = read_text_bounded(
            Path(path_text),
            max_bytes=MAX_OTEL_HEADER_VALUE_CHARS,
            label="OTLP header file",
        ).rstrip("\r\n")
        headers.append(OTelHeader(name=name, value=value))
    return tuple(headers)


def _parse_header_reference(value: str, *, source: str) -> tuple[str, str]:
    name, separator, reference = value.partition("=")
    if not separator or not name or not reference:
        raise ValueError(f"OTLP header {source} references must use NAME=REFERENCE syntax")
    return name, reference


def _parse_protocol(value: str) -> OTelProtocol:
    if value not in {"otlp-http", "console"}:
        raise ValueError("OTel exporter protocol must be otlp-http or console")
    return cast(OTelProtocol, value)
