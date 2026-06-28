from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Literal, cast

import typer
from rich.console import Console

from agent_assure.schema.run import AgentRunRecord, RunSet
from agent_assure.schema.telemetry import SpanPlan
from agent_assure.telemetry.otel_mapping import run_record_to_span_plan
from agent_assure.telemetry.otel_sdk import (
    OpenTelemetryUnavailable,
    OTelExportConfig,
    OTelHeader,
    emit_span_plans,
)

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
    record = AgentRunRecord.model_validate_json(path.read_text(encoding="utf-8"))
    span_plan = run_record_to_span_plan(record)
    payload = json.dumps(span_plan.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"
    if out is None:
        console.print(payload)
        return
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(payload, encoding="utf-8", newline="\n")
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
        typer.Option("--endpoint", help="OTLP HTTP endpoint. Uses SDK defaults when omitted."),
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
        typer.Option("--header", help="OTLP HTTP header as name=value."),
    ] = None,
) -> None:
    try:
        plans = _span_plans_from_path(path)
        config = OTelExportConfig(
            protocol=_parse_protocol(protocol),
            endpoint=endpoint,
            service_name=service_name,
            timeout_seconds=timeout_seconds,
            headers=_parse_headers(header or []),
        )
        result = emit_span_plans(plans, config)
    except OpenTelemetryUnavailable as exc:
        raise typer.BadParameter(str(exc)) from exc
    except (TypeError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    console.print(
        "otel export: "
        f"spans={result.span_count} protocol={result.protocol} "
        f"endpoint={result.endpoint or 'sdk-default'}"
    )


def _span_plans_from_path(path: Path) -> tuple[SpanPlan, ...]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("OTel export input must be a JSON object")
    artifact_kind = payload.get("artifact_kind")
    if artifact_kind == "agent-run-record":
        return (run_record_to_span_plan(AgentRunRecord.model_validate(payload)),)
    if artifact_kind == "run-set":
        runset = RunSet.model_validate(payload)
        return tuple(run_record_to_span_plan(record) for record in runset.runs)
    if artifact_kind == "span-plan":
        return (SpanPlan.model_validate(payload),)
    raise ValueError(
        "OTel export input artifact_kind must be agent-run-record, run-set, or span-plan"
    )


def _parse_headers(values: list[str]) -> tuple[OTelHeader, ...]:
    headers: list[OTelHeader] = []
    for value in values:
        name, separator, header_value = value.partition("=")
        if not separator or not name or not header_value:
            raise ValueError("OTLP headers must use name=value syntax")
        headers.append(OTelHeader(name=name, value=header_value))
    return tuple(headers)


def _parse_protocol(value: str) -> OTelProtocol:
    if value not in {"otlp-http", "console"}:
        raise ValueError("OTel exporter protocol must be otlp-http or console")
    return cast(OTelProtocol, value)
