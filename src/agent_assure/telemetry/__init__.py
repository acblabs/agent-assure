from __future__ import annotations

__all__ = ["OTelExportConfig", "emit_span_plans", "run_record_to_span_plan"]


def __getattr__(name: str) -> object:
    if name == "run_record_to_span_plan":
        from agent_assure.telemetry.otel_mapping import run_record_to_span_plan

        return run_record_to_span_plan
    if name in {"OTelExportConfig", "emit_span_plans"}:
        from agent_assure.telemetry.otel_sdk import OTelExportConfig, emit_span_plans

        return {"OTelExportConfig": OTelExportConfig, "emit_span_plans": emit_span_plans}[name]
    raise AttributeError(name)
