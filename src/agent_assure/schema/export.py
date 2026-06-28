from __future__ import annotations

import json
from pathlib import Path
from typing import TypeAlias

from pydantic import BaseModel

from agent_assure.compare.runsets import ComparisonReport
from agent_assure.evaluation.evaluator import EvaluationReport
from agent_assure.schema.base import SCHEMA_VERSION
from agent_assure.schema.comparison import ComparisonSummary
from agent_assure.schema.environment import EnvironmentInfo
from agent_assure.schema.evaluation import EvaluationSummary
from agent_assure.schema.expectation import Expectation, ExpectationChangeRecord
from agent_assure.schema.live import (
    LiveComparisonReport,
    LiveDriftReport,
    LiveEvaluationReport,
    LiveProtocolRecord,
    LiveTrajectoryReport,
)
from agent_assure.schema.packet import EvidencePacket
from agent_assure.schema.release import ReleaseArtifactManifest, ReleaseDigestReplay
from agent_assure.schema.run import AgentRunRecord, RunSet
from agent_assure.schema.runtime import EmergencyProcessRecord
from agent_assure.schema.suite import CompiledSuite, FixtureManifest
from agent_assure.schema.telemetry import SpanPlan

SchemaModel: TypeAlias = type[BaseModel]

SCHEMA_MODELS: dict[str, SchemaModel] = {
    "agent-run-record": AgentRunRecord,
    "compiled-suite": CompiledSuite,
    "comparison-report": ComparisonReport,
    "comparison-summary": ComparisonSummary,
    "evaluation-report": EvaluationReport,
    "evaluation-summary": EvaluationSummary,
    "emergency-process-record": EmergencyProcessRecord,
    "evidence-packet": EvidencePacket,
    "environment-info": EnvironmentInfo,
    "expectation": Expectation,
    "expectation-change-record": ExpectationChangeRecord,
    "fixture-manifest": FixtureManifest,
    "live-comparison-report": LiveComparisonReport,
    "live-drift-report": LiveDriftReport,
    "live-evaluation-report": LiveEvaluationReport,
    "live-protocol-record": LiveProtocolRecord,
    "live-trajectory-report": LiveTrajectoryReport,
    "release-artifact-manifest": ReleaseArtifactManifest,
    "release-digest-replay": ReleaseDigestReplay,
    "run-set": RunSet,
    "span-plan": SpanPlan,
}


def model_for_kind(kind: str) -> SchemaModel:
    try:
        return SCHEMA_MODELS[kind]
    except KeyError as exc:
        known = ", ".join(sorted(SCHEMA_MODELS))
        raise KeyError(f"unknown artifact kind {kind!r}; expected one of: {known}") from exc


def export_json_schemas(out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for kind, model in sorted(SCHEMA_MODELS.items()):
        schema = model.model_json_schema(mode="validation")
        schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        schema["$id"] = (
            f"https://acblabs.github.io/agent-assure/schemas/v{SCHEMA_VERSION}/"
            f"{kind}.schema.json"
        )
        schema.setdefault("properties", {})
        path = out_dir / f"{kind}.schema.json"
        path.write_text(
            json.dumps(schema, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        written.append(path)
    return written
