from __future__ import annotations

import json
from pathlib import Path
from typing import TypeAlias

from pydantic import BaseModel

from agent_assure.artifact_io import write_text_atomic
from agent_assure.compare.runsets import ComparisonReport
from agent_assure.evaluation.evaluator import EvaluationReport
from agent_assure.schema.base import SCHEMA_VERSION
from agent_assure.schema.campaign import (
    AssuranceMutationCampaign,
    AssuranceMutationCatalog,
)
from agent_assure.schema.comparison import ComparisonSummary
from agent_assure.schema.controls import ControlCoverageReport
from agent_assure.schema.efficacy import (
    ControlEfficacyReport,
    ThreatApplicabilityManifest,
)
from agent_assure.schema.environment import EnvironmentInfo
from agent_assure.schema.evaluation import EvaluationSummary
from agent_assure.schema.expectation import Expectation, ExpectationChangeRecord
from agent_assure.schema.graph import AssuranceEvidenceGraph
from agent_assure.schema.live import (
    LiveComparisonReport,
    LiveDriftReport,
    LiveEvaluationReport,
    LiveProtocolRecord,
    LiveTrajectoryReport,
)
from agent_assure.schema.mutation import (
    AssuranceEvidenceDescriptor,
    AssuranceMutationOperator,
    AssuranceMutationResult,
    ExpectedDetectionContract,
)
from agent_assure.schema.packet import EvidencePacket
from agent_assure.schema.release import ReleaseArtifactManifest, ReleaseDigestReplay
from agent_assure.schema.reproduction_index import ProcessEquivalenceReproductionIndex
from agent_assure.schema.run import AgentRunRecord, RunSet
from agent_assure.schema.runtime import EmergencyProcessRecord
from agent_assure.schema.sensitivity import (
    RAGSensitivityCorpusManifest,
    RAGSensitivityCorpusSnapshot,
    RAGSensitivityKnowledgeContract,
    RAGSensitivityProtocol,
    RAGSensitivityReport,
    RAGSensitivitySyntheticDataAttestation,
)
from agent_assure.schema.stream import (
    StreamEventRecord,
    StreamIngestionDiagnostics,
    StreamRunRecord,
)
from agent_assure.schema.suite import CompiledSuite, FixtureManifest
from agent_assure.schema.telemetry import SpanPlan
from agent_assure.schema.usage import (
    UsageLedger,
    UsagePricingSnapshot,
    UsageSegment,
    UsageSummary,
    UsageSummaryDelta,
)

SchemaModel: TypeAlias = type[BaseModel]
BASE_PERSISTED_IDENTITY_FIELDS = ("artifact_kind", "schema_version")
CONTRACT_IDENTITY_FIELDS = ("schema_name", "contract_id", "contract_version")
CONTRACT_ARTIFACT_KINDS = frozenset(
    {
        "assurance-evidence-descriptor",
        "assurance-evidence-graph",
        "assurance-mutation-campaign",
        "assurance-mutation-catalog",
        "assurance-mutation-operator",
        "assurance-mutation-result",
        "control-efficacy-report",
        "expected-detection-contract",
        "process-equivalence-reproduction-index",
        "evidence-sensitivity-protocol",
        "evidence-sensitivity-report",
        "rag-sensitivity-corpus-manifest",
        "rag-sensitivity-corpus-snapshot",
        "rag-sensitivity-knowledge-contract",
        "rag-sensitivity-synthetic-data-attestation",
        "threat-applicability-manifest",
    }
)

SCHEMA_MODELS: dict[str, SchemaModel] = {
    "agent-run-record": AgentRunRecord,
    "assurance-evidence-descriptor": AssuranceEvidenceDescriptor,
    "assurance-evidence-graph": AssuranceEvidenceGraph,
    "assurance-mutation-campaign": AssuranceMutationCampaign,
    "assurance-mutation-catalog": AssuranceMutationCatalog,
    "assurance-mutation-operator": AssuranceMutationOperator,
    "assurance-mutation-result": AssuranceMutationResult,
    "compiled-suite": CompiledSuite,
    "comparison-report": ComparisonReport,
    "comparison-summary": ComparisonSummary,
    "control-coverage-report": ControlCoverageReport,
    "control-efficacy-report": ControlEfficacyReport,
    "evaluation-report": EvaluationReport,
    "evaluation-summary": EvaluationSummary,
    "emergency-process-record": EmergencyProcessRecord,
    "evidence-packet": EvidencePacket,
    "evidence-sensitivity-protocol": RAGSensitivityProtocol,
    "evidence-sensitivity-report": RAGSensitivityReport,
    "environment-info": EnvironmentInfo,
    "expectation": Expectation,
    "expectation-change-record": ExpectationChangeRecord,
    "expected-detection-contract": ExpectedDetectionContract,
    "fixture-manifest": FixtureManifest,
    "live-comparison-report": LiveComparisonReport,
    "live-drift-report": LiveDriftReport,
    "live-evaluation-report": LiveEvaluationReport,
    "live-protocol-record": LiveProtocolRecord,
    "live-trajectory-report": LiveTrajectoryReport,
    "process-equivalence-reproduction-index": ProcessEquivalenceReproductionIndex,
    "release-artifact-manifest": ReleaseArtifactManifest,
    "release-digest-replay": ReleaseDigestReplay,
    "rag-sensitivity-corpus-manifest": RAGSensitivityCorpusManifest,
    "rag-sensitivity-corpus-snapshot": RAGSensitivityCorpusSnapshot,
    "rag-sensitivity-knowledge-contract": RAGSensitivityKnowledgeContract,
    "rag-sensitivity-synthetic-data-attestation": (RAGSensitivitySyntheticDataAttestation),
    "run-set": RunSet,
    "span-plan": SpanPlan,
    "stream-event-record": StreamEventRecord,
    "stream-ingestion-diagnostics": StreamIngestionDiagnostics,
    "stream-run": StreamRunRecord,
    "threat-applicability-manifest": ThreatApplicabilityManifest,
    "usage-ledger": UsageLedger,
    "usage-pricing-snapshot": UsagePricingSnapshot,
    "usage-segment": UsageSegment,
    "usage-summary": UsageSummary,
    "usage-summary-delta": UsageSummaryDelta,
}


def model_for_kind(kind: str) -> SchemaModel:
    try:
        return SCHEMA_MODELS[kind]
    except KeyError as exc:
        known = ", ".join(sorted(SCHEMA_MODELS))
        raise KeyError(f"unknown artifact kind {kind!r}; expected one of: {known}") from exc


def persisted_identity_fields_for_kind(kind: str) -> tuple[str, ...]:
    if kind in CONTRACT_ARTIFACT_KINDS:
        return (*BASE_PERSISTED_IDENTITY_FIELDS, *CONTRACT_IDENTITY_FIELDS)
    return BASE_PERSISTED_IDENTITY_FIELDS


def require_persisted_identity_in_schema(
    schema: dict[str, object],
    kind: str,
) -> None:
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        raise ValueError(f"{kind} schema has no root properties")
    required_value = schema.get("required", ())
    if not isinstance(required_value, list | tuple):
        raise ValueError(f"{kind} schema has a malformed required declaration")
    required = list(required_value)
    for field_name in persisted_identity_fields_for_kind(kind):
        if field_name not in properties:
            raise ValueError(f"{kind} schema has no persisted identity field {field_name}")
        if field_name not in required:
            required.append(field_name)
    schema["required"] = required


def writer_json_schema(model: SchemaModel) -> dict[str, object]:
    """Return the current writer schema without narrowing compatibility models."""
    schema = model.model_json_schema(mode="validation")
    _pin_persisted_schema_versions_to_defaults(schema)
    return schema


def _pin_persisted_schema_versions_to_defaults(schema: dict[str, object]) -> None:
    """Recursively pin persisted-model fields to the version each model emits."""
    pending: list[object] = [schema]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            properties = value.get("properties")
            if isinstance(properties, dict):
                declaration = properties.get("schema_version")
                if isinstance(declaration, dict):
                    default_version = declaration.get("default")
                    if isinstance(default_version, str):
                        declaration.pop("anyOf", None)
                        declaration.pop("enum", None)
                        declaration.pop("oneOf", None)
                        declaration["const"] = default_version
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)


def export_json_schemas(out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for kind, model in sorted(SCHEMA_MODELS.items()):
        schema = writer_json_schema(model)
        require_persisted_identity_in_schema(schema, kind)
        schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        schema["$id"] = (
            f"https://acblabs.github.io/agent-assure/schemas/v{SCHEMA_VERSION}/{kind}.schema.json"
        )
        schema.setdefault("properties", {})
        path = out_dir / f"{kind}.schema.json"
        write_text_atomic(
            path,
            json.dumps(schema, indent=2, sort_keys=True) + "\n",
        )
        written.append(path)
    return written
