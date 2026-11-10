from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from typing import TypeAlias

from pydantic import BaseModel

import agent_assure
from agent_assure.artifact_io import write_text_atomic
from agent_assure.compare.runsets import ComparisonReport
from agent_assure.evaluation.evaluator import EvaluationReport
from agent_assure.io_limits import load_json_bytes_bounded, read_file_bounded_at
from agent_assure.schema.base import SCHEMA_VERSION
from agent_assure.schema.benchmark import ProcessEquivalenceBenchmarkManifest
from agent_assure.schema.campaign import (
    AssuranceMutationCampaign,
    AssuranceMutationCatalog,
)
from agent_assure.schema.common import harden_json_schema_pattern_ends
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
from agent_assure.schema.pilot import (
    ExternalPilotEvidence,
    ExternalPilotIndependenceReviewReceipt,
    PilotInputManifest,
)
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
from agent_assure.schema.stochastic_sensitivity import (
    RepeatedEvidenceSensitivityProtocol,
    StatisticalSufficiencyReport,
    StochasticEvidenceSensitivityReport,
)
from agent_assure.schema.stream import (
    StreamEventRecord,
    StreamIngestionDiagnostics,
    StreamRunRecord,
)
from agent_assure.schema.study import (
    RealModelStudyManifest,
    RealModelStudyReport,
    StudyExecutionReviewReceipt,
    StudyRegistrationReviewReceipt,
    StudyStatisticalMethodReviewReceipt,
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
from agent_assure.schema.v1_base import V1_SCHEMA_CONTRACT_IDS, V1_WRITER_SCHEMA_VERSION
from agent_assure.schema.v1_compatibility import (
    MAX_COMPATIBILITY_CELLS,
    MAX_COMPATIBILITY_MATRIX_BYTES,
    CompatibilityCell,
    CompatibilityMatrix,
)
from agent_assure.schema.v1_identity import SourceEventIdentity

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
        "external-pilot-evidence",
        "external-pilot-input-manifest",
        "external-pilot-independence-review",
        "expected-detection-contract",
        "process-equivalence-reproduction-index",
        "process-equivalence-benchmark",
        "evidence-sensitivity-protocol",
        "evidence-sensitivity-report",
        "rag-sensitivity-corpus-manifest",
        "rag-sensitivity-corpus-snapshot",
        "rag-sensitivity-knowledge-contract",
        "rag-sensitivity-synthetic-data-attestation",
        "repeated-evidence-sensitivity-protocol",
        "statistical-sufficiency-report",
        "stochastic-evidence-sensitivity-report",
        "threat-applicability-manifest",
        "real-model-study-manifest",
        "real-model-study-report",
        "real-model-study-execution-review",
        "real-model-study-registration-review",
        "real-model-study-statistical-method-review",
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
    "external-pilot-evidence": ExternalPilotEvidence,
    "external-pilot-input-manifest": PilotInputManifest,
    "external-pilot-independence-review": ExternalPilotIndependenceReviewReceipt,
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
    "process-equivalence-benchmark": ProcessEquivalenceBenchmarkManifest,
    "process-equivalence-reproduction-index": ProcessEquivalenceReproductionIndex,
    "release-artifact-manifest": ReleaseArtifactManifest,
    "release-digest-replay": ReleaseDigestReplay,
    "real-model-study-manifest": RealModelStudyManifest,
    "real-model-study-report": RealModelStudyReport,
    "real-model-study-execution-review": StudyExecutionReviewReceipt,
    "real-model-study-registration-review": StudyRegistrationReviewReceipt,
    "real-model-study-statistical-method-review": StudyStatisticalMethodReviewReceipt,
    "rag-sensitivity-corpus-manifest": RAGSensitivityCorpusManifest,
    "rag-sensitivity-corpus-snapshot": RAGSensitivityCorpusSnapshot,
    "rag-sensitivity-knowledge-contract": RAGSensitivityKnowledgeContract,
    "rag-sensitivity-synthetic-data-attestation": (RAGSensitivitySyntheticDataAttestation),
    "repeated-evidence-sensitivity-protocol": RepeatedEvidenceSensitivityProtocol,
    "run-set": RunSet,
    "span-plan": SpanPlan,
    "statistical-sufficiency-report": StatisticalSufficiencyReport,
    "stochastic-evidence-sensitivity-report": StochasticEvidenceSensitivityReport,
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
    harden_json_schema_pattern_ends(schema)
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


class SchemaExportError(ValueError):
    """The selected writer has no complete, identity-correct export profile."""


_V1_SCHEMA_MODELS: Mapping[str, SchemaModel] = MappingProxyType(
    {"source-event-identity/v1": SourceEventIdentity}
)


def _v1_schema_for_contract(contract_id: str, model: SchemaModel) -> dict[str, object]:
    """Check actual model identity without rewriting a legacy schema into v1."""
    schema: dict[str, object] = model.model_json_schema(mode="validation")
    properties = schema.get("properties")
    required = schema.get("required")
    if (
        schema.get("type") != "object"
        or schema.get("additionalProperties") is not False
        or not isinstance(properties, dict)
        or not isinstance(required, list)
    ):
        raise SchemaExportError(f"{contract_id} model lacks a closed required root identity")
    if contract_id == "source-event-identity/v1":
        fields = {"identity_contract_id", "run_id", "producer_id", "producer_epoch", "event_id"}
        if set(properties) != fields or set(required) != fields:
            raise SchemaExportError("source-event-identity/v1 model has the wrong exact field set")
        literals = {"identity_contract_id": contract_id}
        for name in fields - {"identity_contract_id"}:
            declaration = properties[name]
            if not isinstance(declaration, dict) or any(
                declaration.get(key) != value
                for key, value in {"type": "string", "minLength": 1, "maxLength": 512}.items()
            ):
                raise SchemaExportError("source-event-identity/v1 model has wrong component bounds")
    else:
        literals = {
            "contract_id": contract_id,
            "artifact_kind": contract_id.removesuffix("/v1"),
            "schema_version": V1_WRITER_SCHEMA_VERSION,
        }
    for name, literal in literals.items():
        declaration = properties.get(name)
        if (
            name not in required
            or not isinstance(declaration, dict)
            or declaration.get("type") != "string"
            or declaration.get("const") != literal
        ):
            raise SchemaExportError(f"{contract_id} model has the wrong {name} identity")
    harden_json_schema_pattern_ends(schema)
    return schema


def _v1_schema_documents() -> list[tuple[str, dict[str, object]]]:
    expected = frozenset(V1_SCHEMA_CONTRACT_IDS)
    actual = frozenset(_V1_SCHEMA_MODELS)
    unknown = actual - expected
    if unknown:
        raise SchemaExportError(f"unrecognized v1 contracts: {', '.join(sorted(unknown))}")
    documents = [
        (contract_id.removesuffix("/v1"), _v1_schema_for_contract(contract_id, model))
        for contract_id, model in sorted(_V1_SCHEMA_MODELS.items())
    ]
    missing = expected - actual
    if missing:
        raise SchemaExportError(
            f"{V1_WRITER_SCHEMA_VERSION} writer is incomplete; "
            f"missing {len(missing)} required contracts: {', '.join(sorted(missing))}"
        )
    return documents


def _writer_schema_payloads(
    writer_schema_version: str = SCHEMA_VERSION,
) -> list[tuple[str, str]]:
    """Prepare complete candidate resource bytes before any persistence."""
    if type(writer_schema_version) is not str or writer_schema_version not in {
        SCHEMA_VERSION,
        V1_WRITER_SCHEMA_VERSION,
    }:
        raise SchemaExportError(
            "unsupported writer schema version; expected an exact registered version"
        )
    documents: list[tuple[str, dict[str, object]]]
    if writer_schema_version == SCHEMA_VERSION:
        documents = []
        for kind, model in sorted(SCHEMA_MODELS.items()):
            schema = writer_json_schema(model)
            require_persisted_identity_in_schema(schema, kind)
            documents.append((kind, schema))
    else:
        documents = _v1_schema_documents()
    payloads: list[tuple[str, str]] = []
    for kind, schema in documents:
        schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        schema["$id"] = (
            "https://acblabs.github.io/agent-assure/schemas/"
            f"v{writer_schema_version}/{kind}.schema.json"
        )
        schema.setdefault("properties", {})
        payloads.append((kind, json.dumps(schema, indent=2, sort_keys=True) + "\n"))
    return payloads


def export_json_schemas(
    out_dir: Path, *, writer_schema_version: str = SCHEMA_VERSION
) -> list[Path]:
    # Prepare every model, identity and serialized resource before mkdir or
    # writing. Partial v1 catalogs never expose a partial resource directory.
    payloads = _writer_schema_payloads(writer_schema_version)
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for kind, payload in payloads:
        path = out_dir / f"{kind}.schema.json"
        write_text_atomic(path, payload)
        written.append(path)
    return written


# Historical producer facts verified against each local final tag's package
# __init__.py. This is not a reader dispatch registry: every cell's policy and
# reachable root still come only from FROZEN_ROOT_VALIDATION_POLICY.
_TAG_VERIFIED_LEGACY_PRODUCER_WRITERS: tuple[tuple[str, str], ...] = (
    ("0.1.0", "0.1.0"),
    ("0.2.0", "0.2.0"),
    ("0.3.0", "0.2.0"),
    ("0.3.1", "0.3.1"),
    ("0.4.2", "0.3.1"),
    ("0.4.4", "0.4.3"),
    ("0.5.0", "0.5.0"),
    ("0.6.0", "0.6.0"),
    ("0.6.1", "0.6.1"),
    ("0.6.2", "0.6.2"),
    ("0.6.3", "0.6.3"),
    ("0.6.4", "0.6.4"),
    ("0.6.5", "0.6.5"),
    ("0.7.0", "0.6.6"),
)
_COMPATIBILITY_READER_VERSION = "1.0.0a3"
_LEGACY_COMPATIBILITY_RESTRICTIONS = (
    "Compatibility inspection grants no qualification, release, deployment or method admission.",
    "Historical semantics do not establish v1 action consumption, closure or deployment authority.",
    "Runtime authorization requires independently verified current policy and evidence.",
)


def build_legacy_compatibility_matrix(*, schema_root: Path | None = None) -> CompatibilityMatrix:
    """Build a deterministic value without modifying a resource or source file.

    An explicit schema_root is a trusted frozen-source directory. Otherwise
    resources must belong to a verified installed wheel; no checkout fallback
    is attempted. The caller separately authenticates the immutable source or
    candidate inventory. This builder hashes original bytes, validates their
    declared vocabulary, and grants no runtime or release authority.
    """
    from agent_assure.schema import validation as schema_validation

    if schema_root is not None and (
        not isinstance(schema_root, Path) or not schema_root.is_absolute()
    ):
        raise ValueError("compatibility schema root must be an explicit absolute Path")
    installed_reader = (
        schema_validation._installed_reader_identity() if schema_root is None else None
    )
    producers = _TAG_VERIFIED_LEGACY_PRODUCER_WRITERS
    if agent_assure.__version__ == _COMPATIBILITY_READER_VERSION:
        if SCHEMA_VERSION != "0.6.6":
            raise ValueError("preview compatibility requires the preserved legacy default writer")
        producers = (*producers, (_COMPATIBILITY_READER_VERSION, SCHEMA_VERSION))
    pairs = schema_validation.FROZEN_ROOT_VALIDATION_POLICY
    selected = tuple(
        sorted(
            (producer, wire, kind)
            for producer, wire in producers
            for kind, registered_wire in pairs
            if registered_wire == wire
        )
    )
    if not selected or len(selected) > MAX_COMPATIBILITY_CELLS:
        raise ValueError("compatibility matrix exceeds its reviewed finite cell inventory")
    if {wire for _, wire in producers} != {wire for _, wire, _ in selected}:
        raise ValueError("compatibility matrix lacks a declared legacy writer's frozen policy")
    resources: dict[tuple[str, str], str] = {}
    cells: list[CompatibilityCell] = []
    for producer, wire, kind in selected:
        resource_key = (kind, wire)
        if resource_key not in resources:
            relative = f"v{wire}/{kind}.schema.json"
            if schema_root is not None:
                raw = read_file_bounded_at(
                    schema_root,
                    relative,
                    max_bytes=schema_validation.MAX_FROZEN_SCHEMA_BYTES,
                    label="frozen compatibility schema",
                ).data
            else:
                if installed_reader is None:
                    raise AssertionError("installed compatibility reader identity was lost")
                loaded = schema_validation._read_installed_compatibility_resource(
                    installed_reader,
                    relative,
                    max_bytes=schema_validation.MAX_FROZEN_SCHEMA_BYTES,
                )
                if loaded is None:
                    raise ValueError(
                        "compatibility matrix requires every immutable schema resource"
                    )
                raw = loaded
            if len(raw) > schema_validation.MAX_FROZEN_SCHEMA_BYTES:
                raise ValueError("frozen compatibility schema exceeds maximum supported size")
            digest = f"sha256:{hashlib.sha256(raw).hexdigest()}"
            schema = load_json_bytes_bounded(
                raw,
                max_bytes=schema_validation.MAX_FROZEN_SCHEMA_BYTES,
                label="frozen compatibility schema",
            )
            schema_validation._prepare_frozen_schema(schema, schema_version=wire, kind=kind)
            schema_validation._harden_frozen_decimal_patterns(schema)
            harden_json_schema_pattern_ends(schema)
            schema_validation._require_frozen_identity_admission(
                schema, schema_version=wire, kind=kind
            )
            resources[resource_key] = digest
        policy = pairs[resource_key]
        replay = schema_validation._frozen_root_semantic_replay_identity(kind, wire)
        cells.append(
            CompatibilityCell(
                producer_package_version=producer,
                writer_schema_version=wire,
                artifact_kind=kind,
                reader_package_version=_COMPATIBILITY_READER_VERSION,
                disposition=(
                    "shape_and_integrity_only"
                    if policy is schema_validation.FrozenRootValidationPolicy.archival_only
                    else "semantic_replay_and_authorization_eligible"
                ),
                minimum_reader_version=_COMPATIBILITY_READER_VERSION,
                schema_resource_digest=resources[resource_key],
                semantic_replay_identity=replay,
                migration_identity=None,
                losses=(),
                authorization_restrictions=_LEGACY_COMPATIBILITY_RESTRICTIONS,
            )
        )
    return CompatibilityMatrix(format="agent-assure-compatibility-matrix/v1", cells=tuple(cells))


def compatibility_matrix_json_bytes(matrix: CompatibilityMatrix) -> bytes:
    """Encode deterministic reviewed JSON, stopping before the byte cap is exceeded."""
    encoder = json.JSONEncoder(indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False)
    chunks: list[bytes] = []
    total = 1  # Reserve the required final LF within the same byte cap.
    for chunk in encoder.iterencode(matrix.model_dump(mode="json")):
        encoded = chunk.encode("utf-8")
        total += len(encoded)
        if total > MAX_COMPATIBILITY_MATRIX_BYTES:
            raise ValueError("compatibility matrix JSON exceeds maximum supported size")
        chunks.append(encoded)
    return b"".join(chunks) + b"\n"
