from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from agent_assure import __version__
from agent_assure.authoring.compiler import compile_suite
from agent_assure.authoring.yaml_nodes import safe_load_yaml_text
from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.evaluation.evaluator import evaluate_runset
from agent_assure.fixtures.loader import compiled_suite_digest
from agent_assure.fixtures.manifest import (
    build_fixture_manifest,
    fixture_manifest_digest,
    resolve_case_fixture_paths,
    verify_fixture_manifest,
)
from agent_assure.fixtures.resolver import FixtureResolver
from agent_assure.io_limits import (
    MAX_ARTIFACT_JSON_BYTES,
    MAX_CONFIG_TEXT_BYTES,
    loads_json_bounded,
    read_file_bounded,
    read_file_bounded_at,
    read_file_bounded_from_filesystem_root,
)
from agent_assure.onboarding.path_safety import (
    metadata_is_regular_directory,
    metadata_is_regular_file,
    metadata_is_reparse,
    require_regular_directory_chain,
)
from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.schema.common import ExecutionMode, GateState
from agent_assure.schema.evaluation import EvaluationSummary
from agent_assure.schema.provenance import Provenance
from agent_assure.schema.run import (
    AgentRunRecord,
    ClaimEvidenceLink,
    ClaimRecord,
    EvidenceItem,
    EvidenceRef,
    RunSet,
)
from agent_assure.schema.sensitivity import (
    CONTROLLED_DIFFERENCE_DIMENSIONS,
    MAX_SENSITIVITY_CORPUS_BYTES,
    REQUIRED_SENSITIVITY_LIMITATIONS,
    DetectorTestStatus,
    EvidenceSensitivityArmRole,
    EvidenceSensitivityDifferenceCheck,
    EvidenceSensitivityDifferenceManifest,
    EvidenceSensitivityDifferenceState,
    EvidenceSensitivityExpectedRelation,
    RAGSensitivityArmResult,
    RAGSensitivityAuthorityAssignment,
    RAGSensitivityCorpusControlProjection,
    RAGSensitivityCorpusEvidenceBinding,
    RAGSensitivityCorpusManifest,
    RAGSensitivityCorpusSnapshot,
    RAGSensitivityCorpusSnapshotDocument,
    RAGSensitivityDocumentPayload,
    RAGSensitivityEvidenceLinkProjection,
    RAGSensitivityFixtureFileSnapshot,
    RAGSensitivityFixtureRole,
    RAGSensitivityKnowledgeContract,
    RAGSensitivityProtocol,
    RAGSensitivityReport,
    RAGSensitivityRequest,
    RAGSensitivityRetrievedEvidence,
    RAGSensitivitySubjectConfig,
    RAGSensitivitySyntheticDataAttestation,
    RAGSensitivityToolConfig,
    SyntheticDataProvenance,
    derive_corpus_control_projection,
    derive_sensitivity_assessment,
    derive_sensitivity_subject_output,
    derive_snapshot_retrieval,
    normalize_sensitivity_query,
)
from agent_assure.schema.suite import CompiledSuite, FixtureManifest
from agent_assure.sensitivity_contract import (
    SENSITIVITY_EVALUATION_DATE,
    bundled_sensitivity_identity_set,
)

CORPUS_MANIFEST_FILENAME = "corpus-manifest.json"
SENSITIVITY_RUNNER_ID = "rag_sensitivity.synthetic"
MAX_SENSITIVITY_CORPUS_INVENTORY_ENTRIES = 8_192
MAX_SENSITIVITY_CORPUS_DIRECTORIES = 2_048
MAX_SENSITIVITY_CORPUS_DEPTH = 16
SENSITIVITY_METHOD_ASSUMPTIONS = (
    "The knowledge-authority contract correctly declares which contextual evidence governs "
    "the synthetic task.",
    "The committed fixture subject and lexical retriever are deterministic contract-test "
    "components, not measurements of a hosted model.",
)


class SensitivityInputError(ValueError):
    """Raised when a sensitivity input cannot support a trusted execution."""


@dataclass(frozen=True)
class LoadedSensitivityCorpus:
    root: Path
    manifest: RAGSensitivityCorpusManifest
    manifest_file_sha256: str
    documents: tuple[RAGSensitivityDocumentPayload, ...]
    document_content_digests: tuple[str, ...]
    evidence_bindings: tuple[RAGSensitivityCorpusEvidenceBinding, ...]
    evidence_set_digest: str
    snapshot: RAGSensitivityCorpusSnapshot


@dataclass(frozen=True)
class _ArmExecution:
    runset: RunSet
    evaluation: EvaluationSummary
    result: RAGSensitivityArmResult


@dataclass(frozen=True)
class _SensitivityArmInputs:
    compiled_suite: CompiledSuite
    fixture_manifest: FixtureManifest
    fixture_manifest_digest: str
    suite_digest: str
    request: RAGSensitivityRequest
    request_digest: str
    query_digest: str
    subject: RAGSensitivitySubjectConfig
    subject_digest: str
    tool: RAGSensitivityToolConfig
    tool_digest: str
    fixture_snapshots: tuple[RAGSensitivityFixtureFileSnapshot, ...]
    authority_contract: RAGSensitivityKnowledgeContract


@dataclass(frozen=True)
class SensitivityExecutionArtifacts:
    compiled_suite: CompiledSuite
    fixture_manifest: FixtureManifest
    protocol: RAGSensitivityProtocol
    report: RAGSensitivityReport
    baseline_runset: RunSet
    counterfactual_runset: RunSet
    baseline_evaluation: EvaluationSummary
    counterfactual_evaluation: EvaluationSummary


def execute_sensitivity_experiment(
    *,
    suite_path: Path,
    baseline_corpus_dir: Path,
    counterfactual_corpus_dir: Path,
    knowledge_contract_path: Path,
    expected_relation: EvidenceSensitivityExpectedRelation,
    synthetic_data_attestation_path: Path | None = None,
) -> SensitivityExecutionArtifacts:
    """Rerun one deterministic RAG subject from the beginning for each corpus arm."""
    baseline_inputs = _load_arm_inputs(
        suite_path=suite_path,
        knowledge_contract_path=knowledge_contract_path,
    )
    counterfactual_inputs = _load_arm_inputs(
        suite_path=suite_path,
        knowledge_contract_path=knowledge_contract_path,
        fixture_manifest=baseline_inputs.fixture_manifest,
    )
    try:
        verify_fixture_manifest(
            baseline_inputs.fixture_manifest,
            counterfactual_inputs.compiled_suite,
            suite_path.parent,
        )
    except (OSError, RuntimeError, TypeError, ValidationError, ValueError) as exc:
        raise SensitivityInputError(
            "sensitivity fixtures changed during independent arm setup"
        ) from exc
    _require_identical_protocol_inputs(baseline_inputs, counterfactual_inputs)
    baseline_corpus, counterfactual_corpus = _load_distinct_corpora(
        baseline_corpus_dir,
        counterfactual_corpus_dir,
    )
    compiled = baseline_inputs.compiled_suite
    fixture_manifest = baseline_inputs.fixture_manifest
    fixture_digest = baseline_inputs.fixture_manifest_digest
    suite_digest = baseline_inputs.suite_digest
    request = baseline_inputs.request
    subject = baseline_inputs.subject
    tool = baseline_inputs.tool
    fixture_snapshots = baseline_inputs.fixture_snapshots
    contract = baseline_inputs.authority_contract
    if contract.expected_response_relation is not expected_relation:
        raise SensitivityInputError(
            "--expected-relation must exactly match the knowledge-authority contract"
        )
    synthetic_data_provenance, synthetic_data_attestation = _resolve_synthetic_data_provenance(
        suite_digest=suite_digest,
        fixture_manifest_digest=fixture_digest,
        authority_contract=contract,
        baseline=baseline_corpus,
        counterfactual=counterfactual_corpus,
        attestation_path=synthetic_data_attestation_path,
    )

    baseline_control = derive_corpus_control_projection(
        baseline_corpus.snapshot,
        contract,
    )
    counterfactual_control = derive_corpus_control_projection(
        counterfactual_corpus.snapshot,
        contract,
    )

    request_digest = baseline_inputs.request_digest
    subject_digest = baseline_inputs.subject_digest
    tool_digest = baseline_inputs.tool_digest
    query_digest = baseline_inputs.query_digest
    difference_manifest = _build_difference_manifest(
        baseline_inputs=baseline_inputs,
        counterfactual_inputs=counterfactual_inputs,
        baseline=baseline_corpus,
        counterfactual=counterfactual_corpus,
        baseline_control=baseline_control,
        counterfactual_control=counterfactual_control,
    )
    case = compiled.cases[0]
    protocol_id = (
        "rag-sensitivity-"
        + sha256_hexdigest(
            {
                "suite_digest": suite_digest,
                "fixture_manifest_digest": fixture_digest,
                "subject_configuration_digest": subject_digest,
                "baseline_corpus_digest": baseline_corpus.manifest.corpus_digest,
                "counterfactual_corpus_digest": counterfactual_corpus.manifest.corpus_digest,
                "baseline_corpus_snapshot_digest": baseline_corpus.snapshot.snapshot_digest,
                "counterfactual_corpus_snapshot_digest": (
                    counterfactual_corpus.snapshot.snapshot_digest
                ),
                "knowledge_contract_digest": contract.knowledge_contract_digest,
                "expected_relation": expected_relation.value,
            }
        )[:24]
    )
    protocol = RAGSensitivityProtocol.build(
        protocol_id=protocol_id,
        suite_id=compiled.suite_id,
        suite_digest=suite_digest,
        fixture_manifest_digest=fixture_digest,
        case_id=case.case_id,
        fixture_id=case.fixture_id or case.case_id,
        subject_id=subject.subject_id,
        provider="synthetic-fixture",
        model_id=subject.model_id,
        tool_id=tool.tool_id,
        fixture_manifest=fixture_manifest,
        fixture_snapshots=fixture_snapshots,
        request=request,
        subject_configuration=subject,
        tool_configuration=tool,
        request_digest=request_digest,
        query_family_id=request.query_family_id,
        query_digest=query_digest,
        subject_configuration_digest=subject_digest,
        agent_implementation_digest=subject.agent_implementation_digest,
        prompt_template_digest=subject.prompt_template_digest,
        model_digest=subject.model_digest,
        tool_configuration_digest=tool_digest,
        tool_schema_digest=tool.tool_schema_digest,
        retrieval_algorithm_id=tool.retrieval_algorithm_id,
        retrieval_algorithm_version=tool.retrieval_algorithm_version,
        retrieval_top_k=tool.top_k,
        producer_version=__version__,
        deterministic=True,
        detector_test_status=DetectorTestStatus.synthetic_detector_contract_test,
        synthetic_data_provenance=synthetic_data_provenance,
        synthetic_data_attestation_digest=(
            synthetic_data_attestation.attestation_digest
            if synthetic_data_attestation is not None
            else None
        ),
        synthetic_data_attestation=synthetic_data_attestation,
        endpoint="expected_decision_response",
        baseline_corpus_digest=baseline_corpus.manifest.corpus_digest,
        counterfactual_corpus_digest=counterfactual_corpus.manifest.corpus_digest,
        baseline_corpus_snapshot_digest=baseline_corpus.snapshot.snapshot_digest,
        counterfactual_corpus_snapshot_digest=(counterfactual_corpus.snapshot.snapshot_digest),
        baseline_corpus_document_catalog_digest=(baseline_control.document_catalog_digest),
        counterfactual_corpus_document_catalog_digest=(
            counterfactual_control.document_catalog_digest
        ),
        baseline_non_governing_evidence_digest=(baseline_control.non_governing_evidence_digest),
        counterfactual_non_governing_evidence_digest=(
            counterfactual_control.non_governing_evidence_digest
        ),
        baseline_governing_retrieval_identity_digest=(
            baseline_control.governing_retrieval_identity_digest
        ),
        counterfactual_governing_retrieval_identity_digest=(
            counterfactual_control.governing_retrieval_identity_digest
        ),
        baseline_governing_evidence_digest=(baseline_control.governing_evidence_digest),
        counterfactual_governing_evidence_digest=(counterfactual_control.governing_evidence_digest),
        baseline_corpus_query_family_id=baseline_corpus.manifest.query_family_id,
        counterfactual_corpus_query_family_id=(counterfactual_corpus.manifest.query_family_id),
        baseline_retrieval_algorithm_id=(baseline_corpus.manifest.retrieval_algorithm_id),
        counterfactual_retrieval_algorithm_id=(
            counterfactual_corpus.manifest.retrieval_algorithm_id
        ),
        baseline_retrieval_algorithm_version=(baseline_corpus.manifest.retrieval_algorithm_version),
        counterfactual_retrieval_algorithm_version=(
            counterfactual_corpus.manifest.retrieval_algorithm_version
        ),
        baseline_retrieval_top_k=baseline_corpus.manifest.top_k,
        counterfactual_retrieval_top_k=counterfactual_corpus.manifest.top_k,
        baseline_corpus_manifest_file_sha256=baseline_corpus.manifest_file_sha256,
        counterfactual_corpus_manifest_file_sha256=(counterfactual_corpus.manifest_file_sha256),
        baseline_evidence_set_digest=baseline_corpus.evidence_set_digest,
        counterfactual_evidence_set_digest=counterfactual_corpus.evidence_set_digest,
        knowledge_contract_digest=contract.knowledge_contract_digest,
        expected_relation=expected_relation,
        controlled_difference_manifest=difference_manifest,
        assumptions=SENSITIVITY_METHOD_ASSUMPTIONS,
        limitations=(*REQUIRED_SENSITIVITY_LIMITATIONS, *contract.limitations),
    )

    assignments = {item.corpus_digest: item for item in contract.assignments}
    baseline_execution = _execute_arm(
        role=EvidenceSensitivityArmRole.baseline,
        compiled=baseline_inputs.compiled_suite,
        fixture_manifest=baseline_inputs.fixture_manifest,
        request=baseline_inputs.request,
        subject=baseline_inputs.subject,
        tool=baseline_inputs.tool,
        corpus=baseline_corpus,
        assignment=assignments.get(baseline_corpus.manifest.corpus_digest),
        protocol=protocol,
    )
    counterfactual_execution = _execute_arm(
        role=EvidenceSensitivityArmRole.counterfactual,
        compiled=counterfactual_inputs.compiled_suite,
        fixture_manifest=counterfactual_inputs.fixture_manifest,
        request=counterfactual_inputs.request,
        subject=counterfactual_inputs.subject,
        tool=counterfactual_inputs.tool,
        corpus=counterfactual_corpus,
        assignment=assignments.get(counterfactual_corpus.manifest.corpus_digest),
        protocol=protocol,
    )
    report = _build_report(
        compiled_suite=compiled,
        protocol=protocol,
        contract=contract,
        baseline=baseline_execution.result,
        counterfactual=counterfactual_execution.result,
        baseline_snapshot=baseline_corpus.snapshot,
        counterfactual_snapshot=counterfactual_corpus.snapshot,
        baseline_runset=baseline_execution.runset,
        counterfactual_runset=counterfactual_execution.runset,
        baseline_evaluation=baseline_execution.evaluation,
        counterfactual_evaluation=counterfactual_execution.evaluation,
    )
    return SensitivityExecutionArtifacts(
        compiled_suite=compiled,
        fixture_manifest=fixture_manifest,
        protocol=protocol,
        report=report,
        baseline_runset=baseline_execution.runset,
        counterfactual_runset=counterfactual_execution.runset,
        baseline_evaluation=baseline_execution.evaluation,
        counterfactual_evaluation=counterfactual_execution.evaluation,
    )


def load_knowledge_contract(path: Path) -> RAGSensitivityKnowledgeContract:
    try:
        snapshot = read_file_bounded_from_filesystem_root(
            path,
            max_bytes=MAX_CONFIG_TEXT_BYTES,
            label="knowledge-authority contract",
        )
        loaded = safe_load_yaml_text(
            snapshot.data.decode("utf-8"),
            label="knowledge-authority contract",
        )
        if not isinstance(loaded, dict):
            raise TypeError("knowledge-authority contract root must be a mapping")
        return RAGSensitivityKnowledgeContract.model_validate(loaded)
    except (OSError, TypeError, UnicodeDecodeError, ValidationError, ValueError) as exc:
        raise SensitivityInputError("knowledge-authority contract is invalid") from exc


def load_sensitivity_report(path: Path) -> RAGSensitivityReport:
    try:
        snapshot = read_file_bounded(
            path,
            max_bytes=MAX_ARTIFACT_JSON_BYTES,
            label="evidence sensitivity report",
        )
        payload = loads_json_bounded(
            snapshot.data.decode("utf-8"),
            label="evidence sensitivity report",
        )
        return RAGSensitivityReport.model_validate(payload)
    except (OSError, TypeError, UnicodeDecodeError, ValidationError, ValueError) as exc:
        raise SensitivityInputError("evidence sensitivity report is invalid") from exc


def load_synthetic_data_attestation(
    path: Path,
) -> RAGSensitivitySyntheticDataAttestation:
    try:
        snapshot = read_file_bounded(
            path,
            max_bytes=MAX_CONFIG_TEXT_BYTES,
            label="synthetic-data attestation",
        )
        payload = loads_json_bounded(
            snapshot.data.decode("utf-8"),
            label="synthetic-data attestation",
        )
        return RAGSensitivitySyntheticDataAttestation.model_validate(payload)
    except (OSError, TypeError, UnicodeDecodeError, ValidationError, ValueError) as exc:
        raise SensitivityInputError("synthetic-data attestation is invalid") from exc


def _resolve_synthetic_data_provenance(
    *,
    suite_digest: str,
    fixture_manifest_digest: str,
    authority_contract: RAGSensitivityKnowledgeContract,
    baseline: LoadedSensitivityCorpus,
    counterfactual: LoadedSensitivityCorpus,
    attestation_path: Path | None,
) -> tuple[SyntheticDataProvenance, RAGSensitivitySyntheticDataAttestation | None]:
    corpus_snapshot_identities = {
        baseline.manifest.corpus_digest: baseline.snapshot.snapshot_digest,
        counterfactual.manifest.corpus_digest: counterfactual.snapshot.snapshot_digest,
    }
    identity_set = bundled_sensitivity_identity_set(authority_contract.schema_version)
    bundled = (
        identity_set is not None
        and (suite_digest, fixture_manifest_digest) in identity_set.suite_identities
        and authority_contract.knowledge_contract_digest
        == identity_set.knowledge_contract_digest
        and frozenset(corpus_snapshot_identities.items())
        == identity_set.corpus_snapshot_identities
    )
    if bundled:
        if attestation_path is not None:
            raise SensitivityInputError(
                "bundled digest-verified sensitivity inputs must not supply an attestation"
            )
        return SyntheticDataProvenance.bundled_digest_verified, None
    if attestation_path is None:
        raise SensitivityInputError(
            "custom sensitivity inputs require --synthetic-data-attestation"
        )
    attestation = load_synthetic_data_attestation(attestation_path)
    expected_binding = (
        suite_digest,
        fixture_manifest_digest,
        authority_contract.knowledge_contract_digest,
        tuple(sorted(corpus_snapshot_identities)),
        tuple(sorted(corpus_snapshot_identities.values())),
    )
    actual_binding = (
        attestation.suite_digest,
        attestation.fixture_manifest_digest,
        attestation.knowledge_contract_digest,
        attestation.corpus_digests,
        attestation.corpus_snapshot_digests,
    )
    if actual_binding != expected_binding:
        raise SensitivityInputError(
            "synthetic-data attestation does not bind the exact sensitivity inputs"
        )
    return SyntheticDataProvenance.operator_attested, attestation


def _load_arm_inputs(
    *,
    suite_path: Path,
    knowledge_contract_path: Path,
    fixture_manifest: FixtureManifest | None = None,
) -> _SensitivityArmInputs:
    compiled = _load_sensitivity_suite(suite_path)
    manifest = (
        build_fixture_manifest(compiled, suite_path.parent)
        if fixture_manifest is None
        else fixture_manifest
    )
    request, subject, tool, fixture_snapshots = _load_bound_subject_fixture(
        compiled,
        suite_path.parent,
        manifest,
    )
    return _SensitivityArmInputs(
        compiled_suite=compiled,
        fixture_manifest=manifest,
        fixture_manifest_digest=fixture_manifest_digest(manifest),
        suite_digest=compiled_suite_digest(compiled),
        request=request,
        request_digest=sha256_hexdigest(request.model_dump(mode="json")),
        query_digest=sha256_hexdigest(
            {"normalized_query": normalize_sensitivity_query(request.query)}
        ),
        subject=subject,
        subject_digest=sha256_hexdigest(subject.model_dump(mode="json")),
        tool=tool,
        tool_digest=sha256_hexdigest(tool.model_dump(mode="json")),
        fixture_snapshots=fixture_snapshots,
        authority_contract=load_knowledge_contract(knowledge_contract_path),
    )


def _require_identical_protocol_inputs(
    baseline: _SensitivityArmInputs,
    counterfactual: _SensitivityArmInputs,
) -> None:
    comparisons = (
        ("compiled suite", baseline.compiled_suite, counterfactual.compiled_suite),
        ("fixture manifest", baseline.fixture_manifest, counterfactual.fixture_manifest),
        ("fixture snapshots", baseline.fixture_snapshots, counterfactual.fixture_snapshots),
        ("request", baseline.request, counterfactual.request),
        ("subject configuration", baseline.subject, counterfactual.subject),
        ("tool configuration", baseline.tool, counterfactual.tool),
        (
            "knowledge-authority contract",
            baseline.authority_contract,
            counterfactual.authority_contract,
        ),
    )
    changed = tuple(label for label, left, right in comparisons if left != right)
    if changed:
        raise SensitivityInputError(
            "protocol-fixed inputs changed between independent arm setup: " + ", ".join(changed)
        )


def write_sensitivity_artifacts(
    artifacts: SensitivityExecutionArtifacts,
    out_dir: Path,
) -> dict[str, Path]:
    from agent_assure.reporting.sensitivity import write_sensitivity_execution_artifacts

    return write_sensitivity_execution_artifacts(artifacts, out_dir)


def _load_sensitivity_suite(path: Path) -> CompiledSuite:
    try:
        compiled = compile_suite(path)
    except (OSError, TypeError, ValidationError, ValueError) as exc:
        raise SensitivityInputError("sensitivity suite is invalid") from exc
    if compiled.defaults.execution_mode is not ExecutionMode.fixture:
        raise SensitivityInputError("sensitivity v1 supports deterministic fixture mode only")
    if compiled.defaults.runner_id != SENSITIVITY_RUNNER_ID:
        raise SensitivityInputError(f"sensitivity suite runner must be {SENSITIVITY_RUNNER_ID!r}")
    if len(compiled.cases) != 1:
        raise SensitivityInputError("sensitivity v1 requires exactly one suite case")
    return compiled


def _load_bound_subject_fixture(
    compiled: CompiledSuite,
    suite_root: Path,
    manifest: FixtureManifest,
) -> tuple[
    RAGSensitivityRequest,
    RAGSensitivitySubjectConfig,
    RAGSensitivityToolConfig,
    tuple[RAGSensitivityFixtureFileSnapshot, ...],
]:
    resolver = FixtureResolver(suite_root)
    case = compiled.cases[0]
    paths = resolve_case_fixture_paths(
        compiled,
        resolver,
        case.fixture_id or case.case_id,
    )
    entries = {entry.path: entry for entry in manifest.entries}
    try:
        request_payload, request_snapshot = _read_bound_fixture_json(
            resolver,
            paths["requests"],
            entries,
            role=RAGSensitivityFixtureRole.request,
            label="sensitivity request fixture",
        )
        subject_payload, subject_snapshot = _read_bound_fixture_json(
            resolver,
            paths["model_outputs"],
            entries,
            role=RAGSensitivityFixtureRole.subject_configuration,
            label="sensitivity subject fixture",
        )
        tool_payload, tool_snapshot = _read_bound_fixture_json(
            resolver,
            paths["tool_outputs"],
            entries,
            role=RAGSensitivityFixtureRole.tool_configuration,
            label="sensitivity tool fixture",
        )
        request = RAGSensitivityRequest.model_validate(request_payload)
        subject = RAGSensitivitySubjectConfig.model_validate(subject_payload)
        tool = RAGSensitivityToolConfig.model_validate(tool_payload)
    except (KeyError, OSError, TypeError, ValidationError, ValueError) as exc:
        raise SensitivityInputError("sensitivity subject fixtures are invalid") from exc
    if request.query_family_id != compiled.cases[0].case_id and (
        request.query_family_id not in compiled.cases[0].tags
    ):
        # The suite must explicitly carry the query family, either as its case ID
        # or as a stable tag. This prevents a display-only request field.
        raise SensitivityInputError("suite does not bind the request query family")
    return request, subject, tool, (request_snapshot, subject_snapshot, tool_snapshot)


def _read_bound_fixture_json(
    resolver: FixtureResolver,
    path: Path,
    entries: dict[str, Any],
    *,
    role: RAGSensitivityFixtureRole,
    label: str,
) -> tuple[dict[str, object], RAGSensitivityFixtureFileSnapshot]:
    relative = resolver.manifest_path(path)
    entry = entries.get(relative)
    if entry is None:
        raise ValueError(f"{label} is absent from the fixture manifest")
    snapshot = read_file_bounded_at(
        resolver.resolved_root,
        relative,
        max_bytes=MAX_ARTIFACT_JSON_BYTES,
        label=label,
    )
    if snapshot.size != entry.size_bytes or snapshot.sha256 != entry.sha256:
        raise ValueError(f"{label} changed after manifest construction")
    content_utf8 = snapshot.data.decode("utf-8")
    payload = loads_json_bounded(content_utf8, label=label)
    if not isinstance(payload, dict):
        raise TypeError(f"{label} root must be an object")
    exact_snapshot = RAGSensitivityFixtureFileSnapshot(
        role=role,
        path=relative,
        sha256=snapshot.sha256,
        size_bytes=snapshot.size,
        content_utf8=content_utf8,
    )
    return {str(key): value for key, value in payload.items()}, exact_snapshot


def _load_distinct_corpora(
    baseline_dir: Path,
    counterfactual_dir: Path,
) -> tuple[LoadedSensitivityCorpus, LoadedSensitivityCorpus]:
    try:
        baseline_resolved = baseline_dir.resolve(strict=True)
        counterfactual_resolved = counterfactual_dir.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise SensitivityInputError("sensitivity corpus directory is unavailable") from exc
    if baseline_resolved == counterfactual_resolved:
        raise SensitivityInputError("baseline and counterfactual corpora must be distinct")
    baseline = load_sensitivity_corpus(baseline_dir)
    counterfactual = load_sensitivity_corpus(counterfactual_dir)
    if baseline.manifest.corpus_digest == counterfactual.manifest.corpus_digest:
        raise SensitivityInputError("baseline and counterfactual corpus digests must differ")
    return baseline, counterfactual


def load_sensitivity_corpus(corpus_dir: Path) -> LoadedSensitivityCorpus:
    try:
        require_regular_directory_chain(corpus_dir)
        before_inventory = _corpus_inventory(corpus_dir)
        manifest_snapshot = read_file_bounded_at(
            corpus_dir,
            CORPUS_MANIFEST_FILENAME,
            max_bytes=MAX_ARTIFACT_JSON_BYTES,
            label="sensitivity corpus manifest",
        )
        manifest_utf8 = manifest_snapshot.data.decode("utf-8")
        manifest_payload = loads_json_bounded(
            manifest_utf8,
            label="sensitivity corpus manifest",
        )
        manifest = RAGSensitivityCorpusManifest.model_validate(manifest_payload)
        expected_inventory = {
            CORPUS_MANIFEST_FILENAME,
            *(item.path for item in manifest.documents),
        }
        if before_inventory != expected_inventory:
            raise ValueError("sensitivity corpus inventory does not match its manifest")

        total_read_bytes = manifest_snapshot.size
        documents: list[RAGSensitivityDocumentPayload] = []
        content_digests: list[str] = []
        bindings: list[RAGSensitivityCorpusEvidenceBinding] = []
        snapshot_documents: list[RAGSensitivityCorpusSnapshotDocument] = []
        for descriptor in manifest.documents:
            snapshot = read_file_bounded_at(
                corpus_dir,
                descriptor.path,
                max_bytes=MAX_ARTIFACT_JSON_BYTES,
                label="sensitivity corpus document",
            )
            total_read_bytes += snapshot.size
            if total_read_bytes > MAX_SENSITIVITY_CORPUS_BYTES:
                raise ValueError("sensitivity corpus exceeds the aggregate byte limit")
            if snapshot.sha256 != descriptor.content_digest:
                raise ValueError("sensitivity corpus document digest mismatch")
            content_utf8 = snapshot.data.decode("utf-8")
            payload = loads_json_bounded(
                content_utf8,
                label="sensitivity corpus document",
            )
            document = RAGSensitivityDocumentPayload.model_validate(payload)
            if document.source_id != descriptor.source_id:
                raise ValueError("sensitivity corpus document source identity mismatch")
            documents.append(document)
            snapshot_documents.append(
                RAGSensitivityCorpusSnapshotDocument(
                    descriptor=descriptor,
                    payload=document,
                    content_utf8=content_utf8,
                )
            )
            content_digests.append(snapshot.sha256)
            bindings.append(
                RAGSensitivityCorpusEvidenceBinding(
                    source_id=document.source_id,
                    ref_id=document.ref_id,
                    content_digest=snapshot.sha256,
                    governing_decision=document.governing_decision,
                    governing_outcome=document.governing_outcome,
                )
            )
        if _corpus_inventory(corpus_dir) != before_inventory:
            raise ValueError("sensitivity corpus inventory changed during validation")
        canonical_bindings = tuple(sorted(bindings, key=lambda item: (item.source_id, item.ref_id)))
        corpus_snapshot = RAGSensitivityCorpusSnapshot.build(
            corpus_manifest=manifest,
            corpus_manifest_file_sha256=manifest_snapshot.sha256,
            corpus_manifest_utf8=manifest_utf8,
            documents=tuple(snapshot_documents),
        )
        return LoadedSensitivityCorpus(
            root=corpus_dir.resolve(strict=True),
            manifest=manifest,
            manifest_file_sha256=manifest_snapshot.sha256,
            documents=tuple(documents),
            document_content_digests=tuple(content_digests),
            evidence_bindings=canonical_bindings,
            evidence_set_digest=sha256_hexdigest(
                tuple(item.model_dump(mode="json") for item in canonical_bindings)
            ),
            snapshot=corpus_snapshot,
        )
    except (
        OSError,
        RuntimeError,
        TypeError,
        UnicodeDecodeError,
        ValidationError,
        ValueError,
    ) as exc:
        raise SensitivityInputError(
            "sensitivity corpus is invalid or its digest does not match"
        ) from exc


def _corpus_inventory(root: Path) -> set[str]:
    inventory: set[str] = set()
    pending = [(root, 0)]
    entry_count = 0
    directory_count = 1
    aggregate_file_bytes = 0
    if directory_count > MAX_SENSITIVITY_CORPUS_DIRECTORIES:
        raise ValueError("sensitivity corpus inventory exceeds the directory limit")
    while pending:
        directory, depth = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                entry_count += 1
                if entry_count > MAX_SENSITIVITY_CORPUS_INVENTORY_ENTRIES:
                    raise ValueError("sensitivity corpus inventory exceeds the entry limit")
                path = Path(entry.path)
                metadata = entry.stat(follow_symlinks=False)
                if metadata_is_reparse(metadata):
                    raise ValueError("sensitivity corpus refuses symbolic or reparse links")
                if metadata_is_regular_directory(metadata):
                    if depth >= MAX_SENSITIVITY_CORPUS_DEPTH:
                        raise ValueError("sensitivity corpus exceeds the directory depth limit")
                    directory_count += 1
                    if directory_count > MAX_SENSITIVITY_CORPUS_DIRECTORIES:
                        raise ValueError("sensitivity corpus inventory exceeds the directory limit")
                    pending.append((path, depth + 1))
                elif metadata_is_regular_file(metadata):
                    aggregate_file_bytes += metadata.st_size
                    if aggregate_file_bytes > MAX_SENSITIVITY_CORPUS_BYTES:
                        raise ValueError("sensitivity corpus exceeds the aggregate byte limit")
                    inventory.add(path.relative_to(root).as_posix())
                else:
                    raise ValueError("sensitivity corpus contains a non-regular entry")
    return inventory


def _build_difference_manifest(
    *,
    baseline_inputs: _SensitivityArmInputs,
    counterfactual_inputs: _SensitivityArmInputs,
    baseline: LoadedSensitivityCorpus,
    counterfactual: LoadedSensitivityCorpus,
    baseline_control: RAGSensitivityCorpusControlProjection,
    counterfactual_control: RAGSensitivityCorpusControlProjection,
) -> EvidenceSensitivityDifferenceManifest:
    values = {
        "agent_implementation_digest": (
            baseline_inputs.subject.agent_implementation_digest,
            counterfactual_inputs.subject.agent_implementation_digest,
        ),
        "corpus_digest": (
            baseline.manifest.corpus_digest,
            counterfactual.manifest.corpus_digest,
        ),
        "corpus_document_catalog_digest": (
            baseline_control.document_catalog_digest,
            counterfactual_control.document_catalog_digest,
        ),
        "deterministic_subject": (
            str(baseline_inputs.subject.deterministic).lower(),
            str(counterfactual_inputs.subject.deterministic).lower(),
        ),
        "fixture_manifest_digest": (
            baseline_inputs.fixture_manifest_digest,
            counterfactual_inputs.fixture_manifest_digest,
        ),
        "governing_evidence_digest": (
            baseline_control.governing_evidence_digest,
            counterfactual_control.governing_evidence_digest,
        ),
        "governing_retrieval_identity_digest": (
            baseline_control.governing_retrieval_identity_digest,
            counterfactual_control.governing_retrieval_identity_digest,
        ),
        "knowledge_contract_digest": (
            baseline_inputs.authority_contract.knowledge_contract_digest,
            counterfactual_inputs.authority_contract.knowledge_contract_digest,
        ),
        "model_digest": (
            baseline_inputs.subject.model_digest,
            counterfactual_inputs.subject.model_digest,
        ),
        "non_governing_evidence_digest": (
            baseline_control.non_governing_evidence_digest,
            counterfactual_control.non_governing_evidence_digest,
        ),
        "prompt_template_digest": (
            baseline_inputs.subject.prompt_template_digest,
            counterfactual_inputs.subject.prompt_template_digest,
        ),
        "producer_version": (__version__, __version__),
        "query_digest": (
            baseline_inputs.query_digest,
            counterfactual_inputs.query_digest,
        ),
        "query_family_id": (
            baseline.manifest.query_family_id,
            counterfactual.manifest.query_family_id,
        ),
        "request_digest": (
            baseline_inputs.request_digest,
            counterfactual_inputs.request_digest,
        ),
        "retrieval_algorithm": (
            f"{baseline.manifest.retrieval_algorithm_id}"
            f"@{baseline.manifest.retrieval_algorithm_version}",
            f"{counterfactual.manifest.retrieval_algorithm_id}"
            f"@{counterfactual.manifest.retrieval_algorithm_version}",
        ),
        "retrieval_top_k": (
            str(baseline.manifest.top_k),
            str(counterfactual.manifest.top_k),
        ),
        "subject_configuration_digest": (
            baseline_inputs.subject_digest,
            counterfactual_inputs.subject_digest,
        ),
        "suite_digest": (
            baseline_inputs.suite_digest,
            counterfactual_inputs.suite_digest,
        ),
        "tool_configuration_digest": (
            baseline_inputs.tool_digest,
            counterfactual_inputs.tool_digest,
        ),
        "tool_schema_digest": (
            baseline_inputs.tool.tool_schema_digest,
            counterfactual_inputs.tool.tool_schema_digest,
        ),
    }
    checks: list[EvidenceSensitivityDifferenceCheck] = []
    for dimension, expected_equal, basis in CONTROLLED_DIFFERENCE_DIMENSIONS:
        baseline_value, counterfactual_value = values[dimension]
        equal = baseline_value == counterfactual_value
        state = (
            EvidenceSensitivityDifferenceState.controlled
            if expected_equal and equal
            else EvidenceSensitivityDifferenceState.expected_difference
            if not expected_equal and not equal
            else EvidenceSensitivityDifferenceState.confounding
        )
        checks.append(
            EvidenceSensitivityDifferenceCheck(
                dimension=dimension,
                baseline_value=baseline_value,
                counterfactual_value=counterfactual_value,
                expected_equal=expected_equal,
                basis=basis,
                state=state,
            )
        )
    canonical = tuple(checks)
    confounders = tuple(
        item.dimension
        for item in canonical
        if item.state is EvidenceSensitivityDifferenceState.confounding
    )
    return EvidenceSensitivityDifferenceManifest(
        checks=canonical,
        only_declared_differences=not confounders,
        confounding_dimensions=confounders,
    )


def _execute_arm(
    *,
    role: EvidenceSensitivityArmRole,
    compiled: CompiledSuite,
    fixture_manifest: FixtureManifest,
    request: RAGSensitivityRequest,
    subject: RAGSensitivitySubjectConfig,
    tool: RAGSensitivityToolConfig,
    corpus: LoadedSensitivityCorpus,
    assignment: RAGSensitivityAuthorityAssignment | None,
    protocol: RAGSensitivityProtocol,
) -> _ArmExecution:
    retrieved = derive_snapshot_retrieval(corpus.snapshot, protocol.request.query)
    decision, outcome = derive_sensitivity_subject_output(subject, retrieved)

    linked = (
        tuple(
            sorted(
                (
                    RAGSensitivityEvidenceLinkProjection(
                        claim_id=request.claim_id,
                        source_id=item.source_id,
                        ref_id=item.ref_id,
                        content_digest=item.content_digest,
                    )
                    for item in retrieved
                ),
                key=lambda item: (item.claim_id, item.source_id, item.ref_id),
            )
        )
        if subject.emit_evidence_links
        else ()
    )
    arm_slug = role.value
    execution_binding = sha256_hexdigest(
        {
            "protocol_digest": protocol.protocol_digest,
            "arm_role": role.value,
            "subject_configuration_digest": protocol.subject_configuration_digest,
            "corpus_snapshot_digest": corpus.snapshot.snapshot_digest,
        }
    )[:24]
    run_id = f"sensitivity-run-{arm_slug}-{execution_binding}"
    runset_id = f"sensitivity-runset-{arm_slug}-{execution_binding}"
    run = AgentRunRecord(
        run_id=run_id,
        case_id=compiled.cases[0].case_id,
        execution_mode=ExecutionMode.fixture,
        pipeline_id=subject.subject_id,
        recommendation=decision.value,
        outcome=outcome.value,
        input_summary=(
            f"request_digest={protocol.request_digest}; "
            f"query_family={request.query_family_id}; "
            f"corpus_digest={corpus.manifest.corpus_digest}"
        ),
        output_summary=f"recommendation={decision.value}; outcome={outcome.value}",
        provider=protocol.provider,
        model=subject.model_id,
        resolved_model=subject.model_id,
        tools=(tool.tool_id,),
        evidence_refs=tuple(
            EvidenceRef(
                ref_id=item.ref_id,
                source_id=item.source_id,
                claim_ids=(request.claim_id,),
            )
            for item in retrieved
        ),
        evidence_items=tuple(
            EvidenceItem(
                ref_id=item.ref_id,
                source_id=item.source_id,
                content_digest=item.content_digest,
            )
            for item in retrieved
        ),
        claims=(ClaimRecord(claim_id=request.claim_id),),
        claim_evidence_links=tuple(
            ClaimEvidenceLink(
                claim_id=item.claim_id,
                evidence_ref_id=item.ref_id,
            )
            for item in linked
        ),
        provenance=Provenance(
            prompt_digest=subject.prompt_template_digest,
            code_digest=subject.agent_implementation_digest,
            policy_bundle_digest=corpus.manifest.corpus_digest,
            configuration_digest=sha256_hexdigest(subject.model_dump(mode="json")),
            tool_schema_digest=tool.tool_schema_digest,
            model_identifier=subject.model_id,
            fixture_manifest_digest=fixture_manifest_digest(fixture_manifest),
            retrieval_corpus_digest=corpus.manifest.corpus_digest,
        ),
    )
    runset = RunSet(
        runset_id=runset_id,
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=compiled_suite_digest(compiled),
        fixture_manifest_digest=fixture_manifest_digest(fixture_manifest),
        execution_mode=ExecutionMode.fixture,
        protocol_id=protocol.protocol_id,
        protocol_digest=protocol.protocol_digest,
        runs=(run,),
    )
    evaluation = evaluate_runset(
        compiled,
        runset,
        today=SENSITIVITY_EVALUATION_DATE,
    ).candidate_vs_expectations
    runset_digest = sha256_hexdigest(runset.model_dump(mode="json"))
    expected_decision = assignment.expected_decision if assignment is not None else None
    expected_outcome = assignment.expected_outcome if assignment is not None else None
    expected_match = (
        (decision, outcome) == (expected_decision, expected_outcome)
        if assignment is not None
        else None
    )
    governing_supported = assignment is not None and any(
        _retrieved_matches_assignment(item, assignment) for item in retrieved
    )
    governing_linked = assignment is not None and any(
        _link_matches_assignment(item, assignment) for item in linked
    )
    return _ArmExecution(
        runset=runset,
        evaluation=evaluation,
        result=RAGSensitivityArmResult(
            arm_id=f"{protocol.protocol_id}-{arm_slug}",
            role=role,
            corpus_id=corpus.manifest.corpus_id,
            corpus_digest=corpus.manifest.corpus_digest,
            corpus_snapshot_digest=corpus.snapshot.snapshot_digest,
            corpus_manifest_file_sha256=corpus.manifest_file_sha256,
            evidence_set_digest=corpus.evidence_set_digest,
            corpus_evidence=corpus.evidence_bindings,
            runset_id=runset.runset_id,
            runset_digest=runset_digest,
            fixture_manifest_digest=runset.fixture_manifest_digest,
            evaluation_summary_digest=sha256_hexdigest(evaluation.model_dump(mode="json")),
            evaluation_state=evaluation.state,
            query_digest=protocol.query_digest,
            retrieved_evidence=retrieved,
            retrieved_evidence_digest=sha256_hexdigest(
                tuple(item.model_dump(mode="json") for item in retrieved)
            ),
            linked_evidence=linked,
            retrieval_succeeded=bool(retrieved),
            governing_evidence_supported=governing_supported,
            evidence_link_present=governing_linked,
            citation_presence_check=(GateState.pass_ if governing_linked else GateState.fail),
            decision=decision,
            outcome=outcome,
            expected_decision=expected_decision,
            expected_outcome=expected_outcome,
            expected_decision_match=expected_match,
        ),
    )


def _retrieved_matches_assignment(
    item: RAGSensitivityRetrievedEvidence,
    assignment: RAGSensitivityAuthorityAssignment,
) -> bool:
    return (
        item.source_id,
        item.ref_id,
        item.content_digest,
        item.governing_decision,
        item.governing_outcome,
    ) == (
        assignment.governing_source_id,
        assignment.governing_ref_id,
        assignment.governing_content_digest,
        assignment.expected_decision,
        assignment.expected_outcome,
    )


def _link_matches_assignment(
    item: RAGSensitivityEvidenceLinkProjection,
    assignment: RAGSensitivityAuthorityAssignment,
) -> bool:
    return (
        item.claim_id,
        item.source_id,
        item.ref_id,
        item.content_digest,
    ) == (
        assignment.claim_id,
        assignment.governing_source_id,
        assignment.governing_ref_id,
        assignment.governing_content_digest,
    )


def _build_report(
    *,
    compiled_suite: CompiledSuite,
    protocol: RAGSensitivityProtocol,
    contract: RAGSensitivityKnowledgeContract,
    baseline: RAGSensitivityArmResult,
    counterfactual: RAGSensitivityArmResult,
    baseline_snapshot: RAGSensitivityCorpusSnapshot,
    counterfactual_snapshot: RAGSensitivityCorpusSnapshot,
    baseline_runset: RunSet,
    counterfactual_runset: RunSet,
    baseline_evaluation: EvaluationSummary,
    counterfactual_evaluation: EvaluationSummary,
) -> RAGSensitivityReport:
    assessment = derive_sensitivity_assessment(
        protocol,
        contract,
        baseline,
        counterfactual,
    )
    return RAGSensitivityReport.build(
        report_id=f"evidence-sensitivity-{protocol.protocol_digest[:24]}",
        compiled_suite=compiled_suite,
        protocol=protocol,
        authority_contract=contract,
        baseline_corpus_snapshot=baseline_snapshot,
        counterfactual_corpus_snapshot=counterfactual_snapshot,
        baseline_runset=baseline_runset,
        counterfactual_runset=counterfactual_runset,
        baseline_evaluation=baseline_evaluation,
        counterfactual_evaluation=counterfactual_evaluation,
        baseline_arm=baseline,
        counterfactual_arm=counterfactual,
        expected_relation=protocol.expected_relation,
        observed_relation=assessment.observed_relation,
        endpoint="expected_decision_response",
        endpoint_value=assessment.endpoint_value,
        state=assessment.state,
        verdict_bearing=assessment.verdict_bearing,
        gate_effect=assessment.gate_effect,
        reason_codes=assessment.reason_codes,
        outcome_classification=assessment.outcome_classification,
        outcome_message=assessment.outcome_message,
        decision_inertia_finding=assessment.decision_inertia_finding,
        prerequisite_checks=assessment.prerequisite_checks,
        deterministic=True,
        detector_test_status=DetectorTestStatus.synthetic_detector_contract_test,
        synthetic_data_provenance=protocol.synthetic_data_provenance,
        synthetic_data_attestation_digest=protocol.synthetic_data_attestation_digest,
        claim_scope="controlled_evidence_sensitivity_not_causal_guarantee",
        population_claim=(
            "none_bundled_synthetic_fixture_only"
            if protocol.synthetic_data_provenance is SyntheticDataProvenance.bundled_digest_verified
            else "none_operator_attested_synthetic_fixture_only"
        ),
        assumptions=protocol.assumptions,
        limitations=protocol.limitations,
    )


__all__ = [
    "CORPUS_MANIFEST_FILENAME",
    "SENSITIVITY_RUNNER_ID",
    "LoadedSensitivityCorpus",
    "SensitivityExecutionArtifacts",
    "SensitivityInputError",
    "execute_sensitivity_experiment",
    "load_knowledge_contract",
    "load_sensitivity_corpus",
    "load_sensitivity_report",
    "load_synthetic_data_attestation",
    "write_sensitivity_artifacts",
]
