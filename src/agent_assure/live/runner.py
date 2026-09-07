from __future__ import annotations

import hashlib
import json
import random
import time
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Literal
from uuid import uuid5

from agent_assure.authoring.yaml_nodes import safe_load_yaml_text
from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.io_limits import (
    MAX_ARTIFACT_JSON_BYTES,
    MAX_PROMPT_BYTES,
    MAX_STATIC_JSONL_BYTES,
    loads_json_bounded,
    read_file_bounded_at,
    read_text_bounded_at,
)
from agent_assure.live.adapters import (
    GOVERNING_EVIDENCE_RENDERER_ID,
    MAX_EXTERNAL_SCRIPT_FILE_BYTES,
    MAX_GOVERNING_EVIDENCE_BYTES,
    LiveAdapterResourceSnapshot,
    LiveProviderAdapter,
    LiveProviderRequest,
    LiveProviderResponse,
    TrustedLiveExecution,
    build_adapter,
    live_provider_input_text,
    monotonic_ms,
    render_governing_evidence_message,
    snapshot_live_adapter_resource,
)
from agent_assure.live.config import (
    MAX_LIVE_REQUESTS,
    MAX_LIVE_RETRY_BACKOFF_SECONDS,
    LivePromptCase,
    LiveRunConfig,
    live_sdk_identifier,
)
from agent_assure.live.identity import (
    AGENT_ASSURE_EXECUTION_VERSION,
    LIVE_ADAPTER_IMPLEMENTATION_ID,
    LIVE_PROVIDER_REQUEST_ENVELOPE_ID,
)
from agent_assure.live.output_contract import (
    LiveOutputContractError,
    parse_live_structured_content,
)
from agent_assure.live.paths import resolve_live_config_path
from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.privacy.redaction import redact_text
from agent_assure.privacy.safe_errors import safe_error
from agent_assure.rag.sensitivity import LoadedSensitivityCorpus, load_sensitivity_corpus
from agent_assure.runner.ids import AGENT_ASSURE_NAMESPACE
from agent_assure.runner.subprocess_harness import emergency_from_exception
from agent_assure.schema.common import ExecutionMode, GateState, ReasonCode, Severity
from agent_assure.schema.live import LiveProtocolRecord
from agent_assure.schema.provenance import Provenance
from agent_assure.schema.run import AgentRunRecord, PolicyResult, RunSet
from agent_assure.schema.runtime import EmergencyProcessRecord
from agent_assure.schema.sensitivity import (
    MAX_SENSITIVITY_DOCUMENTS,
    RAGSensitivityCaseAuthorityBinding,
    RAGSensitivityCorpusSnapshot,
    RAGSensitivityDocumentPayload,
    RAGSensitivityKnowledgeContract,
    knowledge_contract_case_authority_bindings,
)
from agent_assure.schema.suite import CompiledSuite
from agent_assure.telemetry.context import RuntimeTraceContext, trace_context_for_seed

LIVE_ACCOUNTING_UNAVAILABLE_STOP_REASONS = frozenset(
    {"cost_accounting_unavailable", "token_accounting_unavailable"}
)
LIVE_TERMINAL_STOP_REASONS = frozenset(
    {
        *LIVE_ACCOUNTING_UNAVAILABLE_STOP_REASONS,
        "cost_budget_exhausted_before_attempt",
        "cost_budget_exceeded_after_response",
        "generated_token_budget_exhausted_before_attempt",
        "generated_token_budget_exceeded_after_response",
        "rate_limit_budget_exhausted",
        "token_budget_exhausted_before_attempt",
        "token_budget_exceeded_after_response",
    }
)
LIVE_RUNSET_STOP_REASONS_ALLOWING_UNISSUED_TAIL = frozenset(
    {
        *LIVE_TERMINAL_STOP_REASONS,
        "budget_exhausted",
        "generated_token_budget_exhausted",
        "request_budget_exhausted",
        "token_budget_exhausted",
    }
)
LIVE_NEVER_ISSUED_EXCLUSION_REASONS = frozenset(
    {
        "budget_accounting_unavailable",
        "budget_exhausted",
        "cost_budget_exhausted_before_attempt",
        "generated_token_budget_exhausted",
        "generated_token_budget_exhausted_before_attempt",
        "terminal_policy_stop",
        "token_budget_exhausted",
        "token_budget_exhausted_before_attempt",
    }
)


class LiveBudgetExceededError(ValueError):
    def __init__(self, stop_reason: str, message: str) -> None:
        super().__init__(message)
        self.stop_reason = stop_reason


@dataclass
class _LiveRequestBudget:
    maximum: int
    used: int = 0

    @property
    def exhausted(self) -> bool:
        return self.used >= self.maximum

    def consume(self) -> None:
        if self.exhausted:
            raise LiveBudgetExceededError(
                "request_budget_exhausted",
                "configured max_requests was exhausted before another adapter attempt",
            )
        self.used += 1


@dataclass
class _LiveRateLimitBudget:
    maximum: int
    observed: int = 0

    def record(self) -> None:
        self.observed += 1
        if self.observed > self.maximum:
            raise LiveBudgetExceededError(
                "rate_limit_budget_exhausted",
                "provider rate-limit events exceeded the configured run-wide maximum",
            )


@dataclass
class _LiveAttemptState:
    attempt_count: int = 0
    retry_count: int = 0
    rate_limit_events: int = 0


@dataclass(frozen=True)
class LiveAttemptNotification:
    """Privacy-safe synchronous notification around one actual adapter call."""

    phase: Literal["issued", "succeeded", "failed"]
    request: LiveProviderRequest
    adapter_attempt_index: int
    provider_response_id: str | None = None
    retryable: bool | None = None
    rate_limited: bool | None = None


LiveAttemptObserver = Callable[[LiveAttemptNotification], None]


class LiveAttemptObserverError(RuntimeError):
    """The durable pre/post-dispatch evidence boundary could not be recorded."""


@dataclass(frozen=True)
class LiveExecutionSnapshot:
    """Authoritative detached provider inputs captured before adapter dispatch.

    Validation proves bounded internal consistency and commits the exact bytes
    that will be used. It does not prove that a caller-constructed snapshot came
    from the mutable paths named by the config. Across trust boundaries, accept
    only snapshots returned directly by prepare_live_execution_snapshot.
    """

    prompts: tuple[tuple[str, str], ...]
    prompt_digests: tuple[tuple[str, str], ...]
    governing_evidence: str | None
    governing_evidence_digest: str | None
    rendered_governing_evidence_message: str | None
    rendered_governing_evidence_message_digest: str | None
    corpus_snapshot: RAGSensitivityCorpusSnapshot | None
    corpus_snapshot_digest: str | None
    knowledge_contract: RAGSensitivityKnowledgeContract | None
    knowledge_contract_file_content: bytes | None
    knowledge_contract_file_sha256: str | None
    case_authority_bindings: tuple[RAGSensitivityCaseAuthorityBinding, ...]
    case_authority_manifest_digest: str | None
    adapter_resource: LiveAdapterResourceSnapshot | None

    def prompt_by_case(self) -> dict[str, str]:
        return dict(self.prompts)

    def prompt_digest_by_case(self) -> dict[str, str]:
        return dict(self.prompt_digests)


def _snapshot_sha256(value: object, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"live execution snapshot {label} must be lowercase SHA-256")
    return value


def _snapshot_utf8(value: object, *, label: str, maximum_bytes: int) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"live execution snapshot {label} must be text")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError(f"live execution snapshot {label} is not valid UTF-8 text") from exc
    if len(encoded) > maximum_bytes:
        raise ValueError(f"live execution snapshot {label} exceeds its byte limit")
    return encoded


def _snapshot_pairs(
    value: object,
    *,
    label: str,
) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, tuple):
        raise ValueError(f"live execution snapshot {label} must be an immutable tuple")
    if len(value) > MAX_LIVE_REQUESTS:
        raise ValueError(f"live execution snapshot {label} exceeds the hard entry limit")
    pairs: list[tuple[str, str]] = []
    for item in value:
        if (
            not isinstance(item, tuple)
            or len(item) != 2
            or not isinstance(item[0], str)
            or not isinstance(item[1], str)
        ):
            raise ValueError(f"live execution snapshot {label} entries must be text pairs")
        pairs.append((item[0], item[1]))
    case_ids = tuple(case_id for case_id, _item_value in pairs)
    if len(set(case_ids)) != len(case_ids):
        raise ValueError(f"live execution snapshot {label} contains duplicate case IDs")
    return tuple(pairs)


def _validated_adapter_resource_snapshot(
    resource: object,
    config: LiveRunConfig,
) -> LiveAdapterResourceSnapshot | None:
    adapter_id = config.adapter.adapter_id
    if adapter_id == "static-jsonl":
        if config.adapter.response_jsonl_path is None:
            raise ValueError("static-jsonl adapter requires response_jsonl_path")
        maximum_bytes = MAX_STATIC_JSONL_BYTES
        configured_sha256 = config.adapter.response_jsonl_sha256
        resource_label = "static JSONL resource"
    elif adapter_id == "external-script":
        if config.adapter.script_path is None:
            raise ValueError("external-script adapter requires script_path")
        maximum_bytes = MAX_EXTERNAL_SCRIPT_FILE_BYTES
        configured_sha256 = config.adapter.script_sha256
        resource_label = "external script resource"
    else:
        if resource is not None:
            raise ValueError(
                "live execution snapshot includes an adapter resource for a non-file adapter"
            )
        return None

    if type(resource) is not LiveAdapterResourceSnapshot:
        raise ValueError(f"live execution snapshot requires its exact {resource_label}")
    if resource.adapter_id != adapter_id:
        raise ValueError(f"live execution snapshot {resource_label} adapter identity mismatches")
    if not isinstance(resource.content, bytes):
        raise ValueError(f"live execution snapshot {resource_label} content must be bytes")
    if len(resource.content) > maximum_bytes:
        raise ValueError(f"live execution snapshot {resource_label} exceeds its byte limit")
    content_sha256 = _snapshot_sha256(
        resource.content_sha256,
        label=f"{resource_label} digest",
    )
    if hashlib.sha256(resource.content).hexdigest() != content_sha256:
        raise ValueError(
            f"live execution snapshot {resource_label} digest does not match exact content"
        )
    if configured_sha256 is not None and content_sha256 != configured_sha256:
        raise ValueError(
            f"live execution snapshot {resource_label} does not match configured SHA-256"
        )
    return LiveAdapterResourceSnapshot(
        adapter_id=adapter_id,
        content_sha256=content_sha256,
        content=resource.content,
    )


def _validate_live_execution_snapshot(
    compiled: CompiledSuite,
    config: LiveRunConfig,
    snapshot: object,
) -> LiveExecutionSnapshot:
    """Reconstruct and verify a detached snapshot's internal trust bindings."""

    if type(snapshot) is not LiveExecutionSnapshot:
        raise ValueError("live execution snapshot has an unsupported runtime type")

    prompts = _snapshot_pairs(snapshot.prompts, label="prompts")
    prompt_digests = _snapshot_pairs(snapshot.prompt_digests, label="prompt digests")
    configured_case_ids = tuple(item.case_id for item in config.cases)
    prompt_case_ids = tuple(case_id for case_id, _prompt in prompts)
    digest_case_ids = tuple(case_id for case_id, _digest in prompt_digests)
    if prompt_case_ids != configured_case_ids or digest_case_ids != configured_case_ids:
        raise ValueError(
            "live execution snapshot does not exactly match the configured case manifest"
        )
    expected_prompt_digests: list[tuple[str, str]] = []
    for case_id, prompt in prompts:
        _snapshot_utf8(prompt, label=f"prompt for case {case_id!r}", maximum_bytes=MAX_PROMPT_BYTES)
        if not prompt.strip():
            raise ValueError("live execution snapshot contains an empty prompt")
        expected_prompt_digests.append((case_id, sha256_hexdigest({"prompt": prompt})))
    for _case_id, prompt_digest in prompt_digests:
        _snapshot_sha256(prompt_digest, label="prompt digest")
    if prompt_digests != tuple(expected_prompt_digests):
        raise ValueError("live execution snapshot prompt digest does not match exact prompt bytes")

    knowledge_contract: RAGSensitivityKnowledgeContract | None = None
    if snapshot.knowledge_contract is not None:
        if type(snapshot.knowledge_contract) is not RAGSensitivityKnowledgeContract:
            raise ValueError("live execution snapshot knowledge contract has an invalid type")
        try:
            knowledge_contract = RAGSensitivityKnowledgeContract.model_validate(
                snapshot.knowledge_contract.model_dump(mode="json")
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("live execution snapshot knowledge contract is invalid") from exc
    expects_knowledge_contract = config.knowledge_contract_path is not None
    if (knowledge_contract is not None) != expects_knowledge_contract:
        raise ValueError(
            "live execution snapshot knowledge contract does not match the configured path"
        )
    if knowledge_contract is not None and (
        knowledge_contract.knowledge_contract_digest != config.knowledge_contract_digest
    ):
        raise ValueError(
            "live execution snapshot knowledge contract does not match its configured digest"
        )
    if knowledge_contract is None:
        if (
            snapshot.knowledge_contract_file_content is not None
            or snapshot.knowledge_contract_file_sha256 is not None
        ):
            raise ValueError("live execution snapshot has contract file content without a contract")
        knowledge_contract_file_content = None
        knowledge_contract_file_sha256 = None
    else:
        if not isinstance(snapshot.knowledge_contract_file_content, bytes):
            raise ValueError(
                "live execution snapshot knowledge contract file content must be bytes"
            )
        knowledge_contract_file_content = snapshot.knowledge_contract_file_content
        if len(knowledge_contract_file_content) > MAX_ARTIFACT_JSON_BYTES:
            raise ValueError(
                "live execution snapshot knowledge contract file exceeds its byte limit"
            )
        knowledge_contract_file_sha256 = _snapshot_sha256(
            snapshot.knowledge_contract_file_sha256,
            label="knowledge contract file digest",
        )
        if (
            hashlib.sha256(knowledge_contract_file_content).hexdigest()
            != knowledge_contract_file_sha256
        ):
            raise ValueError(
                "live execution snapshot knowledge contract file digest mismatches exact bytes"
            )
        try:
            contract_file_payload = safe_load_yaml_text(
                knowledge_contract_file_content.decode("utf-8"),
                label="live execution snapshot knowledge contract",
            )
            contract_file_model = RAGSensitivityKnowledgeContract.model_validate(
                contract_file_payload
            )
        except (TypeError, UnicodeDecodeError, ValueError) as exc:
            raise ValueError("live execution snapshot knowledge contract file is invalid") from exc
        if contract_file_model != knowledge_contract:
            raise ValueError(
                "live execution snapshot knowledge contract file does not match its model"
            )

    if not isinstance(snapshot.case_authority_bindings, tuple):
        raise ValueError(
            "live execution snapshot case authority bindings must be an immutable tuple"
        )
    if len(snapshot.case_authority_bindings) > MAX_LIVE_REQUESTS:
        raise ValueError(
            "live execution snapshot case authority bindings exceed the hard entry limit"
        )
    validated_bindings: list[RAGSensitivityCaseAuthorityBinding] = []
    for binding in snapshot.case_authority_bindings:
        if type(binding) is not RAGSensitivityCaseAuthorityBinding:
            raise ValueError("live execution snapshot case authority binding has an invalid type")
        try:
            validated_bindings.append(
                RAGSensitivityCaseAuthorityBinding.model_validate(binding.model_dump(mode="json"))
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("live execution snapshot case authority binding is invalid") from exc
    case_authority_bindings = tuple(validated_bindings)
    if knowledge_contract is None:
        if case_authority_bindings or snapshot.case_authority_manifest_digest is not None:
            raise ValueError(
                "live execution snapshot has case authority metadata without a contract"
            )
        case_authority_manifest_digest = None
    else:
        authority_by_case = {
            item.case_id: item
            for item in knowledge_contract_case_authority_bindings(knowledge_contract)
        }
        sorted_case_ids = tuple(sorted(configured_case_ids))
        if any(case_id not in authority_by_case for case_id in sorted_case_ids):
            raise ValueError(
                "live execution snapshot knowledge contract does not cover configured cases"
            )
        expected_bindings = tuple(authority_by_case[case_id] for case_id in sorted_case_ids)
        if case_authority_bindings != expected_bindings:
            raise ValueError(
                "live execution snapshot case authority bindings do not match the contract"
            )
        case_authority_manifest_digest = _snapshot_sha256(
            snapshot.case_authority_manifest_digest,
            label="case authority manifest digest",
        )
        expected_manifest_digest = sha256_hexdigest(
            tuple(item.model_dump(mode="json") for item in case_authority_bindings)
        )
        if case_authority_manifest_digest != expected_manifest_digest:
            raise ValueError(
                "live execution snapshot case authority manifest digest does not match"
            )
        compiled_cases = {item.case_id: item for item in compiled.cases}
        for binding in case_authority_bindings:
            compiled_case = compiled_cases[binding.case_id]
            if (
                binding.query_family_id != compiled_case.case_id
                and binding.query_family_id not in compiled_case.tags
            ):
                raise ValueError(
                    "live execution snapshot case authority query family is not declared"
                )

    governing_fields = (
        snapshot.governing_evidence,
        snapshot.governing_evidence_digest,
        snapshot.rendered_governing_evidence_message,
        snapshot.rendered_governing_evidence_message_digest,
        snapshot.corpus_snapshot,
        snapshot.corpus_snapshot_digest,
    )
    expects_governing_evidence = config.retrieval_corpus_dir is not None
    if expects_governing_evidence and not all(item is not None for item in governing_fields):
        raise ValueError("live execution snapshot is missing its configured governing evidence")
    if not expects_governing_evidence and any(item is not None for item in governing_fields):
        raise ValueError("live execution snapshot contains unexpected governing evidence")

    governing_evidence: str | None = None
    governing_evidence_digest: str | None = None
    rendered_message: str | None = None
    rendered_message_digest: str | None = None
    corpus_snapshot: RAGSensitivityCorpusSnapshot | None = None
    corpus_snapshot_digest: str | None = None
    governing_documents: tuple[tuple[str, str, str, object, object], ...] = ()
    if expects_governing_evidence:
        if type(snapshot.corpus_snapshot) is not RAGSensitivityCorpusSnapshot:
            raise ValueError("live execution snapshot corpus snapshot has an invalid type")
        try:
            corpus_snapshot = RAGSensitivityCorpusSnapshot.model_validate(
                snapshot.corpus_snapshot.model_dump(mode="json")
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("live execution snapshot corpus snapshot is invalid") from exc
        if corpus_snapshot.corpus_manifest.corpus_digest != config.retrieval_corpus_digest:
            raise ValueError(
                "live execution snapshot corpus model does not match the configured digest"
            )
        evidence_bytes = _snapshot_utf8(
            snapshot.governing_evidence,
            label="governing evidence",
            maximum_bytes=MAX_GOVERNING_EVIDENCE_BYTES,
        )
        governing_evidence = snapshot.governing_evidence
        assert isinstance(governing_evidence, str)
        governing_evidence_digest = _snapshot_sha256(
            snapshot.governing_evidence_digest,
            label="governing evidence digest",
        )
        if hashlib.sha256(evidence_bytes).hexdigest() != governing_evidence_digest:
            raise ValueError(
                "live execution snapshot governing evidence digest does not match exact bytes"
            )
        corpus_snapshot_digest = _snapshot_sha256(
            snapshot.corpus_snapshot_digest,
            label="corpus snapshot digest",
        )
        if corpus_snapshot.snapshot_digest != corpus_snapshot_digest:
            raise ValueError(
                "live execution snapshot corpus model does not match its snapshot digest"
            )
        if governing_evidence != _render_governing_evidence_snapshot(corpus_snapshot):
            raise ValueError(
                "live execution snapshot governing evidence does not match the exact corpus model"
            )
        try:
            evidence_payload = loads_json_bounded(
                governing_evidence,
                label="live execution snapshot governing evidence",
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("live execution snapshot governing evidence is invalid JSON") from exc
        if not isinstance(evidence_payload, dict) or set(evidence_payload) != {
            "artifact_kind",
            "corpus_digest",
            "corpus_snapshot_digest",
            "documents",
        }:
            raise ValueError("live execution snapshot governing evidence has an invalid shape")
        if evidence_payload["artifact_kind"] != "live-governing-evidence":
            raise ValueError("live execution snapshot governing evidence kind is invalid")
        if evidence_payload["corpus_digest"] != config.retrieval_corpus_digest:
            raise ValueError(
                "live execution snapshot governing evidence corpus digest does not match config"
            )
        if evidence_payload["corpus_snapshot_digest"] != corpus_snapshot_digest:
            raise ValueError(
                "live execution snapshot governing evidence corpus snapshot digest mismatches"
            )
        documents = evidence_payload["documents"]
        if (
            not isinstance(documents, list)
            or not documents
            or len(documents) > MAX_SENSITIVITY_DOCUMENTS
        ):
            raise ValueError("live execution snapshot governing evidence documents are invalid")
        validated_documents: list[tuple[str, str, str, object, object]] = []
        document_identities: set[tuple[str, str]] = set()
        for document in documents:
            if not isinstance(document, dict) or set(document) != {
                "content_digest",
                "payload",
                "source_id",
            }:
                raise ValueError(
                    "live execution snapshot governing evidence document has an invalid shape"
                )
            content_digest = _snapshot_sha256(
                document["content_digest"],
                label="governing evidence document content digest",
            )
            source_id = document["source_id"]
            if not isinstance(source_id, str):
                raise ValueError(
                    "live execution snapshot governing evidence document source is invalid"
                )
            try:
                document_payload = RAGSensitivityDocumentPayload.model_validate(document["payload"])
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    "live execution snapshot governing evidence document payload is invalid"
                ) from exc
            if document_payload.model_dump(mode="json") != document["payload"]:
                raise ValueError(
                    "live execution snapshot governing evidence document is not canonical"
                )
            if document_payload.source_id != source_id:
                raise ValueError(
                    "live execution snapshot governing evidence document source mismatches"
                )
            identity = (source_id, document_payload.ref_id)
            if identity in document_identities:
                raise ValueError(
                    "live execution snapshot governing evidence contains duplicate documents"
                )
            document_identities.add(identity)
            validated_documents.append(
                (
                    source_id,
                    document_payload.ref_id,
                    content_digest,
                    document_payload.governing_decision,
                    document_payload.governing_outcome,
                )
            )
        governing_documents = tuple(validated_documents)
        canonical_evidence = json.dumps(
            evidence_payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        if governing_evidence != canonical_evidence:
            raise ValueError("live execution snapshot governing evidence is not canonical")

        expected_knowledge_digest = (
            knowledge_contract.knowledge_contract_digest
            if knowledge_contract is not None
            else config.knowledge_contract_digest
        )
        expected_rendered_message = render_governing_evidence_message(
            governing_evidence=governing_evidence,
            governing_evidence_digest=governing_evidence_digest,
            knowledge_contract_digest=expected_knowledge_digest,
        )
        rendered_message = snapshot.rendered_governing_evidence_message
        if rendered_message != expected_rendered_message:
            raise ValueError(
                "live execution snapshot rendered governing message does not match exact inputs"
            )
        rendered_bytes = _snapshot_utf8(
            rendered_message,
            label="rendered governing message",
            maximum_bytes=MAX_PROMPT_BYTES,
        )
        rendered_message_digest = _snapshot_sha256(
            snapshot.rendered_governing_evidence_message_digest,
            label="rendered governing message digest",
        )
        if hashlib.sha256(rendered_bytes).hexdigest() != rendered_message_digest:
            raise ValueError(
                "live execution snapshot rendered governing message digest mismatches exact bytes"
            )

    if knowledge_contract is not None and governing_documents:
        corpus_digest = config.retrieval_corpus_digest
        assert corpus_digest is not None
        for binding in case_authority_bindings:
            assignment = next(
                (item for item in binding.assignments if item.corpus_digest == corpus_digest),
                None,
            )
            if assignment is None:
                raise ValueError(
                    "live execution snapshot authority binding has no active corpus assignment"
                )
            expected_document = (
                assignment.governing_source_id,
                assignment.governing_ref_id,
                assignment.governing_content_digest,
                assignment.expected_decision,
                assignment.expected_outcome,
            )
            if expected_document not in governing_documents:
                raise ValueError(
                    "live execution snapshot authority assignment does not match governing evidence"
                )

    adapter_resource = _validated_adapter_resource_snapshot(snapshot.adapter_resource, config)
    return LiveExecutionSnapshot(
        prompts=prompts,
        prompt_digests=prompt_digests,
        governing_evidence=governing_evidence,
        governing_evidence_digest=governing_evidence_digest,
        rendered_governing_evidence_message=rendered_message,
        rendered_governing_evidence_message_digest=rendered_message_digest,
        corpus_snapshot=corpus_snapshot,
        corpus_snapshot_digest=corpus_snapshot_digest,
        knowledge_contract=knowledge_contract,
        knowledge_contract_file_content=knowledge_contract_file_content,
        knowledge_contract_file_sha256=knowledge_contract_file_sha256,
        case_authority_bindings=case_authority_bindings,
        case_authority_manifest_digest=case_authority_manifest_digest,
        adapter_resource=adapter_resource,
    )


def validate_live_execution_snapshot(
    compiled: CompiledSuite,
    config: LiveRunConfig,
    snapshot: LiveExecutionSnapshot,
) -> LiveExecutionSnapshot:
    """Validate exact detached bytes, not their origin in current config paths.

    A supplied snapshot is authoritative executable input. Callers crossing a
    trust boundary must obtain it from prepare_live_execution_snapshot rather
    than constructing or accepting one from an untrusted producer.
    """

    compiled = CompiledSuite.model_validate(compiled.model_dump(mode="json"))
    config = LiveRunConfig.model_validate(config.model_dump(mode="json"))
    _validate_cases(compiled, config)
    return _validate_live_execution_snapshot(compiled, config, snapshot)


def run_live_suite(
    compiled: CompiledSuite,
    config: LiveRunConfig,
    *,
    protocol: LiveProtocolRecord,
    config_dir: Path,
    trust: TrustedLiveExecution | None = None,
    execution_snapshot: LiveExecutionSnapshot | None = None,
    attempt_observer: LiveAttemptObserver | None = None,
) -> RunSet:
    # Pydantic's model_copy(update=...) intentionally skips validation. Treat
    # this library API as the final execution boundary and reconstruct every
    # caller-provided contract before using suite, budget, or adapter fields.
    compiled = CompiledSuite.model_validate(compiled.model_dump(mode="json"))
    config = LiveRunConfig.model_validate(config.model_dump(mode="json"))
    protocol = LiveProtocolRecord.model_validate(protocol.model_dump(mode="json"))
    _validate_cases(compiled, config)
    _validate_protocol_config(compiled, config, protocol)
    planned_observations = _planned_observation_count(config)
    if planned_observations > MAX_LIVE_REQUESTS:
        raise ValueError(
            f"planned live observations ({planned_observations}) exceed the hard limit "
            f"({MAX_LIVE_REQUESTS})"
        )
    if config.max_requests is None:
        raise ValueError("live execution requires an explicit max_requests attempt budget")
    if planned_observations > config.max_requests:
        raise ValueError(
            f"planned live observations ({planned_observations}) exceed max_requests "
            f"({config.max_requests})"
        )
    snapshot = (
        prepare_live_execution_snapshot(compiled, config, config_dir=config_dir)
        if execution_snapshot is None
        else _validate_live_execution_snapshot(compiled, config, execution_snapshot)
    )
    prompts = snapshot.prompt_by_case()
    prompt_digests = snapshot.prompt_digest_by_case()
    schedule = _schedule(config)
    request_budget = _LiveRequestBudget(config.max_requests)
    rate_limit_budget = _LiveRateLimitBudget(config.max_rate_limit_events)
    adapter = build_adapter(
        config.adapter,
        base_dir=config_dir,
        trust=trust,
        resource_snapshot=snapshot.adapter_resource,
    )
    configuration_digest = _configuration_digest(compiled, config, snapshot)
    protocol_digest = sha256_hexdigest(protocol)
    committed_cost = Decimal("0")
    committed_total_tokens = 0
    committed_generated_tokens = 0
    cost_budget = Decimal(config.max_total_cost_usd) if config.max_total_cost_usd else None
    max_observation_cost = Decimal(config.max_cost_per_observation_usd)
    attempt_cost_reservation = (
        max_observation_cost if config.adapter.allow_network else Decimal("0")
    )
    last_request_started: float | None = None
    token_window_started: float | None = None
    tokens_window_reserved = 0
    stop_reasons: set[str] = set()
    terminal_stop_reason: str | None = None
    runs: list[AgentRunRecord] = []
    emergency_records: list[EmergencyProcessRecord] = []
    for schedule_index, prompt_case, repetition_index in schedule:
        prompt = prompts[prompt_case.case_id]
        prompt_digest = _provider_input_digest(
            prompt_digests[prompt_case.case_id],
            snapshot,
        )
        run_id = _run_id(
            compiled.suite_id,
            config.variant_id,
            prompt_case.case_id,
            repetition_index,
        )
        observation_id = _observation_id(
            compiled.suite_id,
            config.variant_id,
            prompt_case.case_id,
            repetition_index,
        )
        trace_context = trace_context_for_seed(observation_id)
        if terminal_stop_reason is not None:
            accounting_unavailable = (
                terminal_stop_reason in LIVE_ACCOUNTING_UNAVAILABLE_STOP_REASONS
            )
            runs.append(
                _error_record(
                    compiled,
                    config,
                    prompt_case,
                    repetition_index,
                    schedule_index,
                    configuration_digest,
                    "live_budget_accounting_unavailable"
                    if accounting_unavailable
                    else "live_execution_stopped",
                    "budget accounting became unavailable after an earlier response"
                    if accounting_unavailable
                    else "live execution stopped after an earlier terminal policy event",
                    cluster_by=protocol.cluster_by,
                    exclusion_reason=(
                        "budget_accounting_unavailable"
                        if accounting_unavailable
                        else "terminal_policy_stop"
                    ),
                    prompt_digest=prompt_digest,
                    trace_context=trace_context,
                    reason_code=ReasonCode.POLICY_FAILED,
                )
            )
            continue
        if request_budget.exhausted:
            stop_reasons.add("request_budget_exhausted")
            runs.append(
                _error_record(
                    compiled,
                    config,
                    prompt_case,
                    repetition_index,
                    schedule_index,
                    configuration_digest,
                    "live_request_budget_exhausted",
                    "configured max_requests attempt budget was exhausted",
                    cluster_by=protocol.cluster_by,
                    exclusion_reason="budget_exhausted",
                    prompt_digest=prompt_digest,
                    trace_context=trace_context,
                    reason_code=ReasonCode.POLICY_FAILED,
                )
            )
            continue
        if cost_budget is not None and committed_cost + max_observation_cost > cost_budget:
            stop_reasons.add("budget_exhausted")
            runs.append(
                _error_record(
                    compiled,
                    config,
                    prompt_case,
                    repetition_index,
                    schedule_index,
                    configuration_digest,
                    "live_budget_exhausted",
                    "configured live cost budget would be exceeded before this observation",
                    cluster_by=protocol.cluster_by,
                    exclusion_reason="budget_exhausted",
                    prompt_digest=prompt_digest,
                    trace_context=trace_context,
                    reason_code=ReasonCode.POLICY_FAILED,
                )
            )
            continue
        if (
            config.max_total_tokens is not None
            and committed_total_tokens >= config.max_total_tokens
        ):
            stop_reasons.add("token_budget_exhausted")
            runs.append(
                _error_record(
                    compiled,
                    config,
                    prompt_case,
                    repetition_index,
                    schedule_index,
                    configuration_digest,
                    "live_token_budget_exhausted",
                    "configured live token budget was exhausted before this observation",
                    cluster_by=protocol.cluster_by,
                    exclusion_reason="token_budget_exhausted",
                    prompt_digest=prompt_digest,
                    trace_context=trace_context,
                    reason_code=ReasonCode.POLICY_FAILED,
                )
            )
            continue
        if (
            config.max_generated_tokens is not None
            and config.adapter.max_output_tokens is not None
            and committed_generated_tokens + config.adapter.max_output_tokens
            > config.max_generated_tokens
        ):
            stop_reasons.add("generated_token_budget_exhausted")
            runs.append(
                _error_record(
                    compiled,
                    config,
                    prompt_case,
                    repetition_index,
                    schedule_index,
                    configuration_digest,
                    "live_generated_token_budget_exhausted",
                    "configured generated-token budget would be exceeded before this observation",
                    cluster_by=protocol.cluster_by,
                    exclusion_reason="generated_token_budget_exhausted",
                    prompt_digest=prompt_digest,
                    trace_context=trace_context,
                    reason_code=ReasonCode.POLICY_FAILED,
                )
            )
            continue
        request = LiveProviderRequest(
            run_id=run_id,
            observation_id=observation_id,
            case_id=prompt_case.case_id,
            repetition_index=repetition_index,
            prompt=prompt,
            provider=config.adapter.provider,
            model=config.adapter.model,
            governing_evidence=snapshot.governing_evidence,
            governing_evidence_digest=snapshot.governing_evidence_digest,
            rendered_governing_evidence_message=(snapshot.rendered_governing_evidence_message),
            governing_evidence_renderer_id=(
                GOVERNING_EVIDENCE_RENDERER_ID
                if snapshot.rendered_governing_evidence_message is not None
                else None
            ),
            knowledge_contract_digest=(
                snapshot.knowledge_contract.knowledge_contract_digest
                if snapshot.knowledge_contract is not None
                else config.knowledge_contract_digest
            ),
            allow_case_only_static_response=config.repetitions == 1,
            traceparent=trace_context.traceparent,
            tracestate=trace_context.tracestate,
        )
        provider_input = live_provider_input_text(request)
        token_reservation = _token_reservation(provider_input, config)
        generated_token_reservation = (
            (config.adapter.max_output_tokens or 0) if config.adapter.allow_network else 0
        )
        total_token_reservation = (
            _prompt_token_upper_bound(provider_input) + generated_token_reservation
            if config.adapter.allow_network
            else 0
        )
        observation_committed_cost = Decimal("0")
        observation_committed_generated_tokens = 0
        observation_committed_total_tokens = 0

        def pace_attempt(
            reserved_tokens: int = token_reservation,
            generated_reservation: int = generated_token_reservation,
            total_reservation: int = total_token_reservation,
        ) -> None:
            nonlocal committed_cost, committed_generated_tokens, committed_total_tokens
            nonlocal last_request_started, observation_committed_cost
            nonlocal observation_committed_generated_tokens
            nonlocal observation_committed_total_tokens
            nonlocal token_window_started, tokens_window_reserved
            if cost_budget is not None and committed_cost + attempt_cost_reservation > cost_budget:
                raise LiveBudgetExceededError(
                    "cost_budget_exhausted_before_attempt",
                    "configured live cost budget cannot reserve another adapter attempt",
                )
            if (
                config.max_generated_tokens is not None
                and committed_generated_tokens + generated_reservation > config.max_generated_tokens
            ):
                raise LiveBudgetExceededError(
                    "generated_token_budget_exhausted_before_attempt",
                    "configured generated-token budget cannot reserve another adapter attempt",
                )
            if (
                config.max_total_tokens is not None
                and committed_total_tokens + total_reservation > config.max_total_tokens
            ):
                raise LiveBudgetExceededError(
                    "token_budget_exhausted_before_attempt",
                    "configured total-token budget cannot reserve another adapter attempt",
                )
            token_window_started, tokens_window_reserved = _pace_request(
                config,
                last_request_started,
                token_window_started,
                tokens_window_reserved,
                reserved_tokens,
            )
            # A failed or timed-out network request may still be billable. Reserve
            # the declared per-observation ceiling for every dispatched attempt;
            # ambiguous failed-attempt reservations are never released.
            committed_cost += attempt_cost_reservation
            observation_committed_cost += attempt_cost_reservation
            committed_generated_tokens += generated_reservation
            observation_committed_generated_tokens += generated_reservation
            committed_total_tokens += total_reservation
            observation_committed_total_tokens += total_reservation
            last_request_started = time.perf_counter()

        started = _utc_now()
        start = time.perf_counter()
        response: LiveProviderResponse | None = None
        completed: str | None = None
        attempt_state = _LiveAttemptState()
        try:
            response = _complete_with_retries(
                adapter,
                request,
                config,
                request_budget=request_budget,
                rate_limit_budget=rate_limit_budget,
                attempt_state=attempt_state,
                before_attempt=pace_attempt,
                attempt_observer=attempt_observer,
            )
            latency_ms = monotonic_ms(start)
            completed = completed or _completion_utc(started)
            response_total_tokens = _response_total_tokens(response)
            response_cost = Decimal(response.estimated_cost_usd)
            if not (
                config.adapter.allow_network and response.estimated_cost_source == "not_reported"
            ):
                committed_cost += response_cost - attempt_cost_reservation
                observation_committed_cost += response_cost - attempt_cost_reservation
            if response.completion_tokens is not None:
                committed_generated_tokens += (
                    response.completion_tokens - generated_token_reservation
                )
                observation_committed_generated_tokens += (
                    response.completion_tokens - generated_token_reservation
                )
            if response_total_tokens is not None:
                committed_total_tokens += response_total_tokens - total_token_reservation
                observation_committed_total_tokens += (
                    response_total_tokens - total_token_reservation
                )
            if observation_committed_total_tokens < observation_committed_generated_tokens:
                commitment_gap = (
                    observation_committed_generated_tokens - observation_committed_total_tokens
                )
                committed_total_tokens += commitment_gap
                observation_committed_total_tokens += commitment_gap
            if response_total_tokens is not None and response_total_tokens > token_reservation:
                tokens_window_reserved += response_total_tokens - token_reservation
            _verify_response_budgets(response, config)
            if cost_budget is not None and committed_cost > cost_budget:
                raise LiveBudgetExceededError(
                    "cost_budget_exceeded_after_response",
                    "configured total live cost budget was exceeded after response",
                )
            if (
                config.max_generated_tokens is not None
                and committed_generated_tokens > config.max_generated_tokens
            ):
                raise LiveBudgetExceededError(
                    "generated_token_budget_exceeded_after_response",
                    "configured generated-token budget was exceeded after response",
                )
            if (
                config.max_total_tokens is not None
                and committed_total_tokens > config.max_total_tokens
            ):
                raise LiveBudgetExceededError(
                    "token_budget_exceeded_after_response",
                    "configured total-token budget was exceeded after response",
                )
            record = _record_from_response(
                compiled,
                config,
                prompt_case,
                repetition_index,
                schedule_index,
                configuration_digest,
                response,
                prompt_digest=prompt_digest,
                cost_budget_committed_usd=observation_committed_cost,
                generated_token_budget_committed=(observation_committed_generated_tokens),
                total_token_budget_committed=observation_committed_total_tokens,
                cluster_by=protocol.cluster_by,
                attempt_count=attempt_state.attempt_count,
                retry_count=attempt_state.retry_count,
                rate_limit_events=attempt_state.rate_limit_events,
                started_at_utc=started,
                completed_at_utc=completed,
                latency_ms=latency_ms,
                trace_context=trace_context,
            )
        except Exception as exc:
            if isinstance(exc, LiveAttemptObserverError):
                raise
            emergency = emergency_from_exception(exc)
            if emergency is not None:
                emergency_records.append(emergency)
            if isinstance(exc, LiveBudgetExceededError):
                stop_reasons.add(exc.stop_reason)
                if exc.stop_reason in LIVE_TERMINAL_STOP_REASONS:
                    terminal_stop_reason = exc.stop_reason
            reason_code = (
                ReasonCode.STRUCTURED_OUTPUT_INVALID
                if isinstance(exc, LiveOutputContractError)
                else ReasonCode.POLICY_FAILED
                if isinstance(exc, LiveBudgetExceededError)
                else ReasonCode.RUNTIME_FAILED
            )
            category = (
                "live_structured_output_invalid"
                if isinstance(exc, LiveOutputContractError)
                else "live_budget_accounting_unavailable"
                if isinstance(exc, LiveBudgetExceededError)
                and exc.stop_reason in LIVE_ACCOUNTING_UNAVAILABLE_STOP_REASONS
                else "live_budget_exceeded_after_response"
                if isinstance(exc, LiveBudgetExceededError)
                else "live_adapter_error"
            )
            latency_ms = monotonic_ms(start)
            completed = completed or _completion_utc(started)
            record = _error_record(
                compiled,
                config,
                prompt_case,
                repetition_index,
                schedule_index,
                configuration_digest,
                category,
                str(exc),
                cluster_by=protocol.cluster_by,
                prompt_digest=prompt_digest,
                attempt_count=attempt_state.attempt_count or None,
                retry_count=attempt_state.retry_count,
                rate_limit_events=attempt_state.rate_limit_events,
                started_at_utc=started,
                completed_at_utc=completed,
                latency_ms=latency_ms,
                trace_context=trace_context,
                response=response,
                exclusion_reason=(
                    exc.stop_reason if isinstance(exc, LiveBudgetExceededError) else None
                ),
                cost_budget_committed_usd=observation_committed_cost,
                generated_token_budget_committed=(observation_committed_generated_tokens),
                total_token_budget_committed=observation_committed_total_tokens,
                reason_code=reason_code,
                exc=exc,
            )
        runs.append(record)
    return RunSet(
        artifact_kind="run-set",
        runset_id=_runset_id(compiled.suite_id, config.variant_id, configuration_digest),
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=sha256_hexdigest(compiled.model_dump(mode="json")),
        fixture_manifest_digest=configuration_digest,
        execution_mode=ExecutionMode.live,
        protocol_id=protocol.protocol_id,
        protocol_digest=protocol_digest,
        evidence_sensitivity_design_digest=(config.evidence_sensitivity_design_digest),
        study_manifest_digest=config.study_manifest_digest,
        completion_status="incomplete" if stop_reasons else "complete",
        stop_reasons=tuple(sorted(stop_reasons)),
        emergency_records=tuple(emergency_records),
        runs=tuple(runs),
    )


def _record_from_response(
    compiled: CompiledSuite,
    config: LiveRunConfig,
    prompt_case: LivePromptCase,
    repetition_index: int,
    schedule_index: int,
    configuration_digest: str,
    response: LiveProviderResponse,
    prompt_digest: str,
    *,
    cost_budget_committed_usd: Decimal,
    generated_token_budget_committed: int,
    total_token_budget_committed: int,
    cluster_by: str,
    attempt_count: int,
    retry_count: int,
    rate_limit_events: int,
    started_at_utc: str,
    completed_at_utc: str,
    latency_ms: int,
    trace_context: RuntimeTraceContext,
) -> AgentRunRecord:
    payload = parse_live_structured_content(response.content)
    blocking_policy_failure = any(
        result.state is GateState.fail and result.severity is Severity.blocker
        for result in payload.policy_results
    )
    observation_status = (
        "excluded"
        if response.observation_status == "excluded" or blocking_policy_failure
        else "included"
    )
    exclusion_reason = response.exclusion_reason
    if observation_status == "excluded" and exclusion_reason is None:
        exclusion_reason = (
            "blocking-policy-failure" if blocking_policy_failure else "provider-excluded"
        )
    total_tokens = _response_total_tokens(response)
    observation_id = _observation_id(
        compiled.suite_id,
        config.variant_id,
        prompt_case.case_id,
        repetition_index,
    )
    return AgentRunRecord.model_validate(
        {
            "artifact_kind": "agent-run-record",
            "run_id": _run_id(
                compiled.suite_id,
                config.variant_id,
                prompt_case.case_id,
                repetition_index,
            ),
            "case_id": prompt_case.case_id,
            "execution_mode": ExecutionMode.live.value,
            "pipeline_id": config.pipeline_id,
            "recommendation": payload.recommendation,
            "outcome": payload.outcome,
            "input_summary": redact_text(prompt_case.input_summary),
            "output_summary": redact_text(payload.output_summary),
            "observation_status": observation_status,
            "observation_id": observation_id,
            "repetition_index": repetition_index,
            "schedule_index": schedule_index,
            "randomization_block_id": f"repetition:{repetition_index}",
            "cluster_id": _cluster_id(prompt_case, cluster_by),
            "source_group_id": prompt_case.source_group_id,
            "adapter_id": config.adapter.adapter_id,
            "provider": response.provider,
            # Requested identity is an execution input, not provider output.
            # Provider-resolved identity is persisted separately below.
            "model": config.adapter.model,
            "resolved_model": response.resolved_model,
            "provider_api_version": response.provider_api_version,
            "provider_sdk": response.provider_sdk,
            "provider_region": response.provider_region,
            "provider_response_id": response.provider_response_id,
            "provider_finish_reason": response.provider_finish_reason,
            "provider_serving_fingerprint": response.provider_serving_fingerprint,
            "provider_created_unix_seconds": response.provider_created_unix_seconds,
            "traceparent": trace_context.traceparent,
            "tracestate": trace_context.tracestate,
            "started_at_utc": started_at_utc,
            "completed_at_utc": completed_at_utc,
            "latency_ms": latency_ms,
            "attempt_count": attempt_count,
            "retry_count": retry_count,
            "rate_limit_events": rate_limit_events,
            "exclusion_reason": exclusion_reason,
            "prompt_tokens": response.prompt_tokens,
            "completion_tokens": response.completion_tokens,
            "total_tokens": total_tokens,
            "estimated_cost_usd": response.estimated_cost_usd,
            "estimated_cost_source": response.estimated_cost_source,
            "cost_budget_committed_usd": _cost_string(cost_budget_committed_usd),
            "generated_token_budget_committed": generated_token_budget_committed,
            "total_token_budget_committed": total_token_budget_committed,
            "tools": payload.tools,
            "evidence_refs": payload.evidence_refs,
            "evidence_items": payload.evidence_items,
            "claims": payload.claims,
            "claim_evidence_links": payload.claim_evidence_links,
            "policy_results": payload.policy_results,
            "human_review_required": payload.human_review_required,
            "human_review_performed": payload.human_review_performed,
            "provenance": _provenance(
                config,
                configuration_digest,
                prompt_digest=prompt_digest,
            ).model_dump(mode="json"),
        }
    )


def _error_record(
    compiled: CompiledSuite,
    config: LiveRunConfig,
    prompt_case: LivePromptCase,
    repetition_index: int,
    schedule_index: int,
    configuration_digest: str,
    category: str,
    message: str,
    *,
    cluster_by: str,
    exclusion_reason: str | None = None,
    prompt_digest: str | None = None,
    attempt_count: int | None = None,
    retry_count: int | None = None,
    rate_limit_events: int | None = None,
    started_at_utc: str | None = None,
    completed_at_utc: str | None = None,
    latency_ms: int | None = None,
    trace_context: RuntimeTraceContext | None = None,
    response: LiveProviderResponse | None = None,
    cost_budget_committed_usd: Decimal = Decimal("0"),
    generated_token_budget_committed: int = 0,
    total_token_budget_committed: int = 0,
    reason_code: ReasonCode = ReasonCode.RUNTIME_FAILED,
    exc: Exception | None = None,
) -> AgentRunRecord:
    safe = safe_error(category, message, exc)
    effective_exclusion_reason = exclusion_reason or (
        "structured-output-invalid"
        if reason_code is ReasonCode.STRUCTURED_OUTPUT_INVALID
        else "policy-failed"
        if reason_code is ReasonCode.POLICY_FAILED
        else "runtime-failed"
    )
    trace_context = trace_context or trace_context_for_seed(
        _observation_id(
            compiled.suite_id,
            config.variant_id,
            prompt_case.case_id,
            repetition_index,
        )
    )
    return AgentRunRecord(
        artifact_kind="agent-run-record",
        run_id=_run_id(
            compiled.suite_id,
            config.variant_id,
            prompt_case.case_id,
            repetition_index,
        ),
        case_id=prompt_case.case_id,
        execution_mode=ExecutionMode.live,
        pipeline_id=config.pipeline_id,
        recommendation="error",
        outcome="excluded" if exclusion_reason else "runtime_error",
        input_summary=redact_text(prompt_case.input_summary),
        output_summary=(
            f"live observation failed; code={safe.code}; debug_ref={safe.local_debug_reference}"
        ),
        observation_status="excluded",
        observation_id=_observation_id(
            compiled.suite_id,
            config.variant_id,
            prompt_case.case_id,
            repetition_index,
        ),
        repetition_index=repetition_index,
        schedule_index=schedule_index,
        randomization_block_id=f"repetition:{repetition_index}",
        cluster_id=_cluster_id(prompt_case, cluster_by),
        source_group_id=prompt_case.source_group_id,
        adapter_id=config.adapter.adapter_id,
        provider=response.provider if response else config.adapter.provider,
        model=config.adapter.model,
        resolved_model=(response.resolved_model if response and response.resolved_model else None),
        provider_api_version=(
            response.provider_api_version if response else config.adapter.api_version
        ),
        provider_sdk=response.provider_sdk if response else _sdk_label(config),
        provider_region=response.provider_region if response else config.adapter.region,
        provider_response_id=response.provider_response_id if response else None,
        provider_finish_reason=response.provider_finish_reason if response else None,
        provider_serving_fingerprint=(response.provider_serving_fingerprint if response else None),
        provider_created_unix_seconds=(
            response.provider_created_unix_seconds if response else None
        ),
        traceparent=trace_context.traceparent,
        tracestate=trace_context.tracestate,
        started_at_utc=started_at_utc,
        completed_at_utc=completed_at_utc,
        latency_ms=latency_ms,
        attempt_count=attempt_count,
        retry_count=retry_count,
        rate_limit_events=rate_limit_events,
        exclusion_reason=effective_exclusion_reason,
        prompt_tokens=response.prompt_tokens if response else None,
        completion_tokens=response.completion_tokens if response else None,
        total_tokens=_response_total_tokens(response) if response else None,
        estimated_cost_usd=response.estimated_cost_usd if response else "0.000000",
        estimated_cost_source=response.estimated_cost_source if response else "not_reported",
        cost_budget_committed_usd=_cost_string(cost_budget_committed_usd),
        generated_token_budget_committed=generated_token_budget_committed,
        total_token_budget_committed=total_token_budget_committed,
        policy_results=(
            PolicyResult(
                artifact_kind="policy-result",
                policy_id="runtime.live",
                state=GateState.fail,
                reason_codes=(reason_code,),
                severity=Severity.blocker,
                message=(
                    "live response failed the structured output contract"
                    if reason_code is ReasonCode.STRUCTURED_OUTPUT_INVALID
                    else "live response exceeded the configured budget policy"
                    if reason_code is ReasonCode.POLICY_FAILED
                    else "live adapter failed before a valid structured record was accepted"
                ),
            ),
        ),
        provenance=_provenance(
            config,
            configuration_digest,
            prompt_digest=prompt_digest or sha256_hexdigest(_prompt_digest_input(prompt_case)),
        ),
    )


def _response_total_tokens(response: LiveProviderResponse) -> int | None:
    if response.total_tokens is not None:
        return response.total_tokens
    if response.prompt_tokens is None or response.completion_tokens is None:
        return None
    return response.prompt_tokens + response.completion_tokens


def _cost_string(value: Decimal) -> str:
    return f"{value:.6f}"


def _validate_cases(compiled: CompiledSuite, config: LiveRunConfig) -> None:
    suite_case_ids = {case.case_id for case in compiled.cases}
    config_case_ids = [case.case_id for case in config.cases]
    unknown = sorted(set(config_case_ids) - suite_case_ids)
    if unknown:
        raise ValueError("live config references cases not in suite: " + ", ".join(unknown))
    duplicates = sorted(
        {case_id for case_id in config_case_ids if config_case_ids.count(case_id) > 1}
    )
    if duplicates:
        raise ValueError("live config contains duplicate case_id values: " + ", ".join(duplicates))


def _validate_protocol_config(
    compiled: CompiledSuite,
    config: LiveRunConfig,
    protocol: LiveProtocolRecord,
) -> None:
    suite_digest = sha256_hexdigest(compiled.model_dump(mode="json"))
    protocol_digest = sha256_hexdigest(protocol)
    if protocol.suite_id != compiled.suite_id:
        raise ValueError("live protocol suite_id does not match compiled suite")
    if protocol.suite_version != compiled.suite_version:
        raise ValueError("live protocol suite_version does not match compiled suite")
    if protocol.suite_digest != suite_digest:
        raise ValueError("live protocol suite_digest does not match compiled suite")
    if config.protocol_id != protocol.protocol_id:
        raise ValueError("live run config protocol_id does not match protocol")
    if config.protocol_digest != protocol_digest:
        raise ValueError("live run config protocol_digest does not match protocol")
    if config.tool_schema_digest != protocol.tool_schema_digest:
        raise ValueError("live run config tool_schema_digest does not match protocol")
    if config.policy_bundle_digest != protocol.policy_bundle_digest:
        raise ValueError("live run config policy_bundle_digest does not match protocol")
    planned_requests = len(config.cases) * config.repetitions
    if config.repetitions != protocol.planned_repetitions:
        raise ValueError("live run config repetitions do not match protocol")
    if planned_requests != protocol.planned_observations:
        raise ValueError("live run config planned observations do not match protocol")
    if config.max_requests != protocol.max_requests:
        raise ValueError("live run config max_requests does not match protocol")
    if config.randomization_seed != protocol.randomization_seed:
        raise ValueError("live run config randomization_seed does not match protocol")
    if protocol.cluster_by == "source_group_id" and any(
        prompt_case.source_group_id is None for prompt_case in config.cases
    ):
        raise ValueError("source_group_id clustering requires source_group_id on every case")
    planned_clusters = {
        _cluster_id(prompt_case, protocol.cluster_by) for prompt_case in config.cases
    }
    if len(planned_clusters) != protocol.planned_clusters:
        raise ValueError("live run config cluster count does not match protocol")
    if config.max_total_cost_usd != protocol.max_total_cost_usd:
        raise ValueError("live run config max_total_cost_usd does not match protocol")
    if config.max_cost_per_observation_usd != protocol.max_cost_per_observation_usd:
        raise ValueError("live run config max_cost_per_observation_usd does not match protocol")
    if config.max_generated_tokens != protocol.max_generated_tokens:
        raise ValueError("live run config max_generated_tokens does not match protocol")
    if config.max_total_tokens != protocol.max_total_tokens:
        raise ValueError("live run config max_total_tokens does not match protocol")
    if config.max_retries != protocol.max_retries:
        raise ValueError("live run config max_retries does not match protocol")
    if config.retry_initial_backoff_seconds != protocol.retry_initial_backoff_seconds:
        raise ValueError("live run config retry_initial_backoff_seconds does not match protocol")
    if config.retry_max_backoff_seconds != protocol.retry_max_backoff_seconds:
        raise ValueError("live run config retry_max_backoff_seconds does not match protocol")
    if config.requests_per_minute != protocol.requests_per_minute:
        raise ValueError("live run config requests_per_minute does not match protocol")
    if config.tokens_per_minute != protocol.tokens_per_minute:
        raise ValueError("live run config tokens_per_minute does not match protocol")
    if config.max_rate_limit_events != protocol.max_rate_limit_events:
        raise ValueError("live run config max_rate_limit_events does not match protocol")
    if protocol.tokens_per_minute is not None and config.adapter.max_output_tokens is None:
        raise ValueError("tokens_per_minute requires adapter max_output_tokens")
    if protocol.max_generated_tokens is not None and config.adapter.max_output_tokens is None:
        raise ValueError("max_generated_tokens requires adapter max_output_tokens")
    if config.adapter.adapter_id == "openai-chat-completions" and (
        config.adapter.cost_per_1k_prompt_tokens_usd is None
        or config.adapter.cost_per_1k_completion_tokens_usd is None
    ):
        raise ValueError(
            "openai-chat-completions requires prompt and completion pricing rates "
            "to enforce the declared cost ceilings"
        )
    if config.adapter.allow_network and config.adapter.max_output_tokens is None:
        raise ValueError(
            "network live execution requires adapter max_output_tokens so the "
            "per-attempt cost ceiling is bounded"
        )
    if config.adapter.allow_network and Decimal(config.max_cost_per_observation_usd) <= Decimal(
        "0"
    ):
        raise ValueError("network live execution requires a positive max_cost_per_observation_usd")
    if (
        protocol.max_generated_tokens is not None
        and config.adapter.max_output_tokens is not None
        and config.adapter.max_output_tokens > protocol.max_generated_tokens
    ):
        raise ValueError("adapter max_output_tokens exceeds protocol max_generated_tokens")


def _planned_observation_count(config: LiveRunConfig) -> int:
    return len(config.cases) * config.repetitions


def _schedule(config: LiveRunConfig) -> Iterator[tuple[int, LivePromptCase, int]]:
    rng = random.Random(config.randomization_seed)
    schedule_index = 0
    for repetition_index in range(config.repetitions):
        block = list(config.cases)
        rng.shuffle(block)
        for prompt_case in block:
            yield schedule_index, prompt_case, repetition_index
            schedule_index += 1


def _complete_with_retries(
    adapter: LiveProviderAdapter,
    request: LiveProviderRequest,
    config: LiveRunConfig,
    *,
    request_budget: _LiveRequestBudget,
    rate_limit_budget: _LiveRateLimitBudget,
    attempt_state: _LiveAttemptState,
    before_attempt: Callable[[], None],
    attempt_observer: LiveAttemptObserver | None = None,
) -> LiveProviderResponse:
    max_attempts = config.max_retries + 1
    last_exc: Exception | None = None
    for attempt in range(1, max_attempts + 1):
        before_attempt()
        request_budget.consume()
        attempt_state.attempt_count += 1
        _notify_attempt_observer(
            attempt_observer,
            LiveAttemptNotification(
                phase="issued",
                request=request,
                adapter_attempt_index=attempt,
            ),
        )
        try:
            response = adapter.complete(request)
            if not isinstance(response, LiveProviderResponse):
                raise TypeError("live adapter returned an invalid response object")
            response = LiveProviderResponse.model_validate(response.model_dump(mode="python"))
        except Exception as exc:
            rate_limited = _is_rate_limit_error(exc)
            retryable = _is_retryable_error(exc)
            _notify_attempt_observer(
                attempt_observer,
                LiveAttemptNotification(
                    phase="failed",
                    request=request,
                    adapter_attempt_index=attempt,
                    retryable=retryable,
                    rate_limited=rate_limited,
                ),
            )
            last_exc = exc
            if rate_limited:
                attempt_state.rate_limit_events += 1
                rate_limit_budget.record()
            if not retryable:
                raise
            if attempt >= max_attempts:
                break
            if request_budget.exhausted:
                raise LiveBudgetExceededError(
                    "request_budget_exhausted",
                    "configured max_requests was exhausted before a retry",
                ) from exc
            attempt_state.retry_count += 1
            _sleep_before_retry(
                config,
                attempt_state.retry_count,
                _retry_after_seconds(exc),
            )
            continue
        _notify_attempt_observer(
            attempt_observer,
            LiveAttemptNotification(
                phase="succeeded",
                request=request,
                adapter_attempt_index=attempt,
                provider_response_id=response.provider_response_id,
            ),
        )
        return response
    if last_exc is None:
        raise RuntimeError("live adapter failed without an exception")
    raise last_exc


def _notify_attempt_observer(
    observer: LiveAttemptObserver | None,
    notification: LiveAttemptNotification,
) -> None:
    if observer is None:
        return
    try:
        observer(notification)
    except Exception as exc:
        raise LiveAttemptObserverError(
            "durable execution attempt journal update failed; aborting provider execution"
        ) from exc


def _sleep_before_retry(
    config: LiveRunConfig,
    retry_count: int,
    retry_after_seconds: Decimal | None,
) -> None:
    initial = Decimal(config.retry_initial_backoff_seconds)
    maximum = Decimal(config.retry_max_backoff_seconds)
    if maximum > MAX_LIVE_RETRY_BACKOFF_SECONDS:
        raise RuntimeError("configured retry backoff exceeds the hard safety limit")
    if retry_after_seconds is not None:
        if retry_after_seconds < 0:
            raise RuntimeError("provider Retry-After must not be negative")
        if retry_after_seconds > maximum:
            raise RuntimeError("provider Retry-After exceeds configured retry_max_backoff_seconds")
        seconds = retry_after_seconds
    else:
        seconds = min(maximum, initial * (Decimal(2) ** max(retry_count - 1, 0)))
    if seconds > 0:
        time.sleep(float(seconds))


def _retry_after_seconds(exc: Exception) -> Decimal | None:
    value = getattr(exc, "retry_after_seconds", None)
    if value is None:
        headers = getattr(exc, "headers", None)
        if headers is None:
            return None
        raw = headers.get("Retry-After")
        if raw is None:
            return None
        value = raw
    text = str(value)
    if len(text) > 32:
        raise RuntimeError("provider Retry-After value exceeds the supported length")
    try:
        return Decimal(text)
    except (InvalidOperation, ValueError) as parse_error:
        raise RuntimeError("provider Retry-After value is not a decimal delay") from parse_error


def _pace_request(
    config: LiveRunConfig,
    last_request_started: float | None,
    token_window_started: float | None,
    tokens_window_reserved: int,
    reserved_tokens: int,
) -> tuple[float | None, int]:
    if config.requests_per_minute is not None and last_request_started is not None:
        min_interval = 60.0 / config.requests_per_minute
        elapsed = time.perf_counter() - last_request_started
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
    if config.tokens_per_minute is None:
        return token_window_started, tokens_window_reserved
    if reserved_tokens > config.tokens_per_minute:
        raise ValueError("single live request token reservation exceeds tokens_per_minute")
    now = time.perf_counter()
    if token_window_started is None or now - token_window_started >= 60.0:
        token_window_started = now
        tokens_window_reserved = 0
    if tokens_window_reserved + reserved_tokens > config.tokens_per_minute:
        time.sleep(max(0.0, 60.0 - (now - token_window_started)))
        token_window_started = time.perf_counter()
        tokens_window_reserved = 0
    return token_window_started, tokens_window_reserved + reserved_tokens


def _token_reservation(prompt: str, config: LiveRunConfig) -> int:
    if config.tokens_per_minute is None:
        return 0
    output_tokens = config.adapter.max_output_tokens
    if output_tokens is None:
        raise ValueError("tokens_per_minute requires adapter max_output_tokens")
    return _prompt_token_upper_bound(prompt) + output_tokens


def _prompt_token_upper_bound(prompt: str) -> int:
    # Byte-fallback tokenizers cannot emit more ordinary-text tokens than the
    # UTF-8 byte length. Bytes are conservative where Unicode character count is not.
    return len(prompt.encode("utf-8"))


def _verify_response_budgets(response: LiveProviderResponse, config: LiveRunConfig) -> None:
    if config.adapter.allow_network and response.estimated_cost_source == "not_reported":
        raise LiveBudgetExceededError(
            "cost_accounting_unavailable",
            "provider response omitted usage required to enforce cost ceilings",
        )
    response_total_tokens = _response_total_tokens(response)
    if config.max_total_tokens is not None and response_total_tokens is None:
        raise LiveBudgetExceededError(
            "token_accounting_unavailable",
            "provider response omitted usage required to enforce max_total_tokens",
        )
    if config.max_generated_tokens is not None and response.completion_tokens is None:
        raise LiveBudgetExceededError(
            "token_accounting_unavailable",
            "provider response omitted usage required to enforce max_generated_tokens",
        )
    if Decimal(response.estimated_cost_usd) > Decimal(config.max_cost_per_observation_usd):
        raise LiveBudgetExceededError(
            "cost_budget_exceeded_after_response",
            "provider response exceeded max_cost_per_observation_usd",
        )
    if (
        config.max_total_tokens is not None
        and response_total_tokens is not None
        and response_total_tokens > config.max_total_tokens
    ):
        raise LiveBudgetExceededError(
            "token_budget_exceeded_after_response",
            "provider response exceeded max_total_tokens",
        )
    if (
        config.max_generated_tokens is not None
        and response.completion_tokens is not None
        and response.completion_tokens > config.max_generated_tokens
    ):
        raise LiveBudgetExceededError(
            "generated_token_budget_exceeded_after_response",
            "provider response exceeded max_generated_tokens",
        )


def _is_rate_limit_error(exc: Exception) -> bool:
    if getattr(exc, "status_code", None) == 429:
        return True
    if getattr(exc, "retry_after_seconds", None) is not None:
        return True
    text = str(exc).lower()
    return "429" in text or "retry-after" in text


def _is_retryable_error(exc: Exception) -> bool:
    status_code = getattr(exc, "status_code", None)
    if type(status_code) is int:
        return status_code in {408, 429} or 500 <= status_code <= 599
    if getattr(exc, "retryable", False) is True:
        return True
    if getattr(exc, "retry_after_seconds", None) is not None:
        return True
    return isinstance(exc, (TimeoutError, ConnectionError))


def _read_prompt(config_dir: Path, prompt_path: str) -> str:
    resolve_live_config_path(config_dir, prompt_path, field_name="prompt_path")
    text = read_text_bounded_at(
        config_dir,
        prompt_path,
        max_bytes=MAX_PROMPT_BYTES,
        label="live prompt",
    )
    if not text.strip():
        raise ValueError(f"prompt file is empty: {prompt_path}")
    return text


def _provenance(
    config: LiveRunConfig,
    configuration_digest: str,
    *,
    prompt_digest: str,
) -> Provenance:
    return Provenance(
        artifact_kind="provenance",
        prompt_digest=prompt_digest,
        configuration_digest=configuration_digest,
        policy_bundle_digest=config.policy_bundle_digest,
        tool_schema_digest=config.tool_schema_digest,
        # Provenance binds the requested execution identity. A provider echo is
        # response metadata and is persisted independently as resolved_model.
        model_identifier=config.adapter.model,
        retrieval_corpus_digest=config.retrieval_corpus_digest,
        evidence_sensitivity_design_digest=(config.evidence_sensitivity_design_digest),
        study_manifest_digest=config.study_manifest_digest,
    )


def _configuration_digest(
    compiled: CompiledSuite,
    config: LiveRunConfig,
    snapshot: LiveExecutionSnapshot,
) -> str:
    config_payload = config.model_dump(mode="json")
    # Higher-level commitments bind this content-derived configuration digest.
    # Excluding their back-links prevents commitment cycles without weakening
    # the digest of the executable configuration they bind.
    config_payload.pop("evidence_sensitivity_design_digest", None)
    config_payload.pop("study_manifest_digest", None)
    return sha256_hexdigest(
        {
            "execution_implementation": {
                "agent_assure_version": AGENT_ASSURE_EXECUTION_VERSION,
                "adapter_implementation_id": LIVE_ADAPTER_IMPLEMENTATION_ID,
                "provider_request_envelope_id": LIVE_PROVIDER_REQUEST_ENVELOPE_ID,
            },
            "suite_digest": sha256_hexdigest(compiled.model_dump(mode="json")),
            "live_run_config": config_payload,
            "prompt_digests": snapshot.prompt_digest_by_case(),
            "bound_input_digests": {
                "adapter_resource_sha256": (
                    snapshot.adapter_resource.content_sha256
                    if snapshot.adapter_resource is not None
                    else None
                ),
                "corpus_snapshot_digest": snapshot.corpus_snapshot_digest,
                "governing_evidence_sha256": snapshot.governing_evidence_digest,
                "governing_evidence_renderer_id": (
                    GOVERNING_EVIDENCE_RENDERER_ID
                    if snapshot.rendered_governing_evidence_message is not None
                    else None
                ),
                "rendered_governing_evidence_message_sha256": (
                    snapshot.rendered_governing_evidence_message_digest
                ),
                "knowledge_contract_file_sha256": (snapshot.knowledge_contract_file_sha256),
                "case_authority_manifest_digest": (snapshot.case_authority_manifest_digest),
            },
        }
    )


def prepare_live_execution_snapshot(
    compiled: CompiledSuite,
    config: LiveRunConfig,
    *,
    config_dir: Path,
) -> LiveExecutionSnapshot:
    """Snapshot every bounded executable input without constructing an adapter."""
    compiled = CompiledSuite.model_validate(compiled.model_dump(mode="json"))
    config = LiveRunConfig.model_validate(config.model_dump(mode="json"))
    _validate_cases(compiled, config)
    prompts = tuple(
        (prompt_case.case_id, _read_prompt(config_dir, prompt_case.prompt_path))
        for prompt_case in config.cases
    )
    prompt_digests = tuple(
        (case_id, sha256_hexdigest({"prompt": prompt})) for case_id, prompt in prompts
    )

    corpus: LoadedSensitivityCorpus | None = None
    governing_evidence: str | None = None
    governing_evidence_digest: str | None = None
    rendered_governing_evidence_message: str | None = None
    rendered_governing_evidence_message_digest: str | None = None
    if config.retrieval_corpus_dir is not None:
        corpus_path = resolve_live_config_path(
            config_dir,
            config.retrieval_corpus_dir,
            field_name="retrieval_corpus_dir",
        )
        corpus = load_sensitivity_corpus(corpus_path)
        if corpus.manifest.corpus_digest != config.retrieval_corpus_digest:
            raise ValueError("retrieval corpus does not match its configured corpus digest")
        governing_evidence = _render_governing_evidence(corpus)
        encoded_evidence = governing_evidence.encode("utf-8")
        if len(encoded_evidence) > MAX_GOVERNING_EVIDENCE_BYTES:
            raise ValueError("governing evidence exceeded the provider input byte limit")
        governing_evidence_digest = hashlib.sha256(encoded_evidence).hexdigest()

    knowledge_contract: RAGSensitivityKnowledgeContract | None = None
    knowledge_contract_file_content: bytes | None = None
    knowledge_contract_file_sha256: str | None = None
    case_authority_bindings: tuple[RAGSensitivityCaseAuthorityBinding, ...] = ()
    case_authority_manifest_digest: str | None = None
    if config.knowledge_contract_path is not None:
        resolve_live_config_path(
            config_dir,
            config.knowledge_contract_path,
            field_name="knowledge_contract_path",
        )
        contract_snapshot = read_file_bounded_at(
            config_dir,
            config.knowledge_contract_path,
            max_bytes=MAX_ARTIFACT_JSON_BYTES,
            label="knowledge-authority contract",
        )
        contract_payload = safe_load_yaml_text(
            contract_snapshot.data.decode("utf-8"),
            label="knowledge-authority contract",
        )
        if not isinstance(contract_payload, dict):
            raise TypeError("knowledge-authority contract root must be a mapping")
        knowledge_contract = RAGSensitivityKnowledgeContract.model_validate(contract_payload)
        if knowledge_contract.knowledge_contract_digest != config.knowledge_contract_digest:
            raise ValueError("knowledge-authority contract does not match its configured digest")
        knowledge_contract_file_sha256 = contract_snapshot.sha256
        knowledge_contract_file_content = contract_snapshot.data
        authority_by_case = {
            item.case_id: item
            for item in knowledge_contract_case_authority_bindings(knowledge_contract)
        }
        configured_case_ids = tuple(sorted(item.case_id for item in config.cases))
        missing_case_ids = tuple(
            case_id for case_id in configured_case_ids if case_id not in authority_by_case
        )
        if missing_case_ids:
            raise ValueError(
                "knowledge-authority contract does not explicitly cover configured cases: "
                + ", ".join(missing_case_ids)
            )
        case_authority_bindings = tuple(
            authority_by_case[case_id] for case_id in configured_case_ids
        )
        compiled_cases = {item.case_id: item for item in compiled.cases}
        for case_binding in case_authority_bindings:
            compiled_case = compiled_cases[case_binding.case_id]
            if (
                case_binding.query_family_id != compiled_case.case_id
                and case_binding.query_family_id not in compiled_case.tags
            ):
                raise ValueError("case authority query family is not declared by the compiled case")
        if corpus is not None:
            for case_binding in case_authority_bindings:
                if case_binding.query_family_id != corpus.manifest.query_family_id:
                    raise ValueError(
                        "case authority query family does not match the configured corpus"
                    )
                assignment = next(
                    (
                        item
                        for item in case_binding.assignments
                        if item.corpus_digest == corpus.manifest.corpus_digest
                    ),
                    None,
                )
                if assignment is None:
                    raise ValueError(
                        "case authority binding has no assignment for the configured corpus"
                    )
                if not any(
                    (
                        document.descriptor.source_id,
                        document.payload.ref_id,
                        document.descriptor.content_digest,
                        document.payload.governing_decision,
                        document.payload.governing_outcome,
                    )
                    == (
                        assignment.governing_source_id,
                        assignment.governing_ref_id,
                        assignment.governing_content_digest,
                        assignment.expected_decision,
                        assignment.expected_outcome,
                    )
                    for document in corpus.snapshot.documents
                ):
                    raise ValueError(
                        "case authority assignment does not match exact governing corpus evidence"
                    )
        case_authority_manifest_digest = sha256_hexdigest(
            tuple(item.model_dump(mode="json") for item in case_authority_bindings)
        )

    if governing_evidence is not None and governing_evidence_digest is not None:
        rendered_governing_evidence_message = render_governing_evidence_message(
            governing_evidence=governing_evidence,
            governing_evidence_digest=governing_evidence_digest,
            knowledge_contract_digest=(
                knowledge_contract.knowledge_contract_digest
                if knowledge_contract is not None
                else config.knowledge_contract_digest
            ),
        )
        rendered_governing_evidence_message_digest = hashlib.sha256(
            rendered_governing_evidence_message.encode("utf-8")
        ).hexdigest()

    return _validate_live_execution_snapshot(
        compiled,
        config,
        LiveExecutionSnapshot(
            prompts=prompts,
            prompt_digests=prompt_digests,
            governing_evidence=governing_evidence,
            governing_evidence_digest=governing_evidence_digest,
            rendered_governing_evidence_message=rendered_governing_evidence_message,
            rendered_governing_evidence_message_digest=(rendered_governing_evidence_message_digest),
            corpus_snapshot=corpus.snapshot if corpus is not None else None,
            corpus_snapshot_digest=(
                corpus.snapshot.snapshot_digest if corpus is not None else None
            ),
            knowledge_contract=knowledge_contract,
            knowledge_contract_file_content=knowledge_contract_file_content,
            knowledge_contract_file_sha256=knowledge_contract_file_sha256,
            case_authority_bindings=case_authority_bindings,
            case_authority_manifest_digest=case_authority_manifest_digest,
            adapter_resource=snapshot_live_adapter_resource(config.adapter, base_dir=config_dir),
        ),
    )


def calculate_live_execution_configuration_digest(
    compiled: CompiledSuite,
    config: LiveRunConfig,
    *,
    config_dir: Path,
    execution_snapshot: LiveExecutionSnapshot | None = None,
) -> str:
    """Return the exact arm identity before any provider dispatch.

    This read-only planning operation uses the same bounded prompt reads and
    canonical projection as run_live_suite. It never constructs an adapter,
    opens a network connection, or executes an external script. A supplied
    snapshot is authoritative detached input; validation binds its exact bytes
    but does not prove current mutable-path provenance.
    """
    compiled = CompiledSuite.model_validate(compiled.model_dump(mode="json"))
    config = LiveRunConfig.model_validate(config.model_dump(mode="json"))
    _validate_cases(compiled, config)
    snapshot = (
        prepare_live_execution_snapshot(compiled, config, config_dir=config_dir)
        if execution_snapshot is None
        else _validate_live_execution_snapshot(compiled, config, execution_snapshot)
    )
    return _configuration_digest(compiled, config, snapshot)


def calculate_live_prompt_manifest_digest(
    compiled: CompiledSuite,
    config: LiveRunConfig,
    *,
    config_dir: Path,
    execution_snapshot: LiveExecutionSnapshot | None = None,
) -> str:
    """Return a case-keyed digest of authoritative bounded prompt bytes.

    When a snapshot is supplied, its validated prompt bytes are authoritative;
    the digest does not assert that the mutable prompt paths still contain them.
    """
    compiled = CompiledSuite.model_validate(compiled.model_dump(mode="json"))
    config = LiveRunConfig.model_validate(config.model_dump(mode="json"))
    _validate_cases(compiled, config)
    snapshot = (
        prepare_live_execution_snapshot(compiled, config, config_dir=config_dir)
        if execution_snapshot is None
        else _validate_live_execution_snapshot(compiled, config, execution_snapshot)
    )
    return sha256_hexdigest({"prompt_digests": snapshot.prompt_digest_by_case()})


def calculate_provider_input_manifest_digest(
    provider_input_digest_by_case: Mapping[str, str],
) -> str:
    """Commit an exact case-keyed set of provider-input digests.

    The per-case values are the digests persisted as ``Provenance.prompt_digest``.
    They may include rendered governing evidence and knowledge-contract identity,
    not only the raw case prompt. Canonical case ordering makes the commitment
    independent of mapping insertion order.
    """

    entries = tuple(sorted(provider_input_digest_by_case.items()))
    if not entries:
        raise ValueError("provider-input manifest cannot be empty")
    for case_id, digest in entries:
        if not case_id:
            raise ValueError("provider-input manifest case IDs cannot be empty")
        _snapshot_sha256(digest, label=f"provider-input digest for {case_id}")
    return sha256_hexdigest(
        {
            "purpose": "live-provider-input-manifest/v1",
            "provider_input_digests": entries,
        }
    )


def calculate_live_provider_input_manifest_digest(
    compiled: CompiledSuite,
    config: LiveRunConfig,
    *,
    config_dir: Path,
    execution_snapshot: LiveExecutionSnapshot | None = None,
) -> str:
    """Commit the exact case-keyed provider inputs without provider dispatch."""

    compiled = CompiledSuite.model_validate(compiled.model_dump(mode="json"))
    config = LiveRunConfig.model_validate(config.model_dump(mode="json"))
    _validate_cases(compiled, config)
    snapshot = (
        prepare_live_execution_snapshot(compiled, config, config_dir=config_dir)
        if execution_snapshot is None
        else _validate_live_execution_snapshot(compiled, config, execution_snapshot)
    )
    return calculate_snapshot_provider_input_manifest_digest(snapshot)


def calculate_snapshot_provider_input_manifest_digest(
    snapshot: LiveExecutionSnapshot,
) -> str:
    """Commit provider inputs from a snapshot already validated by its caller."""

    return calculate_provider_input_manifest_digest(
        {
            case_id: _provider_input_digest(prompt_digest, snapshot)
            for case_id, prompt_digest in snapshot.prompt_digests
        }
    )


def _render_governing_evidence(corpus: LoadedSensitivityCorpus) -> str:
    return _render_governing_evidence_snapshot(corpus.snapshot)


def _render_governing_evidence_snapshot(
    snapshot: RAGSensitivityCorpusSnapshot,
) -> str:
    payload = {
        "artifact_kind": "live-governing-evidence",
        "corpus_digest": snapshot.corpus_manifest.corpus_digest,
        "corpus_snapshot_digest": snapshot.snapshot_digest,
        "documents": [
            {
                "content_digest": document.descriptor.content_digest,
                "payload": document.payload.model_dump(mode="json"),
                "source_id": document.descriptor.source_id,
            }
            for document in snapshot.documents
        ],
    }
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _provider_input_digest(
    prompt_digest: str,
    snapshot: LiveExecutionSnapshot,
) -> str:
    knowledge_contract_digest = (
        snapshot.knowledge_contract.knowledge_contract_digest
        if snapshot.knowledge_contract is not None
        else None
    )
    governing_fields = (
        snapshot.governing_evidence,
        snapshot.governing_evidence_digest,
        snapshot.rendered_governing_evidence_message,
        snapshot.rendered_governing_evidence_message_digest,
    )
    if any(item is not None for item in governing_fields) and not all(
        item is not None for item in governing_fields
    ):
        raise ValueError("governing evidence provider-input snapshot is incomplete")
    if snapshot.governing_evidence is None and knowledge_contract_digest is None:
        return prompt_digest

    message_sequence: list[dict[str, str]] = []
    if snapshot.governing_evidence is not None:
        assert snapshot.governing_evidence_digest is not None
        assert snapshot.rendered_governing_evidence_message_digest is not None
        message_sequence.extend(
            (
                {
                    "role": "system",
                    "renderer_id": GOVERNING_EVIDENCE_RENDERER_ID,
                    "content_sha256": (snapshot.rendered_governing_evidence_message_digest),
                },
                {
                    "role": "user",
                    "content_kind": "governing_evidence",
                    "content_sha256": snapshot.governing_evidence_digest,
                },
            )
        )
    message_sequence.append(
        {
            "role": "user",
            "content_kind": "case_prompt",
            "content_digest": prompt_digest,
        }
    )
    return sha256_hexdigest(
        {
            "message_sequence": tuple(message_sequence),
            "knowledge_contract_digest": knowledge_contract_digest,
        }
    )


def _prompt_digest_input(prompt_case: LivePromptCase) -> dict[str, str]:
    return {
        "case_id": prompt_case.case_id,
        "prompt_path": prompt_case.prompt_path,
        "input_summary": redact_text(prompt_case.input_summary),
    }


def _cluster_id(prompt_case: LivePromptCase, cluster_by: str) -> str:
    if cluster_by == "source_group_id":
        if prompt_case.source_group_id is None:
            raise ValueError("source_group_id clustering requires source_group_id")
        return prompt_case.source_group_id
    return prompt_case.case_id


def _runset_id(suite_id: str, variant_id: str, configuration_digest: str) -> str:
    key = f"live:{suite_id}:{variant_id}:{configuration_digest}"
    return f"runset-{uuid5(AGENT_ASSURE_NAMESPACE, key)}"


def _run_id(suite_id: str, variant_id: str, case_id: str, repetition_index: int) -> str:
    key = f"live:{suite_id}:{variant_id}:{case_id}:{repetition_index}"
    return f"run-{uuid5(AGENT_ASSURE_NAMESPACE, key)}"


def _observation_id(suite_id: str, variant_id: str, case_id: str, repetition_index: int) -> str:
    key = f"live-observation:{suite_id}:{variant_id}:{case_id}:{repetition_index}"
    return f"obs-{uuid5(AGENT_ASSURE_NAMESPACE, key)}"


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _completion_utc(started_at_utc: str) -> str:
    observed = datetime.fromisoformat(_utc_now().replace("Z", "+00:00"))
    started = datetime.fromisoformat(started_at_utc.replace("Z", "+00:00"))
    completed = observed if observed > started else started + timedelta(microseconds=1)
    return completed.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _sdk_label(config: LiveRunConfig) -> str | None:
    return live_sdk_identifier(config.adapter)
