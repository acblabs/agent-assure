from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Protocol, runtime_checkable

from pydantic import Field, model_validator
from pydantic.functional_validators import field_validator

from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.schema.base import StrictModel
from agent_assure.schema.common import DigestHex, ExecutionMode
from agent_assure.schema.provenance import Provenance
from agent_assure.schema.run import (
    AgentRunRecord,
    ClaimEvidenceLink,
    ClaimRecord,
    EvidenceRef,
)
from agent_assure.schema.usage import UsageLedger, UsageSegment, UsageSummary
from agent_assure.usage.aggregation import aggregate_usage_segments

EXPERIMENTAL_ADAPTER_API = "agent-assure-framework-adapters/experimental-v0"

_RAW_PAYLOAD_KEYS = frozenset(
    {
        "completion",
        "completions",
        "input",
        "input_summary",
        "message",
        "messages",
        "output",
        "output_summary",
        "prompt",
        "prompts",
        "raw_completion",
        "raw_completions",
        "raw_input",
        "raw_output",
        "raw_prompt",
        "raw_prompts",
        "raw_summary",
        "summary",
        "tool_args",
        "tool_input",
        "tool_inputs",
    }
)
_USAGE_SEGMENT_COMPACT_STRING_FIELDS = (
    "segment_id",
    "case_id",
    "run_id",
    "span_id",
    "parent_span_id",
    "provider",
    "model",
    "operation",
    "cost_basis",
    "pricing_snapshot_id",
)
_OBSERVATION_COMPACT_STRING_FIELDS = (
    "event_type",
    "provider",
    "model",
    "tool_name",
    "review_route",
    "redaction_state",
)


class FrameworkObservation(StrictModel):
    observation_id: str = Field(min_length=1)
    framework: str = Field(min_length=1)
    framework_version: str | None = None
    run_id: str = Field(min_length=1)
    case_id: str | None = None
    sequence_number: int = Field(ge=0)
    timestamp: str | None = None

    node_id: str | None = None
    node_name: str | None = None
    event_type: str = Field(min_length=1)

    provider: str | None = None
    model: str | None = None
    tool_name: str | None = None
    review_route: str | None = None
    evidence_refs: tuple[str, ...] = ()
    redaction_state: str | None = None

    usage_segment: UsageSegment | None = None
    span_context: dict[str, str] | None = None
    privacy_filtered_attributes: dict[str, str] = Field(default_factory=dict)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _coerce_evidence_refs(cls, value: object) -> object:
        return _coerce_string_tuple(value)

    @model_validator(mode="after")
    def _validate_privacy_boundary(self) -> FrameworkObservation:
        validate_privacy_filtered_mapping(
            self.privacy_filtered_attributes,
            owner="privacy_filtered_attributes",
        )
        if self.span_context is not None:
            validate_privacy_filtered_mapping(self.span_context, owner="span_context")
        if self.usage_segment is not None:
            validate_privacy_filtered_usage_segment(self.usage_segment)
        validate_privacy_filtered_observation_labels(self)
        return self


class FrameworkRunProjection(StrictModel):
    pipeline_id: str = Field(min_length=1)
    recommendation: str = Field(min_length=1)
    outcome: str = Field(min_length=1)
    input_summary: str | None = None
    output_summary: str | None = None
    provider: str | None = None
    model: str | None = None
    tools: tuple[str, ...] = ()
    evidence_claim_map: dict[str, tuple[str, ...]] = Field(default_factory=dict)
    evidence_source_map: dict[str, str] = Field(default_factory=dict)
    human_review_required: bool = False
    human_review_performed: bool = False
    adapter_id: str | None = None

    @field_validator("tools", mode="before")
    @classmethod
    def _coerce_tools(cls, value: object) -> object:
        return _coerce_string_tuple(value)

    @field_validator("evidence_claim_map", mode="before")
    @classmethod
    def _coerce_evidence_claim_map(cls, value: object) -> object:
        if not isinstance(value, Mapping):
            return value
        return {
            str(ref_id): _coerce_string_tuple(claim_ids)
            for ref_id, claim_ids in value.items()
        }


@runtime_checkable
class FrameworkAdapter(Protocol):
    adapter_id: str
    framework: str
    experimental: bool

    def observations_from_events(
        self,
        events: Iterable[object],
        *,
        run_id: str | None = None,
        case_id: str | None = None,
    ) -> tuple[FrameworkObservation, ...]:
        """Translate framework events into privacy-filtered observations."""


def build_run_record_from_observations(
    observations: Iterable[FrameworkObservation],
    *,
    projection: FrameworkRunProjection,
    run_id: str,
    case_id: str,
    fixture_manifest_digest: DigestHex,
    configuration_digest: DigestHex | None = None,
    require_observed_final_decision: bool = True,
    require_observed_human_review: bool = False,
) -> AgentRunRecord:
    ordered = tuple(sorted(observations, key=lambda observation: observation.sequence_number))
    if not ordered:
        raise ValueError("at least one framework observation is required")
    _validate_observation_group(ordered, run_id=run_id, case_id=case_id)

    provider = projection.provider or _last_observed(ordered, "provider")
    model = projection.model or _last_observed(ordered, "model")
    evidence_ref_ids = _ordered_unique(
        ref_id for observation in ordered for ref_id in observation.evidence_refs
    )
    tool_names = _ordered_unique(
        (*projection.tools, *tuple(obs.tool_name for obs in ordered if obs.tool_name))
    )
    usage_segments = tuple(
        _usage_segment_for_observation(observation, run_id=run_id, case_id=case_id)
        for observation in ordered
        if observation.usage_segment is not None
    )
    usage_ledger, usage_summary = _usage_artifacts(usage_segments)
    observation_id = _observation_group_id(ordered)
    observed_recommendation = _last_observed_attribute(ordered, "recommendation")
    observed_outcome = _last_observed_attribute(ordered, "outcome")
    observed_human_review_required = _last_observed_bool_attribute(
        ordered,
        "human_review_required",
    )
    observed_human_review_performed = _last_observed_bool_attribute(
        ordered,
        "human_review_performed",
    )
    if require_observed_final_decision and (
        observed_recommendation is None or observed_outcome is None
    ):
        raise ValueError(
            "framework observations must include observed recommendation and outcome "
            "privacy_filtered_attributes"
        )
    if require_observed_human_review and (
        observed_human_review_required is None or observed_human_review_performed is None
    ):
        raise ValueError(
            "framework observations must include observed human_review_required and "
            "human_review_performed privacy_filtered_attributes"
        )
    recommendation = observed_recommendation or projection.recommendation
    outcome = observed_outcome or projection.outcome

    return AgentRunRecord(
        artifact_kind="agent-run-record",
        run_id=run_id,
        case_id=case_id,
        # Framework adapters currently emit fixture-mode review artifacts only.
        # Live mode requires protocol-bound repetition, schedule, and cluster
        # metadata produced by the live runner rather than this projection helper.
        execution_mode=ExecutionMode.fixture,
        pipeline_id=projection.pipeline_id,
        recommendation=recommendation,
        outcome=outcome,
        input_summary=projection.input_summary
        or f"case={case_id}; framework={ordered[0].framework}; observations={len(ordered)}",
        output_summary=projection.output_summary
        or f"recommendation={recommendation}; outcome={outcome}",
        observation_id=observation_id,
        adapter_id=projection.adapter_id or f"framework:{ordered[0].framework}",
        provider=provider,
        model=model,
        tools=tool_names,
        evidence_refs=_evidence_refs(evidence_ref_ids, projection),
        claims=_claim_records(projection.evidence_claim_map),
        claim_evidence_links=_claim_evidence_links(evidence_ref_ids, projection),
        human_review_required=(
            observed_human_review_required
            if observed_human_review_required is not None
            else projection.human_review_required
        ),
        human_review_performed=(
            observed_human_review_performed
            if observed_human_review_performed is not None
            else projection.human_review_performed
        ),
        usage_ledger=usage_ledger,
        usage_summary=usage_summary,
        provenance=Provenance(
            artifact_kind="provenance",
            configuration_digest=configuration_digest,
            fixture_manifest_digest=fixture_manifest_digest,
            model_identifier=model,
        ),
    )


def stable_observation_id(
    *,
    framework: str,
    run_id: str,
    sequence_number: int,
    event_type: str,
    node_name: str | None = None,
    node_id: str | None = None,
) -> str:
    digest = sha256_hexdigest(
        {
            "event_type": event_type,
            "framework": framework,
            "node_id": node_id,
            "node_name": node_name,
            "run_id": run_id,
            "sequence_number": sequence_number,
        }
    )
    return f"{framework}-obs-{digest[:16]}"


def validate_no_raw_payload_keys(payload: Mapping[str, object], *, owner: str) -> None:
    for key in payload:
        if _looks_like_raw_payload_key(str(key)):
            raise ValueError(f"{owner} contains raw payload key {key!r}")


def validate_privacy_filtered_mapping(payload: Mapping[str, str], *, owner: str) -> None:
    validate_no_raw_payload_keys(payload, owner=owner)
    for key, value in payload.items():
        if _looks_like_raw_payload_value(value):
            raise ValueError(
                f"{owner} value for {key!r} must be a compact filtered token, "
                "label, or digest"
            )


def validate_privacy_filtered_usage_segment(segment: UsageSegment) -> None:
    for field_name in _USAGE_SEGMENT_COMPACT_STRING_FIELDS:
        value = getattr(segment, field_name)
        if value is not None and _looks_like_raw_payload_value(value):
            raise ValueError(
                f"usage_segment.{field_name} must be a compact filtered token, "
                "label, or digest"
            )


def validate_privacy_filtered_observation_labels(
    observation: FrameworkObservation,
) -> None:
    for field_name in _OBSERVATION_COMPACT_STRING_FIELDS:
        value = getattr(observation, field_name)
        if value is not None and _looks_like_raw_payload_value(value):
            raise ValueError(
                f"observation.{field_name} must be a compact filtered token, "
                "label, or digest"
            )


def _validate_observation_group(
    observations: tuple[FrameworkObservation, ...],
    *,
    run_id: str,
    case_id: str,
) -> None:
    frameworks = {observation.framework for observation in observations}
    if len(frameworks) != 1:
        raise ValueError("framework observations must come from one framework")
    _validate_unique_observation_field(observations, "observation_id")
    _validate_unique_observation_field(observations, "sequence_number")
    for observation in observations:
        if observation.run_id != run_id:
            raise ValueError("framework observation run_id does not match run record")
        if observation.case_id is not None and observation.case_id != case_id:
            raise ValueError("framework observation case_id does not match run record")


def _validate_unique_observation_field(
    observations: tuple[FrameworkObservation, ...],
    field_name: str,
) -> None:
    seen: set[object] = set()
    duplicates: set[object] = set()
    for observation in observations:
        value = getattr(observation, field_name)
        if value in seen:
            duplicates.add(value)
        seen.add(value)
    if duplicates:
        duplicate_values = ", ".join(sorted(str(value) for value in duplicates))
        raise ValueError(
            f"framework observations contain duplicate {field_name}: {duplicate_values}"
        )


def _usage_artifacts(
    usage_segments: tuple[UsageSegment, ...],
) -> tuple[UsageLedger | None, UsageSummary | None]:
    if not usage_segments:
        return None, None
    usage = aggregate_usage_segments(usage_segments)
    return usage.usage_ledger, usage.usage_summary


def _usage_segment_for_observation(
    observation: FrameworkObservation,
    *,
    run_id: str,
    case_id: str,
) -> UsageSegment:
    if observation.usage_segment is None:
        raise ValueError("observation has no usage segment")
    payload = observation.usage_segment.model_dump(mode="json")
    _set_if_none(payload, "run_id", run_id)
    _set_if_none(payload, "case_id", case_id)
    _set_if_none(payload, "provider", observation.provider)
    _set_if_none(payload, "model", observation.model)
    _set_if_none(payload, "operation", observation.event_type)
    _set_if_none(payload, "event_range_start", observation.sequence_number)
    _set_if_none(payload, "event_range_end", observation.sequence_number)
    if observation.span_context:
        _set_if_none(payload, "span_id", observation.span_context.get("span_id"))
        _set_if_none(
            payload,
            "parent_span_id",
            observation.span_context.get("parent_span_id"),
        )
    return UsageSegment.model_validate(payload)


def _evidence_refs(
    evidence_ref_ids: tuple[str, ...],
    projection: FrameworkRunProjection,
) -> tuple[EvidenceRef, ...]:
    return tuple(
        EvidenceRef(
            artifact_kind="evidence-ref",
            ref_id=ref_id,
            source_id=projection.evidence_source_map.get(ref_id, ref_id),
            claim_ids=projection.evidence_claim_map.get(ref_id, ()),
        )
        for ref_id in evidence_ref_ids
    )


def _claim_records(evidence_claim_map: Mapping[str, tuple[str, ...]]) -> tuple[ClaimRecord, ...]:
    claim_ids = _ordered_unique(
        claim_id
        for claim_ids in evidence_claim_map.values()
        for claim_id in claim_ids
    )
    return tuple(
        ClaimRecord(artifact_kind="claim-record", claim_id=claim_id)
        for claim_id in claim_ids
    )


def _claim_evidence_links(
    evidence_ref_ids: tuple[str, ...],
    projection: FrameworkRunProjection,
) -> tuple[ClaimEvidenceLink, ...]:
    present_refs = set(evidence_ref_ids)
    links: list[ClaimEvidenceLink] = []
    for ref_id, claim_ids in projection.evidence_claim_map.items():
        if ref_id not in present_refs:
            continue
        for claim_id in claim_ids:
            links.append(
                ClaimEvidenceLink(
                    artifact_kind="claim-evidence-link",
                    claim_id=claim_id,
                    evidence_ref_id=ref_id,
                )
            )
    return tuple(links)


def _observation_group_id(observations: tuple[FrameworkObservation, ...]) -> str:
    digest = sha256_hexdigest(
        [
            observation.model_dump(mode="json", exclude={"usage_segment"})
            for observation in observations
        ]
    )
    return f"{observations[0].framework}-observation-group-{digest[:16]}"


def _set_if_none(payload: dict[str, object], key: str, value: object) -> None:
    if payload.get(key) is None:
        payload[key] = value


def _last_observed(
    observations: tuple[FrameworkObservation, ...],
    field_name: str,
) -> str | None:
    for observation in reversed(observations):
        value = getattr(observation, field_name)
        if isinstance(value, str):
            return value
    return None


def _last_observed_attribute(
    observations: tuple[FrameworkObservation, ...],
    key: str,
) -> str | None:
    for observation in reversed(observations):
        value = observation.privacy_filtered_attributes.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _last_observed_bool_attribute(
    observations: tuple[FrameworkObservation, ...],
    key: str,
) -> bool | None:
    for observation in reversed(observations):
        if key not in observation.privacy_filtered_attributes:
            continue
        value = observation.privacy_filtered_attributes[key]
        if value == "true":
            return True
        if value == "false":
            return False
        raise ValueError(
            f"framework observation attribute {key!r} must be exactly 'true' or 'false'"
        )
    return None


def _ordered_unique(values: Iterable[str | None]) -> tuple[str, ...]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value is None or value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return tuple(ordered)


def _coerce_string_tuple(value: object) -> object:
    if value is None:
        return ()
    if isinstance(value, tuple):
        return value
    if isinstance(value, list):
        return tuple(value)
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Sequence) and not isinstance(value, bytes | bytearray):
        return tuple(value)
    return value


def _looks_like_raw_payload_key(key: str) -> bool:
    normalized = key.strip().lower().replace("-", "_").replace(".", "_")
    return normalized in _RAW_PAYLOAD_KEYS or normalized.endswith("_raw")


def _looks_like_raw_payload_value(value: str) -> bool:
    return "\n" in value or "\r" in value or "\t" in value or " " in value
