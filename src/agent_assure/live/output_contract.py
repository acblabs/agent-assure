from __future__ import annotations

from typing import Any

from pydantic import Field
from pydantic.functional_validators import field_validator

from agent_assure.io_limits import loads_json_bounded
from agent_assure.schema.base import StrictModel
from agent_assure.schema.common import MAX_LABEL_CHARS, MAX_SUMMARY_CHARS, coerce_tuple
from agent_assure.schema.run import (
    ClaimEvidenceLink,
    ClaimRecord,
    EvidenceItem,
    EvidenceRef,
    PolicyResult,
)


class LiveOutputContractError(ValueError):
    pass


class LiveStructuredRecord(StrictModel):
    recommendation: str = Field(max_length=MAX_LABEL_CHARS)
    outcome: str = Field(max_length=MAX_LABEL_CHARS)
    output_summary: str = Field(max_length=MAX_SUMMARY_CHARS)
    tools: tuple[str, ...] = ()
    evidence_refs: tuple[EvidenceRef, ...] = ()
    evidence_items: tuple[EvidenceItem, ...] = ()
    claims: tuple[ClaimRecord, ...] = ()
    claim_evidence_links: tuple[ClaimEvidenceLink, ...] = ()
    policy_results: tuple[PolicyResult, ...] = ()
    human_review_required: bool = False
    human_review_performed: bool = False

    @field_validator(
        "tools",
        "evidence_refs",
        "evidence_items",
        "claims",
        "claim_evidence_links",
        "policy_results",
        mode="before",
    )
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)


def parse_live_structured_content(content: str) -> LiveStructuredRecord:
    payload = _parse_json_object(content)
    try:
        return LiveStructuredRecord.model_validate(payload)
    except Exception as exc:
        raise LiveOutputContractError(
            "live structured output failed the AgentRunRecord producer contract"
        ) from exc


def validate_live_structured_content(content: str) -> None:
    parse_live_structured_content(content)


def _parse_json_object(content: str) -> dict[str, Any]:
    text = content.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if len(lines) >= 3 and lines[-1].strip().startswith("```"):
            text = "\n".join(lines[1:-1]).strip()
            if text.startswith("json"):
                text = text[4:].strip()
    try:
        payload = loads_json_bounded(text, label="live structured output JSON")
    except ValueError as exc:
        raise LiveOutputContractError("live structured output was not valid JSON") from exc
    if not isinstance(payload, dict):
        raise LiveOutputContractError("live structured output JSON root must be an object")
    return payload
