from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from enum import StrEnum
from typing import Annotated, Any, Literal, TypeAlias

from pydantic import Field, GetJsonSchemaHandler
from pydantic.functional_validators import field_validator, model_validator
from pydantic_core import CoreSchema

from agent_assure.atlas_catalog import (
    MITRE_ATLAS_2026_06_RELEASE,
    load_mitre_atlas_2026_06_catalog,
)
from agent_assure.schema.base import SCHEMA_VERSION, PersistedArtifact
from agent_assure.schema.common import DigestHex, coerce_enum, coerce_tuple


class ControlFramework(StrEnum):
    nist_ai_rmf = "nist-ai-rmf"
    owasp_llm_top_10_2025 = "owasp-llm-top-10-2025"
    iso_iec_42001 = "iso-iec-42001"
    mitre_atlas_2026_06 = "mitre-atlas-2026-06"


class ControlCoverageState(StrEnum):
    observed = "observed"
    partially_observed = "partially_observed"
    conditionally_observed = "conditionally_observed"
    contradictory_evidence_observed = "contradictory_evidence_observed"
    not_observed = "not_observed"
    not_evaluated = "not_evaluated"
    not_applicable = "not_applicable"
    out_of_scope = "out_of_scope"


class ControlMappingStrength(StrEnum):
    direct = "direct"
    partial = "partial"
    adjacent = "adjacent"
    gap = "gap"
    not_applicable = "not_applicable"


CONTROL_FRAMEWORK_VERSIONS: Mapping[ControlFramework, str] = {
    ControlFramework.nist_ai_rmf: "1.0",
    ControlFramework.owasp_llm_top_10_2025: "2025",
    ControlFramework.iso_iec_42001: "2023",
    ControlFramework.mitre_atlas_2026_06: MITRE_ATLAS_2026_06_RELEASE,
}


def _validate_control_framework_version(
    framework: ControlFramework,
    framework_version: str,
    *,
    owner: str,
) -> None:
    expected_version = CONTROL_FRAMEWORK_VERSIONS[framework]
    if framework_version != expected_version:
        raise ValueError(
            f"{owner} framework {framework.value!r} requires framework_version {expected_version!r}"
        )


def _validate_mitre_mapping_identifiers(
    *,
    control_id: str,
    title: str,
    expected_title: str,
    mapping_strength: ControlMappingStrength,
    atlas_tactic_ids: tuple[str, ...],
    atlas_technique_ids: tuple[str, ...],
    owner: str,
) -> None:
    if title != expected_title:
        raise ValueError(
            f"{owner} {control_id!r} title must match the pinned catalog name {expected_title!r}"
        )
    if control_id not in atlas_technique_ids:
        raise ValueError(
            f"{owner} {control_id!r} must include its control_id in atlas_technique_ids"
        )
    if mapping_strength is ControlMappingStrength.not_applicable and (
        atlas_tactic_ids or atlas_technique_ids != (control_id,)
    ):
        raise ValueError(
            f"{owner} {control_id!r} with mapping_strength 'not_applicable' must use "
            "no tactic IDs and exactly its control_id as the sole technique subject"
        )


_ControlCoverageSemanticItem: TypeAlias = Mapping[str, object]
_SEMANTIC_MAPPING_IDENTITY_SCHEMA_VERSIONS = frozenset({"0.6.6", SCHEMA_VERSION})


_FALSE_OBSERVATION_FORBIDDEN_STATES = frozenset(
    {
        ControlCoverageState.observed,
        ControlCoverageState.contradictory_evidence_observed,
    }
)
_TRUE_OBSERVATION_FORBIDDEN_STATES = frozenset(
    {
        ControlCoverageState.not_observed,
        ControlCoverageState.not_evaluated,
    }
)


CLAIM_BOUNDARY = (
    "This report maps observed `agent-assure` evidence to selected framework concepts "
    "for human review. It is not a compliance attestation, certification, audit "
    "opinion, legal conclusion, regulatory conclusion, or safety claim."
)
MITRE_ATLAS_BOUNDARY = (
    "MITRE ATLAS mappings are planning crosswalks only and are not adversary-emulation "
    "results, ATLAS coverage claims, validation results, endorsements, or "
    "threat-resistance claims."
)


def _project_control_coverage_limitations(
    framework: ControlFramework,
    limitations: Iterable[str],
) -> tuple[str, ...]:
    """Project mandatory boundaries around ordered, deduplicated additions."""

    reserved_boundaries = {CLAIM_BOUNDARY, MITRE_ATLAS_BOUNDARY}
    additions = tuple(
        dict.fromkeys(item for item in limitations if item not in reserved_boundaries)
    )
    if framework is ControlFramework.mitre_atlas_2026_06:
        return (CLAIM_BOUNDARY, *additions, MITRE_ATLAS_BOUNDARY)
    return (CLAIM_BOUNDARY, *additions)


def _derive_control_coverage_report_id(
    *,
    framework: ControlFramework | str,
    framework_version: str,
    mapping_digest: str,
    evidence_packet_id: str | None = None,
    evidence_packet_digest: str,
    item_states: Iterable[tuple[str, ControlCoverageState | str]],
    schema_version: str = SCHEMA_VERSION,
    mapping_version: str | None = None,
    item_semantics: Iterable[_ControlCoverageSemanticItem] | None = None,
    limitations: Iterable[str] | None = None,
) -> str:
    """Replay the versioned control-report identity projection.

    Versions through v0.6.5 retain their published state-only projection.
    Current reports also bind the complete reviewer-visible semantic
    projection, closing collisions where distinct report narratives previously
    shared one report ID. This is identity binding, not source authentication.
    """

    from agent_assure.canonical.digests import sha256_hexdigest

    framework_value = framework.value if isinstance(framework, ControlFramework) else framework
    normalized_item_states = tuple(item_states)
    report_key: dict[str, object] = {
        "framework": framework_value,
        "framework_version": framework_version,
        "mapping_digest": mapping_digest,
        "evidence_packet_digest": evidence_packet_digest,
        "items": [
            {
                "control_id": control_id,
                "coverage_state": (
                    state.value if isinstance(state, ControlCoverageState) else state
                ),
            }
            for control_id, state in normalized_item_states
        ],
    }
    if schema_version in _SEMANTIC_MAPPING_IDENTITY_SCHEMA_VERSIONS:
        if (
            mapping_version is None
            or evidence_packet_id is None
            or item_semantics is None
            or limitations is None
        ):
            raise ValueError(
                "current control-report identity requires mapping_version, evidence_packet_id, "
                "item semantics, and report limitations"
            )
        normalized_items = tuple(dict(item) for item in item_semantics)
        normalized_state_values = tuple(
            (
                control_id,
                state.value if isinstance(state, ControlCoverageState) else state,
            )
            for control_id, state in normalized_item_states
        )
        semantic_states = tuple(
            (item.get("control_id"), item.get("coverage_state")) for item in normalized_items
        )
        if semantic_states != normalized_state_values:
            raise ValueError(
                "control-report identity item semantics must match the supplied item states"
            )
        report_key["schema_version"] = schema_version
        report_key["mapping_version"] = mapping_version
        report_key["evidence_packet_id"] = evidence_packet_id
        report_key["items"] = normalized_items
        report_key["limitations"] = list(limitations)
    return f"control-map-{sha256_hexdigest(report_key)[:16]}"


class ControlEvidenceRef(PersistedArtifact):
    artifact_kind: Literal["control-evidence-ref"] = "control-evidence-ref"
    evidence_kind: str = Field(min_length=1)
    evidence_id: str = Field(min_length=1)
    field_path: str = Field(min_length=1)
    evidence_digest: DigestHex | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    description: str = Field(min_length=1)


class ControlConditionEvaluation(PersistedArtifact):
    artifact_kind: Literal["control-condition-evaluation"] = "control-condition-evaluation"
    rule_id: str = Field(min_length=1)
    signal: str = Field(min_length=1)
    condition: str | None = Field(default=None, exclude_if=lambda value: value is None)
    observed: bool
    coverage_state: ControlCoverageState
    evidence_refs: tuple[ControlEvidenceRef, ...] = ()
    rationale: str = Field(min_length=1)

    @field_validator("coverage_state", mode="before")
    @classmethod
    def _coerce_coverage_state(cls, value: object) -> ControlCoverageState:
        return coerce_enum(ControlCoverageState, value)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _coerce_evidence_refs(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_observation_state(self) -> ControlConditionEvaluation:
        _validate_condition_evaluation_semantics(self)
        return self

    @classmethod
    def __get_pydantic_json_schema__(
        cls,
        core_schema: CoreSchema,
        handler: GetJsonSchemaHandler,
    ) -> dict[str, Any]:
        schema = super().__get_pydantic_json_schema__(core_schema, handler)
        properties = schema.get("properties")
        if not isinstance(properties, dict):  # pragma: no cover - Pydantic invariant
            return schema
        evidence_refs = properties.get("evidence_refs")
        if isinstance(evidence_refs, dict):
            # Full identity uniqueness is replayed in Python because JSON Schema
            # can compare only complete array items. This still rejects exact
            # duplicate wire objects at the structural boundary.
            evidence_refs["uniqueItems"] = True
        schema.setdefault("allOf", []).extend(
            (
                {
                    "if": {
                        "properties": {"observed": {"const": True}},
                        "required": ["observed"],
                    },
                    "then": {
                        "required": ["evidence_refs"],
                        "properties": {
                            "coverage_state": {
                                "enum": sorted(
                                    state.value
                                    for state in ControlCoverageState
                                    if state not in _TRUE_OBSERVATION_FORBIDDEN_STATES
                                ),
                            },
                            "evidence_refs": {"minItems": 1},
                        },
                    },
                },
                {
                    "if": {
                        "properties": {"observed": {"const": False}},
                        "required": ["observed"],
                    },
                    "then": {
                        "properties": {
                            "coverage_state": {
                                "enum": sorted(
                                    state.value
                                    for state in ControlCoverageState
                                    if state not in _FALSE_OBSERVATION_FORBIDDEN_STATES
                                ),
                            }
                        }
                    },
                },
            )
        )
        return schema


def _validate_coverage_state_path(
    *,
    observed: bool,
    coverage_state: ControlCoverageState,
) -> None:
    """Reject states that contradict whether their mapping path matched."""

    if not observed and coverage_state in _FALSE_OBSERVATION_FORBIDDEN_STATES:
        raise ValueError(
            "an unobserved control condition cannot report observed or contradictory evidence"
        )
    if observed and coverage_state in _TRUE_OBSERVATION_FORBIDDEN_STATES:
        raise ValueError(
            "an observed control condition cannot report not_observed or not_evaluated"
        )


def _evidence_ref_identity(
    ref: ControlEvidenceRef,
) -> tuple[str, str, str, DigestHex | None]:
    return (
        ref.evidence_kind,
        ref.evidence_id,
        ref.field_path,
        ref.evidence_digest,
    )


def _validate_condition_evaluation_semantics(
    evaluation: ControlConditionEvaluation,
) -> None:
    """Replay all condition facts that the trusted mapping builder guarantees."""

    _validate_coverage_state_path(
        observed=evaluation.observed,
        coverage_state=evaluation.coverage_state,
    )
    if evaluation.observed and not evaluation.evidence_refs:
        raise ValueError("an observed control condition requires at least one evidence reference")
    identities = tuple(_evidence_ref_identity(ref) for ref in evaluation.evidence_refs)
    if len(identities) != len(set(identities)):
        raise ValueError("control condition evidence reference identities must be unique")


def _validate_unique_lexicographic_identifiers(
    values: tuple[str, ...],
    *,
    owner: str,
) -> None:
    if len(values) != len(set(values)) or values != tuple(sorted(values)):
        raise ValueError(f"{owner} must be unique and lexicographically ordered")


_COVERAGE_STATE_PRIORITY = {
    ControlCoverageState.contradictory_evidence_observed: 80,
    ControlCoverageState.observed: 70,
    ControlCoverageState.conditionally_observed: 60,
    ControlCoverageState.partially_observed: 50,
    ControlCoverageState.not_evaluated: 40,
    ControlCoverageState.not_observed: 30,
    ControlCoverageState.not_applicable: 20,
    ControlCoverageState.out_of_scope: 10,
}


def _aggregate_condition_coverage_state(
    evaluations: tuple[ControlConditionEvaluation, ...],
) -> ControlCoverageState:
    """Replay the deterministic item aggregation used by the coverage builder."""

    rule_ids = tuple(evaluation.rule_id for evaluation in evaluations)
    if len(rule_ids) != len(set(rule_ids)):
        raise ValueError("control coverage item condition rule_id values must be unique")
    for evaluation in evaluations:
        _validate_condition_evaluation_semantics(evaluation)
    if not evaluations:
        return ControlCoverageState.not_observed
    observed = tuple(evaluation for evaluation in evaluations if evaluation.observed)
    state_source = observed or evaluations
    return max(
        (evaluation.coverage_state for evaluation in state_source),
        key=_COVERAGE_STATE_PRIORITY.__getitem__,
    )


def _project_observed_evidence_refs(
    evaluations: tuple[ControlConditionEvaluation, ...],
) -> tuple[ControlEvidenceRef, ...]:
    """Replay the builder's ordered, identity-deduplicated evidence projection."""

    projected: list[ControlEvidenceRef] = []
    seen: set[tuple[str, str, str, DigestHex | None]] = set()
    for evaluation in evaluations:
        if not evaluation.observed:
            continue
        for ref in evaluation.evidence_refs:
            identity = _evidence_ref_identity(ref)
            if identity in seen:
                continue
            seen.add(identity)
            projected.append(ref)
    return tuple(projected)


class ControlCoverageItem(PersistedArtifact):
    artifact_kind: Literal["control-coverage-item"] = "control-coverage-item"
    control_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    coverage_state: ControlCoverageState
    mapping_strength: ControlMappingStrength | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    atlas_tactic_ids: tuple[str, ...] = ()
    atlas_technique_ids: tuple[str, ...] = ()
    evidence_refs: tuple[ControlEvidenceRef, ...] = ()
    condition_evaluations: tuple[ControlConditionEvaluation, ...] = ()
    limitations: tuple[str, ...] = ()

    @field_validator("coverage_state", mode="before")
    @classmethod
    def _coerce_coverage_state(cls, value: object) -> ControlCoverageState:
        return coerce_enum(ControlCoverageState, value)

    @field_validator("mapping_strength", mode="before")
    @classmethod
    def _coerce_mapping_strength(
        cls,
        value: object,
    ) -> ControlMappingStrength | None:
        if value is None:
            return None
        return coerce_enum(ControlMappingStrength, value)

    @field_validator(
        "atlas_tactic_ids",
        "atlas_technique_ids",
        "evidence_refs",
        "condition_evaluations",
        "limitations",
        mode="before",
    )
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_item_invariants(self) -> ControlCoverageItem:
        _validate_control_coverage_item_collections(self)
        expected_state = _aggregate_condition_coverage_state(self.condition_evaluations)
        if self.coverage_state is not expected_state:
            raise ValueError(
                "control coverage item coverage_state must match its condition evaluations"
            )
        expected_refs = _project_observed_evidence_refs(self.condition_evaluations)
        if self.evidence_refs != expected_refs:
            raise ValueError(
                "control coverage item evidence_refs must exactly match the ordered, "
                "deduplicated evidence projection of observed conditions"
            )
        return self

    @classmethod
    def __get_pydantic_json_schema__(
        cls,
        core_schema: CoreSchema,
        handler: GetJsonSchemaHandler,
    ) -> dict[str, Any]:
        schema = super().__get_pydantic_json_schema__(core_schema, handler)
        properties = schema.get("properties")
        if not isinstance(properties, dict):  # pragma: no cover - Pydantic invariant
            return schema
        condition_evaluations = properties.get("condition_evaluations")
        if isinstance(condition_evaluations, dict):
            # Python replay additionally enforces uniqueness by rule_id.
            condition_evaluations["uniqueItems"] = True
        for field_name in (
            "atlas_tactic_ids",
            "atlas_technique_ids",
            "limitations",
        ):
            field_schema = properties.get(field_name)
            if isinstance(field_schema, dict):
                field_schema["uniqueItems"] = True
        return schema


def _validate_control_coverage_item_collections(item: ControlCoverageItem) -> None:
    _validate_unique_lexicographic_identifiers(
        item.atlas_tactic_ids,
        owner="control coverage item atlas_tactic_ids",
    )
    _validate_unique_lexicographic_identifiers(
        item.atlas_technique_ids,
        owner="control coverage item atlas_technique_ids",
    )
    if len(item.limitations) != len(set(item.limitations)):
        raise ValueError("control coverage item limitations must be unique")


def _wire_enum_value(value: object) -> object:
    return value.value if isinstance(value, StrEnum) else value


def _identity_sequence(value: object, *, owner: str) -> tuple[object, ...]:
    if not isinstance(value, list | tuple):
        raise TypeError(f"{owner} must be a sequence")
    return tuple(value)


def _control_evidence_ref_semantics(
    ref: object,
) -> dict[str, object]:
    if isinstance(ref, ControlEvidenceRef):
        return {
            "evidence_kind": ref.evidence_kind,
            "evidence_id": ref.evidence_id,
            "field_path": ref.field_path,
            "evidence_digest": ref.evidence_digest,
            "description": ref.description,
        }
    if not isinstance(ref, Mapping):
        raise TypeError("control evidence identity input must be a mapping or model")
    return {
        "evidence_kind": ref["evidence_kind"],
        "evidence_id": ref["evidence_id"],
        "field_path": ref["field_path"],
        "evidence_digest": ref.get("evidence_digest"),
        "description": ref["description"],
    }


def _control_condition_semantics(
    evaluation: object,
) -> dict[str, object]:
    if isinstance(evaluation, ControlConditionEvaluation):
        return {
            "rule_id": evaluation.rule_id,
            "signal": evaluation.signal,
            "condition": evaluation.condition,
            "observed": evaluation.observed,
            "coverage_state": evaluation.coverage_state.value,
            "evidence_refs": [
                _control_evidence_ref_semantics(ref) for ref in evaluation.evidence_refs
            ],
            "rationale": evaluation.rationale,
        }
    if not isinstance(evaluation, Mapping):
        raise TypeError("control condition identity input must be a mapping or model")
    refs = evaluation.get("evidence_refs", ())
    return {
        "rule_id": evaluation["rule_id"],
        "signal": evaluation["signal"],
        "condition": evaluation.get("condition"),
        "observed": evaluation["observed"],
        "coverage_state": _wire_enum_value(evaluation["coverage_state"]),
        "evidence_refs": [
            _control_evidence_ref_semantics(ref)
            for ref in _identity_sequence(refs, owner="condition evidence_refs")
        ],
        "rationale": evaluation["rationale"],
    }


def _control_coverage_item_semantics(
    item: object,
) -> dict[str, object]:
    if isinstance(item, ControlCoverageItem):
        return {
            "control_id": item.control_id,
            "title": item.title,
            "coverage_state": item.coverage_state.value,
            "mapping_strength": (
                item.mapping_strength.value if item.mapping_strength is not None else None
            ),
            "atlas_tactic_ids": list(item.atlas_tactic_ids),
            "atlas_technique_ids": list(item.atlas_technique_ids),
            "evidence_refs": [_control_evidence_ref_semantics(ref) for ref in item.evidence_refs],
            "condition_evaluations": [
                _control_condition_semantics(evaluation)
                for evaluation in item.condition_evaluations
            ],
            "limitations": list(item.limitations),
        }
    if not isinstance(item, Mapping):
        raise TypeError("control coverage identity input must be a mapping or model")
    evidence_refs = item.get("evidence_refs", ())
    condition_evaluations = item.get("condition_evaluations", ())
    return {
        "control_id": item["control_id"],
        "title": item["title"],
        "coverage_state": _wire_enum_value(item["coverage_state"]),
        "mapping_strength": _wire_enum_value(item.get("mapping_strength")),
        "atlas_tactic_ids": list(
            _identity_sequence(item.get("atlas_tactic_ids", ()), owner="atlas_tactic_ids")
        ),
        "atlas_technique_ids": list(
            _identity_sequence(item.get("atlas_technique_ids", ()), owner="atlas_technique_ids")
        ),
        "evidence_refs": [
            _control_evidence_ref_semantics(ref)
            for ref in _identity_sequence(evidence_refs, owner="item evidence_refs")
        ],
        "condition_evaluations": [
            _control_condition_semantics(evaluation)
            for evaluation in _identity_sequence(
                condition_evaluations,
                owner="condition_evaluations",
            )
        ],
        "limitations": list(
            _identity_sequence(item.get("limitations", ()), owner="item limitations")
        ),
    }


def _control_coverage_semantic_items(
    items: Iterable[object],
) -> tuple[_ControlCoverageSemanticItem, ...]:
    return tuple(_control_coverage_item_semantics(item) for item in items)


def _validate_framework_specific_report_items(report: ControlCoverageReport) -> None:
    _validate_control_framework_version(
        report.framework,
        report.framework_version,
        owner="control coverage report",
    )
    if report.framework is not ControlFramework.mitre_atlas_2026_06:
        strength_ids = tuple(
            item.control_id for item in report.items if item.mapping_strength is not None
        )
        atlas_ids = tuple(
            item.control_id
            for item in report.items
            if item.atlas_tactic_ids or item.atlas_technique_ids
        )
        if strength_ids:
            raise ValueError(
                "non-MITRE control coverage items must not declare mapping_strength: "
                + ", ".join(strength_ids)
            )
        if atlas_ids:
            raise ValueError(
                "non-MITRE control coverage items must not declare ATLAS identifiers: "
                + ", ".join(atlas_ids)
            )
        return

    missing_strength = tuple(
        item.control_id for item in report.items if item.mapping_strength is None
    )
    if missing_strength:
        raise ValueError(
            "MITRE ATLAS control coverage items require mapping_strength: "
            + ", ".join(missing_strength)
        )
    catalog = load_mitre_atlas_2026_06_catalog()
    unknown_control_ids = tuple(
        item.control_id for item in report.items if item.control_id not in catalog.technique_ids
    )
    unknown_tactic_ids = sorted(
        {
            identifier
            for item in report.items
            for identifier in item.atlas_tactic_ids
            if identifier not in catalog.tactic_ids
        }
    )
    unknown_technique_ids = sorted(
        {
            identifier
            for item in report.items
            for identifier in item.atlas_technique_ids
            if identifier not in catalog.technique_ids
        }
    )
    if unknown_control_ids:
        raise ValueError(
            "MITRE ATLAS control_id values are absent from the pinned 2026.06 catalog: "
            + ", ".join(unknown_control_ids)
        )
    if unknown_tactic_ids:
        raise ValueError(
            "MITRE ATLAS tactic identifiers are absent from the pinned 2026.06 catalog: "
            + ", ".join(unknown_tactic_ids)
        )
    if unknown_technique_ids:
        raise ValueError(
            "MITRE ATLAS technique identifiers are absent from the pinned 2026.06 catalog: "
            + ", ".join(unknown_technique_ids)
        )
    for item in report.items:
        if item.mapping_strength is None:  # pragma: no cover - checked above
            continue
        _validate_mitre_mapping_identifiers(
            control_id=item.control_id,
            title=item.title,
            expected_title=catalog.technique_names[item.control_id],
            mapping_strength=item.mapping_strength,
            atlas_tactic_ids=item.atlas_tactic_ids,
            atlas_technique_ids=item.atlas_technique_ids,
            owner="MITRE ATLAS control coverage item",
        )


def _nested_artifact_payload(value: object) -> tuple[dict[str, Any], bool] | None:
    """Copy a nested artifact payload and retain whether its version was explicit."""

    if isinstance(value, PersistedArtifact):
        return (
            value.model_dump(mode="python"),
            "schema_version" in value.model_fields_set,
        )
    if isinstance(value, Mapping):
        return dict(value), "schema_version" in value
    return None


def _inherit_nested_schema_version(
    value: object,
    *,
    expected_version: str,
    owner: str,
) -> dict[str, Any] | object:
    copied = _nested_artifact_payload(value)
    if copied is None:
        return value
    payload, version_was_explicit = copied
    if version_was_explicit and payload.get("schema_version") != expected_version:
        raise ValueError(f"control coverage report and nested {owner} schema versions must match")
    payload["schema_version"] = expected_version
    return payload


def _normalize_condition_payload(
    value: object,
    *,
    expected_version: str,
) -> dict[str, Any] | object:
    normalized = _inherit_nested_schema_version(
        value,
        expected_version=expected_version,
        owner="condition evaluation",
    )
    if not isinstance(normalized, dict):
        return normalized
    refs = (
        value.evidence_refs
        if isinstance(value, ControlConditionEvaluation)
        else normalized.get("evidence_refs")
    )
    if isinstance(refs, list | tuple):
        normalized["evidence_refs"] = [
            _inherit_nested_schema_version(
                ref,
                expected_version=expected_version,
                owner="condition evidence reference",
            )
            for ref in refs
        ]
    return normalized


def _normalize_item_payload(
    value: object,
    *,
    expected_version: str,
) -> dict[str, Any] | object:
    normalized = _inherit_nested_schema_version(
        value,
        expected_version=expected_version,
        owner="item",
    )
    if not isinstance(normalized, dict):
        return normalized
    refs = (
        value.evidence_refs
        if isinstance(value, ControlCoverageItem)
        else normalized.get("evidence_refs")
    )
    if isinstance(refs, list | tuple):
        normalized["evidence_refs"] = [
            _inherit_nested_schema_version(
                ref,
                expected_version=expected_version,
                owner="item evidence reference",
            )
            for ref in refs
        ]
    evaluations = (
        value.condition_evaluations
        if isinstance(value, ControlCoverageItem)
        else normalized.get("condition_evaluations")
    )
    if isinstance(evaluations, list | tuple):
        normalized["condition_evaluations"] = [
            _normalize_condition_payload(
                evaluation,
                expected_version=expected_version,
            )
            for evaluation in evaluations
        ]
    return normalized


class ControlCoverageReport(PersistedArtifact):
    artifact_kind: Literal["control-coverage-report"] = "control-coverage-report"
    report_id: str = Field(min_length=1)
    framework: ControlFramework
    framework_version: str = Field(min_length=1)
    mapping_version: str = Field(min_length=1)
    mapping_digest: DigestHex
    evidence_packet_id: str = Field(min_length=1)
    evidence_packet_digest: DigestHex
    coverage_state_counts: dict[
        ControlCoverageState,
        Annotated[int, Field(ge=0)],
    ]
    items: tuple[ControlCoverageItem, ...]
    limitations: tuple[str, ...]

    @model_validator(mode="before")
    @classmethod
    def _normalize_nested_schema_versions(cls, value: object) -> object:
        if not isinstance(value, Mapping):
            return value
        payload = dict(value)
        expected_version = payload.get("schema_version", SCHEMA_VERSION)
        if not isinstance(expected_version, str):
            return payload
        items = payload.get("items")
        if isinstance(items, list | tuple):
            payload["items"] = [
                _normalize_item_payload(item, expected_version=expected_version) for item in items
            ]
        return payload

    @field_validator("framework", mode="before")
    @classmethod
    def _coerce_framework(cls, value: object) -> ControlFramework:
        return coerce_enum(ControlFramework, value)

    @field_validator("coverage_state_counts", mode="before")
    @classmethod
    def _coerce_coverage_state_counts(cls, value: object) -> object:
        if not isinstance(value, dict):
            return value
        return {coerce_enum(ControlCoverageState, state): count for state, count in value.items()}

    @field_validator("items", "limitations", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_report_invariants(self) -> ControlCoverageReport:
        _validate_control_coverage_review_contract(
            self,
            item_states=tuple((item.control_id, item.coverage_state) for item in self.items),
        )
        nested_versions = (
            nested_version
            for item in self.items
            for nested_version in (
                item.schema_version,
                *(ref.schema_version for ref in item.evidence_refs),
                *(
                    version
                    for evaluation in item.condition_evaluations
                    for version in (
                        evaluation.schema_version,
                        *(ref.schema_version for ref in evaluation.evidence_refs),
                    )
                ),
            )
        )
        if any(version != self.schema_version for version in nested_versions):
            raise ValueError("control coverage report and all nested schema versions must match")
        expected_counts = Counter(item.coverage_state for item in self.items)
        if self.coverage_state_counts != expected_counts:
            raise ValueError(
                "coverage_state_counts must exactly count report items by coverage_state"
            )
        return self

    @classmethod
    def __get_pydantic_json_schema__(
        cls,
        core_schema: CoreSchema,
        handler: GetJsonSchemaHandler,
    ) -> dict[str, Any]:
        schema = super().__get_pydantic_json_schema__(core_schema, handler)
        properties = schema.get("properties")
        if not isinstance(properties, dict):  # pragma: no cover - Pydantic invariant
            return schema
        limitations = properties.get("limitations")
        if isinstance(limitations, dict):
            limitations["contains"] = {"const": CLAIM_BOUNDARY}
            limitations["minContains"] = 1
            limitations["maxContains"] = 1
            limitations["uniqueItems"] = True
        schema.setdefault("allOf", []).extend(
            {
                "if": {
                    "properties": {"framework": {"const": framework.value}},
                    "required": ["framework"],
                },
                "then": {
                    "properties": {
                        "framework_version": {"const": framework_version},
                    }
                },
            }
            for framework, framework_version in CONTROL_FRAMEWORK_VERSIONS.items()
        )
        atlas_catalog = load_mitre_atlas_2026_06_catalog()
        schema.setdefault("allOf", []).append(
            {
                "if": {
                    "properties": {
                        "framework": {
                            "const": ControlFramework.mitre_atlas_2026_06.value,
                        }
                    },
                    "required": ["framework"],
                },
                "then": {
                    "properties": {
                        "limitations": {
                            "contains": {"const": MITRE_ATLAS_BOUNDARY},
                            "minContains": 1,
                            "maxContains": 1,
                        },
                        "items": {
                            "items": {
                                "properties": {
                                    "control_id": {
                                        "enum": sorted(atlas_catalog.technique_ids),
                                        "type": "string",
                                    },
                                    "mapping_strength": {
                                        "enum": [
                                            strength.value for strength in ControlMappingStrength
                                        ],
                                        "type": "string",
                                    },
                                    "atlas_tactic_ids": {
                                        "items": {
                                            "enum": sorted(atlas_catalog.tactic_ids),
                                            "type": "string",
                                        }
                                    },
                                    "atlas_technique_ids": {
                                        "minItems": 1,
                                        "items": {
                                            "enum": sorted(atlas_catalog.technique_ids),
                                            "type": "string",
                                        },
                                    },
                                },
                                "required": ["mapping_strength"],
                                "allOf": [
                                    {
                                        "if": {
                                            "properties": {
                                                "mapping_strength": {
                                                    "const": (
                                                        ControlMappingStrength.not_applicable.value
                                                    )
                                                }
                                            },
                                            "required": ["mapping_strength"],
                                        },
                                        "then": {
                                            "properties": {
                                                "atlas_tactic_ids": {"maxItems": 0},
                                                "atlas_technique_ids": {"maxItems": 1},
                                            }
                                        },
                                    },
                                    *(
                                        {
                                            "if": {
                                                "properties": {
                                                    "control_id": {
                                                        "const": control_id,
                                                    }
                                                },
                                                "required": ["control_id"],
                                            },
                                            "then": {
                                                "properties": {
                                                    "title": {
                                                        "const": atlas_catalog.technique_names[
                                                            control_id
                                                        ],
                                                    },
                                                    "atlas_technique_ids": {
                                                        "contains": {
                                                            "const": control_id,
                                                        },
                                                        "minContains": 1,
                                                        "maxContains": 1,
                                                    },
                                                }
                                            },
                                        }
                                        for control_id in sorted(atlas_catalog.technique_ids)
                                    ),
                                ],
                            }
                        },
                    }
                },
                "else": {
                    "properties": {
                        "limitations": {
                            "not": {
                                "contains": {"const": MITRE_ATLAS_BOUNDARY},
                            }
                        },
                        "items": {
                            "items": {
                                "properties": {
                                    "mapping_strength": {"type": "null"},
                                    "atlas_tactic_ids": {"maxItems": 0},
                                    "atlas_technique_ids": {"maxItems": 0},
                                }
                            }
                        },
                    }
                },
            }
        )
        return schema


def _validate_control_coverage_review_contract(
    report: ControlCoverageReport,
    *,
    item_states: tuple[tuple[str, ControlCoverageState], ...],
    validate_persisted_limitations: bool = True,
) -> None:
    control_ids = tuple(control_id for control_id, _state in item_states)
    if len(control_ids) != len(set(control_ids)):
        raise ValueError("control coverage report control_id values must be unique")
    if validate_persisted_limitations:
        expected_limitations = _project_control_coverage_limitations(
            report.framework,
            report.limitations,
        )
        if report.limitations != expected_limitations:
            raise ValueError(
                "control coverage report limitations must contain each mandatory claim "
                "boundary exactly once, preserve additional limitation order, and contain "
                "no duplicates"
            )
    _validate_framework_specific_report_items(report)
    expected_report_id = _derive_control_coverage_report_id(
        framework=report.framework,
        framework_version=report.framework_version,
        mapping_version=report.mapping_version,
        mapping_digest=report.mapping_digest,
        evidence_packet_id=report.evidence_packet_id,
        evidence_packet_digest=report.evidence_packet_digest,
        item_states=item_states,
        item_semantics=_control_coverage_semantic_items(report.items),
        limitations=report.limitations,
        schema_version=report.schema_version,
    )
    if report.report_id != expected_report_id:
        raise ValueError(
            "control coverage report_id must match its deterministic semantic projection"
        )
