from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from enum import StrEnum
from functools import cache
from types import MappingProxyType
from typing import Annotated, Any, ClassVar, Literal, Self

from pydantic import ConfigDict, Field, ValidationInfo, field_serializer, model_validator
from pydantic.functional_validators import field_validator

from agent_assure.schema.base import FrozenStrictModel, PersistedArtifact, SchemaVersion
from agent_assure.schema.common import (
    MAX_LABEL_CHARS,
    MAX_SUMMARY_CHARS,
    STRICT_RFC3339_TIMESTAMP_PATTERN,
    DigestHex,
    GateState,
    ReasonCode,
    coerce_enum,
    coerce_tuple,
)

CONTRACT_VERSION: Literal["1.0.0"] = "1.0.0"
ASSURANCE_MUTATION_METHOD_ID: Literal["assurance-mutation/core/v1"] = "assurance-mutation/core/v1"
ASSURANCE_MUTATION_PREREQUISITE_CHECK_IDS = (
    "subject-valid",
    "operator-valid",
    "operator-applicable",
    "mutation-execution-completed",
)
STOCHASTIC_SUFFICIENCY_CHECK_ID: Literal["statistical-sufficiency-established"] = (
    "statistical-sufficiency-established"
)
HUMAN_REVIEW_SUFFICIENCY_CHECK_ID: Literal["human-review-sufficiency-established"] = (
    "human-review-sufficiency-established"
)
STOCHASTIC_SUFFICIENCY_LIMITATION = (
    "Stochastic mutation assessment is non-verdict until a typed statistical "
    "sufficiency artifact is supported and validated."
)
HUMAN_REVIEW_SUFFICIENCY_LIMITATION = (
    "Human-reviewed mutation assessment is non-verdict until a typed independent "
    "review-sufficiency artifact is supported and validated."
)
IMPLEMENTATION_MANIFEST_CONTRACT: Literal["AssuranceMutationImplementationManifest/v1"] = (
    "AssuranceMutationImplementationManifest/v1"
)
FINDING_TARGET_DIGEST_CONTRACT: Literal["AssuranceMutationFindingTarget/v1"] = (
    "AssuranceMutationFindingTarget/v1"
)
_SEMVER_PATTERN = r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
_MACHINE_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$"
_ISO_DATE_PATTERN = r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$"
RFC8785_SAFE_INTEGER_MAX = (1 << 53) - 1
_SELF_DIGESTED_IDENTITY_FIELDS = (
    "artifact_kind",
    "schema_version",
    "schema_name",
    "contract_id",
    "contract_version",
)
# These patterns intentionally describe non-root RFC 6901 JSON Pointers. An
# exact changed path may contain a literal ``*`` inside a reference token, but
# not a token whose complete value is ``*``. Permitted-path templates may use
# that complete token as a deterministic single-segment wildcard.
_JSON_POINTER_TOKEN = r"(?:[^~/]|~[01])"
_EXACT_JSON_POINTER_TOKEN = (
    rf"(?:\*(?:{_JSON_POINTER_TOKEN})+|(?:[^~/*]|~[01])(?:{_JSON_POINTER_TOKEN})*|)"
)
_EXACT_JSON_POINTER_PATTERN = rf"^(?:/{_EXACT_JSON_POINTER_TOKEN})+$"
_JSON_POINTER_TEMPLATE_PATTERN = rf"^(?:/(?:{_JSON_POINTER_TOKEN})*)+$"
BoundedSummary = Annotated[
    str,
    Field(min_length=1, max_length=MAX_SUMMARY_CHARS),
]
MachineIdentifier = Annotated[
    str,
    Field(min_length=1, max_length=MAX_LABEL_CHARS, pattern=_MACHINE_ID_PATTERN),
]
ExactJsonPointer = Annotated[
    str,
    Field(
        min_length=1,
        max_length=MAX_SUMMARY_CHARS,
        pattern=_EXACT_JSON_POINTER_PATTERN,
    ),
]
JsonPointerTemplate = Annotated[
    str,
    Field(
        min_length=1,
        max_length=MAX_SUMMARY_CHARS,
        pattern=_JSON_POINTER_TEMPLATE_PATTERN,
    ),
]


def _append_json_schema_rules(
    schema: dict[str, Any],
    *rules: dict[str, Any],
) -> None:
    schema.setdefault("allOf", []).extend(rules)


def _require_contract_identity_json_schema(schema: dict[str, Any]) -> None:
    properties = schema.get("properties", {})
    required = list(schema.get("required", ()))
    for field_name in _SELF_DIGESTED_IDENTITY_FIELDS:
        if field_name in properties and field_name not in required:
            required.append(field_name)
    schema["required"] = required


def _evidence_prerequisites_json_schema_extra(schema: dict[str, Any]) -> None:
    _append_json_schema_rules(
        schema,
        {
            "if": {
                "required": ["state"],
                "properties": {"state": {"const": "satisfied"}},
            },
            "then": {
                "properties": {
                    "checks": {
                        "minItems": 1,
                        "items": {"properties": {"state": {"const": "satisfied"}}},
                    }
                }
            },
        },
    )


def _evidence_descriptor_json_schema_extra(schema: dict[str, Any]) -> None:
    _require_contract_identity_json_schema(schema)
    canonical_checks = [
        {
            "required": ["check_id"],
            "properties": {"check_id": {"const": check_id}},
        }
        for check_id in ASSURANCE_MUTATION_PREREQUISITE_CHECK_IDS
    ]
    _append_json_schema_rules(
        schema,
        {
            "if": {
                "required": ["method"],
                "properties": {
                    "method": {
                        "required": ["method_id"],
                        "properties": {"method_id": {"const": ASSURANCE_MUTATION_METHOD_ID}},
                    }
                },
            },
            "then": {
                "properties": {
                    "prerequisites": {
                        "properties": {
                            "checks": {
                                "minItems": len(canonical_checks),
                                "maxItems": len(canonical_checks),
                                "prefixItems": canonical_checks,
                            }
                        }
                    }
                }
            },
        },
        {
            "if": {
                "required": ["subject"],
                "properties": {
                    "subject": {
                        "required": ["digest"],
                        "properties": {"digest": {"type": "null"}},
                    }
                },
            },
            "then": {
                "properties": {
                    "result": {"properties": {"verdict_bearing": {"const": False}}},
                    "prerequisites": {
                        "properties": {"state": {"enum": ["unmet", "not_evaluated"]}}
                    },
                }
            },
        },
        *_non_deterministic_evidence_json_schema_rules(),
        {
            "if": {
                "required": ["method"],
                "properties": {
                    "method": {
                        "required": ["evaluation_basis"],
                        "properties": {"evaluation_basis": {"const": "llm_advisory"}},
                    }
                },
            },
            "then": {
                "properties": {"result": {"properties": {"verdict_bearing": {"const": False}}}}
            },
        },
    )


def _non_deterministic_evidence_json_schema_rules() -> tuple[dict[str, Any], ...]:
    rules: list[dict[str, Any]] = []
    for basis, check_id in (
        ("stochastic", STOCHASTIC_SUFFICIENCY_CHECK_ID),
        ("human_reviewed", HUMAN_REVIEW_SUFFICIENCY_CHECK_ID),
    ):
        rules.append(
            {
                "if": {
                    "required": ["method"],
                    "properties": {
                        "method": {
                            "required": ["evaluation_basis"],
                            "properties": {"evaluation_basis": {"const": basis}},
                        }
                    },
                },
                "then": {
                    "properties": {
                        "scope": {
                            "required": ["protocol_digest"],
                            "properties": {"protocol_digest": {"type": "string"}},
                        },
                        "result": {"properties": {"verdict_bearing": {"const": False}}},
                        "prerequisites": {
                            "properties": {
                                "state": {"enum": ["unmet", "not_evaluated"]},
                                "checks": {
                                    "contains": {
                                        "required": ["check_id", "state"],
                                        "properties": {
                                            "check_id": {"const": check_id},
                                            "state": {"enum": ["unmet", "not_evaluated"]},
                                        },
                                    }
                                },
                            }
                        },
                    }
                },
            }
        )
    return tuple(rules)


def _expected_detection_contract_json_schema_extra(schema: dict[str, Any]) -> None:
    _require_contract_identity_json_schema(schema)
    known_controls = list(_built_in_policy_ids())
    schema["$comment"] = (
        "JSON Schema enforces the finite control vocabulary and target-ID uniqueness. "
        "Canonical target-ID ordering, required-selector membership in target_control_ids, "
        "and required/prohibited selector disjointness are relational constraints enforced "
        "by the runtime model because JSON Schema 2020-12 cannot express them directly."
    )
    _append_json_schema_rules(
        schema,
        {
            "properties": {
                "target_control_ids": {
                    "items": {"enum": known_controls},
                    "uniqueItems": True,
                },
                "required_findings": {
                    "properties": {
                        "any_of": {
                            "items": {"properties": {"control_id": {"enum": known_controls}}}
                        }
                    }
                },
                "prohibited_substitutes": {
                    "items": {"properties": {"control_id": {"enum": known_controls}}}
                },
            }
        },
    )


def _operator_provenance_json_schema_extra(schema: dict[str, Any]) -> None:
    _append_json_schema_rules(
        schema,
        {
            "if": {
                "required": ["implementation_components"],
                "properties": {"implementation_components": {"maxItems": 0}},
            },
            "then": {
                "properties": {
                    "implementation_digest": {"const": "0" * 64},
                    "introduction_components": {"maxItems": 0},
                    "introduced_at_commit": {"type": "null"},
                    "introduced_in_release": {"type": "null"},
                    "origin": {"properties": {"kind": {"const": "unknown"}}},
                    "target_controls": {"maxItems": 0},
                    "authorship": {
                        "properties": {"relationship_to_control_author": {"const": "unknown"}}
                    },
                }
            },
            "else": {
                "properties": {
                    "introduction_components": {"minItems": 1},
                    "introduced_at_commit": {"type": "string"},
                    "introduced_in_release": {"type": "string"},
                    "origin": {
                        "properties": {
                            "kind": {
                                "enum": [
                                    "external_preexisting",
                                    "third_party_contributed",
                                    "first_party",
                                ]
                            }
                        }
                    },
                    "target_controls": {"minItems": 1},
                }
            },
        },
    )


def _mutation_result_json_schema_extra(schema: dict[str, Any]) -> None:
    _require_contract_identity_json_schema(schema)
    properties = schema.get("properties", {})
    dependent_required = schema.setdefault("dependentRequired", {})
    dependent_required["diagnostic_exception_class"] = ["local_debug_reference"]
    dependent_required["local_debug_reference"] = ["diagnostic_exception_class"]
    for field_name in ("changed_paths", "matched_finding_ids"):
        if field_name in properties:
            properties[field_name]["uniqueItems"] = True
    mutated_states = ["caught", "survived"]
    nonmutation_states = [
        "inapplicable",
        "invalid_operator",
        "invalid_subject",
        "execution_error",
    ]
    rules: list[dict[str, Any]] = [
        {
            "if": {
                "required": ["state"],
                "properties": {"state": {"enum": mutated_states}},
            },
            "then": {
                "required": [
                    "source_digest",
                    "mutated_digest",
                    "expected_finding_target_digest",
                    "changed_paths",
                ],
                "properties": {
                    "source_digest": {"type": "string"},
                    "mutated_digest": {"type": "string"},
                    "expected_finding_target_digest": {"type": "string"},
                    "changed_paths": {"minItems": 1},
                },
            },
        },
        {
            "if": {
                "required": ["state"],
                "properties": {"state": {"enum": nonmutation_states}},
            },
            "then": {
                "properties": {
                    "mutated_digest": {"type": "null"},
                    "expected_finding_target_digest": {"type": "null"},
                    "changed_paths": {"maxItems": 0},
                    "matched_finding_ids": {"maxItems": 0},
                }
            },
        },
        {
            "if": {
                "required": ["state"],
                "properties": {"state": {"const": "caught"}},
            },
            "then": {"properties": {"matched_finding_ids": {"minItems": 1}}},
        },
        {
            "if": {
                "required": ["state"],
                "properties": {"state": {"const": "survived"}},
            },
            "then": {"properties": {"matched_finding_ids": {"maxItems": 0}}},
        },
        {
            "if": {
                "required": ["evaluator_implementation_digest"],
                "properties": {"evaluator_implementation_digest": {"const": "0" * 64}},
            },
            "then": {
                "required": ["state", "diagnostic_code"],
                "properties": {
                    "state": {"const": "execution_error"},
                    "diagnostic_code": {"const": "catalog_integrity_error"},
                },
            },
        },
    ]
    origin_by_independence = {
        "external_preexisting": "external_preexisting",
        "third_party_contributed": "third_party_contributed",
        "first_party_precontrol": "first_party",
        "first_party_postcontrol": "first_party",
    }
    rules.extend(
        {
            "if": {
                "required": ["independence_class"],
                "properties": {"independence_class": {"const": independence_class}},
            },
            "then": {
                "properties": {
                    "provenance": {
                        "properties": {"origin": {"properties": {"kind": {"const": origin_kind}}}}
                    }
                }
            },
        }
        for independence_class, origin_kind in origin_by_independence.items()
    )
    rules.extend(
        {
            "if": {
                "required": ["state", "evaluator_evaluation_basis"],
                "properties": {
                    "state": {"enum": mutated_states},
                    "evaluator_evaluation_basis": {"const": basis},
                },
            },
            "then": {
                "properties": {
                    "limitations": {
                        "contains": {"const": limitation},
                    }
                }
            },
        }
        for basis, limitation in (
            ("stochastic", STOCHASTIC_SUFFICIENCY_LIMITATION),
            ("human_reviewed", HUMAN_REVIEW_SUFFICIENCY_LIMITATION),
        )
    )
    rules.append(
        {
            "if": {
                "required": ["evaluator_evaluation_basis"],
                "properties": {"evaluator_evaluation_basis": {"const": "llm_advisory"}},
            },
            "then": {
                "properties": {
                    "state": {
                        "enum": [
                            "inapplicable",
                            "invalid_operator",
                            "invalid_subject",
                            "execution_error",
                        ]
                    }
                }
            },
        }
    )
    _append_json_schema_rules(schema, *rules)


class SelfDigestedArtifact(PersistedArtifact):
    """Persisted artifact whose canonical digest excludes only itself."""

    model_config = ConfigDict(json_schema_extra=_require_contract_identity_json_schema)

    _digest_field: ClassVar[str]

    @classmethod
    def build(cls, **values: object) -> Self:
        digest_field = cls._digest_field
        prepared = dict(values)
        for field_name in _SELF_DIGESTED_IDENTITY_FIELDS:
            if field_name in prepared:
                continue
            field = cls.model_fields.get(field_name)
            if field is None or field.is_required():
                raise TypeError(f"{cls.__name__} does not define {field_name}")
            prepared[field_name] = field.get_default(call_default_factory=True)
        provisional = cls.model_validate(
            {**prepared, digest_field: "0" * 64},
            context={"skip_self_digest": True},
        )
        payload = provisional.model_dump(mode="json")
        payload[digest_field] = _canonical_sha256(
            provisional.model_dump(mode="json", exclude={digest_field})
        )
        return cls.model_validate(payload)

    @model_validator(mode="before")
    @classmethod
    def _require_persisted_identity(cls, value: object) -> object:
        if not isinstance(value, Mapping):
            return value
        missing = [
            field_name for field_name in _SELF_DIGESTED_IDENTITY_FIELDS if field_name not in value
        ]
        if missing:
            raise ValueError(
                "persisted self-digested artifact requires explicit identity fields: "
                + ", ".join(missing)
            )
        return value

    @model_validator(mode="after")
    def _validate_self_digest(self, info: ValidationInfo) -> SelfDigestedArtifact:
        if isinstance(info.context, dict) and info.context.get("skip_self_digest") is True:
            return self
        digest_field = self._digest_field
        expected = _canonical_sha256(self.model_dump(mode="json", exclude={digest_field}))
        if getattr(self, digest_field) != expected:
            raise ValueError(f"{digest_field} does not match the canonical artifact projection")
        return self


class EvidenceState(StrEnum):
    supported = "supported"
    contradicted = "contradicted"
    violated = "violated"
    inconclusive = "inconclusive"
    not_evaluated = "not_evaluated"
    prerequisites_unmet = "prerequisites_unmet"
    out_of_scope = "out_of_scope"
    expired = "expired"
    invalidated = "invalidated"
    waived = "waived"
    error = "error"


class GateEffect(StrEnum):
    block = "block"
    review = "review"
    informational = "informational"
    ignore = "ignore"


class EvidenceEvaluationBasis(StrEnum):
    deterministic = "deterministic"
    stochastic = "stochastic"
    human_reviewed = "human_reviewed"
    llm_advisory = "llm_advisory"


class PrerequisiteState(StrEnum):
    satisfied = "satisfied"
    unmet = "unmet"
    not_evaluated = "not_evaluated"


class MutationResultState(StrEnum):
    caught = "caught"
    survived = "survived"
    inapplicable = "inapplicable"
    invalid_operator = "invalid_operator"
    invalid_subject = "invalid_subject"
    execution_error = "execution_error"


class IndependenceClass(StrEnum):
    external_preexisting = "external_preexisting"
    third_party_contributed = "third_party_contributed"
    first_party_precontrol = "first_party_precontrol"
    first_party_postcontrol = "first_party_postcontrol"
    unknown = "unknown"


class OperatorOriginKind(StrEnum):
    external_preexisting = "external_preexisting"
    third_party_contributed = "third_party_contributed"
    first_party = "first_party"
    unknown = "unknown"


class AuthorshipRelationship(StrEnum):
    same = "same"
    separate = "separate"
    unknown = "unknown"


class MutationPrivacyClassification(StrEnum):
    schema_metadata_only = "schema_metadata_only"
    synthetic_fixture_metadata = "synthetic_fixture_metadata"


class EvidenceSubject(FrozenStrictModel):
    subject_type: Literal["agent_release", "run_set"]
    digest: DigestHex | None


class EvidenceScope(FrozenStrictModel):
    suite_digest: DigestHex
    protocol_digest: DigestHex | None = None
    population_id: str = Field(
        min_length=1,
        max_length=MAX_LABEL_CHARS,
        pattern=_MACHINE_ID_PATTERN,
    )
    gate_profile_id: MachineIdentifier
    gate_profile_digest: DigestHex
    waiver_set_digest: DigestHex
    evaluation_date: str = Field(pattern=_ISO_DATE_PATTERN)

    @field_validator("evaluation_date")
    @classmethod
    def _validate_evaluation_date(cls, value: str) -> str:
        try:
            datetime.strptime(value, "%Y-%m-%d")
        except ValueError as exc:
            raise ValueError("evaluation_date must be a valid YYYY-MM-DD date") from exc
        return value


class EvidenceMethod(FrozenStrictModel):
    method_id: str = Field(min_length=1, max_length=MAX_LABEL_CHARS)
    implementation_digest: DigestHex
    implementation_version: str = Field(pattern=_SEMVER_PATTERN)
    evaluation_basis: EvidenceEvaluationBasis

    @field_validator("evaluation_basis", mode="before")
    @classmethod
    def _coerce_evaluation_basis(cls, value: object) -> EvidenceEvaluationBasis:
        return coerce_enum(EvidenceEvaluationBasis, value)


class EvidenceResult(FrozenStrictModel):
    state: EvidenceState
    verdict_bearing: bool
    reason_codes: tuple[ReasonCode, ...] = ()
    metrics: Mapping[MachineIdentifier, int | BoundedSummary | bool] = Field(
        default_factory=dict,
        max_length=128,
    )

    @field_validator("state", mode="before")
    @classmethod
    def _coerce_state(cls, value: object) -> EvidenceState:
        return coerce_enum(EvidenceState, value)

    @field_validator("reason_codes", mode="before")
    @classmethod
    def _coerce_reason_codes(cls, value: object) -> object:
        if isinstance(value, list | tuple):
            return tuple(coerce_enum(ReasonCode, item) for item in value)
        return value

    @model_validator(mode="after")
    def _bound_metrics(self) -> EvidenceResult:
        for key, value in self.metrics.items():
            if not key or len(key) > MAX_LABEL_CHARS:
                raise ValueError("evidence metric keys must be bounded non-empty labels")
            if isinstance(value, str) and len(value) > MAX_SUMMARY_CHARS:
                raise ValueError("evidence metric string values must be bounded")
        object.__setattr__(self, "metrics", MappingProxyType(dict(self.metrics)))
        return self

    @field_serializer("metrics")
    def _serialize_metrics(
        self,
        value: Mapping[MachineIdentifier, int | BoundedSummary | bool],
    ) -> dict[MachineIdentifier, int | BoundedSummary | bool]:
        return dict(value)


class PrerequisiteCheck(FrozenStrictModel):
    check_id: str = Field(
        min_length=1,
        max_length=MAX_LABEL_CHARS,
        pattern=_MACHINE_ID_PATTERN,
    )
    state: PrerequisiteState
    reason_codes: tuple[ReasonCode, ...] = ()

    @field_validator("state", mode="before")
    @classmethod
    def _coerce_state(cls, value: object) -> PrerequisiteState:
        return coerce_enum(PrerequisiteState, value)

    @field_validator("reason_codes", mode="before")
    @classmethod
    def _coerce_reason_codes(cls, value: object) -> object:
        if isinstance(value, list | tuple):
            return tuple(coerce_enum(ReasonCode, item) for item in value)
        return value


class EvidencePrerequisites(FrozenStrictModel):
    model_config = ConfigDict(json_schema_extra=_evidence_prerequisites_json_schema_extra)

    state: PrerequisiteState
    checks: tuple[PrerequisiteCheck, ...]

    @field_validator("state", mode="before")
    @classmethod
    def _coerce_state(cls, value: object) -> PrerequisiteState:
        return coerce_enum(PrerequisiteState, value)

    @field_validator("checks", mode="before")
    @classmethod
    def _coerce_checks(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _checks_agree_with_state(self) -> EvidencePrerequisites:
        if self.state is PrerequisiteState.satisfied and not self.checks:
            raise ValueError("satisfied prerequisites require at least one explicit check")
        if self.state is PrerequisiteState.satisfied and any(
            check.state is not PrerequisiteState.satisfied for check in self.checks
        ):
            raise ValueError("satisfied prerequisites cannot contain an unmet check")
        if (
            self.state is not PrerequisiteState.satisfied
            and self.checks
            and all(check.state is PrerequisiteState.satisfied for check in self.checks)
        ):
            raise ValueError("unsatisfied prerequisites require a non-satisfied check")
        return self


class EvidenceValidity(FrozenStrictModel):
    generated_at: str = Field(pattern=STRICT_RFC3339_TIMESTAMP_PATTERN)
    expires_at: str | None = Field(default=None, pattern=STRICT_RFC3339_TIMESTAMP_PATTERN)
    invalidated_by: tuple[MachineIdentifier, ...]

    @field_validator("invalidated_by", mode="before")
    @classmethod
    def _coerce_invalidated_by(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_validity_window(self) -> EvidenceValidity:
        generated_at = _parse_rfc3339(self.generated_at)
        if self.expires_at is not None and _parse_rfc3339(self.expires_at) < generated_at:
            raise ValueError("expires_at cannot precede generated_at")
        if self.expires_at is None and not self.invalidated_by:
            raise ValueError("validity requires expires_at or at least one invalidation trigger")
        if len(set(self.invalidated_by)) != len(self.invalidated_by):
            raise ValueError("validity invalidation triggers must be unique")
        return self


class EvidenceDependency(FrozenStrictModel):
    evidence_id: str = Field(
        min_length=1,
        max_length=MAX_LABEL_CHARS,
        pattern=_MACHINE_ID_PATTERN,
    )
    digest: DigestHex


class EvidenceProducer(FrozenStrictModel):
    name: str = Field(min_length=1, max_length=MAX_LABEL_CHARS)
    version: str = Field(pattern=_SEMVER_PATTERN)


class AssuranceEvidenceDescriptor(SelfDigestedArtifact):
    _digest_field = "evidence_digest"

    model_config = ConfigDict(json_schema_extra=_evidence_descriptor_json_schema_extra)

    artifact_kind: Literal["assurance-evidence-descriptor"] = "assurance-evidence-descriptor"
    schema_version: Literal["0.6.0"] = "0.6.0"
    schema_name: Literal["assurance-evidence-descriptor"] = "assurance-evidence-descriptor"
    contract_id: Literal["AssuranceEvidenceDescriptor/v1"] = "AssuranceEvidenceDescriptor/v1"
    contract_version: Literal["1.0.0"] = CONTRACT_VERSION
    evidence_digest: DigestHex
    evidence_id: str = Field(
        min_length=1,
        max_length=MAX_LABEL_CHARS,
        pattern=_MACHINE_ID_PATTERN,
    )
    evidence_kind: str = Field(
        min_length=1,
        max_length=MAX_LABEL_CHARS,
        pattern=_MACHINE_ID_PATTERN,
    )
    subject: EvidenceSubject
    scope: EvidenceScope
    method: EvidenceMethod
    result: EvidenceResult
    prerequisites: EvidencePrerequisites
    assumptions: tuple[BoundedSummary, ...]
    limitations: tuple[BoundedSummary, ...] = Field(min_length=1)
    validity: EvidenceValidity
    dependencies: tuple[EvidenceDependency, ...]
    producer: EvidenceProducer

    @field_validator("assumptions", "limitations", "dependencies", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_evidence_semantics(self) -> AssuranceEvidenceDescriptor:
        prerequisites_met = self.prerequisites.state is PrerequisiteState.satisfied
        if self.subject.digest is None and (prerequisites_met or self.result.verdict_bearing):
            raise ValueError(
                "an unavailable subject digest requires non-verdict evidence "
                "with unsatisfied prerequisites"
            )
        if not prerequisites_met and self.result.verdict_bearing:
            raise ValueError("unmet prerequisites cannot produce verdict-bearing evidence")
        if not prerequisites_met and self.result.state not in {
            EvidenceState.error,
            EvidenceState.prerequisites_unmet,
        }:
            raise ValueError(
                "unmet prerequisites require prerequisites_unmet or error result state"
            )
        if prerequisites_met and self.result.state is EvidenceState.prerequisites_unmet:
            raise ValueError("satisfied prerequisites conflict with prerequisites_unmet")
        if (
            self.method.evaluation_basis is EvidenceEvaluationBasis.llm_advisory
            and self.result.verdict_bearing
        ):
            raise ValueError(ReasonCode.LLM_JUDGE_VERDICT_BEARING_NOT_SUPPORTED.value)
        if (
            self.method.evaluation_basis
            in {
                EvidenceEvaluationBasis.stochastic,
                EvidenceEvaluationBasis.human_reviewed,
            }
            and self.scope.protocol_digest is None
        ):
            raise ValueError("stochastic and human-reviewed evidence requires a protocol digest")
        basis_sufficiency_check = {
            EvidenceEvaluationBasis.stochastic: STOCHASTIC_SUFFICIENCY_CHECK_ID,
            EvidenceEvaluationBasis.human_reviewed: HUMAN_REVIEW_SUFFICIENCY_CHECK_ID,
        }.get(self.method.evaluation_basis)
        if basis_sufficiency_check is not None:
            matching_checks = tuple(
                check
                for check in self.prerequisites.checks
                if check.check_id == basis_sufficiency_check
            )
            if (
                len(matching_checks) != 1
                or matching_checks[0].state is PrerequisiteState.satisfied
                or self.prerequisites.state is PrerequisiteState.satisfied
                or self.result.verdict_bearing
            ):
                raise ValueError(
                    f"{self.method.evaluation_basis.value} evidence cannot be "
                    "verdict-bearing until a typed sufficiency artifact is supported; "
                    f"it requires one non-satisfied {basis_sufficiency_check!r} check"
                )
        if self.method.method_id == ASSURANCE_MUTATION_METHOD_ID:
            check_ids = tuple(check.check_id for check in self.prerequisites.checks)
            if check_ids != ASSURANCE_MUTATION_PREREQUISITE_CHECK_IDS:
                raise ValueError(
                    f"{ASSURANCE_MUTATION_METHOD_ID} requires the exact canonical "
                    "prerequisite checks"
                )
        dependency_ids = tuple(item.evidence_id for item in self.dependencies)
        if len(set(dependency_ids)) != len(dependency_ids):
            raise ValueError("evidence dependency IDs must be unique")
        return self


class FindingSelector(FrozenStrictModel):
    control_id: str = Field(min_length=1, max_length=MAX_LABEL_CHARS)
    reason_code: ReasonCode
    target: str | None = Field(default=None, max_length=MAX_LABEL_CHARS)

    @field_validator("reason_code", mode="before")
    @classmethod
    def _coerce_reason_code(cls, value: object) -> ReasonCode:
        return coerce_enum(ReasonCode, value)


class RequiredFindingAlternatives(FrozenStrictModel):
    any_of: tuple[FindingSelector, ...] = Field(min_length=1)

    @field_validator("any_of", mode="before")
    @classmethod
    def _coerce_any_of(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _require_unique_alternatives(self) -> RequiredFindingAlternatives:
        keys = tuple(_selector_key(item) for item in self.any_of)
        if len(set(keys)) != len(keys):
            raise ValueError("required finding alternatives must be unique")
        return self


class ExpectedDetectionContract(SelfDigestedArtifact):
    _digest_field = "contract_digest"

    model_config = ConfigDict(json_schema_extra=_expected_detection_contract_json_schema_extra)

    artifact_kind: Literal["expected-detection-contract"] = "expected-detection-contract"
    schema_version: Literal["0.6.0"] = "0.6.0"
    schema_name: Literal["expected-detection-contract"] = "expected-detection-contract"
    contract_id: Literal["ExpectedDetectionContract/v1"] = "ExpectedDetectionContract/v1"
    contract_version: Literal["1.0.0"] = CONTRACT_VERSION
    contract_digest: DigestHex
    operator_id: str = Field(
        min_length=1,
        max_length=MAX_LABEL_CHARS,
        pattern=_MACHINE_ID_PATTERN,
    )
    target_control_ids: tuple[str, ...] = Field(min_length=1)
    required_findings: RequiredFindingAlternatives
    prohibited_substitutes: tuple[FindingSelector, ...]
    expected_gate_effect: GateEffect
    secondary_findings_allowed: bool

    @field_validator("target_control_ids", "prohibited_substitutes", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @field_validator("expected_gate_effect", mode="before")
    @classmethod
    def _coerce_gate_effect(cls, value: object) -> GateEffect:
        return coerce_enum(GateEffect, value)

    @model_validator(mode="after")
    def _validate_detector_identities(self) -> ExpectedDetectionContract:
        if self.target_control_ids != tuple(sorted(set(self.target_control_ids))):
            raise ValueError("target_control_ids must be unique and canonically sorted")
        known_controls = set(_built_in_policy_ids())
        unknown = sorted(set(self.target_control_ids) - known_controls)
        all_selectors = (*self.required_findings.any_of, *self.prohibited_substitutes)
        unknown.extend(sorted({selector.control_id for selector in all_selectors} - known_controls))
        if unknown:
            labels = ", ".join(sorted(set(unknown)))
            raise ValueError("expected detector references unknown controls: " + labels)
        if any(
            selector.control_id not in set(self.target_control_ids)
            for selector in self.required_findings.any_of
        ):
            raise ValueError("required findings must reference a target control")
        required = {_selector_key(item) for item in self.required_findings.any_of}
        prohibited = {_selector_key(item) for item in self.prohibited_substitutes}
        if required & prohibited:
            raise ValueError("required findings and prohibited substitutes must be disjoint")
        return self


class OperatorPrecondition(FrozenStrictModel):
    precondition_id: str = Field(
        min_length=1,
        max_length=MAX_LABEL_CHARS,
        pattern=_MACHINE_ID_PATTERN,
    )
    summary: str = Field(min_length=1, max_length=MAX_SUMMARY_CHARS)


class OperatorOrigin(FrozenStrictModel):
    kind: OperatorOriginKind
    references: tuple[BoundedSummary, ...] = Field(min_length=1)

    @field_validator("kind", mode="before")
    @classmethod
    def _coerce_kind(cls, value: object) -> OperatorOriginKind:
        return coerce_enum(OperatorOriginKind, value)

    @field_validator("references", mode="before")
    @classmethod
    def _coerce_references(cls, value: object) -> object:
        return coerce_tuple(value)


class TargetControlProvenance(FrozenStrictModel):
    control_id: str = Field(min_length=1, max_length=MAX_LABEL_CHARS)
    first_seen_commit: str = Field(pattern=r"^git:[a-f0-9]{40}$")
    digest_at_operator_creation: DigestHex


class OperatorAuthorship(FrozenStrictModel):
    relationship_to_control_author: AuthorshipRelationship

    @field_validator("relationship_to_control_author", mode="before")
    @classmethod
    def _coerce_relationship(cls, value: object) -> AuthorshipRelationship:
        return coerce_enum(AuthorshipRelationship, value)


class OperatorImplementationComponent(FrozenStrictModel):
    component_id: MachineIdentifier
    relative_path: str = Field(
        min_length=1,
        max_length=MAX_LABEL_CHARS,
        pattern=(
            r"^(?:agent_assure/(?:[A-Za-z0-9_./-]+\.py|"
            r"mutation/introduction_snapshots\.json)|"
            r"schemas/v[0-9]+\.[0-9]+\.[0-9]+/[A-Za-z0-9_.-]+\.schema\.json)$"
        ),
    )
    sha256: DigestHex

    @field_validator("relative_path")
    @classmethod
    def _require_safe_relative_path(cls, value: str) -> str:
        if ".." in value.split("/"):
            raise ValueError("implementation component path cannot traverse directories")
        return value


class OperatorProvenance(FrozenStrictModel):
    model_config = ConfigDict(json_schema_extra=_operator_provenance_json_schema_extra)

    operator_id: str = Field(
        min_length=1,
        max_length=MAX_LABEL_CHARS,
        pattern=_MACHINE_ID_PATTERN,
    )
    operator_version: str = Field(pattern=_SEMVER_PATTERN)
    implementation_digest: DigestHex
    implementation_components: tuple[OperatorImplementationComponent, ...]
    introduction_components: tuple[OperatorImplementationComponent, ...]
    introduced_at_commit: str | None = Field(
        default=None,
        pattern=r"^git:(?:[a-f0-9]{40}|uncommitted)$",
    )
    introduced_in_release: str | None = Field(default=None, pattern=_SEMVER_PATTERN)
    origin: OperatorOrigin
    target_controls: tuple[TargetControlProvenance, ...]
    authorship: OperatorAuthorship

    @field_validator(
        "implementation_components",
        "introduction_components",
        "target_controls",
        mode="before",
    )
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_implementation_manifest(self) -> OperatorProvenance:
        components = self.implementation_components
        if not components:
            if (
                self.origin.kind is OperatorOriginKind.unknown
                and self.implementation_digest == "0" * 64
                and not self.introduction_components
                and self.introduced_at_commit is None
                and self.introduced_in_release is None
                and not self.target_controls
                and self.authorship.relationship_to_control_author is AuthorshipRelationship.unknown
            ):
                return self
            if self.origin.kind is OperatorOriginKind.unknown:
                raise ValueError("unknown provenance must not invent implementation facts")
            raise ValueError("known operators require implementation components")
        if self.origin.kind is OperatorOriginKind.unknown:
            raise ValueError("known implementation components require a known origin")
        if self.introduced_at_commit is None or self.introduced_in_release is None:
            raise ValueError("known operators require introduction provenance")
        if not self.introduction_components:
            raise ValueError("known operators require introduction components")
        if not self.target_controls:
            raise ValueError("known operators require target-control provenance")
        self._validate_component_set(components, label="implementation")
        self._validate_component_set(
            self.introduction_components,
            label="introduction",
        )
        expected = mutation_implementation_digest(
            operator_id=self.operator_id,
            operator_version=self.operator_version,
            components=components,
        )
        if self.implementation_digest != expected:
            raise ValueError("implementation digest does not match its component manifest")
        return self

    @staticmethod
    def _validate_component_set(
        components: tuple[OperatorImplementationComponent, ...],
        *,
        label: str,
    ) -> None:
        component_keys = tuple(
            (component.component_id, component.relative_path) for component in components
        )
        if component_keys != tuple(sorted(set(component_keys))):
            raise ValueError(f"{label} components must be unique and canonically sorted")
        component_ids = tuple(component.component_id for component in components)
        if len(set(component_ids)) != len(component_ids):
            raise ValueError(f"{label} component IDs must be unique")
        relative_paths = tuple(component.relative_path for component in components)
        if len(set(relative_paths)) != len(relative_paths):
            raise ValueError(f"{label} component paths must be unique")


class AssuranceMutationOperator(SelfDigestedArtifact):
    _digest_field = "operator_digest"

    artifact_kind: Literal["assurance-mutation-operator"] = "assurance-mutation-operator"
    schema_version: Literal["0.6.0"] = "0.6.0"
    schema_name: Literal["assurance-mutation-operator"] = "assurance-mutation-operator"
    contract_id: Literal["AssuranceMutationOperator/v1"] = "AssuranceMutationOperator/v1"
    contract_version: Literal["1.0.0"] = CONTRACT_VERSION
    operator_digest: DigestHex
    operator_id: str = Field(
        min_length=1,
        max_length=MAX_LABEL_CHARS,
        pattern=_MACHINE_ID_PATTERN,
    )
    operator_version: str = Field(pattern=_SEMVER_PATTERN)
    input_artifact_kind: Literal["run-set"] = "run-set"
    compatible_schema_versions: tuple[SchemaVersion, ...] = Field(min_length=1)
    preconditions: tuple[OperatorPrecondition, ...] = Field(min_length=1)
    permitted_changed_paths: tuple[JsonPointerTemplate, ...] = Field(min_length=1)
    privacy_classification: MutationPrivacyClassification
    provenance: OperatorProvenance
    independence_class: IndependenceClass
    implementation_digest: DigestHex
    expected_detection_contract: ExpectedDetectionContract

    @field_validator(
        "compatible_schema_versions",
        "preconditions",
        "permitted_changed_paths",
        mode="before",
    )
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @field_validator("privacy_classification", mode="before")
    @classmethod
    def _coerce_privacy_classification(cls, value: object) -> MutationPrivacyClassification:
        return coerce_enum(MutationPrivacyClassification, value)

    @field_validator("independence_class", mode="before")
    @classmethod
    def _coerce_independence_class(cls, value: object) -> IndependenceClass:
        return coerce_enum(IndependenceClass, value)

    @model_validator(mode="after")
    def _validate_operator_contract(self) -> AssuranceMutationOperator:
        if self.compatible_schema_versions != tuple(sorted(set(self.compatible_schema_versions))):
            raise ValueError("compatible schema versions must be unique and sorted")
        if self.permitted_changed_paths != tuple(sorted(set(self.permitted_changed_paths))):
            raise ValueError("permitted changed paths must be unique and sorted")
        for pointer in self.permitted_changed_paths:
            if not _json_pointer_is_valid(pointer, allow_wildcard=True):
                raise ValueError(f"invalid permitted changed-path template: {pointer!r}")
        contract = self.expected_detection_contract
        provenance = self.provenance
        if contract.operator_id != self.operator_id or provenance.operator_id != self.operator_id:
            raise ValueError("operator, provenance, and detector contract IDs must match")
        if provenance.operator_version != self.operator_version:
            raise ValueError("operator and provenance versions must match")
        if (
            provenance.implementation_digest != self.implementation_digest
            or contract.operator_id != self.operator_id
        ):
            raise ValueError("operator implementation identity is inconsistent")
        provenance_controls = tuple(sorted(item.control_id for item in provenance.target_controls))
        if provenance_controls != contract.target_control_ids:
            raise ValueError("operator provenance and detector target controls must match")
        _validate_independence_origin(self.independence_class, provenance.origin.kind)
        return self


class ObservedFinding(FrozenStrictModel):
    finding_id: str = Field(min_length=1, max_length=MAX_LABEL_CHARS)
    control_id: str = Field(min_length=1, max_length=MAX_LABEL_CHARS)
    state: GateState
    reason_code: ReasonCode
    target_digest: DigestHex | None = None

    @field_validator("state", mode="before")
    @classmethod
    def _coerce_state(cls, value: object) -> GateState:
        return coerce_enum(GateState, value)

    @field_validator("reason_code", mode="before")
    @classmethod
    def _coerce_reason_code(cls, value: object) -> ReasonCode:
        return coerce_enum(ReasonCode, value)


class AssuranceMutationResult(SelfDigestedArtifact):
    _digest_field = "result_digest"

    model_config = ConfigDict(json_schema_extra=_mutation_result_json_schema_extra)

    artifact_kind: Literal["assurance-mutation-result"] = "assurance-mutation-result"
    schema_version: Literal["0.6.0"] = "0.6.0"
    schema_name: Literal["assurance-mutation-result"] = "assurance-mutation-result"
    contract_id: Literal["AssuranceMutationResult/v1"] = "AssuranceMutationResult/v1"
    contract_version: Literal["1.0.0"] = CONTRACT_VERSION
    result_digest: DigestHex
    source_artifact_kind: Literal["run-set"] = "run-set"
    source_digest: DigestHex | None = None
    mutated_digest: DigestHex | None = None
    operator_id: str = Field(
        min_length=1,
        max_length=MAX_LABEL_CHARS,
        pattern=_MACHINE_ID_PATTERN,
    )
    operator_version: str = Field(pattern=_SEMVER_PATTERN)
    operator_digest: DigestHex
    implementation_digest: DigestHex
    expected_detection_contract_digest: DigestHex
    expected_finding_target_digest: DigestHex | None = None
    evaluator_method_id: MachineIdentifier
    evaluator_implementation_digest: DigestHex
    evaluator_implementation_version: str = Field(pattern=_SEMVER_PATTERN)
    evaluator_evaluation_basis: EvidenceEvaluationBasis
    evaluator_protocol_digest: DigestHex | None = None
    evaluator_population_id: MachineIdentifier
    gate_profile_id: MachineIdentifier
    gate_profile_digest: DigestHex
    waiver_set_digest: DigestHex
    evaluation_date: str = Field(pattern=_ISO_DATE_PATTERN)
    seed: int = Field(ge=0, le=RFC8785_SAFE_INTEGER_MAX)
    changed_paths: tuple[ExactJsonPointer, ...]
    observed_findings: tuple[ObservedFinding, ...]
    matched_finding_ids: tuple[MachineIdentifier, ...]
    state: MutationResultState
    provenance: OperatorProvenance
    independence_class: IndependenceClass
    diagnostic_code: MachineIdentifier | None = None
    diagnostic_exception_class: MachineIdentifier | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    local_debug_reference: MachineIdentifier | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    limitations: tuple[BoundedSummary, ...] = Field(min_length=1)

    @field_validator(
        "changed_paths",
        "observed_findings",
        "matched_finding_ids",
        "limitations",
        mode="before",
    )
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @field_validator("state", mode="before")
    @classmethod
    def _coerce_state(cls, value: object) -> MutationResultState:
        return coerce_enum(MutationResultState, value)

    @field_validator("evaluator_evaluation_basis", mode="before")
    @classmethod
    def _coerce_evaluator_evaluation_basis(cls, value: object) -> EvidenceEvaluationBasis:
        return coerce_enum(EvidenceEvaluationBasis, value)

    @field_validator("independence_class", mode="before")
    @classmethod
    def _coerce_independence_class(cls, value: object) -> IndependenceClass:
        return coerce_enum(IndependenceClass, value)

    @field_validator("evaluation_date")
    @classmethod
    def _validate_evaluation_date(cls, value: str) -> str:
        try:
            datetime.strptime(value, "%Y-%m-%d")
        except ValueError as exc:
            raise ValueError("evaluation_date must be a valid YYYY-MM-DD date") from exc
        return value

    @model_validator(mode="after")
    def _validate_result_state(self) -> AssuranceMutationResult:
        if (
            self.provenance.operator_id != self.operator_id
            or self.provenance.operator_version != self.operator_version
            or self.provenance.implementation_digest != self.implementation_digest
        ):
            raise ValueError("mutation result and operator provenance identities must match")
        if self.evaluator_implementation_digest == "0" * 64 and not (
            self.state is MutationResultState.execution_error
            and self.diagnostic_code == "catalog_integrity_error"
        ):
            raise ValueError(
                "unavailable evaluator implementation identity is reserved for "
                "catalog bootstrap failures"
            )
        diagnostic_identity = (
            self.diagnostic_exception_class,
            self.local_debug_reference,
        )
        if (diagnostic_identity[0] is None) != (diagnostic_identity[1] is None):
            raise ValueError(
                "diagnostic exception class and local debug reference must appear together"
            )
        if diagnostic_identity[0] is not None and (
            self.state is not MutationResultState.execution_error or self.diagnostic_code is None
        ):
            raise ValueError("internal diagnostic identity is reserved for execution errors")
        if (
            self.evaluator_evaluation_basis
            in {
                EvidenceEvaluationBasis.stochastic,
                EvidenceEvaluationBasis.human_reviewed,
            }
            and self.evaluator_protocol_digest is None
        ):
            raise ValueError(
                "stochastic and human-reviewed evaluator identities require a protocol digest"
            )
        required_sufficiency_limitation = {
            EvidenceEvaluationBasis.stochastic: STOCHASTIC_SUFFICIENCY_LIMITATION,
            EvidenceEvaluationBasis.human_reviewed: HUMAN_REVIEW_SUFFICIENCY_LIMITATION,
        }.get(self.evaluator_evaluation_basis)
        if (
            self.state in {MutationResultState.caught, MutationResultState.survived}
            and required_sufficiency_limitation is not None
            and required_sufficiency_limitation not in self.limitations
        ):
            raise ValueError(
                "non-deterministic mutation results require the canonical "
                "non-verdict sufficiency limitation"
            )
        if (
            self.state in {MutationResultState.caught, MutationResultState.survived}
            and self.evaluator_evaluation_basis is EvidenceEvaluationBasis.llm_advisory
        ):
            raise ValueError(ReasonCode.LLM_JUDGE_VERDICT_BEARING_NOT_SUPPORTED.value)
        _validate_independence_origin(self.independence_class, self.provenance.origin.kind)
        mutated_states = {MutationResultState.caught, MutationResultState.survived}
        if self.state in mutated_states:
            if self.source_digest is None or self.mutated_digest is None or not self.changed_paths:
                raise ValueError("caught and survived results require source, mutation, and paths")
            if self.mutated_digest == self.source_digest:
                raise ValueError("mutation must change the canonical subject digest")
            if self.expected_finding_target_digest is None:
                raise ValueError("caught and survived results require an expected target digest")
        elif self.mutated_digest is not None or self.changed_paths or self.matched_finding_ids:
            raise ValueError("non-mutation result states cannot imply a persisted mutation")
        elif self.expected_finding_target_digest is not None:
            raise ValueError("non-mutation result states cannot imply a selected target")
        if self.state is MutationResultState.caught and not self.matched_finding_ids:
            raise ValueError("caught requires a normative matched finding")
        if self.state is not MutationResultState.caught and self.matched_finding_ids:
            raise ValueError("only caught may carry normative matched findings")
        observed_ids = tuple(item.finding_id for item in self.observed_findings)
        if len(set(observed_ids)) != len(observed_ids):
            raise ValueError("observed finding IDs must be unique")
        if len(set(self.matched_finding_ids)) != len(self.matched_finding_ids):
            raise ValueError("matched finding IDs must be unique")
        if not set(self.matched_finding_ids).issubset(observed_ids):
            raise ValueError("matched findings must be present in observed findings")
        observed_by_id = {item.finding_id: item for item in self.observed_findings}
        if any(
            observed_by_id[finding_id].target_digest != self.expected_finding_target_digest
            for finding_id in self.matched_finding_ids
        ):
            raise ValueError("matched findings must carry the expected target digest")
        if self.changed_paths != tuple(sorted(set(self.changed_paths))):
            raise ValueError("changed paths must be unique and canonically sorted")
        if any(not _json_pointer_is_valid(path) for path in self.changed_paths):
            raise ValueError("changed paths must be exact valid JSON Pointers")
        return self


def _selector_key(selector: FindingSelector) -> tuple[str, ReasonCode, str | None]:
    return (selector.control_id, selector.reason_code, selector.target)


@cache
def _built_in_policy_ids() -> tuple[str, ...]:
    # Import lazily: importing policies.catalog first initializes schema.common,
    # whose package initializer exports these mutation models.
    from agent_assure.policies.catalog import BUILT_IN_POLICY_IDS

    return tuple(BUILT_IN_POLICY_IDS)


def _json_pointer_is_valid(pointer: str, *, allow_wildcard: bool = False) -> bool:
    if not pointer or not pointer.startswith("/"):
        return False
    parts = pointer[1:].split("/")
    for part in parts:
        index = 0
        while index < len(part):
            if part[index] != "~":
                index += 1
                continue
            if index + 1 >= len(part) or part[index + 1] not in {"0", "1"}:
                return False
            index += 2
        if not allow_wildcard and part == "*":
            return False
    return True


def _parse_rfc3339(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp is not a valid RFC 3339 date-time") from exc


def _validate_independence_origin(
    independence_class: IndependenceClass,
    origin_kind: OperatorOriginKind,
) -> None:
    if independence_class is IndependenceClass.unknown:
        return
    expected_origin = {
        IndependenceClass.external_preexisting: OperatorOriginKind.external_preexisting,
        IndependenceClass.third_party_contributed: OperatorOriginKind.third_party_contributed,
        IndependenceClass.first_party_precontrol: OperatorOriginKind.first_party,
        IndependenceClass.first_party_postcontrol: OperatorOriginKind.first_party,
    }[independence_class]
    if origin_kind is not expected_origin:
        raise ValueError("independence class conflicts with declared operator origin")


def mutation_implementation_digest(
    *,
    operator_id: str,
    operator_version: str,
    components: tuple[OperatorImplementationComponent, ...],
) -> str:
    """Digest an ordered, reviewable implementation-component manifest."""
    return _canonical_sha256(
        {
            "contract_id": IMPLEMENTATION_MANIFEST_CONTRACT,
            "operator_id": operator_id,
            "operator_version": operator_version,
            "components": [component.model_dump(mode="json") for component in components],
        }
    )


def finding_target_digest(target: str) -> str:
    """Return a domain-separated canonical digest for a finding target.

    The target itself is intentionally omitted from persisted mutation results.
    This digest binds a privacy-minimized observed finding to the exact target
    selected by the deterministic operator without sharing a digest domain with
    artifacts or implementation manifests.
    """
    if not isinstance(target, str):
        raise TypeError("finding target must be a string")
    return _canonical_sha256(
        {
            "contract_id": FINDING_TARGET_DIGEST_CONTRACT,
            "target": target,
        }
    )


def _canonical_sha256(value: object) -> str:
    # Imported lazily so schema package initialization cannot cycle through the
    # canonical layer while that layer is importing ReasonCode.
    from agent_assure.canonical.digests import sha256_hexdigest

    return sha256_hexdigest(value)
