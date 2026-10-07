from __future__ import annotations

from collections import Counter
from datetime import date
from pathlib import Path
from typing import Literal

from pydantic import ConfigDict, Field, model_validator
from pydantic.functional_validators import field_validator

from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.evaluation.expectations import ExpectationResolver
from agent_assure.evaluation.invariants import evaluate_runset_controls
from agent_assure.fixtures.loader import compiled_suite_digest
from agent_assure.io_limits import (
    MAX_JOURNAL_BEARING_RUNSET_JSON_BYTES,
    MAX_PERSISTED_OBSERVATIONS,
)
from agent_assure.policies.base import (
    DEFAULT_GATE_PROFILE,
    ControlResult,
    GateProfile,
    Waiver,
    apply_waivers_with_dispositions,
    rollup_state,
)
from agent_assure.policies.catalog import DEFAULT_NOT_EVALUATED_CAPABILITIES, CapabilityStatus
from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.schema.base import (
    SCHEMA_VERSION,
    FrozenStrictModel,
    PersistedArtifact,
    SchemaVersion,
    StrictModel,
)
from agent_assure.schema.common import (
    V063_CONTRACT_SCHEMA_VERSIONS,
    DigestHex,
    GateState,
    ReasonCode,
    Severity,
    coerce_enum,
    coerce_tuple,
)
from agent_assure.schema.environment import EnvironmentInfo
from agent_assure.schema.evaluation import (
    MAX_WAIVER_DISPOSITIONS,
    EvaluationGateProfileContext,
    EvaluationReplayContext,
    EvaluationSummary,
    EvaluationWaiverContext,
    Finding,
    WaiverDisposition,
    WaiverDispositionStatus,
    current_waiver_governance_array_json_schema,
    validate_current_waiver_governance,
)
from agent_assure.schema.run import RunSet
from agent_assure.schema.suite import CompiledSuite
from agent_assure.schema.usage import (
    UsageSummary,
    usage_container_json_schema_extra,
    validate_usage_field_paths_schema_version,
)
from agent_assure.schema.validation import validate_loaded_artifact_payload
from agent_assure.usage.aggregation import usage_summary_for_runset

_TOOL_ALLOWLIST_CAPABILITY_ID = "tool_allowlist"
_TOOL_ALLOWLIST_NOT_EVALUATED_REASON = "suite and case expectations do not configure a tool policy"
_TOOL_ALLOWLIST_EVALUATED_REASON = (
    "suite or case expectations configure a tool policy; per-case evaluation is reported separately"
)
_DEFAULT_CAPABILITY_BY_ID = {
    capability.capability_id: capability for capability in DEFAULT_NOT_EVALUATED_CAPABILITIES
}
_MANDATORY_CAPABILITY_IDS = frozenset((*_DEFAULT_CAPABILITY_BY_ID, _TOOL_ALLOWLIST_CAPABILITY_ID))

_EVALUATION_REPORT_USAGE_FIELD_PATHS = (
    ("usage_summary",),
    ("candidate_vs_expectations", "usage_summary"),
)
_EVALUATION_REPORT_JSON_SCHEMA_EXTRA = usage_container_json_schema_extra(
    *_EVALUATION_REPORT_USAGE_FIELD_PATHS
)
_RUNSET_DIGEST_SCHEMA_VERSIONS = frozenset(
    {"0.6.0", "0.6.1", "0.6.2", "0.6.3", "0.6.4", "0.6.5", "0.6.6"}
)
_EVALUATION_REPORT_JSON_SCHEMA_EXTRA["allOf"].append(
    {
        "if": {
            "required": ["schema_version"],
            "properties": {
                "schema_version": {
                    "enum": sorted(_RUNSET_DIGEST_SCHEMA_VERSIONS),
                }
            },
        },
        "then": {
            "required": ["runset_digest", "waiver_dispositions"],
            "properties": {"runset_digest": {"type": "string"}},
        },
    }
)
_EVALUATION_REPORT_JSON_SCHEMA_EXTRA["allOf"].append(
    {
        "if": {
            "properties": {"schema_version": {"const": SCHEMA_VERSION}},
        },
        "then": {
            "required": [
                "case_outcomes",
                "capability_coverage",
                "not_evaluated_capabilities",
                "source_projection",
            ],
            "properties": {
                "candidate_vs_expectations": {
                    "required": ["replay_context"],
                },
                "case_outcomes": {
                    "minItems": 1,
                    "uniqueItems": True,
                },
                "source_projection": {
                    "type": "object",
                    "required": [
                        "suite_id",
                        "suite_version",
                        "suite_digest",
                        "runset_id",
                        "runset_digest",
                        "cases",
                        "unknown_run_case_ids",
                        "tool_policy_configured",
                    ],
                    "properties": {
                        "cases": {
                            "minItems": 1,
                            "maxItems": MAX_PERSISTED_OBSERVATIONS,
                            "uniqueItems": True,
                        },
                        "unknown_run_case_ids": {
                            "maxItems": MAX_PERSISTED_OBSERVATIONS,
                            "uniqueItems": True,
                        },
                    },
                },
                "capability_coverage": {
                    "minItems": len(_MANDATORY_CAPABILITY_IDS),
                    "maxItems": len(_MANDATORY_CAPABILITY_IDS),
                    "uniqueItems": True,
                    "items": {
                        "properties": {
                            "capability_id": {
                                "enum": sorted(_MANDATORY_CAPABILITY_IDS),
                            }
                        }
                    },
                    "allOf": [
                        {
                            "contains": {
                                "required": ["capability_id", "state", "reason"],
                                "properties": {
                                    "capability_id": {"const": capability.capability_id},
                                    "state": {"const": GateState.not_evaluated.value},
                                    "reason": {"const": capability.reason},
                                },
                            },
                            "minContains": 1,
                            "maxContains": 1,
                        }
                        for capability in DEFAULT_NOT_EVALUATED_CAPABILITIES
                    ]
                    + [
                        {
                            "contains": {
                                "required": ["capability_id", "state", "reason"],
                                "properties": {
                                    "capability_id": {
                                        "const": _TOOL_ALLOWLIST_CAPABILITY_ID,
                                    },
                                    "state": {
                                        "enum": [
                                            GateState.pass_.value,
                                            GateState.not_evaluated.value,
                                        ]
                                    },
                                    "reason": {
                                        "enum": [
                                            _TOOL_ALLOWLIST_EVALUATED_REASON,
                                            _TOOL_ALLOWLIST_NOT_EVALUATED_REASON,
                                        ]
                                    },
                                },
                                "oneOf": [
                                    {
                                        "properties": {
                                            "state": {"const": GateState.pass_.value},
                                            "reason": {
                                                "const": _TOOL_ALLOWLIST_EVALUATED_REASON,
                                            },
                                        }
                                    },
                                    {
                                        "properties": {
                                            "state": {
                                                "const": GateState.not_evaluated.value,
                                            },
                                            "reason": {
                                                "const": _TOOL_ALLOWLIST_NOT_EVALUATED_REASON,
                                            },
                                        }
                                    },
                                ],
                            },
                            "minContains": 1,
                            "maxContains": 1,
                        }
                    ],
                },
                "not_evaluated_capabilities": {
                    "minItems": len(_DEFAULT_CAPABILITY_BY_ID),
                    "maxItems": len(_MANDATORY_CAPABILITY_IDS),
                    "uniqueItems": True,
                    "items": {
                        "required": ["capability_id", "state", "reason"],
                        "properties": {
                            "capability_id": {
                                "enum": sorted(_MANDATORY_CAPABILITY_IDS),
                            },
                            "state": {"const": GateState.not_evaluated.value},
                        },
                    },
                    "allOf": [
                        {
                            "contains": {
                                "required": ["capability_id", "state", "reason"],
                                "properties": {
                                    "capability_id": {"const": capability.capability_id},
                                    "state": {"const": GateState.not_evaluated.value},
                                    "reason": {"const": capability.reason},
                                },
                            },
                            "minContains": 1,
                            "maxContains": 1,
                        }
                        for capability in DEFAULT_NOT_EVALUATED_CAPABILITIES
                    ],
                },
                "waiver_dispositions": current_waiver_governance_array_json_schema(),
            },
        },
    }
)
for tool_state, reason, expected_not_evaluated_count in (
    (GateState.pass_, _TOOL_ALLOWLIST_EVALUATED_REASON, len(_DEFAULT_CAPABILITY_BY_ID)),
    (
        GateState.not_evaluated,
        _TOOL_ALLOWLIST_NOT_EVALUATED_REASON,
        len(_MANDATORY_CAPABILITY_IDS),
    ),
):
    _EVALUATION_REPORT_JSON_SCHEMA_EXTRA["allOf"].append(
        {
            "if": {
                "required": ["schema_version", "capability_coverage"],
                "properties": {
                    "schema_version": {"const": SCHEMA_VERSION},
                    "capability_coverage": {
                        "contains": {
                            "required": ["capability_id", "state", "reason"],
                            "properties": {
                                "capability_id": {"const": _TOOL_ALLOWLIST_CAPABILITY_ID},
                                "state": {"const": tool_state.value},
                                "reason": {"const": reason},
                            },
                        }
                    },
                },
            },
            "then": {
                "properties": {
                    "not_evaluated_capabilities": {
                        "minItems": expected_not_evaluated_count,
                        "maxItems": expected_not_evaluated_count,
                        **(
                            {
                                "contains": {
                                    "required": ["capability_id", "state", "reason"],
                                    "properties": {
                                        "capability_id": {
                                            "const": _TOOL_ALLOWLIST_CAPABILITY_ID,
                                        },
                                        "state": {
                                            "const": GateState.not_evaluated.value,
                                        },
                                        "reason": {
                                            "const": _TOOL_ALLOWLIST_NOT_EVALUATED_REASON,
                                        },
                                    },
                                }
                            }
                            if tool_state is GateState.not_evaluated
                            else {
                                "not": {
                                    "contains": {
                                        "required": ["capability_id"],
                                        "properties": {
                                            "capability_id": {
                                                "const": _TOOL_ALLOWLIST_CAPABILITY_ID,
                                            }
                                        },
                                    }
                                }
                            }
                        ),
                    }
                }
            },
        }
    )
for tool_policy_configured, tool_state, reason in (
    (True, GateState.pass_, _TOOL_ALLOWLIST_EVALUATED_REASON),
    (False, GateState.not_evaluated, _TOOL_ALLOWLIST_NOT_EVALUATED_REASON),
):
    _EVALUATION_REPORT_JSON_SCHEMA_EXTRA["allOf"].append(
        {
            "if": {
                "required": ["schema_version", "source_projection"],
                "properties": {
                    "schema_version": {"const": SCHEMA_VERSION},
                    "source_projection": {
                        "required": ["tool_policy_configured"],
                        "properties": {"tool_policy_configured": {"const": tool_policy_configured}},
                    },
                },
            },
            "then": {
                "properties": {
                    "capability_coverage": {
                        "contains": {
                            "required": ["capability_id", "state", "reason"],
                            "properties": {
                                "capability_id": {"const": _TOOL_ALLOWLIST_CAPABILITY_ID},
                                "state": {"const": tool_state.value},
                                "reason": {"const": reason},
                            },
                        },
                        "minContains": 1,
                        "maxContains": 1,
                    }
                }
            },
        }
    )
RunSetCompatibilityCode = Literal[
    "privacy_profile_incompatible",
    "suite_binding_mismatch",
    "fixture_binding_mismatch",
]


class RunSetCompatibilityError(ValueError):
    """A safe-to-classify incompatibility between a RunSet and evaluation context."""

    diagnostic_code: RunSetCompatibilityCode

    def __init__(self, diagnostic_code: RunSetCompatibilityCode, message: str) -> None:
        super().__init__(message)
        self.diagnostic_code = diagnostic_code


class EvaluationSourceVerificationError(ValueError):
    """The persisted source projection does not match separately trusted inputs."""


class EvaluationMetrics(StrictModel):
    total_cases: int = Field(ge=0)
    evaluated_cases: int = Field(ge=0)
    unevaluated_cases: int = Field(ge=0)
    passed_cases: int = Field(ge=0)
    warning_cases: int = Field(default=0, ge=0)
    failed_cases: int = Field(ge=0)
    warning_findings: int = Field(ge=0)
    blocking_findings: int = Field(ge=0)
    global_blocking_findings: int = Field(ge=0)
    findings_by_reason: dict[str, int]
    findings_by_control: dict[str, int]


class CapabilityReport(StrictModel):
    capability_id: str = Field(min_length=1)
    state: GateState
    reason: str = Field(min_length=1)

    @field_validator("state", mode="before")
    @classmethod
    def _coerce_state(cls, value: object) -> GateState:
        return coerce_enum(GateState, value)


class EvaluationCaseOutcome(StrictModel):
    """Minimal exhaustive projection of one suite case's evaluation outcome."""

    case_id: str = Field(min_length=1)
    state: GateState

    @field_validator("state", mode="before")
    @classmethod
    def _coerce_state(cls, value: object) -> GateState:
        return coerce_enum(GateState, value)


class EvaluationSourceCase(FrozenStrictModel):
    """Source coverage fact for one case in the digest-identified compiled suite."""

    case_id: str = Field(min_length=1)
    run_record_count: int = Field(ge=0, le=MAX_PERSISTED_OBSERVATIONS)
    record_status: Literal["included", "missing", "duplicate", "excluded"]

    @model_validator(mode="after")
    def _validate_record_status_count(self) -> EvaluationSourceCase:
        if self.record_status == "missing" and self.run_record_count != 0:
            raise ValueError("missing source cases require run_record_count 0")
        if self.record_status in {"included", "excluded"} and self.run_record_count != 1:
            raise ValueError(f"{self.record_status} source cases require run_record_count 1")
        if self.record_status == "duplicate" and self.run_record_count < 2:
            raise ValueError("duplicate source cases require run_record_count at least 2")
        return self


class EvaluationSourceProjection(FrozenStrictModel):
    """Minimal source assertion re-derivable from a trusted suite and RunSet."""

    suite_id: str = Field(min_length=1)
    suite_version: str = Field(min_length=1)
    suite_digest: DigestHex
    runset_id: str = Field(min_length=1)
    runset_digest: DigestHex
    cases: tuple[EvaluationSourceCase, ...] = Field(
        min_length=1,
        max_length=MAX_PERSISTED_OBSERVATIONS,
    )
    unknown_run_case_ids: tuple[str, ...] = Field(max_length=MAX_PERSISTED_OBSERVATIONS)
    tool_policy_configured: bool

    @field_validator("cases", "unknown_run_case_ids", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_case_partition(self) -> EvaluationSourceProjection:
        case_ids = tuple(item.case_id for item in self.cases)
        if "*" in case_ids:
            raise ValueError("evaluation source cases reserve '*' for global findings")
        if len(set(case_ids)) != len(case_ids):
            raise ValueError("evaluation source cases require unique case_id values")
        if self.unknown_run_case_ids != tuple(sorted(set(self.unknown_run_case_ids))):
            raise ValueError("unknown_run_case_ids must be unique and sorted")
        if "*" in self.unknown_run_case_ids:
            raise ValueError("unknown_run_case_ids must not contain the global '*' scope")
        overlap = set(case_ids) & set(self.unknown_run_case_ids)
        if overlap:
            raise ValueError(
                "evaluation source suite cases and unknown RunSet cases must be disjoint"
            )
        return self


class EvaluationReport(PersistedArtifact):
    model_config = ConfigDict(json_schema_extra=_EVALUATION_REPORT_JSON_SCHEMA_EXTRA)

    artifact_kind: Literal["evaluation-report"] = "evaluation-report"
    candidate_vs_expectations: EvaluationSummary
    runset_id: str
    runset_digest: DigestHex | None = Field(default=None, exclude_if=lambda value: value is None)
    suite_id: str
    suite_version: str
    gate_profile: str
    metrics: EvaluationMetrics
    source_projection: EvaluationSourceProjection | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    case_outcomes: tuple[EvaluationCaseOutcome, ...] = ()
    environment: EnvironmentInfo | None = None
    usage_summary: UsageSummary | None = Field(default=None, exclude_if=lambda value: value is None)
    failed_controls: tuple[Finding, ...] = ()
    warning_controls: tuple[Finding, ...] = ()
    waiver_dispositions: tuple[WaiverDisposition, ...] = Field(
        default=(),
        max_length=MAX_WAIVER_DISPOSITIONS,
    )
    capability_coverage: tuple[CapabilityReport, ...] = ()
    not_evaluated_capabilities: tuple[CapabilityReport, ...] = ()
    limitations: tuple[str, ...] = (
        "offline fixture evaluation does not certify safety, compliance, clinical validity, "
        "or live model quality",
    )

    @field_validator(
        "failed_controls",
        "warning_controls",
        "waiver_dispositions",
        "case_outcomes",
        "capability_coverage",
        "not_evaluated_capabilities",
        "limitations",
        mode="before",
    )
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_usage_schema_version(self) -> EvaluationReport:
        if self.schema_version in _RUNSET_DIGEST_SCHEMA_VERSIONS and self.runset_digest is None:
            raise ValueError("v0.6 evaluation report requires runset_digest")
        summary_digest = self.candidate_vs_expectations.runset_digest
        if summary_digest is not None and summary_digest != self.runset_digest:
            raise ValueError(
                "evaluation summary runset_digest must match evaluation report runset_digest"
            )
        validate_usage_field_paths_schema_version(
            self.schema_version,
            owner="evaluation report",
            root=self,
            field_paths=_EVALUATION_REPORT_USAGE_FIELD_PATHS,
        )
        return self

    @model_validator(mode="after")
    def _validate_current_report_coherence(self) -> EvaluationReport:
        """Reconcile every current report aggregate with its decision evidence."""

        if self.schema_version != SCHEMA_VERSION:
            return self

        metrics = self.metrics
        if metrics.total_cases == 0:
            raise ValueError("current evaluation reports require at least one total case")
        if metrics.total_cases != metrics.evaluated_cases + metrics.unevaluated_cases:
            raise ValueError(
                "evaluation metrics total_cases must equal evaluated_cases plus unevaluated_cases"
            )
        if metrics.evaluated_cases != (
            metrics.passed_cases + metrics.warning_cases + metrics.failed_cases
        ):
            raise ValueError(
                "evaluation metrics evaluated_cases must equal passed_cases plus "
                "warning_cases plus failed_cases"
            )
        if metrics.global_blocking_findings > metrics.blocking_findings:
            raise ValueError(
                "evaluation metrics global_blocking_findings cannot exceed blocking_findings"
            )
        if metrics.failed_cases + metrics.global_blocking_findings > metrics.blocking_findings:
            raise ValueError(
                "evaluation metrics failed_cases plus global_blocking_findings cannot exceed "
                "blocking_findings"
            )
        if metrics.warning_cases > metrics.warning_findings:
            raise ValueError("evaluation metrics warning_cases cannot exceed warning_findings")

        summary = self.candidate_vs_expectations
        if summary.schema_version != SCHEMA_VERSION:
            raise ValueError("current evaluation reports require a current evaluation summary")
        if self.runset_id != summary.runset_id:
            raise ValueError("evaluation report runset_id must match its evaluation summary")
        if self.environment != summary.environment:
            raise ValueError("evaluation report environment must match its evaluation summary")
        if self.usage_summary != summary.usage_summary:
            raise ValueError("evaluation report usage_summary must match its evaluation summary")
        replay_context = summary.replay_context
        if replay_context is None:
            raise ValueError(
                "current evaluation reports require replay context binding the suite digest"
            )
        if self.gate_profile != replay_context.gate_profile.profile_id:
            raise ValueError(
                "evaluation report gate_profile must match its evaluation summary replay context"
            )

        source_projection = self.source_projection
        if source_projection is None:
            raise ValueError("current evaluation reports require a persisted source projection")
        if (
            source_projection.suite_id != self.suite_id
            or source_projection.suite_version != self.suite_version
            or source_projection.suite_digest != replay_context.suite_digest
        ):
            raise ValueError(
                "evaluation source projection must match report suite identity and replay digest"
            )
        if (
            source_projection.runset_id != self.runset_id
            or source_projection.runset_digest != self.runset_digest
        ):
            raise ValueError(
                "evaluation source projection must match report RunSet identity and digest"
            )

        outcomes_by_case: dict[str, EvaluationCaseOutcome] = {}
        for outcome in self.case_outcomes:
            if outcome.case_id == "*":
                raise ValueError("evaluation case outcomes reserve '*' for global findings")
            if outcome.case_id in outcomes_by_case:
                raise ValueError(
                    f"evaluation case outcomes contain duplicate case_id {outcome.case_id!r}"
                )
            outcomes_by_case[outcome.case_id] = outcome
        if not outcomes_by_case:
            raise ValueError("current evaluation reports require exhaustive case outcomes")
        source_case_ids = tuple(item.case_id for item in source_projection.cases)
        outcome_case_ids = tuple(item.case_id for item in self.case_outcomes)
        if outcome_case_ids != source_case_ids:
            raise ValueError(
                "evaluation case outcomes must exactly cover the persisted source suite cases"
            )
        for source_case, outcome in zip(
            source_projection.cases,
            self.case_outcomes,
            strict=True,
        ):
            if (
                source_case.record_status == "included" and outcome.state is GateState.not_evaluated
            ) or (
                source_case.record_status != "included"
                and outcome.state is not GateState.not_evaluated
            ):
                raise ValueError(
                    f"evaluation case outcome {outcome.case_id!r} must match persisted "
                    "source record coverage"
                )

        outcome_counts = Counter(outcome.state for outcome in self.case_outcomes)
        expected_case_metrics = {
            "total_cases": len(self.case_outcomes),
            "evaluated_cases": len(self.case_outcomes) - outcome_counts[GateState.not_evaluated],
            "unevaluated_cases": outcome_counts[GateState.not_evaluated],
            "passed_cases": outcome_counts[GateState.pass_],
            "warning_cases": outcome_counts[GateState.warn],
            "failed_cases": outcome_counts[GateState.fail],
        }
        for metric_name, expected_metric_value in expected_case_metrics.items():
            if getattr(metrics, metric_name) != expected_metric_value:
                raise ValueError(
                    f"evaluation metrics {metric_name} must match exhaustive case outcomes"
                )

        capability_by_id = _index_capabilities(
            self.capability_coverage,
            owner="capability_coverage",
        )
        if set(capability_by_id) != _MANDATORY_CAPABILITY_IDS:
            raise ValueError(
                "capability_coverage must exactly contain every mandatory built-in capability"
            )
        for capability_id, expected_capability in _DEFAULT_CAPABILITY_BY_ID.items():
            actual = capability_by_id[capability_id]
            if (
                actual.state is not GateState.not_evaluated
                or actual.reason != expected_capability.reason
            ):
                raise ValueError(
                    f"mandatory capability {capability_id!r} must retain its canonical "
                    "not_evaluated disclosure"
                )
        tool_capability = capability_by_id[_TOOL_ALLOWLIST_CAPABILITY_ID]
        expected_tool_reason = {
            GateState.pass_: _TOOL_ALLOWLIST_EVALUATED_REASON,
            GateState.not_evaluated: _TOOL_ALLOWLIST_NOT_EVALUATED_REASON,
        }.get(tool_capability.state)
        if expected_tool_reason is None or tool_capability.reason != expected_tool_reason:
            raise ValueError(
                "tool_allowlist capability must be canonically reported as pass or not_evaluated"
            )
        expected_tool_state = (
            GateState.pass_ if source_projection.tool_policy_configured else GateState.not_evaluated
        )
        if tool_capability.state is not expected_tool_state:
            raise ValueError(
                "tool_allowlist capability state must match persisted source policy coverage"
            )

        not_evaluated_by_id = _index_capabilities(
            self.not_evaluated_capabilities,
            owner="not_evaluated_capabilities",
        )
        if any(
            capability.state is not GateState.not_evaluated
            for capability in self.not_evaluated_capabilities
        ):
            raise ValueError("not_evaluated_capabilities may contain only not_evaluated states")
        expected_not_evaluated = {
            capability_id: capability
            for capability_id, capability in capability_by_id.items()
            if capability.state is GateState.not_evaluated
        }
        if not_evaluated_by_id != expected_not_evaluated:
            raise ValueError("not_evaluated_capabilities must exactly project capability_coverage")

        summary_findings = summary.findings
        if not summary_findings and summary.state is not GateState.pass_:
            raise ValueError("an evaluation summary without findings must have pass state")

        def findings_by_id(
            findings: tuple[Finding, ...],
            *,
            owner: str,
        ) -> dict[str, Finding]:
            indexed: dict[str, Finding] = {}
            for finding in findings:
                if finding.finding_id in indexed:
                    raise ValueError(
                        f"{owner} contains duplicate finding_id {finding.finding_id!r}"
                    )
                indexed[finding.finding_id] = finding
            return indexed

        summary_by_id = findings_by_id(summary_findings, owner="evaluation summary findings")
        findings_by_case: dict[str, list[Finding]] = {case_id: [] for case_id in outcomes_by_case}
        global_findings: list[Finding] = []
        unknown_case_findings: dict[str, Finding] = {}
        for finding in summary_findings:
            if finding.case_id in findings_by_case:
                findings_by_case[finding.case_id].append(finding)
                continue
            global_findings.append(finding)
            if finding.case_id != "*" and not _is_unknown_case_finding(finding):
                raise ValueError(
                    f"evaluation finding {finding.finding_id!r} has a case_id outside the "
                    "exhaustive case outcomes without a valid global scope"
                )
            if finding.case_id != "*":
                if finding.case_id in unknown_case_findings:
                    raise ValueError(
                        "evaluation findings contain duplicate unknown RunSet case scope "
                        f"{finding.case_id!r}"
                    )
                unknown_case_findings[finding.case_id] = finding

        if set(unknown_case_findings) != set(source_projection.unknown_run_case_ids):
            raise ValueError(
                "unknown-case findings must exactly match persisted unknown RunSet cases"
            )

        for case_id, outcome in outcomes_by_case.items():
            expected_state = _case_outcome_state(tuple(findings_by_case[case_id]))
            if outcome.state is not expected_state:
                raise ValueError(
                    f"evaluation case outcome {case_id!r} state must match its scoped findings"
                )

        expected_global_blocking_findings = sum(
            finding.state is GateState.fail for finding in global_findings
        )
        if metrics.global_blocking_findings != expected_global_blocking_findings:
            raise ValueError(
                "evaluation metrics global_blocking_findings must equal fail-state findings "
                "outside exhaustive case outcomes"
            )

        capability_findings: dict[str, Finding] = {}
        for finding in global_findings:
            if (
                finding.control_id not in _MANDATORY_CAPABILITY_IDS
                or finding.reason_code is not ReasonCode.NOT_EVALUATED
            ):
                continue
            if finding.control_id in capability_findings:
                raise ValueError(
                    f"global capability findings contain duplicate capability_id "
                    f"{finding.control_id!r}"
                )
            capability_findings[finding.control_id] = finding
        expected_capability_finding_ids = (
            set(not_evaluated_by_id) if replay_context.gate_profile.fail_on_not_evaluated else set()
        )
        if set(capability_findings) != expected_capability_finding_ids:
            raise ValueError(
                "global capability findings must match the replay gate profile and "
                "not_evaluated capability projection"
            )
        for capability_id, finding in capability_findings.items():
            capability = not_evaluated_by_id[capability_id]
            if (
                finding.case_id != "*"
                or finding.state is not GateState.fail
                or finding.target != capability_id
                or finding.message != capability.reason
            ):
                raise ValueError(
                    f"global capability finding {capability_id!r} must match its canonical "
                    "not_evaluated disclosure"
                )

        failed_by_id = findings_by_id(self.failed_controls, owner="failed_controls")
        warning_by_id = findings_by_id(self.warning_controls, owner="warning_controls")
        expected_failed = {
            finding.finding_id: finding
            for finding in summary_findings
            if finding.state is GateState.fail
        }
        expected_warnings = {
            finding.finding_id: finding
            for finding in summary_findings
            if finding.state is GateState.warn
        }
        if set(failed_by_id) != set(expected_failed):
            raise ValueError(
                "failed_controls must exactly project fail-state evaluation summary findings"
            )
        if set(warning_by_id) != set(expected_warnings):
            raise ValueError(
                "warning_controls must exactly project warn-state evaluation summary findings"
            )
        if any(finding.state is GateState.pass_ for finding in self.failed_controls):
            raise ValueError("failed_controls must not contain pass-state findings")
        if any(
            finding.state not in (GateState.fail, GateState.warn)
            for finding in self.warning_controls
        ):
            raise ValueError("warning_controls must contain only fail- or warn-state findings")

        for projection_name, projected, expected_projection in (
            ("failed_controls", failed_by_id, expected_failed),
            ("warning_controls", warning_by_id, expected_warnings),
        ):
            for finding_id, finding in projected.items():
                if finding.model_dump(mode="python", exclude={"state"}) != expected_projection[
                    finding_id
                ].model_dump(mode="python", exclude={"state"}):
                    raise ValueError(
                        f"{projection_name} finding {finding_id!r} must match its evaluation "
                        "summary finding"
                    )

        fail_findings = len(expected_failed)
        warn_findings = len(expected_warnings)
        not_evaluated_findings = sum(
            finding.state is GateState.not_evaluated for finding in summary_findings
        )
        if metrics.blocking_findings != fail_findings:
            raise ValueError(
                "evaluation metrics blocking_findings must equal fail-state summary findings"
            )
        if metrics.warning_findings != warn_findings + not_evaluated_findings:
            raise ValueError(
                "evaluation metrics warning_findings must equal warn- and not-evaluated-state "
                "summary findings"
            )
        if metrics.blocking_findings + metrics.warning_findings != len(summary_by_id):
            raise ValueError(
                "evaluation finding metrics must account for every evaluation summary finding"
            )

        findings_by_reason = dict(
            sorted(Counter(finding.reason_code.value for finding in summary_findings).items())
        )
        findings_by_control = dict(
            sorted(Counter(finding.control_id for finding in summary_findings).items())
        )
        if metrics.findings_by_reason != findings_by_reason:
            raise ValueError(
                "evaluation metrics findings_by_reason must match evaluation summary findings"
            )
        if metrics.findings_by_control != findings_by_control:
            raise ValueError(
                "evaluation metrics findings_by_control must match evaluation summary findings"
            )
        return self

    @model_validator(mode="after")
    def _validate_current_waiver_governance(self) -> EvaluationReport:
        if self.schema_version == SCHEMA_VERSION:
            for index, disposition in enumerate(self.waiver_dispositions):
                validate_current_waiver_governance(
                    disposition.owner,
                    disposition.reviewer,
                    disposition.rationale,
                    context=f"evaluation waiver disposition at index {index}",
                )
        return self

    @model_validator(mode="after")
    def _validate_current_waiver_evidence_coherence(self) -> EvaluationReport:
        """Reject ambiguous or non-replayable current waiver audit evidence."""

        if self.schema_version != SCHEMA_VERSION:
            return self

        dispositions_by_id: dict[str, WaiverDisposition] = {}
        for disposition in self.waiver_dispositions:
            if disposition.waiver_id in dispositions_by_id:
                raise ValueError(f"duplicate waiver disposition ID {disposition.waiver_id!r}")
            dispositions_by_id[disposition.waiver_id] = disposition

        effective_statuses = {
            WaiverDispositionStatus.matched,
            WaiverDispositionStatus.expired,
        }
        effective_dispositions = {
            waiver_id: disposition
            for waiver_id, disposition in dispositions_by_id.items()
            if disposition.status in effective_statuses
        }
        replay_context = self.candidate_vs_expectations.replay_context
        replay_waivers = () if replay_context is None else replay_context.waivers
        replay_by_id = {waiver.waiver_id: waiver for waiver in replay_waivers}
        if set(effective_dispositions) != set(replay_by_id):
            raise ValueError(
                "matched and expired waiver dispositions must exactly match replay-context "
                "waiver IDs"
            )

        for waiver_id, replay_waiver in replay_by_id.items():
            disposition = effective_dispositions[waiver_id]
            if replay_waiver.artifact_digest != self.runset_digest:
                raise ValueError(
                    f"replay waiver {waiver_id!r} artifact_digest must match report runset_digest"
                )
            if (
                replay_waiver.owner != disposition.owner
                or replay_waiver.reviewer != disposition.reviewer
                or replay_waiver.rationale != disposition.rationale
                or replay_waiver.reason_code is not disposition.reason_code
                or replay_waiver.finding_id != disposition.finding_id
                or replay_waiver.expires_on != disposition.expires_on
            ):
                raise ValueError(
                    f"replay waiver {waiver_id!r} does not match its report disposition"
                )
        return self


def _index_capabilities(
    capabilities: tuple[CapabilityReport, ...],
    *,
    owner: str,
) -> dict[str, CapabilityReport]:
    indexed: dict[str, CapabilityReport] = {}
    for capability in capabilities:
        if capability.capability_id in indexed:
            raise ValueError(
                f"{owner} contains duplicate capability_id {capability.capability_id!r}"
            )
        indexed[capability.capability_id] = capability
    return indexed


def _is_unevaluated_case_finding(finding: Finding) -> bool:
    return (
        finding.control_id == "valid_record_required"
        and finding.reason_code is ReasonCode.VALID_RECORD_MISSING
        and finding.target in {"missing", "duplicate-suite-case", "observation_status"}
    )


def _is_unknown_case_finding(finding: Finding) -> bool:
    return (
        finding.control_id == "valid_record_required"
        and finding.reason_code is ReasonCode.VALID_RECORD_MISSING
        and finding.target == "unknown-case"
    )


def _case_outcome_state(findings: tuple[Finding, ...]) -> GateState:
    if any(_is_unevaluated_case_finding(finding) for finding in findings):
        return GateState.not_evaluated
    if any(finding.state is GateState.fail for finding in findings):
        return GateState.fail
    if any(finding.state in (GateState.warn, GateState.not_evaluated) for finding in findings):
        return GateState.warn
    return GateState.pass_


def load_runset(
    path: Path,
    *,
    max_bytes: int = MAX_JOURNAL_BEARING_RUNSET_JSON_BYTES,
) -> RunSet:
    runset, _ = load_runset_with_size(path, max_bytes=max_bytes)
    return runset


def load_runset_with_size(
    path: Path,
    *,
    max_bytes: int = MAX_JOURNAL_BEARING_RUNSET_JSON_BYTES,
) -> tuple[RunSet, int]:
    # Imported lazily because schema export registration imports EvaluationReport
    # from this module while validation itself is initializing.
    from agent_assure.schema.validation import (
        load_validated_artifact_payload_with_size,
        project_validated_artifact_payload,
    )

    payload, size = load_validated_artifact_payload_with_size(
        path,
        "run-set",
        max_bytes=max_bytes,
        label="RunSet JSON",
    )
    return project_validated_artifact_payload(payload, RunSet, kind="run-set"), size


def runset_digest(runset: RunSet) -> str:
    return sha256_hexdigest(runset.model_dump(mode="json"))


def _evaluation_source_projection(
    suite: CompiledSuite,
    runset: RunSet,
) -> EvaluationSourceProjection:
    run_counts = Counter(run.case_id for run in runset.runs)
    singleton_runs = {run.case_id: run for run in runset.runs if run_counts[run.case_id] == 1}
    source_cases: list[EvaluationSourceCase] = []
    suite_case_ids = {case.case_id for case in suite.cases}
    for case in suite.cases:
        record_count = run_counts[case.case_id]
        if record_count == 0:
            status: Literal["included", "missing", "duplicate", "excluded"] = "missing"
        elif record_count > 1:
            status = "duplicate"
        elif singleton_runs[case.case_id].observation_status == "excluded":
            status = "excluded"
        else:
            status = "included"
        source_cases.append(
            EvaluationSourceCase(
                case_id=case.case_id,
                run_record_count=record_count,
                record_status=status,
            )
        )
    return EvaluationSourceProjection(
        suite_id=suite.suite_id,
        suite_version=suite.suite_version,
        suite_digest=compiled_suite_digest(suite),
        runset_id=runset.runset_id,
        runset_digest=runset_digest(runset),
        cases=tuple(source_cases),
        unknown_run_case_ids=tuple(sorted(set(run_counts) - suite_case_ids)),
        tool_policy_configured=_suite_has_tool_policy(suite),
    )


def verify_evaluation_report_sources(
    report: EvaluationReport,
    suite: CompiledSuite,
    runset: RunSet,
    *,
    gate_profile: GateProfile,
    waivers: tuple[Waiver, ...],
    evaluation_date: date,
) -> EvaluationSourceProjection:
    """Replay decision evidence against caller-authorized exact inputs.

    Standalone report validation proves only self-consistency. This API
    revalidates the caller-trusted suite, RunSet, gate profile, and complete
    waiver set; authenticates the source projection; and requires an exact
    evaluator replay for the caller-authorized evaluation date. Environment
    enrichment is excluded because it does not change the evaluation decision.

    The gate profile, waivers, and evaluation date are deliberately mandatory:
    accepting any of them from the untrusted report would let the report select
    the policy under which it is verified.
    """

    try:
        validated = EvaluationReport.model_validate(report.model_dump(mode="json"))
    except ValueError as exc:
        raise EvaluationSourceVerificationError(
            "evaluation report failed current semantic validation"
        ) from exc
    if validated.schema_version != SCHEMA_VERSION:
        raise EvaluationSourceVerificationError(
            "trusted source verification supports only the current evaluation-report schema"
        )
    replay_context = validated.candidate_vs_expectations.replay_context
    if replay_context is None:  # pragma: no cover - enforced by current report validation
        raise EvaluationSourceVerificationError(
            "current evaluation report is missing replay context"
        )
    if replay_context.report_mode != "full":
        raise EvaluationSourceVerificationError(
            "trusted source verification requires a full evaluation report"
        )
    try:
        trusted_suite = CompiledSuite.model_validate(suite.model_dump(mode="json"))
        trusted_runset = RunSet.model_validate(runset.model_dump(mode="json"))
        trusted_gate_profile = GateProfile.model_validate(gate_profile.model_dump(mode="json"))
        trusted_waivers = tuple(
            Waiver.model_validate(waiver.model_dump(mode="json")) for waiver in waivers
        )
        if type(evaluation_date) is not date:
            raise ValueError("evaluation_date must be a date")
        validate_runset_compatibility(trusted_suite, trusted_runset)
    except (AttributeError, RunSetCompatibilityError, TypeError, ValueError) as exc:
        diagnostic = (
            exc.diagnostic_code
            if isinstance(exc, RunSetCompatibilityError)
            else "source_model_invalid"
        )
        raise EvaluationSourceVerificationError(
            f"trusted evaluation sources are incompatible: {diagnostic}"
        ) from exc
    expected_source = _evaluation_source_projection(trusted_suite, trusted_runset)
    if validated.source_projection != expected_source:
        raise EvaluationSourceVerificationError(
            "evaluation source projection does not match the trusted suite and RunSet"
        )
    try:
        expected_report = evaluate_runset(
            trusted_suite,
            trusted_runset,
            gate_profile=trusted_gate_profile,
            waivers=trusted_waivers,
            today=evaluation_date,
        )
    except (RunSetCompatibilityError, TypeError, ValueError) as exc:
        raise EvaluationSourceVerificationError(
            "trusted-source evaluation replay could not be completed"
        ) from exc
    if _decision_evidence_projection(validated) != _decision_evidence_projection(expected_report):
        raise EvaluationSourceVerificationError(
            "evaluation decision evidence does not match trusted-source replay"
        )
    return expected_source


def _decision_evidence_projection(report: EvaluationReport) -> dict[str, object]:
    payload = report.model_dump(mode="json")
    payload.pop("environment", None)
    summary = payload.get("candidate_vs_expectations")
    if isinstance(summary, dict):
        summary.pop("environment", None)
    return payload


def evaluate_runset(
    suite: CompiledSuite,
    runset: RunSet,
    *,
    gate_profile: GateProfile = DEFAULT_GATE_PROFILE,
    waivers: tuple[Waiver, ...] = (),
    today: date | None = None,
) -> EvaluationReport:
    suite_payload = suite.model_dump(mode="json", warnings="error")
    suite = CompiledSuite.model_validate(suite_payload)
    validate_loaded_artifact_payload(suite_payload, "compiled-suite")
    runset_payload = runset.model_dump(mode="json", warnings="error")
    runset = RunSet.model_validate(runset_payload)
    validate_loaded_artifact_payload(runset_payload, "run-set")
    gate_profile = GateProfile.model_validate(
        gate_profile.model_dump(mode="json", warnings="error")
    )
    waivers = tuple(
        Waiver.model_validate(waiver.model_dump(mode="json", warnings="error"))
        for waiver in waivers
    )
    if suite.schema_version in V063_CONTRACT_SCHEMA_VERSIONS and not suite.cases:
        raise ValueError("current compiled suites require at least one case for evaluation")
    if runset.schema_version in V063_CONTRACT_SCHEMA_VERSIONS and not runset.runs:
        raise ValueError("current run sets require at least one run record for evaluation")
    validate_runset_compatibility(suite, runset)
    resolver = ExpectationResolver(suite)
    artifact_digest = runset_digest(runset)
    evaluation_date = today or date.today()
    raw_results = evaluate_runset_controls(
        resolver,
        runset,
        allowed_tools=suite.defaults.allowed_tools,
        required_policy_ids=suite.defaults.required_policy_ids,
    )
    waiver_application = apply_waivers_with_dispositions(
        raw_results,
        waivers=waivers,
        artifact_digest=artifact_digest,
        today=evaluation_date,
    )
    adjusted_results = waiver_application.results
    scoring_effective_waiver_ids = frozenset(
        disposition.waiver_id
        for disposition in waiver_application.dispositions
        if disposition.status in (WaiverDispositionStatus.matched, WaiverDispositionStatus.expired)
    )
    capability_coverage = _capabilities(
        DEFAULT_NOT_EVALUATED_CAPABILITIES,
        suite_has_tool_policy=_suite_has_tool_policy(suite),
    )
    capabilities = tuple(
        capability
        for capability in capability_coverage
        if capability.state is GateState.not_evaluated
    )
    capability_results = _capability_results(capabilities)
    rollup_results = adjusted_results
    if gate_profile.fail_on_not_evaluated:
        rollup_results = adjusted_results + capability_results
    report_findings = tuple(
        _finding_from_result(result, schema_version=SCHEMA_VERSION) for result in rollup_results
    )
    summary_findings = tuple(
        _finding_from_result(
            result,
            schema_version=SCHEMA_VERSION,
            state=(
                GateState.fail
                if gate_profile.is_blocking(result)
                else GateState.warn
                if result.state is GateState.fail
                else result.state
            ),
        )
        for result in rollup_results
    )
    state = rollup_state(rollup_results, gate_profile)
    usage_summary = usage_summary_for_runset(runset)
    summary = EvaluationSummary(
        artifact_kind="evaluation-summary",
        schema_version=SCHEMA_VERSION,
        runset_id=runset.runset_id,
        runset_digest=artifact_digest,
        privacy_profile_id=runset.privacy_profile_id or PRIVACY_PROFILE_ID,
        privacy_profile_digest=runset.privacy_profile_digest or PRIVACY_PROFILE_DIGEST,
        state=state,
        findings=summary_findings,
        network_authority_receipt=runset.network_authority_receipt,
        usage_summary=usage_summary,
        replay_context=EvaluationReplayContext(
            suite_digest=compiled_suite_digest(suite),
            gate_profile=EvaluationGateProfileContext(
                profile_id=gate_profile.profile_id,
                fail_severities=gate_profile.fail_severities,
                fail_reason_codes=gate_profile.fail_reason_codes,
                fail_on_warn=gate_profile.fail_on_warn,
                fail_on_not_evaluated=gate_profile.fail_on_not_evaluated,
            ),
            waivers=tuple(
                EvaluationWaiverContext(
                    waiver_id=waiver.waiver_id,
                    owner=waiver.owner,
                    reviewer=waiver.reviewer,
                    rationale=waiver.rationale,
                    reason_code=waiver.reason_code,
                    finding_id=waiver.finding_id,
                    artifact_digest=waiver.artifact_digest,
                    expires_on=waiver.expires_on,
                )
                for waiver in waivers
                if waiver.waiver_id in scoring_effective_waiver_ids
            ),
            evaluation_date=evaluation_date,
        ),
    )
    failed_controls = tuple(
        finding
        for result, finding in zip(rollup_results, report_findings, strict=True)
        if gate_profile.is_blocking(result)
    )
    warning_controls = tuple(
        finding
        for result, finding in zip(rollup_results, report_findings, strict=True)
        if _is_warning_control(result, gate_profile)
    )
    case_outcomes = _case_outcomes(suite, runset, rollup_results, gate_profile)
    source_projection = _evaluation_source_projection(suite, runset)
    return EvaluationReport(
        schema_version=SCHEMA_VERSION,
        candidate_vs_expectations=summary,
        runset_id=runset.runset_id,
        runset_digest=artifact_digest,
        suite_id=suite.suite_id,
        suite_version=suite.suite_version,
        gate_profile=gate_profile.profile_id,
        metrics=_metrics(
            suite,
            rollup_results,
            gate_profile,
            case_outcomes=case_outcomes,
        ),
        source_projection=source_projection,
        case_outcomes=case_outcomes,
        usage_summary=usage_summary,
        failed_controls=failed_controls,
        warning_controls=warning_controls,
        waiver_dispositions=waiver_application.dispositions,
        capability_coverage=capability_coverage,
        not_evaluated_capabilities=capabilities,
    )


def validate_runset_compatibility(suite: CompiledSuite, runset: RunSet) -> None:
    """Validate the bindings every evaluator must honor before scoring a RunSet.

    Mutation evaluators may replace the scoring implementation, but they may not
    bypass the suite, fixture-manifest, or privacy-profile trust bindings.
    """
    if runset.privacy_profile_id is not None and (
        runset.privacy_profile_id,
        runset.privacy_profile_digest,
    ) != (PRIVACY_PROFILE_ID, PRIVACY_PROFILE_DIGEST):
        raise RunSetCompatibilityError(
            "privacy_profile_incompatible",
            "run set privacy detector profile is incompatible with the runtime profile",
        )
    if runset.suite_id != suite.suite_id:
        raise RunSetCompatibilityError(
            "suite_binding_mismatch",
            (
                f"run set suite_id {runset.suite_id!r} does not match "
                f"compiled suite {suite.suite_id!r}"
            ),
        )
    if runset.suite_version != suite.suite_version:
        raise RunSetCompatibilityError(
            "suite_binding_mismatch",
            f"run set suite_version {runset.suite_version!r} does not match compiled suite "
            f"{suite.suite_version!r}",
        )
    expected_suite_digest = compiled_suite_digest(suite)
    if runset.suite_digest != expected_suite_digest:
        raise RunSetCompatibilityError(
            "suite_binding_mismatch",
            f"run set suite_digest {runset.suite_digest!r} does not match compiled suite digest "
            f"{expected_suite_digest!r}",
        )
    _verify_run_fixture_binding(runset)


def _finding_from_result(
    result: ControlResult,
    *,
    schema_version: SchemaVersion,
    state: GateState | None = None,
) -> Finding:
    return Finding(
        artifact_kind="finding",
        schema_version=schema_version,
        finding_id=result.finding_id,
        case_id=result.case_id,
        control_id=result.control_id,
        target=result.target,
        state=result.state if state is None else state,
        reason_code=result.reason_code,
        message=result.message,
    )


def _verify_run_fixture_binding(runset: RunSet) -> None:
    for run in runset.runs:
        run_digest = run.provenance.fixture_manifest_digest
        if run_digest != runset.fixture_manifest_digest:
            raise RunSetCompatibilityError(
                "fixture_binding_mismatch",
                f"run {run.run_id!r} fixture_manifest_digest {run_digest!r} does not match "
                f"run set fixture_manifest_digest {runset.fixture_manifest_digest!r}",
            )


def _metrics(
    suite: CompiledSuite,
    results: tuple[ControlResult, ...],
    gate_profile: GateProfile,
    *,
    case_outcomes: tuple[EvaluationCaseOutcome, ...],
) -> EvaluationMetrics:
    case_ids = {case.case_id for case in suite.cases}
    outcome_counts = Counter(outcome.state for outcome in case_outcomes)
    global_blocking_findings = sum(
        1
        for result in results
        if result.case_id not in case_ids and gate_profile.is_blocking(result)
    )
    findings_by_reason = Counter(result.reason_code.value for result in results)
    findings_by_control = Counter(result.control_id for result in results)
    return EvaluationMetrics(
        total_cases=len(case_outcomes),
        evaluated_cases=len(case_outcomes) - outcome_counts[GateState.not_evaluated],
        unevaluated_cases=outcome_counts[GateState.not_evaluated],
        passed_cases=outcome_counts[GateState.pass_],
        warning_cases=outcome_counts[GateState.warn],
        failed_cases=outcome_counts[GateState.fail],
        warning_findings=sum(
            1 for result in results if _counts_as_warning_metric(result, gate_profile)
        ),
        blocking_findings=sum(1 for result in results if gate_profile.is_blocking(result)),
        global_blocking_findings=global_blocking_findings,
        findings_by_reason=dict(sorted(findings_by_reason.items())),
        findings_by_control=dict(sorted(findings_by_control.items())),
    )


def _case_outcomes(
    suite: CompiledSuite,
    runset: RunSet,
    results: tuple[ControlResult, ...],
    gate_profile: GateProfile,
) -> tuple[EvaluationCaseOutcome, ...]:
    run_counts = Counter(run.case_id for run in runset.runs)
    included_case_ids = {
        run.case_id
        for run in runset.runs
        if run_counts[run.case_id] == 1 and run.observation_status != "excluded"
    }
    results_by_case: dict[str, list[ControlResult]] = {case.case_id: [] for case in suite.cases}
    for result in results:
        if result.case_id in results_by_case:
            results_by_case[result.case_id].append(result)

    outcomes: list[EvaluationCaseOutcome] = []
    for case in suite.cases:
        case_results = tuple(results_by_case[case.case_id])
        if case.case_id not in included_case_ids:
            state = GateState.not_evaluated
        elif any(gate_profile.is_blocking(result) for result in case_results):
            state = GateState.fail
        elif any(_counts_as_warning_metric(result, gate_profile) for result in case_results):
            state = GateState.warn
        else:
            state = GateState.pass_
        outcomes.append(EvaluationCaseOutcome(case_id=case.case_id, state=state))
    return tuple(outcomes)


def _is_warning_control(result: ControlResult, gate_profile: GateProfile) -> bool:
    if result.state is GateState.warn:
        return True
    return result.state is GateState.fail and not gate_profile.is_blocking(result)


def _counts_as_warning_metric(result: ControlResult, gate_profile: GateProfile) -> bool:
    """Classify advisory case findings without changing report projections.

    ``warning_controls`` is a gate-effect projection consumed by mutation
    detection: nonblocking ``not_evaluated`` findings remain outside both the
    failed and warning projections. Metrics still classify an evaluated case
    with such a finding as warning rather than cleanly passed.
    """

    return _is_warning_control(result, gate_profile) or (
        result.state is GateState.not_evaluated and not gate_profile.is_blocking(result)
    )


def _capabilities(
    capabilities: tuple[CapabilityStatus, ...],
    *,
    suite_has_tool_policy: bool,
) -> tuple[CapabilityReport, ...]:
    reports = [
        CapabilityReport(
            capability_id=capability.capability_id,
            state=capability.state,
            reason=capability.reason,
        )
        for capability in capabilities
    ]
    reports.append(
        CapabilityReport(
            capability_id=_TOOL_ALLOWLIST_CAPABILITY_ID,
            state=GateState.pass_ if suite_has_tool_policy else GateState.not_evaluated,
            reason=(
                _TOOL_ALLOWLIST_EVALUATED_REASON
                if suite_has_tool_policy
                else _TOOL_ALLOWLIST_NOT_EVALUATED_REASON
            ),
        )
    )
    return tuple(reports)


def _suite_has_tool_policy(suite: CompiledSuite) -> bool:
    if suite.defaults.allowed_tools:
        return True
    return any(
        expectation.allowed_tools_override
        or bool(expectation.allowed_tools)
        or bool(expectation.forbidden_tools)
        for expectation in suite.resolved_expectations
    )


def _capability_results(
    capabilities: tuple[CapabilityReport, ...],
) -> tuple[ControlResult, ...]:
    return tuple(
        ControlResult(
            control_id=capability.capability_id,
            case_id="*",
            state=capability.state,
            reason_code=ReasonCode.NOT_EVALUATED,
            severity=Severity.info,
            target=capability.capability_id,
            message=capability.reason,
        )
        for capability in capabilities
        if capability.state is GateState.not_evaluated
    )


def reason_code_counts(summary: EvaluationSummary) -> dict[ReasonCode, int]:
    return dict(Counter(finding.reason_code for finding in summary.findings))
