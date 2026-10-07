from __future__ import annotations

from collections.abc import Mapping
from decimal import ROUND_CEILING, ROUND_FLOOR, Decimal, InvalidOperation
from typing import Any, Literal, get_args

from pydantic import ConfigDict, Field, model_validator
from pydantic.functional_validators import field_validator

from agent_assure._decimal_context import with_live_decimal_context
from agent_assure.fixed_point import usd_six_from_picousd
from agent_assure.io_limits import MAX_PERSISTED_OBSERVATIONS
from agent_assure.live.source_projection import BUDGET_STOP_REASONS
from agent_assure.live.work_limits import (
    LIVE_ICC_BOOTSTRAP_ITERATIONS,
    LIVE_MAX_EXACT_PERMUTATION_CLUSTERS,
    LIVE_MONTE_CARLO_ITERATIONS,
    MAX_LIVE_ADVANCED_ENDPOINTS,
    MAX_LIVE_MONITORING_ITEMS,
    MAX_LIVE_OUTCOME_CATEGORIES,
    validate_live_protocol_resampling_work,
)
from agent_assure.schema.base import SCHEMA_VERSION, PersistedArtifact
from agent_assure.schema.common import (
    MACHINE_IDENTIFIER_MAX_CHARS,
    MACHINE_IDENTIFIER_PATTERN,
    MAX_LABEL_CHARS,
    PROVIDER_MODEL_IDENTIFIER_PATTERN,
    UNIT_INTERVAL_6_PATTERN,
    V063_CONTRACT_SCHEMA_VERSIONS,
    DigestHex,
    Fraction6String,
    GateState,
    NonnegativeDecimal6String,
    ReasonCode,
    SignedDecimal6String,
    SignedUnitInterval6String,
    UnitInterval6String,
    coerce_enum,
    coerce_tuple,
    decimal_string,
    validate_machine_identifier,
    validate_provider_model_identifier,
)
from agent_assure.schema.evaluation import Finding
from agent_assure.statistics.binomial_intervals import (
    BERNOULLI_KL_CHERNOFF_UPPER_BOUND_METHOD,
    MAX_CLOPPER_PEARSON_TRIALS,
    MAX_SCALABLE_BINOMIAL_TRIALS,
    ZERO_EVENT_CLOSED_FORM_METHOD,
    binomial_upper_bound_one_sided,
    validate_clopper_pearson_work_budget,
)

DecimalString = NonnegativeDecimal6String
SignedDecimalString = SignedDecimal6String
# The current protocol records statistical and safety constraints but does not
# yet bind the complete arm configuration and prompt manifest before execution.
LIVE_PROTOCOL_BINDS_EXECUTION_CONFIGURATION = False
LIVE_COMPARISON_SOURCE_LINKAGE_LIMITATION = (
    "source-evaluation digests are external linkage; latency and cost absolutes remain "
    "source-declarative until both digests are resolved against trusted evaluation reports"
)
LIVE_DRIFT_SOURCE_LINKAGE_LIMITATION = (
    "source-evaluation digests are external linkage; source truth requires resolving the "
    "ordered evaluation reports and running trusted-source reconciliation"
)
LIVE_TRAJECTORY_SOURCE_LINKAGE_LIMITATION = (
    "source RunSet and evaluation digests are external linkage; source truth requires "
    "resolving both artifacts and running trusted-source reconciliation"
)
CLAIM_EVIDENCE_UNOBSERVABLE_PATH_LIMITATION = (
    "claim-evidence control fields are not fully observable; completeness is unknown"
)
CLAIM_EVIDENCE_UNOBSERVABLE_INVARIANT_LIMITATION = (
    "one or more applicable approvals have unobservable claim-evidence controls; "
    "the invariant cannot establish completeness"
)
LIVE_TRAJECTORY_CLAIM_EVIDENCE_UNOBSERVABLE_LIMITATION = (
    "one or more approval paths have unobservable claim-evidence controls; evidence "
    "completeness is unknown and requires review"
)
_V06_BINDING_SCHEMA_VERSIONS = frozenset(
    {"0.6.0", "0.6.1", "0.6.2", "0.6.3", "0.6.4", "0.6.5", "0.6.6"}
)
_BOUNDED_PROVIDER_METADATA_SCHEMA_VERSION = "0.6.6"
_RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION = "0.6.6"
_BONFERRONI_FLOOR_SCHEMA_VERSION = "0.6.6"
_CURRENT_RARE_EVENT_ANALYSIS_METHOD = "clopper_pearson_exact_one_sided"
_LEGACY_RARE_EVENT_ANALYSIS_METHOD = "poisson_upper_bound"
_RARE_EVENT_ANALYSIS_METHODS = frozenset(
    {_CURRENT_RARE_EVENT_ANALYSIS_METHOD, _LEGACY_RARE_EVENT_ANALYSIS_METHOD}
)
_CURRENT_RARE_EVENT_RESULT_METHODS = frozenset(
    {
        _CURRENT_RARE_EVENT_ANALYSIS_METHOD,
        ZERO_EVENT_CLOSED_FORM_METHOD,
        BERNOULLI_KL_CHERNOFF_UPPER_BOUND_METHOD,
    }
)
_RARE_EVENT_ENDPOINT_KINDS = frozenset(
    {"critical_event_rate", "reason_code_rate", "exclusion_rate"}
)
_PAIRED_RANDOMIZATION_METHODS = frozenset(
    {"paired_cluster_permutation_exact", "paired_cluster_permutation_monte_carlo"}
)
_CURRENT_FIXED_REFERENCE_COMPARISON_METHODS = frozenset(
    {"fixed_reference_cluster_t_interval", "exploratory"}
)
_CURRENT_CONCURRENT_COMPARISON_METHODS = frozenset(
    {
        "paired_cluster_t_interval",
        "paired_cluster_bootstrap_percentile",
        *_PAIRED_RANDOMIZATION_METHODS,
        "exploratory",
    }
)
_CURRENT_ICC_BOOTSTRAP_ITERATIONS = LIVE_ICC_BOOTSTRAP_ITERATIONS
_CURRENT_MONTE_CARLO_RESAMPLES = LIVE_MONTE_CARLO_ITERATIONS + 1
_CURRENT_MAX_EXACT_PERMUTATION_CLUSTERS = LIVE_MAX_EXACT_PERMUTATION_CLUSTERS
_PERSISTED_PROBABILITY_SCALE = 1_000_000
_MACHINE_IDENTIFIER_JSON_SCHEMA_PATTERN = MACHINE_IDENTIFIER_PATTERN.removesuffix("$") + (
    r"(?![\s\S])"
)
_PROVIDER_MODEL_IDENTIFIER_JSON_SCHEMA_PATTERN = (
    PROVIDER_MODEL_IDENTIFIER_PATTERN.removesuffix("$") + r"(?![\s\S])"
)
_PROVIDER_MODEL_METADATA_FIELDS = frozenset({"model", "resolved_model"})
_LIVE_OBSERVATION_PROVIDER_METADATA_FIELDS = (
    "provider",
    "model",
    "resolved_model",
    "provider_api_version",
    "provider_sdk",
    "provider_region",
    "adapter_id",
)
_LIVE_GROUP_PROVIDER_METADATA_FIELDS = ("provider", "model", "adapter_id")


def _legacy_rare_event_method_rejection_schema() -> dict[str, Any]:
    return {
        "not": {
            "required": ["analysis_method"],
            "properties": {"analysis_method": {"const": _LEGACY_RARE_EVENT_ANALYSIS_METHOD}},
        }
    }


def _machine_identifier_field_schemas(
    fields: tuple[str, ...],
) -> dict[str, dict[str, Any]]:
    return {
        field_name: {
            "anyOf": [
                {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": MACHINE_IDENTIFIER_MAX_CHARS,
                    "pattern": (
                        _PROVIDER_MODEL_IDENTIFIER_JSON_SCHEMA_PATTERN
                        if field_name in _PROVIDER_MODEL_METADATA_FIELDS
                        else _MACHINE_IDENTIFIER_JSON_SCHEMA_PATTERN
                    ),
                },
                {"type": "null"},
            ]
        }
        for field_name in fields
    }


def _validate_provider_metadata_identifier(
    value: str,
    *,
    metadata_field: str,
    field_name: str,
) -> None:
    if metadata_field in _PROVIDER_MODEL_METADATA_FIELDS:
        validate_provider_model_identifier(value, field_name=field_name)
    else:
        validate_machine_identifier(value, field_name=field_name)


def _require_non_null_schema_fields(
    schema: dict[str, Any],
    fields: tuple[str, ...],
) -> None:
    current_contract = {
        "if": {
            "properties": {
                "schema_version": {
                    "enum": sorted(_V06_BINDING_SCHEMA_VERSIONS),
                },
            }
        },
        "then": {
            "properties": {field_name: {"not": {"type": "null"}} for field_name in fields},
            "required": list(fields),
        },
    }
    existing = schema.setdefault("allOf", [])
    if isinstance(existing, list):
        existing.append(current_contract)


def _require_current_unique_items(
    schema: dict[str, Any],
    fields: tuple[str, ...],
) -> None:
    current_contract = {
        "if": {
            "properties": {
                "schema_version": {
                    "const": _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION,
                },
            },
        },
        "then": {
            "properties": {field_name: {"uniqueItems": True} for field_name in fields},
        },
    }
    existing = schema.setdefault("allOf", [])
    if isinstance(existing, list):
        existing.append(current_contract)


def _require_current_machine_identifier_fields(
    schema: dict[str, Any],
    fields: tuple[str, ...],
) -> None:
    current_contract = {
        "if": {
            "properties": {
                "schema_version": {"const": _BOUNDED_PROVIDER_METADATA_SCHEMA_VERSION},
            },
        },
        "then": {
            "properties": _machine_identifier_field_schemas(fields),
        },
    }
    existing = schema.setdefault("allOf", [])
    if isinstance(existing, list):
        existing.append(current_contract)


def _live_observation_schema_extra(schema: dict[str, Any]) -> None:
    _require_non_null_schema_fields(
        schema,
        ("prompt_digest", "randomization_block_id", "schedule_index"),
    )
    _require_current_machine_identifier_fields(
        schema,
        _LIVE_OBSERVATION_PROVIDER_METADATA_FIELDS,
    )


def _live_group_schema_extra(schema: dict[str, Any]) -> None:
    _require_current_machine_identifier_fields(
        schema,
        _LIVE_GROUP_PROVIDER_METADATA_FIELDS,
    )


def _statistical_endpoint_plan_schema_extra(schema: dict[str, Any]) -> None:
    _require_current_unique_items(schema, ("reason_codes",))
    current_contract = {
        "if": {
            "required": ["analysis_method"],
            "properties": {
                "schema_version": {"const": _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION},
                "analysis_method": {"const": _CURRENT_RARE_EVENT_ANALYSIS_METHOD},
            },
        },
        "then": {
            "required": ["exposure_unit"],
            "properties": {"exposure_unit": {"const": "independence_cluster"}},
        },
    }
    existing = schema.setdefault("allOf", [])
    if isinstance(existing, list):
        existing.append(current_contract)
        existing.append(
            {
                "if": {
                    "properties": {
                        "schema_version": {"const": _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION}
                    }
                },
                "then": _legacy_rare_event_method_rejection_schema(),
            }
        )


def _advanced_analysis_plan_schema_extra(schema: dict[str, Any]) -> None:
    schema["$comment"] = (
        "For schema_version 0.6.6 (including the model default when omitted), the runtime "
        "model rejects a Bonferroni-adjusted alpha below the persisted six-decimal "
        "precision using ROUND_FLOOR and requires independence-cluster exposure for every "
        "embedded exact-binomial endpoint, including endpoints with historical schema labels. "
        "Released 0.6.5 parent artifacts retain their historical behavior. JSON Schema can "
        "express the exposure constraint and reject a zero familywise alpha, but Draft "
        "2020-12 cannot express division by the number of confirmatory endpoints; consumers "
        "must also run model validation for that relational constraint."
    )
    current_contract = {
        "if": {
            "required": ["multiplicity_method"],
            "properties": {
                "schema_version": {"const": _BONFERRONI_FLOOR_SCHEMA_VERSION},
                "multiplicity_method": {"const": "bonferroni"},
            },
        },
        "then": {
            "properties": {
                "familywise_alpha": {"not": {"const": "0.000000"}},
            },
        },
    }
    existing = schema.setdefault("allOf", [])
    if isinstance(existing, list):
        existing.append(current_contract)
        existing.append(
            {
                "if": {
                    "properties": {
                        "schema_version": {"const": _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION},
                    },
                },
                "then": {
                    "properties": {
                        "endpoints": {
                            "items": {
                                "if": {
                                    "required": ["analysis_method"],
                                    "properties": {
                                        "analysis_method": {
                                            "const": _CURRENT_RARE_EVENT_ANALYSIS_METHOD
                                        }
                                    },
                                },
                                "then": {
                                    "required": ["exposure_unit"],
                                    "properties": {
                                        "exposure_unit": {"const": "independence_cluster"}
                                    },
                                },
                            },
                        },
                    },
                },
            }
        )
        existing.append(
            {
                "if": {
                    "properties": {
                        "schema_version": {"const": _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION}
                    }
                },
                "then": {
                    "properties": {
                        "endpoints": {"items": _legacy_rare_event_method_rejection_schema()}
                    }
                },
            }
        )


def _rare_event_upper_bound_schema_extra(schema: dict[str, Any]) -> None:
    current_contract = {
        "if": {
            "properties": {"schema_version": {"const": _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION}}
        },
        "then": {
            "properties": {
                "analysis_method": {"enum": sorted(_CURRENT_RARE_EVENT_RESULT_METHODS)},
                "event_rate": {"pattern": UNIT_INTERVAL_6_PATTERN},
                "upper_rate_bound": {"pattern": UNIT_INTERVAL_6_PATTERN},
            }
        },
        "else": {
            "properties": {
                "analysis_method": {
                    "enum": [
                        _CURRENT_RARE_EVENT_ANALYSIS_METHOD,
                        _LEGACY_RARE_EVENT_ANALYSIS_METHOD,
                    ]
                }
            }
        },
    }
    existing = schema.setdefault("allOf", [])
    if isinstance(existing, list):
        existing.append(current_contract)


def _live_evaluation_schema_extra(schema: dict[str, Any]) -> None:
    _require_non_null_schema_fields(
        schema,
        ("configuration_digest", "suite_digest"),
    )
    schema["$comment"] = (
        "For current live evaluation reports, the source RunSet digest, source completion "
        "status, bound protocol, and observation outcome sufficient statistics are required. "
        "Embedded observations must also carry pairing identity, and provider metadata in "
        "embedded observations and group summaries must satisfy the current machine-identifier "
        "grammar, even when an embedded artifact retains a historical schema label. Historical "
        "parent reports retain their released nested-observation contract. Relational and "
        "statistical derivation constraints require runtime model validation."
    )
    current_parent_contract = {
        "if": {
            "properties": {
                "schema_version": {"const": _BOUNDED_PROVIDER_METADATA_SCHEMA_VERSION},
            },
        },
        "then": {
            "required": [
                "source_runset_digest",
                "source_completion_status",
                "protocol",
            ],
            "allOf": [
                {
                    "if": {
                        "required": ["observations"],
                        "properties": {
                            "observations": {
                                "contains": {
                                    "required": ["exclusion_reason"],
                                    "properties": {
                                        "exclusion_reason": {"const": reason},
                                    },
                                },
                                "minContains": 1,
                            },
                        },
                    },
                    "then": {
                        "required": ["stop_reasons"],
                        "properties": {
                            "stop_reasons": {
                                "contains": {"const": reason},
                                "minContains": 1,
                            },
                        },
                    },
                }
                for reason in sorted(BUDGET_STOP_REASONS)
            ],
            "properties": {
                "source_runset_digest": {"not": {"type": "null"}},
                "source_completion_status": {"not": {"type": "null"}},
                "protocol": {
                    "not": {"type": "null"},
                    "properties": {
                        "schema_version": {
                            "const": _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION,
                        },
                    },
                },
                "stop_reasons": {"uniqueItems": True},
                "observations": {
                    "items": {
                        "required": [
                            "outcome",
                            "prompt_digest",
                            "randomization_block_id",
                            "schedule_index",
                        ],
                        "properties": {
                            **_machine_identifier_field_schemas(
                                _LIVE_OBSERVATION_PROVIDER_METADATA_FIELDS
                            ),
                            "outcome": {"not": {"type": "null"}},
                            "prompt_digest": {"not": {"type": "null"}},
                            "randomization_block_id": {"not": {"type": "null"}},
                            "schedule_index": {"not": {"type": "null"}},
                        },
                    },
                },
                "overall": {
                    "properties": _machine_identifier_field_schemas(
                        _LIVE_GROUP_PROVIDER_METADATA_FIELDS
                    ),
                },
                "groups": {
                    "items": {
                        "properties": _machine_identifier_field_schemas(
                            _LIVE_GROUP_PROVIDER_METADATA_FIELDS
                        ),
                    },
                },
                "statistical_invariants": {
                    "items": {
                        "properties": {
                            "rare_event_bound": {
                                "if": {"type": "object"},
                                "then": {
                                    "properties": {
                                        "analysis_method": {
                                            "enum": sorted(_CURRENT_RARE_EVENT_RESULT_METHODS)
                                        },
                                        "event_rate": {"pattern": UNIT_INTERVAL_6_PATTERN},
                                        "upper_rate_bound": {"pattern": UNIT_INTERVAL_6_PATTERN},
                                    }
                                },
                            }
                        }
                    }
                },
            },
        },
    }
    existing = schema.setdefault("allOf", [])
    if isinstance(existing, list):
        existing.append(current_parent_contract)


def _live_comparison_schema_extra(schema: dict[str, Any]) -> None:
    properties = schema.get("properties")
    if isinstance(properties, dict):
        limitations_schema = properties.get("limitations")
        if isinstance(limitations_schema, dict):
            limitations_schema.pop("default", None)
    schema["$comment"] = (
        "Current live comparisons require source-evaluation digests and statuses, a bound "
        "protocol, and the named derivation contract. JSON Schema enforces the required bindings "
        "and exactly one mandatory source-linkage limitation; runtime model validation rederives "
        "the complete exact limitation set, statistics, inference, and gate state."
    )
    current_contract = {
        "if": {
            "properties": {
                "schema_version": {"const": _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION},
            },
        },
        "then": {
            "required": [
                "derivation_contract",
                "baseline_evaluation_digest",
                "candidate_evaluation_digest",
                "baseline_completion_status",
                "candidate_completion_status",
                "protocol",
                "limitations",
            ],
            "properties": {
                "derivation_contract": {"const": "agent-assure/live-comparison/v1"},
                "baseline_evaluation_digest": {"not": {"type": "null"}},
                "candidate_evaluation_digest": {"not": {"type": "null"}},
                "baseline_completion_status": {"not": {"type": "null"}},
                "candidate_completion_status": {"not": {"type": "null"}},
                "protocol": {
                    "not": {"type": "null"},
                    "properties": {
                        "schema_version": {
                            "const": _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION,
                        },
                    },
                },
                "baseline_pass_rate": {
                    "properties": {
                        "schema_version": {
                            "const": _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION,
                        },
                    },
                },
                "candidate_pass_rate": {
                    "properties": {
                        "schema_version": {
                            "const": _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION,
                        },
                    },
                },
                "paired_clusters": {
                    "items": {
                        "required": [
                            "baseline_numerator",
                            "baseline_denominator",
                            "candidate_numerator",
                            "candidate_denominator",
                        ],
                        "properties": {
                            "schema_version": {
                                "const": _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION,
                            },
                            "baseline_numerator": {"type": "integer", "minimum": 0},
                            "baseline_denominator": {"type": "integer", "minimum": 0},
                            "candidate_numerator": {"type": "integer", "minimum": 0},
                            "candidate_denominator": {"type": "integer", "minimum": 0},
                        },
                    },
                },
                "randomization_tests": {
                    "items": {
                        "properties": {
                            "schema_version": {
                                "const": _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION,
                            },
                        },
                    },
                },
                "limitations": {
                    "contains": {"const": LIVE_COMPARISON_SOURCE_LINKAGE_LIMITATION},
                    "minContains": 1,
                    "maxContains": 1,
                },
            },
        },
    }
    existing = schema.setdefault("allOf", [])
    if isinstance(existing, list):
        existing.append(current_contract)


def _live_drift_schema_extra(schema: dict[str, Any]) -> None:
    schema["$comment"] = (
        "Current live drift reports require ordered source-evaluation digests, a bound "
        "current protocol, the effective drift plan, and the named derivation contract. "
        "Runtime validation exactly replays all conclusions from the persisted window "
        "projection. Source truth additionally requires trusted-source reconciliation."
    )
    current_contract = {
        "if": {
            "properties": {
                "schema_version": {"const": _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION},
            },
        },
        "then": {
            "required": [
                "derivation_contract",
                "source_evaluation_digests",
                "protocol",
                "drift_plan",
                "limitations",
            ],
            "properties": {
                "derivation_contract": {"const": _LIVE_DRIFT_DERIVATION_CONTRACT},
                "source_evaluation_digests": {"minItems": 1},
                "ordering_variable": {
                    "enum": ["window_index", "window_start_utc"],
                },
                "protocol": {
                    "not": {"type": "null"},
                    "properties": {
                        "schema_version": {
                            "const": _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION,
                        },
                    },
                },
                "drift_plan": {
                    "not": {"type": "null"},
                    "properties": {
                        "schema_version": {
                            "const": _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION,
                        },
                        "metrics": {
                            "minItems": 1,
                            "items": {
                                "required": ["analysis_methods"],
                                "properties": {
                                    "schema_version": {
                                        "const": _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION,
                                    },
                                },
                            },
                        },
                    },
                },
                "comparability": {
                    "properties": {
                        "schema_version": {
                            "const": _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION,
                        },
                    },
                },
                "windows": {
                    "minItems": 1,
                    "items": {
                        "required": [
                            "source_runset_completion_status",
                            "source_evaluation_completion_status",
                            "source_evaluation_exploratory",
                        ],
                        "properties": {
                            "schema_version": {
                                "const": _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION,
                            },
                            "source_runset_completion_status": {
                                "not": {"type": "null"},
                            },
                            "source_evaluation_completion_status": {
                                "not": {"type": "null"},
                            },
                            "source_evaluation_exploratory": {
                                "type": "boolean",
                            },
                            "metrics": {
                                "items": {
                                    "properties": {
                                        "schema_version": {
                                            "const": (_RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION),
                                        },
                                    },
                                },
                            },
                        },
                        "allOf": [
                            {
                                "if": {
                                    "properties": {
                                        "source_evaluation_completion_status": {
                                            "const": "complete"
                                        },
                                    }
                                },
                                "then": {
                                    "properties": {
                                        "source_runset_completion_status": {"const": "complete"},
                                    }
                                },
                            }
                        ],
                    },
                },
                "diagnostics": {
                    "minItems": 1,
                    "items": {
                        "properties": {
                            "schema_version": {
                                "const": _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION,
                            },
                            "state_estimate": {
                                "if": {"type": "object"},
                                "then": {
                                    "properties": {
                                        "schema_version": {
                                            "const": (_RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION),
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
                "limitations": {
                    "contains": {"const": LIVE_DRIFT_SOURCE_LINKAGE_LIMITATION},
                    "minContains": 1,
                    "maxContains": 1,
                },
            },
            "allOf": [
                {
                    "if": {"properties": {"monitoring_status": {"const": "valid"}}},
                    "then": {
                        "properties": {
                            "windows": {
                                "items": {
                                    "properties": {
                                        "source_runset_completion_status": {"const": "complete"},
                                        "source_evaluation_completion_status": {
                                            "const": "complete"
                                        },
                                        "source_evaluation_exploratory": {"const": False},
                                    }
                                }
                            }
                        }
                    },
                }
            ],
        },
    }
    existing = schema.setdefault("allOf", [])
    if isinstance(existing, list):
        existing.append(current_contract)


def _live_trajectory_schema_extra(schema: dict[str, Any]) -> None:
    schema["$comment"] = (
        "Current live trajectory reports require source RunSet and evaluation digests, "
        "a bound current protocol, the effective trajectory plan, the named derivation "
        "contract, an explicit operational-event projection, and applicability-aware "
        "claim-evidence status. Runtime validation exactly replays all conclusions. Source truth "
        "additionally requires trusted-source reconciliation."
    )
    current_contract = {
        "if": {
            "properties": {
                "schema_version": {"const": _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION},
            },
        },
        "then": {
            "required": [
                "derivation_contract",
                "source_runset_digest",
                "source_evaluation_digest",
                "source_runset_completion_status",
                "source_evaluation_completion_status",
                "source_evaluation_stop_reasons",
                "source_evaluation_exploratory",
                "protocol",
                "trajectory_plan",
                "operational_events",
                "limitations",
            ],
            "properties": {
                "derivation_contract": {"const": _LIVE_TRAJECTORY_DERIVATION_CONTRACT},
                "source_runset_digest": {"not": {"type": "null"}},
                "source_evaluation_digest": {"not": {"type": "null"}},
                "source_runset_completion_status": {"not": {"type": "null"}},
                "source_evaluation_completion_status": {"not": {"type": "null"}},
                "source_evaluation_stop_reasons": {
                    "not": {"type": "null"},
                    "uniqueItems": True,
                },
                "source_evaluation_exploratory": {"type": "boolean"},
                "protocol": {
                    "not": {"type": "null"},
                    "properties": {
                        "schema_version": {
                            "const": _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION,
                        },
                    },
                },
                "trajectory_plan": {
                    "not": {"type": "null"},
                    "required": ["analysis_methods"],
                    "properties": {
                        "schema_version": {
                            "const": _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION,
                        },
                        "invariants": {
                            "items": {
                                "properties": {
                                    "schema_version": {
                                        "const": _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION,
                                    },
                                },
                            },
                        },
                    },
                },
                "paths": {
                    "items": {
                        "required": [
                            "approval_outcome",
                            "claim_evidence_complete",
                            "claim_evidence_status",
                            "attempt_count",
                            "retry_count",
                            "rate_limit_event_count",
                            "runtime_failed",
                            "malformed_output",
                        ],
                        "properties": {
                            "schema_version": {
                                "const": _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION,
                            },
                        },
                    },
                },
                "transitions": {
                    "items": {
                        "properties": {
                            "schema_version": {
                                "const": _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION,
                            },
                        },
                    },
                },
                "invariants": {
                    "items": {
                        "required": [
                            "unobservable_observations",
                            "unobservable_observation_ids",
                        ],
                        "properties": {
                            "schema_version": {
                                "const": _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION,
                            },
                        },
                    },
                },
                "history_dependent_checks": {
                    "items": {
                        "properties": {
                            "schema_version": {
                                "const": _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION,
                            },
                        },
                    },
                },
                "operational_events": {
                    "items": {
                        "properties": {
                            "schema_version": {
                                "const": _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION,
                            },
                        },
                    },
                },
                "event_processes": {
                    "items": {
                        "properties": {
                            "schema_version": {
                                "const": _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION,
                            },
                        },
                    },
                },
                "limitations": {
                    "contains": {"const": LIVE_TRAJECTORY_SOURCE_LINKAGE_LIMITATION},
                    "minContains": 1,
                    "maxContains": 1,
                },
            },
            "allOf": [
                {
                    "if": {
                        "properties": {
                            "source_runset_completion_status": {"const": "incomplete"},
                        }
                    },
                    "then": {
                        "properties": {
                            "source_evaluation_completion_status": {"const": "incomplete"},
                        }
                    },
                },
                {
                    "if": {
                        "properties": {
                            "source_evaluation_stop_reasons": {"minItems": 1},
                        }
                    },
                    "then": {
                        "properties": {
                            "source_evaluation_completion_status": {"const": "incomplete"},
                        }
                    },
                },
                {
                    "if": {
                        "properties": {
                            "source_runset_completion_status": {"const": "complete"},
                            "source_evaluation_stop_reasons": {"maxItems": 0},
                        }
                    },
                    "then": {
                        "properties": {
                            "source_evaluation_completion_status": {"const": "complete"},
                        }
                    },
                },
                {
                    "if": {"properties": {"trajectory_status": {"const": "valid"}}},
                    "then": {
                        "properties": {
                            "source_runset_completion_status": {"const": "complete"},
                            "source_evaluation_completion_status": {"const": "complete"},
                            "source_evaluation_exploratory": {"const": False},
                        }
                    },
                },
                {
                    "if": {
                        "required": ["paths"],
                        "properties": {
                            "paths": {
                                "contains": {
                                    "required": ["claim_evidence_status"],
                                    "properties": {
                                        "claim_evidence_status": {
                                            "const": "unobservable",
                                        },
                                    },
                                },
                            },
                        },
                    },
                    "then": {
                        "properties": {
                            "limitations": {
                                "contains": {
                                    "const": (
                                        LIVE_TRAJECTORY_CLAIM_EVIDENCE_UNOBSERVABLE_LIMITATION
                                    ),
                                },
                            },
                        },
                    },
                },
                {
                    "if": {
                        "properties": {
                            "trajectory_plan": {
                                "properties": {
                                    "analysis_methods": {
                                        "contains": {"const": "sequence_invariant_check"},
                                        "minContains": 1,
                                    }
                                }
                            }
                        }
                    },
                    "then": {
                        "properties": {
                            "history_dependent_checks": {
                                "minItems": len(_TRAJECTORY_HISTORY_CHECK_IDS),
                                "maxItems": len(_TRAJECTORY_HISTORY_CHECK_IDS),
                            }
                        }
                    },
                    "else": {
                        "properties": {
                            "invariants": {"maxItems": 0},
                            "history_dependent_checks": {"maxItems": 0},
                        }
                    },
                },
                {
                    "if": {
                        "properties": {
                            "trajectory_plan": {
                                "properties": {
                                    "analysis_methods": {
                                        "contains": {"const": "event_process_summary"},
                                        "minContains": 1,
                                    }
                                }
                            }
                        }
                    },
                    "then": {
                        "properties": {
                            "event_processes": {
                                "minItems": len(_TRAJECTORY_OPERATIONAL_EVENT_TYPES),
                                "maxItems": len(_TRAJECTORY_OPERATIONAL_EVENT_TYPES),
                            }
                        }
                    },
                    "else": {"properties": {"event_processes": {"maxItems": 0}}},
                },
            ],
        },
    }
    existing = schema.setdefault("allOf", [])
    if isinstance(existing, list):
        existing.append(current_contract)


def _trajectory_path_variant_schema(
    states: tuple[TrajectoryState, ...],
) -> dict[str, Any]:
    """Bind every observable fact encoded by one canonical current path."""

    required = ["states", "terminal_state", "transition_count"]
    properties: dict[str, Any] = {
        "states": {"const": list(states)},
        "terminal_state": {"const": states[-1]},
        "transition_count": {"const": len(states) - 1},
        "human_review_performed": {"const": "human_review" in states},
    }
    if "human_review" in states:
        # Pydantic defaults an omitted value to false, which cannot truthfully
        # describe a path containing an observed human-review state.
        required.append("human_review_performed")
    return {"required": required, "properties": properties}


def _trajectory_path_schema_extra(schema: dict[str, Any]) -> None:
    existing = schema.setdefault("allOf", [])
    if not isinstance(existing, list):
        return
    existing.extend(
        [
            {
                "if": {
                    "properties": {
                        "schema_version": {
                            "const": _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION,
                        },
                    },
                },
                "then": {
                    "required": [
                        "claim_evidence_complete",
                        "claim_evidence_status",
                    ],
                    "properties": {
                        "claim_evidence_complete": {"type": "boolean"},
                        "claim_evidence_status": {
                            "enum": [
                                "not_evaluated",
                                "not_applicable",
                                "complete",
                                "incomplete",
                                "unobservable",
                            ],
                        },
                        "states": {"uniqueItems": True},
                    },
                    "allOf": [
                        {
                            "if": {
                                "required": ["states"],
                                "properties": {
                                    "states": {
                                        "contains": {"const": "excluded"},
                                    },
                                },
                            },
                            "then": {
                                "properties": {
                                    "claim_evidence_status": {
                                        "const": "not_evaluated",
                                    },
                                },
                            },
                            "else": {
                                "if": {
                                    "required": ["approval_outcome"],
                                    "properties": {
                                        "approval_outcome": {"const": True},
                                    },
                                },
                                "then": {
                                    "properties": {
                                        "claim_evidence_status": {
                                            "enum": [
                                                "complete",
                                                "incomplete",
                                                "unobservable",
                                            ],
                                        },
                                    },
                                },
                                "else": {
                                    "properties": {
                                        "claim_evidence_status": {
                                            "const": "not_applicable",
                                        },
                                    },
                                },
                            },
                        },
                        {
                            "oneOf": [
                                *(
                                    _trajectory_path_variant_schema(states)
                                    for states in _CANONICAL_EXCLUDED_TRAJECTORY_STATES
                                ),
                                *(
                                    _trajectory_path_variant_schema(states)
                                    for states in _CANONICAL_INCLUDED_TRAJECTORY_STATES
                                ),
                            ],
                        },
                        {
                            "if": {
                                "required": ["limitations"],
                                "properties": {
                                    "limitations": {
                                        "contains": {
                                            "const": (CLAIM_EVIDENCE_UNOBSERVABLE_PATH_LIMITATION),
                                        },
                                        "minContains": 1,
                                    },
                                },
                            },
                            "then": {
                                "required": ["claim_evidence_status"],
                                "properties": {
                                    "claim_evidence_status": {"const": "unobservable"},
                                },
                            },
                        },
                    ],
                },
                "else": {
                    "properties": {
                        "claim_evidence_status": {
                            "anyOf": [
                                {
                                    "enum": [
                                        "complete",
                                        "incomplete",
                                        "unobservable",
                                    ],
                                },
                                {"type": "null"},
                            ],
                        },
                    },
                },
            },
            {
                "if": {
                    "required": ["claim_evidence_status"],
                    "properties": {
                        "claim_evidence_status": {"const": "complete"},
                    },
                },
                "then": {
                    "required": ["claim_evidence_complete"],
                    "properties": {
                        "claim_evidence_complete": {"const": True},
                    },
                },
            },
            {
                "if": {
                    "required": ["claim_evidence_status"],
                    "properties": {
                        "claim_evidence_status": {
                            "enum": [
                                "not_evaluated",
                                "not_applicable",
                                "incomplete",
                                "unobservable",
                            ],
                        },
                    },
                },
                "then": {
                    "required": ["claim_evidence_complete"],
                    "properties": {
                        "claim_evidence_complete": {"const": False},
                    },
                },
            },
            {
                "if": {
                    "required": ["claim_evidence_status"],
                    "properties": {
                        "claim_evidence_status": {"const": "unobservable"},
                    },
                },
                "then": {
                    "required": ["limitations"],
                    "properties": {
                        "limitations": {
                            "contains": {
                                "const": CLAIM_EVIDENCE_UNOBSERVABLE_PATH_LIMITATION,
                            },
                        },
                    },
                },
            },
        ]
    )


def _trajectory_invariant_result_schema_extra(schema: dict[str, Any]) -> None:
    existing = schema.setdefault("allOf", [])
    if not isinstance(existing, list):
        return
    existing.extend(
        [
            {
                "if": {
                    "properties": {
                        "schema_version": {
                            "const": _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION,
                        },
                    },
                },
                "then": {
                    "required": [
                        "unobservable_observations",
                        "unobservable_observation_ids",
                    ],
                    "properties": {
                        "unobservable_observations": {"type": "integer"},
                        "unobservable_observation_ids": {"type": "array"},
                    },
                },
            },
            {
                "if": {
                    "required": ["unobservable_observations"],
                    "properties": {
                        "unobservable_observations": {"minimum": 1},
                    },
                },
                "then": {
                    "required": [
                        "invariant_type",
                        "prerequisite_status",
                        "state",
                        "limitations",
                        "unobservable_observation_ids",
                    ],
                    "properties": {
                        "invariant_type": {"const": "claim_evidence_before_approval"},
                        "prerequisite_status": {
                            "enum": ["exploratory", "invalid"],
                        },
                        "state": {"enum": ["fail", "warn"]},
                        "limitations": {
                            "contains": {
                                "const": CLAIM_EVIDENCE_UNOBSERVABLE_INVARIANT_LIMITATION,
                            },
                        },
                    },
                },
            },
        ]
    )


def _trajectory_invariant_plan_schema_extra(schema: dict[str, Any]) -> None:
    """Mirror the current invariant-type field contract in exported JSON Schema."""

    schema["$comment"] = (
        "required_review_for_approval currently supports only the observable "
        "human_review state. Other invariant types must not carry required_state or "
        "before_state. Runtime validation additionally applies the same conditional "
        "contract."
    )
    existing = schema.setdefault("allOf", [])
    if not isinstance(existing, list):
        return
    _require_current_unique_items(schema, ("forbidden_states",))
    existing.append(
        {
            "if": {
                "required": ["invariant_type"],
                "properties": {
                    "invariant_type": {"const": "required_review_for_approval"},
                },
            },
            "then": {
                "required": ["required_state"],
                "properties": {
                    "required_state": {"not": {"type": "null"}},
                    "before_state": {"type": "null"},
                },
            },
            "else": {
                "properties": {
                    "required_state": {"type": "null"},
                    "before_state": {"type": "null"},
                },
            },
        }
    )
    existing.append(
        {
            "if": {
                "required": ["invariant_type"],
                "properties": {
                    "schema_version": {
                        "const": _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION,
                    },
                    "invariant_type": {"const": "required_review_for_approval"},
                },
            },
            "then": {
                "properties": {
                    "required_state": {"const": "human_review"},
                },
            },
        }
    )


def _live_protocol_record_schema_extra(schema: dict[str, Any]) -> None:
    _require_current_unique_items(
        schema,
        ("allowed_exclusion_reasons", "provider_version_capture"),
    )
    schema["$comment"] = (
        "Current protocol records require current-version nested plans and plan items. "
        "Runtime validation also applies corrected Bonferroni floor arithmetic and "
        "independence-cluster rare-event exposure. JSON Schema expresses the version and "
        "rare-event constraints; adjusted-alpha division remains a runtime relational "
        "constraint."
    )
    current_contract = {
        "if": {"properties": {"schema_version": {"const": SCHEMA_VERSION}}},
        "then": {
            "properties": {
                "advanced_analysis_plan": {
                    "properties": {
                        "schema_version": {"const": SCHEMA_VERSION},
                        "endpoints": {
                            "items": {
                                "properties": {
                                    "schema_version": {"const": SCHEMA_VERSION},
                                },
                                "if": {
                                    "required": ["analysis_method"],
                                    "properties": {
                                        "analysis_method": {
                                            "const": _CURRENT_RARE_EVENT_ANALYSIS_METHOD
                                        }
                                    },
                                },
                                "then": {
                                    "required": ["exposure_unit"],
                                    "properties": {
                                        "exposure_unit": {"const": "independence_cluster"}
                                    },
                                },
                            }
                        },
                    }
                },
                "drift_monitoring_plan": {
                    "properties": {
                        "schema_version": {"const": SCHEMA_VERSION},
                        "metrics": {
                            "items": {
                                "properties": {
                                    "schema_version": {"const": SCHEMA_VERSION},
                                }
                            }
                        },
                    }
                },
                "trajectory_analysis_plan": {
                    "properties": {
                        "schema_version": {"const": SCHEMA_VERSION},
                        "invariants": {
                            "items": {
                                "properties": {
                                    "schema_version": {"const": SCHEMA_VERSION},
                                }
                            }
                        },
                    }
                },
            }
        },
    }
    existing = schema.setdefault("allOf", [])
    if isinstance(existing, list):
        existing.append(current_contract)
        existing.append(
            {
                "if": {"properties": {"schema_version": {"const": SCHEMA_VERSION}}},
                "then": {
                    "properties": {
                        "advanced_analysis_plan": {
                            "properties": {
                                "endpoints": {"items": _legacy_rare_event_method_rejection_schema()}
                            }
                        }
                    }
                },
            }
        )


def _drift_window_schema_extra(schema: dict[str, Any]) -> None:
    _require_non_null_schema_fields(schema, ("configuration_digest",))
    existing = schema.setdefault("allOf", [])
    if isinstance(existing, list):
        existing.append(
            {
                "if": {
                    "properties": {
                        "schema_version": {
                            "const": _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION,
                        },
                    },
                },
                "then": {
                    "required": [
                        "source_runset_completion_status",
                        "source_evaluation_completion_status",
                        "source_evaluation_exploratory",
                    ],
                    "properties": {
                        "source_runset_completion_status": {"not": {"type": "null"}},
                        "source_evaluation_completion_status": {"not": {"type": "null"}},
                        "source_evaluation_exploratory": {"type": "boolean"},
                    },
                    "allOf": [
                        {
                            "if": {
                                "properties": {
                                    "source_evaluation_completion_status": {"const": "complete"},
                                }
                            },
                            "then": {
                                "properties": {
                                    "source_runset_completion_status": {"const": "complete"},
                                }
                            },
                        }
                    ],
                },
            }
        )


def _drift_comparability_schema_extra(schema: dict[str, Any]) -> None:
    _require_non_null_schema_fields(schema, ("configuration_digest_matches",))


def _drift_metric_plan_schema_extra(schema: dict[str, Any]) -> None:
    """Expose the runtime's mandatory descriptive basis to schema-only consumers."""

    _require_current_unique_items(schema, ("analysis_methods", "reason_codes"))
    existing = schema.setdefault("allOf", [])
    if isinstance(existing, list):
        existing.append(
            {
                "properties": {
                    "analysis_methods": {
                        "contains": {"const": "descriptive_trend"},
                        "minContains": 1,
                        "uniqueItems": True,
                    }
                }
            }
        )


def _drift_monitoring_plan_schema_extra(schema: dict[str, Any]) -> None:
    """Require a declared confirmatory endpoint for a confirmatory plan."""

    existing = schema.setdefault("allOf", [])
    if isinstance(existing, list):
        existing.append(
            {
                "if": {
                    "properties": {
                        "schema_version": {
                            "const": _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION,
                        },
                    },
                },
                "then": {
                    "properties": {
                        "ordering_variable": {
                            "enum": ["window_index", "window_start_utc"],
                        },
                    },
                },
            }
        )
        existing.append(
            {
                "if": {
                    "required": ["interpretation"],
                    "properties": {"interpretation": {"const": "confirmatory"}},
                },
                "then": {
                    "required": ["drift_hypothesis"],
                    "properties": {
                        "drift_hypothesis": {"not": {"type": "null"}},
                        "metrics": {
                            "contains": {
                                "required": ["interpretation"],
                                "properties": {"interpretation": {"const": "confirmatory"}},
                            },
                            "minContains": 1,
                        },
                    },
                },
            }
        )
        existing.append(
            {
                "if": {
                    "properties": {
                        "metrics": {
                            "contains": {
                                "required": ["interpretation"],
                                "properties": {"interpretation": {"const": "confirmatory"}},
                            },
                            "minContains": 1,
                        }
                    }
                },
                "then": {
                    "required": ["interpretation", "drift_hypothesis"],
                    "properties": {
                        "interpretation": {"const": "confirmatory"},
                        "drift_hypothesis": {"not": {"type": "null"}},
                    },
                },
            }
        )


def _drift_metric_diagnostic_schema_extra(schema: dict[str, Any]) -> None:
    """Keep persisted signal availability aligned with declared method authority."""

    existing = schema.setdefault("allOf", [])
    if not isinstance(existing, list):
        return
    existing.append(
        {
            "if": {
                "properties": {
                    "schema_version": {"const": _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION}
                }
            },
            "then": {
                "allOf": [
                    {"properties": {"stationarity_signal": {"not": {"const": "not_evaluated"}}}},
                    {
                        "if": {
                            "properties": {
                                "analysis_methods": {
                                    "contains": {
                                        "enum": [
                                            "lag1_autocorrelation",
                                            "ar1_summary",
                                        ]
                                    },
                                    "minContains": 1,
                                }
                            }
                        },
                        "then": {
                            "properties": {"dependence_signal": {"not": {"const": "not_evaluated"}}}
                        },
                        "else": {"properties": {"dependence_signal": {"const": "not_evaluated"}}},
                    },
                ]
            },
        }
    )


def _trajectory_analysis_plan_schema_extra(schema: dict[str, Any]) -> None:
    """Represent supported methods and confirmatory-target coherence in JSON Schema."""

    _require_current_unique_items(schema, ("analysis_methods",))
    existing = schema.setdefault("allOf", [])
    if not isinstance(existing, list):
        return
    existing.append(
        {
            "properties": {
                "analysis_methods": {
                    "contains": {"const": "observable_transition_profile"},
                    "minContains": 1,
                    "uniqueItems": True,
                }
            }
        }
    )
    for source, required in (
        ("event_process_summary", "burst_window_count"),
        ("burst_window_count", "event_process_summary"),
    ):
        existing.append(
            {
                "if": {
                    "required": ["analysis_methods"],
                    "properties": {
                        "analysis_methods": {
                            "contains": {"const": source},
                            "minContains": 1,
                        }
                    },
                },
                "then": {
                    "properties": {
                        "analysis_methods": {
                            "contains": {"const": required},
                            "minContains": 1,
                        }
                    }
                },
            }
        )
    existing.append(
        {
            "if": {
                "required": ["invariants"],
                "properties": {"invariants": {"minItems": 1}},
            },
            "then": {
                "properties": {
                    "analysis_methods": {
                        "contains": {"const": "sequence_invariant_check"},
                        "minContains": 1,
                    }
                }
            },
        }
    )
    existing.append(
        {
            "if": {
                "required": ["interpretation"],
                "properties": {"interpretation": {"const": "confirmatory"}},
            },
            "then": {
                "required": ["invariants"],
                "properties": {
                    "analysis_methods": {
                        "minItems": len(_TRAJECTORY_SUPPORTED_METHODS),
                        "maxItems": len(_TRAJECTORY_SUPPORTED_METHODS),
                        "allOf": [
                            {"contains": {"const": method}, "minContains": 1}
                            for method in sorted(_TRAJECTORY_SUPPORTED_METHODS)
                        ],
                    },
                    "invariants": {
                        "contains": {
                            "required": ["interpretation"],
                            "properties": {"interpretation": {"const": "confirmatory"}},
                        },
                        "minContains": 1,
                    },
                },
            },
        }
    )
    existing.append(
        {
            "if": {
                "required": ["invariants"],
                "properties": {
                    "invariants": {
                        "contains": {
                            "required": ["interpretation"],
                            "properties": {"interpretation": {"const": "confirmatory"}},
                        },
                        "minContains": 1,
                    }
                },
            },
            "then": {
                "required": ["interpretation"],
                "properties": {"interpretation": {"const": "confirmatory"}},
            },
        }
    )


AnalysisMethod = Literal[
    "paired_cluster_t_interval",
    "paired_cluster_bootstrap_percentile",
    "paired_cluster_permutation_exact",
    "paired_cluster_permutation_monte_carlo",
    "fixed_reference_cluster_t_interval",
    "cluster_t_interval",
    "exploratory",
]

EndpointAnalysisMethod = Literal[
    "cluster_t_interval",
    "cluster_bootstrap_percentile",
    "clopper_pearson_exact_one_sided",
    "poisson_upper_bound",
    "hierarchical_binomial_summary",
    "beta_binomial_cluster_summary",
    "descriptive_rate",
]
RareEventResultMethod = Literal[
    "clopper_pearson_exact_one_sided",
    "clopper_pearson_zero_event_closed_form",
    "bernoulli_kl_chernoff_upper_bound_one_sided",
]
_UNIMPLEMENTED_ENDPOINT_ANALYSIS_METHODS = {
    "cluster_t_interval",
    "cluster_bootstrap_percentile",
    "beta_binomial_cluster_summary",
}
EndpointKind = Literal[
    "expectation_pass_rate",
    "reason_code_rate",
    "critical_event_rate",
    "exclusion_rate",
    "outcome_rate",
]
EndpointInterpretation = Literal["confirmatory", "exploratory"]
EndpointRole = Literal["primary", "secondary", "diagnostic"]
EndpointPrerequisiteStatus = Literal["met", "exploratory", "invalid"]
MultiplicityMethod = Literal["none", "single_endpoint", "bonferroni"]
ObservedIccUse = Literal["disabled", "large_cluster_threshold", "external_review"]
DriftMetric = Literal[
    "expectation_pass_rate",
    "reason_code_rate",
    "exclusion_rate",
    "retry_rate",
    "rate_limit_rate",
    "latency_p50_ms",
    "cost_total_usd",
]
DriftAnalysisMethod = Literal[
    "descriptive_trend",
    "lag1_autocorrelation",
    "ar1_summary",
    "state_space_ewma",
]
DriftInterpretation = Literal["confirmatory", "exploratory"]
DriftComparabilityStatus = Literal["pass", "exploratory", "invalid"]
DriftMonitoringStatus = Literal["valid", "exploratory", "invalid"]
DriftOrderingVariable = Literal[
    "window_index",
    "window_start_utc",
    "release_sequence",
    "provider_version_window",
]
DriftStationaritySignal = Literal["not_evaluated", "none", "review", "invalid"]
TrajectoryState = Literal[
    "start",
    "request_assembly",
    "provider_call",
    "tool_call",
    "evidence_check",
    "policy_check",
    "redaction_check",
    "human_review",
    "verdict",
    "excluded",
    "emergency",
]
TrajectoryAnalysisMethod = Literal[
    "observable_transition_profile",
    "sequence_invariant_check",
    "event_process_summary",
    "burst_window_count",
]
TrajectoryInterpretation = Literal["exploratory", "confirmatory"]
TrajectoryPrerequisiteStatus = Literal["met", "exploratory", "invalid"]
ClaimEvidenceStatus = Literal[
    "not_evaluated",
    "not_applicable",
    "complete",
    "incomplete",
    "unobservable",
]
TrajectoryInvariantCategory = Literal[
    "governance_control_failure",
    "operational_reliability_warning",
]
TrajectoryInvariantType = Literal[
    "forbidden_state",
    "required_review_for_approval",
    "claim_evidence_before_approval",
    "attempt_retry_consistency",
]
OperationalEventType = Literal[
    "retry",
    "rate_limit",
    "exclusion",
    "runtime_failure",
    "malformed_output",
    "emergency_process",
    "budget_stop",
]
OperationalBurstSignal = Literal["none", "review", "invalid"]
_MAX_DRIFT_ANALYSIS_METHODS = len(get_args(DriftAnalysisMethod))
_MAX_TRAJECTORY_ANALYSIS_METHODS = len(get_args(TrajectoryAnalysisMethod))
_MAX_TRAJECTORY_PATH_STATES = len(get_args(TrajectoryState))
_MAX_TRAJECTORY_TRANSITIONS = _MAX_TRAJECTORY_PATH_STATES**2
_MAX_OPERATIONAL_EVENT_PROCESSES = len(get_args(OperationalEventType))
_MAX_TRAJECTORY_OPERATIONAL_EVENT_INPUTS = MAX_PERSISTED_OBSERVATIONS * 8


def _ordered_optional_state_subsets(
    states: tuple[TrajectoryState, ...],
) -> tuple[tuple[TrajectoryState, ...], ...]:
    return tuple(
        tuple(state for state_index, state in enumerate(states) if selection & (1 << state_index))
        for selection in range(1 << len(states))
    )


_CANONICAL_EXCLUDED_TRAJECTORY_STATES: tuple[tuple[TrajectoryState, ...], ...] = tuple(
    ("start", "request_assembly", *optional_states, "excluded")
    for optional_states in _ordered_optional_state_subsets(("human_review", "emergency"))
)
_CANONICAL_INCLUDED_TRAJECTORY_STATES: tuple[tuple[TrajectoryState, ...], ...] = tuple(
    ("start", "request_assembly", "provider_call", *optional_states, "verdict")
    for optional_states in _ordered_optional_state_subsets(
        (
            "tool_call",
            "evidence_check",
            "policy_check",
            "redaction_check",
            "human_review",
            "emergency",
        )
    )
)
_CANONICAL_EXCLUDED_TRAJECTORY_STATE_SET = frozenset(_CANONICAL_EXCLUDED_TRAJECTORY_STATES)
_CANONICAL_INCLUDED_TRAJECTORY_STATE_SET = frozenset(_CANONICAL_INCLUDED_TRAJECTORY_STATES)

_LIVE_DRIFT_DERIVATION_CONTRACT = "agent-assure/live-drift/v1"
_LIVE_TRAJECTORY_DERIVATION_CONTRACT = "agent-assure/live-trajectory/v1"
_TRAJECTORY_SUPPORTED_METHODS = frozenset(get_args(TrajectoryAnalysisMethod))
_DRIFT_ANALYSIS_METHOD_RANK = {
    value: index for index, value in enumerate(get_args(DriftAnalysisMethod))
}
_TRAJECTORY_ANALYSIS_METHOD_RANK = {
    value: index for index, value in enumerate(get_args(TrajectoryAnalysisMethod))
}
_TRAJECTORY_STATE_RANK = {value: index for index, value in enumerate(get_args(TrajectoryState))}
# Keep this rank aligned with the persisted arm identity projected by live statistics.
_PERSISTED_ARM_IDENTITY_FIELDS = (
    "provider",
    "model",
    "resolved_model",
    "provider_api_version",
    "provider_sdk",
    "provider_region",
    "adapter_id",
    "pipeline_id",
)
_PROVIDER_VERSION_CAPTURE_RANK = {
    value: index for index, value in enumerate(_PERSISTED_ARM_IDENTITY_FIELDS)
}


def _decimal(value: str | int) -> Decimal:
    return Decimal(str(value))


def _require_current_canonical_set_sequence(
    *,
    schema_version: str,
    values: tuple[Any, ...],
    canonical_values: tuple[Any, ...],
    field_name: str,
) -> None:
    if schema_version != _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION:
        return
    if len(values) != len(set(values)):
        raise ValueError(f"current {field_name} values must be unique")
    if values != canonical_values:
        raise ValueError(f"current {field_name} values must use canonical order")


def _decimal_string(value: Decimal) -> str:
    return decimal_string(value)


@with_live_decimal_context
def _validated_rate_string(numerator: int, denominator: int) -> str:
    if denominator <= 0 or not 0 <= numerator <= denominator:
        raise ValueError("rate counts are outside the binomial domain")
    return decimal_string(Decimal(numerator) / Decimal(denominator))


@with_live_decimal_context
def _validated_outward_upper_string(value: Decimal) -> str:
    if not value.is_finite() or value < Decimal("0"):
        raise ValueError("upper endpoint must be finite and non-negative")
    return format(value.quantize(Decimal("0.000001"), rounding=ROUND_CEILING), "f")


class StatisticalEndpointPlan(PersistedArtifact):
    model_config = ConfigDict(json_schema_extra=_statistical_endpoint_plan_schema_extra)

    artifact_kind: Literal["statistical-endpoint-plan"] = "statistical-endpoint-plan"
    endpoint_id: str = Field(min_length=1)
    label: str = Field(min_length=1)
    endpoint_kind: EndpointKind
    role: EndpointRole = "secondary"
    interpretation: EndpointInterpretation = "exploratory"
    analysis_method: EndpointAnalysisMethod = "descriptive_rate"
    reason_codes: tuple[ReasonCode, ...] = Field(default=(), max_length=len(ReasonCode))
    outcome: str | None = None
    minimum_clusters: int = Field(default=30, ge=1)
    minimum_observations: int = Field(default=1, ge=1)
    minimum_events: int = Field(default=0, ge=0)
    exposure_unit: str = Field(default="observation", min_length=1)
    family_id: str | None = Field(default=None, min_length=1)
    hierarchy_rank: int | None = Field(default=None, ge=1)
    exchangeability_assumption: Literal[
        "not_applicable",
        "baseline_candidate_relabeling",
    ] = "not_applicable"

    @field_validator("reason_codes", mode="before")
    @classmethod
    def _coerce_reason_codes(cls, value: object) -> object:
        if isinstance(value, list | tuple):
            return tuple(coerce_enum(ReasonCode, item) for item in value)
        return value

    @field_validator("analysis_method", mode="before")
    @classmethod
    def _reject_unimplemented_analysis_method(cls, value: object) -> object:
        if isinstance(value, str) and value in _UNIMPLEMENTED_ENDPOINT_ANALYSIS_METHODS:
            raise ValueError(f"advanced endpoint analysis_method {value!r} is not implemented")
        return value

    @model_validator(mode="after")
    def _validate_endpoint(self) -> StatisticalEndpointPlan:
        _require_current_canonical_set_sequence(
            schema_version=self.schema_version,
            values=self.reason_codes,
            canonical_values=tuple(sorted(self.reason_codes, key=lambda reason: reason.value)),
            field_name="statistical endpoint reason_codes",
        )
        if self.endpoint_kind in {"reason_code_rate", "critical_event_rate"}:
            if not self.reason_codes:
                raise ValueError(
                    "reason_code_rate and critical_event_rate endpoints require reason_codes"
                )
        elif self.reason_codes:
            raise ValueError("reason_codes are only valid for reason-code endpoints")
        if self.endpoint_kind == "outcome_rate" and not self.outcome:
            raise ValueError("outcome_rate endpoints require outcome")
        if self.endpoint_kind != "outcome_rate" and self.outcome is not None:
            raise ValueError("outcome is only valid for outcome_rate endpoints")
        if self.analysis_method in _RARE_EVENT_ANALYSIS_METHODS and self.endpoint_kind not in {
            "critical_event_rate",
            "reason_code_rate",
            "exclusion_rate",
        }:
            raise ValueError(
                "rare-event upper bounds require a critical-event, reason-code, "
                "or exclusion endpoint"
            )
        if (
            self.schema_version == _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION
            and self.analysis_method == _LEGACY_RARE_EVENT_ANALYSIS_METHOD
        ):
            raise ValueError(
                "current rare-event endpoints require "
                "analysis_method='clopper_pearson_exact_one_sided'"
            )
        if (
            self.schema_version == _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION
            and self.analysis_method == _CURRENT_RARE_EVENT_ANALYSIS_METHOD
            and self.exposure_unit != "independence_cluster"
        ):
            raise ValueError(
                "clopper_pearson_exact_one_sided requires exposure_unit='independence_cluster'"
            )
        return self


class AdvancedAnalysisPlan(PersistedArtifact):
    model_config = ConfigDict(json_schema_extra=_advanced_analysis_plan_schema_extra)

    artifact_kind: Literal["advanced-analysis-plan"] = "advanced-analysis-plan"
    multiplicity_method: MultiplicityMethod = "none"
    familywise_alpha: Fraction6String = Field(default="0.050000", pattern=r"^0\.[0-9]{6}$")
    observed_icc_confirmatory_use: ObservedIccUse = "disabled"
    observed_icc_large_cluster_threshold: int | None = Field(default=None, ge=30)
    endpoints: tuple[StatisticalEndpointPlan, ...] = Field(
        min_length=1,
        max_length=MAX_LIVE_ADVANCED_ENDPOINTS,
    )

    @field_validator("endpoints", mode="before")
    @classmethod
    def _coerce_endpoints(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    @with_live_decimal_context
    def _validate_plan(self) -> AdvancedAnalysisPlan:
        if not Decimal("0") < Decimal(self.familywise_alpha) < Decimal("1"):
            raise ValueError("familywise_alpha must be greater than zero and less than one")
        endpoint_ids = [endpoint.endpoint_id for endpoint in self.endpoints]
        if len(endpoint_ids) != len(set(endpoint_ids)):
            raise ValueError("advanced analysis endpoint_id values must be unique")
        if self.schema_version == _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION:
            for endpoint in self.endpoints:
                if endpoint.analysis_method == _LEGACY_RARE_EVENT_ANALYSIS_METHOD:
                    raise ValueError(
                        "current rare-event endpoints require "
                        "analysis_method='clopper_pearson_exact_one_sided'"
                    )
                if (
                    endpoint.analysis_method == _CURRENT_RARE_EVENT_ANALYSIS_METHOD
                    and endpoint.exposure_unit != "independence_cluster"
                ):
                    raise ValueError(
                        "clopper_pearson_exact_one_sided requires "
                        "exposure_unit='independence_cluster'"
                    )
        primary_count = sum(1 for endpoint in self.endpoints if endpoint.role == "primary")
        if primary_count != 1:
            raise ValueError("advanced analysis plan requires exactly one primary endpoint")
        confirmatory = tuple(
            endpoint for endpoint in self.endpoints if endpoint.interpretation == "confirmatory"
        )
        if self.observed_icc_confirmatory_use == "large_cluster_threshold":
            if self.observed_icc_large_cluster_threshold is None:
                raise ValueError(
                    "large_cluster_threshold observed ICC use requires "
                    "observed_icc_large_cluster_threshold"
                )
        elif self.observed_icc_large_cluster_threshold is not None:
            raise ValueError(
                "observed_icc_large_cluster_threshold is only valid for "
                "large_cluster_threshold observed ICC use"
            )
        if not confirmatory:
            return self
        if len(confirmatory) == 1 and self.multiplicity_method == "none":
            raise ValueError(
                "a confirmatory endpoint requires single_endpoint or bonferroni multiplicity_method"
            )
        if len(confirmatory) > 1 and self.multiplicity_method != "bonferroni":
            raise ValueError(
                "multiple confirmatory endpoints require bonferroni multiplicity_method"
            )
        adjusted_alpha = Decimal(self.familywise_alpha) / Decimal(len(confirmatory))
        if self.schema_version == _BONFERRONI_FLOOR_SCHEMA_VERSION:
            adjusted_alpha_below_precision = adjusted_alpha.quantize(
                Decimal("0.000001"),
                rounding=ROUND_FLOOR,
            ) == Decimal("0")
        else:
            adjusted_alpha_below_precision = decimal_string(adjusted_alpha) == "0.000000"
        if self.multiplicity_method == "bonferroni" and adjusted_alpha_below_precision:
            raise ValueError(
                "Bonferroni-adjusted alpha is below the persisted six-decimal precision"
            )
        if any(endpoint.hierarchy_rank is not None for endpoint in confirmatory):
            raise ValueError("hierarchy_rank is reserved for a future fixed-sequence method")
        return self


class DriftMetricPlan(PersistedArtifact):
    model_config = ConfigDict(json_schema_extra=_drift_metric_plan_schema_extra)

    artifact_kind: Literal["drift-metric-plan"] = "drift-metric-plan"
    metric: DriftMetric
    label: str = Field(min_length=1)
    interpretation: DriftInterpretation = "exploratory"
    analysis_methods: tuple[DriftAnalysisMethod, ...] = Field(
        default=("descriptive_trend",),
        min_length=1,
        max_length=_MAX_DRIFT_ANALYSIS_METHODS,
    )
    reason_codes: tuple[ReasonCode, ...] = Field(default=(), max_length=len(ReasonCode))
    minimum_windows: int = Field(default=6, ge=2)
    minimum_dependence_windows: int = Field(default=8, ge=8)
    minimum_state_space_windows: int = Field(default=6, ge=6)
    minimum_observations_per_window: int = Field(default=1, ge=1)
    slope_review_threshold: DecimalString = Field(
        default="0.050000",
        pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    step_review_threshold: DecimalString = Field(
        default="0.100000",
        pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    autocorrelation_review_threshold: UnitInterval6String = Field(
        default="0.500000",
    )
    ar1_review_threshold: UnitInterval6String = Field(
        default="0.500000",
    )
    state_space_alpha: UnitInterval6String = Field(
        default="0.300000",
    )

    @field_validator("analysis_methods", mode="before")
    @classmethod
    def _coerce_analysis_methods(cls, value: object) -> object:
        return coerce_tuple(value)

    @field_validator("reason_codes", mode="before")
    @classmethod
    def _coerce_reason_codes(cls, value: object) -> object:
        if isinstance(value, list | tuple):
            return tuple(coerce_enum(ReasonCode, item) for item in value)
        return value

    @model_validator(mode="after")
    @with_live_decimal_context
    def _validate_metric_plan(self) -> DriftMetricPlan:
        if len(self.analysis_methods) != len(set(self.analysis_methods)):
            raise ValueError("drift analysis_methods values must be unique")
        _require_current_canonical_set_sequence(
            schema_version=self.schema_version,
            values=self.analysis_methods,
            canonical_values=tuple(
                sorted(
                    self.analysis_methods,
                    key=_DRIFT_ANALYSIS_METHOD_RANK.__getitem__,
                )
            ),
            field_name="drift analysis_methods",
        )
        _require_current_canonical_set_sequence(
            schema_version=self.schema_version,
            values=self.reason_codes,
            canonical_values=tuple(sorted(self.reason_codes, key=lambda reason: reason.value)),
            field_name="drift reason_codes",
        )
        if "descriptive_trend" not in self.analysis_methods:
            raise ValueError(
                "drift metrics require descriptive_trend as the authoritative base method"
            )
        if self.metric == "reason_code_rate":
            if not self.reason_codes:
                raise ValueError("reason_code_rate drift metrics require reason_codes")
        elif self.reason_codes:
            raise ValueError("reason_codes are only valid for reason_code_rate drift metrics")
        alpha = _decimal(self.state_space_alpha)
        if alpha <= Decimal("0") or alpha > Decimal("1"):
            raise ValueError("state_space_alpha must be greater than 0 and no more than 1")
        return self


class DriftMonitoringPlan(PersistedArtifact):
    model_config = ConfigDict(json_schema_extra=_drift_monitoring_plan_schema_extra)

    artifact_kind: Literal["drift-monitoring-plan"] = "drift-monitoring-plan"
    plan_id: str = Field(min_length=1)
    interpretation: DriftInterpretation = "exploratory"
    ordering_variable: DriftOrderingVariable = "window_index"
    comparability_mode: Literal["strict_protocol_digest", "material_fields"] = (
        "strict_protocol_digest"
    )
    allow_bounded_sensitivity_on_comparability_failure: bool = False
    drift_hypothesis: str | None = Field(default=None, min_length=1)
    metrics: tuple[DriftMetricPlan, ...] = Field(
        min_length=1,
        max_length=MAX_LIVE_MONITORING_ITEMS,
    )
    known_provider_version_unknowns: tuple[str, ...] = ()

    @field_validator("metrics", "known_provider_version_unknowns", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_monitoring_plan(self) -> DriftMonitoringPlan:
        if (
            self.schema_version == _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION
            and self.ordering_variable not in {"window_index", "window_start_utc"}
        ):
            raise ValueError(
                "current drift monitoring supports only window_index or window_start_utc ordering"
            )
        metric_keys = [
            (metric.metric, tuple(reason.value for reason in metric.reason_codes))
            for metric in self.metrics
        ]
        if len(metric_keys) != len(set(metric_keys)):
            raise ValueError("drift monitoring metrics must be unique by metric and reason codes")
        confirmatory_metrics = [
            metric for metric in self.metrics if metric.interpretation == "confirmatory"
        ]
        if self.interpretation == "confirmatory" and not confirmatory_metrics:
            raise ValueError(
                "confirmatory drift monitoring requires at least one confirmatory metric"
            )
        if self.interpretation == "confirmatory" or confirmatory_metrics:
            if self.drift_hypothesis is None:
                raise ValueError(
                    "confirmatory drift monitoring requires a predeclared drift_hypothesis"
                )
            if self.interpretation != "confirmatory":
                raise ValueError(
                    "confirmatory drift metrics require a confirmatory monitoring plan"
                )
        return self


class TrajectoryInvariantPlan(PersistedArtifact):
    model_config = ConfigDict(json_schema_extra=_trajectory_invariant_plan_schema_extra)

    artifact_kind: Literal["trajectory-invariant-plan"] = "trajectory-invariant-plan"
    invariant_id: str = Field(min_length=1)
    label: str = Field(min_length=1)
    invariant_type: TrajectoryInvariantType
    category: TrajectoryInvariantCategory = "governance_control_failure"
    interpretation: TrajectoryInterpretation = "exploratory"
    forbidden_states: tuple[TrajectoryState, ...] = Field(
        default=(),
        max_length=_MAX_TRAJECTORY_PATH_STATES,
    )
    required_state: TrajectoryState | None = None
    before_state: TrajectoryState | None = None
    minimum_observations: int = Field(default=1, ge=1)

    @field_validator("forbidden_states", mode="before")
    @classmethod
    def _coerce_forbidden_states(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_invariant(self) -> TrajectoryInvariantPlan:
        _require_current_canonical_set_sequence(
            schema_version=self.schema_version,
            values=self.forbidden_states,
            canonical_values=tuple(
                sorted(
                    self.forbidden_states,
                    key=_TRAJECTORY_STATE_RANK.__getitem__,
                )
            ),
            field_name="trajectory forbidden_states",
        )
        if self.invariant_type == "forbidden_state":
            if not self.forbidden_states:
                raise ValueError("forbidden_state invariants require forbidden_states")
        elif self.forbidden_states:
            raise ValueError("forbidden_states are only valid for forbidden_state invariants")
        if self.invariant_type == "required_review_for_approval":
            if self.required_state is None:
                raise ValueError("required_review_for_approval invariants require required_state")
            if (
                self.schema_version == _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION
                and self.required_state != "human_review"
            ):
                raise ValueError(
                    "current required_review_for_approval invariants require "
                    "required_state='human_review'"
                )
            if self.before_state is not None:
                raise ValueError(
                    "required_review_for_approval does not support measured ordering; "
                    "before_state is reserved for future ordered event data"
                )
        elif self.required_state is not None or self.before_state is not None:
            raise ValueError(
                "required_state and before_state are only valid for "
                "required_review_for_approval invariants"
            )
        return self


class TrajectoryAnalysisPlan(PersistedArtifact):
    model_config = ConfigDict(json_schema_extra=_trajectory_analysis_plan_schema_extra)

    artifact_kind: Literal["trajectory-analysis-plan"] = "trajectory-analysis-plan"
    plan_id: str = Field(min_length=1)
    interpretation: TrajectoryInterpretation = "exploratory"
    analysis_methods: tuple[TrajectoryAnalysisMethod, ...] = Field(
        default=(
            "observable_transition_profile",
            "sequence_invariant_check",
            "event_process_summary",
            "burst_window_count",
        ),
        min_length=1,
        max_length=_MAX_TRAJECTORY_ANALYSIS_METHODS,
    )
    minimum_observations: int = Field(default=1, ge=1)
    minimum_transition_support: int = Field(default=1, ge=1)
    minimum_event_count: int = Field(default=3, ge=0)
    minimum_event_exposure: int = Field(default=1, ge=1)
    burst_window_seconds: int = Field(default=60, ge=1)
    burst_count_threshold: int = Field(default=3, ge=2)
    invariants: tuple[TrajectoryInvariantPlan, ...] = Field(
        default=(),
        max_length=MAX_LIVE_MONITORING_ITEMS,
    )

    @field_validator("analysis_methods", "invariants", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_plan(self) -> TrajectoryAnalysisPlan:
        if len(self.analysis_methods) != len(set(self.analysis_methods)):
            raise ValueError("trajectory analysis_methods values must be unique")
        _require_current_canonical_set_sequence(
            schema_version=self.schema_version,
            values=self.analysis_methods,
            canonical_values=tuple(
                sorted(
                    self.analysis_methods,
                    key=_TRAJECTORY_ANALYSIS_METHOD_RANK.__getitem__,
                )
            ),
            field_name="trajectory analysis_methods",
        )
        methods = set(self.analysis_methods)
        if "observable_transition_profile" not in methods:
            raise ValueError(
                "trajectory plans require observable_transition_profile as the base method"
            )
        if ("event_process_summary" in methods) != ("burst_window_count" in methods):
            raise ValueError(
                "event_process_summary and burst_window_count must be declared together"
            )
        invariant_ids = [invariant.invariant_id for invariant in self.invariants]
        if len(invariant_ids) != len(set(invariant_ids)):
            raise ValueError("trajectory invariant_id values must be unique")
        if self.invariants and "sequence_invariant_check" not in methods:
            raise ValueError("trajectory invariants require the sequence_invariant_check method")
        if self.interpretation == "confirmatory" and methods != _TRAJECTORY_SUPPORTED_METHODS:
            raise ValueError(
                "confirmatory trajectory plans require the complete supported analysis method set"
            )
        confirmatory_invariants = tuple(
            invariant for invariant in self.invariants if invariant.interpretation == "confirmatory"
        )
        if self.interpretation == "confirmatory" and not confirmatory_invariants:
            raise ValueError(
                "confirmatory trajectory plans require at least one confirmatory invariant"
            )
        if self.interpretation == "exploratory" and confirmatory_invariants:
            raise ValueError(
                "confirmatory trajectory invariants require a confirmatory trajectory plan"
            )
        return self


def _require_current_live_protocol_plan_versions(protocol: LiveProtocolRecord) -> None:
    """Keep current protocol trees aligned with the current writer contract."""

    if protocol.schema_version != SCHEMA_VERSION:
        return
    nested: list[tuple[str, PersistedArtifact]] = []
    if protocol.advanced_analysis_plan is not None:
        nested.append(("advanced analysis plan", protocol.advanced_analysis_plan))
        nested.extend(
            ("statistical endpoint plan", endpoint)
            for endpoint in protocol.advanced_analysis_plan.endpoints
        )
    if protocol.drift_monitoring_plan is not None:
        nested.append(("drift monitoring plan", protocol.drift_monitoring_plan))
        nested.extend(
            ("drift metric plan", metric) for metric in protocol.drift_monitoring_plan.metrics
        )
    if protocol.trajectory_analysis_plan is not None:
        nested.append(("trajectory analysis plan", protocol.trajectory_analysis_plan))
        nested.extend(
            ("trajectory invariant plan", invariant)
            for invariant in protocol.trajectory_analysis_plan.invariants
        )
    for owner, artifact in nested:
        if artifact.schema_version != protocol.schema_version:
            raise ValueError(f"{owner} schema_version must match its current live protocol record")


def _mapping_or_attribute(value: object, field_name: str) -> object:
    if isinstance(value, Mapping):
        return value.get(field_name)
    return getattr(value, field_name, None)


def _current_rare_event_work_items(value: object) -> tuple[tuple[int, int, Decimal], ...]:
    if not isinstance(value, Mapping):
        return ()
    schema_version = value.get("schema_version", SCHEMA_VERSION)
    if schema_version != _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION:
        return ()
    raw_invariants = value.get("statistical_invariants", ())
    if not isinstance(raw_invariants, list | tuple):
        return ()
    work_items: list[tuple[int, int, Decimal]] = []
    for raw_invariant in raw_invariants:
        raw_bound = _mapping_or_attribute(raw_invariant, "rare_event_bound")
        if raw_bound is None:
            continue
        observed_events = _mapping_or_attribute(raw_bound, "observed_events")
        exposure = _mapping_or_attribute(raw_bound, "exposure")
        confidence_level = _mapping_or_attribute(raw_bound, "confidence_level")
        if not isinstance(observed_events, int) or isinstance(observed_events, bool):
            continue
        if not isinstance(exposure, int) or isinstance(exposure, bool):
            continue
        if not isinstance(confidence_level, str):
            continue
        if not 0 <= observed_events <= exposure <= MAX_CLOPPER_PEARSON_TRIALS or exposure == 0:
            continue
        try:
            confidence = Decimal(confidence_level)
        except InvalidOperation:
            continue
        if not confidence.is_finite() or not Decimal("0") < confidence < Decimal("1"):
            continue
        work_items.append((observed_events, exposure, Decimal("1") - confidence))
    return tuple(work_items)


@with_live_decimal_context
def _require_current_rare_event_bound_identity(
    bound: RareEventUpperBound,
    *,
    owner: str,
) -> None:
    if bound.analysis_method not in _CURRENT_RARE_EVENT_RESULT_METHODS:
        raise ValueError(f"{owner} uses an unsupported current rare-event method")
    if bound.exposure_unit != "independence_cluster":
        raise ValueError(f"{owner} requires independence-cluster exposure")
    if bound.exposure == 0 or bound.exposure > MAX_SCALABLE_BINOMIAL_TRIALS:
        raise ValueError(f"{owner} exposure is outside the scalable binomial domain")
    if bound.observed_events > bound.exposure:
        raise ValueError(f"{owner} observed_events cannot exceed exposure")
    confidence = Decimal(bound.confidence_level)
    if not Decimal("0") < confidence < Decimal("1"):
        raise ValueError(f"{owner} confidence_level must be between zero and one")
    alpha = Decimal("1") - confidence
    if bound.exposure <= MAX_CLOPPER_PEARSON_TRIALS:
        validate_clopper_pearson_work_budget(((bound.observed_events, bound.exposure, alpha),))
    interval = binomial_upper_bound_one_sided(
        bound.observed_events,
        bound.exposure,
        alpha,
    )
    if bound.analysis_method != interval.method:
        raise ValueError(f"{owner} analysis_method does not match its count/exposure regime")
    if bound.event_rate != _validated_rate_string(bound.observed_events, bound.exposure):
        raise ValueError(f"{owner} event_rate does not match observed_events/exposure")
    if bound.zero_events is not (bound.observed_events == 0):
        raise ValueError(f"{owner} zero_events does not match observed_events")
    if bound.confidence_level != decimal_string(interval.confidence_level):
        raise ValueError(f"{owner} confidence_level is inconsistent with the selected bound")
    if bound.upper_rate_bound != _validated_outward_upper_string(interval.upper_rate_bound):
        raise ValueError(f"{owner} upper_rate_bound does not match the selected bound")
    expected_count = _validated_outward_upper_string(interval.upper_count_bound)
    if bound.upper_count_bound != expected_count:
        raise ValueError(f"{owner} upper_count_bound does not match the selected bound")


class RareEventUpperBound(PersistedArtifact):
    model_config = ConfigDict(json_schema_extra=_rare_event_upper_bound_schema_extra)

    artifact_kind: Literal["rare-event-upper-bound"] = "rare-event-upper-bound"
    endpoint_id: str = Field(min_length=1)
    label: str = Field(min_length=1)
    observed_events: int = Field(ge=0)
    exposure: int = Field(ge=0)
    exposure_unit: str = Field(min_length=1)
    event_rate: UnitInterval6String
    upper_count_bound: DecimalString = Field(pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$")
    upper_rate_bound: DecimalString = Field(pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$")
    confidence_level: Fraction6String = Field(
        default="0.950000",
        pattern=r"^0\.[0-9]{6}$",
    )
    interval_sidedness: Literal["one_sided_upper"] = "one_sided_upper"
    analysis_method: Literal[
        "clopper_pearson_exact_one_sided",
        "clopper_pearson_zero_event_closed_form",
        "bernoulli_kl_chernoff_upper_bound_one_sided",
        "poisson_upper_bound",
    ] = "clopper_pearson_exact_one_sided"
    zero_events: bool = False
    limitations: tuple[str, ...] = ()

    @field_validator("limitations", mode="before")
    @classmethod
    def _coerce_limitations(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_current_exact_binomial_contract(self) -> RareEventUpperBound:
        if self.schema_version != _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION:
            if self.analysis_method in {
                ZERO_EVENT_CLOSED_FORM_METHOD,
                BERNOULLI_KL_CHERNOFF_UPPER_BOUND_METHOD,
            }:
                raise ValueError("historical rare-event bounds cannot claim current methods")
            return self
        _require_current_rare_event_bound_identity(self, owner="current rare-event bound")
        return self

    @model_validator(mode="after")
    def _validate_legacy_exact_poisson_contract(self) -> RareEventUpperBound:
        from agent_assure.live.legacy_validation import validate_legacy_rare_event_bound

        validate_legacy_rare_event_bound(self)
        return self


class ClusterCorrelationSummary(PersistedArtifact):
    artifact_kind: Literal["cluster-correlation-summary"] = "cluster-correlation-summary"
    endpoint_id: str = Field(min_length=1)
    label: str = Field(min_length=1)
    cluster_count: int = Field(ge=0)
    observation_count: int = Field(ge=0)
    planned_intraclass_correlation: Fraction6String = Field(pattern=r"^0\.[0-9]{6}$")
    observed_intraclass_correlation: SignedUnitInterval6String | None = None
    uncertainty_method: Literal[
        "cluster_bootstrap_percentile",
        "not_evaluated",
    ] = "not_evaluated"
    ci_lower: SignedUnitInterval6String | None = None
    ci_upper: SignedUnitInterval6String | None = None
    bootstrap_iterations: int = Field(default=0, ge=0)
    confirmatory_use: Literal[
        "disabled",
        "eligible_large_cluster_threshold",
        "eligible_external_review",
    ] = "disabled"
    confirmatory_interval_uses_planned_icc: bool = True
    limitations: tuple[str, ...] = ()

    @field_validator("limitations", mode="before")
    @classmethod
    def _coerce_limitations(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_current_relations(self) -> ClusterCorrelationSummary:
        if self.schema_version == _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION:
            _require_current_cluster_correlation_identity(
                self,
                owner="current cluster correlation",
            )
        return self

    @model_validator(mode="after")
    def _validate_legacy_relations(self) -> ClusterCorrelationSummary:
        from agent_assure.live.legacy_validation import validate_legacy_cluster_correlation

        validate_legacy_cluster_correlation(self)
        return self


def _require_current_cluster_correlation_identity(
    summary: ClusterCorrelationSummary,
    *,
    owner: str,
) -> None:
    if summary.cluster_count > summary.observation_count:
        raise ValueError(f"{owner} cluster_count cannot exceed observation_count")
    lower = summary.ci_lower
    upper = summary.ci_upper
    if (lower is None) is not (upper is None):
        raise ValueError(f"{owner} confidence interval endpoints must be jointly present")
    if lower is not None and upper is not None and Decimal(lower) > Decimal(upper):
        raise ValueError(f"{owner} confidence interval endpoints are reversed")
    if summary.uncertainty_method == "not_evaluated":
        if lower is not None or summary.bootstrap_iterations != 0:
            raise ValueError(f"{owner} unevaluated uncertainty must not carry an interval")
    elif (
        summary.observed_intraclass_correlation is None
        or lower is None
        or summary.bootstrap_iterations != _CURRENT_ICC_BOOTSTRAP_ITERATIONS
    ):
        raise ValueError(f"{owner} bootstrap uncertainty metadata is inconsistent")


@with_live_decimal_context
def _require_current_statistical_invariant_identity(
    invariant: StatisticalInvariantResult,
    *,
    owner: str,
) -> None:
    if invariant.denominator == 0:
        raise ValueError(f"{owner} denominator must be greater than zero")
    if invariant.numerator > invariant.denominator:
        raise ValueError(f"{owner} numerator cannot exceed denominator")
    if not 0 < invariant.cluster_count <= invariant.denominator:
        raise ValueError(f"{owner} cluster_count is inconsistent with denominator")
    if invariant.rate != _validated_rate_string(invariant.numerator, invariant.denominator):
        raise ValueError(f"{owner} rate does not match numerator/denominator")
    if not Decimal("0") < Decimal(invariant.adjusted_alpha) < Decimal("1"):
        raise ValueError(f"{owner} adjusted_alpha must be between zero and one")

    bound = invariant.rare_event_bound
    if invariant.analysis_method == _LEGACY_RARE_EVENT_ANALYSIS_METHOD:
        raise ValueError(f"{owner} cannot use the legacy Poisson selector")
    if bound is None and invariant.analysis_method in _CURRENT_RARE_EVENT_RESULT_METHODS:
        raise ValueError(f"{owner} rare-event analysis requires a bound")
    if bound is not None:
        if invariant.endpoint_kind not in _RARE_EVENT_ENDPOINT_KINDS:
            raise ValueError(f"{owner} rare-event bound is invalid for this endpoint kind")
        if invariant.analysis_method not in _CURRENT_RARE_EVENT_RESULT_METHODS:
            raise ValueError(f"{owner} analysis_method does not match its rare-event bound")
        if invariant.analysis_method != bound.analysis_method:
            raise ValueError(f"{owner} analysis_method does not match its rare-event bound")
        if bound.endpoint_id != invariant.endpoint_id or bound.label != invariant.label:
            raise ValueError(f"{owner} rare-event bound identity does not match its endpoint")
        if bound.exposure != invariant.cluster_count:
            raise ValueError(f"{owner} rare-event exposure does not match cluster_count")
        if bound.observed_events > invariant.numerator:
            raise ValueError(f"{owner} cluster events cannot exceed observation events")
        _require_current_rare_event_bound_identity(bound, owner=f"{owner} rare-event bound")

    correlation = invariant.cluster_correlation
    if correlation is not None:
        if correlation.endpoint_id != invariant.endpoint_id or correlation.label != invariant.label:
            raise ValueError(f"{owner} cluster-correlation identity does not match its endpoint")
        if correlation.cluster_count != invariant.cluster_count:
            raise ValueError(f"{owner} correlation cluster_count does not match its endpoint")
        if correlation.observation_count != invariant.denominator:
            raise ValueError(f"{owner} correlation observation_count does not match its endpoint")
        _require_current_cluster_correlation_identity(
            correlation,
            owner=f"{owner} cluster correlation",
        )


class StatisticalInvariantResult(PersistedArtifact):
    artifact_kind: Literal["statistical-invariant-result"] = "statistical-invariant-result"
    endpoint_id: str = Field(min_length=1)
    label: str = Field(min_length=1)
    endpoint_kind: EndpointKind
    role: EndpointRole
    interpretation: EndpointInterpretation
    analysis_method: EndpointAnalysisMethod | RareEventResultMethod
    prerequisite_status: EndpointPrerequisiteStatus
    multiplicity_method: MultiplicityMethod
    adjusted_alpha: Fraction6String = Field(pattern=r"^0\.[0-9]{6}$")
    numerator: int = Field(ge=0)
    denominator: int = Field(ge=0)
    cluster_count: int = Field(ge=0)
    rate: UnitInterval6String
    reason_codes: tuple[ReasonCode, ...] = Field(default=(), max_length=len(ReasonCode))
    outcome: str | None = None
    rare_event_bound: RareEventUpperBound | None = None
    cluster_correlation: ClusterCorrelationSummary | None = None
    limitations: tuple[str, ...] = ()

    @field_validator("reason_codes", mode="before")
    @classmethod
    def _coerce_reason_codes(cls, value: object) -> object:
        if isinstance(value, list | tuple):
            return tuple(coerce_enum(ReasonCode, item) for item in value)
        return value

    @field_validator("limitations", mode="before")
    @classmethod
    def _coerce_limitations(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_current_relations(self) -> StatisticalInvariantResult:
        if self.schema_version != _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION:
            if self.analysis_method in {
                ZERO_EVENT_CLOSED_FORM_METHOD,
                BERNOULLI_KL_CHERNOFF_UPPER_BOUND_METHOD,
            }:
                raise ValueError("historical invariants cannot claim current rare-event methods")
            return self
        _require_current_statistical_invariant_identity(
            self,
            owner="current statistical invariant",
        )
        return self

    @model_validator(mode="after")
    def _validate_legacy_relations(self) -> StatisticalInvariantResult:
        from agent_assure.live.legacy_validation import (
            validate_legacy_statistical_invariant,
        )

        validate_legacy_statistical_invariant(self)
        return self


def _probability_micro_numerator(value: DecimalString) -> int:
    whole, fractional = value.split(".", maxsplit=1)
    return int(whole) * _PERSISTED_PROBABILITY_SCALE + int(fractional)


def _require_upward_probability_projection(
    value: DecimalString,
    *,
    resamples: int,
    owner: str,
) -> None:
    """Require a six-place upward projection of k / resamples for 1 <= k <= n."""
    projected = _probability_micro_numerator(value)
    lower_count = ((projected - 1) * resamples // _PERSISTED_PROBABILITY_SCALE) + 1
    upper_count = projected * resamples // _PERSISTED_PROBABILITY_SCALE
    if max(1, lower_count) > min(resamples, upper_count):
        raise ValueError(f"{owner} p_value is not attainable from its resample count")


def _require_current_randomization_test_identity(
    result: PairedRandomizationTestResult,
    *,
    owner: str,
) -> None:
    p_value = result.p_value
    adjusted_p_value = result.adjusted_p_value
    if (p_value is None) is not (adjusted_p_value is None):
        raise ValueError(f"{owner} p_value fields must be jointly present")
    if p_value is None or adjusted_p_value is None:
        if result.resamples != 0 or result.exhaustive:
            raise ValueError(f"{owner} unevaluated test cannot claim resampling")
        if result.prerequisite_status == "met":
            raise ValueError(f"{owner} met prerequisites require a p-value")
        return

    if Decimal(adjusted_p_value) < Decimal(p_value):
        raise ValueError(f"{owner} adjusted_p_value cannot be below p_value")
    if result.compared_clusters == 0 or result.resamples == 0:
        raise ValueError(f"{owner} evaluated test requires clusters and resamples")
    if result.prerequisite_status == "invalid":
        raise ValueError(f"{owner} invalid prerequisites cannot carry a p-value")
    if result.exchangeability_assumption != "baseline_candidate_relabeling":
        raise ValueError(f"{owner} evaluated test requires the exchangeability assumption")
    if result.analysis_method == "paired_cluster_permutation_exact":
        if not result.exhaustive or result.seed is not None:
            raise ValueError(f"{owner} exact test must be exhaustive and seed-free")
        if result.compared_clusters > _CURRENT_MAX_EXACT_PERMUTATION_CLUSTERS:
            raise ValueError(f"{owner} exceeds the exact permutation cluster limit")
        if result.resamples != 1 << result.compared_clusters:
            raise ValueError(f"{owner} exact resample count is inconsistent")
    elif (
        result.exhaustive
        or result.seed is None
        or result.resamples != _CURRENT_MONTE_CARLO_RESAMPLES
    ):
        raise ValueError(f"{owner} Monte Carlo resampling metadata is inconsistent")
    _require_upward_probability_projection(
        p_value,
        resamples=result.resamples,
        owner=owner,
    )


class PairedRandomizationTestResult(PersistedArtifact):
    artifact_kind: Literal["paired-randomization-test-result"] = "paired-randomization-test-result"
    endpoint_id: str = Field(min_length=1)
    label: str = Field(min_length=1)
    interpretation: EndpointInterpretation
    analysis_method: Literal[
        "paired_cluster_permutation_exact",
        "paired_cluster_permutation_monte_carlo",
    ]
    prerequisite_status: EndpointPrerequisiteStatus
    exchangeability_assumption: Literal[
        "baseline_candidate_relabeling",
        "not_applicable",
    ]
    compared_clusters: int = Field(ge=0)
    observed_difference: SignedUnitInterval6String
    non_inferiority_margin: Fraction6String = Field(pattern=r"^0\.[0-9]{6}$")
    p_value: UnitInterval6String | None = None
    adjusted_p_value: UnitInterval6String | None = None
    exhaustive: bool = False
    resamples: int = Field(ge=0)
    seed: str | None = None
    limitations: tuple[str, ...] = ()

    @field_validator("limitations", mode="before")
    @classmethod
    def _coerce_limitations(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_current_relations(self) -> PairedRandomizationTestResult:
        if self.schema_version == _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION:
            _require_current_randomization_test_identity(
                self,
                owner="current paired randomization result",
            )
        return self

    @model_validator(mode="after")
    def _validate_legacy_relations(self) -> PairedRandomizationTestResult:
        from agent_assure.live.legacy_validation import validate_legacy_randomization_test

        validate_legacy_randomization_test(self)
        return self


class LiveProtocolRecord(PersistedArtifact):
    model_config = ConfigDict(json_schema_extra=_live_protocol_record_schema_extra)

    artifact_kind: Literal["live-protocol-record"] = "live-protocol-record"
    protocol_id: str = Field(min_length=1)
    suite_id: str = Field(min_length=1)
    suite_version: str = Field(min_length=1)
    suite_digest: DigestHex
    baseline_mode: Literal["concurrent_paired", "fixed_reference"] = "concurrent_paired"
    hypothesis_family: Literal[
        "governance_control_non_inferiority",
        "provider_model_comparison",
        "regression_detection",
    ] = "governance_control_non_inferiority"
    primary_endpoint: Literal["expectation_pass_rate", "reason_code_rate"] = "expectation_pass_rate"
    analysis_method: AnalysisMethod = "paired_cluster_t_interval"
    baseline_group_id: str = "overall"
    candidate_group_id: str = "overall"
    fixed_reference_pass_rate: UnitInterval6String | None = None
    confidence_level: Literal["0.950000"] = "0.950000"
    non_inferiority_margin: Fraction6String = Field(pattern=r"^0\.[0-9]{6}$")
    cluster_by: Literal["case_id", "source_group_id"] = "case_id"
    planned_observations: int = Field(ge=1, le=MAX_PERSISTED_OBSERVATIONS)
    planned_clusters: int = Field(ge=1, le=MAX_PERSISTED_OBSERVATIONS)
    planned_observations_per_cluster: DecimalString = Field(
        pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    assumed_intraclass_correlation: Fraction6String = Field(pattern=r"^0\.[0-9]{6}$")
    design_effect: DecimalString = Field(pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$")
    planned_effective_n: DecimalString = Field(pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$")
    sample_size_rationale: str = Field(min_length=1)
    planned_repetitions: int = Field(ge=1, le=MAX_PERSISTED_OBSERVATIONS)
    randomization_seed: int = Field(ge=0)
    randomization_blocking: Literal["balanced_case_blocks"] = "balanced_case_blocks"
    max_requests: int = Field(ge=1, le=MAX_PERSISTED_OBSERVATIONS)
    max_total_cost_usd: DecimalString = Field(pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$")
    max_cost_per_observation_usd: DecimalString = Field(
        pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    max_generated_tokens: int | None = Field(default=None, ge=1)
    max_total_tokens: int | None = Field(default=None, ge=1)
    max_retries: int = Field(default=2, ge=0)
    retry_initial_backoff_seconds: DecimalString = Field(
        default="1.000000",
        pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    retry_max_backoff_seconds: DecimalString = Field(
        default="8.000000",
        pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    requests_per_minute: int | None = Field(default=None, ge=1)
    tokens_per_minute: int | None = Field(default=None, ge=1)
    max_rate_limit_events: int = Field(default=0, ge=0)
    exclusion_policy: str = Field(min_length=1)
    allowed_exclusion_reasons: tuple[str, ...] = ()
    max_exclusion_rate: Fraction6String = Field(default="0.000000", pattern=r"^0\.[0-9]{6}$")
    provider_version_capture: tuple[str, ...] = ()
    stopping_rules: tuple[str, ...] = ()
    tool_schema_digest: DigestHex
    policy_bundle_digest: DigestHex
    analysis_digest: DigestHex
    advanced_analysis_plan: AdvancedAnalysisPlan | None = None
    drift_monitoring_plan: DriftMonitoringPlan | None = None
    trajectory_analysis_plan: TrajectoryAnalysisPlan | None = None
    approved_data_boundary: str = Field(min_length=1)
    safety_limits: tuple[str, ...] = ()

    @field_validator(
        "allowed_exclusion_reasons",
        "provider_version_capture",
        "stopping_rules",
        "safety_limits",
        mode="before",
    )
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    @with_live_decimal_context
    def _validate_protocol_plan(self) -> LiveProtocolRecord:
        _require_current_canonical_set_sequence(
            schema_version=self.schema_version,
            values=self.allowed_exclusion_reasons,
            canonical_values=tuple(sorted(self.allowed_exclusion_reasons)),
            field_name="allowed_exclusion_reasons",
        )
        _require_current_canonical_set_sequence(
            schema_version=self.schema_version,
            values=self.provider_version_capture,
            canonical_values=tuple(
                sorted(
                    self.provider_version_capture,
                    key=lambda value: (
                        _PROVIDER_VERSION_CAPTURE_RANK.get(
                            value,
                            len(_PROVIDER_VERSION_CAPTURE_RANK),
                        ),
                        value,
                    ),
                )
            ),
            field_name="provider_version_capture",
        )
        if self.baseline_mode == "fixed_reference" and self.fixed_reference_pass_rate is None:
            raise ValueError("fixed_reference baseline_mode requires fixed_reference_pass_rate")
        if self.baseline_mode == "concurrent_paired" and self.fixed_reference_pass_rate is not None:
            raise ValueError(
                "concurrent_paired baseline_mode must not set fixed_reference_pass_rate"
            )
        if self.baseline_mode == "fixed_reference" and self.analysis_method not in {
            "fixed_reference_cluster_t_interval",
            "exploratory",
        }:
            raise ValueError(
                "fixed_reference baseline_mode requires fixed_reference_cluster_t_interval analysis"
            )
        if self.baseline_mode == "concurrent_paired" and self.analysis_method not in {
            "paired_cluster_t_interval",
            "paired_cluster_bootstrap_percentile",
            "paired_cluster_permutation_exact",
            "paired_cluster_permutation_monte_carlo",
            "exploratory",
        }:
            raise ValueError("concurrent_paired baseline_mode requires a paired cluster analysis")
        validate_live_protocol_resampling_work(
            self.analysis_method,
            self.planned_clusters,
            baseline_mode=self.baseline_mode,
        )
        planned_mean = _decimal(self.planned_observations) / _decimal(self.planned_clusters)
        if self.planned_observations_per_cluster != _decimal_string(planned_mean):
            raise ValueError(
                "planned_observations_per_cluster must equal planned_observations / "
                "planned_clusters"
            )
        cluster_size = _decimal(self.planned_observations_per_cluster)
        rho = _decimal(self.assumed_intraclass_correlation)
        design_effect = Decimal("1") + (cluster_size - Decimal("1")) * rho
        if self.design_effect != _decimal_string(design_effect):
            raise ValueError("design_effect must equal 1 + (m - 1) * rho")
        effective_n = _decimal(self.planned_observations) / design_effect
        if self.planned_effective_n != _decimal_string(effective_n):
            raise ValueError("planned_effective_n must equal planned_observations / design_effect")
        if self.analysis_method in {
            "paired_cluster_permutation_exact",
            "paired_cluster_permutation_monte_carlo",
        }:
            if self.baseline_mode != "concurrent_paired":
                raise ValueError(
                    "paired permutation methods require concurrent_paired baseline_mode"
                )
            if self.advanced_analysis_plan is None:
                raise ValueError("paired permutation methods require advanced_analysis_plan")
            if _decimal(self.non_inferiority_margin) != Decimal("0"):
                raise ValueError(
                    "paired permutation methods support only a zero "
                    "non_inferiority_margin; sign-flip randomization is not calibrated "
                    "for a shifted non-inferiority null"
                )
        if self.advanced_analysis_plan is not None:
            self._validate_advanced_analysis_plan()
            if self.schema_version == SCHEMA_VERSION:
                self._validate_current_advanced_analysis_contract()
        _require_current_live_protocol_plan_versions(self)
        return self

    def _validate_current_advanced_analysis_contract(self) -> None:
        if self.advanced_analysis_plan is None:
            return
        for endpoint in self.advanced_analysis_plan.endpoints:
            if endpoint.analysis_method == _LEGACY_RARE_EVENT_ANALYSIS_METHOD:
                raise ValueError(
                    "current rare-event endpoints require "
                    "analysis_method='clopper_pearson_exact_one_sided'"
                )
            if (
                endpoint.analysis_method == _CURRENT_RARE_EVENT_ANALYSIS_METHOD
                and endpoint.exposure_unit != "independence_cluster"
            ):
                raise ValueError(
                    "clopper_pearson_exact_one_sided requires exposure_unit='independence_cluster'"
                )
        confirmatory = tuple(
            endpoint
            for endpoint in self.advanced_analysis_plan.endpoints
            if endpoint.interpretation == "confirmatory"
        )
        if self.advanced_analysis_plan.multiplicity_method != "bonferroni" or not confirmatory:
            return
        adjusted_alpha = Decimal(self.advanced_analysis_plan.familywise_alpha) / Decimal(
            len(confirmatory)
        )
        if adjusted_alpha.quantize(
            Decimal("0.000001"),
            rounding=ROUND_FLOOR,
        ) == Decimal("0"):
            raise ValueError(
                "Bonferroni-adjusted alpha is below the persisted six-decimal precision"
            )

    def _validate_advanced_analysis_plan(self) -> None:
        if self.advanced_analysis_plan is None:
            raise ValueError("advanced_analysis_plan is required for advanced analysis")
        if self.analysis_method in {
            "paired_cluster_permutation_exact",
            "paired_cluster_permutation_monte_carlo",
        }:
            primary = next(
                endpoint
                for endpoint in self.advanced_analysis_plan.endpoints
                if endpoint.role == "primary"
            )
            if primary.exchangeability_assumption != "baseline_candidate_relabeling":
                raise ValueError(
                    "paired permutation primary analysis requires a predeclared "
                    "baseline_candidate_relabeling exchangeability assumption"
                )
            if primary.endpoint_kind != "expectation_pass_rate":
                raise ValueError(
                    "paired permutation comparison currently supports only an "
                    "expectation_pass_rate primary endpoint"
                )
        for endpoint in self.advanced_analysis_plan.endpoints:
            if (
                endpoint.interpretation == "confirmatory"
                and endpoint.minimum_clusters > self.planned_clusters
            ):
                raise ValueError(
                    "confirmatory endpoint minimum_clusters cannot exceed planned_clusters"
                )
            if endpoint.role == "primary" and endpoint.endpoint_kind != self.primary_endpoint:
                raise ValueError("primary advanced endpoint must match primary_endpoint")


class LiveRate(PersistedArtifact):
    artifact_kind: Literal["live-rate"] = "live-rate"
    label: str = Field(min_length=1)
    numerator: int = Field(ge=0)
    denominator: int = Field(ge=0)
    cluster_count: int = Field(ge=0)
    effective_n: DecimalString = Field(pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$")
    design_effect: DecimalString = Field(pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$")
    largest_cluster_size: int = Field(ge=0)
    largest_cluster_design_effect: DecimalString = Field(
        pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    largest_cluster_effective_n: DecimalString = Field(
        pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    assumed_intraclass_correlation: Fraction6String = Field(pattern=r"^0\.[0-9]{6}$")
    analysis_method: str = Field(min_length=1)
    exploratory: bool = False
    rate: UnitInterval6String
    cluster_mean_rate: UnitInterval6String
    interval_center: Literal["cluster_mean_rate", "pooled_rate"] = "cluster_mean_rate"
    interval_center_value: UnitInterval6String
    confidence_level: Literal["0.950000"] = "0.950000"
    ci_lower: UnitInterval6String
    ci_upper: UnitInterval6String

    @model_validator(mode="after")
    def _validate_zero_denominator_rate(self) -> LiveRate:
        if self.schema_version not in V063_CONTRACT_SCHEMA_VERSIONS or self.denominator != 0:
            return self
        if self.analysis_method != "fixed_reference":
            raise ValueError(
                "current live rates with denominator=0 must use the "
                "fixed_reference point-value representation"
            )
        point_values = {
            self.rate,
            self.cluster_mean_rate,
            self.interval_center_value,
            self.ci_lower,
            self.ci_upper,
        }
        if (
            self.numerator != 0
            or self.cluster_count != 0
            or self.effective_n != "0.000000"
            or self.design_effect != "1.000000"
            or self.largest_cluster_size != 0
            or self.largest_cluster_design_effect != "1.000000"
            or self.largest_cluster_effective_n != "0.000000"
            or self.exploratory
            or self.interval_center != "pooled_rate"
            or len(point_values) != 1
        ):
            raise ValueError(
                "fixed_reference zero-denominator live rates must be count-free point values"
            )
        return self

    @model_validator(mode="after")
    def _validate_current_positive_denominator_identity(self) -> LiveRate:
        if (
            self.schema_version != _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION
            or self.denominator == 0
        ):
            return self
        _require_positive_live_rate_identity(self)
        return self

    @model_validator(mode="after")
    def _validate_legacy_identity(self) -> LiveRate:
        from agent_assure.live.legacy_validation import validate_legacy_live_rate

        validate_legacy_live_rate(self)
        return self


@with_live_decimal_context
def _require_positive_live_rate_identity(rate: LiveRate) -> None:
    if rate.numerator > rate.denominator:
        raise ValueError("live rate numerator cannot exceed denominator")
    if not 1 <= rate.cluster_count <= rate.denominator:
        raise ValueError(
            "positive-denominator live rates require cluster_count between one and denominator"
        )

    minimum_largest_cluster = (rate.denominator + rate.cluster_count - 1) // rate.cluster_count
    maximum_largest_cluster = rate.denominator - rate.cluster_count + 1
    if not minimum_largest_cluster <= rate.largest_cluster_size <= maximum_largest_cluster:
        raise ValueError("largest_cluster_size is impossible for denominator and cluster_count")

    expected_rate = _validated_rate_string(rate.numerator, rate.denominator)
    if rate.rate != expected_rate:
        raise ValueError("live rate does not match numerator and denominator")
    expected_center = (
        rate.cluster_mean_rate if rate.interval_center == "cluster_mean_rate" else rate.rate
    )
    if rate.interval_center_value != expected_center:
        raise ValueError("live rate interval_center_value does not match interval_center")
    if Decimal(rate.ci_lower) > Decimal(rate.ci_upper):
        raise ValueError("live rate confidence interval endpoints are reversed")

    denominator = Decimal(rate.denominator)
    cluster_count = Decimal(rate.cluster_count)
    intraclass_correlation = Decimal(rate.assumed_intraclass_correlation)
    design_effect = (
        Decimal("1") + (denominator / cluster_count - Decimal("1")) * intraclass_correlation
    )
    largest_cluster_design_effect = (
        Decimal("1") + (Decimal(rate.largest_cluster_size) - Decimal("1")) * intraclass_correlation
    )
    expected_derived = (
        decimal_string(denominator / design_effect),
        decimal_string(design_effect),
        decimal_string(largest_cluster_design_effect),
        decimal_string(denominator / largest_cluster_design_effect),
    )
    persisted_derived = (
        rate.effective_n,
        rate.design_effect,
        rate.largest_cluster_design_effect,
        rate.largest_cluster_effective_n,
    )
    if persisted_derived != expected_derived:
        raise ValueError(
            "live rate effective sample sizes and design effects do not match "
            "the persisted cluster counts and intraclass correlation"
        )


@with_live_decimal_context
def _require_current_live_distribution_identity(distribution: LiveDistribution) -> None:
    statistics = (
        distribution.min,
        distribution.p50,
        distribution.p95,
        distribution.max,
        distribution.mean,
        distribution.total,
    )
    if distribution.count == 0:
        if any(value is not None for value in statistics):
            raise ValueError("zero-count live distributions must not contain statistics")
        return
    if any(value is None for value in statistics):
        raise ValueError("positive-count live distributions require all statistics")
    persisted = tuple(Decimal(value) for value in statistics if value is not None)
    minimum, p50, p95, maximum, mean, total = persisted
    if not minimum <= p50 <= p95 <= maximum:
        raise ValueError("live distribution quantiles must be monotonically ordered")
    if not minimum <= mean <= maximum:
        raise ValueError("live distribution mean must lie between min and max")
    rounding_tolerance = Decimal("0.0000005") * Decimal(distribution.count + 1)
    if abs(total - mean * Decimal(distribution.count)) > rounding_tolerance:
        raise ValueError("live distribution total and mean are inconsistent with count")


class LiveDistribution(PersistedArtifact):
    artifact_kind: Literal["live-distribution"] = "live-distribution"
    metric: Literal["latency_ms", "estimated_cost_usd"]
    count: int = Field(ge=0)
    min: DecimalString | None = Field(default=None, pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$")
    p50: DecimalString | None = Field(default=None, pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$")
    p95: DecimalString | None = Field(default=None, pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$")
    max: DecimalString | None = Field(default=None, pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$")
    mean: DecimalString | None = Field(default=None, pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$")
    total: DecimalString | None = Field(default=None, pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$")

    @model_validator(mode="after")
    @with_live_decimal_context
    def _validate_current_distribution(self) -> LiveDistribution:
        if self.schema_version != _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION:
            return self
        _require_current_live_distribution_identity(self)
        return self

    @model_validator(mode="after")
    def _validate_legacy_distribution(self) -> LiveDistribution:
        from agent_assure.live.legacy_validation import validate_legacy_live_distribution

        validate_legacy_live_distribution(self)
        return self


class LiveObservationResult(PersistedArtifact):
    model_config = ConfigDict(json_schema_extra=_live_observation_schema_extra)

    artifact_kind: Literal["live-observation-result"] = "live-observation-result"
    observation_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    case_id: str = Field(min_length=1)
    repetition_index: int = Field(ge=0)
    schedule_index: int | None = Field(default=None, ge=0)
    randomization_block_id: str | None = Field(default=None, min_length=1)
    prompt_digest: DigestHex | None = None
    provider: str | None = None
    model: str | None = None
    resolved_model: str | None = None
    provider_api_version: str | None = None
    provider_sdk: str | None = None
    provider_region: str | None = None
    adapter_id: str | None = None
    pipeline_id: str = Field(min_length=1)
    cluster_id: str = Field(min_length=1)
    source_group_id: str | None = None
    started_at_utc: str | None = None
    completed_at_utc: str | None = None
    observation_status: Literal["included", "excluded"] = "included"
    exclusion_reason: str | None = None
    attempt_count: int | None = Field(default=None, ge=1)
    retry_count: int | None = Field(default=None, ge=0)
    rate_limit_events: int | None = Field(default=None, ge=0)
    tool_schema_digest: DigestHex
    policy_bundle_digest: DigestHex
    # Current live reports persist the non-sensitive sufficient statistics used
    # to derive aggregate outcomes and resource distributions. Historical
    # observations did not carry these fields, so they remain nullable at the
    # leaf model and are required by the current parent-report contract below.
    outcome: str | None = Field(default=None, max_length=MAX_LABEL_CHARS)
    latency_ms: int | None = Field(default=None, ge=0)
    estimated_cost_usd: DecimalString | None = Field(
        default=None,
        pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    estimated_cost_picousd: int | None = Field(default=None, ge=0)
    state: GateState
    reason_codes: tuple[ReasonCode, ...] = Field(default=(), max_length=len(ReasonCode))
    findings: tuple[Finding, ...] = ()

    @field_validator("state", mode="before")
    @classmethod
    def _coerce_state(cls, value: object) -> GateState:
        return coerce_enum(GateState, value)

    @field_validator("reason_codes", mode="before")
    @classmethod
    def _coerce_reason_codes(cls, value: object) -> object:
        if isinstance(value, list | tuple):
            return tuple(coerce_enum(ReasonCode, item) for item in value)
        return value

    @field_validator("findings", mode="before")
    @classmethod
    def _coerce_findings(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_current_machine_identifiers(self) -> LiveObservationResult:
        if self.schema_version == _BOUNDED_PROVIDER_METADATA_SCHEMA_VERSION:
            for field_name in _LIVE_OBSERVATION_PROVIDER_METADATA_FIELDS:
                value = getattr(self, field_name)
                if value is not None:
                    _validate_provider_metadata_identifier(
                        value,
                        metadata_field=field_name,
                        field_name=field_name,
                    )
        return self

    @model_validator(mode="after")
    def _require_current_pairing_identity(self) -> LiveObservationResult:
        if self.schema_version in _V06_BINDING_SCHEMA_VERSIONS and (
            self.schedule_index is None
            or self.randomization_block_id is None
            or self.prompt_digest is None
        ):
            raise ValueError(
                "v0.6 live observations require prompt, schedule, and randomization identity"
            )
        return self

    @model_validator(mode="after")
    def _require_current_exact_cost_identity(self) -> LiveObservationResult:
        if (
            self.schema_version != _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION
            or self.estimated_cost_picousd is None
        ):
            return self
        if self.estimated_cost_usd is None:
            raise ValueError("estimated_cost_picousd requires estimated_cost_usd")
        if usd_six_from_picousd(self.estimated_cost_picousd) != self.estimated_cost_usd:
            raise ValueError(
                "estimated_cost_usd must be the half-even six-decimal projection of "
                "estimated_cost_picousd"
            )
        return self


class LiveGroupSummary(PersistedArtifact):
    model_config = ConfigDict(json_schema_extra=_live_group_schema_extra)

    artifact_kind: Literal["live-group-summary"] = "live-group-summary"
    group_id: str = Field(min_length=1)
    provider: str | None = None
    model: str | None = None
    adapter_id: str | None = None
    pipeline_id: str = Field(min_length=1)
    observations: int = Field(ge=0)
    included_observations: int = Field(ge=0)
    excluded_observations: int = Field(ge=0)
    cluster_count: int = Field(ge=0)
    effective_n: DecimalString = Field(pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$")
    design_effect: DecimalString = Field(pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$")
    exclusion_rate: LiveRate
    expectation_pass_rate: LiveRate
    outcome_rates: tuple[LiveRate, ...] = Field(
        default=(),
        max_length=MAX_LIVE_OUTCOME_CATEGORIES,
    )
    reason_code_rates: tuple[LiveRate, ...] = Field(
        default=(),
        max_length=len(ReasonCode),
    )
    latency_ms: LiveDistribution
    estimated_cost_usd: LiveDistribution

    @field_validator("outcome_rates", "reason_code_rates", mode="before")
    @classmethod
    def _coerce_rates(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_current_machine_identifiers(self) -> LiveGroupSummary:
        if self.schema_version == _BOUNDED_PROVIDER_METADATA_SCHEMA_VERSION:
            for field_name in _LIVE_GROUP_PROVIDER_METADATA_FIELDS:
                value = getattr(self, field_name)
                if value is not None:
                    _validate_provider_metadata_identifier(
                        value,
                        metadata_field=field_name,
                        field_name=field_name,
                    )
        return self


def _live_observation_group_id(observation: LiveObservationResult) -> str:
    return "|".join(
        (
            f"provider={observation.provider or 'unknown'}",
            f"model={observation.model or 'unknown'}",
            f"adapter={observation.adapter_id or 'unknown'}",
            f"pipeline={observation.pipeline_id or 'unknown'}",
        )
    )


@with_live_decimal_context
def _require_live_rate_identity(
    rate: LiveRate,
    *,
    label: str,
    numerator: int,
    denominator: int,
    owner: str,
) -> None:
    if rate.label != label:
        raise ValueError(f"{owner} rate label must be {label!r}")
    if rate.numerator != numerator:
        raise ValueError(f"{owner} {label} rate numerator does not match observations")
    if rate.denominator != denominator:
        raise ValueError(f"{owner} {label} rate denominator does not match observations")
    expected_rate = (
        decimal_string(Decimal(numerator) / Decimal(denominator))
        if denominator
        else decimal_string(Decimal("0"))
    )
    if rate.rate != expected_rate:
        raise ValueError(f"{owner} {label} rate does not match numerator and denominator")


def _require_live_group_summary_identity(
    summary: LiveGroupSummary,
    observations: tuple[LiveObservationResult, ...],
    *,
    owner: str,
) -> None:
    included = tuple(
        observation for observation in observations if observation.observation_status == "included"
    )
    excluded_count = len(observations) - len(included)
    if summary.observations != len(observations):
        raise ValueError(f"{owner} observations count does not match observations")
    if summary.included_observations != len(included):
        raise ValueError(f"{owner} included_observations count does not match observations")
    if summary.excluded_observations != excluded_count:
        raise ValueError(f"{owner} excluded_observations count does not match observations")

    _require_live_rate_identity(
        summary.exclusion_rate,
        label="exclusion",
        numerator=excluded_count,
        denominator=len(observations),
        owner=owner,
    )
    _require_live_rate_identity(
        summary.expectation_pass_rate,
        label="expectation_pass",
        numerator=sum(1 for observation in included if observation.state is GateState.pass_),
        denominator=len(included),
        owner=owner,
    )

    reason_counts = {
        reason_code: sum(1 for observation in included if reason_code in observation.reason_codes)
        for reason_code in {
            reason_code for observation in included for reason_code in observation.reason_codes
        }
    }
    reason_rates_by_label: dict[str, LiveRate] = {}
    for rate in summary.reason_code_rates:
        if rate.label in reason_rates_by_label:
            raise ValueError(f"{owner} contains duplicate reason-code rate labels")
        reason_rates_by_label[rate.label] = rate
    expected_labels = {f"reason_code:{reason_code.value}" for reason_code in reason_counts}
    if set(reason_rates_by_label) != expected_labels:
        raise ValueError(f"{owner} reason-code rates do not match observations")
    for reason_code, numerator in reason_counts.items():
        label = f"reason_code:{reason_code.value}"
        _require_live_rate_identity(
            reason_rates_by_label[label],
            label=label,
            numerator=numerator,
            denominator=len(included),
            owner=owner,
        )


class LiveEvaluationReport(PersistedArtifact):
    model_config = ConfigDict(json_schema_extra=_live_evaluation_schema_extra)

    artifact_kind: Literal["live-evaluation-report"] = "live-evaluation-report"
    runset_id: str = Field(min_length=1)
    suite_id: str = Field(min_length=1)
    suite_version: str = Field(min_length=1)
    suite_digest: DigestHex | None = None
    configuration_digest: DigestHex | None = None
    source_runset_digest: DigestHex | None = None
    source_completion_status: Literal["complete", "incomplete"] | None = None
    protocol_id: str | None = None
    protocol_digest: DigestHex | None = None
    protocol: LiveProtocolRecord | None = None
    baseline_mode: Literal["concurrent_paired", "fixed_reference"] | None = None
    analysis_method: str = Field(default="cluster_t_interval", min_length=1)
    exploratory: bool = True
    cluster_by: Literal["case_id", "source_group_id"] = "case_id"
    planned_repetitions: int | None = Field(default=None, ge=1)
    planned_observations: int | None = Field(default=None, ge=1)
    planned_clusters: int | None = Field(default=None, ge=1)
    completion_status: Literal["complete", "incomplete"] = "complete"
    stop_reasons: tuple[str, ...] = ()
    budget_exceeded: bool = False
    state: GateState
    confidence_level: Literal["0.950000"] = "0.950000"
    observations: tuple[LiveObservationResult, ...] = Field(
        max_length=MAX_PERSISTED_OBSERVATIONS,
    )
    overall: LiveGroupSummary
    groups: tuple[LiveGroupSummary, ...] = Field(max_length=MAX_PERSISTED_OBSERVATIONS)
    statistical_invariants: tuple[StatisticalInvariantResult, ...] = Field(
        default=(),
        max_length=MAX_LIVE_ADVANCED_ENDPOINTS,
    )
    limitations: tuple[str, ...] = (
        "live evaluation is time-bound to the declared provider, model, adapter, "
        "configuration, and execution window",
        "aggregate rates do not certify safety, compliance, clinical validity, or provider "
        "superiority in general",
        "design-effect and effective-n fields are planning and sensitivity metadata; "
        "cluster intervals use the declared empirical cluster-rate method",
        "the current protocol schema does not carry an execution-configuration digest; "
        "configuration_digest records the executed configuration and exact prompt manifest "
        "but cannot prove that configuration was frozen in the protocol before execution",
    )

    @model_validator(mode="before")
    @classmethod
    def _preflight_current_exact_bound_work(cls, value: object) -> object:
        work_items = _current_rare_event_work_items(value)
        if work_items:
            validate_clopper_pearson_work_budget(work_items)
        return value

    @field_validator(
        "observations",
        "groups",
        "statistical_invariants",
        "limitations",
        "stop_reasons",
        mode="before",
    )
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @field_validator("state", mode="before")
    @classmethod
    def _coerce_state(cls, value: object) -> GateState:
        return coerce_enum(GateState, value)

    @model_validator(mode="after")
    def _require_current_execution_binding(self) -> LiveEvaluationReport:
        if self.schema_version in _V06_BINDING_SCHEMA_VERSIONS and (
            self.suite_digest is None or self.configuration_digest is None
        ):
            raise ValueError("v0.6 live evaluation reports require suite and configuration digests")
        return self

    @model_validator(mode="after")
    def _require_current_derivation_binding(self) -> LiveEvaluationReport:
        if self.schema_version != _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION:
            return self
        if self.source_runset_digest is None or self.source_completion_status is None:
            raise ValueError(
                "current live evaluation reports require source RunSet digest and completion status"
            )
        if self.protocol is None:
            raise ValueError("current live evaluation reports require the bound protocol record")
        if self.protocol.schema_version != _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION:
            raise ValueError(
                "current live evaluation reports require a current bound protocol record"
            )
        _require_current_live_protocol_plan_versions(self.protocol)
        if any(observation.outcome is None for observation in self.observations):
            raise ValueError(
                "current live evaluation observations require outcome sufficient statistics"
            )
        return self

    @model_validator(mode="after")
    def _require_current_observation_protocol_coherence(self) -> LiveEvaluationReport:
        if self.schema_version != _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION:
            return self
        from agent_assure.live.statistics import (
            verify_persisted_observation_protocol_coherence,
        )

        verify_persisted_observation_protocol_coherence(self)
        return self

    @model_validator(mode="after")
    def _require_current_nested_pairing_identity(self) -> LiveEvaluationReport:
        if self.schema_version != _BOUNDED_PROVIDER_METADATA_SCHEMA_VERSION:
            return self
        for observation in self.observations:
            if (
                observation.schedule_index is None
                or observation.randomization_block_id is None
                or observation.prompt_digest is None
            ):
                raise ValueError(
                    "current live evaluation reports require embedded observations to carry "
                    "prompt, schedule, and randomization identity"
                )
        return self

    @model_validator(mode="after")
    def _validate_current_nested_machine_identifiers(self) -> LiveEvaluationReport:
        if self.schema_version != _BOUNDED_PROVIDER_METADATA_SCHEMA_VERSION:
            return self
        for index, observation in enumerate(self.observations):
            for field_name in _LIVE_OBSERVATION_PROVIDER_METADATA_FIELDS:
                value = getattr(observation, field_name)
                if value is not None:
                    _validate_provider_metadata_identifier(
                        value,
                        metadata_field=field_name,
                        field_name=f"observations[{index}].{field_name}",
                    )
        for field_name in _LIVE_GROUP_PROVIDER_METADATA_FIELDS:
            value = getattr(self.overall, field_name)
            if value is not None:
                _validate_provider_metadata_identifier(
                    value,
                    metadata_field=field_name,
                    field_name=f"overall.{field_name}",
                )
        for index, group in enumerate(self.groups):
            for field_name in _LIVE_GROUP_PROVIDER_METADATA_FIELDS:
                value = getattr(group, field_name)
                if value is not None:
                    _validate_provider_metadata_identifier(
                        value,
                        metadata_field=field_name,
                        field_name=f"groups[{index}].{field_name}",
                    )
        return self

    @model_validator(mode="after")
    def _validate_current_rare_event_bounds(self) -> LiveEvaluationReport:
        if self.schema_version != _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION:
            return self
        endpoint_ids = [invariant.endpoint_id for invariant in self.statistical_invariants]
        if len(endpoint_ids) != len(set(endpoint_ids)):
            raise ValueError("current live evaluation report endpoint_id values must be unique")
        for index, invariant in enumerate(self.statistical_invariants):
            _require_current_statistical_invariant_identity(
                invariant,
                owner=f"statistical_invariants[{index}]",
            )
        return self

    @model_validator(mode="after")
    def _require_unique_observation_identity(self) -> LiveEvaluationReport:
        observation_ids: set[str] = set()
        run_ids: set[str] = set()
        schedule_identities: set[tuple[str, int, int | None, str | None, str | None]] = set()
        for observation in self.observations:
            if observation.observation_id in observation_ids:
                raise ValueError("live evaluation report contains duplicate observation_id")
            observation_ids.add(observation.observation_id)
            if observation.run_id in run_ids:
                raise ValueError("live evaluation report contains duplicate run_id")
            run_ids.add(observation.run_id)
            schedule_identity = (
                observation.case_id,
                observation.repetition_index,
                observation.schedule_index,
                observation.randomization_block_id,
                observation.prompt_digest,
            )
            if schedule_identity in schedule_identities:
                raise ValueError(
                    "live evaluation report contains duplicate prompt and schedule identity"
                )
            schedule_identities.add(schedule_identity)
        return self

    @model_validator(mode="after")
    def _require_derivable_summary_consistency(self) -> LiveEvaluationReport:
        if self.schema_version not in _V06_BINDING_SCHEMA_VERSIONS:
            return self
        if self.overall.group_id != "overall":
            raise ValueError("live evaluation overall summary must use group_id 'overall'")
        _require_live_group_summary_identity(
            self.overall,
            self.observations,
            owner="live evaluation overall summary",
        )

        observations_by_group: dict[str, list[LiveObservationResult]] = {}
        for observation in self.observations:
            group_id = _live_observation_group_id(observation)
            observations_by_group.setdefault(group_id, []).append(observation)
        groups_by_id: dict[str, LiveGroupSummary] = {}
        for group in self.groups:
            if group.group_id in groups_by_id:
                raise ValueError("live evaluation report contains duplicate group_id")
            groups_by_id[group.group_id] = group
        if set(groups_by_id) != set(observations_by_group):
            raise ValueError(
                "live evaluation report group summaries do not match observation groups"
            )
        for group_id, group_observations in observations_by_group.items():
            _require_live_group_summary_identity(
                groups_by_id[group_id],
                tuple(group_observations),
                owner=f"live evaluation group {group_id!r}",
            )
        return self

    @model_validator(mode="after")
    def _require_current_full_derivation_consistency(self) -> LiveEvaluationReport:
        if self.schema_version != _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION:
            return self
        # Delayed import avoids a module-initialization cycle while keeping the
        # generator and persisted verifier on one derivation implementation.
        from agent_assure.live.statistics import verify_live_evaluation_report_derivation

        verify_live_evaluation_report_derivation(self)
        return self

    @model_validator(mode="after")
    def _require_legacy_derivation_consistency(self) -> LiveEvaluationReport:
        from agent_assure.live.legacy_validation import (
            validate_legacy_live_evaluation_report,
        )

        validate_legacy_live_evaluation_report(self)
        return self


class PairedClusterRate(PersistedArtifact):
    """Canonical sufficient statistic for one paired comparison cluster."""

    artifact_kind: Literal["paired-cluster-rate"] = "paired-cluster-rate"
    cluster_id: str = Field(min_length=1, max_length=MAX_LABEL_CHARS)
    baseline_numerator: int | None = Field(default=None, ge=0)
    baseline_denominator: int | None = Field(default=None, ge=0)
    candidate_numerator: int | None = Field(default=None, ge=0)
    candidate_denominator: int | None = Field(default=None, ge=0)
    baseline_rate: UnitInterval6String
    candidate_rate: UnitInterval6String
    difference: SignedUnitInterval6String

    @model_validator(mode="after")
    def _validate_current_count_rates(self) -> PairedClusterRate:
        if self.schema_version != _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION:
            return self
        counts = (
            self.baseline_numerator,
            self.baseline_denominator,
            self.candidate_numerator,
            self.candidate_denominator,
        )
        if any(value is None for value in counts):
            raise ValueError("current paired cluster rates require per-arm count evidence")
        for owner, numerator, denominator, rate in (
            (
                "baseline",
                self.baseline_numerator,
                self.baseline_denominator,
                self.baseline_rate,
            ),
            (
                "candidate",
                self.candidate_numerator,
                self.candidate_denominator,
                self.candidate_rate,
            ),
        ):
            assert numerator is not None and denominator is not None
            if numerator > denominator:
                raise ValueError(f"paired cluster {owner} numerator cannot exceed denominator")
            if denominator == 0:
                if numerator != 0:
                    raise ValueError(
                        f"paired cluster {owner} zero denominator requires zero events"
                    )
                continue
            if rate != _validated_rate_string(numerator, denominator):
                raise ValueError(
                    f"paired cluster {owner} rate does not match numerator and denominator"
                )
        return self

    @model_validator(mode="after")
    @with_live_decimal_context
    def _validate_difference(self) -> PairedClusterRate:
        if self.schema_version == _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION:
            assert self.baseline_numerator is not None
            assert self.baseline_denominator is not None
            assert self.candidate_numerator is not None
            assert self.candidate_denominator is not None
            baseline_rate = (
                _decimal(self.baseline_rate)
                if self.baseline_denominator == 0
                else Decimal(self.baseline_numerator) / Decimal(self.baseline_denominator)
            )
            candidate_rate = (
                _decimal(self.candidate_rate)
                if self.candidate_denominator == 0
                else Decimal(self.candidate_numerator) / Decimal(self.candidate_denominator)
            )
        else:
            baseline_rate = _decimal(self.baseline_rate)
            candidate_rate = _decimal(self.candidate_rate)
        expected = _decimal_string(candidate_rate - baseline_rate)
        if self.difference != expected:
            raise ValueError("paired cluster difference must equal candidate minus baseline")
        return self


@with_live_decimal_context
def _require_current_comparison_rate_identity(
    rate: LiveRate,
    *,
    owner: str,
    allow_fixed_reference: bool,
) -> None:
    if rate.denominator == 0:
        if not allow_fixed_reference or rate.analysis_method != "fixed_reference":
            raise ValueError(f"{owner} zero denominator is not a fixed reference")
        point_values = {
            rate.rate,
            rate.cluster_mean_rate,
            rate.interval_center_value,
            rate.ci_lower,
            rate.ci_upper,
        }
        if (
            rate.numerator != 0
            or rate.cluster_count != 0
            or rate.effective_n != "0.000000"
            or rate.design_effect != "1.000000"
            or rate.largest_cluster_size != 0
            or rate.largest_cluster_design_effect != "1.000000"
            or rate.largest_cluster_effective_n != "0.000000"
            or rate.exploratory
            or rate.interval_center != "pooled_rate"
            or len(point_values) != 1
        ):
            raise ValueError(f"{owner} fixed-reference representation is inconsistent")
        return
    try:
        _require_positive_live_rate_identity(rate)
    except ValueError as error:
        raise ValueError(f"{owner} is inconsistent: {error}") from error


@with_live_decimal_context
def _require_current_live_comparison_identity(report: LiveComparisonReport) -> None:
    nested_artifacts: tuple[PersistedArtifact, ...] = (
        report.baseline_pass_rate,
        report.candidate_pass_rate,
        *report.paired_clusters,
        *report.randomization_tests,
    )
    if any(
        artifact.schema_version != _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION
        for artifact in nested_artifacts
    ):
        raise ValueError("current live comparisons require current nested statistical artifacts")
    fixed_reference = report.baseline_mode == "fixed_reference"
    allowed_methods = (
        _CURRENT_FIXED_REFERENCE_COMPARISON_METHODS
        if fixed_reference
        else _CURRENT_CONCURRENT_COMPARISON_METHODS
    )
    if report.analysis_method not in allowed_methods:
        raise ValueError(
            f"{report.baseline_mode} baseline_mode has an inconsistent comparison analysis_method"
        )
    _require_current_comparison_rate_identity(
        report.baseline_pass_rate,
        owner="baseline_pass_rate",
        allow_fixed_reference=fixed_reference,
    )
    _require_current_comparison_rate_identity(
        report.candidate_pass_rate,
        owner="candidate_pass_rate",
        allow_fixed_reference=False,
    )
    expected_baseline_label = (
        "fixed_reference_expectation_pass" if fixed_reference else "expectation_pass"
    )
    if report.baseline_pass_rate.label != expected_baseline_label:
        raise ValueError("baseline_pass_rate label is inconsistent with baseline_mode")
    if report.candidate_pass_rate.label != "expectation_pass":
        raise ValueError("candidate_pass_rate label must be 'expectation_pass'")
    if fixed_reference:
        if report.fixed_reference_pass_rate != report.baseline_pass_rate.rate:
            raise ValueError("fixed reference value does not match baseline_pass_rate")
    elif report.fixed_reference_pass_rate is not None:
        raise ValueError("concurrent paired comparison cannot carry a fixed reference")

    if report.compared_clusters > 0:
        if fixed_reference:
            if report.compared_clusters != report.candidate_pass_rate.cluster_count:
                raise ValueError("compared_clusters does not match the candidate arm cluster_count")
        elif report.compared_clusters > min(
            report.baseline_pass_rate.cluster_count,
            report.candidate_pass_rate.cluster_count,
        ):
            raise ValueError("compared_clusters cannot exceed either arm cluster_count")

    persisted_difference = Decimal(report.pass_rate_difference)
    projected_difference = Decimal(report.candidate_pass_rate.cluster_mean_rate) - Decimal(
        report.baseline_pass_rate.cluster_mean_rate
    )
    if abs(persisted_difference - projected_difference) > Decimal("0.000002"):
        raise ValueError("pass_rate_difference does not match candidate minus baseline")
    if Decimal(report.difference_ci_lower) > Decimal(report.difference_ci_upper):
        raise ValueError("comparison confidence interval endpoints are reversed")
    expected_effective_n = Decimal("0")
    if report.compared_clusters > 0:
        expected_effective_n = (
            Decimal(report.candidate_pass_rate.effective_n)
            if fixed_reference
            else min(
                Decimal(report.baseline_pass_rate.effective_n),
                Decimal(report.candidate_pass_rate.effective_n),
            )
        )
    if report.effective_n != decimal_string(expected_effective_n):
        raise ValueError("comparison effective_n is inconsistent with its arms")

    is_randomization = report.analysis_method in _PAIRED_RANDOMIZATION_METHODS
    expected_randomization_tests = int(is_randomization and report.compared_clusters > 0)
    if len(report.randomization_tests) != expected_randomization_tests:
        raise ValueError("comparison randomization test cardinality is inconsistent")
    for result in report.randomization_tests:
        _require_current_randomization_test_identity(result, owner="randomization test")
        if result.analysis_method != report.analysis_method:
            raise ValueError("randomization test analysis_method does not match comparison")
        if result.compared_clusters != report.compared_clusters:
            raise ValueError("randomization test cluster count does not match comparison")
        if result.observed_difference != report.pass_rate_difference:
            raise ValueError("randomization observed_difference does not match comparison")
        if result.non_inferiority_margin != report.non_inferiority_margin:
            raise ValueError("randomization margin does not match comparison")

    if report.state not in {GateState.fail, GateState.not_evaluated}:
        raise ValueError("current exploratory comparison cannot claim a passing gate state")
    if report.compared_clusters == 0:
        if report.state is not GateState.not_evaluated:
            raise ValueError("zero-cluster comparison must be not_evaluated")
        return
    decision_value = (
        persisted_difference if is_randomization else Decimal(report.difference_ci_lower)
    )
    boundary = -Decimal(report.non_inferiority_margin)
    boundary_breached = decision_value < boundary or (
        not is_randomization
        and Decimal(report.non_inferiority_margin) != Decimal("0")
        and decision_value == boundary
    )
    if boundary_breached and report.state is not GateState.fail:
        raise ValueError("comparison gate state understates a non-inferiority breach")
    if (
        is_randomization
        and decision_value > boundary + Decimal("0.000001")
        and report.state is GateState.fail
    ):
        raise ValueError("comparison gate state claims an impossible non-inferiority breach")
    if (
        not is_randomization
        and not boundary_breached
        and report.state is not GateState.not_evaluated
    ):
        raise ValueError("exploratory interval comparison must be not_evaluated")


class LiveComparisonReport(PersistedArtifact):
    model_config = ConfigDict(json_schema_extra=_live_comparison_schema_extra)

    artifact_kind: Literal["live-comparison-report"] = "live-comparison-report"
    derivation_contract: Literal["agent-assure/live-comparison/v1"] | None = None
    baseline_runset_id: str = Field(min_length=1)
    candidate_runset_id: str = Field(min_length=1)
    baseline_evaluation_digest: DigestHex | None = None
    candidate_evaluation_digest: DigestHex | None = None
    baseline_completion_status: Literal["complete", "incomplete"] | None = None
    candidate_completion_status: Literal["complete", "incomplete"] | None = None
    baseline_stop_reasons: tuple[str, ...] = ()
    candidate_stop_reasons: tuple[str, ...] = ()
    suite_id: str = Field(min_length=1)
    suite_version: str = Field(min_length=1)
    baseline_group_id: str = Field(min_length=1)
    candidate_group_id: str = Field(min_length=1)
    protocol_id: str = Field(min_length=1)
    protocol_digest: DigestHex
    protocol: LiveProtocolRecord | None = None
    baseline_mode: Literal["concurrent_paired", "fixed_reference"]
    analysis_method: str = Field(min_length=1)
    exploratory: bool = False
    state: GateState
    confidence_level: Literal["0.950000"] = "0.950000"
    non_inferiority_margin: Fraction6String = Field(pattern=r"^0\.[0-9]{6}$")
    baseline_pass_rate: LiveRate
    candidate_pass_rate: LiveRate
    pass_rate_difference: SignedUnitInterval6String
    difference_ci_lower: SignedUnitInterval6String
    difference_ci_upper: SignedUnitInterval6String
    compared_clusters: int = Field(ge=0)
    effective_n: DecimalString = Field(pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$")
    fixed_reference_pass_rate: UnitInterval6String | None = None
    paired_clusters: tuple[PairedClusterRate, ...] = Field(
        default=(),
        max_length=MAX_PERSISTED_OBSERVATIONS,
    )
    baseline_latency_p50_ms: DecimalString | None = Field(
        default=None,
        pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    candidate_latency_p50_ms: DecimalString | None = Field(
        default=None,
        pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    baseline_cost_total_usd: DecimalString | None = Field(
        default=None,
        pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    candidate_cost_total_usd: DecimalString | None = Field(
        default=None,
        pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    latency_p50_difference_ms: SignedDecimalString | None = Field(
        default=None,
        pattern=r"^-?(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    cost_total_difference_usd: SignedDecimalString | None = Field(
        default=None,
        pattern=r"^-?(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    randomization_tests: tuple[PairedRandomizationTestResult, ...] = Field(
        default=(),
        max_length=1,
    )
    limitations: tuple[str, ...] = (
        "live comparison intervals are descriptive unless the protocol predeclares the "
        "comparison as confirmatory",
    )

    @field_validator("state", mode="before")
    @classmethod
    def _coerce_state(cls, value: object) -> GateState:
        return coerce_enum(GateState, value)

    @field_validator(
        "baseline_stop_reasons",
        "candidate_stop_reasons",
        "paired_clusters",
        "randomization_tests",
        "limitations",
        mode="before",
    )
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_current_relations(self) -> LiveComparisonReport:
        if self.schema_version == _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION:
            _require_current_live_comparison_identity(self)
        return self

    @model_validator(mode="after")
    def _validate_current_derivation(self) -> LiveComparisonReport:
        if self.schema_version != _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION:
            return self
        if (
            self.derivation_contract != "agent-assure/live-comparison/v1"
            or self.baseline_evaluation_digest is None
            or self.candidate_evaluation_digest is None
            or self.baseline_completion_status is None
            or self.candidate_completion_status is None
            or self.protocol is None
        ):
            raise ValueError(
                "current live comparisons require source digests, source status, "
                "bound protocol, and derivation contract"
            )
        if self.protocol.schema_version != _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION:
            raise ValueError("current live comparisons require a current bound protocol record")
        _require_current_live_protocol_plan_versions(self.protocol)
        from agent_assure.live.comparison import verify_live_comparison_report_derivation

        verify_live_comparison_report_derivation(self)
        return self

    @model_validator(mode="after")
    def _validate_legacy_derivation(self) -> LiveComparisonReport:
        from agent_assure.live.legacy_validation import (
            validate_legacy_live_comparison_report,
        )

        validate_legacy_live_comparison_report(self)
        return self


_DRIFT_METRIC_SOURCES = {
    "expectation_pass_rate": "pooled_rate",
    "reason_code_rate": "reason_code_rate",
    "exclusion_rate": "observation_rate",
    "retry_rate": "observation_rate",
    "rate_limit_rate": "observation_rate",
    "latency_p50_ms": "distribution_p50",
    "cost_total_usd": "distribution_total",
}
_DRIFT_RATE_SOURCES = frozenset({"pooled_rate", "observation_rate", "reason_code_rate"})


def _drift_metric_key(
    metric: DriftWindowMetric | DriftMetricDiagnostic,
) -> tuple[DriftMetric, tuple[ReasonCode, ...]]:
    return metric.metric, metric.reason_codes


def _require_nested_report_version(
    nested: PersistedArtifact,
    parent_version: str,
    *,
    owner: str,
) -> None:
    if nested.schema_version != parent_version:
        raise ValueError(f"{owner} schema_version must match its parent report")


@with_live_decimal_context
def _require_current_drift_window_metric_identity(metric: DriftWindowMetric) -> None:
    expected_source = _DRIFT_METRIC_SOURCES[metric.metric]
    if metric.source != expected_source:
        raise ValueError("drift window metric source does not match metric")
    if metric.metric == "reason_code_rate":
        if not metric.reason_codes:
            raise ValueError("reason_code_rate drift metrics require reason_codes")
    elif metric.reason_codes:
        raise ValueError("reason_codes are only valid for reason_code_rate drift metrics")
    if metric.source in _DRIFT_RATE_SOURCES:
        if metric.numerator is None or metric.denominator is None:
            raise ValueError("rate drift metrics require numerator and denominator")
        if metric.numerator > metric.denominator:
            raise ValueError("drift rate numerator cannot exceed denominator")
        if metric.denominator == 0:
            if metric.numerator != 0 or metric.value is not None:
                raise ValueError("zero-denominator drift rates must be zero-count and valueless")
            return
        expected_value = _validated_rate_string(metric.numerator, metric.denominator)
        if metric.value != expected_value:
            raise ValueError("drift rate value does not match numerator and denominator")
        return
    if metric.numerator is not None or metric.denominator is None:
        raise ValueError("distribution drift metrics require only a denominator count")
    if (metric.denominator == 0) != (metric.value is None):
        raise ValueError("distribution drift metric value must match denominator presence")


def _require_current_drift_window_identity(window: DriftWindowSummary) -> None:
    if (
        window.schema_version == _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION
        and window.source_evaluation_completion_status == "complete"
        and window.source_runset_completion_status != "complete"
    ):
        raise ValueError("complete drift source evaluations require a complete source RunSet")
    if window.observations != window.included_observations + window.excluded_observations:
        raise ValueError("drift window observations must equal included plus excluded")
    keys = [_drift_metric_key(metric) for metric in window.metrics]
    if len(keys) != len(set(keys)):
        raise ValueError("drift window metrics must be unique by metric and reason codes")
    for metric in window.metrics:
        _require_current_drift_window_metric_identity(metric)
        if metric.metric in {"expectation_pass_rate", "reason_code_rate"}:
            expected_denominator = window.included_observations
            if metric.denominator != expected_denominator:
                raise ValueError("included-observation drift metric denominator is inconsistent")
        elif metric.metric in {"exclusion_rate", "retry_rate", "rate_limit_rate"}:
            if metric.denominator != window.observations:
                raise ValueError("observation-rate drift metric denominator is inconsistent")
        elif metric.denominator is None or metric.denominator > window.included_observations:
            raise ValueError("distribution drift metric count exceeds included observations")


def _require_current_drift_comparability_identity(
    comparability: DriftComparabilityResult,
) -> None:
    if comparability.configuration_digest_matches is None:
        raise ValueError("current drift comparability requires configuration digest identity")
    material_fields_match = all(
        (
            comparability.suite_matches,
            comparability.baseline_mode_matches,
            comparability.analysis_method_matches,
            comparability.configuration_digest_matches,
            comparability.tool_schema_digest_matches,
            comparability.policy_bundle_digest_matches,
        )
    )
    if comparability.material_fields_match != material_fields_match:
        raise ValueError("drift material_fields_match does not match material comparisons")
    if comparability.compared_windows < 2 and comparability.status != "invalid":
        raise ValueError("fewer than two drift windows require invalid comparability")
    if not material_fields_match and comparability.status != "invalid":
        raise ValueError("material drift mismatches require invalid comparability")
    if comparability.status == "pass":
        if not comparability.protocol_digest_matches or comparability.failures:
            raise ValueError(
                "passing drift comparability requires matching protocol and no failures"
            )
    elif comparability.status == "exploratory":
        if not material_fields_match or comparability.protocol_digest_matches:
            raise ValueError(
                "exploratory drift comparability requires only a protocol-digest mismatch"
            )


def _drift_state_name(metric: DriftMetric) -> str:
    if metric == "expectation_pass_rate":
        return "governance_health"
    if metric in {"reason_code_rate", "exclusion_rate", "retry_rate", "rate_limit_rate"}:
        return "control_reliability"
    return "drift_state"


def _require_current_drift_state_identity(state: DriftStateEstimate) -> None:
    if state.state_name != _drift_state_name(state.metric):
        raise ValueError("drift state name does not match metric")
    estimates = (state.latest_level, state.latest_drift_per_window, state.innovation_variance)
    if any(value is None for value in estimates):
        raise ValueError("current drift state estimates require the complete estimate triplet")
    if Decimal(state.smoothing_alpha) <= Decimal("0"):
        raise ValueError("drift state smoothing_alpha must be greater than zero")


def _require_current_drift_diagnostic_identity(diagnostic: DriftMetricDiagnostic) -> None:
    if len(diagnostic.analysis_methods) != len(set(diagnostic.analysis_methods)):
        raise ValueError("drift diagnostic analysis_methods must be unique")
    if "descriptive_trend" not in diagnostic.analysis_methods:
        raise ValueError("drift diagnostics require the declared descriptive_trend method")
    if diagnostic.metric == "reason_code_rate":
        if not diagnostic.reason_codes:
            raise ValueError("reason_code_rate drift diagnostics require reason_codes")
    elif diagnostic.reason_codes:
        raise ValueError("reason_codes are only valid for reason_code_rate drift diagnostics")
    basic_values = (diagnostic.first_value, diagnostic.last_value, diagnostic.mean_value)
    if diagnostic.windows == 0:
        if diagnostic.observations != 0 or any(value is not None for value in basic_values):
            raise ValueError("empty drift diagnostics must not contain observations or values")
    elif any(value is None for value in basic_values):
        raise ValueError("nonempty drift diagnostics require first, last, and mean values")
    max_step_available = diagnostic.windows >= 2 and diagnostic.missing_windows == 0
    if max_step_available != (diagnostic.max_step_change is not None):
        raise ValueError("drift max_step_change presence must match the available windows")
    if (
        "lag1_autocorrelation" not in diagnostic.analysis_methods
        and diagnostic.lag1_autocorrelation is not None
    ):
        raise ValueError("lag-1 results require the lag1_autocorrelation method")
    ar1_values = (
        diagnostic.ar1_phi,
        diagnostic.ar1_intercept,
        diagnostic.ar1_innovation_variance,
    )
    if any(value is not None for value in ar1_values) and not all(
        value is not None for value in ar1_values
    ):
        raise ValueError("AR(1) drift results must be present or absent as a complete triplet")
    if "ar1_summary" not in diagnostic.analysis_methods and any(
        value is not None for value in ar1_values
    ):
        raise ValueError("AR(1) results require the ar1_summary method")
    if diagnostic.state_estimate is not None:
        if "state_space_ewma" not in diagnostic.analysis_methods:
            raise ValueError("drift state estimates require the state_space_ewma method")
        _require_current_drift_state_identity(diagnostic.state_estimate)
        if (
            diagnostic.state_estimate.metric != diagnostic.metric
            or diagnostic.state_estimate.label != diagnostic.label
            or diagnostic.state_estimate.prerequisite_status != diagnostic.prerequisite_status
        ):
            raise ValueError("drift state estimate identity does not match its diagnostic")
    dependence_declared = bool(
        {"lag1_autocorrelation", "ar1_summary"}.intersection(diagnostic.analysis_methods)
    )
    if diagnostic.stationarity_signal == "not_evaluated":
        raise ValueError("declared descriptive drift analysis requires a stationarity signal")
    if dependence_declared == (diagnostic.dependence_signal == "not_evaluated"):
        raise ValueError(
            "drift dependence signal availability must match the declared dependence methods"
        )
    if diagnostic.prerequisite_status == "invalid":
        expected_dependence_signal = "invalid" if dependence_declared else "not_evaluated"
        if (
            diagnostic.stationarity_signal != "invalid"
            or diagnostic.dependence_signal != expected_dependence_signal
        ):
            raise ValueError("invalid drift prerequisites require invalid diagnostic signals")
    else:
        if "invalid" in {diagnostic.stationarity_signal, diagnostic.dependence_signal}:
            raise ValueError("non-invalid drift prerequisites cannot produce invalid signals")
        has_review_signal = "review" in {
            diagnostic.stationarity_signal,
            diagnostic.dependence_signal,
        }
        if bool(diagnostic.review_reasons) != has_review_signal:
            raise ValueError("drift review reasons must match review signal presence")


@with_live_decimal_context
def _require_current_live_drift_report_identity(report: LiveDriftReport) -> None:
    if report.state is not GateState.not_evaluated:
        raise ValueError("live drift reports must remain non-verdict review artifacts")
    if (
        report.schema_version == _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION
        and report.ordering_variable not in {"window_index", "window_start_utc"}
    ):
        raise ValueError(
            "current live drift reports support only window_index or window_start_utc ordering"
        )
    if not report.windows:
        raise ValueError("live drift reports require at least one window")
    _require_nested_report_version(
        report.comparability,
        report.schema_version,
        owner="drift comparability",
    )
    for window in report.windows:
        _require_nested_report_version(
            window,
            report.schema_version,
            owner="drift window",
        )
        for metric in window.metrics:
            _require_nested_report_version(
                metric,
                report.schema_version,
                owner="drift window metric",
            )
    for diagnostic in report.diagnostics:
        _require_nested_report_version(
            diagnostic,
            report.schema_version,
            owner="drift diagnostic",
        )
        if diagnostic.state_estimate is not None:
            _require_nested_report_version(
                diagnostic.state_estimate,
                report.schema_version,
                owner="drift state estimate",
            )
    if tuple(window.window_index for window in report.windows) != tuple(range(len(report.windows))):
        raise ValueError("drift windows must be ordered with contiguous zero-based indexes")
    if any(
        window.suite_id != report.suite_id or window.suite_version != report.suite_version
        for window in report.windows
    ):
        raise ValueError("drift window suite identity does not match the report")
    for window in report.windows:
        _require_current_drift_window_identity(window)
    _require_current_drift_comparability_identity(report.comparability)
    if report.comparability.compared_windows != len(report.windows):
        raise ValueError("drift comparability window count does not match report windows")
    if (
        report.comparability.suite_id != report.suite_id
        or report.comparability.suite_version != report.suite_version
    ):
        raise ValueError("drift comparability suite identity does not match the report")

    if not report.diagnostics:
        raise ValueError("live drift reports require at least one metric diagnostic")
    diagnostic_keys = [_drift_metric_key(diagnostic) for diagnostic in report.diagnostics]
    if len(diagnostic_keys) != len(set(diagnostic_keys)):
        raise ValueError("drift diagnostics must be unique by metric and reason codes")
    expected_keys = set(diagnostic_keys)
    window_metric_maps: list[
        dict[tuple[DriftMetric, tuple[ReasonCode, ...]], DriftWindowMetric]
    ] = []
    for window in report.windows:
        metrics_by_key = {_drift_metric_key(metric): metric for metric in window.metrics}
        if set(metrics_by_key) != expected_keys:
            raise ValueError("every drift window must contain exactly the diagnostic metric set")
        window_metric_maps.append(metrics_by_key)
    for diagnostic in report.diagnostics:
        _require_current_drift_diagnostic_identity(diagnostic)
        key = _drift_metric_key(diagnostic)
        series: list[tuple[str, int]] = []
        for metrics_by_key in window_metric_maps:
            metric = metrics_by_key[key]
            if metric.label != diagnostic.label:
                raise ValueError("drift diagnostic label does not match its window metrics")
            if metric.value is not None:
                series.append((metric.value, metric.denominator or 0))
        if diagnostic.windows != len(series):
            raise ValueError("drift diagnostic window count does not match persisted values")
        if diagnostic.missing_windows != len(report.windows) - len(series):
            raise ValueError("drift diagnostic missing-window count is inconsistent")
        if diagnostic.observations != sum(denominator for _, denominator in series):
            raise ValueError("drift diagnostic observations do not match metric denominators")
        values = tuple(Decimal(value) for value, _ in series)
        expected_first = decimal_string(values[0]) if values else None
        expected_last = decimal_string(values[-1]) if values else None
        expected_mean = (
            decimal_string(sum(values, Decimal("0")) / Decimal(len(values))) if values else None
        )
        expected_max_step = (
            decimal_string(
                max(abs(right - left) for left, right in zip(values, values[1:], strict=False))
            )
            if len(values) >= 2 and diagnostic.missing_windows == 0
            else None
        )
        if (
            diagnostic.first_value != expected_first
            or diagnostic.last_value != expected_last
            or diagnostic.mean_value != expected_mean
            or diagnostic.max_step_change != expected_max_step
        ):
            raise ValueError("drift diagnostic summary does not match window metric values")

    if report.schema_version == _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION:
        if report.drift_plan is None:
            raise ValueError("current live drift reports require their effective drift plan")
        from agent_assure.live.drift import _monitoring_status

        expected_status = _monitoring_status(
            report.drift_plan,
            report.comparability,
            report.diagnostics,
        )
        if report.monitoring_status != expected_status:
            raise ValueError("drift monitoring_status does not match report prerequisites")


class DriftWindowMetric(PersistedArtifact):
    artifact_kind: Literal["drift-window-metric"] = "drift-window-metric"
    metric: DriftMetric
    label: str = Field(min_length=1)
    reason_codes: tuple[ReasonCode, ...] = ()
    value: DecimalString | None = Field(
        default=None,
        pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    numerator: int | None = Field(default=None, ge=0)
    denominator: int | None = Field(default=None, ge=0)
    source: Literal[
        "pooled_rate",
        "observation_rate",
        "distribution_p50",
        "distribution_total",
        "reason_code_rate",
    ]

    @field_validator("reason_codes", mode="before")
    @classmethod
    def _coerce_reason_codes(cls, value: object) -> object:
        if isinstance(value, list | tuple):
            return tuple(coerce_enum(ReasonCode, item) for item in value)
        return value

    @model_validator(mode="after")
    def _validate_current_identity(self) -> DriftWindowMetric:
        if self.schema_version == _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION:
            _require_current_drift_window_metric_identity(self)
        return self


class DriftWindowSummary(PersistedArtifact):
    model_config = ConfigDict(json_schema_extra=_drift_window_schema_extra)

    artifact_kind: Literal["drift-window-summary"] = "drift-window-summary"
    window_id: str = Field(min_length=1)
    window_index: int = Field(ge=0)
    runset_id: str = Field(min_length=1)
    suite_id: str = Field(min_length=1)
    suite_version: str = Field(min_length=1)
    configuration_digest: DigestHex | None = None
    source_runset_completion_status: Literal["complete", "incomplete"] | None = None
    source_evaluation_completion_status: Literal["complete", "incomplete"] | None = None
    source_evaluation_exploratory: bool | None = None
    protocol_id: str | None = None
    protocol_digest: DigestHex | None = None
    baseline_mode: Literal["concurrent_paired", "fixed_reference"] | None = None
    analysis_method: str = Field(min_length=1)
    observation_window_start_utc: str | None = None
    observation_window_end_utc: str | None = None
    observations: int = Field(ge=0)
    included_observations: int = Field(ge=0)
    excluded_observations: int = Field(ge=0)
    provider_version_unknown: bool = False
    provider_version_keys: tuple[str, ...] = ()
    tool_schema_digests: tuple[DigestHex, ...] = ()
    policy_bundle_digests: tuple[DigestHex, ...] = ()
    metrics: tuple[DriftWindowMetric, ...] = Field(
        default=(),
        max_length=MAX_LIVE_MONITORING_ITEMS,
    )

    @field_validator(
        "provider_version_keys",
        "tool_schema_digests",
        "policy_bundle_digests",
        "metrics",
        mode="before",
    )
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _require_current_configuration_digest(self) -> DriftWindowSummary:
        if (
            self.schema_version in _V06_BINDING_SCHEMA_VERSIONS
            and self.configuration_digest is None
        ):
            raise ValueError("v0.6 drift windows require configuration_digest")
        if self.schema_version == _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION:
            if (
                self.source_runset_completion_status is None
                or self.source_evaluation_completion_status is None
                or self.source_evaluation_exploratory is None
            ):
                raise ValueError(
                    "current drift windows require source RunSet and effective evaluation "
                    "qualification"
                )
            _require_current_drift_window_identity(self)
        return self


class DriftComparabilityResult(PersistedArtifact):
    model_config = ConfigDict(json_schema_extra=_drift_comparability_schema_extra)

    artifact_kind: Literal["drift-comparability-result"] = "drift-comparability-result"
    status: DriftComparabilityStatus
    compared_windows: int = Field(ge=0)
    suite_matches: bool
    baseline_mode_matches: bool
    analysis_method_matches: bool
    configuration_digest_matches: bool | None = None
    protocol_digest_matches: bool
    material_fields_match: bool
    tool_schema_digest_matches: bool
    policy_bundle_digest_matches: bool
    reference_protocol_digest: DigestHex | None = None
    suite_id: str | None = None
    suite_version: str | None = None
    baseline_mode: str | None = None
    analysis_method: str | None = None
    failures: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()

    @field_validator("failures", "limitations", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _require_current_configuration_comparability(
        self,
    ) -> DriftComparabilityResult:
        if (
            self.schema_version in _V06_BINDING_SCHEMA_VERSIONS
            and self.configuration_digest_matches is None
        ):
            raise ValueError("v0.6 drift comparability requires configuration_digest_matches")
        if self.schema_version == _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION:
            _require_current_drift_comparability_identity(self)
        return self


class DriftStateEstimate(PersistedArtifact):
    artifact_kind: Literal["drift-state-estimate"] = "drift-state-estimate"
    state_name: Literal["governance_health", "control_reliability", "drift_state"]
    metric: DriftMetric
    label: str = Field(min_length=1)
    prerequisite_status: EndpointPrerequisiteStatus
    smoothing_alpha: UnitInterval6String
    latest_level: SignedDecimalString | None = Field(
        default=None,
        pattern=r"^-?(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    latest_drift_per_window: SignedDecimalString | None = Field(
        default=None,
        pattern=r"^-?(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    innovation_variance: DecimalString | None = Field(
        default=None,
        pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    limitations: tuple[str, ...] = ()

    @field_validator("limitations", mode="before")
    @classmethod
    def _coerce_limitations(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_current_identity(self) -> DriftStateEstimate:
        if self.schema_version == _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION:
            _require_current_drift_state_identity(self)
        return self


class DriftMetricDiagnostic(PersistedArtifact):
    model_config = ConfigDict(json_schema_extra=_drift_metric_diagnostic_schema_extra)

    artifact_kind: Literal["drift-metric-diagnostic"] = "drift-metric-diagnostic"
    metric: DriftMetric
    label: str = Field(min_length=1)
    reason_codes: tuple[ReasonCode, ...] = Field(default=(), max_length=len(ReasonCode))
    interpretation: DriftInterpretation
    analysis_methods: tuple[DriftAnalysisMethod, ...] = Field(
        min_length=1,
        max_length=_MAX_DRIFT_ANALYSIS_METHODS,
    )
    prerequisite_status: EndpointPrerequisiteStatus
    windows: int = Field(ge=0)
    observations: int = Field(ge=0)
    missing_windows: int = Field(ge=0)
    first_value: DecimalString | None = Field(
        default=None,
        pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    last_value: DecimalString | None = Field(
        default=None,
        pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    mean_value: DecimalString | None = Field(
        default=None,
        pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    slope_per_window: SignedDecimalString | None = Field(
        default=None,
        pattern=r"^-?(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    max_step_change: DecimalString | None = Field(
        default=None,
        pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    lag1_autocorrelation: SignedUnitInterval6String | None = None
    ar1_phi: SignedUnitInterval6String | None = None
    ar1_intercept: SignedDecimalString | None = Field(
        default=None,
        pattern=r"^-?(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    ar1_innovation_variance: DecimalString | None = Field(
        default=None,
        pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    stationarity_signal: DriftStationaritySignal = "none"
    dependence_signal: DriftStationaritySignal = "none"
    review_reasons: tuple[str, ...] = ()
    state_estimate: DriftStateEstimate | None = None
    limitations: tuple[str, ...] = ()

    @field_validator("reason_codes", mode="before")
    @classmethod
    def _coerce_reason_codes(cls, value: object) -> object:
        if isinstance(value, list | tuple):
            return tuple(coerce_enum(ReasonCode, item) for item in value)
        return value

    @field_validator(
        "analysis_methods",
        "review_reasons",
        "limitations",
        mode="before",
    )
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_current_identity(self) -> DriftMetricDiagnostic:
        if self.schema_version == _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION:
            _require_current_drift_diagnostic_identity(self)
        return self


class LiveDriftReport(PersistedArtifact):
    model_config = ConfigDict(json_schema_extra=_live_drift_schema_extra)

    artifact_kind: Literal["live-drift-report"] = "live-drift-report"
    derivation_contract: Literal["agent-assure/live-drift/v1"] | None = None
    report_id: str = Field(min_length=1)
    source_evaluation_digests: tuple[DigestHex, ...] = Field(
        default=(),
        max_length=MAX_PERSISTED_OBSERVATIONS,
    )
    protocol_id: str | None = None
    protocol_digest: DigestHex | None = None
    protocol: LiveProtocolRecord | None = None
    drift_plan_id: str | None = None
    drift_plan: DriftMonitoringPlan | None = None
    suite_id: str = Field(min_length=1)
    suite_version: str = Field(min_length=1)
    ordering_variable: DriftOrderingVariable = "window_index"
    interpretation: DriftInterpretation = "exploratory"
    state: GateState = GateState.not_evaluated
    monitoring_status: DriftMonitoringStatus
    observation_window_start_utc: str | None = None
    observation_window_end_utc: str | None = None
    comparability: DriftComparabilityResult
    windows: tuple[DriftWindowSummary, ...] = Field(
        max_length=MAX_PERSISTED_OBSERVATIONS,
    )
    diagnostics: tuple[DriftMetricDiagnostic, ...] = Field(
        max_length=MAX_LIVE_MONITORING_ITEMS,
    )
    limitations: tuple[str, ...] = (
        "cross-window monitoring is a review signal and is not a release-verdict gate",
        "stationarity or drift signals do not establish safety, compliance, clinical "
        "validity, provider quality, or model intent",
        "latent-state summaries describe governance health, control reliability, or drift "
        "state from observable records only",
    )

    @field_validator("state", mode="before")
    @classmethod
    def _coerce_state(cls, value: object) -> GateState:
        return coerce_enum(GateState, value)

    @field_validator(
        "source_evaluation_digests",
        "windows",
        "diagnostics",
        "limitations",
        mode="before",
    )
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_current_identity(self) -> LiveDriftReport:
        if self.schema_version in _V06_BINDING_SCHEMA_VERSIONS:
            _require_current_live_drift_report_identity(self)
        return self

    @model_validator(mode="after")
    def _validate_current_derivation(self) -> LiveDriftReport:
        if self.schema_version != _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION:
            return self
        if (
            self.derivation_contract != _LIVE_DRIFT_DERIVATION_CONTRACT
            or not self.source_evaluation_digests
            or self.protocol is None
            or self.drift_plan is None
        ):
            raise ValueError(
                "current live drift reports require ordered source digests, bound protocol, "
                "effective drift plan, and derivation contract"
            )
        if self.protocol.schema_version != _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION:
            raise ValueError("current live drift reports require a current bound protocol record")
        _require_current_live_protocol_plan_versions(self.protocol)
        if self.drift_plan.schema_version != self.schema_version or any(
            metric.schema_version != self.schema_version for metric in self.drift_plan.metrics
        ):
            raise ValueError(
                "effective drift plan schema_version must match its current live drift report"
            )
        from agent_assure.live.drift import verify_live_drift_report_derivation

        verify_live_drift_report_derivation(self)
        return self

    @model_validator(mode="after")
    def _validate_legacy_derivation(self) -> LiveDriftReport:
        from agent_assure.live.legacy_validation import validate_legacy_live_drift_report

        validate_legacy_live_drift_report(self)
        return self


_TRAJECTORY_OPERATIONAL_EVENT_TYPES = frozenset(
    {
        "retry",
        "rate_limit",
        "exclusion",
        "runtime_failure",
        "malformed_output",
        "emergency_process",
        "budget_stop",
    }
)
_TRAJECTORY_HISTORY_CHECK_IDS = frozenset(
    {
        "review-required-history",
        "claim-evidence-history",
        "retry-provider-history",
    }
)


def trajectory_path_is_included(path: TrajectoryPathSummary) -> bool:
    """Return whether a trajectory path represents an evaluated observation."""

    return "excluded" not in path.states


def trajectory_path_is_included_approval(path: TrajectoryPathSummary) -> bool:
    """Return whether approval-specific controls apply to a trajectory path."""

    return trajectory_path_is_included(path) and path.approval_outcome


def trajectory_path_is_included_review_approval(path: TrajectoryPathSummary) -> bool:
    """Return whether the required-review approval invariant applies to a path."""

    return trajectory_path_is_included_approval(path) and path.human_review_required


def _require_current_trajectory_path_identity(path: TrajectoryPathSummary) -> None:
    if path.states[0] != "start":
        raise ValueError("trajectory paths must begin in the start state")
    if path.terminal_state != path.states[-1]:
        raise ValueError("trajectory terminal_state must match the final path state")
    if path.transition_count != len(path.states) - 1:
        raise ValueError("trajectory transition_count must match the stored path")
    if path.human_review_performed != ("human_review" in path.states):
        raise ValueError("trajectory human-review fact does not match the stored path")
    if path.schema_version != _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION:
        return
    if len(path.states) != len(set(path.states)):
        raise ValueError("current trajectory path states must be unique")
    excluded_count = path.states.count("excluded")
    if bool(excluded_count) != (path.terminal_state == "excluded"):
        raise ValueError(
            "trajectory excluded-state membership must match the excluded terminal state"
        )
    if excluded_count:
        if excluded_count != 1 or path.states[-1] != "excluded":
            raise ValueError("trajectory excluded state must occur exactly once as terminal state")
    elif path.terminal_state != "verdict":
        raise ValueError("included trajectory paths must terminate in the verdict state")
    if any(state in {"verdict", "excluded"} for state in path.states[:-1]):
        raise ValueError("trajectory terminal states may occur only as the final path state")
    canonical_states = (
        _CANONICAL_EXCLUDED_TRAJECTORY_STATE_SET
        if excluded_count
        else _CANONICAL_INCLUDED_TRAJECTORY_STATE_SET
    )
    if path.states not in canonical_states:
        raise ValueError(
            "current trajectory path states must follow the canonical observable order"
        )
    if path.claim_evidence_status is None or path.claim_evidence_complete is None:
        raise ValueError(
            "current trajectory paths require claim-evidence status and compatibility state"
        )
    expected_complete = path.claim_evidence_status == "complete"
    if path.claim_evidence_complete is not expected_complete:
        raise ValueError("trajectory claim-evidence compatibility state does not match status")
    if not trajectory_path_is_included(path):
        expected_status: ClaimEvidenceStatus = "not_evaluated"
    elif not path.approval_outcome:
        expected_status = "not_applicable"
    elif path.claim_evidence_status in {"complete", "incomplete", "unobservable"}:
        expected_status = path.claim_evidence_status
    else:
        raise ValueError(
            "included approval paths require complete, incomplete, or unobservable "
            "claim-evidence status"
        )
    if path.claim_evidence_status != expected_status:
        raise ValueError(
            "trajectory claim-evidence status does not match observation and approval applicability"
        )
    has_unobservable_limitation = CLAIM_EVIDENCE_UNOBSERVABLE_PATH_LIMITATION in path.limitations
    if has_unobservable_limitation is not (path.claim_evidence_status == "unobservable"):
        raise ValueError("trajectory claim-evidence observability limitation does not match status")


def _require_current_trajectory_transition_identity(
    transition: TrajectoryTransitionSummary,
) -> None:
    if transition.count <= 0 or transition.from_state_count <= 0:
        raise ValueError("persisted trajectory transitions require positive observed support")
    if transition.count > transition.from_state_count:
        raise ValueError("trajectory transition count cannot exceed from-state support")
    if transition.conditional_frequency != _validated_rate_string(
        transition.count,
        transition.from_state_count,
    ):
        raise ValueError("trajectory conditional frequency does not match transition counts")
    if transition.prerequisite_status == "invalid":
        raise ValueError("observed trajectory transitions cannot have invalid prerequisites")


def _require_current_trajectory_invariant_identity(
    invariant: TrajectoryInvariantResult,
) -> None:
    affected_ids = invariant.affected_observation_ids
    if len(affected_ids) != len(set(affected_ids)):
        raise ValueError("trajectory invariant affected observation IDs must be unique")
    if invariant.affected_observations != len(affected_ids):
        raise ValueError("trajectory invariant affected count does not match its IDs")
    if invariant.affected_observations > invariant.evaluated_observations:
        raise ValueError("trajectory invariant affected count exceeds evaluated observations")
    expected_state = GateState.not_evaluated
    if affected_ids and invariant.prerequisite_status != "invalid":
        expected_state = (
            GateState.fail if invariant.category == "governance_control_failure" else GateState.warn
        )
    if invariant.schema_version != _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION:
        if invariant.state is not expected_state:
            raise ValueError("trajectory invariant state does not match affected observations")
        return
    if (
        invariant.unobservable_observations is None
        or invariant.unobservable_observation_ids is None
    ):
        raise ValueError(
            "current trajectory invariants require explicit unobservable observation counts"
        )
    unobservable_ids = invariant.unobservable_observation_ids
    if len(unobservable_ids) != len(set(unobservable_ids)):
        raise ValueError("trajectory invariant unobservable observation IDs must be unique")
    if set(affected_ids).intersection(unobservable_ids):
        raise ValueError(
            "trajectory invariant observations cannot be both affected and unobservable"
        )
    if invariant.unobservable_observations != len(unobservable_ids):
        raise ValueError("trajectory invariant unobservable count does not match its IDs")
    if unobservable_ids and invariant.invariant_type != "claim_evidence_before_approval":
        raise ValueError("only claim-evidence invariants can contain unobservable observations")
    if unobservable_ids and invariant.prerequisite_status == "met":
        raise ValueError(
            "trajectory invariants with unobservable observations cannot claim met prerequisites"
        )
    has_unobservable_limitation = (
        CLAIM_EVIDENCE_UNOBSERVABLE_INVARIANT_LIMITATION in invariant.limitations
    )
    if has_unobservable_limitation is not bool(unobservable_ids):
        raise ValueError(
            "trajectory invariant observability limitation does not match unobservable observations"
        )
    if not affected_ids and unobservable_ids:
        expected_state = GateState.warn
    if invariant.state is not expected_state:
        raise ValueError(
            "trajectory invariant state does not match affected or unobservable observations"
        )


def _require_current_history_check_identity(check: HistoryDependentTrajectoryCheck) -> None:
    affected_ids = check.affected_observation_ids
    if len(affected_ids) != len(set(affected_ids)):
        raise ValueError("history-dependent affected observation IDs must be unique")
    if check.affected_observations != len(affected_ids):
        raise ValueError("history-dependent affected count does not match its IDs")
    if check.prerequisite_status == "exploratory":
        raise ValueError("history-dependent checks use only met or invalid prerequisites")


@with_live_decimal_context
def _require_current_operational_event_identity(
    process: OperationalEventProcessSummary,
) -> None:
    if process.exposure_unit != "observation":
        raise ValueError("operational event exposure_unit must be observation")
    if process.timestamped_events + process.missing_timestamp_events != process.observed_events:
        raise ValueError("operational event timestamp counts do not match observed events")
    if process.exposure == 0:
        if process.observed_events != 0 or process.event_rate != "0.000000":
            raise ValueError("zero-exposure operational event summaries must be empty")
    else:
        raw_rate = Decimal(process.observed_events) / Decimal(process.exposure)
        expected_rate = decimal_string(
            raw_rate
            if process.schema_version == _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION
            else min(Decimal("1"), raw_rate)
        )
        if process.event_rate != expected_rate:
            raise ValueError("operational event rate does not match events and exposure")
    timing_values = (process.observation_window_seconds, process.mean_interarrival_seconds)
    if process.timestamped_events < 2:
        if any(value is not None for value in timing_values):
            raise ValueError("fewer than two timestamped events cannot have timing statistics")
    else:
        if any(value is None for value in timing_values):
            raise ValueError("two or more timestamped events require timing statistics")
        if (
            process.observation_window_seconds is not None
            and process.mean_interarrival_seconds is not None
        ):
            expected_window = Decimal(process.mean_interarrival_seconds) * Decimal(
                process.timestamped_events - 1
            )
            rounding_tolerance = Decimal("0.0000005") * Decimal(process.timestamped_events)
            if (
                abs(Decimal(process.observation_window_seconds) - expected_window)
                > rounding_tolerance
            ):
                raise ValueError(
                    "operational event window and mean interarrival time are inconsistent"
                )
    if process.timestamped_events == 0:
        if process.max_events_in_burst_window != 0:
            raise ValueError("untimestamped event summaries cannot report a burst count")
    elif not 1 <= process.max_events_in_burst_window <= process.timestamped_events:
        raise ValueError("operational burst count is outside timestamped event support")
    invalid_burst_required = (
        process.prerequisite_status == "invalid"
        or (process.observed_events > 0 and process.prerequisite_status != "met")
        or (process.observed_events > 0 and process.timestamped_events == 0)
        or process.missing_timestamp_events > 0
    )
    if (process.burst_signal == "invalid") != invalid_burst_required:
        raise ValueError("operational burst signal does not match persisted prerequisites")


@with_live_decimal_context
def _require_current_live_trajectory_report_identity(report: LiveTrajectoryReport) -> None:
    if report.state is not GateState.not_evaluated:
        raise ValueError("live trajectory reports must remain non-verdict review artifacts")
    if report.schema_version == _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION:
        stop_reasons = report.source_evaluation_stop_reasons
        if stop_reasons is not None:
            if stop_reasons != tuple(sorted(set(stop_reasons))):
                raise ValueError(
                    "current trajectory source evaluation stop reasons must be unique and sorted"
                )
            expected_completion = (
                "incomplete"
                if stop_reasons or report.source_runset_completion_status == "incomplete"
                else "complete"
            )
            if report.source_evaluation_completion_status != expected_completion:
                raise ValueError(
                    "trajectory source evaluation completion status does not match its "
                    "RunSet status and stop reasons"
                )
    nested_artifacts: tuple[tuple[str, PersistedArtifact], ...] = (
        *(("trajectory path", item) for item in report.paths),
        *(("trajectory transition", item) for item in report.transitions),
        *(("trajectory invariant", item) for item in report.invariants),
        *(("trajectory history check", item) for item in report.history_dependent_checks),
        *(("trajectory operational event", item) for item in report.operational_events),
        *(("trajectory event process", item) for item in report.event_processes),
    )
    for owner, nested in nested_artifacts:
        _require_nested_report_version(
            nested,
            report.schema_version,
            owner=owner,
        )
    if report.observations != len(report.paths):
        raise ValueError("trajectory observation count does not match stored paths")
    if report.observations != report.included_observations + report.excluded_observations:
        raise ValueError("trajectory observations must equal included plus excluded")
    excluded_paths = sum(1 for path in report.paths if "excluded" in path.states)
    if report.excluded_observations != excluded_paths:
        raise ValueError("trajectory excluded count does not match excluded paths")
    observation_ids = [path.observation_id for path in report.paths]
    run_ids = [path.run_id for path in report.paths]
    if len(observation_ids) != len(set(observation_ids)):
        raise ValueError("trajectory path observation IDs must be unique")
    if len(run_ids) != len(set(run_ids)):
        raise ValueError("trajectory path run IDs must be unique")
    for path in report.paths:
        _require_current_trajectory_path_identity(path)

    plan_methods = (
        set(report.trajectory_plan.analysis_methods)
        if report.trajectory_plan is not None
        else set(_TRAJECTORY_SUPPORTED_METHODS)
    )

    transition_counts: dict[tuple[TrajectoryState, TrajectoryState], int] = {}
    from_state_counts: dict[TrajectoryState, int] = {}
    for path in report.paths:
        for left, right in zip(path.states, path.states[1:], strict=False):
            pair = (left, right)
            transition_counts[pair] = transition_counts.get(pair, 0) + 1
            from_state_counts[left] = from_state_counts.get(left, 0) + 1
    transition_by_pair: dict[
        tuple[TrajectoryState, TrajectoryState],
        TrajectoryTransitionSummary,
    ] = {}
    for transition in report.transitions:
        _require_current_trajectory_transition_identity(transition)
        pair = (transition.from_state, transition.to_state)
        if pair in transition_by_pair:
            raise ValueError("trajectory transition pairs must be unique")
        transition_by_pair[pair] = transition
    if "observable_transition_profile" not in plan_methods and report.transitions:
        raise ValueError("trajectory transition outputs require the declared transition method")
    if "observable_transition_profile" in plan_methods and set(transition_by_pair) != set(
        transition_counts
    ):
        raise ValueError("trajectory transition set does not match stored paths")
    for pair, expected_count in transition_counts.items():
        transition = transition_by_pair[pair]
        if (
            transition.count != expected_count
            or transition.from_state_count != from_state_counts[pair[0]]
        ):
            raise ValueError("trajectory transition counts do not match stored paths")

    path_id_set = set(observation_ids)
    invariant_ids = [invariant.invariant_id for invariant in report.invariants]
    if len(invariant_ids) != len(set(invariant_ids)):
        raise ValueError("trajectory invariant IDs must be unique")
    for invariant in report.invariants:
        _require_current_trajectory_invariant_identity(invariant)
        if invariant.evaluated_observations > len(report.paths):
            raise ValueError("trajectory invariant evaluated count exceeds stored paths")
        if (
            invariant.unobservable_observations is not None
            and invariant.evaluated_observations + invariant.unobservable_observations
            > len(report.paths)
        ):
            raise ValueError(
                "trajectory invariant evaluated and unobservable counts exceed stored paths"
            )
        if not set(invariant.affected_observation_ids) <= path_id_set:
            raise ValueError("trajectory invariant references an unknown observation")
        if (
            invariant.unobservable_observation_ids is not None
            and not set(invariant.unobservable_observation_ids) <= path_id_set
        ):
            raise ValueError(
                "trajectory invariant unobservable IDs reference an unknown observation"
            )
    if "sequence_invariant_check" not in plan_methods and report.invariants:
        raise ValueError("trajectory invariant outputs require sequence_invariant_check")

    check_ids = [check.check_id for check in report.history_dependent_checks]
    if len(check_ids) != len(set(check_ids)):
        raise ValueError("history-dependent trajectory check IDs must be unique")
    if "sequence_invariant_check" in plan_methods:
        if set(check_ids) != _TRAJECTORY_HISTORY_CHECK_IDS:
            raise ValueError("trajectory report must contain the complete history-check set")
    elif check_ids:
        raise ValueError("trajectory history checks require sequence_invariant_check")
    if report.schema_version == _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION:
        evidence_is_unobservable = any(
            trajectory_path_is_included_approval(path)
            and path.claim_evidence_status == "unobservable"
            for path in report.paths
        )
    else:
        evidence_is_unobservable = any(
            path.approval_outcome and path.claim_evidence_status == "unobservable"
            for path in report.paths
        )
    for check in report.history_dependent_checks:
        _require_current_history_check_identity(check)
        if not set(check.affected_observation_ids) <= path_id_set:
            raise ValueError("history-dependent check references an unknown observation")
        if report.schema_version == _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION:
            if check.check_id == "review-required-history":
                has_applicable_paths = any(
                    trajectory_path_is_included_review_approval(path) for path in report.paths
                )
                has_unobservable_paths = False
            elif check.check_id == "claim-evidence-history":
                applicable_paths = tuple(
                    path for path in report.paths if trajectory_path_is_included_approval(path)
                )
                has_applicable_paths = bool(applicable_paths)
                has_unobservable_paths = any(
                    path.claim_evidence_status == "unobservable" for path in applicable_paths
                )
            else:
                has_applicable_paths = any(
                    trajectory_path_is_included(path) and path.retry_count is not None
                    for path in report.paths
                )
                has_unobservable_paths = False
        else:
            has_applicable_paths = bool(report.paths)
            has_unobservable_paths = (
                check.check_id == "claim-evidence-history" and evidence_is_unobservable
            )
        expected_history_status: TrajectoryPrerequisiteStatus = (
            "invalid" if not has_applicable_paths or has_unobservable_paths else "met"
        )
        if check.prerequisite_status != expected_history_status:
            raise ValueError("history-dependent prerequisite status does not match path presence")

    event_types = [process.event_type for process in report.event_processes]
    if len(event_types) != len(set(event_types)):
        raise ValueError("operational event process types must be unique")
    if "event_process_summary" in plan_methods:
        if set(event_types) != _TRAJECTORY_OPERATIONAL_EVENT_TYPES:
            raise ValueError("trajectory report must contain the complete operational event set")
    elif event_types:
        raise ValueError("trajectory event-process outputs require event_process_summary")
    for process in report.event_processes:
        _require_current_operational_event_identity(process)
        if process.exposure != report.observations:
            raise ValueError("operational event exposure does not match trajectory observations")

    if not report.paths:
        if (
            report.trajectory_status != "invalid"
            or report.transition_assumption_status != "invalid"
        ):
            raise ValueError("empty trajectory reports require invalid status and assumptions")
    if report.transition_assumption_status == "met" and any(
        transition.prerequisite_status != "met" for transition in report.transitions
    ):
        raise ValueError("met transition assumptions require met transition prerequisites")
    has_unobservable_limitation = (
        LIVE_TRAJECTORY_CLAIM_EVIDENCE_UNOBSERVABLE_LIMITATION in report.limitations
    )
    if has_unobservable_limitation is not evidence_is_unobservable:
        raise ValueError("trajectory report observability limitation does not match stored paths")
    if (
        report.schema_version == _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION
        and report.trajectory_status == "valid"
    ):
        confirmatory_invariants = tuple(
            invariant
            for invariant in report.invariants
            if invariant.interpretation == "confirmatory"
        )
        required_statuses = (
            *(transition.prerequisite_status for transition in report.transitions),
            *(invariant.prerequisite_status for invariant in confirmatory_invariants),
            *(process.prerequisite_status for process in report.event_processes),
        )
        if (
            report.interpretation != "confirmatory"
            or not confirmatory_invariants
            or report.source_runset_completion_status != "complete"
            or report.source_evaluation_completion_status != "complete"
            or report.source_evaluation_exploratory is not False
            or report.transition_assumption_status != "met"
            or any(status != "met" for status in required_statuses)
        ):
            raise ValueError("valid trajectory status requires confirmatory met prerequisites")


class TrajectoryPathSummary(PersistedArtifact):
    model_config = ConfigDict(json_schema_extra=_trajectory_path_schema_extra)

    artifact_kind: Literal["trajectory-path-summary"] = "trajectory-path-summary"
    observation_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    case_id: str = Field(min_length=1)
    repetition_index: int = Field(ge=0)
    cluster_id: str = Field(min_length=1)
    terminal_state: TrajectoryState
    states: tuple[TrajectoryState, ...] = Field(
        min_length=2,
        max_length=_MAX_TRAJECTORY_PATH_STATES,
    )
    transition_count: int = Field(ge=1)
    tool_count: int = Field(ge=0)
    claim_count: int = Field(ge=0)
    evidence_ref_count: int = Field(ge=0)
    claim_evidence_link_count: int = Field(ge=0)
    policy_result_count: int = Field(ge=0)
    human_review_required: bool = False
    human_review_performed: bool = False
    approval_outcome: bool = False
    claim_evidence_complete: bool | None = Field(
        default=None,
        description=(
            "Backward-compatible projection of claim_evidence_status. True only for "
            "complete; all other statuses project to false."
        ),
    )
    claim_evidence_status: ClaimEvidenceStatus | None = Field(
        default=None,
        description=(
            "Evaluator-aligned evidence status. Excluded observations are not_evaluated; "
            "included non-approvals are not_applicable; only included approvals can be "
            "complete, incomplete, or unobservable."
        ),
    )
    attempt_count: int | None = Field(default=None, ge=0)
    retry_count: int | None = Field(default=None, ge=0)
    rate_limit_event_count: int = Field(default=0, ge=0)
    runtime_failed: bool = False
    malformed_output: bool = False
    has_ordered_timestamps: bool = False
    limitations: tuple[str, ...] = ()

    @field_validator("states", "limitations", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_current_identity(self) -> TrajectoryPathSummary:
        if self.schema_version == _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION:
            _require_current_trajectory_path_identity(self)
        elif self.claim_evidence_status is not None:
            if self.claim_evidence_status in {"not_evaluated", "not_applicable"}:
                raise ValueError(
                    "not_evaluated and not_applicable claim-evidence statuses are "
                    "current-schema-only"
                )
            if self.claim_evidence_complete is None:
                raise ValueError(
                    "trajectory claim-evidence status requires its compatibility state"
                )
            if self.claim_evidence_complete is not (self.claim_evidence_status == "complete"):
                raise ValueError(
                    "trajectory claim-evidence compatibility state does not match status"
                )
        return self


class TrajectoryTransitionSummary(PersistedArtifact):
    artifact_kind: Literal["trajectory-transition-summary"] = "trajectory-transition-summary"
    from_state: TrajectoryState
    to_state: TrajectoryState
    count: int = Field(ge=0)
    from_state_count: int = Field(ge=0)
    conditional_frequency: UnitInterval6String
    prerequisite_status: TrajectoryPrerequisiteStatus
    limitations: tuple[str, ...] = ()

    @field_validator("limitations", mode="before")
    @classmethod
    def _coerce_limitations(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_current_identity(self) -> TrajectoryTransitionSummary:
        if self.schema_version == _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION:
            _require_current_trajectory_transition_identity(self)
        return self


class TrajectoryInvariantResult(PersistedArtifact):
    model_config = ConfigDict(json_schema_extra=_trajectory_invariant_result_schema_extra)

    artifact_kind: Literal["trajectory-invariant-result"] = "trajectory-invariant-result"
    invariant_id: str = Field(min_length=1)
    label: str = Field(min_length=1)
    invariant_type: TrajectoryInvariantType
    category: TrajectoryInvariantCategory
    interpretation: TrajectoryInterpretation
    prerequisite_status: TrajectoryPrerequisiteStatus
    affected_observations: int = Field(ge=0)
    evaluated_observations: int = Field(ge=0)
    affected_observation_ids: tuple[str, ...] = Field(
        default=(),
        max_length=MAX_PERSISTED_OBSERVATIONS,
    )
    unobservable_observations: int | None = Field(
        default=None,
        ge=0,
        description=(
            "Applicable observations excluded from evaluated_observations because the "
            "claim-evidence controls were unobservable."
        ),
    )
    unobservable_observation_ids: tuple[str, ...] | None = Field(
        default=None,
        max_length=MAX_PERSISTED_OBSERVATIONS,
        description="Observation IDs counted by unobservable_observations.",
    )
    state: GateState = GateState.not_evaluated
    limitations: tuple[str, ...] = ()

    @field_validator("state", mode="before")
    @classmethod
    def _coerce_state(cls, value: object) -> GateState:
        return coerce_enum(GateState, value)

    @field_validator(
        "affected_observation_ids",
        "unobservable_observation_ids",
        "limitations",
        mode="before",
    )
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_current_identity(self) -> TrajectoryInvariantResult:
        if self.schema_version == _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION:
            _require_current_trajectory_invariant_identity(self)
        return self


class HistoryDependentTrajectoryCheck(PersistedArtifact):
    artifact_kind: Literal["history-dependent-trajectory-check"] = (
        "history-dependent-trajectory-check"
    )
    check_id: str = Field(min_length=1)
    dependency: str = Field(min_length=1)
    prerequisite_status: TrajectoryPrerequisiteStatus
    affected_observations: int = Field(ge=0)
    affected_observation_ids: tuple[str, ...] = Field(
        default=(),
        max_length=MAX_PERSISTED_OBSERVATIONS,
    )
    limitations: tuple[str, ...] = ()

    @field_validator("affected_observation_ids", "limitations", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_current_identity(self) -> HistoryDependentTrajectoryCheck:
        if self.schema_version == _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION:
            _require_current_history_check_identity(self)
        return self


class OperationalEventProcessSummary(PersistedArtifact):
    artifact_kind: Literal["operational-event-process-summary"] = (
        "operational-event-process-summary"
    )
    event_type: OperationalEventType
    observed_events: int = Field(ge=0)
    exposure: int = Field(ge=0)
    exposure_unit: str = Field(default="observation", min_length=1)
    event_rate: DecimalString = Field(
        pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
        description=(
            "Observed events per exposure unit. This is a non-negative count rate, "
            "not a probability, and may exceed 1.000000."
        ),
    )
    analysis_method: Literal[
        "poisson_rate",
        "renewal_gap_summary",
        "burst_window_count",
    ]
    prerequisite_status: TrajectoryPrerequisiteStatus
    timestamped_events: int = Field(ge=0)
    missing_timestamp_events: int = Field(ge=0)
    observation_window_seconds: DecimalString | None = Field(
        default=None,
        pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    mean_interarrival_seconds: DecimalString | None = Field(
        default=None,
        pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    max_events_in_burst_window: int = Field(ge=0)
    burst_window_seconds: int = Field(ge=1)
    burst_signal: OperationalBurstSignal = "none"
    limitations: tuple[str, ...] = ()

    @field_validator("limitations", mode="before")
    @classmethod
    def _coerce_limitations(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_current_identity(self) -> OperationalEventProcessSummary:
        if self.schema_version == _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION:
            _require_current_operational_event_identity(self)
        return self


class TrajectoryOperationalEvent(PersistedArtifact):
    artifact_kind: Literal["trajectory-operational-event"] = "trajectory-operational-event"
    event_type: OperationalEventType
    observation_id: str | None = Field(default=None, min_length=1)
    count: int = Field(ge=1, le=MAX_PERSISTED_OBSERVATIONS)
    timestamp_utc: str | None = None


class LiveTrajectoryReport(PersistedArtifact):
    model_config = ConfigDict(json_schema_extra=_live_trajectory_schema_extra)

    artifact_kind: Literal["live-trajectory-report"] = "live-trajectory-report"
    derivation_contract: Literal["agent-assure/live-trajectory/v1"] | None = None
    report_id: str = Field(min_length=1)
    runset_id: str = Field(min_length=1)
    evaluation_report_id: str = Field(min_length=1)
    source_runset_digest: DigestHex | None = None
    source_evaluation_digest: DigestHex | None = None
    source_runset_completion_status: Literal["complete", "incomplete"] | None = None
    source_evaluation_completion_status: Literal["complete", "incomplete"] | None = None
    source_evaluation_stop_reasons: tuple[str, ...] | None = None
    source_evaluation_exploratory: bool | None = None
    protocol_id: str | None = None
    protocol_digest: DigestHex | None = None
    protocol: LiveProtocolRecord | None = None
    trajectory_plan_id: str | None = None
    trajectory_plan: TrajectoryAnalysisPlan | None = None
    suite_id: str = Field(min_length=1)
    suite_version: str = Field(min_length=1)
    interpretation: TrajectoryInterpretation = "exploratory"
    state: GateState = GateState.not_evaluated
    trajectory_status: Literal["valid", "exploratory", "invalid"]
    transition_assumption: Literal["canonical_observable_order"] = "canonical_observable_order"
    transition_assumption_status: TrajectoryPrerequisiteStatus
    observations: int = Field(ge=0)
    included_observations: int = Field(ge=0)
    excluded_observations: int = Field(ge=0)
    paths: tuple[TrajectoryPathSummary, ...] = Field(
        max_length=MAX_PERSISTED_OBSERVATIONS,
    )
    transitions: tuple[TrajectoryTransitionSummary, ...] = Field(
        max_length=_MAX_TRAJECTORY_TRANSITIONS,
    )
    invariants: tuple[TrajectoryInvariantResult, ...] = Field(
        max_length=MAX_LIVE_MONITORING_ITEMS,
    )
    history_dependent_checks: tuple[HistoryDependentTrajectoryCheck, ...] = Field(
        max_length=MAX_LIVE_MONITORING_ITEMS,
    )
    operational_events: tuple[TrajectoryOperationalEvent, ...] = Field(
        default=(),
        max_length=_MAX_TRAJECTORY_OPERATIONAL_EVENT_INPUTS,
    )
    event_processes: tuple[OperationalEventProcessSummary, ...] = Field(
        max_length=_MAX_OPERATIONAL_EVENT_PROCESSES,
    )
    limitations: tuple[str, ...] = (
        "trajectory analysis is derived from privacy-filtered structured artifacts",
        "trajectory and event-process outputs are review signals and are not release-verdict gates",
        "path coverage over observed records is not proof that unsafe paths are impossible",
    )

    @field_validator("state", mode="before")
    @classmethod
    def _coerce_state(cls, value: object) -> GateState:
        return coerce_enum(GateState, value)

    @field_validator(
        "paths",
        "transitions",
        "invariants",
        "history_dependent_checks",
        "operational_events",
        "event_processes",
        "limitations",
        "source_evaluation_stop_reasons",
        mode="before",
    )
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_current_identity(self) -> LiveTrajectoryReport:
        if self.schema_version in _V06_BINDING_SCHEMA_VERSIONS:
            _require_current_live_trajectory_report_identity(self)
        return self

    @model_validator(mode="after")
    def _validate_current_derivation(self) -> LiveTrajectoryReport:
        if self.schema_version != _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION:
            return self
        if (
            self.derivation_contract != _LIVE_TRAJECTORY_DERIVATION_CONTRACT
            or self.source_runset_digest is None
            or self.source_evaluation_digest is None
            or self.source_runset_completion_status is None
            or self.source_evaluation_completion_status is None
            or self.source_evaluation_stop_reasons is None
            or self.source_evaluation_exploratory is None
            or self.protocol is None
            or self.trajectory_plan is None
        ):
            raise ValueError(
                "current live trajectory reports require source digests, completion "
                "qualification and stop reasons, bound protocol, effective trajectory "
                "plan, and derivation contract"
            )
        if self.protocol.schema_version != _RARE_EVENT_CLUSTER_EXPOSURE_SCHEMA_VERSION:
            raise ValueError(
                "current live trajectory reports require a current bound protocol record"
            )
        _require_current_live_protocol_plan_versions(self.protocol)
        if self.trajectory_plan.schema_version != self.schema_version or any(
            invariant.schema_version != self.schema_version
            for invariant in self.trajectory_plan.invariants
        ):
            raise ValueError(
                "effective trajectory plan schema_version must match its current live "
                "trajectory report"
            )
        from agent_assure.live.trajectory import verify_live_trajectory_report_derivation

        verify_live_trajectory_report_derivation(self)
        return self

    @model_validator(mode="after")
    def _validate_legacy_derivation(self) -> LiveTrajectoryReport:
        from agent_assure.live.legacy_validation import (
            validate_legacy_live_trajectory_report,
        )

        validate_legacy_live_trajectory_report(self)
        return self
