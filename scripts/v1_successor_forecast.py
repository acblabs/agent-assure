"""Pure, nonauthorizing successor projection of delivery-forecast/v1.

The historical generation-2 ledger/catalog/aggregation definitions are inputs,
not mutable authorization. The host authenticates their exact source bytes and
rebuilds the complete roadmap ledger before calling this module. Two actual
human signatures over the containing producer and acceptance claims establish
the lifecycle; this projection cannot assert acceptance or verify a signature.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from typing import Any, cast

from scripts import v1_s1_successor as core

SCHEMA_PATH = "docs/governance/v1/sprint2/delivery-forecast.schema.json"
RECORD_DOMAIN = b"agent-assure:delivery-forecast/v3\x00"
V4_SCHEMA_PATH = "docs/governance/v1/sprint2/delivery-forecast-v4.schema.json"
V4_RECORD_DOMAIN = b"agent-assure:delivery-forecast/v4\x00"
METHOD_ID = "comonotonic-quantile-sum/v1"
METHOD_VERSION = "1.1.0"
METHOD_DEFINITION_DIGEST = "sha256:028ff736a0d4c7ac37a5fb15ba1ee733401a8be453569fc07b37fae6b27517f7"
REGISTRY_DIGEST = "sha256:7cac700d33f41f97156f459bf48bae5e4c65d36505aab6cb7e5c2df4acae1ba6"
CATALOG_DIGEST = "sha256:33cee0874eecf79f36a0dadcafa831525df206c9fdc67d9ab4759138475da439"
MAX_EXACT_INTEGER = 2**53 - 1
SCENARIOS = ("stable_core_committed", "optional_profile_planned")
PLANNING_INPUT_BINDINGS = (
    {
        "path": "docs/governance/v1/delivery-forecast.aggregation-registry.json",
        "size_bytes": 3366,
        "sha256": "sha256:687622f6edf8bedc16d0b14a3126805cccdfcd73dd563f4f5ce445c128afd454",
    },
    {
        "path": "docs/governance/v1/delivery-forecast.aggregation-registry.schema.json",
        "size_bytes": 5229,
        "sha256": "sha256:fe26890f9f053be9cc2c2782af2fe50e25f1ff7a99e6525ec02dc67d132994d1",
    },
    {
        "path": "docs/governance/v1/delivery-forecast.estimation-catalog.json",
        "size_bytes": 20010,
        "sha256": "sha256:64dfa1bd30a3da051b92bfc2a00a5581ee8e71a7aa2deaa4360670d08bd1f94d",
    },
    {
        "path": "docs/governance/v1/delivery-forecast.estimation-catalog.schema.json",
        "size_bytes": 9888,
        "sha256": "sha256:f35777e10f3257da91b0505c3bf90cc8e155b7ab556f8e0ba2352a2881acb1bf",
    },
)
_SOURCE_FIELDS = {
    "roadmap_digest",
    "ticket_set_digest",
    "dependency_graph_digest",
    "release_train_digest",
    "baseline_commit",
    "kickoff_claim_digest",
    "scope_digest",
    "trust_snapshot_digest",
    "inventory_digest",
    "dispatch_scope_digest",
    "approval_roster",
    "planning_input_bindings",
}
_ROSTER_FIELDS = {
    "person_id",
    "roles",
    "competence_scopes",
    "conflicts",
    "review_capacity",
    "mode",
    "independence",
}
_HUMAN_ROW_FIELDS = {"ticket_id", "estimate_scope", "execution_estimates"}
_V4_METADATA_FIELDS = {
    "confidence",
    "dependency_assumptions",
    "risk_assumptions",
    "current_status",
    "trusted_issue_time",
}
V4_DEPENDENCE_ASSUMPTIONS = (
    "full_positive_rank_dependence_no_diversification_credit",
    "reported_quantile_sums_are_exact_only_under_the_bound_comonotonic_construction",
)
_HUMAN_OCCURRENCE_FIELDS = {
    "occurrence_id",
    "p50_effort_hours",
    "p90_effort_hours",
    "reviewer_p50_effort_hours",
    "rationale",
}
_FILE_SCOPE_CONSTANTS = {
    "evidence_basis": "roadmap_resolved_allowed_files_cardinality",
    "interpretation": "unresolved_scope_not_zero_implementation_work",
    "estimate_status": "nonbinding_placeholders_pending_dispatch_scope_resolution",
    "rebaseline_trigger": (
        "resolve_approved_file_scope_at_ticket_dispatch_and_reestimate_when_concrete_"
        "surface_count_differs"
    ),
}


class ForecastError(core.SuccessorError):
    """The successor forecast does not exactly satisfy its pure contract."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ForecastError(message)


def _object(value: object, owner: str) -> dict[str, Any]:
    _require(isinstance(value, Mapping), f"{owner}: object required")
    result = dict(cast(Mapping[str, Any], value))
    _require(all(type(key) is str for key in result), f"{owner}: string keys required")
    return result


def _closed(value: object, fields: set[str], owner: str) -> dict[str, Any]:
    result = _object(value, owner)
    _require(set(result) == fields, f"{owner}: unexpected or missing fields")
    return result


def _array(value: object, owner: str, *, minimum: int = 1) -> list[Any]:
    _require(
        type(value) is list and minimum <= len(value) <= 4096, f"{owner}: bounded array required"
    )
    return cast(list[Any], value)


def _strings(value: object, owner: str) -> list[str]:
    result = [core._text(item, owner=owner) for item in _array(value, owner)]
    _require(len(set(result)) == len(result), f"{owner}: duplicate values")
    return result


def _integer(value: object, owner: str) -> int:
    _require(
        type(value) is int and 0 <= value <= MAX_EXACT_INTEGER, f"{owner}: exact integer required"
    )
    return cast(int, value)


def _sum(values: Sequence[int], owner: str) -> int:
    total = 0
    for value in values:
        total = _integer(total + _integer(value, owner), owner)
    return total


def _digest(domain: str, value: object) -> str:
    return core.content_digest(domain.encode("ascii") + b"\x00" + core.canonical_bytes(value))


def _validate_source(source: Mapping[str, Any], ledger: Mapping[str, Any]) -> dict[str, Any]:
    value = _closed(source, _SOURCE_FIELDS, "forecast source")
    for name in _SOURCE_FIELDS - {"baseline_commit", "approval_roster", "planning_input_bindings"}:
        core._digest(value[name])
    core._oid(value["baseline_commit"])
    for name in ("roadmap_digest", "ticket_set_digest", "release_train_digest"):
        _require(value[name] == ledger.get(name), f"forecast source {name} differs from ledger")
    if "dependency_graph_digest" in ledger:
        _require(
            value["dependency_graph_digest"] == ledger["dependency_graph_digest"],
            "forecast dependency graph differs from ledger",
        )
    _require(
        value["inventory_digest"] == ledger.get("baseline_observations_digest"),
        "forecast inventory differs from ledger",
    )
    bindings = _array(value["planning_input_bindings"], "planning input bindings")
    for binding in bindings:
        item = _closed(binding, {"path", "size_bytes", "sha256"}, "planning input binding")
        _integer(item["size_bytes"], "planning input size")
    _require(
        bindings == list(PLANNING_INPUT_BINDINGS),
        "forecast planning inputs are not the pinned bytes",
    )
    roster = _closed(value["approval_roster"], _ROSTER_FIELDS, "forecast approval roster")
    core._text(roster["person_id"], owner="roster person")
    _require(
        set(_strings(roster["roles"], "roster roles"))
        == {"technical_lead", "repository_maintainer"},
        "forecast roster roles differ",
    )
    _require(
        {"planning_governance:s1_successor", "schema_compatibility"}
        <= set(_strings(roster["competence_scopes"], "roster competence scopes")),
        "forecast roster competence scopes are incomplete",
    )
    _strings(roster["conflicts"], "roster conflicts")
    core._text(roster["review_capacity"], owner="roster review capacity")
    _require(
        roster["mode"] == "maintainer_development"
        and roster["independence"] == "NO_INDEPENDENT_REVIEW",
        "forecast roster mode differs",
    )
    return copy.deepcopy(value)


def _quantiles(value: Mapping[str, Any], owner: str) -> tuple[int, int, int]:
    p50 = _integer(value.get("p50_effort_hours"), f"{owner} P50")
    p90 = _integer(value.get("p90_effort_hours"), f"{owner} P90")
    review = _integer(value.get("reviewer_p50_effort_hours"), f"{owner} reviewer P50")
    _require(p50 <= p90, f"{owner}: inverted engineering quantiles")
    return p50, p90, review


def _aggregate(executions: Sequence[Mapping[str, Any]], tickets: Sequence[str]) -> dict[str, Any]:
    p50 = _sum([item["selected_p50_effort_hours"] for item in executions], "aggregate P50")
    p90 = _sum([item["selected_p90_effort_hours"] for item in executions], "aggregate P90")
    review = _sum(
        [item["selected_reviewer_p50_effort_hours"] for item in executions], "aggregate reviewer"
    )
    unique = sorted(set(tickets))
    return {
        "ticket_ids": unique,
        "ticket_count": len(unique),
        "occurrence_count": len(executions),
        "engineering_p50_effort_hours": p50,
        "engineering_p90_effort_hours": p90,
        "reviewer_p50_effort_hours": review,
        "combined_p50_effort_hours": _sum([p50, review], "combined P50"),
        "combined_p90_effort_hours": None,
        "elapsed_waits_included": False,
    }


def _execution(proposal: Mapping[str, Any], selected: object) -> dict[str, Any]:
    chosen = _closed(selected, _HUMAN_OCCURRENCE_FIELDS, "forecast human occurrence")
    occurrence_id = core._text(proposal.get("occurrence_id"), owner="source occurrence")
    _require(chosen["occurrence_id"] == occurrence_id, "forecast occurrence identity/order differs")
    proposed = _quantiles(_object(proposal.get("effort_proposal"), "proposed effort"), "proposal")
    adopted = _quantiles(chosen, "selected effort")
    rationale = core._text(chosen["rationale"], owner="human estimate rationale")
    elapsed = _object(proposal.get("elapsed_time"), "elapsed time")
    _require(
        elapsed.get("included_in_effort_quantiles") is False, "elapsed waits included in effort"
    )
    _require(
        elapsed.get("critical_path_status")
        in {"not_modeled_pending_human_review", "not_modeled_scope_rebaseline_required"},
        "unknown elapsed critical path status",
    )
    immutable = copy.deepcopy(
        {
            key: value
            for key, value in proposal.items()
            if key not in {"proposal_digest", "decision"}
        }
    )
    immutable["elapsed_time"]["critical_path_status"] = "not_modeled_pending_human_review"
    _require(
        proposal.get("proposal_digest")
        == _digest("agent-assure:delivery-forecast-occurrence-proposal/v2", immutable),
        "forecast occurrence proposal digest mismatch",
    )
    maximum = _integer(elapsed.get("maximum_single_known_wait_hours"), "maximum known wait")
    serial = _integer(elapsed.get("serial_sum_known_wait_hours"), "serial known waits")
    _require(maximum <= serial, "maximum wait exceeds serial sum")
    scenario = proposal.get("scenario_class")
    _require(scenario in SCENARIOS, "unknown forecast scenario")
    return {
        "occurrence_id": occurrence_id,
        "sprint": core._text(proposal.get("sprint"), owner="forecast sprint"),
        "release": core._text(proposal.get("release"), owner="forecast release"),
        "scenario_class": scenario,
        "workload_vector_digest": core._digest(proposal.get("workload_vector_digest")),
        "proposal_digest": core._digest(proposal.get("proposal_digest")),
        "derivation_disposition": "reestimated_after_inventory",
        "proposed_p50_effort_hours": proposed[0],
        "proposed_p90_effort_hours": proposed[1],
        "proposed_reviewer_p50_effort_hours": proposed[2],
        "selected_p50_effort_hours": adopted[0],
        "selected_p90_effort_hours": adopted[1],
        "selected_reviewer_p50_effort_hours": adopted[2],
        "selection_mode": "adopt_machine_proposal" if proposed == adopted else "human_adjusted",
        "rationale": rationale,
        "maximum_single_known_wait_hours": maximum,
        "serial_sum_known_wait_hours": serial,
        "unquantified_wait_dependency_count": _integer(
            elapsed.get("unquantified_wait_dependency_count"), "unquantified waits"
        ),
        "elapsed_wait_included": False,
        "calendar_critical_path_modeled": False,
    }


def build_projection(
    *,
    authoring_ledger: Mapping[str, Any],
    human_estimates: object,
    source: Mapping[str, Any],
    issued_at_utc: str,
    valid_until_utc: str,
    now: datetime,
) -> dict[str, Any]:
    """Recompute all ordered rows and occurrences; produce no authorization.

    Population size comes from the authenticated, fully rebuilt roadmap ledger,
    never a selected dispatch subset. Current production inputs are 68 tickets
    and 121 occurrences; this pure function also supports smaller test sources.
    """
    ledger = _object(authoring_ledger, "authoring ledger")
    _require(
        ledger.get("format") == "agent-assure-delivery-forecast-authoring-ledger/2",
        "forecast requires the generation-2 authoring ledger",
    )
    _require(
        ledger.get("ledger_digest")
        == _digest(
            "agent-assure:delivery-forecast-authoring-ledger/v2",
            {key: value for key, value in ledger.items() if key != "ledger_digest"},
        ),
        "forecast authoring ledger digest mismatch",
    )
    _require(
        ledger.get("estimation_catalog_digest") == CATALOG_DIGEST,
        "forecast estimation catalog differs",
    )
    provenance = _validate_source(source, ledger)
    inventory_time = core._time(ledger.get("inventory_completed_at_utc"))
    issue, expiry, current = core._time(issued_at_utc), core._time(valid_until_utc), core._now(now)
    _require(
        inventory_time <= issue <= current < expiry and expiry - issue <= timedelta(days=30),
        "forecast issue/expiry/inventory interval is future, stale, or excessive",
    )
    raw_rows = _array(ledger.get("rows"), "forecast ledger rows")
    selected_rows = _array(human_estimates, "forecast human rows")
    _require(len(raw_rows) == len(selected_rows), "forecast must cover every ticket")
    rows: list[dict[str, Any]] = []
    all_executions: list[dict[str, Any]] = []
    all_tickets: list[str] = []
    seen_tickets: set[str] = set()
    seen_occurrences: set[str] = set()
    for raw_row, raw_selected in zip(raw_rows, selected_rows, strict=True):
        row = _object(raw_row, "forecast source row")
        selected = _closed(raw_selected, _HUMAN_ROW_FIELDS, "forecast human row")
        ticket = core._text(row.get("ticket_id"), owner="forecast ticket")
        scope = core._text(row.get("estimate_scope"), owner="forecast estimate scope")
        _require(
            ticket not in seen_tickets
            and selected["ticket_id"] == ticket
            and selected["estimate_scope"] == scope,
            "forecast ticket identity/scope/order differs",
        )
        seen_tickets.add(ticket)
        proposals = _array(row.get("execution_proposals"), "forecast source occurrences")
        estimates = _array(selected["execution_estimates"], "forecast human occurrences")
        _require(len(proposals) == len(estimates), "forecast must cover every occurrence")
        executions = []
        for raw_proposal, chosen in zip(proposals, estimates, strict=True):
            execution = _execution(_object(raw_proposal, "forecast proposal"), chosen)
            _require(
                execution["occurrence_id"] not in seen_occurrences, "duplicate forecast occurrence"
            )
            seen_occurrences.add(execution["occurrence_id"])
            executions.append(execution)
            all_executions.append(execution)
            all_tickets.append(ticket)
            _require(len(all_executions) <= 4096, "forecast occurrence population exceeds budget")
        rows.append(
            {
                "ticket_id": ticket,
                "estimate_scope": scope,
                "prior_disposition": "stale_not_used_as_anchor",
                "derivation_disposition": "reestimated_after_inventory",
                "planned_execution_count": len(executions),
                "execution_estimates": executions,
                "aggregate": _aggregate(executions, [ticket]),
            }
        )
    file_scope = _closed(
        ledger.get("file_scope_observation"),
        {"ticket_count", "resolved_ticket_count", "unresolved_ticket_count"}
        | set(_FILE_SCOPE_CONSTANTS),
        "forecast file scope",
    )
    _require(
        all(file_scope[key] == value for key, value in _FILE_SCOPE_CONSTANTS.items()),
        "forecast file scope interpretation differs",
    )
    _require(
        _integer(file_scope.get("ticket_count"), "file scope ticket count") == len(rows),
        "forecast file scope population differs",
    )
    resolved = _integer(file_scope.get("resolved_ticket_count"), "resolved ticket count")
    unresolved = _integer(file_scope.get("unresolved_ticket_count"), "unresolved ticket count")
    _require(
        _sum([resolved, unresolved], "file scope total") == len(rows),
        "forecast file scope counts do not reconcile",
    )
    scenarios = []
    for scenario in SCENARIOS:
        members = [
            (item, ticket)
            for item, ticket in zip(all_executions, all_tickets, strict=True)
            if item["scenario_class"] == scenario
        ]
        scenarios.append(
            {
                "scenario_id": scenario,
                **_aggregate([item for item, _ in members], [ticket for _, ticket in members]),
            }
        )
    projection = {
        "contract_id": "delivery-forecast/v1",
        "format": "agent-assure-delivery-forecast/3",
        "spec_revision": "6.5",
        "projection_status": "prepared_non_authorizing",
        "authorization_effect": "none",
        "signature_lifecycle": "external_producer_and_repository_maintainer_sshsig_claims",
        "source": provenance,
        "authoring_ledger_digest": core._digest(ledger["ledger_digest"]),
        "human_estimates_digest": _digest(
            "agent-assure:delivery-forecast-human-estimates/v3", human_estimates
        ),
        "approval_roster_digest": _digest(
            "agent-assure:delivery-forecast-approval-roster/v3", provenance["approval_roster"]
        ),
        "estimation_catalog_digest": CATALOG_DIGEST,
        "aggregation_method_registry_digest": REGISTRY_DIGEST,
        "aggregation_method": {
            "method_id": METHOD_ID,
            "version": METHOD_VERSION,
            "definition_digest": METHOD_DEFINITION_DIGEST,
            "unit": "focused_person_hour",
            "dependence_assumption": "full_positive_rank_dependence_no_diversification_credit",
            "reviewer_effort_coupling": "same_shared_rank_as_engineering_no_reviewer_p90_available",
            "quantile_definition": "Q_p(X)=inf{x:F_X(x)>=p}",
            "arithmetic": "checked_nonnegative_integer_sum_no_rounding",
            "independence_claimed": False,
            "distribution_free_upper_bound_claimed": False,
        },
        "file_scope_observation": copy.deepcopy(file_scope),
        "inventory_completed_at_utc": ledger["inventory_completed_at_utc"],
        "issued_at_utc": issued_at_utc,
        "valid_until_utc": valid_until_utc,
        "trusted_time_basis": "maintainer_host_utc_externally_unattested",
        "actual_signature_time_claimed": False,
        "confidence_basis": (
            "selected_subjective_uncalibrated_planning_quantiles_pending_external_signatures"
        ),
        "calendar_commitment": False,
        "portfolio_scenarios": scenarios,
        "portfolio_aggregate": _aggregate(all_executions, all_tickets),
        "rows": rows,
    }
    return {
        **projection,
        "record_digest": core.content_digest(RECORD_DOMAIN + core.canonical_bytes(projection)),
    }


def build_projection_v4(
    *,
    authoring_ledger: Mapping[str, Any],
    human_estimates: object,
    source: Mapping[str, Any],
    issued_at_utc: str,
    valid_until_utc: str,
    now: datetime,
) -> dict[str, Any]:
    """Build a complete, explicitly selected planning row contract.

    Version 3 remains a historical replay surface. Version 4 requires fresh,
    explicit per-ticket planning metadata; it does not turn a prior signature,
    machine suggestion, or global confidence statement into a human decision.
    The caller must authenticate the source and obtain the separate signatures.
    """
    selected_rows = copy.deepcopy(_array(human_estimates, "generation-4 human rows"))
    inventory_time = core._time(authoring_ledger.get("inventory_completed_at_utc"))
    issue = core._time(issued_at_utc)
    legacy_selections: list[dict[str, Any]] = []
    metadata: list[dict[str, Any]] = []
    for raw_row in selected_rows:
        selected = _closed(
            raw_row, _HUMAN_ROW_FIELDS | _V4_METADATA_FIELDS, "generation-4 human row"
        )
        _require(selected["confidence"] in ("low", "medium", "high"), "invalid row confidence")
        _require(
            selected["current_status"] in ("not_started", "in_progress", "blocked", "done"),
            "invalid row current status",
        )
        for field in ("dependency_assumptions", "risk_assumptions"):
            assumptions = _strings(selected[field], f"row {field}")
            _require(all(item.strip() for item in assumptions), f"row {field}: blank assumption")
        row_issue = core._time(selected["trusted_issue_time"])
        _require(
            inventory_time <= row_issue <= issue,
            "row issue time must follow inventory and not exceed record issue time",
        )
        legacy_selections.append({key: selected[key] for key in _HUMAN_ROW_FIELDS})
        metadata.append({key: copy.deepcopy(selected[key]) for key in _V4_METADATA_FIELDS})

    # Reuse the exact checked arithmetic and ordered occurrence reconstruction.
    # This creates a new projection, never mutates a historical record or input.
    previous = build_projection(
        authoring_ledger=authoring_ledger,
        human_estimates=legacy_selections,
        source=source,
        issued_at_utc=issued_at_utc,
        valid_until_utc=valid_until_utc,
        now=now,
    )
    projection = {key: value for key, value in previous.items() if key != "record_digest"}
    projection["format"] = "agent-assure-delivery-forecast/4"
    projection["human_estimates_digest"] = _digest(
        "agent-assure:delivery-forecast-human-estimates/v4", selected_rows
    )
    projection["approval_roster_digest"] = _digest(
        "agent-assure:delivery-forecast-approval-roster/v4", projection["source"]["approval_roster"]
    )
    for row, adopted in zip(projection["rows"], metadata, strict=True):
        aggregate = row["aggregate"]
        row.update(
            aggregate_p50_effort_hours=aggregate["engineering_p50_effort_hours"],
            aggregate_p90_effort_hours=aggregate["engineering_p90_effort_hours"],
            aggregate_reviewer_effort_hours=aggregate["reviewer_p50_effort_hours"],
            aggregate_method_id=METHOD_ID,
            aggregate_method_definition_digest=METHOD_DEFINITION_DIGEST,
            aggregate_dependence_assumptions=list(V4_DEPENDENCE_ASSUMPTIONS),
            **adopted,
        )
        for execution in row["execution_estimates"]:
            execution.update(
                p50_effort_hours=execution["selected_p50_effort_hours"],
                p90_effort_hours=execution["selected_p90_effort_hours"],
                reviewer_effort_hours=execution["selected_reviewer_p50_effort_hours"],
            )
    return {
        **projection,
        "record_digest": core.content_digest(V4_RECORD_DOMAIN + core.canonical_bytes(projection)),
    }


def validate_projection(
    record: Mapping[str, Any],
    *,
    authoring_ledger: Mapping[str, Any],
    human_estimates: object,
    source: Mapping[str, Any],
    now: datetime,
) -> dict[str, Any]:
    """Reconstruct a supported projection from authenticated external inputs.

    This checks the entire value graph, including exact types and digest bytes.
    A caller must separately verify signatures, source authenticity and scope;
    a schema-valid or correctly hashed record is not acceptance evidence.
    """
    supplied = _object(record, "forecast projection")
    version = supplied.get("format")
    _require(
        version in ("agent-assure-delivery-forecast/3", "agent-assure-delivery-forecast/4"),
        "unsupported forecast projection format",
    )
    builder = (
        build_projection_v4 if version == "agent-assure-delivery-forecast/4" else build_projection
    )
    expected = builder(
        authoring_ledger=authoring_ledger,
        human_estimates=human_estimates,
        source=source,
        issued_at_utc=core._text(supplied.get("issued_at_utc"), owner="forecast issue time"),
        valid_until_utc=core._text(supplied.get("valid_until_utc"), owner="forecast expiry time"),
        now=now,
    )
    # Python value equality aliases True with 1 and 1.0 with 1. Canonical bytes
    # distinguish booleans, but JCS normalizes integral floats. Enforce the
    # recursive JSON types before comparing either representation.
    _require(_same_json_types(supplied, expected), "forecast projection JSON types differ")
    _require(
        core.canonical_bytes(supplied) == core.canonical_bytes(expected),
        "forecast projection differs from complete reconstruction",
    )
    return expected


def _same_json_types(value: Any, expected: Any) -> bool:
    if type(value) is not type(expected):
        return False
    if type(expected) is dict:
        return set(value) == set(expected) and all(
            _same_json_types(value[key], item) for key, item in expected.items()
        )
    if type(expected) is list:
        return len(value) == len(expected) and all(
            _same_json_types(item, other) for item, other in zip(value, expected, strict=True)
        )
    return True
