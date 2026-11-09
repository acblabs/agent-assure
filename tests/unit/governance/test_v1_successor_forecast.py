"""Independent exact-arithmetic QA for the successor planning projection.

Every source is a tiny public synthetic fixture. These tests neither supply
private roadmap data nor create human or independent-method acceptance.
"""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from datetime import UTC, datetime, timedelta
from fractions import Fraction
from pathlib import Path
from typing import Any

import pytest
import rfc8785
from jsonschema import Draft202012Validator, ValidationError

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import v1_s1_governance as legacy  # noqa: E402
from scripts import v1_s1_successor as core  # noqa: E402
from scripts import v1_successor_forecast as forecast  # noqa: E402

ISSUED = datetime(2026, 11, 7, 12, tzinfo=UTC)
NOW = ISSUED + timedelta(minutes=1)
VALID_UNTIL = ISSUED + timedelta(days=2)


def _digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


def _stamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _refresh(ledger: dict[str, Any]) -> None:
    ledger["ledger_digest"] = legacy.domain_digest(
        legacy.LEDGER_V2_DOMAIN,
        {key: value for key, value in ledger.items() if key != "ledger_digest"},
    )


def _fixture() -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    rows = []
    for ticket, cases in (
        ("V1-SYN-01", ((2, 9, 1), (3, 10, 2))),
        ("V1-SYN-02", ((4, 14, 3),)),
    ):
        proposals = []
        for index, (p50, p90, reviewer) in enumerate(cases):
            sprint, release = f"S{index + 2}", f"1.0.0a{index + 2}"
            proposal = {
                "occurrence_id": f"{ticket}@{sprint}/{release}",
                "sprint": sprint,
                "release": release,
                "scenario_class": (
                    "stable_core_committed" if index == 0 else "optional_profile_planned"
                ),
                "workload_vector_digest": _digest(f"synthetic workload {ticket}/{index}"),
                "effort_proposal": {
                    "p50_effort_hours": p50,
                    "p90_effort_hours": p90,
                    "reviewer_p50_effort_hours": reviewer,
                },
                "elapsed_time": {
                    "included_in_effort_quantiles": False,
                    "maximum_single_known_wait_hours": 24 * (index + 1),
                    "serial_sum_known_wait_hours": 48 * (index + 1),
                    "unquantified_wait_dependency_count": index + 1,
                    "critical_path_status": "not_modeled_pending_human_review",
                },
            }
            proposal["proposal_digest"] = legacy._occurrence_proposal_v2_digest(proposal)
            proposals.append(proposal)
        rows.append(
            {
                "ticket_id": ticket,
                "estimate_scope": "per_candidate_execution",
                "execution_proposals": proposals,
            }
        )
    ledger = {
        "format": "agent-assure-delivery-forecast-authoring-ledger/2",
        "spec_revision": "6.5",
        "roadmap_digest": _digest("synthetic roadmap bytes"),
        "ticket_set_digest": _digest("synthetic sorted ticket set"),
        "release_train_digest": _digest("synthetic release train"),
        "baseline_observations_digest": _digest("synthetic source inventory"),
        "inventory_completed_at_utc": _stamp(ISSUED - timedelta(minutes=5)),
        "estimation_catalog_digest": legacy.ESTIMATION_CATALOG_V2_DIGEST,
        "file_scope_observation": {
            "ticket_count": 2,
            "resolved_ticket_count": 0,
            "unresolved_ticket_count": 2,
            "evidence_basis": "roadmap_resolved_allowed_files_cardinality",
            "interpretation": "unresolved_scope_not_zero_implementation_work",
            "estimate_status": "nonbinding_placeholders_pending_dispatch_scope_resolution",
            "rebaseline_trigger": (
                "resolve_approved_file_scope_at_ticket_dispatch_and_reestimate_"
                "when_concrete_surface_count_differs"
            ),
        },
        "rows": rows,
    }
    _refresh(ledger)
    selected = [
        {
            "ticket_id": row["ticket_id"],
            "estimate_scope": row["estimate_scope"],
            "execution_estimates": [
                {
                    "occurrence_id": occurrence["occurrence_id"],
                    **occurrence["effort_proposal"],
                    "rationale": "Synthetic explicit adoption after source review",
                }
                for occurrence in row["execution_proposals"]
            ],
        }
        for row in rows
    ]
    selected[0]["execution_estimates"][0].update(
        p50_effort_hours=5,
        p90_effort_hours=12,
        rationale="Synthetic human revised the first occurrence after reviewing its scope",
    )
    source = {
        "roadmap_digest": ledger["roadmap_digest"],
        "ticket_set_digest": ledger["ticket_set_digest"],
        "dependency_graph_digest": _digest("synthetic dependency graph"),
        "release_train_digest": ledger["release_train_digest"],
        "baseline_commit": "a" * 40,
        "kickoff_claim_digest": _digest("synthetic signed kickoff claim"),
        "scope_digest": _digest("synthetic exact prospective scope"),
        "trust_snapshot_digest": _digest("synthetic scoped trust snapshot"),
        "inventory_digest": ledger["baseline_observations_digest"],
        "dispatch_scope_digest": _digest("synthetic dispatch file observations"),
        "approval_roster": {
            "person_id": "acblabs",
            "roles": ["repository_maintainer", "technical_lead"],
            "competence_scopes": ["planning_governance:s1_successor", "schema_compatibility"],
            "conflicts": ["Synthetic single-maintainer development review"],
            "review_capacity": "Synthetic explicitly declared capacity",
            "mode": "maintainer_development",
            "independence": "NO_INDEPENDENT_REVIEW",
        },
        "planning_input_bindings": copy.deepcopy(list(forecast.PLANNING_INPUT_BINDINGS)),
    }
    return ledger, selected, source


def _build(
    ledger: dict[str, Any], selected: list[dict[str, Any]], source: dict[str, Any], **times: Any
) -> dict[str, Any]:
    return forecast.build_projection(
        authoring_ledger=ledger,
        human_estimates=selected,
        source=source,
        issued_at_utc=times.get("issued_at_utc", _stamp(ISSUED)),
        valid_until_utc=times.get("valid_until_utc", _stamp(VALID_UNTIL)),
        now=times.get("now", NOW),
    )


def _quantile(atoms: list[tuple[int, Fraction]], rank: Fraction) -> int:
    accumulated = Fraction(0)
    for value, probability in sorted(atoms):
        accumulated += probability
        if accumulated >= rank:
            return value
    raise AssertionError("reference atom masses must total one")


def test_selected_projection_matches_independent_common_rank_distribution_and_set_union() -> None:
    ledger, selected, source = _fixture()
    before = copy.deepcopy((ledger, selected, source))
    record = _build(ledger, selected, source)
    assert (ledger, selected, source) == before
    assert record["contract_id"] == "delivery-forecast/v1"
    assert record["format"] == "agent-assure-delivery-forecast/3"
    assert record["authorization_effect"] == "none"
    assert record["projection_status"] == "prepared_non_authorizing"
    assert record["calendar_commitment"] is False
    assert record["actual_signature_time_claimed"] is False
    assert "uncalibrated" in record["confidence_basis"]

    # Shared-rank state masses construct nondecreasing marginal quantiles.
    # Quantiles are obtained directly from the distribution of summed atoms.
    atoms = []
    review_atoms = []
    for state, mass in ((0, Fraction(1, 2)), (1, Fraction(2, 5)), (2, Fraction(1, 10))):
        engineering = 0
        reviewer = 0
        for row in selected:
            for item in row["execution_estimates"]:
                engineering += (
                    item["p50_effort_hours"]
                    if state == 0
                    else item["p90_effort_hours"] * (1 if state == 1 else 2)
                )
                # Only reviewer P50 is elicited. This illustrative tail is one
                # compatible completion, not an inferred reviewer P90.
                reviewer += item["reviewer_p50_effort_hours"] * (state + 1)
        atoms.append((engineering, mass))
        review_atoms.append((engineering + reviewer, mass))
    aggregate = record["portfolio_aggregate"]
    assert aggregate["engineering_p50_effort_hours"] == _quantile(atoms, Fraction(1, 2)) == 12
    assert aggregate["engineering_p90_effort_hours"] == _quantile(atoms, Fraction(9, 10)) == 36
    assert aggregate["reviewer_p50_effort_hours"] == 6
    assert aggregate["combined_p50_effort_hours"] == _quantile(review_atoms, Fraction(1, 2)) == 18
    assert aggregate["combined_p90_effort_hours"] is None
    assert aggregate["elapsed_waits_included"] is False
    assert aggregate["ticket_ids"] == ["V1-SYN-01", "V1-SYN-02"]
    assert aggregate["ticket_count"] == 2 and aggregate["occurrence_count"] == 3
    stable, optional = record["portfolio_scenarios"]
    assert stable["scenario_id"] == "stable_core_committed"
    assert optional["scenario_id"] == "optional_profile_planned"
    assert stable["engineering_p50_effort_hours"] == 9
    assert stable["engineering_p90_effort_hours"] == 26
    assert stable["reviewer_p50_effort_hours"] == 4
    assert optional["engineering_p50_effort_hours"] == 3
    assert optional["engineering_p90_effort_hours"] == 10
    assert optional["reviewer_p50_effort_hours"] == 2
    assert stable["ticket_count"] + optional["ticket_count"] == 3
    assert aggregate["ticket_count"] == len(set(stable["ticket_ids"]) | set(optional["ticket_ids"]))
    first = record["rows"][0]["execution_estimates"][0]
    assert first["proposed_p50_effort_hours"] == 2
    assert first["selected_p50_effort_hours"] == 5
    assert first["selection_mode"] == "human_adjusted"
    assert first["maximum_single_known_wait_hours"] == 24
    assert first["serial_sum_known_wait_hours"] == 48
    assert first["calendar_critical_path_modeled"] is False
    assert record["rows"][0]["aggregate"]["engineering_p50_effort_hours"] == 8
    assert record["rows"][1]["aggregate"]["engineering_p50_effort_hours"] == 4


def test_record_and_method_bindings_use_exact_pinned_domain_separated_bytes() -> None:
    ledger, selected, source = _fixture()
    record = _build(ledger, selected, source)
    projection = {key: value for key, value in record.items() if key != "record_digest"}
    assert (
        record["record_digest"]
        == "sha256:"
        + hashlib.sha256(
            b"agent-assure:delivery-forecast/v3\x00" + rfc8785.dumps(projection)
        ).hexdigest()
    )
    assert record["authoring_ledger_digest"] == ledger["ledger_digest"]
    assert record["aggregation_method_registry_digest"] == forecast.REGISTRY_DIGEST
    assert record["aggregation_method"]["definition_digest"] == forecast.METHOD_DEFINITION_DIGEST
    assert record["aggregation_method"]["method_id"] == "comonotonic-quantile-sum/v1"
    assert record["aggregation_method"]["version"] == "1.1.0"
    assert record["aggregation_method"]["independence_claimed"] is False
    assert record["aggregation_method"]["distribution_free_upper_bound_claimed"] is False
    assert (
        record["human_estimates_digest"]
        == "sha256:"
        + hashlib.sha256(
            b"agent-assure:delivery-forecast-human-estimates/v3\x00" + rfc8785.dumps(selected)
        ).hexdigest()
    )
    assert (
        record["approval_roster_digest"]
        == "sha256:"
        + hashlib.sha256(
            b"agent-assure:delivery-forecast-approval-roster/v3\x00"
            + rfc8785.dumps(source["approval_roster"])
        ).hexdigest()
    )
    for binding in forecast.PLANNING_INPUT_BINDINGS:
        raw = (ROOT / binding["path"]).read_bytes()
        assert binding["size_bytes"] == len(raw)
        assert binding["sha256"] == "sha256:" + hashlib.sha256(raw).hexdigest()
    registry = json.loads(
        (ROOT / "docs/governance/v1/delivery-forecast.aggregation-registry.json").read_bytes()
    )
    method = registry["methods"][0]
    assert (
        method["definition_digest"]
        == "sha256:"
        + hashlib.sha256(
            b"agent-assure:delivery-forecast-aggregation-method/v2\x00"
            + rfc8785.dumps(
                {key: value for key, value in method.items() if key != "definition_digest"}
            )
        ).hexdigest()
    )
    assert (
        registry["registry_digest"]
        == "sha256:"
        + hashlib.sha256(
            b"agent-assure:delivery-forecast-aggregation-registry/v2\x00"
            + rfc8785.dumps(
                {key: value for key, value in registry.items() if key != "registry_digest"}
            )
        ).hexdigest()
    )
    assert method["definition_digest"] == record["aggregation_method"]["definition_digest"]
    assert registry["registry_digest"] == record["aggregation_method_registry_digest"]


def test_new_closed_forecast_schema_accepts_exact_projection_and_rejects_overclaims() -> None:
    schema = json.loads((ROOT / forecast.SCHEMA_PATH).read_bytes())
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    record = _build(*_fixture())
    validator.validate(record)
    variants = []
    for field, value in (
        ("format", "agent-assure-delivery-forecast/2"),
        ("authorization_effect", "production_release"),
        ("actual_signature_time_claimed", True),
        ("calendar_commitment", True),
        ("signature_envelope", {"status": "signed"}),
    ):
        changed = copy.deepcopy(record)
        changed[field] = value
        variants.append(changed)
    changed = copy.deepcopy(record)
    changed["portfolio_aggregate"]["combined_p90_effort_hours"] = 100
    variants.append(changed)
    for changed in variants:
        with pytest.raises(ValidationError):
            validator.validate(changed)


def test_review_and_validity_source_changes_create_another_exact_subject() -> None:
    ledger, selected, source = _fixture()
    original = _build(ledger, selected, source)
    for field in ("dependency_graph_digest", "baseline_commit", "trust_snapshot_digest"):
        changed = copy.deepcopy(source)
        changed[field] = "b" * 40 if field == "baseline_commit" else _digest("another source")
        current = _build(ledger, selected, changed)
        assert current["source"][field] == changed[field]
        assert current["record_digest"] != original["record_digest"]
    later = _build(
        ledger, selected, source, valid_until_utc=_stamp(VALID_UNTIL + timedelta(seconds=1))
    )
    assert later["record_digest"] != original["record_digest"]
    changed_estimates = copy.deepcopy(selected)
    changed_estimates[0]["execution_estimates"][0]["rationale"] += "; explicit revision"
    revised = _build(ledger, changed_estimates, source)
    assert revised["portfolio_aggregate"] == original["portfolio_aggregate"]
    assert revised["human_estimates_digest"] != original["human_estimates_digest"]
    assert revised["record_digest"] != original["record_digest"]


def test_common_rank_quantile_sum_is_not_a_distribution_free_upper_bound() -> None:
    # Both workloads have mass .91 at zero and .09 at100, so both marginal
    # Q_.9 values are zero. Aligning rare events keeps the sum's Q_.9 at zero;
    # disjoint rare events raise it to100 with exactly the same marginals.
    common_rank = [(0, Fraction(91, 100)), (200, Fraction(9, 100))]
    disjoint_events = [(0, Fraction(82, 100)), (100, Fraction(18, 100))]
    assert _quantile(common_rank, Fraction(9, 10)) == 0
    assert _quantile(disjoint_events, Fraction(9, 10)) == 100
    ledger, selected, source = _fixture()
    assert (
        _build(ledger, selected, source)["aggregation_method"][
            "distribution_free_upper_bound_claimed"
        ]
        is False
    )


def test_reviewer_p50_does_not_identify_a_combined_p90_even_under_common_rank() -> None:
    # The two reviewer tails share Q_.5=6 and the same rank variable, but give
    # different Q_.9 values after adding the identical engineering workload.
    quiet_tail = [(18, Fraction(1, 2)), (42, Fraction(2, 5)), (78, Fraction(1, 10))]
    heavy_tail = [
        (18, Fraction(1, 2)),
        (1_000_036, Fraction(2, 5)),
        (2_000_072, Fraction(1, 10)),
    ]
    assert _quantile(quiet_tail, Fraction(1, 2)) == _quantile(heavy_tail, Fraction(1, 2)) == 18
    assert _quantile(quiet_tail, Fraction(9, 10)) == 42
    assert _quantile(heavy_tail, Fraction(9, 10)) == 1_000_036
    ledger, selected, source = _fixture()
    assert (
        _build(ledger, selected, source)["portfolio_aggregate"]["combined_p90_effort_hours"] is None
    )


def test_exact_integer_boundary_and_aggregate_overflow_are_checked_without_rounding() -> None:
    ledger, selected, source = _fixture()
    for row in selected:
        for occurrence in row["execution_estimates"]:
            occurrence.update(p50_effort_hours=0, p90_effort_hours=0, reviewer_p50_effort_hours=0)
    selected[0]["execution_estimates"][0]["p90_effort_hours"] = 2**53 - 1
    record = _build(ledger, selected, source)
    assert record["portfolio_aggregate"]["engineering_p90_effort_hours"] == 2**53 - 1
    selected[1]["execution_estimates"][0]["p90_effort_hours"] = 1
    with pytest.raises(core.SuccessorError, match="exact integer"):
        _build(ledger, selected, source)
    selected[1]["execution_estimates"][0]["p90_effort_hours"] = 0
    first = selected[0]["execution_estimates"][0]
    first.update(p50_effort_hours=2**53 - 1, reviewer_p50_effort_hours=1)
    with pytest.raises(core.SuccessorError, match="exact integer"):
        _build(ledger, selected, source)


def test_waits_change_the_bound_record_without_becoming_person_hours() -> None:
    ledger, selected, source = _fixture()
    initial = _build(ledger, selected, source)
    proposal = ledger["rows"][0]["execution_proposals"][0]
    proposal["elapsed_time"].update(
        maximum_single_known_wait_hours=10_000,
        serial_sum_known_wait_hours=20_000,
        unquantified_wait_dependency_count=100,
    )
    proposal["proposal_digest"] = legacy._occurrence_proposal_v2_digest(proposal)
    _refresh(ledger)
    revised = _build(ledger, selected, source)
    assert revised["portfolio_aggregate"] == initial["portfolio_aggregate"]
    assert revised["record_digest"] != initial["record_digest"]
    assert revised["rows"][0]["execution_estimates"][0]["serial_sum_known_wait_hours"] == 20_000


def test_empty_optional_partition_is_explicit_and_reconciles_to_the_full_portfolio() -> None:
    ledger, selected, source = _fixture()
    for row in ledger["rows"]:
        for proposal in row["execution_proposals"]:
            proposal["scenario_class"] = "stable_core_committed"
            proposal["proposal_digest"] = legacy._occurrence_proposal_v2_digest(proposal)
    _refresh(ledger)
    record = _build(ledger, selected, source)
    stable, optional = record["portfolio_scenarios"]
    assert optional["ticket_ids"] == []
    assert optional["ticket_count"] == optional["occurrence_count"] == 0
    assert optional["engineering_p50_effort_hours"] == 0
    assert optional["engineering_p90_effort_hours"] == 0
    assert optional["reviewer_p50_effort_hours"] == 0
    assert {key: value for key, value in stable.items() if key != "scenario_id"} == record[
        "portfolio_aggregate"
    ]


@pytest.mark.parametrize(
    "mutation",
    [
        "missing-source",
        "unknown-source",
        "wrong-roadmap",
        "wrong-ticket-set",
        "wrong-release-train",
        "wrong-inventory",
        "malformed-base-commit",
        "altered-planning-input",
        "altered-roster-mode",
        "independent-roster-claim",
        "stale-ledger-digest",
        "stale-proposal-digest",
        "duplicate-ticket",
        "duplicate-occurrence",
        "unknown-scenario",
        "contradictory-waits",
        "negative-wait-count",
        "missing-selected-ticket",
        "reordered-selected-tickets",
        "missing-selected-occurrence",
        "reordered-selected-occurrences",
        "boolean-hours",
        "floating-hours",
        "negative-hours",
        "inverted-quantiles",
        "overflowing-hours",
        "empty-rationale",
        "claimed-actuals",
    ],
)
def test_forecast_rejects_broken_source_identity_coverage_or_exact_arithmetic(
    mutation: str,
) -> None:
    ledger, selected, source = _fixture()
    proposal = ledger["rows"][0]["execution_proposals"][0]
    estimate = selected[0]["execution_estimates"][0]
    refresh = False
    if mutation == "missing-source":
        source.pop("dependency_graph_digest")
    elif mutation == "unknown-source":
        source["unreviewed_actual_hours"] = 12
    elif mutation.startswith("wrong-"):
        field = {
            "wrong-roadmap": "roadmap_digest",
            "wrong-ticket-set": "ticket_set_digest",
            "wrong-release-train": "release_train_digest",
            "wrong-inventory": "inventory_digest",
        }[mutation]
        source[field] = _digest("altered identity")
    elif mutation == "malformed-base-commit":
        source["baseline_commit"] = "not-an-object-id"
    elif mutation == "altered-planning-input":
        source["planning_input_bindings"][0]["sha256"] = _digest("altered planning input")
    elif mutation == "altered-roster-mode":
        source["approval_roster"]["mode"] = "production_release"
    elif mutation == "independent-roster-claim":
        source["approval_roster"]["independence"] = "INDEPENDENT_REVIEW"
    elif mutation == "stale-ledger-digest":
        ledger["ledger_digest"] = _digest("wrong ledger")
    elif mutation == "stale-proposal-digest":
        proposal["effort_proposal"]["p90_effort_hours"] += 1
        refresh = True
    elif mutation == "duplicate-ticket":
        ledger["rows"][1]["ticket_id"] = ledger["rows"][0]["ticket_id"]
        selected[1]["ticket_id"] = selected[0]["ticket_id"]
        refresh = True
    elif mutation == "duplicate-occurrence":
        duplicate = ledger["rows"][1]["execution_proposals"][0]
        duplicate["occurrence_id"] = proposal["occurrence_id"]
        duplicate["proposal_digest"] = legacy._occurrence_proposal_v2_digest(duplicate)
        selected[1]["execution_estimates"][0]["occurrence_id"] = proposal["occurrence_id"]
        refresh = True
    elif mutation == "unknown-scenario":
        proposal["scenario_class"] = "unapproved_profile"
        proposal["proposal_digest"] = legacy._occurrence_proposal_v2_digest(proposal)
        refresh = True
    elif mutation == "contradictory-waits":
        proposal["elapsed_time"]["serial_sum_known_wait_hours"] = 0
        proposal["proposal_digest"] = legacy._occurrence_proposal_v2_digest(proposal)
        refresh = True
    elif mutation == "negative-wait-count":
        proposal["elapsed_time"]["unquantified_wait_dependency_count"] = -1
        proposal["proposal_digest"] = legacy._occurrence_proposal_v2_digest(proposal)
        refresh = True
    elif mutation == "missing-selected-ticket":
        selected.pop()
    elif mutation == "reordered-selected-tickets":
        selected.reverse()
    elif mutation == "missing-selected-occurrence":
        selected[0]["execution_estimates"].pop()
    elif mutation == "reordered-selected-occurrences":
        selected[0]["execution_estimates"].reverse()
    elif mutation == "boolean-hours":
        estimate["p50_effort_hours"] = True
    elif mutation == "floating-hours":
        estimate["p50_effort_hours"] = 5.0
    elif mutation == "negative-hours":
        estimate["p50_effort_hours"] = -1
    elif mutation == "inverted-quantiles":
        estimate["p90_effort_hours"] = estimate["p50_effort_hours"] - 1
    elif mutation == "overflowing-hours":
        estimate["p90_effort_hours"] = 2**53
    elif mutation == "empty-rationale":
        estimate["rationale"] = ""
    else:
        estimate["actual_hours"] = 1
    if refresh:
        _refresh(ledger)
    with pytest.raises(core.SuccessorError):
        _build(ledger, selected, source)


@pytest.mark.parametrize(
    "times",
    [
        {"now": VALID_UNTIL},
        {"now": ISSUED - timedelta(microseconds=1)},
        {"now": datetime(2026, 11, 7, 12)},
        {"valid_until_utc": _stamp(ISSUED)},
        {"valid_until_utc": _stamp(ISSUED - timedelta(seconds=1))},
        {"valid_until_utc": _stamp(ISSUED + timedelta(days=30, seconds=1))},
        {"issued_at_utc": _stamp(ISSUED - timedelta(hours=1))},
    ],
)
def test_forecast_freshness_is_half_open_bounded_and_follows_inventory(
    times: dict[str, Any],
) -> None:
    ledger, selected, source = _fixture()
    with pytest.raises(core.SuccessorError):
        _build(ledger, selected, source, **times)


def _v4_fixture() -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    ledger, selected, source = _fixture()
    for index, row in enumerate(selected):
        row.update(
            confidence="medium" if index == 0 else "low",
            dependency_assumptions=[f"Synthetic dependency receipt for {row['ticket_id']}"],
            risk_assumptions=["Synthetic capacity and file scopes remain explicitly unresolved"],
            current_status="in_progress" if index == 0 else "blocked",
            trusted_issue_time=_stamp(ISSUED - timedelta(minutes=index)),
        )
    return ledger, selected, source


def _build_v4(
    ledger: dict[str, Any], selected: list[dict[str, Any]], source: dict[str, Any], **times: Any
) -> dict[str, Any]:
    return forecast.build_projection_v4(
        authoring_ledger=ledger,
        human_estimates=selected,
        source=source,
        issued_at_utc=times.get("issued_at_utc", _stamp(ISSUED)),
        valid_until_utc=times.get("valid_until_utc", _stamp(VALID_UNTIL)),
        now=times.get("now", NOW),
    )


def _validate(
    record: dict[str, Any],
    ledger: dict[str, Any],
    selected: list[dict[str, Any]],
    source: dict[str, Any],
    *,
    now: datetime = NOW,
) -> dict[str, Any]:
    return forecast.validate_projection(
        record, authoring_ledger=ledger, human_estimates=selected, source=source, now=now
    )


def _rehash_v4(record: dict[str, Any]) -> None:
    record["record_digest"] = (
        "sha256:"
        + hashlib.sha256(
            b"agent-assure:delivery-forecast/v4\x00"
            + rfc8785.dumps({key: value for key, value in record.items() if key != "record_digest"})
        ).hexdigest()
    )


def test_v4_rows_express_complete_roadmap_contract_and_preserve_exact_arithmetic() -> None:
    ledger, selected, source = _v4_fixture()
    before = copy.deepcopy((ledger, selected, source))
    record = _build_v4(ledger, selected, source)
    assert (ledger, selected, source) == before
    assert record["format"] == "agent-assure-delivery-forecast/4"
    assert record["authorization_effect"] == "none"
    required = {
        "ticket_id",
        "estimate_scope",
        "planned_execution_count",
        "execution_estimates",
        "aggregate_p50_effort_hours",
        "aggregate_p90_effort_hours",
        "aggregate_reviewer_effort_hours",
        "aggregate_method_id",
        "aggregate_method_definition_digest",
        "aggregate_dependence_assumptions",
        "confidence",
        "dependency_assumptions",
        "risk_assumptions",
        "current_status",
        "trusted_issue_time",
    }
    for row, adopted in zip(record["rows"], selected, strict=True):
        assert required <= row.keys()
        for key in (
            "confidence",
            "dependency_assumptions",
            "risk_assumptions",
            "current_status",
            "trusted_issue_time",
        ):
            assert row[key] == adopted[key]
        executions = adopted["execution_estimates"]
        assert row["aggregate_p50_effort_hours"] == sum(
            item["p50_effort_hours"] for item in executions
        )
        assert row["aggregate_p90_effort_hours"] == sum(
            item["p90_effort_hours"] for item in executions
        )
        assert row["aggregate_reviewer_effort_hours"] == sum(
            item["reviewer_p50_effort_hours"] for item in executions
        )
        assert row["aggregate_method_id"] == "comonotonic-quantile-sum/v1"
        assert (
            row["aggregate_method_definition_digest"]
            == record["aggregation_method"]["definition_digest"]
        )
        assert row["aggregate_dependence_assumptions"] == [
            "full_positive_rank_dependence_no_diversification_credit",
            "reported_quantile_sums_are_exact_only_under_the_bound_comonotonic_construction",
        ]
        for occurrence, chosen in zip(row["execution_estimates"], executions, strict=True):
            assert occurrence["p50_effort_hours"] == chosen["p50_effort_hours"]
            assert occurrence["p90_effort_hours"] == chosen["p90_effort_hours"]
            assert occurrence["reviewer_effort_hours"] == chosen["reviewer_p50_effort_hours"]
    legacy_selection = [
        {
            key: value
            for key, value in row.items()
            if key in {"ticket_id", "estimate_scope", "execution_estimates"}
        }
        for row in selected
    ]
    historical = _build(ledger, legacy_selection, source)
    assert record["portfolio_aggregate"] == historical["portfolio_aggregate"]
    assert record["portfolio_scenarios"] == historical["portfolio_scenarios"]
    assert record["portfolio_aggregate"]["combined_p90_effort_hours"] is None
    assert historical["format"] == "agent-assure-delivery-forecast/3"
    assert record["record_digest"] != historical["record_digest"]
    assert record["human_estimates_digest"] != historical["human_estimates_digest"]
    expected = copy.deepcopy(record)
    _rehash_v4(expected)
    assert expected == record
    assert _validate(record, ledger, selected, source) == record
    assert _validate(historical, ledger, legacy_selection, source) == historical


def test_v4_closed_schema_and_replay_reject_omissions_overclaims_and_rehashed_tampering() -> None:
    schema = json.loads((ROOT / forecast.V4_SCHEMA_PATH).read_bytes())
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    ledger, selected, source = _v4_fixture()
    record = _build_v4(ledger, selected, source)
    validator.validate(record)
    for field in (
        "confidence",
        "dependency_assumptions",
        "risk_assumptions",
        "current_status",
        "trusted_issue_time",
    ):
        changed = copy.deepcopy(record)
        changed["rows"][0].pop(field)
        _rehash_v4(changed)
        with pytest.raises(ValidationError):
            validator.validate(changed)
        with pytest.raises(core.SuccessorError):
            _validate(changed, ledger, selected, source)
    # Each value here satisfies the schema. A fresh attacker-computed digest
    # cannot replace the independently supplied human selections or arithmetic.
    mutations = [
        ("confidence", "high"),
        ("risk_assumptions", ["Unreviewed substitution"]),
        ("dependency_assumptions", ["Unreviewed dependency replacement"]),
        ("current_status", "done"),
        ("aggregate_p50_effort_hours", 0),
        ("trusted_issue_time", _stamp(ISSUED - timedelta(minutes=2))),
    ]
    for key, value in mutations:
        changed = copy.deepcopy(record)
        changed["rows"][0][key] = value
        _rehash_v4(changed)
        validator.validate(changed)
        with pytest.raises(core.SuccessorError, match="complete reconstruction"):
            _validate(changed, ledger, selected, source)
    changed = copy.deepcopy(record)
    changed["rows"][0]["execution_estimates"][0]["p50_effort_hours"] += 1
    _rehash_v4(changed)
    validator.validate(changed)
    with pytest.raises(core.SuccessorError):
        _validate(changed, ledger, selected, source)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("confidence", None),
        ("confidence", "certain"),
        ("confidence", True),
        ("dependency_assumptions", []),
        ("dependency_assumptions", ["same", "same"]),
        ("dependency_assumptions", [" "]),
        ("risk_assumptions", "not an array"),
        ("risk_assumptions", [""]),
        ("risk_assumptions", ["x" * 4097]),
        ("current_status", "accepted_for_development"),
        ("current_status", False),
        ("trusted_issue_time", None),
        ("trusted_issue_time", "2026-11-07T12:00:00+00:00"),
        ("trusted_issue_time", "2026-11-07T12:00:00.000001Z"),
        ("trusted_issue_time", "2026-11-07T11:54:59Z"),
    ],
)
def test_v4_never_invents_or_accepts_invalid_human_row_metadata(field: str, value: Any) -> None:
    ledger, selected, source = _v4_fixture()
    selected[0][field] = value
    with pytest.raises(core.SuccessorError):
        _build_v4(ledger, selected, source)


def test_v4_requires_each_metadata_field_and_version_changes_are_not_implicit() -> None:
    for field in (
        "confidence",
        "dependency_assumptions",
        "risk_assumptions",
        "current_status",
        "trusted_issue_time",
    ):
        ledger, selected, source = _v4_fixture()
        selected[0].pop(field)
        with pytest.raises(core.SuccessorError, match="unexpected or missing fields"):
            _build_v4(ledger, selected, source)
    with pytest.raises(core.SuccessorError):
        _build_v4(*_fixture())
    ledger, selected, source = _v4_fixture()
    with pytest.raises(core.SuccessorError):
        _build(ledger, selected, source)
    record = _build_v4(ledger, selected, source)
    record["format"] = "agent-assure-delivery-forecast/5"
    with pytest.raises(core.SuccessorError, match="unsupported"):
        _validate(record, ledger, selected, source)


@pytest.mark.parametrize("value", [True, 1.0])
def test_replay_does_not_alias_booleans_or_integral_floats_with_exact_integers(value: Any) -> None:
    for version in (3, 4):
        ledger, selected, source = _v4_fixture() if version == 4 else _fixture()
        record = (
            _build_v4(ledger, selected, source)
            if version == 4
            else _build(ledger, selected, source)
        )
        record["portfolio_scenarios"][1]["ticket_count"] = value
        domain = f"agent-assure:delivery-forecast/v{version}".encode() + b"\x00"
        record["record_digest"] = (
            "sha256:"
            + hashlib.sha256(
                domain
                + rfc8785.dumps(
                    {key: item for key, item in record.items() if key != "record_digest"}
                )
            ).hexdigest()
        )
        with pytest.raises(core.SuccessorError, match="JSON types"):
            _validate(record, ledger, selected, source)


def test_v4_expiry_cannot_be_refreshed_by_rehashing_or_metadata_review() -> None:
    ledger, selected, source = _v4_fixture()
    record = _build_v4(ledger, selected, source)
    with pytest.raises(core.SuccessorError, match="future, stale, or excessive"):
        _validate(record, ledger, selected, source, now=VALID_UNTIL)
    # Selection changes yield another signed subject, not a silent refresh of
    # the original record or an assertion that the new subject was accepted.
    changed = copy.deepcopy(selected)
    changed[0]["confidence"] = "high"
    revised = _build_v4(ledger, changed, source)
    assert revised["record_digest"] != record["record_digest"]
    assert revised["issued_at_utc"] == record["issued_at_utc"]
    assert revised["valid_until_utc"] == record["valid_until_utc"]
    assert revised["projection_status"] == "prepared_non_authorizing"
