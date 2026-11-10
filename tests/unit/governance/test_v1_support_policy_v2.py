"""Support proposals cannot weaken the already effective security intake.

These checks independently bind the public policy and exercise the proposed
wire contract's refusal of weaker clocks, objectives, coverage and authority.
They do not assert that operational staffing or policy adoption has occurred.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any, cast

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parents[3]
DIRECTORY = ROOT / "docs/governance/v1/sprint2"
SECURITY_DIGEST = "sha256:a3224d87ef2aadccf79c06095e03080ad0287189af90e6be6d4c98d6d492ee3b"
INTAKE_ID = "agent-assure/security-vulnerability-intake/v1"


def _record(name: str) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads((DIRECTORY / name).read_text(encoding="utf-8")))


@pytest.fixture
def policy() -> dict[str, Any]:
    return _record("support-policy-v2.json")


@pytest.fixture
def validator() -> jsonschema.Draft202012Validator:
    schema = _record("support-policy-v2.schema.json")
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


def test_schema_accepts_the_pending_proposal_without_inventing_adoption(
    policy: dict[str, Any], validator: jsonschema.Draft202012Validator
) -> None:
    validator.validate(policy)
    assert policy["status"] == "pending_human_operational_acceptance"
    assert policy["operational_owner_person_id"] is None
    assert policy["targets_are_operational_commitments"] is False
    assert policy["existing_security_intake_objectives_remain_in_force"] is True
    assert policy["activation_rule"] == "verified_detached_operational_acceptance_only"
    acceptance = policy["operational_acceptance_required"]
    assert acceptance["issuer_role"] == "release_policy_owner"
    assert acceptance["competence_scope"] == "operational_support:0.7.x"
    assert acceptance["explicit_capacity_and_backup_required"] is True


def test_security_source_is_exactly_bound_and_never_replaced(policy: dict[str, Any]) -> None:
    source = (ROOT / "SECURITY.md").read_bytes()
    binding = policy["security_intake_precedence"]
    assert "sha256:" + hashlib.sha256(source).hexdigest() == SECURITY_DIGEST
    assert binding["source_path"] == "SECURITY.md"
    assert binding["source_sha256"] == SECURITY_DIGEST
    assert binding["policy_id"] == INTAKE_ID
    assert INTAKE_ID.encode("ascii") in source
    assert binding["replacement_authorized"] is False
    assert binding["source_change_requires_fresh_subject_review"] is True


def test_effective_acknowledgments_use_the_stricter_existing_objectives(
    policy: dict[str, Any],
) -> None:
    targets = policy["response_targets"]
    # Independent public-policy requirements, not expected values from the schema.
    existing_acknowledgments = {"critical": 1, "high": 4}
    existing_containment = {"critical": 4, "high": 24}
    proposed_coordination = {"critical": 24, "high": 72}
    for severity in ("critical", "high"):
        coordination = targets[f"maintenance_coordination_{severity}_acknowledgment_hours"]
        assert coordination == proposed_coordination[severity]
        effective = targets[f"{severity}_acknowledgment_hours"]
        assert effective == min(existing_acknowledgments[severity], coordination)
        assert (
            targets[f"{severity}_containment_or_safe_state_hours"]
            <= (existing_containment[severity])
        )
    assert targets["critical_initial_assessment_hours"] <= 4
    assert targets["high_initial_assessment_hours"] <= 24
    assert targets["critical_remediation_days"] == 7
    assert targets["high_remediation_days"] == 30
    assert targets["containment_is_release_completion"] is False
    assert targets["containment_satisfies_remediation_target"] is False
    assert targets["incident_can_waive_release_controls"] is False


def test_intake_clock_precedes_actionability_and_cannot_be_reset(policy: dict[str, Any]) -> None:
    intake = policy["security_intake_precedence"]
    assert intake["clock_start"] == (
        "earlier_of_report_received_at_utc_and_internally_detected_at_utc"
    )
    assert intake["clock_is_continuous_24_7"] is True
    assert intake["forwarding_validation_actionability_or_reclassification_resets_clock"] is False
    assert intake["uncertain_credible_critical_signal"] == (
        "apply_critical_objectives_until_named_owner_records_lower_severity_evidence"
    )
    assert policy["response_targets"]["deadline_reset_on_reclassification"] is False
    assert policy["response_targets"]["clock_basis"] == (
        "elapsed_UTC_from_earlier_report_receipt_or_internal_detection_"
        "never_actionability_validation_or_reclassification"
    )


def test_primary_failure_has_a_distinct_person_and_durable_fallback(policy: dict[str, Any]) -> None:
    escalation = policy["security_escalation"]
    assert escalation["coverage"] == "continuous_24_7_primary_and_independent_fallback_on_call"
    assert escalation["critical_primary_page"] == "immediate"
    assert escalation["critical_delivery_confirmation_minutes"] <= 5
    assert escalation["primary_unavailable_or_delivery_failure"] == (
        "activate_independent_fallback_immediately"
    )
    assert escalation["critical_no_human_acknowledgment_fallback_minutes"] <= 15
    assert escalation["fallback_requires_distinct_person"] is True
    assert escalation["fallback_requires_distinct_durable_route"] is True
    assert (
        escalation[
            "fallback_can_depend_solely_on_same_github_account_identity_provider_or_notification_path"
        ]
        is False
    )
    assert escalation["temporary_risk_acceptance_can_authorize_release_or_publication"] is False


def test_private_roster_role_refs_preserve_separation_without_public_person_names(
    policy: dict[str, Any],
) -> None:
    assert policy["organization_id"] == "acblabs"
    acceptance = policy["operational_acceptance_required"]
    assert acceptance["identity_disclosure"] == (
        "organizational_role_refs_with_access_controlled_roster"
    )
    assert acceptance["signed_private_roster_reference_and_revision_required"] is True
    assert acceptance["verifier_checks_signed_owner_role_separation_attestation"] is True
    assert acceptance["public_individual_names_or_destinations_required"] is False
    assert acceptance["private_roster_content_hash_required"] is False
    assert acceptance["private_roster_revision_retained_and_auditable"] is True
    assert acceptance["private_roster_assurance_level"] == (
        "owner_attested_not_independently_verified"
    )
    assert acceptance["private_roster_revision_rule"] == (
        "immutable_owner_supplied_revision_not_mutable_alias_or_placeholder"
    )
    escalation = policy["security_escalation"]
    assert escalation["organization_label_is_staffing_evidence"] is False
    assert escalation["distinct_people_attested_in_private_roster_required"] is True
    assert escalation["fallback_requires_distinct_person"] is True
    assert escalation["fallback_requires_distinct_durable_route"] is True
    # The proposed policy requires these assurances without inventing actual
    # people, role assignments, private roster identifiers or revision values.
    assert "private_roster_ref" not in policy
    assert "private_roster_revision" not in policy
    assert policy["operational_owner_person_id"] is None


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("response_targets", "critical_acknowledgment_hours"), 24),
        (("response_targets", "high_acknowledgment_hours"), 72),
        (("response_targets", "critical_containment_or_safe_state_hours"), 24),
        (("response_targets", "high_containment_or_safe_state_hours"), 48),
        (("response_targets", "clock_basis"), "from_first_actionable_or_validated_report"),
        (("response_targets", "deadline_reset_on_reclassification"), True),
        (("response_targets", "containment_satisfies_remediation_target"), True),
        (("security_intake_precedence", "clock_start"), "from_first_confirmed_report"),
        (("security_intake_precedence", "clock_is_continuous_24_7"), False),
        (("security_intake_precedence", "replacement_authorized"), True),
        (("security_intake_precedence", "source_sha256"), "sha256:" + "0" * 64),
        (("security_escalation", "critical_delivery_confirmation_minutes"), 30),
        (("security_escalation", "critical_no_human_acknowledgment_fallback_minutes"), 60),
        (("security_escalation", "fallback_requires_distinct_person"), False),
        (("security_escalation", "fallback_requires_distinct_durable_route"), False),
        (("security_escalation", "coverage"), "business_hours_only"),
        (("security_escalation", "organization_label_is_staffing_evidence"), True),
        (("security_escalation", "distinct_people_attested_in_private_roster_required"), False),
        (
            ("operational_acceptance_required", "public_individual_names_or_destinations_required"),
            True,
        ),
        (
            (
                "operational_acceptance_required",
                "signed_private_roster_reference_and_revision_required",
            ),
            False,
        ),
        (
            ("operational_acceptance_required", "private_roster_assurance_level"),
            "independently_verified",
        ),
        (
            ("operational_acceptance_required", "private_roster_revision_retained_and_auditable"),
            False,
        ),
        (("organization_id",), "unreviewed-organization"),
        (("operational_acceptance_required", "maximum_receipt_validity_days"), 31),
        (("operational_acceptance_required", "receipt_expiry_terminates_support"), True),
        (("operational_owner_person_id",), "unreviewed-owner"),
        (("targets_are_operational_commitments",), True),
        (("minimum_overlap_days",), 0),
        (("silent_support_gap_allowed",), True),
    ],
)
def test_closed_policy_rejects_weaker_intake_or_fabricated_adoption(
    path: tuple[str, ...],
    replacement: Any,
    policy: dict[str, Any],
    validator: jsonschema.Draft202012Validator,
) -> None:
    mutated = copy.deepcopy(policy)
    parent = mutated
    for component in path[:-1]:
        parent = parent[component]
    parent[path[-1]] = replacement
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(mutated)


@pytest.mark.parametrize("field", ["security_intake_precedence", "security_escalation"])
def test_security_source_and_escalation_cannot_be_omitted(
    field: str,
    policy: dict[str, Any],
    validator: jsonschema.Draft202012Validator,
) -> None:
    del policy[field]
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(policy)
