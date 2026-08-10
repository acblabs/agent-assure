from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import cast

from agent_assure.authoring.yaml_nodes import MAX_YAML_BYTES, load_yaml_nodes_text
from agent_assure.io_limits import read_file_bounded
from agent_assure.schema.campaign import (
    AssuranceMutationCampaign,
    AssuranceMutationCatalog,
)
from agent_assure.schema.efficacy import (
    INDEPENDENCE_CLASS_ORDER,
    INDEPENDENT_CHALLENGE_CLASSES,
    MAX_EFFICACY_LIMITATIONS,
    ControlEfficacyGateDecision,
    ControlEfficacyGateProfile,
    ControlEfficacyReport,
    EfficacyStratum,
    ExactRate,
    OperatorEfficacyOutcome,
    ThreatApplicability,
    ThreatApplicabilityItem,
    ThreatApplicabilityManifest,
    ThreatCoverageItem,
    control_efficacy_semantic_state,
    derive_control_efficacy_gate_decision,
    mutation_state_counts,
    threat_scope_semantic_state,
)
from agent_assure.schema.mutation import (
    EvidenceEvaluationBasis,
    IndependenceClass,
    MutationResultState,
)

DEFAULT_EFFICACY_LIMITATIONS = (
    "Mutation efficacy is bounded to the declared catalog, subject, evaluator, and manifest.",
    "Kill rates are detector-test ratios, not safety, compliance, or certification scores.",
    "Threat mappings are planning evidence and do not establish conformance.",
)
ThreatManifestReader = Callable[[Path], bytes]
_THREAT_MANIFEST_AUTHORING_FIELDS = frozenset(
    {"threat_source", "present_control_ids", "items", "limitations"}
)
_THREAT_MANIFEST_PERSISTED_FIELDS = frozenset(ThreatApplicabilityManifest.model_fields)


def load_threat_applicability_manifest(
    path: Path,
    *,
    reader: ThreatManifestReader | None = None,
) -> ThreatApplicabilityManifest:
    """Load either the minimal authored YAML form or a persisted manifest.

    The authored form deliberately omits persisted identity and self-digest
    fields; those are constructed deterministically. A document must match one
    complete form exactly, so mixed or extension-bearing input fails closed.
    """
    label = "threat applicability manifest"
    data = (
        reader(path)
        if reader is not None
        else read_file_bounded(
            path,
            max_bytes=MAX_YAML_BYTES,
            label=label,
        ).data
    )
    loaded = load_yaml_nodes_text(data.decode("utf-8"), label=label)
    if not isinstance(loaded.data, Mapping):
        raise ValueError("threat applicability manifest root must be a mapping")
    payload = dict(cast(Mapping[str, object], loaded.data))
    fields = frozenset(payload)
    if fields == _THREAT_MANIFEST_AUTHORING_FIELDS:
        return ThreatApplicabilityManifest.build(**payload)
    if fields == _THREAT_MANIFEST_PERSISTED_FIELDS:
        return ThreatApplicabilityManifest.model_validate(payload)
    raise ValueError(
        "threat applicability manifest must be exactly the authored or persisted v1 form"
    )


def build_control_efficacy_report(
    campaign: AssuranceMutationCampaign,
    catalog: AssuranceMutationCatalog,
    threat_manifest: ThreatApplicabilityManifest,
    *,
    required_operator_ids: tuple[str, ...],
    limitations: tuple[str, ...] = (),
) -> ControlEfficacyReport:
    """Build a deterministic, self-validating efficacy projection.

    A kill-rate denominator contains only completed verdict-bearing outcomes
    (``caught`` and ``survived``). Invalid, error, and inapplicable outcomes
    remain first-class counts and cannot be hidden inside that denominator.
    """
    _validate_catalog_campaign_binding(catalog, campaign)
    required = _validate_required_operator_ids(required_operator_ids, catalog)
    manifest_by_id = {item.threat_id: item for item in threat_manifest.items}

    catalog_by_id = {item.descriptor.operator_id: item for item in catalog.operators}
    present_controls = set(threat_manifest.present_control_ids)
    outcomes: list[OperatorEfficacyOutcome] = []
    required_set = set(required)
    for campaign_entry in campaign.operator_results:
        catalog_entry = catalog_by_id[campaign_entry.operator_id]
        threat_ids = tuple(
            threat_id
            for threat_id in catalog_entry.threat_source_references
            if threat_id in manifest_by_id
        )
        unscoped_catalog_threat_ids = tuple(
            threat_id
            for threat_id in catalog_entry.threat_source_references
            if threat_id not in manifest_by_id
        )
        critical_threat_ids = tuple(
            threat_id
            for threat_id in threat_ids
            if manifest_by_id[threat_id].applicability is ThreatApplicability.applicable
            and manifest_by_id[threat_id].critical
        )
        target_control_ids = catalog_entry.descriptor.expected_detection_contract.target_control_ids
        outcomes.append(
            OperatorEfficacyOutcome(
                operator_id=campaign_entry.operator_id,
                invariant_family=campaign_entry.invariant_family,
                independence_class=campaign_entry.result.independence_class,
                applicability=campaign_entry.applicability,
                state=campaign_entry.result.state,
                required=campaign_entry.operator_id in required_set,
                catalog_threat_ids=catalog_entry.threat_source_references,
                threat_ids=threat_ids,
                unscoped_catalog_threat_ids=unscoped_catalog_threat_ids,
                critical_threat_ids=critical_threat_ids,
                target_control_ids=target_control_ids,
                present_target_control_ids=tuple(
                    control_id
                    for control_id in target_control_ids
                    if control_id in present_controls
                ),
            )
        )
    outcome_tuple = tuple(outcomes)
    counts = mutation_state_counts(outcome_tuple)

    invariant_families = tuple(sorted({item.invariant_family for item in catalog.operators}))
    outcomes_by_family: dict[str, list[OperatorEfficacyOutcome]] = {
        family: [] for family in invariant_families
    }
    for outcome in outcome_tuple:
        outcomes_by_family[outcome.invariant_family].append(outcome)
    family_strata = tuple(
        _stratum(
            family,
            outcomes_by_family[family],
        )
        for family in invariant_families
    )
    outcomes_by_independence: dict[IndependenceClass, list[OperatorEfficacyOutcome]] = {
        independence_class: [] for independence_class in INDEPENDENCE_CLASS_ORDER
    }
    for outcome in outcome_tuple:
        outcomes_by_independence[outcome.independence_class].append(outcome)
    independence_strata = tuple(
        _stratum(
            independence_class.value,
            outcomes_by_independence[independence_class],
            independent_challenge_eligible=(independence_class in INDEPENDENT_CHALLENGE_CLASSES),
        )
        for independence_class in INDEPENDENCE_CLASS_ORDER
    )

    threat_coverage = _threat_coverage_projection(threat_manifest.items, outcome_tuple)
    applicable_threats = tuple(
        item for item in threat_coverage if item.applicability is ThreatApplicability.applicable
    )
    challenged_threats = tuple(item for item in applicable_threats if item.challenged)
    independently_challenged_threats = tuple(
        item for item in applicable_threats if item.independently_challenged
    )
    critical_uncovered_ids = tuple(
        item.threat_id for item in applicable_threats if item.critical and not item.challenged
    )
    unknown_ids = tuple(
        item.threat_id
        for item in threat_coverage
        if item.applicability is ThreatApplicability.unknown
    )
    unscoped_catalog_threat_ids = tuple(
        sorted(
            {
                threat_id
                for outcome in outcome_tuple
                for threat_id in outcome.unscoped_catalog_threat_ids
            }
        )
    )

    required_survivor_ids = tuple(
        item.operator_id
        for item in outcome_tuple
        if item.required and item.state is MutationResultState.survived
    )
    critical_survivor_ids = tuple(
        item.operator_id
        for item in outcome_tuple
        if item.critical_threat_ids and item.state is MutationResultState.survived
    )
    outcome_by_id = {item.operator_id: item for item in outcome_tuple}
    required_not_evaluated_ids = tuple(
        operator_id
        for operator_id in required
        if operator_id not in outcome_by_id
        or outcome_by_id[operator_id].state
        not in {MutationResultState.caught, MutationResultState.survived}
    )
    invalid_or_error_states = {
        MutationResultState.invalid_operator,
        MutationResultState.invalid_subject,
        MutationResultState.execution_error,
    }
    invalid_or_error_ids = tuple(
        item.operator_id for item in outcome_tuple if item.state in invalid_or_error_states
    )

    report_limitations = (*DEFAULT_EFFICACY_LIMITATIONS, *limitations)
    if len(report_limitations) > MAX_EFFICACY_LIMITATIONS:
        raise ValueError("control-efficacy report has too many limitations")
    if len(set(report_limitations)) != len(report_limitations):
        raise ValueError("control-efficacy report limitations must be unique")

    return ControlEfficacyReport.build(
        campaign_digest=campaign.campaign_digest,
        source_digest=campaign.source_digest,
        suite_digest=campaign.suite_digest,
        catalog_id=catalog.catalog_id,
        catalog_digest=catalog.catalog_digest,
        threat_manifest_digest=threat_manifest.manifest_digest,
        semantic_state=control_efficacy_semantic_state(
            counts,
            pending_count=len(campaign.pending_operator_order),
        ),
        threat_scope_state=threat_scope_semantic_state(
            applicable_count=len(applicable_threats),
            challenged_count=len(challenged_threats),
            critical_uncovered_count=len(critical_uncovered_ids),
            unknown_count=len(unknown_ids),
            unscoped_catalog_threat_count=len(unscoped_catalog_threat_ids),
        ),
        canonical_operator_ids=campaign.canonical_operator_order,
        canonical_invariant_families=invariant_families,
        selected_operator_ids=campaign.selected_operator_order,
        pending_operator_ids=campaign.pending_operator_order,
        required_operator_ids=required,
        operator_outcomes=outcome_tuple,
        state_counts=counts,
        applicable_operator_count=counts.applicable,
        caught_operator_count=counts.caught,
        survived_operator_count=counts.survived,
        inapplicable_operator_count=counts.inapplicable,
        invalid_operator_count=counts.invalid_operator,
        invalid_subject_count=counts.invalid_subject,
        execution_error_count=counts.execution_error,
        catalog_kill_rate=ExactRate.from_counts(counts.caught, counts.applicable),
        required_survivor_count=len(required_survivor_ids),
        critical_survivor_count=len(critical_survivor_ids),
        required_survivor_operator_ids=required_survivor_ids,
        critical_survivor_operator_ids=critical_survivor_ids,
        required_not_evaluated_operator_ids=required_not_evaluated_ids,
        invalid_or_error_operator_ids=invalid_or_error_ids,
        kill_rate_by_invariant_family=family_strata,
        kill_rate_by_independence_class=independence_strata,
        threat_coverage=threat_coverage,
        applicable_threat_category_count=len(applicable_threats),
        challenged_threat_category_count=len(challenged_threats),
        independently_challenged_threat_category_count=len(independently_challenged_threats),
        critical_uncovered_threat_count=len(critical_uncovered_ids),
        unknown_applicability_count=len(unknown_ids),
        critical_uncovered_threat_ids=critical_uncovered_ids,
        unknown_applicability_threat_ids=unknown_ids,
        unscoped_catalog_threat_count=len(unscoped_catalog_threat_ids),
        unscoped_catalog_threat_ids=unscoped_catalog_threat_ids,
        threat_challenge_rate=ExactRate.from_counts(
            len(challenged_threats),
            len(applicable_threats),
        ),
        independent_threat_challenge_rate=ExactRate.from_counts(
            len(independently_challenged_threats),
            len(applicable_threats),
        ),
        limitations=report_limitations,
    )


def evaluate_control_efficacy_gate(
    report: ControlEfficacyReport,
    profile: ControlEfficacyGateProfile,
) -> ControlEfficacyGateDecision:
    """Map semantic evidence to policy effects without changing report state."""
    return derive_control_efficacy_gate_decision(report, profile)


def _stratum(
    name: str,
    outcomes: Iterable[OperatorEfficacyOutcome],
    *,
    independent_challenge_eligible: bool | None = None,
) -> EfficacyStratum:
    outcome_tuple = tuple(outcomes)
    counts = mutation_state_counts(outcome_tuple)
    return EfficacyStratum(
        stratum=name,
        independent_challenge_eligible=independent_challenge_eligible,
        state_counts=counts,
        kill_rate=ExactRate.from_counts(counts.caught, counts.applicable),
    )


def _threat_coverage_projection(
    manifest_items: tuple[ThreatApplicabilityItem, ...],
    outcomes: tuple[OperatorEfficacyOutcome, ...],
) -> tuple[ThreatCoverageItem, ...]:
    """Build the manifest projection in O(items + declared operator references)."""
    manifest_by_id = {item.threat_id: item for item in manifest_items}
    challengers_by_threat: dict[str, list[str]] = {threat_id: [] for threat_id in manifest_by_id}
    independent_challengers_by_threat: dict[str, list[str]] = {
        threat_id: [] for threat_id in manifest_by_id
    }
    for outcome in outcomes:
        if not outcome.present_target_control_ids or not outcome.completed_challenge:
            continue
        for threat_id in outcome.threat_ids:
            manifest_item = manifest_by_id[threat_id]
            if manifest_item.applicability is not ThreatApplicability.applicable:
                continue
            challengers_by_threat[threat_id].append(outcome.operator_id)
            if outcome.independent_challenge_eligible:
                independent_challengers_by_threat[threat_id].append(outcome.operator_id)

    return tuple(
        ThreatCoverageItem(
            threat_id=manifest_item.threat_id,
            applicability=manifest_item.applicability,
            critical=manifest_item.critical,
            challenging_operator_ids=tuple(
                sorted(set(challengers_by_threat[manifest_item.threat_id]))
            ),
            independent_challenging_operator_ids=tuple(
                sorted(set(independent_challengers_by_threat[manifest_item.threat_id]))
            ),
        )
        for manifest_item in manifest_items
    )


def _validate_required_operator_ids(
    required_operator_ids: tuple[str, ...],
    catalog: AssuranceMutationCatalog,
) -> tuple[str, ...]:
    if len(required_operator_ids) != len(set(required_operator_ids)):
        raise ValueError("required operator IDs must be unique")
    catalog_order = tuple(item.descriptor.operator_id for item in catalog.operators)
    required_set = set(required_operator_ids)
    unknown = tuple(sorted(required_set - set(catalog_order)))
    if unknown:
        raise ValueError("required operator IDs are outside the catalog: " + ", ".join(unknown))
    return tuple(operator_id for operator_id in catalog_order if operator_id in required_set)


def _validate_catalog_campaign_binding(
    catalog: AssuranceMutationCatalog,
    campaign: AssuranceMutationCampaign,
) -> None:
    if (
        campaign.catalog_id != catalog.catalog_id
        or campaign.catalog_digest != catalog.catalog_digest
    ):
        raise ValueError("mutation campaign is not bound to the supplied catalog")
    catalog_order = tuple(item.descriptor.operator_id for item in catalog.operators)
    if campaign.canonical_operator_order != catalog_order:
        raise ValueError("mutation campaign operator order does not match the catalog")
    catalog_by_id = {item.descriptor.operator_id: item for item in catalog.operators}
    for campaign_entry in campaign.operator_results:
        catalog_entry = catalog_by_id.get(campaign_entry.operator_id)
        if catalog_entry is None:
            raise ValueError("mutation campaign references an operator outside the catalog")
        descriptor = catalog_entry.descriptor
        result = campaign_entry.result
        if (
            result.state in {MutationResultState.caught, MutationResultState.survived}
            and result.evaluator_evaluation_basis is not EvidenceEvaluationBasis.deterministic
        ):
            raise ValueError(
                "control efficacy requires deterministic verdict-bearing mutation results; "
                f"operator {campaign_entry.operator_id!r} uses "
                f"{result.evaluator_evaluation_basis.value!r}"
            )
        if campaign_entry.invariant_family != catalog_entry.invariant_family:
            raise ValueError("campaign invariant family does not match catalog metadata")
        if campaign_entry.expected_detection_contract != descriptor.expected_detection_contract:
            raise ValueError("campaign expected detector does not match catalog metadata")
        if (
            result.operator_version != descriptor.operator_version
            or result.operator_digest != descriptor.operator_digest
            or result.implementation_digest != descriptor.implementation_digest
            or result.provenance != descriptor.provenance
            or result.independence_class is not descriptor.independence_class
        ):
            raise ValueError("campaign result identity does not match its catalog operator")
