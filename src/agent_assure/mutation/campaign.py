from __future__ import annotations

from collections.abc import Iterable, Mapping
from copy import deepcopy
from dataclasses import dataclass
from datetime import date

from agent_assure import __version__
from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.fixtures.loader import compiled_suite_digest
from agent_assure.mutation.catalog import RegisteredOperator, registered_operators
from agent_assure.mutation.execution import (
    MutationEvaluatorBinding,
    MutationExecution,
    execute_mutation,
    validated_runset_projection,
)
from agent_assure.policies.base import DEFAULT_GATE_PROFILE, GateProfile, Waiver
from agent_assure.privacy.redaction import assert_runset_payload_safe_for_persistence
from agent_assure.schema.campaign import (
    CORE_MUTATION_CATALOG_ID,
    CORE_MUTATION_CATALOG_ORDERING,
    CORE_MUTATION_OPERATOR_COUNT,
    CORE_MUTATION_OPERATOR_IDS,
    FAIL_FAST_MUTATION_STATES,
    AssuranceMutationCampaign,
    AssuranceMutationCatalog,
    MutationCampaignCompletion,
    MutationCampaignMode,
    MutationCampaignOperatorResult,
    MutationCatalogOperator,
    mutation_result_applicability,
)
from agent_assure.schema.mutation import (
    RFC8785_SAFE_INTEGER_MAX,
    MutationResultState,
    finding_target_digest,
)
from agent_assure.schema.suite import CompiledSuite

_CATALOG_LIMITATIONS = (
    "The finite mutation catalog does not represent every possible agent failure.",
    "Results are scoped to the exact source, suite, catalog, evaluator, gate profile, and seed.",
    "Catalog membership is not a statistical sample and carries no confidence interval.",
)
_CAMPAIGN_LIMITATIONS = (
    "Each operator ran independently against the same immutable source; "
    "mutations were not chained.",
    "A caught result supports only the operator's normative expected-detector contract.",
    "The finite campaign is not a safety score or a claim of universal control coverage.",
    "No statistical confidence interval applies to this finite deterministic catalog.",
)

_CAMPAIGN_SOURCE_ERROR_MESSAGE = (
    "mutation campaign source cannot establish a canonical JSON identity"
)
_CAMPAIGN_SOURCE_PROJECTION_ERROR_MESSAGE = (
    "mutation campaign source failed RunSet validation and projection"
)
_CAMPAIGN_SOURCE_PRIVACY_ERROR_MESSAGE = (
    "mutation campaign source failed the bound privacy-detector profile"
)
_CAMPAIGN_SOURCE_MUTATION_MESSAGE = "mutation campaign source changed during isolated execution"


class MutationCampaignSourceError(ValueError):
    """Raised when a campaign source fails its bounded preflight."""


@dataclass(frozen=True)
class MutationCampaignExecution:
    catalog: AssuranceMutationCatalog
    campaign: AssuranceMutationCampaign
    operator_executions: tuple[MutationExecution, ...]


def build_core_catalog(
    operators: Iterable[RegisteredOperator] | None = None,
) -> AssuranceMutationCatalog:
    """Build the canonical, self-digested closed core catalog."""
    resolved = tuple(operators) if operators is not None else registered_operators()
    canonical = tuple(sorted(resolved, key=lambda item: item.descriptor.operator_id))
    operator_ids = tuple(item.descriptor.operator_id for item in canonical)
    if not canonical:
        raise ValueError("the core mutation catalog cannot be empty")
    if len(set(operator_ids)) != len(operator_ids):
        raise ValueError("the core mutation catalog contains duplicate operator IDs")
    if len(canonical) != CORE_MUTATION_OPERATOR_COUNT or operator_ids != CORE_MUTATION_OPERATOR_IDS:
        raise ValueError("core/v1 must contain exactly the registered core operator IDs")
    if any(not item.stable for item in canonical):
        raise ValueError("the core mutation catalog contains a non-stable operator")
    return AssuranceMutationCatalog.build(
        catalog_id=CORE_MUTATION_CATALOG_ID,
        ordering_semantics=CORE_MUTATION_CATALOG_ORDERING,
        operators=tuple(
            MutationCatalogOperator(
                descriptor=item.descriptor,
                invariant_family=item.invariant_family,
                threat_source_references=item.threat_source_references,
                stable=True,
            )
            for item in canonical
        ),
        limitations=_CATALOG_LIMITATIONS,
    )


def execute_mutation_campaign(
    suite: CompiledSuite,
    source_payload: Mapping[str, object],
    *,
    seed: int,
    generated_at: str,
    mode: MutationCampaignMode = MutationCampaignMode.full_report,
    operator_ids: tuple[str, ...] = (),
    invariant_families: tuple[str, ...] = (),
    threat_ids: tuple[str, ...] = (),
    evaluator_binding: MutationEvaluatorBinding | None = None,
    gate_profile: GateProfile = DEFAULT_GATE_PROFILE,
    waivers: tuple[Waiver, ...] = (),
    evaluation_date: date | None = None,
    catalog_operators: Iterable[RegisteredOperator] | None = None,
) -> MutationCampaignExecution:
    """Execute a deterministic catalog selection without mutation composition."""
    if seed < 0 or seed > RFC8785_SAFE_INTEGER_MAX:
        raise ValueError(f"mutation seed must be between 0 and {RFC8785_SAFE_INTEGER_MAX}")
    if not isinstance(mode, MutationCampaignMode):
        mode = MutationCampaignMode(mode)

    source, source_digest = _prepare_campaign_source(source_payload)
    resolved_operators = (
        tuple(catalog_operators) if catalog_operators is not None else registered_operators()
    )
    catalog = build_core_catalog(resolved_operators)
    selected = _select_operators(
        resolved_operators,
        catalog,
        operator_ids=operator_ids,
        invariant_families=invariant_families,
        threat_ids=threat_ids,
    )

    executions: list[MutationExecution] = []
    entries: list[MutationCampaignOperatorResult] = []
    for registered in selected:
        execution = execute_mutation(
            suite,
            source,
            operator_id=registered.descriptor.operator_id,
            seed=seed,
            generated_at=generated_at,
            evaluator_binding=evaluator_binding,
            gate_profile=gate_profile,
            waivers=waivers,
            evaluation_date=evaluation_date,
        )
        _require_unchanged_campaign_source(source, expected_digest=source_digest)
        executions.append(execution)
        entries.append(_campaign_entry(registered, execution, seed=seed))
        if (
            mode is MutationCampaignMode.fail_fast
            and execution.result.state in FAIL_FAST_MUTATION_STATES
        ):
            break

    executed_ids = tuple(item.operator_id for item in entries)
    selected_ids = tuple(item.descriptor.operator_id for item in selected)
    pending_ids = selected_ids[len(executed_ids) :]
    completion = (
        MutationCampaignCompletion.stopped_early
        if pending_ids
        else MutationCampaignCompletion.complete
    )
    campaign = AssuranceMutationCampaign.build(
        source_digest=source_digest,
        suite_digest=compiled_suite_digest(suite),
        catalog_id=catalog.catalog_id,
        catalog_digest=catalog.catalog_digest,
        producer_version=__version__,
        mode=mode,
        completion=completion,
        campaign_seed=seed,
        canonical_operator_order=tuple(item.descriptor.operator_id for item in catalog.operators),
        selected_operator_order=selected_ids,
        executed_operator_order=executed_ids,
        pending_operator_order=pending_ids,
        operator_results=tuple(entries),
        limitations=_CAMPAIGN_LIMITATIONS,
    )
    return MutationCampaignExecution(
        catalog=catalog,
        campaign=campaign,
        operator_executions=tuple(executions),
    )


def _prepare_campaign_source(
    source_payload: Mapping[str, object],
) -> tuple[dict[str, object], str]:
    """Copy, project, privacy-check, and identify one campaign source."""
    try:
        copied_source = deepcopy(dict(source_payload))
        if not _is_strict_json_value(copied_source):
            raise TypeError("campaign source is not strict JSON data")
    except (RecursionError, TypeError, ValueError):
        raise MutationCampaignSourceError(_CAMPAIGN_SOURCE_ERROR_MESSAGE) from None

    try:
        _, projected_source = validated_runset_projection(copied_source)
    except (RecursionError, TypeError, ValueError):
        raise MutationCampaignSourceError(_CAMPAIGN_SOURCE_PROJECTION_ERROR_MESSAGE) from None

    try:
        assert_runset_payload_safe_for_persistence(copied_source)
        assert_runset_payload_safe_for_persistence(projected_source)
    except (RecursionError, TypeError, ValueError):
        raise MutationCampaignSourceError(_CAMPAIGN_SOURCE_PRIVACY_ERROR_MESSAGE) from None

    try:
        source_digest = sha256_hexdigest(projected_source)
    except (RecursionError, TypeError, ValueError):
        raise MutationCampaignSourceError(_CAMPAIGN_SOURCE_ERROR_MESSAGE) from None
    return projected_source, source_digest


def _require_unchanged_campaign_source(
    source: Mapping[str, object],
    *,
    expected_digest: str,
) -> None:
    """Fail closed if an isolated execution mutates the campaign-owned source."""
    try:
        if not _is_strict_json_value(source):
            raise TypeError("campaign source is no longer strict JSON data")
        current_digest = sha256_hexdigest(source)
    except (RecursionError, TypeError, ValueError):
        raise RuntimeError(_CAMPAIGN_SOURCE_MUTATION_MESSAGE) from None
    if current_digest != expected_digest:
        raise RuntimeError(_CAMPAIGN_SOURCE_MUTATION_MESSAGE)


def _is_strict_json_value(value: object) -> bool:
    """Return whether a value uses only exact, non-lossy JSON runtime types."""
    if value is None or type(value) in {bool, int, str}:
        return True
    if isinstance(value, list) and type(value) is list:
        return all(_is_strict_json_value(item) for item in value)
    if isinstance(value, dict) and type(value) is dict:
        return all(type(key) is str and _is_strict_json_value(item) for key, item in value.items())
    return False


def mutation_campaign_exit_code(campaign: AssuranceMutationCampaign) -> int:
    """Return the stable campaign exit code using worst-state precedence."""
    states = tuple(item.result.state for item in campaign.operator_results)
    if MutationResultState.execution_error in states:
        return 4
    if any(
        state in {MutationResultState.invalid_operator, MutationResultState.invalid_subject}
        for state in states
    ):
        return 2
    if MutationResultState.survived in states:
        return 1
    if states and all(state is MutationResultState.inapplicable for state in states):
        return 3
    return 0


def _select_operators(
    operators: tuple[RegisteredOperator, ...],
    catalog: AssuranceMutationCatalog,
    *,
    operator_ids: tuple[str, ...],
    invariant_families: tuple[str, ...],
    threat_ids: tuple[str, ...],
) -> tuple[RegisteredOperator, ...]:
    _require_unique_filter(operator_ids, label="operator")
    _require_unique_filter(invariant_families, label="invariant family")
    _require_unique_filter(threat_ids, label="threat ID")

    by_id = {item.descriptor.operator_id: item for item in operators}
    canonical_ids = tuple(item.descriptor.operator_id for item in catalog.operators)
    unknown_operators = sorted(set(operator_ids) - set(canonical_ids))
    if unknown_operators:
        raise ValueError("unknown mutation operator filter: " + ", ".join(unknown_operators))
    known_families = {item.invariant_family for item in operators}
    unknown_families = sorted(set(invariant_families) - known_families)
    if unknown_families:
        raise ValueError("unknown invariant-family filter: " + ", ".join(unknown_families))
    known_threats = {threat_id for item in operators for threat_id in item.threat_source_references}
    unknown_threats = sorted(set(threat_ids) - known_threats)
    if unknown_threats:
        raise ValueError("unknown threat-ID filter: " + ", ".join(unknown_threats))

    operator_filter = set(operator_ids)
    family_filter = set(invariant_families)
    threat_filter = set(threat_ids)
    selected = tuple(
        by_id[operator_id]
        for operator_id in canonical_ids
        if (not operator_filter or operator_id in operator_filter)
        and (not family_filter or by_id[operator_id].invariant_family in family_filter)
        and (
            not threat_filter
            or threat_filter.intersection(by_id[operator_id].threat_source_references)
        )
    )
    if not selected:
        raise ValueError("mutation campaign filters selected no operators")
    return selected


def _require_unique_filter(values: tuple[str, ...], *, label: str) -> None:
    if len(set(values)) != len(values):
        raise ValueError(f"{label} filters must be unique")


def _campaign_entry(
    registered: RegisteredOperator,
    execution: MutationExecution,
    *,
    seed: int,
) -> MutationCampaignOperatorResult:
    contract = registered.descriptor.expected_detection_contract
    prohibited_ids = tuple(
        sorted(
            finding.finding_id
            for finding in execution.result.observed_findings
            if any(
                finding.control_id == selector.control_id
                and finding.reason_code is selector.reason_code
                and (
                    selector.target is None
                    or finding.target_digest == finding_target_digest(selector.target)
                )
                for selector in contract.prohibited_substitutes
            )
        )
    )
    return MutationCampaignOperatorResult(
        operator_id=registered.descriptor.operator_id,
        invariant_family=registered.invariant_family,
        seed=seed,
        applicability=mutation_result_applicability(execution.result),
        expected_detection_contract=contract,
        result=execution.result,
        prohibited_substitute_finding_ids=prohibited_ids,
    )
