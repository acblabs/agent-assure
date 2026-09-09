from __future__ import annotations

import json
import os
from datetime import date
from difflib import unified_diff
from pathlib import Path
from typing import Any, Literal, cast

import pytest

from agent_assure.authoring.compiler import compile_suite
from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.mutation.campaign import (
    MutationCampaignExecution,
    execute_mutation_campaign,
)
from agent_assure.runner.fixture_runner import load_variant_config, run_suite
from agent_assure.schema.campaign import AssuranceMutationCampaign
from agent_assure.schema.mutation import FindingSelector
from agent_assure.schema.run import RunSet
from agent_assure.schema.suite import CompiledSuite
from agent_assure.streaming import ingest_jsonl_events, stream_run_to_runset

ROOT = Path(__file__).resolve().parents[2]
GOLDEN_ROOT = ROOT / "tests" / "golden" / "campaigns"
PRIOR_AUTH_ROOT = ROOT / "examples" / "prior_auth_synthetic"
STREAMING_ROOT = ROOT / "examples" / "streaming_process_regression"

CAMPAIGN_SEED = 20260720
GENERATED_AT = "2026-07-20T00:00:00Z"
EVALUATION_DATE = date(2026, 7, 20)
UPDATE_GOLDENS_ENV = "AGENT_ASSURE_UPDATE_CAMPAIGN_GOLDENS"

FixtureName = Literal[
    "prior_auth_synthetic_baseline",
    "streaming_process_regression_baseline",
]


@pytest.mark.parametrize(
    "fixture_name",
    (
        "prior_auth_synthetic_baseline",
        "streaming_process_regression_baseline",
    ),
)
def test_real_baseline_core_campaign_matches_golden(fixture_name: FixtureName) -> None:
    suite, runset = _load_fixture(fixture_name)
    execution = execute_mutation_campaign(
        suite,
        runset.model_dump(mode="json"),
        seed=CAMPAIGN_SEED,
        generated_at=GENERATED_AT,
        evaluation_date=EVALUATION_DATE,
    )
    _assert_exact_self_digests(execution)

    summary = _campaign_summary(fixture_name, suite, runset, execution)
    golden_path = GOLDEN_ROOT / f"{fixture_name}.summary.json"
    _assert_or_update_golden(golden_path, summary)


def _load_fixture(fixture_name: FixtureName) -> tuple[CompiledSuite, RunSet]:
    if fixture_name == "prior_auth_synthetic_baseline":
        suite_path = PRIOR_AUTH_ROOT / "suite.yaml"
        suite = compile_suite(suite_path)
        runset = run_suite(
            suite,
            load_variant_config(PRIOR_AUTH_ROOT / "variants" / "baseline.yaml"),
            PRIOR_AUTH_ROOT,
        )
        return suite, runset

    suite = compile_suite(STREAMING_ROOT / "suite.yaml")
    ingestion = ingest_jsonl_events(
        STREAMING_ROOT / "events" / "baseline.jsonl",
        sequence_scope="global",
    )
    runset = stream_run_to_runset(ingestion.stream_run, suite)
    return suite, runset


def _campaign_summary(
    fixture_name: FixtureName,
    suite: CompiledSuite,
    runset: RunSet,
    execution: MutationCampaignExecution,
) -> dict[str, object]:
    catalog = execution.catalog
    campaign = execution.campaign
    semantic_projection = _runtime_neutral_campaign_projection(campaign)

    return {
        "summary_contract": "mutation-campaign-golden-summary/v2",
        "fixture": fixture_name,
        "replay_parameters": {
            "campaign_seed": campaign.campaign_seed,
            "evaluation_date": campaign.operator_results[0].result.evaluation_date,
            "generated_at": GENERATED_AT,
            "mode": campaign.mode.value,
        },
        "source_identity": {
            "artifact_kind": runset.artifact_kind,
            "runset_id": runset.runset_id,
            "source_digest": campaign.source_digest,
            "suite_id": suite.suite_id,
            "suite_digest": campaign.suite_digest,
            "run_count": len(runset.runs),
        },
        "catalog_identity": {
            "catalog_id": catalog.catalog_id,
            "catalog_digest": catalog.catalog_digest,
            "ordering_semantics": catalog.ordering_semantics,
            "operator_order": list(campaign.canonical_operator_order),
        },
        "campaign_identity": {
            "artifact_kind": campaign.artifact_kind,
            "schema_version": campaign.schema_version,
            "contract_id": campaign.contract_id,
            "contract_version": campaign.contract_version,
            "producer_version": campaign.producer_version,
            "source_artifact_kind": campaign.source_artifact_kind,
            "semantic_projection_contract": ("assurance-mutation-campaign/runtime-neutral/v1"),
            "semantic_projection_digest": sha256_hexdigest(semantic_projection),
            "excluded_runtime_bound_fields": [
                "campaign_digest",
                "operator_results[].result.result_digest",
                "operator_results[].result.evaluator_implementation_digest",
            ],
            "mode": campaign.mode.value,
            "completion": campaign.completion.value,
            "campaign_seed": campaign.campaign_seed,
            "selected_operator_order": list(campaign.selected_operator_order),
            "executed_operator_order": list(campaign.executed_operator_order),
            "pending_operator_order": list(campaign.pending_operator_order),
            "limitations": list(campaign.limitations),
        },
        "operator_results": [
            {
                "operator_id": entry.operator_id,
                "invariant_family": entry.invariant_family,
                "seed": entry.seed,
                "applicability": entry.applicability.value,
                "state": entry.result.state.value,
                "independence_class": entry.result.independence_class.value,
                "changed_paths": list(entry.result.changed_paths),
                "observed_findings": [
                    finding.model_dump(mode="json") for finding in entry.result.observed_findings
                ],
                "matched_finding_ids": list(entry.result.matched_finding_ids),
                "prohibited_substitute_finding_ids": list(entry.prohibited_substitute_finding_ids),
                "diagnostic": {
                    "code": entry.result.diagnostic_code,
                    "exception_class": entry.result.diagnostic_exception_class,
                    "local_debug_reference": entry.result.local_debug_reference,
                    "limitations": list(entry.result.limitations),
                },
                "mutation_identity": {
                    "source_digest": entry.result.source_digest,
                    "mutated_digest": entry.result.mutated_digest,
                    "operator_version": entry.result.operator_version,
                    "operator_digest": entry.result.operator_digest,
                    "implementation_digest": entry.result.implementation_digest,
                    "expected_detection_contract_digest": (
                        entry.result.expected_detection_contract_digest
                    ),
                    "expected_finding_target_digest": (entry.result.expected_finding_target_digest),
                },
                "evaluator_semantics": {
                    "method_id": entry.result.evaluator_method_id,
                    "implementation_version": (entry.result.evaluator_implementation_version),
                    "evaluation_basis": (entry.result.evaluator_evaluation_basis.value),
                    "protocol_digest": entry.result.evaluator_protocol_digest,
                    "population_id": entry.result.evaluator_population_id,
                    "gate_profile_id": entry.result.gate_profile_id,
                    "gate_profile_digest": entry.result.gate_profile_digest,
                    "waiver_set_digest": entry.result.waiver_set_digest,
                    "evaluation_date": entry.result.evaluation_date,
                },
                "expected_contract": {
                    "contract_digest": entry.expected_detection_contract.contract_digest,
                    "target_control_ids": list(
                        entry.expected_detection_contract.target_control_ids
                    ),
                    "required_any_of": [
                        _selector_summary(selector)
                        for selector in (entry.expected_detection_contract.required_findings.any_of)
                    ],
                    "prohibited_substitutes": [
                        _selector_summary(selector)
                        for selector in (entry.expected_detection_contract.prohibited_substitutes)
                    ],
                    "expected_gate_effect": (
                        entry.expected_detection_contract.expected_gate_effect.value
                    ),
                    "secondary_findings_allowed": (
                        entry.expected_detection_contract.secondary_findings_allowed
                    ),
                },
            }
            for entry in campaign.operator_results
        ],
    }


def _runtime_neutral_campaign_projection(
    campaign: AssuranceMutationCampaign,
) -> dict[str, Any]:
    """Return the complete campaign projection minus runtime-bound digests."""
    projection = campaign.model_dump(mode="json")
    del projection["campaign_digest"]
    operator_results = cast(list[dict[str, Any]], projection["operator_results"])
    for entry in operator_results:
        result = cast(dict[str, Any], entry["result"])
        del result["result_digest"]
        del result["evaluator_implementation_digest"]
    return projection


def _assert_exact_self_digests(execution: MutationCampaignExecution) -> None:
    campaign = execution.campaign
    assert campaign.campaign_digest == sha256_hexdigest(
        campaign.model_dump(mode="json", exclude={"campaign_digest"})
    )
    for entry in campaign.operator_results:
        result = entry.result
        assert result.result_digest == sha256_hexdigest(
            result.model_dump(mode="json", exclude={"result_digest"})
        )


def _selector_summary(selector: FindingSelector) -> dict[str, str | None]:
    return {
        "control_id": selector.control_id,
        "reason_code": selector.reason_code.value,
        "target": selector.target,
    }


def _assert_or_update_golden(path: Path, summary: dict[str, object]) -> None:
    actual = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    if os.environ.get(UPDATE_GOLDENS_ENV) == "1":
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(actual, encoding="utf-8", newline="\n")

    if not path.exists():
        pytest.fail(
            f"campaign golden is missing: {path.relative_to(ROOT)}\n"
            f"Set {UPDATE_GOLDENS_ENV}=1 and rerun this test to create it."
        )

    expected = path.read_text(encoding="utf-8")
    if expected != actual:
        diff = "".join(
            unified_diff(
                expected.splitlines(keepends=True),
                actual.splitlines(keepends=True),
                fromfile=f"expected/{path.name}",
                tofile=f"actual/{path.name}",
            )
        )
        pytest.fail(
            f"campaign golden changed: {path.relative_to(ROOT)}\n"
            f"Set {UPDATE_GOLDENS_ENV}=1 and rerun this test only after reviewing "
            f"the source, catalog, contract, and result drift.\n{diff}"
        )
