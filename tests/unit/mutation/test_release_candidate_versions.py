from __future__ import annotations

from datetime import date
from typing import cast

import pytest
from pydantic import ValidationError

from agent_assure.fixtures.loader import compiled_suite_digest
from agent_assure.mutation import campaign as mutation_campaign
from agent_assure.mutation import execution as mutation_execution
from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.schema.expectation import Expectation
from agent_assure.schema.mutation import EvidenceProducer, MutationResultState
from agent_assure.schema.provenance import Provenance
from agent_assure.schema.run import (
    AgentRunRecord,
    ClaimEvidenceLink,
    EvidenceItem,
    EvidenceRef,
    RunSet,
)
from agent_assure.schema.suite import CompiledSuite, SuiteCase, SuiteDefaults
from agent_assure.schema.validation import validate_artifact_payload

_RELEASE_CANDIDATE_VERSION = "0.6.1rc1"


def test_release_candidate_build_produces_valid_mutation_campaign_artifacts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    suite, source = _fixture()
    monkeypatch.setattr(
        mutation_execution,
        "__version__",
        _RELEASE_CANDIDATE_VERSION,
    )
    monkeypatch.setattr(
        mutation_campaign,
        "__version__",
        _RELEASE_CANDIDATE_VERSION,
    )
    mutation_execution._built_in_evaluator_binding.cache_clear()
    try:
        execution = mutation_campaign.execute_mutation_campaign(
            suite,
            source,
            seed=17,
            generated_at="2026-07-29T00:00:00Z",
            operator_ids=("drop-material-evidence-link",),
            evaluation_date=date(2026, 7, 29),
        )
    finally:
        mutation_execution._built_in_evaluator_binding.cache_clear()

    operator_execution = execution.operator_executions[0]
    result = operator_execution.result
    descriptor = operator_execution.evidence_descriptor

    assert result.state is MutationResultState.caught
    assert result.evaluator_implementation_version == _RELEASE_CANDIDATE_VERSION
    assert descriptor.method.implementation_version == _RELEASE_CANDIDATE_VERSION
    assert descriptor.producer.version == _RELEASE_CANDIDATE_VERSION
    assert execution.campaign.producer_version == _RELEASE_CANDIDATE_VERSION
    assert validate_artifact_payload(
        result.model_dump(mode="json"),
        "assurance-mutation-result",
    ) == ("pydantic+jsonschema")
    assert validate_artifact_payload(
        descriptor.model_dump(mode="json"),
        "assurance-evidence-descriptor",
    ) == ("pydantic+jsonschema")
    assert validate_artifact_payload(
        execution.campaign.model_dump(mode="json"),
        "assurance-mutation-campaign",
    ) == ("pydantic+jsonschema")


@pytest.mark.parametrize(
    "invalid_version",
    (
        "0.6.1rc0",
        "0.6.1rc01",
        "0.6.1RC1",
        "0.6.1-rc.1",
        "0.6.1.dev1",
        "0.6.1+local",
    ),
)
def test_release_version_fields_reject_versions_outside_release_workflow(
    invalid_version: str,
) -> None:
    with pytest.raises(ValidationError, match="version"):
        EvidenceProducer(
            name="agent-assure",
            version=invalid_version,
        )


def _fixture() -> tuple[CompiledSuite, dict[str, object]]:
    expectation = Expectation(
        expectation_id="expectation-case-a",
        case_id="case-a",
        material_claim_ids=("claim-a",),
    )
    suite = CompiledSuite(
        suite_id="release-candidate-mutation-suite",
        suite_version="1.0.0",
        defaults=SuiteDefaults(runner_id="release.candidate.mutation.tests"),
        cases=(
            SuiteCase(
                case_id="case-a",
                title="Release candidate mutation case",
                expectation_id=expectation.expectation_id,
            ),
        ),
        resolved_expectations=(expectation,),
        source_digest="a" * 64,
    )
    fixture_digest = "b" * 64
    runset = RunSet(
        runset_id="release-candidate-mutation-runset",
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        suite_id=suite.suite_id,
        suite_version=suite.suite_version,
        suite_digest=compiled_suite_digest(suite),
        fixture_manifest_digest=fixture_digest,
        runs=(
            AgentRunRecord(
                run_id="run-case-a",
                case_id="case-a",
                pipeline_id="release-candidate.tests",
                recommendation="approve",
                outcome="approved",
                input_summary="synthetic input",
                output_summary="synthetic output",
                evidence_refs=(
                    EvidenceRef(
                        ref_id="evidence-a",
                        source_id="source-a",
                    ),
                ),
                evidence_items=(
                    EvidenceItem(
                        ref_id="evidence-a",
                        source_id="source-a",
                        content_digest="c" * 64,
                    ),
                ),
                claim_evidence_links=(
                    ClaimEvidenceLink(
                        claim_id="claim-a",
                        evidence_ref_id="evidence-a",
                    ),
                ),
                provenance=Provenance(fixture_manifest_digest=fixture_digest),
            ),
        ),
    )
    return suite, cast(dict[str, object], runset.model_dump(mode="json"))
