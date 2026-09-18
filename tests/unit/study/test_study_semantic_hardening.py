from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import ValidationError

import agent_assure.schema.study as study_schema
import agent_assure.study.analysis as study_analysis
from agent_assure.live.config import LiveAdapterConfig, LivePromptCase, LiveRunConfig
from agent_assure.rag import repeated_sensitivity as repeated_workflow
from agent_assure.rag.repeated_sensitivity import run_repeated_live_study
from agent_assure.reporting.study import render_real_model_study_markdown
from agent_assure.schema.benchmark import (
    ProcessEquivalenceBenchmarkManifest,
    benchmark_has_registered_confirmatory_bar,
    calculate_benchmark_confirmatory_structure_digest,
)
from agent_assure.schema.live import LiveProtocolRecord
from agent_assure.schema.run import LiveExecutionAttemptJournal, RunSet
from agent_assure.schema.stochastic_sensitivity import (
    CaseClusterBinding,
    FixedFrameDescriptivePlan,
    RepeatedEvidenceSensitivityProtocol,
)
from agent_assure.schema.study import (
    UNRESOLVED_INDEPENDENCE_BASIS,
    RealModelStudyManifest,
    RealModelStudyReport,
    StudyAnalysisDeclaration,
    StudyConditionBinding,
    StudyConditionResult,
    StudyConditionState,
    StudyExecutionOrigin,
    StudyExpectedResponseDiagnostic,
    StudyFixedFrameDependenceAcknowledgement,
    StudyFixedFrameDescriptiveRule,
    StudyHypothesisClassification,
    StudyHypothesisDecisionRule,
    StudyIndependenceDesignBasis,
    StudyIndependenceJustification,
    StudyIndependenceJustificationStatus,
    StudyInferenceScope,
    StudyObservedExecutionProvenance,
    StudySemanticNearDuplicateDisposition,
)
from agent_assure.schema.suite import CompiledSuite
from agent_assure.study.analysis import (
    StudyConditionEvidence,
    analyze_real_model_study,
    validate_study_manifest_inputs,
)
from agent_assure.study_dispatch import StudyDispatchPreflightEvidence
from agent_assure.study_method_review import (
    build_study_statistical_method_review_receipt,
)
from tests.unit.study.test_real_model_study import (
    StudyFixture,
    _analyze,
    _condition_evidence,
    _fixture,
    _manifest,
    _rebuild_manifest,
    _replace_runset_records,
)

ROOT = Path(__file__).resolve().parents[3]


def _set_decision(payload: dict[str, Any], decision: str) -> dict[str, Any]:
    payload["recommendation"] = decision
    payload["outcome"] = "approved" if decision == "approve" else "denied"
    return payload


def _split_inertia_evidence(fixture: StudyFixture) -> StudyConditionEvidence:
    case_ids = tuple(run.case_id for run in fixture.evidence.baseline_runset.runs)
    baseline_correct_ids = set(case_ids[: len(case_ids) // 2])

    def baseline(payload: dict[str, Any]) -> dict[str, Any]:
        return (
            payload
            if payload["case_id"] in baseline_correct_ids
            else _set_decision(payload, "deny")
        )

    def counterfactual(payload: dict[str, Any]) -> dict[str, Any]:
        return (
            _set_decision(payload, "approve")
            if payload["case_id"] in baseline_correct_ids
            else payload
        )

    baseline_runset = _replace_runset_records(
        fixture.evidence.baseline_runset,
        baseline,
    )
    counterfactual_runset = _replace_runset_records(
        fixture.evidence.counterfactual_runset,
        counterfactual,
    )
    return _condition_evidence(
        manifest=fixture.manifest,
        binding=fixture.manifest.conditions[0],
        protocol=fixture.protocol,
        baseline_runset=baseline_runset,
        counterfactual_runset=counterfactual_runset,
    )


def _with_fingerprint(
    fixture: StudyFixture,
    *,
    baseline_fingerprint: str | None,
    counterfactual_fingerprint: str | None,
    condition_id: str | None = None,
) -> StudyConditionEvidence:
    def set_fingerprint(value: str | None):  # type: ignore[no-untyped-def]
        def transform(payload: dict[str, Any]) -> dict[str, Any]:
            if value is None:
                payload.pop("provider_serving_fingerprint", None)
            else:
                payload["provider_serving_fingerprint"] = value
            return payload

        return transform

    selected_condition_id = condition_id or fixture.manifest.conditions[0].condition_id
    source = fixture.evidence_by_condition[selected_condition_id]
    binding = next(
        item for item in fixture.manifest.conditions if item.condition_id == selected_condition_id
    )
    baseline = _replace_runset_records(
        source.baseline_runset,
        set_fingerprint(baseline_fingerprint),
    )
    counterfactual = _replace_runset_records(
        source.counterfactual_runset,
        set_fingerprint(counterfactual_fingerprint),
    )
    return _condition_evidence(
        manifest=fixture.manifest,
        binding=binding,
        protocol=fixture.protocols[selected_condition_id],
        baseline_runset=baseline,
        counterfactual_runset=counterfactual,
    )


def _analyze_with_condition_fingerprints(
    fixture: StudyFixture,
    fingerprints: dict[str, str | None],
) -> RealModelStudyReport:
    evidence = dict(fixture.evidence_by_condition)
    for condition_id, fingerprint in fingerprints.items():
        evidence[condition_id] = _with_fingerprint(
            fixture,
            condition_id=condition_id,
            baseline_fingerprint=fingerprint,
            counterfactual_fingerprint=fingerprint,
        )
    return analyze_real_model_study(
        manifest=fixture.manifest,
        benchmark=fixture.benchmark,
        protocols=fixture.protocols,
        evidence=evidence,
    )


def _unresolved_independence() -> StudyIndependenceJustification:
    return StudyIndependenceJustification(
        status=StudyIndependenceJustificationStatus.unresolved_authoring_placeholder,
        design_basis=StudyIndependenceDesignBasis.unresolved,
        semantic_near_duplicate_disposition=(StudySemanticNearDuplicateDisposition.unresolved),
        cluster_unit_definition=(
            "Each proposed inferential unit is one separately dispatched case-ID "
            "cluster in a finite frozen conformance frame."
        ),
        independence_basis=UNRESOLVED_INDEPENDENCE_BASIS,
        dependence_risks_and_mitigations=(
            "All cases share one task template, so identities and digests establish "
            "replayability but do not establish behavioral independence."
        ),
        residual_scope_limitation=(
            "Any eventual inference remains conditional on qualified human review "
            "and scoped to the exact finite frame."
        ),
    )


def _fixed_frame_protocol(
    protocol: RepeatedEvidenceSensitivityProtocol,
) -> RepeatedEvidenceSensitivityProtocol:
    payload = protocol.model_dump(mode="json")
    for field_name in (
        "protocol_digest",
        "design_commitment_digest",
        "inferential_unit",
        "multiplicity_family",
        "multiplicity_method",
        "multiplicity_family_size",
    ):
        payload.pop(field_name, None)
    payload.update(
        {
            "interpretation": "fixed_frame_descriptive",
            "descriptive_unit": protocol.cluster_by,
            "design": FixedFrameDescriptivePlan(
                planned_descriptive_clusters=len(protocol.planned_cluster_ids)
            ).model_dump(mode="json"),
            "limitations": tuple(
                sorted(
                    {
                        *protocol.limitations,
                        (
                            "Finite-frame counts and rates describe only the exact "
                            "frozen planned clusters; no population inference is made."
                        ),
                    }
                )
            ),
        }
    )
    return RepeatedEvidenceSensitivityProtocol.build(**payload)


def _fixed_frame_manifest(
    fixture: StudyFixture,
    protocols: dict[str, RepeatedEvidenceSensitivityProtocol] | None = None,
) -> RealModelStudyManifest:
    fixed_protocols = protocols or {
        condition_id: _fixed_frame_protocol(protocol)
        for condition_id, protocol in fixture.protocols.items()
    }
    execution_origins = {item.execution_origin for item in fixture.manifest.conditions}
    assert len(execution_origins) == 1
    bound = _manifest(
        fixture.benchmark,
        fixed_protocols,
        execution_origin=next(iter(execution_origins)),
    )
    source_rule = fixture.manifest.hypothesis_decision_rule
    audit_sha256 = source_rule.independence_justification.design_audit_artifact_sha256
    assert audit_sha256 is not None
    rule = StudyFixedFrameDescriptiveRule(
        inference_scope=StudyInferenceScope.fixed_frame_descriptive_conformance,
        target_task_model_conditions=source_rule.target_task_model_conditions,
        negative_control_conditions=source_rule.negative_control_conditions,
        dependence_acknowledgement=StudyFixedFrameDependenceAcknowledgement(
            dependence_audit_artifact_sha256=audit_sha256,
            descriptive_unit_definition=(
                "Each reported unit is one committed case cluster in this exact finite "
                "synthetic conformance frame, without a population-sampling claim."
            ),
            dependence_basis=(
                "The cases form a shared-template parameter grid, so the design does "
                "not claim independent exchangeable behavioral units."
            ),
            dependence_risks_and_mitigations=(
                "Shared task structure and adjacent parameters can induce correlated "
                "behavior; the analysis therefore reports only fixed-frame rates."
            ),
            residual_scope_limitation=(
                "Results describe only these exact committed cases and provider calls, "
                "with no prevalence or population generalization."
            ),
        ),
        descriptive_scope_rationale=(
            "This downscope reports exact finite-frame counts and rates while explicitly "
            "prohibiting confirmatory, prevalence, and population-level inference."
        ),
    )
    return _rebuild_manifest(
        bound,
        analysis_status=StudyAnalysisDeclaration(
            primary=StudyInferenceScope.fixed_frame_descriptive_conformance
        ),
        hypothesis_decision_rule=rule,
    )


def _fixed_frame_evidence(
    fixture: StudyFixture,
    manifest: RealModelStudyManifest,
    protocols: dict[str, RepeatedEvidenceSensitivityProtocol],
) -> dict[str, StudyConditionEvidence]:
    bindings = {item.condition_id: item for item in manifest.conditions}

    def rebind_runset(
        source: RunSet,
        protocol: RepeatedEvidenceSensitivityProtocol,
    ) -> RunSet:
        payload = source.model_dump(mode="json")
        payload["evidence_sensitivity_design_digest"] = protocol.design_commitment_digest
        payload["study_manifest_digest"] = manifest.manifest_digest
        for raw_run in payload["runs"]:
            provenance = dict(raw_run["provenance"])
            provenance["evidence_sensitivity_design_digest"] = protocol.design_commitment_digest
            provenance["study_manifest_digest"] = manifest.manifest_digest
            raw_run["provenance"] = provenance
        if payload.get("execution_attempt_journal") is not None:
            journal_payload = dict(payload["execution_attempt_journal"])
            journal_payload.pop("journal_digest")
            journal_payload["repeated_protocol_digest"] = protocol.protocol_digest
            journal_payload["study_manifest_digest"] = manifest.manifest_digest
            journal = LiveExecutionAttemptJournal.build(**journal_payload)
            payload["execution_attempt_journal_digest"] = journal.journal_digest
            payload["execution_attempt_journal"] = journal.model_dump(mode="json")
        return RunSet.model_validate(payload)

    return {
        condition_id: _condition_evidence(
            manifest=manifest,
            binding=bindings[condition_id],
            protocol=protocols[condition_id],
            baseline_runset=rebind_runset(
                source.baseline_runset,
                protocols[condition_id],
            ),
            counterfactual_runset=rebind_runset(
                source.counterfactual_runset,
                protocols[condition_id],
            ),
        )
        for condition_id, source in fixture.evidence_by_condition.items()
    }


def test_fixed_frame_downscope_is_analyzable_but_never_classified() -> None:
    fixture = _fixture()
    protocols = {
        condition_id: _fixed_frame_protocol(protocol)
        for condition_id, protocol in fixture.protocols.items()
    }
    manifest = _fixed_frame_manifest(fixture, protocols)
    evidence = _fixed_frame_evidence(fixture, manifest, protocols)

    report = analyze_real_model_study(
        manifest=manifest,
        benchmark=fixture.benchmark,
        protocols=protocols,
        evidence=evidence,
    )

    assert report.protocol_valid is True
    assert report.inferential_statistics_applicable is False
    assert report.statistical_sufficiency_satisfied is False
    assert report.invariant_controls_satisfied is True
    assert report.hypothesis_classification is StudyHypothesisClassification.not_measured
    assert all(
        result.state is StudyConditionState.fixed_frame_descriptive for result in report.conditions
    )
    assert all(
        result.decision_inertia_rate is not None
        for result in report.conditions
        if result.analysis_role.value == "inertia_estimand"
    )

    markdown = render_real_model_study_markdown(report)
    assert "Inferential statistics applicable: false" in markdown
    assert "Frame completeness satisfied: true" in markdown
    assert "Inferential decision rule: inactive" in markdown
    assert "Frame clusters (committed/complete)" in markdown
    assert "Statistical sufficiency" not in markdown
    assert "Inferential unit:" not in markdown
    assert "Materiality threshold:" not in markdown
    assert "Familywise alpha:" not in markdown
    assert "Minimum independent clusters:" not in markdown
    assert "Adjusted one-sided inertia interval:" not in markdown
    assert "Adjusted one-sided unexpected-change interval:" not in markdown


def test_study_inference_scope_is_never_implicitly_confirmatory() -> None:
    fixture = _fixture()
    rule_payload = fixture.manifest.hypothesis_decision_rule.model_dump(mode="json")
    rule_payload.pop("inference_scope")
    with pytest.raises(ValidationError, match="inference_scope"):
        StudyHypothesisDecisionRule.model_validate(rule_payload)

    manifest_payload = fixture.manifest.model_dump(mode="json")
    manifest_payload.pop("analysis_status")
    with pytest.raises(ValidationError, match="analysis_status"):
        RealModelStudyManifest.model_validate(manifest_payload)


def test_directional_contract_names_the_combined_wrong_decision_guarantee() -> None:
    fixture = _fixture()
    rule = fixture.manifest.hypothesis_decision_rule
    assert (
        rule.directional_error_control
        == "complementary_hypotheses_combined_wrong_direction_fwer_at_most_familywise_alpha"
    )

    payload = rule.model_dump(mode="json")
    payload["directional_error_control"] = (
        "each_direction_separately_fwer_controlled_not_joint_two_sided_alpha"
    )
    with pytest.raises(ValidationError, match="directional_error_control"):
        StudyHypothesisDecisionRule.model_validate(payload)


def test_confirmatory_scope_rejects_shared_template_grid_as_independence_basis() -> None:
    fixture = _fixture()
    payload = fixture.manifest.hypothesis_decision_rule.independence_justification.model_dump(
        mode="json"
    )
    payload.update(
        {
            "design_basis": "shared_template_parameter_grid",
            "semantic_near_duplicate_disposition": "fixed_frame_descriptive_only",
        }
    )

    with pytest.raises(ValidationError, match="confirmatory independence"):
        StudyIndependenceJustification.model_validate(payload)


def test_exact_v0_2_shared_template_grid_is_rejected_before_provider_execution() -> None:
    fixture = _fixture()
    benchmark = ProcessEquivalenceBenchmarkManifest.model_validate_json(
        (ROOT / "examples/process_equivalence_benchmark_v0_2/benchmark.json").read_text(
            encoding="utf-8"
        )
    )
    confirmatory_manifest = _manifest(benchmark, fixture.protocols)

    assert not benchmark_has_registered_confirmatory_bar(fixture.benchmark)
    assert benchmark_has_registered_confirmatory_bar(benchmark)
    with pytest.raises(ValueError, match="shared-template parameter-grid benchmark"):
        validate_study_manifest_inputs(
            confirmatory_manifest,
            benchmark,
            fixture.protocols,
        )


def test_v0_2_grid_relabeling_cannot_bypass_confirmatory_bar() -> None:
    benchmark = ProcessEquivalenceBenchmarkManifest.model_validate_json(
        (ROOT / "examples/process_equivalence_benchmark_v0_2/benchmark.json").read_text(
            encoding="utf-8"
        )
    )
    values = benchmark.model_dump(mode="python", exclude={"benchmark_digest"})
    values["benchmark_id"] = "relabelled-shared-grid"
    values["cases"] = tuple(
        case.model_copy(
            update={
                "case_id": f"relabelled-case-{index:03d}",
                "task_id": f"relabelled-task-{index:03d}",
                "authority_contract_id": f"relabelled-contract-{index:03d}",
                "query_family_id": f"relabelled-query-{index:03d}",
            }
        )
        for index, case in enumerate(benchmark.cases)
    )
    relabelled = ProcessEquivalenceBenchmarkManifest.build(**values)

    assert relabelled.benchmark_digest != benchmark.benchmark_digest
    assert calculate_benchmark_confirmatory_structure_digest(relabelled) == (
        calculate_benchmark_confirmatory_structure_digest(benchmark)
    )
    assert benchmark_has_registered_confirmatory_bar(relabelled)


def test_exact_v0_2_grid_is_rejected_at_actual_dispatch_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(real_provider_execution=True)
    benchmark = ProcessEquivalenceBenchmarkManifest.model_validate_json(
        (ROOT / "examples/process_equivalence_benchmark_v0_2/benchmark.json").read_text(
            encoding="utf-8"
        )
    )
    manifest = _manifest(
        benchmark,
        fixture.protocols,
        execution_origin=StudyExecutionOrigin.real_provider,
    )
    condition_id, protocol = next(iter(fixture.protocols.items()))
    protocol_path = tmp_path / "registered-protocol.json"
    protocol_path.write_text(
        json.dumps(protocol.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    config = LiveRunConfig(
        variant_id="grid-dispatch-guard",
        pipeline_id="sensitivity-pipeline",
        execution_profile="preregistered_paired_study",
        tool_schema_digest="a" * 64,
        policy_bundle_digest="b" * 64,
        evidence_sensitivity_design_digest=protocol.design_commitment_digest,
        study_manifest_digest=manifest.manifest_digest,
        adapter=LiveAdapterConfig(
            adapter_id="openai-chat-completions",
            provider="synthetic-provider",
            model="synthetic-model",
        ),
        cases=(
            LivePromptCase(
                case_id="case-a",
                prompt_path="case-a.txt",
                input_summary="synthetic request",
            ),
        ),
        max_requests=1,
        max_retries=0,
    )
    dispatches: list[str] = []

    def unexpected_dispatch(*args: object, **kwargs: object) -> object:
        del args, kwargs
        dispatches.append("called")
        raise AssertionError("known grid reached provider dispatch")

    monkeypatch.setattr(repeated_workflow, "run_live_suite", unexpected_dispatch)

    with pytest.raises(ValueError, match="shared-template parameter-grid benchmark"):
        run_repeated_live_study(
            compiled=cast(CompiledSuite, object()),
            protocol=protocol,
            baseline_config=config,
            counterfactual_config=config,
            operational_protocol=cast(LiveProtocolRecord, object()),
            baseline_config_dir=tmp_path,
            counterfactual_config_dir=tmp_path,
            registered_protocol_path=protocol_path,
            study_manifest=manifest,
            study_benchmark=benchmark,
            study_condition_id=condition_id,
            # A valid registration cannot be constructed for this known-
            # ineligible grid. A non-null sentinel proves the library dispatch
            # boundary reaches structural validation before any provider call.
            study_dispatch_evidence=cast(StudyDispatchPreflightEvidence, object()),
        )

    assert dispatches == []


def test_exact_v0_2_grid_remains_available_for_fixed_frame_descriptive_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture()
    benchmark = ProcessEquivalenceBenchmarkManifest.model_validate_json(
        (ROOT / "examples/process_equivalence_benchmark_v0_2/benchmark.json").read_text(
            encoding="utf-8"
        )
    )
    canonical_bound = _manifest(benchmark, fixture.protocols)
    fixed_frame = _fixed_frame_manifest(fixture)
    descriptive_manifest = _rebuild_manifest(
        canonical_bound,
        analysis_status=fixed_frame.analysis_status,
        hypothesis_decision_rule=fixed_frame.hypothesis_decision_rule,
    )
    monkeypatch.setattr(
        study_analysis,
        "_validate_benchmark_condition_frames",
        lambda *_args: None,
    )
    monkeypatch.setattr(
        study_analysis,
        "_validate_condition_protocol",
        lambda **_kwargs: None,
    )

    validate_study_manifest_inputs(
        descriptive_manifest,
        benchmark,
        fixture.protocols,
    )


def test_inertia_breakdown_is_descriptive_exact_and_published() -> None:
    fixture = _fixture()
    report = _analyze(fixture, _split_inertia_evidence(fixture))
    result = report.conditions[0]
    breakdown = result.decision_inertia_descriptive_breakdown

    assert result.state is StudyConditionState.analyzed
    assert result.decision_inertia_cluster_count == result.planned_clusters == 4
    assert breakdown is not None
    assert (
        breakdown.baseline_correct_same_decision_cluster_count,
        breakdown.baseline_incorrect_same_decision_cluster_count,
        breakdown.mixed_baseline_correctness_same_decision_cluster_count,
    ) == (2, 2, 0)
    assert (
        breakdown.baseline_correct_same_decision_rate,
        breakdown.baseline_incorrect_same_decision_rate,
        breakdown.mixed_baseline_correctness_same_decision_rate,
    ) == ("0.500000", "0.500000", "0.000000")
    assert report.hypothesis_classification is StudyHypothesisClassification.supported

    diagnostic = result.expected_response_diagnostic
    assert diagnostic is not None
    assert diagnostic.diagnostic_state == "expected_response_not_supported"
    assert diagnostic.sprint7_hypothesis_effect == "non_verdict"
    assert (
        diagnostic.polarity_relative_to_sprint7_hypothesis
        == "inverse_signal_for_direct_same_decision_inertia"
    )
    assert diagnostic.source_report.state.value == "block"
    payload = result.model_dump(mode="json")
    assert "stochastic_report" not in payload

    markdown = render_real_model_study_markdown(report)
    assert "Descriptive same-decision inertia split" in markdown
    assert "2/2/0" in markdown
    assert "descriptive only, not external truth" in markdown
    assert "Expected-response diagnostic state (non-hypothesis)" in markdown


def test_expected_response_diagnostic_has_relation_specific_control_polarity() -> None:
    report = _analyze(_fixture())
    control = next(
        result
        for result in report.conditions
        if result.analysis_role.value == "invariant_negative_control"
    )
    diagnostic = control.expected_response_diagnostic

    assert diagnostic is not None
    assert (
        diagnostic.polarity_relative_to_sprint7_hypothesis
        == "not_applicable_to_inertia_estimand_aligned_with_invariant_control"
    )
    assert diagnostic.sprint7_hypothesis_effect == "non_verdict"
    rendered = render_real_model_study_markdown(report)
    assert "expected stability aligns with the invariant-control role" in rendered

    payload = diagnostic.model_dump(mode="json")
    payload["polarity_relative_to_sprint7_hypothesis"] = (
        "inverse_signal_for_direct_same_decision_inertia"
    )
    with pytest.raises(
        ValidationError,
        match="diagnostic polarity must derive from its protocol relation",
    ):
        StudyExpectedResponseDiagnostic.model_validate(payload)


def test_inertia_breakdown_classifies_a_mixed_member_cluster_exactly() -> None:
    fixture = _fixture()
    result = _analyze(fixture, _split_inertia_evidence(fixture)).conditions[0]
    assert result.sufficiency_report is not None

    # Re-cluster the exact replayed observations solely to exercise the pure
    # descriptive derivation: one cluster contains one baseline-correct and one
    # baseline-incorrect same-decision member; the other two remain homogeneous.
    cluster_by_case = {
        "case-a": "mixed",
        "case-b": "correct",
        "case-c": "mixed",
        "case-d": "incorrect",
    }
    protocol = result.sufficiency_report.protocol.model_copy(
        update={
            "planned_cluster_ids": ("correct", "incorrect", "mixed"),
            "case_cluster_bindings": tuple(
                CaseClusterBinding(case_id=case_id, cluster_id=cluster_id)
                for case_id, cluster_id in cluster_by_case.items()
            ),
        }
    )
    observations = tuple(
        observation.model_copy(update={"cluster_id": cluster_by_case[observation.case_id]})
        for observation in result.sufficiency_report.observations
    )
    sufficiency = result.sufficiency_report.model_copy(
        update={"protocol": protocol, "observations": observations}
    )

    descriptive_counts = study_schema.derive_study_inertia_descriptive_counts(sufficiency)
    _, inertia_count, _, _, _, _, _ = study_schema.derive_study_cluster_endpoint_counts(sufficiency)

    assert descriptive_counts == (1, 1, 1)
    assert sum(descriptive_counts) == inertia_count == 3


def test_inertia_breakdown_tampering_fails_exact_replay() -> None:
    fixture = _fixture()
    result = _analyze(fixture, _split_inertia_evidence(fixture)).conditions[0]
    payload = result.model_dump(mode="json")
    breakdown = cast(dict[str, Any], payload["decision_inertia_descriptive_breakdown"])
    breakdown["baseline_correct_same_decision_cluster_count"] = 1
    breakdown["baseline_correct_same_decision_rate"] = "0.250000"

    with pytest.raises(
        ValidationError,
        match="must exactly partition the confirmatory inertia count",
    ):
        StudyConditionResult.model_validate(payload)


@pytest.mark.parametrize(
    "resolved_model",
    (
        "gpt-4o",
        "gpt-4o-latest",
        "gpt-4o-2025-04-14-latest",
        "gpt-4o-prefix-2025-04-14-revision",
        "gpt-4o-2025-02-30",
    ),
)
def test_real_provider_rejects_versionless_or_suffixed_model_aliases(
    resolved_model: str,
) -> None:
    fixture = _fixture()
    payload = fixture.manifest.conditions[0].model_dump(mode="json")
    payload.update(
        {
            "execution_origin": "real_provider",
            "execution_attempt_id": "immutable-version-test-attempt",
            "expected_resolved_model": resolved_model,
        }
    )

    with pytest.raises(ValidationError, match="provider snapshot identifier"):
        StudyConditionBinding.model_validate(payload)


def test_real_provider_accepts_exact_dated_model_snapshot() -> None:
    fixture = _fixture()
    payload = fixture.manifest.conditions[0].model_dump(mode="json")
    payload.update(
        {
            "execution_origin": "real_provider",
            "execution_attempt_id": "immutable-version-test-attempt",
            "expected_resolved_model": "provider-model-2025-04-14",
        }
    )

    binding = StudyConditionBinding.model_validate(payload)
    assert binding.expected_resolved_model == "provider-model-2025-04-14"


def test_real_provider_manifest_rejects_unresolved_independence_basis() -> None:
    fixture = _fixture()
    bindings: list[StudyConditionBinding] = []
    for index, binding in enumerate(fixture.manifest.conditions):
        payload = binding.model_dump(mode="json")
        payload.update(
            {
                "execution_origin": "real_provider",
                "execution_attempt_id": f"independence-test-attempt-{index}",
                "expected_resolved_model": "provider-model-2025-04-14",
            }
        )
        bindings.append(StudyConditionBinding.model_validate(payload))
    rule_payload = fixture.manifest.hypothesis_decision_rule.model_dump(mode="json")
    rule_payload["independence_justification"] = _unresolved_independence().model_dump(mode="json")
    rule = StudyHypothesisDecisionRule.model_validate(rule_payload)

    with pytest.raises(ValidationError, match="positive design-based independence"):
        _rebuild_manifest(
            fixture.manifest,
            conditions=tuple(bindings),
            hypothesis_decision_rule=rule,
        )


def test_statistical_method_review_rejects_unresolved_synthetic_manifest() -> None:
    fixture = _fixture()
    rule_payload = fixture.manifest.hypothesis_decision_rule.model_dump(mode="json")
    rule_payload["independence_justification"] = _unresolved_independence().model_dump(mode="json")
    manifest = _rebuild_manifest(
        fixture.manifest,
        hypothesis_decision_rule=StudyHypothesisDecisionRule.model_validate(rule_payload),
    )

    with pytest.raises(ValueError, match="positive design-based independence"):
        build_study_statistical_method_review_receipt(
            manifest=manifest,
            benchmark=fixture.benchmark,
            protocols=fixture.protocols,
            registration_record_bytes=fixture.registration_record_bytes,
            registration_review_receipt=fixture.registration_review_receipt,
            independence_audit_artifact_bytes=fixture.independence_audit_artifact_bytes,
            receipt_id="unresolved-independence-review",
            reviewed_at_utc="2025-01-03T00:00:00Z",
            reviewer_pseudonym="independent-statistical-reviewer",
            reviewer_statistical_qualification_confirmed=True,
            reviewer_qualification_basis_types=("professional_statistical_practice",),
            reviewer_qualification_evidence_digest="0123456789abcdef" * 4,
            reviewer_qualification_basis=(
                "The reviewer has documented statistical design and exact "
                "binomial-inference qualifications."
            ),
            reviewer_independent_of_design_execution_and_analysis=True,
            reviewer_independence_rationale=(
                "The reviewer did not design, execute, analyze, or sponsor this "
                "synthetic validation study."
            ),
            design_basis_reviewed_and_accepted=True,
            design_review_rationale=(
                "Independent review would need to accept a concrete cluster-construction "
                "basis before confirmatory provider execution."
            ),
            semantic_near_duplicate_audit_reviewed=True,
            semantic_near_duplicate_pseudoreplication_rejected=True,
            semantic_near_duplicate_review_rationale=(
                "Independent review would need to disposition every semantic duplicate "
                "before treating clusters as separate units."
            ),
            benchmark_cluster_assignments_reviewed=True,
            independence_and_exchangeability_assumptions_reviewed=True,
            sampling_frame_and_estimand_reviewed=True,
            multiplicity_and_interval_method_reviewed=True,
            combined_directional_decision_error_control_reviewed=True,
            power_and_decision_boundary_reachability_reviewed=True,
            negative_control_design_reviewed=True,
        )


def test_all_absent_fingerprints_are_explicit_and_do_not_block_analysis() -> None:
    fixture = _fixture(real_provider_execution=True)
    report = _analyze(fixture)
    result = report.conditions[0]
    provenance = result.observed_execution_provenance

    assert result.state is StudyConditionState.analyzed
    assert provenance is not None
    assert provenance.provider_serving_fingerprint_records == 0
    assert provenance.distinct_provider_serving_fingerprints == 0
    assert provenance.provider_serving_fingerprint_set_digest is None
    assert (
        provenance.provider_serving_fingerprint_policy
        == "all_absent_or_complete_and_stable_across_condition"
    )
    assert result.observed_model_identities[0].provider_serving_fingerprint is None


def test_complete_stable_fingerprint_is_bound_and_published() -> None:
    fixture = _fixture(real_provider_execution=True)
    fingerprint = "fp-stable-2025-04-14"
    report = _analyze_with_condition_fingerprints(
        fixture,
        {condition.condition_id: fingerprint for condition in fixture.manifest.conditions},
    )
    result = report.conditions[0]
    provenance = result.observed_execution_provenance

    assert result.state is StudyConditionState.analyzed
    assert provenance is not None
    assert provenance.provider_serving_fingerprint_records == provenance.run_records
    assert provenance.distinct_provider_serving_fingerprints == 1
    assert provenance.provider_serving_fingerprint_set_digest is not None
    assert result.observed_model_identities[0].provider_serving_fingerprint == fingerprint
    assert (
        fixture.manifest.conditions[0].provider_serving_fingerprint_policy
        == "all_absent_or_complete_and_stable_across_model_matched_condition_group"
    )
    markdown = render_real_model_study_markdown(report)
    assert "Provider serving-fingerprint coverage" in markdown
    assert "Model-matched target/control serving-fingerprint policy" in markdown
    assert "provider metadata, not proof of immutable serving infrastructure" in markdown


def test_model_matched_target_control_fingerprint_drift_invalidates_group() -> None:
    fixture = _fixture(real_provider_execution=True)
    targets = set(fixture.manifest.hypothesis_decision_rule.target_task_model_conditions)
    report = _analyze_with_condition_fingerprints(
        fixture,
        {
            condition.condition_id: (
                "fp-target-2025-04-14"
                if condition.condition_id in targets
                else "fp-control-2025-04-14"
            )
            for condition in fixture.manifest.conditions
        },
    )

    assert all(
        result.state is StudyConditionState.invalidated
        and "provider-serving-fingerprint-group-drift" in result.deviation_codes
        for result in report.conditions
    )
    assert report.hypothesis_classification is StudyHypothesisClassification.not_measured
    assert report.protocol_valid is False


def test_model_matched_cross_condition_fingerprint_partial_coverage_invalidates_group() -> None:
    fixture = _fixture(real_provider_execution=True)
    first_condition_id = fixture.manifest.conditions[0].condition_id
    report = _analyze_with_condition_fingerprints(
        fixture,
        {first_condition_id: "fp-partial-2025-04-14"},
    )

    assert all(
        result.state is StudyConditionState.invalidated
        and "provider-serving-fingerprint-group-incomplete" in result.deviation_codes
        for result in report.conditions
    )
    assert report.hypothesis_classification is StudyHypothesisClassification.not_measured
    assert report.protocol_valid is False


def test_report_rejects_forged_model_matched_fingerprint_drift() -> None:
    fixture = _fixture(real_provider_execution=True)
    original_fingerprint = "fp-stable-2025-04-14"
    report = _analyze_with_condition_fingerprints(
        fixture,
        {condition.condition_id: original_fingerprint for condition in fixture.manifest.conditions},
    )
    payload = report.model_dump(mode="json")
    condition_payload = cast(dict[str, Any], cast(list[Any], payload["conditions"])[0])
    identities = cast(list[dict[str, Any]], condition_payload["observed_model_identities"])
    forged_fingerprint = "fp-forged-2025-04-15"
    identities[0]["provider_serving_fingerprint"] = forged_fingerprint
    provenance_payload = cast(
        dict[str, Any],
        condition_payload["observed_execution_provenance"],
    )
    provenance_payload.pop("provenance_digest")
    provenance_payload["provider_serving_fingerprint_set_digest"] = study_schema._canonical_sha256(  # noqa: SLF001 - adversarial relation test
        {
            "purpose": "study-provider-serving-fingerprints/v1",
            "fingerprints": (forged_fingerprint,),
        }
    )
    condition_payload["observed_execution_provenance"] = StudyObservedExecutionProvenance.build(
        **provenance_payload
    ).model_dump(mode="json")
    payload.pop("report_digest")

    with pytest.raises(
        ValidationError,
        match="model-matched conditions must share one provider serving fingerprint",
    ):
        RealModelStudyReport.build(**payload)


@pytest.mark.parametrize(
    ("baseline_fingerprint", "counterfactual_fingerprint", "deviation"),
    (
        ("fp-one", None, "provider-serving-fingerprint-incomplete"),
        ("fp-one", "fp-two", "provider-serving-fingerprint-drift"),
    ),
)
def test_partial_or_drifting_fingerprints_cannot_yield_classified_evidence(
    baseline_fingerprint: str | None,
    counterfactual_fingerprint: str | None,
    deviation: str,
) -> None:
    fixture = _fixture(real_provider_execution=True)
    evidence = _with_fingerprint(
        fixture,
        baseline_fingerprint=baseline_fingerprint,
        counterfactual_fingerprint=counterfactual_fingerprint,
    )
    report = _analyze(fixture, evidence)
    result = report.conditions[0]

    assert result.state is StudyConditionState.invalidated
    assert deviation in result.deviation_codes
    assert "provider-dispatch-provenance-incomplete" in result.deviation_codes
    assert report.hypothesis_classification is StudyHypothesisClassification.not_measured
    assert report.confirmatory_conclusion_permitted is False


def test_fingerprint_set_digest_tampering_fails_report_relation() -> None:
    fixture = _fixture(real_provider_execution=True)
    fingerprint = "fp-stable-2025-04-14"
    report = _analyze_with_condition_fingerprints(
        fixture,
        {condition.condition_id: fingerprint for condition in fixture.manifest.conditions},
    )
    payload = report.model_dump(mode="json")
    condition_payload = cast(dict[str, Any], cast(list[Any], payload["conditions"])[0])
    provenance_payload = cast(
        dict[str, Any],
        condition_payload["observed_execution_provenance"],
    )
    provenance_payload.pop("provenance_digest")
    provenance_payload["provider_serving_fingerprint_set_digest"] = "f" * 64
    forged_provenance = StudyObservedExecutionProvenance.build(**provenance_payload)
    condition_payload["observed_execution_provenance"] = forged_provenance.model_dump(mode="json")
    payload.pop("report_digest")

    with pytest.raises(
        ValidationError,
        match="fingerprint digest must bind the exposed stable identity",
    ):
        RealModelStudyReport.build(**payload)


def test_report_rejects_aggregate_interval_work_before_exact_evaluation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = _analyze(_fixture())
    payload = report.model_dump(mode="json")
    raw_conditions = cast(list[dict[str, Any]], payload["conditions"])
    for index, condition in enumerate(raw_conditions):
        field_name = (
            "decision_inertia_interval"
            if "decision_inertia_interval" in condition
            else "control_unexpected_change_interval"
        )
        interval = cast(dict[str, Any], condition[field_name])
        interval.update(
            {
                "successes": 498 + index,
                "trials": 1_000,
                "adjusted_alpha": "0.025000000000",
            }
        )

    calls = 0

    def forbidden_exact_evaluation(*args: object, **kwargs: object) -> object:
        nonlocal calls
        calls += 1
        raise AssertionError("nested exact interval validation ran before aggregate precheck")

    monkeypatch.setattr(
        study_schema,
        "clopper_pearson_one_sided",
        forbidden_exact_evaluation,
    )

    with pytest.raises(
        ValidationError,
        match="aggregate Clopper-Pearson exact-tail work exceeds",
    ):
        RealModelStudyReport.model_validate(payload)
    assert calls == 0


def test_manifest_rejects_worst_case_interval_work_before_reachability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture()
    resized_conditions: list[StudyConditionBinding] = []
    for condition in fixture.manifest.conditions:
        condition_payload = condition.model_dump(mode="json")
        condition_payload.update(
            {
                "planned_pairs": 1_000,
                "planned_clusters": 1_000,
            }
        )
        resized_conditions.append(StudyConditionBinding.model_validate(condition_payload))

    assert (
        sum(
            study_schema.clopper_pearson_interval_pair_work_units(500, 1_000)
            for _ in resized_conditions[:2]
        )
        == study_schema.MAX_CLOPPER_PEARSON_AGGREGATE_WORK_UNITS
    )
    study_schema._validate_study_interval_design_work_budget(  # noqa: SLF001
        tuple(resized_conditions[:2])
    )

    calls = 0

    def forbidden_reachability_evaluation(*args: object, **kwargs: object) -> object:
        nonlocal calls
        calls += 1
        raise AssertionError("reachability ran before planned aggregate-work validation")

    monkeypatch.setattr(
        study_schema,
        "clopper_pearson_one_sided",
        forbidden_reachability_evaluation,
    )

    with pytest.raises(
        ValidationError,
        match="planned Clopper-Pearson exact-tail work exceeds",
    ):
        _rebuild_manifest(
            fixture.manifest,
            conditions=tuple(resized_conditions),
        )
    assert calls == 0
