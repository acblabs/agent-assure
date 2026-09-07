from __future__ import annotations

from decimal import ROUND_DOWN, Decimal, Inexact, Rounded, localcontext
from hashlib import sha256

import pytest
from pydantic import ValidationError

from agent_assure.rag.sensitivity_statistics import (
    analyze_cluster_response,
    build_stochastic_sensitivity_report,
    evaluate_statistical_sufficiency,
    plan_binary_paired_design,
)
from agent_assure.schema.sensitivity import (
    RAGSensitivityAuthorityAssignment,
    RAGSensitivityCaseAuthorityBinding,
)
from agent_assure.schema.stochastic_sensitivity import (
    BinaryPairedDesignPlan,
    CaseClusterBinding,
    CouplingDescriptor,
    PairedSensitivityObservation,
    RepeatedEvidenceSensitivityProtocol,
    RunRecordArtifactDependency,
    RunSetArtifactDependency,
    SensitivityArmBinding,
    StatisticalSufficiencyReport,
    derive_cluster_response_vector,
    derive_confirmatory_cluster_response_vector,
)


def _digest(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def _plan(
    *,
    maximum_exclusion_rate: str = "0.000000",
    multiplicity_method: str = "single_endpoint",
    multiplicity_family_size: int = 1,
    planned_inferential_clusters: int | None = None,
    diagnostic_threshold: int = 20,
    resamples: int = 1_000,
) -> BinaryPairedDesignPlan:
    return plan_binary_paired_design(
        familywise_alpha="0.050000",
        desired_power="0.800000",
        null_response_rate="0.500000",
        alternative_response_rate="0.900000",
        maximum_exclusion_rate=maximum_exclusion_rate,
        planned_inferential_clusters=planned_inferential_clusters,
        multiplicity_method=multiplicity_method,  # type: ignore[arg-type]
        multiplicity_family_size=multiplicity_family_size,
        monte_carlo_diagnostic_threshold_clusters=diagnostic_threshold,
        monte_carlo_resamples=resamples,
    )


def test_design_planning_is_independent_of_ambient_decimal_context() -> None:
    arguments = {
        "familywise_alpha": "0.050000",
        "desired_power": "0.500000",
        "null_response_rate": "0.123456",
        "alternative_response_rate": "0.654321",
        "multiplicity_method": "bonferroni",
        "multiplicity_family_size": 3,
        "monte_carlo_resamples": 1_000,
    }
    expected = plan_binary_paired_design(**arguments)  # type: ignore[arg-type]

    with localcontext() as context:
        context.prec = 1
        context.Emin = -5
        context.Emax = 5
        context.rounding = ROUND_DOWN
        context.traps[Inexact] = True
        context.traps[Rounded] = True
        observed = plan_binary_paired_design(**arguments)  # type: ignore[arg-type]

    assert observed == expected
    assert observed.adjusted_alpha == "0.016666"
    assert observed.minimum_detectable_difference == "0.530865"


def _arm(arm_id: str, configuration: str, corpus: str) -> SensitivityArmBinding:
    is_counterfactual = arm_id == "counterfactual_evidence"
    return SensitivityArmBinding(
        arm_id=arm_id,
        configuration_digest=_digest(configuration),
        corpus_digest=_digest(corpus),
        expected_recommendation="deny" if is_counterfactual else "approve",
        expected_outcome="denied" if is_counterfactual else "approved",
        prompt_manifest_digest=_digest("prompt"),
        case_manifest_digest=_digest("cases"),
        knowledge_contract_digest=_digest("knowledge-contract"),
        provider="provider",
        requested_model="model",
        adapter_id="openai-chat-completions",
        pipeline_id="pipeline",
        tool_schema_digest=_digest("tool-schema"),
        policy_bundle_digest=_digest("policy-bundle"),
    )


def _protocol(
    *,
    protocol_id: str = "study",
    case_count: int | None = None,
    cluster_by_case: tuple[str, ...] | None = None,
    execution_mode: str = "stochastic_live",
    interpretation: str = "confirmatory",
    design: BinaryPairedDesignPlan | None = None,
    multiplicity_method: str = "single_endpoint",
    multiplicity_family_size: int = 1,
    allowed_exclusion_reasons: tuple[str, ...] = (),
) -> RepeatedEvidenceSensitivityProtocol:
    design = design or _plan(
        multiplicity_method=multiplicity_method,
        multiplicity_family_size=multiplicity_family_size,
    )
    if cluster_by_case is not None:
        case_count = len(cluster_by_case)
    case_count = case_count or design.planned_inferential_clusters
    cases = tuple(f"case-{index:02d}" for index in range(case_count))
    cluster_by_case = cluster_by_case or cases
    clusters = tuple(sorted(set(cluster_by_case)))
    bindings = tuple(
        CaseClusterBinding(case_id=case_id, cluster_id=cluster_id)
        for case_id, cluster_id in zip(cases, cluster_by_case, strict=True)
    )
    cluster_by = "case_id" if cluster_by_case == cases else "source_group_id"
    baseline = _arm("baseline_evidence", "baseline-config", "baseline-corpus")
    counterfactual = _arm(
        "counterfactual_evidence",
        "counterfactual-config",
        "counterfactual-corpus",
    )
    return RepeatedEvidenceSensitivityProtocol.build(
        protocol_id=protocol_id,
        interpretation=interpretation,
        execution_mode=execution_mode,
        inferential_unit=cluster_by,
        cluster_by=cluster_by,
        baseline_arm=baseline,
        counterfactual_arm=counterfactual,
        planned_case_ids=cases,
        planned_cluster_ids=clusters,
        case_cluster_bindings=bindings,
        case_authority_bindings=tuple(
            RAGSensitivityCaseAuthorityBinding(
                case_id=case_id,
                query_family_id="shared-query-family",
                assignments=tuple(
                    sorted(
                        (
                            RAGSensitivityAuthorityAssignment(
                                corpus_digest=baseline.corpus_digest,
                                expected_decision=baseline.expected_recommendation,
                                expected_outcome=baseline.expected_outcome,
                                governing_source_id=f"source-{case_id}",
                                governing_ref_id=f"ref-{case_id}",
                                governing_content_digest=_digest(f"baseline-content-{case_id}"),
                                claim_id=f"claim-{case_id}",
                            ),
                            RAGSensitivityAuthorityAssignment(
                                corpus_digest=counterfactual.corpus_digest,
                                expected_decision=counterfactual.expected_recommendation,
                                expected_outcome=counterfactual.expected_outcome,
                                governing_source_id=f"source-{case_id}",
                                governing_ref_id=f"ref-{case_id}",
                                governing_content_digest=_digest(
                                    f"counterfactual-content-{case_id}"
                                ),
                                claim_id=f"claim-{case_id}",
                            ),
                        ),
                        key=lambda item: item.corpus_digest,
                    )
                ),
            )
            for case_id in cases
        ),
        repetitions_per_arm=1,
        planned_pairs=case_count,
        multiplicity_family="evidence-sensitivity",
        multiplicity_method=multiplicity_method,
        multiplicity_family_size=multiplicity_family_size,
        coupling=CouplingDescriptor(
            pairing_identity_verified=True,
            stochastic_dimensions=(
                "provider_sampling_randomness",
                "temporal_execution_order",
            ),
            shared=("case_identity",),
            intentionally_different=("governing_corpus_digest",),
            not_shared=(
                "provider_sampling_randomness",
                "temporal_execution_order",
            ),
            unknown=(),
            requested_provider_seed=True,
            classification="nominally_paired",
            variance_reduction_claim_permitted=False,
        ),
        design=design,
        allowed_exclusion_reasons=allowed_exclusion_reasons,
        limitations=("Scoped statistical protocol.",),
    )


def _source_runsets(
    protocol: RepeatedEvidenceSensitivityProtocol,
    *,
    observations: tuple[PairedSensitivityObservation, ...] | None = None,
    design_commitment: str | None = None,
) -> tuple[RunSetArtifactDependency, ...]:
    commitment = design_commitment or protocol.design_commitment_digest
    observations = observations or _observations(protocol)
    common = {
        "operational_protocol_id": "live-protocol",
        "operational_protocol_digest": _digest("live-protocol"),
        "evidence_sensitivity_design_digest": commitment,
    }
    dependencies: list[RunSetArtifactDependency] = []
    for arm_id, arm, id_field, digest_field in (
        (
            "baseline_evidence",
            protocol.baseline_arm,
            "baseline_run_id",
            "baseline_run_digest",
        ),
        (
            "counterfactual_evidence",
            protocol.counterfactual_arm,
            "counterfactual_run_id",
            "counterfactual_run_digest",
        ),
    ):
        records: list[RunRecordArtifactDependency] = []
        for observation in observations:
            run_id = getattr(observation, id_field)
            run_digest = getattr(observation, digest_field)
            if run_id is None:
                assert run_digest is None
                continue
            assert run_digest is not None
            records.append(
                RunRecordArtifactDependency(
                    case_id=observation.case_id,
                    repetition_index=observation.repetition_index,
                    run_id=run_id,
                    run_digest=run_digest,
                )
            )
        dependencies.append(
            RunSetArtifactDependency(
                arm_id=arm_id,
                runset_id=f"{arm_id}-runs",
                runset_digest=_digest(f"{arm_id}-runs"),
                execution_configuration_digest=arm.configuration_digest,
                completion_status=(
                    "complete" if len(records) == protocol.planned_pairs else "incomplete"
                ),
                stop_reasons=(
                    () if len(records) == protocol.planned_pairs else ("source-records-incomplete",)
                ),
                records=tuple(records),
                **common,
            )
        )
    return tuple(dependencies)


def _observations(
    protocol: RepeatedEvidenceSensitivityProtocol,
    *,
    zero_cases: frozenset[str] = frozenset(),
    dispositions: dict[str, tuple[str, str]] | None = None,
) -> tuple[PairedSensitivityObservation, ...]:
    dispositions = dispositions or {}
    cluster_by_case = {item.case_id: item.cluster_id for item in protocol.case_cluster_bindings}
    values: list[PairedSensitivityObservation] = []
    for case_id in protocol.planned_case_ids:
        disposition, reason = dispositions.get(case_id, ("included", ""))
        source = {
            "baseline_run_id": f"baseline-{case_id}",
            "baseline_run_digest": _digest(f"baseline-{case_id}"),
            "counterfactual_run_id": f"counterfactual-{case_id}",
            "counterfactual_run_digest": _digest(f"counterfactual-{case_id}"),
        }
        if disposition != "included":
            if disposition == "missing_counterfactual":
                partial_source = {
                    "baseline_run_id": source["baseline_run_id"],
                    "baseline_run_digest": source["baseline_run_digest"],
                }
            elif disposition == "missing_baseline":
                partial_source = {
                    "counterfactual_run_id": source["counterfactual_run_id"],
                    "counterfactual_run_digest": source["counterfactual_run_digest"],
                }
            elif disposition == "missing_both":
                partial_source = {}
            else:
                partial_source = source
            values.append(
                PairedSensitivityObservation(
                    case_id=case_id,
                    repetition_index=0,
                    cluster_id=cluster_by_case[case_id],
                    disposition=disposition,
                    disposition_reason=reason,
                    **partial_source,
                )
            )
            continue
        response = case_id not in zero_cases
        values.append(
            PairedSensitivityObservation(
                case_id=case_id,
                repetition_index=0,
                cluster_id=cluster_by_case[case_id],
                disposition="included",
                baseline_recommendation="approve",
                baseline_outcome="approved",
                counterfactual_recommendation="deny" if response else "approve",
                counterfactual_outcome="denied" if response else "approved",
                baseline_expected_recommendation=(protocol.baseline_arm.expected_recommendation),
                baseline_expected_outcome=protocol.baseline_arm.expected_outcome,
                counterfactual_expected_recommendation=(
                    protocol.counterfactual_arm.expected_recommendation
                ),
                counterfactual_expected_outcome=(protocol.counterfactual_arm.expected_outcome),
                endpoint_value=int(response),
                **source,
            )
        )
    return tuple(values)


def _evaluate(
    protocol: RepeatedEvidenceSensitivityProtocol,
    observations: tuple[PairedSensitivityObservation, ...] | None = None,
) -> StatisticalSufficiencyReport:
    observations = observations or _observations(protocol)
    return evaluate_statistical_sufficiency(
        protocol,
        observations,
        source_runsets=_source_runsets(protocol, observations=observations),
    )


def test_exact_power_reference_vector_uses_the_planned_composite_frame() -> None:
    plan = _plan()
    assert plan.analysis_method == "cluster_binary_exact"
    assert plan.confirmatory_cluster_frame == "all_frozen_planned_clusters"
    assert plan.non_analyzable_cluster_policy == "score_zero"
    assert plan.planned_inferential_clusters == 8
    assert plan.critical_cluster_responses == 7
    assert plan.achieved_type_i_error == "0.035157"
    assert plan.achieved_power == "0.813104"
    exclusion_policy = _plan(maximum_exclusion_rate="0.200000")
    assert exclusion_policy.planned_inferential_clusters == 8


def test_fixed_frame_recomputes_power_and_rejects_an_underpowered_n() -> None:
    with pytest.raises(
        ValueError,
        match=r"planned_inferential_clusters=10 does not meet desired_power",
    ):
        _plan(planned_inferential_clusters=10)

    fixed = _plan(planned_inferential_clusters=11)
    assert fixed.planned_inferential_clusters == 11
    assert fixed.critical_cluster_responses == 9
    assert fixed.achieved_type_i_error == "0.032715"
    assert fixed.achieved_power == "0.910438"


def test_bonferroni_plan_is_conservative_and_exactly_validated() -> None:
    plan = _plan(multiplicity_method="bonferroni", multiplicity_family_size=2)
    assert plan.adjusted_alpha == "0.025000"
    assert plan.achieved_type_i_error <= plan.adjusted_alpha
    protocol = _protocol(
        design=plan,
        case_count=plan.planned_inferential_clusters,
        multiplicity_method="bonferroni",
        multiplicity_family_size=2,
    )
    assert protocol.design == plan
    payload = plan.model_dump(mode="json")
    payload["achieved_power"] = "0.999999"
    with pytest.raises(ValidationError, match="derived values"):
        BinaryPairedDesignPlan.model_validate(payload)


def test_satisfied_exact_analysis_is_verdict_bearing_and_dependency_bound() -> None:
    sufficiency = _evaluate(_protocol())
    assert sufficiency.state.value == "satisfied"
    assert sufficiency.analyzable_clusters == 8
    assert sufficiency.analysis is not None
    assert sufficiency.analysis.method == "cluster_binomial_exact"
    assert sufficiency.analysis.exact_p_value is True
    assert sufficiency.analysis.confirmatory_cluster_frame == "all_frozen_planned_clusters"
    assert sufficiency.analysis.non_analyzable_cluster_policy == "score_zero"
    assert sufficiency.analysis.analyzable_clusters == 8
    assert sufficiency.analysis.non_analyzable_clusters_scored_zero == 0
    assert sufficiency.analysis.exact_p_value_expression.evaluate() == Decimal("0.00390625")
    assert sufficiency.analysis.p_value_upper_bound == "0.003907"
    report = build_stochastic_sensitivity_report(sufficiency)
    assert report.state.value == "pass"
    assert report.verdict_bearing
    assert report.observed_counterexample_count == 0
    assert report.estimated_response_rate == "1.000000"
    assert report.dependency is not None
    assert report.dependency.target_digest == sufficiency.report_digest


def test_every_pair_is_required_for_the_frozen_cluster_endpoint() -> None:
    protocol = _protocol(cluster_by_case=tuple(f"source-{index // 2:02d}" for index in range(16)))
    observations = _observations(
        protocol,
        zero_cases=frozenset({protocol.planned_case_ids[0]}),
    )
    assert derive_cluster_response_vector(protocol, observations) == (
        0,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
    )
    analysis = analyze_cluster_response(protocol, observations)
    assert analysis.compared_clusters == 8
    assert analysis.responding_clusters == 7
    assert analysis.included_pairs == 16
    assert analysis.exact_p_value_expression.evaluate() == Decimal("0.03515625")
    assert analysis.p_value_upper_bound == "0.035157"
    report = build_stochastic_sensitivity_report(_evaluate(protocol, observations))
    assert report.observed_counterexample_count == 1
    assert report.observed_cluster_response_count == 7
    assert report.estimated_response_rate == "0.875000"


def test_descriptive_cluster_vector_treats_missing_cells_as_non_analyzable() -> None:
    protocol = _protocol()
    observations = _observations(protocol)

    assert derive_cluster_response_vector(protocol, observations[:-1]) == (1,) * 7


def test_monte_carlo_diagnostic_is_reproducible_order_and_domain_bound() -> None:
    design = _plan(diagnostic_threshold=5, resamples=1_000)
    protocol = _protocol(protocol_id="study-a", design=design)
    observations = _observations(protocol)
    first = analyze_cluster_response(protocol, observations)
    reordered = analyze_cluster_response(protocol, tuple(reversed(observations)))
    assert first == reordered
    assert first.method == "cluster_binomial_exact_with_monte_carlo_diagnostic"
    assert first.exact_p_value is True
    assert first.exact_p_value_expression.evaluate() == Decimal("0.00390625")
    assert first.p_value_upper_bound == "0.003907"
    assert first.monte_carlo_seed is not None
    assert first.monte_carlo_resamples == 1_000
    assert first.monte_carlo_estimate is not None
    assert Decimal(first.monte_carlo_estimate) != first.exact_p_value_expression.evaluate()
    other_domain = _protocol(protocol_id="study-b", design=design)
    other = analyze_cluster_response(other_domain, _observations(other_domain))
    assert other.exact_p_value_expression == first.exact_p_value_expression
    assert other.monte_carlo_seed != first.monte_carlo_seed


def test_exclusions_above_declared_ceiling_are_inconclusive_and_never_pass() -> None:
    protocol = _protocol(allowed_exclusion_reasons=("planned-exclusion",))
    observations = _observations(
        protocol,
        dispositions={protocol.planned_case_ids[-1]: ("excluded_both", "planned-exclusion")},
    )
    sufficiency = _evaluate(protocol, observations)
    report = build_stochastic_sensitivity_report(sufficiency)
    assert sufficiency.included_pairs == 7
    assert sufficiency.analyzable_clusters == 7
    assert sufficiency.state.value == "inconclusive"
    assert report.state.value == "inconclusive"
    assert not report.verdict_bearing
    assert report.dependency is None


def test_allowed_exclusions_use_the_fixed_planned_cluster_denominator() -> None:
    design = _plan(maximum_exclusion_rate="0.250000")
    protocol = _protocol(
        design=design,
        allowed_exclusion_reasons=("planned-exclusion",),
    )
    excluded_cases = protocol.planned_case_ids[-2:]
    observations = _observations(
        protocol,
        dispositions={
            case_id: ("excluded_both", "planned-exclusion") for case_id in excluded_cases
        },
    )

    assert derive_cluster_response_vector(protocol, observations) == (1,) * 6
    assert derive_confirmatory_cluster_response_vector(
        protocol,
        observations,
    ) == (1,) * 6 + (0, 0)

    sufficiency = _evaluate(protocol, observations)
    assert sufficiency.state.value == "satisfied"
    assert sufficiency.analyzable_clusters == 6
    assert sufficiency.actual_clusters == 8
    assert sufficiency.analysis is not None
    assert sufficiency.analysis.compared_clusters == 8
    assert sufficiency.analysis.analyzable_clusters == 6
    assert sufficiency.analysis.non_analyzable_clusters_scored_zero == 2
    assert sufficiency.analysis.responding_clusters == 6
    assert sufficiency.analysis.planned_cluster_response_rate == "0.750000"
    assert sufficiency.analysis.planned_cluster_difference_from_null == "0.250000"
    assert sufficiency.analysis.exact_p_value_expression.evaluate() == Decimal("0.14453125")

    report = build_stochastic_sensitivity_report(sufficiency)
    assert report.state.value == "block"
    assert report.population_claim == (
        "expected_decision_response_cluster_rate_above_null_not_supported"
    )
    assert report.observed_cluster_count == 6
    assert report.observed_cluster_response_count == 6
    assert report.estimated_response_rate == "0.750000"


def test_complete_source_dependencies_must_cover_every_planned_cell() -> None:
    protocol = _protocol()
    observations = _observations(protocol)
    baseline, counterfactual = _source_runsets(protocol, observations=observations)
    incomplete_complete_arm = baseline.model_copy(update={"records": baseline.records[:-1]})

    with pytest.raises(ValidationError, match="source_runsets"):
        evaluate_statistical_sufficiency(
            protocol,
            observations,
            source_runsets=(incomplete_complete_arm, counterfactual),
        )


@pytest.mark.parametrize("malformation", ("unplanned", "duplicate"))
def test_evaluator_rejects_extra_or_duplicate_source_cells(malformation: str) -> None:
    protocol = _protocol()
    observations = _observations(protocol)
    baseline, counterfactual = _source_runsets(protocol, observations=observations)
    first = baseline.records[0]
    extra = RunRecordArtifactDependency(
        case_id=("unplanned-case" if malformation == "unplanned" else first.case_id),
        repetition_index=first.repetition_index,
        run_id=f"{malformation}-run",
        run_digest=_digest(f"{malformation}-run"),
    )
    records = tuple(
        sorted(
            (*baseline.records, extra),
            key=lambda item: (
                item.case_id,
                item.repetition_index,
                item.run_id,
                item.run_digest,
            ),
        )
    )
    malformed = baseline.model_copy(update={"records": records})

    with pytest.raises(ValidationError, match="source_runsets"):
        evaluate_statistical_sufficiency(
            protocol,
            observations,
            source_runsets=(malformed, counterfactual),
        )


def test_schema_rejects_unconsumed_source_records_even_with_digest_checks_bypassed() -> None:
    sufficiency = _evaluate(_protocol())
    baseline, counterfactual = sufficiency.source_runsets
    extra = RunRecordArtifactDependency(
        case_id="unplanned-case",
        repetition_index=0,
        run_id="unplanned-run",
        run_digest=_digest("unplanned-run"),
    )
    records = tuple(
        sorted(
            (*baseline.records, extra),
            key=lambda item: (
                item.case_id,
                item.repetition_index,
                item.run_id,
                item.run_digest,
            ),
        )
    )
    malformed = baseline.model_copy(update={"records": records})
    payload = sufficiency.model_dump(mode="json")
    payload["source_runsets"] = [
        malformed.model_dump(mode="json"),
        counterfactual.model_dump(mode="json"),
    ]

    with pytest.raises(ValidationError, match="source_runsets"):
        StatisticalSufficiencyReport.model_validate(
            payload,
            context={"skip_self_digest": True},
        )


def test_missing_and_incomplete_pair_manifests_cannot_pass() -> None:
    protocol = _protocol()
    observations = _observations(
        protocol,
        dispositions={
            protocol.planned_case_ids[-1]: (
                "missing_counterfactual",
                "counterfactual-pair-missing",
            )
        },
    )
    sufficiency = _evaluate(protocol, observations)
    report = build_stochastic_sensitivity_report(sufficiency)
    assert sufficiency.missing_pairs == 1
    assert sufficiency.state.value == "inconclusive"
    assert sufficiency.analysis is not None
    prerequisites = {item.check_id: item for item in sufficiency.prerequisites}
    assert prerequisites["missing_pair_policy"].state.value == "unmet"
    assert "independent_clusters" not in prerequisites
    assert "sample_size" not in prerequisites
    assert report.gate_effect.value == "non_verdict"
    assert report.dependency is None
    with pytest.raises(ValueError, match="exactly and uniquely cover"):
        _evaluate(protocol, observations[:-1])


@pytest.mark.parametrize(
    "disposition",
    ("identity_mismatch", "invalid_baseline", "invalid_counterfactual", "invalid_both"),
)
def test_structural_source_failure_is_prerequisites_unmet_never_pass(
    disposition: str,
) -> None:
    protocol = _protocol()
    observations = _observations(
        protocol,
        dispositions={protocol.planned_case_ids[0]: (disposition, "source-record-invalid")},
    )
    sufficiency = _evaluate(protocol, observations)
    report = build_stochastic_sensitivity_report(sufficiency)
    prerequisites = {item.check_id: item for item in sufficiency.prerequisites}
    assert sufficiency.state.value == "prerequisites_unmet"
    assert report.state.value == "prerequisites_unmet"
    assert not report.verdict_bearing
    assert report.dependency is None
    if disposition.startswith("invalid_"):
        assert prerequisites["record_validity"].state.value == "unmet"
        assert prerequisites["record_validity"].reason_code == "invalid-run-record"
        assert prerequisites["arm_configuration_comparability"].state.value == "satisfied"
    else:
        assert prerequisites["record_validity"].state.value == "satisfied"
        assert prerequisites["arm_configuration_comparability"].state.value == "unmet"


def test_deterministic_mode_bypasses_inference_and_population_estimation() -> None:
    protocol = _protocol(
        execution_mode="deterministic_fixture",
        interpretation="exploratory",
    )
    sufficiency = evaluate_statistical_sufficiency(protocol, _observations(protocol))
    report = build_stochastic_sensitivity_report(sufficiency)
    assert sufficiency.analysis is None
    assert not sufficiency.population_claim_permitted
    assert sufficiency.state.value == "inconclusive"
    assert report.observed_pair_count == 8
    assert report.estimated_response_rate is None
    assert report.population_claim == "none"
    assert report.dependency is None


def test_live_source_runsets_and_design_commitment_are_mandatory() -> None:
    protocol = _protocol()
    observations = _observations(protocol)
    unbound = evaluate_statistical_sufficiency(protocol, observations)
    assert unbound.state.value == "prerequisites_unmet"
    assert build_stochastic_sensitivity_report(unbound).state.value == ("prerequisites_unmet")
    with pytest.raises(ValidationError, match="source_runsets"):
        evaluate_statistical_sufficiency(
            protocol,
            observations,
            source_runsets=_source_runsets(
                protocol,
                observations=observations,
                design_commitment=_digest("post-hoc-design"),
            ),
        )


def test_embedded_analysis_forgery_is_rejected_by_exact_recomputation() -> None:
    sufficiency = _evaluate(_protocol())
    payload = sufficiency.model_dump(mode="json")
    assert isinstance(payload["analysis"], dict)
    assert isinstance(payload["analysis"]["exact_p_value_expression"], dict)
    payload["analysis"]["exact_p_value_expression"]["threshold"] = 1
    payload["analysis"]["p_value_upper_bound"] = "0.500000"
    with pytest.raises(ValidationError, match="p-value expression|analysis must exactly recompute"):
        StatisticalSufficiencyReport.model_validate(
            payload,
            context={"skip_self_digest": True},
        )


def test_tampered_final_dependency_is_rejected() -> None:
    report = build_stochastic_sensitivity_report(_evaluate(_protocol()))
    payload = report.model_dump(mode="json")
    assert isinstance(payload["dependency"], dict)
    payload["dependency"]["target_digest"] = _digest("forged-sufficiency")
    with pytest.raises(ValidationError, match="report_digest|dependency"):
        type(report).model_validate(payload)
