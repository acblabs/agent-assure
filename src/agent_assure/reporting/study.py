"""Privacy-safe publication for preregistered real-model study evidence."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from pydantic import BaseModel

from agent_assure.io_limits import MAX_ARTIFACT_JSON_BYTES
from agent_assure.privacy.persistence import (
    UnsafePersistedTextError,
    assert_persisted_payload_safe,
    assert_persisted_text_safe,
)
from agent_assure.privacy.redaction import (
    assert_runset_payload_safe_for_persistence,
    redact_runset_payload,
)
from agent_assure.reporting.markdown_safety import markdown_code_span, markdown_text
from agent_assure.reporting.stochastic_sensitivity import (
    RepeatedSensitivityOutputConflictError,
    publish_generation,
)
from agent_assure.schema.benchmark import ProcessEquivalenceBenchmarkManifest
from agent_assure.schema.run import RunSet
from agent_assure.schema.stochastic_sensitivity import (
    RepeatedEvidenceSensitivityProtocol,
)
from agent_assure.schema.study import (
    RealModelStudyManifest,
    RealModelStudyReport,
    StudyExecutionReviewReceipt,
    StudyObservedExecutionProvenance,
    StudyRegistrationReviewReceipt,
    StudyStatisticalMethodReviewReceipt,
)
from agent_assure.study.analysis import StudyConditionEvidence, analyze_real_model_study
from agent_assure.study_artifact_serialization import published_model_json_bytes
from agent_assure.study_execution_review import validate_study_execution_review
from agent_assure.study_limits import (
    MAX_STUDY_BUNDLE_FILES,
    MAX_STUDY_BUNDLE_TOTAL_BYTES,
    MAX_STUDY_RUNSET_JSON_BYTES,
)
from agent_assure.study_method_review import validate_study_statistical_method_review
from agent_assure.study_registration import validate_study_registration


class StudyOutputConflictError(ValueError):
    """Raised when a destination contains another study generation."""


class StudyPrivacyError(ValueError):
    """Raised when study evidence is not safe to persist unchanged."""


_STUDY_MAX_OUTPUT_ENTRIES = MAX_STUDY_BUNDLE_FILES


def _study_artifact_byte_limit(name: str) -> int:
    return (
        MAX_STUDY_RUNSET_JSON_BYTES
        if name.endswith(".source.runset.json")
        else MAX_ARTIFACT_JSON_BYTES
    )


class _StudyArtifactSizeBudget:
    """Account exact publication bytes without retaining serialized artifacts."""

    def __init__(self, *, max_total_bytes: int | None = None) -> None:
        self.total_bytes = 0
        self.max_total_bytes = (
            MAX_STUDY_BUNDLE_TOTAL_BYTES if max_total_bytes is None else max_total_bytes
        )
        self._names: set[str] = set()

    def add_bytes(self, name: str, value: bytes) -> None:
        if name in self._names:
            raise ValueError("study publication contains a duplicate artifact name")
        encoded_size = len(value)
        if encoded_size > _study_artifact_byte_limit(name):
            raise ValueError(f"study publication artifact exceeds its byte limit: {name}")
        if self.total_bytes + encoded_size > self.max_total_bytes:
            raise ValueError("study publication exceeds the maximum supported aggregate size")
        self._names.add(name)
        self.total_bytes += encoded_size

    def add_model(self, name: str, value: BaseModel) -> None:
        self.add_bytes(name, published_model_json_bytes(value))

    def add_text(self, name: str, value: str) -> None:
        self.add_bytes(name, value.encode("utf-8"))


class _StudyArtifactAccumulator:
    """Retain publication text only while the complete generation stays bounded."""

    def __init__(self, *, max_total_bytes: int | None = None) -> None:
        self.texts: dict[str, str] = {}
        self.total_bytes = 0
        self.max_total_bytes = (
            MAX_STUDY_BUNDLE_TOTAL_BYTES if max_total_bytes is None else max_total_bytes
        )

    def add(self, name: str, value: str) -> None:
        if name in self.texts:
            raise ValueError("study publication contains a duplicate artifact name")
        encoded_size = len(value.encode("utf-8"))
        if encoded_size > _study_artifact_byte_limit(name):
            raise ValueError(f"study publication artifact exceeds its byte limit: {name}")
        if self.total_bytes + encoded_size > self.max_total_bytes:
            raise ValueError("study publication exceeds the maximum supported aggregate size")
        self.texts[name] = value
        self.total_bytes += encoded_size


def write_real_model_study_artifacts(
    *,
    manifest: RealModelStudyManifest,
    benchmark: ProcessEquivalenceBenchmarkManifest,
    protocols: Mapping[str, RepeatedEvidenceSensitivityProtocol],
    evidence: Mapping[str, StudyConditionEvidence | None],
    report: RealModelStudyReport,
    registration_record_bytes: bytes,
    registration_review_receipt: StudyRegistrationReviewReceipt,
    statistical_method_review_receipt: StudyStatisticalMethodReviewReceipt | None = None,
    execution_review_receipt: StudyExecutionReviewReceipt | None = None,
    out_dir: Path,
) -> dict[str, Path]:
    """Recompute and atomically publish one complete replayable study generation."""

    manifest = RealModelStudyManifest.model_validate(manifest.model_dump(mode="json"))
    benchmark = ProcessEquivalenceBenchmarkManifest.model_validate(
        benchmark.model_dump(mode="json")
    )
    report = RealModelStudyReport.model_validate(report.model_dump(mode="json"))
    try:
        registration = validate_study_registration(
            manifest=manifest,
            registration_record_bytes=registration_record_bytes,
            review_receipt=registration_review_receipt,
        )
    except UnsafePersistedTextError as exc:
        raise StudyPrivacyError(str(exc)) from exc
    expected_condition_ids = tuple(binding.condition_id for binding in manifest.conditions)
    if tuple(sorted(protocols)) != expected_condition_ids:
        raise ValueError("study protocols must exactly cover the frozen condition IDs")
    if tuple(sorted(evidence)) != expected_condition_ids:
        raise ValueError("study evidence must exactly cover the frozen condition IDs")
    validated_protocols = {
        condition_id: RepeatedEvidenceSensitivityProtocol.model_validate(
            protocol.model_dump(mode="json")
        )
        for condition_id, protocol in protocols.items()
    }
    _preflight_study_artifact_sizes(
        manifest=manifest,
        benchmark=benchmark,
        protocols=validated_protocols,
        evidence=evidence,
        report=report,
        registration_record_text=registration.record_text,
        registration_review_receipt=registration.review_receipt,
        statistical_method_review_receipt=statistical_method_review_receipt,
        execution_review_receipt=execution_review_receipt,
    )
    validated_evidence = {
        condition_id: _validated_condition_evidence(item) for condition_id, item in evidence.items()
    }
    recomputed = analyze_real_model_study(
        manifest=manifest,
        benchmark=benchmark,
        protocols=validated_protocols,
        evidence=validated_evidence,
    )
    if recomputed != report:
        raise ValueError(
            "study report does not exactly regenerate from the supplied privacy-safe evidence"
        )

    artifacts = _StudyArtifactAccumulator()
    artifacts.add("real-model-study-manifest.json", _safe_model_json_text(manifest))
    artifacts.add("process-equivalence-benchmark.json", _safe_model_json_text(benchmark))
    artifacts.add("study-registration-record.json", registration.record_text)
    artifacts.add(
        "study-registration-review.json",
        _safe_model_json_text(registration.review_receipt),
    )
    artifacts.add("real-model-study-report.json", _safe_model_json_text(report))
    artifacts.add("real-model-study-report.md", render_real_model_study_markdown(report))
    for index, binding in enumerate(manifest.conditions):
        prefix = f"condition-{index:03d}"
        registered_protocol = validated_protocols[binding.condition_id]
        artifacts.add(
            f"{prefix}.registered.protocol.json",
            _safe_model_json_text(registered_protocol),
        )
        condition_evidence = validated_evidence[binding.condition_id]
        if condition_evidence is None:
            continue
        artifacts.add(
            f"{prefix}.source.protocol.json",
            _safe_model_json_text(condition_evidence.protocol),
        )
        artifacts.add(
            f"{prefix}.baseline.source.runset.json",
            _safe_model_json_text(condition_evidence.baseline_runset),
        )
        artifacts.add(
            f"{prefix}.counterfactual.source.runset.json",
            _safe_model_json_text(condition_evidence.counterfactual_runset),
        )
        provenance = condition_evidence.observed_execution_provenance
        if provenance is not None:
            artifacts.add(
                f"{prefix}.observed-execution-provenance.json",
                _safe_model_json_text(provenance),
            )

    texts = artifacts.texts

    if statistical_method_review_receipt is not None:
        validated_method_review = validate_study_statistical_method_review(
            manifest=manifest,
            benchmark=benchmark,
            protocols=validated_protocols,
            review_receipt=statistical_method_review_receipt,
            manifest_bytes=texts["real-model-study-manifest.json"].encode("utf-8"),
            benchmark_bytes=texts["process-equivalence-benchmark.json"].encode("utf-8"),
            registered_protocol_bytes={
                binding.condition_id: texts[
                    f"condition-{index:03d}.registered.protocol.json"
                ].encode("utf-8")
                for index, binding in enumerate(manifest.conditions)
            },
        )
        artifacts.add(
            "study-statistical-method-review.json",
            _safe_model_json_text(validated_method_review.receipt),
        )

    if execution_review_receipt is not None:
        if any(validated_evidence[binding.condition_id] is None for binding in manifest.conditions):
            raise ValueError("study execution review requires source evidence for every condition")
        validated_execution_review = validate_study_execution_review(
            manifest=manifest,
            benchmark=benchmark,
            protocols=validated_protocols,
            report=report,
            evidence=validated_evidence,
            review_receipt=execution_review_receipt,
            manifest_bytes=texts["real-model-study-manifest.json"].encode("utf-8"),
            report_bytes=texts["real-model-study-report.json"].encode("utf-8"),
            baseline_runset_bytes={
                binding.condition_id: texts[
                    f"condition-{index:03d}.baseline.source.runset.json"
                ].encode("utf-8")
                for index, binding in enumerate(manifest.conditions)
            },
            counterfactual_runset_bytes={
                binding.condition_id: texts[
                    f"condition-{index:03d}.counterfactual.source.runset.json"
                ].encode("utf-8")
                for index, binding in enumerate(manifest.conditions)
            },
        )
        artifacts.add(
            "study-execution-review.json",
            _safe_model_json_text(validated_execution_review.receipt),
        )

    if len(texts) > _STUDY_MAX_OUTPUT_ENTRIES:
        raise ValueError("study publication inventory exceeds the supported condition bound")
    _assert_text_safe(texts["real-model-study-report.md"])
    try:
        runset_byte_limits = {
            name: MAX_STUDY_RUNSET_JSON_BYTES
            for name in texts
            if name.endswith(".source.runset.json")
        }
        return publish_generation(
            out_dir,
            texts,
            expected_filenames=tuple(texts),
            max_output_entries=_STUDY_MAX_OUTPUT_ENTRIES,
            artifact_max_bytes=runset_byte_limits,
        )
    except RepeatedSensitivityOutputConflictError as exc:
        raise StudyOutputConflictError(
            "destination contains a different or incomplete study generation"
        ) from exc


def _preflight_study_artifact_sizes(
    *,
    manifest: RealModelStudyManifest,
    benchmark: ProcessEquivalenceBenchmarkManifest,
    protocols: Mapping[str, RepeatedEvidenceSensitivityProtocol],
    evidence: Mapping[str, StudyConditionEvidence | None],
    report: RealModelStudyReport,
    registration_record_text: str,
    registration_review_receipt: StudyRegistrationReviewReceipt,
    statistical_method_review_receipt: StudyStatisticalMethodReviewReceipt | None,
    execution_review_receipt: StudyExecutionReviewReceipt | None,
) -> None:
    """Reject oversized generations before copying or reanalyzing source RunSets."""

    budget = _StudyArtifactSizeBudget()
    budget.add_model("real-model-study-manifest.json", manifest)
    budget.add_model("process-equivalence-benchmark.json", benchmark)
    budget.add_text("study-registration-record.json", registration_record_text)
    budget.add_model("study-registration-review.json", registration_review_receipt)
    budget.add_model("real-model-study-report.json", report)
    budget.add_text("real-model-study-report.md", render_real_model_study_markdown(report))
    for index, binding in enumerate(manifest.conditions):
        prefix = f"condition-{index:03d}"
        budget.add_model(
            f"{prefix}.registered.protocol.json",
            protocols[binding.condition_id],
        )
        condition_evidence = evidence[binding.condition_id]
        if condition_evidence is None:
            continue
        budget.add_model(
            f"{prefix}.source.protocol.json",
            condition_evidence.protocol,
        )
        budget.add_model(
            f"{prefix}.baseline.source.runset.json",
            condition_evidence.baseline_runset,
        )
        budget.add_model(
            f"{prefix}.counterfactual.source.runset.json",
            condition_evidence.counterfactual_runset,
        )
        if condition_evidence.observed_execution_provenance is not None:
            budget.add_model(
                f"{prefix}.observed-execution-provenance.json",
                condition_evidence.observed_execution_provenance,
            )
    if statistical_method_review_receipt is not None:
        budget.add_model(
            "study-statistical-method-review.json",
            statistical_method_review_receipt,
        )
    if execution_review_receipt is not None:
        budget.add_model("study-execution-review.json", execution_review_receipt)


def render_real_model_study_markdown(report: RealModelStudyReport) -> str:
    """Render the bounded structured result without exposing raw model content."""

    registration = report.manifest.registration
    rule = report.manifest.hypothesis_decision_rule
    inferential_statistics_applicable = report.inferential_statistics_applicable
    lines = [
        "# Real-model study report",
        "",
        f"- Study: {markdown_code_span(report.manifest.study_id)}",
        f"- Report digest: {markdown_code_span(report.report_digest)}",
        f"- Manifest digest: {markdown_code_span(report.manifest_digest)}",
        f"- Benchmark digest: {markdown_code_span(report.benchmark_digest)}",
        f"- Protocol-set digest: {markdown_code_span(report.protocol_set_digest)}",
        (
            "- Hypothesis-decision-rule digest: "
            f"{markdown_code_span(report.hypothesis_decision_rule_digest)}"
        ),
        (
            "- Hypothesis classification: "
            f"{markdown_code_span(report.hypothesis_classification.value)}"
        ),
        (f"- Inference scope: {markdown_code_span(rule.inference_scope.value)}"),
        (f"- Inferential statistics applicable: {str(inferential_statistics_applicable).lower()}"),
        f"- Protocol valid: {str(report.protocol_valid).lower()}",
        (
            (
                "- Statistical sufficiency satisfied: "
                if inferential_statistics_applicable
                else "- Frame completeness satisfied: "
            )
            + f"{str(report.statistical_sufficiency_satisfied).lower()}"
        ),
        (
            "- Invariant negative controls satisfied: "
            f"{str(report.invariant_controls_satisfied).lower()}"
        ),
        (
            "- Confirmatory conclusion permitted: "
            f"{str(report.confirmatory_conclusion_permitted).lower()}"
        ),
        (f"- Standalone report publication eligible: {str(report.publication_eligible).lower()}"),
        (
            "- Registration evidence verified by this report: "
            f"{str(report.registration_evidence_verified).lower()}"
        ),
        (
            "- Registration verification required: "
            f"{markdown_code_span(report.registration_evidence_verification)}"
        ),
        (
            "Publication eligibility is derived separately by the closed-bundle "
            "verifier after exact registration-record and review-receipt validation."
        ),
        "",
        "The result is scoped to the frozen tasks, authority contracts, provider/model "
        "identities, configurations, protocols, and execution window. It is not a "
        "provider-wide, causal, safety, or compliance claim.",
        *(
            (
                "This study is explicitly downscoped to fixed-frame descriptive "
                "conformance. Rates describe only the committed frame; hypothesis "
                "classification and independent-cluster inference are prohibited.",
            )
            if rule.inference_scope.value == "fixed_frame_descriptive_conformance"
            else ()
        ),
        (
            "The primary inertia endpoint is a direct same-decision measure on "
            "decision-flip conditions. A contradicted inertia hypothesis can include "
            "wrong-direction arm changes and therefore does not, by itself, establish "
            "expected evidence responsiveness."
        ),
        (
            "The descriptive baseline-correct inertia split means agreement with the "
            "preregistered baseline expected recommendation and outcome only; it is "
            "not an external, clinical, or policy-truth determination."
        ),
        "",
        "## Preregistration and decision rule",
        "",
        f"- Registration method: {markdown_code_span(registration.method.value)}",
        f"- Registration reference: {markdown_code_span(registration.reference_id)}",
        (f"- Registration evidence digest: {markdown_code_span(registration.evidence_digest)}"),
        f"- Registered at: {markdown_code_span(registration.registered_at_utc)}",
        (
            "- Planned execution window: "
            f"{markdown_code_span(report.manifest.execution_window.start)} to "
            f"{markdown_code_span(report.manifest.execution_window.end)}"
        ),
        f"- Estimand: {markdown_code_span(rule.estimand)}",
        f"- Derivation: {markdown_code_span(rule.derivation)}",
        (
            "- Inertia target conditions: "
            + ", ".join(markdown_code_span(item) for item in rule.target_task_model_conditions)
        ),
        (
            "- Invariant negative-control conditions: "
            + ", ".join(markdown_code_span(item) for item in rule.negative_control_conditions)
        ),
        f"- Invariant control gate: {markdown_code_span(rule.invariant_control_gate)}",
        *(
            (
                f"- Inferential unit: {markdown_code_span(rule.inferential_unit)}",
                (f"- Materiality threshold: {markdown_code_span(rule.materiality_threshold)}"),
                f"- Familywise alpha: {markdown_code_span(rule.familywise_alpha)}",
                (
                    "- Directional error control: "
                    f"{markdown_code_span(rule.directional_error_control)}. Support and "
                    "contradiction are each FWER-controlled over target conditions; the "
                    "combined rule is not a single joint two-sided-alpha guarantee."
                ),
                (
                    "- Multiplicity / interval: "
                    f"{markdown_code_span(rule.multiplicity_method)} / "
                    f"{markdown_code_span(rule.interval_method)}"
                ),
                (
                    "- Minimum independent clusters: "
                    f"{markdown_code_span(str(rule.minimum_independent_clusters))}"
                ),
                (
                    "- Independence justification status: "
                    f"{markdown_code_span(rule.independence_justification.status.value)}"
                ),
                (
                    "- Independence software-verification scope: "
                    f"{markdown_code_span(rule.independence_justification.software_verification_scope)}"
                ),
            )
            if inferential_statistics_applicable
            else (
                "- Inferential decision rule: inactive for fixed-frame descriptive scope",
                (
                    "- Frame-dependence status: "
                    f"{markdown_code_span(rule.independence_justification.status.value)}"
                ),
                (
                    "- Scope limitation: rates and counts apply only to the exact "
                    "committed frame; no interval or population-generalization claim "
                    "is rendered."
                ),
            )
        ),
        "",
        "## Conditions",
        "",
    ]
    for result, binding in zip(
        report.conditions,
        report.manifest.conditions,
        strict=True,
    ):
        lines.extend(
            [
                f"### {markdown_text(result.condition_id)}",
                "",
                f"- State: {markdown_code_span(result.state.value)}",
                f"- Provider: {markdown_code_span(binding.provider)}",
                f"- Requested model: {markdown_code_span(binding.requested_model)}",
                (
                    "- Expected resolved model: "
                    f"{markdown_code_span(binding.expected_resolved_model)}"
                ),
                (
                    "- Provider API / SDK / region: "
                    f"{markdown_code_span(binding.provider_api_version or 'not-declared')} / "
                    f"{markdown_code_span(binding.provider_sdk or 'not-declared')} / "
                    f"{markdown_code_span(binding.provider_region or 'not-declared')}"
                ),
                (
                    "- Adapter / pipeline: "
                    f"{markdown_code_span(binding.adapter_id)} / "
                    f"{markdown_code_span(binding.pipeline_id)}"
                ),
                (
                    "- Model-matched target/control serving-fingerprint policy: "
                    f"{markdown_code_span(binding.provider_serving_fingerprint_policy)}"
                ),
                (
                    "- Baseline configuration digest: "
                    f"{markdown_code_span(binding.baseline_configuration_digest)}"
                ),
                (
                    "- Counterfactual configuration digest: "
                    f"{markdown_code_span(binding.counterfactual_configuration_digest)}"
                ),
                (
                    "- Protocol / design commitment digests: "
                    f"{markdown_code_span(result.protocol_digest)} / "
                    f"{markdown_code_span(result.design_commitment_digest)}"
                ),
                (
                    "- Pairs (planned/actual/included/missing/excluded/invalid): "
                    f"{binding.planned_pairs}/{result.actual_pairs}/"
                    f"{result.included_pairs}/{result.missing_pairs}/"
                    f"{result.excluded_pairs}/{result.invalid_pairs}"
                ),
                (
                    (
                        "- Clusters (planned/analyzable): "
                        if inferential_statistics_applicable
                        else "- Frame clusters (committed/complete): "
                    )
                    + f"{result.planned_clusters}/{result.analyzable_clusters}"
                ),
                (
                    f"- Coupling: {markdown_code_span(result.coupling.classification.value)}"
                    if result.coupling is not None
                    else "- Coupling: not available"
                ),
            ]
        )
        if result.observed_execution_window is not None:
            lines.append(
                "- Observed execution window: "
                f"{markdown_code_span(result.observed_execution_window.start)} to "
                f"{markdown_code_span(result.observed_execution_window.end)}"
            )
        if result.observed_execution_provenance is not None:
            provenance = result.observed_execution_provenance
            fingerprint_digest_label = markdown_code_span(
                provenance.provider_serving_fingerprint_set_digest or "not-reported"
            )
            lines.extend(
                [
                    (
                        "- Declared / observed execution origin: "
                        f"{markdown_code_span(provenance.declared_origin.value)} / "
                        f"{markdown_code_span(provenance.observed_origin.value)}"
                    ),
                    (
                        "- Observed execution provenance digest: "
                        f"{markdown_code_span(provenance.provenance_digest)}"
                    ),
                    (
                        "- Provider dispatch metadata coverage "
                        "(records / response IDs / distinct response IDs): "
                        f"{provenance.run_records}/"
                        f"{provenance.provider_response_id_records}/"
                        f"{provenance.distinct_provider_response_ids}"
                    ),
                    (
                        "- Provider serving-fingerprint coverage "
                        "(records / distinct values / set digest): "
                        f"{provenance.provider_serving_fingerprint_records}/"
                        f"{provenance.distinct_provider_serving_fingerprints}/"
                        f"{fingerprint_digest_label}"
                    ),
                    (
                        "- Provider serving-fingerprint policy: "
                        f"{markdown_code_span(provenance.provider_serving_fingerprint_policy)}. "
                        "A stable reported value detects within-condition drift; it is "
                        "provider metadata, not proof of immutable serving infrastructure."
                    ),
                ]
            )
        if result.observed_model_identities:
            lines.append("- Observed model identities:")
            for identity in result.observed_model_identities:
                lines.append(
                    "  - "
                    f"{markdown_code_span(identity.provider)} / "
                    f"{markdown_code_span(identity.requested_model)} / "
                    f"{markdown_code_span(identity.resolved_model or 'not-reported')} / "
                    f"{markdown_code_span(identity.adapter_id)} / "
                    f"{markdown_code_span(identity.pipeline_id)} / serving fingerprint "
                    f"{markdown_code_span(identity.provider_serving_fingerprint or 'not-reported')}"
                )
        if result.coupling is not None:
            coupling = result.coupling
            lines.extend(
                [
                    (
                        "- Pairing identity verified: "
                        f"{str(coupling.pairing_identity_verified).lower()}"
                    ),
                    (
                        "- Coupling dimensions (shared / intentionally different / "
                        "not shared / unknown): "
                        f"{_enum_values(coupling.shared)} / "
                        f"{_enum_values(coupling.intentionally_different)} / "
                        f"{_enum_values(coupling.not_shared)} / "
                        f"{_enum_values(coupling.unknown)}"
                    ),
                    (
                        "- Variance-reduction claim permitted: "
                        f"{str(coupling.variance_reduction_claim_permitted).lower()}"
                    ),
                ]
            )
        if result.sufficiency_report is not None:
            lines.append(
                (
                    "- Statistical sufficiency state: "
                    if inferential_statistics_applicable
                    else "- Frame completeness state: "
                )
                + f"{markdown_code_span(result.sufficiency_report.state.value)}"
            )
        if result.expected_response_diagnostic is not None:
            diagnostic = result.expected_response_diagnostic
            polarity_explanation = (
                "the replayed Sprint 6 expected-response endpoint is an inverse "
                "signal for direct same-decision inertia."
                if diagnostic.polarity_relative_to_sprint7_hypothesis
                == "inverse_signal_for_direct_same_decision_inertia"
                else (
                    "the inertia estimand is not applicable to this condition; "
                    "expected stability aligns with the invariant-control role, "
                    "whose exact zero-change gate remains authoritative."
                )
            )
            lines.extend(
                [
                    (
                        "- Expected-response diagnostic state (non-hypothesis): "
                        f"{markdown_code_span(diagnostic.diagnostic_state)}"
                    ),
                    (
                        "- Sprint 7 hypothesis effect: "
                        f"{markdown_code_span(diagnostic.sprint7_hypothesis_effect)}; "
                        f"{polarity_explanation}"
                    ),
                ]
            )
        if result.decision_inertia_rate is not None:
            interval = result.decision_inertia_interval
            breakdown = result.decision_inertia_descriptive_breakdown
            assert interval is not None
            assert breakdown is not None
            lines.extend(
                [
                    (
                        "- Decision clusters "
                        "(expected response / direct inertia / wrong direction / "
                        "other non-inertia): "
                        f"{result.decision_response_cluster_count}/"
                        f"{result.decision_inertia_cluster_count}/"
                        f"{result.decision_wrong_direction_cluster_count}/"
                        f"{result.decision_other_non_inertia_cluster_count}"
                    ),
                    (
                        "- Decision response rate: "
                        f"{markdown_code_span(result.decision_response_rate or '')}"
                    ),
                    (
                        "- Decision inertia rate: "
                        f"{markdown_code_span(result.decision_inertia_rate)}"
                    ),
                    (
                        "- Descriptive same-decision inertia split "
                        "(baseline-correct / baseline-incorrect / mixed baseline "
                        "correctness; denominator = frozen planned clusters): "
                        f"{breakdown.baseline_correct_same_decision_cluster_count}/"
                        f"{breakdown.baseline_incorrect_same_decision_cluster_count}/"
                        f"{breakdown.mixed_baseline_correctness_same_decision_cluster_count}; "
                        f"{markdown_code_span(breakdown.baseline_correct_same_decision_rate)}/"
                        f"{markdown_code_span(breakdown.baseline_incorrect_same_decision_rate)}/"
                        f"{markdown_code_span(breakdown.mixed_baseline_correctness_same_decision_rate)}"
                    ),
                    (
                        "- Baseline-correct definition: matches the preregistered "
                        "baseline expected recommendation and outcome; descriptive "
                        "only, not external truth."
                    ),
                    *(
                        (
                            "- Adjusted one-sided inertia interval: "
                            f"[{markdown_code_span(interval.lower_bound)}, "
                            f"{markdown_code_span(interval.upper_bound)}]",
                        )
                        if inferential_statistics_applicable
                        else ()
                    ),
                ]
            )
        if result.control_unexpected_change_rate is not None:
            interval = result.control_unexpected_change_interval
            assert interval is not None
            lines.extend(
                [
                    (
                        "- Invariant control stability clusters: "
                        f"{result.control_expected_stability_cluster_count}"
                    ),
                    (
                        "- Invariant control unexpected-change rate: "
                        f"{markdown_code_span(result.control_unexpected_change_rate)}"
                    ),
                    *(
                        (
                            "- Adjusted one-sided unexpected-change interval: "
                            f"[{markdown_code_span(interval.lower_bound)}, "
                            f"{markdown_code_span(interval.upper_bound)}]",
                        )
                        if inferential_statistics_applicable
                        else ()
                    ),
                    (
                        "- Invariant control gate: "
                        + (
                            "satisfied"
                            if result.control_unexpected_change_cluster_count == 0
                            else "blocked by observed arm-to-arm change"
                        )
                    ),
                ]
            )
        if result.deviation_codes:
            lines.append(
                "- Deviations: "
                + ", ".join(markdown_code_span(item) for item in result.deviation_codes)
            )
        if result.failure_summaries:
            lines.append("- Failure summaries:")
            for failure in result.failure_summaries:
                examples = (
                    ", ".join(markdown_code_span(item) for item in failure.example_case_ids)
                    or "none"
                )
                lines.append(
                    "  - "
                    f"{markdown_code_span(failure.reason_code)}: {failure.count}; "
                    f"example case IDs: {examples}"
                )
        operational = result.operational_summary
        lines.append(
            "- Operational records (runs / cost reported / latency reported): "
            f"{operational.run_records}/{operational.cost_reported_records}/"
            f"{operational.latency_reported_records}"
        )
        cost = operational.total_estimated_cost_microusd
        lines.append(
            "- Estimated cost: "
            + (
                f"{markdown_code_span(str(cost))} micro-USD"
                if cost is not None
                else "not completely reported"
            )
        )
        if operational.total_latency_ms is None:
            lines.append("- Latency summary: not reported")
        else:
            lines.append(
                "- Latency (total/minimum/maximum): "
                f"{operational.total_latency_ms}/{operational.minimum_latency_ms}/"
                f"{operational.maximum_latency_ms} ms"
            )
        lines.extend(
            [
                "",
            ]
        )

    if report.deviations:
        lines.extend(
            [
                "## Study-level deviations",
                "",
                *[f"- {markdown_code_span(item)}" for item in report.deviations],
                "",
            ]
        )
    lines.extend(["## Limitations", ""])
    lines.extend(f"- {markdown_text(item)}" for item in report.limitations)
    lines.extend(
        [
            "",
            "## Drift boundary",
            "",
            markdown_text(report.drift_boundary),
            "",
        ]
    )
    rendered = "\n".join(lines)
    _assert_text_safe(rendered)
    return rendered


def _enum_values(values: tuple[object, ...]) -> str:
    if not values:
        return "none"
    return ", ".join(markdown_code_span(getattr(item, "value", str(item))) for item in values)


def _validated_condition_evidence(
    value: StudyConditionEvidence | None,
) -> StudyConditionEvidence | None:
    if value is None:
        return None
    return StudyConditionEvidence(
        protocol=RepeatedEvidenceSensitivityProtocol.model_validate(
            value.protocol.model_dump(mode="json")
        ),
        baseline_runset=_unchanged_safe_runset(value.baseline_runset),
        counterfactual_runset=_unchanged_safe_runset(value.counterfactual_runset),
        observed_execution_provenance=(
            StudyObservedExecutionProvenance.model_validate(
                value.observed_execution_provenance.model_dump(mode="json")
            )
            if value.observed_execution_provenance is not None
            else None
        ),
    )


def _unchanged_safe_runset(value: RunSet) -> RunSet:
    runset = RunSet.model_validate(value.model_dump(mode="json"))
    original = runset.model_dump(mode="json", warnings="error")
    _assert_no_persisted_credentials(original, owner="study source RunSet")
    filtered = redact_runset_payload(original)
    assert_runset_payload_safe_for_persistence(filtered)
    if filtered != original:
        raise StudyPrivacyError(
            "study source RunSets must already be privacy-filtered because "
            "redaction would invalidate their cryptographic dependencies"
        )
    return runset


def _safe_model_json_text(model: BaseModel) -> str:
    payload = model.model_dump(mode="json", warnings="error")
    _assert_persisted_payload_safe(payload, owner="study evidence")
    return published_model_json_bytes(model).decode("utf-8")


def _assert_text_safe(value: str) -> None:
    _assert_persisted_payload_safe(
        {"content": value},
        owner="rendered study evidence",
    )


def _assert_persisted_payload_safe(value: object, *, owner: str) -> None:
    try:
        assert_persisted_payload_safe(value, owner=owner)
    except UnsafePersistedTextError as exc:
        raise StudyPrivacyError(str(exc)) from exc


def _assert_no_persisted_credentials(
    value: object,
    *,
    owner: str,
    field_name: str | None = None,
) -> None:
    try:
        assert_persisted_text_safe(
            value,
            owner=owner,
            field_name=field_name,
        )
    except UnsafePersistedTextError as exc:
        raise StudyPrivacyError(str(exc)) from exc


__all__ = [
    "StudyOutputConflictError",
    "StudyPrivacyError",
    "render_real_model_study_markdown",
    "write_real_model_study_artifacts",
]
