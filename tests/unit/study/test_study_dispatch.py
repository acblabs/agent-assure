from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest
from typer.testing import CliRunner

import agent_assure.study.analysis as study_analysis
import agent_assure.study_dispatch as study_dispatch
from agent_assure.authoring.compiler import compile_suite
from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.cli import rag_cmd as rag_cmd_module
from agent_assure.cli.main import app
from agent_assure.live.config import LiveAdapterConfig, LivePromptCase, LiveRunConfig
from agent_assure.rag import repeated_sensitivity as repeated_workflow
from agent_assure.rag.repeated_sensitivity import run_repeated_live_study
from agent_assure.schema.live import LiveProtocolRecord
from agent_assure.schema.run import RunSet
from agent_assure.schema.stochastic_sensitivity import RepeatedEvidenceSensitivityProtocol
from agent_assure.schema.study import (
    StudyRegistrationReviewReceipt,
    StudyStatisticalMethodReviewReceipt,
)
from agent_assure.schema.suite import CompiledSuite
from agent_assure.study_artifact_serialization import published_model_json_bytes
from agent_assure.study_dispatch import (
    StudyDispatchPreflightEvidence,
    ValidatedStudyDispatchPreflight,
    require_validated_study_dispatch_authorization,
    require_validated_study_dispatch_window_open,
    validate_study_dispatch_preflight,
)
from agent_assure.study_method_review import build_study_statistical_method_review_receipt
from tests.unit.study.test_real_model_study import StudyFixture, _fixture

RUNNER = CliRunner()


def _method_review(fixture: StudyFixture):  # type: ignore[no-untyped-def]
    return build_study_statistical_method_review_receipt(
        manifest=fixture.manifest,
        benchmark=fixture.benchmark,
        protocols=fixture.protocols,
        registration_record_bytes=fixture.registration_record_bytes,
        registration_review_receipt=fixture.registration_review_receipt,
        independence_audit_artifact_bytes=fixture.independence_audit_artifact_bytes,
        receipt_id="dispatch-statistical-method-review",
        reviewed_at_utc="2025-01-03T00:00:00Z",
        reviewer_pseudonym="independent-statistical-reviewer",
        reviewer_statistical_qualification_confirmed=True,
        reviewer_qualification_basis_types=("professional_statistical_practice",),
        reviewer_qualification_evidence_digest="0123456789abcdef" * 4,
        reviewer_qualification_basis=(
            "The reviewer has applied expertise in clustered binomial inference, "
            "multiplicity control, and prospective power analysis."
        ),
        reviewer_independent_of_design_execution_and_analysis=True,
        reviewer_independence_rationale=(
            "The reviewer did not design this benchmark, dispatch provider calls, "
            "select observations, or perform the final analysis."
        ),
        design_basis_reviewed_and_accepted=True,
        design_review_rationale=(
            "Independent inspection supports separate cluster construction within "
            "this bounded synthetic unit-test design."
        ),
        semantic_near_duplicate_audit_reviewed=True,
        semantic_near_duplicate_pseudoreplication_rejected=True,
        semantic_near_duplicate_review_rationale=(
            "The digest-bound comparison found no unhandled semantic duplicate "
            "counted as another cluster in this test fixture."
        ),
        benchmark_cluster_assignments_reviewed=True,
        independence_and_exchangeability_assumptions_reviewed=True,
        sampling_frame_and_estimand_reviewed=True,
        multiplicity_and_interval_method_reviewed=True,
        combined_directional_decision_error_control_reviewed=True,
        power_and_decision_boundary_reachability_reviewed=True,
        negative_control_design_reviewed=True,
    )


def _evidence(fixture: StudyFixture) -> StudyDispatchPreflightEvidence:
    return StudyDispatchPreflightEvidence(
        manifest_bytes=published_model_json_bytes(fixture.manifest),
        benchmark_bytes=published_model_json_bytes(fixture.benchmark),
        registration_record_bytes=fixture.registration_record_bytes,
        registration_review_receipt=fixture.registration_review_receipt,
        independence_audit_artifact_bytes=fixture.independence_audit_artifact_bytes,
        statistical_method_review_receipt=_method_review(fixture),
        protocols=fixture.protocols,
        registered_protocol_bytes={
            condition_id: published_model_json_bytes(protocol)
            for condition_id, protocol in fixture.protocols.items()
        },
    )


def _config(fixture: StudyFixture, condition_id: str, *, variant_id: str) -> LiveRunConfig:
    protocol = fixture.protocols[condition_id]
    return LiveRunConfig(
        variant_id=variant_id,
        pipeline_id="sensitivity-pipeline",
        execution_profile="preregistered_paired_study",
        tool_schema_digest="a" * 64,
        policy_bundle_digest="b" * 64,
        study_manifest_digest=fixture.manifest.manifest_digest,
        retrieval_corpus_dir="corpus",
        retrieval_corpus_digest=protocol.baseline_arm.corpus_digest,
        knowledge_contract_path="knowledge-contract.yaml",
        knowledge_contract_digest=protocol.baseline_arm.knowledge_contract_digest,
        evidence_sensitivity_design_digest=protocol.design_commitment_digest,
        fail_fast_on_excluded_response=True,
        adapter=LiveAdapterConfig(
            adapter_id="openai-chat-completions",
            provider="synthetic-provider",
            model="synthetic-model",
        ),
        cases=(
            LivePromptCase(
                case_id=protocol.planned_case_ids[0],
                prompt_path="case.txt",
                input_summary="synthetic request",
            ),
        ),
        max_requests=1,
        max_retries=0,
    )


def _arm_config(
    fixture: StudyFixture,
    condition_id: str,
    *,
    arm_id: str,
) -> LiveRunConfig:
    protocol = fixture.protocols[condition_id]
    arm = protocol.baseline_arm if arm_id == "baseline_evidence" else protocol.counterfactual_arm
    return LiveRunConfig(
        variant_id=arm_id,
        pipeline_id=arm.pipeline_id,
        execution_profile="preregistered_paired_study",
        tool_schema_digest=arm.tool_schema_digest,
        policy_bundle_digest=arm.policy_bundle_digest,
        study_manifest_digest=fixture.manifest.manifest_digest,
        retrieval_corpus_dir=f"{arm_id}-corpus",
        retrieval_corpus_digest=arm.corpus_digest,
        knowledge_contract_path="knowledge-contract.yaml",
        knowledge_contract_digest=arm.knowledge_contract_digest,
        evidence_sensitivity_design_digest=protocol.design_commitment_digest,
        fail_fast_on_excluded_response=True,
        adapter=LiveAdapterConfig(
            adapter_id="openai-chat-completions",
            provider=arm.provider,
            model=arm.requested_model,
        ),
        cases=tuple(
            LivePromptCase(
                case_id=case_id,
                prompt_path=f"{case_id}.txt",
                input_summary="synthetic request",
            )
            for case_id in protocol.planned_case_ids
        ),
        repetitions=protocol.repetitions_per_arm,
        max_requests=protocol.planned_pairs,
        max_retries=0,
    )


def _operational_protocol(compiled: CompiledSuite) -> LiveProtocolRecord:
    return LiveProtocolRecord(
        schema_version="0.6.6",
        protocol_id="study-dispatch-orchestration-test",
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=sha256_hexdigest(compiled.model_dump(mode="json")),
        non_inferiority_margin="0.050000",
        planned_observations=1,
        planned_clusters=1,
        planned_observations_per_cluster="1.000000",
        assumed_intraclass_correlation="0.200000",
        design_effect="1.000000",
        planned_effective_n="1.000000",
        sample_size_rationale="bounded study-dispatch regression",
        planned_repetitions=1,
        randomization_seed=0,
        max_requests=1,
        max_total_cost_usd="1.000000",
        max_cost_per_observation_usd="1.000000",
        exclusion_policy="fail closed on preregistered study execution failure",
        tool_schema_digest="7" * 64,
        policy_bundle_digest="8" * 64,
        analysis_digest="6" * 64,
        approved_data_boundary="synthetic unit-test inputs",
    )


def _run_to_preflight(
    *,
    fixture: StudyFixture,
    evidence: StudyDispatchPreflightEvidence | None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    dispatches: list[str],
    registered_protocol_bytes: bytes | None = None,
    protocol_override: RepeatedEvidenceSensitivityProtocol | None = None,
) -> None:
    condition_id = next(iter(fixture.protocols))
    protocol = protocol_override or fixture.protocols[condition_id]
    protocol_path = tmp_path / "registered-protocol.json"
    protocol_path.write_bytes(
        registered_protocol_bytes
        or (json.dumps(protocol.model_dump(mode="json"), indent=2, sort_keys=True) + "\n").encode(
            "utf-8"
        )
    )
    monkeypatch.setattr(
        study_analysis,
        "bind_study_manifest_to_live_config",
        lambda **values: values["config"],
    )

    def unexpected_dispatch(*args: object, **kwargs: object) -> RunSet:
        del args, kwargs
        dispatches.append("called")
        raise AssertionError("invalid study preflight reached provider execution")

    monkeypatch.setattr(repeated_workflow, "run_live_suite", unexpected_dispatch)
    run_repeated_live_study(
        compiled=cast(CompiledSuite, object()),
        protocol=protocol,
        baseline_config=_config(fixture, condition_id, variant_id="baseline"),
        counterfactual_config=_config(fixture, condition_id, variant_id="counterfactual"),
        operational_protocol=cast(LiveProtocolRecord, object()),
        baseline_config_dir=tmp_path,
        counterfactual_config_dir=tmp_path,
        registered_protocol_path=protocol_path,
        study_manifest=fixture.manifest,
        study_benchmark=fixture.benchmark,
        study_condition_id=condition_id,
        study_dispatch_evidence=evidence,
    )


def test_valid_dispatch_preflight_accepts_exact_reviewed_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(real_provider_execution=True)
    monkeypatch.setattr(
        study_dispatch,
        "_utc_now",
        lambda: datetime(2025, 2, 10, 12, tzinfo=UTC),
    )

    validate_study_dispatch_preflight(
        manifest=fixture.manifest,
        benchmark=fixture.benchmark,
        evidence=_evidence(fixture),
    )


def test_dispatch_proof_authorizes_only_registered_arms_and_rechecks_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(TypeError, match="issued only by dispatch preflight"):
        ValidatedStudyDispatchPreflight()

    fixture = _fixture(real_provider_execution=True)
    monkeypatch.setattr(
        study_dispatch,
        "_utc_now",
        lambda: datetime(2025, 2, 10, 12, tzinfo=UTC),
    )
    proof = validate_study_dispatch_preflight(
        manifest=fixture.manifest,
        benchmark=fixture.benchmark,
        evidence=_evidence(fixture),
    )
    condition = fixture.manifest.conditions[0]

    require_validated_study_dispatch_authorization(
        proof,
        study_manifest_digest=fixture.manifest.manifest_digest,
        evidence_sensitivity_design_digest=condition.design_commitment_digest,
        configuration_digest=condition.baseline_configuration_digest,
    )
    with pytest.raises(ValueError, match="does not authorize this design and configuration"):
        require_validated_study_dispatch_authorization(
            proof,
            study_manifest_digest=fixture.manifest.manifest_digest,
            evidence_sensitivity_design_digest=condition.design_commitment_digest,
            configuration_digest="f" * 64,
        )

    monkeypatch.setattr(
        study_dispatch,
        "_utc_now",
        lambda: datetime(2025, 3, 1, tzinfo=UTC),
    )
    with pytest.raises(ValueError, match="execution window is closed"):
        require_validated_study_dispatch_window_open(
            proof,
            boundary="test provider attempt",
        )


def test_dispatch_proof_never_authorizes_synthetic_condition_arms(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(real_provider_execution=False)
    monkeypatch.setattr(
        study_dispatch,
        "_utc_now",
        lambda: datetime(2025, 2, 10, 12, tzinfo=UTC),
    )
    proof = validate_study_dispatch_preflight(
        manifest=fixture.manifest,
        benchmark=fixture.benchmark,
        evidence=_evidence(fixture),
    )
    condition = fixture.manifest.conditions[0]

    with pytest.raises(ValueError, match="does not authorize this design and configuration"):
        require_validated_study_dispatch_authorization(
            proof,
            study_manifest_digest=fixture.manifest.manifest_digest,
            evidence_sensitivity_design_digest=condition.design_commitment_digest,
            configuration_digest=condition.baseline_configuration_digest,
        )


def test_missing_dispatch_evidence_fails_before_live_runner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(real_provider_execution=True)
    dispatches: list[str] = []

    with pytest.raises(ValueError, match="preflight evidence"):
        _run_to_preflight(
            fixture=fixture,
            evidence=None,
            tmp_path=tmp_path,
            monkeypatch=monkeypatch,
            dispatches=dispatches,
        )

    assert dispatches == []


def test_synthetic_condition_cannot_authorize_provider_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(real_provider_execution=False)
    values = fixture.protocol.model_dump(
        mode="python",
        exclude={"protocol_digest", "design_commitment_digest"},
    )
    values["execution_attempt_id"] = "unauthorized-provider-attempt"
    live_protocol = RepeatedEvidenceSensitivityProtocol.build(**values)
    dispatches: list[str] = []

    with pytest.raises(ValueError, match="preregistered as real_provider"):
        _run_to_preflight(
            fixture=fixture,
            evidence=_evidence(fixture),
            tmp_path=tmp_path,
            monkeypatch=monkeypatch,
            dispatches=dispatches,
            protocol_override=live_protocol,
        )

    assert dispatches == []


def test_alternate_active_protocol_serialization_fails_before_live_runner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(real_provider_execution=True)
    condition_id = next(iter(fixture.protocols))
    protocol = fixture.protocols[condition_id]
    alternate_bytes = json.dumps(
        protocol.model_dump(mode="json"),
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    dispatches: list[str] = []

    with pytest.raises(ValueError, match="active registered protocol bytes"):
        _run_to_preflight(
            fixture=fixture,
            evidence=_evidence(fixture),
            tmp_path=tmp_path,
            monkeypatch=monkeypatch,
            dispatches=dispatches,
            registered_protocol_bytes=alternate_bytes,
        )

    assert dispatches == []


@pytest.mark.parametrize(
    "tamper",
    (
        "audit",
        "registration-receipt",
        "protocol-bytes",
    ),
)
def test_tampered_dispatch_evidence_fails_before_live_runner(
    tamper: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(real_provider_execution=True)
    evidence = _evidence(fixture)
    if tamper == "audit":
        evidence = replace(evidence, independence_audit_artifact_bytes=b"changed audit")
    elif tamper == "registration-receipt":
        evidence = replace(
            evidence,
            registration_review_receipt=evidence.registration_review_receipt.model_copy(
                update={"reviewer_pseudonym": "substituted-reviewer"}
            ),
        )
    else:
        condition_id = next(iter(evidence.registered_protocol_bytes))
        evidence = replace(
            evidence,
            registered_protocol_bytes={
                **evidence.registered_protocol_bytes,
                condition_id: b"{}\n",
            },
        )
    dispatches: list[str] = []
    monkeypatch.setattr(
        study_dispatch,
        "_utc_now",
        lambda: datetime(2025, 2, 10, 12, tzinfo=UTC),
    )

    with pytest.raises(ValueError):
        _run_to_preflight(
            fixture=fixture,
            evidence=evidence,
            tmp_path=tmp_path,
            monkeypatch=monkeypatch,
            dispatches=dispatches,
        )

    assert dispatches == []


def test_method_review_before_registration_review_fails_before_live_runner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(real_provider_execution=True)
    receipt_values = fixture.registration_review_receipt.model_dump(
        mode="python",
        exclude={"review_receipt_digest"},
    )
    receipt_values["reviewed_at_utc"] = "2025-01-04T00:00:00Z"
    registration_review = StudyRegistrationReviewReceipt.build(**receipt_values)
    method_values = _method_review(fixture).model_dump(
        mode="python",
        exclude={"review_receipt_digest"},
    )
    method_values["registration_review_receipt_digest"] = registration_review.review_receipt_digest
    evidence = replace(
        _evidence(fixture),
        registration_review_receipt=registration_review,
        statistical_method_review_receipt=StudyStatisticalMethodReviewReceipt.build(
            **method_values
        ),
    )
    dispatches: list[str] = []
    monkeypatch.setattr(
        study_dispatch,
        "_utc_now",
        lambda: datetime(2025, 2, 10, 12, tzinfo=UTC),
    )

    with pytest.raises(ValueError, match="after registration review"):
        _run_to_preflight(
            fixture=fixture,
            evidence=evidence,
            tmp_path=tmp_path,
            monkeypatch=monkeypatch,
            dispatches=dispatches,
        )

    assert dispatches == []


@pytest.mark.parametrize(
    "observed_at",
    (
        datetime(2025, 1, 31, 23, 59, 59, tzinfo=UTC),
        datetime(2025, 3, 1, 0, 0, tzinfo=UTC),
        datetime(2025, 3, 2, 0, 0, tzinfo=UTC),
    ),
)
def test_outside_execution_window_fails_before_live_runner(
    observed_at: datetime,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(real_provider_execution=True)
    dispatches: list[str] = []
    monkeypatch.setattr(study_dispatch, "_utc_now", lambda: observed_at)

    with pytest.raises(ValueError, match="execution window"):
        _run_to_preflight(
            fixture=fixture,
            evidence=_evidence(fixture),
            tmp_path=tmp_path,
            monkeypatch=monkeypatch,
            dispatches=dispatches,
        )

    assert dispatches == []


def test_incomplete_study_baseline_abandons_attempt_before_counterfactual_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(real_provider_execution=True)
    condition_id = next(iter(fixture.protocols))
    protocol = fixture.protocols[condition_id]
    protocol_path = tmp_path / "registered-protocol.json"
    protocol_path.write_bytes(published_model_json_bytes(protocol))
    compiled = compile_suite(Path("examples/expense_approval_minimal/suite.yaml"))
    incomplete_baseline = fixture.evidence_by_condition[condition_id].baseline_runset.model_copy(
        update={
            "completion_status": "incomplete",
            "stop_reasons": ("live_adapter_error",),
        }
    )
    dispatches: list[str] = []

    monkeypatch.setattr(
        study_dispatch,
        "_utc_now",
        lambda: datetime(2025, 2, 10, 12, tzinfo=UTC),
    )
    monkeypatch.setattr(
        study_analysis,
        "bind_study_manifest_to_live_config",
        lambda **values: values["config"],
    )
    monkeypatch.setattr(
        repeated_workflow,
        "_validate_operational_protocol_binding",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        repeated_workflow,
        "prepare_live_execution_snapshot",
        lambda *_args, **_kwargs: object(),
    )
    monkeypatch.setattr(
        repeated_workflow,
        "validate_live_arm_prebinding",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        repeated_workflow,
        "_validate_live_pair_schedule",
        lambda *_args, **_kwargs: None,
    )

    def incomplete_dispatch(
        _compiled: CompiledSuite,
        config: LiveRunConfig,
        **_kwargs: object,
    ) -> RunSet:
        dispatches.append(config.variant_id)
        if config.variant_id != "baseline_evidence":
            raise AssertionError("counterfactual provider dispatch must not occur")
        return incomplete_baseline

    monkeypatch.setattr(repeated_workflow, "run_live_suite", incomplete_dispatch)

    with pytest.raises(ValueError, match="baseline live arm did not complete"):
        run_repeated_live_study(
            compiled=compiled,
            protocol=protocol,
            baseline_config=_arm_config(
                fixture,
                condition_id,
                arm_id="baseline_evidence",
            ),
            counterfactual_config=_arm_config(
                fixture,
                condition_id,
                arm_id="counterfactual_evidence",
            ),
            operational_protocol=_operational_protocol(compiled),
            baseline_config_dir=tmp_path,
            counterfactual_config_dir=tmp_path,
            registered_protocol_path=protocol_path,
            study_manifest=fixture.manifest,
            study_benchmark=fixture.benchmark,
            study_condition_id=condition_id,
            study_dispatch_evidence=_evidence(fixture),
        )

    journal_path = repeated_workflow.execution_attempt_journal_path(protocol_path, protocol)
    event_types = tuple(
        json.loads(line)["event_type"]
        for line in journal_path.read_text(encoding="utf-8").splitlines()
    )
    assert dispatches == ["baseline_evidence"]
    assert event_types == (
        "attempt_reserved",
        "arm_started",
        "attempt_abandoned",
    )


def test_repeated_run_cli_assembles_exact_full_study_preflight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(real_provider_execution=True)
    evidence = _evidence(fixture)
    condition_id = next(iter(fixture.protocols))
    protocol_paths: dict[str, Path] = {}
    for protocol_condition_id, protocol in fixture.protocols.items():
        path = tmp_path / f"{protocol_condition_id}.protocol.json"
        path.write_bytes(published_model_json_bytes(protocol))
        protocol_paths[protocol_condition_id] = path
    artifact_paths = {
        "manifest": tmp_path / "manifest.json",
        "benchmark": tmp_path / "benchmark.json",
        "registration": tmp_path / "registration.json",
        "registration_review": tmp_path / "registration-review.json",
        "audit": tmp_path / "independence-audit.md",
        "method_review": tmp_path / "method-review.json",
    }
    artifact_paths["manifest"].write_bytes(evidence.manifest_bytes)
    artifact_paths["benchmark"].write_bytes(evidence.benchmark_bytes)
    artifact_paths["registration"].write_bytes(evidence.registration_record_bytes)
    artifact_paths["registration_review"].write_bytes(
        published_model_json_bytes(evidence.registration_review_receipt)
    )
    artifact_paths["audit"].write_bytes(evidence.independence_audit_artifact_bytes)
    artifact_paths["method_review"].write_bytes(
        published_model_json_bytes(evidence.statistical_method_review_receipt)
    )
    base_paths = {
        name: tmp_path / f"{name}.json" for name in ("suite", "baseline", "counterfactual", "live")
    }
    for path in base_paths.values():
        path.write_text("{}\n", encoding="utf-8")
    baseline_config = _config(fixture, condition_id, variant_id="baseline")
    counterfactual_config = _config(fixture, condition_id, variant_id="counterfactual")
    captured: dict[str, object] = {}

    monkeypatch.setattr(rag_cmd_module, "load_compiled_suite", lambda _path: object())
    monkeypatch.setattr(
        rag_cmd_module,
        "load_live_run_config",
        lambda path: baseline_config if path == base_paths["baseline"] else counterfactual_config,
    )
    monkeypatch.setattr(rag_cmd_module, "_load_operational_live_protocol", lambda _path: object())
    monkeypatch.setattr(rag_cmd_module, "_confirm_trusted_live_config", lambda *_, **__: None)

    def capture_dispatch(**values: object) -> tuple[RunSet, RunSet]:
        captured.update(values)
        return (
            fixture.evidence.baseline_runset,
            fixture.evidence.counterfactual_runset,
        )

    monkeypatch.setattr(rag_cmd_module, "run_repeated_live_study", capture_dispatch)
    monkeypatch.setattr(
        rag_cmd_module,
        "write_repeated_run_artifacts",
        lambda **_values: {
            "baseline.runset.json": tmp_path / "baseline.runset.json",
            "counterfactual.runset.json": tmp_path / "counterfactual.runset.json",
        },
    )
    arguments = [
        "rag",
        "sensitivity",
        "run",
        "--protocol",
        str(protocol_paths[condition_id]),
        "--compiled-suite",
        str(base_paths["suite"]),
        "--baseline-config",
        str(base_paths["baseline"]),
        "--counterfactual-config",
        str(base_paths["counterfactual"]),
        "--live-protocol",
        str(base_paths["live"]),
        "--out",
        str(tmp_path / "run-output"),
        "--network-opt-in",
        "--study-manifest",
        str(artifact_paths["manifest"]),
        "--benchmark",
        str(artifact_paths["benchmark"]),
        "--study-condition-id",
        condition_id,
        "--study-registration-record",
        str(artifact_paths["registration"]),
        "--study-registration-review",
        str(artifact_paths["registration_review"]),
        "--study-independence-audit",
        str(artifact_paths["audit"]),
        "--study-statistical-method-review",
        str(artifact_paths["method_review"]),
    ]
    for other_condition_id, path in protocol_paths.items():
        if other_condition_id != condition_id:
            arguments.extend(("--study-protocol", f"{other_condition_id}={path}"))

    result = RUNNER.invoke(app, arguments)

    assert result.exit_code == 0, result.output
    assembled = captured["study_dispatch_evidence"]
    assert isinstance(assembled, StudyDispatchPreflightEvidence)
    assert assembled.manifest_bytes == evidence.manifest_bytes
    assert assembled.benchmark_bytes == evidence.benchmark_bytes
    assert assembled.registration_record_bytes == evidence.registration_record_bytes
    assert assembled.independence_audit_artifact_bytes == (
        evidence.independence_audit_artifact_bytes
    )
    assert assembled.registration_review_receipt == evidence.registration_review_receipt
    assert assembled.statistical_method_review_receipt == evidence.statistical_method_review_receipt
    assert assembled.protocols == evidence.protocols
    assert assembled.registered_protocol_bytes == evidence.registered_protocol_bytes


def test_repeated_run_cli_rejects_partial_study_preflight_without_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(real_provider_execution=True)
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_bytes(published_model_json_bytes(fixture.manifest))
    input_paths = {
        name: tmp_path / f"{name}.json"
        for name in ("protocol", "suite", "baseline", "counterfactual", "live")
    }
    for path in input_paths.values():
        path.write_text("{}\n", encoding="utf-8")
    dispatched = False
    monkeypatch.setattr(
        rag_cmd_module, "load_repeated_sensitivity_protocol", lambda _path: fixture.protocol
    )
    monkeypatch.setattr(rag_cmd_module, "load_compiled_suite", lambda _path: object())
    monkeypatch.setattr(rag_cmd_module, "load_live_run_config", lambda _path: object())
    monkeypatch.setattr(rag_cmd_module, "_load_operational_live_protocol", lambda _path: object())

    def unexpected_dispatch(**_values: object) -> tuple[RunSet, RunSet]:
        nonlocal dispatched
        dispatched = True
        raise AssertionError("partial study preflight reached dispatch")

    monkeypatch.setattr(rag_cmd_module, "run_repeated_live_study", unexpected_dispatch)
    result = RUNNER.invoke(
        app,
        [
            "rag",
            "sensitivity",
            "run",
            "--protocol",
            str(input_paths["protocol"]),
            "--compiled-suite",
            str(input_paths["suite"]),
            "--baseline-config",
            str(input_paths["baseline"]),
            "--counterfactual-config",
            str(input_paths["counterfactual"]),
            "--live-protocol",
            str(input_paths["live"]),
            "--out",
            str(tmp_path / "run-output"),
            "--network-opt-in",
            "--study-manifest",
            str(manifest_path),
            "--study-condition-id",
            fixture.manifest.conditions[0].condition_id,
        ],
    )

    assert result.exit_code == 2
    assert "requires the exact manifest, benchmark" in result.output
    assert dispatched is False
