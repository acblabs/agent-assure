from __future__ import annotations

import json
import os
import stat
import threading
from hashlib import sha256
from pathlib import Path
from typing import Literal

import pytest
from click import unstyle
from typer.testing import CliRunner

from agent_assure.cli import rag_cmd as rag_cmd_module
from agent_assure.cli.main import app
from agent_assure.live.config import (
    LiveAdapterConfig,
    LivePromptCase,
    LiveRunConfig,
    LiveScriptEnvVar,
    load_live_run_config,
)
from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.rag.sensitivity import SensitivityInputError
from agent_assure.rag.sensitivity_statistics import plan_binary_paired_design
from agent_assure.release_evidence import build_digest_replay, verify_digest_replay
from agent_assure.reporting.stochastic_sensitivity import (
    REPEATED_ANALYSIS_OUTPUT_FILENAMES,
)
from agent_assure.rooted_io import RootedDirectoryDescriptor
from agent_assure.schema.common import ExecutionMode
from agent_assure.schema.provenance import Provenance
from agent_assure.schema.run import AgentRunRecord, RunSet
from agent_assure.schema.sensitivity import (
    RAGSensitivityAuthorityAssignment,
    RAGSensitivityCaseAuthorityBinding,
)
from agent_assure.schema.stochastic_sensitivity import (
    CaseClusterBinding,
    CouplingClassification,
    CouplingCondition,
    CouplingDescriptor,
    RepeatedEvidenceSensitivityProtocol,
    SensitivityArmBinding,
    StatisticalSufficiencyReport,
    StochasticEvidenceSensitivityReport,
)

RUNNER = CliRunner()


def _digest(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def _arm(
    arm_id: Literal["baseline_evidence", "counterfactual_evidence"],
) -> SensitivityArmBinding:
    arm_name = arm_id.removesuffix("_evidence")
    is_baseline = arm_id == "baseline_evidence"
    return SensitivityArmBinding(
        arm_id=arm_id,
        expected_recommendation="approve" if is_baseline else "deny",
        expected_outcome="approved" if is_baseline else "denied",
        configuration_digest=_digest(f"{arm_name}-configuration"),
        corpus_digest=_digest(f"{arm_name}-corpus"),
        prompt_manifest_digest=_digest("prompt-manifest"),
        case_manifest_digest=_digest("case-manifest"),
        knowledge_contract_digest=_digest("knowledge-contract"),
        provider="synthetic-provider",
        requested_model="synthetic-model",
        adapter_id="openai-chat-completions",
        pipeline_id="synthetic-pipeline",
        tool_schema_digest=_digest("tool-schema"),
        policy_bundle_digest=_digest("policy-bundle"),
    )


def _protocol() -> RepeatedEvidenceSensitivityProtocol:
    design = plan_binary_paired_design(
        familywise_alpha="0.050000",
        desired_power="0.800000",
        null_response_rate="0.500000",
        alternative_response_rate="0.900000",
        monte_carlo_resamples=1_000,
    )
    cases = tuple(f"case-{index:02d}" for index in range(design.planned_inferential_clusters))
    baseline_arm = _arm("baseline_evidence")
    counterfactual_arm = _arm("counterfactual_evidence")
    return RepeatedEvidenceSensitivityProtocol.build(
        protocol_id="cli-repeated-study",
        interpretation="confirmatory",
        execution_mode="stochastic_live",
        inferential_unit="case_id",
        cluster_by="case_id",
        baseline_arm=baseline_arm,
        counterfactual_arm=counterfactual_arm,
        planned_case_ids=cases,
        planned_cluster_ids=cases,
        case_cluster_bindings=tuple(
            CaseClusterBinding(case_id=case_id, cluster_id=case_id) for case_id in cases
        ),
        case_authority_bindings=tuple(
            _case_authority_binding(case_id, baseline_arm, counterfactual_arm) for case_id in cases
        ),
        repetitions_per_arm=1,
        planned_pairs=len(cases),
        multiplicity_family="evidence-sensitivity",
        coupling=CouplingDescriptor(
            pairing_identity_verified=True,
            stochastic_dimensions=(
                CouplingCondition.provider_sampling_randomness,
                CouplingCondition.temporal_execution_order,
            ),
            shared=(CouplingCondition.case_identity,),
            intentionally_different=(CouplingCondition.governing_corpus_digest,),
            not_shared=(
                CouplingCondition.provider_sampling_randomness,
                CouplingCondition.temporal_execution_order,
            ),
            requested_provider_seed=True,
            classification=CouplingClassification.nominally_paired,
            variance_reduction_claim_permitted=False,
        ),
        design=design,
        limitations=("Synthetic CLI integration fixture.",),
    )


def _case_authority_binding(
    case_id: str,
    baseline: SensitivityArmBinding,
    counterfactual: SensitivityArmBinding,
) -> RAGSensitivityCaseAuthorityBinding:
    assignments = (
        RAGSensitivityAuthorityAssignment(
            corpus_digest=baseline.corpus_digest,
            expected_decision=baseline.expected_recommendation,
            expected_outcome=baseline.expected_outcome,
            governing_source_id=f"authority-{case_id}",
            governing_ref_id=f"ref-{case_id}",
            governing_content_digest=_digest(f"baseline-authority-{case_id}"),
            claim_id=f"claim-{case_id}",
        ),
        RAGSensitivityAuthorityAssignment(
            corpus_digest=counterfactual.corpus_digest,
            expected_decision=counterfactual.expected_recommendation,
            expected_outcome=counterfactual.expected_outcome,
            governing_source_id=f"authority-{case_id}",
            governing_ref_id=f"ref-{case_id}",
            governing_content_digest=_digest(f"counterfactual-authority-{case_id}"),
            claim_id=f"claim-{case_id}",
        ),
    )
    return RAGSensitivityCaseAuthorityBinding(
        case_id=case_id,
        query_family_id="synthetic-query-family",
        assignments=tuple(sorted(assignments, key=lambda item: item.corpus_digest)),
    )


def _deterministic_protocol() -> RepeatedEvidenceSensitivityProtocol:
    payload = _protocol().model_dump(
        mode="python",
        exclude={"protocol_digest", "design_commitment_digest"},
    )
    payload.update(
        {
            "protocol_id": "cli-deterministic-rehearsal",
            "interpretation": "exploratory",
            "execution_mode": "deterministic_fixture",
        }
    )
    return RepeatedEvidenceSensitivityProtocol.build(**payload)


def _runset(
    protocol: RepeatedEvidenceSensitivityProtocol,
    arm_id: Literal["baseline_evidence", "counterfactual_evidence"],
    *,
    omitted_case: str | None = None,
) -> RunSet:
    arm = protocol.baseline_arm if arm_id == "baseline_evidence" else protocol.counterfactual_arm
    is_baseline = arm_id == "baseline_evidence"
    runs = tuple(
        AgentRunRecord(
            run_id=f"{arm_id}-{case_id}",
            case_id=case_id,
            execution_mode=ExecutionMode.live,
            pipeline_id=arm.pipeline_id,
            recommendation="approve" if is_baseline else "deny",
            outcome="approved" if is_baseline else "denied",
            input_summary="synthetic paired input",
            output_summary="synthetic structured decision",
            observation_id=f"{arm_id}-{case_id}-observation",
            repetition_index=0,
            schedule_index=index,
            randomization_block_id=f"block-{index:02d}",
            cluster_id=case_id,
            adapter_id=arm.adapter_id,
            provider=arm.provider,
            model=arm.requested_model,
            resolved_model=arm.resolved_model,
            provider_api_version=arm.provider_api_version,
            provider_sdk=arm.provider_sdk,
            provider_region=arm.provider_region,
            cost_budget_committed_usd="0.000000",
            generated_token_budget_committed=0,
            total_token_budget_committed=0,
            provenance=Provenance(
                configuration_digest=arm.configuration_digest,
                policy_bundle_digest=arm.policy_bundle_digest,
                tool_schema_digest=arm.tool_schema_digest,
                retrieval_corpus_digest=arm.corpus_digest,
                evidence_sensitivity_design_digest=protocol.design_commitment_digest,
                model_identifier=arm.requested_model,
            ),
        )
        for index, case_id in enumerate(protocol.planned_case_ids)
        if case_id != omitted_case
    )
    return RunSet(
        runset_id=f"{arm_id}-runset",
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        suite_id="synthetic-suite",
        suite_version="1.0.0",
        suite_digest=_digest("suite"),
        fixture_manifest_digest=arm.configuration_digest,
        execution_mode=ExecutionMode.live,
        protocol_id="operational-live-protocol",
        protocol_digest=_digest("operational-live-protocol"),
        evidence_sensitivity_design_digest=protocol.design_commitment_digest,
        completion_status="incomplete" if omitted_case is not None else "complete",
        stop_reasons=("synthetic-source-omission",) if omitted_case is not None else (),
        runs=runs,
    )


def _fixture_runset(
    protocol: RepeatedEvidenceSensitivityProtocol,
    arm_id: Literal["baseline_evidence", "counterfactual_evidence"],
) -> RunSet:
    payload = _runset(protocol, arm_id).model_dump(mode="python")
    payload["execution_mode"] = ExecutionMode.fixture
    payload["runs"] = [{**run, "execution_mode": ExecutionMode.fixture} for run in payload["runs"]]
    return RunSet.model_validate(payload)


def _uncommitted_live_config(variant_id: str) -> LiveRunConfig:
    return LiveRunConfig(
        variant_id=variant_id,
        pipeline_id="sensitivity-pipeline",
        tool_schema_digest=_digest("tool-schema"),
        policy_bundle_digest=_digest("policy-bundle"),
        retrieval_corpus_digest=_digest(f"{variant_id}-corpus"),
        retrieval_corpus_dir="corpus",
        knowledge_contract_digest=_digest("knowledge-contract"),
        knowledge_contract_path="knowledge-contract.json",
        adapter=LiveAdapterConfig(
            adapter_id="openai-chat-completions",
            provider="synthetic-provider",
            model="synthetic-model",
            endpoint_url="https://api.example.test/v1/chat/completions",
            api_key_env="AGENT_ASSURE_TEST_API_KEY",
            allowed_endpoint_hosts=("api.example.test",),
            max_output_tokens=64,
            allow_network=True,
            cost_per_1k_prompt_tokens_usd="0.001000",
            cost_per_1k_completion_tokens_usd="0.002000",
            sdk_name="openai",
            sdk_version="1.2.3",
        ),
        cases=(
            LivePromptCase(
                case_id="case-00",
                prompt_path="prompt.txt",
                input_summary="synthetic finalize fixture",
            ),
        ),
    )


def _finalized_facts(config: LiveRunConfig) -> dict[str, object]:
    is_baseline = config.variant_id == "baseline"
    return {
        "configuration_digest": _digest(f"{config.variant_id}-configuration"),
        "corpus_digest": config.retrieval_corpus_digest,
        "prompt_manifest_digest": _digest("prompt-manifest"),
        "case_manifest_digest": _digest("case-manifest"),
        "knowledge_contract_digest": config.knowledge_contract_digest,
        "provider": config.adapter.provider,
        "requested_model": config.adapter.model,
        "provider_api_version": config.adapter.api_version,
        "provider_sdk": "openai/1.2.3",
        "provider_region": config.adapter.region,
        "adapter_id": config.adapter.adapter_id,
        "pipeline_id": config.pipeline_id,
        "tool_schema_digest": config.tool_schema_digest,
        "policy_bundle_digest": config.policy_bundle_digest,
        "expected_recommendation": "approve" if is_baseline else "deny",
        "expected_outcome": "approved" if is_baseline else "denied",
    }


def _write_json(path: Path, value: object) -> None:
    payload = value.model_dump(mode="json") if hasattr(value, "model_dump") else value
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _persist_study(
    tmp_path: Path,
    *,
    omitted_counterfactual_case: str | None = None,
) -> tuple[RepeatedEvidenceSensitivityProtocol, Path, Path]:
    protocol = _protocol()
    protocol_path = tmp_path / "protocol.json"
    runset_dir = tmp_path / "paired-runs"
    runset_dir.mkdir()
    _write_json(protocol_path, protocol)
    _write_json(runset_dir / "baseline.runset.json", _runset(protocol, "baseline_evidence"))
    _write_json(
        runset_dir / "counterfactual.runset.json",
        _runset(
            protocol,
            "counterfactual_evidence",
            omitted_case=omitted_counterfactual_case,
        ),
    )
    return protocol, protocol_path, runset_dir


def test_repeated_sensitivity_finalize_content_binds_both_configs_without_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    template_path = tmp_path / "protocol-template.json"
    compiled_path = tmp_path / "compiled-suite.json"
    baseline_path = tmp_path / "baseline.uncommitted.json"
    counterfactual_path = tmp_path / "counterfactual.uncommitted.json"
    protocol_out = tmp_path / "protocol.json"
    baseline_out = tmp_path / "baseline.final.json"
    counterfactual_out = tmp_path / "counterfactual.final.json"
    authored_protocol = _protocol()
    template = authored_protocol.model_dump(
        mode="json",
        exclude={"protocol_digest", "design_commitment_digest"},
    )
    baseline = _uncommitted_live_config("baseline")
    counterfactual = _uncommitted_live_config("counterfactual")
    _write_json(template_path, template)
    _write_json(compiled_path, {})
    _write_json(baseline_path, baseline)
    _write_json(counterfactual_path, counterfactual)

    monkeypatch.setattr(rag_cmd_module, "load_compiled_suite", lambda _: object())
    monkeypatch.setattr(
        rag_cmd_module,
        "load_live_run_config",
        lambda path: baseline if path == baseline_path else counterfactual,
    )
    monkeypatch.setattr(
        rag_cmd_module,
        "calculate_live_arm_binding_facts",
        lambda *, config, **_: {
            **_finalized_facts(config),
            "case_authority_bindings": authored_protocol.case_authority_bindings,
        },
    )

    def reject_dispatch(**_: object) -> tuple[RunSet, RunSet]:
        raise AssertionError("finalization must not dispatch an adapter")

    def reject_post_commit_protocol_read(_: Path) -> RepeatedEvidenceSensitivityProtocol:
        raise AssertionError("finalization must not reload a published output")

    monkeypatch.setattr(rag_cmd_module, "run_repeated_live_study", reject_dispatch)
    monkeypatch.setattr(
        rag_cmd_module,
        "load_repeated_sensitivity_protocol",
        reject_post_commit_protocol_read,
    )
    arguments = [
        "rag",
        "sensitivity",
        "finalize",
        "--template",
        str(template_path),
        "--compiled-suite",
        str(compiled_path),
        "--baseline-config",
        str(baseline_path),
        "--counterfactual-config",
        str(counterfactual_path),
        "--out",
        str(protocol_out),
        "--baseline-config-out",
        str(baseline_out),
        "--counterfactual-config-out",
        str(counterfactual_out),
    ]

    result = RUNNER.invoke(app, arguments)

    assert result.exit_code == 0, result.output
    finalized_protocol = RepeatedEvidenceSensitivityProtocol.model_validate(
        json.loads(protocol_out.read_text(encoding="utf-8"))
    )
    finalized_baseline = load_live_run_config(baseline_out)
    finalized_counterfactual = load_live_run_config(counterfactual_out)
    assert (
        finalized_protocol.baseline_arm.configuration_digest
        == _finalized_facts(baseline)["configuration_digest"]
    )
    assert finalized_protocol.counterfactual_arm.expected_recommendation == "deny"
    assert finalized_protocol.baseline_arm.provider_sdk == "openai/1.2.3"
    assert finalized_protocol.counterfactual_arm.provider_sdk == "openai/1.2.3"
    assert finalized_baseline.adapter.sdk_name == "openai"
    assert finalized_baseline.adapter.sdk_version == "1.2.3"
    assert (
        finalized_baseline.evidence_sensitivity_design_digest
        == finalized_protocol.design_commitment_digest
        == finalized_counterfactual.evidence_sensitivity_design_digest
    )
    assert load_live_run_config(baseline_path).evidence_sensitivity_design_digest is None
    assert load_live_run_config(counterfactual_path).evidence_sensitivity_design_digest is None

    repeated = RUNNER.invoke(app, arguments)
    assert repeated.exit_code == 0, repeated.output
    assert "design commitment digest:" in repeated.output


def test_repeated_sensitivity_finalize_requires_sibling_config_outputs(
    tmp_path: Path,
) -> None:
    inputs = tuple(tmp_path / name for name in ("template", "suite", "base", "counter"))
    for path in inputs:
        path.write_text("{}\n", encoding="utf-8")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()

    result = RUNNER.invoke(
        app,
        [
            "rag",
            "sensitivity",
            "finalize",
            "--template",
            str(inputs[0]),
            "--compiled-suite",
            str(inputs[1]),
            "--baseline-config",
            str(inputs[2]),
            "--counterfactual-config",
            str(inputs[3]),
            "--out",
            str(tmp_path / "protocol.json"),
            "--baseline-config-out",
            str(elsewhere / "baseline.json"),
            "--counterfactual-config-out",
            str(tmp_path / "counterfactual.json"),
        ],
    )

    assert result.exit_code == 2
    assert "finalized config must use a distinct filename beside" in result.output


def test_repeated_sensitivity_finalize_refuses_every_inline_environment_value(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    template_path = tmp_path / "protocol-template.json"
    compiled_path = tmp_path / "compiled-suite.json"
    baseline_path = tmp_path / "baseline.uncommitted.json"
    counterfactual_path = tmp_path / "counterfactual.uncommitted.json"
    protocol_out = tmp_path / "protocol.json"
    baseline_out = tmp_path / "baseline.final.json"
    counterfactual_out = tmp_path / "counterfactual.final.json"
    template = _protocol().model_dump(
        mode="json",
        exclude={"protocol_digest", "design_commitment_digest"},
    )
    baseline = _uncommitted_live_config("baseline")
    baseline = baseline.model_copy(
        update={
            "adapter": baseline.adapter.model_copy(
                update={
                    # Deliberately benign-looking: finalization rejects all raw
                    # values instead of pretending detectors can prove safety.
                    "script_env": (LiveScriptEnvVar(name="CUSTOM_FLAG", value="enabled"),),
                }
            )
        }
    )
    counterfactual = _uncommitted_live_config("counterfactual")
    _write_json(template_path, template)
    _write_json(compiled_path, {})
    _write_json(baseline_path, baseline)
    _write_json(counterfactual_path, counterfactual)
    monkeypatch.setattr(rag_cmd_module, "load_compiled_suite", lambda _: object())
    monkeypatch.setattr(
        rag_cmd_module,
        "load_live_run_config",
        lambda path: baseline if path == baseline_path else counterfactual,
    )

    result = RUNNER.invoke(
        app,
        [
            "rag",
            "sensitivity",
            "finalize",
            "--template",
            str(template_path),
            "--compiled-suite",
            str(compiled_path),
            "--baseline-config",
            str(baseline_path),
            "--counterfactual-config",
            str(counterfactual_path),
            "--out",
            str(protocol_out),
            "--baseline-config-out",
            str(baseline_out),
            "--counterfactual-config-out",
            str(counterfactual_out),
        ],
    )

    assert result.exit_code == 2
    assert "refuses to persist them" in result.output
    assert "enabled" not in result.output
    assert not protocol_out.exists()
    assert not baseline_out.exists()
    assert not counterfactual_out.exists()


def test_finalize_publication_never_clobbers_or_unlinks_final_names(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    third = tmp_path / "third.json"
    outputs = (
        (first, "first\n", "first output"),
        (second, "second\n", "second output"),
        (third, "third\n", "third output"),
    )
    second.write_text("foreign\n", encoding="utf-8")

    with pytest.raises(ValueError, match="already exists with different content"):
        rag_cmd_module._publish_finalize_outputs(outputs)
    assert not first.exists()
    assert second.read_text(encoding="utf-8") == "foreign\n"
    assert not third.exists()

    second.unlink()
    real_open = RootedDirectoryDescriptor.open_regular_file_exclusive_with_metadata
    collided = False

    def create_concurrent_entry(
        self: RootedDirectoryDescriptor,
        name: str | Path,
        *,
        mode: int = 0o600,
    ) -> tuple[int, os.stat_result]:
        nonlocal collided
        if str(name) == second.name and not collided:
            (self.path / second.name).write_text("concurrent\n", encoding="utf-8")
            collided = True
        return real_open(self, name, mode=mode)

    monkeypatch.setattr(
        RootedDirectoryDescriptor,
        "open_regular_file_exclusive_with_metadata",
        create_concurrent_entry,
    )
    with pytest.raises(FileExistsError):
        rag_cmd_module._publish_finalize_outputs(outputs)

    assert collided
    assert first.read_text(encoding="utf-8") == "first\n"
    assert second.read_text(encoding="utf-8") == "concurrent\n"
    assert not third.exists()


def test_finalize_publication_serializes_partially_overlapping_output_sets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shared = tmp_path / "00-shared.json"
    a_second = tmp_path / "10-a-second.json"
    a_third = tmp_path / "11-a-third.json"
    b_second = tmp_path / "20-b-second.json"
    b_third = tmp_path / "21-b-third.json"
    outputs_a = (
        (shared, "shared\n", "shared output"),
        (a_second, "a-second\n", "A second output"),
        (a_third, "a-third\n", "A third output"),
    )
    outputs_b = (
        (shared, "shared\n", "shared output"),
        (b_second, "b-second\n", "B second output"),
        (b_third, "b-third\n", "B third output"),
    )
    a_wrote_shared = threading.Event()
    release_a = threading.Event()
    b_lock_attempted = threading.Event()
    b_finished = threading.Event()
    real_write_all = rag_cmd_module._write_all
    real_lock = rag_cmd_module._lock_finalize_descriptor
    outcomes: dict[str, BaseException | None] = {}

    def pause_a_after_shared_write(descriptor: int, payload: bytes) -> None:
        real_write_all(descriptor, payload)
        if threading.current_thread().name == "publisher-a" and payload == b"shared\n":
            a_wrote_shared.set()
            if not release_a.wait(timeout=10):
                raise TimeoutError("test did not release publisher A")

    def observe_b_lock_attempt(descriptor: int) -> None:
        if threading.current_thread().name == "publisher-b":
            b_lock_attempted.set()
        real_lock(descriptor)

    def publish(
        name: str,
        outputs: tuple[tuple[Path, str, str], ...],
        finished: threading.Event | None = None,
    ) -> None:
        try:
            rag_cmd_module._publish_finalize_outputs(outputs)
        except BaseException as exc:
            outcomes[name] = exc
        else:
            outcomes[name] = None
        finally:
            if finished is not None:
                finished.set()

    monkeypatch.setattr(rag_cmd_module, "_write_all", pause_a_after_shared_write)
    monkeypatch.setattr(
        rag_cmd_module,
        "_lock_finalize_descriptor",
        observe_b_lock_attempt,
    )
    publisher_a = threading.Thread(
        target=publish,
        args=("a", outputs_a),
        name="publisher-a",
    )
    publisher_b = threading.Thread(
        target=publish,
        args=("b", outputs_b, b_finished),
        name="publisher-b",
    )

    publisher_a.start()
    assert a_wrote_shared.wait(timeout=10)
    a_second.write_text("concurrent\n", encoding="utf-8")
    publisher_b.start()
    assert b_lock_attempted.wait(timeout=10)
    assert not b_finished.wait(timeout=0.2)
    release_a.set()
    publisher_a.join(timeout=10)
    publisher_b.join(timeout=10)

    assert not publisher_a.is_alive()
    assert not publisher_b.is_alive()
    assert isinstance(outcomes["a"], FileExistsError)
    assert outcomes["b"] is None
    assert shared.read_text(encoding="utf-8") == "shared\n"
    assert a_second.read_text(encoding="utf-8") == "concurrent\n"
    assert not a_third.exists()
    assert b_second.read_text(encoding="utf-8") == "b-second\n"
    assert b_third.read_text(encoding="utf-8") == "b-third\n"


def test_finalize_publication_close_failure_still_releases_output_locks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outputs = tuple(
        (tmp_path / f"output-{index}.json", f"output-{index}\n", f"output {index}")
        for index in range(3)
    )
    real_close = rag_cmd_module._close_created_finalize_outputs
    inject_close_error = True

    def report_close_error(
        created: list[rag_cmd_module._CreatedFinalizeOutput],
    ) -> tuple[str, ...]:
        errors = real_close(created)
        if inject_close_error:
            return (*errors, "injected created-descriptor close failure")
        return errors

    monkeypatch.setattr(
        rag_cmd_module,
        "_close_created_finalize_outputs",
        report_close_error,
    )
    with pytest.raises(OSError, match="resource release was incomplete"):
        rag_cmd_module._publish_finalize_outputs(outputs)

    inject_close_error = False
    rag_cmd_module._publish_finalize_outputs(outputs)
    assert tuple(path.read_text(encoding="utf-8") for path, _, _ in outputs) == (
        "output-0\n",
        "output-1\n",
        "output-2\n",
    )

    foreign = tmp_path / "foreign.json"
    foreign.write_text("foreign\n", encoding="utf-8")
    inject_close_error = True
    with pytest.raises(ValueError, match="already exists with different content"):
        rag_cmd_module._publish_finalize_outputs(((foreign, "expected\n", "foreign output"),))


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory durability regression")
def test_finalize_publication_syncs_each_created_parent_before_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    second_parent = tmp_path / "second-parent"
    second_parent.mkdir()
    outputs = (
        (tmp_path / "first.json", "first\n", "first output"),
        (tmp_path / "second.json", "second\n", "second output"),
        (second_parent / "third.json", "third\n", "third output"),
    )
    real_fsync = os.fsync
    synced_directories: list[tuple[int, int]] = []

    def observe_fsync(descriptor: int) -> None:
        metadata = os.fstat(descriptor)
        if stat.S_ISDIR(metadata.st_mode):
            synced_directories.append((metadata.st_dev, metadata.st_ino))
        real_fsync(descriptor)

    monkeypatch.setattr(rag_cmd_module.os, "fsync", observe_fsync)
    rag_cmd_module._publish_finalize_outputs(outputs)

    expected_parents = {
        (os.lstat(tmp_path).st_dev, os.lstat(tmp_path).st_ino),
        (os.lstat(second_parent).st_dev, os.lstat(second_parent).st_ino),
    }
    assert set(synced_directories) == expected_parents
    assert len(synced_directories) == len(expected_parents)


def test_repeated_sensitivity_plan_recomputes_valid_protocol(tmp_path: Path) -> None:
    protocol = _protocol()
    protocol_path = tmp_path / "protocol.json"
    _write_json(protocol_path, protocol)

    result = RUNNER.invoke(
        app,
        ["rag", "sensitivity", "plan", "--protocol", str(protocol_path)],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["protocol_id"] == protocol.protocol_id
    assert payload["protocol_digest"] == protocol.protocol_digest
    assert payload["endpoint"] == "expected_decision_response"
    assert payload["design"] == protocol.design.model_dump(mode="json")


@pytest.mark.parametrize("failure", ("malformed", "tampered"))
def test_repeated_sensitivity_plan_rejects_invalid_protocols(
    tmp_path: Path,
    failure: str,
) -> None:
    protocol_path = tmp_path / "protocol.json"
    if failure == "malformed":
        protocol_path.write_text("{", encoding="utf-8")
    else:
        payload = _protocol().model_dump(mode="json")
        payload["multiplicity_family"] = "post-hoc-family"
        _write_json(protocol_path, payload)

    result = RUNNER.invoke(
        app,
        ["rag", "sensitivity", "plan", "--protocol", str(protocol_path)],
    )

    assert result.exit_code == 2
    assert "invalid repeated sensitivity protocol:" in result.output


def test_repeated_sensitivity_analyze_publishes_exact_six_file_pass_bundle(
    tmp_path: Path,
) -> None:
    protocol, protocol_path, runset_dir = _persist_study(tmp_path)
    out = tmp_path / "analysis"

    result = RUNNER.invoke(
        app,
        [
            "rag",
            "sensitivity",
            "analyze",
            "--protocol",
            str(protocol_path),
            "--runset",
            str(runset_dir),
            "--out",
            str(out),
        ],
    )

    assert result.exit_code == 0, result.output
    assert {item.name for item in out.iterdir()} == set(REPEATED_ANALYSIS_OUTPUT_FILENAMES)
    sufficiency = StatisticalSufficiencyReport.model_validate(
        json.loads((out / "statistical-sufficiency-report.json").read_text(encoding="utf-8"))
    )
    report = StochasticEvidenceSensitivityReport.model_validate(
        json.loads((out / "stochastic-evidence-sensitivity.json").read_text(encoding="utf-8"))
    )
    assert sufficiency.protocol == protocol
    assert sufficiency.state.value == "satisfied"
    assert len(sufficiency.source_runsets) == 2
    assert report.state.value == "pass"
    assert report.verdict_bearing is True
    assert "stochastic sensitivity state: pass" in result.output

    replay = build_digest_replay(
        (
            (
                "statistical-sufficiency-report",
                out / "statistical-sufficiency-report.json",
            ),
            (
                "stochastic-evidence-sensitivity-report",
                out / "stochastic-evidence-sensitivity.json",
            ),
        ),
        project_root=out,
    )
    assert tuple(item.digest_mode for item in replay.artifacts) == (
        "replay-stable-json-sha256",
        "replay-stable-json-sha256",
    )
    assert verify_digest_replay(replay, artifact_root=out).ok


def test_repeated_sensitivity_analyze_incomplete_bundle_is_nonverdict(
    tmp_path: Path,
) -> None:
    protocol = _protocol()
    omitted_case = protocol.planned_case_ids[-1]
    _, protocol_path, runset_dir = _persist_study(
        tmp_path,
        omitted_counterfactual_case=omitted_case,
    )
    out = tmp_path / "analysis"

    result = RUNNER.invoke(
        app,
        [
            "rag",
            "sensitivity",
            "analyze",
            "--protocol",
            str(protocol_path),
            "--runset",
            str(runset_dir),
            "--out",
            str(out),
        ],
    )

    assert result.exit_code == 1, result.output
    assert {item.name for item in out.iterdir()} == set(REPEATED_ANALYSIS_OUTPUT_FILENAMES)
    report = StochasticEvidenceSensitivityReport.model_validate(
        json.loads((out / "stochastic-evidence-sensitivity.json").read_text(encoding="utf-8"))
    )
    assert report.state.value == "inconclusive"
    assert report.gate_effect.value == "non_verdict"
    assert report.verdict_bearing is False
    assert report.dependency is None


def test_repeated_sensitivity_analyze_deterministic_fixture_omits_live_dependencies(
    tmp_path: Path,
) -> None:
    protocol = _deterministic_protocol()
    protocol_path = tmp_path / "protocol.json"
    runset_dir = tmp_path / "fixture-runs"
    runset_dir.mkdir()
    _write_json(protocol_path, protocol)
    _write_json(
        runset_dir / "baseline.runset.json",
        _fixture_runset(protocol, "baseline_evidence"),
    )
    _write_json(
        runset_dir / "counterfactual.runset.json",
        _fixture_runset(protocol, "counterfactual_evidence"),
    )
    out = tmp_path / "fixture-analysis"

    result = RUNNER.invoke(
        app,
        [
            "rag",
            "sensitivity",
            "analyze",
            "--protocol",
            str(protocol_path),
            "--runset",
            str(runset_dir),
            "--out",
            str(out),
        ],
    )

    assert result.exit_code == 1, result.output
    sufficiency = StatisticalSufficiencyReport.model_validate(
        json.loads((out / "statistical-sufficiency-report.json").read_text(encoding="utf-8"))
    )
    assert sufficiency.source_runsets == ()
    assert sufficiency.state.value == "inconclusive"


def test_repeated_sensitivity_analyze_rejects_missing_arm_source(tmp_path: Path) -> None:
    protocol = _protocol()
    protocol_path = tmp_path / "protocol.json"
    runset_dir = tmp_path / "paired-runs"
    runset_dir.mkdir()
    _write_json(protocol_path, protocol)
    _write_json(runset_dir / "baseline.runset.json", _runset(protocol, "baseline_evidence"))

    result = RUNNER.invoke(
        app,
        [
            "rag",
            "sensitivity",
            "analyze",
            "--protocol",
            str(protocol_path),
            "--runset",
            str(runset_dir),
            "--out",
            str(tmp_path / "analysis"),
        ],
    )

    assert result.exit_code == 2
    assert "paired run directory is missing an arm RunSet" in result.output


def test_repeated_sensitivity_analyze_rejects_malformed_arm_source(tmp_path: Path) -> None:
    _, protocol_path, runset_dir = _persist_study(tmp_path)
    (runset_dir / "counterfactual.runset.json").write_text("{", encoding="utf-8")

    result = RUNNER.invoke(
        app,
        [
            "rag",
            "sensitivity",
            "analyze",
            "--protocol",
            str(protocol_path),
            "--runset",
            str(runset_dir),
            "--out",
            str(tmp_path / "analysis"),
        ],
    )

    assert result.exit_code == 2
    assert "repeated sensitivity analysis failed:" in result.output


def test_repeated_sensitivity_run_requires_network_opt_in_before_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    protocol = _protocol()
    inputs = tuple(tmp_path / name for name in ("protocol", "suite", "base", "counter", "live"))
    for path in inputs:
        path.write_text("{}\n", encoding="utf-8")
    dispatched = False

    monkeypatch.setattr(rag_cmd_module, "load_repeated_sensitivity_protocol", lambda _: protocol)
    monkeypatch.setattr(rag_cmd_module, "load_compiled_suite", lambda _: object())
    monkeypatch.setattr(rag_cmd_module, "load_live_run_config", lambda _: object())
    monkeypatch.setattr(rag_cmd_module, "_load_operational_live_protocol", lambda _: object())

    def fail_if_dispatched(**_: object) -> tuple[RunSet, RunSet]:
        nonlocal dispatched
        dispatched = True
        raise AssertionError("adapter dispatch occurred without explicit network opt-in")

    monkeypatch.setattr(rag_cmd_module, "run_repeated_live_study", fail_if_dispatched)
    result = RUNNER.invoke(
        app,
        [
            "rag",
            "sensitivity",
            "run",
            "--protocol",
            str(inputs[0]),
            "--compiled-suite",
            str(inputs[1]),
            "--baseline-config",
            str(inputs[2]),
            "--counterfactual-config",
            str(inputs[3]),
            "--live-protocol",
            str(inputs[4]),
            "--out",
            str(tmp_path / "paired-output"),
        ],
    )

    assert result.exit_code == 2
    assert "requires explicit --network-opt-in" in result.output
    assert dispatched is False


def test_sensitivity_help_and_legacy_deterministic_dispatch_remain_compatible(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    help_result = RUNNER.invoke(
        app,
        ["rag", "sensitivity", "--help"],
        terminal_width=240,
    )
    assert help_result.exit_code == 0, help_result.output
    help_output = unstyle(help_result.output)
    assert "--suite" in help_output
    assert "plan" in help_output
    assert "finalize" in help_output
    assert "analyze" in help_output
    assert "run" in help_output

    suite = tmp_path / "suite.yaml"
    knowledge = tmp_path / "knowledge.yaml"
    baseline = tmp_path / "baseline"
    counterfactual = tmp_path / "counterfactual"
    suite.write_text("{}\n", encoding="utf-8")
    knowledge.write_text("{}\n", encoding="utf-8")
    baseline.mkdir()
    counterfactual.mkdir()

    def legacy_dispatch(**_: object) -> object:
        raise SensitivityInputError("legacy deterministic dispatch reached")

    monkeypatch.setattr(rag_cmd_module, "execute_sensitivity_experiment", legacy_dispatch)
    result = RUNNER.invoke(
        app,
        [
            "rag",
            "sensitivity",
            "--suite",
            str(suite),
            "--baseline-corpus",
            str(baseline),
            "--counterfactual-corpus",
            str(counterfactual),
            "--knowledge-contract",
            str(knowledge),
            "--expected-relation",
            "decision_flip",
            "--out",
            str(tmp_path / "legacy-output"),
        ],
    )

    assert result.exit_code == 2
    assert "legacy deterministic dispatch reached" in result.output
