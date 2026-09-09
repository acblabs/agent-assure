from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from agent_assure.cli import rag_cmd as rag_cmd_module
from agent_assure.cli import study_cmd as study_cmd_module
from agent_assure.cli.main import app
from agent_assure.live.config import LiveRunConfig
from agent_assure.reporting.study import write_real_model_study_artifacts
from agent_assure.schema.study import (
    RealModelStudyManifest,
    StudyExecutionReviewReceipt,
    StudyRegistrationReviewReceipt,
    StudyStatisticalMethodReviewReceipt,
)
from agent_assure.study_execution_review import build_study_execution_review_receipt
from agent_assure.study_method_review import (
    build_study_statistical_method_review_receipt,
)
from tests.integration.test_repeated_sensitivity_cli import (
    _uncommitted_live_config,
)
from tests.unit.study.test_real_model_study import StudyFixture, _analyze, _fixture

RUNNER = CliRunner()
ROOT = Path(__file__).resolve().parents[2]


def _write_json(path: Path, value: object) -> None:
    payload = value.model_dump(mode="json") if hasattr(value, "model_dump") else value
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def test_study_input_budget_counts_exact_raw_whitespace_bytes(tmp_path: Path) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    first.write_bytes(b'{"value":1}' + (b" " * 4_096))
    second.write_bytes(b'{"value":2}' + (b" " * 4_096))
    budget = study_cmd_module._StudyInputByteBudget(
        remaining=first.stat().st_size + second.stat().st_size - 1
    )

    assert study_cmd_module._load_authoring_mapping(
        first,
        label="first inflated input",
        byte_budget=budget,
    ) == {"value": 1}
    assert budget.remaining == second.stat().st_size - 1
    with pytest.raises(ValueError, match="exceeds maximum supported size"):
        study_cmd_module._load_authoring_mapping(
            second,
            label="second inflated input",
            byte_budget=budget,
        )


def _reject_dispatch(**_: object) -> object:
    raise AssertionError("study authoring and binding must not dispatch a provider")


def _bound_config(config: LiveRunConfig, manifest: RealModelStudyManifest) -> LiveRunConfig:
    return LiveRunConfig.model_validate(
        {
            **config.model_dump(mode="json"),
            "study_manifest_digest": manifest.manifest_digest,
        }
    )


def _method_review_receipt(fixture: StudyFixture) -> StudyStatisticalMethodReviewReceipt:
    return build_study_statistical_method_review_receipt(
        manifest=fixture.manifest,
        benchmark=fixture.benchmark,
        protocols=fixture.protocols,
        receipt_id="integration-statistical-method-review",
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
            "The reviewer did not author the benchmark or design, dispatch provider "
            "calls, select observations, or conduct the final analysis."
        ),
        independence_design_basis_reviewed_and_accepted=True,
        independence_acceptance_rationale=(
            "Independent inspection supports the synthetic generator's separate "
            "cluster construction within this bounded integration-test design."
        ),
        semantic_near_duplicate_audit_reviewed=True,
        semantic_near_duplicate_pseudoreplication_rejected=True,
        semantic_near_duplicate_review_rationale=(
            "The digest-bound comparison found no unhandled semantic duplicate "
            "counted as another cluster in the integration fixture."
        ),
        benchmark_cluster_assignments_reviewed=True,
        independence_and_exchangeability_assumptions_reviewed=True,
        sampling_frame_and_estimand_reviewed=True,
        multiplicity_and_interval_method_reviewed=True,
        power_and_decision_boundary_reachability_reviewed=True,
        negative_control_design_reviewed=True,
    )


def _execution_review_template() -> dict[str, object]:
    return {
        "receipt_id": "integration-execution-review",
        "reviewed_at_utc": "2025-04-01T00:00:00Z",
        "reviewer_pseudonym": "independent-integration-reviewer",
        "reviewer_independent_of_execution": True,
        "reviewer_independence_rationale": (
            "The reviewer did not operate the integration fixture execution."
        ),
        "provider_log_review_scope": (
            "The reviewer inspected every integration provider event across the "
            "registered execution window and all request classes."
        ),
        "provider_log_evidence_digest": "1234567890abcdef" * 4,
        "provider_account_review_scope": (
            "The reviewer reconciled the complete integration usage ledger against "
            "every recorded attempt and terminal response."
        ),
        "provider_account_evidence_digest": "abcdef0123456789" * 4,
        "provider_log_and_account_review_confirmed": True,
        "provider_log_time_window_coverage_confirmed": True,
        "provider_account_usage_reconciled": True,
        "exhaustive_attempt_failure_retry_accounting_confirmed": True,
        "provider_response_id_matches_confirmed": True,
        "exact_runset_artifact_digest_matches_confirmed": True,
        "provider_serving_fingerprint_availability_reviewed": True,
    }


def test_study_input_commitment_snapshots_without_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    compiled_path = tmp_path / "compiled-suite.json"
    config_path = tmp_path / "baseline.config.json"
    _write_json(compiled_path, {})
    _write_json(config_path, {})
    compiled = object()
    config = _uncommitted_live_config("baseline")
    monkeypatch.setattr(study_cmd_module, "load_compiled_suite", lambda _path: compiled)
    monkeypatch.setattr(study_cmd_module, "load_live_run_config", lambda _path: config)
    monkeypatch.setattr(rag_cmd_module, "run_repeated_live_study", _reject_dispatch)

    def calculate(actual_compiled: object, actual_config: object, *, config_dir: Path) -> str:
        assert actual_compiled is compiled
        assert actual_config is config
        assert config_dir == tmp_path
        return "a" * 64

    monkeypatch.setattr(
        study_cmd_module,
        "calculate_live_provider_input_manifest_digest",
        calculate,
    )

    result = RUNNER.invoke(
        app,
        [
            "rag",
            "study",
            "input-commitment",
            "--compiled-suite",
            str(compiled_path),
            "--config",
            str(config_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert result.output == f"provider input manifest digest: {'a' * 64}\n"


def test_study_review_execution_builds_exact_post_window_receipt_without_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(real_provider_execution=True)
    report = _analyze(fixture)
    bundle = tmp_path / "unreviewed-bundle"
    write_real_model_study_artifacts(
        manifest=fixture.manifest,
        benchmark=fixture.benchmark,
        protocols=fixture.protocols,
        evidence=fixture.evidence_by_condition,
        report=report,
        registration_record_bytes=fixture.registration_record_bytes,
        registration_review_receipt=fixture.registration_review_receipt,
        out_dir=bundle,
    )
    untouched_template_path = ROOT / "docs" / "templates" / "real_model_study_execution_review.yaml"
    template_path = tmp_path / "execution-review-template.json"
    _write_json(template_path, _execution_review_template())
    receipt_path = tmp_path / "study-execution-review.json"
    monkeypatch.setattr(rag_cmd_module, "run_repeated_live_study", _reject_dispatch)

    untouched = RUNNER.invoke(
        app,
        [
            "rag",
            "study",
            "review-execution",
            "--bundle",
            str(bundle),
            "--template",
            str(untouched_template_path),
            "--out",
            str(receipt_path),
        ],
    )
    assert untouched.exit_code == 2
    assert "Input should be True" in untouched.output
    assert not receipt_path.exists()

    result = RUNNER.invoke(
        app,
        [
            "rag",
            "study",
            "review-execution",
            "--bundle",
            str(bundle),
            "--template",
            str(template_path),
            "--out",
            str(receipt_path),
        ],
    )

    assert result.exit_code == 0, result.output
    receipt = StudyExecutionReviewReceipt.model_validate_json(
        receipt_path.read_text(encoding="utf-8")
    )
    assert receipt.study_manifest_digest == fixture.manifest.manifest_digest
    assert receipt.study_report_digest == report.report_digest
    assert len(receipt.conditions) == len(fixture.manifest.conditions)
    assert receipt.provider_log_and_account_review_confirmed is True
    assert receipt.exhaustive_attempt_failure_retry_accounting_confirmed is True
    for condition, binding in zip(
        receipt.conditions,
        fixture.manifest.conditions,
        strict=True,
    ):
        evidence = fixture.evidence_by_condition[binding.condition_id]
        assert condition.execution_attempt_id == binding.execution_attempt_id
        assert (
            condition.execution_attempt_journal_digest
            == evidence.baseline_runset.execution_attempt_journal_digest
            == evidence.counterfactual_runset.execution_attempt_journal_digest
        )


def test_study_review_statistics_binds_exact_design_without_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(real_provider_execution=True)
    manifest_path = tmp_path / "study-manifest.json"
    benchmark_path = tmp_path / "benchmark.json"
    template_path = tmp_path / "statistical-method-review.json"
    receipt_path = tmp_path / "statistical-method-review-receipt.json"
    _write_json(manifest_path, fixture.manifest)
    _write_json(benchmark_path, fixture.benchmark)
    _write_json(
        template_path,
        _method_review_receipt(fixture).model_dump(
            mode="json",
            exclude={
                "schema_name",
                "schema_version",
                "artifact_kind",
                "contract_id",
                "contract_version",
                "study_id",
                "study_manifest_digest",
                "study_manifest_sha256",
                "benchmark_digest",
                "benchmark_sha256",
                "protocol_set_digest",
                "hypothesis_decision_rule_digest",
                "registered_at_utc",
                "execution_window_start_utc",
                "approved_inference_scope",
                "independence_design_basis",
                "independence_audit_artifact_sha256",
                "semantic_near_duplicate_disposition",
                "conditions",
                "method_review_receipt_digest",
                "approval_disposition",
                "unresolved_methodological_concerns",
                "attestation_basis",
                "reviewer_identity_authentication",
            },
        ),
    )
    protocol_paths: dict[str, Path] = {}
    for index, (condition_id, protocol) in enumerate(fixture.protocols.items()):
        protocol_path = tmp_path / f"protocol-{index:03d}.json"
        _write_json(protocol_path, protocol)
        protocol_paths[condition_id] = protocol_path
    monkeypatch.setattr(rag_cmd_module, "run_repeated_live_study", _reject_dispatch)
    arguments = [
        "rag",
        "study",
        "review-statistics",
        "--manifest",
        str(manifest_path),
        "--benchmark",
        str(benchmark_path),
        "--template",
        str(template_path),
        "--out",
        str(receipt_path),
    ]
    for condition_id, protocol_path in protocol_paths.items():
        arguments.extend(("--protocol", f"{condition_id}={protocol_path}"))

    untouched_arguments = list(arguments)
    untouched_arguments[untouched_arguments.index(str(template_path))] = str(
        ROOT / "docs" / "templates" / "real_model_study_statistical_method_review.yaml"
    )
    untouched = RUNNER.invoke(app, untouched_arguments)
    assert untouched.exit_code == 2
    assert "Input should be True" in untouched.output
    assert not receipt_path.exists()

    result = RUNNER.invoke(app, arguments)

    assert result.exit_code == 0, result.output
    receipt = StudyStatisticalMethodReviewReceipt.model_validate_json(
        receipt_path.read_text(encoding="utf-8")
    )
    assert receipt.study_manifest_digest == fixture.manifest.manifest_digest
    assert receipt.protocol_set_digest == fixture.manifest.protocol_set_digest
    assert len(receipt.conditions) == len(fixture.manifest.conditions)


def test_study_review_registration_builds_bound_receipt_without_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture()
    manifest_path = tmp_path / "study-manifest.json"
    record_path = tmp_path / "registration-record.json"
    template_path = tmp_path / "registration-review.yaml"
    out = tmp_path / "registration-review.json"
    _write_json(manifest_path, fixture.manifest)
    record_path.write_bytes(fixture.registration_record_bytes)
    template_path.write_text(
        "\n".join(
            (
                "receipt_id: integration-registration-review",
                "reviewed_at_utc: '2025-01-02T00:00:00Z'",
                "reviewer_pseudonym: integration-reviewer",
                "registration_record_coverage_confirmed: true",
                "pre_observation_ordering_confirmed: true",
                "registration_reference_resolved: true",
                "registration_record_digest_match_confirmed: true",
                "registration_record_immutability_confirmed: true",
                "",
            )
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(rag_cmd_module, "run_repeated_live_study", _reject_dispatch)

    untouched = RUNNER.invoke(
        app,
        [
            "rag",
            "study",
            "review-registration",
            "--manifest",
            str(manifest_path),
            "--record",
            str(record_path),
            "--template",
            str(ROOT / "docs" / "templates" / "real_model_study_registration_review.yaml"),
            "--out",
            str(out),
        ],
    )
    assert untouched.exit_code == 2
    assert "Input should be True" in untouched.output
    assert not out.exists()

    result = RUNNER.invoke(
        app,
        [
            "rag",
            "study",
            "review-registration",
            "--manifest",
            str(manifest_path),
            "--record",
            str(record_path),
            "--template",
            str(template_path),
            "--out",
            str(out),
        ],
    )

    assert result.exit_code == 0, result.output
    receipt = StudyRegistrationReviewReceipt.model_validate_json(out.read_text(encoding="utf-8"))
    assert receipt.study_manifest_digest == fixture.manifest.manifest_digest
    assert receipt.registration_evidence_sha256 == (fixture.manifest.registration.evidence_digest)
    assert receipt.registration_reference_resolved is True


def test_study_review_registration_rejects_post_window_review(
    tmp_path: Path,
) -> None:
    fixture = _fixture()
    manifest_path = tmp_path / "study-manifest.json"
    record_path = tmp_path / "registration-record.json"
    template_path = tmp_path / "registration-review.json"
    out = tmp_path / "registration-review-receipt.json"
    _write_json(manifest_path, fixture.manifest)
    record_path.write_bytes(fixture.registration_record_bytes)
    _write_json(
        template_path,
        {
            "receipt_id": "late-registration-review",
            "reviewed_at_utc": "2025-02-02T00:00:00Z",
            "reviewer_pseudonym": "integration-reviewer",
            "registration_record_coverage_confirmed": True,
            "pre_observation_ordering_confirmed": True,
            "registration_reference_resolved": True,
            "registration_record_digest_match_confirmed": True,
            "registration_record_immutability_confirmed": True,
        },
    )

    result = RUNNER.invoke(
        app,
        [
            "rag",
            "study",
            "review-registration",
            "--manifest",
            str(manifest_path),
            "--record",
            str(record_path),
            "--template",
            str(template_path),
            "--out",
            str(out),
        ],
    )

    assert result.exit_code == 2
    assert "before the planned execution window" in result.output
    assert not out.exists()


def test_study_finalize_commits_an_exact_manifest_without_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture()
    template_path = tmp_path / "study-template.json"
    benchmark_path = tmp_path / "benchmark.json"
    protocol_paths = {
        condition_id: tmp_path / f"protocol-{index:03d}.json"
        for index, condition_id in enumerate(fixture.protocols)
    }
    out = tmp_path / "study-manifest.json"
    template = fixture.manifest.model_dump(
        mode="json",
        exclude={
            "manifest_digest",
            "protocol_set_digest",
            "hypothesis_decision_rule_digest",
        },
    )
    _write_json(template_path, template)
    _write_json(benchmark_path, fixture.benchmark)
    for condition_id, protocol in fixture.protocols.items():
        _write_json(protocol_paths[condition_id], protocol)
    monkeypatch.setattr(rag_cmd_module, "run_repeated_live_study", _reject_dispatch)
    arguments = [
        "rag",
        "study",
        "finalize",
        "--template",
        str(template_path),
        "--benchmark",
        str(benchmark_path),
        "--out",
        str(out),
    ]
    for condition_id, protocol_path in protocol_paths.items():
        arguments[arguments.index("--out") : arguments.index("--out")] = [
            "--protocol",
            f"{condition_id}={protocol_path}",
        ]

    result = RUNNER.invoke(app, arguments)
    repeated = RUNNER.invoke(app, arguments)

    assert result.exit_code == 0, result.output
    assert repeated.exit_code == 0, repeated.output
    persisted = RealModelStudyManifest.model_validate_json(out.read_text(encoding="utf-8"))
    assert persisted == fixture.manifest
    assert f"manifest digest: {fixture.manifest.manifest_digest}" in result.output


def test_study_bind_config_validates_then_atomically_publishes_both_arms(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture()
    condition_id = fixture.manifest.conditions[0].condition_id
    manifest_path = tmp_path / "study-manifest.json"
    benchmark_path = tmp_path / "benchmark.json"
    protocol_path = tmp_path / "protocol.json"
    compiled_path = tmp_path / "compiled-suite.json"
    baseline_path = tmp_path / "baseline.json"
    counterfactual_path = tmp_path / "counterfactual.json"
    baseline_out = tmp_path / "baseline.study-bound.json"
    counterfactual_out = tmp_path / "counterfactual.study-bound.json"
    baseline = _uncommitted_live_config("baseline")
    counterfactual = _uncommitted_live_config("counterfactual")
    for path, value in (
        (manifest_path, fixture.manifest),
        (benchmark_path, fixture.benchmark),
        (protocol_path, fixture.protocol),
        (compiled_path, {}),
        (baseline_path, baseline),
        (counterfactual_path, counterfactual),
    ):
        _write_json(path, value)

    monkeypatch.setattr(study_cmd_module, "load_compiled_suite", lambda _path: object())
    monkeypatch.setattr(rag_cmd_module, "run_repeated_live_study", _reject_dispatch)
    calls: list[str] = []

    def bind(**values: Any) -> LiveRunConfig:
        calls.append(values["arm_id"])
        assert values["condition_id"] == condition_id
        assert values["manifest"] == fixture.manifest
        assert values["benchmark"] == fixture.benchmark
        assert values["protocol"] == fixture.protocol
        config = values["config"]
        assert isinstance(config, LiveRunConfig)
        return _bound_config(config, fixture.manifest)

    monkeypatch.setattr(study_cmd_module, "bind_study_manifest_to_live_config", bind)
    result = RUNNER.invoke(
        app,
        [
            "rag",
            "study",
            "bind-config",
            "--manifest",
            str(manifest_path),
            "--benchmark",
            str(benchmark_path),
            "--condition-id",
            condition_id,
            "--protocol",
            str(protocol_path),
            "--compiled-suite",
            str(compiled_path),
            "--baseline-config",
            str(baseline_path),
            "--counterfactual-config",
            str(counterfactual_path),
            "--baseline-config-out",
            str(baseline_out),
            "--counterfactual-config-out",
            str(counterfactual_out),
        ],
    )

    assert result.exit_code == 0, result.output
    assert calls == ["baseline_evidence", "counterfactual_evidence"]
    persisted_baseline = LiveRunConfig.model_validate_json(baseline_out.read_text(encoding="utf-8"))
    persisted_counterfactual = LiveRunConfig.model_validate_json(
        counterfactual_out.read_text(encoding="utf-8")
    )
    assert (
        persisted_baseline.study_manifest_digest
        == fixture.manifest.manifest_digest
        == persisted_counterfactual.study_manifest_digest
    )


def test_study_bind_config_failure_cannot_leave_one_arm_published(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture()
    condition_id = fixture.manifest.conditions[0].condition_id
    manifest_path = tmp_path / "study-manifest.json"
    benchmark_path = tmp_path / "benchmark.json"
    protocol_path = tmp_path / "protocol.json"
    compiled_path = tmp_path / "compiled-suite.json"
    baseline_path = tmp_path / "baseline.json"
    counterfactual_path = tmp_path / "counterfactual.json"
    baseline_out = tmp_path / "baseline.study-bound.json"
    counterfactual_out = tmp_path / "counterfactual.study-bound.json"
    for path, value in (
        (manifest_path, fixture.manifest),
        (benchmark_path, fixture.benchmark),
        (protocol_path, fixture.protocol),
        (compiled_path, {}),
        (baseline_path, _uncommitted_live_config("baseline")),
        (counterfactual_path, _uncommitted_live_config("counterfactual")),
    ):
        _write_json(path, value)

    monkeypatch.setattr(study_cmd_module, "load_compiled_suite", lambda _path: object())

    def fail_second_arm(**values: Any) -> LiveRunConfig:
        if values["arm_id"] == "counterfactual_evidence":
            raise ValueError("counterfactual validation failed")
        config = values["config"]
        assert isinstance(config, LiveRunConfig)
        return _bound_config(config, fixture.manifest)

    monkeypatch.setattr(
        study_cmd_module,
        "bind_study_manifest_to_live_config",
        fail_second_arm,
    )
    result = RUNNER.invoke(
        app,
        [
            "rag",
            "study",
            "bind-config",
            "--manifest",
            str(manifest_path),
            "--benchmark",
            str(benchmark_path),
            "--condition-id",
            condition_id,
            "--protocol",
            str(protocol_path),
            "--compiled-suite",
            str(compiled_path),
            "--baseline-config",
            str(baseline_path),
            "--counterfactual-config",
            str(counterfactual_path),
            "--baseline-config-out",
            str(baseline_out),
            "--counterfactual-config-out",
            str(counterfactual_out),
        ],
    )

    assert result.exit_code == 2
    assert "counterfactual validation failed" in result.output
    assert not baseline_out.exists()
    assert not counterfactual_out.exists()


def test_study_analyze_publishes_the_replay_bundle_from_relative_evidence(
    tmp_path: Path,
) -> None:
    fixture = _fixture(
        responses=(False, False, False, False),
        real_provider_execution=True,
    )
    manifest_path = tmp_path / "study-manifest.json"
    benchmark_path = tmp_path / "benchmark.json"
    evidence_path = tmp_path / "evidence.json"
    registration_record_path = tmp_path / "registration-record.json"
    registration_review_path = tmp_path / "registration-review.json"
    statistical_method_review_path = tmp_path / "statistical-method-review.json"
    execution_review_path = tmp_path / "execution-review.json"
    out = tmp_path / "published-study"
    _write_json(manifest_path, fixture.manifest)
    _write_json(benchmark_path, fixture.benchmark)
    registration_record_path.write_bytes(fixture.registration_record_bytes)
    _write_json(registration_review_path, fixture.registration_review_receipt)
    _write_json(statistical_method_review_path, _method_review_receipt(fixture))
    execution_review_receipt = build_study_execution_review_receipt(
        manifest=fixture.manifest,
        benchmark=fixture.benchmark,
        protocols=fixture.protocols,
        report=_analyze(fixture),
        evidence=fixture.evidence_by_condition,
        **_execution_review_template(),
    )
    _write_json(execution_review_path, execution_review_receipt)
    descriptor_conditions = []
    for index, binding in enumerate(fixture.manifest.conditions):
        condition_id = binding.condition_id
        protocol_path = tmp_path / f"registered-protocol-{index:03d}.json"
        source_dir = tmp_path / f"source-{index:03d}"
        source_dir.mkdir()
        condition_evidence = fixture.evidence_by_condition[condition_id]
        _write_json(protocol_path, fixture.protocols[condition_id])
        _write_json(
            source_dir / "repeated-evidence-sensitivity-protocol.json",
            condition_evidence.protocol,
        )
        _write_json(
            source_dir / "baseline.runset.json",
            condition_evidence.baseline_runset,
        )
        _write_json(
            source_dir / "counterfactual.runset.json",
            condition_evidence.counterfactual_runset,
        )
        descriptor_conditions.append(
            {
                "condition_id": condition_id,
                "registered_protocol": protocol_path.name,
                "source_run_directory": source_dir.name,
            }
        )
    _write_json(
        evidence_path,
        {
            "schema_name": "real-model-study-evidence-input/v1",
            "registration_record": registration_record_path.name,
            "registration_review_receipt": registration_review_path.name,
            "statistical_method_review_receipt": statistical_method_review_path.name,
            "execution_review_receipt": execution_review_path.name,
            "conditions": descriptor_conditions,
        },
    )

    result = RUNNER.invoke(
        app,
        [
            "rag",
            "study",
            "analyze",
            "--manifest",
            str(manifest_path),
            "--benchmark",
            str(benchmark_path),
            "--evidence",
            str(evidence_path),
            "--out",
            str(out),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "hypothesis classification: supported" in result.output
    assert (out / "real-model-study-report.json").is_file()
    assert (out / "study-registration-record.json").read_bytes() == (
        fixture.registration_record_bytes
    )
    assert (out / "study-registration-review.json").is_file()
    assert (out / "study-statistical-method-review.json").is_file()
    assert (out / "study-execution-review.json").is_file()
    assert (out / "condition-000.baseline.source.runset.json").is_file()
    assert (out / "condition-000.counterfactual.source.runset.json").is_file()
    assert (out / "condition-003.observed-execution-provenance.json").is_file()
