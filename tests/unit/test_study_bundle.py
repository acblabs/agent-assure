from __future__ import annotations

import json
from pathlib import Path

import pytest

import agent_assure.study_bundle as study_bundle_module
from agent_assure.reporting.study import write_real_model_study_artifacts
from agent_assure.schema.study import (
    StudyExecutionReviewReceipt,
    StudyRegistrationReviewReceipt,
    StudyStatisticalMethodReviewReceipt,
)
from agent_assure.study.analysis import StudyConditionEvidence, analyze_real_model_study
from agent_assure.study_bundle import (
    MAX_STUDY_BUNDLE_FILES,
    ValidatedStudyBundle,
    load_and_validate_study_bundle,
)
from agent_assure.study_execution_review import build_study_execution_review_receipt
from agent_assure.study_method_review import build_study_statistical_method_review_receipt
from tests.unit.study.test_real_model_study import _analyze, _fixture


def _write_bundle(
    tmp_path: Path,
    *,
    real_provider_execution: bool = False,
    execution_review: bool | None = None,
    statistical_method_review: bool | None = None,
) -> tuple[Path, object]:
    fixture = _fixture(
        responses=(False, True, True, True),
        real_provider_execution=real_provider_execution,
    )
    report = _analyze(fixture)
    should_review = real_provider_execution if execution_review is None else execution_review
    should_review_method = (
        real_provider_execution if statistical_method_review is None else statistical_method_review
    )
    method_review_receipt = (
        build_study_statistical_method_review_receipt(
            manifest=fixture.manifest,
            benchmark=fixture.benchmark,
            protocols=fixture.protocols,
            receipt_id="synthetic-statistical-method-review",
            reviewed_at_utc="2025-01-15T00:00:00Z",
            reviewer_pseudonym="independent-synthetic-statistician",
            reviewer_statistical_qualification_confirmed=True,
            reviewer_qualification_basis_types=("professional_statistical_practice",),
            reviewer_qualification_evidence_digest="0123456789abcdef" * 4,
            reviewer_qualification_basis=(
                "Training and applied experience in clustered exact binomial inference."
            ),
            reviewer_independent_of_design_execution_and_analysis=True,
            reviewer_independence_rationale=(
                "The test reviewer did not design, execute, or analyze this study."
            ),
            independence_design_basis_reviewed_and_accepted=True,
            independence_acceptance_rationale=(
                "Independent audit review supports the synthetic generator's separate "
                "cluster construction for this bounded deterministic test design."
            ),
            semantic_near_duplicate_audit_reviewed=True,
            semantic_near_duplicate_pseudoreplication_rejected=True,
            semantic_near_duplicate_review_rationale=(
                "Every synthetic cluster was compared and the audit found no unhandled "
                "semantic duplicate counted as a separate unit."
            ),
            benchmark_cluster_assignments_reviewed=True,
            independence_and_exchangeability_assumptions_reviewed=True,
            sampling_frame_and_estimand_reviewed=True,
            multiplicity_and_interval_method_reviewed=True,
            power_and_decision_boundary_reachability_reviewed=True,
            negative_control_design_reviewed=True,
        )
        if should_review_method
        else None
    )
    execution_review_receipt = (
        build_study_execution_review_receipt(
            manifest=fixture.manifest,
            benchmark=fixture.benchmark,
            protocols=fixture.protocols,
            report=report,
            evidence=fixture.evidence_by_condition,
            receipt_id="synthetic-execution-review",
            reviewed_at_utc="2025-04-01T00:00:00Z",
            reviewer_pseudonym="independent-synthetic-reviewer",
            reviewer_independent_of_execution=True,
            reviewer_independence_rationale=(
                "The deterministic test reviewer did not operate the provider execution."
            ),
            provider_log_review_scope=(
                "The reviewer inspected every synthetic provider log event across the full "
                "registered execution window and all request classes."
            ),
            provider_log_evidence_digest="1234567890abcdef" * 4,
            provider_account_review_scope=(
                "The reviewer reconciled the synthetic account usage ledger for the full "
                "execution window against every dispatched request."
            ),
            provider_account_evidence_digest="abcdef0123456789" * 4,
            provider_log_and_account_review_confirmed=True,
            provider_log_time_window_coverage_confirmed=True,
            provider_account_usage_reconciled=True,
            exhaustive_attempt_failure_retry_accounting_confirmed=True,
            provider_response_id_matches_confirmed=True,
            exact_runset_artifact_digest_matches_confirmed=True,
            provider_serving_fingerprint_availability_reviewed=True,
        )
        if should_review
        else None
    )
    out = tmp_path / "study-bundle"
    write_real_model_study_artifacts(
        manifest=fixture.manifest,
        benchmark=fixture.benchmark,
        protocols=fixture.protocols,
        evidence=fixture.evidence_by_condition,
        report=report,
        registration_record_bytes=fixture.registration_record_bytes,
        registration_review_receipt=fixture.registration_review_receipt,
        statistical_method_review_receipt=method_review_receipt,
        execution_review_receipt=execution_review_receipt,
        out_dir=out,
    )
    return out, report


def test_study_bundle_replays_every_pinned_source_artifact(tmp_path: Path) -> None:
    out, report = _write_bundle(tmp_path)

    verified = load_and_validate_study_bundle(out)

    assert verified.report == report
    assert verified.file_count == 6 + (5 * 4)
    assert verified.registration_evidence_verified is True
    assert verified.execution_review_verified is False
    assert verified.execution_review_receipt is None
    assert verified.statistical_method_review_verified is False
    assert verified.statistical_method_review_receipt is None
    assert verified.registration_record_sha256 == verified.manifest.registration.evidence_digest
    assert verified.total_bytes > 0
    assert tuple(verified.protocols) == tuple(
        item.condition_id for item in verified.manifest.conditions
    )
    with pytest.raises(TypeError):
        ValidatedStudyBundle()
    uninitialized = object.__new__(ValidatedStudyBundle)
    assert not uninitialized.is_mechanically_verified


def test_verified_bundle_derives_readiness_while_report_stays_fail_closed(
    tmp_path: Path,
) -> None:
    out, report = _write_bundle(tmp_path, real_provider_execution=True)

    verified = load_and_validate_study_bundle(out)

    assert report.registration_evidence_verified is False
    assert report.confirmatory_conclusion_permitted is False
    assert report.publication_eligible is False
    assert verified.registration_evidence_verified is True
    assert verified.execution_review_verified is True
    assert verified.execution_review_receipt is not None
    assert verified.statistical_method_review_verified is True
    assert verified.statistical_method_review_receipt is not None
    assert verified.is_publication_ready is True


def test_real_provider_bundle_without_post_execution_review_is_not_ready(
    tmp_path: Path,
) -> None:
    out, _report = _write_bundle(
        tmp_path,
        real_provider_execution=True,
        execution_review=False,
    )

    verified = load_and_validate_study_bundle(out)

    assert verified.execution_review_receipt is None
    assert verified.execution_review_verified is False
    assert verified.is_publication_ready is False


def test_real_provider_bundle_without_statistical_method_review_is_not_ready(
    tmp_path: Path,
) -> None:
    out, _report = _write_bundle(
        tmp_path,
        real_provider_execution=True,
        statistical_method_review=False,
    )

    verified = load_and_validate_study_bundle(out)

    assert verified.statistical_method_review_receipt is None
    assert verified.statistical_method_review_verified is False
    assert verified.is_publication_ready is False


def test_study_bundle_replays_invalidated_source_trio_without_provenance(
    tmp_path: Path,
) -> None:
    fixture = _fixture()
    condition_id = fixture.manifest.conditions[0].condition_id
    source = fixture.evidence_by_condition[condition_id]
    missing = StudyConditionEvidence(
        protocol=source.protocol,
        baseline_runset=source.baseline_runset,
        counterfactual_runset=source.counterfactual_runset,
        observed_execution_provenance=None,
    )
    evidence = {**fixture.evidence_by_condition, condition_id: missing}
    report = analyze_real_model_study(
        manifest=fixture.manifest,
        benchmark=fixture.benchmark,
        protocols=fixture.protocols,
        evidence=evidence,
    )
    out = tmp_path / "invalidated-study-bundle"
    write_real_model_study_artifacts(
        manifest=fixture.manifest,
        benchmark=fixture.benchmark,
        protocols=fixture.protocols,
        evidence=evidence,
        report=report,
        registration_record_bytes=fixture.registration_record_bytes,
        registration_review_receipt=fixture.registration_review_receipt,
        out_dir=out,
    )

    verified = load_and_validate_study_bundle(out)

    assert verified.report == report
    assert verified.evidence[condition_id] is not None
    assert verified.evidence[condition_id].observed_execution_provenance is None
    assert not (out / "condition-000.observed-execution-provenance.json").exists()
    assert verified.is_publication_ready is False


@pytest.mark.parametrize(
    "mutation",
    ("extra", "partial-condition", "noncanonical-json", "markdown-drift"),
)
def test_study_bundle_rejects_inventory_and_rendering_drift(
    tmp_path: Path,
    mutation: str,
) -> None:
    out, _report = _write_bundle(tmp_path)
    if mutation == "extra":
        (out / "unregistered-extra.json").write_text("{}\n", encoding="utf-8")
    elif mutation == "partial-condition":
        (out / "condition-000.observed-execution-provenance.json").unlink()
    elif mutation == "noncanonical-json":
        manifest_path = out / "real-model-study-manifest.json"
        manifest_path.write_text(
            manifest_path.read_text(encoding="utf-8") + " \n",
            encoding="utf-8",
        )
    else:
        markdown_path = out / "real-model-study-report.md"
        markdown_path.write_text(
            markdown_path.read_text(encoding="utf-8") + "drift\n",
            encoding="utf-8",
        )

    with pytest.raises(ValueError):
        load_and_validate_study_bundle(out)


def test_study_bundle_rejects_canonical_source_bytes_that_do_not_replay(
    tmp_path: Path,
) -> None:
    out, _report = _write_bundle(tmp_path)
    runset_path = out / "condition-000.baseline.source.runset.json"
    payload = json.loads(runset_path.read_text(encoding="utf-8"))
    payload["runset_id"] = "self-consistent-but-unregistered-runset"
    runset_path.write_bytes((json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8"))

    with pytest.raises(ValueError, match="does not exactly replay"):
        load_and_validate_study_bundle(out)


def test_study_bundle_enforces_an_aggregate_byte_ceiling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    out, _report = _write_bundle(tmp_path)
    monkeypatch.setattr(study_bundle_module, "MAX_STUDY_BUNDLE_TOTAL_BYTES", 1)

    with pytest.raises(ValueError):
        load_and_validate_study_bundle(out)


def test_study_bundle_file_bound_covers_the_full_schema_condition_limit() -> None:
    assert MAX_STUDY_BUNDLE_FILES == 8 + (5 * 64) == 328


def test_study_bundle_rejects_statistical_review_that_does_not_bind_design(
    tmp_path: Path,
) -> None:
    out, _report = _write_bundle(tmp_path, real_provider_execution=True)
    receipt_path = out / "study-statistical-method-review.json"
    source = StudyStatisticalMethodReviewReceipt.model_validate_json(
        receipt_path.read_text(encoding="utf-8")
    )
    values = source.model_dump(mode="json", exclude={"method_review_receipt_digest"})
    values["benchmark_digest"] = "f" * 64
    receipt = StudyStatisticalMethodReviewReceipt.build(**values)
    receipt_path.write_bytes(
        (json.dumps(receipt.model_dump(mode="json"), indent=2, sort_keys=True) + "\n").encode(
            "utf-8"
        )
    )

    with pytest.raises(ValueError, match="does not exactly bind"):
        load_and_validate_study_bundle(out)


def test_study_bundle_rejects_execution_review_that_does_not_bind_source_bytes(
    tmp_path: Path,
) -> None:
    out, _report = _write_bundle(tmp_path, real_provider_execution=True)
    receipt_path = out / "study-execution-review.json"
    source = StudyExecutionReviewReceipt.model_validate_json(
        receipt_path.read_text(encoding="utf-8")
    )
    values = source.model_dump(
        mode="json",
        exclude={"execution_review_receipt_digest"},
    )
    conditions = list(values["conditions"])
    conditions[0] = {
        **conditions[0],
        "baseline_runset_sha256": "f" * 64,
    }
    values["conditions"] = conditions
    receipt = StudyExecutionReviewReceipt.build(**values)
    receipt_path.write_bytes(
        (json.dumps(receipt.model_dump(mode="json"), indent=2, sort_keys=True) + "\n").encode(
            "utf-8"
        )
    )

    with pytest.raises(ValueError, match="does not exactly bind"):
        load_and_validate_study_bundle(out)


def test_study_bundle_rejects_execution_review_attempt_journal_substitution(
    tmp_path: Path,
) -> None:
    out, _report = _write_bundle(tmp_path, real_provider_execution=True)
    receipt_path = out / "study-execution-review.json"
    source = StudyExecutionReviewReceipt.model_validate_json(
        receipt_path.read_text(encoding="utf-8")
    )
    values = source.model_dump(
        mode="json",
        exclude={"execution_review_receipt_digest"},
    )
    conditions = list(values["conditions"])
    conditions[0] = {
        **conditions[0],
        "execution_attempt_journal_digest": "f" * 64,
    }
    values["conditions"] = conditions
    receipt = StudyExecutionReviewReceipt.build(**values)
    receipt_path.write_bytes(
        (json.dumps(receipt.model_dump(mode="json"), indent=2, sort_keys=True) + "\n").encode(
            "utf-8"
        )
    )

    with pytest.raises(ValueError, match="does not exactly bind"):
        load_and_validate_study_bundle(out)


def test_study_bundle_rejects_registration_record_byte_drift(tmp_path: Path) -> None:
    out, _report = _write_bundle(tmp_path)
    record_path = out / "study-registration-record.json"
    record_path.write_text('{"analysis_plan":"changed"}\n', encoding="utf-8")

    with pytest.raises(ValueError, match="manifest evidence digest"):
        load_and_validate_study_bundle(out)


def test_study_bundle_rejects_receipt_that_does_not_bind_manifest(
    tmp_path: Path,
) -> None:
    out, _report = _write_bundle(tmp_path)
    receipt_path = out / "study-registration-review.json"
    source = StudyRegistrationReviewReceipt.model_validate_json(
        receipt_path.read_text(encoding="utf-8")
    )
    values = source.model_dump(
        mode="json",
        exclude={"review_receipt_digest"},
    )
    values["registration_reference_id"] = "another-registration"
    receipt = StudyRegistrationReviewReceipt.build(**values)
    receipt_path.write_bytes(
        (json.dumps(receipt.model_dump(mode="json"), indent=2, sort_keys=True) + "\n").encode(
            "utf-8"
        )
    )

    with pytest.raises(ValueError, match="does not exactly bind"):
        load_and_validate_study_bundle(out)


def test_study_bundle_rejects_review_after_execution_window(tmp_path: Path) -> None:
    out, _report = _write_bundle(tmp_path)
    receipt_path = out / "study-registration-review.json"
    source = StudyRegistrationReviewReceipt.model_validate_json(
        receipt_path.read_text(encoding="utf-8")
    )
    values = source.model_dump(
        mode="json",
        exclude={"review_receipt_digest"},
    )
    values["reviewed_at_utc"] = "2025-02-02T00:00:00Z"
    receipt = StudyRegistrationReviewReceipt.build(**values)
    receipt_path.write_bytes(
        (json.dumps(receipt.model_dump(mode="json"), indent=2, sort_keys=True) + "\n").encode(
            "utf-8"
        )
    )

    with pytest.raises(ValueError, match="before the planned execution window"):
        load_and_validate_study_bundle(out)


@pytest.mark.parametrize(
    ("contents", "message"),
    (
        (b"", "must not be empty"),
        (b"\xff", "valid UTF-8 JSON"),
    ),
)
def test_study_bundle_rejects_unusable_registration_record_bytes(
    tmp_path: Path,
    contents: bytes,
    message: str,
) -> None:
    out, _report = _write_bundle(tmp_path)
    (out / "study-registration-record.json").write_bytes(contents)

    with pytest.raises(ValueError, match=message):
        load_and_validate_study_bundle(out)


def test_study_bundle_privacy_scans_non_rendered_registration_fields(
    tmp_path: Path,
) -> None:
    out, _report = _write_bundle(tmp_path)
    (out / "study-registration-record.json").write_text(
        '{"analysis_plan":"frozen","operator_note":"alice@example.com"}\n',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="sensitive or credential material"):
        load_and_validate_study_bundle(out)


@pytest.mark.parametrize(
    ("mutation", "expected_message"),
    (
        ("signed-uri", "sensitive or credential material"),
        ("nested-uri", "sensitive or credential material"),
        ("credential-key", "credential-bearing mapping key"),
    ),
)
def test_study_bundle_independently_rejects_structural_credentials(
    tmp_path: Path,
    mutation: str,
    expected_message: str,
) -> None:
    out, _report = _write_bundle(tmp_path)
    manifest_path = out / "real-model-study-manifest.json"
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    if mutation == "signed-uri":
        payload["limitations"][0] = "https://example.test/result?sig=x"
    elif mutation == "nested-uri":
        payload["limitations"][0] = (
            "https://example.test/?next=https%3A%2F%2Falice%3Asecret%40nested.test"
        )
    else:
        payload["https://alice:secret@example.test"] = "bounded"
    manifest_path.write_bytes(
        (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    )

    with pytest.raises(ValueError, match=expected_message):
        load_and_validate_study_bundle(out)
