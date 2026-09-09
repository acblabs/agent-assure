from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

import agent_assure.study.analysis as study_analysis_module
from agent_assure.io_limits import MAX_ARTIFACT_JSON_BYTES
from agent_assure.privacy.detectors import MAX_PRIVACY_SCAN_CHARS
from agent_assure.reporting import stochastic_sensitivity as stochastic_writer
from agent_assure.reporting import study as study_writer
from agent_assure.reporting.study import (
    StudyPrivacyError,
    write_real_model_study_artifacts,
)
from agent_assure.rooted_io import RootedDirectoryDescriptor
from agent_assure.schema.run import RunSet
from agent_assure.schema.stochastic_sensitivity import (
    RepeatedEvidenceSensitivityProtocol,
)
from agent_assure.schema.study import (
    MAX_STUDY_CONDITIONS,
    RealModelStudyReport,
    StudyObservedExecutionProvenance,
)
from agent_assure.study.analysis import StudyConditionEvidence, analyze_real_model_study
from agent_assure.study_bundle import load_and_validate_study_bundle
from agent_assure.study_limits import (
    STUDY_BUNDLE_BASE_FILE_COUNT,
    STUDY_BUNDLE_FILES_PER_EXECUTED_CONDITION,
)
from tests.unit.rag.test_repeated_live_workflow import _maximum_journaled_pair
from tests.unit.study.test_real_model_study import (
    _analyze,
    _fixture,
    _replace_runset_records,
)


def test_large_generation_requires_an_explicit_scoped_entry_bound(tmp_path: Path) -> None:
    texts = {f"artifact-{index:02d}.json": "{}\n" for index in range(33)}
    expected = tuple(texts)

    with pytest.raises(ValueError, match="exceeds its declared entry bound"):
        stochastic_writer.publish_generation(
            tmp_path / "default-bound",
            texts,
            expected_filenames=expected,
        )

    written = stochastic_writer.publish_generation(
        tmp_path / "scoped-bound",
        texts,
        expected_filenames=expected,
        max_output_entries=len(texts),
    )

    assert tuple(written) == expected


@pytest.mark.skipif(os.name == "nt", reason="POSIX parent-swap regression")
def test_generation_publication_rejects_parent_swap_after_anchored_acquisition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requested_parent = tmp_path / "requested-parent"
    moved_parent = tmp_path / "moved-parent"
    outside_parent = tmp_path / "outside-parent"
    requested_parent.mkdir()
    outside_parent.mkdir()
    output = requested_parent / "generation"
    original_open = stochastic_writer.open_or_create_rooted_directory_from_filesystem_root
    swapped = False

    def swap_after_acquisition(
        directory: Path,
        *,
        label: str,
        mode: int = 0o700,
    ) -> RootedDirectoryDescriptor:
        nonlocal swapped
        lease = original_open(directory, label=label, mode=mode)
        if directory == requested_parent and not swapped:
            requested_parent.rename(moved_parent)
            requested_parent.symlink_to(outside_parent, target_is_directory=True)
            swapped = True
        return lease

    monkeypatch.setattr(
        stochastic_writer,
        "open_or_create_rooted_directory_from_filesystem_root",
        swap_after_acquisition,
    )

    with pytest.raises((OSError, ValueError), match="repeated sensitivity output parent"):
        stochastic_writer.publish_generation(
            output,
            {"artifact.json": "{}\n"},
            expected_filenames=("artifact.json",),
        )

    assert swapped
    assert not (outside_parent / output.name).exists()
    assert not (moved_parent / output.name).exists()


def test_study_inventory_supports_the_declared_64_condition_boundary(
    tmp_path: Path,
) -> None:
    expected_count = (
        STUDY_BUNDLE_BASE_FILE_COUNT
        + STUDY_BUNDLE_FILES_PER_EXECUTED_CONDITION * MAX_STUDY_CONDITIONS
    )
    texts = {f"artifact-{index:03d}.json": "{}\n" for index in range(expected_count)}
    expected = tuple(texts)

    assert MAX_STUDY_CONDITIONS == 64
    assert study_writer._STUDY_MAX_OUTPUT_ENTRIES == expected_count
    written = stochastic_writer.publish_generation(
        tmp_path / "maximum-study-inventory",
        texts,
        expected_filenames=expected,
        max_output_entries=study_writer._STUDY_MAX_OUTPUT_ENTRIES,
    )

    assert len(written) == expected_count


def test_study_writer_publishes_an_exact_replayable_generation(tmp_path: Path) -> None:
    fixture = _fixture(responses=(False, True, True, True))
    report = _analyze(fixture)
    out = tmp_path / "published-study"

    first = write_real_model_study_artifacts(
        manifest=fixture.manifest,
        benchmark=fixture.benchmark,
        protocols=fixture.protocols,
        evidence=fixture.evidence_by_condition,
        report=report,
        registration_record_bytes=fixture.registration_record_bytes,
        registration_review_receipt=fixture.registration_review_receipt,
        out_dir=out,
    )
    second = write_real_model_study_artifacts(
        manifest=fixture.manifest,
        benchmark=fixture.benchmark,
        protocols=fixture.protocols,
        evidence=fixture.evidence_by_condition,
        report=report,
        registration_record_bytes=fixture.registration_record_bytes,
        registration_review_receipt=fixture.registration_review_receipt,
        out_dir=out,
    )

    expected_names = {
        "real-model-study-manifest.json",
        "process-equivalence-benchmark.json",
        "study-registration-record.json",
        "study-registration-review.json",
        "real-model-study-report.json",
        "real-model-study-report.md",
        *{
            f"condition-{index:03d}.{suffix}"
            for index in range(4)
            for suffix in (
                "registered.protocol.json",
                "source.protocol.json",
                "baseline.source.runset.json",
                "counterfactual.source.runset.json",
                "observed-execution-provenance.json",
            )
        },
    }
    assert set(first) == expected_names
    assert first == second
    assert {path.name for path in out.iterdir()} == expected_names

    persisted_report = RealModelStudyReport.model_validate(
        json.loads(first["real-model-study-report.json"].read_text(encoding="utf-8"))
    )
    persisted_protocols: dict[str, RepeatedEvidenceSensitivityProtocol] = {}
    persisted_evidence: dict[str, StudyConditionEvidence] = {}
    for index, binding in enumerate(fixture.manifest.conditions):
        prefix = f"condition-{index:03d}"
        persisted_registered = RepeatedEvidenceSensitivityProtocol.model_validate(
            json.loads(first[f"{prefix}.registered.protocol.json"].read_text(encoding="utf-8"))
        )
        persisted_source = RepeatedEvidenceSensitivityProtocol.model_validate(
            json.loads(first[f"{prefix}.source.protocol.json"].read_text(encoding="utf-8"))
        )
        persisted_baseline = RunSet.model_validate(
            json.loads(first[f"{prefix}.baseline.source.runset.json"].read_text(encoding="utf-8"))
        )
        persisted_counterfactual = RunSet.model_validate(
            json.loads(
                first[f"{prefix}.counterfactual.source.runset.json"].read_text(encoding="utf-8")
            )
        )
        persisted_provenance = StudyObservedExecutionProvenance.model_validate(
            json.loads(
                first[f"{prefix}.observed-execution-provenance.json"].read_text(encoding="utf-8")
            )
        )
        persisted_protocols[binding.condition_id] = persisted_registered
        persisted_evidence[binding.condition_id] = StudyConditionEvidence(
            protocol=persisted_source,
            baseline_runset=persisted_baseline,
            counterfactual_runset=persisted_counterfactual,
            observed_execution_provenance=persisted_provenance,
        )
    replay = analyze_real_model_study(
        manifest=fixture.manifest,
        benchmark=fixture.benchmark,
        protocols=persisted_protocols,
        evidence=persisted_evidence,
    )

    assert persisted_report == report == replay
    markdown = first["real-model-study-report.md"].read_text(encoding="utf-8")
    assert "It is not a provider-wide, causal, safety, or compliance claim." in markdown
    assert "synthetic structured decision" not in markdown
    assert "## Preregistration and decision rule" in markdown
    assert "- Registration method: `version_control_commit`" in markdown
    assert "- Materiality threshold: `0.500000`" in markdown
    assert "- Baseline configuration digest:" in markdown
    assert "- Counterfactual configuration digest:" in markdown
    assert "- Observed model identities:" in markdown
    assert "- Pairing identity verified: true" in markdown
    assert "- Variance-reduction claim permitted: false" in markdown
    assert "- Statistical sufficiency state:" in markdown
    assert "- Operational records (runs / cost reported / latency reported):" in markdown
    assert "- Latency (total/minimum/maximum):" in markdown


@pytest.mark.parametrize(
    ("condition_count", "real_provider_execution"),
    (
        (6, True),
        (MAX_STUDY_CONDITIONS, False),
    ),
)
def test_study_writer_and_bundle_verifier_accept_declared_condition_scale(
    tmp_path: Path,
    condition_count: int,
    real_provider_execution: bool,
) -> None:
    fixture = _fixture(
        condition_count=condition_count,
        real_provider_execution=real_provider_execution,
    )
    report = _analyze(fixture)
    out = tmp_path / f"published-study-{condition_count}"

    written = write_real_model_study_artifacts(
        manifest=fixture.manifest,
        benchmark=fixture.benchmark,
        protocols=fixture.protocols,
        evidence=fixture.evidence_by_condition,
        report=report,
        registration_record_bytes=fixture.registration_record_bytes,
        registration_review_receipt=fixture.registration_review_receipt,
        out_dir=out,
    )
    verified = load_and_validate_study_bundle(out)
    markdown = written["real-model-study-report.md"].read_text(encoding="utf-8")

    assert len(markdown) > MAX_PRIVACY_SCAN_CHARS
    assert len(verified.report.conditions) == condition_count
    assert verified.report == report


def test_study_writer_rejects_a_report_not_derived_from_supplied_evidence(
    tmp_path: Path,
) -> None:
    fixture = _fixture(responses=(True, True, True, True))
    other_report = _analyze(_fixture(responses=(False, False, False, False)))

    with pytest.raises(ValueError, match="does not exactly regenerate"):
        write_real_model_study_artifacts(
            manifest=fixture.manifest,
            benchmark=fixture.benchmark,
            protocols=fixture.protocols,
            evidence=fixture.evidence_by_condition,
            report=other_report,
            registration_record_bytes=fixture.registration_record_bytes,
            registration_review_receipt=fixture.registration_review_receipt,
            out_dir=tmp_path / "must-not-publish",
        )

    assert not (tmp_path / "must-not-publish").exists()


def test_study_writer_rejects_source_evidence_that_redaction_would_change(
    tmp_path: Path,
) -> None:
    fixture = _fixture()
    condition_id = fixture.manifest.conditions[0].condition_id

    def inject_identifier(payload: dict[str, Any]) -> dict[str, Any]:
        payload["output_summary"] = "Contact alice@example.com for the raw response."
        return payload

    unsafe = StudyConditionEvidence(
        protocol=fixture.protocol,
        baseline_runset=_replace_runset_records(
            fixture.evidence.baseline_runset,
            inject_identifier,
        ),
        counterfactual_runset=fixture.evidence.counterfactual_runset,
        observed_execution_provenance=fixture.evidence.observed_execution_provenance,
    )
    evidence = {**fixture.evidence_by_condition, condition_id: unsafe}

    with pytest.raises(StudyPrivacyError, match="sensitive or credential material"):
        write_real_model_study_artifacts(
            manifest=fixture.manifest,
            benchmark=fixture.benchmark,
            protocols=fixture.protocols,
            evidence=evidence,
            report=_analyze(fixture),
            registration_record_bytes=fixture.registration_record_bytes,
            registration_review_receipt=fixture.registration_review_receipt,
            out_dir=tmp_path / "must-not-publish",
        )

    assert not (tmp_path / "must-not-publish").exists()


@pytest.mark.parametrize(
    "credential_uri",
    (
        "https://alice:secret@example.test/v1",
        "https://example.test/v1?sig=x",
        "https://example.test/v1?next=https%3A%2F%2Falice%3Asecret%40nested.test",
    ),
)
def test_study_writer_rejects_structural_credentials_in_nested_runset_strings(
    tmp_path: Path,
    credential_uri: str,
) -> None:
    fixture = _fixture()
    condition_id = fixture.manifest.conditions[0].condition_id

    def inject_credential_uri(payload: dict[str, Any]) -> dict[str, Any]:
        payload["output_summary"] = credential_uri
        return payload

    unsafe = StudyConditionEvidence(
        protocol=fixture.protocol,
        baseline_runset=_replace_runset_records(
            fixture.evidence.baseline_runset,
            inject_credential_uri,
        ),
        counterfactual_runset=fixture.evidence.counterfactual_runset,
        observed_execution_provenance=fixture.evidence.observed_execution_provenance,
    )

    with pytest.raises(StudyPrivacyError, match="credential material"):
        write_real_model_study_artifacts(
            manifest=fixture.manifest,
            benchmark=fixture.benchmark,
            protocols=fixture.protocols,
            evidence={**fixture.evidence_by_condition, condition_id: unsafe},
            report=_analyze(fixture),
            registration_record_bytes=fixture.registration_record_bytes,
            registration_review_receipt=fixture.registration_review_receipt,
            out_dir=tmp_path / "must-not-publish",
        )

    assert not (tmp_path / "must-not-publish").exists()


def test_study_writer_preserves_invalidated_sources_without_a_provenance_sidecar(
    tmp_path: Path,
) -> None:
    fixture = _fixture()
    condition_id = fixture.manifest.conditions[0].condition_id
    missing = StudyConditionEvidence(
        protocol=fixture.evidence.protocol,
        baseline_runset=fixture.evidence.baseline_runset,
        counterfactual_runset=fixture.evidence.counterfactual_runset,
        observed_execution_provenance=None,
    )

    evidence = {**fixture.evidence_by_condition, condition_id: missing}
    report = analyze_real_model_study(
        manifest=fixture.manifest,
        benchmark=fixture.benchmark,
        protocols=fixture.protocols,
        evidence=evidence,
    )
    out = tmp_path / "invalidated-study"

    written = write_real_model_study_artifacts(
        manifest=fixture.manifest,
        benchmark=fixture.benchmark,
        protocols=fixture.protocols,
        evidence=evidence,
        report=report,
        registration_record_bytes=fixture.registration_record_bytes,
        registration_review_receipt=fixture.registration_review_receipt,
        out_dir=out,
    )

    assert report.conditions[0].state.value == "invalidated"
    assert "condition-000.source.protocol.json" in written
    assert "condition-000.observed-execution-provenance.json" not in written


def test_study_writer_enforces_the_bundle_aggregate_byte_ceiling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture()
    monkeypatch.setattr(study_writer, "MAX_STUDY_BUNDLE_TOTAL_BYTES", 1)

    def unreachable(*args: object, **kwargs: object) -> None:
        pytest.fail("oversized input reached evidence copying or reanalysis")

    monkeypatch.setattr(study_writer, "_validated_condition_evidence", unreachable)
    monkeypatch.setattr(study_writer, "analyze_real_model_study", unreachable)

    with pytest.raises(ValueError, match="maximum supported aggregate size"):
        write_real_model_study_artifacts(
            manifest=fixture.manifest,
            benchmark=fixture.benchmark,
            protocols=fixture.protocols,
            evidence=fixture.evidence_by_condition,
            report=_analyze(fixture),
            registration_record_bytes=fixture.registration_record_bytes,
            registration_review_receipt=fixture.registration_review_receipt,
            out_dir=tmp_path / "must-not-publish",
        )

    assert not (tmp_path / "must-not-publish").exists()


def test_study_artifact_budget_rejects_before_retaining_the_excess_artifact() -> None:
    accumulator = study_writer._StudyArtifactAccumulator(max_total_bytes=10)
    accumulator.add("first.json", "123456")

    with pytest.raises(ValueError, match="maximum supported aggregate size"):
        accumulator.add("second.json", "12345")

    assert accumulator.texts == {"first.json": "123456"}
    assert accumulator.total_bytes == 6


def test_study_bundle_transports_a_maximum_journaled_runset_through_the_64_mib_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture()
    report = _analyze(fixture)
    _, large_baseline, _ = _maximum_journaled_pair()
    condition_id = fixture.manifest.conditions[0].condition_id
    original_counterfactual = fixture.evidence_by_condition[condition_id].counterfactual_runset
    evidence = {
        **fixture.evidence_by_condition,
        condition_id: StudyConditionEvidence(
            protocol=fixture.protocols[condition_id],
            baseline_runset=large_baseline,
            counterfactual_runset=original_counterfactual,
            observed_execution_provenance=None,
        ),
    }
    # This regression isolates byte transport. Exact semantic replay (including
    # invalid evidence) is covered separately, while the maximum-bound repeated
    # test above exercises the complete journal reconciliation and analysis.
    monkeypatch.setattr(study_writer, "analyze_real_model_study", lambda **_: report)
    monkeypatch.setattr(study_analysis_module, "analyze_real_model_study", lambda **_: report)

    out = tmp_path / "large-invalidated-study"
    written = write_real_model_study_artifacts(
        manifest=fixture.manifest,
        benchmark=fixture.benchmark,
        protocols=fixture.protocols,
        evidence=evidence,
        report=report,
        registration_record_bytes=fixture.registration_record_bytes,
        registration_review_receipt=fixture.registration_review_receipt,
        out_dir=out,
    )
    assert (
        written["condition-000.baseline.source.runset.json"].stat().st_size
        > MAX_ARTIFACT_JSON_BYTES
    )

    replayed = load_and_validate_study_bundle(out)
    assert replayed.report == report
    replayed_evidence = replayed.evidence[condition_id]
    assert replayed_evidence is not None
    assert replayed_evidence.baseline_runset == large_baseline
    assert replayed_evidence.counterfactual_runset == original_counterfactual
