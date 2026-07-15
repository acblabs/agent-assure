from __future__ import annotations

from pathlib import Path

import pytest

from agent_assure.authoring.compiler import compile_suite
from agent_assure.compare.invariant_diff import diff_behavior, diff_control_findings
from agent_assure.compare.provenance_diff import PROVENANCE_FIELDS
from agent_assure.compare.runsets import InvalidComparisonError, compare_runsets
from agent_assure.evaluation.evaluator import evaluate_runset
from agent_assure.runner.fixture_runner import load_variant_config, run_suite
from agent_assure.schema.common import ComparisonClassification, GateState, ReasonCode
from agent_assure.schema.provenance import Provenance
from agent_assure.schema.run import EvidenceItem, RunSet
from agent_assure.schema.suite import CompiledSuite

SUITE = Path("examples/prior_auth_synthetic/suite.yaml")
BASELINE = Path("examples/prior_auth_synthetic/variants/baseline.yaml")
EVIDENCE_CANDIDATE = Path(
    "examples/prior_auth_synthetic/variants/candidate_evidence_normalization.yaml"
)


def test_compare_classifies_new_candidate_failure() -> None:
    compiled = compile_suite(SUITE)
    baseline = _runset(compiled, BASELINE)
    candidate = _runset(compiled, EVIDENCE_CANDIDATE)

    report = compare_runsets(compiled, baseline, candidate)

    assert report.comparison_summary.classification is ComparisonClassification.new_failure
    assert report.comparison_summary.baseline_state is GateState.pass_
    assert report.comparison_summary.candidate_state is GateState.fail
    assert report.fixture_equivalence.state is GateState.pass_
    assert any(
        change.reason_code is ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE
        for change in report.control_changes
    )


def test_provenance_only_changes_do_not_create_verdict_findings() -> None:
    compiled = compile_suite(SUITE)
    baseline = _runset(compiled, BASELINE)
    candidate = _with_provenance_digest(baseline, field="code_digest", value="a" * 64)

    report = compare_runsets(compiled, baseline, candidate)

    assert (
        report.comparison_summary.classification
        is ComparisonClassification.provenance_only_change
    )
    assert report.comparison_summary.candidate_state is GateState.pass_
    assert report.comparison_summary.verdict_findings == ()
    assert report.provenance_changes[0].field == "code_digest"


def test_identical_runsets_are_classified_as_unchanged() -> None:
    compiled = compile_suite(SUITE)
    baseline = _runset(compiled, BASELINE)

    report = compare_runsets(compiled, baseline, baseline)

    assert report.comparison_summary.classification is ComparisonClassification.unchanged
    assert report.control_changes == ()
    assert report.behavioral_changes == ()
    assert report.provenance_changes == ()


def test_behavior_and_provenance_changes_keep_both_signals_in_classification() -> None:
    compiled = compile_suite(SUITE)
    baseline = _runset(compiled, BASELINE)
    first = baseline.runs[0]
    provenance = first.provenance.model_copy(update={"code_digest": "a" * 64})
    replacement = first.model_copy(
        update={
            "output_summary": "redacted output with nonblocking formatting change",
            "provenance": provenance,
        }
    )
    candidate = baseline.model_copy(
        update={
            "runset_id": f"{baseline.runset_id}-behavior-and-provenance",
            "runs": (replacement, *baseline.runs[1:]),
        }
    )

    report = compare_runsets(compiled, baseline, candidate)

    assert (
        report.comparison_summary.classification
        is ComparisonClassification.allowed_behavioral_and_provenance_change
    )
    assert report.behavioral_changes
    assert report.provenance_changes
    assert any(
        "provenance changes are reported separately" in item
        for item in report.verdict_explanations
    )


def test_provenance_diff_field_whitelist_tracks_schema_fields() -> None:
    schema_fields = tuple(
        field_name
        for field_name in Provenance.model_fields
        if field_name not in {"schema_version", "artifact_kind"}
    )

    assert PROVENANCE_FIELDS == schema_fields


def test_fixture_mismatch_is_invalid_comparison() -> None:
    compiled = compile_suite(SUITE)
    baseline = _runset(compiled, BASELINE)
    candidate = _with_provenance_digest(
        baseline,
        field="fixture_manifest_digest",
        value="b" * 64,
    )

    with pytest.raises(InvalidComparisonError) as exc_info:
        compare_runsets(compiled, baseline, candidate)

    report = exc_info.value.report
    assert report is not None
    assert report.comparison_summary.classification is ComparisonClassification.invalid_comparison
    assert report.fixture_equivalence.state is GateState.fail


def test_control_diff_uses_stable_finding_identity_not_message_text() -> None:
    compiled = compile_suite(SUITE)
    candidate = _runset(compiled, EVIDENCE_CANDIDATE)
    baseline_report = evaluate_runset(compiled, candidate)
    finding = baseline_report.failed_controls[0]
    reworded = finding.model_copy(update={"message": "same failure with clearer wording"})
    candidate_report = baseline_report.model_copy(update={"failed_controls": (reworded,)})

    changes = diff_control_findings(baseline_report, candidate_report)

    assert len(changes) == 1
    assert changes[0].classification is ComparisonClassification.persistent_failure


def test_behavior_diff_includes_evidence_item_digest_changes() -> None:
    compiled = compile_suite(SUITE)
    baseline = _runset(compiled, BASELINE)
    first = baseline.runs[0]
    baseline_item = EvidenceItem(
        artifact_kind="evidence-item",
        ref_id="evidence-digest-ref",
        source_id="source-1",
        content_digest="a" * 64,
    )
    baseline_first = first.model_copy(update={"evidence_items": (baseline_item,)})
    baseline_with_item = baseline.model_copy(
        update={
            "runset_id": f"{baseline.runset_id}-with-evidence-item",
            "runs": (baseline_first, *baseline.runs[1:]),
        }
    )
    candidate_item = baseline_item.model_copy(update={"content_digest": "b" * 64})
    candidate_first = baseline_first.model_copy(update={"evidence_items": (candidate_item,)})
    candidate = baseline_with_item.model_copy(
        update={
            "runset_id": f"{baseline.runset_id}-changed-evidence-item",
            "runs": (candidate_first, *baseline.runs[1:]),
        }
    )

    changes = diff_behavior(baseline_with_item, candidate)

    assert {change.field for change in changes} == {"evidence_items"}


def _runset(compiled: CompiledSuite, variant_path: Path) -> RunSet:
    return run_suite(compiled, load_variant_config(variant_path), SUITE.parent)


def _with_provenance_digest(runset: RunSet, *, field: str, value: str) -> RunSet:
    first = runset.runs[0]
    provenance = first.provenance.model_copy(update={field: value})
    replacement = first.model_copy(update={"provenance": provenance})
    return runset.model_copy(
        update={
            "runset_id": f"{runset.runset_id}-{field}",
            "runs": (replacement, *runset.runs[1:]),
        }
    )
