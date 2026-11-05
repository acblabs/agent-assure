from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

import agent_assure.sensitivity_comparison as sensitivity_comparison_module
from agent_assure.ci import GateOutcome, gate_evidence_sensitivity_report
from agent_assure.rag.sensitivity import execute_sensitivity_experiment
from agent_assure.reporting.sensitivity import (
    render_sensitivity_html,
    render_sensitivity_markdown,
    sensitivity_report_json_text,
)
from agent_assure.schema.comparison import ComparisonSummary
from agent_assure.schema.sensitivity import (
    EvidenceSensitivityExpectedRelation,
    RAGSensitivityReport,
)
from agent_assure.sensitivity_comparison import (
    derive_sensitivity_comparison,
    sensitivity_comparison_binding_error,
)

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "examples" / "evidence_sensitivity"


@pytest.fixture(scope="module")
def responsive_report() -> RAGSensitivityReport:
    return execute_sensitivity_experiment(
        suite_path=EXAMPLE / "responsive_suite.yaml",
        baseline_corpus_dir=EXAMPLE / "corpora" / "policy_a",
        counterfactual_corpus_dir=EXAMPLE / "corpora" / "policy_b",
        knowledge_contract_path=EXAMPLE / "knowledge-contract.yaml",
        expected_relation=EvidenceSensitivityExpectedRelation.decision_flip,
    ).report


def test_comparison_derivation_rejects_forged_report_before_gate_pass(
    responsive_report: RAGSensitivityReport,
) -> None:
    comparison = derive_sensitivity_comparison(responsive_report)
    assert sensitivity_comparison_binding_error(comparison, responsive_report) is None
    assert gate_evidence_sensitivity_report(responsive_report).outcome is GateOutcome.pass_

    forged_report = responsive_report.model_copy(
        update={"artifact_kind": "forged-evidence-sensitivity-report"}
    )

    with pytest.raises(ValidationError, match="artifact_kind"):
        derive_sensitivity_comparison(forged_report)
    with pytest.raises(ValidationError, match="artifact_kind"):
        sensitivity_comparison_binding_error(comparison, forged_report)

    decision = gate_evidence_sensitivity_report(forged_report)
    assert decision.outcome is GateOutcome.invalid
    assert decision.exit_code == 2


def test_comparison_derivation_requires_public_report_admission(
    responsive_report: RAGSensitivityReport,
) -> None:
    payload = responsive_report.model_dump(
        mode="json",
        exclude={"report_digest"},
        warnings="error",
    )
    payload["schema_version"] = "0.6.5"
    invalid_historical_report = RAGSensitivityReport.build(**payload)
    round_tripped = RAGSensitivityReport.model_validate(
        invalid_historical_report.model_dump(mode="json", warnings="error")
    )
    assert round_tripped == invalid_historical_report

    with pytest.raises(ValueError, match="failed JSON Schema validation"):
        derive_sensitivity_comparison(invalid_historical_report)

    comparison = derive_sensitivity_comparison(responsive_report)
    with pytest.raises(ValueError, match="failed JSON Schema validation"):
        sensitivity_comparison_binding_error(comparison, invalid_historical_report)
    for renderer in (
        sensitivity_report_json_text,
        render_sensitivity_markdown,
        render_sensitivity_html,
    ):
        with pytest.raises(ValueError, match="failed JSON Schema validation"):
            renderer(invalid_historical_report)

    decision = gate_evidence_sensitivity_report(invalid_historical_report)
    assert decision.outcome is GateOutcome.invalid
    assert decision.exit_code == 2


def test_comparison_binding_requires_exact_comparison_admission(
    responsive_report: RAGSensitivityReport,
) -> None:
    comparison = derive_sensitivity_comparison(responsive_report)
    forged_comparison = comparison.model_copy(update={"artifact_kind": "forged-comparison-summary"})

    with pytest.raises(ValidationError, match="artifact_kind"):
        sensitivity_comparison_binding_error(forged_comparison, responsive_report)

    archival_payload = comparison.model_dump(mode="json", warnings="error")
    archival_payload["schema_version"] = "0.6.5"
    archival_comparison = ComparisonSummary.model_validate(archival_payload)

    with pytest.raises(ValueError, match="archival-only"):
        sensitivity_comparison_binding_error(archival_comparison, responsive_report)


@pytest.mark.parametrize("operation", ("derive", "bind"))
def test_comparison_typed_valid_input_cannot_bypass_a_failed_public_boundary(
    responsive_report: RAGSensitivityReport,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    comparison = derive_sensitivity_comparison(responsive_report)
    boundary_error = ValueError("writer-schema boundary rejected this typed-valid input")

    def reject_boundary(*_args: object, **_kwargs: object) -> None:
        raise boundary_error

    monkeypatch.setattr(
        sensitivity_comparison_module,
        "validate_loaded_artifact_model",
        reject_boundary,
    )
    with pytest.raises(ValueError) as rejected:
        if operation == "derive":
            derive_sensitivity_comparison(responsive_report)
        else:
            sensitivity_comparison_binding_error(comparison, responsive_report)
    assert rejected.value is boundary_error


def test_comparison_binding_preserves_comparison_first_typed_error_precedence(
    responsive_report: RAGSensitivityReport,
) -> None:
    comparison = derive_sensitivity_comparison(responsive_report).model_copy(
        update={"artifact_kind": "forged-comparison-summary"}
    )
    report = responsive_report.model_copy(
        update={"artifact_kind": "forged-evidence-sensitivity-report"}
    )

    with pytest.raises(ValidationError) as rejected:
        sensitivity_comparison_binding_error(comparison, report)

    error = rejected.value.errors()[0]
    assert error["loc"] == ("artifact_kind",)
    assert error["ctx"]["expected"] == "'comparison-summary'"
    assert rejected.value.__suppress_context__ is True


def test_comparison_derivation_owns_its_report_snapshot_and_rechecks_later_mutation(
    responsive_report: RAGSensitivityReport,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = responsive_report.model_copy(deep=True)
    original_compare = sensitivity_comparison_module.compare_runsets
    derived_snapshots: list[object] = []

    def mutate_caller_after_admission(suite, baseline, counterfactual, **kwargs):
        # Frozen model assignment is not a trust proof: unsafe construction or
        # object mutation can still forge a caller-owned nested model.
        assert baseline is not report.baseline_runset
        assert baseline.runs[0] is not report.baseline_runset.runs[0]
        derived_snapshots.append(baseline)
        object.__setattr__(report.baseline_runset.runs[0], "tools", ("different-tool",))
        return original_compare(suite, baseline, counterfactual, **kwargs)

    monkeypatch.setattr(
        sensitivity_comparison_module,
        "compare_runsets",
        mutate_caller_after_admission,
    )
    comparison = derive_sensitivity_comparison(report)
    assert comparison.baseline_runset_digest == responsive_report.baseline_arm.runset_digest

    # The completed call used its admitted snapshot; a second public call must
    # inspect the changed caller bytes instead of reusing its earlier proof.
    with pytest.raises(ValueError):
        derive_sensitivity_comparison(report)
    assert len(derived_snapshots) == 1


def test_comparison_binding_owns_its_comparison_snapshot_and_rechecks_later_mutation(
    responsive_report: RAGSensitivityReport,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    comparison = derive_sensitivity_comparison(responsive_report).model_copy(deep=True)
    original_admit = sensitivity_comparison_module.validate_loaded_artifact_model

    def mutate_caller_after_admission(payload, model, *, kind):
        admitted = original_admit(payload, model, kind=kind)
        if kind == "comparison-summary":
            assert admitted is not comparison
            object.__setattr__(comparison, "baseline_runset_digest", "0" * 64)
        return admitted

    monkeypatch.setattr(
        sensitivity_comparison_module,
        "validate_loaded_artifact_model",
        mutate_caller_after_admission,
    )
    assert sensitivity_comparison_binding_error(comparison, responsive_report) is None
    assert sensitivity_comparison_binding_error(comparison, responsive_report) is not None
