from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

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
