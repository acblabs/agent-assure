from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from agent_assure.demo.common import (
    DemoError,
    ExpectedCommandResult,
    artifact_path,
    copy_example_resource,
    prepare_output_dir,
    run_cli_command,
    write_json,
)
from agent_assure.examples.prior_auth_synthetic.rag import (
    RAG_BASELINE_VARIANT_ID,
    RAG_CORPUS_VERSION_SKEW_VARIANT_ID,
    RAG_RERANKER_REGRESSION_VARIANT_ID,
    CounterfactualFamilyEvaluation,
    CounterfactualQueryFamily,
    evaluate_counterfactual_family,
    load_counterfactual_query_families,
    retrieval_diff_summary,
    retrieval_output_payload,
    retrieve_for_variant,
)
from agent_assure.schema.common import ComparisonClassification, GateState, ReasonCode
from agent_assure.schema.comparison import ComparisonSummary
from agent_assure.schema.evaluation import EvaluationSummary
from agent_assure.schema.packet import EvidencePacket
from agent_assure.schema.run import AgentRunRecord, RunSet
from agent_assure.schema.suite import CompiledSuite

RAG_CASE_ID = "rag-pt-duration"
MISSING_CLAIM_ID = "claim-duration"
RAG_THESIS_TITLE = "Output equivalence is not retrieval-process equivalence"


def run_rag_demo(out_dir: Path, *, clean: bool) -> dict[str, object]:
    root = prepare_output_dir(out_dir, clean=clean)
    example_dir = copy_example_resource(
        "prior_auth_synthetic",
        root / "example" / "prior_auth_synthetic",
        owner_root=root,
    )
    compiled_path = root / "prior-auth-rag.compiled.json"
    manifest_path = root / "prior-auth-rag.fixture-manifest.json"
    baseline_runset_path = root / "baseline.runset.json"
    candidate_runset_path = root / "candidate-reranker-regression.runset.json"
    skew_runset_path = root / "candidate-corpus-version-skew.runset.json"
    baseline_report_dir = root / "baseline-report"
    candidate_report_dir = root / "reranker-regression-report"
    comparison_report_dir = root / "comparison-report"
    ci_report_dir = root / "ci-report"
    skew_report_dir = root / "corpus-skew-report"
    skew_comparison_dir = root / "corpus-skew-comparison-report"
    evidence_diff_path = root / "evidence-diff.html"
    summary_path = root / "demo-summary.json"

    suite_yaml = example_dir / "rag_suite.yaml"
    baseline_variant = example_dir / "variants" / "rag_baseline.yaml"
    candidate_variant = example_dir / "variants" / "candidate_rag_reranker_regression.yaml"
    skew_variant = example_dir / "variants" / "candidate_rag_corpus_version_skew.yaml"

    command_results: list[ExpectedCommandResult] = []
    command_results.append(
        run_cli_command(
            name="compile-suite",
            args=[
                "suite",
                "compile",
                str(suite_yaml),
                "--out",
                str(compiled_path),
                "--manifest",
                str(manifest_path),
            ],
            out_dir=root,
            expected_exit_codes={0},
            cwd=root,
        )
    )
    command_results.append(
        run_cli_command(
            name="run-baseline",
            args=[
                "suite",
                "run",
                str(compiled_path),
                "--variant",
                str(baseline_variant),
                "--manifest",
                str(manifest_path),
                "--source",
                str(suite_yaml),
                "--out",
                str(baseline_runset_path),
            ],
            out_dir=root,
            expected_exit_codes={0},
            cwd=root,
        )
    )
    command_results.append(
        run_cli_command(
            name="run-reranker-candidate",
            args=[
                "suite",
                "run",
                str(compiled_path),
                "--variant",
                str(candidate_variant),
                "--manifest",
                str(manifest_path),
                "--source",
                str(suite_yaml),
                "--out",
                str(candidate_runset_path),
            ],
            out_dir=root,
            expected_exit_codes={0},
            cwd=root,
        )
    )
    command_results.append(
        run_cli_command(
            name="evaluate-baseline",
            args=[
                "evaluate",
                str(baseline_runset_path),
                "--suite",
                str(compiled_path),
                "--out-dir",
                str(baseline_report_dir),
            ],
            out_dir=root,
            expected_exit_codes={0},
            cwd=root,
        )
    )
    command_results.append(
        run_cli_command(
            name="evaluate-reranker-candidate",
            args=[
                "evaluate",
                str(candidate_runset_path),
                "--suite",
                str(compiled_path),
                "--out-dir",
                str(candidate_report_dir),
            ],
            out_dir=root,
            expected_exit_codes={1},
            cwd=root,
        )
    )
    command_results.append(
        run_cli_command(
            name="compare-reranker-candidate",
            args=[
                "compare",
                str(baseline_runset_path),
                str(candidate_runset_path),
                "--suite",
                str(compiled_path),
                "--out-dir",
                str(comparison_report_dir),
            ],
            out_dir=root,
            expected_exit_codes={1},
            cwd=root,
        )
    )
    command_results.append(
        run_cli_command(
            name="ci-report",
            args=[
                "ci",
                str(candidate_runset_path),
                "--suite",
                str(compiled_path),
                "--baseline",
                str(baseline_runset_path),
                "--out-dir",
                str(ci_report_dir),
            ],
            out_dir=root,
            expected_exit_codes={1},
            cwd=root,
        )
    )
    packet_path = ci_report_dir / "evidence-packet.json"
    command_results.append(
        run_cli_command(
            name="ci-gate-packet",
            args=["ci", "gate", str(packet_path)],
            out_dir=root,
            expected_exit_codes={1},
            cwd=root,
        )
    )
    command_results.append(
        run_cli_command(
            name="diff-render",
            args=[
                "diff",
                "render",
                "--baseline",
                str(baseline_runset_path),
                "--candidate",
                str(candidate_runset_path),
                "--comparison",
                str(comparison_report_dir / "comparison-summary.json"),
                "--packet",
                str(packet_path),
                "--out",
                str(evidence_diff_path),
                "--title",
                RAG_THESIS_TITLE,
            ],
            out_dir=root,
            expected_exit_codes={0},
            cwd=root,
        )
    )
    command_results.append(
        run_cli_command(
            name="run-corpus-skew-candidate",
            args=[
                "suite",
                "run",
                str(compiled_path),
                "--variant",
                str(skew_variant),
                "--manifest",
                str(manifest_path),
                "--source",
                str(suite_yaml),
                "--out",
                str(skew_runset_path),
            ],
            out_dir=root,
            expected_exit_codes={0},
            cwd=root,
        )
    )
    command_results.append(
        run_cli_command(
            name="evaluate-corpus-skew-candidate",
            args=[
                "evaluate",
                str(skew_runset_path),
                "--suite",
                str(compiled_path),
                "--out-dir",
                str(skew_report_dir),
            ],
            out_dir=root,
            expected_exit_codes={0},
            cwd=root,
        )
    )
    command_results.append(
        run_cli_command(
            name="compare-corpus-skew-candidate",
            args=[
                "compare",
                str(baseline_runset_path),
                str(skew_runset_path),
                "--suite",
                str(compiled_path),
                "--out-dir",
                str(skew_comparison_dir),
            ],
            out_dir=root,
            expected_exit_codes={0},
            cwd=root,
        )
    )

    summary = _build_summary(
        root=root,
        example_dir=example_dir,
        compiled_suite_path=compiled_path,
        baseline_runset_path=baseline_runset_path,
        candidate_runset_path=candidate_runset_path,
        skew_runset_path=skew_runset_path,
        baseline_summary_path=baseline_report_dir / "evaluation-summary.json",
        candidate_summary_path=candidate_report_dir / "evaluation-summary.json",
        skew_summary_path=skew_report_dir / "evaluation-summary.json",
        comparison_summary_path=comparison_report_dir / "comparison-summary.json",
        skew_comparison_summary_path=skew_comparison_dir / "comparison-summary.json",
        packet_path=packet_path,
        evidence_diff_path=evidence_diff_path,
        command_results=tuple(command_results),
    )
    _assert_success_summary(summary, root=root)
    write_json(summary_path, summary)
    return summary


def render_rag_text(summary: dict[str, object]) -> str:
    visible = cast(dict[str, Any], summary["visible_final_output"])
    baseline = cast(dict[str, Any], visible["baseline"])
    candidate = cast(dict[str, Any], visible["candidate"])
    process = cast(dict[str, Any], summary["retrieval_process_regression"])
    skew = cast(dict[str, Any], summary["corpus_version_skew"])
    counterfactual = cast(dict[str, Any], summary["counterfactual_robustness"])
    artifacts = cast(dict[str, Any], summary["artifacts"])
    missing_links = cast(list[str], process["missing_evidence_links"])
    missing_sources = cast(list[str], process["missing_required_source_ids"])
    reason_codes = cast(list[str], summary["blocking_reason_codes"])
    candidate_families = _counterfactual_report_families(counterfactual, "candidate")
    candidate_escalations = _counterfactual_escalation_text(candidate_families)
    return "\n".join(
        (
            "agent-assure RAG provenance demo",
            "",
            "Final visible output:",
            f"  case: {visible['case_id']}",
            (
                "  baseline:  "
                f"recommendation={baseline['recommendation']}; outcome={baseline['outcome']}"
            ),
            (
                "  candidate: "
                f"recommendation={candidate['recommendation']}; outcome={candidate['outcome']}"
            ),
            f"  output equivalence: {summary['output_equivalence']}",
            "",
            "Retrieval-process assurance:",
            f"  retrieval corpus digest: {process['retrieval_corpus_digest_state']}",
            f"  missing required source: {', '.join(missing_sources)}",
            f"  missing evidence link: {', '.join(missing_links)}",
            f"  reason: {', '.join(reason_codes)}",
            f"  classification: {process['classification']}",
            "",
            "Corpus-version skew:",
            f"  retrieval corpus digest: {skew['retrieval_corpus_digest_state']}",
            f"  classification: {skew['classification']}",
            f"  advisory only: {str(skew['advisory_only']).lower()}",
            "",
            "Counterfactual RAG robustness:",
            f"  framing: {counterfactual['framing']}",
            (
                "  semantic equivalence proven: "
                f"{str(counterfactual['semantic_equivalence_proven']).lower()}"
            ),
            f"  candidate escalated variants: {candidate_escalations}",
            "",
            "CI gate:",
            "  blocked as expected for the reranker regression",
            "",
            "Artifacts:",
            f"  {artifacts['summary']}",
            f"  {artifacts['baseline_report']}",
            f"  {artifacts['candidate_report']}",
            f"  {artifacts['comparison_report']}",
            f"  {artifacts['corpus_skew_comparison_report']}",
            f"  {artifacts['evidence_packet']}",
            f"  {artifacts['evidence_diff_html']}",
            "",
            "Demo result:",
            "  success: same answer, same corpus digest, dropped claim support caught",
        )
    )


def _build_summary(
    *,
    root: Path,
    example_dir: Path,
    compiled_suite_path: Path,
    baseline_runset_path: Path,
    candidate_runset_path: Path,
    skew_runset_path: Path,
    baseline_summary_path: Path,
    candidate_summary_path: Path,
    skew_summary_path: Path,
    comparison_summary_path: Path,
    skew_comparison_summary_path: Path,
    packet_path: Path,
    evidence_diff_path: Path,
    command_results: tuple[ExpectedCommandResult, ...],
) -> dict[str, object]:
    baseline_runset = _load_runset(baseline_runset_path)
    compiled_suite = _load_compiled_suite(compiled_suite_path)
    candidate_runset = _load_runset(candidate_runset_path)
    skew_runset = _load_runset(skew_runset_path)
    baseline_summary = _load_evaluation_summary(baseline_summary_path)
    candidate_summary = _load_evaluation_summary(candidate_summary_path)
    skew_summary = _load_evaluation_summary(skew_summary_path)
    comparison_summary = _load_comparison_summary(comparison_summary_path)
    skew_comparison_summary = _load_comparison_summary(skew_comparison_summary_path)
    packet = _load_packet(packet_path)
    baseline_run = _run_by_case(baseline_runset, RAG_CASE_ID)
    candidate_run = _run_by_case(candidate_runset, RAG_CASE_ID)
    skew_run = _run_by_case(skew_runset, RAG_CASE_ID)
    request = _load_request(example_dir)
    baseline_retrieval = retrieve_for_variant(
        example_dir,
        request,
        variant_id=RAG_BASELINE_VARIANT_ID,
    )
    candidate_retrieval = retrieve_for_variant(
        example_dir,
        request,
        variant_id=RAG_RERANKER_REGRESSION_VARIANT_ID,
    )
    skew_retrieval = retrieve_for_variant(
        example_dir,
        request,
        variant_id=RAG_CORPUS_VERSION_SKEW_VARIANT_ID,
    )
    hero_drift = retrieval_diff_summary(baseline_retrieval, candidate_retrieval)
    skew_drift = retrieval_diff_summary(baseline_retrieval, skew_retrieval)
    counterfactual_families = load_counterfactual_query_families(
        example_dir,
        compiled_suite=compiled_suite,
    )
    baseline_counterfactual = tuple(
        evaluate_counterfactual_family(
            example_dir,
            family,
            variant_id=RAG_BASELINE_VARIANT_ID,
            canonical_decision_matches_family_expectation=(
                _run_matches_counterfactual_expectations(
                    baseline_run,
                    (family,),
                )
            ),
        )
        for family in counterfactual_families
    )
    candidate_counterfactual = tuple(
        evaluate_counterfactual_family(
            example_dir,
            family,
            variant_id=RAG_RERANKER_REGRESSION_VARIANT_ID,
            canonical_decision_matches_family_expectation=(
                _run_matches_counterfactual_expectations(
                    candidate_run,
                    (family,),
                )
            ),
        )
        for family in counterfactual_families
    )
    blocking_reason_codes = sorted(
        {
            finding.reason_code.value
            for finding in candidate_summary.findings
            if finding.state is GateState.fail
        }
    )
    missing_links = sorted(
        _claim_id_from_target(finding.target)
        for finding in candidate_summary.findings
        if finding.reason_code is ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE
        and finding.target.startswith("claim:")
    )
    expected_regression_caught = _expected_regression_caught(
        baseline_summary=baseline_summary,
        candidate_summary=candidate_summary,
        skew_summary=skew_summary,
        comparison_summary=comparison_summary,
        skew_comparison_summary=skew_comparison_summary,
        baseline_run=baseline_run,
        candidate_run=candidate_run,
        skew_run=skew_run,
        blocking_reason_codes=blocking_reason_codes,
        missing_links=missing_links,
        hero_drift=hero_drift,
        skew_drift=skew_drift,
        baseline_counterfactual=baseline_counterfactual,
        candidate_counterfactual=candidate_counterfactual,
        command_results=command_results,
    )
    return {
        "demo": "rag",
        "status": "success" if expected_regression_caught else "failure",
        "underlying_exit_code": _underlying_exit_code(command_results),
        "thesis": RAG_THESIS_TITLE,
        "output_equivalence": (
            "preserved"
            if _visible_output(baseline_run) == _visible_output(candidate_run)
            else "changed"
        ),
        "expected_regression_caught": expected_regression_caught,
        "blocking_reason_codes": blocking_reason_codes,
        "visible_final_output": {
            "case_id": RAG_CASE_ID,
            "baseline": {
                "recommendation": baseline_run.recommendation,
                "outcome": baseline_run.outcome,
            },
            "candidate": {
                "recommendation": candidate_run.recommendation,
                "outcome": candidate_run.outcome,
            },
        },
        "retrieval_process_regression": {
            "missing_evidence_links": missing_links,
            "missing_required_source_ids": list(
                cast(tuple[str, ...], hero_drift["missing_required_source_ids"])
            ),
            "retrieval_corpus_digest_state": (
                "unchanged" if not hero_drift["corpus_digest_changed"] else "changed"
            ),
            "baseline_retrieval_corpus_digest": baseline_run.provenance.retrieval_corpus_digest,
            "candidate_retrieval_corpus_digest": candidate_run.provenance.retrieval_corpus_digest,
            "candidate_state": candidate_summary.state.value,
            "baseline_state": baseline_summary.state.value,
            "classification": comparison_summary.classification.value,
            "fixture_equivalence": comparison_summary.fixture_equivalence_state.value,
            "ci_blocked_as_expected": _command_exit(command_results, "ci-report") == 1,
            "packet_gate_blocked_as_expected": _command_exit(command_results, "ci-gate-packet")
            == 1,
            "retrieval_drift": hero_drift,
            "baseline_retrieval_output": retrieval_output_payload(baseline_retrieval),
            "candidate_retrieval_output": retrieval_output_payload(candidate_retrieval),
        },
        "corpus_version_skew": {
            "baseline_retrieval_corpus_digest": baseline_run.provenance.retrieval_corpus_digest,
            "candidate_retrieval_corpus_digest": skew_run.provenance.retrieval_corpus_digest,
            "retrieval_corpus_digest_state": (
                "changed" if skew_drift["corpus_digest_changed"] else "unchanged"
            ),
            "candidate_state": skew_summary.state.value,
            "classification": skew_comparison_summary.classification.value,
            "advisory_only": (
                skew_summary.state is GateState.pass_
                and skew_comparison_summary.classification
                is ComparisonClassification.provenance_only_change
            ),
            "retrieval_drift": skew_drift,
            "candidate_retrieval_output": retrieval_output_payload(skew_retrieval),
        },
        "counterfactual_robustness": {
            "framing": "fixture_author_declared_metamorphic_family",
            "semantic_equivalence_proven": False,
            "baseline": [
                evaluation.report_payload() for evaluation in baseline_counterfactual
            ],
            "candidate": [
                evaluation.report_payload() for evaluation in candidate_counterfactual
            ],
        },
        "artifacts": {
            "summary": artifact_path(root / "demo-summary.json", root=root),
            "compiled_suite": artifact_path(root / "prior-auth-rag.compiled.json", root=root),
            "fixture_manifest": artifact_path(
                root / "prior-auth-rag.fixture-manifest.json",
                root=root,
            ),
            "baseline_runset": artifact_path(baseline_runset_path, root=root),
            "candidate_runset": artifact_path(candidate_runset_path, root=root),
            "corpus_skew_runset": artifact_path(skew_runset_path, root=root),
            "baseline_report": artifact_path(
                root / "baseline-report" / "evaluation-report.md",
                root=root,
            ),
            "candidate_report": artifact_path(
                root / "reranker-regression-report" / "evaluation-report.md",
                root=root,
            ),
            "comparison_report": artifact_path(
                root / "comparison-report" / "comparison-report.md",
                root=root,
            ),
            "corpus_skew_comparison_report": artifact_path(
                root / "corpus-skew-comparison-report" / "comparison-report.md",
                root=root,
            ),
            "evidence_packet": artifact_path(packet_path, root=root),
            "evidence_diff_html": artifact_path(evidence_diff_path, root=root),
        },
        "packet_id": packet.packet_id,
        "commands": [result.model_dump(root=root) for result in command_results],
    }


def _expected_regression_caught(
    *,
    baseline_summary: EvaluationSummary,
    candidate_summary: EvaluationSummary,
    skew_summary: EvaluationSummary,
    comparison_summary: ComparisonSummary,
    skew_comparison_summary: ComparisonSummary,
    baseline_run: AgentRunRecord,
    candidate_run: AgentRunRecord,
    skew_run: AgentRunRecord,
    blocking_reason_codes: list[str],
    missing_links: list[str],
    hero_drift: dict[str, object],
    skew_drift: dict[str, object],
    baseline_counterfactual: tuple[CounterfactualFamilyEvaluation, ...],
    candidate_counterfactual: tuple[CounterfactualFamilyEvaluation, ...],
    command_results: tuple[ExpectedCommandResult, ...],
) -> bool:
    return (
        baseline_summary.state is GateState.pass_
        and candidate_summary.state is GateState.fail
        and skew_summary.state is GateState.pass_
        and _visible_output(baseline_run) == _visible_output(candidate_run)
        and _visible_output(baseline_run) == _visible_output(skew_run)
        and baseline_run.recommendation == candidate_run.recommendation == "approve"
        and baseline_run.outcome == candidate_run.outcome == "approve"
        and baseline_run.provenance.retrieval_corpus_digest
        == candidate_run.provenance.retrieval_corpus_digest
        and baseline_run.provenance.retrieval_corpus_digest
        != skew_run.provenance.retrieval_corpus_digest
        and missing_links == [MISSING_CLAIM_ID]
        and blocking_reason_codes == [ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE.value]
        and cast(tuple[str, ...], hero_drift["missing_required_source_ids"])
        == ("policy:acme-health:pt-coverage:duration-limit",)
        and hero_drift["corpus_digest_changed"] is False
        and skew_drift["corpus_digest_changed"] is True
        and comparison_summary.classification is ComparisonClassification.new_failure
        and skew_comparison_summary.classification
        is ComparisonClassification.provenance_only_change
        and comparison_summary.fixture_equivalence_state is GateState.pass_
        and skew_comparison_summary.fixture_equivalence_state is GateState.pass_
        and _counterfactual_acceptance_met(
            baseline_counterfactual,
            candidate_counterfactual,
        )
        and _command_exit(command_results, "ci-report") == 1
        and _command_exit(command_results, "ci-gate-packet") == 1
        and all(result.matched for result in command_results)
    )


def _assert_success_summary(summary: dict[str, object], *, root: Path) -> None:
    if summary["status"] != "success":
        raise DemoError("RAG demo did not prove the expected retrieval-process regression")
    artifacts = cast(dict[str, str], summary["artifacts"])
    required_artifact_names = (
        "summary",
        "baseline_report",
        "candidate_report",
        "comparison_report",
        "corpus_skew_comparison_report",
        "evidence_packet",
        "evidence_diff_html",
    )
    for name in required_artifact_names:
        relative_path = artifacts[name]
        if not relative_path:
            raise DemoError(f"RAG demo summary omitted artifact path: {name}")
        if name == "summary":
            continue
        if not (root / relative_path).exists():
            raise DemoError(f"RAG demo artifact is missing: {relative_path}")


def _load_runset(path: Path) -> RunSet:
    return RunSet.model_validate_json(path.read_text(encoding="utf-8"))


def _load_compiled_suite(path: Path) -> CompiledSuite:
    return CompiledSuite.model_validate_json(path.read_text(encoding="utf-8"))


def _load_evaluation_summary(path: Path) -> EvaluationSummary:
    return EvaluationSummary.model_validate_json(path.read_text(encoding="utf-8"))


def _load_comparison_summary(path: Path) -> ComparisonSummary:
    return ComparisonSummary.model_validate_json(path.read_text(encoding="utf-8"))


def _load_packet(path: Path) -> EvidencePacket:
    return EvidencePacket.model_validate_json(path.read_text(encoding="utf-8"))


def _load_request(example_dir: Path) -> dict[str, object]:
    path = example_dir / "fixtures" / "rag" / "requests" / "rag-pt-duration.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise DemoError(f"RAG request fixture root must be an object: {path}")
    return {str(key): value for key, value in payload.items()}


def _run_by_case(runset: RunSet, case_id: str) -> AgentRunRecord:
    for run in runset.runs:
        if run.case_id == case_id:
            return run
    raise DemoError(f"expected case is missing from run set {runset.runset_id}: {case_id}")


def _visible_output(run: AgentRunRecord) -> tuple[str, str]:
    return run.recommendation, run.outcome


def _run_matches_counterfactual_expectations(
    run: AgentRunRecord,
    families: tuple[CounterfactualQueryFamily, ...],
) -> bool:
    return all(
        (
            family.expected_recommendation is None
            or run.recommendation == family.expected_recommendation
        )
        and run.outcome in family.allowed_outcomes
        for family in families
    )


def _counterfactual_escalation_text(families: list[dict[str, Any]]) -> str:
    escalations = [
        f"{family['query_family_id']}:{variant_id}"
        for family in families
        for variant_id in cast(list[str], family["escalated_variants"])
    ]
    return ", ".join(escalations) if escalations else "none"


def _counterfactual_report_families(
    counterfactual: dict[str, Any],
    key: str,
) -> list[dict[str, Any]]:
    value = counterfactual.get(key)
    if not isinstance(value, list):
        raise TypeError(f"counterfactual_robustness.{key} must be a list")
    families: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise TypeError(f"counterfactual_robustness.{key}[{index}] must be an object")
        query_family_id = item.get("query_family_id")
        if not isinstance(query_family_id, str) or not query_family_id:
            raise TypeError(
                f"counterfactual_robustness.{key}[{index}].query_family_id "
                "must be a non-empty string"
            )
        escalated_variants = item.get("escalated_variants")
        if not isinstance(escalated_variants, (list, tuple)) or not all(
            isinstance(variant_id, str) for variant_id in escalated_variants
        ):
            raise TypeError(
                f"counterfactual_robustness.{key}[{index}].escalated_variants "
                "must be a sequence of strings"
            )
        families.append(item)
    return families


def _counterfactual_acceptance_met(
    baseline: tuple[CounterfactualFamilyEvaluation, ...],
    candidate: tuple[CounterfactualFamilyEvaluation, ...],
) -> bool:
    return (
        bool(baseline)
        and all(
            evaluation.canonical_decision_matches_family_expectation is True
            and evaluation.preserved_material_claim_support
            and not evaluation.escalated_variants
            for evaluation in baseline
        )
        and any(
            evaluation.canonical_decision_matches_family_expectation is True
            and not evaluation.preserved_material_claim_support
            and evaluation.escalated_variants
            for evaluation in candidate
        )
    )


def _claim_id_from_target(target: str) -> str:
    return target.removeprefix("claim:")


def _command_exit(results: tuple[ExpectedCommandResult, ...], name: str) -> int | None:
    for result in results:
        if result.name == name:
            return result.actual_exit_code
    return None


def _underlying_exit_code(results: tuple[ExpectedCommandResult, ...]) -> int:
    for name in (
        "ci-gate-packet",
        "ci-report",
        "compare-reranker-candidate",
        "evaluate-reranker-candidate",
    ):
        exit_code = _command_exit(results, name)
        if exit_code is not None:
            return exit_code
    return 0
