from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from typer.testing import CliRunner

from agent_assure.cli.demo_cmd import _strict_exit_code
from agent_assure.cli.main import app
from agent_assure.demo.rag import RAG_THESIS_TITLE, render_rag_text
from agent_assure.schema.common import ComparisonClassification, GateState, ReasonCode

RUNNER = CliRunner()


def test_rag_demo_exits_zero_on_expected_retrieval_regression(tmp_path: Path) -> None:
    out_dir = tmp_path / "rag"
    result = RUNNER.invoke(
        app,
        [
            "demo",
            "rag",
            "--out",
            str(out_dir),
            "--clean",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0, result.output
    summary = json.loads(result.output)
    assert summary == _json(out_dir / "demo-summary.json")
    assert summary["demo"] == "rag"
    assert summary["status"] == "success"
    assert summary["underlying_exit_code"] == 1
    assert summary["thesis"] == RAG_THESIS_TITLE
    assert summary["output_equivalence"] == "preserved"
    assert summary["expected_regression_caught"] is True
    assert summary["blocking_reason_codes"] == [
        ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE.value
    ]

    visible = cast(dict[str, Any], summary["visible_final_output"])
    assert visible["case_id"] == "rag-pt-duration"
    assert visible["baseline"] == {"outcome": "approve", "recommendation": "approve"}
    assert visible["candidate"] == {"outcome": "approve", "recommendation": "approve"}

    process = cast(dict[str, Any], summary["retrieval_process_regression"])
    assert process["missing_evidence_links"] == ["claim-duration"]
    assert process["missing_required_source_ids"] == [
        "policy:acme-health:pt-coverage:duration-limit"
    ]
    assert process["retrieval_corpus_digest_state"] == "unchanged"
    assert process["baseline_retrieval_corpus_digest"] == process[
        "candidate_retrieval_corpus_digest"
    ]
    assert process["baseline_state"] == GateState.pass_.value
    assert process["candidate_state"] == GateState.fail.value
    assert process["classification"] == ComparisonClassification.new_failure.value
    assert process["fixture_equivalence"] == GateState.pass_.value
    assert process["ci_blocked_as_expected"] is True
    assert process["packet_gate_blocked_as_expected"] is True
    assert process["retrieval_drift"]["retrieval_jaccard_bps"] == 5000

    skew = cast(dict[str, Any], summary["corpus_version_skew"])
    assert skew["retrieval_corpus_digest_state"] == "changed"
    assert skew["candidate_state"] == GateState.pass_.value
    assert skew["classification"] == ComparisonClassification.provenance_only_change.value
    assert skew["advisory_only"] is True

    command_exits = {
        command["name"]: command["actual_exit_code"]
        for command in cast(list[dict[str, Any]], summary["commands"])
    }
    assert command_exits == {
        "compile-suite": 0,
        "run-baseline": 0,
        "run-reranker-candidate": 0,
        "evaluate-baseline": 0,
        "evaluate-reranker-candidate": 1,
        "compare-reranker-candidate": 1,
        "ci-report": 1,
        "ci-gate-packet": 1,
        "diff-render": 0,
        "run-corpus-skew-candidate": 0,
        "evaluate-corpus-skew-candidate": 0,
        "compare-corpus-skew-candidate": 0,
    }
    assert _strict_exit_code(summary) == 1
    assert str(out_dir) not in json.dumps(summary)

    artifacts = cast(dict[str, str], summary["artifacts"])
    for artifact in artifacts.values():
        assert (out_dir / artifact).exists()
    rendered_text = render_rag_text(summary)
    assert "retrieval corpus digest: unchanged" in rendered_text
    assert "advisory only: true" in rendered_text

    html = (out_dir / artifacts["evidence_diff_html"]).read_text(encoding="utf-8")
    assert RAG_THESIS_TITLE in html
    assert "Retrieval corpus digest" in html
    assert "unchanged" in html
    assert process["baseline_retrieval_corpus_digest"] in html
    assert "claim-duration" in html
    assert "ref-rag-duration-limit" in html
    assert ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE.value in html
    assert "<script" not in html.lower()
    assert "https://" not in html.lower()
    assert "http://" not in html.lower()


def _json(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload
