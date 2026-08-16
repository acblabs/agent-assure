from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from agent_assure.cli.main import app
from agent_assure.graph.builder import build_evidence_graph
from agent_assure.reporting.graph import write_evidence_graph
from agent_assure.schema.graph import AssuranceEvidenceGraph, EvidenceGraphSubjectPayload

RUNNER = CliRunner()


def _write_graph(path: Path) -> AssuranceEvidenceGraph:
    graph = build_evidence_graph(
        subject=EvidenceGraphSubjectPayload(
            subject_type="run_set",
            subject_id="graph-cli-runset",
            subject_digest="a" * 64,
        )
    )
    write_evidence_graph(graph, path)
    return graph


def test_graph_validate_and_digest_commands_report_canonical_identity(
    tmp_path: Path,
) -> None:
    path = tmp_path / "assurance-evidence-graph.json"
    graph = _write_graph(path)

    validation = RUNNER.invoke(app, ["graph", "validate", str(path)])
    digest = RUNNER.invoke(app, ["graph", "digest", str(path)])

    assert validation.exit_code == 0, validation.output
    assert graph.contract_id in validation.output
    assert graph.graph_digest in validation.output
    assert digest.exit_code == 0, digest.output
    assert digest.output.strip() == graph.graph_digest


def test_graph_cli_validation_is_fail_closed_and_value_free(tmp_path: Path) -> None:
    path = tmp_path / "forged-graph.json"
    _write_graph(path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["graph_digest"] = "0" * 64
    payload["untrusted_secret"] = "alice@example.com"
    path.write_text(json.dumps(payload), encoding="utf-8")

    result = RUNNER.invoke(app, ["graph", "validate", str(path)])

    assert result.exit_code != 0
    assert "validation failed" in result.output
    assert "alice@example.com" not in result.output
