from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import TypeAdapter, ValidationError
from typer.testing import CliRunner

from agent_assure.artifact_io import file_sha256
from agent_assure.cli import demo_cmd
from agent_assure.cli.main import app
from agent_assure.demo.assure_the_assurance import (
    _offline_network_guard,
    render_assure_the_assurance_text,
)
from agent_assure.demo.common import DemoError
from agent_assure.reporting.campaign import validate_mutation_campaign_artifact_generation
from agent_assure.reporting.packet import (
    load_evidence_packet,
    packet_summary_files_binding_error,
)
from agent_assure.schema.validation import validate_artifact

RUNNER = CliRunner()


def test_prepared_walkthrough_console_facts_match_the_authoritative_renderer() -> None:
    walkthrough = (
        Path(__file__).resolve().parents[2]
        / "docs"
        / "assets"
        / "assure_the_assurance_walkthrough.txt"
    ).read_text(encoding="utf-8")
    expected = walkthrough.split("EXPECTED CONSOLE FACTS:\n\n", 1)[1].split(
        "\n\nThe wrapper returns",
        1,
    )[0]
    summary: dict[str, object] = {
        "ordinary_baseline_state": "pass",
        "strong_mutation_state": "caught",
        "weakened_mutation_state": "survived",
        "control_efficacy_gate_state": "fail",
        "required_survivor_count": 1,
        "critical_survivor_count": 1,
        "unrelated_failure_counted_as_detection": False,
        "artifacts": {
            "mutation_results": "mutation-results",
            "control_efficacy_report": "control-efficacy-report.json",
            "control_efficacy_config": "control-efficacy-config.json",
            "assurance_evidence_graph": "assurance-evidence-graph.json",
            "mutation_evidence_graph": "mutation-evidence-graph.json",
            "evidence_packet": "evidence-packet.json",
            "reviewer_facing_report": "reviewer-facing-report.md",
            "summary": "demo-summary.json",
        },
    }

    assert expected == render_assure_the_assurance_text(summary)


def test_assure_the_assurance_demo_is_offline_portable_and_rejects_substitution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    detached_cwd = tmp_path / "detached-cwd"
    detached_cwd.mkdir()
    monkeypatch.chdir(detached_cwd)
    out = tmp_path / "assure-the-assurance"

    result = RUNNER.invoke(
        app,
        [
            "demo",
            "assure-the-assurance",
            "--out",
            str(out),
            "--clean",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0, result.output
    summary = cast(dict[str, Any], json.loads(result.output))
    assert summary == _json(out / "demo-summary.json")
    assert summary["demo"] == "assure-the-assurance"
    assert summary["status"] == "success"
    assert summary["underlying_exit_code"] == 1
    assert {
        "ordinary_baseline_state": summary["ordinary_baseline_state"],
        "strong_mutation_state": summary["strong_mutation_state"],
        "weakened_mutation_state": summary["weakened_mutation_state"],
        "control_efficacy_gate_state": summary["control_efficacy_gate_state"],
        "required_survivor_count": summary["required_survivor_count"],
        "critical_survivor_count": summary["critical_survivor_count"],
        "unrelated_failure_counted_as_detection": summary["unrelated_failure_counted_as_detection"],
        "unrelated_failure_detector_state": summary["unrelated_failure_detector_state"],
    } == {
        "ordinary_baseline_state": "pass",
        "strong_mutation_state": "caught",
        "weakened_mutation_state": "survived",
        "control_efficacy_gate_state": "fail",
        "required_survivor_count": 1,
        "critical_survivor_count": 1,
        "unrelated_failure_counted_as_detection": False,
        "unrelated_failure_detector_state": "survived",
    }
    assert summary["unrelated_failure_probes"] == {
        "control_mismatch": {
            "detector_state": "survived",
            "matched_finding_count": 0,
        },
        "reason_mismatch": {
            "detector_state": "survived",
            "matched_finding_count": 0,
        },
        "target_mismatch": {
            "detector_state": "survived",
            "matched_finding_count": 0,
        },
    }
    assert str(out) not in json.dumps(summary)

    commands = cast(list[dict[str, Any]], summary["commands"])
    assert {command["name"]: command["actual_exit_code"] for command in commands} == {
        "compile-suite": 0,
        "run-baseline": 0,
        "evaluate-baseline": 0,
        "ci-gate-efficacy-packet": 1,
    }
    assert all(command["matched"] is True for command in commands)
    assert all(cast(list[str], command["command"])[0] == "<python>" for command in commands)

    artifacts = cast(dict[str, str], summary["artifacts"])
    assert all(not Path(path).is_absolute() for path in artifacts.values())
    for path in artifacts.values():
        assert (out / path).exists()
    assert (out / "example" / "prior_auth_synthetic" / "suite.yaml").is_file()
    assert (out / ".runtime" / "sitecustomize.py").is_file()

    strong_generation = out / artifacts["strong_campaign_generation"]
    weakened_generation = out / artifacts["weakened_campaign_generation"]
    validate_mutation_campaign_artifact_generation(strong_generation.parent)
    validate_mutation_campaign_artifact_generation(weakened_generation.parent)
    assert (
        validate_artifact(
            out / artifacts["control_efficacy_report"],
            "control-efficacy-report",
        )
        == "pydantic+jsonschema"
    )
    efficacy_report = _json(out / artifacts["control_efficacy_report"])
    assert efficacy_report["unscoped_catalog_threat_count"] == 0
    assert efficacy_report["unscoped_catalog_threat_ids"] == []
    assert [
        item["threat_id"] for item in cast(list[dict[str, Any]], efficacy_report["threat_coverage"])
    ] == ["AML.T0067.000", "material-claim-link-regression"]
    assert (
        validate_artifact(
            out / artifacts["evidence_packet"],
            "evidence-packet",
        )
        == "pydantic+jsonschema"
    )
    assert (
        validate_artifact(
            out / artifacts["assurance_evidence_graph"],
            "assurance-evidence-graph",
        )
        == "pydantic+jsonschema"
    )
    graph = _json(out / artifacts["assurance_evidence_graph"])
    mutation_graph = _json(out / artifacts["mutation_evidence_graph"])
    assert graph["contract_id"] == "AssuranceEvidenceGraph/v1"
    assert graph["graph_digest"] == summary["evidence_graph_digest"]
    assert graph["nodes"]
    assert graph["edges"]
    assert graph["limitations"]
    assert mutation_graph["graph_digest"] == summary["mutation_evidence_graph_digest"]
    assert any(
        node["payload"].get("evidence_type") == "mutation_result"
        for node in cast(list[dict[str, Any]], mutation_graph["nodes"])
    )
    packet = _json(out / artifacts["evidence_packet"])
    persisted_packet = load_evidence_packet(out / artifacts["evidence_packet"])
    assert persisted_packet.release_manifest is not None
    assert packet_summary_files_binding_error(persisted_packet, artifact_root=out) is None
    assert artifacts["release_artifact_manifest"] == "release-artifact-manifest.json"
    assert packet["release_manifest"] == _json(out / artifacts["release_artifact_manifest"])
    config_digest = next(
        item
        for item in cast(list[dict[str, Any]], packet["artifact_digests"])
        if item["role"] == "control-efficacy-gate-profile"
    )
    assert config_digest["sha256"] == file_sha256(out / artifacts["control_efficacy_config"])
    graph_digest = next(
        item
        for item in cast(list[dict[str, Any]], packet["artifact_digests"])
        if item["role"] == "assurance-evidence-graph"
    )
    graph_file_sha256 = file_sha256(out / artifacts["assurance_evidence_graph"])
    assert graph_digest["sha256"] == graph_file_sha256
    assert packet["evidence_graph_digest"] == graph["graph_digest"]

    hashes = cast(dict[str, str], summary["artifact_sha256"])
    for name, digest in hashes.items():
        assert file_sha256(out / artifacts[name]) == digest
    assert hashes["assurance_evidence_graph"] == graph_file_sha256
    reviewer = (out / artifacts["reviewer_facing_report"]).read_text(encoding="utf-8")
    assert "the unrelated failure did not count as a kill" in reviewer
    assert "Matched normative finding count: `0`" in reviewer
    assert f"Packet-bound graph digest: {graph['graph_digest']}." in reviewer
    assert f"Mutation-enriched graph digest: {mutation_graph['graph_digest']}." in reviewer
    assert (
        "Mutation-enriched nodes / edges: "
        f"{len(mutation_graph['nodes'])} / {len(mutation_graph['edges'])}." in reviewer
    )
    assert "Contradictions and limitations remain first-class findings." in reviewer
    assert "http://" not in reviewer.lower()
    assert "https://" not in reviewer.lower()

    packet_gate = RUNNER.invoke(
        app,
        [
            "ci",
            "gate",
            str(out / artifacts["evidence_packet"]),
            "--efficacy-policy",
            str(out / artifacts["control_efficacy_config"]),
            "--allow-advisory-efficacy",
        ],
    )
    assert packet_gate.exit_code == 1, packet_gate.output
    assert "evidence-packet=" in packet_gate.output

    first_summary_bytes = (out / "demo-summary.json").read_bytes()
    strict = RUNNER.invoke(
        app,
        [
            "demo",
            "assure-the-assurance",
            "--out",
            str(out),
            "--no-clean",
            "--format",
            "json",
            "--strict",
        ],
    )
    assert strict.exit_code == 1, strict.output
    assert cast(dict[str, Any], json.loads(strict.output)) == summary
    assert (out / "demo-summary.json").read_bytes() == first_summary_bytes


def test_assure_demo_blocks_parent_network_and_invalidates_stale_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    out = tmp_path / "assure-the-assurance"
    success = RUNNER.invoke(
        app,
        ["demo", "assure-the-assurance", "--out", str(out), "--clean"],
    )
    assert success.exit_code == 0, success.output
    assert (out / "demo-summary.json").is_file()

    def unguarded_network(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("parent demo network primitive was not guarded")

    monkeypatch.setattr(socket, "create_connection", unguarded_network)

    def attempt_network(*_args: object, **_kwargs: object) -> None:
        socket.create_connection(("127.0.0.1", 9))

    monkeypatch.setattr(
        "agent_assure.demo.assure_the_assurance.execute_mutation_campaign",
        attempt_network,
    )
    failure = RUNNER.invoke(
        app,
        [
            "demo",
            "assure-the-assurance",
            "--out",
            str(out),
            "--no-clean",
            "--format",
            "json",
        ],
    )

    assert failure.exit_code == 1
    payload = cast(dict[str, Any], json.loads(failure.output))
    assert payload["status"] == "failure"
    assert "network access is disabled" in cast(str, payload["error"])
    assert not (out / "demo-summary.json").exists()


def test_assure_demo_parent_guard_blocks_udp_sendto() -> None:
    with _offline_network_guard():
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            with pytest.raises(DemoError, match="network access is disabled"):
                probe.sendto(b"offline-probe", ("127.0.0.1", 9))
        finally:
            probe.close()


@pytest.mark.parametrize(
    ("command", "runner_name"),
    (
        ("assure-the-assurance", "run_assure_the_assurance_demo"),
        ("flagship", "run_flagship_demo"),
        ("rag", "run_rag_demo"),
        ("measurement-cases", "run_measurement_cases_demo"),
    ),
)
@pytest.mark.parametrize("error_kind", ("oserror", "value", "validation"))
def test_demo_json_operational_failures_are_bounded_and_path_safe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
    runner_name: str,
    error_kind: str,
) -> None:
    out = tmp_path / f"{command}-private-output"
    validation_error: ValidationError | None = None
    if error_kind == "validation":
        try:
            TypeAdapter(int).validate_python("not-an-integer")
        except ValidationError as exc:
            validation_error = exc

    def fail(*_args: object, **_kwargs: object) -> None:
        if error_kind == "oserror":
            raise OSError(f"filesystem failed at {out}\x1b[31m\x07")
        if error_kind == "validation":
            assert validation_error is not None
            raise validation_error
        raise ValueError(f"invalid value at {out}\x1b[31m\x07")

    monkeypatch.setattr(demo_cmd, runner_name, fail)

    result = RUNNER.invoke(
        app,
        ["demo", command, "--out", str(out), "--format", "json"],
    )

    assert result.exit_code == 1, result.output
    payload = cast(dict[str, Any], json.loads(result.output))
    assert payload["demo"] == command
    assert payload["status"] == "failure"
    assert payload["out"] == "<output-directory>"
    assert isinstance(payload["error"], str)
    assert len(cast(str, payload["error"])) <= 512
    assert str(out) not in result.output
    assert "\x1b" not in result.output
    assert "\x07" not in result.output
    assert "Traceback" not in result.output


def _json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload
