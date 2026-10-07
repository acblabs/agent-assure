from __future__ import annotations

import json
import re
from collections.abc import Callable
from copy import deepcopy
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import ValidationError as PydanticValidationError
from typer.testing import CliRunner

from agent_assure.ci import gate_comparison_summary, gate_evidence_packet
from agent_assure.cli.main import app
from agent_assure.compare.runsets import ComparisonReport, FixtureEquivalenceReport
from agent_assure.evaluation.evaluator import EvaluationMetrics
from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.release_evidence import load_digest_replay
from agent_assure.schema import validation as artifact_validation
from agent_assure.schema.common import ComparisonClassification, GateState
from agent_assure.schema.comparison import ComparisonSummary
from agent_assure.schema.evaluation import EvaluationSummary
from agent_assure.schema.packet import EvidencePacket, PacketArtifactDigest
from agent_assure.schema.run import AgentRunRecord, RunSet
from agent_assure.schema.validation import (
    ArchivalOnlyArtifactError,
    FrozenRootValidationPolicy,
    validate_artifact_payload,
    validate_historical_artifact_payload_for_release_replay,
)

_HISTORICAL_SCHEMA_VERSIONS = (
    "0.1.0",
    "0.2.0",
    "0.3.1",
    "0.4.3",
    "0.5.0",
    "0.6.0",
    "0.6.1",
    "0.6.2",
    "0.6.3",
    "0.6.4",
    "0.6.5",
)
_HISTORICAL_DECISION_ROOTS = (
    "evaluation-summary",
    "evaluation-report",
    "comparison-summary",
    "comparison-report",
    "evidence-packet",
    "release-artifact-manifest",
    "release-digest-replay",
)

_UNREACHABLE_USAGE_DISPATCH_PAIRS = frozenset(
    (artifact_kind, schema_version)
    for schema_version in (
        "0.5.0",
        "0.6.0",
        "0.6.1",
        "0.6.2",
        "0.6.3",
        "0.6.4",
        "0.6.5",
    )
    for artifact_kind in (
        "usage-ledger",
        "usage-pricing-snapshot",
        "usage-segment",
        "usage-summary",
        "usage-summary-delta",
    )
)
_BROAD_PREINTRODUCTION_WIRE_PAIRS = frozenset(
    {
        ("control-coverage-report", "0.2.0"),
        ("control-coverage-report", "0.3.1"),
        ("stream-event-record", "0.2.0"),
        ("stream-event-record", "0.3.1"),
        ("stream-event-record", "0.4.3"),
        ("stream-ingestion-diagnostics", "0.2.0"),
        ("stream-ingestion-diagnostics", "0.3.1"),
        ("stream-ingestion-diagnostics", "0.4.3"),
        ("stream-run", "0.2.0"),
        ("stream-run", "0.3.1"),
        ("stream-run", "0.4.3"),
    }
)
_NON_DISPATCH_SCHEMA_DIRECTORY_EXCEPTIONS = {
    # v0.3.0 changed packaging only. Its immutable package snapshot deliberately
    # retains v0.2.0 root wire identities and is never a v0.3.0 dispatch target.
    "v0.3.0": "package-release snapshot whose persisted wire version remains 0.2.0",
    # Development exports are disposable smoke-test output, never frozen replay
    # inputs and therefore never members of FROZEN_SCHEMA_VERSIONS.
    "unreleased": "non-gating development schema export staging directory",
}
_SEMVER_SCHEMA_DIRECTORY = re.compile(r"^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")


@pytest.mark.parametrize("schema_version", _HISTORICAL_SCHEMA_VERSIONS)
@pytest.mark.parametrize("artifact_kind", _HISTORICAL_DECISION_ROOTS)
def test_historical_decision_roots_are_archival_only(
    schema_version: str,
    artifact_kind: str,
) -> None:
    payload = {
        "artifact_kind": artifact_kind,
        "schema_version": schema_version,
    }

    with pytest.raises(ArchivalOnlyArtifactError, match="archival-only"):
        artifact_validation._reject_archival_only_artifact(payload, kind=artifact_kind)


def test_archival_policy_uses_trusted_kind_and_version_when_artifact_kind_is_absent() -> None:
    payload = _contradictory_v043_evaluation_summary()
    assert "artifact_kind" not in payload
    assert (
        artifact_validation._validate_legacy_frozen_schema(payload, "evaluation-summary")
        == "frozen-jsonschema"
    )

    with pytest.raises(ArchivalOnlyArtifactError, match="archival-only"):
        validate_artifact_payload(payload, "evaluation-summary")


def test_validate_cli_rejects_structurally_valid_historical_standard_decision(
    tmp_path: Path,
) -> None:
    payload = _contradictory_v043_evaluation_summary()
    assert (
        artifact_validation._validate_legacy_frozen_schema(payload, "evaluation-summary")
        == "frozen-jsonschema"
    )
    path = tmp_path / "historical-evaluation-summary.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    result = CliRunner().invoke(
        app,
        ["validate", str(path), "--kind", "evaluation-summary"],
    )

    assert result.exit_code == 2
    assert "archival-only" in result.output
    assert "valid evaluation-summary:" not in result.output


@pytest.mark.parametrize("schema_version", _HISTORICAL_SCHEMA_VERSIONS)
@pytest.mark.parametrize(
    ("artifact_kind", "payload_factory"),
    (
        ("release-artifact-manifest", lambda version: _release_manifest_payload(version)),
        ("release-digest-replay", lambda version: _release_replay_payload(version)),
    ),
)
@pytest.mark.parametrize("duplicate_field", ("role", "path"))
def test_historical_release_roots_replay_identity_uniqueness(
    schema_version: str,
    artifact_kind: str,
    payload_factory: Callable[[str], dict[str, object]],
    duplicate_field: str,
) -> None:
    payload = payload_factory(schema_version)
    with pytest.raises(ArchivalOnlyArtifactError, match="archival-only"):
        validate_artifact_payload(payload, artifact_kind)
    assert (
        validate_historical_artifact_payload_for_release_replay(payload, artifact_kind)
        == "frozen-jsonschema+release-integrity-only"
    )
    duplicate = deepcopy(payload)
    artifacts = duplicate["artifacts"]
    assert isinstance(artifacts, list)
    first, second = artifacts
    assert isinstance(first, dict)
    assert isinstance(second, dict)
    second[duplicate_field] = first[duplicate_field]

    with pytest.raises(ValueError, match="failed integrity validation"):
        validate_historical_artifact_payload_for_release_replay(duplicate, artifact_kind)


def test_historical_release_replay_loader_uses_non_assurance_integrity_path(
    tmp_path: Path,
) -> None:
    payload = _release_replay_payload("0.6.2")
    path = tmp_path / "release-digest-replay.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ArchivalOnlyArtifactError, match="archival-only"):
        validate_artifact_payload(payload, "release-digest-replay")
    replay = load_digest_replay(path)

    assert replay.schema_version == "0.6.2"
    assert tuple(item.role for item in replay.artifacts) == ("first", "second")


def _frozen_root_wire_contract() -> tuple[
    set[tuple[str, str]],
    set[tuple[str, str]],
    set[tuple[str, str]],
]:
    """Return exported, root-declared, and exactly dispatchable wire pairs."""

    schema_root = Path(__file__).resolve().parents[3] / "schemas"
    frozen_versions = set(artifact_validation.FROZEN_SCHEMA_VERSIONS)
    version_dirs = tuple(path for path in schema_root.iterdir() if path.is_dir())
    _assert_schema_directory_registry(
        {version_dir.name for version_dir in version_dirs},
        frozen_versions=frozen_versions,
    )
    exported_pairs: set[tuple[str, str]] = set()
    root_declared_pairs: set[tuple[str, str]] = set()
    dispatch_reachable_pairs: set[tuple[str, str]] = set()

    for version_dir in version_dirs:
        if version_dir.name in _NON_DISPATCH_SCHEMA_DIRECTORY_EXCEPTIONS:
            continue
        assert _SEMVER_SCHEMA_DIRECTORY.fullmatch(version_dir.name)
        wire_version = version_dir.name.removeprefix("v")
        assert wire_version in frozen_versions
        for schema_path in version_dir.glob("*.schema.json"):
            artifact_kind = schema_path.name.removesuffix(".schema.json")
            exported_pair = (artifact_kind, wire_version)
            exported_pairs.add(exported_pair)

            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            assert isinstance(schema, dict)
            properties = schema.get("properties")
            assert isinstance(properties, dict)
            root_version_schema = properties.get("schema_version")
            assert isinstance(root_version_schema, dict)
            Draft202012Validator.check_schema(root_version_schema)
            validator = Draft202012Validator(root_version_schema)
            admitted_versions = {
                candidate for candidate in frozen_versions if validator.is_valid(candidate)
            }
            root_declared_pairs.update(
                (artifact_kind, admitted_version) for admitted_version in admitted_versions
            )
            if wire_version in admitted_versions:
                dispatch_reachable_pairs.add(exported_pair)

    return exported_pairs, root_declared_pairs, dispatch_reachable_pairs


def _assert_schema_directory_registry(
    directory_names: set[str],
    *,
    frozen_versions: set[str],
) -> None:
    registered_directories = {f"v{version}" for version in frozen_versions}
    expected_directories = registered_directories | _NON_DISPATCH_SCHEMA_DIRECTORY_EXCEPTIONS.keys()
    unexpected = directory_names - expected_directories
    missing = expected_directories - directory_names
    assert not unexpected and not missing, (
        "schema directory registry is not exhaustive; unregistered schema directories="
        f"{sorted(unexpected)!r}, missing registered directories={sorted(missing)!r}"
    )
    assert all(
        _SEMVER_SCHEMA_DIRECTORY.fullmatch(name) for name in directory_names - {"unreleased"}
    )


def test_schema_directory_registry_rejects_unregistered_semver_directory() -> None:
    schema_root = Path(__file__).resolve().parents[3] / "schemas"
    directory_names = {path.name for path in schema_root.iterdir() if path.is_dir()}
    directory_names.add("v9.9.9")

    with pytest.raises(AssertionError, match="unregistered schema directories"):
        _assert_schema_directory_registry(
            directory_names,
            frozen_versions=set(artifact_validation.FROZEN_SCHEMA_VERSIONS),
        )


def test_frozen_root_policy_is_exhaustive_for_dispatch_reachable_wires() -> None:
    exported_pairs, root_declared_pairs, dispatch_reachable_pairs = _frozen_root_wire_contract()
    registered_pairs = set(artifact_validation.FROZEN_ROOT_VALIDATION_POLICY)

    # A policy exists if and only if the exact dispatch file exists and its
    # root schema admits the wire version selected by that path.  File count
    # alone is not a reachability contract.
    assert registered_pairs == dispatch_reachable_pairs
    assert exported_pairs - dispatch_reachable_pairs == _UNREACHABLE_USAGE_DISPATCH_PAIRS
    assert root_declared_pairs - exported_pairs == _BROAD_PREINTRODUCTION_WIRE_PAIRS
    assert all(
        artifact_validation.FROZEN_ROOT_VALIDATION_POLICY[pair]
        in {
            FrozenRootValidationPolicy.semantic_replay,
            FrozenRootValidationPolicy.archival_only,
            FrozenRootValidationPolicy.current_semantic,
        }
        for pair in registered_pairs
    )
    assert artifact_validation.FROZEN_ROOT_VALIDATION_POLICY[("run-set", "0.5.0")] is (
        FrozenRootValidationPolicy.semantic_replay
    )
    assert (
        artifact_validation.FROZEN_ROOT_VALIDATION_POLICY[("evaluation-summary", "0.5.0")]
        is FrozenRootValidationPolicy.archival_only
    )
    assert (
        artifact_validation.FROZEN_ROOT_VALIDATION_POLICY[("release-digest-replay", "0.6.5")]
        is FrozenRootValidationPolicy.archival_only
    )
    assert (
        artifact_validation.FROZEN_ROOT_VALIDATION_POLICY[("evaluation-summary", "0.6.6")]
        is FrozenRootValidationPolicy.current_semantic
    )
    with pytest.raises(ValueError, match="no frozen validation policy"):
        artifact_validation._frozen_root_policy(
            kind="run-set",
            schema_version="0.3.0",
        )


@pytest.mark.parametrize(
    ("artifact_kind", "schema_version"),
    sorted(_UNREACHABLE_USAGE_DISPATCH_PAIRS | _BROAD_PREINTRODUCTION_WIRE_PAIRS),
)
def test_non_dispatchable_frozen_root_version_pairs_fail_closed(
    artifact_kind: str,
    schema_version: str,
) -> None:
    payload = {
        "artifact_kind": artifact_kind,
        "schema_version": schema_version,
    }

    with pytest.raises(ValueError, match="no frozen validation policy"):
        validate_artifact_payload(payload, artifact_kind)


def test_structural_only_historical_runset_contradiction_reaches_semantic_replay() -> None:
    record = AgentRunRecord(
        schema_version="0.5.0",
        run_id="fixture-run",
        case_id="case-a",
        execution_mode="fixture",
        pipeline_id="pipeline-a",
        recommendation="approve",
        outcome="approve",
        input_summary="input",
        output_summary="output",
    )
    runset = RunSet(
        schema_version="0.5.0",
        runset_id="mixed-mode-runset",
        suite_id="suite-a",
        suite_version="0.5.0",
        suite_digest="a" * 64,
        fixture_manifest_digest="b" * 64,
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        runs=(record,),
    )
    payload = runset.model_dump(mode="json")
    pending: list[object] = [payload]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            if "schema_version" in value:
                value["schema_version"] = "0.5.0"
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
    payload["execution_mode"] = "live"
    payload["protocol_id"] = "protocol-a"
    payload["protocol_digest"] = "c" * 64
    assert (
        artifact_validation._validate_legacy_frozen_schema(payload, "run-set")
        == "frozen-jsonschema"
    )

    with pytest.raises(ValueError, match="run-set artifact failed model validation"):
        validate_artifact_payload(payload, "run-set")


def test_structural_only_historical_run_record_token_arithmetic_reaches_semantic_replay() -> None:
    payload: dict[str, object] = {
        "artifact_kind": "agent-run-record",
        "schema_version": "0.5.0",
        "run_id": "run-impossible-token-arithmetic",
        "case_id": "case-a",
        "execution_mode": "fixture",
        "pipeline_id": "pipeline-a",
        "recommendation": "approve",
        "outcome": "approve",
        "input_summary": "input",
        "output_summary": "output",
        "prompt_tokens": 2,
        "completion_tokens": 3,
        "total_tokens": 99,
    }
    assert (
        artifact_validation._validate_legacy_frozen_schema(payload, "agent-run-record")
        == "frozen-jsonschema"
    )

    with pytest.raises(ValueError, match="agent-run-record artifact failed model validation"):
        validate_artifact_payload(payload, "agent-run-record")


def test_structural_only_historical_compiled_suite_replays_expectation_references() -> None:
    path = (
        Path(__file__).resolve().parents[2]
        / "golden"
        / "compiled_suites"
        / "prior_auth_synthetic.v0.5.0.compiled.json"
    )
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["cases"][0]["expectation_id"] = "does-not-exist"
    assert (
        artifact_validation._validate_legacy_frozen_schema(payload, "compiled-suite")
        == "frozen-jsonschema"
    )

    with pytest.raises(ValueError, match="compiled-suite artifact failed model validation"):
        validate_artifact_payload(payload, "compiled-suite")


def test_structural_only_historical_usage_range_reaches_semantic_replay() -> None:
    payload: dict[str, object] = {
        "artifact_kind": "usage-segment",
        "schema_version": "0.4.3",
        "segment_id": "segment-invalid-range",
        "event_range_start": 10,
        "event_range_end": 9,
        "currency": "USD",
        "limitations": [],
    }
    assert (
        artifact_validation._validate_legacy_frozen_schema(payload, "usage-segment")
        == "frozen-jsonschema"
    )

    with pytest.raises(ValueError, match="usage-segment artifact failed model validation"):
        validate_artifact_payload(payload, "usage-segment")


def test_current_comparison_model_rejects_failed_fixture_with_allowed_verdict() -> None:
    payload = _incoherent_comparison_payload()

    with pytest.raises(PydanticValidationError, match="failed fixture equivalence"):
        ComparisonSummary.model_validate(payload)


@pytest.mark.parametrize(
    ("report_state", "summary_state", "classification"),
    (
        (
            GateState.fail,
            GateState.pass_,
            ComparisonClassification.allowed_behavioral_change,
        ),
        (
            GateState.pass_,
            GateState.fail,
            ComparisonClassification.invalid_comparison,
        ),
    ),
)
def test_current_comparison_report_rejects_conflicting_fixture_states(
    report_state: GateState,
    summary_state: GateState,
    classification: ComparisonClassification,
) -> None:
    payload = _coherent_invalid_report(_coherent_invalid_comparison()).model_dump(mode="json")
    fixture_equivalence = payload["fixture_equivalence"]
    comparison_summary = payload["comparison_summary"]
    assert isinstance(fixture_equivalence, dict)
    assert isinstance(comparison_summary, dict)
    fixture_equivalence["state"] = report_state.value
    comparison_summary["fixture_equivalence_state"] = summary_state.value
    comparison_summary["classification"] = classification.value

    with pytest.raises(PydanticValidationError, match="fixture equivalence state"):
        ComparisonReport.model_validate(payload)
    with pytest.raises((JsonSchemaValidationError, ValueError)):
        validate_artifact_payload(payload, "comparison-report")


@pytest.mark.parametrize(
    "artifact_kind", ("comparison-summary", "comparison-report", "evidence-packet")
)
def test_public_validator_rejects_current_failed_fixture_with_allowed_verdict(
    artifact_kind: str,
) -> None:
    payloads = _current_comparison_payloads()

    with pytest.raises((JsonSchemaValidationError, ValueError)):
        validate_artifact_payload(payloads[artifact_kind], artifact_kind)


def test_public_comparison_validation_cannot_accept_typed_gate_invalidity() -> None:
    coherent_summary = _coherent_invalid_comparison()
    incoherent_summary = coherent_summary.model_copy(
        update={"classification": ComparisonClassification.allowed_behavioral_change}
    )
    summary_payload = incoherent_summary.model_dump(mode="json")
    summary_decision = gate_comparison_summary(incoherent_summary)

    assert summary_decision.exit_code == 2
    assert summary_decision.outcome.value == "invalid"
    with pytest.raises((JsonSchemaValidationError, ValueError)):
        validate_artifact_payload(summary_payload, "comparison-summary")

    packet = _coherent_invalid_packet(coherent_summary)
    incoherent_packet = packet.model_copy(update={"comparison": incoherent_summary})
    packet_payload = incoherent_packet.model_dump(mode="json")
    packet_decision = gate_evidence_packet(
        incoherent_packet,
        allow_missing_efficacy_for_migration=True,
    )

    assert packet_decision.exit_code == 2
    assert packet_decision.outcome.value == "invalid"
    with pytest.raises((JsonSchemaValidationError, ValueError)):
        validate_artifact_payload(packet_payload, "evidence-packet")


def _release_manifest_payload(schema_version: str) -> dict[str, object]:
    return {
        "artifact_kind": "release-artifact-manifest",
        "schema_version": schema_version,
        "manifest_id": "historical-manifest",
        "artifacts": _release_artifacts(schema_version, replay=False),
        "environment": {
            "artifact_kind": "environment-info",
            "schema_version": schema_version,
            "platform": "test",
            "python_version": "3.14",
        },
    }


def _contradictory_v043_evaluation_summary() -> dict[str, object]:
    return {
        "schema_version": "0.4.3",
        "runset_id": "historical-runset",
        "state": GateState.pass_.value,
        "findings": [
            {
                "finding_id": "contradictory-finding",
                "case_id": "case-a",
                "state": GateState.fail.value,
                "reason_code": "POLICY_FAILED",
                "message": "a failing finding cannot support a pass verdict",
            }
        ],
    }


def _release_replay_payload(schema_version: str) -> dict[str, object]:
    return {
        "artifact_kind": "release-digest-replay",
        "schema_version": schema_version,
        "artifacts": _release_artifacts(schema_version, replay=True),
    }


def _release_artifacts(schema_version: str, *, replay: bool) -> list[dict[str, object]]:
    artifact_kind = "release-replay-artifact" if replay else "release-artifact"
    return [
        {
            "artifact_kind": artifact_kind,
            "schema_version": schema_version,
            "role": "first",
            "path": "first.json",
            "sha256": "a" * 64,
        },
        {
            "artifact_kind": artifact_kind,
            "schema_version": schema_version,
            "role": "second",
            "path": "second.json",
            "sha256": "b" * 64,
        },
    ]


def _privacy_profile() -> dict[str, str]:
    return {
        "privacy_profile_id": PRIVACY_PROFILE_ID,
        "privacy_profile_digest": PRIVACY_PROFILE_DIGEST,
    }


def _evaluation(runset_id: str, digest_character: str) -> EvaluationSummary:
    return EvaluationSummary(
        runset_id=runset_id,
        runset_digest=digest_character * 64,
        state=GateState.not_evaluated,
        **_privacy_profile(),
    )


def _coherent_invalid_comparison() -> ComparisonSummary:
    return ComparisonSummary(
        baseline_runset_id="baseline",
        candidate_runset_id="candidate",
        baseline_runset_digest="b" * 64,
        candidate_runset_digest="c" * 64,
        classification=ComparisonClassification.invalid_comparison,
        fixture_equivalence_state=GateState.fail,
        baseline_state=GateState.not_evaluated,
        candidate_state=GateState.not_evaluated,
        **_privacy_profile(),
    )


def _incoherent_comparison_payload() -> dict[str, object]:
    payload = _coherent_invalid_comparison().model_dump(mode="json")
    payload["classification"] = ComparisonClassification.allowed_behavioral_change.value
    return payload


def _metrics() -> EvaluationMetrics:
    return EvaluationMetrics(
        total_cases=0,
        evaluated_cases=0,
        unevaluated_cases=0,
        passed_cases=0,
        warning_cases=0,
        failed_cases=0,
        warning_findings=0,
        blocking_findings=0,
        global_blocking_findings=0,
        findings_by_reason={},
        findings_by_control={},
    )


def _coherent_invalid_report(summary: ComparisonSummary) -> ComparisonReport:
    return ComparisonReport(
        candidate_vs_expectations=_evaluation("candidate", "c"),
        verdict_explanations=("fixture equivalence failed",),
        fixture_equivalence=FixtureEquivalenceReport(state=GateState.fail),
        baseline_vs_expectations=_evaluation("baseline", "b"),
        control_changes=(),
        behavioral_changes=(),
        provenance_changes=(),
        not_evaluated_capabilities=(),
        limitations=("test fixture",),
        comparison_summary=summary,
        baseline_metrics=_metrics(),
        candidate_metrics=_metrics(),
        suite_id="suite",
        suite_version="1",
        gate_profile="default",
    )


def _coherent_invalid_packet(summary: ComparisonSummary) -> EvidencePacket:
    return EvidencePacket(
        packet_id="comparison-packet",
        interpretation=("fixture equivalence failed",),
        evaluation=_evaluation("candidate", "c"),
        comparison=summary,
        artifact_digests=(
            PacketArtifactDigest(role="evaluation-summary", sha256="e" * 64),
            PacketArtifactDigest(role="comparison-summary", sha256="f" * 64),
        ),
        limitations=("test fixture",),
    )


def _current_comparison_payloads() -> dict[str, dict[str, object]]:
    summary = _coherent_invalid_comparison()
    summary_payload = _incoherent_comparison_payload()
    report_payload = _coherent_invalid_report(summary).model_dump(mode="json")
    report_payload["comparison_summary"] = deepcopy(summary_payload)
    packet_payload = _coherent_invalid_packet(summary).model_dump(mode="json")
    packet_payload["comparison"] = deepcopy(summary_payload)
    return {
        "comparison-summary": summary_payload,
        "comparison-report": report_payload,
        "evidence-packet": packet_payload,
    }
