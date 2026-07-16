from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from agent_assure.authoring.compiler import compile_suite
from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.runner.fixture_runner import load_variant_config, run_suite, write_runset
from agent_assure.runner.ids import DeterministicIds
from agent_assure.schema.run import AgentRunRecord, RunSet

SUITE = Path("examples/prior_auth_synthetic/suite.yaml")
BASELINE = Path("examples/prior_auth_synthetic/variants/baseline.yaml")


def test_deterministic_ids_are_stable() -> None:
    ids = DeterministicIds()
    assert ids.run_id("suite", "variant", "case") == ids.run_id("suite", "variant", "case")
    assert ids.run_id("suite", "variant", "case") != ids.run_id("suite", "variant", "other")


def test_variant_config_digest_is_stable() -> None:
    first = load_variant_config(BASELINE)
    second = load_variant_config(BASELINE)
    assert first.configuration_digest == second.configuration_digest
    assert first.runner_id == "prior_auth.synthetic"
    assert first.behavior.evidence_assembly == "association_preserving"


def test_variant_config_rejects_unknown_behavior_fields(tmp_path) -> None:  # type: ignore[no-untyped-def]
    variant = tmp_path / "variant.yaml"
    variant.write_text(
        """
variant_id: bad-variant
pipeline_id: bad-pipeline
runner_id: prior_auth.synthetic
behavior:
  unknown_behavior_knob: legacy
""".lstrip(),
        encoding="utf-8",
    )
    with pytest.raises(ValidationError):
        load_variant_config(variant)


def test_run_suite_is_deterministic_for_same_inputs() -> None:
    compiled = compile_suite(SUITE)
    variant = load_variant_config(BASELINE)
    first = run_suite(compiled, variant, SUITE.parent)
    second = run_suite(compiled, variant, SUITE.parent)
    assert first == second


def test_default_fixture_hmac_key_is_limited_to_bundled_synthetic_suites() -> None:
    compiled = compile_suite(SUITE).model_copy(update={"suite_id": "private-suite"})
    variant = load_variant_config(BASELINE)

    with pytest.raises(ValueError, match="default fixture HMAC key"):
        run_suite(compiled, variant, SUITE.parent)


def test_explicit_fixture_hmac_key_allows_non_synthetic_suite() -> None:
    compiled = compile_suite(SUITE).model_copy(update={"suite_id": "private-suite"})
    variant = load_variant_config(BASELINE)

    runset = run_suite(
        compiled,
        variant,
        SUITE.parent,
        hmac_key=b"private-test-key-32-byte-value-0000",
    )

    assert runset.suite_id == "private-suite"


def test_run_suite_verifies_source_digest_when_source_is_supplied(tmp_path) -> None:  # type: ignore[no-untyped-def]
    compiled = compile_suite(SUITE)
    bad_source = tmp_path / "suite.yaml"
    bad_source.write_text(
        """
suite_id: changed
suite_version: 0.1.0
cases: []
""".lstrip(),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="suite source digest mismatch"):
        run_suite(
            compiled,
            load_variant_config(BASELINE),
            SUITE.parent,
            source_yaml=bad_source,
        )


def test_write_runset_redacts_sensitive_summaries_before_persistence(tmp_path) -> None:  # type: ignore[no-untyped-def]
    traceparent = "00-11111111111111111111111111111111-2222222222222222-01"
    record = AgentRunRecord(
        artifact_kind="agent-run-record",
        run_id="run-001",
        case_id="case-001",
        execution_mode="fixture",
        pipeline_id="pipeline",
        recommendation="approve",
        outcome="approve",
        input_summary="patient=Jane ssn: 123-45-6789",
        output_summary="email jane@example.com",
        traceparent=traceparent,
    )
    runset = RunSet(
        artifact_kind="run-set",
        runset_id="runset-001",
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        suite_id="suite-001",
        suite_version="0.1.0",
        suite_digest="0" * 64,
        fixture_manifest_digest="1" * 64,
        runs=(record,),
    )
    path = tmp_path / "runset.json"

    write_runset(runset, path)

    text = path.read_text(encoding="utf-8")
    assert "123-45-6789" not in text
    assert "jane@example.com" not in text
    loaded = RunSet.model_validate_json(text)
    assert "[REDACTED]" in loaded.runs[0].input_summary
    assert "[REDACTED]" in loaded.runs[0].output_summary
    assert loaded.runs[0].traceparent == traceparent


def test_write_runset_rejects_sensitive_preserved_decision_fields(tmp_path) -> None:  # type: ignore[no-untyped-def]
    record = AgentRunRecord(
        artifact_kind="agent-run-record",
        run_id="run-001",
        case_id="case-001",
        execution_mode="fixture",
        pipeline_id="pipeline",
        recommendation="approve ssn: 123-45-6789",
        outcome="approve",
        input_summary="plain",
        output_summary="plain",
    )
    runset = RunSet(
        artifact_kind="run-set",
        runset_id="runset-001",
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        suite_id="suite-001",
        suite_version="0.1.0",
        suite_digest="0" * 64,
        fixture_manifest_digest="1" * 64,
        runs=(record,),
    )

    with pytest.raises(ValueError, match="preserved field"):
        write_runset(runset, tmp_path / "runset.json")


def test_write_runset_rejects_sensitive_preserved_provider_metadata(tmp_path) -> None:  # type: ignore[no-untyped-def]
    record = AgentRunRecord(
        artifact_kind="agent-run-record",
        run_id="run-001",
        case_id="case-001",
        execution_mode="fixture",
        pipeline_id="pipeline",
        recommendation="approve",
        outcome="approve",
        input_summary="plain",
        output_summary="plain",
        provider_response_id="authorization=abcdef1234567890",
    )
    runset = RunSet(
        artifact_kind="run-set",
        runset_id="runset-001",
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        suite_id="suite-001",
        suite_version="0.1.0",
        suite_digest="0" * 64,
        fixture_manifest_digest="1" * 64,
        runs=(record,),
    )

    with pytest.raises(ValueError, match="provider_response_id"):
        write_runset(runset, tmp_path / "runset.json")
