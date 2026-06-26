from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from agent_assure.authoring.compiler import compile_suite
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
    )
    runset = RunSet(
        artifact_kind="run-set",
        runset_id="runset-001",
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
