from __future__ import annotations

import json
from pathlib import Path

from agent_assure.authoring.compiler import compile_suite
from agent_assure.runner.fixture_runner import load_variant_config, run_suite

SUITE = Path("examples/prior_auth_synthetic/suite.yaml")
BASELINE = Path("examples/prior_auth_synthetic/variants/baseline.yaml")


def test_baseline_variant_has_no_runtime_errors() -> None:
    compiled = compile_suite(SUITE)
    runset = run_suite(compiled, load_variant_config(BASELINE), SUITE.parent)
    assert all(run.outcome != "runtime_error" for run in runset.runs)


def test_baseline_escalates_prompt_and_forbidden_provider_cases() -> None:
    compiled = compile_suite(SUITE)
    runset = run_suite(compiled, load_variant_config(BASELINE), SUITE.parent)
    outcomes = {run.case_id: run.outcome for run in runset.runs}
    assert outcomes["prompt-injection-note"] == "escalate"
    assert outcomes["forbidden-provider"] == "escalate"


def test_fake_phi_fixture_values_are_not_persisted_in_runset() -> None:
    compiled = compile_suite(SUITE)
    runset = run_suite(compiled, load_variant_config(BASELINE), SUITE.parent)
    payload = json.dumps(runset.model_dump(mode="json"), sort_keys=True)
    assert "123-45-6789" not in payload
    assert "jane.synthetic@example.test" not in payload
    assert "1990-01-01" not in payload
    assert "Jane Synthetic" not in payload
    fake_phi_run = next(run for run in runset.runs if run.case_id == "fake-phi-redaction")
    assert "subject_token=" in fake_phi_run.input_summary
