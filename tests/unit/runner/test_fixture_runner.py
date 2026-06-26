from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from agent_assure.authoring.compiler import compile_suite
from agent_assure.runner.fixture_runner import load_variant_config, run_suite
from agent_assure.runner.ids import DeterministicIds

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
