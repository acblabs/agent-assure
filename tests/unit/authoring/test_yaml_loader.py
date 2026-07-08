from __future__ import annotations

import pytest
from pydantic import ValidationError

from agent_assure.authoring.compiler import compile_suite
from agent_assure.authoring.yaml_lint import lint_yaml


def test_yaml_ambiguous_scalar_preserves_lexeme(tmp_path) -> None:  # type: ignore[no-untyped-def]
    suite = tmp_path / "suite.yaml"
    suite.write_text(
        """
suite_id: demo
suite_version: 0.1.0
cases:
  - case_id: 00123
    title: Leading zero case
    expectation:
      expected_recommendation: approve
""".lstrip(),
        encoding="utf-8",
    )
    warnings = lint_yaml(suite)
    compiled = compile_suite(suite)
    assert compiled.cases[0].case_id == "00123"
    assert compiled.resolved_expectations[0].case_id == "00123"
    assert warnings
    assert "ambiguous scalar preserved as string" in warnings[0].message


def test_yaml_lint_warns_on_non_nfc_string(tmp_path) -> None:  # type: ignore[no-untyped-def]
    suite = tmp_path / "suite.yaml"
    suite.write_text(
        """
suite_id: demo
suite_version: 0.1.0
cases:
  - case_id: cafe\u0301
    title: Non NFC case
    expectation:
      expected_recommendation: approve
""".lstrip(),
        encoding="utf-8",
    )
    warnings = lint_yaml(suite)
    assert any("not NFC-normalized" in warning.message for warning in warnings)


def test_conflicting_expectation_shortcuts_fail(tmp_path) -> None:  # type: ignore[no-untyped-def]
    suite = tmp_path / "suite.yaml"
    suite.write_text(
        """
suite_id: demo
suite_version: 0.1.0
cases:
  - case_id: case-001
    title: Conflicting shortcuts
    expectation:
      expected_recommendation: approve
      allowed_outcomes:
        - approve
""".lstrip(),
        encoding="utf-8",
    )
    with pytest.raises(ValidationError):
        compile_suite(suite)


def test_compiled_suite_has_resolved_expectations_only() -> None:
    compiled = compile_suite(__import__("pathlib").Path("examples/prior_auth_synthetic/suite.yaml"))
    dumped = compiled.model_dump(mode="json")
    assert "resolved_expectations" in dumped
    assert "expectation" not in dumped["cases"][0]


def test_yaml_duplicate_mapping_keys_fail(tmp_path) -> None:  # type: ignore[no-untyped-def]
    suite = tmp_path / "suite.yaml"
    suite.write_text(
        """
suite_id: demo
suite_id: duplicate
suite_version: 0.1.0
cases: []
""".lstrip(),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="duplicate YAML mapping key"):
        compile_suite(suite)


def test_yaml_aliases_are_rejected_before_expansion(tmp_path) -> None:  # type: ignore[no-untyped-def]
    suite = tmp_path / "suite.yaml"
    suite.write_text(
        """
suite_id: demo
suite_version: 0.1.0
defaults: &defaults
  runner_id: prior_auth.synthetic
aliased_defaults: *defaults
cases: []
""".lstrip(),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="aliases are not supported"):
        compile_suite(suite)


def test_expectation_defaults_are_resolved_and_digest_recorded(tmp_path) -> None:  # type: ignore[no-untyped-def]
    suite = tmp_path / "suite.yaml"
    suite.write_text(
        """
suite_id: demo
suite_version: 0.1.0
defaults:
  expectation:
    allowed_outcomes:
      - approve
    required_human_review: true
cases:
  - case_id: case-001
    title: Defaulted expectation
    expectation:
      required_evidence_refs:
        - ref-001
""".lstrip(),
        encoding="utf-8",
    )

    compiled = compile_suite(suite)
    expectation = compiled.resolved_expectations[0]

    assert expectation.allowed_outcomes == ("approve",)
    assert expectation.required_human_review is True
    assert expectation.expectation_digest is not None
