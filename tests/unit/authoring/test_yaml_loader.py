from __future__ import annotations

import pytest
import yaml
from pydantic import ValidationError

from agent_assure.authoring.compiler import compile_suite
from agent_assure.authoring.yaml_lint import lint_yaml
from agent_assure.authoring.yaml_nodes import (
    MAX_YAML_BYTES,
    load_yaml_nodes,
    load_yaml_nodes_text,
    validate_yaml_nodes_text,
)


def test_yaml_node_composition_explicitly_uses_safe_loader(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    compose = yaml.compose
    loaders: list[type[yaml.SafeLoader]] = []

    def record_loader(text: str, *, Loader: type[yaml.SafeLoader]):  # type: ignore[no-untyped-def, name-defined]
        loaders.append(Loader)
        return compose(text, Loader=Loader)

    monkeypatch.setattr("agent_assure.authoring.yaml_nodes.yaml.compose", record_loader)

    loaded = load_yaml_nodes_text("suite_id: demo\n")
    validate_yaml_nodes_text("suite_id: demo\n")

    assert loaded.data == {"suite_id": "demo"}
    assert loaders == [yaml.SafeLoader, yaml.SafeLoader]


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


def test_yaml_structural_error_redacts_sensitive_mapping_key() -> None:
    secret = "Bearer ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    text = f'"{secret}": first\n"{secret}": second\n'

    with pytest.raises(ValueError, match="duplicate YAML mapping key") as raised:
        validate_yaml_nodes_text(text, label="test YAML")

    assert secret not in str(raised.value)
    assert "[REDACTED]" in str(raised.value)


@pytest.mark.parametrize("escaped_key", (r"\u001b[2Jspoof", r"evil\nline"))
def test_yaml_structural_error_escapes_control_characters(escaped_key: str) -> None:
    text = f'"{escaped_key}": first\n"{escaped_key}": second\n'

    with pytest.raises(ValueError, match="duplicate YAML mapping key") as raised:
        validate_yaml_nodes_text(text, label="test YAML")

    message = str(raised.value)
    assert "\x1b" not in message
    assert "evil\nline" not in message


def test_yaml_ambiguous_scalar_warning_redacts_sensitive_value() -> None:
    value = "4111111111111111"

    loaded = load_yaml_nodes_text(f"card: {value}\n")

    assert value not in loaded.warnings[0].message
    assert "[REDACTED]" in loaded.warnings[0].message


def test_yaml_warning_preserves_clean_structural_path() -> None:
    loaded = load_yaml_nodes_text("value: 00123\n")

    assert loaded.warnings[0].path == "$.value"


def test_yaml_structural_error_redacts_sensitive_key_split_across_lines() -> None:
    escaped_key = r"4111\n1111\n1111\n1111"
    text = f'"{escaped_key}": first\n"{escaped_key}": second\n'

    with pytest.raises(ValueError, match="duplicate YAML mapping key") as raised:
        validate_yaml_nodes_text(text, label="test YAML")

    message = str(raised.value)
    assert "4111" not in message
    assert "[REDACTED]" in message


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


def test_yaml_inline_merge_keys_are_rejected() -> None:
    with pytest.raises(ValueError, match="merge keys are not supported"):
        validate_yaml_nodes_text("outer:\n  <<: {key: value}\n")


@pytest.mark.parametrize("key", ("1", "01", "true", "null"))
def test_yaml_non_string_mapping_keys_are_rejected(key: str) -> None:
    with pytest.raises(ValueError, match="mapping keys must be strings"):
        validate_yaml_nodes_text(f"{key}: value\n")


def test_yaml_loader_rejects_oversized_file_before_parse(tmp_path) -> None:  # type: ignore[no-untyped-def]
    suite = tmp_path / "suite.yaml"
    suite.write_bytes(b"a" * (MAX_YAML_BYTES + 1))

    with pytest.raises(ValueError, match="suite YAML exceeds maximum supported size"):
        load_yaml_nodes(suite)


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


def test_empty_case_tool_allowlist_is_recorded_as_explicit_override(tmp_path) -> None:  # type: ignore[no-untyped-def]
    suite = tmp_path / "suite.yaml"
    suite.write_text(
        """
suite_id: demo
suite_version: 0.1.0
defaults:
  allowed_tools:
    - suite_tool
cases:
  - case_id: case-001
    title: No tools case
    expectation:
      allowed_tools: []
""".lstrip(),
        encoding="utf-8",
    )

    compiled = compile_suite(suite)
    expectation = compiled.resolved_expectations[0]

    assert expectation.allowed_tools == ()
    assert expectation.allowed_tools_override is True
