from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import cast

import pytest
from typer.testing import CliRunner, Result

from agent_assure.authoring.compiler import compile_suite
from agent_assure.canonical.jcs import canonical_bytes
from agent_assure.canonical.normalize import digest_projection
from agent_assure.cli import controls_cmd
from agent_assure.cli.main import app
from agent_assure.evaluation.evaluator import EvaluationReport, evaluate_runset
from agent_assure.fixtures.loader import (
    compiled_suite_digest,
    load_compiled_suite,
    write_compiled_suite,
)
from agent_assure.mutation import catalog as mutation_catalog
from agent_assure.mutation import execution as mutation_execution
from agent_assure.mutation.execution import (
    MutationEvaluatorBinding,
    MutationExecution,
    execute_mutation,
)
from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.reporting import mutation as mutation_reporting
from agent_assure.reporting.mutation import (
    EVIDENCE_DESCRIPTOR_FILENAME,
    MUTATED_RUNSET_FILENAME,
    MUTATION_RESULT_FILENAME,
    write_mutation_artifacts,
)
from agent_assure.runner.fixture_runner import write_runset
from agent_assure.schema.common import ReasonCode
from agent_assure.schema.mutation import (
    RFC8785_SAFE_INTEGER_MAX,
    AssuranceEvidenceDescriptor,
    EvidenceEvaluationBasis,
)
from agent_assure.schema.provenance import Provenance
from agent_assure.schema.run import (
    AgentRunRecord,
    ClaimEvidenceLink,
    EvidenceItem,
    RunSet,
)
from agent_assure.schema.suite import CompiledSuite
from agent_assure.schema.validation import validate_artifact

_RUNNER = CliRunner()
_OPERATOR = "drop-material-evidence-link"


@dataclass(frozen=True)
class _FixtureFiles:
    suite_yaml: Path
    compiled_suite: Path
    runset: Path


def test_controls_mutate_accepts_yaml_and_persists_canonical_reproducible_artifacts(
    tmp_path: Path,
) -> None:
    files = _write_fixture_files(tmp_path)
    source_bytes = files.runset.read_bytes()
    yaml_out = tmp_path / "yaml-out"
    json_out = tmp_path / "json-out"

    yaml_result = _invoke_mutate(files.suite_yaml, files.runset, yaml_out, seed=7331)
    json_result = _invoke_mutate(files.compiled_suite, files.runset, json_out, seed=7331)

    assert yaml_result.exit_code == 0, yaml_result.output
    assert json_result.exit_code == 0, json_result.output
    assert "mutation state: caught" in yaml_result.output
    assert files.runset.read_bytes() == source_bytes

    result_path = yaml_out / MUTATION_RESULT_FILENAME
    descriptor_path = yaml_out / EVIDENCE_DESCRIPTOR_FILENAME
    mutated_path = yaml_out / MUTATED_RUNSET_FILENAME
    assert result_path.is_file()
    assert descriptor_path.is_file()
    assert mutated_path.is_file()
    assert validate_artifact(result_path, "assurance-mutation-result") == ("pydantic+jsonschema")
    assert validate_artifact(descriptor_path, "assurance-evidence-descriptor") == (
        "pydantic+jsonschema"
    )
    assert validate_artifact(mutated_path, "run-set") == "pydantic+jsonschema"
    _assert_canonical_json(result_path)
    _assert_canonical_json(descriptor_path)
    _assert_canonical_json(mutated_path)

    result_payload = _read_object(result_path)
    assert result_payload["state"] == "caught"
    assert result_payload["seed"] == 7331
    assert result_payload["changed_paths"] == ["/runs/0/claim_evidence_links"]
    assert result_payload["mutated_digest"] == hashlib.sha256(mutated_path.read_bytes()).hexdigest()

    assert result_path.read_bytes() == (json_out / MUTATION_RESULT_FILENAME).read_bytes()
    assert mutated_path.read_bytes() == (json_out / MUTATED_RUNSET_FILENAME).read_bytes()


def test_controls_mutate_maps_survived_to_exit_one(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    files = _write_fixture_files(tmp_path)
    monkeypatch.setattr(
        controls_cmd,
        "execute_mutation",
        partial(
            execute_mutation,
            evaluator_binding=_bound_evaluator(_without_material_evidence_detector),
        ),
    )
    out = tmp_path / "survived"

    result = _invoke_mutate(files.compiled_suite, files.runset, out)

    assert result.exit_code == 1, result.output
    assert _read_object(out / MUTATION_RESULT_FILENAME)["state"] == "survived"
    assert (out / MUTATED_RUNSET_FILENAME).is_file()


def test_controls_mutate_maps_both_invalid_states_to_exit_two(tmp_path: Path) -> None:
    files = _write_fixture_files(tmp_path)
    invalid_subject = tmp_path / "invalid-runset.json"
    invalid_subject.write_text("{}", encoding="utf-8")

    invalid_operator_out = tmp_path / "invalid-operator"
    invalid_operator = _invoke_mutate(
        files.compiled_suite,
        files.runset,
        invalid_operator_out,
        operator="unregistered-operator",
    )
    invalid_subject_out = tmp_path / "invalid-subject"
    invalid_runset = _invoke_mutate(
        files.compiled_suite,
        invalid_subject,
        invalid_subject_out,
    )

    assert invalid_operator.exit_code == 2, invalid_operator.output
    assert invalid_runset.exit_code == 2, invalid_runset.output
    assert _read_object(invalid_operator_out / MUTATION_RESULT_FILENAME)["state"] == (
        "invalid_operator"
    )
    assert _read_object(invalid_subject_out / MUTATION_RESULT_FILENAME)["state"] == (
        "invalid_subject"
    )
    assert not (invalid_operator_out / MUTATED_RUNSET_FILENAME).exists()
    assert not (invalid_subject_out / MUTATED_RUNSET_FILENAME).exists()


def test_controls_mutate_rejects_sensitive_summary_without_rewriting_source(
    tmp_path: Path,
) -> None:
    files = _write_fixture_files(tmp_path)
    sensitive_value = "Bearer abcdefghijklmnopqrstuvwxyz123456"
    payload = _read_object(files.runset)
    runs = cast(list[dict[str, object]], payload["runs"])
    runs[0]["input_summary"] = sensitive_value
    files.runset.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    source_bytes = files.runset.read_bytes()
    out = tmp_path / "sensitive-summary"

    result = _invoke_mutate(files.compiled_suite, files.runset, out)

    assert result.exit_code == 2, result.output
    assert _read_object(out / MUTATION_RESULT_FILENAME)["state"] == "invalid_subject"
    assert files.runset.read_bytes() == source_bytes
    assert not (out / MUTATED_RUNSET_FILENAME).exists()
    assert sensitive_value not in (out / MUTATION_RESULT_FILENAME).read_text(encoding="utf-8")
    assert sensitive_value not in (out / EVIDENCE_DESCRIPTOR_FILENAME).read_text(encoding="utf-8")


def test_controls_mutate_sanitizes_sensitive_unknown_operator_identity(
    tmp_path: Path,
) -> None:
    files = _write_fixture_files(tmp_path)
    sensitive_operator = "sk-proj-" + ("C" * 24)
    out = tmp_path / "sensitive-operator"

    result = _invoke_mutate(
        files.compiled_suite,
        files.runset,
        out,
        operator=sensitive_operator,
    )

    assert result.exit_code == 2, result.output
    result_payload = _read_object(out / MUTATION_RESULT_FILENAME)
    assert result_payload["state"] == "invalid_operator"
    assert result_payload["operator_id"] == "unknown-operator"
    assert sensitive_operator not in (out / MUTATION_RESULT_FILENAME).read_text(encoding="utf-8")
    assert sensitive_operator not in (out / EVIDENCE_DESCRIPTOR_FILENAME).read_text(
        encoding="utf-8"
    )


def test_controls_mutate_maps_inapplicable_to_exit_three(tmp_path: Path) -> None:
    files = _write_fixture_files(tmp_path)
    out = tmp_path / "inapplicable"

    result = _invoke_mutate(
        files.compiled_suite,
        files.runset,
        out,
        operator="inject-forbidden-tool",
    )

    assert result.exit_code == 3, result.output
    assert _read_object(out / MUTATION_RESULT_FILENAME)["state"] == "inapplicable"
    assert not (out / MUTATED_RUNSET_FILENAME).exists()


def test_controls_mutate_maps_execution_error_to_exit_four_without_leaking_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    files = _write_fixture_files(tmp_path)
    sensitive_error = "Bearer abcdefghijklmnopqrstuvwxyz123456"

    def failing_evaluator(
        _suite: CompiledSuite,
        _runset: RunSet,
    ) -> EvaluationReport:
        raise RuntimeError(sensitive_error)

    monkeypatch.setattr(
        controls_cmd,
        "execute_mutation",
        partial(
            execute_mutation,
            evaluator_binding=_bound_evaluator(failing_evaluator),
        ),
    )
    out = tmp_path / "execution-error"

    result = _invoke_mutate(files.compiled_suite, files.runset, out)

    assert result.exit_code == 4, result.output
    assert _read_object(out / MUTATION_RESULT_FILENAME)["state"] == "execution_error"
    assert sensitive_error not in result.output
    assert sensitive_error not in (out / MUTATION_RESULT_FILENAME).read_text(encoding="utf-8")
    assert sensitive_error not in (out / EVIDENCE_DESCRIPTOR_FILENAME).read_text(encoding="utf-8")


def test_controls_mutate_persists_structured_catalog_bootstrap_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    files = _write_fixture_files(tmp_path)
    sensitive_error = "C:/private/build/package/component.py"

    def fail_component_read(_relative_path: str) -> bytes:
        raise OSError(sensitive_error)

    mutation_execution._built_in_evaluator_binding.cache_clear()
    mutation_catalog._operator_catalog.cache_clear()
    monkeypatch.setattr(mutation_catalog, "_read_packaged_component", fail_component_read)
    out = tmp_path / "catalog-bootstrap-error"
    try:
        result = _invoke_mutate(files.compiled_suite, files.runset, out)
    finally:
        mutation_execution._built_in_evaluator_binding.cache_clear()
        mutation_catalog._operator_catalog.cache_clear()

    assert result.exit_code == 4, result.output
    result_path = out / MUTATION_RESULT_FILENAME
    descriptor_path = out / EVIDENCE_DESCRIPTOR_FILENAME
    result_payload = _read_object(result_path)
    assert result_payload["state"] == "execution_error"
    assert result_payload["diagnostic_code"] == "catalog_integrity_error"
    assert result_payload["evaluator_implementation_digest"] == "0" * 64
    assert validate_artifact(result_path, "assurance-mutation-result") == (
        "pydantic+jsonschema"
    )
    assert validate_artifact(descriptor_path, "assurance-evidence-descriptor") == (
        "pydantic+jsonschema"
    )
    assert sensitive_error not in result.output
    assert sensitive_error not in result_path.read_text(encoding="utf-8")
    assert sensitive_error not in descriptor_path.read_text(encoding="utf-8")
    assert not (out / MUTATED_RUNSET_FILENAME).exists()


def test_controls_mutate_hides_unexpected_exception_details(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    files = _write_fixture_files(tmp_path)
    sensitive_error = "Bearer abcdefghijklmnopqrstuvwxyz123456"

    def unexpected_failure(*_args: object, **_kwargs: object) -> MutationExecution:
        raise RuntimeError(sensitive_error)

    monkeypatch.setattr(controls_cmd, "execute_mutation", unexpected_failure)
    out = tmp_path / "unexpected-exception"

    result = _invoke_mutate(files.compiled_suite, files.runset, out)

    assert result.exit_code == 4, result.output
    assert "mutation execution error: bounded internal error" in result.output
    assert sensitive_error not in result.output
    assert not out.exists()


def test_controls_mutate_rejects_over_depth_input_before_execution(tmp_path: Path) -> None:
    files = _write_fixture_files(tmp_path)
    over_depth = tmp_path / "over-depth.json"
    over_depth.write_text('{"nested":' + "[" * 81 + "0" + "]" * 81 + "}", encoding="utf-8")
    out = tmp_path / "over-depth-out"

    result = _invoke_mutate(files.compiled_suite, over_depth, out)

    assert result.exit_code == 2, result.output
    assert "exceeds maximum supported nesting depth" in result.output
    assert not out.exists()


@pytest.mark.parametrize("seed", (-1, RFC8785_SAFE_INTEGER_MAX + 1))
def test_controls_mutate_rejects_seed_outside_canonical_integer_domain(
    tmp_path: Path,
    seed: int,
) -> None:
    files = _write_fixture_files(tmp_path)
    out = tmp_path / "invalid-seed"

    result = _invoke_mutate(files.compiled_suite, files.runset, out, seed=seed)

    assert result.exit_code == 2, result.output
    assert not out.exists()


def test_controls_mutate_rejects_runset_at_fixed_output_path(tmp_path: Path) -> None:
    files = _write_fixture_files(tmp_path)
    out = tmp_path / "direct-alias"
    out.mkdir()
    aliased_runset = out / MUTATED_RUNSET_FILENAME
    source_bytes = files.runset.read_bytes()
    aliased_runset.write_bytes(source_bytes)

    result = _invoke_mutate(files.compiled_suite, aliased_runset, out)

    assert result.exit_code == 2, result.output
    assert "aliases a fixed mutation output path" in result.output
    assert aliased_runset.read_bytes() == source_bytes
    assert not (out / MUTATION_RESULT_FILENAME).exists()
    assert not (out / EVIDENCE_DESCRIPTOR_FILENAME).exists()


def test_controls_mutate_rejects_suite_at_fixed_output_path(tmp_path: Path) -> None:
    files = _write_fixture_files(tmp_path)
    out = tmp_path / "suite-direct-alias"
    out.mkdir()
    aliased_suite = out / MUTATION_RESULT_FILENAME
    source_bytes = files.compiled_suite.read_bytes()
    aliased_suite.write_bytes(source_bytes)

    result = _invoke_mutate(aliased_suite, files.runset, out)

    assert result.exit_code == 2, result.output
    assert "aliases a fixed mutation output path" in result.output
    assert aliased_suite.read_bytes() == source_bytes
    assert not (out / EVIDENCE_DESCRIPTOR_FILENAME).exists()
    assert not (out / MUTATED_RUNSET_FILENAME).exists()


def test_controls_mutate_rejects_suite_hard_link_alias_without_touching_source(
    tmp_path: Path,
) -> None:
    files = _write_fixture_files(tmp_path)
    out = tmp_path / "suite-hard-link-alias"
    out.mkdir()
    alias = out / EVIDENCE_DESCRIPTOR_FILENAME
    try:
        os.link(files.compiled_suite, alias)
    except OSError as exc:
        pytest.skip(f"hard links are unavailable: {exc}")
    source_bytes = files.compiled_suite.read_bytes()

    result = _invoke_mutate(files.compiled_suite, files.runset, out)

    assert result.exit_code == 2, result.output
    assert files.compiled_suite.read_bytes() == source_bytes
    assert os.path.samefile(files.compiled_suite, alias)
    assert not (out / MUTATION_RESULT_FILENAME).exists()


def test_controls_mutate_rejects_suite_symlink_alias_without_touching_source(
    tmp_path: Path,
) -> None:
    files = _write_fixture_files(tmp_path)
    out = tmp_path / "suite-symlink-alias"
    out.mkdir()
    alias = out / MUTATED_RUNSET_FILENAME
    try:
        alias.symlink_to(files.compiled_suite)
    except OSError as exc:
        pytest.skip(f"symbolic links are unavailable: {exc}")
    source_bytes = files.compiled_suite.read_bytes()

    result = _invoke_mutate(files.compiled_suite, files.runset, out)

    assert result.exit_code == 2, result.output
    assert files.compiled_suite.read_bytes() == source_bytes
    assert alias.is_symlink()
    assert not (out / MUTATION_RESULT_FILENAME).exists()
    assert not (out / EVIDENCE_DESCRIPTOR_FILENAME).exists()


def test_controls_mutate_rejects_hard_link_alias_without_touching_source(
    tmp_path: Path,
) -> None:
    files = _write_fixture_files(tmp_path)
    out = tmp_path / "hard-link-alias"
    out.mkdir()
    alias = out / MUTATION_RESULT_FILENAME
    try:
        os.link(files.runset, alias)
    except OSError as exc:
        pytest.skip(f"hard links are unavailable: {exc}")
    source_bytes = files.runset.read_bytes()

    result = _invoke_mutate(files.compiled_suite, files.runset, out)

    assert result.exit_code == 2, result.output
    assert files.runset.read_bytes() == source_bytes
    assert os.path.samefile(files.runset, alias)
    assert not (out / EVIDENCE_DESCRIPTOR_FILENAME).exists()


def test_controls_mutate_rejects_symlink_alias_without_touching_source(
    tmp_path: Path,
) -> None:
    files = _write_fixture_files(tmp_path)
    out = tmp_path / "symlink-alias"
    out.mkdir()
    alias = out / EVIDENCE_DESCRIPTOR_FILENAME
    try:
        alias.symlink_to(files.runset)
    except OSError as exc:
        pytest.skip(f"symbolic links are unavailable: {exc}")
    source_bytes = files.runset.read_bytes()

    result = _invoke_mutate(files.compiled_suite, files.runset, out)

    assert result.exit_code == 2, result.output
    assert files.runset.read_bytes() == source_bytes
    assert alias.is_symlink()
    assert not (out / MUTATION_RESULT_FILENAME).exists()


def test_controls_mutate_replaces_unrelated_output_symlink_without_following_target(
    tmp_path: Path,
) -> None:
    files = _write_fixture_files(tmp_path)
    out = tmp_path / "unrelated-symlink"
    out.mkdir()
    sentinel = tmp_path / "sentinel.txt"
    sentinel_bytes = b"must remain unchanged"
    sentinel.write_bytes(sentinel_bytes)
    output_symlink = out / EVIDENCE_DESCRIPTOR_FILENAME
    try:
        output_symlink.symlink_to(sentinel)
    except OSError as exc:
        pytest.skip(f"symbolic links are unavailable: {exc}")

    result = _invoke_mutate(files.compiled_suite, files.runset, out)

    assert result.exit_code == 0, result.output
    assert sentinel.read_bytes() == sentinel_bytes
    assert not output_symlink.is_symlink()
    assert validate_artifact(output_symlink, "assurance-evidence-descriptor") == (
        "pydantic+jsonschema"
    )


def test_controls_mutate_replaces_unrelated_output_hard_link_without_modifying_peer(
    tmp_path: Path,
) -> None:
    files = _write_fixture_files(tmp_path)
    out = tmp_path / "unrelated-hard-link"
    out.mkdir()
    sentinel = tmp_path / "hard-link-sentinel.txt"
    sentinel_bytes = b"must remain unchanged"
    sentinel.write_bytes(sentinel_bytes)
    output_link = out / MUTATION_RESULT_FILENAME
    try:
        os.link(sentinel, output_link)
    except OSError as exc:
        pytest.skip(f"hard links are unavailable: {exc}")

    result = _invoke_mutate(files.compiled_suite, files.runset, out)

    assert result.exit_code == 0, result.output
    assert sentinel.read_bytes() == sentinel_bytes
    assert not os.path.samefile(sentinel, output_link)
    assert validate_artifact(output_link, "assurance-mutation-result") == ("pydantic+jsonschema")


def test_controls_mutate_removes_stale_mutated_runset_on_reused_output_dir(
    tmp_path: Path,
) -> None:
    files = _write_fixture_files(tmp_path)
    out = tmp_path / "reused-output"
    first = _invoke_mutate(files.compiled_suite, files.runset, out)
    assert first.exit_code == 0, first.output
    assert (out / MUTATED_RUNSET_FILENAME).is_file()

    second = _invoke_mutate(
        files.compiled_suite,
        files.runset,
        out,
        operator="inject-forbidden-tool",
    )

    assert second.exit_code == 3, second.output
    assert _read_object(out / MUTATION_RESULT_FILENAME)["state"] == "inapplicable"
    assert not (out / MUTATED_RUNSET_FILENAME).exists()
    assert (
        validate_artifact(
            out / EVIDENCE_DESCRIPTOR_FILENAME,
            "assurance-evidence-descriptor",
        )
        == "pydantic+jsonschema"
    )


def test_staging_write_failure_preserves_prior_complete_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    files = _write_fixture_files(tmp_path)
    out = tmp_path / "stage-failure"
    first = _invoke_mutate(files.compiled_suite, files.runset, out, seed=1)
    assert first.exit_code == 0, first.output
    prior_generation = _fixed_output_bytes(out)
    real_write = mutation_reporting._write_staged_file

    def failing_write(path: Path, content: bytes) -> None:
        if path.name == f"new-{EVIDENCE_DESCRIPTOR_FILENAME}":
            raise OSError("injected staging write failure")
        real_write(path, content)

    monkeypatch.setattr(mutation_reporting, "_write_staged_file", failing_write)

    second = _invoke_mutate(files.compiled_suite, files.runset, out, seed=2)

    assert second.exit_code == 4, second.output
    assert _fixed_output_bytes(out) == prior_generation
    assert not tuple(out.glob(".agent-assure-mutation-txn-*"))


def test_atomic_replace_failure_rolls_back_prior_complete_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    files = _write_fixture_files(tmp_path)
    out = tmp_path / "replace-failure"
    first = _invoke_mutate(files.compiled_suite, files.runset, out, seed=1)
    assert first.exit_code == 0, first.output
    prior_generation = _fixed_output_bytes(out)
    real_replace = mutation_reporting._replace_entry
    failure_injected = False

    def failing_replace(source: Path, destination: Path) -> None:
        nonlocal failure_injected
        is_descriptor_commit = (
            source.name == f"new-{EVIDENCE_DESCRIPTOR_FILENAME}"
            and destination.name == EVIDENCE_DESCRIPTOR_FILENAME
        )
        if is_descriptor_commit and not failure_injected:
            failure_injected = True
            raise OSError("injected atomic replace failure")
        real_replace(source, destination)

    monkeypatch.setattr(mutation_reporting, "_replace_entry", failing_replace)

    second = _invoke_mutate(files.compiled_suite, files.runset, out, seed=2)

    assert second.exit_code == 4, second.output
    assert failure_injected is True
    assert _fixed_output_bytes(out) == prior_generation
    assert not tuple(out.glob(".agent-assure-mutation-txn-*"))


def test_writer_rejects_individually_valid_but_mismatched_result_descriptor_pair(
    tmp_path: Path,
) -> None:
    files = _write_fixture_files(tmp_path)
    suite = load_compiled_suite(files.compiled_suite)
    source_payload = _read_object(files.runset)
    first = execute_mutation(
        suite,
        source_payload,
        operator_id=_OPERATOR,
        seed=1,
        generated_at="2026-07-20T00:00:00Z",
    )
    second = execute_mutation(
        suite,
        source_payload,
        operator_id=_OPERATOR,
        seed=2,
        generated_at="2026-07-20T00:00:00Z",
    )
    assert first.result.result_digest != second.result.result_digest
    mismatched = MutationExecution(
        result=first.result,
        evidence_descriptor=second.evidence_descriptor,
        mutated_payload=first.mutated_payload,
        suite_digest=first.suite_digest,
        generated_at=first.generated_at,
    )
    out = tmp_path / "mismatched-pair"

    with pytest.raises(ValueError, match="does not depend on this mutation result digest"):
        write_mutation_artifacts(mismatched, out, source_inputs=(files.runset,))

    assert not out.exists()


def test_writer_rejects_semantically_altered_but_self_valid_descriptor(
    tmp_path: Path,
) -> None:
    files = _write_fixture_files(tmp_path)
    suite = load_compiled_suite(files.compiled_suite)
    execution = execute_mutation(
        suite,
        _read_object(files.runset),
        operator_id=_OPERATOR,
        seed=17,
        generated_at="2026-07-20T00:00:00Z",
    )
    descriptor_payload = execution.evidence_descriptor.model_dump(
        mode="json",
        exclude={"evidence_digest"},
    )
    result_projection = cast(dict[str, object], descriptor_payload["result"])
    result_projection["state"] = "contradicted"
    altered_descriptor = AssuranceEvidenceDescriptor.build(**descriptor_payload)
    altered = MutationExecution(
        result=execution.result,
        evidence_descriptor=altered_descriptor,
        mutated_payload=execution.mutated_payload,
        suite_digest=execution.suite_digest,
        generated_at=execution.generated_at,
    )
    out = tmp_path / "altered-descriptor"

    with pytest.raises(ValueError, match="complete mutation result projection"):
        write_mutation_artifacts(
            altered,
            out,
            source_inputs=(files.compiled_suite, files.runset),
        )

    assert not out.exists()


def _invoke_mutate(
    suite: Path,
    runset: Path,
    out: Path,
    *,
    operator: str = _OPERATOR,
    seed: int = 17,
) -> Result:
    return _RUNNER.invoke(
        app,
        [
            "controls",
            "mutate",
            "--suite",
            str(suite),
            "--runset",
            str(runset),
            "--operator",
            operator,
            "--seed",
            str(seed),
            "--out",
            str(out),
        ],
    )


def _write_fixture_files(tmp_path: Path) -> _FixtureFiles:
    suite_yaml = tmp_path / "suite.yaml"
    suite_yaml.write_text(
        """\
suite_id: mutation-cli-suite
suite_version: "1.0.0"
defaults:
  runner_id: mutation.cli.tests
cases:
  - case_id: case-a
    title: Mutation CLI test case
    expectation:
      material_claim_ids:
        - claim-a
""",
        encoding="utf-8",
    )
    suite = compile_suite(suite_yaml)
    compiled_suite = tmp_path / "compiled-suite.json"
    write_compiled_suite(suite, compiled_suite)

    fixture_digest = "c" * 64
    runset = RunSet(
        runset_id="mutation-cli-runset",
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        suite_id=suite.suite_id,
        suite_version=suite.suite_version,
        suite_digest=compiled_suite_digest(suite),
        fixture_manifest_digest=fixture_digest,
        runs=(
            AgentRunRecord(
                run_id="run-case-a",
                case_id="case-a",
                pipeline_id="mutation.cli.tests",
                recommendation="approve",
                outcome="approved",
                input_summary="synthetic input",
                output_summary="synthetic output",
                evidence_items=(
                    EvidenceItem(
                        ref_id="evidence-a",
                        source_id="source-a",
                        content_digest="d" * 64,
                    ),
                ),
                claim_evidence_links=(
                    ClaimEvidenceLink(
                        claim_id="claim-a",
                        evidence_ref_id="evidence-a",
                    ),
                ),
                provenance=Provenance(fixture_manifest_digest=fixture_digest),
            ),
        ),
    )
    runset_path = tmp_path / "runset.json"
    write_runset(runset, runset_path)
    return _FixtureFiles(
        suite_yaml=suite_yaml,
        compiled_suite=compiled_suite,
        runset=runset_path,
    )


def _without_material_evidence_detector(
    suite: CompiledSuite,
    runset: RunSet,
) -> EvaluationReport:
    report = evaluate_runset(suite, runset)
    findings = tuple(
        finding
        for finding in report.candidate_vs_expectations.findings
        if not (
            finding.control_id == "material_claims_have_evidence"
            and finding.reason_code is ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE
        )
    )
    failed_controls = tuple(
        finding
        for finding in report.failed_controls
        if not (
            finding.control_id == "material_claims_have_evidence"
            and finding.reason_code is ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE
        )
    )
    summary = report.candidate_vs_expectations.model_copy(update={"findings": findings})
    return report.model_copy(
        update={
            "candidate_vs_expectations": summary,
            "failed_controls": failed_controls,
        }
    )


def _bound_evaluator(
    evaluator: Callable[[CompiledSuite, RunSet], EvaluationReport],
) -> MutationEvaluatorBinding:
    return MutationEvaluatorBinding(
        evaluator=evaluator,
        method_id="assurance-mutation/integration-test-evaluator/v1",
        implementation_version="1.0.0",
        implementation_digest="e" * 64,
        evaluation_basis=EvidenceEvaluationBasis.deterministic,
        protocol_digest=None,
        population_id="deterministic-fixture-v1",
    )


def _assert_canonical_json(path: Path) -> None:
    payload = _read_object(path)
    assert path.read_bytes() == canonical_bytes(digest_projection(payload))


def _fixed_output_bytes(out: Path) -> dict[str, bytes]:
    return {
        filename: (out / filename).read_bytes()
        for filename in (
            MUTATION_RESULT_FILENAME,
            EVIDENCE_DESCRIPTOR_FILENAME,
            MUTATED_RUNSET_FILENAME,
        )
    }


def _read_object(path: Path) -> dict[str, object]:
    return cast(dict[str, object], json.loads(path.read_text(encoding="utf-8")))
