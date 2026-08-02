from __future__ import annotations

import errno
import hashlib
import json
import os
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
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
from agent_assure.mutation.campaign import execute_mutation_campaign
from agent_assure.mutation.execution import (
    MutationEvaluatorBinding,
    MutationExecution,
    execute_mutation,
)
from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.reporting import campaign as campaign_reporting
from agent_assure.reporting import mutation as mutation_reporting
from agent_assure.reporting.campaign import (
    MUTATION_CAMPAIGN_FILENAME,
    MUTATION_CAMPAIGN_GENERATION_MANIFEST_FILENAME,
    MUTATION_CATALOG_FILENAME,
    ensure_inputs_do_not_alias_mutation_campaign_output,
    validate_mutation_campaign_artifact_generation,
    write_mutation_campaign_artifacts,
)
from agent_assure.reporting.mutation import (
    EVIDENCE_DESCRIPTOR_FILENAME,
    MUTATED_RUNSET_FILENAME,
    MUTATION_GENERATION_MANIFEST_FILENAME,
    MUTATION_OUTPUT_LOCK_FILENAME,
    MUTATION_RESULT_FILENAME,
    ensure_inputs_do_not_alias_mutation_output,
    open_validated_mutation_artifact_generation,
    validate_mutation_artifact_generation,
    write_mutation_artifacts,
)
from agent_assure.runner.fixture_runner import write_runset
from agent_assure.schema.campaign import CORE_MUTATION_CATALOG_ID
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
    EvidenceRef,
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


def test_controls_mutate_refuses_a_filesystem_root_output_directory() -> None:
    filesystem_root = Path(Path.cwd().anchor)

    with pytest.raises(ValueError, match="filesystem root"):
        ensure_inputs_do_not_alias_mutation_output((), filesystem_root)
    with pytest.raises(ValueError, match="filesystem root"):
        ensure_inputs_do_not_alias_mutation_campaign_output((), filesystem_root)


def test_controls_mutate_help_states_exact_fail_fast_boundary() -> None:
    result = _RUNNER.invoke(app, ["controls", "mutate", "--help"])
    normalized = " ".join(
        result.output.replace("│", " ").replace("|", " ").split()
    )

    assert result.exit_code == 0, result.output
    assert "survived, invalid_operator, invalid_subject" in normalized
    assert "execution_error" in normalized
    assert "caught and inapplicable continue" in normalized


def test_controls_mutate_campaign_persists_a_valid_digest_bound_generation(
    tmp_path: Path,
) -> None:
    files = _write_fixture_files(tmp_path)
    source_bytes = files.runset.read_bytes()
    out = tmp_path / "campaign"

    result = _invoke_campaign(files.compiled_suite, files.runset, out)

    assert result.exit_code == 0, result.output
    assert "mutation campaign completion: complete" in result.output
    assert files.runset.read_bytes() == source_bytes
    paths = validate_mutation_campaign_artifact_generation(out)
    assert paths.catalog == out / MUTATION_CATALOG_FILENAME
    assert paths.campaign == out / MUTATION_CAMPAIGN_FILENAME
    assert paths.generation_manifest == (
        out / MUTATION_CAMPAIGN_GENERATION_MANIFEST_FILENAME
    )
    assert len(paths.operator_artifacts) == 1
    assert paths.operator_artifacts[0].operator_id == _OPERATOR
    assert validate_artifact(paths.catalog, "assurance-mutation-catalog") == (
        "pydantic+jsonschema"
    )
    assert validate_artifact(paths.campaign, "assurance-mutation-campaign") == (
        "pydantic+jsonschema"
    )
    _assert_canonical_json(paths.catalog)
    _assert_canonical_json(paths.campaign)
    _assert_canonical_json(paths.generation_manifest)

    campaign = _read_object(paths.campaign)
    assert campaign["catalog_id"] == CORE_MUTATION_CATALOG_ID
    assert campaign["selected_operator_order"] == [_OPERATOR]
    assert campaign["executed_operator_order"] == [_OPERATOR]
    assert campaign["pending_operator_order"] == []


def test_controls_mutate_campaign_reports_mixed_states_and_exact_scope(
    tmp_path: Path,
) -> None:
    files = _write_fixture_files(tmp_path)
    out = tmp_path / "campaign-mixed-states"

    result = _invoke_campaign(
        files.compiled_suite,
        files.runset,
        out,
        operators=(
            _OPERATOR,
            "bypass-required-human-review",
        ),
    )

    assert result.exit_code == 0, result.output
    normalized = " ".join(result.output.split())
    inapplicable_line = (
        "mutation operator result: "
        "operator_id=bypass-required-human-review "
        "state=inapplicable applicability=inapplicable"
    )
    caught_line = (
        "mutation operator result: "
        f"operator_id={_OPERATOR} state=caught applicability=applicable"
    )
    assert inapplicable_line in normalized
    assert caught_line in normalized
    assert normalized.index(inapplicable_line) < normalized.index(caught_line)
    assert (
        "mutation campaign state counts: caught=1, survived=0, inapplicable=1, "
        "invalid_operator=0, invalid_subject=0, execution_error=0"
    ) in normalized
    assert (
        "mutation campaign applicability counts: applicable=1, inapplicable=1, "
        "not_evaluated=0"
    ) in normalized
    assert (
        "caught entries support only their exact fixture transformations "
        "and expected-detector contracts"
    ) in normalized
    assert "caught does not assert exclusive detector isolation" in normalized
    assert "non-prohibited secondary findings remain visible" in normalized
    assert "inapplicable entries were not exercised" in normalized
    assert "independence_classes=first_party_postcontrol" in normalized
    assert "this campaign is not a safety score or mutation kill rate" in normalized
    assert "not a broader model, planner, or red-team robustness result" in normalized


def test_controls_mutate_campaign_accepts_repeatable_operator_filters(
    tmp_path: Path,
) -> None:
    files = _write_fixture_files(tmp_path)
    out = tmp_path / "campaign-filtered"

    result = _invoke_campaign(
        files.compiled_suite,
        files.runset,
        out,
        operators=(
            "inject-forbidden-tool",
            _OPERATOR,
        ),
    )

    assert result.exit_code == 0, result.output
    campaign = _read_object(out / MUTATION_CAMPAIGN_FILENAME)
    assert campaign["selected_operator_order"] == [
        _OPERATOR,
        "inject-forbidden-tool",
    ]
    assert campaign["executed_operator_order"] == [
        _OPERATOR,
        "inject-forbidden-tool",
    ]


def test_controls_mutate_campaign_routes_family_threat_and_fail_fast_filters(
    tmp_path: Path,
) -> None:
    files = _write_fixture_files(tmp_path)
    out = tmp_path / "campaign-family-threat"

    result = _invoke_campaign(
        files.compiled_suite,
        files.runset,
        out,
        operators=(),
        extra_args=(
            "--invariant-family",
            "material-evidence-linkage",
            "--threat-id",
            "AML.T0067.000",
            "--fail-fast",
        ),
    )

    assert result.exit_code == 0, result.output
    campaign = _read_object(out / MUTATION_CAMPAIGN_FILENAME)
    assert campaign["mode"] == "fail_fast"
    assert campaign["selected_operator_order"] == [_OPERATOR]
    assert campaign["executed_operator_order"] == [_OPERATOR]


def test_controls_mutate_campaign_rejects_conflicting_modes(
    tmp_path: Path,
) -> None:
    files = _write_fixture_files(tmp_path)
    out = tmp_path / "campaign-conflicting-mode"

    result = _invoke_campaign(
        files.compiled_suite,
        files.runset,
        out,
        extra_args=("--full-report", "--fail-fast"),
    )

    assert result.exit_code == 2
    assert "mutually exclusive" in result.output
    assert not out.exists()


def test_controls_mutate_campaign_rejects_noncanonical_source_without_artifacts(
    tmp_path: Path,
) -> None:
    files = _write_fixture_files(tmp_path)
    sensitive_value = "Bearer campaign-cli-secret-123456789"
    payload = _read_object(files.runset)
    payload["unexpected_float"] = 1.25
    payload["unexpected_context"] = sensitive_value
    files.runset.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    out = tmp_path / "campaign-noncanonical-source"

    result = _invoke_campaign(files.compiled_suite, files.runset, out)

    assert result.exit_code == 2
    normalized_output = " ".join(result.output.split())
    assert (
        "invalid mutation input: mutation campaign source cannot establish "
        "a canonical JSON identity"
    ) in normalized_output
    assert sensitive_value not in result.output
    assert not out.exists()


def test_controls_mutate_campaign_rejects_schema_invalid_source_without_artifacts(
    tmp_path: Path,
) -> None:
    files = _write_fixture_files(tmp_path)
    sensitive_value = "Bearer campaign-schema-secret-123456789"
    payload = _read_object(files.runset)
    payload.pop("suite_id")
    runs = cast(list[dict[str, object]], payload["runs"])
    runs[0]["input_summary"] = sensitive_value
    files.runset.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    source_bytes = files.runset.read_bytes()
    out = tmp_path / "campaign-schema-invalid-source"

    result = _invoke_campaign(files.compiled_suite, files.runset, out)

    assert result.exit_code == 2
    normalized_output = " ".join(result.output.split())
    assert (
        "invalid mutation input: mutation campaign source failed RunSet "
        "validation and projection"
    ) in normalized_output
    assert sensitive_value not in result.output
    assert files.runset.read_bytes() == source_bytes
    assert not out.exists()


def test_controls_mutate_campaign_rejects_sensitive_source_without_artifacts(
    tmp_path: Path,
) -> None:
    files = _write_fixture_files(tmp_path)
    sensitive_value = "Bearer campaign-privacy-secret-123456789"
    payload = _read_object(files.runset)
    runs = cast(list[dict[str, object]], payload["runs"])
    runs[0]["input_summary"] = sensitive_value
    files.runset.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    source_bytes = files.runset.read_bytes()
    out = tmp_path / "campaign-sensitive-source"

    result = _invoke_campaign(files.compiled_suite, files.runset, out)

    assert result.exit_code == 2
    normalized_output = " ".join(result.output.split())
    assert (
        "invalid mutation input: mutation campaign source failed the bound "
        "privacy-detector profile"
    ) in normalized_output
    assert sensitive_value not in result.output
    assert files.runset.read_bytes() == source_bytes
    assert not out.exists()


def test_controls_mutate_without_catalog_requires_exactly_one_operator(
    tmp_path: Path,
) -> None:
    files = _write_fixture_files(tmp_path)
    base_args = [
        "controls",
        "mutate",
        "--suite",
        str(files.compiled_suite),
        "--runset",
        str(files.runset),
        "--out",
        str(tmp_path / "legacy-cardinality"),
    ]

    missing = _RUNNER.invoke(app, base_args)
    repeated = _RUNNER.invoke(
        app,
        [
            *base_args,
            "--operator",
            _OPERATOR,
            "--operator",
            "inject-forbidden-tool",
        ],
    )

    assert missing.exit_code == 2
    assert repeated.exit_code == 2
    assert "exactly one --operator" in missing.output
    assert "exactly one --operator" in repeated.output
    assert not (tmp_path / "legacy-cardinality").exists()


def test_campaign_writer_rejects_guarded_out_of_range_operator_lookalike(
    tmp_path: Path,
) -> None:
    files = _write_fixture_files(tmp_path)
    suite = load_compiled_suite(files.compiled_suite)
    execution = execute_mutation_campaign(
        suite,
        _read_object(files.runset),
        seed=17,
        generated_at="2026-07-20T00:00:00Z",
        operator_ids=(_OPERATOR,),
    )
    out = tmp_path / "campaign-out-of-range-name"
    out.mkdir()
    external_input = out / "operator-999-mutation-result.json"
    external_input.write_bytes(b"not a campaign artifact")

    with pytest.raises(ValueError, match="aliases a protected campaign output"):
        ensure_inputs_do_not_alias_mutation_campaign_output((external_input,), out)
    with pytest.raises(ValueError, match="aliases a protected campaign output"):
        write_mutation_campaign_artifacts(
            execution,
            out,
            source_inputs=(
                files.compiled_suite,
                files.runset,
                external_input,
            ),
        )

    assert external_input.read_bytes() == b"not a campaign artifact"
    assert not (out / MUTATION_CAMPAIGN_GENERATION_MANIFEST_FILENAME).exists()

    write_mutation_campaign_artifacts(
        execution,
        out,
        source_inputs=(files.compiled_suite, files.runset),
    )

    assert not external_input.exists()
    validate_mutation_campaign_artifact_generation(out)


def test_campaign_validator_rejects_out_of_range_operator_lookalike(
    tmp_path: Path,
) -> None:
    files = _write_fixture_files(tmp_path)
    suite = load_compiled_suite(files.compiled_suite)
    execution = execute_mutation_campaign(
        suite,
        _read_object(files.runset),
        seed=17,
        generated_at="2026-07-20T00:00:00Z",
        operator_ids=(_OPERATOR,),
    )
    out = tmp_path / "campaign-lookalike-validation"
    write_mutation_campaign_artifacts(execution, out)
    lookalike = out / "operator-256-evidence-descriptor.json"
    lookalike.write_bytes(b"reserved campaign lookalike")

    with pytest.raises(ValueError, match="unexpected mutation campaign artifact"):
        validate_mutation_campaign_artifact_generation(out)


def test_single_and_campaign_writers_reject_mixed_namespaces_without_changes(
    tmp_path: Path,
) -> None:
    files = _write_fixture_files(tmp_path)
    suite = load_compiled_suite(files.compiled_suite)
    source_payload = _read_object(files.runset)
    single_execution = execute_mutation(
        suite,
        source_payload,
        operator_id=_OPERATOR,
        seed=17,
        generated_at="2026-07-20T00:00:00Z",
    )
    campaign_execution = execute_mutation_campaign(
        suite,
        source_payload,
        seed=17,
        generated_at="2026-07-20T00:00:00Z",
        operator_ids=(_OPERATOR,),
    )

    single_out = tmp_path / "single-namespace"
    write_mutation_artifacts(single_execution, single_out)
    single_before = _fixed_output_bytes(single_out)

    with pytest.raises(ValueError, match="mixes single and campaign"):
        write_mutation_campaign_artifacts(campaign_execution, single_out)

    assert _fixed_output_bytes(single_out) == single_before
    assert not (single_out / MUTATION_CAMPAIGN_GENERATION_MANIFEST_FILENAME).exists()
    assert not tuple(single_out.glob(".agent-assure-mutation-campaign-txn-*"))

    campaign_out = tmp_path / "campaign-namespace"
    write_mutation_campaign_artifacts(campaign_execution, campaign_out)
    campaign_before = {
        child.name: child.read_bytes()
        for child in campaign_out.iterdir()
        if child.is_file() and child.name != MUTATION_OUTPUT_LOCK_FILENAME
    }

    with pytest.raises(ValueError, match="mixes single and campaign"):
        write_mutation_artifacts(single_execution, campaign_out)

    assert {
        child.name: child.read_bytes()
        for child in campaign_out.iterdir()
        if child.is_file() and child.name != MUTATION_OUTPUT_LOCK_FILENAME
    } == campaign_before
    assert not (campaign_out / MUTATION_GENERATION_MANIFEST_FILENAME).exists()
    assert not tuple(campaign_out.glob(".agent-assure-mutation-txn-*"))


def test_single_and_campaign_validators_reject_mixed_namespaces(
    tmp_path: Path,
) -> None:
    files = _write_fixture_files(tmp_path)
    suite = load_compiled_suite(files.compiled_suite)
    source_payload = _read_object(files.runset)
    single_execution = execute_mutation(
        suite,
        source_payload,
        operator_id=_OPERATOR,
        seed=17,
        generated_at="2026-07-20T00:00:00Z",
    )
    campaign_execution = execute_mutation_campaign(
        suite,
        source_payload,
        seed=17,
        generated_at="2026-07-20T00:00:00Z",
        operator_ids=(_OPERATOR,),
    )

    single_out = tmp_path / "mixed-single-validator"
    write_mutation_artifacts(single_execution, single_out)
    (single_out / "operator-999-mutated-runset.json").write_bytes(
        b"foreign campaign lookalike"
    )
    with pytest.raises(ValueError, match="mixes single and campaign"):
        validate_mutation_artifact_generation(single_out)

    campaign_out = tmp_path / "mixed-campaign-validator"
    write_mutation_campaign_artifacts(campaign_execution, campaign_out)
    (campaign_out / MUTATION_RESULT_FILENAME).write_bytes(b"foreign single")
    with pytest.raises(ValueError, match="mixes single and campaign"):
        validate_mutation_campaign_artifact_generation(campaign_out)


def test_generation_validators_reject_symlinked_members(
    tmp_path: Path,
) -> None:
    files = _write_fixture_files(tmp_path)
    suite = load_compiled_suite(files.compiled_suite)
    source_payload = _read_object(files.runset)
    single_execution = execute_mutation(
        suite,
        source_payload,
        operator_id=_OPERATOR,
        seed=17,
        generated_at="2026-07-20T00:00:00Z",
    )
    campaign_execution = execute_mutation_campaign(
        suite,
        source_payload,
        seed=17,
        generated_at="2026-07-20T00:00:00Z",
        operator_ids=(_OPERATOR,),
    )

    single_out = tmp_path / "single-symlink-member"
    write_mutation_artifacts(single_execution, single_out)
    single_member = single_out / MUTATION_RESULT_FILENAME
    single_target = tmp_path / "single-result-target.json"
    os.replace(single_member, single_target)
    try:
        single_member.symlink_to(single_target)
    except OSError as exc:
        pytest.skip(f"file symlinks are unavailable: {exc}")

    with pytest.raises(ValueError, match="must be a regular file"):
        validate_mutation_artifact_generation(single_out)
    single_target_bytes = single_target.read_bytes()

    campaign_out = tmp_path / "campaign-symlink-member"
    write_mutation_campaign_artifacts(campaign_execution, campaign_out)
    campaign_member = campaign_out / "operator-000-mutation-result.json"
    campaign_target = tmp_path / "campaign-result-target.json"
    os.replace(campaign_member, campaign_target)
    campaign_member.symlink_to(campaign_target)

    with pytest.raises(ValueError, match="must be a regular file"):
        validate_mutation_campaign_artifact_generation(campaign_out)
    assert single_target.read_bytes() == single_target_bytes


def test_generation_validators_enforce_per_file_and_aggregate_bounds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    files = _write_fixture_files(tmp_path)
    suite = load_compiled_suite(files.compiled_suite)
    source_payload = _read_object(files.runset)
    execution = execute_mutation(
        suite,
        source_payload,
        operator_id=_OPERATOR,
        seed=17,
        generated_at="2026-07-20T00:00:00Z",
    )
    out = tmp_path / "bounded-single-generation"
    write_mutation_artifacts(execution, out)

    with monkeypatch.context() as bounded_file:
        bounded_file.setattr(mutation_reporting, "MAX_ARTIFACT_JSON_BYTES", 1)
        with pytest.raises(ValueError, match="exceeds maximum supported size"):
            validate_mutation_artifact_generation(out)

    manifest_size = (out / MUTATION_GENERATION_MANIFEST_FILENAME).stat().st_size
    with monkeypatch.context() as bounded_generation:
        bounded_generation.setattr(
            mutation_reporting,
            "_MAX_SINGLE_GENERATION_BYTES",
            manifest_size,
        )
        with pytest.raises(ValueError, match="maximum aggregate size"):
            validate_mutation_artifact_generation(out)

    campaign_execution = execute_mutation_campaign(
        suite,
        source_payload,
        seed=17,
        generated_at="2026-07-20T00:00:00Z",
        operator_ids=(_OPERATOR,),
    )
    campaign_out = tmp_path / "bounded-campaign-generation"
    write_mutation_campaign_artifacts(campaign_execution, campaign_out)
    campaign_manifest_size = (
        campaign_out / MUTATION_CAMPAIGN_GENERATION_MANIFEST_FILENAME
    ).stat().st_size
    with monkeypatch.context() as bounded_campaign:
        bounded_campaign.setattr(
            campaign_reporting,
            "_MAX_CAMPAIGN_GENERATION_BYTES",
            campaign_manifest_size,
        )
        with pytest.raises(ValueError, match="maximum aggregate size"):
            validate_mutation_campaign_artifact_generation(campaign_out)


@pytest.mark.skipif(
    os.path.normcase("Artifact.JSON") != os.path.normcase("artifact.json"),
    reason="requires a case-insensitive filesystem",
)
def test_campaign_writer_cleans_stale_case_variant_artifact(
    tmp_path: Path,
) -> None:
    files = _write_fixture_files(tmp_path)
    suite = load_compiled_suite(files.compiled_suite)
    source_payload = _read_object(files.runset)
    first = execute_mutation_campaign(
        suite,
        source_payload,
        seed=17,
        generated_at="2026-07-20T00:00:00Z",
        operator_ids=(_OPERATOR, "bypass-required-human-review"),
    )
    second = execute_mutation_campaign(
        suite,
        source_payload,
        seed=17,
        generated_at="2026-07-20T00:00:00Z",
        operator_ids=(_OPERATOR,),
    )
    out = tmp_path / "campaign-case-cleanup"
    write_mutation_campaign_artifacts(first, out)
    stale = out / "operator-001-mutation-result.json"
    case_variant = out / "OPERATOR-001-MUTATION-RESULT.JSON"
    os.replace(stale, case_variant)

    write_mutation_campaign_artifacts(second, out)

    assert not case_variant.exists()
    validate_mutation_campaign_artifact_generation(out)


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
    assert "caught this exact fixture transformation" in yaml_result.output
    normalized_output = " ".join(yaml_result.output.split())
    assert "not a broader model, planner, or red-team robustness result" in normalized_output
    assert "independence_class=first_party_postcontrol" in normalized_output
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


def test_controls_mutate_cli_applies_and_binds_waiver_gate_configuration(
    tmp_path: Path,
) -> None:
    files = _write_fixture_files(tmp_path)
    baseline_out = tmp_path / "gate-config-baseline"
    baseline = _invoke_mutate(files.compiled_suite, files.runset, baseline_out)
    assert baseline.exit_code == 0, baseline.output
    baseline_result = _read_object(baseline_out / MUTATION_RESULT_FILENAME)
    matched_ids = cast(list[str], baseline_result["matched_finding_ids"])
    waiver = tmp_path / "mutation-waiver.json"
    waiver.write_text(
        json.dumps(
            {
                "waiver_id": "waiver-cli-mutation-target",
                "owner": "test-owner",
                "rationale": "exercise configured mutation gate",
                "reason_code": "MATERIAL_CLAIM_MISSING_EVIDENCE",
                "finding_id": matched_ids[0],
                "artifact_digest": baseline_result["mutated_digest"],
                "expires_on": "2026-08-01",
                "reviewer": "test-reviewer",
            }
        ),
        encoding="utf-8",
    )

    waived_out = tmp_path / "gate-config-waived"
    waived = _invoke_mutate(
        files.compiled_suite,
        files.runset,
        waived_out,
        extra_args=("--waiver", str(waiver), "--today", "2026-07-20"),
    )
    assert waived.exit_code == 1, waived.output
    waived_result = _read_object(waived_out / MUTATION_RESULT_FILENAME)
    assert waived_result["state"] == "survived"
    assert waived_result["gate_profile_id"] == "default"
    assert waived_result["evaluation_date"] == "2026-07-20"
    assert waived_result["waiver_set_digest"] != baseline_result["waiver_set_digest"]

    fail_on_warn_out = tmp_path / "gate-config-fail-on-warn"
    fail_on_warn = _invoke_mutate(
        files.compiled_suite,
        files.runset,
        fail_on_warn_out,
        extra_args=(
            "--waiver",
            str(waiver),
            "--today",
            "2026-07-20",
            "--fail-on-warn",
        ),
    )
    assert fail_on_warn.exit_code == 0, fail_on_warn.output
    fail_on_warn_result = _read_object(fail_on_warn_out / MUTATION_RESULT_FILENAME)
    assert fail_on_warn_result["state"] == "caught"
    assert fail_on_warn_result["gate_profile_digest"] != waived_result["gate_profile_digest"]


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
    assert validate_artifact(result_path, "assurance-mutation-result") == ("pydantic+jsonschema")
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


def test_controls_mutate_rejects_input_at_output_lock_path_without_touching_it(
    tmp_path: Path,
) -> None:
    files = _write_fixture_files(tmp_path)
    out = tmp_path / "lock-alias-output"
    out.mkdir()
    aliased_runset = out / MUTATION_OUTPUT_LOCK_FILENAME
    source_bytes = files.runset.read_bytes()
    aliased_runset.write_bytes(source_bytes)

    result = _invoke_mutate(files.compiled_suite, aliased_runset, out)

    assert result.exit_code == 2, result.output
    assert "aliases a fixed mutation output path" in result.output
    assert aliased_runset.read_bytes() == source_bytes
    assert not (out / MUTATION_RESULT_FILENAME).exists()


def test_controls_mutate_rejects_linked_output_directory(
    tmp_path: Path,
) -> None:
    files = _write_fixture_files(tmp_path)
    real_out = tmp_path / "real-output"
    linked_out = tmp_path / "linked-output"
    real_out.mkdir()
    try:
        linked_out.symlink_to(real_out, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlinks are unavailable: {exc}")

    result = _invoke_mutate(files.compiled_suite, files.runset, linked_out)

    assert result.exit_code == 4, result.output
    assert "linked directory component" in result.output
    assert not (real_out / MUTATION_RESULT_FILENAME).exists()
    assert not (real_out / MUTATION_OUTPUT_LOCK_FILENAME).exists()


def test_controls_mutate_rejects_lock_symlink_without_modifying_target(
    tmp_path: Path,
) -> None:
    files = _write_fixture_files(tmp_path)
    out = tmp_path / "lock-symlink-output"
    out.mkdir()
    sentinel = tmp_path / "lock-symlink-sentinel"
    sentinel_bytes = b"do-not-modify"
    sentinel.write_bytes(sentinel_bytes)
    lock_path = out / MUTATION_OUTPUT_LOCK_FILENAME
    try:
        lock_path.symlink_to(sentinel)
    except OSError as exc:
        pytest.skip(f"file symlinks are unavailable: {exc}")

    result = _invoke_mutate(files.compiled_suite, files.runset, out)

    assert result.exit_code == 4, result.output
    assert "unsafe mutation output lock path" in result.output
    assert sentinel.read_bytes() == sentinel_bytes
    assert not (out / MUTATION_RESULT_FILENAME).exists()


def test_safe_lock_open_normalizes_nofollow_symlink_rejection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject_symlink(_path: Path, _flags: int, _mode: int) -> int:
        raise OSError(errno.ELOOP, "Too many levels of symbolic links")

    monkeypatch.setattr(os, "open", reject_symlink)

    with pytest.raises(OSError, match="refusing unsafe mutation output lock path"):
        mutation_reporting._open_safe_lock_file(tmp_path / MUTATION_OUTPUT_LOCK_FILENAME)


def test_controls_mutate_rejects_lock_hardlink_without_modifying_peer(
    tmp_path: Path,
) -> None:
    files = _write_fixture_files(tmp_path)
    out = tmp_path / "lock-hardlink-output"
    out.mkdir()
    sentinel = tmp_path / "lock-hardlink-sentinel"
    sentinel_bytes = b"do-not-modify"
    sentinel.write_bytes(sentinel_bytes)
    lock_path = out / MUTATION_OUTPUT_LOCK_FILENAME
    try:
        os.link(sentinel, lock_path)
    except OSError as exc:
        pytest.skip(f"hard links are unavailable: {exc}")

    result = _invoke_mutate(files.compiled_suite, files.runset, out)

    assert result.exit_code == 4, result.output
    assert "unsafe mutation output lock path" in result.output
    assert sentinel.read_bytes() == sentinel_bytes
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


def test_concurrent_writers_publish_only_complete_serialized_generations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    files = _write_fixture_files(tmp_path)
    suite = load_compiled_suite(files.compiled_suite)
    source_payload = _read_object(files.runset)
    executions = tuple(
        execute_mutation(
            suite,
            source_payload,
            operator_id=_OPERATOR,
            seed=seed,
            generated_at="2026-07-20T00:00:00Z",
        )
        for seed in (1, 2)
    )
    out = tmp_path / "concurrent-output"
    state_lock = threading.Lock()
    active_writers = 0
    max_active_writers = 0
    real_replace_generation = mutation_reporting._replace_output_generation

    def observed_replace_generation(*args: object, **kwargs: object) -> None:
        nonlocal active_writers, max_active_writers
        with state_lock:
            active_writers += 1
            max_active_writers = max(max_active_writers, active_writers)
        try:
            time.sleep(0.05)
            real_replace_generation(*args, **kwargs)  # type: ignore[arg-type]
        finally:
            with state_lock:
                active_writers -= 1

    monkeypatch.setattr(
        mutation_reporting,
        "_replace_output_generation",
        observed_replace_generation,
    )
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = tuple(
            executor.submit(write_mutation_artifacts, execution, out) for execution in executions
        )
        for future in futures:
            future.result()

    assert max_active_writers == 1
    with open_validated_mutation_artifact_generation(out) as paths:
        result = _read_object(paths.result)
        descriptor = _read_object(paths.evidence_descriptor)
        dependencies = cast(list[dict[str, object]], descriptor["dependencies"])
        assert any(
            dependency["digest"] == result["result_digest"]
            for dependency in dependencies
        )


def test_generation_manifest_fails_closed_on_partial_or_crash_torn_output(
    tmp_path: Path,
) -> None:
    files = _write_fixture_files(tmp_path)
    out = tmp_path / "torn-output"
    result = _invoke_mutate(files.compiled_suite, files.runset, out)
    assert result.exit_code == 0, result.output
    validate_mutation_artifact_generation(out)

    (out / MUTATION_RESULT_FILENAME).write_bytes(b"{}")

    with pytest.raises(ValueError, match="artifact digest does not match"):
        validate_mutation_artifact_generation(out)


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
    extra_args: tuple[str, ...] = (),
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
            *extra_args,
            "--out",
            str(out),
        ],
    )


def _invoke_campaign(
    suite: Path,
    runset: Path,
    out: Path,
    *,
    operators: tuple[str, ...] = (_OPERATOR,),
    seed: int = 17,
    extra_args: tuple[str, ...] = (),
) -> Result:
    operator_args = [
        argument
        for operator in operators
        for argument in ("--operator", operator)
    ]
    return _RUNNER.invoke(
        app,
        [
            "controls",
            "mutate",
            "--suite",
            str(suite),
            "--runset",
            str(runset),
            "--catalog",
            CORE_MUTATION_CATALOG_ID,
            *operator_args,
            "--seed",
            str(seed),
            *extra_args,
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
                evidence_refs=(
                    EvidenceRef(
                        ref_id="evidence-a",
                        source_id="source-a",
                    ),
                ),
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
        gate_profile_id="default",
        gate_profile_digest="c" * 64,
        waiver_set_digest="d" * 64,
        evaluation_date="2026-07-20",
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
            MUTATION_GENERATION_MANIFEST_FILENAME,
        )
    }


def _read_object(path: Path) -> dict[str, object]:
    return cast(dict[str, object], json.loads(path.read_text(encoding="utf-8")))
