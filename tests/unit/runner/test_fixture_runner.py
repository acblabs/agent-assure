from __future__ import annotations

import json
import pickle
import shutil
from pathlib import Path

import pytest
from pydantic import ValidationError

import agent_assure.runner.fixture_runner as fixture_runner_module
from agent_assure.authoring.compiler import compile_suite
from agent_assure.authoring.yaml_nodes import MAX_YAML_DEPTH
from agent_assure.fixtures.loader import compiled_suite_digest
from agent_assure.fixtures.manifest import build_fixture_manifest, fixture_manifest_digest
from agent_assure.fixtures.resolver import FixtureResolver
from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.runner.clock import DeterministicClock
from agent_assure.runner.fixture_runner import (
    _BUNDLED_SYNTHETIC_SUITE_IDENTITIES,
    RunnerContext,
    load_variant_config,
    run_suite,
    write_runset,
)
from agent_assure.runner.ids import DeterministicIds
from agent_assure.schema.common import ReasonCode
from agent_assure.schema.run import AgentRunRecord, RunSet

SUITE = Path("examples/prior_auth_synthetic/suite.yaml")
BASELINE = Path("examples/prior_auth_synthetic/variants/baseline.yaml")
RAG_SUITE = Path("examples/prior_auth_synthetic/rag_suite.yaml")
RAG_BASELINE = Path("examples/prior_auth_synthetic/variants/rag_baseline.yaml")


@pytest.mark.parametrize(
    ("suite_id", "suite_path"),
    (
        ("expense-approval-minimal", Path("examples/expense_approval_minimal/suite.yaml")),
        ("prior-auth-synthetic", SUITE),
        ("prior-auth-synthetic-rag", Path("examples/prior_auth_synthetic/rag_suite.yaml")),
        (
            "process-measurement-cases",
            Path("examples/process_measurement_cases/suite.yaml"),
        ),
    ),
)
def test_bundled_synthetic_hmac_identities_match_reviewed_artifacts(
    suite_id: str,
    suite_path: Path,
) -> None:
    compiled = compile_suite(suite_path)
    manifest = build_fixture_manifest(compiled, suite_path.parent)
    identity = _BUNDLED_SYNTHETIC_SUITE_IDENTITIES[suite_id]

    assert compiled_suite_digest(compiled) == identity.compiled_suite_digest
    assert fixture_manifest_digest(manifest) == identity.fixture_manifest_digest


def test_deterministic_ids_are_stable() -> None:
    ids = DeterministicIds()
    assert ids.run_id("suite", "variant", "case") == ids.run_id("suite", "variant", "case")
    assert ids.run_id("suite", "variant", "case") != ids.run_id("suite", "variant", "other")


def test_runner_context_remains_pickleable() -> None:
    compiled = compile_suite(SUITE)
    manifest = build_fixture_manifest(compiled, SUITE.parent)
    context = RunnerContext(
        suite=compiled,
        suite_root=SUITE.parent,
        variant=load_variant_config(BASELINE),
        clock=DeterministicClock(),
        ids=DeterministicIds(),
        resolver=FixtureResolver(SUITE.parent),
        hmac_key=b"private-test-key-32-byte-value-0000",
        fixture_manifest=manifest,
        fixture_manifest_digest=fixture_manifest_digest(manifest),
    )

    restored = pickle.loads(pickle.dumps(context))

    assert restored == context
    assert restored.fixture_entries_by_path == context.fixture_entries_by_path


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


def test_variant_config_rejects_duplicate_yaml_keys(tmp_path: Path) -> None:
    variant = tmp_path / "variant.yaml"
    variant.write_text(
        "variant_id: first\nvariant_id: second\nrunner_id: prior_auth.synthetic\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="duplicate YAML mapping key"):
        load_variant_config(variant)


def test_variant_config_rejects_yaml_aliases(tmp_path: Path) -> None:
    variant = tmp_path / "variant.yaml"
    variant.write_text(
        "variant_id: &variant baseline\npipeline_id: *variant\nrunner_id: prior_auth.synthetic\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="aliases are not supported"):
        load_variant_config(variant)


def test_variant_config_rejects_excessive_yaml_nesting(tmp_path: Path) -> None:
    variant = tmp_path / "variant.yaml"
    variant.write_text(
        "variant_id: " + ("[" * (MAX_YAML_DEPTH + 1)) + "baseline" + ("]" * (MAX_YAML_DEPTH + 1)),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="exceeds maximum supported nesting depth"):
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


def test_default_fixture_hmac_key_rejects_before_traversing_untrusted_fixture_root(
    tmp_path: Path,
) -> None:
    compiled = compile_suite(SUITE).model_copy(update={"suite_id": "private-suite"})

    with pytest.raises(ValueError, match="default fixture HMAC key"):
        run_suite(compiled, load_variant_config(BASELINE), tmp_path / "missing")


def test_default_fixture_hmac_key_rejects_modified_suite_with_bundled_ids() -> None:
    compiled = compile_suite(SUITE)
    first_case = compiled.cases[0].model_copy(update={"title": "Private subject case"})
    modified = compiled.model_copy(update={"cases": (first_case, *compiled.cases[1:])})

    with pytest.raises(ValueError, match="exact bundled synthetic"):
        run_suite(modified, load_variant_config(BASELINE), SUITE.parent)


def test_default_fixture_hmac_key_rejects_modified_fixture_with_bundled_ids(
    tmp_path: Path,
) -> None:
    suite_root = tmp_path / "prior_auth_synthetic"
    shutil.copytree(SUITE.parent, suite_root)
    fixture_path = suite_root / "fixtures" / "shared" / "requests" / "straightforward-approval.json"
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    fixture["member_id"] = "REAL-MEMBER-001"
    fixture_path.write_text(json.dumps(fixture), encoding="utf-8")

    with pytest.raises(ValueError, match="exact bundled synthetic"):
        run_suite(
            compile_suite(suite_root / "suite.yaml"),
            load_variant_config(suite_root / "variants" / "baseline.yaml"),
            suite_root,
        )


def test_default_fixture_hmac_key_allows_exact_copy_of_bundled_example(
    tmp_path: Path,
) -> None:
    suite_root = tmp_path / "prior_auth_synthetic"
    shutil.copytree(SUITE.parent, suite_root)

    runset = run_suite(
        compile_suite(suite_root / "suite.yaml"),
        load_variant_config(suite_root / "variants" / "baseline.yaml"),
        suite_root,
    )

    assert runset.suite_id == "prior-auth-synthetic"


def test_fixture_read_rejects_mutation_after_manifest_approval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    suite_root = tmp_path / "prior_auth_synthetic"
    shutil.copytree(SUITE.parent, suite_root)
    fixture_path = suite_root / "fixtures" / "shared" / "requests" / "straightforward-approval.json"
    original_validate = fixture_runner_module._validate_fixture_hmac_manifest

    def approve_then_mutate(identity, fixture_manifest) -> None:  # type: ignore[no-untyped-def]
        original_validate(identity, fixture_manifest)
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        fixture["member_id"] = "MUTATED-AFTER-APPROVAL"
        fixture_path.write_text(json.dumps(fixture), encoding="utf-8")

    monkeypatch.setattr(
        fixture_runner_module,
        "_validate_fixture_hmac_manifest",
        approve_then_mutate,
    )

    runset = run_suite(
        compile_suite(suite_root / "suite.yaml"),
        load_variant_config(suite_root / "variants" / "baseline.yaml"),
        suite_root,
    )

    assert runset.runs[0].case_id == "00123"
    assert runset.runs[0].outcome == "runtime_error"
    assert runset.runs[0].policy_results[0].reason_codes == (ReasonCode.RUNTIME_FAILED,)


def test_rag_ancillary_fixture_rejects_mutation_after_manifest_approval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    suite_root = tmp_path / "prior_auth_synthetic"
    shutil.copytree(RAG_SUITE.parent, suite_root)
    corpus_manifest = suite_root / "fixtures" / "rag" / "corpus_manifest.json"
    original_validate = fixture_runner_module._validate_fixture_hmac_manifest

    def approve_then_mutate(identity, fixture_manifest) -> None:  # type: ignore[no-untyped-def]
        original_validate(identity, fixture_manifest)
        corpus_manifest.write_bytes(corpus_manifest.read_bytes() + b"\n")

    monkeypatch.setattr(
        fixture_runner_module,
        "_validate_fixture_hmac_manifest",
        approve_then_mutate,
    )

    runset = run_suite(
        compile_suite(suite_root / RAG_SUITE.name),
        load_variant_config(suite_root / "variants" / RAG_BASELINE.name),
        suite_root,
    )

    assert len(runset.runs) == 1
    assert runset.runs[0].outcome == "runtime_error"
    assert runset.runs[0].policy_results[0].reason_codes == (ReasonCode.RUNTIME_FAILED,)


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


def test_explicit_fixture_hmac_key_is_validated_at_runner_boundary() -> None:
    with pytest.raises(ValueError, match="at least 32 bytes"):
        run_suite(
            compile_suite(SUITE),
            load_variant_config(BASELINE),
            SUITE.parent,
            hmac_key=b"too-short",
        )


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
