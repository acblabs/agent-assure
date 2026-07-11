from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import yaml
from pydantic import Field
from pydantic.functional_validators import field_validator

from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.fixtures.loader import compiled_suite_digest, verify_source_digest
from agent_assure.fixtures.manifest import (
    build_fixture_manifest,
    fixture_manifest_digest,
    resolve_case_fixture_paths,
    validate_fixture_layout,
    verify_fixture_manifest,
)
from agent_assure.fixtures.resolver import FixtureResolver
from agent_assure.privacy.redaction import redact_runset_payload
from agent_assure.privacy.safe_errors import safe_error
from agent_assure.runner.clock import DeterministicClock
from agent_assure.runner.ids import DeterministicIds
from agent_assure.runner.registry import get_runner
from agent_assure.schema.base import StrictModel
from agent_assure.schema.common import ExecutionMode, GateState, ReasonCode, Severity
from agent_assure.schema.provenance import Provenance
from agent_assure.schema.run import AgentRunRecord, PolicyResult, RunSet
from agent_assure.schema.suite import CompiledSuite, FixtureManifest, SuiteCase

FIXTURE_HMAC_KEY = b"agent-assure-fixture-mode-example-key"
DEFAULT_HMAC_KEY_ALLOWED_SYNTHETIC_RUNNERS = frozenset(
    {
        ("expense-approval-minimal", "expense_approval.minimal"),
        ("prior-auth-synthetic", "prior_auth.synthetic"),
        ("prior-auth-synthetic", "prior_auth.synthetic_evidence_refactor"),
        ("prior-auth-synthetic-rag", "prior_auth.synthetic_rag"),
        ("process-measurement-cases", "process_measurement.synthetic"),
    }
)


class VariantBehaviorConfig(StrictModel):
    evidence_assembly: Literal[
        "association_preserving",
        "source_digest_normalized",
    ] = "association_preserving"
    provider_policy_precedence: Literal["policy_over_runtime", "runtime_over_policy"] = (
        "policy_over_runtime"
    )
    runtime_error_case: str | None = None


class ProviderPolicyConfig(StrictModel):
    forbidden_providers: tuple[str, ...] = ()
    runtime_allowed_providers: tuple[str, ...] = ()

    @field_validator("forbidden_providers", "runtime_allowed_providers", mode="before")
    @classmethod
    def _coerce_provider_sequences(cls, value: object) -> object:
        if isinstance(value, list):
            return tuple(value)
        return value


class VariantConfig(StrictModel):
    variant_id: str
    pipeline_id: str
    runner_id: str | None
    behavior: VariantBehaviorConfig = Field(default_factory=VariantBehaviorConfig)
    provider_policy: ProviderPolicyConfig = Field(default_factory=ProviderPolicyConfig)

    @property
    def configuration_digest(self) -> str:
        return sha256_hexdigest(self.model_dump(mode="json"))


@dataclass(frozen=True)
class LoadedFixtures:
    fixture_id: str
    request: dict[str, object]
    model_output: dict[str, object]
    tool_output: dict[str, object]


@dataclass(frozen=True)
class RunnerContext:
    suite: CompiledSuite
    suite_root: Path
    variant: VariantConfig
    clock: DeterministicClock
    ids: DeterministicIds
    resolver: FixtureResolver
    hmac_key: bytes
    fixture_manifest: FixtureManifest
    fixture_manifest_digest: str


def load_variant_config(path: Path) -> VariantConfig:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise TypeError("variant must be a mapping")
    data = {str(key): value for key, value in loaded.items()}
    data.setdefault("pipeline_id", data.get("variant_id"))
    data.setdefault("runner_id", None)
    return VariantConfig.model_validate(data)


def run_suite(
    compiled: CompiledSuite,
    variant: VariantConfig,
    suite_root: Path,
    *,
    mode: ExecutionMode = ExecutionMode.fixture,
    expected_manifest: FixtureManifest | None = None,
    source_yaml: Path | None = None,
    hmac_key: bytes = FIXTURE_HMAC_KEY,
) -> RunSet:
    if mode is not ExecutionMode.fixture:
        raise ValueError("fixture runner only supports fixture execution mode")
    _validate_fixture_hmac_key(compiled, variant, hmac_key)
    if source_yaml is not None:
        verify_source_digest(compiled, source_yaml)
    resolver = FixtureResolver(suite_root)
    validate_fixture_layout(compiled, resolver)
    fixture_manifest = build_fixture_manifest(compiled, suite_root)
    if expected_manifest is not None:
        verify_fixture_manifest(expected_manifest, compiled, suite_root)
    manifest_digest = fixture_manifest_digest(fixture_manifest)
    ids = DeterministicIds()
    context = RunnerContext(
        suite=compiled,
        suite_root=suite_root,
        variant=variant,
        clock=DeterministicClock(),
        ids=ids,
        resolver=resolver,
        hmac_key=hmac_key,
        fixture_manifest=fixture_manifest,
        fixture_manifest_digest=manifest_digest,
    )
    runner = get_runner(variant.runner_id or compiled.defaults.runner_id)
    runs: list[AgentRunRecord] = []
    for index, case in enumerate(compiled.cases):
        try:
            fixtures = load_case_fixtures(case, context)
            record = runner(case, fixtures, variant, context)
        except Exception as exc:
            record = _error_record(case, context, exc, index)
        runs.append(record)
    return RunSet(
        runset_id=ids.runset_id(compiled.suite_id, variant.variant_id),
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=compiled_suite_digest(compiled),
        fixture_manifest_digest=manifest_digest,
        execution_mode=ExecutionMode.fixture,
        runs=tuple(runs),
    )


def _validate_fixture_hmac_key(
    compiled: CompiledSuite,
    variant: VariantConfig,
    hmac_key: bytes,
) -> None:
    if hmac_key != FIXTURE_HMAC_KEY:
        return
    runner_id = variant.runner_id or compiled.defaults.runner_id
    if (compiled.suite_id, runner_id) in DEFAULT_HMAC_KEY_ALLOWED_SYNTHETIC_RUNNERS:
        return
    raise ValueError(
        "the default fixture HMAC key is only allowed for bundled synthetic examples; "
        "pass an explicit hmac_key for non-synthetic fixture data"
    )


def load_case_fixtures(case: SuiteCase, context: RunnerContext) -> LoadedFixtures:
    fixture_id = case.fixture_id or case.case_id
    paths = resolve_case_fixture_paths(context.suite, context.resolver, fixture_id)
    return LoadedFixtures(
        fixture_id=fixture_id,
        request=_read_fixture_json(paths["requests"]),
        model_output=_read_fixture_json(paths["model_outputs"]),
        tool_output=_read_fixture_json(paths["tool_outputs"]),
    )


def write_runset(runset: RunSet, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = redact_runset_payload(runset.model_dump(mode="json"))
    RunSet.model_validate(payload)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _error_record(
    case: SuiteCase,
    context: RunnerContext,
    exc: Exception,
    index: int,
) -> AgentRunRecord:
    safe = safe_error("runner_execution_error", str(exc), exc)
    run_id = context.ids.run_id(context.suite.suite_id, context.variant.variant_id, case.case_id)
    return AgentRunRecord(
        artifact_kind="agent-run-record",
        run_id=run_id,
        case_id=case.case_id,
        execution_mode=ExecutionMode.fixture,
        pipeline_id=context.variant.pipeline_id,
        recommendation="error",
        outcome="runtime_error",
        input_summary=f"case={case.case_id}; variant={context.variant.variant_id}",
        output_summary=(
            f"runtime failure captured; code={safe.code}; "
            f"debug_ref={safe.local_debug_reference}; index={index}"
        ),
        policy_results=(
            PolicyResult(
                artifact_kind="policy-result",
                policy_id="runtime.fixture",
                state=GateState.fail,
                reason_codes=(ReasonCode.RUNTIME_FAILED,),
                severity=Severity.blocker,
                message="fixture runner captured an in-process runtime failure",
            ),
        ),
        provenance=_provenance(context),
    )


def _provenance(context: RunnerContext) -> Provenance:
    return Provenance(
        artifact_kind="provenance",
        configuration_digest=context.variant.configuration_digest,
        fixture_manifest_digest=context.fixture_manifest_digest,
    )


def _read_fixture_json(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"fixture JSON root must be an object: {path}")
    return {str(key): value for key, value in payload.items()}
