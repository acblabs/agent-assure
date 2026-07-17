from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic.functional_validators import field_validator

from agent_assure.authoring.yaml_nodes import safe_load_yaml_text
from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.canonical.hmac_tokens import MIN_HMAC_KEY_BYTES
from agent_assure.fixtures.loader import compiled_suite_digest, verify_source_digest
from agent_assure.fixtures.manifest import (
    build_fixture_manifest,
    fixture_manifest_digest,
    resolve_case_fixture_paths,
    validate_fixture_layout,
    verify_fixture_manifest,
)
from agent_assure.fixtures.resolver import FixtureResolver
from agent_assure.io_limits import (
    MAX_ARTIFACT_JSON_BYTES,
    MAX_CONFIG_TEXT_BYTES,
    loads_json_bounded,
    read_bytes_bounded,
    read_text_bounded,
)
from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.privacy.redaction import (
    assert_runset_payload_safe_for_persistence,
    redact_runset_payload,
)
from agent_assure.privacy.safe_errors import safe_error
from agent_assure.runner.clock import DeterministicClock
from agent_assure.runner.ids import DeterministicIds
from agent_assure.runner.registry import get_runner
from agent_assure.schema.base import StrictModel
from agent_assure.schema.common import ExecutionMode, GateState, ReasonCode, Severity
from agent_assure.schema.provenance import Provenance
from agent_assure.schema.run import AgentRunRecord, PolicyResult, RunSet
from agent_assure.schema.suite import (
    CompiledSuite,
    FixtureManifest,
    FixtureManifestEntry,
    SuiteCase,
)

# This is intentionally public demo material. run_suite permits it only when the
# suite and every fixture byte match a bundled synthetic example identity.
FIXTURE_HMAC_KEY = b"agent-assure-fixture-mode-example-key"


@dataclass(frozen=True)
class _BundledSyntheticSuiteIdentity:
    compiled_suite_digest: str
    fixture_manifest_digest: str
    allowed_runner_ids: frozenset[str]


_BUNDLED_SYNTHETIC_SUITE_IDENTITIES = {
    # These digests are deliberately pinned constants, not values derived from
    # mutable package resources at runtime. Updating a bundled example requires
    # an explicit review and update of its identity here.
    "expense-approval-minimal": _BundledSyntheticSuiteIdentity(
        compiled_suite_digest="6f3c7ffb120407335e309c08f7e4ab90f790e7ddabd0a33eff66a0cca854486c",
        fixture_manifest_digest="4ef579a221182d1bb0c0381499f52055b143a3835a7ce9648343dbf5ddf9e56b",
        allowed_runner_ids=frozenset({"expense_approval.minimal"}),
    ),
    "prior-auth-synthetic": _BundledSyntheticSuiteIdentity(
        compiled_suite_digest="32bb447bb8a9551d624e8afeca640d585277bb53f80f39d2a8b4d78738d43c6d",
        fixture_manifest_digest="6bab362f96eba3b0189f08a3ec78e71f1a9aef02797d54332baf6b418e7f1e36",
        allowed_runner_ids=frozenset(
            {"prior_auth.synthetic", "prior_auth.synthetic_evidence_refactor"}
        ),
    ),
    "prior-auth-synthetic-rag": _BundledSyntheticSuiteIdentity(
        compiled_suite_digest="5f8b811233e15e1966201e6af0f510ab21f37c6d50f0271d5ad638e58debde94",
        fixture_manifest_digest="a547c2acef76674f6128f44d0d06cbf2ad622790e27de0d8ad803f04b1961b88",
        allowed_runner_ids=frozenset({"prior_auth.synthetic_rag"}),
    ),
    "process-measurement-cases": _BundledSyntheticSuiteIdentity(
        compiled_suite_digest="2f251b3c74605850705862b6a688abb7d033119c39d37e9932df520115e3b9a1",
        fixture_manifest_digest="3c01aa9feb7095d79988ba7b3dd1f5774c84d74870d467fe5a206dac3f49e129",
        allowed_runner_ids=frozenset({"process_measurement.synthetic"}),
    ),
}


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
    fixture_entries_by_path: dict[str, FixtureManifestEntry] = field(
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "fixture_entries_by_path",
            {entry.path: entry for entry in self.fixture_manifest.entries},
        )

    def read_fixture_bytes(self, path: Path) -> bytes:
        manifest_path = self.resolver.manifest_path(path)
        expected = self.fixture_entries_by_path.get(manifest_path)
        if expected is None:
            raise ValueError(f"fixture is absent from approved manifest: {manifest_path}")
        data = read_bytes_bounded(
            path,
            max_bytes=MAX_ARTIFACT_JSON_BYTES,
            label=f"fixture {manifest_path}",
        )
        if len(data) != expected.size_bytes or hashlib.sha256(data).hexdigest() != expected.sha256:
            raise ValueError(f"fixture changed after manifest approval: {manifest_path}")
        return data

    def read_fixture_json(self, path: Path) -> dict[str, object]:
        manifest_path = self.resolver.manifest_path(path)
        payload = loads_json_bounded(
            self.read_fixture_bytes(path).decode("utf-8"),
            label=f"fixture JSON {manifest_path}",
        )
        if not isinstance(payload, dict):
            raise ValueError(f"fixture JSON {manifest_path} root must be an object")
        return {str(key): value for key, value in payload.items()}


def load_variant_config(path: Path) -> VariantConfig:
    text = read_text_bounded(path, max_bytes=MAX_CONFIG_TEXT_BYTES, label="variant YAML")
    loaded = safe_load_yaml_text(text, label="variant YAML")
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
    _validate_fixture_hmac_key_material(hmac_key)
    if source_yaml is not None:
        verify_source_digest(compiled, source_yaml)
    default_key_identity = _validate_fixture_hmac_suite_identity(compiled, variant, hmac_key)
    resolver = FixtureResolver(suite_root)
    validate_fixture_layout(compiled, resolver)
    fixture_manifest = build_fixture_manifest(compiled, suite_root)
    _validate_fixture_hmac_manifest(default_key_identity, fixture_manifest)
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
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=compiled_suite_digest(compiled),
        fixture_manifest_digest=manifest_digest,
        execution_mode=ExecutionMode.fixture,
        runs=tuple(runs),
    )


def _validate_fixture_hmac_suite_identity(
    compiled: CompiledSuite,
    variant: VariantConfig,
    hmac_key: bytes,
) -> _BundledSyntheticSuiteIdentity | None:
    if hmac_key != FIXTURE_HMAC_KEY:
        return None
    runner_id = variant.runner_id or compiled.defaults.runner_id
    identity = _bundled_synthetic_suite_identity(compiled.suite_id)
    if (
        identity is not None
        and runner_id in identity.allowed_runner_ids
        and compiled_suite_digest(compiled) == identity.compiled_suite_digest
    ):
        return identity
    raise ValueError(
        "the default fixture HMAC key is only allowed for exact bundled synthetic "
        "suite and fixture artifacts; "
        "pass an explicit hmac_key for non-synthetic fixture data"
    )


def _validate_fixture_hmac_manifest(
    identity: _BundledSyntheticSuiteIdentity | None,
    fixture_manifest: FixtureManifest,
) -> None:
    if identity is None:
        return
    if fixture_manifest_digest(fixture_manifest) == identity.fixture_manifest_digest:
        return
    raise ValueError(
        "the default fixture HMAC key is only allowed for exact bundled synthetic "
        "suite and fixture artifacts; "
        "pass an explicit hmac_key for non-synthetic fixture data"
    )


def _validate_fixture_hmac_key_material(hmac_key: bytes) -> None:
    if not isinstance(hmac_key, bytes):
        raise TypeError("fixture HMAC key must be bytes")
    if len(hmac_key) < MIN_HMAC_KEY_BYTES:
        raise ValueError(f"fixture HMAC key must be at least {MIN_HMAC_KEY_BYTES} bytes")


def _bundled_synthetic_suite_identity(
    suite_id: str,
) -> _BundledSyntheticSuiteIdentity | None:
    return _BUNDLED_SYNTHETIC_SUITE_IDENTITIES.get(suite_id)


def load_case_fixtures(case: SuiteCase, context: RunnerContext) -> LoadedFixtures:
    fixture_id = case.fixture_id or case.case_id
    paths = resolve_case_fixture_paths(context.suite, context.resolver, fixture_id)
    return LoadedFixtures(
        fixture_id=fixture_id,
        request=_read_fixture_json(paths["requests"], context),
        model_output=_read_fixture_json(paths["model_outputs"], context),
        tool_output=_read_fixture_json(paths["tool_outputs"], context),
    )


def write_runset(runset: RunSet, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = redact_runset_payload(runset.model_dump(mode="json"))
    assert_runset_payload_safe_for_persistence(payload)
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


def _read_fixture_json(path: Path, context: RunnerContext) -> dict[str, object]:
    return context.read_fixture_json(path)
