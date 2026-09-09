from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from enum import StrEnum
from typing import Annotated, Literal, Self

import rfc8785
from pydantic import ConfigDict, Field, field_validator, model_validator

from agent_assure.privacy.credential_uri import (
    PERSISTED_CREDENTIAL_NAMES,
    PERSISTED_CREDENTIAL_SUFFIXES,
    SENSITIVE_HEADER_NAMES,
    contains_persisted_credential,
    matches_credential_name,
)
from agent_assure.privacy.redaction import redact_packet_payload
from agent_assure.rooted_io import portable_relative_path_parts
from agent_assure.schema.base import FrozenStrictModel
from agent_assure.schema.common import (
    PACKAGE_RELEASE_VERSION_PATTERN,
    STRICT_RFC3339_TIMESTAMP_PATTERN,
    DigestHex,
    MachineIdentifier,
    coerce_enum,
    coerce_tuple,
)
from agent_assure.schema.mutation import (
    SelfDigestedArtifact,
    _require_contract_identity_json_schema,
)
from agent_assure.timestamps import parse_rfc3339_timestamp

MAX_PILOT_ARTIFACTS = 256
MAX_PILOT_COMMANDS = 64
MAX_PILOT_COMMAND_ARGUMENTS = 128
MAX_PILOT_ENVIRONMENT_COMPONENTS = 64
MAX_PILOT_FINDINGS = 128
MAX_PILOT_REMEDIATIONS = 128

GitRevision = Annotated[str, Field(pattern=r"^[a-f0-9]{40}$")]
WorkflowInputValue = Annotated[
    str,
    Field(min_length=1, max_length=2_048, pattern=r"^[^\x00\r\n]+$"),
]
_GITHUB_ACTIONS_RUN_URL = re.compile(
    r"^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/actions/runs/"
    r"([1-9][0-9]*)/attempts/([1-9][0-9]*)$"
)
_PILOT_WORKFLOW_PATHS = {
    "capture": ".github/workflows/external-pilot-capture.yml",
    "finalize": ".github/workflows/external-pilot-finalize.yml",
}
_PILOT_WORKFLOW_INPUTS = {
    "capture": frozenset(
        {
            "attest_independent_non_maintainer",
            "consent_to_temporary_actions_storage",
            "participant_pseudonym",
        }
    ),
    "finalize": frozenset(
        {
            "capture_run_attempt",
            "capture_run_id",
            "friction_assessment",
            "friction_category",
            "grant_privacy_filtered_publication",
            "prior_candidate_evidence_digest",
            "reattest_independent_non_maintainer",
            "remediation_disposition",
            "remediation_source_revision",
        }
    ),
}

PilotText = Annotated[str, Field(min_length=1, max_length=2_048)]
PilotVersion = Annotated[str, Field(min_length=1, max_length=128)]
CommandArgument = Annotated[
    str,
    Field(min_length=1, max_length=2_048, pattern=r"^[^\x00\r\n]+$"),
]
_HEADER_OPTIONS = frozenset({"header", "proxy-header"})
_CONTROLS_VALUE_OPTIONS = frozenset(
    {
        "catalog",
        "invariant-family",
        "operator",
        "out",
        "runset",
        "seed",
        "suite",
        "threat-id",
        "today",
        "waiver",
    }
)
_CONTROLS_FLAG_OPTIONS = frozenset(
    {
        "fail-fast",
        "fail-on-not-evaluated",
        "fail-on-warn",
        "full-report",
    }
)
_CONTROLS_REPEATABLE_OPTIONS = frozenset({"invariant-family", "operator", "threat-id", "waiver"})
_RAG_VALUE_OPTIONS = frozenset(
    {
        "baseline-corpus",
        "counterfactual-corpus",
        "expected-relation",
        "knowledge-contract",
        "out",
        "suite",
        "synthetic-data-attestation",
    }
)
_RAG_REQUIRED_OPTIONS = frozenset(
    {
        "baseline-corpus",
        "counterfactual-corpus",
        "expected-relation",
        "knowledge-contract",
        "out",
        "suite",
    }
)


def _normalized_option(value: str) -> tuple[str | None, str | None]:
    """Parse an exact lowercase, hyphenated long option accepted by Typer."""

    if not value.startswith("--") or value == "--":
        return None, None
    option, separator, inline_value = value[2:].partition("=")
    if not option or option != option.casefold() or "_" in option:
        return None, None
    return option, inline_value if separator else None


def _normalized_credential_option(value: str) -> tuple[str | None, str | None]:
    """Normalize adversarial option spellings for privacy scanning only."""

    if not value.startswith("--") or value == "--":
        return None, None
    option, separator, inline_value = value[2:].partition("=")
    if not option:
        return None, None
    return option.casefold().replace("_", "-"), inline_value if separator else None


def _is_credential_value_option(value: str) -> bool:
    option, _, _ = value.partition("=")
    if option in {"-u", "-U"} or (
        option.startswith(("-u", "-U")) and not option.startswith("--") and ":" in option[2:]
    ):
        return True
    normalized, _ = _normalized_credential_option(option)
    return normalized is not None and _is_credential_name(normalized)


def _is_credential_name(value: str) -> bool:
    return matches_credential_name(
        value,
        exact_names=PERSISTED_CREDENTIAL_NAMES,
        suffixes=PERSISTED_CREDENTIAL_SUFFIXES,
    )


def _looks_like_sensitive_header(value: str) -> bool:
    header_name, separator, _ = value.partition(":")
    normalized_name = header_name.strip().casefold().replace("_", "-")
    return bool(separator) and (
        normalized_name in SENSITIVE_HEADER_NAMES or _is_credential_name(normalized_name)
    )


def _contains_persisted_credential(value: str) -> bool:
    return contains_persisted_credential(
        value,
        exact_names=PERSISTED_CREDENTIAL_NAMES,
        suffixes=PERSISTED_CREDENTIAL_SUFFIXES,
        sensitive_header_names=SENSITIVE_HEADER_NAMES,
    )


def _argv_contains_credential_material(argv: tuple[str, ...]) -> bool:
    for index, argument in enumerate(argv):
        if _is_credential_value_option(argument):
            return True
        normalized, inline_value = _normalized_credential_option(argument)
        if normalized in _HEADER_OPTIONS:
            header_value = inline_value
            if header_value is None and index + 1 < len(argv):
                header_value = argv[index + 1]
            if header_value is None or _looks_like_sensitive_header(header_value):
                return True
        if argument.startswith("-H") and argument != "-H":
            if _looks_like_sensitive_header(argument[2:]):
                return True
        if argument == "-H":
            if index + 1 >= len(argv) or _looks_like_sensitive_header(argv[index + 1]):
                return True
        candidates = [argument]
        if inline_value is not None:
            candidates.append(inline_value)
        elif normalized is None:
            _, separator, assigned_value = argument.partition("=")
            if separator and assigned_value:
                candidates.append(assigned_value)
        for candidate in candidates:
            if _looks_like_sensitive_header(candidate) or _contains_persisted_credential(candidate):
                return True
    return False


def _durable_value_contains_credential_material(value: object) -> bool:
    """Scan every persisted scalar without pairing safe metadata keys and values."""

    pending = [value]
    while pending:
        candidate = pending.pop()
        if isinstance(candidate, str):
            if _contains_persisted_credential(candidate):
                return True
        elif isinstance(candidate, Mapping):
            pending.extend(candidate.keys())
            pending.extend(candidate.values())
        elif isinstance(candidate, Sequence) and not isinstance(
            candidate,
            bytes | bytearray,
        ):
            pending.extend(candidate)
    return False


def _parse_long_options(
    arguments: tuple[str, ...],
    *,
    value_options: frozenset[str],
    flag_options: frozenset[str],
    repeatable_options: frozenset[str] = frozenset(),
) -> dict[str, tuple[str, ...]] | None:
    """Parse a closed, execution-bearing subset of a Typer command line."""

    parsed: dict[str, list[str]] = {}
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument in {"-h", "--help", "--version"}:
            return None
        option, inline_value = _normalized_option(argument)
        if option is None:
            return None
        if option in flag_options:
            if inline_value is not None or option in parsed:
                return None
            parsed[option] = []
            index += 1
            continue
        if option not in value_options:
            return None
        if option in parsed and option not in repeatable_options:
            return None
        if inline_value is None:
            index += 1
            if index >= len(arguments) or arguments[index].startswith("-"):
                return None
            option_value = arguments[index]
        else:
            if not inline_value:
                return None
            option_value = inline_value
        parsed.setdefault(option, []).append(option_value)
        index += 1
    return {option: tuple(values) for option, values in parsed.items()}


def _workflow_output_contract(
    argv: tuple[str, ...],
    workflow_id: Literal["controls-mutate", "rag-sensitivity"],
) -> str | None:
    """Return the exact output contract for a supported executable invocation."""

    if not argv:
        return None
    launcher = argv[0].replace(chr(92), "/").rsplit("/", 1)[-1].casefold()
    if launcher in {"agent-assure", "agent-assure.exe"}:
        command_start = 1
    elif (
        launcher in {"python", "python.exe", "python3", "python3.exe", "py", "py.exe"}
        and len(argv) >= 3
        and argv[1] == "-m"
        and argv[2] == "agent_assure.cli.main"
    ):
        command_start = 3
    else:
        return None
    expected = {
        "controls-mutate": ("controls", "mutate"),
        "rag-sensitivity": ("rag", "sensitivity"),
    }[workflow_id]
    if argv[command_start : command_start + len(expected)] != expected:
        return None
    remaining = argv[command_start + len(expected) :]
    if workflow_id == "rag-sensitivity":
        parsed = _parse_long_options(
            remaining,
            value_options=_RAG_VALUE_OPTIONS,
            flag_options=frozenset(),
        )
        if parsed is None or not _RAG_REQUIRED_OPTIONS.issubset(parsed):
            return None
        if parsed["expected-relation"] != ("decision_flip",):
            return None
        return "RAGSensitivityReport/v1"

    parsed = _parse_long_options(
        remaining,
        value_options=_CONTROLS_VALUE_OPTIONS,
        flag_options=_CONTROLS_FLAG_OPTIONS,
        repeatable_options=_CONTROLS_REPEATABLE_OPTIONS,
    )
    if parsed is None or not {"suite", "runset", "out"}.issubset(parsed):
        return None
    catalog = parsed.get("catalog")
    operators = parsed.get("operator", ())
    if catalog is None:
        if len(operators) != 1:
            return None
        if {"invariant-family", "threat-id", "full-report", "fail-fast"} & parsed.keys():
            return None
        output_contract = "AssuranceMutationResult/v1"
    elif catalog != ("core/v1",):
        return None
    else:
        if {"full-report", "fail-fast"}.issubset(parsed):
            return None
        output_contract = "AssuranceMutationCampaign/v1"
    if "seed" in parsed:
        try:
            seed = int(parsed["seed"][0])
        except ValueError:
            return None
        if not 0 <= seed <= 9_007_199_254_740_991:
            return None
    return output_contract


def _invokes_agent_assure_workflow(
    argv: tuple[str, ...],
    workflow_id: Literal["controls-mutate", "rag-sensitivity"],
) -> bool:
    """Return whether argv directly executes the declared signature workflow."""

    return _workflow_output_contract(argv, workflow_id) is not None


class PilotClassification(StrEnum):
    external = "external"
    internal_dogfood = "internal_dogfood"
    synthetic = "synthetic"


class PilotAttemptStatus(StrEnum):
    attempted = "attempted"
    completed = "completed"
    not_attempted = "not_attempted"


class PilotExecutionContext(StrEnum):
    continuous_integration = "continuous_integration"
    local = "local"


class PilotEnvironmentControl(StrEnum):
    independently_controlled_non_maintainer = "independently_controlled_non_maintainer"
    maintainer_controlled = "maintainer_controlled"
    synthetic_harness = "synthetic_harness"
    unverified = "unverified"


class PilotInputOrigin(StrEnum):
    non_bundled = "non_bundled"
    bundled = "bundled"
    mixed_bundled_non_bundled = "mixed_bundled_non_bundled"
    synthetic = "synthetic"
    absent = "absent"


class PilotInputKind(StrEnum):
    configuration = "configuration"
    data = "data"


class PilotInputIdentityKind(StrEnum):
    compiled_suite = "compiled_suite"
    run_set = "run_set"
    waiver_set = "waiver_set"
    knowledge_contract = "knowledge_contract"
    rag_corpus = "rag_corpus"
    synthetic_data_attestation = "synthetic_data_attestation"


_WORKFLOW_INPUT_OPTION_KINDS: dict[
    Literal["controls-mutate", "rag-sensitivity"],
    dict[str, PilotInputKind],
] = {
    "controls-mutate": {
        "suite": PilotInputKind.configuration,
        "waiver": PilotInputKind.configuration,
        "runset": PilotInputKind.data,
    },
    "rag-sensitivity": {
        "suite": PilotInputKind.configuration,
        "knowledge-contract": PilotInputKind.configuration,
        "baseline-corpus": PilotInputKind.data,
        "counterfactual-corpus": PilotInputKind.data,
        "synthetic-data-attestation": PilotInputKind.data,
    },
}

_WORKFLOW_INPUT_OPTION_IDENTITIES: dict[
    Literal["controls-mutate", "rag-sensitivity"],
    dict[str, PilotInputIdentityKind],
] = {
    "controls-mutate": {
        "suite": PilotInputIdentityKind.compiled_suite,
        "waiver": PilotInputIdentityKind.waiver_set,
        "runset": PilotInputIdentityKind.run_set,
    },
    "rag-sensitivity": {
        "suite": PilotInputIdentityKind.compiled_suite,
        "knowledge-contract": PilotInputIdentityKind.knowledge_contract,
        "baseline-corpus": PilotInputIdentityKind.rag_corpus,
        "counterfactual-corpus": PilotInputIdentityKind.rag_corpus,
        "synthetic-data-attestation": PilotInputIdentityKind.synthetic_data_attestation,
    },
}


def pilot_workflow_input_arguments(
    argv: tuple[str, ...],
    workflow_id: Literal["controls-mutate", "rag-sensitivity"],
) -> tuple[tuple[PilotInputKind, str, str], ...] | None:
    """Return the exact input-bearing option values for a valid workflow argv."""

    if _workflow_output_contract(argv, workflow_id) is None:
        return None
    launcher = argv[0].replace(chr(92), "/").rsplit("/", 1)[-1].casefold()
    command_start = 1 if launcher in {"agent-assure", "agent-assure.exe"} else 3
    command_words = 2
    remaining = argv[command_start + command_words :]
    if workflow_id == "rag-sensitivity":
        parsed = _parse_long_options(
            remaining,
            value_options=_RAG_VALUE_OPTIONS,
            flag_options=frozenset(),
        )
    else:
        parsed = _parse_long_options(
            remaining,
            value_options=_CONTROLS_VALUE_OPTIONS,
            flag_options=_CONTROLS_FLAG_OPTIONS,
            repeatable_options=_CONTROLS_REPEATABLE_OPTIONS,
        )
    if parsed is None:  # pragma: no cover - output-contract validation guards this
        return None
    option_kinds = _WORKFLOW_INPUT_OPTION_KINDS[workflow_id]
    return tuple(
        (option_kinds[option], option, option_value)
        for option, option_values in parsed.items()
        if option in option_kinds
        for option_value in option_values
    )


class PilotArtifactRole(StrEnum):
    tested_distribution = "tested_distribution"
    environment_manifest = "environment_manifest"
    environment_control_evidence = "environment_control_evidence"
    input_manifest = "input_manifest"
    execution_evidence = "execution_evidence"
    assurance_output = "assurance_output"
    friction_assessment = "friction_assessment"
    remediation_record = "remediation_record"
    consent_record = "consent_record"


class PilotArtifactContentScope(StrEnum):
    distribution_binary = "distribution_binary"
    metadata_only = "metadata_only"
    privacy_filtered = "privacy_filtered"


class PilotConsentStatus(StrEnum):
    granted = "granted"
    withheld = "withheld"
    not_requested = "not_requested"


class PilotPublicationScope(StrEnum):
    private_record = "private_record"
    aggregate_summary = "aggregate_summary"
    privacy_filtered_record = "privacy_filtered_record"


class PilotFrictionAssessmentState(StrEnum):
    friction_observed = "friction_observed"
    no_friction_observed = "no_friction_observed"
    not_assessed = "not_assessed"


class PilotFrictionCategory(StrEnum):
    installation = "installation"
    configuration = "configuration"
    diagnostics = "diagnostics"
    continuous_integration = "continuous_integration"
    runtime = "runtime"
    documentation = "documentation"
    other = "other"


class PilotRemediationArea(StrEnum):
    onboarding = "onboarding"
    initialization = "initialization"
    diagnostics = "diagnostics"
    documentation = "documentation"
    integration = "integration"
    roadmap = "roadmap"
    other = "other"


class PilotRemediationDisposition(StrEnum):
    applied = "applied"
    planned = "planned"
    deferred = "deferred"
    no_change_required = "no_change_required"


class PilotWorkflowDispatchInput(FrozenStrictModel):
    """One public, non-secret workflow-dispatch input reviewed from a run record."""

    name: MachineIdentifier
    value: WorkflowInputValue


def calculate_pilot_workflow_inputs_digest(
    inputs: Sequence[PilotWorkflowDispatchInput],
) -> str:
    """Bind the complete canonical workflow-dispatch input mapping."""

    return hashlib.sha256(
        rfc8785.dumps(
            {
                "contract_id": "PilotWorkflowDispatchInputs/v1",
                "inputs": tuple(item.model_dump(mode="json") for item in inputs),
            }
        )
    ).hexdigest()


class PilotWorkflowRunReview(FrozenStrictModel):
    """Human-reviewed binding between one Actions run and trusted workflow bytes."""

    stage: Literal["capture", "finalize"]
    run_url: str = Field(min_length=1, max_length=512)
    run_attempt: int = Field(ge=1)
    run_head_sha: GitRevision
    trusted_workflow_revision: GitRevision
    execution_source_revision: GitRevision
    workflow_path: str = Field(min_length=1, max_length=255)
    run_head_workflow_sha256: DigestHex
    trusted_workflow_sha256: DigestHex
    workflow_bytes_match_trusted_revision: Literal[True]
    public_inputs: tuple[PilotWorkflowDispatchInput, ...] = Field(min_length=1, max_length=32)
    public_inputs_sha256: DigestHex

    @field_validator("public_inputs", mode="before")
    @classmethod
    def _coerce_public_inputs(cls, value: object) -> object:
        return coerce_tuple(value)

    @classmethod
    def build(cls, **values: object) -> Self:
        prepared = dict(values)
        raw_inputs = coerce_tuple(prepared.get("public_inputs"))
        if not isinstance(raw_inputs, tuple):
            raise TypeError("pilot workflow public inputs must be a sequence")
        inputs = tuple(PilotWorkflowDispatchInput.model_validate(item) for item in raw_inputs)
        prepared["public_inputs"] = inputs
        prepared["public_inputs_sha256"] = calculate_pilot_workflow_inputs_digest(inputs)
        return cls.model_validate(prepared)

    @model_validator(mode="after")
    def _validate_run_review(self) -> Self:
        match = _GITHUB_ACTIONS_RUN_URL.fullmatch(self.run_url)
        if match is None:
            raise ValueError(
                "pilot workflow run URL must name one attempt-specific public GitHub Actions run"
            )
        if int(match.group(4)) != self.run_attempt:
            raise ValueError("pilot workflow run attempt must match its attempt-specific URL")
        if self.workflow_path != _PILOT_WORKFLOW_PATHS[self.stage]:
            raise ValueError("pilot workflow path does not match its reviewed stage")
        if self.run_head_workflow_sha256 != self.trusted_workflow_sha256:
            raise ValueError("pilot run-head workflow bytes must match the trusted workflow bytes")
        if self.public_inputs != tuple(sorted(self.public_inputs, key=lambda item: item.name)):
            raise ValueError("pilot workflow public inputs must use canonical name ordering")
        names = tuple(item.name for item in self.public_inputs)
        if len(set(names)) != len(names):
            raise ValueError("pilot workflow public input names must be unique")
        if set(names) != _PILOT_WORKFLOW_INPUTS[self.stage]:
            raise ValueError("pilot workflow public inputs must exactly cover the reviewed stage")
        expected_digest = calculate_pilot_workflow_inputs_digest(self.public_inputs)
        if self.public_inputs_sha256 != expected_digest:
            raise ValueError("pilot workflow public input digest does not match its exact values")
        input_values = {item.name: item.value for item in self.public_inputs}
        required_true = (
            {"attest_independent_non_maintainer", "consent_to_temporary_actions_storage"}
            if self.stage == "capture"
            else {"grant_privacy_filtered_publication", "reattest_independent_non_maintainer"}
        )
        if any(input_values[name] != "true" for name in required_true):
            raise ValueError("reviewed pilot consent and control inputs must be true")
        return self

    @property
    def repository(self) -> str:
        match = _GITHUB_ACTIONS_RUN_URL.fullmatch(self.run_url)
        if match is None:  # pragma: no cover - model validation guards this
            raise RuntimeError("validated pilot workflow run URL became invalid")
        return f"{match.group(1)}/{match.group(2)}"

    @property
    def run_id(self) -> str:
        match = _GITHUB_ACTIONS_RUN_URL.fullmatch(self.run_url)
        if match is None:  # pragma: no cover - model validation guards this
            raise RuntimeError("validated pilot workflow run URL became invalid")
        return match.group(3)

    @property
    def input_values(self) -> dict[str, str]:
        return {item.name: item.value for item in self.public_inputs}


class PilotArtifactDigest(FrozenStrictModel):
    artifact_id: MachineIdentifier
    path: str = Field(min_length=1, max_length=255)
    role: PilotArtifactRole
    sha256: DigestHex
    content_scope: PilotArtifactContentScope
    schema_validated: bool
    schema_contract: MachineIdentifier | None
    producing_command_id: MachineIdentifier | None = None

    @field_validator("path")
    @classmethod
    def _validate_bundle_path(cls, value: str) -> str:
        parts = portable_relative_path_parts(value)
        if len(parts) != 1 or parts[0] != value:
            raise ValueError("pilot artifact path must be one canonical portable bundle-root child")
        return value

    @field_validator("role", mode="before")
    @classmethod
    def _coerce_role(cls, value: object) -> PilotArtifactRole:
        return coerce_enum(PilotArtifactRole, value)

    @field_validator("content_scope", mode="before")
    @classmethod
    def _coerce_content_scope(cls, value: object) -> PilotArtifactContentScope:
        return coerce_enum(PilotArtifactContentScope, value)

    @model_validator(mode="after")
    def _validate_schema_claim(self) -> Self:
        if self.role is PilotArtifactRole.tested_distribution:
            if self.content_scope is not PilotArtifactContentScope.distribution_binary:
                raise ValueError(
                    "pilot tested distribution artifacts require distribution_binary content scope"
                )
        elif self.content_scope is PilotArtifactContentScope.distribution_binary:
            raise ValueError(
                "distribution_binary content scope is valid only for tested distributions"
            )
        if self.schema_validated != (self.schema_contract is not None):
            raise ValueError(
                "pilot artifact schema validation and schema contract must be present together"
            )
        if self.role is PilotArtifactRole.input_manifest and (
            not self.schema_validated or self.schema_contract != "PilotInputManifest/v1"
        ):
            raise ValueError(
                "pilot input manifest artifacts require PilotInputManifest/v1 validation"
            )
        if (self.role is PilotArtifactRole.assurance_output) != (
            self.producing_command_id is not None
        ):
            raise ValueError("only assurance outputs must bind exactly one producing pilot command")
        return self


class PilotInputManifestEntry(FrozenStrictModel):
    entry_id: MachineIdentifier
    input_kind: PilotInputKind
    origin: PilotInputOrigin
    option_name: MachineIdentifier
    option_value: CommandArgument
    content_sha256: DigestHex
    semantic_identity_kind: PilotInputIdentityKind
    semantic_identity_digest: DigestHex

    @field_validator("input_kind", mode="before")
    @classmethod
    def _coerce_input_kind(cls, value: object) -> PilotInputKind:
        return coerce_enum(PilotInputKind, value)

    @field_validator("semantic_identity_kind", mode="before")
    @classmethod
    def _coerce_identity_kind(cls, value: object) -> PilotInputIdentityKind:
        return coerce_enum(PilotInputIdentityKind, value)

    @field_validator("origin", mode="before")
    @classmethod
    def _coerce_origin(cls, value: object) -> PilotInputOrigin:
        return coerce_enum(PilotInputOrigin, value)

    @classmethod
    def from_content_bytes(cls, *, content: bytes, **values: object) -> Self:
        """Build one entry by hashing the exact bytes supplied to execution."""

        if type(content) is not bytes:
            raise TypeError("pilot input manifest content must be immutable bytes")
        prepared = dict(values)
        prepared["content_sha256"] = hashlib.sha256(content).hexdigest()
        return cls.model_validate(prepared)

    @model_validator(mode="after")
    def _validate_entry(self) -> Self:
        if self.origin in {
            PilotInputOrigin.absent,
            PilotInputOrigin.mixed_bundled_non_bundled,
        }:
            raise ValueError("pilot input manifest entries require one concrete, non-absent origin")
        return self


def calculate_pilot_input_set_digest(
    entries: Sequence[PilotInputManifestEntry],
    input_kind: PilotInputKind,
) -> str | None:
    selected = tuple(entry for entry in entries if entry.input_kind is input_kind)
    if not selected:
        return None
    payload = {
        "contract_id": "PilotInputSet/v1",
        "input_kind": input_kind.value,
        "entries": tuple(entry.model_dump(mode="json") for entry in selected),
    }
    return hashlib.sha256(rfc8785.dumps(payload)).hexdigest()


class PilotInputManifest(FrozenStrictModel):
    model_config = ConfigDict(json_schema_extra=_require_contract_identity_json_schema)

    artifact_kind: Literal["external-pilot-input-manifest"] = "external-pilot-input-manifest"
    schema_version: Literal["0.6.6"] = "0.6.6"
    schema_name: Literal["external-pilot-input-manifest"] = "external-pilot-input-manifest"
    contract_id: Literal["PilotInputManifest/v1"] = "PilotInputManifest/v1"
    contract_version: Literal["1.0.0"] = "1.0.0"
    workflow_id: Literal["controls-mutate", "rag-sensitivity"]
    entries: tuple[PilotInputManifestEntry, ...] = Field(min_length=1, max_length=64)
    configuration_digest: DigestHex | None
    data_digest: DigestHex | None

    @field_validator("entries", mode="before")
    @classmethod
    def _coerce_entries(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="before")
    @classmethod
    def _require_persisted_identity(cls, value: object) -> object:
        if not isinstance(value, Mapping):
            return value
        identity_fields = (
            "artifact_kind",
            "schema_version",
            "schema_name",
            "contract_id",
            "contract_version",
        )
        missing = tuple(field_name for field_name in identity_fields if field_name not in value)
        if missing:
            raise ValueError(
                "persisted pilot input manifest requires explicit identity fields: "
                + ", ".join(missing)
            )
        return value

    @classmethod
    def build(cls, **values: object) -> Self:
        prepared = dict(values)
        prepared.setdefault("artifact_kind", "external-pilot-input-manifest")
        prepared.setdefault("schema_version", "0.6.6")
        prepared.setdefault("schema_name", "external-pilot-input-manifest")
        prepared.setdefault("contract_id", "PilotInputManifest/v1")
        prepared.setdefault("contract_version", "1.0.0")
        raw_entries = coerce_tuple(prepared.get("entries"))
        if not isinstance(raw_entries, tuple):
            raise TypeError("pilot input manifest entries must be a sequence")
        entries = tuple(PilotInputManifestEntry.model_validate(item) for item in raw_entries)
        prepared["entries"] = entries
        prepared["configuration_digest"] = calculate_pilot_input_set_digest(
            entries,
            PilotInputKind.configuration,
        )
        prepared["data_digest"] = calculate_pilot_input_set_digest(entries, PilotInputKind.data)
        return cls.model_validate(prepared)

    @model_validator(mode="after")
    def _validate_manifest(self) -> Self:
        ordering = tuple(
            (entry.input_kind.value, entry.option_name, entry.option_value, entry.entry_id)
            for entry in self.entries
        )
        if ordering != tuple(sorted(ordering)):
            raise ValueError("pilot input manifest entries must use canonical ordering")
        if len({entry.entry_id for entry in self.entries}) != len(self.entries):
            raise ValueError("pilot input manifest entry IDs must be unique")
        argument_keys = tuple(
            (entry.input_kind, entry.option_name, entry.option_value) for entry in self.entries
        )
        if len(set(argument_keys)) != len(argument_keys):
            raise ValueError("pilot input manifest option bindings must be unique")
        allowed = _WORKFLOW_INPUT_OPTION_KINDS[self.workflow_id]
        if any(allowed.get(entry.option_name) is not entry.input_kind for entry in self.entries):
            raise ValueError("pilot input manifest contains an unsupported workflow input option")
        expected_identities = _WORKFLOW_INPUT_OPTION_IDENTITIES[self.workflow_id]
        if any(
            expected_identities.get(entry.option_name) is not entry.semantic_identity_kind
            for entry in self.entries
        ):
            raise ValueError(
                "pilot input manifest semantic identity kind does not match its workflow option"
            )
        waiver_digests = {
            entry.semantic_identity_digest
            for entry in self.entries
            if entry.option_name == "waiver"
        }
        if len(waiver_digests) > 1:
            raise ValueError("pilot waiver entries must bind the same aggregate waiver-set digest")
        expected_configuration = calculate_pilot_input_set_digest(
            self.entries,
            PilotInputKind.configuration,
        )
        expected_data = calculate_pilot_input_set_digest(self.entries, PilotInputKind.data)
        if (self.configuration_digest, self.data_digest) != (
            expected_configuration,
            expected_data,
        ):
            raise ValueError("pilot input manifest aggregate digests do not match its entries")
        return self


class PilotSubject(FrozenStrictModel):
    implementation_id: MachineIdentifier
    implementation_version: str = Field(pattern=PACKAGE_RELEASE_VERSION_PATTERN)
    source_revision: MachineIdentifier
    distribution_artifact_id: MachineIdentifier
    distribution_digest: DigestHex


class PilotEnvironmentComponent(FrozenStrictModel):
    component_id: MachineIdentifier
    version: PilotVersion


class PilotEnvironment(FrozenStrictModel):
    environment_id: MachineIdentifier
    execution_context: PilotExecutionContext
    control: PilotEnvironmentControl
    platform: PilotText
    components: tuple[PilotEnvironmentComponent, ...] = Field(
        min_length=1,
        max_length=MAX_PILOT_ENVIRONMENT_COMPONENTS,
    )
    environment_manifest_artifact_id: MachineIdentifier
    environment_manifest_digest: DigestHex
    control_evidence_artifact_id: MachineIdentifier | None

    @field_validator("execution_context", mode="before")
    @classmethod
    def _coerce_execution_context(cls, value: object) -> PilotExecutionContext:
        return coerce_enum(PilotExecutionContext, value)

    @field_validator("control", mode="before")
    @classmethod
    def _coerce_control(cls, value: object) -> PilotEnvironmentControl:
        return coerce_enum(PilotEnvironmentControl, value)

    @field_validator("components", mode="before")
    @classmethod
    def _coerce_components(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_components_and_control_evidence(self) -> Self:
        if self.components != tuple(sorted(self.components, key=lambda item: item.component_id)):
            raise ValueError(
                "pilot environment components must use canonical component-ID ordering"
            )
        if len({item.component_id for item in self.components}) != len(self.components):
            raise ValueError("pilot environment component IDs must be unique")
        has_control_evidence = self.control_evidence_artifact_id is not None
        control_is_evidenced = self.control is not PilotEnvironmentControl.unverified
        if has_control_evidence != control_is_evidenced:
            raise ValueError(
                "verified pilot environment control requires exactly one control evidence reference"
            )
        return self


class PilotInputBoundary(FrozenStrictModel):
    configuration_origin: PilotInputOrigin
    configuration_digest: DigestHex | None
    data_origin: PilotInputOrigin
    data_digest: DigestHex | None
    input_manifest_artifact_id: MachineIdentifier
    input_manifest_digest: DigestHex

    @field_validator("configuration_origin", "data_origin", mode="before")
    @classmethod
    def _coerce_origin(cls, value: object) -> PilotInputOrigin:
        return coerce_enum(PilotInputOrigin, value)

    @model_validator(mode="after")
    def _validate_origin_digests(self) -> Self:
        bindings = (
            ("configuration", self.configuration_origin, self.configuration_digest),
            ("data", self.data_origin, self.data_digest),
        )
        for label, origin, digest in bindings:
            if (origin is PilotInputOrigin.absent) != (digest is None):
                raise ValueError(
                    f"pilot {label} digest must be present exactly when its origin is not absent"
                )
        if all(origin is PilotInputOrigin.absent for _, origin, _ in bindings):
            raise ValueError("pilot input boundary requires configuration or data")
        return self

    @property
    def has_non_bundled_source(self) -> bool:
        return any(
            origin
            in {
                PilotInputOrigin.non_bundled,
                PilotInputOrigin.mixed_bundled_non_bundled,
            }
            for origin in (self.configuration_origin, self.data_origin)
        )


class PilotCommandExecution(FrozenStrictModel):
    command_id: MachineIdentifier
    sequence: int = Field(ge=1, le=MAX_PILOT_COMMANDS)
    argv: tuple[CommandArgument, ...] = Field(
        min_length=1,
        max_length=MAX_PILOT_COMMAND_ARGUMENTS,
    )
    working_directory_id: MachineIdentifier
    environment_variable_names: tuple[MachineIdentifier, ...] = Field(max_length=128)
    credential_values_persisted: Literal[False]
    raw_output_persisted: Literal[False]
    tested_distribution_artifact_id: MachineIdentifier
    tested_distribution_digest: DigestHex
    implementation_source_revision: MachineIdentifier
    input_manifest_artifact_id: MachineIdentifier
    consumed_input_entry_ids: tuple[MachineIdentifier, ...] = Field(max_length=64)
    started_at: str = Field(pattern=STRICT_RFC3339_TIMESTAMP_PATTERN)
    finished_at: str = Field(pattern=STRICT_RFC3339_TIMESTAMP_PATTERN)
    exit_code: int = Field(ge=-255, le=255)
    execution_evidence_artifact_id: MachineIdentifier
    execution_evidence_digest: DigestHex

    @field_validator(
        "argv",
        "environment_variable_names",
        "consumed_input_entry_ids",
        mode="before",
    )
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_command(self) -> Self:
        if _argv_contains_credential_material(self.argv):
            raise ValueError(
                "pilot command argv cannot persist credential material; "
                "record environment-variable names or non-secret file references instead"
            )
        if self.environment_variable_names != tuple(sorted(self.environment_variable_names)):
            raise ValueError("pilot command environment variable names must use canonical ordering")
        if len(set(self.environment_variable_names)) != len(self.environment_variable_names):
            raise ValueError("pilot command environment variable names must be unique")
        if self.consumed_input_entry_ids != tuple(sorted(set(self.consumed_input_entry_ids))):
            raise ValueError("pilot command consumed input entry IDs must be unique and sorted")
        if parse_rfc3339_timestamp(
            self.finished_at,
            field_name="pilot command finished_at",
        ) < parse_rfc3339_timestamp(
            self.started_at,
            field_name="pilot command started_at",
        ):
            raise ValueError("pilot command finished_at cannot precede started_at")
        return self


class PilotPublication(FrozenStrictModel):
    consent_status: PilotConsentStatus
    publication_scope: PilotPublicationScope
    consent_artifact_id: MachineIdentifier | None
    consent_digest: DigestHex | None
    published_artifact_ids: tuple[MachineIdentifier, ...] = Field(max_length=MAX_PILOT_ARTIFACTS)

    @field_validator("consent_status", mode="before")
    @classmethod
    def _coerce_consent_status(cls, value: object) -> PilotConsentStatus:
        return coerce_enum(PilotConsentStatus, value)

    @field_validator("publication_scope", mode="before")
    @classmethod
    def _coerce_publication_scope(cls, value: object) -> PilotPublicationScope:
        return coerce_enum(PilotPublicationScope, value)

    @field_validator("published_artifact_ids", mode="before")
    @classmethod
    def _coerce_published_artifact_ids(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_consent_and_scope(self) -> Self:
        if self.published_artifact_ids != tuple(sorted(self.published_artifact_ids)):
            raise ValueError("published pilot artifact IDs must use canonical ordering")
        if len(set(self.published_artifact_ids)) != len(self.published_artifact_ids):
            raise ValueError("published pilot artifact IDs must be unique")
        has_consent_anchor = (
            self.consent_artifact_id is not None and self.consent_digest is not None
        )
        if (self.consent_artifact_id is None) != (self.consent_digest is None):
            raise ValueError("pilot consent artifact ID and digest must be present together")
        if self.consent_status is PilotConsentStatus.not_requested and has_consent_anchor:
            raise ValueError("not-requested publication consent cannot carry a consent artifact")
        if self.consent_status is not PilotConsentStatus.not_requested and not has_consent_anchor:
            raise ValueError(
                "requested publication consent requires a digest-bound consent artifact"
            )
        if self.publication_scope is not PilotPublicationScope.private_record:
            if self.consent_status is not PilotConsentStatus.granted:
                raise ValueError("non-private pilot publication requires granted consent")
        if self.publication_scope is PilotPublicationScope.privacy_filtered_record:
            if not self.published_artifact_ids:
                raise ValueError("privacy-filtered pilot publication requires artifact references")
        elif self.published_artifact_ids:
            raise ValueError(
                "published pilot artifact references belong only to privacy-filtered record scope"
            )
        return self


class PilotFrictionFinding(FrozenStrictModel):
    friction_id: MachineIdentifier
    category: PilotFrictionCategory
    summary: PilotText
    evidence_artifact_ids: tuple[MachineIdentifier, ...] = Field(min_length=1, max_length=32)
    remediation_ids: tuple[MachineIdentifier, ...] = Field(min_length=1, max_length=32)

    @field_validator("category", mode="before")
    @classmethod
    def _coerce_category(cls, value: object) -> PilotFrictionCategory:
        return coerce_enum(PilotFrictionCategory, value)

    @field_validator("evidence_artifact_ids", "remediation_ids", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_references(self) -> Self:
        for label, values in (
            ("evidence artifact", self.evidence_artifact_ids),
            ("remediation", self.remediation_ids),
        ):
            if values != tuple(sorted(values)):
                raise ValueError(f"pilot friction {label} IDs must use canonical ordering")
            if len(set(values)) != len(values):
                raise ValueError(f"pilot friction {label} IDs must be unique")
        return self


class PilotRemediationReference(FrozenStrictModel):
    remediation_id: MachineIdentifier
    areas: tuple[PilotRemediationArea, ...] = Field(min_length=1, max_length=8)
    disposition: PilotRemediationDisposition
    remediation_artifact_id: MachineIdentifier
    remediation_digest: DigestHex

    @field_validator("areas", mode="before")
    @classmethod
    def _coerce_areas(cls, value: object) -> object:
        if isinstance(value, list | tuple):
            return tuple(coerce_enum(PilotRemediationArea, item) for item in value)
        return value

    @field_validator("disposition", mode="before")
    @classmethod
    def _coerce_disposition(cls, value: object) -> PilotRemediationDisposition:
        return coerce_enum(PilotRemediationDisposition, value)

    @model_validator(mode="after")
    def _validate_areas(self) -> Self:
        if self.areas != tuple(sorted(self.areas, key=lambda item: item.value)):
            raise ValueError("pilot remediation areas must use canonical ordering")
        if len(set(self.areas)) != len(self.areas):
            raise ValueError("pilot remediation areas must be unique")
        return self


class PilotPrivacyBoundary(FrozenStrictModel):
    raw_inputs_persisted: Literal[False]
    raw_outputs_persisted: Literal[False]
    credential_values_persisted: Literal[False]
    participant_direct_identifiers_persisted: Literal[False]
    persisted_content: Literal["digests_and_privacy_filtered_metadata_only"]


class ExternalPilotEvidence(SelfDigestedArtifact):
    """Digest-bound adoption evidence with deliberately non-release-gating semantics."""

    _digest_field = "pilot_evidence_digest"

    artifact_kind: Literal["external-pilot-evidence"] = "external-pilot-evidence"
    schema_version: Literal["0.6.6"] = "0.6.6"
    schema_name: Literal["external-pilot-evidence"] = "external-pilot-evidence"
    contract_id: Literal["ExternalPilotEvidence/v1"] = "ExternalPilotEvidence/v1"
    contract_version: Literal["1.0.0"] = "1.0.0"
    pilot_evidence_digest: DigestHex
    pilot_id: MachineIdentifier
    workflow_id: Literal["controls-mutate", "rag-sensitivity"]
    participant_pseudonym: MachineIdentifier
    classification: PilotClassification
    attempt_status: PilotAttemptStatus
    qualifies_as_external_attempt: bool
    subject: PilotSubject
    environment: PilotEnvironment
    inputs: PilotInputBoundary
    commands: tuple[PilotCommandExecution, ...] = Field(max_length=MAX_PILOT_COMMANDS)
    artifacts: tuple[PilotArtifactDigest, ...] = Field(min_length=3, max_length=MAX_PILOT_ARTIFACTS)
    friction_assessment: PilotFrictionAssessmentState
    friction_assessment_artifact_id: MachineIdentifier | None
    friction_findings: tuple[PilotFrictionFinding, ...] = Field(max_length=MAX_PILOT_FINDINGS)
    remediations: tuple[PilotRemediationReference, ...] = Field(max_length=MAX_PILOT_REMEDIATIONS)
    publication: PilotPublication
    privacy: PilotPrivacyBoundary
    recorded_at: str = Field(pattern=STRICT_RFC3339_TIMESTAMP_PATTERN)
    limitations: tuple[PilotText, ...] = Field(min_length=1, max_length=64)
    evidence_phase: Literal["pre_candidate"]
    evidence_use: Literal["learning_and_remediation_only"]
    clean_reproduction_gate_eligible: Literal[False]
    exact_candidate_gate_eligible: Literal[False]
    ci_integration_gate_eligible: Literal[False]

    @field_validator("classification", mode="before")
    @classmethod
    def _coerce_classification(cls, value: object) -> PilotClassification:
        return coerce_enum(PilotClassification, value)

    @field_validator("attempt_status", mode="before")
    @classmethod
    def _coerce_attempt_status(cls, value: object) -> PilotAttemptStatus:
        return coerce_enum(PilotAttemptStatus, value)

    @field_validator("friction_assessment", mode="before")
    @classmethod
    def _coerce_friction_assessment(cls, value: object) -> PilotFrictionAssessmentState:
        return coerce_enum(PilotFrictionAssessmentState, value)

    @field_validator(
        "commands",
        "artifacts",
        "friction_findings",
        "remediations",
        "limitations",
        mode="before",
    )
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_evidence_contract(self) -> Self:
        payload = self.model_dump(mode="json", warnings="error")
        if redact_packet_payload(payload) != payload or _durable_value_contains_credential_material(
            payload
        ):
            raise ValueError("pilot evidence must already contain only privacy-filtered metadata")
        artifacts = self._validate_canonical_artifacts()
        self._validate_primary_artifact_anchors(artifacts)
        self._validate_commands(artifacts)
        self._validate_friction_and_remediation(artifacts)
        self._validate_publication(artifacts)
        self._validate_attempt_classification()
        if self.limitations != tuple(sorted(self.limitations)):
            raise ValueError("pilot limitations must use canonical ordering")
        if len(set(self.limitations)) != len(self.limitations):
            raise ValueError("pilot limitations must be unique")
        latest_command = max(
            (
                parse_rfc3339_timestamp(
                    item.finished_at,
                    field_name="pilot command finished_at",
                )
                for item in self.commands
            ),
            default=None,
        )
        if latest_command is not None and latest_command > parse_rfc3339_timestamp(
            self.recorded_at,
            field_name="pilot recorded_at",
        ):
            raise ValueError("pilot recorded_at cannot precede command completion")
        return self

    def _validate_canonical_artifacts(self) -> dict[str, PilotArtifactDigest]:
        if self.artifacts != tuple(sorted(self.artifacts, key=lambda item: item.artifact_id)):
            raise ValueError("pilot artifacts must use canonical artifact-ID ordering")
        artifacts = {item.artifact_id: item for item in self.artifacts}
        if len(artifacts) != len(self.artifacts):
            raise ValueError("pilot artifact IDs must be unique")
        normalized_paths = [item.path.casefold() for item in self.artifacts]
        if len(set(normalized_paths)) != len(normalized_paths):
            raise ValueError(
                "pilot artifact paths must be unique under portable case-insensitive matching"
            )
        return artifacts

    def _validate_primary_artifact_anchors(
        self,
        artifacts: dict[str, PilotArtifactDigest],
    ) -> None:
        _require_artifact(
            artifacts,
            artifact_id=self.subject.distribution_artifact_id,
            digest=self.subject.distribution_digest,
            role=PilotArtifactRole.tested_distribution,
            label="tested distribution",
        )
        _require_artifact(
            artifacts,
            artifact_id=self.environment.environment_manifest_artifact_id,
            digest=self.environment.environment_manifest_digest,
            role=PilotArtifactRole.environment_manifest,
            label="environment manifest",
        )
        _require_artifact(
            artifacts,
            artifact_id=self.inputs.input_manifest_artifact_id,
            digest=self.inputs.input_manifest_digest,
            role=PilotArtifactRole.input_manifest,
            label="input manifest",
        )
        control_id = self.environment.control_evidence_artifact_id
        if control_id is not None:
            _require_artifact(
                artifacts,
                artifact_id=control_id,
                role=PilotArtifactRole.environment_control_evidence,
                label="environment control evidence",
            )

    def _validate_commands(self, artifacts: dict[str, PilotArtifactDigest]) -> None:
        if self.commands != tuple(sorted(self.commands, key=lambda item: item.sequence)):
            raise ValueError("pilot commands must use canonical execution ordering")
        if tuple(item.sequence for item in self.commands) != tuple(
            range(1, len(self.commands) + 1)
        ):
            raise ValueError("pilot command sequence must be contiguous and start at one")
        if len({item.command_id for item in self.commands}) != len(self.commands):
            raise ValueError("pilot command IDs must be unique")
        commands_by_id = {item.command_id: item for item in self.commands}
        for command in self.commands:
            if _argv_contains_credential_material(command.argv):
                raise ValueError("pilot command argv cannot persist credential material")
            _require_artifact(
                artifacts,
                artifact_id=command.execution_evidence_artifact_id,
                digest=command.execution_evidence_digest,
                role=PilotArtifactRole.execution_evidence,
                label=f"execution evidence for command {command.command_id}",
            )
            _require_artifact(
                artifacts,
                artifact_id=command.tested_distribution_artifact_id,
                digest=command.tested_distribution_digest,
                role=PilotArtifactRole.tested_distribution,
                label=f"tested distribution for command {command.command_id}",
            )
            if (
                command.tested_distribution_artifact_id != self.subject.distribution_artifact_id
                or command.tested_distribution_digest != self.subject.distribution_digest
                or command.implementation_source_revision != self.subject.source_revision
            ):
                raise ValueError(
                    "pilot command must bind the exact subject distribution and source revision"
                )
            if command.input_manifest_artifact_id != self.inputs.input_manifest_artifact_id:
                raise ValueError("pilot command must bind the exact pilot input manifest")
            invocation_inputs = pilot_workflow_input_arguments(command.argv, self.workflow_id)
            if invocation_inputs is not None and not command.consumed_input_entry_ids:
                raise ValueError(
                    "pilot workflow command must bind every consumed input manifest entry"
                )
        for artifact in self.artifacts:
            producer_id = artifact.producing_command_id
            if producer_id is None:
                continue
            producer = commands_by_id.get(producer_id)
            if producer is None:
                raise ValueError("pilot assurance output producing command must resolve exactly")
            expected_contract = _workflow_output_contract(producer.argv, self.workflow_id)
            if (
                artifact.schema_contract is not None
                and artifact.schema_contract != expected_contract
            ):
                raise ValueError(
                    "pilot assurance output must match the exact executed workflow contract "
                    "of its producing command"
                )

    def _validate_friction_and_remediation(
        self,
        artifacts: dict[str, PilotArtifactDigest],
    ) -> None:
        if self.friction_findings != tuple(
            sorted(self.friction_findings, key=lambda item: item.friction_id)
        ):
            raise ValueError("pilot friction findings must use canonical friction-ID ordering")
        if len({item.friction_id for item in self.friction_findings}) != len(
            self.friction_findings
        ):
            raise ValueError("pilot friction IDs must be unique")
        if self.remediations != tuple(
            sorted(self.remediations, key=lambda item: item.remediation_id)
        ):
            raise ValueError("pilot remediations must use canonical remediation-ID ordering")
        remediation_by_id = {item.remediation_id: item for item in self.remediations}
        if len(remediation_by_id) != len(self.remediations):
            raise ValueError("pilot remediation IDs must be unique")
        for remediation in self.remediations:
            _require_artifact(
                artifacts,
                artifact_id=remediation.remediation_artifact_id,
                digest=remediation.remediation_digest,
                role=PilotArtifactRole.remediation_record,
                label=f"remediation evidence for {remediation.remediation_id}",
            )
        for finding in self.friction_findings:
            for artifact_id in finding.evidence_artifact_ids:
                _require_artifact(
                    artifacts,
                    artifact_id=artifact_id,
                    role=PilotArtifactRole.friction_assessment,
                    label=f"friction evidence for {finding.friction_id}",
                )
            if not set(finding.remediation_ids).issubset(remediation_by_id):
                raise ValueError("pilot friction remediation references must resolve exactly")
        referenced_remediations = {
            remediation_id
            for finding in self.friction_findings
            for remediation_id in finding.remediation_ids
        }
        if set(remediation_by_id) != referenced_remediations:
            raise ValueError("every pilot remediation must be referenced by a friction finding")
        assessment_id = self.friction_assessment_artifact_id
        if assessment_id is not None:
            _require_artifact(
                artifacts,
                artifact_id=assessment_id,
                role=PilotArtifactRole.friction_assessment,
                label="friction assessment",
            )
        if self.friction_assessment is PilotFrictionAssessmentState.friction_observed:
            if assessment_id is None or not self.friction_findings or not self.remediations:
                raise ValueError(
                    "observed pilot friction requires assessment evidence, findings, "
                    "and remediation"
                )
        elif self.friction_assessment is PilotFrictionAssessmentState.no_friction_observed:
            if assessment_id is None:
                raise ValueError("no-friction pilot assessment requires evidence")
            if self.friction_findings or self.remediations:
                raise ValueError(
                    "no-friction pilot assessment cannot contain findings or remediation"
                )
        elif assessment_id is not None or self.friction_findings or self.remediations:
            raise ValueError(
                "unassessed pilot friction cannot carry assessment evidence or findings"
            )

    def _validate_publication(self, artifacts: dict[str, PilotArtifactDigest]) -> None:
        publication = self.publication
        if publication.consent_artifact_id is not None:
            _require_artifact(
                artifacts,
                artifact_id=publication.consent_artifact_id,
                digest=publication.consent_digest,
                role=PilotArtifactRole.consent_record,
                label="publication consent",
            )
        for artifact_id in publication.published_artifact_ids:
            artifact = artifacts.get(artifact_id)
            if artifact is None:
                raise ValueError("published pilot artifact references must resolve exactly")
            if artifact.content_scope not in (
                PilotArtifactContentScope.distribution_binary,
                PilotArtifactContentScope.metadata_only,
                PilotArtifactContentScope.privacy_filtered,
            ):
                raise ValueError("published pilot artifacts must be privacy safe")

    def _validate_attempt_classification(self) -> None:
        was_attempted = self.attempt_status in (
            PilotAttemptStatus.attempted,
            PilotAttemptStatus.completed,
        )
        if was_attempted:
            if not self.commands:
                raise ValueError("attempted pilot evidence requires at least one exact command")
            if self.friction_assessment is PilotFrictionAssessmentState.not_assessed:
                raise ValueError("attempted pilot evidence requires a friction assessment")
        else:
            if self.commands:
                raise ValueError("not-attempted pilot evidence cannot contain command executions")
            if self.friction_assessment is not PilotFrictionAssessmentState.not_assessed:
                raise ValueError("not-attempted pilot evidence cannot claim a friction assessment")
            execution_roles = {
                PilotArtifactRole.execution_evidence,
                PilotArtifactRole.assurance_output,
                PilotArtifactRole.friction_assessment,
                PilotArtifactRole.remediation_record,
            }
            if any(item.role in execution_roles for item in self.artifacts):
                raise ValueError(
                    "not-attempted pilot evidence cannot contain execution or remediation artifacts"
                )
        if self.attempt_status is PilotAttemptStatus.completed:
            completed_outputs = tuple(
                item for item in self.artifacts if item.role is PilotArtifactRole.assurance_output
            )
            expected_contracts = {
                contract
                for command in self.commands
                if (contract := _workflow_output_contract(command.argv, self.workflow_id))
                is not None
            }
            if not completed_outputs or not expected_contracts:
                raise ValueError(
                    "completed pilot evidence requires an executable signature workflow and "
                    "its schema-valid assurance output artifact"
                )
            if any(
                not item.schema_validated or item.schema_contract not in expected_contracts
                for item in completed_outputs
            ):
                expected = ", ".join(sorted(expected_contracts))
                raise ValueError(
                    "completed pilot evidence requires a schema-valid assurance output under "
                    f"the exact executed workflow contract: {expected}"
                )
            command_by_id = {item.command_id: item for item in self.commands}
            producing_commands = []
            for item in completed_outputs:
                producer_id = item.producing_command_id
                if producer_id is None:
                    raise ValueError("completed pilot assurance output has no producing command")
                producing_commands.append(command_by_id[producer_id])
            if any(command.exit_code not in {0, 1} for command in producing_commands):
                raise ValueError(
                    "completed pilot assurance outputs require a producing command with "
                    "a completed evidence-bearing exit code"
                )

        external_attempt = self.classification is PilotClassification.external and was_attempted
        if external_attempt:
            if (
                self.environment.execution_context
                is not PilotExecutionContext.continuous_integration
            ):
                raise ValueError("external pilot attempt requires continuous-integration execution")
            if self.environment.control is not (
                PilotEnvironmentControl.independently_controlled_non_maintainer
            ):
                raise ValueError(
                    "external pilot attempt requires an independently controlled "
                    "non-maintainer environment"
                )
            if self.environment.control_evidence_artifact_id is None:
                raise ValueError("external pilot attempt requires environment-control evidence")
            if not self.inputs.has_non_bundled_source:
                raise ValueError(
                    "external pilot attempt requires non-bundled configuration or data"
                )
            if not any(
                _invokes_agent_assure_workflow(command.argv, self.workflow_id)
                for command in self.commands
            ):
                raise ValueError(
                    "external pilot attempt requires a direct Agent Assure invocation "
                    "matching workflow_id"
                )
        if self.qualifies_as_external_attempt is not external_attempt:
            raise ValueError(
                "qualifies_as_external_attempt must match the validated pilot classification"
            )


class ExternalPilotIndependenceReviewReceipt(SelfDigestedArtifact):
    """Operator-attested review bound to one exact external-pilot evidence bundle."""

    _digest_field = "review_receipt_digest"

    artifact_kind: Literal["external-pilot-independence-review"] = (
        "external-pilot-independence-review"
    )
    schema_version: Literal["0.6.6"] = "0.6.6"
    schema_name: Literal["external-pilot-independence-review"] = (
        "external-pilot-independence-review"
    )
    contract_id: Literal["ExternalPilotIndependenceReviewReceipt/v1"] = (
        "ExternalPilotIndependenceReviewReceipt/v1"
    )
    contract_version: Literal["1.0.0"] = "1.0.0"
    review_receipt_digest: DigestHex
    receipt_id: MachineIdentifier
    pilot_id: MachineIdentifier
    pilot_participant_pseudonym: MachineIdentifier
    pilot_evidence_digest: DigestHex
    pilot_evidence_file_sha256: DigestHex
    artifact_manifest_digest: DigestHex
    environment_control_evidence_artifact_id: MachineIdentifier
    environment_control_evidence_sha256: DigestHex
    publication_consent_artifact_id: MachineIdentifier
    publication_consent_sha256: DigestHex
    pilot_execution_source_revision: GitRevision
    pilot_friction_assessment: PilotFrictionAssessmentState
    pilot_friction_categories: tuple[PilotFrictionCategory, ...] = Field(
        max_length=MAX_PILOT_FINDINGS
    )
    pilot_remediation_dispositions: tuple[PilotRemediationDisposition, ...] = Field(
        max_length=MAX_PILOT_REMEDIATIONS
    )
    pilot_remediation_source_revision: GitRevision | None
    prior_planned_candidate_evidence_digest: DigestHex | None
    capture_workflow_run: PilotWorkflowRunReview
    finalize_workflow_run: PilotWorkflowRunReview
    expected_release_line: str = Field(
        pattern=r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
    )
    reviewer_pseudonym: MachineIdentifier
    review_method: Literal["human_operator_attestation"] = "human_operator_attestation"
    reviewer_identity_authentication: Literal["out_of_band_not_machine_verified"] = (
        "out_of_band_not_machine_verified"
    )
    manual_approval_is_trust_root: Literal[True]
    reviewer_independent_of_pilot_execution: Literal[True]
    reviewer_independence_rationale: PilotText
    environment_control_evidence_reviewed: Literal[True]
    artifact_inventory_reviewed: Literal[True]
    tested_distribution_provenance_reviewed: Literal[True]
    command_input_bindings_reviewed: Literal[True]
    execution_time_input_content_digests_reviewed: Literal[True]
    input_semantic_identities_reviewed: Literal[True]
    complete_bundle_publication_consent_reviewed: Literal[True]
    run_head_shas_reviewed: Literal[True]
    workflow_run_urls_reviewed: Literal[True]
    trusted_workflow_bytes_reviewed: Literal[True]
    execution_source_pins_reviewed: Literal[True]
    public_workflow_inputs_reviewed: Literal[True]
    friction_and_remediation_disposition_reviewed: Literal[True]
    friction_category_and_remediation_bindings_reviewed: Literal[True]
    privacy_boundary_reviewed: Literal[True]
    review_outcome: Literal["approved_for_empirical_checkpoint"]
    reviewed_at: str = Field(pattern=STRICT_RFC3339_TIMESTAMP_PATTERN)

    @field_validator("pilot_friction_assessment", mode="before")
    @classmethod
    def _coerce_reviewed_friction(cls, value: object) -> PilotFrictionAssessmentState:
        return coerce_enum(PilotFrictionAssessmentState, value)

    @field_validator("pilot_friction_categories", mode="before")
    @classmethod
    def _coerce_reviewed_friction_categories(cls, value: object) -> object:
        values = coerce_tuple(value)
        if isinstance(values, tuple):
            return tuple(coerce_enum(PilotFrictionCategory, item) for item in values)
        return values

    @field_validator("pilot_remediation_dispositions", mode="before")
    @classmethod
    def _coerce_reviewed_remediations(cls, value: object) -> object:
        values = coerce_tuple(value)
        if isinstance(values, tuple):
            return tuple(coerce_enum(PilotRemediationDisposition, item) for item in values)
        return values

    @model_validator(mode="after")
    def _validate_review_receipt(self) -> Self:
        payload = self.model_dump(mode="json", warnings="error")
        if redact_packet_payload(payload) != payload or _durable_value_contains_credential_material(
            payload
        ):
            raise ValueError(
                "pilot independence review must contain only privacy-filtered metadata"
            )
        if self.reviewer_pseudonym.casefold() == self.pilot_participant_pseudonym.casefold():
            raise ValueError("pilot reviewer must be distinct from the pilot participant")
        capture = self.capture_workflow_run
        finalize = self.finalize_workflow_run
        if capture.stage != "capture" or finalize.stage != "finalize":
            raise ValueError("pilot review receipt requires capture and finalize run bindings")
        if capture.repository.casefold() != finalize.repository.casefold():
            raise ValueError("pilot capture and finalization must come from the same fork")
        if capture.trusted_workflow_revision != finalize.trusted_workflow_revision:
            raise ValueError("pilot workflows must use one trusted upstream workflow revision")
        if (
            capture.execution_source_revision != self.pilot_execution_source_revision
            or finalize.execution_source_revision != self.pilot_execution_source_revision
        ):
            raise ValueError(
                "pilot workflow execution-source pins must match the reviewed pilot source"
            )
        if capture.input_values["participant_pseudonym"] != self.pilot_participant_pseudonym:
            raise ValueError("pilot capture public pseudonym does not match the evidence")
        if finalize.input_values["capture_run_id"] != capture.run_id:
            raise ValueError("pilot finalization public inputs do not bind the capture run URL")
        if finalize.input_values["capture_run_attempt"] != str(capture.run_attempt):
            raise ValueError("pilot finalization public inputs do not bind the capture run attempt")
        if finalize.input_values["friction_assessment"] != self.pilot_friction_assessment.value:
            raise ValueError("pilot finalization public friction state does not match the evidence")
        if self.pilot_friction_categories != tuple(
            sorted(self.pilot_friction_categories, key=lambda item: item.value)
        ) or len(set(self.pilot_friction_categories)) != len(self.pilot_friction_categories):
            raise ValueError("reviewed pilot friction categories must be canonical and unique")
        expected_category = (
            self.pilot_friction_categories[0].value
            if len(self.pilot_friction_categories) == 1
            else "not_applicable"
        )
        if finalize.input_values["friction_category"] != expected_category:
            raise ValueError(
                "pilot finalization public friction category does not match the evidence"
            )
        expected_disposition = (
            self.pilot_remediation_dispositions[0].value
            if len(self.pilot_remediation_dispositions) == 1
            else "not_applicable"
        )
        if finalize.input_values["remediation_disposition"] != expected_disposition:
            raise ValueError(
                "pilot finalization remediation disposition does not match the evidence"
            )
        if expected_disposition == PilotRemediationDisposition.applied.value:
            if (
                self.pilot_remediation_source_revision is None
                or self.prior_planned_candidate_evidence_digest is None
            ):
                raise ValueError(
                    "applied pilot remediation requires source and prior-candidate bindings"
                )
            if (
                finalize.input_values["remediation_source_revision"]
                != self.pilot_remediation_source_revision
                or finalize.input_values["prior_candidate_evidence_digest"]
                != self.prior_planned_candidate_evidence_digest
            ):
                raise ValueError(
                    "pilot finalization applied-remediation inputs do not match the evidence"
                )
        elif (
            self.pilot_remediation_source_revision is not None
            or self.prior_planned_candidate_evidence_digest is not None
            or finalize.input_values["remediation_source_revision"] != "none"
            or finalize.input_values["prior_candidate_evidence_digest"] != "none"
        ):
            raise ValueError(
                "non-applied pilot remediation cannot carry applied-remediation bindings"
            )
        if self.pilot_friction_assessment is PilotFrictionAssessmentState.friction_observed:
            if (
                len(self.pilot_friction_categories) != 1
                or len(self.pilot_remediation_dispositions) != 1
            ):
                raise ValueError(
                    "observed pilot friction requires one reviewed category and remediation"
                )
        elif self.pilot_friction_categories or self.pilot_remediation_dispositions:
            raise ValueError(
                "no-friction pilot review cannot claim friction categories or remediations"
            )
        return self


def _require_artifact(
    artifacts: dict[str, PilotArtifactDigest],
    *,
    artifact_id: str,
    role: PilotArtifactRole,
    label: str,
    digest: str | None = None,
) -> PilotArtifactDigest:
    artifact = artifacts.get(artifact_id)
    if artifact is None or artifact.role is not role:
        raise ValueError(f"pilot {label} artifact reference must resolve with the required role")
    if digest is not None and artifact.sha256 != digest:
        raise ValueError(f"pilot {label} artifact digest must match its referenced artifact")
    return artifact


__all__ = [
    "calculate_pilot_workflow_inputs_digest",
    "calculate_pilot_input_set_digest",
    "ExternalPilotEvidence",
    "ExternalPilotIndependenceReviewReceipt",
    "PilotArtifactContentScope",
    "PilotArtifactDigest",
    "PilotArtifactRole",
    "PilotAttemptStatus",
    "PilotClassification",
    "PilotCommandExecution",
    "PilotConsentStatus",
    "PilotEnvironment",
    "PilotEnvironmentComponent",
    "PilotEnvironmentControl",
    "PilotExecutionContext",
    "PilotFrictionAssessmentState",
    "PilotFrictionCategory",
    "PilotFrictionFinding",
    "PilotInputBoundary",
    "PilotInputIdentityKind",
    "PilotInputKind",
    "PilotInputManifest",
    "PilotInputManifestEntry",
    "PilotInputOrigin",
    "PilotPrivacyBoundary",
    "PilotPublication",
    "PilotPublicationScope",
    "PilotRemediationArea",
    "PilotRemediationDisposition",
    "PilotRemediationReference",
    "PilotSubject",
    "PilotWorkflowDispatchInput",
    "PilotWorkflowRunReview",
    "pilot_workflow_input_arguments",
]
