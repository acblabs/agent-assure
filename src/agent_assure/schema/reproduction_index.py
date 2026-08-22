from __future__ import annotations

from enum import StrEnum
from typing import Literal, Self

from pydantic import Field, field_validator, model_validator

from agent_assure.rooted_io import portable_relative_path_parts
from agent_assure.schema.base import FrozenStrictModel
from agent_assure.schema.common import DigestHex, coerce_enum, coerce_tuple
from agent_assure.schema.mutation import BoundedSummary, MachineIdentifier, SelfDigestedArtifact

MAX_REPRODUCTION_INDEX_SOURCE_CLOSURE_ENTRIES = 4_096
REPRODUCTION_INDEX_SOURCE_INVENTORY_POLICY: Literal[
    "recursive_regular_files_no_runtime_cache_v1"
] = "recursive_regular_files_no_runtime_cache_v1"


class ProcessEquivalenceStratum(StrEnum):
    same_output_different_process = "same_output_different_process"
    evidence_insensitivity = "evidence_insensitivity"


class ProcessEquivalenceExpectedObservation(StrEnum):
    evidence_insensitivity_blocked = "evidence_insensitivity_blocked"
    same_output_different_process_detected = "same_output_different_process_detected"


class ProcessEquivalenceReproductionIndexSourceArtifact(FrozenStrictModel):
    path: str = Field(min_length=1, max_length=1024)
    sha256: DigestHex

    @field_validator("path")
    @classmethod
    def _validate_canonical_path(cls, value: str) -> str:
        canonical = "/".join(portable_relative_path_parts(value))
        if value != canonical:
            raise ValueError(
                "reproduction-index source artifact path must be canonical and portable"
            )
        return value


class ProcessEquivalenceReproductionIndexSourceClosure(FrozenStrictModel):
    source_root: str = Field(min_length=1, max_length=1024)
    inventory_policy: Literal["recursive_regular_files_no_runtime_cache_v1"] = (
        REPRODUCTION_INDEX_SOURCE_INVENTORY_POLICY
    )
    closure_digest: DigestHex
    entries: tuple[ProcessEquivalenceReproductionIndexSourceArtifact, ...] = Field(
        min_length=1,
        max_length=MAX_REPRODUCTION_INDEX_SOURCE_CLOSURE_ENTRIES,
    )

    @field_validator("source_root")
    @classmethod
    def _validate_source_root(cls, value: str) -> str:
        canonical = "/".join(portable_relative_path_parts(value))
        if value != canonical:
            raise ValueError("reproduction-index source root must be canonical and portable")
        return value

    @field_validator("entries", mode="before")
    @classmethod
    def _coerce_entries(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_closure(self) -> Self:
        if self.entries != tuple(sorted(self.entries, key=lambda item: item.path)):
            raise ValueError("reproduction-index source closure entries must be unique and sorted")
        if len({item.path for item in self.entries}) != len(self.entries):
            raise ValueError("reproduction-index source closure entry paths must be unique")
        expected_digest = _canonical_sha256(
            tuple(item.model_dump(mode="json") for item in self.entries)
        )
        if self.closure_digest != expected_digest:
            raise ValueError(
                "reproduction-index source closure digest does not match canonical sorted entries"
            )
        return self

    @classmethod
    def build(
        cls,
        *,
        source_root: str,
        entries: tuple[ProcessEquivalenceReproductionIndexSourceArtifact, ...],
    ) -> ProcessEquivalenceReproductionIndexSourceClosure:
        canonical_entries = tuple(sorted(entries, key=lambda item: item.path))
        return cls(
            source_root=source_root,
            closure_digest=_canonical_sha256(
                tuple(item.model_dump(mode="json") for item in canonical_entries)
            ),
            entries=canonical_entries,
        )


class ProcessEquivalenceReproductionIndexReplay(FrozenStrictModel):
    program: Literal["agent-assure"] = "agent-assure"
    command: Literal["demo"] = "demo"
    demo: Literal["evidence-sensitivity", "flagship"]
    clean: Literal[True] = True
    output_format: Literal["json"] = "json"
    expected_exit_code: Literal[0] = 0
    expected_observation: ProcessEquivalenceExpectedObservation

    @field_validator("expected_observation", mode="before")
    @classmethod
    def _coerce_observation(cls, value: object) -> ProcessEquivalenceExpectedObservation:
        return coerce_enum(ProcessEquivalenceExpectedObservation, value)


class ProcessEquivalenceReproductionIndexCase(FrozenStrictModel):
    case_id: MachineIdentifier
    stratum: ProcessEquivalenceStratum
    subject_designation: Literal["synthetic_detector_contract_test"] = (
        "synthetic_detector_contract_test"
    )
    source_artifacts: tuple[ProcessEquivalenceReproductionIndexSourceArtifact, ...] = Field(
        min_length=1,
        max_length=32,
    )
    source_closure: ProcessEquivalenceReproductionIndexSourceClosure
    replay: ProcessEquivalenceReproductionIndexReplay

    @field_validator("stratum", mode="before")
    @classmethod
    def _coerce_stratum(cls, value: object) -> ProcessEquivalenceStratum:
        return coerce_enum(ProcessEquivalenceStratum, value)

    @field_validator("source_artifacts", mode="before")
    @classmethod
    def _coerce_sources(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_sources(self) -> Self:
        if self.source_artifacts != tuple(
            sorted(self.source_artifacts, key=lambda item: item.path)
        ):
            raise ValueError("reproduction-index source artifacts must be unique and sorted")
        if len({item.path for item in self.source_artifacts}) != len(self.source_artifacts):
            raise ValueError("reproduction-index source artifact paths must be unique")
        closure_entries = {
            f"{self.source_closure.source_root}/{item.path}": item.sha256
            for item in self.source_closure.entries
        }
        if any(closure_entries.get(item.path) != item.sha256 for item in self.source_artifacts):
            raise ValueError(
                "reproduction-index source artifact anchors must resolve exactly in source closure"
            )
        expected_replay = {
            ProcessEquivalenceStratum.evidence_insensitivity: (
                "evidence-sensitivity",
                ProcessEquivalenceExpectedObservation.evidence_insensitivity_blocked,
            ),
            ProcessEquivalenceStratum.same_output_different_process: (
                "flagship",
                ProcessEquivalenceExpectedObservation.same_output_different_process_detected,
            ),
        }[self.stratum]
        if (self.replay.demo, self.replay.expected_observation) != expected_replay:
            raise ValueError("reproduction-index replay demo and observation are fixed by stratum")
        return self


def _canonical_sha256(value: object) -> str:
    # Imported lazily so schema package initialization cannot cycle through the
    # canonical layer while that layer is importing schema.common.
    from agent_assure.canonical.digests import sha256_hexdigest

    return sha256_hexdigest(value)


class ProcessEquivalenceReproductionIndex(SelfDigestedArtifact):
    _digest_field = "reproduction_index_digest"

    artifact_kind: Literal["process-equivalence-reproduction-index"] = (
        "process-equivalence-reproduction-index"
    )
    schema_version: Literal["0.6.4"] = "0.6.4"
    schema_name: Literal["process-equivalence-reproduction-index"] = (
        "process-equivalence-reproduction-index"
    )
    contract_id: Literal["ProcessEquivalenceReproductionIndex/v1"] = (
        "ProcessEquivalenceReproductionIndex/v1"
    )
    contract_version: Literal["1.0.0"] = "1.0.0"
    reproduction_index_digest: DigestHex
    reproduction_index_id: Literal["process-equivalence-reproduction-index"] = (
        "process-equivalence-reproduction-index"
    )
    reproduction_index_version: Literal["0.1.0"] = "0.1.0"
    cases: tuple[ProcessEquivalenceReproductionIndexCase, ...] = Field(
        min_length=2,
        max_length=256,
    )
    leaderboard_supported: Literal[False] = False
    prevalence_claim_supported: Literal[False] = False
    real_model_measurement: Literal[False] = False
    limitations: tuple[BoundedSummary, ...] = Field(min_length=1, max_length=64)

    @field_validator("cases", "limitations", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_case_scope(self) -> Self:
        if self.cases != tuple(sorted(self.cases, key=lambda item: item.case_id)):
            raise ValueError("reproduction-index cases must use canonical case-ID ordering")
        if len({item.case_id for item in self.cases}) != len(self.cases):
            raise ValueError("reproduction-index case IDs must be unique")
        required = set(ProcessEquivalenceStratum)
        observed = {item.stratum for item in self.cases}
        if not required.issubset(observed):
            raise ValueError(
                "reproduction index must contain every required process-equivalence stratum"
            )
        return self


__all__ = [
    "ProcessEquivalenceReproductionIndex",
    "ProcessEquivalenceReproductionIndexCase",
    "ProcessEquivalenceReproductionIndexReplay",
    "ProcessEquivalenceReproductionIndexSourceArtifact",
    "ProcessEquivalenceReproductionIndexSourceClosure",
    "ProcessEquivalenceExpectedObservation",
    "ProcessEquivalenceStratum",
]
