from __future__ import annotations

from typing import Literal

from pydantic import Field
from pydantic.functional_validators import field_validator

from agent_assure.schema.base import PersistedArtifact
from agent_assure.schema.common import ExecutionMode, coerce_enum, coerce_tuple
from agent_assure.schema.expectation import Expectation


class SuiteDefaults(PersistedArtifact):
    artifact_kind: Literal["suite-defaults"] = "suite-defaults"
    execution_mode: ExecutionMode = ExecutionMode.fixture
    required_policy_ids: tuple[str, ...] = ()

    @field_validator("execution_mode", mode="before")
    @classmethod
    def _coerce_execution_mode(cls, value: object) -> ExecutionMode:
        return coerce_enum(ExecutionMode, value)

    @field_validator("required_policy_ids", mode="before")
    @classmethod
    def _coerce_required_policy_ids(cls, value: object) -> object:
        return coerce_tuple(value)


class SuiteCase(PersistedArtifact):
    artifact_kind: Literal["suite-case"] = "suite-case"
    case_id: str = Field(min_length=1)
    title: str = Field(min_length=1)


class CompiledSuite(PersistedArtifact):
    artifact_kind: Literal["compiled-suite"] = "compiled-suite"
    suite_id: str = Field(min_length=1)
    suite_version: str = Field(min_length=1)
    defaults: SuiteDefaults = SuiteDefaults()
    cases: tuple[SuiteCase, ...]
    resolved_expectations: tuple[Expectation, ...]
    source_digest: str

    @field_validator("cases", "resolved_expectations", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)
