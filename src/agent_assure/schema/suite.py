from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator
from pydantic.functional_validators import field_validator

from agent_assure.schema.base import PersistedArtifact
from agent_assure.schema.common import DigestHex, ExecutionMode, coerce_enum, coerce_tuple
from agent_assure.schema.expectation import Expectation


class SuiteDefaults(PersistedArtifact):
    artifact_kind: Literal["suite-defaults"] = "suite-defaults"
    execution_mode: ExecutionMode = ExecutionMode.fixture
    runner_id: str = Field(default="prior_auth.synthetic", min_length=1)
    fixture_roots: tuple[str, ...] = ("fixtures/shared",)
    required_policy_ids: tuple[str, ...] = ()
    allowed_tools: tuple[str, ...] = ()

    @field_validator("execution_mode", mode="before")
    @classmethod
    def _coerce_execution_mode(cls, value: object) -> ExecutionMode:
        return coerce_enum(ExecutionMode, value)

    @field_validator("fixture_roots", "required_policy_ids", "allowed_tools", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)


class SuiteCase(PersistedArtifact):
    artifact_kind: Literal["suite-case"] = "suite-case"
    case_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    expectation_id: str = Field(min_length=1)
    fixture_id: str | None = Field(default=None, min_length=1)
    tags: tuple[str, ...] = ()

    @field_validator("tags", mode="before")
    @classmethod
    def _coerce_tags(cls, value: object) -> object:
        return coerce_tuple(value)


class CompiledSuite(PersistedArtifact):
    artifact_kind: Literal["compiled-suite"] = "compiled-suite"
    suite_id: str = Field(min_length=1)
    suite_version: str = Field(min_length=1)
    defaults: SuiteDefaults = SuiteDefaults()
    cases: tuple[SuiteCase, ...]
    resolved_expectations: tuple[Expectation, ...]
    source_digest: DigestHex

    @field_validator("cases", "resolved_expectations", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _expectation_links_are_explicit(self) -> CompiledSuite:
        case_ids = [case.case_id for case in self.cases]
        duplicate_case_ids = _duplicates(case_ids)
        if duplicate_case_ids:
            raise ValueError(
                "cases must have unique case_id values: " + ", ".join(duplicate_case_ids)
            )
        expectation_by_id = {
            expectation.expectation_id: expectation for expectation in self.resolved_expectations
        }
        if len(expectation_by_id) != len(self.resolved_expectations):
            raise ValueError("resolved_expectations must have unique expectation_id values")
        expectation_case_ids = [expectation.case_id for expectation in self.resolved_expectations]
        duplicate_expectation_case_ids = _duplicates(expectation_case_ids)
        if duplicate_expectation_case_ids:
            raise ValueError(
                "resolved_expectations must have unique case_id values: "
                + ", ".join(duplicate_expectation_case_ids)
            )
        for case in self.cases:
            expectation = expectation_by_id.get(case.expectation_id)
            if expectation is None:
                raise ValueError(
                    f"case {case.case_id!r} references unknown expectation_id "
                    f"{case.expectation_id!r}"
                )
            if expectation.case_id != case.case_id:
                raise ValueError(
                    f"case {case.case_id!r} expectation_id {case.expectation_id!r} "
                    f"points to case_id {expectation.case_id!r}"
                )
        extra_expectations = sorted(set(expectation_case_ids) - set(case_ids))
        if extra_expectations:
            raise ValueError(
                "resolved_expectations contains case_id values not present in cases: "
                + ", ".join(extra_expectations)
            )
        return self


class FixtureManifestEntry(PersistedArtifact):
    artifact_kind: Literal["fixture-manifest-entry"] = "fixture-manifest-entry"
    path: str = Field(min_length=1)
    sha256: DigestHex
    size_bytes: int = Field(ge=0)


class FixtureManifest(PersistedArtifact):
    artifact_kind: Literal["fixture-manifest"] = "fixture-manifest"
    suite_id: str = Field(min_length=1)
    suite_version: str = Field(min_length=1)
    fixture_roots: tuple[str, ...]
    entries: tuple[FixtureManifestEntry, ...]

    @field_validator("fixture_roots", "entries", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)


def _duplicates(values: list[str]) -> list[str]:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for value in values:
        if value in seen:
            duplicates.add(value)
        seen.add(value)
    return sorted(duplicates)
