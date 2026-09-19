from __future__ import annotations

from typing import Literal, Self

from pydantic import Field, field_validator, model_validator

from agent_assure.schema.base import FrozenStrictModel
from agent_assure.schema.common import DigestHex, MachineIdentifier, coerce_tuple
from agent_assure.schema.mutation import SelfDigestedArtifact

PROCESS_EQUIVALENCE_BENCHMARK_SCHEMA_VERSION: Literal["0.6.6"] = "0.6.6"
PROCESS_EQUIVALENCE_BENCHMARK_CONTRACT_VERSION: Literal["1.0.0"] = "1.0.0"
PROCESS_EQUIVALENCE_BENCHMARK_VERSION: Literal["0.2.0"] = "0.2.0"
MAX_PROCESS_EQUIVALENCE_BENCHMARK_CASES = 10_000
PROCESS_EQUIVALENCE_BENCHMARK_V0_2_SHARED_TEMPLATE_GRID_DIGEST = (
    "9f734a3910933d92e5993e3e6f54ca23756146848d78e17317480f48ab54bb54"
)
PROCESS_EQUIVALENCE_BENCHMARK_V0_2_SHARED_TEMPLATE_GRID_STRUCTURE_DIGEST = (
    "90fbcc92ebdf38f89b43295d1a65d79e86a2607271a527542a6fcacff7be058c"
)
_CONFIRMATORY_INELIGIBLE_BENCHMARK_DIGESTS = frozenset(
    {PROCESS_EQUIVALENCE_BENCHMARK_V0_2_SHARED_TEMPLATE_GRID_DIGEST}
)
_CONFIRMATORY_INELIGIBLE_BENCHMARK_STRUCTURE_DIGESTS = frozenset(
    {PROCESS_EQUIVALENCE_BENCHMARK_V0_2_SHARED_TEMPLATE_GRID_STRUCTURE_DIGEST}
)


class ProcessEquivalenceBenchmarkCase(FrozenStrictModel):
    """Privacy-safe identity and digest binding for one benchmark input.

    The descriptor intentionally has no free-text or result-bearing surface. The
    referenced source and input can be resolved only by an execution environment
    that already possesses the separately governed material.
    """

    task_id: MachineIdentifier
    authority_contract_id: MachineIdentifier
    query_family_id: MachineIdentifier
    case_id: MachineIdentifier
    expected_relation: Literal["decision_flip", "decision_invariant"]
    baseline_expected_decision: Literal["approve", "deny"]
    counterfactual_expected_decision: Literal["approve", "deny"]
    source_digest: DigestHex
    input_digest: DigestHex

    @model_validator(mode="after")
    def _validate_expected_relation(self) -> Self:
        decisions_match = self.baseline_expected_decision == self.counterfactual_expected_decision
        if decisions_match != (self.expected_relation == "decision_invariant"):
            raise ValueError("benchmark expected relation contradicts its directional decisions")
        return self

    @property
    def canonical_key(self) -> tuple[str, str, str, str]:
        return (
            self.case_id,
            self.task_id,
            self.authority_contract_id,
            self.query_family_id,
        )


class ProcessEquivalenceBenchmarkManifest(SelfDigestedArtifact):
    """Digest-bound Process-Equivalence Benchmark v0.2 input manifest.

    This artifact catalogs inputs that may be used for real-model measurement;
    it neither records execution nor carries empirical result claims.
    """

    _digest_field = "benchmark_digest"

    artifact_kind: Literal["process-equivalence-benchmark"] = "process-equivalence-benchmark"
    schema_version: Literal["0.6.6"] = PROCESS_EQUIVALENCE_BENCHMARK_SCHEMA_VERSION
    schema_name: Literal["process-equivalence-benchmark"] = "process-equivalence-benchmark"
    contract_id: Literal["ProcessEquivalenceBenchmark/v1"] = "ProcessEquivalenceBenchmark/v1"
    contract_version: Literal["1.0.0"] = PROCESS_EQUIVALENCE_BENCHMARK_CONTRACT_VERSION
    benchmark_digest: DigestHex
    benchmark_id: MachineIdentifier
    benchmark_version: Literal["0.2.0"] = PROCESS_EQUIVALENCE_BENCHMARK_VERSION
    data_classification: Literal["non_sensitive"] = "non_sensitive"
    content_representation: Literal["identity_and_digest_bindings_only"] = (
        "identity_and_digest_bindings_only"
    )
    real_model_measurement_compatible: Literal[True] = True
    cases: tuple[ProcessEquivalenceBenchmarkCase, ...] = Field(
        min_length=1,
        max_length=MAX_PROCESS_EQUIVALENCE_BENCHMARK_CASES,
    )

    @field_validator("cases", mode="before")
    @classmethod
    def _coerce_cases(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_case_catalog(self) -> Self:
        keys = tuple(case.canonical_key for case in self.cases)
        if keys != tuple(sorted(keys)):
            raise ValueError("benchmark cases must use canonical identity ordering")
        if len(set(keys)) != len(keys):
            raise ValueError("benchmark cases must be unique")
        case_ids = tuple(case.case_id for case in self.cases)
        if len(set(case_ids)) != len(case_ids):
            raise ValueError("benchmark case IDs must be globally unique")
        input_digests = tuple(case.input_digest for case in self.cases)
        if len(set(input_digests)) != len(input_digests):
            raise ValueError(
                "benchmark input digests must be globally unique; exact duplicate "
                "inputs are not independent cases"
            )
        directional_paths = {
            (case.baseline_expected_decision, case.counterfactual_expected_decision)
            for case in self.cases
            if case.expected_relation == "decision_flip"
        }
        if not {("approve", "deny"), ("deny", "approve")}.issubset(directional_paths):
            raise ValueError("benchmark must cover both directional decision-flip paths")
        invariant_paths = {
            (case.baseline_expected_decision, case.counterfactual_expected_decision)
            for case in self.cases
            if case.expected_relation == "decision_invariant"
        }
        if not {("approve", "approve"), ("deny", "deny")}.issubset(invariant_paths):
            raise ValueError(
                "benchmark must cover both directional decision-invariant control paths"
            )
        return self


# The short name is convenient for consumers that treat the manifest as the
# released benchmark artifact. Keep one implementation and therefore one digest
# contract behind both public spellings.
ProcessEquivalenceBenchmark = ProcessEquivalenceBenchmarkManifest
ProcessEquivalenceBenchmarkCaseDescriptor = ProcessEquivalenceBenchmarkCase


def calculate_benchmark_confirmatory_structure_digest(
    benchmark: ProcessEquivalenceBenchmarkManifest,
) -> str:
    """Digest the semantic case frame while excluding all relabelable metadata."""

    from agent_assure.canonical.digests import sha256_hexdigest

    cases = tuple(
        sorted(
            (
                {
                    "expected_relation": case.expected_relation,
                    "baseline_expected_decision": case.baseline_expected_decision,
                    "counterfactual_expected_decision": case.counterfactual_expected_decision,
                    "source_digest": case.source_digest,
                    "input_digest": case.input_digest,
                }
                for case in benchmark.cases
            ),
            key=lambda case: (
                case["source_digest"],
                case["input_digest"],
                case["expected_relation"],
                case["baseline_expected_decision"],
                case["counterfactual_expected_decision"],
            ),
        )
    )
    return sha256_hexdigest(
        {
            "purpose": "process-equivalence-benchmark-confirmatory-case-frame/v1",
            "cases": cases,
        }
    )


def registered_confirmatory_benchmark_bar_reason(
    benchmark: ProcessEquivalenceBenchmarkManifest,
) -> str | None:
    """Return a registered structural bar to independent-cluster inference.

    Absence of a registered bar is not evidence that cases are independent.
    The manifest's design justification, exact audit artifact, and qualified
    review remain separate requirements.
    """

    if (
        benchmark.benchmark_digest in _CONFIRMATORY_INELIGIBLE_BENCHMARK_DIGESTS
        or calculate_benchmark_confirmatory_structure_digest(benchmark)
        in _CONFIRMATORY_INELIGIBLE_BENCHMARK_STRUCTURE_DIGESTS
    ):
        return "known_shared_template_parameter_grid"
    return None


def benchmark_has_registered_confirmatory_bar(
    benchmark: ProcessEquivalenceBenchmarkManifest,
) -> bool:
    """Return whether a defense-in-depth benchmark-level bar is registered.

    A false result is deliberately not an eligibility decision. Confirmatory
    eligibility requires an exact positive statistical-method approval; this
    registry only prevents already-known bad frames from being relabelled.
    """

    return registered_confirmatory_benchmark_bar_reason(benchmark) is not None


__all__ = [
    "MAX_PROCESS_EQUIVALENCE_BENCHMARK_CASES",
    "PROCESS_EQUIVALENCE_BENCHMARK_CONTRACT_VERSION",
    "PROCESS_EQUIVALENCE_BENCHMARK_SCHEMA_VERSION",
    "PROCESS_EQUIVALENCE_BENCHMARK_V0_2_SHARED_TEMPLATE_GRID_DIGEST",
    "PROCESS_EQUIVALENCE_BENCHMARK_V0_2_SHARED_TEMPLATE_GRID_STRUCTURE_DIGEST",
    "PROCESS_EQUIVALENCE_BENCHMARK_VERSION",
    "ProcessEquivalenceBenchmark",
    "ProcessEquivalenceBenchmarkCase",
    "ProcessEquivalenceBenchmarkCaseDescriptor",
    "ProcessEquivalenceBenchmarkManifest",
    "benchmark_has_registered_confirmatory_bar",
    "calculate_benchmark_confirmatory_structure_digest",
    "registered_confirmatory_benchmark_bar_reason",
]
