from __future__ import annotations

from agent_assure.compare.case_map import unique_case_map
from agent_assure.schema.base import StrictModel
from agent_assure.schema.run import RunSet

PROVENANCE_FIELDS = (
    "prompt_digest",
    "code_digest",
    "policy_bundle_digest",
    "configuration_digest",
    "tool_schema_digest",
    "model_identifier",
    "fixture_manifest_digest",
    "retrieval_corpus_digest",
)


class ProvenanceChange(StrictModel):
    case_id: str
    field: str
    baseline_value: str | None = None
    candidate_value: str | None = None


def diff_provenance(baseline: RunSet, candidate: RunSet) -> tuple[ProvenanceChange, ...]:
    baseline_runs = unique_case_map(baseline)
    candidate_runs = unique_case_map(candidate)
    changes: list[ProvenanceChange] = []
    for case_id in sorted(set(baseline_runs) & set(candidate_runs)):
        baseline_run = baseline_runs[case_id]
        candidate_run = candidate_runs[case_id]
        for field in PROVENANCE_FIELDS:
            baseline_value = getattr(baseline_run.provenance, field)
            candidate_value = getattr(candidate_run.provenance, field)
            if baseline_value != candidate_value:
                changes.append(
                    ProvenanceChange(
                        case_id=case_id,
                        field=field,
                        baseline_value=baseline_value,
                        candidate_value=candidate_value,
                    )
                )
    return tuple(changes)


def summarize_provenance_change(change: ProvenanceChange) -> str:
    return (
        f"{change.case_id}:{change.field}: "
        f"{change.baseline_value or '<unset>'} -> {change.candidate_value or '<unset>'}"
    )
