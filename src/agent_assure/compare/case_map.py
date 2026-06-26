from __future__ import annotations

from collections import Counter

from agent_assure.schema.run import AgentRunRecord, RunSet


def case_counts(runset: RunSet) -> Counter[str]:
    return Counter(run.case_id for run in runset.runs)


def unique_case_map(runset: RunSet) -> dict[str, AgentRunRecord]:
    """Return the first run for each case_id in deterministic RunSet order.

    Comparison checks use case_counts separately to fail duplicate case records
    before interpreting this first-wins map.
    """
    runs: dict[str, AgentRunRecord] = {}
    for run in runset.runs:
        runs.setdefault(run.case_id, run)
    return runs
