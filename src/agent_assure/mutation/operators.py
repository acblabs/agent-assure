from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

from agent_assure.schema.expectation import Expectation
from agent_assure.schema.run import AgentRunRecord, RunSet
from agent_assure.schema.suite import CompiledSuite


@dataclass(frozen=True)
class PayloadChange:
    """One replacement at an exact RFC 6901 JSON Pointer."""

    path: str
    value: object


@dataclass(frozen=True)
class MutationTarget:
    """A deterministic, schema-owned mutation candidate."""

    identity: str
    expected_finding_target: str
    changes: tuple[PayloadChange, ...]


def drop_material_evidence_link_targets(
    suite: CompiledSuite,
    subject: RunSet,
    source_payload: Mapping[str, object],
) -> tuple[MutationTarget, ...]:
    expectations = {item.case_id: item for item in suite.resolved_expectations}
    raw_runs = _raw_runs(source_payload)
    targets: list[MutationTarget] = []
    for run_index, run in _evaluable_runs(subject):
        expectation = expectations.get(run.case_id)
        if expectation is None or not expectation.material_claim_ids:
            continue
        present_items = {item.ref_id for item in run.evidence_items}
        linked_claims = {
            link.claim_id
            for link in run.claim_evidence_links
            if link.evidence_ref_id in present_items
        }
        raw_run = _raw_run(raw_runs, run_index)
        raw_links = _raw_sequence(raw_run, "claim_evidence_links")
        for claim_id in sorted(set(expectation.material_claim_ids) & linked_claims):
            remaining = [
                item
                for item in raw_links
                if not (isinstance(item, Mapping) and item.get("claim_id") == claim_id)
            ]
            targets.append(
                MutationTarget(
                    identity=f"{run.case_id}\0{run.run_id}\0{claim_id}",
                    expected_finding_target=f"claim:{claim_id}",
                    changes=(
                        PayloadChange(
                            path=f"/runs/{run_index}/claim_evidence_links",
                            value=remaining,
                        ),
                    ),
                )
            )
    return tuple(sorted(targets, key=lambda item: item.identity))


def bypass_required_human_review_targets(
    suite: CompiledSuite,
    subject: RunSet,
    source_payload: Mapping[str, object],
) -> tuple[MutationTarget, ...]:
    expectations = {item.case_id: item for item in suite.resolved_expectations}
    targets: list[MutationTarget] = []
    for run_index, run in _evaluable_runs(subject):
        expectation = expectations.get(run.case_id)
        if (
            expectation is None
            or not expectation.required_human_review
            or not run.human_review_required
            or not run.human_review_performed
        ):
            continue
        targets.extend(
            (
                MutationTarget(
                    identity=f"{run.case_id}\0{run.run_id}\0routing",
                    expected_finding_target="human_review_required",
                    changes=(
                        PayloadChange(
                            path=f"/runs/{run_index}/human_review_required",
                            value=False,
                        ),
                    ),
                ),
                MutationTarget(
                    identity=f"{run.case_id}\0{run.run_id}\0completion",
                    expected_finding_target="human_review_performed",
                    changes=(
                        PayloadChange(
                            path=f"/runs/{run_index}/human_review_performed",
                            value=False,
                        ),
                    ),
                ),
            )
        )
    return tuple(sorted(targets, key=lambda item: item.identity))


def inject_forbidden_tool_targets(
    suite: CompiledSuite,
    subject: RunSet,
    source_payload: Mapping[str, object],
) -> tuple[MutationTarget, ...]:
    expectations = {item.case_id: item for item in suite.resolved_expectations}
    raw_runs = _raw_runs(source_payload)
    targets: list[MutationTarget] = []
    for run_index, run in _evaluable_runs(subject):
        expectation = expectations.get(run.case_id)
        if expectation is None:
            continue
        effective_allowed = _effective_allowed_tools(suite, expectation)
        existing_tools = set(run.tools)
        forbidden_candidates = sorted(set(expectation.forbidden_tools) - existing_tools)
        if forbidden_candidates:
            targets.append(
                _tool_injection_target(
                    run_index,
                    run,
                    raw_runs,
                    forbidden_candidates[0],
                    branch="explicit",
                )
            )
        if effective_allowed is None:
            continue
        synthetic_tool = _synthetic_forbidden_tool(
            existing_tools | set(effective_allowed) | set(expectation.forbidden_tools)
        )
        targets.append(
            _tool_injection_target(
                run_index,
                run,
                raw_runs,
                synthetic_tool,
                branch="allowlist",
            )
        )
    return tuple(sorted(targets, key=lambda item: item.identity))


def _effective_allowed_tools(
    suite: CompiledSuite,
    expectation: Expectation,
) -> tuple[str, ...] | None:
    if expectation.allowed_tools_override:
        return expectation.allowed_tools
    if expectation.allowed_tools:
        return expectation.allowed_tools
    if suite.defaults.allowed_tools:
        return suite.defaults.allowed_tools
    return None


def _evaluable_runs(subject: RunSet) -> tuple[tuple[int, AgentRunRecord], ...]:
    """Return only records the evaluator can treat as one case observation."""
    case_counts = Counter(run.case_id for run in subject.runs)
    return tuple(
        (run_index, run)
        for run_index, run in enumerate(subject.runs)
        if run.observation_status == "included" and case_counts[run.case_id] == 1
    )


def _synthetic_forbidden_tool(disallowed: set[str]) -> str:
    base = "agent-assure.synthetic-forbidden-tool"
    if base not in disallowed:
        return base
    suffix = 1
    while f"{base}-{suffix}" in disallowed:
        suffix += 1
    return f"{base}-{suffix}"


def _tool_injection_target(
    run_index: int,
    run: AgentRunRecord,
    raw_runs: list[object],
    tool: str,
    *,
    branch: str,
) -> MutationTarget:
    raw_run = _raw_run(raw_runs, run_index)
    raw_tools = list(_raw_sequence(raw_run, "tools"))
    raw_tools.append(tool)
    return MutationTarget(
        identity=f"{run.case_id}\0{run.run_id}\0{branch}\0{tool}",
        expected_finding_target=f"tool:{tool}",
        changes=(
            PayloadChange(
                path=f"/runs/{run_index}/tools",
                value=raw_tools,
            ),
        ),
    )


def _raw_runs(source_payload: Mapping[str, object]) -> list[object]:
    runs = source_payload.get("runs")
    if not isinstance(runs, list):
        raise ValueError("validated run set payload must contain a runs array")
    return runs


def _raw_run(raw_runs: list[object], run_index: int) -> Mapping[str, object]:
    try:
        run = raw_runs[run_index]
    except IndexError as exc:
        raise ValueError("typed and raw run-set ordering differ") from exc
    if not isinstance(run, Mapping):
        raise ValueError("validated run set payload must contain run objects")
    return cast(Mapping[str, object], run)


def _raw_sequence(raw_run: Mapping[str, object], field_name: str) -> list[object]:
    value = raw_run.get(field_name, [])
    if not isinstance(value, list):
        raise ValueError(f"validated run field {field_name!r} must be an array")
    return value
