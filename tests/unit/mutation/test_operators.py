from __future__ import annotations

from collections.abc import Callable, Mapping
from copy import deepcopy
from typing import cast

import pytest

from agent_assure.mutation.operators import (
    MutationTarget,
    bypass_required_human_review_targets,
    drop_material_evidence_link_targets,
    inject_forbidden_tool_targets,
)
from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.schema.expectation import Expectation
from agent_assure.schema.run import (
    AgentRunRecord,
    ClaimEvidenceLink,
    EvidenceItem,
    RunSet,
)
from agent_assure.schema.suite import CompiledSuite, SuiteCase, SuiteDefaults

TargetBuilder = Callable[
    [CompiledSuite, RunSet, Mapping[str, object]],
    tuple[MutationTarget, ...],
]


def test_drop_material_evidence_link_plans_exact_replacement_without_mutation() -> None:
    expectation = _expectation(
        "evidence-case",
        material_claim_ids=("claim-selected",),
    )
    suite = _suite((expectation,))
    subject = _runset(
        (
            _run(
                "evidence-case",
                evidence_items=(
                    _evidence_item("ref-selected-a"),
                    _evidence_item("ref-other"),
                    _evidence_item("ref-selected-b"),
                ),
                claim_evidence_links=(
                    _link("claim-selected", "ref-selected-a"),
                    _link("claim-other", "ref-other"),
                    _link("claim-selected", "ref-selected-b"),
                    _link("claim-selected", "ref-not-present"),
                    _link("claim-other-unbacked", "ref-not-present"),
                ),
            ),
        )
    )
    source_payload = _source_payload(subject)

    targets = _plan_without_mutation(
        drop_material_evidence_link_targets,
        suite,
        subject,
        source_payload,
    )

    assert len(targets) == 1
    target = targets[0]
    assert target.identity == "evidence-case\0run-evidence-case\0claim-selected"
    assert target.expected_finding_target == "claim:claim-selected"
    assert len(target.changes) == 1
    assert target.changes[0].path == "/runs/0/claim_evidence_links"

    raw_links = _raw_run_sequence(source_payload, 0, "claim_evidence_links")
    expected_remaining = [raw_links[1], raw_links[4]]
    assert target.changes[0].value == expected_remaining
    assert all(
        not isinstance(link, Mapping) or link.get("claim_id") != "claim-selected"
        for link in cast(list[object], target.changes[0].value)
    )


def test_drop_material_evidence_link_is_inapplicable_without_backed_link() -> None:
    expectation = _expectation(
        "unlinked-evidence-case",
        material_claim_ids=("claim-selected",),
    )
    suite = _suite((expectation,))
    subject = _runset(
        (
            _run(
                "unlinked-evidence-case",
                claim_evidence_links=(_link("claim-selected", "ref-not-present"),),
            ),
        )
    )
    source_payload = _source_payload(subject)

    assert (
        _plan_without_mutation(
            drop_material_evidence_link_targets,
            suite,
            subject,
            source_payload,
        )
        == ()
    )


def test_bypass_required_review_isolates_routing_and_completion_without_mutation() -> None:
    expectation = _expectation("review-case", required_human_review=True)
    suite = _suite((expectation,))
    subject = _runset(
        (
            _run(
                "review-case",
                human_review_required=True,
                human_review_performed=True,
            ),
        )
    )
    source_payload = _source_payload(subject)

    targets = _plan_without_mutation(
        bypass_required_human_review_targets,
        suite,
        subject,
        source_payload,
    )

    assert tuple(target.identity for target in targets) == (
        "review-case\0run-review-case\0completion",
        "review-case\0run-review-case\0routing",
    )
    assert tuple(target.expected_finding_target for target in targets) == (
        "human_review_performed",
        "human_review_required",
    )
    assert tuple(
        tuple((change.path, change.value) for change in target.changes) for target in targets
    ) == (
        (("/runs/0/human_review_performed", False),),
        (("/runs/0/human_review_required", False),),
    )


def test_bypass_required_review_is_inapplicable_after_review_was_bypassed() -> None:
    expectation = _expectation("already-bypassed", required_human_review=True)
    suite = _suite((expectation,))
    subject = _runset(
        (
            _run(
                "already-bypassed",
                human_review_required=False,
                human_review_performed=False,
            ),
        )
    )
    source_payload = _source_payload(subject)

    assert (
        _plan_without_mutation(
            bypass_required_human_review_targets,
            suite,
            subject,
            source_payload,
        )
        == ()
    )


def test_inject_forbidden_tool_isolates_explicit_and_allowlist_branches() -> None:
    expectation = _expectation(
        "declared-tool-case",
        forbidden_tools=("z-forbidden-tool", "a-forbidden-tool"),
    )
    suite = _suite((expectation,), allowed_tools=("safe-tool",))
    subject = _runset((_run("declared-tool-case", tools=("safe-tool",)),))
    source_payload = _source_payload(subject)

    targets = _plan_without_mutation(
        inject_forbidden_tool_targets,
        suite,
        subject,
        source_payload,
    )

    assert tuple(target.identity for target in targets) == (
        (
            "declared-tool-case\0run-declared-tool-case\0allowlist\0"
            "agent-assure.synthetic-forbidden-tool"
        ),
        "declared-tool-case\0run-declared-tool-case\0explicit\0a-forbidden-tool",
    )
    assert tuple(target.expected_finding_target for target in targets) == (
        "tool:agent-assure.synthetic-forbidden-tool",
        "tool:a-forbidden-tool",
    )
    assert tuple(
        tuple((change.path, change.value) for change in target.changes) for target in targets
    ) == (
        (
            (
                "/runs/0/tools",
                ["safe-tool", "agent-assure.synthetic-forbidden-tool"],
            ),
        ),
        (("/runs/0/tools", ["safe-tool", "a-forbidden-tool"]),),
    )


def test_inject_forbidden_tool_uses_synthetic_sentinel_for_allowlist() -> None:
    expectation = _expectation("allowlist-tool-case")
    suite = _suite((expectation,), allowed_tools=("safe-tool",))
    subject = _runset((_run("allowlist-tool-case", tools=("safe-tool",)),))
    source_payload = _source_payload(subject)

    targets = _plan_without_mutation(
        inject_forbidden_tool_targets,
        suite,
        subject,
        source_payload,
    )

    assert len(targets) == 1
    target = targets[0]
    assert target.identity == (
        "allowlist-tool-case\0run-allowlist-tool-case\0allowlist\0"
        "agent-assure.synthetic-forbidden-tool"
    )
    assert target.expected_finding_target == "tool:agent-assure.synthetic-forbidden-tool"
    assert tuple((change.path, change.value) for change in target.changes) == (
        (
            "/runs/0/tools",
            ["safe-tool", "agent-assure.synthetic-forbidden-tool"],
        ),
    )


def test_inject_forbidden_tool_is_inapplicable_without_tool_boundary() -> None:
    expectation = _expectation("unrestricted-tool-case")
    suite = _suite((expectation,))
    subject = _runset((_run("unrestricted-tool-case", tools=("ordinary-tool",)),))
    source_payload = _source_payload(subject)

    assert (
        _plan_without_mutation(
            inject_forbidden_tool_targets,
            suite,
            subject,
            source_payload,
        )
        == ()
    )


@pytest.mark.parametrize(
    ("builder", "expected_identities", "expected_paths"),
    (
        (
            drop_material_evidence_link_targets,
            (
                "a-case\0run-a-case\0claim-a",
                "z-case\0run-z-case\0claim-z",
            ),
            (
                "/runs/1/claim_evidence_links",
                "/runs/0/claim_evidence_links",
            ),
        ),
        (
            bypass_required_human_review_targets,
            (
                "a-case\0run-a-case\0completion",
                "a-case\0run-a-case\0routing",
                "z-case\0run-z-case\0completion",
                "z-case\0run-z-case\0routing",
            ),
            (
                "/runs/1/human_review_performed",
                "/runs/1/human_review_required",
                "/runs/0/human_review_performed",
                "/runs/0/human_review_required",
            ),
        ),
        (
            inject_forbidden_tool_targets,
            (
                "a-case\0run-a-case\0explicit\0a-forbidden-tool",
                "z-case\0run-z-case\0explicit\0z-forbidden-tool",
            ),
            (
                "/runs/1/tools",
                "/runs/0/tools",
            ),
        ),
    ),
)
def test_operator_target_order_is_deterministic(
    builder: TargetBuilder,
    expected_identities: tuple[str, ...],
    expected_paths: tuple[str, ...],
) -> None:
    expectations = (
        _expectation(
            "z-case",
            material_claim_ids=("claim-z",),
            required_human_review=True,
            forbidden_tools=("z-forbidden-tool",),
        ),
        _expectation(
            "a-case",
            material_claim_ids=("claim-a",),
            required_human_review=True,
            forbidden_tools=("a-forbidden-tool",),
        ),
    )
    suite = _suite(expectations)
    subject = _runset(
        (
            _fully_applicable_run("z-case", "claim-z", "ref-z"),
            _fully_applicable_run("a-case", "claim-a", "ref-a"),
        )
    )
    source_payload = _source_payload(subject)

    first = builder(suite, subject, source_payload)
    second = builder(suite, subject, deepcopy(source_payload))

    assert first == second
    assert tuple(target.identity for target in first) == expected_identities
    assert tuple(target.changes[0].path for target in first) == expected_paths


@pytest.mark.parametrize(
    "builder",
    (
        drop_material_evidence_link_targets,
        bypass_required_human_review_targets,
        inject_forbidden_tool_targets,
    ),
)
def test_operators_ignore_excluded_and_non_singleton_observations(
    builder: TargetBuilder,
) -> None:
    expectation = _expectation(
        "case-a",
        material_claim_ids=("claim-a",),
        required_human_review=True,
        forbidden_tools=("forbidden-tool",),
    )
    suite = _suite((expectation,), allowed_tools=("safe-tool",))
    base = _fully_applicable_run("case-a", "claim-a", "ref-a")
    excluded = base.model_copy(
        update={
            "run_id": "run-excluded",
            "observation_status": "excluded",
            "exclusion_reason": "synthetic exclusion",
        }
    )
    duplicate_a = base.model_copy(update={"run_id": "run-duplicate-a"})
    duplicate_b = base.model_copy(update={"run_id": "run-duplicate-b"})

    excluded_subject = _runset((excluded,))
    duplicate_subject = _runset((duplicate_a, duplicate_b))

    assert builder(suite, excluded_subject, _source_payload(excluded_subject)) == ()
    assert builder(suite, duplicate_subject, _source_payload(duplicate_subject)) == ()


def _plan_without_mutation(
    builder: TargetBuilder,
    suite: CompiledSuite,
    subject: RunSet,
    source_payload: dict[str, object],
) -> tuple[MutationTarget, ...]:
    raw_before = deepcopy(source_payload)
    typed_before = subject.model_dump(mode="json")

    targets = builder(suite, subject, source_payload)

    assert source_payload == raw_before
    assert subject.model_dump(mode="json") == typed_before
    return targets


def _expectation(case_id: str, **updates: object) -> Expectation:
    payload: dict[str, object] = {
        "expectation_id": f"expectation-{case_id}",
        "case_id": case_id,
    }
    payload.update(updates)
    return Expectation.model_validate(payload)


def _suite(
    expectations: tuple[Expectation, ...],
    *,
    allowed_tools: tuple[str, ...] = (),
) -> CompiledSuite:
    return CompiledSuite(
        suite_id="mutation-operator-test-suite",
        suite_version="1.0.0",
        defaults=SuiteDefaults(
            runner_id="mutation.operator.tests",
            allowed_tools=allowed_tools,
        ),
        cases=tuple(
            SuiteCase(
                case_id=expectation.case_id,
                title=f"Mutation test case {expectation.case_id}",
                expectation_id=expectation.expectation_id,
            )
            for expectation in expectations
        ),
        resolved_expectations=expectations,
        source_digest="a" * 64,
    )


def _runset(runs: tuple[AgentRunRecord, ...]) -> RunSet:
    return RunSet(
        runset_id="mutation-operator-test-runset",
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        suite_id="mutation-operator-test-suite",
        suite_version="1.0.0",
        suite_digest="b" * 64,
        fixture_manifest_digest="c" * 64,
        runs=runs,
    )


def _run(
    case_id: str,
    *,
    evidence_items: tuple[EvidenceItem, ...] = (),
    claim_evidence_links: tuple[ClaimEvidenceLink, ...] = (),
    tools: tuple[str, ...] = (),
    human_review_required: bool = False,
    human_review_performed: bool = False,
) -> AgentRunRecord:
    return AgentRunRecord(
        run_id=f"run-{case_id}",
        case_id=case_id,
        pipeline_id="mutation-operator-test-pipeline",
        recommendation="approve",
        outcome="approved",
        input_summary="synthetic input",
        output_summary="synthetic output",
        evidence_items=evidence_items,
        claim_evidence_links=claim_evidence_links,
        tools=tools,
        human_review_required=human_review_required,
        human_review_performed=human_review_performed,
    )


def _fully_applicable_run(
    case_id: str,
    claim_id: str,
    ref_id: str,
) -> AgentRunRecord:
    return _run(
        case_id,
        evidence_items=(_evidence_item(ref_id),),
        claim_evidence_links=(_link(claim_id, ref_id),),
        human_review_required=True,
        human_review_performed=True,
    )


def _evidence_item(ref_id: str) -> EvidenceItem:
    return EvidenceItem(
        ref_id=ref_id,
        source_id=f"source-{ref_id}",
        content_digest="d" * 64,
    )


def _link(claim_id: str, ref_id: str) -> ClaimEvidenceLink:
    return ClaimEvidenceLink(claim_id=claim_id, evidence_ref_id=ref_id)


def _source_payload(subject: RunSet) -> dict[str, object]:
    return cast(dict[str, object], subject.model_dump(mode="json"))


def _raw_run_sequence(
    source_payload: dict[str, object],
    run_index: int,
    field_name: str,
) -> list[object]:
    raw_runs = cast(list[dict[str, object]], source_payload["runs"])
    return cast(list[object], raw_runs[run_index][field_name])
