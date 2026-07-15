from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from agent_assure.adapters import (
    FrameworkObservation,
    FrameworkRunProjection,
    GoogleADKAdapter,
    build_run_record_from_observations,
)
from agent_assure.authoring.compiler import compile_suite
from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.evaluation.evaluator import EvaluationReport, evaluate_runset
from agent_assure.fixtures.loader import compiled_suite_digest
from agent_assure.schema.common import ExecutionMode
from agent_assure.schema.run import RunSet
from agent_assure.schema.usage import UsageSegment

ExampleVariant = Literal["baseline", "candidate_review_bypass"]
ExecutionPath = Literal["synthetic-adk-events"]

EXAMPLE_ROOT = Path(__file__).resolve().parent
SUITE_PATH = EXAMPLE_ROOT / "suite.yaml"
CASE_ID = "adk-benefit-001"
PROVIDER = "google-vertex-ai"
MODEL = "gemini-2.5-flash"
TOOL_NAME = "benefit_policy_lookup"
EVIDENCE_REF = "ref-benefit-policy-v9"
CLAIM_ID = "claim-benefit-evidence"
SOURCE_ID = "benefit-policy-v9"
BASELINE_REVIEW_ROUTE = "clinical_review"
CANDIDATE_REVIEW_ROUTE = "auto_approval"
BASELINE_DELEGATION_ROUTE = "root_to_policy_agent"
CANDIDATE_DELEGATION_ROUTE = "root_to_fast_path_agent"
ADK_COMPATIBILITY_TARGET = "2.4.0"
RAW_REQUEST = (
    "Member M-4477 asks for a benefit exception on authorization A-99123 with "
    "supporting plan document D-331."
)


@dataclass(frozen=True)
class VariantRun:
    runset: RunSet
    execution_path: ExecutionPath
    review_route: str
    delegation_route: str


@dataclass(frozen=True)
class OfflineExampleRun:
    summary: dict[str, object]
    baseline: RunSet
    candidate: RunSet


@dataclass(frozen=True)
class SyntheticADKEvent:
    author: str
    invocation_id: str
    id: str
    custom_metadata: Mapping[str, object] | None = None
    actions: Mapping[str, object] | None = None
    metadata: Mapping[str, object] | None = None
    timestamp: float | None = None
    content: Mapping[str, object] | None = None


def run_variant(variant: ExampleVariant) -> RunSet:
    return _run_variant(variant).runset


def _run_variant(variant: ExampleVariant) -> VariantRun:
    compiled = compile_suite(SUITE_PATH)
    fixture_manifest_digest = _fixture_manifest_digest()
    adapter = GoogleADKAdapter(framework_version=ADK_COMPATIBILITY_TARGET)
    run_id = _stable_id("run", variant, CASE_ID)
    observations, execution_path = _adk_observations(
        adapter,
        variant,
        run_id=run_id,
        case_id=CASE_ID,
    )
    record = build_run_record_from_observations(
        observations,
        projection=_projection(),
        run_id=run_id,
        case_id=CASE_ID,
        fixture_manifest_digest=fixture_manifest_digest,
        configuration_digest=_configuration_digest(variant),
        require_observed_human_review=True,
    )
    return VariantRun(
        runset=RunSet(
            artifact_kind="run-set",
            runset_id=_stable_id("runset", variant, CASE_ID),
            suite_id=compiled.suite_id,
            suite_version=compiled.suite_version,
            suite_digest=compiled_suite_digest(compiled),
            fixture_manifest_digest=fixture_manifest_digest,
            execution_mode=ExecutionMode.fixture,
            runs=(record,),
        ),
        execution_path=execution_path,
        review_route=_last_review_route(observations),
        delegation_route=_last_privacy_attribute(observations, "delegation_route") or "",
    )


def evaluate_variant(variant: ExampleVariant) -> EvaluationReport:
    compiled = compile_suite(SUITE_PATH)
    return evaluate_runset(compiled, run_variant(variant))


def run_offline_example() -> dict[str, object]:
    return _run_offline_example().summary


def _run_offline_example() -> OfflineExampleRun:
    compiled = compile_suite(SUITE_PATH)
    baseline_result = _run_variant("baseline")
    candidate_result = _run_variant("candidate_review_bypass")
    baseline = baseline_result.runset
    candidate = candidate_result.runset
    baseline_report = evaluate_runset(compiled, baseline)
    candidate_report = evaluate_runset(compiled, candidate)
    baseline_run = baseline.runs[0]
    candidate_run = candidate.runs[0]
    summary: dict[str, object] = {
        "example": "adk-process-assurance",
        "status": "success",
        "adk_execution": "synthetic-adk-events",
        "adk_compatibility_target": ADK_COMPATIBILITY_TARGET,
        "baseline_state": baseline_report.candidate_vs_expectations.state.value,
        "candidate_state": candidate_report.candidate_vs_expectations.state.value,
        "same_final_decision": (
            baseline_run.recommendation == candidate_run.recommendation
            and baseline_run.outcome == candidate_run.outcome
        ),
        "baseline_review_route": baseline_result.review_route,
        "candidate_review_route": candidate_result.review_route,
        "baseline_delegation_route": baseline_result.delegation_route,
        "candidate_delegation_route": candidate_result.delegation_route,
        "candidate_human_review_required": candidate_run.human_review_required,
        "candidate_reason_codes": [
            finding.reason_code.value
            for finding in candidate_report.candidate_vs_expectations.findings
        ],
        "candidate_evidence_refs": [ref.ref_id for ref in candidate_run.evidence_refs],
        "candidate_usage_total_tokens": (
            candidate_run.usage_summary.total_tokens
            if candidate_run.usage_summary is not None
            else None
        ),
    }
    return OfflineExampleRun(summary=summary, baseline=baseline, candidate=candidate)


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    out_dir = Path(args[0]) if args else None
    result = _run_offline_example()
    summary = result.summary
    if out_dir is not None:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "summary.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        _write_json(
            out_dir / "baseline.runset.json",
            result.baseline.model_dump(mode="json"),
        )
        _write_json(
            out_dir / "candidate.runset.json",
            result.candidate.model_dump(mode="json"),
        )
    print(json.dumps(summary, sort_keys=True))
    return 0


def _adk_observations(
    adapter: GoogleADKAdapter,
    variant: ExampleVariant,
    *,
    run_id: str,
    case_id: str,
) -> tuple[tuple[FrameworkObservation, ...], ExecutionPath]:
    events = _synthetic_adk_events(variant, case_id=case_id)
    return (
        adapter.observations_from_events(events, run_id=run_id, case_id=case_id),
        "synthetic-adk-events",
    )


def _synthetic_adk_events(
    variant: ExampleVariant,
    *,
    case_id: str,
) -> tuple[object, ...]:
    invocation_id = _stable_id("adk-invocation", variant, case_id)
    review_route = _review_route(variant)
    delegation_route = _delegation_route(variant)
    return (
        {
            "author": "root_agent",
            "invocation_id": invocation_id,
            "timestamp": 1700000000.0,
            "content": {"parts": [{"text": RAW_REQUEST}]},
            "custom_metadata": {
                "agent_assure": _metadata(
                    case_id=case_id,
                    sequence_number=1,
                    event_type="case_intake",
                    node_name="root_agent",
                    privacy_filtered_attributes={
                        "case_bucket": "benefit_exception",
                        "request_digest": sha256_hexdigest({"request": RAW_REQUEST}),
                    },
                )
            },
        },
        SyntheticADKEvent(
            author="policy_agent",
            invocation_id=invocation_id,
            id=_stable_id("adk-event-policy", variant, case_id),
            timestamp=1700000000.1,
            content={"parts": [{"function_call": {"args": "raw_args_not_persisted"}}]},
            custom_metadata={
                "agent_assure": _metadata(
                    case_id=case_id,
                    sequence_number=2,
                    event_type="delegation",
                    node_name="policy_agent",
                    tool_name=TOOL_NAME,
                    evidence_refs=(EVIDENCE_REF,),
                    privacy_filtered_attributes={
                        "delegation_route": delegation_route,
                        "policy_version": "benefit-policy-v9",
                    },
                )
            },
        ),
        SyntheticADKEvent(
            author="review_agent",
            invocation_id=invocation_id,
            id=_stable_id("adk-event-review", variant, case_id),
            timestamp=1700000000.2,
            actions={
                "state_delta": {
                    "agent_assure": _metadata(
                        case_id=case_id,
                        sequence_number=3,
                        event_type="review_route",
                        node_name="review_agent",
                        review_route=review_route,
                        privacy_filtered_attributes={
                            "human_review_required": (
                                _observed_human_review_required(variant)
                            ),
                            "human_review_performed": (
                                _observed_human_review_performed(variant)
                            ),
                        },
                    )
                }
            },
        ),
        SyntheticADKEvent(
            author="decision_agent",
            invocation_id=invocation_id,
            id=_stable_id("adk-event-decision", variant, case_id),
            timestamp=1700000000.3,
            custom_metadata={
                "agent_assure": _metadata(
                    case_id=case_id,
                    sequence_number=4,
                    event_type="decision",
                    node_name="decision_agent",
                    provider=PROVIDER,
                    model=MODEL,
                    review_route=review_route,
                    privacy_filtered_attributes={
                        "recommendation": "approve",
                        "outcome": "approved_with_review",
                    },
                    usage_segment=_decision_usage_segment(variant),
                )
            },
        ),
    )


def _metadata(
    *,
    case_id: str,
    sequence_number: int,
    event_type: str,
    node_name: str,
    provider: str | None = None,
    model: str | None = None,
    tool_name: str | None = None,
    review_route: str | None = None,
    evidence_refs: tuple[str, ...] = (),
    privacy_filtered_attributes: Mapping[str, str] | None = None,
    usage_segment: Mapping[str, object] | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "case_id": case_id,
        "event_type": event_type,
        "node_name": node_name,
        "sequence_number": sequence_number,
        "redaction_state": "redacted",
        "privacy_filtered_attributes": dict(privacy_filtered_attributes or {}),
    }
    if provider is not None:
        payload["provider"] = provider
    if model is not None:
        payload["model"] = model
    if tool_name is not None:
        payload["tool_name"] = tool_name
    if review_route is not None:
        payload["review_route"] = review_route
    if evidence_refs:
        payload["evidence_refs"] = evidence_refs
    if usage_segment is not None:
        payload["usage_segment"] = usage_segment
    return payload


def _decision_usage_segment(variant: ExampleVariant) -> dict[str, object]:
    if variant == "baseline":
        prompt_tokens = 13
        completion_tokens = 9
        total_tokens = 22
        latency_ms = 31
    else:
        prompt_tokens = 10
        completion_tokens = 7
        total_tokens = 17
        latency_ms = 21
    return UsageSegment(
        segment_id=f"usage-{variant}-{CASE_ID}",
        provider=PROVIDER,
        model=MODEL,
        operation="decision",
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        total_tokens=total_tokens,
        tool_call_count=1,
        retry_count=0,
        latency_ms=latency_ms,
    ).model_dump(mode="json")


def _projection() -> FrameworkRunProjection:
    return FrameworkRunProjection(
        pipeline_id="adk-process-assurance",
        recommendation="approve",
        outcome="approved_with_review",
        provider=PROVIDER,
        model=MODEL,
        evidence_claim_map={EVIDENCE_REF: (CLAIM_ID,)},
        evidence_source_map={EVIDENCE_REF: SOURCE_ID},
        human_review_required=True,
        human_review_performed=True,
        adapter_id=GoogleADKAdapter.adapter_id,
    )


def _fixture_manifest_digest() -> str:
    return sha256_hexdigest(
        {
            "case_id": CASE_ID,
            "example": "adk-process-assurance",
            "request_digest": sha256_hexdigest({"request": RAW_REQUEST}),
        }
    )


def _configuration_digest(variant: ExampleVariant) -> str:
    return sha256_hexdigest(
        {
            "adapter": GoogleADKAdapter.adapter_id,
            "example": "adk-process-assurance",
            "variant": variant,
        }
    )


def _stable_id(prefix: str, variant: ExampleVariant, case_id: str) -> str:
    digest = sha256_hexdigest(
        {
            "case_id": case_id,
            "example": "adk-process-assurance",
            "prefix": prefix,
            "variant": variant,
        }
    )
    return f"{prefix}-{digest[:16]}"


def _review_route(variant: ExampleVariant) -> str:
    if variant == "baseline":
        return BASELINE_REVIEW_ROUTE
    return CANDIDATE_REVIEW_ROUTE


def _delegation_route(variant: ExampleVariant) -> str:
    if variant == "baseline":
        return BASELINE_DELEGATION_ROUTE
    return CANDIDATE_DELEGATION_ROUTE


def _observed_human_review_required(variant: ExampleVariant) -> str:
    if variant == "baseline":
        return "true"
    return "false"


def _observed_human_review_performed(variant: ExampleVariant) -> str:
    if variant == "baseline":
        return "true"
    return "false"


def _last_review_route(observations: tuple[FrameworkObservation, ...]) -> str:
    for observation in reversed(observations):
        if observation.review_route is not None:
            return observation.review_route
    return ""


def _last_privacy_attribute(
    observations: tuple[FrameworkObservation, ...],
    key: str,
) -> str | None:
    for observation in reversed(observations):
        value = observation.privacy_filtered_attributes.get(key)
        if value:
            return value
    return None


def _write_json(path: Path, payload: object) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


if __name__ == "__main__":
    raise SystemExit(main())
