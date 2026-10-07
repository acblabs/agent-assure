from __future__ import annotations

from agent_assure.authoring.compiler import compile_suite
from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.fixtures.loader import compiled_suite_digest
from agent_assure.live.comparison import compare_live_reports
from agent_assure.live.statistics import evaluate_live_runset
from agent_assure.reporting.live import render_live_comparison_markdown
from agent_assure.schema.common import ExecutionMode
from agent_assure.schema.live import (
    LIVE_COMPARISON_SOURCE_LINKAGE_LIMITATION,
    LiveEvaluationReport,
)
from tests.unit.evaluation.test_live_statistics import (
    SUITE,
    RunSet,
    _protocol,
    _record,
)


def test_live_comparison_markdown_labels_operational_deltas_source_declarative() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(
        compiled,
        observations=1,
        clusters=1,
        repetitions=1,
        max_cost_per_observation_usd="5.000000",
    )
    protocol_digest = sha256_hexdigest(protocol)

    def evaluation(runset_id: str, *, latency_ms: int, cost: str) -> LiveEvaluationReport:
        return evaluate_live_runset(
            compiled,
            RunSet(
                artifact_kind="run-set",
                runset_id=runset_id,
                suite_id=compiled.suite_id,
                suite_version=compiled.suite_version,
                suite_digest=compiled_suite_digest(compiled),
                fixture_manifest_digest="4" * 64,
                execution_mode=ExecutionMode.live,
                protocol_id=protocol.protocol_id,
                protocol_digest=protocol_digest,
                runs=(
                    _record(
                        repetition_index=0,
                        linked=True,
                        latency_ms=latency_ms,
                        cost=cost,
                    ),
                ),
            ),
            protocol=protocol,
        )

    baseline = evaluation("markdown-baseline", latency_ms=100, cost="0.500000")
    candidate = evaluation("markdown-candidate", latency_ms=1500, cost="3.000000")
    report = compare_live_reports(baseline, candidate, protocol=protocol)

    markdown = render_live_comparison_markdown(report)

    source_linkage_literal = (
        "source-evaluation digests are external linkage; latency and cost absolutes "
        "remain source-declarative until both digests are resolved against trusted "
        "evaluation reports"
    )
    assert LIVE_COMPARISON_SOURCE_LINKAGE_LIMITATION == source_linkage_literal
    assert report.schema_version == "0.6.6"
    disclosure = f"{source_linkage_literal}."
    operational = markdown.split("## Operational Deltas", 1)[1].split(
        "## Randomization Tests",
        1,
    )[0]
    assert disclosure in operational
    assert operational.index(disclosure) < operational.index("p50 latency difference ms")
    assert f"Baseline evaluation digest: `{report.baseline_evaluation_digest}`" in operational
    assert f"Candidate evaluation digest: `{report.candidate_evaluation_digest}`" in operational
    assert "not_recorded" not in operational
    assert "p50 latency difference ms: `1400.000000`" in operational
    assert "total cost difference USD: `2.500000`" in operational

    card_shaped_digest = "cd18620ee20204105499754aa35d7ff45d9c37483cfb06df8ab3b461571d7993"
    collision_report = report.model_copy(
        update={
            "baseline_evaluation_digest": card_shaped_digest,
            "candidate_evaluation_digest": card_shaped_digest,
        }
    )
    collision_markdown = render_live_comparison_markdown(collision_report)

    assert f"Baseline evaluation digest: `{card_shaped_digest}`" in collision_markdown
    assert f"Candidate evaluation digest: `{card_shaped_digest}`" in collision_markdown
