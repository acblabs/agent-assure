from __future__ import annotations

from decimal import Decimal

from agent_assure.reporting.markdown_safety import markdown_code_span, markdown_text
from agent_assure.schema.usage import UsageSummary


def prefixed_usage_summary_lines(
    prefix: str,
    summary: UsageSummary | None,
) -> list[str]:
    return [
        line.replace("- ", f"- {prefix} ", 1)
        for line in usage_summary_lines(summary)
    ]


def usage_summary_lines(summary: UsageSummary | None) -> list[str]:
    if summary is None:
        return ["- measured usage: `not_observed`"]
    lines = [
        f"- total tokens: `{observed_int(summary.total_tokens)}`",
        f"- tool calls: `{observed_int(summary.total_tool_calls)}`",
        f"- retries: `{observed_int(summary.total_retries)}`",
        f"- latency ms: `{observed_int(summary.total_latency_ms)}`",
        _estimated_cost_line(summary),
    ]
    if (
        summary.estimated_cost_microusd is not None
        and summary.cost_observation_count is not None
    ):
        cost_per_observation_value = cost_per_observation(
            summary.estimated_cost_microusd,
            summary.cost_observation_count,
        )
        lines.append(
            "- declared estimated cost per cost observation: "
            f"`{cost_per_observation_value}` micro-USD"
        )
    if summary.cost_basis_ids:
        lines.append(
            "- cost basis: "
            + ", ".join(markdown_code_span(cost_basis) for cost_basis in summary.cost_basis_ids)
        )
    if summary.pricing_snapshot_ids:
        lines.append(
            "- pricing snapshots: "
            + ", ".join(
                markdown_code_span(snapshot_id) for snapshot_id in summary.pricing_snapshot_ids
            )
        )
    if summary.pricing_snapshot_digests:
        lines.append(
            "- pricing snapshot digests: "
            + ", ".join(f"`{digest}`" for digest in summary.pricing_snapshot_digests)
        )
    lines.extend(f"- limitation: {markdown_text(limitation)}" for limitation in summary.limitations)
    return lines


def observed_int(value: int | None) -> str:
    if value is None:
        return "not_observed"
    return str(value)


def cost_per_observation(estimated_cost_microusd: int, observations: int) -> str:
    if observations <= 0:
        return "not_observed"
    value = Decimal(estimated_cost_microusd) / Decimal(observations)
    return f"{value:.6f}".rstrip("0").rstrip(".")


def _estimated_cost_line(summary: UsageSummary) -> str:
    if summary.estimated_cost_microusd is None:
        return "- declared estimated cost: `not_observed`"
    return f"- declared estimated cost: `{summary.estimated_cost_microusd}` micro-USD"
