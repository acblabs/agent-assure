from __future__ import annotations

from rich.console import Console
from rich.table import Table

from agent_assure.evaluation.evaluator import EvaluationReport
from agent_assure.schema.common import GateState


def render_evaluation_console(report: EvaluationReport, console: Console | None = None) -> None:
    console = console or Console()
    summary = report.candidate_vs_expectations
    console.print(_candidate_table(report))
    if summary.state is not GateState.pass_:
        console.print(_findings_table(report))
    console.print(_capability_table(report))


def _candidate_table(report: EvaluationReport) -> Table:
    summary = report.candidate_vs_expectations
    table = Table(title="Candidate vs Expectations")
    table.add_column("RunSet")
    table.add_column("Suite")
    table.add_column("State")
    table.add_column("Blocking")
    table.add_column("Global")
    table.add_row(
        report.runset_id,
        f"{report.suite_id}@{report.suite_version}",
        summary.state.value,
        str(report.metrics.blocking_findings),
        str(report.metrics.global_blocking_findings),
    )
    return table


def _findings_table(report: EvaluationReport) -> Table:
    table = Table(title="Why the Candidate Passed or Failed")
    table.add_column("Case")
    table.add_column("Control")
    table.add_column("Target")
    table.add_column("Reason")
    table.add_column("State")
    table.add_column("Message")
    for finding in report.candidate_vs_expectations.findings:
        table.add_row(
            finding.case_id,
            finding.control_id,
            finding.target,
            finding.reason_code.value,
            finding.state.value,
            finding.message,
        )
    return table


def _capability_table(report: EvaluationReport) -> Table:
    table = Table(title="Not-Evaluated Capabilities")
    table.add_column("Capability")
    table.add_column("State")
    table.add_column("Reason")
    for capability in report.not_evaluated_capabilities:
        table.add_row(capability.capability_id, capability.state.value, capability.reason)
    return table
