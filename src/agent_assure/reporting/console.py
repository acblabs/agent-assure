from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich.text import Text

from agent_assure.compare.runsets import ComparisonReport
from agent_assure.evaluation.evaluator import EvaluationReport
from agent_assure.reporting.text_safety import sanitize_display_text
from agent_assure.schema.common import GateState


def _console_text(value: object) -> Text:
    """Return redacted literal text with terminal control characters removed."""
    return Text(sanitize_display_text(value))


def render_evaluation_console(report: EvaluationReport, console: Console | None = None) -> None:
    console = console or Console()
    summary = report.candidate_vs_expectations
    console.print(_candidate_table(report))
    if summary.state is not GateState.pass_:
        console.print(_findings_table(report))
    if report.waiver_dispositions:
        console.print(_waiver_table(report))
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
        _console_text(report.runset_id),
        _console_text(f"{report.suite_id}@{report.suite_version}"),
        _console_text(summary.state.value),
        _console_text(report.metrics.blocking_findings),
        _console_text(report.metrics.global_blocking_findings),
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
            _console_text(finding.case_id),
            _console_text(finding.control_id),
            _console_text(finding.target),
            _console_text(finding.reason_code.value),
            _console_text(finding.state.value),
            _console_text(finding.message),
        )
    return table


def _capability_table(report: EvaluationReport) -> Table:
    table = Table(title="Not-Evaluated Capabilities")
    table.add_column("Capability")
    table.add_column("State")
    table.add_column("Reason")
    for capability in report.not_evaluated_capabilities:
        table.add_row(
            _console_text(capability.capability_id),
            _console_text(capability.state.value),
            _console_text(capability.reason),
        )
    return table


def _waiver_table(report: EvaluationReport) -> Table:
    table = Table(title="Waiver Dispositions")
    table.add_column("Waiver")
    table.add_column("Status")
    table.add_column("Finding")
    table.add_column("Reason")
    table.add_column("Expires")
    for disposition in report.waiver_dispositions:
        table.add_row(
            _console_text(disposition.waiver_id),
            _console_text(disposition.status.value),
            _console_text(disposition.finding_id),
            _console_text(disposition.reason_code.value),
            _console_text(disposition.expires_on.isoformat()),
        )
    return table


def render_comparison_console(report: ComparisonReport, console: Console | None = None) -> None:
    console = console or Console()
    console.print(_comparison_candidate_table(report))
    if report.candidate_vs_expectations.state is not GateState.pass_:
        console.print(_comparison_findings_table(report))
    console.print(_fixture_table(report))
    console.print(_comparison_changes_table(report))


def _comparison_candidate_table(report: ComparisonReport) -> Table:
    summary = report.comparison_summary
    table = Table(title="Candidate vs Expectations")
    table.add_column("Candidate")
    table.add_column("Baseline")
    table.add_column("Suite")
    table.add_column("Candidate State")
    table.add_column("Classification")
    table.add_row(
        _console_text(summary.candidate_runset_id),
        _console_text(summary.baseline_runset_id),
        _console_text(f"{report.suite_id}@{report.suite_version}"),
        _console_text(report.candidate_vs_expectations.state.value),
        _console_text(summary.classification.value),
    )
    return table


def _comparison_findings_table(report: ComparisonReport) -> Table:
    table = Table(title="Why the Candidate Passed or Failed")
    table.add_column("Explanation")
    for line in report.verdict_explanations:
        table.add_row(_console_text(line))
    return table


def _fixture_table(report: ComparisonReport) -> Table:
    table = Table(title="Fixture-Equivalence Result")
    table.add_column("State")
    table.add_column("Compared Digests")
    table.add_column("Findings")
    table.add_row(
        _console_text(report.fixture_equivalence.state.value),
        _console_text(len(report.fixture_equivalence.compared_digests)),
        _console_text(len(report.fixture_equivalence.findings)),
    )
    return table


def _comparison_changes_table(report: ComparisonReport) -> Table:
    table = Table(title="Baseline-to-Candidate Control Changes")
    table.add_column("Classification")
    table.add_column("Case")
    table.add_column("Control")
    table.add_column("Reason")
    if report.control_changes:
        for change in report.control_changes:
            table.add_row(
                _console_text(change.classification.value),
                _console_text(change.case_id),
                _console_text(change.control_id),
                _console_text(change.reason_code.value),
            )
    else:
        table.add_row(
            _console_text(report.comparison_summary.classification.value),
            _console_text("-"),
            _console_text("-"),
            _console_text("no verdict-bearing changes"),
        )
    return table
