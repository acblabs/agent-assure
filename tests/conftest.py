from __future__ import annotations

from typing import Any

import pytest

_SKIPPED_NODE_IDS: set[str] = set()


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--fail-on-skip",
        action="store_true",
        default=False,
        help="Return a failing exit status if any selected test is skipped.",
    )


def pytest_configure(config: pytest.Config) -> None:
    del config
    _SKIPPED_NODE_IDS.clear()


def pytest_runtest_logreport(report: Any) -> None:
    if report.skipped:
        _SKIPPED_NODE_IDS.add(str(report.nodeid))


def pytest_collectreport(report: Any) -> None:
    if report.skipped:
        _SKIPPED_NODE_IDS.add(str(report.nodeid))


@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    del exitstatus
    if session.config.getoption("--fail-on-skip") and _SKIPPED_NODE_IDS:
        reporter = session.config.pluginmanager.get_plugin("terminalreporter")
        if reporter is not None:
            reporter.write_sep(
                "=",
                "fail-on-skip: " + ", ".join(sorted(_SKIPPED_NODE_IDS)),
            )
        session.exitstatus = pytest.ExitCode.TESTS_FAILED
