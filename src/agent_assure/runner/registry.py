from __future__ import annotations

import re
from collections.abc import Callable
from threading import RLock
from typing import TYPE_CHECKING

from agent_assure.schema.run import AgentRunRecord

if TYPE_CHECKING:
    from agent_assure.runner.fixture_runner import LoadedFixtures, RunnerContext, VariantConfig
    from agent_assure.schema.suite import SuiteCase

RunnerCallable = Callable[
    ["SuiteCase", "LoadedFixtures", "VariantConfig", "RunnerContext"],
    AgentRunRecord,
]

_RUNNER_REGISTRY: dict[str, RunnerCallable] = {}
_BUILTINS_REGISTERED = False
_REGISTRY_LOCK = RLock()
_RUNNER_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def register_runner(runner_id: str, runner: RunnerCallable) -> None:
    if _RUNNER_ID.fullmatch(runner_id) is None:
        raise ValueError("runner_id must be a bounded machine identifier")
    if not callable(runner):
        raise TypeError("runner must be callable")
    with _REGISTRY_LOCK:
        existing = _RUNNER_REGISTRY.get(runner_id)
        if existing is not None and existing is not runner:
            raise ValueError(f"runner_id {runner_id!r} is already registered")
        _RUNNER_REGISTRY[runner_id] = runner


def get_runner(runner_id: str) -> RunnerCallable:
    register_builtin_runners()
    with _REGISTRY_LOCK:
        try:
            return _RUNNER_REGISTRY[runner_id]
        except KeyError as exc:
            known = ", ".join(sorted(_RUNNER_REGISTRY)) or "<none>"
            raise KeyError(
                f"unknown runner_id {runner_id!r}; registered runners: {known}"
            ) from exc


def registered_runner_ids() -> tuple[str, ...]:
    register_builtin_runners()
    with _REGISTRY_LOCK:
        return tuple(sorted(_RUNNER_REGISTRY))


def register_builtin_runners() -> None:
    global _BUILTINS_REGISTERED
    with _REGISTRY_LOCK:
        if _BUILTINS_REGISTERED:
            return
        from agent_assure.examples.expense_approval_minimal.runner import run_expense_case
        from agent_assure.examples.prior_auth_synthetic.runner import (
            run_prior_auth_case,
            run_prior_auth_case_evidence_refactor,
            run_prior_auth_case_rag,
        )
        from agent_assure.examples.process_measurement_cases.runner import (
            run_process_measurement_case,
        )

        register_runner("expense_approval.minimal", run_expense_case)
        register_runner("prior_auth.synthetic", run_prior_auth_case)
        register_runner(
            "prior_auth.synthetic_evidence_refactor",
            run_prior_auth_case_evidence_refactor,
        )
        register_runner("prior_auth.synthetic_rag", run_prior_auth_case_rag)
        register_runner("process_measurement.synthetic", run_process_measurement_case)
        _BUILTINS_REGISTERED = True
