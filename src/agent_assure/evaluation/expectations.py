from __future__ import annotations

from dataclasses import dataclass

from agent_assure.schema.expectation import Expectation
from agent_assure.schema.suite import CompiledSuite, SuiteCase


@dataclass(frozen=True)
class CaseExpectation:
    case: SuiteCase
    expectation: Expectation


class ExpectationResolver:
    def __init__(self, suite: CompiledSuite) -> None:
        self._case_by_id = {case.case_id: case for case in suite.cases}
        self._expectation_by_case = {
            expectation.case_id: expectation for expectation in suite.resolved_expectations
        }
        if len(self._case_by_id) != len(suite.cases):
            raise ValueError("compiled suite contains duplicate case_id values")
        if len(self._expectation_by_case) != len(suite.resolved_expectations):
            raise ValueError("compiled suite contains duplicate expectation case_id values")
        missing = sorted(set(self._case_by_id) - set(self._expectation_by_case))
        if missing:
            raise ValueError(f"compiled suite missing expectations for cases: {', '.join(missing)}")

    def cases(self) -> tuple[CaseExpectation, ...]:
        return tuple(
            CaseExpectation(case=case, expectation=self._expectation_by_case[case.case_id])
            for case in self._case_by_id.values()
        )

    def for_case(self, case_id: str) -> CaseExpectation:
        try:
            case = self._case_by_id[case_id]
            expectation = self._expectation_by_case[case_id]
        except KeyError as exc:
            raise KeyError(f"unknown suite case_id {case_id!r}") from exc
        return CaseExpectation(case=case, expectation=expectation)

    @property
    def case_ids(self) -> tuple[str, ...]:
        return tuple(self._case_by_id)
