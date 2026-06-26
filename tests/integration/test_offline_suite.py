from __future__ import annotations

from agent_assure.authoring.compiler import compile_suite


def test_prior_auth_suite_compiles_offline() -> None:
    compiled = compile_suite(__import__("pathlib").Path("examples/prior_auth_synthetic/suite.yaml"))
    assert compiled.suite_id == "prior-auth-synthetic"
    assert len(compiled.resolved_expectations) == 2
