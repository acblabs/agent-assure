# agent-assure

`agent-assure` is an early implementation of expectation-driven assurance and
change-control checks for deterministic AI agent governance pipelines.

The current implementation supports offline schema validation, YAML suite
compilation, canonical digest generation, privacy-preserving summaries, and an
offline deterministic fixture runner with fixture manifests across synthetic
prior-authorization and minimal expense-approval examples. It does not run live
models, certify safety, validate clinical use, prove regulatory compliance, or
claim OpenTelemetry adoption.

## Five-minute local check

```bash
pip install -e ".[dev]"
agent-assure --help
agent-assure schema export --out schemas/v0.1.0
agent-assure suite lint examples/prior_auth_synthetic/suite.yaml
agent-assure suite compile examples/prior_auth_synthetic/suite.yaml --out .tmp/compiled-suite.json --manifest .tmp/fixture-manifest.json
agent-assure validate .tmp/compiled-suite.json --kind compiled-suite
agent-assure validate .tmp/fixture-manifest.json --kind fixture-manifest
agent-assure suite run .tmp/compiled-suite.json --variant examples/prior_auth_synthetic/variants/baseline.yaml --manifest .tmp/fixture-manifest.json --out .tmp/baseline-runset.json
agent-assure validate .tmp/baseline-runset.json --kind run-set
agent-assure otel preview tests/fixtures/run_record.json --out .tmp/span-plan.json
pytest
```

## Small generic example

The expense-approval example is a compact non-healthcare suite that uses the
same offline fixture and expectation method. It is a generic demonstration, not
a benchmark.

```bash
agent-assure suite compile examples/expense_approval_minimal/suite.yaml --out .tmp/expense.compiled.json --manifest .tmp/expense.fixtures.json
agent-assure suite run .tmp/expense.compiled.json --variant examples/expense_approval_minimal/variants/baseline.yaml --manifest .tmp/expense.fixtures.json --out .tmp/expense.baseline.json
agent-assure suite run .tmp/expense.compiled.json --variant examples/expense_approval_minimal/variants/candidate_provider_policy.yaml --manifest .tmp/expense.fixtures.json --out .tmp/expense.candidate.json
```

## Current claim boundary

The project currently claims only deterministic, offline controls implemented in
this repository. Public claims are tracked in
`docs/claims_traceability_matrix.yaml`.

## Development

```bash
git config core.hooksPath .githooks
python scripts/check_docs_alignment.py
ruff check .
mypy src
pytest
python -m build
```

Dependency locking for release builds is documented in
`docs/dependency_locking.md`.

The installed package includes bundled deterministic examples for reproducible
local demos. They are not a stable extension API; see `docs/api_surface.md`.
