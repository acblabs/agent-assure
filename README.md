# agent-assure

`agent-assure` is an early implementation of expectation-driven assurance and
change-control checks for deterministic AI agent governance pipelines.

The current implementation supports offline schema validation, YAML suite
compilation, canonical digest generation, privacy-preserving summaries,
deterministic fixture runs, expectation evaluation, and JSON/Markdown/Rich
reports across synthetic prior-authorization and minimal expense-approval
examples. It does not run live models, certify safety, validate clinical use,
prove regulatory compliance, or claim OpenTelemetry adoption.

## Five-minute flagship demo

Run these commands one at a time from the repository root. The final two
commands write reports and are expected to exit `1`; the GitHub Actions snippet
below shows how to assert those expected failures in `set -e` contexts.

```bash
pip install -e ".[dev]"
mkdir -p .tmp/showcase
agent-assure suite compile examples/prior_auth_synthetic/suite.yaml --out .tmp/showcase/prior-auth.compiled.json --manifest .tmp/showcase/prior-auth.fixtures.json
agent-assure suite run .tmp/showcase/prior-auth.compiled.json --variant examples/prior_auth_synthetic/variants/baseline.yaml --manifest .tmp/showcase/prior-auth.fixtures.json --out .tmp/showcase/prior-auth.baseline.json
agent-assure suite run .tmp/showcase/prior-auth.compiled.json --variant examples/prior_auth_synthetic/variants/candidate_evidence_normalization.yaml --manifest .tmp/showcase/prior-auth.fixtures.json --out .tmp/showcase/prior-auth.evidence-candidate.json
agent-assure evaluate .tmp/showcase/prior-auth.baseline.json --suite .tmp/showcase/prior-auth.compiled.json --out-dir .tmp/showcase/baseline-report
agent-assure evaluate .tmp/showcase/prior-auth.evidence-candidate.json --suite .tmp/showcase/prior-auth.compiled.json --out-dir .tmp/showcase/evidence-report
agent-assure compare .tmp/showcase/prior-auth.baseline.json .tmp/showcase/prior-auth.evidence-candidate.json --suite .tmp/showcase/prior-auth.compiled.json --out-dir .tmp/showcase/comparison-report
```

The baseline evaluation exits `0` and writes a `pass` summary with ten evaluated
cases and zero blocking findings. The candidate evaluation is expected to exit
`1`; its report contains one blocking finding for
`shared-source-multi-claim` with reason code
`MATERIAL_CLAIM_MISSING_EVIDENCE`.

The comparison command is also expected to exit `1`. It writes
`.tmp/showcase/comparison-report/comparison-report.md` with classification
`new_failure` and fixture-equivalence state `pass`. For the failing case, the
baseline and candidate both keep `recommendation=approve; outcome=approve`; the
material regression is the missing `claim-duration` evidence link. See
`docs/showcase.md` for the expected report fields, GitHub Actions snippet, and
artifact digest summary.

## Small generic example

The expense-approval example is a compact non-healthcare suite that uses the
same offline fixture and expectation method. It is a generic demonstration, not
a benchmark.

```bash
agent-assure suite compile examples/expense_approval_minimal/suite.yaml --out .tmp/expense.compiled.json --manifest .tmp/expense.fixtures.json
agent-assure suite run .tmp/expense.compiled.json --variant examples/expense_approval_minimal/variants/baseline.yaml --manifest .tmp/expense.fixtures.json --out .tmp/expense.baseline.json
agent-assure suite run .tmp/expense.compiled.json --variant examples/expense_approval_minimal/variants/candidate_provider_policy.yaml --manifest .tmp/expense.fixtures.json --out .tmp/expense.candidate.json
agent-assure evaluate .tmp/expense.baseline.json --suite .tmp/expense.compiled.json --out-dir .tmp/expense.baseline-report
```

## Current claim boundary

The project currently claims only deterministic, offline controls implemented in
this repository. Public claims are tracked in
`docs/claims_traceability_matrix.yaml`.

## GitHub Actions snippet

```yaml
name: agent-assure-showcase
on: [push, pull_request]
jobs:
  flagship:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install -e ".[dev]"
      - run: mkdir -p .tmp/showcase
      - run: agent-assure suite compile examples/prior_auth_synthetic/suite.yaml --out .tmp/showcase/prior-auth.compiled.json --manifest .tmp/showcase/prior-auth.fixtures.json
      - run: agent-assure suite run .tmp/showcase/prior-auth.compiled.json --variant examples/prior_auth_synthetic/variants/baseline.yaml --manifest .tmp/showcase/prior-auth.fixtures.json --out .tmp/showcase/prior-auth.baseline.json
      - run: agent-assure suite run .tmp/showcase/prior-auth.compiled.json --variant examples/prior_auth_synthetic/variants/candidate_evidence_normalization.yaml --manifest .tmp/showcase/prior-auth.fixtures.json --out .tmp/showcase/prior-auth.evidence-candidate.json
      - run: agent-assure evaluate .tmp/showcase/prior-auth.baseline.json --suite .tmp/showcase/prior-auth.compiled.json --out-dir .tmp/showcase/baseline-report
      - name: Evaluate evidence candidate
        run: |
          set +e
          agent-assure evaluate .tmp/showcase/prior-auth.evidence-candidate.json --suite .tmp/showcase/prior-auth.compiled.json --out-dir .tmp/showcase/evidence-report
          status=$?
          set -e
          if [ "$status" -ne 1 ]; then
            echo "expected exit 1, got $status"
            exit 1
          fi
          grep -q "MATERIAL_CLAIM_MISSING_EVIDENCE" .tmp/showcase/evidence-report/evaluation-report.md
      - name: Compare baseline to candidate
        run: |
          set +e
          agent-assure compare .tmp/showcase/prior-auth.baseline.json .tmp/showcase/prior-auth.evidence-candidate.json --suite .tmp/showcase/prior-auth.compiled.json --out-dir .tmp/showcase/comparison-report
          status=$?
          set -e
          if [ "$status" -ne 1 ]; then
            echo "expected exit 1, got $status"
            exit 1
          fi
          grep -q 'Classification: `new_failure`' .tmp/showcase/comparison-report/comparison-report.md
          grep -q 'Fixture-Equivalence Result' .tmp/showcase/comparison-report/comparison-report.md
          grep -q 'State: `pass`' .tmp/showcase/comparison-report/comparison-report.md
```

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
