# Expense Demo

The expense approval example is a compact non-healthcare fixture suite. It uses
the same suite compilation, fixture run, evaluation, and report-writing path as
the flagship demo.

The one-command wrapper is focused on the flagship fixture. The expense fixture
remains bundled and runnable directly:

```bash
agent-assure suite compile examples/expense_approval_minimal/suite.yaml --out .tmp/expense/expense.compiled.json --manifest .tmp/expense/expense.fixtures.json
agent-assure suite run .tmp/expense/expense.compiled.json --variant examples/expense_approval_minimal/variants/baseline.yaml --manifest .tmp/expense/expense.fixtures.json --out .tmp/expense/baseline.runset.json
agent-assure suite run .tmp/expense/expense.compiled.json --variant examples/expense_approval_minimal/variants/candidate_provider_policy.yaml --manifest .tmp/expense/expense.fixtures.json --out .tmp/expense/candidate.runset.json
agent-assure evaluate .tmp/expense/baseline.runset.json --suite .tmp/expense/expense.compiled.json --out-dir .tmp/expense/baseline-report
agent-assure evaluate .tmp/expense/candidate.runset.json --suite .tmp/expense/expense.compiled.json --out-dir .tmp/expense/candidate-report
```

The candidate provider-policy variant is expected to produce deterministic
process findings. Use it as a small fixture when the healthcare-shaped flagship
example is not the right first read for a reviewer.
