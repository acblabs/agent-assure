# Expense Approval Minimal Example

This compact non-healthcare example uses the same offline fixture and
expectation flow as the larger synthetic suite. It is intentionally small and is
not a benchmark.

```bash
agent-assure suite compile examples/expense_approval_minimal/suite.yaml --out .tmp/expense.compiled.json --manifest .tmp/expense.fixtures.json
agent-assure suite run .tmp/expense.compiled.json --variant examples/expense_approval_minimal/variants/baseline.yaml --manifest .tmp/expense.fixtures.json --out .tmp/expense.baseline.json
agent-assure suite run .tmp/expense.compiled.json --variant examples/expense_approval_minimal/variants/candidate_provider_policy.yaml --manifest .tmp/expense.fixtures.json --out .tmp/expense.candidate.json
```

The baseline uses the configured provider policy to route `exp-003` to manual
review. The candidate uses the same request, model-output, and tool-output
fixtures but lets runtime provider defaults take precedence, so `exp-003`
returns `approve_without_review`.
