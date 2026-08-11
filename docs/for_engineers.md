# For Engineers

## Install

```bash
pip install agent-assure
agent-assure --version
```

For repository development:

```bash
pip install -e ".[dev]"
make check
```

## Run flagship demo

```bash
agent-assure demo flagship --out .tmp/demo/flagship --clean
```

The command exits `0` only when the expected same-output process regression is
caught. Under the hood, the demo invokes the real CLI commands in subprocesses
and verifies their exit codes and artifacts.

## Run expense demo

The expense approval fixture is bundled for a compact non-healthcare example.
The one-command demo path focuses on the flagship fixture; the expense suite can
still be run directly:

```bash
agent-assure suite compile examples/expense_approval_minimal/suite.yaml --out .tmp/expense/expense.compiled.json --manifest .tmp/expense/expense.fixtures.json
agent-assure suite run .tmp/expense/expense.compiled.json --variant examples/expense_approval_minimal/variants/baseline.yaml --manifest .tmp/expense/expense.fixtures.json --out .tmp/expense/baseline.runset.json
agent-assure suite run .tmp/expense/expense.compiled.json --variant examples/expense_approval_minimal/variants/candidate_provider_policy.yaml --manifest .tmp/expense/expense.fixtures.json --out .tmp/expense/candidate.runset.json
agent-assure evaluate .tmp/expense/baseline.runset.json --suite .tmp/expense/expense.compiled.json --out-dir .tmp/expense/baseline-report
agent-assure evaluate .tmp/expense/candidate.runset.json --suite .tmp/expense/expense.compiled.json --out-dir .tmp/expense/candidate-report
```

The candidate evaluation is expected to exit nonzero after writing deterministic
provider, outcome, and human-review findings.

## Use CI gate

```bash
agent-assure ci CANDIDATE.runset.json --suite SUITE.compiled.json --baseline BASELINE.runset.json --out-dir .tmp/ci-report --report-mode full
```

The command exits nonzero when a blocking finding is observed. Demo wrappers may
turn an expected blocking finding into a successful demonstration, but the core
CI command remains strict.

## Read evidence packet

`evidence-packet.json` is the machine-readable review artifact. It contains the
evaluation summary, comparison summary when available, limitations, artifact
digests, and environment context.

## Render evidence diff

```bash
agent-assure diff render --baseline BASELINE.runset.json --candidate CANDIDATE.runset.json --comparison comparison-summary.json --packet evidence-packet.json --out evidence-diff.html
```

The output is a single local HTML file with inline CSS and escaped dynamic
content.

## Schemas

Schema changes are versioned. The released v0.6.2 snapshot is frozen under
`schemas/v0.6.2/`; earlier released snapshots remain available for replay.
`schemas/unreleased/` is only a non-gating exporter smoke-test target. Future
schema changes require a new versioned snapshot.

## Bundled examples

Installed wheels include deterministic examples under
`agent_assure.examples`. Runtime code loads them with `importlib.resources` so
demos work from editable installs, wheels, and arbitrary current directories.

## Public vs experimental API

The CLI, YAML authoring format, persisted versioned JSON artifacts, and
`AgentRunRecord` producer contract are the Release Candidate (`v0.6.2`) primary
surface. The package-level PyPI `Development Status :: 4 - Beta` classifier is
the closest standardized classifier to an RC; framework adapters, live
execution, streaming, and mutation contracts remain experimental or
development RFCs. Internal Python modules may change; use documented CLI
commands and schema exports for integration points.
