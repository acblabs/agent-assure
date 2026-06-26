# CLI Contract

Current commands:

- `agent-assure --help`
- `agent-assure validate PATH --kind KIND`
- `agent-assure schema export --out DIR`
- `agent-assure suite lint PATH`
- `agent-assure suite compile PATH --out PATH [--manifest PATH]`
- `agent-assure suite run COMPILED_SUITE_JSON --variant VARIANT_YAML --out RUNSET_JSON [--manifest PATH] [--suite-digest DIGEST] [--source SUITE_YAML]`
- `agent-assure evaluate RUNSET_JSON --suite COMPILED_SUITE_JSON --out-dir REPORT_DIR [--waiver WAIVER_JSON_OR_YAML] [--fail-on-warn]`
- `agent-assure otel preview PATH [--out PATH]`

`evaluate` writes `evaluation-report.json`, `evaluation-summary.json`, and
`evaluation-report.md`, and prints a Rich console summary. Reports lead with
candidate vs expectations. Unsupported live or certification-style capabilities
are reported as `not_evaluated`; they do not fail the default gate profile.
`--fail-on-warn` makes warning controls blocking; gate profiles may also treat
`not_evaluated` capabilities as blocking.

Evaluation metrics distinguish case-level results from global gate failures.
`evaluated_cases` counts suite cases with exactly one run record.
`unevaluated_cases` counts missing or duplicate case records. `failed_cases`
counts blocking findings only among evaluated cases, so `passed_cases`,
`failed_cases`, and `unevaluated_cases` partition `total_cases`. Global
failures, such as expired waivers or blocked `not_evaluated` capabilities, are
reported separately as `global_blocking_findings`.

Waivers bind to a run-set digest, reason code, and exact `finding_id`; expired
waivers fail closed.

Comparison, CI gating, and packet generation command groups exist as
placeholders and do not claim completed behavior.

Exit-code mapping:

- `0`: command succeeded with no blocking gate failure.
- `1`: evaluation, policy, invariant, or configured gate failed.
- `2`: invalid user input or schema validation failure.
- `3`: tooling, IO, unexpected runtime, or internal error.

Default roll-up precedence for evaluated controls is `fail`, then `warn`, then
`pass`. `not_evaluated` capabilities remain separate unless the selected gate
profile makes them blocking. Warnings exit `0` unless `--fail-on-warn` is
selected.
