# CLI Contract

Current commands:

- `agent-assure --help`
- `agent-assure validate PATH --kind KIND`
- `agent-assure schema export --out DIR`
- `agent-assure suite lint PATH`
- `agent-assure suite compile PATH --out PATH [--manifest PATH]`
- `agent-assure suite run COMPILED_SUITE_JSON --variant VARIANT_YAML --out RUNSET_JSON [--manifest PATH] [--suite-digest DIGEST] [--source SUITE_YAML]`
- `agent-assure evaluate RUNSET_JSON --suite COMPILED_SUITE_JSON --out-dir REPORT_DIR [--waiver WAIVER_JSON_OR_YAML] [--fail-on-warn] [--fail-on-not-evaluated]`
- `agent-assure compare BASELINE_RUNSET CANDIDATE_RUNSET --suite COMPILED_SUITE_JSON --out-dir REPORT_DIR [--waiver WAIVER_JSON_OR_YAML] [--fail-on-warn] [--fail-on-not-evaluated]`
- `agent-assure packet build EVALUATION_SUMMARY_JSON --out EVIDENCE_PACKET_JSON [--comparison COMPARISON_SUMMARY_JSON] [--packet-id ID]`
- `agent-assure ci CANDIDATE_RUNSET --suite COMPILED_SUITE_JSON --out-dir REPORT_DIR [--baseline BASELINE_RUNSET] [--report-mode full|fail-fast] [--waiver WAIVER_JSON_OR_YAML] [--fail-on-warn] [--fail-on-not-evaluated]`
- `agent-assure ci gate SUMMARY_OR_PACKET_JSON [--fail-on-warn] [--fail-on-not-evaluated]`
- `agent-assure release replay RELEASE_DIGEST_REPLAY_JSON [--artifact-root DIR] [--require-role ROLE] [--expect-commit COMMIT] [--require-current-commit/--no-require-current-commit] [--require-core/--no-require-core]`
- `agent-assure otel preview PATH [--out PATH]`

`evaluate` writes `evaluation-report.json`, `evaluation-summary.json`,
`evaluation-report.md`, `dependency-inventory.json`, and
`release-artifact-manifest.json`, and prints a Rich console summary. The JSON
report and summary embed local environment metadata. The Markdown and console
report sections lead with candidate vs expectations. Unsupported live or
certification-style capabilities are reported as `not_evaluated`; they do not
fail the default gate profile.
`--fail-on-warn` makes warning controls blocking; `--fail-on-not-evaluated`
makes unsupported capabilities blocking.

Evaluation metrics distinguish case-level results from global gate failures.
`evaluated_cases` counts suite cases with exactly one run record.
`unevaluated_cases` counts missing or duplicate case records. `failed_cases`
counts blocking findings only among evaluated cases, so `passed_cases`,
`failed_cases`, and `unevaluated_cases` partition `total_cases`. Global
failures, such as expired waivers or blocked `not_evaluated` capabilities, are
reported separately as `global_blocking_findings`.

Waivers bind to a run-set digest, reason code, and exact `finding_id`; expired
waivers fail closed.

`compare` writes `comparison-report.json`, `comparison-summary.json`,
`comparison-report.md`, `dependency-inventory.json`, and
`release-artifact-manifest.json`, and prints a Rich console summary. The JSON
report and summary embed local environment metadata. The Markdown and console
report sections lead with the candidate's expectation verdict, then explain why
it passed or failed, then show fixture equivalence, baseline context, control
changes, provenance changes, not-evaluated capabilities, and limitations.
Provenance-only differences are reported for review but do not create regression
verdicts. Fixture-equivalence failure is an invalid comparison and exits `2`.

`packet build` writes an `evidence-packet` JSON artifact, `evidence-packet.md`,
`dependency-inventory.json`, and `release-artifact-manifest.json` from an
evaluation summary and optional comparison summary. The packet records SHA-256
file digests for the summary artifacts it encloses, local environment metadata,
lockfile digest when a supported lockfile is present, dependency-inventory
digest, and an interpretation block. These exact-file digests are
environment-bound reproducibility anchors, not signatures or attestations; they
are separate from the cross-platform-stable JCS content digests used for suites,
fixture manifests, and runset provenance.

`ci` evaluates a candidate RunSet, optionally compares it with a baseline, writes
reports, builds a packet, writes a dependency inventory and release manifest,
then gates the result. `--report-mode full` writes all deterministic findings.
`--report-mode fail-fast` emits only the first blocking candidate finding and
stops before comparison; it consumes an already-created deterministic RunSet and
does not short-circuit fixture execution. The report metrics continue to reflect
the evaluated RunSet, while the findings list is intentionally truncated. On
nonzero exit it writes `ci-diagnostics.json` with exit code, reason code,
artifact path, validator, and report paths, and prints the same decision as
structured JSON. `ci gate` remains available for post-hoc gating of an existing
`evaluation-summary`, `comparison-summary`, or `evidence-packet`.

`release replay` validates a `release-digest-replay` artifact under
`--artifact-root`. It recomputes raw SHA-256 file digests for replay-stable
source artifacts and stable JSON projection digests for environment-bearing
review artifacts. By default it requires the compiled-suite, fixture-manifest,
evidence-packet, and release-artifact-manifest roles. `--require-current-commit`
requires the current git checkout to match the replay file's `source_commit`;
`--expect-commit` checks an explicit commit value. Digest mismatches, missing
release artifacts, commit mismatches, or unavailable git commit metadata when
commit checking is requested exit `1`; malformed replay artifacts exit `2`
through Typer validation. Keyless cosign signature verification remains an
external `cosign verify-blob` operation documented in `docs/release_evidence.md`.

Exit-code mapping:

- `0`: command succeeded with no blocking gate failure.
- `1`: evaluation, policy, invariant, or configured gate failed.
- `2`: invalid user input, schema validation failure, invalid comparison, or
  fixture-equivalence failure.
- `3`: tooling, IO, unexpected runtime, or internal error.

Default roll-up precedence for comparison exits is `invalid_comparison`, then
`fail`, then `warn`, then `not_evaluated`, then `pass`.
`not_evaluated` capabilities remain separate unless the selected gate profile
makes them blocking. Warnings exit `0` unless `--fail-on-warn` is selected.
