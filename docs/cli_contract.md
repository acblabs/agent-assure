# CLI Contract

Current commands:

- `agent-assure --help`
- `agent-assure validate PATH --kind KIND`
- `agent-assure schema export --out DIR`
- `agent-assure suite lint PATH`
- `agent-assure suite compile PATH --out PATH [--manifest PATH]`
- `agent-assure suite run COMPILED_SUITE_JSON --variant VARIANT_YAML --out RUNSET_JSON [--manifest PATH] [--suite-digest DIGEST] [--source SUITE_YAML] [--hmac-key-env ENV]`
- `agent-assure evaluate RUNSET_JSON --suite COMPILED_SUITE_JSON --out-dir REPORT_DIR [--waiver WAIVER_JSON_OR_YAML] [--fail-on-warn] [--fail-on-not-evaluated]`
- `agent-assure compare BASELINE_RUNSET CANDIDATE_RUNSET --suite COMPILED_SUITE_JSON --out-dir REPORT_DIR [--waiver WAIVER_JSON_OR_YAML] [--fail-on-warn] [--fail-on-not-evaluated]`
- `agent-assure packet build EVALUATION_SUMMARY_JSON --out EVIDENCE_PACKET_JSON [--comparison COMPARISON_SUMMARY_JSON] [--packet-id ID]`
- `agent-assure ci CANDIDATE_RUNSET --suite COMPILED_SUITE_JSON --out-dir REPORT_DIR [--baseline BASELINE_RUNSET] [--report-mode full|fail-fast] [--waiver WAIVER_JSON_OR_YAML] [--fail-on-warn] [--fail-on-not-evaluated]`
- `agent-assure ci gate SUMMARY_OR_PACKET_JSON [--fail-on-warn] [--fail-on-not-evaluated]`
- `agent-assure live adapters`
- `agent-assure live run COMPILED_SUITE_JSON --config LIVE_CONFIG_YAML_OR_JSON --protocol LIVE_PROTOCOL_JSON --out LIVE_RUNSET_JSON`
- `agent-assure live evaluate LIVE_RUNSET_JSON --suite COMPILED_SUITE_JSON --protocol LIVE_PROTOCOL_JSON --out-dir REPORT_DIR [--confidence-level DECIMAL]`
- `agent-assure live compare BASELINE_LIVE_REPORT_JSON CANDIDATE_LIVE_REPORT_JSON --protocol LIVE_PROTOCOL_JSON --out-dir REPORT_DIR`
- `agent-assure live drift LIVE_EVALUATION_REPORT_JSON... --protocol LIVE_PROTOCOL_JSON --out-dir REPORT_DIR`
- `agent-assure live trajectory LIVE_RUNSET_JSON --report LIVE_EVALUATION_REPORT_JSON --protocol LIVE_PROTOCOL_JSON --out-dir REPORT_DIR`
- `agent-assure release replay RELEASE_DIGEST_REPLAY_JSON [--artifact-root DIR] [--require-role ROLE] [--expect-commit COMMIT] [--expect-ref REF] [--require-current-commit/--no-require-current-commit] [--require-core/--no-require-core]`
- `agent-assure otel preview PATH [--out PATH]`
- `agent-assure otel export RECORD_OR_RUNSET_OR_SPAN_PLAN_JSON [--protocol otlp-http|console] [--endpoint URL] [--service-name NAME] [--timeout-seconds SECONDS] [--header NAME=VALUE]`

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

`live adapters` lists installed live adapter identifiers. `live run` consumes a
compiled suite, live run configuration, and `live-protocol-record`. The command
checks that the config matches the frozen protocol ID, digest, planned
repetitions, tool-schema and policy-bundle digests, request budget, cost
budget, retry policy, and rate-limit caps, then writes a `run-set` with
`execution_mode` `live` and protocol binding. When `tokens_per_minute` is
declared, the adapter must declare `max_output_tokens`; the runner reserves the
prompt character count plus max generated tokens before each provider call. The
static JSONL adapter is intended for offline tests and fixtures. The
`external-script` adapter invokes a configured script through a no-shell
subprocess harness, sends the live request as JSON on stdin, propagates W3C
trace context through environment variables and request JSON, enforces the
configured timeout, and expects JSON stdout containing either `content` or a
structured `record`. Scripts do not inherit the full parent environment by
default; only names in `script_env_allowlist`, explicit `script_env` entries,
and runner-injected trace/request variables are passed. The live request
payload includes the original prompt text. Subprocess spawn failures, timeouts,
nonzero exits, invalid stdout, and stdout that fails the structured output
contract create redacted `emergency-process-record` artifacts on the RunSet and
a structured-output or runtime-failure live record. The OpenAI-compatible
chat-completions adapter requires explicit `allow_network: true` in the live
config and an API key environment variable. OpenAI cost is recorded as a local
estimate when token pricing is configured and as not reported otherwise; it is
not a billing assertion. Live run records store redacted
summaries, provider/model labels, resolved provider-version metadata when
required by the protocol, observation IDs, trace context, cluster/source-group
IDs, repetition and schedule indexes, attempt/retry/rate-limit counters,
inclusion or exclusion state, timestamps, token counts when available,
estimated cost, estimated-cost source, latency, and provenance digests. They do
not persist raw prompts or raw provider outputs.

The default `max_rate_limit_events` value is `0`, so the first rate-limit
response stops the run unless the frozen live configuration and protocol allow
rate-limit events.

`live evaluate` evaluates each included live observation against the compiled
expectation for its case, checks actual observations against the protocol
binding, then writes `live-evaluation-report.json` and
`live-evaluation-report.md`. The report includes completion status, stop
reasons, budget-exhaustion status, cluster-aware
expectation-pass rates, outcome rates, reason-code rates, exclusion rates,
pooled and cluster-mean rates, cluster counts, design effects, effective sample
sizes, largest-cluster sensitivity values, interval-center metadata that states
whether a confidence interval is around a cluster mean or pooled rate,
per-observation tool-schema and policy-bundle provenance digests, exploratory
flags, provider/model group summaries, latency distributions, estimated-cost
distributions,
observation-level findings, optional protocol-declared statistical-invariant
results, and limitations. Statistical-invariant results can include rare-event
one-sided Poisson upper bounds at the protocol confidence level and observed
cluster-correlation summaries with uncertainty; zero observed critical events
are reported as bounded evidence, not proof of absence. Degenerate per-arm
cluster intervals are labeled as a
boundary heuristic rather than an ordinary t interval. It exits `1` when any included
observation has a blocking
expectation/policy finding or protocol exclusion limits are exceeded.

`live compare` compares two protocol-bound live evaluation reports. Group IDs,
baseline mode, non-inferiority margin, and confidence level come from the
`live-protocol-record`, not CLI flags. `concurrent_paired` mode uses matched
cluster-level pass-rate differences with the protocol-declared paired cluster
t-interval, paired cluster percentile bootstrap, or paired randomization test.
`fixed_reference` mode compares candidate cluster rates with the frozen
reference rate and does not use paired language. The command writes
`live-comparison-report.json` and `live-comparison-report.md`, including
baseline/candidate pass rates, pass-rate difference, a cluster-level interval,
compared-cluster count, effective sample size, exploratory status, p50 latency
delta, total-cost delta, and optional paired randomization test results.
Comparisons with fewer than 30 compared clusters, percentile bootstrap
comparisons with fewer than 50 compared clusters, or paired randomization tests
whose exchangeability declaration, identical included cluster sets, identical
included case/repetition sets within clusters, or exact-enumeration
prerequisites are not met cannot produce a confirmatory pass. When all paired
cluster differences are identical, the limitations section labels the
zero-width empirical interval as degenerate. A non-inferiority gate failure
means the interval did not rule out a drop larger than the margin; it is a
fail-closed gate result, not proof of candidate inferiority. The comparison is
time-bound to the reports being compared and is not a general provider-quality
claim.

`live drift` consumes ordered `live-evaluation-report` JSON artifacts and a
`live-protocol-record`, then writes `live-drift-report.json` and
`live-drift-report.md`. The report first checks cross-window comparability for
suite identity, baseline mode, analysis method, protocol digest, tool-schema
digest, policy-bundle digest, and timestamp order when timestamps are present.
Comparable series can report ordered trend, adjacent-window step changes,
separate dependence diagnostics from lag-1 autocorrelation and AR(1) summaries
when enough ordered windows exist, and EWMA state summaries named as governance
health, control reliability, or drift state when their declared window
threshold is met. Drift reports use
`not_evaluated` gate state and are exploratory by default; review signals do
not establish safety, compliance, clinical validity, provider quality, model
intent, or general model-quality regression. An invalid comparability result
writes the report and exits `1`.

`live trajectory` consumes a protocol-bound `run-set`, its
`live-evaluation-report`, and the matching `live-protocol-record`, then writes
`live-trajectory-report.json` and `live-trajectory-report.md`. The report
derives privacy-filtered observable state paths from structured run,
evaluation, and emergency-process records; summarizes observable transition
profiles over canonical state order; reports sequence invariants; surfaces
history-dependent checks; and summarizes operational event processes for
retries, rate limits, exclusions, malformed outputs, runtime failures,
emergency process records, and budget stops. Governance-control trajectory
findings and operational reliability warnings are reported separately. The
report uses `not_evaluated` gate state and is a review artifact; path coverage
does not prove unsafe paths are impossible. Missing timestamps, low event
counts, low exposure, weak transition support, or incompatible protocol binding
mark the affected outputs exploratory or invalid. An invalid trajectory report
writes the report when it can and exits `1`.

`release replay` validates a `release-digest-replay` artifact under
`--artifact-root`. It recomputes raw SHA-256 file digests for replay-stable
source artifacts and stable JSON projection digests for environment-bearing
review artifacts. When replay verifies the release artifact manifest, it also
cross-checks each manifest-listed `sha256` against the available artifact
bytes, including SBOM, wheel, source distribution, and dependency inventory
entries.
For environment-bearing manifest children, the raw manifest hash is checked
against bytes and the manifest replay projection uses the child's stable digest.
By default it requires the compiled-suite, fixture-manifest, evidence-packet,
and release-artifact-manifest roles. `--require-current-commit` requires the
current git checkout to match the replay file's `source_commit`;
`--expect-commit` checks the replay file's `source_commit` value without reading
the current checkout; `--expect-ref` checks the replay file's `source_ref`.
Replay artifact paths must be relative to `--artifact-root` and cannot contain
parent-directory segments. Digest mismatches, missing release artifacts, source
commit/ref mismatches, or unavailable git commit metadata when current-checkout
checking is requested exit `1`; malformed replay artifacts exit `2` through
Typer validation. Keyless cosign signature verification remains an external
`cosign verify-blob` operation documented in `docs/release_evidence.md`.

`otel preview` writes the privacy-filtered `span-plan` derived from a single
`agent-run-record`. `otel export` accepts an `agent-run-record`, `run-set`, or
precomputed `span-plan`, derives span plans where needed, and emits
OpenTelemetry SDK spans using either the console exporter or OTLP HTTP exporter.
OTLP export requires installing the optional `agent-assure[otel]` dependencies.
The exporter extracts any span-plan `traceparent` as parent context and emits
only attributes and events already present in the span plan. It is projection
from persisted span plans, not live instrumentation of the adapter HTTP request
or external subprocess lifecycle; provider-call timing remains the recorded
run metadata rather than SDK span timing. The exporter does not emit raw
prompts, raw outputs, tool arguments, unredacted summaries,
`gen_ai.response.tokens`, `gen_ai.operation.name`, or `rpc.method`.

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
