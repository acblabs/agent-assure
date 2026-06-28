# Claims Traceability Matrix

This matrix ties public claims to implementation evidence. The YAML file beside
this document is the machine-checked source for documentation alignment.

| Claim ID | Evidence summary |
| --- | --- |
| `offline-fixture-mode` | Local CLI commands compile, manifest, and run shared fixtures without model or provider calls. |
| `strict-schemas` | Persisted Pydantic artifacts are strict, frozen, and versioned. |
| `json-schema-parity` | Runtime validation and JSON Schema validation share the same parity corpus. |
| `yaml-lexeme-preservation` | YAML node loading preserves ambiguous scalar lexemes as strings. |
| `canonical-digests` | Digest inputs use one projection path and RFC 8785 JCS bytes; persisted operational values use schema-normalized strings and integers, with release replay providing stable projections for environment-bearing artifacts. |
| `hmac-sensitive-correlation` | Sensitive correlation examples use HMAC-SHA256 with a test-only key. |
| `privacy-redaction` | Author-time summaries and runset writes can be redacted before persistence; raw sensitive summaries fail evaluation and span-plan/report attributes are filtered. |
| `otel-span-plan-preview` | Span plans are derived from structured records, pinned to a snapshot, and can feed optional SDK/OTLP export. |
| `fixture-example-suites` | The synthetic prior-authorization and minimal expense-approval examples both run from local fixture suites. |
| `evidence-refactor-regression` | The evidence refactor candidate preserves ordinary evidence links while exposing the shared-source multi-claim edge case. |
| `bundled-examples-api-boundary` | Bundled example modules are included for reproducible demos but are not a stable extension API. |
| `expectation-evaluator-reports` | RunSet evaluation checks expectations and built-in deterministic controls, then writes JSON, Markdown, and Rich console reports. |
| `comparison-reports` | RunSet comparison checks fixture equivalence, classifies deterministic control changes, and reports provenance changes separately from verdicts. |
| `evidence-packets-ci-gates` | Evidence packets bundle deterministic summaries with interpretation guidance, environment provenance, dependency-inventory, manifest, replay-stable digests, and manifest-listed digest cross-checks; CI gates provide full/fail-fast exits over candidate RunSets, summaries, and packets. |
| `signed-release-evidence` | Release evidence, SBOM, wheel, and source distribution blobs can be signed keylessly in GitHub Actions and verified against exact workflow identity and blob bytes; replay also checks manifest-listed hashes when files are present. |
| `flagship-showcase-demo` | The README and showcase document reproduce a passing baseline and an evidence-normalization candidate with stable visible output and a missing material evidence link. |
| `publishable-review-artifacts` | Measurement, executive, technical-report, standards, and reproducibility artifacts are aligned to deterministic fixture evidence and conservative claim boundaries. |
| `standards-freshness-review` | OpenTelemetry-facing documentation records a freshness review, local compatibility lock, mapping matrix, and deferred contribution stance pending confirmation of a real upstream gap. |
| `live-statistical-protocol` | A statistical protocol defines baseline handling modes, hypotheses, sample-size planning, 95 percent confidence intervals, cluster-count guardrails, retry/exclusion rules, provider-version and provenance capture, rate-limit handling, cost budgets, and live-run ethics and safety limits. |
| `live-stochastic-evaluation` | Live commands require a frozen protocol, produce protocol-bound repeated live RunSets, report cluster-aware pooled and cluster-mean rates with explicit interval-center metadata, account for exclusions and incomplete stops, compare paired or fixed-reference reports using protocol-declared methods with exploratory guardrails, and report provider/model operational distributions. |
| `runtime-isolation-otel-export` | Live execution can run configured external scripts through a no-shell subprocess harness with declared environment passing, capture redacted emergency process records, propagate W3C trace context, and export privacy-filtered span-plan projections through optional OpenTelemetry SDK/OTLP support. |
