# Claims Traceability Matrix

This matrix ties public claims to implementation evidence. The YAML file beside
this document is the machine-checked source for documentation alignment.

| Claim ID | Evidence summary |
| --- | --- |
| `offline-fixture-mode` | Local CLI commands compile, manifest, and run shared fixtures without model or provider calls. |
| `strict-schemas` | Persisted Pydantic artifacts are strict, frozen, and versioned. |
| `json-schema-parity` | Runtime validation and JSON Schema validation share the same parity corpus. |
| `yaml-lexeme-preservation` | YAML node loading preserves ambiguous scalar lexemes as strings. |
| `canonical-digests` | Digest inputs use one projection path and RFC 8785 JCS bytes. |
| `hmac-sensitive-correlation` | Sensitive correlation examples use HMAC-SHA256 with a test-only key. |
| `privacy-redaction` | Author-time summaries and runset writes can be redacted before persistence; raw sensitive summaries fail evaluation and span-plan/report attributes are filtered. |
| `otel-span-plan-preview` | Span plans are derived from structured records and pinned to a snapshot. |
| `fixture-example-suites` | The synthetic prior-authorization and minimal expense-approval examples both run from local fixture suites. |
| `evidence-refactor-regression` | The evidence refactor candidate preserves ordinary evidence links while exposing the shared-source multi-claim edge case. |
| `bundled-examples-api-boundary` | Bundled example modules are included for reproducible demos but are not a stable extension API. |
| `expectation-evaluator-reports` | RunSet evaluation checks expectations and built-in deterministic controls, then writes JSON, Markdown, and Rich console reports. |
| `comparison-reports` | RunSet comparison checks fixture equivalence, classifies deterministic control changes, and reports provenance changes separately from verdicts. |
| `evidence-packets-ci-gates` | Evidence packets bundle deterministic summaries with interpretation guidance, environment provenance, dependency-inventory and manifest digests; CI gates provide full/fail-fast exits over candidate RunSets, summaries, and packets. |
| `flagship-showcase-demo` | The README and showcase document reproduce a passing baseline and an evidence-normalization candidate with stable visible output and a missing material evidence link. |
