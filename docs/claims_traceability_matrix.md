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
| `privacy-redaction` | Author-time summaries can be redacted before persistence; persisted summaries are checked and span-plan attributes are filtered. |
| `otel-span-plan-preview` | Span plans are derived from structured records and pinned to a snapshot. |
