# Schema Reference

Schema version: `0.1.0`.

Persisted artifacts include `schema_version` and `artifact_kind`.

Exported roots:

- `agent-run-record`
- `compiled-suite`
- `comparison-summary`
- `evaluation-summary`
- `evidence-packet`
- `expectation`
- `expectation-change-record`
- `run-set`
- `span-plan`

`AgentRunRecord` intentionally has no persisted `otel_attributes` field. OTel
attributes are derived from structured fields during span-plan projection.
