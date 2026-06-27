# Schema Reference

Schema version: `0.1.0`.

Persisted artifacts include `schema_version` and `artifact_kind`.

Exported roots:

- `agent-run-record`
- `compiled-suite`
- `comparison-report`
- `comparison-summary`
- `evaluation-report`
- `evaluation-summary`
- `environment-info`
- `evidence-packet`
- `expectation`
- `expectation-change-record`
- `fixture-manifest`
- `release-artifact-manifest`
- `release-digest-replay`
- `run-set`
- `span-plan`

`AgentRunRecord` intentionally has no persisted `otel_attributes` field. OTel
attributes are derived from structured fields during span-plan projection.

`AgentRunRecord` and `RunSet` are intentionally lean in v0.1 fixture mode. They
persist deterministic case identity, summaries, outcomes, evidence references,
claim-evidence links, provider/model labels, tool names, and fixture/provenance
bindings. They do not yet persist live run status, created/completed
timestamps, model-call records, tool-call records, retrieval records, token
usage, observed metrics, risk tags, variant names, or capability inventories.
Future live/stochastic releases must add those fields through explicit schema
evolution and digest-projection tests.
