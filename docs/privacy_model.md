# Privacy Model

Current privacy controls are intentionally bounded. The project redacts common
sensitive patterns from author-time summaries, safe errors, markdown-style output
paths, runset writes, reports, and span-plan attributes. The detector set covers
SSN-like values, emails, payment-card-like numbers, DOB patterns, selected
patient/member fields, bearer/JWT/API-key-like tokens, selected cloud and
source-control tokens, secret-looking key/value pairs, URL query secrets, and
phone-number fields.

RunSet write-time redaction now walks persisted structured fields recursively
while preserving digest/hash provenance metadata and known schema-owned
structural fields such as run IDs, case IDs, status values, and `traceparent`.
Those preservation rules apply only to scalar string values; nested mappings or
lists under preserved keys are still traversed and redacted. Free-form
`exclusion_reason` values are also redacted rather than preserved, because live
adapters can emit operational reason text even when common values are short
codes.
Evaluation similarly scans persisted run-record strings and emits
verdict-bearing redaction findings for sensitive-looking content. Raw
sensitive-looking values are still allowed at model construction so evaluation
can fail closed when external producers submit unsafe records.

The bundled fixture HMAC key is accepted only for the repository's synthetic
example runners. Non-synthetic fixture runs must pass an explicit key, or use
`agent-assure suite run --hmac-key-env ENV` to read one from the environment.

These controls are pattern-based guardrails, not production-grade PHI
de-identification or comprehensive DLP. Raw prompts and raw provider responses
are not persisted in RunSet artifacts, but live adapters and external scripts
process the prompt they are invoked with.

Usage evidence, when present, is a separate observable category. It may include
provider/model labels, operation labels, pricing snapshot IDs and digests,
cost-basis text, token counts, retry counts, latency, and declared estimated
cost in integer micro-USD. These fields are review metadata rather than raw
prompt or tool argument content, but producers should keep labels free of
sensitive identifiers.
Current reports surface usage summaries and limitations; any future renderer
that displays segment labels directly should pass them through the standard
redaction path.
