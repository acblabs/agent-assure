# Privacy Model

Current privacy controls are intentionally narrow. The project redacts common
sensitive patterns from author-time summaries, safe errors, markdown-style output
paths, and span-plan attributes. Persisted run-record validation rejects
sensitive-looking summaries rather than silently repairing loaded JSON. It does
not provide production-grade PHI de-identification.
