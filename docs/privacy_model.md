# Privacy Model

Current privacy controls are intentionally narrow. The project redacts common
sensitive patterns from author-time summaries, safe errors, markdown-style output
paths, runset writes, reports, and span-plan attributes. Raw sensitive-looking
summaries are allowed at model construction so evaluation can emit a
verdict-bearing redaction finding, but runner persistence redacts summary fields
before writing a runset artifact.

RunSet write-time redaction is an explicit allowlist for `input_summary` and
`output_summary` on each run record. Other structured run fields are expected to
carry identifiers, verdict inputs, or already-safe messages; safe-error creation
and report rendering apply their own redaction filters. Future additions of free
text run fields should either join the summary allowlist or document a separate
filter at the producer boundary. The project does not provide production-grade
PHI de-identification.
