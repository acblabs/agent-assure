# Privacy Model

Current privacy controls are intentionally bounded. The project redacts common
sensitive patterns from author-time summaries, safe errors, markdown-style output
paths, runset writes, reports, and span-plan attributes. The detector set covers
SSN-like values, emails, payment-card-like numbers, DOB patterns, selected
patient/member fields, bearer/JWT/API-key-like tokens, selected cloud and
source-control tokens, secret-looking key/value pairs, URL query secrets, and
phone-number fields.

The detector semantics have an explicit compatibility identity. Current
`RunSet`, `EvaluationSummary`, and `ComparisonSummary` artifacts require
`privacy_profile_id: agent-assure/privacy-detectors/v1` and a
`privacy_profile_digest`. The digest is SHA-256 over an RFC 8785 canonical
manifest containing the ordered detector IDs, regular expressions and flags,
their mandatory literal guards, the search and substitution algorithms, and
the redaction replacement text.
Changing any manifest entry changes the digest; changing detector behavior
also requires an intentional profile-ID version decision. The digest is a
reproducibility and compatibility anchor, not a signature or attestation.

Each scalar privacy scan is capped at 16,384 characters. A longer scalar is
treated as sensitive and redacted in full instead of being evaluated by the
backtracking regular-expression engine. Semantics-preserving literal guards
also skip detectors whose mandatory marker is absent. Mapping keys are scanned
as well as values; sensitive-looking or control-character-bearing keys fail
closed at persistence and telemetry boundaries rather than becoming attribute
names.

Evaluation fails closed when a current-schema RunSet declares a detector
profile different from the runtime profile. Baseline/candidate comparison
requires both RunSets to declare the identical runtime-implemented profile;
unbound legacy RunSets remain replayable but are not comparison-compatible.
Evidence packets and evidence-diff rendering also require
their evaluation, comparison, and RunSet inputs to agree on the profile.
Accepted legacy artifacts remain readable without these fields, and their
runtime-only compatibility values are omitted when serialized so frozen
legacy artifacts and digests do not change.

When `evaluate_runset` evaluates an unbound legacy RunSet, it applies the
current runtime detector profile and records that profile on the new evaluation
summary. That binding describes evaluation-time detection only; it does not
retroactively identify the unknown profile used to redact or persist the
legacy RunSet. Legacy inputs therefore remain replayable, but their original
persistence/redaction provenance remains unknown.

RunSet write-time redaction now walks persisted structured fields recursively
while preserving digest/hash provenance metadata and known schema-owned
structural fields such as run IDs, case IDs, status values, and `traceparent`.
Those preservation rules apply only to scalar string values; nested mappings or
lists under preserved keys are still traversed and redacted. Free-form
`exclusion_reason` values are also redacted rather than preserved, because live
adapters can emit operational reason text even when common values are short
codes.
Before writing the redacted RunSet, persistence fails closed when preserved
decision fields, run/suite/case identifiers, observation IDs, provider-response
IDs, provider/model version labels, pricing labels, evidence identifiers,
script names, or debug references contain sensitive-looking values. This keeps
schema-owned identifiers stable when they are clean, but prevents sensitive
content from surviving solely because a field is structurally preserved.
Run `started_at_utc` and `completed_at_utc` values are also bounded,
calendar-valid RFC 3339 strings and remain subject to fail-closed sensitive
content scanning even though clean timestamp structure is preserved.
Evaluation similarly scans persisted run-record strings and emits
verdict-bearing redaction findings for sensitive-looking content. Raw
sensitive-looking values are still allowed at model construction so evaluation
can fail closed when external producers submit unsafe records.

The bundled fixture HMAC key is accepted only when the compiled-suite digest,
complete fixture-manifest digest, and runner identity match a bundled synthetic
example's reviewed, pinned identity. Fixture JSON is parsed from the exact byte
buffer rechecked against that approved manifest. Non-synthetic or modified
fixture runs must pass an explicit key of at least 32 bytes, or use
`agent-assure suite run --hmac-key-env ENV` to read one from the environment.
HMAC-derived subject tokens are pseudonyms for correlation, not anonymized
values; operators must protect the HMAC key and avoid relying on tokens as
irreversible de-identification for enumerable identifiers.

These controls are pattern-based guardrails, not production-grade PHI
de-identification or comprehensive DLP. Raw prompts and raw provider responses
are not persisted in RunSet artifacts, but live adapters and external scripts
process the prompt they are invoked with.
The payment-card-like detector is deliberately conservative: it matches
13-to-16-digit sequences with optional spaces or hyphens and does not perform a
Luhn check. This can flag non-card identifiers. Treat detector findings as a
fail-closed review boundary, not as proof that a value is actually sensitive or
that an unflagged value is safe.

Usage evidence, when present, is a separate observable category. It may include
provider/model labels, operation labels, pricing snapshot IDs and digests,
cost-basis text, token counts, retry counts, latency, and declared estimated
cost in integer micro-USD. These fields are review metadata rather than raw
prompt or tool argument content, but producers should keep labels free of
sensitive identifiers.
Current reports surface usage summaries and limitations; any future renderer
that displays segment labels directly should pass them through the standard
redaction path.

OpenTelemetry export is a separate final egress boundary. It recursively scans
precomputed span plans and externally supplied RunSets immediately before SDK
initialization, validates W3C `traceparent` and `tracestate`, and caps span,
event, attribute, key, and value cardinality. String values and canonical
decimal integer representations are scanned both independently and together
with their attribute keys, preventing numeric identifiers or split label/value
pairs from bypassing context-sensitive detectors. Authentication headers must
be loaded from an environment variable or protected file; secret values are
not accepted directly in process arguments. The OTLP transport ignores ambient
proxy, SDK header, credential-provider, and client-certificate settings and
does not follow redirects. SDK resource attributes, propagator selection,
sampling, span limits, and OTLP compression are project-pinned rather than
inherited from the process environment. Plans without an explicit trace carrier
start from an empty root context, and export, flush, or shutdown failures prevent
a successful result.

## Assurance Mutation Boundary

Assurance mutation starts from a validated, privacy-filtered RunSet and changes
only paths owned by that schema. The ordinary result persists source and
transformed digests, exact changed paths, reason codes, bounded finding
summaries, operator identity, provenance, independence class, and limitations.
It binds the selected expected finding target and each observed finding target
with domain-separated digests rather than copying their target strings. It does
not copy raw prompts, completions, messages, tool arguments, tool results, token
chunks, credentials, or unredacted summaries into the result.

The transformed RunSet remains subject to the normal recursive redaction,
privacy-profile binding, and fail-closed sensitive-field checks. Clearly
labeled synthetic fixtures may carry synthetic content for reproducibility;
that exception does not permit caller content to bypass ordinary persistence
rules.

RunSet persistence and packet/report projection intentionally apply different
policies to usage provenance IDs. RunSets preserve clean schema-owned usage IDs
and fail closed if those preserved values look sensitive, because runsets are
the source evidence. Evidence packets and rendered reports redact
sensitive-looking `cost_basis_ids` and `pricing_snapshot_ids` values in place,
because those artifacts are derived review/share surfaces.
