# Privacy Model

Current privacy controls are intentionally bounded. The project redacts common
sensitive patterns from author-time summaries, safe errors, markdown-style output
paths, runset writes, reports, and span-plan attributes. The detector set covers
SSN-like values, emails, payment-card-like numbers, DOB patterns, selected
patient/member fields, bearer/JWT/API-key-like tokens, selected cloud and
source-control tokens, secret-looking key/value pairs, URL query secrets, and
phone-number fields.

Ordinary incomplete-RunSet findings report only the declared stop-reason count.
They do not copy caller-supplied stop-reason text into finding messages, console
output, or Markdown reports.

First-party console, Markdown, and evidence-diff HTML report values are treated
as untrusted display text. Values pass through the standard sensitive-pattern
redactor, Unicode control and format characters are removed, whitespace is
collapsed, and the result is redacted again in case control removal reassembled
a secret. Rich receives literal text objects, while Markdown and HTML apply
their format-specific escaping after this shared boundary. This prevents report
fields from injecting terminal formatting, forging rows, applying bidi spoofing,
or bypassing display redaction.

JSON escaping protects artifact bytes at rest, but it is not display
sanitization: parsers restore control and bidirectional-format code points in
semantic strings. Downstream consumers must apply control- and bidi-safe display
encoding before rendering parsed report fields in terminals, logs, or review UIs.

The detector semantics have an explicit compatibility identity. Current
`RunSet`, `EvaluationSummary`, and `ComparisonSummary` artifacts require
`privacy_profile_id: agent-assure/privacy-detectors/v3` and a
`privacy_profile_digest`. The digest is SHA-256 over an RFC 8785 canonical
manifest containing the ordered detector IDs, regular expressions and flags,
their mandatory literal guards, Unicode scan-view normalization, the search and
substitution algorithms, structured mapping policy, and the redaction
replacement text. The v3 scanner
checks both the exact scalar and an NFKC compatibility view that converts
tab/line-break controls to spaces and removes other Unicode category-C code
points. It also maps Unicode dash punctuation and U+2212 MINUS SIGN to the ASCII
hyphen so SSN- and card-like values cannot evade detection with visual dash
substitutions. If that view reconstructs a sensitive-looking value, the exact
original scalar is redacted in full; accepted values are never silently
normalized before persistence.
Changing any manifest entry changes the digest; changing detector behavior
also requires an intentional profile-ID version decision. The digest is a
reproducibility and compatibility anchor, not a signature or attestation.

Each scalar privacy scan is capped at 16,384 characters. A longer scalar is
treated as sensitive and redacted in full instead of being evaluated by the
backtracking regular-expression engine. Semantics-preserving literal guards
skip detectors whose mandatory marker is absent for ASCII scalars. Non-ASCII
scalars conservatively run every detector, avoiding mismatches between Unicode
case-insensitive regex semantics and ASCII marker lookup. Mapping keys are
scanned as well as values. Every non-empty scalar under a recognized ASCII
sensitive label is sensitive regardless of its length; labels accept repeated
space, period, underscore, and hyphen separators. Non-ASCII mapping keys with
non-empty scalar values fail closed because a partial visual-confusable table
would create bypasses. Only the empty string and the exact canonical
`[REDACTED]` sentinel are exempt. These structured-key semantics, including the
exact label expression, flags, non-ASCII policy, and exemptions, are bound into
the privacy-profile digest.

Evidence-sensitivity has one bounded exception for exact JSON source mirrors
that may legitimately cross the scalar cap. A mirror is preserved only when
its UTF-8 bytes match the adjacent SHA-256 digest (and declared size, for
fixtures), it decodes to a mapping, and a recursive privacy pass leaves the
decoded mapping unchanged. Fixture mirrors are limited to the schema roles
`request`, `subject_configuration`, and `tool_configuration`; unknown or legacy
role spellings do not receive the exemption. The exception independently
rejects inputs above the declared 1 MiB corpus/fixture byte envelope before
hashing or JSON parsing. A byte-limit, digest, size, decoded-value, or privacy
mismatch falls back to ordinary fail-closed redaction.

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

## Repeated Evidence-Sensitivity Boundary

The repeated protocol and statistical reports persist exact digests and
bounded provider/model, pair, cluster, disposition, structured decision, and
analysis metadata. `PairedSensitivityObservation` deliberately persists the
bounded baseline/counterfactual `recommendation` and `outcome` tokens extracted
from validated provider records; these are decision fields, not raw completion
bodies. The schemas have no fields for raw prompts, raw provider response
bodies, tool arguments, tool results, unrestricted provider payloads, or
credential values. Network adapters obtain a credential from a configured
environment variable only after explicit network consent; the protocol records
neither the secret nor its value-derived digest.

These omissions do not make the remaining metadata anonymous. Case IDs,
provider response IDs retained in underlying live RunSets, model revisions,
cluster labels, timestamps, and stable digests can be linkable. Producers must
use privacy-safe identifiers and apply the existing bounded read, recursive
redaction, and publication controls to RunSets before assembling the paired
reports. The statistical artifact summarizes privacy-filtered structured
records; it is not a substitute for source-system access controls or DLP.

Repeated analysis publication also retains the exact privacy-filtered baseline
and counterfactual RunSets as separate `baseline.source.runset.json` and
`counterfactual.source.runset.json` files. They are not nested into the
statistical roots, but a stochastic packet binds both atomically through the
`stochastic-baseline-source-runset` and
`stochastic-counterfactual-source-runset` artifact-digest roles and the same
release-manifest roles when a manifest is present. Packet CI reparses both files
and recomputes whole-RunSet and per-record digests, then reconstructs the
canonical paired observations before accepting their structured decision,
disposition, cluster, endpoint, or source-record semantics. The packet's
publication and retention boundary therefore includes those exact source
snapshots; replay establishes consistency, not anonymity, confidentiality,
authenticity, or permission to retain them.

## Assurance Mutation Boundary

Assurance mutation starts from a validated, privacy-filtered RunSet and changes
only paths owned by that schema. The ordinary result persists source and
transformed digests, exact changed paths, reason codes, bounded finding
summaries, operator identity, provenance, independence class, and limitations.
It binds the selected expected finding target and each observed finding target
with domain-separated digests rather than copying their target strings. It does
not copy raw prompts, completions, messages, tool arguments, tool results, token
chunks, credentials, or unredacted summaries into the result.

A catalog campaign enforces that boundary before creating any campaign
identity. It first rejects non-strict JSON, then rejects RunSets that cannot be
validated and projected, then privacy-scans both the private input copy and its
validated model projection. A privacy match raises the fixed campaign-level
`mutation campaign source failed the bound privacy-detector profile` error
before source hashing, catalog construction, operator execution, or artifact
publication. Projection failure and noncanonical JSON use separate fixed
messages with the same no-artifact behavior. The single-operator command keeps
schema and source-privacy failures as bounded `invalid_subject` results.

The transformed RunSet remains subject to the normal recursive redaction,
privacy-profile binding, and fail-closed sensitive-field checks. Clearly
labeled synthetic fixtures may carry synthetic content for reproducibility;
the privacy-redaction exception replaces only its exact marker in a private
probe and rescans every other candidate path. It does not permit caller content
to bypass ordinary persistence rules.

Controls-mutation configuration and threat-applicability YAML are trusted
authoring inputs, not observation payloads, and are not a secret store or PHI
de-identification boundary. Authors must not put prompts, completions, tool
payloads, credentials, personal data, or other sensitive free text into those
files. Manifest owners are constrained machine identifiers; rationales are
bounded but may still disclose authored text if the manifest itself is shared.

The derived control-efficacy report does not copy manifest owners or
rationales. It binds the manifest by digest and persists only threat IDs,
applicability, critical flags, operator IDs, invariant families, independence
classes, control IDs, exact counts/ratios, semantic states, and limitations.
The nested packet gate adds stable reason codes, effects, and affected operator
or threat IDs. These identifiers remain review-visible and should use
non-sensitive governance labels.

`doctor controls-mutate` is read-only and emits bounded, redacted diagnostic
messages. The packaged assure-the-assurance demonstration uses only bundled
synthetic fixture content and writes paths relative to its output root in the
machine summary.

RunSet persistence and packet/report projection intentionally apply different
policies to usage provenance IDs. RunSets preserve clean schema-owned usage IDs
and fail closed if those preserved values look sensitive, because runsets are
the source evidence. Evidence packets and rendered reports redact
sensitive-looking `cost_basis_ids` and `pricing_snapshot_ids` values in place,
because those artifacts are derived review/share surfaces.
