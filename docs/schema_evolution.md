# Schema Evolution

Release-candidate schema snapshot: `schemas/v0.6.6/`. Package line v0.7.0 emits
persisted artifact `schema_version: 0.6.6`; its matching stable tag freezes the
snapshot. Earlier released snapshots remain immutable.

An active release candidate is exported to its versioned `schemas/vX.Y.Z/`
directory. `schemas/unreleased/` is a non-gating exporter smoke-test target,
not the candidate source of truth. A matching release tag freezes the versioned
directory, as `schemas/v0.3.1/` was frozen for the v0.3.1 schema release.

Use these directories as the release lifecycle:

- `schemas/v0.1.0/` and `schemas/v0.2.0/` retain earlier release schema sets.
- `schemas/v0.3.0/` contains the stable exported schema snapshot for v0.3.0.
- `schemas/v0.3.1/` contains the active release schema snapshot for v0.3.1
  and the package-only v0.4.0 through v0.4.2 releases.
- `schemas/v0.4.3/` contains the release schema snapshot for v0.4.3
  and the package-only v0.4.4 release.
- `schemas/v0.5.0/` contains the released v0.5.0 snapshot and is immutable.
- `schemas/v0.6.0/` contains the released v0.6.0 snapshot and is immutable.
- `schemas/v0.6.1/` contains the released v0.6.1 snapshot and is immutable.
- `schemas/v0.6.2/` contains the released v0.6.2 snapshot and is immutable.
- `schemas/v0.6.3/` contains the released v0.6.3 snapshot and is immutable.
- `schemas/v0.6.4/` contains the released v0.6.4 snapshot and is immutable.
- `schemas/v0.6.5/` contains the released v0.6.5 snapshot and is immutable.
- `schemas/v0.6.6/` contains the version-bound writer snapshot emitted by
  package line v0.7.0; the matching stable tag makes it immutable.
- `schemas/unreleased/` is a disposable development-export smoke target.

Before a package release mapped to it exists, an active versioned directory is
a release candidate and may be regenerated as the candidate schema changes.
Once that mapped tag exists, the directory is immutable: subsequent schema
changes must bump `SCHEMA_VERSION` and use a new `schemas/vX.Y.Z/` directory.
Schema checks enforce both current-schema parity and released-snapshot
immutability. The historical `v0.1.0` snapshot predates this policy and uses
`v0.2.0`, when that
snapshot stabilized, as its immutable baseline.

Automation has complementary checks:

- frozen schema parity exports the current schema surface to
  `schemas/v0.6.6/` and fails if those candidate files drift;
- tagged-schema immutability compares every released snapshot with its local
  full-history Git tag baseline; its dedicated CI job requires release tags
  rather than silently skipping when history is unavailable;
- schema packaging consistency discovers frozen `schemas/v*` directories and
  fails if `pyproject.toml` does not force-include the same directories under
  `agent_assure/schema_resources/`;
- schema staging exports the current schema surface to
  `schemas/unreleased/` and fails if no schema files are produced.

When a release freezes a new `schemas/vX.Y.Z/` directory, run
`make schema-force-includes` to refresh the Hatch wheel force-include block.
`make schema-check` runs the same helper in `--check` mode and fails if the
static packaging block drifts from the frozen schema directories.

`schemas/unreleased/` is a staging scratch area, not a drift gate. Generated
`*.schema.json` files in that directory are ignored by Git until a release cut
freezes them into `schemas/vX.Y.Z/`.

The wheel ships frozen schema snapshots under the package namespace
`agent_assure/schema_resources/` for release inspection. It does not install a
generic top-level `schemas/` directory into `site-packages`, and it does not
ship `schemas/unreleased/`.

The package version, persisted artifact `schema_version`, exported schema
directory, JSON Schema `$id`, and producer contracts are related but not
identical version surfaces. The v0.3.0 package release froze a v0.3.0 schema
snapshot without changing persisted artifact `schema_version`, which remained
`0.2.0`. The v0.3.1 package release changes persisted artifact shape
additively for measured usage evidence, so it updates the package version,
current schema version, JSON Schema `$id`, frozen schema directory, package
schema resources, and release gates together. A release that changes behavioral producer obligations
without changing JSON shape must publish a versioned producer contract and
document the compatibility boundary.

The v0.5.0 artifact shape requires `privacy_profile_id` and
`privacy_profile_digest` on RunSets, evaluation summaries, and comparison
summaries. Earlier accepted schema versions do not gain those fields: replay
loads them as unbound legacy artifacts and omits runtime-only nulls from model
dumps. This preserves frozen legacy JSON and digest identity.

Evaluating an unbound legacy RunSet applies the current runtime detector and
binds the resulting current evaluation summary to that evaluation-time
profile. It does not establish which detector or redaction rules were used
when the legacy RunSet was originally persisted.

## Privacy Detector Producer Contract

Current contract ID: `agent-assure/privacy-detectors/v9`.

Current contract digest:
`c14c0f46e64c25be871235d93c6123c3a3bf3e92fa86824bbf33dbe8bc2a720d`.

Current producers persist the profile ID and the SHA-256 digest of the RFC 8785
canonical detector manifest. The manifest binds ordered pattern IDs,
expressions and flags, Unicode scan-view normalization, non-ASCII marker policy,
structured mapping reconstruction, detection and redaction algorithms, and
replacement text. A pattern, flag, ordering, normalization, algorithm, or
replacement change must update the canonical digest. Any
behaviorally incompatible detector change must also version the profile ID and
document whether cross-profile comparison is supported. The current comparator
supports only identical profiles implemented by the running package; it fails
closed rather than treating cross-profile results as equivalent.

The v0.6.5 package writer emitted profile v3. The v0.7.0 package
emits schema version 0.6.6 with privacy profile v9.
Profile v9 additionally binds UTF-8 percent-encoded confusable normalization,
complete multi-secret URL redaction, and ASCII-digit PAN boundary and
candidate-selection rules into the canonical manifest.
The intervening hardening adds credential forms, fixed-depth percent-aware
bounded forward URL scanning, 13–19 digit Luhn-filtered card detection, bounded
email syntax, and fail-closed handling when substitution makes an initially
bounded scalar exceed the scan limit. Frozen v0.6.5 artifacts are still
schema-replayable, but they are not silently upgraded or accepted as v9
evaluation input. Migration requires regeneration from the original suite and
source material under the current writer. Historical verification may instead
remain pinned to the v0.6.5 package; outputs from the two detector profiles
must not be mixed in one comparison or release claim.

The release tag validator expects package and schema versions to match unless
the package version is listed in its explicit release-to-schema mapping. The
v0.4.0 through v0.4.2 package releases map to schema version `0.3.1` because
they add RAG, counterfactual-query, adapter, and governance-crosswalk release
surfaces without changing persisted JSON artifact shape. The v0.4.3 package
release adds the `control-coverage-report` persisted root and therefore emits
`schema_version: 0.4.3`. The v0.4.4 package release keeps the persisted schema
at `0.4.3` because its release surface is process-positioning documentation,
fixture demos, report rendering, and control-map behavior hardening rather than
a new persisted JSON artifact shape. The v0.7.0 package is explicitly
mapped to schema version `0.6.6`: it advances the package release line without
renaming the current persisted JSON shape.

Because v0.3.0 does not change persisted artifact shape, the JSON Schema `$id`
values inside `schemas/v0.3.0/` still point to the `v0.2.0` schema namespace.
This is intentional for v0.3.0: the directory is a package-release snapshot,
while the persisted artifact schema namespace remains `0.2.0`.

## Replay Support Window

For the current package line, the CLI keeps replay and validation support for
the release schema snapshots in `schemas/v0.1.0/`, `schemas/v0.2.0/`,
`schemas/v0.3.0/`, `schemas/v0.3.1/`, `schemas/v0.4.3/`,
`schemas/v0.5.0/`, `schemas/v0.6.0/`, `schemas/v0.6.1/`,
`schemas/v0.6.2/`, `schemas/v0.6.3/`, `schemas/v0.6.4/`, and
`schemas/v0.6.5/`. The v0.7.0 package line is the candidate writer surface
before publication and the current surface only after its matching stable tag.
It emits schema version 0.6.6 and accepts those frozen
versions only where the artifact-specific compatibility contract permits it,
while historical replay remains bounded to tagged snapshots; current-schema
checks target `schemas/v0.6.6/`. Frozen-schema availability does not imply
assurance-valid replay. Evaluation summaries and reports, comparison summaries
and reports, and evidence packets through v0.6.5 remain archival structural
resources because they lack a complete version-specific semantic replay.
Pre-v0.6 live protocol, evaluation, comparison, drift, and trajectory roots are
also archival structural resources. Historical drift and trajectory roots
remain archival through v0.6.5 because their plans and exact sources are not
bound in the persisted wire forms. The current assurance validator rejects
these categories instead of certifying a shape-only result. Historical release
manifests and digest replays are likewise archival-only at the public assurance
boundary. Their separately documented release-reproduction path can check
frozen shape, retained role/path uniqueness, and digests, but is explicitly an
integrity-only operation rather than assurance validation.

Current `release-digest-replay` envelopes cannot mix historical persisted JSON
roots into a current semantic replay. The trusted envelope version is carried
through direct role replay and release-manifest recursion, and every mapped JSON
child root must match the current writer schema version exactly. Historical
envelopes continue to validate their children against the exact frozen schema
for integrity-only reproduction; that path does not confer assurance validity.

Every exported frozen `(artifact kind, schema version)` pair has an exhaustive,
default-deny public-validation policy: complete semantic replay or
archival-only. Adding a frozen schema without adding its pair to that registry
fails the registry parity test and an unregistered runtime pair fails closed.
The trusted requested kind and parsed schema version select the policy; optional
historical identity fields cannot select or bypass it. Supported non-archival
inputs are checked against their immutable frozen schema before typed semantic
projection. Archival-only roots first establish that exact frozen wire identity
and are then rejected at the public assurance boundary; callers may use the
frozen schemas directly only for structural inspection. Successful historical
assurance validation is labeled `frozen-jsonschema+semantic-replay`; the plain
`frozen-jsonschema` label is reserved for internal structural inspection.

Compatibility parsing is not itself semantic assurance. In particular, the
v0.6.0-v0.6.5 live-protocol vocabulary can represent historical trajectory
states that the replay evaluator does not implement. The public assurance
validator accepts `required_review_for_approval` only with
`required_state: human_review` for those versions; other historical values may
still be parsed for archival inspection, but fail closed at semantic replay.

The v0.1 `release-digest-replay` contract is shape-identical to v0.2; the
integrity-only release loader validates frozen v0.1 shape and role/path
uniqueness, then projects only root and child schema labels to v0.2 so the typed
digest verifier can consume it. The source file and referenced digest material
are not rewritten, and this projection does not authorize an assurance claim.

Default core-role enforcement is also replay-versioned. The normalized v0.1
contract and supported schemas through v0.6.2 use the historical four-role
release set; v0.6.3 adds `assurance-evidence-graph`. Core-role policy selection
rejects an unmapped schema version rather than applying the newest role set to
old bundles or silently weakening completeness checks.

The four evidence-carrying roots introduced in v0.6.0 additionally receive
their compatible self-digest and relational model checks after the immutable
v0.6.0 schema admits their historical shape. Current exported schemas remain
version-exact at every nested persisted-model boundary; frozen-schema replay is
a separate read path and does not make historical labels valid current wire
output.

Historical v0.6.0-v0.6.5 live evaluation and comparison reports receive a
version-aware semantic projection after frozen-schema validation. The runtime
rederives group identity, cardinality, included/excluded counts, pooled rates,
cluster counts and means, largest-cluster size, and reason-code rates from
embedded observations. The old wire format did not retain enough source RunSet
or protocol state to reconstruct every outcome rate, latency/cost distribution,
or confidence-interval kernel; those historical fields are compatibility
evidence only and are not treated as confirmatory statistics by the current
verifier.

The compatibility models can still recheck recoverable portions of historical
v0.6.0-v0.6.5 drift and trajectory payloads for migration tooling, including
some comparability, trend, path, and count identities. That partial projection
cannot prove that plan-declared diagnostics or governance findings were not
omitted. The public assurance validator therefore rejects both historical
families outright, even when the recoverable subset is internally consistent.
Frozen v0.2.0-v0.5.0 schemas and v0.6.0-v0.6.5 schemas remain immutable for
direct archival shape inspection; regenerate current, source-bound evidence
before making an assurance decision.

Evidence packets apply that split recursively. Current schema v0.6.6 enforces
the nested persisted-artifact versions required by the writer, with separately
versioned usage artifacts as the explicit exception, and the writer validates
the complete post-redaction payload against the pinned current schema before
persistence. Frozen packet schemas through v0.6.5 remain available for direct
structural inspection and explicit non-assurance migration work. The public
packet loader, writer, assurance validator, and gate reject those historical
packet roots before projection or persistence.

The authored `controls-mutation-onboarding-config` is outside this replay
window. It is package-bound input for the onboarding workflow, not an exported
evidence root, and therefore has no frozen JSON Schema compatibility promise.

The golden check follows the same split: unversioned flagship compiled-suite
and fixture-manifest goldens track the current v0.7.0 package producer and its
schema version 0.6.6, while explicitly
named `*.v0.5.0.*.json` and `*.v0.6.3.*.json` goldens are byte-pinned and
replayed through their corresponding frozen JSON Schemas. `--update-golden`
never rewrites those legacy fixtures.

The evidence-sensitivity report goldens instead track the exact current writer,
including `producer_version` and all derived self-digests. A TestPyPI RC ref
must therefore intentionally regenerate and commit RC-version goldens; the
final-version ref must intentionally regenerate and commit the stable-version
goldens before tagging. The ordered procedure is pinned in
[PyPI Release Runbook](release_pypi.md#testpypi-candidate).

Future minor releases should keep at least the two previous minor release
schema snapshots available for local replay unless release notes explicitly
declare a narrower support boundary. Removing a frozen schema snapshot requires
a release note, migration guidance, and a compatibility test update. Development
schemas in `schemas/unreleased/` are never part of the replay support window.

## Required Updates

Enum widening, enum removal, root artifact changes, and reason-code changes must
update exported JSON Schemas, docs, parity tests, and the reason-code registry.

Any new persisted artifact root must include:

- a strict Pydantic model;
- exported JSON Schema under the release schema directory;
- schema-reference documentation;
- runtime/JSON Schema parity coverage;
- digest-projection coverage when the artifact participates in provenance;
- traceability or release notes explaining the public claim it supports.

## Evidence-Carrying Release Contracts

The evidence descriptor, mutation operator, expected-detection contract, and
mutation result were introduced as persisted roots in the v0.6.0 schema
surface. Current producers emit their additive v0.6.6 representation while
retaining frozen v0.6.0, v0.6.1, v0.6.2, v0.6.3, v0.6.4, and v0.6.5
validation and replay. The mutation
catalog and campaign are new persisted roots in v0.6.1. All six separately carry a stable
`/v1` contract ID and `contract_version: 1.0.0`. This separation allows a
future additive JSON shape change to follow the ordinary schema lifecycle
without implying that the method semantics changed, and allows a behavioral
contract revision to be identified without relabeling historical JSON.

`AssuranceEvidenceGraph/v1` is introduced on the v0.6.3 writer surface. It
projects evaluation, comparison, mutation, control-efficacy, gate,
and limitation evidence into a closed four-node/five-edge vocabulary. Its
canonical `graph_digest` excludes only itself, and every typed node payload has
its own canonical digest. Its first frozen historical wire form is v0.6.3;
older packet fields are instead accounted for by its exhaustive compatibility
manifest. Graph validation is structural and does not replace the existing
typed gate decision or change CI behavior.

The v0.6.4 comparison writer adds canonical baseline and candidate RunSet
digests. Current persisted comparison summaries require both; frozen schemas
through v0.6.3 remain unchanged and project without synthesized digests. The
pair closes authenticated comparison-to-RunSet binding while allowing
producer-local environment metadata to remain outside the controlled
sensitivity semantic projection.

The schema v0.6.6 writer emitted by package v0.7.0 adds eight persisted roots:
`ProcessEquivalenceBenchmark/v1`, `RealModelStudyManifest/v1`,
`StudyRegistrationReviewReceipt/v1`, `StudyExecutionReviewReceipt/v1`,
`RealModelStudyReport/v1`, `ExternalPilotEvidence/v1`,
`PilotInputManifest/v1`, and
`ExternalPilotIndependenceReviewReceipt/v1`. The benchmark
binds a non-sensitive v0.2 case catalog without observations. The study
manifest binds the declared locator and digest for an independently
materialized pre-observation registration record, exact condition
protocols/configurations/model identities, execution window, budget,
publication boundary, and hypothesis rule. The study registration-review
receipt binds exact raw registration bytes and a mandatory pre-execution human
checklist. The execution-review receipt binds an independent post-window human
review of provider logs/account records to the exact manifest, report, RunSets,
observed provenance, and provider-response-ID-set digests. The study report
binds that manifest to replayed privacy-filtered
RunSets and derived observed-execution provenance, directly partitions
same-decision inertia from response and wrong-direction movement, gates on
invariant controls, and omits inapplicable statistics for non-executed,
invalidated, or underpowered conditions. RunSets and record provenance can
carry the manifest digest so a later analysis cannot substitute evidence
produced without the frozen study backlink.

The pilot root records pseudonymous environment, input, command, artifact,
friction, remediation, consent, and privacy evidence. Its schema fixes
pre-candidate pilot evidence to learning/remediation-only and makes every
later exact-candidate gate-eligibility field false. These additions are
experimental contracts; they do not imply that a real-model study or external
pilot ran, and they do not authorize an empirical claim for v0.7.0.
The typed pilot input manifest maps every input-bearing workflow argv value to
a privacy-safe content digest and derives separate configuration/data aggregate
digests. Each recorded command binds that manifest, the exact tested wheel
digest, and the declared source revision; the closed-bundle verifier rejects
dangling, unused, or mismatched argv bindings.

The schema v0.6.6 RunSet persistence boundary is intentionally stricter than
earlier writers: structural credential names, headers, and URI forms are
checked on all non-exempt strings rather than only by the narrower
sensitive-value detector. This can reject an older producer's
credential-shaped identifiers or free text. The canonical HMAC-pseudonym
`input_summary` grammar is implemented once and shared by both RunSet-specific
and generic durable-payload checks;
there is no broader token-name exemption.

Every raw persisted v0.6.0, v0.6.1, v0.6.2, v0.6.3, v0.6.4, v0.6.5, or
v0.6.6 artifact must explicitly carry
`artifact_kind` and `schema_version`; model defaults are construction
conveniences, not permission to omit wire discriminators. Evidence descriptors,
mutation operators, expected-detection contracts, mutation results, catalogs,
campaigns, evidence graphs, process-equivalence benchmarks, real-model study
manifests/reports/review receipts, and external-pilot evidence additionally require
`schema_name`, `contract_id`, and `contract_version` in raw payloads.

Each root has one explicit self-digest field: `evidence_digest`,
`operator_digest`, `contract_digest`, `result_digest`, `catalog_digest`, or
`campaign_digest`; the evidence graph uses `graph_digest`, while the
development benchmark, study, and pilot roots use `benchmark_digest`,
`manifest_digest`, `review_receipt_digest`, `report_digest`, and
`pilot_evidence_digest`. The
corresponding digest projection excludes only that field and uses the
repository RFC 8785 canonicalization path. Historical
schema snapshots and replay artifacts are not rewritten when these roots are
added.

Mutation results may reference accepted historical RunSet inputs, but the
result itself uses the current schema. The canonical source digest binds the
version-aware schema-validated, current `RunSet` model JSON projection. That
projection retains the accepted `schema_version` and materializes
schema-permitted omitted defaults before RFC 8785/SHA-256 hashing; it does not
hash raw source bytes or imply that a legacy artifact was produced under
current semantics. Campaigns, mutation results, evidence subjects, and
evaluator reports reuse that projection rather than defining parallel RunSet
identities.

## AgentRunRecord Producer Contract

Current contract ID: `agent-run-record-producer-contract/v2`.

External producers of `AgentRunRecord` artifacts must populate
`claim_evidence_links` for every material claim they intend to satisfy. Each
link must point to a present `evidence_items[].ref_id` in the same run record.
`evidence_refs[].claim_ids` is display and compatibility context only; it does
not satisfy `material_claims_have_evidence`.

This contract is behavioral, not merely syntactic. A record can validate
against an accepted legacy schema version such as `0.2.0` and still fail
deterministic evaluation if it omits explicit material claim-evidence links.

Version 2 additionally requires current producers to declare the provenance of
recommendation, outcome, summary, tool, evidence, claim, policy-result, and
human-review fields through `structured_field_origins`. `fixture`,
`instrumented_adapter`, `model_self_report`, `runner_observed`, and
`legacy_unspecified` are deliberately distinct. Direct model self-report is
accepted for decision/output evaluation but cannot establish that a tool,
evidence lookup, policy evaluation, or human review occurred. An instrumented
adapter remains a trusted producer boundary, not an independent attestation.

The v1 compatibility rule is explicit: omitted origins on fixture records are
interpreted as authored fixture input; omitted origins on live records become
`legacy_unspecified` and cannot satisfy process controls. Untrusted failures,
warnings, not-evaluated results, forbidden tools, and contradictory evidence
remain conservative negative signals, so reducing source trust cannot improve
a verdict.

## Live-Capable Schema Additions

Live-capable development adds `live-protocol-record`,
`live-evaluation-report`, `live-comparison-report`, `live-drift-report`,
`live-trajectory-report`, and `emergency-process-record` persisted artifacts.
Live reports may reference the protocol record digest so reviewers can verify
that the run used the declared hypotheses, baseline mode, sample-size plan,
retry/exclusion rules, provider-version capture, rate-limit policy, cost
budget, tool-schema digest, policy-bundle digest, and safety limits. Live
RunSets and reports can also record incomplete execution, stop reasons,
cluster-mean rates, and exploratory comparison status so low-power or
budget-constrained runs are not interpreted as confirmatory evidence.
The live protocol can also carry an optional advanced statistical endpoint plan.
Those nested endpoint declarations are persisted schema fields and are included
in the protocol digest. Live evaluation reports can persist statistical
invariant results, rare-event upper bounds, and observed cluster-correlation
summaries; live comparison reports can persist paired randomization test
results. These fields are review evidence and do not change deterministic
fixture-mode producer obligations.
The live protocol can also carry an optional drift monitoring plan. Those
metric declarations are included in the protocol digest. `live-drift-report`
artifacts persist cross-window comparability results, ordered-window summaries,
trend, adjacent-step, separate serial-dependence, AR(1), and EWMA monitoring
diagnostics when their declared window-count prerequisites are met. Drift
report fields are derived review evidence and do not make drift signals release
verdicts or deterministic fixture-mode obligations. `analysis_methods` is
authoritative: every metric declares the descriptive-trend basis, optional
dependence and EWMA outputs are emitted only when declared, and a confirmatory
plan must contain at least one confirmatory metric. Exploratory metric
shortfalls do not downgrade an otherwise met confirmatory monitoring status.
The live protocol can also carry an optional trajectory analysis plan. Those
sequence-invariant and event-process declarations are included in the protocol
digest. `live-trajectory-report` artifacts persist privacy-filtered observable
path summaries, transition profiles, history-dependent checks, trajectory
invariant results, and operational event-process summaries. These fields are
derived review evidence with `not_evaluated` gate state; they do not persist raw
prompts, raw outputs, tool arguments, sensitive identifiers, or unredacted
summaries, and they do not replace expectation, policy, invariant, or configured
comparison gates. Observable transitions are the required base method;
sequence findings and event-process/burst outputs appear only when their method
families are declared. Confirmatory trajectory plans require the complete
supported method set and at least one confirmatory invariant target;
exploratory plans cannot contain confirmatory invariants. A trajectory status
cannot be `valid` without a persisted confirmatory target. Zero observed events
with adequate exposure are a met zero-count process, while positive
under-threshold or incompletely timestamped processes cannot assert a no-burst
conclusion.

The v0.2 schema release adds `schemas/v0.2.0`, updates JSON Schema `$id`
values, and keeps the v0.1 release schemas in `schemas/v0.1.0` for replay of
the earlier release surface. Schema parity coverage includes v0.2 live protocol,
evaluation, comparison, drift, trajectory, emergency-process, release-manifest,
and release-replay roots.

The v0.3 package release adds `schemas/v0.3.0` as the frozen release snapshot
used by release gates and wheel-content inspection. The persisted artifact
schema version remains `0.2.0` because v0.3.0 focuses on packaging, demos, and
release evidence rather than a breaking artifact-shape change.

The v0.3.1 package release adds `schemas/v0.3.1` as the active frozen release
snapshot. It keeps `schemas/v0.3.0` unchanged for replay, accepts legacy
`schema_version: 0.2.0` artifacts, and emits `schema_version: 0.3.1` for newly
produced artifacts.

The v0.4.2 package release keeps the active frozen schema snapshot at
`schemas/v0.3.1` and continues to emit `schema_version: 0.3.1`. Its release
surface is behavioral and integration-oriented: RAG provenance fixtures,
counterfactual query-family fixtures, the experimental LangGraph adapter, and
governance crosswalk documentation.

The v0.4.3 package release adds `schemas/v0.4.3` as the active frozen release
snapshot. It keeps earlier schema directories unchanged for replay and emits
`schema_version: 0.4.3` for newly produced persisted artifacts. The new
`control-coverage-report` root maps evidence-packet facts to selected
framework concepts with conditional rule evaluations, coverage states,
evidence references, mapping digests, evidence-packet digests, and explicit
claim boundaries. The v0.4.3 usage extension also adds
`usage-pricing-snapshot`, summary-level pricing snapshot IDs, and integer
basis-point usage deltas. These reports are traceability maps and measured
usage facts for human review, not scorecards, framework grades, or business
impact claims.

The v0.4.4 package release keeps `schemas/v0.4.3` as the active frozen release
snapshot and continues to emit `schema_version: 0.4.3`. Its release surface is
process-assurance positioning, bundled deterministic measurement cases,
evidence-diff rendering for operational counters and measured usage, and
control-map behavior hardening.

The v0.5.0 schema surface adds streaming event roots:
`stream-event-record`, `stream-ingestion-diagnostics`, and `stream-run`.
New persisted artifacts emit `schema_version: 0.5.0`, while usage roots keep
their v0.4.3 usage schema label. Stream ingestion records an explicit global or
producer-local sequence contract, validates and deduplicates JSONL events by
their declared composite key, carries canonical payload digests for conflict
checks, aggregates usage segments, and projects privacy-filtered stream
trajectories into fixture-mode RunSets and ordered span plans. Stream artifacts
do not persist raw prompts, raw token chunks, raw tool arguments, or unredacted
model output.

## Usage Schema Foundation

The v0.3.1 release surface stages optional measured-usage fields on run,
evaluation, comparison, and packet artifacts. The additive model is
`UsageSegment -> UsageLedger -> UsageSummary`, with `UsageSummaryDelta` for
baseline-to-candidate comparisons. Usage segments include `span_id`,
`parent_span_id`, `event_range_start`, and `event_range_end` so future streaming
ingestion can attach usage to ordered events without redesigning the schema.
The usage artifact roots are introduced in v0.3.1. Usage segments, summaries,
and summary deltas continue to emit `schema_version: "0.4.3"` and accept
v0.3.1 roots for replay; v0.4.3-only fields are rejected when labeled as
v0.3.1. New usage ledgers emit `schema_version: "0.6.6"` because
`sum_complete_fields_v2` is a new aggregation contract. Historical v0.4.3
ledgers remain readable with `sum_known_fields_v1`; a v0.4.3 label cannot claim
the v2 method. Container
artifacts that carry usage fields use `schema_version: "0.3.1"` or later;
legacy-labeled containers reject direct and nested usage evidence.
Segment-level pricing snapshot digests are v0.4.3-only and cannot be attached
to a `schema_version: "0.3.1"` usage segment.

Persisted money uses `estimated_cost_microusd: int | None`. Do not introduce
float money fields in persisted artifacts. Missing usage is represented as
`not_observed` in summaries and reports; it is not a deterministic evaluation
failure. Generated wording must stay on measured usage, usage delta, declared
estimated cost, and per-cost-observation evidence when a matched denominator is
declared, and must not claim business impact. Micro-USD cost evidence is
USD-only by design in this release even though the `currency` field remains for
schema continuity. New declared pricing snapshots use v0.6.6
`usage-pricing-snapshot` artifacts with canonical six-place decimal dollars per
million tokens, optional cached-input and reasoning-token rates, USD-only
currency, and limitations. The implementation converts those strings to fixed
point integers and applies round-half-even only at the final micro-USD boundary.
Legacy v0.4.3 integer micro-USD-per-token snapshots remain readable, but their
rate family cannot be relabeled or mixed with v0.6.6 rates. The
pricing helper refuses total-token-only inputs; callers must provide
prompt/completion splits and token-class rates for cached or reasoning tokens.
Demo fixtures must say they are demo pricing and not live provider pricing.
Cost deltas require matching declared cost basis, pricing snapshot IDs, and
pricing snapshot content digests on both sides; missing or mismatched provenance
is carried as a limitation instead of a cost delta.
When a usage ledger and summary are both present, the summary must match the
ledger-derived values and include the ledger-derived limitations. The v0.6.6
ledger suppresses any metric total unless every segment supplies that metric;
summary-to-summary aggregation applies the same complete-coverage rule.
Consequently incomplete metrics cannot produce a comparison delta. Exported JSON Schema enforces the
cost-bearing-segment limitation requirement and the legacy-container usage
field gate; ledger missingness equality is a derived invariant enforced by
Pydantic validation. Baseline-to-candidate percentage-style usage deltas are
persisted as integer basis points, never floats.
