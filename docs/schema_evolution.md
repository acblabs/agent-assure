# Schema Evolution

Active released schema snapshot: `schemas/v0.5.0/`.

Persisted artifact `schema_version`: `0.5.0`.

Development schema changes for the next schema release are exported to
`schemas/unreleased/`. Stable package releases that change the persisted
artifact schema freeze a copy into `schemas/vX.Y.Z/`, such as
`schemas/v0.3.1/` for the v0.3.1 schema release.

Use these directories as the release lifecycle:

- `schemas/v0.1.0/` and `schemas/v0.2.0/` retain earlier release schema sets.
- `schemas/v0.3.0/` contains the stable exported schema snapshot for v0.3.0.
- `schemas/v0.3.1/` contains the active release schema snapshot for v0.3.1
  and the package-only v0.4.0 through v0.4.2 releases.
- `schemas/v0.4.3/` contains the release schema snapshot for v0.4.3
  and the package-only v0.4.4 release.
- `schemas/v0.5.0/` contains the active release schema snapshot for v0.5.0.
- `schemas/unreleased/` is the development export target for the next release.

Automation has two separate checks:

- frozen schema parity exports the current release schema surface to
  `schemas/v0.5.0/` and fails if those committed files drift;
- schema packaging consistency discovers frozen `schemas/v*` directories and
  fails if `pyproject.toml` does not force-include the same directories under
  `agent_assure/schema_resources/`;
- schema staging exports the current development schema surface to
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

The release tag validator expects package and schema versions to match unless
the package version is listed in its explicit release-to-schema mapping. The
v0.4.0 through v0.4.2 package releases map to schema version `0.3.1` because
they add RAG, counterfactual-query, adapter, and governance-crosswalk release
surfaces without changing persisted JSON artifact shape. The v0.4.3 package
release adds the `control-coverage-report` persisted root and therefore emits
`schema_version: 0.4.3`. The v0.4.4 package release keeps the persisted schema
at `0.4.3` because its release surface is process-positioning documentation,
fixture demos, report rendering, and control-map behavior hardening rather than
a new persisted JSON artifact shape.

Because v0.3.0 does not change persisted artifact shape, the JSON Schema `$id`
values inside `schemas/v0.3.0/` still point to the `v0.2.0` schema namespace.
This is intentional for v0.3.0: the directory is a package-release snapshot,
while the persisted artifact schema namespace remains `0.2.0`.

## Replay Support Window

For the current package line, the CLI keeps replay and validation support for the
release schema snapshots in `schemas/v0.1.0/`, `schemas/v0.2.0/`, and
`schemas/v0.3.0/`, `schemas/v0.3.1/`, and `schemas/v0.4.3/`, while active
development and release checks target `schemas/v0.5.0/`.

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

## AgentRunRecord Producer Contract

Current contract ID: `agent-run-record-producer-contract/v1`.

External producers of `AgentRunRecord` artifacts must populate
`claim_evidence_links` for every material claim they intend to satisfy. Each
link must point to a present `evidence_refs[].ref_id` in the same run record.
`evidence_refs[].claim_ids` is display and compatibility context only; it does
not satisfy `material_claims_have_evidence`.

This contract is behavioral, not merely syntactic. A record can validate
against an accepted legacy schema version such as `0.2.0` and still fail
deterministic evaluation if it omits explicit material claim-evidence links.

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
verdicts or deterministic fixture-mode obligations.
The live protocol can also carry an optional trajectory analysis plan. Those
sequence-invariant and event-process declarations are included in the protocol
digest. `live-trajectory-report` artifacts persist privacy-filtered observable
path summaries, transition profiles, history-dependent checks, trajectory
invariant results, and operational event-process summaries. These fields are
derived review evidence with `not_evaluated` gate state; they do not persist raw
prompts, raw outputs, tool arguments, sensitive identifiers, or unredacted
summaries, and they do not replace expectation, policy, invariant, or configured
comparison gates.

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

The v0.5.0 schema release adds streaming event roots:
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
The usage artifact roots are introduced in v0.3.1. v0.4.3 producers emit usage
roots with `schema_version: "0.4.3"` and still accept v0.3.1 usage roots for
replay; v0.4.3-only fields are rejected when labeled as v0.3.1. Container
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
schema continuity. Declared pricing snapshots use explicit
`usage-pricing-snapshot` artifacts with integer micro-USD token rates, optional
cached-input and reasoning-token rates, USD-only currency, and limitations. The
pricing helper refuses total-token-only inputs; callers must provide
prompt/completion splits and token-class rates for cached or reasoning tokens.
Demo fixtures must say they are demo pricing and not live provider pricing.
Cost deltas require matching declared cost basis, pricing snapshot IDs, and
pricing snapshot content digests on both sides; missing or mismatched provenance
is carried as a limitation instead of a cost delta.
When a usage ledger and summary are both present, the summary must match the
ledger-derived values and include the ledger-derived limitations. Partial
missingness is carried into summaries and deltas so known-field totals are not
read as complete observations. Exported JSON Schema enforces the
cost-bearing-segment limitation requirement and the legacy-container usage
field gate; ledger missingness equality is a derived invariant enforced by
Pydantic validation. Baseline-to-candidate percentage-style usage deltas are
persisted as integer basis points, never floats.
