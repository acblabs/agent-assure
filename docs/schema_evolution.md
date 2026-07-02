# Schema Evolution

Released schema snapshot: `schemas/v0.3.0/`.

Persisted artifact `schema_version`: `0.2.0`.

Development schema changes for the next release are exported to
`schemas/unreleased/`. Stable package releases freeze a copy into
`schemas/vX.Y.Z/`, such as `schemas/v0.3.0/` for the v0.3.0 release.

Use these directories as the release lifecycle:

- `schemas/v0.1.0/` and `schemas/v0.2.0/` retain earlier release schema sets.
- `schemas/v0.3.0/` contains the stable exported schema snapshot for v0.3.0.
- `schemas/unreleased/` is the development export target for the next release.

Automation has two separate checks:

- frozen schema parity exports the current release schema surface to
  `schemas/v0.3.0/` and fails if those committed files drift;
- schema staging exports the current development schema surface to
  `schemas/unreleased/` and fails if no schema files are produced.

`schemas/unreleased/` is a staging scratch area, not a drift gate. Generated
`*.schema.json` files in that directory are ignored by Git until a release cut
freezes them into `schemas/vX.Y.Z/`.

The wheel ships frozen schema snapshots under the package namespace
`agent_assure/schema_resources/` for release inspection. It does not install a
generic top-level `schemas/` directory into `site-packages`, and it does not
ship `schemas/unreleased/`.

The package version, persisted artifact `schema_version`, exported schema
directory, JSON Schema `$id`, and producer contracts are related but not
identical version surfaces. The v0.3.0 package release freezes a v0.3.0 schema
snapshot without changing persisted artifact `schema_version`, which remains
`0.2.0`. A release that changes persisted artifact shape must update all schema
surfaces together. A release that changes behavioral producer obligations
without changing JSON shape must publish a versioned producer contract and
document the compatibility boundary.

Because v0.3.0 does not change persisted artifact shape, the JSON Schema `$id`
values inside `schemas/v0.3.0/` still point to the `v0.2.0` schema namespace.
This is intentional for v0.3.0: the directory is a package-release snapshot,
while the persisted artifact schema namespace remains `0.2.0`.

## Replay Support Window

For the v0.3.x line, the CLI keeps replay and validation support for the
release schema snapshots in `schemas/v0.1.0/`, `schemas/v0.2.0/`, and
`schemas/v0.3.0/`.

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
against schema version `0.2.0` and still fail deterministic evaluation if it
omits explicit material claim-evidence links.

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
