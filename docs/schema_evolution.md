# Schema Evolution

Released schema version: `0.2.0`.

The package version, persisted artifact `schema_version`, exported schema
directory, JSON Schema `$id`, and producer contracts are related but not
identical version surfaces. A release that changes persisted artifact shape
must update all schema surfaces together. A release that changes behavioral
producer obligations without changing JSON shape must publish a versioned
producer contract and document the compatibility boundary.

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
`live-evaluation-report`, `live-comparison-report`, and
`emergency-process-record` persisted artifacts.
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

The v0.2 schema release adds `schemas/v0.2.0`, updates JSON Schema `$id`
values, and keeps the v0.1 release schemas in `schemas/v0.1.0` for replay of
the earlier release surface.
