# Schema Evolution

Released schema version: `0.1.0`.

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
against schema version `0.1.0` and still fail deterministic evaluation if it
omits explicit material claim-evidence links.

## Next Live-Capable Schema Release

The first release that executes live stochastic evaluations must add a
machine-readable live protocol record as a persisted artifact. RunSets and
evidence packets for live execution must reference the protocol record digest so
reviewers can verify that the run used the declared hypotheses, baseline mode,
sample-size plan, retry/exclusion rules, provider-version capture, rate-limit
policy, cost budget, and safety limits.

That release must either add a new schema directory and update JSON Schema
`$id` values, or explicitly document why the persisted shape remains compatible
while publishing a new producer-contract version.
