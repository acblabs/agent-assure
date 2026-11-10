# ADR 0024: Bounded planning dispatch for the first schema work packages

- Identifier: `ADR-V1-SCHEMA-BOOTSTRAP`
- Status: proposed; no acceptance or editing authority
- Decision owners: technical lead and schema-competent repository maintainer
- Proposed mode: `maintainer_development`; `NO_INDEPENDENT_REVIEW`
- Scope: the first S3 `SCHEMA-01A` and `SCHEMA-01D` work only
- Amends, if accepted: roadmap Appendix A's production pre-dispatch requirement,
  ADR 0021's pre-dispatch route and ADR 0022's first-writer start boundary, solely
  for this explicitly limited A/D bootstrap
- Runtime, qualification, release and deployment effect: none

## Problem and smallest counterexample

Roadmap Appendix A requires a signed `dispatch-context/v1` before editing.
ADR 0022 includes that contract in the production set owned by `SCHEMA-01D`
and requires its exact implementation-acceptance receipt before a first writer
starts implementation. The first SCHEMA-01D dispatch therefore needs a record
whose production writer needs the receipt that this dispatch is meant to earn.
There is no implemented trusted dispatch generator or explicit planning
exception for this case. A draft packet or another contract name cannot silently
satisfy the existing gate.

The completed S1/S2 acceptance does not resolve this cycle or grant an S3 file
scope. This proposal preserves all previously accepted subjects and does not
claim that a production dispatch schema or generator has been implemented.

## Proposed decision

Permit a separate **planning-governance bootstrap packet**, identified as
`agent-assure-schema-bootstrap-dispatch/1`, solely to start the explicitly
enumerated SCHEMA-01A/D work. It is not a production `dispatch-context/v1`, an
implementation-acceptance receipt, an authorization artifact, or an assurance
claim. It has no runtime or release effect. Accepting this decision creates no
exception for any other production first writer.

Before editing, its trusted verifier must reproduce and authenticate:

1. Full private roadmap digest/revision; selected exact source slices with byte
   offsets, lengths and digests; the complete applicable global invariants,
   ticket, work packages, normative sections and SCHEMA-001/002 seeds.
2. The exact S3 / 1.0.0a3 / stable-core occurrence, accepted ADRs, direct and
   transitive prerequisites, accepted receipt digests and the independently
   adopted occurrence-graph expectations. An unknown prerequisite stops dispatch.
3. The approved exact create/modify/generated paths and their baseline identities,
   generated-resource workflow, commands, resource/work limits and stop rules.
4. Actual accountable owner, implementation agents, reviewer, capacity, backup
   disclosure, conflicts, mode, competence and explicit purpose-scoped key trust.
5. The scoped forecast rebaseline or reconfirmation against the now-concrete
   source/generated surface; unchanged estimates require an explicit accountable
   human decision, not an automatic carry-forward.
6. Exact generator/verifier implementation identities, canonical packet digest,
   scoped human approval/signature and validity capped by every prerequisite.
   Candidate-supplied success flags or trust files are insufficient.

For this pre-candidate planning occurrence only, `candidate` and
`profile_instance` are explicit null values with the reason that no immutable
release candidate or active profile exists. The packet still binds the exact
source commit, intended release and work packages. A null value cannot stand for
an unavailable required runtime candidate, profile or qualification receipt.

Keep the full packet and private slices outside public Git/CI. Use the existing
Ed25519 SSHSIG governance profile for its explicitly adopted planning purpose.
Do not reuse correction-only key purposes as dispatch authority. The packet and
authority must be freshly verified before editing; preparation and a generic
chat instruction to proceed do not establish this verification.

Use the accepted dispatch caps without enlargement: 2,097,152 UTF-8 packet bytes,
256 slices, 262,144 bytes per slice, 512 prerequisite receipts, 256 exact file
paths, 64 commands and 128 stop conditions. Exceeding a limit stops preparation;
neither truncation nor an automatic limit increase is allowed.

## Sunset and preservation

This exception ends at SCHEMA-01D implementation acceptance, on its own earlier
expiry, or on any relevant source, scope, dependency or trust change. Subsequent
editing dispatches require the implemented production dispatch contract and
accepted first-writer prerequisites. A partially implemented schema set cannot
extend this exception to another ticket.

SCHEMA-01A and SCHEMA-01D still need their own exact, signed
`implementation_acceptance` receipts from the assigned schema-competent
repository maintainer. The bootstrap cannot issue those receipts or replace
their schema, matrix, installed-wheel, digest-DAG and test evidence. TEMP-01A
still waits for both. SCHEMA-01B/C require separate approved scopes after these
gates; no ordering or migration implementation is included here.

Preserve released snapshots, historical ADRs, trusted oracle expectations,
legacy semantics, security/privacy limits and every qualification/release gate.
The separately enumerated current report-fixture refresh, if explicitly approved,
may update new package producer/evaluator version metadata and its derived hashes
only. It cannot change an oracle conclusion, score, decision, case, historical
version-labelled fixture or expected behavior. Any such difference stops the
refresh for separate review.
No production policy or oracle can be weakened under this decision. A missing
conclusion-bearing semantic answer returns to its designated human decision
owner. Proposed scope and version details live in the
[dispatch proposal](../governance/v1/sprint3/schema-dispatch-proposal.json).

## Acceptance still required

This file is a proposed owner decision. It must receive exact-subject human
development-design acceptance before the exception exists. The actual
assignment, capacity, file-scope approval, forecast decision, packet, scoped key
authority and verification remain separate required evidence. No signature,
staffing fact, accepted estimate or completed implementation is inferred here.
