# ADR 0021: V1 release registry, dispatch, and support contracts

- Identifier: `ADR-V1-RELEASE-REGISTRY`
- Ticket: `V1-BASE-06`; work packages `BASE-06R`, `BASE-06M`, `BASE-06D`, `BASE-06E`
- Status: proposed for development acceptance
- Approval mode: `maintainer_development`; `NO_INDEPENDENT_REVIEW`
- Author: LLM implementation agents under the maintainer's current instruction
- Accountable development owner: `technical_lead`; reviewer responsibility: `security_reviewer`
- Acceptance authority: a scoped human receipt, not this document or its author
- Authorization effect: none; package `0.7.0` and writer `0.6.6` remain separate

This decision specifies the architecture for subsequent implementation. It does
not establish that a protected registry, publication credentials, policy signer,
or independently qualified verifier already exists. The S1 successor closure and
the S2 drafting/design receipts remain explicit prerequisites to governed
dispatch. Existing S1 signatures and tags cannot accept this new decision.

## BASE-06R: protected registry and activation

Use `protected-git-ref/v1`. A verifier-owned trust configuration identifies an
HTTPS repository, one exact ref namespace, allowed Ed25519/Sigstore identities,
tenant, policy scope, and registry writer. Discovery never follows a URL or ref
selected by candidate evidence. The proposed namespace is
`refs/heads/assurance/stable-1.0`; its repository and server protection settings
must be adopted and independently verified before activation. No protection is
inferred from a branch name or this proposal.

One least-privilege writer performs an authenticated compare-and-swap against
the exact previously verified object ID. A winner must read the ref back from
the authoritative remote over authenticated transport and verify its signed
head, object ancestry, freshness, and intended predecessor. An acknowledged
push alone is insufficient. A concurrent loser rereads and reports a conflict;
it does not force-update or retry against an unreviewed predecessor. Remote
unavailability is unavailable evidence, not proof of staleness or permission to
use an unbounded cache. Conflicting valid heads constitute a fork and stop
authorization. Rollback is a new forward transition with a separately approved
last-known-good target, single-winner nonce consumption, and full read-back.

The digest graph has this order, where `A -> B` means A binds B's digest:

1. Candidate and qualification artifacts bind their own source/configuration.
2. Three independently verified pre-activation channel receipts bind the exact
   private-store, GitHub, and production-PyPI inventories, respectively.
3. A signed assurance head binds the candidate, required claims, all applicable
   admissions, release approval, lifecycle transitions, and channel receipts.
4. The registry CAS installs that head.
5. An external post-CAS commit proof binds the installed head, expected and
   observed ref identities, remote read-back, and trusted observation basis.

Neither the commit proof nor a receipt claiming that the registry is a fourth
channel is reachable from the head. The authorizer reads both the signed head
and its external commit proof and checks the live ref. Self-consistent local
digests do not prove the current remote head. Candidate code cannot run with
registry or publication credentials.

Each `channel-publication-receipt/v1` names its channel-specific target,
expected inventory, observed immutable object identities, sizes and hashes,
verification time/basis, verifier, and candidate digest. Inventories differ by
channel; shared wheel/sdist bytes must agree. Partial uploads remain incomplete.
An exact retry is idempotent. A conflicting immutable artifact is abandoned or
yanked under policy, never silently replaced. Visibility is not activation.

Candidate verification uses a fresh, verifier-owned environment, the exact
staged wheel, a platform-bound locked wheelhouse, `--no-index --require-hashes
--no-deps` for locked dependencies, and `--no-index --no-deps` for that wheel.
Run outside the source tree with user site disabled and `PYTHONPATH` cleared.
Verify `pip check`, distribution and CLI version, console-script interpreter,
package location, RECORD and direct-url linkage. Never rebuild or repair the
wheel under qualification. The credential-free verification job dominates
every signing/publication job for the same candidate digest.

Profile instances are explicit: `staged`, `active`, `deprecated`, `retired`, or
`disabled_for_candidate`. Only a signed current active instance or a deprecated
instance inside its signed support deadline has its declared authorization
effect. Deprecation emits a deterministic migration notice. An absent deadline,
expired signature, retired instance, or disabled candidate fails closed.
Activation/deprecation is enumerated in the candidate and head; installation
cannot change lifecycle state.

## BASE-06M: support and distribution

The companion [support policy](../governance/v1/sprint2/support-policy.json)
is a concrete proposal for `POLICY-V1-SUPPORT`. It retains the inventoried
`0.7.x` line during the v1 feature train. Its response targets, support deadline,
maintenance branch, and authority must be accepted by the human policy owner;
pending fields cannot imply an operational commitment. No EOL is inferred
from a v1 preview. Until an accepted replacement policy supplies an overlap and
EOL decision, this proposal cannot authorize dropping the existing line.

Maintenance releases use the same exact-byte candidate qualification,
dependency/SBOM verification, independent release review, artifact inventory,
publication and activation controls as the bound release profile. An emergency
branch starts at the exact supported release commit, not the v1 development
head. A critical incident can suspend publication or authorization; it cannot
waive missing evidence. Policy changes are new signed versions.

S1 and S2 produce governance bundles only. Every package preview from S3 has a
repeatable final `V1-DIST-01` wave consuming all source-ticket completions.
Publish signed GitHub assets and the exact production-PyPI PEP 440 prerelease;
verify both inventories and an isolated exact-version installation. Require an
exact pin or explicit prerelease opt-in. TestPyPI is optional publication
preflight only: never a dependency/retention authority and never combined with
PyPI via `--extra-index-url`. Declining PyPI requires a signed train amendment
to a GitHub-wheel/locked-wheelhouse contract before execution.

## BASE-06D: bounded dispatch context

`dispatch-context/v1` is a reproducible projection, not an alternative roadmap.
The source roadmap remains private. A packet identifies the full source digest
and revision; exact occurrence `(ticket, sprint, release, candidate, profile
instance)`; relevant work packages; direct and transitive prerequisite receipt
digests; accepted ADR digests; global invariants; normative section and seed
slices with byte offsets and lengths; exact allowed files; executable commands;
resource limits; stop conditions; generator identity; and canonical digest.
The dispatch verifier reproduces every required projection from the full source
and independently adopted occurrence expectations. It rejects a source mismatch,
missing item, changed offset, unknown prerequisite, unresolved scope, invalid
receipt, or an attempt to override the source. A signature cannot repair an
incomplete projection. Private packets belong under `.tmp`, never public CI.

Proposed development limits are 2,097,152 UTF-8 packet bytes, 256 slices,
262,144 bytes per slice, 512 prerequisite receipts, 256 exact file paths, 64
commands, and 128 stop conditions. These are engineering caps, not measured
release qualification. Overflow returns `DISPATCH_CONTEXT_LIMIT_EXCEEDED`;
truncation and automatic cap increases are forbidden. Missing required source
requires retrieval or a stop, never an abbreviated dispatch.

The independent `occurrence-graph-expectations/v1` contract declares the exact
typed nodes, edges, critical work-package dependencies and canonical order.
Counts and graph/order digests are computed from these independent maps and
compared with the source graph. Do not generate expectations from the graph
being tested. The S2 review package records this as an explicit downstream
implementation/acceptance obligation; it does not call a source-derived graph
an independent oracle.

Every editing dispatch binds a named accountable human, selected mode, approved
dependencies, separate worktree when concurrent file scopes overlap, exact
allowed files and work limits. Protect oracle implementations and expectations;
candidate code never runs with trusted CI, registry, or policy privileges.
Contradictory normative semantics, oracle disagreement, missing authority,
unapproved files or side effects stop the affected operation. Another LLM
session is not independent review.

## BASE-06E: evidence transfer

`candidate-equivalence-transfer/v1` binds source/target candidates, predecessor,
the full transitive impact closure, and every control's
`unchanged|affected|not_applicable` disposition with supporting evidence. Cover
schema/resources, dependency closure, build/toolchain, policy/method,
instrumentation, privacy, deployment context and source. Include the exact
residual rerun set and results, invalidators, issue/expiry, and independent
reviewer signature and competence. Equal Git trees or lockfiles alone are
insufficient. An unresolved binding or conclusion-bearing change produces
`full_rerun_required`. A transfer cannot waive a required independent review or
carry evidence onto a new subject by renaming it.

## Verification and acceptance

The S2 tooling validates strict planning schemas, referenced bytes, identities,
six-ticket coverage and the four work packages; it never emits a deployment
authorization. The exact ADR and policy digests are the subjects of human
development acceptance. Acceptance requires cross-review against
`ADR-V1-EVIDENCE`, `ADR-V1-AUTH`, `ADR-V1-NUM-STAT`, `ADR-V1-IO`, and
`ADR-V1-SCHEMA`, including the acyclic digest graph. Unresolved policy adoption,
staffing, registry server protection and independent qualification remain
visible. This decision does not claim that later release infrastructure is
implemented or qualified.

Design seed dispositions: `AUTH-003` stays nonauthorizing without required
support; `TEMP-006` remains inconclusive with open required history;
`TRUST-001` cannot gain independence by signing; `STAT-010` rejects a
moments-only restart; `IO-001` rejects a missing chunk. Production conversion
belongs to `V1-AUTH-01`, `V1-EVID-02`, `V1-TRUST-01`, `V1-STAT-01`, and
`V1-IO-01`, respectively. `GOV-001`–`GOV-012` retain the mode, competence,
distinct-person and pre-mode-inventory boundaries in ADR 0016, with downstream
enforcement owned by `V1-BASE-06` and `V1-REL-01`.
