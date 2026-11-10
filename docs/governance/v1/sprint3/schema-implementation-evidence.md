# Schema implementation evidence

Status: **in progress; no SCHEMA-01A or SCHEMA-01D implementation acceptance**.
This records development evidence and limitations. It grants no qualification,
method admission, release or deployment authority.

## Dispatch basis

- Work packages: SCHEMA-01A and SCHEMA-01D under the accepted bootstrap exception.
- Parent packet digest: `sha256:4b4ac646506d0167c5b9c0ee557d9e79a4ba81e0faba7ee55f870b0b2a56aa28`.
- Additive test/profile amendment: `sha256:6c40be1d9a271823cacd65b42784a32e20ad22f40d484c75fd6dfadb55d1e7af`.
- The maintainer's actual native signature verified before amended execution.
- Development owner/reviewer: acblabs; `NO_INDEPENDENT_REVIEW` remains explicit.
- The original checkpoint expired. A separately signed repair renewal permits
  bounded repair checks until `2026-11-10T07:12:10.990486Z`; it preserves the
  original forecast, assignments, trust expiry and lack of implementation acceptance.

## Implemented increment

- Immutable exact four-key cells, bounded versions, explicit dispositions,
  minimum-reader checks, original-byte resource hashes and binary-search lookup.
- Bounded duplicate-rejecting matrix loading with explicit array-to-tuple
  conversion and strict scalar handling.
- Installed-reader discovery in the existing validation module. Raw METADATA
  and RECORD are bounded before parsing; arbitrary RECORD entries are not
  followed. Selected module and metadata bytes must match their owned hashes.
  Provenance belongs to the exact distribution, and directory/VCS installs fail.
- Pinned installed matrix and schema discovery, minimum-reader-before-resource
  ordering, actual identity constraint checks and offline reference handling.
- Existing frozen-root policy remains the semantic ceiling. No migration or
  declared semantic loss gains eligibility. Every result has effect `none`.
- A pure deterministic matrix builder expands fourteen verified legacy
  producer/writer pairs against the existing policy and hashes unchanged source
  snapshots. It adds the preview producer only after its actual version choice.

The default package/writer versions, existing writer models, legacy validation
functions, default exports and released schema bytes are unchanged. No new
production v1 contract is registered. New-writer cells remain absent.

## Validation observations

The retained local command observations include fresh signature/input checks,
scope checks, immutable environment checks and resource supervision. They are
local development observations; hosted validation must bind its own source.

| Check | Observation | Result |
| --- | --- | --- |
| Hardened compatibility, matrix and bounded storage tests | FocusedA006; approved command 11 | 180 passed |
| Ruff across the assigned checkout | LintA004; approved command 7 | Passed |
| Strict mypy across source and scripts | TypesA005; approved command 8 | 301 files passed |
| Existing schema regression suite | SchemaA002; approved command 2 | Failed: 78 failed nodes and 37 setup-error nodes |
| Documentation alignment | DocsA001; approved command 9 | Failed at Git discovery and existing filesystem-root access |

The bounded storage test produced a prospective matrix with 432 cells covering
14 legacy producers, 12 writer versions and reader `1.0.0a3`. Its 380,685 bytes
have exact-file digest
`sha256:9c90a00a6d3d7783786a7934805d4c53570b26ab157afd89c68ffd26fe86f33d`.
That privately retained review artifact is not an installed or accepted resource.
Documentation alignment could not inspect Git-tracked assets/action pins or
derive the existing flagship showcase facts in this execution profile. Its
failure is retained; it is not waived by the focused test results.

The broad failure report identifies existing filesystem-root ancestor-handle
denials in the current sandbox and unavailable bare Git in its closed PATH.
Read-only probes with GENERIC_READ, FILE_READ_ATTRIBUTES and zero access all
failed at the denied ancestor; they succeeded at the assigned workspace root.
No security pins were removed, tests skipped, permissions widened or candidate
commands elevated. This failed report is not a successful regression gate.

## Remaining acceptance work

SCHEMA-01A still needs reviewed packaged matrix/resources, installed-wheel
evidence, complete compatible-host checks and its actual human acceptance.
SCHEMA-01D still needs the exact 42 closed schemas, canonical projections,
instance/dependency graph checks, generated-resource review and its own human
acceptance. No first-writer or dependent TEMP-01A dispatch is authorized by this
document. SCHEMA-01B/C, publication and qualification remain deferred.

A compatible isolated runner is required for the full regression gate. The
repository's existing Windows CI configuration provides a handoff reference;
no remote run or new runner was created in this development observation.

## Bounded repair observations

The renewed repair scope adds a conservative identity-admission repair, explicit
post-closure verification APIs, archive-member diagnostics and exact public-proof
exceptions, and history-scan policy handling. The signed earlier records and
released resources remain unchanged.

| Check | Observation | Result |
| --- | --- | --- |
| Compatibility and identity regression tests | RepairSchema003; command 11 | 221 passed |
| Historical correction and post-closure verification tests | RepairGovernance002; command 12 | 80 passed |
| Ruff across the assigned checkout | RepairLint005; command 7 | Passed |
| Strict mypy across source and scripts | RepairTypes003; command 8 | 303 files passed |
| Explicit formatting | RepairFormat008; command 19 | Passed; packaged Python syntax trees preserved |
| History, archive and workflow test selection | RepairSecurity002; command 13 | Incomplete: supervisor directory-sharing failure |
| Candidate campaign summary | RepairGoldenSummary001; command 15 | Failed: existing filesystem-root access denial |

The identity check uses forced scalar literals and required presence to evaluate
guards conservatively. Asserted root-instance `oneOf` alternatives require a
bounded pairwise exclusivity proof. This is an identity-consistency check, not a
general satisfiability solver or acceptance of an artifact. Tests cover overlapping
alternatives, conditional presence/literal propagation, strict scalar distinctions,
reference cycles, resource limits and the complete existing legacy resource set.

The history policy retains the exact 21 reviewed historical fingerprints. Only
eight known findings may be derived for an exact pull-request merge identity,
ordered parents and complete pinned source blobs. The detector configuration,
digest-pinned scanner and canary behavior are unchanged.

Each of three source-distribution failures was attributed to actual archived
member bytes before adding its exact signature-field pins: Sprint 2 correction
acceptance, its predecessor signed components, and the Sprint 3 dispatch proposal.
The last attribution used an archive retained from interrupted RepairBuild003;
it does not turn that interrupted build into a successful build gate. Earlier
RepairBuild001/002 passed for their earlier development source snapshots. All
these payloads identify version `0.7.0`, not the required developer preview.

RepairBuild003 and RepairSecurity002 retain supervisor failures while pinning
temporary directories (native errors 2 and 32). Their scope and immutable
environment postchecks passed; neither run is a successful regression/build gate.
Any proposed supervisor revision remains separate from the signed active profile
until independently adopted.

The two campaign goldens remain unchanged. The final-source summary could not
read its suite through the existing filesystem-root guard in this sandbox. No
unrestricted golden update, loader bypass or candidate elevation was used.

The post-closure API requires independently authenticated expected claims,
implementation/runtime bindings, enrolled authorities, Git access, signature
verification and clock inputs. No public post-closure amendment has yet been
accepted. The ordinary authoring guard remains closed after source changes;
passing the new tests alone does not restore the default historical-verification
command or hosted gate.

## Follow-up repair verification

The signed supervisor accepted `FinalBuild004` (command 16): both source archive
and wheel built successfully from that repair snapshot. It then accepted
`FinalPrivacy004` (command 17), checking both freshly built artifacts. These
observations supersede the interrupted-build limitation for that snapshot; the
package still identifies `0.7.0`, not the Sprint 3 preview.

`FinalSecurity003` completed command 13 with 205 passing tests and 21 failures
while constructing the synthetic history repositories. Bounded stderr
diagnostics in `FinalSecurityDiagnostic005` established the cause: Git rejected
the 265-character proof path with `Filename too long`. The intervening
`FinalSecurityDiagnostic004` retained a supervisor directory-sharing failure;
it supplies no successful test result.

The fixture helper now enables command-local Git long-path support and exposes
at most 2,048 stderr bytes on a nonzero exit. It still rejects every nonzero exit
and changes no production scanner or exception rule. With that repair,
`FinalSecurityLongPaths006` passed all 226 wheel-content, history-policy and
workflow tests, including the exact three-command workflow assertions. Scope,
immutable environment and fixed-checkpoint postchecks passed.

The retained 80-test governance observation predates the added real rooted-I/O
preflight. That preflight and the complete native governance suite still need
compatible-host verification. Hosted execution must also verify the unchanged
digest-pinned scanner, complete-history projection and merge-only canaries.

Final-source build, privacy and lint observations after this documentation update
are retained separately in the operator command audit and PR #50. The two
campaign goldens, missing post-closure adoption and A/D acceptance requirements
above remain outstanding.

## URI-fragment identity repair

Further source review identified a resolver mismatch: a percent-encoded local
reference could select a literal definition in the consistency profile while
the artifact validator selected the percent-decoded definition. Four collision
regressions use the real Draft 2020-12 validator, with a valid `0.6.5` witness
and an invalid `0.6.6` witness, including encoded percent and `~1` cases.
`IdentityUriRed007` reproduced all four false admissions while the other 221
focused tests passed. Its failure is retained with successful scope and
immutable-environment postchecks.

The bounded profile now rejects percent-bearing references before any pointer
lookup, preserving the existing length, depth, work and reference limits.
`IdentityUriGreen008` passed all 225 focused compatibility/identity tests under
the signed supervisor, with scope, environment and checkpoint postchecks passed.
The legacy resource regression remains in that selection. No released schema
bytes, writer versions, matrix cells or artifact-validation behavior changed.

Hosted passes at the intermediate commit `a545efd5` remain evidence for that
source. They do not replace final-source checks of this reference repair.
