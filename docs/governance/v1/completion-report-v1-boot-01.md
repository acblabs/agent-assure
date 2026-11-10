# Ticket completion report: V1-BOOT-01

- Ticket ID / dispatch kind: `V1-BOOT-01` / `kickoff`
- Target profile / approval mode: `stable-core` / `maintainer_development`
- Owner and author identities: the initial proposal names `acblabs`
  (`technical_lead`) as owner; implementation artifacts were drafted by LLM
  agents under the user's bounded S1 instruction
- Reviewer identity, competence and conflicts: the initial proposal names
  `acblabs` (`repository_maintainer`), competent only for the recorded S1
  planning and bounded-development scopes; same-person self-review conflict
  declared; `NO_INDEPENDENT_REVIEW`
- Base / result commit: base
  `3b060f4da94f4d0d80e7ae507580fce82ef9bf96`; during report preparation, result
  commit `R` was not yet created or human-reviewed; an accepted receipt must
  bind its full 40-hex identity
- Approved file scope: S1 governance records, schemas, validator, documentation,
  build/docs integration, and governance tests only; no production package
  files
- Required scoped receipt: `development_design_acceptance`; its pre-acceptance
  template is pending human review and signature

This report intentionally preserves preparation-time facts. It does not mirror
mutable acceptance status: only the signed completion receipt, signed bundle,
exact closure commit `C`, and verified signed fixed-tag attestation can
establish an eventual accepted state.

Corrective note: the generation-1 report remains evidence of what was prepared
and run at that time; it is not the current S2 acceptance basis. Generation 2
uses the linear successor `C1 -> R2 -> C2`, replacement signed evidence, and
fixed tag `agent-assure-s1-1.0.0a1-acceptance-v2`.

## Prepared evidence

The initial stage delivers a machine-validated proposal, not human acceptance:

- a 38-role `V1-APPROVAL-ROSTER` with only `technical_lead` and
  `repository_maintainer` proposed as staffed by `acblabs`;
- explicit competence, conflict, capacity, no-backup, unfilled-role, and
  `NO_INDEPENDENT_REVIEW` declarations;
- the exact future staffing, execution-authorization, qualification-receipt,
  pilot, and release sequence recorded as nonauthorizing limitations in
  `approval-roster.json`;
- a separate bounded `V1-BOOT-01` kickoff authorization;
- an S1-only Ed25519 public-key declaration with a displayed fingerprint and
  explicit trust-on-first-use limitations;
- closed schemas, semantic validation, and adversarial tests for these records.

No person, approval, signature, independence, qualification, or release
authority is inferred from the interactive instruction or repository handle.

## Requirement and change traceability

- Roadmap sections 2.5 and 14.2: the active mode is
  `maintainer_development`; development self-acceptance is distinguishable from
  independent qualification.
- Definition of ready: the user's instruction authorizes bounded S1
  implementation and identifies one accountable human; cryptographic identity
  binding remains pending.
- Acceptance criterion 1: every roadmap role is represented exactly once;
  future and independent roles are explicitly null rather than fabricated.
- Acceptance criterion 2: `GOV-001` through `GOV-012` retain their exact
  permit/deny meanings and downstream conversion owners in `ADR-V1-MAP`.
- Acceptance criterion 3: the selected development mode, unresolved
  admissions, conflict, and qualification limitations are explicit. The
  authoritative future plan is the trio of nonauthorizing `Future stable-core`
  limitations in `approval-roster.json`; this report only cross-references that
  record. No method is admitted by this receipt.
- Preserved compatibility: package version `0.7.0`, writer schema `0.6.6`,
  released schemas, production policy, and runtime behavior are unchanged.

Changed artifacts in this ticket's reviewed set are enumerated and raw-byte
hashed by the completion-receipt generator. The private roadmap is input only
and is excluded from that set.

## Commands actually executed

Working directory: repository root on Windows; Python `3.12.13` in `.venv`.

- `git fetch --prune origin main --tags` — exit 0; fetched base and tag resolve
  to the same immutable commit recorded above.
- `.venv\Scripts\python.exe -m pip check` — exit 0; no broken requirements.
- `.venv\Scripts\python.exe -m ruff check .` — passed repository-wide.
- `.venv\Scripts\python.exe -m mypy src scripts` — passed for 291 source files.
- `.venv\Scripts\python.exe -m pytest
  tests/unit/governance/test_v1_s1_governance.py` with a repository-writable
  temporary root — 101 passed. The alternate temporary root was required because
  sandbox policy denied the default Windows temporary directory.
- `.venv\Scripts\python.exe -m pytest
  tests/integration/test_v1_s1_historical_check.py` with a repository-writable
  temporary root — 1 passed. This exercises a real two-commit historical
  closure, eight ephemeral-test-key SSHSIG signatures, a canonical annotated
  acceptance tag, and verification after the live working tree is corrupted.
- `.venv\Scripts\python.exe -m pytest
  tests/unit/release/test_coverage_gate.py` — 14 passed, 2 skipped. The
  fail-closed coverage inventory confirms that the governance suite is assigned
  exactly once to the `unit-a` CI coverage shard.
- `.venv\Scripts\python.exe -m pytest tests/unit/docs
  tests/integration/test_schema_parity.py` — 169 passed outside the filesystem
  sandbox after the first in-sandbox run produced 158 passes and 11 Windows
  access-denied failures in rooted-I/O probes.
- `scripts/check_docs_alignment.py` and strict MkDocs build — passed.
- `make lint type dependency-lock-freshness docs-align claim-boundary
  examples-parity reproduction-index-check build schema-check` — passed,
  including wheel/sdist construction and all frozen/tagged-schema checks.
- Full baseline `.venv\Scripts\python.exe -m pytest` — collected 6,308 tests
  but exceeded the 604-second inspection limit; exit 124. No full-suite pass is
  claimed.
- A subsequent exact `make check schema-check` run remained responsive and
  CPU-active in the full-suite `pytest` target but exceeded the 3,604-second
  command limit; exit 124. The runner emitted no buffered failure summary, and
  no full-suite or aggregate `make` pass is claimed.

The `101 passed` count above is the exact historical generation-1 result. It
does not cover the corrective code at `R2` and must not be presented as a
post-amendment result. Before generation-2 closure, a fresh full verification
run must target exact `R2`. The replacement BOOT completion receipt records its
exact command, `subject_commit=R2`, host-unattested start/completion
observations, collected/passed/skipped/failed counts, exit code, and observation
basis; the generation-2 bundle binds that receipt.

The preparation-time fresh-process governance check is not a human acceptance
check. A strict ceremony check is a separate invocation of the frozen external
PowerShell runtime launcher, which starts the absolute base interpreter with
the exact `-I -S -B` profile after the human-signature phases and closure
commit.

## Verification and limitations

The preparation-time tests cover strict JSON, schemas, digest canonicalization,
bounded validity, stale-estimate rejection, ledger/forecast math, real SSHSIG
verification/tampering, local-only roadmap provenance, process-serialized and
plan-bound journal recovery after a process crash, hash-pinned tools, hostile
Git configuration, a frozen isolated Python runtime, closed schema-format
validation, durable Git closure validation, and the signed current-gate
attestation/tag round trip including noncanonical-message rejection. Windows
sudden-power-loss atomicity or durability is not established. Roster semantics
also fail closed when required roles, assignments, conflicts, or capacity
statements drift.

Preparation-time limitations: `NO_INDEPENDENT_REVIEW`; public-key fingerprint
confirmation, roster approval, both kickoff signatures, all forecast decisions,
result-commit review, and completion/bundle signatures are all pending in the
pre-acceptance preparation state; so is the final current-gate attestation signature
and tag. Windows Time service attestation was unavailable, and
the recorded full repository test run timed out. Permanent scope limitation: S1
has no production, method-admission, qualification, release, deployment, or
runtime authorization effect.

Generation-1 `signed_at_utc` values are signer-declared, host-unattested times;
SSHSIG proves claim integrity and key possession but supplies no timestamp. The
generation-2 current-acceptance envelope therefore claims no actual signature
time.

## Acceptance receipt

Purpose: `development_design_acceptance`. The initial proposal names `acblabs`
as accepting human, with approval and signature still pending. If the human
later completes the documented ceremony, the signed receipt binds this exact
report, every reviewed artifact and its raw-byte digest, the approved roster
digest, kickoff digest, base/result commits, validity interval, conflicts,
competence scope, and allowed operations. The governance tool prepares claims
and verifies externally created signatures; it cannot access a private key or
sign for the human.

The generation-1 `R` had exactly the 29-path net scope enumerated in the
governance README, and its direct-child `C` contained the two signed completion
receipts and `governance-bundle.json`. Those immutable objects remain
historical. Until the replacement receipt is accepted, its SSHSIG verifies,
and strict generation-2 `R2`/`C2` plus v2 signed-tag validation succeeds, S2
remains prohibited. Even then the evidence cannot satisfy an independent
qualification or authorize release.
