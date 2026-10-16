# Ticket completion report: V1-BASE-01

- Ticket ID / dispatch kind: `V1-BASE-01` / `inventory`
- Target profile / approval mode: `stable-core` / `maintainer_development`
- Owner and author identities: the initial proposal names `acblabs`
  (`technical_lead`) as owner; inventory and implementation artifacts were
  drafted by LLM agents under the user's bounded S1 instruction
- Reviewer identity, competence and conflicts: the initial proposal names
  `acblabs` (`repository_maintainer`), competent only for the recorded S1
  planning and bounded-development scopes; same-person self-review conflict
  declared; `NO_INDEPENDENT_REVIEW`
- Base / result commit: base
  `3b060f4da94f4d0d80e7ae507580fce82ef9bf96`; during report preparation, result
  commit `R` was not yet created or human-reviewed; an accepted receipt must
  bind its full 40-hex identity
- Approved file scope: repository inventory, `ADR-V1-MAP`, planning-governance
  schemas/records, validator, tests, and build/docs integration only; no
  production package files
- Required scoped receipt: `development_design_acceptance`; its pre-acceptance
  template is pending human review and signature

This report intentionally preserves preparation-time facts. It does not mirror
mutable acceptance status: only the signed completion receipt, signed bundle,
exact closure commit `C`, and verified signed fixed-tag attestation can
establish an eventual accepted state.

Corrective note: the generation-1 report remains evidence of what was prepared
and run at that time; it is not the current S2 acceptance basis. Generation 2
re-estimates all 68 rows and 121 occurrences after inventory and binds the
replacement evidence through the linear successor `C1 -> R2 -> C2` and fixed
tag `agent-assure-s1-1.0.0a1-acceptance-v2`.

## Prepared evidence

The initial stage delivers a machine-validated inventory and forecast proposal:

- verified remote/tag/base identities and a versioned repository reuse map;
- explicit package, writer-schema, CLI, dependency-lock, adapter, schema-export,
  and production file-boundary contracts;
- a baseline-observations record with commands, outcomes, trusted-time limits,
  raw lock digests, and hash-pinned Git/HTTPS/OpenSSH executable identities;
- a separate bounded `V1-BASE-01` kickoff authorization;
- an immutable one-entry aggregation registry;
- a baseline-bound authoring ledger with all 68 tickets and all 121 ordered
  occurrences;
- a recomputable `delivery-forecast/v1` proposal and closed Draft 2020-12
  schemas;
- ticket completion and S1 governance-bundle contracts that remain explicitly
  noninstallable and nonauthorizing.

## Requirement and change traceability

- Roadmap section 2 and `BASE-01F`: every ticket ID, dependency edge, release
  occurrence, estimate scope, per-occurrence estimate, confidence, risk, status,
  and trusted issue time is bound and recomputed.
- Authorized remote: `https://github.com/acblabs/agent-assure.git`; fetched
  `origin/main` and annotated `v0.7.0` both resolve to the pinned base commit.
- CLI reservation: `agent-assure test activate`; the current CLI has no `test`
  group, and the probe exits 2 with no collision.
- LangGraph: declared `>=1.0,<2`, locked at `1.2.9`, still experimental until
  later typed instrumentation and qualification. Google ADK remains
  experimental and locked at `2.4.0`.
- Aggregation: `comonotonic-quantile-sum/v1`, method digest
  `sha256:46bf522f3a3809085bb411835fb495e4b78349a808b12bd584a4c2f1fc4a29df`,
  registry digest
  `sha256:67f74a2a8f66c7ccb43d29dd1d224a823789659816eed3af2220a64f1973aca3`.
  Portfolio proposals total 5,480 P50 effort hours, 9,008 P90 effort hours,
  and 2,056 P50 reviewer hours. These are additive effort quantiles under full
  positive rank dependence (comonotonicity), with no diversification credit.
  They are not calendar promises, confidence bounds, or distribution-free
  upper bounds. These generation-1 values were derived from stale priors and
  are not valid inputs to S2 planning.
- Semantic seeds `AUTH-003`, `TEMP-006`, `TRUST-001`, `STAT-010`, `IO-001`,
  `GOV-011`, and `GOV-012` are allocated to exact downstream conversion owners;
  no production fixture is claimed at S1.
- Preserved compatibility: package version `0.7.0`, writer schema `0.6.6`,
  released schemas, production policy, and runtime behavior are unchanged.

Changed artifacts in this ticket's reviewed set are enumerated and raw-byte
hashed by the completion-receipt generator. The private roadmap is input only,
locally excluded, absent from the index/history, and never copied into an
artifact.

## Commands actually executed

Working directory: repository root on Windows; Python `3.12.13` in `.venv`.

- `git fetch --prune origin main --tags` — exit 0; observed at
  `2026-10-15T15:10:22.477094Z` using maintainer-trusted host UTC.
- Git ref/tag/diff/branch probes — fetched main and tag commit equal the pinned
  base; tag object is `ea4b50bd461efd817b7dc2fa5591d06ed9599a6e`; no tracked-tree delta.
- `w32tm /query /status` — unavailable, exit `-2147023834`; Windows Time
  service was not started.
- `.venv\Scripts\agent-assure.exe test activate --help` — exit 2; no `test`
  command group exists.
- `.venv\Scripts\python.exe -m pip check` — exit 0; no broken requirements.
- `.venv\Scripts\python.exe -m ruff check .` — passed repository-wide.
- `.venv\Scripts\python.exe -m mypy src scripts` — passed for 291 source files.
- `.venv\Scripts\python.exe -m pytest
  tests/unit/governance/test_v1_s1_governance.py` with a repository-writable
  temporary root — 101 passed.
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
post-amendment result. Generation-2 closure requires a fresh run against exact
`R2`; its command, subject commit, host-unattested start/completion observations,
collected/passed/skipped/failed counts, exit code, and observation basis are
recorded in the replacement BOOT completion receipt and bound by the bundle.

## Verification and limitations

The preparation-time focused suite covers strict JSON and RFC 8785, digest
domains, 30-day validity boundaries, frozen aggregation math, occurrence
allocation, ledger and schema tampering, contradictory accepted states, real
ephemeral Ed25519 SSHSIG attacks, local-only roadmap history,
process-serialized journaled batch rollback and recovery after a process crash,
durable closure discovery after later descendants, the acceptance-time HEAD
gate, and contaminated closure rejection. Windows sudden-power-loss atomicity
or durability is not established. It also covers stale-estimate renewal,
frozen-runtime and executable identity drift, closed schema-format semantics,
hostile local Git configuration, and the signed current-gate attestation/tag
round trip including noncanonical-message rejection. Accepted
Git-provenance validation rejects replace refs, alternate stores, shallow or
grafted history, nonlinear/unauthorized intermediate commits, nonregular blobs,
and divergent result commits.

Preparation-time limitations: `NO_INDEPENDENT_REVIEW`; the
roster/key/kickoffs, 68 row decisions, 121 occurrence decisions, forecast
signatures, result commit, completion receipts, and bundle signature are all
pending in the pre-acceptance preparation state; so is the final current-gate
attestation signature and tag. Windows Time service attestation was
unavailable, and the recorded full repository test run timed out. Permanent
scope limitation: S1 does not qualify LangGraph, Google ADK, a statistical
method, a profile, or a release.

Generation-1 `signed_at_utc` values are signer-declared, host-unattested times;
SSHSIG proves claim integrity and key possession but supplies no timestamp. The
generation-2 current-acceptance envelope therefore claims no actual signature
time.

## Acceptance receipt

Purpose: `development_design_acceptance`. The initial proposal names `acblabs`
as accepting human, with approval and signature still pending. If the human
later completes the documented ceremony, the signed receipt binds this exact
report, the complete reviewed artifact set, roster and kickoff digests,
base/result commits, competence/conflicts, validity interval, and allowed
operations. The governance tool prepares claims and verifies externally
created signatures; it cannot access a private key or sign for the human.

The generation-1 `R` had exactly the 29-path net scope enumerated in the
governance README, and its direct-child `C` contained the two signed completion
receipts and `governance-bundle.json`. Those immutable objects remain
historical. Only replacement evidence plus strict generation-2 `R2`/`C2` and
v2 signed-tag validation may permit use of the corrected map and forecast for
S2 planning; none can substitute for independent qualification, method
admission, or release authorization.
