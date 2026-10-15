# ADR 0016: V1 repository map and S1 planning governance

- Identifier: `ADR-V1-MAP`
- Preparation lifecycle status: proposed; authoritative status comes only from
  signed governance records and a validated Git closure
- Receipt purpose: `development_design_acceptance`
- Approval mode: `maintainer_development`
- Authoring agent: LLM implementation agent acting under the user's bounded S1
  instruction
- Accountable approving person: `acblabs` (`technical_lead`,
  `repository_maintainer`); phase-1 approval signatures are verified in the
  result commit
- Independent reviewer: `NO_INDEPENDENT_REVIEW`
- Conflict: the same sole maintainer directs and accepts S1 development work; no
  independent claim is made
- Baseline tag object: `ea4b50bd461efd817b7dc2fa5591d06ed9599a6e`
- Baseline tag commit: `3b060f4da94f4d0d80e7ae507580fce82ef9bf96`
- Feature-branch base commit: `3b060f4da94f4d0d80e7ae507580fce82ef9bf96`

The exact Markdown file digest is bound by the external `ADR-V1-MAP` acceptance
receipt. It is not embedded here because a file cannot contain its own raw-byte
digest without a self-reference.

## Context and authority

Agent Assure v1 extends an established local-first assurance compiler. S1 is a
noninstallable governance baseline, not a package release and not permission to
edit production behavior. This record maps actual repository contracts and
freezes the planning-governance rules needed before S2. Later ADRs remain
responsible for evidence, authorization, statistical, I/O, release-registry,
schema, formal, and process semantics.

The user designated one human owner and delegated implementation drafting to
LLMs. LLMs may inventory, draft, calculate, and test, but cannot supply a human
approval or independent-review receipt. The roster therefore staffs only the
two roles needed for S1 and leaves future qualified roles explicitly unfilled.

## Verified Git baseline

The authorized remote is `https://github.com/acblabs/agent-assure.git`.
`git fetch --prune origin main --tags` completed with exit code 0. The fetch was
observed at `2026-10-15T15:10:22.477094Z` using maintainer-trusted host UTC;
Windows Time service attestation was unavailable. The immutable post-fetch
identities are:

| Identity | Object |
| --- | --- |
| `origin/main^{commit}` | `3b060f4da94f4d0d80e7ae507580fce82ef9bf96` |
| `v0.7.0^{object}` | `ea4b50bd461efd817b7dc2fa5591d06ed9599a6e` |
| `v0.7.0^{commit}` | `3b060f4da94f4d0d80e7ae507580fce82ef9bf96` |
| S1 branch base | `3b060f4da94f4d0d80e7ae507580fce82ef9bf96` |

`v0.7.0` is an annotated tag. The tag commit and fetched `origin/main` are
identical, so their tracked-tree delta is empty. The working branch
`feat/v1-assurance-compiler` was created at that exact commit. Before this S1
inspection, local `HEAD` was
`366bbc89d7e3d0bca8c210d62a6c57ddeff8ff1b` and the local `origin/main`
tracking ref was `7bb928c74bc089ef422c5c895d1297bde94424a9`. Neither stale local identity is
the v1 base.

The private implementation roadmap has raw-byte digest
`sha256:8fc2e6e6f83b6a6ac6c27492473de8690b9360eac584131b6e8b42785f4386eb`.
It is excluded through `.git/info/exclude`, not a versioned ignore rule. The
unrelated `.claude/settings.local.json` remains user-owned and outside S1.

The baseline inventory was closed at `2026-10-15T18:05:09.407800Z`. Python was
`3.12.13`; `pip check` passed; the current CLI rejected
`agent-assure test activate` with exit code 2 because no `test` command exists,
so the future surface is available. Baseline Ruff and mypy runs passed. The full
repository pytest run collected 6,308 tests but exceeded the 604-second
inspection limit and exited 124; this record does not claim a full-suite pass.
The exact commands, outcomes, observation times, and limitations are bound in
`baseline-observations.json`.

The governance entry point requires the frozen PowerShell launcher and absolute
base CPython 3.12.13 interpreter with the exact `-I -S -B` profile. Before
Python starts, the launcher uses the explicit Windows/.NET trust base to verify
all 2,766 non-cache base-runtime files, reject sourceless bytecode and reparse
points, clear OpenSSL code-loading variables, constrain executable search, and
create a fresh pre-start bytecode-cache prefix. The Python bootstrap rechecks
that inventory, the interpreter and DLL identities, closed standard-library
path, absence of `site`/`.pth` startup, and the exact allowlisted third-party
runtime inventory; direct Python invocation is rejected.
Governed subprocesses are likewise bound to the recorded Windows host
identities for the real Git binary, its HTTPS transport helper, and OpenSSH
`ssh-keygen` by absolute path, byte length, and SHA-256 digest. `PATH` is not a
trust source. Every Git invocation disables hooks through a fresh empty
directory and rejects repository configuration capable of changing object
resolution, status, or transport. Acceptance-time remote evidence is queried
and fetched from the literal approved HTTPS URL in a temporary bare repository
with system, global, and working-repository configuration excluded. A tool or
runtime upgrade is a reviewed governance-input change, not an implicit
continuation of the baseline.

## Version identities and compatibility boundary

Package, writer schema, method, adapter, and planning-contract versions are
separate identities:

| Identity | Current value | Source |
| --- | --- | --- |
| Python package | `0.7.0` | `pyproject.toml` |
| Current writer schema | `0.6.6` | `src/agent_assure/__init__.py`, `schema/base.py` |
| Supported Python declaration | `>=3.11` | `pyproject.toml` |
| S1 planning contract | `delivery-forecast/v1` | `docs/governance/v1/` |
| Roadmap specification | `6.5` | private roadmap input |

No equality between these versions is implied. Released `schemas/v*` snapshots
are immutable. New writer resources stage under the existing unreleased/export
workflow and may move to a new version only through the accepted schema ADR and
S3 implementation receipts.

## Verified repository anchors

These symbols and paths exist at the pinned integration commit and are the
reuse boundary. `RunRecordV04` does not exist and must not be invented.

| Responsibility | Verified anchor |
| --- | --- |
| Run and field provenance | `AgentRunRecord`, `StructuredFieldOrigin` in `src/agent_assure/schema/run.py` |
| Framework observations | `FrameworkObservation` in `src/agent_assure/adapters/base.py` |
| Stream identity and coherence | `StreamSequenceContract`, `StreamEventRecord`, `StreamRunRecord` in `src/agent_assure/schema/stream.py` |
| Typed evidence | `AssuranceEvidenceDescriptor` in `src/agent_assure/schema/mutation.py` |
| Evidence packet | `EvidencePacket` in `src/agent_assure/schema/packet.py` |
| Existing gate behavior | `GateOutcome`, `GateDecision`, and `gate_*` functions in `src/agent_assure/ci.py` |
| Strict model boundary | `src/agent_assure/schema/base.py`, `schema/validation.py` |
| Canonical identity | `src/agent_assure/canonical/` |
| Rooted/no-clobber I/O | `artifact_io.py`, `rooted_io.py`, `artifact_transaction.py` |
| Statistical helpers | `src/agent_assure/statistics/` |
| Existing temporal/structural analysis | `live/trajectory.py`, `live/drift.py` |
| Policy and trust | `policies/`, `release_trust/` |
| Reporting | `reporting/` and the existing release manifest contracts |
| OTel compatibility | `compat/otel_mapping_matrix.yaml`, `compat/otel_genai_semconv.lock` |

The OTel lock declares a local snapshot identity; this record does not upgrade
it to an independently verified upstream commit.

## Owned file map and dispatch gates

The following exact existing roots are the permitted extension surfaces.
Creating a new file under one of them still requires the owning ticket's
accepted design and file-scope receipt. S1 itself changes none of them.

| Work area | Existing/owned paths | Gate before production edit |
| --- | --- | --- |
| Event coverage, closure, and order | `src/agent_assure/schema/stream.py`, `src/agent_assure/streaming/` | `ADR-V1-EVIDENCE`, then `SCHEMA-01A/D` where a writer changes |
| Provenance and run compatibility | `src/agent_assure/schema/run.py`, `src/agent_assure/adapters/base.py` | `ADR-V1-EVIDENCE` and `ADR-V1-SCHEMA` |
| Production wire models | `src/agent_assure/schema/`, `schemas/unreleased/`, generated future snapshot | `ADR-V1-SCHEMA`; never edit a released snapshot |
| Canonical projections and digests | `src/agent_assure/canonical/` | Owning semantic ADR plus compatibility tests |
| Authorization compiler and policy | `src/agent_assure/policies/`, `src/agent_assure/ci.py`, future modules mapped by `ADR-V1-AUTH` | `ADR-V1-AUTH`; legacy gate authority must remain distinct |
| Trust and release registry | `src/agent_assure/release_trust/`, release tooling under `src/agent_assure/cli/` | `ADR-V1-RELEASE-REGISTRY` |
| Numerical/statistical methods | `src/agent_assure/statistics/` | `ADR-V1-NUM-STAT`; qualified use additionally needs method admission |
| Temporal and structural analysis | `src/agent_assure/live/trajectory.py`, `live/drift.py`, related schema modules | Applicable evidence/process ADR and schema receipt |
| Framework integrations | `src/agent_assure/adapters/`, `docs/integrations/`, optional lock files | Exact adapter ticket and qualification boundary |
| OTLP/MCP import | `src/agent_assure/telemetry/`, `streaming/`, the two verified `compat/` files | Import/schema design acceptance |
| Reporting and OSCAL | `src/agent_assure/reporting/`, downstream manifest resources | Packet finalization first; OSCAL cannot strengthen evidence |
| Formal/intervention research | Existing `runner/` and `mutation/` boundaries; any new root requires an explicit map amendment | ADR 0015 amendment or intervention design receipt |
| Public CLI | `src/agent_assure/cli/main.py` and a ticket-owned command module | Exact command authority and compatibility tests |
| S1 governance only | `docs/governance/v1/`, this ADR, `scripts/v1_s1_governance.ps1`, `scripts/v1_s1_governance.py`, governance tests | S1 maintainer-development scope |

This map reserves roots; it does not authorize cross-ticket edits or silently
approve semantics. An unmapped production root requires an `ADR-V1-MAP`
amendment.

## CLI reservation

The current Typer root exposes no `test` command group, and repository search
found no `activate` collision. The exact future public activation path is
reserved as:

```text
agent-assure test activate
```

`V1-STAT-06` owns implementation. There may be no alias, force flag,
environment-variable bypass, direct-function bypass, or preview-skip route.
An incompatible future collision blocks implementation for a roadmap/map
amendment. This command performs statistical-state activation only and can
never emit deployment authorization.

## Framework integration decision

LangGraph 1.x is the selected stable-v1 reference framework, but the current
code is accurately classified as experimental:

- package declaration: `langgraph>=1.0,<2`;
- locked development identity: `langgraph==1.2.9`;
- lock SHA-256:
  `b4e6deb32a38c87a44f3ed7e637230ee36b02ba0f6c29e4e196601db3c90d977`;
- current adapter identifier: `experimental-langgraph`;
- current projection: privacy-filtered fixture-mode observations, not a
  qualified approval/consumption authority.

The initial release-bearing support target is the exact locked version 1.2.9.
The wider dependency declaration is install compatibility, not qualification.
Broadening release-bearing support requires a tested version matrix and a map
amendment or accepted adapter decision. Stable implementation must add typed
approval issuance, action/tool consumption, closure, and order instrumentation
without treating free-form metadata as authority. Until that surface is
implemented and qualified, an authorization request that depends on it fails
closed with `UNSUPPORTED_INTEGRATION`.

Google ADK remains `experimental-google-adk`:

- package declaration: `google-adk>=2.4,<3`;
- lock identity: `google-adk==2.4.0`;
- lock SHA-256:
  `a047eeb295573937b6643b4a8b3ab6d79a356aa73c8d3a1de274a150dd0530c1`.

Its current importability, examples, or tests do not admit it for stable-v1
authorization.

## Dependency and generated-schema contracts

Core dependencies remain the six direct runtime declarations in
`pyproject.toml`: Pydantic, Typer, Rich, PyYAML, RFC 8785, and JSON Schema.
Optional dependency groups are `adk`, `langgraph`, `otel`, and `dev`; NumPy is
absent from the core and inspected optional locks. Lock files are authoritative
for their selected environment, and optional imports must fail with a typed
unsupported disposition rather than changing semantics. The resolved lock
closures contain 78 distributions for the core/development lock, 101 for the
LangGraph lock, and 106 for the Google ADK lock. Relevant raw lock digests at
the baseline are:

| File | SHA-256 |
| --- | --- |
| `requirements.lock` | `9d127f21617573476278605601f131c875d4def7c102aca5cdd39dda4f261ee4` |
| `requirements-langgraph.lock` | `b4e6deb32a38c87a44f3ed7e637230ee36b02ba0f6c29e4e196601db3c90d977` |
| `requirements-adk.lock` | `a047eeb295573937b6643b4a8b3ab6d79a356aa73c8d3a1de274a150dd0530c1` |

`agent-assure schema export`, `scripts/schema_target.py`,
`scripts/sync_schema_force_includes.py`, and the Makefile schema checks are the
actual generation and verification path. Frozen snapshots through v0.6.6 are
packaged explicitly. A producer migration must preserve source identity and
declare defaults and losses; it cannot invent order, authority, coverage, or a
historical pass.

## Delivery forecast contract

The planning schema is frozen at
`docs/governance/v1/delivery-forecast.schema.json`, outside production schema
snapshots. `scripts/v1_s1_governance.py` parses the private roadmap read-only,
rejects duplicate JSON keys and unsafe JSON values, derives exact ticket and
occurrence coverage, and recomputes every aggregate and digest.

Digest strings use lowercase `sha256:<hex>`. Except for the raw roadmap digest,
each digest is:

```text
SHA256(ASCII(domain) || 0x00 || RFC8785(projection))
```

The domains and projections are:

| Field | Domain / projection |
| --- | --- |
| `full_roadmap_digest` | SHA-256 of exact roadmap bytes |
| `sorted_ticket_set_digest` | `agent-assure:roadmap-ticket-set/v1`; sorted ticket IDs |
| `dependency_graph_digest` | `agent-assure:roadmap-dependency-graph/v1`; ticket-sorted dependency rows |
| `release_train_digest` | `agent-assure:roadmap-release-train/v1`; complete release-train object, preserving array order |
| method digest | `agent-assure:delivery-forecast-aggregation-method/v1`; method definition excluding its digest |
| aggregation registry | `agent-assure:delivery-forecast-aggregation-registry/v1`; registry excluding its digest |
| authoring ledger | `agent-assure:delivery-forecast-authoring-ledger/v1`; ledger excluding its digest |
| forecast record | `agent-assure:delivery-forecast/v1`; record excluding `record_digest`, `signature_envelope`, and `acceptance_receipt` |
| acceptance receipt | `agent-assure:governance-receipt/v1`; receipt excluding its digest and signature |
| baseline observations | `agent-assure:baseline-observations/v1`; observations excluding their digest |
| kickoff/completion/bundle | their versioned `agent-assure:*` domains; semantic projection excluding digest and signature envelope |

The current source snapshot contains 68 tickets and 121 ordered ticket
occurrences across 39 releases. Counts are diagnostic consequences of the
source, not substitutes for set/order validation.

For S1, both ticket starts may become ready together, but the roadmap's
deterministic Kahn ordering places `BASE-01F`, `V1-BASE-01` close, and then
`V1-BOOT-01` close. That total-order tie-break is validated for signature
chronology without misrepresenting it as an additional dependency edge.

### Effort authoring

One focused-engineer day is exactly eight accountable effort hours. Effort is
not wall-clock duration or unattended LLM runtime. For a repeated
`ticket_completion` scope, the roadmap's integer-hour total prior is split by
`divmod(total_hours, occurrence_count)`: each occurrence receives the quotient
and the first remainder occurrences in release-train order receive one extra
hour. Per-execution scopes receive one proposal per declared occurrence. Every
occurrence must then be explicitly marked
`affirmatively_reconfirmed_after_inventory` or
`reestimated_after_inventory` by the accountable maintainer; pending proposals
cannot authorize S2 commitment.

The aggregation method is `comonotonic-quantile-sum/v1`, definition digest
`sha256:46bf522f3a3809085bb411835fb495e4b78349a808b12bd584a4c2f1fc4a29df`.
Its one-entry immutable registry digest is
`sha256:67f74a2a8f66c7ccb43d29dd1d224a823789659816eed3af2220a64f1973aca3`.
For a shared latent severity rank, occurrence efforts are comonotonic, so the
sum's modeled P50 and P90 are the sums of occurrence P50s and P90s. Reviewer
effort is also additive. This is a tail-aligned planning model, not a
distribution-free bound, confidence interval, or calendar forecast. It makes
the dependence assumption explicit and avoids unsupported Monte Carlo or
copula precision from only two input quantiles.

The authoring ledger is cryptographically bound to the baseline-observations
digest and inventory-completion time. Its issue time cannot predate that
inventory, and a confirmation cannot predate the inventory or postdate the
ledger issue. Forecast, kickoff, completion, and bundle validity intervals are
half-open and cannot exceed 30 days. Each forecast row preserves its earliest
actual row/occurrence confirmation time (or the ledger issue time while wholly
pending), and forecast expiry cannot exceed 30 days after the oldest such row
time. A fresh wrapper therefore cannot renew stale estimate decisions. The
initially checked-in forecast and ledger are proposals. Their estimates,
assumptions, trusted-time basis, and
unsigned envelopes have no acceptance effect. Windows Time attestation was
unavailable (`w32tm` service not started), so S1 uses maintainer-trusted host
UTC only if the maintainer explicitly accepts that development-governance time
basis.

Every signed record uses Ed25519 OpenSSH SSHSIG with namespace
`agent-assure-governance-v1`, SHA-512 message hashing, canonical 70-column LF
armor, and canonical outer base64. The signed bytes are a domain-separated RFC
8785 claim binding signer ID, role, subject digest, public-key fingerprint, and
signature time. The repository-local public key is TOFU metadata: successful
verification proves possession of that key, not legal identity, independence,
or qualification.

## Seed allocation

S1 reviews seed meanings but does not build their production schemas:

| Seed | Retained result | Production-schema conversion owner(s) |
| --- | --- | --- |
| `AUTH-003` | Missing supported required evidence means `release_authorized=false` | `V1-AUTH-01` |
| `TEMP-006` | Open approval-channel/required history remains `inconclusive` | `V1-EVID-02` |
| `TRUST-001` | A signed model self-report retains `model_self_report` origin and is not independently eligible | `V1-TRUST-01` |
| `STAT-010` | Moments-only restart state is invalid with `REPLAY_STATE_INSUFFICIENT` | `V1-STAT-01` |
| `IO-001` | A missing manifest chunk makes execution evidence invalid | `V1-IO-01` |
| `GOV-001` | Authorized `maintainer_development` inventory is permitted | `V1-BOOT-01`; downstream `V1-BASE-06`, `V1-REL-01` |
| `GOV-002` | Authorized maintainer decision drafting is permitted | `V1-BOOT-01`; downstream `V1-BASE-06`, `V1-REL-01` |
| `GOV-003` | Authorized maintainer sandbox prototyping is permitted | `V1-BOOT-01`; downstream `V1-BASE-06`, `V1-REL-01` |
| `GOV-004` | Maintainer mode cannot perform method admission | `V1-BOOT-01`; downstream `V1-BASE-06`, `V1-REL-01` |
| `GOV-005` | Maintainer mode cannot issue qualified release approval | `V1-BOOT-01`; downstream `V1-BASE-06`, `V1-REL-01` |
| `GOV-006` | One person under two labels cannot satisfy peer implementation review | `V1-BOOT-01`; downstream `V1-BASE-06`, `V1-REL-01` |
| `GOV-007` | Qualified distinct-person peer review is permitted in peer-reviewed mode | `V1-BOOT-01`; downstream `V1-BASE-06`, `V1-REL-01` |
| `GOV-008` | Method admission needs qualified admission, accepted independence, and a qualification receipt | `V1-BOOT-01`; downstream `V1-BASE-06`, `V1-REL-01` |
| `GOV-009` | Method admission fails when external review is required but the reviewer is not external | `V1-BOOT-01`; downstream `V1-BASE-06`, `V1-REL-01` |
| `GOV-010` | Inventory without an owner is not permitted | `V1-BOOT-01`; downstream `V1-BASE-06`, `V1-REL-01` |
| `GOV-011` | Pre-mode read-only inventory needs direct named-maintainer authorization | `V1-BOOT-01`; downstream `V1-BASE-01`, `V1-BASE-06` |
| `GOV-012` | The same pre-mode inventory without named authorization is not permitted | `V1-BOOT-01`; downstream `V1-BASE-01`, `V1-BASE-06` |

These are reviewed semantic allocations, not implemented production fixtures or
proof that the downstream contracts already exist.

## Alternatives, risks, and compatibility

- Treating the stale local tracking ref as authoritative was rejected; the
  fetched remote and tag are now identical and pinned.
- Promoting the existing LangGraph adapter by renaming it was rejected; its
  fixture-mode evidence surface lacks the future stable authority contract.
- Treating the broad optional dependency range as qualification was rejected;
  initial release-bearing support is the exact lock identity.
- A simulated probabilistic aggregate was rejected because two quantiles do
  not identify occurrence distributions or dependence. The selected model is
  explicit, deterministic, and deliberately conservative about dependence.
- LLM-generated estimates and machine-prepared signature claims are not human
  decisions or signatures. The governance program has no private-key input and
  cannot sign; only the maintainer can review and externally sign a claim.
- The host's unavailable time service weakens time provenance. This is visible
  and blocks silent claims of externally attested time.
- The local private roadmap exclusion can be overridden by a forced add;
  reviewers must verify it is absent from the index before any commit.

## Stage-specific acceptance

The initial draft-completion state requires this map, the closed planning
schema, the immutable method definition, all 68 ticket proposals, all 121
occurrence proposals, and successful structural/digest validation. This is a
non-accepting state.

Development-record acceptance is a human-only, three-phase signing ceremony
with seven SSHSIGs. A final eighth SSHSIG attests the live closure gate. The
governance program may prepare canonical claims, verify public-key signatures,
and install verified record batches under a process lock with a plan-bound
recovery journal, but it never reads or uses the private key and never signs on
the human's behalf. This establishes process serialization and recovery after a
process crash; Windows sudden-power-loss atomicity or durability is not
established. The steps are ordered:

1. The maintainer explicitly affirms identity, scope, conflicts, capacity,
   absence of a backup, private-key control, and the unattested-host-UTC
   limitation; reviews all ticket and release-occurrence decisions; and
   externally signs the two kickoff and two forecast predecessor claims.
2. After reviewing and creating result commit `R`, the maintainer externally
   signs the BASE completion claim and then the BOOT completion claim.
3. After both signed receipts verify, the maintainer externally signs the
   governance-bundle claim.
4. At clean closure `C`, the validator performs the isolated authoritative
   remote check and prepares a current-gate attestation. The maintainer reviews
   it and externally signs its claim within one hour; the verified signed
   record becomes the exact message of fixed annotated tag
   `agent-assure-s1-1.0.0a1-acceptance`.

`R` must be the direct, non-merge child of pinned base
`3b060f4da94f4d0d80e7ae507580fce82ef9bf96`. Its base-to-result diff must
contain every and only the 29 regular-file additions or modifications listed in
the governance README under "Reviewed result commit R" and may use only `A` or
`M` status. The two completion receipts and `governance-bundle.json` are
deliberately outside `R`, because they attest `R`.

Closure commit `C` must be the direct child of `R` and must add or modify every
and only these three paths:

- `docs/governance/v1/completion-receipt-v1-base-01.json`;
- `docs/governance/v1/completion-receipt-v1-boot-01.json`;
- `docs/governance/v1/governance-bundle.json`.

The one-time current gate requires a clean checkout exactly at `C` and a fresh
isolated authoritative query/fetch of main and the annotated `v0.7.0` tag;
strict `--accept-now` checking fails unless `--fetch-authoritative-refs` and a
new local attestation plan are supplied. That check prepares evidence but does
not itself claim acceptance. Later historical checking requires the explicit
full 40-hex `C` and annotated-tag object, derives commitment time from the
embedded human SSHSIG, reads the governed records from `C`, and proves that `C`
is the unique valid closure on the current `HEAD` lineage. A caller cannot
replace the signed time with a convenient historical timestamp. Exact frozen,
absolute launcher, interpreter, and tool identities, isolated launcher ceremony
commands, claim names, tag construction, and staging pathspecs are specified in
the governance README.

Qualification and admission are outside S1. `NO_INDEPENDENT_REVIEW` cannot
satisfy any later independent qualification, method admission, pilot, or
release requirement. The authoritative, concrete future staffing,
execution-authorization, receipt, pilot, and release sequence is recorded as
the three nonauthorizing qualification-plan limitations in
`docs/governance/v1/approval-roster.json`; it remains wholly pending.

## Approval and remaining work

During pre-acceptance preparation, the machine-authored S1 proposal was
implemented and structurally testable while every accountable human approval
and signature remained pending. That preparation-state statement is historical
and does not attempt to mirror mutable status. Acceptance exists only if the
signed records, exact `R`/`C` Git scopes, and signed fixed-tag attestation pass
the historical strict validator. A pending draft authorizes no production
feature edit or S2 commitment.
