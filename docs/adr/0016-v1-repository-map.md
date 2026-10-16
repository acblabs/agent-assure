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

## Repository map and dispatch gates

The following table is an architectural inventory of verified existing anchors,
not an exhaustive path allowlist and not authority to edit them. An omitted
existing path is not thereby "unauthorized." Concrete edit authority comes from
the owning ticket's accepted design and exact file-scope receipt. S1 itself
changes none of these production paths.

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
| Formal/intervention research | Existing `runner/` and `mutation/` boundaries; an omitted or new root must be called out in the accepted ticket scope | ADR 0015 amendment or intervention design receipt |
| Public CLI | `src/agent_assure/cli/main.py` and a ticket-owned command module | Exact command authority and compatibility tests |
| S1 governance only | `docs/governance/v1/`, this ADR, `.github/workflows/ci.yml`, `Makefile`, `mkdocs.yml`, both `scripts/v1_s1_governance.*` entry points, governance tests, and `tests/unit/release/test_coverage_gate.py` | Prospectively signed, exact S1 maintainer-development file scope |

This map identifies likely ownership and review gates; it does not authorize
cross-ticket edits or silently approve semantics. If implementation needs an
omitted or new production root, the ticket must identify that path explicitly
and explain its ownership before the edit. Amend this ADR when the omission
changes the architecture; a path-list omission alone is not a claim that the
path is forbidden.

For the corrective generation, the authoritative bounded list is
`tracked_allowed_paths` in the prospectively signed
`docs/governance/v1/corrective-kickoff-authorization.json`. That list, rather
than this summary table, determines whether an `R2` path was authorized.

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
| method digest | `agent-assure:delivery-forecast-aggregation-method/v2`; method definition excluding its digest |
| aggregation registry | `agent-assure:delivery-forecast-aggregation-registry/v2`; registry excluding its digest |
| estimation catalog | `agent-assure:delivery-forecast-estimation-catalog/v1`; catalog excluding `catalog_digest` |
| authoring ledger | `agent-assure:delivery-forecast-authoring-ledger/v2`; ledger excluding its digest |
| forecast decision manifest | `agent-assure:delivery-forecast-decision-manifest/v2`; exact ordered manifest excluding `manifest_digest` |
| forecast record | `agent-assure:delivery-forecast/v2`; record excluding `record_digest`, `signature_envelope`, and `acceptance_receipt` |
| forecast acceptance receipt | `agent-assure:delivery-forecast-acceptance-receipt/v2`; exact accepted receipt excluding its digest and signature |
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
not wall-clock duration or unattended LLM runtime. Every roadmap estimate whose
basis is `provisional_before_V1-BASE-01` is
`STALE_NOT_COMMITTABLE`: it may not seed a work-unit count, an occurrence
allocation, or an effort value. Generation 2 therefore requires all 68 ticket
rows and all 121 ordered occurrences to use
`reestimated_after_inventory`; mechanical reconfirmation is invalid.

The versioned `bottom-up-wbs/1` estimation catalog produces machine-authored,
nonbinding proposals. Each proposal binds the roadmap item and inventory
digests, repository anchors, a workload vector, and atomic work items covering
design, implementation, structured contracts, verification, fixtures/vectors,
documentation, CI/release operations, and review where applicable. For
`ticket_completion`, each source acceptance criterion is assigned exactly once
across the ticket lifecycle's occurrences. For repeated-execution scopes, every
criterion is covered exactly once per occurrence. Each declared work package is
assigned exactly once to its declared sprint, and every release-train occurrence
has one digest-bound anchor. Omissions and duplicate coverage fail closed.
Component P50, P90, and reviewer P50 person-hours are
checked integer sums of the versioned work-unit catalog. Elapsed waiting or
exposure time remains separate from accountable effort. The human maintainer
must review every row and occurrence, record a specific rationale, and sign the
digest-bound decisions; the generator cannot infer that judgment.

The aggregation method remains `comonotonic-quantile-sum/v1` version `1.1.0`,
represented by `agent-assure-delivery-forecast-aggregation-method/2` with
definition digest
`sha256:028ff736a0d4c7ac37a5fb15ba1ee733401a8be453569fc07b37fae6b27517f7`.
The `/2` registry digest is
`sha256:7cac700d33f41f97156f459bf48bae5e4c65d36505aab6cb7e5c2df4acae1ba6`.
The `agent-assure-delivery-forecast-estimation-catalog/1` digest is
`sha256:33cee0874eecf79f36a0dadcafa831525df206c9fdc67d9ab4759138475da439`.
The pending generation-2 authoring-ledger digest is
`sha256:c65573f5b9045c08b926e739c1e4491fc038bc203df80454697a23c36d4d9fbf`,
and the pending forecast record digest is
`sha256:66d1e5a2b29f0405bbd4ef0c10c74d17c7930fd5c7f93a9140b0abc0438d0220`.
Ledger and forecast records use format generation `/2`; the external planning
contract remains `delivery-forecast/v1`.

This block is an enforced handoff, not a claim that the pending proposal has
already been accepted. After the human imports, both lines must be updated to
the exact installed statuses and digests; generation-2 receipt planning fails
until this block and the governance README agree with those files.

<!-- agent-assure:forecast-v2-final:start -->
- Generation-2 authoring ledger status: `human_decisions_imported`; digest: `sha256:825e811fa5a0dc841e8f8a316b4fb5be1183dc5793bce90506928237ad7020ca`.
- Generation-2 delivery forecast status: `accepted`; digest: `sha256:61858dd4aaa04ee6dc202fba8384a2b264e9374e24eed7c7936793e331068b5b`.
<!-- agent-assure:forecast-v2-final:end -->

For a shared latent severity rank, occurrence efforts are comonotonic (full
positive rank dependence), so the sum's modeled P50 and P90 are the sums of
occurrence P50s and P90s. Reviewer effort is also additive. The model gives no
diversification credit. It is not a distribution-free upper bound, confidence
interval, or calendar forecast. It makes
the dependence assumption explicit and avoids unsupported Monte Carlo or
copula precision from only two input quantiles.

The generation-2 authoring ledger is cryptographically bound to the corrective
authorization, baseline observation, roadmap, release-train, ticket-set,
estimation-catalog, and inventory-completion evidence. Its machine proposal has
no human decision or confirmation time: all human-controlled fields remain null
until the maintainer reviews one exact, ordered batch manifest itemizing all 68
rows and all 121 occurrences. One timestamp-free SSHSIG binds every coverage,
workload-vector, WBS, proposal, selected-value, status, and rationale field; no
per-item review time is invented. After verified import, the estimates are
described as human-adopted subjective planning quantiles, not empirically
calibrated values, and unresolved file scope still requires dispatch
rebaselining. Forecast, kickoff, completion, and bundle validity
intervals are half-open and cannot exceed 30 days, and a fresh wrapper cannot
renew stale decisions. The initially checked-in forecast and ledger remain
nonbinding proposals; their estimates, assumptions, null trusted-time basis,
and unsigned envelopes have no acceptance effect. Windows Time attestation was
unavailable (`w32tm` service not started), so host UTC can be used only if the
maintainer explicitly accepts that limited development-governance basis.

Forecast development acceptance derives competence and conflicts from the
exact frozen approval roster, not from key possession or generic prose. The
receipt binds roster digest
`sha256:3959beb1e485be1d030540585e7d1cbd77e4b93fd487a5ae4ba7f8a98a3a1ca5`,
the `acblabs` identity, both staffed roles, all three declared competence
scopes, all three conflict disclosures, and `NO_INDEPENDENT_REVIEW`. Both the
schema and semantic recomputation reject a changed or incomplete binding.

Every signed record uses Ed25519 OpenSSH SSHSIG with namespace
`agent-assure-governance-v1`, SHA-512 message hashing, canonical 70-column LF
armor, and canonical outer base64. The signed bytes are a domain-separated RFC
8785 claim binding signer ID, role, subject digest, and public-key fingerprint.
Generation-1 envelopes also bind a signer-declared `signed_at_utc`. SSHSIG
itself contains no trusted timestamp, so verification proves possession of the
key and integrity of the declaration, not when the signature operation
occurred, legal identity, independence, or qualification. Generation-2
current-acceptance and forecast envelopes deliberately omit a signature time.
Forecast claim-preparation start and import-verification completion are
captured at their truthful boundaries as externally unattested host-UTC
operational observations; import-verification start is captured as well. After
both exact claims verify, all three observations are persisted identically in
the producer and acceptance envelopes. Validation enforces
`issue <= preparation <= import start <= import completion < expiry`. None is
represented as the signature time, and the evidence explicitly remains outside
the SSHSIG claim. The subsequent corrective closure inventory and signed
current-acceptance attestation bind the installed forecast bytes, forming the
durable integrity boundary for that post-signature evidence. The records state
that SSHSIG has no timestamp capability and that no actual signature time is
claimed.

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
  explicit and deterministic: it assumes full positive rank dependence and
  gives no diversification credit. No distribution-free bound interpretation
  is claimed.
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
with seven SSHSIGs. A final eighth SSHSIG binds the human's live-closure-gate
declaration; it does not independently timestamp the gate or signature. The
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
   it and declares a signing time within the one-hour policy window before
   externally signing its claim; the SSHSIG does not independently prove the
   operation time. The verified signed record becomes the exact message of the
   fixed annotated tag `agent-assure-s1-1.0.0a1-acceptance`.

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
human's signed declaration, reads the governed records from `C`, and proves
that `C` is the unique valid closure on the current `HEAD` lineage. A caller
cannot replace the signed declaration with a convenient historical timestamp,
but this is not independent timestamping. Exact frozen,
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
and does not attempt to mirror mutable status. Generation-1 acceptance could be
evaluated only if the signed records, exact `R`/`C` Git scopes, and signed
fixed-tag attestation passed the historical strict validator; the corrective
section below now governs current status. A pending draft authorizes no
production feature edit or S2 commitment.

## Corrective generation

An acceptance audit found that generation 1 was not a suitable current basis
for S2: every forecast occurrence retained a stale roadmap prior, and the
closure also lacked sufficiently explicit time-evidence, verifier-bootstrap,
long-path diagnostic, and post-amendment verification controls. This does not
rewrite the original evidence. Result `R1`
`038b1a8c80fc419106eecd43f4a70b14ba026106`, closure `C1`
`6165bc6436aada6cbeb4fc4119eafa9b5dfdb000`, tag object
`1f7bfe058dfb84d8cf4afaf971a57e5c3a12a5fb`, and tag
`agent-assure-s1-1.0.0a1-acceptance` remain immutable historical objects.

The corrective kickoff claim with digest
`sha256:4477162d48826c8cece417e78ef8dcb4a5ef3047c24bf0cdef20d8fb55ba1f60`
was imported and verified before the corrective branch was created and before
tracked corrective edits began. It prospectively authorizes only the bounded
engineering scope; it is not a retrospective authorization or a substitute for
the later per-estimate decisions, completion conclusions, or signatures.

The only current successor topology is linear: `C1 -> R2 -> C2`. `R2` is a
direct, non-merge corrective result; `C2` is its direct, non-merge signed
closure. The generation-2 fixed tag is
`agent-assure-s1-1.0.0a1-acceptance-v2`, and its message uses
`agent-assure-s1-current-acceptance-attestation/2`. Generation 2 requires all
68 ticket rows and all 121 ordered occurrences to be re-estimated after
inventory from obligation-covering work breakdowns rather than mechanically
reconfirming stale priors.

The generation-2 attestation signs a finalization deadline equal to the earlier
of gate completion plus one hour and bundle expiry. Before first publication,
and again before reporting idempotent reuse, the finalizer requires host now to
remain inside that half-open window and revalidates the live signed records,
exact clean `C2` topology, and pinned local refs. This is a bounded validator
freshness rule, not an SSHSIG signing-time claim; OpenSSH provides no such
timestamp.

The historical `101 passed` unit-test observations in the ticket reports remain
truthful records of their original run, not evidence that `R2` passed. The
replacement BOOT completion receipt binds a fresh post-amendment run to exact
`R2`, including command, host-unattested start/completion observations, outcome
counts, exit code, and observation basis. Windows CI additionally exercises
governance units, long-path blob reads, and synthetic-roadmap historical
validation without receiving the private roadmap. Hosted CI is not evidence of
the accepted maintainer host or its clock.

Historical verification of generation 2 uses a clean detached worktree at
`C2`. An external PowerShell precheck compares the launcher and validator file
hashes with the v2 attestation-bound values before executing either, and the
validator then checks its executing file and launcher bytes against the regular
Git blobs at `C2`. A program's self-reported hash and its Python `main()` import
guard are consistency and misuse controls, not a security boundary or trust
root. S2 remains prohibited until the replacement signatures, `C2`, fixed v2
tag object, and this generation-aware historical validation all succeed.
