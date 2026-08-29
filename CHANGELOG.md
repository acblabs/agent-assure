# Changelog

## Unreleased

## 0.6.5 - 2026-08-29

- Introduced privacy detector profile v3. It normalizes Unicode dash
  equivalents, prevents non-ASCII case-folding from bypassing detector-marker
  pruning, treats every non-empty value under a sensitive label as sensitive,
  fails closed on non-ASCII structured keys, rejects
  inline persisted live-script credentials, and bounds/redacts untrusted YAML
  diagnostics.
- Made deterministic and stochastic directory-publication locks best-effort
  one-millisecond coordination only; planted or held predictable lock entries
  can no longer block publication. Atomic no-replace installation plus exact
  generation adoption is the integrity boundary. Multi-file finalization keeps
  its explicit 60-second rooted-lock deadline.
- Made concurrent Windows generation adoption tolerate only the short-lived,
  numeric WinError 32/33 sharing state created by an honest winner's rename pin.
  Reconciliation is capped at 250 milliseconds and repeats complete rooted
  identity and exact-generation verification on every attempt; unrelated access
  failures and exhaustion remain fail-closed.
- Hoisted POSIX atomic-rename bindings to module scope, added modern FreeBSD
  `renameat2` support and an ABI-width-guarded Linux
  `renameat2` syscall path
  for libc implementations without the wrapper, while preserving fail-closed
  behavior on unsupported kernels, filesystems, and ABIs. Exact-statistics
  caches now retain sufficient statistics instead of endpoint tuples and
  expose an explicit quiescent-lifecycle clear operation for embedded services.
- Made deterministic and stochastic evidence-sensitivity publication
  crash-atomic at the target-directory boundary without enumerating the shared
  parent or counting retained stages. Writers validate a complete owner-only,
  randomly named sibling stage immediately before one atomic no-replace rename;
  POSIX retains child pins through commit and Windows performs a fresh exact
  pinned verification after commit. Exact concurrent generations are adopted
  idempotently, while committed targets are never rolled back.
- Bound manifest-advertised candidate evaluations to the exact candidate
  RunSet and compiled suite by independently reproducing the deterministic
  evaluation from captured snapshots. Current evaluation gates require an
  authenticated RunSet digest, manifest-bearing library packet gates require an
  artifact root, and present stochastic non-verdict evidence is invalid unless
  explicitly allowed.
- Routed atomic file replacement, rollback unlink, and authored suite,
  knowledge-contract, protocol, and live-config reads through pinned rooted
  directory handles. Added fail-closed input/output alias checks, bounded
  RunSet cardinality and artifact size, bounded finding messages, safe Markdown
  table cells, and redacted bounded YAML diagnostics.
- Hardened evidence delivery and content binding across release replay, exact
  prompt/corpus/authority/adapter resources, requested-versus-resolved model
  identity, and closed directional endpoint assignments. Planning, estimation,
  and gating now share the fixed planned-cluster denominator and exact rejection
  rule; included runtime-invalid pairs fail closed, and `rag sensitivity
  finalize` creates the no-dispatch protocol/config design commitment.
- Added self-digested repeated paired evidence-sensitivity, statistical
  sufficiency, and stochastic-result contracts for the narrow binary
  `expected_decision_response` endpoint. Verdict-bearing stochastic evidence
  now depends on the exact satisfied sufficiency artifact; underpowered,
  incomplete, or structurally invalid studies remain non-verdict.
- Added immutable two-arm live prebinding and explicit pair-manifest assembly.
  Provider/model/tool/policy or undeclared arm differences fail closed, while
  missing and excluded cells remain reason-coded instead of disappearing from
  the denominator audit.
- Bound every analyzed pair to canonical record membership in the exact
  content-addressed source RunSets and included the unchanged privacy-safe
  source snapshots as separate files in the durable analysis bundle. Stochastic
  packets now bind those files atomically under the mandatory
  `stochastic-baseline-source-runset` and
  `stochastic-counterfactual-source-runset` roles. CI reparses both snapshots,
  recomputes whole-RunSet and per-record digests, reruns the canonical paired
  observation assembler, and requires exact equality with the sufficiency
  observations, including recommendation, outcome, disposition, cluster, and
  endpoint semantics.
- Added exact one-sided cluster-binomial planning and analysis under a declared
  independent-exchangeable-cluster assumption. The planner targets the same
  fixed planned-frame composite endpoint used by the gate: `p0`, `p1`, and the
  estimated response rate all include every frozen planned cluster, with a
  non-analyzable cluster scored as zero while observed/analyzable counts remain
  separate. Version 1 requires balanced cluster composition. The fixed-N
  planner recomputes the integer critical value and exact power at every
  candidate N because the discrete feasibility surface is not monotone;
  `maximum_exclusion_rate` is an audit cap, not sample-size inflation. Analytic
  exact p-values remain authoritative; a domain-separated, SHA-256-derived
  Monte Carlo path is a reproducibility diagnostic only.
- Bound verdict-bearing stochastic packet and graph projections to the exact
  counterfactual evaluation RunSet ID and digest, with both source RunSet
  execution-configuration digests anchored to their predeclared protocol arms.
  When a comparison is present, both baseline and candidate IDs and digests
  must match the exact source arms.
- Added a rigorous methods guide and authoring template covering the five
  coupling classes, explicit network consent, deterministic-fixture bypass,
  privacy boundaries, and the separation between observed counterexamples and
  estimated response rates. Independent statistical review is invited and has
  not yet occurred.

## 0.6.4 - 2026-08-22

- Added a deterministic, authority-scoped RAG evidence-sensitivity protocol
  that reruns the full synthetic subject path against two exact committed
  corpora while holding the suite, fixtures, request, query family, subject,
  prompt, model, tools, retrieval configuration, and producer version fixed.
- Added self-digested corpus-manifest, knowledge-authority, protocol, and
  sensitivity-report contracts. Reports distinguish responsive and
  evidence-insensitive verdicts from confounded or prerequisite-unmet
  non-verdicts, preserve exact retrieval and claim-link evidence for both arms,
  and emit stable reason codes and JSON, Markdown, and HTML views.
- Made sensitivity evidence self-contained with manifest-bound raw request,
  subject, and tool fixture snapshots plus self-digested raw-and-decoded corpus
  snapshots. Validation replays ranked retrieval, tie-breaking, links, and
  subject-mode outputs exactly; undeclared distractor drift is confounded, and
  decoded privacy violations reject transactionally before publication.
- Added the offline `demo evidence-sensitivity` detector contract with a
  responsive control and an evidence-inertial regression, plus a synthetic
  process-equivalence reproduction index spanning
  same-output/different-process and evidence-insensitivity strata. Neither
  artifact reports real-model prevalence or benchmark results.
- Extended evidence packets and the closed four-node/five-edge assurance graph
  projection to carry optional evidence-sensitivity results without introducing
  a general intervention, checkpoint, state-injection, or causal-model surface.
- Bound sensitivity comparisons to the authenticated baseline and counterfactual
  RunSet digests, emitted a packet-ready comparison sidecar, and covered the
  ordinary CLI compare-to-packet-and-CI workflow including environment metadata.
  The v0.6.4 comparison model and writer schema now both require the authenticated
  baseline/candidate digest pair; comparison reports, packets, CI gates, and JSON
  publication reject contradictory comparison/evaluation identities.
- Added direction-aware sensitivity outcome classifications and rendering so a
  wrong-direction decision flip cannot be presented as an expected response;
  made the reversed negative-control assets mandatory in source, wheel, and
  installed-package verification.
- Revalidated complete comparison-summary, packet, and sensitivity-report models
  at public graph and CI trust boundaries, closing non-validating in-memory copy
  bypasses while keeping validation diagnostics free of untrusted input values.
  Packet Markdown now carries the typed outcome classification and canonical
  directional message.
- Tightened graph and canonical-message directionality: verdict-bearing
  sensitivity evidence requires a bound, distinct `approve`/`deny` expected
  path, observed relations must match the exact decision pair, and non-verdict
  projections cannot carry the verdict-only expected-response-missing reason.

- Made the advertised 256-document sensitivity envelope usable without allowing
  an oversized aggregate manifest scalar to be silently redacted. Digest-bound
  raw JSON is retained only after decoded-equivalence and privacy checks, while
  privacy-policy rejections are now classified consistently as invalid input.
- Introduced privacy detector profile v2. Its profile-bound NFKC/category-C
  deobfuscation view detects sensitive values split by bidi, zero-width,
  control, surrogate, private-use, or unassigned code points; reconstructed
  matches redact the exact original scalar in full without mutating accepted
  raw evidence bytes.
- Enforced synthetic provenance for sensitivity inputs: bundled fixtures are
  accepted only against reviewed immutable digest pins, and custom corpora need
  a self-digested operator declaration bound to every suite, fixture, contract,
  corpus, and raw snapshot identity. Reports disclose whether provenance was
  package-verified or operator-declared and that exact raw bytes persist.
- Revalidated every typed graph and direct-gate input at the trust boundary,
  required exact evaluation-to-sensitivity and authenticated-comparison digest
  bindings, and rejected v0.6.3 graph labels carrying v0.6.4-only content.
  Packet CI can now require sensitivity evidence explicitly and treats
  sensitivity non-verdicts as invalid unless an advisory override is selected.
- Made sensitivity publication an exclusive, no-overwrite transaction. Its
  manifest binds all 14 non-circular source and reviewer artifacts; verification
  consumes the same descriptor-pinned bounded byte snapshots used for typed
  parsing and packet binding. Atomic rooted directory claims and anchored
  rollback prevent output-directory swaps from diverting artifact bytes. An
  existing output is accepted without rewriting only when all 17 generated files
  and every nested binding form one exact deterministic generation.
- Made Windows sensitivity publication claim directories and create files
  relative to pinned native handles. Parent identity and canonical final path
  are revalidated, child native and descriptor identities must match, no handle
  shares delete access, and rollback uses identity-checked handle disposition
  instead of mutable path deletion. Native API loss, anomalous status or
  disposition values, reparse entries, collisions, and incomplete cleanup fail
  closed and are required by Windows CI. Link or reparse substitution during
  rollback is treated as ownership loss while every retained pin and directory
  lease is released unconditionally. The `0600`/`0700` creation modes are POSIX
  controls only; Windows confidentiality depends on the parent directory DACL.
- Made authenticated comparison identity verifier-owned in CI. Standalone and
  packet-embedded legacy unbound comparisons fail closed by default; the
  compatibility override is use-scoped, rejected when unnecessary, and recorded
  on every decision path. Packet root inference now requires exactly one fully
  valid candidate, while terminal diagnostics re-redact after Unicode-control
  normalization.
- Hardened distribution verification with bounded, link-safe, single-pass
  archive inspection, exact wheel `RECORD` verification, and byte-for-byte
  wheel/sdist source equivalence. Smoke verification builds the sdist offline,
  requires its wheel to match the published wheel including metadata, installs
  project artifacts with `--no-deps --no-compile --no-index`, and admits only the
  exact declared whole-environment delta. Core Metadata cardinality follows the
  standard's multiple-use fields, including optional extras and import identity
  declarations. Packaged examples and the process-equivalence reproduction
  index are enforced in CI.

## 0.6.3 - 2026-08-17

- Made signed-release verification enforce one coherent packet, graph, source-
  summary, and manifest set after every blob signature is verified. The
  privacy-filtered evaluation and comparison summaries are retained, signed,
  and published with the release evidence so independently valid same-commit
  workflow reruns cannot be silently mixed.
- Prevented `packet graph --out` from overwriting any packet-bound artifact.
  Re-emitting the packet's exact bound graph in place remains idempotent, while
  evaluation summaries, release manifests, and every other bound role fail
  closed before a write.
- Added an optional canonical `runset_digest` to evaluation summaries and made
  first-party evaluators populate it, allowing packet evidence graphs to join
  control-efficacy and gate evidence to the primary run-set subject only when
  the source identity is authenticated.
- Kept default release replay compatible with frozen bundles by selecting core
  artifact roles from the replay schema version: schemas through v0.6.2 retain
  the legacy four-role contract, while v0.6.3 additionally requires the
  assurance evidence graph. Unmapped schema versions fail closed, and explicit
  `--require-role` checks remain additive.
- Added `AssuranceEvidenceGraph/v1` as a closed four-node/five-edge,
  RFC-8785-digested projection of evaluation, comparison, mutation,
  control-efficacy, gate, and limitation evidence. Current first-party packet
  and CI output bind both its semantic graph digest and exact graph-file digest,
  while graphless third-party v0.6 packets remain valid. Persisted validation
  recomputes schema-owned node identities, preserves non-deterministic mutation
  outcomes as non-verdict evidence, keeps gate profiles as policy provenance,
  rejects fixture-invalid comparison support, and closes graph reason and
  reference-role semantics. Graph and current source models reject empty
  projected identifiers, and the graph contract documents that digest-scoped
  gate evidence may occupy a component separate from its primary textual
  subject.
- Enforced provider allowlists and denylists independently of review routing,
  scoped fixture-remediation suppression to the controls that actually ran, and
  made required-policy `not_evaluated` results fail closed without duplicating
  required-policy findings in live observations.
- Preserved raw failure history during runset comparison so candidate-only
  waivers remain visible as waived failures rather than appearing resolved.
- Made stream ingestion reject digest/model contradictions and tightened stream
  terminal-event, route, outcome, recommendation, and boolean-label invariants.
- Pinned OpenAI-compatible HTTPS connections to freshly screened DNS answers
  while preserving hostname-based TLS verification, closing the resolution-to-
  connection DNS-rebinding window, and exercised the urllib handler path across
  the supported Python matrix.
- Made observed zero-denominator live rates fail closed instead of fabricating
  numeric zero estimates or intervals, enforced exclusion ceilings before empty
  sample handling, and downgraded unbound advanced analyses to exploratory
  evidence.
- Rejected conflicting content digests for the same evidence identity, bounded
  rooted file reads through descriptor-based path checks, and strengthened
  authored YAML against unknown keys, ambiguous defaults, and empty current
  suites/runsets.
- Hardened configured external-script launches with root-stable file and
  working-directory leases, sealed script-byte execution and descendant cleanup
  on Linux, and suspended launch, identity revalidation, and kill-on-close job
  assignment on Windows, backed by native Windows containment CI. This remains
  lifecycle containment for trusted configured scripts, not an adversarial
  same-UID sandbox.
- Required current evidence packets to bind exactly one evaluation summary and
  exactly one comparison summary when present; made evaluation summaries derive
  coherent verdicts from non-pass findings, and made standalone and full CI
  revalidate persisted packets against exact source summary bytes.

## 0.6.2 - 2026-08-10

- Prevented scaffold rollback from deleting a concurrently replaced file when
  POSIX reuses an inode, and made doctor classify linked output entries before
  resolving their targets.
- Refreshed every audited dependency lock to `cryptography==50.0.0`, resolving
  `PYSEC-2026-3552`, and made the LangGraph and OpenTelemetry lock-generator
  headers reproducible from repository-relative commands.
- Added opt-in `ci --format json` output for every completed full-run or
  artifact-gate decision, including `pass`, `review`, `not_evaluated`, and
  invalid artifact loads, while retaining the existing default text behavior.
- Made control-efficacy, mutation, and packet CLI output non-wrapping so paths
  and digests remain copyable at narrow terminal widths, and replaced packet
  message-content inspection with structural efficacy-decision logic.
- Canonicalized threat challenger projections locally, named the shared
  efficacy-limitation bound, narrowed doctor catalog diagnostics to expected
  failures, and normalized doctor configuration-path reporting.
- Completed the control-efficacy reason-code registry and its alignment check,
  removed internal planning terminology from shipped catalog text, and
  clarified advisory versus strict verifier semantic binding.
- Strengthened the `ExactRate` writer JSON Schema so zero denominators require
  both `undefined_zero_denominator` state and a zero numerator, while positive
  denominators require `defined` state.
- Made strict efficacy verification cross-check report-owned catalog and threat
  projections against the installed catalog and separately loaded verifier
  manifest instead of trusting matching digest strings alone.
- Made packet construction bind the report to the configuration's current,
  confined threat-manifest snapshot before publishing outputs, and made legacy
  packet serialization omit only the newly introduced efficacy fields.
- Completed the assurance demo's selected-operator threat scope and made
  destructive demo cleanup reject linked or reparse-point ownership markers.
- Added self-digested `ControlEfficacyReport/v1` and
  `ThreatApplicabilityManifest/v1` contracts. Reports preserve exact
  `caught / (caught + survived)` ratios, explicit undefined zero-denominator
  state, all mutation-result counts, invariant-family strata, and all five
  independence strata.
- Added threat applicability, critical-gap, required-survivor, and independent
  challenge projections with semantic evidence state kept separate from
  configurable gate effects. Invalid subjects and execution failures remain
  visible outside the detector-ratio denominator.
- Added `controls efficacy`, standalone and packet CI gating, and optional
  control-efficacy evidence in packets without merging control-challenge scope
  into candidate evidence closure.
- Added an idempotent `init controls-mutation` scaffold, static read-only
  `doctor controls-mutate` diagnostics, and an installed-package offline
  `demo assure-the-assurance` workflow covering caught, survived, and rejected
  unrelated-failure detection paths.
- Extended release-facing claim checks to reject numeric system-safety
  percentages while preserving legitimate statistical confidence-interval
  language, and documented the exact metric and review boundaries.
- Made surviving required and critical mutation operators non-bypassable:
  their profile fields and gate findings are block-only in both runtime and
  JSON Schema, while decision derivation reads those pinned authored fields.
- Added `CRITICAL_THREAT_UNCOVERED` as an explicit gate finding and mapped it
  to `review` by default. `ci gate --fail-on-warn` makes that review blocking,
  while `--fail-on-not-evaluated` now covers both control-efficacy semantic
  state and threat-scope state.
- Rejected `caught` or `survived` campaign results whose evaluator basis is
  stochastic or human-reviewed; verdict-bearing control-efficacy outcomes must
  be deterministic until a typed sufficiency artifact is supported.
- Preserved catalog threat references missing from the authored manifest as
  exact `unscoped_catalog_threat_*` residuals, gave them the distinct
  `unscoped_catalog_references` scope state and
  `UNSCOPED_CATALOG_THREAT_REFERENCE` gate reason, and mapped them to review
  by default. The generated quickstart now declares its complete selected
  operator scope, and doctor reports `CM_THREAT_SCOPE` when an authored
  manifest is thin.
- Required efficacy-bearing packets to bind exactly one
  `control-efficacy-report` digest and one `control-efficacy-config` digest,
  added release replay for both roles, and defined the config role as the
  exact authored YAML or JSON input that determined the embedded gate profile.
- Required efficacy report writers and packets to bind a gate decision to its
  exact profile and freshly re-derived findings and effects, rather than only
  its report digest. Evidence-packet construction now enforces nested artifact
  schema-version coherence and validates the post-redaction packet against the
  selected current writer or legacy frozen schema before persistence.
- Documented `controls-mutation-onboarding-config` as package-bound authored
  input rather than an exported frozen evidence schema.
- Replaced packet CI routing recovered from human-readable message prefixes
  with a structural `pass`, `review`, `not_evaluated`, `fail`, or `invalid`
  outcome that is consistent with the exit code and emitted in diagnostics.
  Combined packet messages retain the controlling label while disclosing the
  attached efficacy semantic state, threat-scope state, and survivor and
  unscoped-reference counts.
- Changed successful `ci gate` display prefixes so `warn` now emits
  `ci gate review:` instead of `ci gate pass:`, and `not_evaluated` now emits
  `ci gate not-evaluated:` instead of `ci gate pass:`. Human-readable prefixes
  are display text; the structural outcome in diagnostics and the process exit
  code are the automation contract.
- Updated packet and efficacy Markdown to render actionable, bounded gate and
  residual details, and synchronized the assurance walkthrough with all six
  emitted review artifacts.

## 0.6.1 - 2026-08-02

- Added an exact, fail-closed recovery and read-only publication-validation
  path for verifier-promoted release artifacts, and made checkout-free GitHub
  release commands name the repository explicitly.
- Restricted the production release tag path to stable `vX.Y.Z` versions so
  TestPyPI release candidates cannot be accidentally routed to production.
- Expanded the closed development-RFC `core/v1` catalog from three to seven
  stable deterministic operators, adding evidence source-identity skew,
  synthetic sensitive-summary injection, exact duplicate observation replay,
  and synthetic incomplete budget-stop challenges.
- Added normative detector support for evidence provenance identity, valid
  record structure, and RunSet completion, with exact target control/reason
  code mappings and explicit runtime-failure prohibited substitutes. Paired
  evidence reference/item source identity is an always-on deterministic
  RunSet invariant, not a mutation-campaign-only check.
- Added self-digested `AssuranceMutationCatalog/v1` and
  `AssuranceMutationCampaign/v1` artifacts with canonical operator ordering,
  catalog identity, selected/executed/pending order, applicability, expected
  and observed findings, prohibited-substitute IDs, completion state, and
  limitations.
- Added `controls mutate --catalog core/v1` with repeatable operator,
  invariant-family, and threat-source filters, stable seed replay, full-report
  and fail-fast modes, and deterministic worst-state exit precedence.
- Required every campaign operator to execute independently against the same
  immutable source; v1 forbids mutation chaining and composition.
- Added rollback-capable campaign generations with fixed catalog, campaign, and
  generation-manifest outputs plus canonical per-operator result, descriptor,
  and optional transformed-RunSet files.
- Bound catalog identity to operator versions, implementations, normative
  detector contracts, provenance, independence, invariant families,
  threat-source references, ordering semantics, and limitations.
- Added an exact, contract-bound exception for the catalog's fixed synthetic
  privacy challenge while retaining fail-closed source and ordinary candidate
  privacy validation.
- Advanced current package and persisted schema metadata to v0.6.1 while
  preserving the frozen v0.6.0 snapshot and its v0.6 relational validation
  semantics.
- Pinned every published v0.6.1 wire schema to its emitted version, including
  nested mutation contracts, and restored self-digest and relational checks
  after frozen v0.6.0 shape validation.
- Made evidence provenance fail closed for blank identifiers, orphaned
  reference/item records, and inconsistent source identities; provenance,
  required-evidence, and material-claim findings now use separate
  privacy-minimized domain-separated targets and generic messages.
- Extended the v0.6.1 machine-identifier grammar to expectation and evidence
  graph claim/link fields, and rejected current run or compiled-suite
  containers carrying legacy evidence graph or expectation members.
- Routed first-party console, Markdown, and evidence-diff HTML rendering through
  one redacting control/bidi-safe display boundary.
- Bounded mutation-generation reads and aggregate validation work to stable
  regular-file descriptor snapshots, rejected mixed single/campaign output
  namespaces, cleaned Windows case-variant campaign artifacts, and deferred
  duplicate-replay payload copying until after deterministic target selection.
- Required release provenance checks to verify that each target control is
  declared by an exact literal in its mapped source at the claimed first-seen
  commit, failing closed for unavailable or unparseable historical content.
- Published the exact catalog mapping, deterministic reproduction inputs,
  bounded interpretation, and a reviewed source/fixture contribution path that
  does not load executable plugins. This release does not claim a safety score,
  mutation kill rate, statistical confidence interval, universal coverage,
  stamped release provenance, or external validation.

## 0.6.0 - 2026-07-25

- Routed persisted runtime and CLI inputs through explicit wire-identity and
  frozen-schema validation before current-model projection, and rejected
  RFC 8785-unsafe integers before accepted artifacts reach canonical hashing.
  Current-model projection failures now use value-free diagnostics, including
  legacy artifacts accepted through frozen schemas.
- Made finding IDs unambiguous when identity components contain delimiters.
  Existing exact-finding waivers must be regenerated because their
  `finding_id` values intentionally change under the versioned identity
  projection.
- Rejected RunSets whose child records use a different execution mode and
  rejected inconsistent zero-valued prompt/completion token totals.
- Bound mutation results and evidence descriptors to the complete gate-profile
  digest, order-independent waiver-set digest, and evaluation date; exposed the
  matching waiver and gate flags on `controls mutate`, and labeled built-in
  results as `first_party_postcontrol`.
- Rejected verdict-bearing `llm_advisory` mutation outcomes before evaluator
  execution and normalized custom evaluator-identity conflicts into typed
  mutation result states.
- Serialized mutation writers and added an atomically published generation
  manifest so interrupted or mixed fixed-file generations fail closed; added
  fixed-output alias, linked-directory, and filesystem-root guards.
- Bound live evaluations to exact suite, protocol, configuration, prompt, arm,
  case-schedule, provider-version, and derived-cluster identities; rejected
  duplicate report observations, and prevented unbound source-group designs or
  protocol-unbound execution configurations and degenerate intervals from
  producing confirmatory passes.
- Rejected nonzero-margin paired sign-flip tests and required strict
  non-inferiority at the declared margin boundary; bound cross-window drift
  comparability to the executed configuration digest.
- Made exact equality at a zero non-inferiority margin inconclusive instead of
  a blocking regression, applied endpoint-adjusted Bonferroni alpha to
  confirmatory Poisson bounds, and persisted each bound's effective confidence
  level.
- Added fail-closed consistency checks for observation-derived live report
  summaries and privacy-minimized matched, unmatched, and expired waiver
  dispositions without changing waiver gate semantics.
- Preserved policy warnings that originate in fixtures and diffed all fail-state
  findings independently of whether the active gate profile blocks or warns.
- Removed stale CI-owned outputs before each run, streamed packet and
  generation-member hashing, restricted action uploads to generated artifacts,
  rejected input/output aliases and unsafe output roots, and hardened immutable
  historical Git reads against hooks, replacement objects, configuration, and
  partial-clone lazy fetch.
- Restricted Windows provenance reads to `git.exe`, enabled complete lockfile
  auditing on direct `main` updates, corrected repository CODEOWNERS, and
  narrowed release reproducibility language to same-toolchain fresh-job byte
  matching.
- Validated release-replay roles against their declared artifact contracts and
  rejected lexical, resolved-path, symlink, and hard-link aliases in replay and
  manifest inputs.
- Clarified the v0.6.0 Release Candidate maturity, development-RFC mutation
  status, evidence limitations, and claim traceability across product and
  engineering documentation.

- Added strict evidence descriptor, deterministic mutation operator,
  expected-detection, and mutation-result contracts with canonical
  self-digests, provenance, independence classes, and privacy-minimized
  findings.
- Added three deterministic built-in control challenges and single-operator
  `controls mutate` execution with bounded input, source immutability,
  before/after validation, canonical output artifacts, and documented semantic
  exit codes.
- Bound expected and observed finding targets with privacy-minimized digests,
  aligned exact and wildcard JSON Pointer validation across Pydantic and JSON
  Schema, and added specific safe diagnostics for subject incompatibilities.
- Made the built-in catalog lazy and package-resource aware, and separated
  immutable target-control creation snapshots from live implementation
  component identity with fail-closed release verification.
- Bound mutation and built-in evaluator identity to reviewed transitive source
  manifests, and made release provenance replay those implementation components
  at the claimed introduction commit. Release workflows now fetch full history
  for that verification.
- Closed evaluator-identity gaps by binding the complete packaged first-party
  Python tree, package initializers, frozen legacy RunSet schemas, runtime
  dependency versions, and the canonical RunSet digest carried by each v0.6
  evaluation report.
- Made network retry budgets conservative per attempt: ambiguous failed calls
  retain declared cost and token reservations, later attempts fail before
  exceeding local ceilings, v0.6 live records persist committed amounts, and
  rate-limit thresholds now stop dispatch across the entire run.
- Restricted live-provider retries to transient transport failures, HTTP 408,
  HTTP 429, HTTP 5xx, and explicitly retryable provider errors; permanent
  request and response-shape failures now fail on the first attempt.
- Preserved frozen legacy validation semantics, completed immutable mutation
  introduction provenance, and pinned the canonical release-evidence producer
  to the exact reviewed Python runtime.
- Bound mandatory privacy detector guards into the privacy-profile digest,
  made tool-policy capability reporting account for case-scoped expectations,
  and kept stochastic or human-reviewed mutation results non-verdict-bearing
  until their declared sufficiency basis is met.
- Added privacy-safe exception diagnostics, branch-isolated human-review and
  tool-policy mutation targets, and matching cross-field constraints across
  the Pydantic and published JSON Schema contracts.
- Pinned the optional OpenTelemetry API, SDK, and OTLP HTTP exporter to the
  exact tested 1.44.0 tuple, added a
  dedicated hash-locked real-exporter CI contract, and made private OTLP HTTP
  transport incompatibilities fail closed before span egress.
- Aligned the OpenTelemetry contract tests with the fail-closed exporter,
  exercised real console emission and real pinned OTLP HTTP private transport
  construction without network egress, and removed the stale DNS-resolution
  opt-out expectation.
- Restricted repository-schema precedence to verified `src` checkouts so an
  installed wheel uses its reviewed packaged frozen schemas instead of an
  unrelated adjacent `schemas` directory.
- Canonicalized tool-policy findings by deduplicating and sorting tool names,
  with explicit `forbidden_tools` taking precedence over allowlist failures.
  This can change finding order, count, messages, IDs, and derived report
  digests for duplicate or overlapping tool declarations.
- Expanded RunSet persistence checks to reject sensitive-looking content in
  redactable string fields while exempting valid structural digests and
  designated preserved, non-fail-closed fields.
- Required explicit wire discriminators on raw v0.6 artifacts, strengthened
  RFC 3339 run-timestamp validation and privacy checks, bound mutation results
  to verified non-zero evaluator identity except for an explicit unavailable
  sentinel reserved for pre-evaluation catalog-integrity errors, constrained
  the core method to its ordered canonical prerequisite set, and limited
  missing evidence-subject digests to non-verdict-bearing results with
  unsatisfied prerequisites.
- Added architecture decisions that bound the product as an assurance compiler,
  preserve method assumptions and limitations, constrain signature claims,
  separate deterministic and stochastic semantics, keep LLM-derived judgments
  advisory, and defer stable formal or conformal method commitments.
- Added the `v0.6.0` schema candidate while preserving the frozen `v0.5.0`
  snapshot byte-for-byte.

## 0.5.0 - 2026-07-17

- Added versioned privacy detector identity: current RunSets, evaluation
  summaries, and comparison summaries bind a canonical detector profile
  digest; evaluation, comparison, evidence packets, and evidence-diff rendering
  reject incompatible profile combinations while legacy artifact dumps remain
  unchanged.
- Clarified that evaluating an unbound legacy RunSet stamps the resulting
  summary with the evaluation-time runtime profile while leaving the original
  persistence/redaction profile unknown; comparison remains fail-closed for
  unbound legacy inputs.
- Added a full-history CI guard that compares every released schema snapshot
  with its Git tag baseline, while allowing the active pre-release snapshot to
  evolve until its matching release tag exists.
- Added v0.5.0 streaming event ingestion with explicit global or producer-local
  sequencing contracts, JSONL validation, canonical payload digests,
  deterministic jitter sorting, duplicate diagnostics, and conflict failures.
- Added `agent-assure stream ingest` and `agent-assure stream evaluate`, plus
  stream projection into fixture-mode RunSets, ordered span plans, usage
  summaries, and the `examples/streaming_process_regression` fixture suite for
  same-final-output process regressions.
- Hardened stream handling by requiring timestamped producer-local merge order,
  revalidating persisted stream-run digests and composite keys during
  evaluation, failing closed on malformed evidence removals and case-ID
  conflicts, clearing review state on bypass routes, and mirroring the
  streaming example into packaged resources.
- Added an experimental Google ADK framework adapter, optional
  `agent-assure[adk]` dependency metadata, docs, and an offline
  `adk_process_assurance` example whose candidate preserves the final decision
  and evidence while bypassing the observed human-review flag.
- Hardened the Google ADK adapter around the real ADK 2.4 event shape by
  preferring `custom_metadata`, reading `actions.state_delta`, preserving
  numeric event timestamps, avoiding per-event IDs as run IDs, and failing
  closed on malformed observed review flags.
- Bumped package and active persisted artifact schema metadata to `0.5.0` and
  added the frozen `schemas/v0.5.0` snapshot with stream artifact roots.
- Hardened security boundaries for untrusted inputs by adding strict bounded
  JSON loading, YAML structural caps with explicit `SafeLoader` composition,
  duplicate-key and non-finite-number rejection, and safer CLI error handling.
- Hardened live execution and fixture integrity by fail-closing truncated
  emergency stderr summaries, requiring per-capability interactive trust
  prompts, pinning bundled fixture identities, and rereading manifest-approved
  fixture bytes exactly at execution time.

## 0.4.4 - 2026-07-12

- Added a non-combative process-assurance vs answer-quality eval positioning
  doc, a bundled `process_measurement_cases` fixture suite, and
  `agent-assure demo measurement-cases` to show same-answer process changes
  without making competitive benchmark claims.
- Extended evidence-diff HTML process tables to render operational counters,
  measured usage summaries, and usage deltas alongside evidence, provider,
  human-review, and privacy findings.
- Tightened control coverage mapping semantics so `control_evaluated` requires
  packet-resident control-specific evidence, built-in mappings prefer packaged
  resources over development checkout files, OWASP 2025 executable maps include
  `LLM07` and `LLM08`, and control-map docs list the full CLI contract.
- Closed additional control-map edge cases by requiring scoped fail/warn mapping
  conditions, omitting partial AND-rule evidence from item-level evidence,
  renaming control evidence reference hashes to `evidence_digest`, and aligning
  OWASP/NIST review-side failure mappings with contradictory evidence states.
- Bumped package metadata to `0.4.4` while retaining the active persisted
  artifact schema at `0.4.3`; the release validator maps v0.4.4 to the
  committed `schemas/v0.4.3` snapshot.

## 0.4.3 - 2026-07-10

- Added `agent-assure controls map` to produce framework evidence mapping
  reports from evidence packets for NIST AI RMF, OWASP LLM Top 10 2025,
  ISO/IEC 42001, and MITRE ATLAS 2026.06.
- Added conditional mapping files, explicit coverage states, packet and mapping
  digests, Markdown/JSON control coverage reports, claim-boundary language,
  and MITRE ATLAS planning-crosswalk metadata with mapping strengths.
- Bumped the active package/schema surface to v0.4.3 and added a frozen
  `schemas/v0.4.3` release snapshot while keeping earlier schema directories
  available for replay.

## 0.4.2 - 2026-07-10

- Surfaced the governance crosswalks in the README and added standalone NIST AI
  RMF and OWASP LLM Top 10 planning crosswalk docs so all four frameworks
  (NIST AI RMF, OWASP LLM Top 10, ISO/IEC 42001, MITRE ATLAS) have dedicated
  pages derived from the threat coverage matrix, with explicit
  non-conformance boundary language.
- Added a MITRE ATLAS 2026.06 planning crosswalk to the threat coverage matrix,
  including conservative mapping-strength labels, explicit ATLAS-relevant gaps,
  an offline ATLAS ID validation fixture with provenance notes, and a
  bidirectional Markdown/YAML consistency guard with prose provenance checks.
- Refreshed public docs for the current release surface and expanded the
  ISO/IEC 42001 planning crosswalk into a structured control table linked from
  the docs nav.
- Added an experimental framework adapter foundation with a deep LangGraph
  translator, privacy-filtered framework observations, measured-usage
  attachment, optional `agent-assure[langgraph]` metadata, and an offline
  LangGraph expense-assurance example whose candidate preserves the final
  decision while dropping required policy evidence.
- Added a deterministic RAG provenance assurance demo with committed
  digest-addressed prior-auth policy chunks, scaled-integer cached vectors,
  `agent-assure demo rag`, and a hero reranker regression that preserves the
  visible decision and corpus digest while losing material duration evidence.
- Added fixture-declared counterfactual RAG query families for the synthetic
  prior-auth RAG path, with distinct committed query-vector keys and
  deterministic reports that summarize required-ref coverage separately from
  source-ID and material-claim support across paraphrase/noise variants without
  exposing raw query text or claiming semantic proof.
- Bumped package metadata to `0.4.2` while keeping the persisted artifact
  schema at `0.3.1`; the release validator now records the explicit
  package-to-schema mapping for the v0.4 package-only releases.

## 0.3.1 - 2026-07-06

- Published v0.3.1 to PyPI and completed post-publish validation from a fresh
  unpinned install: `pip install agent-assure` resolved `0.3.1`,
  `agent-assure --version` returned `0.3.1`, and the packaged flagship demo
  caught the expected process-assurance regression.
- Added a v0.3.1 measured-usage schema foundation with integer
  `estimated_cost_microusd`, usage ledgers, summaries, comparison deltas,
  optional usage fields on existing artifacts, and report wording that treats
  missing usage as `not_observed`.
- Bumped the active package/schema surface to v0.3.1, added a frozen
  `schemas/v0.3.1` release snapshot, kept `schemas/v0.3.0` immutable for
  replay, and restored the frozen-schema gate to compare the current exporter
  against the active release snapshot.
- Hardened usage evidence by requiring explicit limitations on cost-bearing
  segments, rejecting ledger/summary mismatches, propagating partial
  missingness limitations into summaries and deltas, rejecting legacy-labeled
  containers that carry v0.3.1 usage fields, and rejecting
  return-on-investment acronym language in the claim-boundary linter.
- Hardened the release publish path so the PyPI job verifies downloaded
  release-bundle cosign signatures against the release workflow identity before
  digest replay or package staging. Release manifest emission now rejects
  artifact paths outside the project root instead of recording unreplayable
  absolute paths, and release build/reproduction scripts write per-step logs
  under the release output directory. Release and evidence workflows now pin
  `SOURCE_DATE_EPOCH`, release CI evaluation uses a fixed `--today` date, and
  release manifests can still cover report output directories outside the
  current working directory by choosing a true common artifact root.
- Tightened privacy redaction so preserved structural keys and digest fields
  only bypass redaction for scalar string values; nested values under those
  keys are still traversed and scrubbed, and free-form `exclusion_reason`
  values are no longer preserved from sensitive-value redaction.
- Expanded claim-boundary scanning to `CHANGELOG.md` and release notes, widened
  CI/package metadata to Python 3.14 to match the checked-in lockfile, and
  constrained isolated builds to `hatchling>=1.27,<2`.
- Centralized frozen schema version discovery for wheel-content and clean-wheel
  smoke checks, added a schema-resource force-include consistency gate, and
  made release tag validation check package, schema, and frozen snapshot
  versions together.
- Fixed live incomplete-run rollups so observed included failures remain
  verdict-bearing after budget stops, preserved response usage counters on
  post-response budget failure records, and replaced production `assert`
  statements in live execution paths with explicit errors.
- Aligned evidence policy with the producer contract by requiring
  `claim_evidence_links` to point at present `evidence_refs[].ref_id` values,
  and expanded behavior diffs to include digest-bearing evidence items, claims,
  and explicit claim-evidence links.
- Aligned the evidence-diff HTML renderer with the same claim-evidence contract,
  restored "Output equivalence is not process equivalence" as the public
  thesis while keeping decision-field equivalence for the precise
  `recommendation`/`outcome` comparison, and kept git/lockfile provenance
  rooted at the source project even when reports are written to external output
  directories.
- Added typed release-script coverage for `scripts/`, dynamic active-schema
  Makefile targets, a schema force-include sync helper, and workflow
  consistency checks for the pinned release `SOURCE_DATE_EPOCH`.
- Refreshed the flagship evidence-diff golden from a claim-link fixture that
  uses explicit `claim_evidence_links`, added a renderer consistency guard for
  missing-evidence findings, aligned the final release workflow with
  `make release-check`, and moved TestPyPI/local release verification snippets
  to the locked editable install pattern used by final release builds.

## 0.3.0 - 2026-07-01

- Published v0.3.0 to PyPI and completed post-publish validation from the
  installed package: the packaged flagship demo preserved output equivalence
  and blocked the expected process-assurance regression.
- Prepared the v0.3.0 adoption release package metadata for PyPI and TestPyPI,
  including project URLs, Python 3.11-3.13 classifiers, release keywords, and
  the `0.3.0` package version.
- Added Trusted Publishing for TestPyPI and PyPI. Final PyPI publishing now
  runs from the signed release workflow and publishes the package files from
  the release bundle artifact instead of rebuilding them in a parallel workflow.
- Bundled deterministic prior-authorization and expense-approval example suite
  resources under the package namespace so installed wheels contain the data
  needed for offline example flows.
- Tightened wheel-content and clean-venv smoke checks so release gates inspect
  actual wheel contents and assert packaged example resources from an installed
  wheel.
- Added a packaged-example parity check so top-level repository examples and
  bundled example resources cannot silently drift.
- Pinned third-party GitHub Actions used in OIDC publish/signing jobs to
  immutable commit SHAs while retaining comments with the reviewed upstream
  tags.
- Hardened package-publish jobs by validating workflow-dispatch version input
  with a strict release-version parser and rechecking downloaded package
  artifacts immediately before TestPyPI/PyPI upload.
- Hardened the reusable GitHub Action against shell interpretation of
  caller-provided paths and variants, removed the inert demo expected-failure
  environment marker, added a regression test that core commands ignore that
  marker if set externally, and made the wheel smoke test assert the installed
  demo network guard.
- Added the PyPI release runbook with TestPyPI install checks, Windows
  PowerShell equivalents, credential timing guidance, and the relationship
  between package publishing and the signed GitHub release bundle.

## 0.2.0 - 2026-06-28

- Added protocol-bound live trajectory reports with a new
  `live-trajectory-report` schema and `agent-assure live trajectory` command.
  Reports derive privacy-filtered observable state paths from structured live
  RunSets, evaluation reports, and emergency records; summarize observable
  transition profiles; make history-dependent checks explicit; separate
  governance-control trajectory findings from operational reliability warnings;
  and report retry, rate-limit, exclusion, malformed-output, runtime-failure,
  emergency-process, and budget-stop event streams with exploratory burst
  signals under declared event-count, exposure, timestamp, and transition
  support prerequisites.
- Added protocol-bound cross-window live drift monitoring with a new
  `live-drift-report` schema and `agent-assure live drift` command. Reports
  check suite/protocol, baseline-mode, analysis-method, tool-schema, and
  policy-bundle comparability, validate timestamp order when available, and
  emit ordered trend, adjacent-step, separate lag-1 autocorrelation and AR(1)
  dependence diagnostics, and EWMA governance-health or control-reliability
  summaries as exploratory review signals by default once method-specific
  minimum-window prerequisites are met.
- Added optional protocol-bound advanced live statistical endpoints with
  confirmatory/exploratory labels, Bonferroni multiplicity validation, rare-event Poisson
  upper bounds, observed cluster-correlation summaries with bootstrap
  uncertainty, and paired exact or Monte Carlo randomization tests that fail
  closed when structural pairing, exchangeability, or enumeration prerequisites
  are not met. Bootstrap and Monte Carlo paths now use stable SHA-256-derived
  integer seeds, and degenerate per-arm cluster intervals are labeled as
  boundary heuristics.
- Added runtime isolation and OpenTelemetry export support for live execution:
  an `external-script` live adapter backed by a no-shell subprocess harness,
  redacted `emergency-process-record` artifacts for subprocess crashes,
  timeouts, nonzero exits, and invalid output, W3C trace-context propagation
  into live adapters and external scripts, trace-bearing span plans, and
  optional `agent-assure[otel]` SDK/OTLP export via `agent-assure otel export`.
- Added initial live evaluation support: strict live protocol/report schemas,
  explicit live provider adapters, protocol-bound repeated live RunSets,
  cluster-aware expectation-pass/outcome/reason-code/exclusion rates,
  pooled and cluster-mean rate reporting, design-effect and
  effective-sample-size reporting with largest-cluster sensitivity,
  protocol-declared paired-cluster t or bootstrap and fixed-reference live
  comparison reports with exploratory cluster-count guardrails, provider-version
  and tool/policy provenance checks, retry/rate-limit/token-pacing/budget
  metadata, incomplete-run status, cost/latency distributions, and
  `agent-assure live` CLI commands. The static JSONL adapter keeps the live
  path testable without sockets; the OpenAI-compatible adapter requires
  explicit network opt-in.
- Bumped persisted artifact and package version metadata to `0.2.0`, exported
  current JSON Schemas under `schemas/v0.2.0`, and retained the v0.1 release
  schema set for historical replay.
- Hardened live statistical reporting by sharing one t-critical/interval
  implementation across evaluation and comparison paths, labeling per-arm
  confidence-interval centers explicitly, avoiding spuriously exact zero-width
  boundary intervals, using the declared cluster bootstrap method for
  descriptive per-arm rates when applicable, and rejecting paired comparisons
  whose included cluster or case/repetition sets do not match.
- Hardened v0.2 live pre-release review issues by unifying six-place decimal
  rendering for protocol and report calculations, enforcing cumulative total
  and generated token budgets after live responses, preserving unclamped
  latency and cost comparison deltas, exposing rare-event Poisson bound
  sidedness, adding a Poisson bisection tolerance, and rejecting paired
  randomization protocols whose primary endpoint is not the expectation pass
  rate actually tested by the comparison path.
- Hardened live response handling with a strict structured-output contract,
  malformed-output emergency records, post-response budget-stop records,
  estimated-cost source metadata, redacted live summaries before record
  construction, and explicit tests for malformed JSON, budget exhaustion,
  cluster-edge cases, paired-cluster mismatches, and subprocess environment
  isolation.
- Narrowed the external-script adapter environment boundary so scripts receive
  only declared allowlisted variables, explicit config overlays, and
  runner-injected trace/request variables rather than the full parent
  environment.
- Added and tightened a statistical protocol for live stochastic
  evaluation, covering baseline handling modes, hypotheses, reproducible
  sample-size planning, confidence intervals, interim-look rules, retry and
  exclusion rules, provider-version capture, rate-limit handling, cost budgets,
  live-run ethics and safety limits, and the machine-readable protocol
  record requirement.
- Documented `agent-run-record-producer-contract/v1` so external
  `AgentRunRecord` producers have a versioned contract for explicit material
  claim-evidence links.
- Hardened documentation-alignment checks so required Markdown sections ignore
  fenced-code headings, missing protocol sections are covered by tests, and
  conservative public-claim wording conventions are documented.
- Hardened release replay so release manifests cross-check recorded artifact
  digests against regenerated files, including manifest-listed SBOM and
  distribution bytes, instead of treating manifest `sha256` values as
  informational.
- Moved the fixture-evaluation operation name out of `gen_ai.operation.name`
  and into the project namespace; `gen_ai.operation.name` is now documented as
  intentionally not emitted.
- Tightened material-claim evidence evaluation so only explicit
  `ClaimEvidenceLink` records pointing to present evidence satisfy the
  invariant.
- Added hash-pinned release dependency installation via `requirements.lock`,
  plus documentation for the lean persisted schema and release replay boundary.
- Added an explicit distribution reproducibility check for the evidence
  reproduce job and documented the claim-evidence-link contract for external
  `AgentRunRecord` producers.
- Hardened the final v0.2.0 pre-tag security posture by making live
  producer-supplied failing policy results verdict-bearing, confining live
  prompt/JSONL/script/cwd paths to the live config directory, requiring HTTPS
  and explicit host allowlisting for non-default OpenAI-compatible endpoints,
  bounding external-script stdout/stderr capture, recursively redacting
  persisted run artifacts for common secret token patterns while preserving
  schema-owned structural identifiers, restricting the bundled fixture HMAC key
  to repository synthetic examples, and documenting the remaining live adapter
  trust boundary.

## 0.1.0 - 2026-06-27

- Finalized the v0.1.0 release bundle workflow with release tag validation,
  documentation alignment, test/schema gates, SBOM generation, Python source
  distribution and wheel assets, replay verification, keyless cosign signing,
  and GitHub release asset upload. Hardened bundle assembly to use one
  environment snapshot for the manifest and SBOM, normalized project package
  names in SBOM component filtering, and documented that manifest-listed SBOM
  and distribution bytes are cross-checked during replay while exact release
  blobs remain cosign-verifiable workflow-signed artifacts.
- Hardened release digest replay by separating replay source-commit/source-ref
  validation from current-checkout validation, centralizing role digest-mode
  policy, rejecting artifact paths that escape the replay root, and adding CI
  schema-export drift checks. Replay findings now report generic `expected` and
  `actual` values because findings may compare digests, commits, refs, or path
  state.
- Expanded public review artifacts: measurement use-case brief,
  executive one-pager, citable abstracts, technical report, reproducibility
  appendix, OpenTelemetry gap analysis, deferred contribution candidate,
  standards freshness checklist, and traceability coverage for those public
  claims.
- Added CI orchestration over candidate RunSets with optional baseline
  comparison, full/fail-fast report modes, structured diagnostics, evidence
  packet generation, Markdown packets, environment provenance, local dependency
  inventory generation, release artifact manifests, replay-stable release
  digest checks, and keyless cosign signing/verification workflow support for
  exact release evidence blobs.
- Hardened post-review contracts: RunSets now bind suite version/digest and
  fixture manifest digest, evidence records include explicit claim-evidence
  links, provider expectation failures emit `FORBIDDEN_PROVIDER`, comparison
  diffs use stable finding identity instead of message text, decimal digest
  projection uses fixed six-place strings, SafeError carries non-leaking debug
  metadata, runset writes redact summaries before persistence, and report/span
  output is privacy-filtered before display.
- Added the initial implementation: package skeleton, strict schemas, schema
  export, validator parity, YAML compilation, canonical digests, privacy
  utilities, HMAC tokens, and OpenTelemetry-aligned span-plan preview.
- Added fixture manifests, safe fixture path resolution, compiled-suite loading,
  golden drift checks, deterministic fixture runs, and the synthetic prior
  authorization example variants.
- Hardened fixture runs with typed variant configs, explicit case-to-expectation
  links, multi-root fixture validation, source digest checks, and catalog-based
  prior authorization evidence assembly.
- Reworked the prior authorization evidence regression to arise from duplicate
  source/content associations during catalog reconstruction, modeled provider
  selection as layered configuration precedence, added a fake-PHI redaction
  fixture case, and enabled socket-disabled pytest runs.
- Expanded the prior authorization evidence fixtures to cover nine ordinary
  one-source/one-claim cases plus the shared-source edge case, added a
  blind-review release-evidence rubric, and added a minimal expense-approval
  example with baseline and provider-control candidate variants.
- Moved bundled example subject logic under an explicit package examples
  namespace, merged duplicate evidence references before persistence, and
  removed unused split-case YAML placeholders.
- Kept bundled example modules installable for reproducibility while documenting
  that they are not a stable public extension API, and moved the intentionally
  lossy evidence assembly behavior out of shared framework evidence helpers.
- Added deterministic RunSet evaluation with expectation resolution, material
  evidence-link invariants, structured output and configured tool controls,
  provider review-boundary and human-review controls, gate profiles, disjoint
  case metrics, per-finding time-bounded waivers, not-evaluated capability
  reporting, and JSON/Markdown/Rich evaluation reports.
- Added RunSet comparison with fixture-equivalence gating, final comparison
  classifications, provenance-only diffing, candidate-first JSON/Markdown/Rich
  reports, and invalid-comparison exit behavior.
- Added a public flagship showcase with exact local commands, expected
  pass/fail output fields, baseline-to-candidate comparison story, GitHub
  Actions usage snippet, and reproducibility digest summary.
