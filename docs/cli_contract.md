# CLI Contract

Current commands:

- `agent-assure --help`
- `agent-assure validate PATH --kind KIND`
- `agent-assure schema export --out DIR`
- `agent-assure suite lint PATH`
- `agent-assure suite compile PATH --out PATH [--manifest PATH]`
- `agent-assure suite run COMPILED_SUITE_JSON --variant VARIANT_YAML --out RUNSET_JSON [--manifest PATH] [--suite-digest DIGEST] [--source SUITE_YAML] [--hmac-key-env ENV]`
- `agent-assure evaluate RUNSET_JSON --suite COMPILED_SUITE_JSON --out-dir REPORT_DIR [--waiver WAIVER_JSON_OR_YAML] [--fail-on-warn] [--fail-on-not-evaluated]`
- `agent-assure compare BASELINE_RUNSET CANDIDATE_RUNSET --suite COMPILED_SUITE_JSON --out-dir REPORT_DIR [--waiver WAIVER_JSON_OR_YAML] [--fail-on-warn] [--fail-on-not-evaluated]`
- `agent-assure packet build EVALUATION_SUMMARY_JSON --out EVIDENCE_PACKET_JSON [--comparison COMPARISON_SUMMARY_JSON] [--control-efficacy CONTROL_EFFICACY_REPORT_JSON --efficacy-config CONTROLS_MUTATION_YAML] [--evidence-sensitivity EVIDENCE_SENSITIVITY_REPORT_JSON] [--statistical-sufficiency STATISTICAL_SUFFICIENCY_REPORT_JSON --stochastic-evidence-sensitivity STOCHASTIC_EVIDENCE_SENSITIVITY_REPORT_JSON --stochastic-baseline-source-runset BASELINE_SOURCE_RUNSET_JSON --stochastic-counterfactual-source-runset COUNTERFACTUAL_SOURCE_RUNSET_JSON] [--packet-id ID]`
- `agent-assure init controls-mutation [--out-dir DIR]`
- `agent-assure doctor controls-mutate [--config CONTROLS_MUTATION_YAML]`
- `agent-assure controls map EVIDENCE_PACKET_JSON --framework nist-ai-rmf|owasp-llm-top-10-2025|iso-iec-42001|mitre-atlas-2026-06 --out-dir REPORT_DIR`
- `agent-assure controls efficacy [--config CONTROLS_MUTATION_YAML] [--campaign CAMPAIGN_DIR] [--allow-external-campaign] [--out REPORT_DIR]`
- `agent-assure controls mutate --suite SUITE_YAML_OR_COMPILED_JSON --runset RUNSET_JSON --operator OPERATOR_ID --out REPORT_DIR [--seed INTEGER] [--waiver WAIVER_JSON_OR_YAML] [--fail-on-warn] [--fail-on-not-evaluated] [--today YYYY-MM-DD]`
- `agent-assure controls mutate --suite SUITE_YAML_OR_COMPILED_JSON --runset RUNSET_JSON --catalog core/v1 --out REPORT_DIR [--operator OPERATOR_ID] [--invariant-family FAMILY] [--threat-id ID] [--seed INTEGER] [--full-report|--fail-fast] [--waiver WAIVER_JSON_OR_YAML] [--fail-on-warn] [--fail-on-not-evaluated] [--today YYYY-MM-DD]`
- `agent-assure ci CANDIDATE_RUNSET --suite COMPILED_SUITE_JSON --out-dir REPORT_DIR [--baseline BASELINE_RUNSET] [--report-mode full|fail-fast] [--waiver WAIVER_JSON_OR_YAML] [--fail-on-warn] [--fail-on-not-evaluated] [--format text|json]`
- `agent-assure ci gate SUMMARY_REPORT_OR_PACKET_JSON [--artifact-root DIR] [--efficacy-policy CONTROLS_MUTATION_YAML_OR_PROFILE_JSON] [--require-efficacy] [--require-evidence-sensitivity] [--require-stochastic-evidence-sensitivity] [--allow-sensitivity-non-verdict] [--allow-legacy-unbound-comparison] [--strict-efficacy|--allow-advisory-efficacy] [--fail-on-warn] [--fail-on-not-evaluated] [--format text|json]`
- `agent-assure demo assure-the-assurance [--out DIR] [--clean|--no-clean] [--format text|json] [--strict]`
- `agent-assure demo evidence-sensitivity [--out DIR] [--clean|--no-clean] [--format text|json] [--strict]`
- `agent-assure rag sensitivity --suite SUITE_YAML --baseline-corpus DIR --counterfactual-corpus DIR --knowledge-contract CONTRACT_YAML --expected-relation decision_flip --out DIR [--synthetic-data-attestation ATTESTATION_JSON]`
- `agent-assure rag sensitivity plan --protocol REPEATED_PROTOCOL_JSON_OR_YAML`
- `agent-assure rag sensitivity finalize --template REPEATED_PROTOCOL_TEMPLATE_JSON_OR_YAML --compiled-suite COMPILED_SUITE_JSON --baseline-config BASELINE_UNCOMMITTED_LIVE_CONFIG --counterfactual-config COUNTERFACTUAL_UNCOMMITTED_LIVE_CONFIG --out REPEATED_PROTOCOL_JSON --baseline-config-out BASELINE_FINAL_LIVE_CONFIG_JSON --counterfactual-config-out COUNTERFACTUAL_FINAL_LIVE_CONFIG_JSON`
- `agent-assure rag sensitivity run --protocol REPEATED_PROTOCOL_JSON_OR_YAML --compiled-suite COMPILED_SUITE_JSON --baseline-config LIVE_CONFIG --counterfactual-config LIVE_CONFIG --live-protocol LIVE_PROTOCOL_JSON --out RUNSET_DIR --network-opt-in [--trust-config] [--ci] [--allow-external-script] [--allow-script-env]`
- `agent-assure rag sensitivity analyze --protocol REPEATED_PROTOCOL_JSON_OR_YAML --runset RUNSET_DIR --out ANALYSIS_DIR`
- `agent-assure rag study input-commitment --compiled-suite COMPILED_SUITE_JSON --config UNBOUND_LIVE_CONFIG_JSON_OR_YAML`
- `agent-assure rag study finalize --template STUDY_MANIFEST_TEMPLATE_JSON_OR_YAML --benchmark PROCESS_EQUIVALENCE_BENCHMARK_JSON --protocol CONDITION_ID=REPEATED_PROTOCOL_JSON_OR_YAML [--protocol CONDITION_ID=PATH ...] --out STUDY_MANIFEST_JSON`
- `agent-assure rag study review-registration --manifest STUDY_MANIFEST_JSON --record REGISTRATION_RECORD_JSON --template REGISTRATION_REVIEW_TEMPLATE_JSON_OR_YAML --out REGISTRATION_REVIEW_RECEIPT_JSON`
- `agent-assure rag study review-execution --bundle STUDY_PRE_REVIEW_BUNDLE_DIR --template EXECUTION_REVIEW_TEMPLATE_JSON_OR_YAML --out EXECUTION_REVIEW_RECEIPT_JSON`
- `agent-assure rag study bind-config --manifest STUDY_MANIFEST_JSON --benchmark PROCESS_EQUIVALENCE_BENCHMARK_JSON --condition-id CONDITION_ID --protocol REPEATED_PROTOCOL_JSON_OR_YAML --compiled-suite COMPILED_SUITE_JSON --baseline-config BASELINE_LIVE_CONFIG --counterfactual-config COUNTERFACTUAL_LIVE_CONFIG --baseline-config-out BASELINE_STUDY_BOUND_JSON --counterfactual-config-out COUNTERFACTUAL_STUDY_BOUND_JSON`
- `agent-assure rag study analyze --manifest STUDY_MANIFEST_JSON --benchmark PROCESS_EQUIVALENCE_BENCHMARK_JSON --evidence STUDY_EVIDENCE_DESCRIPTOR_JSON_OR_YAML --out STUDY_PUBLICATION_DIR`
- `agent-assure live adapters`
- `agent-assure live run COMPILED_SUITE_JSON --config LIVE_CONFIG_YAML_OR_JSON --protocol LIVE_PROTOCOL_JSON --out LIVE_RUNSET_JSON [--trust-config] [--ci] [--allow-network] [--allow-external-script] [--allow-script-env] [--strict-endpoint-resolution]`
- `agent-assure live evaluate LIVE_RUNSET_JSON --suite COMPILED_SUITE_JSON --protocol LIVE_PROTOCOL_JSON --out-dir REPORT_DIR [--confidence-level DECIMAL]`
- `agent-assure live compare BASELINE_LIVE_REPORT_JSON CANDIDATE_LIVE_REPORT_JSON --protocol LIVE_PROTOCOL_JSON --out-dir REPORT_DIR`
- `agent-assure live drift LIVE_EVALUATION_REPORT_JSON... --protocol LIVE_PROTOCOL_JSON --out-dir REPORT_DIR`
- `agent-assure live trajectory LIVE_RUNSET_JSON --report LIVE_EVALUATION_REPORT_JSON --protocol LIVE_PROTOCOL_JSON --out-dir REPORT_DIR`
- `agent-assure stream ingest EVENTS_JSONL --sequence-scope global|producer_local --out STREAM_RUN_JSON [--producer-field producer_id|node_id|span_id] [--diagnostics-out PATH]`
- `agent-assure stream evaluate STREAM_RUN_JSON --suite SUITE_YAML_OR_COMPILED_JSON --out-dir REPORT_DIR [--waiver WAIVER_JSON_OR_YAML] [--fail-on-warn] [--fail-on-not-evaluated]`
- `agent-assure release replay RELEASE_DIGEST_REPLAY_JSON [--artifact-root DIR] [--require-role ROLE] [--expect-commit COMMIT] [--expect-ref REF] [--require-current-commit/--no-require-current-commit] [--require-core/--no-require-core]`
- `agent-assure release pilot finalize --template EXTERNAL_PILOT_TEMPLATE_JSON_OR_YAML --out EXTERNAL_PILOT_EVIDENCE_JSON`
- `agent-assure release pilot review --bundle-root EXTERNAL_PILOT_BUNDLE_DIR [--evidence EXTERNAL_PILOT_EVIDENCE_CHILD] --template PILOT_REVIEW_TEMPLATE_JSON_OR_YAML [--out PILOT_REVIEW_RECEIPT_CHILD]`
- `agent-assure otel preview PATH [--out PATH]`
- `agent-assure otel export RECORD_OR_RUNSET_OR_SPAN_PLAN_JSON [--protocol otlp-http|console] [--endpoint URL] [--allowed-endpoint-host HOST] [--service-name NAME] [--timeout-seconds SECONDS] [--header-env NAME=ENV_VAR] [--header-file NAME=PATH]`

`rag sensitivity` accepts only the v1 `decision_flip` relation. It compiles one
deterministic fixture-mode suite case, validates two distinct exact-inventory
corpora and a self-digested knowledge-authority contract, and independently
reruns retrieval, subject generation, evidence linking, RunSet construction,
and ordinary evaluation for each arm. It writes `protocol.json`, both RunSets,
both evaluation summaries, a canonical `comparison-summary.json`, the detector
JSON/Markdown/HTML, a privacy-filtered assurance graph, a release manifest, and
a gate-ready evidence packet in JSON and Markdown.
It exits `0` for `responsive`, `1` for a valid `evidence_insensitive` result,
and `2` for invalid input, `confounded`, or `prerequisites_unmet`. A confounded
or prerequisite-unmet report is explicitly non-verdict. Exit `4` is reserved
for bounded internal construction/execution or artifact-publication faults;
declared sensitivity input and path-validation faults remain exit `2`.

Bundled sensitivity resources are classified as synthetic only when all pinned
suite/fixture, authority-contract, corpus, and corpus-snapshot digests match.
Every other exact input set requires a self-digested
`--synthetic-data-attestation` bound to the current suite, fixture manifest,
authority contract, two corpus digests, and two exact corpus-snapshot digests.
Reports distinguish
`bundled_digest_verified` from `operator_attested`; the latter is an author
assertion, not semantic verification. The protocol and report disclose
`raw_content_persistence=exact_corpus_and_fixture_utf8_embedded`. Exact raw
input UTF-8 is copied into detector artifacts and downstream packets, so custom
inputs must contain no real personal, confidential, or production data.

The output directory must be disjoint from both corpora and every authenticated
fixture root. If it already exists, it must be the complete exact deterministic
generation: all 17 single-link files, bytes, typed artifacts, and nested bindings
are verified through the pinned parent before idempotent adoption. A
partial generation, mismatched sidecar or packet, mixed namespace, link, or
unrelated artifact is invalid input and is not replaced. A fresh generation is
fully written and descriptor-validated in a random owner-only private sibling;
artifact handles are flushed, and POSIX also syncs the staged directory. It is
then committed with one atomic no-replace directory rename. The target is never
rolled back after commit. Pre-commit interruption can retain a non-adoptable
private stage. Later publication neither enumerates nor count-caps retained
stages; they can accumulate and consume storage or inodes, but planted
lookalikes cannot exhaust an application recovery limit. An exact committed
target remains adoptable.

The directory publisher makes a rooted advisory-lock attempt bounded at one
millisecond. Unsafe, planted, or contended lock entries are bypassed. Integrity
and writer convergence rely on private random staging, atomic no-replace
directory installation, and exact concurrent-generation adoption rather than
lock availability.

The v1 command runs only the `responsive`, `evidence_reversed`, and
`evidence_inertial` declarative fixture subject modes; it does not execute an
arbitrary agent or hosted model. The reversed mode is a negative control that
produces an incorrect decision flip without decision inertia while retaining
governing retrieval and links. Verdict-bearing stdout always states that the
synthetic harness result does not show that a model used contextual evidence
instead of parametric memory.

The canonical comparison sidecar is rederived from the exact nested RunSets
with the detector's fixed evaluation date, default gate profile, and no waivers.
It carries both canonical RunSet digests and intentionally omits producer-local
environment metadata. The producer's packet binds that comparison, the exact
counterfactual evaluation, the sensitivity report, and the graph's raw and
semantic identities in the same staged, atomically committed publication.

`demo evidence-sensitivity` stages the installed-package fixtures and verifies
one responsive control plus one caught evidence-inertial regression. The
ordinary wrapper exits `0` when that detector contract behaves as declared;
`--strict` propagates the expected blocking result as exit `1`. The demo is a
synthetic detector contract test, not a real-model benchmark or prevalence
measurement. See [Controlled RAG Evidence Sensitivity](evidence_sensitivity.md).

The nested `rag sensitivity plan`, `finalize`, `run`, and `analyze` commands are the
separate repeated stochastic workflow. `plan` verifies the self-digest and
independently recomputes the frozen exact-binomial critical value, type-I error,
and power at the declared `planned_inferential_clusters`, then prints its
canonical summary. This exact-N recomputation is required because the discrete
power-feasibility surface is not monotone.

`finalize` is the no-dispatch bridge from an authoring template and two
uncommitted live configs to an executable commitment. It snapshots the compiled
case prompts, governing corpora, knowledge-authority contract, and any
file-backed adapter resources; computes each arm's exact configuration, prompt,
case, corpus, authority, adapter, policy, and tool identities; derives the
closed expected recommendation/outcome assignments from the authority contract;
builds and self-digests the repeated protocol; and injects that protocol's
design commitment digest into both finalized configs. It then recomputes the arm
facts and fails if adding the backlink changed either execution identity. The
command never constructs an adapter, performs network I/O, or dispatches a model.

Each finalized config must use a distinct `.json` filename in the same directory
as its uncommitted input so relative resource paths preserve the exact bytes they
identified. The protocol output must also be distinct. Publication is bounded,
no-clobber, and serialized across overlapping finalize invocations. Before
preflight, the command acquires persistent, rooted, single-link advisory lock
files for every final output in canonical path order; invocations sharing even
one output cannot adopt that output until its current writer has finished. These
locks coordinate compliant Agent Assure writers and are not an authorization
boundary against a process that ignores advisory locking.

On POSIX and Windows, each acquisition uses nonblocking attempts governed by an
explicit 60-second monotonic deadline. A timeout releases any locks already
acquired by that invocation and fails before output preflight or creation.

All existing outputs are then preflighted, an exact existing output is accepted,
and any different content fails before an absent output is created. Absent
outputs are exclusively created through pinned parent directories. The command
never replaces a final output. On a recoverable failure it removes only entries
that the current locked invocation created and whose pinned device/inode identity
still matches; it never removes a pre-existing or concurrently substituted
entry. Completed invocations are convergent and idempotent. Before reporting success on POSIX,
the command syncs every unique parent directory in which it created a final
name. Windows has no directory-sync operation in this path; file handles are
flushed, while final-name durability remains subject to Windows filesystem and
host guarantees. A handled failure is rolled back when identity-bound cleanup
succeeds. An abrupt process or host interruption during an in-place write can
leave an exclusively created output complete or partially written. A retry accepts byte-exact completed
outputs but fails closed on a partial or differing entry; an operator must
inspect and remove that entry before retrying. The three-file operation is not a
single cross-file filesystem transaction. Source configs must not already carry an
`evidence_sensitivity_design_digest`.

`run` rejects either arm before
provider execution when its
live configuration does not match the exact prebinding, creates a new atomic
directory containing `baseline.runset.json` and
`counterfactual.runset.json`, and never performs the statistical analysis
implicitly. Every paired live invocation requires `--network-opt-in`; an
actually network-backed adapter additionally requires its configuration opt-in.
Risky configuration execution also follows the existing
`--trust-config`/`--ci` acknowledgement boundary.
Before dispatch, `run` reopens the exact `--protocol` file and exclusively
reserves its preregistered `execution_attempt_id` in a synced, output-independent
journal beside that file. A second invocation with a different `--out` still
fails before provider dispatch while the reservation remains. This local guard
depends on retaining and protecting the registered protocol directory; strict
global single-execution claims require an external append-only registry or
equivalent trusted coordinator.

`analyze` outer-joins both RunSets over the complete planned pair manifest and
embeds those observations in `statistical-sufficiency-report.json`. It writes
that artifact, the repeated protocol, exact unchanged privacy-safe baseline and
counterfactual snapshots as separate `baseline.source.runset.json` and
`counterfactual.source.runset.json` files, and the stochastic JSON/Markdown
views through an atomic privacy-checked publication. It accepts `--runset DIR`
or the mutually exclusive explicit
`--baseline-runset` and `--counterfactual-runset` pair. Exit `0` means the
derived stochastic state is `pass`; exit `1` covers `block`, `inconclusive`, or
`prerequisites_unmet`; malformed, unbound, privacy-rejected, or conflicting
input exits `2`. See
[Repeated Paired Evidence Sensitivity](repeated_evidence_sensitivity.md).

The analyzer always evaluates exactly the frozen
`planned_inferential_clusters` frame. A complete analyzable cluster contributes
its observed composite bit; a non-analyzable planned cluster contributes zero.
Observed/analyzable counts remain separate audit fields.
`maximum_exclusion_rate` is checked as an audit cap and never changes the
denominator. Missing pairs, incomplete source execution, or excess exclusions
therefore remain non-verdict even when a conservative exact analysis is
available for inspection.

The nested `rag study input-commitment`, `finalize`,
`review-registration`, `bind-config`, `analyze`, and `review-execution`
commands compose repeated conditions into a preregistered real-model study.
This is an untagged development surface; no real-provider study result is
included in the repository.

`study input-commitment` snapshots a compiled suite and unbound live config
without dispatch, renders the exact case-keyed provider inputs, and prints
their aggregate manifest digest. Owners run it for both arms and freeze those
digests in the manifest; final config binding and RunSet replay recompute them.

`study finalize` accepts a manifest authoring mapping, the exact
Process-Equivalence Benchmark v0.2 manifest, and one
`CONDITION_ID=PROTOCOL_PATH` entry for every condition. It strips any supplied
derived manifest, protocol-set, and hypothesis-rule digests, recomputes them,
then validates exact condition, benchmark-case, task, authority, protocol,
model, configuration, planned-frame, and decision-rule bindings. It neither
constructs an adapter nor dispatches a provider. Before finalization, the study
owner must place an independently materialized authoring/registration record
covering the exact frozen inputs in a genuine version-control commit or
append-only registry. `registration.reference_id` is that immutable record's
external locator and `registration.evidence_digest` is the record's digest;
it is not a circular claim that the record contains the self-digested manifest.
A
`local_digest_commitment` remains structurally usable but cannot permit a
confirmatory publication.

`study review-registration` takes that finalized manifest, the exact UTF-8
JSON registration-record bytes, and the mandatory human checklist in
`docs/templates/real_model_study_registration_review.yaml`. It checks the raw
SHA-256, requires explicit reference-resolution, byte-match, immutability,
coverage, and pre-observation attestations, enforces review before the
execution window, builds the self-digested receipt, and publishes it
no-clobber. It does not contact the VCS/registry or authenticate the reviewer;
those remain operator and repository-approval trust boundaries.

`study bind-config` verifies one frozen condition against the exact benchmark
and writes both study-bound arm configurations under the same lock-coordinated,
no-clobber, recoverable-failure rollback contract described above. This is not a
two-file crash-atomic transaction: abrupt termination or power loss can expose a
partial pair, which consumers must reject. The inputs and
outputs must be distinct, confined files, and neither arm may contain inline
environment values. Both outputs carry the same exact study-manifest digest;
the command fails before publication if either arm, configuration digest,
design commitment, compiled suite, protocol identity, prompt bytes, or
knowledge-contract bytes differ. It performs no provider dispatch and does not
grant network consent.

Execution remains the separately authorized `rag sensitivity run` command,
invoked once for each condition with the study-bound configs and the existing
network, risky-config, credential, and budget controls.

`study analyze` consumes a relative-path descriptor with exactly one sorted
entry per frozen condition:

```yaml
schema_name: real-model-study-evidence-input/v1
registration_record: registration/registration-record.json
registration_review_receipt: registration/study-registration-review.json
statistical_method_review_receipt: registration/study-statistical-method-review.json
execution_review_receipt: registration/study-execution-review.json
conditions:
  - condition_id: provider-model-condition
    registered_protocol: condition/protocol.json
    source_run_directory: condition/run
```

Both registration paths are mandatory, bounded, relative inputs. The
statistical-method review path is optional only for a non-publishable draft
replay and mandatory for publication readiness. The execution review path is
optional for a pre-review replay and mandatory for publication readiness.
Each source directory contains
`repeated-evidence-sensitivity-protocol.json`, `baseline.runset.json`, and
`counterfactual.runset.json`. A null `source_run_directory` is represented
as `not_executed`; it is not an escape hatch for a study result. The analyzer
compares the source protocol with the separately retained registered protocol,
replays the exact paired analysis, validates manifest backlinks and
provider/model/config/window/cost identity, and atomically publishes the
manifest, benchmark, exact registration record, canonical review receipt,
report JSON/Markdown, registered protocols, and any exact privacy-filtered
source protocols, RunSets, and observed-execution-provenance sidecars. It then
reopens and exactly replays the closed output inventory.

`study review-execution` consumes that exact closed pre-review bundle after
the planned execution window and a mandatory human checklist. It derives and
binds the manifest/report byte digests, every source RunSet ID and byte digest,
observed-provenance digests, and provider-response-ID-set digests. The reviewer
attests to independent provider log/account comparison; the command does not
cryptographically authenticate that reviewer or provider. Add the resulting
receipt to the descriptor and analyze into a new empty final directory.

Before provider execution, `study review-statistics` builds a self-digested
receipt from a qualified independent review template and binds it to the exact
manifest, benchmark, and registered protocol set. Reviewer identity and
qualifications remain out-of-band trust inputs.

Exit `0` means the factory-verified closed bundle is study-publication-ready:
the direct same-decision analysis and invariant controls satisfy the frozen
rules, all executions have real-provider provenance, and the exact external
registration record and provider-backed execution have timely operator review
receipts bound to the replayed bytes. A standalone report always keeps its
publication and confirmatory-permission flags false. Exit `1` means a
replayable bundle exists but is not study-publication-ready, including a
missing statistical-method or execution review, `control_failed`,
`not_executed`, `invalidated`,
`underpowered`, synthetic origin, or local-only registration. Invalid input,
privacy failure, or an output conflict exits `2`; a bounded unexpected
internal failure exits `4`.
The implementation records inapplicable statistics by omitting their fields,
never by manufacturing zero estimates. See
[Preregistered Real-Model Study](real_model_study.md).

OTLP authentication values are never accepted directly in command-line arguments. Use
`--header-env` to read a value from an environment variable or `--header-file` to read it
from a protected, bounded UTF-8 file. The legacy `--header NAME=VALUE` form is rejected
because process arguments are commonly retained in shell history and exposed to local
process inspection.

Externally supplied JSON artifacts, configurations, JSONL records, provider
responses, and external-script output retain their existing byte limits and
also enforce a shared maximum of 80 object/array nesting levels. JSON objects
with duplicate member names (including escape-equivalent names) and non-finite
numeric values are rejected. Over-depth input fails closed as input validation,
structured-output validation, or a runtime failure, as appropriate to the
calling boundary. Suite, live-config, variant, and waiver YAML uses the safe
loader and structural validation; aliases and merge keys, duplicate mapping
keys, non-string mapping keys, node depth over 80, and excessive node counts are
rejected. These rules are deliberate parser compatibility constraints.

`evaluate` writes `evaluation-report.json`, `evaluation-summary.json`,
`evaluation-report.md`, `dependency-inventory.json`, and
`release-artifact-manifest.json`, and prints a Rich console summary. The JSON
report and summary embed local environment metadata. The Markdown and console
report sections lead with candidate vs expectations. Unsupported live or
certification-style capabilities are reported as `not_evaluated`; they do not
fail the default gate profile.
When measured usage is present, the Markdown report includes total tokens,
tool calls, retries, latency, declared estimated cost, pricing snapshot IDs and
digests, cost-basis labels, and per-cost-observation evidence when a matched
denominator is declared. Missing usage is rendered as `not_observed`.
`--fail-on-warn` makes warning controls blocking; `--fail-on-not-evaluated`
makes unsupported capabilities blocking.

Evaluation metrics distinguish case-level results from global gate failures.
`evaluated_cases` counts suite cases with exactly one included run record.
`unevaluated_cases` counts missing, duplicate, or excluded case records.
`failed_cases` counts evaluated suite cases with fail findings, whether or not
the selected gate profile makes those findings blocking. `passed_cases` counts
evaluated suite cases without fail findings. Passed, failed, and unevaluated
cases partition total cases. Coverage failures for missing, duplicate, or
excluded records still fail the gate and are counted in `blocking_findings`;
global failures, such as expired waivers, incomplete ordinary run sets, or
blocked `not_evaluated` capabilities, are reported separately as
`global_blocking_findings`. Gate-profile-filtered fail findings are
non-blocking, but they roll up to `warn` and appear in warning controls rather
than being treated as a clean pass.

Waivers bind to a run-set digest, reason code, and exact `finding_id`; expired
waivers fail closed. An expired waiver whose artifact digest still matches is a
global blocker even when its former finding is no longer emitted; remove or
renew that waiver explicitly so stale governance exceptions cannot linger.
Evaluation reports record exactly one privacy-minimized disposition for every
supplied waiver: `matched`, `unmatched_artifact`, `unmatched_finding`,
`unmatched_reason`, or `expired`. Dispositions include the waiver ID, finding
ID, reason code, and expiry date, but omit owner, reviewer, and rationale.
Unmatched dispositions are audit metadata only and do not alter gate findings,
metrics, or rollup state.

`compare` writes `comparison-report.json`, `comparison-summary.json`,
`comparison-report.md`, `dependency-inventory.json`, and
`release-artifact-manifest.json`, and prints a Rich console summary. The JSON
report and summary embed local environment metadata. The Markdown and console
report sections lead with the candidate's expectation verdict, then explain why
it passed or failed, then show fixture equivalence, baseline context, control
changes, provenance changes, not-evaluated capabilities, and limitations.
Provenance-only differences are reported for review but do not create regression
verdicts. Fixture-equivalence failure is an invalid comparison and exits `2`.
When baseline or candidate usage evidence is present, comparison summaries and
reports include baseline and candidate usage summaries plus deterministic
integer basis-point deltas. Declared estimated cost deltas are compared only
when currency, cost basis, pricing snapshot IDs, and pricing snapshot digests
are explicitly declared and match on both sides.

Current first-party comparison summaries carry canonical baseline and candidate
RunSet digests. A comparison of the exact RunSets emitted by `rag sensitivity`
is compatible with the accompanying report even though ordinary `compare`
adds local environment metadata: sensitivity binding excludes only that
top-level environment field and still exactly compares every semantic field.
Non-default gate profiles or waivers remain outside the canonical detector
comparison and are rejected whenever they change its semantic projection.

`packet build` writes an `evidence-packet` JSON artifact, `evidence-packet.md`,
`assurance-evidence-graph.json`, `dependency-inventory.json`, and
`release-artifact-manifest.json` from an evaluation summary and optional
comparison summary. The ordinary `ci` producer writes and binds the same graph
beside its packet. The packet records SHA-256 file digests for the summary and
graph artifacts it encloses, the graph's semantic RFC 8785 digest, local
environment metadata, lockfile digest when a supported lockfile is present,
dependency-inventory digest, and an interpretation block. These exact-file
digests are
environment-bound reproducibility anchors, not signatures or attestations; they
are separate from the cross-platform-stable JCS content digests used for suites,
fixture manifests, and runset provenance.
If the enclosed summaries contain measured usage, the packet preserves that
usage evidence beside the governance findings. Usage evidence never changes the
deterministic gate state by itself.

`--evidence-sensitivity` carries one validated controlled RAG sensitivity
report. Its counterfactual RunSet must exactly match the packet evaluation; a
present comparison must exactly match both report arms. Packet construction
binds the report's exact bytes under the `evidence-sensitivity-report` role in
both packet digests and the release manifest, and the packet graph preserves its
typed status, endpoint, decision-inertia finding, reason codes, and limitations.
Packet CI consumes the nested gate effect: `evidence_insensitive` exits `1`,
`responsive` passes that dimension, and a sensitivity non-verdict becomes an
explicit `not_evaluated` outcome that blocks under `--fail-on-not-evaluated`.
Packet Markdown leads the sensitivity section with the same declarative-harness
non-claim as the direct CLI.

The public packet builder accepts a repeated study only as one atomic four-file
bundle: `--statistical-sufficiency`,
`--stochastic-evidence-sensitivity`,
`--stochastic-baseline-source-runset`, and
`--stochastic-counterfactual-source-runset`. It snapshots and schema-validates
all four inputs before publication, then reassembles the canonical paired
observations from the exact source RunSets. At the final publication boundary it
reopens both source paths and requires their identity and bytes to equal the
producer snapshots. A partial, mismatched, or concurrently changed bundle fails
and rolls back every owned output. Success establishes consistency at that
point in time; a later source change is detected by independent `ci gate`
verification rather than prevented by the packet builder.

When a packet carries the repeated-study sufficiency and stochastic reports, a
verdict requires both together and an exact subject join: the packet evaluation
RunSet ID and digest equal the counterfactual source dependency, and both source
RunSet execution-configuration digests equal their predeclared protocol arms. A
present comparison must equal both exact source-arm RunSet IDs and digests. The
packet's graph projection carries and validates the candidate RunSet and
configuration binding.

Packet artifact digests additionally require the source snapshots atomically
under `stochastic-baseline-source-runset` and
`stochastic-counterfactual-source-runset`; a present release manifest requires
the same roles. `ci gate` parses both files from its confined
release-manifest artifact root, recomputes each RunSet and every record digest
into the sufficiency dependencies, reruns the canonical paired observation
assembler, and requires the complete reconstructed observation tuple to equal
the sufficiency observations. Recommendation, outcome, disposition, cluster,
endpoint, and source-record semantics therefore cannot be changed behind valid
source digests. The in-process verifier may instead receive one explicit exact
baseline/counterfactual RunSet tuple. Nested statistical reports alone cannot
satisfy this verification; absent verifier-accessible sources make the packet
invalid.

`--control-efficacy` and `--efficacy-config` must be supplied together. The
first loads a validated `control-efficacy-report`; the second loads the
controls-mutation configuration and computes a digest-bound gate decision from
its required catalog, required operators, and configured effects. The packet
stores the report, exact gate profile, and decision together or stores none of
them. Validation re-derives the decision and requires exact equality. Its
Markdown renders this as catalog-relative assurance control challenge scope,
separate from the candidate evaluation's evidence closure. Packet construction
records the report and configuration file digests under the
`control-efficacy-report` and `control-efficacy-onboarding-config` artifact
roles. The latter role identifies the exact onboarding YAML passed to
`--efficacy-config` whose parsed policy determined the embedded profile.
Programmatic producers that bind a standalone gate-profile JSON file use the
distinct `control-efficacy-gate-profile` role; current packets reject the
ambiguous legacy `control-efficacy-config` role.

Packet construction requires schema-version coherence for every nested
persisted artifact constrained by the packet writer schema, except separately
versioned usage artifacts. The post-redaction JSON is validated against the
schema selected by the packet root version before any packet bytes are written;
current output uses the pinned current writer schema and coherent supported
legacy output uses its frozen schema.

CI acceptance is stricter than legacy model readability. A standalone legacy
comparison, or a comparison-bearing packet whose comparison lacks authenticated
baseline and candidate RunSet digests, is invalid with exit `2` by default.
This includes a schema-valid v0.6.3 packet downgrade whose candidate ID still
matches an evaluation carrying different bytes.
`--allow-legacy-unbound-comparison` is an explicit compatibility opt-in for
`ci gate` only; the human-readable decision records
`legacy_unbound_comparison=allowed`. The option is invalid when the selected
artifact has no comparison or already has both digests, preventing a latent
always-on downgrade policy. It is also rejected for a full `ci` producer
invocation and cannot make malformed legacy bytes loadable.

`init controls-mutation` creates four deterministic managed files under
`agent-assure-controls-mutation` by default: `controls-mutation.yaml`,
`suite.yaml`, `runset.json`, and `threat-applicability.yaml`. An exact rerun is
idempotent. An exact partial generation is resumed by creating only its missing
managed files; any differing managed bytes make the command exit `2` before
replacing a file. The authored configuration uses confined portable relative
paths and binds the installed package version, `core/v1` catalog, selected
operators, required operators, and efficacy gate effects. Selected operator
IDs are canonicalized into catalog-compatible lexicographic order at the
configuration boundary.

`controls-mutation-onboarding-config` is package-bound authored input. Its
`artifact_kind` and `schema_version` support strict parsing, but it is not an
exported evidence root and has no checked-in frozen JSON Schema compatibility
contract. Use the matching installed package to read or regenerate it; the
`control-efficacy-onboarding-config` packet digest role binds its exact input
bytes without promoting it to a frozen evidence artifact.

`doctor controls-mutate` performs ordered static, read-only diagnostics. It
checks the configuration and confined paths, package and schema versions,
suite/RunSet binding, threat manifest, catalog identity, operator selection,
required-operator coverage, configured operators' catalog threat references,
output path, and static applicability against the subject.
`CM_THREAT_SCOPE` names every configured catalog reference absent from the
manifest. Diagnostics are stable `PASS`, `FAIL`, or `SKIP` records with
bounded messages and actions. A ready workflow exits `0`; any blocking
diagnostic exits `2`. Doctor does not mutate a subject, run an evaluator,
execute a campaign, write workflow output, or access the network.

`controls efficacy` consumes a controls-mutation configuration and a validated,
atomically published campaign generation. The campaign directory comes from
`output_dir` in the configuration by default. An explicit `--campaign` is
still confined beneath the configuration directory unless
`--allow-external-campaign` is also supplied; the opt-out is intended only for
verifier-controlled inputs. The report is written to `control-efficacy` beside
that configuration by default. The command writes
`control-efficacy-report.json` and `control-efficacy-report.md`. Before writing,
it rejects lexical, resolved-path, symlink, junction, and hard-link aliases
between either output and the configuration, threat manifest, or validated
campaign generation inputs.

The report stores exact `caught / (caught + survived)` ratios. Inapplicable,
invalid-operator, invalid-subject, and execution-error outcomes remain separate
counts outside the denominator. A zero denominator is represented as `0/0`
with `undefined_zero_denominator`, never as a numeric rate. The same rules
apply to invariant-family and independence strata. All five independence
classes are emitted even when their counts are zero; only
`external_preexisting`, `third_party_contributed`, and
`first_party_precontrol` are eligible for independent threat-challenge counts.
Completed `caught` and `survived` results must use a deterministic evaluator
basis. Stochastic or human-reviewed verdict outcomes make efficacy input
invalid rather than contributing to the ratio.

Threat coverage is derived from the authored, self-digested threat manifest.
An applicable category is challenged only by a completed operator that
references it and targets a control declared present. A survived operator can
therefore exercise a threat category without satisfying its detector contract.
Critical operator status derives from applicable critical threat references;
unknown applicability remains explicit.

The report's semantic state and threat-scope state are independent of the gate
profile. The gate decision maps observed facts through explicit profile fields.
Required survivors, critical survivors, invalid/error outcomes, and
unevaluated required operators have block-only fields and non-bypassable
`block` floors. Remaining applicable survivors, critical and remaining
applicable uncovered threats, unknown applicability, and unscoped catalog
references may use configured `block`, `review`, `informational`, or `ignore`
effects. Critical uncovered threats emit `CRITICAL_THREAT_UNCOVERED` and map to
`review` by default. A blocking decision
exits `1`; invalid configuration, manifest, campaign, or binding input exits
`2`; pass and review-only decisions exit `0` after writing both report files.

Efficacy-aware CLI and programmatic gates use strict verification by default
when control-efficacy evidence is present. Evidence presence is a separate
requirement: `--require-efficacy` makes a missing efficacy section in an
evidence packet invalid with exit `2`, and supplying `--efficacy-policy`
implicitly requires that evidence. Without either presence requirement, a
packet with no efficacy section is gated on its evaluation and comparison
evidence and explicitly records `efficacy_evidence=absent`,
`efficacy_verification=not_requested`, and `efficacy_required=false`; it does
not claim an efficacy check occurred.

Evidence-sensitivity presence is independently verifier-owned.
`--require-evidence-sensitivity` makes a packet without the report invalid
with exit `2`, closing the optional-field stripping downgrade for workflows
that require Sprint 5 sensitivity evidence. Generic packet construction cannot
infer the missing requirement from a comparison alone, so release automation
must set this verifier option explicitly. When a report is present, confounded
and prerequisites-unmet states fail closed as invalid with exit `2`.
`--allow-sensitivity-non-verdict` is the explicit advisory opt-in that restores
an exit-`0` `not_evaluated` result; `--fail-on-not-evaluated` instead
continues to make that state blocking.

Strict verification of present efficacy requires a separate verifier-owned
controls-mutation YAML through `--efficacy-policy`; it pins the installed
catalog digest, exact selected and required operator scope, and the separately
loaded threat-manifest digest. Exit `0` requires a passing verifier decision,
`all_evaluated_applicable_caught`, `all_applicable_challenged`, and no
invalid/error or required non-verdict operators. Missing verifier inputs for
present efficacy are invalid with exit `2`. A bare profile JSON is accepted
only for `--allow-advisory-efficacy`; because it carries no separate selected
scope, its expected selected operators equal its required operators and a
report with any additional selected operator is rejected. Advisory mode
retains `--fail-on-warn` and `--fail-on-not-evaluated` behavior.

Every `GateDecision` records `efficacy_evidence` as `not_applicable`, `absent`,
or `present`; `efficacy_verification` as `not_requested`, `advisory`, or
`strict`; and the Boolean `efficacy_required`. Strict and advisory decisions are
distinguishable in structured CI output even when their outcome and policy
digests match. Verifier policy files and YAML-referenced threat manifests use
the confined-input policy: their lexical ancestor chain may not contain a
symbolic link, junction, or other reparse component, and the final file must be
a regular file with exactly one hard link. This deliberately fails closed for
symlinked checkout roots and hardlinked policy files.

`controls map` consumes an evidence packet and writes
`control-coverage-report.json` and `control-coverage-report.md` for the selected
framework. The report maps packet-resident evidence to framework concepts for
human review, includes a mapping digest and evidence-packet digest, preserves
claim-boundary limitations, and does not infer passing local controls from an
evaluation-summary rollup alone. Built-in mappings cover NIST AI RMF, OWASP LLM
Top 10 2025, ISO/IEC 42001, and the pinned MITRE ATLAS 2026.06 catalog.

`controls mutate` validates a compiled suite and RunSet, applies exactly one
built-in deterministic operator to an immutable copy, validates the transformed
subject, evaluates the normative expected-detection contract, and writes a
canonical `assurance-mutation-result`. When a transformed subject is produced,
the command writes it beside the result. The exact filenames are
`assurance-mutation-result.json`, `assurance-evidence-descriptor.json`,
`mutation-generation-manifest.json`, and, for `caught` or `survived`,
`mutated-runset.json`. Reports contain exact changed paths, digests, reason
codes, bounded finding summaries, operator and evaluator provenance,
independence class, and limitations; they do not copy raw prompt, completion,
message, or tool payload content. The result and descriptor bind the canonical
gate-profile digest, the order-independent waiver-set digest (including an
explicit empty set), and the evaluation date. The same source digest, complete
operator identity, and seed produce identical transformed bytes. The result
digest is identical only when every serialized result field other than the
self-digest is also unchanged, including the operator and expected-detection
identities, evaluator and protocol/population identities, gate profile, waiver
set, evaluation date, and resulting findings, state, diagnostics, and
limitations.
Callers that require an identical result digest must pass the same `--today`
value. When it is omitted, the command uses the current date, which is
intentionally part of the result digest.

With `--catalog core/v1`, `controls mutate` runs a deterministic campaign.
`--operator`, `--invariant-family`, and `--threat-id` are repeatable filters;
when multiple filter categories are supplied, an operator must satisfy every
category. Unknown or duplicate filters and filters that select no operator are
invalid input. Selection and execution always follow the catalog's canonical
lexicographic operator order, independent of CLI flag order.

Campaign execution completes three ordered source-preflight stages before
computing `source_digest`, constructing the catalog, or executing an operator:

1. the private copy must contain only strict JSON runtime values, or the command
   reports `mutation campaign source cannot establish a canonical JSON identity`;
2. that copy must pass version-aware RunSet validation and current-model
   projection, or it reports
   `mutation campaign source failed RunSet validation and projection`; and
3. both the copied input and validated projection must pass the bound
   privacy-detector profile, or it reports
   `mutation campaign source failed the bound privacy-detector profile`.

Each is a campaign-level invalid-input rejection: the CLI prefixes the fixed,
non-sensitive message with `invalid mutation input:`, exits `2`, and writes no
catalog, campaign, or per-operator artifact. No source digest is fabricated.
Without `--catalog`, schema or source-privacy failure remains the ordinary
single-operator `invalid_subject` result and its bounded result artifacts.

`--full-report` is the default and executes every selected operator against the
same immutable source. `--fail-fast` is mutually exclusive with it and stops
after the first `survived`, `invalid_operator`, `invalid_subject`, or
`execution_error`; caught and inapplicable entries do not stop execution.
Neither mode chains mutations. Full-report execution isolates an operator
failure and continues with the next selected operator.

Campaign output uses the fixed global filenames
`assurance-mutation-catalog.json`, `assurance-mutation-campaign.json`, and
`mutation-campaign-generation-manifest.json`. Per-operator files use the
canonical executed index:
`operator-NNN-mutation-result.json`,
`operator-NNN-evidence-descriptor.json`, and, when a transformed subject
exists, `operator-NNN-mutated-runset.json`. The campaign records selected,
executed, and pending order, per-operator applicability, expected and observed
detector evidence, prohibited substitutes, semantic states, bounded
diagnostics, provenance, independence, and limitations.

After a campaign generation is published, CLI output lists every executed
operator in canonical order with its semantic state and applicability. It also
prints complete state and applicability counts, including zero-count states,
followed by an exact-fixture scope boundary: caught entries support only their
declared transformations and expected-detector contracts, inapplicable entries
were not exercised, and the campaign itself is not a safety score or broader
robustness result. The separate `controls efficacy` projection is the only path
that derives a catalog detector kill ratio, with its numerator, denominator,
undefined state, strata, and limitations preserved explicitly.

The campaign and catalog are self-digested RFC 8785 JSON artifacts. Exact
campaign replay requires the same source and suite content, catalog digest and
selected order, package/operator/evaluator identities, mode, seed, gate
profile, waiver set, and evaluation date. Byte-identical evidence descriptors
also require the same generation timestamp.

The artifact files are staged and replaced as one rollback-capable generation.
Writers are serialized per output directory, and the generation manifest is
published last as the atomic commit marker after the member files are durable.
Readers must validate and consume the fixed files while holding the shared
generation lock through
`open_validated_mutation_artifact_generation`; a torn or interrupted
replacement therefore fails closed without a validation-to-read race.
`validate_mutation_artifact_generation` is a point-in-time diagnostic only. A
generation without a transformed subject removes an older fixed-name
`mutated-runset.json`. Suite, RunSet, and waiver input aliases with any fixed
output, through resolved paths, symlinks, junctions, or hardlinks, are rejected
before persistence.

Campaign files use the same staged, rollback-capable publication model under
the campaign generation manifest. The manifest is published last and binds
every present global and per-operator member by role, operator identity where
applicable, and file digest. Reusing the directory removes stale protected
campaign members that are absent from the replacement generation. Campaign
inputs may not alias any protected campaign output through lexical, resolved,
symlink, junction, or hard-link identity.

`demo assure-the-assurance` runs an installed-package, network-disabled
detector-of-detectors demonstration. It verifies a passing ordinary baseline,
a caught material-evidence mutation under the normal control, the same mutation
surviving a deliberately weakened gate profile, and rejection of an unrelated
blocking finding as substitute detection. It writes strong and weakened
campaign generations, `control-efficacy-report.json`,
`control-efficacy-report.md`, `control-efficacy-config.json`,
`evidence-packet.json`,
`reviewer-facing-report.md`, and `demo-summary.json`. The summary uses paths
relative to the demo root and records exact hashes for its review artifacts.
The wrapper exits `0` only when all expected facts and internal command exits
match. `--strict` instead returns the underlying blocking packet-gate exit.

`ci` evaluates a candidate RunSet, optionally compares it with a baseline, writes
reports, builds a packet, writes a dependency inventory and release manifest,
then gates the result. `--report-mode full` writes all deterministic findings.
`--report-mode fail-fast` emits only the first blocking candidate finding and
stops before comparison; it consumes an already-created deterministic RunSet and
does not short-circuit fixture execution. The report metrics continue to reflect
the evaluated RunSet, while the findings list is intentionally truncated. On
nonzero exit it writes `ci-diagnostics.json` with the structural outcome, exit
code, reason code, artifact path, validator, and report paths, and prints the
same decision as structured JSON. `--format json` emits one structural decision
object for every completed `ci` or `ci gate` evaluation, including successful
and nonblocking outcomes; it also emits an `invalid` decision when a named
input exists but cannot be loaded or validated. Default `text` output retains
the existing human-readable success behavior and the existing structured
failure output from full `ci`. Human-readable decision messages are redacted,
collapsed to one line, and stripped of Unicode control/format characters before
terminal output. JSON decisions retain structured values and use JSON escaping
for control characters. CLI syntax errors that occur before an artifact
can be evaluated remain ordinary Typer usage errors. Outcomes are `pass`, `review`,
`not_evaluated`, `fail`, or `invalid`; each outcome is validated against its
exit code. `ci gate` remains available for post-hoc gating of an existing
`evaluation-summary`, `comparison-summary`, `control-efficacy-report`, or
`evidence-packet`. Strict efficacy gating uses only the external verifier
policy for acceptance. Packet gating still validates the embedded,
report-digest-bound profile and decision exactly as producer provenance, then
derives a separate verifier decision. It combines that result with evaluation
and optional comparison decisions by structural outcome, never by parsing
display messages. Precedence is `invalid`, `fail`, `review`,
`not_evaluated`, then `pass`. Strict gating validates transported facts but
does not rerun operators. A protected CI workflow making an efficacy assurance
claim must regenerate the campaign and efficacy report from pinned inputs
before gating and protect policy, manifest, scope, and workflow changes with
required review.

When `ci gate` receives an evidence packet with a release manifest, it reopens
the referenced evaluation and optional comparison summary beneath a trusted
artifact root. The gate requires each exact file's raw SHA-256 to match both
packet digest records and the release manifest, and requires the fully parsed
summary to equal the nested packet summary. Without `--artifact-root`, the CLI
fully validates both the packet directory (the current producer layout) and the
enclosing source/Git root (the legacy repo-relative layout), deduplicates equal
candidates, and accepts only a sole valid root. If both distinct trees satisfy
every binding, the root is ambiguous and gating fails with exit `2`; if neither
does, the binding failure is surfaced. An explicit `--artifact-root` is used
exclusively and bypasses inference. Manifest paths remain relative, normalized,
and confined. `--artifact-root` is not accepted for other gate artifacts or for
a full `ci` run. A named root must exist and be a directory. Those checks occur
inside `ci gate`, so `--format json` reports a missing or non-directory root as
a structured `invalid` decision with exit `2` instead of a framework usage
message.

`live adapters` lists installed live adapter identifiers. `live run` consumes a
compiled suite, live run configuration, and `live-protocol-record`. The command
checks that the config matches the frozen protocol ID, digest, planned
repetitions, tool-schema and policy-bundle digests, request budget, cost
budget, retry policy, and rate-limit caps, then writes a `run-set` with
`execution_mode` `live` and protocol binding. When `tokens_per_minute` is
declared, the adapter must declare `max_output_tokens`; the runner reserves the
prompt character count plus max generated tokens before each provider call. The
static JSONL adapter is intended for offline tests and fixtures. The
`external-script` adapter invokes a configured script through a no-shell
subprocess harness, sends the live request as JSON on stdin, propagates W3C
trace context through environment variables and request JSON, enforces the
configured timeout, and expects JSON stdout containing either `content` or a
structured `record`. The script and working directory are reopened beneath the
live-config root for every request through component-pinned file and directory
leases. On Linux, the harness executes the exact bounded script snapshot from a
sealed memory file and changes directory through the pinned descriptor; a
subreaper supervisor cleans up ordinary descendants. On Windows, restrictive
path handles remain open while the child is created suspended, identities are
revalidated, and a kill-on-close job is assigned before execution resumes.
Other POSIX platforms fail closed because immutable descriptor-bound script
execution is unavailable. Scripts do not inherit the full parent environment
by default; only names in `script_env_allowlist`, bounded non-sensitive
`script_env` entries, and runner-injected trace/request variables are passed.
Inline `script_env` values are bounded and screened as reconstructed
`name=value` assignments for direct live execution. Repeated-sensitivity
finalization refuses every inline value because its finalized configurations
are published artifacts; runtime-only values must use `script_env_allowlist`.
The configured
interpreter or executable and runtime-loaded dependencies remain trusted host
state. The live request payload includes the original prompt text. Subprocess
spawn failures, timeouts, nonzero exits, invalid stdout, and stdout that fails
the structured output contract create redacted `emergency-process-record`
artifacts on the RunSet and a structured-output or runtime-failure live record.
Risky live configs require
operator acknowledgement before execution.
Prompt-driven runs (without
`--trust-config`) require a separate, default-deny confirmation for each
capability a config requests: external-script execution, network egress, and/or
selected host environment variables. Prompts identify the configured script,
the endpoint host for endpoint-bound adapters, and environment variable names
without displaying variable values; sensitive-looking configured display text
is redacted. External scripts are explicitly identified as unsandboxed same-UID
host code that can access caller-readable files and networks, signal peer
processes permitted by the OS, and load unpinned dependencies; their
`endpoint_url` is not presented as an enforced destination. Non-interactive CI
runs must pass `--trust-config` plus the matching risk-specific flags:
`--allow-external-script`, `--allow-network`, and/or
`--allow-script-env`. Every endpoint-bound network adapter requires endpoint
DNS safety screening to succeed during adapter construction and request
dispatch. `--strict-endpoint-resolution` is retained for CLI
compatibility only; endpoint DNS screening is mandatory for endpoint-bound
network adapters and cannot be disabled.
The OpenAI-compatible
chat-completions adapter uses Python standard-library HTTP support, requires
explicit `allow_network: true` in the live config, requires HTTPS and an API key
environment variable, and validates non-default endpoint hosts against the
declared allowlist. Literal localhost/private/link-local/reserved/multicast
hosts are rejected, resolved A/AAAA results are screened at adapter
construction, and OpenAI-compatible requests repeat that screen immediately
before dispatch. Each request dials only the numeric addresses accepted by that
screen while preserving the original hostname for HTTP Host, TLS SNI, and
certificate verification. This is per-request socket-level IP pinning, not
certificate or SPKI pinning. OpenAI runs must configure both prompt and
completion pricing rates before dispatch. Every network run also requires
`max_output_tokens` and a positive per-attempt cost ceiling. Before each network
attempt, including a retry, the runner reserves the full per-observation ceiling
against the total
budget. A failed or timed-out attempt retains that reservation because the
provider may have processed and billed it; only a successful response with
usable accounting replaces its own reservation with the observed or locally
estimated amount. The committed amount is persisted as
`cost_budget_committed_usd`. Generated- and total-token ceilings use the same
retain-on-ambiguity rule, reserving `max_output_tokens` plus the prompt UTF-8
byte length per network attempt and persisting both token commitments. If a
network response omits the usage needed for cost
accounting, or any response omits usage needed for a declared token ceiling,
the observation fails budget policy and later requests are not dispatched.
Configured retry backoff is capped at 300 seconds. These controls bound local
dispatch using conservative commitments; they cannot prove the provider's final
invoice or replace provider-side spending limits. OpenAI cost remains a local
estimate rather than a billing assertion. Live run records store redacted
summaries, provider/model labels, resolved provider-version metadata when
required by the protocol, observation IDs, trace context, cluster/source-group
IDs, repetition and schedule indexes, attempt/retry/rate-limit counters,
inclusion or exclusion state, timestamps, token counts when available,
estimated cost, estimated-cost source, conservative cost/token-budget
commitments, latency, and provenance digests. They do
not persist raw prompts or raw provider outputs.

The default `max_rate_limit_events` value is `0`, so the first rate-limit
response stops the run unless the frozen live configuration and protocol allow
rate-limit events.

`live evaluate` evaluates each included live observation against the compiled
expectation for its case, checks actual observations against the protocol
binding, then writes `live-evaluation-report.json` and
`live-evaluation-report.md`. The report includes completion status, stop
reasons, budget-exhaustion status, cluster-aware
expectation-pass rates, outcome rates, reason-code rates, exclusion rates,
pooled and cluster-mean rates, cluster counts, design effects, effective sample
sizes, largest-cluster sensitivity values, interval-center metadata that states
whether a confidence interval is around a cluster mean or pooled rate,
per-observation tool-schema and policy-bundle provenance digests, exploratory
flags, suite and execution-configuration digests, provider/model group
summaries, latency distributions, estimated-cost distributions,
observation-level findings, optional protocol-declared statistical-invariant
results, and limitations. Statistical-invariant results can include rare-event
one-sided Poisson upper bounds at their persisted effective confidence level and
observed cluster-correlation summaries with uncertainty. Confirmatory
Bonferroni Poisson endpoints use the endpoint-adjusted alpha for that bound;
zero observed critical events are reported as bounded evidence, not proof of
absence. Degenerate per-arm
cluster intervals are labeled as a
boundary heuristic rather than an ordinary t interval. It exits `1` when any included
observation has a blocking
expectation/policy finding or protocol exclusion limits are exceeded.

`live compare` compares two protocol-bound live evaluation reports. Group IDs,
baseline mode, non-inferiority margin, and confidence level come from the
`live-protocol-record`, not CLI flags. `concurrent_paired` mode uses matched
cluster-level pass-rate differences with the protocol-declared paired cluster
t-interval, paired cluster percentile bootstrap, or paired randomization test.
`fixed_reference` mode compares candidate cluster rates with the frozen
reference rate and does not use paired language. The command writes
`live-comparison-report.json` and `live-comparison-report.md`, including
baseline/candidate pass rates, pass-rate difference, a cluster-level interval,
compared-cluster count, effective sample size, exploratory status, p50 latency
delta, total-cost delta, and optional paired randomization test results.
Comparisons with fewer than 30 compared clusters, percentile bootstrap
comparisons with fewer than 50 compared clusters, or paired randomization tests
whose exchangeability declaration, identical included cluster sets, identical
included case/repetition sets within clusters, or exact-enumeration
prerequisites are not met cannot produce a confirmatory pass. When all paired
cluster differences are identical, the limitations section labels the
zero-width empirical interval as degenerate and the comparison cannot produce a
confirmatory interval pass. Paired sign-flip randomization is limited to a zero
non-inferiority margin. Exact equality at that zero margin is inconclusive and
returns `not_evaluated`, not `fail`. An actual non-inferiority boundary breach
remains a fail-closed gate result, not proof of candidate inferiority or a
statistically confirmatory regression. The comparison is time-bound to the
reports being compared and is not a general provider-quality claim.

`live drift` consumes ordered `live-evaluation-report` JSON artifacts and a
`live-protocol-record`, then writes `live-drift-report.json` and
`live-drift-report.md`. The report first checks cross-window comparability for
suite identity, baseline mode, analysis method, protocol digest, tool-schema
digest, policy-bundle digest, and timestamp order when timestamps are present.
Comparable series can report ordered trend, adjacent-window step changes,
separate dependence diagnostics from lag-1 autocorrelation and AR(1) summaries
when enough ordered windows exist, and EWMA state summaries named as governance
health, control reliability, or drift state when their declared window
threshold is met. Drift reports use
`not_evaluated` gate state and are exploratory by default; review signals do
not establish safety, compliance, clinical validity, provider quality, model
intent, or general model-quality regression. An invalid comparability result
writes the report and exits `1`.

`live trajectory` consumes a protocol-bound `run-set`, its
`live-evaluation-report`, and the matching `live-protocol-record`, then writes
`live-trajectory-report.json` and `live-trajectory-report.md`. The report
derives privacy-filtered observable state paths from structured run,
evaluation, and emergency-process records; summarizes observable transition
profiles over canonical state order; reports sequence invariants; surfaces
history-dependent checks; and summarizes operational event processes for
retries, rate limits, exclusions, malformed outputs, runtime failures,
emergency process records, and budget stops. Governance-control trajectory
findings and operational reliability warnings are reported separately. The
report uses `not_evaluated` gate state and is a review artifact; path coverage
does not prove unsafe paths are impossible. Missing timestamps, low event
counts, low exposure, weak transition support, or incompatible protocol binding
mark the affected outputs exploratory or invalid. An invalid trajectory report
writes the report when it can and exits `1`.

Transition profiles are Markov-style summaries over observable adjacent states;
history-dependent checks cover non-Markov conditions such as required review
before approval or complete claim-evidence history across retries.
Burst-window event-process screens are reliability review signals and do not
claim a fitted Hawkes or other point-process intensity model.

`stream ingest` consumes privacy-filtered JSONL stream events and writes a
`stream-run` artifact plus `stream-ingestion-diagnostics.json`. The sequencing
contract must be declared before ingestion. `global` means
`run_id + sequence_number` is the unique composite key. `producer_local` means
the key is `run_id + declared producer field + sequence_number`, and every
event must carry that producer field. Producer-local sequence numbers are not
globally comparable; each producer-local event must therefore include a
timestamp, and accepted events are merged by timestamp before producer-local
sequence tie-breaks. Global timestamps remain optional, but every supplied
stream timestamp must use strict RFC 3339 date-time syntax with an uppercase
`T` and either `Z` or a numeric UTC offset. Timestamps are normalized to UTC for
ordering and latency calculations. Duplicates with the same composite key,
same `event_id`, and same canonical payload digest are deduplicated with a
diagnostic count.
Conflicting duplicate `event_id` or digest values fail closed. At-least-once
producers must redeliver the same logical event with stable timestamp and
privacy-filtered payload fields when they expect idempotent deduplication.
Output events are sorted deterministically by run ID, sequence number,
timestamp, and digest for global streams, and by run ID, timestamp, producer,
sequence number, and digest for producer-local streams, so out-of-order arrival
jitter does not change the persisted trajectory.
The per-event `digest` field is optional for producers. When present, it must
match the ingestion projection, which is the stable wire contract for
cross-language producers: recursively remove `digest`, `event_id`,
`artifact_kind`, and `schema_version`; omit null object fields, empty projected
object/list fields, and default `currency: "USD"` fields; then SHA-256 hash the
canonical JSON projection.

`stream evaluate` projects a `stream-run` into a normal fixture-mode `run-set`,
writes `stream-runset.json` and `stream-span-plans.json`, then runs the
ordinary expectation evaluator. It revalidates persisted stream order,
composite-key uniqueness, event digests, and the stream ID before projection so
hand-edited `stream-run` artifacts cannot bypass the ingest contract. The
projection derives active evidence links, human-review route state, retry and
rate-limit counters, usage summaries, and ordered span-plan events from the
stream artifact without persisting raw prompts, raw tool arguments, raw token
chunks, or unredacted model output. A candidate can therefore keep the same
final recommendation and outcome while failing on a removed evidence link,
bypassed review route, or other observable process regression. Retry bursts and
usage changes are surfaced as measured review evidence by default; they become
blocking only when the suite or selected policy declares a blocking expectation.
In v0.5.0, stream span plans are flat per-run span plans. Source `span_id` and
`parent_span_id` values are preserved as event attributes for OpenTelemetry
consumers, but the persisted `span-plan` schema does not yet model nested child
span records.

`release pilot finalize` loads one bounded JSON/YAML authoring mapping,
removes any supplied self-digest, constructs `ExternalPilotEvidence/v1`
through its model builder, verifies an exact canonical-JSON round trip, and
publishes without overwriting different bytes. Its `--out` option is required
so an omitted publication destination fails during CLI parsing, before the
template is loaded or modeled. `release pilot review`
requires a closed flat bundle containing exactly that evidence and every
declared artifact, with the human-only template outside the bundle. It pins and
validates all bytes, derives the evidence-file SHA-256, artifact-manifest
digest, environment-control binding, pilot/participant identity, and release
line, and accepts only reviewer attestations from the template. After
no-clobber publication it verifies the complete bundle. An absent receipt or
an already-valid exact receipt supports idempotent reruns; any extra entry,
changed artifact, derived template field, different existing receipt, link, or
privacy violation exits `2`. Bounded internal faults exit `4`.

Both pilot commands keep persistent publication locks beside, rather than
inside, the evidence directory. They refuse a target directory that is the
current working directory or its ancestor, and refuse a lock root at the
filesystem root. Operators must run from the parent of a dedicated evidence
directory and name that output directory explicitly; the CLI will not silently
write a lock above the working directory.

`release replay` validates a `release-digest-replay` artifact under
`--artifact-root`. It recomputes raw SHA-256 file digests for replay-stable
source artifacts and stable JSON projection digests for environment-bearing
review artifacts. When replay verifies the release artifact manifest, it also
cross-checks each manifest-listed `sha256` against the available artifact
bytes, including SBOM, wheel, source distribution, and dependency inventory
entries.
For environment-bearing manifest children, the raw manifest hash is checked
against bytes and the manifest replay projection uses the child's stable digest.
By default, `--require-core` selects the first-party core roles from the replay
schema version. Supported schemas through v0.6.2 require compiled-suite,
fixture-manifest, evidence-packet, and release-artifact-manifest; v0.6.3 also
requires assurance-evidence-graph. An unmapped schema version fails closed, and
each explicit `--require-role` is additive to the versioned core set. Stable
graph replay removes only self/payload digests and summary source digests
transitively affected by excluded environment metadata; all semantic payloads,
states, identities, and edges remain covered.
The corresponding packet graph digest is normalized as a presence binding in
the stable projection, while raw packet, graph, and manifest hashes remain
byte-exact verification inputs. `--require-current-commit` requires the current
git checkout to match the replay file's `source_commit`;
`--expect-commit` checks the replay file's `source_commit` value without reading
the current checkout; `--expect-ref` checks the replay file's `source_ref`.
Replay artifact paths must be relative to `--artifact-root` and cannot contain
parent-directory segments. Digest mismatches, missing release artifacts, source
commit/ref mismatches, or unavailable git commit metadata when current-checkout
checking is requested exit `1`; malformed replay artifacts exit `2` through
Typer validation. Keyless cosign signature verification remains an external
`cosign verify-blob` operation documented in `docs/release_evidence.md`.

`otel preview` writes the privacy-filtered `span-plan` derived from a single
`agent-run-record`. `otel export` accepts an `agent-run-record`, `run-set`, or
precomputed `span-plan`, derives span plans where needed, and emits
OpenTelemetry SDK spans using either the console exporter or OTLP HTTP exporter.
OTLP export requires installing the optional `agent-assure[otel]` dependencies.
OTLP HTTP export requires an explicit HTTPS `--endpoint` and the endpoint host
must be supplied through `--allowed-endpoint-host`; SDK environment-default
endpoints are not used by `agent-assure`. OTLP endpoint DNS screening fails
closed and is mandatory; an unresolved host is always rejected.
The upstream OTLP exporter performs its own DNS resolution when connecting, so
the screened addresses are not pinned and a DNS validation-to-connect TOCTOU
window remains.
The OTLP transport passes an explicit endpoint and non-empty validated header
map to the SDK, uses a project-owned Requests session with `trust_env` disabled,
does not follow redirects, pins no compression, and clears ambient SDK
client-certificate state. Export constructs a resource containing only the
validated `service.name`, uses the W3C trace-context propagator directly, starts
unparented plans from an explicit empty context, and pins an always-on sampler
and schema-aligned span limits. Ambient SDK resource, propagator, sampler, and
limit settings are not used; an ambient SDK-disabled state fails closed.
Exporter results, exceptions, flush completion, shutdown, and the exact number
of exported spans are checked before the command reports success.
The exporter extracts any span-plan `traceparent` as parent context and emits
only attributes and events already present in the span plan. It is projection
from persisted span plans, not live instrumentation of the adapter HTTP request
or external subprocess lifecycle; provider-call timing remains the recorded
run metadata rather than SDK span timing. The exporter does not emit raw
prompts, raw outputs, tool arguments, unredacted summaries,
`gen_ai.response.tokens`, `gen_ai.operation.name`, or `rpc.method`.

Exit-code mapping:

- `0`: command succeeded with no blocking gate failure.
- `1`: evaluation, policy, invariant, or configured gate failed.
- `2`: invalid user input, schema validation failure, invalid comparison, or
  fixture-equivalence failure.

Tooling, IO, unexpected runtime, and internal errors are emitted by the command
that encounters them; current commands do not reserve a distinct stable exit
code for that class.

The development-RFC `controls mutate` command has a documented exit map because callers must
distinguish the mutation result from input and execution failures:

- `0`: `caught`;
- `1`: `survived`;
- `2`: invalid (`invalid_operator` or `invalid_subject`);
- `3`: `inapplicable`;
- `4`: `execution_error`.

The result artifact preserves `invalid_operator` or `invalid_subject` even
though both states share exit `2`.

Catalog campaigns use deterministic failure precedence plus an
all-inapplicable sentinel:

- `4`: at least one executed operator has `execution_error`;
- `2`: otherwise, at least one executed operator is `invalid_operator` or
  `invalid_subject`;
- `1`: otherwise, at least one executed operator `survived`;
- `3`: every executed operator is `inapplicable`;
- `0`: otherwise, including caught results and mixed caught/inapplicable
  results.

Campaign exits do not compute an aggregate score or ratio. A validated
campaign may be projected later by `controls efficacy`; that command preserves
the six outcome states and exact denominator semantics described above.

`invalid_subject` diagnostics distinguish bounded schema validation, privacy
violations, runtime privacy-profile incompatibility, suite binding, and fixture
binding without echoing source identifiers or digests. Unexpected evaluator
exceptions are `execution_error`, not subject validation failures. Catalog
identity failures also exit `4` with the bounded `catalog_integrity_error`
diagnostic.

Default roll-up precedence for comparison exits is `invalid_comparison`, then
`fail`, then `warn`, then `not_evaluated`, then `pass`.
`not_evaluated` capabilities remain separate unless the selected gate profile
makes them blocking. Warnings exit `0` unless `--fail-on-warn` is selected.
