# Controlled RAG Evidence Sensitivity

v0.6.4 adds a deterministic, authority-scoped detector contract for one
narrow question: when the governing contextual evidence changes under an
otherwise controlled RAG protocol, does the declared decision response change
as expected?

This is a **synthetic detector contract test**. It operationalizes a declared
evidence-response relation for committed fixtures. It is not a causal
guarantee, a measurement of real-model failure prevalence, or a general
intervention framework.

For repeated stochastic live observations of the same narrow binary relation,
use the separate [Repeated Paired Evidence Sensitivity](repeated_evidence_sensitivity.md)
protocol. Its conclusions require a satisfied statistical-sufficiency artifact;
the deterministic contract described here does not produce population estimates.

The v1 producer is a declarative fixture harness/oracle, not an adapter for an
arbitrary agent or hosted model. It accepts only `responsive`,
`evidence_reversed`, and `evidence_inertial` fixture subject modes. The
responsive mode copies the retrieved document's declared governing decision and
outcome; the reversed mode returns the coherent opposite of each unique
retrieved approve/deny decision while preserving escalation for ambiguous
retrieval; and the inertial mode returns one fixture-fixed tuple in both arms.
These modes exercise the detector's pass, wrong-flip, and fixed-output paths. A
`responsive` state therefore checks the declared harness wiring. It is not
evidence that a model used contextual evidence instead of parametric memory.

## Run the installed-package demonstration

```bash
agent-assure demo evidence-sensitivity \
  --out .tmp/demo/evidence-sensitivity \
  --clean
```

The demo independently compiles the suite and reloads the fixtures, authority
contract, and corpus for each arm, then independently executes retrieval,
subject output, evidence linking, RunSet construction, and evaluation. It
requires the independently derived protocol-fixed setup to match exactly before
constructing the two-arm protocol. Policy A is the authority-bound baseline and
requires `approve` / `approved`; policy B is the counterfactual and requires
`deny` / `denied`. The responsive synthetic subject follows both authority
assignments. The evidence-inertial synthetic subject keeps the baseline approval
in both arms, so the detector emits
`EVIDENCE_SENSITIVITY_EXPECTED_RESPONSE_MISSING` and blocks that result.

The ordinary demo wrapper exits `0` only after verifying both the responsive
control and the caught evidence-inertial regression. Add `--strict` to propagate
the blocking detector result as exit `1`.

The repository-recorded terminal walkthrough in
[`assets/evidence_sensitivity_walkthrough.txt`](assets/evidence_sensitivity_walkthrough.txt)
captures the expected console contract, artifact review path, and strict exit
without presenting the synthetic fixture as external or prevalence evidence.

## Run the protocol directly

```bash
agent-assure rag sensitivity \
  --suite examples/evidence_sensitivity/responsive_suite.yaml \
  --baseline-corpus examples/evidence_sensitivity/corpora/policy_a \
  --counterfactual-corpus examples/evidence_sensitivity/corpora/policy_b \
  --knowledge-contract examples/evidence_sensitivity/knowledge-contract.yaml \
  --expected-relation decision_flip \
  --out .tmp/evidence-sensitivity
```

The suite must bind one of the three declarative v1 fixture subject modes. This
command does not invoke a user-supplied agent, generation endpoint, or hosted
model.

### Synthetic-data provenance and raw persistence

The bundled examples are accepted as synthetic only when the compiled-suite,
fixture-manifest, authority-contract, corpus, and corpus-snapshot digests match
the reviewed identities pinned in the package. Their reports record
`synthetic_data_provenance=bundled_digest_verified` and carry no attestation.

Any changed or external suite, fixture, contract, or corpus is a custom input
and must provide `--synthetic-data-attestation PATH`. That JSON artifact is a
self-digested `RAGSensitivitySyntheticDataAttestation/v1` record whose
`suite_digest`, `fixture_manifest_digest`, `knowledge_contract_digest`, two
sorted `corpus_digests`, and two sorted `corpus_snapshot_digests` bind the exact
current inputs, including the exact raw corpus-manifest UTF-8. It must explicitly
acknowledge raw-content persistence and attest that no real personal,
confidential, or production data is present. A binding mismatch, stale
self-digest, or missing attestation is invalid input (exit `2`) before
publication. Accepted custom runs record
`synthetic_data_provenance=operator_attested` and the attestation digest.

Operator attestation is an attributable machine-readable assertion by the
artifact author; it is not semantic inspection, independent verification, a
signature, or proof that the bytes are synthetic. The command embeds exact raw
UTF-8 for both corpus documents/manifests and selected fixture files in the
protocol, snapshots, report, and any packet that embeds the report. Do not run
custom inputs unless their author is authorized to persist and redistribute
every input byte. The privacy detector is a narrow fail-closed pattern screen,
not a general confidential-data classifier.

The semantic experiment exits are:

- `0` for a verdict-bearing `responsive` result;
- `1` for a verdict-bearing `evidence_insensitive` result; and
- `2` for invalid input, unmet prerequisites, or a `confounded` non-verdict.

Exit `4` is reserved for an artifact-publication error or a bounded internal
construction/execution fault. A declared `SensitivityInputError` and CLI path
validation failure remain invalid input with exit `2`.

These codes deliberately distinguish a detected response failure from an
experiment that cannot support a verdict.

## Controlled protocol

Both arms bind the same compiled suite, fixture manifest, request, normalized
query, query family, deterministic subject configuration, agent
implementation, prompt template, model identity, tool configuration and schema,
retrieval algorithm and version, `top_k`, knowledge-authority contract, and
producer version. The v1 controlled-difference vocabulary is closed.

Every controlled-difference check names its basis. Thirteen `protocol_fixed`
checks are structural setup guarantees: their values come from the independently
reloaded arm inputs but must match exactly before protocol construction, so they
are not arm-execution observations. Eight `arm_observed` checks compare values
independently derived from the baseline and counterfactual corpora or
executions. Only the latter have discriminating power between arms; the explicit
basis prevents structural invariants from being misread as 13 additional
empirical comparisons.

The `agent_implementation_digest`, `prompt_template_digest`, `model_digest`,
and `tool_schema_digest` fields are fixture-declared, unverified 64-hex
provenance labels. v1 does not hash an implementation, prompt, model, or tool
schema to derive them. Equality of those fields proves only that both arms
carry the same declarations; it does not authenticate the named resources.

The protocol carries the exact typed request, subject, and tool configuration,
their bounded raw UTF-8 fixture bytes, and the complete fixture manifest. Each
fixture role must resolve through exactly one declared fixture root to the
suite-selected `fixture_id`; its path, byte length, SHA-256, parsed model, and
canonical configuration digest are all revalidated. A valid file elsewhere in
the manifest cannot substitute for the selected fixture.

Only these two dimensions may differ:

| Dimension | Required relation |
| --- | --- |
| `corpus_digest` | different |
| `governing_evidence_digest` | different |

Every other registered dimension must compare equal. A difference in any of
them produces `EVIDENCE_SENSITIVITY_CONFOUNDED`, a non-verdict, and exit `2`.
The report preserves the exact corpus-manifest file SHA-256 values in addition
to the semantic corpus and evidence-set digests.

Each report also embeds self-digested exact corpus snapshots: raw manifest
UTF-8, raw document UTF-8, and the decoded typed document payloads. Across the
two arms, document path/source/reference catalogs must match, all non-governing
document content must match, and the governing document's retrieval identity
(including retrieval terms) must match. Only the governing document's exact
content and declared decision output may change. Added, removed, or modified
distractors therefore make the experiment confounded instead of silently
becoming part of the intervention.

Each arm starts from an independent setup path: suite compilation, fixture
manifest construction and role resolution, request/subject/tool loading,
authority-contract loading, and corpus loading. Exact equivalence of the
protocol-fixed setup is a fail-closed prerequisite. Each arm then independently
performs retrieval, subject decision generation, evidence-link emission, RunSet
construction, and ordinary suite evaluation. The detector does not edit a
completed run, inject intermediate state, resume a checkpoint, or reuse the
other arm's output. Validation independently replays the complete deterministic
retrieval from the authenticated request and snapshot, including overlap
scores, ordering, tie-breaks, and `top_k`, then derives links and output from the
authenticated declarative subject mode.

## Authority and evidence prerequisites

The self-digested knowledge contract binds exactly two distinct corpus digests
to one case, query family, logical source, reference, and claim target. Each
assignment also binds the governing document's exact content digest and its
expected recommendation and outcome. A `decision_flip` contract requires one
`approve` / `approved` assignment and one `deny` / `denied` assignment.

A verdict is available only when:

- both ordinary arm evaluations pass;
- the authority contract exactly matches both corpus inventories;
- both outputs are comparable decision tuples;
- the controlled-difference manifest contains no extra difference;
- both arms use the deterministic fixture subject and bound fixture identity;
- retrieval succeeds in both arms;
- the exact authority-bound governing evidence is retrieved in both arms; and
- both arms contain the exact claim-to-evidence link.

Missing governing retrieval or evidence links are prerequisite failures, not
evidence-insensitivity verdicts. Invalid or ambiguous authority input also
cannot become a detector pass.

## Endpoint and states

The only v1 expected relation is `decision_flip`. The endpoint
`expected_decision_response` is true only when each arm's exact
recommendation/outcome tuple matches its authority assignment after all
prerequisites pass.

| State | Verdict role | Gate effect | Meaning |
| --- | --- | --- | --- |
| `responsive` | verdict-bearing | `pass` | Both arms produced their exact authority-bound decisions. |
| `evidence_insensitive` | verdict-bearing | `block` | The valid protocol did not produce the expected decision response. |
| `confounded` | non-verdict | `non_verdict` | An undeclared controlled dimension changed. |
| `prerequisites_unmet` | non-verdict | `non_verdict` | Authority, retrieval, linking, evaluation, or comparability was insufficient. |

The report also carries an exactly derived `outcome_classification`:
`expected_response_observed`, `decision_inertia`, `wrong_direction_flip`,
`incomparable_response`, or `not_evaluated`. Its outcome message records the
directional authority-bound and observed decision paths, from baseline to
counterfactual. Report validation recomputes both fields from the authenticated
arm outputs, state, and observed relation; producers cannot supply independent
outcome prose. The exported canonical message helper applies the same directional
checks, including a bound binary expected flip for verdict-bearing outcomes.

Decision inertia is a narrower finding: both arms returned the same exact
recommendation/outcome tuple even though the authority-bound evidence changed.
The committed `evidence_reversed` negative control keeps governing retrieval and
links intact but returns the coherent opposite of each authority assignment. It
therefore produces `observed_relation=decision_flip`,
`decision_inertia_finding.detected=false`, and a blocking
`evidence_insensitive` state. This separately exercises a wrong flip that the
inertial fixture cannot represent.

## Review artifacts

The command publishes its artifact set transactionally:

| Artifact | Review purpose |
| --- | --- |
| `compiled-suite.json` | Exact compiled one-case suite used by both arms |
| `fixture-manifest.json` | Complete manifest bound to the protocol's raw fixture snapshots |
| `protocol.json` | Self-digested identities and controlled-difference manifest |
| `baseline-corpus-snapshot.json` | Self-digested raw and decoded baseline corpus evidence |
| `counterfactual-corpus-snapshot.json` | Self-digested raw and decoded counterfactual corpus evidence |
| `baseline.runset.json` | Complete baseline arm evidence |
| `counterfactual.runset.json` | Complete counterfactual arm evidence |
| `baseline-evaluation-summary.json` | Ordinary baseline expectation result |
| `counterfactual-evaluation-summary.json` | Ordinary counterfactual expectation result |
| `comparison-summary.json` | Packet-ready canonical comparison of the exact authenticated arm RunSets |
| `evidence-sensitivity.json` | Self-digested machine-readable detector report |
| `evidence-sensitivity.md` | Portable reviewer summary |
| `evidence-sensitivity.html` | Self-contained reviewer view |
| `assurance-evidence-graph.json` | Privacy-filtered graph over the exact evaluation, comparison, and detector report |
| `release-artifact-manifest.json` | Raw-byte identities for all 14 non-circular source and reviewer artifacts |
| `evidence-packet.json` | Complete gate-ready packet carrying the detector and exact graph binding |
| `evidence-packet.md` | Portable packet reviewer summary |

The report embeds the exact compiled suite, both complete RunSets, and both
evaluation summaries in addition to recording corpus and evidence digests,
authority assignments, retrieval/support/link checks for both arms, observed
and expected relations, the typed directional outcome, decision inertia, every
prerequisite and reason code,
deterministic status, assumptions, and limitations. A standalone report can
therefore authenticate and replay both executions without relying on sibling
files.

The canonical comparison sidecar uses the detector's fixed evaluation date,
default gate profile, and no waivers. It carries the baseline and candidate
RunSet digests and omits local environment metadata. A normal first-party
`compare` result over the same emitted RunSets is also accepted: the binder
ignores only its top-level environment field while retaining exact equality for
all identity, classification, state, provenance, finding, and usage fields.

Before any output directory is created, publication revalidates every model,
requires the embedded suite, RunSets, and summaries to equal their sibling
artifacts exactly, freshly re-evaluates both RunSets, and applies the privacy
profile recursively.
Decoded snapshot payloads are carried alongside raw JSON specifically so
Unicode-escaped sensitive values cannot hide inside an opaque string. Any such
value rejects the whole bundle without partial output.
The output directory must not overlap either corpus or any authenticated fixture
root. Publication pins its parent and serializes every cooperating writer for
that target when a rooted advisory lock is immediately available. Directory
publication treats that lock only as an optimization: acquisition is bounded at
one millisecond, and an unsafe, planted, or contended lock is bypassed. Integrity
and writer convergence instead rely on private random staging, atomic no-replace
directory installation, and exact validation before concurrent-generation
adoption. A fresh generation is built
in a random private `.agent-assure-sensitivity-*.tmp` sibling: the directory is
owner-only (`0700` on POSIX and a verified owner-only DACL on Windows), and each
artifact is created with exclusive, no-follow, single-link semantics (`0600` on
POSIX). The publisher retains every file descriptor while it rechecks the exact
inventory and bytes, reparses the graph, manifest, and packet, and verifies all
packet/manifest bindings from those same bounded snapshots. Every artifact
handle is flushed before commit. POSIX also syncs the staged directory before
rename and the parent afterward. On Windows, file flushing is requested, but
directory-entry durability remains dependent on the filesystem and host.

The sole target commit is an atomic no-replace directory rename beneath the
pinned parent. The target path is absent before that point and is never rolled
back afterward, including when a later durability check reports an error. A
concurrent or unrelated target is never replaced; platforms without a supported
atomic no-replace directory operation fail closed. Native Windows creation and
rename remain handle-relative, use no-delete-share leases while identities are
validated, and reject reparse or ACL drift. POSIX operations remain
descriptor-anchored and reject link or identity drift. Linux uses libc
`renameat2` or a direct syscall on an explicit ABI allowlist, modern FreeBSD
requires libc `renameat2`, and macOS requires `renameatx_np`; missing kernel,
filesystem, ABI, or libc support fails closed without a racy fallback.

A pre-existing target is inspected through the pinned parent and is adopted only
when all 17 single-link files are present, every byte equals the
complete deterministic generation, and the graph, nested/external manifest,
packet, packet Markdown, and all bindings revalidate. That exact generation
returns without rewriting any file. Windows reconciliation retries only numeric
WinError 32/33 for at most 250 milliseconds while an honest winner releases its
rename-pinning claim; every attempt repeats complete rooted and exact-generation
validation. Other errors, exhaustion, and any partial or different generation
fail closed. A handled failure or process interruption before commit can leave its
private sibling stage, but never a partial target. Such a stage is not adoptable
and is not deleted automatically because interrupted ownership cannot be proved.
A fresh publication neither enumerates nor count-caps retained stages, so
attacker-planted lookalikes cannot exhaust an application recovery limit.
Retained stages can still accumulate and consume storage or inodes. Operators
may remove them only after confirming no publisher is active. A safely created
persistent lock file is expected and should remain.

The producer automatically emits a complete evidence packet. Its four typed
packet digests bind the exact counterfactual evaluation, canonical
authenticated-arm comparison, detector report, and privacy-filtered graph.
The nested release manifest additionally binds the compiled suite, fixture
manifest, protocol, both corpus snapshots, both RunSets, the baseline
evaluation, and the sensitivity Markdown and HTML. Verifiers check every
manifest path for normalized confinement and every file's bounded raw SHA-256
before typed semantic checks. The manifest cannot bind itself or the packet
outputs without a digest cycle, so the packet JSON is the trust root: the
external manifest must equal its nested manifest, and packet Markdown must
equal a fresh rendering of the revalidated, privacy-safe packet. The report's
counterfactual RunSet is the packet's authenticated evaluation subject, and the
comparison exactly matches both arms. Packet CI blocks a verdict-bearing
evidence-insensitive result. A confounded or prerequisite-unmet report is
non-verdict and makes the emitted packet invalid with exit `2` by default.
`ci gate --allow-sensitivity-non-verdict` is the explicit advisory opt-in;
`--fail-on-not-evaluated` keeps that advisory result blocking.

The packet schema remains usable for workflows where sensitivity is not
applicable. Verifiers that require this detector must use
`ci gate --require-evidence-sensitivity`; this prevents a producer from
turning a blocking sensitivity packet green by removing the optional report and
rebuilding an otherwise self-consistent packet.

## Process-equivalence reproduction index

`examples/process_equivalence_reproduction_index.json` is a self-digested
synthetic reproduction index. Its v0.1 contract requires both of these strata:

- `same_output_different_process`, reproduced by the flagship demonstration in
  which the visible output stays fixed while a material evidence link disappears;
  and
- `evidence_insensitivity`, reproduced by this authority-flip demonstration.

Validate the index with:

```bash
agent-assure validate examples/process_equivalence_reproduction_index.json \
  --kind process-equivalence-reproduction-index
```

Each case keeps salient source-artifact anchors and also binds a complete source
closure for its demo resource root. The repository updater assigns the current
root for each stratum; the frozen contract validates only a canonical portable
path so a repository reorganization does not invalidate an already published
artifact. Each closure enumerates every recursive regular source file as a
sorted portable relative path plus SHA-256, excludes only runtime cache
artifacts under its declared policy, and hashes the canonical entry inventory.
Any in-scope file addition, removal, rename, or byte change therefore requires a
new closure digest and reproduction-index self-digest. Its closed replay record
selects one supported installed-package demo, JSON output, clean execution,
expected exit, and a stratum-specific machine-readable observation. The index
explicitly disables leaderboard, prevalence, and real-model measurement claims;
it is not a scored model benchmark.

## Research context and claim boundary

Prior work documents that language models can rely on parametric memory when
context conflicts with it, and that conflict behavior depends on experimental
setting and model/task conditions:

- Longpre et al., [Entity-Based Knowledge Conflicts in Question
  Answering](https://aclanthology.org/2021.emnlp-main.565/) (EMNLP 2021),
  formalize context–memory conflict for entity-based QA.
- Kortukov et al., [Studying Large Language Model Behaviors Under
  Context-Memory Conflicts With Real Documents](https://arxiv.org/abs/2404.16032)
  (arXiv:2404.16032), examine the phenomenon with real documents and report
  setting-dependent update failures.
- Marjanović et al., [DYNAMICQA: Tracing Internal Knowledge Conflicts in
  Language Models](https://aclanthology.org/2024.findings-emnlp.838/) (Findings
  of EMNLP 2024), study dynamic and disputable facts and their relationship to
  contextual updates.
- Shi et al., [Trusting Your Evidence: Hallucinate Less with Context-aware
  Decoding](https://aclanthology.org/2024.naacl-short.69/) (NAACL 2024), study
  context-aware decoding when contextual evidence conflicts with prior
  knowledge.

`agent-assure` does not claim to discover or estimate that research phenomenon.
It turns one authority-scoped expected relation into a reproducible,
digest-bound release control for a deterministic synthetic fixture. Extending
the method to hosted models, stochastic trials, or population estimates would
require a separate protocol and claim boundary, including an independent
generation path and retrieval evidence that is not itself the declared decision
oracle.
