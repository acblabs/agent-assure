# Preregistered Real-Model Study

Status: development contract. No real-provider study result is included in this
repository, and no provider execution is authorized by this documentation. The
latest published package remains `v0.6.5`; the `0.6.6` schemas and commands
described here are an untagged development surface.

The real-model study workflow measures one narrow behavior: whether a model's
structured decision follows a frozen, authoritative context substitution under
an exact task, authority contract, provider/model identity, configuration,
protocol, and execution window. It does not estimate general model quality,
safety, or provider-wide behavior.

## Research Context

Prior work documents conflicts between contextual evidence and model memory,
including entity-based knowledge conflicts in question answering
([Longpre et al., 2021](https://aclanthology.org/2021.emnlp-main.565/)),
behavior under realistic context-memory conflicts
([Kortukov et al., 2024](https://openreview.net/pdf?id=xm8zYRfrqE)), and
context-aware decoding intended to reduce hallucination when evidence is
available ([Shi et al., 2024](https://aclanthology.org/2024.naacl-short.69/)).
A broader survey describes the relationship between language-model knowledge
and external knowledge ([Xu et al., 2024](https://aclanthology.org/2024.emnlp-main.486/)).

These papers motivate measuring the behavior. They do not validate Agent
Assure, establish this study's result, or justify a universal claim that
context should always override model memory. The authority contract is an
authored premise for each task, not a claim about every question or domain.

## Contract Set

The workflow uses six typed development artifacts plus the exact raw
preregistration JSON record:

- `ProcessEquivalenceBenchmark/v1` publishes Process-Equivalence Benchmark
  v0.2 as canonically ordered task, authority-contract, query-family, case, and
  source/input digest bindings. The manifest contains no observations or
  scores. At live binding, `input_digest` must equal raw SHA-256 of the exact
  UTF-8 prompt snapshot and `source_digest` must equal raw SHA-256 of the exact
  knowledge-contract file snapshot used by the runner.
- `RepeatedEvidenceSensitivityProtocol/v1` freezes one paired condition,
  including exact arm configurations, the planned case/cluster frame, and the
  sufficiency design.
- `RealModelStudyManifest/v1` binds all conditions, the benchmark, protocol
  set, the compact semantic study contract, each executable RAG knowledge
  contract, declared `execution_origin`, execution window, budget, publication
  policy, and hypothesis decision rule before provider observations.
- `StudyRegistrationReviewReceipt/v1` binds the exact manifest and
  preregistration-record SHA-256 to a mandatory human checklist completed
  before the execution window. The reviewer explicitly attests that the
  registration reference resolved, the external bytes matched, and the
  record's immutability was checked. Reviewer identity remains authenticated
  out of band, not by the JSON artifact.
- `StudyStatisticalMethodReviewReceipt/v1` binds a qualified, independent
  pre-execution review to the exact manifest, benchmark, registered protocol
  bytes, cluster frame, multiplicity/interval method, reachable decision
  boundaries, and negative controls. The receipt proves artifact identity and
  ordering; reviewer qualifications and conclusions are out-of-band human
  attestations.
- `StudyExecutionReviewReceipt/v1` binds the exact manifest and report bytes,
  both source RunSet byte digests and IDs for every condition, the derived
  execution-provenance digests, preregistered execution-attempt IDs, attempt-
  journal digests, and provider-response-ID-set digests to a post-window
  independent human review of provider logs and account records. The reviewer
  must explicitly attest that every issued attempt, failure, retry, terminal
  response, and planned cell is exhaustively accounted for.
  It makes that human trust boundary explicit; it does not authenticate the
  provider, account, reviewer, or response IDs cryptographically.
- `RealModelStudyReport/v1` is deterministically regenerated from the frozen
  manifest and privacy-filtered source RunSets. It records every condition,
  missing/excluded/invalid pair counts, sufficiency, cost and latency coverage,
  limitations, and the scoped hypothesis classification.

Each persisted root is self-digested. A source RunSet and every record used by
the study must carry the exact study-manifest backlink in addition to the
repeated protocol's design commitment. Digest consistency detects changed
bytes and mismatched bindings; it is not a signature, timestamp, or proof of
source authenticity.

## Inference eligibility and trust boundary

The manifest makes inference scope machine-readable rather than leaving it in
prose:

| Scope | Required design disposition | Report behavior | Bundle/readiness eligibility |
| --- | --- | --- | --- |
| `confirmatory_independent_clusters` | A resolved independent-cluster design basis, digest-bound independence audit, and explicit semantic-near-duplicate disposition accepted by the qualified reviewer. | `inferential_statistics_applicable=true`; the preregistered multiplicity, interval, and decision rules may classify only after every validity gate passes. | May satisfy `ValidatedStudyBundle.is_publication_ready` and Sprint 7, but only with all other real-provider, review, benchmark, and pilot requirements. |
| `fixed_frame_descriptive_conformance` | Shared-template dependence is acknowledged and the method reviewer approves the downscope. | `inferential_statistics_applicable=false`; classification is always `not_measured`; release-facing Markdown reports frame completeness plus counts/rates and omits inferential units, alpha, materiality thresholds, minimum-independent-cluster claims, and adjusted intervals. | May satisfy only scoped descriptive publication readiness. It can never satisfy the Sprint 7 empirical checkpoint. |

Distinct IDs and digests prove identity, not independence. The software binds
the structured design basis, audit digest, near-duplicate disposition, and
review decision; it cannot establish that the audit was competent or truthful.
Reviewer identity, qualification evidence, provider-log access, and provider
account access remain authenticated out of band.

The two knowledge digests serve different purposes and are deliberately not
interchangeable. `study_knowledge_contract_digest` binds the three-field
semantic premise stated in the manifest. `knowledge_contract_digest` binds the
full executable RAG knowledge contract used by both protocol arms, including
its actual query and authority machinery. Finalization rejects a semantic
digest mismatch; protocol validation rejects an executable-contract mismatch.

## Freeze Before Observation

Complete these steps before the first provider observation is collected or
analyzed:

1. Obtain human approval for the provider, exact model/version, execution
   window, budget, credential handling, and network use.
2. Select non-sensitive benchmark cases and freeze a repeated paired protocol
   for each condition. A confirmatory study protocol must set
   `maximum_exclusion_rate` to `0.000000`.
3. Fill the
   [study-manifest authoring template](https://github.com/acblabs/agent-assure/blob/main/docs/templates/real_model_study_manifest.yaml),
   including exact provider/model/configuration identity and the complete
   decision rule. The safe authoring default is
   `execution_origin: synthetic_fixture`; before registration, change a
   condition to `real_provider` only when it is planned for direct authorized
   provider execution with complete dispatch provenance. Never edit that field
   after observations begin.
4. Materialize a separate pre-observation authoring/registration record that
   covers those exact frozen inputs, and place that record in a genuine
   version-control commit or append-only registry.
5. Set `registration.reference_id` to the external immutable-record locator
   and `registration.evidence_digest` to the digest of that independently
   materialized registration record. Then finalize the self-digested manifest
   without provider dispatch.
6. Verify that the finalized manifest matches the registered commitments and
   bind both live arm configurations under lock-coordinated, no-clobber
   publication. Recoverable failures remove only transaction-owned entries, but
   the pair is not crash-atomic; consumers reject a half-bound pair left by
   abrupt termination or power loss.

Every study-bound live configuration must preregister
`fail_fast_on_excluded_response: true`. Binding rejects a false or omitted
value before snapshot preparation. A non-stop or malformed provider response
therefore invalidates the attempt and stops the unissued tail instead of
spending the remaining planned request budget.

`version_control_commit` and `append_only_registry` are the registration
methods eligible for a confirmatory conclusion. `local_digest_commitment` is
useful for drafting and replay but is deliberately ineligible for publication.
The registration record is separate because a commit that contained a manifest
whose own fields named that commit would create a circular identity. The model
validates the declared locator and evidence-digest shape; it does not contact
the VCS or registry or prove that the record is immutable. A human reviewer
must verify the external registration evidence, coverage, and time ordering.

For a `real_provider` condition, `expected_resolved_model` must end in a valid
`YYYY-MM-DD` provider snapshot date. This is a provider-neutral syntactic
preregistration constraint, not evidence that the provider's serving backend is
immutable. An undated alias such as `latest`, a date embedded anywhere except
the end, or an invalid calendar date is rejected. The exact resolved model ID
observed on every arm and repetition must still equal that frozen value.

Changing the benchmark, protocol, decision rule, planned frame, provider,
model, API/SDK/region identity, adapter, pipeline, either configuration, or the
declared execution origin or execution window after observation begins invalidates the affected
confirmatory condition. Start a newly registered study instead of editing the
old commitment.

## Prespecified Decision Rule

The primary endpoint is `direct_same_decision_inertia` on frozen
`decision_flip` conditions. An analyzable cluster is inertia only when every
included pair produces the same coherent decision/outcome tuple in both arms.
This direct classification counts both approve-to-approve and deny-to-deny
without inferring inertia as the complement of expected response. Exact
expected baseline-to-counterfactual movement is response; coherent movement in
the opposite orientation is `wrong_direction`; mixed non-inertial clusters are
`other_non_inertia`. Wrong-direction and other-non-inertia observations do not
manufacture support for responsiveness.

Frozen `decision_invariant` conditions are negative controls, not members of
the inertia estimand. Expected stability passes; any coherent arm change enters
`control_failed` with an exact unexpected-change rate and interval and blocks
the study classification. Stable-but-wrong or malformed decision/outcome
tuples invalidate the condition. Every provider/model/API/SDK/region/adapter/
pipeline execution identity represented by an inertia target must have a
model-matched invariant control, and vice versa; a control run against a cheaper
or otherwise different model cannot validate a target condition.

Missing, excluded, or invalid pairs never enter an analyzed endpoint. The
confirmatory protocol requires zero exclusions; any observed exclusion or
other deviation invalidates the condition and suppresses classification.

For each decision-flip condition `j`:

```text
decision_inertia_rate[j] =
    same_decision_clusters[j] / frozen_planned_independent_clusters[j]
```

The zero-exclusion confirmatory gate requires the analyzable cluster count to
equal that frozen planned denominator before an interval or classification is
reported. `analyzable_clusters` remains an execution diagnostic; it does not
silently substitute a post-observation subset into the inferential denominator.

Published decision-flip results also carry a descriptive, non-inferential
partition of same-decision inertia: clusters whose included members are all
baseline-correct, all baseline-incorrect, or mixed on baseline correctness.
Here, “correct” means agreement with the preregistered expected recommendation
and outcome tuple; it is not a claim of external, clinical, or policy truth.
All three rates use the same frozen planned-cluster denominator and their counts
must sum exactly to the direct same-decision inertia count. The partition does
not change the confirmatory estimand or its decision rule.

The manifest freezes the disjoint exhaustive inertia-target and invariant-
control condition sets, inferential unit `case_cluster`, minimum independent-
cluster count, finite-frame interpretation, exchangeability assumption,
materiality threshold, familywise alpha, and these exact rules:

- interval: one-sided exact Clopper-Pearson;
- multiplicity: Bonferroni across the frozen `target_task_model_conditions`
  decision-flip family only;
- adjusted alpha: conservatively rounded down to six decimal places before
  interval evaluation and serialized to twelve places;
- interval bounds: conservatively rounded outward to twelve decimal places;
- `supported`: any adjusted lower bound is strictly above the materiality
  threshold;
- `contradicted`: every adjusted upper bound is at or below the threshold;
- `inconclusive`: otherwise, but only after every condition is valid and
  statistically sufficient.

The support and contradiction directions are each separate one-sided claims
with familywise error controlled across target conditions by their own
Bonferroni bounds. The bidirectional rule is not one combined alpha-level
directional test: if a single error budget across either possible declaration
is required, the preregistration must allocate alpha between directions before
observations.

Manifest finalization evaluates the two extreme possible observations for each
decision-flip target under the same Bonferroni-adjusted alpha and conservative
outward serialization. It rejects a planned target unless both `supported` and
`contradicted` are mathematically reachable. Invariant controls instead apply
the prespecified zero-unexpected-change gate and do not consume alpha. Their
persisted intervals are descriptive uncertainty references evaluated at the
same target-family adjusted alpha; those intervals do not decide whether a
control passes.

Every condition's bound repeated protocol, including a control protocol, must
set `multiplicity_family_size` to the number of decision-flip targets. This
keeps protocol identity and persisted descriptive intervals aligned with the
manifest's inferential family without turning controls into inferential tests.

The canonical four-condition template contains two inferential decision-flip
targets and two exact-gate controls. Its familywise alpha `0.05` therefore gives
adjusted alpha `0.025`, not `0.0125`. At `n=42` and materiality threshold
`0.10`, the exact outward-rounded boundaries are deliberately asymmetric:

- zero inertia clusters have upper bound `0.084083854941`, so
  `contradicted` requires zero in both decision-flip targets;
- nine inertia clusters have lower bound `0.102959649897`, so `supported`
  requires at least nine in either target; and
- one through eight inertia clusters in every target are `inconclusive`.

For scale only, if each target truly had inertia probability `0.05`, the chance
of observing zero among 42 is `0.115982` per target; it is `0.013452` for both
only under the additional assumption that the two target-condition counts are
independent. These operating probabilities are design diagnostics, not study
results. The manifest's required `decision_boundary_rationale` freezes human
acceptance of this asymmetry before provider spend.

Exact intervals quantify binomial sampling uncertainty only under the declared
within-condition independent-exchangeable binary endpoint model. They do not
verify that assumption, remove selection bias, turn repeated calls into
independent units, or establish a causal effect.

Exact-tail recomputation is also deliberately resource-bounded. A single
interval pair permits at most 1,000 trials. Manifest finalization conservatively
charges the worst possible lower/upper pair for every target and control and
rejects a design that can exceed the fixed aggregate work ceiling; report
ingestion independently applies the same ceiling to observed interval cache
keys before nested interval validation. On one
reference run, exact calls at `n=100`, `250`, `500`, and `1000` took about
`0.04`, `0.15`, `0.43`, and `1.65` seconds. Without the aggregate guard,
two bounds for each of 64 1,000-trial conditions would therefore take roughly
3.5 minutes. Those are calibration landmarks, not service-level guarantees.
The aggregate ceiling is intentionally below the full structural
`64 conditions x 1000 trials` design space. If a prospective design can exceed
it, reduce or partition the design into separately preregistered and
independently interpreted studies before observations begin; never split an
observed report to evade the resource ceiling or multiplicity family.

The v0.2 frame is especially narrow: all 168 cases use one task, and within a
42-case stratum the visible input varies only by an integer eligibility score.
Distinct case IDs, authority bindings, fixture commitments, and globally unique
exact `input_digest` values block byte-identical prompt reuse and make replay
auditable. They do not detect semantic or near duplicates, independent task
families, shared prompt-template effects, or correlated model behavior.

Accordingly, the manifest records `sampling_frame` as
`finite_frozen_conformance_frame`, freezes the exchangeability assumption, and
requires a structured, substantive `independence_justification`. The shipped
authoring template is intentionally marked `unresolved_authoring_placeholder`;
real-provider registration and qualified statistical-method review reject that
status. A resolved author assertion records the inferential-unit definition,
positive design basis, dependence risks and mitigations, and residual scope
limitation separately. Software validates only that structure and presence. A
human owner must reject confirmatory use when independence is not defensible;
passing digest, structure, and reachability validators is not evidence that it
is true. Results remain scoped to the observed finite frame and must not be
generalized to a provider, model family, user population, or deployment
distribution.

## Result States and Fail-Closed Semantics

| Condition state | Meaning | Confirmatory statistic |
| --- | --- | --- |
| `analyzed` | Exact identity and protocol bindings hold, sufficiency is satisfied, and any invariant control is stable. | Role-specific direct endpoint is required and recomputed. |
| `control_failed` | An invariant negative control changed across arms. | Unexpected-change count/rate/interval retained; study classification blocked. |
| `underpowered` | Evidence is structurally usable but the frozen sufficiency rule is inconclusive. | Omitted. |
| `invalidated` | A protocol, identity, window, cost-accounting, source-replay, or other declared deviation exists. | Omitted. |
| `not_executed` | No observations exist for the planned condition; the complete planned frame is reported missing. | Omitted. |

`control_failed`, `underpowered`, `invalidated`, and `not_executed` conditions
force the study classification to `not_measured`; none can support or
contradict the hypothesis. Inapplicable statistical fields are absent rather
than populated with zero, explicit nulls, or estimates from a changed
denominator.
Invalidated conditions also omit the nested sufficiency and expected-response
diagnostic/source report so a consumer cannot mistake an embedded source
verdict for the study's invalidated result. For analyzed conditions, the
diagnostic exposes a neutral `diagnostic_state`; its nested Sprint 6 source
report retains the older `pass`/`block` replay state. For decision-flip
conditions, expected response is an inverse signal for direct same-decision
inertia. For invariant controls, the inertia estimand is inapplicable and
expected stability aligns with the control role; the exact zero-change gate,
not the nested source state, decides whether the control passes. All nested
source states remain non-verdict diagnostics for the Sprint 7 classification. Pair counts, failure
summaries, identities, execution timing, and operational accounting remain
available for audit.

A standalone `RealModelStudyReport` always records
`registration_evidence_verified: false` and keeps
`confirmatory_conclusion_permitted` and `publication_eligible` false. It can
classify the frozen analysis, but it cannot authenticate separate registration
bytes or a reviewer.

Study-only publication readiness is derived only after the closed-directory
verifier pins and replays the exact inventory, matches the raw registration
record SHA-256 to the manifest, validates the self-digested registration review
and its pre-execution ordering, validates a qualified independent statistical-
method review of the exact manifest, benchmark, registered protocols, cluster
assignments, multiplicity rule, and reachable decision boundaries before
execution, verifies observed real-provider provenance for every condition,
and validates a self-digested post-execution review against
the exact manifest, report, RunSet, provenance, preregistered attempt ID,
attempt-journal, and provider-response-ID-set digests. Real-provider provenance
also requires every included provider call to carry a normal `stop` finish
reason; missing or abnormal termination metadata invalidates the condition.
Provider serving fingerprints, when the provider emits them, must be present on
every arm/repetition and single-valued within each condition. Across every
model-matched target/control group, all otherwise valid conditions must then
either omit the fingerprint or report the same single value; partial group
coverage or a mismatch invalidates every otherwise valid member and suppresses
classification. Complete absence is allowed explicitly, and even a complete
stable value is provider-supplied metadata—not proof of immutable serving
infrastructure. The report binds each exposed stable value with a canonical set
digest and independently revalidates the group relation.
All three reviews are human attestations: Agent Assure does not
cryptographically authenticate the remote VCS/registry, provider account,
response IDs, immutability, or reviewer identities. A valid negative or
inconclusive result is eligible under the same rules as a supported result;
the implementation must not suppress or relabel it.

Operational accounting records both provider/local estimated cost and
`cost_budget_committed_usd`, which includes retry reservations. The aggregate
budget is enforced against the larger total. Crossing the preregistered
ceiling produces a valid, replayable `study-budget-exceeded` invalidated
artifact; it never produces a confirmatory statistic. The template's zero
budget is therefore a deliberately non-executable drafting default and must be
replaced only after human approval.

## CLI Workflow

Before freezing the manifest, compute each arm's exact case-keyed provider
input commitment from the compiled suite and unbound live config:

```bash
agent-assure rag study input-commitment \
  --compiled-suite condition/compiled-suite.json \
  --config condition/baseline.config.json
```

Run it separately for the baseline and counterfactual configs and copy the two
printed digests into the matching condition binding. The command snapshots the
configured resources and rendered provider inputs without dispatching a
provider. Final binding recomputes the same values and fails closed on drift.

Finalize a manifest from the template, exact benchmark, and every registered
condition protocol:

```bash
agent-assure rag study finalize \
  --template docs/templates/real_model_study_manifest.yaml \
  --benchmark examples/process_equivalence_benchmark_v0_2/benchmark.json \
  --protocol provider-model-condition=condition/protocol.json \
  --out study/real-model-study-manifest.json
```

This command computes the manifest, protocol-set, and hypothesis-rule digests
and validates exact benchmark/protocol coverage. Condition case frames must be
pairwise disjoint and together exhaust the supplied benchmark; each frame must
also be homogeneous for the relation and ordered decision orientation bound by
its protocol. It does not construct an adapter or dispatch a provider.

After independently resolving the external reference and checking the exact
record bytes, copy the
[registration-review template](https://github.com/acblabs/agent-assure/blob/main/docs/templates/real_model_study_registration_review.yaml).
The reviewer must run this before the execution window:

```bash
agent-assure rag study review-registration \
  --manifest study/real-model-study-manifest.json \
  --record study/registration/registration-record.json \
  --template study/registration/review.yaml \
  --out study/registration/study-registration-review.json
```

The command checks the raw record SHA-256 against the manifest, requires every
review assertion to be true, enforces `registered_at < reviewed_at <
execution_window.start`, builds the receipt's self-digest, and publishes it
without overwriting different bytes. It performs no provider dispatch and does
not resolve or authenticate the external reference itself; the human
attestation and repository approval are the trust roots.

After registration and before the planned execution window, a statistically
qualified reviewer who is independent of design, execution, and analysis must
complete the
[statistical-method review template](https://github.com/acblabs/agent-assure/blob/main/docs/templates/real_model_study_statistical_method_review.yaml).
Bind that review to the exact manifest, benchmark, and complete registered
protocol set:

```bash
agent-assure rag study review-statistics \
  --manifest study/real-model-study-manifest.json \
  --benchmark examples/process_equivalence_benchmark_v0_2/benchmark.json \
  --protocol provider-model-condition=condition/protocol.json \
  --template study/registration/statistical-method-review.yaml \
  --out study/registration/study-statistical-method-review.json
```

The command requires affirmative review of cluster assignments, independence
and exchangeability assumptions, the sampling frame and estimand,
multiplicity and exact interval construction, power and reachable decision
boundaries, and negative controls. It records substantive qualification and
independence rationales. Reviewer identity, qualifications, and the truth of
the attestations remain out-of-band trust inputs; the self-digested receipt
proves which local design bytes those attestations cover.

Then bind both arm configs in one operation:

```bash
agent-assure rag study bind-config \
  --manifest study/real-model-study-manifest.json \
  --benchmark examples/process_equivalence_benchmark_v0_2/benchmark.json \
  --condition-id provider-model-condition \
  --protocol condition/protocol.json \
  --compiled-suite condition/compiled-suite.json \
  --baseline-config condition/baseline.config.json \
  --counterfactual-config condition/counterfactual.config.json \
  --baseline-config-out condition/baseline.study-bound.json \
  --counterfactual-config-out condition/counterfactual.study-bound.json
```

Binding snapshots each arm's executable resources once, validates that same
immutable snapshot against the repeated protocol, and checks every configured
case against the benchmark prompt and knowledge-contract byte digests. No
second filesystem read is used for those checks. It also recomputes the exact
case-keyed provider-input manifest—including rendered governing evidence and
knowledge-contract identity—and requires it to match the arm digest frozen in
the preregistered study manifest. Replay derives the same aggregate from each
complete RunSet's `provenance.prompt_digest` values; a changed, omitted, or
case-swapped provider input invalidates the condition even if an attacker
recomputes the RunSet digest.

Provider execution remains a separate, explicitly authorized
`agent-assure rag sensitivity run` operation for each condition. It retains
the existing `--network-opt-in`, adapter configuration, credential, budget,
and risky-config consent boundaries. The study commands do not grant network
permission.

Next, copy the
[evidence descriptor template](https://github.com/acblabs/agent-assure/blob/main/docs/templates/real_model_study_evidence.yaml) beside
the registered protocols and source run directories, then analyze:

```bash
agent-assure rag study analyze \
  --manifest study/real-model-study-manifest.json \
  --benchmark examples/process_equivalence_benchmark_v0_2/benchmark.json \
  --evidence study/evidence.yaml \
  --out study/publication-pre-review
```

Descriptor paths are relative to the descriptor and cannot escape its root.
The exact registration record and canonical registration-review paths are
mandatory; the record is copied byte-for-byte and must hash to the manifest
commitment. The statistical-method review path is required for publication
readiness and may be null or omitted only for a non-publishable draft replay.
For each executed condition the source directory must contain
`repeated-evidence-sensitivity-protocol.json`, `baseline.runset.json`, and
`counterfactual.runset.json`. Keeping `source_run_directory: null` records the
condition honestly as `not_executed`.

The closed generation additionally contains the exact registration record,
canonical registration review, and a locally derived, RunSet-bound
observed-execution-provenance sidecar when dispatch metadata is complete. The
analyzer reopens and fully replays that exact inventory before returning.

The first complete real-provider analysis intentionally exits `1` and writes
a replayable pre-review bundle because execution truth has not yet been
independently reviewed. After the planned execution window ends, complete the
[execution-review template](https://github.com/acblabs/agent-assure/blob/main/docs/templates/real_model_study_execution_review.yaml)
and bind the review to that exact bundle:

```bash
agent-assure rag study review-execution \
  --bundle study/publication-pre-review \
  --template study/registration/execution-review.yaml \
  --out study/registration/study-execution-review.json
```

Set `execution_review_receipt` in the evidence descriptor to that relative
receipt path, then rerun `study analyze` into a new empty final directory. The
analyzer independently replays the exact publication pipeline and commits one
privacy-checked generation containing the manifest, benchmark, both human
review receipts, JSON and Markdown report, each registered protocol, and—only
for executed conditions—the exact source protocol and both privacy-filtered
RunSets. Exit `0` means the factory-verified closed bundle is
study-publication-ready: the direct analysis and invariant controls satisfy the
frozen rules, every execution has real-provider provenance, and both timely
operator reviews bind the exact evidence bytes. Standalone report publication
flags remain false. Exit `1` means a replayable bundle exists but is not
study-publication-ready, including a missing statistical-method or execution review,
`control_failed`, `not_executed`, `invalidated`, `underpowered`,
synthetic origin, or local-only registration. Invalid input exits `2`, and a
bounded internal failure exits `4`.

## Privacy and Interpretation Boundary

The manifest fixes `publish_raw_prompts`, `publish_raw_completions`, and
`publish_credentials` to false. The report schema has no raw prompt,
completion, tool-payload, or credential field. Published source RunSets still
contain structured decisions, stable identifiers, timestamps, provider/model
metadata, and sometimes provider response IDs. Those values can be linkable.

Use only non-sensitive benchmark inputs and privacy-safe pseudonymous IDs.
Apply source-system retention and access controls in addition to Agent
Assure's bounded pattern scanner. Pattern matching is not comprehensive DLP,
de-identification, consent, or publication authorization.

A reported decision-inertia rate is scoped only to the frozen benchmark,
authority contracts, task/model conditions, configurations, execution window,
and assumptions. Do not restate it as prevalence across models, proof that a
model used parametric memory, a vendor leaderboard, a safety probability, or a
claim that context should always govern.
