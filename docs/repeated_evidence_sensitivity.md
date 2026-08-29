# Repeated Paired Evidence Sensitivity

The repeated evidence-sensitivity contracts answer one deliberately narrow
stochastic question: under a predeclared paired design, what proportion of the
frozen planned independent clusters exhibit the declared
`expected_decision_response` after the governing evidence changes, when every
non-analyzable planned cluster is conservatively scored as zero? That fixed
planned-frame composite is the confirmatory endpoint. Version 1 supports only
an authority-bound `decision_flip`: one arm must predeclare
`approve`/`approved`, the other must predeclare `deny`/`denied`, and each
observed arm must exactly match its own assignment.

This method does not establish causality, general model quality, provider-wide
behavior, safety, or compliance. Its population statement is conditional on
the frozen protocol, the observed execution window, the declared sampling
frame, and the cluster exchangeability assumption. The deterministic
[controlled RAG detector](evidence_sensitivity.md) remains a separate fixture
contract.

## Artifact chain

The method uses three self-digested `v1` roots:

1. `repeated-evidence-sensitivity-protocol` freezes the endpoint, pair
   identities, case-to-cluster map, sequential arm order, both exact arms,
   coupling declaration, multiplicity family, exclusions, and power plan
   before execution. Its separate design commitment is carried into both live
   configurations and source RunSets.
2. `statistical-sufficiency-report` records every planned pair, including
   missing and excluded cells, binds the exact baseline and counterfactual
   source RunSet IDs and digests plus canonical per-record membership
   commitments, recomputes sample counts, and evaluates the design
   prerequisites. The durable analysis bundle also carries the exact
   privacy-safe source RunSet snapshots as separate files; they are not copied
   into the sufficiency root.
3. `stochastic-evidence-sensitivity-report` derives the final state from the
   sufficiency artifact. A verdict-bearing result carries an exact
   `depends_on` reference to the satisfied sufficiency report ID and digest.

`prerequisites_unmet` identifies a structurally invalid study, such as an
undeclared arm difference or unresolved pairing. `inconclusive` identifies a
validly recorded study that cannot support the planned inference, such as
missing pairs, excess exclusions, incomplete execution, or exploratory or
fixture execution. Neither state can produce a passing stochastic verdict.

Published prerequisite checks report `unmet` whenever an evaluated condition
fails. `not_evaluated` is reserved for a check that was not assessed. Literal,
self-digest, multiplicity, powered-frame, and complete-manifest invariants that
schema validation has already made impossible to misstate are not republished
as independently “satisfied” checks. Independence and exchangeability are
explicit modeling assumptions and limitations, not empirical prerequisites
that the software claims to have verified.

## Endpoint and observational units

For case `c` and repetition `r`, the observational pair key is
`(case_id, repetition_index)`. The default independence cluster is `case_id`;
`source_group_id` is available only when the protocol and case schedule bind
that grouping before execution. The protocol contains an explicit, frozen
`case_cluster_bindings` map. Repetitions and multiple cases within one cluster
are not counted as independent inferential units.

Version 1 also requires every planned cluster to contain the same number of
cases; `repetitions_per_arm` is already global. This narrow restriction keeps
the strict all-pairs composite endpoint structurally comparable across
clusters. An unbalanced frame would give clusters different endpoint
compositions and make a common exchangeable Bernoulli probability implausible
by construction, so protocol validation rejects it before execution.

For an included pair, the binary endpoint is exactly:

```text
expected_decision_response[c, r] = 1
  when (baseline_recommendation, baseline_outcome)
       = frozen baseline expected assignment
   and (counterfactual_recommendation, counterfactual_outcome)
       = frozen counterfactual expected assignment
otherwise 0
```

The four frozen expected fields are copied into every included paired
observation and checked against the embedded protocol. An endpoint value of
`0` includes inertia, a wrong-direction flip, or any other valid structured
decision that misses either exact assignment. Provider/runtime failures and
blocker-policy records can never be scored as positive endpoints. A
predeclared operational runtime or budget failure is a zero-scored exclusion
only when its record carries the exact `runtime.live` blocker provenance emitted
by the live runner; it remains subject to the frozen exclusion cap. Malformed
structured output, missing or mismatched operational provenance, and unrelated
domain blocker failures are typed as invalid non-included pairs. Reports keep
`observed_counterexample_count` separate from `estimated_response_rate`.

The descriptive cluster endpoint is one bit per complete, analyzable cluster:

```text
observed_cluster_response[cluster] = 1
  only when every planned pair in that cluster is present, included,
  and has expected_decision_response = 1
  0 otherwise, provided the cluster is complete and analyzable
```

A cluster with any missing, excluded, identity-mismatched, or undeclared-
difference pair is incomplete and is not counted in
`observed_cluster_count` or `analyzable_clusters`. Those observed counts
remain descriptive.

`actual_pairs` counts planned cells with both source observations, including
excluded, invalid, or identity-mismatched cells; `actual_clusters` counts the
distinct clusters represented by those nonmissing cells. `included_pairs` and
`analyzable_clusters` remain stricter, separate quantities.

The confirmatory vector has a different, fixed denominator. It contains exactly
one bit for every frozen planned cluster:

```text
confirmatory_cluster_response[cluster] =
  observed_cluster_response[cluster] for an analyzable cluster
  0                                    otherwise
```

This zero assignment is explicit and pessimistic. Selective missingness or an
allowed exclusion cannot improve the one-sided upper-tail result by removing a
failure from the denominator. Whenever an exact analysis is present,
`estimated_response_rate` uses the confirmatory responding-cluster count
divided by the full planned-cluster count; the observed/analyzable counts remain
available separately. The embedded exact analysis makes that audit explicit
with `compared_clusters`, `analyzable_clusters`,
`non_analyzable_clusters_scored_zero`, `responding_clusters`, and
`planned_cluster_response_rate`; its difference from the null is persisted as
`planned_cluster_difference_from_null`. A deterministic fixture can report
observed pair counters, but it deliberately leaves the estimate unset and makes
no population claim.

The contract does not accept continuous outcomes, LLM-judge scores, semantic
similarity judgments, adaptive endpoints, or post-hoc endpoint substitution.

## Immutable arm prebinding

Both arms bind their content-derived execution configuration, governing corpus,
prompt manifest, case manifest, knowledge contract, expected decision,
provider/requested model, adapter resources, pipeline, tool schema, and policy
bundle. The only intended intervention is the governing evidence corpus; its
digest must be listed under `coupling.intentionally_different` as
`governing_corpus_digest`.

Before either live adapter is constructed, `run_repeated_live_study` snapshots
every bounded executable input. It loads and digest-verifies
`retrieval_corpus_dir`, renders those exact corpus documents into the provider
input, loads and validates `knowledge_contract_path`, verifies that contract
has the matching corpus assignment, and content-binds prompts and any JSONL or
external-script resource. A digest label without the verified corpus directory
and authority-contract file is not a confirmatory intervention.

The CLI and `run_repeated_live_study` always create both snapshots internally
from the rooted configuration paths; neither accepts a detached caller snapshot.
Lower-level library functions can consume a supplied `LiveExecutionSnapshot`,
whose exact bytes are then authoritative. That lower-level form binds what will
execute but, without configured per-resource digests or a signed preparation
receipt, does not independently attest that a hostile caller obtained those
bytes from the mutable paths named in the config.

Schema version `0.6.5` permits verdict-bearing confirmatory stochastic execution
only with the `openai-chat-completions` adapter. Static JSONL and external-script
adapters remain useful for deterministic or exploratory rehearsal, but cannot
be mislabeled as confirmatory live evidence.

The verified corpus evidence is delivered to the provider. The knowledge
contract is provenance and prebinding metadata, not additional provider prompt
content. A schema `0.6.5` `RAGSensitivityKnowledgeContract` carries a canonical,
unique `case_authority_bindings` entry for every planned case, with exact
corpus-to-expected-output assignments for both arms. The legacy scalar
case/query/assignment fields must mirror one of those entries; a legacy contract
without the collection is therefore safe only for a one-case frame. Finalization
fails unless both arm snapshots expose the same authority bindings and those
bindings exactly cover the frozen case frame.

The content-derived configuration digest `C` excludes only the design
commitment back-link, so it can be computed before the design digest `D`.
`D` binds both arms' exact `C` values, expected assignments, frame, endpoint,
and design. The finalized `D` is then carried by both configurations, every run
record, and both RunSets without changing `C`. Source validation requires the
same `C` and `D`, closing selection of a differently configured RunSet after
outcomes are known. This is a commitment and replay boundary, not an external
timestamp: without an append-only registry or signed time source it cannot
prove that only one execution occurred or prevent cherry-picking among
multiple executions made under identical `C` and `D`.

Resolved model and provider response metadata can exist only after a call.
The record preserves the requested model separately; a frozen non-null resolved
identity is enforced, while an unfrozen provider-returned snapshot remains
auditable rather than becoming a false mismatch.
An unexpected provider/model/tool/policy identity is retained as an
`identity_mismatch` or `undeclared_arm_difference` disposition and makes
statistical prerequisites fail closed; it is never silently dropped.

The complete case/repetition schedule is also frozen. Pair assembly performs
an outer join over that manifest, so a missing arm remains an explicit,
reason-coded record. Operational exclusions must use an exact predeclared live
producer reason and remain within the planned exclusion ceiling; each arm's
reason is retained independently. Malformed structured output and blocker-policy
records are invalid evidence, not operational exclusions, even if an author
places their reason text in the allowlist. Analysis additionally requires the exact two
source RunSet identities, digests, per-record identities and digests,
execution-configuration digests, operational-protocol identity, and shared
design commitment. A completed arm dependency must cover the frozen
`(case_id, repetition_index)` manifest exactly. An explicitly incomplete arm
may contain only a duplicate-free subset of that manifest, and that subset must
equal the observation's non-null source bindings. Extra, unplanned, duplicate,
or unconsumed dependency records are invalid. These dependencies are part of
the sufficiency artifact's canonical validation.

Verdict-bearing packet use binds the packet evaluation subject to the exact
counterfactual source RunSet ID and digest and requires both source RunSet
execution-configuration digests to match their predeclared protocol arms. If a
comparison is present, its baseline and candidate RunSet IDs and digests must
equal the two exact source arms. A verdict-bearing graph projection carries the
candidate RunSet ID, RunSet digest, and configuration digest and requires a
RunSet subject with those values. These checks establish exact subject and
configuration identity; they do not establish a causal intervention.

A stochastic packet also binds both separate source snapshots atomically in its
artifact digests under `stochastic-baseline-source-runset` and
`stochastic-counterfactual-source-runset`. A release manifest, when present,
must carry those same roles. Packet verification parses both RunSets,
recomputes each complete RunSet digest and every record-membership digest into
the two sufficiency dependency objects, and requires exact equality. It also
reruns the canonical paired observation assembler and requires the entire
ordered result to equal the sufficiency observations, including recommendation,
outcome, disposition, cluster, endpoint, and source-record semantics. A
verifier therefore needs either the confined release-manifest artifact root or
an explicit exact baseline/counterfactual RunSet tuple; without
verifier-accessible sources the packet is invalid. The nested reports alone are
insufficient for this replay.

## Coupling is not pairing

Structural pairing means that the two observations have the same planned case
and repetition identity. It does not prove that provider-side randomness was
shared. The coupling descriptor partitions every stochastic dimension into
canonical, disjoint `shared`, `intentionally_different`, `not_shared`, and
`unknown` sets and derives one of five classifications:

| Classification | Meaning |
| --- | --- |
| `fully_coupled` | Pair identity is verified and every declared stochastic dimension is supported as shared. |
| `partially_coupled` | Pair identity is verified; some stochastic dimensions are supported as shared and others are explicitly not shared. |
| `nominally_paired` | Pair identity is verified, but no declared stochastic dimension is supported as shared. |
| `unpaired` | The structural pair identity is not verified. |
| `unknown` | Pair identity exists, but at least one relevant stochastic dimension has unresolved sharing. |

A requested provider seed never establishes shared randomness. Version 1 does
not accept an authored digest as proof of provider seed sharing and forbids a
live protocol from marking `provider_sampling_randomness` as shared. It also
executes `baseline_then_counterfactual`, so `temporal_execution_order` cannot
be marked shared. The analysis may remain structurally paired when randomness
is unshared, but version 1 makes no variance-reduction claim under any coupling
classification.

## Binary design planning

Planning declares the one-sided cluster-response null rate `p0`, alternative
cluster-response rate `p1`, familywise alpha, desired power, and exclusion
ceiling. Both rates describe the planned-frame composite endpoint: one only
when every planned pair in a cluster is included and responds, otherwise zero.
Without an authored frame size, `plan_binary_paired_design` finds the smallest
planned-cluster count `N` and critical responding-cluster count `k` for which:

```text
Pr[X >= k | X ~ Binomial(N, p0)] <= adjusted_alpha
                                      and k / N > p0
Pr[X >= k | X ~ Binomial(N, p1)] >= desired_power
```

For a Bonferroni family, `adjusted_alpha` is `familywise_alpha / family_size`.
The planner uses the same exact one-sided binomial upper-tail test as the final
analysis; it does not use a normal approximation or a pair-level effective
sample-size substitute. Authors may instead supply
`planned_inferential_clusters=N`; the planner then recomputes `k`, exact type-I
error, and power at that exact `N`, and rejects the frame if it misses desired
power. Exact-test power is not monotone in `N` because the integer critical
value can jump, so a minimum powered size cannot justify a larger frame using
the smaller design's operating characteristics. The protocol must enumerate
exactly `planned_inferential_clusters` frozen cluster identities. The exclusion
ceiling is a runtime policy limit and does not change that frame:

```text
len(planned_cluster_ids) = planned_inferential_clusters = N
```

Planning `p0` and `p1` are probabilities for that entire planned-frame
composite cluster endpoint, not probabilities for individual calls or response
conditional on analyzability.

For a cluster containing one case repeated `R` times, if pair responses were
independent with common probability `q`, the all-pairs composite probability
would be `q^R`. Thus `R=30`, composite `p0=0.5`, and composite `p1=0.8` imply
pair-level values of approximately `0.977` and `0.993`, respectively. Real
within-cluster dependence changes that calculation, but never makes repeats
additional independent clusters. The shipped template therefore uses
`repetitions_per_arm: 1`. Authors choosing `R>1` must justify composite `p0`
and `p1` for that exact repetition rule; changing `R` changes the estimand.

## Exact cluster-binary analysis

Confirmatory inference assumes the predeclared composite cluster endpoints are
independent, exchangeable Bernoulli outcomes with a common null response
probability. For `N` frozen planned clusters and `S*` conservative responding
clusters after the explicit zero assignment, the authoritative p-value is
always:

```text
Pr[X >= S* | X ~ Binomial(N, p0)]
```

The fixed-`N` upper-tail test cannot become more favorable merely because a
planned cluster is not analyzable. Missing pairs, incomplete source execution,
and excess exclusions still make the report non-verdict even though the
conservative analysis may remain available for inspection.

The artifact persists a compact, lossless exact-tail expression: binomial
trials, observed-success threshold, and the null probability as integer
millionths. Validation recomputes the analytic tail from that bounded
expression. A separate six-place value is a conservative ceiling for displays;
it never drives the gate. The gate uses the frozen integer rejection threshold
planned above, which is exactly the same rejection region as the analytic test.
Above the predeclared diagnostic threshold, the implementation
may also simulate the same binomial null with a domain-separated SHA-256
counter bitstream and an unbiased rational Bernoulli sampler. Its stable seed
binds the protocol and observed counts. The Monte Carlo estimate is only a
reproducibility diagnostic: it never replaces the exact p-value and cannot
change `pass`, `block`, power, or sufficiency.

A satisfied report supports `pass` only when the responding-cluster count is at
least the frozen critical count. That threshold jointly enforces the exact
one-sided alpha bound and a planned-frame response rate strictly above `p0`.
Otherwise a statistically sufficient study returns `block`.
Underpowered, exploratory, deterministic-fixture, incomplete, or structurally
invalid studies remain non-verdict. No result establishes causality or general
provider or model quality.

## Authoring and finalizing a protocol

Start from
[`repeated_evidence_sensitivity_protocol.yaml`](https://github.com/acblabs/agent-assure/blob/main/docs/templates/repeated_evidence_sensitivity_protocol.yaml).
Its zero-filled digest fields are authoring placeholders and fail ordinary
artifact validation. Authors freeze the endpoint, planned case/cluster frame,
coupling and multiplicity declarations, powered design, limitations, two
uncommitted live configs, and the authority contract that declares the closed
per-case expectations. The configs must omit the sensitivity design back-link.
Arm identity/digest values in the authoring template are illustrative
placeholders: finalization derives and overwrites them from the exact compiled
suite, configs, prompts, corpora, authority file, and adapter resources.

```bash
agent-assure rag sensitivity finalize \
  --template repeated-protocol.authoring.yaml \
  --compiled-suite compiled-suite.json \
  --baseline-config baseline-live.uncommitted.json \
  --counterfactual-config counterfactual-live.uncommitted.json \
  --out repeated-protocol.json \
  --baseline-config-out baseline-live.final.json \
  --counterfactual-config-out counterfactual-live.final.json
```

Finalization performs no adapter or network dispatch. It derives both exact arm
bindings and the per-case authority projection, binds them into the non-circular
`design_commitment_digest`, computes the full `protocol_digest`, injects that
design digest into both emitted configs, and proves the backlink did not change
either content-derived configuration digest. Each finalized config output must
be a distinct `.json` sibling of its uncommitted input so relative resources
retain their meaning. Publication preflights all three outputs, never replaces a
concurrent entry, and accepts only exact idempotent outputs. It never unlinks a
final output during handled failure. An interruption can therefore retain a
complete or partial exclusively created file; a retry accepts an exact complete
file but fails closed on a partial or different entry until an operator inspects
and removes it. On POSIX, each unique parent containing a newly created final
name is synced before success. Windows flushes each file but provides no parent
directory sync in this path, so final-name durability remains filesystem- and
host-dependent. POSIX whole-file and Windows byte-lock acquisition both use
nonblocking attempts under an explicit 60-second monotonic deadline and fail
before preflight on timeout. The three outputs are not one cross-file
transaction.
Freeze and review the finalized JSON before execution; never derive or replace
these commitments after observing outcomes.

The CLI keeps validation, execution, and analysis separate:

```bash
agent-assure rag sensitivity plan --protocol repeated-protocol.json

agent-assure rag sensitivity run \
  --protocol repeated-protocol.json \
  --compiled-suite compiled-suite.json \
  --baseline-config baseline-live.final.json \
  --counterfactual-config counterfactual-live.final.json \
  --live-protocol operational-live-protocol.json \
  --network-opt-in --trust-config \
  --out .tmp/repeated-runs

agent-assure rag sensitivity analyze \
  --protocol repeated-protocol.json \
  --runset .tmp/repeated-runs \
  --out .tmp/repeated-analysis
```

The repeated `run` command always requires `--network-opt-in`, including for an
offline rehearsal; a configuration that disallows networking still cannot
perform network I/O. Static JSONL and external-script adapters are accepted only
for exploratory rehearsal and can never source a confirmatory population
claim. Static JSONL case-only fallback is permitted only when
`repetitions_per_arm=1`; a repeated study must provide an exact
`(case_id, repetition_index)` response for every cell. `plan` never executes an
adapter. `run` writes
the two arm RunSets but deliberately does not infer a result. `analyze` is the
only command that constructs paired observations, binds both source RunSets
and their record manifests, and writes the exact privacy-safe snapshots as
separate `baseline.source.runset.json` and
`counterfactual.source.runset.json` files beside the sufficiency artifact and
dependency-bound stochastic report.

## Live execution and network consent

The repeated runner reuses the existing live adapters and their safety
boundary. Network adapters require both `allow_network: true` in each trusted
live configuration and an explicit `TrustedLiveExecution(allow_network=True)`
acknowledgement. Credentials are read from the configured environment-variable
name at adapter construction; secret values are not fields in the repeated
protocol or its statistical reports.

```python
from agent_assure.live.adapters import TrustedLiveExecution
from agent_assure.rag.repeated_sensitivity import run_repeated_live_study

baseline, counterfactual = run_repeated_live_study(
    compiled=compiled_suite,
    protocol=repeated_protocol,
    baseline_config=baseline_live_config,
    counterfactual_config=counterfactual_live_config,
    operational_protocol=live_protocol,
    baseline_config_dir=baseline_config_dir,
    counterfactual_config_dir=counterfactual_config_dir,
    baseline_trust=TrustedLiveExecution(allow_network=True),
    counterfactual_trust=TrustedLiveExecution(allow_network=True),
)
```

Use the static JSONL adapter only for offline exploratory rehearsal. Its exact
response bytes are content-bound into the execution configuration. Network
consent authorizes the configured egress only; it does not broaden the
statistical claim or make rehearsal data confirmatory.

The repeated-run and repeated-analysis writers make a best-effort rooted
advisory-lock attempt per target, bounded at one millisecond. An unsafe, planted,
or contended lock is bypassed; integrity and writer convergence instead rely on
private random staging, atomic no-replace directory installation, and exact
validation before concurrent-generation adoption. Writers build and verify
every file in a random private sibling staging directory, then install the whole
directory with one atomic no-replace rename. The target path is absent before
that commit and is never rolled back afterward; an exact concurrent invocation
adopts the committed generation. On Windows, the winner's rename-pinning handle
can briefly deny a fresh verification lease while post-install identity checks
finish. Reconciliation retries only numeric WinError 32/33 for at most 250
milliseconds, repeating the full rooted identity, inventory, link-count, and
exact-byte validation on every attempt; all other errors and exhaustion fail
closed.
Linux requires `renameat2(RENAME_NOREPLACE)` through libc or an allowlisted
direct-syscall ABI, modern FreeBSD requires libc `renameat2`, and macOS requires
`renameatx_np(RENAME_EXCL)`. Missing kernel, filesystem, ABI, or libc support
fails closed without a check-then-rename fallback. Process
death or a handled pre-commit failure
can leave a hidden `.agent-assure-stochastic-*.tmp` sibling, but never a partial
target generation. Later publication ignores that non-adoptable staging entry
and does not delete it because ownership cannot be re-proved after interruption.
Handled pre-commit errors report the exact retained path. Later publication
neither enumerates nor count-caps retained stages, so planted lookalikes cannot
exhaust an application recovery limit; real remnants can still accumulate and
consume storage or inodes. Operators may remove them only after confirming that
no publisher is active; a safely created persistent lock file is expected and
should remain. An error after the
atomic rename explicitly reports that the target is committed and retained;
neither post-commit validation nor directory-durability failure triggers
rollback.

## Privacy and review boundary

Repeated artifacts persist bounded structured recommendations/outcomes,
digests, model/provider labels, pair dispositions, aggregate counts, and
method metadata. In particular, paired observations retain validated bounded
`recommendation` and `outcome` decision tokens derived from each provider
record; they do not retain the raw completion or response body. They do not
define fields for raw prompts, tool arguments, tool results, credential values,
or unrestricted provider payloads.
Inputs still pass through the existing live record redaction and bounded-output
contracts. Treat exact identifiers and digests as potentially sensitive
metadata and apply the repository privacy model to publication and retention.
The separate source RunSet snapshots remain full privacy-filtered artifacts,
not aggregate statistics. A packet that binds them extends its review and
retention boundary to those exact files even though it does not duplicate them
inside either statistical root.

This first method is intentionally narrow and would benefit from independent
statistical review, especially of the independent exchangeable cluster
assumption, the strict all-planned-pairs cluster endpoint, exclusion policy,
and the chosen cluster-level `p0`/`p1` for a real sampling frame. No independent
statistical review has yet occurred. Such review should be recorded separately
and must not be inferred from schema validation or test coverage.
