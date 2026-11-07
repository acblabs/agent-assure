# ADR 0019: V1 numerical and statistical contracts

- Identifier: `ADR-V1-NUM-STAT`
- Ticket: `V1-BASE-04`; target: `stable-core`; operation: `decision_draft`
- Status: proposed for development acceptance; human acceptance and independent
  method admission are pending
- Preparation authority: the user's instruction to prepare the S1 prerequisites
  and Sprint 2; this document does not manufacture a signed start receipt
- Owner responsibility: `statistical_lead`; reviewer responsibility:
  `independent_method_reviewer`; assignments and competence require the current
  approved roster
- Author: LLM implementation agent; independence: `NO_INDEPENDENT_REVIEW`
- Required start purpose: `drafting_authorization`; completion purpose:
  `development_design_acceptance`
- Qualification owners: `V1-QUAL-02` for stable inference and directional
  authorization, `V1-STAT-04` for M1 diagnostics, and `V1-STAT-08` for optional F1
- Authorization effect of this draft: `none`

## Context and scope

The existing project distinguishes deterministic replay from stochastic
inference in ADR 0013 and preserves method prerequisites in ADR 0011. This
decision defines the proposed numerical and inferential contracts needed before
v1 implementation. It does not amend historical writer schemas, promote an
existing statistical helper, admit a method, or grant deployment authority.
ADR 0014 continues to make every LLM judge output advisory, including a label
used as a proposed endpoint. LLM-derived values cannot become verdict-bearing
through aggregation or a signed wrapper.

The source baseline is the private Revision 6.5 specification already identified
by `ADR-V1-MAP`. This ADR restates the operative design in original form. The
external completion receipt must bind this file's exact bytes; embedding its own
raw-byte digest would be self-referential. A development acceptance does not
replace the independently reviewed mathematical, sampling, implementation, and
qualification evidence required for later admission.

## Decision numbers and conservative replay

Decision values have separate fields for arithmetic representation and assurance.
Representations are integer, reduced rational, exact decimal, or diagnostic
binary-float string; assurance is `exact`, `certified_enclosure`, or `diagnostic`.
An exactly represented approximation is not automatically an exact result.

Rational numerators and denominators are bounded canonical decimal-integer
strings, with positive denominator, greatest common divisor one, unique zero,
and no plus sign or redundant leading zeros. Decimal coefficient/exponent pairs
have a unique normalization. Reject excessive digit lengths and exponent ranges
before allocation or arithmetic. JSON-safe integer rules remain intact; random
seeds use fixed-width hexadecimal strings. The numeric work profile must bind
maximum digits, operations, precision, wall time, and memory before execution;
an unspecified or exceeded limit cannot yield eligible decision evidence.

For a positive serialization quantum `q`, retain conservative endpoints
`L_stored = q floor(L/q)` and `U_stored = q ceil(U/q)`. Round an e-process lower
bound downward before using it to establish a crossing; round a rejection
p-value upward. Do not substitute one universal decimal precision for a margin
that requires finer resolution. Exhaustion yields `NUMERIC_RESOLUTION_INSUFFICIENT`
and a nonauthorizing review result.

A verifier reconstructs the method from the authenticated ordered source ledger
or sufficient replay state, validates persisted enclosures, and derives the
decision again. A producer verdict or digest alone is insufficient. Each result
binds algorithm/version, source and protocol digests, arithmetic and precision,
rounding, bounds, work status, platform/dependency profile, and randomization
identity. Moment summaries do not suffice when a claim depends on historical
prefix maxima or exclusions. No unchecked float optimizer may certify a root,
cell, extremum, or crossing.

Strict inequalities remain strict after serialization. Equality at a margin or
crossing threshold is unresolved. Empty retained sets and contradictory certified
directional evidence are `STATISTICAL_CONFLICT`, which is distinct from malformed
arithmetic, an invalid enclosure, or method-assumption failure.

## Frozen method and adapter identities

| Method | Permitted proposed use | Required data and validity contract |
| --- | --- | --- |
| B1 `uniform-beta-binomial/v1` | Qualified time-uniform inference/reporting; no stable threshold-authorization adapter | Binary scheduled-draw clusters with a common conditional Bernoulli probability |
| D1 `bounded-mean-directional-e/v1` | Qualified one-sided mean-threshold support through its crossing adapter | Bounded scheduled-draw clusters, predictable bets, full-filtration null, and a registered common-mean bridge |
| M1-VA `bounded-mean-variance-adaptive/v1` | Separately scheduled advisory diagnostic | Bounded ordered clusters; candidate-mean conditional equality; certified outward extrema |
| F1 `fixed-frame-binary/v1` | Optional independently admitted finite-population inference | Already-realized fixed binary frame and verifier-controlled uniform sampling without replacement |

The stable release depends on admission of B1 reporting and D1 threshold use.
M1-VA and F1 are separate work. There is no automatic fallback among these
methods, fixed-sample Clopper-Pearson intervals, planned-frame rates, or causal
estimators. `bernoulli-one-sided-beta-mixture/v1-candidate` and a D1 cap of
`c=3/4` remain future identities requiring an amendment and new admission.

### B1: uniform beta-binomial mixture

For ordered binary values, define `S_t = sum(X_i)` and `F_t = t-S_t`. Freeze
the Beta(1,1) mixing distribution. For an interior candidate probability `p`,

```text
E_t(p) = B(S_t+1, F_t+1) / [p^S_t (1-p)^F_t]
       = S_t! F_t! / [(t+1)! p^S_t (1-p)^F_t],   E_0(p)=1.
```

Under an interior common conditional Bernoulli-`p` law, the likelihood ratio for any
fixed alternative is a martingale; integrating its nonnegative values over
the frozen uniform prior preserves that property. Ville's inequality supplies
the registered anytime exclusion bound. At `p=0` or `p=1`, compatible all-zero
or all-one paths have the exact value `1/(t+1)`, and the boundary process is a
nonnegative supermartingale. An impossible observation excludes that endpoint
without serializing infinity. The initial retained set
is `[0,1]`.

For an allocation `alpha`, retain every `p` for which the historical maximum
through the consumed prefix does not exceed `1/alpha`. Certified outward root
brackets must include unresolved regions. Historical exclusions are sticky;
terminal `(t,S_t)` alone cannot reconstruct them. Register either separate
directional inversions or one `alpha_CS <= min(alpha_PASS,alpha_FAIL)` and state
exactly which coverage guarantee is claimed. A simultaneous two-sided claim
must account for both allocations where required.

Uniform B1 extrema cannot feed stable threshold authorization:
`METHOD_DECISION_ADAPTER_UNADMITTED`. A future one-sided mixture needs its own
prior, alternative support, adapter, vectors, derivation, qualification, and
admission. A mathematical reason that a reporting interval is useful does not
waive this product admission boundary.

### D1: centered directional boundary e-process

An endpoint is normalized to `[0,1]`, with an interior registered margin
`0 < delta < 1` and fixed `c=1/2`. Each direction has its own consumed values
`Z_i`, moments, wealth, crossing history, and state. With a boundary prefix of
length `n`, write `S_n=sum(Z_j)` and `Q_n=sum(Z_j^2)`. Freeze

```text
mu_n = (delta + S_n)/(n+1)
q_n  = (delta + Q_n)/(n+1)
v_n  = q_n - mu_n^2
h_n  = v_n + (mu_n-delta)^2
     = [delta(1-delta) + sum((Z_j-delta)^2)]/(n+1)
r_n  = (mu_n-delta)/h_n

lambda_PASS = max(-c/(1-delta), min(0,r_n))
lambda_FAIL = min( c/delta,     max(0,r_n))
E_0^direction = 1
E_t^direction = product(1 + lambda_i^direction*(Z_i^direction-delta)).
```

The bet is evaluated before revealing any next-batch input or signal and stays
fixed for that registered batch. The values above are not posterior estimates
or additional observations: the unit pseudomeasure assigns weight `1-delta`
to zero and `delta` to one. Its total mass is one, first moment `delta`, and
second moment `delta`. Expanding around the resulting `mu_n` gives

```text
(n+1) v_n = delta(1-delta) + (delta-mu_n)^2
            + sum((Z_j-mu_n)^2)
          >= delta(1-delta) > 0.
```

Thus division by `h_n` is defined, and `v_n >= delta(1-delta)/(n+1)`.
An exact state violating the bound is invalid; a certified interval that cannot
establish positivity requires more precision. This derivation is agent-authored
design evidence, not an independent human method-review receipt.

For PASS, `lambda` lies in `[-c/(1-delta),0]`; its smallest factor occurs at
`Z=1` and is at least `1-c=1/2`. Under the PASS null
`E[X_i | F_(i-1)] >= delta`, predictability and the nonpositive bet give

```text
E[1 + lambda_i*(X_i-delta) | F_(i-1)] <= 1.
```

For FAIL, `lambda` lies in `[0,c/delta]`; the minimum factor occurs at zero
and is again at least `1/2`. Under the FAIL null
`E[X_i | F_(i-1)] <= delta`, its conditional expected factor is at most one.
The respective nonnegative wealth processes are therefore test
supermartingales. Their validity follows from the sign, cap, predictability,
and null; no optimality claim is made for the selected adaptive bet.

At empty history `mu_0=delta`, so both bets are exactly zero and both wealths
are one. Consequently the entire first batch is uninformative for crossing:
`zero_bet_prefix=min(first_batch_size,N)`. If `N<=first_batch_size`, no interior
threshold crossing is reachable. Activation must reject a qualification or
decision-time promise requiring one. A geometric ramp starts with a batch of
one but does not make the first observation informative; a nonzero initial bet
would change the statistical method identity.

The crossing event is a certified lower bound on historical maximum wealth
strictly greater than `1/alpha_direction`. Persist the first crossing prefix,
historical maximum, current-head wealth, allocation, and policy separately.
An equality or unresolved enclosure cannot cross. D1 emits a
`directional_crossing` descriptor, not invented extrema with `U<delta` or
`L>delta`.

Its mathematical rejection concerns a pointwise conditional null. A crossing
alone does not establish a claim about an arbitrary drifting sequence average.
Release-bearing use must bind `E[X_i | F_(i-1)]=mu` at all positions under the
admitted common-mean bridge, or an independently admitted replacement theorem.
Without that bridge use `ESTIMAND_TRANSLATION_UNSATISFIED` and retain advisory
status.

Exact reference checks for the interior method are:

| Margin and past values | Frozen PASS bet | Frozen FAIL bet | Consequence |
| --- | --- | --- | --- |
| Any interior margin, empty history | `0` | `0` | First-batch wealth remains exactly `1` |
| `delta=1/2`, history `[0]` | `-1` | `0` | A next zero multiplies PASS wealth by `3/2` |
| `delta=1/4`, history `[0]` | `-2/3` | `0` | A next zero multiplies PASS wealth by `7/6` |
| `delta=1/4`, history `[1]` | `0` | `1` | A next one multiplies FAIL wealth by `7/4` |

At `delta=0`, strict PASS is impossible. An eligible exact positive value or
an enclosure with positive lower bound is a null-impossible FAIL witness.
At `delta=1`, strict FAIL is impossible and an exact value below one or an
enclosure with upper bound below one is the mirrored PASS witness. An enclosure
touching the boundary is insufficient. Do not clamp boundaries by epsilon or
divide by zero. Reject transformed margins outside `[0,1]` with
`MARGIN_OUTSIDE_REGISTERED_BOUNDS`. For paired `D_i in [a,b]`, require `a<b`
and normalize both `X_i=(D_i-a)/(b-a)` and the margin. A sampled baseline is not
a population constant; its uncertainty stays in a paired design or a clearly
conditional fixed-reference estimand.

### M1-VA and F1 remain separate

M1-VA uses its own symmetric unit pseudomeasure: half at zero, half at one.
For candidate `m`, form past-only moments from that regularizer and use
`lambda_i(m)=clip((mu_n-m)/(v_n+(mu_n-m)^2),-1/2,1/2)`. Its product is a
martingale under the full-filtration conditional-mean equality at `m`.
Substituting D1's delta-centered regularizer silently changes this method.

M1 inversion retains
`C_t={m: max_(s<=t) M_s(m)<=1/alpha}` without assuming connectedness.
Only certified outward extrema of a conservative outer cover are needed;
unresolved cells stay in that cover. A cell may be removed only by a certified
lower bound over the entire cell at some prefix, or a separately reviewed
deterministic containment argument. Point sampling and a different confidence
sequence's coverage theorem do not justify pruning. Freeze precision, cell,
depth, digit, operation, time, and RSS limits; exhaustion returns a sound cover
and review. Preserve clipping breakpoints, outward interval factor evaluation,
downward-rounded log-prefix bounds, shared prefix caches, and exact exclusion
witnesses. Qualify adversarial paths through `t=5,000`. A moments-only restart
requesting historical exclusion is `REPLAY_STATE_INSUFFICIENT`. M1 is advisory
in v1; its historical synthetic growth illustration is not a sample-size or
performance promise.

F1 fixes `N` already-realized binary values and samples uniformly without
replacement. For a candidate total `K`, prefix successes `a` and failures `b`,

```text
L_t(K) = (K)_a (N-K)_b / (N)_t
Q_t    = sum_(k=0..N) L_t(k)/(N+1)
E_t(K) = Q_t/L_t(K) on feasible prefixes.
```

Here `(n)_r` denotes a falling factorial. Impossible totals are removed by
feasibility; do not divide by their zero likelihood. At support boundaries the
mixture may put mass on a branch impossible under the fixed-`K` law, so the
process is a nonnegative supermartingale, not necessarily a martingale.
Freeze `0<alpha_F1<=min(alpha_PASS,alpha_FAIL)<1`, charged to both directional
ledgers. Retain exactly feasible totals whose historical maximum has never
exceeded `1/alpha_F1`; persist sorted totals and first-exclusion witnesses,
not just their hull. For a nonempty set use normalized extrema and the strict
directional adapter. Census leaves the observed total feasible. Fresh stochastic
outputs for a fixed prompt list do not instantiate a fixed outcome population.

## Population, endpoint, and execution identity

The initial stable bridge is `iid-superpopulation-draw/v1`. Its estimand is
`mu_pi=sum_j pi_j E[X | case=j, frozen subject and within-draw protocol]`, for
one immutable probability distribution sampled with replacement at each
position. Freeze exact rational probabilities summing to one, stratum/case
materialization, endpoint/reducer, retries, bounds, missingness, and reset and
isolation receipts. A convenient benchmark permutation, fixed quotas, adaptive
case selection, and without-replacement sampling are different designs.

`verifier-scheduled-draw-cluster/v1` identifies a draw by the registered design,
verifier position, signed draw receipt, reset/isolation receipt, and case
lineage. Retries, tool calls, rollouts, rephrasings, and prompt aliases inside
one draw cannot create extra updates. Session/environment/window/RNG/source
attributes must agree within that key and do not split it. Repeated case
lineage may contribute independently randomized later draws only with this
admitted bridge and distinct valid draw/reset receipts; otherwise merge
conservatively. Endpoint outputs arrive as one atomic ordered vector for every
still-open endpoint at a position. Endpoint iteration or completion order
cannot select the bundle result.

Freeze `iid-full-filtration-common-mean/v1`. The null conditions on all prior
conceptual positions, endpoint information revealed before the next atomic
position vector, and revealed scheduler, provider, environment, retry, routing,
latency, and isolation signals, including earlier positions in a concurrent
batch. Components of the same atomic vector are not revealed sequentially;
conditioning on an earlier component would define a different filtration.
Freeze its `full_filtration_contract_digest`
into the registration, design receipt, method admission, checkpoint, and
qualification envelope. Pre-batch marginal means alone are insufficient:
if `X_1=X_2` is a fair Bernoulli and the frozen bet is `lambda=1` at `delta=1/2`,
each pre-batch marginal factor has mean one, but

```text
E[(1+(X_1-1/2))(1+(X_2-1/2))] = ( (1/2)^2 + (3/2)^2 )/2 = 5/4.
```

At the second conceptual position the conditional-mean null fails. This is a
counterexample to the marginal-only argument, not a counterexample to the
full-filtration theorem. A different joint-product bridge requires its own
identity, derivation, independent admission, and qualification.

The complete `within-draw-protocol/v1` binds endpoint meaning, materialization,
prompt program and distribution, rollout count/configurations/seeds, model
identity, tools and environment, eligibility, retry/timeout/missingness, reducer
inputs/configuration, and bounds. Recompute its canonical digest and require
agreement across every related receipt and rollout. An unbound prompt change
or protocol mismatch produces `ENDPOINT_PROTOCOL_NONSTATIONARY`; an intact
digest is necessary but does not prove the common-mean assumption.

### Predictable batching, anti-selection, and missingness

`fixed-batch-boundary/v1` registers `B>=1`; `B=1` is serial. The separate proposed
`geometric-batch-ramp/v1` uses `q_0=0` and
`b_r=min(2^(r-1),B_max,N-q_(r-1))` until the horizon is assigned. It starts at
one, doubles predictably, and repeats the cap once reached. Freeze horizon,
schedule generator and parameters, position assignment digest, maximum in-flight
count, analysis order, next-batch gate, and post-stop treatment before reveal.
Never resize using outcomes, latency, provider behavior, or realized cost.

Atomically checkpoint all endpoint states and bets before drawing any case or
revealing any input/signal for the next batch. Each signed draw receipt binds
that checkpoint, registration, position/batch, schedule, endpoint protocol,
and ticks satisfying `checkpoint_tick < draw_issued_tick <= execution_start_tick`.
Check exact coverage and duplicates; a caller's assertion that checkpointing
happened first is insufficient. No next batch launches until every launched
position has a terminal endpoint disposition. Ordered quarantine seals later
outcomes and correlated metadata from betting, tuning, continuation, release,
and candidate-selection actors until prior positions close. Omitting a known
outcome from state does not remove it from the filtration.

For admitted `directional_worst_case/v1`, every scheduled position has a
coherent latent bounded endpoint. At verifier-owned timeout/closure use
`Z_PASS=1` and `Z_FAIL=0`; observed positions use `X` in both streams. The
pathwise inequalities `Z_PASS>=X` and `Z_FAIL<=X` retain the respective
conditional nulls even with outcome-dependent missingness. Maintain separate
directional histories. A late value is `late_after_committed_imputation` and
cannot replace statistical history; independent consumers still receive it.
No coherent latent endpoint means `METHOD_ASSUMPTIONS_UNSATISFIED`. B1, M1,
F1, and causal interpretations do not inherit this missingness rule.

Only authenticated `pre_execution_infrastructure_retry` failures can retry the
same draw. A coarse sealed receipt proves no prompt delivery, process start,
token, tool action, side effect, or correlated detail was revealed. Preserve
position/case/provider/model/configuration and deterministic attempt sub-seed;
freeze attempt/time caps. Ambiguity, post-start failure, content rejection,
missing attestation, or exhaustion closes under the registered missingness
rule. Retry does not allocate a new sample or refund alpha. Qualification must
report imputation and retry rates, late values, and the sensitivity bounds
`E[Z_PASS]<=min(1,mu_X+P(missing))` and
`E[Z_FAIL]>=max(0,mu_X-P(missing))`.

### Closing, bundle composition, and launched-evidence drain

The canonical default is `close-on-first-decisive-crossing/v1`, explicitly
materialized in registration. Instantiate only mandatory PASS and enabled
FAIL-veto directions. A direction freezes at its first certified crossing;
same-atomic-update opposite crossings for an endpoint are conflict. Preserve
each endpoint's decisive prefix. Still-open endpoints continue on atomic
position vectors. Recompute the bundle with precedence
`CONFLICT > FAIL > PASS > OPEN`: any endpoint conflict closes conflict; any
enabled-veto FAIL closes fail; all mandatory PASS endpoints closing pass closes
pass; otherwise remain open. Horizon exhaustion while open yields review.
A fail-only endpoint need not cross to permit bundle PASS. An endpoint PASS
does not close a bundle with another required endpoint still open.

The separately qualified `current-head-threshold/v1` evaluates all applicable
thresholds at one authenticated common head. `historical-anytime-crossing/v1`
is reporting-only while execution continues. They cannot be selected after
observing which yields a favorable conclusion.

Every bundle close, including closure at the final launched position, first
enters `PENDING_LAUNCHED_EVIDENCE_DRAIN`. Its atomic close receipt binds the
endpoint vector and prefixes, launched-position set, compiler-derived exact
consumer-instance registry, final checkpoint, no-next-batch gate, tick,
signer, and predecessor. Statistical exclusion does not erase an observation.
Post-registration-prefix statistical exclusion takes precedence over
post-endpoint-prefix exclusion; otherwise a position is consumed through the
endpoint prefix. Keep late-after-imputation distinct. The untyped `audit_only`
wire label is forbidden.

Append-only `evidence-consumer-disposition/v1` records bind every launched
position and exact consumer/claim/obligation instance to source evidence,
disposition, predecessor, result, prefix, and derived effect. Temporal,
integrity, structural, and advisory consumers classify retained evidence
independently. An eligible approval-bypass observation can therefore veto a
release even if statistics exclude that position.

`evidence-consumer-drain-completion/v1` verifies the entire launched-position
by compiler-derived-consumer-instance matrix, latest-row uniqueness, terminal
status, exact source/result resolution, and domain-separated digests. Every
terminal result digest resolves exactly once to a signed result artifact.
Pending yields `LAUNCHED_EVIDENCE_DRAIN_PENDING`; invalid coverage is an
integrity error; a terminal violation yields a typed veto. Only a clean drain
permits positive authorization evaluation. Report launched, closed, consumed,
and decision-prefix counts separately, including batch rounds, actual cost,
and drain tail. A decision prefix is not execution cost.

## Identity reachability before spend

Release-bearing stable statistics initially permit only
`immutable_local_artifact` and `provider_attested_immutable_revision`. Tier 2
requires an admitted authority that can bind the actual serving revision,
routing/system policy, inference configuration, transformations,
tokenizer/runtime/tools, cache/carryover isolation, execution window, trust
snapshot, signature, and validity. Weights-only or model-name-only evidence
cannot establish this envelope. A customer/gateway/adapter signature does not
attest hidden provider state.

`provider_resolved_nonimmutable_version` is advisory for stable statistics;
`mutable_alias` supports only a scoped deployment observation. Fingerprints
detect inconsistency but cannot prove stationarity or promote tiers. A
`provider-stationarity/v1` record has `epistemic_status=assumption_not_proof`
and effect `none`, even with canaries, fixed fingerprints, and a short window.
Fingerprint changes, mixing, or disappearance after supply produce
`MODEL_IDENTITY_DRIFT` and do not refund activated alpha. Time-block
randomization and paired interleaving are useful drift diagnostics, not proof
of the admitted stable common-mean bridge.

`authorization-capability-preflight/v1` binds exact manifest and claim
modes/scopes/authorities, adapter capabilities, profile admission, qualification,
and authenticated identity. It launches no draws, activates no registration,
and spends no alpha. Report tier-3 statistical requirements as advisory with
`PROVIDER_IDENTITY_NOT_RELEASE_BEARING`, assess deterministic temporal claims
on their own contracts, and expose whether the complete manifest is reachable.
Temporal eligibility cannot satisfy a separately required statistical claim.
Recheck identity during execution; preflight is neither stationarity proof nor
authorization. A tier-3 release-bearing bridge needs a new theorem, method
identity, independent admission, qualification, and roadmap amendment.

## Alpha families, registration, and freshness

The persistent family root identifies the program/deployment decision,
required-claim namespace, population/frame, policy lineage, and horizon/closure
rule independently of the candidate. A trusted receipt controls root creation
and succession. Renaming or switching candidates does not reset the family.
The default exact registration weight is `w_k=1/[k(k+1)]`, `k>=1`, whose sum is
one by telescoping. A front-loaded family needs a ratified model and fixed
parameter; no implicit migration or outcome-based renormalization is allowed.

For a frozen mandatory-AND bundle, each mandatory endpoint may use
`alpha_PASS(j,k)=alpha_PASS,F*w_k`. A false bundle PASS requires a crossing
for at least one true mandatory endpoint null, so the intersection-union bound
needs no endpoint independence. This argument does not license any-of rules,
post-outcome endpoint deletion, independently actionable multiple claims, or
alternative endpoint selection.

FAIL/veto by any enabled endpoint is a union. Register positive weights with
`sum_j u_j<=1` and use `alpha_FAIL(j,k)=alpha_FAIL,F*u_j*w_k`; otherwise claim
only endpoint-wise control. Require both family allocations in `(0,1)`.
A zero endpoint weight disables that direction entirely and is not an active
test with `alpha=0`. PASS and FAIL guarantees remain separate; a two-sided
coverage claim must account for both. These bounds do not require independent
endpoints, but each endpoint's registered filtration theorem must hold.

Lifecycle is `reserved -> activated -> closed` or
`reserved -> voided_unactivated`. Reservation allocates no index and spends
no alpha. The signed `activation-preview/v1` binds the current authenticated
head, prospective `k`, weight, endpoint allocations/thresholds, immutable
design, exact qualification envelope, resource forecast and uncertainty,
validity, signer, and acknowledgement policy. It states both
`registration_index_allocated=false` and `alpha_spent=false`.

Activation atomically CASes that exact previewed head, allocates the next `k`,
and irreversibly spends the directional allocations before external execution
or reveal of randomness, case/schedule, outcome, timeout, provider response,
or correlated proxy to an actor who can affect the design. A competing advance
returns `ACTIVATION_PREVIEW_STALE`; no path may silently substitute another
index. Every API/CLI path requires the unexpired preview and has no bypass.
Explicit acknowledgement at `k>=5` is an additional cost control, not method
qualification. An activated crash or missing result is not refundable;
voiding an unrevealed reservation means an index was never allocated.

The exact qualification envelope includes candidate, method/admission,
adapter/direction, allocation/index range, margin/transform, target distribution,
endpoint set/roles/combination, complete within-draw protocol, cluster/reducer,
full-filtration bridge, batch protocol/assignment, identity tier, stationarity
and fingerprint contract, retries/timeouts/missingness, drain policy, named
effects, maximum sample/time/cost/round/drain resources, host, and Monte Carlo
policy. No nearest-envelope substitution is permitted. Register a planning
horizon `k_required` and contingency; GA requires qualification through at
least their sum. An out-of-envelope preview returns
`QUALIFICATION_ENVELOPE_EXCEEDED` without alpha spend or index allocation.

Continuation may extend only operational ceilings under the identical
statistical identity, committed future-position generator, and admitted
envelope. Changes to endpoints, roles, margins, alpha, schedule, reducer,
population, model requirement, missingness, drain consumers, or other bound
identity require a new registration. New allocation never legalizes reuse of
adaptively selected observations. Automatic e-process mergers are excluded.

Checkpoints bind authenticated source order, method replay and crossing state,
allocation, lifecycle, policies, and predecessor under an exclusive writer and
expected-head CAS. `registration-state-projection/v1` is keyed by family and
registration in the signed current family head. Decisions bind that exact
projection and allocation, accepted head, and trusted registry descriptor.
Currentness is checked in order:

1. No trusted current head by the deadline:
   `STATISTICAL_FRESHNESS_UNAVAILABLE`, equality unknown.
2. Invalid binding, signature, index/ancestry, no-fork, keyed inclusion, or
   allocation proof: `STATISTICAL_FRESHNESS_INTEGRITY_INVALID`, equality unknown.
3. Valid proofs but changed projection or allocation:
   `STATISTICAL_DECISION_STALE`.
4. Equal authenticated projection and allocation: statistically current;
   separate candidate/policy/context/profile/assurance freshness still applies.

Another registration advancing the family does not stale an unchanged closed
projection. A successor of the same registration does. Offline bundles support
historical replay, never current deployment freshness. A hash chain alone
does not detect restoration to an older internally consistent history.

## Seed review, implementation allocation, and qualification plan

The following are design dispositions, not claims of executed production tests.

| Seed | Required interpretation | Production conversion owner |
| --- | --- | --- |
| `AUTH-003` | Missing supported required evidence prevents release authorization, irrespective of an attractive numerical result | `V1-AUTH-01` |
| `TEMP-006` | Required open history remains inconclusive; a statistical aggregate cannot invent closure | `V1-EVID-02` |
| `TRUST-001` | A signed model self-report retains its origin and does not become independently eligible endpoint evidence | `V1-TRUST-01` |
| `STAT-010` | Moment-only restart state cannot establish historical exclusions; return `REPLAY_STATE_INSUFFICIENT` | `V1-STAT-01` |
| `IO-001` | A missing manifest chunk invalidates execution evidence and cannot silently disappear from the estimator | `V1-IO-01` |

Downstream work must also retain the D1 exact arithmetic, boundary, dependence,
batch, identity, and drain subprobes allocated to `V1-STAT-09` and
`V1-QUAL-02`, including `BND-007`, `STAT-008`, `STAT-019`, and `ALPHA-005`.
The independent reviewer must reproduce the pseudoweight derivation, factor
floor, conditional supermartingale argument, endpoint composition, and
estimand bridge. Exact small-history enumeration checks rational states,
boundary witnesses, sign/cap rules, missingness domination, first-zero-bet
reachability, restart, and marginal-only counterexamples. A simulation cannot
replace those proofs.

Held-out, preregistered qualification sizes power and resources for every named
effect, margin, allocation/index range, schedule, identity, and missingness
envelope. Use upper confidence bounds for false-PASS, false-FAIL,
missing/imputed, unresolved, and resource-risk ceilings; lower confidence
bounds for power. Report uncertainty, median/p90/p99 clusters, actual launched
cost/time, rounds, censoring, zero-bet prefix, and drain tail. Freeze the DGP,
replicate plan, Monte Carlo uncertainty rule, and acceptance gates before
outcomes. A favorable fixture path cannot supply a median stopping-time claim.
Do not tune `c`, pseudoweights, mixture, schedule, or qualification targets after
seeing results.

Open human decisions are the exact roster assignments/competence and conflicts,
development acceptance of this digest, qualification execution scope and
resources, independent review, and method/profile admission. No unresolved
item is represented as accepted. The future completion receipt must enumerate
actual inspection/validation commands and outcomes rather than treating this
ADR's mathematical argument or planned tests as a passing implementation run.
