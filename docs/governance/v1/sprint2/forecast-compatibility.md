# Successor delivery forecast compatibility

The successor preserves the external planning contract `delivery-forecast/v1`
using the new `agent-assure-delivery-forecast/3` wire format. The historical
`agent-assure-delivery-forecast/2` schema, accepted records, method registry,
catalog and signatures remain byte-identical. A generation-2 reader does not
accept a generation-3 record implicitly. The successor's closed schema and
semantic reconstruction define its explicit compatible planning projection.

## Preserved meaning and source bindings

The producer's `delivery_forecast` object is the planning record. It binds:

- The complete roadmap, sorted ticket set, dependency graph and ordered release
  train; all source tickets and every ordered occurrence remain represented.
- The exact prospective kickoff, result commit, file-scope observation, current
  inventory, authoring ledger, selected estimates and resolved dispatch scopes.
- The explicitly adopted bootstrap roster and trust snapshot, including the
  human's roles, competence scopes, conflicts and capacity.
- The original method `comonotonic-quantile-sum/v1`, definition version `1.1.0`,
  definition digest
  `sha256:028ff736a0d4c7ac37a5fb15ba1ee733401a8be453569fc07b37fae6b27517f7`,
  and registry digest
  `sha256:7cac700d33f41f97156f459bf48bae5e4c65d36505aab6cb7e5c2df4acae1ba6`.
- Exact raw identities of the frozen registry, estimation catalog and their
  schemas. The host checks these bytes against the committed result and signed
  bootstrap before decoding them. Fractional quantile ranks in that one frozen
  registry do not relax the integer-only rule for ordinary host inputs.

The original bottom-up authoring ledger remains an auditable machine proposal.
Generation 3 separately records every explicitly selected occurrence estimate
and rationale, permitting human edits without rewriting the proposal or
pretending that proposed values were independently observed actual effort.
Recalculation changes neither the original inventory observation nor the
record's validity interval.

## Arithmetic and forecast interpretation

Engineering P50/P90 and reviewer P50 person-hours are separate checked integer
sums. Every ticket, each of the two scenario partitions, and the portfolio
reconcile from the selected occurrences. Scenario ticket counts use set unions;
a ticket present in both partitions is counted once in the portfolio. Known
elapsed waits retain their own fields and do not enter effort totals.

Under the inherited shared-rank model, sums of the specified quantiles are exact
within that model. Engineering P50 plus reviewer P50 can form the modeled
combined P50. Reviewer P90 inputs have not been supplied, so combined P90 remains
absent. These are subjective, uncalibrated planning estimates, without a
distribution-free bound, independent-review claim or calendar commitment.

## Lifecycle and signatures

The projection is prepared, nonauthorizing review material. It does not
self-declare acceptance. Its domain-separated record digest covers the complete
planning object. The actual technical-lead signature covers the enclosing
producer decision, including this exact object. A distinct repository-maintainer
acceptance signature binds both that producer decision and its planning-record
digest under the external contract identity. One person can hold both explicit
development roles; `NO_INDEPENDENT_REVIEW` remains visible.

The original inventory must precede issue, issue must not be future, and the
half-open validity interval is at most 30 days and remains inside the adopted
trust scope. A new wrapper cannot refresh an old interval. Collection caps
the forecast evidence and aggregate receipt at the original source expiry;
fixed-tag finalization cannot extend beyond the earliest prerequisite expiry.
Collection and replay recompute the ledger, immutable inputs, projection and selected-value aggregates
and verify both signatures. The signed successor aggregate then binds the
producer and acceptance digests. Production method admission and release
authorization retain their separate roadmap gates.

The [host runbook](host-runbook.md) describes forecast preparation, human edits,
recalculation, signing, and import. The [successor schema](delivery-forecast.schema.json)
defines the closed wire representation; schema validity alone has no authority.
