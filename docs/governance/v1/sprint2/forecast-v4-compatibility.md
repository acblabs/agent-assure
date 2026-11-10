# Complete delivery forecast projection, generation 4

Status: implemented for engineering review; new human acceptance remains required.
This correction has no runtime, method-admission or release-authorization effect.

`agent-assure-delivery-forecast/4` preserves the external planning contract
`delivery-forecast/v1` while explicitly representing every roadmap-required
per-ticket field. The historical generation-2 and generation-3 schemas, signed
records, aggregation registry and method definition remain immutable. Generation
3 can still be reconstructed for historical replay. Its signatures cannot accept
generation 4, and it is not silently upgraded or relabeled as conforming.

## Per-ticket planning decisions

The caller supplies an explicit selection for every authenticated ledger row in
ledger order. In addition to ticket identity, estimate scope and every ordered
occurrence estimate, each selection must contain:

| Field | Requirement |
| --- | --- |
| `confidence` | One of `low`, `medium`, `high`; subjective planning confidence, not a statistical confidence level. |
| `dependency_assumptions` | A nonempty, duplicate-free array of bounded, nonblank statements reviewed for that ticket. |
| `risk_assumptions` | A nonempty, duplicate-free array of bounded, nonblank statements reviewed for that ticket. |
| `current_status` | One of `not_started`, `in_progress`, `blocked`, `done`; a planning observation, not a completion receipt. |
| `trusted_issue_time` | An explicit UTC observation no earlier than the bound inventory and no later than the enclosing record issue time. |

There are no defaults, metadata inheritance or automatic adoption from historical
rows, machine proposals, filenames or global confidence language. Any machine
suggestion remains a proposal until a human explicitly adopts its exact subject.
UTC observations retain the existing externally unattested host-time limitation;
they do not claim an actual SSHSIG operation time or an independent clock.

## Arithmetic and complete row representation

The builder emits all fifteen required row fields. It recomputes
`aggregate_p50_effort_hours`, `aggregate_p90_effort_hours` and
`aggregate_reviewer_effort_hours` from the complete ordered selected occurrence
set. Every row names `aggregate_method_id`,
`aggregate_method_definition_digest` and the exact
`aggregate_dependence_assumptions`. These values agree with the immutable
`comonotonic-quantile-sum/v1` definition version `1.1.0` and its bound registry.

Each execution exposes the roadmap's `sprint`, `release`, `p50_effort_hours`,
`p90_effort_hours` and `reviewer_effort_hours` fields. The latter three equal the
retained `selected_*` values exactly; neither form is independently editable.
The nested row aggregate and portfolio/scenario aggregates remain as explicit
diagnostics, and must reconcile with the required row fields.

Arithmetic remains checked nonnegative integer addition within the RFC 8785
exact-integer range. Engineering P50/P90 and reviewer P50 remain separate.
Combined P50 is defined under the declared common-rank model; combined P90
remains null because reviewer P90 inputs were not elicited. Quantile sums are
exact only under that model, not distribution-free upper bounds, calibrated
probabilities, independent-review evidence or calendar commitments. Elapsed
waits do not enter person-hour sums.

## Verification and acceptance

`build_projection` retains generation-3 behavior. `build_projection_v4` requires
the explicit complete selections and produces the new subject. The closed
[generation-4 schema](delivery-forecast-v4.schema.json) admits neither missing
metadata nor unrecognized fields. `validate_projection` reconstructs either
supported version from separately supplied authenticated ledger, selections and
source bindings. It checks the entire value graph and exact JSON types, rather
than trusting an attacker-recomputed digest or Python's Boolean/integer equality.
Schema validity alone does not establish source authenticity or acceptance.

Generation 4 uses distinct `agent-assure:delivery-forecast/v4`,
`agent-assure:delivery-forecast-human-estimates/v4` and
`agent-assure:delivery-forecast-approval-roster/v4` digest domains, each followed
by a zero byte and RFC 8785 payload bytes. The source retains the same pinned
historical catalog and method registry identities. Any changed metadata,
assumption, selected estimate, source or validity interval produces a different
signed subject. Replay checks the original half-open interval; recomputation
does not renew it.

Closure requires a new producer signature and exactly one separate maintainer
acceptance receipt binding this generation-4 planning-record digest, together
with the applicable corrected governance acceptance. Existing generation-3
acceptance cannot discharge these new obligations. No function in this module
creates a human decision, reads a private key or grants dispatch authority.
