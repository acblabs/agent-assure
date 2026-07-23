# ADR 0015: Formal and Conformal Methods Are Not v1 Commitments

Status: accepted

## Context

Bounded model checking and conformal methods can be valuable under carefully
declared abstractions and statistical assumptions. Those prerequisites and
external use cases are not yet stable product contracts.

## Decision

Do not make bounded model checking or stable conformal certification part of
the v1 commitment. The current product remains centered on reproducible,
privacy-filtered evidence for declared process controls.

Any later formal method must identify the abstraction, property, bound, and
counterexample semantics. Any later conformal method must identify the loss,
calibration unit and population, exchangeability or alternative assumptions,
sample sufficiency, drift invalidation, and ordinary no-result states.

## Consequences

- Current reports do not imply formal verification or distribution-free
  coverage.
- Research prototypes cannot silently become release gates.
- Admission of either method requires a concrete decision need, a versioned
  contract, reference validation, and conservative public wording.
