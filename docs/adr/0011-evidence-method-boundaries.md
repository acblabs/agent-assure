# ADR 0011: Evidence Methods Preserve Their Boundaries

Status: accepted

## Context

A result can be misread when its prerequisites, assumptions, limitations, or
dependencies are separated from the value being reported.

## Decision

Every durable evidence method binds its method and implementation identity,
prerequisite state, assumptions, limitations, dependencies, validity window,
and invalidation conditions in the evidence descriptor.

An absent prerequisite is never interpreted as satisfied. A result whose
prerequisites are unmet cannot be verdict-bearing. Projections and rendered
views must preserve limitations and dependency identities.

## Consequences

- Method results remain interpretable outside the process that generated them.
- A digest or successful parse cannot silently strengthen an evidence claim.
- Schema and renderer tests must cover prerequisite failure, limitation
  preservation, and invalidation behavior.
