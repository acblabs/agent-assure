# ADR 0013: Deterministic and Stochastic Evidence Have Different Semantics

Status: accepted

## Context

A deterministic fixture replay and a repeated stochastic study answer
different questions. Treating one as the other creates unsupported population
or reproducibility claims.

## Decision

A deterministic fixture result records the exact observed behavior of a
versioned local subject and inputs. Replaying it can establish reproducibility
for those artifacts, but it does not estimate behavior prevalence.

A stochastic conclusion requires a declared protocol, inferential unit,
configuration identities, sampling and pairing plan, missing-observation rules,
sample-size rationale, analysis method, and sufficient observations. When
those prerequisites are not met, the result remains inconclusive or records
unmet prerequisites.

## Consequences

- Fixture demonstrations use exact descriptive language.
- Population or robustness language depends on protocol-valid stochastic
  evidence.
- Reports never infer confidence intervals from a finite set of authored
  deterministic fixtures.
