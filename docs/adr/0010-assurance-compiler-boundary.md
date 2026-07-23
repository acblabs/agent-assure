# ADR 0010: Assurance Compiler Boundary

Status: accepted

## Context

Agent release review needs reproducible evidence about declared controls without
turning `agent-assure` into a tracing service, telemetry store, or runtime
authorization layer.

## Decision

Position `agent-assure` as an Agent Release Assurance Compiler for
Evidence-Carrying Agent Releases. It consumes declared controls and
privacy-filtered artifacts, applies versioned evidence methods, and writes
local, digest-bound results for review and CI.

The product does not collect arbitrary production telemetry, retain hosted
state, provide trace search, or replace an observability backend. Existing
observability systems may supply structured inputs, but they remain separate
systems with separate trust boundaries.

## Consequences

- Core workflows remain local-first and inspectable.
- Persisted artifacts and CLI contracts are the primary integration surface.
- Runtime monitoring, storage, alert routing, and incident response remain the
  responsibility of other systems.
- Product claims stay scoped to the declared subject, controls, methods, and
  evidence supplied to a run.
