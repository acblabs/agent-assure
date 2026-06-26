# Invariant Diffing

Hashes and provenance changes are reported as context. Verdicts come from
expectations, invariants, policy checks, and configured gates.

RunSet comparison validates both records against the same compiled suite, checks
fixture equivalence before interpreting baseline-to-candidate changes, and keeps
provenance differences in a separate report section. A changed prompt, code,
configuration, model identifier, tool schema, or fixture manifest digest is not
itself a regression verdict. Fixture material mismatch is treated as an invalid
comparison because the deterministic oracle is no longer shared.
