# ADR 0014: LLM-Derived Judgments Are Permanently Advisory

Status: accepted

## Context

LLM-derived judgments can help a reviewer summarize or prioritize evidence,
but their stochastic behavior, drift, and potential correlation with the
subject make them unsuitable as independent release verdicts.

## Decision

LLM-derived judgments are always exploratory and non-verdict-bearing. They may
assist bounded summarization, extraction, prioritization, or issue flagging.
They may not satisfy a control or prerequisite, count an assurance mutation as
caught, override deterministic or protocol-valid findings, resolve an
inconclusive result, or directly pass, fail, approve, or block a gate.

Human approval does not reclassify the model judgment. Any human verdict must
be separately attributable to an accountable reviewer and grounded in
independently reviewable evidence. Unsupported verdict-bearing use fails with
`LLM_JUDGE_VERDICT_BEARING_NOT_SUPPORTED`.

## Consequences

- Advisory outputs stay segregated from gate inputs.
- Schemas and validators reject verdict-bearing LLM-judgment roles.
- Future evaluator characterization may measure advisory reliability without
  changing this boundary.
