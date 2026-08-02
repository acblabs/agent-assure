# Reason Code Registry

Reason codes are stable machine-facing identifiers for deterministic findings.

- `EXPECTED_OUTCOME_MISMATCH`: observed recommendation or outcome did not match the case expectation.
- `FORBIDDEN_OUTCOME`: observed outcome is explicitly forbidden for the case.
- `MATERIAL_CLAIM_MISSING_EVIDENCE`: a fixture-declared material claim has no structured evidence link.
- `EVIDENCE_PROVENANCE_MISMATCH`: an evidence reference and its paired
  content-addressed evidence item disagree about source identity.
- `REQUIRED_SOURCE_MISSING`: an expected evidence reference is absent.
- `POLICY_FAILED`: a gate, policy, or waiver control failed outside a case-specific invariant.
- `REQUIRED_HUMAN_REVIEW_ABSENT`: the result did not route to human review, or did not record performed review, when the expectation required it.
- `REVIEW_BOUNDARY_FAILED`: an expectation-declared review boundary was not preserved.
- `FORBIDDEN_PROVIDER`: a provider expectation or runtime provider policy identified
  a forbidden provider without the required review boundary.
  This is a review-boundary control, not a pure provider allowlist: a forbidden
  provider routed through the required review boundary does not emit this reason.
- `FORBIDDEN_TOOL`: a tool was explicitly forbidden or was outside an
  effective configured allowlist. Explicit prohibition takes precedence when
  both conditions apply.
- `STRUCTURED_OUTPUT_INVALID`: structured output failed validation.
- `REDACTION_FAILED`: redaction did not satisfy the configured check.
- `RAW_SENSITIVE_CONTENT`: persisted summaries contain sensitive-looking content.
- `PROMPT_INJECTION_BOUNDARY`: a runtime prompt-boundary signal was emitted or captured.
- `RUNTIME_FAILED`: execution produced a runtime error record.
- `RUNSET_INCOMPLETE`: evaluation received a RunSet whose declared execution did
  not complete.
- `VALID_RECORD_MISSING`: a suite case is missing a valid run record or has duplicate records.
- `FIXTURE_EQUIVALENCE_FAILED`: compared runs do not share equivalent fixture material.
- `NON_NFC_STRING`: canonicalization rejected a non-NFC string.
- `NON_FINITE_NUMBER`: canonicalization rejected a non-finite number.
- `LLM_JUDGE_VERDICT_BEARING_NOT_SUPPORTED`: a descriptor attempted to use an
  LLM-derived advisory judgment as verdict-bearing evidence. LLM-derived
  judgments remain advisory and segregated from release gates.
- `NOT_EVALUATED`: a capability was explicitly not evaluated.
