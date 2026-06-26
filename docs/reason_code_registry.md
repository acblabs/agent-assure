# Reason Code Registry

Reason codes are stable machine-facing identifiers for deterministic findings.

- `EXPECTED_OUTCOME_MISMATCH`: observed recommendation or outcome did not match the case expectation.
- `FORBIDDEN_OUTCOME`: observed outcome is explicitly forbidden for the case.
- `MATERIAL_CLAIM_MISSING_EVIDENCE`: a fixture-declared material claim has no structured evidence link.
- `REQUIRED_SOURCE_MISSING`: an expected evidence reference is absent.
- `POLICY_FAILED`: a gate, policy, or waiver control failed outside a case-specific invariant.
- `REQUIRED_HUMAN_REVIEW_ABSENT`: the result did not route to human review when the expectation required it.
- `REVIEW_BOUNDARY_FAILED`: an expectation-declared review boundary was not preserved.
- `FORBIDDEN_PROVIDER`: a provider expectation or runtime provider policy identified
  a forbidden provider without the required review boundary.
- `FORBIDDEN_TOOL`: a tool was outside a configured allowlist.
- `STRUCTURED_OUTPUT_INVALID`: structured output failed validation.
- `REDACTION_FAILED`: redaction did not satisfy the configured check.
- `RAW_SENSITIVE_CONTENT`: persisted summaries contain sensitive-looking content.
- `PROMPT_INJECTION_BOUNDARY`: a runtime prompt-boundary signal was emitted or captured.
- `RUNTIME_FAILED`: fixture execution produced a runtime error record.
- `VALID_RECORD_MISSING`: a suite case is missing a valid run record or has duplicate records.
- `FIXTURE_EQUIVALENCE_FAILED`: compared runs do not share equivalent fixture material.
- `NON_NFC_STRING`: canonicalization rejected a non-NFC string.
- `NON_FINITE_NUMBER`: canonicalization rejected a non-finite number.
- `NOT_EVALUATED`: a capability was explicitly not evaluated.
