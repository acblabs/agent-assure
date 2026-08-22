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

## Control-Efficacy Gate Reasons

Control-efficacy gates use a separate stable reason namespace:

- `REQUIRED_OPERATOR_SURVIVED`: an operator required by the verifier's gate
  profile survived its challenge. This finding always blocks.
- `CRITICAL_OPERATOR_SURVIVED`: an operator associated with an applicable,
  critical threat survived its challenge. This finding always blocks.
- `APPLICABLE_OPERATOR_SURVIVED`: a selected operator outside the required and
  critical floors survived its challenge. The default profile maps this finding
  to `review`.
- `CRITICAL_THREAT_UNCOVERED`: an applicable, critical threat category had no
  completed challenge. The default profile maps this finding to `review`.
- `APPLICABLE_THREAT_UNCOVERED`: an applicable, non-critical threat category had
  no completed challenge. The default profile maps this finding to `review`.
- `INVALID_OR_ERROR_OPERATOR`: a selected operator produced an invalid-operator,
  invalid-subject, or execution-error outcome. This finding always blocks.
- `REQUIRED_OPERATOR_NOT_EVALUATED`: an operator required by the verifier's gate
  profile had no caught-or-survived outcome. This finding always blocks.
- `UNKNOWN_THREAT_APPLICABILITY`: a threat manifest entry retained `unknown`
  applicability. The default profile maps this finding to `review`.
- `UNSCOPED_CATALOG_THREAT_REFERENCE`: a selected catalog operator referenced a
  threat ID absent from the verifier's threat manifest. The default profile maps
  this finding to `review`.

Strict efficacy CI rejects every one of these finding states regardless of an
advisory effect mapping.

## Evidence-Sensitivity Reasons

The controlled RAG evidence-sensitivity contract uses a separate closed reason
namespace:

- `EVIDENCE_SENSITIVITY_EXPECTED_RESPONSE_MISSING`: all prerequisites passed,
  but the two exact decision tuples did not satisfy the authority-bound expected
  response.
- `EVIDENCE_SENSITIVITY_CONFOUNDED`: at least one dimension required to remain
  equal changed, or a dimension required to differ did not change. The result is
  non-verdict.
- `EVIDENCE_NOT_RETRIEVED_IN_BOTH_ARMS`: retrieval failed or the exact
  authority-bound governing evidence was not retrieved in both arms. The result
  is non-verdict.
- `EVIDENCE_LINK_NOT_PRESENT_IN_BOTH_ARMS`: the exact authority-bound
  claim-to-evidence link was absent from at least one arm. The result is
  non-verdict.
- `EVIDENCE_AUTHORITY_CONTRACT_INVALID`: the otherwise parseable authority
  mapping did not exactly bind the protocol corpora, case, query family, or
  governing evidence. The result is non-verdict.
- `EVIDENCE_SENSITIVITY_PREREQUISITES_UNMET`: one or more verdict prerequisites
  failed. Specific prerequisite reasons are retained alongside this roll-up.

## Evidence Graph Projection Reasons

The evidence graph uses a separate closed reason namespace for findings that
are created by projection rather than copied from a source finding:

- `EVIDENCE_SCOPE_LIMITATION`: a source limitation was projected as a
  non-verdict finding.
- `MUTATION_CAUGHT`: the mutation source recorded a caught outcome.
- `MUTATION_SURVIVED`: the mutation source recorded a survived outcome.
- `MUTATION_INAPPLICABLE`: the mutation source recorded an inapplicable
  outcome.
- `MUTATION_INVALID_OPERATOR`: the mutation source recorded an invalid
  operator.
- `MUTATION_INVALID_SUBJECT`: the mutation source recorded an invalid subject.
- `MUTATION_EXECUTION_ERROR`: mutation execution failed.
- `THREAT_CHALLENGED`: an applicable threat category had at least one completed
  challenger. This means exercised coverage, not successful detection or
  mitigation.
- `THREAT_UNCOVERED`: an applicable threat category had no completed
  challenger.
- `THREAT_NOT_APPLICABLE`: the threat category was explicitly outside scope.
- `THREAT_APPLICABILITY_UNKNOWN`: the threat category retained unknown
  applicability.

Graph validation requires the exact registered reason for each mutation,
threat-applicability, challenge, and limitation state. Mutation diagnostic
codes are carried separately under the `diagnostic` reference role and are not
part of the applicability namespace.
