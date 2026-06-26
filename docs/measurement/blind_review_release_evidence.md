# Blind Review Release Evidence Rubric

This artifact records how reviewers should assess whether the evidence
normalization candidate looks like a plausible engineering refactor rather than
a case-specific failure. It is a release-readiness aid, not an external
validation claim.

## Review Input

Reviewers should inspect a blinded summary of the candidate behavior:

- Evidence assembly changes from preserving every association to rebuilding a
  catalog keyed by source identifier and content digest.
- The candidate variant uses the same request, model-output, and tool-output
  fixtures as the baseline.
- The visible recommendation and outcome remain unchanged for the shared-source
  case.
- The implementation must not branch on case identifier, fixture identifier, or
  material claim identifier.

## Evidence To Record

Before release, record:

- The ordinary one-source/one-claim evidence cases retain the same
  recommendation, outcome, evidence reference, and material claim link under the
  candidate.
- The shared-source multi-claim case is the only material-claim evidence-link
  loss under the candidate.
- The candidate behavior is configured as a general evidence assembly mode, not
  as a case-specific override.
- Source review finds no explicit planted-failure marker or branch on the edge
  case identifier.

## Rubric

Use `pass`, `warn`, or `fail` for each item:

| Item | Pass condition |
| --- | --- |
| Plausible refactor | The change could reasonably be introduced while deduplicating evidence by source and digest. |
| Shared fixtures | Baseline and candidate use identical request, model-output, and tool-output fixtures. |
| Ordinary-case preservation | The ordinary evidence cases keep their evidence links under the candidate. |
| Edge-case specificity | The only material evidence-link loss is the shared-source multi-claim case. |
| No case-specific branch | Implementation review finds no branch on the edge case identifier or claim identifier. |

Any `fail` should block release evidence that uses this candidate as the
flagship deterministic regression.
