# Invariant-Based Change Control for Agentic AI Governance Pipelines

Core thesis: deterministic governance-pipeline changes should be evaluated
against labeled expectations and invariants rather than raw output hashes or
baseline similarity.

The current implementation evaluates fixed local fixture suites with compiled
expectations, deterministic controls, fixture-equivalence checks, and separate
provenance diffing. The results below are reproducible from repository artifacts
and do not measure live model quality, stochastic reliability, safety,
certification, compliance, or clinical validity.

## Deterministic Results

### Prior-Authorization Synthetic Suite

| RunSet | Verdict | Passed cases | Failed cases | Blocking findings | Interpretation |
| --- | --- | ---: | ---: | ---: | --- |
| Baseline | `pass` | 10 | 0 | 0 | Fixed fixtures satisfy compiled expectations and controls. |
| Evidence-normalization candidate | `fail` | 9 | 1 | 1 | A material claim in the shared-source multi-claim case lacks a structured evidence link. |
| Provider-policy candidate | `fail` | 9 | 1 | 4 | Provider precedence changes violate outcome, forbidden-outcome, human-review, and review-boundary controls. |
| Smoke candidate | `fail` | 7 | 3 | 7 | Multiple deterministic controls fail, including a captured runtime error. |

| Baseline comparison | Classification | Fixture equivalence | Control changes | Provenance changes |
| --- | --- | --- | ---: | ---: |
| Evidence-normalization candidate | `new_failure` | `pass` | 1 | 10 |
| Provider-policy candidate | `new_failure` | `pass` | 4 | 10 |
| Smoke candidate | `new_failure` | `pass` | 7 | 11 |

### Expense-Approval Minimal Suite

| RunSet | Verdict | Passed cases | Failed cases | Blocking findings | Interpretation |
| --- | --- | ---: | ---: | ---: | --- |
| Baseline | `pass` | 3 | 0 | 0 | The neutral-domain fixture suite satisfies compiled expectations and controls. |
| Provider-policy candidate | `fail` | 2 | 1 | 4 | A deterministic governance-control change violates outcome, human-review, and review-boundary checks. |

| Baseline comparison | Classification | Fixture equivalence | Control changes | Provenance changes |
| --- | --- | --- | ---: | ---: |
| Provider-policy candidate | `new_failure` | `pass` | 4 | 3 |

## Failure Analysis

The evidence-normalization candidate is the central change-control example. Its
visible recommendation category remains within the fixture expectation for nine
ordinary cases, while the shared-source multi-claim case loses a required
material evidence association. A raw output hash or prompt digest would not
explain this failure; the invariant identifies the missing evidence link and
reason code directly.

The provider-policy examples show a different class of deterministic regression:
the configured governance boundary changes the selected provider path and loses
required review behavior. The comparison report classifies these as new
failures because the baseline passes the same expectations under equivalent
fixtures.

Provenance diffs are included for review, but they are not verdict shortcuts.
Configuration digest changes appear across candidate variants because the tested
pipeline configuration changed. Those differences help reproduce and inspect the
run, but the failing verdict comes only from expectation, policy, invariant, or
gate results.
