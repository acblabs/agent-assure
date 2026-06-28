# Invariant-Based Change Control for Agentic AI Governance Pipelines

## Thesis

Deterministic governance-pipeline changes should be evaluated against labeled
expectations and invariants rather than raw output hashes or baseline similarity.

Agentic workflows often include components that do not show up in the final
answer: evidence assembly, source attribution, provider selection, tool
allowlists, redaction, escalation, and human-review routing. A candidate can
keep the visible answer stable while weakening one of those controls. A
governance review process needs artifacts that make that failure mode visible.

The current implementation evaluates fixed local fixture suites with compiled
expectations, deterministic controls, fixture-equivalence checks, and separate
provenance diffing. The results below are reproducible from repository artifacts
and do not measure live model quality, stochastic reliability, safety,
certification, compliance, or clinical validity.

## Method

The evaluation model has three layers:

1. Candidate versus expectations is the primary oracle.
2. Candidate versus baseline is secondary change context.
3. Provenance digests explain what material participated in a run, but do not
   decide whether behavior passed.

The implementation follows that model by:

- compiling YAML suites into strict JSON artifacts with resolved expectations;
- preserving semantic-string lexemes during YAML authoring;
- binding RunSets to suite and fixture-manifest digests;
- running variants against fixed local model and tool outputs;
- evaluating explicit outcome, evidence, provider, tool, redaction,
  prompt-boundary, runtime, escalation, and human-review controls;
- marking unsupported capabilities as `not_evaluated`;
- comparing baseline and candidate only after fixture equivalence is checked;
- reporting provenance changes separately from verdict-bearing changes;
- producing JSON, Markdown, Rich console output, evidence packets, release
  manifests, dependency inventories, and replay digests.

## Artifact Model

The core persisted artifacts are strict, immutable schema roots:

- `CompiledSuite` records resolved cases, expectations, suite defaults, and
  source provenance.
- `FixtureManifest` records shared fixture files with normalized paths and
  SHA-256 file digests.
- `AgentRunRecord` records one deterministic case run without raw prompts,
  raw outputs, tool arguments, or persisted OpenTelemetry attributes.
- `RunSet` groups records for one variant and binds them to suite and fixture
  provenance.
- `EvaluationReport` and `EvaluationSummary` record candidate-vs-expectation
  verdicts and findings.
- `ComparisonReport` and `ComparisonSummary` record fixture equivalence,
  baseline context, verdict-bearing changes, and provenance-only changes.
- `EvidencePacket` bundles deterministic summaries with interpretation
  guidance, environment metadata, input digests, dependency inventory, and
  release manifest references.

Hashes are used for replay and provenance. Behavioral verdicts come only from
expectations, invariants, policies, or configured gates.

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
ordinary cases. In the shared-source multi-claim case, the candidate preserves:

```text
recommendation=approve
outcome=approve
```

The candidate still fails because the material `claim-duration` claim loses its
structured evidence link. A raw output hash or prompt digest would not explain
this failure. The invariant identifies the missing evidence link and emits:

```text
MATERIAL_CLAIM_MISSING_EVIDENCE
```

The provider-policy examples show a different class of deterministic
regression: configuration precedence changes the selected provider path and
loses required review behavior. The comparison report classifies these as new
failures because the baseline passes the same expectations under equivalent
fixtures.

Provenance diffs are included for review, but they are not verdict shortcuts.
Configuration digest changes appear across candidate variants because the
tested pipeline configuration changed. Those differences help reproduce and
inspect the run, but the failing verdict comes only from expectation, policy,
invariant, or gate results.

## Threats To Validity

The examples are synthetic and fixture-bound. They demonstrate measurement
mechanics and deterministic governance-control behavior; they do not estimate
real-world task quality or safety.

Fixture authors declare materiality in v0.1. The evaluator does not infer
materiality from rationale text. This keeps the oracle explicit, but it also
means suite quality depends on expectation authoring.

The fixture runner captures ordinary in-process Python exceptions. Live
execution can also run configured external scripts through a no-shell
subprocess harness and record redacted emergency process metadata for local
process failures. Catastrophic host termination, malicious-script containment,
and production workload isolation remain out of scope. Live provider version
drift, rate limits, cost distributions, and latency distributions are handled
only inside declared live protocols and are not part of the deterministic
fixture result table above.

## Release Evidence

Release evidence connects the deterministic results to reproducible artifacts:

- local commands compile suites, run variants, evaluate RunSets, compare
  baseline and candidate, and build evidence packets;
- environment metadata records installed packages, Python version, platform,
  dependency-inventory digest, and optional lockfile digest;
- release replay uses stable projections for environment-bearing JSON artifacts
  and raw file digests for stable source artifacts, then cross-checks
  manifest-listed child artifact hashes when those files are available;
- keyless cosign workflow signing can verify exact blob bytes and GitHub
  Actions workflow identity.

The signature verifies exact bytes and workflow identity. It is not a safety,
compliance, clinical-validity, live model-quality, or standards-acceptance
claim.

## Conclusion

Invariant-based change control gives reviewers a way to evaluate deterministic
agent-governance changes without confusing provenance changes with behavioral
regressions. The method is deliberately narrow: fixed fixtures, explicit
expectations, reproducible reports, and conservative claims. That narrowness is
the point. It creates a stable base for later live stochastic evaluation while
keeping v0.1 evidence reviewable and reproducible.
