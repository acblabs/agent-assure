# Who Assures the Assurance?

An agent release gate is still software. Its policy can be weakened, its
finding can be routed to a warning, its evidence matcher can accept the wrong
failure, or its expected control can stop running. A green application test
does not answer whether the gate would detect the process regression it was
designed to block.

That makes assurance controls testable subjects in their own right.

## Test the detector, not only the agent

Agent Assure's deterministic mutation operators make one declared change to a
validated, immutable fixture artifact. Each operator carries a normative
expected-detection contract: the target control, reason code, privacy-minimized
finding target, and gate effect that must be observed for that exact change.

The distinction matters. If an evidence link is removed and the evaluator
fails only because an unrelated outcome check was broken, the assurance
control did not catch the evidence-link mutation. The unrelated finding is
recorded as prohibited substitute evidence; it cannot turn a survivor into a
caught result.

This gives each completed applicable challenge one of two verdict-bearing
states:

- `caught`: the normative detector contract matched; or
- `survived`: the transformation was valid and applicable, but that contract
  did not match.

Inapplicable, invalid, and execution-error outcomes remain distinct. Treating
them as catches would reward a broken test harness. Treating them as survivors
would hide a different operational problem.

## A ratio with a deliberately narrow name

The control-efficacy report computes an exact catalog detector kill ratio:

```text
caught / (caught + survived)
```

The numerator and denominator are stored directly. A zero denominator is
explicitly undefined. No percentage is fabricated, and invalid or incomplete
work cannot disappear into the arithmetic.

The ratio describes only the selected deterministic catalog challenges over
the exact campaign inputs. It does not estimate the frequency of real-world
failures, the completeness of the threat model, or the probability of a
desirable production outcome. Those would require different designs and
evidence.

## Independence is part of the result

A detector test written after the detector can share the detector's blind
spots. That does not make the test useless, but it changes what the evidence
supports.

The report therefore shows every outcome in one of five independence strata.
External pre-existing, third-party-contributed, and first-party-precontrol
challenges are eligible for the independent challenge count. First-party
postcontrol and unknown-origin challenges are not. Zero-count strata remain
visible so a full catalog ratio cannot masquerade as independent coverage.

The built-in `core/v1` operators are currently first-party postcontrol. They
provide reproducible regression tests for known control contracts. Independent
coverage requires separately sourced challenges with reviewable provenance.

## Threat scope is authored, not inferred

A good result over the wrong scope is still the wrong result. The threat
applicability manifest records which threat categories are applicable,
not-applicable, or unknown; which target controls are present; which categories
are critical; who owns a not-applicable decision; and what limitations apply.

The report binds that manifest by digest. It reports applicable categories,
categories with a completed challenge, independently challenged categories,
critical gaps, and unknown applicability. A survived challenge can count as
having exercised a category while still failing the detector test. Coverage
and response are separate facts.

Critical operator status is derived from the manifest: a surviving operator is
critical when it references an applicable category marked critical. There is
no second operator-criticality list to drift away from threat scope.

## Facts first, policy second

Semantic report state and gate decision are intentionally separate. The
report says whether a survivor was observed, every evaluated applicable
operator was caught, the campaign was indeterminate, or no challenge was
evaluated. A gate profile then maps specific conditions to `block`, `review`,
`informational`, or `ignore`.

Required or critical survivors, invalid/error outcomes, and required operators
that were not evaluated use block-only policy fields. Unknown threat
applicability requires review by default. Changing a configurable policy effect
changes the decision, not the underlying report facts.

Evidence packets preserve the same separation. Candidate evidence closure can
pass while the control-efficacy section blocks because a required detector was
weakened. That is the point: the release gate should not trust its own green
state without challenge evidence.

## See the failure mode locally

The packaged demonstration runs without a provider key or network access:

```bash
agent-assure demo assure-the-assurance \
  --out .tmp/demo/assure-the-assurance \
  --clean
```

It checks four concrete facts:

1. the ordinary synthetic candidate passes its declared expectations;
2. the material-evidence mutation is caught under the normal control;
3. the same mutation survives a deliberately weakened gate profile; and
4. an unrelated blocking finding does not count as detection.

The demo writes machine-readable campaigns, a self-digested efficacy report,
a digest-bound packet and gate decision, a reviewer-facing Markdown report,
and a summary of artifact paths and hashes. The wrapper succeeds only when the
expected blocking demonstration is reproduced. `--strict` exposes the
underlying nonzero gate result for CI-oriented walkthroughs.

This is a detector-of-detectors test over a finite synthetic catalog. Its value
is precise: it makes the assurance layer's declared response observable,
reviewable, and repeatable without turning that evidence into a broader claim.
