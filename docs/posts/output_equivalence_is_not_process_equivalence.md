# Output Equivalence Is Not Process Equivalence

## The failure mode

An agent pipeline can return the same final answer after a change while the
process around that answer shifts. The answer may still say approve, deny, or
summarize the same result, but the candidate may have dropped material
evidence, bypassed review routing, changed provider/tool boundaries, or altered
redaction behavior.

## Why output-only evals miss process regressions

Output-only evals look at the final response. That is necessary, but it is not
enough for governed agentic workflows. Reviewers often care about the route as
well as the destination: which sources were linked, which tools were called,
which policy checks fired, and which provenance was preserved.

## Observable process controls

`agent-assure` focuses on declared, observable controls. In fixture mode, those
controls include material claim evidence links, expected outputs,
provider/tool boundaries, privacy-filtered summaries, review routing, fixture
equivalence, and artifact digests.

## Minimal example

The flagship fixture keeps the visible final output stable:

```text
baseline:  recommendation=approve; outcome=approve
candidate: recommendation=approve; outcome=approve
```

The candidate fails because it drops the material `claim-duration` evidence
link. The comparison classifies the change as `new_failure` while fixture
equivalence remains `pass`.

## Why this matters for agentic systems

Agentic systems often use tools, retrieval, routing, retries, and review
handoffs. A small implementation change can preserve the final answer while
removing a control the reviewer expected. The risk is not that output checks are
wrong; it is that they measure a different axis.

## What evidence packets should contain

Evidence packets should preserve machine-readable summaries, artifact digests,
human-readable reports, limitations, and enough provenance for a reviewer to
replay or inspect the local evidence path.

## What this does not claim

This project is not a compliance attestation. Safety review remains a separate
human and organizational responsibility.

`agent-assure` supports review of observed process evidence. It does not
replace legal, regulatory, clinical, provider-quality, model-quality, or
business-impact review.
