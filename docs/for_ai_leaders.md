# For AI Leaders

## Why final-answer checks are insufficient

Final-answer checks can miss process regressions. A candidate agent pipeline can
return the same approval, denial, recommendation, or summary while dropping
material evidence, changing review routing, switching provider/tool boundaries,
or weakening provenance.

## What process assurance measures

`agent-assure` evaluates declared, observable expectations around a run:
evidence links, provider/tool boundaries, privacy-filtered redaction behavior,
review routing, fixture equivalence, and provenance. It turns those observations
into local evidence packets and CI-gate signals for human review.

## Where this fits in CI/CD and release review

Use `agent-assure` where a team already has fixtures, expected controls, or
release evidence that should remain stable across implementation changes. A CI
job can run a candidate pipeline, compare it to a baseline, and block when a
declared process invariant fails.

## What an evidence packet contains

An evidence packet can contain evaluation summaries, comparison summaries,
artifact digests, limitations, dependency inventory, environment details, and
human-readable reports. The packet is designed to be inspected locally and
attached to a release review.

## What this does not claim

This project is not a compliance attestation. Safety review remains a separate
human and organizational responsibility.

`agent-assure` does not replace legal, regulatory, clinical, provider-quality,
model-quality, or business-impact review.

## How to interpret the flagship demo

The flagship fixture keeps `recommendation=approve; outcome=approve` in both
baseline and candidate runs. The candidate fails because it drops a material
`claim-duration` evidence link. The important signal is not that the final
answer changed; it did not. The signal is that the reviewed process did.
