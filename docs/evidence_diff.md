# Evidence Diff

`agent-assure diff render` creates a single local HTML artifact for reviewer
inspection.

The v0.3.0 renderer is intentionally static:

- local HTML only;
- inline CSS;
- escaped dynamic content;
- no external JavaScript, CSS, fonts, or network calls;
- no raw prompts, raw tool arguments, or unredacted sensitive summaries.

Render from existing artifacts:

```bash
agent-assure diff render --baseline BASELINE.runset.json --candidate CANDIDATE.runset.json --comparison comparison-summary.json --packet evidence-packet.json --out evidence-diff.html
```

The page shows final-output equivalence and process evidence side by side,
including missing evidence links, candidate findings, comparison
classification, fixture-equivalence state, CI-gate result, artifact paths, and
packet digests.

The flagship demo writes the artifact to:

```text
.tmp/demo/flagship/evidence-diff.html
```
