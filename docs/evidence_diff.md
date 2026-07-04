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

The page keeps the thesis "Output equivalence is not process equivalence" in
the first viewport, but leads with a data-driven verdict header and dashboard.
The dashboard separates visible decision-field equivalence for
`recommendation` and `outcome` from process-layer regressions and CI-gate
behavior.

`Process-affected cases` means cases with candidate process findings or missing
baseline material-claim evidence links. It is intentionally not derived from the
decision-field comparison, because a case can preserve `recommendation` and
`outcome` while still regressing the evidence chain. Findings without case IDs
are rendered as unscoped findings rather than being folded into a case count.

The primary process view is a unified `Process Evidence Diff`: all cases remain
visible, unchanged rows are visually de-emphasized without reducing text
legibility, and missing material-claim links are rendered with explicit removed
link markers. For process changes outside claim-evidence links, the diff lists
the changed process fields, such as tools, policy states, human review, or
provider/model. The full baseline and candidate process evidence tables remain
available below the unified view for audit review, alongside missing evidence
links, candidate findings, comparison classification, fixture-equivalence state,
CI-gate result, artifact paths, and packet digests.

The flagship demo writes the artifact to:

```text
.tmp/demo/flagship/evidence-diff.html
```
