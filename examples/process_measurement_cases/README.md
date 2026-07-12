# Process Measurement Cases

This deterministic fixture suite demonstrates process-assurance cases that are
not intended as a benchmark against other tools.

The baseline and candidate variants use the same fixture material. Several
candidate cases keep the same visible recommendation and outcome while changing
process evidence: evidence links, provider/model metadata, human-review routing,
evidence source identity, retries, and measured usage.

The provider-boundary case declares an approved provider and required review
route; the candidate switches provider and drops that route, so it produces a
real provider-boundary finding rather than only a metadata diff. The privacy
case was renamed to an evidence-source identity case: the candidate keeps the
same evidence reference and digest but changes the evidence source identifier,
making the provenance drift visible without claiming a redaction finding.

Run from a checkout:

```bash
agent-assure demo measurement-cases --out .tmp/measurement-cases --clean
```

The demo writes a compiled suite, baseline and candidate runsets, evaluation
reports, a comparison report, an evidence packet, and an evidence-diff HTML
artifact.
