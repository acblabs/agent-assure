# Process Measurement Cases

This deterministic fixture suite demonstrates process-assurance cases that are
not intended as a benchmark against other tools.

The baseline and candidate variants use the same fixture material. Several
candidate cases keep the same visible recommendation and outcome while changing
process evidence: evidence links, provider/model metadata, human-review routing,
residual sensitive metadata, retries, and measured usage.

The provider-boundary case declares an approved provider and required review
route; the candidate switches provider and drops that route, so it produces a
real provider-boundary finding rather than only a metadata diff. The privacy
case deliberately encodes sensitive-looking residual metadata in an evidence
source field to exercise persisted artifact redaction checks with synthetic
data.

Run from a checkout:

```bash
agent-assure demo measurement-cases --out .tmp/measurement-cases --clean
```

The demo writes a compiled suite, baseline and candidate runsets, evaluation
reports, a comparison report, an evidence packet, and an evidence-diff HTML
artifact.
