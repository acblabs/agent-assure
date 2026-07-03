# Flagship Demo

Run:

```bash
agent-assure demo flagship --out .tmp/demo/flagship --clean
```

Expected punchline:

```text
decision fields: preserved
missing evidence link: claim-duration
classification: new_failure
CI gate: blocked as expected
```

The demo loads the bundled `prior_auth_synthetic` fixture through package
resources, stages it in the output directory, runs the baseline and candidate
variants, evaluates both run sets, compares them, builds an evidence packet
through the CI command, gates that packet, and renders `evidence-diff.html`.

The visible decision fields remain stable:

```text
baseline:  recommendation=approve; outcome=approve
candidate: recommendation=approve; outcome=approve
```

The process regression is the missing material `claim-duration` evidence link.
The candidate evaluation includes `MATERIAL_CLAIM_MISSING_EVIDENCE`, and the
comparison classification is `new_failure` under passing fixture equivalence.

Key artifacts:

- `.tmp/demo/flagship/demo-summary.json`
- `.tmp/demo/flagship/baseline-report/evaluation-report.md`
- `.tmp/demo/flagship/evidence-report/evaluation-report.md`
- `.tmp/demo/flagship/comparison-report/comparison-report.md`
- `.tmp/demo/flagship/ci-report/evidence-packet.json`
- `.tmp/demo/flagship/evidence-diff.html`
