# Prior Authorization Synthetic Example

This synthetic example exercises offline suite compilation, fixture manifests,
and deterministic fixture runs across ten fixed cases. It uses local JSON
fixtures only; no provider SDK or network access is required.

```bash
agent-assure suite compile examples/prior_auth_synthetic/suite.yaml --out .tmp/prior-auth.compiled.json --manifest .tmp/prior-auth.fixtures.json
agent-assure suite run .tmp/prior-auth.compiled.json --variant examples/prior_auth_synthetic/variants/baseline.yaml --manifest .tmp/prior-auth.fixtures.json --out .tmp/prior-auth.baseline.json
agent-assure suite run .tmp/prior-auth.compiled.json --variant examples/prior_auth_synthetic/variants/candidate_evidence_normalization.yaml --manifest .tmp/prior-auth.fixtures.json --out .tmp/prior-auth.evidence-candidate.json
agent-assure suite run .tmp/prior-auth.compiled.json --variant examples/prior_auth_synthetic/variants/candidate_provider_policy.yaml --manifest .tmp/prior-auth.fixtures.json --out .tmp/prior-auth.provider-candidate.json
```

The variants share the same request, model-output, and tool-output fixtures. The
evidence-normalization variant switches from association-preserving evidence
assembly to catalog reconstruction; for the shared-source case, the visible
recommendation stays the same while duplicate source/content associations lose a
secondary claim link. The
provider-policy variant lets runtime provider defaults take precedence over the
policy bundle, so a provider the baseline escalates is allowed through. The
fake-PHI case checks that raw synthetic sensitive values from fixtures are not
persisted in run records. The smoke variant additionally exercises in-process
failure capture.

The evidence-normalization candidate is supported by a release-evidence review
rubric in `docs/measurement/blind_review_release_evidence.md`.
