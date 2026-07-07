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

To reproduce the flagship evidence-linking failure, evaluate the baseline and
evidence-normalization candidate, then compare them:

```bash
agent-assure evaluate .tmp/prior-auth.baseline.json --suite .tmp/prior-auth.compiled.json --out-dir .tmp/prior-auth.baseline-report
agent-assure evaluate .tmp/prior-auth.evidence-candidate.json --suite .tmp/prior-auth.compiled.json --out-dir .tmp/prior-auth.evidence-report
agent-assure compare .tmp/prior-auth.baseline.json .tmp/prior-auth.evidence-candidate.json --suite .tmp/prior-auth.compiled.json --out-dir .tmp/prior-auth.comparison-report
```

The candidate evaluation and comparison are expected to exit `1`. The candidate
report contains `MATERIAL_CLAIM_MISSING_EVIDENCE` for
`shared-source-multi-claim` and `claim:claim-duration`; the comparison report
classifies the change as `new_failure` while fixture equivalence remains `pass`.

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

## RAG provenance path

The example also includes a one-case RAG provenance suite that uses committed
policy chunks, scaled-integer cached vectors, fixture-pinned effective-date
filters, and explicit `retrieval_corpus_digest` provenance.

```bash
agent-assure suite compile examples/prior_auth_synthetic/rag_suite.yaml --out .tmp/prior-auth-rag.compiled.json --manifest .tmp/prior-auth-rag.fixtures.json
agent-assure suite run .tmp/prior-auth-rag.compiled.json --variant examples/prior_auth_synthetic/variants/rag_baseline.yaml --manifest .tmp/prior-auth-rag.fixtures.json --source examples/prior_auth_synthetic/rag_suite.yaml --out .tmp/prior-auth-rag.baseline.json
agent-assure suite run .tmp/prior-auth-rag.compiled.json --variant examples/prior_auth_synthetic/variants/candidate_rag_reranker_regression.yaml --manifest .tmp/prior-auth-rag.fixtures.json --source examples/prior_auth_synthetic/rag_suite.yaml --out .tmp/prior-auth-rag.reranker-candidate.json
agent-assure suite run .tmp/prior-auth-rag.compiled.json --variant examples/prior_auth_synthetic/variants/candidate_rag_corpus_version_skew.yaml --manifest .tmp/prior-auth-rag.fixtures.json --source examples/prior_auth_synthetic/rag_suite.yaml --out .tmp/prior-auth-rag.corpus-skew.json
```

The reranker-regression candidate preserves `recommendation=approve` and
`outcome=approve` with the same retrieval corpus digest, but drops the retrieved
duration source and triggers `MATERIAL_CLAIM_MISSING_EVIDENCE`. The
corpus-version-skew candidate preserves the decision and evidence links while
changing `provenance.retrieval_corpus_digest`, so comparison reports it as
provenance-only drift.

The RAG fixture includes `fixtures/rag/counterfactual_query_families.json`.
Those query variants are fixture-author-declared metamorphic cases for the same
synthetic decision. Each variant uses a distinct committed query-vector key,
and some committed entries may intentionally share the same vector value. The
family inherits the canonical case's expected decision, required refs, and
material claims from `rag_suite.yaml`. agent-assure measures required-ref
coverage separately from source-ID and material-claim support across the
declared variants. Decision equivalence is measured on the canonical case only;
the paraphrase variants recompute retrieval evidence support and do not prove
semantic equivalence between natural-language queries.
