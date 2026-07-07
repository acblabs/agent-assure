# RAG Provenance Demo

Run:

```bash
agent-assure demo rag --out .tmp/demo/rag --clean
```

Expected punchline:

```text
output equivalence: preserved
retrieval corpus digest: unchanged
missing evidence link: claim-duration
classification: new_failure
CI gate: blocked as expected
```

The demo stages the bundled prior-auth example, compiles `rag_suite.yaml`, runs a
baseline RAG variant, runs a reranker-regression candidate, evaluates both run
sets, compares them, builds and gates an evidence packet, and renders a local
`evidence-diff.html`.

The visible decision remains stable:

```text
baseline:  recommendation=approve; outcome=approve
candidate: recommendation=approve; outcome=approve
```

The retrieval-process regression is narrower: the candidate uses the same
indexed corpus digest but drops the retrieved source that supports
`claim-duration`. The candidate evaluation uses the existing
`MATERIAL_CLAIM_MISSING_EVIDENCE` reason code.

The demo also runs a corpus-version-skew candidate. That candidate preserves the
decision and material evidence links while changing
`provenance.retrieval_corpus_digest`; the comparison records a
`provenance_only_change` rather than a blocking regression.

Runtime retrieval uses committed JSON artifacts:

- `fixtures/rag/corpus_manifest.json`
- `fixtures/rag/corpus_manifest_skewed.json`
- `fixtures/rag/vector_manifest.json`
- `fixtures/rag/cached_vectors.json`
- `fixtures/rag/policy_corpus/current/*.json`

The cached vectors are scaled integers. Vector-manifest digesting uses exact
file bytes, cosine scoring stays in Python `Decimal` arithmetic, and retrieval
scores are quantized to six decimal places. Policy effective-date filtering uses
the fixture `as_of_date`; it does not read the ambient system clock. Policy
validity windows are treated as `[effective_date, expires_date)`.
The retrieval request fixture fully pins `top_k`, `score_threshold`,
`required_source_ids`, and `reranker_configs`; the reranker regression is a
synthetic fixture-mode perturbation, not a production reranker implementation.
