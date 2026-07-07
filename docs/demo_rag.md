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

The bundled RAG fixture also contains a counterfactual query family for the
same physical-therapy duration decision. The fixture author declares those
query variants to be metamorphic equivalents for this synthetic case, and the
demo measures whether declared refs, source IDs, and claim support remain
present across the declared variants. Each variant points at a distinct
committed query-vector key, so paraphrase fixtures can exercise keyed retrieval
or reranker behavior without generating embeddings during tests. Some committed
entries may intentionally share the same vector value. The family inherits the
canonical case's expected recommendation, required refs, and material claims
from `rag_suite.yaml`, while declaring RAG-specific source IDs in the family
fixture. Reported required-ref coverage tracks only those inherited suite refs;
duration support is also reported through the source-ID and material-claim
dimensions. The report stores query digests and stable variant IDs, not raw
query text. Decision equivalence is measured on the canonical case only; each
paraphrase variant recomputes retrieval evidence support, not a separate model
decision. This does not prove semantic equivalence; it is fixture evidence that
retrieval support stayed preserved for an authored query family.

Runtime retrieval uses committed JSON artifacts:

- `fixtures/rag/corpus_manifest.json`
- `fixtures/rag/corpus_manifest_skewed.json`
- `fixtures/rag/vector_manifest.json`
- `fixtures/rag/cached_vectors.json`
- `fixtures/rag/policy_corpus/current/*.json`
- `fixtures/rag/counterfactual_query_families.json`

The cached vectors are scaled integers. Vector-manifest digesting uses exact
file bytes, cosine scoring stays in Python `Decimal` arithmetic, and retrieval
scores are quantized to six decimal places. Policy effective-date filtering uses
the fixture `as_of_date`; it does not read the ambient system clock. Policy
validity windows are treated as `[effective_date, expires_date)`.
The retrieval request fixture fully pins `top_k`, `score_threshold`,
`required_source_ids`, and `reranker_configs`; the reranker regression is a
synthetic fixture-mode perturbation, not a production reranker implementation.
For the counterfactual family, the synthetic reranker drops duration support for
one declared paraphrase while preserving the other declared paraphrases, making
the affected query variant visible in the demo summary.
