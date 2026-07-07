# ADR 0009: RAG Provenance Example Shape

Status: accepted

## Context

Sprint 7 adds RAG provenance assurance without destabilizing the existing
flagship prior-authorization demo. The existing `shared-source-multi-claim`
case already demonstrates a missing material claim link, but its fixture path is
not a retrieval-shaped example.

## Decision

Use a RAG-specific suite inside the existing `prior_auth_synthetic` example:

- `examples/prior_auth_synthetic/rag_suite.yaml`
- `examples/prior_auth_synthetic/fixtures/rag/`
- `examples/prior_auth_synthetic/variants/rag_*.yaml`

The packaged copy under `src/agent_assure/examples/prior_auth_synthetic/` stays
byte-aligned with the top-level example through the packaged-example parity
check.

This preserves the existing ten-case flagship suite and fixture manifest while
still extending prior-auth with a digest-addressed policy retrieval path. The
RAG runner loads corpus, vector, and retrieval fixtures from the example tree,
computes evidence associations only from retrieved chunks, and writes
`provenance.retrieval_corpus_digest` on the normal `AgentRunRecord`.

## Consequences

- The current `agent-assure demo flagship` behavior remains unchanged.
- `agent-assure demo rag` can use the same compile, run, evaluate, compare, CI,
  packet, and evidence-diff flow as the flagship demo.
- The hero reranker regression keeps the same retrieval corpus digest while
  dropping the secondary duration source.
- The corpus-version-skew variant changes only provenance when evidence links
  remain intact.
- No new top-level run-record, provenance, or reason-code fields are required.
