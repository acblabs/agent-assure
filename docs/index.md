# agent-assure

`agent-assure` is a local-first process assurance toolkit for agentic AI
pipelines.

The core thesis is simple: output equivalence is not process equivalence. A
candidate pipeline can preserve the visible decision while changing the
evidence, review route, provider/tool boundary, redaction behavior, retries, or
provenance around that answer. In the flagship demo, that output-equivalence
claim is grounded in decision equivalence: the recommendation and outcome stay
the same.

The v0.3.0 adoption path is intentionally small:

```bash
pip install agent-assure
agent-assure demo flagship
```

The demo runs offline, produces local review artifacts, and shows a candidate
with preserved output equivalence that drops the material `claim-duration`
evidence link. The CI gate blocks that process regression as expected.

## Start Here

- [For AI leaders](for_ai_leaders.md)
- [For engineers](for_engineers.md)
- [What this measures](what_this_measures.md)
- [Flagship demo](demo_flagship.md)
- [RAG provenance demo](demo_rag.md)
- [Evidence diff](evidence_diff.md)
- [Claim boundary](claim_boundary.md)
