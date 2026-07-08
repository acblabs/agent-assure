# agent-assure

`agent-assure` is a local-first process assurance toolkit for agentic AI
pipelines.

The core thesis is simple: output equivalence is not process equivalence. A
candidate pipeline can preserve the visible decision while changing the
evidence, review route, provider/tool boundary, redaction behavior, retries, or
provenance around that answer. In the flagship demo, that output-equivalence
claim is grounded in decision equivalence: the recommendation and outcome stay
the same.

The current adoption path is intentionally small:

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

## Governance Crosswalks

The machine-readable matrix in `docs/threat_coverage_matrix.yaml` tags local
controls with OWASP LLM Top 10 2025 risks, NIST AI RMF functions, ISO/IEC 42001
concept areas, and the pinned MITRE ATLAS 2026.06 planning crosswalk. These are
review aids, not broad framework outcome claims.

- [ISO/IEC 42001 crosswalk](governance_crosswalk_iso42001.md)
- [MITRE ATLAS crosswalk](governance_crosswalk_mitre_atlas.md)
