# Expectation Authoring

Expectations are the primary oracle. A case may specify an expected
recommendation or an allowed outcome set, but not both. Material claim IDs are
declared by the fixture author and are never inferred from rationale text.

During evaluation, `material_claim_ids` are checked only against structured
claim-evidence links that point to present evidence items. The
`evidence_refs[].claim_ids` view is compatibility/display context and does not
satisfy the material-claim invariant by itself. The evaluator does not scan
prose, call a model, use embeddings, or infer whether an undeclared claim is
material.

Adapters or external `AgentRunRecord` producers must emit explicit
`claim_evidence_links` for every material claim they intend to satisfy;
`evidence_refs[].claim_ids` alone is not an evaluator contract.
