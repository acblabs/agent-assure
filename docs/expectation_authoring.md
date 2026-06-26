# Expectation Authoring

Expectations are the primary oracle. A case may specify an expected
recommendation or an allowed outcome set, but not both. Material claim IDs are
declared by the fixture author and are never inferred from rationale text.

During evaluation, `material_claim_ids` are checked only against structured
claim-evidence links that point to present evidence items. The compatibility
`evidence_refs[].claim_ids` view is used only for older records without explicit
links. The evaluator does not scan prose, call a model, use embeddings, or infer
whether an undeclared claim is material.
