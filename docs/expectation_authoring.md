# Expectation Authoring

Expectations are the primary oracle. A case may specify an expected
recommendation or an allowed outcome set, but not both. Material claim IDs are
declared by the fixture author and are never inferred from rationale text.

During evaluation, `material_claim_ids` are checked only against structured
evidence references and their `claim_ids`. The evaluator does not scan prose,
call a model, use embeddings, or infer whether an undeclared claim is material.
