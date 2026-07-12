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

Adapters or external `AgentRunRecord` producers must follow
`agent-run-record-producer-contract/v1`: emit explicit `claim_evidence_links`
for every material claim they intend to satisfy, and point each link to a
present `evidence_refs[].ref_id` in the same run record.
`evidence_refs[].claim_ids` alone is display/compatibility context and is not
an evaluator contract.

For human-review expectations, `required_human_review` means the run must retain
the declared review route. `human_review_performed` is an observed process fact
for reporting and live trajectory checks, not a substitute for the route flag
in deterministic expectation evaluation.
