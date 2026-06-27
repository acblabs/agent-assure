# multi_llm Integration

`agent-assure` is framework-neutral. Future integration work may adapt
deterministic `multi_llm` artifacts into `AgentRunRecord`, `RunSet`, and
evidence-packet artifacts after the generic APIs stabilize.

Any adapter that produces `AgentRunRecord` artifacts must follow
`agent-run-record-producer-contract/v1`: populate `claim_evidence_links` for
material-claim evidence, and point each link to a present evidence reference.
`evidence_refs[].claim_ids` is display/compatibility context only and does not
satisfy `material_claims_have_evidence`.
