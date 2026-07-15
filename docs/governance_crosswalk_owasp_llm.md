# OWASP LLM Top 10 Crosswalk

This is a planning crosswalk only. It tags `agent-assure` controls with the
OWASP Top 10 for LLM Applications 2025 risk IDs declared in
`docs/threat_coverage_matrix.yaml`. This project is not a compliance attestation
and this crosswalk is not an OWASP assessment result.

These are reviewer-facing risk tags, not a claim that a control mitigates a risk
category in full. They identify where deterministic review evidence may help a
team reason about a related OWASP risk area.

## Risk ID Reference

| ID | OWASP LLM Top 10 (2025) Risk |
| --- | --- |
| `LLM01` | Prompt Injection |
| `LLM02` | Sensitive Information Disclosure |
| `LLM05` | Improper Output Handling |
| `LLM06` | Excessive Agency |
| `LLM07` | System Prompt Leakage |
| `LLM08` | Vector and Embedding Weaknesses |
| `LLM09` | Misinformation |

Only the risk IDs referenced by at least one control are listed above.

## Current Control Mapping

| Control | Status | OWASP LLM Risks | Project Threats |
| --- | --- | --- | --- |
| `runtime_success_required` | `evaluated` | `LLM08` | `fixture-runtime-failure` |
| `structured_output_required` | `evaluated` | `LLM02` | `invalid-structured-record` |
| `evidence_required` | `evaluated` | `LLM09` | `missing-required-evidence` |
| `material_claims_have_evidence` | `evaluated` | `LLM09` | `material-claim-link-regression` |
| `tool_allowlist` | `evaluated_when_configured` | `LLM06` | `unexpected-tool-use` |
| `provider_review_boundary` | `evaluated` | `LLM05` | `forbidden-provider-review-boundary` |
| `human_review_required` | `evaluated` | `LLM05` | `missing-review-route` |
| `redaction_required` | `partially_evaluated` | `LLM02` | `persisted-sensitive-content` |
| `prompt_injection_control_boundary` | `partially_evaluated` | `LLM01` | `prompt-boundary-bypass` |
| `live_persisted_policy_results` | `evaluated_when_live` | `LLM02`, `LLM09` | `live-adapter-suppressed-policy-failure` |
| `live_config_path_confinement` | `evaluated` | `LLM06`, `LLM07` | `live-config-path-traversal` |
| `live_openai_endpoint_allowlist` | `evaluated` | `LLM05`, `LLM07` | `network-adapter-key-exfiltration` |
| `external_script_output_limit` | `evaluated` | `LLM06` | `external-script-output-dos` |

## Risks Not Mapped

The following 2025 risk categories are not tagged to any current control. They
are listed to keep scope honest rather than implied as covered:

- `LLM03` Supply Chain
- `LLM04` Data and Model Poisoning
- `LLM10` Unbounded Consumption

The `external_script_output_limit` control bounds one narrow output-volume
failure mode; it is tagged `LLM06` (Excessive Agency) in the matrix and is not a
general Unbounded Consumption defense.

## Interpretation Boundary

The table reports declared local review areas for deterministic artifacts. A tag
indicates a related risk area, not that `agent-assure` prevents, detects, or
fully mitigates the OWASP risk in a production system. It does not establish
OWASP LLM Top 10 conformance.
