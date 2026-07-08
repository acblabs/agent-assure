# ISO/IEC 42001 Crosswalk

This is a planning crosswalk only. It organizes `agent-assure` controls by the
local ISO/IEC 42001 concept areas declared in
`docs/threat_coverage_matrix.yaml`. This project is not a compliance
attestation.

These are reviewer-facing concept labels, not ISO clause IDs. They identify
where deterministic evidence may help a team prepare review material.

## Current Control Mapping

| Control | Status | ISO/IEC 42001 Concept Areas | Project Threats |
| --- | --- | --- | --- |
| `runtime_success_required` | `evaluated` | monitoring; accountability | `fixture-runtime-failure` |
| `structured_output_required` | `evaluated` | documentation; monitoring | `invalid-structured-record` |
| `evidence_required` | `evaluated` | transparency; documentation | `missing-required-evidence` |
| `material_claims_have_evidence` | `evaluated` | transparency; accountability | `material-claim-link-regression` |
| `tool_allowlist` | `evaluated_when_configured` | AI system lifecycle governance; monitoring | `unexpected-tool-use` |
| `provider_review_boundary` | `evaluated` | AI system lifecycle governance; accountability | `forbidden-provider-review-boundary` |
| `human_review_required` | `evaluated` | human oversight; accountability | `missing-review-route` |
| `redaction_required` | `partially_evaluated` | transparency; documentation | `persisted-sensitive-content` |
| `prompt_injection_control_boundary` | `evaluated` | human oversight; monitoring | `prompt-boundary-bypass` |
| `live_persisted_policy_results` | `evaluated_when_live` | monitoring; accountability | `live-adapter-suppressed-policy-failure` |
| `live_config_path_confinement` | `evaluated` | AI system lifecycle governance; monitoring | `live-config-path-traversal` |
| `live_openai_endpoint_allowlist` | `evaluated` | AI system lifecycle governance; monitoring | `network-adapter-key-exfiltration` |
| `external_script_output_limit` | `evaluated` | monitoring | `external-script-output-dos` |

## Interpretation Boundary

The table reports declared local review areas for deterministic artifacts. It
does not judge an organization's AI management system, operating context,
policy completeness, or legal duties, and it does not establish ISO/IEC 42001
conformance.
