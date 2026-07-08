# NIST AI RMF Crosswalk

This is a planning crosswalk only. It organizes `agent-assure` controls by the
NIST AI Risk Management Framework functions (`Govern`, `Map`, `Measure`,
`Manage`) declared in `docs/threat_coverage_matrix.yaml`. This project is not a
compliance attestation and this crosswalk is not a NIST assessment result.

These are reviewer-facing function tags, not a claim of AI RMF conformance,
profile completeness, or subcategory coverage. They identify where deterministic
review evidence may help a team prepare its own AI RMF material.

## Current Control Mapping

| Control | Status | NIST AI RMF Functions | Project Threats |
| --- | --- | --- | --- |
| `runtime_success_required` | `evaluated` | Measure; Manage | `fixture-runtime-failure` |
| `structured_output_required` | `evaluated` | Measure | `invalid-structured-record` |
| `evidence_required` | `evaluated` | Measure; Govern | `missing-required-evidence` |
| `material_claims_have_evidence` | `evaluated` | Measure; Govern | `material-claim-link-regression` |
| `tool_allowlist` | `evaluated_when_configured` | Measure; Manage | `unexpected-tool-use` |
| `provider_review_boundary` | `evaluated` | Measure; Manage | `forbidden-provider-review-boundary` |
| `human_review_required` | `evaluated` | Measure; Manage | `missing-review-route` |
| `redaction_required` | `partially_evaluated` | Measure; Govern | `persisted-sensitive-content` |
| `prompt_injection_control_boundary` | `evaluated` | Measure; Manage | `prompt-boundary-bypass` |
| `live_persisted_policy_results` | `evaluated_when_live` | Measure; Manage | `live-adapter-suppressed-policy-failure` |
| `live_config_path_confinement` | `evaluated` | Manage | `live-config-path-traversal` |
| `live_openai_endpoint_allowlist` | `evaluated` | Manage | `network-adapter-key-exfiltration` |
| `external_script_output_limit` | `evaluated` | Manage | `external-script-output-dos` |

## Function Emphasis

`agent-assure` concentrates on the `Measure` and `Manage` functions: it produces
deterministic measurement artifacts around agent process behavior and supports
managing declared release-time process invariants. It touches `Govern` where
transparency, documentation, and accountability of the evidence trail are
involved.

The `Map` function is intentionally out of scope. The project does not perform
context discovery or stakeholder-impact mapping; that boundary is kept visible
in the matrix rather than implied as covered.

## Declared Gaps

The matrix keeps AI RMF-relevant work that the project does not perform visible
instead of treating silence as coverage.

| Gap | NIST AI RMF Functions |
| --- | --- |
| `raw_payload_persistence_forbidden` | Measure; Govern |
| `live-adapter-attestation` | Measure; Manage |
| `live-stochastic-model-quality-regression` | Measure |
| `context-discovery-and-stakeholder-impact-mapping` | Map |
| `production-runtime-isolation` | Manage |
| `safety-or-regulatory-certification` | Govern |

## Interpretation Boundary

The table reports declared local review areas for deterministic artifacts. It
does not judge an organization's risk management program, operating context,
risk tolerance, or governance duties, and it does not establish NIST AI RMF
conformance.
