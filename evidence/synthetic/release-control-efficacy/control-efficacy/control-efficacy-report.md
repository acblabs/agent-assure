# Control Efficacy Report

## Claim Boundary

- Mutation efficacy is bounded to the declared catalog, subject, evaluator, and manifest.
- Kill rates are detector-test ratios, not safety, compliance, or certification scores.
- Threat mappings are planning evidence and do not establish conformance.

## Evidence Identity

- Report digest: `fba1c219c8ed3fd4421af17cdff0a9f13ad2bd6542826167223f0d0cc3bd45b9`
- Campaign digest: `eae4e9fe1f5f272bfe04542a31832c9fca0fcf3da0a5e6f974c19bf2e965d036`
- Catalog: `core/v1`
- Catalog digest: `0ac5eac866c49408d3a44a2e92341aab916eb245b0dea2bbd1fc4bfe96a63df8`
- Threat manifest digest: `edaab6b88665c403e72c100bfb9c9bf8c17376ba47e791a4c88e5d8ce2e2ab4e`

## Semantic Evidence State

- Control efficacy: `all_evaluated_applicable_caught`
- Threat scope: `all_applicable_challenged`
- These semantic states are computed independently of gate-profile effects.

## Exact Catalog Metrics

- Catalog detector kill ratio (`catalog_kill_rate`): `7/7` (`defined`)
- Canonical catalog operators: `7`
- Canonical invariant families: `7`
- Selected operators: `7`
- Completed selected operators: `7`
- Pending selected operators: `0`
- Applicable operators: `7`
- Caught: `7`
- Survived: `0`
- Inapplicable: `0`
- Invalid operator: `0`
- Invalid subject: `0`
- Execution error: `0`
- Required survivors: `0`
- Critical survivors: `0`

## Gate-Profile Decision

- Profile: `control-efficacy/default`
- Decision: `pass`
- No gate-profile rule was triggered.

## Independence Strata

| Independence class | Independent coverage eligible | Caught | Survived | Inapplicable | Invalid operator | Invalid subject | Execution error | Kill rate |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| `external_preexisting` | yes | 0 | 0 | 0 | 0 | 0 | 0 | `0/0` (`undefined_zero_denominator`) |
| `third_party_contributed` | yes | 0 | 0 | 0 | 0 | 0 | 0 | `0/0` (`undefined_zero_denominator`) |
| `first_party_precontrol` | yes | 0 | 0 | 0 | 0 | 0 | 0 | `0/0` (`undefined_zero_denominator`) |
| `first_party_postcontrol` | no | 7 | 0 | 0 | 0 | 0 | 0 | `7/7` (`defined`) |
| `unknown` | no | 0 | 0 | 0 | 0 | 0 | 0 | `0/0` (`undefined_zero_denominator`) |

## Invariant-Family Strata

| Invariant family | Caught | Survived | Inapplicable | Invalid operator | Invalid subject | Execution error | Kill rate |
|---|---:|---:|---:|---:|---:|---:|---|
| `human-review-routing` | 1 | 0 | 0 | 0 | 0 | 0 | `1/1` (`defined`) |
| `material-evidence-linkage` | 1 | 0 | 0 | 0 | 0 | 0 | `1/1` (`defined`) |
| `privacy-redaction` | 1 | 0 | 0 | 0 | 0 | 0 | `1/1` (`defined`) |
| `provenance-corpus-identity` | 1 | 0 | 0 | 0 | 0 | 0 | `1/1` (`defined`) |
| `runset-completion-integrity` | 1 | 0 | 0 | 0 | 0 | 0 | `1/1` (`defined`) |
| `stream-replay-integrity` | 1 | 0 | 0 | 0 | 0 | 0 | `1/1` (`defined`) |
| `tool-boundary` | 1 | 0 | 0 | 0 | 0 | 0 | `1/1` (`defined`) |

## Threat Applicability and Challenge Coverage

- Applicable threat categories: `15`
- Challenged threat categories: `15`
- Independently challenged threat categories: `0`
- Challenge rate: `15/15` (`defined`)
- Independent challenge rate: `0/15` (`defined`)
- Critical uncovered threats: `0`
- Unknown applicability: `0`
- Catalog threat references absent from manifest: `0`
- Critical uncovered threat IDs: `none`
- Unknown-applicability threat IDs: `none`
- Catalog threat IDs absent from manifest: `none`

## Operator Outcomes

| Operator | State | Applicability | Invariant family | Independence class | Required | Critical applicable threat |
|---|---|---|---|---|---:|---:|
| `bypass-required-human-review` | `caught` | `applicable` | `human-review-routing` | `first_party_postcontrol` | yes | yes |
| `drop-material-evidence-link` | `caught` | `applicable` | `material-evidence-linkage` | `first_party_postcontrol` | yes | yes |
| `inject-forbidden-tool` | `caught` | `applicable` | `tool-boundary` | `first_party_postcontrol` | yes | yes |
| `inject-synthetic-sensitive-summary` | `caught` | `applicable` | `privacy-redaction` | `first_party_postcontrol` | yes | yes |
| `mark-incomplete-budget-stop` | `caught` | `applicable` | `runset-completion-integrity` | `first_party_postcontrol` | yes | no |
| `replay-duplicate-case-observation` | `caught` | `applicable` | `stream-replay-integrity` | `first_party_postcontrol` | yes | no |
| `skew-evidence-source-identity` | `caught` | `applicable` | `provenance-corpus-identity` | `first_party_postcontrol` | yes | no |
