# Control Efficacy Report

## Claim Boundary

- Mutation efficacy is bounded to the declared catalog, subject, evaluator, and manifest.
- Kill rates are detector-test ratios, not safety, compliance, or certification scores.
- Threat mappings are planning evidence and do not establish conformance.

## Evidence Identity

- Report digest: `416e5aac9d23c5c7d1d3b4bf0c2e2e97d0e198f8752c442a08d6df91a1d6ba22`
- Campaign digest: `f088d1944b2ce9cb23f84e24b38b68ab93e354632a34975409679328a1602f1b`
- Catalog: `core/v1`
- Catalog digest: `b04aecb1fb613a46c8d52ca8e48648fd1e96d00a804ce47896be12bd6236697f`
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
