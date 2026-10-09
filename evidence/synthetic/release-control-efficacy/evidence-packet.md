# Evidence Packet

## How to Interpret

- Start with candidate\_vs\_expectations: pass means no blocking deterministic finding under the selected gate profile; fail means at least one expectation, policy, invariant, or configured gate failed.
- If a comparison summary is present, fixture\_equivalence\_state must be pass before interpreting candidate-to-baseline changes.
- Artifact digests and release-manifest digests are reproducibility anchors over local files; they are not signatures or external attestations.
- Not-evaluated capabilities are explicit scope boundaries, not evidence that the capability passed.
- If a usage summary is present, treat it as measured usage and declared estimated cost evidence for human review, not business impact evidence.
- If control efficacy is present, interpret it as catalog-relative challenge scope; it remains separate from candidate evidence closure.

## Candidate Summary

- Run set: `runset-69e59deb-4cf5-500e-bb17-405262e32611`
- State: `pass`
- Findings: `0`
- Usage summary: `not_observed`

## Assurance Control Challenge

- Boundary: catalog-relative scope adequacy; this is separate from candidate evidence closure.
- Catalog: `core/v1`
- Semantic state: `all_evaluated_applicable_caught`
- Gate profile: `control-efficacy/default`
- Gate mapping: `pass`
- Catalog detector kill ratio: `7/7 (defined)`
- Required survivors: `0` / `7` required
- Critical survivors: `0`; operator IDs: `&lt;none&gt;`
- Threat categories challenged: `15` / `15` applicable
- Independently challenged threat categories: `0` / `15` applicable
- Critical uncovered threats: `0` / `15` applicable
- Unknown applicability: `0` / `15` declared
- Unscoped catalog threats: `0`; threat IDs: `&lt;none&gt;`

### Gate Findings

- None.

### Independence Strata

- `external_preexisting`: `0/0 (undefined_zero_denominator)`; caught=0, survived=0, invalid_subject=0, total=0
- `third_party_contributed`: `0/0 (undefined_zero_denominator)`; caught=0, survived=0, invalid_subject=0, total=0
- `first_party_precontrol`: `0/0 (undefined_zero_denominator)`; caught=0, survived=0, invalid_subject=0, total=0
- `first_party_postcontrol`: `7/7 (defined)`; caught=7, survived=0, invalid_subject=0, total=7
- `unknown`: `0/0 (undefined_zero_denominator)`; caught=0, survived=0, invalid_subject=0, total=0

## Environment

- Platform: `Windows-11-10.0.26300-SP0`
- Python: `3.12.13`
- Git commit: `c39e3205625f39030237e4d8e5f38365b4d71dd5`
- Git dirty: `True`
- Lockfile: `requirements.lock`
- Lockfile digest: `9d127f21617573476278605601f131c875d4def7c102aca5cdd39dda4f261ee4`
- Dependency inventory: `evidence/synthetic/release-control-efficacy/dependency-inventory.json`
- Dependency inventory digest: `37cbfe5555e32ea99e02bf67f3324f9f5d6556523fbbd8ac7f23c98a19b13702`
- Installed packages: `81`

## Release Artifact Manifest

- `evaluation-summary` `evidence/synthetic/release-control-efficacy/evaluation/evaluation-summary.json` `c329c62ca9191d16ad57accc483cc85fe602a0f48b0a4b99ade00a09a6b767c7`
- `assurance-evidence-graph` `evidence/synthetic/release-control-efficacy/assurance-evidence-graph.json` `7de42d437d7978509f4221ebe38c8384be50d6e1a06b58037862ce421f156f1e`
- `dependency-inventory` `evidence/synthetic/release-control-efficacy/dependency-inventory.json` `37cbfe5555e32ea99e02bf67f3324f9f5d6556523fbbd8ac7f23c98a19b13702`
- `control-efficacy-report` `evidence/synthetic/release-control-efficacy/control-efficacy/control-efficacy-report.json` `1c5e1d34e020388600e882ac1836f83f5954566fa31bc8ca904f10cf8b965ec1`
- `control-efficacy-onboarding-config` `evidence/synthetic/release-control-efficacy/controls-mutation.yaml` `d34c25c55e15bdc8478c53bf479af3836e276ca67dc0247390dc32db49416f42`

## Evidence Graph

- Contract: `AssuranceEvidenceGraph/v1`
- Semantic digest: `05513153f32519c5552af446ee1ea0da1baa74acc032eb4f8823c48271f1695f`
- Exact-file digest: `7de42d437d7978509f4221ebe38c8384be50d6e1a06b58037862ce421f156f1e`

## Measured Usage

- measured usage: `not_observed`

## Limitations

- evidence packets summarize deterministic fixture-mode results; they are not signatures, attestations, safety certifications, compliance certifications, or live model-quality evidence
