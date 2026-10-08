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
- Git commit: `a2bdf8528b4c027a5f0bfc947dc247f15fb5ae1e`
- Git dirty: `True`
- Lockfile: `requirements.lock`
- Lockfile digest: `9d127f21617573476278605601f131c875d4def7c102aca5cdd39dda4f261ee4`
- Dependency inventory: `evidence/synthetic/release-control-efficacy/dependency-inventory.json`
- Dependency inventory digest: `e9fc7d81788c3aeba4fe4a75f61d493dbebb6165d4cb4a343f1fb05c738e28d3`
- Installed packages: `81`

## Release Artifact Manifest

- `evaluation-summary` `evidence/synthetic/release-control-efficacy/evaluation/evaluation-summary.json` `abd69480e0bd33ca413eccb7ea14d99197e895401c1b9b2895ece588b2687294`
- `assurance-evidence-graph` `evidence/synthetic/release-control-efficacy/assurance-evidence-graph.json` `b2833e9c6bce84e150e7001ee0d1bf4ef98d13b32d9c7a4ba827e3cdf984539c`
- `dependency-inventory` `evidence/synthetic/release-control-efficacy/dependency-inventory.json` `e9fc7d81788c3aeba4fe4a75f61d493dbebb6165d4cb4a343f1fb05c738e28d3`
- `control-efficacy-report` `evidence/synthetic/release-control-efficacy/control-efficacy/control-efficacy-report.json` `39343772a2cb010558ea2220b08ab2be4abb065605f779449a5da08880853a63`
- `control-efficacy-onboarding-config` `evidence/synthetic/release-control-efficacy/controls-mutation.yaml` `d34c25c55e15bdc8478c53bf479af3836e276ca67dc0247390dc32db49416f42`

## Evidence Graph

- Contract: `AssuranceEvidenceGraph/v1`
- Semantic digest: `71953a1b78162fff3143334e3e96fe518a1f4592ea2f1cbb0c97c1aac41dcd4b`
- Exact-file digest: `b2833e9c6bce84e150e7001ee0d1bf4ef98d13b32d9c7a4ba827e3cdf984539c`

## Measured Usage

- measured usage: `not_observed`

## Limitations

- evidence packets summarize deterministic fixture-mode results; they are not signatures, attestations, safety certifications, compliance certifications, or live model-quality evidence
