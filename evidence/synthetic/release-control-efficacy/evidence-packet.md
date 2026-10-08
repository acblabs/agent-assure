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
- Git commit: `42b8b1f289ef57b4b3c83d21f637b4b91278fc72`
- Git dirty: `True`
- Lockfile: `requirements.lock`
- Lockfile digest: `9d127f21617573476278605601f131c875d4def7c102aca5cdd39dda4f261ee4`
- Dependency inventory: `evidence/synthetic/release-control-efficacy/dependency-inventory.json`
- Dependency inventory digest: `0e9c396198c7a066e41d71eb45d0a46a8e593c1e1f8e05f530627148664efc01`
- Installed packages: `81`

## Release Artifact Manifest

- `evaluation-summary` `evidence/synthetic/release-control-efficacy/evaluation/evaluation-summary.json` `84a3d8a48a3f46a843572106616fc1103f4b99efa2881abd9570dee9e008fb72`
- `assurance-evidence-graph` `evidence/synthetic/release-control-efficacy/assurance-evidence-graph.json` `02625cd9b566de93fd67ebe39aea9dfa4c44dfeee2be3d209b2154b1ac575f41`
- `dependency-inventory` `evidence/synthetic/release-control-efficacy/dependency-inventory.json` `0e9c396198c7a066e41d71eb45d0a46a8e593c1e1f8e05f530627148664efc01`
- `control-efficacy-report` `evidence/synthetic/release-control-efficacy/control-efficacy/control-efficacy-report.json` `73d6a517f8ded12d11e5a631274e2c36f3538d2257b1d716f36e16a22340a182`
- `control-efficacy-onboarding-config` `evidence/synthetic/release-control-efficacy/controls-mutation.yaml` `a2faaf29e25ceb98270747c7f78de815ace998d1496f3c8a438215dea0b67d5a`

## Evidence Graph

- Contract: `AssuranceEvidenceGraph/v1`
- Semantic digest: `3f94627937da4e3a284cabe3080a0f62a86685f407b7abcab7f7dec00025cd09`
- Exact-file digest: `02625cd9b566de93fd67ebe39aea9dfa4c44dfeee2be3d209b2154b1ac575f41`

## Measured Usage

- measured usage: `not_observed`

## Limitations

- evidence packets summarize deterministic fixture-mode results; they are not signatures, attestations, safety certifications, compliance certifications, or live model-quality evidence
