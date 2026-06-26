# Flagship Showcase

This showcase demonstrates one deterministic governance-pipeline regression
under fixed local fixtures. It is a reproducible fixture-mode example, not a
live model-quality, safety, clinical-validation, compliance, endorsement, or
standards-adoption claim.

## Commands

Run the commands one at a time from the repository root. The candidate
evaluation and comparison commands are expected to exit `1` after writing their
reports.

```bash
pip install -e ".[dev]"
mkdir -p .tmp/showcase
agent-assure suite compile examples/prior_auth_synthetic/suite.yaml --out .tmp/showcase/prior-auth.compiled.json --manifest .tmp/showcase/prior-auth.fixtures.json
agent-assure suite run .tmp/showcase/prior-auth.compiled.json --variant examples/prior_auth_synthetic/variants/baseline.yaml --manifest .tmp/showcase/prior-auth.fixtures.json --out .tmp/showcase/prior-auth.baseline.json
agent-assure suite run .tmp/showcase/prior-auth.compiled.json --variant examples/prior_auth_synthetic/variants/candidate_evidence_normalization.yaml --manifest .tmp/showcase/prior-auth.fixtures.json --out .tmp/showcase/prior-auth.evidence-candidate.json
agent-assure evaluate .tmp/showcase/prior-auth.baseline.json --suite .tmp/showcase/prior-auth.compiled.json --out-dir .tmp/showcase/baseline-report
agent-assure evaluate .tmp/showcase/prior-auth.evidence-candidate.json --suite .tmp/showcase/prior-auth.compiled.json --out-dir .tmp/showcase/evidence-report
agent-assure compare .tmp/showcase/prior-auth.baseline.json .tmp/showcase/prior-auth.evidence-candidate.json --suite .tmp/showcase/prior-auth.compiled.json --out-dir .tmp/showcase/comparison-report
```

## Expected Story

The baseline evaluation report is a pass:

```text
.tmp/showcase/baseline-report/evaluation-summary.json
state: pass
findings: []
```

The evidence-normalization candidate is a fail with one blocking finding:

```text
.tmp/showcase/evidence-report/evaluation-summary.json
state: fail
case_id: shared-source-multi-claim
control_id: material_claims_have_evidence
target: claim:claim-duration
reason_code: MATERIAL_CLAIM_MISSING_EVIDENCE
message: fixture-declared material claim 'claim-duration' has no evidence link
```

The baseline-to-candidate comparison classifies the change as a new failure
while fixture equivalence passes:

```text
.tmp/showcase/comparison-report/comparison-summary.json
baseline_state: pass
candidate_state: fail
classification: new_failure
fixture_equivalence_state: pass
```

For `shared-source-multi-claim`, both run sets retain the visible answer:
`recommendation=approve; outcome=approve`. The comparison report's behavioral
record change is the structured evidence reference: the baseline links
`claim-duration` and `claim-eligibility` to the shared source, while the
candidate keeps only `claim-eligibility`. The verdict comes from the
fixture-declared material evidence invariant, not from output hashes or
provenance changes.

## Report Paths

- `.tmp/showcase/baseline-report/evaluation-report.md`
- `.tmp/showcase/evidence-report/evaluation-report.md`
- `.tmp/showcase/comparison-report/comparison-report.md`
- `.tmp/showcase/comparison-report/comparison-summary.json`

## Artifact Digest Summary

These SHA-256 file digests are for the LF-normalized JSON artifacts emitted by
the command sequence above. They are reproducibility anchors, not signatures,
release attestations, SBOMs, or cosign verification material.

| Artifact | SHA-256 |
| --- | --- |
| `.tmp/showcase/prior-auth.compiled.json` | `0003e103eb402fc786ed1beb4fd0d985bae1c1e8c5e16daa9a1526faf5a86c46` |
| `.tmp/showcase/prior-auth.fixtures.json` | `18e66c33492400cc89ed40b318a56e38381a86e88a8d1da9807f2fccc2740eb9` |
| `.tmp/showcase/prior-auth.baseline.json` | `2287d584967b16db4e60283e97a25e1d74ca90867ea0e9245b2ee8ba5b317e8e` |
| `.tmp/showcase/prior-auth.evidence-candidate.json` | `3965e2389b9db9b200cf1497a5585e2542859da4495c0bd287eb5bbbc15f2b40` |
| `.tmp/showcase/baseline-report/evaluation-report.json` | `fc00d73436eeb09d4c038b42719339775fca6aa1c78e2660b65eb9cfabef10bf` |
| `.tmp/showcase/baseline-report/evaluation-summary.json` | `5c2c77e307077be81cb02a9031bb26054d80787ef23e0960e5ae3ba6a524a3c9` |
| `.tmp/showcase/evidence-report/evaluation-report.json` | `e782fd54e320a574ab70845c07fe923ecf5d9eef0154345a063786ebd3e2875d` |
| `.tmp/showcase/evidence-report/evaluation-summary.json` | `04390305879e06b69c69722f393307233814699ed6774957f4287339e55ad5d0` |
| `.tmp/showcase/comparison-report/comparison-report.json` | `76d3caf34c9b6635d68833637fbf5bed41ad07fd6b1981d46dc63cf75293cf9f` |
| `.tmp/showcase/comparison-report/comparison-summary.json` | `18c3e298f71af91df7d95afd85b7e233310e211d779982b7ec2565ee0de002df` |

## GitHub Actions Usage

This workflow snippet runs the same showcase without using live providers. The
two expected-failure steps assert the CLI exits `1` for the deterministic
candidate regression.

```yaml
name: agent-assure-showcase
on: [push, pull_request]
jobs:
  flagship:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install -e ".[dev]"
      - run: mkdir -p .tmp/showcase
      - run: agent-assure suite compile examples/prior_auth_synthetic/suite.yaml --out .tmp/showcase/prior-auth.compiled.json --manifest .tmp/showcase/prior-auth.fixtures.json
      - run: agent-assure suite run .tmp/showcase/prior-auth.compiled.json --variant examples/prior_auth_synthetic/variants/baseline.yaml --manifest .tmp/showcase/prior-auth.fixtures.json --out .tmp/showcase/prior-auth.baseline.json
      - run: agent-assure suite run .tmp/showcase/prior-auth.compiled.json --variant examples/prior_auth_synthetic/variants/candidate_evidence_normalization.yaml --manifest .tmp/showcase/prior-auth.fixtures.json --out .tmp/showcase/prior-auth.evidence-candidate.json
      - run: agent-assure evaluate .tmp/showcase/prior-auth.baseline.json --suite .tmp/showcase/prior-auth.compiled.json --out-dir .tmp/showcase/baseline-report
      - name: Evaluate expected candidate failure
        run: |
          set +e
          agent-assure evaluate .tmp/showcase/prior-auth.evidence-candidate.json --suite .tmp/showcase/prior-auth.compiled.json --out-dir .tmp/showcase/evidence-report
          status=$?
          set -e
          if [ "$status" -ne 1 ]; then
            echo "expected exit 1, got $status"
            exit 1
          fi
          grep -q "MATERIAL_CLAIM_MISSING_EVIDENCE" .tmp/showcase/evidence-report/evaluation-report.md
      - name: Compare expected new failure
        run: |
          set +e
          agent-assure compare .tmp/showcase/prior-auth.baseline.json .tmp/showcase/prior-auth.evidence-candidate.json --suite .tmp/showcase/prior-auth.compiled.json --out-dir .tmp/showcase/comparison-report
          status=$?
          set -e
          if [ "$status" -ne 1 ]; then
            echo "expected exit 1, got $status"
            exit 1
          fi
          grep -q 'Classification: `new_failure`' .tmp/showcase/comparison-report/comparison-report.md
          grep -q "claim-duration" .tmp/showcase/comparison-report/comparison-report.md
```
