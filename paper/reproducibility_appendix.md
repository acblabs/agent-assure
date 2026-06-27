# Reproducibility Appendix

This appendix records commands for reproducing the deterministic fixture-mode
artifacts from a clean checkout. The commands do not call live model providers
and do not require provider API keys for the bundled examples.

## Environment

Use Python 3.11 or newer and install the project in editable mode:

```bash
pip install -e ".[dev]"
```

The installed console script is `agent-assure`. If you are developing directly
from the source tree before installing, use the local environment's Python
launcher with `PYTHONPATH=src`.

## Schema Export And Validation

```bash
agent-assure schema export --out schemas/v0.1.0
agent-assure suite compile examples/prior_auth_synthetic/suite.yaml --out .tmp/repro/prior-auth.compiled.json --manifest .tmp/repro/prior-auth.fixtures.json
agent-assure validate .tmp/repro/prior-auth.compiled.json --kind compiled-suite
agent-assure validate .tmp/repro/prior-auth.fixtures.json --kind fixture-manifest
```

The validation commands should exit `0` and state that the `agent-assure`
validator was used.

## Flagship Prior-Authorization Showcase

```bash
mkdir -p .tmp/repro
agent-assure suite compile examples/prior_auth_synthetic/suite.yaml --out .tmp/repro/prior-auth.compiled.json --manifest .tmp/repro/prior-auth.fixtures.json
agent-assure suite run .tmp/repro/prior-auth.compiled.json --variant examples/prior_auth_synthetic/variants/baseline.yaml --manifest .tmp/repro/prior-auth.fixtures.json --out .tmp/repro/prior-auth.baseline.json
agent-assure suite run .tmp/repro/prior-auth.compiled.json --variant examples/prior_auth_synthetic/variants/candidate_evidence_normalization.yaml --manifest .tmp/repro/prior-auth.fixtures.json --out .tmp/repro/prior-auth.evidence-candidate.json
agent-assure evaluate .tmp/repro/prior-auth.baseline.json --suite .tmp/repro/prior-auth.compiled.json --out-dir .tmp/repro/baseline-report
agent-assure evaluate .tmp/repro/prior-auth.evidence-candidate.json --suite .tmp/repro/prior-auth.compiled.json --out-dir .tmp/repro/evidence-report
agent-assure compare .tmp/repro/prior-auth.baseline.json .tmp/repro/prior-auth.evidence-candidate.json --suite .tmp/repro/prior-auth.compiled.json --out-dir .tmp/repro/comparison-report
agent-assure ci .tmp/repro/prior-auth.evidence-candidate.json --suite .tmp/repro/prior-auth.compiled.json --baseline .tmp/repro/prior-auth.baseline.json --out-dir .tmp/repro/ci-report --report-mode full
```

Expected exits:

- baseline evaluation exits `0`;
- candidate evaluation exits `1`;
- comparison exits `1`;
- CI exits `1`.

The nonzero exits are expected because the candidate introduces a deterministic
material evidence-link failure. The reports are still written before exit.

Expected key fields:

```text
case_id: shared-source-multi-claim
control_id: material_claims_have_evidence
target: claim:claim-duration
reason_code: MATERIAL_CLAIM_MISSING_EVIDENCE
classification: new_failure
fixture_equivalence_state: pass
```

## Evidence Packet

After the candidate evaluation and comparison reports exist:

```bash
agent-assure packet build .tmp/repro/evidence-report/evaluation-summary.json --comparison .tmp/repro/comparison-report/comparison-summary.json --out .tmp/repro/evidence-packet.json
agent-assure ci gate .tmp/repro/evidence-packet.json
```

The packet gate exits `1` for the known failing candidate. The packet contains
interpretation guidance, deterministic report summaries, environment metadata,
input artifact digests, dependency-inventory digest, and release manifest
references. It does not contain raw fixture payloads, prompts, outputs, tool
arguments, or unredacted sensitive summaries.

## Minimal Expense-Approval Example

```bash
agent-assure suite compile examples/expense_approval_minimal/suite.yaml --out .tmp/repro/expense.compiled.json --manifest .tmp/repro/expense.fixtures.json
agent-assure suite run .tmp/repro/expense.compiled.json --variant examples/expense_approval_minimal/variants/baseline.yaml --manifest .tmp/repro/expense.fixtures.json --out .tmp/repro/expense.baseline.json
agent-assure suite run .tmp/repro/expense.compiled.json --variant examples/expense_approval_minimal/variants/candidate_provider_policy.yaml --manifest .tmp/repro/expense.fixtures.json --out .tmp/repro/expense.candidate.json
agent-assure evaluate .tmp/repro/expense.baseline.json --suite .tmp/repro/expense.compiled.json --out-dir .tmp/repro/expense-baseline-report
agent-assure evaluate .tmp/repro/expense.candidate.json --suite .tmp/repro/expense.compiled.json --out-dir .tmp/repro/expense-candidate-report
```

The baseline evaluation exits `0`. The provider-policy candidate exits `1` and
shows deterministic outcome, provider, and human-review control failures.

## OpenTelemetry-Aligned Preview

```bash
agent-assure otel preview tests/fixtures/run_record.json --out .tmp/repro/span-plan.json
```

The span plan is derived from structured run-record fields. It does not persist
raw payloads and does not emit `gen_ai.response.tokens` or generic
`rpc.method` attributes for local fixture tool artifacts.

## Release Replay

```bash
python scripts/build_release_bundle.py --out .tmp/release --write-digests .tmp/release/release-digest-replay.json
agent-assure release replay .tmp/release/release-digest-replay.json --artifact-root . --require-current-commit
```

Release replay uses raw file digests for stable source artifacts and stable JSON
projection digests for environment-bearing review artifacts. The release bundle
also records an SBOM plus Python wheel and source distribution assets in the
release manifest. Digest replay is a reproducibility check, not a
cryptographic signature. Cosign verification of workflow-signed release blobs
is documented in `docs/release_evidence.md`.

## Test And Quality Checks

```bash
python scripts/check_docs_alignment.py
ruff check .
mypy src
pytest
python -m build
```

The test configuration disables sockets for pytest. This guards the fixture-mode
claim that bundled examples run without live network access.

## Digest Notes

Stable source artifacts such as compiled suites, fixture manifests, and RunSets
can be compared by raw SHA-256 file digest after canonical writes. Reports,
packets, dependency inventories, and manifests include local environment
metadata that may differ across machines; release replay uses stable projections
for those environment-bearing artifacts.
