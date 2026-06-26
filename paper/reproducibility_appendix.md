# Reproducibility Appendix

Current reproduction commands:

```bash
pip install -e ".[dev]"
agent-assure schema export --out schemas/v0.1.0
agent-assure suite compile examples/prior_auth_synthetic/suite.yaml --out .tmp/compiled-suite.json
agent-assure validate .tmp/compiled-suite.json --kind compiled-suite
agent-assure suite run .tmp/compiled-suite.json --variant examples/prior_auth_synthetic/variants/baseline.yaml --out .tmp/baseline-runset.json
agent-assure suite run .tmp/compiled-suite.json --variant examples/prior_auth_synthetic/variants/candidate_evidence_normalization.yaml --out .tmp/evidence-candidate-runset.json
agent-assure evaluate .tmp/baseline-runset.json --suite .tmp/compiled-suite.json --out-dir .tmp/baseline-report
agent-assure compare .tmp/baseline-runset.json .tmp/evidence-candidate-runset.json --suite .tmp/compiled-suite.json --out-dir .tmp/comparison-report
agent-assure ci .tmp/evidence-candidate-runset.json --suite .tmp/compiled-suite.json --baseline .tmp/baseline-runset.json --out-dir .tmp/ci-report --report-mode full
agent-assure otel preview tests/fixtures/run_record.json --out .tmp/span-plan.json
pytest
```

The comparison and CI commands above are expected to exit `1` because the
candidate introduces a deterministic material-evidence finding. Their artifacts
are still written before exit.
