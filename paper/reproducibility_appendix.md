# Reproducibility Appendix

Current reproduction commands:

```bash
pip install -e ".[dev]"
agent-assure schema export --out schemas/v0.1.0
agent-assure suite compile examples/prior_auth_synthetic/suite.yaml --out .tmp/compiled-suite.json
agent-assure validate .tmp/compiled-suite.json --kind compiled-suite
agent-assure otel preview tests/fixtures/run_record.json --out .tmp/span-plan.json
pytest
```
