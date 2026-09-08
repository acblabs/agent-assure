# Contributing

Contributions should preserve the project claim boundary: expectation-driven
offline assurance first, live stochastic evaluation later.

Non-maintainers who want to help with the external CI learning checkpoint can
follow the [external pilot quickstart](docs/external_pilot_quickstart.md). A
volunteer response, fork, or workflow run is not publication consent or a claim
of independent validation.

Run before opening a pull request:

```bash
python scripts/check_docs_alignment.py
ruff check .
mypy src
pytest
```
