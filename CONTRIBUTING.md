# Contributing

Contributions should preserve the project claim boundary: expectation-driven
offline assurance first, live stochastic evaluation later.

Run before opening a pull request:

```bash
python scripts/check_docs_alignment.py
ruff check .
mypy src
pytest
```
