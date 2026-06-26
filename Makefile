.PHONY: test lint type build docs-align schemas

test:
	pytest

lint:
	ruff check .

type:
	mypy src

build:
	python -m build

docs-align:
	python scripts/check_docs_alignment.py

schemas:
	agent-assure schema export --out schemas/v0.1.0
