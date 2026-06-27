.PHONY: test lint type build docs-align schemas schema-check

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

schema-check:
	agent-assure schema export --out schemas/v0.1.0
	git diff --exit-code -- schemas/v0.1.0
