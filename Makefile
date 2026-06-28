.PHONY: test lint type build docs-align schemas schema-check release-bundle

test:
	pytest

lint:
	ruff check .

type:
	mypy src

build:
	python -m build

release-bundle:
	python scripts/build_release_bundle.py --out .tmp/release --write-digests .tmp/release/release-digest-replay.json

docs-align:
	python scripts/check_docs_alignment.py

schemas:
	agent-assure schema export --out schemas/v0.2.0

schema-check:
	agent-assure schema export --out schemas/v0.2.0
	git diff --exit-code -- schemas/v0.2.0
