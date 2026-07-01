.PHONY: test lint type clean-dist build docs-align claim-boundary examples-parity schemas schema-staging schema-check release-bundle check release-check demo

test:
	pytest

lint:
	ruff check .

type:
	mypy src

clean-dist:
	python scripts/clean_dist.py

build: clean-dist
	python -m build --no-isolation

release-bundle:
	python scripts/build_release_bundle.py --out .tmp/release --write-digests .tmp/release/release-digest-replay.json

docs-align:
	python scripts/check_docs_alignment.py

claim-boundary:
	python scripts/check_claim_boundaries.py

examples-parity:
	python scripts/check_packaged_examples.py

check: lint type test docs-align claim-boundary examples-parity build

release-check: check
	python -m twine check dist/*
	python scripts/check_wheel_contents.py
	python scripts/smoke_install_wheel.py

demo:
	python -c "import sys; sys.path.insert(0, 'src'); from agent_assure.cli.main import app; app()" demo flagship --out .tmp/demo/flagship --clean

schemas: schema-staging

schema-staging:
	python scripts/check_schema_staging.py

schema-check:
	agent-assure schema export --out schemas/v0.2.0
	git diff --exit-code -- schemas/v0.2.0
	python scripts/check_schema_staging.py
