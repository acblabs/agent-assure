PYTHON ?= $(or $(wildcard .venv/Scripts/python.exe),$(wildcard .venv/bin/python),python)
SOURCE_CLI_PYTHON := $(PYTHON)
SCHEMA_DIR ?= $(shell $(PYTHON) scripts/schema_target.py)

.PHONY: test lint type clean-dist build docs-align claim-boundary examples-parity schemas schema-force-includes schema-staging schema-check release-bundle check release-check demo

test:
	$(PYTHON) -m pytest

lint:
	$(PYTHON) -m ruff check .

type:
	$(PYTHON) -m mypy src scripts

clean-dist:
	$(PYTHON) scripts/clean_dist.py

build: clean-dist
	$(PYTHON) -m build --no-isolation

release-bundle:
	$(PYTHON) scripts/build_release_bundle.py --out .tmp/release --write-digests .tmp/release/release-digest-replay.json

docs-align:
	$(PYTHON) scripts/check_docs_alignment.py

claim-boundary:
	$(PYTHON) scripts/check_claim_boundaries.py

examples-parity:
	$(PYTHON) scripts/check_packaged_examples.py

check: lint type test docs-align claim-boundary examples-parity build

release-check: check schema-check
	$(PYTHON) -m twine check dist/*
	$(PYTHON) scripts/check_wheel_contents.py
	$(PYTHON) scripts/smoke_install_wheel.py

demo:
	$(SOURCE_CLI_PYTHON) scripts/run_source_cli.py demo flagship --out .tmp/demo/flagship --clean

schemas:
	$(SOURCE_CLI_PYTHON) scripts/run_source_cli.py schema export --out $(SCHEMA_DIR)
	$(PYTHON) scripts/sync_schema_force_includes.py

schema-force-includes:
	$(PYTHON) scripts/sync_schema_force_includes.py

schema-staging:
	$(PYTHON) scripts/check_schema_staging.py

schema-check:
	$(PYTHON) scripts/sync_schema_force_includes.py --check
	$(PYTHON) scripts/check_frozen_schemas.py
	$(PYTHON) scripts/check_tagged_schema_immutability.py
	$(PYTHON) scripts/check_schema_staging.py
