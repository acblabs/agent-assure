PYTHON ?= $(or $(wildcard .venv/Scripts/python.exe),$(wildcard .venv/bin/python),python)
SOURCE_CLI_PYTHON := $(PYTHON)
SCHEMA_DIR ?= $(shell $(PYTHON) scripts/schema_target.py)
PROJECT_VERSION := $(shell $(PYTHON) -c "import tomllib; print(tomllib.load(open('pyproject.toml','rb'))['project']['version'])")
EXPECTED_RELEASE ?= $(PROJECT_VERSION)

.PHONY: test lint type clean-dist build docs-align claim-boundary examples-parity reproduction-index-check schemas schema-force-includes schema-staging schema-check release-provenance release-bundle check release-check demo

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

release-provenance:
	$(PYTHON) scripts/check_mutation_release_provenance.py --expected-release "$(EXPECTED_RELEASE)"

release-bundle: release-provenance
	$(PYTHON) scripts/build_release_bundle.py --expected-release "$(EXPECTED_RELEASE)" --out .tmp/release --write-digests .tmp/release/release-digest-replay.json

docs-align:
	$(PYTHON) scripts/check_docs_alignment.py

claim-boundary:
	$(PYTHON) scripts/check_claim_boundaries.py

examples-parity:
	$(PYTHON) scripts/check_packaged_examples.py

reproduction-index-check:
	$(PYTHON) scripts/update_process_equivalence_reproduction_index.py

check: lint type test docs-align claim-boundary examples-parity reproduction-index-check build

release-check: check schema-check release-provenance
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
