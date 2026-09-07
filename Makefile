PYTHON ?= $(or $(wildcard .venv/Scripts/python.exe),$(wildcard .venv/bin/python),python)
SOURCE_CLI_PYTHON := $(PYTHON)
SCHEMA_DIR ?= $(shell $(PYTHON) scripts/schema_target.py)
PROJECT_VERSION := $(shell $(PYTHON) -c "import tomllib; print(tomllib.load(open('pyproject.toml','rb'))['project']['version'])")
EXPECTED_RELEASE ?= $(PROJECT_VERSION)
RUFF_FORMAT_CHECK_PATHS ?= src/agent_assure/live/config.py
EMPIRICAL_EVIDENCE_DIR ?= evidence/empirical
EMPIRICAL_STUDY_BUNDLE_ROOT ?= $(EMPIRICAL_EVIDENCE_DIR)/real-model-study
EXTERNAL_PILOT_BUNDLE_ROOT ?= $(EMPIRICAL_EVIDENCE_DIR)/external-pilot
EXTERNAL_PILOT_EVIDENCE ?= external-pilot-evidence.json
EXTERNAL_PILOT_REVIEW_RECEIPT ?= external-pilot-independence-review.json

.PHONY: test lint type clean-dist build docs-align claim-boundary examples-parity reproduction-index-check schemas schema-force-includes schema-staging schema-check release-provenance release-bundle empirical-readiness check release-check release-publish-check demo

test:
	$(PYTHON) -m pytest

# This file was formatter-clean before Sprint 7. Keep that invariant in CI
# without making routine lint depend on unrelated repository-wide format debt.
lint:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m ruff format --check $(RUFF_FORMAT_CHECK_PATHS)

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

empirical-readiness:
	$(PYTHON) scripts/check_empirical_readiness.py --study-bundle-root "$(EMPIRICAL_STUDY_BUNDLE_ROOT)" --external-pilot-bundle-root "$(EXTERNAL_PILOT_BUNDLE_ROOT)" --external-pilot-evidence "$(EXTERNAL_PILOT_EVIDENCE)" --external-pilot-review-receipt "$(EXTERNAL_PILOT_REVIEW_RECEIPT)" --benchmark "examples/process_equivalence_benchmark_v0_2/benchmark.json" --expected-release "$(EXPECTED_RELEASE)"

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

# Publishing paths use this target. Routine development CI intentionally keeps
# release-check usable before empirical artifacts exist, while candidate/tag
# creation fails closed until the v0.6.6 empirical checkpoint is met.
release-publish-check: empirical-readiness
	$(MAKE) release-check EXPECTED_RELEASE="$(EXPECTED_RELEASE)"

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
