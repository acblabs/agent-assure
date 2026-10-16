PYTHON ?= $(or $(wildcard .venv/Scripts/python.exe),$(wildcard .venv/bin/python),python)
SOURCE_CLI_PYTHON := $(PYTHON)
SCHEMA_DIR ?= $(shell $(PYTHON) scripts/schema_target.py)
PROJECT_VERSION := $(shell $(PYTHON) -c "import tomllib; print(tomllib.load(open('pyproject.toml','rb'))['project']['version'])")
EXPECTED_RELEASE ?= $(PROJECT_VERSION)
RUFF_FORMAT_CHECK_PATHS ?= .
EMPIRICAL_EVIDENCE_DIR ?= evidence/empirical
EMPIRICAL_STUDY_BUNDLE_ROOT ?= $(EMPIRICAL_EVIDENCE_DIR)/real-model-study
EXTERNAL_PILOT_BUNDLE_ROOT ?= $(EMPIRICAL_EVIDENCE_DIR)/external-pilot
EXTERNAL_PILOT_EVIDENCE ?= external-pilot-evidence.json
EXTERNAL_PILOT_REVIEW_RECEIPT ?= external-pilot-independence-review.json
RELEASE_EFFICACY_PACKET ?= evidence/synthetic/release-control-efficacy/evidence-packet.json
RELEASE_EFFICACY_POLICY ?= evidence/synthetic/release-control-efficacy/controls-mutation.yaml
RELEASE_EFFICACY_ARTIFACT_ROOT ?= .
V1_ROADMAP ?= Agent_Assure_Implementation_Roadmap.md
V1_GOVERNANCE_DIR ?= docs/governance/v1
V1_GOVERNANCE_POWERSHELL ?= C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe
V1_GOVERNANCE_LAUNCHER ?= $(abspath scripts/v1_s1_governance.ps1)
V1_GOVERNANCE_COMMITMENT_TIME ?=
V1_GOVERNANCE_CLOSURE_COMMIT ?=
V1_GOVERNANCE_ACCEPTANCE_TAG_OBJECT ?=
V1_GOVERNANCE_ACCEPTANCE_GENERATION ?= 2
V1_GOVERNANCE_PENDING_TIME_ARG = $(if $(filter 1,$(V1_GOVERNANCE_ACCEPTANCE_GENERATION)),--commitment-time "$(V1_GOVERNANCE_COMMITMENT_TIME)")

.PHONY: test lint type dependency-lock-freshness clean-dist build docs-align claim-boundary examples-parity reproduction-index-check schemas schema-force-includes schema-staging schema-check release-provenance release-bundle release-claim-profile-check release-control-efficacy-regenerate release-control-efficacy-check empirical-readiness check release-check release-publish-check demo v1-governance-check v1-governance-check-nonaccepting

test:
	$(PYTHON) -m pytest

lint:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m ruff format --check $(RUFF_FORMAT_CHECK_PATHS)

type:
	$(PYTHON) -m mypy src scripts

dependency-lock-freshness:
	$(PYTHON) scripts/check_dependency_lock_freshness.py

clean-dist:
	$(PYTHON) scripts/clean_dist.py

build: clean-dist
	$(PYTHON) -m build --no-isolation

release-provenance:
	$(PYTHON) scripts/check_mutation_release_provenance.py --expected-release "$(EXPECTED_RELEASE)"

release-bundle: release-provenance
	$(PYTHON) scripts/build_release_bundle.py --expected-release "$(EXPECTED_RELEASE)" --out .tmp/release --write-digests .tmp/release/release-digest-replay.json

release-claim-profile-check:
	$(PYTHON) scripts/check_release_claim_profile.py --expected-release "$(EXPECTED_RELEASE)"

release-control-efficacy-regenerate:
	$(PYTHON) scripts/regenerate_release_control_efficacy.py --expected-release "$(EXPECTED_RELEASE)" --replace-generated

release-control-efficacy-check:
	$(SOURCE_CLI_PYTHON) scripts/run_source_cli.py ci gate "$(RELEASE_EFFICACY_PACKET)" --artifact-root "$(RELEASE_EFFICACY_ARTIFACT_ROOT)" --release-profile --efficacy-policy "$(RELEASE_EFFICACY_POLICY)"

empirical-readiness:
	$(PYTHON) scripts/check_empirical_readiness.py --study-bundle-root "$(EMPIRICAL_STUDY_BUNDLE_ROOT)" --external-pilot-bundle-root "$(EXTERNAL_PILOT_BUNDLE_ROOT)" --external-pilot-evidence "$(EXTERNAL_PILOT_EVIDENCE)" --external-pilot-review-receipt "$(EXTERNAL_PILOT_REVIEW_RECEIPT)" --benchmark "study/registration/frozen-non-grid-benchmark.json" --expected-release "$(EXPECTED_RELEASE)"

docs-align:
	$(PYTHON) scripts/check_docs_alignment.py

claim-boundary:
	$(PYTHON) scripts/check_claim_boundaries.py

examples-parity:
	$(PYTHON) scripts/check_packaged_examples.py

reproduction-index-check:
	$(PYTHON) scripts/update_process_equivalence_reproduction_index.py

check: lint type dependency-lock-freshness test docs-align claim-boundary examples-parity reproduction-index-check build

release-check: check schema-check release-provenance
	$(PYTHON) -m twine check dist/*
	$(PYTHON) scripts/check_wheel_contents.py
	$(PYTHON) scripts/smoke_install_wheel.py

# Publishing paths use this single ordered, version-bound target. Empirical
# readiness remains an independent claim-qualification check and is not part of
# the bounded v0.7.0 software-distribution profile.
release-publish-check:
	$(MAKE) release-claim-profile-check EXPECTED_RELEASE="$(EXPECTED_RELEASE)"
	$(MAKE) release-control-efficacy-check
	$(MAKE) release-check EXPECTED_RELEASE="$(EXPECTED_RELEASE)"

demo:
	$(SOURCE_CLI_PYTHON) scripts/run_source_cli.py demo flagship --out .tmp/demo/flagship --clean

# The roadmap is intentionally local-only, so these explicit targets are not
# part of CI's default check graph. The default performs generation-aware,
# durable historical validation of the signed closure. For generation 2, invoke
# it from a clean standalone `clone --no-local --no-checkout` at C2 only after
# the artifact-hash and frozen-runtime inventory preflights; this convenience
# target is not itself a trust root.
# The nonaccepting target validates a self-consistent draft or in-progress
# record set. Generation 1 requires its caller-supplied trusted time;
# generation 2 accepts no caller-supplied event time.
v1-governance-check:
	"$(V1_GOVERNANCE_POWERSHELL)" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$(V1_GOVERNANCE_LAUNCHER)" check --roadmap "$(V1_ROADMAP)" --governance-dir "$(V1_GOVERNANCE_DIR)" --repository-root . --historical --closure-commit "$(V1_GOVERNANCE_CLOSURE_COMMIT)" --acceptance-tag-object "$(V1_GOVERNANCE_ACCEPTANCE_TAG_OBJECT)"

v1-governance-check-nonaccepting:
	"$(V1_GOVERNANCE_POWERSHELL)" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$(V1_GOVERNANCE_LAUNCHER)" check --roadmap "$(V1_ROADMAP)" --governance-dir "$(V1_GOVERNANCE_DIR)" --repository-root . --allow-pending --acceptance-generation "$(V1_GOVERNANCE_ACCEPTANCE_GENERATION)" $(V1_GOVERNANCE_PENDING_TIME_ARG)

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
