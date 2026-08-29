from __future__ import annotations

import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from agent_assure.mutation import catalog
from agent_assure.mutation.campaign import build_core_catalog
from agent_assure.mutation.catalog import (
    CatalogIntegrityError,
    built_in_evaluator_implementation_components,
    implementation_component_sha256,
    lf_normalized_sha256,
    registered_operators,
)
from agent_assure.schema.mutation import mutation_implementation_digest
from agent_assure.schema.validation import FROZEN_SCHEMA_VERSIONS

_ROOT = Path(__file__).resolve().parents[3]
_SOURCE_ROOT = _ROOT / "src"
_EXPECTED_FROZEN_RUNSET_SCHEMA_PATHS = tuple(
    f"schemas/v{version}/run-set.schema.json" for version in sorted(FROZEN_SCHEMA_VERSIONS)
)
_EXPECTED_FROZEN_SCHEMA_DIR_NAMES = frozenset(f"v{version}" for version in FROZEN_SCHEMA_VERSIONS)
_CONTROL_FIRST_SEEN_COMMIT = "git:441fc73793fd9154a2830613dfe2a521ca3eeaa1"
_RUNSET_COMPLETION_FIRST_SEEN_COMMIT = "git:cdb7d2e0647bfbd86c558bbc5e6b74c15722185e"
_TARGETS = {
    "bypass-required-human-review": (
        "human_review_required",
        "agent_assure/policies/human_review.py",
        "5bf534408536881aacc96be591ae67ca22121a2de3626a632c899b32e2e15d9e",
        _CONTROL_FIRST_SEEN_COMMIT,
    ),
    "drop-material-evidence-link": (
        "material_claims_have_evidence",
        "agent_assure/policies/evidence.py",
        "ab793747a5f3744c42c95cb43f12d67880988e2696cbc57f12d4f703311d7e99",
        _CONTROL_FIRST_SEEN_COMMIT,
    ),
    "inject-forbidden-tool": (
        "tool_allowlist",
        "agent_assure/policies/tools.py",
        "36a3f9b02bf2262d2847e69ebe8e5c518a6c315359dd13c9382afcc9c4004e5e",
        _CONTROL_FIRST_SEEN_COMMIT,
    ),
    "inject-synthetic-sensitive-summary": (
        "redaction_required",
        "agent_assure/policies/privacy.py",
        "8a522291e65a5c96aad8ea4a1d4dadf6e1779a9c9140f824493a5449ea407a1f",
        _CONTROL_FIRST_SEEN_COMMIT,
    ),
    "mark-incomplete-budget-stop": (
        "runset_completion_required",
        "agent_assure/evaluation/invariants.py",
        "9fe68e183e5d23885086f6c5fb8962f1d3b4d19a051d727b78e13d81f11ee42c",
        _RUNSET_COMPLETION_FIRST_SEEN_COMMIT,
    ),
    "replay-duplicate-case-observation": (
        "valid_record_required",
        "agent_assure/evaluation/invariants.py",
        "9fe68e183e5d23885086f6c5fb8962f1d3b4d19a051d727b78e13d81f11ee42c",
        _CONTROL_FIRST_SEEN_COMMIT,
    ),
    "skew-evidence-source-identity": (
        "evidence_provenance_identity",
        "agent_assure/policies/evidence.py",
        "95ee56977546a4755d1d17e566f090c4e8ba88990f6002661d82e5b540b8f29e",
        "git:820621d1e42862cfa4356468b4de24d0138165c3",
    ),
}
_IDENTITY_CRITICAL_PATHS = (
    "agent_assure/__init__.py",
    "agent_assure/canonical/__init__.py",
    "agent_assure/evaluation/__init__.py",
    "agent_assure/fixtures/__init__.py",
    "agent_assure/mutation/catalog.py",
    "agent_assure/mutation/__init__.py",
    "agent_assure/mutation/detection.py",
    "agent_assure/mutation/execution.py",
    "agent_assure/mutation/introduction_snapshots.json",
    "agent_assure/mutation/operators.py",
    "agent_assure/schema/mutation.py",
    "agent_assure/schema/validation.py",
    "agent_assure/evaluation/evaluator.py",
    "agent_assure/evaluation/expectations.py",
    "agent_assure/evaluation/invariants.py",
    "agent_assure/fixtures/loader.py",
    "agent_assure/policies/base.py",
    "agent_assure/policies/catalog.py",
    "agent_assure/policies/evidence.py",
    "agent_assure/policies/human_review.py",
    "agent_assure/policies/injection.py",
    "agent_assure/policies/output_schema.py",
    "agent_assure/policies/privacy.py",
    "agent_assure/policies/providers.py",
    "agent_assure/policies/review_boundary.py",
    "agent_assure/policies/runtime.py",
    "agent_assure/policies/tools.py",
    "agent_assure/policies/__init__.py",
    "agent_assure/privacy/__init__.py",
    "agent_assure/runner/__init__.py",
    "agent_assure/runner/ids.py",
    "agent_assure/schema/__init__.py",
    "agent_assure/schema/expectation.py",
    "agent_assure/schema/usage.py",
    "agent_assure/usage/aggregation.py",
    "agent_assure/usage/__init__.py",
    "schemas/v0.5.0/run-set.schema.json",
    "schemas/v0.6.0/run-set.schema.json",
    "schemas/v0.6.1/run-set.schema.json",
)


def test_component_manifest_binds_dispatch_schema_evaluation_and_controls() -> None:
    operators = registered_operators()

    assert tuple(item.descriptor.operator_id for item in operators) == tuple(sorted(_TARGETS))
    manifests = {
        tuple(
            (component.component_id, component.relative_path, component.sha256)
            for component in item.descriptor.provenance.implementation_components
        )
        for item in operators
    }
    assert len(manifests) == 1
    manifest = next(iter(manifests))
    paths = {relative_path for _, relative_path, _ in manifest}
    assert set(_IDENTITY_CRITICAL_PATHS) <= paths


def test_evaluator_manifest_is_shared_and_covers_every_evaluator_policy() -> None:
    evaluator_paths = {
        component.relative_path for component in built_in_evaluator_implementation_components()
    }
    operator_paths = {
        component.relative_path
        for component in registered_operators()[0].descriptor.provenance.implementation_components
    }
    policy_paths = {
        path.relative_to(_SOURCE_ROOT).as_posix()
        for path in (_SOURCE_ROOT / "agent_assure" / "policies").glob("*.py")
        if path.name != "__init__.py"
    }
    packaged_python_paths = {
        path.relative_to(_SOURCE_ROOT).as_posix()
        for path in (_SOURCE_ROOT / "agent_assure").rglob("*.py")
    }
    frozen_runset_schemas = {
        path.relative_to(_ROOT).as_posix()
        for path in (_ROOT / "schemas").glob("v*/run-set.schema.json")
        if path.parent.name in _EXPECTED_FROZEN_SCHEMA_DIR_NAMES
    }

    assert evaluator_paths <= operator_paths
    assert packaged_python_paths <= evaluator_paths
    assert frozen_runset_schemas == set(_EXPECTED_FROZEN_RUNSET_SCHEMA_PATHS)
    assert frozen_runset_schemas <= evaluator_paths
    assert policy_paths <= evaluator_paths
    assert {
        "agent_assure/evaluation/expectations.py",
        "agent_assure/fixtures/loader.py",
        "agent_assure/runner/ids.py",
        "agent_assure/usage/aggregation.py",
        "agent_assure/mutation/introduction_snapshots.json",
    } <= evaluator_paths


def test_catalog_frozen_runset_schema_paths_match_validator_versions() -> None:
    assert catalog._FROZEN_RUNSET_SCHEMA_PATHS == _EXPECTED_FROZEN_RUNSET_SCHEMA_PATHS
    assert "schemas/v0.6.1/run-set.schema.json" in catalog._FROZEN_RUNSET_SCHEMA_PATHS
    assert "schemas/v0.6.2/run-set.schema.json" in catalog._FROZEN_RUNSET_SCHEMA_PATHS
    assert "schemas/v0.6.3/run-set.schema.json" in catalog._FROZEN_RUNSET_SCHEMA_PATHS
    assert "schemas/v0.6.4/run-set.schema.json" in catalog._FROZEN_RUNSET_SCHEMA_PATHS


def test_core_operators_declare_current_and_frozen_v06_compatibility() -> None:
    assert {
        operator.descriptor.compatible_schema_versions for operator in registered_operators()
    } == {("0.5.0", "0.6.0", "0.6.1", "0.6.2", "0.6.3", "0.6.4", "0.6.5")}


def test_component_digests_are_lf_normalized_current_source_digests() -> None:
    components = registered_operators()[0].descriptor.provenance.implementation_components

    for component in components:
        source_path = (
            _SOURCE_ROOT / component.relative_path
            if component.relative_path.startswith("agent_assure/")
            else _ROOT / component.relative_path
        )
        source = source_path.read_bytes()
        expected = implementation_component_sha256(component.relative_path, source)
        assert component.sha256 == expected, component.relative_path


def test_target_control_provenance_uses_authored_creation_snapshot() -> None:
    for registered in registered_operators():
        descriptor = registered.descriptor
        control_id, _, creation_digest, first_seen_commit = _TARGETS[descriptor.operator_id]

        assert len(descriptor.provenance.target_controls) == 1
        target = descriptor.provenance.target_controls[0]
        assert target.control_id == control_id
        assert target.first_seen_commit == first_seen_commit
        assert target.digest_at_operator_creation == creation_digest


def test_introduction_snapshot_is_authored_and_stable() -> None:
    snapshots = {
        item.descriptor.operator_id: tuple(
            (component.component_id, component.relative_path, component.sha256)
            for component in item.descriptor.provenance.introduction_components
        )
        for item in registered_operators()
    }

    historical_snapshot = (
        (
            "mutation.catalog",
            "agent_assure/mutation/catalog.py",
            "1187ce27fab137cd0b18b82b456cebe23186b160d916113c2a6dd27c4d9bf915",
        ),
        (
            "mutation.operators",
            "agent_assure/mutation/operators.py",
            "7e5d514056ec31ff4614dd8324fe6152ccc288ec664339a83c6f3f35397ac4b7",
        ),
    )
    current_snapshot = (
        (
            "mutation.catalog",
            "agent_assure/mutation/catalog.py",
            "5c738052914b77caf32978830692008cccda014c5db5ab4d92ee24805611a050",
        ),
        (
            "mutation.operators",
            "agent_assure/mutation/operators.py",
            "510c51beb9ca455eb7e61338755c4c641c6560ba88b6c5a5fe48db6f1447a2e3",
        ),
    )

    assert set(snapshots) == set(_TARGETS)
    assert {
        snapshots[operator_id]
        for operator_id in (
            "bypass-required-human-review",
            "drop-material-evidence-link",
            "inject-forbidden-tool",
        )
    } == {historical_snapshot}
    assert {
        snapshots[operator_id]
        for operator_id in (
            "inject-synthetic-sensitive-summary",
            "mark-incomplete-budget-stop",
            "replay-duplicate-case-observation",
            "skew-evidence-source-identity",
        )
    } == {current_snapshot}


def test_core_catalog_metadata_is_stable_canonical_and_cross_domain() -> None:
    operators = registered_operators()

    assert len(operators) == 7
    assert all(item.stable for item in operators)
    assert {item.descriptor.operator_id: item.invariant_family for item in operators} == {
        "bypass-required-human-review": "human-review-routing",
        "drop-material-evidence-link": "material-evidence-linkage",
        "inject-forbidden-tool": "tool-boundary",
        "inject-synthetic-sensitive-summary": "privacy-redaction",
        "mark-incomplete-budget-stop": "runset-completion-integrity",
        "replay-duplicate-case-observation": "stream-replay-integrity",
        "skew-evidence-source-identity": "provenance-corpus-identity",
    }
    assert all(item.invariant_family != "unclassified" for item in operators)
    assert all(item.threat_source_references for item in operators)
    assert all(
        item.threat_source_references == tuple(sorted(set(item.threat_source_references)))
        for item in operators
    )
    assert (
        next(
            item
            for item in operators
            if item.descriptor.operator_id == "inject-synthetic-sensitive-summary"
        ).descriptor.privacy_classification.value
        == "synthetic_fixture_sensitive_marker"
    )


def test_sprint_two_operator_introduction_provenance_is_stamped() -> None:
    sprint_two_ids = {
        "inject-synthetic-sensitive-summary",
        "mark-incomplete-budget-stop",
        "replay-duplicate-case-observation",
        "skew-evidence-source-identity",
    }

    for item in registered_operators():
        if item.descriptor.operator_id not in sprint_two_ids:
            continue
        assert item.descriptor.provenance.introduced_at_commit == (
            "git:820621d1e42862cfa4356468b4de24d0138165c3"
        )
        assert item.descriptor.provenance.introduced_in_release == "0.6.1rc1"


def test_introduction_snapshot_rejects_duplicate_json_keys() -> None:
    source = b'{"drop-material-evidence-link": [], "drop-material-evidence-link": []}'

    with pytest.raises(CatalogIntegrityError, match="duplicate key"):
        catalog.introduction_components_from_source(
            "drop-material-evidence-link",
            source,
        )


def test_creation_digest_does_not_follow_live_component_manifest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = registered_operators()
    original_creation_digests = {
        item.descriptor.operator_id: (
            item.descriptor.provenance.target_controls[0].digest_at_operator_creation
        )
        for item in original
    }
    original_introduction_snapshots = {
        item.descriptor.operator_id: item.descriptor.provenance.introduction_components
        for item in original
    }
    changed_components = tuple(
        component.model_copy(update={"sha256": "0" * 64})
        if component.relative_path == "agent_assure/policies/evidence.py"
        else component
        for component in original[0].descriptor.provenance.implementation_components
    )

    catalog._operator_catalog.cache_clear()
    try:
        with monkeypatch.context() as context:
            context.setattr(catalog, "_implementation_components", lambda: changed_components)
            rebuilt = registered_operators()
            assert {
                item.descriptor.operator_id: (
                    item.descriptor.provenance.target_controls[0].digest_at_operator_creation
                )
                for item in rebuilt
            } == original_creation_digests
            assert {
                item.descriptor.operator_id: item.descriptor.provenance.introduction_components
                for item in rebuilt
            } == original_introduction_snapshots
            assert (
                rebuilt[0].descriptor.implementation_digest
                != original[0].descriptor.implementation_digest
            )
    finally:
        catalog._operator_catalog.cache_clear()


def test_lf_normalized_digest_is_invariant_across_line_endings() -> None:
    canonical = b"alpha\nbeta\ngamma\n"

    assert lf_normalized_sha256(canonical) == lf_normalized_sha256(b"alpha\r\nbeta\r\ngamma\r\n")
    assert lf_normalized_sha256(canonical) == lf_normalized_sha256(b"alpha\r\nbeta\ngamma\r")


def test_catalog_component_identity_normalizes_only_introduction_stamp() -> None:
    path = "agent_assure/mutation/catalog.py"
    unstamped = b'introduced_at_commit="git:uncommitted"\noperator_version = "1.0.0"\n'
    stamped = unstamped.replace(b"git:uncommitted", b"git:" + b"a" * 40)
    changed_method = stamped.replace(b'operator_version = "1.0.0"', b'operator_version = "1.0.1"')

    assert implementation_component_sha256(path, unstamped) == (
        implementation_component_sha256(path, stamped)
    )
    assert implementation_component_sha256(path, changed_method) != (
        implementation_component_sha256(path, stamped)
    )


def test_catalog_component_identity_normalizes_only_first_seen_mapping_values() -> None:
    path = "agent_assure/mutation/catalog.py"
    unstamped_block = (
        b"_CONTROL_FIRST_SEEN_COMMITS = {\n"
        b'    "evidence_provenance_identity": "git:uncommitted",\n'
        b'    "historical-control": "git:' + b"d" * 40 + b'",\n'
        b"}\n"
    )
    stamped_block = unstamped_block.replace(
        b"git:uncommitted",
        b"git:" + b"a" * 40,
    )
    outside_block = b'_OTHER_COMMITS = {\n    "control-a": "git:' + b"b" * 40 + b'",\n}\n'
    method = b'operator_version = "1.0.0"\n'
    unstamped = unstamped_block + outside_block + method
    stamped = stamped_block + outside_block + method

    assert implementation_component_sha256(path, unstamped) == (
        implementation_component_sha256(path, stamped)
    )

    changed_control_id = stamped.replace(
        b'"evidence_provenance_identity":',
        b'"different-control":',
        1,
    )
    assert implementation_component_sha256(path, changed_control_id) != (
        implementation_component_sha256(path, stamped)
    )

    changed_historical_revision = stamped.replace(
        b"git:" + b"d" * 40,
        b"git:" + b"e" * 40,
    )
    assert implementation_component_sha256(path, changed_historical_revision) != (
        implementation_component_sha256(path, stamped)
    )

    changed_outside_revision = stamped.replace(
        b"git:" + b"b" * 40,
        b"git:" + b"c" * 40,
    )
    assert implementation_component_sha256(path, changed_outside_revision) != (
        implementation_component_sha256(path, stamped)
    )

    changed_method = stamped.replace(
        b'operator_version = "1.0.0"',
        b'operator_version = "1.0.1"',
    )
    assert implementation_component_sha256(path, changed_method) != (
        implementation_component_sha256(path, stamped)
    )


def test_catalog_integrity_failure_is_typed_and_lazy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unreadable_component(_path: str) -> bytes:
        raise OSError("unreadable")

    catalog._operator_catalog.cache_clear()
    try:
        with monkeypatch.context() as context:
            context.setattr(
                catalog,
                "_read_packaged_component",
                unreadable_component,
            )
            with pytest.raises(CatalogIntegrityError, match="implementation component"):
                registered_operators()
    finally:
        catalog._operator_catalog.cache_clear()


def test_cli_import_does_not_construct_catalog() -> None:
    code = """
from agent_assure.mutation import catalog

def reject_catalog_construction():
    raise AssertionError("catalog constructed during CLI import")

catalog._implementation_components = reject_catalog_construction
from agent_assure.cli.main import app
assert app is not None
"""
    completed = subprocess.run(
        [sys.executable, "-c", code],
        cwd=_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr


def test_catalog_constructs_from_direct_zip_import(tmp_path: Path) -> None:
    expected_catalog_digest = build_core_catalog().catalog_digest
    archive = tmp_path / "agent_assure_direct_import.whl"
    package_root = _SOURCE_ROOT / "agent_assure"
    with zipfile.ZipFile(archive, "w") as wheel:
        for source in sorted(package_root.rglob("*.py")):
            wheel.write(source, source.relative_to(_SOURCE_ROOT).as_posix())
        introduction_snapshot = package_root / "mutation" / "introduction_snapshots.json"
        wheel.write(
            introduction_snapshot,
            introduction_snapshot.relative_to(_SOURCE_ROOT).as_posix(),
        )
        for schema_path in sorted(
            path
            for path in (_ROOT / "schemas").glob("v*/run-set.schema.json")
            if path.parent.name in _EXPECTED_FROZEN_SCHEMA_DIR_NAMES
        ):
            wheel.write(
                schema_path,
                (f"agent_assure/schema_resources/{schema_path.parent.name}/{schema_path.name}"),
            )
    code = f"""
import sys
sys.path.insert(0, {str(archive)!r})
import agent_assure
from agent_assure.mutation.catalog import registered_operators
from agent_assure.mutation.campaign import build_core_catalog
from agent_assure.schema.campaign import (
    AssuranceMutationCampaign,
    AssuranceMutationCatalog,
)
assert '.whl' in agent_assure.__file__
operators = registered_operators()
assert len(operators) == 7
catalog = build_core_catalog(operators)
assert catalog.catalog_id == 'core/v1'
assert len(catalog.operators) == 7
assert catalog.catalog_digest == {expected_catalog_digest!r}
assert AssuranceMutationCatalog.model_fields['artifact_kind'].default == (
    'assurance-mutation-catalog'
)
assert AssuranceMutationCampaign.model_fields['artifact_kind'].default == (
    'assurance-mutation-campaign'
)
"""
    completed = subprocess.run(
        [sys.executable, "-c", code],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr


def test_implementation_digest_replays_from_persisted_component_manifest() -> None:
    for registered in registered_operators():
        descriptor = registered.descriptor
        expected = mutation_implementation_digest(
            operator_id=descriptor.operator_id,
            operator_version=descriptor.operator_version,
            components=descriptor.provenance.implementation_components,
        )

        assert descriptor.implementation_digest == expected
        assert descriptor.provenance.implementation_digest == expected


@pytest.mark.parametrize("relative_path", _IDENTITY_CRITICAL_PATHS)
def test_identity_critical_source_digest_change_changes_method_identity(
    relative_path: str,
) -> None:
    descriptor = registered_operators()[0].descriptor
    components = descriptor.provenance.implementation_components
    assert any(component.relative_path == relative_path for component in components)
    changed_components = tuple(
        component.model_copy(
            update={"sha256": ("0" * 64 if component.sha256 != "0" * 64 else "1" * 64)}
        )
        if component.relative_path == relative_path
        else component
        for component in components
    )

    changed_digest = mutation_implementation_digest(
        operator_id=descriptor.operator_id,
        operator_version=descriptor.operator_version,
        components=changed_components,
    )

    assert changed_digest != descriptor.implementation_digest
