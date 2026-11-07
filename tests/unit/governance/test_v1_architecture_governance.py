from __future__ import annotations

import copy
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import scripts.v1_architecture_governance as governance  # noqa: E402, I001


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def _link(link: Path, target: Path, *, directory: bool = False) -> None:
    try:
        link.symlink_to(target, target_is_directory=directory)
    except (OSError, NotImplementedError) as exc:
        if os.name == "nt":
            pytest.skip(f"native symlink privilege unavailable: {exc}")
        raise


@pytest.fixture
def package_repository(tmp_path: Path) -> Path:
    """Public contracts plus disposable sources; fixture tooling is never executed."""
    root = tmp_path / "repository"
    root.mkdir()
    directory = root / governance.DIRECTORY
    directory.mkdir(parents=True)
    for name in ("architecture-package", "support-policy", "s1-successor-protocol"):
        relative = f"{governance.DIRECTORY}/{name}.schema.json"
        (root / relative).write_bytes((ROOT / relative).read_bytes())
    for relative in governance.SUPPLEMENTARY:
        (root / relative).write_bytes((ROOT / relative).read_bytes())
    for ticket, values in governance.DECISIONS.items():
        target = root / values[1]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(f"# Synthetic {ticket}\nIdentifier: {values[0]}\n", encoding="utf-8")
    for name in governance.HISTORICAL_FILES:
        target = root / "docs/governance/v1" / name
        target.write_bytes((ROOT / "docs/governance/v1" / name).read_bytes())
    for relative in governance.TOOLING:
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if relative.endswith(".schema.json") or relative == ".github/workflows/ci.yml":
            target.write_bytes((ROOT / relative).read_bytes())
        else:
            target.write_text(f"# Synthetic immutable input: {relative}\n", encoding="utf-8")
    governance.refresh(root)
    return root


@pytest.mark.parametrize(
    "payload",
    [
        b'{"a":1,"a":2}',
        b'{"outer":{"a":1,"a":2}}',
        b'{"a":1,"\\u0061":2}',
        b'{"a":NaN}',
        b'{"a":Infinity}',
        b'{"a":-Infinity}',
        b'{"a":1e400}',
        b'{"a":1.0}',
        b'{"a":1e0}',
        b'{"a":-0.0}',
        b'{"a":0.25}',
        b'{"a":9007199254740992}',
        b'\xef\xbb\xbf{"a":1}',
        b'{"a":"\xff"}',
        b'{"a":1} trailing',
        b"[]",
        b"null",
        b"true",
    ],
)
def test_json_rejects_ambiguous_or_noncanonicalizable_values(payload: bytes) -> None:
    with pytest.raises(governance.ArchitectureError):
        governance.parse_json(payload)


def test_json_limits_are_checked_before_recursive_decoding(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = b'{"a":' + b"[" * governance.MAX_DEPTH + b"0" + b"]" * governance.MAX_DEPTH + b"}"

    def decoding_must_not_start(*args: Any, **kwargs: Any) -> None:
        pytest.fail("depth-limited input reached the JSON decoder")

    monkeypatch.setattr(governance.json, "loads", decoding_must_not_start)
    with pytest.raises(governance.ArchitectureError, match="nesting"):
        governance.parse_json(payload)
    with pytest.raises(governance.ArchitectureError, match="byte limit"):
        governance.parse_json(b" " * (governance.MAX_JSON_BYTES + 1))


def test_json_depth_scanner_does_not_count_escaped_string_delimiters() -> None:
    value = {"text": '[{\\"' * governance.MAX_DEPTH, "nested": [{"value": True}]}
    assert governance.parse_json(json.dumps(value).encode()) == value


@pytest.mark.parametrize("value", [True, False, -1, 1.5, "2", None])
def test_integer_schema_rejects_boolean_and_wrong_numeric_types(tmp_path: Path, value: Any) -> None:
    _write_json(
        tmp_path / governance.DIRECTORY / "synthetic.schema.json",
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "additionalProperties": False,
            "required": ["count"],
            "properties": {"count": {"type": "integer", "minimum": 0}},
        },
    )
    with pytest.raises(governance.ArchitectureError, match="schema validation"):
        governance.validate_schema(tmp_path, {"count": value}, "synthetic")
    governance.validate_schema(tmp_path, {"count": 2}, "synthetic")


@pytest.mark.parametrize("keyword", ["$ref", "$dynamicRef"])
def test_schema_rejects_external_references_before_constructing_validator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, keyword: str
) -> None:
    _write_json(
        tmp_path / governance.DIRECTORY / "synthetic.schema.json",
        {"type": "object", "properties": {"a": {keyword: "https://invalid.example/schema"}}},
    )

    def validator_must_not_start(*args: Any, **kwargs: Any) -> None:
        pytest.fail("an external reference reached schema validation")

    monkeypatch.setattr(
        governance.jsonschema.Draft202012Validator, "check_schema", validator_must_not_start
    )
    with pytest.raises(governance.ArchitectureError, match="external schema"):
        governance.validate_schema(tmp_path, {}, "synthetic")


def test_internal_schema_references_remain_supported(tmp_path: Path) -> None:
    _write_json(
        tmp_path / governance.DIRECTORY / "synthetic.schema.json",
        {
            "type": "object",
            "$defs": {"value": {"type": "integer"}},
            "properties": {"a": {"$ref": "#/$defs/value"}},
        },
    )
    governance.validate_schema(tmp_path, {"a": 3}, "synthetic")
    with pytest.raises(governance.ArchitectureError):
        governance.validate_schema(tmp_path, {"a": "three"}, "synthetic")


@pytest.mark.parametrize(
    "relative",
    ["", "/file", "a\\file", "C:/file", "a//file", "a/../file", "./file", "a./file", "a /file"],
)
def test_rooted_rejects_noncanonical_paths_before_filesystem_lookup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, relative: str
) -> None:
    monkeypatch.setattr(
        governance, "_regular", lambda path: pytest.fail("invalid path reached the filesystem")
    )
    with pytest.raises(governance.ArchitectureError):
        governance.rooted(tmp_path, relative)


@pytest.mark.parametrize(
    "relative",
    ["CON", "nul.txt", "COM1.log", "LPT9", "bad?name", "bad|name", 'bad"name', "bad\x01name"],
)
def test_rooted_rejects_nonportable_windows_names_without_opening_devices(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, relative: str
) -> None:
    monkeypatch.setattr(
        governance, "_regular", lambda path: pytest.fail("nonportable path reached the filesystem")
    )
    with pytest.raises(governance.ArchitectureError):
        governance.rooted(tmp_path, relative)


def test_rooted_rejects_directory_and_file_or_ancestor_symlink(tmp_path: Path) -> None:
    actual = tmp_path / "actual"
    actual.mkdir()
    (actual / "record.json").write_text("{}", encoding="utf-8")
    with pytest.raises(governance.ArchitectureError, match="regular file"):
        governance.rooted(tmp_path, "actual")
    _link(tmp_path / "record.json", actual / "record.json")
    with pytest.raises(governance.ArchitectureError, match="symlink/reparse"):
        governance.rooted(tmp_path, "record.json")
    _link(tmp_path / "linked", actual, directory=True)
    with pytest.raises(governance.ArchitectureError, match="symlink/reparse"):
        governance.rooted(tmp_path, "linked/record.json")
    with pytest.raises(governance.ArchitectureError, match="symlink/reparse"):
        governance.rooted(tmp_path / "linked", "record.json")


def test_rooted_rejects_native_reparse_metadata_without_needing_junction_privilege(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "record.json"
    target.write_text("{}", encoding="utf-8")
    original = Path.lstat

    def metadata(path: Path) -> Any:
        info = original(path)
        if path == target:
            return SimpleNamespace(st_mode=info.st_mode, st_file_attributes=0x400)
        return info

    monkeypatch.setattr(Path, "lstat", metadata)
    with pytest.raises(governance.ArchitectureError, match="symlink/reparse"):
        governance.rooted(tmp_path, "record.json")


def test_read_bytes_enforces_size_before_reading_contents(tmp_path: Path) -> None:
    (tmp_path / "record.json").write_bytes(b"x" * 21)
    with pytest.raises(governance.ArchitectureError, match="byte limit|bounded rooted"):
        governance.read_bytes(tmp_path, "record.json", 20)
    assert governance.read_bytes(tmp_path, "record.json", 21) == b"x" * 21


def test_bounded_open_rejects_a_file_swapped_to_a_symlink_after_initial_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    target = root / "record.json"
    target.write_bytes(b"legitimate")
    external = tmp_path / "external.json"
    external.write_bytes(b"external bytes must never be returned")
    original = governance.rooted

    def swap_after_check(directory: Path, relative: str) -> Path:
        admitted = original(directory, relative)
        target.unlink()
        _link(target, external)
        return admitted

    monkeypatch.setattr(governance, "rooted", swap_after_check)
    with pytest.raises((governance.ArchitectureError, OSError, ValueError)):
        governance.read_bytes(root, "record.json")


@pytest.mark.parametrize(
    "edges,reason",
    [
        ({"a": ["absent"]}, "unknown"),
        ({"a": [], "b": ["a", "a"]}, "duplicate"),
        ({"a": ["a"]}, "cyclic"),
        ({"a": ["b"], "b": ["c"], "c": ["a"]}, "cyclic"),
    ],
)
def test_digest_graph_rejects_ambiguous_or_impossible_dependencies(
    edges: dict[str, list[str]], reason: str
) -> None:
    with pytest.raises(governance.ArchitectureError, match=reason):
        governance.check_dag(edges)


def test_digest_graph_handles_deep_shared_dependencies_without_recursion() -> None:
    edges = {"root": []}
    for index in range(1500):
        edges[f"node-{index}"] = [f"node-{index - 1}"] if index else ["root"]
    edges["joined"] = ["node-1499", "root"]
    governance.check_dag(edges)


def test_wire_inventory_rejects_an_acyclic_indirect_head_to_post_cas_proof() -> None:
    head, proof = "assurance-release-head/v1", "assurance-head-commit-proof/v1"
    inventory = {
        "format": "agent-assure-v1-wire-contract-inventory/1",
        "status": "proposed_for_development",
        "authorization_effect": "none",
        "dependency_direction": "artifact_binds_dependency",
        "schema_owner_work_package_id": "SCHEMA-01D",
        "production_wire_schema_contract_ids": [head, "intermediate/v1", proof],
        "contract_dependencies": {head: ["intermediate/v1"], "intermediate/v1": [proof], proof: []},
    }
    with pytest.raises(governance.ArchitectureError, match="post-CAS proof"):
        governance.check_inventory(inventory)


def _ci_fixture(root: Path) -> tuple[Path, dict[str, Any], list[dict[str, Any]]]:
    workflow_path = root / ".github/workflows/ci.yml"
    workflow_path.parent.mkdir(parents=True)
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    protocol_path = ROOT / governance.DIRECTORY / "s1-successor-protocol.json"
    expected = json.loads(protocol_path.read_text(encoding="utf-8"))["required_ci_instances"]
    workflow_path.write_text(yaml.safe_dump({"jobs": workflow["jobs"]}), encoding="utf-8")
    return workflow_path, workflow, expected


def test_ci_inventory_requires_every_python_matrix_instance(tmp_path: Path) -> None:
    path, workflow, expected = _ci_fixture(tmp_path)
    governance.check_ci_instances(tmp_path, expected)
    versions = workflow["jobs"]["test"]["strategy"]["matrix"]["python-version"]
    versions.remove("3.11")
    path.write_text(yaml.safe_dump({"jobs": workflow["jobs"]}), encoding="utf-8")
    with pytest.raises(governance.ArchitectureError):
        governance.check_ci_instances(tmp_path, expected)


def test_ci_inventory_rejects_duplicate_job_definitions(tmp_path: Path) -> None:
    path, _, expected = _ci_fixture(tmp_path)
    with path.open("a", encoding="utf-8") as handle:
        handle.write("  test:\n    runs-on: ubuntu-latest\n    steps: []\n")
    with pytest.raises(governance.ArchitectureError):
        governance.check_ci_instances(tmp_path, expected)


def test_ci_inventory_rejects_unregistered_matrix_exclusions(tmp_path: Path) -> None:
    path, workflow, expected = _ci_fixture(tmp_path)
    workflow["jobs"]["test"]["strategy"]["matrix"]["exclude"] = [{"python-version": "3.11"}]
    path.write_text(yaml.safe_dump({"jobs": workflow["jobs"]}), encoding="utf-8")
    with pytest.raises(governance.ArchitectureError):
        governance.check_ci_instances(tmp_path, expected)


def test_ci_inventory_rejects_an_incomplete_expected_instance_list(tmp_path: Path) -> None:
    _, _, expected = _ci_fixture(tmp_path)
    missing = [
        row for row in expected if row != {"job_id": "test", "matrix": {"python-version": "3.11"}}
    ]
    assert len(missing) == len(expected) - 1
    with pytest.raises(governance.ArchitectureError):
        governance.check_ci_instances(tmp_path, missing)


@pytest.mark.parametrize(
    "group", ["decisions", "supplementary_artifacts", "historical_artifacts", "tooling_artifacts"]
)
def test_package_binds_exact_decision_supplementary_and_historic_bytes(
    package_repository: Path, group: str
) -> None:
    package = governance.check_package(package_repository)
    row = package[group][0]
    relative = row["artifact"]["path"] if group == "decisions" else row["path"]
    with (package_repository / relative).open("ab") as handle:
        handle.write(b"\n ")
    with pytest.raises(governance.ArchitectureError, match="exact current|immutable S1"):
        governance.check_package(package_repository)


def test_refresh_cannot_rebind_changed_historical_acceptance_bytes(
    package_repository: Path,
) -> None:
    target = package_repository / "docs/governance/v1" / governance.HISTORICAL_FILES[0]
    target.write_bytes(target.read_bytes() + b"\n")
    package = package_repository / governance.DIRECTORY / "architecture-package.json"
    preserved = package.read_bytes()
    with pytest.raises(governance.ArchitectureError, match="immutable S1"):
        governance.refresh(package_repository)
    assert package.read_bytes() == preserved


@pytest.mark.parametrize(
    "field,value",
    [
        ("authorization_effect", "authorize"),
        ("status", "accepted"),
        ("extra", True),
        ("signature", "forged signature"),
        ("signature_envelope", {"status": "signed", "signer_person_id": "invented"}),
    ],
)
def test_package_cannot_be_promoted_or_extended_by_editing_json(
    package_repository: Path, field: str, value: Any
) -> None:
    path = package_repository / governance.DIRECTORY / "architecture-package.json"
    package = json.loads(path.read_text(encoding="utf-8"))
    package[field] = value
    _write_json(path, package)
    with pytest.raises(governance.ArchitectureError):
        governance.check_package(package_repository)


@pytest.mark.parametrize(
    "field,value",
    [
        ("predecessor_closure_commit", "f" * 40),
        ("acceptance_tag_name", "agent-assure-s1-1.0.0a1-acceptance-v2"),
        ("required_ci_job_ids", []),
    ],
)
def test_refresh_cannot_bless_a_successor_with_weakened_immutable_prerequisites(
    package_repository: Path, field: str, value: Any
) -> None:
    path = package_repository / governance.DIRECTORY / "s1-successor-protocol.json"
    protocol = json.loads(path.read_text(encoding="utf-8"))
    protocol[field] = value
    _write_json(path, protocol)
    package = package_repository / governance.DIRECTORY / "architecture-package.json"
    preserved = package.read_bytes()
    with pytest.raises(governance.ArchitectureError):
        governance.refresh(package_repository)
    assert package.read_bytes() == preserved


def test_refresh_rejects_a_self_consistent_but_incomplete_singleton_wire_inventory(
    package_repository: Path,
) -> None:
    path = package_repository / governance.DIRECTORY / "wire-contract-inventory.json"
    inventory = json.loads(path.read_text(encoding="utf-8"))
    inventory["production_wire_schema_contract_ids"] = ["invented-singleton/v1"]
    inventory["contract_dependencies"] = {"invented-singleton/v1": []}
    _write_json(path, inventory)
    package = package_repository / governance.DIRECTORY / "architecture-package.json"
    preserved = package.read_bytes()
    with pytest.raises(governance.ArchitectureError):
        governance.refresh(package_repository)
    assert package.read_bytes() == preserved


@pytest.mark.parametrize("count", [True, 121.0, 120, "121"])
def test_refresh_rejects_typed_occurrence_count_corruption(
    package_repository: Path, count: Any
) -> None:
    path = package_repository / governance.DIRECTORY / "occurrence-graph-expectations.json"
    expectations = json.loads(path.read_text(encoding="utf-8"))
    expectations["expectations"]["node_counts_by_kind"]["ticket_start"] = count
    _write_json(path, expectations)
    package = package_repository / governance.DIRECTORY / "architecture-package.json"
    preserved = package.read_bytes()
    with pytest.raises(governance.ArchitectureError):
        governance.refresh(package_repository)
    assert package.read_bytes() == preserved


@pytest.mark.parametrize(
    "field,value",
    [
        ("signature", "invented external signature"),
        ("human_acceptance", {"decision": "accept", "person_id": "invented"}),
        ("competence_acceptance", {"scope": "release_policy", "verified": True}),
    ],
)
def test_draft_support_policy_cannot_import_unverified_acceptance_or_signatures(
    package_repository: Path, field: str, value: Any
) -> None:
    path = package_repository / governance.DIRECTORY / "support-policy.json"
    policy = json.loads(path.read_text(encoding="utf-8"))
    policy[field] = value
    _write_json(path, policy)
    package = package_repository / governance.DIRECTORY / "architecture-package.json"
    preserved = package.read_bytes()
    with pytest.raises(governance.ArchitectureError):
        governance.refresh(package_repository)
    assert package.read_bytes() == preserved


def test_rehashed_package_cannot_substitute_a_historical_artifact_binding(
    package_repository: Path,
) -> None:
    path = package_repository / governance.DIRECTORY / "architecture-package.json"
    package = json.loads(path.read_text(encoding="utf-8"))
    package["historical_artifacts"][0]["sha256"] = "sha256:" + "f" * 64
    projection = {key: value for key, value in package.items() if key != "package_digest"}
    package["package_digest"] = governance.domain_digest(
        "agent-assure:v1-architecture-package/v1", projection
    )
    _write_json(path, package)
    with pytest.raises(governance.ArchitectureError):
        governance.check_package(package_repository)


def test_draft_integrity_success_does_not_report_dispatch_or_acceptance(
    package_repository: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert governance.main(["check", "--repository-root", str(package_repository)]) == 0
    checked = json.loads(capsys.readouterr().out)
    assert checked["accepted"] is False
    assert checked["s2_dispatch_ready"] is False
    assert checked["authorization_effect"] == "none"
    assert checked["pending_gates"]
    assert governance.main(["readiness", "--repository-root", str(package_repository)]) == 1
    readiness = json.loads(capsys.readouterr().out)
    assert readiness == checked


def test_failed_check_returns_error_without_a_success_report(
    package_repository: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = package_repository / next(iter(governance.DECISIONS.values()))[1]
    path.write_bytes(b"tampered")
    assert governance.main(["check", "--repository-root", str(package_repository)]) == 2
    streams = capsys.readouterr()
    assert streams.out == ""
    assert "exact current" in streams.err


def test_refresh_refuses_to_overwrite_a_non_draft_package(package_repository: Path) -> None:
    path = package_repository / governance.DIRECTORY / "architecture-package.json"
    package = json.loads(path.read_text(encoding="utf-8"))
    package["status"] = "accepted"
    _write_json(path, package)
    preserved = path.read_bytes()
    with pytest.raises(governance.ArchitectureError, match="non-draft"):
        governance.refresh(package_repository)
    assert path.read_bytes() == preserved


def test_refresh_does_not_clobber_a_preexisting_temporary_file(package_repository: Path) -> None:
    target = package_repository / governance.DIRECTORY / "architecture-package.json"
    temporary = target.with_name(target.name + ".new")
    temporary.write_bytes(b"owned by a prior failed attempt")
    before = target.read_bytes()
    with pytest.raises(FileExistsError):
        governance.refresh(package_repository)
    assert target.read_bytes() == before
    assert temporary.read_bytes() == b"owned by a prior failed attempt"


def test_review_freezes_reviewed_bytes_without_inventing_a_signer(package_repository: Path) -> None:
    output = package_repository / ".tmp/review/fresh"
    package = governance.check_package(package_repository)
    result = governance.prepare_review(package_repository, output)
    request = json.loads((output / "review-request.json").read_text(encoding="utf-8"))
    assert request["package_digest"] == package["package_digest"]
    assert request["signer_person_id"] is None
    assert request["signature"] is None
    assert request["accepted_competence_scopes"] == []
    assert request["authorization_effect"] == "none"
    assert request["independent_review_claimed"] is False
    assert result["claim_sha256"] == governance.raw_digest(
        (output / "review-request.claim").read_bytes()
    )
    reviewed = [row["artifact"] for row in package["decisions"]]
    reviewed.extend(package["supplementary_artifacts"])
    for item in reviewed:
        copied = output / "snapshot" / item["path"]
        assert copied.read_bytes() == (package_repository / item["path"]).read_bytes()
        assert governance.raw_digest(copied.read_bytes()) == item["sha256"]
    for item in result["files"]:
        assert governance.artifact(output, item["path"]) == item


def test_review_output_is_no_clobber_and_must_stay_inside_workspace_tmp(
    package_repository: Path,
) -> None:
    output = package_repository / ".tmp/existing"
    output.mkdir(parents=True)
    (output / "sentinel").write_bytes(b"preserve")
    with pytest.raises(governance.ArchitectureError, match="already exists"):
        governance.prepare_review(package_repository, output)
    assert (output / "sentinel").read_bytes() == b"preserve"
    for invalid in (package_repository / "review", package_repository.parent / "outside"):
        with pytest.raises(governance.ArchitectureError, match="workspace .tmp|inside .tmp"):
            governance.prepare_review(package_repository, invalid)
        assert not invalid.exists()


def test_review_rejects_a_linked_output_ancestor(package_repository: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    temporary = package_repository / ".tmp"
    temporary.mkdir()
    _link(temporary / "linked", outside, directory=True)
    with pytest.raises(governance.ArchitectureError, match="symlink/reparse"):
        governance.prepare_review(package_repository, temporary / "linked/review")
    assert list(outside.iterdir()) == []


def test_review_rejects_a_real_directory_replaced_between_claim_and_lease(
    package_repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = package_repository / ".tmp/fresh-output"
    output.parent.mkdir()
    moved = output.with_name("original-claimed-directory")
    original = governance.open_rooted_directory
    replacements = 0

    def replace_before_lease(root: Path, relative: str | Path, *args: Any, **kwargs: Any) -> Any:
        nonlocal replacements
        if root == package_repository and Path(relative).parts == (".tmp", "fresh-output"):
            assert replacements == 0
            original_identity = (output.stat().st_dev, output.stat().st_ino)
            output.rename(moved)
            output.mkdir()
            assert (output.stat().st_dev, output.stat().st_ino) != original_identity
            replacements += 1
        return original(root, relative, *args, **kwargs)

    monkeypatch.setattr(governance, "open_rooted_directory", replace_before_lease)
    with pytest.raises(governance.ArchitectureError, match="replaced before pinning"):
        governance.prepare_review(package_repository, output)
    assert replacements == 1
    assert list(output.iterdir()) == []
    assert list(moved.iterdir()) == []
    assert not (output / "snapshot-manifest.json").exists()
    assert not (moved / "snapshot-manifest.json").exists()


def test_review_detects_copy_time_edit_even_if_source_is_restored(
    package_repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    relative = next(iter(governance.DECISIONS.values()))[1]
    original = governance.read_bytes
    reads = 0

    def read_with_transient_change(root: Path, path: str, *args: Any, **kwargs: Any) -> bytes:
        nonlocal reads
        actual = original(root, path, *args, **kwargs)
        if root == package_repository and path == relative:
            reads += 1
            if reads == 2:
                return b"transient attacker-controlled review bytes\n"
        return actual

    monkeypatch.setattr(governance, "read_bytes", read_with_transient_change)
    output = package_repository / ".tmp/transient"
    with pytest.raises(governance.ArchitectureError, match="snapshot|bind|changed"):
        governance.prepare_review(package_repository, output)
    assert not (output / "snapshot-manifest.json").exists()


def test_review_detects_a_source_change_that_persists_through_final_check(
    package_repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    relative = next(iter(governance.DECISIONS.values()))[1]
    original = governance.read_bytes
    reads = 0

    def change_after_copy(root: Path, path: str, *args: Any, **kwargs: Any) -> bytes:
        nonlocal reads
        actual = original(root, path, *args, **kwargs)
        if root == package_repository and path == relative:
            reads += 1
            if reads == 2:
                (root / path).write_bytes(b"a concurrent persistent change\n")
        return actual

    monkeypatch.setattr(governance, "read_bytes", change_after_copy)
    output = package_repository / ".tmp/persistent"
    with pytest.raises(governance.ArchitectureError, match="snapshot|bind|changed|exact current"):
        governance.prepare_review(package_repository, output)
    assert not (output / "snapshot-manifest.json").exists()


def test_domain_separation_prevents_cross_kind_digest_reuse() -> None:
    source = {"decision": "pending", "authorization_effect": "none"}
    assert governance.domain_digest("review/v1", source) != governance.domain_digest(
        "receipt/v1", source
    )
    assert governance.domain_digest("review/v1", source) == governance.domain_digest(
        "review/v1", copy.deepcopy(source)
    )
