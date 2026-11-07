"""Validate and prepare the nonauthorizing S1-successor / S2 review package.

This is development tooling, not a replacement for the authenticated S1
launcher, a signature verifier, or an acceptance authority. In particular,
``check`` success means consistent draft bytes, never permission to dispatch.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from collections.abc import Mapping, Sequence
from contextlib import ExitStack
from pathlib import Path, PurePosixPath
from typing import Any, cast

import jsonschema
import rfc8785
import yaml

from agent_assure.rooted_io import (
    RootedDirectoryDescriptor,
    claim_rooted_directory,
    open_rooted_bounded_file,
    open_rooted_directory,
)

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = "docs/governance/v1/sprint2"
MAX_JSON_BYTES = 2_097_152
MAX_ARTIFACT_BYTES = 4_194_304
MAX_DEPTH = 48
SPEC_DIGEST = "sha256:8fc2e6e6f83b6a6ac6c27492473de8690b9360eac584131b6e8b42785f4386eb"
PREDECESSOR = "db5133e09860d292047b963b0fb81b3e7385b7fa"
DECISIONS = {
    "V1-BASE-02": (
        "ADR-V1-EVIDENCE",
        "docs/adr/0017-v1-evidence-temporal-semantics.md",
        "assurance_lead",
        "telemetry_security_reviewer",
    ),
    "V1-BASE-03": (
        "ADR-V1-AUTH",
        "docs/adr/0018-v1-verifier-authorization.md",
        "release_policy_owner",
        "security_reviewer",
    ),
    "V1-BASE-04": (
        "ADR-V1-NUM-STAT",
        "docs/adr/0019-v1-numerical-statistical-contracts.md",
        "statistical_lead",
        "independent_method_reviewer",
    ),
    "V1-BASE-05": (
        "ADR-V1-IO",
        "docs/adr/0020-v1-bounded-artifact-io.md",
        "platform_lead",
        "security_reliability_reviewer",
    ),
    "V1-BASE-06": (
        "ADR-V1-RELEASE-REGISTRY",
        "docs/adr/0021-v1-release-registry-dispatch.md",
        "technical_lead",
        "security_reviewer",
    ),
    "V1-BASE-09": (
        "ADR-V1-SCHEMA",
        "docs/adr/0022-v1-schema-wire-contracts.md",
        "technical_lead",
        "repository_maintainer",
    ),
}
WORK_PACKAGES = ("BASE-06R", "BASE-06M", "BASE-06D", "BASE-06E")
REQUIRED_GATES = (
    "successor_kickoff_signature",
    "successor_trusted_host_execution",
    "successor_full_check_graph",
    "successor_hosted_ci",
    "successor_signed_closure_and_fixed_tag",
    "successor_standalone_historical_verification",
    "current_forecast_rebaseline",
    "scoped_roster_and_key_trust",
    "six_drafting_authorizations",
    "six_development_design_acceptances",
    "support_policy_acceptance",
    "product_metric_policy_acceptance",
)
CI_JOBS = (
    "test",
    "dependency-lower-bounds",
    "composite-action-smoke",
    "composite-action-strict-smoke",
    "coverage-shards",
    "coverage-gate",
    "windows-containment",
    "schema-immutability",
    "windows-governance",
    "langgraph-smoke",
    "adk-smoke",
    "otel-contract",
)
HISTORICAL_FILES = (
    "approval-roster.json",
    "maintainer-signing-key.json",
    "baseline-observations.json",
    "kickoff-authorization-v1-boot-01.json",
    "kickoff-authorization-v1-base-01.json",
    "corrective-kickoff-authorization.json",
    "delivery-forecast.json",
    "delivery-forecast.authoring-ledger.json",
    "delivery-forecast.estimation-catalog.json",
    "delivery-forecast.aggregation-registry.json",
    "completion-receipt-v1-base-01.json",
    "completion-receipt-v1-boot-01.json",
    "governance-bundle.json",
)
HISTORICAL_SHA256 = (
    "ea439f5832bec5af63d5b6be2a3d9118964671bfdb91f0fe660c485635c4a751",
    "12f6925ae7327050928861fee8ad02664b12614ef29f5e1b36d4c4783b4ae0e3",
    "5d043a1e7e9f7734c1bfe9d55b37ba1cfb3b0a6bb7a48044b795096ef2c57985",
    "b8f3cff124ff422110e94263f1fbcf448870418734c6847c1ac5c28bd9184e16",
    "c7b4e5ae96b29d1185d7a1115885e8971d070a55551fa6e992fc733f225b5f82",
    "6976180e6eb59a6d0761fc6bda62bdbdb42c73f48ff41993382e349db76c09c5",
    "1ed3756302a133d0a574806643c7bd55441c687938a0df1a82387764cdec826d",
    "93506b106041e4ae09fb8c857745bd07a76557a48b4aea7900960d5ab8681823",
    "64dfa1bd30a3da051b92bfc2a00a5581ee8e71a7aa2deaa4360670d08bd1f94d",
    "687622f6edf8bedc16d0b14a3126805cccdfcd73dd563f4f5ce445c128afd454",
    "1ea21efefcb32d615734f84d0a56b63d373bdaa829018db9523ac9d195b5770d",
    "45330151f43b1ed7d8ee993d1e5349f8577721b45d1d663b4ff6b4ec4bf3901d",
    "032f847449998ad994671f7b221a97c0c1b6ace2595c97f232faa8c524c98818",
)
SUPPLEMENTARY = (
    f"{DIRECTORY}/support-policy.json",
    f"{DIRECTORY}/wire-contract-inventory.json",
    f"{DIRECTORY}/s1-successor-protocol.json",
    f"{DIRECTORY}/occurrence-graph-expectations.json",
)
TOOLING = (
    "scripts/v1_architecture_governance.py",
    "tests/unit/governance/test_v1_architecture_governance.py",
    f"{DIRECTORY}/architecture-package.schema.json",
    f"{DIRECTORY}/support-policy.schema.json",
    f"{DIRECTORY}/s1-successor-protocol.schema.json",
    f"{DIRECTORY}/wire-contract-inventory.schema.json",
    f"{DIRECTORY}/occurrence-graph-expectations.schema.json",
    "scripts/v1_s1_successor.py",
    "scripts/v1_s1_governance.py",
    "scripts/v1_successor_host.py",
    "scripts/v1_successor_forecast.py",
    "scripts/v1_successor_io.py",
    "scripts/v1_successor_ci.py",
    "scripts/v1_successor_checks.py",
    "tests/unit/governance/test_v1_s1_successor.py",
    "tests/unit/governance/test_v1_statistical_contract_vectors.py",
    "tests/unit/governance/test_v1_successor_host.py",
    "tests/unit/governance/test_v1_successor_forecast.py",
    "tests/unit/governance/test_v1_successor_io.py",
    "tests/unit/governance/test_v1_successor_ci.py",
    "tests/unit/governance/test_v1_successor_checks.py",
    "tests/unit/governance/test_v1_successor_bootstrap.py",
    f"{DIRECTORY}/s1-successor-host.schema.json",
    f"{DIRECTORY}/delivery-forecast.schema.json",
    f"{DIRECTORY}/forecast-compatibility.md",
    f"{DIRECTORY}/host-runbook.md",
    f"{DIRECTORY}/s1-successor-acceptance.schema.json",
    "Makefile",
    ".github/workflows/ci.yml",
    "mkdocs.yml",
    f"{DIRECTORY}/README.md",
)


class ArchitectureError(ValueError):
    """An inconsistent, unsafe, or incomplete development package."""


def raw_digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def domain_digest(domain: str, value: Any) -> str:
    return raw_digest(domain.encode("ascii") + b"\x00" + rfc8785.dumps(value))


def _regular(path: Path) -> None:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise ArchitectureError("symlink/reparse paths are not admitted")


def rooted(root: Path, relative: str) -> Path:
    """Admit only exact portable relative paths, checking every ancestor."""
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise ArchitectureError("expected a nonempty POSIX relative path")
    parts = relative.split("/")
    devices = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    devices.update(f"{prefix}{i}" for prefix in ("COM", "LPT") for i in "123456789¹²³")
    if any(
        p in {"", ".", ".."}
        or p.endswith((".", " "))
        or any(ord(c) < 32 or c in '<>:"|?*' for c in p)
        or p.split(".")[0].upper() in devices
        for p in parts
    ):
        raise ArchitectureError("noncanonical relative path")
    if PurePosixPath(relative).is_absolute():
        raise ArchitectureError("absolute paths are not admitted")
    current = root.absolute()
    # Inspect the root's ancestors too; resolve() alone would conceal a link.
    for ancestor in reversed((current, *current.parents)):
        _regular(ancestor)
    for part in parts:
        current /= part
        _regular(current)
    if not current.is_file():
        raise ArchitectureError("expected a regular file")
    return current


def read_bytes(root: Path, relative: str, limit: int = MAX_ARTIFACT_BYTES) -> bytes:
    rooted(root, relative)
    absolute_root = root.absolute()
    try:
        with open_rooted_bounded_file(
            absolute_root,
            relative,
            max_bytes=limit,
            label="architecture review input",
        ) as descriptor:
            return descriptor.contents.data
    except (ValueError, OSError) as exc:
        raise ArchitectureError("bounded rooted artifact read failed") from exc


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ArchitectureError("duplicate JSON object key")
        result[key] = value
    return result


def _invalid_constant(value: str) -> Any:
    raise ArchitectureError(f"nonfinite JSON constant is forbidden: {value}")


def parse_json(payload: bytes) -> dict[str, Any]:
    if len(payload) > MAX_JSON_BYTES:
        raise ArchitectureError("JSON exceeds the byte limit")
    # Bound nesting before json.loads(), including malicious recursive inputs.
    depth = 0
    in_string = escaped = False
    for byte in payload:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                in_string = False
        elif byte == 34:
            in_string = True
        elif byte in (91, 123):
            depth += 1
            if depth > MAX_DEPTH:
                raise ArchitectureError("JSON nesting exceeds the limit")
        elif byte in (93, 125):
            depth -= 1
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_unique,
            parse_constant=_invalid_constant,
            parse_float=_invalid_constant,
        )
        rfc8785.dumps(value)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ArchitectureError("invalid bounded canonicalizable JSON") from exc
    if not isinstance(value, dict):
        raise ArchitectureError("JSON root must be an object")
    return cast(dict[str, Any], value)


def load(root: Path, relative: str) -> dict[str, Any]:
    return parse_json(read_bytes(root, relative, MAX_JSON_BYTES))


def artifact(root: Path, relative: str) -> dict[str, Any]:
    data = read_bytes(root, relative)
    return {"path": relative, "size_bytes": len(data), "sha256": raw_digest(data)}


def validate_schema(root: Path, record: dict[str, Any], name: str) -> None:
    schema = load(root, f"{DIRECTORY}/{name}.schema.json")

    # All schemas are closed, local documents; never resolve hostile URLs.
    def check_refs(value: Any) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if key in {"$ref", "$dynamicRef", "$recursiveRef"} and (
                    not isinstance(item, str) or not item.startswith("#/")
                ):
                    raise ArchitectureError("external schema references are forbidden")
                check_refs(item)
        elif isinstance(value, list):
            for item in value:
                check_refs(item)

    check_refs(schema)
    try:
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.Draft202012Validator(schema).validate(record)
    except (jsonschema.ValidationError, jsonschema.SchemaError) as exc:
        raise ArchitectureError(f"{name}: schema validation failed") from exc


def check_dag(edges: Mapping[str, Sequence[str]]) -> None:
    """Reject unknown dependencies, duplicates and directed cycles in O(V+E)."""
    remaining = {key: len(value) for key, value in edges.items()}
    consumers: dict[str, list[str]] = {key: [] for key in edges}
    for key, dependencies in edges.items():
        if len(set(dependencies)) != len(dependencies):
            raise ArchitectureError("duplicate digest dependency")
        for dependency in dependencies:
            if dependency not in edges:
                raise ArchitectureError("unknown digest dependency")
            consumers[dependency].append(key)
    ready = [key for key, count in remaining.items() if count == 0]
    visited = 0
    while ready:
        key = ready.pop()
        visited += 1
        for consumer in consumers[key]:
            remaining[consumer] -= 1
            if remaining[consumer] == 0:
                ready.append(consumer)
    if visited != len(edges):
        raise ArchitectureError("cyclic digest dependency graph")


def check_inventory(inventory: dict[str, Any]) -> None:
    if (
        inventory.get("format") != "agent-assure-v1-wire-contract-inventory/1"
        or inventory.get("status") != "proposed_for_development"
        or inventory.get("authorization_effect") != "none"
        or inventory.get("dependency_direction") != "artifact_binds_dependency"
        or inventory.get("schema_owner_work_package_id") != "SCHEMA-01D"
    ):
        raise ArchitectureError("wire inventory identity or scope differs")
    contracts = inventory.get("production_wire_schema_contract_ids")
    edges = inventory.get("contract_dependencies")
    if (
        not isinstance(contracts, list)
        or not contracts
        or not all(isinstance(item, str) and item for item in contracts)
        or len(set(contracts)) != len(contracts)
        or not isinstance(edges, dict)
        or set(edges) != set(contracts)
    ):
        raise ArchitectureError("wire inventory must enumerate each contract exactly once")
    if any(
        not isinstance(ds, list) or not all(isinstance(d, str) for d in ds) for ds in edges.values()
    ):
        raise ArchitectureError("invalid wire dependency adjacency")
    check_dag(edges)
    head = "assurance-release-head/v1"
    proof = "assurance-head-commit-proof/v1"
    if head in edges and proof in edges:
        reachable: set[str] = set()
        pending = list(edges[head])
        while pending:
            node = pending.pop()
            if node not in reachable:
                reachable.add(node)
                pending.extend(edges[node])
        if proof in reachable:
            raise ArchitectureError("post-CAS proof must not be reachable from its head")


def check_ci_instances(root: Path, expected: list[dict[str, Any]]) -> None:
    """Compare the proposed full CI inventory with the actual static workflow.

    This validates configuration only. Actual results must be authenticated at
    acceptance time; successful parsing cannot substitute for a green run.
    """

    class UniqueLoader(yaml.SafeLoader):  # type: ignore[misc]
        pass

    def mapping(loader: Any, node: Any) -> dict[str, Any]:
        loader.flatten_mapping(node)
        result: dict[str, Any] = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node)
            if key in result:
                raise ArchitectureError("duplicate CI workflow key")
            result[key] = loader.construct_object(value_node)
        return result

    UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
    try:
        workflow = yaml.load(read_bytes(root, ".github/workflows/ci.yml"), Loader=UniqueLoader)
        jobs = workflow["jobs"]
        if set(jobs) != set(CI_JOBS):
            raise ArchitectureError("CI job set differs from the successor policy")
        actual: list[dict[str, Any]] = []
        for job_id, job in jobs.items():
            matrix = job.get("strategy", {}).get("matrix", {})
            if job_id == "coverage-shards":
                if set(matrix) != {"include"}:
                    raise ArchitectureError("unsupported coverage matrix")
                for item in matrix["include"]:
                    if set(item) != {"shard", "test_paths"}:
                        raise ArchitectureError("unsupported coverage matrix row")
                    actual.append({"job_id": job_id, "matrix": {"shard": item["shard"]}})
            elif job_id in {"test", "dependency-lower-bounds", "windows-containment"}:
                if set(matrix) != {"python-version"}:
                    raise ArchitectureError("unsupported Python matrix")
                for version in matrix["python-version"]:
                    actual.append({"job_id": job_id, "matrix": {"python-version": version}})
            else:
                if matrix:
                    raise ArchitectureError("unregistered CI matrix")
                actual.append({"job_id": job_id, "matrix": {}})
        actual_keys = [rfc8785.dumps(row) for row in actual]
        expected_keys = [rfc8785.dumps(row) for row in expected]
        if len(set(actual_keys)) != len(actual_keys) or sorted(actual_keys) != sorted(
            expected_keys
        ):
            raise ArchitectureError("CI matrix instances differ from the successor policy")
    except (yaml.YAMLError, KeyError, TypeError, AttributeError) as exc:
        raise ArchitectureError("unsupported static CI workflow") from exc


def build_package(root: Path) -> dict[str, Any]:
    historical = [artifact(root, "docs/governance/v1/" + path) for path in HISTORICAL_FILES]
    for row, expected_hash in zip(historical, HISTORICAL_SHA256, strict=True):
        if row["sha256"] != "sha256:" + expected_hash:
            raise ArchitectureError("immutable S1 historical artifact changed")
    decisions = [
        {
            "ticket_id": ticket,
            "decision_id": values[0],
            "artifact": artifact(root, values[1]),
            "owner_role": values[2],
            "reviewer_role": values[3],
            "dependencies": ["V1-BOOT-01", "V1-BASE-01"],
            "start_receipt": "drafting_authorization",
            "completion_receipt": "development_design_acceptance",
            "status": "proposed_for_development",
        }
        for ticket, values in DECISIONS.items()
    ]
    projection: dict[str, Any] = {
        "format": "agent-assure-v1-architecture-package/1",
        "spec_revision": "6.5",
        "roadmap_digest": SPEC_DIGEST,
        "sprint": "S2",
        "release": "1.0.0a2",
        "maturity": "architecture-frozen-proposal",
        "artifact_kind": "governance-bundle",
        "status": "proposed_for_development",
        "authorization_effect": "none",
        "package_version": None,
        "distribution_channels": [],
        "approval_mode": "maintainer_development",
        "independent_review_claimed": False,
        "predecessor_closure_commit": PREDECESSOR,
        "decisions": decisions,
        "work_packages": list(WORK_PACKAGES),
        "supplementary_artifacts": [artifact(root, path) for path in SUPPLEMENTARY],
        "historical_artifacts": historical,
        "tooling_artifacts": [artifact(root, path) for path in TOOLING],
        "pending_gates": list(REQUIRED_GATES),
    }
    return {
        **projection,
        "package_digest": domain_digest("agent-assure:v1-architecture-package/v1", projection),
    }


def check_package(root: Path) -> dict[str, Any]:
    package = load(root, f"{DIRECTORY}/architecture-package.json")
    validate_schema(root, package, "architecture-package")
    expected = build_package(root)
    if package != expected:
        raise ArchitectureError("package does not bind the exact current decision/source bytes")
    check_supplementary(root)
    return package


def check_supplementary(root: Path) -> None:
    support = load(root, f"{DIRECTORY}/support-policy.json")
    validate_schema(root, support, "support-policy")
    protocol = load(root, f"{DIRECTORY}/s1-successor-protocol.json")
    validate_schema(root, protocol, "s1-successor-protocol")
    if protocol["predecessor_closure_commit"] != PREDECESSOR:
        raise ArchitectureError("successor protocol changed immutable predecessor")
    if protocol["required_ci_job_ids"] != list(CI_JOBS):
        raise ArchitectureError("successor protocol omits or reorders required CI jobs")
    if protocol["acceptance_tag_name"] != "agent-assure-s1-1.0.0a1-acceptance-v3":
        raise ArchitectureError("successor must use a new fixed tag")
    check_ci_instances(root, protocol["required_ci_instances"])
    check_inventory(load(root, f"{DIRECTORY}/wire-contract-inventory.json"))
    validate_schema(
        root, load(root, f"{DIRECTORY}/wire-contract-inventory.json"), "wire-contract-inventory"
    )
    validate_schema(
        root,
        load(root, f"{DIRECTORY}/occurrence-graph-expectations.json"),
        "occurrence-graph-expectations",
    )


def refresh(root: Path) -> None:
    """Refresh draft content bindings only; never change signed S1 evidence."""
    check_supplementary(root)
    package = build_package(root)
    validate_schema(root, package, "architecture-package")
    target = root / DIRECTORY / "architecture-package.json"
    if target.is_symlink() or (
        target.exists() and getattr(target.lstat(), "st_file_attributes", 0) & 0x400
    ):
        raise ArchitectureError("refusing to replace a linked package")
    # Only this explicitly draft, unsigned, fixed destination is replaceable.
    if target.exists():
        previous = load(root, f"{DIRECTORY}/architecture-package.json")
        if previous.get("status") != "proposed_for_development":
            raise ArchitectureError("refusing to overwrite a non-draft package")
    payload = (json.dumps(package, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    with open_rooted_directory(root, DIRECTORY, label="draft package parent") as parent:
        descriptor, metadata = parent.open_regular_file_exclusive_with_metadata(
            "architecture-package.json.new"
        )
        try:
            with os.fdopen(os.dup(descriptor), "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            parent.replace_regular_file(
                "architecture-package.json.new",
                "architecture-package.json",
                source_descriptor=descriptor,
                expected_device=metadata.st_dev,
                expected_inode=metadata.st_ino,
            )
        finally:
            os.close(descriptor)


def prepare_review(root: Path, output: Path) -> dict[str, Any]:
    """Freeze exact review bytes; a review acknowledgment is not acceptance."""
    package = check_package(root)
    absolute = output.absolute()
    try:
        relative = absolute.relative_to(root.absolute()).as_posix()
    except ValueError as exc:
        raise ArchitectureError("review output must stay inside the workspace .tmp") from exc
    if not relative.startswith(".tmp/") or ".." in relative.split("/"):
        raise ArchitectureError("review output must be a fresh path inside .tmp")
    ancestor = absolute.parent
    while not ancestor.exists():
        ancestor = ancestor.parent
    for path in (ancestor, *ancestor.parents):
        _regular(path)
    if absolute.exists() or absolute.is_symlink():
        raise ArchitectureError("review output already exists; use a fresh identifier")
    # Never generate signatures, signer competence, receipt acceptance or times.
    projection = {
        "format": "agent-assure-v1-development-review-request/1",
        "purpose": "review_acknowledgment_only",
        "package_digest": package["package_digest"],
        "authorization_effect": "none",
        "independent_review_claimed": False,
        "pending_gates": list(REQUIRED_GATES),
        "required_signature_namespace": "agent-assure-governance-v1",
        "signer_person_id": None,
        "accepted_competence_scopes": [],
        "signature": None,
    }
    claim = b"agent-assure:v1-development-review-request/v1\x00" + rfc8785.dumps(projection)
    # Snapshot every reviewed byte, not only hashes pointing at mutable files.
    package_path = f"{DIRECTORY}/architecture-package.json"
    package_payload = read_bytes(root, package_path)
    if parse_json(package_payload) != package:
        raise ArchitectureError("package changed before review snapshot")
    bindings: list[dict[str, Any]] = [
        {
            "path": package_path,
            "size_bytes": len(package_payload),
            "sha256": raw_digest(package_payload),
        }
    ]
    bindings += [row["artifact"] for row in package["decisions"]]
    bindings += package["supplementary_artifacts"] + package["tooling_artifacts"]
    with ExitStack() as stack:
        directories: dict[tuple[str, ...], RootedDirectoryDescriptor] = {
            (): stack.enter_context(open_rooted_directory(root, ".", label="review workspace"))
        }

        def directory(parts: tuple[str, ...]) -> RootedDirectoryDescriptor:
            if parts in directories:
                return directories[parts]
            parent = directory(parts[:-1])
            # Only the existing shared .tmp/ ancestors may be reused. Everything
            # at or below the operator-selected output is exclusively claimed.
            is_existing_ancestor = len(parts) < len(relative.split("/"))
            created_identity: tuple[int, int] | None = None
            if not is_existing_ancestor or not (root.joinpath(*parts)).exists():
                with claim_rooted_directory(parent, parts[-1], label="review output") as claimed:
                    created_identity = (claimed.device, claimed.inode)
            lease = stack.enter_context(
                open_rooted_directory(root, Path(*parts), label="review output")
            )
            # Windows mutation claims intentionally deny reopening while held.
            # Release the claim, reopen through the pinned root, and require
            # the exact created object before admitting any child mutation.
            if created_identity is not None and (lease.device, lease.inode) != created_identity:
                raise ArchitectureError("new review directory was replaced before pinning")
            directories[parts] = lease
            return lease

        output_parts = tuple(relative.split("/"))
        directory(output_parts)
        inventory: list[dict[str, Any]] = []

        def write_new(name: str, payload: bytes) -> None:
            parts = tuple(name.split("/"))
            parent = directory(output_parts + parts[:-1])
            descriptor = parent.open_regular_file_exclusive(parts[-1])
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            persisted = parent.read_file_bounded(
                parts[-1], max_bytes=MAX_ARTIFACT_BYTES, label="review snapshot read-back"
            )
            if persisted.data != payload:
                raise ArchitectureError("snapshot read-back differs from reviewed bytes")
            inventory.append(
                {"path": name, "size_bytes": len(payload), "sha256": raw_digest(payload)}
            )

        for binding in bindings:
            relative_path = binding["path"]
            payload = read_bytes(root, relative_path)
            if len(payload) != binding["size_bytes"] or raw_digest(payload) != binding["sha256"]:
                raise ArchitectureError("review snapshot differs from its package binding")
            write_new("snapshot/" + relative_path, payload)
        write_new("review-request.json", (json.dumps(projection, indent=2) + "\n").encode("utf-8"))
        write_new("review-request.claim", claim)
        result = {
            "format": "agent-assure-v1-review-snapshot/1",
            "files": sorted(inventory, key=lambda row: row["path"]),
            "claim_sha256": raw_digest(claim),
            "authorization_effect": "none",
        }
        # Completion is manifest-last, after source and per-file read-back checks.
        if check_package(root) != package:
            raise ArchitectureError("source changed during review snapshot; do not use it")
        write_new("snapshot-manifest.json", (json.dumps(result, indent=2) + "\n").encode("utf-8"))
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "refresh", "readiness", "prepare-review"))
    parser.add_argument("--repository-root", type=Path, default=ROOT)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    try:
        root = args.repository_root.absolute()
        if args.command == "refresh":
            refresh(root)
        package = check_package(root)
        if args.command == "prepare-review":
            if args.out is None:
                parser.error("prepare-review requires --out")
            prepare_review(root, args.out)
        result = {
            "result": "draft_integrity_valid",
            "authorization_effect": "none",
            "package_digest": package["package_digest"],
            "accepted": False,
            "s2_dispatch_ready": False,
            "pending_gates": list(REQUIRED_GATES),
        }
        print(json.dumps(result, sort_keys=True))
        return 1 if args.command == "readiness" else 0
    except (ArchitectureError, OSError, rfc8785.CanonicalizationError) as exc:
        print(f"v1 architecture governance error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
