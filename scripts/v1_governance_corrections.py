"""Prepare and inspect additive S1/S2 corrections without creating authority.

The original v3 package remains immutable. Public source checks validate a new
draft binding, never acceptance. Private review snapshots contain exact claims
for a separately authenticated verifier; this program never loads a private key.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import sys
from collections.abc import Mapping, Sequence
from contextlib import ExitStack
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import jsonschema

from agent_assure.rooted_io import (
    RootedDirectoryDescriptor,
    claim_rooted_directory,
    open_rooted_directory,
)
from scripts import v1_architecture_governance as architecture
from scripts import v1_correction_acceptance as acceptance
from scripts import v1_successor_forecast as forecast

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = "docs/governance/v1/sprint2"
SOURCE_BINDINGS = f"{DIRECTORY}/correction-source-bindings.json"
PREDECESSOR_PACKAGE_DIGEST = (
    "sha256:598248c782262629d8b0afa3a9661911f34bcaf9d177115cbbe84c22f15bef08"
)
REPLACED = frozenset(
    {
        "scripts/v1_successor_forecast.py",
        "tests/unit/governance/test_v1_successor_forecast.py",
        "scripts/v1_architecture_governance.py",
        "Makefile",
        "mkdocs.yml",
    }
)
ADDED = (
    "scripts/v1_governance_corrections.py",
    "scripts/v1_correction_acceptance.py",
    "tests/unit/governance/test_v1_governance_corrections.py",
    "tests/unit/governance/test_v1_correction_acceptance.py",
    "docs/adr/0023-v1-governance-closure-corrections.md",
    f"{DIRECTORY}/delivery-forecast-v4.schema.json",
    f"{DIRECTORY}/forecast-v4-compatibility.md",
    f"{DIRECTORY}/support-policy-v2.json",
    f"{DIRECTORY}/support-policy-v2.schema.json",
    f"{DIRECTORY}/closure-corrections.md",
    f"{DIRECTORY}/closure-handoff.json",
    f"{DIRECTORY}/foundation-review.json",
    "tests/unit/governance/test_v1_support_policy_v2.py",
)
SUPPORT_TEXT_FIELDS = frozenset(
    {
        "person_id",
        "organization_id",
        "capacity",
        "primary_role_ref",
        "fallback_role_ref",
        "private_roster_ref",
        "private_roster_revision",
        "fallback_route_ref",
        "conflicts",
        "limitations",
    }
)
SUPPORT_COVERAGE_FIELDS = frozenset(
    {
        "primary_coverage_24x7",
        "fallback_coverage_24x7",
        "independent_fallback_person_and_route",
        "private_roster_revision_retained_and_auditable",
    }
)


def _require(value: bool, message: str) -> None:
    if not value:
        raise architecture.ArchitectureError(message)


def _json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode()


def _load(root: Path, relative: str) -> dict[str, Any]:
    return architecture.parse_json(architecture.read_bytes(root, relative))


def _binding(root: Path, relative: str) -> dict[str, Any]:
    return architecture.artifact(root, relative)


def validate_support_adoption(value: Mapping[str, Any]) -> None:
    """Require owner-attested private role separation without disclosing names.

    Different role references are a structural check, not proof of different
    people. The scoped owner attests actual staffing/routes in the private roster.
    """
    _require(
        set(value) == SUPPORT_TEXT_FIELDS | SUPPORT_COVERAGE_FIELDS,
        "explicit support adoption and coverage fields required",
    )
    for field in SUPPORT_TEXT_FIELDS:
        text = value[field]
        _require(
            type(text) is str and 0 < len(text) <= 4096 and bool(text.strip()),
            f"support {field} must be explicitly supplied",
        )
    for field in SUPPORT_COVERAGE_FIELDS:
        _require(value[field] is True, f"support {field} requires explicit coverage")
    for field in (
        "organization_id",
        "primary_role_ref",
        "fallback_role_ref",
        "private_roster_ref",
        "private_roster_revision",
        "fallback_route_ref",
    ):
        reference = value[field]
        _require(
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@#-]{0,255}", reference) is not None,
            f"support {field} requires a bounded opaque reference",
        )
        _require(reference[-1] not in ":/#@", f"support {field} has an empty reference suffix")
        _require(
            re.split(r"[:/#@]", reference)[-1].casefold()
            not in {"none", "pending", "unassigned", "unknown", "latest", "current", "template"},
            f"support {field} is unresolved or mutable",
        )
    _require(
        value["primary_role_ref"].casefold() != value["fallback_role_ref"].casefold()
        and value["primary_role_ref"].casefold() != value["organization_id"].casefold()
        and value["fallback_role_ref"].casefold() != value["organization_id"].casefold(),
        "separate primary and fallback role references required",
    )


def build_source_bindings(root: Path) -> dict[str, Any]:
    """Account for changed tooling without rewriting its signed predecessor."""
    predecessor = _load(root, f"{DIRECTORY}/architecture-package.json")
    projection = {key: value for key, value in predecessor.items() if key != "package_digest"}
    _require(
        predecessor.get("package_digest") == PREDECESSOR_PACKAGE_DIGEST
        and architecture.domain_digest("agent-assure:v1-architecture-package/v1", projection)
        == PREDECESSOR_PACKAGE_DIGEST,
        "immutable predecessor package differs",
    )
    current = architecture.build_package(root)
    for key in projection.keys() - {"tooling_artifacts"}:
        _require(current[key] == predecessor[key], f"immutable predecessor {key} differs")
    changes = []
    for old, new in zip(
        predecessor["tooling_artifacts"], current["tooling_artifacts"], strict=True
    ):
        _require(old["path"] == new["path"], "predecessor tooling inventory changed")
        if old != new:
            _require(old["path"] in REPLACED, "unapproved predecessor tooling replacement")
            changes.append({"path": old["path"], "predecessor": old, "current": new})
    # Git normalizes these reviewed text paths to LF. Binding CRLF working-copy
    # bytes would create a package that cannot verify in a clean checkout.
    for path in (*ADDED, *REPLACED):
        _require(
            b"\r" not in architecture.read_bytes(root, path),
            "correction text must use LF bytes before binding",
        )
    policy = _load(root, f"{DIRECTORY}/support-policy-v2.json")
    foundation = _load(root, f"{DIRECTORY}/foundation-review.json")
    dependencies = []
    for path, expected in (
        (
            policy["security_intake_precedence"]["source_path"],
            policy["security_intake_precedence"]["source_sha256"],
        ),
        (
            foundation["codeowners_inspection"]["path"],
            foundation["codeowners_inspection"]["sha256"],
        ),
    ):
        binding = _binding(root, path)
        _require(binding["sha256"] == expected, "bound security or ownership source changed")
        dependencies.append(binding)
    value = {
        "format": "agent-assure-sprint12-correction-source-bindings/1",
        "status": "prepared_for_human_review",
        "authorization_effect": "none",
        "predecessor_package_digest": PREDECESSOR_PACKAGE_DIGEST,
        "replacements": changes,
        "added_artifacts": [_binding(root, path) for path in ADDED],
        "external_dependencies": dependencies,
    }
    return {
        **value,
        "record_digest": architecture.domain_digest(
            "agent-assure:sprint12-source-bindings/v1", value
        ),
    }


def check_sources(root: Path) -> dict[str, Any]:
    record = _load(root, SOURCE_BINDINGS)
    _require(record == build_source_bindings(root), "correction source binding differs")
    architecture.check_supplementary(root)
    for name in ("support-policy-v2", "delivery-forecast-v4"):
        schema = _load(root, f"{DIRECTORY}/{name}.schema.json")
        jsonschema.Draft202012Validator.check_schema(schema)
        if name == "support-policy-v2":
            jsonschema.Draft202012Validator(schema).validate(
                _load(root, f"{DIRECTORY}/{name}.json")
            )
    return record


def refresh_source_bindings(root: Path) -> None:
    """Replace only the unsigned draft through a pinned parent descriptor."""
    value = build_source_bindings(root)
    previous = _load(root, SOURCE_BINDINGS)
    _require(
        previous == {}
        or (
            previous.get("format") == "agent-assure-sprint12-correction-source-bindings/1"
            and previous.get("status") == "prepared_for_human_review"
            and not {"signature", "signature_envelope", "acceptance_receipt"} & previous.keys()
        ),
        "refusing to overwrite non-draft source bindings",
    )
    with open_rooted_directory(root, DIRECTORY, label="correction binding parent") as parent:
        descriptor, metadata = parent.open_regular_file_exclusive_with_metadata(
            "correction-source-bindings.json.new"
        )
        try:
            with os.fdopen(os.dup(descriptor), "wb") as handle:
                handle.write(_json(value))
                handle.flush()
                os.fsync(handle.fileno())
            parent.replace_regular_file(
                "correction-source-bindings.json.new",
                "correction-source-bindings.json",
                source_descriptor=descriptor,
                expected_device=metadata.st_dev,
                expected_inode=metadata.st_ino,
            )
        finally:
            os.close(descriptor)


def propose_rows(producer: Mapping[str, Any], issue: str) -> list[dict[str, Any]]:
    """Labelled machine proposals; no metadata is represented as human-adopted."""
    ledger = producer["authoring_ledger"]
    selections = producer["human_estimates"]
    _require(len(ledger["rows"]) == len(selections), "prior selection coverage differs")
    result = []
    for source_row, prior in zip(ledger["rows"], selections, strict=True):
        _require(source_row["ticket_id"] == prior["ticket_id"], "prior ticket order differs")
        row = copy.deepcopy(prior)
        dependencies = source_row["dependency_anchor"]["ticket_ids"]
        row.update(
            confidence="low",
            dependency_assumptions=[
                "Scoped prerequisite receipts must be current before dispatch: "
                + (", ".join(dependencies) if dependencies else "no static ticket prerequisites"),
                "Exact future source/generated file scopes require separate dispatch approval.",
            ],
            risk_assumptions=[
                "Subjective planning quantities remain uncalibrated; review and resource "
                "availability "
                "may change effort and calendar duration.",
                "Engineering P90 excludes reviewer P90; no combined P90 is identified.",
            ],
            current_status="in_progress"
            if row["ticket_id"].startswith("V1-BASE-")
            else "not_started",
            trusted_issue_time=issue,
        )
        for execution in row["execution_estimates"]:
            execution["rationale"] = (
                "Machine proposal: retain the previously signed selected effort for review; "
                "the new metadata and current scope require explicit human adoption."
            )
        result.append(row)
    return result


def build_review(
    root: Path,
    producer_document: Mapping[str, Any],
    prior_bundle: Mapping[str, Any],
    rows: object,
    support_adoption: Mapping[str, Any],
    *,
    now: datetime,
) -> tuple[dict[str, Any], dict[str, bytes]]:
    """Compile exact subjects and claims; authentication belongs to the trusted caller."""
    sources = check_sources(root)
    producer = producer_document["claim"]
    previous = producer["delivery_forecast"]
    _require(prior_bundle.get("status") == "accepted_for_development", "prior bundle not accepted")
    _require(
        prior_bundle["bundle"]["claim"]["architecture_package_digest"]
        == PREDECESSOR_PACKAGE_DIGEST,
        "wrong predecessor architecture subject",
    )
    _require(
        previous["source"]["roadmap_digest"] == architecture.SPEC_DIGEST,
        "forecast binds another roadmap",
    )
    issue = now.astimezone(UTC).isoformat().replace("+00:00", "Z")
    expiry = previous["valid_until_utc"]
    corrected = forecast.build_projection_v4(
        authoring_ledger=producer["authoring_ledger"],
        human_estimates=rows,
        source=previous["source"],
        issued_at_utc=issue,
        valid_until_utc=expiry,
        now=now,
    )
    schema = _load(root, forecast.V4_SCHEMA_PATH)
    jsonschema.Draft202012Validator(schema).validate(corrected)
    policy = _load(root, f"{DIRECTORY}/support-policy-v2.json")
    validate_support_adoption(support_adoption)
    _require(
        support_adoption["organization_id"] == policy["organization_id"],
        "support organization differs from policy",
    )
    subjects: dict[str, bytes] = {
        "foundation_adoption": _json(_load(root, f"{DIRECTORY}/foundation-review.json")),
        "forecast_producer": _json(corrected),
        "forecast_acceptance": _json(
            {
                "decision": "accept_complete_planning_projection",
                "record_digest": corrected["record_digest"],
                "producer_subject_digest": architecture.raw_digest(_json(corrected)),
                "independent_or_runtime_effect": "none",
            }
        ),
        "design_amendment": architecture.read_bytes(
            root, "docs/adr/0023-v1-governance-closure-corrections.md"
        ),
        "support_policy": _json(
            {
                "decision": "adopt_operational_support_policy",
                "policy_path": f"{DIRECTORY}/support-policy-v2.json",
                "policy_sha256": _binding(root, f"{DIRECTORY}/support-policy-v2.json")["sha256"],
                "supported_line": policy["supported_line"],
                "targets": policy["response_targets"],
                "targets_become_operational_commitments": True,
                "receipt_expiry_terminates_support": False,
                "coverage_evidence": (
                    "policy_owner_attested_private_roster_not_independently_verified"
                ),
                **dict(support_adoption),
            }
        ),
    }
    predecessor_digest = architecture.domain_digest(
        "agent-assure:sprint12-predecessor-bundle/v1", prior_bundle
    )
    files = {
        "subjects/" + key + (".md" if key == "design_amendment" else ".json"): value
        for key, value in subjects.items()
    }
    files.update(
        {
            "inputs/prior-producer.json": _json(producer_document),
            "inputs/prior-s2-bundle.json": _json(prior_bundle),
            "inputs/selected-rows.json": _json(rows),
            "inputs/support-adoption.json": _json(support_adoption),
        }
    )
    for binding in [
        *sources["added_artifacts"],
        *sources["external_dependencies"],
        *[row["current"] for row in sources["replacements"]],
    ]:
        payload = architecture.read_bytes(root, binding["path"])
        _require(
            len(payload) == binding["size_bytes"]
            and architecture.raw_digest(payload) == binding["sha256"],
            "source changed during snapshot",
        )
        files["snapshot/" + binding["path"]] = payload
    old_package_path = f"{DIRECTORY}/architecture-package.json"
    old_package = _load(root, old_package_path)
    files["predecessor/" + old_package_path] = architecture.read_bytes(root, old_package_path)
    predecessor_bindings = [row["artifact"] for row in old_package["decisions"]]
    predecessor_bindings += (
        old_package["supplementary_artifacts"] + old_package["historical_artifacts"]
    )
    predecessor_bindings += [
        row for row in old_package["tooling_artifacts"] if row["path"] not in REPLACED
    ]
    for binding in predecessor_bindings:
        payload = architecture.read_bytes(root, binding["path"])
        _require(
            len(payload) == binding["size_bytes"]
            and architecture.raw_digest(payload) == binding["sha256"],
            "predecessor changed during snapshot",
        )
        files["predecessor/" + binding["path"]] = payload
    files["snapshot/" + SOURCE_BINDINGS] = architecture.read_bytes(root, SOURCE_BINDINGS)
    inventory = [
        {"path": name, "size_bytes": len(payload), "sha256": architecture.raw_digest(payload)}
        for name, payload in sorted(files.items())
    ]
    package = {
        "format": "agent-assure-sprint12-correction-review/1",
        "status": "pending_human_decisions_and_trusted_verification",
        "authorization_effect": "none",
        "proposal_authority": "machine_authored_nonbinding_until_exact_human_adoption",
        "source_bindings_digest": sources["record_digest"],
        "roadmap_digest": architecture.SPEC_DIGEST,
        "predecessor_bundle_digest": predecessor_digest,
        "issued_at_utc": issue,
        "valid_until_utc": expiry,
        "files": inventory,
    }
    digest = architecture.domain_digest("agent-assure:sprint12-correction-review/v1", package)
    claims: dict[str, dict[str, Any]] = {}
    for name, spec in acceptance.CLAIM_SPECS.items():
        subject_digest = (
            acceptance.closure_subject_digest(claims)
            if name == "correction_close"
            else architecture.raw_digest(subjects[name])
        )
        claims[name] = {
            "format": acceptance.CLAIM_FORMAT,
            "claim_id": name,
            "purpose": spec.purpose,
            "issuer_role": spec.role,
            "subject_digest": subject_digest,
            "predecessor_bundle_digest": predecessor_digest,
            "roadmap_digest": architecture.SPEC_DIGEST,
            "correction_package_digest": digest,
            "issued_at_utc": issue,
            "valid_until_utc": expiry,
            "independence": "NO_INDEPENDENT_REVIEW",
            "authorization_effect": "development_governance_only",
        }
        files[f"claims/{name}.json"] = _json(claims[name])
        files[f"claims/{name}.claim"] = acceptance.claim_bytes(claims[name])
    request = {
        **package,
        "package_digest": digest,
        "expected_claims": claims,
        "trusted_bootstrap_required": True,
        "sprint3_file_scope_authorized": False,
    }
    files["review-request.json"] = _json(request)
    _require(check_sources(root) == sources, "sources changed during review construction")
    return request, files


def verify_review_acceptance(
    request: Mapping[str, Any],
    files: Mapping[str, bytes],
    documents: Mapping[str, Mapping[str, Any]],
    authorities: Mapping[str, Any],
    verify_signature: Any,
    *,
    now: Any,
    prerequisite_valid_until_utc: str,
) -> acceptance.AcceptedCorrection:
    """Trusted integration: verify subjects before the low-level signature gate.

    The caller must independently reconstruct ``request``/``files`` with
    ``build_review`` from authenticated predecessor evidence and reviewed bytes.
    Submitted envelopes must never supply expected claims or adopted keys.
    """
    value = dict(request)
    expected_claims = value.pop("expected_claims")
    digest = value.pop("package_digest")
    _require(value.pop("trusted_bootstrap_required") is True, "trusted bootstrap required")
    _require(
        value.pop("sprint3_file_scope_authorized") is False, "future file scope cannot be granted"
    )
    _require(
        architecture.domain_digest("agent-assure:sprint12-correction-review/v1", value) == digest,
        "review package digest differs",
    )
    for claim in expected_claims.values():
        _require(
            claim["correction_package_digest"] == digest
            and claim["predecessor_bundle_digest"] == value["predecessor_bundle_digest"]
            and claim["roadmap_digest"] == value["roadmap_digest"]
            and claim["issued_at_utc"] == value["issued_at_utc"]
            and claim["valid_until_utc"] == value["valid_until_utc"],
            "claim and review source/validity bindings differ",
        )
    names = set()
    for binding in value["files"]:
        path = binding["path"]
        _require(path not in names, "duplicate review file")
        names.add(path)
        payload = files[path]
        _require(
            type(payload) is bytes
            and type(binding["size_bytes"]) is int
            and len(payload) == binding["size_bytes"]
            and architecture.raw_digest(payload) == binding["sha256"],
            "review file differs",
        )
    derived_files = {"review-request.json": _json(dict(request))}
    for name, claim in expected_claims.items():
        derived_files[f"claims/{name}.json"] = _json(claim)
        derived_files[f"claims/{name}.claim"] = acceptance.claim_bytes(claim)
    _require(set(files) == names | set(derived_files), "unexpected or missing review files")
    _require(
        all(files[name] == payload for name, payload in derived_files.items()),
        "derived review claims differ",
    )
    for name in acceptance.CLAIM_SPECS.keys() - {"correction_close"}:
        path = "subjects/" + name + (".md" if name == "design_amendment" else ".json")
        _require(
            path in names
            and architecture.raw_digest(files[path]) == expected_claims[name]["subject_digest"],
            "review claim subject differs",
        )
    support = architecture.parse_json(files["subjects/support_policy.json"])
    validate_support_adoption(
        {field: support[field] for field in SUPPORT_TEXT_FIELDS | SUPPORT_COVERAGE_FIELDS}
    )
    _require(
        support["person_id"] == authorities["release_policy_owner"].person_id,
        "support owner differs from adopted policy authority",
    )
    policy_path = "snapshot/" + support["policy_path"]
    _require(
        policy_path in names
        and architecture.raw_digest(files[policy_path]) == support["policy_sha256"],
        "support policy snapshot differs",
    )
    policy = architecture.parse_json(files[policy_path])
    security_source = policy["security_intake_precedence"]
    security_path = "snapshot/" + security_source["source_path"]
    _require(
        security_path in names
        and architecture.raw_digest(files[security_path]) == security_source["source_sha256"],
        "public security policy source differs",
    )
    foundation = architecture.parse_json(files["subjects/foundation_adoption.json"])
    ownership_source = foundation["codeowners_inspection"]
    ownership_path = "snapshot/" + ownership_source["path"]
    _require(
        ownership_path in names
        and architecture.raw_digest(files[ownership_path]) == ownership_source["sha256"],
        "ownership inspection source differs",
    )
    _require(
        support["organization_id"] == policy["organization_id"]
        and support["supported_line"] == policy["supported_line"]
        and architecture.domain_digest(
            "agent-assure:sprint12-support-targets/v1", support["targets"]
        )
        == architecture.domain_digest(
            "agent-assure:sprint12-support-targets/v1", policy["response_targets"]
        )
        and support["coverage_evidence"]
        == "policy_owner_attested_private_roster_not_independently_verified",
        "support organization, targets or evidence strength differs",
    )
    _require(
        support["decision"] == "adopt_operational_support_policy"
        and support["targets_become_operational_commitments"] is True
        and support["receipt_expiry_terminates_support"] is False,
        "operational support decision incomplete",
    )
    return acceptance.verify_correction_acceptance(
        documents,
        expected_claims,
        authorities,
        verify_signature,
        now=now,
        prerequisite_valid_until_utc=prerequisite_valid_until_utc,
    )


def publish_snapshot(root: Path, output: Path, files: Mapping[str, bytes]) -> None:
    """Exclusive descriptor-rooted publication; completion manifest appears last."""
    _require(0 < len(files) <= 256, "bounded snapshot file count required")
    _require(
        all(type(payload) is bytes and len(payload) <= 4_194_304 for payload in files.values()),
        "bounded snapshot payloads required",
    )
    _require(
        sum(map(len, files.values())) <= 32 * 1024 * 1024, "snapshot total byte limit exceeded"
    )
    names = set()
    devices = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    devices.update(f"{prefix}{i}" for prefix in ("COM", "LPT") for i in "123456789¹²³")
    for name in files:
        _require(type(name) is str and name != "snapshot-manifest.json", "reserved snapshot path")
        tokens = tuple(name.split("/"))
        _require(
            len(tokens) <= 32
            and all(
                token not in {"", ".", ".."}
                and not token.endswith((".", " "))
                and token.split(".")[0].upper() not in devices
                and not any(ord(c) < 32 or c in '<>:"|?*\\' for c in token)
                for token in tokens
            ),
            "noncanonical snapshot path",
        )
        _require(name.casefold() not in names, "case-insensitive snapshot collision")
        names.add(name.casefold())
    relative = output.absolute().relative_to(root.absolute()).as_posix()
    _require(relative.startswith(".governance-archive/"), "private archive output required")
    parts = tuple(relative.split("/"))
    _require(
        len(parts) == 2 and all(part not in {"", ".", ".."} for part in parts),
        "fresh direct archive identifier required",
    )
    _require(not output.exists() and not output.is_symlink(), "output already exists")
    with ExitStack() as stack:
        directories: dict[tuple[str, ...], RootedDirectoryDescriptor] = {
            (): stack.enter_context(open_rooted_directory(root, ".", label="correction workspace"))
        }

        def directory(path: tuple[str, ...]) -> RootedDirectoryDescriptor:
            if path in directories:
                return directories[path]
            parent = directory(path[:-1])
            identity = None
            if len(path) != 1 or not (root / path[0]).exists():
                with claim_rooted_directory(
                    parent, path[-1], label="correction snapshot"
                ) as claimed:
                    identity = (claimed.device, claimed.inode)
            lease = stack.enter_context(open_rooted_directory(root, Path(*path), label="snapshot"))
            _require(identity is None or identity == (lease.device, lease.inode), "output replaced")
            directories[path] = lease
            return lease

        directory(parts)
        inventory = []
        for name, payload in files.items():
            tokens = tuple(name.split("/"))
            _require(
                all(token not in {"", ".", ".."} and "\\" not in token for token in tokens),
                "noncanonical snapshot path",
            )
            parent = directory(parts + tokens[:-1])
            with os.fdopen(parent.open_regular_file_exclusive(tokens[-1]), "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            observed = parent.read_file_bounded(tokens[-1], max_bytes=4_194_304, label="readback")
            _require(observed.data == payload, "snapshot readback differs")
            inventory.append(
                {
                    "path": name,
                    "sha256": architecture.raw_digest(payload),
                    "size_bytes": len(payload),
                }
            )
        manifest = _json(
            {
                "format": "agent-assure-sprint12-snapshot/1",
                "authorization_effect": "none",
                "files": sorted(inventory, key=lambda row: row["path"]),
            }
        )
        with os.fdopen(
            directory(parts).open_regular_file_exclusive("snapshot-manifest.json"), "wb"
        ) as handle:
            handle.write(manifest)
            handle.flush()
            os.fsync(handle.fileno())


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "bind", "propose", "prepare"))
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--producer")
    parser.add_argument("--bundle")
    parser.add_argument("--rows")
    parser.add_argument("--support-adoption")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    try:
        root = args.root.absolute()
        if args.command == "bind":
            refresh_source_bindings(root)
        sources = check_sources(root)
        result: dict[str, Any] = {
            "result": "correction_draft_integrity_valid",
            "accepted": False,
            "authorization_effect": "none",
            "source_digest": sources["record_digest"],
        }
        if args.command in {"prepare", "propose"}:
            _require(
                args.producer is not None and args.out is not None,
                "producer and fresh output required",
            )
            producer = _load(root, args.producer)
            now = datetime.now(UTC)
            if args.command == "propose":
                rows = propose_rows(producer["claim"], now.isoformat().replace("+00:00", "Z"))
                prior = producer["claim"]
                preview = forecast.build_projection_v4(
                    authoring_ledger=prior["authoring_ledger"],
                    human_estimates=rows,
                    source=prior["delivery_forecast"]["source"],
                    issued_at_utc=now.isoformat().replace("+00:00", "Z"),
                    valid_until_utc=prior["delivery_forecast"]["valid_until_utc"],
                    now=now,
                )
                jsonschema.Draft202012Validator(_load(root, forecast.V4_SCHEMA_PATH)).validate(
                    preview
                )
                files = {
                    "selected-rows.proposal.json": _json({"rows": rows}),
                    "forecast.proposal.json": _json(preview),
                    "proposal-authority.json": _json(
                        {
                            "status": "machine_proposed_not_human_adopted",
                            "authorization_effect": "none",
                            "acceptance_requires": (
                                "explicit_review_exact_signatures_and_trusted_verification"
                            ),
                        }
                    ),
                    "support-adoption.template.json": _json(
                        {key: None for key in sorted(SUPPORT_TEXT_FIELDS | SUPPORT_COVERAGE_FIELDS)}
                    ),
                }
                publish_snapshot(root, args.out, files)
                result["result"] = "machine_proposals_prepared_no_human_adoption"
            else:
                _require(
                    all(
                        value is not None
                        for value in (args.bundle, args.rows, args.support_adoption)
                    ),
                    "bundle, selected rows and explicit support adoption required",
                )
                request, files = build_review(
                    root,
                    producer,
                    _load(root, args.bundle),
                    _load(root, args.rows)["rows"],
                    _load(root, args.support_adoption),
                    now=now,
                )
                publish_snapshot(root, args.out, files)
                result.update(
                    result="six_exact_correction_claims_prepared",
                    package_digest=request["package_digest"],
                )
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ValueError, KeyError, OSError, jsonschema.ValidationError) as exc:
        print(f"governance correction error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
