"""Synthetic trust contexts test an exact overlay, never bootstrap real authority.

The SSH callback below deliberately does not perform cryptography. Existing
OpenSSH tests qualify that primitive; these tests exercise source, scope,
temporal, signature-envelope, immutable-object and publication-topology gates.
"""

from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import zipfile
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from test_v1_governance_corrections import historical_git_executable  # noqa: E402

from scripts import v1_architecture_governance as architecture  # noqa: E402
from scripts import v1_postclosure_tooling as post  # noqa: E402
from scripts import v1_successor_io as git_io  # noqa: E402

IMPLEMENTATION = "a" * 40
PUBLICATION = "b" * 40
CURRENT = "c" * 40
NOW = datetime(2026, 11, 10, 3, tzinfo=UTC)


def test_assigned_checkout_rooted_io_can_read_exact_accepted_package() -> None:
    """Exercise the real operator read path without Git or a staged fixture.

    The raw pin is independently derived from immutable accepted source commit
    3a85cf19a9e71fc658d70ceee904ab9f7811d716, not supplied by the current file.
    A host capability denial is a failing preflight, never a skipped check.
    """
    raw = architecture.read_bytes(
        ROOT,
        "docs/governance/v1/sprint2/architecture-package.json",
        limit=14_586,
    )
    assert len(raw) == 14_586 <= architecture.MAX_ARTIFACT_BYTES
    assert hashlib.sha256(raw).hexdigest() == (
        "32225858b4d4a4a4207bf43ab0d44782d3a1e74fd7e744191641ba9293dc86d2"
    )


@pytest.fixture(scope="module")
def historical_files() -> dict[str, bytes]:
    paths = post.historical_source_paths()
    assert 0 < len(paths) <= post.MAX_FILES
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.upper()
        in {
            "SYSTEMROOT",
            "WINDIR",
            "COMSPEC",
            "PATH",
            "PATHEXT",
            "TEMP",
            "TMP",
            "HOME",
            "USERPROFILE",
            "APPDATA",
            "LOCALAPPDATA",
            "PROGRAMFILES",
        }
    }
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ATTR_NOSYSTEM": "1",
        }
    )
    result = subprocess.run(
        [
            historical_git_executable(),
            "--no-optional-locks",
            "--no-replace-objects",
            "--literal-pathspecs",
            "-c",
            "core.fsmonitor=false",
            "-c",
            f"safe.directory={ROOT}",
            "-c",
            f"core.attributesFile={os.devnull}",
            "archive",
            "--format=zip",
            post.HISTORICAL_SOURCE,
            "--",
            *paths,
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        check=True,
        timeout=30,
    )
    assert len(result.stdout) <= post.MAX_TOTAL_BYTES
    with zipfile.ZipFile(io.BytesIO(result.stdout)) as archive:
        members = archive.infolist()
        assert len(members) <= 256
        files = [member for member in members if not member.is_dir()]
        assert len(files) == len(paths) and {member.filename for member in files} == set(paths)
        assert sum(member.file_size for member in files) <= post.MAX_TOTAL_BYTES
        data = {}
        for member in files:
            assert stat.S_IFMT(member.external_attr >> 16) in {0, stat.S_IFREG}
            assert member.file_size <= architecture.MAX_ARTIFACT_BYTES
            raw = archive.read(member)
            assert len(raw) == member.file_size
            data[member.filename] = raw
    return data


class FakeGit:
    def __init__(
        self, historical: dict[str, bytes], published: dict[str, bytes], current: dict[str, bytes]
    ) -> None:
        self.files = {
            post.HISTORICAL_SOURCE: historical.copy(),
            post.PUBLISHED_EVIDENCE: published.copy(),
            IMPLEMENTATION: current.copy(),
            CURRENT: current.copy(),
            PUBLICATION: {},
        }
        self.reads: list[tuple[str, str]] = []
        self.parents = (IMPLEMENTATION,)
        self.changes = (post.AMENDMENT_PATH,)
        self.tag = git_io.AnnotatedTag(post.S1_TAG_OBJECT, post.S1_CLOSURE, b"retained fixed tag")
        self.ancestors = {(post.PUBLISHED_EVIDENCE, IMPLEMENTATION), (PUBLICATION, CURRENT)}

    def read_commit_artifact(self, commit: str, path: str) -> bytes:
        self.reads.append((commit, path))
        return self.files[commit][path]

    def resolve_commit(self, oid: str) -> Any:
        assert len(oid) == 40
        return SimpleNamespace(parents=self.parents if oid == PUBLICATION else ())

    def changed_paths(self, base_commit: str, target_commit: str) -> tuple[str, ...]:
        if (base_commit, target_commit) == (post.HISTORICAL_SOURCE, IMPLEMENTATION):
            return ("scripts/v1_postclosure_tooling.py",)
        assert (base_commit, target_commit) == (IMPLEMENTATION, PUBLICATION)
        return self.changes

    def require_ancestor(self, ancestor: str, descendant: str) -> None:
        if (ancestor, descendant) not in self.ancestors:
            raise git_io.SuccessorIOError("not the independently required ancestry")

    def read_annotated_tag(self, name: str) -> git_io.AnnotatedTag:
        assert name == post.S1_TAG
        return self.tag


class Case:
    def __init__(self, root: Path, historical: dict[str, bytes]) -> None:
        self.root = root
        root.mkdir()
        public = {
            path: (ROOT / path).read_bytes() for path in {post.PUBLIC_MANIFEST, *post.PUBLIC_FILES}
        }
        current = {**historical, **public}
        for path in {*post.NEW_FILES, *post.MODIFIABLE_HISTORICAL_FILES}:
            current[path] = (ROOT / path).read_bytes()
        for path, raw in current.items():
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        self.git = FakeGit(historical, public, current)
        historical_rows = [post.binding(path, raw) for path, raw in sorted(historical.items())]
        public_rows = [post.binding(path, raw) for path, raw in sorted(public.items())]
        current_rows = [post.binding(path, raw) for path, raw in sorted(current.items())]
        old = {row["path"]: row for row in historical_rows + public_rows}
        self.claim: dict[str, Any] = {
            "format": "agent-assure-post-closure-tooling-amendment/1",
            "purpose": post.PURPOSE,
            "decision": "adopt_exact_current_tooling_overlay_and_historical_verification_route",
            "issuer_person_id": post.ROOT_PERSON,
            "issuer_role": "repository_maintainer",
            "key_id": post.ROOT_KEY_ID,
            "approval_mode": "maintainer_development",
            "independence": "NO_INDEPENDENT_REVIEW",
            "authorization_effect": (
                "historical_and_exact_current_tooling_development_verification_only"
            ),
            "historical_source_commit": post.HISTORICAL_SOURCE,
            "published_correction_evidence_commit": post.PUBLISHED_EVIDENCE,
            "accepted_sprint12_receipt_digest": post.RECEIPT_DIGEST,
            "historical_source_bindings_digest": post.SOURCE_DIGEST,
            "historical_predecessor_package_digest": post.corrections.PREDECESSOR_PACKAGE_DIGEST,
            "s1_v3_closure_commit": post.S1_CLOSURE,
            "s1_v3_fixed_tag_object": post.S1_TAG_OBJECT,
            "reviewed_implementation_source_commit": IMPLEMENTATION,
            "receipt_publication_topology": (
                "receipt_only_direct_child_of_reviewed_implementation_commit"
            ),
            "authority_record_path": post.AMENDMENT_PATH,
            "issued_at_utc": "2026-11-10T02:00:00Z",
            "valid_until_utc": post.EXPIRY,
            "historical_source_inventory": historical_rows,
            "published_evidence_inventory": public_rows,
            "reviewed_current_inventory": current_rows,
            "current_tooling_overlay": [
                {"path": row["path"], "predecessor": old.get(row["path"]), "current": row}
                for row in current_rows
                if row != old.get(row["path"])
            ],
            "external_runtime_profile_digest": "sha256:" + "d" * 64,
            "key_scope_adoption": {
                "purpose": post.PURPOSE,
                "trust_snapshot_digest": "sha256:" + "e" * 64,
            },
            "retained_constraints": post.RETAINED_CONSTRAINTS.copy(),
        }
        receipt = json.loads(public[post.PUBLIC_RECEIPT])
        # A real signature's framing is useful synthetic data, but the test-only
        # callback does not verify it and this context confers no real authority.
        self.envelope = copy.deepcopy(receipt["authority_document"]["signature_envelope"])
        self.calls: list[dict[str, Any]] = []
        root_key = git_io.TrustedKey(
            post.ROOT_KEY_ID,
            post.ROOT_PERSON,
            post.ROOT_PUBLIC_KEY,
            "repository_maintainer",
            ("planning_governance:s1_successor",),
            (post.PURPOSE,),
            "sha256:" + "e" * 64,
            "2026-11-09T19:56:47.187684Z",
            post.EXPIRY,
        )
        historical_key = replace(root_key, allowed_purposes=post.HISTORICAL_PURPOSES)
        self.inputs = post.AuthenticatedInputs(
            b"",
            root_key,
            historical_key,
            self.git,
            self.signature,
            lambda: NOW,
            self.claim["external_runtime_profile_digest"],
            PUBLICATION,
            CURRENT,
        )
        self.freeze()

    def signature(self, **values: Any) -> None:
        self.calls.append(values)

    def freeze(self) -> None:
        self.inputs = replace(
            self.inputs, expected_claim=post.acceptance.core.canonical_bytes(self.claim)
        )
        raw = (
            json.dumps(
                {"claim": self.claim, "signature_envelope": self.envelope}, sort_keys=True, indent=2
            )
            + "\n"
        ).encode()
        target = self.root / post.AMENDMENT_PATH
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        self.git.files[PUBLICATION][post.AMENDMENT_PATH] = raw


@pytest.fixture
def case(tmp_path: Path, historical_files: dict[str, bytes]) -> Case:
    return Case(tmp_path / "synthetic-postclosure", historical_files)


def test_exact_historical_proof_and_current_overlay_are_separate(case: Case) -> None:
    result = post.verify(case.root, inputs=case.inputs)
    assert result.published_historical_receipt_signatures_and_source_bindings_verified
    assert result.exact_postclosure_tooling_overlay_verified
    assert result.retained_original_host_replay_performed is False
    assert (
        result.authorization_effect
        == "historical_and_exact_current_tooling_development_verification_only"
    )
    assert len(case.calls) == 24  # New amendment, seven corrections, original S1, 15 S2 records.
    assert {commit for commit, _ in case.git.reads} == {
        post.HISTORICAL_SOURCE,
        post.PUBLISHED_EVIDENCE,
        IMPLEMENTATION,
        PUBLICATION,
        CURRENT,
    }


def test_authenticated_operator_can_supply_architecture_gate_without_reauthoring(
    case: Case,
) -> None:
    original = (case.root / post.corrections.SOURCE_BINDINGS).read_bytes()
    with pytest.raises(
        architecture.ArchitectureError, match="unapproved predecessor tooling replacement"
    ):
        post.corrections.build_source_bindings(case.root)
    package = architecture.check_package(
        case.root, postclosure_verifier=lambda root: post.verify(root, inputs=case.inputs)
    )
    assert package["package_digest"] == post.corrections.PREDECESSOR_PACKAGE_DIGEST
    assert (case.root / post.corrections.SOURCE_BINDINGS).read_bytes() == original


def test_amendment_schema_is_closed_and_requires_exact_inventory(case: Case) -> None:
    schema = json.loads((ROOT / post.SCHEMA_PATH).read_bytes())
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(schema)
    validator.validate({"claim": case.claim, "signature_envelope": case.envelope})
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(
            {"claim": case.claim, "signature_envelope": case.envelope, "accepted": True}
        )


@pytest.mark.parametrize(
    "change", ["claim", "purpose", "scope", "namespace", "wrong-key", "expired", "future"]
)
def test_unadmitted_amendment_fails_before_reading_git(case: Case, change: str) -> None:
    if change == "claim":
        case.claim["retained_constraints"]["retained_original_host_replay_claimed"] = True
    elif change == "purpose":
        case.claim["purpose"] = "release-approval/v1"
    elif change == "scope":
        case.inputs = replace(
            case.inputs, root_key=replace(case.inputs.root_key, allowed_purposes=("unrelated/v1",))
        )
    elif change == "namespace":
        case.envelope["namespace"] = "unrelated"
    elif change == "wrong-key":
        case.envelope["key_id"] = "different-key"
    elif change == "expired":
        case.inputs = replace(case.inputs, now=lambda: datetime(2026, 12, 8, tzinfo=UTC))
    else:
        case.claim["issued_at_utc"] = "2026-11-11T00:00:00Z"
    case.freeze()
    with pytest.raises((architecture.ArchitectureError, git_io.SuccessorIOError)):
        post.verify(case.root, inputs=case.inputs)
    assert case.git.reads == []


def test_bad_signature_cannot_select_helpers_or_historical_inputs(case: Case) -> None:
    def reject(**_values: Any) -> None:
        raise ValueError("synthetic native rejection")

    with pytest.raises(ValueError, match="native rejection"):
        post.verify(case.root, inputs=replace(case.inputs, verify_signature=reject))
    assert case.git.reads == []


@pytest.mark.parametrize(
    "change", ["missing", "duplicate", "reordered", "unknown", "protected", "overlay"]
)
def test_complete_exact_inventory_and_overlay_are_mandatory(case: Case, change: str) -> None:
    rows = case.claim["reviewed_current_inventory"]
    if change == "missing":
        rows.pop()
    elif change == "duplicate":
        rows.append(copy.deepcopy(rows[-1]))
    elif change == "reordered":
        rows.reverse()
    elif change == "unknown":
        rows[0]["path"] = "unknown/file.py"
    elif change == "protected":
        path = "SECURITY.md"
        raw = case.git.files[IMPLEMENTATION][path] + b"\nChanged policy\n"
        case.git.files[IMPLEMENTATION][path] = raw
        index = next(i for i, row in enumerate(rows) if row["path"] == path)
        rows[index] = post.binding(path, raw)
    else:
        case.claim["current_tooling_overlay"].pop()
    case.freeze()
    with pytest.raises(architecture.ArchitectureError):
        post.verify(case.root, inputs=case.inputs)


@pytest.mark.parametrize(
    "change",
    [
        "parent",
        "merge",
        "extra-file",
        "tag",
        "ancestry",
        "historical-blob",
        "reviewed-helper",
        "current-helper",
        "CRLF",
    ],
)
def test_wrong_topology_missing_proof_and_source_substitution_are_rejected(
    case: Case, change: str
) -> None:
    if change == "parent":
        case.git.parents = ("f" * 40,)
    elif change == "merge":
        case.git.parents = (IMPLEMENTATION, "f" * 40)
    elif change == "extra-file":
        case.git.changes = (post.AMENDMENT_PATH, "scripts/unreviewed.py")
    elif change == "tag":
        case.git.tag = replace(case.git.tag, object_oid="f" * 40)
    elif change == "ancestry":
        case.git.ancestors.clear()
    elif change == "historical-blob":
        case.git.files[post.HISTORICAL_SOURCE][post.corrections.SOURCE_BINDINGS] += b" "
    elif change == "reviewed-helper":
        case.git.files[IMPLEMENTATION]["scripts/v1_postclosure_tooling.py"] += b"\n# changed\n"
    else:
        target = case.root / "scripts/v1_postclosure_tooling.py"
        raw = target.read_bytes()
        target.write_bytes(
            raw.replace(b"\n", b"\r\n") if change == "CRLF" else raw + b"\n# changed\n"
        )
    with pytest.raises((architecture.ArchitectureError, git_io.SuccessorIOError)):
        post.verify(case.root, inputs=case.inputs)


def test_missing_amendment_has_no_legacy_success_fallback(case: Case) -> None:
    (case.root / post.AMENDMENT_PATH).unlink()
    with pytest.raises((architecture.ArchitectureError, OSError)):
        post.verify(case.root, inputs=case.inputs)


def test_source_only_boolean_callback_does_not_satisfy_architecture_gate(case: Case) -> None:
    with pytest.raises(architecture.ArchitectureError, match="post-closure proof"):
        architecture.check_package(case.root, postclosure_verifier=lambda _root: True)


@pytest.mark.parametrize("size", [False, True, 0.0, 1.0])
def test_source_binding_size_requires_an_integer_excluding_bool_and_float(size: object) -> None:
    with pytest.raises(architecture.ArchitectureError, match="source size"):
        post._rows([{"path": "test.py", "sha256": "sha256:" + "d" * 64, "size_bytes": size}])


def test_submitted_numeric_zero_cannot_impersonate_reviewed_false(case: Case) -> None:
    target = case.root / post.AMENDMENT_PATH
    document = json.loads(target.read_bytes())
    document["claim"]["retained_constraints"]["retained_original_host_replay_claimed"] = 0
    target.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(architecture.ArchitectureError, match="reviewed exact claim"):
        post.verify(case.root, inputs=case.inputs)
    assert case.git.reads == []


def test_even_resigned_numeric_zero_is_outside_the_closed_boolean_contract(case: Case) -> None:
    case.claim["retained_constraints"]["retained_original_host_replay_claimed"] = 0
    case.freeze()
    with pytest.raises(architecture.ArchitectureError, match="constraints differ"):
        post.verify(case.root, inputs=case.inputs)


def test_clock_regression_between_signature_checks_is_rejected(case: Case) -> None:
    calls = 0

    def clock() -> datetime:
        nonlocal calls
        calls += 1
        return NOW.replace(second=1 if calls in {2, 3} else 0)

    with pytest.raises(architecture.ArchitectureError, match="clock regressed"):
        post.verify(case.root, inputs=replace(case.inputs, now=clock))
