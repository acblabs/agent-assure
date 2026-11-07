from __future__ import annotations

import base64
import hashlib
import os
import shutil
import subprocess
import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import v1_s1_governance as legacy  # noqa: E402
from scripts import v1_successor_io as io  # noqa: E402


def object_id(kind: str, payload: bytes) -> str:
    return hashlib.sha1(
        f"{kind} {len(payload)}\x00".encode() + payload,
        usedforsecurity=False,
    ).hexdigest()


class Objects:
    def __init__(self) -> None:
        self.values: dict[str, tuple[str, bytes]] = {}
        self.commands: list[tuple[str, ...]] = []
        self.preflights = 0
        self.mutate: Any = None

    def put(self, kind: str, payload: bytes) -> str:
        oid = object_id(kind, payload)
        self.values[oid] = kind, payload
        return oid

    def preflight(self, root: Path) -> None:
        assert root.is_absolute()
        self.preflights += 1

    def run(self, args: Any, **limits: Any) -> subprocess.CompletedProcess[bytes]:
        self.commands.append(tuple(args))
        assert limits["max_stdout_bytes"] >= 0
        assert limits["max_stderr_bytes"] == io.MAX_STDERR_BYTES
        assert args[0] == "cat-file"
        kind, payload = self.values[args[2]]
        output = (
            kind.encode() + b"\n"
            if args[1] == "-t"
            else (str(len(payload)).encode() + b"\n" if args[1] == "-s" else payload)
        )
        if self.mutate is not None:
            output = self.mutate(args, output)
        return subprocess.CompletedProcess(args, 0, output, b"")

    def reader(self, tmp_path: Path) -> io.GitReader:
        return io.GitReader(tmp_path, self.run, preflight=self.preflight)


def commit(objects: Objects, tree: str, parents: tuple[str, ...] = ()) -> str:
    payload = b"tree " + tree.encode() + b"\n"
    payload += b"".join(b"parent " + p.encode() + b"\n" for p in parents)
    payload += (
        b"author T <t@example.invalid> 0 +0000\n"
        b"committer T <t@example.invalid> 0 +0000\n\nmessage\n"
    )
    return objects.put("commit", payload)


def tree_entry(mode: bytes, name: bytes, oid: str) -> bytes:
    return mode + b" " + name + b"\x00" + bytes.fromhex(oid)


def test_regular_blob_traversal_rehashes_every_object_and_preflights_every_call(
    tmp_path: Path,
) -> None:
    objects = Objects()
    blob = objects.put("blob", b"exact artifact\n")
    subtree = objects.put("tree", tree_entry(b"100644", b"receipt.json", blob))
    tree = objects.put("tree", tree_entry(b"40000", b"docs", subtree))
    oid = commit(objects, tree)
    reader = objects.reader(tmp_path)
    assert reader.read_commit_artifact(oid, "docs/receipt.json") == b"exact artifact\n"
    assert reader.resolve_commit(oid).parents == ()
    assert objects.preflights == len(objects.commands) == 15


@pytest.mark.parametrize("mode", [b"120000", b"160000", b"40000"])
def test_artifact_cannot_be_a_link_submodule_or_directory(tmp_path: Path, mode: bytes) -> None:
    objects = Objects()
    blob = objects.put("blob", b"outside")
    tree = objects.put("tree", tree_entry(mode, b"receipt", blob))
    with pytest.raises(io.SuccessorIOError, match="regular"):
        objects.reader(tmp_path).read_commit_artifact(commit(objects, tree), "receipt")


def test_symlink_in_intermediate_tree_is_rejected(tmp_path: Path) -> None:
    objects = Objects()
    blob = objects.put("blob", b"outside")
    tree = objects.put("tree", tree_entry(b"120000", b"docs", blob))
    with pytest.raises(io.SuccessorIOError, match="non-tree"):
        objects.reader(tmp_path).read_commit_artifact(commit(objects, tree), "docs/file")


@pytest.mark.parametrize("path", ["../x", "/x", "a//b", "a/./b", "a\\b", "a\x00b", "a\nb"])
def test_path_grammar_never_becomes_a_git_revision_expression(tmp_path: Path, path: str) -> None:
    objects = Objects()
    with pytest.raises(io.SuccessorIOError):
        objects.reader(tmp_path).read_commit_artifact("1" * 40, path)
    assert objects.commands == []


@pytest.mark.parametrize("mutation", ["payload", "size", "type", "overlong", "truncated"])
def test_immutable_object_substitution_is_rejected(tmp_path: Path, mutation: str) -> None:
    objects = Objects()
    tree = objects.put("tree", b"")
    oid = commit(objects, tree)

    def mutate(args: Any, output: bytes) -> bytes:
        if mutation == "size" and args[1] == "-s":
            return b"01\n"
        if mutation == "type" and args[1] == "-t":
            return b"blob\n"
        if args[1] == "commit":
            return {
                "payload": output.replace(b"message", b"Message"),
                "overlong": output + b"x",
                "truncated": output[:-1],
            }.get(mutation, output)
        return output

    objects.mutate = mutate
    with pytest.raises(io.SuccessorIOError):
        objects.reader(tmp_path).resolve_commit(oid)


def test_byte_ceiling_is_checked_before_fetching_object_content(tmp_path: Path) -> None:
    objects = Objects()
    tree = objects.put("tree", b"")
    oid = commit(objects, tree)
    objects.mutate = lambda args, data: b"99999999\n" if args[1] == "-s" else data
    with pytest.raises(io.SuccessorIOError, match="ceiling"):
        objects.reader(tmp_path).resolve_commit(oid)
    assert all(args[1] != "commit" for args in objects.commands)


def test_git_preflight_boolean_is_not_treated_as_verification(tmp_path: Path) -> None:
    objects = Objects()
    reader = io.GitReader(tmp_path, objects.run, preflight=lambda _: False)  # type: ignore[arg-type]
    with pytest.raises(io.SuccessorIOError, match="not return a flag"):
        reader.resolve_commit("1" * 40)
    assert objects.commands == []


def test_duplicate_or_truncated_tree_entries_are_rejected(tmp_path: Path) -> None:
    for malformed in (b"100644 x\0short",):
        objects = Objects()
        tree = objects.put("tree", malformed)
        with pytest.raises(io.SuccessorIOError, match="malformed"):
            objects.reader(tmp_path).read_commit_artifact(commit(objects, tree), "x")
    objects = Objects()
    blob = objects.put("blob", b"x")
    entry = tree_entry(b"100644", b"x", blob)
    tree = objects.put("tree", entry + entry)
    with pytest.raises(io.SuccessorIOError, match="ambiguous"):
        objects.reader(tmp_path).read_commit_artifact(commit(objects, tree), "x")


@pytest.fixture
def local_git(tmp_path: Path) -> tuple[io.GitReader, Any, Path]:
    executable = shutil.which("git")
    if executable is None:
        pytest.skip("test host Git is unavailable")
    executable = str(Path(executable).resolve())
    root = tmp_path / "repo"
    root.mkdir()
    environment = dict(os.environ)
    for key in list(environment):
        if key.upper().startswith("GIT_"):
            del environment[key]
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
        }
    )

    def git(*args: str) -> bytes:
        result = subprocess.run(
            [executable, "--no-replace-objects", "-C", str(root), *args],
            env=environment,
            capture_output=True,
            check=True,
            timeout=15,
        )
        return result.stdout

    git("init", "--quiet")
    git("config", "user.email", "t@example.invalid")
    git("config", "user.name", "Synthetic test")
    git("config", "core.autocrlf", "false")

    def runner(
        args: Any,
        *,
        max_stdout_bytes: int,
        max_stderr_bytes: int,
        input_bytes: bytes | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        return io._bounded_process(
            [executable, "--no-replace-objects", "-C", str(root), *args],
            environment,
            (max_stdout_bytes, max_stderr_bytes),
            input_bytes,
        )

    return io.GitReader(root, runner, preflight=lambda _: None), git, root


def test_actual_git_commit_diff_tag_and_artifact_round_trip(local_git: Any) -> None:
    reader, git, root = local_git
    (root / "a file.json").write_bytes(b"first\n")
    git("add", "--", "a file.json")
    git("commit", "--quiet", "-m", "first")
    base = git("rev-parse", "HEAD").strip().decode()
    assert reader.read_commit_artifact(base, "a file.json") == b"first\n"
    (root / "a file.json").write_bytes(b"second\n")
    git("add", "--", "a file.json")
    git("commit", "--quiet", "-m", "second")
    target = git("rev-parse", "HEAD").strip().decode()
    assert reader.resolve_commit(target).parents == (base,)
    reader.require_ancestor(base, target)
    assert reader.changed_paths(base, target) == ("a file.json",)
    assert reader.changed_line_count(base, target) == 2
    with pytest.raises(io.SuccessorIOError):
        reader.require_ancestor(target, base)
    git("tag", "-a", "test-v3", "-m", '{"proposal":true}')
    tag = reader.read_annotated_tag("test-v3")
    assert tag.target_commit == target and tag.message == b'{"proposal":true}\n'
    git("tag", "lightweight")
    with pytest.raises(io.SuccessorIOError, match="type"):
        reader.read_annotated_tag("lightweight")


@pytest.mark.parametrize("tag", ["--help", "x^{commit}", "x..y", "x/y", "x\ny", "x."])
def test_tag_expression_injection_is_rejected(tmp_path: Path, tag: str) -> None:
    objects = Objects()
    with pytest.raises(io.SuccessorIOError):
        objects.reader(tmp_path).read_annotated_tag(tag)
    assert objects.commands == []


def test_bounded_pipe_capture_handles_both_streams_and_rejects_excess() -> None:
    result = io._bounded_process(
        [
            sys.executable,
            "-I",
            "-S",
            "-c",
            "import sys;sys.stdout.write('1234');sys.stderr.write('abc')",
        ],
        os.environ,
        (4, 3),
    )
    assert result.returncode == 0 and result.stdout == b"1234" and result.stderr == b"abc"
    with pytest.raises(io.SuccessorIOError, match="bounded"):
        io._bounded_process(
            [sys.executable, "-I", "-S", "-c", "print('12345')"], os.environ, (4, 3)
        )


def test_bounded_process_timeout_kills_child_without_waiting_for_its_sleep(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    readings = iter((0.0, 31.0, 31.0))
    monkeypatch.setattr(io.time, "monotonic", lambda: next(readings, 31.0))
    with pytest.raises(io.SuccessorIOError, match="timed out"):
        io._bounded_process(
            [sys.executable, "-I", "-S", "-c", "import time;time.sleep(60)"], os.environ, (0, 0)
        )


def test_factories_reject_imported_nonbootstrapped_legacy_module(tmp_path: Path) -> None:
    with pytest.raises(io.SuccessorIOError, match="frozen"):
        io.frozen_git_reader(legacy, tmp_path)
    callback = io.frozen_signature_callback(legacy)
    with pytest.raises(io.SuccessorIOError, match="frozen"):
        callback(signature_base64="", payload=b"", signer_person_id="test", public_key="")


def test_actual_frozen_factory_adapter_uses_pinned_test_git_and_closed_metadata(
    local_git: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reader, git, root = local_git
    (root / "file").write_bytes(b"source\n")
    git("add", "--", "file")
    git("commit", "--quiet", "-m", "source")
    oid = git("rev-parse", "HEAD").strip().decode()
    git("remote", "add", "origin", legacy.APPROVED_ORIGIN_URL)
    git("config", "--unset", "core.autocrlf")
    (root / ".git/info/exclude").write_bytes(legacy.POST_V2_CONTROL_GIT_EXCLUDE_BYTES)
    executable = Path(shutil.which("git") or "").resolve()
    payload = executable.read_bytes()
    monkeypatch.setattr(
        legacy,
        "TRUSTED_EXECUTABLE_IDENTITIES",
        {
            "git": legacy.TrustedExecutableIdentity(
                str(executable), len(payload), hashlib.sha256(payload).hexdigest()
            )
        },
    )
    # This is an explicit test seam, not an actual runtime/bootstrap assertion.
    monkeypatch.setattr(legacy, "_main_has_active_runtime_bootstrap", lambda: True)
    frozen = io.frozen_git_reader(legacy, root)
    assert frozen.read_commit_artifact(oid, "file") == b"source\n"
    git("config", "alias.evil", "!echo should-never-run")
    with pytest.raises(io.SuccessorIOError, match="unapproved local"):
        frozen.resolve_commit(oid)


@pytest.mark.parametrize(
    "payload",
    [
        b"remote.origin.url\nwrong\0",
        b"remote.origin.url\nright\0include.path\nother\0",
        b"remote.origin.url\nright\0remote.origin.url\nright\0",
        b"core.bare\nfalse\0",
        b"remote.origin.url\nright\nextra\0",
        b"remote.origin.url\nright",
    ],
)
def test_closed_git_metadata_language_rejects_unsafe_ambiguity(payload: bytes) -> None:
    with pytest.raises(io.SuccessorIOError):
        io._validate_local_config(payload, "right")


def one_commit(local_git: Any) -> tuple[io.GitReader, Any, str]:
    reader, git, root = local_git
    (root / "file").write_text("first\n", encoding="utf-8")
    git("add", "--", "file")
    git("commit", "--quiet", "-m", "first")
    return reader, git, git("rev-parse", "HEAD").strip().decode()


def test_local_fixed_tag_cas_round_trip_and_idempotence(local_git: Any) -> None:
    reader, git, commit = one_commit(local_git)
    publisher = io.TagPublisher(reader.repository_root, reader._runner, preflight=lambda _: None)
    message = b'{"claim":{"status":"signed"},"signature_envelope":{"test":true}}'
    first = publisher.publish_fixed_tag(
        io.successor.SUCCESSOR_TAG,
        commit,
        message,
        tagger_person_id="synthetic-maintainer",
        observed_at=datetime(2026, 11, 7, tzinfo=UTC),
    )
    second = publisher.publish_fixed_tag(
        io.successor.SUCCESSOR_TAG,
        commit,
        message,
        tagger_person_id="synthetic-maintainer",
        observed_at=datetime(2026, 11, 8, tzinfo=UTC),
    )
    assert first == second
    assert (
        first.object_oid
        == git("rev-parse", "refs/tags/" + io.successor.SUCCESSOR_TAG).strip().decode()
    )
    with pytest.raises(io.SuccessorIOError, match="different bytes"):
        publisher.publish_fixed_tag(
            io.successor.SUCCESSOR_TAG,
            commit,
            b'{"other":true}',
            tagger_person_id="synthetic-maintainer",
            observed_at=datetime(2026, 11, 7, tzinfo=UTC),
        )
    assert reader.read_annotated_tag(io.successor.SUCCESSOR_TAG) == first


@pytest.mark.parametrize(
    "case", ["different-name", "symbolic", "lightweight", "noncanonical", "timezone"]
)
def test_fixed_tag_rejects_unsafe_or_conflicting_publication(local_git: Any, case: str) -> None:
    reader, git, commit = one_commit(local_git)
    publisher = io.TagPublisher(reader.repository_root, reader._runner, preflight=lambda _: None)
    name = io.successor.SUCCESSOR_TAG
    message = b'{"test":true}'
    observed = datetime(2026, 11, 7, tzinfo=UTC)
    if case == "different-name":
        name = "agent-assure-s1-1.0.0a1-acceptance-v2"
    elif case == "symbolic":
        git("tag", "elsewhere")
        git("symbolic-ref", "refs/tags/" + name, "refs/tags/elsewhere")
    elif case == "lightweight":
        git("tag", name)
    elif case == "noncanonical":
        message = b'{ "test": true }\n'
    elif case == "timezone":
        observed = observed.replace(tzinfo=None)
    with pytest.raises(io.SuccessorIOError):
        publisher.publish_fixed_tag(
            name, commit, message, tagger_person_id="test", observed_at=observed
        )


@pytest.mark.parametrize("same", [True, False])
def test_fixed_tag_cas_loser_accepts_only_exact_equal_winner(local_git: Any, same: bool) -> None:
    reader, git, commit = one_commit(local_git)
    normal_runner = reader._runner
    message = b'{"test":true}'

    def race(args: Any, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        if args[0] == "update-ref":
            if same:
                git("update-ref", args[2], args[3])
            else:
                git("tag", "-a", io.successor.SUCCESSOR_TAG, "-m", "conflicting")
            return subprocess.CompletedProcess(args, 128, b"", b"simulated CAS loser")
        return normal_runner(args, **kwargs)

    publisher = io.TagPublisher(reader.repository_root, race, preflight=lambda _: None)
    if same:
        result = publisher.publish_fixed_tag(
            io.successor.SUCCESSOR_TAG,
            commit,
            message,
            tagger_person_id="test",
            observed_at=datetime(2026, 11, 7, tzinfo=UTC),
        )
        assert result.message == message and result.target_commit == commit
    else:
        with pytest.raises(io.SuccessorIOError, match="conflicting"):
            publisher.publish_fixed_tag(
                io.successor.SUCCESSOR_TAG,
                commit,
                message,
                tagger_person_id="test",
                observed_at=datetime(2026, 11, 7, tzinfo=UTC),
            )


@pytest.mark.parametrize(
    "row", [b"-\t-\tfile\0", b"01\t0\tfile\0", b"1\t0\t../x\0", b"1\t0\tfile", b"1\t0\tfile\0" * 2]
)
def test_numstat_rejects_binary_or_ambiguous_budget_inputs(local_git: Any, row: bytes) -> None:
    reader, _, commit = one_commit(local_git)
    normal_runner = reader._runner

    def substituted(args: Any, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        if args[0] == "diff":
            return subprocess.CompletedProcess(args, 0, row, b"")
        return normal_runner(args, **kwargs)

    reader = io.GitReader(reader.repository_root, substituted, preflight=lambda _: None)
    with pytest.raises(io.SuccessorIOError):
        reader.changed_line_count(commit, commit)


def synthetic_receipt(result: str, parent: str) -> bytes:
    """Only a storage-shape fixture; this is not authenticated acceptance evidence."""
    core = io.successor
    digest = "sha256:" + "a" * 64
    record: dict[str, Any] = {
        "format": "agent-assure-s1-successor-acceptance/3",
        "acceptance_generation": 3,
        "status": "accepted_for_development",
        "authorization_effect": "development_governance_only",
        "predecessor_closure_commit": core.PREDECESSOR_CLOSURE,
        "result_commit": result,
        "result_parent_commit": parent,
        "scope_digest": digest,
        "kickoff_claim_digest": digest,
        "issued_at_utc": "2026-11-07T00:00:00Z",
        "valid_until_utc": "2026-12-01T00:00:00Z",
        "clock_basis": "maintainer_host_utc_externally_unattested",
        "actual_signature_time_claimed": False,
        "signature_envelope": {"synthetic": True},
        **{field: digest for field in core.EVIDENCE_REFERENCE_FIELDS},
    }
    record["receipt_digest"] = core.receipt_digest(record)
    return core.canonical_bytes(record)


def test_receipt_only_closure_plumbing_preserves_head_index_source_and_tree_order(
    local_git: Any,
) -> None:
    reader, git, first = one_commit(local_git)
    root = reader.repository_root
    (root / "docs/governance/v1/sprint2").mkdir(parents=True)
    (root / "docs/governance/v1/sprint2/existing.json").write_bytes(b"existing\n")
    (root / "docs/governance/v1/sprint2.txt").write_bytes(b"sibling\n")
    (root / "source.py").write_bytes(b"preserved source\n")
    git("add", "--", ".")
    git("commit", "--quiet", "-m", "R3-source")
    result = git("rev-parse", "HEAD").strip().decode()
    index = (root / ".git/index").read_bytes()
    refs = git("show-ref")
    receipt = synthetic_receipt(result, first)
    publisher = io.TagPublisher(root, reader._runner, preflight=lambda _: None)
    closure = publisher.create_closure_commit(
        result,
        receipt,
        committer_person_id="synthetic-maintainer",
        observed_at=datetime(2026, 11, 7, tzinfo=UTC),
    )
    assert closure.parents == (result,)
    assert reader.changed_paths(result, closure.oid) == (io.successor.RECEIPT_PATH,)
    assert reader.read_commit_artifact(closure.oid, io.successor.RECEIPT_PATH) == receipt
    assert reader.read_commit_artifact(closure.oid, "source.py") == b"preserved source\n"
    assert (
        reader.read_commit_artifact(closure.oid, "docs/governance/v1/sprint2/existing.json")
        == b"existing\n"
    )
    assert git("rev-parse", "HEAD").strip().decode() == result
    assert (root / ".git/index").read_bytes() == index and git("show-ref") == refs
    assert not (root / io.successor.RECEIPT_PATH).exists()
    repeated = publisher.create_closure_commit(
        result,
        receipt,
        committer_person_id="synthetic-maintainer",
        observed_at=datetime(2026, 11, 7, tzinfo=UTC),
    )
    assert repeated == closure


@pytest.mark.parametrize("case", ["staged", "unstaged", "wrong-result", "pending", "existing"])
def test_closure_object_requires_unchanged_exact_source_and_new_accepted_receipt(
    local_git: Any, case: str
) -> None:
    reader, git, result = one_commit(local_git)
    root = reader.repository_root
    if case == "existing":
        path = root / io.successor.RECEIPT_PATH
        path.parent.mkdir(parents=True)
        path.write_bytes(b"already present\n")
        git("add", "--", io.successor.RECEIPT_PATH)
        git("commit", "--quiet", "-m", "prior-receipt")
        result = git("rev-parse", "HEAD").strip().decode()
    if case in {"staged", "unstaged"}:
        (root / "file").write_bytes(b"changed\n")
        if case == "staged":
            git("add", "--", "file")
    receipt = synthetic_receipt(result, "0" * 40)
    if case in {"wrong-result", "pending"}:
        import json

        document = json.loads(receipt)
        document["result_commit"] = "f" * 40 if case == "wrong-result" else result
        if case == "pending":
            document["status"] = "pending_human_review"
            document["signature_envelope"] = None
        document["receipt_digest"] = io.successor.receipt_digest(document)
        receipt = io.successor.canonical_bytes(document)
    index = (root / ".git/index").read_bytes()
    publisher = io.TagPublisher(root, reader._runner, preflight=lambda _: None)
    with pytest.raises((io.SuccessorIOError, io.successor.SuccessorError)):
        publisher.create_closure_commit(
            result,
            receipt,
            committer_person_id="test",
            observed_at=datetime(2026, 11, 7, tzinfo=UTC),
        )
    assert git("rev-parse", "HEAD").strip().decode() == result
    assert (root / ".git/index").read_bytes() == index


def tagged_closure(local_git: Any) -> tuple[io.TagPublisher, Any, str]:
    reader, git, result = one_commit(local_git)
    publisher = io.TagPublisher(reader.repository_root, reader._runner, preflight=lambda _: None)
    closure = publisher.create_closure_commit(
        result,
        synthetic_receipt(result, "0" * 40),
        committer_person_id="test",
        observed_at=datetime(2026, 11, 7, tzinfo=UTC),
    )
    publisher.publish_fixed_tag(
        io.successor.SUCCESSOR_TAG,
        closure.oid,
        b'{"test":true}',
        tagger_person_id="test",
        observed_at=datetime(2026, 11, 7, tzinfo=UTC),
    )
    return publisher, git, closure.oid


def test_standalone_local_clone_checks_out_exact_c3_without_touching_capture(
    local_git: Any,
) -> None:
    publisher, git, closure = tagged_closure(local_git)
    root = publisher.repository_root
    head, index = git("rev-parse", "HEAD"), (root / ".git/index").read_bytes()
    destination = root / ".tmp/s1-acceptance/successor-v3/replay-1/clone"
    template = destination.parent / "empty-template"
    publisher.prepare_standalone_clone(closure, destination, empty_template=template)
    assert git("-C", str(destination), "rev-parse", "HEAD").strip().decode() == closure
    assert git("-C", str(destination), "status", "--porcelain=v1") == b""
    assert (
        git("-C", str(destination), "config", "--get", "remote.origin.url").strip()
        == legacy.APPROVED_ORIGIN_URL.encode()
    )
    assert not (destination / ".git/objects/info/alternates").exists()
    assert (destination / io.successor.RECEIPT_PATH).is_file()
    assert (root / ".git/index").read_bytes() == index and git("rev-parse", "HEAD") == head
    with pytest.raises((OSError, io.SuccessorIOError)):
        publisher.prepare_standalone_clone(closure, destination, empty_template=template)


@pytest.mark.parametrize(
    "case", ["outside", "wrong-prefix", "wrong-template", "wrong-commit", "existing-template"]
)
def test_standalone_clone_rejects_unowned_or_wrong_subject_paths(local_git: Any, case: str) -> None:
    publisher, git, closure = tagged_closure(local_git)
    root = publisher.repository_root
    destination = root / ".tmp/s1-acceptance/successor-v3/replay-2/clone"
    template = destination.parent / "empty-template"
    if case == "outside":
        destination = root.parent / "external/clone"
        template = destination.parent / "empty-template"
    elif case == "wrong-prefix":
        destination = root / ".tmp/other/clone"
        template = destination.parent / "empty-template"
    elif case == "wrong-template":
        template = destination.parent / "untrusted-template"
    elif case == "wrong-commit":
        closure = git("rev-parse", "HEAD").strip().decode()
    elif case == "existing-template":
        template.mkdir(parents=True)
        (template / "marker").write_bytes(b"preserve")
    index = (root / ".git/index").read_bytes()
    with pytest.raises((io.SuccessorIOError, OSError)):
        publisher.prepare_standalone_clone(closure, destination, empty_template=template)
    assert not destination.exists()
    assert (root / ".git/index").read_bytes() == index
    if case == "existing-template":
        assert (template / "marker").read_bytes() == b"preserve"


def test_standalone_clone_rejects_linked_parent_without_touching_target(local_git: Any) -> None:
    publisher, _, closure = tagged_closure(local_git)
    root = publisher.repository_root
    outside = root.parent / "unowned"
    outside.mkdir()
    (outside / "marker").write_bytes(b"preserve")
    prefix = root / ".tmp/s1-acceptance/successor-v3"
    prefix.mkdir(parents=True)
    try:
        (prefix / "replay-3").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("test host does not allow creation of a directory symlink")
    destination = prefix / "replay-3/clone"
    with pytest.raises((io.SuccessorIOError, OSError)):
        publisher.prepare_standalone_clone(
            closure, destination, empty_template=destination.parent / "empty-template"
        )
    assert list(outside.iterdir()) == [outside / "marker"]


@pytest.mark.parametrize("run_id", ["con", "nul", "com1", "lpt9"])
def test_clone_run_identifier_cannot_be_a_windows_device(tmp_path: Path, run_id: str) -> None:
    with pytest.raises(io.SuccessorIOError, match="governed clone path"):
        io._clone_destination(
            tmp_path, tmp_path / ".tmp/s1-acceptance/successor-v3" / run_id / "clone"
        )


@pytest.mark.skipif(os.name != "nt", reason="frozen native Windows Git upload-pack profile")
def test_native_frozen_clone_uses_authenticated_upload_pack_with_spaces(
    local_git: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, git, closure = tagged_closure(local_git)
    root = prepared.repository_root
    executable = Path(legacy.FROZEN_S1_EXECUTABLE_IDENTITIES["git"].path)
    assert executable.is_file()
    payload = executable.read_bytes()
    monkeypatch.setattr(
        legacy,
        "TRUSTED_EXECUTABLE_IDENTITIES",
        {
            "git": legacy.TrustedExecutableIdentity(
                str(executable), len(payload), hashlib.sha256(payload).hexdigest()
            )
        },
    )
    monkeypatch.setattr(legacy, "_main_has_active_runtime_bootstrap", lambda: True)
    git("remote", "add", "origin", legacy.APPROVED_ORIGIN_URL)
    git("config", "--unset", "core.autocrlf")
    (root / ".git/info/exclude").write_bytes(legacy.POST_V2_CONTROL_GIT_EXCLUDE_BYTES)
    publisher = io.frozen_tag_publisher(legacy, root)
    normal_process = io._bounded_process
    failures: list[bytes] = []

    def capture_failure(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        result = normal_process(*args, **kwargs)
        if result.returncode:
            failures.append(result.stderr)
        return result

    monkeypatch.setattr(io, "_bounded_process", capture_failure)
    helper = io.frozen_upload_pack_identity(legacy)
    assert helper["sha256"] == "sha256:" + hashlib.sha256(payload).hexdigest()
    prefix = root / ".tmp/s1-acceptance/successor-v3"
    base_bytes = len(str((prefix / "clone/.git").absolute()).encode("utf-8"))
    run_length = min(64, 215 - base_bytes - 1)
    if run_length < 1:
        pytest.skip("test workspace exceeds qualified Windows Git depth; shorten --basetemp")
    destination = prefix / ("n" * run_length) / "clone"
    assert len(str((destination / ".git").absolute()).encode("utf-8")) <= 215
    try:
        publisher.prepare_standalone_clone(
            closure, destination, empty_template=destination.parent / "empty-template"
        )
    except io.SuccessorIOError:
        pytest.fail(repr(failures))
    assert git("-C", str(destination), "rev-parse", "HEAD").strip().decode() == closure


@pytest.mark.skipif(os.name != "nt", reason="frozen native Windows Git path limit")
def test_windows_clone_depth_fails_before_any_target_is_created(tmp_path: Path) -> None:
    destination = tmp_path / ("long-capture-root-" + "x" * 180) / "clone"
    with pytest.raises(io.SuccessorIOError, match="CLONE_GIT_PATH_LIMIT_EXCEEDED"):
        io.require_qualified_clone_path(destination)
    assert not destination.exists() and not destination.parent.exists()


@pytest.fixture
def signed_example(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[bytes, dict[str, Any], io.TrustedKey]:
    executable = shutil.which("ssh-keygen")
    if executable is None:
        pytest.skip("test host OpenSSH is unavailable")
    executable_path = Path(executable).resolve()
    payload = executable_path.read_bytes()
    monkeypatch.setattr(
        legacy,
        "TRUSTED_EXECUTABLE_IDENTITIES",
        {
            "ssh-keygen": legacy.TrustedExecutableIdentity(
                str(executable_path), len(payload), hashlib.sha256(payload).hexdigest()
            )
        },
    )
    private = tmp_path / "ephemeral-test-key"
    subprocess.run(
        [str(executable_path), "-t", "ed25519", "-N", "", "-C", "test-only", "-f", str(private)],
        capture_output=True,
        check=True,
        timeout=15,
    )
    subject = tmp_path / "subject"
    subject.write_bytes(b"exact domain-separated test bytes\x00\n")
    subprocess.run(
        [
            str(executable_path),
            "-Y",
            "sign",
            "-f",
            str(private),
            "-n",
            "agent-assure-governance-v1",
            "-O",
            "hashalg=sha512",
            str(subject),
        ],
        capture_output=True,
        check=True,
        timeout=15,
    )
    public = private.with_suffix(".pub").read_text().strip().split()
    key = io.TrustedKey(
        "test-key",
        "test-person",
        " ".join(public[:2]),
        "repository_maintainer",
        ("planning_governance:s1_successor",),
        ("test-purpose",),
        "sha256:" + "a" * 64,
        "2026-11-01T00:00:00Z",
        "2026-12-01T00:00:00Z",
    )
    envelope = {
        "profile": "openssh-sshsig-ed25519/v1",
        "namespace": "agent-assure-governance-v1",
        "signer_person_id": key.person_id,
        "key_id": key.key_id,
        "signature": base64.b64encode(subject.with_suffix(".sig").read_bytes()).decode(),
    }
    return subject.read_bytes(), envelope, key


def test_real_openssh_signature_verifies_exact_bytes(signed_example: Any) -> None:
    payload, envelope, key = signed_example

    def now() -> datetime:
        return datetime(2026, 11, 7, 14, 0, tzinfo=UTC)

    result = io.verify(
        payload, envelope, key, legacy._verify_sshsig, now=now, purpose="test-purpose"
    )
    assert result.payload_sha256 == "sha256:" + hashlib.sha256(payload).hexdigest()
    assert result.competence_scopes == key.competence_scopes
    with pytest.raises(legacy.GovernanceError, match="verification failed"):
        io.verify(
            payload + b"tamper",
            envelope,
            key,
            legacy._verify_sshsig,
            now=now,
            purpose="test-purpose",
        )


def test_real_openssh_fingerprint_key_id_is_accepted_and_wrong_fingerprint_rejected(
    signed_example: Any,
) -> None:
    payload, envelope, key = signed_example
    fingerprint = io.public_key_fingerprint(key.public_key)
    adopted = replace(key, key_id=fingerprint)
    envelope["key_id"] = fingerprint
    result = io.verify(
        payload,
        envelope,
        adopted,
        legacy._verify_sshsig,
        now=lambda: datetime(2026, 11, 7, tzinfo=UTC),
        purpose="test-purpose",
    )
    assert result.signer_person_id == adopted.person_id
    invalid = replace(adopted, key_id="SHA256:" + "A" * 43)
    envelope["key_id"] = invalid.key_id
    with pytest.raises(io.SuccessorIOError, match="fingerprint"):
        io.verify(
            payload,
            envelope,
            invalid,
            legacy._verify_sshsig,
            now=lambda: datetime(2026, 11, 7, tzinfo=UTC),
            purpose="test-purpose",
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("namespace", "other"),
        ("key_id", "other"),
        ("signer_person_id", "other"),
        ("profile", "other"),
        ("unexpected", True),
        ("signature", "not-base64"),
    ],
)
def test_signature_profile_and_authority_substitution_fail_before_crypto(
    signed_example: Any, field: str, value: Any
) -> None:
    payload, envelope, key = signed_example
    envelope[field] = value
    called = False

    def callback(**kwargs: Any) -> None:
        nonlocal called
        called = True

    with pytest.raises(io.SuccessorIOError):
        io.verify(
            payload,
            envelope,
            key,
            callback,
            now=lambda: datetime(2026, 11, 7, tzinfo=UTC),
            purpose="test-purpose",
        )
    assert called is False


def test_key_scope_expiry_and_verification_clock_are_enforced(signed_example: Any) -> None:
    payload, envelope, key = signed_example
    with pytest.raises(io.SuccessorIOError, match="scope"):
        io.verify(
            payload,
            envelope,
            key,
            lambda **_: None,
            now=lambda: datetime(2026, 11, 7, tzinfo=UTC),
            purpose="different-purpose",
        )
    with pytest.raises(io.SuccessorIOError, match="current"):
        io.verify(
            payload,
            envelope,
            replace(key, valid_until_utc="2026-11-02T00:00:00Z"),
            lambda **_: None,
            now=lambda: datetime(2026, 11, 7, tzinfo=UTC),
            purpose="test-purpose",
        )
    moments = iter(
        (
            datetime(2026, 11, 7, tzinfo=UTC),
            datetime(2026, 11, 7, tzinfo=UTC) - timedelta(seconds=1),
        )
    )
    with pytest.raises(io.SuccessorIOError, match="regressed"):
        io.verify(
            payload,
            envelope,
            key,
            lambda **_: None,
            now=lambda: next(moments),
            purpose="test-purpose",
        )
