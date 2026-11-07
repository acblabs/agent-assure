"""Bounded immutable Git and Ed25519 SSHSIG adapters for the S1 successor.

The production factories require the existing authenticated S1 launcher. The
injectable runners and signature callbacks are test seams, not trust bootstrap.
Direct process launches use authenticated absolute executables and
``shell=False``. The narrowly scoped local Git transport receives a quoted,
authenticated upload-pack path. No operation signs or accepts a producer's
assertion that a signature verified.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import shlex
import stat
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from agent_assure.rooted_io import (
    RootedDirectoryDescriptor,
    claim_rooted_directory,
    open_rooted_directory,
)
from scripts import v1_s1_successor as successor

MAX_OBJECT_BYTES = 4 * 1024 * 1024
MAX_TREE_BYTES = 16 * 1024 * 1024
MAX_TREE_TRAVERSAL_BYTES = 64 * 1024 * 1024
MAX_CHANGED_PATH_BYTES = 1024 * 1024
MAX_STDERR_BYTES = 4096
MAX_SIGNATURE_BYTES = 16_384
# Pinned Git for Windows 2.54.0 rejects strlen(GIT_DIR) > PATH_MAX - 40,
# independently of core.longpaths. PATH_MAX is 260 in its MinGW CRT profile.
# https://github.com/git-for-windows/git/blob/v2.54.0.windows.1/setup.c#L1052
MAX_PINNED_WINDOWS_GIT_DIR_BYTES = 220
_OID = re.compile(r"[0-9a-f]{40}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_TAG = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,159}\Z")
_IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@+-]{0,127}\Z")
_UTC = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z\Z")


class SuccessorIOError(ValueError):
    """Rejected Git content, authority, framing, or bounded subprocess result."""


class GitRunner(Protocol):
    def __call__(
        self,
        arguments: Sequence[str],
        *,
        max_stdout_bytes: int,
        max_stderr_bytes: int,
        input_bytes: bytes | None = None,
    ) -> subprocess.CompletedProcess[bytes]: ...


class SSHVerifier(Protocol):
    def __call__(
        self,
        *,
        signature_base64: str,
        payload: bytes,
        signer_person_id: str,
        public_key: str,
    ) -> None: ...


@dataclass(frozen=True)
class AnnotatedTag:
    object_oid: str
    target_commit: str
    message: bytes


@dataclass(frozen=True)
class TrustedKey:
    """Already adopted verifier-owned authority; never populate from an envelope."""

    key_id: str
    person_id: str
    public_key: str
    role: str
    competence_scopes: tuple[str, ...]
    allowed_purposes: tuple[str, ...]
    trust_snapshot_digest: str
    valid_from_utc: str
    valid_until_utc: str


def _require(value: bool, message: str) -> None:
    if not value:
        raise SuccessorIOError(message)


def _oid(value: str) -> str:
    _require(
        type(value) is str and _OID.fullmatch(value) is not None, "full Git object ID required"
    )
    return value


def _path(value: str) -> tuple[str, ...]:
    _require(
        type(value) is str and 0 < len(value.encode("utf-8")) <= 4096,
        "bounded relative Git path required",
    )
    parts = tuple(value.split("/"))
    _require(
        len(parts) <= 64
        and all(part not in {"", ".", ".."} for part in parts)
        and "\\" not in value
        and "\x00" not in value
        and not any(ord(c) < 32 for c in value),
        "noncanonical Git path",
    )
    return parts


def _object_oid(kind: str, payload: bytes) -> str:
    # Git's pinned 40-hex identity format is SHA-1; no new assurance primitive.
    return hashlib.sha1(
        f"{kind} {len(payload)}\x00".encode("ascii") + payload,
        usedforsecurity=False,
    ).hexdigest()


class GitReader:
    """Small read-only command vocabulary over an authenticated bounded runner."""

    def __init__(
        self,
        repository_root: Path,
        runner: GitRunner,
        *,
        preflight: Callable[[Path], None],
    ) -> None:
        _require(callable(runner) and callable(preflight), "trusted Git runner/preflight required")
        self.repository_root = repository_root.absolute()
        self._runner = runner
        self._preflight = preflight

    def _run(
        self,
        arguments: Sequence[str],
        limit: int,
        *,
        allowed_codes: tuple[int, ...] = (0,),
        input_bytes: bytes | None = None,
    ) -> bytes:
        preflight_result: Any = self._preflight(self.repository_root)
        _require(preflight_result is None, "Git preflight must raise on failure, not return a flag")
        if input_bytes is None:
            result = self._runner(
                arguments, max_stdout_bytes=limit, max_stderr_bytes=MAX_STDERR_BYTES
            )
        else:
            result = self._runner(
                arguments,
                max_stdout_bytes=limit,
                max_stderr_bytes=MAX_STDERR_BYTES,
                input_bytes=input_bytes,
            )
        _require(
            type(result.stdout) is bytes and type(result.stderr) is bytes,
            "Git runner returned non-byte streams",
        )
        _require(
            len(result.stdout) <= limit and len(result.stderr) <= MAX_STDERR_BYTES,
            "Git runner exceeded its output ceiling",
        )
        _require(
            type(result.returncode) is int and result.returncode in allowed_codes,
            "governed Git inspection failed",
        )
        return result.stdout

    def _object(self, oid: str, kind: str, limit: int = MAX_OBJECT_BYTES) -> bytes:
        _oid(oid)
        _require(
            self._run(("cat-file", "-t", oid), 32) == kind.encode("ascii") + b"\n",
            "unexpected immutable Git object type",
        )
        size = self._run(("cat-file", "-s", oid), 32)
        _require(
            re.fullmatch(rb"(?:0|[1-9][0-9]{0,9})\n", size) is not None,
            "noncanonical Git object size",
        )
        length = int(size)
        _require(length <= limit, "immutable Git object exceeds byte ceiling")
        payload = self._run(("cat-file", kind, oid), length)
        _require(
            len(payload) == length and _object_oid(kind, payload) == oid,
            "immutable Git object bytes do not match object ID",
        )
        return payload

    def _commit(self, oid: str) -> tuple[str, tuple[str, ...]]:
        payload = self._object(oid, "commit")
        headers, separator, _ = payload.partition(b"\n\n")
        lines = headers.split(b"\n")
        _require(bool(separator) and bool(lines), "malformed Git commit")
        tree = re.fullmatch(rb"tree ([0-9a-f]{40})", lines[0])
        _require(
            tree is not None and not any(line.startswith(b"tree ") for line in lines[1:]),
            "ambiguous Git root tree",
        )
        parents: list[str] = []
        for line in lines[1:]:
            if line.startswith(b"parent "):
                match = re.fullmatch(rb"parent ([0-9a-f]{40})", line)
                _require(match is not None, "malformed Git parent")
                assert match is not None
                parents.append(match.group(1).decode("ascii"))
        _require(len(parents) == len(set(parents)), "duplicate Git parent")
        assert tree is not None
        return tree.group(1).decode("ascii"), tuple(parents)

    def resolve_commit(self, oid: str) -> successor.GitCommit:
        _, parents = self._commit(oid)
        return successor.GitCommit(oid, parents)

    def require_ancestor(self, ancestor: str, descendant: str) -> None:
        _oid(ancestor)
        _oid(descendant)
        self.resolve_commit(ancestor)
        self.resolve_commit(descendant)
        self._run(("merge-base", "--is-ancestor", ancestor, descendant), 0)

    def changed_paths(self, base_commit: str, target_commit: str) -> tuple[str, ...]:
        self.resolve_commit(base_commit)
        self.resolve_commit(target_commit)
        payload = self._run(
            (
                "diff-tree",
                "--no-commit-id",
                "--name-only",
                "-r",
                "-z",
                "--no-renames",
                "--no-ext-diff",
                base_commit,
                target_commit,
                "--",
            ),
            MAX_CHANGED_PATH_BYTES,
        )
        if not payload:
            return ()
        _require(payload.endswith(b"\x00"), "unterminated Git changed-path list")
        try:
            paths = tuple(
                item.decode("utf-8", errors="strict") for item in payload[:-1].split(b"\x00")
            )
        except UnicodeDecodeError as exc:
            raise SuccessorIOError("Git changed path is not UTF-8") from exc
        _require(len(paths) <= 4096 and len(paths) == len(set(paths)), "ambiguous Git path list")
        for path in paths:
            _path(path)
        return tuple(sorted(paths, key=lambda path: path.encode("utf-8")))

    def changed_line_count(self, base_commit: str, target_commit: str) -> int:
        self.resolve_commit(base_commit)
        self.resolve_commit(target_commit)
        payload = self._run(
            (
                "diff",
                "--no-renames",
                "--no-ext-diff",
                "--no-textconv",
                "--numstat",
                "-z",
                base_commit,
                target_commit,
                "--",
            ),
            MAX_CHANGED_PATH_BYTES,
        )
        if not payload:
            return 0
        _require(payload.endswith(b"\x00"), "unterminated Git numstat list")
        total = 0
        seen: set[str] = set()
        for record in payload[:-1].split(b"\x00"):
            fields = record.split(b"\t", 2)
            _require(len(fields) == 3, "malformed Git numstat row")
            _require(
                all(
                    re.fullmatch(rb"(?:0|[1-9][0-9]{0,9})", value) is not None
                    for value in fields[:2]
                ),
                "binary or invalid diff is outside line budget",
            )
            try:
                path = fields[2].decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise SuccessorIOError("numstat path is not UTF-8") from exc
            _path(path)
            _require(path not in seen and len(seen) < 4096, "ambiguous Git numstat path")
            seen.add(path)
            total += int(fields[0]) + int(fields[1])
        return total

    def read_commit_artifact(self, commit: str, path: str) -> bytes:
        parts = _path(path)
        tree, _ = self._commit(commit)
        consumed = 0
        for index, part in enumerate(parts):
            data = self._object(
                tree, "tree", min(MAX_TREE_BYTES, MAX_TREE_TRAVERSAL_BYTES - consumed)
            )
            consumed += len(data)
            offset = 0
            found: tuple[bytes, str] | None = None
            seen: set[bytes] = set()
            while offset < len(data):
                space = data.find(b" ", offset)
                end = data.find(b"\x00", space + 1)
                _require(
                    space > offset and end > space + 1 and end + 21 <= len(data),
                    "malformed immutable Git tree",
                )
                mode, name = data[offset:space], data[space + 1 : end]
                _require(
                    mode in {b"40000", b"100644", b"100755", b"120000", b"160000"}
                    and b"/" not in name
                    and name not in seen,
                    "ambiguous Git tree entry",
                )
                seen.add(name)
                entry_oid = data[end + 1 : end + 21].hex()
                if name == part.encode("utf-8"):
                    found = (mode, entry_oid)
                offset = end + 21
            _require(found is not None, "artifact is absent from immutable Git tree")
            assert found is not None
            mode, tree = found
            if index != len(parts) - 1:
                _require(mode == b"40000", "artifact traverses a symlink or non-tree")
            else:
                _require(mode in {b"100644", b"100755"}, "artifact is not a regular Git file")
        return self._object(tree, "blob")

    def read_annotated_tag(self, name: str) -> AnnotatedTag:
        _require(
            type(name) is str
            and _TAG.fullmatch(name) is not None
            and not name.endswith(".")
            and ".." not in name,
            "exact fixed tag name required",
        )
        output = self._run(("rev-parse", "--verify", "--end-of-options", "refs/tags/" + name), 41)
        _require(re.fullmatch(rb"[0-9a-f]{40}\n", output) is not None, "ambiguous Git tag ref")
        oid = output[:-1].decode("ascii")
        payload = self._object(oid, "tag")
        headers, separator, message = payload.partition(b"\n\n")
        lines = headers.split(b"\n")
        _require(bool(separator) and len(lines) == 4, "malformed annotated tag headers")
        target = re.fullmatch(rb"object ([0-9a-f]{40})", lines[0])
        _require(
            target is not None
            and lines[1] == b"type commit"
            and lines[2] == b"tag " + name.encode("ascii")
            and lines[3].startswith(b"tagger ")
            and len(lines[3]) > 7,
            "annotated tag identity/type mismatch",
        )
        assert target is not None
        target_oid = target.group(1).decode("ascii")
        self.resolve_commit(target_oid)
        _require(bool(message), "empty annotated tag attestation")
        return AnnotatedTag(oid, target_oid, message)


class TagPublisher(GitReader):
    """Local fixed-tag CAS only; the caller must first verify the signed claim.

    No method pushes, creates commits, signs, replaces a fixed ref, or gives a
    tag any authority. The immutable object's identity is recomputed and remote
    publication remains a separately governed operation.
    """

    def prepare_standalone_clone(
        self,
        closure_commit: str,
        destination: Path,
        *,
        empty_template: Path,
    ) -> None:
        """Create a fresh owned local-only historical clone at exact C3.

        The clone and template paths must both be absent beneath one governed
        run directory. Failures preserve diagnostics; no path is deleted or
        reused. The frozen Windows factory pins the upload-pack executable.
        """
        self.resolve_commit(closure_commit)
        _require(
            self.read_annotated_tag(successor.SUCCESSOR_TAG).target_commit == closure_commit,
            "standalone replay must follow fixed-tag publication of C3",
        )
        root = self.repository_root.absolute()
        relative, run = _clone_destination(root, destination)
        require_qualified_clone_path(destination)
        _require(
            empty_template.absolute() == destination.absolute().parent / "empty-template",
            "clone template must use the exact governed empty-template path",
        )
        head_before = self._run(("rev-parse", "--verify", "--end-of-options", "HEAD"), 41)
        index_before = self._index_snapshot()
        with ExitStack() as stack:
            parent = stack.enter_context(_open_clone_directory(root, "."))
            parts: list[str] = []
            for component in (".tmp", "s1-acceptance", "successor-v3", run):
                parts.append(component)
                try:
                    child = _open_clone_directory(root, Path(*parts))
                except FileNotFoundError:
                    with claim_rooted_directory(
                        parent, component, label="historical clone parent"
                    ) as claim:
                        expected = claim.device, claim.inode
                    child = _open_clone_directory(root, Path(*parts))
                    _require(
                        (child.device, child.inode) == expected,
                        "clone parent replaced before pinning",
                    )
                parent = stack.enter_context(child)
            for name in ("empty-template", "clone"):
                with claim_rooted_directory(
                    parent, name, label="fresh historical clone directory"
                ) as claim:
                    expected = claim.device, claim.inode
                lease = stack.enter_context(_open_clone_directory(root, Path(*parts, name)))
                _require(
                    (lease.device, lease.inode) == expected,
                    "clone directory replaced before pinning",
                )
                _require(
                    lease.entry_names(max_entries=0, label="fresh clone directory") == (),
                    "historical clone directory is not empty",
                )
            self._run(
                (
                    "-C",
                    str(destination.absolute().parent),
                    "-c",
                    "core.longpaths=true",
                    "clone",
                    "--no-local",
                    "--no-checkout",
                    "--quiet",
                    "--no-progress",
                    "--template=" + str(empty_template.absolute()),
                    "--",
                    str(root),
                    "clone",
                ),
                4096,
            )
            # Parent-runner prefixes remain authenticated; only the final -C
            # selects the newly owned child for non-network metadata/checkout.
            prefix = ("-C", str(destination.absolute()), "-c", "core.longpaths=true")
            approved = "https://github.com/acblabs/agent-assure.git"
            self._run((*prefix, "config", "--local", "remote.origin.url", approved), 0)
            self._run(
                (
                    *prefix,
                    "checkout",
                    "--quiet",
                    "--detach",
                    "--no-recurse-submodules",
                    closure_commit,
                    "--",
                ),
                4096,
            )
            _require(
                self._run((*prefix, "rev-parse", "--verify", "--end-of-options", "HEAD"), 41)
                == closure_commit.encode("ascii") + b"\n",
                "historical clone HEAD differs",
            )
            _require(
                self._run(
                    (*prefix, "status", "--porcelain=v1", "--untracked-files=all"),
                    MAX_CHANGED_PATH_BYTES,
                )
                == b"",
                "historical clone is not clean",
            )
            _require(
                self._run((*prefix, "rev-parse", "--is-shallow-repository"), 16) == b"false\n",
                "historical clone is shallow",
            )
            _validate_local_config(
                self._run(
                    (*prefix, "config", "--local", "--no-includes", "--null", "--list"), 131_072
                ),
                approved,
            )
            stack.enter_context(_open_clone_directory(root, relative / ".git"))
            alternates = destination / ".git/objects/info/alternates"
            try:
                metadata = alternates.lstat()
            except FileNotFoundError:
                pass
            else:
                _require(
                    stat.S_ISREG(metadata.st_mode)
                    and not stat.S_ISLNK(metadata.st_mode)
                    and not getattr(metadata, "st_file_attributes", 0) & 0x400
                    and metadata.st_size == 0,
                    "historical clone has alternate object stores",
                )
            _require(
                self._run(("rev-parse", "--verify", "--end-of-options", "HEAD"), 41) == head_before
                and self._index_snapshot() == index_before,
                "standalone cloning changed the source HEAD or index",
            )

    def _write_object(self, kind: str, payload: bytes) -> str:
        _require(
            kind in {"blob", "tree", "commit"} and len(payload) <= MAX_OBJECT_BYTES,
            "bounded closure object required",
        )
        oid = _object_oid(kind, payload)
        output = self._run(("hash-object", "-t", kind, "-w", "--stdin"), 41, input_bytes=payload)
        _require(output == oid.encode("ascii") + b"\n", "closure object write changed identity")
        _require(self._object(oid, kind) == payload, "closure object read-back changed bytes")
        return oid

    def _index_snapshot(self) -> tuple[int, int, str]:
        path = self.repository_root / ".git/index"
        admitted = path.lstat()
        _require(
            stat.S_ISREG(admitted.st_mode)
            and not stat.S_ISLNK(admitted.st_mode)
            and not getattr(admitted, "st_file_attributes", 0) & 0x400
            and admitted.st_nlink == 1
            and admitted.st_size <= MAX_TREE_BYTES,
            "bounded unlinked Git index required",
        )
        with path.open("rb") as handle:
            before = os.fstat(handle.fileno())
            _require(
                (before.st_dev, before.st_ino) == (admitted.st_dev, admitted.st_ino),
                "Git index changed before bounded read",
            )
            payload = handle.read(MAX_TREE_BYTES + 1)
            after = os.fstat(handle.fileno())
        # On native Windows, fstat/lstat can expose different ctime meanings.
        # Compare ctime within each API, and object identity/size/mtime across
        # both APIs; access time is intentionally irrelevant to read stability.
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns")
        current = path.lstat()
        _require(
            len(payload) == admitted.st_size
            and len(payload) <= MAX_TREE_BYTES
            and current.st_nlink == 1
            and before.st_ctime_ns == after.st_ctime_ns
            and admitted.st_ctime_ns == current.st_ctime_ns
            and all(
                getattr(before, key) == getattr(after, key) == getattr(current, key)
                for key in fields
            ),
            "Git index changed during bounded read",
        )
        return admitted.st_dev, admitted.st_ino, hashlib.sha256(payload).hexdigest()

    def create_closure_commit(
        self,
        result_commit: str,
        receipt_bytes: bytes,
        *,
        committer_person_id: str,
        observed_at: datetime,
    ) -> successor.GitCommit:
        """Write a receipt-only C3 object without changing checkout, index or refs.

        The human signature and all source-specific evidence must already have
        been verified by the host controller. This leaf verifies closed receipt
        structure/subject and immutable Git topology; it never grants acceptance.
        """
        _require(
            type(committer_person_id) is str
            and _IDENTITY.fullmatch(committer_person_id) is not None,
            "canonical committer identity required",
        )
        _require(
            isinstance(observed_at, datetime)
            and observed_at.tzinfo is not None
            and observed_at.utcoffset() == UTC.utcoffset(observed_at)
            and observed_at.microsecond == 0,
            "whole-second UTC commit observation required",
        )
        record = successor._load_json(receipt_bytes, canonical=False)
        successor._check_receipt_shape(record)
        _require(
            record["status"] == "accepted_for_development"
            and type(record["signature_envelope"]) is dict
            and record["result_commit"] == result_commit,
            "closure requires the signed accepted receipt for exact R3",
        )
        root_tree, _ = self._commit(result_commit)
        expected_head = result_commit.encode("ascii") + b"\n"
        _require(
            self._run(("rev-parse", "--verify", "--end-of-options", "HEAD"), 41) == expected_head,
            "closure preparation requires clean capture checkout HEAD=R3",
        )
        self._run(("diff-index", "--cached", "--quiet", "--no-ext-diff", result_commit, "--"), 0)
        self._run(("diff-files", "--quiet", "--no-ext-diff", "--"), 0)
        index_before = self._index_snapshot()
        parts = tuple(part.encode("utf-8") for part in _path(successor.RECEIPT_PATH))
        new_blob = self._write_object("blob", receipt_bytes)
        traversed = 0

        def replace_entry(tree_oid: str | None, depth: int) -> str:
            nonlocal traversed
            remaining = MAX_TREE_TRAVERSAL_BYTES - traversed
            data = (
                b""
                if tree_oid is None
                else self._object(tree_oid, "tree", min(MAX_TREE_BYTES, remaining))
            )
            traversed += len(data)
            _require(traversed <= MAX_TREE_TRAVERSAL_BYTES, "closure tree traversal exceeds budget")
            entries: dict[bytes, tuple[bytes, str]] = {}
            order: list[bytes] = []
            offset = 0
            while offset < len(data):
                space = data.find(b" ", offset)
                end = data.find(b"\0", space + 1)
                _require(
                    space > offset and end > space + 1 and end + 21 <= len(data),
                    "malformed closure source tree",
                )
                mode, name = data[offset:space], data[space + 1 : end]
                _require(
                    mode in {b"40000", b"100644", b"100755", b"120000", b"160000"}
                    and b"/" not in name
                    and name not in {b".", b".."}
                    and name not in entries,
                    "ambiguous closure source tree",
                )
                entries[name] = mode, data[end + 1 : end + 21].hex()
                order.append(name + (b"/" if mode == b"40000" else b""))
                offset = end + 21
            _require(order == sorted(order), "noncanonical closure source tree order")
            name = parts[depth]
            if depth == len(parts) - 1:
                _require(name not in entries, "successor receipt already exists at R3")
                entries[name] = b"100644", new_blob
            else:
                prior = entries.get(name)
                _require(prior is None or prior[0] == b"40000", "closure path traverses non-tree")
                entries[name] = (
                    b"40000",
                    replace_entry(None if prior is None else prior[1], depth + 1),
                )
            names = sorted(
                entries, key=lambda item: item + (b"/" if entries[item][0] == b"40000" else b"")
            )
            updated = b"".join(
                entries[name][0] + b" " + name + b"\0" + bytes.fromhex(entries[name][1])
                for name in names
            )
            return self._write_object("tree", updated)

        tree = replace_entry(root_tree, 0)
        epoch = int(observed_at.timestamp())
        _require(epoch >= 0, "commit observation predates the Unix epoch")
        identity = f"{committer_person_id} <governance@agent-assure.invalid> {epoch} +0000"
        payload = (
            f"tree {tree}\nparent {result_commit}\nauthor {identity}\ncommitter {identity}\n\n"
            "Agent Assure S1 successor receipt-only closure v3\n"
        ).encode("ascii")
        oid = self._write_object("commit", payload)
        result = self.resolve_commit(oid)
        _require(
            result.parents == (result_commit,)
            and self.changed_paths(result_commit, oid) == (successor.RECEIPT_PATH,),
            "closure changes more than its exact receipt path",
        )
        _require(
            self.read_commit_artifact(oid, successor.RECEIPT_PATH) == receipt_bytes,
            "closure receipt read-back differs",
        )
        _require(
            self._run(("rev-parse", "--verify", "--end-of-options", "HEAD"), 41) == expected_head
            and self._index_snapshot() == index_before,
            "closure object creation changed checkout HEAD or index",
        )
        return result

    def publish_fixed_tag(
        self,
        name: str,
        target_commit: str,
        message: bytes,
        *,
        tagger_person_id: str,
        observed_at: datetime,
    ) -> AnnotatedTag:
        _require(
            name == successor.SUCCESSOR_TAG, "only the new fixed successor tag may be published"
        )
        self.resolve_commit(target_commit)
        _require(
            type(tagger_person_id) is str and _IDENTITY.fullmatch(tagger_person_id) is not None,
            "canonical tagger identity required",
        )
        _require(
            isinstance(observed_at, datetime)
            and observed_at.tzinfo is not None
            and observed_at.utcoffset() == UTC.utcoffset(observed_at)
            and observed_at.microsecond == 0,
            "whole-second UTC tag observation required",
        )
        _require(
            type(message) is bytes and 0 < len(message) < MAX_OBJECT_BYTES - 1024,
            "bounded canonical tag message required",
        )
        try:
            successor._load_json(message, canonical=True)
        except (ValueError, TypeError) as exc:
            raise SuccessorIOError("tag message must be canonical JSON object bytes") from exc
        ref = "refs/tags/" + name
        symbolic = self._run(("symbolic-ref", "--quiet", ref), 256, allowed_codes=(0, 1))
        _require(not symbolic, "fixed successor ref must not be symbolic")
        existing = self._run(
            ("rev-parse", "--verify", "--quiet", "--end-of-options", ref), 41, allowed_codes=(0, 1)
        )
        if existing:
            tag = self.read_annotated_tag(name)
            _require(
                tag.target_commit == target_commit and tag.message == message,
                "fixed successor tag already exists with different bytes",
            )
            return tag
        epoch = int(observed_at.timestamp())
        _require(epoch >= 0, "tag observation predates the Unix epoch")
        payload = (
            f"object {target_commit}\ntype commit\ntag {name}\n"
            f"tagger {tagger_person_id} <governance@agent-assure.invalid> {epoch} +0000\n\n"
        ).encode("ascii") + message
        expected_oid = _object_oid("tag", payload)
        output = self._run(("hash-object", "-t", "tag", "-w", "--stdin"), 41, input_bytes=payload)
        _require(
            output == expected_oid.encode("ascii") + b"\n", "written tag object identity differs"
        )
        # CAS failures are not force-retried. A simultaneous equal winner is
        # accepted only after exact object/type/target/message read-back.
        self._run(
            ("update-ref", "--no-deref", ref, expected_oid, "0" * 40), 0, allowed_codes=(0, 1, 128)
        )
        tag = self.read_annotated_tag(name)
        _require(
            tag.target_commit == target_commit and tag.message == message,
            "fixed-tag CAS lost to a conflicting value",
        )
        return tag


def require_qualified_clone_path(destination: Path) -> None:
    """Reject unsupported native Git depth before creating directories/objects."""
    git_dir_bytes = len(str((destination / ".git").absolute()).encode("utf-8"))
    _require(
        os.name != "nt" or git_dir_bytes <= MAX_PINNED_WINDOWS_GIT_DIR_BYTES,
        "CLONE_GIT_PATH_LIMIT_EXCEEDED: pinned Windows Git requires the absolute .git path "
        "to be at most 220 UTF-8 bytes; shorten the capture root or run identifier",
    )


def _open_clone_directory(root: Path, relative: str | Path) -> RootedDirectoryDescriptor:
    try:
        return open_rooted_directory(root, relative, label="historical clone directory")
    except FileNotFoundError:
        raise
    except (ValueError, OSError) as exc:
        raise SuccessorIOError("historical clone path is not a safe pinned directory") from exc


def _clone_destination(root: Path, destination: Path) -> tuple[Path, str]:
    try:
        relative = destination.absolute().relative_to(root.absolute())
    except ValueError as exc:
        raise SuccessorIOError("clone destination escapes the governed workspace") from exc
    parts = relative.parts
    _require(
        len(parts) == 5
        and parts[:3] == (".tmp", "s1-acceptance", "successor-v3")
        and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", parts[3]) is not None
        and parts[3]
        not in {
            "con",
            "prn",
            "aux",
            "nul",
            *(f"{prefix}{index}" for prefix in ("com", "lpt") for index in range(1, 10)),
        }
        and parts[4] == "clone",
        "exact fresh governed clone path required",
    )
    return relative, parts[3]


def _utc(value: str) -> datetime:
    _require(
        type(value) is str and _UTC.fullmatch(value) is not None,
        "strict UTC authority time required",
    )
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SuccessorIOError("invalid authority time") from exc


def _ssh_string(data: bytes, offset: int) -> tuple[bytes, int]:
    _require(offset + 4 <= len(data), "truncated SSH framing")
    size = int.from_bytes(data[offset : offset + 4], "big")
    start = offset + 4
    _require(start + size <= len(data), "truncated SSH string")
    return data[start : start + size], start + size


def _key_blob(public_key: str) -> bytes:
    _require(
        type(public_key) is str and len(public_key) < 256, "bounded Ed25519 public key required"
    )
    parts = public_key.split(" ")
    _require(len(parts) == 2 and parts[0] == "ssh-ed25519", "canonical Ed25519 public key required")
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except ValueError as exc:
        raise SuccessorIOError("invalid Ed25519 public-key encoding") from exc
    _require(base64.b64encode(blob).decode("ascii") == parts[1], "noncanonical public-key base64")
    algorithm, offset = _ssh_string(blob, 0)
    key, end = _ssh_string(blob, offset)
    _require(
        algorithm == b"ssh-ed25519" and len(key) == 32 and end == len(blob),
        "malformed Ed25519 public-key blob",
    )
    return blob


def _signature_shape(encoded: str, key_blob: bytes) -> None:
    _require(
        type(encoded) is str and 0 < len(encoded) <= MAX_SIGNATURE_BYTES,
        "bounded SSHSIG envelope required",
    )
    try:
        armor = base64.b64decode(encoded, validate=True)
        _require(
            base64.b64encode(armor).decode("ascii") == encoded, "noncanonical signature base64"
        )
        text = armor.decode("ascii")
    except (ValueError, UnicodeError) as exc:
        raise SuccessorIOError("invalid signature encoding") from exc
    lines = text.split("\n")
    _require(
        len(lines) >= 4
        and lines[0] == "-----BEGIN SSH SIGNATURE-----"
        and lines[-2:] == ["-----END SSH SIGNATURE-----", ""],
        "noncanonical SSHSIG armor",
    )
    body = lines[1:-2]
    _require(
        bool(body) and all(len(line) == 70 for line in body[:-1]) and 1 <= len(body[-1]) <= 70,
        "noncanonical SSHSIG armor wrapping",
    )
    try:
        blob = base64.b64decode("".join(body), validate=True)
    except ValueError as exc:
        raise SuccessorIOError("invalid SSHSIG armor base64") from exc
    _require(base64.b64encode(blob).decode("ascii") == "".join(body), "noncanonical SSHSIG payload")
    _require(blob[:10] == b"SSHSIG\x00\x00\x00\x01", "unsupported SSHSIG version")
    offset = 10
    fields: list[bytes] = []
    for _ in range(5):
        field, offset = _ssh_string(blob, offset)
        fields.append(field)
    _require(
        offset == len(blob)
        and fields[:4] == [key_blob, b"agent-assure-governance-v1", b"", b"sha512"],
        "SSHSIG key/namespace/hash binding mismatch",
    )
    algorithm, position = _ssh_string(fields[4], 0)
    signature, end = _ssh_string(fields[4], position)
    _require(
        algorithm == b"ssh-ed25519" and len(signature) == 64 and end == len(fields[4]),
        "SSHSIG is not a canonical Ed25519 signature",
    )


def public_key_fingerprint(public_key: str) -> str:
    """OpenSSH fingerprint of one validated canonical Ed25519 public key."""
    encoded = base64.b64encode(hashlib.sha256(_key_blob(public_key)).digest()).decode("ascii")
    return "SHA256:" + encoded.rstrip("=")


def verify(
    payload: bytes,
    envelope: Mapping[str, Any],
    trusted_key: TrustedKey,
    oldverifycallback: SSHVerifier,
    *,
    now: Callable[[], datetime],
    purpose: str,
) -> successor.VerifiedSignature:
    """Verify exact bytes with existing OpenSSH, then apply separately trusted authority."""
    _require(
        type(payload) is bytes and len(payload) <= MAX_OBJECT_BYTES,
        "bounded signature payload required",
    )
    _require(
        type(trusted_key) is TrustedKey and callable(oldverifycallback) and callable(now),
        "trusted key/verifier/clock required",
    )
    for value in (trusted_key.person_id, trusted_key.role):
        _require(
            type(value) is str and _IDENTITY.fullmatch(value) is not None,
            "invalid authority identity",
        )
    _require(
        type(trusted_key.key_id) is str
        and len(trusted_key.key_id) <= 256
        and (
            _IDENTITY.fullmatch(trusted_key.key_id) is not None
            or trusted_key.key_id == public_key_fingerprint(trusted_key.public_key)
        ),
        "key ID must be an adopted opaque label or exact public-key fingerprint",
    )
    for values in (trusted_key.competence_scopes, trusted_key.allowed_purposes):
        _require(
            type(values) is tuple
            and bool(values)
            and len(values) <= 128
            and all(type(value) is str and 0 < len(value) <= 256 for value in values),
            "invalid adopted authority scopes",
        )
        _require(len(values) == len(set(values)), "duplicate adopted authority scope")
    _require(
        type(trusted_key.trust_snapshot_digest) is str
        and _DIGEST.fullmatch(trusted_key.trust_snapshot_digest) is not None,
        "adopted trust snapshot digest required",
    )
    _require(
        purpose in trusted_key.allowed_purposes, "signature purpose is outside adopted key scope"
    )
    _require(
        type(envelope) is dict
        and set(envelope) == {"profile", "namespace", "signer_person_id", "key_id", "signature"},
        "closed signature envelope required",
    )
    _require(
        envelope["profile"] == successor.SIGNATURE_PROFILE
        and envelope["namespace"] == successor.SIGNATURE_NAMESPACE
        and envelope["signer_person_id"] == trusted_key.person_id
        and envelope["key_id"] == trusted_key.key_id,
        "signature authority substitution",
    )
    blob = _key_blob(trusted_key.public_key)
    _signature_shape(envelope["signature"], blob)
    begin = now()
    _require(
        isinstance(begin, datetime)
        and begin.tzinfo is not None
        and begin.utcoffset() == UTC.utcoffset(begin),
        "UTC verification clock required",
    )
    start, expiry = _utc(trusted_key.valid_from_utc), _utc(trusted_key.valid_until_utc)
    _require(start <= begin < expiry, "signature authority not current at verification start")
    result: Any = oldverifycallback(  # type: ignore[func-returns-value]
        signature_base64=envelope["signature"],
        payload=payload,
        signer_person_id=trusted_key.person_id,
        public_key=trusted_key.public_key,
    )
    _require(result is None, "signature verifier must raise on failure, not return a success flag")
    completed = now()
    _require(
        isinstance(completed, datetime)
        and completed.tzinfo is not None
        and completed.utcoffset() == UTC.utcoffset(completed)
        and begin <= completed < expiry,
        "authority expired or clock regressed during verification",
    )
    return successor.VerifiedSignature(
        successor.content_digest(payload),
        trusted_key.person_id,
        trusted_key.role,
        trusted_key.competence_scopes,
        trusted_key.trust_snapshot_digest,
        trusted_key.valid_from_utc,
        trusted_key.valid_until_utc,
        completed.isoformat().replace("+00:00", "Z"),
    )


def _bounded_process(
    argv: list[str],
    environment: Mapping[str, str],
    limits: tuple[int, int],
    input_bytes: bytes | None = None,
) -> subprocess.CompletedProcess[bytes]:
    _require(
        input_bytes is None
        or (type(input_bytes) is bytes and len(input_bytes) <= MAX_OBJECT_BYTES),
        "bounded subprocess input required",
    )
    process = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL if input_bytes is None else subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=dict(environment),
        shell=False,
    )
    chunks: list[bytearray] = [bytearray(), bytearray()]
    overflow = threading.Event()
    errors: list[BaseException] = []

    def stop() -> None:
        try:
            process.kill()
        except OSError:
            pass

    def read(index: int, stream: Any) -> None:
        try:
            while True:
                block = stream.read(min(65_536, limits[index] + 1 - len(chunks[index])))
                if not block:
                    break
                chunks[index].extend(block)
                if len(chunks[index]) > limits[index]:
                    overflow.set()
                    stop()
                    break
        except BaseException as exc:
            errors.append(exc)
            overflow.set()
            stop()
        finally:
            stream.close()

    threads = [
        threading.Thread(target=read, args=(index, stream), daemon=True)
        for index, stream in enumerate((process.stdout, process.stderr))
    ]
    if input_bytes is not None:

        def feed() -> None:
            assert process.stdin is not None
            try:
                process.stdin.write(input_bytes)
                process.stdin.flush()
            except (OSError, ValueError):
                pass
            finally:
                process.stdin.close()

        threads.append(threading.Thread(target=feed, daemon=True))
    try:
        for thread in threads:
            thread.start()
        deadline = time.monotonic() + 30
        while process.poll() is None and not overflow.is_set() and time.monotonic() < deadline:
            overflow.wait(0.02)
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
        for thread in threads:
            thread.join(timeout=5)
        _require(
            not any(thread.is_alive() for thread in threads), "Git pipe reader did not terminate"
        )
        _require(not errors and not overflow.is_set(), "Git output exceeded bounded capture")
        _require(time.monotonic() < deadline, "bounded Git inspection timed out")
        return subprocess.CompletedProcess(
            argv, process.returncode, bytes(chunks[0]), bytes(chunks[1])
        )
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def frozen_git_reader(governance: Any, repository_root: Path) -> GitReader:
    """Create the real adapter only inside the existing authenticated S1 entrypoint."""

    def require_runtime() -> None:
        _require(
            governance._main_has_active_runtime_bootstrap() is True,
            "successor Git adapter requires the frozen S1 launcher",
        )

    def preflight(root: Path) -> None:
        require_runtime()
        governance._post_r2_safe_directory(root, owner="successor repository root")
        governance._post_r2_safe_directory(root / ".git", owner="successor .git root")
        config = root / ".git/config"
        metadata = config.lstat()
        _require(
            stat.S_ISREG(metadata.st_mode)
            and not stat.S_ISLNK(metadata.st_mode)
            and not getattr(metadata, "st_file_attributes", 0) & 0x400
            and metadata.st_size <= 131_072,
            "bounded regular local Git config required",
        )

        def inspect(arguments: Sequence[str], limit: int) -> bytes:
            result = runner(arguments, max_stdout_bytes=limit, max_stderr_bytes=MAX_STDERR_BYTES)
            _require(
                result.returncode == 0
                and len(result.stdout) <= limit
                and len(result.stderr) <= MAX_STDERR_BYTES,
                "bounded Git metadata inspection failed",
            )
            return result.stdout

        for query, expected in (
            ("--show-toplevel", root.resolve()),
            ("--absolute-git-dir", (root / ".git").resolve()),
        ):
            try:
                observed = Path(
                    inspect(("rev-parse", query), 4096).decode("utf-8").strip()
                ).resolve()
            except UnicodeError as exc:
                raise SuccessorIOError("non-UTF8 Git repository identity") from exc
            _require(observed == expected, "Git repository identity differs from trusted root")
        raw_config = inspect(("config", "--local", "--no-includes", "--null", "--list"), 131_072)
        _validate_local_config(raw_config, governance.APPROVED_ORIGIN_URL)
        _require(
            not inspect(
                ("for-each-ref", "--count=1", "--format=%(refname)", "refs/replace/"), 4096
            ).strip(),
            "Git replacement refs are forbidden",
        )
        _require(
            inspect(("rev-parse", "--is-shallow-repository"), 16) == b"false\n",
            "full Git history required",
        )
        for relative in ("info/grafts", "objects/info/alternates", "shallow"):
            path = root / ".git" / relative
            try:
                metadata = path.lstat()
            except FileNotFoundError:
                continue
            _require(
                stat.S_ISREG(metadata.st_mode)
                and not stat.S_ISLNK(metadata.st_mode)
                and not getattr(metadata, "st_file_attributes", 0) & 0x400
                and metadata.st_size == 0,
                "Git grafts/alternates/shallow metadata forbidden",
            )
        governance._post_v2_control_git_metadata_preflight(root)

    def runner(
        arguments: Sequence[str],
        *,
        max_stdout_bytes: int,
        max_stderr_bytes: int,
        input_bytes: bytes | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        require_runtime()
        executable = governance._trusted_executable("git", repository_root=repository_root)
        command = list(arguments)
        environment = governance._governance_subprocess_environment()
        clone_prefix: list[str] = []
        clone_parent: Path | None = None
        # This fixed option must precede clone itself: Windows index-pack may
        # otherwise fail before the later checkout gets its own longpath flag.
        if (
            len(command) >= 5
            and command[0] == "-C"
            and command[2:5] == ["-c", "core.longpaths=true", "clone"]
        ):
            clone_parent = Path(command[1]).absolute()
            command = command[4:]
        elif command[:3] == ["-c", "core.longpaths=true", "clone"]:
            command = command[2:]
        if command[:1] == ["clone"]:
            _require(
                len(command) == 9
                and command[:5]
                == ["clone", "--no-local", "--no-checkout", "--quiet", "--no-progress"]
                and command[5].startswith("--template=")
                and command[6] == "--"
                and command[7] == str(repository_root.absolute()),
                "only exact governed local cloning is permitted",
            )
            if clone_parent is None:
                destination = Path(command[8])
            else:
                _require(
                    command[8] == "clone", "owned clone must use its literal relative child name"
                )
                destination = clone_parent / "clone"
            _clone_destination(repository_root, destination)
            _require(
                Path(command[5][11:]).absolute()
                == destination.absolute().parent / "empty-template",
                "clone template differs from owned run directory",
            )
            upload = frozen_upload_pack_identity(governance)
            command.insert(
                6, "--upload-pack=" + shlex.quote(str(upload["path"]).replace("\\", "/"))
            )
            environment["GIT_ALLOW_PROTOCOL"] = "file"
            clone_prefix = ["-c", "protocol.file.allow=always", "-c", "core.longpaths=true"]
            if clone_parent is not None:
                clone_prefix = ["-C", str(clone_parent), *clone_prefix]
        with tempfile.TemporaryDirectory(prefix="agent-assure-successor-hooks-") as temporary:
            argv = [
                *governance._git_invocation_prefix(executable, Path(temporary)),
                "-c",
                f"safe.directory={repository_root.absolute()}",
                "-C",
                str(repository_root.absolute()),
                "-c",
                "core.longpaths=true",
                *clone_prefix,
                *command,
            ]
            return _bounded_process(
                argv,
                environment,
                (max_stdout_bytes, max_stderr_bytes),
                input_bytes,
            )

    require_runtime()
    require_qualified_clone_path(repository_root)
    return GitReader(repository_root, runner, preflight=preflight)


def frozen_upload_pack_identity(governance: Any) -> dict[str, Any]:
    """Admit only the same Git executable bytes under its upload-pack dispatch name."""
    _require(
        governance._main_has_active_runtime_bootstrap() is True,
        "upload-pack identity requires the frozen S1 launcher",
    )
    executable = Path(governance._trusted_executable("git"))
    helper = executable.with_name(
        "git-upload-pack.exe" if executable.suffix == ".exe" else "git-upload-pack"
    )
    governance._post_r2_safe_directory(helper.parent, owner="pinned Git upload-pack parent")
    info = helper.lstat()
    identity = governance.TRUSTED_EXECUTABLE_IDENTITIES["git"]
    _require(
        stat.S_ISREG(info.st_mode)
        and not stat.S_ISLNK(info.st_mode)
        and not getattr(info, "st_file_attributes", 0) & 0x400
        and info.st_size == identity.size_bytes <= MAX_TREE_BYTES,
        "upload-pack is not the same pinned Git executable profile",
    )
    digest = hashlib.sha256()
    with helper.open("rb") as handle:
        for block in iter(lambda: handle.read(65_536), b""):
            digest.update(block)
    _require(
        digest.hexdigest() == identity.sha256, "upload-pack executable bytes differ from pinned Git"
    )
    return {
        "path": str(helper),
        "size_bytes": info.st_size,
        "sha256": "sha256:" + digest.hexdigest(),
    }


def _validate_local_config(payload: bytes, approved_origin: str) -> None:
    """The existing S1 closed local-config language, with bounded capture."""
    exact = {
        "core.repositoryformatversion": {"0"},
        "core.filemode": {"true", "false"},
        "core.bare": {"false"},
        "core.logallrefupdates": {"true"},
        "core.symlinks": {"true", "false"},
        "core.ignorecase": {"true", "false"},
        "remote.origin.url": {approved_origin},
        "remote.origin.fetch": {"+refs/heads/*:refs/remotes/origin/*"},
        "gpg.format": {"ssh"},
        "tag.gpgsign": {"true"},
    }
    _require(payload.endswith(b"\x00"), "local Git config must be NUL terminated")
    observed: set[str] = set()
    for row in payload[:-1].split(b"\x00"):
        key_bytes, separator, value_bytes = row.partition(b"\n")
        _require(
            bool(separator) and bool(key_bytes) and b"\n" not in value_bytes and b"\r" not in row,
            "malformed local Git config",
        )
        try:
            key, value = key_bytes.decode("utf-8").casefold(), value_bytes.decode("utf-8")
        except UnicodeError as exc:
            raise SuccessorIOError("local Git config is not UTF-8") from exc
        _require(key not in observed, "duplicate local Git configuration key")
        observed.add(key)
        if key in exact:
            _require(value in exact[key], "local Git configuration changes trusted behavior")
        elif key in {"user.name", "user.email", "user.signingkey"}:
            _require(bool(value), "empty local Git user metadata")
        elif key.startswith("branch."):
            field = key.rpartition(".")[2]
            _require(
                (field == "remote" and value == "origin")
                or (field == "merge" and value.startswith("refs/heads/"))
                or (field == "vscode-merge-base" and value.startswith("origin/")),
                "unapproved branch configuration",
            )
        else:
            raise SuccessorIOError("unapproved local Git configuration key")
    _require("remote.origin.url" in observed, "approved repository origin is required")


def frozen_signature_callback(governance: Any) -> SSHVerifier:
    """Keep actual cryptographic verification in the already hardened OpenSSH boundary."""

    def callback(
        *, signature_base64: str, payload: bytes, signer_person_id: str, public_key: str
    ) -> None:
        _require(
            governance._main_has_active_runtime_bootstrap() is True,
            "successor signature adapter requires the frozen S1 launcher",
        )
        governance._verify_sshsig(
            signature_base64=signature_base64,
            payload=payload,
            signer_person_id=signer_person_id,
            public_key=public_key,
        )

    return callback


def frozen_tag_publisher(governance: Any, repository_root: Path) -> TagPublisher:
    """Use the same frozen Git boundary for an explicitly requested local CAS."""
    reader = frozen_git_reader(governance, repository_root)
    return TagPublisher(repository_root, reader._runner, preflight=reader._preflight)
