"""Prepare exact PR-merge exceptions without omitting any history from scanning.

The static ignore policy remains commit scoped. Eight reviewed public facts can
reappear in GitHub's changing PR merge commit. Only that exact merge, its two
expected parents and the complete reviewed blobs may derive temporary entries.
This helper never changes detector rules or accepts global path/line ignores.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path

# Private test seam; the CLI keeps the normal CI executable lookup unchanged.
_GIT_EXECUTABLE = "git"

MAX_POLICY_BYTES = 64 * 1024
MAX_OBJECT_BYTES = 1024 * 1024
MAX_POLICY_ENTRIES = 1024
_OID = re.compile(r"[0-9a-f]{40}", flags=re.ASCII)
_FINGERPRINT = re.compile(
    r"[0-9a-f]{40}:[^:\x00-\x20\x7f]+:[a-z0-9-]+:[1-9][0-9]{0,7}",
    flags=re.ASCII,
)
_PROOF_PATH = "docs/governance/v1/sprint2/correction-native-verification.json"
_REVIEWED_BLOBS = (
    (
        "Makefile",
        "e7f2b14f65a07d7213d74522bea02bdc1a083a77",
        "fbda2add232c267fc84c2127370e754f68f678de4d532f8cb310bba0a957908f",
        (25,),
    ),
    (
        _PROOF_PATH,
        "d97bb0f1f4cac9d81eaddc53efde537138786617",
        "88e9c15d28919d21e3f74cf6dd4860fa64f7df911a9bc5e9bcb30f1dc1b2d062",
        (10, 19, 28, 37, 46, 55, 64),
    ),
)
_PUBLIC_VERIFICATION = re.compile(
    r'Good "agent-assure-governance-v1" signature for acblabs with ED25519 key '
    r"SHA256:[A-Za-z0-9+/]{43}\r\n",
    flags=re.ASCII,
)


def _git(repo: Path, *arguments: str, maximum: int = 256) -> bytes:
    # All calls below have fixed-size query output, or read an object only after
    # checking its advertised size. Disable replacement objects and ambient Git
    # overrides so parent/blob evidence comes from the requested object itself.
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update(
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_NO_LAZY_FETCH="1",
        GIT_NO_REPLACE_OBJECTS="1",
        GIT_OPTIONAL_LOCKS="0",
        GIT_TERMINAL_PROMPT="0",
    )
    completed = subprocess.run(
        [
            _GIT_EXECUTABLE,
            "-c",
            "core.fsmonitor=false",
            "-c",
            "protocol.allow=never",
            "--no-pager",
            *arguments,
        ],
        cwd=repo,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=15,
        check=False,
    )
    if completed.returncode != 0 or len(completed.stdout) > maximum:
        raise ValueError("history exception Git evidence is unavailable or exceeds its bound")
    return completed.stdout


def _object(repo: Path, oid: str, kind: str, maximum: int) -> bytes:
    if _OID.fullmatch(oid) is None:
        raise ValueError("history exception object identity is malformed")
    if _git(repo, "cat-file", "-t", oid) != kind.encode() + b"\n":
        raise ValueError("history exception object has an unexpected type")
    raw_size = _git(repo, "cat-file", "-s", oid)
    if re.fullmatch(rb"(?:0|[1-9][0-9]{0,8})\n", raw_size) is None:
        raise ValueError("history exception object size is malformed")
    size = int(raw_size)
    if size > maximum:
        raise ValueError("history exception object exceeds its byte bound")
    raw = _git(repo, "cat-file", kind, oid, maximum=maximum)
    if len(raw) != size:
        raise ValueError("history exception object changed during reading")
    return raw


def _blob(repo: Path, commit: str, path: str, maximum: int) -> tuple[str, bytes]:
    raw_oid = _git(repo, "rev-parse", "--verify", f"{commit}:{path}")
    oid = raw_oid.decode("ascii").rstrip("\n")
    if raw_oid != oid.encode() + b"\n" or _OID.fullmatch(oid) is None:
        raise ValueError("history exception blob identity is malformed")
    return oid, _object(repo, oid, "blob", maximum)


def _policy(data: bytes) -> set[str]:
    if len(data) > MAX_POLICY_BYTES:
        raise ValueError("history ignore policy exceeds its byte bound")
    text = data.decode("utf-8")
    if "\r" in text or (text and not text.endswith("\n")):
        raise ValueError("history ignore policy must have canonical LF framing")
    entries: set[str] = set()
    for line in text.splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        if _FINGERPRINT.fullmatch(value) is None:
            raise ValueError("history ignore policy requires exact commit fingerprints")
        if value in entries or len(entries) >= MAX_POLICY_ENTRIES:
            raise ValueError("history ignore policy is duplicated or exceeds its entry bound")
        entries.add(value)
    return entries


def _classify_reviewed_lines(path: str, data: bytes, lines: tuple[int, ...]) -> None:
    source_lines = data.decode("utf-8").splitlines()
    if any(line > len(source_lines) for line in lines):
        raise ValueError("reviewed history finding line is absent")
    if path == "Makefile":
        expected = "V1_SUCCESSOR_" + "CI_" + "TOKEN_" + "ENVIRONMENT ?="
        if lines != (25,) or source_lines[24] != expected:
            raise ValueError("reviewed empty declaration classification changed")
        return
    document = json.loads(data)
    checks = document.get("checks")
    if not isinstance(checks, list) or len(checks) != 8:
        raise ValueError("reviewed public verification inventory changed")
    for index, line in enumerate(lines):
        check = checks[index]
        value = json.loads("{" + source_lines[line - 1].strip().rstrip(",") + "}")
        if (
            not isinstance(check, dict)
            or type(check.get("exit_code")) is not int
            or check.get("exit_code") != 0
            or check.get("expected_valid") is not True
            or check.get("stderr") != ""
            or set(value) != {"stdout"}
            or value["stdout"] != check.get("stdout")
            or not isinstance(value["stdout"], str)
            or _PUBLIC_VERIFICATION.fullmatch(value["stdout"]) is None
        ):
            raise ValueError("reviewed public verification classification changed")


def prepare_ignore(
    *,
    repo: Path,
    event: str,
    commit: str,
    base: str,
    head: str,
    output: Path,
) -> tuple[str, ...]:
    if event not in {"pull_request", "push", "schedule", "workflow_dispatch"}:
        raise ValueError("history exception event is unsupported")
    if _OID.fullmatch(commit) is None:
        raise ValueError("history exception checkout identity is malformed")
    if _git(repo, "rev-parse", "--verify", "HEAD") != commit.encode() + b"\n":
        raise ValueError("history exception checkout does not match the event")
    _unused, policy = _blob(repo, commit, ".gitleaksignore", MAX_POLICY_BYTES)
    retained = _policy(policy)
    derived: tuple[str, ...] = ()
    if event == "pull_request":
        if (
            _OID.fullmatch(base) is None
            or _OID.fullmatch(head) is None
            or len({commit, base, head}) != 3
        ):
            raise ValueError("history exception PR parent identities are malformed")
        raw_commit = _object(repo, commit, "commit", MAX_OBJECT_BYTES)
        headers = raw_commit.partition(b"\n\n")[0].splitlines()
        parents = tuple(line[7:].decode("ascii") for line in headers if line.startswith(b"parent "))
        if parents != (base, head):
            raise ValueError("history exception PR merge parents differ from the event")
        pending: list[str] = []
        for path, expected_blob, expected_sha256, lines in _REVIEWED_BLOBS:
            blob, data = _blob(repo, commit, path, MAX_OBJECT_BYTES)
            if blob != expected_blob or hashlib.sha256(data).hexdigest() != expected_sha256:
                raise ValueError("history exception reviewed blob changed; review required")
            _classify_reviewed_lines(path, data, lines)
            pending.extend(f"{commit}:{path}:generic-api-key:{line}" for line in lines)
        if len(pending) != 8 or len(set(pending)) != 8:
            raise ValueError("history exception reviewed finding inventory changed")
        derived = tuple(sorted(set(pending) - retained))
    elif base or head:
        raise ValueError("history merge exceptions require a pull-request event")
    result = policy + "".join(value + "\n" for value in derived).encode("ascii")
    _policy(result)
    repo_root = repo.resolve(strict=True)
    destination = output.absolute()
    if destination.parent.resolve(strict=True) != destination.parent:
        raise ValueError("history ignore output parent must have an exact filesystem identity")
    if destination.is_relative_to(repo_root):
        raise ValueError("history ignore output must remain outside the checkout")
    if not stat.S_ISDIR(destination.parent.stat().st_mode):
        raise ValueError("history ignore output parent must be a directory")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(destination, flags, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(result)
    return derived


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        derived = prepare_ignore(
            repo=Path.cwd(),
            event=arguments.event,
            commit=arguments.commit,
            base=arguments.base,
            head=arguments.head,
            output=arguments.output,
        )
    except (OSError, UnicodeError, ValueError, subprocess.SubprocessError):
        parser.exit(1, "history-ignore: exact source/event proof failed; review required\n")
    print(f"history-ignore: exact temporary policy prepared; derived={len(derived)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
