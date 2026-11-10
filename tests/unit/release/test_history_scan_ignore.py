from __future__ import annotations

import hashlib
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

import scripts.prepare_history_scan_ignore as history_scan_ignore
from scripts.prepare_history_scan_ignore import prepare_ignore

ROOT = Path(__file__).resolve().parents[3]
_PROOF = "docs/governance/v1/sprint2/correction-native-verification.json"


def _native_git_executable() -> str:
    available = shutil.which("git")
    if available is not None:
        return available
    if os.name != "nt":
        raise RuntimeError("native Git is required; no enrolled fallback exists for this platform")
    # The sealed Windows development profile already authenticates this exact
    # executable before every command. Recheck it here; do not broaden PATH or
    # discover another runtime through environment variables or installation search.
    enrolled = Path(r"C:\Program Files\Git\mingw64\bin\git.exe")
    metadata = enrolled.lstat()
    maximum = 8 * 1024 * 1024
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or bool(getattr(metadata, "st_file_attributes", 0) & 0x400)
        or metadata.st_size > maximum
    ):
        raise RuntimeError("enrolled Git must be a bounded regular non-reparse executable")
    with enrolled.open("rb") as stream:
        raw = stream.read(maximum + 1)
    if (
        len(raw) != metadata.st_size
        or len(raw) > maximum
        or hashlib.sha256(raw).hexdigest()
        != "cab4c4eea1d869cf9f7be73868dc9a90ad2df1b1b673e5f8c8714a576c25ea96"
    ):
        raise RuntimeError("enrolled Git executable bytes differ from the authenticated profile")
    return str(enrolled)


@pytest.fixture(autouse=True)
def _use_native_git(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(history_scan_ignore, "_GIT_EXECUTABLE", _native_git_executable())


def _git(repo: Path, *arguments: str) -> str:
    environment = dict(os.environ)
    environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    completed = subprocess.run(
        [
            history_scan_ignore._GIT_EXECUTABLE,
            "-c",
            "core.fsmonitor=false",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.longpaths=true",
            *arguments,
        ],
        cwd=repo,
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=15,
    )
    if completed.returncode != 0:
        diagnostic = completed.stderr[:2048].decode("utf-8", errors="replace")
        raise RuntimeError(
            f"history fixture Git {arguments[0]} failed ({completed.returncode}): {diagnostic}"
        )
    return completed.stdout.decode().strip()


def _repository(
    directory: Path,
    *,
    change: str = "",
    parents: str = "ordered",
    policy_override: bytes | None = None,
) -> tuple[Path, str, str, str, bytes]:
    repo = directory / "repository"
    repo.mkdir()
    _git(repo, "init", "--quiet")
    _git(repo, "config", "user.name", "History policy tests")
    _git(repo, "config", "user.email", "history-policy@example.invalid")
    _git(repo, "config", "core.autocrlf", "false")
    _git(repo, "config", "core.hooksPath", os.devnull)
    policy = ("1" * 40 + ":tests/static.py:generic-api-key:4\n").encode()
    if policy_override is not None:
        policy = policy_override
    (repo / ".gitleaksignore").write_bytes(policy)
    for path in ("Makefile", _PROOF):
        destination = repo / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((ROOT / path).read_bytes())
    _git(repo, "add", ".")
    original_tree = _git(repo, "write-tree")
    base = _git(repo, "commit-tree", original_tree, "-m", "base")
    if change:
        makefile = repo / "Makefile"
        raw = makefile.read_bytes()
        if change == "second-credential":
            raw += b"\nAPI_" + b"KEY=" + b"x" * 32 + b"\n"
        elif change == "same-line-credential":
            lines = raw.splitlines(keepends=True)
            lines[24] = lines[24].rstrip(b"\n") + b" # api_" + b"key=" + b"y" * 32 + b"\n"
            raw = b"".join(lines)
        elif change == "line":
            raw = b"\n" + raw
        elif change == "blob":
            raw += b"\n# unreviewed source bytes\n"
        else:
            raise AssertionError("unknown test mutation")
        makefile.write_bytes(raw)
        _git(repo, "add", ".")
    head_tree = _git(repo, "write-tree")
    head = _git(repo, "commit-tree", head_tree, "-p", base, "-m", "head")
    order = (base, head)
    if parents == "reversed":
        order = (head, base)
    elif parents == "single":
        order = (head,)
    elif parents == "three":
        third = _git(repo, "commit-tree", original_tree, "-m", "third")
        order = (base, head, third)
    arguments = [item for parent in order for item in ("-p", parent)]
    commit = _git(repo, "commit-tree", head_tree, *arguments, "-m", "merge")
    _git(repo, "update-ref", "refs/heads/main", commit)
    _git(repo, "symbolic-ref", "HEAD", "refs/heads/main")
    return repo, commit, base, head, policy


def test_exact_pr_merge_adds_only_eight_reviewed_commit_fingerprints(tmp_path: Path) -> None:
    repo, commit, base, head, policy = _repository(tmp_path)
    output = tmp_path / "gitleaksignore"
    derived = prepare_ignore(
        repo=repo, event="pull_request", commit=commit, base=base, head=head, output=output
    )
    expected = {
        f"{commit}:Makefile:generic-api-key:25",
        *(f"{commit}:{_PROOF}:generic-api-key:{line}" for line in (10, 19, 28, 37, 46, 55, 64)),
    }
    assert set(derived) == expected
    expected_bytes = policy + "".join(value + "\n" for value in sorted(expected)).encode()
    assert output.read_bytes() == expected_bytes
    assert (repo / ".gitleaksignore").read_bytes() == policy
    assert all(len(value.split(":")) == 4 for value in derived)


@pytest.mark.parametrize("change", ["second-credential", "same-line-credential", "line", "blob"])
def test_changed_reviewed_blob_never_receives_an_exception(tmp_path: Path, change: str) -> None:
    repo, commit, base, head, _policy = _repository(tmp_path, change=change)
    output = tmp_path / "gitleaksignore"
    with pytest.raises(ValueError, match="reviewed blob changed"):
        prepare_ignore(
            repo=repo, event="pull_request", commit=commit, base=base, head=head, output=output
        )
    assert not output.exists()


@pytest.mark.parametrize("parents", ["reversed", "single", "three"])
def test_wrong_merge_topology_never_receives_an_exception(tmp_path: Path, parents: str) -> None:
    repo, commit, base, head, _policy = _repository(tmp_path, parents=parents)
    output = tmp_path / "gitleaksignore"
    with pytest.raises(ValueError, match="merge parents differ"):
        prepare_ignore(
            repo=repo, event="pull_request", commit=commit, base=base, head=head, output=output
        )
    assert not output.exists()


@pytest.mark.parametrize("event", ["push", "schedule", "workflow_dispatch"])
def test_non_pr_events_preserve_static_policy_without_deriving_exceptions(
    tmp_path: Path, event: str
) -> None:
    repo, commit, _base, _head, policy = _repository(tmp_path)
    output = tmp_path / "gitleaksignore"
    assert (
        prepare_ignore(repo=repo, event=event, commit=commit, base="", head="", output=output) == ()
    )
    assert output.read_bytes() == policy


def test_push_event_cannot_claim_pr_merge_authority(tmp_path: Path) -> None:
    repo, commit, base, head, _policy = _repository(tmp_path)
    output = tmp_path / "gitleaksignore"
    with pytest.raises(ValueError, match="require a pull-request event"):
        prepare_ignore(repo=repo, event="push", commit=commit, base=base, head=head, output=output)
    assert not output.exists()


@pytest.mark.parametrize("field", ["commit", "base", "head"])
def test_event_identity_must_be_exact_canonical_hex(tmp_path: Path, field: str) -> None:
    repo, commit, base, head, _policy = _repository(tmp_path)
    identities = {"commit": commit, "base": base, "head": head}
    identities[field] = identities[field].upper() + "\n"
    output = tmp_path / "gitleaksignore"
    with pytest.raises(ValueError, match="identity|identities"):
        prepare_ignore(repo=repo, event="pull_request", output=output, **identities)
    assert not output.exists()


def test_temporary_policy_cannot_replace_source_or_existing_output(tmp_path: Path) -> None:
    repo, commit, base, head, policy = _repository(tmp_path)
    with pytest.raises(ValueError, match="outside the checkout"):
        prepare_ignore(
            repo=repo,
            event="pull_request",
            commit=commit,
            base=base,
            head=head,
            output=repo / ".gitleaksignore",
        )
    output = tmp_path / "gitleaksignore"
    output.write_bytes(b"retained output\n")
    with pytest.raises(FileExistsError):
        prepare_ignore(
            repo=repo, event="pull_request", commit=commit, base=base, head=head, output=output
        )
    assert output.read_bytes() == b"retained output\n"
    assert (repo / ".gitleaksignore").read_bytes() == policy


def test_git_replacement_objects_cannot_forge_the_event_parents(tmp_path: Path) -> None:
    repo, commit, base, head, _policy = _repository(tmp_path, parents="reversed")
    tree = _git(repo, "rev-parse", f"{commit}^{{tree}}")
    substitute = _git(repo, "commit-tree", tree, "-p", base, "-p", head, "-m", "replacement")
    _git(repo, "replace", commit, substitute)
    with pytest.raises(ValueError, match="merge parents differ"):
        prepare_ignore(
            repo=repo,
            event="pull_request",
            commit=commit,
            base=base,
            head=head,
            output=tmp_path / "gitleaksignore",
        )


@pytest.mark.parametrize(
    "policy",
    [
        b"Makefile:generic-api-key:25\n",
        ("1" * 40 + ":Makefile:generic-api-key:0\n").encode(),
        ("1" * 40 + ":Makefile:generic-api-key:25\n").encode() * 2,
        b"#" + b"a" * (64 * 1024),
    ],
    ids=("global", "zero-line", "duplicate", "oversize"),
)
def test_inherited_policy_cannot_introduce_global_or_malformed_suppressions(
    tmp_path: Path, policy: bytes
) -> None:
    repo, commit, base, head, _policy = _repository(tmp_path, policy_override=policy)
    output = tmp_path / "gitleaksignore"
    with pytest.raises(ValueError, match="policy|byte bound"):
        prepare_ignore(
            repo=repo, event="pull_request", commit=commit, base=base, head=head, output=output
        )
    assert not output.exists()
