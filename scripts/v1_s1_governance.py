"""Generate and validate the non-runtime Agent Assure v1 S1 planning forecast.

This module deliberately lives under ``scripts`` rather than the production
package.  S1 is a governance bundle, not an installable feature release.  The
private roadmap is an input and is never copied into a tracked artifact.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import importlib.machinery
import json
import math
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unicodedata
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from functools import wraps
from importlib.machinery import ModuleSpec
from pathlib import Path
from types import ModuleType
from typing import Any, Final, cast
from urllib.parse import urlsplit

# The S1 validator is deliberately host-bound.  Strict command execution starts
# with the reviewed base interpreter rather than the ignored, workspace-writable
# virtual-environment launcher.  ``-S`` is essential: unlike ``-I``, it prevents
# ``site`` and executable ``.pth`` files from running before this bootstrap.
_FROZEN_PYTHON_ROOT: Final = Path(
    r"C:\Users\user\AppData\Roaming\uv\python\cpython-3.12.13-windows-x86_64-none"
)
_FROZEN_PYTHON_EXECUTABLE: Final = _FROZEN_PYTHON_ROOT / "python.exe"
_FROZEN_PYTHON_EXECUTABLE_SIZE: Final = 91_648
_FROZEN_PYTHON_EXECUTABLE_SHA256: Final = (
    "88b9e780cfdc38597c7f53e20f7165262befa28d9a5e9470360d349e172ecf37"
)
_FROZEN_PYTHON_DLL: Final = _FROZEN_PYTHON_ROOT / "python312.dll"
_FROZEN_PYTHON_DLL_SIZE: Final = 6_969_856
_FROZEN_PYTHON_DLL_SHA256: Final = (
    "cf1be428af1ee607d8015e27411912276b9b02815a080457a1ece46c59d9b314"
)
_FROZEN_PYTHON_VERSION: Final = (3, 12, 13)
_FROZEN_PYTHON_CACHE_TAG: Final = "cpython-312"
_BASE_RUNTIME_INVENTORY_DOMAIN: Final = b"agent-assure:s1-base-python-runtime-inventory/v1\x00"
_FROZEN_BASE_RUNTIME_FILE_COUNT: Final = 2_766
_FROZEN_BASE_RUNTIME_SIZE_BYTES: Final = 54_224_916
_FROZEN_BASE_RUNTIME_SHA256: Final = (
    "4e2b76aeadc0f328a00b520b2dc6cb4991486eaa9496b18d5035bac7b63ea152"
)
_RUNTIME_INVENTORY_DOMAIN: Final = b"agent-assure:s1-python-runtime-inventory/v1\x00"
_RUNTIME_ROOTS: Final = (
    "attr",
    "attrs",
    "jsonschema",
    "jsonschema_specifications",
    "referencing",
    "rfc8785",
    "rpds",
    "typing_extensions.py",
)
_RUNTIME_TOP_LEVEL_IMPORTS: Final = frozenset(
    {
        "attr",
        "attrs",
        "jsonschema",
        "jsonschema_specifications",
        "referencing",
        "rfc8785",
        "rpds",
        "typing_extensions",
    }
)
_FROZEN_RUNTIME_FILE_COUNT: Final = 116
_FROZEN_RUNTIME_SIZE_BYTES: Final = 1_581_377
_FROZEN_RUNTIME_SHA256: Final = "a8a4451bde03104cc2a6dae38a30ae0bef63f717a39e5b996e05c10b83fdae02"
_LAUNCHER_PROFILE: Final = "agent-assure-s1-powershell-runtime-launcher/v1"
_LAUNCHER_PROFILE_ENV: Final = "AGENT_ASSURE_S1_LAUNCHER_PROFILE"
_LAUNCHER_RUNTIME_DIGEST_ENV: Final = "AGENT_ASSURE_S1_BASE_RUNTIME_SHA256"
_LAUNCHER_CHILD_PATH: Final = (
    str(_FROZEN_PYTHON_ROOT)
    + ";"
    + str(_FROZEN_PYTHON_ROOT / "DLLs")
    + r";C:\Windows\System32;C:\Windows"
)


class _GovernanceRuntimeImportGuard:
    """Prevent optional or attacker-added site packages from executing."""

    def __init__(self, site_packages: Path) -> None:
        self._site_packages = site_packages

    def _verify_site_origin(self, spec: ModuleSpec, *, fullname: str) -> ModuleSpec:
        candidates: list[Path] = []
        origin = spec.origin
        if origin is not None and origin != "namespace":
            candidates.append(Path(origin))
        if spec.submodule_search_locations is not None:
            candidates.extend(Path(value) for value in spec.submodule_search_locations)
        if not candidates:
            raise ImportError(f"approved S1 runtime import has no file origin: {fullname}")
        site_root = self._site_packages.resolve(strict=True)
        for candidate in candidates:
            try:
                candidate.resolve(strict=True).relative_to(site_root)
            except (OSError, ValueError) as exc:
                raise ImportError(
                    f"approved S1 runtime import escaped its inventory: {fullname}"
                ) from exc
        return spec

    def find_spec(
        self,
        fullname: str,
        path: Sequence[str] | None = None,
        target: ModuleType | None = None,
    ) -> ModuleSpec | None:
        del target
        top_level = fullname.partition(".")[0]
        if top_level in _RUNTIME_TOP_LEVEL_IMPORTS:
            search_path: Sequence[str]
            if path is None:
                search_path = [str(self._site_packages)]
            else:
                site_root = self._site_packages.resolve(strict=True)
                for value in path:
                    try:
                        Path(value).resolve(strict=True).relative_to(site_root)
                    except (OSError, ValueError) as exc:
                        raise ImportError(
                            f"approved S1 runtime package path escaped its inventory: {fullname}"
                        ) from exc
                search_path = path
            approved = importlib.machinery.PathFinder.find_spec(fullname, search_path)
            if approved is None:
                raise ImportError(f"approved S1 runtime import is absent: {fullname}")
            return self._verify_site_origin(approved, fullname=fullname)
        candidate = importlib.machinery.PathFinder.find_spec(fullname, [str(self._site_packages)])
        if candidate is not None:
            raise ImportError(f"unapproved S1 runtime import blocked: {fullname}")
        return None


_BOOTSTRAPPED_RUNTIME_GUARD: _GovernanceRuntimeImportGuard | None = None


def _early_normalized_path(path: str | Path) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(path)))


def _early_reject_reparse_path(path: Path, *, owner: str) -> None:
    """Reject every existing link/reparse component before trusting bytes."""

    absolute = Path(os.path.abspath(path))
    cursor = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        cursor /= component
        if not cursor.exists():
            raise RuntimeError(f"{owner} is missing: {cursor}")
        metadata = cursor.lstat()
        attributes = getattr(metadata, "st_file_attributes", 0)
        if cursor.is_symlink() or bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT):
            raise RuntimeError(f"{owner} contains a reparse point: {cursor}")


def _early_verify_file(
    path: Path,
    *,
    expected_size: int,
    expected_sha256: str,
    owner: str,
) -> None:
    _early_reject_reparse_path(path, owner=owner)
    if not path.is_file():
        raise RuntimeError(f"{owner} is not a regular file")
    metadata = path.stat()
    if metadata.st_size != expected_size:
        raise RuntimeError(f"{owner} byte length changed")
    with path.open("rb") as handle:
        observed = hashlib.file_digest(handle, "sha256").hexdigest()
    if observed != expected_sha256:
        raise RuntimeError(f"{owner} SHA-256 changed")


def _runtime_inventory(site_packages: Path) -> tuple[int, int, str]:
    """Hash the exact executable third-party surface without importing it."""

    _early_reject_reparse_path(site_packages, owner="S1 site-packages directory")
    rows: list[tuple[str, int, bytes]] = []
    for root_name in _RUNTIME_ROOTS:
        root = site_packages / root_name
        _early_reject_reparse_path(root, owner=f"S1 runtime root {root_name}")
        if root_name.endswith(".py"):
            if not root.is_file():
                raise RuntimeError(f"S1 runtime root {root_name} is not a regular file")
            collision_stem = root_name.removesuffix(".py")
            collisions = [
                site_packages / collision_stem,
                site_packages / f"{collision_stem}.pyc",
                site_packages / f"{collision_stem}.pyd",
                site_packages / f"{collision_stem}.pyw",
            ]
            candidates = [root]
        else:
            if not root.is_dir():
                raise RuntimeError(f"S1 runtime root {root_name} is not a directory")
            collisions = [
                site_packages / f"{root_name}.py",
                site_packages / f"{root_name}.pyc",
                site_packages / f"{root_name}.pyd",
                site_packages / f"{root_name}.pyw",
            ]
            candidates = sorted(root.rglob("*"), key=lambda value: value.as_posix())
        if any(collision.exists() or collision.is_symlink() for collision in collisions):
            raise RuntimeError(f"S1 runtime root {root_name} has an import-name collision")
        for candidate in candidates:
            relative = candidate.relative_to(site_packages)
            if "__pycache__" in relative.parts:
                continue
            if candidate.is_symlink() or bool(
                getattr(candidate.lstat(), "st_file_attributes", 0)
                & stat.FILE_ATTRIBUTE_REPARSE_POINT
            ):
                raise RuntimeError(f"S1 runtime inventory contains a reparse point: {relative}")
            if candidate.is_dir():
                continue
            if not candidate.is_file():
                raise RuntimeError(f"S1 runtime inventory contains a non-file: {relative}")
            if candidate.suffix == ".pyc":
                raise RuntimeError(
                    f"S1 runtime inventory contains a sourceless bytecode file: {relative}"
                )
            payload_size = candidate.stat().st_size
            with candidate.open("rb") as handle:
                payload_digest = hashlib.file_digest(handle, "sha256").digest()
            rows.append((relative.as_posix(), payload_size, payload_digest))
    rows.sort(key=lambda row: row[0].encode("utf-8"))
    digest = hashlib.sha256(_RUNTIME_INVENTORY_DOMAIN)
    for relative_name, size, file_digest in rows:
        encoded = relative_name.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        digest.update(size.to_bytes(8, "big"))
        digest.update(file_digest)
    return len(rows), sum(row[1] for row in rows), digest.hexdigest()


def _base_runtime_inventory(runtime_root: Path) -> tuple[int, int, str]:
    """Recheck every file admitted by the externally verified base runtime."""

    _early_reject_reparse_path(runtime_root, owner="S1 base Python runtime")
    rows: list[tuple[str, int, bytes]] = []
    for candidate in runtime_root.rglob("*"):
        relative = candidate.relative_to(runtime_root)
        metadata = candidate.lstat()
        attributes = getattr(metadata, "st_file_attributes", 0)
        if candidate.is_symlink() or bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT):
            raise RuntimeError(f"S1 base runtime contains a reparse point: {relative}")
        if candidate.is_dir():
            continue
        if not candidate.is_file():
            raise RuntimeError(f"S1 base runtime contains a non-file: {relative}")
        if "__pycache__" in relative.parts:
            continue
        if candidate.suffix.casefold() == ".pyc":
            raise RuntimeError(f"S1 base runtime contains sourceless bytecode: {relative}")
        size = metadata.st_size
        with candidate.open("rb") as handle:
            file_digest = hashlib.file_digest(handle, "sha256").digest()
        rows.append((relative.as_posix(), size, file_digest))
    rows.sort(key=lambda row: row[0].encode("utf-8"))
    digest = hashlib.sha256(_BASE_RUNTIME_INVENTORY_DOMAIN)
    for relative_name, size, file_digest in rows:
        encoded = relative_name.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        digest.update(size.to_bytes(8, "big"))
        digest.update(file_digest)
    return len(rows), sum(row[1] for row in rows), digest.hexdigest()


def _bootstrap_governance_runtime() -> _GovernanceRuntimeImportGuard:
    """Establish the closed S1 Python runtime before third-party imports."""

    expected_flags = (0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, False, 0, 0, True, 4300)
    if tuple(sys.flags) != expected_flags or sys.warnoptions or "site" in sys.modules:
        raise RuntimeError(
            "invoke the frozen launcher with its exact Python -I -S -B profile; "
            "altered flags and site/.pth startup are forbidden"
        )
    if os.name != "nt" or sys.implementation.name != "cpython":
        raise RuntimeError("the frozen S1 governance runtime requires Windows CPython")
    if tuple(sys.version_info[:3]) != _FROZEN_PYTHON_VERSION:
        raise RuntimeError("the S1 Python version changed")
    if sys.implementation.cache_tag != _FROZEN_PYTHON_CACHE_TAG:
        raise RuntimeError("the S1 Python cache tag changed")
    if os.environ.pop(_LAUNCHER_PROFILE_ENV, None) != _LAUNCHER_PROFILE:
        raise RuntimeError("the S1 command did not pass the frozen external launcher")
    if os.environ.pop(_LAUNCHER_RUNTIME_DIGEST_ENV, None) != _FROZEN_BASE_RUNTIME_SHA256:
        raise RuntimeError("the external launcher base-runtime attestation changed")
    if any(os.environ.get(name) for name in ("OPENSSL_CONF", "OPENSSL_ENGINES", "OPENSSL_MODULES")):
        raise RuntimeError("the frozen launcher did not clear OpenSSL code-loading variables")
    if os.environ.get("PATH") != _LAUNCHER_CHILD_PATH:
        raise RuntimeError("the frozen launcher child PATH changed")
    if os.environ.get("NoDefaultCurrentDirectoryInExePath") != "1":
        raise RuntimeError("the frozen launcher executable-search guard changed")
    if _early_normalized_path(sys.executable) != _early_normalized_path(_FROZEN_PYTHON_EXECUTABLE):
        raise RuntimeError("the S1 command is not using the frozen base Python executable")
    expected_sys_path = [
        _FROZEN_PYTHON_ROOT / "python312.zip",
        _FROZEN_PYTHON_ROOT / "DLLs",
        _FROZEN_PYTHON_ROOT / "Lib",
        _FROZEN_PYTHON_ROOT,
    ]
    if [_early_normalized_path(value) for value in sys.path] != [
        _early_normalized_path(value) for value in expected_sys_path
    ]:
        raise RuntimeError("the isolated S1 Python standard-library path changed")
    if expected_sys_path[0].exists() or expected_sys_path[0].is_symlink():
        raise RuntimeError("the normally absent python312.zip path became populated")
    observed_base_runtime = _base_runtime_inventory(_FROZEN_PYTHON_ROOT)
    expected_base_runtime = (
        _FROZEN_BASE_RUNTIME_FILE_COUNT,
        _FROZEN_BASE_RUNTIME_SIZE_BYTES,
        _FROZEN_BASE_RUNTIME_SHA256,
    )
    if observed_base_runtime != expected_base_runtime:
        raise RuntimeError("the frozen S1 base Python runtime inventory changed")
    _early_verify_file(
        _FROZEN_PYTHON_EXECUTABLE,
        expected_size=_FROZEN_PYTHON_EXECUTABLE_SIZE,
        expected_sha256=_FROZEN_PYTHON_EXECUTABLE_SHA256,
        owner="frozen S1 Python executable",
    )
    _early_verify_file(
        _FROZEN_PYTHON_DLL,
        expected_size=_FROZEN_PYTHON_DLL_SIZE,
        expected_sha256=_FROZEN_PYTHON_DLL_SHA256,
        owner="frozen S1 Python DLL",
    )
    script_path = Path(__file__)
    _early_reject_reparse_path(script_path, owner="S1 governance validator")
    repository_root = script_path.resolve().parent.parent
    if _early_normalized_path(Path(__file__).resolve()) != _early_normalized_path(
        repository_root / "scripts/v1_s1_governance.py"
    ):
        raise RuntimeError("the S1 governance validator path changed")
    site_packages = repository_root / ".venv/Lib/site-packages"
    observed_inventory = _runtime_inventory(site_packages)
    expected_inventory = (
        _FROZEN_RUNTIME_FILE_COUNT,
        _FROZEN_RUNTIME_SIZE_BYTES,
        _FROZEN_RUNTIME_SHA256,
    )
    if observed_inventory != expected_inventory:
        raise RuntimeError("the frozen S1 third-party runtime inventory changed")
    preloaded_runtime_modules = sorted(
        name for name in sys.modules if name.partition(".")[0] in _RUNTIME_TOP_LEVEL_IMPORTS
    )
    if preloaded_runtime_modules:
        raise RuntimeError(
            "third-party runtime modules loaded before verification: "
            + ", ".join(preloaded_runtime_modules)
        )
    cache_parent = repository_root / ".tmp/s1-runtime-pycache"
    cache_value = sys._xoptions.get("pycache_prefix")
    if set(sys._xoptions) != {"pycache_prefix"} or not isinstance(cache_value, str):
        raise RuntimeError("the frozen launcher did not supply one isolated pycache prefix")
    cache_directory = Path(cache_value)
    _early_reject_reparse_path(cache_directory, owner="S1 runtime bytecode isolation directory")
    if (
        cache_directory.parent.resolve() != cache_parent.resolve()
        or not cache_directory.name.startswith("run-")
        or _early_normalized_path(sys.pycache_prefix or "")
        != _early_normalized_path(cache_directory)
        or any(cache_directory.iterdir())
    ):
        raise RuntimeError("the S1 runtime pycache prefix is not a fresh launcher directory")
    runtime_guard = _GovernanceRuntimeImportGuard(site_packages)
    sys.meta_path.insert(0, runtime_guard)
    sys.path.append(str(site_packages))
    return runtime_guard


if __name__ == "__main__":
    try:
        _BOOTSTRAPPED_RUNTIME_GUARD = _bootstrap_governance_runtime()
    except (OSError, RuntimeError) as exc:
        raise SystemExit(f"v1 S1 governance error: {exc}") from exc

# These imports intentionally occur only after the strict runtime bootstrap.
# isort: split
import jsonschema  # noqa: E402
import rfc8785  # noqa: E402

SPEC_REVISION: Final = "6.5"
FORECAST_CONTRACT_ID: Final = "delivery-forecast/v1"
METHOD_ID: Final = "comonotonic-quantile-sum/v1"
METHOD_DOMAIN: Final = "agent-assure:delivery-forecast-aggregation-method/v1"
METHOD_REGISTRY_DOMAIN: Final = "agent-assure:delivery-forecast-aggregation-registry/v1"
FORECAST_DOMAIN: Final = "agent-assure:delivery-forecast/v1"
RECEIPT_DOMAIN: Final = "agent-assure:governance-receipt/v1"
LEDGER_DOMAIN: Final = "agent-assure:delivery-forecast-authoring-ledger/v1"
ROSTER_DOMAIN: Final = "agent-assure:approval-roster/v1"
KICKOFF_DOMAIN: Final = "agent-assure:kickoff-authorization/v1"
TICKET_RECEIPT_DOMAIN: Final = "agent-assure:ticket-completion-receipt/v1"
BUNDLE_DOMAIN: Final = "agent-assure:governance-bundle/v1"
SIGNING_KEY_DOMAIN: Final = "agent-assure:governance-signing-key/v1"
BASELINE_OBSERVATIONS_DOMAIN: Final = "agent-assure:baseline-observations/v1"
TICKET_SET_DOMAIN: Final = "agent-assure:roadmap-ticket-set/v1"
DEPENDENCY_GRAPH_DOMAIN: Final = "agent-assure:roadmap-dependency-graph/v1"
RELEASE_TRAIN_DOMAIN: Final = "agent-assure:roadmap-release-train/v1"
SIGNATURE_NAMESPACE: Final = "agent-assure-governance-v1"
SIGNATURE_PROFILE: Final = "openssh-sshsig-ed25519/v1"
SIGNATURE_PAYLOAD_ENCODING: Final = "agent-assure-domain-separated-rfc8785-signature-claim/v1"
SIGNATURE_ENCODING: Final = "base64-canonical-lf-openssh-sshsig-armored"
SIGNATURE_CLAIM_DOMAIN: Final = "agent-assure:sshsig-claim/v1"
SIGNATURE_ENVELOPE_FIELDS: Final = frozenset(
    {
        "profile",
        "status",
        "namespace",
        "signed_payload_encoding",
        "signature_encoding",
        "signer_person_id",
        "signer_role",
        "subject_digest",
        "public_key_fingerprint",
        "signed_at_utc",
        "signature",
    }
)
ACCEPTANCE_PLAN_DOMAIN: Final = "agent-assure:s1-acceptance-signature-plan/v1"
CURRENT_ACCEPTANCE_ATTESTATION_DOMAIN: Final = "agent-assure:s1-current-acceptance-attestation/v1"
MAINTAINER_KEY_FINGERPRINT: Final = "SHA256:L/6IRITdktnUQOfbr6iuf48k2MtolzDFvxWaQHU4G7k"
MAINTAINER_PUBLIC_KEY: Final = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP7Bgeqxj82OCpkAsF4Qzby2m5PfOnh4lNKzl3fXZ/uB"
)
FOCUSED_DAY_HOURS: Final = 8
PINNED_BASE_COMMIT: Final = "3b060f4da94f4d0d80e7ae507580fce82ef9bf96"
PINNED_TAG_OBJECT: Final = "ea4b50bd461efd817b7dc2fa5591d06ed9599a6e"
APPROVED_ORIGIN_URL: Final = "https://github.com/acblabs/agent-assure.git"
S1_BRANCH_NAME: Final = "feat/v1-assurance-compiler"
S1_ACCEPTANCE_TAG_NAME: Final = "agent-assure-s1-1.0.0a1-acceptance"
PINNED_LOCK_DIGESTS: Final[dict[str, str]] = {
    "requirements.lock": "sha256:9d127f21617573476278605601f131c875d4def7c102aca5cdd39dda4f261ee4",
    "requirements-langgraph.lock": (
        "sha256:b4e6deb32a38c87a44f3ed7e637230ee36b02ba0f6c29e4e196601db3c90d977"
    ),
    "requirements-adk.lock": (
        "sha256:a047eeb295573937b6643b4a8b3ab6d79a356aa73c8d3a1de274a150dd0530c1"
    ),
}
MAX_S1_VALIDITY: Final = timedelta(days=30)
MAX_ACCEPTANCE_ATTESTATION_DELAY: Final = timedelta(hours=1)
MAX_ROADMAP_BYTES: Final = 4 * 1024 * 1024
MAX_GOVERNANCE_JSON_BYTES: Final = 8 * 1024 * 1024

BLOCK_PATTERN: Final = re.compile(
    r"^<!-- handoff:block ([a-z]+) ([^\n]+) -->\n"
    r"(?P<fence>`{3,})(?P<language>[A-Za-z0-9_-]*)\n"
    r"(?P<content>[\s\S]*?)\n(?P=fence)\n<!-- handoff:end -->$",
    re.MULTILINE,
)
SHA256_PATTERN: Final = re.compile(r"^sha256:[0-9a-f]{64}$")
GIT_COMMIT_PATTERN: Final = re.compile(r"^[0-9a-f]{40}$")
UTC_PATTERN: Final = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$"
)


class GovernanceError(ValueError):
    """Raised when a governance input or artifact violates the frozen contract."""


@dataclass(frozen=True)
class RoadmapSnapshot:
    raw_digest: str
    tickets: tuple[dict[str, Any], ...]
    release_train: dict[str, Any]
    approval_roster_template: dict[str, Any]
    ticket_set_digest: str
    dependency_graph_digest: str
    release_train_digest: str


@dataclass(frozen=True)
class TrustedExecutableIdentity:
    """Immutable identity for an external executable in the S1 host profile."""

    path: str
    size_bytes: int
    sha256: str


# S1's recorded baseline host is Windows.  These identities deliberately name
# the real Git program (not the PATH-facing cmd launcher), the HTTPS transport
# helper used by an authoritative fetch, and OpenSSH's signature verifier.  A
# host update is a governance-input change and therefore fails closed until the
# identities are reviewed and revised.
FROZEN_S1_EXECUTABLE_IDENTITIES: Final[dict[str, TrustedExecutableIdentity]] = {
    "git": TrustedExecutableIdentity(
        path=r"C:\Program Files\Git\mingw64\bin\git.exe",
        size_bytes=4_422_544,
        sha256="cab4c4eea1d869cf9f7be73868dc9a90ad2df1b1b673e5f8c8714a576c25ea96",
    ),
    "git-remote-https": TrustedExecutableIdentity(
        path=r"C:\Program Files\Git\mingw64\libexec\git-core\git-remote-https.exe",
        size_bytes=2_629_024,
        sha256="f4c9d7f2f85b795603f501c25ad63fff82fce233ae0fc3d48e4e3c8669e5d788",
    ),
    "ssh-keygen": TrustedExecutableIdentity(
        path=r"C:\Windows\System32\OpenSSH\ssh-keygen.exe",
        size_bytes=861_184,
        sha256="c9dc170cd161db87e75eb6cf282f1325005b9e35628b9a36cb19883a8be1a34f",
    ),
}
TRUSTED_EXECUTABLE_IDENTITIES: Final[dict[str, TrustedExecutableIdentity]] = dict(
    FROZEN_S1_EXECUTABLE_IDENTITIES
)


def _reject_json_constant(value: str) -> None:
    raise GovernanceError(f"non-finite JSON constant is forbidden: {value}")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise GovernanceError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def strict_json_loads(payload: str) -> object:
    try:
        value = json.loads(
            payload,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except json.JSONDecodeError as exc:
        raise GovernanceError(
            f"malformed JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc
    _validate_json_value(value)
    return value


def _validate_json_value(value: object, *, path: str = "$") -> None:
    if isinstance(value, bool) or value is None:
        return
    if isinstance(value, int):
        if not (-(2**53) + 1 <= value <= (2**53) - 1):
            raise GovernanceError(f"integer outside RFC 8785 safe range at {path}")
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise GovernanceError(f"non-finite number at {path}")
        return
    if isinstance(value, str):
        if unicodedata.normalize("NFC", value) != value:
            raise GovernanceError(f"non-NFC string at {path}")
        if any(ord(character) < 0x20 or 0xD800 <= ord(character) <= 0xDFFF for character in value):
            raise GovernanceError(f"control or surrogate character at {path}")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json_value(item, path=f"{path}/{index}")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise GovernanceError(f"non-string object key at {path}")
            _validate_json_value(key, path=f"{path}/<key>")
            _validate_json_value(item, path=f"{path}/{key}")
        return
    raise GovernanceError(f"unsupported JSON value {type(value).__name__} at {path}")


def canonical_bytes(value: object) -> bytes:
    _validate_json_value(value)
    result = rfc8785.dumps(cast(Any, value))
    if not isinstance(result, bytes):
        raise GovernanceError("RFC 8785 encoder did not return bytes")
    return result


def domain_digest(domain: str, value: object) -> str:
    payload = domain.encode("ascii") + b"\x00" + canonical_bytes(value)
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def raw_digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _as_object(value: object, *, owner: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GovernanceError(f"{owner} must be a JSON object")
    return cast(dict[str, Any], value)


def _as_array(value: object, *, owner: str) -> list[Any]:
    if not isinstance(value, list):
        raise GovernanceError(f"{owner} must be a JSON array")
    return value


def load_roadmap(path: Path) -> RoadmapSnapshot:
    if not path.is_file():
        raise GovernanceError(f"roadmap is not a regular file: {path}")
    raw = path.read_bytes()
    if len(raw) > MAX_ROADMAP_BYTES:
        raise GovernanceError("roadmap exceeds the 4 MiB input limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise GovernanceError("roadmap is not UTF-8") from exc
    normalized = text.replace("\r\n", "\n")
    if "\r" in normalized:
        raise GovernanceError("roadmap contains a lone carriage return")

    records: dict[tuple[str, str], str] = {}
    order: list[tuple[str, str]] = []
    for match in BLOCK_PATTERN.finditer(normalized):
        key = (match.group(1), match.group(2))
        if key in records:
            raise GovernanceError(f"duplicate roadmap block: {key!r}")
        records[key] = match.group("content")
        order.append(key)

    defaults_key = ("json", "ticket-defaults")
    train_key = ("json", "release-train.json")
    roster_key = ("json", "approval-roster")
    if defaults_key not in records or train_key not in records or roster_key not in records:
        raise GovernanceError(
            "roadmap lacks ticket defaults, release-train, or approval-roster block"
        )
    defaults = _as_object(strict_json_loads(records[defaults_key]), owner="ticket-defaults")
    release_train = _as_object(strict_json_loads(records[train_key]), owner="release-train")
    approval_roster_template = _as_object(
        strict_json_loads(records[roster_key]), owner="approval-roster"
    )

    tickets: list[dict[str, Any]] = []
    for kind, identifier in order:
        if kind != "ticket":
            continue
        item = _as_object(strict_json_loads(records[(kind, identifier)]), owner=identifier)
        if item.get("id") != identifier:
            raise GovernanceError(f"ticket block identity mismatch: {identifier}")
        tickets.append({**defaults, **item})
    tickets.sort(key=lambda ticket: _utf8_sort_key(_required_string(ticket, "id")))
    identifiers = [_required_string(ticket, "id") for ticket in tickets]
    if len(identifiers) != len(set(identifiers)):
        raise GovernanceError("duplicate ticket identity")

    ticket_set_projection = {
        "contract_id": "roadmap-ticket-set/v1",
        "ticket_ids": identifiers,
    }
    dependency_rows = [
        {
            "ticket_id": _required_string(ticket, "id"),
            "depends_on": sorted(_required_string_array(ticket, "depends_on"), key=_utf8_sort_key),
        }
        for ticket in tickets
    ]
    dependency_projection = {
        "contract_id": "roadmap-dependency-graph/v1",
        "rows": dependency_rows,
    }
    snapshot = RoadmapSnapshot(
        raw_digest=raw_digest(raw),
        tickets=tuple(tickets),
        release_train=release_train,
        approval_roster_template=approval_roster_template,
        ticket_set_digest=domain_digest(TICKET_SET_DOMAIN, ticket_set_projection),
        dependency_graph_digest=domain_digest(DEPENDENCY_GRAPH_DOMAIN, dependency_projection),
        release_train_digest=domain_digest(RELEASE_TRAIN_DOMAIN, release_train),
    )
    _validate_roadmap_contract(snapshot)
    return snapshot


def _validate_roadmap_contract(snapshot: RoadmapSnapshot) -> None:
    if snapshot.release_train.get("format") != "agent-assure-release-train/6":
        raise GovernanceError("roadmap release train format is not the frozen v6 contract")
    if snapshot.release_train.get("spec_revision") != SPEC_REVISION:
        raise GovernanceError("roadmap release train specification revision is not 6.5")
    if snapshot.approval_roster_template.get("format") != "agent-assure-approval-roster/1":
        raise GovernanceError("roadmap approval roster template format is not supported")
    if snapshot.approval_roster_template.get("spec_revision") != SPEC_REVISION:
        raise GovernanceError("roadmap approval roster template revision is not 6.5")
    cadence = _as_object(
        snapshot.release_train.get("planning_cadence"), owner="release-train planning_cadence"
    )
    exact_cadence = {
        "forecast_contract": FORECAST_CONTRACT_ID,
        "forecast_producer_ticket_id": "V1-BASE-01",
        "forecast_producer_work_package_id": "BASE-01F",
        "required_before_sprint": "S2",
        "forecast_must_cover_all_ticket_ids": True,
        "forecast_must_be_current_at_commitment": True,
    }
    for key, expected in exact_cadence.items():
        if cadence.get(key) != expected:
            raise GovernanceError(f"roadmap planning cadence changed frozen field {key}")

    ticket_by_id = {_required_string(ticket, "id"): ticket for ticket in snapshot.tickets}
    if len(ticket_by_id) != len(snapshot.tickets):
        raise GovernanceError("roadmap ticket identities are not unique")
    graph: dict[str, list[str]] = {}
    for ticket_id, ticket in ticket_by_id.items():
        dependencies = _required_string_array(ticket, "depends_on")
        if ticket_id in dependencies:
            raise GovernanceError(f"ticket {ticket_id} depends on itself")
        unknown = sorted(set(dependencies) - set(ticket_by_id), key=_utf8_sort_key)
        if unknown:
            raise GovernanceError(
                f"ticket {ticket_id} references unknown dependencies: {', '.join(unknown)}"
            )
        graph[ticket_id] = dependencies

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(ticket_id: str) -> None:
        if ticket_id in visiting:
            raise GovernanceError(f"ticket dependency graph contains a cycle at {ticket_id}")
        if ticket_id in visited:
            return
        visiting.add(ticket_id)
        for dependency in graph[ticket_id]:
            visit(dependency)
        visiting.remove(ticket_id)
        visited.add(ticket_id)

    for ticket_id in sorted(graph, key=_utf8_sort_key):
        visit(ticket_id)

    entries = _as_array(snapshot.release_train.get("entries"), owner="release-train.entries")
    first_occurrence: dict[str, int] = {}
    seen_sprints: set[str] = set()
    seen_releases: set[str] = set()
    s1_entry: Mapping[str, Any] | None = None
    for index, item in enumerate(entries):
        entry = _as_object(item, owner="release-train entry")
        sprint = _required_string(entry, "sprint")
        release = _required_string(entry, "release")
        if sprint in seen_sprints or release in seen_releases:
            raise GovernanceError("release train contains a duplicate sprint or release identity")
        seen_sprints.add(sprint)
        seen_releases.add(release)
        for ticket_id in _required_string_array(entry, "ticket_ids"):
            if ticket_id not in ticket_by_id:
                raise GovernanceError(f"release train references unknown ticket: {ticket_id}")
            first_occurrence.setdefault(ticket_id, index)
        if sprint == "S1":
            s1_entry = entry
    if set(first_occurrence) != set(ticket_by_id):
        missing = sorted(set(ticket_by_id) - set(first_occurrence), key=_utf8_sort_key)
        raise GovernanceError(f"release train omits tickets: {', '.join(missing)}")
    for ticket_id, dependencies in graph.items():
        for dependency in dependencies:
            if first_occurrence[dependency] > first_occurrence[ticket_id]:
                raise GovernanceError(
                    f"ticket {ticket_id} is scheduled before dependency {dependency} first appears"
                )
    if s1_entry is None:
        raise GovernanceError("release train does not contain S1")
    exact_s1 = {
        "release": "1.0.0a1",
        "maturity": "governed-baseline",
        "artifact_kind": "governance-bundle",
        "ticket_ids": ["V1-BOOT-01", "V1-BASE-01"],
        "authorization_effect": "none",
        "installability": "none",
        "distribution_channels": [],
        "package_version": None,
    }
    for key, expected in exact_s1.items():
        if s1_entry.get(key) != expected:
            raise GovernanceError(f"S1 release entry changed frozen field {key}")


def _utf8_sort_key(value: str) -> bytes:
    return value.encode("utf-8")


def _required_string(mapping: Mapping[str, Any], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise GovernanceError(f"{key} must be a nonempty string")
    return value


def _required_string_array(mapping: Mapping[str, Any], key: str) -> list[str]:
    raw = _as_array(mapping.get(key), owner=key)
    values: list[str] = []
    for value in raw:
        if not isinstance(value, str) or not value:
            raise GovernanceError(f"{key} entries must be nonempty strings")
        values.append(value)
    if len(values) != len(set(values)):
        raise GovernanceError(f"{key} entries must be unique")
    return values


def _required_nonnegative_number(mapping: Mapping[str, Any], key: str) -> int | float:
    value = mapping.get(key)
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise GovernanceError(f"{key} must be a JSON number")
    if isinstance(value, float) and not math.isfinite(value):
        raise GovernanceError(f"{key} must be finite and nonnegative")
    if value < 0:
        raise GovernanceError(f"{key} must be finite and nonnegative")
    return value


def aggregation_method_definition() -> dict[str, Any]:
    return {
        "format": "agent-assure-delivery-forecast-aggregation-method/1",
        "method_id": METHOD_ID,
        "version": "1.0.0",
        "unit": "focused_engineer_hour",
        "evaluated_quantile_ranks": [0.5, 0.9],
        "quantile_definition": "Q_p(X)=inf{x:F_X(x)>=p}",
        "dependence_model": {
            "name": "comonotonic_shared_severity_rank",
            "definition": (
                "For every occurrence i, X_i=Q_i(U), where U~Uniform(0,1) is global and shared "
                "across the portfolio and Q_i is a nondecreasing generalized-inverse marginal "
                "quantile function. Only ranks p in {0.5,0.9} are evaluated."
            ),
            "independence_claimed": False,
            "reviewer_effort_coupling": (
                "Reviewer-effort P50 entries use the same global shared-rank planning model; only "
                "their additive P50 is reported."
            ),
        },
        "aggregation": {
            "aggregate_p50_effort_hours": {
                "operation": "checked_integer_sum",
                "source_field": "p50_effort_hours",
                "quantile_rank": 0.5,
            },
            "aggregate_p90_effort_hours": {
                "operation": "checked_integer_sum",
                "source_field": "p90_effort_hours",
                "quantile_rank": 0.9,
            },
            "aggregate_reviewer_effort_hours": {
                "operation": "checked_integer_sum",
                "source_field": "reviewer_effort_hours",
                "quantile_rank": 0.5,
            },
        },
        "interpretation": [
            "At the two declared ranks, the aggregate P50 and P90 are tail-aligned additive "
            "planning quantiles under the declared comonotonic model.",
            "They are not distribution-free bounds, confidence intervals, elapsed-calendar "
            "forecasts, or evidence of ticket independence.",
            "The two supplied ranks do not identify a complete marginal distribution between "
            "or beyond P50 and P90.",
            "Parallel execution changes elapsed time but does not discount accountable effort.",
        ],
        "arithmetic": {
            "input_type": "nonnegative integer hours",
            "maximum_exact_integer": 2**53 - 1,
            "rounding": "none after authoring; day priors are converted at exactly 8 hours/day",
        },
    }


def aggregation_method_record() -> dict[str, Any]:
    definition = aggregation_method_definition()
    return {
        **definition,
        "definition_digest": domain_digest(METHOD_DOMAIN, definition),
    }


def aggregation_method_registry() -> dict[str, Any]:
    method = aggregation_method_record()
    projection = {
        "format": "agent-assure-delivery-forecast-aggregation-registry/1",
        "spec_revision": SPEC_REVISION,
        "methods": [method],
    }
    return {
        **projection,
        "registry_digest": domain_digest(METHOD_REGISTRY_DOMAIN, projection),
    }


def _resolve_aggregation_method(
    registry: Mapping[str, Any], method_id: str = METHOD_ID
) -> dict[str, Any]:
    expected = aggregation_method_registry()
    if dict(registry) != expected:
        raise GovernanceError("aggregation method registry differs from the frozen definition")
    methods = _as_array(registry.get("methods"), owner="aggregation registry methods")
    matching = [
        _as_object(item, owner="aggregation method")
        for item in methods
        if isinstance(item, dict) and item.get("method_id") == method_id
    ]
    if len(matching) != 1:
        raise GovernanceError(
            f"aggregation method registry does not resolve exactly one {method_id}"
        )
    return matching[0]


def release_occurrences(snapshot: RoadmapSnapshot) -> dict[str, list[tuple[str, str]]]:
    entries = _as_array(snapshot.release_train.get("entries"), owner="release-train.entries")
    occurrences: dict[str, list[tuple[str, str]]] = {
        _required_string(ticket, "id"): [] for ticket in snapshot.tickets
    }
    seen_sprints: set[str] = set()
    for entry_value in entries:
        entry = _as_object(entry_value, owner="release entry")
        sprint = _required_string(entry, "sprint")
        release = _required_string(entry, "release")
        if sprint in seen_sprints:
            raise GovernanceError(f"duplicate release-train sprint: {sprint}")
        seen_sprints.add(sprint)
        for ticket_id in _required_string_array(entry, "ticket_ids"):
            if ticket_id not in occurrences:
                raise GovernanceError(f"release train references unknown ticket: {ticket_id}")
            occurrences[ticket_id].append((sprint, release))
    missing = [ticket_id for ticket_id, values in occurrences.items() if not values]
    if missing:
        raise GovernanceError("tickets missing release occurrences: " + ", ".join(missing))
    return occurrences


def _integer_hours(days: int | float, *, owner: str) -> int:
    try:
        hours = Decimal(str(days)) * FOCUSED_DAY_HOURS
    except InvalidOperation as exc:
        raise GovernanceError(f"{owner} is not a finite decimal day value") from exc
    if not hours.is_finite() or hours != hours.to_integral_value():
        raise GovernanceError(f"{owner} does not convert to an integer hour")
    return int(hours)


def _distribute_integer(total: int, count: int) -> list[int]:
    if count <= 0:
        raise GovernanceError("distribution count must be positive")
    quotient, remainder = divmod(total, count)
    return [quotient + (1 if index < remainder else 0) for index in range(count)]


def _initial_dependency_assumptions(ticket: Mapping[str, Any]) -> list[str]:
    ticket_id = _required_string(ticket, "id")
    dependencies = _required_string_array(ticket, "depends_on")
    declared = ", ".join(dependencies) if dependencies else "none"
    return [
        f"Declared ticket predecessors for {ticket_id}: {declared}.",
        "Every declared predecessor closes with its operation-scoped receipt before dispatch.",
        "Sprint labels express dependency order and are not calendar commitments.",
    ]


def _initial_risk_assumptions(ticket: Mapping[str, Any]) -> list[str]:
    ticket_id = _required_string(ticket, "id")
    title = _required_string(ticket, "title")
    stop_conditions = _required_string_array(ticket, "stop_conditions")
    stop_digest = domain_digest(
        "agent-assure:roadmap-ticket-stop-conditions/v1",
        {"ticket_id": ticket_id, "stop_conditions": stop_conditions},
    )
    return [
        f"Estimate scope is limited to {ticket_id}: {title}.",
        f"Roadmap stop-condition set is bound by {stop_digest}.",
        "A roadmap, dependency, estimate-scope, or occurrence-order change requires rebaselining.",
        "Missing qualified staffing can delay acceptance but cannot weaken an assurance gate.",
        (
            "LLM assistance does not reduce accountable review, verification, or rework effort "
            "to zero."
        ),
    ]


def build_authoring_ledger(
    snapshot: RoadmapSnapshot,
    *,
    issued_at: str,
    producer_person_id: str,
    baseline_observations_digest_value: str,
    inventory_completed_at: str,
) -> dict[str, Any]:
    issue_time = _parse_utc(issued_at, owner="issued_at")
    if SHA256_PATTERN.fullmatch(baseline_observations_digest_value) is None:
        raise GovernanceError("baseline observations digest is invalid")
    inventory_time = _parse_utc(inventory_completed_at, owner="inventory_completed_at_utc")
    if issue_time < inventory_time:
        raise GovernanceError("authoring ledger predates completion of baseline inventory")
    occurrences = release_occurrences(snapshot)
    rows: list[dict[str, Any]] = []
    for ticket in snapshot.tickets:
        ticket_id = _required_string(ticket, "id")
        delivery = _as_object(ticket.get("delivery"), owner=f"{ticket_id}.delivery")
        estimate = _as_object(delivery.get("estimate"), owner=f"{ticket_id}.delivery.estimate")
        scope = _required_string(estimate, "scope")
        p50_total = _integer_hours(
            _required_nonnegative_number(estimate, "p50"), owner=f"{ticket_id}.p50"
        )
        p90_total = _integer_hours(
            _required_nonnegative_number(estimate, "p90"), owner=f"{ticket_id}.p90"
        )
        review_total = _integer_hours(
            _required_nonnegative_number(delivery, "review_effort_p50_days"),
            owner=f"{ticket_id}.review",
        )
        ticket_occurrences = occurrences[ticket_id]
        if scope == "ticket_completion" and len(ticket_occurrences) > 1:
            p50_values = _distribute_integer(p50_total, len(ticket_occurrences))
            p90_values = _distribute_integer(p90_total, len(ticket_occurrences))
            review_values = _distribute_integer(review_total, len(ticket_occurrences))
            proposal_rule = "split_ticket_completion_total_across_nonoverlapping_occurrences"
        else:
            p50_values = [p50_total] * len(ticket_occurrences)
            p90_values = [p90_total] * len(ticket_occurrences)
            review_values = [review_total] * len(ticket_occurrences)
            proposal_rule = "apply_declared_per_scope_prior_to_each_occurrence"
        proposed: list[dict[str, Any]] = []
        for index, (sprint, release) in enumerate(ticket_occurrences):
            proposed.append(
                {
                    "sprint": sprint,
                    "release": release,
                    "proposed_p50_effort_hours": p50_values[index],
                    "proposed_p90_effort_hours": p90_values[index],
                    "proposed_reviewer_effort_hours": review_values[index],
                    "selected_p50_effort_hours": p50_values[index],
                    "selected_p90_effort_hours": p90_values[index],
                    "selected_reviewer_effort_hours": review_values[index],
                    "decision": "pending_maintainer_reconfirmation",
                    "rationale": (
                        "Mechanically derived provisional roadmap prior; this is not a "
                        "repository-grounded re-estimate. Accountable maintainer confirmation or "
                        "re-estimation after inventory is required."
                    ),
                    "confirmed_by_person_id": None,
                    "confirmed_at_utc": None,
                }
            )
        rows.append(
            {
                "ticket_id": ticket_id,
                "estimate_scope": scope,
                "roadmap_prior": {
                    "unit": _required_string(estimate, "unit"),
                    "p50": estimate.get("p50"),
                    "p90": estimate.get("p90"),
                    "review_effort_p50_days": delivery.get("review_effort_p50_days"),
                    "confidence": _required_string(estimate, "confidence"),
                    "basis": _required_string(estimate, "basis"),
                },
                "proposal_rule": proposal_rule,
                "selected_confidence": _required_string(estimate, "confidence"),
                "selected_current_status": (
                    "in_progress" if ticket_id in {"V1-BOOT-01", "V1-BASE-01"} else "not_started"
                ),
                "selected_dependency_assumptions": _initial_dependency_assumptions(ticket),
                "selected_risk_assumptions": _initial_risk_assumptions(ticket),
                "row_decision": "pending_maintainer_reconfirmation",
                "row_decision_rationale": (
                    "Confidence, dependency assumptions, and ticket-specific risk assumptions "
                    "require accountable maintainer confirmation or re-estimation."
                ),
                "row_confirmed_by_person_id": None,
                "row_confirmed_at_utc": None,
                "execution_proposals": proposed,
            }
        )
    projection = {
        "format": "agent-assure-delivery-forecast-authoring-ledger/1",
        "spec_revision": SPEC_REVISION,
        "roadmap_digest": snapshot.raw_digest,
        "baseline_observations_digest": baseline_observations_digest_value,
        "inventory_completed_at_utc": inventory_completed_at,
        "proposal_preparer_kind": "llm_implementation_agent",
        "accountable_maintainer_person_id": producer_person_id,
        "issued_at_utc": issued_at,
        "accountable_confirmation_required": True,
        "rows": rows,
    }
    return {**projection, "ledger_digest": domain_digest(LEDGER_DOMAIN, projection)}


def _ledger_rows(ledger: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    rows = _as_array(ledger.get("rows"), owner="authoring ledger rows")
    by_id: dict[str, dict[str, Any]] = {}
    for raw_row in rows:
        row = _as_object(raw_row, owner="authoring ledger row")
        ticket_id = _required_string(row, "ticket_id")
        if ticket_id in by_id:
            raise GovernanceError(f"duplicate ledger ticket: {ticket_id}")
        by_id[ticket_id] = row
    return by_id


def approval_roster_digest(roster: Mapping[str, Any]) -> str:
    return domain_digest(ROSTER_DOMAIN, dict(roster))


def validate_approval_roster(
    snapshot: RoadmapSnapshot,
    roster: Mapping[str, Any],
    schema: Mapping[str, Any],
    *,
    allow_pending: bool,
) -> tuple[str, str]:
    _validate_json_schema(roster, schema, owner="approval roster")
    if roster.get("format") != "agent-assure-approval-roster/1":
        raise GovernanceError("approval roster format is not supported")
    if roster.get("spec_revision") != SPEC_REVISION:
        raise GovernanceError("approval roster specification revision is stale")
    if roster.get("selected_mode") != "maintainer_development":
        raise GovernanceError("S1 is scoped to maintainer_development mode")
    selection_status = _required_string(roster, "selection_status")
    if selection_status not in {"not_approved", "approved"}:
        raise GovernanceError("approval roster selection status is invalid")
    if not allow_pending and selection_status != "approved":
        raise GovernanceError("approval roster has not been approved")

    template_assignments = _as_array(
        snapshot.approval_roster_template.get("role_assignments"),
        owner="roadmap approval roster assignments",
    )
    expected_roles = [
        _required_string(_as_object(item, owner="roadmap role assignment"), "role")
        for item in template_assignments
    ]
    assignments = _as_array(roster.get("role_assignments"), owner="role_assignments")
    actual_roles = [
        _required_string(_as_object(item, owner="role assignment"), "role") for item in assignments
    ]
    if actual_roles != expected_roles or len(actual_roles) != len(set(actual_roles)):
        raise GovernanceError("approval roster must preserve the exact ordered 38-role template")

    people = _as_array(roster.get("people"), owner="people")
    people_by_id: dict[str, dict[str, Any]] = {}
    for item in people:
        person = _as_object(item, owner="person")
        person_id = _required_string(person, "person_id")
        if person_id in people_by_id:
            raise GovernanceError(f"duplicate roster person identity: {person_id}")
        people_by_id[person_id] = person
    maintainer_person_id = _required_string(roster, "maintainer_person_id")
    if maintainer_person_id not in people_by_id:
        raise GovernanceError("roster maintainer identity is not present in people")

    assignments_by_role: dict[str, dict[str, Any]] = {}
    for item in assignments:
        assignment = _as_object(item, owner="role assignment")
        role = _required_string(assignment, "role")
        assignments_by_role[role] = assignment
        for reference_field in ("person_id", "backup_person_id"):
            reference = assignment.get(reference_field)
            if reference is not None and reference not in people_by_id:
                raise GovernanceError(
                    f"{role}.{reference_field} references an unknown person identity"
                )
        if assignment.get("person_id") is not None and not assignment.get("review_capacity"):
            raise GovernanceError(f"staffed role {role} must declare review capacity")
        if assignment.get("person_id") is not None and assignment.get(
            "person_id"
        ) == assignment.get("backup_person_id"):
            raise GovernanceError(f"role {role} cannot use the same person as its own backup")

    for required_role in ("technical_lead", "repository_maintainer"):
        if assignments_by_role[required_role].get("person_id") != maintainer_person_id:
            raise GovernanceError(
                f"S1 {required_role} must be assigned to the named maintainer person"
            )
    for role, assignment in assignments_by_role.items():
        if (
            role not in {"technical_lead", "repository_maintainer"}
            and assignment.get("person_id") is not None
        ):
            raise GovernanceError(f"future or independent role {role} must remain unfilled in S1")
        if assignment.get("backup_person_id") is not None:
            raise GovernanceError(f"S1 roster declares no confirmed backup for role {role}")
    competence = set(
        _required_string_array(people_by_id[maintainer_person_id], "competence_scopes")
    )
    required_competence = {
        "planning_governance:s1",
        "repository_maintenance:bounded_development",
        "technical_direction:s1",
    }
    if not required_competence <= competence:
        raise GovernanceError("S1 maintainer competence declaration is incomplete")
    conflicts = set(_required_string_array(people_by_id[maintainer_person_id], "conflicts"))
    required_conflicts = {
        "Sole human owner and development acceptor for S1",
        (
            "Cannot issue an independent-review receipt for self-authored or LLM-authored "
            "work accepted under this identity"
        ),
        "Repository-configured handle; legal identity is not asserted by this record",
    }
    if not required_conflicts <= conflicts:
        raise GovernanceError("S1 maintainer conflict declaration is incomplete")
    incompatibilities = set(_required_string_array(roster, "incompatibilities"))
    required_incompatibilities = {
        "An author cannot supply the independent review receipt for the same scoped artifact",
        "A second LLM session, account, title, or role label is not a second independent person",
        "The S1 maintainer may self-accept bounded development only with NO_INDEPENDENT_REVIEW",
        (
            "Release, method-admission, qualification, and independent-pilot receipts require "
            "later compatible staffing"
        ),
    }
    if not required_incompatibilities <= incompatibilities:
        raise GovernanceError("S1 approval incompatibility rules are incomplete")
    limitations = set(_required_string_array(roster, "limitations"))
    if "NO_INDEPENDENT_REVIEW" not in limitations:
        raise GovernanceError("maintainer-development roster must declare NO_INDEPENDENT_REVIEW")
    if _as_array(roster.get("qualification_receipts"), owner="qualification_receipts"):
        raise GovernanceError("S1 roster cannot claim qualification receipts")
    return approval_roster_digest(roster), maintainer_person_id


def _ticket_by_id(snapshot: RoadmapSnapshot, ticket_id: str) -> dict[str, Any]:
    matches = [ticket for ticket in snapshot.tickets if ticket.get("id") == ticket_id]
    if len(matches) != 1:
        raise GovernanceError(f"roadmap does not resolve exactly one ticket {ticket_id}")
    return matches[0]


def _kickoff_scope(ticket_id: str) -> tuple[list[str], list[str]]:
    common_forbidden = [
        "No production package behavior, trusted policy, oracle, or frozen schema may be edited.",
        (
            "No method admission, qualification, pilot, release, deployment, or runtime "
            "authorization is granted."
        ),
        "No independent-review claim may be issued by the sole maintainer or an LLM session.",
        "No contributor work may be reset, stashed, deleted, or overwritten.",
    ]
    if ticket_id == "V1-BOOT-01":
        return (
            [
                "Prepare and validate the exact 38-role V1-APPROVAL-ROSTER proposal.",
                (
                    "Draft bounded S1 governance records, schemas, documentation, and "
                    "adversarial tests."
                ),
                "Inspect repository governance anchors and the private roadmap read-only.",
            ],
            common_forbidden,
        )
    if ticket_id == "V1-BASE-01":
        return (
            [
                (
                    "Fetch and inventory the authorized origin, refs, tags, tracked tree, CLI, "
                    "dependencies, and schema workflow."
                ),
                (
                    "Draft ADR-V1-MAP, the closed delivery-forecast/v1 contract, and planning "
                    "evidence."
                ),
                "Run non-mutating baseline checks and governance-specific validation tests.",
            ],
            common_forbidden,
        )
    raise GovernanceError(f"{ticket_id} is not an S1 kickoff ticket")


def _kickoff_projection(record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in record.items()
        if key not in {"authorization_digest", "signature_envelope"}
    }


def build_kickoff_authorization(
    snapshot: RoadmapSnapshot,
    *,
    ticket_id: str,
    roster_digest: str,
    person_id: str,
    issued_at: str,
    valid_until: str,
    status: str = "pending_human_signature",
) -> dict[str, Any]:
    _validate_validity_interval(issued_at, valid_until, owner=f"{ticket_id} kickoff")
    if status not in {"pending_human_signature", "authorized"}:
        raise GovernanceError(f"{ticket_id} kickoff status is invalid")
    ticket = _ticket_by_id(snapshot, ticket_id)
    allowed, forbidden = _kickoff_scope(ticket_id)
    projection: dict[str, Any] = {
        "format": "agent-assure-kickoff-authorization/1",
        "spec_revision": SPEC_REVISION,
        "authorization_status": status,
        "purpose": "kickoff_authorization",
        "subject_ticket_id": ticket_id,
        "subject_dispatch_kind": _required_string(ticket, "dispatch_kind"),
        "approval_mode": "maintainer_development",
        "approval_roster_digest": roster_digest,
        "authorizer_person_id": person_id,
        "authorizer_role": "repository_maintainer",
        "issued_at_utc": issued_at,
        "valid_until_utc": valid_until,
        "authorization_effect": "bounded_s1_governance_only",
        "allowed_operations": allowed,
        "forbidden_operations": forbidden,
        "source_instruction_evidence": {
            "kind": "interactive_user_instruction",
            "summary": (
                "The user requested S1 implementation and stated they are the individual in charge "
                "while delegating code implementation to LLMs."
            ),
            "identity_binding_status": (
                "bound_by_authorization_signature"
                if status == "authorized"
                else "pending_cryptographic_confirmation"
            ),
        },
        "limitations": [
            "NO_INDEPENDENT_REVIEW",
            (
                "The interactive account is not treated as cryptographically bound to the "
                "repository handle until signature verification succeeds."
            ),
            (
                "This authorization has no runtime, release, deployment, qualification, or "
                "method-admission effect."
            ),
        ],
    }
    digest = domain_digest(KICKOFF_DOMAIN, projection)
    return {
        **projection,
        "authorization_digest": digest,
        "signature_envelope": _pending_signature(person_id, "repository_maintainer", digest),
    }


def validate_kickoff_authorization(
    snapshot: RoadmapSnapshot,
    record: Mapping[str, Any],
    schema: Mapping[str, Any],
    *,
    expected_ticket_id: str,
    expected_roster_digest: str,
    expected_person_id: str,
    allow_pending: bool,
    validation_time: datetime | None = None,
) -> None:
    _validate_json_schema(record, schema, owner=f"{expected_ticket_id} kickoff authorization")
    if validation_time is not None and validation_time.tzinfo is None:
        raise GovernanceError("kickoff validation time must be timezone-aware")
    status = _required_string(record, "authorization_status")
    expected = build_kickoff_authorization(
        snapshot,
        ticket_id=expected_ticket_id,
        roster_digest=expected_roster_digest,
        person_id=expected_person_id,
        issued_at=_required_string(record, "issued_at_utc"),
        valid_until=_required_string(record, "valid_until_utc"),
        status=status,
    )
    if _kickoff_projection(record) != _kickoff_projection(expected):
        raise GovernanceError(
            f"{expected_ticket_id} kickoff authorization differs from its trusted projection"
        )
    digest = domain_digest(KICKOFF_DOMAIN, _kickoff_projection(record))
    if record.get("authorization_digest") != digest:
        raise GovernanceError(f"{expected_ticket_id} kickoff authorization digest mismatch")
    issue_time, expiry_time = _validate_validity_interval(
        _required_string(record, "issued_at_utc"),
        _required_string(record, "valid_until_utc"),
        owner=f"{expected_ticket_id} kickoff",
    )
    signature_may_be_pending = allow_pending and status != "authorized"
    if status == "authorized" and validation_time is None:
        raise GovernanceError(
            f"{expected_ticket_id} authorized kickoff requires a trusted validation time"
        )
    _validate_signature_envelope(
        record.get("signature_envelope"),
        expected_person_id=expected_person_id,
        expected_role="repository_maintainer",
        expected_subject_digest=digest,
        allow_pending=signature_may_be_pending,
        not_before=issue_time,
        not_after=expiry_time,
        validation_time=validation_time,
    )
    if status == "authorized" and validation_time is not None:
        at = validation_time.astimezone(UTC)
        if not issue_time <= at < expiry_time:
            raise GovernanceError(f"{expected_ticket_id} kickoff authorization is not current")
    if not allow_pending and status != "authorized":
        raise GovernanceError(f"{expected_ticket_id} kickoff authorization is pending")


def _validate_confirmation_metadata(
    value: Mapping[str, Any],
    *,
    decision_key: str,
    person_key: str,
    time_key: str,
    expected_person_id: str,
    inventory_completed_at: datetime,
    ledger_issue_time: datetime,
    owner: str,
) -> str:
    decision = _required_string(value, decision_key)
    allowed = {
        "pending_maintainer_reconfirmation",
        "affirmatively_reconfirmed_after_inventory",
        "reestimated_after_inventory",
    }
    if decision not in allowed:
        raise GovernanceError(f"{owner} contains an unknown confirmation decision")
    person = value.get(person_key)
    confirmation_time = value.get(time_key)
    if decision == "pending_maintainer_reconfirmation":
        if person is not None or confirmation_time is not None:
            raise GovernanceError(
                f"pending {owner} must not claim a confirmer or confirmation time"
            )
        return decision
    if person != expected_person_id:
        raise GovernanceError(f"{owner} confirmer does not match the accountable maintainer")
    if not isinstance(confirmation_time, str):
        raise GovernanceError(f"confirmed {owner} must contain a confirmation time")
    parsed = _parse_utc(confirmation_time, owner=f"{owner}.{time_key}")
    if parsed < inventory_completed_at:
        raise GovernanceError(f"{owner} confirmation predates completed inventory")
    if parsed > ledger_issue_time:
        raise GovernanceError(f"{owner} confirmation time is after ledger issue time")
    return decision


def validate_authoring_ledger(
    snapshot: RoadmapSnapshot,
    ledger: Mapping[str, Any],
    schema: Mapping[str, Any],
    *,
    expected_person_id: str,
    baseline_observations: Mapping[str, Any],
) -> None:
    _validate_json_schema(ledger, schema, owner="delivery forecast authoring ledger")
    if ledger.get("roadmap_digest") != snapshot.raw_digest:
        raise GovernanceError("authoring ledger is bound to another roadmap")
    if ledger.get("accountable_maintainer_person_id") != expected_person_id:
        raise GovernanceError("authoring ledger accountable maintainer differs from the roster")
    issued_at = _required_string(ledger, "issued_at_utc")
    issue_time = _parse_utc(issued_at, owner="authoring ledger issued_at_utc")
    expected_baseline_digest = _required_string(baseline_observations, "observations_digest")
    inventory_completed_at_value = _required_string(
        baseline_observations, "inventory_completed_at_utc"
    )
    inventory_completed_at = _parse_utc(
        inventory_completed_at_value, owner="baseline inventory_completed_at_utc"
    )
    if ledger.get("baseline_observations_digest") != expected_baseline_digest:
        raise GovernanceError("authoring ledger is bound to other baseline observations")
    if ledger.get("inventory_completed_at_utc") != inventory_completed_at_value:
        raise GovernanceError("authoring ledger inventory completion time changed")
    if issue_time < inventory_completed_at:
        raise GovernanceError("authoring ledger predates completed inventory")
    if ledger.get("ledger_digest") != _ledger_digest(ledger):
        raise GovernanceError("authoring ledger digest mismatch")
    expected = build_authoring_ledger(
        snapshot,
        issued_at=issued_at,
        producer_person_id=expected_person_id,
        baseline_observations_digest_value=expected_baseline_digest,
        inventory_completed_at=inventory_completed_at_value,
    )
    expected_rows = _as_array(expected.get("rows"), owner="expected ledger rows")
    actual_rows = _as_array(ledger.get("rows"), owner="authoring ledger rows")
    if len(actual_rows) != len(expected_rows):
        raise GovernanceError("authoring ledger does not contain exactly one row per ticket")
    fixed_top_level = {
        "format",
        "spec_revision",
        "roadmap_digest",
        "baseline_observations_digest",
        "inventory_completed_at_utc",
        "proposal_preparer_kind",
        "accountable_maintainer_person_id",
        "issued_at_utc",
        "accountable_confirmation_required",
    }
    for key in fixed_top_level:
        if ledger.get(key) != expected.get(key):
            raise GovernanceError(f"authoring ledger fixed field differs from source: {key}")

    for raw_actual, raw_expected in zip(actual_rows, expected_rows, strict=True):
        actual = _as_object(raw_actual, owner="authoring ledger row")
        baseline = _as_object(raw_expected, owner="expected authoring ledger row")
        ticket_id = _required_string(baseline, "ticket_id")
        for key in {
            "ticket_id",
            "estimate_scope",
            "roadmap_prior",
            "proposal_rule",
        }:
            if actual.get(key) != baseline.get(key):
                raise GovernanceError(f"{ticket_id} ledger field differs from source: {key}")
        row_decision = _validate_confirmation_metadata(
            actual,
            decision_key="row_decision",
            person_key="row_confirmed_by_person_id",
            time_key="row_confirmed_at_utc",
            expected_person_id=expected_person_id,
            inventory_completed_at=inventory_completed_at,
            ledger_issue_time=issue_time,
            owner=f"{ticket_id} row decision",
        )
        selected_confidence = _required_string(actual, "selected_confidence")
        if selected_confidence not in {"low", "medium", "high"}:
            raise GovernanceError(f"{ticket_id} selected confidence is invalid")
        selected_status = _required_string(actual, "selected_current_status")
        if selected_status not in {"not_started", "in_progress", "blocked", "done"}:
            raise GovernanceError(f"{ticket_id} selected current status is invalid")
        _required_string_array(actual, "selected_dependency_assumptions")
        _required_string_array(actual, "selected_risk_assumptions")
        if row_decision in {
            "pending_maintainer_reconfirmation",
            "affirmatively_reconfirmed_after_inventory",
        }:
            for key in {
                "selected_confidence",
                "selected_current_status",
                "selected_dependency_assumptions",
                "selected_risk_assumptions",
            }:
                if actual.get(key) != baseline.get(key):
                    raise GovernanceError(
                        f"{ticket_id} {row_decision} cannot alter the baseline {key}"
                    )
        if row_decision == "reestimated_after_inventory":
            rationale = _required_string(actual, "row_decision_rationale")
            if rationale == baseline.get("row_decision_rationale"):
                raise GovernanceError(f"{ticket_id} re-estimation needs a specific row rationale")

        actual_proposals = _as_array(
            actual.get("execution_proposals"), owner=f"{ticket_id}.execution_proposals"
        )
        expected_proposals = _as_array(
            baseline.get("execution_proposals"), owner=f"expected {ticket_id}.execution_proposals"
        )
        if len(actual_proposals) != len(expected_proposals):
            raise GovernanceError(f"{ticket_id} authoring ledger occurrence count changed")
        for raw_proposal, raw_baseline_proposal in zip(
            actual_proposals, expected_proposals, strict=True
        ):
            proposal = _as_object(raw_proposal, owner=f"{ticket_id} execution proposal")
            baseline_proposal = _as_object(
                raw_baseline_proposal, owner=f"expected {ticket_id} execution proposal"
            )
            sprint = _required_string(baseline_proposal, "sprint")
            fixed_proposal_fields = {
                "sprint",
                "release",
                "proposed_p50_effort_hours",
                "proposed_p90_effort_hours",
                "proposed_reviewer_effort_hours",
            }
            for key in fixed_proposal_fields:
                if proposal.get(key) != baseline_proposal.get(key):
                    raise GovernanceError(
                        f"{ticket_id}/{sprint} changed source proposal field {key}"
                    )
            decision = _validate_confirmation_metadata(
                proposal,
                decision_key="decision",
                person_key="confirmed_by_person_id",
                time_key="confirmed_at_utc",
                expected_person_id=expected_person_id,
                inventory_completed_at=inventory_completed_at,
                ledger_issue_time=issue_time,
                owner=f"{ticket_id}/{sprint} estimate",
            )
            selected = (
                _required_integer(proposal, "selected_p50_effort_hours"),
                _required_integer(proposal, "selected_p90_effort_hours"),
                _required_integer(proposal, "selected_reviewer_effort_hours"),
            )
            if selected[1] < selected[0]:
                raise GovernanceError(f"P90 is below P50 for {ticket_id}/{sprint}")
            proposed = (
                _required_integer(proposal, "proposed_p50_effort_hours"),
                _required_integer(proposal, "proposed_p90_effort_hours"),
                _required_integer(proposal, "proposed_reviewer_effort_hours"),
            )
            if (
                decision
                in {
                    "pending_maintainer_reconfirmation",
                    "affirmatively_reconfirmed_after_inventory",
                }
                and selected != proposed
            ):
                raise GovernanceError(
                    f"{ticket_id}/{sprint} {decision} cannot alter the source proposal"
                )
            if decision == "reestimated_after_inventory":
                rationale = _required_string(proposal, "rationale")
                if rationale == baseline_proposal.get("rationale"):
                    raise GovernanceError(
                        f"{ticket_id}/{sprint} re-estimation needs a specific rationale"
                    )


def build_forecast(
    snapshot: RoadmapSnapshot,
    ledger: Mapping[str, Any],
    registry: Mapping[str, Any],
    *,
    issued_at: str,
    valid_until: str,
    producer_person_id: str,
    approval_roster_digest_value: str,
    requested_status: str | None = None,
    trusted_time_basis: str = "maintainer-trusted host UTC; Windows Time attestation unavailable",
) -> dict[str, Any]:
    issue_time, expiry_time = _validate_validity_interval(
        issued_at, valid_until, owner="delivery forecast"
    )
    if SHA256_PATTERN.fullmatch(approval_roster_digest_value) is None:
        raise GovernanceError("approval roster digest is not a canonical SHA-256 digest")
    method = _resolve_aggregation_method(registry)
    method_id = _required_string(method, "method_id")
    method_digest = _required_string(method, "definition_digest")
    registry_digest = _required_string(registry, "registry_digest")
    ledger_digest = _required_string(ledger, "ledger_digest")
    if ledger_digest != _ledger_digest(ledger):
        raise GovernanceError("authoring ledger digest mismatch")
    if ledger.get("accountable_maintainer_person_id") != producer_person_id:
        raise GovernanceError("forecast producer differs from the ledger accountable maintainer")
    ledger_issue_time = _parse_utc(
        _required_string(ledger, "issued_at_utc"), owner="authoring ledger issued_at_utc"
    )
    inventory_completed_at = _parse_utc(
        _required_string(ledger, "inventory_completed_at_utc"),
        owner="authoring ledger inventory_completed_at_utc",
    )
    if inventory_completed_at > ledger_issue_time:
        raise GovernanceError("authoring ledger predates its baseline inventory")
    if ledger_issue_time > issue_time:
        raise GovernanceError("forecast issue time predates its authoring ledger")
    ledger_by_id = _ledger_rows(ledger)
    occurrences = release_occurrences(snapshot)

    rows: list[dict[str, Any]] = []
    for ticket in snapshot.tickets:
        ticket_id = _required_string(ticket, "id")
        if ticket_id not in ledger_by_id:
            raise GovernanceError(f"authoring ledger lacks ticket: {ticket_id}")
        ledger_row = ledger_by_id[ticket_id]
        scope = _required_string(ledger_row, "estimate_scope")
        delivery = _as_object(ticket.get("delivery"), owner=f"{ticket_id}.delivery")
        estimate = _as_object(delivery.get("estimate"), owner=f"{ticket_id}.estimate")
        expected_scope = _required_string(estimate, "scope")
        if scope != expected_scope:
            raise GovernanceError(
                f"estimate scope for {ticket_id} is {scope!r}, expected {expected_scope!r}"
            )
        proposals = _as_array(
            ledger_row.get("execution_proposals"), owner=f"{ticket_id}.execution_proposals"
        )
        expected_occurrences = occurrences[ticket_id]
        if len(proposals) != len(expected_occurrences):
            raise GovernanceError(f"occurrence count mismatch for {ticket_id}")
        execution_estimates: list[dict[str, Any]] = []
        decisions: set[str] = set()
        confirmation_times: list[tuple[datetime, str]] = []
        for raw_proposal, (expected_sprint, expected_release) in zip(
            proposals, expected_occurrences, strict=True
        ):
            proposal = _as_object(raw_proposal, owner=f"{ticket_id} proposal")
            sprint = _required_string(proposal, "sprint")
            release = _required_string(proposal, "release")
            if (sprint, release) != (expected_sprint, expected_release):
                raise GovernanceError(f"reordered or changed occurrence for {ticket_id}")
            p50 = _required_integer(proposal, "selected_p50_effort_hours")
            p90 = _required_integer(proposal, "selected_p90_effort_hours")
            reviewer = _required_integer(proposal, "selected_reviewer_effort_hours")
            if p90 < p50:
                raise GovernanceError(f"P90 is below P50 for {ticket_id}/{sprint}")
            decision = _validate_confirmation_metadata(
                proposal,
                decision_key="decision",
                person_key="confirmed_by_person_id",
                time_key="confirmed_at_utc",
                expected_person_id=producer_person_id,
                inventory_completed_at=inventory_completed_at,
                ledger_issue_time=ledger_issue_time,
                owner=f"{ticket_id}/{sprint} estimate",
            )
            if decision != "pending_maintainer_reconfirmation":
                confirmation_value = _required_string(proposal, "confirmed_at_utc")
                confirmation_times.append(
                    (
                        _parse_utc(
                            confirmation_value,
                            owner=f"{ticket_id}/{sprint} estimate.confirmed_at_utc",
                        ),
                        confirmation_value,
                    )
                )
            proposed_values = (
                _required_integer(proposal, "proposed_p50_effort_hours"),
                _required_integer(proposal, "proposed_p90_effort_hours"),
                _required_integer(proposal, "proposed_reviewer_effort_hours"),
            )
            if (
                decision
                in {
                    "pending_maintainer_reconfirmation",
                    "affirmatively_reconfirmed_after_inventory",
                }
                and (p50, p90, reviewer) != proposed_values
            ):
                raise GovernanceError(
                    f"{ticket_id}/{sprint} changed a proposal without a re-estimation decision"
                )
            decisions.add(decision)
            execution_estimates.append(
                {
                    "sprint": sprint,
                    "release": release,
                    "p50_effort_hours": p50,
                    "p90_effort_hours": p90,
                    "reviewer_effort_hours": reviewer,
                }
            )
        row_decision = _validate_confirmation_metadata(
            ledger_row,
            decision_key="row_decision",
            person_key="row_confirmed_by_person_id",
            time_key="row_confirmed_at_utc",
            expected_person_id=producer_person_id,
            inventory_completed_at=inventory_completed_at,
            ledger_issue_time=ledger_issue_time,
            owner=f"{ticket_id} row decision",
        )
        if row_decision != "pending_maintainer_reconfirmation":
            row_confirmation_value = _required_string(ledger_row, "row_confirmed_at_utc")
            confirmation_times.append(
                (
                    _parse_utc(
                        row_confirmation_value,
                        owner=f"{ticket_id} row decision.row_confirmed_at_utc",
                    ),
                    row_confirmation_value,
                )
            )
        row_trusted_issue_time = (
            min(confirmation_times, key=lambda item: item[0])[1]
            if confirmation_times
            else _required_string(ledger, "issued_at_utc")
        )
        rebaseline_status = (
            "confirmed"
            if decisions
            and decisions
            <= {"affirmatively_reconfirmed_after_inventory", "reestimated_after_inventory"}
            and row_decision
            in {"affirmatively_reconfirmed_after_inventory", "reestimated_after_inventory"}
            else "pending_maintainer_confirmation"
        )
        dependency_assumptions = _required_string_array(
            ledger_row, "selected_dependency_assumptions"
        )
        risk_assumptions = _required_string_array(ledger_row, "selected_risk_assumptions")
        rows.append(
            {
                "ticket_id": ticket_id,
                "estimate_scope": scope,
                "planned_execution_count": len(execution_estimates),
                "execution_estimates": execution_estimates,
                "aggregate_p50_effort_hours": _checked_sum(
                    (item["p50_effort_hours"] for item in execution_estimates),
                    owner=f"{ticket_id} aggregate P50",
                ),
                "aggregate_p90_effort_hours": _checked_sum(
                    (item["p90_effort_hours"] for item in execution_estimates),
                    owner=f"{ticket_id} aggregate P90",
                ),
                "aggregate_reviewer_effort_hours": _checked_sum(
                    (item["reviewer_effort_hours"] for item in execution_estimates),
                    owner=f"{ticket_id} aggregate reviewer effort",
                ),
                "aggregate_method_id": method_id,
                "aggregate_method_definition_digest": method_digest,
                "aggregate_dependence_assumptions": [
                    "Occurrence effort ranks are comonotonic under one shared latent severity.",
                    "Effort is additive; no elapsed-time or parallelism discount is applied.",
                    "No ticket or occurrence independence is claimed.",
                ],
                "confidence": _required_string(ledger_row, "selected_confidence"),
                "dependency_assumptions": dependency_assumptions,
                "risk_assumptions": risk_assumptions,
                "current_status": _required_string(ledger_row, "selected_current_status"),
                "trusted_issue_time": row_trusted_issue_time,
                "rebaseline_status": rebaseline_status,
            }
        )
    if set(ledger_by_id) != {_required_string(ticket, "id") for ticket in snapshot.tickets}:
        raise GovernanceError("authoring ledger has missing or extra ticket rows")
    if not rows:
        raise GovernanceError("delivery forecast requires at least one ticket row")
    oldest_decision_time = min(
        _parse_utc(
            _required_string(row, "trusted_issue_time"),
            owner=f"{_required_string(row, 'ticket_id')}.trusted_issue_time",
        )
        for row in rows
    )
    if expiry_time > oldest_decision_time + MAX_S1_VALIDITY:
        raise GovernanceError(
            "delivery forecast valid_until_utc exceeds 30 days after its oldest decision"
        )
    all_confirmed = all(row["rebaseline_status"] == "confirmed" for row in rows)
    derived_status = "ready_for_acceptance" if all_confirmed else "proposed"
    forecast_status = requested_status or derived_status
    if forecast_status not in {"proposed", "ready_for_acceptance", "accepted"}:
        raise GovernanceError(f"unknown forecast status: {forecast_status}")
    if not all_confirmed and forecast_status != "proposed":
        raise GovernanceError("an unconfirmed ledger can produce only a proposed forecast")
    if all_confirmed and forecast_status == "proposed":
        raise GovernanceError("a fully confirmed ledger cannot remain proposed")
    portfolio = {
        "ticket_count": len(rows),
        "occurrence_count": sum(row["planned_execution_count"] for row in rows),
        "aggregate_p50_effort_hours": _checked_sum(
            (row["aggregate_p50_effort_hours"] for row in rows), owner="portfolio P50"
        ),
        "aggregate_p90_effort_hours": _checked_sum(
            (row["aggregate_p90_effort_hours"] for row in rows), owner="portfolio P90"
        ),
        "aggregate_reviewer_effort_hours": _checked_sum(
            (row["aggregate_reviewer_effort_hours"] for row in rows),
            owner="portfolio reviewer effort",
        ),
        "aggregate_method_id": method_id,
        "aggregate_method_definition_digest": method_digest,
    }
    projection: dict[str, Any] = {
        "contract_id": FORECAST_CONTRACT_ID,
        "spec_revision": SPEC_REVISION,
        "forecast_status": forecast_status,
        "full_roadmap_digest": snapshot.raw_digest,
        "sorted_ticket_set_digest": snapshot.ticket_set_digest,
        "dependency_graph_digest": snapshot.dependency_graph_digest,
        "release_train_digest": snapshot.release_train_digest,
        "aggregation_method_registry_digest": registry_digest,
        "authoring_ledger_digest": ledger_digest,
        "approval_roster_digest": approval_roster_digest_value,
        "issued_at_utc": issued_at,
        "valid_until_utc": valid_until,
        "trusted_time_basis": trusted_time_basis,
        "producer_person_id": producer_person_id,
        "producer_role": "technical_lead",
        "portfolio_aggregate": portfolio,
        "rows": rows,
    }
    record_digest = domain_digest(FORECAST_DOMAIN, projection)
    signature = _pending_signature(producer_person_id, "technical_lead", record_digest)
    receipt_projection: dict[str, Any] = {
        "receipt_type": "development_design_acceptance",
        "receipt_status": (
            "accepted_for_development"
            if forecast_status == "accepted"
            else "pending_human_acceptance"
        ),
        "subject_contract_id": FORECAST_CONTRACT_ID,
        "subject_record_digest": record_digest,
        "bound_source_digests": {
            "full_roadmap_digest": snapshot.raw_digest,
            "sorted_ticket_set_digest": snapshot.ticket_set_digest,
            "dependency_graph_digest": snapshot.dependency_graph_digest,
            "release_train_digest": snapshot.release_train_digest,
            "aggregation_method_registry_digest": registry_digest,
            "authoring_ledger_digest": ledger_digest,
        },
        "issuer_person_id": producer_person_id,
        "issuer_role": "repository_maintainer",
        "approval_mode": "maintainer_development",
        "approval_roster_digest": approval_roster_digest_value,
        "independence_claimed": False,
        "authorization_effect": "none",
        "author_reviewer_relationship": "same_person_maintainer_development_self_acceptance",
        "accepted_competence": [
            "planning_governance:s1",
            "repository_maintenance:bounded_development",
            "technical_direction:s1",
        ],
        "conflicts": [
            "Sole maintainer self-acceptance; no independence is claimed.",
            "LLM-authored proposal reviewed under accountable human authority.",
        ],
        "issued_at_utc": issued_at,
        "validity_context": {
            "not_before_utc": issued_at,
            "not_after_utc": valid_until,
            "half_open_interval": True,
        },
        "review_evidence": [
            "ADR-V1-MAP",
            "delivery-forecast.authoring-ledger.json",
            "delivery-forecast.aggregation-registry.json",
            "scripts/v1_s1_governance.py validation",
        ],
        "allowed_operations": [
            "S2 commitment after every estimate is human-confirmed and signatures verify",
            "bounded development planning",
        ],
        "limitations": [
            "NO_INDEPENDENT_REVIEW",
            (
                "No method admission, qualification, release authorization, or runtime "
                "authorization effect."
            ),
            "Pending signatures or pending estimate confirmations make this receipt non-accepting.",
        ],
    }
    receipt_digest = domain_digest(RECEIPT_DOMAIN, receipt_projection)
    receipt = {
        **receipt_projection,
        "receipt_digest": receipt_digest,
        "signature_envelope": _pending_signature(
            producer_person_id, "repository_maintainer", receipt_digest
        ),
    }
    return {
        **projection,
        "record_digest": record_digest,
        "signature_envelope": signature,
        "acceptance_receipt": receipt,
    }


def _required_integer(mapping: Mapping[str, Any], key: str) -> int:
    value = mapping.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > 2**53 - 1:
        raise GovernanceError(f"{key} must be a nonnegative integer")
    return value


def _checked_sum(values: Iterable[int], *, owner: str) -> int:
    total = 0
    for value in values:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise GovernanceError(f"{owner} contains a non-integer or negative value")
        total += value
        if total > 2**53 - 1:
            raise GovernanceError(f"{owner} exceeds the RFC 8785 safe-integer range")
    return total


def _pending_signature(person_id: str, role: str, subject_digest: str) -> dict[str, Any]:
    return {
        "profile": SIGNATURE_PROFILE,
        "status": "pending_human_signature",
        "namespace": SIGNATURE_NAMESPACE,
        "signed_payload_encoding": SIGNATURE_PAYLOAD_ENCODING,
        "signature_encoding": SIGNATURE_ENCODING,
        "signer_person_id": person_id,
        "signer_role": role,
        "subject_digest": subject_digest,
        "public_key_fingerprint": MAINTAINER_KEY_FINGERPRINT,
        "signed_at_utc": None,
        "signature": None,
    }


def _parse_utc(value: str, *, owner: str) -> datetime:
    if UTC_PATTERN.fullmatch(value) is None:
        raise GovernanceError(
            f"{owner} must use canonical RFC 3339 UTC with seconds and a Z suffix"
        )
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise GovernanceError(f"{owner} is not RFC 3339 UTC") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise GovernanceError(f"{owner} must be UTC")
    return parsed


def _validate_validity_interval(
    issued_at: str, valid_until: str, *, owner: str
) -> tuple[datetime, datetime]:
    """Parse and bound an S1 half-open validity interval.

    S1 records deliberately expire after at most 30 days.  This prevents a
    structurally valid but effectively perpetual planning authorization from
    surviving changes to the roadmap, repository, staffing, or trust key.
    """

    issue_time = _parse_utc(issued_at, owner=f"{owner} issued_at_utc")
    expiry_time = _parse_utc(valid_until, owner=f"{owner} valid_until_utc")
    duration = expiry_time - issue_time
    if duration <= timedelta(0):
        raise GovernanceError(f"{owner} validity interval must be nonempty")
    if duration > MAX_S1_VALIDITY:
        raise GovernanceError(f"{owner} validity interval exceeds 30 days")
    return issue_time, expiry_time


def _ledger_digest(ledger: Mapping[str, Any]) -> str:
    projection = {key: value for key, value in ledger.items() if key != "ledger_digest"}
    return domain_digest(LEDGER_DOMAIN, projection)


def _forecast_projection(forecast: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in forecast.items()
        if key not in {"signature_envelope", "record_digest", "acceptance_receipt"}
    }


def _receipt_projection(receipt: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in receipt.items()
        if key not in {"signature_envelope", "receipt_digest"}
    }


def _ticket_receipt_projection(receipt: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in receipt.items()
        if key not in {"receipt_digest", "signature_envelope"}
    }


def _record_projection(record: Mapping[str, Any], digest_field: str) -> dict[str, Any]:
    return {key: value for key, value in record.items() if key != digest_field}


def validate_maintainer_signing_key(
    record: Mapping[str, Any],
    schema: Mapping[str, Any],
    *,
    expected_person_id: str,
    allow_pending: bool,
) -> str:
    """Validate the checked-in public trust-key declaration and return its digest."""

    _validate_json_schema(record, schema, owner="maintainer signing key")
    expected_fields: dict[str, object] = {
        "format": "agent-assure-governance-signing-key/1",
        "spec_revision": SPEC_REVISION,
        "person_id": expected_person_id,
        "algorithm": "ssh-ed25519",
        "public_key": MAINTAINER_PUBLIC_KEY,
        "public_key_fingerprint": MAINTAINER_KEY_FINGERPRINT,
        "signature_profile": SIGNATURE_PROFILE,
        "allowed_namespace": SIGNATURE_NAMESPACE,
        "allowed_roles": ["repository_maintainer", "technical_lead"],
        "trust_scope": [
            "S1 maintainer-development governance records only",
            (
                "Public-key possession does not establish legal identity, independence, or "
                "qualification"
            ),
        ],
    }
    for field, expected in expected_fields.items():
        if record.get(field) != expected:
            raise GovernanceError(f"maintainer signing key has unexpected {field}")
    status = _required_string(record, "key_status")
    if status not in {"pending_human_confirmation", "confirmed_by_human"}:
        raise GovernanceError("maintainer signing key status is invalid")
    limitations = set(_required_string_array(record, "limitations"))
    permanent_limitations = {
        "Repository-local TOFU metadata is not an independent trust anchor",
        ("No runtime, method-admission, deployment, or release-authorization trust is granted"),
    }
    if not permanent_limitations <= limitations:
        raise GovernanceError("maintainer signing key limitations are incomplete")
    if status == "pending_human_confirmation":
        if "Pending explicit human affirmation of the displayed fingerprint" not in limitations:
            raise GovernanceError("pending trust key omits the human-confirmation limitation")
        if record.get("out_of_band_confirmation_evidence") is not None:
            raise GovernanceError("pending trust key must not assert confirmation evidence")
    else:
        evidence = record.get("out_of_band_confirmation_evidence")
        if not isinstance(evidence, str) or not evidence.strip():
            raise GovernanceError("confirmed trust key requires out-of-band evidence")
        if "Pending explicit human affirmation of the displayed fingerprint" in limitations:
            raise GovernanceError("confirmed trust key retains a false pending limitation")
    digest = domain_digest(SIGNING_KEY_DOMAIN, _record_projection(record, "record_digest"))
    if record.get("record_digest") != digest:
        raise GovernanceError("maintainer signing key record digest mismatch")
    if not allow_pending and status != "confirmed_by_human":
        raise GovernanceError("maintainer signing key is pending human confirmation")
    return digest


def _baseline_full_suite_status(record: Mapping[str, Any]) -> str:
    runs = _as_array(record.get("validation_runs"), owner="baseline validation_runs")
    matches = [
        _as_object(run, owner="baseline validation run")
        for run in runs
        if isinstance(run, dict) and run.get("check_id") == "repository_pytest_full"
    ]
    if len(matches) != 1:
        raise GovernanceError("baseline observations require exactly one full pytest result")
    status = _required_string(matches[0], "outcome")
    if status not in {"passed", "failed", "timed_out"}:
        raise GovernanceError("full pytest baseline outcome is invalid")
    return status


def validate_baseline_observations(
    snapshot: RoadmapSnapshot,
    record: Mapping[str, Any],
    schema: Mapping[str, Any],
    *,
    repository_root: Path,
) -> str:
    """Validate immutable S1 inventory facts without refreshing external state."""

    _validate_json_schema(record, schema, owner="baseline observations")
    inventory_completed_at = _parse_utc(
        _required_string(record, "inventory_completed_at_utc"),
        owner="baseline inventory_completed_at_utc",
    )
    repository = _as_object(record.get("repository"), owner="baseline repository")
    expected_repository_fields: dict[str, object] = {
        "approved_remote_url": "https://github.com/acblabs/agent-assure.git",
        "fetch_command": "git fetch --prune origin main --tags",
        "fetch_exit_code": 0,
        "origin_main_commit": PINNED_BASE_COMMIT,
        "baseline_tag_name": "v0.7.0",
        "baseline_tag_object": "ea4b50bd461efd817b7dc2fa5591d06ed9599a6e",
        "baseline_tag_commit": PINNED_BASE_COMMIT,
        "tag_main_delta": "none",
        "branch_name": "feat/v1-assurance-compiler",
        "branch_base_commit": PINNED_BASE_COMMIT,
    }
    for field, expected in expected_repository_fields.items():
        if repository.get(field) != expected:
            raise GovernanceError(f"baseline repository evidence has unexpected {field}")
    fetch_observed_at = _parse_utc(
        _required_string(repository, "fetch_observed_at_utc"),
        owner="baseline fetch_observed_at_utc",
    )
    if inventory_completed_at < fetch_observed_at:
        raise GovernanceError("baseline inventory completion predates the fetch observation")
    environment = _as_object(record.get("environment"), owner="baseline environment")
    if environment.get("platform") != "Windows" or environment.get("python_version") != "3.12.13":
        raise GovernanceError("baseline platform or Python identity changed")
    command_expectations = {
        "pip_check": ("passed", 0),
        "time_attestation": ("unavailable", -2147023834),
    }
    for name, (expected_outcome, expected_exit_code) in command_expectations.items():
        command_result = _as_object(environment.get(name), owner=f"baseline {name}")
        if command_result.get("outcome") != expected_outcome:
            raise GovernanceError(f"baseline {name} outcome changed")
        if command_result.get("exit_code") != expected_exit_code:
            raise GovernanceError(f"baseline {name} exit code changed")
        observed_at = _parse_utc(
            _required_string(command_result, "observed_at_utc"),
            owner=f"baseline {name} observed_at_utc",
        )
        if observed_at > inventory_completed_at:
            raise GovernanceError(f"baseline {name} was recorded after inventory completion")
    tool_observed_at = _parse_utc(
        _required_string(environment, "trusted_executables_observed_at_utc"),
        owner="baseline trusted_executables_observed_at_utc",
    )
    if tool_observed_at > inventory_completed_at:
        raise GovernanceError("trusted executable identity was recorded after inventory completion")
    trusted_tools: dict[str, dict[str, Any]] = {}
    for value in _as_array(
        environment.get("trusted_executables"), owner="baseline trusted_executables"
    ):
        tool = _as_object(value, owner="baseline trusted executable")
        if set(tool) != {"name", "absolute_path", "size_bytes", "sha256"}:
            raise GovernanceError("baseline trusted executable evidence has unexpected fields")
        name = _required_string(tool, "name")
        if name in trusted_tools:
            raise GovernanceError(f"duplicate baseline trusted executable: {name}")
        trusted_tools[name] = tool
    if set(trusted_tools) != set(FROZEN_S1_EXECUTABLE_IDENTITIES):
        raise GovernanceError("baseline trusted executable evidence is incomplete")
    for name, identity in FROZEN_S1_EXECUTABLE_IDENTITIES.items():
        tool = trusted_tools[name]
        expected_tool = {
            "name": name,
            "absolute_path": identity.path,
            "size_bytes": identity.size_bytes,
            "sha256": f"sha256:{identity.sha256}",
        }
        if tool != expected_tool:
            raise GovernanceError(f"baseline trusted executable identity changed: {name}")
    runtime_observed_at = _parse_utc(
        _required_string(environment, "trusted_python_runtime_observed_at_utc"),
        owner="baseline trusted_python_runtime_observed_at_utc",
    )
    if runtime_observed_at > inventory_completed_at:
        raise GovernanceError("trusted Python runtime was recorded after inventory completion")
    expected_python_runtime: dict[str, object] = {
        "execution_profile": "powershell-preverified-cpython-3.12.13-I-S-B/v1",
        "launcher_profile": _LAUNCHER_PROFILE,
        "implementation": "CPython",
        "version": "3.12.13",
        "cache_tag": _FROZEN_PYTHON_CACHE_TAG,
        "python_executable": {
            "absolute_path": str(_FROZEN_PYTHON_EXECUTABLE),
            "size_bytes": _FROZEN_PYTHON_EXECUTABLE_SIZE,
            "sha256": f"sha256:{_FROZEN_PYTHON_EXECUTABLE_SHA256}",
        },
        "python_dll": {
            "absolute_path": str(_FROZEN_PYTHON_DLL),
            "size_bytes": _FROZEN_PYTHON_DLL_SIZE,
            "sha256": f"sha256:{_FROZEN_PYTHON_DLL_SHA256}",
        },
        "base_runtime_file_count": _FROZEN_BASE_RUNTIME_FILE_COUNT,
        "base_runtime_size_bytes": _FROZEN_BASE_RUNTIME_SIZE_BYTES,
        "base_runtime_sha256": f"sha256:{_FROZEN_BASE_RUNTIME_SHA256}",
        "site_packages_path": str(
            (repository_root.resolve() / ".venv/Lib/site-packages").resolve()
        ),
        "runtime_roots": list(_RUNTIME_ROOTS),
        "runtime_file_count": _FROZEN_RUNTIME_FILE_COUNT,
        "runtime_size_bytes": _FROZEN_RUNTIME_SIZE_BYTES,
        "runtime_sha256": f"sha256:{_FROZEN_RUNTIME_SHA256}",
        "site_startup_disabled": True,
        "bytecode_writes_disabled": True,
        "fresh_prestart_pycache_prefix_required": True,
    }
    runtime = _as_object(
        environment.get("trusted_python_runtime"), owner="baseline trusted Python runtime"
    )
    if runtime != expected_python_runtime:
        raise GovernanceError("baseline trusted Python runtime identity changed")
    cli_reservation = _as_object(record.get("cli_reservation"), owner="CLI reservation")
    if (
        cli_reservation.get("collision_found") is not False
        or cli_reservation.get("probe_exit_code") != 2
    ):
        raise GovernanceError("baseline CLI collision observation changed")
    cli_observed_at = _parse_utc(
        _required_string(cli_reservation, "observed_at_utc"),
        owner="baseline CLI observed_at_utc",
    )
    if cli_observed_at > inventory_completed_at:
        raise GovernanceError("baseline CLI observation follows inventory completion")
    roadmap = _as_object(record.get("roadmap"), owner="baseline roadmap")
    if roadmap != {
        "raw_digest": snapshot.raw_digest,
        "local_only": True,
        "git_index_tracked": False,
    }:
        raise GovernanceError("baseline roadmap evidence is not the local-only source snapshot")
    locks = _as_array(record.get("dependency_locks"), owner="dependency_locks")
    observed_paths: set[str] = set()
    for item in locks:
        lock = _as_object(item, owner="dependency lock")
        path = _required_string(lock, "path")
        if path in observed_paths:
            raise GovernanceError(f"duplicate dependency lock evidence: {path}")
        observed_paths.add(path)
        if lock.get("sha256") != PINNED_LOCK_DIGESTS.get(path):
            raise GovernanceError(
                f"dependency lock digest differs from the frozen baseline: {path}"
            )
        committed = _run_git(repository_root, ["show", f"{PINNED_BASE_COMMIT}:{path}"])
        if committed.returncode != 0 or raw_digest(committed.stdout) != lock.get("sha256"):
            raise GovernanceError(f"pinned base commit does not reproduce dependency lock: {path}")
    if observed_paths != set(PINNED_LOCK_DIGESTS):
        raise GovernanceError("baseline dependency lock evidence is incomplete")
    validation_runs = _as_array(record.get("validation_runs"), owner="validation_runs")
    check_ids: set[str] = set()
    for item in validation_runs:
        run = _as_object(item, owner="baseline validation run")
        check_id = _required_string(run, "check_id")
        if check_id in check_ids:
            raise GovernanceError(f"duplicate baseline validation check: {check_id}")
        check_ids.add(check_id)
        observed_at = _parse_utc(
            _required_string(run, "observed_at_utc"),
            owner=f"baseline {check_id} observed_at_utc",
        )
        if observed_at > inventory_completed_at:
            raise GovernanceError(f"baseline {check_id} was recorded after inventory completion")
    _baseline_full_suite_status(record)
    digest = domain_digest(
        BASELINE_OBSERVATIONS_DOMAIN,
        _record_projection(record, "observations_digest"),
    )
    if record.get("observations_digest") != digest:
        raise GovernanceError("baseline observations digest mismatch")
    return digest


def _artifact_evidence(repository_root: Path, relative_path: str, *, kind: str) -> dict[str, Any]:
    root = repository_root.resolve()
    path = (root / relative_path).resolve()
    try:
        canonical_relative = path.relative_to(root).as_posix()
    except ValueError as exc:
        raise GovernanceError(f"artifact path leaves the repository root: {relative_path}") from exc
    if canonical_relative != Path(relative_path).as_posix():
        raise GovernanceError(f"artifact path is not canonical: {relative_path}")
    if not path.is_file() or path.is_symlink():
        raise GovernanceError(f"artifact is not a regular non-symlink file: {relative_path}")
    payload = path.read_bytes()
    return {
        "path": canonical_relative,
        "kind": kind,
        "size_bytes": len(payload),
        "sha256": raw_digest(payload),
    }


def _artifact_evidence_for_payload(
    repository_root: Path, relative_path: str, *, kind: str, payload: bytes
) -> dict[str, Any]:
    """Build artifact evidence for bytes staged but not yet installed."""

    root = repository_root.resolve()
    path = (root / relative_path).resolve()
    try:
        canonical_relative = path.relative_to(root).as_posix()
    except ValueError as exc:
        raise GovernanceError(f"artifact path leaves the repository root: {relative_path}") from exc
    if canonical_relative != Path(relative_path).as_posix():
        raise GovernanceError(f"artifact path is not canonical: {relative_path}")
    return {
        "path": canonical_relative,
        "kind": kind,
        "size_bytes": len(payload),
        "sha256": raw_digest(payload),
    }


def _artifact_evidence_from_commit(
    repository_root: Path,
    result_commit: str,
    relative_path: str,
    *,
    kind: str,
) -> dict[str, Any]:
    tree_entry = _run_git(repository_root, ["ls-tree", result_commit, "--", relative_path])
    fields = tree_entry.stdout.split(None, 3)
    if (
        tree_entry.returncode != 0
        or len(fields) < 4
        or fields[0] not in {b"100644", b"100755"}
        or fields[1] != b"blob"
    ):
        raise GovernanceError(f"result artifact is not a regular Git blob: {relative_path}")
    committed = _run_git(repository_root, ["show", f"{result_commit}:{relative_path}"])
    if committed.returncode != 0:
        raise GovernanceError(f"unable to read result artifact: {relative_path}")
    return {
        "path": relative_path,
        "kind": kind,
        "size_bytes": len(committed.stdout),
        "sha256": raw_digest(committed.stdout),
    }


def _validated_artifact_evidence(
    records: Sequence[Mapping[str, Any]],
    expected_paths: Sequence[tuple[str, str]],
    *,
    owner: str,
) -> list[dict[str, Any]]:
    """Validate and canonically order self-authenticating artifact evidence.

    Accepted records must remain verifiable after a later sprint changes the
    working tree.  This helper validates the frozen evidence carried by the
    signed record; the corresponding Git-object bytes are checked separately.
    """

    expected = dict(expected_paths)
    if len(expected) != len(expected_paths):
        raise GovernanceError(f"{owner} expected path contract contains duplicates")
    observed: dict[str, dict[str, Any]] = {}
    required_keys = {"path", "kind", "size_bytes", "sha256"}
    for value in records:
        record = _as_object(value, owner=f"{owner} artifact")
        if set(record) != required_keys:
            raise GovernanceError(f"{owner} artifact evidence has unexpected fields")
        path = _required_string(record, "path")
        if path in observed:
            raise GovernanceError(f"{owner} artifact evidence repeats path: {path}")
        expected_kind = expected.get(path)
        if expected_kind is None:
            raise GovernanceError(f"{owner} artifact evidence has unexpected path: {path}")
        if record.get("kind") != expected_kind:
            raise GovernanceError(f"{owner} artifact kind changed for {path}")
        size_bytes = _required_integer(record, "size_bytes")
        if size_bytes > 16 * 1024 * 1024:
            raise GovernanceError(f"{owner} artifact exceeds the evidence size limit: {path}")
        digest = record.get("sha256")
        if not isinstance(digest, str) or SHA256_PATTERN.fullmatch(digest) is None:
            raise GovernanceError(f"{owner} artifact digest is invalid: {path}")
        observed[path] = dict(record)
    missing = sorted(set(expected) - set(observed), key=_utf8_sort_key)
    if missing:
        raise GovernanceError(f"{owner} artifact evidence is missing paths: {missing}")
    return [observed[path] for path in sorted(observed, key=_utf8_sort_key)]


def _trusted_executable(name: str, *, repository_root: Path | None = None) -> str:
    """Return a hash-pinned executable without consulting caller-controlled PATH."""

    identity = TRUSTED_EXECUTABLE_IDENTITIES.get(name)
    if identity is None:
        raise GovernanceError(f"{name} has no frozen S1 executable identity")
    configured = Path(identity.path)
    try:
        resolved = configured.resolve(strict=True)
    except OSError as exc:
        raise GovernanceError(f"trusted {name} executable is unavailable") from exc
    if (
        not configured.is_absolute()
        or not resolved.is_file()
        or os.path.normcase(str(resolved)) != os.path.normcase(str(configured))
    ):
        raise GovernanceError(f"trusted {name} path is not an absolute regular file")
    for component in (resolved, *resolved.parents):
        try:
            attributes = getattr(component.lstat(), "st_file_attributes", 0)
        except OSError as exc:
            raise GovernanceError(f"unable to attest trusted {name} path") from exc
        # FILE_ATTRIBUTE_REPARSE_POINT.  Reject junctions as well as symlinks;
        # Path.is_symlink() alone does not cover every Windows reparse type.
        if attributes & 0x400:
            raise GovernanceError(f"trusted {name} path traverses a reparse point")
    forbidden_roots = [Path(__file__).resolve().parents[1]]
    if repository_root is not None:
        forbidden_roots.append(repository_root.resolve())
    for root in forbidden_roots:
        try:
            resolved.relative_to(root)
        except ValueError:
            continue
        raise GovernanceError(f"refusing worktree-local {name} executable: {resolved}")
    try:
        actual_size = resolved.stat().st_size
        digest = hashlib.sha256()
        with resolved.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise GovernanceError(f"unable to attest trusted {name} executable") from exc
    if actual_size != identity.size_bytes or digest.hexdigest() != identity.sha256:
        raise GovernanceError(f"trusted {name} executable identity changed")
    return str(resolved)


def _governance_subprocess_environment() -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith("GIT_")
        and key.upper()
        not in {
            "ALL_PROXY",
            "BASH_ENV",
            "CURL_CA_BUNDLE",
            "DYLD_INSERT_LIBRARIES",
            "DYLD_LIBRARY_PATH",
            "ENV",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "LD_LIBRARY_PATH",
            "LD_PRELOAD",
            "NO_PROXY",
            "OPENSSL_CONF",
            "OPENSSL_ENGINES",
            "OPENSSL_MODULES",
            "REQUESTS_CA_BUNDLE",
            "SSL_CERT_DIR",
            "SSL_CERT_FILE",
            "SSH_AGENT_PID",
            "SSH_ASKPASS",
            "SSH_ASKPASS_REQUIRE",
            "SSH_AUTH_SOCK",
        }
    }
    environment.update(
        {
            "GIT_ALLOW_PROTOCOL": "https",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PROTOCOL_FROM_USER": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "GCM_INTERACTIVE": "Never",
            "LANG": "C",
            "LC_ALL": "C",
            "NoDefaultCurrentDirectoryInExePath": "1",
        }
    )
    environment["PATH"] = (
        r"C:\Program Files\Git\mingw64\bin;C:\Program Files\Git\usr\bin;"
        r"C:\Windows\System32;C:\Windows"
        if os.name == "nt"
        else "/usr/bin:/bin"
    )
    return environment


def _git_invocation_prefix(executable: str, hooks_directory: Path) -> list[str]:
    return [
        executable,
        "--no-replace-objects",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.untrackedCache=false",
        "-c",
        f"core.hooksPath={hooks_directory.resolve(strict=True)}",
        "-c",
        "credential.helper=",
        "-c",
        "http.proxy=",
        "-c",
        "http.sslVerify=true",
        "-c",
        "protocol.allow=never",
        "-c",
        "protocol.https.allow=always",
    ]


def _run_git(repository_root: Path, arguments: Sequence[str]) -> subprocess.CompletedProcess[bytes]:
    executable = _trusted_executable("git", repository_root=repository_root)
    try:
        with tempfile.TemporaryDirectory(prefix="agent-assure-s1-hooks-") as temporary:
            hooks_directory = Path(temporary)
            return subprocess.run(
                [
                    *_git_invocation_prefix(executable, hooks_directory),
                    "-c",
                    f"safe.directory={repository_root.resolve()}",
                    "-C",
                    str(repository_root.resolve()),
                    *arguments,
                ],
                capture_output=True,
                check=False,
                env=_governance_subprocess_environment(),
                timeout=30,
            )
    except subprocess.TimeoutExpired as exc:
        raise GovernanceError("governed Git inspection timed out") from exc


def _run_isolated_git(
    working_directory: Path, arguments: Sequence[str], *, network: bool = False
) -> subprocess.CompletedProcess[bytes]:
    """Run Git outside the worktree with system/global/local config disabled."""

    executable = _trusted_executable("git")
    if network:
        _trusted_executable("git-remote-https")
    try:
        with tempfile.TemporaryDirectory(prefix="agent-assure-s1-hooks-") as temporary:
            hooks_directory = Path(temporary)
            return subprocess.run(
                [*_git_invocation_prefix(executable, hooks_directory), *arguments],
                cwd=working_directory.resolve(strict=True),
                capture_output=True,
                check=False,
                env=_governance_subprocess_environment(),
                timeout=120 if network else 30,
            )
    except subprocess.TimeoutExpired as exc:
        raise GovernanceError("isolated governed Git operation timed out") from exc


def _validate_local_git_configuration(repository_root: Path) -> None:
    """Reject repository configuration capable of changing governed observations."""

    completed = _run_git(
        repository_root,
        ["config", "--local", "--no-includes", "--null", "--list"],
    )
    if completed.returncode != 0:
        raise GovernanceError("unable to inspect repository-local Git configuration")
    entries = completed.stdout.split(b"\0")
    if entries[-1:] == [b""]:
        entries.pop()
    observed: dict[str, str] = {}
    exact_values: dict[str, set[str]] = {
        "core.repositoryformatversion": {"0"},
        "core.filemode": {"true", "false"},
        "core.bare": {"false"},
        "core.logallrefupdates": {"true"},
        "core.symlinks": {"true", "false"},
        "core.ignorecase": {"true", "false"},
        "remote.origin.url": {APPROVED_ORIGIN_URL},
        "remote.origin.fetch": {"+refs/heads/*:refs/remotes/origin/*"},
        "gpg.format": {"ssh"},
        "tag.gpgsign": {"true"},
    }
    inert_user_keys = {"user.name", "user.email", "user.signingkey"}
    for raw_entry in entries:
        raw_key, separator, raw_value = raw_entry.partition(b"\n")
        if not separator or not raw_key or b"\n" in raw_value or b"\r" in raw_entry:
            raise GovernanceError("repository-local Git configuration is malformed")
        try:
            key = raw_key.decode("utf-8", errors="strict").casefold()
            value = raw_value.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise GovernanceError("repository-local Git configuration is not UTF-8") from exc
        if key in observed:
            raise GovernanceError(f"repository-local Git configuration repeats {key}")
        observed[key] = value
        if key in exact_values:
            if value not in exact_values[key]:
                raise GovernanceError(f"repository-local Git configuration changes {key}")
            continue
        if key in inert_user_keys and value:
            continue
        if key.startswith("branch."):
            _, field_separator, field = key.rpartition(".")
            if not field_separator or field not in {"merge", "remote", "vscode-merge-base"}:
                raise GovernanceError(f"repository-local Git configuration forbids {key}")
            if field == "remote" and value != "origin":
                raise GovernanceError(f"repository-local Git configuration changes {key}")
            if field == "merge" and not value.startswith("refs/heads/"):
                raise GovernanceError(f"repository-local Git configuration changes {key}")
            if field == "vscode-merge-base" and not value.startswith("origin/"):
                raise GovernanceError(f"repository-local Git configuration changes {key}")
            continue
        raise GovernanceError(f"repository-local Git configuration forbids {key}")


def _validate_repository_identity(repository_root: Path) -> None:
    root = repository_root.resolve()
    top = _run_git(root, ["rev-parse", "--show-toplevel"])
    if top.returncode != 0:
        raise GovernanceError("unable to resolve the governed Git worktree root")
    reported_root = Path(top.stdout.decode("utf-8", errors="strict").strip()).resolve()
    if reported_root != root:
        raise GovernanceError("Git worktree root differs from the requested repository root")
    local_git_dir = root / ".git"
    try:
        git_dir_attributes = getattr(local_git_dir.lstat(), "st_file_attributes", 0)
    except OSError as exc:
        raise GovernanceError("unable to attest the repository .git directory") from exc
    expected_git_dir = local_git_dir.resolve()
    if not local_git_dir.is_dir() or local_git_dir.is_symlink() or git_dir_attributes & 0x400:
        raise GovernanceError("governed repository requires a local non-symlink .git directory")
    config_path = root / ".git" / "config"
    try:
        config_attributes = getattr(config_path.lstat(), "st_file_attributes", 0)
    except OSError as exc:
        raise GovernanceError("unable to attest the repository .git/config") from exc
    if not config_path.is_file() or config_path.is_symlink() or config_attributes & 0x400:
        raise GovernanceError("governed repository requires a regular non-link .git/config")
    git_dir = _run_git(root, ["rev-parse", "--absolute-git-dir"])
    if git_dir.returncode != 0:
        raise GovernanceError("unable to resolve the governed Git directory")
    reported_git_dir = Path(git_dir.stdout.decode("utf-8", errors="strict").strip()).resolve()
    if reported_git_dir != expected_git_dir:
        raise GovernanceError("Git directory differs from the requested repository .git directory")
    _validate_local_git_configuration(root)


def validate_local_only_roadmap(repository_root: Path, roadmap_path: Path) -> str:
    """Prove the private roadmap is local-only, ignored locally, and unversioned."""

    root = repository_root.resolve()
    _validate_repository_identity(root)
    resolved = roadmap_path.resolve()
    try:
        relative = resolved.relative_to(root).as_posix()
    except ValueError as exc:
        raise GovernanceError("private roadmap must remain inside the repository worktree") from exc
    if relative != "Agent_Assure_Implementation_Roadmap.md":
        raise GovernanceError("unexpected private roadmap path")
    indexed = _run_git(root, ["ls-files", "--stage", "--", relative])
    if indexed.returncode != 0:
        raise GovernanceError("unable to inspect the Git index for the private roadmap")
    if indexed.stdout.strip():
        raise GovernanceError("private roadmap is tracked or staged in the Git index")
    ignored = _run_git(root, ["check-ignore", "-v", "--no-index", "--", relative])
    if ignored.returncode != 0 or b".git/info/exclude" not in ignored.stdout.replace(b"\\", b"/"):
        raise GovernanceError("private roadmap is not protected by .git/info/exclude")
    history = _run_git(root, ["log", "--all", "--format=%H", "--", relative])
    if history.returncode != 0:
        raise GovernanceError("unable to inspect Git history for the private roadmap")
    if history.stdout.strip():
        raise GovernanceError("private roadmap exists in reachable local Git history")
    return relative


def _validate_git_history_safety(repository_root: Path) -> None:
    """Reject Git object-resolution features that can rewrite provenance."""

    _validate_repository_identity(repository_root)
    replacements = _run_git(
        repository_root, ["for-each-ref", "--format=%(refname)", "refs/replace/"]
    )
    if replacements.returncode != 0 or replacements.stdout.strip():
        raise GovernanceError("accepted completion provenance forbids Git replacement refs")
    shallow = _run_git(repository_root, ["rev-parse", "--is-shallow-repository"])
    if shallow.returncode != 0 or shallow.stdout.strip() != b"false":
        raise GovernanceError("accepted completion provenance requires full Git history")
    graft_path_result = _run_git(repository_root, ["rev-parse", "--git-path", "info/grafts"])
    if graft_path_result.returncode != 0:
        raise GovernanceError("unable to resolve the Git graft path")
    graft_path = Path(graft_path_result.stdout.decode("utf-8", errors="strict").strip())
    if not graft_path.is_absolute():
        graft_path = repository_root.resolve() / graft_path
    if graft_path.is_file() and graft_path.read_bytes().strip():
        raise GovernanceError("accepted completion provenance forbids Git grafts")
    alternates_path = repository_root.resolve() / ".git" / "objects" / "info" / "alternates"
    if alternates_path.is_file() and alternates_path.read_bytes().strip():
        raise GovernanceError("accepted completion provenance forbids alternate object stores")


def _fetch_authoritative_remote_refs() -> dict[str, str]:
    """Resolve and fetch the approved refs in a config-isolated temporary repository."""

    expected = {
        "refs/heads/main": PINNED_BASE_COMMIT,
        "refs/tags/v0.7.0": PINNED_TAG_OBJECT,
        "refs/tags/v0.7.0^{}": PINNED_BASE_COMMIT,
    }
    with tempfile.TemporaryDirectory(prefix="agent-assure-s1-remote-") as temporary:
        isolated = Path(temporary)
        initialized = _run_isolated_git(isolated, ["init", "--bare", "--quiet", "."])
        if initialized.returncode != 0:
            raise GovernanceError("unable to initialize the isolated acceptance fetch repository")
        queried = _run_isolated_git(
            isolated,
            [
                "ls-remote",
                "--exit-code",
                APPROVED_ORIGIN_URL,
                "refs/heads/main",
                "refs/tags/v0.7.0",
                "refs/tags/v0.7.0^{}",
            ],
            network=True,
        )
        if queried.returncode != 0:
            diagnostic = queried.stderr.decode("utf-8", errors="replace").strip()
            raise GovernanceError(f"unable to resolve authoritative remote refs: {diagnostic}")
        observed: dict[str, str] = {}
        for line in queried.stdout.decode("ascii", errors="strict").splitlines():
            fields = line.split("\t")
            if (
                len(fields) != 2
                or GIT_COMMIT_PATTERN.fullmatch(fields[0]) is None
                or fields[1] in observed
            ):
                raise GovernanceError("authoritative remote returned malformed or duplicate refs")
            observed[fields[1]] = fields[0]
        if observed != expected:
            raise GovernanceError("authoritative remote head or annotated tag moved")
        fetched = _run_isolated_git(
            isolated,
            [
                "fetch",
                "--quiet",
                "--prune",
                "--no-tags",
                "--force",
                APPROVED_ORIGIN_URL,
                "+refs/heads/main:refs/heads/agent-assure-authoritative-main",
                "+refs/tags/v0.7.0:refs/tags/agent-assure-authoritative-v0.7.0",
            ],
            network=True,
        )
        if fetched.returncode != 0:
            diagnostic = fetched.stderr.decode("utf-8", errors="replace").strip()
            raise GovernanceError(f"acceptance fetch failed: {diagnostic}")
        fetched_refs = {
            "refs/heads/main": "refs/heads/agent-assure-authoritative-main^{commit}",
            "refs/tags/v0.7.0": "refs/tags/agent-assure-authoritative-v0.7.0^{tag}",
            "refs/tags/v0.7.0^{}": "refs/tags/agent-assure-authoritative-v0.7.0^{commit}",
        }
        for remote_ref, isolated_ref in fetched_refs.items():
            resolved = _run_isolated_git(isolated, ["rev-parse", "--verify", isolated_ref])
            if resolved.returncode != 0:
                raise GovernanceError(f"isolated fetch cannot resolve {remote_ref}")
            actual = resolved.stdout.decode("ascii", errors="strict").strip()
            if actual != expected[remote_ref]:
                raise GovernanceError(f"isolated fetch disagrees for {remote_ref}")
    return observed


def validate_live_acceptance_repository(repository_root: Path, *, fetch: bool) -> dict[str, Any]:
    """Validate mutable repository facts at the one-time acceptance boundary."""

    _validate_git_history_safety(repository_root)
    remote = _run_git(repository_root, ["remote", "get-url", "--all", "origin"])
    if remote.returncode != 0:
        raise GovernanceError("unable to resolve the authorized origin URL")
    remote_urls = remote.stdout.decode("utf-8", errors="strict").splitlines()
    if remote_urls != [APPROVED_ORIGIN_URL]:
        raise GovernanceError("origin URL differs from the approved S1 remote")
    observed_remote_refs: dict[str, str] = {}
    if fetch:
        observed_remote_refs = _fetch_authoritative_remote_refs()

    expected_refs = {
        "refs/remotes/origin/main^{commit}": PINNED_BASE_COMMIT,
        "refs/tags/v0.7.0^{tag}": PINNED_TAG_OBJECT,
        "refs/tags/v0.7.0^{commit}": PINNED_BASE_COMMIT,
    }
    local_refs: dict[str, str] = {}
    for ref, expected in expected_refs.items():
        resolved = _run_git(repository_root, ["rev-parse", "--verify", ref])
        if resolved.returncode != 0:
            raise GovernanceError(f"acceptance repository cannot resolve {ref}")
        actual = resolved.stdout.decode("ascii", errors="strict").strip()
        if actual != expected:
            raise GovernanceError(f"acceptance repository ref moved: {ref}")
        local_refs[ref] = actual
    branch = _run_git(repository_root, ["symbolic-ref", "--quiet", "--short", "HEAD"])
    if branch.returncode != 0:
        raise GovernanceError("acceptance repository HEAD is detached")
    if branch.stdout.decode("utf-8", errors="strict").strip() != S1_BRANCH_NAME:
        raise GovernanceError("acceptance repository is not on the governed S1 branch")
    head = _run_git(repository_root, ["rev-parse", "--verify", "HEAD^{commit}"])
    if head.returncode != 0:
        raise GovernanceError("unable to resolve acceptance repository HEAD")
    head_commit = head.stdout.decode("ascii", errors="strict").strip()
    ancestry = _run_git(
        repository_root,
        ["merge-base", "--is-ancestor", PINNED_BASE_COMMIT, head_commit],
    )
    if ancestry.returncode != 0:
        raise GovernanceError("acceptance repository HEAD does not descend from the pinned base")
    return {
        "approved_remote_url": APPROVED_ORIGIN_URL,
        "authoritative_remote_refs": observed_remote_refs,
        "branch_name": S1_BRANCH_NAME,
        "fetch_performed": fetch,
        "head_commit": head_commit,
        "local_refs": local_refs,
    }


def _validate_reviewed_commit(
    repository_root: Path,
    *,
    base_commit: str,
    result_commit: str,
    artifacts: Sequence[Mapping[str, Any]],
) -> None:
    _validate_git_history_safety(repository_root)
    exists = _run_git(repository_root, ["cat-file", "-e", f"{result_commit}^{{commit}}"])
    if exists.returncode != 0:
        raise GovernanceError("completion result commit does not resolve to a Git commit")
    ancestry = _run_git(
        repository_root, ["merge-base", "--is-ancestor", base_commit, result_commit]
    )
    if ancestry.returncode != 0:
        raise GovernanceError("completion result commit does not descend from the pinned base")
    for artifact in artifacts:
        relative_path = _required_string(artifact, "path")
        committed = _run_git(repository_root, ["show", f"{result_commit}:{relative_path}"])
        if committed.returncode != 0:
            raise GovernanceError(
                f"reviewed artifact is absent from completion result commit: {relative_path}"
            )
        expected_size = _required_integer(artifact, "size_bytes")
        if len(committed.stdout) != expected_size:
            raise GovernanceError(
                f"reviewed artifact size differs from completion result commit: {relative_path}"
            )
        if raw_digest(committed.stdout) != artifact.get("sha256"):
            raise GovernanceError(
                f"reviewed artifact digest differs from completion result commit: {relative_path}"
            )


def _git_name_status(repository_root: Path, older: str, newer: str) -> dict[str, str]:
    changed = _run_git(
        repository_root,
        ["diff", "--name-status", "--no-renames", "-z", older, newer, "--"],
    )
    if changed.returncode != 0:
        raise GovernanceError("unable to inspect a governed Git change set")
    fields = [field for field in changed.stdout.split(b"\x00") if field]
    if len(fields) % 2 != 0:
        raise GovernanceError("Git returned a malformed governed change-set record")
    result: dict[str, str] = {}
    for index in range(0, len(fields), 2):
        status = fields[index].decode("ascii", errors="strict")
        try:
            path = fields[index + 1].decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise GovernanceError("governed commit contains a non-UTF-8 path") from exc
        if path in result:
            raise GovernanceError(f"governed change set repeats a path: {path}")
        result[path] = status
    return result


def _validate_s1_commit_scope(
    repository_root: Path,
    *,
    base_commit: str,
    result_commit: str,
    inventory: Sequence[Mapping[str, Any]],
) -> None:
    """Prove that the reviewed S1 commit contains governance changes only.

    Completion receipts and the release object necessarily follow the commit
    they attest, so they are excluded from the commit content requirement.
    Every other bundle artifact must be byte-identical in that commit, and no
    unlisted path or non-regular Git object is allowed.
    """

    post_commit_paths = {
        "docs/governance/v1/completion-receipt-v1-base-01.json",
        "docs/governance/v1/completion-receipt-v1-boot-01.json",
    }
    committed_inventory = [
        artifact
        for artifact in inventory
        if _required_string(artifact, "path") not in post_commit_paths
    ]
    expected_paths = {_required_string(artifact, "path") for artifact in committed_inventory}
    parent_record = _run_git(repository_root, ["rev-list", "--parents", "-n", "1", result_commit])
    parent_fields = parent_record.stdout.decode("ascii", errors="strict").split()
    if (
        parent_record.returncode != 0
        or len(parent_fields) != 2
        or parent_fields[0] != result_commit
        or parent_fields[1] != base_commit
    ):
        raise GovernanceError(
            "S1 result commit must be the direct, non-merge child of the pinned base"
        )
    history = _run_git(
        repository_root,
        ["rev-list", "--reverse", "--parents", result_commit, f"^{base_commit}"],
    )
    if history.returncode != 0 or not history.stdout.strip():
        raise GovernanceError("unable to enumerate the S1 result commit history")
    previous = base_commit
    for raw_line in history.stdout.decode("ascii", errors="strict").splitlines():
        parts = raw_line.split()
        if len(parts) != 2 or parts[1] != previous:
            raise GovernanceError("S1 result history must be a linear chain from the pinned base")
        commit = parts[0]
        per_commit = _git_name_status(repository_root, previous, commit)
        for path, status in per_commit.items():
            if path not in expected_paths:
                raise GovernanceError(f"S1 history touched an unauthorized path: {path}")
            if status not in {"A", "M"}:
                raise GovernanceError(
                    f"S1 history uses forbidden {status} change for governed path: {path}"
                )
        previous = commit
    if previous != result_commit:
        raise GovernanceError("S1 result commit is not the tip of its reviewed linear history")

    net_changes = _git_name_status(repository_root, base_commit, result_commit)
    observed_paths = set(net_changes)
    for path, status in net_changes.items():
        if status not in {"A", "M"}:
            raise GovernanceError(f"S1 result commit uses forbidden {status} change: {path}")
    if observed_paths != expected_paths:
        unexpected = sorted(observed_paths - expected_paths)
        missing = sorted(expected_paths - observed_paths)
        raise GovernanceError(
            f"S1 result commit scope mismatch (unexpected={unexpected}, missing={missing})"
        )
    _validate_reviewed_commit(
        repository_root,
        base_commit=base_commit,
        result_commit=result_commit,
        artifacts=committed_inventory,
    )
    for path in sorted(expected_paths):
        tree_entry = _run_git(repository_root, ["ls-tree", result_commit, "--", path])
        if tree_entry.returncode != 0 or not tree_entry.stdout:
            raise GovernanceError(f"S1 result commit lacks a tree entry for {path}")
        fields = tree_entry.stdout.split(None, 3)
        if len(fields) < 4 or fields[0] not in {b"100644", b"100755"} or fields[1] != b"blob":
            raise GovernanceError(f"S1 artifact is not a regular Git blob: {path}")


def _validate_s1_closure_checkout(
    repository_root: Path,
    *,
    result_commit: str,
    bundle: Mapping[str, Any],
    require_current_checkout: bool = False,
    expected_closure_commit: str | None = None,
) -> str:
    """Find and validate the unique durable closure commit for an S1 result.

    The closure is discovered from reachable history instead of assuming that
    it remains ``HEAD`` forever.  ``require_current_checkout`` is the explicit
    one-time acceptance gate: it additionally requires the clean checkout to
    be positioned at that closure commit.  Later S2 commits can therefore
    retain verifiable S1 history without weakening acceptance-time checks.
    """

    closure_paths = {
        "docs/governance/v1/completion-receipt-v1-base-01.json",
        "docs/governance/v1/completion-receipt-v1-boot-01.json",
        "docs/governance/v1/governance-bundle.json",
    }
    receipt_path_contract = [
        ("docs/governance/v1/completion-receipt-v1-base-01.json", "completion_receipt"),
        ("docs/governance/v1/completion-receipt-v1-boot-01.json", "completion_receipt"),
    ]
    raw_inventory = [
        _as_object(item, owner="bundle artifact")
        for item in _as_array(bundle.get("artifact_inventory"), owner="artifact_inventory")
    ]
    receipt_path_names = {path for path, _kind in receipt_path_contract}
    receipt_evidence = _validated_artifact_evidence(
        [item for item in raw_inventory if item.get("path") in receipt_path_names],
        receipt_path_contract,
        owner="S1 closure",
    )
    receipt_evidence_by_path = {cast(str, item["path"]): item for item in receipt_evidence}
    expected_bundle_bytes = _render_json_bytes(bundle)

    head = _run_git(repository_root, ["rev-parse", "HEAD^{commit}"])
    if head.returncode != 0:
        raise GovernanceError("unable to resolve the current repository HEAD")
    head_commit = head.stdout.decode("ascii", errors="strict").strip()
    graph = _run_git(repository_root, ["rev-list", "--all", "HEAD", "--children"])
    if graph.returncode != 0:
        raise GovernanceError("unable to enumerate reachable S1 closure candidates")
    direct_children: list[str] = []
    for line in graph.stdout.decode("ascii", errors="strict").splitlines():
        parts = line.split()
        if parts and parts[0] == result_commit:
            direct_children.extend(parts[1:])
    matching: list[str] = []
    for candidate in sorted(set(direct_children)):
        parents = _run_git(repository_root, ["rev-list", "--parents", "-n", "1", candidate])
        parts = parents.stdout.decode("ascii", errors="strict").split()
        if parents.returncode != 0 or len(parts) != 2 or parts[1] != result_commit:
            continue
        changes = _git_name_status(repository_root, result_commit, candidate)
        if set(changes) != closure_paths or any(
            status not in {"A", "M"} for status in changes.values()
        ):
            continue
        candidate_matches = True
        for path in sorted(closure_paths):
            tree_entry = _run_git(repository_root, ["ls-tree", candidate, "--", path])
            fields = tree_entry.stdout.split(None, 3)
            if (
                tree_entry.returncode != 0
                or len(fields) < 4
                or fields[0] not in {b"100644", b"100755"}
                or fields[1] != b"blob"
            ):
                candidate_matches = False
                break
            committed = _run_git(repository_root, ["show", f"{candidate}:{path}"])
            if committed.returncode != 0:
                candidate_matches = False
                break
            if path == "docs/governance/v1/governance-bundle.json":
                if committed.stdout != expected_bundle_bytes:
                    candidate_matches = False
                    break
            else:
                evidence = receipt_evidence_by_path[path]
                if (
                    len(committed.stdout) != evidence["size_bytes"]
                    or raw_digest(committed.stdout) != evidence["sha256"]
                ):
                    candidate_matches = False
                    break
        if candidate_matches:
            ancestor = _run_git(
                repository_root,
                ["merge-base", "--is-ancestor", candidate, head_commit],
            )
            candidate_matches = ancestor.returncode == 0
        if candidate_matches:
            matching.append(candidate)
    if len(matching) != 1:
        raise GovernanceError(
            "accepted S1 history must contain exactly one reachable linear closure commit "
            "with the current receipts and bundle"
        )
    closure_commit = matching[0]
    if expected_closure_commit is not None and closure_commit != expected_closure_commit:
        raise GovernanceError("selected historical closure is not the unique valid S1 closure")
    expected_bundle_digest = domain_digest(BUNDLE_DOMAIN, _bundle_projection(bundle))
    if bundle.get("bundle_digest") != expected_bundle_digest:
        raise GovernanceError("closure commit bundle digest changed")
    if require_current_checkout:
        if head_commit != closure_commit:
            raise GovernanceError("S1 acceptance checkout is not at the closure commit")
        dirty = _run_git(repository_root, ["status", "--porcelain=v1", "--untracked-files=all"])
        if dirty.returncode != 0 or dirty.stdout.strip():
            raise GovernanceError("accepted S1 checkout is not clean")
    return closure_commit


def _completion_review_paths(ticket_id: str) -> list[tuple[str, str]]:
    if ticket_id == "V1-BOOT-01":
        return [
            ("docs/governance/v1/approval-roster.json", "decision_record"),
            ("docs/governance/v1/approval-roster.schema.json", "planning_schema"),
            ("docs/governance/v1/kickoff-authorization.schema.json", "planning_schema"),
            (
                "docs/governance/v1/kickoff-authorization-v1-boot-01.json",
                "kickoff_authorization",
            ),
            (
                "docs/governance/v1/maintainer-signing-key.json",
                "governance_trust_key",
            ),
            (
                "docs/governance/v1/maintainer-signing-key.schema.json",
                "planning_schema",
            ),
            ("scripts/v1_s1_governance.ps1", "governance_runtime_launcher"),
            ("scripts/v1_s1_governance.py", "governance_validator"),
        ]
    if ticket_id == "V1-BASE-01":
        return [
            (".github/workflows/ci.yml", "continuous_integration"),
            ("docs/adr/0016-v1-repository-map.md", "decision_record"),
            ("docs/governance/v1/baseline-observations.json", "planning_evidence"),
            (
                "docs/governance/v1/baseline-observations.schema.json",
                "planning_schema",
            ),
            (
                "docs/governance/v1/delivery-forecast.aggregation-registry.json",
                "planning_method_registry",
            ),
            (
                "docs/governance/v1/delivery-forecast.aggregation-registry.schema.json",
                "planning_schema",
            ),
            (
                "docs/governance/v1/delivery-forecast.authoring-ledger.json",
                "planning_evidence",
            ),
            (
                "docs/governance/v1/delivery-forecast.authoring-ledger.schema.json",
                "planning_schema",
            ),
            ("docs/governance/v1/delivery-forecast.json", "planning_evidence"),
            ("docs/governance/v1/delivery-forecast.schema.json", "planning_schema"),
            (
                "docs/governance/v1/kickoff-authorization-v1-base-01.json",
                "kickoff_authorization",
            ),
            ("scripts/v1_s1_governance.ps1", "governance_runtime_launcher"),
            ("scripts/v1_s1_governance.py", "governance_validator"),
            (
                "tests/integration/test_v1_s1_historical_check.py",
                "integration_verification",
            ),
            ("tests/unit/governance/test_v1_s1_governance.py", "verification"),
            ("tests/unit/release/test_coverage_gate.py", "continuous_integration_verification"),
        ]
    raise GovernanceError(f"{ticket_id} is not an S1 completion ticket")


def _completion_allowed_operations(ticket_id: str) -> list[str]:
    if ticket_id == "V1-BOOT-01":
        return [
            "Rely on the accepted S1 staffing mode for bounded development governance only.",
            "Dispatch work only to roles actually staffed and within recorded capacity.",
        ]
    if ticket_id == "V1-BASE-01":
        return [
            "Use the accepted repository map to resolve later ticket file scopes.",
            "Commit to S2 only while the separately accepted delivery forecast is current.",
            "Draft later design records without treating S1 as method or release admission.",
        ]
    raise GovernanceError(f"{ticket_id} is not an S1 completion ticket")


def build_ticket_completion_receipt(
    snapshot: RoadmapSnapshot,
    *,
    repository_root: Path,
    ticket_id: str,
    roster_digest: str,
    kickoff_authorization_digest: str,
    person_id: str,
    base_commit: str,
    result_commit: str | None,
    issued_at: str,
    valid_until: str,
    status: str = "pending_human_acceptance",
    artifact_evidence_override: Sequence[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    if base_commit != PINNED_BASE_COMMIT:
        raise GovernanceError("completion receipt base commit differs from ADR-V1-MAP")
    if result_commit is not None and GIT_COMMIT_PATTERN.fullmatch(result_commit) is None:
        raise GovernanceError("completion receipt result commit is not a full Git object ID")
    if status not in {"pending_human_acceptance", "accepted_for_development"}:
        raise GovernanceError(f"{ticket_id} completion status is invalid")
    if status == "accepted_for_development" and result_commit is None:
        raise GovernanceError("an accepted completion receipt requires a reviewed result commit")
    _validate_validity_interval(issued_at, valid_until, owner=f"{ticket_id} completion receipt")
    ticket = _ticket_by_id(snapshot, ticket_id)
    report_path = f"docs/governance/v1/completion-report-{ticket_id.lower()}.md"
    review_paths = _completion_review_paths(ticket_id)
    if artifact_evidence_override is None:
        report = _artifact_evidence(repository_root, report_path, kind="completion_report")
        reviewed = [
            _artifact_evidence(repository_root, path, kind=kind) for path, kind in review_paths
        ]
        reviewed.sort(key=lambda item: _utf8_sort_key(cast(str, item["path"])))
    else:
        frozen = _validated_artifact_evidence(
            artifact_evidence_override,
            [(report_path, "completion_report"), *review_paths],
            owner=f"{ticket_id} completion receipt",
        )
        by_path = {cast(str, item["path"]): item for item in frozen}
        report = by_path[report_path]
        reviewed = [by_path[path] for path, _kind in review_paths]
        reviewed.sort(key=lambda item: _utf8_sort_key(cast(str, item["path"])))
    artifact_set_digest = domain_digest(
        "agent-assure:s1-reviewed-artifact-set/v1", {"artifacts": reviewed}
    )
    projection: dict[str, Any] = {
        "format": "agent-assure-ticket-completion-receipt/1",
        "spec_revision": SPEC_REVISION,
        "receipt_purpose": "development_design_acceptance",
        "receipt_status": status,
        "subject_ticket_id": ticket_id,
        "subject_dispatch_kind": _required_string(ticket, "dispatch_kind"),
        "subject_stage": "S1-governed-baseline",
        "subject_roadmap_digest": snapshot.raw_digest,
        "subject_report": report,
        "reviewed_artifacts": reviewed,
        "reviewed_artifact_set_digest": artifact_set_digest,
        "approval_roster_digest": roster_digest,
        "kickoff_authorization_digest": kickoff_authorization_digest,
        "base_commit": base_commit,
        "result_commit": result_commit,
        "issuer_person_id": person_id,
        "issuer_role": "repository_maintainer",
        "owner_role": _required_string(ticket, "owner_role"),
        "approval_mode": "maintainer_development",
        "author_reviewer_relationship": "same_person_maintainer_development_self_acceptance",
        "independence_claimed": False,
        "authorization_effect": "none",
        "accepted_competence": [
            "planning_governance:s1",
            "repository_maintenance:bounded_development",
            "technical_direction:s1",
        ],
        "conflicts": [
            "Sole maintainer self-acceptance; no independence is claimed.",
            "LLM-authored implementation evidence requires accountable human review.",
        ],
        "issued_at_utc": issued_at,
        "valid_until_utc": valid_until,
        "allowed_operations": _completion_allowed_operations(ticket_id),
        "limitations": [
            "NO_INDEPENDENT_REVIEW",
            (
                "No method admission, qualification, pilot, release, deployment, or runtime "
                "authorization."
            ),
            "Pending status or signature is non-accepting.",
        ],
    }
    digest = domain_digest(TICKET_RECEIPT_DOMAIN, projection)
    return {
        **projection,
        "receipt_digest": digest,
        "signature_envelope": _pending_signature(person_id, "repository_maintainer", digest),
    }


def validate_ticket_completion_receipt(
    snapshot: RoadmapSnapshot,
    record: Mapping[str, Any],
    schema: Mapping[str, Any],
    *,
    repository_root: Path,
    expected_ticket_id: str,
    expected_roster_digest: str,
    expected_kickoff_digest: str,
    expected_person_id: str,
    expected_base_commit: str,
    allow_pending: bool,
    validation_time: datetime | None = None,
    expected_kickoff_record: Mapping[str, Any] | None = None,
) -> None:
    _validate_json_schema(record, schema, owner=f"{expected_ticket_id} completion receipt")
    if validation_time is not None and validation_time.tzinfo is None:
        raise GovernanceError("completion validation time must be timezone-aware")
    status = _required_string(record, "receipt_status")
    result_commit_value = record.get("result_commit")
    if result_commit_value is not None and not isinstance(result_commit_value, str):
        raise GovernanceError("completion receipt result commit must be a string or null")
    artifact_evidence_override: list[Mapping[str, Any]] | None = None
    if status == "accepted_for_development":
        subject_report = _as_object(record.get("subject_report"), owner="subject report")
        reviewed_artifacts = [
            _as_object(item, owner="reviewed artifact")
            for item in _as_array(record.get("reviewed_artifacts"), owner="reviewed_artifacts")
        ]
        artifact_evidence_override = [subject_report, *reviewed_artifacts]
    expected = build_ticket_completion_receipt(
        snapshot,
        repository_root=repository_root,
        ticket_id=expected_ticket_id,
        roster_digest=expected_roster_digest,
        kickoff_authorization_digest=expected_kickoff_digest,
        person_id=expected_person_id,
        base_commit=expected_base_commit,
        result_commit=result_commit_value,
        issued_at=_required_string(record, "issued_at_utc"),
        valid_until=_required_string(record, "valid_until_utc"),
        status=status,
        artifact_evidence_override=artifact_evidence_override,
    )
    if _ticket_receipt_projection(record) != _ticket_receipt_projection(expected):
        raise GovernanceError(
            f"{expected_ticket_id} completion receipt differs from current reviewed artifacts"
        )
    digest = domain_digest(TICKET_RECEIPT_DOMAIN, _ticket_receipt_projection(record))
    if record.get("receipt_digest") != digest:
        raise GovernanceError(f"{expected_ticket_id} completion receipt digest mismatch")
    if status == "accepted_for_development":
        if not isinstance(result_commit_value, str) or artifact_evidence_override is None:
            raise GovernanceError("accepted completion receipt lacks reviewed commit evidence")
        _validate_reviewed_commit(
            repository_root,
            base_commit=expected_base_commit,
            result_commit=result_commit_value,
            artifacts=artifact_evidence_override,
        )
    issue_time, expiry_time = _validate_validity_interval(
        _required_string(record, "issued_at_utc"),
        _required_string(record, "valid_until_utc"),
        owner=f"{expected_ticket_id} completion receipt",
    )
    signature_may_be_pending = allow_pending and status != "accepted_for_development"
    if status == "accepted_for_development" and validation_time is None:
        raise GovernanceError(
            f"{expected_ticket_id} accepted completion requires a trusted validation time"
        )
    completion_signature_time = _validate_signature_envelope(
        record.get("signature_envelope"),
        expected_person_id=expected_person_id,
        expected_role="repository_maintainer",
        expected_subject_digest=digest,
        allow_pending=signature_may_be_pending,
        not_before=issue_time,
        not_after=expiry_time,
        validation_time=validation_time,
    )
    if status == "accepted_for_development" and validation_time is not None:
        at = validation_time.astimezone(UTC)
        if not issue_time <= at < expiry_time:
            raise GovernanceError(f"{expected_ticket_id} completion receipt is not current")
    if status == "accepted_for_development":
        if expected_kickoff_record is None:
            raise GovernanceError("accepted completion requires its validated kickoff record")
        if expected_kickoff_record.get("authorization_status") != "authorized":
            raise GovernanceError("accepted completion requires an authorized kickoff")
        if expected_kickoff_record.get("subject_ticket_id") != expected_ticket_id:
            raise GovernanceError("accepted completion kickoff targets another ticket")
        if expected_kickoff_record.get("approval_roster_digest") != expected_roster_digest:
            raise GovernanceError("accepted completion kickoff targets another roster")
        if expected_kickoff_record.get("authorization_digest") != expected_kickoff_digest:
            raise GovernanceError("accepted completion kickoff digest binding changed")
        kickoff_issue, kickoff_expiry = _validate_validity_interval(
            _required_string(expected_kickoff_record, "issued_at_utc"),
            _required_string(expected_kickoff_record, "valid_until_utc"),
            owner=f"{expected_ticket_id} kickoff",
        )
        recomputed_kickoff_digest = domain_digest(
            KICKOFF_DOMAIN, _kickoff_projection(expected_kickoff_record)
        )
        if recomputed_kickoff_digest != expected_kickoff_digest:
            raise GovernanceError("accepted completion kickoff digest does not recompute")
        verified_kickoff_time = _validate_signature_envelope(
            expected_kickoff_record.get("signature_envelope"),
            expected_person_id=expected_person_id,
            expected_role="repository_maintainer",
            expected_subject_digest=expected_kickoff_digest,
            allow_pending=False,
            not_before=kickoff_issue,
            not_after=kickoff_expiry,
            validation_time=validation_time,
        )
        kickoff_envelope = _as_object(
            expected_kickoff_record.get("signature_envelope"), owner="kickoff signature"
        )
        kickoff_signed_at = kickoff_envelope.get("signed_at_utc")
        if not isinstance(kickoff_signed_at, str):
            raise GovernanceError("accepted completion kickoff lacks a signature time")
        kickoff_signature_time = _parse_utc(kickoff_signed_at, owner="kickoff signature time")
        if verified_kickoff_time != kickoff_signature_time:
            raise GovernanceError("kickoff signature verification time is inconsistent")
        if completion_signature_time is None or completion_signature_time < kickoff_signature_time:
            raise GovernanceError("completion signature predates its kickoff authorization")
    if not allow_pending and status != "accepted_for_development":
        raise GovernanceError(f"{expected_ticket_id} completion receipt is pending")


def _bundle_projection(bundle: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in bundle.items()
        if key not in {"bundle_digest", "signature_envelope"}
    }


def _bundle_inventory_paths() -> list[tuple[str, str]]:
    return [
        (".github/workflows/ci.yml", "continuous_integration"),
        ("Makefile", "build_integration"),
        ("docs/adr/0016-v1-repository-map.md", "decision_record"),
        ("docs/governance/v1/README.md", "governance_documentation"),
        ("docs/governance/v1/approval-roster.json", "decision_record"),
        ("docs/governance/v1/approval-roster.schema.json", "planning_schema"),
        ("docs/governance/v1/baseline-observations.json", "planning_evidence"),
        ("docs/governance/v1/baseline-observations.schema.json", "planning_schema"),
        ("docs/governance/v1/completion-receipt-v1-base-01.json", "completion_receipt"),
        ("docs/governance/v1/completion-receipt-v1-boot-01.json", "completion_receipt"),
        ("docs/governance/v1/completion-report-v1-base-01.md", "completion_report"),
        ("docs/governance/v1/completion-report-v1-boot-01.md", "completion_report"),
        (
            "docs/governance/v1/delivery-forecast.aggregation-registry.json",
            "planning_method_registry",
        ),
        (
            "docs/governance/v1/delivery-forecast.aggregation-registry.schema.json",
            "planning_schema",
        ),
        ("docs/governance/v1/delivery-forecast.authoring-ledger.json", "planning_evidence"),
        (
            "docs/governance/v1/delivery-forecast.authoring-ledger.schema.json",
            "planning_schema",
        ),
        ("docs/governance/v1/delivery-forecast.json", "planning_evidence"),
        ("docs/governance/v1/delivery-forecast.schema.json", "planning_schema"),
        (
            "docs/governance/v1/governance-bundle.schema.json",
            "planning_schema",
        ),
        (
            "docs/governance/v1/kickoff-authorization-v1-base-01.json",
            "kickoff_authorization",
        ),
        (
            "docs/governance/v1/kickoff-authorization-v1-boot-01.json",
            "kickoff_authorization",
        ),
        ("docs/governance/v1/kickoff-authorization.schema.json", "planning_schema"),
        (
            "docs/governance/v1/maintainer-signing-key.json",
            "governance_trust_key",
        ),
        (
            "docs/governance/v1/maintainer-signing-key.schema.json",
            "planning_schema",
        ),
        (
            "docs/governance/v1/ticket-completion-receipt.schema.json",
            "planning_schema",
        ),
        ("mkdocs.yml", "documentation_integration"),
        ("scripts/v1_s1_governance.ps1", "governance_runtime_launcher"),
        ("scripts/v1_s1_governance.py", "governance_validator"),
        (
            "tests/integration/test_v1_s1_historical_check.py",
            "integration_verification",
        ),
        ("tests/unit/governance/test_v1_s1_governance.py", "verification"),
        ("tests/unit/release/test_coverage_gate.py", "continuous_integration_verification"),
    ]


def build_governance_bundle(
    snapshot: RoadmapSnapshot,
    *,
    repository_root: Path,
    roster: Mapping[str, Any],
    kickoff_records: Mapping[str, Mapping[str, Any]],
    completion_receipts: Mapping[str, Mapping[str, Any]],
    forecast: Mapping[str, Any],
    signing_key: Mapping[str, Any],
    baseline_observations: Mapping[str, Any],
    person_id: str,
    base_commit: str,
    issued_at: str,
    valid_until: str,
    status: str = "pending_human_acceptance",
    artifact_payload_overrides: Mapping[str, bytes] | None = None,
    artifact_inventory_override: Sequence[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    if status not in {"pending_human_acceptance", "accepted_for_development"}:
        raise GovernanceError("S1 governance bundle status is invalid")
    if base_commit != PINNED_BASE_COMMIT:
        raise GovernanceError("S1 governance bundle base commit differs from ADR-V1-MAP")
    expected_ticket_ids = {"V1-BOOT-01", "V1-BASE-01"}
    if set(kickoff_records) != expected_ticket_ids:
        raise GovernanceError("S1 governance bundle requires exactly both kickoff records")
    if set(completion_receipts) != expected_ticket_ids:
        raise GovernanceError("S1 governance bundle requires exactly both completion receipts")
    _validate_validity_interval(issued_at, valid_until, owner="S1 governance bundle")
    roster_digest = approval_roster_digest(roster)
    inventory_paths = _bundle_inventory_paths()
    if artifact_payload_overrides is not None and artifact_inventory_override is not None:
        raise GovernanceError("bundle payload and inventory overrides are mutually exclusive")
    if artifact_inventory_override is not None:
        inventory = _validated_artifact_evidence(
            artifact_inventory_override,
            inventory_paths,
            owner="S1 governance bundle",
        )
    else:
        overrides = artifact_payload_overrides or {}
        known_paths = {path for path, _ in inventory_paths}
        unknown_overrides = sorted(set(overrides) - known_paths)
        if unknown_overrides:
            raise GovernanceError(
                f"bundle artifact overrides contain unknown paths: {unknown_overrides}"
            )
        inventory = [
            (
                _artifact_evidence_for_payload(
                    repository_root,
                    path,
                    kind=kind,
                    payload=overrides[path],
                )
                if path in overrides
                else _artifact_evidence(repository_root, path, kind=kind)
            )
            for path, kind in inventory_paths
        ]
        inventory.sort(key=lambda item: _utf8_sort_key(cast(str, item["path"])))
    artifact_set_digest = domain_digest(
        "agent-assure:s1-governance-bundle-artifact-set/v1", {"artifacts": inventory}
    )
    kickoff_bindings = [
        {
            "ticket_id": ticket_id,
            "authorization_status": _required_string(record, "authorization_status"),
            "authorization_digest": _required_string(record, "authorization_digest"),
        }
        for ticket_id, record in sorted(kickoff_records.items(), key=lambda item: item[0])
    ]
    completion_bindings = [
        {
            "ticket_id": ticket_id,
            "receipt_status": _required_string(record, "receipt_status"),
            "receipt_digest": _required_string(record, "receipt_digest"),
        }
        for ticket_id, record in sorted(completion_receipts.items(), key=lambda item: item[0])
    ]
    completion_result_commits = {
        record.get("result_commit") for record in completion_receipts.values()
    }
    if status == "accepted_for_development":
        if len(completion_result_commits) != 1 or None in completion_result_commits:
            raise GovernanceError("accepted S1 bundle requires one common reviewed result commit")
        result_commit = next(iter(completion_result_commits))
        if not isinstance(result_commit, str):
            raise GovernanceError("accepted S1 result commit is invalid")
    else:
        if completion_result_commits != {None}:
            raise GovernanceError("pending S1 completion receipts must not assert result commits")
        result_commit = None
    forecast_receipt = _as_object(
        forecast.get("acceptance_receipt"), owner="forecast acceptance_receipt"
    )
    signing_key_digest = _required_string(signing_key, "record_digest")
    baseline_observations_digest = _required_string(baseline_observations, "observations_digest")
    full_suite_status = _baseline_full_suite_status(baseline_observations)
    limitations = [
        "NO_INDEPENDENT_REVIEW",
        (
            "Windows Time attestation was unavailable; host UTC requires explicit maintainer "
            "acceptance."
        ),
        (
            "No method, profile, qualification, release, deployment, or runtime authorization "
            "is granted."
        ),
        (
            "The repository-local public key declaration is TOFU metadata, not independent "
            "identity proof."
        ),
    ]
    if status == "pending_human_acceptance":
        limitations.append(
            "Human decisions and signatures remain non-accepting until cryptographically completed."
        )
    if full_suite_status == "timed_out":
        limitations.append(
            "The full repository pytest suite timed out during baseline inspection and is not "
            "claimed as passing."
        )
    elif full_suite_status == "failed":
        limitations.append(
            "The full repository pytest suite failed during baseline inspection and is not "
            "claimed as passing."
        )
    projection: dict[str, Any] = {
        "format": "agent-assure-governance-bundle/1",
        "spec_revision": SPEC_REVISION,
        "bundle_status": status,
        "sprint": "S1",
        "release": "1.0.0a1",
        "train": "stable-1.0",
        "maturity": "governed-baseline",
        "artifact_kind": "governance-bundle",
        "source_ticket_ids": ["V1-BOOT-01", "V1-BASE-01"],
        "authorization_effect": "none",
        "installability": "none",
        "distribution_channels": [],
        "package_version": None,
        "base_commit": base_commit,
        "result_commit": result_commit,
        "roadmap_digest": snapshot.raw_digest,
        "approval_roster_digest": roster_digest,
        "signed_decisions": {
            "roster_selection_status": _required_string(roster, "selection_status"),
            "signing_key_status": _required_string(signing_key, "key_status"),
            "signing_key_record_digest": signing_key_digest,
            "kickoff_authorizations": kickoff_bindings,
            "ticket_completion_receipts": completion_bindings,
        },
        "compatibility_note": {
            "baseline_package_version": "0.7.0",
            "baseline_writer_schema_version": "0.6.6",
            "production_behavior_changed": False,
            "installable_artifact_emitted": False,
            "note": (
                "S1 adds planning governance only; package and writer identities remain separate "
                "and unchanged."
            ),
        },
        "known_limitations": limitations,
        "planning_evidence": {
            "baseline_observations_digest": baseline_observations_digest,
            "full_repository_pytest_outcome": full_suite_status,
            "forecast_status": _required_string(forecast, "forecast_status"),
            "forecast_record_digest": _required_string(forecast, "record_digest"),
            "forecast_acceptance_receipt_status": _required_string(
                forecast_receipt, "receipt_status"
            ),
            "forecast_acceptance_receipt_digest": _required_string(
                forecast_receipt, "receipt_digest"
            ),
            "aggregation_method_registry_digest": _required_string(
                forecast, "aggregation_method_registry_digest"
            ),
            "authoring_ledger_digest": _required_string(forecast, "authoring_ledger_digest"),
            "ticket_count": _required_integer(
                _as_object(forecast.get("portfolio_aggregate"), owner="portfolio aggregate"),
                "ticket_count",
            ),
            "occurrence_count": _required_integer(
                _as_object(forecast.get("portfolio_aggregate"), owner="portfolio aggregate"),
                "occurrence_count",
            ),
        },
        "artifact_inventory": inventory,
        "artifact_set_digest": artifact_set_digest,
        "issuer_person_id": person_id,
        "issuer_role": "repository_maintainer",
        "approval_mode": "maintainer_development",
        "independence_claimed": False,
        "issued_at_utc": issued_at,
        "valid_until_utc": valid_until,
    }
    digest = domain_digest(BUNDLE_DOMAIN, projection)
    return {
        **projection,
        "bundle_digest": digest,
        "signature_envelope": _pending_signature(person_id, "repository_maintainer", digest),
    }


def validate_governance_bundle(
    snapshot: RoadmapSnapshot,
    bundle: Mapping[str, Any],
    schema: Mapping[str, Any],
    *,
    repository_root: Path,
    roster: Mapping[str, Any],
    kickoff_records: Mapping[str, Mapping[str, Any]],
    completion_receipts: Mapping[str, Mapping[str, Any]],
    forecast: Mapping[str, Any],
    signing_key: Mapping[str, Any],
    baseline_observations: Mapping[str, Any],
    expected_person_id: str,
    expected_base_commit: str,
    allow_pending: bool,
    validation_time: datetime | None = None,
    require_bundle_on_disk: bool = True,
    require_predecessors_on_disk: bool = True,
    require_current_closure: bool = False,
    require_closure: bool = True,
    artifact_payload_overrides: Mapping[str, bytes] | None = None,
    historical_records: Mapping[str, Mapping[str, Any]] | None = None,
    expected_closure_commit: str | None = None,
) -> None:
    _validate_json_schema(bundle, schema, owner="S1 governance bundle")
    if validation_time is not None and validation_time.tzinfo is None:
        raise GovernanceError("bundle validation time must be timezone-aware")
    status = _required_string(bundle, "bundle_status")
    predecessor_allow_pending = allow_pending and status != "accepted_for_development"
    root = repository_root.resolve()

    def load_governance_record(name: str) -> dict[str, Any]:
        relative = f"docs/governance/v1/{name}"
        if historical_records is None:
            return _read_json(root / relative)
        if relative not in historical_records:
            raise GovernanceError(f"historical record set is missing {relative}")
        return dict(historical_records[relative])

    def require_disk_record(path: str, supplied: Mapping[str, Any]) -> dict[str, Any]:
        actual = _read_json(root / path)
        if actual != supplied:
            raise GovernanceError(f"caller-supplied record differs from disk: {path}")
        return actual

    if require_bundle_on_disk:
        require_disk_record("docs/governance/v1/governance-bundle.json", bundle)
    elif (
        historical_records is not None
        and load_governance_record("governance-bundle.json") != bundle
    ):
        raise GovernanceError("historical bundle differs from the selected closure")
    if require_predecessors_on_disk:
        disk_schema = require_disk_record(
            "docs/governance/v1/governance-bundle.schema.json", schema
        )
        if disk_schema != schema:
            raise GovernanceError("governance bundle schema differs from disk")
        require_disk_record("docs/governance/v1/approval-roster.json", roster)
        require_disk_record("docs/governance/v1/delivery-forecast.json", forecast)
        require_disk_record("docs/governance/v1/maintainer-signing-key.json", signing_key)
        require_disk_record("docs/governance/v1/baseline-observations.json", baseline_observations)
    elif historical_records is not None:
        supplied_records = {
            "approval-roster.json": roster,
            "delivery-forecast.json": forecast,
            "maintainer-signing-key.json": signing_key,
            "baseline-observations.json": baseline_observations,
        }
        for name, supplied in supplied_records.items():
            if load_governance_record(name) != supplied:
                raise GovernanceError(f"historical predecessor differs from closure: {name}")
    for ticket_id in ("V1-BOOT-01", "V1-BASE-01"):
        if ticket_id not in kickoff_records or ticket_id not in completion_receipts:
            raise GovernanceError(f"S1 bundle is missing predecessor {ticket_id}")
        if not require_predecessors_on_disk:
            if historical_records is not None:
                kickoff_name = f"kickoff-authorization-{ticket_id.lower()}.json"
                receipt_name = f"completion-receipt-{ticket_id.lower()}.json"
                if load_governance_record(kickoff_name) != kickoff_records[ticket_id]:
                    raise GovernanceError(
                        f"historical predecessor differs from closure: {kickoff_name}"
                    )
                if load_governance_record(receipt_name) != completion_receipts[ticket_id]:
                    raise GovernanceError(
                        f"historical predecessor differs from closure: {receipt_name}"
                    )
            continue
        require_disk_record(
            f"docs/governance/v1/kickoff-authorization-{ticket_id.lower()}.json",
            kickoff_records[ticket_id],
        )
        require_disk_record(
            f"docs/governance/v1/completion-receipt-{ticket_id.lower()}.json",
            completion_receipts[ticket_id],
        )

    roster_schema = load_governance_record("approval-roster.schema.json")
    roster_digest, roster_person_id = validate_approval_roster(
        snapshot,
        roster,
        roster_schema,
        allow_pending=predecessor_allow_pending,
    )
    if roster_person_id != expected_person_id:
        raise GovernanceError("bundle issuer differs from the roster maintainer")
    key_schema = load_governance_record("maintainer-signing-key.schema.json")
    validate_maintainer_signing_key(
        signing_key,
        key_schema,
        expected_person_id=expected_person_id,
        allow_pending=predecessor_allow_pending,
    )
    baseline_schema = load_governance_record("baseline-observations.schema.json")
    validate_baseline_observations(
        snapshot,
        baseline_observations,
        baseline_schema,
        repository_root=root,
    )
    kickoff_schema = load_governance_record("kickoff-authorization.schema.json")
    for ticket_id in ("V1-BOOT-01", "V1-BASE-01"):
        validate_kickoff_authorization(
            snapshot,
            kickoff_records[ticket_id],
            kickoff_schema,
            expected_ticket_id=ticket_id,
            expected_roster_digest=roster_digest,
            expected_person_id=expected_person_id,
            allow_pending=predecessor_allow_pending,
            validation_time=validation_time,
        )
    registry = load_governance_record("delivery-forecast.aggregation-registry.json")
    registry_schema = load_governance_record("delivery-forecast.aggregation-registry.schema.json")
    _validate_json_schema(registry, registry_schema, owner="aggregation method registry")
    _resolve_aggregation_method(registry)
    ledger = load_governance_record("delivery-forecast.authoring-ledger.json")
    ledger_schema = load_governance_record("delivery-forecast.authoring-ledger.schema.json")
    validate_authoring_ledger(
        snapshot,
        ledger,
        ledger_schema,
        expected_person_id=expected_person_id,
        baseline_observations=baseline_observations,
    )
    forecast_schema = load_governance_record("delivery-forecast.schema.json")
    validate_forecast(
        snapshot,
        ledger,
        registry,
        forecast,
        forecast_schema,
        expected_person_id=expected_person_id,
        approval_roster_digest_value=roster_digest,
        allow_pending=predecessor_allow_pending,
        commitment_time=validation_time,
    )
    completion_schema = load_governance_record("ticket-completion-receipt.schema.json")
    for ticket_id in ("V1-BOOT-01", "V1-BASE-01"):
        validate_ticket_completion_receipt(
            snapshot,
            completion_receipts[ticket_id],
            completion_schema,
            repository_root=root,
            expected_ticket_id=ticket_id,
            expected_roster_digest=roster_digest,
            expected_kickoff_digest=_required_string(
                kickoff_records[ticket_id], "authorization_digest"
            ),
            expected_person_id=expected_person_id,
            expected_base_commit=expected_base_commit,
            allow_pending=predecessor_allow_pending,
            validation_time=validation_time,
            expected_kickoff_record=kickoff_records[ticket_id],
        )

    frozen_inventory: list[dict[str, Any]] | None = None
    if status == "accepted_for_development":
        if artifact_payload_overrides is not None:
            raise GovernanceError("accepted bundle validation cannot use staged payload overrides")
        frozen_inventory = [
            _as_object(item, owner="bundle artifact")
            for item in _as_array(bundle.get("artifact_inventory"), owner="artifact_inventory")
        ]
    expected = build_governance_bundle(
        snapshot,
        repository_root=repository_root,
        roster=roster,
        kickoff_records=kickoff_records,
        completion_receipts=completion_receipts,
        forecast=forecast,
        signing_key=signing_key,
        baseline_observations=baseline_observations,
        person_id=expected_person_id,
        base_commit=expected_base_commit,
        issued_at=_required_string(bundle, "issued_at_utc"),
        valid_until=_required_string(bundle, "valid_until_utc"),
        status=status,
        artifact_payload_overrides=artifact_payload_overrides,
        artifact_inventory_override=frozen_inventory,
    )
    if _bundle_projection(bundle) != _bundle_projection(expected):
        raise GovernanceError("S1 governance bundle differs from current artifacts")
    digest = domain_digest(BUNDLE_DOMAIN, _bundle_projection(bundle))
    if bundle.get("bundle_digest") != digest:
        raise GovernanceError("S1 governance bundle digest mismatch")
    issue_time, expiry_time = _validate_validity_interval(
        _required_string(bundle, "issued_at_utc"),
        _required_string(bundle, "valid_until_utc"),
        owner="S1 governance bundle",
    )
    signature_may_be_pending = allow_pending and status != "accepted_for_development"
    if status == "accepted_for_development" and validation_time is None:
        raise GovernanceError("accepted S1 bundle requires a trusted validation time")
    bundle_signature_time = _validate_signature_envelope(
        bundle.get("signature_envelope"),
        expected_person_id=expected_person_id,
        expected_role="repository_maintainer",
        expected_subject_digest=digest,
        allow_pending=signature_may_be_pending,
        not_before=issue_time,
        not_after=expiry_time,
        validation_time=validation_time,
    )
    if status == "accepted_for_development" and validation_time is not None:
        at = validation_time.astimezone(UTC)
        if not issue_time <= at < expiry_time:
            raise GovernanceError("accepted S1 bundle is not current")
    if status == "accepted_for_development":
        forecast_receipt = _as_object(
            forecast.get("acceptance_receipt"), owner="forecast acceptance_receipt"
        )
        if roster.get("selection_status") != "approved":
            raise GovernanceError("accepted bundle requires an approved roster")
        if forecast.get("forecast_status") != "accepted":
            raise GovernanceError("accepted bundle requires an accepted delivery forecast")
        if signing_key.get("key_status") != "confirmed_by_human":
            raise GovernanceError("accepted bundle requires human confirmation of the trust key")
        if any(
            record.get("authorization_status") != "authorized"
            for record in kickoff_records.values()
        ):
            raise GovernanceError("accepted bundle requires both authorized kickoff records")
        if any(
            record.get("receipt_status") != "accepted_for_development"
            for record in completion_receipts.values()
        ):
            raise GovernanceError("accepted bundle requires both accepted ticket receipts")
        if forecast_receipt.get("receipt_status") != "accepted_for_development":
            raise GovernanceError("accepted bundle requires forecast maintainer acceptance")
        result_commit = bundle.get("result_commit")
        if not isinstance(result_commit, str):
            raise GovernanceError("accepted bundle requires one reviewed result commit")
        if frozen_inventory is None:
            raise GovernanceError("accepted bundle lacks a frozen artifact inventory")
        _validate_s1_commit_scope(
            repository_root,
            base_commit=expected_base_commit,
            result_commit=result_commit,
            inventory=frozen_inventory,
        )
        if require_closure:
            _validate_s1_closure_checkout(
                repository_root,
                result_commit=result_commit,
                bundle=bundle,
                require_current_checkout=require_current_closure,
                expected_closure_commit=expected_closure_commit,
            )
        elif require_current_closure:
            raise GovernanceError("current-closure validation cannot be disabled at acceptance")

        def signed_time(record: Mapping[str, Any], *, owner: str) -> datetime:
            envelope = _as_object(record.get("signature_envelope"), owner=f"{owner} signature")
            signed_at = envelope.get("signed_at_utc")
            if not isinstance(signed_at, str):
                raise GovernanceError(f"accepted {owner} lacks a signature time")
            return _parse_utc(signed_at, owner=f"{owner} signature time")

        kickoff_times = {
            ticket_id: signed_time(kickoff_records[ticket_id], owner=f"{ticket_id} kickoff")
            for ticket_id in sorted(kickoff_records)
        }
        forecast_producer_time = signed_time(forecast, owner="forecast producer")
        forecast_acceptance_time = signed_time(forecast_receipt, owner="forecast acceptance")
        base_completion_time = signed_time(
            completion_receipts["V1-BASE-01"], owner="V1-BASE-01 completion"
        )
        boot_completion_time = signed_time(
            completion_receipts["V1-BOOT-01"], owner="V1-BOOT-01 completion"
        )
        if forecast_producer_time < kickoff_times["V1-BASE-01"]:
            raise GovernanceError("forecast producer signature predates the BASE kickoff")
        if base_completion_time < forecast_acceptance_time:
            raise GovernanceError("BASE completion predates forecast acceptance")
        if boot_completion_time < base_completion_time:
            raise GovernanceError(
                "BOOT completion predates the roadmap's deterministic BASE/BOOT close order"
            )
        closure_predecessor_time = max(
            forecast_acceptance_time,
            base_completion_time,
            boot_completion_time,
        )
        if bundle_signature_time is None or bundle_signature_time < closure_predecessor_time:
            raise GovernanceError("bundle signature predates an S1 closure predecessor")
    if not allow_pending and status != "accepted_for_development":
        raise GovernanceError("S1 governance bundle is pending")


def validate_forecast(
    snapshot: RoadmapSnapshot,
    ledger: Mapping[str, Any],
    registry: Mapping[str, Any],
    forecast: Mapping[str, Any],
    schema: Mapping[str, Any],
    *,
    expected_person_id: str,
    approval_roster_digest_value: str,
    allow_pending: bool,
    commitment_time: datetime | None = None,
) -> None:
    _validate_json_schema(forecast, schema, owner="delivery forecast")
    if forecast.get("producer_person_id") != expected_person_id:
        raise GovernanceError("forecast producer is not the rostered technical lead")
    if forecast.get("approval_roster_digest") != approval_roster_digest_value:
        raise GovernanceError("forecast is bound to another approval roster")
    issued_at = _required_string(forecast, "issued_at_utc")
    valid_until = _required_string(forecast, "valid_until_utc")
    issue_time, expiry_time = _validate_validity_interval(
        issued_at, valid_until, owner="delivery forecast"
    )
    effective_commitment_time = commitment_time
    status = _required_string(forecast, "forecast_status")
    if effective_commitment_time is None and (not allow_pending or status == "accepted"):
        raise GovernanceError(
            "strict forecast validation requires an explicit trusted commitment time"
        )
    if effective_commitment_time is not None:
        if effective_commitment_time.tzinfo is None:
            raise GovernanceError("commitment time must be timezone-aware UTC")
        effective_commitment_time = effective_commitment_time.astimezone(UTC)
        if not issue_time <= effective_commitment_time < expiry_time:
            raise GovernanceError(
                "trusted commitment time is outside the forecast's half-open validity interval"
            )
    expected = build_forecast(
        snapshot,
        ledger,
        registry,
        issued_at=issued_at,
        valid_until=valid_until,
        producer_person_id=expected_person_id,
        approval_roster_digest_value=approval_roster_digest_value,
        requested_status=status,
        trusted_time_basis=_required_string(forecast, "trusted_time_basis"),
    )
    if _forecast_projection(forecast) != _forecast_projection(expected):
        raise GovernanceError("forecast projection does not recompute from trusted inputs")
    expected_record_digest = domain_digest(FORECAST_DOMAIN, _forecast_projection(forecast))
    if forecast.get("record_digest") != expected_record_digest:
        raise GovernanceError("forecast record digest mismatch")
    signature_may_be_pending = allow_pending and status != "accepted"
    producer_signature_time = _validate_signature_envelope(
        forecast.get("signature_envelope"),
        expected_person_id=expected_person_id,
        expected_role="technical_lead",
        expected_subject_digest=expected_record_digest,
        allow_pending=signature_may_be_pending,
        not_before=issue_time,
        not_after=expiry_time,
        validation_time=effective_commitment_time,
    )
    receipt = _as_object(forecast.get("acceptance_receipt"), owner="acceptance_receipt")
    expected_receipt = _as_object(
        expected.get("acceptance_receipt"), owner="expected acceptance_receipt"
    )
    if _receipt_projection(receipt) != _receipt_projection(expected_receipt):
        raise GovernanceError("forecast acceptance receipt differs from its trusted projection")
    receipt_digest = domain_digest(RECEIPT_DOMAIN, _receipt_projection(receipt))
    if receipt.get("receipt_digest") != receipt_digest:
        raise GovernanceError("acceptance receipt digest mismatch")
    receipt_signature_time = _validate_signature_envelope(
        receipt.get("signature_envelope"),
        expected_person_id=expected_person_id,
        expected_role="repository_maintainer",
        expected_subject_digest=receipt_digest,
        allow_pending=signature_may_be_pending,
        not_before=issue_time,
        not_after=expiry_time,
        validation_time=effective_commitment_time,
    )
    if (
        producer_signature_time is not None
        and receipt_signature_time is not None
        and receipt_signature_time < producer_signature_time
    ):
        raise GovernanceError("forecast acceptance receipt predates the producer signature")
    if not allow_pending:
        if status != "accepted":
            raise GovernanceError("forecast is not accepted")
        if any(row.get("rebaseline_status") != "confirmed" for row in _forecast_rows(forecast)):
            raise GovernanceError("forecast contains unconfirmed estimates")
        if receipt.get("receipt_status") != "accepted_for_development":
            raise GovernanceError("forecast acceptance receipt is not accepting")


def _forecast_rows(forecast: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [
        _as_object(row, owner="forecast row")
        for row in _as_array(forecast.get("rows"), owner="forecast rows")
    ]


def _signature_status(value: object) -> str:
    envelope = _as_object(value, owner="signature envelope")
    return _required_string(envelope, "status")


def _public_key_fingerprint(public_key: str) -> str:
    parts = public_key.split()
    if len(parts) != 2 or parts[0] != "ssh-ed25519":
        raise GovernanceError("trusted maintainer key must be one canonical ssh-ed25519 key")
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except (ValueError, TypeError) as exc:
        raise GovernanceError("trusted maintainer key contains invalid base64") from exc
    if base64.b64encode(blob).decode("ascii") != parts[1]:
        raise GovernanceError("trusted maintainer key base64 is not canonical")
    encoded = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
    return f"SHA256:{encoded}"


def _verify_sshsig(
    *, signature_base64: str, payload: bytes, signer_person_id: str, public_key: str
) -> None:
    executable = _trusted_executable("ssh-keygen")
    try:
        signature_bytes = base64.b64decode(signature_base64, validate=True)
        if base64.b64encode(signature_bytes).decode("ascii") != signature_base64:
            raise GovernanceError("signature outer base64 is not canonical")
        signature = signature_bytes.decode("ascii")
    except (ValueError, UnicodeDecodeError) as exc:
        raise GovernanceError("signature is not canonical base64-encoded ASCII") from exc
    if (
        "\r" in signature
        or not signature.startswith("-----BEGIN SSH SIGNATURE-----\n")
        or not signature.endswith("-----END SSH SIGNATURE-----\n")
    ):
        raise GovernanceError("signature is not canonical armored OpenSSH sshsig text")
    armor_lines = signature.splitlines()
    if len(armor_lines) < 3:
        raise GovernanceError("OpenSSH signature armor is empty")
    encoded_lines = armor_lines[1:-1]
    if any(len(line) != 70 for line in encoded_lines[:-1]) or not (
        1 <= len(encoded_lines[-1]) <= 70
    ):
        raise GovernanceError("OpenSSH signature armor uses noncanonical line wrapping")
    encoded_blob = "".join(encoded_lines)
    try:
        sshsig_blob = base64.b64decode(encoded_blob, validate=True)
    except ValueError as exc:
        raise GovernanceError("OpenSSH signature armor contains invalid base64") from exc
    if base64.b64encode(sshsig_blob).decode("ascii") != encoded_blob:
        raise GovernanceError("OpenSSH signature armor base64 is not canonical")
    canonical_lines = [
        encoded_blob[index : index + 70] for index in range(0, len(encoded_blob), 70)
    ]
    canonical_armor = (
        "-----BEGIN SSH SIGNATURE-----\n"
        + "\n".join(canonical_lines)
        + "\n-----END SSH SIGNATURE-----\n"
    )
    if canonical_armor != signature:
        raise GovernanceError("OpenSSH signature armor is not canonical")

    offset = 0

    def read_bytes(length: int, *, owner: str) -> bytes:
        nonlocal offset
        end = offset + length
        if length < 0 or end > len(sshsig_blob):
            raise GovernanceError(f"OpenSSH signature has truncated {owner}")
        value = sshsig_blob[offset:end]
        offset = end
        return value

    def read_u32(*, owner: str) -> int:
        return int.from_bytes(read_bytes(4, owner=owner), "big")

    def read_string(*, owner: str) -> bytes:
        return read_bytes(read_u32(owner=f"{owner} length"), owner=owner)

    if read_bytes(6, owner="magic") != b"SSHSIG":
        raise GovernanceError("OpenSSH signature has an invalid magic value")
    if read_u32(owner="version") != 1:
        raise GovernanceError("OpenSSH signature version is not supported")
    embedded_key = read_string(owner="public key")
    expected_key_blob = base64.b64decode(public_key.split()[1], validate=True)
    if embedded_key != expected_key_blob:
        raise GovernanceError("OpenSSH signature embeds another public key")
    if read_string(owner="namespace") != SIGNATURE_NAMESPACE.encode("ascii"):
        raise GovernanceError("OpenSSH signature embeds another namespace")
    if read_string(owner="reserved") != b"":
        raise GovernanceError("OpenSSH signature reserved field must be empty")
    if read_string(owner="hash algorithm") != b"sha512":
        raise GovernanceError("OpenSSH signature must use the frozen sha512 message hash")
    signature_field = read_string(owner="signature field")
    if offset != len(sshsig_blob):
        raise GovernanceError("OpenSSH signature contains trailing data")
    inner_offset = 0

    def read_inner_string(*, owner: str) -> bytes:
        nonlocal inner_offset
        if inner_offset + 4 > len(signature_field):
            raise GovernanceError(f"OpenSSH signature has truncated inner {owner}")
        length = int.from_bytes(signature_field[inner_offset : inner_offset + 4], "big")
        inner_offset += 4
        end = inner_offset + length
        if end > len(signature_field):
            raise GovernanceError(f"OpenSSH signature has truncated inner {owner}")
        value = signature_field[inner_offset:end]
        inner_offset = end
        return value

    if read_inner_string(owner="algorithm") != b"ssh-ed25519":
        raise GovernanceError("OpenSSH signature algorithm is not ssh-ed25519")
    if len(read_inner_string(owner="signature bytes")) != 64 or inner_offset != len(
        signature_field
    ):
        raise GovernanceError("OpenSSH Ed25519 signature field is malformed")
    with tempfile.TemporaryDirectory(prefix="agent-assure-s1-verify-") as temporary:
        root = Path(temporary)
        allowed_signers = root / "allowed_signers"
        signature_path = root / "signature.sshsig"
        allowed_signers.write_text(
            f'{signer_person_id} namespaces="{SIGNATURE_NAMESPACE}" {public_key}\n',
            encoding="ascii",
            newline="\n",
        )
        signature_path.write_text(signature, encoding="ascii", newline="\n")
        try:
            completed = subprocess.run(
                [
                    executable,
                    "-Y",
                    "verify",
                    "-f",
                    str(allowed_signers),
                    "-I",
                    signer_person_id,
                    "-n",
                    SIGNATURE_NAMESPACE,
                    "-s",
                    str(signature_path),
                ],
                input=payload,
                capture_output=True,
                check=False,
                env=_governance_subprocess_environment(),
                timeout=10,
            )
        except subprocess.TimeoutExpired as exc:
            raise GovernanceError("OpenSSH signature verification timed out") from exc
    if completed.returncode != 0:
        diagnostic = completed.stderr.decode("utf-8", errors="replace").strip()
        raise GovernanceError(f"OpenSSH signature verification failed: {diagnostic}")


def _validate_signature_envelope(
    value: object,
    *,
    expected_person_id: str,
    expected_role: str,
    expected_subject_digest: str,
    allow_pending: bool,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
    validation_time: datetime | None = None,
) -> datetime | None:
    envelope = _as_object(value, owner="signature envelope")
    if set(envelope) != SIGNATURE_ENVELOPE_FIELDS:
        raise GovernanceError("signature envelope has unexpected fields")
    exact = {
        "profile": SIGNATURE_PROFILE,
        "namespace": SIGNATURE_NAMESPACE,
        "signed_payload_encoding": SIGNATURE_PAYLOAD_ENCODING,
        "signature_encoding": SIGNATURE_ENCODING,
        "signer_person_id": expected_person_id,
        "signer_role": expected_role,
        "subject_digest": expected_subject_digest,
        "public_key_fingerprint": MAINTAINER_KEY_FINGERPRINT,
    }
    for key, expected in exact.items():
        if envelope.get(key) != expected:
            raise GovernanceError(f"signature envelope {key} does not match its trusted binding")
    actual_fingerprint = _public_key_fingerprint(MAINTAINER_PUBLIC_KEY)
    if actual_fingerprint != MAINTAINER_KEY_FINGERPRINT:
        raise GovernanceError(
            "embedded maintainer public key does not match its frozen fingerprint"
        )
    status = _required_string(envelope, "status")
    signature = envelope.get("signature")
    signed_at_value = envelope.get("signed_at_utc")
    if status == "pending_human_signature":
        if signature is not None or signed_at_value is not None:
            raise GovernanceError(
                "pending signature envelope must contain null signature and signed_at_utc"
            )
        if not allow_pending:
            raise GovernanceError("required governance signature is pending")
        return None
    if status != "signed" or not isinstance(signature, str):
        raise GovernanceError("signature envelope must be pending or contain a signed sshsig")
    if not isinstance(signed_at_value, str):
        raise GovernanceError("signed signature envelope must contain signed_at_utc")
    signed_at = _parse_utc(signed_at_value, owner="signature signed_at_utc")
    if not_before is not None and signed_at < not_before:
        raise GovernanceError("signature predates its subject validity interval")
    if not_after is not None and signed_at >= not_after:
        raise GovernanceError("signature is outside its subject validity interval")
    if validation_time is not None and signed_at > validation_time:
        raise GovernanceError("signature time is later than the trusted validation time")
    _verify_sshsig(
        signature_base64=signature,
        payload=_signature_claim_bytes(envelope),
        signer_person_id=expected_person_id,
        public_key=MAINTAINER_PUBLIC_KEY,
    )
    return signed_at


def _signature_claim_bytes(envelope: Mapping[str, Any]) -> bytes:
    signed_at = envelope.get("signed_at_utc")
    if not isinstance(signed_at, str):
        raise GovernanceError("signed signature envelope lacks a canonical signature time")
    claim = {
        "namespace": _required_string(envelope, "namespace"),
        "signer_person_id": _required_string(envelope, "signer_person_id"),
        "signer_role": _required_string(envelope, "signer_role"),
        "subject_digest": _required_string(envelope, "subject_digest"),
        "public_key_fingerprint": _required_string(envelope, "public_key_fingerprint"),
        "signed_at_utc": signed_at,
    }
    return SIGNATURE_CLAIM_DOMAIN.encode("ascii") + b"\x00" + canonical_bytes(claim)


def _render_json_bytes(value: object) -> bytes:
    _validate_json_value(value)
    return (json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode("utf-8")


def _render_acceptance_attestation_bytes(value: object) -> bytes:
    """Render the tag record with one byte-level, insertion-order-free encoding."""

    _validate_json_value(value)
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(_render_json_bytes(value))
    temporary.replace(path)


def _write_json_batch(records: Mapping[Path, object]) -> None:
    """Pre-render, stage, and install a small JSON batch with rollback on error."""

    if not records:
        return
    rendered = {path: _render_json_bytes(value) for path, value in records.items()}
    prior = {path: path.read_bytes() if path.is_file() else None for path in records}
    staged: dict[Path, Path] = {}
    installed: list[Path] = []
    try:
        for path, payload in rendered.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                mode="wb",
                prefix=f".{path.name}.",
                suffix=".tmp",
                dir=path.parent,
                delete=False,
            ) as handle:
                handle.write(payload)
                handle.flush()
                staged[path] = Path(handle.name)
        for path in records:
            staged[path].replace(path)
            installed.append(path)
    except OSError as exc:
        rollback_errors: list[str] = []
        for path in reversed(installed):
            try:
                previous = prior[path]
                if previous is None:
                    path.unlink(missing_ok=True)
                else:
                    recovery = path.with_name(f".{path.name}.rollback.tmp")
                    recovery.write_bytes(previous)
                    recovery.replace(path)
            except OSError as rollback_exc:
                rollback_errors.append(f"{path}: {rollback_exc}")
        detail = f"; rollback errors: {rollback_errors}" if rollback_errors else ""
        raise GovernanceError(f"unable to install governance JSON batch: {exc}{detail}") from exc
    finally:
        for temporary in staged.values():
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


def _resolve_repository_path_without_links(
    repository_root: Path,
    value: str | Path,
    *,
    owner: str,
) -> Path:
    """Lexically confine a path and reject existing symlink/junction components."""

    root = repository_root.resolve()
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = root / candidate
    absolute = Path(os.path.abspath(candidate))
    try:
        relative = absolute.relative_to(root)
    except ValueError as exc:
        raise GovernanceError(f"{owner} leaves the repository root") from exc
    cursor = root
    for component in relative.parts:
        cursor /= component
        is_junction = getattr(cursor, "is_junction", None)
        if cursor.is_symlink() or (callable(is_junction) and bool(is_junction())):
            raise GovernanceError(f"{owner} contains a symlink or junction: {cursor}")
    return absolute


def _fsync_directory(path: Path) -> None:
    """Durably order directory-entry changes where the platform permits it."""

    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _durable_replace(path: Path, payload: bytes, *, suffix: str) -> None:
    """Flush file contents and replace one file; sync its directory where supported."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=f".{path.name}.",
            suffix=suffix,
            dir=path.parent,
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
        _fsync_directory(path.parent)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


@contextmanager
def _acceptance_import_lock(repository_root: Path) -> Iterator[None]:
    """Take a process-scoped advisory lock for S1 acceptance imports."""

    lock_directory = _resolve_repository_path_without_links(
        repository_root,
        ".tmp/s1-acceptance",
        owner="acceptance import lock directory",
    )
    lock_directory.mkdir(parents=True, exist_ok=True)
    # Recheck after creation so a pre-existing junction or symlink cannot move
    # the lock outside the governed repository. Concurrent same-user mutation
    # remains part of the explicitly documented host-compromise boundary.
    lock_directory = _resolve_repository_path_without_links(
        repository_root,
        lock_directory,
        owner="acceptance import lock directory",
    )
    lock_path = _resolve_repository_path_without_links(
        repository_root,
        lock_directory / ".import.lock",
        owner="acceptance import lock",
    )
    handle = lock_path.open("a+b")
    locked = False
    try:
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"\x00")
            handle.flush()
            os.fsync(handle.fileno())
        handle.seek(0)
        try:
            if os.name == "nt":
                msvcrt_module = __import__("msvcrt")
                cast(Any, msvcrt_module).locking(
                    handle.fileno(), cast(Any, msvcrt_module).LK_NBLCK, 1
                )
            else:
                fcntl_module = cast(Any, __import__("fcntl"))
                fcntl_module.flock(handle.fileno(), fcntl_module.LOCK_EX | fcntl_module.LOCK_NB)
        except OSError as exc:
            raise GovernanceError("another S1 acceptance import is active") from exc
        locked = True
        yield
    finally:
        if locked:
            try:
                handle.seek(0)
                if os.name == "nt":
                    msvcrt_module = cast(Any, __import__("msvcrt"))
                    msvcrt_module.locking(handle.fileno(), msvcrt_module.LK_UNLCK, 1)
                else:
                    fcntl_module = cast(Any, __import__("fcntl"))
                    fcntl_module.flock(handle.fileno(), fcntl_module.LOCK_UN)
            except OSError:
                pass
        handle.close()


def _acceptance_transaction_journal(repository_root: Path) -> Path:
    return repository_root / ".tmp/s1-acceptance/import-transaction.json"


def _guard_acceptance_reader(
    function: Callable[[argparse.Namespace], int],
) -> Callable[[argparse.Namespace], int]:
    """Serialize a command against imports and reject incomplete transactions."""

    @wraps(function)
    def guarded(args: argparse.Namespace) -> int:
        repository_root = Path(cast(str, args.repository_root)).resolve()
        with _acceptance_import_lock(repository_root):
            journal = _acceptance_transaction_journal(repository_root)
            if journal.exists() or journal.is_symlink():
                raise GovernanceError(
                    "an incomplete S1 acceptance transaction exists; recover it with the "
                    "same signed import plan before reading governance records"
                )
            return function(args)

    return guarded


def _acceptance_stage_path(
    repository_root: Path,
    target: Path,
    *,
    plan_digest: str,
) -> Path:
    """Derive the sole staging path authorized for a plan target."""

    root = repository_root.resolve()
    if SHA256_PATTERN.fullmatch(plan_digest) is None:
        raise GovernanceError("acceptance plan digest must be a canonical SHA-256 digest")
    confined = _resolve_repository_path_without_links(root, target, owner="acceptance target")
    if confined != target:
        raise GovernanceError("acceptance target path is not normalized")
    try:
        relative = target.relative_to(root).as_posix()
    except ValueError as exc:
        raise GovernanceError("acceptance target leaves the repository root") from exc
    token = hashlib.sha256(f"{plan_digest}\x00{relative}".encode()).hexdigest()[:20]
    return target.with_name(f".{target.name}.s1-accept-{token}.tmp")


def _acceptance_plan_target_prior_evidence(
    plan: Mapping[str, Any],
    *,
    expected_target_paths: set[str],
) -> dict[str, tuple[int, str]]:
    """Extract plan-bound evidence for every pre-import target."""

    sources: dict[str, tuple[int, str]] = {}
    for value in _as_array(plan.get("source_files"), owner="acceptance plan source files"):
        source = _as_object(value, owner="acceptance plan source file")
        if set(source) != {"path", "size_bytes", "sha256"}:
            raise GovernanceError("acceptance plan source evidence is malformed")
        path = _required_string(source, "path")
        size = _required_integer(source, "size_bytes")
        digest = _required_string(source, "sha256")
        if size < 0 or SHA256_PATTERN.fullmatch(digest) is None:
            raise GovernanceError("acceptance plan source evidence is malformed")
        if path in sources:
            raise GovernanceError(f"acceptance plan repeats source file: {path}")
        sources[path] = (size, digest)
    missing = expected_target_paths - set(sources)
    if missing:
        rendered = ", ".join(sorted(missing, key=_utf8_sort_key))
        raise GovernanceError(f"acceptance plan lacks prior evidence for targets: {rendered}")
    return {path: sources[path] for path in expected_target_paths}


def _decode_journal_bytes(value: object, *, owner: str) -> bytes:
    if not isinstance(value, str):
        raise GovernanceError(f"{owner} must be base64 text")
    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise GovernanceError(f"{owner} is not canonical base64") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise GovernanceError(f"{owner} is not canonical base64")
    return decoded


def _recover_acceptance_transaction(
    repository_root: Path,
    *,
    expected_plan_digest: str,
    expected_prior_evidence: Mapping[str, tuple[int, str]],
    expected_next_payloads: Mapping[str, bytes],
) -> None:
    """Roll back an interrupted import against evidence outside the journal."""

    journal_path = _acceptance_transaction_journal(repository_root)
    if not journal_path.exists():
        return
    if journal_path.is_symlink() or not journal_path.is_file():
        raise GovernanceError("acceptance transaction journal is not a regular file")
    journal = _read_json(journal_path)
    if set(journal) != {"format", "plan_digest", "records"} or journal.get("format") != (
        "agent-assure-s1-acceptance-import-transaction/1"
    ):
        raise GovernanceError("acceptance transaction journal is malformed")
    if journal.get("plan_digest") != expected_plan_digest:
        raise GovernanceError("an interrupted acceptance import exists for a different plan digest")
    expected_target_paths = set(expected_prior_evidence)
    if set(expected_next_payloads) != expected_target_paths:
        raise GovernanceError("acceptance recovery evidence target sets differ")
    raw_records = _as_array(journal.get("records"), owner="acceptance transaction records")
    records: dict[str, dict[str, Any]] = {}
    for raw_record in raw_records:
        record = _as_object(raw_record, owner="acceptance transaction record")
        required = {
            "path",
            "prior_present",
            "prior_size_bytes",
            "prior_sha256",
            "prior_bytes_base64",
            "next_size_bytes",
            "next_sha256",
            "stage_path",
        }
        if set(record) != required:
            raise GovernanceError("acceptance transaction record is malformed")
        relative = _required_string(record, "path")
        if relative in records:
            raise GovernanceError("acceptance transaction repeats a target path")
        records[relative] = record
    if set(records) != expected_target_paths:
        raise GovernanceError("interrupted acceptance transaction target set changed")

    governance_root = (repository_root / "docs/governance/v1").resolve()
    validated: list[tuple[Path, Path, bytes | None, bytes | None]] = []
    for relative, record in records.items():
        target = _resolve_repository_path_without_links(
            repository_root, relative, owner="acceptance transaction target"
        )
        stage = _acceptance_stage_path(
            repository_root,
            target,
            plan_digest=expected_plan_digest,
        )
        expected_stage_relative = stage.relative_to(repository_root.resolve()).as_posix()
        if _required_string(record, "stage_path") != expected_stage_relative:
            raise GovernanceError("acceptance transaction staging path is not deterministic")
        try:
            target.relative_to(governance_root)
            stage.relative_to(governance_root)
        except ValueError as exc:
            raise GovernanceError(
                "acceptance transaction path leaves governance directory"
            ) from exc
        if target.exists() and not target.is_file():
            raise GovernanceError("acceptance transaction target is not a regular file")
        if stage.exists() and not stage.is_file():
            raise GovernanceError("acceptance transaction staging path is not a regular file")
        prior_present = record.get("prior_present")
        if not isinstance(prior_present, bool):
            raise GovernanceError("acceptance transaction prior_present must be boolean")
        expected_prior_size, expected_prior_digest = expected_prior_evidence[relative]
        if not prior_present:
            raise GovernanceError("acceptance transaction conflicts with plan prior evidence")
        prior: bytes | None
        prior = _decode_journal_bytes(
            record.get("prior_bytes_base64"), owner=f"{relative} prior bytes"
        )
        journal_prior_size = _required_integer(record, "prior_size_bytes")
        journal_prior_digest = _required_string(record, "prior_sha256")
        if (
            journal_prior_size != expected_prior_size
            or journal_prior_digest != expected_prior_digest
            or len(prior) != expected_prior_size
            or raw_digest(prior) != expected_prior_digest
        ):
            raise GovernanceError("acceptance transaction prior evidence differs from its plan")
        expected_next = expected_next_payloads[relative]
        if _required_integer(record, "next_size_bytes") != len(expected_next) or _required_string(
            record, "next_sha256"
        ) != raw_digest(expected_next):
            raise GovernanceError("acceptance transaction next evidence differs from its plan")
        current = target.read_bytes() if target.is_file() else None
        current_is_prior = current == prior
        current_is_next = current == expected_next
        if not current_is_prior and not current_is_next:
            raise GovernanceError(
                f"cannot recover acceptance target with unknown bytes: {relative}"
            )
        validated.append((target, stage, prior, current))

    for target, stage, prior, current in validated:
        if current != prior:
            if prior is None:
                target.unlink(missing_ok=True)
                _fsync_directory(target.parent)
            else:
                _durable_replace(target, prior, suffix=".recovery.tmp")
        stage.unlink(missing_ok=True)
    journal_path.unlink()
    _fsync_directory(journal_path.parent)


def _install_acceptance_targets(
    repository_root: Path,
    records: Mapping[Path, Mapping[str, Any]],
    *,
    plan_digest: str,
    expected_prior_evidence: Mapping[str, tuple[int, str]],
) -> None:
    """Install a serialized phase with journaled process-crash rollback metadata."""

    if not records:
        raise GovernanceError("acceptance import has no targets")
    root = repository_root.resolve()
    rendered = {path: _render_json_bytes(record) for path, record in records.items()}
    target_paths = {path.relative_to(root).as_posix() for path in records}
    if set(expected_prior_evidence) != target_paths:
        raise GovernanceError("acceptance install prior-evidence target set changed")
    journal_records: list[dict[str, Any]] = []
    stages: dict[Path, Path] = {}
    for path in sorted(rendered, key=lambda value: _utf8_sort_key(str(value))):
        confined = _resolve_repository_path_without_links(root, path, owner="acceptance target")
        if confined != path:
            raise GovernanceError("acceptance target path is not normalized")
        if path.exists() and not path.is_file():
            raise GovernanceError(f"acceptance target is not a regular file: {path}")
        relative = path.relative_to(root).as_posix()
        if not path.exists():
            raise GovernanceError(f"acceptance target lacks its plan-bound prior file: {path}")
        prior = path.read_bytes()
        expected_prior_size, expected_prior_digest = expected_prior_evidence[relative]
        if len(prior) != expected_prior_size or raw_digest(prior) != expected_prior_digest:
            raise GovernanceError(f"acceptance target differs from plan prior evidence: {path}")
        stage = _acceptance_stage_path(root, path, plan_digest=plan_digest)
        if stage.exists() or stage.is_symlink():
            raise GovernanceError(f"acceptance staging path already exists: {stage.name}")
        stages[path] = stage
        payload = rendered[path]
        journal_records.append(
            {
                "path": relative,
                "prior_present": True,
                "prior_size_bytes": len(prior),
                "prior_sha256": raw_digest(prior),
                "prior_bytes_base64": base64.b64encode(prior).decode("ascii"),
                "next_size_bytes": len(payload),
                "next_sha256": raw_digest(payload),
                "stage_path": stage.relative_to(root).as_posix(),
            }
        )
    journal = {
        "format": "agent-assure-s1-acceptance-import-transaction/1",
        "plan_digest": plan_digest,
        "records": journal_records,
    }
    journal_path = _acceptance_transaction_journal(root)
    if journal_path.exists() or journal_path.is_symlink():
        raise GovernanceError("acceptance transaction journal already exists")
    _durable_replace(journal_path, _render_json_bytes(journal), suffix=".journal.tmp")
    try:
        for path, stage in stages.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            with stage.open("xb") as handle:
                handle.write(rendered[path])
                handle.flush()
                os.fsync(handle.fileno())
        for path, stage in stages.items():
            stage.replace(path)
            _fsync_directory(path.parent)
        for path, payload in rendered.items():
            if not path.is_file() or path.is_symlink() or path.read_bytes() != payload:
                raise GovernanceError(f"acceptance target post-install verification failed: {path}")
        journal_path.unlink()
        _fsync_directory(journal_path.parent)
    except Exception as exc:
        expected_next_payloads = {
            path.relative_to(root).as_posix(): payload for path, payload in rendered.items()
        }
        try:
            _recover_acceptance_transaction(
                root,
                expected_plan_digest=plan_digest,
                expected_prior_evidence=expected_prior_evidence,
                expected_next_payloads=expected_next_payloads,
            )
        except Exception as recovery_exc:
            raise GovernanceError(
                "acceptance import failed and requires recovery with the same plan digest: "
                f"{recovery_exc}"
            ) from exc
        if isinstance(exc, GovernanceError):
            raise
        raise GovernanceError(f"unable to install acceptance records: {exc}") from exc


def _private_acceptance_path(
    repository_root: Path,
    value: str | Path,
    *,
    owner: str,
    must_exist: bool | None = None,
) -> Path:
    """Resolve a locally ignored acceptance artifact under .tmp/s1-acceptance."""

    root = repository_root.resolve()
    resolved = _resolve_repository_path_without_links(root, value, owner=owner)
    staging_root = _resolve_repository_path_without_links(
        root, ".tmp/s1-acceptance", owner="acceptance staging root"
    )
    try:
        relative_to_staging = resolved.relative_to(staging_root)
        relative_to_repository = resolved.relative_to(root).as_posix()
    except ValueError as exc:
        raise GovernanceError(f"{owner} must be under .tmp/s1-acceptance") from exc
    if not relative_to_staging.parts:
        raise GovernanceError(f"{owner} must name an item below .tmp/s1-acceptance")
    indexed = _run_git(root, ["ls-files", "--stage", "--", relative_to_repository])
    if indexed.returncode != 0 or indexed.stdout.strip():
        raise GovernanceError(f"{owner} must remain outside the Git index")
    ignore_probe = relative_to_repository
    if must_exist is False and resolved.suffix == "":
        ignore_probe += "/plan.json"
    ignored = _run_git(root, ["check-ignore", "--no-index", "--", ignore_probe])
    if ignored.returncode != 0:
        raise GovernanceError(f"{owner} is not protected by a local ignore rule")
    if must_exist is True and not resolved.exists():
        raise GovernanceError(f"{owner} does not exist")
    if must_exist is False and resolved.exists():
        raise GovernanceError(f"refusing to overwrite existing {owner}")
    return resolved


def _source_file_evidence(repository_root: Path, path: Path) -> dict[str, Any]:
    root = repository_root.resolve()
    resolved = _resolve_repository_path_without_links(root, path, owner="acceptance source file")
    try:
        relative = resolved.relative_to(root).as_posix()
    except ValueError as exc:
        raise GovernanceError("acceptance source file leaves the repository root") from exc
    if not resolved.is_file() or resolved.is_symlink():
        raise GovernanceError(f"acceptance source is not a regular file: {relative}")
    payload = resolved.read_bytes()
    return {"path": relative, "size_bytes": len(payload), "sha256": raw_digest(payload)}


def _plan_projection(plan: Mapping[str, Any]) -> dict[str, Any]:
    return _record_projection(plan, "plan_digest")


def _nested_object(record: Mapping[str, Any], path: Sequence[str], *, owner: str) -> dict[str, Any]:
    current: object = record
    for component in path:
        current = _as_object(current, owner=owner).get(component)
    return _as_object(current, owner=owner)


def _claim_descriptor(
    *,
    claim_id: str,
    target_path: str,
    envelope_path: Sequence[str],
    target_record: Mapping[str, Any],
    signed_at: str,
) -> tuple[dict[str, Any], bytes]:
    if re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", claim_id) is None:
        raise GovernanceError(f"invalid acceptance claim id: {claim_id}")
    _parse_utc(signed_at, owner=f"{claim_id} signed_at")
    envelope = copy.deepcopy(
        _nested_object(target_record, envelope_path, owner=f"{claim_id} envelope")
    )
    if envelope.get("status") != "pending_human_signature":
        raise GovernanceError(f"{claim_id} target envelope is not an unsigned machine draft")
    if envelope.get("signed_at_utc") is not None or envelope.get("signature") is not None:
        raise GovernanceError(f"{claim_id} target envelope already contains signature material")
    envelope["status"] = "signed"
    envelope["signed_at_utc"] = signed_at
    payload = _signature_claim_bytes(envelope)
    claim_file = f"claims/{claim_id}.claim"
    descriptor = {
        "claim_id": claim_id,
        "target_path": target_path,
        "envelope_path": list(envelope_path),
        "signed_at_utc": signed_at,
        "signer_person_id": _required_string(envelope, "signer_person_id"),
        "signer_role": _required_string(envelope, "signer_role"),
        "subject_digest": _required_string(envelope, "subject_digest"),
        "claim_file": claim_file,
        "claim_size_bytes": len(payload),
        "claim_sha256": raw_digest(payload),
    }
    return descriptor, payload


def _write_acceptance_plan(
    repository_root: Path,
    plan_directory: Path,
    *,
    phase: str,
    source_paths: Sequence[Path],
    targets: Mapping[str, Mapping[str, Any]],
    claim_specs: Sequence[tuple[str, str, Sequence[str], str]],
    result_commit: str | None = None,
) -> dict[str, Any]:
    root = repository_root.resolve()
    if plan_directory.exists():
        raise GovernanceError("acceptance plan directory already exists")
    canonical_targets = [
        {"path": path, "record": copy.deepcopy(targets[path])}
        for path in sorted(targets, key=_utf8_sort_key)
    ]
    target_by_path = {item["path"]: item["record"] for item in canonical_targets}
    claims: list[dict[str, Any]] = []
    claim_payloads: dict[str, bytes] = {}
    for claim_id, target_path, envelope_path, signed_at in claim_specs:
        if target_path not in target_by_path:
            raise GovernanceError(f"acceptance claim targets an unknown record: {target_path}")
        descriptor, payload = _claim_descriptor(
            claim_id=claim_id,
            target_path=target_path,
            envelope_path=envelope_path,
            target_record=cast(Mapping[str, Any], target_by_path[target_path]),
            signed_at=signed_at,
        )
        if descriptor["claim_file"] in claim_payloads:
            raise GovernanceError("acceptance plan repeats a claim file")
        claims.append(descriptor)
        claim_payloads[cast(str, descriptor["claim_file"])] = payload
    unique_source_paths = {path.resolve() for path in source_paths}
    sources = [
        _source_file_evidence(root, path)
        for path in sorted(unique_source_paths, key=lambda item: _utf8_sort_key(str(item)))
    ]
    projection: dict[str, Any] = {
        "format": "agent-assure-s1-acceptance-signature-plan/1",
        "spec_revision": SPEC_REVISION,
        "phase": phase,
        "authorization_effect": "none",
        "result_commit": result_commit,
        "source_files": sources,
        "targets": canonical_targets,
        "claims": claims,
    }
    plan = {**projection, "plan_digest": domain_digest(ACCEPTANCE_PLAN_DOMAIN, projection)}
    parent = plan_directory.parent
    parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{plan_directory.name}.", dir=parent))
    try:
        (temporary / "claims").mkdir()
        (temporary / "plan.json").write_bytes(_render_json_bytes(plan))
        for relative, payload in claim_payloads.items():
            path = temporary / relative
            path.write_bytes(payload)
        temporary.replace(plan_directory)
    except OSError as exc:
        raise GovernanceError(f"unable to write acceptance signature plan: {exc}") from exc
    finally:
        if temporary.exists():
            shutil.rmtree(temporary, ignore_errors=True)
    return plan


def _read_acceptance_plan(plan_directory: Path) -> dict[str, Any]:
    plan = _read_json(plan_directory / "plan.json")
    required = {
        "format",
        "spec_revision",
        "phase",
        "authorization_effect",
        "result_commit",
        "source_files",
        "targets",
        "claims",
        "plan_digest",
    }
    if set(plan) != required:
        raise GovernanceError("acceptance plan has missing or unexpected fields")
    if (
        plan.get("format") != "agent-assure-s1-acceptance-signature-plan/1"
        or plan.get("spec_revision") != SPEC_REVISION
        or plan.get("authorization_effect") != "none"
    ):
        raise GovernanceError("acceptance plan identity is invalid")
    expected_digest = domain_digest(ACCEPTANCE_PLAN_DOMAIN, _plan_projection(plan))
    if plan.get("plan_digest") != expected_digest:
        raise GovernanceError("acceptance plan digest mismatch")
    claims = _as_array(plan.get("claims"), owner="acceptance plan claims")
    claim_ids: set[str] = set()
    claim_files: set[str] = set()
    for value in claims:
        claim = _as_object(value, owner="acceptance plan claim")
        claim_id = _required_string(claim, "claim_id")
        claim_file = _required_string(claim, "claim_file")
        if claim_id in claim_ids or claim_file in claim_files:
            raise GovernanceError("acceptance plan repeats a claim id or file")
        claim_ids.add(claim_id)
        claim_files.add(claim_file)
        path = (plan_directory / claim_file).resolve()
        try:
            path.relative_to(plan_directory.resolve())
        except ValueError as exc:
            raise GovernanceError("acceptance claim path leaves its plan directory") from exc
        if not path.is_file() or path.is_symlink():
            raise GovernanceError(f"acceptance claim file is missing: {claim_file}")
        payload = path.read_bytes()
        if len(payload) != _required_integer(claim, "claim_size_bytes") or raw_digest(
            payload
        ) != claim.get("claim_sha256"):
            raise GovernanceError(f"acceptance claim file changed: {claim_file}")
    return plan


def _verify_plan_sources(repository_root: Path, plan: Mapping[str, Any]) -> None:
    observed: set[str] = set()
    for value in _as_array(plan.get("source_files"), owner="acceptance plan source files"):
        source = _as_object(value, owner="acceptance plan source file")
        path = _required_string(source, "path")
        if path in observed:
            raise GovernanceError(f"acceptance plan repeats source file: {path}")
        observed.add(path)
        actual = _source_file_evidence(repository_root, repository_root / path)
        if actual != source:
            raise GovernanceError(f"acceptance source file changed after plan creation: {path}")


def _canonical_sshsig_armor(payload: bytes) -> bytes:
    try:
        text = payload.decode("ascii").replace("\r\n", "\n")
    except UnicodeDecodeError as exc:
        raise GovernanceError("imported SSHSIG is not ASCII armor") from exc
    if "\r" in text:
        raise GovernanceError("imported SSHSIG contains a noncanonical carriage return")
    lines = text.splitlines()
    if (
        len(lines) < 3
        or lines[0] != "-----BEGIN SSH SIGNATURE-----"
        or lines[-1] != "-----END SSH SIGNATURE-----"
    ):
        raise GovernanceError("imported SSHSIG armor boundary is invalid")
    encoded = "".join(lines[1:-1])
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except ValueError as exc:
        raise GovernanceError("imported SSHSIG armor contains invalid base64") from exc
    if base64.b64encode(decoded).decode("ascii") != encoded:
        raise GovernanceError("imported SSHSIG armor base64 is not canonical")
    wrapped = "\n".join(encoded[index : index + 70] for index in range(0, len(encoded), 70))
    return ("-----BEGIN SSH SIGNATURE-----\n" + wrapped + "\n-----END SSH SIGNATURE-----\n").encode(
        "ascii"
    )


def _materialize_signed_plan_targets(
    plan_directory: Path, plan: Mapping[str, Any]
) -> dict[str, dict[str, Any]]:
    targets: dict[str, dict[str, Any]] = {}
    for value in _as_array(plan.get("targets"), owner="acceptance plan targets"):
        target = _as_object(value, owner="acceptance plan target")
        path = _required_string(target, "path")
        if path in targets:
            raise GovernanceError(f"acceptance plan repeats target path: {path}")
        targets[path] = copy.deepcopy(_as_object(target.get("record"), owner=path))
    expected_signature_paths: set[Path] = set()
    for value in _as_array(plan.get("claims"), owner="acceptance plan claims"):
        claim = _as_object(value, owner="acceptance plan claim")
        target_path = _required_string(claim, "target_path")
        if target_path not in targets:
            raise GovernanceError("acceptance claim targets a missing plan record")
        envelope_path = _required_string_array(claim, "envelope_path")
        envelope = _nested_object(
            targets[target_path], envelope_path, owner=f"{target_path} signature envelope"
        )
        if envelope.get("status") != "pending_human_signature":
            raise GovernanceError("acceptance plan target signature is no longer pending")
        signature_path = (
            plan_directory / (_required_string(claim, "claim_file") + ".sig")
        ).resolve()
        expected_signature_paths.add(signature_path)
        if not signature_path.is_file() or signature_path.is_symlink():
            raise GovernanceError(f"missing human SSHSIG: {signature_path.name}")
        armor = _canonical_sshsig_armor(signature_path.read_bytes())
        envelope["status"] = "signed"
        envelope["signed_at_utc"] = _required_string(claim, "signed_at_utc")
        envelope["signature"] = base64.b64encode(armor).decode("ascii")
        claim_payload = (plan_directory / _required_string(claim, "claim_file")).read_bytes()
        if claim_payload != _signature_claim_bytes(envelope):
            raise GovernanceError("signed envelope no longer reproduces its exported claim")
        _verify_sshsig(
            signature_base64=cast(str, envelope["signature"]),
            payload=claim_payload,
            signer_person_id=_required_string(claim, "signer_person_id"),
            public_key=MAINTAINER_PUBLIC_KEY,
        )
    actual_signature_paths = set((plan_directory / "claims").glob("*.sig"))
    if actual_signature_paths != expected_signature_paths:
        raise GovernanceError("acceptance plan contains missing or unexpected SSHSIG files")
    return targets


def _current_acceptance_attestation_projection(
    record: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        key: value
        for key, value in record.items()
        if key not in {"attestation_digest", "signature_envelope"}
    }


def _validate_live_repository_evidence(
    value: object,
    *,
    expected_closure_commit: str,
) -> dict[str, Any]:
    evidence = _as_object(value, owner="current acceptance live repository evidence")
    required = {
        "approved_remote_url",
        "authoritative_remote_refs",
        "branch_name",
        "fetch_performed",
        "head_commit",
        "local_refs",
    }
    if set(evidence) != required:
        raise GovernanceError("current acceptance live repository evidence has unexpected fields")
    expected_remote_refs = {
        "refs/heads/main": PINNED_BASE_COMMIT,
        "refs/tags/v0.7.0": PINNED_TAG_OBJECT,
        "refs/tags/v0.7.0^{}": PINNED_BASE_COMMIT,
    }
    expected_local_refs = {
        "refs/remotes/origin/main^{commit}": PINNED_BASE_COMMIT,
        "refs/tags/v0.7.0^{tag}": PINNED_TAG_OBJECT,
        "refs/tags/v0.7.0^{commit}": PINNED_BASE_COMMIT,
    }
    if (
        evidence.get("approved_remote_url") != APPROVED_ORIGIN_URL
        or evidence.get("authoritative_remote_refs") != expected_remote_refs
        or evidence.get("local_refs") != expected_local_refs
        or evidence.get("branch_name") != S1_BRANCH_NAME
        or evidence.get("fetch_performed") is not True
        or evidence.get("head_commit") != expected_closure_commit
    ):
        raise GovernanceError("current acceptance live repository evidence changed")
    return copy.deepcopy(evidence)


def build_current_acceptance_attestation(
    snapshot: RoadmapSnapshot,
    *,
    repository_root: Path,
    bundle: Mapping[str, Any],
    live_repository_evidence: Mapping[str, Any],
    gate_checked_at: str,
    signature_requested_at: str,
    signer_person_id: str,
) -> dict[str, Any]:
    """Build the human-signable proof of the one-time live acceptance gate."""

    closure_commit = _required_string(live_repository_evidence, "head_commit")
    if GIT_COMMIT_PATTERN.fullmatch(closure_commit) is None:
        raise GovernanceError("current acceptance closure commit is not a full Git object ID")
    gate_time = _parse_utc(gate_checked_at, owner="current acceptance gate_checked_at_utc")
    signature_time = _parse_utc(
        signature_requested_at,
        owner="current acceptance signature_requested_at_utc",
    )
    if signature_time < gate_time:
        raise GovernanceError("current acceptance signature time predates the live gate")
    if signature_time - gate_time > MAX_ACCEPTANCE_ATTESTATION_DELAY:
        raise GovernanceError(
            "current acceptance signature time is more than one hour after the gate"
        )
    bundle_issue, bundle_expiry = _validate_validity_interval(
        _required_string(bundle, "issued_at_utc"),
        _required_string(bundle, "valid_until_utc"),
        owner="S1 governance bundle",
    )
    if not bundle_issue <= gate_time <= signature_time < bundle_expiry:
        raise GovernanceError(
            "current acceptance gate and signature request must remain inside bundle validity"
        )
    live_evidence = _validate_live_repository_evidence(
        live_repository_evidence,
        expected_closure_commit=closure_commit,
    )
    result_commit = _required_string(bundle, "result_commit")
    if GIT_COMMIT_PATTERN.fullmatch(result_commit) is None:
        raise GovernanceError("current acceptance bundle result commit is invalid")
    bundle_digest = _required_string(bundle, "bundle_digest")
    if SHA256_PATTERN.fullmatch(bundle_digest) is None:
        raise GovernanceError("current acceptance bundle digest is invalid")
    projection: dict[str, Any] = {
        "format": "agent-assure-s1-current-acceptance-attestation/1",
        "spec_revision": SPEC_REVISION,
        "release": "1.0.0a1",
        "maturity": "governed-baseline",
        "authorization_scope": "development_governance_only",
        "independent_review_claimed": False,
        "acceptance_tag_name": S1_ACCEPTANCE_TAG_NAME,
        "closure_commit": closure_commit,
        "result_commit": result_commit,
        "bundle_digest": bundle_digest,
        "full_roadmap_digest": snapshot.raw_digest,
        "gate_checked_at_utc": gate_checked_at,
        "signature_requested_at_utc": signature_requested_at,
        "current_gate_result": "valid_current_closure",
        "live_repository_evidence": live_evidence,
        "validator_artifact": _artifact_evidence_from_commit(
            repository_root,
            closure_commit,
            "scripts/v1_s1_governance.py",
            kind="governance_validator",
        ),
        "launcher_artifact": _artifact_evidence_from_commit(
            repository_root,
            closure_commit,
            "scripts/v1_s1_governance.ps1",
            kind="governance_runtime_launcher",
        ),
        "signer_person_id": signer_person_id,
    }
    digest = domain_digest(CURRENT_ACCEPTANCE_ATTESTATION_DOMAIN, projection)
    return {
        **projection,
        "attestation_digest": digest,
        "signature_envelope": _pending_signature(
            signer_person_id,
            "repository_maintainer",
            digest,
        ),
    }


def _validate_current_acceptance_attestation(
    record: Mapping[str, Any],
    *,
    repository_root: Path,
    expected_closure_commit: str,
    expected_roadmap_digest: str,
    allow_pending: bool,
) -> tuple[datetime, datetime | None]:
    required = {
        "format",
        "spec_revision",
        "release",
        "maturity",
        "authorization_scope",
        "independent_review_claimed",
        "acceptance_tag_name",
        "closure_commit",
        "result_commit",
        "bundle_digest",
        "full_roadmap_digest",
        "gate_checked_at_utc",
        "signature_requested_at_utc",
        "current_gate_result",
        "live_repository_evidence",
        "validator_artifact",
        "launcher_artifact",
        "signer_person_id",
        "attestation_digest",
        "signature_envelope",
    }
    if set(record) != required:
        raise GovernanceError("current acceptance attestation has unexpected fields")
    exact: dict[str, object] = {
        "format": "agent-assure-s1-current-acceptance-attestation/1",
        "spec_revision": SPEC_REVISION,
        "release": "1.0.0a1",
        "maturity": "governed-baseline",
        "authorization_scope": "development_governance_only",
        "independent_review_claimed": False,
        "acceptance_tag_name": S1_ACCEPTANCE_TAG_NAME,
        "closure_commit": expected_closure_commit,
        "full_roadmap_digest": expected_roadmap_digest,
        "current_gate_result": "valid_current_closure",
    }
    for key, expected in exact.items():
        if record.get(key) != expected:
            raise GovernanceError(f"current acceptance attestation changed {key}")
    if GIT_COMMIT_PATTERN.fullmatch(_required_string(record, "result_commit")) is None:
        raise GovernanceError("current acceptance attestation result commit is invalid")
    if SHA256_PATTERN.fullmatch(_required_string(record, "bundle_digest")) is None:
        raise GovernanceError("current acceptance attestation bundle digest is invalid")
    _validate_live_repository_evidence(
        record.get("live_repository_evidence"),
        expected_closure_commit=expected_closure_commit,
    )
    validator = _as_object(record.get("validator_artifact"), owner="validator_artifact")
    expected_validator = _artifact_evidence_from_commit(
        repository_root,
        expected_closure_commit,
        "scripts/v1_s1_governance.py",
        kind="governance_validator",
    )
    if validator != expected_validator:
        raise GovernanceError("current acceptance attestation validator artifact changed")
    launcher = _as_object(record.get("launcher_artifact"), owner="launcher_artifact")
    expected_launcher = _artifact_evidence_from_commit(
        repository_root,
        expected_closure_commit,
        "scripts/v1_s1_governance.ps1",
        kind="governance_runtime_launcher",
    )
    if launcher != expected_launcher:
        raise GovernanceError("current acceptance attestation launcher artifact changed")
    expected_digest = domain_digest(
        CURRENT_ACCEPTANCE_ATTESTATION_DOMAIN,
        _current_acceptance_attestation_projection(record),
    )
    if record.get("attestation_digest") != expected_digest:
        raise GovernanceError("current acceptance attestation digest mismatch")
    gate_time = _parse_utc(
        _required_string(record, "gate_checked_at_utc"),
        owner="current acceptance gate_checked_at_utc",
    )
    requested_signature_time = _parse_utc(
        _required_string(record, "signature_requested_at_utc"),
        owner="current acceptance signature_requested_at_utc",
    )
    if requested_signature_time < gate_time:
        raise GovernanceError("current acceptance attestation signature predates the live gate")
    if requested_signature_time - gate_time > MAX_ACCEPTANCE_ATTESTATION_DELAY:
        raise GovernanceError("current acceptance attestation was not signed within one hour")
    signer_person_id = _required_string(record, "signer_person_id")
    signature_time = _validate_signature_envelope(
        record.get("signature_envelope"),
        expected_person_id=signer_person_id,
        expected_role="repository_maintainer",
        expected_subject_digest=expected_digest,
        allow_pending=allow_pending,
        not_before=gate_time,
        validation_time=requested_signature_time,
    )
    if signature_time is not None and signature_time != requested_signature_time:
        raise GovernanceError("current acceptance signature time differs from its signed request")
    return gate_time, signature_time


def _write_current_acceptance_attestation_plan(
    plan_directory: Path,
    record: Mapping[str, Any],
) -> dict[str, Any]:
    if plan_directory.exists() or plan_directory.is_symlink():
        raise GovernanceError("current acceptance attestation plan directory already exists")
    envelope = copy.deepcopy(
        _as_object(record.get("signature_envelope"), owner="attestation signature envelope")
    )
    if envelope.get("status") != "pending_human_signature":
        raise GovernanceError("current acceptance attestation plan must begin unsigned")
    envelope["status"] = "signed"
    envelope["signed_at_utc"] = _required_string(record, "signature_requested_at_utc")
    envelope["signature"] = None
    claim = _signature_claim_bytes(envelope)
    parent = plan_directory.parent
    parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{plan_directory.name}.", dir=parent))
    try:
        (temporary / "attestation.pending.json").write_bytes(
            _render_acceptance_attestation_bytes(record)
        )
        (temporary / "attestation.claim").write_bytes(claim)
        temporary.replace(plan_directory)
    except OSError as exc:
        raise GovernanceError(
            f"unable to write current acceptance attestation plan: {exc}"
        ) from exc
    finally:
        if temporary.exists():
            shutil.rmtree(temporary, ignore_errors=True)
    return {
        "attestation_digest": _required_string(record, "attestation_digest"),
        "claim_sha256": raw_digest(claim),
        "claim_size_bytes": len(claim),
        "plan_directory": str(plan_directory),
    }


def _read_tagged_current_acceptance_attestation(
    repository_root: Path,
    *,
    tag_object: str,
    expected_closure_commit: str,
) -> dict[str, Any]:
    if GIT_COMMIT_PATTERN.fullmatch(tag_object) is None:
        raise GovernanceError("--acceptance-tag-object must be a full lowercase 40-hex object ID")
    ref = _run_git(
        repository_root,
        ["rev-parse", "--verify", f"refs/tags/{S1_ACCEPTANCE_TAG_NAME}^{{tag}}"],
    )
    if ref.returncode != 0 or ref.stdout.decode("ascii", errors="strict").strip() != tag_object:
        raise GovernanceError("the fixed S1 acceptance tag does not resolve to the selected object")
    object_type = _run_git(repository_root, ["cat-file", "-t", tag_object])
    if object_type.returncode != 0 or object_type.stdout.strip() != b"tag":
        raise GovernanceError("--acceptance-tag-object does not identify an annotated Git tag")
    raw_result = _run_git(repository_root, ["cat-file", "tag", tag_object])
    if raw_result.returncode != 0:
        raise GovernanceError("unable to read the S1 acceptance tag object")
    raw = raw_result.stdout
    if len(raw) > MAX_GOVERNANCE_JSON_BYTES:
        raise GovernanceError("S1 acceptance tag object exceeds the governance size limit")
    header, separator, message = raw.partition(b"\n\n")
    if not separator:
        raise GovernanceError("S1 acceptance tag object lacks a message boundary")
    try:
        header_lines = header.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as exc:
        raise GovernanceError("S1 acceptance tag header is not UTF-8") from exc
    if len(header_lines) != 4:
        raise GovernanceError("S1 acceptance tag has unexpected headers")
    if header_lines[0] != f"object {expected_closure_commit}":
        raise GovernanceError("S1 acceptance tag targets another closure commit")
    if header_lines[1] != "type commit" or header_lines[2] != f"tag {S1_ACCEPTANCE_TAG_NAME}":
        raise GovernanceError("S1 acceptance tag identity changed")
    if re.fullmatch(r"tagger .+ <[^<>\r\n]+> [0-9]+ [+-][0-9]{4}", header_lines[3]) is None:
        raise GovernanceError("S1 acceptance tagger header is malformed")
    try:
        parsed = strict_json_loads(message.decode("utf-8", errors="strict"))
    except UnicodeDecodeError as exc:
        raise GovernanceError("S1 acceptance tag message is not UTF-8") from exc
    record = _as_object(parsed, owner="S1 acceptance tag message")
    if message != _render_acceptance_attestation_bytes(record):
        raise GovernanceError("S1 acceptance tag message is not the canonical rendered record")
    return record


@_guard_acceptance_reader
def acceptance_attestation_finalize(args: argparse.Namespace) -> int:
    """Verify the eighth human SSHSIG and render the tag-contained attestation."""

    repository_root = Path(cast(str, args.repository_root)).resolve()
    _validate_git_history_safety(repository_root)
    plan_directory = _private_acceptance_path(
        repository_root,
        cast(str, args.plan_dir),
        owner="current acceptance attestation plan",
        must_exist=True,
    )
    if not plan_directory.is_dir():
        raise GovernanceError("current acceptance attestation plan must be a directory")
    expected_names = {
        "attestation.pending.json",
        "attestation.claim",
        "attestation.claim.sig",
    }
    observed_names = {entry.name for entry in plan_directory.iterdir()}
    if observed_names != expected_names:
        raise GovernanceError("current acceptance attestation plan has missing or extra files")
    for name in expected_names:
        path = plan_directory / name
        if not path.is_file() or path.is_symlink():
            raise GovernanceError("current acceptance attestation plan contains a non-file")
    record = _read_json(plan_directory / "attestation.pending.json")
    expected_digest = cast(str, args.expected_attestation_digest)
    if SHA256_PATTERN.fullmatch(expected_digest) is None:
        raise GovernanceError("--expected-attestation-digest must be a canonical SHA-256 digest")
    if record.get("attestation_digest") != expected_digest:
        raise GovernanceError(
            "current acceptance attestation differs from the human-confirmed expected digest"
        )
    closure_commit = _required_string(record, "closure_commit")
    _validate_current_acceptance_attestation(
        record,
        repository_root=repository_root,
        expected_closure_commit=closure_commit,
        expected_roadmap_digest=_required_string(record, "full_roadmap_digest"),
        allow_pending=True,
    )
    envelope = _as_object(record.get("signature_envelope"), owner="signature_envelope")
    signed_envelope = copy.deepcopy(envelope)
    signed_envelope["status"] = "signed"
    signed_envelope["signed_at_utc"] = _required_string(record, "signature_requested_at_utc")
    armor = _canonical_sshsig_armor((plan_directory / "attestation.claim.sig").read_bytes())
    signed_envelope["signature"] = base64.b64encode(armor).decode("ascii")
    expected_claim = _signature_claim_bytes(signed_envelope)
    if (plan_directory / "attestation.claim").read_bytes() != expected_claim:
        raise GovernanceError("current acceptance attestation claim changed after preparation")
    signed_record = copy.deepcopy(record)
    signed_record["signature_envelope"] = signed_envelope
    _validate_current_acceptance_attestation(
        signed_record,
        repository_root=repository_root,
        expected_closure_commit=closure_commit,
        expected_roadmap_digest=_required_string(record, "full_roadmap_digest"),
        allow_pending=False,
    )
    output = plan_directory / "attestation.signed.json"
    payload = _render_acceptance_attestation_bytes(signed_record)
    try:
        with output.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        _fsync_directory(plan_directory)
    except OSError as exc:
        raise GovernanceError(
            f"unable to write signed current acceptance attestation: {exc}"
        ) from exc
    print(
        json.dumps(
            {
                "acceptance_tag_name": S1_ACCEPTANCE_TAG_NAME,
                "attestation_digest": expected_digest,
                "closure_commit": closure_commit,
                "output": str(output),
                "result": "verified_current_acceptance_attestation_ready_for_tag",
            },
            sort_keys=True,
        )
    )
    return 0


def _is_pristine_machine_draft(
    path: Path,
    record: Mapping[str, Any],
    *,
    snapshot: RoadmapSnapshot | None = None,
    person_id: str | None = None,
) -> bool:
    """Return true only for an unsigned record with no human-authored decision."""

    name = path.name
    if name == "delivery-forecast.aggregation-registry.json":
        return record == aggregation_method_registry()
    if name == "delivery-forecast.authoring-ledger.json":
        if snapshot is None or person_id is None:
            return False
        expected = build_authoring_ledger(
            snapshot,
            issued_at=_required_string(record, "issued_at_utc"),
            producer_person_id=person_id,
            baseline_observations_digest_value=_required_string(
                record, "baseline_observations_digest"
            ),
            inventory_completed_at=_required_string(record, "inventory_completed_at_utc"),
        )
        return record == expected
    if name == "delivery-forecast.json":
        receipt = _as_object(record.get("acceptance_receipt"), owner="acceptance receipt")
        return (
            record.get("forecast_status") == "proposed"
            and _signature_status(record.get("signature_envelope")) == "pending_human_signature"
            and receipt.get("receipt_status") == "pending_human_acceptance"
            and _signature_status(receipt.get("signature_envelope")) == "pending_human_signature"
            and all(
                _as_object(row, owner="forecast row").get("rebaseline_status")
                == "pending_maintainer_confirmation"
                for row in _as_array(record.get("rows"), owner="forecast rows")
            )
        )
    if name.startswith("kickoff-authorization-"):
        return (
            record.get("authorization_status") == "pending_human_signature"
            and _signature_status(record.get("signature_envelope")) == "pending_human_signature"
        )
    if name.startswith("completion-receipt-"):
        return (
            record.get("receipt_status") == "pending_human_acceptance"
            and record.get("result_commit") is None
            and _signature_status(record.get("signature_envelope")) == "pending_human_signature"
        )
    if name == "governance-bundle.json":
        return (
            record.get("bundle_status") == "pending_human_acceptance"
            and record.get("result_commit") is None
            and _signature_status(record.get("signature_envelope")) == "pending_human_signature"
        )
    return False


def _read_json(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise GovernanceError(f"unable to read {path}: {exc}") from exc
    if len(raw) > MAX_GOVERNANCE_JSON_BYTES:
        raise GovernanceError(f"governance JSON exceeds the 8 MiB limit: {path}")
    try:
        payload = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise GovernanceError(f"governance JSON is not UTF-8: {path}") from exc
    if payload.startswith("\ufeff"):
        raise GovernanceError(f"governance JSON must not contain a UTF-8 BOM: {path}")
    return _as_object(strict_json_loads(payload), owner=str(path))


def _read_json_from_commit(
    repository_root: Path, commit: str, relative_path: str
) -> dict[str, Any]:
    if GIT_COMMIT_PATTERN.fullmatch(commit) is None:
        raise GovernanceError("historical closure commit must be a full 40-hex object ID")
    tree_entry = _run_git(repository_root, ["ls-tree", commit, "--", relative_path])
    fields = tree_entry.stdout.split(None, 3)
    if (
        tree_entry.returncode != 0
        or len(fields) < 4
        or fields[0] not in {b"100644", b"100755"}
        or fields[1] != b"blob"
    ):
        raise GovernanceError(f"historical JSON is not a regular Git blob: {relative_path}")
    committed = _run_git(repository_root, ["show", f"{commit}:{relative_path}"])
    if committed.returncode != 0:
        raise GovernanceError(f"unable to read historical JSON: {relative_path}")
    if len(committed.stdout) > MAX_GOVERNANCE_JSON_BYTES:
        raise GovernanceError(f"historical governance JSON exceeds 8 MiB: {relative_path}")
    try:
        payload = committed.stdout.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise GovernanceError(f"historical governance JSON is not UTF-8: {relative_path}") from exc
    if payload.startswith("\ufeff"):
        raise GovernanceError(f"historical governance JSON has a UTF-8 BOM: {relative_path}")
    return _as_object(strict_json_loads(payload), owner=relative_path)


def _historical_governance_json_paths() -> list[str]:
    names = [
        "approval-roster.json",
        "approval-roster.schema.json",
        "baseline-observations.json",
        "baseline-observations.schema.json",
        "completion-receipt-v1-base-01.json",
        "completion-receipt-v1-boot-01.json",
        "delivery-forecast.aggregation-registry.json",
        "delivery-forecast.aggregation-registry.schema.json",
        "delivery-forecast.authoring-ledger.json",
        "delivery-forecast.authoring-ledger.schema.json",
        "delivery-forecast.json",
        "delivery-forecast.schema.json",
        "governance-bundle.json",
        "governance-bundle.schema.json",
        "kickoff-authorization-v1-base-01.json",
        "kickoff-authorization-v1-boot-01.json",
        "kickoff-authorization.schema.json",
        "maintainer-signing-key.json",
        "maintainer-signing-key.schema.json",
        "ticket-completion-receipt.schema.json",
    ]
    return [f"docs/governance/v1/{name}" for name in names]


def _schema_declared_formats(value: object) -> set[str]:
    formats: set[str] = set()
    if isinstance(value, Mapping):
        declared = value.get("format")
        if isinstance(declared, str):
            formats.add(declared)
        for child in value.values():
            formats.update(_schema_declared_formats(child))
    elif isinstance(value, list):
        for child in value:
            formats.update(_schema_declared_formats(child))
    return formats


def _schema_external_references(value: object) -> set[str]:
    references: set[str] = set()
    if isinstance(value, Mapping):
        for keyword in ("$ref", "$dynamicRef"):
            reference = value.get(keyword)
            if isinstance(reference, str) and not reference.startswith("#"):
                references.add(reference)
        for child in value.values():
            references.update(_schema_external_references(child))
    elif isinstance(value, list):
        for child in value:
            references.update(_schema_external_references(child))
    return references


def _schema_canonical_utc(value: object) -> bool:
    if not isinstance(value, str):
        return True
    if UTC_PATTERN.fullmatch(value) is None:
        return False
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() == timedelta(0)


def _schema_absolute_uri(value: object) -> bool:
    if not isinstance(value, str):
        return True
    if not value or any(character.isspace() or ord(character) < 0x20 for character in value):
        return False
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        return False
    if (
        re.fullmatch(r"[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+", value) is None
        or re.search(r"%(?![0-9A-Fa-f]{2})", value) is not None
    ):
        return False
    try:
        parsed = urlsplit(value)
        _ = parsed.port
        hostname = parsed.hostname
    except ValueError:
        return False
    if re.fullmatch(r"[A-Za-z][A-Za-z0-9+.-]*", parsed.scheme) is None:
        return False
    return parsed.scheme not in {"http", "https"} or bool(parsed.netloc and hostname)


def _closed_schema_format_checker(schema: Mapping[str, Any]) -> jsonschema.FormatChecker:
    supported = {"date-time", "uri"}
    unexpected = _schema_declared_formats(schema) - supported
    if unexpected:
        raise GovernanceError(
            "governance schema declares unsupported formats: "
            + ", ".join(sorted(unexpected, key=_utf8_sort_key))
        )
    checker = jsonschema.FormatChecker(formats=[])
    checkers = cast(dict[str, tuple[Any, tuple[type[BaseException], ...]]], checker.checkers)
    checkers["date-time"] = (_schema_canonical_utc, ())
    checkers["uri"] = (_schema_absolute_uri, ())
    return checker


def _validate_json_schema(
    instance: Mapping[str, Any], schema: Mapping[str, Any], *, owner: str
) -> None:
    external_references = _schema_external_references(schema)
    if external_references:
        raise GovernanceError(
            f"{owner} schema contains nonlocal references: "
            + ", ".join(sorted(external_references, key=_utf8_sort_key))
        )
    try:
        jsonschema.Draft202012Validator.check_schema(schema)
        validator = jsonschema.Draft202012Validator(
            schema, format_checker=_closed_schema_format_checker(schema)
        )
        error = next(iter(validator.iter_errors(instance)), None)
    except jsonschema.SchemaError as exc:
        raise GovernanceError(f"{owner} schema is invalid: {exc.message}") from exc
    if error is not None:
        location = "/".join(str(part) for part in error.absolute_path) or "$"
        raise GovernanceError(f"{owner} schema validation failed at {location}: {error.message}")


def _governance_root(repository_root: Path, value: str | Path) -> Path:
    root = Path(value).resolve()
    if root != (repository_root.resolve() / "docs/governance/v1").resolve():
        raise GovernanceError("S1 governance directory must be docs/governance/v1")
    return root


def _validate_signed_predecessors(
    snapshot: RoadmapSnapshot,
    *,
    repository_root: Path,
    governance_root: Path,
    validation_time: datetime,
) -> dict[str, Any]:
    roster = _read_json(governance_root / "approval-roster.json")
    roster_schema = _read_json(governance_root / "approval-roster.schema.json")
    roster_digest, person_id = validate_approval_roster(
        snapshot, roster, roster_schema, allow_pending=False
    )
    signing_key = _read_json(governance_root / "maintainer-signing-key.json")
    validate_maintainer_signing_key(
        signing_key,
        _read_json(governance_root / "maintainer-signing-key.schema.json"),
        expected_person_id=person_id,
        allow_pending=False,
    )
    baseline = _read_json(governance_root / "baseline-observations.json")
    validate_baseline_observations(
        snapshot,
        baseline,
        _read_json(governance_root / "baseline-observations.schema.json"),
        repository_root=repository_root,
    )
    kickoff_schema = _read_json(governance_root / "kickoff-authorization.schema.json")
    kickoffs: dict[str, dict[str, Any]] = {}
    for ticket_id in ("V1-BOOT-01", "V1-BASE-01"):
        kickoff = _read_json(governance_root / f"kickoff-authorization-{ticket_id.lower()}.json")
        validate_kickoff_authorization(
            snapshot,
            kickoff,
            kickoff_schema,
            expected_ticket_id=ticket_id,
            expected_roster_digest=roster_digest,
            expected_person_id=person_id,
            allow_pending=False,
            validation_time=validation_time,
        )
        kickoffs[ticket_id] = kickoff
    registry = _read_json(governance_root / "delivery-forecast.aggregation-registry.json")
    registry_schema = _read_json(
        governance_root / "delivery-forecast.aggregation-registry.schema.json"
    )
    _validate_json_schema(registry, registry_schema, owner="aggregation method registry")
    _resolve_aggregation_method(registry)
    ledger = _read_json(governance_root / "delivery-forecast.authoring-ledger.json")
    validate_authoring_ledger(
        snapshot,
        ledger,
        _read_json(governance_root / "delivery-forecast.authoring-ledger.schema.json"),
        expected_person_id=person_id,
        baseline_observations=baseline,
    )
    forecast = _read_json(governance_root / "delivery-forecast.json")
    validate_forecast(
        snapshot,
        ledger,
        registry,
        forecast,
        _read_json(governance_root / "delivery-forecast.schema.json"),
        expected_person_id=person_id,
        approval_roster_digest_value=roster_digest,
        allow_pending=False,
        commitment_time=validation_time,
    )
    return {
        "roster": roster,
        "roster_digest": roster_digest,
        "person_id": person_id,
        "signing_key": signing_key,
        "baseline": baseline,
        "kickoffs": kickoffs,
        "registry": registry,
        "ledger": ledger,
        "forecast": forecast,
    }


def _predecessor_source_paths(governance_root: Path) -> list[Path]:
    names = [
        "approval-roster.json",
        "approval-roster.schema.json",
        "baseline-observations.json",
        "baseline-observations.schema.json",
        "delivery-forecast.aggregation-registry.json",
        "delivery-forecast.aggregation-registry.schema.json",
        "delivery-forecast.authoring-ledger.json",
        "delivery-forecast.authoring-ledger.schema.json",
        "delivery-forecast.json",
        "delivery-forecast.schema.json",
        "kickoff-authorization-v1-base-01.json",
        "kickoff-authorization-v1-boot-01.json",
        "kickoff-authorization.schema.json",
        "maintainer-signing-key.json",
        "maintainer-signing-key.schema.json",
    ]
    return [governance_root / name for name in names]


@_guard_acceptance_reader
def acceptance_decision_template(args: argparse.Namespace) -> int:
    """Export a local-only, nonauthorizing human-decision worksheet."""

    repository_root = Path(cast(str, args.repository_root)).resolve()
    governance_root = _governance_root(repository_root, cast(str, args.governance_dir))
    output = _private_acceptance_path(
        repository_root,
        cast(str, args.output),
        owner="acceptance decision worksheet",
        must_exist=False,
    )
    roadmap = Path(cast(str, args.roadmap))
    validate_local_only_roadmap(repository_root, roadmap)
    snapshot = load_roadmap(roadmap)
    roster = _read_json(governance_root / "approval-roster.json")
    roster_digest, person_id = validate_approval_roster(
        snapshot,
        roster,
        _read_json(governance_root / "approval-roster.schema.json"),
        allow_pending=True,
    )
    signing_key = _read_json(governance_root / "maintainer-signing-key.json")
    validate_maintainer_signing_key(
        signing_key,
        _read_json(governance_root / "maintainer-signing-key.schema.json"),
        expected_person_id=person_id,
        allow_pending=True,
    )
    baseline = _read_json(governance_root / "baseline-observations.json")
    validate_baseline_observations(
        snapshot,
        baseline,
        _read_json(governance_root / "baseline-observations.schema.json"),
        repository_root=repository_root,
    )
    ledger = _read_json(governance_root / "delivery-forecast.authoring-ledger.json")
    validate_authoring_ledger(
        snapshot,
        ledger,
        _read_json(governance_root / "delivery-forecast.authoring-ledger.schema.json"),
        expected_person_id=person_id,
        baseline_observations=baseline,
    )
    template = {
        "format": "agent-assure-s1-human-decisions/1",
        "affirmations": {
            "accepts_no_independent_review": False,
            "accepts_unattested_host_utc": False,
            "confirms_private_key_control": False,
            "reviewed_conflicts_and_capacity": False,
            "reviewed_every_ticket_row": False,
            "reviewed_every_release_occurrence": False,
        },
        "approval_roster": roster,
        "maintainer_signing_key": signing_key,
        "authoring_ledger": ledger,
        "current_approval_roster_digest": roster_digest,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    _write_json(output, template)
    print(
        json.dumps(
            {
                "authorization_effect": "none",
                "output": output.relative_to(repository_root).as_posix(),
                "result": "human_decision_template_created",
            },
            sort_keys=True,
        )
    )
    return 0


def _load_human_decisions(path: Path) -> dict[str, Any]:
    decisions = _read_json(path)
    required = {
        "format",
        "affirmations",
        "approval_roster",
        "maintainer_signing_key",
        "authoring_ledger",
        "current_approval_roster_digest",
    }
    if set(decisions) != required or decisions.get("format") != (
        "agent-assure-s1-human-decisions/1"
    ):
        raise GovernanceError("human decision worksheet has missing or unexpected fields")
    affirmations = _as_object(decisions.get("affirmations"), owner="human affirmations")
    expected_affirmations = {
        "accepts_no_independent_review",
        "accepts_unattested_host_utc",
        "confirms_private_key_control",
        "reviewed_conflicts_and_capacity",
        "reviewed_every_ticket_row",
        "reviewed_every_release_occurrence",
    }
    if set(affirmations) != expected_affirmations or any(
        affirmations.get(key) is not True for key in expected_affirmations
    ):
        raise GovernanceError("every explicit human affirmation must be true")
    return decisions


def _prepare_predecessor_plan(
    args: argparse.Namespace,
    *,
    repository_root: Path,
    governance_root: Path,
    snapshot: RoadmapSnapshot,
    plan_directory: Path,
) -> dict[str, Any]:
    decisions_path = _private_acceptance_path(
        repository_root,
        cast(str, args.decisions),
        owner="human decision worksheet",
        must_exist=True,
    )
    decisions = _load_human_decisions(decisions_path)
    roster = _as_object(decisions.get("approval_roster"), owner="approved roster")
    roster_digest, person_id = validate_approval_roster(
        snapshot,
        roster,
        _read_json(governance_root / "approval-roster.schema.json"),
        allow_pending=False,
    )
    if decisions.get("current_approval_roster_digest") != approval_roster_digest(
        _read_json(governance_root / "approval-roster.json")
    ):
        raise GovernanceError("human decision worksheet was based on another roster draft")
    signing_key = copy.deepcopy(
        _as_object(decisions.get("maintainer_signing_key"), owner="confirmed signing key")
    )
    signing_key["record_digest"] = domain_digest(
        SIGNING_KEY_DOMAIN, _record_projection(signing_key, "record_digest")
    )
    validate_maintainer_signing_key(
        signing_key,
        _read_json(governance_root / "maintainer-signing-key.schema.json"),
        expected_person_id=person_id,
        allow_pending=False,
    )
    baseline = _read_json(governance_root / "baseline-observations.json")
    validate_baseline_observations(
        snapshot,
        baseline,
        _read_json(governance_root / "baseline-observations.schema.json"),
        repository_root=repository_root,
    )
    ledger = copy.deepcopy(
        _as_object(decisions.get("authoring_ledger"), owner="confirmed authoring ledger")
    )
    ledger["ledger_digest"] = _ledger_digest(ledger)
    validate_authoring_ledger(
        snapshot,
        ledger,
        _read_json(governance_root / "delivery-forecast.authoring-ledger.schema.json"),
        expected_person_id=person_id,
        baseline_observations=baseline,
    )
    registry = _read_json(governance_root / "delivery-forecast.aggregation-registry.json")
    _validate_json_schema(
        registry,
        _read_json(governance_root / "delivery-forecast.aggregation-registry.schema.json"),
        owner="aggregation method registry",
    )
    issued_at = cast(str, args.issued_at)
    valid_until = cast(str, args.valid_until)
    signed_at = cast(str, args.signed_at)
    issue_time, expiry_time = _validate_validity_interval(
        issued_at, valid_until, owner="acceptance predecessor plan"
    )
    signature_time = _parse_utc(signed_at, owner="--signed-at")
    if not issue_time <= signature_time < expiry_time:
        raise GovernanceError("predecessor signature time is outside the validity interval")
    kickoffs = {
        ticket_id: build_kickoff_authorization(
            snapshot,
            ticket_id=ticket_id,
            roster_digest=roster_digest,
            person_id=person_id,
            issued_at=issued_at,
            valid_until=valid_until,
            status="authorized",
        )
        for ticket_id in ("V1-BOOT-01", "V1-BASE-01")
    }
    forecast = build_forecast(
        snapshot,
        ledger,
        registry,
        issued_at=issued_at,
        valid_until=valid_until,
        producer_person_id=person_id,
        approval_roster_digest_value=roster_digest,
        requested_status="accepted",
        trusted_time_basis=cast(str, args.trusted_time_basis),
    )
    targets = {
        "docs/governance/v1/approval-roster.json": roster,
        "docs/governance/v1/maintainer-signing-key.json": signing_key,
        "docs/governance/v1/delivery-forecast.authoring-ledger.json": ledger,
        "docs/governance/v1/kickoff-authorization-v1-base-01.json": kickoffs["V1-BASE-01"],
        "docs/governance/v1/kickoff-authorization-v1-boot-01.json": kickoffs["V1-BOOT-01"],
        "docs/governance/v1/delivery-forecast.json": forecast,
    }
    claim_specs = [
        (
            "kickoff-base",
            "docs/governance/v1/kickoff-authorization-v1-base-01.json",
            ["signature_envelope"],
            signed_at,
        ),
        (
            "kickoff-boot",
            "docs/governance/v1/kickoff-authorization-v1-boot-01.json",
            ["signature_envelope"],
            signed_at,
        ),
        (
            "forecast-producer",
            "docs/governance/v1/delivery-forecast.json",
            ["signature_envelope"],
            signed_at,
        ),
        (
            "forecast-acceptance",
            "docs/governance/v1/delivery-forecast.json",
            ["acceptance_receipt", "signature_envelope"],
            signed_at,
        ),
    ]
    source_paths = [decisions_path, *_predecessor_source_paths(governance_root)]
    return _write_acceptance_plan(
        repository_root,
        plan_directory,
        phase="predecessors",
        source_paths=source_paths,
        targets=targets,
        claim_specs=claim_specs,
    )


def _result_artifact_inventory(repository_root: Path, result_commit: str) -> list[dict[str, Any]]:
    if GIT_COMMIT_PATTERN.fullmatch(result_commit) is None:
        raise GovernanceError("S1 result commit must be a full 40-hex object ID")
    receipt_paths = {
        "docs/governance/v1/completion-receipt-v1-base-01.json",
        "docs/governance/v1/completion-receipt-v1-boot-01.json",
    }
    inventory = [
        _artifact_evidence_from_commit(
            repository_root,
            result_commit,
            path,
            kind=kind,
        )
        for path, kind in _bundle_inventory_paths()
        if path not in receipt_paths
    ]
    _validate_s1_commit_scope(
        repository_root,
        base_commit=PINNED_BASE_COMMIT,
        result_commit=result_commit,
        inventory=inventory,
    )
    return inventory


def _prepare_completion_plan(
    args: argparse.Namespace,
    *,
    repository_root: Path,
    governance_root: Path,
    snapshot: RoadmapSnapshot,
    plan_directory: Path,
) -> dict[str, Any]:
    validation_time = _parse_utc(cast(str, args.commitment_time), owner="--commitment-time")
    context = _validate_signed_predecessors(
        snapshot,
        repository_root=repository_root,
        governance_root=governance_root,
        validation_time=validation_time,
    )
    result_commit = cast(str, args.result_commit)
    result_inventory = _result_artifact_inventory(repository_root, result_commit)
    result_by_path = {cast(str, item["path"]): item for item in result_inventory}
    issued_at = cast(str, args.issued_at)
    valid_until = cast(str, args.valid_until)
    signed_at = cast(str, args.signed_at)
    issue_time, expiry_time = _validate_validity_interval(
        issued_at, valid_until, owner="acceptance completion plan"
    )
    signature_time = _parse_utc(signed_at, owner="--signed-at")
    if not issue_time <= signature_time < expiry_time or signature_time > validation_time:
        raise GovernanceError("completion signature time is outside the trusted interval")
    kickoffs = cast(dict[str, dict[str, Any]], context["kickoffs"])
    receipts: dict[str, dict[str, Any]] = {}
    for ticket_id in ("V1-BASE-01", "V1-BOOT-01"):
        report_path = f"docs/governance/v1/completion-report-{ticket_id.lower()}.md"
        evidence = [result_by_path[report_path]] + [
            result_by_path[path] for path, _kind in _completion_review_paths(ticket_id)
        ]
        receipt = build_ticket_completion_receipt(
            snapshot,
            repository_root=repository_root,
            ticket_id=ticket_id,
            roster_digest=cast(str, context["roster_digest"]),
            kickoff_authorization_digest=_required_string(
                kickoffs[ticket_id], "authorization_digest"
            ),
            person_id=cast(str, context["person_id"]),
            base_commit=PINNED_BASE_COMMIT,
            result_commit=result_commit,
            issued_at=issued_at,
            valid_until=valid_until,
            status="accepted_for_development",
            artifact_evidence_override=evidence,
        )
        receipts[ticket_id] = receipt
    targets = {
        "docs/governance/v1/completion-receipt-v1-base-01.json": receipts["V1-BASE-01"],
        "docs/governance/v1/completion-receipt-v1-boot-01.json": receipts["V1-BOOT-01"],
    }
    claim_specs = [
        (
            "completion-base",
            "docs/governance/v1/completion-receipt-v1-base-01.json",
            ["signature_envelope"],
            signed_at,
        ),
        (
            "completion-boot",
            "docs/governance/v1/completion-receipt-v1-boot-01.json",
            ["signature_envelope"],
            signed_at,
        ),
    ]
    source_paths = [
        *_predecessor_source_paths(governance_root),
        governance_root / "ticket-completion-receipt.schema.json",
        governance_root / "completion-receipt-v1-base-01.json",
        governance_root / "completion-receipt-v1-boot-01.json",
    ]
    return _write_acceptance_plan(
        repository_root,
        plan_directory,
        phase="completions",
        source_paths=source_paths,
        targets=targets,
        claim_specs=claim_specs,
        result_commit=result_commit,
    )


def _load_signed_completion_receipts(
    snapshot: RoadmapSnapshot,
    *,
    repository_root: Path,
    governance_root: Path,
    context: Mapping[str, Any],
    validation_time: datetime,
) -> dict[str, dict[str, Any]]:
    schema = _read_json(governance_root / "ticket-completion-receipt.schema.json")
    kickoffs = cast(dict[str, dict[str, Any]], context["kickoffs"])
    receipts: dict[str, dict[str, Any]] = {}
    for ticket_id in ("V1-BASE-01", "V1-BOOT-01"):
        receipt = _read_json(governance_root / f"completion-receipt-{ticket_id.lower()}.json")
        validate_ticket_completion_receipt(
            snapshot,
            receipt,
            schema,
            repository_root=repository_root,
            expected_ticket_id=ticket_id,
            expected_roster_digest=cast(str, context["roster_digest"]),
            expected_kickoff_digest=_required_string(kickoffs[ticket_id], "authorization_digest"),
            expected_person_id=cast(str, context["person_id"]),
            expected_base_commit=PINNED_BASE_COMMIT,
            allow_pending=False,
            validation_time=validation_time,
            expected_kickoff_record=kickoffs[ticket_id],
        )
        receipts[ticket_id] = receipt
    return receipts


def _prepare_bundle_plan(
    args: argparse.Namespace,
    *,
    repository_root: Path,
    governance_root: Path,
    snapshot: RoadmapSnapshot,
    plan_directory: Path,
) -> dict[str, Any]:
    validation_time = _parse_utc(cast(str, args.commitment_time), owner="--commitment-time")
    context = _validate_signed_predecessors(
        snapshot,
        repository_root=repository_root,
        governance_root=governance_root,
        validation_time=validation_time,
    )
    receipts = _load_signed_completion_receipts(
        snapshot,
        repository_root=repository_root,
        governance_root=governance_root,
        context=context,
        validation_time=validation_time,
    )
    result_commits = {receipt.get("result_commit") for receipt in receipts.values()}
    if len(result_commits) != 1 or None in result_commits:
        raise GovernanceError("signed completion receipts do not bind one result commit")
    result_commit = cast(str, next(iter(result_commits)))
    nonreceipt_inventory = _result_artifact_inventory(repository_root, result_commit)
    inventory = [*nonreceipt_inventory]
    for path, kind in _bundle_inventory_paths():
        if kind != "completion_receipt":
            continue
        inventory.append(_artifact_evidence(repository_root, path, kind=kind))
    inventory = _validated_artifact_evidence(
        inventory,
        _bundle_inventory_paths(),
        owner="accepted S1 bundle plan",
    )
    issued_at = cast(str, args.issued_at)
    valid_until = cast(str, args.valid_until)
    signed_at = cast(str, args.signed_at)
    issue_time, expiry_time = _validate_validity_interval(
        issued_at, valid_until, owner="acceptance bundle plan"
    )
    signature_time = _parse_utc(signed_at, owner="--signed-at")
    if not issue_time <= signature_time < expiry_time or signature_time > validation_time:
        raise GovernanceError("bundle signature time is outside the trusted interval")
    bundle = build_governance_bundle(
        snapshot,
        repository_root=repository_root,
        roster=cast(Mapping[str, Any], context["roster"]),
        kickoff_records=cast(Mapping[str, Mapping[str, Any]], context["kickoffs"]),
        completion_receipts=receipts,
        forecast=cast(Mapping[str, Any], context["forecast"]),
        signing_key=cast(Mapping[str, Any], context["signing_key"]),
        baseline_observations=cast(Mapping[str, Any], context["baseline"]),
        person_id=cast(str, context["person_id"]),
        base_commit=PINNED_BASE_COMMIT,
        issued_at=issued_at,
        valid_until=valid_until,
        status="accepted_for_development",
        artifact_inventory_override=inventory,
    )
    bundle_path = "docs/governance/v1/governance-bundle.json"
    return _write_acceptance_plan(
        repository_root,
        plan_directory,
        phase="bundle",
        source_paths=[
            *_predecessor_source_paths(governance_root),
            governance_root / "ticket-completion-receipt.schema.json",
            governance_root / "completion-receipt-v1-base-01.json",
            governance_root / "completion-receipt-v1-boot-01.json",
            governance_root / "governance-bundle.json",
            governance_root / "governance-bundle.schema.json",
        ],
        targets={bundle_path: bundle},
        claim_specs=[("governance-bundle", bundle_path, ["signature_envelope"], signed_at)],
        result_commit=result_commit,
    )


@_guard_acceptance_reader
def acceptance_prepare(args: argparse.Namespace) -> int:
    """Build an immutable local signing plan without accessing a private key."""

    repository_root = Path(cast(str, args.repository_root)).resolve()
    governance_root = _governance_root(repository_root, cast(str, args.governance_dir))
    plan_directory = _private_acceptance_path(
        repository_root,
        cast(str, args.plan_dir),
        owner="acceptance signature plan",
        must_exist=False,
    )
    roadmap = Path(cast(str, args.roadmap))
    validate_local_only_roadmap(repository_root, roadmap)
    snapshot = load_roadmap(roadmap)
    phase = cast(str, args.phase)
    if phase == "predecessors":
        if args.decisions is None:
            raise GovernanceError("predecessor preparation requires --decisions")
        if args.commitment_time is not None or args.result_commit is not None:
            raise GovernanceError(
                "predecessor preparation does not accept --commitment-time or --result-commit"
            )
        plan = _prepare_predecessor_plan(
            args,
            repository_root=repository_root,
            governance_root=governance_root,
            snapshot=snapshot,
            plan_directory=plan_directory,
        )
    elif phase == "completions":
        if args.decisions is not None:
            raise GovernanceError("completion preparation does not accept --decisions")
        if args.commitment_time is None or args.result_commit is None:
            raise GovernanceError(
                "completion preparation requires --commitment-time and --result-commit"
            )
        plan = _prepare_completion_plan(
            args,
            repository_root=repository_root,
            governance_root=governance_root,
            snapshot=snapshot,
            plan_directory=plan_directory,
        )
    elif phase == "bundle":
        if args.decisions is not None or args.result_commit is not None:
            raise GovernanceError("bundle preparation does not accept decisions/result override")
        if args.commitment_time is None:
            raise GovernanceError("bundle preparation requires --commitment-time")
        plan = _prepare_bundle_plan(
            args,
            repository_root=repository_root,
            governance_root=governance_root,
            snapshot=snapshot,
            plan_directory=plan_directory,
        )
    else:
        raise GovernanceError(f"unsupported acceptance phase: {phase}")
    print(
        json.dumps(
            {
                "authorization_effect": "none",
                "claim_count": len(_as_array(plan.get("claims"), owner="claims")),
                "phase": phase,
                "plan_digest": plan["plan_digest"],
                "plan_dir": plan_directory.relative_to(repository_root).as_posix(),
                "result": "signature_plan_created",
            },
            sort_keys=True,
        )
    )
    return 0


def _signed_envelope_time(
    record: Mapping[str, Any], path: Sequence[str], *, owner: str
) -> datetime:
    envelope = _nested_object(record, path, owner=f"{owner} signature envelope")
    signed_at = envelope.get("signed_at_utc")
    if not isinstance(signed_at, str):
        raise GovernanceError(f"{owner} lacks a signed_at_utc value")
    return _parse_utc(signed_at, owner=f"{owner} signed_at_utc")


def _validate_predecessor_plan_targets(
    snapshot: RoadmapSnapshot,
    targets: Mapping[str, Mapping[str, Any]],
    *,
    repository_root: Path,
    governance_root: Path,
    validation_time: datetime,
) -> None:
    expected_paths = {
        "docs/governance/v1/approval-roster.json",
        "docs/governance/v1/maintainer-signing-key.json",
        "docs/governance/v1/delivery-forecast.authoring-ledger.json",
        "docs/governance/v1/kickoff-authorization-v1-base-01.json",
        "docs/governance/v1/kickoff-authorization-v1-boot-01.json",
        "docs/governance/v1/delivery-forecast.json",
    }
    if set(targets) != expected_paths:
        raise GovernanceError("predecessor plan target set is not exact")
    roster = targets["docs/governance/v1/approval-roster.json"]
    roster_digest, person_id = validate_approval_roster(
        snapshot,
        roster,
        _read_json(governance_root / "approval-roster.schema.json"),
        allow_pending=False,
    )
    signing_key = targets["docs/governance/v1/maintainer-signing-key.json"]
    validate_maintainer_signing_key(
        signing_key,
        _read_json(governance_root / "maintainer-signing-key.schema.json"),
        expected_person_id=person_id,
        allow_pending=False,
    )
    baseline = _read_json(governance_root / "baseline-observations.json")
    validate_baseline_observations(
        snapshot,
        baseline,
        _read_json(governance_root / "baseline-observations.schema.json"),
        repository_root=repository_root,
    )
    ledger = targets["docs/governance/v1/delivery-forecast.authoring-ledger.json"]
    validate_authoring_ledger(
        snapshot,
        ledger,
        _read_json(governance_root / "delivery-forecast.authoring-ledger.schema.json"),
        expected_person_id=person_id,
        baseline_observations=baseline,
    )
    registry = _read_json(governance_root / "delivery-forecast.aggregation-registry.json")
    registry_schema = _read_json(
        governance_root / "delivery-forecast.aggregation-registry.schema.json"
    )
    _validate_json_schema(registry, registry_schema, owner="aggregation method registry")
    kickoffs: dict[str, Mapping[str, Any]] = {}
    kickoff_schema = _read_json(governance_root / "kickoff-authorization.schema.json")
    for ticket_id in ("V1-BASE-01", "V1-BOOT-01"):
        kickoff = targets[f"docs/governance/v1/kickoff-authorization-{ticket_id.lower()}.json"]
        validate_kickoff_authorization(
            snapshot,
            kickoff,
            kickoff_schema,
            expected_ticket_id=ticket_id,
            expected_roster_digest=roster_digest,
            expected_person_id=person_id,
            allow_pending=False,
            validation_time=validation_time,
        )
        kickoffs[ticket_id] = kickoff
    forecast = targets["docs/governance/v1/delivery-forecast.json"]
    validate_forecast(
        snapshot,
        ledger,
        registry,
        forecast,
        _read_json(governance_root / "delivery-forecast.schema.json"),
        expected_person_id=person_id,
        approval_roster_digest_value=roster_digest,
        allow_pending=False,
        commitment_time=validation_time,
    )
    if _signed_envelope_time(
        forecast, ["signature_envelope"], owner="forecast producer"
    ) < _signed_envelope_time(kickoffs["V1-BASE-01"], ["signature_envelope"], owner="BASE kickoff"):
        raise GovernanceError("forecast producer signature predates the BASE kickoff")


def _validate_completion_plan_targets(
    snapshot: RoadmapSnapshot,
    targets: Mapping[str, Mapping[str, Any]],
    *,
    repository_root: Path,
    governance_root: Path,
    validation_time: datetime,
    result_commit: str,
) -> None:
    expected_paths = {
        "docs/governance/v1/completion-receipt-v1-base-01.json",
        "docs/governance/v1/completion-receipt-v1-boot-01.json",
    }
    if set(targets) != expected_paths:
        raise GovernanceError("completion plan target set is not exact")
    context = _validate_signed_predecessors(
        snapshot,
        repository_root=repository_root,
        governance_root=governance_root,
        validation_time=validation_time,
    )
    kickoffs = cast(dict[str, dict[str, Any]], context["kickoffs"])
    schema = _read_json(governance_root / "ticket-completion-receipt.schema.json")
    receipts: dict[str, Mapping[str, Any]] = {}
    for ticket_id in ("V1-BASE-01", "V1-BOOT-01"):
        receipt = targets[f"docs/governance/v1/completion-receipt-{ticket_id.lower()}.json"]
        if receipt.get("result_commit") != result_commit:
            raise GovernanceError("completion plan receipt changed its result commit")
        validate_ticket_completion_receipt(
            snapshot,
            receipt,
            schema,
            repository_root=repository_root,
            expected_ticket_id=ticket_id,
            expected_roster_digest=cast(str, context["roster_digest"]),
            expected_kickoff_digest=_required_string(kickoffs[ticket_id], "authorization_digest"),
            expected_person_id=cast(str, context["person_id"]),
            expected_base_commit=PINNED_BASE_COMMIT,
            allow_pending=False,
            validation_time=validation_time,
            expected_kickoff_record=kickoffs[ticket_id],
        )
        receipts[ticket_id] = receipt
    if _signed_envelope_time(
        receipts["V1-BOOT-01"], ["signature_envelope"], owner="BOOT completion"
    ) < _signed_envelope_time(
        receipts["V1-BASE-01"], ["signature_envelope"], owner="BASE completion"
    ):
        raise GovernanceError("completion signatures violate the canonical BASE/BOOT close order")
    _result_artifact_inventory(repository_root, result_commit)


def _validate_bundle_plan_targets(
    snapshot: RoadmapSnapshot,
    targets: Mapping[str, Mapping[str, Any]],
    *,
    repository_root: Path,
    governance_root: Path,
    validation_time: datetime,
    result_commit: str,
) -> None:
    bundle_path = "docs/governance/v1/governance-bundle.json"
    if set(targets) != {bundle_path}:
        raise GovernanceError("bundle plan target set is not exact")
    context = _validate_signed_predecessors(
        snapshot,
        repository_root=repository_root,
        governance_root=governance_root,
        validation_time=validation_time,
    )
    receipts = _load_signed_completion_receipts(
        snapshot,
        repository_root=repository_root,
        governance_root=governance_root,
        context=context,
        validation_time=validation_time,
    )
    bundle = targets[bundle_path]
    if bundle.get("result_commit") != result_commit:
        raise GovernanceError("bundle plan changed its result commit")
    validate_governance_bundle(
        snapshot,
        bundle,
        _read_json(governance_root / "governance-bundle.schema.json"),
        repository_root=repository_root,
        roster=cast(Mapping[str, Any], context["roster"]),
        kickoff_records=cast(Mapping[str, Mapping[str, Any]], context["kickoffs"]),
        completion_receipts=receipts,
        forecast=cast(Mapping[str, Any], context["forecast"]),
        signing_key=cast(Mapping[str, Any], context["signing_key"]),
        baseline_observations=cast(Mapping[str, Any], context["baseline"]),
        expected_person_id=cast(str, context["person_id"]),
        expected_base_commit=PINNED_BASE_COMMIT,
        allow_pending=False,
        validation_time=validation_time,
        require_bundle_on_disk=False,
        require_predecessors_on_disk=True,
        require_closure=False,
    )


def acceptance_import(args: argparse.Namespace) -> int:
    """Verify SSHSIG files and perform one journaled, serialized phase install."""

    repository_root = Path(cast(str, args.repository_root)).resolve()
    governance_root = _governance_root(repository_root, cast(str, args.governance_dir))
    plan_directory = _private_acceptance_path(
        repository_root,
        cast(str, args.plan_dir),
        owner="acceptance signature plan",
        must_exist=True,
    )
    if not plan_directory.is_dir():
        raise GovernanceError("acceptance signature plan must be a directory")
    roadmap = Path(cast(str, args.roadmap))
    validate_local_only_roadmap(repository_root, roadmap)
    snapshot = load_roadmap(roadmap)
    validation_time = _parse_utc(cast(str, args.commitment_time), owner="--commitment-time")
    plan = _read_acceptance_plan(plan_directory)
    expected_plan_digest = cast(str, args.expected_plan_digest)
    if SHA256_PATTERN.fullmatch(expected_plan_digest) is None:
        raise GovernanceError("--expected-plan-digest must be a canonical SHA-256 digest")
    if plan.get("plan_digest") != expected_plan_digest:
        raise GovernanceError(
            "acceptance plan digest differs from the human-confirmed expected digest"
        )
    raw_plan_targets = _as_array(plan.get("targets"), owner="acceptance plan targets")
    planned_target_paths = {
        _required_string(_as_object(item, owner="acceptance plan target"), "path")
        for item in raw_plan_targets
    }
    if len(planned_target_paths) != len(raw_plan_targets):
        raise GovernanceError("acceptance plan repeats a target path")
    expected_prior_evidence = _acceptance_plan_target_prior_evidence(
        plan,
        expected_target_paths=planned_target_paths,
    )
    targets = _materialize_signed_plan_targets(plan_directory, plan)
    expected_next_payloads = {
        relative: _render_json_bytes(record) for relative, record in targets.items()
    }
    with _acceptance_import_lock(repository_root):
        _recover_acceptance_transaction(
            repository_root,
            expected_plan_digest=expected_plan_digest,
            expected_prior_evidence=expected_prior_evidence,
            expected_next_payloads=expected_next_payloads,
        )
    _verify_plan_sources(repository_root, plan)
    phase = _required_string(plan, "phase")
    result_commit_value = plan.get("result_commit")
    if phase == "predecessors":
        if result_commit_value is not None:
            raise GovernanceError("predecessor plan unexpectedly binds a result commit")
        _validate_predecessor_plan_targets(
            snapshot,
            targets,
            repository_root=repository_root,
            governance_root=governance_root,
            validation_time=validation_time,
        )
    elif phase == "completions":
        if not isinstance(result_commit_value, str):
            raise GovernanceError("completion plan lacks a result commit")
        _validate_completion_plan_targets(
            snapshot,
            targets,
            repository_root=repository_root,
            governance_root=governance_root,
            validation_time=validation_time,
            result_commit=result_commit_value,
        )
    elif phase == "bundle":
        if not isinstance(result_commit_value, str):
            raise GovernanceError("bundle plan lacks a result commit")
        _validate_bundle_plan_targets(
            snapshot,
            targets,
            repository_root=repository_root,
            governance_root=governance_root,
            validation_time=validation_time,
            result_commit=result_commit_value,
        )
    else:
        raise GovernanceError(f"unsupported acceptance plan phase: {phase}")
    output_records: dict[Path, Mapping[str, Any]] = {}
    for relative, record in targets.items():
        path = _resolve_repository_path_without_links(
            repository_root, relative, owner="acceptance plan target"
        )
        try:
            path.relative_to(governance_root)
        except ValueError as exc:
            raise GovernanceError("acceptance plan target leaves the governance directory") from exc
        output_records[path] = record
    with _acceptance_import_lock(repository_root):
        _recover_acceptance_transaction(
            repository_root,
            expected_plan_digest=expected_plan_digest,
            expected_prior_evidence=expected_prior_evidence,
            expected_next_payloads=expected_next_payloads,
        )
        _verify_plan_sources(repository_root, plan)
        _install_acceptance_targets(
            repository_root,
            output_records,
            plan_digest=expected_plan_digest,
            expected_prior_evidence=expected_prior_evidence,
        )
    installed_records = {
        relative: {
            "sha256": raw_digest(_render_json_bytes(record)),
            "size_bytes": len(_render_json_bytes(record)),
        }
        for relative, record in sorted(targets.items(), key=lambda item: _utf8_sort_key(item[0]))
    }
    print(
        json.dumps(
            {
                "authorization_effect": "human-signed_records_installed",
                "installed_records": installed_records,
                "phase": phase,
                "plan_digest": plan["plan_digest"],
                "result": "verified_signatures_imported",
                "target_count": len(targets),
            },
            sort_keys=True,
        )
    )
    return 0


@_guard_acceptance_reader
def acceptance_result_paths(args: argparse.Namespace) -> int:
    """Write the exact NUL-delimited result-commit staging allowlist."""

    repository_root = Path(cast(str, args.repository_root)).resolve()
    governance_root = _governance_root(repository_root, cast(str, args.governance_dir))
    output = _private_acceptance_path(
        repository_root,
        cast(str, args.output),
        owner="result pathspec file",
        must_exist=False,
    )
    roadmap = Path(cast(str, args.roadmap))
    validate_local_only_roadmap(repository_root, roadmap)
    snapshot = load_roadmap(roadmap)
    validation_time = _parse_utc(cast(str, args.commitment_time), owner="--commitment-time")
    _validate_signed_predecessors(
        snapshot,
        repository_root=repository_root,
        governance_root=governance_root,
        validation_time=validation_time,
    )
    excluded = {
        "docs/governance/v1/completion-receipt-v1-base-01.json",
        "docs/governance/v1/completion-receipt-v1-boot-01.json",
    }
    paths = [path for path, _kind in _bundle_inventory_paths() if path not in excluded]
    for relative in paths:
        path = repository_root / relative
        if not path.is_file() or path.is_symlink():
            raise GovernanceError(f"result staging artifact is not a regular file: {relative}")
    payload = b"\x00".join(path.encode("utf-8") for path in paths) + b"\x00"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(payload)
    print(
        json.dumps(
            {
                "authorization_effect": "none",
                "path_count": len(paths),
                "pathspec_sha256": raw_digest(payload),
                "result": "result_pathspec_created",
                "use": (
                    f'git add --pathspec-from-file="{output.relative_to(repository_root)}" '
                    "--pathspec-file-nul"
                ),
            },
            sort_keys=True,
        )
    )
    return 0


@_guard_acceptance_reader
def generate_draft(args: argparse.Namespace) -> int:
    roadmap = Path(cast(str, args.roadmap))
    output = Path(cast(str, args.output))
    repository_root = Path(cast(str, args.repository_root)).resolve()
    if output.resolve() != (repository_root / "docs/governance/v1").resolve():
        raise GovernanceError("S1 governance output must be docs/governance/v1")
    validate_local_only_roadmap(repository_root, roadmap)
    snapshot = load_roadmap(roadmap)
    existing_forecast_path = output / "delivery-forecast.json"
    if existing_forecast_path.is_file():
        existing_forecast = _read_json(existing_forecast_path)
        if existing_forecast.get("forecast_status") == "accepted":
            raise GovernanceError("refusing to overwrite an accepted delivery forecast")
    roster = _read_json(output / "approval-roster.json")
    roster_schema = _read_json(output / "approval-roster.schema.json")
    roster_digest, person_id = validate_approval_roster(
        snapshot, roster, roster_schema, allow_pending=True
    )
    requested_person_id = cast(str, args.person_id)
    if requested_person_id != person_id:
        raise GovernanceError("--person-id differs from the approval roster maintainer")
    baseline = _read_json(output / "baseline-observations.json")
    baseline_schema = _read_json(output / "baseline-observations.schema.json")
    validate_baseline_observations(
        snapshot, baseline, baseline_schema, repository_root=repository_root
    )
    kickoff_schema = _read_json(output / "kickoff-authorization.schema.json")
    kickoff_records: dict[str, dict[str, Any]] = {}
    for ticket_id in ("V1-BOOT-01", "V1-BASE-01"):
        kickoff = build_kickoff_authorization(
            snapshot,
            ticket_id=ticket_id,
            roster_digest=roster_digest,
            person_id=person_id,
            issued_at=cast(str, args.issued_at),
            valid_until=cast(str, args.valid_until),
        )
        validate_kickoff_authorization(
            snapshot,
            kickoff,
            kickoff_schema,
            expected_ticket_id=ticket_id,
            expected_roster_digest=roster_digest,
            expected_person_id=person_id,
            allow_pending=True,
        )
        kickoff_records[ticket_id] = kickoff
    registry = aggregation_method_registry()
    registry_schema = _read_json(output / "delivery-forecast.aggregation-registry.schema.json")
    _validate_json_schema(registry, registry_schema, owner="aggregation method registry")
    ledger = build_authoring_ledger(
        snapshot,
        issued_at=cast(str, args.issued_at),
        producer_person_id=person_id,
        baseline_observations_digest_value=_required_string(baseline, "observations_digest"),
        inventory_completed_at=_required_string(baseline, "inventory_completed_at_utc"),
    )
    ledger_schema = _read_json(output / "delivery-forecast.authoring-ledger.schema.json")
    validate_authoring_ledger(
        snapshot,
        ledger,
        ledger_schema,
        expected_person_id=person_id,
        baseline_observations=baseline,
    )
    forecast = build_forecast(
        snapshot,
        ledger,
        registry,
        issued_at=cast(str, args.issued_at),
        valid_until=cast(str, args.valid_until),
        producer_person_id=person_id,
        approval_roster_digest_value=roster_digest,
        trusted_time_basis=cast(str, args.trusted_time_basis),
    )
    forecast_schema = _read_json(output / "delivery-forecast.schema.json")
    validate_forecast(
        snapshot,
        ledger,
        registry,
        forecast,
        forecast_schema,
        expected_person_id=person_id,
        approval_roster_digest_value=roster_digest,
        allow_pending=True,
    )
    generated_records: dict[Path, Mapping[str, Any]] = {
        output / "delivery-forecast.aggregation-registry.json": registry,
        output / "delivery-forecast.authoring-ledger.json": ledger,
        output / "delivery-forecast.json": forecast,
    }
    for ticket_id, kickoff in kickoff_records.items():
        slug = ticket_id.lower()
        generated_records[output / f"kickoff-authorization-{slug}.json"] = kickoff
    for path, generated in generated_records.items():
        if path.is_file() and _read_json(path) != generated:
            existing = _read_json(path)
            if not (
                bool(args.replace_pristine_drafts)
                and _is_pristine_machine_draft(
                    path,
                    existing,
                    snapshot=snapshot,
                    person_id=person_id,
                )
            ):
                raise GovernanceError(
                    f"refusing to overwrite a differing governance record: {path}"
                )
    _write_json_batch(generated_records)
    print(
        json.dumps(
            {
                "forecast_status": forecast["forecast_status"],
                "roadmap_digest": snapshot.raw_digest,
                "ticket_count": len(snapshot.tickets),
                "occurrence_count": sum(
                    len(value) for value in release_occurrences(snapshot).values()
                ),
                "record_digest": forecast["record_digest"],
            },
            sort_keys=True,
        )
    )
    return 0


@_guard_acceptance_reader
def assemble_draft(args: argparse.Namespace) -> int:
    """Assemble pending completion receipts and the noninstallable S1 object."""

    repository_root = Path(cast(str, args.repository_root)).resolve()
    root = Path(cast(str, args.governance_dir)).resolve()
    if root != (repository_root / "docs/governance/v1").resolve():
        raise GovernanceError("S1 governance directory must be docs/governance/v1")
    roadmap_path = Path(cast(str, args.roadmap))
    validate_local_only_roadmap(repository_root, roadmap_path)
    snapshot = load_roadmap(roadmap_path)
    issued_at = cast(str, args.issued_at)
    valid_until = cast(str, args.valid_until)
    _validate_validity_interval(issued_at, valid_until, owner="S1 assembly")

    for receipt_path in (
        root / "completion-receipt-v1-boot-01.json",
        root / "completion-receipt-v1-base-01.json",
    ):
        if receipt_path.is_file():
            existing_receipt = _read_json(receipt_path)
            if existing_receipt.get("receipt_status") == "accepted_for_development":
                raise GovernanceError(f"refusing to overwrite accepted receipt: {receipt_path}")
    bundle_path = root / "governance-bundle.json"
    if bundle_path.is_file():
        existing_bundle = _read_json(bundle_path)
        if existing_bundle.get("bundle_status") == "accepted_for_development":
            raise GovernanceError("refusing to overwrite an accepted S1 governance bundle")

    roster = _read_json(root / "approval-roster.json")
    roster_schema = _read_json(root / "approval-roster.schema.json")
    roster_digest, person_id = validate_approval_roster(
        snapshot, roster, roster_schema, allow_pending=True
    )
    signing_key = _read_json(root / "maintainer-signing-key.json")
    signing_key_schema = _read_json(root / "maintainer-signing-key.schema.json")
    validate_maintainer_signing_key(
        signing_key,
        signing_key_schema,
        expected_person_id=person_id,
        allow_pending=True,
    )
    baseline = _read_json(root / "baseline-observations.json")
    baseline_schema = _read_json(root / "baseline-observations.schema.json")
    validate_baseline_observations(
        snapshot, baseline, baseline_schema, repository_root=repository_root
    )

    kickoff_schema = _read_json(root / "kickoff-authorization.schema.json")
    kickoff_records: dict[str, dict[str, Any]] = {}
    for ticket_id in ("V1-BOOT-01", "V1-BASE-01"):
        kickoff = _read_json(root / f"kickoff-authorization-{ticket_id.lower()}.json")
        validate_kickoff_authorization(
            snapshot,
            kickoff,
            kickoff_schema,
            expected_ticket_id=ticket_id,
            expected_roster_digest=roster_digest,
            expected_person_id=person_id,
            allow_pending=True,
        )
        kickoff_records[ticket_id] = kickoff

    registry = _read_json(root / "delivery-forecast.aggregation-registry.json")
    registry_schema = _read_json(root / "delivery-forecast.aggregation-registry.schema.json")
    _validate_json_schema(registry, registry_schema, owner="aggregation method registry")
    _resolve_aggregation_method(registry)
    ledger = _read_json(root / "delivery-forecast.authoring-ledger.json")
    ledger_schema = _read_json(root / "delivery-forecast.authoring-ledger.schema.json")
    validate_authoring_ledger(
        snapshot,
        ledger,
        ledger_schema,
        expected_person_id=person_id,
        baseline_observations=baseline,
    )
    forecast = _read_json(root / "delivery-forecast.json")
    forecast_schema = _read_json(root / "delivery-forecast.schema.json")
    validate_forecast(
        snapshot,
        ledger,
        registry,
        forecast,
        forecast_schema,
        expected_person_id=person_id,
        approval_roster_digest_value=roster_digest,
        allow_pending=True,
    )

    completion_schema = _read_json(root / "ticket-completion-receipt.schema.json")
    completion_receipts: dict[str, dict[str, Any]] = {}
    receipt_paths: dict[str, Path] = {}
    for ticket_id in ("V1-BOOT-01", "V1-BASE-01"):
        receipt = build_ticket_completion_receipt(
            snapshot,
            repository_root=repository_root,
            ticket_id=ticket_id,
            roster_digest=roster_digest,
            kickoff_authorization_digest=_required_string(
                kickoff_records[ticket_id], "authorization_digest"
            ),
            person_id=person_id,
            base_commit=PINNED_BASE_COMMIT,
            result_commit=None,
            issued_at=issued_at,
            valid_until=valid_until,
        )
        _validate_json_schema(receipt, completion_schema, owner=f"{ticket_id} receipt")
        completion_receipts[ticket_id] = receipt
        receipt_path = root / f"completion-receipt-{ticket_id.lower()}.json"
        receipt_paths[ticket_id] = receipt_path
        if receipt_path.is_file() and _read_json(receipt_path) != receipt:
            existing_receipt = _read_json(receipt_path)
            if not (
                bool(args.replace_pristine_drafts)
                and _is_pristine_machine_draft(receipt_path, existing_receipt)
            ):
                raise GovernanceError(
                    f"refusing to overwrite a differing completion receipt: {receipt_path}"
                )

    receipt_payload_overrides = {
        receipt_paths[ticket_id].relative_to(repository_root).as_posix(): _render_json_bytes(
            receipt
        )
        for ticket_id, receipt in completion_receipts.items()
    }

    bundle = build_governance_bundle(
        snapshot,
        repository_root=repository_root,
        roster=roster,
        kickoff_records=kickoff_records,
        completion_receipts=completion_receipts,
        forecast=forecast,
        signing_key=signing_key,
        baseline_observations=baseline,
        person_id=person_id,
        base_commit=PINNED_BASE_COMMIT,
        issued_at=issued_at,
        valid_until=valid_until,
        artifact_payload_overrides=receipt_payload_overrides,
    )
    bundle_schema = _read_json(root / "governance-bundle.schema.json")
    validate_governance_bundle(
        snapshot,
        bundle,
        bundle_schema,
        repository_root=repository_root,
        roster=roster,
        kickoff_records=kickoff_records,
        completion_receipts=completion_receipts,
        forecast=forecast,
        signing_key=signing_key,
        baseline_observations=baseline,
        expected_person_id=person_id,
        expected_base_commit=PINNED_BASE_COMMIT,
        allow_pending=True,
        require_bundle_on_disk=False,
        require_predecessors_on_disk=False,
        artifact_payload_overrides=receipt_payload_overrides,
    )
    if bundle_path.is_file() and _read_json(bundle_path) != bundle:
        existing_bundle = _read_json(bundle_path)
        if not (
            bool(args.replace_pristine_drafts)
            and _is_pristine_machine_draft(bundle_path, existing_bundle)
        ):
            raise GovernanceError("refusing to overwrite a differing S1 governance bundle")
    _write_json_batch(
        {
            receipt_paths["V1-BOOT-01"]: completion_receipts["V1-BOOT-01"],
            receipt_paths["V1-BASE-01"]: completion_receipts["V1-BASE-01"],
            bundle_path: bundle,
        }
    )
    validate_governance_bundle(
        snapshot,
        bundle,
        bundle_schema,
        repository_root=repository_root,
        roster=roster,
        kickoff_records=kickoff_records,
        completion_receipts=completion_receipts,
        forecast=forecast,
        signing_key=signing_key,
        baseline_observations=baseline,
        expected_person_id=person_id,
        expected_base_commit=PINNED_BASE_COMMIT,
        allow_pending=True,
    )
    print(
        json.dumps(
            {
                "bundle_digest": bundle["bundle_digest"],
                "bundle_status": bundle["bundle_status"],
                "completion_receipts": {
                    ticket_id: receipt["receipt_digest"]
                    for ticket_id, receipt in completion_receipts.items()
                },
                "result": "valid_pending_nonaccepting",
            },
            sort_keys=True,
        )
    )
    return 0


@_guard_acceptance_reader
def check(args: argparse.Namespace) -> int:
    repository_root = Path(cast(str, args.repository_root)).resolve()
    root = Path(cast(str, args.governance_dir)).resolve()
    closure_commit_value = getattr(args, "closure_commit", None)
    acceptance_tag_object_value = getattr(args, "acceptance_tag_object", None)
    attestation_plan_dir_value = getattr(args, "attestation_plan_dir", None)
    attestation_signed_at_value = getattr(args, "attestation_signed_at", None)
    commitment_time_value = getattr(args, "commitment_time", None)
    if closure_commit_value is not None and not isinstance(closure_commit_value, str):
        raise GovernanceError("--closure-commit must be a full 40-hex Git commit ID")
    closure_commit: str | None = closure_commit_value
    if root != (repository_root / "docs/governance/v1").resolve():
        raise GovernanceError("S1 governance directory must be docs/governance/v1")
    if args.allow_pending and (args.accept_now or args.historical):
        raise GovernanceError(
            "--allow-pending cannot be combined with --accept-now or --historical"
        )
    if not args.allow_pending and bool(args.accept_now) == bool(args.historical):
        raise GovernanceError(
            "strict checking requires exactly one of --accept-now or --historical"
        )
    if args.fetch_authoritative_refs and not args.accept_now:
        raise GovernanceError("--fetch-authoritative-refs requires --accept-now")
    if args.accept_now and not args.fetch_authoritative_refs:
        raise GovernanceError("--accept-now requires --fetch-authoritative-refs")
    if args.historical:
        if closure_commit is None:
            raise GovernanceError("--historical requires --closure-commit")
        if GIT_COMMIT_PATTERN.fullmatch(closure_commit) is None:
            raise GovernanceError("--closure-commit must be a full lowercase 40-hex commit ID")
        if not isinstance(acceptance_tag_object_value, str):
            raise GovernanceError("--historical requires --acceptance-tag-object")
        if commitment_time_value is not None:
            raise GovernanceError(
                "--historical derives its trusted commitment time from the signed acceptance tag"
            )
        if attestation_plan_dir_value is not None or attestation_signed_at_value is not None:
            raise GovernanceError(
                "historical checking cannot prepare a current acceptance attestation"
            )
    elif closure_commit is not None:
        raise GovernanceError("--closure-commit is valid only with --historical")
    elif acceptance_tag_object_value is not None:
        raise GovernanceError("--acceptance-tag-object is valid only with --historical")
    attestation_plan_directory: Path | None = None
    if args.accept_now:
        if commitment_time_value is None:
            raise GovernanceError("--accept-now requires --commitment-time")
        if not isinstance(attestation_plan_dir_value, str):
            raise GovernanceError("--accept-now requires --attestation-plan-dir")
        if not isinstance(attestation_signed_at_value, str):
            raise GovernanceError("--accept-now requires --attestation-signed-at")
        attestation_plan_directory = _private_acceptance_path(
            repository_root,
            attestation_plan_dir_value,
            owner="current acceptance attestation plan",
            must_exist=False,
        )
    elif attestation_plan_dir_value is not None or attestation_signed_at_value is not None:
        raise GovernanceError("acceptance attestation preparation requires --accept-now")
    roadmap_path = Path(cast(str, args.roadmap))
    validate_local_only_roadmap(repository_root, roadmap_path)
    snapshot = load_roadmap(roadmap_path)

    commitment_time: datetime | None = None
    historical_attestation: dict[str, Any] | None = None
    historical_attestation_signature_time: datetime | None = None
    historical_records: dict[str, dict[str, Any]] | None = None
    if closure_commit is not None:
        _validate_git_history_safety(repository_root)
        object_type = _run_git(repository_root, ["cat-file", "-t", closure_commit])
        if object_type.returncode != 0 or object_type.stdout.strip() != b"commit":
            raise GovernanceError("--closure-commit does not identify a Git commit")
        if not isinstance(acceptance_tag_object_value, str):
            raise GovernanceError("historical checking requires an acceptance tag object")
        historical_attestation = _read_tagged_current_acceptance_attestation(
            repository_root,
            tag_object=acceptance_tag_object_value,
            expected_closure_commit=closure_commit,
        )
        commitment_time, historical_attestation_signature_time = (
            _validate_current_acceptance_attestation(
                historical_attestation,
                repository_root=repository_root,
                expected_closure_commit=closure_commit,
                expected_roadmap_digest=snapshot.raw_digest,
                allow_pending=False,
            )
        )
        historical_paths = _historical_governance_json_paths()
        if len(historical_paths) != len(set(historical_paths)):
            raise GovernanceError("historical governance path contract contains duplicates")
        historical_records = {
            path: _read_json_from_commit(repository_root, closure_commit, path)
            for path in historical_paths
        }

    def read_governance_record(name: str) -> dict[str, Any]:
        relative = f"docs/governance/v1/{name}"
        if historical_records is None:
            return _read_json(root / name)
        if relative not in historical_records:
            raise GovernanceError(f"historical record set is missing {relative}")
        return dict(historical_records[relative])

    roster = read_governance_record("approval-roster.json")
    roster_schema = read_governance_record("approval-roster.schema.json")
    roster_digest, person_id = validate_approval_roster(
        snapshot, roster, roster_schema, allow_pending=bool(args.allow_pending)
    )
    if historical_attestation is None:
        commitment_time = (
            _parse_utc(cast(str, commitment_time_value), owner="--commitment-time")
            if commitment_time_value is not None
            else None
        )
    if not args.allow_pending and commitment_time is None:
        raise GovernanceError("strict checking requires --commitment-time")
    live_repository_evidence: dict[str, Any] | None = None
    if args.accept_now:
        live_repository_evidence = validate_live_acceptance_repository(repository_root, fetch=True)
    signing_key = read_governance_record("maintainer-signing-key.json")
    baseline = read_governance_record("baseline-observations.json")
    kickoff_schema = read_governance_record("kickoff-authorization.schema.json")
    kickoff_records: dict[str, dict[str, Any]] = {}
    for ticket_id in ("V1-BOOT-01", "V1-BASE-01"):
        kickoff = read_governance_record(f"kickoff-authorization-{ticket_id.lower()}.json")
        validate_kickoff_authorization(
            snapshot,
            kickoff,
            kickoff_schema,
            expected_ticket_id=ticket_id,
            expected_roster_digest=roster_digest,
            expected_person_id=person_id,
            allow_pending=bool(args.allow_pending),
            validation_time=commitment_time,
        )
        kickoff_records[ticket_id] = kickoff
    registry = read_governance_record("delivery-forecast.aggregation-registry.json")
    registry_schema = read_governance_record("delivery-forecast.aggregation-registry.schema.json")
    _validate_json_schema(registry, registry_schema, owner="aggregation method registry")
    _resolve_aggregation_method(registry)
    ledger = read_governance_record("delivery-forecast.authoring-ledger.json")
    ledger_schema = read_governance_record("delivery-forecast.authoring-ledger.schema.json")
    validate_authoring_ledger(
        snapshot,
        ledger,
        ledger_schema,
        expected_person_id=person_id,
        baseline_observations=baseline,
    )
    forecast = read_governance_record("delivery-forecast.json")
    schema = read_governance_record("delivery-forecast.schema.json")
    validate_forecast(
        snapshot,
        ledger,
        registry,
        forecast,
        schema,
        expected_person_id=person_id,
        approval_roster_digest_value=roster_digest,
        allow_pending=bool(args.allow_pending),
        commitment_time=commitment_time,
    )
    completion_schema = read_governance_record("ticket-completion-receipt.schema.json")
    completion_receipts: dict[str, dict[str, Any]] = {}
    for ticket_id in ("V1-BOOT-01", "V1-BASE-01"):
        receipt = read_governance_record(f"completion-receipt-{ticket_id.lower()}.json")
        validate_ticket_completion_receipt(
            snapshot,
            receipt,
            completion_schema,
            repository_root=repository_root,
            expected_ticket_id=ticket_id,
            expected_roster_digest=roster_digest,
            expected_kickoff_digest=_required_string(
                kickoff_records[ticket_id], "authorization_digest"
            ),
            expected_person_id=person_id,
            expected_base_commit=PINNED_BASE_COMMIT,
            allow_pending=bool(args.allow_pending),
            validation_time=commitment_time,
            expected_kickoff_record=kickoff_records[ticket_id],
        )
        completion_receipts[ticket_id] = receipt
    bundle = read_governance_record("governance-bundle.json")
    bundle_schema = read_governance_record("governance-bundle.schema.json")
    validate_governance_bundle(
        snapshot,
        bundle,
        bundle_schema,
        repository_root=repository_root,
        roster=roster,
        kickoff_records=kickoff_records,
        completion_receipts=completion_receipts,
        forecast=forecast,
        signing_key=signing_key,
        baseline_observations=baseline,
        expected_person_id=person_id,
        expected_base_commit=PINNED_BASE_COMMIT,
        allow_pending=bool(args.allow_pending),
        validation_time=commitment_time,
        require_bundle_on_disk=historical_records is None,
        require_predecessors_on_disk=historical_records is None,
        require_current_closure=bool(args.accept_now),
        historical_records=historical_records,
        expected_closure_commit=closure_commit,
    )
    attestation_plan: dict[str, Any] | None = None
    if historical_attestation is not None:
        if historical_attestation.get("bundle_digest") != bundle.get("bundle_digest"):
            raise GovernanceError("signed current acceptance attestation binds another bundle")
        if historical_attestation.get("result_commit") != bundle.get("result_commit"):
            raise GovernanceError("signed current acceptance attestation binds another result")
        if historical_attestation.get("signer_person_id") != person_id:
            raise GovernanceError("signed current acceptance attestation uses another maintainer")
        if historical_attestation_signature_time is None:
            raise GovernanceError("signed current acceptance attestation lacks a signature time")
        bundle_issue, bundle_expiry = _validate_validity_interval(
            _required_string(bundle, "issued_at_utc"),
            _required_string(bundle, "valid_until_utc"),
            owner="S1 governance bundle",
        )
        if not bundle_issue <= historical_attestation_signature_time < bundle_expiry:
            raise GovernanceError(
                "signed current acceptance attestation is outside the bundle validity interval"
            )
    elif args.accept_now:
        if (
            live_repository_evidence is None
            or commitment_time_value is None
            or not isinstance(attestation_signed_at_value, str)
            or attestation_plan_directory is None
        ):
            raise GovernanceError("current acceptance attestation inputs are incomplete")
        attestation = build_current_acceptance_attestation(
            snapshot,
            repository_root=repository_root,
            bundle=bundle,
            live_repository_evidence=live_repository_evidence,
            gate_checked_at=cast(str, commitment_time_value),
            signature_requested_at=attestation_signed_at_value,
            signer_person_id=person_id,
        )
        _validate_current_acceptance_attestation(
            attestation,
            repository_root=repository_root,
            expected_closure_commit=_required_string(live_repository_evidence, "head_commit"),
            expected_roadmap_digest=snapshot.raw_digest,
            allow_pending=True,
        )
        attestation_plan = _write_current_acceptance_attestation_plan(
            attestation_plan_directory,
            attestation,
        )
    print(
        json.dumps(
            {
                "forecast_status": forecast["forecast_status"],
                "record_digest": forecast["record_digest"],
                "bundle_status": bundle["bundle_status"],
                "bundle_digest": bundle["bundle_digest"],
                "result": (
                    "valid_pending_nonaccepting"
                    if args.allow_pending
                    else (
                        "valid_current_closure_attestation_prepared"
                        if args.accept_now
                        else "valid_historical_accepted"
                    )
                ),
                "signatures": (
                    "pending_allowed"
                    if args.allow_pending
                    else (
                        "governance_records_valid_attestation_pending"
                        if args.accept_now
                        else "all_required_verified"
                    )
                ),
                **({"attestation_plan": attestation_plan} if attestation_plan else {}),
                **(
                    {"acceptance_tag_object": acceptance_tag_object_value}
                    if historical_attestation is not None
                    else {}
                ),
            },
            sort_keys=True,
        )
    )
    return 0


@_guard_acceptance_reader
def acceptance_preflight(args: argparse.Namespace) -> int:
    """Re-resolve mutable Git facts before the human acceptance ceremony."""

    repository_root = Path(cast(str, args.repository_root)).resolve()
    validate_live_acceptance_repository(repository_root, fetch=bool(args.fetch))
    print(
        json.dumps(
            {
                "branch": S1_BRANCH_NAME,
                "fetch_performed": bool(args.fetch),
                "origin": APPROVED_ORIGIN_URL,
                "origin_main_commit": PINNED_BASE_COMMIT,
                "result": "valid_live_acceptance_repository",
                "tag_object": PINNED_TAG_OBJECT,
            },
            sort_keys=True,
        )
    )
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    generate = subparsers.add_parser("generate-draft", help="Generate the reviewable S1 forecast")
    generate.add_argument("--roadmap", required=True)
    generate.add_argument("--output", required=True)
    generate.add_argument("--issued-at", required=True)
    generate.add_argument("--valid-until", required=True)
    generate.add_argument("--person-id", required=True)
    generate.add_argument("--repository-root", default=".")
    generate.add_argument(
        "--replace-pristine-drafts",
        action="store_true",
        help="Replace only unsigned, entirely unconfirmed machine drafts",
    )
    generate.add_argument(
        "--trusted-time-basis",
        default="maintainer-trusted host UTC; Windows Time attestation unavailable",
    )
    generate.set_defaults(handler=generate_draft)

    assemble = subparsers.add_parser(
        "assemble-draft", help="Assemble pending S1 completion and release records"
    )
    assemble.add_argument("--roadmap", required=True)
    assemble.add_argument("--governance-dir", required=True)
    assemble.add_argument("--repository-root", default=".")
    assemble.add_argument("--issued-at", required=True)
    assemble.add_argument("--valid-until", required=True)
    assemble.add_argument(
        "--replace-pristine-drafts",
        action="store_true",
        help="Replace only unsigned pending completion and bundle drafts",
    )
    assemble.set_defaults(handler=assemble_draft)

    decision_template = subparsers.add_parser(
        "acceptance-decision-template",
        help="Create a local-only worksheet for explicit human S1 decisions",
    )
    decision_template.add_argument("--roadmap", required=True)
    decision_template.add_argument("--governance-dir", required=True)
    decision_template.add_argument("--output", required=True)
    decision_template.add_argument("--repository-root", default=".")
    decision_template.set_defaults(handler=acceptance_decision_template)

    prepare = subparsers.add_parser(
        "acceptance-prepare",
        help="Prepare a no-private-key signature plan for one acceptance phase",
    )
    prepare.add_argument(
        "--phase", choices=("predecessors", "completions", "bundle"), required=True
    )
    prepare.add_argument("--roadmap", required=True)
    prepare.add_argument("--governance-dir", required=True)
    prepare.add_argument("--plan-dir", required=True)
    prepare.add_argument("--issued-at", required=True)
    prepare.add_argument("--valid-until", required=True)
    prepare.add_argument("--signed-at", required=True)
    prepare.add_argument("--decisions")
    prepare.add_argument("--commitment-time")
    prepare.add_argument("--result-commit")
    prepare.add_argument("--repository-root", default=".")
    prepare.add_argument(
        "--trusted-time-basis",
        default="maintainer-trusted host UTC; Windows Time attestation unavailable",
    )
    prepare.set_defaults(handler=acceptance_prepare)

    import_signatures = subparsers.add_parser(
        "acceptance-import",
        help="Verify SSHSIG files and journal-install one signed phase",
    )
    import_signatures.add_argument("--roadmap", required=True)
    import_signatures.add_argument("--governance-dir", required=True)
    import_signatures.add_argument("--plan-dir", required=True)
    import_signatures.add_argument(
        "--expected-plan-digest",
        required=True,
        help="Require the exact digest displayed when the signature plan was prepared",
    )
    import_signatures.add_argument("--commitment-time", required=True)
    import_signatures.add_argument("--repository-root", default=".")
    import_signatures.set_defaults(handler=acceptance_import)

    finalize_attestation = subparsers.add_parser(
        "acceptance-attestation-finalize",
        help="Verify the human SSHSIG over the current-gate attestation and render its tag record",
    )
    finalize_attestation.add_argument("--plan-dir", required=True)
    finalize_attestation.add_argument(
        "--expected-attestation-digest",
        required=True,
        help="Require the exact digest displayed by the successful current-gate check",
    )
    finalize_attestation.add_argument("--repository-root", default=".")
    finalize_attestation.set_defaults(handler=acceptance_attestation_finalize)

    result_paths = subparsers.add_parser(
        "acceptance-result-paths",
        help="Write the exact NUL-delimited staging allowlist for the S1 result commit",
    )
    result_paths.add_argument("--roadmap", required=True)
    result_paths.add_argument("--governance-dir", required=True)
    result_paths.add_argument("--output", required=True)
    result_paths.add_argument("--commitment-time", required=True)
    result_paths.add_argument("--repository-root", default=".")
    result_paths.set_defaults(handler=acceptance_result_paths)

    validate = subparsers.add_parser("check", help="Validate forecast structure and recomputation")
    validate.add_argument("--roadmap", required=True)
    validate.add_argument("--governance-dir", required=True)
    validate.add_argument("--allow-pending", action="store_true")
    validate.add_argument(
        "--accept-now",
        action="store_true",
        help="Require a clean checkout at the unique S1 closure commit",
    )
    validate.add_argument(
        "--historical",
        action="store_true",
        help="Verify an accepted S1 closure on the current HEAD lineage",
    )
    validate.add_argument(
        "--closure-commit",
        help="Full closure commit ID required with --historical and forbidden otherwise",
    )
    validate.add_argument(
        "--acceptance-tag-object",
        help="Full annotated-tag object ID required with --historical and forbidden otherwise",
    )
    validate.add_argument(
        "--fetch-authoritative-refs",
        action="store_true",
        help="Perform the mandatory authoritative fetch and remote-ref check for acceptance",
    )
    validate.add_argument("--commitment-time")
    validate.add_argument(
        "--attestation-plan-dir",
        help="New ignored plan directory required with --accept-now",
    )
    validate.add_argument(
        "--attestation-signed-at",
        help="Planned human SSHSIG time, no earlier than and within one hour of the current gate",
    )
    validate.add_argument("--repository-root", default=".")
    validate.set_defaults(handler=check)

    preflight = subparsers.add_parser(
        "acceptance-preflight",
        help="Validate live Git remote, refs, tag, branch, and history safety",
    )
    preflight.add_argument("--repository-root", default=".")
    preflight.add_argument(
        "--fetch",
        action="store_true",
        help="Fetch origin/main and tags before resolving the acceptance refs",
    )
    preflight.set_defaults(handler=acceptance_preflight)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    runtime_guard = _BOOTSTRAPPED_RUNTIME_GUARD
    if (
        __name__ != "__main__"
        or runtime_guard is None
        or not sys.meta_path
        or sys.meta_path[0] is not runtime_guard
    ):
        print(
            "v1 S1 governance error: commands require successful frozen runtime bootstrap",
            file=sys.stderr,
        )
        return 2
    args = _parser().parse_args(argv)
    handler = cast(Any, args.handler)
    try:
        return int(handler(args))
    except (GovernanceError, OSError) as exc:
        print(f"v1 S1 governance error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
