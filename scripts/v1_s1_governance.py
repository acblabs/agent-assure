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
from contextlib import ExitStack, contextmanager
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
ESTIMATION_CATALOG_V2_DOMAIN: Final = "agent-assure:delivery-forecast-estimation-catalog/v1"
METHOD_V2_DOMAIN: Final = "agent-assure:delivery-forecast-aggregation-method/v2"
METHOD_REGISTRY_V2_DOMAIN: Final = "agent-assure:delivery-forecast-aggregation-registry/v2"
FORECAST_V2_DOMAIN: Final = "agent-assure:delivery-forecast/v2"
LEDGER_V2_DOMAIN: Final = "agent-assure:delivery-forecast-authoring-ledger/v2"
OBLIGATION_COVERAGE_V2_DOMAIN: Final = "agent-assure:delivery-forecast-obligation-coverage/v2"
WORKLOAD_VECTOR_V2_DOMAIN: Final = "agent-assure:delivery-forecast-workload-vector/v2"
OCCURRENCE_PROPOSAL_V2_DOMAIN: Final = "agent-assure:delivery-forecast-occurrence-proposal/v2"
FORECAST_DECISION_MANIFEST_V2_DOMAIN: Final = "agent-assure:delivery-forecast-decision-manifest/v2"
FORECAST_ACCEPTANCE_RECEIPT_V2_DOMAIN: Final = (
    "agent-assure:delivery-forecast-acceptance-receipt/v2"
)
FORECAST_DECISION_PLAN_V2_DOMAIN: Final = (
    "agent-assure:delivery-forecast-decision-signature-plan/v2"
)
FORECAST_SIGNATURE_PLAN_V2_DOMAIN: Final = "agent-assure:delivery-forecast-final-signature-plan/v2"
FORECAST_DECISION_IMPORT_V2_DOMAIN: Final = (
    "agent-assure:delivery-forecast-decision-signature-import/v2"
)
FORECAST_SIGNATURE_IMPORT_V2_DOMAIN: Final = (
    "agent-assure:delivery-forecast-final-signature-import/v2"
)
ACCEPTANCE_CRITERION_SOURCE_DOMAIN: Final = "agent-assure:roadmap-acceptance-criterion/v1"
WORK_PACKAGE_SOURCE_DOMAIN: Final = "agent-assure:roadmap-work-package/v1"
ESTIMATE_PRIOR_SOURCE_DOMAIN: Final = "agent-assure:roadmap-estimate-prior/v1"
ACCEPTANCE_CRITERIA_SET_DOMAIN: Final = "agent-assure:roadmap-acceptance-criteria-set/v1"
WORK_PACKAGE_SET_DOMAIN: Final = "agent-assure:roadmap-work-package-set/v1"
TICKET_DELIVERY_SOURCE_DOMAIN: Final = "agent-assure:roadmap-ticket-delivery/v1"
TICKET_DEPENDENCIES_SOURCE_DOMAIN: Final = "agent-assure:roadmap-ticket-dependencies/v1"
RELEASE_TRAIN_ENTRY_SOURCE_DOMAIN: Final = "agent-assure:roadmap-release-train-entry/v1"
RELEASE_OCCURRENCE_SOURCE_DOMAIN: Final = "agent-assure:roadmap-release-occurrence/v1"
ELAPSED_WAIT_REQUIREMENT_DOMAIN: Final = "agent-assure:roadmap-elapsed-wait-requirement/v1"
ESTIMATION_CATALOG_V2_DIGEST: Final = (
    "sha256:33cee0874eecf79f36a0dadcafa831525df206c9fdc67d9ab4759138475da439"
)
ROSTER_DOMAIN: Final = "agent-assure:approval-roster/v1"
KICKOFF_DOMAIN: Final = "agent-assure:kickoff-authorization/v1"
TICKET_RECEIPT_DOMAIN: Final = "agent-assure:ticket-completion-receipt/v1"
BUNDLE_DOMAIN: Final = "agent-assure:governance-bundle/v1"
TICKET_RECEIPT_V2_DOMAIN: Final = "agent-assure:ticket-completion-receipt/v2"
BUNDLE_V2_DOMAIN: Final = "agent-assure:governance-bundle/v2"
CORRECTIVE_CHANGE_ALLOWLIST_DOMAIN: Final = "agent-assure:s1-corrective-change-allowlist/v2"
CORRECTIVE_RESULT_ARTIFACT_SET_DOMAIN: Final = "agent-assure:s1-corrective-result-artifact-set/v2"
CORRECTIVE_REVIEWED_ARTIFACT_SET_DOMAIN: Final = (
    "agent-assure:s1-corrective-reviewed-artifact-set/v2"
)
CORRECTIVE_CLOSURE_ARTIFACT_SET_DOMAIN: Final = "agent-assure:s1-corrective-closure-artifact-set/v2"
POST_R2_SUITE_EVIDENCE_DOMAIN: Final = "agent-assure:s1-post-r2-suite-evidence/v3"
CORRECTIVE_RECEIPT_PLAN_V2_DOMAIN: Final = "agent-assure:s1-corrective-receipt-signature-plan/v2"
CORRECTIVE_RECEIPT_IMPORT_V2_DOMAIN: Final = (
    "agent-assure:s1-corrective-receipt-signature-import/v2"
)
CORRECTIVE_BUNDLE_PLAN_V2_DOMAIN: Final = "agent-assure:s1-corrective-bundle-signature-plan/v2"
CORRECTIVE_CLOSURE_IMPORT_V2_DOMAIN: Final = (
    "agent-assure:s1-corrective-closure-signature-import/v2"
)
SIGNING_KEY_DOMAIN: Final = "agent-assure:governance-signing-key/v1"
BASELINE_OBSERVATIONS_DOMAIN: Final = "agent-assure:baseline-observations/v1"
BASELINE_OBSERVATIONS_V2_DOMAIN: Final = "agent-assure:baseline-observations/v2"
CORRECTIVE_KICKOFF_CLAIM_DIGEST: Final = (
    "sha256:4477162d48826c8cece417e78ef8dcb4a5ef3047c24bf0cdef20d8fb55ba1f60"
)
CORRECTIVE_KICKOFF_CLAIM_SIZE: Final = 6_712
TICKET_SET_DOMAIN: Final = "agent-assure:roadmap-ticket-set/v1"
DEPENDENCY_GRAPH_DOMAIN: Final = "agent-assure:roadmap-dependency-graph/v1"
RELEASE_TRAIN_DOMAIN: Final = "agent-assure:roadmap-release-train/v1"
SIGNATURE_NAMESPACE: Final = "agent-assure-governance-v1"
SIGNATURE_PROFILE: Final = "openssh-sshsig-ed25519/v1"
SIGNATURE_PAYLOAD_ENCODING: Final = "agent-assure-domain-separated-rfc8785-signature-claim/v1"
ATTESTATION_V2_SIGNATURE_PAYLOAD_ENCODING: Final = (
    "agent-assure-domain-separated-rfc8785-signature-claim/v2"
)
SIGNATURE_ENCODING: Final = "base64-canonical-lf-openssh-sshsig-armored"
SIGNATURE_CLAIM_DOMAIN: Final = "agent-assure:sshsig-claim/v1"
ATTESTATION_V2_SIGNATURE_CLAIM_DOMAIN: Final = "agent-assure:sshsig-claim/v2"
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
CURRENT_ACCEPTANCE_ATTESTATION_V2_DOMAIN: Final = (
    "agent-assure:s1-current-acceptance-attestation/v2"
)
CURRENT_ACCEPTANCE_ATTESTATION_V1_FORMAT: Final = "agent-assure-s1-current-acceptance-attestation/1"
CURRENT_ACCEPTANCE_ATTESTATION_V2_FORMAT: Final = "agent-assure-s1-current-acceptance-attestation/2"
ATTESTATION_V2_SIGNATURE_ENVELOPE_FIELDS: Final = frozenset(
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
        "signature",
    }
)
_NO_SIGNATURE_VERIFICATION_EVIDENCE: Final = object()
FORECAST_V2_SIGNATURE_IMPORT_EVIDENCE_FIELDS: Final = frozenset(
    {
        "status",
        "signature_plan_digest",
        "claim_preparation_started_at_utc",
        "import_verification_started_at_utc",
        "import_verification_completed_at_utc",
        "clock_basis",
        "sshsig_timestamp_capability",
        "actual_signature_time_claimed",
        "verification_result",
        "signature_claim_binding",
        "durable_integrity_binding",
    }
)
ATTESTATION_V2_TIME_EVIDENCE: Final = {
    "clock_basis": "maintainer_host_utc_externally_unattested",
    "sshsig_timestamp_capability": "none",
    "actual_signature_time_claimed": False,
}
MAINTAINER_KEY_FINGERPRINT: Final = "SHA256:L/6IRITdktnUQOfbr6iuf48k2MtolzDFvxWaQHU4G7k"
MAINTAINER_PUBLIC_KEY: Final = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP7Bgeqxj82OCpkAsF4Qzby2m5PfOnh4lNKzl3fXZ/uB"
)
FOCUSED_DAY_HOURS: Final = 8
PINNED_BASE_COMMIT: Final = "3b060f4da94f4d0d80e7ae507580fce82ef9bf96"
PINNED_TAG_OBJECT: Final = "ea4b50bd461efd817b7dc2fa5591d06ed9599a6e"
APPROVED_ORIGIN_URL: Final = "https://github.com/acblabs/agent-assure.git"
S1_BRANCH_NAME: Final = "feat/v1-assurance-compiler"
S1_CORRECTIVE_BRANCH_NAME: Final = "fix/s1-governed-baseline-v2"
S1_ACCEPTANCE_TAG_NAME: Final = "agent-assure-s1-1.0.0a1-acceptance"
S1_ACCEPTANCE_V2_TAG_NAME: Final = "agent-assure-s1-1.0.0a1-acceptance-v2"
S1_ACCEPTANCE_V1_TAG_OBJECT: Final = "1f7bfe058dfb84d8cf4afaf971a57e5c3a12a5fb"
S1_ACCEPTANCE_V1_CLOSURE_COMMIT: Final = "6165bc6436aada6cbeb4fc4119eafa9b5dfdb000"
S1_ACCEPTANCE_V1_RESULT_COMMIT: Final = "038b1a8c80fc419106eecd43f4a70b14ba026106"
S1_ACCEPTANCE_V1_BUNDLE_DIGEST: Final = (
    "sha256:62d4ddd81f2f619597b40a39d75a084e5bd0bc5ad99e2653f3fe6659b0194a82"
)
S1_ACCEPTANCE_V1_FORECAST_DIGEST: Final = (
    "sha256:e151679546b1a2d9f62a179052c97ba61ed6b249b05d69c11f23220287b56460"
)
S1_ACCEPTANCE_V1_RECEIPT_DIGESTS: Final = {
    "V1-BASE-01": "sha256:3a0a1a36586023147ea0e3cf7cf23d619bfc283da25445f5f72169eaf5226d1e",
    "V1-BOOT-01": "sha256:ae5bf055cdd56292dec33422877a1fddce4a297b34879e5d58441ff8fa63c32a",
}
S1_CORRECTIVE_CLOSURE_PATHS: Final = frozenset(
    {
        "docs/governance/v1/completion-receipt-v1-base-01.json",
        "docs/governance/v1/completion-receipt-v1-boot-01.json",
        "docs/governance/v1/governance-bundle.json",
    }
)
POST_R2_PYTHON_ARGUMENTS: Final = (
    "-I",
    "-S",
    "-B",
    "-X",
    "utf8",
)
POST_R2_PYTEST_ARGUMENTS: Final = (
    # Repository ``addopts`` are prepended by pytest.  Assign the final
    # verbosity explicitly so a configured ``-q`` cannot combine with this
    # command into ``-qq``, which suppresses the terminal totals we attest.
    "--verbosity=-1",
    "-p",
    "no:cacheprovider",
    "-p",
    "pytest_socket",
    "-p",
    "_hypothesis_pytestplugin",
    "-p",
    "pytest_cov.plugin",
    "--color=no",
    "--hypothesis-seed=0",
)
CORRECTIVE_LOCAL_ONLY_PATH_PREFIXES: Final = (
    ".tmp/s1-acceptance/correction-v2-",
    ".tmp/s1-acceptance/phase-v2-",
    ".tmp/s1-acceptance/current-gate-v2-",
)
POST_R2_PROCESS_TEMP_ROOT: Final = Path(r"C:\tmp")
POST_R2_PROCESS_TEMP_PREFIX: Final = "agent-assure-s1-post-r2-process-temp-"
POST_R2_PROCESS_USER_TEMP_DIRECTORY: Final = "temp"
POST_R2_PYTEST_BASETEMP_DIRECTORY: Final = "pytest"
POST_R2_DESCENDANT_RUNTIME_DIRECTORY: Final = "descendant-runtime"
POST_R2_DESCENDANT_RUNTIME_PATHS_FILE: Final = "00_agent_assure_s1_paths.pth"
POST_R2_DESCENDANT_RUNTIME_GUARD_FILE: Final = "sitecustomize.py"
POST_R2_DESCENDANT_NO_SITE_ENV: Final = "AGENT_ASSURE_S1_POST_R2_REQUESTED_NO_SITE"
POST_R2_DESCENDANT_ORIGINAL_PYTHONPATH_ENV: Final = "AGENT_ASSURE_S1_POST_R2_ORIGINAL_PYTHONPATH"
POST_R2_DESCENDANT_ORIGINAL_PYTHONPATH_PRESENT_ENV: Final = (
    "AGENT_ASSURE_S1_POST_R2_ORIGINAL_PYTHONPATH_PRESENT"
)
POST_R2_DESCENDANT_RUNTIME_REQUIRED_DIRECTORIES: Final = (
    "Lib",
    "Lib/site-packages",
    "Scripts",
)
POST_R2_SUITE_EVIDENCE_DIRECTORY: Final = ".tmp/s1-acceptance/correction-v2-post-r2-suite-evidence"
POST_R2_TEST_RUNTIME_INVENTORY_DOMAIN: Final = (
    b"agent-assure:s1-post-r2-test-runtime-inventory/v1\x00"
)
POST_R2_TEST_RUNTIME_EXCLUDED_DIRECTORY_NAMES: Final = frozenset({"__pycache__"})
POST_R2_TEST_RUNTIME_FORBIDDEN_FILE_SUFFIXES: Final = frozenset({".pyc", ".pyo"})
POST_R2_TEST_RUNTIME_FILE_COUNT: Final = 5_473
POST_R2_TEST_RUNTIME_SIZE_BYTES: Final = 92_718_636
POST_R2_TEST_RUNTIME_SHA256: Final = (
    "a1fc3961699a2eed1fdbeccba871a55b760f3764da3e54c1a638fc18bafb7f2c"
)
POST_R2_TEST_SURFACE_INVENTORY_DOMAIN: Final = (
    b"agent-assure:s1-post-r2-test-surface-inventory/v1\x00"
)
POST_R2_TEST_AFFECTING_DIRECTORIES: Final = (
    ".githooks",
    ".github",
    "compat",
    "docs",
    "evidence",
    "examples",
    "mappings",
    "paper",
    "schemas",
    "scripts",
    "src",
    "tests",
    "third_party",
)
POST_R2_TRACKED_ROOT_FILES: Final = (
    ".dockerignore",
    ".gitattributes",
    ".gitignore",
    ".gitleaks.toml",
    ".gitleaksignore",
    "CHANGELOG.md",
    "CITATION.cff",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "FEATURES.md",
    "LICENSE",
    "Makefile",
    "README.md",
    "SECURITY.md",
    "THIRD_PARTY_NOTICES.md",
    "mkdocs.yml",
    "pyproject.toml",
    "requirements-adk.lock",
    "requirements-langgraph.lock",
    "requirements-min.constraints.txt",
    "requirements-min.lock",
    "requirements-otel.lock",
    "requirements.lock",
)
POST_R2_ROOT_TEST_CONFIG_PATHS: Final = (
    ".coveragerc",
    "conftest.py",
    "mkdocs.yml",
    "pyproject.toml",
    "pytest.ini",
    "pytest.toml",
    "setup.cfg",
    "sitecustomize.py",
    "tox.ini",
    "usercustomize.py",
)
POST_R2_GIT_EXCLUDE_SIZE_BYTES: Final = 2_368
POST_R2_GIT_EXCLUDE_SHA256: Final = (
    "7c13bf60842aceead989daabbab30e5ae8fc3e4cf2100af9781e692790265060"
)
POST_R2_CHILD_PATH: Final = ";".join(
    (
        str(_FROZEN_PYTHON_ROOT),
        str(_FROZEN_PYTHON_ROOT / "DLLs"),
        r"C:\Program Files\Git\mingw64\bin",
        r"C:\Windows\System32\OpenSSH",
        r"C:\Windows\System32",
        r"C:\Windows",
    )
)


def _post_r2_descendant_sitecustomize_source(
    descendant_python: Path,
    pycache_prefix: Path,
    *,
    repository_root: Path,
    site_packages: Path,
) -> str:
    """Return the fail-closed, recursively inherited Python launch guard."""

    runtime_root = descendant_python.parent.parent
    guard_directory = runtime_root / "Lib/site-packages"
    no_site_paths = (
        guard_directory,
        repository_root / "src",
        repository_root,
        site_packages,
    )
    return f"""\
from __future__ import annotations

import importlib.machinery
import importlib.util
import os
import re
import subprocess
import sys

_AGENT_ASSURE_GOVERNED_PYTHON = {str(descendant_python)!r}
_AGENT_ASSURE_PYCACHE_PREFIX = {str(pycache_prefix)!r}
_AGENT_ASSURE_GUARD_DIRECTORY = {str(guard_directory)!r}
_AGENT_ASSURE_NO_SITE_PATHS = {tuple(str(path) for path in no_site_paths)!r}
_AGENT_ASSURE_NO_SITE_ENV = {POST_R2_DESCENDANT_NO_SITE_ENV!r}
_AGENT_ASSURE_ORIGINAL_PYTHONPATH_ENV = {POST_R2_DESCENDANT_ORIGINAL_PYTHONPATH_ENV!r}
_AGENT_ASSURE_ORIGINAL_PYTHONPATH_PRESENT_ENV = {
        POST_R2_DESCENDANT_ORIGINAL_PYTHONPATH_PRESENT_ENV!r
    }
_AGENT_ASSURE_BOOTSTRAP_INSTALL = bool(
    globals().get("_AGENT_ASSURE_BOOTSTRAP_INSTALL", False)
)
_AGENT_ASSURE_MARKER = (
    _AGENT_ASSURE_GOVERNED_PYTHON,
    _AGENT_ASSURE_PYCACHE_PREFIX,
)
_AGENT_ASSURE_FLAGS = (
    "-B",
    "-s",
    "-P",
    "-X",
    "pycache_prefix=" + _AGENT_ASSURE_PYCACHE_PREFIX,
)
_AGENT_ASSURE_PYTHON_TOKEN = re.compile(
    r"(?<![0-9A-Za-z_.-])python(?:\\.exe)?(?![0-9A-Za-z_.-])",
    re.IGNORECASE,
)
_AGENT_ASSURE_SIMPLE_FLAG_CHARACTERS = frozenset("bBdEhiIOPqRsSuvVWx?")
_AGENT_ASSURE_BUILTIN_WARNING_CATEGORIES = frozenset({{
    "BytesWarning",
    "DeprecationWarning",
    "EncodingWarning",
    "FutureWarning",
    "ImportWarning",
    "PendingDeprecationWarning",
    "ResourceWarning",
    "RuntimeWarning",
    "SyntaxWarning",
    "UnicodeWarning",
    "UserWarning",
    "Warning",
}})

if not sys.dont_write_bytecode or os.path.normcase(
    sys.pycache_prefix or ""
) != os.path.normcase(_AGENT_ASSURE_PYCACHE_PREFIX):
    raise SystemExit("post-R2 descendant Python bytecode policy is not active")


def _agent_assure_normalized_executable(value):
    if not isinstance(value, (str, bytes, os.PathLike)):
        return None
    try:
        return os.path.normcase(os.path.abspath(os.fsdecode(value)))
    except (OSError, TypeError, ValueError):
        return None


def _agent_assure_python_option_name(value):
    return value.split("=", 1)[0].casefold()


def _agent_assure_validate_warning_option(value):
    try:
        text = os.fsdecode(value)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("governed Python -W option must be text") from exc
    fields = tuple(part.strip() for part in text.split(":"))
    if len(fields) > 5:
        raise RuntimeError("governed Python -W option has too many fields")
    category = fields[2] if len(fields) > 2 else ""
    if category and category not in _AGENT_ASSURE_BUILTIN_WARNING_CATEGORIES:
        raise RuntimeError(
            "governed Python -W category must be a builtin warning class"
        )


def _agent_assure_rewrite_python_options(arguments):
    rewritten = [arguments[0]]
    requested_no_site = False
    index = 1
    while index < len(arguments):
        token = arguments[index]
        if not isinstance(token, (str, bytes, os.PathLike)):
            raise RuntimeError("governed Python argv entries must be path-like strings")
        text = os.fsdecode(token)
        if text in {{"-c", "-m"}} or (
            len(text) > 2 and text[:2] in {{"-c", "-m"}}
        ):
            rewritten.extend(arguments[index:])
            return rewritten, requested_no_site
        if text == "--":
            rewritten.extend(arguments[index:])
            return rewritten, requested_no_site
        if text == "-" or not text.startswith("-"):
            rewritten.extend(arguments[index:])
            return rewritten, requested_no_site
        if text == "-X":
            if index + 1 >= len(arguments):
                raise RuntimeError("governed Python -X option is incomplete")
            option = os.fsdecode(arguments[index + 1])
            if _agent_assure_python_option_name(option) == "pycache_prefix":
                raise RuntimeError("caller cannot override the governed pycache prefix")
            rewritten.extend((token, arguments[index + 1]))
            index += 2
            continue
        if text.startswith("-X"):
            if _agent_assure_python_option_name(text[2:]) == "pycache_prefix":
                raise RuntimeError("caller cannot override the governed pycache prefix")
            rewritten.append(token)
            index += 1
            continue
        if text == "-W":
            if index + 1 >= len(arguments):
                raise RuntimeError("governed Python -W option is incomplete")
            _agent_assure_validate_warning_option(arguments[index + 1])
            rewritten.extend((token, arguments[index + 1]))
            index += 2
            continue
        if text.startswith("-W"):
            _agent_assure_validate_warning_option(text[2:])
            rewritten.append(token)
            index += 1
            continue
        if text == "--check-hash-based-pycs":
            if index + 1 >= len(arguments):
                raise RuntimeError(
                    "governed Python --check-hash-based-pycs option is incomplete"
                )
            rewritten.extend((token, arguments[index + 1]))
            index += 2
            continue
        if text.startswith("--check-hash-based-pycs=") or text.startswith("--"):
            rewritten.append(token)
            index += 1
            continue
        cluster = text[1:]
        if "S" in cluster:
            if not cluster or any(
                character not in _AGENT_ASSURE_SIMPLE_FLAG_CHARACTERS
                for character in cluster
            ):
                raise RuntimeError("governed Python -S option cannot be parsed safely")
            requested_no_site = True
            cluster = cluster.replace("S", "")
            if cluster:
                rewritten.append("-" + cluster)
        else:
            rewritten.append(token)
        index += 1
    return rewritten, requested_no_site


def _agent_assure_scalar_names_python(arguments):
    try:
        text = os.fsdecode(arguments)
    except (TypeError, ValueError):
        return False
    return bool(_AGENT_ASSURE_PYTHON_TOKEN.search(text))


def _agent_assure_guarded_arguments(arguments, explicit_executable, shell):
    governed = _agent_assure_normalized_executable(_AGENT_ASSURE_GOVERNED_PYTHON)
    explicit = _agent_assure_normalized_executable(explicit_executable)
    explicit_text = (
        os.fsdecode(explicit_executable)
        if isinstance(explicit_executable, (str, bytes, os.PathLike))
        else None
    )
    governed_name = os.path.basename(_AGENT_ASSURE_GOVERNED_PYTHON).casefold()
    governed_alias_names = {{governed_name, os.path.splitext(governed_name)[0]}}
    explicit_is_governed_alias = (
        explicit_text is not None
        and not os.path.dirname(explicit_text)
        and os.path.basename(explicit_text).casefold() in governed_alias_names
    )
    explicit_targets_governed = explicit == governed or explicit_is_governed_alias
    guarded_executable = (
        _AGENT_ASSURE_GOVERNED_PYTHON
        if explicit_is_governed_alias
        else explicit_executable
    )
    if isinstance(arguments, (str, bytes, os.PathLike)):
        if explicit_targets_governed or _agent_assure_scalar_names_python(arguments):
            raise RuntimeError("governed Python subprocess argv must be a sequence")
        return arguments, False, False, guarded_executable
    try:
        sequence = list(arguments)
    except TypeError as exc:
        raise RuntimeError("post-R2 subprocess argv must be a sequence") from exc
    if not sequence:
        raise RuntimeError("post-R2 subprocess argv must not be empty")
    argv_zero = _agent_assure_normalized_executable(sequence[0])
    argv_text = os.fsdecode(sequence[0])
    argv_name = os.path.basename(argv_text).casefold()
    argv_is_governed_alias = (
        not os.path.dirname(argv_text) and argv_name in governed_alias_names
    )
    argv_targets_governed = argv_zero == governed or argv_is_governed_alias
    if argv_targets_governed and explicit is not None and not explicit_targets_governed:
        raise RuntimeError("governed Python argv conflicts with subprocess executable")
    if not argv_targets_governed and not explicit_targets_governed:
        if shell and any(
            _agent_assure_scalar_names_python(token)
            for token in sequence
            if isinstance(token, (str, bytes, os.PathLike))
        ):
            raise RuntimeError("governed Python subprocess shell execution is forbidden")
        return sequence, False, False, guarded_executable
    if shell:
        raise RuntimeError("governed Python subprocess shell execution is forbidden")
    argv_zero_for_launch = (
        _AGENT_ASSURE_GOVERNED_PYTHON
        if argv_is_governed_alias
        else sequence[0]
    )
    rewritten, requested_no_site = _agent_assure_rewrite_python_options(
        [argv_zero_for_launch, *sequence[1:]]
    )
    return (
        [rewritten[0], *_AGENT_ASSURE_FLAGS, *rewritten[1:]],
        True,
        requested_no_site,
        guarded_executable,
    )


def _agent_assure_pop_environment_value(environment, name):
    matches = [
        key
        for key in environment
        if isinstance(key, str) and key.casefold() == name.casefold()
    ]
    if len(matches) > 1:
        raise RuntimeError("governed Python environment contains duplicate " + name)
    if not matches:
        return None
    value = environment.pop(matches[0])
    if not isinstance(value, str):
        raise RuntimeError("governed Python environment value must be text: " + name)
    return value


def _agent_assure_discard_environment_values(environment, name):
    for key in list(environment):
        if isinstance(key, str) and key.casefold() == name.casefold():
            environment.pop(key)


def _agent_assure_guarded_environment(environment, requested_no_site):
    try:
        guarded = os.environ.copy() if environment is None else dict(environment)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("governed Python environment must be a mapping") from exc
    original_pythonpath = _agent_assure_pop_environment_value(
        guarded,
        "PYTHONPATH",
    )
    original_parts = (
        [] if original_pythonpath is None else original_pythonpath.split(os.pathsep)
    )
    normalized_guard = _agent_assure_normalized_executable(
        _AGENT_ASSURE_GUARD_DIRECTORY
    )
    while original_parts and (
        _agent_assure_normalized_executable(original_parts[0]) == normalized_guard
    ):
        original_parts.pop(0)
    restored_pythonpath = os.pathsep.join(original_parts)
    guarded["PYTHONPATH"] = _AGENT_ASSURE_GUARD_DIRECTORY
    for internal_name in (
        _AGENT_ASSURE_NO_SITE_ENV,
        _AGENT_ASSURE_ORIGINAL_PYTHONPATH_ENV,
        _AGENT_ASSURE_ORIGINAL_PYTHONPATH_PRESENT_ENV,
    ):
        _agent_assure_discard_environment_values(guarded, internal_name)
    guarded[_AGENT_ASSURE_ORIGINAL_PYTHONPATH_ENV] = restored_pythonpath
    guarded[_AGENT_ASSURE_ORIGINAL_PYTHONPATH_PRESENT_ENV] = (
        "1" if original_pythonpath is not None else "0"
    )
    caller_path = _agent_assure_pop_environment_value(guarded, "PATH")
    governed_path = os.environ.get("PATH", "")
    if caller_path and caller_path != governed_path:
        guarded["PATH"] = governed_path + os.pathsep + caller_path
    else:
        guarded["PATH"] = governed_path
    for essential_name in ("COMSPEC", "SYSTEMROOT", "WINDIR"):
        essential_value = os.environ.get(essential_name)
        if essential_value is not None:
            _agent_assure_discard_environment_values(guarded, essential_name)
            guarded[essential_name] = essential_value
    guarded[_AGENT_ASSURE_NO_SITE_ENV] = "1" if requested_no_site else "0"
    for forbidden_name in (
        "PYTHONCASEOK",
        "PYTHONHOME",
        "PYTHONPLATLIBDIR",
        "PYTHONUSERBASE",
        "PYTHONWARNINGS",
    ):
        _agent_assure_discard_environment_values(guarded, forbidden_name)
    for policy_name, policy_value in (
        ("PYTHONDONTWRITEBYTECODE", "1"),
        ("PYTHONNOUSERSITE", "1"),
        ("PYTHONPYCACHEPREFIX", _AGENT_ASSURE_PYCACHE_PREFIX),
        ("PYTHONSAFEPATH", "1"),
    ):
        _agent_assure_discard_environment_values(guarded, policy_name)
        guarded[policy_name] = policy_value
    return guarded


def _agent_assure_startup_context():
    if _AGENT_ASSURE_BOOTSTRAP_INSTALL:
        return False, ()
    marker = _agent_assure_pop_environment_value(
        os.environ,
        _AGENT_ASSURE_NO_SITE_ENV,
    )
    if marker not in {{"0", "1"}}:
        raise SystemExit("post-R2 descendant startup marker is absent")
    original_pythonpath = _agent_assure_pop_environment_value(
        os.environ,
        _AGENT_ASSURE_ORIGINAL_PYTHONPATH_ENV,
    )
    original_pythonpath_present = _agent_assure_pop_environment_value(
        os.environ,
        _AGENT_ASSURE_ORIGINAL_PYTHONPATH_PRESENT_ENV,
    )
    if original_pythonpath is None or original_pythonpath_present not in {{"0", "1"}}:
        raise SystemExit("post-R2 descendant original Python path marker is invalid")
    pythonpath = _agent_assure_pop_environment_value(os.environ, "PYTHONPATH")
    if pythonpath is None or os.pathsep in pythonpath:
        raise SystemExit("post-R2 descendant guard path is absent")
    if _agent_assure_normalized_executable(
        pythonpath
    ) != _agent_assure_normalized_executable(_AGENT_ASSURE_GUARD_DIRECTORY):
        raise SystemExit("post-R2 descendant guard path is not first")
    if original_pythonpath_present == "1":
        os.environ["PYTHONPATH"] = original_pythonpath
        original_entries = tuple(original_pythonpath.split(os.pathsep))
    else:
        os.environ.pop("PYTHONPATH", None)
        original_entries = ()
    return marker == "1", original_entries


def _agent_assure_apply_no_site_paths(original_entries):
    preserved_counts = {{}}
    if not sys.flags.ignore_environment:
        for entry in original_entries:
            normalized = _agent_assure_normalized_executable(entry)
            preserved_counts[normalized] = preserved_counts.get(normalized, 0) + 1
    removed = {{
        _agent_assure_normalized_executable(path)
        for path in _AGENT_ASSURE_NO_SITE_PATHS
    }}
    filtered = []
    for entry in sys.path:
        normalized = _agent_assure_normalized_executable(entry)
        if normalized in removed:
            remaining = preserved_counts.get(normalized, 0)
            if remaining:
                preserved_counts[normalized] = remaining - 1
                filtered.append(entry)
            continue
        filtered.append(entry)
    sys.path[:] = filtered


def _agent_assure_restore_original_pythonpath(original_entries):
    if sys.flags.ignore_environment or not original_entries:
        return
    try:
        restored = [os.path.abspath(entry or os.curdir) for entry in original_entries]
    except (OSError, TypeError, ValueError) as exc:
        raise SystemExit("post-R2 descendant original Python path is invalid") from exc
    sys.path[:0] = restored


def _agent_assure_chain_original_sitecustomize(original_entries):
    if sys.flags.ignore_environment or not original_entries:
        return
    specification = importlib.machinery.PathFinder.find_spec(
        "sitecustomize",
        list(original_entries),
    )
    if specification is None or specification.loader is None:
        return
    origin = getattr(specification, "origin", None)
    if origin is not None and _agent_assure_normalized_executable(
        origin
    ) == _agent_assure_normalized_executable(__file__):
        return
    chained = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(chained)


_agent_assure_requested_no_site, _agent_assure_original_pythonpath = (
    _agent_assure_startup_context()
)


_agent_assure_existing_marker = getattr(
    subprocess,
    "_agent_assure_s1_post_r2_launch_guard",
    None,
)
if _agent_assure_existing_marker not in (None, _AGENT_ASSURE_MARKER):
    raise SystemExit("conflicting post-R2 Python launch guard")
if _agent_assure_existing_marker is None:
    _AgentAssureOriginalPopen = subprocess.Popen

    class _AgentAssureGovernedPopen(_AgentAssureOriginalPopen):
        def __init__(self, *positional, **keywords):
            if positional:
                arguments = positional[0]
                remaining = list(positional[1:])
                keyword_arguments = False
            elif "args" in keywords:
                arguments = keywords["args"]
                remaining = []
                keyword_arguments = True
            else:
                super().__init__(*positional, **keywords)
                return
            explicit_executable = (
                remaining[1]
                if len(remaining) > 1
                else keywords.get("executable")
            )
            shell = (
                remaining[7]
                if len(remaining) > 7
                else keywords.get("shell", False)
            )
            guarded, is_governed, requested_no_site, guarded_executable = (
                _agent_assure_guarded_arguments(
                    arguments,
                    explicit_executable,
                    shell,
                )
            )
            if is_governed:
                environment = (
                    remaining[9]
                    if len(remaining) > 9
                    else keywords.get("env")
                )
                guarded_environment = _agent_assure_guarded_environment(
                    environment,
                    requested_no_site,
                )
                if len(remaining) > 9:
                    remaining[9] = guarded_environment
                else:
                    keywords["env"] = guarded_environment
                if len(remaining) > 1:
                    remaining[1] = guarded_executable
                elif "executable" in keywords:
                    keywords["executable"] = guarded_executable
            if keyword_arguments:
                keywords["args"] = guarded
                super().__init__(**keywords)
                return
            super().__init__(
                guarded,
                *remaining,
                **keywords,
            )

    subprocess.Popen = _AgentAssureGovernedPopen
    subprocess._agent_assure_s1_post_r2_launch_guard = _AGENT_ASSURE_MARKER

_agent_assure_installed_popen = subprocess.Popen
_agent_assure_restore_original_pythonpath(_agent_assure_original_pythonpath)
if _agent_assure_requested_no_site:
    _agent_assure_apply_no_site_paths(_agent_assure_original_pythonpath)
else:
    _agent_assure_chain_original_sitecustomize(_agent_assure_original_pythonpath)
if (
    subprocess.Popen is not _agent_assure_installed_popen
    or getattr(subprocess, "_agent_assure_s1_post_r2_launch_guard", None)
    != _AGENT_ASSURE_MARKER
):
    raise SystemExit("post-R2 descendant Python launch guard was replaced")
"""


def _post_r2_safe_directory(path: Path, *, owner: str) -> os.stat_result:
    """Require one exact, existing directory without link/reparse traversal."""

    try:
        metadata = path.lstat()
    except OSError as exc:
        raise GovernanceError(f"{owner} is unavailable") from exc
    attributes = getattr(metadata, "st_file_attributes", 0)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)
    ):
        raise GovernanceError(f"{owner} is not a safe directory")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise GovernanceError(f"{owner} cannot be resolved safely") from exc
    if _early_normalized_path(resolved) != _early_normalized_path(path):
        raise GovernanceError(f"{owner} traverses a reparse point")
    return metadata


def _post_r2_process_temp_root() -> Path:
    """Validate and return the configured external process-temp root."""

    root = POST_R2_PROCESS_TEMP_ROOT
    if not root.is_absolute():
        raise GovernanceError("post-R2 process temporary root must be absolute")
    _post_r2_safe_directory(root, owner="post-R2 process temporary root")
    return root


def _post_r2_validate_process_temp(
    process_temp: Path,
    *,
    require_empty: bool,
) -> None:
    """Bind a process-temp directory to its safe governed root and prefix."""

    root = _post_r2_process_temp_root()
    if (
        not process_temp.is_absolute()
        or process_temp.parent != root
        or not process_temp.name.startswith(POST_R2_PROCESS_TEMP_PREFIX)
        or len(process_temp.name) <= len(POST_R2_PROCESS_TEMP_PREFIX)
    ):
        raise GovernanceError("post-R2 process temporary directory path changed")
    _post_r2_safe_directory(
        process_temp,
        owner="post-R2 process temporary directory",
    )
    if require_empty and any(process_temp.iterdir()):
        raise GovernanceError("post-R2 process temporary directory is not fresh")


def _post_r2_delete_readonly_file_by_handle(
    process_temp: Path,
    candidate: Path,
    relative: Path,
    original_error: BaseException,
) -> None:
    """Delete one verified Windows read-only file through its pinned handle."""

    if os.name != "nt":  # pragma: no cover - guarded by the callback on non-Windows hosts
        raise original_error

    import ctypes
    from ctypes import wintypes

    delete_access = 0x00010000
    file_read_attributes = 0x00000080
    file_write_attributes = 0x00000100
    file_share_read = 0x00000001
    file_share_write = 0x00000002
    open_existing = 3
    file_attribute_readonly = 0x00000001
    file_attribute_directory = 0x00000010
    file_attribute_reparse_point = 0x00000400
    file_flag_backup_semantics = 0x02000000
    file_flag_open_reparse_point = 0x00200000
    file_type_disk = 0x0001
    file_attribute_tag_info = 9
    file_disposition_info_ex = 21
    file_disposition_flag_delete = 0x00000001
    file_disposition_flag_posix_semantics = 0x00000002
    file_disposition_flag_force_image_section_check = 0x00000004
    file_disposition_flag_ignore_readonly_attribute = 0x00000010
    invalid_handle_value = wintypes.HANDLE(-1).value

    class FileAttributeTagInfo(ctypes.Structure):
        _fields_ = [
            ("file_attributes", wintypes.DWORD),
            ("reparse_tag", wintypes.DWORD),
        ]

    class FileDispositionInfoEx(ctypes.Structure):
        _fields_ = [("flags", wintypes.DWORD)]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    compare_string_ordinal = kernel32.CompareStringOrdinal
    compare_string_ordinal.argtypes = [
        wintypes.LPCWSTR,
        ctypes.c_int,
        wintypes.LPCWSTR,
        ctypes.c_int,
        wintypes.BOOL,
    ]
    compare_string_ordinal.restype = ctypes.c_int
    get_file_information = kernel32.GetFileInformationByHandleEx
    get_file_information.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    get_file_information.restype = wintypes.BOOL
    get_file_type = kernel32.GetFileType
    get_file_type.argtypes = [wintypes.HANDLE]
    get_file_type.restype = wintypes.DWORD
    get_final_path = kernel32.GetFinalPathNameByHandleW
    get_final_path.argtypes = [
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    get_final_path.restype = wintypes.DWORD
    set_file_information = kernel32.SetFileInformationByHandle
    set_file_information.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    set_file_information.restype = wintypes.BOOL

    def last_error(operation: str, path: Path) -> GovernanceError:
        cause = ctypes.WinError(ctypes.get_last_error())
        failure = GovernanceError(f"post-R2 cleanup could not {operation}: {path}")
        failure.__cause__ = cause
        return failure

    @contextmanager
    def opened_handle(
        path: Path,
        *,
        desired_access: int,
        share_access: int,
        directory: bool,
    ) -> Iterator[int]:
        flags = file_flag_open_reparse_point
        if directory:
            flags |= file_flag_backup_semantics
        handle = create_file(
            os.fspath(path),
            desired_access,
            share_access,
            None,
            open_existing,
            flags,
            None,
        )
        if handle == invalid_handle_value:
            raise last_error("open a pinned path", path)
        try:
            yield handle
        except BaseException as primary:
            if not close_handle(handle):
                primary.add_note(str(last_error("close a pinned handle", path)))
            raise
        else:
            if not close_handle(handle):
                raise last_error("close a pinned handle", path)

    def handle_attributes(handle: int, path: Path) -> int:
        information = FileAttributeTagInfo()
        if not get_file_information(
            handle,
            file_attribute_tag_info,
            ctypes.byref(information),
            ctypes.sizeof(information),
        ):
            raise last_error("read pinned-path attributes", path)
        return int(information.file_attributes)

    def handle_final_path(handle: int, path: Path) -> str:
        capacity = 32_768
        while True:
            buffer = ctypes.create_unicode_buffer(capacity)
            length = get_final_path(handle, buffer, capacity, 0)
            if length == 0:
                raise last_error("resolve a pinned path", path)
            if length < capacity:
                final_path = buffer.value
                break
            capacity = int(length)
            if capacity > 65_536:
                raise GovernanceError("post-R2 cleanup resolved path exceeds its safe bound")
        if final_path.startswith("\\\\?\\UNC\\"):
            final_path = "\\\\" + final_path[8:]
        elif final_path.startswith("\\\\?\\"):
            final_path = final_path[4:]
        return final_path

    def handle_path_matches(handle: int, path: Path) -> bool:
        final_path = handle_final_path(handle, path)
        expected_path = os.path.abspath(os.fspath(path))
        comparison = int(compare_string_ordinal(final_path, -1, expected_path, -1, True))
        if comparison == 0:
            raise last_error("compare a pinned path", path)
        return comparison == 2  # CSTR_EQUAL

    governed_root = _post_r2_process_temp_root()
    if _early_normalized_path(process_temp.parent) != _early_normalized_path(governed_root):
        raise GovernanceError("post-R2 cleanup callback root changed")

    directory_paths = [governed_root, process_temp]
    current = process_temp
    for part in relative.parts[:-1]:
        current /= part
        directory_paths.append(current)

    with ExitStack() as pinned_directories:
        for directory_path in directory_paths:
            directory_handle = pinned_directories.enter_context(
                opened_handle(
                    directory_path,
                    desired_access=file_read_attributes,
                    # Omitting FILE_SHARE_DELETE pins every ancestor name.
                    share_access=file_share_read | file_share_write,
                    directory=True,
                )
            )
            attributes = handle_attributes(directory_handle, directory_path)
            if not attributes & file_attribute_directory:
                raise GovernanceError("post-R2 cleanup candidate traverses a non-directory")
            if attributes & file_attribute_reparse_point:
                raise GovernanceError("post-R2 cleanup candidate traverses a reparse point")
            if not handle_path_matches(directory_handle, directory_path):
                raise GovernanceError("post-R2 cleanup directory resolved outside its lexical path")

        with opened_handle(
            candidate,
            # FileDispositionInformationEx formally requires write-attribute
            # access when IGNORE_READONLY_ATTRIBUTE is used; it does not
            # rewrite the shared read-only attribute.
            desired_access=delete_access | file_read_attributes | file_write_attributes,
            # Cleanup starts only after pytest exits. Exclusive sharing makes
            # a surviving reader/writer fail closed as a sharing violation.
            share_access=0,
            directory=False,
        ) as candidate_handle:
            attributes = handle_attributes(candidate_handle, candidate)
            if get_file_type(candidate_handle) != file_type_disk:
                raise GovernanceError("post-R2 cleanup candidate is not a disk file")
            if attributes & (file_attribute_directory | file_attribute_reparse_point):
                raise GovernanceError("post-R2 cleanup candidate is not a regular file")
            if not attributes & file_attribute_readonly:
                raise original_error
            if not handle_path_matches(candidate_handle, candidate):
                raise GovernanceError("post-R2 cleanup candidate resolved outside its lexical path")

            disposition = FileDispositionInfoEx(
                file_disposition_flag_delete
                | file_disposition_flag_posix_semantics
                | file_disposition_flag_force_image_section_check
                | file_disposition_flag_ignore_readonly_attribute
            )
            if not set_file_information(
                candidate_handle,
                file_disposition_info_ex,
                ctypes.byref(disposition),
                ctypes.sizeof(disposition),
            ):
                raise last_error("delete a read-only file through its pinned handle", candidate)

        try:
            candidate.lstat()
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise GovernanceError("post-R2 cleanup could not prove pinned-file deletion") from exc
        else:
            raise GovernanceError("post-R2 cleanup pinned-file deletion left the path present")


def _post_r2_retry_readonly_unlink(
    process_temp: Path,
    function: Callable[..., Any],
    raw_path: str,
    error: BaseException,
) -> None:
    """Retry only a contained Windows read-only regular-file unlink."""

    candidate = Path(raw_path)
    try:
        relative = candidate.relative_to(process_temp)
    except ValueError as exc:
        raise GovernanceError("post-R2 cleanup callback path leaves its governed root") from exc
    if (
        not isinstance(error, PermissionError)
        or getattr(error, "winerror", None) != 5
        or function is not os.unlink
        or not candidate.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} or ":" in part for part in relative.parts)
    ):
        raise error
    if os.name != "nt":
        raise error

    _post_r2_delete_readonly_file_by_handle(
        process_temp,
        candidate,
        relative,
        error,
    )


def _cleanup_post_r2_process_temp(process_temp: Path) -> None:
    """Delete only a freshly revalidated governed process-temp tree."""

    root = _post_r2_process_temp_root()
    if (
        not process_temp.is_absolute()
        or process_temp.parent != root
        or not process_temp.name.startswith(POST_R2_PROCESS_TEMP_PREFIX)
        or len(process_temp.name) <= len(POST_R2_PROCESS_TEMP_PREFIX)
    ):
        raise GovernanceError("post-R2 process temporary cleanup path changed")
    try:
        process_temp.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise GovernanceError("post-R2 process temporary cleanup path is unavailable") from exc
    _post_r2_validate_process_temp(process_temp, require_empty=False)
    if sys.version_info >= (3, 12):
        shutil.rmtree(
            process_temp,
            onexc=lambda function, path, error: _post_r2_retry_readonly_unlink(
                process_temp,
                function,
                path,
                error,
            ),
        )
    else:  # pragma: no cover - the accepted S1 runtime is frozen to Python 3.12
        shutil.rmtree(
            process_temp,
            onerror=lambda function, path, error_info: _post_r2_retry_readonly_unlink(
                process_temp,
                function,
                path,
                error_info[1],
            ),
        )
    try:
        process_temp.lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise GovernanceError("post-R2 process temporary cleanup could not prove absence") from exc
    else:
        raise GovernanceError("post-R2 process temporary cleanup left the directory present")
    _post_r2_process_temp_root()


def _cleanup_post_r2_process_temp_after_failure(
    process_temp: Path,
    primary: BaseException,
) -> None:
    """Preserve a primary failure while making cleanup failure inspectable."""

    try:
        _cleanup_post_r2_process_temp(process_temp)
    except BaseException as cleanup_error:
        primary.add_note(
            "post-R2 process temporary cleanup also failed: "
            f"{type(cleanup_error).__name__}: {cleanup_error}"
        )


def _post_r2_descendant_runtime_payloads(
    repository_root: Path,
    *,
    basetemp: Path,
    process_temp: Path,
) -> dict[str, bytes]:
    """Derive the exact ephemeral venv used by every Python descendant."""

    root = repository_root.resolve()
    runtime_root = process_temp / POST_R2_DESCENDANT_RUNTIME_DIRECTORY
    descendant_python = runtime_root / "Scripts/python.exe"
    pycache_prefix = basetemp / "python-bytecode-cache"
    configuration = (
        f"home = {_FROZEN_PYTHON_ROOT}\n"
        "implementation = CPython\n"
        "version_info = 3.12.13.final.0\n"
        "include-system-site-packages = false\n"
        f"executable = {_FROZEN_PYTHON_EXECUTABLE}\n"
    ).encode()
    authenticated_paths = (f"{root / 'src'}\n{root}\n{root / '.venv/Lib/site-packages'}\n").encode()
    startup_guard = _post_r2_descendant_sitecustomize_source(
        descendant_python,
        pycache_prefix,
        repository_root=root,
        site_packages=root / ".venv/Lib/site-packages",
    ).encode("utf-8")
    return {
        "pyvenv.cfg": configuration,
        f"Lib/site-packages/{POST_R2_DESCENDANT_RUNTIME_PATHS_FILE}": authenticated_paths,
        f"Lib/site-packages/{POST_R2_DESCENDANT_RUNTIME_GUARD_FILE}": startup_guard,
    }


def _post_r2_descendant_runtime_record(
    repository_root: Path,
    *,
    basetemp: Path,
    process_temp: Path,
) -> dict[str, Any]:
    """Describe the exact derived runtime without requiring it to persist."""

    runtime_root = process_temp / POST_R2_DESCENDANT_RUNTIME_DIRECTORY
    payloads = _post_r2_descendant_runtime_payloads(
        repository_root,
        basetemp=basetemp,
        process_temp=process_temp,
    )

    def file_record(relative_path: str) -> dict[str, Any]:
        payload = payloads[relative_path]
        return {
            "absolute_path": str(runtime_root / Path(relative_path)),
            "relative_path": relative_path,
            "size_bytes": len(payload),
            "sha256": raw_digest(payload),
        }

    return {
        "format": "agent-assure-s1-post-r2-descendant-runtime/1",
        "root": str(runtime_root),
        "derivation": "fresh_exact_files_from_authenticated_base_and_test_runtime",
        "tree_policy": "exact_regular_files_no_reparse_points",
        "python_executable": {
            "absolute_path": str(runtime_root / "Scripts/python.exe"),
            "relative_path": "Scripts/python.exe",
            "size_bytes": _FROZEN_PYTHON_EXECUTABLE_SIZE,
            "sha256": "sha256:" + _FROZEN_PYTHON_EXECUTABLE_SHA256,
        },
        "pyvenv_configuration": file_record("pyvenv.cfg"),
        "authenticated_paths": file_record(
            f"Lib/site-packages/{POST_R2_DESCENDANT_RUNTIME_PATHS_FILE}"
        ),
        "startup_guard": file_record(f"Lib/site-packages/{POST_R2_DESCENDANT_RUNTIME_GUARD_FILE}"),
    }


def _verify_post_r2_descendant_runtime(
    repository_root: Path,
    *,
    basetemp: Path,
    process_temp: Path,
    require_empty_user_temp: bool,
) -> dict[str, Any]:
    """Verify the derived runtime tree and fresh-cache invariants."""

    _post_r2_validate_process_temp(process_temp, require_empty=False)
    runtime_root = process_temp / POST_R2_DESCENDANT_RUNTIME_DIRECTORY
    user_temp = process_temp / POST_R2_PROCESS_USER_TEMP_DIRECTORY
    pycache_prefix = basetemp / "python-bytecode-cache"
    expected_payloads = _post_r2_descendant_runtime_payloads(
        repository_root,
        basetemp=basetemp,
        process_temp=process_temp,
    )
    descendant_python_relative = "Scripts/python.exe"
    expected_paths = {*expected_payloads, descendant_python_relative}
    expected_directories = set(POST_R2_DESCENDANT_RUNTIME_REQUIRED_DIRECTORIES)
    observed_paths: set[str] = set()
    observed_directories: set[str] = set()
    for directory in (
        runtime_root,
        runtime_root / "Scripts",
        runtime_root / "Lib",
        runtime_root / "Lib/site-packages",
        user_temp,
    ):
        _post_r2_safe_directory(
            directory,
            owner="post-R2 descendant runtime directory",
        )
    for candidate in runtime_root.rglob("*"):
        relative = candidate.relative_to(runtime_root).as_posix()
        metadata = candidate.lstat()
        attributes = getattr(metadata, "st_file_attributes", 0)
        if stat.S_ISLNK(metadata.st_mode) or bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT):
            raise GovernanceError("post-R2 descendant runtime contains a reparse point")
        if stat.S_ISDIR(metadata.st_mode):
            _post_r2_safe_directory(
                candidate,
                owner="post-R2 descendant runtime directory",
            )
            observed_directories.add(relative)
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise GovernanceError("post-R2 descendant runtime contains a non-file")
        observed_paths.add(relative)
        payload = candidate.read_bytes()
        if relative == descendant_python_relative:
            valid_payload = (
                len(payload) == _FROZEN_PYTHON_EXECUTABLE_SIZE
                and hashlib.sha256(payload).hexdigest() == _FROZEN_PYTHON_EXECUTABLE_SHA256
            )
        else:
            valid_payload = relative in expected_payloads and payload == expected_payloads[relative]
        if not valid_payload:
            raise GovernanceError("post-R2 descendant runtime bytes changed")
    if observed_directories != expected_directories:
        raise GovernanceError("post-R2 descendant runtime directory set changed")
    if observed_paths != expected_paths:
        raise GovernanceError("post-R2 descendant runtime file set changed")
    if require_empty_user_temp and any(user_temp.iterdir()):
        raise GovernanceError("post-R2 descendant user temporary directory is not fresh")
    if pycache_prefix.exists() or pycache_prefix.is_symlink():
        raise GovernanceError("post-R2 governed Python bytecode cache was materialized")
    return _post_r2_descendant_runtime_record(
        repository_root,
        basetemp=basetemp,
        process_temp=process_temp,
    )


def _prepare_post_r2_descendant_runtime(
    repository_root: Path,
    *,
    basetemp: Path,
    process_temp: Path,
) -> dict[str, Any]:
    """Create and verify an exact ephemeral descendant virtual environment."""

    try:
        _post_r2_validate_process_temp(process_temp, require_empty=True)
        runtime_root = process_temp / POST_R2_DESCENDANT_RUNTIME_DIRECTORY
        (runtime_root / "Scripts").mkdir(parents=True)
        (runtime_root / "Lib/site-packages").mkdir(parents=True)
        (process_temp / POST_R2_PROCESS_USER_TEMP_DIRECTORY).mkdir()
        descendant_python = runtime_root / "Scripts/python.exe"
        with descendant_python.open("xb") as handle:
            handle.write(_FROZEN_PYTHON_EXECUTABLE.read_bytes())
            handle.flush()
            os.fsync(handle.fileno())
        for relative_path, payload in _post_r2_descendant_runtime_payloads(
            repository_root,
            basetemp=basetemp,
            process_temp=process_temp,
        ).items():
            target = runtime_root / Path(relative_path)
            with target.open("xb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        return _verify_post_r2_descendant_runtime(
            repository_root,
            basetemp=basetemp,
            process_temp=process_temp,
            require_empty_user_temp=True,
        )
    except BaseException as primary:
        _cleanup_post_r2_process_temp_after_failure(process_temp, primary)
        raise


def _post_r2_pytest_bootstrap_source(
    repository_root: Path,
    *,
    basetemp: Path,
    process_temp: Path,
) -> str:
    """Return the fixed stdlib-only verifier that runs before pytest imports."""

    process_temp_root = POST_R2_PROCESS_TEMP_ROOT
    descendant_runtime_root = process_temp / POST_R2_DESCENDANT_RUNTIME_DIRECTORY
    descendant_python = descendant_runtime_root / "Scripts/python.exe"
    descendant_user_temp = process_temp / POST_R2_PROCESS_USER_TEMP_DIRECTORY
    descendant_payloads = _post_r2_descendant_runtime_payloads(
        repository_root,
        basetemp=basetemp,
        process_temp=process_temp,
    )
    descendant_guard_relative = f"Lib/site-packages/{POST_R2_DESCENDANT_RUNTIME_GUARD_FILE}"
    source = f"""\
import hashlib
import os
import runpy
import stat
import sys
from pathlib import Path

if not (sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode):
    raise RuntimeError("post-R2 Python isolation flags changed")
if "site" in sys.modules:
    raise RuntimeError("site imported before post-R2 runtime verification")

repository_root = Path(sys.argv[1])
source_root = Path(sys.argv[2])
site_packages = Path(sys.argv[3])
expected_pycache = Path(sys.argv[4])
expected_surface_count = int(sys.argv[5])
expected_surface_size = int(sys.argv[6])
expected_surface_digest = sys.argv[7]
pytest_arguments = sys.argv[8:]

if Path(sys.pycache_prefix or "") != expected_pycache:
    raise RuntimeError("post-R2 pycache prefix changed")

runtime_rows = []
for candidate in sorted(
    site_packages.rglob("*"),
    key=lambda value: value.as_posix().encode("utf-8"),
):
    relative = candidate.relative_to(site_packages)
    if "__pycache__" in relative.parts:
        continue
    metadata = candidate.lstat()
    attributes = getattr(metadata, "st_file_attributes", 0)
    if candidate.is_symlink() or bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT):
        raise RuntimeError(f"post-R2 runtime reparse point: {{relative.as_posix()}}")
    if candidate.is_dir():
        continue
    if not candidate.is_file():
        raise RuntimeError(f"post-R2 runtime non-file: {{relative.as_posix()}}")
    if candidate.suffix.casefold() in {{".pyc", ".pyo"}}:
        raise RuntimeError(f"post-R2 runtime direct bytecode: {{relative.as_posix()}}")
    payload = candidate.read_bytes()
    runtime_rows.append((relative.as_posix(), len(payload), hashlib.sha256(payload).digest()))
runtime_rows.sort(key=lambda row: row[0].encode("utf-8"))
runtime_digest = hashlib.sha256({POST_R2_TEST_RUNTIME_INVENTORY_DOMAIN!r})
for relative, size, file_digest in runtime_rows:
    encoded = relative.encode("utf-8")
    runtime_digest.update(len(encoded).to_bytes(8, "big"))
    runtime_digest.update(encoded)
    runtime_digest.update(size.to_bytes(8, "big"))
    runtime_digest.update(file_digest)
if (len(runtime_rows), sum(row[1] for row in runtime_rows), runtime_digest.hexdigest()) != (
    {POST_R2_TEST_RUNTIME_FILE_COUNT},
    {POST_R2_TEST_RUNTIME_SIZE_BYTES},
    {POST_R2_TEST_RUNTIME_SHA256!r},
):
    raise RuntimeError("post-R2 authenticated site-packages inventory changed")

exclude_path = repository_root / ".git/info/exclude"
exclude_payload = exclude_path.read_bytes()
if (len(exclude_payload), hashlib.sha256(exclude_payload).hexdigest()) != (
    {POST_R2_GIT_EXCLUDE_SIZE_BYTES},
    {POST_R2_GIT_EXCLUDE_SHA256!r},
):
    raise RuntimeError("post-R2 local-exclude policy changed")

directory_roots = {POST_R2_TEST_AFFECTING_DIRECTORIES!r}
tracked_root_files = {POST_R2_TRACKED_ROOT_FILES!r}
root_configs = {POST_R2_ROOT_TEST_CONFIG_PATHS!r}
surface_paths = set()

def admit_surface_file(path, relative):
    metadata = path.lstat()
    attributes = getattr(metadata, "st_file_attributes", 0)
    if path.is_symlink() or bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT):
        raise RuntimeError(f"post-R2 test-surface reparse point: {{relative}}")
    if not path.is_file():
        raise RuntimeError(f"post-R2 test-surface non-file: {{relative}}")
    if path.suffix.casefold() in {{".pyc", ".pyo"}}:
        raise RuntimeError(f"post-R2 repository direct bytecode: {{relative}}")
    surface_paths.add(relative)

for name in tracked_root_files:
    candidate = repository_root / name
    if not candidate.exists() and not candidate.is_symlink():
        raise RuntimeError(f"post-R2 tracked root file missing: {{name}}")
    admit_surface_file(candidate, name)
for name in root_configs:
    candidate = repository_root / name
    if candidate.exists() or candidate.is_symlink():
        admit_surface_file(candidate, name)
for candidate in repository_root.iterdir():
    if (
        candidate.name not in root_configs
        and candidate.suffix.casefold() in {{".py", ".pyc", ".pyo"}}
    ):
        admit_surface_file(candidate, candidate.name)
    if (
        candidate.is_dir()
        and not candidate.is_symlink()
        and candidate.name.isidentifier()
        and candidate.name not in directory_roots
    ):
        raise RuntimeError(f"post-R2 import-capable root directory: {{candidate.name}}")
for top_level in directory_roots:
    top = repository_root / top_level
    if not top.is_dir() or top.is_symlink():
        raise RuntimeError(f"post-R2 test-surface root changed: {{top_level}}")
    for current, directories, files in os.walk(top, topdown=True):
        current_path = Path(current)
        retained = []
        for name in sorted(directories, key=lambda value: value.encode("utf-8")):
            child = current_path / name
            relative = child.relative_to(repository_root).as_posix()
            metadata = child.lstat()
            attributes = getattr(metadata, "st_file_attributes", 0)
            if child.is_symlink() or bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT):
                raise RuntimeError(f"post-R2 test-surface reparse point: {{relative}}")
            if name != "__pycache__":
                retained.append(name)
        directories[:] = retained
        for name in sorted(files, key=lambda value: value.encode("utf-8")):
            candidate = current_path / name
            admit_surface_file(candidate, candidate.relative_to(repository_root).as_posix())

surface_rows = []
for relative in sorted(surface_paths, key=lambda value: value.encode("utf-8")):
    payload = (repository_root / relative).read_bytes()
    surface_rows.append((relative, len(payload), hashlib.sha256(payload).digest()))
surface_digest = hashlib.sha256({POST_R2_TEST_SURFACE_INVENTORY_DOMAIN!r})
for relative, size, file_digest in surface_rows:
    encoded = relative.encode("utf-8")
    surface_digest.update(len(encoded).to_bytes(8, "big"))
    surface_digest.update(encoded)
    surface_digest.update(size.to_bytes(8, "big"))
    surface_digest.update(file_digest)
if (
    len(surface_rows),
    sum(row[1] for row in surface_rows),
    "sha256:" + surface_digest.hexdigest(),
) != (expected_surface_count, expected_surface_size, expected_surface_digest):
    raise RuntimeError("post-R2 authenticated repository test surface changed")

process_temp_root = Path({str(process_temp_root)!r})
process_temp = Path({str(process_temp)!r})
descendant_runtime_root = Path({str(descendant_runtime_root)!r})
descendant_python = Path({str(descendant_python)!r})
descendant_user_temp = Path({str(descendant_user_temp)!r})
pytest_basetemp = expected_pycache.parent
expected_descendant_payloads = {descendant_payloads!r}
descendant_python_relative = "Scripts/python.exe"

def require_bound_directory(directory, owner):
    metadata = directory.lstat()
    attributes = getattr(metadata, "st_file_attributes", 0)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)
    ):
        raise RuntimeError(f"{{owner}} is not a safe directory")
    resolved = directory.resolve(strict=True)
    if os.path.normcase(os.path.abspath(resolved)) != os.path.normcase(
        os.path.abspath(directory)
    ):
        raise RuntimeError(f"{{owner}} traverses a reparse point")

if (
    not process_temp_root.is_absolute()
    or not process_temp.is_absolute()
    or process_temp.parent != process_temp_root
    or not process_temp.name.startswith({POST_R2_PROCESS_TEMP_PREFIX!r})
    or len(process_temp.name) <= len({POST_R2_PROCESS_TEMP_PREFIX!r})
    or descendant_runtime_root.parent != process_temp
    or descendant_user_temp.parent != process_temp
    or pytest_basetemp.parent != process_temp
    or pytest_basetemp.name != {POST_R2_PYTEST_BASETEMP_DIRECTORY!r}
    or pytest_basetemp.exists()
    or pytest_basetemp.is_symlink()
):
    raise RuntimeError("post-R2 process temporary path binding changed")
require_bound_directory(process_temp_root, "post-R2 process temporary root")
require_bound_directory(process_temp, "post-R2 process temporary directory")
if Path(os.environ.get("TEMP", "")) != descendant_user_temp:
    raise RuntimeError("post-R2 descendant temporary directory changed")
if os.environ.get("TMP") != os.environ.get("TEMP"):
    raise RuntimeError("post-R2 descendant temporary directory aliases changed")
for directory in (
    descendant_runtime_root,
    descendant_runtime_root / "Scripts",
    descendant_runtime_root / "Lib",
    descendant_runtime_root / "Lib/site-packages",
    descendant_user_temp,
):
    require_bound_directory(directory, "post-R2 descendant runtime directory")
observed_descendant_paths = set()
observed_descendant_directories = set()
for current, directories, files in os.walk(descendant_runtime_root, topdown=True):
    current_path = Path(current)
    for name in sorted(directories, key=lambda value: value.encode("utf-8")):
        child = current_path / name
        require_bound_directory(child, "post-R2 descendant runtime directory")
        observed_descendant_directories.add(
            child.relative_to(descendant_runtime_root).as_posix()
        )
    for name in sorted(files, key=lambda value: value.encode("utf-8")):
        candidate = current_path / name
        relative = candidate.relative_to(descendant_runtime_root).as_posix()
        metadata = candidate.lstat()
        attributes = getattr(metadata, "st_file_attributes", 0)
        if (
            not candidate.is_file()
            or candidate.is_symlink()
            or bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)
        ):
            raise RuntimeError("post-R2 descendant runtime non-regular file")
        payload = candidate.read_bytes()
        if relative == descendant_python_relative:
            valid_payload = (
                len(payload) == {_FROZEN_PYTHON_EXECUTABLE_SIZE}
                and hashlib.sha256(payload).hexdigest()
                == {_FROZEN_PYTHON_EXECUTABLE_SHA256!r}
            )
        else:
            expected_payload = expected_descendant_payloads.get(relative)
            valid_payload = expected_payload is not None and payload == expected_payload
        if not valid_payload:
            raise RuntimeError("post-R2 descendant runtime bytes changed")
        observed_descendant_paths.add(relative)
if observed_descendant_directories != set(
    {POST_R2_DESCENDANT_RUNTIME_REQUIRED_DIRECTORIES!r}
):
    raise RuntimeError("post-R2 descendant runtime directory set changed")
if observed_descendant_paths != {{*expected_descendant_payloads, descendant_python_relative}}:
    raise RuntimeError("post-R2 descendant runtime file set changed")
if expected_pycache.exists() or expected_pycache.is_symlink():
    raise RuntimeError("post-R2 bytecode cache materialized before pytest")

sys.executable = str(descendant_python)
descendant_guard_source = expected_descendant_payloads[{descendant_guard_relative!r}]
exec(
    compile(
        descendant_guard_source,
        str(descendant_runtime_root / {descendant_guard_relative!r}),
        "exec",
    ),
    {{
        "__name__": "sitecustomize",
        "__file__": str(descendant_runtime_root / {descendant_guard_relative!r}),
        "_AGENT_ASSURE_BOOTSTRAP_INSTALL": True,
    }},
)
sys.path[:0] = [str(source_root), str(repository_root), str(site_packages)]
sys.argv = ["pytest", *pytest_arguments]
runpy.run_module("pytest", run_name="__main__", alter_sys=True)
"""
    # Governance records reject control characters in canonical strings.  The
    # actual ``-c`` argument is therefore one line whose repr-literal expands
    # to the reviewed bootstrap only after the isolated interpreter starts.
    return "exec(" + repr(source) + ")"


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
MAX_GIT_DIAGNOSTIC_CHARS: Final = 512
MAX_OPENSSH_DIAGNOSTIC_CHARS: Final = 512

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
CORRECTIVE_UTC_100NS_PATTERN: Final = re.compile(
    r"^(?P<whole>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(?:\.(?P<fraction>[0-9]{1,7}))?Z$"
)


class GovernanceError(ValueError):
    """Raised when a governance input or artifact violates the frozen contract."""


class _GitBlobSemanticError(GovernanceError):
    """A tree entry is absent or is not the exact regular blob requested."""


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


# Generation 2 deliberately has a separate, frozen estimation implementation.
# Generation-1 builders and validators above and below remain available for the
# signed historical closure.  In particular, no generation-2 record is ever
# interpreted by a generation-1 digest domain.
_FORECAST_V2_INPUT_RULE_IDS: Final = (
    "covered-criterion-cardinality/v1",
    "ticket-command-cardinality/v1",
    "cumulative-active-profile-cardinality/v1",
    "ticket-golden-case-cardinality/v1",
    "ticket-normative-section-cardinality/v1",
    "exact-occurrence-anchor/v1",
    "evidence-receipt-instance-cardinality/v1",
    "ticket-existing-anchor-cardinality/v1",
    "ticket-change-role-cardinality/v1",
    "artifact-operation-class/v1",
    "release-entry-ticket-cardinality/v1",
    "ticket-file-scope-cardinality/v1",
    "structured-contract-key-cardinality/v1",
    "ticket-dependency-cardinality/v1",
    "empty-file-scope-indicator/v1",
    "covered-work-package-cardinality/v1",
    "assigned-work-package-edge-cardinality/v1",
)
_FORECAST_V2_QUANTITY_RULE_IDS: Final = (
    "criteria-coverage-count/v1",
    "work-package-count/v1",
    "structured-contract-count/v1",
    "bounded-surface-groups/v1",
    "verification-obligation-count/v1",
    "fixture-floor/v1",
    "normative-groups/v1",
    "receipt-instance-count/v1",
    "integration-edge-floor/v1",
    "release-operation-class/v1",
    "cumulative-optional-profile-count/v1",
    "unresolved-file-scope-indicator/v1",
)
_FORECAST_V2_WORK_UNITS: Final = (
    ("WI-01", "acceptance_analysis_unit", 1, 2, 1),
    ("WI-02", "work_package_design_unit", 2, 4, 1),
    ("WI-03", "structured_contract_unit", 2, 5, 2),
    ("WI-04", "implementation_surface_unit", 3, 7, 1),
    ("WI-05", "verification_unit", 2, 5, 2),
    ("WI-06", "fixture_vector_unit", 1, 3, 1),
    ("WI-07", "documentation_trace_unit", 1, 2, 1),
    ("WI-08", "evidence_receipt_unit", 1, 3, 2),
    ("WI-09", "integration_edge_unit", 1, 3, 1),
    ("WI-10", "release_operation_unit", 3, 8, 2),
    ("WI-11", "cumulative_profile_control_unit", 2, 5, 2),
    ("WI-12", "unresolved_scope_uncertainty_unit", 2, 10, 2),
)


def aggregation_method_registry_v2() -> dict[str, Any]:
    """Return the exact generation-2, no-diversification aggregation registry."""

    definition: dict[str, Any] = {
        "format": "agent-assure-delivery-forecast-aggregation-method/2",
        "method_id": METHOD_ID,
        "version": "1.1.0",
        "definition_digest_domain": METHOD_V2_DOMAIN,
        "unit": "focused_person_hour",
        "evaluated_quantile_ranks": [0.5, 0.9],
        "quantile_definition": "Q_p(X)=inf{x:F_X(x)>=p}",
        "effort_scope": {
            "included": ["engineering_effort", "reviewer_effort"],
            "excluded": ["elapsed_wait_time", "calendar_duration", "parallelism_discount"],
        },
        "dependence_model": {
            "name": "full_positive_rank_dependence_no_diversification_credit",
            "definition": (
                "For every included workload component i, X_i=Q_i(U), where one U "
                "distributed Uniform(0,1) is shared globally and every Q_i is a "
                "nondecreasing generalized-inverse marginal quantile function."
            ),
            "independence_claimed": False,
            "upper_bound_claimed": False,
            "diversification_credit": "none",
            "reviewer_effort_coupling": (
                "Reviewer-effort P50 entries use the same shared-rank planning assumption; "
                "only their additive P50 is reported."
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
                "source_field": "reviewer_p50_effort_hours",
                "quantile_rank": 0.5,
            },
        },
        "scenario_aggregation": {
            "partition_field": "scenario_class",
            "required_partitions": ["stable_core_committed", "optional_profile_planned"],
            "full_portfolio_operation": ("checked_effort_and_occurrence_sum_with_ticket_id_union"),
        },
        "interpretation": [
            (
                "At the declared ranks, additive quantiles are mathematically exact only "
                "under the stated comonotonic construction."
            ),
            (
                "Full positive rank dependence gives no diversification credit; it is a "
                "planning assumption, not a distribution-free bound or a claim that reality "
                "is maximally dependent."
            ),
            (
                "Two elicited ranks do not identify a complete marginal distribution, "
                "confidence interval, or probability of meeting a calendar date."
            ),
            (
                "Stable-core and optional-profile partitions are reported separately before "
                "the full-portfolio sum."
            ),
            "Elapsed waits remain separate and cannot be added to person-hours.",
        ],
        "arithmetic": {
            "input_type": "nonnegative integer hours",
            "maximum_exact_integer": 2**53 - 1,
            "rounding": "none after catalog unit multiplication",
        },
    }
    method = {**definition, "definition_digest": domain_digest(METHOD_V2_DOMAIN, definition)}
    projection = {
        "format": "agent-assure-delivery-forecast-aggregation-registry/2",
        "spec_revision": SPEC_REVISION,
        "registry_digest_domain": METHOD_REGISTRY_V2_DOMAIN,
        "methods": [method],
    }
    return {
        **projection,
        "registry_digest": domain_digest(METHOD_REGISTRY_V2_DOMAIN, projection),
    }


def validate_estimation_catalog_v2(catalog: Mapping[str, Any], schema: Mapping[str, Any]) -> None:
    """Validate the frozen catalog without evaluating catalog expression strings."""

    _validate_json_schema(catalog, schema, owner="delivery forecast estimation catalog")
    projection = {key: value for key, value in catalog.items() if key != "catalog_digest"}
    calculated = domain_digest(ESTIMATION_CATALOG_V2_DOMAIN, projection)
    if catalog.get("catalog_digest") != calculated:
        raise GovernanceError("estimation catalog digest mismatch")
    if calculated != ESTIMATION_CATALOG_V2_DIGEST:
        raise GovernanceError("estimation catalog differs from the frozen generation-2 catalog")
    if catalog.get("format") != "agent-assure-delivery-forecast-estimation-catalog/1":
        raise GovernanceError("estimation catalog format changed")
    if catalog.get("model_revision") != "bottom-up-wbs/1":
        raise GovernanceError("estimation catalog model revision changed")
    derivation = _as_object(catalog.get("workload_derivation"), owner="workload derivation")
    input_rules = _as_array(derivation.get("input_count_rules"), owner="input count rules")
    quantity_rules = _as_array(derivation.get("quantity_rules"), owner="quantity rules")
    observed_input_rule_ids = tuple(
        _required_string(_as_object(rule, owner="input rule"), "rule_id") for rule in input_rules
    )
    if observed_input_rule_ids != _FORECAST_V2_INPUT_RULE_IDS:
        raise GovernanceError("estimation catalog input rule IDs or order changed")
    observed_quantity_rule_ids = tuple(
        _required_string(_as_object(rule, owner="quantity rule"), "rule_id")
        for rule in quantity_rules
    )
    if observed_quantity_rule_ids != _FORECAST_V2_QUANTITY_RULE_IDS:
        raise GovernanceError("estimation catalog quantity rule IDs or order changed")
    units = _as_array(catalog.get("work_unit_catalog"), owner="work unit catalog")
    observed_units = tuple(
        (
            f"WI-{index:02d}",
            _required_string(_as_object(unit, owner="work unit"), "unit_id"),
            _required_integer(_as_object(unit, owner="work unit"), "p50_effort_hours"),
            _required_integer(_as_object(unit, owner="work unit"), "p90_effort_hours"),
            _required_integer(_as_object(unit, owner="work unit"), "reviewer_p50_effort_hours"),
        )
        for index, unit in enumerate(units, 1)
    )
    if observed_units != _FORECAST_V2_WORK_UNITS:
        raise GovernanceError("estimation catalog work-unit identities or rates changed")


def _resolve_aggregation_method_v2(registry: Mapping[str, Any]) -> dict[str, Any]:
    expected = aggregation_method_registry_v2()
    if dict(registry) != expected:
        raise GovernanceError(
            "generation-2 aggregation registry differs from its frozen definition"
        )
    return cast(dict[str, Any], expected["methods"][0])


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


def _checked_forecast_v2_integer(value: int, *, owner: str) -> int:
    if type(value) is not int or value < 0 or value > 2**53 - 1:
        raise GovernanceError(f"{owner} is outside the nonnegative exact-integer range")
    return value


def _checked_forecast_v2_sum(values: Iterable[int], *, owner: str) -> int:
    result = 0
    for value in values:
        _checked_forecast_v2_integer(value, owner=owner)
        result += value
        _checked_forecast_v2_integer(result, owner=owner)
    return result


def _checked_forecast_v2_multiply(left: int, right: int, *, owner: str) -> int:
    _checked_forecast_v2_integer(left, owner=owner)
    _checked_forecast_v2_integer(right, owner=owner)
    return _checked_forecast_v2_integer(left * right, owner=owner)


def _forecast_v2_occurrences(
    snapshot: RoadmapSnapshot,
) -> dict[str, list[tuple[int, dict[str, Any]]]]:
    result: dict[str, list[tuple[int, dict[str, Any]]]] = {
        _required_string(ticket, "id"): [] for ticket in snapshot.tickets
    }
    entries = _as_array(snapshot.release_train.get("entries"), owner="release-train.entries")
    for entry_index, raw_entry in enumerate(entries, 1):
        entry = _as_object(raw_entry, owner=f"release-train entry {entry_index}")
        for ticket_id in _required_string_array(entry, "ticket_ids"):
            if ticket_id not in result:
                raise GovernanceError(f"release train references unknown ticket: {ticket_id}")
            result[ticket_id].append((entry_index, entry))
    if any(not values for values in result.values()):
        raise GovernanceError("every roadmap ticket must have at least one release occurrence")
    return result


def _forecast_v2_source_obligations(
    ticket: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    ticket_id = _required_string(ticket, "id")
    criteria: list[dict[str, Any]] = []
    for index, criterion in enumerate(_required_string_array(ticket, "acceptance_criteria"), 1):
        criteria.append(
            {
                "obligation_id": f"AC-{index:03d}",
                "source_digest": domain_digest(
                    ACCEPTANCE_CRITERION_SOURCE_DOMAIN,
                    {
                        "ticket_id": ticket_id,
                        "criterion_index": index,
                        "criterion": criterion,
                    },
                ),
            }
        )
    packages: list[dict[str, Any]] = []
    for raw_package in _as_array(
        ticket.get("work_packages", []), owner=f"{ticket_id}.work_packages"
    ):
        package = _as_object(raw_package, owner=f"{ticket_id} work package")
        packages.append(
            {
                "obligation_id": _required_string(package, "id"),
                "source_digest": domain_digest(
                    WORK_PACKAGE_SOURCE_DOMAIN,
                    {"ticket_id": ticket_id, "work_package": package},
                ),
            }
        )
    return criteria, packages


def _forecast_v2_count_contract_keys(value: object) -> int:
    if isinstance(value, dict):
        own = sum(
            1
            for key in value
            if isinstance(key, str) and (key.endswith("_contract") or key.endswith("_contracts"))
        )
        return own + sum(_forecast_v2_count_contract_keys(item) for item in value.values())
    if isinstance(value, list):
        return sum(_forecast_v2_count_contract_keys(item) for item in value)
    return 0


_FORECAST_V2_WAIT_TOKENS: Final = frozenset(
    {"wait", "elapsed", "window", "fresh", "freshness", "age", "before", "after", "duration"}
)


def _forecast_v2_source_contains_wait_token(value: object) -> bool:
    strings: list[str] = []

    def visit(item: object) -> None:
        if isinstance(item, dict):
            for key in sorted(item, key=_utf8_sort_key):
                strings.append(key.lower())
                visit(item[key])
        elif isinstance(item, list):
            for child in item:
                visit(child)
        elif isinstance(item, str):
            strings.append(item.lower())

    visit(value)
    return any(
        token in _FORECAST_V2_WAIT_TOKENS
        for string in strings
        for token in re.split("[^a-z]+", string)
        if token
    )


def _forecast_v2_numeric_waits(
    source: object,
    *,
    source_obligation_id: str,
) -> list[dict[str, Any]]:
    candidates: list[tuple[list[str | int], int]] = []

    def visit(value: object, path: list[str | int]) -> None:
        if isinstance(value, dict):
            for key in sorted(value, key=_utf8_sort_key):
                child = value[key]
                child_path = [*path, key]
                if key in {"minimum_elapsed_seconds", "minimum_observation_window_days"}:
                    if isinstance(child, bool) or not isinstance(child, int | float):
                        raise GovernanceError("elapsed wait source must be numeric")
                    hours = Decimal(str(child))
                    if key == "minimum_elapsed_seconds":
                        hours /= Decimal(3600)
                    else:
                        hours *= Decimal(24)
                    if not hours.is_finite() or hours < 0 or hours != hours.to_integral_value():
                        raise GovernanceError(
                            "elapsed wait source does not convert to integral hours"
                        )
                    candidates.append((child_path, int(hours)))
                visit(child, child_path)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, [*path, index])

    visit(source, [])
    waits: list[dict[str, Any]] = []
    for index, (field_path, hours) in enumerate(candidates, 1):
        digest = domain_digest(
            ELAPSED_WAIT_REQUIREMENT_DOMAIN,
            {
                "source_obligation_id": source_obligation_id,
                "field_path": field_path,
                "source_value": _forecast_v2_value_at_path(source, field_path),
            },
        )
        waits.append(
            {
                "wait_id": f"WAIT-{index:03d}",
                "source_obligation_id": source_obligation_id,
                "minimum_elapsed_hours": hours,
                "requirement_digest": digest,
            }
        )
    return waits


def _forecast_v2_value_at_path(value: object, path: Sequence[str | int]) -> object:
    current = value
    for component in path:
        if isinstance(component, str) and isinstance(current, dict):
            current = current[component]
        elif isinstance(component, int) and isinstance(current, list):
            current = current[component]
        else:
            raise GovernanceError("invalid elapsed wait field path")
    return current


def _forecast_v2_receipt_instances(
    ticket: Mapping[str, Any], assigned_packages: Sequence[Mapping[str, Any]], *, is_final: bool
) -> int:
    if assigned_packages:
        batch_components = sum(
            1
            for package in assigned_packages
            if "profile_admission_instance_id" in package
            or "stable_core_renewal_instance_id" in package
        )
        if batch_components:
            return batch_components + 1
        result = 0
        for package in assigned_packages:
            singular = 1 if isinstance(package.get("completion_receipt_contract"), dict) else 0
            plural_value = package.get("completion_receipt_contracts", [])
            plural = len(plural_value) if isinstance(plural_value, list) else 0
            result += max(1, singular + plural)
        return result
    scope = _required_string(
        _as_object(
            _as_object(ticket.get("delivery"), owner="ticket delivery").get("estimate"),
            owner="ticket estimate",
        ),
        "scope",
    )
    if scope != "ticket_completion" or is_final:
        return len(_required_string_array(ticket, "required_completion_receipts"))
    return 0


def _forecast_v2_release_anchor(entry: Mapping[str, Any]) -> str:
    ticket_ids = _required_string_array(entry, "ticket_ids")
    for candidate in ("V1-REL-02", "V1-REL-01", "V1-CAND-01", "V1-DIST-01"):
        if candidate in ticket_ids:
            return candidate
    return ticket_ids[0]


def _forecast_v2_release_operation_units(artifact_kind: str) -> int:
    if artifact_kind == "governance-bundle":
        return 1
    if artifact_kind in {
        "evidence-bundle",
        "package-preview",
        "staged-final-bytes",
        "staged-profile-candidate",
    }:
        return 2
    if artifact_kind in {"package-promotion", "exact-byte-profile-promotion"}:
        return 3
    raise GovernanceError(f"unknown release artifact kind: {artifact_kind}")


def _forecast_v2_profile_count(ticket_id: str, train: str) -> int:
    if ticket_id != "V1-REL-02":
        return 0
    mapping = {
        "stable-1.0": 0,
        "oscal-1.1": 1,
        "otel-1.2": 2,
        "statistics-1.3": 4,
        "structural-1.4": 5,
        "formal-1.5": 6,
        "intervention-1.6": 7,
    }
    try:
        return mapping[train]
    except KeyError as exc:
        raise GovernanceError(f"unknown release train: {train}") from exc


def _forecast_v2_file_scope_observation(snapshot: RoadmapSnapshot) -> dict[str, Any]:
    resolved = sum(1 for ticket in snapshot.tickets if ticket.get("resolved_allowed_files"))
    return {
        "ticket_count": len(snapshot.tickets),
        "resolved_ticket_count": resolved,
        "unresolved_ticket_count": len(snapshot.tickets) - resolved,
        "evidence_basis": "roadmap_resolved_allowed_files_cardinality",
        "interpretation": "unresolved_scope_not_zero_implementation_work",
        "estimate_status": "nonbinding_placeholders_pending_dispatch_scope_resolution",
        "rebaseline_trigger": (
            "resolve_approved_file_scope_at_ticket_dispatch_and_reestimate_when_concrete_"
            "surface_count_differs"
        ),
    }


def build_authoring_ledger_v2(
    snapshot: RoadmapSnapshot,
    catalog: Mapping[str, Any],
    *,
    baseline_observations_digest_value: str,
    inventory_completed_at: str,
    decision_evidence: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build every generation-2 occurrence from digest-bound roadmap obligations.

    Catalog expressions are explanatory text only.  All admitted rule IDs map
    to the explicit Python operations below; there is no ``eval`` path.
    """

    if catalog.get("catalog_digest") != ESTIMATION_CATALOG_V2_DIGEST:
        raise GovernanceError("generation-2 ledger requires the frozen estimation catalog")
    if SHA256_PATTERN.fullmatch(baseline_observations_digest_value) is None:
        raise GovernanceError("baseline observations digest is invalid")
    _parse_utc(inventory_completed_at, owner="inventory_completed_at_utc")
    occurrence_map = _forecast_v2_occurrences(snapshot)
    entry_occurrence_counts: dict[str, int] = {}
    rows: list[dict[str, Any]] = []

    for ticket in snapshot.tickets:
        ticket_id = _required_string(ticket, "id")
        delivery = _as_object(ticket.get("delivery"), owner=f"{ticket_id}.delivery")
        estimate = _as_object(delivery.get("estimate"), owner=f"{ticket_id}.delivery.estimate")
        estimate_scope = _required_string(estimate, "scope")
        ticket_occurrences = occurrence_map[ticket_id]
        source_criteria, source_packages = _forecast_v2_source_obligations(ticket)
        package_by_id = {
            _required_string(_as_object(package, owner="work package"), "id"): _as_object(
                package, owner="work package"
            )
            for package in _as_array(ticket.get("work_packages", []), owner="work packages")
        }
        criterion_values = _required_string_array(ticket, "acceptance_criteria")

        prior = {
            "unit": estimate.get("unit"),
            "p50": estimate.get("p50"),
            "p90": estimate.get("p90"),
            "review_effort_p50_days": delivery.get("review_effort_p50_days"),
            "confidence": estimate.get("confidence"),
            "basis": estimate.get("basis"),
        }
        acceptance_set_projection = {
            "ticket_id": ticket_id,
            "obligations": copy.deepcopy(source_criteria),
        }
        work_package_set_projection = {
            "ticket_id": ticket_id,
            "obligations": copy.deepcopy(source_packages),
        }
        dependency_ids = _required_string_array(ticket, "depends_on")
        dependency_projection = {"ticket_id": ticket_id, "depends_on": dependency_ids}
        execution_proposals: list[dict[str, Any]] = []

        for occurrence_index, (_entry_index, entry) in enumerate(ticket_occurrences, 1):
            sprint = _required_string(entry, "sprint")
            release = _required_string(entry, "release")
            occurrence_id = f"{ticket_id}@{sprint}/{release}"
            if occurrence_id in entry_occurrence_counts:
                raise GovernanceError(f"duplicate forecast occurrence: {occurrence_id}")
            entry_occurrence_counts[occurrence_id] = 1
            if estimate_scope == "ticket_completion":
                criterion_indices = [
                    index
                    for index in range(len(source_criteria))
                    if index % len(ticket_occurrences) == occurrence_index - 1
                ]
                recurrence_binding = "ticket_lifecycle_once"
            else:
                criterion_indices = list(range(len(source_criteria)))
                recurrence_binding = "once_per_occurrence"
            assigned_package_ids = [
                package["obligation_id"]
                for package in source_packages
                if _required_string(package_by_id[package["obligation_id"]], "planned_sprint")
                == sprint
            ]
            assigned_packages = [package_by_id[value] for value in assigned_package_ids]
            covered_criteria: list[dict[str, Any]] = []
            covered_sources: list[tuple[str, object]] = []
            for ordinal, source_index in enumerate(criterion_indices, 1):
                source = source_criteria[source_index]
                covered_criteria.append(
                    {
                        **source,
                        "recurrence_binding": recurrence_binding,
                        "primary_work_item_id": "WI-01",
                        "primary_work_unit_ordinal": ordinal,
                    }
                )
                covered_sources.append((source["obligation_id"], criterion_values[source_index]))
            covered_packages: list[dict[str, Any]] = []
            for ordinal, package_id in enumerate(assigned_package_ids, 1):
                source = next(
                    item for item in source_packages if item["obligation_id"] == package_id
                )
                covered_packages.append(
                    {
                        **source,
                        "recurrence_binding": "work_package_once_at_declared_sprint",
                        "primary_work_item_id": "WI-02",
                        "primary_work_unit_ordinal": ordinal,
                    }
                )
                covered_sources.append((package_id, package_by_id[package_id]))
            occurrence_projection = {
                "ticket_id": ticket_id,
                "sprint": sprint,
                "release": release,
            }
            coverage_projection = {
                "acceptance_criteria": covered_criteria,
                "work_packages": covered_packages,
                "occurrence_anchor_digest": domain_digest(
                    RELEASE_OCCURRENCE_SOURCE_DOMAIN, occurrence_projection
                ),
                "occurrence_anchor_work_item_id": "WI-09",
                "occurrence_anchor_work_unit_ordinal": 1,
            }
            coverage = {
                **coverage_projection,
                "coverage_digest": domain_digest(
                    OBLIGATION_COVERAGE_V2_DOMAIN, coverage_projection
                ),
            }

            is_first = occurrence_index == 1
            is_final = occurrence_index == len(ticket_occurrences)
            entry_anchor = _forecast_v2_release_anchor(entry)
            workload_vector = {
                "acceptance_criterion_coverage_count": len(covered_criteria),
                "acceptance_command_count": len(
                    _required_string_array(ticket, "acceptance_commands")
                ),
                "cumulative_optional_profile_count": _forecast_v2_profile_count(
                    ticket_id, _required_string(entry, "train")
                ),
                "evidence_receipt_instance_count": _forecast_v2_receipt_instances(
                    ticket, assigned_packages, is_final=is_final
                ),
                "existing_anchor_count": (
                    len(_required_string_array(ticket, "existing_anchors_to_verify"))
                    if is_first
                    else 0
                ),
                "golden_case_count": len(_required_string_array(ticket, "golden_case_ids")),
                "normative_section_count": (
                    len(_required_string_array(ticket, "normative_sections")) if is_first else 0
                ),
                "occurrence_anchor_count": 1,
                "proposed_change_role_count": (
                    len(_required_string_array(ticket, "proposed_change_roles")) if is_first else 0
                ),
                "release_operation_class_units": (
                    _forecast_v2_release_operation_units(_required_string(entry, "artifact_kind"))
                    if ticket_id == entry_anchor
                    else 0
                ),
                "release_surface_count": (
                    len(_required_string_array(entry, "ticket_ids"))
                    if ticket_id == entry_anchor
                    else 0
                ),
                "resolved_allowed_file_count": (
                    len(_required_string_array(ticket, "resolved_allowed_files")) if is_first else 0
                ),
                "structured_contract_count": (
                    sum(_forecast_v2_count_contract_keys(package) for package in assigned_packages)
                    + (
                        _forecast_v2_count_contract_keys(
                            {key: value for key, value in ticket.items() if key != "work_packages"}
                        )
                        if is_first
                        else 0
                    )
                ),
                "ticket_dependency_count": len(dependency_ids),
                "unresolved_file_scope_indicator": (
                    1
                    if is_first and not _required_string_array(ticket, "resolved_allowed_files")
                    else 0
                ),
                "work_package_coverage_count": len(covered_packages),
                "work_package_dependency_count": sum(
                    len(
                        _required_string_array(package, "depends_on_work_package_ids")
                        if "depends_on_work_package_ids" in package
                        else []
                    )
                    for package in assigned_packages
                ),
            }
            workload_digest = domain_digest(WORKLOAD_VECTOR_V2_DOMAIN, workload_vector)
            quantities = (
                workload_vector["acceptance_criterion_coverage_count"],
                workload_vector["work_package_coverage_count"],
                workload_vector["structured_contract_count"],
                math.ceil(
                    (
                        workload_vector["resolved_allowed_file_count"]
                        + workload_vector["existing_anchor_count"]
                        + workload_vector["proposed_change_role_count"]
                        + workload_vector["work_package_coverage_count"]
                    )
                    / 4
                ),
                max(
                    1,
                    workload_vector["acceptance_criterion_coverage_count"]
                    + workload_vector["acceptance_command_count"]
                    + workload_vector["golden_case_count"],
                ),
                max(1, workload_vector["golden_case_count"]),
                math.ceil(workload_vector["normative_section_count"] / 4),
                workload_vector["evidence_receipt_instance_count"],
                max(
                    1,
                    workload_vector["ticket_dependency_count"]
                    + workload_vector["work_package_dependency_count"]
                    + workload_vector["release_surface_count"],
                ),
                workload_vector["release_operation_class_units"],
                workload_vector["cumulative_optional_profile_count"],
                workload_vector["unresolved_file_scope_indicator"],
            )
            work_breakdown: list[dict[str, Any]] = []
            for unit, quantity in zip(_FORECAST_V2_WORK_UNITS, quantities, strict=True):
                if quantity == 0:
                    continue
                work_item_id, unit_id, p50_rate, p90_rate, reviewer_rate = unit
                work_breakdown.append(
                    {
                        "work_item_id": work_item_id,
                        "unit_id": unit_id,
                        "quantity": quantity,
                        "p50_effort_hours": _checked_forecast_v2_multiply(
                            quantity, p50_rate, owner=f"{occurrence_id} P50"
                        ),
                        "p90_effort_hours": _checked_forecast_v2_multiply(
                            quantity, p90_rate, owner=f"{occurrence_id} P90"
                        ),
                        "reviewer_p50_effort_hours": _checked_forecast_v2_multiply(
                            quantity, reviewer_rate, owner=f"{occurrence_id} reviewer P50"
                        ),
                    }
                )
            effort = {
                "p50_effort_hours": _checked_forecast_v2_sum(
                    (item["p50_effort_hours"] for item in work_breakdown),
                    owner=f"{occurrence_id} P50",
                ),
                "p90_effort_hours": _checked_forecast_v2_sum(
                    (item["p90_effort_hours"] for item in work_breakdown),
                    owner=f"{occurrence_id} P90",
                ),
                "reviewer_p50_effort_hours": _checked_forecast_v2_sum(
                    (item["reviewer_p50_effort_hours"] for item in work_breakdown),
                    owner=f"{occurrence_id} reviewer P50",
                ),
            }
            known_waits: list[dict[str, Any]] = []
            unquantified = 0
            for source_id, source_value in covered_sources:
                waits = _forecast_v2_numeric_waits(source_value, source_obligation_id=source_id)
                for wait in waits:
                    wait["wait_id"] = f"WAIT-{len(known_waits) + 1:03d}"
                    known_waits.append(wait)
                if not waits and _forecast_v2_source_contains_wait_token(source_value):
                    unquantified += 1
            elapsed_time = {
                "included_in_effort_quantiles": False,
                "known_wait_requirements": known_waits,
                "maximum_single_known_wait_hours": max(
                    (wait["minimum_elapsed_hours"] for wait in known_waits), default=0
                ),
                "serial_sum_known_wait_hours": _checked_forecast_v2_sum(
                    (wait["minimum_elapsed_hours"] for wait in known_waits),
                    owner=f"{occurrence_id} waits",
                ),
                "unquantified_wait_dependency_count": unquantified,
                "critical_path_status": "not_modeled_pending_human_review",
            }
            proposal_projection = {
                "occurrence_id": occurrence_id,
                "occurrence_index": occurrence_index,
                "sprint": sprint,
                "release": release,
                "release_train_entry_digest": domain_digest(
                    RELEASE_TRAIN_ENTRY_SOURCE_DOMAIN, entry
                ),
                "scenario_class": (
                    "stable_core_committed"
                    if _required_string(entry, "train") == "stable-1.0"
                    else "optional_profile_planned"
                ),
                "derivation_disposition": "reestimated_after_inventory",
                "obligation_coverage": coverage,
                "workload_vector": workload_vector,
                "workload_vector_digest": workload_digest,
                "work_breakdown": work_breakdown,
                "effort_proposal": effort,
                "elapsed_time": elapsed_time,
            }
            proposal = {
                **proposal_projection,
                "proposal_digest": domain_digest(
                    OCCURRENCE_PROPOSAL_V2_DOMAIN, proposal_projection
                ),
                "decision": {
                    "status": "pending_explicit_human_review",
                    "selected_p50_effort_hours": None,
                    "selected_p90_effort_hours": None,
                    "selected_reviewer_effort_hours": None,
                    "reviewed_by_person_id": None,
                    "reviewed_at_utc": None,
                    "rationale": None,
                },
            }
            execution_proposals.append(proposal)

        rows.append(
            {
                "ticket_id": ticket_id,
                "estimate_scope": estimate_scope,
                "roadmap_prior_evidence": {
                    "basis": "provisional_before_V1-BASE-01",
                    "source_digest": domain_digest(
                        ESTIMATE_PRIOR_SOURCE_DOMAIN,
                        {"ticket_id": ticket_id, "prior": prior},
                    ),
                    "disposition": "stale_not_used_as_anchor",
                    "used_in_proposal": False,
                },
                "source_anchors": {
                    "acceptance_criteria_count": len(source_criteria),
                    "acceptance_criteria_set_digest": domain_digest(
                        ACCEPTANCE_CRITERIA_SET_DOMAIN, acceptance_set_projection
                    ),
                    "work_package_count": len(source_packages),
                    "work_package_set_digest": domain_digest(
                        WORK_PACKAGE_SET_DOMAIN, work_package_set_projection
                    ),
                    "delivery_digest": domain_digest(
                        TICKET_DELIVERY_SOURCE_DOMAIN,
                        {"ticket_id": ticket_id, "delivery": delivery},
                    ),
                },
                "coverage_contract": {
                    "acceptance_recurrence": (
                        "ticket_lifecycle_once"
                        if estimate_scope == "ticket_completion"
                        else "once_per_occurrence"
                    ),
                    "required_acceptance_coverage_count": (
                        len(source_criteria)
                        if estimate_scope == "ticket_completion"
                        else len(source_criteria) * len(ticket_occurrences)
                    ),
                    "required_work_package_coverage_count": len(source_packages),
                    "required_occurrence_anchor_count": len(ticket_occurrences),
                },
                "dependency_anchor": {
                    "ticket_ids": dependency_ids,
                    "dependency_digest": domain_digest(
                        TICKET_DEPENDENCIES_SOURCE_DOMAIN, dependency_projection
                    ),
                },
                "derivation_disposition": "reestimated_after_inventory",
                "proposal_epistemic_status": ("uncalibrated_machine_proposal_pending_human_review"),
                "row_decision": {
                    "status": "pending_explicit_human_review",
                    "reviewed_by_person_id": None,
                    "reviewed_at_utc": None,
                    "rationale": None,
                },
                "execution_proposals": execution_proposals,
            }
        )

    projection: dict[str, Any] = {
        "format": "agent-assure-delivery-forecast-authoring-ledger/2",
        "spec_revision": SPEC_REVISION,
        "roadmap_digest": snapshot.raw_digest,
        "ticket_set_digest": snapshot.ticket_set_digest,
        "release_train_digest": snapshot.release_train_digest,
        "corrective_authorization_claim_digest": CORRECTIVE_KICKOFF_CLAIM_DIGEST,
        "baseline_observations_digest": baseline_observations_digest_value,
        "inventory_completed_at_utc": inventory_completed_at,
        "estimation_catalog_digest": ESTIMATION_CATALOG_V2_DIGEST,
        "file_scope_observation": _forecast_v2_file_scope_observation(snapshot),
        "proposal_preparer_kind": "llm_implementation_agent",
        "proposal_authority": "machine_authored_nonbinding",
        "human_review_requirement": "every_row_and_occurrence",
        "decision_evidence": copy.deepcopy(decision_evidence),
        "rows": rows,
    }
    return {**projection, "ledger_digest": domain_digest(LEDGER_V2_DOMAIN, projection)}


def _ledger_v2_digest(ledger: Mapping[str, Any]) -> str:
    return domain_digest(
        LEDGER_V2_DOMAIN,
        {key: value for key, value in ledger.items() if key != "ledger_digest"},
    )


def build_forecast_decision_manifest_v2(
    pending_ledger: Mapping[str, Any],
) -> dict[str, Any]:
    """Create one ordered, itemized decision over every row and occurrence."""

    if pending_ledger.get("decision_evidence") is not None:
        raise GovernanceError("decision manifest must be built from the pending proposal ledger")
    rows = _as_array(pending_ledger.get("rows"), owner="decision source rows")
    items: list[dict[str, Any]] = []
    occurrence_count = 0
    for raw_row in rows:
        row = _as_object(raw_row, owner="decision source row")
        ticket_id = _required_string(row, "ticket_id")
        proposals = _as_array(row.get("execution_proposals"), owner=f"{ticket_id} proposals")
        anchors = _as_object(row.get("source_anchors"), owner=f"{ticket_id} source anchors")
        dependencies = _as_object(
            row.get("dependency_anchor"), owner=f"{ticket_id} dependency anchor"
        )
        items.append(
            {
                "item_kind": "ticket_row",
                "ticket_id": ticket_id,
                "decision_status": "human_accepted",
                "selection_mode": "adopt_machine_proposal",
                "source_anchor_digest_tuple": [
                    anchors["acceptance_criteria_set_digest"],
                    anchors["work_package_set_digest"],
                    anchors["delivery_digest"],
                    dependencies["dependency_digest"],
                ],
                "occurrence_count": len(proposals),
                "rationale": (
                    f"Adopt the enumerated {ticket_id} bottom-up proposal after reviewing "
                    f"{anchors['acceptance_criteria_count']} acceptance criteria, "
                    f"{anchors['work_package_count']} work packages, and {len(proposals)} "
                    "release-train occurrences; the values remain subjective planning "
                    "quantiles and unresolved file scope triggers dispatch rebaselining."
                ),
            }
        )
        for raw_proposal in proposals:
            proposal = _as_object(raw_proposal, owner=f"{ticket_id} proposal")
            coverage = _as_object(proposal.get("obligation_coverage"), owner="proposal coverage")
            effort = _as_object(proposal.get("effort_proposal"), owner="proposal effort")
            work_breakdown = _as_array(
                proposal.get("work_breakdown"), owner="proposal work breakdown"
            )
            items.append(
                {
                    "item_kind": "execution_occurrence",
                    "ticket_id": ticket_id,
                    "occurrence_id": proposal["occurrence_id"],
                    "occurrence_index": proposal["occurrence_index"],
                    "scenario_class": proposal["scenario_class"],
                    "decision_status": "human_accepted",
                    "selection_mode": "adopt_machine_proposal",
                    "coverage_digest": coverage["coverage_digest"],
                    "workload_vector_digest": proposal["workload_vector_digest"],
                    "work_breakdown_digest": domain_digest(
                        "agent-assure:delivery-forecast-work-breakdown/v2",
                        work_breakdown,
                    ),
                    "proposal_digest": proposal["proposal_digest"],
                    "selected_p50_effort_hours": effort["p50_effort_hours"],
                    "selected_p90_effort_hours": effort["p90_effort_hours"],
                    "selected_reviewer_effort_hours": effort["reviewer_p50_effort_hours"],
                    "elapsed_wait_included": False,
                    "rationale": (
                        f"Adopt {proposal['occurrence_id']} exactly as itemized: "
                        f"{len(coverage['acceptance_criteria'])} acceptance obligations, "
                        f"{len(coverage['work_packages'])} work packages, and "
                        f"{len(work_breakdown)} nonzero WBS line items under the frozen "
                        "no-diversification method; elapsed waits remain excluded."
                    ),
                }
            )
            occurrence_count += 1
    projection = {
        "format": "agent-assure-delivery-forecast-decision-manifest/2",
        "spec_revision": SPEC_REVISION,
        "roadmap_digest": pending_ledger["roadmap_digest"],
        "proposal_ledger_digest": pending_ledger["ledger_digest"],
        "estimation_catalog_digest": pending_ledger["estimation_catalog_digest"],
        "decision_authority": {
            "person_id": "acblabs",
            "role": "repository_maintainer",
            "approval_mode": "maintainer_development",
        },
        "shared_decision_basis": "maintainer_adoption_of_enumerated_machine_proposals",
        "ticket_row_count": len(rows),
        "execution_occurrence_count": occurrence_count,
        "items": items,
    }
    return {
        **projection,
        "manifest_digest": domain_digest(FORECAST_DECISION_MANIFEST_V2_DOMAIN, projection),
    }


def _apply_forecast_decision_manifest_v2(
    pending_ledger: Mapping[str, Any],
    manifest: Mapping[str, Any],
    signature_envelope: Mapping[str, Any],
) -> dict[str, Any]:
    expected_manifest = build_forecast_decision_manifest_v2(pending_ledger)
    if dict(manifest) != expected_manifest:
        raise GovernanceError("forecast decision manifest differs from the exact itemized proposal")
    manifest_digest = _required_string(manifest, "manifest_digest")
    _validate_signature_envelope_v2(
        signature_envelope,
        expected_person_id="acblabs",
        expected_role="repository_maintainer",
        expected_subject_digest=manifest_digest,
        allow_pending=False,
        owner="forecast batch decision",
    )
    result = copy.deepcopy(dict(pending_ledger))
    items = _as_array(manifest.get("items"), owner="forecast decision items")
    cursor = 0
    for row in cast(list[dict[str, Any]], result["rows"]):
        row_item = _as_object(items[cursor], owner="forecast row decision")
        cursor += 1
        row["row_decision"] = {
            "status": "human_accepted",
            "reviewed_by_person_id": "acblabs",
            "reviewed_at_utc": None,
            "rationale": row_item["rationale"],
        }
        row["proposal_epistemic_status"] = (
            "human_adopted_subjective_planning_quantiles_unresolved_scope_rebaseline_required"
        )
        for proposal in cast(list[dict[str, Any]], row["execution_proposals"]):
            item = _as_object(items[cursor], owner="forecast occurrence decision")
            cursor += 1
            proposal["elapsed_time"]["critical_path_status"] = (
                "not_modeled_scope_rebaseline_required"
            )
            proposal["decision"] = {
                "status": "human_accepted",
                "selected_p50_effort_hours": item["selected_p50_effort_hours"],
                "selected_p90_effort_hours": item["selected_p90_effort_hours"],
                "selected_reviewer_effort_hours": item["selected_reviewer_effort_hours"],
                "reviewed_by_person_id": "acblabs",
                "reviewed_at_utc": None,
                "rationale": item["rationale"],
            }
    if cursor != len(items):
        raise GovernanceError("forecast decision manifest has trailing or missing items")
    result["decision_evidence"] = {
        "decision_manifest_digest": manifest_digest,
        "shared_decision_basis": manifest["shared_decision_basis"],
        "signature_envelope": copy.deepcopy(dict(signature_envelope)),
    }
    result["ledger_digest"] = _ledger_v2_digest(result)
    return result


def validate_authoring_ledger_v2(
    snapshot: RoadmapSnapshot,
    ledger: Mapping[str, Any],
    schema: Mapping[str, Any],
    catalog: Mapping[str, Any],
    *,
    baseline_observations: Mapping[str, Any],
    allow_pending: bool,
) -> None:
    _validate_json_schema(ledger, schema, owner="generation-2 forecast authoring ledger")
    expected_pending = build_authoring_ledger_v2(
        snapshot,
        catalog,
        baseline_observations_digest_value=_required_string(
            baseline_observations, "observations_digest"
        ),
        inventory_completed_at=_required_string(
            baseline_observations, "inventory_completed_at_utc"
        ),
    )
    evidence = ledger.get("decision_evidence")
    if evidence is None:
        if not allow_pending:
            raise GovernanceError("forecast authoring ledger decisions are pending")
        if dict(ledger) != expected_pending:
            raise GovernanceError("pending authoring ledger does not exactly recompute")
    else:
        decision_evidence = _as_object(evidence, owner="decision evidence")
        manifest = build_forecast_decision_manifest_v2(expected_pending)
        if decision_evidence.get("decision_manifest_digest") != manifest["manifest_digest"]:
            raise GovernanceError("authoring ledger decision manifest digest mismatch")
        expected = _apply_forecast_decision_manifest_v2(
            expected_pending,
            manifest,
            _as_object(
                decision_evidence.get("signature_envelope"),
                owner="decision signature envelope",
            ),
        )
        if dict(ledger) != expected:
            raise GovernanceError("decided authoring ledger does not exactly recompute")
    if ledger.get("ledger_digest") != _ledger_v2_digest(ledger):
        raise GovernanceError("generation-2 authoring ledger digest mismatch")
    rows = _as_array(ledger.get("rows"), owner="authoring ledger rows")
    occurrence_total = sum(
        len(
            _as_array(
                _as_object(row, owner="ledger row").get("execution_proposals"),
                owner="execution proposals",
            )
        )
        for row in rows
    )
    if len(rows) != 68 or occurrence_total != 121:
        raise GovernanceError("authoring ledger must contain exactly 68 rows and 121 occurrences")
    source_acceptance = sum(
        _required_integer(
            _as_object(row, owner="ledger row")["source_anchors"],
            "acceptance_criteria_count",
        )
        for row in rows
    )
    source_packages = sum(
        _required_integer(
            _as_object(row, owner="ledger row")["source_anchors"],
            "work_package_count",
        )
        for row in rows
    )
    if (source_acceptance, source_packages) != (360, 102):
        raise GovernanceError("roadmap source inventory must contain exactly 360 ACs and 102 WPs")
    covered_acceptance = sum(
        len(
            _as_array(
                _as_object(
                    _as_object(proposal, owner="proposal").get("obligation_coverage"),
                    owner="obligation coverage",
                ).get("acceptance_criteria"),
                owner="covered acceptance criteria",
            )
        )
        for row in rows
        for proposal in _as_array(
            _as_object(row, owner="ledger row").get("execution_proposals"),
            owner="execution proposals",
        )
    )
    covered_packages = sum(
        len(
            _as_array(
                _as_object(
                    _as_object(proposal, owner="proposal").get("obligation_coverage"),
                    owner="obligation coverage",
                ).get("work_packages"),
                owner="covered work packages",
            )
        )
        for row in rows
        for proposal in _as_array(
            _as_object(row, owner="ledger row").get("execution_proposals"),
            owner="execution proposals",
        )
    )
    if (covered_acceptance, covered_packages) != (745, 102):
        raise GovernanceError("ledger coverage must contain exactly 745 AC and 102 WP instances")
    release_anchor_count = sum(
        1
        for row in rows
        for proposal in _as_array(
            _as_object(row, owner="ledger row").get("execution_proposals"),
            owner="execution proposals",
        )
        if _as_object(proposal, owner="proposal")["workload_vector"][
            "release_operation_class_units"
        ]
        > 0
    )
    if release_anchor_count != 39:
        raise GovernanceError("each release entry must have exactly one release-operation anchor")
    proposals = [
        _as_object(proposal, owner="execution proposal")
        for row in rows
        for proposal in _as_array(
            _as_object(row, owner="ledger row").get("execution_proposals"),
            owner="execution proposals",
        )
    ]
    waits = [
        _as_object(wait, owner="known wait")
        for proposal in proposals
        for wait in _as_array(
            _as_object(proposal.get("elapsed_time"), owner="elapsed time").get(
                "known_wait_requirements"
            ),
            owner="known wait requirements",
        )
    ]
    if [wait.get("minimum_elapsed_hours") for wait in waits] != [168, 336]:
        raise GovernanceError("known elapsed waits changed from the exact two-source inventory")
    if (
        sum(
            _required_integer(
                _as_object(proposal.get("elapsed_time"), owner="elapsed time"),
                "unquantified_wait_dependency_count",
            )
            for proposal in proposals
        )
        != 350
    ):
        raise GovernanceError("unquantified wait diagnostic changed from the source inventory")
    if _forecast_v2_file_scope_observation(snapshot)["unresolved_ticket_count"] != 68:
        raise GovernanceError("all 68 ticket file scopes must remain explicitly unresolved")
    rel02_rows = [
        row for row in rows if _as_object(row, owner="ledger row").get("ticket_id") == "V1-REL-02"
    ]
    if len(rel02_rows) != 1:
        raise GovernanceError("ledger must contain exactly one V1-REL-02 row")
    rel02_proposals = _as_array(
        _as_object(rel02_rows[0], owner="V1-REL-02 row").get("execution_proposals"),
        owner="V1-REL-02 proposals",
    )
    if [
        _as_object(
            _as_object(proposal, owner="V1-REL-02 proposal").get("workload_vector"),
            owner="V1-REL-02 workload vector",
        ).get("cumulative_optional_profile_count")
        for proposal in rel02_proposals
    ] != [1, 2, 2, 4, 4, 5, 5, 6, 6, 7, 7]:
        raise GovernanceError("V1-REL-02 cumulative profile sequence changed")


def _forecast_v2_projection(forecast: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in forecast.items()
        if key not in {"record_digest", "signature_envelope", "acceptance_receipt"}
    }


def _forecast_v2_pending_signature(subject_digest: str) -> dict[str, Any]:
    return {
        "profile": SIGNATURE_PROFILE,
        "status": "pending_human_signature",
        "namespace": SIGNATURE_NAMESPACE,
        "signed_payload_encoding": ATTESTATION_V2_SIGNATURE_PAYLOAD_ENCODING,
        "signature_encoding": SIGNATURE_ENCODING,
        "signer_person_id": None,
        "signer_role": None,
        "subject_digest": subject_digest,
        "public_key_fingerprint": MAINTAINER_KEY_FINGERPRINT,
        "signature": None,
        "verification_evidence": None,
    }


def _forecast_v2_signature_envelope(
    person_id: str, role: str, subject_digest: str
) -> dict[str, Any]:
    envelope = _pending_signature_v2(person_id, role, subject_digest)
    envelope["verification_evidence"] = None
    return envelope


def _forecast_v2_signature_import_evidence(
    *,
    signature_plan_digest: str,
    claim_preparation_started_at_utc: str,
    import_verification_started_at_utc: str,
    import_verification_completed_at_utc: str,
    issued_at_utc: str,
    valid_until_utc: str,
) -> dict[str, Any]:
    if SHA256_PATTERN.fullmatch(signature_plan_digest) is None:
        raise GovernanceError("forecast signature plan digest is invalid")
    issue_time, expiry_time = _validate_validity_interval(
        issued_at_utc, valid_until_utc, owner="forecast signature import evidence"
    )
    prepared = _parse_utc(
        claim_preparation_started_at_utc,
        owner="forecast claim preparation start observation",
    )
    import_started = _parse_utc(
        import_verification_started_at_utc,
        owner="forecast import verification start observation",
    )
    import_completed = _parse_utc(
        import_verification_completed_at_utc,
        owner="forecast import verification completion observation",
    )
    if not issue_time <= prepared <= import_started <= import_completed < expiry_time:
        raise GovernanceError(
            "forecast signature import observations violate their validity ordering"
        )
    return {
        "status": "verified_after_signature_import",
        "signature_plan_digest": signature_plan_digest,
        "claim_preparation_started_at_utc": claim_preparation_started_at_utc,
        "import_verification_started_at_utc": import_verification_started_at_utc,
        "import_verification_completed_at_utc": import_verification_completed_at_utc,
        "clock_basis": "maintainer_host_utc_externally_unattested",
        "sshsig_timestamp_capability": "none",
        "actual_signature_time_claimed": False,
        "verification_result": "both_signatures_valid_exact_payload_key_and_namespace",
        "signature_claim_binding": "excluded_post_signature_observation_not_in_sshsig_claim",
        "durable_integrity_binding": (
            "corrective_closure_artifact_inventory_and_acceptance_attestation"
        ),
    }


def _validate_forecast_v2_signature_import_evidence(
    value: object, *, issued_at_utc: str, valid_until_utc: str
) -> dict[str, Any]:
    evidence = _as_object(value, owner="forecast signature import evidence")
    if set(evidence) != FORECAST_V2_SIGNATURE_IMPORT_EVIDENCE_FIELDS:
        raise GovernanceError("forecast signature import evidence has unexpected fields")
    expected = _forecast_v2_signature_import_evidence(
        signature_plan_digest=_required_string(evidence, "signature_plan_digest"),
        claim_preparation_started_at_utc=_required_string(
            evidence, "claim_preparation_started_at_utc"
        ),
        import_verification_started_at_utc=_required_string(
            evidence, "import_verification_started_at_utc"
        ),
        import_verification_completed_at_utc=_required_string(
            evidence, "import_verification_completed_at_utc"
        ),
        issued_at_utc=issued_at_utc,
        valid_until_utc=valid_until_utc,
    )
    if evidence != expected:
        raise GovernanceError("forecast signature import evidence semantics changed")
    return evidence


def _forecast_v2_roster_metadata(
    roster: Mapping[str, Any], *, expected_digest: str
) -> dict[str, Any]:
    actual_digest = approval_roster_digest(roster)
    if actual_digest != expected_digest:
        raise GovernanceError("forecast approval roster digest mismatch")
    if (
        roster.get("selection_status") != "approved"
        or roster.get("selected_mode") != "maintainer_development"
        or roster.get("maintainer_person_id") != "acblabs"
    ):
        raise GovernanceError("forecast acceptance requires the approved S1 maintainer roster")
    people = [
        _as_object(item, owner="forecast approval roster person")
        for item in _as_array(roster.get("people"), owner="forecast approval roster people")
    ]
    matches = [person for person in people if person.get("person_id") == "acblabs"]
    if len(matches) != 1:
        raise GovernanceError("forecast acceptor has no unique approval-roster identity")
    person = matches[0]
    scopes = _required_string_array(person, "competence_scopes")
    required_scopes = {
        "planning_governance:s1",
        "repository_maintenance:bounded_development",
        "technical_direction:s1",
    }
    if not required_scopes <= set(scopes):
        raise GovernanceError("forecast acceptor lacks the required rostered competence")
    conflicts = _required_string_array(person, "conflicts")
    assignments = {
        _required_string(assignment, "role"): assignment
        for assignment in (
            _as_object(item, owner="forecast approval roster role assignment")
            for item in _as_array(
                roster.get("role_assignments"),
                owner="forecast approval roster role assignments",
            )
        )
    }
    roles = ["repository_maintainer", "technical_lead"]
    if any(
        role not in assignments or assignments[role].get("person_id") != "acblabs" for role in roles
    ):
        raise GovernanceError("forecast acceptor lacks the required rostered role assignments")
    if "NO_INDEPENDENT_REVIEW" not in _required_string_array(roster, "limitations"):
        raise GovernanceError("forecast roster omits NO_INDEPENDENT_REVIEW")
    return {
        "competence_basis": {
            "approval_roster_digest": actual_digest,
            "issuer_person_id": "acblabs",
            "issuer_role_assignments": roles,
            "issuer_competence_scopes": scopes,
        },
        "conflicts": {
            "approval_roster_digest": actual_digest,
            "issuer_person_id": "acblabs",
            "issuer_conflict_disclosures": conflicts,
            "independence_limitation": "NO_INDEPENDENT_REVIEW",
        },
    }


def _forecast_v2_acceptance_receipt(
    *,
    record_digest: str,
    ledger: Mapping[str, Any],
    approval_roster: Mapping[str, Any],
    approval_roster_digest_value: str,
    accepted: bool,
) -> dict[str, Any]:
    roster_metadata = _forecast_v2_roster_metadata(
        approval_roster, expected_digest=approval_roster_digest_value
    )
    decision_evidence = ledger.get("decision_evidence")
    decision_manifest_digest = (
        _as_object(decision_evidence, owner="decision evidence").get("decision_manifest_digest")
        if decision_evidence is not None
        else None
    )
    common: dict[str, Any] = {
        "receipt_type": "development_design_acceptance",
        "receipt_status": (
            "accepted_for_development" if accepted else "pending_explicit_human_review"
        ),
        "subject_contract_id": FORECAST_CONTRACT_ID,
        "subject_record_digest": record_digest,
        "approval_mode": "maintainer_development",
        "competence_basis": roster_metadata["competence_basis"],
        "allowed_operations": [
            "use_as_a_nonbinding_development_planning_baseline",
            "rebaseline_at_dispatch_after_concrete_file_scope_resolution",
        ],
        "exclusions": [
            "no_runtime_release_deployment_qualification_or_method_admission_authority",
            "no_calendar_delivery_commitment_or_distribution_free_probability_bound",
            "no_independent_review_claim",
        ],
        "conflicts": roster_metadata["conflicts"],
        "review_evidence": {
            "decision_manifest_digest": decision_manifest_digest,
            "authoring_ledger_digest": ledger["ledger_digest"],
            "estimation_catalog_digest": ledger["estimation_catalog_digest"],
            "approval_roster_digest": approval_roster_digest_value,
            "ticket_row_count": len(_as_array(ledger.get("rows"), owner="ledger rows")),
            "execution_occurrence_count": sum(
                len(
                    _as_array(
                        _as_object(row, owner="ledger row").get("execution_proposals"),
                        owner="execution proposals",
                    )
                )
                for row in _as_array(ledger.get("rows"), owner="ledger rows")
            ),
        },
        "limitations": [
            "all_estimates_are_subjective_planning_quantiles_from_uncalibrated_unit_rates",
            "all_68_ticket_file_scopes_are_unresolved_and_require_dispatch_rebaselining",
            "elapsed_waits_resource_capacity_parallelism_and_calendar_critical_path_are_not_modeled",
            "openssh_sshsig_contains_no_timestamp_and_no_actual_signature_time_is_claimed",
        ],
        "issuer_person_id": "acblabs" if accepted else None,
        "issuer_role": "repository_maintainer" if accepted else None,
        "decision": "accept" if accepted else None,
    }
    if not accepted:
        return {**common, "receipt_digest": None, "signature_envelope": None}
    receipt_digest = domain_digest(FORECAST_ACCEPTANCE_RECEIPT_V2_DOMAIN, common)
    return {
        **common,
        "receipt_digest": receipt_digest,
        "signature_envelope": _forecast_v2_signature_envelope(
            "acblabs", "repository_maintainer", receipt_digest
        ),
    }


def build_forecast_v2(
    snapshot: RoadmapSnapshot,
    ledger: Mapping[str, Any],
    registry: Mapping[str, Any],
    *,
    approval_roster: Mapping[str, Any],
    approval_roster_digest_value: str,
    issued_at: str | None = None,
    valid_until: str | None = None,
    trusted_time_basis: str | None = None,
    accepted_candidate: bool = False,
) -> dict[str, Any]:
    method = _resolve_aggregation_method_v2(registry)
    decided = ledger.get("decision_evidence") is not None
    if decided:
        if not all(
            isinstance(value, str) for value in (issued_at, valid_until, trusted_time_basis)
        ):
            raise GovernanceError("decided forecast requires issue, expiry, and trusted-time basis")
        issue_time, _expiry_time = _validate_validity_interval(
            cast(str, issued_at), cast(str, valid_until), owner="generation-2 forecast"
        )
        inventory_time = _parse_utc(
            _required_string(ledger, "inventory_completed_at_utc"),
            owner="forecast inventory completion",
        )
        if issue_time < inventory_time:
            raise GovernanceError("forecast issue time predates completed baseline inventory")
    elif any(value is not None for value in (issued_at, valid_until, trusted_time_basis)):
        raise GovernanceError("pending forecast must not claim issue or validity times")
    if accepted_candidate and not decided:
        raise GovernanceError("an accepted forecast candidate requires signed batch decisions")
    method_digest = _required_string(method, "definition_digest")
    rows: list[dict[str, Any]] = []
    scenario_values: dict[str, dict[str, Any]] = {
        scenario: {"tickets": set(), "occurrences": 0, "p50": 0, "p90": 0, "review": 0}
        for scenario in ("stable_core_committed", "optional_profile_planned")
    }
    portfolio_tickets: set[str] = set()
    for raw_row in _as_array(ledger.get("rows"), owner="ledger rows"):
        source_row = _as_object(raw_row, owner="ledger row")
        ticket_id = _required_string(source_row, "ticket_id")
        portfolio_tickets.add(ticket_id)
        estimates: list[dict[str, Any]] = []
        row_p50: list[int] = []
        row_p90: list[int] = []
        row_review: list[int] = []
        for raw_proposal in _as_array(
            source_row.get("execution_proposals"), owner=f"{ticket_id} proposals"
        ):
            proposal = _as_object(raw_proposal, owner=f"{ticket_id} proposal")
            effort = _as_object(proposal.get("effort_proposal"), owner="effort proposal")
            elapsed = _as_object(proposal.get("elapsed_time"), owner="elapsed time")
            decision = _as_object(proposal.get("decision"), owner="proposal decision")
            proposed_values = (
                _required_integer(effort, "p50_effort_hours"),
                _required_integer(effort, "p90_effort_hours"),
                _required_integer(effort, "reviewer_p50_effort_hours"),
            )
            selected_values = (
                decision.get("selected_p50_effort_hours"),
                decision.get("selected_p90_effort_hours"),
                decision.get("selected_reviewer_effort_hours"),
            )
            values = cast(tuple[int, int, int], selected_values) if decided else proposed_values
            if values[1] < values[0]:
                raise GovernanceError(f"P90 is below P50 for {proposal['occurrence_id']}")
            row_p50.append(values[0])
            row_p90.append(values[1])
            row_review.append(values[2])
            scenario = _required_string(proposal, "scenario_class")
            accumulator = scenario_values[scenario]
            cast(set[str], accumulator["tickets"]).add(ticket_id)
            accumulator["occurrences"] += 1
            accumulator["p50"] = _checked_forecast_v2_sum(
                (cast(int, accumulator["p50"]), values[0]), owner="scenario P50"
            )
            accumulator["p90"] = _checked_forecast_v2_sum(
                (cast(int, accumulator["p90"]), values[1]), owner="scenario P90"
            )
            accumulator["review"] = _checked_forecast_v2_sum(
                (cast(int, accumulator["review"]), values[2]), owner="scenario reviewer"
            )
            estimates.append(
                {
                    "occurrence_id": proposal["occurrence_id"],
                    "sprint": proposal["sprint"],
                    "release": proposal["release"],
                    "scenario_class": scenario,
                    "derivation_disposition": "reestimated_after_inventory",
                    "workload_vector_digest": proposal["workload_vector_digest"],
                    "proposal_digest": proposal["proposal_digest"],
                    "proposed_p50_effort_hours": proposed_values[0],
                    "proposed_p90_effort_hours": proposed_values[1],
                    "proposed_reviewer_effort_hours": proposed_values[2],
                    "p50_effort_hours": values[0] if decided else None,
                    "p90_effort_hours": values[1] if decided else None,
                    "reviewer_effort_hours": values[2] if decided else None,
                    "selected_p50_effort_hours": values[0] if decided else None,
                    "selected_p90_effort_hours": values[1] if decided else None,
                    "selected_reviewer_effort_hours": values[2] if decided else None,
                    "maximum_single_known_wait_hours": elapsed["maximum_single_known_wait_hours"],
                    "serial_sum_known_wait_hours": elapsed["serial_sum_known_wait_hours"],
                    "unquantified_wait_dependency_count": elapsed[
                        "unquantified_wait_dependency_count"
                    ],
                    "elapsed_wait_included": False,
                    "decision_status": decision["status"],
                }
            )
        rows.append(
            {
                "ticket_id": ticket_id,
                "estimate_scope": source_row["estimate_scope"],
                "prior_disposition": "stale_not_used_as_anchor",
                "derivation_disposition": "reestimated_after_inventory",
                "planned_execution_count": len(estimates),
                "execution_estimates": estimates,
                "aggregate_p50_effort_hours": _checked_forecast_v2_sum(
                    row_p50, owner=f"{ticket_id} P50"
                ),
                "aggregate_p90_effort_hours": _checked_forecast_v2_sum(
                    row_p90, owner=f"{ticket_id} P90"
                ),
                "aggregate_reviewer_effort_hours": _checked_forecast_v2_sum(
                    row_review, owner=f"{ticket_id} reviewer"
                ),
                "aggregate_method_id": METHOD_ID,
                "aggregate_method_definition_digest": method_digest,
                "aggregate_dependence_assumptions": [
                    "full_positive_rank_dependence_no_diversification_credit",
                    "reported_quantile_sums_are_exact_only_under_the_bound_comonotonic_construction",
                ],
                "confidence": "low",
                "dependency_assumptions": [
                    "bound_roadmap_dependency_edges_and_release_train_order_remain_unchanged",
                    "ticket_execution_waits_for_declared_dependency_and_work_package_receipts",
                ],
                "risk_assumptions": [
                    (
                        "human_adopted_subjective_unit_rates_remain_uncalibrated"
                        if decided
                        else "uncalibrated_machine_unit_rates_require_explicit_human_review"
                    ),
                    "resource_capacity_parallelism_and_calendar_critical_path_are_not_modeled",
                    "unresolved_file_scope_requires_dispatch_rebaseline",
                ],
                "current_status": "not_started",
                "trusted_issue_time": issued_at if decided else None,
                "elapsed_wait_included": False,
                "proposal_epistemic_status": (
                    "human_adopted_subjective_planning_quantiles_unresolved_scope_rebaseline_required"
                    if decided
                    else "uncalibrated_machine_proposal_pending_human_review"
                ),
                "decision_status": source_row["row_decision"]["status"],
            }
        )
    scenarios: list[dict[str, Any]] = []
    for scenario_id in ("stable_core_committed", "optional_profile_planned"):
        value = scenario_values[scenario_id]
        scenarios.append(
            {
                "scenario_id": scenario_id,
                "ticket_count": len(cast(set[str], value["tickets"])),
                "occurrence_count": value["occurrences"],
                "aggregate_p50_effort_hours": value["p50"],
                "aggregate_p90_effort_hours": value["p90"],
                "aggregate_reviewer_effort_hours": value["review"],
                "aggregate_method_id": METHOD_ID,
                "aggregate_method_definition_digest": method_digest,
                "elapsed_wait_included": False,
            }
        )
    projection = {
        "contract_id": FORECAST_CONTRACT_ID,
        "format": "agent-assure-delivery-forecast/2",
        "spec_revision": SPEC_REVISION,
        "forecast_status": (
            "accepted"
            if accepted_candidate
            else "ready_for_signature"
            if decided
            else "proposed_pending_explicit_human_review"
        ),
        "proposal_authority": "machine_authored_nonbinding",
        "human_review_status": "complete" if decided else "pending_explicit_human_review",
        "full_roadmap_digest": snapshot.raw_digest,
        "sorted_ticket_set_digest": snapshot.ticket_set_digest,
        "dependency_graph_digest": snapshot.dependency_graph_digest,
        "release_train_digest": snapshot.release_train_digest,
        "corrective_authorization_claim_digest": CORRECTIVE_KICKOFF_CLAIM_DIGEST,
        "baseline_observations_digest": ledger["baseline_observations_digest"],
        "estimation_catalog_digest": ledger["estimation_catalog_digest"],
        "aggregation_method_registry_digest": registry["registry_digest"],
        "authoring_ledger_digest": ledger["ledger_digest"],
        "approval_roster_digest": approval_roster_digest_value,
        "file_scope_observation": copy.deepcopy(ledger["file_scope_observation"]),
        "issued_at_utc": issued_at if decided else None,
        "valid_until_utc": valid_until if decided else None,
        "trusted_time_basis": trusted_time_basis if decided else None,
        "producer_person_id": "acblabs" if decided else None,
        "producer_role": "technical_lead" if decided else None,
        "proposal_preparer_kind": "llm_implementation_agent",
        "portfolio_scenarios": scenarios,
        "portfolio_aggregate": {
            "ticket_count": len(portfolio_tickets),
            "occurrence_count": _checked_forecast_v2_sum(
                (cast(int, value["occurrences"]) for value in scenario_values.values()),
                owner="portfolio occurrences",
            ),
            "aggregate_p50_effort_hours": _checked_forecast_v2_sum(
                (cast(int, value["p50"]) for value in scenario_values.values()),
                owner="portfolio P50",
            ),
            "aggregate_p90_effort_hours": _checked_forecast_v2_sum(
                (cast(int, value["p90"]) for value in scenario_values.values()),
                owner="portfolio P90",
            ),
            "aggregate_reviewer_effort_hours": _checked_forecast_v2_sum(
                (cast(int, value["review"]) for value in scenario_values.values()),
                owner="portfolio reviewer",
            ),
            "aggregate_method_id": METHOD_ID,
            "aggregate_method_definition_digest": method_digest,
            "elapsed_wait_included": False,
        },
        "rows": rows,
    }
    record_digest = domain_digest(FORECAST_V2_DOMAIN, projection)
    if accepted_candidate:
        signature_envelope = _forecast_v2_signature_envelope(
            "acblabs", "technical_lead", record_digest
        )
    else:
        signature_envelope = _forecast_v2_pending_signature(record_digest)
    return {
        **projection,
        "record_digest": record_digest,
        "signature_envelope": signature_envelope,
        "acceptance_receipt": _forecast_v2_acceptance_receipt(
            record_digest=record_digest,
            ledger=ledger,
            approval_roster=approval_roster,
            approval_roster_digest_value=approval_roster_digest_value,
            accepted=accepted_candidate,
        ),
    }


def validate_forecast_v2(
    snapshot: RoadmapSnapshot,
    ledger: Mapping[str, Any],
    registry: Mapping[str, Any],
    forecast: Mapping[str, Any],
    schema: Mapping[str, Any],
    *,
    approval_roster: Mapping[str, Any],
    approval_roster_digest_value: str,
    allow_pending: bool,
) -> None:
    _validate_json_schema(forecast, schema, owner="generation-2 delivery forecast")
    status = _required_string(forecast, "forecast_status")
    if status == "proposed_pending_explicit_human_review":
        expected = build_forecast_v2(
            snapshot,
            ledger,
            registry,
            approval_roster=approval_roster,
            approval_roster_digest_value=approval_roster_digest_value,
        )
        if not allow_pending:
            raise GovernanceError("delivery forecast human review is pending")
        if dict(forecast) != expected:
            raise GovernanceError("pending delivery forecast does not exactly recompute")
        return
    issued_at = _required_string(forecast, "issued_at_utc")
    valid_until = _required_string(forecast, "valid_until_utc")
    trusted_time_basis = _required_string(forecast, "trusted_time_basis")
    if status == "ready_for_signature":
        expected = build_forecast_v2(
            snapshot,
            ledger,
            registry,
            approval_roster=approval_roster,
            approval_roster_digest_value=approval_roster_digest_value,
            issued_at=issued_at,
            valid_until=valid_until,
            trusted_time_basis=trusted_time_basis,
        )
        if not allow_pending:
            raise GovernanceError("delivery forecast signatures are pending")
        if dict(forecast) != expected:
            raise GovernanceError("ready delivery forecast does not exactly recompute")
        return
    if status != "accepted":
        raise GovernanceError("unknown generation-2 delivery forecast status")
    expected = build_forecast_v2(
        snapshot,
        ledger,
        registry,
        approval_roster=approval_roster,
        approval_roster_digest_value=approval_roster_digest_value,
        issued_at=issued_at,
        valid_until=valid_until,
        trusted_time_basis=trusted_time_basis,
        accepted_candidate=True,
    )
    producer_signature = _as_object(
        forecast.get("signature_envelope"), owner="forecast producer signature"
    )
    producer_verification_evidence = _validate_forecast_v2_signature_import_evidence(
        producer_signature.get("verification_evidence"),
        issued_at_utc=issued_at,
        valid_until_utc=valid_until,
    )
    _validate_signature_envelope_v2(
        producer_signature,
        expected_person_id="acblabs",
        expected_role="technical_lead",
        expected_subject_digest=_required_string(expected, "record_digest"),
        allow_pending=False,
        owner="forecast producer",
        expected_verification_evidence=producer_verification_evidence,
    )
    actual_receipt = _as_object(
        forecast.get("acceptance_receipt"), owner="forecast acceptance receipt"
    )
    expected_receipt = _as_object(
        expected.get("acceptance_receipt"), owner="expected forecast acceptance receipt"
    )
    receipt_signature = _as_object(
        actual_receipt.get("signature_envelope"), owner="forecast acceptance signature"
    )
    receipt_verification_evidence = _validate_forecast_v2_signature_import_evidence(
        receipt_signature.get("verification_evidence"),
        issued_at_utc=issued_at,
        valid_until_utc=valid_until,
    )
    if receipt_verification_evidence != producer_verification_evidence:
        raise GovernanceError("forecast producer and acceptance import observations do not match")
    _validate_signature_envelope_v2(
        receipt_signature,
        expected_person_id="acblabs",
        expected_role="repository_maintainer",
        expected_subject_digest=_required_string(expected_receipt, "receipt_digest"),
        allow_pending=False,
        owner="forecast acceptance receipt",
        expected_verification_evidence=receipt_verification_evidence,
    )
    expected["signature_envelope"] = copy.deepcopy(producer_signature)
    expected_receipt["signature_envelope"] = copy.deepcopy(receipt_signature)
    if dict(forecast) != expected:
        raise GovernanceError("accepted delivery forecast does not exactly recompute")


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


def _parse_corrective_utc_100ns(value: str, *, owner: str) -> tuple[datetime, int]:
    """Parse canonical .NET-style UTC while retaining the seventh digit.

    The user-signed corrective kickoff was prepared by PowerShell, whose
    round-trip timestamp format can carry 100 ns ticks.  Python ``datetime``
    stores only microseconds, so ordering uses a separate seven-digit tick
    value instead of silently truncating the signed evidence.
    """

    match = CORRECTIVE_UTC_100NS_PATTERN.fullmatch(value)
    if match is None:
        raise GovernanceError(
            f"{owner} must use canonical UTC with seconds, up to seven fractional digits, "
            "and a Z suffix"
        )
    try:
        whole = datetime.strptime(match.group("whole"), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=UTC)
    except ValueError as exc:
        raise GovernanceError(f"{owner} is not a valid UTC calendar timestamp") from exc
    ticks = int((match.group("fraction") or "").ljust(7, "0"))
    return whole, ticks


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
    excluded = {"receipt_digest", "signature_envelope"}
    if receipt.get("format") == "agent-assure-ticket-completion-receipt/2":
        excluded.add("signature_import_evidence")
    return {key: value for key, value in receipt.items() if key not in excluded}


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


def validate_corrective_kickoff_authorization(
    record: Mapping[str, Any],
    schema: Mapping[str, Any],
    *,
    expected_roadmap_digest: str,
) -> str:
    """Validate the exact prospective corrective authorization and SSHSIG.

    The detached SSH signature authenticates exact claim bytes, but SSHSIG has
    no timestamp.  The wrapper therefore records only an externally-unattested
    import observation and never promotes it to a signature-time assertion.
    """

    _validate_json_schema(record, schema, owner="corrective kickoff authorization")
    if record.get("format") != "agent-assure-s1-corrective-kickoff-authorization/1":
        raise GovernanceError("corrective kickoff authorization format changed")
    if (
        record.get("acceptance_generation") != 2
        or record.get("authorization_status") != "authorized"
        or record.get("authorization_kind") != "prospective_corrective_implementation"
        or record.get("authorization_effect") != "corrective_s1_development_governance_only"
    ):
        raise GovernanceError("corrective kickoff authorization identity changed")

    signed_claim = _as_object(record.get("signed_claim"), owner="corrective signed claim")
    claim_payload = (
        json.dumps(
            signed_claim,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    claim_artifact = _as_object(
        record.get("signed_claim_artifact"), owner="corrective signed claim artifact"
    )
    if (
        claim_artifact.get("serialization_profile")
        != "utf8-json-sorted-keys-indent-2-lf-terminal-lf"
        or claim_artifact.get("size_bytes") != CORRECTIVE_KICKOFF_CLAIM_SIZE
        or len(claim_payload) != CORRECTIVE_KICKOFF_CLAIM_SIZE
        or claim_artifact.get("sha256") != CORRECTIVE_KICKOFF_CLAIM_DIGEST
        or raw_digest(claim_payload) != CORRECTIVE_KICKOFF_CLAIM_DIGEST
    ):
        raise GovernanceError("corrective kickoff signed claim bytes changed")
    evidence = _as_object(signed_claim.get("evidence"), owner="corrective claim evidence")
    if evidence.get("roadmap_raw_sha256") != expected_roadmap_digest:
        raise GovernanceError("corrective kickoff targets another roadmap")
    _validate_corrective_local_only_path_prefixes(signed_claim)
    topology = _as_object(signed_claim.get("expected_topology"), owner="corrective claim topology")
    if topology != {
        "corrective_closure_parent": "R2",
        "corrective_result_parent": S1_ACCEPTANCE_V1_CLOSURE_COMMIT,
        "shape": "C1 -> R2 -> C2",
        "successor_tag_name": S1_ACCEPTANCE_V2_TAG_NAME,
    }:
        raise GovernanceError("corrective kickoff topology changed")
    superseded = _as_object(
        signed_claim.get("superseded_acceptance"),
        owner="corrective superseded acceptance",
    )
    expected_superseded = {
        "acceptance_tag_name": S1_ACCEPTANCE_TAG_NAME,
        "bundle_digest": (
            "sha256:62d4ddd81f2f619597b40a39d75a084e5bd0bc5ad99e2653f3fe6659b0194a82"
        ),
        "closure_commit": S1_ACCEPTANCE_V1_CLOSURE_COMMIT,
        "forecast_digest": (
            "sha256:e151679546b1a2d9f62a179052c97ba61ed6b249b05d69c11f23220287b56460"
        ),
        "result_commit": S1_ACCEPTANCE_V1_RESULT_COMMIT,
        "tag_object": S1_ACCEPTANCE_V1_TAG_OBJECT,
    }
    if superseded != expected_superseded:
        raise GovernanceError("corrective kickoff predecessor binding changed")
    plan_time = _parse_corrective_utc_100ns(
        _required_string(signed_claim, "plan_created_at_utc"),
        owner="corrective kickoff plan_created_at_utc",
    )

    signature_evidence = _as_object(
        record.get("signature_evidence"), owner="corrective kickoff signature evidence"
    )
    try:
        armor_base64 = _required_string(signature_evidence, "armored_signature_base64")
        armor_bytes = base64.b64decode(armor_base64, validate=True)
    except (ValueError, TypeError) as exc:
        raise GovernanceError("corrective kickoff SSHSIG armor base64 is invalid") from exc
    if base64.b64encode(armor_bytes).decode("ascii") != armor_base64:
        raise GovernanceError("corrective kickoff SSHSIG armor base64 is not canonical")
    canonical_armor = _canonical_sshsig_armor(armor_bytes)
    if canonical_armor != armor_bytes:
        raise GovernanceError("corrective kickoff SSHSIG armor is not canonical")
    if (
        signature_evidence.get("signature_file_size_bytes") != len(armor_bytes)
        or signature_evidence.get("signature_file_sha256") != raw_digest(armor_bytes)
        or signature_evidence.get("signature_time_status") != "unavailable_sshsig_has_no_timestamp"
    ):
        raise GovernanceError("corrective kickoff signature evidence changed")
    _verify_sshsig(
        signature_base64=armor_base64,
        payload=claim_payload,
        signer_person_id="acblabs",
        public_key=MAINTAINER_PUBLIC_KEY,
    )

    imported = _as_object(
        record.get("import_verification"), owner="corrective kickoff import verification"
    )
    recorded_time = _parse_corrective_utc_100ns(
        _required_string(imported, "verification_recorded_at_utc"),
        owner="corrective kickoff verification_recorded_at_utc",
    )
    if recorded_time < plan_time:
        raise GovernanceError("corrective kickoff verification record predates its plan")
    if (
        imported.get("actual_signature_time_claimed") is not False
        or imported.get("verification_time_status")
        != "host_observation_recorded_after_verification_not_signature_time"
        or imported.get("verification_result") != "valid_exact_payload_key_and_namespace"
        or imported.get("predecessor_head_commit") != S1_ACCEPTANCE_V1_CLOSURE_COMMIT
        or imported.get("predecessor_tag_object") != S1_ACCEPTANCE_V1_TAG_OBJECT
        or imported.get("roadmap_digest_at_import") != expected_roadmap_digest
    ):
        raise GovernanceError("corrective kickoff import evidence changed")
    return CORRECTIVE_KICKOFF_CLAIM_DIGEST


def _baseline_v2_observation_window(
    value: object,
    *,
    owner: str,
    inventory_start: datetime,
    inventory_end: datetime,
) -> tuple[datetime, datetime]:
    window = _as_object(value, owner=f"{owner} observation window")
    started = _parse_utc(
        _required_string(window, "started_at_utc"), owner=f"{owner} started_at_utc"
    )
    completed = _parse_utc(
        _required_string(window, "completed_at_utc"),
        owner=f"{owner} completed_at_utc",
    )
    if not inventory_start <= started <= completed <= inventory_end:
        raise GovernanceError(
            f"{owner} observation must fall inside the corrective inventory window"
        )
    return started, completed


def _validate_baseline_observations_v2(
    snapshot: RoadmapSnapshot,
    record: Mapping[str, Any],
    schema: Mapping[str, Any],
    *,
    repository_root: Path,
) -> str:
    _validate_json_schema(record, schema, owner="generation-2 baseline observations")
    exact = {
        "format": "agent-assure-baseline-observations/2",
        "spec_revision": SPEC_REVISION,
        "acceptance_generation": 2,
        "supersedes_observations_digest": (
            "sha256:41a433296c91d119a4f5a73fff039e17df80ccf9bfdf33c6605ed8def5fbf197"
        ),
        "corrective_authorization_claim_digest": CORRECTIVE_KICKOFF_CLAIM_DIGEST,
    }
    for key, expected in exact.items():
        if record.get(key) != expected:
            raise GovernanceError(f"generation-2 baseline changed {key}")
    inventory_start = _parse_utc(
        _required_string(record, "inventory_started_at_utc"),
        owner="generation-2 baseline inventory_started_at_utc",
    )
    inventory_end = _parse_utc(
        _required_string(record, "inventory_completed_at_utc"),
        owner="generation-2 baseline inventory_completed_at_utc",
    )
    if inventory_end < inventory_start:
        raise GovernanceError("generation-2 baseline inventory ends before it starts")
    time_evidence = _as_object(record.get("time_evidence"), owner="baseline time evidence")
    if time_evidence != {
        "clock_basis": "maintainer_host_utc_externally_unattested",
        "external_attestation_status": "unavailable_windows_time_service_not_started",
        "sshsig_timestamp_capability": "none",
        "actual_signature_time_claimed": False,
    }:
        raise GovernanceError("generation-2 baseline time semantics changed")

    repository = _as_object(record.get("repository"), owner="generation-2 repository")
    _baseline_v2_observation_window(
        repository.get("observation_window"),
        owner="repository identity",
        inventory_start=inventory_start,
        inventory_end=inventory_end,
    )
    repository_exact = {
        "approved_remote_url": APPROVED_ORIGIN_URL,
        "authoritative_fetch_status": "deferred_to_final_current_acceptance_gate",
        "cached_origin_main_commit": PINNED_BASE_COMMIT,
        "baseline_tag_name": "v0.7.0",
        "baseline_tag_object": PINNED_TAG_OBJECT,
        "baseline_tag_commit": PINNED_BASE_COMMIT,
        "corrective_branch_name": S1_CORRECTIVE_BRANCH_NAME,
        "inventory_head_commit": S1_ACCEPTANCE_V1_CLOSURE_COMMIT,
        "required_corrective_result_parent": S1_ACCEPTANCE_V1_CLOSURE_COMMIT,
    }
    for key, expected in repository_exact.items():
        if repository.get(key) != expected:
            raise GovernanceError(f"generation-2 baseline repository changed {key}")

    roadmap = _as_object(record.get("roadmap"), owner="generation-2 roadmap")
    _baseline_v2_observation_window(
        roadmap.get("observation_window"),
        owner="private roadmap",
        inventory_start=inventory_start,
        inventory_end=inventory_end,
    )
    if (
        roadmap.get("raw_digest") != snapshot.raw_digest
        or roadmap.get("size_bytes") != 2_390_013
        or roadmap.get("local_only") is not True
        or roadmap.get("git_ignored") is not True
        or roadmap.get("git_index_tracked") is not False
    ):
        raise GovernanceError("generation-2 baseline roadmap evidence changed")

    environment = _as_object(record.get("environment"), owner="generation-2 environment")
    if environment.get("platform") != "Windows" or environment.get("python_version") != "3.12.13":
        raise GovernanceError("generation-2 baseline platform or Python identity changed")
    command_expectations = {
        "pip_check": ("passed", 0),
        "time_attestation": ("unavailable", -2147023834),
    }
    for name, (outcome, exit_code) in command_expectations.items():
        command = _as_object(environment.get(name), owner=f"generation-2 {name}")
        if command.get("outcome") != outcome or command.get("exit_code") != exit_code:
            raise GovernanceError(f"generation-2 baseline {name} changed")
        _baseline_v2_observation_window(
            {
                "started_at_utc": command.get("started_at_utc"),
                "completed_at_utc": command.get("completed_at_utc"),
            },
            owner=name,
            inventory_start=inventory_start,
            inventory_end=inventory_end,
        )

    tool_record = _as_object(
        environment.get("trusted_executables"), owner="generation-2 trusted executables"
    )
    _baseline_v2_observation_window(
        tool_record.get("observation_window"),
        owner="trusted executables",
        inventory_start=inventory_start,
        inventory_end=inventory_end,
    )
    observed_tools: dict[str, Mapping[str, Any]] = {}
    for value in _as_array(tool_record.get("artifacts"), owner="trusted executable artifacts"):
        tool = _as_object(value, owner="trusted executable")
        name = _required_string(tool, "name")
        if name in observed_tools:
            raise GovernanceError(f"duplicate generation-2 trusted executable: {name}")
        observed_tools[name] = tool
    if set(observed_tools) != set(FROZEN_S1_EXECUTABLE_IDENTITIES):
        raise GovernanceError("generation-2 trusted executable inventory is incomplete")
    for name, identity in FROZEN_S1_EXECUTABLE_IDENTITIES.items():
        if observed_tools[name] != {
            "name": name,
            "absolute_path": identity.path,
            "size_bytes": identity.size_bytes,
            "sha256": f"sha256:{identity.sha256}",
        }:
            raise GovernanceError(f"generation-2 trusted executable changed: {name}")

    runtime = _as_object(
        environment.get("trusted_python_runtime"), owner="generation-2 Python runtime"
    )
    for field, owner in (
        ("file_observation_window", "trusted Python files"),
        ("inventory_observation_window", "trusted Python inventories"),
    ):
        _baseline_v2_observation_window(
            runtime.get(field),
            owner=owner,
            inventory_start=inventory_start,
            inventory_end=inventory_end,
        )
    if (
        runtime.get("execution_profile") != "powershell-preverified-cpython-3.12.13-I-S-B/v1"
        or runtime.get("launcher_profile") != _LAUNCHER_PROFILE
    ):
        raise GovernanceError("generation-2 Python execution profile changed")
    expected_runtime_files = {
        "python.exe": {
            "name": "python.exe",
            "absolute_path": str(_FROZEN_PYTHON_EXECUTABLE),
            "size_bytes": _FROZEN_PYTHON_EXECUTABLE_SIZE,
            "sha256": f"sha256:{_FROZEN_PYTHON_EXECUTABLE_SHA256}",
        },
        "python312.dll": {
            "name": "python312.dll",
            "absolute_path": str(_FROZEN_PYTHON_DLL),
            "size_bytes": _FROZEN_PYTHON_DLL_SIZE,
            "sha256": f"sha256:{_FROZEN_PYTHON_DLL_SHA256}",
        },
    }
    runtime_files: dict[str, Mapping[str, Any]] = {}
    for item in _as_array(runtime.get("files"), owner="trusted Python files"):
        runtime_file = _as_object(item, owner="trusted Python file")
        name = _required_string(runtime_file, "name")
        if name in runtime_files:
            raise GovernanceError(f"duplicate generation-2 trusted Python file: {name}")
        runtime_files[name] = runtime_file
    if runtime_files != expected_runtime_files:
        raise GovernanceError("generation-2 trusted Python files changed")
    if runtime.get("base_runtime_inventory") != {
        "file_count": _FROZEN_BASE_RUNTIME_FILE_COUNT,
        "size_bytes": _FROZEN_BASE_RUNTIME_SIZE_BYTES,
        "sha256": f"sha256:{_FROZEN_BASE_RUNTIME_SHA256}",
    } or runtime.get("site_runtime_inventory") != {
        "file_count": _FROZEN_RUNTIME_FILE_COUNT,
        "size_bytes": _FROZEN_RUNTIME_SIZE_BYTES,
        "sha256": f"sha256:{_FROZEN_RUNTIME_SHA256}",
    }:
        raise GovernanceError("generation-2 Python runtime inventory changed")

    cli = _as_object(record.get("cli_reservation"), owner="generation-2 CLI reservation")
    if (
        cli.get("outcome") != "expected_absence"
        or cli.get("exit_code") != 2
        or cli.get("reserved_command") != "agent-assure test activate"
        or cli.get("collision_found") is not False
    ):
        raise GovernanceError("generation-2 CLI reservation changed")
    _baseline_v2_observation_window(
        {
            "started_at_utc": cli.get("started_at_utc"),
            "completed_at_utc": cli.get("completed_at_utc"),
        },
        owner="CLI reservation",
        inventory_start=inventory_start,
        inventory_end=inventory_end,
    )

    locks_record = _as_object(record.get("dependency_locks"), owner="dependency locks")
    _baseline_v2_observation_window(
        locks_record.get("observation_window"),
        owner="dependency locks",
        inventory_start=inventory_start,
        inventory_end=inventory_end,
    )
    observed_locks: dict[str, str] = {}
    for value in _as_array(locks_record.get("artifacts"), owner="dependency lock artifacts"):
        lock = _as_object(value, owner="dependency lock")
        path = _required_string(lock, "path")
        digest = _required_string(lock, "sha256")
        if path in observed_locks:
            raise GovernanceError(f"duplicate generation-2 dependency lock: {path}")
        observed_locks[path] = digest
    if observed_locks != PINNED_LOCK_DIGESTS:
        raise GovernanceError("generation-2 dependency lock identities changed")
    for path, digest in observed_locks.items():
        committed = _read_commit_blob(
            repository_root,
            PINNED_BASE_COMMIT,
            path,
            owner="pinned dependency lock",
        )
        if raw_digest(committed) != digest:
            raise GovernanceError(f"pinned base does not reproduce dependency lock: {path}")

    integrity = _as_object(record.get("git_integrity"), owner="generation-2 Git integrity")
    _baseline_v2_observation_window(
        integrity.get("observation_window"),
        owner="Git integrity",
        inventory_start=inventory_start,
        inventory_end=inventory_end,
    )
    if (
        integrity.get("replacement_refs") != []
        or integrity.get("shallow_repository") is not False
        or integrity.get("grafts_present") is not False
        or integrity.get("alternate_object_store_present") is not False
        or integrity.get("generation_1_tag_object") != S1_ACCEPTANCE_V1_TAG_OBJECT
        or integrity.get("generation_2_tag_absent") is not True
    ):
        raise GovernanceError("generation-2 Git integrity observation changed")

    expected_digest = domain_digest(
        BASELINE_OBSERVATIONS_V2_DOMAIN,
        _record_projection(record, "observations_digest"),
    )
    if record.get("observations_digest") != expected_digest:
        raise GovernanceError("generation-2 baseline observations digest mismatch")
    return expected_digest


def _baseline_full_suite_status(record: Mapping[str, Any]) -> str:
    if record.get("format") == "agent-assure-baseline-observations/2":
        historical = _as_object(
            record.get("historical_context"), owner="generation-2 baseline historical context"
        )
        if historical.get("post_r2_full_suite_required") is not True:
            raise GovernanceError("generation-2 baseline must require post-R2 verification")
        return "post_result_verification_required"
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

    if record.get("format") == "agent-assure-baseline-observations/2":
        return _validate_baseline_observations_v2(
            snapshot,
            record,
            schema,
            repository_root=repository_root,
        )

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
    committed = _read_commit_blob(
        repository_root,
        result_commit,
        relative_path,
        owner="result artifact",
    )
    return {
        "path": relative_path,
        "kind": kind,
        "size_bytes": len(committed),
        "sha256": raw_digest(committed),
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


def _require_empty_openssh_program_data(path: Path) -> None:
    """Require the isolated OpenSSH machine-data directory to remain pristine."""

    _post_r2_safe_directory(path, owner="isolated OpenSSH PROGRAMDATA directory")
    try:
        modified = next(path.iterdir(), None) is not None
    except OSError as exc:
        raise GovernanceError("unable to inspect isolated OpenSSH PROGRAMDATA") from exc
    if modified:
        raise GovernanceError("OpenSSH modified its isolated PROGRAMDATA directory")


@contextmanager
def _isolated_openssh_environment() -> Iterator[dict[str, str]]:
    """Yield a governed environment with fresh per-call Windows machine data."""

    with tempfile.TemporaryDirectory(prefix="agent-assure-s1-openssh-") as temporary:
        program_data = Path(temporary) / "program-data"
        program_data.mkdir()
        _require_empty_openssh_program_data(program_data)
        environment = _governance_subprocess_environment()
        for key in tuple(environment):
            if key.casefold() == "programdata":
                del environment[key]
        environment["PROGRAMDATA"] = str(program_data)
        try:
            yield environment
        except BaseException as primary:
            try:
                _require_empty_openssh_program_data(program_data)
            except BaseException as postcondition:
                primary.add_note(
                    f"isolated OpenSSH PROGRAMDATA postcondition also failed: {postcondition}"
                )
            raise
        else:
            _require_empty_openssh_program_data(program_data)


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


def _run_git(
    repository_root: Path,
    arguments: Sequence[str],
    *,
    input_bytes: bytes | None = None,
) -> subprocess.CompletedProcess[bytes]:
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
                input=input_bytes,
                timeout=30,
            )
    except subprocess.TimeoutExpired as exc:
        raise GovernanceError("governed Git inspection timed out") from exc


def _bounded_git_failure(completed: subprocess.CompletedProcess[bytes]) -> str:
    """Return a stable, bounded diagnostic for a failed governed Git call."""

    raw = completed.stderr if completed.stderr else completed.stdout
    detail = " ".join(raw.decode("utf-8", errors="replace").split())
    if len(detail) > MAX_GIT_DIAGNOSTIC_CHARS:
        detail = detail[: MAX_GIT_DIAGNOSTIC_CHARS - 3] + "..."
    status = f"Git exited with status {completed.returncode}"
    return f"{status}: {detail}" if detail else status


def _read_commit_blob(
    repository_root: Path,
    commit: str,
    relative_path: str,
    *,
    owner: str,
) -> bytes:
    """Read one exact regular blob without revision/path expression parsing.

    ``git show <revision>:<path>`` combines two independently supplied values
    into Git's revision-expression grammar.  That is unnecessary here and can
    turn path handling failures into misleading content mismatches.  Resolve
    the exact tree entry with NUL-delimited output, validate its mode/type/path,
    and then address the immutable blob object directly.
    """

    if GIT_COMMIT_PATTERN.fullmatch(commit) is None:
        raise GovernanceError(f"{owner} commit must be a full lowercase 40-hex object ID")
    if (
        not relative_path
        or "\x00" in relative_path
        or "\\" in relative_path
        or Path(relative_path).is_absolute()
        or Path(relative_path).as_posix() != relative_path
        or any(part in {"", ".", ".."} for part in relative_path.split("/"))
    ):
        raise GovernanceError(f"{owner} path is not a canonical repository path: {relative_path}")
    tree_entry = _run_git(
        repository_root,
        ["ls-tree", "-z", "--full-tree", commit, "--", f":(top,literal){relative_path}"],
    )
    if tree_entry.returncode != 0:
        raise GovernanceError(
            f"unable to inspect {owner} tree entry: {relative_path} "
            f"({_bounded_git_failure(tree_entry)})"
        )
    if not tree_entry.stdout.endswith(b"\x00"):
        if tree_entry.stdout:
            raise _GitBlobSemanticError(
                f"Git returned a malformed {owner} tree entry: {relative_path}"
            )
        raise _GitBlobSemanticError(f"{owner} is not a regular Git blob: {relative_path}")
    records = tree_entry.stdout[:-1].split(b"\x00")
    if len(records) != 1:
        raise _GitBlobSemanticError(
            f"Git returned an ambiguous {owner} tree entry: {relative_path}"
        )
    metadata, separator, raw_path = records[0].partition(b"\t")
    fields = metadata.split(b" ")
    if (
        separator != b"\t"
        or len(fields) != 3
        or fields[0] not in {b"100644", b"100755"}
        or fields[1] != b"blob"
        or re.fullmatch(rb"[0-9a-f]{40}", fields[2]) is None
    ):
        raise _GitBlobSemanticError(f"{owner} is not a regular Git blob: {relative_path}")
    try:
        observed_path = raw_path.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise _GitBlobSemanticError(f"{owner} tree path is not UTF-8: {relative_path}") from exc
    if observed_path != relative_path:
        raise _GitBlobSemanticError(f"Git returned another {owner} tree path: {relative_path}")
    blob = _run_git(repository_root, ["cat-file", "blob", fields[2].decode("ascii")])
    if blob.returncode != 0:
        raise GovernanceError(
            f"unable to read {owner}: {relative_path} ({_bounded_git_failure(blob)})"
        )
    return blob.stdout


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
    """Require an ignored, untracked path and current bytes absent from the object DB."""

    root = repository_root.resolve()
    _validate_repository_identity(root)
    resolved = _resolve_repository_path_without_links(
        root,
        roadmap_path,
        owner="private roadmap",
    )
    relative = resolved.relative_to(root).as_posix()
    if relative != "Agent_Assure_Implementation_Roadmap.md":
        raise GovernanceError("unexpected private roadmap path")
    if not resolved.is_file():
        raise GovernanceError("private roadmap is not a regular file")
    roadmap_bytes = resolved.read_bytes()
    if len(roadmap_bytes) > MAX_ROADMAP_BYTES:
        raise GovernanceError("roadmap exceeds the 4 MiB input limit")
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
    object_id_result = _run_git(
        root,
        ["hash-object", "--stdin"],
        input_bytes=roadmap_bytes,
    )
    object_id = object_id_result.stdout.decode("ascii", errors="strict").strip()
    if object_id_result.returncode != 0 or GIT_COMMIT_PATTERN.fullmatch(object_id) is None:
        raise GovernanceError("unable to compute the private roadmap Git blob ID")
    object_lookup = _run_git(
        root,
        ["cat-file", "--batch-check=%(objectname) %(objecttype)"],
        input_bytes=f"{object_id}\n".encode("ascii"),
    )
    if object_lookup.returncode != 0:
        raise GovernanceError("unable to inspect the Git object database for roadmap bytes")
    lookup_fields = object_lookup.stdout.decode("ascii", errors="strict").strip().split()
    if lookup_fields == [object_id, "missing"]:
        return relative
    if len(lookup_fields) == 2 and lookup_fields[0] == object_id:
        raise GovernanceError(
            "private roadmap bytes already exist in the local Git object database"
        )
    raise GovernanceError("unexpected Git object lookup result for private roadmap bytes")


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


def _validate_corrective_acceptance_tag_state(
    repository_root: Path,
    *,
    head_commit: str,
) -> None:
    """Require the immutable predecessor tag and an unused successor tag name."""

    predecessor_refs = {
        f"refs/tags/{S1_ACCEPTANCE_TAG_NAME}^{{tag}}": S1_ACCEPTANCE_V1_TAG_OBJECT,
        f"refs/tags/{S1_ACCEPTANCE_TAG_NAME}^{{commit}}": S1_ACCEPTANCE_V1_CLOSURE_COMMIT,
    }
    for ref, expected in predecessor_refs.items():
        resolved = _run_git(repository_root, ["rev-parse", "--verify", ref])
        if resolved.returncode != 0:
            raise GovernanceError(
                "generation-2 preflight cannot resolve the immutable predecessor acceptance tag"
            )
        actual = resolved.stdout.decode("ascii", errors="strict").strip()
        if actual != expected:
            raise GovernanceError("generation-2 predecessor acceptance tag moved or changed")
    predecessor_ancestry = _run_git(
        repository_root,
        ["merge-base", "--is-ancestor", S1_ACCEPTANCE_V1_CLOSURE_COMMIT, head_commit],
    )
    if predecessor_ancestry.returncode != 0:
        raise GovernanceError(
            "generation-2 HEAD does not descend from the predecessor acceptance closure"
        )
    successor_ref = f"refs/tags/{S1_ACCEPTANCE_V2_TAG_NAME}"
    successor = _run_git(
        repository_root,
        ["show-ref", "--verify", "--quiet", successor_ref],
    )
    if successor.returncode == 0:
        raise GovernanceError(
            "generation-2 successor acceptance tag already exists and must never be moved"
        )
    if successor.returncode != 1:
        raise GovernanceError(
            "generation-2 preflight could not prove the successor acceptance tag is absent"
        )


def validate_live_acceptance_repository(
    repository_root: Path,
    *,
    fetch: bool,
    expected_branch_name: str = S1_BRANCH_NAME,
) -> dict[str, Any]:
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
    if branch.stdout.decode("utf-8", errors="strict").strip() != expected_branch_name:
        raise GovernanceError("acceptance repository is not on the governed acceptance branch")
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
    if expected_branch_name == S1_CORRECTIVE_BRANCH_NAME:
        _validate_corrective_acceptance_tag_state(
            repository_root,
            head_commit=head_commit,
        )
    return {
        "approved_remote_url": APPROVED_ORIGIN_URL,
        "authoritative_remote_refs": observed_remote_refs,
        "branch_name": expected_branch_name,
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
        committed = _read_commit_blob(
            repository_root,
            result_commit,
            relative_path,
            owner="reviewed artifact",
        )
        expected_size = _required_integer(artifact, "size_bytes")
        if len(committed) != expected_size:
            raise GovernanceError(
                f"reviewed artifact size differs from completion result commit: {relative_path}"
            )
        if raw_digest(committed) != artifact.get("sha256"):
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
        _read_commit_blob(
            repository_root,
            result_commit,
            path,
            owner="S1 artifact",
        )


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
            try:
                committed = _read_commit_blob(
                    repository_root,
                    candidate,
                    path,
                    owner="S1 closure artifact",
                )
            except _GitBlobSemanticError:
                candidate_matches = False
                break
            if path == "docs/governance/v1/governance-bundle.json":
                if committed != expected_bundle_bytes:
                    candidate_matches = False
                    break
            else:
                evidence = receipt_evidence_by_path[path]
                if (
                    len(committed) != evidence["size_bytes"]
                    or raw_digest(committed) != evidence["sha256"]
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
    bundle_domain = (
        BUNDLE_V2_DOMAIN
        if bundle.get("format") == "agent-assure-governance-bundle/2"
        else BUNDLE_DOMAIN
    )
    expected_bundle_digest = domain_digest(bundle_domain, _bundle_projection(bundle))
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
    if record.get("format") == "agent-assure-ticket-completion-receipt/2":
        validate_ticket_completion_receipt_v2(
            snapshot,
            record,
            schema,
            repository_root=repository_root,
            expected_ticket_id=expected_ticket_id,
            expected_roster_digest=expected_roster_digest,
            # Generation 2 replaces, rather than extends, the generation-1
            # kickoff/receipt chain.  The compatibility wrapper still accepts
            # the legacy arguments so historical generation-1 callers remain
            # byte-for-byte stable, but a v2 record is always anchored to the
            # one signed corrective kickoff and immutable C1 closure.
            expected_corrective_authorization_digest=CORRECTIVE_KICKOFF_CLAIM_DIGEST,
            expected_person_id=expected_person_id,
            expected_result_parent=S1_ACCEPTANCE_V1_CLOSURE_COMMIT,
            allow_pending=allow_pending,
        )
        return
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
    excluded = {"bundle_digest", "signature_envelope"}
    if bundle.get("format") == "agent-assure-governance-bundle/2":
        excluded.add("signature_import_evidence")
    return {key: value for key, value in bundle.items() if key not in excluded}


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
    if bundle.get("format") == "agent-assure-governance-bundle/2":
        validate_governance_bundle_v2(
            snapshot,
            bundle,
            schema,
            repository_root=repository_root,
            roster=roster,
            completion_receipts=completion_receipts,
            forecast=forecast,
            baseline_observations=baseline_observations,
            expected_person_id=expected_person_id,
            expected_result_parent=S1_ACCEPTANCE_V1_CLOSURE_COMMIT,
            allow_pending=allow_pending,
            validation_time=validation_time,
            require_current_closure=require_current_closure,
            require_closure=require_closure,
            expected_closure_commit=expected_closure_commit,
        )
        return
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


def _bounded_openssh_failure(completed: subprocess.CompletedProcess[bytes]) -> str:
    """Return a stable, bounded diagnostic for a failed OpenSSH invocation."""

    details: list[str] = []
    for name, raw in (("stderr", completed.stderr), ("stdout", completed.stdout)):
        detail = " ".join(raw.decode("utf-8", errors="replace").split())
        if detail:
            details.append(f"{name}={detail}")
    rendered = "; ".join(details) if details else "<no stdout/stderr>"
    if len(rendered) > MAX_OPENSSH_DIAGNOSTIC_CHARS:
        rendered = rendered[: MAX_OPENSSH_DIAGNOSTIC_CHARS - 3] + "..."
    return f"OpenSSH exited with status {completed.returncode}: {rendered}"


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
            with _isolated_openssh_environment() as environment:
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
                    env=environment,
                    timeout=10,
                )
        except subprocess.TimeoutExpired as exc:
            raise GovernanceError("OpenSSH signature verification timed out") from exc
    if completed.returncode != 0:
        raise GovernanceError(
            "OpenSSH signature verification failed: " + _bounded_openssh_failure(completed)
        )


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


def _pending_signature_v2(person_id: str, role: str, subject_digest: str) -> dict[str, Any]:
    """Create a generation-2 SSHSIG envelope with no signature-time claim.

    OpenSSH SSHSIG carries no trusted or untrusted timestamp.  Generation 2
    therefore binds any relevant preparation times through the signed subject
    and deliberately omits the legacy ``signed_at_utc`` member everywhere.
    """

    return {
        "profile": SIGNATURE_PROFILE,
        "status": "pending_human_signature",
        "namespace": SIGNATURE_NAMESPACE,
        "signed_payload_encoding": ATTESTATION_V2_SIGNATURE_PAYLOAD_ENCODING,
        "signature_encoding": SIGNATURE_ENCODING,
        "signer_person_id": person_id,
        "signer_role": role,
        "subject_digest": subject_digest,
        "public_key_fingerprint": MAINTAINER_KEY_FINGERPRINT,
        "signature": None,
    }


def _signature_claim_bytes_v2(envelope: Mapping[str, Any]) -> bytes:
    """Render a timestamp-free, role-bound generation-2 signature claim."""

    claim = {
        "namespace": _required_string(envelope, "namespace"),
        "signer_person_id": _required_string(envelope, "signer_person_id"),
        "signer_role": _required_string(envelope, "signer_role"),
        "subject_digest": _required_string(envelope, "subject_digest"),
        "public_key_fingerprint": _required_string(envelope, "public_key_fingerprint"),
    }
    return ATTESTATION_V2_SIGNATURE_CLAIM_DOMAIN.encode("ascii") + b"\x00" + canonical_bytes(claim)


def _validate_signature_envelope_v2(
    value: object,
    *,
    expected_person_id: str,
    expected_role: str,
    expected_subject_digest: str,
    allow_pending: bool,
    owner: str,
    expected_verification_evidence: object = _NO_SIGNATURE_VERIFICATION_EVIDENCE,
) -> bool:
    """Validate a generation-2 SSHSIG without inventing a signing time."""

    envelope = _as_object(value, owner=f"{owner} signature envelope")
    expected_fields = ATTESTATION_V2_SIGNATURE_ENVELOPE_FIELDS
    if expected_verification_evidence is not _NO_SIGNATURE_VERIFICATION_EVIDENCE:
        expected_fields = expected_fields | {"verification_evidence"}
    if set(envelope) != expected_fields:
        raise GovernanceError(f"{owner} signature envelope has unexpected fields")
    if (
        expected_verification_evidence is not _NO_SIGNATURE_VERIFICATION_EVIDENCE
        and envelope.get("verification_evidence") != expected_verification_evidence
    ):
        raise GovernanceError(f"{owner} signature verification evidence changed")
    exact = {
        "profile": SIGNATURE_PROFILE,
        "namespace": SIGNATURE_NAMESPACE,
        "signed_payload_encoding": ATTESTATION_V2_SIGNATURE_PAYLOAD_ENCODING,
        "signature_encoding": SIGNATURE_ENCODING,
        "signer_person_id": expected_person_id,
        "signer_role": expected_role,
        "subject_digest": expected_subject_digest,
        "public_key_fingerprint": MAINTAINER_KEY_FINGERPRINT,
    }
    for key, expected in exact.items():
        if envelope.get(key) != expected:
            raise GovernanceError(f"{owner} signature envelope {key} changed")
    if _public_key_fingerprint(MAINTAINER_PUBLIC_KEY) != MAINTAINER_KEY_FINGERPRINT:
        raise GovernanceError(
            "embedded maintainer public key does not match its frozen fingerprint"
        )
    status = _required_string(envelope, "status")
    signature = envelope.get("signature")
    if status == "pending_human_signature":
        if signature is not None:
            raise GovernanceError(f"pending {owner} signature must contain a null signature")
        if not allow_pending:
            raise GovernanceError(f"required {owner} signature is pending")
        return False
    if status != "signed" or not isinstance(signature, str):
        raise GovernanceError(f"{owner} signature must be pending or contain a signed sshsig")
    _verify_sshsig(
        signature_base64=signature,
        payload=_signature_claim_bytes_v2(envelope),
        signer_person_id=expected_person_id,
        public_key=MAINTAINER_PUBLIC_KEY,
    )
    return True


def _pending_attestation_v2_signature(
    person_id: str, role: str, subject_digest: str
) -> dict[str, Any]:
    return _pending_signature_v2(person_id, role, subject_digest)


def _attestation_v2_signature_claim_bytes(envelope: Mapping[str, Any]) -> bytes:
    return _signature_claim_bytes_v2(envelope)


def _validate_attestation_v2_signature_envelope(
    value: object,
    *,
    expected_person_id: str,
    expected_subject_digest: str,
    allow_pending: bool,
) -> bool:
    return _validate_signature_envelope_v2(
        value,
        expected_person_id=expected_person_id,
        expected_role="repository_maintainer",
        expected_subject_digest=expected_subject_digest,
        allow_pending=allow_pending,
        owner="generation-2 acceptance",
    )


def _corrective_authorized_paths(
    corrective_authorization: Mapping[str, Any],
) -> tuple[str, ...]:
    """Return the canonical path allowlist authenticated by the corrective kickoff."""

    if (
        corrective_authorization.get("format")
        != "agent-assure-s1-corrective-kickoff-authorization/1"
        or corrective_authorization.get("authorization_status") != "authorized"
    ):
        raise GovernanceError("corrective authorization is not the signed authorized record")
    claim_artifact = _as_object(
        corrective_authorization.get("signed_claim_artifact"),
        owner="corrective signed claim artifact",
    )
    if claim_artifact.get("sha256") != CORRECTIVE_KICKOFF_CLAIM_DIGEST:
        raise GovernanceError("corrective authorization claim digest changed")
    signed_claim = _as_object(
        corrective_authorization.get("signed_claim"), owner="corrective signed claim"
    )
    raw_paths = _required_string_array(signed_claim, "tracked_allowed_paths")
    if len(raw_paths) != len(set(raw_paths)):
        raise GovernanceError("corrective authorization repeats an allowed path")
    ordered = tuple(sorted(raw_paths, key=_utf8_sort_key))
    if tuple(raw_paths) != ordered:
        raise GovernanceError("corrective authorization path allowlist is not canonical")
    if not S1_CORRECTIVE_CLOSURE_PATHS <= set(ordered):
        raise GovernanceError("corrective authorization omits a required closure path")
    for path in ordered:
        if (
            Path(path).as_posix() != path
            or path.startswith("/")
            or "\\" in path
            or ".." in Path(path).parts
        ):
            raise GovernanceError(f"corrective authorization contains a noncanonical path: {path}")
    return ordered


def _corrective_artifact_kind(path: str) -> str:
    if path.endswith(".schema.json"):
        return "governance_schema"
    if path.endswith(".json"):
        return "governance_record"
    if path.endswith(".md"):
        return "governance_documentation"
    if path.endswith(".py"):
        return "verification_or_validator"
    if path.endswith(".ps1"):
        return "governance_runtime_launcher"
    if path.endswith(".yml") or path.endswith(".yaml"):
        return "repository_integration"
    return "repository_integration"


def _corrective_result_artifact_inventory(
    repository_root: Path,
    *,
    result_commit: str,
    corrective_authorization: Mapping[str, Any],
    expected_result_parent: str | None = None,
) -> list[dict[str, Any]]:
    """Validate C1 -> R2 and return the exact, byte-bound R2 change inventory."""

    if GIT_COMMIT_PATTERN.fullmatch(result_commit) is None:
        raise GovernanceError("corrective result commit must be a full 40-hex object ID")
    if expected_result_parent is None:
        expected_result_parent = S1_ACCEPTANCE_V1_CLOSURE_COMMIT
    if expected_result_parent != S1_ACCEPTANCE_V1_CLOSURE_COMMIT:
        raise GovernanceError("corrective result parent must be immutable generation-1 C1")
    parent_record = _run_git(repository_root, ["rev-list", "--parents", "-n", "1", result_commit])
    fields = parent_record.stdout.decode("ascii", errors="strict").split()
    if parent_record.returncode != 0 or fields != [result_commit, expected_result_parent]:
        raise GovernanceError(
            "corrective R2 must be the direct, non-merge child of immutable generation-1 C1"
        )
    allowed_all = set(_corrective_authorized_paths(corrective_authorization))
    allowed_result = allowed_all - S1_CORRECTIVE_CLOSURE_PATHS
    changes = _git_name_status(repository_root, expected_result_parent, result_commit)
    if not changes:
        raise GovernanceError("corrective R2 must contain at least one governed correction")
    unauthorized = sorted(set(changes) - allowed_result, key=_utf8_sort_key)
    if unauthorized:
        raise GovernanceError(f"corrective R2 touched unauthorized paths: {unauthorized}")
    forbidden_statuses = {
        path: status for path, status in changes.items() if status not in {"A", "M"}
    }
    if forbidden_statuses:
        raise GovernanceError(
            f"corrective R2 contains forbidden change statuses: {forbidden_statuses}"
        )
    inventory: list[dict[str, Any]] = []
    for path in sorted(changes, key=_utf8_sort_key):
        payload = _read_commit_blob(
            repository_root,
            result_commit,
            path,
            owner="corrective R2 artifact",
        )
        inventory.append(
            {
                "path": path,
                "kind": _corrective_artifact_kind(path),
                "change_status": changes[path],
                "size_bytes": len(payload),
                "sha256": raw_digest(payload),
            }
        )
    return inventory


def _corrective_change_control(
    repository_root: Path,
    *,
    result_commit: str,
    corrective_authorization: Mapping[str, Any],
    expected_result_parent: str | None = None,
) -> dict[str, Any]:
    if expected_result_parent is None:
        expected_result_parent = S1_ACCEPTANCE_V1_CLOSURE_COMMIT
    authorized_paths = list(_corrective_authorized_paths(corrective_authorization))
    inventory = _corrective_result_artifact_inventory(
        repository_root,
        result_commit=result_commit,
        corrective_authorization=corrective_authorization,
        expected_result_parent=expected_result_parent,
    )
    return {
        "result_parent_commit": expected_result_parent,
        "result_commit": result_commit,
        "authorized_change_paths": authorized_paths,
        "authorized_change_paths_digest": domain_digest(
            CORRECTIVE_CHANGE_ALLOWLIST_DOMAIN, {"paths": authorized_paths}
        ),
        "result_artifact_inventory": inventory,
        "result_artifact_set_digest": domain_digest(
            CORRECTIVE_RESULT_ARTIFACT_SET_DOMAIN, {"artifacts": inventory}
        ),
    }


def _validate_generation_1_closure_placeholders(
    repository_root: Path,
    governance_root: Path,
) -> dict[str, dict[str, Any]]:
    """Require the three live closure files to remain the exact C1 bytes.

    A generation-2 forecast and its supporting records intentionally coexist
    with the immutable generation-1 closure files before C2 is materialized.
    Treating those files as a v1 bundle over the new forecast would be both
    false and impossible.  This byte comparison is the explicit transition
    state: no result commit is needed, and no mixed-generation closure is
    accepted.
    """

    root = repository_root.resolve()
    expected_governance_root = (root / "docs/governance/v1").resolve()
    if governance_root.resolve() != expected_governance_root:
        raise GovernanceError("S1 governance directory must be docs/governance/v1")
    records: dict[str, dict[str, Any]] = {}
    for relative in sorted(S1_CORRECTIVE_CLOSURE_PATHS, key=_utf8_sort_key):
        path = _resolve_repository_path_without_links(
            root,
            relative,
            owner="generation-1 closure placeholder",
        )
        if not path.is_file() or path.is_symlink():
            raise GovernanceError(
                f"generation-1 closure placeholder is not a regular file: {relative}"
            )
        expected = _read_commit_blob(
            root,
            S1_ACCEPTANCE_V1_CLOSURE_COMMIT,
            relative,
            owner="immutable generation-1 closure placeholder",
        )
        actual = path.read_bytes()
        if actual != expected:
            raise GovernanceError(
                f"generation-1 closure placeholder differs from immutable C1: {relative}"
            )
        record = _read_json(path)
        expected_format = (
            "agent-assure-governance-bundle/1"
            if relative.endswith("governance-bundle.json")
            else "agent-assure-ticket-completion-receipt/1"
        )
        if record.get("format") != expected_format:
            raise GovernanceError(f"generation-1 closure placeholder identity changed: {relative}")
        records[relative] = record
    return records


def _require_clean_corrective_result_checkout(
    repository_root: Path,
    *,
    result_commit: str,
    owner: str,
) -> dict[str, Any]:
    state = _post_r2_repository_state(repository_root)
    if state.get("head_commit") != result_commit or state.get("clean") is not True:
        raise GovernanceError(f"{owner} requires a clean checkout at exact R2")
    return state


def _forecast_binding_v2(forecast: Mapping[str, Any], *, require_accepted: bool) -> dict[str, Any]:
    if forecast.get("format") != "agent-assure-delivery-forecast/2":
        raise GovernanceError("corrective closure requires the generation-2 delivery forecast")
    fields = {
        "forecast_record_digest": "record_digest",
        "estimation_catalog_digest": "estimation_catalog_digest",
        "aggregation_method_registry_digest": "aggregation_method_registry_digest",
        "authoring_ledger_digest": "authoring_ledger_digest",
    }
    result: dict[str, Any] = {
        "forecast_format": "agent-assure-delivery-forecast/2",
        "forecast_status": _required_string(forecast, "forecast_status"),
        "human_review_status": _required_string(forecast, "human_review_status"),
    }
    for target, source in fields.items():
        value = _required_string(forecast, source)
        if SHA256_PATTERN.fullmatch(value) is None:
            raise GovernanceError(f"corrective forecast {source} is not a SHA-256 digest")
        result[target] = value
    receipt = _as_object(forecast.get("acceptance_receipt"), owner="forecast acceptance receipt")
    result["forecast_acceptance_status"] = _required_string(receipt, "receipt_status")
    receipt_digest = receipt.get("receipt_digest")
    if not isinstance(receipt_digest, str) or SHA256_PATTERN.fullmatch(receipt_digest) is None:
        if require_accepted:
            raise GovernanceError("corrective forecast acceptance receipt lacks a bound digest")
        result["forecast_acceptance_receipt_digest"] = None
    else:
        result["forecast_acceptance_receipt_digest"] = receipt_digest
    if require_accepted:
        if (
            result["forecast_status"] != "accepted"
            or result["human_review_status"] != "complete"
            or result["forecast_acceptance_status"] != "accepted_for_development"
        ):
            raise GovernanceError(
                "corrective closure requires the accepted human-reviewed forecast"
            )
        producer_envelope = _as_object(
            forecast.get("signature_envelope"), owner="forecast producer signature"
        )
        acceptance_envelope = _as_object(
            receipt.get("signature_envelope"), owner="forecast acceptance signature"
        )
        if (
            producer_envelope.get("status") != "signed"
            or acceptance_envelope.get("status") != "signed"
        ):
            raise GovernanceError("corrective closure requires both forecast SSHSIGs")
    return result


def _post_r2_execution_outcome(exit_code: int) -> str:
    return {
        0: "passed",
        1: "failed",
        2: "interrupted",
        3: "internal_error",
        4: "usage_error",
        5: "no_tests_collected",
    }.get(exit_code, "unexpected_exit")


def _parse_post_r2_pytest_totals(stdout: bytes, stderr: bytes) -> dict[str, int]:
    """Parse pytest's terminal summary without trusting hand-entered counts."""

    try:
        rendered_streams = {
            "stdout": stdout.decode("utf-8", errors="strict"),
            "stderr": stderr.decode("utf-8", errors="strict"),
        }
    except UnicodeDecodeError as exc:
        raise GovernanceError("post-R2 pytest output is not deterministic UTF-8") from exc

    category = r"(?:passed|failed|skipped|xfailed|xpassed|errors?|deselected|warnings?)"
    statistic = rf"(?:[1-9][0-9]* {category})"
    summary_pattern = re.compile(
        rf"(?P<statistics>{statistic}(?:, {statistic})*) "
        r"in [0-9]+\.[0-9]{2}s(?: \([^\r\n()]+\))?"
    )
    wrapped_prefix_pattern = re.compile(rf"{statistic}(?:, {statistic})*,")
    candidates: list[tuple[str, str, re.Match[str]]] = []
    wrapped_prefixes: list[tuple[str, str]] = []
    for stream_name, rendered in rendered_streams.items():
        for line in rendered.splitlines():
            summary_match = summary_pattern.fullmatch(line)
            if summary_match is not None:
                candidates.append((stream_name, line, summary_match))
            if wrapped_prefix_pattern.fullmatch(line):
                wrapped_prefixes.append((stream_name, line))
    if not candidates:
        raise GovernanceError("post-R2 pytest output lacks a parseable terminal summary")
    if len(candidates) != 1 or wrapped_prefixes:
        raise GovernanceError("post-R2 pytest output has ambiguous terminal summaries")
    stream_name, _line, summary_match = candidates[0]
    if stream_name != "stdout":
        raise GovernanceError("post-R2 pytest terminal summary is not on stdout")

    category_pattern = re.compile(
        r"(?P<count>[1-9][0-9]*) "
        r"(?P<category>passed|failed|skipped|xfailed|xpassed|errors?|deselected|warnings?)"
    )
    matches = [
        category_pattern.fullmatch(value) for value in summary_match.group("statistics").split(", ")
    ]
    if any(match is None for match in matches):
        raise GovernanceError("post-R2 pytest terminal summary grammar changed")
    totals = {
        "passed": 0,
        "failed": 0,
        "skipped": 0,
        "xfailed": 0,
        "xpassed": 0,
        "errors": 0,
    }
    seen: set[str] = set()
    deselected = 0
    for match in matches:
        assert match is not None
        raw_category = match.group("category")
        category = "errors" if raw_category in {"error", "errors"} else raw_category
        category = "warnings" if category in {"warning", "warnings"} else category
        if category == "deselected":
            if category in seen:
                raise GovernanceError(f"post-R2 pytest summary repeats category: {category}")
            seen.add(category)
            deselected = int(match.group("count"))
            continue
        if category == "warnings":
            if category in seen:
                raise GovernanceError(f"post-R2 pytest summary repeats category: {category}")
            seen.add(category)
            continue
        if category in seen:
            raise GovernanceError(f"post-R2 pytest summary repeats category: {category}")
        seen.add(category)
        totals[category] = int(match.group("count"))
    totals["collected"] = sum(totals[name] for name in totals if name != "errors") + deselected
    if totals["collected"] <= 0:
        raise GovernanceError("post-R2 pytest summary reports no collected tests")
    return {
        "collected": totals["collected"],
        "passed": totals["passed"],
        "failed": totals["failed"],
        "skipped": totals["skipped"],
        "xfailed": totals["xfailed"],
        "xpassed": totals["xpassed"],
        "errors": totals["errors"],
    }


def _parse_post_r2_pytest_execution_totals(
    completed: subprocess.CompletedProcess[bytes],
) -> dict[str, int]:
    """Parse totals while retaining non-sensitive facts needed to diagnose failure."""

    try:
        return _parse_post_r2_pytest_totals(completed.stdout, completed.stderr)
    except GovernanceError as exc:
        raise GovernanceError(
            f"{exc}; exit_code={completed.returncode}; "
            f"outcome={_post_r2_execution_outcome(completed.returncode)}; "
            f"stdout_size_bytes={len(completed.stdout)}; "
            f"stdout_sha256={raw_digest(completed.stdout)}; "
            f"stderr_size_bytes={len(completed.stderr)}; "
            f"stderr_sha256={raw_digest(completed.stderr)}"
        ) from exc


def _post_r2_repository_state(repository_root: Path) -> dict[str, Any]:
    head = _run_git(repository_root, ["rev-parse", "--verify", "HEAD^{commit}"])
    if head.returncode != 0:
        raise GovernanceError("unable to resolve repository HEAD for post-R2 evidence")
    status = _run_git(repository_root, ["status", "--porcelain=v1", "--untracked-files=all"])
    if status.returncode != 0:
        raise GovernanceError("unable to inspect repository cleanliness for post-R2 evidence")
    return {
        "head_commit": head.stdout.decode("ascii", errors="strict").strip(),
        "clean": not bool(status.stdout),
        "status_command": ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        "status_stdout_size_bytes": len(status.stdout),
        "status_stdout_sha256": raw_digest(status.stdout),
    }


def _measure_post_r2_test_runtime_inventory(
    repository_root: Path,
    site_packages: Path,
) -> dict[str, Any]:
    """Measure every non-cache file admitted to the pytest import path."""

    root = repository_root.resolve()
    site_root = _resolve_repository_path_without_links(
        root,
        site_packages,
        owner="post-R2 pytest site-packages",
    )
    if not site_root.is_dir() or site_root.is_symlink():
        raise GovernanceError("post-R2 pytest site-packages is not a regular directory")
    rows: list[tuple[str, int, bytes]] = []
    for candidate in sorted(site_root.rglob("*"), key=lambda value: value.as_posix()):
        relative = candidate.relative_to(site_root)
        if any(
            part in POST_R2_TEST_RUNTIME_EXCLUDED_DIRECTORY_NAMES for part in relative.parts[:-1]
        ):
            continue
        metadata = candidate.lstat()
        attributes = getattr(metadata, "st_file_attributes", 0)
        if candidate.is_symlink() or bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT):
            raise GovernanceError(
                f"post-R2 pytest runtime contains a reparse point: {relative.as_posix()}"
            )
        if candidate.is_dir():
            continue
        if not candidate.is_file():
            raise GovernanceError(
                f"post-R2 pytest runtime contains a non-file: {relative.as_posix()}"
            )
        if candidate.suffix.casefold() in POST_R2_TEST_RUNTIME_FORBIDDEN_FILE_SUFFIXES:
            raise GovernanceError(
                f"post-R2 pytest runtime contains direct sourceless bytecode: {relative.as_posix()}"
            )
        size = metadata.st_size
        with candidate.open("rb") as handle:
            file_hash = hashlib.file_digest(handle, "sha256").digest()
        rows.append((relative.as_posix(), size, file_hash))
    if not rows:
        raise GovernanceError("post-R2 pytest runtime inventory is empty")
    rows.sort(key=lambda row: _utf8_sort_key(row[0]))
    inventory_digest = hashlib.sha256(POST_R2_TEST_RUNTIME_INVENTORY_DOMAIN)
    for relative_name, size, file_digest in rows:
        encoded = relative_name.encode("utf-8")
        inventory_digest.update(len(encoded).to_bytes(8, "big"))
        inventory_digest.update(encoded)
        inventory_digest.update(size.to_bytes(8, "big"))
        inventory_digest.update(file_digest)
    inventory = {
        "format": "agent-assure-s1-post-r2-test-runtime-inventory/1",
        "relative_root": site_root.relative_to(root).as_posix(),
        "exclusion_policy": {
            "directory_names": sorted(POST_R2_TEST_RUNTIME_EXCLUDED_DIRECTORY_NAMES),
            "forbidden_direct_file_suffixes": sorted(POST_R2_TEST_RUNTIME_FORBIDDEN_FILE_SUFFIXES),
            "reason": "cache_directories_inert_under_fresh_pycache_prefix",
        },
        "file_count": len(rows),
        "size_bytes": sum(row[1] for row in rows),
        "sha256": "sha256:" + inventory_digest.hexdigest(),
    }
    return inventory


def _post_r2_test_runtime_inventory(
    repository_root: Path,
    site_packages: Path,
) -> dict[str, Any]:
    """Authenticate the measured pytest import path against the frozen inventory."""

    inventory = _measure_post_r2_test_runtime_inventory(repository_root, site_packages)
    expected = {
        "file_count": POST_R2_TEST_RUNTIME_FILE_COUNT,
        "size_bytes": POST_R2_TEST_RUNTIME_SIZE_BYTES,
        "sha256": "sha256:" + POST_R2_TEST_RUNTIME_SHA256,
    }
    if any(inventory[key] != value for key, value in expected.items()):
        raise GovernanceError("post-R2 pytest site-packages inventory changed")
    return inventory


def _post_r2_runtime_file_evidence(
    repository_root: Path,
    path: Path,
    *,
    owner: str,
) -> dict[str, Any]:
    root = repository_root.resolve()
    resolved = _resolve_repository_path_without_links(root, path, owner=owner)
    if not resolved.is_file() or resolved.is_symlink():
        raise GovernanceError(f"{owner} is not a regular file")
    payload = resolved.read_bytes()
    return {
        "absolute_path": str(resolved),
        "relative_path": resolved.relative_to(root).as_posix(),
        "size_bytes": len(payload),
        "sha256": raw_digest(payload),
    }


def _post_r2_test_runtime_evidence(repository_root: Path) -> dict[str, Any]:
    """Bind the authenticated venv packages and already-frozen base runtime."""

    root = repository_root.resolve()
    try:
        observed_base_inventory = _base_runtime_inventory(_FROZEN_PYTHON_ROOT)
        _early_verify_file(
            _FROZEN_PYTHON_EXECUTABLE,
            expected_size=_FROZEN_PYTHON_EXECUTABLE_SIZE,
            expected_sha256=_FROZEN_PYTHON_EXECUTABLE_SHA256,
            owner="post-R2 frozen Python executable",
        )
        _early_verify_file(
            _FROZEN_PYTHON_DLL,
            expected_size=_FROZEN_PYTHON_DLL_SIZE,
            expected_sha256=_FROZEN_PYTHON_DLL_SHA256,
            owner="post-R2 frozen Python DLL",
        )
    except (OSError, RuntimeError) as exc:
        raise GovernanceError(f"post-R2 frozen base runtime validation failed: {exc}") from exc
    expected_base_inventory = (
        _FROZEN_BASE_RUNTIME_FILE_COUNT,
        _FROZEN_BASE_RUNTIME_SIZE_BYTES,
        _FROZEN_BASE_RUNTIME_SHA256,
    )
    if observed_base_inventory != expected_base_inventory:
        raise GovernanceError("post-R2 frozen base runtime inventory changed")
    configuration = root / ".venv/pyvenv.cfg"
    site_packages = root / ".venv/Lib/site-packages"
    return {
        "format": "agent-assure-s1-post-r2-test-runtime/2",
        "pyvenv_configuration": _post_r2_runtime_file_evidence(
            root,
            configuration,
            owner="post-R2 pyvenv configuration",
        ),
        "site_packages_inventory": _post_r2_test_runtime_inventory(root, site_packages),
        "base_runtime": {
            "root": str(_FROZEN_PYTHON_ROOT),
            "python_executable": {
                "absolute_path": str(_FROZEN_PYTHON_EXECUTABLE),
                "size_bytes": _FROZEN_PYTHON_EXECUTABLE_SIZE,
                "sha256": "sha256:" + _FROZEN_PYTHON_EXECUTABLE_SHA256,
            },
            "python_dll": {
                "absolute_path": str(_FROZEN_PYTHON_DLL),
                "size_bytes": _FROZEN_PYTHON_DLL_SIZE,
                "sha256": "sha256:" + _FROZEN_PYTHON_DLL_SHA256,
            },
            "inventory": {
                "file_count": _FROZEN_BASE_RUNTIME_FILE_COUNT,
                "size_bytes": _FROZEN_BASE_RUNTIME_SIZE_BYTES,
                "sha256": "sha256:" + _FROZEN_BASE_RUNTIME_SHA256,
            },
        },
    }


def _post_r2_git_tree_entries(
    repository_root: Path,
    result_commit: str,
) -> dict[str, tuple[str, str]]:
    """Read the immutable commit tree without consulting the mutable index."""

    object_format = _run_git(repository_root, ["rev-parse", "--show-object-format"])
    if object_format.returncode != 0 or object_format.stdout.strip() != b"sha1":
        raise GovernanceError("post-R2 test-surface verification requires SHA-1 Git objects")
    completed = _run_git(repository_root, ["ls-tree", "-r", "-z", result_commit])
    if completed.returncode != 0:
        raise GovernanceError("unable to enumerate the immutable post-R2 test surface")
    entries: dict[str, tuple[str, str]] = {}
    for raw_entry in completed.stdout.split(b"\x00"):
        if not raw_entry:
            continue
        try:
            metadata, raw_path = raw_entry.split(b"\t", 1)
            mode, object_type, object_id = metadata.decode("ascii").split(" ")
            relative = raw_path.decode("utf-8", errors="strict")
        except (UnicodeDecodeError, ValueError) as exc:
            raise GovernanceError("post-R2 commit tree contains an invalid entry") from exc
        if (
            object_type != "blob"
            or mode not in {"100644", "100755"}
            or GIT_COMMIT_PATTERN.fullmatch(object_id) is None
            or relative in entries
        ):
            raise GovernanceError("post-R2 commit tree contains an unsupported entry")
        entries[relative] = (mode, object_id)
    return entries


def _post_r2_git_exclude_evidence(repository_root: Path) -> dict[str, Any]:
    """Require the accepted host's exact local-exclude bytes."""

    path = repository_root / ".git/info/exclude"
    if not path.is_file() or path.is_symlink():
        raise GovernanceError("post-R2 .git/info/exclude is not a regular file")
    payload = path.read_bytes()
    digest = raw_digest(payload)
    if (
        len(payload) != POST_R2_GIT_EXCLUDE_SIZE_BYTES
        or digest != "sha256:" + POST_R2_GIT_EXCLUDE_SHA256
    ):
        raise GovernanceError("post-R2 .git/info/exclude policy changed")
    return {
        "path": ".git/info/exclude",
        "size_bytes": len(payload),
        "sha256": digest,
    }


def _post_r2_test_surface_evidence(
    repository_root: Path,
    *,
    result_commit: str,
) -> dict[str, Any]:
    """Bind every tracked byte and reject extra files that can affect pytest."""

    root = repository_root.resolve()
    all_entries = _post_r2_git_tree_entries(root, result_commit)
    directory_roots = set(POST_R2_TEST_AFFECTING_DIRECTORIES)
    tracked_root_files = set(POST_R2_TRACKED_ROOT_FILES)
    commit_directory_roots = {
        Path(relative).parts[0] for relative in all_entries if len(Path(relative).parts) > 1
    }
    commit_root_files = {relative for relative in all_entries if len(Path(relative).parts) == 1}
    if commit_directory_roots != directory_roots:
        raise GovernanceError("post-R2 tracked top-level directory set changed")
    if commit_root_files != tracked_root_files:
        raise GovernanceError("post-R2 tracked root-file set changed")

    def in_scope(relative: str) -> bool:
        path = Path(relative)
        if len(path.parts) == 1:
            return relative in tracked_root_files
        return path.parts[0] in directory_roots

    expected = {path: entry for path, entry in all_entries.items() if in_scope(path)}
    observed: set[str] = set()

    def require_regular_file(path: Path, relative: str) -> None:
        metadata = path.lstat()
        attributes = getattr(metadata, "st_file_attributes", 0)
        if path.is_symlink() or bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT):
            raise GovernanceError(f"post-R2 test surface contains a reparse point: {relative}")
        if not path.is_file():
            raise GovernanceError(f"post-R2 test surface contains a non-file: {relative}")
        if path.suffix.casefold() in POST_R2_TEST_RUNTIME_FORBIDDEN_FILE_SUFFIXES:
            raise GovernanceError(
                f"post-R2 repository contains direct sourceless bytecode: {relative}"
            )
        observed.add(relative)

    for name in POST_R2_TRACKED_ROOT_FILES:
        candidate = root / name
        if not candidate.exists() and not candidate.is_symlink():
            raise GovernanceError(f"post-R2 tracked root file is missing: {name}")
        require_regular_file(candidate, name)
    for name in POST_R2_ROOT_TEST_CONFIG_PATHS:
        candidate = root / name
        if candidate.exists() or candidate.is_symlink():
            require_regular_file(candidate, name)
    for candidate in root.iterdir():
        if candidate.name not in tracked_root_files and candidate.suffix.casefold() in {
            ".py",
            ".pyc",
            ".pyo",
        }:
            require_regular_file(candidate, candidate.name)
        if (
            candidate.name.isidentifier()
            and candidate.name not in directory_roots
            and (candidate.is_dir() or candidate.is_symlink())
        ):
            raise GovernanceError(
                "post-R2 repository contains an untracked import-capable root directory: "
                f"{candidate.name}"
            )

    def walk_error(error: OSError) -> None:
        raise GovernanceError(f"unable to enumerate post-R2 test surface: {error}")

    for top_level in POST_R2_TEST_AFFECTING_DIRECTORIES:
        top = root / top_level
        if not top.is_dir() or top.is_symlink():
            raise GovernanceError(f"post-R2 test-surface root is not a directory: {top_level}")
        for current, directories, files in os.walk(top, topdown=True, onerror=walk_error):
            current_path = Path(current)
            retained_directories: list[str] = []
            for name in sorted(directories, key=_utf8_sort_key):
                child = current_path / name
                relative = child.relative_to(root).as_posix()
                metadata = child.lstat()
                attributes = getattr(metadata, "st_file_attributes", 0)
                if child.is_symlink() or bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT):
                    raise GovernanceError(
                        f"post-R2 test surface contains a reparse point: {relative}"
                    )
                if name != "__pycache__":
                    retained_directories.append(name)
            directories[:] = retained_directories
            for name in sorted(files, key=_utf8_sort_key):
                candidate = current_path / name
                relative = candidate.relative_to(root).as_posix()
                require_regular_file(candidate, relative)

    if observed != set(expected):
        extras = sorted(observed - set(expected), key=_utf8_sort_key)
        missing = sorted(set(expected) - observed, key=_utf8_sort_key)
        raise GovernanceError(
            "post-R2 test surface differs from immutable R2 "
            f"(extra={extras[:8]}, missing={missing[:8]})"
        )

    rows: list[tuple[str, int, bytes]] = []
    for relative in sorted(observed, key=_utf8_sort_key):
        path = root / relative
        payload = path.read_bytes()
        _mode, expected_object_id = expected[relative]
        git_object = hashlib.sha1(
            b"blob " + str(len(payload)).encode("ascii") + b"\x00" + payload,
            usedforsecurity=False,
        ).hexdigest()
        if git_object != expected_object_id:
            raise GovernanceError(f"post-R2 test-surface bytes differ from R2: {relative}")
        rows.append((relative, len(payload), hashlib.sha256(payload).digest()))

    digest = hashlib.sha256(POST_R2_TEST_SURFACE_INVENTORY_DOMAIN)
    for relative, size, file_digest in rows:
        encoded = relative.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        digest.update(size.to_bytes(8, "big"))
        digest.update(file_digest)
    return {
        "format": "agent-assure-s1-post-r2-test-surface/1",
        "subject_result_commit": result_commit,
        "directory_roots": list(POST_R2_TEST_AFFECTING_DIRECTORIES),
        "tracked_root_files": list(POST_R2_TRACKED_ROOT_FILES),
        "root_config_paths": list(POST_R2_ROOT_TEST_CONFIG_PATHS),
        "cache_policy": {
            "excluded_directory_name": "__pycache__",
            "reason": "fresh_absolute_pycache_prefix_makes_source_adjacent_caches_inert",
            "forbidden_direct_file_suffixes": sorted(POST_R2_TEST_RUNTIME_FORBIDDEN_FILE_SUFFIXES),
        },
        "local_exclude": _post_r2_git_exclude_evidence(root),
        "file_count": len(rows),
        "size_bytes": sum(row[1] for row in rows),
        "sha256": "sha256:" + digest.hexdigest(),
    }


def _post_r2_governance_source_evidence(
    repository_root: Path,
    roadmap_path: Path,
) -> list[dict[str, Any]]:
    paths = (
        roadmap_path.resolve(),
        repository_root / "docs/governance/v1/corrective-kickoff-authorization.json",
        repository_root / "docs/governance/v1/corrective-kickoff-authorization.schema.json",
    )
    return [
        _source_file_evidence(repository_root, path)
        for path in sorted(paths, key=lambda value: _utf8_sort_key(str(value)))
    ]


def _allocate_post_r2_run_paths(_repository_root: Path) -> tuple[Path, Path]:
    """Allocate one fresh external root for pytest and its governed runtime."""

    process_temp_root = _post_r2_process_temp_root()
    process_temp: Path | None = None
    try:
        process_temp = Path(
            tempfile.mkdtemp(
                prefix=POST_R2_PROCESS_TEMP_PREFIX,
                dir=process_temp_root,
            )
        )
        _post_r2_validate_process_temp(process_temp, require_empty=True)
        basetemp = process_temp / POST_R2_PYTEST_BASETEMP_DIRECTORY
        if basetemp.exists() or basetemp.is_symlink():
            raise GovernanceError("post-R2 pytest basetemp must be absent before process start")
    except BaseException as primary:
        if process_temp is not None:
            _cleanup_post_r2_process_temp_after_failure(process_temp, primary)
        raise
    return basetemp, process_temp


def _post_r2_pytest_argv(
    repository_root: Path,
    *,
    basetemp: Path,
    process_temp: Path,
    test_surface: Mapping[str, Any],
) -> list[str]:
    """Build the exact site-free frozen-Python pytest command."""

    root = repository_root.resolve()
    if not basetemp.is_absolute():
        raise GovernanceError("post-R2 pytest basetemp must be absolute")
    pycache_prefix = basetemp / "python-bytecode-cache"
    site_packages = root / ".venv/Lib/site-packages"
    return [
        str(_FROZEN_PYTHON_EXECUTABLE),
        *POST_R2_PYTHON_ARGUMENTS,
        "-X",
        f"pycache_prefix={pycache_prefix}",
        "-",
        str(root),
        str(root / "src"),
        str(site_packages),
        str(pycache_prefix),
        str(_required_integer(test_surface, "file_count")),
        str(_required_integer(test_surface, "size_bytes")),
        _required_string(test_surface, "sha256"),
        *POST_R2_PYTEST_ARGUMENTS,
        "--basetemp",
        str(basetemp),
    ]


def _post_r2_bootstrap_input(
    repository_root: Path,
    *,
    basetemp: Path,
    process_temp: Path,
) -> tuple[bytes, dict[str, Any]]:
    """Return the exact stdin bootstrap and its evidence-bound identity."""

    payload = _post_r2_pytest_bootstrap_source(
        repository_root.resolve(),
        basetemp=basetemp,
        process_temp=process_temp,
    ).encode("utf-8")
    return payload, {
        "transport": "python_stdin_utf8",
        "size_bytes": len(payload),
        "sha256": raw_digest(payload),
    }


def _post_r2_bytecode_policy(basetemp: Path) -> dict[str, Any]:
    pycache_prefix = basetemp / "python-bytecode-cache"
    return {
        "basetemp": str(basetemp),
        "basetemp_precondition": "fresh_unique_and_absent_immediately_before_spawn",
        "pycache_prefix": str(pycache_prefix),
        "pycache_prefix_precondition": "absent_immediately_before_spawn",
        "main_process_write_policy": "disabled_by_-B",
        "descendant_read_policy": "explicit_fresh_prefix_injected_at_recursive_Popen_boundary",
        "descendant_write_policy": "explicit_-B_injected_at_recursive_Popen_boundary",
        "descendant_guard_bypass_policy": "sitecustomize_fails_closed_without_exact_cli_policy",
        "pycache_prefix_postcondition": "absent_after_suite_execution",
        "repository_cache_policy": "source_adjacent___pycache___ignored_via_fresh_prefix",
        "repository_direct_bytecode_policy": "reject_pyc_and_pyo",
        "site_packages_cache_policy": "excluded_inert___pycache___only",
        "site_packages_direct_bytecode_policy": "reject_pyc_and_pyo",
    }


def _publish_post_r2_suite_evidence_directory(
    evidence_root: Path,
    *,
    record: Mapping[str, Any],
    stdout: bytes,
    stderr: bytes,
) -> None:
    """Atomically publish the complete three-file evidence set."""

    evidence_root.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(
        tempfile.mkdtemp(
            prefix=f"{evidence_root.name}-publish-",
            suffix=".publish.tmp",
            dir=evidence_root.parent,
        )
    )
    try:
        payloads = {
            "post-r2-suite-evidence.json": _render_json_bytes(record),
            "pytest.stdout.bin": stdout,
            "pytest.stderr.bin": stderr,
        }
        for name, payload in payloads.items():
            with (temporary / name).open("xb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        _fsync_directory(temporary)
        temporary.replace(evidence_root)
        _fsync_directory(evidence_root.parent)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary, ignore_errors=True)


def _canonical_host_utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _post_r2_subprocess_environment(
    repository_root: Path,
    basetemp: Path,
    *,
    process_temp: Path,
) -> dict[str, str]:
    """Build the complete allowlisted child environment from no inherited state."""

    root = repository_root.resolve()
    if not basetemp.is_absolute() or not process_temp.is_absolute():
        raise GovernanceError("post-R2 child environment paths must be absolute")
    pycache_prefix = basetemp / "python-bytecode-cache"
    descendant_scripts = process_temp / POST_R2_DESCENDANT_RUNTIME_DIRECTORY / "Scripts"
    user_temp = process_temp / POST_R2_PROCESS_USER_TEMP_DIRECTORY
    return {
        "COMSPEC": r"C:\Windows\System32\cmd.exe",
        "GIT_CONFIG_COUNT": "2",
        "GIT_CONFIG_GLOBAL": "NUL",
        "GIT_CONFIG_KEY_0": "core.autocrlf",
        "GIT_CONFIG_KEY_1": "safe.directory",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_VALUE_0": "true",
        "GIT_CONFIG_VALUE_1": str(root),
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": r"C:\Users\user",
        "HOMEDRIVE": "C:",
        "HOMEPATH": r"\Users\user",
        "HYPOTHESIS_STORAGE_DIRECTORY": str(basetemp / "hypothesis"),
        "NO_COLOR": "1",
        "NoDefaultCurrentDirectoryInExePath": "1",
        "PATH": str(descendant_scripts) + ";" + POST_R2_CHILD_PATH,
        "PATHEXT": ".COM;.EXE;.BAT;.CMD",
        "PROCESSOR_ARCHITECTURE": "AMD64",
        "PYTHONNOUSERSITE": "1",
        "PYTHONPYCACHEPREFIX": str(pycache_prefix),
        "PYTHONSAFEPATH": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUTF8": "1",
        "PY_COLORS": "0",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "SYSTEMROOT": r"C:\Windows",
        "TEMP": str(user_temp),
        "TMP": str(user_temp),
        "USERPROFILE": r"C:\Users\user",
        "WINDIR": r"C:\Windows",
    }


def _execute_post_r2_pytest(
    repository_root: Path,
    *,
    test_surface: Mapping[str, Any],
) -> tuple[
    Path,
    list[str],
    dict[str, str],
    dict[str, Any],
    dict[str, Any],
    str,
    subprocess.CompletedProcess[bytes],
    str,
]:
    """Run pytest once with fresh governed storage and return exact execution facts."""

    root = repository_root.resolve()
    basetemp, process_temp = _allocate_post_r2_run_paths(root)
    try:
        if basetemp != process_temp / POST_R2_PYTEST_BASETEMP_DIRECTORY:
            raise GovernanceError("post-R2 pytest basetemp path binding changed")
        descendant_runtime = _prepare_post_r2_descendant_runtime(
            root,
            basetemp=basetemp,
            process_temp=process_temp,
        )
        argv = _post_r2_pytest_argv(
            root,
            basetemp=basetemp,
            process_temp=process_temp,
            test_surface=test_surface,
        )
        environment = _post_r2_subprocess_environment(
            root,
            basetemp,
            process_temp=process_temp,
        )
        bootstrap_payload, bootstrap_input = _post_r2_bootstrap_input(
            root,
            basetemp=basetemp,
            process_temp=process_temp,
        )
        pycache_prefix = basetemp / "python-bytecode-cache"
        if (
            basetemp.exists()
            or basetemp.is_symlink()
            or pycache_prefix.exists()
            or pycache_prefix.is_symlink()
        ):
            raise GovernanceError(
                "post-R2 basetemp and bytecode prefix must be absent immediately before spawn"
            )
        if (
            _verify_post_r2_descendant_runtime(
                root,
                basetemp=basetemp,
                process_temp=process_temp,
                require_empty_user_temp=True,
            )
            != descendant_runtime
        ):
            raise GovernanceError("post-R2 descendant runtime changed before spawn")
        started_at = _canonical_host_utc_now()
        completed = subprocess.run(
            argv,
            cwd=root,
            env=environment,
            input=bootstrap_payload,
            capture_output=True,
            check=False,
        )
        completed_at = _canonical_host_utc_now()
        if (
            _verify_post_r2_descendant_runtime(
                root,
                basetemp=basetemp,
                process_temp=process_temp,
                require_empty_user_temp=False,
            )
            != descendant_runtime
        ):
            raise GovernanceError("post-R2 descendant runtime changed during suite execution")
        result = (
            basetemp,
            argv,
            environment,
            descendant_runtime,
            bootstrap_input,
            started_at,
            completed,
            completed_at,
        )
    except BaseException as primary:
        _cleanup_post_r2_process_temp_after_failure(process_temp, primary)
        raise
    _cleanup_post_r2_process_temp(process_temp)
    return result


def capture_post_r2_suite_evidence(
    repository_root: Path,
    *,
    roadmap_path: Path,
    result_commit: str,
    corrective_authorization: Mapping[str, Any],
    evidence_directory: str | Path = POST_R2_SUITE_EVIDENCE_DIRECTORY,
) -> dict[str, Any]:
    """Run the exact full suite once and persist local-only, source-verifiable evidence.

    The output directory is deliberately separate from pytest's ignored
    ``--basetemp`` so pytest cleanup cannot delete the evidence it is meant to
    support.  The function never manufactures or accepts result counts; all
    totals are parsed from the captured raw pytest streams.
    """

    root = repository_root.resolve()
    evidence_root = _corrective_private_acceptance_path(
        root,
        evidence_directory,
        owner="post-R2 suite evidence directory",
        must_exist=False,
    )
    if evidence_root.exists() or evidence_root.is_symlink():
        if not evidence_root.is_dir() or evidence_root.is_symlink():
            raise GovernanceError("post-R2 suite evidence target is not a regular directory")
        evidence_path = evidence_root / "post-r2-suite-evidence.json"
        return validate_post_r2_suite_evidence_source(
            evidence_path,
            expected_result_commit=result_commit,
            expected_repository_root=root,
            require_passed=False,
        )
    _corrective_result_artifact_inventory(
        root,
        result_commit=result_commit,
        corrective_authorization=corrective_authorization,
    )
    governance_sources = _post_r2_governance_source_evidence(root, roadmap_path)
    pre_state = _post_r2_repository_state(root)
    if pre_state != {
        **pre_state,
        "head_commit": result_commit,
        "clean": True,
    }:
        raise GovernanceError("post-R2 suite must start at clean R2")

    test_runtime = _post_r2_test_runtime_evidence(root)
    test_surface = _post_r2_test_surface_evidence(
        root,
        result_commit=result_commit,
    )
    (
        basetemp,
        argv,
        environment,
        descendant_runtime,
        bootstrap_input,
        started_at,
        completed,
        completed_at,
    ) = _execute_post_r2_pytest(root, test_surface=test_surface)
    if evidence_root == basetemp or evidence_root.is_relative_to(basetemp):
        raise GovernanceError("post-R2 evidence must be outside pytest's basetemp")
    if (
        _post_r2_test_surface_evidence(
            root,
            result_commit=result_commit,
        )
        != test_surface
    ):
        raise GovernanceError("post-R2 repository test surface changed during suite execution")
    if _post_r2_test_runtime_evidence(root) != test_runtime:
        raise GovernanceError("post-R2 pytest runtime changed during suite execution")
    if _post_r2_governance_source_evidence(root, roadmap_path) != governance_sources:
        raise GovernanceError("post-R2 governance sources changed during suite execution")
    _corrective_result_artifact_inventory(
        root,
        result_commit=result_commit,
        corrective_authorization=corrective_authorization,
    )
    post_state = _post_r2_repository_state(root)
    totals = _parse_post_r2_pytest_execution_totals(completed)
    projection: dict[str, Any] = {
        "format": "agent-assure-s1-post-r2-suite-evidence/3",
        "acceptance_generation": 2,
        "subject_result_parent_commit": S1_ACCEPTANCE_V1_CLOSURE_COMMIT,
        "subject_result_commit": result_commit,
        "corrective_authorization_claim_digest": CORRECTIVE_KICKOFF_CLAIM_DIGEST,
        "governance_sources": governance_sources,
        "repository_test_surface": test_surface,
        "command": {
            "argv": argv,
            "working_directory": str(root),
            "environment": environment,
            "python_executable": test_runtime["base_runtime"]["python_executable"],
            "descendant_runtime": descendant_runtime,
            "bootstrap_input": bootstrap_input,
            "bytecode_policy": _post_r2_bytecode_policy(basetemp),
            "test_runtime": test_runtime,
        },
        "time_evidence": {
            **ATTESTATION_V2_TIME_EVIDENCE,
            "started_at_utc": started_at,
            "completed_at_utc": completed_at,
        },
        "repository_precondition": pre_state,
        "repository_postcondition": post_state,
        "execution": {
            "exit_code": completed.returncode,
            "outcome": _post_r2_execution_outcome(completed.returncode),
            "pytest_totals": totals,
            "stdout": {
                "file_name": "pytest.stdout.bin",
                "size_bytes": len(completed.stdout),
                "sha256": raw_digest(completed.stdout),
            },
            "stderr": {
                "file_name": "pytest.stderr.bin",
                "size_bytes": len(completed.stderr),
                "sha256": raw_digest(completed.stderr),
            },
        },
    }
    record = {
        **projection,
        "evidence_digest": domain_digest(POST_R2_SUITE_EVIDENCE_DOMAIN, projection),
    }
    try:
        _publish_post_r2_suite_evidence_directory(
            evidence_root,
            record=record,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )
    except FileExistsError:
        return validate_post_r2_suite_evidence_source(
            evidence_root / "post-r2-suite-evidence.json",
            expected_result_commit=result_commit,
            expected_repository_root=root,
            require_passed=False,
        )
    return record


def _validate_post_r2_test_surface_record(
    value: object,
    *,
    expected_result_commit: str,
) -> dict[str, Any]:
    surface = _as_object(value, owner="post-R2 repository test surface")
    if set(surface) != {
        "format",
        "subject_result_commit",
        "directory_roots",
        "tracked_root_files",
        "root_config_paths",
        "cache_policy",
        "local_exclude",
        "file_count",
        "size_bytes",
        "sha256",
    }:
        raise GovernanceError("post-R2 repository test-surface evidence is malformed")
    if (
        surface.get("format") != "agent-assure-s1-post-r2-test-surface/1"
        or surface.get("subject_result_commit") != expected_result_commit
        or surface.get("directory_roots") != list(POST_R2_TEST_AFFECTING_DIRECTORIES)
        or surface.get("tracked_root_files") != list(POST_R2_TRACKED_ROOT_FILES)
        or surface.get("root_config_paths") != list(POST_R2_ROOT_TEST_CONFIG_PATHS)
        or surface.get("cache_policy")
        != {
            "excluded_directory_name": "__pycache__",
            "reason": "fresh_absolute_pycache_prefix_makes_source_adjacent_caches_inert",
            "forbidden_direct_file_suffixes": sorted(POST_R2_TEST_RUNTIME_FORBIDDEN_FILE_SUFFIXES),
        }
        or _required_integer(surface, "file_count") <= 0
        or _required_integer(surface, "size_bytes") <= 0
        or SHA256_PATTERN.fullmatch(_required_string(surface, "sha256")) is None
    ):
        raise GovernanceError("post-R2 repository test-surface evidence changed")
    local_exclude = _as_object(
        surface.get("local_exclude"),
        owner="post-R2 local-exclude evidence",
    )
    if local_exclude != {
        "path": ".git/info/exclude",
        "size_bytes": POST_R2_GIT_EXCLUDE_SIZE_BYTES,
        "sha256": "sha256:" + POST_R2_GIT_EXCLUDE_SHA256,
    }:
        raise GovernanceError("post-R2 local-exclude evidence changed")
    return surface


def _validate_embedded_post_r2_suite_evidence(
    evidence: Mapping[str, Any],
    *,
    expected_result_commit: str,
    require_passed: bool,
) -> dict[str, Any]:
    expected_keys = {
        "format",
        "acceptance_generation",
        "subject_result_parent_commit",
        "subject_result_commit",
        "corrective_authorization_claim_digest",
        "governance_sources",
        "repository_test_surface",
        "command",
        "time_evidence",
        "repository_precondition",
        "repository_postcondition",
        "execution",
        "evidence_digest",
    }
    if set(evidence) != expected_keys:
        raise GovernanceError("post-R2 suite evidence has missing or unexpected fields")
    exact = {
        "format": "agent-assure-s1-post-r2-suite-evidence/3",
        "acceptance_generation": 2,
        "subject_result_parent_commit": S1_ACCEPTANCE_V1_CLOSURE_COMMIT,
        "subject_result_commit": expected_result_commit,
        "corrective_authorization_claim_digest": CORRECTIVE_KICKOFF_CLAIM_DIGEST,
    }
    for key, expected in exact.items():
        if evidence.get(key) != expected:
            raise GovernanceError(f"post-R2 suite evidence changed {key}")
    governance_sources = _as_array(
        evidence.get("governance_sources"), owner="post-R2 governance sources"
    )
    source_paths: set[str] = set()
    for value in governance_sources:
        source = _as_object(value, owner="post-R2 governance source")
        if set(source) != {"path", "size_bytes", "sha256"}:
            raise GovernanceError("post-R2 governance source evidence is malformed")
        path = _required_string(source, "path")
        if path in source_paths:
            raise GovernanceError("post-R2 governance source evidence repeats a path")
        source_paths.add(path)
        if (
            _required_integer(source, "size_bytes") <= 0
            or SHA256_PATTERN.fullmatch(_required_string(source, "sha256")) is None
        ):
            raise GovernanceError("post-R2 governance source evidence is invalid")
    required_governance_sources = {
        "docs/governance/v1/corrective-kickoff-authorization.json",
        "docs/governance/v1/corrective-kickoff-authorization.schema.json",
    }
    roadmap_sources = source_paths - required_governance_sources
    if not required_governance_sources <= source_paths or roadmap_sources != {
        "Agent_Assure_Implementation_Roadmap.md"
    }:
        raise GovernanceError("post-R2 governance source set is not exact")
    test_surface = _validate_post_r2_test_surface_record(
        evidence.get("repository_test_surface"),
        expected_result_commit=expected_result_commit,
    )
    command = _as_object(evidence.get("command"), owner="post-R2 suite command")
    if set(command) != {
        "argv",
        "working_directory",
        "environment",
        "python_executable",
        "descendant_runtime",
        "bootstrap_input",
        "bytecode_policy",
        "test_runtime",
    }:
        raise GovernanceError("post-R2 suite command has unexpected fields")
    raw_argv = _as_array(command.get("argv"), owner="post-R2 suite argv")
    if not raw_argv or any(not isinstance(value, str) or not value for value in raw_argv):
        raise GovernanceError("post-R2 suite argv entries must be non-empty strings")
    argv = cast(list[str], raw_argv)
    executable = _as_object(command.get("python_executable"), owner="post-R2 Python executable")
    working_directory_value = command.get("working_directory")
    if not isinstance(working_directory_value, str):
        raise GovernanceError("post-R2 suite working directory must be absolute")
    working_directory = Path(working_directory_value)
    if len(argv) < 2 or argv[-2] != "--basetemp":
        raise GovernanceError("post-R2 suite must carry one exact absolute --basetemp")
    basetemp = Path(argv[-1])
    if not working_directory.is_absolute() or not basetemp.is_absolute():
        raise GovernanceError("post-R2 suite paths must be absolute")
    normalized_root = Path(os.path.abspath(working_directory))
    normalized_basetemp = Path(os.path.abspath(basetemp))

    raw_environment = _as_object(command.get("environment"), owner="post-R2 environment")
    if any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in raw_environment.items()
    ):
        raise GovernanceError("post-R2 environment must contain only string pairs")
    environment = cast(dict[str, str], raw_environment)
    user_temp_value = environment.get("TEMP")
    if not isinstance(user_temp_value, str) or environment.get("TMP") != user_temp_value:
        raise GovernanceError("post-R2 process temporary directory binding changed")
    user_temp = Path(os.path.abspath(user_temp_value))
    if not Path(user_temp_value).is_absolute():
        raise GovernanceError("post-R2 process temporary directory must be absolute")
    process_temp = user_temp.parent
    if (
        user_temp.name != POST_R2_PROCESS_USER_TEMP_DIRECTORY
        or process_temp.parent != POST_R2_PROCESS_TEMP_ROOT
        or not process_temp.name.startswith(POST_R2_PROCESS_TEMP_PREFIX)
        or len(process_temp.name) <= len(POST_R2_PROCESS_TEMP_PREFIX)
    ):
        raise GovernanceError("post-R2 process temporary directory prefix changed")
    if normalized_basetemp != process_temp / POST_R2_PYTEST_BASETEMP_DIRECTORY:
        raise GovernanceError("post-R2 suite basetemp is not bound to process temporary storage")
    expected_environment = _post_r2_subprocess_environment(
        normalized_root,
        normalized_basetemp,
        process_temp=process_temp,
    )
    if environment != expected_environment:
        raise GovernanceError("post-R2 suite exact environment changed")
    _expected_bootstrap_payload, expected_bootstrap_input = _post_r2_bootstrap_input(
        normalized_root,
        basetemp=normalized_basetemp,
        process_temp=process_temp,
    )
    if command.get("bootstrap_input") != expected_bootstrap_input:
        raise GovernanceError("post-R2 suite bootstrap stdin identity changed")
    expected_argv = _post_r2_pytest_argv(
        normalized_root,
        basetemp=normalized_basetemp,
        process_temp=process_temp,
        test_surface=test_surface,
    )
    if argv != expected_argv:
        raise GovernanceError("post-R2 suite pytest argv changed")
    if command.get("bytecode_policy") != _post_r2_bytecode_policy(normalized_basetemp):
        raise GovernanceError("post-R2 suite bytecode policy changed")
    expected_descendant_runtime = _post_r2_descendant_runtime_record(
        normalized_root,
        basetemp=normalized_basetemp,
        process_temp=process_temp,
    )
    if command.get("descendant_runtime") != expected_descendant_runtime:
        raise GovernanceError("post-R2 descendant runtime evidence changed")
    expected_executable = {
        "absolute_path": str(_FROZEN_PYTHON_EXECUTABLE),
        "size_bytes": _FROZEN_PYTHON_EXECUTABLE_SIZE,
        "sha256": "sha256:" + _FROZEN_PYTHON_EXECUTABLE_SHA256,
    }
    if (
        set(executable)
        != {
            "absolute_path",
            "size_bytes",
            "sha256",
        }
        or executable != expected_executable
    ):
        raise GovernanceError("post-R2 frozen Python executable evidence changed")
    if argv[0] != executable["absolute_path"]:
        raise GovernanceError("post-R2 suite argv is not bound to its Python executable")
    test_runtime = _as_object(command.get("test_runtime"), owner="post-R2 test runtime")
    if (
        set(test_runtime)
        != {
            "format",
            "pyvenv_configuration",
            "site_packages_inventory",
            "base_runtime",
        }
        or test_runtime.get("format") != "agent-assure-s1-post-r2-test-runtime/2"
    ):
        raise GovernanceError("post-R2 test runtime evidence is malformed")
    pyvenv = _as_object(
        test_runtime.get("pyvenv_configuration"),
        owner="post-R2 pyvenv configuration",
    )
    if set(pyvenv) != {
        "absolute_path",
        "relative_path",
        "size_bytes",
        "sha256",
    } or (
        not isinstance(pyvenv.get("absolute_path"), str)
        or not Path(cast(str, pyvenv["absolute_path"])).is_absolute()
        or pyvenv.get("relative_path") != ".venv/pyvenv.cfg"
        or not isinstance(pyvenv.get("size_bytes"), int)
        or cast(int, pyvenv["size_bytes"]) <= 0
        or not isinstance(pyvenv.get("sha256"), str)
        or SHA256_PATTERN.fullmatch(cast(str, pyvenv["sha256"])) is None
    ):
        raise GovernanceError("post-R2 pyvenv configuration evidence is invalid")
    inventory = _as_object(
        test_runtime.get("site_packages_inventory"),
        owner="post-R2 test runtime inventory",
    )
    if set(inventory) != {
        "format",
        "relative_root",
        "exclusion_policy",
        "file_count",
        "size_bytes",
        "sha256",
    } or (
        inventory.get("format") != "agent-assure-s1-post-r2-test-runtime-inventory/1"
        or inventory.get("relative_root") != ".venv/Lib/site-packages"
        or inventory.get("exclusion_policy")
        != {
            "directory_names": sorted(POST_R2_TEST_RUNTIME_EXCLUDED_DIRECTORY_NAMES),
            "forbidden_direct_file_suffixes": sorted(POST_R2_TEST_RUNTIME_FORBIDDEN_FILE_SUFFIXES),
            "reason": "cache_directories_inert_under_fresh_pycache_prefix",
        }
        or inventory.get("file_count") != POST_R2_TEST_RUNTIME_FILE_COUNT
        or inventory.get("size_bytes") != POST_R2_TEST_RUNTIME_SIZE_BYTES
        or inventory.get("sha256") != "sha256:" + POST_R2_TEST_RUNTIME_SHA256
    ):
        raise GovernanceError("post-R2 test runtime inventory evidence is invalid")
    expected_base_runtime = {
        "root": str(_FROZEN_PYTHON_ROOT),
        "python_executable": {
            "absolute_path": str(_FROZEN_PYTHON_EXECUTABLE),
            "size_bytes": _FROZEN_PYTHON_EXECUTABLE_SIZE,
            "sha256": "sha256:" + _FROZEN_PYTHON_EXECUTABLE_SHA256,
        },
        "python_dll": {
            "absolute_path": str(_FROZEN_PYTHON_DLL),
            "size_bytes": _FROZEN_PYTHON_DLL_SIZE,
            "sha256": "sha256:" + _FROZEN_PYTHON_DLL_SHA256,
        },
        "inventory": {
            "file_count": _FROZEN_BASE_RUNTIME_FILE_COUNT,
            "size_bytes": _FROZEN_BASE_RUNTIME_SIZE_BYTES,
            "sha256": "sha256:" + _FROZEN_BASE_RUNTIME_SHA256,
        },
    }
    if (
        test_runtime.get("base_runtime") != expected_base_runtime
        or expected_base_runtime["python_executable"] != executable
    ):
        raise GovernanceError("post-R2 base runtime identity changed")

    time_evidence = _as_object(evidence.get("time_evidence"), owner="post-R2 time evidence")
    if set(time_evidence) != {
        "clock_basis",
        "sshsig_timestamp_capability",
        "actual_signature_time_claimed",
        "started_at_utc",
        "completed_at_utc",
    }:
        raise GovernanceError("post-R2 time evidence has unexpected fields")
    for key, expected in ATTESTATION_V2_TIME_EVIDENCE.items():
        if time_evidence.get(key) != expected:
            raise GovernanceError(f"post-R2 time semantics changed {key}")
    started = _parse_utc(
        _required_string(time_evidence, "started_at_utc"), owner="post-R2 suite start"
    )
    completed = _parse_utc(
        _required_string(time_evidence, "completed_at_utc"), owner="post-R2 suite completion"
    )
    if completed < started:
        raise GovernanceError("post-R2 suite completion predates its start")

    empty_digest = raw_digest(b"")
    for state_name in ("repository_precondition", "repository_postcondition"):
        state = _as_object(evidence.get(state_name), owner=f"post-R2 {state_name}")
        if state != {
            "head_commit": expected_result_commit,
            "clean": True,
            "status_command": [
                "git",
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ],
            "status_stdout_size_bytes": 0,
            "status_stdout_sha256": empty_digest,
        }:
            raise GovernanceError(f"post-R2 {state_name} is not clean R2")
    execution = _as_object(evidence.get("execution"), owner="post-R2 suite execution")
    if set(execution) != {"exit_code", "outcome", "pytest_totals", "stdout", "stderr"}:
        raise GovernanceError("post-R2 suite execution has unexpected fields")
    exit_code = _required_integer(execution, "exit_code")
    if execution.get("outcome") != _post_r2_execution_outcome(exit_code):
        raise GovernanceError("post-R2 suite outcome does not match its exit code")
    totals = _as_object(execution.get("pytest_totals"), owner="post-R2 pytest totals")
    total_keys = {"collected", "passed", "failed", "skipped", "xfailed", "xpassed", "errors"}
    if set(totals) != total_keys or any(
        not isinstance(totals.get(key), int) or cast(int, totals[key]) < 0 for key in total_keys
    ):
        raise GovernanceError("post-R2 pytest totals are invalid")
    executed_count = sum(
        cast(int, totals[name]) for name in ("passed", "failed", "skipped", "xfailed", "xpassed")
    )
    if totals.get("collected") != executed_count:
        raise GovernanceError("post-R2 collected count does not equal terminal outcome totals")
    for stream_name in ("stdout", "stderr"):
        stream = _as_object(execution.get(stream_name), owner=f"post-R2 {stream_name}")
        if set(stream) != {"file_name", "size_bytes", "sha256"}:
            raise GovernanceError(f"post-R2 {stream_name} evidence has unexpected fields")
        if stream.get("file_name") != f"pytest.{stream_name}.bin":
            raise GovernanceError(f"post-R2 {stream_name} file name changed")
        if (
            not isinstance(stream.get("size_bytes"), int)
            or cast(int, stream["size_bytes"]) < 0
            or not isinstance(stream.get("sha256"), str)
            or SHA256_PATTERN.fullmatch(cast(str, stream["sha256"])) is None
        ):
            raise GovernanceError(f"post-R2 {stream_name} artifact evidence is invalid")
    if require_passed and (
        exit_code != 0
        or execution.get("outcome") != "passed"
        or totals.get("failed") != 0
        or totals.get("errors") != 0
        or cast(int, totals.get("passed", 0)) <= 0
    ):
        raise GovernanceError("post-R2 full suite did not pass")
    projection = {key: value for key, value in evidence.items() if key != "evidence_digest"}
    digest = domain_digest(POST_R2_SUITE_EVIDENCE_DOMAIN, projection)
    if evidence.get("evidence_digest") != digest:
        raise GovernanceError("post-R2 suite evidence digest mismatch")
    return copy.deepcopy(dict(evidence))


def validate_post_r2_suite_evidence_source(
    evidence_path: Path,
    *,
    expected_result_commit: str,
    expected_repository_root: Path | None = None,
    require_passed: bool = True,
) -> dict[str, Any]:
    evidence_directory = evidence_path.parent
    if not evidence_directory.is_dir() or evidence_directory.is_symlink():
        raise GovernanceError("post-R2 evidence source is not a regular directory")
    observed_names = {entry.name for entry in evidence_directory.iterdir()}
    if observed_names != {
        "post-r2-suite-evidence.json",
        "pytest.stdout.bin",
        "pytest.stderr.bin",
    }:
        raise GovernanceError("post-R2 evidence source is not the exact complete set")
    for name in observed_names:
        source = evidence_directory / name
        if not source.is_file() or source.is_symlink():
            raise GovernanceError("post-R2 evidence source contains a non-regular file")
    record = _read_json(evidence_path)
    validated = _validate_embedded_post_r2_suite_evidence(
        record,
        expected_result_commit=expected_result_commit,
        require_passed=require_passed,
    )
    command = _as_object(validated["command"], owner="post-R2 command")
    if expected_repository_root is not None:
        observed_root = os.path.normcase(
            os.path.normpath(_required_string(command, "working_directory"))
        )
        required_root = os.path.normcase(os.path.normpath(str(expected_repository_root.resolve())))
        if observed_root != required_root:
            raise GovernanceError("post-R2 evidence was captured in another repository")
    executable = _as_object(command.get("python_executable"), owner="post-R2 Python executable")
    executable_path = Path(_required_string(executable, "absolute_path"))
    if not executable_path.is_file() or executable_path.is_symlink():
        raise GovernanceError("post-R2 Python executable source is not a regular file")
    executable_payload = executable_path.read_bytes()
    if len(executable_payload) != executable.get("size_bytes") or raw_digest(
        executable_payload
    ) != executable.get("sha256"):
        raise GovernanceError("post-R2 Python executable source bytes changed")
    runtime_root = (
        expected_repository_root.resolve()
        if expected_repository_root is not None
        else Path(_required_string(command, "working_directory")).resolve()
    )
    embedded_sources = [
        copy.deepcopy(dict(_as_object(value, owner="post-R2 governance source")))
        for value in _as_array(
            validated.get("governance_sources"), owner="post-R2 governance sources"
        )
    ]
    embedded_paths = {_required_string(source, "path") for source in embedded_sources}
    fixed_sources = {
        "docs/governance/v1/corrective-kickoff-authorization.json",
        "docs/governance/v1/corrective-kickoff-authorization.schema.json",
    }
    roadmap_relative = next(iter(embedded_paths - fixed_sources))
    roadmap_path = runtime_root / roadmap_relative
    if embedded_sources != _post_r2_governance_source_evidence(
        runtime_root,
        roadmap_path,
    ):
        raise GovernanceError("post-R2 governance source bytes changed")
    if validated.get("repository_test_surface") != _post_r2_test_surface_evidence(
        runtime_root,
        result_commit=expected_result_commit,
    ):
        raise GovernanceError("post-R2 repository test-surface bytes changed")
    test_runtime = _as_object(command.get("test_runtime"), owner="post-R2 test runtime")
    if test_runtime != _post_r2_test_runtime_evidence(runtime_root):
        raise GovernanceError("post-R2 test runtime source bytes changed")
    for stream_name in ("stdout", "stderr"):
        stream = _as_object(
            _as_object(validated["execution"], owner="post-R2 execution").get(stream_name),
            owner=f"post-R2 {stream_name}",
        )
        stream_path = evidence_path.parent / _required_string(stream, "file_name")
        if not stream_path.is_file() or stream_path.is_symlink():
            raise GovernanceError(f"post-R2 {stream_name} source is not a regular file")
        payload = stream_path.read_bytes()
        if len(payload) != stream.get("size_bytes") or raw_digest(payload) != stream.get("sha256"):
            raise GovernanceError(f"post-R2 {stream_name} source bytes changed")
    execution = _as_object(validated["execution"], owner="post-R2 execution")
    stdout_record = _as_object(execution["stdout"], owner="post-R2 stdout")
    stderr_record = _as_object(execution["stderr"], owner="post-R2 stderr")
    stdout = (evidence_path.parent / _required_string(stdout_record, "file_name")).read_bytes()
    stderr = (evidence_path.parent / _required_string(stderr_record, "file_name")).read_bytes()
    if execution.get("pytest_totals") != _parse_post_r2_pytest_totals(stdout, stderr):
        raise GovernanceError("post-R2 pytest totals do not match captured output bytes")
    return validated


def _completion_review_paths_v2(ticket_id: str) -> list[tuple[str, str]]:
    implementation_and_verification = [
        ("scripts/v1_s1_governance.py", "governance_validator"),
        ("tests/unit/governance/test_v1_s1_governance.py", "verification"),
        ("tests/integration/test_v1_s1_historical_check.py", "integration_verification"),
    ]
    if ticket_id == "V1-BASE-01":
        return [
            ("docs/adr/0016-v1-repository-map.md", "decision_record"),
            ("docs/governance/v1/README.md", "governance_documentation"),
            ("docs/governance/v1/baseline-observations.json", "planning_evidence"),
            ("docs/governance/v1/baseline-observations.schema.json", "planning_schema"),
            (
                "docs/governance/v1/delivery-forecast.estimation-catalog.json",
                "planning_method_catalog",
            ),
            (
                "docs/governance/v1/delivery-forecast.estimation-catalog.schema.json",
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
            *implementation_and_verification,
        ]
    if ticket_id == "V1-BOOT-01":
        return [
            (".github/workflows/ci.yml", "continuous_integration"),
            ("Makefile", "build_integration"),
            ("mkdocs.yml", "documentation_integration"),
            (
                "docs/governance/v1/corrective-kickoff-authorization.json",
                "corrective_authorization",
            ),
            (
                "docs/governance/v1/corrective-kickoff-authorization.schema.json",
                "planning_schema",
            ),
            (
                "docs/governance/v1/current-acceptance-attestation.schema.json",
                "planning_schema",
            ),
            ("docs/governance/v1/governance-bundle.schema.json", "planning_schema"),
            (
                "docs/governance/v1/ticket-completion-receipt.schema.json",
                "planning_schema",
            ),
        ]
    raise GovernanceError(f"{ticket_id} is not an S1 corrective completion ticket")


def _superseded_receipt_binding(repository_root: Path, *, ticket_id: str) -> dict[str, Any]:
    previous = _read_json_from_commit(
        repository_root,
        S1_ACCEPTANCE_V1_CLOSURE_COMMIT,
        f"docs/governance/v1/completion-receipt-{ticket_id.lower()}.json",
    )
    if (
        previous.get("format") != "agent-assure-ticket-completion-receipt/1"
        or previous.get("subject_ticket_id") != ticket_id
    ):
        raise GovernanceError(f"immutable generation-1 {ticket_id} receipt identity changed")
    expected_digest = S1_ACCEPTANCE_V1_RECEIPT_DIGESTS[ticket_id]
    if (
        previous.get("receipt_digest") != expected_digest
        or domain_digest(TICKET_RECEIPT_DOMAIN, _ticket_receipt_projection(previous))
        != expected_digest
    ):
        raise GovernanceError(f"immutable generation-1 {ticket_id} receipt digest changed")
    return {
        "acceptance_generation": 1,
        "receipt_format": "agent-assure-ticket-completion-receipt/1",
        "receipt_digest": expected_digest,
        "closure_commit": S1_ACCEPTANCE_V1_CLOSURE_COMMIT,
        "disposition": "superseded_nonconforming",
        "nonconformance": "generation_1_forecast_and_provenance_findings",
    }


def _load_corrective_authorization_from_result(
    snapshot: RoadmapSnapshot,
    repository_root: Path,
    result_commit: str,
) -> dict[str, Any]:
    authorization = _read_json_from_commit(
        repository_root,
        result_commit,
        "docs/governance/v1/corrective-kickoff-authorization.json",
    )
    schema = _read_json_from_commit(
        repository_root,
        result_commit,
        "docs/governance/v1/corrective-kickoff-authorization.schema.json",
    )
    validate_corrective_kickoff_authorization(
        authorization,
        schema,
        expected_roadmap_digest=snapshot.raw_digest,
    )
    return authorization


def _load_forecast_from_result(repository_root: Path, result_commit: str) -> dict[str, Any]:
    return _read_json_from_commit(
        repository_root,
        result_commit,
        "docs/governance/v1/delivery-forecast.json",
    )


def _load_roster_from_result(repository_root: Path, result_commit: str) -> dict[str, Any]:
    return _read_json_from_commit(
        repository_root,
        result_commit,
        "docs/governance/v1/approval-roster.json",
    )


def _corrective_authorization_binding(
    corrective_authorization: Mapping[str, Any],
) -> dict[str, Any]:
    claim = _as_object(
        corrective_authorization.get("signed_claim"), owner="corrective signed claim"
    )
    return {
        "claim_digest": CORRECTIVE_KICKOFF_CLAIM_DIGEST,
        "authorization_status": _required_string(corrective_authorization, "authorization_status"),
        "authorization_kind": _required_string(claim, "authorization_kind"),
        "authorization_effect": _required_string(claim, "authorization_effect"),
        "authorized_person_id": _required_string(claim, "authorized_person_id"),
        "authorized_role": _required_string(claim, "authorized_role"),
    }


def _rostered_issuer_metadata(
    roster: Mapping[str, Any], *, expected_person_id: str
) -> dict[str, Any]:
    if (
        roster.get("selected_mode") != "maintainer_development"
        or roster.get("maintainer_person_id") != expected_person_id
    ):
        raise GovernanceError("corrective receipt issuer is not the rostered maintainer")
    people = [
        _as_object(item, owner="approval roster person")
        for item in _as_array(roster.get("people"), owner="approval roster people")
    ]
    matches = [item for item in people if item.get("person_id") == expected_person_id]
    if len(matches) != 1:
        raise GovernanceError("corrective receipt issuer has no unique roster identity")
    person = matches[0]
    competence_scopes = _required_string_array(person, "competence_scopes")
    required_scopes = {
        "planning_governance:s1",
        "repository_maintenance:bounded_development",
    }
    if not required_scopes <= set(competence_scopes):
        raise GovernanceError("corrective receipt issuer lacks required S1 competence")
    assignments = {
        _required_string(assignment, "role"): assignment
        for assignment in (
            _as_object(item, owner="approval roster role assignment")
            for item in _as_array(
                roster.get("role_assignments"), owner="approval roster role assignments"
            )
        )
    }
    for role in ("repository_maintainer", "technical_lead"):
        assignment = assignments.get(role)
        if assignment is None or assignment.get("person_id") != expected_person_id:
            raise GovernanceError(f"corrective receipt issuer is not the rostered {role}")
    return {
        "issuer_competence_scopes": competence_scopes,
        "issuer_conflicts": _required_string_array(person, "conflicts"),
        "issuer_mode": "maintainer_development",
    }


def _pending_signature_import_evidence() -> dict[str, Any]:
    return {
        "status": "pending_signature_import",
        "verification_recorded_at_utc": None,
        "clock_basis": "maintainer_host_utc_externally_unattested",
        "sshsig_timestamp_capability": "none",
        "actual_signature_time_claimed": False,
        "verification_result": None,
    }


def record_v2_signature_import_observation(
    record: Mapping[str, Any],
) -> dict[str, Any]:
    """Add an honest post-signature host observation without calling it signing time.

    This field is intentionally outside the SSHSIG subject projection.  The
    closure commit and final annotated tag bind the observation durably, while
    the SSHSIG continues to authenticate only the pre-signature claim.
    """

    result = copy.deepcopy(dict(record))
    if result.get("signature_import_evidence") != _pending_signature_import_evidence():
        raise GovernanceError("v2 signature import observation is not pending")
    record_format = result.get("format")
    if record_format == "agent-assure-ticket-completion-receipt/2":
        owner = "corrective completion"
        subject_digest = _required_string(result, "receipt_digest")
    elif record_format == "agent-assure-governance-bundle/2":
        owner = "corrective governance bundle"
        subject_digest = _required_string(result, "bundle_digest")
    else:
        raise GovernanceError("signature import observation requires a v2 closure record")
    signature_verified = _validate_signature_envelope_v2(
        result.get("signature_envelope"),
        expected_person_id=_required_string(result, "issuer_person_id"),
        expected_role=_required_string(result, "issuer_role"),
        expected_subject_digest=subject_digest,
        allow_pending=False,
        owner=owner,
    )
    if not signature_verified:  # pragma: no cover - allow_pending=False is fail closed.
        raise GovernanceError("cannot observe an unverified v2 SSHSIG import")
    prepared = _parse_utc(
        _required_string(result, "claim_prepared_at_utc"), owner="claim preparation"
    )
    verification_recorded_at = _canonical_host_utc_now()
    observed = _parse_utc(verification_recorded_at, owner="signature verification observation")
    if observed < prepared:
        raise GovernanceError("signature verification observation predates claim preparation")
    result["signature_import_evidence"] = {
        "status": "verified_after_import",
        "verification_recorded_at_utc": verification_recorded_at,
        "clock_basis": "maintainer_host_utc_externally_unattested",
        "sshsig_timestamp_capability": "none",
        "actual_signature_time_claimed": False,
        "verification_result": "valid_exact_payload_key_and_namespace",
    }
    return result


def _validate_v2_signature_import_evidence(
    record: Mapping[str, Any], *, signature_verified: bool, owner: str
) -> None:
    evidence = _as_object(
        record.get("signature_import_evidence"), owner=f"{owner} signature import evidence"
    )
    expected_common = {
        "clock_basis": "maintainer_host_utc_externally_unattested",
        "sshsig_timestamp_capability": "none",
        "actual_signature_time_claimed": False,
    }
    for key, expected in expected_common.items():
        if evidence.get(key) != expected:
            raise GovernanceError(f"{owner} signature import evidence changed {key}")
    if not signature_verified:
        if evidence != _pending_signature_import_evidence():
            raise GovernanceError(f"pending {owner} has nonpending signature import evidence")
        return
    if (
        evidence.get("status") != "verified_after_import"
        or evidence.get("verification_result") != "valid_exact_payload_key_and_namespace"
    ):
        raise GovernanceError(f"signed {owner} lacks verified signature import evidence")
    observed = evidence.get("verification_recorded_at_utc")
    if not isinstance(observed, str):
        raise GovernanceError(f"signed {owner} lacks a verification observation time")
    if _parse_utc(observed, owner=f"{owner} verification observation") < _parse_utc(
        _required_string(record, "claim_prepared_at_utc"), owner=f"{owner} claim preparation"
    ):
        raise GovernanceError(f"{owner} verification observation predates claim preparation")


def _ticket_completion_receipt_v2_projection(
    snapshot: RoadmapSnapshot,
    *,
    repository_root: Path,
    ticket_id: str,
    roster: Mapping[str, Any],
    person_id: str,
    result_commit: str,
    corrective_authorization: Mapping[str, Any],
    forecast: Mapping[str, Any],
    claim_prepared_at: str,
    status: str,
    post_result_verification: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if ticket_id not in S1_ACCEPTANCE_V1_RECEIPT_DIGESTS:
        raise GovernanceError(f"{ticket_id} is not an S1 corrective completion ticket")
    if status not in {"pending_human_acceptance", "accepted_for_development"}:
        raise GovernanceError(f"{ticket_id} corrective completion status is invalid")
    if status == "accepted_for_development" and roster.get("selection_status") != "approved":
        raise GovernanceError(
            f"{ticket_id} accepted corrective completion requires the approved roster"
        )
    roster_digest = approval_roster_digest(roster)
    issuer_metadata = _rostered_issuer_metadata(roster, expected_person_id=person_id)
    _parse_utc(claim_prepared_at, owner=f"{ticket_id} claim_prepared_at_utc")
    ticket = _ticket_by_id(snapshot, ticket_id)
    reviewer_role = _required_string(ticket, "reviewer_role")
    if reviewer_role != "repository_maintainer":
        raise GovernanceError(
            f"{ticket_id} corrective completion issuer does not match its declared reviewer role"
        )
    change_control = _corrective_change_control(
        repository_root,
        result_commit=result_commit,
        corrective_authorization=corrective_authorization,
    )
    report_path = f"docs/governance/v1/completion-report-{ticket_id.lower()}.md"
    report = _artifact_evidence_from_commit(
        repository_root,
        result_commit,
        report_path,
        kind="completion_report",
    )
    reviewed = [
        _artifact_evidence_from_commit(
            repository_root,
            result_commit,
            path,
            kind=kind,
        )
        for path, kind in _completion_review_paths_v2(ticket_id)
    ]
    reviewed.sort(key=lambda item: _utf8_sort_key(cast(str, item["path"])))
    reviewed_set = [report, *reviewed]
    reviewed_set.sort(key=lambda item: _utf8_sort_key(cast(str, item["path"])))
    if ticket_id == "V1-BASE-01":
        if post_result_verification is not None:
            raise GovernanceError("BASE corrective receipt must not duplicate BOOT suite evidence")
        suite_evidence: dict[str, Any] | None = None
    else:
        if post_result_verification is None:
            raise GovernanceError("BOOT corrective receipt requires post-R2 suite evidence")
        suite_evidence = _validate_embedded_post_r2_suite_evidence(
            post_result_verification,
            expected_result_commit=result_commit,
            require_passed=True,
        )
    reviewed_artifact_set_digest = domain_digest(
        CORRECTIVE_REVIEWED_ARTIFACT_SET_DOMAIN, {"artifacts": reviewed_set}
    )
    review_evidence = {
        "review_method": "accountable_human_maintainer_self_acceptance",
        "llm_implementation_handoff_disclosed": True,
        "subject_report_sha256": _required_string(report, "sha256"),
        "reviewed_artifact_set_digest": reviewed_artifact_set_digest,
        "result_artifact_set_digest": _required_string(
            change_control, "result_artifact_set_digest"
        ),
        "post_r2_suite_evidence_digest": (
            None if suite_evidence is None else _required_string(suite_evidence, "evidence_digest")
        ),
    }
    return {
        "format": "agent-assure-ticket-completion-receipt/2",
        "spec_revision": SPEC_REVISION,
        "acceptance_generation": 2,
        "receipt_purpose": "development_design_acceptance",
        "receipt_status": status,
        "replacement_for": _superseded_receipt_binding(repository_root, ticket_id=ticket_id),
        "corrective_authorization_claim_digest": CORRECTIVE_KICKOFF_CLAIM_DIGEST,
        "corrective_authorization": _corrective_authorization_binding(corrective_authorization),
        "subject_ticket_id": ticket_id,
        "subject_dispatch_kind": _required_string(ticket, "dispatch_kind"),
        "subject_stage": "S1-governed-baseline-corrective-generation-2",
        "subject_roadmap_digest": snapshot.raw_digest,
        "subject_report": report,
        "reviewed_artifacts": reviewed,
        "reviewed_artifact_set_digest": reviewed_artifact_set_digest,
        "review_evidence": review_evidence,
        "approval_roster_digest": roster_digest,
        "forecast_evidence": _forecast_binding_v2(forecast, require_accepted=True),
        "change_control": change_control,
        "post_result_verification": suite_evidence,
        "issuer_person_id": person_id,
        "issuer_role": "repository_maintainer",
        "owner_role": _required_string(ticket, "owner_role"),
        "reviewer_role": reviewer_role,
        **issuer_metadata,
        "approval_mode": "maintainer_development",
        "author_reviewer_relationship": ("same_person_maintainer_development_self_acceptance"),
        "independence_claimed": False,
        "independence_basis": (
            "same_person_maintainer_development_self_acceptance_with_recorded_conflicts"
        ),
        "authorization_effect": "none",
        "time_evidence": dict(ATTESTATION_V2_TIME_EVIDENCE),
        "claim_prepared_at_utc": claim_prepared_at,
        "validity_context": {
            "kind": "bounded_by_generation_2_governance_bundle",
            "standalone_currentness_claimed": False,
            "current_acceptance_requires_current_bundle": True,
        },
        "allowed_operations": _completion_allowed_operations(ticket_id),
        "exclusions": [
            "independent_review",
            "method_admission",
            "qualification",
            "pilot_authorization",
            "release_authorization",
            "deployment_authorization",
            "runtime_authorization",
        ],
        "limitations": [
            "NO_INDEPENDENT_REVIEW",
            "SSHSIG contains no signing timestamp; no actual signing time is claimed.",
            (
                "No method admission, qualification, pilot, release, deployment, or runtime "
                "authorization is granted."
            ),
        ],
    }


def build_ticket_completion_receipt_v2(
    snapshot: RoadmapSnapshot,
    *,
    repository_root: Path,
    ticket_id: str,
    roster_digest: str,
    person_id: str,
    result_commit: str,
    post_r2_suite_evidence_path: Path | None = None,
    status: str = "pending_human_acceptance",
) -> dict[str, Any]:
    corrective_authorization = _load_corrective_authorization_from_result(
        snapshot, repository_root, result_commit
    )
    forecast = _load_forecast_from_result(repository_root, result_commit)
    roster = _load_roster_from_result(repository_root, result_commit)
    if approval_roster_digest(roster) != roster_digest:
        raise GovernanceError("corrective completion targets another approval roster")
    post_evidence: Mapping[str, Any] | None = None
    if ticket_id == "V1-BOOT-01":
        if post_r2_suite_evidence_path is None:
            raise GovernanceError("BOOT corrective receipt requires local post-R2 suite evidence")
        source = _corrective_private_acceptance_path(
            repository_root,
            post_r2_suite_evidence_path,
            owner="post-R2 suite evidence source",
            must_exist=True,
        )
        post_evidence = validate_post_r2_suite_evidence_source(
            source,
            expected_result_commit=result_commit,
            expected_repository_root=repository_root,
            require_passed=True,
        )
    elif post_r2_suite_evidence_path is not None:
        raise GovernanceError("post-R2 suite evidence belongs only to the BOOT receipt")
    claim_prepared_at = _canonical_host_utc_now()
    projection = _ticket_completion_receipt_v2_projection(
        snapshot,
        repository_root=repository_root,
        ticket_id=ticket_id,
        roster=roster,
        person_id=person_id,
        result_commit=result_commit,
        corrective_authorization=corrective_authorization,
        forecast=forecast,
        claim_prepared_at=claim_prepared_at,
        status=status,
        post_result_verification=post_evidence,
    )
    digest = domain_digest(TICKET_RECEIPT_V2_DOMAIN, projection)
    return {
        **projection,
        "receipt_digest": digest,
        "signature_envelope": _pending_signature_v2(person_id, "repository_maintainer", digest),
        "signature_import_evidence": _pending_signature_import_evidence(),
    }


def validate_ticket_completion_receipt_v2(
    snapshot: RoadmapSnapshot,
    record: Mapping[str, Any],
    schema: Mapping[str, Any],
    *,
    repository_root: Path,
    expected_ticket_id: str,
    expected_roster_digest: str,
    expected_corrective_authorization_digest: str,
    expected_person_id: str,
    expected_result_parent: str,
    allow_pending: bool,
) -> None:
    _validate_json_schema(record, schema, owner=f"{expected_ticket_id} corrective receipt")
    if expected_result_parent != S1_ACCEPTANCE_V1_CLOSURE_COMMIT:
        raise GovernanceError("corrective receipt expected parent is not immutable C1")
    if expected_corrective_authorization_digest != CORRECTIVE_KICKOFF_CLAIM_DIGEST:
        raise GovernanceError("corrective receipt authorization digest is not the signed kickoff")
    result_commit = _required_string(
        _as_object(record.get("change_control"), owner="corrective change control"),
        "result_commit",
    )
    authorization = _load_corrective_authorization_from_result(
        snapshot, repository_root, result_commit
    )
    forecast = _load_forecast_from_result(repository_root, result_commit)
    roster = _load_roster_from_result(repository_root, result_commit)
    if approval_roster_digest(roster) != expected_roster_digest:
        raise GovernanceError("corrective receipt approval roster digest changed")
    post_evidence_value = record.get("post_result_verification")
    post_evidence = (
        None
        if post_evidence_value is None
        else _as_object(post_evidence_value, owner="post-R2 suite evidence")
    )
    expected = _ticket_completion_receipt_v2_projection(
        snapshot,
        repository_root=repository_root,
        ticket_id=expected_ticket_id,
        roster=roster,
        person_id=expected_person_id,
        result_commit=result_commit,
        corrective_authorization=authorization,
        forecast=forecast,
        claim_prepared_at=_required_string(record, "claim_prepared_at_utc"),
        status=_required_string(record, "receipt_status"),
        post_result_verification=post_evidence,
    )
    if _ticket_receipt_projection(record) != expected:
        raise GovernanceError(f"{expected_ticket_id} corrective receipt differs from R2 artifacts")
    digest = domain_digest(TICKET_RECEIPT_V2_DOMAIN, expected)
    if record.get("receipt_digest") != digest:
        raise GovernanceError(f"{expected_ticket_id} corrective receipt digest mismatch")
    status = _required_string(record, "receipt_status")
    signature_may_be_pending = allow_pending and status != "accepted_for_development"
    signature_verified = _validate_signature_envelope_v2(
        record.get("signature_envelope"),
        expected_person_id=expected_person_id,
        expected_role="repository_maintainer",
        expected_subject_digest=digest,
        allow_pending=signature_may_be_pending,
        owner=f"{expected_ticket_id} corrective completion",
    )
    _validate_v2_signature_import_evidence(
        record,
        signature_verified=signature_verified,
        owner=f"{expected_ticket_id} corrective completion",
    )
    if not allow_pending and status != "accepted_for_development":
        raise GovernanceError(f"{expected_ticket_id} corrective receipt is pending")


def _generation_1_supersession_binding(
    snapshot: RoadmapSnapshot,
    repository_root: Path,
) -> dict[str, Any]:
    for child, parent, owner in (
        (S1_ACCEPTANCE_V1_RESULT_COMMIT, PINNED_BASE_COMMIT, "generation-1 result"),
        (
            S1_ACCEPTANCE_V1_CLOSURE_COMMIT,
            S1_ACCEPTANCE_V1_RESULT_COMMIT,
            "generation-1 closure",
        ),
    ):
        history = _run_git(
            repository_root,
            ["rev-list", "--parents", "-n", "1", child],
        )
        fields = history.stdout.decode("ascii", errors="strict").split()
        if history.returncode != 0 or fields != [child, parent]:
            raise GovernanceError(f"immutable {owner} topology changed")
    forecast = _read_json_from_commit(
        repository_root,
        S1_ACCEPTANCE_V1_CLOSURE_COMMIT,
        "docs/governance/v1/delivery-forecast.json",
    )
    if (
        forecast.get("record_digest") != S1_ACCEPTANCE_V1_FORECAST_DIGEST
        or domain_digest(FORECAST_DOMAIN, _forecast_projection(forecast))
        != S1_ACCEPTANCE_V1_FORECAST_DIGEST
    ):
        raise GovernanceError("immutable generation-1 forecast digest changed")
    bundle = _read_json_from_commit(
        repository_root,
        S1_ACCEPTANCE_V1_CLOSURE_COMMIT,
        "docs/governance/v1/governance-bundle.json",
    )
    if (
        bundle.get("bundle_digest") != S1_ACCEPTANCE_V1_BUNDLE_DIGEST
        or domain_digest(BUNDLE_DOMAIN, _bundle_projection(bundle))
        != S1_ACCEPTANCE_V1_BUNDLE_DIGEST
    ):
        raise GovernanceError("immutable generation-1 bundle digest changed")
    _validate_generation_1_predecessor_acceptance(
        repository_root,
        expected_roadmap_digest=snapshot.raw_digest,
    )
    return {
        "acceptance_generation": 1,
        "disposition": "superseded_nonconforming",
        "noncurrent_reason": "forecast_and_governance_provenance_nonconformance",
        "tag_name": S1_ACCEPTANCE_TAG_NAME,
        "tag_object": S1_ACCEPTANCE_V1_TAG_OBJECT,
        "baseline_commit": PINNED_BASE_COMMIT,
        "result_commit": S1_ACCEPTANCE_V1_RESULT_COMMIT,
        "closure_commit": S1_ACCEPTANCE_V1_CLOSURE_COMMIT,
        "bundle_digest": S1_ACCEPTANCE_V1_BUNDLE_DIGEST,
        "forecast_digest": S1_ACCEPTANCE_V1_FORECAST_DIGEST,
        "objects_remain_immutable": True,
    }


def _corrective_completion_bindings(
    completion_receipts: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    if set(completion_receipts) != {"V1-BASE-01", "V1-BOOT-01"}:
        raise GovernanceError("corrective bundle requires exactly BASE and BOOT replacements")
    return [
        {
            "ticket_id": ticket_id,
            "receipt_format": _required_string(record, "format"),
            "receipt_status": _required_string(record, "receipt_status"),
            "receipt_digest": _required_string(record, "receipt_digest"),
            "superseded_receipt_digest": _required_string(
                _as_object(record.get("replacement_for"), owner="replacement binding"),
                "receipt_digest",
            ),
        }
        for ticket_id, record in sorted(completion_receipts.items(), key=lambda item: item[0])
    ]


def _validate_corrective_review_partition(
    completion_receipts: Mapping[str, Mapping[str, Any]],
    *,
    result_artifact_inventory: Sequence[Mapping[str, Any]],
) -> None:
    """Require every R2 change to be reviewed by exactly one replacement receipt."""

    if set(completion_receipts) != {"V1-BASE-01", "V1-BOOT-01"}:
        raise GovernanceError("corrective review partition requires both replacement receipts")
    reviewed_paths: list[str] = []
    for ticket_id, receipt in sorted(completion_receipts.items()):
        report = _as_object(receipt.get("subject_report"), owner=f"{ticket_id} subject report")
        reviewed_paths.append(_required_string(report, "path"))
        reviewed_paths.extend(
            _required_string(
                _as_object(value, owner=f"{ticket_id} reviewed artifact"),
                "path",
            )
            for value in _as_array(
                receipt.get("reviewed_artifacts"),
                owner=f"{ticket_id} reviewed artifacts",
            )
        )
    duplicates = sorted(
        {path for path in reviewed_paths if reviewed_paths.count(path) > 1},
        key=_utf8_sort_key,
    )
    if duplicates:
        raise GovernanceError(
            f"corrective replacement receipts review an R2 path more than once: {duplicates}"
        )
    result_paths = [
        _required_string(
            _as_object(value, owner="corrective result artifact"),
            "path",
        )
        for value in result_artifact_inventory
    ]
    if len(result_paths) != len(set(result_paths)):
        raise GovernanceError("corrective result artifact inventory repeats a path")
    missing = sorted(set(result_paths) - set(reviewed_paths), key=_utf8_sort_key)
    extraneous = sorted(set(reviewed_paths) - set(result_paths), key=_utf8_sort_key)
    if missing or extraneous:
        raise GovernanceError(
            "corrective replacement receipt review partition differs from R2 changes: "
            f"missing={missing}, extraneous={extraneous}"
        )


def _corrective_receipt_artifact_inventory(
    completion_receipts: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    inventory: list[dict[str, Any]] = []
    for ticket_id, record in sorted(completion_receipts.items(), key=lambda item: item[0]):
        path = f"docs/governance/v1/completion-receipt-{ticket_id.lower()}.json"
        payload = _render_json_bytes(record)
        inventory.append(
            {
                "path": path,
                "kind": "completion_receipt",
                "size_bytes": len(payload),
                "sha256": raw_digest(payload),
            }
        )
    return inventory


def _governance_bundle_v2_projection(
    snapshot: RoadmapSnapshot,
    *,
    repository_root: Path,
    roster: Mapping[str, Any],
    completion_receipts: Mapping[str, Mapping[str, Any]],
    forecast: Mapping[str, Any],
    baseline_observations: Mapping[str, Any],
    corrective_authorization: Mapping[str, Any],
    person_id: str,
    result_commit: str,
    issued_at: str,
    valid_until: str,
    claim_prepared_at: str,
    status: str,
) -> dict[str, Any]:
    if status not in {"pending_human_acceptance", "accepted_for_development"}:
        raise GovernanceError("corrective governance bundle status is invalid")
    issue_time, expiry_time = _validate_validity_interval(
        issued_at, valid_until, owner="corrective governance bundle"
    )
    preparation_time = _parse_utc(
        claim_prepared_at, owner="corrective bundle claim_prepared_at_utc"
    )
    if not issue_time <= preparation_time < expiry_time:
        raise GovernanceError(
            "corrective bundle claim preparation is outside its validity interval"
        )
    roster_digest = approval_roster_digest(roster)
    forecast_evidence = _forecast_binding_v2(forecast, require_accepted=True)
    change_control = _corrective_change_control(
        repository_root,
        result_commit=result_commit,
        corrective_authorization=corrective_authorization,
    )
    _validate_corrective_review_partition(
        completion_receipts,
        result_artifact_inventory=_as_array(
            change_control.get("result_artifact_inventory"),
            owner="corrective result artifact inventory",
        ),
    )
    receipt_import_times: list[datetime] = []
    for ticket_id, receipt in completion_receipts.items():
        if (
            receipt.get("receipt_status") != "accepted_for_development"
            or _as_object(
                receipt.get("signature_envelope"),
                owner=f"{ticket_id} corrective receipt signature",
            ).get("status")
            != "signed"
        ):
            raise GovernanceError(
                f"corrective bundle requires accepted signed {ticket_id} replacement"
            )
        receipt_prepared = _parse_utc(
            _required_string(receipt, "claim_prepared_at_utc"),
            owner=f"{ticket_id} corrective receipt claim preparation",
        )
        import_evidence = _as_object(
            receipt.get("signature_import_evidence"),
            owner=f"{ticket_id} corrective receipt signature import",
        )
        receipt_imported = _parse_utc(
            _required_string(import_evidence, "verification_recorded_at_utc"),
            owner=f"{ticket_id} corrective receipt signature verification",
        )
        if (
            import_evidence.get("status") != "verified_after_import"
            or not issue_time <= receipt_prepared <= receipt_imported < expiry_time
        ):
            raise GovernanceError(
                f"{ticket_id} corrective receipt is outside bundle validity or unverified"
            )
        receipt_import_times.append(receipt_imported)
    if receipt_import_times and preparation_time < max(receipt_import_times):
        raise GovernanceError(
            "corrective bundle claim preparation predates replacement signature verification"
        )
    completion_bindings = _corrective_completion_bindings(completion_receipts)
    receipt_inventory = _corrective_receipt_artifact_inventory(completion_receipts)
    boot_evidence = _as_object(
        completion_receipts["V1-BOOT-01"].get("post_result_verification"),
        owner="BOOT post-R2 suite evidence",
    )
    validated_suite = _validate_embedded_post_r2_suite_evidence(
        boot_evidence,
        expected_result_commit=result_commit,
        require_passed=True,
    )
    if completion_receipts["V1-BASE-01"].get("post_result_verification") is not None:
        raise GovernanceError("BASE receipt must not carry BOOT suite evidence")
    return {
        "format": "agent-assure-governance-bundle/2",
        "spec_revision": SPEC_REVISION,
        "acceptance_generation": 2,
        "bundle_status": status,
        "sprint": "S1",
        "release": "1.0.0a1",
        "train": "stable-1.0",
        "maturity": "governed-baseline-corrective-generation-2",
        "artifact_kind": "governance-bundle",
        "source_ticket_ids": ["V1-BOOT-01", "V1-BASE-01"],
        "authorization_effect": "none",
        "installability": "none",
        "distribution_channels": [],
        "package_version": None,
        "result_commit": result_commit,
        "predecessor_acceptance": _generation_1_supersession_binding(
            snapshot,
            repository_root,
        ),
        "corrective_authorization_claim_digest": CORRECTIVE_KICKOFF_CLAIM_DIGEST,
        "corrective_authorization": _corrective_authorization_binding(corrective_authorization),
        "roadmap_digest": snapshot.raw_digest,
        "approval_roster_digest": roster_digest,
        "signed_decisions": {
            "roster_selection_status": _required_string(roster, "selection_status"),
            "ticket_completion_receipts": completion_bindings,
        },
        "planning_evidence": {
            "baseline_observations_digest": _required_string(
                baseline_observations, "observations_digest"
            ),
            **forecast_evidence,
        },
        "change_control": change_control,
        "post_result_verification": validated_suite,
        "artifact_inventory": receipt_inventory,
        "artifact_set_digest": domain_digest(
            CORRECTIVE_CLOSURE_ARTIFACT_SET_DOMAIN, {"artifacts": receipt_inventory}
        ),
        "expected_closure": {
            "result_parent_commit": S1_ACCEPTANCE_V1_CLOSURE_COMMIT,
            "result_commit": result_commit,
            "closure_parent_commit": result_commit,
            "closure_changed_paths": sorted(S1_CORRECTIVE_CLOSURE_PATHS, key=_utf8_sort_key),
            "closure_change_statuses": ["A", "M"],
            "successor_acceptance_generation": 2,
            "successor_tag_name": S1_ACCEPTANCE_V2_TAG_NAME,
        },
        "compatibility_note": {
            "baseline_package_version": "0.7.0",
            "baseline_writer_schema_version": "0.6.6",
            "production_behavior_changed": False,
            "installable_artifact_emitted": False,
            "note": (
                "Generation 2 replaces only S1 planning-governance acceptance; package and "
                "writer identities remain unchanged."
            ),
        },
        "known_limitations": [
            "NO_INDEPENDENT_REVIEW",
            "SSHSIG contains no signing timestamp; no actual signing time is claimed.",
            (
                "No method, profile, qualification, release, deployment, or runtime "
                "authorization is granted."
            ),
        ],
        "issuer_person_id": person_id,
        "issuer_role": "repository_maintainer",
        "approval_mode": "maintainer_development",
        "independence_claimed": False,
        "time_evidence": dict(ATTESTATION_V2_TIME_EVIDENCE),
        "issued_at_utc": issued_at,
        "valid_until_utc": valid_until,
        "claim_prepared_at_utc": claim_prepared_at,
    }


def build_governance_bundle_v2(
    snapshot: RoadmapSnapshot,
    *,
    repository_root: Path,
    roster: Mapping[str, Any],
    completion_receipts: Mapping[str, Mapping[str, Any]],
    forecast: Mapping[str, Any],
    baseline_observations: Mapping[str, Any],
    person_id: str,
    result_commit: str,
    issued_at: str,
    valid_until: str,
    status: str = "pending_human_acceptance",
) -> dict[str, Any]:
    authorization = _load_corrective_authorization_from_result(
        snapshot, repository_root, result_commit
    )
    claim_prepared_at = _canonical_host_utc_now()
    projection = _governance_bundle_v2_projection(
        snapshot,
        repository_root=repository_root,
        roster=roster,
        completion_receipts=completion_receipts,
        forecast=forecast,
        baseline_observations=baseline_observations,
        corrective_authorization=authorization,
        person_id=person_id,
        result_commit=result_commit,
        issued_at=issued_at,
        valid_until=valid_until,
        claim_prepared_at=claim_prepared_at,
        status=status,
    )
    digest = domain_digest(BUNDLE_V2_DOMAIN, projection)
    return {
        **projection,
        "bundle_digest": digest,
        "signature_envelope": _pending_signature_v2(person_id, "repository_maintainer", digest),
        "signature_import_evidence": _pending_signature_import_evidence(),
    }


def validate_governance_bundle_v2(
    snapshot: RoadmapSnapshot,
    bundle: Mapping[str, Any],
    schema: Mapping[str, Any],
    *,
    repository_root: Path,
    roster: Mapping[str, Any],
    completion_receipts: Mapping[str, Mapping[str, Any]],
    forecast: Mapping[str, Any],
    baseline_observations: Mapping[str, Any],
    expected_person_id: str,
    expected_result_parent: str,
    allow_pending: bool,
    validation_time: datetime | None,
    require_current_closure: bool,
    require_closure: bool,
    expected_closure_commit: str | None,
) -> None:
    _validate_json_schema(bundle, schema, owner="S1 corrective governance bundle")
    if expected_result_parent != S1_ACCEPTANCE_V1_CLOSURE_COMMIT:
        raise GovernanceError("corrective bundle expected parent is not immutable C1")
    change_control = _as_object(bundle.get("change_control"), owner="corrective change control")
    result_commit = _required_string(change_control, "result_commit")
    authorization = _load_corrective_authorization_from_result(
        snapshot, repository_root, result_commit
    )
    receipt_schema = _read_json_from_commit(
        repository_root,
        result_commit,
        "docs/governance/v1/ticket-completion-receipt.schema.json",
    )
    roster_digest = approval_roster_digest(roster)
    for ticket_id in ("V1-BASE-01", "V1-BOOT-01"):
        if ticket_id not in completion_receipts:
            raise GovernanceError(f"corrective bundle is missing {ticket_id} replacement")
        validate_ticket_completion_receipt_v2(
            snapshot,
            completion_receipts[ticket_id],
            receipt_schema,
            repository_root=repository_root,
            expected_ticket_id=ticket_id,
            expected_roster_digest=roster_digest,
            expected_corrective_authorization_digest=CORRECTIVE_KICKOFF_CLAIM_DIGEST,
            expected_person_id=expected_person_id,
            expected_result_parent=expected_result_parent,
            allow_pending=allow_pending,
        )
    expected = _governance_bundle_v2_projection(
        snapshot,
        repository_root=repository_root,
        roster=roster,
        completion_receipts=completion_receipts,
        forecast=forecast,
        baseline_observations=baseline_observations,
        corrective_authorization=authorization,
        person_id=expected_person_id,
        result_commit=result_commit,
        issued_at=_required_string(bundle, "issued_at_utc"),
        valid_until=_required_string(bundle, "valid_until_utc"),
        claim_prepared_at=_required_string(bundle, "claim_prepared_at_utc"),
        status=_required_string(bundle, "bundle_status"),
    )
    if _bundle_projection(bundle) != expected:
        raise GovernanceError("S1 corrective governance bundle differs from exact evidence")
    digest = domain_digest(BUNDLE_V2_DOMAIN, expected)
    if bundle.get("bundle_digest") != digest:
        raise GovernanceError("S1 corrective governance bundle digest mismatch")
    status = _required_string(bundle, "bundle_status")
    signature_may_be_pending = allow_pending and status != "accepted_for_development"
    signature_verified = _validate_signature_envelope_v2(
        bundle.get("signature_envelope"),
        expected_person_id=expected_person_id,
        expected_role="repository_maintainer",
        expected_subject_digest=digest,
        allow_pending=signature_may_be_pending,
        owner="S1 corrective governance bundle",
    )
    _validate_v2_signature_import_evidence(
        bundle,
        signature_verified=signature_verified,
        owner="S1 corrective governance bundle",
    )
    if status == "accepted_for_development":
        if validation_time is None:
            raise GovernanceError("accepted corrective bundle requires a validation time")
        if validation_time.tzinfo is None:
            raise GovernanceError("corrective bundle validation time must be timezone-aware")
        issue_time, expiry_time = _validate_validity_interval(
            _required_string(bundle, "issued_at_utc"),
            _required_string(bundle, "valid_until_utc"),
            owner="corrective governance bundle",
        )
        if not issue_time <= validation_time.astimezone(UTC) < expiry_time:
            raise GovernanceError("accepted corrective bundle is not current")
        if roster.get("selection_status") != "approved":
            raise GovernanceError("accepted corrective bundle requires the approved roster")
        if any(
            receipt.get("receipt_status") != "accepted_for_development"
            for receipt in completion_receipts.values()
        ):
            raise GovernanceError("accepted corrective bundle requires both signed replacements")
        if require_closure:
            _validate_s1_closure_checkout(
                repository_root,
                result_commit=result_commit,
                bundle=bundle,
                require_current_checkout=require_current_closure,
                expected_closure_commit=expected_closure_commit,
            )
        elif require_current_closure:
            raise GovernanceError("current corrective closure validation cannot be disabled")
    if not allow_pending and status != "accepted_for_development":
        raise GovernanceError("S1 corrective governance bundle is pending")


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
            prefix=f"{path.name}.",
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


def _publish_new_file_atomically(
    path: Path,
    payload: bytes,
    *,
    staging_directory: Path,
) -> None:
    """Durably publish one new file without exposing a partial target.

    The fully flushed staging file lives outside the exact-content plan
    directory but on the same filesystem.  Linking it into place is atomic and
    fails rather than replacing an existing target.  A process crash can leave
    an orphan staging file, but it cannot leave a partial target or make the
    immutable plan directory fail its exact-name check on retry.
    """

    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=f".{path.parent.name}.{path.name}.",
            suffix=".publish.tmp",
            dir=staging_directory,
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path)
        _fsync_directory(path.parent)
        temporary.unlink()
        temporary = None
        _fsync_directory(staging_directory)
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


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
        lock_directory / "correction-v2-import.lock",
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
    return repository_root / ".tmp/s1-acceptance/correction-v2-import-transaction.json"


def _require_frozen_runtime(
    function: Callable[[argparse.Namespace], int],
) -> Callable[[argparse.Namespace], int]:
    """Reject every command handler unless the frozen launcher bootstrapped it.

    ``__wrapped__`` is deliberately retained as the narrow unit/integration-test
    seam.  Production dispatch and ordinary imported calls always enter this
    outer wrapper first.
    """

    @wraps(function)
    def guarded(args: argparse.Namespace) -> int:
        if not _main_has_active_runtime_bootstrap():
            raise GovernanceError("commands require successful frozen runtime bootstrap")
        return function(args)

    guarded.__dict__["__requires_frozen_runtime__"] = True
    return guarded


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
    staging_root = _resolve_repository_path_without_links(
        root,
        ".tmp/s1-acceptance/correction-v2-install-staging",
        owner="acceptance transaction staging root",
    )
    return staging_root / f"{token}-{target.name}.tmp"


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
    staging_root = (repository_root / ".tmp/s1-acceptance/correction-v2-install-staging").resolve()
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
        except ValueError as exc:
            raise GovernanceError(
                "acceptance transaction target leaves governance directory"
            ) from exc
        try:
            stage.relative_to(staging_root)
        except ValueError as exc:
            raise GovernanceError(
                "acceptance transaction stage leaves signed corrective staging"
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
                stage.unlink(missing_ok=True)
                stage.parent.mkdir(parents=True, exist_ok=True)
                with stage.open("xb") as handle:
                    handle.write(prior)
                    handle.flush()
                    os.fsync(handle.fileno())
                stage.replace(target)
                _fsync_directory(target.parent)
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
            stage.parent.mkdir(parents=True, exist_ok=True)
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


def _corrective_private_acceptance_path(
    repository_root: Path,
    value: str | Path,
    *,
    owner: str,
    must_exist: bool | None = None,
) -> Path:
    """Resolve a generation-2 artifact under an exact signed local-only prefix."""

    root = repository_root.resolve()
    resolved = _private_acceptance_path(
        root,
        value,
        owner=owner,
        must_exist=must_exist,
    )
    relative = resolved.relative_to(root).as_posix()
    _require_corrective_local_only_path(relative, owner=owner)
    return resolved


def _validate_corrective_local_only_path_prefixes(
    signed_claim: Mapping[str, Any],
) -> tuple[str, ...]:
    """Require the exact ordered local-only prefixes in the signed kickoff claim."""

    observed = tuple(_required_string_array(signed_claim, "local_only_path_prefixes"))
    if observed != CORRECTIVE_LOCAL_ONLY_PATH_PREFIXES:
        raise GovernanceError("corrective kickoff local-only path prefixes changed")
    return observed


def _require_corrective_local_only_path(relative: str, *, owner: str) -> None:
    """Reject any generation-2 local artifact outside its signed prefix set."""

    if (
        Path(relative).as_posix() != relative
        or relative.startswith("/")
        or "\\" in relative
        or ".." in Path(relative).parts
        or not any(relative.startswith(prefix) for prefix in CORRECTIVE_LOCAL_ONLY_PATH_PREFIXES)
    ):
        allowed = ", ".join(CORRECTIVE_LOCAL_ONLY_PATH_PREFIXES)
        raise GovernanceError(
            f"{owner} is outside the signed corrective local-only prefixes: {allowed}"
        )


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
    temporary = Path(tempfile.mkdtemp(prefix=f"{plan_directory.name}-staging-", dir=parent))
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


def _verify_plan_sources_after_target_install(
    repository_root: Path,
    plan: Mapping[str, Any],
    *,
    installed_target_paths: set[str],
) -> None:
    """Recheck every immutable plan source while exempting exact installed targets."""

    observed: set[str] = set()
    for value in _as_array(plan.get("source_files"), owner="acceptance plan source files"):
        source = _as_object(value, owner="acceptance plan source file")
        path = _required_string(source, "path")
        if path in observed:
            raise GovernanceError(f"acceptance plan repeats source file: {path}")
        observed.add(path)
        if path in installed_target_paths:
            continue
        actual = _source_file_evidence(repository_root, repository_root / path)
        if actual != source:
            raise GovernanceError(f"acceptance source file changed after plan creation: {path}")
    if not installed_target_paths <= observed:
        missing = ", ".join(sorted(installed_target_paths - observed, key=_utf8_sort_key))
        raise GovernanceError(f"acceptance plan lacks installed target sources: {missing}")


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
    expected_branch_name: str = S1_BRANCH_NAME,
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
        or evidence.get("branch_name") != expected_branch_name
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
        "format": CURRENT_ACCEPTANCE_ATTESTATION_V1_FORMAT,
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


def _v1_predecessor_acceptance_binding() -> dict[str, Any]:
    return {
        "tag_name": S1_ACCEPTANCE_TAG_NAME,
        "tag_object": S1_ACCEPTANCE_V1_TAG_OBJECT,
        "closure_commit": S1_ACCEPTANCE_V1_CLOSURE_COMMIT,
        "result_commit": S1_ACCEPTANCE_V1_RESULT_COMMIT,
        "disposition": "superseded_nonconforming",
        "current_for_s2_commitment": False,
    }


def _validate_attestation_v2_event_times(
    *,
    validation_started_at: str,
    gate_completed_at: str,
    attestation_preparation_started_at: str,
) -> tuple[datetime, datetime, datetime]:
    """Validate runtime-captured host observations without claiming a signing time."""

    validation_started_time = _parse_utc(
        validation_started_at,
        owner="generation-2 acceptance validation_started_at_utc",
    )
    gate_time = _parse_utc(
        gate_completed_at,
        owner="generation-2 acceptance gate_completed_at_utc",
    )
    preparation_started_time = _parse_utc(
        attestation_preparation_started_at,
        owner="generation-2 acceptance attestation_preparation_started_at_utc",
    )
    if not validation_started_time <= gate_time <= preparation_started_time:
        raise GovernanceError(
            "generation-2 acceptance times must satisfy validation start <= gate completion "
            "<= attestation preparation start"
        )
    if preparation_started_time - gate_time > MAX_ACCEPTANCE_ATTESTATION_DELAY:
        raise GovernanceError(
            "generation-2 attestation preparation started more than one hour after the gate"
        )
    return validation_started_time, gate_time, preparation_started_time


def _canonical_utc_timestamp(value: datetime) -> str:
    """Render a timezone-aware instant in the governance UTC profile."""

    if value.tzinfo is None:
        raise GovernanceError("canonical UTC rendering requires a timezone-aware instant")
    observed = value.astimezone(UTC)
    timespec = "microseconds" if observed.microsecond else "seconds"
    return observed.isoformat(timespec=timespec).replace("+00:00", "Z")


def _derive_generation_2_finalization_deadline(
    *,
    gate_time: datetime,
    bundle: Mapping[str, Any],
) -> tuple[str, datetime]:
    """Derive the signed half-open finalization deadline from gate and bundle."""

    if gate_time.tzinfo is None:
        raise GovernanceError("generation-2 gate observation must be timezone-aware")
    _bundle_issue, bundle_expiry = _validate_validity_interval(
        _required_string(bundle, "issued_at_utc"),
        _required_string(bundle, "valid_until_utc"),
        owner="S1 generation-2 governance bundle",
    )
    deadline = min(
        gate_time.astimezone(UTC) + MAX_ACCEPTANCE_ATTESTATION_DELAY,
        bundle_expiry,
    )
    if deadline <= gate_time.astimezone(UTC):
        raise GovernanceError("generation-2 finalization deadline is not after the gate")
    return _canonical_utc_timestamp(deadline), deadline


def _validate_generation_2_finalization_deadline_binding(
    record: Mapping[str, Any],
    *,
    bundle: Mapping[str, Any],
) -> datetime:
    """Require the signed deadline to be the exact gate/bundle derivation."""

    gate_time = _parse_utc(
        _required_string(record, "gate_completed_at_utc"),
        owner="generation-2 acceptance gate_completed_at_utc",
    )
    expected_value, expected_time = _derive_generation_2_finalization_deadline(
        gate_time=gate_time,
        bundle=bundle,
    )
    if record.get("finalization_deadline_at_utc") != expected_value:
        raise GovernanceError(
            "generation-2 finalization deadline is not min(gate completion + one hour, "
            "bundle expiry)"
        )
    preparation_time = _parse_utc(
        _required_string(record, "attestation_preparation_started_at_utc"),
        owner="generation-2 acceptance attestation_preparation_started_at_utc",
    )
    if preparation_time >= expected_time:
        raise GovernanceError(
            "generation-2 attestation preparation did not leave a live finalization window"
        )
    return expected_time


def _validate_generation_2_finalization_freshness(
    record: Mapping[str, Any],
    *,
    bundle: Mapping[str, Any],
    observed_at: datetime,
) -> datetime:
    """Fail closed unless host-now remains inside the signed finalization window."""

    if observed_at.tzinfo is None:
        raise GovernanceError("generation-2 finalization host observation must be timezone-aware")
    deadline = _validate_generation_2_finalization_deadline_binding(record, bundle=bundle)
    preparation_time = _parse_utc(
        _required_string(record, "attestation_preparation_started_at_utc"),
        owner="generation-2 acceptance attestation_preparation_started_at_utc",
    )
    observed = observed_at.astimezone(UTC)
    if observed < preparation_time:
        raise GovernanceError(
            "generation-2 finalization host observation predates attestation preparation"
        )
    if observed >= deadline:
        raise GovernanceError("generation-2 attestation finalization deadline has expired")
    return deadline


def _utc_100ns_order_key(value: datetime) -> tuple[datetime, int]:
    """Represent a timezone-aware instant without losing corrective 100 ns ordering."""

    if value.tzinfo is None:
        raise GovernanceError("generation-2 gate observation must be timezone-aware")
    observed = value.astimezone(UTC)
    return observed.replace(microsecond=0), observed.microsecond * 10


def _corrective_authorization_verification_key(
    corrective_authorization: Mapping[str, Any],
) -> tuple[datetime, int]:
    imported = _as_object(
        corrective_authorization.get("import_verification"),
        owner="corrective kickoff import verification",
    )
    return _parse_corrective_utc_100ns(
        _required_string(imported, "verification_recorded_at_utc"),
        owner="corrective kickoff verification_recorded_at_utc",
    )


def _validate_corrective_authorization_precedes_baseline(
    *,
    corrective_authorization: Mapping[str, Any],
    baseline: Mapping[str, Any],
) -> None:
    """Reject a retroactive inventory that predates its signed authorization."""

    authorization_observed = _corrective_authorization_verification_key(corrective_authorization)
    inventory_started = _parse_corrective_utc_100ns(
        _required_string(baseline, "inventory_started_at_utc"),
        owner="generation-2 baseline inventory_started_at_utc",
    )
    if authorization_observed > inventory_started:
        raise GovernanceError(
            "generation-2 baseline inventory predates corrective authorization verification"
        )


def _validate_generation_2_bundle_gate_ordering(
    *,
    validation_started_time: datetime,
    gate_time: datetime,
    bundle: Mapping[str, Any],
) -> tuple[datetime, datetime]:
    """Validate the bundle's host observations through the sampled final gate."""

    if bundle.get("format") != "agent-assure-governance-bundle/2":
        raise GovernanceError("generation-2 gate requires a generation-2 governance bundle")
    if validation_started_time.tzinfo is None or gate_time.tzinfo is None:
        raise GovernanceError("generation-2 gate observations must be timezone-aware")
    observed_start = validation_started_time.astimezone(UTC)
    observed_gate = gate_time.astimezone(UTC)
    issue_time, expiry_time = _validate_validity_interval(
        _required_string(bundle, "issued_at_utc"),
        _required_string(bundle, "valid_until_utc"),
        owner="generation-2 governance bundle",
    )
    claim_prepared = _parse_utc(
        _required_string(bundle, "claim_prepared_at_utc"),
        owner="generation-2 governance bundle claim_prepared_at_utc",
    )
    import_evidence = _as_object(
        bundle.get("signature_import_evidence"),
        owner="generation-2 governance bundle signature import evidence",
    )
    verification_recorded = _parse_utc(
        _required_string(import_evidence, "verification_recorded_at_utc"),
        owner="generation-2 governance bundle verification_recorded_at_utc",
    )
    if not (
        issue_time
        <= claim_prepared
        <= verification_recorded
        <= observed_start
        <= observed_gate
        < expiry_time
    ):
        raise GovernanceError(
            "generation-2 governance bundle observations violate "
            "issue <= claim preparation <= import verification <= validation start "
            "<= final gate < expiry"
        )
    return issue_time, expiry_time


def _validate_generation_2_final_gate_validity(
    *,
    validation_started_time: datetime,
    gate_time: datetime,
    kickoff_records: Mapping[str, Mapping[str, Any]],
    corrective_authorization: Mapping[str, Any],
    forecast: Mapping[str, Any],
    bundle: Mapping[str, Any],
) -> None:
    """Confirm every generation-2 predecessor at the exact sampled final gate."""

    if validation_started_time.tzinfo is None or gate_time.tzinfo is None:
        raise GovernanceError("generation-2 gate observations must be timezone-aware")
    observed_start = validation_started_time.astimezone(UTC)
    observed_gate = gate_time.astimezone(UTC)
    if _corrective_authorization_verification_key(corrective_authorization) > _utc_100ns_order_key(
        observed_start
    ):
        raise GovernanceError(
            "corrective authorization verification occurs after generation-2 validation start"
        )

    for ticket_id, record in sorted(kickoff_records.items()):
        owner = f"{ticket_id} kickoff"
        issue_time, expiry_time = _validate_validity_interval(
            _required_string(record, "issued_at_utc"),
            _required_string(record, "valid_until_utc"),
            owner=owner,
        )
        if not issue_time <= observed_start <= observed_gate < expiry_time:
            raise GovernanceError(
                f"{owner} is not current from validation start through the final gate observation"
            )

    if (
        forecast.get("format") != "agent-assure-delivery-forecast/2"
        or forecast.get("forecast_status") != "accepted"
    ):
        raise GovernanceError("generation-2 gate requires an accepted generation-2 forecast")
    forecast_issue, forecast_expiry = _validate_validity_interval(
        _required_string(forecast, "issued_at_utc"),
        _required_string(forecast, "valid_until_utc"),
        owner="generation-2 delivery forecast",
    )
    producer_envelope = _as_object(
        forecast.get("signature_envelope"), owner="forecast producer signature"
    )
    acceptance_receipt = _as_object(
        forecast.get("acceptance_receipt"), owner="forecast acceptance receipt"
    )
    acceptance_envelope = _as_object(
        acceptance_receipt.get("signature_envelope"),
        owner="forecast acceptance signature",
    )
    producer_evidence = _validate_forecast_v2_signature_import_evidence(
        producer_envelope.get("verification_evidence"),
        issued_at_utc=_required_string(forecast, "issued_at_utc"),
        valid_until_utc=_required_string(forecast, "valid_until_utc"),
    )
    acceptance_evidence = _validate_forecast_v2_signature_import_evidence(
        acceptance_envelope.get("verification_evidence"),
        issued_at_utc=_required_string(forecast, "issued_at_utc"),
        valid_until_utc=_required_string(forecast, "valid_until_utc"),
    )
    if producer_evidence != acceptance_evidence:
        raise GovernanceError(
            "forecast producer and acceptance import observations do not match at the gate"
        )
    forecast_import_completed = _parse_utc(
        _required_string(producer_evidence, "import_verification_completed_at_utc"),
        owner="forecast import verification completion observation",
    )
    if not (
        forecast_issue
        <= forecast_import_completed
        <= observed_start
        <= observed_gate
        < forecast_expiry
    ):
        raise GovernanceError(
            "generation-2 forecast observations violate import completion <= validation "
            "start <= final gate < expiry"
        )

    _validate_generation_2_bundle_gate_ordering(
        validation_started_time=observed_start,
        gate_time=observed_gate,
        bundle=bundle,
    )


def build_current_acceptance_attestation_v2(
    snapshot: RoadmapSnapshot,
    *,
    repository_root: Path,
    bundle: Mapping[str, Any],
    live_repository_evidence: Mapping[str, Any],
    validation_started_at: str,
    gate_completed_at: str,
    attestation_preparation_started_at: str,
    signer_person_id: str,
) -> dict[str, Any]:
    """Build the generation-2 acceptance proof with truthful SSHSIG time semantics."""

    closure_commit = _required_string(live_repository_evidence, "head_commit")
    if GIT_COMMIT_PATTERN.fullmatch(closure_commit) is None:
        raise GovernanceError("generation-2 closure commit is not a full Git object ID")
    validation_started_time, gate_time, preparation_started_time = (
        _validate_attestation_v2_event_times(
            validation_started_at=validation_started_at,
            gate_completed_at=gate_completed_at,
            attestation_preparation_started_at=attestation_preparation_started_at,
        )
    )
    bundle_issue, bundle_expiry = _validate_validity_interval(
        _required_string(bundle, "issued_at_utc"),
        _required_string(bundle, "valid_until_utc"),
        owner="S1 generation-2 governance bundle",
    )
    if not (
        bundle_issue
        <= validation_started_time
        <= gate_time
        <= preparation_started_time
        < bundle_expiry
    ):
        raise GovernanceError("generation-2 validation events must remain inside bundle validity")
    finalization_deadline_at, finalization_deadline_time = (
        _derive_generation_2_finalization_deadline(
            gate_time=gate_time,
            bundle=bundle,
        )
    )
    if preparation_started_time >= finalization_deadline_time:
        raise GovernanceError(
            "generation-2 attestation preparation did not leave a live finalization window"
        )
    live_evidence = _validate_live_repository_evidence(
        live_repository_evidence,
        expected_closure_commit=closure_commit,
        expected_branch_name=S1_CORRECTIVE_BRANCH_NAME,
    )
    result_commit = _required_string(bundle, "result_commit")
    if GIT_COMMIT_PATTERN.fullmatch(result_commit) is None:
        raise GovernanceError("generation-2 bundle result commit is invalid")
    bundle_digest = _required_string(bundle, "bundle_digest")
    if SHA256_PATTERN.fullmatch(bundle_digest) is None:
        raise GovernanceError("generation-2 bundle digest is invalid")
    projection: dict[str, Any] = {
        "format": CURRENT_ACCEPTANCE_ATTESTATION_V2_FORMAT,
        "spec_revision": SPEC_REVISION,
        "release": "1.0.0a1",
        "maturity": "governed-baseline",
        "authorization_scope": "development_governance_only",
        "independent_review_claimed": False,
        "acceptance_generation": 2,
        "supersedes_acceptance_generation": 1,
        "predecessor_acceptance": _v1_predecessor_acceptance_binding(),
        "acceptance_tag_name": S1_ACCEPTANCE_V2_TAG_NAME,
        "closure_commit": closure_commit,
        "result_commit": result_commit,
        "bundle_digest": bundle_digest,
        "full_roadmap_digest": snapshot.raw_digest,
        "validation_started_at_utc": validation_started_at,
        "gate_completed_at_utc": gate_completed_at,
        "attestation_preparation_started_at_utc": attestation_preparation_started_at,
        "finalization_deadline_at_utc": finalization_deadline_at,
        "time_evidence": dict(ATTESTATION_V2_TIME_EVIDENCE),
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
    digest = domain_digest(CURRENT_ACCEPTANCE_ATTESTATION_V2_DOMAIN, projection)
    return {
        **projection,
        "attestation_digest": digest,
        "signature_envelope": _pending_attestation_v2_signature(
            signer_person_id,
            "repository_maintainer",
            digest,
        ),
    }


def _validate_executing_acceptance_artifacts(
    record: Mapping[str, Any],
    *,
    repository_root: Path,
) -> None:
    """Bind a generation-2 historical result to the bytes doing the checking.

    This closes the bootstrap evidence gap for the accepted host workflow: the
    Python module currently executing must be the selected worktree's validator,
    and both it and the external launcher on disk must equal the artifacts bound
    into the signed tag.  It does not make an already-compromised Python process
    a trust root; the reviewed external launcher and runtime bootstrap remain the
    process-integrity boundary.
    """

    root = repository_root.resolve()
    expected_validator_path = (root / "scripts/v1_s1_governance.py").resolve()
    executing_validator_path = Path(__file__).resolve()
    if _early_normalized_path(executing_validator_path) != _early_normalized_path(
        expected_validator_path
    ):
        raise GovernanceError(
            "generation-2 historical check is not executing the selected worktree validator"
        )
    expected_validator = _as_object(record.get("validator_artifact"), owner="validator_artifact")
    observed_validator = _artifact_evidence(
        root,
        "scripts/v1_s1_governance.py",
        kind="governance_validator",
    )
    if observed_validator != expected_validator:
        raise GovernanceError(
            "generation-2 executing validator bytes differ from the signed attestation"
        )
    expected_launcher = _as_object(record.get("launcher_artifact"), owner="launcher_artifact")
    observed_launcher = _artifact_evidence(
        root,
        "scripts/v1_s1_governance.ps1",
        kind="governance_runtime_launcher",
    )
    if observed_launcher != expected_launcher:
        raise GovernanceError("generation-2 launcher bytes differ from the signed attestation")


def _validate_historical_v2_checkout_state(
    repository_root: Path,
    *,
    expected_closure_commit: str,
) -> None:
    """Require historical generation-2 execution at the exact clean C2 tree."""

    head = _run_git(repository_root, ["rev-parse", "--verify", "HEAD^{commit}"])
    if head.returncode != 0:
        raise GovernanceError("unable to resolve HEAD for generation-2 historical checking")
    observed_head = head.stdout.decode("ascii", errors="strict").strip()
    if observed_head != expected_closure_commit:
        raise GovernanceError(
            "generation-2 historical checking requires HEAD at the exact closure commit"
        )
    status = _run_git(
        repository_root,
        ["status", "--porcelain=v1", "--untracked-files=all"],
    )
    if status.returncode != 0:
        raise GovernanceError(
            "unable to inspect worktree cleanliness for generation-2 historical checking"
        )
    if status.stdout:
        changed_paths = " ".join(status.stdout.decode("utf-8", errors="replace").split())[
            :MAX_GIT_DIAGNOSTIC_CHARS
        ]
        raise GovernanceError(
            "generation-2 historical checking requires a clean closure worktree: " + changed_paths
        )


def _validate_current_acceptance_attestation(
    record: Mapping[str, Any],
    *,
    repository_root: Path,
    expected_closure_commit: str,
    expected_roadmap_digest: str,
    allow_pending: bool,
    require_executing_artifacts: bool = False,
) -> tuple[datetime, datetime | None]:
    if record.get("format") == CURRENT_ACCEPTANCE_ATTESTATION_V2_FORMAT:
        return _validate_current_acceptance_attestation_v2(
            record,
            repository_root=repository_root,
            expected_closure_commit=expected_closure_commit,
            expected_roadmap_digest=expected_roadmap_digest,
            allow_pending=allow_pending,
            require_executing_artifacts=require_executing_artifacts,
        )
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
        "format": CURRENT_ACCEPTANCE_ATTESTATION_V1_FORMAT,
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


def _validate_current_acceptance_attestation_v2(
    record: Mapping[str, Any],
    *,
    repository_root: Path,
    expected_closure_commit: str,
    expected_roadmap_digest: str,
    allow_pending: bool,
    require_executing_artifacts: bool,
) -> tuple[datetime, datetime | None]:
    """Validate generation 2 without representing preparation time as signing time."""

    required = {
        "format",
        "spec_revision",
        "release",
        "maturity",
        "authorization_scope",
        "independent_review_claimed",
        "acceptance_generation",
        "supersedes_acceptance_generation",
        "predecessor_acceptance",
        "acceptance_tag_name",
        "closure_commit",
        "result_commit",
        "bundle_digest",
        "full_roadmap_digest",
        "validation_started_at_utc",
        "gate_completed_at_utc",
        "attestation_preparation_started_at_utc",
        "finalization_deadline_at_utc",
        "time_evidence",
        "current_gate_result",
        "live_repository_evidence",
        "validator_artifact",
        "launcher_artifact",
        "signer_person_id",
        "attestation_digest",
        "signature_envelope",
    }
    if set(record) != required:
        raise GovernanceError("generation-2 acceptance attestation has unexpected fields")
    exact: dict[str, object] = {
        "format": CURRENT_ACCEPTANCE_ATTESTATION_V2_FORMAT,
        "spec_revision": SPEC_REVISION,
        "release": "1.0.0a1",
        "maturity": "governed-baseline",
        "authorization_scope": "development_governance_only",
        "independent_review_claimed": False,
        "acceptance_generation": 2,
        "supersedes_acceptance_generation": 1,
        "predecessor_acceptance": _v1_predecessor_acceptance_binding(),
        "acceptance_tag_name": S1_ACCEPTANCE_V2_TAG_NAME,
        "closure_commit": expected_closure_commit,
        "full_roadmap_digest": expected_roadmap_digest,
        "time_evidence": ATTESTATION_V2_TIME_EVIDENCE,
        "current_gate_result": "valid_current_closure",
    }
    for key, expected in exact.items():
        if record.get(key) != expected:
            raise GovernanceError(f"generation-2 acceptance attestation changed {key}")
    if GIT_COMMIT_PATTERN.fullmatch(_required_string(record, "result_commit")) is None:
        raise GovernanceError("generation-2 acceptance result commit is invalid")
    if SHA256_PATTERN.fullmatch(_required_string(record, "bundle_digest")) is None:
        raise GovernanceError("generation-2 acceptance bundle digest is invalid")
    _validate_live_repository_evidence(
        record.get("live_repository_evidence"),
        expected_closure_commit=expected_closure_commit,
        expected_branch_name=S1_CORRECTIVE_BRANCH_NAME,
    )
    validator = _as_object(record.get("validator_artifact"), owner="validator_artifact")
    expected_validator = _artifact_evidence_from_commit(
        repository_root,
        expected_closure_commit,
        "scripts/v1_s1_governance.py",
        kind="governance_validator",
    )
    if validator != expected_validator:
        raise GovernanceError("generation-2 acceptance validator artifact changed")
    launcher = _as_object(record.get("launcher_artifact"), owner="launcher_artifact")
    expected_launcher = _artifact_evidence_from_commit(
        repository_root,
        expected_closure_commit,
        "scripts/v1_s1_governance.ps1",
        kind="governance_runtime_launcher",
    )
    if launcher != expected_launcher:
        raise GovernanceError("generation-2 acceptance launcher artifact changed")
    if require_executing_artifacts:
        _validate_historical_v2_checkout_state(
            repository_root,
            expected_closure_commit=expected_closure_commit,
        )
        _validate_executing_acceptance_artifacts(record, repository_root=repository_root)
    expected_digest = domain_digest(
        CURRENT_ACCEPTANCE_ATTESTATION_V2_DOMAIN,
        _current_acceptance_attestation_projection(record),
    )
    if record.get("attestation_digest") != expected_digest:
        raise GovernanceError("generation-2 acceptance attestation digest mismatch")
    _validation_started_time, gate_time, preparation_started_time = (
        _validate_attestation_v2_event_times(
            validation_started_at=_required_string(record, "validation_started_at_utc"),
            gate_completed_at=_required_string(record, "gate_completed_at_utc"),
            attestation_preparation_started_at=_required_string(
                record,
                "attestation_preparation_started_at_utc",
            ),
        )
    )
    finalization_deadline_value = _required_string(
        record,
        "finalization_deadline_at_utc",
    )
    finalization_deadline_time = _parse_utc(
        finalization_deadline_value,
        owner="generation-2 acceptance finalization_deadline_at_utc",
    )
    if finalization_deadline_value != _canonical_utc_timestamp(finalization_deadline_time):
        raise GovernanceError("generation-2 finalization deadline is not canonically rendered")
    if not (
        gate_time < finalization_deadline_time <= gate_time + MAX_ACCEPTANCE_ATTESTATION_DELAY
        and preparation_started_time < finalization_deadline_time
    ):
        raise GovernanceError(
            "generation-2 finalization deadline is outside the gate-to-finalization window"
        )
    signer_person_id = _required_string(record, "signer_person_id")
    signed = _validate_attestation_v2_signature_envelope(
        record.get("signature_envelope"),
        expected_person_id=signer_person_id,
        expected_subject_digest=expected_digest,
        allow_pending=allow_pending,
    )
    return gate_time, preparation_started_time if signed else None


def _validate_historical_attestation_bundle_time_evidence(
    record: Mapping[str, Any],
    *,
    acceptance_generation: int,
    gate_time: datetime,
    attestation_evidence_time: datetime | None,
    bundle: Mapping[str, Any],
) -> None:
    """Validate bundle-relative time evidence without upgrading SSHSIG semantics."""

    if acceptance_generation == 2:
        if attestation_evidence_time is None:
            raise GovernanceError(
                "signed generation-2 acceptance attestation lacks its preparation-start "
                "host observation"
            )
        if record.get("time_evidence") != ATTESTATION_V2_TIME_EVIDENCE:
            raise GovernanceError("generation-2 acceptance time semantics changed")
        validation_started_time = _parse_utc(
            _required_string(record, "validation_started_at_utc"),
            owner="generation-2 acceptance validation_started_at_utc",
        )
        _bundle_issue, bundle_expiry = _validate_generation_2_bundle_gate_ordering(
            validation_started_time=validation_started_time,
            gate_time=gate_time,
            bundle=bundle,
        )
        finalization_deadline = _validate_generation_2_finalization_deadline_binding(
            record,
            bundle=bundle,
        )
        if not gate_time <= attestation_evidence_time < bundle_expiry:
            raise GovernanceError(
                "generation-2 gate or preparation-start host observation is outside the "
                "bundle validity interval"
            )
        if attestation_evidence_time >= finalization_deadline:
            raise GovernanceError(
                "generation-2 preparation-start observation is outside the signed "
                "finalization window"
            )
        return
    if acceptance_generation != 1:
        raise GovernanceError("unsupported S1 acceptance generation")
    bundle_issue, bundle_expiry = _validate_validity_interval(
        _required_string(bundle, "issued_at_utc"),
        _required_string(bundle, "valid_until_utc"),
        owner="S1 governance bundle",
    )
    if attestation_evidence_time is None:
        raise GovernanceError("signed current acceptance attestation lacks a trusted ordering time")
    if not bundle_issue <= attestation_evidence_time < bundle_expiry:
        raise GovernanceError(
            "current acceptance attestation ordering evidence is outside the bundle "
            "validity interval"
        )


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
    envelope["signature"] = None
    record_format = record.get("format")
    if record_format == CURRENT_ACCEPTANCE_ATTESTATION_V1_FORMAT:
        envelope["signed_at_utc"] = _required_string(record, "signature_requested_at_utc")
        claim = _signature_claim_bytes(envelope)
    elif record_format == CURRENT_ACCEPTANCE_ATTESTATION_V2_FORMAT:
        claim = _attestation_v2_signature_claim_bytes(envelope)
    else:
        raise GovernanceError("current acceptance attestation format is unsupported")
    parent = plan_directory.parent
    parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f"{plan_directory.name}-staging-", dir=parent))
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
    if header_lines[1] != "type commit" or not header_lines[2].startswith("tag "):
        raise GovernanceError("S1 acceptance tag identity changed")
    tag_name = header_lines[2].removeprefix("tag ")
    if tag_name not in {S1_ACCEPTANCE_TAG_NAME, S1_ACCEPTANCE_V2_TAG_NAME}:
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
    expected_tag_name = {
        CURRENT_ACCEPTANCE_ATTESTATION_V1_FORMAT: S1_ACCEPTANCE_TAG_NAME,
        CURRENT_ACCEPTANCE_ATTESTATION_V2_FORMAT: S1_ACCEPTANCE_V2_TAG_NAME,
    }.get(_required_string(record, "format"))
    if expected_tag_name is None or tag_name != expected_tag_name:
        raise GovernanceError("S1 acceptance tag identity changed")
    if record.get("acceptance_tag_name") != expected_tag_name:
        raise GovernanceError("S1 acceptance tag record names another tag")
    ref = _run_git(
        repository_root,
        ["rev-parse", "--verify", f"refs/tags/{expected_tag_name}^{{tag}}"],
    )
    if ref.returncode != 0 or ref.stdout.decode("ascii", errors="strict").strip() != tag_object:
        raise GovernanceError("the fixed S1 acceptance tag does not resolve to the selected object")
    return record


def _validate_generation_1_predecessor_acceptance(
    repository_root: Path,
    *,
    expected_roadmap_digest: str,
) -> dict[str, Any]:
    """Revalidate the immutable A1 ref and object before accepting generation 2.

    Merely embedding A1's object ID in the generation-2 claim is insufficient:
    the public, fixed predecessor ref could later be deleted or moved.  This
    check requires that the ref still resolves to the exact annotated object,
    that the object still peels to C1, that its canonical tag message is the
    signed generation-1 attestation, and that the attestation itself verifies.
    """

    predecessor = _read_tagged_current_acceptance_attestation(
        repository_root,
        tag_object=S1_ACCEPTANCE_V1_TAG_OBJECT,
        expected_closure_commit=S1_ACCEPTANCE_V1_CLOSURE_COMMIT,
    )
    if predecessor.get("format") != CURRENT_ACCEPTANCE_ATTESTATION_V1_FORMAT:
        raise GovernanceError("generation-1 predecessor tag contains another format")
    _gate_time, signature_time = _validate_current_acceptance_attestation(
        predecessor,
        repository_root=repository_root,
        expected_closure_commit=S1_ACCEPTANCE_V1_CLOSURE_COMMIT,
        expected_roadmap_digest=expected_roadmap_digest,
        allow_pending=False,
    )
    if signature_time is None:
        raise GovernanceError("generation-1 predecessor attestation is not signed")
    return predecessor


def _validate_generation_2_finalization_local_repository(
    repository_root: Path,
    *,
    record: Mapping[str, Any],
) -> None:
    """Re-resolve the exact local refs and clean C2 identity without a new fetch."""

    closure_commit = _required_string(record, "closure_commit")
    signed_evidence = _validate_live_repository_evidence(
        record.get("live_repository_evidence"),
        expected_closure_commit=closure_commit,
        expected_branch_name=S1_CORRECTIVE_BRANCH_NAME,
    )
    observed = validate_live_acceptance_repository(
        repository_root,
        fetch=False,
        expected_branch_name=S1_CORRECTIVE_BRANCH_NAME,
    )
    if (
        observed.get("fetch_performed") is not False
        or observed.get("authoritative_remote_refs") != {}
    ):
        raise GovernanceError("generation-2 finalization local-ref check changed semantics")
    for field in ("approved_remote_url", "branch_name", "head_commit", "local_refs"):
        if observed.get(field) != signed_evidence.get(field):
            raise GovernanceError(f"generation-2 finalization current repository changed {field}")


def _revalidate_generation_2_finalization_state(
    repository_root: Path,
    *,
    record: Mapping[str, Any],
) -> str:
    """Revalidate fresh live records, exact topology, clean C2, and local refs.

    The clock readings are host observations only.  They bound when this
    verifier is willing to publish or reuse the signed record; they do not
    represent when OpenSSH produced the SSHSIG.
    """

    root = repository_root.resolve()
    governance_root = (root / "docs/governance/v1").resolve()
    roadmap_path = (root / "Agent_Assure_Implementation_Roadmap.md").resolve()
    started_at = _parse_utc(
        _canonical_host_utc_now(),
        owner="generation-2 finalization validation start",
    )
    bundle = _read_json(governance_root / "governance-bundle.json")
    if bundle.get("format") != "agent-assure-governance-bundle/2":
        raise GovernanceError("generation-2 finalization requires the live generation-2 bundle")
    if bundle.get("bundle_digest") != record.get("bundle_digest"):
        raise GovernanceError("generation-2 finalization live bundle digest changed")
    if bundle.get("result_commit") != record.get("result_commit"):
        raise GovernanceError("generation-2 finalization live result commit changed")
    _validate_generation_2_finalization_freshness(
        record,
        bundle=bundle,
        observed_at=started_at,
    )

    snapshot, _catalog, _registry, baseline, _ledger, roster, roster_digest = (
        _load_forecast_v2_workspace(
            repository_root=root,
            governance_root=governance_root,
            roadmap_path=roadmap_path,
            allow_pending=False,
        )
    )
    if snapshot.raw_digest != record.get("full_roadmap_digest"):
        raise GovernanceError("generation-2 finalization private roadmap digest changed")

    signing_key = _read_json(governance_root / "maintainer-signing-key.json")
    corrective_authorization = _read_json(governance_root / "corrective-kickoff-authorization.json")
    kickoff_schema = _read_json(governance_root / "kickoff-authorization.schema.json")
    kickoff_records: dict[str, dict[str, Any]] = {}
    for ticket_id in ("V1-BOOT-01", "V1-BASE-01"):
        kickoff = _read_json(governance_root / f"kickoff-authorization-{ticket_id.lower()}.json")
        validate_kickoff_authorization(
            snapshot,
            kickoff,
            kickoff_schema,
            expected_ticket_id=ticket_id,
            expected_roster_digest=roster_digest,
            expected_person_id="acblabs",
            allow_pending=False,
            validation_time=started_at,
        )
        kickoff_records[ticket_id] = kickoff

    forecast = _read_json(governance_root / "delivery-forecast.json")
    completion_receipts = {
        ticket_id: _read_json(governance_root / f"completion-receipt-{ticket_id.lower()}.json")
        for ticket_id in ("V1-BOOT-01", "V1-BASE-01")
    }
    validate_governance_bundle(
        snapshot,
        bundle,
        _read_json(governance_root / "governance-bundle.schema.json"),
        repository_root=root,
        roster=roster,
        kickoff_records=kickoff_records,
        completion_receipts=completion_receipts,
        forecast=forecast,
        signing_key=signing_key,
        baseline_observations=baseline,
        expected_person_id="acblabs",
        expected_base_commit=PINNED_BASE_COMMIT,
        allow_pending=False,
        validation_time=started_at,
        require_bundle_on_disk=True,
        require_predecessors_on_disk=True,
        require_current_closure=True,
        require_closure=True,
        expected_closure_commit=_required_string(record, "closure_commit"),
    )

    _validate_generation_2_finalization_local_repository(root, record=record)
    _validate_s1_closure_checkout(
        root,
        result_commit=_required_string(bundle, "result_commit"),
        bundle=bundle,
        require_current_checkout=True,
        expected_closure_commit=_required_string(record, "closure_commit"),
    )
    for relative, expected in (
        ("governance-bundle.json", bundle),
        (
            "completion-receipt-v1-boot-01.json",
            completion_receipts["V1-BOOT-01"],
        ),
        (
            "completion-receipt-v1-base-01.json",
            completion_receipts["V1-BASE-01"],
        ),
    ):
        if _read_json(governance_root / relative) != expected:
            raise GovernanceError(
                "generation-2 finalization live closure record changed during revalidation"
            )
    completed_at = _parse_utc(
        _canonical_host_utc_now(),
        owner="generation-2 finalization validation completion",
    )
    if completed_at < started_at:
        raise GovernanceError(
            "generation-2 finalization host clock moved backwards during revalidation"
        )
    validation_started_time = _parse_utc(
        _required_string(record, "validation_started_at_utc"),
        owner="generation-2 acceptance validation_started_at_utc",
    )
    _validate_generation_2_final_gate_validity(
        validation_started_time=validation_started_time,
        gate_time=completed_at,
        kickoff_records=kickoff_records,
        corrective_authorization=corrective_authorization,
        forecast=forecast,
        bundle=bundle,
    )
    deadline = _validate_generation_2_finalization_freshness(
        record,
        bundle=bundle,
        observed_at=completed_at,
    )
    return _canonical_utc_timestamp(deadline)


@_require_frozen_runtime
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
    output = plan_directory / "attestation.signed.json"
    plan_input_names = {
        "attestation.pending.json",
        "attestation.claim",
        "attestation.claim.sig",
    }
    observed_names = {entry.name for entry in plan_directory.iterdir()}
    if observed_names not in (
        plan_input_names,
        plan_input_names | {output.name},
    ):
        raise GovernanceError("current acceptance attestation plan has missing or extra files")
    for name in plan_input_names:
        path = plan_directory / name
        if not path.is_file() or path.is_symlink():
            raise GovernanceError("current acceptance attestation plan contains a non-file")
    output_already_present = output.name in observed_names
    if output_already_present and (not output.is_file() or output.is_symlink()):
        raise GovernanceError("signed current acceptance attestation is not a regular file")
    record = _read_json(plan_directory / "attestation.pending.json")
    if record.get("format") == CURRENT_ACCEPTANCE_ATTESTATION_V2_FORMAT:
        enforced_plan_directory = _corrective_private_acceptance_path(
            repository_root,
            cast(str, args.plan_dir),
            owner="generation-2 current acceptance attestation plan",
            must_exist=True,
        )
        if enforced_plan_directory != plan_directory:
            raise GovernanceError("generation-2 attestation plan path changed during validation")
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
    record_format = record.get("format")
    if record_format == CURRENT_ACCEPTANCE_ATTESTATION_V1_FORMAT:
        signed_envelope["signed_at_utc"] = _required_string(record, "signature_requested_at_utc")
        expected_claim = _signature_claim_bytes(signed_envelope)
    elif record_format == CURRENT_ACCEPTANCE_ATTESTATION_V2_FORMAT:
        expected_claim = _attestation_v2_signature_claim_bytes(signed_envelope)
    else:
        raise GovernanceError("current acceptance attestation format is unsupported")
    armor = _canonical_sshsig_armor((plan_directory / "attestation.claim.sig").read_bytes())
    signed_envelope["signature"] = base64.b64encode(armor).decode("ascii")
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
    payload = _render_acceptance_attestation_bytes(signed_record)
    finalization_deadline: str | None = None

    def publish_or_reuse_exact_payload() -> None:
        if output_already_present:
            try:
                existing_payload = output.read_bytes()
            except OSError as exc:
                raise GovernanceError(
                    f"unable to read existing signed current acceptance attestation: {exc}"
                ) from exc
            if existing_payload != payload:
                raise GovernanceError(
                    "existing signed current acceptance attestation differs from the "
                    "reverified exact output"
                )
            return
        try:
            publication_staging = plan_directory.parent
            if record_format == CURRENT_ACCEPTANCE_ATTESTATION_V2_FORMAT:
                publication_staging = _corrective_private_acceptance_path(
                    repository_root,
                    ".tmp/s1-acceptance/current-gate-v2-atomic-publication",
                    owner="generation-2 attestation atomic publication staging",
                    must_exist=None,
                )
                publication_staging.mkdir(parents=True, exist_ok=True)
            _publish_new_file_atomically(
                output,
                payload,
                staging_directory=publication_staging,
            )
        except OSError as exc:
            raise GovernanceError(
                f"unable to atomically publish signed current acceptance attestation: {exc}"
            ) from exc

    if record_format == CURRENT_ACCEPTANCE_ATTESTATION_V2_FORMAT:
        if output_already_present:
            # Establish that this is an exact retry before spending trust in a
            # current-state result, then read it again after revalidation to
            # close an ordinary concurrent-replacement window.
            publish_or_reuse_exact_payload()
        finalization_deadline = _revalidate_generation_2_finalization_state(
            repository_root,
            record=signed_record,
        )
        publish_or_reuse_exact_payload()
    else:
        publish_or_reuse_exact_payload()
    print(
        json.dumps(
            {
                "acceptance_tag_name": (
                    S1_ACCEPTANCE_V2_TAG_NAME
                    if record_format == CURRENT_ACCEPTANCE_ATTESTATION_V2_FORMAT
                    else S1_ACCEPTANCE_TAG_NAME
                ),
                "attestation_digest": expected_digest,
                "closure_commit": closure_commit,
                "idempotent_recovery": output_already_present,
                "output": str(output),
                "result": "verified_current_acceptance_attestation_ready_for_tag",
                **(
                    {"finalization_deadline_at_utc": finalization_deadline}
                    if finalization_deadline is not None
                    else {}
                ),
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
    committed = _read_commit_blob(
        repository_root,
        commit,
        relative_path,
        owner="historical JSON",
    )
    if len(committed) > MAX_GOVERNANCE_JSON_BYTES:
        raise GovernanceError(f"historical governance JSON exceeds 8 MiB: {relative_path}")
    try:
        payload = committed.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise GovernanceError(f"historical governance JSON is not UTF-8: {relative_path}") from exc
    if payload.startswith("\ufeff"):
        raise GovernanceError(f"historical governance JSON has a UTF-8 BOM: {relative_path}")
    return _as_object(strict_json_loads(payload), owner=relative_path)


def _historical_governance_json_paths(*, acceptance_generation: int = 1) -> list[str]:
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
    if acceptance_generation == 2:
        names.extend(
            [
                "corrective-kickoff-authorization.json",
                "corrective-kickoff-authorization.schema.json",
                "current-acceptance-attestation.schema.json",
                "delivery-forecast.estimation-catalog.json",
                "delivery-forecast.estimation-catalog.schema.json",
            ]
        )
    elif acceptance_generation != 1:
        raise GovernanceError("unsupported S1 acceptance generation")
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


@_require_frozen_runtime
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
        allow_pending=False,
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


@_require_frozen_runtime
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


@_require_frozen_runtime
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


@_require_frozen_runtime
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


_FORECAST_V2_GOVERNANCE_SOURCE_NAMES: Final[tuple[str, ...]] = (
    "approval-roster.json",
    "approval-roster.schema.json",
    "baseline-observations.json",
    "baseline-observations.schema.json",
    "corrective-kickoff-authorization.json",
    "corrective-kickoff-authorization.schema.json",
    "delivery-forecast.aggregation-registry.json",
    "delivery-forecast.aggregation-registry.schema.json",
    "delivery-forecast.authoring-ledger.json",
    "delivery-forecast.authoring-ledger.schema.json",
    "delivery-forecast.estimation-catalog.json",
    "delivery-forecast.estimation-catalog.schema.json",
    "delivery-forecast.json",
    "delivery-forecast.schema.json",
    "maintainer-signing-key.json",
    "maintainer-signing-key.schema.json",
)


def _forecast_v2_source_paths(
    repository_root: Path, governance_root: Path, roadmap_path: Path
) -> list[Path]:
    """Return every record/schema consumed by either forecast-v2 ceremony phase."""

    expected_governance_root = (repository_root / "docs/governance/v1").resolve()
    if governance_root.resolve() != expected_governance_root:
        raise GovernanceError("forecast-v2 governance directory must be docs/governance/v1")
    return [
        roadmap_path.resolve(),
        *(expected_governance_root / name for name in _FORECAST_V2_GOVERNANCE_SOURCE_NAMES),
    ]


def _require_forecast_v2_plan_source_set(
    repository_root: Path,
    plan: Mapping[str, Any],
    *,
    expected_paths: Sequence[Path],
) -> None:
    """Reject omitted, substituted, or duplicated forecast-v2 plan sources."""

    root = repository_root.resolve()
    expected: set[str] = set()
    for path in expected_paths:
        try:
            expected.add(path.resolve().relative_to(root).as_posix())
        except ValueError as exc:
            raise GovernanceError("forecast-v2 source leaves the repository root") from exc
    observed: list[str] = []
    for value in _as_array(plan.get("source_files"), owner="forecast-v2 plan source files"):
        source = _as_object(value, owner="forecast-v2 plan source file")
        observed.append(_required_string(source, "path"))
    if len(observed) != len(set(observed)):
        raise GovernanceError("forecast-v2 plan repeats a source file")
    if set(observed) != expected:
        raise GovernanceError("forecast-v2 plan source set is not exact")


def _verify_forecast_v2_plan_sources(
    repository_root: Path,
    plan: Mapping[str, Any],
    *,
    expected_paths: Sequence[Path],
) -> None:
    """Reject an inexact source set or source bytes changed after preparation."""

    _require_forecast_v2_plan_source_set(
        repository_root,
        plan,
        expected_paths=expected_paths,
    )
    root = repository_root.resolve()
    _verify_plan_sources(root, plan)


def _load_forecast_v2_workspace(
    *, repository_root: Path, governance_root: Path, roadmap_path: Path, allow_pending: bool
) -> tuple[
    RoadmapSnapshot,
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    str,
]:
    if governance_root != (repository_root / "docs/governance/v1").resolve():
        raise GovernanceError("forecast-v2 governance directory must be docs/governance/v1")
    validate_local_only_roadmap(repository_root, roadmap_path)
    snapshot = load_roadmap(roadmap_path)
    signing_key = _read_json(governance_root / "maintainer-signing-key.json")
    validate_maintainer_signing_key(
        signing_key,
        _read_json(governance_root / "maintainer-signing-key.schema.json"),
        expected_person_id="acblabs",
        allow_pending=False,
    )
    corrective_authorization = _read_json(governance_root / "corrective-kickoff-authorization.json")
    validate_corrective_kickoff_authorization(
        corrective_authorization,
        _read_json(governance_root / "corrective-kickoff-authorization.schema.json"),
        expected_roadmap_digest=snapshot.raw_digest,
    )
    baseline = _read_json(governance_root / "baseline-observations.json")
    validate_baseline_observations(
        snapshot,
        baseline,
        _read_json(governance_root / "baseline-observations.schema.json"),
        repository_root=repository_root,
    )
    _validate_corrective_authorization_precedes_baseline(
        corrective_authorization=corrective_authorization,
        baseline=baseline,
    )
    catalog = _read_json(governance_root / "delivery-forecast.estimation-catalog.json")
    validate_estimation_catalog_v2(
        catalog,
        _read_json(governance_root / "delivery-forecast.estimation-catalog.schema.json"),
    )
    registry = _read_json(governance_root / "delivery-forecast.aggregation-registry.json")
    _validate_json_schema(
        registry,
        _read_json(governance_root / "delivery-forecast.aggregation-registry.schema.json"),
        owner="generation-2 aggregation registry",
    )
    _resolve_aggregation_method_v2(registry)
    ledger = _read_json(governance_root / "delivery-forecast.authoring-ledger.json")
    validate_authoring_ledger_v2(
        snapshot,
        ledger,
        _read_json(governance_root / "delivery-forecast.authoring-ledger.schema.json"),
        catalog,
        baseline_observations=baseline,
        allow_pending=allow_pending,
    )
    roster = _read_json(governance_root / "approval-roster.json")
    roster_digest, person_id = validate_approval_roster(
        snapshot,
        roster,
        _read_json(governance_root / "approval-roster.schema.json"),
        allow_pending=False,
    )
    if person_id != "acblabs":
        raise GovernanceError("forecast-v2 workflow requires the frozen acblabs maintainer")
    forecast = _read_json(governance_root / "delivery-forecast.json")
    validate_forecast_v2(
        snapshot,
        ledger,
        registry,
        forecast,
        _read_json(governance_root / "delivery-forecast.schema.json"),
        approval_roster=roster,
        approval_roster_digest_value=roster_digest,
        allow_pending=allow_pending,
    )
    return snapshot, catalog, registry, baseline, ledger, roster, roster_digest


def _write_forecast_v2_plan(
    plan_directory: Path,
    *,
    plan: Mapping[str, Any],
    claims: Mapping[str, bytes],
) -> None:
    plan_directory.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(
        tempfile.mkdtemp(prefix=f"{plan_directory.name}-staging-", dir=plan_directory.parent)
    )
    try:
        (temporary / "plan.json").write_bytes(_render_json_bytes(plan))
        for name, payload in claims.items():
            (temporary / name).write_bytes(payload)
        temporary.replace(plan_directory)
    except OSError as exc:
        raise GovernanceError(f"unable to write forecast-v2 signature plan: {exc}") from exc
    finally:
        if temporary.exists():
            shutil.rmtree(temporary, ignore_errors=True)


def _forecast_v2_sign_command(claim_path: Path) -> str:
    return (
        f'"{FROZEN_S1_EXECUTABLE_IDENTITIES["ssh-keygen"].path}" -Y sign '
        '-f "<ABSOLUTE_PRIVATE_KEY_PATH>" '
        f'-n "{SIGNATURE_NAMESPACE}" -O "hashalg=sha512" "{claim_path.resolve()}"'
    )


def _capture_forecast_v2_host_utc(
    *,
    owner: str,
    not_before: Sequence[datetime] = (),
    before: datetime | None = None,
) -> str:
    """Capture, then validate, an explicitly unattested host-UTC observation."""

    value = _canonical_host_utc_now()
    observed = _parse_utc(value, owner=owner)
    if any(observed < lower for lower in not_before):
        raise GovernanceError(f"{owner} is earlier than its required predecessor")
    if before is not None and observed >= before:
        raise GovernanceError(f"{owner} is outside the forecast validity interval")
    return value


@_require_frozen_runtime
@_guard_acceptance_reader
def forecast_v2_decision_plan(args: argparse.Namespace) -> int:
    repository_root = Path(cast(str, args.repository_root)).resolve()
    governance_root = Path(cast(str, args.governance_dir)).resolve()
    roadmap_path = Path(cast(str, args.roadmap)).resolve()
    snapshot, catalog, registry, baseline, ledger, _roster, roster_digest = (
        _load_forecast_v2_workspace(
            repository_root=repository_root,
            governance_root=governance_root,
            roadmap_path=roadmap_path,
            allow_pending=True,
        )
    )
    if ledger.get("decision_evidence") is not None:
        raise GovernanceError("forecast batch decision is already installed")
    manifest = build_forecast_decision_manifest_v2(ledger)
    envelope = _pending_signature_v2(
        "acblabs", "repository_maintainer", manifest["manifest_digest"]
    )
    signed_shape = copy.deepcopy(envelope)
    signed_shape["status"] = "signed"
    claim = _signature_claim_bytes_v2(signed_shape)
    source_paths = _forecast_v2_source_paths(repository_root, governance_root, roadmap_path)
    projection = {
        "format": "agent-assure-delivery-forecast-decision-signature-plan/2",
        "spec_revision": SPEC_REVISION,
        "authorization_effect": "none_until_verified_import",
        "manifest": manifest,
        "signature_envelope": envelope,
        "claim_file": "decision.claim",
        "claim_size_bytes": len(claim),
        "claim_sha256": raw_digest(claim),
        "source_files": [
            _source_file_evidence(repository_root, path)
            for path in sorted(source_paths, key=lambda value: _utf8_sort_key(str(value)))
        ],
        "expected_ready_inputs": {
            "roadmap_digest": snapshot.raw_digest,
            "catalog_digest": catalog["catalog_digest"],
            "registry_digest": registry["registry_digest"],
            "baseline_digest": baseline["observations_digest"],
            "approval_roster_digest": roster_digest,
        },
    }
    plan = {
        **projection,
        "plan_digest": domain_digest(FORECAST_DECISION_PLAN_V2_DOMAIN, projection),
    }
    plan_directory = _corrective_private_acceptance_path(
        repository_root,
        cast(str, args.plan_dir),
        owner="forecast-v2 decision plan",
        must_exist=False,
    )
    _write_forecast_v2_plan(plan_directory, plan=plan, claims={"decision.claim": claim})
    print(
        json.dumps(
            {
                "authorization_effect": "none_until_verified_import",
                "manifest_digest": manifest["manifest_digest"],
                "plan_digest": plan["plan_digest"],
                "plan_directory": str(plan_directory.resolve()),
                "sign_command": _forecast_v2_sign_command(plan_directory / "decision.claim"),
            },
            sort_keys=True,
        )
    )
    return 0


def _read_forecast_v2_plan(
    plan_directory: Path, *, expected_format: str, domain: str, expected_digest: str
) -> dict[str, Any]:
    if SHA256_PATTERN.fullmatch(expected_digest) is None:
        raise GovernanceError("expected plan digest must be a canonical SHA-256 digest")
    plan = _read_json(plan_directory / "plan.json")
    if plan.get("format") != expected_format or plan.get("spec_revision") != SPEC_REVISION:
        raise GovernanceError("forecast-v2 plan identity changed")
    projection = {key: value for key, value in plan.items() if key != "plan_digest"}
    calculated = domain_digest(domain, projection)
    if plan.get("plan_digest") != calculated or calculated != expected_digest:
        raise GovernanceError("forecast-v2 plan digest differs from the confirmed digest")
    return plan


def _require_forecast_v2_plan_files(plan_directory: Path, names: set[str]) -> None:
    observed = {entry.name for entry in plan_directory.iterdir()}
    if observed != names:
        raise GovernanceError("forecast-v2 plan has missing or unexpected files")
    for name in names:
        path = plan_directory / name
        if not path.is_file() or path.is_symlink():
            raise GovernanceError("forecast-v2 plan contains a non-regular file")


def _forecast_v2_import_projection(
    *,
    artifact_format: str,
    authorization_effect: str,
    plan_digest: str,
    targets: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    if SHA256_PATTERN.fullmatch(plan_digest) is None:
        raise GovernanceError("forecast-v2 import plan digest is invalid")
    if not targets:
        raise GovernanceError("forecast-v2 import artifact has no targets")
    return {
        "format": artifact_format,
        "spec_revision": SPEC_REVISION,
        "authorization_effect": authorization_effect,
        "plan_digest": plan_digest,
        "targets": [
            {"path": path, "record": copy.deepcopy(dict(targets[path]))}
            for path in sorted(targets, key=_utf8_sort_key)
        ],
    }


def _build_forecast_v2_import_artifact(
    *,
    artifact_format: str,
    authorization_effect: str,
    plan_digest: str,
    targets: Mapping[str, Mapping[str, Any]],
    domain: str,
) -> dict[str, Any]:
    projection = _forecast_v2_import_projection(
        artifact_format=artifact_format,
        authorization_effect=authorization_effect,
        plan_digest=plan_digest,
        targets=targets,
    )
    return {
        **projection,
        "import_artifact_digest": domain_digest(domain, projection),
    }


def _read_forecast_v2_import_artifact(
    path: Path,
    *,
    expected_format: str,
    expected_authorization_effect: str,
    expected_plan_digest: str,
    expected_target_paths: set[str],
    domain: str,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    artifact = _read_json(path)
    if set(artifact) != {
        "format",
        "spec_revision",
        "authorization_effect",
        "plan_digest",
        "targets",
        "import_artifact_digest",
    } or (
        artifact.get("format") != expected_format
        or artifact.get("spec_revision") != SPEC_REVISION
        or artifact.get("authorization_effect") != expected_authorization_effect
        or artifact.get("plan_digest") != expected_plan_digest
    ):
        raise GovernanceError("forecast-v2 import artifact identity changed")
    targets: dict[str, dict[str, Any]] = {}
    for value in _as_array(artifact.get("targets"), owner="forecast-v2 import targets"):
        target = _as_object(value, owner="forecast-v2 import target")
        if set(target) != {"path", "record"}:
            raise GovernanceError("forecast-v2 import target is malformed")
        relative = _required_string(target, "path")
        if relative in targets:
            raise GovernanceError("forecast-v2 import artifact repeats a target")
        targets[relative] = copy.deepcopy(dict(_as_object(target.get("record"), owner=relative)))
    if set(targets) != expected_target_paths:
        raise GovernanceError("forecast-v2 import artifact target set changed")
    projection = _forecast_v2_import_projection(
        artifact_format=expected_format,
        authorization_effect=expected_authorization_effect,
        plan_digest=expected_plan_digest,
        targets=targets,
    )
    if (
        artifact.get("import_artifact_digest") != domain_digest(domain, projection)
        or {key: value for key, value in artifact.items() if key != "import_artifact_digest"}
        != projection
    ):
        raise GovernanceError("forecast-v2 import artifact digest mismatch")
    return artifact, targets


def _acceptance_target_payload_state(
    repository_root: Path,
    expected_payloads: Mapping[str, bytes],
) -> tuple[bool, bool]:
    matches: list[bool] = []
    for relative, expected in expected_payloads.items():
        target = _resolve_repository_path_without_links(
            repository_root,
            relative,
            owner="acceptance import target",
        )
        matches.append(
            target.is_file() and not target.is_symlink() and target.read_bytes() == expected
        )
    return all(matches), any(matches)


@_require_frozen_runtime
def forecast_v2_decision_import(args: argparse.Namespace) -> int:
    """Verify, persist, recover, and atomically install the batch decision."""

    repository_root = Path(cast(str, args.repository_root)).resolve()
    governance_root = Path(cast(str, args.governance_dir)).resolve()
    roadmap_path = Path(cast(str, args.roadmap)).resolve()
    plan_directory = _corrective_private_acceptance_path(
        repository_root,
        cast(str, args.plan_dir),
        owner="forecast-v2 decision plan",
        must_exist=True,
    )
    stable_import_path = plan_directory / "verified-decision-import.json"
    base_names = {"plan.json", "decision.claim", "decision.claim.sig"}
    observed_names = {entry.name for entry in plan_directory.iterdir()}
    if observed_names not in (base_names, base_names | {stable_import_path.name}):
        raise GovernanceError("forecast-v2 decision plan has missing or unexpected files")
    _require_forecast_v2_plan_files(plan_directory, observed_names)
    expected_plan_digest = cast(str, args.expected_plan_digest)
    plan = _read_forecast_v2_plan(
        plan_directory,
        expected_format="agent-assure-delivery-forecast-decision-signature-plan/2",
        domain=FORECAST_DECISION_PLAN_V2_DOMAIN,
        expected_digest=expected_plan_digest,
    )
    _require_forecast_v2_plan_source_set(
        repository_root,
        plan,
        expected_paths=_forecast_v2_source_paths(repository_root, governance_root, roadmap_path),
    )
    relative_targets = {
        "docs/governance/v1/delivery-forecast.authoring-ledger.json",
        "docs/governance/v1/delivery-forecast.json",
    }
    prior = _acceptance_plan_target_prior_evidence(plan, expected_target_paths=relative_targets)

    if stable_import_path.exists() or stable_import_path.is_symlink():
        if not stable_import_path.is_file() or stable_import_path.is_symlink():
            raise GovernanceError("forecast decision import artifact is not a regular file")
        _artifact, imported_targets = _read_forecast_v2_import_artifact(
            stable_import_path,
            expected_format="agent-assure-delivery-forecast-decision-signature-import/2",
            expected_authorization_effect="verified_decision_targets_may_be_installed",
            expected_plan_digest=expected_plan_digest,
            expected_target_paths=relative_targets,
            domain=FORECAST_DECISION_IMPORT_V2_DOMAIN,
        )
    else:
        imported_targets = {}

    expected_next_payloads = {
        relative: _render_json_bytes(record) for relative, record in imported_targets.items()
    }

    def validate_targets(
        context: tuple[
            RoadmapSnapshot,
            dict[str, Any],
            dict[str, Any],
            dict[str, Any],
            dict[str, Any],
            dict[str, Any],
            str,
        ],
        targets: Mapping[str, Mapping[str, Any]],
    ) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
        snapshot, catalog, registry, baseline, prior_ledger, roster, roster_digest = context
        decided_ledger = targets["docs/governance/v1/delivery-forecast.authoring-ledger.json"]
        ready_forecast = targets["docs/governance/v1/delivery-forecast.json"]
        manifest = _as_object(plan.get("manifest"), owner="forecast decision manifest")
        if manifest != build_forecast_decision_manifest_v2(prior_ledger):
            raise GovernanceError("forecast decision manifest changed after preparation")
        validate_authoring_ledger_v2(
            snapshot,
            decided_ledger,
            _read_json(governance_root / "delivery-forecast.authoring-ledger.schema.json"),
            catalog,
            baseline_observations=baseline,
            allow_pending=False,
        )
        expected_ready = build_forecast_v2(
            snapshot,
            decided_ledger,
            registry,
            approval_roster=roster,
            approval_roster_digest_value=roster_digest,
            issued_at=_required_string(ready_forecast, "issued_at_utc"),
            valid_until=_required_string(ready_forecast, "valid_until_utc"),
            trusted_time_basis=_required_string(ready_forecast, "trusted_time_basis"),
        )
        if ready_forecast != expected_ready:
            raise GovernanceError("verified forecast decision import target changed")
        validate_forecast_v2(
            snapshot,
            decided_ledger,
            registry,
            ready_forecast,
            _read_json(governance_root / "delivery-forecast.schema.json"),
            approval_roster=roster,
            approval_roster_digest_value=roster_digest,
            allow_pending=True,
        )
        return decided_ledger, ready_forecast

    def finish(
        decided_ledger: Mapping[str, Any],
        ready_forecast: Mapping[str, Any],
        *,
        idempotent_recovery: bool,
    ) -> int:
        manifest = _as_object(plan.get("manifest"), owner="forecast decision manifest")
        print(
            json.dumps(
                {
                    "actual_signature_time_claimed": False,
                    "decision_manifest_digest": manifest["manifest_digest"],
                    "forecast_issued_at_utc": ready_forecast["issued_at_utc"],
                    "forecast_status": "ready_for_signature",
                    "forecast_valid_until_utc": ready_forecast["valid_until_utc"],
                    "idempotent_recovery": idempotent_recovery,
                    "ledger_digest": decided_ledger["ledger_digest"],
                    "record_digest": ready_forecast["record_digest"],
                    "result": "verified_itemized_batch_decision_installed",
                },
                sort_keys=True,
            )
        )
        return 0

    with _acceptance_import_lock(repository_root):
        journal = _acceptance_transaction_journal(repository_root)
        if (journal.exists() or journal.is_symlink()) and not imported_targets:
            raise GovernanceError(
                "forecast decision recovery requires its verified import artifact"
            )
        if imported_targets:
            _recover_acceptance_transaction(
                repository_root,
                expected_plan_digest=expected_plan_digest,
                expected_prior_evidence=prior,
                expected_next_payloads=expected_next_payloads,
            )
            all_next, any_next = _acceptance_target_payload_state(
                repository_root,
                expected_next_payloads,
            )
            if all_next:
                _verify_plan_sources_after_target_install(
                    repository_root,
                    plan,
                    installed_target_paths=relative_targets,
                )
                current = _load_forecast_v2_workspace(
                    repository_root=repository_root,
                    governance_root=governance_root,
                    roadmap_path=roadmap_path,
                    allow_pending=True,
                )
                on_disk_targets = {
                    relative: _read_json(repository_root / relative)
                    for relative in relative_targets
                }
                if on_disk_targets != imported_targets:
                    raise GovernanceError("installed forecast decision targets changed")
                decided_ledger = on_disk_targets[
                    "docs/governance/v1/delivery-forecast.authoring-ledger.json"
                ]
                ready_forecast = on_disk_targets["docs/governance/v1/delivery-forecast.json"]
                # The loader already validates the post-install pair; bind it
                # back to the persisted import artifact before reporting success.
                if current[4] != decided_ledger:
                    raise GovernanceError("installed forecast decision ledger changed")
                still_all_next, _ = _acceptance_target_payload_state(
                    repository_root,
                    expected_next_payloads,
                )
                if not still_all_next:
                    raise GovernanceError("forecast decision targets changed during validation")
                return finish(
                    decided_ledger,
                    ready_forecast,
                    idempotent_recovery=True,
                )
            if any_next:
                raise GovernanceError(
                    "forecast decision has a partial install without a recoverable transaction"
                )

        _verify_forecast_v2_plan_sources(
            repository_root,
            plan,
            expected_paths=_forecast_v2_source_paths(
                repository_root, governance_root, roadmap_path
            ),
        )
        context = _load_forecast_v2_workspace(
            repository_root=repository_root,
            governance_root=governance_root,
            roadmap_path=roadmap_path,
            allow_pending=True,
        )
        ledger = context[4]
        if ledger.get("decision_evidence") is not None:
            raise GovernanceError("forecast batch decision is already installed")
        if not imported_targets:
            manifest = _as_object(plan.get("manifest"), owner="forecast decision manifest")
            if manifest != build_forecast_decision_manifest_v2(ledger):
                raise GovernanceError("forecast decision manifest changed after preparation")
            envelope = copy.deepcopy(
                _as_object(plan.get("signature_envelope"), owner="forecast decision envelope")
            )
            envelope["status"] = "signed"
            claim = (plan_directory / "decision.claim").read_bytes()
            if (
                len(claim) != _required_integer(plan, "claim_size_bytes")
                or raw_digest(claim) != plan.get("claim_sha256")
                or claim != _signature_claim_bytes_v2(envelope)
            ):
                raise GovernanceError("forecast decision claim changed after preparation")
            signature_path = plan_directory / "decision.claim.sig"
            envelope["signature"] = base64.b64encode(
                _canonical_sshsig_armor(signature_path.read_bytes())
            ).decode("ascii")
            decided_ledger = _apply_forecast_decision_manifest_v2(
                ledger,
                manifest,
                envelope,
            )
            issued_at = _capture_forecast_v2_host_utc(
                owner="forecast decision import verification completion",
                not_before=(
                    _parse_utc(
                        _required_string(ledger, "inventory_completed_at_utc"),
                        owner="baseline inventory completion",
                    ),
                ),
            )
            valid_until = (
                (
                    _parse_utc(issued_at, owner="forecast decision import completion")
                    + MAX_S1_VALIDITY
                )
                .isoformat(timespec="microseconds")
                .replace("+00:00", "Z")
            )
            ready_forecast = build_forecast_v2(
                context[0],
                decided_ledger,
                context[2],
                approval_roster=context[5],
                approval_roster_digest_value=context[6],
                issued_at=issued_at,
                valid_until=valid_until,
                trusted_time_basis=(
                    "maintainer-trusted host UTC; Windows Time attestation unavailable; "
                    "OpenSSH SSHSIG carries no timestamp"
                ),
            )
            imported_targets = {
                "docs/governance/v1/delivery-forecast.authoring-ledger.json": decided_ledger,
                "docs/governance/v1/delivery-forecast.json": ready_forecast,
            }
            validate_targets(context, imported_targets)
            artifact = _build_forecast_v2_import_artifact(
                artifact_format=("agent-assure-delivery-forecast-decision-signature-import/2"),
                authorization_effect="verified_decision_targets_may_be_installed",
                plan_digest=expected_plan_digest,
                targets=imported_targets,
                domain=FORECAST_DECISION_IMPORT_V2_DOMAIN,
            )
            _write_new_private_json(
                stable_import_path,
                artifact,
                owner="forecast decision import artifact",
            )
            expected_next_payloads = {
                relative: _render_json_bytes(record)
                for relative, record in imported_targets.items()
            }
        else:
            validate_targets(context, imported_targets)

        target_records = {
            repository_root / relative: record for relative, record in imported_targets.items()
        }
        _install_acceptance_targets(
            repository_root,
            target_records,
            plan_digest=expected_plan_digest,
            expected_prior_evidence=prior,
        )
        all_next, _ = _acceptance_target_payload_state(
            repository_root,
            expected_next_payloads,
        )
        if not all_next:
            raise GovernanceError("forecast decision install postcondition failed")
        _verify_plan_sources_after_target_install(
            repository_root,
            plan,
            installed_target_paths=relative_targets,
        )
        post_context = _load_forecast_v2_workspace(
            repository_root=repository_root,
            governance_root=governance_root,
            roadmap_path=roadmap_path,
            allow_pending=True,
        )
        decided_ledger = imported_targets[
            "docs/governance/v1/delivery-forecast.authoring-ledger.json"
        ]
        ready_forecast = imported_targets["docs/governance/v1/delivery-forecast.json"]
        if post_context[4] != decided_ledger:
            raise GovernanceError("forecast decision post-install validation changed")
        return finish(decided_ledger, ready_forecast, idempotent_recovery=False)


@_require_frozen_runtime
@_guard_acceptance_reader
def forecast_v2_signature_plan(args: argparse.Namespace) -> int:
    repository_root = Path(cast(str, args.repository_root)).resolve()
    governance_root = Path(cast(str, args.governance_dir)).resolve()
    roadmap_path = Path(cast(str, args.roadmap)).resolve()
    snapshot, _catalog, registry, _baseline, ledger, roster, roster_digest = (
        _load_forecast_v2_workspace(
            repository_root=repository_root,
            governance_root=governance_root,
            roadmap_path=roadmap_path,
            allow_pending=True,
        )
    )
    ready = _read_json(governance_root / "delivery-forecast.json")
    if ready.get("forecast_status") != "ready_for_signature":
        raise GovernanceError("forecast must have an imported batch decision before signing")
    issue_time, expiry_time = _validate_validity_interval(
        _required_string(ready, "issued_at_utc"),
        _required_string(ready, "valid_until_utc"),
        owner="forecast signature plan",
    )
    claim_preparation_started_at = _capture_forecast_v2_host_utc(
        owner="claim preparation start observation",
        not_before=(issue_time,),
        before=expiry_time,
    )
    candidate = build_forecast_v2(
        snapshot,
        ledger,
        registry,
        approval_roster=roster,
        approval_roster_digest_value=roster_digest,
        issued_at=_required_string(ready, "issued_at_utc"),
        valid_until=_required_string(ready, "valid_until_utc"),
        trusted_time_basis=_required_string(ready, "trusted_time_basis"),
        accepted_candidate=True,
    )
    producer = copy.deepcopy(
        _as_object(candidate.get("signature_envelope"), owner="producer envelope")
    )
    producer["status"] = "signed"
    receipt = _as_object(candidate.get("acceptance_receipt"), owner="acceptance receipt")
    acceptance = copy.deepcopy(
        _as_object(receipt.get("signature_envelope"), owner="acceptance envelope")
    )
    acceptance["status"] = "signed"
    claims = {
        "producer.claim": _signature_claim_bytes_v2(producer),
        "acceptance-receipt.claim": _signature_claim_bytes_v2(acceptance),
    }
    source_paths = _forecast_v2_source_paths(repository_root, governance_root, roadmap_path)
    projection = {
        "format": "agent-assure-delivery-forecast-final-signature-plan/2",
        "spec_revision": SPEC_REVISION,
        "authorization_effect": "none_until_both_signatures_verify",
        "time_evidence": {
            "claim_preparation_started_at_utc": claim_preparation_started_at,
            "clock_basis": "maintainer_host_utc_externally_unattested",
            "sshsig_timestamp_capability": "none",
            "actual_signature_time_claimed": False,
            "import_verification_semantics": (
                "internally_captured_completion_observation_must_be_not_before_claim_"
                "preparation_start_and_within_forecast_validity"
            ),
        },
        "candidate": candidate,
        "claims": [
            {
                "claim_id": name.removesuffix(".claim"),
                "claim_file": name,
                "claim_size_bytes": len(payload),
                "claim_sha256": raw_digest(payload),
            }
            for name, payload in claims.items()
        ],
        "source_files": [
            _source_file_evidence(repository_root, path)
            for path in sorted(source_paths, key=lambda value: _utf8_sort_key(str(value)))
        ],
    }
    plan = {
        **projection,
        "plan_digest": domain_digest(FORECAST_SIGNATURE_PLAN_V2_DOMAIN, projection),
    }
    plan_directory = _corrective_private_acceptance_path(
        repository_root,
        cast(str, args.plan_dir),
        owner="forecast-v2 final signature plan",
        must_exist=False,
    )
    _write_forecast_v2_plan(plan_directory, plan=plan, claims=claims)
    print(
        json.dumps(
            {
                "actual_signature_time_claimed": False,
                "acceptance_receipt_digest": receipt["receipt_digest"],
                "claim_preparation_started_at_utc": claim_preparation_started_at,
                "plan_digest": plan["plan_digest"],
                "plan_directory": str(plan_directory.resolve()),
                "producer_record_digest": candidate["record_digest"],
                "sign_commands": [
                    _forecast_v2_sign_command(plan_directory / "producer.claim"),
                    _forecast_v2_sign_command(plan_directory / "acceptance-receipt.claim"),
                ],
            },
            sort_keys=True,
        )
    )
    return 0


@_require_frozen_runtime
def forecast_v2_signature_import(args: argparse.Namespace) -> int:
    """Verify, persist, recover, and atomically install both final signatures."""

    repository_root = Path(cast(str, args.repository_root)).resolve()
    governance_root = Path(cast(str, args.governance_dir)).resolve()
    roadmap_path = Path(cast(str, args.roadmap)).resolve()
    plan_directory = _corrective_private_acceptance_path(
        repository_root,
        cast(str, args.plan_dir),
        owner="forecast-v2 final signature plan",
        must_exist=True,
    )
    stable_import_path = plan_directory / "verified-final-signature-import.json"
    base_names = {
        "plan.json",
        "producer.claim",
        "producer.claim.sig",
        "acceptance-receipt.claim",
        "acceptance-receipt.claim.sig",
    }
    observed_names = {entry.name for entry in plan_directory.iterdir()}
    if observed_names not in (base_names, base_names | {stable_import_path.name}):
        raise GovernanceError("forecast-v2 final signature plan has unexpected files")
    _require_forecast_v2_plan_files(plan_directory, observed_names)
    expected_plan_digest = cast(str, args.expected_plan_digest)
    plan = _read_forecast_v2_plan(
        plan_directory,
        expected_format="agent-assure-delivery-forecast-final-signature-plan/2",
        domain=FORECAST_SIGNATURE_PLAN_V2_DOMAIN,
        expected_digest=expected_plan_digest,
    )
    _require_forecast_v2_plan_source_set(
        repository_root,
        plan,
        expected_paths=_forecast_v2_source_paths(repository_root, governance_root, roadmap_path),
    )
    relative_target = "docs/governance/v1/delivery-forecast.json"
    relative_targets = {relative_target}
    prior = _acceptance_plan_target_prior_evidence(
        plan,
        expected_target_paths=relative_targets,
    )
    time_evidence = _as_object(plan.get("time_evidence"), owner="signature time evidence")
    if time_evidence != {
        "claim_preparation_started_at_utc": time_evidence.get("claim_preparation_started_at_utc"),
        "clock_basis": "maintainer_host_utc_externally_unattested",
        "sshsig_timestamp_capability": "none",
        "actual_signature_time_claimed": False,
        "import_verification_semantics": (
            "internally_captured_completion_observation_must_be_not_before_claim_"
            "preparation_start_and_within_forecast_validity"
        ),
    }:
        raise GovernanceError("forecast signature time semantics changed")
    prepared = _parse_utc(
        _required_string(time_evidence, "claim_preparation_started_at_utc"),
        owner="claim preparation start observation",
    )
    if stable_import_path.exists() or stable_import_path.is_symlink():
        if not stable_import_path.is_file() or stable_import_path.is_symlink():
            raise GovernanceError("forecast final signature import artifact is not regular")
        _artifact, imported_targets = _read_forecast_v2_import_artifact(
            stable_import_path,
            expected_format="agent-assure-delivery-forecast-final-signature-import/2",
            expected_authorization_effect="verified_final_forecast_may_be_installed",
            expected_plan_digest=expected_plan_digest,
            expected_target_paths=relative_targets,
            domain=FORECAST_SIGNATURE_IMPORT_V2_DOMAIN,
        )
    else:
        imported_targets = {}
    expected_next_payloads = {
        relative: _render_json_bytes(record) for relative, record in imported_targets.items()
    }

    def validate_candidate(
        context: tuple[
            RoadmapSnapshot,
            dict[str, Any],
            dict[str, Any],
            dict[str, Any],
            dict[str, Any],
            dict[str, Any],
            str,
        ],
        ready: Mapping[str, Any],
        candidate: Mapping[str, Any],
        *,
        require_signed: bool,
    ) -> None:
        snapshot, _catalog, registry, _baseline, ledger, roster, roster_digest = context
        expected_candidate = build_forecast_v2(
            snapshot,
            ledger,
            registry,
            approval_roster=roster,
            approval_roster_digest_value=roster_digest,
            issued_at=_required_string(ready, "issued_at_utc"),
            valid_until=_required_string(ready, "valid_until_utc"),
            trusted_time_basis=_required_string(ready, "trusted_time_basis"),
            accepted_candidate=True,
        )
        normalized = copy.deepcopy(dict(candidate))
        normalized["signature_envelope"] = copy.deepcopy(expected_candidate["signature_envelope"])
        normalized_receipt = _as_object(
            normalized.get("acceptance_receipt"), owner="accepted forecast receipt"
        )
        expected_receipt = _as_object(
            expected_candidate.get("acceptance_receipt"), owner="expected forecast receipt"
        )
        normalized_receipt["signature_envelope"] = copy.deepcopy(
            expected_receipt["signature_envelope"]
        )
        if normalized != expected_candidate:
            raise GovernanceError("accepted forecast import target changed after preparation")
        if not require_signed:
            return
        validate_forecast_v2(
            snapshot,
            ledger,
            registry,
            candidate,
            _read_json(governance_root / "delivery-forecast.schema.json"),
            approval_roster=roster,
            approval_roster_digest_value=roster_digest,
            allow_pending=False,
        )

    def finish(candidate: Mapping[str, Any], *, idempotent_recovery: bool) -> int:
        producer_evidence = _as_object(
            _as_object(
                candidate.get("signature_envelope"), owner="producer signature envelope"
            ).get("verification_evidence"),
            owner="producer signature verification evidence",
        )
        print(
            json.dumps(
                {
                    "acceptance_receipt_digest": _as_object(
                        candidate.get("acceptance_receipt"), owner="acceptance receipt"
                    )["receipt_digest"],
                    "actual_signature_time_claimed": False,
                    "forecast_status": "accepted",
                    "idempotent_recovery": idempotent_recovery,
                    "import_verification_completed_at_utc": producer_evidence[
                        "import_verification_completed_at_utc"
                    ],
                    "import_verification_started_at_utc": producer_evidence[
                        "import_verification_started_at_utc"
                    ],
                    "record_digest": candidate["record_digest"],
                    "result": "both_timestamp_free_signatures_verified_and_installed",
                },
                sort_keys=True,
            )
        )
        return 0

    with _acceptance_import_lock(repository_root):
        journal = _acceptance_transaction_journal(repository_root)
        if (journal.exists() or journal.is_symlink()) and not imported_targets:
            raise GovernanceError(
                "forecast final signature recovery requires its verified import artifact"
            )
        if imported_targets:
            _recover_acceptance_transaction(
                repository_root,
                expected_plan_digest=expected_plan_digest,
                expected_prior_evidence=prior,
                expected_next_payloads=expected_next_payloads,
            )
            all_next, any_next = _acceptance_target_payload_state(
                repository_root,
                expected_next_payloads,
            )
            if all_next:
                _verify_plan_sources_after_target_install(
                    repository_root,
                    plan,
                    installed_target_paths=relative_targets,
                )
                current = _load_forecast_v2_workspace(
                    repository_root=repository_root,
                    governance_root=governance_root,
                    roadmap_path=roadmap_path,
                    allow_pending=False,
                )
                candidate = _read_json(repository_root / relative_target)
                if candidate != imported_targets[relative_target]:
                    raise GovernanceError("installed accepted forecast changed")
                # The accepted loader proves all cryptographic and semantic
                # invariants; bind its ledger and the target bytes once more.
                if current[4].get("decision_evidence") is None:
                    raise GovernanceError("accepted forecast lost its decision predecessor")
                still_all_next, _ = _acceptance_target_payload_state(
                    repository_root,
                    expected_next_payloads,
                )
                if not still_all_next:
                    raise GovernanceError("accepted forecast changed during validation")
                return finish(candidate, idempotent_recovery=True)
            if any_next:
                raise GovernanceError(
                    "forecast signature has a partial install without recovery evidence"
                )

        _verify_forecast_v2_plan_sources(
            repository_root,
            plan,
            expected_paths=_forecast_v2_source_paths(
                repository_root, governance_root, roadmap_path
            ),
        )
        context = _load_forecast_v2_workspace(
            repository_root=repository_root,
            governance_root=governance_root,
            roadmap_path=roadmap_path,
            allow_pending=True,
        )
        ready = _read_json(governance_root / "delivery-forecast.json")
        if ready.get("forecast_status") != "ready_for_signature":
            raise GovernanceError("forecast is not ready for its final signatures")
        issue_time, expiry_time = _validate_validity_interval(
            _required_string(ready, "issued_at_utc"),
            _required_string(ready, "valid_until_utc"),
            owner="forecast signature import",
        )
        if not imported_targets:
            import_verification_started_at = _canonical_host_utc_now()
            import_started = _parse_utc(
                import_verification_started_at,
                owner="import verification start observation",
            )
            if import_started < prepared or not issue_time <= import_started < expiry_time:
                raise GovernanceError(
                    "import verification start must follow claim preparation within validity"
                )
            candidate = copy.deepcopy(
                _as_object(plan.get("candidate"), owner="accepted forecast candidate")
            )
            validate_candidate(context, ready, candidate, require_signed=False)
            descriptors = {
                _required_string(
                    _as_object(value, owner="signature claim"), "claim_id"
                ): _as_object(value, owner="signature claim")
                for value in _as_array(plan.get("claims"), owner="signature claims")
            }
            if set(descriptors) != {"producer", "acceptance-receipt"}:
                raise GovernanceError("final signature plan must contain exactly two claims")
            envelopes = {
                "producer": _as_object(
                    candidate.get("signature_envelope"), owner="producer signature envelope"
                ),
                "acceptance-receipt": _as_object(
                    _as_object(candidate.get("acceptance_receipt"), owner="acceptance receipt").get(
                        "signature_envelope"
                    ),
                    owner="acceptance receipt signature envelope",
                ),
            }
            expected_subject_digests = {
                "producer": _required_string(candidate, "record_digest"),
                "acceptance-receipt": _required_string(
                    _as_object(candidate.get("acceptance_receipt"), owner="acceptance receipt"),
                    "receipt_digest",
                ),
            }
            for claim_id in ("producer", "acceptance-receipt"):
                descriptor = descriptors[claim_id]
                claim_path = plan_directory / _required_string(descriptor, "claim_file")
                payload = claim_path.read_bytes()
                envelope = envelopes[claim_id]
                envelope["status"] = "signed"
                if (
                    len(payload) != _required_integer(descriptor, "claim_size_bytes")
                    or raw_digest(payload) != descriptor.get("claim_sha256")
                    or payload != _signature_claim_bytes_v2(envelope)
                ):
                    raise GovernanceError(f"{claim_id} claim changed after preparation")
                signature_path = claim_path.with_name(claim_path.name + ".sig")
                envelope["signature"] = base64.b64encode(
                    _canonical_sshsig_armor(signature_path.read_bytes())
                ).decode("ascii")
                _validate_signature_envelope_v2(
                    envelope,
                    expected_person_id="acblabs",
                    expected_role=(
                        "technical_lead" if claim_id == "producer" else "repository_maintainer"
                    ),
                    expected_subject_digest=expected_subject_digests[claim_id],
                    allow_pending=False,
                    owner=f"forecast {claim_id} preliminary import",
                    expected_verification_evidence=None,
                )
            import_verification_completed_at = _capture_forecast_v2_host_utc(
                owner="import verification completion observation",
                not_before=(import_started,),
                before=expiry_time,
            )
            verification_evidence = _forecast_v2_signature_import_evidence(
                signature_plan_digest=expected_plan_digest,
                claim_preparation_started_at_utc=_required_string(
                    time_evidence, "claim_preparation_started_at_utc"
                ),
                import_verification_started_at_utc=import_verification_started_at,
                import_verification_completed_at_utc=import_verification_completed_at,
                issued_at_utc=_required_string(ready, "issued_at_utc"),
                valid_until_utc=_required_string(ready, "valid_until_utc"),
            )
            for envelope in envelopes.values():
                envelope["verification_evidence"] = copy.deepcopy(verification_evidence)
            validate_candidate(context, ready, candidate, require_signed=True)
            imported_targets = {relative_target: candidate}
            artifact = _build_forecast_v2_import_artifact(
                artifact_format="agent-assure-delivery-forecast-final-signature-import/2",
                authorization_effect="verified_final_forecast_may_be_installed",
                plan_digest=expected_plan_digest,
                targets=imported_targets,
                domain=FORECAST_SIGNATURE_IMPORT_V2_DOMAIN,
            )
            _write_new_private_json(
                stable_import_path,
                artifact,
                owner="forecast final signature import artifact",
            )
            expected_next_payloads = {relative_target: _render_json_bytes(candidate)}
        else:
            candidate = imported_targets[relative_target]
            validate_candidate(context, ready, candidate, require_signed=True)

        _install_acceptance_targets(
            repository_root,
            {governance_root / "delivery-forecast.json": candidate},
            plan_digest=expected_plan_digest,
            expected_prior_evidence=prior,
        )
        all_next, _ = _acceptance_target_payload_state(
            repository_root,
            expected_next_payloads,
        )
        if not all_next:
            raise GovernanceError("forecast final signature install postcondition failed")
        _verify_plan_sources_after_target_install(
            repository_root,
            plan,
            installed_target_paths=relative_targets,
        )
        _load_forecast_v2_workspace(
            repository_root=repository_root,
            governance_root=governance_root,
            roadmap_path=roadmap_path,
            allow_pending=False,
        )
        return finish(candidate, idempotent_recovery=False)


def _corrective_v2_source_paths(
    repository_root: Path,
    roadmap_path: Path,
    *,
    extra_paths: Sequence[Path] = (),
) -> list[Path]:
    """Return every mutable source whose bytes a corrective plan consumes."""

    governance_root = (repository_root / "docs/governance/v1").resolve()
    paths = set(_forecast_v2_source_paths(repository_root, governance_root, roadmap_path))
    relative_paths = {
        path
        for ticket_id in ("V1-BASE-01", "V1-BOOT-01")
        for path, _kind in _completion_review_paths_v2(ticket_id)
    }
    relative_paths.update(
        {
            "docs/governance/v1/approval-roster.json",
            "docs/governance/v1/approval-roster.schema.json",
            "docs/governance/v1/completion-report-v1-base-01.md",
            "docs/governance/v1/completion-report-v1-boot-01.md",
            *S1_CORRECTIVE_CLOSURE_PATHS,
        }
    )
    paths.update(repository_root / path for path in relative_paths)
    paths.update(path.resolve() for path in extra_paths)
    return sorted(paths, key=lambda value: _utf8_sort_key(str(value)))


def _require_corrective_v2_plan_source_set(
    repository_root: Path,
    roadmap_path: Path,
    plan: Mapping[str, Any],
    *,
    expected_private_extra_count: int,
) -> None:
    """Require the full corrective trust/review basis plus exact private inputs."""

    root = repository_root.resolve()
    required = {
        path.resolve().relative_to(root).as_posix()
        for path in _corrective_v2_source_paths(root, roadmap_path)
    }
    observed = [
        _required_string(
            _as_object(value, owner="corrective plan source file"),
            "path",
        )
        for value in _as_array(plan.get("source_files"), owner="corrective plan source files")
    ]
    if len(observed) != len(set(observed)):
        raise GovernanceError("corrective plan repeats a source file")
    observed_set = set(observed)
    extras = observed_set - required
    if not required <= observed_set or len(extras) != expected_private_extra_count:
        raise GovernanceError("corrective plan source set is not exact")
    for relative in extras:
        _require_corrective_local_only_path(
            relative,
            owner="corrective private plan source",
        )


_FORECAST_V2_FINAL_DOC_START: Final = "<!-- agent-assure:forecast-v2-final:start -->"
_FORECAST_V2_FINAL_DOC_END: Final = "<!-- agent-assure:forecast-v2-final:end -->"


def _forecast_v2_final_documentation_block(
    ledger: Mapping[str, Any], forecast: Mapping[str, Any]
) -> str:
    if ledger.get("decision_evidence") is None:
        raise GovernanceError("final forecast documentation requires imported human decisions")
    if forecast.get("forecast_status") != "accepted":
        raise GovernanceError("final forecast documentation requires an accepted forecast")
    ledger_digest = _required_string(ledger, "ledger_digest")
    forecast_digest = _required_string(forecast, "record_digest")
    if (
        SHA256_PATTERN.fullmatch(ledger_digest) is None
        or SHA256_PATTERN.fullmatch(forecast_digest) is None
    ):
        raise GovernanceError("final forecast documentation digest is not canonical")
    return "\n".join(
        (
            _FORECAST_V2_FINAL_DOC_START,
            (
                "- Generation-2 authoring ledger status: `human_decisions_imported`; "
                f"digest: `{ledger_digest}`."
            ),
            (f"- Generation-2 delivery forecast status: `accepted`; digest: `{forecast_digest}`."),
            _FORECAST_V2_FINAL_DOC_END,
        )
    )


def _validate_forecast_v2_final_documentation(
    repository_root: Path,
    *,
    ledger: Mapping[str, Any],
    forecast: Mapping[str, Any],
) -> None:
    """Require both governed documents to name the installed final artifacts."""

    expected = _forecast_v2_final_documentation_block(ledger, forecast)
    for relative in (
        "docs/governance/v1/README.md",
        "docs/adr/0016-v1-repository-map.md",
    ):
        path = repository_root / relative
        if not path.is_file() or path.is_symlink():
            raise GovernanceError(f"final forecast documentation is not a regular file: {relative}")
        text = path.read_text(encoding="utf-8")
        if (
            text.count(_FORECAST_V2_FINAL_DOC_START) != 1
            or text.count(_FORECAST_V2_FINAL_DOC_END) != 1
            or expected not in text
        ):
            raise GovernanceError(
                "final accepted ledger/forecast status and digest are not documented "
                f"exactly in {relative}"
            )


@_require_frozen_runtime
@_guard_acceptance_reader
def forecast_v2_documentation_check(args: argparse.Namespace) -> int:
    """Validate final forecast records and their exact pre-R2 documentation."""

    repository_root = Path(cast(str, args.repository_root)).resolve()
    governance_root = Path(cast(str, args.governance_dir)).resolve()
    roadmap_path = Path(cast(str, args.roadmap)).resolve()
    snapshot, _catalog, registry, _baseline, ledger, roster, roster_digest = (
        _load_forecast_v2_workspace(
            repository_root=repository_root,
            governance_root=governance_root,
            roadmap_path=roadmap_path,
            allow_pending=False,
        )
    )
    forecast = _read_json(governance_root / "delivery-forecast.json")
    validate_forecast_v2(
        snapshot,
        ledger,
        registry,
        forecast,
        _read_json(governance_root / "delivery-forecast.schema.json"),
        approval_roster=roster,
        approval_roster_digest_value=roster_digest,
        allow_pending=False,
    )
    _validate_forecast_v2_final_documentation(
        repository_root,
        ledger=ledger,
        forecast=forecast,
    )
    print(
        json.dumps(
            {
                "forecast_status": forecast["forecast_status"],
                "ledger_digest": ledger["ledger_digest"],
                "record_digest": forecast["record_digest"],
                "result": "valid_final_forecast_documentation",
            },
            sort_keys=True,
        )
    )
    return 0


def _load_corrective_v2_workspace(
    *,
    repository_root: Path,
    governance_root: Path,
    roadmap_path: Path,
    result_commit: str,
    allow_materialized_closure: bool = False,
) -> dict[str, Any]:
    """Validate clean R2 and load the complete generation-2 closure context."""

    if allow_materialized_closure:
        state = _post_r2_repository_state(repository_root)
        if state.get("head_commit") != result_commit:
            raise GovernanceError("materialized corrective closure is not based on exact R2")
        _validate_corrective_closure_worktree(
            repository_root,
            result_commit=result_commit,
        )
    else:
        _require_clean_corrective_result_checkout(
            repository_root,
            result_commit=result_commit,
            owner="generation-2 corrective closure workflow",
        )
        _validate_generation_1_closure_placeholders(repository_root, governance_root)
    snapshot, _catalog, _registry, baseline, ledger, _roster, workspace_roster_digest = (
        _load_forecast_v2_workspace(
            repository_root=repository_root,
            governance_root=governance_root,
            roadmap_path=roadmap_path,
            allow_pending=False,
        )
    )
    roster = _read_json(governance_root / "approval-roster.json")
    roster_digest, person_id = validate_approval_roster(
        snapshot,
        roster,
        _read_json(governance_root / "approval-roster.schema.json"),
        allow_pending=False,
    )
    if roster_digest != workspace_roster_digest:
        raise GovernanceError("corrective closure approval roster digest changed")
    authorization = _load_corrective_authorization_from_result(
        snapshot,
        repository_root,
        result_commit,
    )
    change_control = _corrective_change_control(
        repository_root,
        result_commit=result_commit,
        corrective_authorization=authorization,
    )
    forecast = _read_json(governance_root / "delivery-forecast.json")
    if _forecast_binding_v2(forecast, require_accepted=True)["forecast_status"] != ("accepted"):
        raise GovernanceError("corrective closure forecast is not accepted")
    return {
        "snapshot": snapshot,
        "baseline": baseline,
        "ledger": ledger,
        "roster": roster,
        "roster_digest": roster_digest,
        "person_id": person_id,
        "authorization": authorization,
        "change_control": change_control,
        "forecast": forecast,
    }


def _write_corrective_v2_plan(
    plan_directory: Path,
    *,
    plan: Mapping[str, Any],
    claims: Mapping[str, bytes],
) -> None:
    if plan_directory.exists() or plan_directory.is_symlink():
        raise GovernanceError("corrective signature plan directory already exists")
    plan_directory.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(
        tempfile.mkdtemp(prefix=f"{plan_directory.name}-staging-", dir=plan_directory.parent)
    )
    try:
        (temporary / "plan.json").write_bytes(_render_json_bytes(plan))
        for name, payload in claims.items():
            if Path(name).name != name or not name.endswith(".claim"):
                raise GovernanceError("corrective plan claim name is not canonical")
            (temporary / name).write_bytes(payload)
        temporary.replace(plan_directory)
    except OSError as exc:
        raise GovernanceError(f"unable to write corrective signature plan: {exc}") from exc
    finally:
        if temporary.exists():
            shutil.rmtree(temporary, ignore_errors=True)


def _read_corrective_v2_plan(
    plan_directory: Path,
    *,
    expected_format: str,
    domain: str,
    expected_digest: str,
    expected_fields: set[str],
) -> dict[str, Any]:
    if SHA256_PATTERN.fullmatch(expected_digest) is None:
        raise GovernanceError("expected corrective plan digest is not canonical SHA-256")
    plan = _read_json(plan_directory / "plan.json")
    if set(plan) != expected_fields | {"plan_digest"}:
        raise GovernanceError("corrective signature plan has missing or unexpected fields")
    if (
        plan.get("format") != expected_format
        or plan.get("spec_revision") != SPEC_REVISION
        or plan.get("authorization_effect") != "none_until_verified_import"
    ):
        raise GovernanceError("corrective signature plan identity changed")
    projection = {key: value for key, value in plan.items() if key != "plan_digest"}
    calculated = domain_digest(domain, projection)
    if plan.get("plan_digest") != calculated or calculated != expected_digest:
        raise GovernanceError("corrective signature plan differs from the human-confirmed digest")
    return plan


def _require_corrective_v2_plan_files(
    plan_directory: Path,
    *,
    expected_names: set[str],
) -> None:
    if not plan_directory.is_dir() or plan_directory.is_symlink():
        raise GovernanceError("corrective signature plan must be a regular directory")
    observed = {entry.name for entry in plan_directory.iterdir()}
    if observed != expected_names:
        raise GovernanceError("corrective signature plan has missing or unexpected files")
    for name in expected_names:
        path = plan_directory / name
        if not path.is_file() or path.is_symlink():
            raise GovernanceError("corrective signature plan contains a non-regular file")


def _corrective_v2_claim_descriptor(
    *,
    claim_id: str,
    target_path: str,
    target_record: Mapping[str, Any],
) -> tuple[dict[str, Any], bytes]:
    if re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", claim_id) is None:
        raise GovernanceError(f"invalid corrective claim id: {claim_id}")
    envelope = _as_object(
        target_record.get("signature_envelope"),
        owner=f"{claim_id} signature envelope",
    )
    subject_field = (
        "receipt_digest"
        if target_record.get("format") == "agent-assure-ticket-completion-receipt/2"
        else "bundle_digest"
    )
    subject_digest = _required_string(target_record, subject_field)
    if envelope != _pending_signature_v2(
        _required_string(target_record, "issuer_person_id"),
        _required_string(target_record, "issuer_role"),
        subject_digest,
    ):
        raise GovernanceError(f"{claim_id} target envelope is not the exact pending v2 shape")
    payload = _signature_claim_bytes_v2(envelope)
    claim_file = f"{claim_id}.claim"
    return (
        {
            "claim_id": claim_id,
            "target_path": target_path,
            "claim_file": claim_file,
            "claim_size_bytes": len(payload),
            "claim_sha256": raw_digest(payload),
            "signer_person_id": _required_string(envelope, "signer_person_id"),
            "signer_role": _required_string(envelope, "signer_role"),
            "subject_digest": subject_digest,
        },
        payload,
    )


def _corrective_v2_plan_targets(plan: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    targets: dict[str, dict[str, Any]] = {}
    for value in _as_array(plan.get("targets"), owner="corrective plan targets"):
        target = _as_object(value, owner="corrective plan target")
        if set(target) != {"path", "record"}:
            raise GovernanceError("corrective plan target descriptor is malformed")
        path = _required_string(target, "path")
        if path in targets:
            raise GovernanceError("corrective plan repeats a target path")
        targets[path] = copy.deepcopy(_as_object(target.get("record"), owner=path))
    return targets


def _materialize_corrective_v2_plan_targets(
    plan_directory: Path,
    plan: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    targets = _corrective_v2_plan_targets(plan)
    expected_signature_paths: set[Path] = set()
    observed_claim_ids: set[str] = set()
    for value in _as_array(plan.get("claims"), owner="corrective plan claims"):
        claim = _as_object(value, owner="corrective plan claim")
        required = {
            "claim_id",
            "target_path",
            "claim_file",
            "claim_size_bytes",
            "claim_sha256",
            "signer_person_id",
            "signer_role",
            "subject_digest",
        }
        if set(claim) != required:
            raise GovernanceError("corrective plan claim descriptor is malformed")
        claim_id = _required_string(claim, "claim_id")
        if claim_id in observed_claim_ids:
            raise GovernanceError("corrective plan repeats a claim id")
        observed_claim_ids.add(claim_id)
        target_path = _required_string(claim, "target_path")
        if target_path not in targets:
            raise GovernanceError("corrective claim targets a missing record")
        claim_name = _required_string(claim, "claim_file")
        if Path(claim_name).name != claim_name or claim_name != f"{claim_id}.claim":
            raise GovernanceError("corrective claim file name is not canonical")
        claim_path = plan_directory / claim_name
        payload = claim_path.read_bytes()
        if len(payload) != _required_integer(claim, "claim_size_bytes") or raw_digest(
            payload
        ) != claim.get("claim_sha256"):
            raise GovernanceError(f"corrective claim changed after preparation: {claim_id}")
        record = targets[target_path]
        envelope = _as_object(
            record.get("signature_envelope"),
            owner=f"{claim_id} signature envelope",
        )
        if envelope.get("status") != "pending_human_signature":
            raise GovernanceError("corrective plan target signature is no longer pending")
        if payload != _signature_claim_bytes_v2(envelope):
            raise GovernanceError("corrective claim no longer matches its target envelope")
        signature_path = plan_directory / f"{claim_name}.sig"
        expected_signature_paths.add(signature_path.resolve())
        if not signature_path.is_file() or signature_path.is_symlink():
            raise GovernanceError(f"missing human SSHSIG: {signature_path.name}")
        envelope["status"] = "signed"
        envelope["signature"] = base64.b64encode(
            _canonical_sshsig_armor(signature_path.read_bytes())
        ).decode("ascii")
        _validate_signature_envelope_v2(
            envelope,
            expected_person_id=_required_string(claim, "signer_person_id"),
            expected_role=_required_string(claim, "signer_role"),
            expected_subject_digest=_required_string(claim, "subject_digest"),
            allow_pending=False,
            owner=claim_id,
        )
    actual_signature_paths = {path.resolve() for path in plan_directory.glob("*.claim.sig")}
    if actual_signature_paths != expected_signature_paths:
        raise GovernanceError("corrective plan contains missing or unexpected SSHSIG files")
    return targets


def _validate_corrective_receipt_plan_candidate(
    snapshot: RoadmapSnapshot,
    record: Mapping[str, Any],
    *,
    repository_root: Path,
    ticket_id: str,
    roster: Mapping[str, Any],
    person_id: str,
    result_commit: str,
    corrective_authorization: Mapping[str, Any],
    forecast: Mapping[str, Any],
) -> None:
    if record.get("receipt_status") != "accepted_for_development":
        raise GovernanceError(f"{ticket_id} corrective plan is not an acceptance candidate")
    post_value = record.get("post_result_verification")
    post_evidence = (
        None
        if post_value is None
        else _as_object(post_value, owner=f"{ticket_id} post-R2 suite evidence")
    )
    expected = _ticket_completion_receipt_v2_projection(
        snapshot,
        repository_root=repository_root,
        ticket_id=ticket_id,
        roster=roster,
        person_id=person_id,
        result_commit=result_commit,
        corrective_authorization=corrective_authorization,
        forecast=forecast,
        claim_prepared_at=_required_string(record, "claim_prepared_at_utc"),
        status="accepted_for_development",
        post_result_verification=post_evidence,
    )
    if _ticket_receipt_projection(record) != expected:
        raise GovernanceError(f"{ticket_id} corrective plan candidate changed")
    digest = domain_digest(TICKET_RECEIPT_V2_DOMAIN, expected)
    if record.get("receipt_digest") != digest:
        raise GovernanceError(f"{ticket_id} corrective plan digest mismatch")
    if record.get("signature_envelope") != _pending_signature_v2(
        person_id,
        "repository_maintainer",
        digest,
    ):
        raise GovernanceError(f"{ticket_id} corrective plan envelope changed")
    if record.get("signature_import_evidence") != _pending_signature_import_evidence():
        raise GovernanceError(f"{ticket_id} corrective plan import evidence is not pending")


def _corrective_receipt_import_projection(
    *,
    receipt_plan_digest: str,
    result_commit: str,
    bundle_validity: Mapping[str, Any],
    targets: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    expected_paths = {
        "docs/governance/v1/completion-receipt-v1-base-01.json",
        "docs/governance/v1/completion-receipt-v1-boot-01.json",
    }
    if set(targets) != expected_paths:
        raise GovernanceError("corrective receipt import target set is not exact")
    if SHA256_PATTERN.fullmatch(receipt_plan_digest) is None:
        raise GovernanceError("corrective receipt import plan digest is invalid")
    if GIT_COMMIT_PATTERN.fullmatch(result_commit) is None:
        raise GovernanceError("corrective receipt import result commit is invalid")
    validity = dict(bundle_validity)
    if set(validity) != {"issued_at_utc", "valid_until_utc"}:
        raise GovernanceError("corrective receipt import validity is malformed")
    _validate_validity_interval(
        _required_string(validity, "issued_at_utc"),
        _required_string(validity, "valid_until_utc"),
        owner="corrective receipt import bundle validity",
    )
    return {
        "format": "agent-assure-s1-corrective-receipt-signature-import/2",
        "spec_revision": SPEC_REVISION,
        "authorization_effect": "signed_receipts_verified_not_installed",
        "receipt_plan_digest": receipt_plan_digest,
        "result_commit": result_commit,
        "bundle_validity": validity,
        "targets": [
            {"path": path, "record": copy.deepcopy(dict(targets[path]))}
            for path in sorted(targets, key=_utf8_sort_key)
        ],
    }


def _build_corrective_receipt_import_artifact(
    *,
    receipt_plan_digest: str,
    result_commit: str,
    bundle_validity: Mapping[str, Any],
    targets: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    projection = _corrective_receipt_import_projection(
        receipt_plan_digest=receipt_plan_digest,
        result_commit=result_commit,
        bundle_validity=bundle_validity,
        targets=targets,
    )
    return {
        **projection,
        "import_artifact_digest": domain_digest(
            CORRECTIVE_RECEIPT_IMPORT_V2_DOMAIN,
            projection,
        ),
    }


def _read_corrective_receipt_import_artifact(
    path: Path,
    *,
    expected_plan_digest: str,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    artifact = _read_json(path)
    required = {
        "format",
        "spec_revision",
        "authorization_effect",
        "receipt_plan_digest",
        "result_commit",
        "bundle_validity",
        "targets",
        "import_artifact_digest",
    }
    if set(artifact) != required:
        raise GovernanceError("corrective receipt import artifact is malformed")
    if (
        artifact.get("format") != "agent-assure-s1-corrective-receipt-signature-import/2"
        or artifact.get("spec_revision") != SPEC_REVISION
        or artifact.get("authorization_effect") != "signed_receipts_verified_not_installed"
        or artifact.get("receipt_plan_digest") != expected_plan_digest
    ):
        raise GovernanceError("corrective receipt import artifact identity changed")
    targets = _corrective_v2_plan_targets(artifact)
    projection = _corrective_receipt_import_projection(
        receipt_plan_digest=_required_string(artifact, "receipt_plan_digest"),
        result_commit=_required_string(artifact, "result_commit"),
        bundle_validity=_as_object(
            artifact.get("bundle_validity"), owner="corrective bundle validity"
        ),
        targets=targets,
    )
    digest = domain_digest(CORRECTIVE_RECEIPT_IMPORT_V2_DOMAIN, projection)
    if artifact.get("import_artifact_digest") != digest:
        raise GovernanceError("corrective receipt import artifact digest mismatch")
    if {key: value for key, value in artifact.items() if key != "import_artifact_digest"} != (
        projection
    ):
        raise GovernanceError("corrective receipt import artifact differs from its projection")
    return artifact, targets


def _write_new_private_json(path: Path, value: Mapping[str, Any], *, owner: str) -> None:
    """Publish one immutable local JSON artifact without exposing partial bytes.

    The payload is fully flushed in the acceptance staging root and then linked
    into place.  A retry after publication is idempotent only when the target is
    the exact canonical payload; an incomplete or conflicting target fails
    closed and is never removed automatically.
    """

    payload = _render_json_bytes(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        if not path.is_file() or path.is_symlink() or path.read_bytes() != payload:
            raise GovernanceError(f"refusing to overwrite existing {owner}")
        return
    acceptance_root: Path | None = None
    for candidate in path.parents:
        if candidate.name == "s1-acceptance" and candidate.parent.name == ".tmp":
            acceptance_root = candidate
            break
    if acceptance_root is None:
        raise GovernanceError(f"{owner} is outside the acceptance staging root")
    repository_root = acceptance_root.parents[1]
    staging_directory = _resolve_repository_path_without_links(
        repository_root,
        ".tmp/s1-acceptance/correction-v2-atomic-publication",
        owner="corrective atomic publication staging",
    )
    staging_directory.mkdir(parents=True, exist_ok=True)
    try:
        _publish_new_file_atomically(
            path,
            payload,
            staging_directory=staging_directory,
        )
    except FileExistsError as exc:
        if path.is_file() and not path.is_symlink() and path.read_bytes() == payload:
            return
        raise GovernanceError(f"refusing to overwrite existing {owner}") from exc
    except OSError as exc:
        raise GovernanceError(f"unable to write {owner}: {exc}") from exc


def _validate_corrective_bundle_plan_candidate(
    snapshot: RoadmapSnapshot,
    bundle: Mapping[str, Any],
    *,
    repository_root: Path,
    roster: Mapping[str, Any],
    completion_receipts: Mapping[str, Mapping[str, Any]],
    forecast: Mapping[str, Any],
    baseline_observations: Mapping[str, Any],
    corrective_authorization: Mapping[str, Any],
    person_id: str,
    result_commit: str,
) -> None:
    if bundle.get("bundle_status") != "accepted_for_development":
        raise GovernanceError("corrective bundle plan is not an acceptance candidate")
    expected = _governance_bundle_v2_projection(
        snapshot,
        repository_root=repository_root,
        roster=roster,
        completion_receipts=completion_receipts,
        forecast=forecast,
        baseline_observations=baseline_observations,
        corrective_authorization=corrective_authorization,
        person_id=person_id,
        result_commit=result_commit,
        issued_at=_required_string(bundle, "issued_at_utc"),
        valid_until=_required_string(bundle, "valid_until_utc"),
        claim_prepared_at=_required_string(bundle, "claim_prepared_at_utc"),
        status="accepted_for_development",
    )
    if _bundle_projection(bundle) != expected:
        raise GovernanceError("corrective bundle plan candidate changed")
    digest = domain_digest(BUNDLE_V2_DOMAIN, expected)
    if bundle.get("bundle_digest") != digest:
        raise GovernanceError("corrective bundle plan digest mismatch")
    if bundle.get("signature_envelope") != _pending_signature_v2(
        person_id,
        "repository_maintainer",
        digest,
    ):
        raise GovernanceError("corrective bundle plan envelope changed")
    if bundle.get("signature_import_evidence") != _pending_signature_import_evidence():
        raise GovernanceError("corrective bundle plan import evidence is not pending")


def _validate_corrective_closure_worktree(
    repository_root: Path,
    *,
    result_commit: str,
) -> dict[str, str]:
    completed = _run_git(
        repository_root,
        ["diff", "--name-status", "--no-renames", result_commit, "--"],
    )
    if completed.returncode != 0:
        raise GovernanceError("unable to inspect the materialized C2 worktree")
    changes: dict[str, str] = {}
    for raw_line in completed.stdout.decode("utf-8", errors="strict").splitlines():
        fields = raw_line.split("\t")
        if len(fields) != 2 or fields[0] not in {"A", "M"}:
            raise GovernanceError("materialized C2 contains a forbidden change status")
        status, path = fields
        if path in changes:
            raise GovernanceError("materialized C2 repeats a changed path")
        changes[path] = status
    if set(changes) != S1_CORRECTIVE_CLOSURE_PATHS:
        raise GovernanceError("materialized C2 does not change exactly the three closure files")
    untracked = _run_git(
        repository_root,
        ["ls-files", "--others", "--exclude-standard"],
    )
    if untracked.returncode != 0 or untracked.stdout:
        raise GovernanceError("materialized C2 worktree contains unignored untracked files")
    return changes


@_require_frozen_runtime
def corrective_v2_suite_capture(args: argparse.Namespace) -> int:
    """Run and preserve the exact clean-R2 full-suite evidence."""

    repository_root = Path(cast(str, args.repository_root)).resolve()
    governance_root = _governance_root(repository_root, cast(str, args.governance_dir))
    roadmap_path = Path(cast(str, args.roadmap)).resolve()
    result_commit = cast(str, args.result_commit)
    if GIT_COMMIT_PATTERN.fullmatch(result_commit) is None:
        raise GovernanceError("--result-commit must be a full lowercase 40-hex commit ID")
    with _acceptance_import_lock(repository_root):
        journal = _acceptance_transaction_journal(repository_root)
        if journal.exists() or journal.is_symlink():
            raise GovernanceError(
                "post-R2 suite capture cannot start with an incomplete acceptance import"
            )
        context = _load_corrective_v2_workspace(
            repository_root=repository_root,
            governance_root=governance_root,
            roadmap_path=roadmap_path,
            result_commit=result_commit,
        )
    evidence_directory = cast(str, args.evidence_dir)
    record = capture_post_r2_suite_evidence(
        repository_root,
        roadmap_path=roadmap_path,
        result_commit=result_commit,
        corrective_authorization=cast(Mapping[str, Any], context["authorization"]),
        evidence_directory=evidence_directory,
    )
    # Do not hold the acceptance lock while pytest runs: governance tests must
    # be able to acquire it in child processes.  Reacquire it at the boundary
    # and fail closed if a concurrent import began or changed clean R2.
    with _acceptance_import_lock(repository_root):
        journal = _acceptance_transaction_journal(repository_root)
        if journal.exists() or journal.is_symlink():
            raise GovernanceError(
                "post-R2 suite capture ended with an incomplete acceptance import"
            )
        _require_clean_corrective_result_checkout(
            repository_root,
            result_commit=result_commit,
            owner="post-R2 suite capture postcondition",
        )
    evidence_path = _corrective_private_acceptance_path(
        repository_root,
        Path(evidence_directory) / "post-r2-suite-evidence.json",
        owner="post-R2 suite evidence",
        must_exist=True,
    )
    print(
        json.dumps(
            {
                "authorization_effect": "none",
                "evidence_digest": record["evidence_digest"],
                "evidence_path": str(evidence_path),
                "pytest_totals": record["execution"]["pytest_totals"],
                "result": "clean_r2_full_suite_evidence_captured",
                "result_commit": result_commit,
            },
            sort_keys=True,
        )
    )
    return 0


@_require_frozen_runtime
@_guard_acceptance_reader
def corrective_v2_receipt_plan(args: argparse.Namespace) -> int:
    """Prepare the two timestamp-free replacement receipt claims."""

    repository_root = Path(cast(str, args.repository_root)).resolve()
    governance_root = _governance_root(repository_root, cast(str, args.governance_dir))
    roadmap_path = Path(cast(str, args.roadmap)).resolve()
    result_commit = cast(str, args.result_commit)
    if GIT_COMMIT_PATTERN.fullmatch(result_commit) is None:
        raise GovernanceError("--result-commit must be a full lowercase 40-hex commit ID")
    plan_directory = _corrective_private_acceptance_path(
        repository_root,
        cast(str, args.plan_dir),
        owner="corrective receipt signature plan",
        must_exist=False,
    )
    evidence_path = _corrective_private_acceptance_path(
        repository_root,
        cast(str, args.post_r2_evidence),
        owner="post-R2 suite evidence source",
        must_exist=True,
    )
    context = _load_corrective_v2_workspace(
        repository_root=repository_root,
        governance_root=governance_root,
        roadmap_path=roadmap_path,
        result_commit=result_commit,
    )
    _validate_forecast_v2_final_documentation(
        repository_root,
        ledger=cast(Mapping[str, Any], context["ledger"]),
        forecast=cast(Mapping[str, Any], context["forecast"]),
    )
    validate_post_r2_suite_evidence_source(
        evidence_path,
        expected_result_commit=result_commit,
        expected_repository_root=repository_root,
        require_passed=True,
    )
    issued_at = _canonical_host_utc_now()
    valid_until = (
        (_parse_utc(issued_at, owner="corrective bundle validity start") + MAX_S1_VALIDITY)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )
    roster = cast(Mapping[str, Any], context["roster"])
    person_id = cast(str, context["person_id"])
    roster_digest = cast(str, context["roster_digest"])
    receipts = {
        "V1-BASE-01": build_ticket_completion_receipt_v2(
            cast(RoadmapSnapshot, context["snapshot"]),
            repository_root=repository_root,
            ticket_id="V1-BASE-01",
            roster_digest=roster_digest,
            person_id=person_id,
            result_commit=result_commit,
            status="accepted_for_development",
        ),
        "V1-BOOT-01": build_ticket_completion_receipt_v2(
            cast(RoadmapSnapshot, context["snapshot"]),
            repository_root=repository_root,
            ticket_id="V1-BOOT-01",
            roster_digest=roster_digest,
            person_id=person_id,
            result_commit=result_commit,
            post_r2_suite_evidence_path=evidence_path,
            status="accepted_for_development",
        ),
    }
    target_by_ticket = {
        ticket_id: f"docs/governance/v1/completion-receipt-{ticket_id.lower()}.json"
        for ticket_id in receipts
    }
    targets = {target_by_ticket[ticket_id]: record for ticket_id, record in receipts.items()}
    claims: list[dict[str, Any]] = []
    claim_payloads: dict[str, bytes] = {}
    for ticket_id in ("V1-BASE-01", "V1-BOOT-01"):
        _validate_corrective_receipt_plan_candidate(
            cast(RoadmapSnapshot, context["snapshot"]),
            receipts[ticket_id],
            repository_root=repository_root,
            ticket_id=ticket_id,
            roster=roster,
            person_id=person_id,
            result_commit=result_commit,
            corrective_authorization=cast(Mapping[str, Any], context["authorization"]),
            forecast=cast(Mapping[str, Any], context["forecast"]),
        )
        claim_id = f"completion-{ticket_id.removeprefix('V1-').lower()}"
        descriptor, payload = _corrective_v2_claim_descriptor(
            claim_id=claim_id,
            target_path=target_by_ticket[ticket_id],
            target_record=receipts[ticket_id],
        )
        claims.append(descriptor)
        claim_payloads[cast(str, descriptor["claim_file"])] = payload
    source_paths = _corrective_v2_source_paths(
        repository_root,
        roadmap_path,
        extra_paths=(evidence_path,),
    )
    projection = {
        "format": "agent-assure-s1-corrective-receipt-signature-plan/2",
        "spec_revision": SPEC_REVISION,
        "authorization_effect": "none_until_verified_import",
        "result_commit": result_commit,
        "corrective_authorization_claim_digest": CORRECTIVE_KICKOFF_CLAIM_DIGEST,
        "bundle_validity": {
            "issued_at_utc": issued_at,
            "valid_until_utc": valid_until,
        },
        "post_r2_suite_evidence_digest": _required_string(
            _as_object(
                receipts["V1-BOOT-01"].get("post_result_verification"),
                owner="BOOT post-R2 suite evidence",
            ),
            "evidence_digest",
        ),
        "targets": [
            {"path": path, "record": targets[path]} for path in sorted(targets, key=_utf8_sort_key)
        ],
        "claims": claims,
        "source_files": [_source_file_evidence(repository_root, path) for path in source_paths],
    }
    plan = {
        **projection,
        "plan_digest": domain_digest(CORRECTIVE_RECEIPT_PLAN_V2_DOMAIN, projection),
    }
    _write_corrective_v2_plan(
        plan_directory,
        plan=plan,
        claims=claim_payloads,
    )
    print(
        json.dumps(
            {
                "actual_signature_time_claimed": False,
                "authorization_effect": "none_until_verified_import",
                "bundle_validity": projection["bundle_validity"],
                "plan_digest": plan["plan_digest"],
                "plan_directory": str(plan_directory),
                "receipt_digests": {
                    ticket_id: receipts[ticket_id]["receipt_digest"]
                    for ticket_id in sorted(receipts)
                },
                "sign_commands": [
                    _forecast_v2_sign_command(plan_directory / claim_name)
                    for claim_name in sorted(claim_payloads, key=_utf8_sort_key)
                ],
            },
            sort_keys=True,
        )
    )
    return 0


@_require_frozen_runtime
@_guard_acceptance_reader
def corrective_v2_receipt_import(args: argparse.Namespace) -> int:
    """Verify both receipt SSHSIGs and persist only a local import artifact."""

    repository_root = Path(cast(str, args.repository_root)).resolve()
    governance_root = _governance_root(repository_root, cast(str, args.governance_dir))
    roadmap_path = Path(cast(str, args.roadmap)).resolve()
    plan_directory = _corrective_private_acceptance_path(
        repository_root,
        cast(str, args.plan_dir),
        owner="corrective receipt signature plan",
        must_exist=True,
    )
    output_path = _corrective_private_acceptance_path(
        repository_root,
        cast(str, args.output),
        owner="corrective receipt import artifact",
        must_exist=None,
    )
    _require_corrective_v2_plan_files(
        plan_directory,
        expected_names={
            "plan.json",
            "completion-base-01.claim",
            "completion-base-01.claim.sig",
            "completion-boot-01.claim",
            "completion-boot-01.claim.sig",
        },
    )
    expected_fields = {
        "format",
        "spec_revision",
        "authorization_effect",
        "result_commit",
        "corrective_authorization_claim_digest",
        "bundle_validity",
        "post_r2_suite_evidence_digest",
        "targets",
        "claims",
        "source_files",
    }
    expected_plan_digest = cast(str, args.expected_plan_digest)
    plan = _read_corrective_v2_plan(
        plan_directory,
        expected_format="agent-assure-s1-corrective-receipt-signature-plan/2",
        domain=CORRECTIVE_RECEIPT_PLAN_V2_DOMAIN,
        expected_digest=expected_plan_digest,
        expected_fields=expected_fields,
    )
    _require_corrective_v2_plan_source_set(
        repository_root,
        roadmap_path,
        plan,
        expected_private_extra_count=1,
    )
    if plan.get("corrective_authorization_claim_digest") != CORRECTIVE_KICKOFF_CLAIM_DIGEST:
        raise GovernanceError("corrective receipt plan authorization digest changed")
    _verify_plan_sources(repository_root, plan)
    result_commit = _required_string(plan, "result_commit")
    context = _load_corrective_v2_workspace(
        repository_root=repository_root,
        governance_root=governance_root,
        roadmap_path=roadmap_path,
        result_commit=result_commit,
    )
    pending_targets = _corrective_v2_plan_targets(plan)
    expected_target_paths = {
        "docs/governance/v1/completion-receipt-v1-base-01.json",
        "docs/governance/v1/completion-receipt-v1-boot-01.json",
    }
    if set(pending_targets) != expected_target_paths:
        raise GovernanceError("corrective receipt plan target set is not exact")
    for ticket_id in ("V1-BASE-01", "V1-BOOT-01"):
        path = f"docs/governance/v1/completion-receipt-{ticket_id.lower()}.json"
        _validate_corrective_receipt_plan_candidate(
            cast(RoadmapSnapshot, context["snapshot"]),
            pending_targets[path],
            repository_root=repository_root,
            ticket_id=ticket_id,
            roster=cast(Mapping[str, Any], context["roster"]),
            person_id=cast(str, context["person_id"]),
            result_commit=result_commit,
            corrective_authorization=cast(Mapping[str, Any], context["authorization"]),
            forecast=cast(Mapping[str, Any], context["forecast"]),
        )
    receipt_schema = _read_json(governance_root / "ticket-completion-receipt.schema.json")

    def validate_imported_targets(
        imported_targets: Mapping[str, Mapping[str, Any]],
    ) -> None:
        if set(imported_targets) != expected_target_paths:
            raise GovernanceError("corrective receipt import target set is not exact")
        for ticket_id in ("V1-BASE-01", "V1-BOOT-01"):
            path = f"docs/governance/v1/completion-receipt-{ticket_id.lower()}.json"
            validate_ticket_completion_receipt_v2(
                cast(RoadmapSnapshot, context["snapshot"]),
                imported_targets[path],
                receipt_schema,
                repository_root=repository_root,
                expected_ticket_id=ticket_id,
                expected_roster_digest=cast(str, context["roster_digest"]),
                expected_corrective_authorization_digest=CORRECTIVE_KICKOFF_CLAIM_DIGEST,
                expected_person_id=cast(str, context["person_id"]),
                expected_result_parent=S1_ACCEPTANCE_V1_CLOSURE_COMMIT,
                allow_pending=False,
            )

    if output_path.exists() or output_path.is_symlink():
        if not output_path.is_file() or output_path.is_symlink():
            raise GovernanceError("corrective receipt import artifact is not a regular file")
        artifact, existing_targets = _read_corrective_receipt_import_artifact(
            output_path,
            expected_plan_digest=expected_plan_digest,
        )
        if artifact.get("result_commit") != result_commit or artifact.get(
            "bundle_validity"
        ) != plan.get("bundle_validity"):
            raise GovernanceError("corrective receipt import artifact changed plan bindings")
        validate_imported_targets(existing_targets)
        print(
            json.dumps(
                {
                    "actual_signature_time_claimed": False,
                    "authorization_effect": "signed_receipts_verified_not_installed",
                    "idempotent_recovery": True,
                    "import_artifact_digest": artifact["import_artifact_digest"],
                    "output": str(output_path),
                    "receipt_plan_digest": expected_plan_digest,
                    "result": "both_replacement_receipts_verified_locally",
                    "result_commit": result_commit,
                },
                sort_keys=True,
            )
        )
        return 0

    signed_targets = _materialize_corrective_v2_plan_targets(plan_directory, plan)
    imported_targets: dict[str, dict[str, Any]] = {
        path: record_v2_signature_import_observation(record)
        for path, record in signed_targets.items()
    }
    validate_imported_targets(imported_targets)
    artifact = _build_corrective_receipt_import_artifact(
        receipt_plan_digest=expected_plan_digest,
        result_commit=result_commit,
        bundle_validity=_as_object(plan.get("bundle_validity"), owner="corrective bundle validity"),
        targets=imported_targets,
    )
    _write_new_private_json(
        output_path,
        artifact,
        owner="corrective receipt import artifact",
    )
    print(
        json.dumps(
            {
                "actual_signature_time_claimed": False,
                "authorization_effect": "signed_receipts_verified_not_installed",
                "idempotent_recovery": False,
                "import_artifact_digest": artifact["import_artifact_digest"],
                "output": str(output_path),
                "receipt_plan_digest": expected_plan_digest,
                "result": "both_replacement_receipts_verified_locally",
                "result_commit": result_commit,
            },
            sort_keys=True,
        )
    )
    return 0


def _corrective_closure_import_projection(
    *,
    bundle_plan_digest: str,
    result_commit: str,
    targets: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    if set(targets) != S1_CORRECTIVE_CLOSURE_PATHS:
        raise GovernanceError("corrective closure import target set is not exact")
    if SHA256_PATTERN.fullmatch(bundle_plan_digest) is None:
        raise GovernanceError("corrective closure import plan digest is invalid")
    if GIT_COMMIT_PATTERN.fullmatch(result_commit) is None:
        raise GovernanceError("corrective closure import result commit is invalid")
    return {
        "format": "agent-assure-s1-corrective-closure-signature-import/2",
        "spec_revision": SPEC_REVISION,
        "authorization_effect": "verified_closure_ready_for_atomic_install",
        "bundle_plan_digest": bundle_plan_digest,
        "result_commit": result_commit,
        "targets": [
            {"path": path, "record": copy.deepcopy(dict(targets[path]))}
            for path in sorted(targets, key=_utf8_sort_key)
        ],
    }


def _build_corrective_closure_import_artifact(
    *,
    bundle_plan_digest: str,
    result_commit: str,
    targets: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    projection = _corrective_closure_import_projection(
        bundle_plan_digest=bundle_plan_digest,
        result_commit=result_commit,
        targets=targets,
    )
    return {
        **projection,
        "import_artifact_digest": domain_digest(
            CORRECTIVE_CLOSURE_IMPORT_V2_DOMAIN,
            projection,
        ),
    }


def _read_corrective_closure_import_artifact(
    path: Path,
    *,
    expected_plan_digest: str,
    expected_result_commit: str,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    artifact = _read_json(path)
    required = {
        "format",
        "spec_revision",
        "authorization_effect",
        "bundle_plan_digest",
        "result_commit",
        "targets",
        "import_artifact_digest",
    }
    if set(artifact) != required:
        raise GovernanceError("corrective closure import artifact is malformed")
    if (
        artifact.get("format") != "agent-assure-s1-corrective-closure-signature-import/2"
        or artifact.get("spec_revision") != SPEC_REVISION
        or artifact.get("authorization_effect") != "verified_closure_ready_for_atomic_install"
        or artifact.get("bundle_plan_digest") != expected_plan_digest
        or artifact.get("result_commit") != expected_result_commit
    ):
        raise GovernanceError("corrective closure import artifact identity changed")
    targets = _corrective_v2_plan_targets(artifact)
    projection = _corrective_closure_import_projection(
        bundle_plan_digest=expected_plan_digest,
        result_commit=expected_result_commit,
        targets=targets,
    )
    digest = domain_digest(CORRECTIVE_CLOSURE_IMPORT_V2_DOMAIN, projection)
    if artifact.get("import_artifact_digest") != digest:
        raise GovernanceError("corrective closure import artifact digest mismatch")
    if {key: value for key, value in artifact.items() if key != "import_artifact_digest"} != (
        projection
    ):
        raise GovernanceError("corrective closure import artifact differs from its projection")
    return artifact, targets


def _corrective_target_payload_state(
    repository_root: Path,
    expected_payloads: Mapping[str, bytes],
) -> tuple[bool, bool]:
    matches: list[bool] = []
    for relative, payload in expected_payloads.items():
        path = _resolve_repository_path_without_links(
            repository_root,
            relative,
            owner="corrective closure installed target",
        )
        matches.append(path.is_file() and not path.is_symlink() and path.read_bytes() == payload)
    return all(matches), any(matches)


def _verify_corrective_plan_sources_after_install(
    repository_root: Path,
    plan: Mapping[str, Any],
) -> None:
    non_target_sources = [
        value
        for value in _as_array(plan.get("source_files"), owner="corrective source files")
        if _required_string(_as_object(value, owner="corrective source file"), "path")
        not in S1_CORRECTIVE_CLOSURE_PATHS
    ]
    filtered = {**plan, "source_files": non_target_sources}
    _verify_plan_sources(repository_root, filtered)


def _validate_materialized_corrective_closure(
    *,
    repository_root: Path,
    governance_root: Path,
    context: Mapping[str, Any],
    targets: Mapping[str, Mapping[str, Any]],
    validation_time: datetime,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    completion_receipts = {
        ticket_id: dict(targets[f"docs/governance/v1/completion-receipt-{ticket_id.lower()}.json"])
        for ticket_id in ("V1-BASE-01", "V1-BOOT-01")
    }
    bundle = dict(targets["docs/governance/v1/governance-bundle.json"])
    validate_governance_bundle_v2(
        cast(RoadmapSnapshot, context["snapshot"]),
        bundle,
        _read_json(governance_root / "governance-bundle.schema.json"),
        repository_root=repository_root,
        roster=cast(Mapping[str, Any], context["roster"]),
        completion_receipts=completion_receipts,
        forecast=cast(Mapping[str, Any], context["forecast"]),
        baseline_observations=cast(Mapping[str, Any], context["baseline"]),
        expected_person_id=cast(str, context["person_id"]),
        expected_result_parent=S1_ACCEPTANCE_V1_CLOSURE_COMMIT,
        allow_pending=False,
        validation_time=validation_time,
        require_current_closure=False,
        require_closure=False,
        expected_closure_commit=None,
    )
    return bundle, completion_receipts


@_require_frozen_runtime
@_guard_acceptance_reader
def corrective_v2_bundle_plan(args: argparse.Namespace) -> int:
    """Prepare the timestamp-free bundle claim over both verified receipts."""

    repository_root = Path(cast(str, args.repository_root)).resolve()
    governance_root = _governance_root(repository_root, cast(str, args.governance_dir))
    roadmap_path = Path(cast(str, args.roadmap)).resolve()
    result_commit = cast(str, args.result_commit)
    if GIT_COMMIT_PATTERN.fullmatch(result_commit) is None:
        raise GovernanceError("--result-commit must be a full lowercase 40-hex commit ID")
    plan_directory = _corrective_private_acceptance_path(
        repository_root,
        cast(str, args.plan_dir),
        owner="corrective bundle signature plan",
        must_exist=False,
    )
    receipt_import_path = _corrective_private_acceptance_path(
        repository_root,
        cast(str, args.receipt_import),
        owner="corrective receipt import artifact",
        must_exist=True,
    )
    expected_receipt_plan_digest = cast(str, args.expected_receipt_plan_digest)
    receipt_artifact, receipt_targets = _read_corrective_receipt_import_artifact(
        receipt_import_path,
        expected_plan_digest=expected_receipt_plan_digest,
    )
    if receipt_artifact.get("result_commit") != result_commit:
        raise GovernanceError("corrective receipt import targets another R2")
    context = _load_corrective_v2_workspace(
        repository_root=repository_root,
        governance_root=governance_root,
        roadmap_path=roadmap_path,
        result_commit=result_commit,
    )
    completion_receipts = {
        ticket_id: receipt_targets[
            f"docs/governance/v1/completion-receipt-{ticket_id.lower()}.json"
        ]
        for ticket_id in ("V1-BASE-01", "V1-BOOT-01")
    }
    receipt_schema = _read_json(governance_root / "ticket-completion-receipt.schema.json")
    for ticket_id, receipt in completion_receipts.items():
        validate_ticket_completion_receipt_v2(
            cast(RoadmapSnapshot, context["snapshot"]),
            receipt,
            receipt_schema,
            repository_root=repository_root,
            expected_ticket_id=ticket_id,
            expected_roster_digest=cast(str, context["roster_digest"]),
            expected_corrective_authorization_digest=CORRECTIVE_KICKOFF_CLAIM_DIGEST,
            expected_person_id=cast(str, context["person_id"]),
            expected_result_parent=S1_ACCEPTANCE_V1_CLOSURE_COMMIT,
            allow_pending=False,
        )
    validity = _as_object(
        receipt_artifact.get("bundle_validity"), owner="corrective bundle validity"
    )
    bundle = build_governance_bundle_v2(
        cast(RoadmapSnapshot, context["snapshot"]),
        repository_root=repository_root,
        roster=cast(Mapping[str, Any], context["roster"]),
        completion_receipts=completion_receipts,
        forecast=cast(Mapping[str, Any], context["forecast"]),
        baseline_observations=cast(Mapping[str, Any], context["baseline"]),
        person_id=cast(str, context["person_id"]),
        result_commit=result_commit,
        issued_at=_required_string(validity, "issued_at_utc"),
        valid_until=_required_string(validity, "valid_until_utc"),
        status="accepted_for_development",
    )
    _validate_corrective_bundle_plan_candidate(
        cast(RoadmapSnapshot, context["snapshot"]),
        bundle,
        repository_root=repository_root,
        roster=cast(Mapping[str, Any], context["roster"]),
        completion_receipts=completion_receipts,
        forecast=cast(Mapping[str, Any], context["forecast"]),
        baseline_observations=cast(Mapping[str, Any], context["baseline"]),
        corrective_authorization=cast(Mapping[str, Any], context["authorization"]),
        person_id=cast(str, context["person_id"]),
        result_commit=result_commit,
    )
    bundle_path = "docs/governance/v1/governance-bundle.json"
    targets = {**receipt_targets, bundle_path: bundle}
    descriptor, claim = _corrective_v2_claim_descriptor(
        claim_id="governance-bundle",
        target_path=bundle_path,
        target_record=bundle,
    )
    source_paths = _corrective_v2_source_paths(
        repository_root,
        roadmap_path,
        extra_paths=(receipt_import_path,),
    )
    projection = {
        "format": "agent-assure-s1-corrective-bundle-signature-plan/2",
        "spec_revision": SPEC_REVISION,
        "authorization_effect": "none_until_verified_import",
        "result_commit": result_commit,
        "corrective_authorization_claim_digest": CORRECTIVE_KICKOFF_CLAIM_DIGEST,
        "receipt_plan_digest": expected_receipt_plan_digest,
        "receipt_import_artifact_digest": _required_string(
            receipt_artifact, "import_artifact_digest"
        ),
        "targets": [
            {"path": path, "record": targets[path]} for path in sorted(targets, key=_utf8_sort_key)
        ],
        "claims": [descriptor],
        "source_files": [_source_file_evidence(repository_root, path) for path in source_paths],
    }
    plan = {
        **projection,
        "plan_digest": domain_digest(CORRECTIVE_BUNDLE_PLAN_V2_DOMAIN, projection),
    }
    _write_corrective_v2_plan(
        plan_directory,
        plan=plan,
        claims={"governance-bundle.claim": claim},
    )
    print(
        json.dumps(
            {
                "actual_signature_time_claimed": False,
                "authorization_effect": "none_until_verified_import",
                "bundle_digest": bundle["bundle_digest"],
                "plan_digest": plan["plan_digest"],
                "plan_directory": str(plan_directory),
                "receipt_import_artifact_digest": receipt_artifact["import_artifact_digest"],
                "sign_command": _forecast_v2_sign_command(
                    plan_directory / "governance-bundle.claim"
                ),
            },
            sort_keys=True,
        )
    )
    return 0


@_require_frozen_runtime
def corrective_v2_bundle_import(args: argparse.Namespace) -> int:
    """Verify the bundle SSHSIG and atomically install exactly the C2 records."""

    repository_root = Path(cast(str, args.repository_root)).resolve()
    governance_root = _governance_root(repository_root, cast(str, args.governance_dir))
    roadmap_path = Path(cast(str, args.roadmap)).resolve()
    plan_directory = _corrective_private_acceptance_path(
        repository_root,
        cast(str, args.plan_dir),
        owner="corrective bundle signature plan",
        must_exist=True,
    )
    stable_import_path = plan_directory / "verified-closure-import.json"
    base_plan_names = {
        "plan.json",
        "governance-bundle.claim",
        "governance-bundle.claim.sig",
    }
    observed_names = {entry.name for entry in plan_directory.iterdir()}
    allowed_name_sets = (
        base_plan_names,
        base_plan_names | {stable_import_path.name},
    )
    if observed_names not in allowed_name_sets:
        raise GovernanceError("corrective bundle plan has missing or unexpected files")
    _require_corrective_v2_plan_files(
        plan_directory,
        expected_names=observed_names,
    )
    expected_fields = {
        "format",
        "spec_revision",
        "authorization_effect",
        "result_commit",
        "corrective_authorization_claim_digest",
        "receipt_plan_digest",
        "receipt_import_artifact_digest",
        "targets",
        "claims",
        "source_files",
    }
    expected_plan_digest = cast(str, args.expected_plan_digest)
    plan = _read_corrective_v2_plan(
        plan_directory,
        expected_format="agent-assure-s1-corrective-bundle-signature-plan/2",
        domain=CORRECTIVE_BUNDLE_PLAN_V2_DOMAIN,
        expected_digest=expected_plan_digest,
        expected_fields=expected_fields,
    )
    _require_corrective_v2_plan_source_set(
        repository_root,
        roadmap_path,
        plan,
        expected_private_extra_count=1,
    )
    result_commit = _required_string(plan, "result_commit")
    if plan.get("corrective_authorization_claim_digest") != CORRECTIVE_KICKOFF_CLAIM_DIGEST:
        raise GovernanceError("corrective bundle plan authorization digest changed")
    planned_targets = _corrective_v2_plan_targets(plan)
    if set(planned_targets) != S1_CORRECTIVE_CLOSURE_PATHS:
        raise GovernanceError("corrective bundle plan target set is not exact")
    expected_prior_evidence = _acceptance_plan_target_prior_evidence(
        plan,
        expected_target_paths=set(S1_CORRECTIVE_CLOSURE_PATHS),
    )

    if stable_import_path.exists() or stable_import_path.is_symlink():
        if not stable_import_path.is_file() or stable_import_path.is_symlink():
            raise GovernanceError("corrective closure import artifact is not a regular file")
        _artifact, closure_targets = _read_corrective_closure_import_artifact(
            stable_import_path,
            expected_plan_digest=expected_plan_digest,
            expected_result_commit=result_commit,
        )
    else:
        _verify_plan_sources(repository_root, plan)
        materialized = _materialize_corrective_v2_plan_targets(plan_directory, plan)
        bundle_path = "docs/governance/v1/governance-bundle.json"
        materialized[bundle_path] = record_v2_signature_import_observation(
            materialized[bundle_path]
        )
        artifact = _build_corrective_closure_import_artifact(
            bundle_plan_digest=expected_plan_digest,
            result_commit=result_commit,
            targets=materialized,
        )
        _write_new_private_json(
            stable_import_path,
            artifact,
            owner="corrective closure import artifact",
        )
        closure_targets = materialized

    expected_next_payloads = {
        relative: _render_json_bytes(record) for relative, record in closure_targets.items()
    }

    def finish(*, bundle: Mapping[str, Any], idempotent_recovery: bool) -> int:
        changes = _validate_corrective_closure_worktree(
            repository_root,
            result_commit=result_commit,
        )
        print(
            json.dumps(
                {
                    "actual_signature_time_claimed": False,
                    "authorization_effect": "verified_closure_records_installed",
                    "bundle_digest": bundle["bundle_digest"],
                    "changed_paths": changes,
                    "idempotent_recovery": idempotent_recovery,
                    "installed_records": {
                        relative: {
                            "sha256": raw_digest(_render_json_bytes(record)),
                            "size_bytes": len(_render_json_bytes(record)),
                        }
                        for relative, record in sorted(
                            closure_targets.items(),
                            key=lambda item: _utf8_sort_key(item[0]),
                        )
                    },
                    "plan_digest": expected_plan_digest,
                    "result": "three_c2_records_atomically_installed_not_committed",
                    "result_commit": result_commit,
                },
                sort_keys=True,
            )
        )
        return 0

    with _acceptance_import_lock(repository_root):
        _recover_acceptance_transaction(
            repository_root,
            expected_plan_digest=expected_plan_digest,
            expected_prior_evidence=expected_prior_evidence,
            expected_next_payloads=expected_next_payloads,
        )
        all_next, any_next = _corrective_target_payload_state(
            repository_root,
            expected_next_payloads,
        )
        if all_next:
            _verify_corrective_plan_sources_after_install(repository_root, plan)
            context = _load_corrective_v2_workspace(
                repository_root=repository_root,
                governance_root=governance_root,
                roadmap_path=roadmap_path,
                result_commit=result_commit,
                allow_materialized_closure=True,
            )
            validation_time = _parse_utc(
                _canonical_host_utc_now(),
                owner="corrective closure idempotent recovery validation",
            )
            bundle, _receipts = _validate_materialized_corrective_closure(
                repository_root=repository_root,
                governance_root=governance_root,
                context=context,
                targets=closure_targets,
                validation_time=validation_time,
            )
            still_all_next, _ = _corrective_target_payload_state(
                repository_root,
                expected_next_payloads,
            )
            if not still_all_next:
                raise GovernanceError(
                    "corrective closure target bytes changed during idempotent validation"
                )
            return finish(bundle=bundle, idempotent_recovery=True)
        if any_next:
            raise GovernanceError(
                "corrective closure has a partial install without a recoverable transaction"
            )
    _verify_plan_sources(repository_root, plan)
    context = _load_corrective_v2_workspace(
        repository_root=repository_root,
        governance_root=governance_root,
        roadmap_path=roadmap_path,
        result_commit=result_commit,
    )
    validation_time = _parse_utc(
        _canonical_host_utc_now(), owner="corrective closure import validation"
    )
    bundle, _receipts = _validate_materialized_corrective_closure(
        repository_root=repository_root,
        governance_root=governance_root,
        context=context,
        targets=closure_targets,
        validation_time=validation_time,
    )
    output_records = {
        _resolve_repository_path_without_links(
            repository_root,
            relative,
            owner="corrective closure target",
        ): record
        for relative, record in closure_targets.items()
    }
    with _acceptance_import_lock(repository_root):
        _recover_acceptance_transaction(
            repository_root,
            expected_plan_digest=expected_plan_digest,
            expected_prior_evidence=expected_prior_evidence,
            expected_next_payloads=expected_next_payloads,
        )
        _verify_plan_sources(repository_root, plan)
        _require_clean_corrective_result_checkout(
            repository_root,
            result_commit=result_commit,
            owner="corrective closure atomic install",
        )
        _install_acceptance_targets(
            repository_root,
            output_records,
            plan_digest=expected_plan_digest,
            expected_prior_evidence=expected_prior_evidence,
        )
        all_next, _ = _corrective_target_payload_state(
            repository_root,
            expected_next_payloads,
        )
        if not all_next:
            raise GovernanceError("corrective closure target bytes changed after atomic install")
        return finish(bundle=bundle, idempotent_recovery=False)


@_require_frozen_runtime
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


@_require_frozen_runtime
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


@_require_frozen_runtime
@_guard_acceptance_reader
def check(args: argparse.Namespace) -> int:
    repository_root = Path(cast(str, args.repository_root)).resolve()
    root = Path(cast(str, args.governance_dir)).resolve()
    acceptance_generation_value = getattr(args, "acceptance_generation", None)
    if acceptance_generation_value is not None and (
        type(acceptance_generation_value) is not int or acceptance_generation_value not in {1, 2}
    ):
        raise GovernanceError("--acceptance-generation must be 1 or 2")
    requested_acceptance_generation: int | None = acceptance_generation_value
    live_acceptance_generation = requested_acceptance_generation or 1
    effective_acceptance_generation = live_acceptance_generation
    closure_commit_value = getattr(args, "closure_commit", None)
    acceptance_tag_object_value = getattr(args, "acceptance_tag_object", None)
    attestation_plan_dir_value = getattr(args, "attestation_plan_dir", None)
    attestation_signed_at_value = getattr(args, "attestation_signed_at", None)
    commitment_time_value = getattr(args, "commitment_time", None)
    deprecated_event_inputs = {
        "--gate-checked-at": getattr(args, "gate_checked_at", None),
        "--plan-created-at": getattr(args, "plan_created_at", None),
        "--claim-prepared-at": getattr(args, "claim_prepared_at", None),
    }
    if any(value is not None for value in deprecated_event_inputs.values()):
        raise GovernanceError(
            "generation-2 event times are captured internally and cannot be supplied by callers"
        )
    if closure_commit_value is not None and not isinstance(closure_commit_value, str):
        raise GovernanceError("--closure-commit must be a full 40-hex Git commit ID")
    closure_commit: str | None = closure_commit_value
    if root != (repository_root / "docs/governance/v1").resolve():
        raise GovernanceError("S1 governance directory must be docs/governance/v1")
    if args.allow_pending and (args.accept_now or args.historical):
        raise GovernanceError(
            "--allow-pending cannot be combined with --accept-now or --historical"
        )
    if args.allow_pending and live_acceptance_generation == 2 and commitment_time_value is not None:
        raise GovernanceError("generation-2 --allow-pending does not accept --commitment-time")
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
        if not isinstance(attestation_plan_dir_value, str):
            raise GovernanceError("--accept-now requires --attestation-plan-dir")
        if live_acceptance_generation == 1:
            if commitment_time_value is None:
                raise GovernanceError("--accept-now requires --commitment-time")
            if not isinstance(attestation_signed_at_value, str):
                raise GovernanceError("--accept-now requires --attestation-signed-at")
        else:
            if commitment_time_value is not None:
                raise GovernanceError(
                    "generation-2 --accept-now captures its commitment time internally"
                )
            if attestation_signed_at_value is not None:
                raise GovernanceError(
                    "generation-2 --accept-now does not accept --attestation-signed-at"
                )
        acceptance_path_resolver = (
            _corrective_private_acceptance_path
            if live_acceptance_generation == 2
            else _private_acceptance_path
        )
        attestation_plan_directory = acceptance_path_resolver(
            repository_root,
            attestation_plan_dir_value,
            owner="current acceptance attestation plan",
            must_exist=False,
        )
    elif attestation_plan_dir_value is not None or attestation_signed_at_value is not None:
        raise GovernanceError("acceptance attestation preparation requires --accept-now")
    validation_started_at_value = (
        _canonical_host_utc_now()
        if live_acceptance_generation == 2 and (args.accept_now or args.allow_pending)
        else None
    )
    roadmap_path = Path(cast(str, args.roadmap))
    validate_local_only_roadmap(repository_root, roadmap_path)
    snapshot = load_roadmap(roadmap_path)

    commitment_time: datetime | None = None
    historical_attestation: dict[str, Any] | None = None
    historical_attestation_signature_time: datetime | None = None
    historical_attestation_preparation_time: datetime | None = None
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
        historical_acceptance_generation = (
            2
            if historical_attestation.get("format") == CURRENT_ACCEPTANCE_ATTESTATION_V2_FORMAT
            else 1
        )
        effective_acceptance_generation = historical_acceptance_generation
        if (
            requested_acceptance_generation is not None
            and requested_acceptance_generation != historical_acceptance_generation
        ):
            raise GovernanceError(
                "--acceptance-generation does not match the selected acceptance tag"
            )
        if historical_acceptance_generation == 2:
            _validate_generation_1_predecessor_acceptance(
                repository_root,
                expected_roadmap_digest=snapshot.raw_digest,
            )
        if historical_attestation.get("format") == CURRENT_ACCEPTANCE_ATTESTATION_V2_FORMAT:
            historical_attestation_schema = _read_json_from_commit(
                repository_root,
                closure_commit,
                "docs/governance/v1/current-acceptance-attestation.schema.json",
            )
            _validate_json_schema(
                historical_attestation,
                historical_attestation_schema,
                owner="generation-2 current acceptance attestation",
            )
        commitment_time, attestation_evidence_time = _validate_current_acceptance_attestation(
            historical_attestation,
            repository_root=repository_root,
            expected_closure_commit=closure_commit,
            expected_roadmap_digest=snapshot.raw_digest,
            allow_pending=False,
            require_executing_artifacts=True,
        )
        if historical_acceptance_generation == 2:
            historical_attestation_preparation_time = attestation_evidence_time
        else:
            historical_attestation_signature_time = attestation_evidence_time
        historical_paths = _historical_governance_json_paths(
            acceptance_generation=historical_acceptance_generation
        )
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

    live_repository_evidence: dict[str, Any] | None = None
    gate_completed_at_value: str | None = None
    attestation_preparation_started_at_value: str | None = None
    if args.accept_now:
        live_repository_evidence = validate_live_acceptance_repository(
            repository_root,
            fetch=True,
            expected_branch_name=(
                S1_CORRECTIVE_BRANCH_NAME if live_acceptance_generation == 2 else S1_BRANCH_NAME
            ),
        )

    roster = read_governance_record("approval-roster.json")
    roster_schema = read_governance_record("approval-roster.schema.json")
    roster_digest, person_id = validate_approval_roster(
        snapshot, roster, roster_schema, allow_pending=bool(args.allow_pending)
    )
    if historical_attestation is None:
        live_commitment_time_value = (
            validation_started_at_value
            if live_acceptance_generation == 2 and (args.accept_now or args.allow_pending)
            else commitment_time_value
        )
        commitment_time = (
            _parse_utc(
                cast(str, live_commitment_time_value),
                owner=(
                    "internally captured generation-2 validation start"
                    if live_acceptance_generation == 2 and (args.accept_now or args.allow_pending)
                    else "--commitment-time"
                ),
            )
            if live_commitment_time_value is not None
            else None
        )
    if not args.allow_pending and commitment_time is None:
        raise GovernanceError(
            "strict generation-2 checking failed to capture validation start"
            if args.accept_now and live_acceptance_generation == 2
            else "strict checking requires --commitment-time"
        )
    signing_key = read_governance_record("maintainer-signing-key.json")
    baseline = read_governance_record("baseline-observations.json")
    corrective_authorization: dict[str, Any] | None = None
    if effective_acceptance_generation == 2:
        signing_key_schema = read_governance_record("maintainer-signing-key.schema.json")
        validate_maintainer_signing_key(
            signing_key,
            signing_key_schema,
            expected_person_id=person_id,
            allow_pending=bool(args.allow_pending),
        )
        corrective_authorization = read_governance_record("corrective-kickoff-authorization.json")
        corrective_authorization_schema = read_governance_record(
            "corrective-kickoff-authorization.schema.json"
        )
        validate_corrective_kickoff_authorization(
            corrective_authorization,
            corrective_authorization_schema,
            expected_roadmap_digest=snapshot.raw_digest,
        )
        _corrective_authorized_paths(corrective_authorization)
        baseline_schema = read_governance_record("baseline-observations.schema.json")
        validate_baseline_observations(
            snapshot,
            baseline,
            baseline_schema,
            repository_root=repository_root,
        )
        _validate_corrective_authorization_precedes_baseline(
            corrective_authorization=corrective_authorization,
            baseline=baseline,
        )
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
    ledger = read_governance_record("delivery-forecast.authoring-ledger.json")
    ledger_schema = read_governance_record("delivery-forecast.authoring-ledger.schema.json")
    forecast = read_governance_record("delivery-forecast.json")
    schema = read_governance_record("delivery-forecast.schema.json")
    if registry.get("format") == "agent-assure-delivery-forecast-aggregation-registry/2":
        catalog = read_governance_record("delivery-forecast.estimation-catalog.json")
        catalog_schema = read_governance_record("delivery-forecast.estimation-catalog.schema.json")
        validate_estimation_catalog_v2(catalog, catalog_schema)
        _resolve_aggregation_method_v2(registry)
        validate_authoring_ledger_v2(
            snapshot,
            ledger,
            ledger_schema,
            catalog,
            baseline_observations=baseline,
            allow_pending=bool(args.allow_pending),
        )
        validate_forecast_v2(
            snapshot,
            ledger,
            registry,
            forecast,
            schema,
            approval_roster=roster,
            approval_roster_digest_value=roster_digest,
            allow_pending=bool(args.allow_pending),
        )
    else:
        _resolve_aggregation_method(registry)
        validate_authoring_ledger(
            snapshot,
            ledger,
            ledger_schema,
            expected_person_id=person_id,
            baseline_observations=baseline,
        )
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
    completion_receipts = {
        ticket_id: read_governance_record(f"completion-receipt-{ticket_id.lower()}.json")
        for ticket_id in ("V1-BOOT-01", "V1-BASE-01")
    }
    bundle = read_governance_record("governance-bundle.json")
    bundle_schema = read_governance_record("governance-bundle.schema.json")
    generation_2_placeholder_state = (
        bool(args.allow_pending)
        and live_acceptance_generation == 2
        and historical_records is None
        and bundle.get("format") == "agent-assure-governance-bundle/1"
        and all(
            receipt.get("format") == "agent-assure-ticket-completion-receipt/1"
            for receipt in completion_receipts.values()
        )
    )
    if generation_2_placeholder_state:
        placeholders = _validate_generation_1_closure_placeholders(
            repository_root,
            root,
        )
        expected_receipts = {
            ticket_id: placeholders[
                f"docs/governance/v1/completion-receipt-{ticket_id.lower()}.json"
            ]
            for ticket_id in ("V1-BOOT-01", "V1-BASE-01")
        }
        if (
            completion_receipts != expected_receipts
            or bundle != placeholders["docs/governance/v1/governance-bundle.json"]
        ):
            raise GovernanceError("generation-1 closure placeholder records changed")
    else:
        formats = {
            bundle.get("format"),
            *(receipt.get("format") for receipt in completion_receipts.values()),
        }
        if (
            live_acceptance_generation == 2
            and historical_records is None
            and formats
            != {
                "agent-assure-governance-bundle/2",
                "agent-assure-ticket-completion-receipt/2",
            }
        ):
            raise GovernanceError(
                "generation-2 closure is mixed; require either exact C1 placeholders "
                "or all v2 records"
            )
        for ticket_id, receipt in completion_receipts.items():
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
        bundle_validation_time = commitment_time
        if bundle.get("format") == "agent-assure-governance-bundle/2" and (
            bundle_validation_time is None
        ):
            bundle_validation_time = _parse_utc(
                _canonical_host_utc_now(),
                owner="generation-2 nonaccepting validation observation",
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
            allow_pending=bool(args.allow_pending),
            validation_time=bundle_validation_time,
            require_bundle_on_disk=historical_records is None,
            require_predecessors_on_disk=historical_records is None,
            require_current_closure=bool(args.accept_now),
            require_closure=not bool(args.allow_pending),
            historical_records=historical_records,
            expected_closure_commit=closure_commit,
        )
    if args.accept_now and live_acceptance_generation == 2:
        if corrective_authorization is None or commitment_time is None:
            raise GovernanceError("generation-2 gate predecessor inputs are incomplete")
        gate_completed_at_value = _canonical_host_utc_now()
        gate_completion_time = _parse_utc(
            gate_completed_at_value,
            owner="internally captured generation-2 gate completion",
        )
        _validate_generation_2_final_gate_validity(
            validation_started_time=commitment_time,
            gate_time=gate_completion_time,
            kickoff_records=kickoff_records,
            corrective_authorization=corrective_authorization,
            forecast=forecast,
            bundle=bundle,
        )
        attestation_preparation_started_at_value = _canonical_host_utc_now()
        commitment_time = gate_completion_time
    elif historical_attestation is not None and historical_acceptance_generation == 2:
        if corrective_authorization is None or commitment_time is None:
            raise GovernanceError("generation-2 historical gate inputs are incomplete")
        historical_validation_started = _parse_utc(
            _required_string(historical_attestation, "validation_started_at_utc"),
            owner="generation-2 acceptance validation_started_at_utc",
        )
        _validate_generation_2_final_gate_validity(
            validation_started_time=historical_validation_started,
            gate_time=commitment_time,
            kickoff_records=kickoff_records,
            corrective_authorization=corrective_authorization,
            forecast=forecast,
            bundle=bundle,
        )

    attestation_plan: dict[str, Any] | None = None
    if historical_attestation is not None:
        if commitment_time is None:
            raise GovernanceError(
                "signed current acceptance attestation lacks a validated gate time"
            )
        if historical_attestation.get("bundle_digest") != bundle.get("bundle_digest"):
            raise GovernanceError("signed current acceptance attestation binds another bundle")
        if historical_attestation.get("result_commit") != bundle.get("result_commit"):
            raise GovernanceError("signed current acceptance attestation binds another result")
        if historical_attestation.get("signer_person_id") != person_id:
            raise GovernanceError("signed current acceptance attestation uses another maintainer")
        _validate_historical_attestation_bundle_time_evidence(
            historical_attestation,
            acceptance_generation=historical_acceptance_generation,
            gate_time=commitment_time,
            attestation_evidence_time=(
                historical_attestation_preparation_time
                if historical_acceptance_generation == 2
                else historical_attestation_signature_time
            ),
            bundle=bundle,
        )
    elif args.accept_now:
        if live_repository_evidence is None or attestation_plan_directory is None:
            raise GovernanceError("current acceptance attestation inputs are incomplete")
        if live_acceptance_generation == 1:
            if commitment_time_value is None or not isinstance(attestation_signed_at_value, str):
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
        else:
            if not all(
                isinstance(value, str)
                for value in (
                    validation_started_at_value,
                    gate_completed_at_value,
                    attestation_preparation_started_at_value,
                )
            ):
                raise GovernanceError("current acceptance attestation inputs are incomplete")
            attestation = build_current_acceptance_attestation_v2(
                snapshot,
                repository_root=repository_root,
                bundle=bundle,
                live_repository_evidence=live_repository_evidence,
                validation_started_at=cast(str, validation_started_at_value),
                gate_completed_at=cast(str, gate_completed_at_value),
                attestation_preparation_started_at=cast(
                    str,
                    attestation_preparation_started_at_value,
                ),
                signer_person_id=person_id,
            )
            attestation_schema = read_governance_record(
                "current-acceptance-attestation.schema.json"
            )
            _validate_json_schema(
                attestation,
                attestation_schema,
                owner="generation-2 current acceptance attestation",
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


@_require_frozen_runtime
@_guard_acceptance_reader
def acceptance_preflight(args: argparse.Namespace) -> int:
    """Re-resolve mutable Git facts before the human acceptance ceremony."""

    repository_root = Path(cast(str, args.repository_root)).resolve()
    acceptance_generation_value = getattr(args, "acceptance_generation", None)
    if acceptance_generation_value is not None and (
        type(acceptance_generation_value) is not int or acceptance_generation_value not in {1, 2}
    ):
        raise GovernanceError("--acceptance-generation must be 1 or 2")
    acceptance_generation = acceptance_generation_value or 1
    branch_name = S1_CORRECTIVE_BRANCH_NAME if acceptance_generation == 2 else S1_BRANCH_NAME
    acceptance_tag_name = (
        S1_ACCEPTANCE_V2_TAG_NAME if acceptance_generation == 2 else S1_ACCEPTANCE_TAG_NAME
    )
    validate_live_acceptance_repository(
        repository_root,
        fetch=bool(args.fetch),
        expected_branch_name=branch_name,
    )
    print(
        json.dumps(
            {
                "acceptance_generation": acceptance_generation,
                "acceptance_tag_name": acceptance_tag_name,
                "branch": branch_name,
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
    corrective_suite = subparsers.add_parser(
        "corrective-v2-suite-capture",
        help="Run the exact full suite at clean R2 and preserve local raw evidence",
    )
    corrective_suite.add_argument("--roadmap", required=True)
    corrective_suite.add_argument("--governance-dir", required=True)
    corrective_suite.add_argument("--result-commit", required=True)
    corrective_suite.add_argument(
        "--evidence-dir",
        default=POST_R2_SUITE_EVIDENCE_DIRECTORY,
    )
    corrective_suite.add_argument("--repository-root", default=".")
    corrective_suite.set_defaults(handler=corrective_v2_suite_capture)

    corrective_receipt_plan = subparsers.add_parser(
        "corrective-v2-receipt-plan",
        help="Prepare timestamp-free BASE and BOOT replacement receipt claims",
    )
    corrective_receipt_plan.add_argument("--roadmap", required=True)
    corrective_receipt_plan.add_argument("--governance-dir", required=True)
    corrective_receipt_plan.add_argument("--result-commit", required=True)
    corrective_receipt_plan.add_argument("--post-r2-evidence", required=True)
    corrective_receipt_plan.add_argument("--plan-dir", required=True)
    corrective_receipt_plan.add_argument("--repository-root", default=".")
    corrective_receipt_plan.set_defaults(handler=corrective_v2_receipt_plan)

    corrective_receipt_import = subparsers.add_parser(
        "corrective-v2-receipt-import",
        help="Verify both receipt SSHSIGs into a local, non-installed artifact",
    )
    corrective_receipt_import.add_argument("--roadmap", required=True)
    corrective_receipt_import.add_argument("--governance-dir", required=True)
    corrective_receipt_import.add_argument("--plan-dir", required=True)
    corrective_receipt_import.add_argument("--expected-plan-digest", required=True)
    corrective_receipt_import.add_argument("--output", required=True)
    corrective_receipt_import.add_argument("--repository-root", default=".")
    corrective_receipt_import.set_defaults(handler=corrective_v2_receipt_import)

    corrective_bundle_plan = subparsers.add_parser(
        "corrective-v2-bundle-plan",
        help="Prepare the timestamp-free generation-2 governance-bundle claim",
    )
    corrective_bundle_plan.add_argument("--roadmap", required=True)
    corrective_bundle_plan.add_argument("--governance-dir", required=True)
    corrective_bundle_plan.add_argument("--result-commit", required=True)
    corrective_bundle_plan.add_argument("--receipt-import", required=True)
    corrective_bundle_plan.add_argument("--expected-receipt-plan-digest", required=True)
    corrective_bundle_plan.add_argument("--plan-dir", required=True)
    corrective_bundle_plan.add_argument("--repository-root", default=".")
    corrective_bundle_plan.set_defaults(handler=corrective_v2_bundle_plan)

    corrective_bundle_import = subparsers.add_parser(
        "corrective-v2-bundle-import",
        help="Verify the bundle SSHSIG and atomically install only the three C2 records",
    )
    corrective_bundle_import.add_argument("--roadmap", required=True)
    corrective_bundle_import.add_argument("--governance-dir", required=True)
    corrective_bundle_import.add_argument("--plan-dir", required=True)
    corrective_bundle_import.add_argument("--expected-plan-digest", required=True)
    corrective_bundle_import.add_argument("--repository-root", default=".")
    corrective_bundle_import.set_defaults(handler=corrective_v2_bundle_import)

    forecast_decision_plan = subparsers.add_parser(
        "forecast-v2-decision-plan",
        help="Prepare one timestamp-free itemized 68-row/121-occurrence decision claim",
    )
    forecast_decision_plan.add_argument("--roadmap", required=True)
    forecast_decision_plan.add_argument("--governance-dir", required=True)
    forecast_decision_plan.add_argument("--plan-dir", required=True)
    forecast_decision_plan.add_argument("--repository-root", default=".")
    forecast_decision_plan.set_defaults(handler=forecast_v2_decision_plan)

    forecast_decision_import = subparsers.add_parser(
        "forecast-v2-decision-import",
        help="Verify and install the one signed generation-2 batch decision",
    )
    forecast_decision_import.add_argument("--roadmap", required=True)
    forecast_decision_import.add_argument("--governance-dir", required=True)
    forecast_decision_import.add_argument("--plan-dir", required=True)
    forecast_decision_import.add_argument("--expected-plan-digest", required=True)
    forecast_decision_import.add_argument("--repository-root", default=".")
    forecast_decision_import.set_defaults(handler=forecast_v2_decision_import)

    forecast_signature_plan = subparsers.add_parser(
        "forecast-v2-signature-plan",
        help="Prepare timestamp-free producer and acceptance-receipt SSHSIG claims",
    )
    forecast_signature_plan.add_argument("--roadmap", required=True)
    forecast_signature_plan.add_argument("--governance-dir", required=True)
    forecast_signature_plan.add_argument("--plan-dir", required=True)
    forecast_signature_plan.add_argument("--repository-root", default=".")
    forecast_signature_plan.set_defaults(handler=forecast_v2_signature_plan)

    forecast_signature_import = subparsers.add_parser(
        "forecast-v2-signature-import",
        help="Verify and install both timestamp-free final forecast signatures",
    )
    forecast_signature_import.add_argument("--roadmap", required=True)
    forecast_signature_import.add_argument("--governance-dir", required=True)
    forecast_signature_import.add_argument("--plan-dir", required=True)
    forecast_signature_import.add_argument("--expected-plan-digest", required=True)
    forecast_signature_import.add_argument("--repository-root", default=".")
    forecast_signature_import.set_defaults(handler=forecast_v2_signature_import)

    forecast_documentation_check = subparsers.add_parser(
        "forecast-v2-documentation-check",
        help="Validate exact final forecast status/digests in README and ADR before R2",
    )
    forecast_documentation_check.add_argument("--roadmap", required=True)
    forecast_documentation_check.add_argument("--governance-dir", required=True)
    forecast_documentation_check.add_argument("--repository-root", default=".")
    forecast_documentation_check.set_defaults(handler=forecast_v2_documentation_check)

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
    validate.add_argument(
        "--acceptance-generation",
        type=int,
        choices=(1, 2),
        help=(
            "Acceptance generation to prepare or require; omitted live checks preserve "
            "generation 1 and historical checks infer the signed tag generation"
        ),
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
    preflight.add_argument(
        "--acceptance-generation",
        type=int,
        choices=(1, 2),
        help="Acceptance generation whose governed branch and fixed tag are being prepared",
    )
    preflight.set_defaults(handler=acceptance_preflight)
    return parser


def _main_has_active_runtime_bootstrap() -> bool:
    """Detect unsupported invocation, not hostile mutation inside this process.

    Code already executing in this interpreter can mutate Python objects and is
    outside this guard's threat boundary.  Process integrity comes from the
    external reviewed launcher and the import-before-use bootstrap above.  This
    check prevents ordinary imports, ``-m`` execution, displaced entry points,
    and a removed/reordered import guard from being mistaken for that workflow.
    """

    runtime_guard = _BOOTSTRAPPED_RUNTIME_GUARD
    if __name__ != "__main__" or type(runtime_guard) is not _GovernanceRuntimeImportGuard:
        return False
    if not sys.meta_path or sys.meta_path[0] is not runtime_guard:
        return False
    if sum(candidate is runtime_guard for candidate in sys.meta_path) != 1:
        return False
    script_path = Path(__file__).resolve()
    try:
        entry_path = Path(sys.argv[0]).resolve(strict=True)
        site_packages = runtime_guard._site_packages.resolve(strict=True)
    except OSError:
        return False
    expected_site_packages = script_path.parent.parent / ".venv/Lib/site-packages"
    return (
        __spec__ is None
        and _early_normalized_path(entry_path) == _early_normalized_path(script_path)
        and _early_normalized_path(site_packages) == _early_normalized_path(expected_site_packages)
        and bool(sys.path)
        and _early_normalized_path(sys.path[-1]) == _early_normalized_path(site_packages)
    )


def main(argv: Sequence[str] | None = None) -> int:
    if not _main_has_active_runtime_bootstrap():
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
