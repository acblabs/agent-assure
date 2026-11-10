"""Frozen-host orchestration for successor and architecture development acceptance.

Ordinary Python invocation can prepare a bootstrap review request only. All
accepting operations enter through the authenticated S1 PowerShell launcher.
No command signs, reads private keys, changes release policy, or pushes a ref.
"""

from __future__ import annotations

import argparse
import base64
import codecs
import encodings
import json
import os
import re
import sys
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime, timedelta
from importlib.machinery import ModuleSpec
from pathlib import Path
from threading import RLock
from types import ModuleType
from typing import Any, cast

import jsonschema

from agent_assure.rooted_io import (
    claim_rooted_directory,
    open_rooted_bounded_file,
    open_rooted_directory,
)
from scripts import v1_s1_successor as core
from scripts import v1_successor_checks as checks
from scripts import v1_successor_ci as ci
from scripts import v1_successor_forecast as forecast
from scripts import v1_successor_io as git_io

MAX_BYTES = 4 * 1024 * 1024
RUNTIME_FILE_MAX_BYTES = 64 * 1024 * 1024
ROADMAP_DIGEST = "sha256:8fc2e6e6f83b6a6ac6c27492473de8690b9360eac584131b6e8b42785f4386eb"
PRIVATE_PREFIX = ".tmp/s1-acceptance/successor-v3/"
BOOTSTRAP_DOMAIN = b"agent-assure:s1-successor-host-bootstrap/v3\x00"
HUMAN_DOMAIN = b"agent-assure:s1-successor-human-decision/v3\x00"
CORE_SCHEMA = "docs/governance/v1/sprint2/s1-successor-acceptance.schema.json"
HOST_SCHEMA = "docs/governance/v1/sprint2/s1-successor-host.schema.json"
ROOT_PUBLIC_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP7Bgeqxj82OCpkAsF4Qzby2m5PfOnh4lNKzl3fXZ/uB"
ROOT_PERSON = "acblabs"
PREDECESSOR_TAGS = (
    ("agent-assure-s1-1.0.0a1-acceptance", "1f7bfe058dfb84d8cf4afaf971a57e5c3a12a5fb"),
    ("agent-assure-s1-1.0.0a1-acceptance-v2", "aba5ac9111fd2be3a1b0e8e3ac7c3ebb8cb002be"),
)
MODULE_FILES = (
    ("agent_assure.io_limits", "src/agent_assure/io_limits.py"),
    ("agent_assure.rooted_io", "src/agent_assure/rooted_io.py"),
    ("scripts.v1_s1_successor", "scripts/v1_s1_successor.py"),
    ("scripts.v1_successor_forecast", "scripts/v1_successor_forecast.py"),
    ("scripts.v1_successor_io", "scripts/v1_successor_io.py"),
    ("scripts.v1_successor_ci", "scripts/v1_successor_ci.py"),
    ("scripts.v1_successor_checks", "scripts/v1_successor_checks.py"),
    ("scripts.v1_successor_host", "scripts/v1_successor_host.py"),
)
BOOTSTRAP_FILES = (
    "scripts/v1_s1_governance.py",
    "scripts/v1_s1_governance.ps1",
    *(path for _, path in MODULE_FILES),
    CORE_SCHEMA,
    HOST_SCHEMA,
    forecast.SCHEMA_PATH,
    *(str(row["path"]) for row in forecast.PLANNING_INPUT_BINDINGS),
    "scripts/v1_architecture_governance.py",
    *(
        f"docs/governance/v1/sprint2/{name}.schema.json"
        for name in (
            "architecture-package",
            "support-policy",
            "s1-successor-protocol",
            "wire-contract-inventory",
            "occurrence-graph-expectations",
        )
    ),
)
DECISIONS = (
    ("V1-BASE-02", "ADR-V1-EVIDENCE", "docs/adr/0017-v1-evidence-temporal-semantics.md"),
    ("V1-BASE-03", "ADR-V1-AUTH", "docs/adr/0018-v1-verifier-authorization.md"),
    ("V1-BASE-04", "ADR-V1-NUM-STAT", "docs/adr/0019-v1-numerical-statistical-contracts.md"),
    ("V1-BASE-05", "ADR-V1-IO", "docs/adr/0020-v1-bounded-artifact-io.md"),
    ("V1-BASE-06", "ADR-V1-RELEASE-REGISTRY", "docs/adr/0021-v1-release-registry-dispatch.md"),
    ("V1-BASE-09", "ADR-V1-SCHEMA", "docs/adr/0022-v1-schema-wire-contracts.md"),
)
S2_BUNDLE_PATH = "docs/governance/v1/sprint2/accepted-bundle.json"
START_MARKER_PATH = "docs/governance/v1/sprint2/successor-start.json"
_IDNA_RUNTIME_ROOT = Path(
    r"C:\Users\user\AppData\Roaming\uv\python\cpython-3.12.13-windows-x86_64-none"
)
_IDNA_CODEC_SOURCE = _IDNA_RUNTIME_ROOT / "Lib/encodings/idna.py"
_IDNA_CODEC_SIZE = 9710
_IDNA_CODEC_SHA256 = "sha256:9ca58e82d12b171f25d57239ad237dae5c44214a70f2f4f39358c2759b8b9013"
_IDNA_CODEC_LOCK = RLock()
_IDNA_CODEC_MODULE: ModuleType | None = None
_IDNA_CODEC_INFO: codecs.CodecInfo | None = None
_IDNA_CODEC_BINDINGS: dict[str, Any] | None = None


class HostError(core.SuccessorError):
    """A host operation has no valid scoped authority or evidence."""


def utc_now() -> datetime:
    return datetime.now(UTC)


def timestamp(value: datetime) -> str:
    core._now(value)
    return value.isoformat().replace("+00:00", "Z")


def _require(value: bool, message: str) -> None:
    if not value:
        raise HostError(message)


def _idna_runtime_matches() -> bool:
    return (
        os.name == "nt"
        and sys.version_info[:3] == (3, 12, 13)
        and Path(sys.executable).absolute() == _IDNA_RUNTIME_ROOT / "python.exe"
        and bool(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode)
    )


def _prepare_authenticated_idna_codec(legacy: Any) -> None:
    """Load one pinned stdlib dependency without changing the legacy guard.

    The immutable guard's site-only probe mistakes ``encodings.idna`` for the
    unrelated third-party ``idna`` package. The external launcher has already
    authenticated the full base runtime. Lease and recheck this exact source,
    execute its raw bytes, and retain the normal public codec/TLS behavior.
    This runs before collection or any HTTP timeout begins. Unexpected cached
    modules, including independently preloaded stdlib modules, fail closed.
    """
    global _IDNA_CODEC_MODULE, _IDNA_CODEC_INFO, _IDNA_CODEC_BINDINGS
    _require(
        legacy._main_has_active_runtime_bootstrap() is True and _idna_runtime_matches(),
        "authenticated IDNA preparation requires the frozen base runtime",
    )
    guard = getattr(legacy, "_BOOTSTRAPPED_RUNTIME_GUARD", None)
    guard_type = getattr(legacy, "_GovernanceRuntimeImportGuard", None)
    _require(
        guard_type is not None
        and type(guard) is guard_type
        and bool(sys.meta_path)
        and sys.meta_path[0] is guard
        and sum(candidate is guard for candidate in sys.meta_path) == 1,
        "authenticated IDNA preparation requires the unchanged legacy guard",
    )
    finders = tuple(sys.meta_path)

    def guard_unchanged() -> bool:
        return len(sys.meta_path) == len(finders) and all(
            current is original for current, original in zip(sys.meta_path, finders, strict=True)
        )

    with _IDNA_CODEC_LOCK:
        try:
            with open_rooted_bounded_file(
                Path(_IDNA_CODEC_SOURCE.anchor),
                _IDNA_CODEC_SOURCE.relative_to(_IDNA_CODEC_SOURCE.anchor),
                max_bytes=_IDNA_CODEC_SIZE,
                label="authenticated stdlib IDNA source",
            ) as descriptor:
                raw = descriptor.contents.data
                _require(
                    len(raw) == _IDNA_CODEC_SIZE and core.content_digest(raw) == _IDNA_CODEC_SHA256,
                    "authenticated stdlib IDNA source bytes changed",
                )
                if _IDNA_CODEC_MODULE is not None:
                    module = _IDNA_CODEC_MODULE
                    _require(
                        sys.modules.get("encodings.idna") is module
                        and vars(encodings).get("idna") is module
                        and module.__name__ == "encodings.idna"
                        and module.__file__ == str(_IDNA_CODEC_SOURCE)
                        and module.__package__ == "encodings"
                        and type(module.__spec__) is ModuleSpec
                        and module.__spec__.origin == str(_IDNA_CODEC_SOURCE)
                        and module.__spec__.loader is None
                        and module.__cached__ is None
                        and _IDNA_CODEC_BINDINGS is not None
                        and module.__dict__.keys() == _IDNA_CODEC_BINDINGS.keys()
                        and all(
                            module.__dict__[key] is value
                            for key, value in _IDNA_CODEC_BINDINGS.items()
                        )
                        and codecs.lookup("idna") is _IDNA_CODEC_INFO
                        and "api.github.com".encode("idna") == b"api.github.com"
                        and guard_unchanged(),
                        "authenticated stdlib IDNA module identity changed",
                    )
                    return
                _require(
                    "encodings.idna" not in sys.modules and "idna" not in vars(encodings),
                    "unexpected preloaded stdlib IDNA module",
                )
                module = ModuleType("encodings.idna")
                module.__file__ = str(_IDNA_CODEC_SOURCE)
                module.__package__ = "encodings"
                module.__spec__ = ModuleSpec(
                    "encodings.idna", loader=None, origin=str(_IDNA_CODEC_SOURCE)
                )
                module.__dict__["__cached__"] = None
                try:
                    # Compile leased source directly; never consult or create pyc.
                    exec(
                        compile(raw, str(_IDNA_CODEC_SOURCE), "exec", dont_inherit=True),
                        module.__dict__,
                    )
                    sys.modules["encodings.idna"] = module
                    vars(encodings)["idna"] = module
                    info = codecs.lookup("idna")
                    _require(
                        type(info) is codecs.CodecInfo
                        and info.name == "idna"
                        and getattr(info.encode, "__func__", None) is module.Codec.encode
                        and getattr(info.decode, "__func__", None) is module.Codec.decode
                        and info.incrementalencoder is module.IncrementalEncoder
                        and info.incrementaldecoder is module.IncrementalDecoder
                        and "api.github.com".encode("idna") == b"api.github.com"
                        and guard_unchanged(),
                        "authenticated stdlib IDNA codec registration failed",
                    )
                    _IDNA_CODEC_MODULE, _IDNA_CODEC_INFO = module, info
                    _IDNA_CODEC_BINDINGS = dict(module.__dict__)
                except BaseException:
                    if sys.modules.get("encodings.idna") is module:
                        del sys.modules["encodings.idna"]
                    if vars(encodings).get("idna") is module:
                        delattr(encodings, "idna")
                    raise
        except HostError:
            raise
        except Exception as exc:
            raise HostError("authenticated stdlib IDNA preparation failed") from exc


def _closed(value: object, fields: set[str]) -> dict[str, Any]:
    return core._object(value, fields=fields)


def parse_json(raw: bytes) -> dict[str, Any]:
    # Use the same duplicate/float/depth policy for every persisted host input.
    depth = 0
    quoted = escaped = False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            _require(depth <= 48, "host JSON nesting limit exceeded")
        elif byte in (93, 125):
            depth -= 1
    return core._load_json(raw, canonical=False)


def _safe_strings(value: object) -> None:
    if isinstance(value, str):
        _require(
            unicodedata.normalize("NFC", value) == value
            and not any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in value),
            "host governance strings require NFC without controls or surrogates",
        )
    elif isinstance(value, dict):
        for key, item in value.items():
            _safe_strings(key)
            _safe_strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _safe_strings(item)


def read_bytes(root: Path, path: str, *, maximum: int = MAX_BYTES) -> bytes:
    core.prepare_kickoff_claim(
        base_commit="0" * 40,
        allowed_paths=(path,),
        work_limits={
            "maximum_changed_files": 1,
            "maximum_diff_lines": 1,
            "maximum_wall_clock_seconds": 1,
        },
        policy_digest="sha256:" + "0" * 64,
        schema_digest="sha256:" + "0" * 64,
        signer_person_id="path-validation",
    )
    with open_rooted_bounded_file(
        root, path, max_bytes=maximum, label="successor host input"
    ) as fd:
        return fd.contents.data


def read_json(root: Path, path: str) -> dict[str, Any]:
    return parse_json(read_bytes(root, path))


def _private(path: str) -> None:
    _require(
        path.startswith(PRIVATE_PREFIX) and len(path.split("/")) >= 5,
        "successor outputs require an explicit private v3 run path",
    )
    _require(
        all(part not in {"", ".", ".."} for part in path.split("/")),
        "noncanonical successor output path",
    )


def write_new(root: Path, path: str, payload: bytes, *, maximum: int = MAX_BYTES) -> None:
    """No-clobber publication through pinned, no-follow directory handles."""
    _private(path)
    _require(
        type(maximum) is int
        and 0 < maximum <= RUNTIME_FILE_MAX_BYTES
        and len(payload) <= maximum
        and (
            maximum <= 16 * 1024 * 1024
            or re.fullmatch(
                re.escape(PRIVATE_PREFIX) + r"[A-Za-z0-9_-]{1,63}/clone/\.venv/.+", path
            )
            is not None
        ),
        "successor output byte limit exceeded",
    )
    parent_parts = path.split("/")[:-1]
    # Existing ancestors are leased from the trusted root. Newly created ones
    # are identity-checked after releasing the exclusive Windows claim.
    from contextlib import ExitStack

    with ExitStack() as stack:
        parent = stack.enter_context(open_rooted_directory(root, ".", label="successor root"))
        for index, part in enumerate(parent_parts):
            expected: tuple[int, int] | None = None
            try:
                parent.stat_entry_no_follow(part)
            except FileNotFoundError:
                with claim_rooted_directory(
                    parent, part, label="successor private directory"
                ) as owned:
                    expected = (owned.device, owned.inode)
            lease = stack.enter_context(
                open_rooted_directory(
                    root, Path(*parent_parts[: index + 1]), label="successor private directory"
                )
            )
            _require(
                expected is None or expected == (lease.device, lease.inode),
                "successor private directory changed",
            )
            parent = lease
        name = path.split("/")[-1]
        descriptor = parent.open_regular_file_exclusive(name)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        observed = parent.read_file_bounded(name, max_bytes=maximum, label="successor output")
        _require(observed.data == payload, "successor output read-back differs")


def write_json(root: Path, path: str, value: Mapping[str, Any]) -> None:
    write_new(root, path, core.canonical_bytes(dict(value)))


def _inventory(root: Path) -> list[dict[str, Any]]:
    result = []
    for path in BOOTSTRAP_FILES:
        data = read_bytes(root, path)
        result.append({"path": path, "size_bytes": len(data), "sha256": core.content_digest(data)})
    return result


def _trust_digest(trust: Mapping[str, Any]) -> str:
    return core.content_digest(
        b"agent-assure:s1-successor-trust-snapshot/v3\x00" + core.canonical_bytes(dict(trust))
    )


def powershell_identity() -> dict[str, Any]:
    path = Path(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
    _require(os.name == "nt" and path.is_absolute(), "the adopted S1 host is native Windows")
    for ancestor in (path, *path.parents):
        info = ancestor.lstat()
        _require(
            not ancestor.is_symlink() and not getattr(info, "st_file_attributes", 0) & 0x400,
            "PowerShell trust-base path contains a reparse point",
        )
    before = path.stat()
    _require(before.st_size <= MAX_BYTES, "PowerShell trust-base executable exceeds explicit bound")
    raw = path.read_bytes()
    after = path.stat()
    _require(
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        and len(raw) == before.st_size,
        "PowerShell trust-base executable changed",
    )
    return {"path": str(path), "size_bytes": len(raw), "sha256": core.content_digest(raw)}


def _policy(root: Path, trust: Mapping[str, Any]) -> core.SuccessorPolicy:
    return core.SuccessorPolicy(
        trust_snapshot_digest=_trust_digest(trust),
        signer_person_id=ROOT_PERSON,
        workflow_digest=core.content_digest(read_bytes(root, ".github/workflows/ci.yml")),
        expected_validator_digest=core.content_digest(
            read_bytes(root, "scripts/v1_s1_governance.py")
        ),
        required_ci_instances=core.MANDATORY_CI_INSTANCES,
        required_local_checks=core.MANDATORY_LOCAL_CHECKS,
        required_native_controls=core.MANDATORY_NATIVE_CONTROLS,
        predecessor_tag_objects=PREDECESSOR_TAGS,
    )


def prepare_bootstrap(root: Path, profile: Mapping[str, Any], *, now: datetime) -> dict[str, Any]:
    """Prepare explicit proposed scope extensions; a signature is still required."""
    trust = _closed(
        dict(profile),
        {
            "person_id",
            "key_id",
            "public_key",
            "competence_scopes",
            "conflicts",
            "review_capacity",
            "valid_from_utc",
            "valid_until_utc",
            "mode",
            "independence",
            "roles",
        },
    )
    _require(
        trust["person_id"] == ROOT_PERSON and trust["public_key"] == ROOT_PUBLIC_KEY,
        "bootstrap root key/identity differs from the confirmed S1 root",
    )
    _require(
        trust["mode"] == "maintainer_development"
        and trust["independence"] == "NO_INDEPENDENT_REVIEW",
        "unsupported bootstrap mode",
    )
    _require(
        set(core._strings(trust["roles"])) == {"repository_maintainer", "technical_lead"},
        "explicit development role assignments are required",
    )
    _require(
        {"planning_governance:s1_successor", "schema_compatibility"}
        <= set(core._strings(trust["competence_scopes"])),
        "explicit scope extension missing",
    )
    _require(
        bool(core._strings(trust["conflicts"]))
        and bool(core._text(trust["review_capacity"], owner="human review capacity")),
        "human competence/conflict/capacity declaration is incomplete",
    )
    start, end = core._time(trust["valid_from_utc"]), core._time(trust["valid_until_utc"])
    _require(
        start <= core._now(now) < end and end - start <= timedelta(days=30),
        "bootstrap validity is future, stale, or excessive",
    )
    inventory = _inventory(root)
    expansion = checks.expansion_projection(core.content_digest(read_bytes(root, "Makefile")))
    trust["implementation_binding"] = core.content_digest(core.canonical_bytes(inventory))
    trust["local_check_expansion_digest"] = core.content_digest(
        b"agent-assure:s1-local-check-expansion/v3\x00" + core.canonical_bytes(expansion)
    )
    trust["capture_repository_root"] = str(root.absolute())
    trust["powershell_identity"] = powershell_identity()
    policy = _policy(root, trust)
    claim = {
        "format": "agent-assure-s1-successor-host-bootstrap/3",
        "purpose": "scoped_development_trust_and_bootstrap",
        "authorization_effect": "development_governance_only",
        "trust": trust,
        "policy": asdict(policy),
        "policy_digest": core.successor_policy_digest(policy),
        "implementation_inventory": inventory,
        "local_check_expansion": expansion,
        "exclusions": [
            "no_independent_review",
            "no_method_admission",
            "no_runtime_or_release_authorization",
        ],
        "actual_signature_time_claimed": False,
    }
    _safe_strings(claim)
    return parse_json(core.canonical_bytes(claim))


def policy_from_claim(claim: Mapping[str, Any]) -> core.SuccessorPolicy:
    data = _closed(claim["policy"], set(core.SuccessorPolicy.__dataclass_fields__))
    for field in ("required_ci_instances", "required_local_checks", "required_native_controls"):
        data[field] = tuple(core._strings(data[field]))
    tags = data["predecessor_tag_objects"]
    _require(
        type(tags) is list and all(type(row) is list and len(row) == 2 for row in tags),
        "invalid predecessor tag policy",
    )
    data["predecessor_tag_objects"] = tuple(tuple(row) for row in tags)
    policy = core.SuccessorPolicy(**data)
    core._validate_policy(policy)
    _require(
        claim["policy_digest"] == core.successor_policy_digest(policy), "policy binding differs"
    )
    _require(
        policy.trust_snapshot_digest == _trust_digest(core._object(claim["trust"])),
        "trust snapshot differs from verifier policy",
    )
    return policy


def bootstrap_claim_bytes(claim: Mapping[str, Any]) -> bytes:
    return BOOTSTRAP_DOMAIN + core.canonical_bytes(dict(claim))


@dataclass(frozen=True)
class CollectedEvidence:
    evidence: core.VerifiedEvidence
    source: dict[str, Any]


def proposed_human_estimates(ledger: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Concrete editable proposals, never inferred human decisions or actuals."""
    rows = ledger.get("rows")
    _require(type(rows) is list and 0 < len(rows) <= 4096, "forecast source rows are missing")
    result = []
    for row in cast(list[dict[str, Any]], rows):
        estimates = []
        for occurrence in row["execution_proposals"]:
            effort = occurrence["effort_proposal"]
            estimates.append(
                {
                    "occurrence_id": occurrence["occurrence_id"],
                    "p50_effort_hours": effort["p50_effort_hours"],
                    "p90_effort_hours": effort["p90_effort_hours"],
                    "reviewer_p50_effort_hours": effort["reviewer_p50_effort_hours"],
                    "rationale": (
                        "Proposed adoption after reviewing the bound work breakdown "
                        "and exact file scope; subjective planning only."
                    ),
                }
            )
        result.append(
            {
                "ticket_id": row["ticket_id"],
                "estimate_scope": row["estimate_scope"],
                "execution_estimates": estimates,
            }
        )
    return result


def human_estimate_summary(ledger: Mapping[str, Any], selected: object) -> dict[str, Any]:
    """Validate all ticket/occurrence identities and reconcile named quantiles."""
    defaults = proposed_human_estimates(ledger)
    _require(
        type(selected) is list and len(selected) == len(defaults),
        "forecast must cover every source ticket exactly once",
    )
    totals = {
        "engineering_p50_effort_hours": 0,
        "engineering_p90_effort_hours": 0,
        "reviewer_p50_effort_hours": 0,
    }
    seen: set[str] = set()
    for expected, raw in zip(defaults, cast(list[Any], selected), strict=True):
        row = _closed(raw, {"ticket_id", "estimate_scope", "execution_estimates"})
        _require(
            row["ticket_id"] == expected["ticket_id"]
            and row["estimate_scope"] == expected["estimate_scope"]
            and row["ticket_id"] not in seen,
            "forecast ticket identity, scope or order differs",
        )
        seen.add(row["ticket_id"])
        estimates = row["execution_estimates"]
        _require(
            type(estimates) is list and len(estimates) == len(expected["execution_estimates"]),
            "forecast occurrence set is incomplete",
        )
        for occurrence, wanted in zip(estimates, expected["execution_estimates"], strict=True):
            value = _closed(
                occurrence,
                {
                    "occurrence_id",
                    "p50_effort_hours",
                    "p90_effort_hours",
                    "reviewer_p50_effort_hours",
                    "rationale",
                },
            )
            _require(
                value["occurrence_id"] == wanted["occurrence_id"],
                "forecast occurrence identity/order differs",
            )
            p50 = core._integer(value["p50_effort_hours"], minimum=1)
            p90 = core._integer(value["p90_effort_hours"], minimum=1)
            review = core._integer(value["reviewer_p50_effort_hours"], minimum=1)
            _require(
                p50 <= p90 <= 10_000_000 and review <= 10_000_000,
                "forecast quantiles are inverted or exceed the planning representation budget",
            )
            core._text(value["rationale"], owner="human estimate rationale")
            totals["engineering_p50_effort_hours"] += p50
            totals["engineering_p90_effort_hours"] += p90
            totals["reviewer_p50_effort_hours"] += review
    return {
        "method_id": "comonotonic-quantile-sum/v1",
        "dependence_assumption": "full_positive_rank_dependence_no_diversification_credit",
        **totals,
        "combined_p90_effort_hours": None,
        "elapsed_waits_included": False,
        "confidence_basis": "human_adopted_subjective_uncalibrated_planning_quantiles",
        "calendar_commitment": False,
    }


class HostBoundary:
    """Actual signature/Git boundary with a collector-owned evidence registry.

    During collection only authenticated source adapters register evidence.
    During replay a signed aggregate receipt binds all loaded evidence digests;
    every source witness is checked again by its source-specific validator.
    There is no public register-passed-JSON operation.
    """

    def __init__(
        self,
        *,
        root: Path,
        reader: git_io.GitReader,
        key: git_io.TrustedKey,
        verify_callback: Callable[..., None],
        policy: core.SuccessorPolicy,
        trust: Mapping[str, Any],
        now: Callable[[], datetime] = utc_now,
    ) -> None:
        self.root, self.reader, self.key = root, reader, key
        self.verify_callback, self.policy, self.now = verify_callback, policy, now
        self.trust = dict(trust)
        self._evidence: dict[str, CollectedEvidence] = {}
        self._signatures: dict[tuple[str, str, str], core.VerifiedSignature] = {}
        self._tags: dict[str, core.VerifiedTag] = {}
        self._publication: core.VerifiedEvidence | None = None

    def _record(
        self,
        kind: str,
        subject: str,
        payload: Mapping[str, Any],
        source: Mapping[str, Any],
        *,
        observed_at: datetime | None = None,
        valid_until: datetime | None = None,
    ) -> str:
        current = self.now() if observed_at is None else core._now(observed_at)
        _require(current <= self.now(), "a source observation cannot be future-dated")
        expiry = min(
            current + timedelta(seconds=self.policy.maximum_age_seconds),
            core._time(self.key.valid_until_utc),
        )
        if valid_until is not None:
            expiry = min(expiry, core._now(valid_until))
        _require(current < expiry, "source evidence has no remaining validity interval")
        document = {
            "format": "agent-assure-s1-successor-evidence/3",
            "kind": kind,
            "subject_commit": subject,
            "issued_at_utc": timestamp(current),
            "valid_until_utc": timestamp(expiry),
            "payload": dict(payload),
            "source_witness_digest": core.content_digest(core.canonical_bytes(dict(source))),
        }
        evidence = core.VerifiedEvidence(core.canonical_bytes(document))
        digest = core.evidence_digest(evidence)
        self._evidence[digest] = CollectedEvidence(
            evidence, parse_json(core.canonical_bytes(dict(source)))
        )
        return digest

    def resolve_evidence(self, digest: str, kind: str) -> core.VerifiedEvidence:
        try:
            record = self._evidence[digest]
        except KeyError as exc:
            raise HostError(
                "evidence was not produced or authenticated by this host session"
            ) from exc
        document = parse_json(record.evidence.canonical_payload)
        _require(document["kind"] == kind, "evidence kind substitution")
        _require(core.evidence_digest(record.evidence) == digest, "evidence bytes changed")
        _require(
            document.get("source_witness_digest")
            == core.content_digest(core.canonical_bytes(record.source)),
            "evidence source witness changed",
        )
        return record.evidence

    def resolve_commit(self, oid: str) -> core.GitCommit:
        return self.reader.resolve_commit(oid)

    def require_ancestor(self, ancestor: str, descendant: str) -> None:
        self.reader.require_ancestor(ancestor, descendant)

    def read_commit_artifact(self, commit: str, path: str) -> bytes:
        return self.reader.read_commit_artifact(commit, path)

    def changed_paths(self, base_commit: str, target_commit: str) -> tuple[str, ...]:
        return self.reader.changed_paths(base_commit, target_commit)

    def verify_signature(
        self, payload: bytes, envelope: Mapping[str, Any], purpose: str
    ) -> core.VerifiedSignature:
        identity = (
            core.content_digest(payload),
            core.content_digest(core.canonical_bytes(dict(envelope))),
            purpose,
        )
        try:
            return self._signatures[identity]
        except KeyError as exc:
            raise HostError(
                "signature must be cryptographically checked before the validation cutoff"
            ) from exc

    def preverify_signature(
        self, payload: bytes, envelope: Mapping[str, Any], purpose: str
    ) -> core.VerifiedSignature:
        verified = git_io.verify(
            payload, envelope, self.key, self.verify_callback, now=self.now, purpose=purpose
        )
        identity = (
            core.content_digest(payload),
            core.content_digest(core.canonical_bytes(dict(envelope))),
            purpose,
        )
        self._signatures[identity] = verified
        return verified

    def resolve_tag(self, name: str) -> core.VerifiedTag:
        tag = self.reader.read_annotated_tag(name)
        # Historical fixed tags retain their existing v1/v2 signature formats;
        # their exact immutable Git object IDs are the accepted policy anchors.
        if name in dict(self.policy.predecessor_tag_objects):
            _require(
                tag.object_oid == dict(self.policy.predecessor_tag_objects)[name],
                "immutable predecessor tag changed",
            )
            return core.VerifiedTag(tag.object_oid, tag.target_commit, b"", None)
        _require(name == core.SUCCESSOR_TAG, "unregistered successor tag")
        message = parse_json(tag.message)
        _closed(message, {"claim", "signature_envelope"})
        claim = core.canonical_bytes(message["claim"])
        verified = self.verify_signature(
            claim, message["signature_envelope"], "s1-successor-tag/v3"
        )
        return core.VerifiedTag(tag.object_oid, tag.target_commit, claim, verified)

    def preverify_tag(self) -> core.VerifiedTag:
        tag = self.reader.read_annotated_tag(core.SUCCESSOR_TAG)
        message = _closed(parse_json(tag.message), {"claim", "signature_envelope"})
        claim = core.canonical_bytes(message["claim"])
        verified = self.preverify_signature(
            claim, message["signature_envelope"], "s1-successor-tag/v3"
        )
        result = core.VerifiedTag(tag.object_oid, tag.target_commit, claim, verified)
        self._tags[core.SUCCESSOR_TAG] = result
        return result

    def export_evidence(self) -> dict[str, Any]:
        return {
            digest: {"document": parse_json(row.evidence.canonical_payload), "source": row.source}
            for digest, row in sorted(self._evidence.items())
        }

    def resolve_publication(self, tag: core.VerifiedTag) -> core.VerifiedEvidence:
        _require(
            self._publication is not None, "human countersigned publication observation is missing"
        )
        publication = cast(core.VerifiedEvidence, self._publication)
        document = parse_json(publication.canonical_payload)
        _require(
            document["payload"]["tag_object"] == tag.object_oid,
            "publication observation belongs to another tag",
        )
        return publication


def _signing_output(root: Path, out: str, claim: Mapping[str, Any], payload: bytes) -> None:
    _private(out + "/claim.json")
    write_json(root, out + "/claim.json", dict(claim))
    write_new(root, out + "/claim", payload)
    write_json(
        root,
        out + "/request.json",
        {
            "format": "agent-assure-s1-successor-signing-request/3",
            "status": "pending_human_signature",
            "claim_sha256": core.content_digest(payload),
            "namespace": core.SIGNATURE_NAMESPACE,
            "signature_time_capability": "none",
            "authorization_effect": "none",
        },
    )


PURPOSES = (
    "s1-successor-kickoff/v3",
    "s1-successor-acceptance/v3",
    "s1-successor-tag/v3",
    "s1-successor-publication/v3",
    "successor-forecast-producer/v3",
    "successor-forecast-acceptance/v3",
    "s2-drafting/v1",
    "s2-design-acceptance/v1",
    "s2-bundle/v1",
    "successor-source-manifest/v3",
)


def trusted_key(claim: Mapping[str, Any]) -> git_io.TrustedKey:
    trust = core._object(claim["trust"])
    _require(
        trust["public_key"] == ROOT_PUBLIC_KEY and trust["person_id"] == ROOT_PERSON,
        "a bootstrap cannot silently rotate the confirmed root key",
    )
    _require(
        trust["key_id"] == git_io.public_key_fingerprint(ROOT_PUBLIC_KEY),
        "bootstrap key identity differs from its public bytes",
    )
    return git_io.TrustedKey(
        key_id=str(trust["key_id"]),
        person_id=ROOT_PERSON,
        public_key=ROOT_PUBLIC_KEY,
        role="repository_maintainer",
        competence_scopes=tuple(core._strings(trust["competence_scopes"])),
        allowed_purposes=PURPOSES,
        trust_snapshot_digest=_trust_digest(trust),
        valid_from_utc=str(trust["valid_from_utc"]),
        valid_until_utc=str(trust["valid_until_utc"]),
    )


def validate_bootstrap_claim(
    root: Path, claim: Mapping[str, Any], now: datetime
) -> core.SuccessorPolicy:
    _closed(
        dict(claim),
        {
            "format",
            "purpose",
            "authorization_effect",
            "trust",
            "policy",
            "policy_digest",
            "implementation_inventory",
            "local_check_expansion",
            "exclusions",
            "actual_signature_time_claimed",
        },
    )
    _require(
        claim["format"] == "agent-assure-s1-successor-host-bootstrap/3"
        and claim["purpose"] == "scoped_development_trust_and_bootstrap"
        and claim["authorization_effect"] == "development_governance_only"
        and claim["actual_signature_time_claimed"] is False,
        "unsupported bootstrap authority",
    )
    _require(
        claim["exclusions"]
        == ["no_independent_review", "no_method_admission", "no_runtime_or_release_authorization"],
        "bootstrap exclusions were weakened",
    )
    trust = core._object(claim["trust"])
    profile_fields = {
        "person_id",
        "key_id",
        "public_key",
        "competence_scopes",
        "conflicts",
        "review_capacity",
        "valid_from_utc",
        "valid_until_utc",
        "mode",
        "independence",
        "roles",
    }
    _closed(
        trust,
        profile_fields
        | {
            "implementation_binding",
            "local_check_expansion_digest",
            "capture_repository_root",
            "powershell_identity",
        },
    )
    profile = {key: trust[key] for key in profile_fields}
    _require(
        profile["mode"] == "maintainer_development"
        and profile["independence"] == "NO_INDEPENDENT_REVIEW",
        "unsupported development mode",
    )
    _require(
        set(core._strings(profile["roles"])) == {"repository_maintainer", "technical_lead"},
        "explicit development role assignments missing",
    )
    key = trusted_key(claim)
    _require(
        core._time(key.valid_from_utc) <= now < core._time(key.valid_until_utc)
        and core._time(key.valid_until_utc) - core._time(key.valid_from_utc) <= timedelta(days=30),
        "bootstrap scope expired or future",
    )
    _require(
        {"planning_governance:s1_successor", "schema_compatibility"} <= set(key.competence_scopes),
        "required explicit human competence declaration missing",
    )
    _require(
        bool(core._strings(trust["conflicts"]))
        and bool(core._text(trust["review_capacity"], owner="review capacity")),
        "scope conflicts/capacity missing",
    )
    _require(
        claim["implementation_inventory"] == _inventory(root),
        "executing implementation bytes differ from the signed bootstrap",
    )
    _require(
        trust["powershell_identity"] == powershell_identity(),
        "the adopted PowerShell trust-base executable differs",
    )
    _require(
        trust["implementation_binding"]
        == core.content_digest(core.canonical_bytes(_inventory(root))),
        "implementation binding differs",
    )
    expansion = checks.expansion_projection(core.content_digest(read_bytes(root, "Makefile")))
    _require(
        claim["local_check_expansion"] == expansion
        and trust["local_check_expansion_digest"]
        == core.content_digest(
            b"agent-assure:s1-local-check-expansion/v3\x00" + core.canonical_bytes(expansion)
        ),
        "local check expansion is not the adopted exact graph",
    )
    policy = policy_from_claim(claim)
    _require(
        policy == _policy(root, trust), "successor policy differs from the signed implementation"
    )
    return policy


def _native_totals_projection(value: object) -> dict[str, int]:
    """Project validated legacy terminal totals without changing their format."""
    original = _closed(
        value, {"collected", "passed", "failed", "skipped", "xfailed", "xpassed", "errors"}
    )
    totals = {key: core._integer(count) for key, count in original.items()}
    _require(
        totals["collected"] > 0
        and totals["passed"] > 0
        and all(totals[key] == 0 for key in ("failed", "errors", "xfailed", "xpassed"))
        and totals["collected"] == totals["passed"] + totals["skipped"],
        "native legacy totals are not complete and passing for successor acceptance",
    )
    # The authenticated legacy validator rejects deselection by requiring
    # collected == passed + failed + skipped + xfailed + xpassed. Its immutable
    # seven-field record has no deselected member; do not add one to the source.
    return {
        **{key: totals[key] for key in ("collected", "passed", "skipped", "failed", "errors")},
        "deselected": 0,
    }


class FrozenHost:
    """A real host session, constructed only after old-bootstrap authentication."""

    def __init__(
        self,
        legacy: Any,
        root: Path,
        bootstrap: Mapping[str, Any],
        *,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        _require(
            legacy._main_has_active_runtime_bootstrap() is True,
            "accepting operations require the frozen PowerShell runtime",
        )
        self.legacy, self.root, self.clock = legacy, root.absolute(), clock
        self.bootstrap = _closed(dict(bootstrap), {"claim", "signature_envelope"})
        self.claim = core._object(self.bootstrap["claim"])
        self.policy = validate_bootstrap_claim(self.root, self.claim, self.clock())
        self.key = trusted_key(self.claim)
        self.reader = git_io.frozen_tag_publisher(legacy, self.root)
        callback = git_io.frozen_signature_callback(legacy)
        # The old entrypoint verifies this root signature before loading ANY
        # local module. Recheck it here; no JSON verification flag is trusted.
        root_key = replace(self.key, allowed_purposes=("successor-host-bootstrap/v3",))
        git_io.verify(
            bootstrap_claim_bytes(self.claim),
            self.bootstrap["signature_envelope"],
            root_key,
            callback,
            now=self.clock,
            purpose="successor-host-bootstrap/v3",
        )
        _prepare_authenticated_idna_codec(legacy)
        self.boundary = HostBoundary(
            root=self.root,
            reader=self.reader,
            key=self.key,
            verify_callback=callback,
            policy=self.policy,
            trust=core._object(self.claim["trust"]),
            now=self.clock,
        )
        self._last_verification: dict[str, Any] | None = None
        self._last_verification_path: str | None = None

    def _verify_human(self, document: Mapping[str, Any], purpose: str) -> dict[str, Any]:
        value = _closed(dict(document), {"claim", "signature_envelope"})
        claim = core._object(value["claim"])
        _require(
            claim.get("purpose") == purpose
            and claim.get("policy_digest") == self.claim["policy_digest"],
            "human decision purpose or policy binding differs",
        )
        payload = HUMAN_DOMAIN + core.canonical_bytes(claim)
        expected_role = (
            "technical_lead"
            if purpose == "successor-forecast-producer/v3"
            else "repository_maintainer"
        )
        _require(
            claim.get("issuer_role") == expected_role
            and expected_role in self.claim["trust"]["roles"],
            "human decision role differs",
        )
        key = replace(self.key, role=expected_role)
        git_io.verify(
            payload,
            value["signature_envelope"],
            key,
            self.boundary.verify_callback,
            now=self.clock,
            purpose=purpose,
        )
        return claim

    def _implementation_at(self, commit: str) -> None:
        for row in self.claim["implementation_inventory"]:
            raw = self.reader.read_commit_artifact(commit, row["path"])
            _require(
                len(raw) == row["size_bytes"] and core.content_digest(raw) == row["sha256"],
                "the signed implementation is not committed at the prospective base",
            )
        _require(
            core.content_digest(
                self.reader.read_commit_artifact(commit, ".github/workflows/ci.yml")
            )
            == self.policy.workflow_digest,
            "prospective workflow differs from the signed policy",
        )
        make = self.reader.read_commit_artifact(commit, "Makefile")
        _require(
            checks.expansion_projection(core.content_digest(make))
            == self.claim["local_check_expansion"],
            "prospective Makefile differs from the adopted expansion",
        )

    def kickoff_plan(self, request: Mapping[str, Any]) -> dict[str, Any]:
        data = _closed(
            dict(request), {"action", "base_commit", "allowed_paths", "work_limits", "out"}
        )
        base = self.reader.resolve_commit(core._oid(data["base_commit"]))
        self.reader.require_ancestor(core.PREDECESSOR_CLOSURE, base.oid)
        self._implementation_at(base.oid)
        _require(
            base.oid != core.PREDECESSOR_CLOSURE,
            "successor base must include reviewed corrective controls",
        )
        claim, signing = core.prepare_kickoff_claim(
            base_commit=base.oid,
            allowed_paths=tuple(core._strings(data["allowed_paths"])),
            work_limits=core._object(data["work_limits"]),
            policy_digest=self.claim["policy_digest"],
            schema_digest=core.content_digest(read_bytes(self.root, CORE_SCHEMA)),
            signer_person_id=ROOT_PERSON,
        )
        _signing_output(self.root, str(data["out"]), claim, signing.canonical_claim)
        return {
            "result": "kickoff_signature_pending",
            "claim_digest": signing.claim_sha256,
            "authorization_effect": "none",
        }

    def kickoff_import(self, request: Mapping[str, Any]) -> dict[str, Any]:
        data = _closed(dict(request), {"action", "claim", "signature_envelope", "out"})
        claim = core._object(read_json(self.root, str(data["claim"])))
        scope = core._object(claim["scope"])
        reproduced, signing = core.prepare_kickoff_claim(
            base_commit=scope["base_commit"],
            allowed_paths=tuple(core._strings(scope["allowed_paths"])),
            work_limits=core._object(scope["work_limits"]),
            policy_digest=self.claim["policy_digest"],
            schema_digest=core.content_digest(read_bytes(self.root, CORE_SCHEMA)),
            signer_person_id=ROOT_PERSON,
        )
        _require(claim == reproduced, "kickoff differs from its exact scope, policy or schema")
        self.reader.resolve_commit(scope["base_commit"])
        self._implementation_at(scope["base_commit"])
        envelope = read_json(self.root, str(data["signature_envelope"]))
        verified = self.boundary.preverify_signature(
            signing.canonical_claim, envelope, "s1-successor-kickoff/v3"
        )
        # A truthful host observation, not an SSHSIG signing timestamp.
        imported = self.clock()
        result = {
            "format": "agent-assure-s1-successor-kickoff-import/3",
            "claim": claim,
            "signature_envelope": envelope,
            "claim_digest": signing.claim_sha256,
            "verification_completed_at_utc": verified.verification_completed_at_utc,
            "import_observed_at_utc": timestamp(imported),
            "clock_basis": "maintainer_host_utc_externally_unattested",
        }
        write_json(self.root, str(data["out"]) + "/kickoff-import.json", result)
        return {
            "result": "kickoff_imported",
            "claim_digest": signing.claim_sha256,
            "authorization_effect": "bounded_corrective_development_only",
        }

    def _kickoff(self, path: str) -> tuple[dict[str, Any], dict[str, Any]]:
        record = read_json(self.source_root, path)
        _closed(
            record,
            {
                "format",
                "claim",
                "signature_envelope",
                "claim_digest",
                "verification_completed_at_utc",
                "import_observed_at_utc",
                "clock_basis",
            },
        )
        _require(
            record["format"] == "agent-assure-s1-successor-kickoff-import/3"
            and record["clock_basis"] == "maintainer_host_utc_externally_unattested",
            "wrong kickoff import",
        )
        claim = core._object(record["claim"])
        scope = core._object(claim["scope"])
        expected, signing = core.prepare_kickoff_claim(
            base_commit=scope["base_commit"],
            allowed_paths=tuple(core._strings(scope["allowed_paths"])),
            work_limits=core._object(scope["work_limits"]),
            policy_digest=self.claim["policy_digest"],
            schema_digest=core.content_digest(read_bytes(self.root, CORE_SCHEMA)),
            signer_person_id=ROOT_PERSON,
        )
        _require(
            expected == claim and record["claim_digest"] == signing.claim_sha256,
            "kickoff import substitution",
        )
        self.boundary.preverify_signature(
            signing.canonical_claim, record["signature_envelope"], "s1-successor-kickoff/v3"
        )
        _require(
            core._time(record["verification_completed_at_utc"])
            <= core._time(record["import_observed_at_utc"])
            <= self.clock(),
            "kickoff import chronology invalid",
        )
        return record, scope

    def start_work(self, request: Mapping[str, Any]) -> dict[str, Any]:
        data = _closed(dict(request), {"action", "kickoff", "out"})
        kickoff, scope = self._kickoff(str(data["kickoff"]))
        self.reader.require_ancestor(core.PREDECESSOR_CLOSURE, scope["base_commit"])
        started = self.clock()
        _require(
            core._time(kickoff["import_observed_at_utc"]) < started,
            "work must follow kickoff import",
        )
        marker = {
            "format": "agent-assure-s1-successor-work-start/3",
            "base_commit": scope["base_commit"],
            "kickoff_claim_digest": kickoff["claim_digest"],
            "scope_digest": kickoff["claim"]["scope_digest"],
            "started_at_utc": timestamp(started),
            "clock_basis": "maintainer_host_utc_externally_unattested",
        }
        _require(
            START_MARKER_PATH in scope["allowed_paths"],
            "the versioned successor start marker must be prospectively scoped",
        )
        write_json(self.root, str(data["out"]) + "/work-start.json", marker)
        # A small prospective, versioned change makes R3 a genuine nonempty
        # successor without retrospectively authorizing the reviewed tooling
        # already committed at the signed base. This is not a signature.
        with open_rooted_directory(
            self.root,
            str(Path(START_MARKER_PATH).parent.as_posix()),
            label="scoped successor start marker",
        ) as parent:
            descriptor = parent.open_regular_file_exclusive(Path(START_MARKER_PATH).name)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(core.canonical_bytes(marker) + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
        return {"result": "work_start_recorded", "authorization_effect": "none"}

    def forecast_plan(self, request: Mapping[str, Any]) -> dict[str, Any]:
        data = _closed(dict(request), {"action", "kickoff", "result_commit", "roadmap", "out"})
        kickoff, scope = self._kickoff(str(data["kickoff"]))
        result = self.reader.resolve_commit(core._oid(data["result_commit"]))
        self.reader.require_ancestor(scope["base_commit"], result.oid)
        roadmap_path = self.root / str(data["roadmap"])
        self.legacy.validate_local_only_roadmap(self.root, roadmap_path)
        snapshot = self.legacy.load_roadmap(roadmap_path)
        _require(snapshot.raw_digest == ROADMAP_DIGEST, "roadmap differs from accepted source")
        catalog = self._forecast_inputs(result.oid)
        inventory = {
            "result_commit": result.oid,
            "scope_digest": kickoff["claim"]["scope_digest"],
            "changed_paths": list(self.reader.changed_paths(scope["base_commit"], result.oid)),
            "implementation_inventory": _inventory(self.root),
        }
        observed = timestamp(self.clock())
        ledger = self.legacy.build_authoring_ledger_v2(
            snapshot,
            catalog,
            baseline_observations_digest_value=core.content_digest(core.canonical_bytes(inventory)),
            inventory_completed_at=observed,
        )
        selected = proposed_human_estimates(ledger)
        claim = {
            "format": "agent-assure-successor-forecast-decision/3",
            "purpose": "successor-forecast-producer/v3",
            "issuer_role": "technical_lead",
            "policy_digest": self.claim["policy_digest"],
            "baseline_commit": result.oid,
            "scope_digest": kickoff["claim"]["scope_digest"],
            "roadmap_digest": snapshot.raw_digest,
            "inventory": inventory,
            "inventory_observed_at_utc": observed,
            "authoring_ledger": ledger,
            "dispatch_scope_rebaseline": self._dispatch_scope_rebaseline(),
            "human_estimates": selected,
            "estimate_summary": human_estimate_summary(ledger, selected),
            "decision": "HUMAN_REVIEW_REQUIRED",
            "engineering_and_review_quantiles_separate": True,
            "combined_p90_claimed": False,
            "independence": "NO_INDEPENDENT_REVIEW",
        }
        claim["delivery_forecast"] = self._forecast_projection(
            claim,
            snapshot=snapshot,
            kickoff_claim_digest=kickoff["claim_digest"],
            issued_at_utc=observed,
            valid_until_utc=timestamp(
                min(self.clock() + timedelta(days=30), core._time(self.key.valid_until_utc))
            ),
        )
        _signing_output(
            self.root, str(data["out"]), claim, HUMAN_DOMAIN + core.canonical_bytes(claim)
        )
        return {"result": "forecast_review_pending", "authorization_effect": "none"}

    def _forecast_inputs(self, result_commit: str) -> dict[str, Any]:
        """Authenticate immutable planning inputs before decoding their bytes."""
        signed = {row["path"]: row for row in self.claim["implementation_inventory"]}
        payloads: dict[str, bytes] = {}
        for binding in forecast.PLANNING_INPUT_BINDINGS:
            path = str(binding["path"])
            raw = read_bytes(self.root, path)
            _require(
                signed.get(path) == binding
                and len(raw) == binding["size_bytes"]
                and core.content_digest(raw) == binding["sha256"]
                and self.reader.read_commit_artifact(result_commit, path) == raw,
                "forecast planning input differs from frozen method/catalog or tested result",
            )
            payloads[path] = raw
        # Only these exact historical byte strings may contain fractional
        # quantile ranks. General host input retains strict integer JSON.
        prefix = "docs/governance/v1/delivery-forecast."
        catalog = json.loads(payloads[prefix + "estimation-catalog.json"])
        registry = json.loads(payloads[prefix + "aggregation-registry.json"])
        self.legacy.validate_estimation_catalog_v2(
            catalog, json.loads(payloads[prefix + "estimation-catalog.schema.json"])
        )
        self.legacy._resolve_aggregation_method_v2(registry)
        jsonschema.Draft202012Validator(
            json.loads(payloads[prefix + "aggregation-registry.schema.json"])
        ).validate(registry)
        return cast(dict[str, Any], catalog)

    def _forecast_projection(
        self,
        claim: Mapping[str, Any],
        *,
        snapshot: Any,
        kickoff_claim_digest: str,
        issued_at_utc: str,
        valid_until_utc: str,
    ) -> dict[str, Any]:
        trust = self.claim["trust"]
        source = {
            "roadmap_digest": snapshot.raw_digest,
            "ticket_set_digest": snapshot.ticket_set_digest,
            "dependency_graph_digest": snapshot.dependency_graph_digest,
            "release_train_digest": snapshot.release_train_digest,
            "baseline_commit": claim["baseline_commit"],
            "kickoff_claim_digest": kickoff_claim_digest,
            "scope_digest": claim["scope_digest"],
            "trust_snapshot_digest": self.policy.trust_snapshot_digest,
            "inventory_digest": core.content_digest(core.canonical_bytes(claim["inventory"])),
            "dispatch_scope_digest": core.content_digest(
                core.canonical_bytes(claim["dispatch_scope_rebaseline"])
            ),
            "approval_roster": {
                key: trust[key]
                for key in (
                    "person_id",
                    "roles",
                    "competence_scopes",
                    "conflicts",
                    "review_capacity",
                    "mode",
                    "independence",
                )
            },
            "planning_input_bindings": list(forecast.PLANNING_INPUT_BINDINGS),
        }
        projection = forecast.build_projection(
            authoring_ledger=core._object(claim["authoring_ledger"]),
            human_estimates=claim["human_estimates"],
            source=source,
            issued_at_utc=issued_at_utc,
            valid_until_utc=valid_until_utc,
            now=self.clock(),
        )
        schema_raw = read_bytes(self.root, forecast.SCHEMA_PATH)
        signed = {row["path"]: row for row in self.claim["implementation_inventory"]}
        _require(
            signed[forecast.SCHEMA_PATH]["sha256"] == core.content_digest(schema_raw),
            "forecast schema differs from signed bootstrap",
        )
        schema = parse_json(schema_raw)
        _require(
            not any(not ref.startswith("#/") for ref in _schema_references(schema)),
            "external forecast schema resolution is forbidden",
        )
        jsonschema.Draft202012Validator(schema).validate(projection)
        return projection

    def _dispatch_scope_rebaseline(self) -> dict[str, Any]:
        scopes = []
        for ticket, _, path in DECISIONS:
            raw = read_bytes(self.root, path)
            scopes.append(
                {
                    "ticket_id": ticket,
                    "resolved_allowed_files": [path],
                    "artifacts": [
                        {"path": path, "size_bytes": len(raw), "sha256": core.content_digest(raw)}
                    ],
                    "current_status": "development_proposal_prepared_pending_human_acceptance",
                }
            )
        return {
            "resolved_sprint2_ticket_scopes": scopes,
            "future_ticket_file_scopes": "unresolved_until_their_exact_dispatch_not_zero_work",
            "sunk_effort_or_actual_hours_claimed": False,
            "planning_scope": (
                "full_ticket_and_occurrence_portfolio_with_explicit_current_S2_file_inventory"
            ),
        }

    def forecast_recalculate(self, request: Mapping[str, Any]) -> dict[str, Any]:
        data = _closed(dict(request), {"action", "claim", "out"})
        claim = read_json(self.source_root, str(data["claim"]))
        _require(
            claim.get("format") == "agent-assure-successor-forecast-decision/3"
            and claim.get("decision") == "HUMAN_REVIEW_REQUIRED"
            and claim.get("policy_digest") == self.claim["policy_digest"],
            "only an unsigned pending producer proposal can be recalculated",
        )
        claim["estimate_summary"] = human_estimate_summary(
            claim["authoring_ledger"], claim["human_estimates"]
        )
        previous = core._object(claim["delivery_forecast"])
        claim["delivery_forecast"] = forecast.build_projection(
            authoring_ledger=core._object(claim["authoring_ledger"]),
            human_estimates=claim["human_estimates"],
            source=core._object(previous["source"]),
            issued_at_utc=previous["issued_at_utc"],
            valid_until_utc=previous["valid_until_utc"],
            now=self.clock(),
        )
        _signing_output(
            self.root, str(data["out"]), claim, HUMAN_DOMAIN + core.canonical_bytes(claim)
        )
        return {
            "result": "forecast_quantiles_reconciled_human_decision_pending",
            "authorization_effect": "none",
        }

    def observe_result(self, request: Mapping[str, Any]) -> dict[str, Any]:
        data = _closed(dict(request), {"action", "kickoff", "work_start", "result_commit", "out"})
        kickoff, scope = self._kickoff(str(data["kickoff"]))
        start = read_json(self.root, str(data["work_start"]))
        _closed(
            start,
            {
                "format",
                "base_commit",
                "kickoff_claim_digest",
                "scope_digest",
                "started_at_utc",
                "clock_basis",
            },
        )
        _require(
            start["format"] == "agent-assure-s1-successor-work-start/3"
            and start["base_commit"] == scope["base_commit"]
            and start["kickoff_claim_digest"] == kickoff["claim_digest"]
            and start["scope_digest"] == kickoff["claim"]["scope_digest"],
            "work-start subject differs",
        )
        result = self.reader.resolve_commit(core._oid(data["result_commit"]))
        _require(len(result.parents) == 1, "result is a merge or root commit")
        self.reader.require_ancestor(scope["base_commit"], result.oid)
        changes = self.reader.changed_paths(scope["base_commit"], result.oid)
        lines = self.reader.changed_line_count(scope["base_commit"], result.oid)
        limits = scope["work_limits"]
        observed = self.clock()
        _require(
            bool(changes)
            and set(changes) <= set(scope["allowed_paths"])
            and len(changes) <= limits["maximum_changed_files"]
            and lines <= limits["maximum_diff_lines"],
            "result exceeds the signed scope/work profile",
        )
        _require(
            core._time(kickoff["import_observed_at_utc"])
            < core._time(start["started_at_utc"])
            <= observed
            and (observed - core._time(start["started_at_utc"])).total_seconds()
            <= limits["maximum_wall_clock_seconds"],
            "result work is stale or unbound",
        )
        self.legacy._require_clean_corrective_result_checkout(
            self.root, result_commit=result.oid, owner="successor result observation"
        )
        record = {
            "format": "agent-assure-s1-successor-result-observation/3",
            "result_commit": result.oid,
            "result_parent_commit": result.parents[0],
            "base_commit": scope["base_commit"],
            "scope_digest": kickoff["claim"]["scope_digest"],
            "kickoff_claim_digest": kickoff["claim_digest"],
            "work_started_at_utc": start["started_at_utc"],
            "commit_observed_at_utc": timestamp(observed),
            "changed_paths": list(changes),
            "changed_line_count": lines,
            "allowed_paths": scope["allowed_paths"],
            "clock_basis": "maintainer_host_utc_externally_unattested",
            "work_start_path": data["work_start"],
            "work_start_sha256": core.content_digest(
                read_bytes(self.source_root, str(data["work_start"]))
            ),
        }
        write_json(self.root, str(data["out"]) + "/result-observation.json", record)
        return {
            "result": "exact_result_observed_before_checks",
            "result_commit": result.oid,
            "authorization_effect": "none",
        }

    def _scope_observation(
        self, observation: Mapping[str, Any], kickoff: Mapping[str, Any], scope: Mapping[str, Any]
    ) -> core.GitCommit:
        data = _closed(
            dict(observation),
            {
                "format",
                "result_commit",
                "result_parent_commit",
                "base_commit",
                "scope_digest",
                "kickoff_claim_digest",
                "work_started_at_utc",
                "commit_observed_at_utc",
                "changed_paths",
                "changed_line_count",
                "allowed_paths",
                "clock_basis",
                "work_start_path",
                "work_start_sha256",
            },
        )
        _require(
            data["format"] == "agent-assure-s1-successor-result-observation/3"
            and data["clock_basis"] == "maintainer_host_utc_externally_unattested"
            and data["kickoff_claim_digest"] == kickoff["claim_digest"]
            and data["scope_digest"] == kickoff["claim"]["scope_digest"]
            and data["base_commit"] == scope["base_commit"]
            and data["allowed_paths"] == scope["allowed_paths"],
            "result scope differs from prospective authorization",
        )
        start_raw = read_bytes(self.source_root, str(data["work_start_path"]))
        start = parse_json(start_raw)
        _closed(
            start,
            {
                "format",
                "base_commit",
                "kickoff_claim_digest",
                "scope_digest",
                "started_at_utc",
                "clock_basis",
            },
        )
        _require(
            core.content_digest(start_raw) == data["work_start_sha256"]
            and start["format"] == "agent-assure-s1-successor-work-start/3"
            and start["kickoff_claim_digest"] == kickoff["claim_digest"]
            and start["base_commit"] == scope["base_commit"]
            and start["scope_digest"] == data["scope_digest"]
            and start["started_at_utc"] == data["work_started_at_utc"],
            "work-start observation changed",
        )
        result = self.reader.resolve_commit(core._oid(data["result_commit"]))
        _require(result.parents == (data["result_parent_commit"],), "result parent changed")
        self.reader.require_ancestor(scope["base_commit"], result.oid)
        changed = self.reader.changed_paths(scope["base_commit"], result.oid)
        lines = self.reader.changed_line_count(scope["base_commit"], result.oid)
        limits = scope["work_limits"]
        _require(
            bool(changed)
            and list(changed) == data["changed_paths"]
            and set(changed) <= set(scope["allowed_paths"])
            and len(changed) <= limits["maximum_changed_files"]
            and type(data["changed_line_count"]) is int
            and lines == data["changed_line_count"]
            and lines <= limits["maximum_diff_lines"],
            "result exceeds the actual signed scope or work limits",
        )
        started, observed = (
            core._time(data["work_started_at_utc"]),
            core._time(data["commit_observed_at_utc"]),
        )
        _require(
            core._time(kickoff["import_observed_at_utc"]) < started <= observed <= self.clock()
            and (observed - started).total_seconds() <= limits["maximum_wall_clock_seconds"],
            "result work observation is stale, future or outside budget",
        )
        return result

    def _forecast(
        self,
        path: str,
        acceptance_path: str,
        *,
        base_commit: str,
        kickoff_claim_digest: str,
        result: str,
        scope_digest: str,
        roadmap: str,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        producer_document = read_json(self.source_root, path)
        producer = self._verify_human(producer_document, "successor-forecast-producer/v3")
        _closed(
            producer,
            {
                "format",
                "purpose",
                "issuer_role",
                "policy_digest",
                "baseline_commit",
                "scope_digest",
                "roadmap_digest",
                "inventory",
                "inventory_observed_at_utc",
                "authoring_ledger",
                "dispatch_scope_rebaseline",
                "human_estimates",
                "estimate_summary",
                "decision",
                "engineering_and_review_quantiles_separate",
                "combined_p90_claimed",
                "independence",
                "delivery_forecast",
            },
        )
        _require(
            producer["format"] == "agent-assure-successor-forecast-decision/3"
            and producer["baseline_commit"] == result
            and producer["scope_digest"] == scope_digest
            and producer["decision"] == "accept_reestimated_proposal"
            and producer["engineering_and_review_quantiles_separate"] is True
            and producer["combined_p90_claimed"] is False
            and producer["independence"] == "NO_INDEPENDENT_REVIEW",
            "forecast is stale, pending or overclaimed",
        )
        roadmap_path = self.source_root / roadmap
        self.legacy.validate_local_only_roadmap(self.source_root, roadmap_path)
        snapshot = self.legacy.load_roadmap(roadmap_path)
        _require(
            snapshot.raw_digest == producer["roadmap_digest"] == ROADMAP_DIGEST,
            "forecast roadmap changed",
        )
        inventory = _closed(
            producer["inventory"],
            {"result_commit", "scope_digest", "changed_paths", "implementation_inventory"},
        )
        _require(
            inventory["result_commit"] == result
            and inventory["scope_digest"] == scope_digest
            and inventory["changed_paths"] == list(self.reader.changed_paths(base_commit, result))
            and inventory["implementation_inventory"] == _inventory(self.root),
            "forecast inventory changed",
        )
        catalog = self._forecast_inputs(result)
        expected = self.legacy.build_authoring_ledger_v2(
            snapshot,
            catalog,
            baseline_observations_digest_value=core.content_digest(core.canonical_bytes(inventory)),
            inventory_completed_at=producer["inventory_observed_at_utc"],
        )
        _require(
            producer["authoring_ledger"] == expected,
            "forecast is not the recomputed full-ticket/occurrence proposal",
        )
        _require(
            producer["dispatch_scope_rebaseline"] == self._dispatch_scope_rebaseline(),
            "forecast dispatch scopes differ from current exact artifacts",
        )
        _require(
            producer["estimate_summary"]
            == human_estimate_summary(expected, producer["human_estimates"]),
            "human-selected forecast quantiles are incomplete or unreconciled",
        )
        _require(
            core._time(producer["inventory_observed_at_utc"]) <= self.clock(),
            "future forecast inventory",
        )
        projection = core._object(producer["delivery_forecast"])
        issue = core._time(projection.get("issued_at_utc"))
        expiry = core._time(projection.get("valid_until_utc"))
        _require(
            core._time(self.key.valid_from_utc)
            <= issue
            < expiry
            <= core._time(self.key.valid_until_utc),
            "forecast validity exceeds its explicitly adopted authority",
        )
        _require(
            projection
            == self._forecast_projection(
                producer,
                snapshot=snapshot,
                kickoff_claim_digest=kickoff_claim_digest,
                issued_at_utc=projection["issued_at_utc"],
                valid_until_utc=projection["valid_until_utc"],
            ),
            "delivery-forecast/v1 projection differs from its immutable sources or selected values",
        )
        acceptance_document = read_json(self.source_root, acceptance_path)
        acceptance = self._verify_human(acceptance_document, "successor-forecast-acceptance/v3")
        _closed(
            acceptance,
            {
                "format",
                "purpose",
                "issuer_role",
                "policy_digest",
                "forecast_digest",
                "decision",
                "contract_id",
                "forecast_record_digest",
            },
        )
        digest = core.content_digest(HUMAN_DOMAIN + core.canonical_bytes(producer))
        _require(
            acceptance["format"] == "agent-assure-successor-forecast-acceptance/3"
            and acceptance["forecast_digest"] == digest
            and acceptance["contract_id"] == "delivery-forecast/v1"
            and acceptance["forecast_record_digest"] == projection["record_digest"]
            and acceptance["decision"] == "accept",
            "forecast lacks a separate exact maintainer acceptance",
        )
        return producer, acceptance

    def forecast_acceptance_plan(self, request: Mapping[str, Any]) -> dict[str, Any]:
        data = _closed(dict(request), {"action", "producer_document", "out"})
        producer = self._verify_human(
            read_json(self.root, str(data["producer_document"])), "successor-forecast-producer/v3"
        )
        _require(
            producer.get("decision") == "accept_reestimated_proposal",
            "forecast producer decision is pending",
        )
        claim = {
            "format": "agent-assure-successor-forecast-acceptance/3",
            "purpose": "successor-forecast-acceptance/v3",
            "issuer_role": "repository_maintainer",
            "policy_digest": self.claim["policy_digest"],
            "forecast_digest": core.content_digest(HUMAN_DOMAIN + core.canonical_bytes(producer)),
            "decision": "HUMAN_REVIEW_REQUIRED",
            "contract_id": "delivery-forecast/v1",
            "forecast_record_digest": producer["delivery_forecast"]["record_digest"],
        }
        _signing_output(
            self.root, str(data["out"]), claim, HUMAN_DOMAIN + core.canonical_bytes(claim)
        )
        return {"result": "forecast_maintainer_decision_pending", "authorization_effect": "none"}

    def _native(
        self, path: str, result: core.GitCommit, kickoff_digest: str
    ) -> tuple[str, dict[str, Any]]:
        # First admission always validates the ORIGINAL three files and current
        # clean R3/runtime, not merely an embedded producer summary.
        native = self.legacy.validate_post_v2_control_suite_evidence_source(
            self.root / path,
            expected_subject_commit=result.oid,
            expected_subject_parent_commit=result.parents[0],
            expected_repository_root=self.root,
            require_passed=True,
        )
        execution = native["execution"]
        totals = _native_totals_projection(execution["pytest_totals"])
        payload = {
            "source_format": native["format"],
            "kickoff_claim_digest": kickoff_digest,
            "started_at_utc": native["time_evidence"]["started_at_utc"],
            "completed_at_utc": native["time_evidence"]["completed_at_utc"],
            "exit_code": execution["exit_code"],
            **totals,
            "control_ids": list(self.policy.required_native_controls),
            "source_record_digest": core.content_digest(read_bytes(self.root, path)),
        }
        reference = self.boundary._record(
            "native-full-suite-v4",
            result.oid,
            payload,
            {"type": "native-v4-originals", "path": path},
        )
        return reference, native

    def collect(self, request: Mapping[str, Any], *, token: str) -> dict[str, Any]:
        data = _closed(
            dict(request),
            {
                "action",
                "kickoff",
                "result_observation",
                "roadmap",
                "native_dir",
                "checks_dir",
                "forecast_producer",
                "forecast_acceptance",
                "run_id",
                "run_attempt",
                "out",
            },
        )
        _require(bool(token), "authenticated CI read-back requires an explicit in-memory token")
        kickoff, scope = self._kickoff(str(data["kickoff"]))
        observation = read_json(self.root, str(data["result_observation"]))
        _require(
            observation["kickoff_claim_digest"] == kickoff["claim_digest"]
            and observation["scope_digest"] == kickoff["claim"]["scope_digest"],
            "result observation is unbound",
        )
        result = self._scope_observation(observation, kickoff, scope)
        producer, forecast_acceptance = self._forecast(
            str(data["forecast_producer"]),
            str(data["forecast_acceptance"]),
            base_commit=scope["base_commit"],
            kickoff_claim_digest=kickoff["claim_digest"],
            result=result.oid,
            scope_digest=kickoff["claim"]["scope_digest"],
            roadmap=str(data["roadmap"]),
        )
        refs: dict[str, str] = {}
        refs["kickoff_evidence_digest"] = self.boundary._record(
            "prospective-kickoff",
            core.PREDECESSOR_CLOSURE,
            {
                "claim_digest": kickoff["claim_digest"],
                "scope_digest": kickoff["claim"]["scope_digest"],
                "policy_digest": self.claim["policy_digest"],
                "signature_verification_completed_at_utc": kickoff["verification_completed_at_utc"],
            },
            {
                "type": "kickoff-import",
                "path": data["kickoff"],
                "sha256": core.content_digest(read_bytes(self.source_root, str(data["kickoff"]))),
            },
            observed_at=core._time(kickoff["import_observed_at_utc"]),
        )
        refs["result_evidence_digest"] = self.boundary._record(
            "result-observation",
            result.oid,
            {
                key: observation[key]
                for key in (
                    "work_started_at_utc",
                    "commit_observed_at_utc",
                    "scope_digest",
                    "allowed_paths",
                    "changed_paths",
                )
            },
            {
                "type": "result-observation",
                "path": data["result_observation"],
                "sha256": core.content_digest(
                    read_bytes(self.source_root, str(data["result_observation"]))
                ),
            },
            observed_at=core._time(observation["commit_observed_at_utc"]),
        )
        native_dir = str(data["native_dir"])
        _require(
            native_dir.startswith(".tmp/s1-acceptance/post-v2-control-"),
            "native capture uses the existing v4 namespace",
        )
        self.legacy.capture_post_v2_control_suite_evidence(
            self.root,
            roadmap_path=self.root / str(data["roadmap"]),
            subject_commit=result.oid,
            evidence_directory=native_dir,
        )
        native_path = native_dir + "/post-v2-control-suite-evidence.json"
        native_ref, native = self._native(native_path, result, kickoff["claim_digest"])
        _require(
            core._time(observation["commit_observed_at_utc"])
            <= core._time(native["time_evidence"]["started_at_utc"]),
            "native evidence predates the observed result",
        )
        refs["native_suite_evidence_digest"] = native_ref
        backend = checks.FrozenCheckBackend(
            self.legacy, self.root, result.oid, self.root / str(data["checks_dir"])
        )
        try:
            local = checks.collect_local_checks(
                backend,
                native_v4_evidence_digest=native["evidence_digest"],
                makefile_digest=core.content_digest(read_bytes(self.root, "Makefile")),
                canonical_bytes=core.canonical_bytes,
            )
        except checks.LocalCheckFailure as failed:
            self._write_local(
                str(data["out"]) + "/failed-checks", failed.child_records, failed.raw_streams
            )
            raise
        _require(
            local.expansion_digest == self.claim["trust"]["local_check_expansion_digest"],
            "local expansion approval differs",
        )
        self._write_local(
            str(data["out"]) + "/local-checks", local.child_records, local.raw_streams
        )
        refs["local_checks_evidence_digest"] = self.boundary._record(
            "complete-local-checks",
            result.oid,
            local.payload,
            {"type": "local-check-ledger", "path": str(data["out"]) + "/local-checks/ledger.json"},
        )
        # Start the bounded HTTP budget only after potentially hours of local
        # execution. An eagerly constructed transport would expire unused.
        transport = ci.AuthenticatedGitHubTransport(token)
        readback = ci.read_hosted_ci(
            transport=transport,
            run_id=core._integer(data["run_id"], minimum=1),
            run_attempt=core._integer(data["run_attempt"], minimum=1),
            expected_head_sha=result.oid,
            expected_workflow_digest=self.policy.workflow_digest,
            workflow_blob_reader=self.reader.read_commit_artifact,
            required_ci_instances=self.policy.required_ci_instances,
            now=self.clock(),
        )
        refs["hosted_ci_evidence_digest"] = self.boundary._record(
            "hosted-ci",
            result.oid,
            readback.payload,
            {
                "type": "authenticated-github-readback",
                "observation": readback.observation,
                "run_id": data["run_id"],
                "run_attempt": data["run_attempt"],
            },
        )
        trust = self.claim["trust"]
        refs["roster_evidence_digest"] = self.boundary._record(
            "scoped-roster",
            result.oid,
            {
                "person_id": ROOT_PERSON,
                **{
                    key: trust[key]
                    for key in ("competence_scopes", "conflicts", "review_capacity", "mode")
                },
                "independence": "NO_INDEPENDENT_REVIEW",
            },
            {"type": "signed-bootstrap-scope"},
        )
        refs["signing_key_evidence_digest"] = self.boundary._record(
            "scoped-signing-key",
            result.oid,
            {
                "person_id": ROOT_PERSON,
                "trust_snapshot_digest": self.policy.trust_snapshot_digest,
                "allowed_scopes": ["s1_successor_governance", "s2_development_governance"],
            },
            {"type": "signed-bootstrap-scope"},
        )
        refs["forecast_evidence_digest"] = self.boundary._record(
            "fresh-forecast",
            result.oid,
            {
                "baseline_commit": result.oid,
                "scope_digest": kickoff["claim"]["scope_digest"],
                "disposition": "human_accepted_after_dispatch_scope_rebaseline",
                "forecast_digest": core.content_digest(
                    HUMAN_DOMAIN + core.canonical_bytes(producer)
                ),
                "acceptance_receipt_digest": core.content_digest(
                    HUMAN_DOMAIN + core.canonical_bytes(forecast_acceptance)
                ),
            },
            {
                "type": "signed-forecast",
                "producer": data["forecast_producer"],
                "acceptance": data["forecast_acceptance"],
                "roadmap": data["roadmap"],
            },
            valid_until=core._time(producer["delivery_forecast"]["valid_until_utc"]),
        )
        # Revalidate originals and exact clean R3 after all children/network I/O.
        self.legacy.validate_post_v2_control_suite_evidence_source(
            self.root / native_path,
            expected_subject_commit=result.oid,
            expected_subject_parent_commit=result.parents[0],
            expected_repository_root=self.root,
            require_passed=True,
        )
        pending = core.prepare_successor_acceptance(
            result_commit=result.oid,
            result_parent_commit=result.parents[0],
            scope_digest=kickoff["claim"]["scope_digest"],
            kickoff_claim_digest=kickoff["claim_digest"],
            evidence_references=refs,
            policy=self.policy,
            boundary=self.boundary,
            now=self.clock(),
        )
        pending["valid_until_utc"] = timestamp(self._source_validity_ceiling(pending))
        pending["receipt_digest"] = core.receipt_digest(pending)
        core._validate_inputs(pending, self.policy, self.clock(), self.boundary)
        template, signing = core.prepare_receipt_signing_request(pending)
        _signing_output(
            self.root, str(data["out"]) + "/receipt-signing", template, signing.canonical_claim
        )
        write_json(self.root, str(data["out"]) + "/evidence.json", self.boundary.export_evidence())
        write_json(self.root, str(data["out"]) + "/pending-receipt.json", pending)
        return {
            "result": "authenticated_checks_collected_human_acceptance_pending",
            "receipt_digest": pending["receipt_digest"],
            "authorization_effect": "none",
        }

    def _write_local(
        self, path: str, records: Sequence[Mapping[str, Any]], streams: Sequence[tuple[str, bytes]]
    ) -> None:
        for name, raw in streams:
            write_new(self.root, path + "/" + name, raw, maximum=16 * 1024 * 1024)
        write_json(self.root, path + "/ledger.json", {"records": list(records)})

    @property
    def source_root(self) -> Path:
        path = Path(str(self.claim["trust"]["capture_repository_root"]))
        _require(path.is_absolute(), "capture source root must be explicitly adopted and absolute")
        with open_rooted_directory(path, ".", label="adopted capture source"):
            pass
        return path

    def _load_evidence(self, path: str, accepted: Mapping[str, Any]) -> None:
        previous = self.boundary._evidence
        self.boundary._evidence = dict(previous)
        try:
            self._load_evidence_staged(path, accepted)
        except BaseException:
            self.boundary._evidence = previous
            raise

    def _load_evidence_staged(self, path: str, accepted: Mapping[str, Any]) -> None:
        """Admit persisted witnesses only after exact aggregate signature check.

        Live receipt import revalidates original native sources and human
        signatures. Historical replay uses the retained, explicitly adopted
        capture checkout; it never manufactures an execution in the new clone.
        """
        self.boundary.preverify_signature(
            core.signature_claim(accepted),
            accepted["signature_envelope"],
            "s1-successor-acceptance/v3",
        )
        store = read_json(self.source_root, path)
        references = {
            str(accepted[field]): kind for field, kind in core.EVIDENCE_REFERENCE_FIELDS.items()
        }
        _require(
            set(store) == set(references), "source store is missing or adds signed receipt evidence"
        )
        for reference, kind in references.items():
            row = _closed(store[reference], {"document", "source"})
            document, source = core._object(row["document"]), core._object(row["source"])
            evidence = core.VerifiedEvidence(core.canonical_bytes(document))
            _require(
                core.evidence_digest(evidence) == reference and document["kind"] == kind,
                "persisted source evidence was substituted",
            )
            _require(
                document.get("source_witness_digest")
                == core.content_digest(core.canonical_bytes(source)),
                "source witness does not match signed evidence reference",
            )
            self.boundary._evidence[reference] = CollectedEvidence(evidence, source)
        # Validate each witness, never a JSON 'verified/passed' assertion.
        result = self.reader.resolve_commit(str(accepted["result_commit"]))
        for reference, kind in references.items():
            collected = self.boundary._evidence[reference]
            document = parse_json(collected.evidence.canonical_payload)
            source, payload = collected.source, document["payload"]
            if kind == "prospective-kickoff":
                _closed(source, {"type", "path", "sha256"})
                _require(source["type"] == "kickoff-import", "wrong kickoff source")
                _require(
                    source["sha256"]
                    == core.content_digest(read_bytes(self.source_root, str(source["path"]))),
                    "kickoff import bytes changed",
                )
                kickoff, _ = self._kickoff(str(source["path"]))
                _require(
                    payload
                    == {
                        "claim_digest": kickoff["claim_digest"],
                        "scope_digest": kickoff["claim"]["scope_digest"],
                        "policy_digest": self.claim["policy_digest"],
                        "signature_verification_completed_at_utc": kickoff[
                            "verification_completed_at_utc"
                        ],
                    },
                    "kickoff witness differs from signed scope",
                )
            elif kind == "result-observation":
                _closed(source, {"type", "path", "sha256"})
                _require(
                    source["sha256"]
                    == core.content_digest(read_bytes(self.source_root, str(source["path"]))),
                    "result observation bytes changed",
                )
                observed = read_json(self.source_root, str(source["path"]))
                _require(
                    source["type"] == "result-observation"
                    and observed["result_commit"] == result.oid
                    and payload
                    == {
                        key: observed[key]
                        for key in (
                            "work_started_at_utc",
                            "commit_observed_at_utc",
                            "scope_digest",
                            "allowed_paths",
                            "changed_paths",
                        )
                    },
                    "result observation differs from actual signed scope",
                )
                kickoff_source = self.boundary._evidence[
                    str(accepted["kickoff_evidence_digest"])
                ].source
                kickoff, scope = self._kickoff(str(kickoff_source["path"]))
                self._scope_observation(observed, kickoff, scope)
                # Recompute actual Git changes, not a producer's list.
                _require(
                    tuple(observed["changed_paths"])
                    == self.reader.changed_paths(observed["base_commit"], result.oid)
                    and observed["changed_line_count"]
                    == self.reader.changed_line_count(observed["base_commit"], result.oid),
                    "actual result diff differs from the recorded scope",
                )
            elif kind == "native-full-suite-v4":
                _closed(source, {"type", "path"})
                _require(source["type"] == "native-v4-originals", "wrong native source type")
                native = self.legacy.validate_post_v2_control_suite_evidence_source(
                    self.source_root / str(source["path"]),
                    expected_subject_commit=result.oid,
                    expected_subject_parent_commit=result.parents[0],
                    expected_repository_root=self.source_root,
                    require_passed=True,
                )
                _require(
                    payload["source_record_digest"]
                    == core.content_digest(read_bytes(self.source_root, str(source["path"])))
                    and payload["started_at_utc"] == native["time_evidence"]["started_at_utc"]
                    and payload["completed_at_utc"] == native["time_evidence"]["completed_at_utc"]
                    and payload["exit_code"] == native["execution"]["exit_code"]
                    and all(
                        payload[key] == count
                        for key, count in _native_totals_projection(
                            native["execution"]["pytest_totals"]
                        ).items()
                    ),
                    "native normalized payload differs from original evidence",
                )
            elif kind == "complete-local-checks":
                _closed(source, {"type", "path"})
                _require(source["type"] == "local-check-ledger", "wrong local check source")
                ledger = read_json(self.source_root, str(source["path"]))
                _closed(ledger, {"records"})
                records = ledger["records"]
                _require(
                    type(records) is list
                    and len(records) == len(checks.make_check_expansion()) + 1,
                    "local child graph incomplete",
                )
                children, aggregate = records[:-1], records[-1]
                _require(
                    aggregate["children"] == children
                    and aggregate["expansion"] == self.claim["local_check_expansion"]
                    and aggregate["expansion_digest"]
                    == self.claim["trust"]["local_check_expansion_digest"],
                    "local check expansion changed",
                )
                digest = core.content_digest(
                    b"agent-assure:s1-local-check-ledger/v3\x00" + core.canonical_bytes(aggregate)
                )
                _require(
                    payload["checks"][0]["output_digest"] == digest
                    and payload["checks"][1]["output_digest"]
                    == core.content_digest(core.canonical_bytes(children[-1])),
                    "local child ledger differs from signed outputs",
                )
                checks.validate_ruff_binary(self.source_root)
                for child, spec in zip(children, checks.make_check_expansion(), strict=True):
                    _require(
                        child["id"] == spec.check_id
                        and type(child["exit_code"]) is int
                        and child["exit_code"] == 0
                        and child["command"]["spec"] == checks._spec_record(spec)
                        and child["command"].get("native_tool")
                        == (dict(checks.RUFF_BINARY_IDENTITY) if spec.module == "ruff" else None),
                        "local child command or result differs",
                    )
                    for channel in ("stdout", "stderr"):
                        stream = child[channel]
                        raw = read_bytes(
                            self.source_root,
                            str(Path(str(source["path"])).parent.as_posix())
                            + "/"
                            + stream["file_name"],
                            maximum=16 * 1024 * 1024,
                        )
                        _require(
                            len(raw) == stream["size_bytes"]
                            and core.content_digest(raw) == stream["sha256"],
                            "local check diagnostic bytes differ",
                        )
            elif kind == "hosted-ci":
                _closed(source, {"type", "observation", "run_id", "run_attempt"})
                _require(
                    source["type"] == "authenticated-github-readback"
                    and payload["run_id"] == str(source["run_id"])
                    and payload["run_attempt"] == source["run_attempt"],
                    "CI witness differs from authenticated collection",
                )
                # The source witness is now digest-bound to the human-signed
                # aggregate. Replay preserves that authenticated observation;
                # it does not claim a fresh network call or TLS timestamp.
                _require(
                    source["observation"].get("transport_profile")
                    == "fixed-host-authenticated-https-no-redirect/v1"
                    and source["observation"].get("api_host") == ci.API_HOST
                    and source["observation"].get("workflow_blob_sha256")
                    == self.policy.workflow_digest,
                    "unsupported original CI authentication contract",
                )
            elif kind == "scoped-roster":
                _require(source == {"type": "signed-bootstrap-scope"}, "wrong roster source")
                expected = {
                    "person_id": ROOT_PERSON,
                    **{
                        key: self.claim["trust"][key]
                        for key in ("competence_scopes", "conflicts", "review_capacity", "mode")
                    },
                    "independence": "NO_INDEPENDENT_REVIEW",
                }
                _require(
                    payload == expected, "roster differs from explicit human bootstrap decision"
                )
            elif kind == "scoped-signing-key":
                _require(
                    source == {"type": "signed-bootstrap-scope"}
                    and payload
                    == {
                        "person_id": ROOT_PERSON,
                        "trust_snapshot_digest": self.policy.trust_snapshot_digest,
                        "allowed_scopes": ["s1_successor_governance", "s2_development_governance"],
                    },
                    "key scope extension is not explicitly signed",
                )
            elif kind == "fresh-forecast":
                _closed(source, {"type", "producer", "acceptance", "roadmap"})
                _require(source["type"] == "signed-forecast", "wrong forecast source")
                kickoff_source = self.boundary._evidence[
                    str(accepted["kickoff_evidence_digest"])
                ].source
                forecast_kickoff, forecast_scope = self._kickoff(str(kickoff_source["path"]))
                producer, acceptance = self._forecast(
                    str(source["producer"]),
                    str(source["acceptance"]),
                    base_commit=forecast_scope["base_commit"],
                    kickoff_claim_digest=forecast_kickoff["claim_digest"],
                    result=result.oid,
                    scope_digest=str(accepted["scope_digest"]),
                    roadmap=str(source["roadmap"]),
                )
                _require(
                    core._time(document["valid_until_utc"])
                    <= core._time(producer["delivery_forecast"]["valid_until_utc"]),
                    "forecast evidence wrapper extends its signed decision interval",
                )
                _require(
                    payload["forecast_digest"]
                    == core.content_digest(HUMAN_DOMAIN + core.canonical_bytes(producer))
                    and payload["acceptance_receipt_digest"]
                    == core.content_digest(HUMAN_DOMAIN + core.canonical_bytes(acceptance)),
                    "forecast witnesses differ from signed producer and acceptance",
                )

    def receipt_import(self, request: Mapping[str, Any]) -> dict[str, Any]:
        data = _closed(dict(request), {"action", "collection", "signature_envelope", "out"})
        collection = str(data["collection"])
        pending = read_json(self.source_root, collection + "/pending-receipt.json")
        accepted, _ = core.accepted_signing_claim(pending)
        accepted["signature_envelope"] = read_json(self.root, str(data["signature_envelope"]))
        self._load_evidence(collection + "/evidence.json", accepted)
        core.validate_successor_receipt(
            accepted, policy=self.policy, boundary=self.boundary, now=self.clock()
        )
        # Object-only closure creation leaves clean HEAD=R3 and the capture
        # worktree/index intact for all subsequent source revalidation.
        closure = self.reader.create_closure_commit(
            accepted["result_commit"],
            core.canonical_bytes(accepted) + b"\n",
            committer_person_id=ROOT_PERSON,
            observed_at=self.clock().replace(microsecond=0),
        )
        write_json(self.root, str(data["out"]) + "/accepted-receipt.json", accepted)
        write_json(
            self.root,
            str(data["out"]) + "/closure.json",
            {
                "format": "agent-assure-s1-successor-closure-object/3",
                "closure_commit": closure.oid,
                "result_commit": accepted["result_commit"],
                "receipt_digest": accepted["receipt_digest"],
                "evidence": collection + "/evidence.json",
                "authorization_effect": "none",
            },
        )
        return {
            "result": "signed_receipt_verified_closure_object_created",
            "closure_commit": closure.oid,
            "authorization_effect": "none",
        }

    def _accepted(self, path: str, evidence_path: str) -> dict[str, Any]:
        accepted = core.load_successor_receipt(read_bytes(self.source_root, path))
        self._load_evidence(evidence_path, accepted)
        core.validate_successor_receipt(
            accepted, policy=self.policy, boundary=self.boundary, now=self.clock()
        )
        return accepted

    def _source_validity_ceiling(self, accepted: Mapping[str, Any]) -> datetime:
        """Publication cannot outlive any original, authenticated source."""
        limits = [
            core._time(accepted["valid_until_utc"]),
            core._time(self.key.valid_until_utc),
        ]
        for field in core.EVIDENCE_REFERENCE_FIELDS:
            source = self.boundary._evidence[str(accepted[field])].evidence
            limits.append(core._time(parse_json(source.canonical_payload)["valid_until_utc"]))
        return min(limits)

    def tag_plan(self, request: Mapping[str, Any]) -> dict[str, Any]:
        data = _closed(dict(request), {"action", "accepted_receipt", "evidence", "out"})
        accepted = self._accepted(str(data["accepted_receipt"]), str(data["evidence"]))
        # Recover the exact deterministic closure object without altering HEAD.
        # Its commit time is captured once in receipt-import's closure.json.
        closure_record = read_json(
            self.source_root,
            str(Path(str(data["accepted_receipt"])).parent.as_posix()) + "/closure.json",
        )
        closure = self.reader.resolve_commit(closure_record["closure_commit"])
        _require(
            closure.parents == (accepted["result_commit"],)
            and self.reader.changed_paths(accepted["result_commit"], closure.oid)
            == (core.RECEIPT_PATH,),
            "closure is not the exact receipt-only child",
        )
        stored = self.reader.read_commit_artifact(closure.oid, core.RECEIPT_PATH)
        _require(parse_json(stored) == accepted, "closure receipt differs")
        prepared = self.clock()
        deadline = min(
            prepared + timedelta(seconds=self.policy.finalization_window_seconds),
            self._source_validity_ceiling(accepted),
        )
        _require(prepared < deadline, "no current tag-finalization interval remains")
        claim = {
            "format": "agent-assure-s1-current-acceptance-attestation/3",
            "acceptance_generation": 3,
            "predecessor_closure_commit": core.PREDECESSOR_CLOSURE,
            "result_commit": accepted["result_commit"],
            "closure_commit": closure.oid,
            "receipt_path": core.RECEIPT_PATH,
            "receipt_sha256": core.content_digest(stored),
            "receipt_digest": accepted["receipt_digest"],
            "prepared_at_utc": timestamp(prepared),
            "finalize_by_utc": timestamp(deadline),
        }
        _signing_output(self.root, str(data["out"]), claim, core.canonical_bytes(claim))
        return {
            "result": "fixed_tag_attestation_signature_pending",
            "finalize_by_utc": timestamp(deadline),
            "authorization_effect": "none",
        }

    def tag_finalize(self, request: Mapping[str, Any]) -> dict[str, Any]:
        data = _closed(
            dict(request),
            {"action", "tag_claim", "signature_envelope", "accepted_receipt", "evidence", "out"},
        )
        accepted = self._accepted(str(data["accepted_receipt"]), str(data["evidence"]))
        claim = read_json(self.root, str(data["tag_claim"]))
        _closed(
            claim,
            {
                "format",
                "acceptance_generation",
                "predecessor_closure_commit",
                "result_commit",
                "closure_commit",
                "receipt_path",
                "receipt_sha256",
                "receipt_digest",
                "prepared_at_utc",
                "finalize_by_utc",
            },
        )
        _require(
            claim["format"] == "agent-assure-s1-current-acceptance-attestation/3"
            and type(claim["acceptance_generation"]) is int
            and claim["acceptance_generation"] == 3
            and claim["predecessor_closure_commit"] == core.PREDECESSOR_CLOSURE
            and claim["result_commit"] == accepted["result_commit"]
            and claim["receipt_path"] == core.RECEIPT_PATH
            and claim["receipt_digest"] == accepted["receipt_digest"],
            "tag claim has different subject/authority",
        )
        closure = self.reader.resolve_commit(core._oid(claim["closure_commit"]))
        _require(
            closure.parents == (accepted["result_commit"],)
            and self.reader.changed_paths(accepted["result_commit"], closure.oid)
            == (core.RECEIPT_PATH,),
            "tag cannot activate untested closure changes",
        )
        stored = self.reader.read_commit_artifact(closure.oid, core.RECEIPT_PATH)
        _require(
            parse_json(stored) == accepted
            and core.content_digest(stored) == claim["receipt_sha256"],
            "tag receipt binding differs",
        )
        envelope = read_json(self.root, str(data["signature_envelope"]))
        self.boundary.preverify_signature(
            core.canonical_bytes(claim), envelope, "s1-successor-tag/v3"
        )
        prepared, deadline = (
            core._time(claim["prepared_at_utc"]),
            core._time(claim["finalize_by_utc"]),
        )
        # Recheck actual now immediately before BOTH first publication and
        # idempotent reuse. An old claimed verification time cannot bypass it.
        current = self.clock()
        _require(
            core._time(accepted["issued_at_utc"])
            <= prepared
            <= current
            < deadline
            <= self._source_validity_ceiling(accepted)
            and deadline - prepared <= timedelta(seconds=self.policy.finalization_window_seconds),
            "tag finalization window expired, is future, or exceeds policy",
        )
        message = core.canonical_bytes({"claim": claim, "signature_envelope": envelope})
        tag = self.reader.publish_fixed_tag(
            core.SUCCESSOR_TAG,
            closure.oid,
            message,
            tagger_person_id=ROOT_PERSON,
            observed_at=current.replace(microsecond=0),
        )
        readback = self.clock()
        _require(
            readback < deadline,
            "tag exists but read-back completed after deadline; no acceptance emitted",
        )
        observed = {
            "tag_object": tag.object_oid,
            "closure_commit": closure.oid,
            "tag_claim_sha256": core.content_digest(core.canonical_bytes(claim)),
            "receipt_sha256": core.content_digest(stored),
            # These are truthful publication/read-back observations,
            # not the SSHSIG time or a claimed physical CAS instant.
            "published_at_utc": timestamp(readback),
            "readback_completed_at_utc": timestamp(readback),
            "clock_basis": "maintainer_host_utc_externally_unattested",
            "actual_signature_time_claimed": False,
        }
        witness = {
            "format": "agent-assure-s1-successor-publication-observation/3",
            "publication": observed,
            "tag_message_sha256": core.content_digest(message),
            "policy_digest": self.claim["policy_digest"],
        }
        write_json(self.root, str(data["out"]) + "/publication-observation.json", witness)
        return {
            "result": "fixed_local_tag_published_publication_countersignature_pending",
            "tag_object": tag.object_oid,
            "authorization_effect": "none",
            "remote_publication": "not_performed",
        }

    def publication_plan(self, request: Mapping[str, Any]) -> dict[str, Any]:
        data = _closed(dict(request), {"action", "publication", "out"})
        witness = read_json(self.source_root, str(data["publication"]))
        _closed(witness, {"format", "publication", "tag_message_sha256", "policy_digest"})
        _require(
            witness["format"] == "agent-assure-s1-successor-publication-observation/3"
            and witness["policy_digest"] == self.claim["policy_digest"],
            "wrong publication witness",
        )
        tag = self.boundary.preverify_tag()
        raw_tag = self.reader.read_annotated_tag(core.SUCCESSOR_TAG)
        _require(
            witness["publication"]["tag_object"] == tag.object_oid
            and witness["tag_message_sha256"] == core.content_digest(raw_tag.message),
            "publication tag bytes differ",
        )
        source = {"type": "frozen-host-publication-observation", "witness": witness}
        current = self.clock()
        document = {
            "format": "agent-assure-s1-successor-evidence/3",
            "kind": "fixed-tag-publication",
            "subject_commit": tag.target_commit,
            "issued_at_utc": timestamp(current),
            "valid_until_utc": self.key.valid_until_utc,
            "payload": witness["publication"],
            "source_witness_digest": core.content_digest(core.canonical_bytes(source)),
        }
        claim = {
            "format": "agent-assure-s1-successor-publication-acceptance/3",
            "purpose": "s1-successor-publication/v3",
            "issuer_role": "repository_maintainer",
            "policy_digest": self.claim["policy_digest"],
            "publication_evidence": document,
            "source": source,
            "decision": "HUMAN_REVIEW_REQUIRED",
        }
        _signing_output(
            self.root, str(data["out"]), claim, HUMAN_DOMAIN + core.canonical_bytes(claim)
        )
        return {
            "result": "publication_observation_human_acceptance_pending",
            "authorization_effect": "none",
        }

    def _publication(self, path: str) -> core.VerifiedEvidence:
        document = read_json(self.source_root, path)
        claim = self._verify_human(document, "s1-successor-publication/v3")
        _closed(
            claim,
            {
                "format",
                "purpose",
                "issuer_role",
                "policy_digest",
                "publication_evidence",
                "source",
                "decision",
            },
        )
        _require(
            claim["format"] == "agent-assure-s1-successor-publication-acceptance/3"
            and claim["decision"] == "accept",
            "publication source acceptance is pending",
        )
        evidence = core.VerifiedEvidence(core.canonical_bytes(claim["publication_evidence"]))
        wrapper = parse_json(evidence.canonical_payload)
        _require(
            wrapper.get("source_witness_digest")
            == core.content_digest(core.canonical_bytes(claim["source"])),
            "publication source witness changed",
        )
        source = _closed(claim["source"], {"type", "witness"})
        _require(
            source["type"] == "frozen-host-publication-observation"
            and wrapper["payload"] == source["witness"]["publication"],
            "publication source/summary differs",
        )
        raw = self.reader.read_annotated_tag(core.SUCCESSOR_TAG)
        _require(
            source["witness"]["tag_message_sha256"] == core.content_digest(raw.message)
            and source["witness"]["policy_digest"] == self.claim["policy_digest"],
            "publication exact-byte or policy binding differs",
        )
        self.boundary._publication = evidence
        return evidence

    def verify_replay(self, request: Mapping[str, Any]) -> dict[str, Any]:
        data = _closed(
            dict(request), {"action", "accepted_receipt", "evidence", "publication", "out"}
        )
        _require(
            self.root != self.source_root, "standalone replay must execute from another checkout"
        )
        accepted = self._accepted(str(data["accepted_receipt"]), str(data["evidence"]))
        tag = self.boundary.preverify_tag()
        self._publication(str(data["publication"]))
        subject = core.validate_successor_subject(
            accepted,
            closure_commit=tag.target_commit,
            policy=self.policy,
            boundary=self.boundary,
            now=self.clock(),
        )
        # This is a real independently launched clone's check result; it is
        # deliberately NONaccepting until the parent binds actual execution.
        return {
            "result": "standalone_subject_verified",
            "subject": asdict(subject),
            "validator_digest": self.policy.expected_validator_digest,
            "authorization_effect": "none",
        }

    def verify(self, request: Mapping[str, Any], *, bootstrap_path: str) -> dict[str, Any]:
        data = _closed(
            dict(request), {"action", "accepted_receipt", "evidence", "publication", "out"}
        )
        accepted = self._accepted(str(data["accepted_receipt"]), str(data["evidence"]))
        tag = self.boundary.preverify_tag()
        publication = self._publication(str(data["publication"]))
        subject = core.validate_successor_subject(
            accepted,
            closure_commit=tag.target_commit,
            policy=self.policy,
            boundary=self.boundary,
            now=self.clock(),
        )
        out = str(data["out"])
        destination = self.root / out / "clone"
        self.reader.prepare_standalone_clone(
            tag.target_commit, destination, empty_template=destination.parent / "empty-template"
        )
        self._copy_replay_runtime(destination)
        # Reuse the exact signed bootstrap; code is checked in the child before
        # ANY local module executes. Original capture witnesses remain data in
        # their adopted retained clean R3 checkout, not imports from that tree.
        child_bootstrap = out + "/clone/.tmp/s1-acceptance/successor-v3/replay/bootstrap.json"
        child_request = out + "/clone/.tmp/s1-acceptance/successor-v3/replay/request.json"
        write_json(self.root, child_bootstrap, self.bootstrap)
        child = {**dict(data), "action": "verify-replay"}
        write_json(self.root, child_request, child)
        powershell = Path(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
        # The external launcher/PowerShell remains an explicit trust-base
        # component. Pin its exact bytes in the human bootstrap inventory.
        power_identity = self.claim["trust"].get("powershell_identity")
        _require(
            type(power_identity) is dict and power_identity.get("path") == str(powershell),
            "standalone PowerShell interpreter is not explicitly pinned",
        )
        raw_power = powershell.read_bytes()
        _require(
            len(raw_power) == power_identity.get("size_bytes")
            and core.content_digest(raw_power) == power_identity.get("sha256"),
            "PowerShell binary identity changed",
        )
        started = self.clock()
        command = [
            str(powershell),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(destination / "scripts/v1_s1_governance.ps1"),
            "successor",
            "--repository-root",
            str(destination),
            "--bootstrap",
            ".tmp/s1-acceptance/successor-v3/replay/bootstrap.json",
            "--request",
            ".tmp/s1-acceptance/successor-v3/replay/request.json",
        ]
        retained = {
            "SYSTEMROOT",
            "WINDIR",
            "COMSPEC",
            "TEMP",
            "TMP",
            "USERPROFILE",
            "APPDATA",
            "LOCALAPPDATA",
            "PROGRAMDATA",
            "HOMEDRIVE",
            "HOMEPATH",
            "PROCESSOR_ARCHITECTURE",
            "NUMBER_OF_PROCESSORS",
            "OS",
            "PATHEXT",
        }
        environment = {key: value for key, value in os.environ.items() if key.upper() in retained}
        environment["PATH"] = r"C:\Windows\System32;C:\Windows"
        environment["NoDefaultCurrentDirectoryInExePath"] = "1"
        code, stdout, stderr = checks.run_bounded(
            command,
            cwd=destination,
            environment=environment,
            payload=b"",
            timeout_seconds=900,
            max_stream_bytes=1024 * 1024,
        )
        completed = self.clock()
        _require(code == 0, "standalone historical child failed; no accepted successor emitted")
        lines = [line for line in stdout.decode("utf-8").splitlines() if line.strip()]
        _require(len(lines) == 1, "standalone child output is ambiguous")
        child_result = parse_json(lines[0].encode("utf-8"))
        _require(
            child_result
            == {
                "result": "standalone_subject_verified",
                "subject": asdict(subject),
                "validator_digest": self.policy.expected_validator_digest,
                "authorization_effect": "none",
            },
            "standalone child returned another subject",
        )
        proof_payload = {
            "tag_object": tag.object_oid,
            "receipt_sha256": subject.receipt_sha256,
            "mode": "standalone_clone_no_local",
            "exit_code": code,
            "started_at_utc": timestamp(started),
            "completed_at_utc": timestamp(completed),
            "validator_digest": self.policy.expected_validator_digest,
            "publication_evidence_digest": core.evidence_digest(publication),
        }
        reference = self.boundary._record(
            "standalone-historical-replay",
            tag.target_commit,
            proof_payload,
            {
                "type": "frozen-standalone-child",
                "command": command,
                "stdout_sha256": core.content_digest(stdout),
                "stderr_sha256": core.content_digest(stderr),
                "source_root": str(self.source_root),
                "clone_root": str(destination),
                "powershell_identity": power_identity,
            },
        )
        accepted_successor = core.validate_successor_closure(
            accepted,
            closure_commit=tag.target_commit,
            historical_replay_digest=reference,
            policy=self.policy,
            boundary=self.boundary,
            now=self.clock(),
        )
        report = {
            "format": "agent-assure-s1-successor-host-verification/3",
            "accepted_successor": asdict(accepted_successor),
            "subject": asdict(subject),
            "accepted_receipt": data["accepted_receipt"],
            "evidence": data["evidence"],
            "publication": data["publication"],
            "history": self.boundary.export_evidence()[reference],
            "authorization_effect": "development_governance_only",
            "independent_review": "NO_INDEPENDENT_REVIEW",
        }
        write_json(self.root, out + "/verification.json", report)
        self._last_verification = parse_json(core.canonical_bytes(report))
        self._last_verification_path = out + "/verification.json"
        return {
            "result": "successor_closure_verified",
            "closure_commit": tag.target_commit,
            "fixed_tag_object": tag.object_oid,
            "authorization_effect": "development_governance_only",
        }

    def _copy_replay_runtime(self, destination: Path) -> None:
        runtime = self.legacy._post_r2_test_runtime_evidence(self.source_root)
        source = self.source_root / ".venv"
        total = 0
        for current, directories, files in os.walk(source, followlinks=False):
            directories[:] = sorted(name for name in directories if name != "__pycache__")
            current_path = Path(current)
            for name in [*directories, *files]:
                info = (current_path / name).lstat()
                _require(
                    not (getattr(info, "st_file_attributes", 0) & 0x400)
                    and not (current_path / name).is_symlink(),
                    "replay runtime contains a linked path",
                )
            for name in sorted(files):
                relative = (current_path / name).relative_to(self.source_root).as_posix()
                raw = read_bytes(self.source_root, relative, maximum=RUNTIME_FILE_MAX_BYTES)
                total += len(raw)
                _require(
                    total <= 256 * 1024 * 1024, "frozen replay runtime copy exceeds explicit budget"
                )
                target = destination.relative_to(self.root).as_posix() + "/" + relative
                write_new(self.root, target, raw, maximum=RUNTIME_FILE_MAX_BYTES)
        copied_runtime = self.legacy._post_r2_test_runtime_evidence(destination)
        # Only this explicitly root-relative file moves. Base interpreter and
        # every content/inventory identity must remain exactly authenticated.
        for evidence, root in ((runtime, self.source_root), (copied_runtime, destination)):
            configuration = evidence["pyvenv_configuration"]
            _require(
                configuration["absolute_path"] == str((root / ".venv/pyvenv.cfg").resolve()),
                "runtime configuration path differs from exact owned root",
            )
        runtime = {**runtime, "pyvenv_configuration": dict(runtime["pyvenv_configuration"])}
        copied_runtime = {
            **copied_runtime,
            "pyvenv_configuration": dict(copied_runtime["pyvenv_configuration"]),
        }
        runtime["pyvenv_configuration"]["absolute_path"] = ".venv/pyvenv.cfg"
        copied_runtime["pyvenv_configuration"]["absolute_path"] = ".venv/pyvenv.cfg"
        _require(
            copied_runtime == runtime,
            "standalone runtime copy differs from authenticated source",
        )
        # Git metadata is created only in this newly owned standalone clone.
        # No existing repository's local policy is rewritten.
        clone_relative = destination.relative_to(self.root).as_posix()
        write_new(
            self.root,
            clone_relative + "/.git/info/exclude",
            self.legacy.POST_V2_CONTROL_GIT_EXCLUDE_BYTES,
        )
        _require(
            not (destination / ".git/info/attributes").exists(),
            "standalone clone has local attributes",
        )

    def _recheck_successor(self, locator_path: str, out: str) -> dict[str, Any]:
        # An earlier JSON success flag is NEVER consumed as execution proof.
        # Read only locators, perform a fresh real standalone replay, then use
        # the resulting in-process validated subject/evidence.
        previous = read_json(self.source_root, locator_path)
        _require(
            previous.get("format") == "agent-assure-s1-successor-host-verification/3",
            "successor locator document has another format",
        )
        import uuid

        replay_out = PRIVATE_PREFIX + "recheck-" + uuid.uuid4().hex
        request = {
            "action": "verify",
            "accepted_receipt": previous["accepted_receipt"],
            "evidence": previous["evidence"],
            "publication": previous["publication"],
            "out": replay_out,
        }
        self._last_verification = None
        self._last_verification_path = None
        self.verify(request, bootstrap_path="already_authenticated_in_memory")
        _require(
            self._last_verification is not None, "fresh in-process successor verification is absent"
        )
        return cast(dict[str, Any], self._last_verification)

    def _s2_claims(
        self, verification: Mapping[str, Any]
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        accepted = {
            key: value
            for key, value in core._object(verification["accepted_successor"]).items()
            if key != "historical_replay_digest"
        }
        result_commit = core._oid(accepted["result_commit"])
        source_cache: dict[str, bytes] = {}

        def committed(path: str) -> bytes:
            if path in source_cache:
                return source_cache[path]
            recorded = self.reader.read_commit_artifact(result_commit, path)
            _require(
                recorded == read_bytes(self.root, path),
                "S2 source differs from immutable tested R3",
            )
            source_cache[path] = recorded
            return recorded

        basis = core.content_digest(core.canonical_bytes(accepted))
        package = parse_json(committed("docs/governance/v1/sprint2/architecture-package.json"))
        for name in (
            "architecture-package",
            "support-policy",
            "s1-successor-protocol",
            "wire-contract-inventory",
            "occurrence-graph-expectations",
        ):
            schema_path = f"docs/governance/v1/sprint2/{name}.schema.json"
            schema_raw = committed(schema_path)
            schema = parse_json(schema_raw)
            value = parse_json(committed(f"docs/governance/v1/sprint2/{name}.json"))
            signed = {row["path"]: row for row in self.claim["implementation_inventory"]}
            _require(
                signed[schema_path]["sha256"] == core.content_digest(schema_raw)
                and signed[schema_path]["size_bytes"] == len(schema_raw),
                "S2 schema differs from signed implementation",
            )
            _require(
                not any(not str(ref).startswith("#/") for ref in _schema_references(schema)),
                "external architecture schema resolution is forbidden",
            )
            jsonschema.Draft202012Validator(schema).validate(value)
        projection = {key: value for key, value in package.items() if key != "package_digest"}
        _require(
            package.get("package_digest")
            == core.content_digest(
                b"agent-assure:v1-architecture-package/v1\x00" + core.canonical_bytes(projection)
            ),
            "architecture package content digest changed",
        )
        expected_decisions = {ticket: (identifier, path) for ticket, identifier, path in DECISIONS}
        _require(
            len(package["decisions"]) == len(expected_decisions)
            and {row["ticket_id"] for row in package["decisions"]} == set(expected_decisions),
            "architecture package omits or duplicates a required decision",
        )
        for row in package["decisions"]:
            identifier, path = expected_decisions[row["ticket_id"]]
            raw = committed(path)
            _require(
                row["decision_id"] == identifier
                and row["artifact"]
                == {"path": path, "size_bytes": len(raw), "sha256": core.content_digest(raw)},
                "architecture decision binding differs",
            )
        for group in ("supplementary_artifacts", "tooling_artifacts", "historical_artifacts"):
            for row in package[group]:
                raw = committed(row["path"])
                _require(
                    row
                    == {
                        "path": row["path"],
                        "size_bytes": len(raw),
                        "sha256": core.content_digest(raw),
                    },
                    "architecture source binding changed",
                )
        claims: list[dict[str, Any]] = []
        for ticket, identifier, path in DECISIONS:
            artifact_digest = core.content_digest(committed(path))
            common = {
                "issuer_role": "repository_maintainer",
                "policy_digest": self.claim["policy_digest"],
                "successor_basis_digest": basis,
                "ticket_id": ticket,
                "decision_id": identifier,
                "subject_path": path,
                "subject_sha256": artifact_digest,
                "approval_mode": "maintainer_development",
                "independence": "NO_INDEPENDENT_REVIEW",
                "authorization_effect": "development_governance_only",
            }
            start = {
                "format": "agent-assure-s2-drafting-authorization/1",
                "purpose": "s2-drafting/v1",
                **common,
                "allowed_operations": ["review_staged_design", "prepare_scoped_design_acceptance"],
                "retrospective_authorization_claimed": False,
            }
            claims.append(start)
            claims.append(
                {
                    "format": "agent-assure-s2-development-design-acceptance/1",
                    "purpose": "s2-design-acceptance/v1",
                    **common,
                    "start_claim_digest": core.content_digest(
                        HUMAN_DOMAIN + core.canonical_bytes(start)
                    ),
                    "decision": "accept_for_development",
                    "qualified_review_pending": True,
                    "method_or_profile_admission": False,
                }
            )
        for identifier, ticket, path in (
            ("POLICY-V1-SUPPORT", "V1-BASE-06", "docs/governance/v1/sprint2/support-policy.json"),
            (
                "PRODUCT-INCONCLUSIVE-01",
                "V1-BASE-02",
                "docs/adr/0017-v1-evidence-temporal-semantics.md",
            ),
        ):
            claim = {
                "format": "agent-assure-s2-development-policy-acceptance/1",
                "purpose": "s2-design-acceptance/v1",
                "issuer_role": "repository_maintainer",
                "policy_digest": self.claim["policy_digest"],
                "successor_basis_digest": basis,
                "ticket_id": ticket,
                "decision_id": identifier,
                "subject_path": path,
                "subject_sha256": core.content_digest(committed(path)),
                "decision": "accept_for_development",
                "authorization_effect": "development_governance_only",
                "operational_or_qualified_use": (
                    "requires_its_declared_future_policy_and_admission_receipts"
                ),
            }
            if identifier == "PRODUCT-INCONCLUSIVE-01":
                candidates = [
                    parse_json(match.encode("utf-8"))
                    for match in re.findall(
                        r"```json\s*\n(.*?)\n```",
                        committed(path).decode("utf-8"),
                        re.DOTALL,
                    )
                ]
                metrics = [row for row in candidates if row.get("decision_item_id") == identifier]
                _require(len(metrics) == 1, "product metric proposal is missing or ambiguous")
                metric = metrics[0]
                floor = core._integer(metric["minimum_applicable_obligation_attempts"], minimum=1)
                ratio = _closed(metric["maximum_inconclusive_rate"], {"numerator", "denominator"})
                numerator = core._integer(ratio["numerator"])
                denominator = core._integer(ratio["denominator"], minimum=1)
                _require(numerator <= denominator, "inconclusive rate ceiling exceeds one")
                claim["proposed_denominator_floor"] = floor
                claim["proposed_ceiling"] = ratio
                claim["empirical_or_confidence_claimed"] = False
            claims.append(claim)
        bundle_claim = {
            "format": "agent-assure-s2-governance-bundle/1",
            "purpose": "s2-bundle/v1",
            "issuer_role": "repository_maintainer",
            "policy_digest": self.claim["policy_digest"],
            "sprint": "S2",
            "release": "1.0.0a2",
            "maturity": "architecture-frozen",
            "artifact_kind": "governance-bundle",
            "package_version": None,
            "distribution_channels": [],
            "successor_basis": accepted,
            "architecture_package_digest": package["package_digest"],
            "decision_claim_digests": [
                core.content_digest(HUMAN_DOMAIN + core.canonical_bytes(row)) for row in claims
            ],
            "decision": "accept_for_development",
            "independence": "NO_INDEPENDENT_REVIEW",
            "pending_qualified_admissions": [
                "independent_method_review",
                "method_admission",
                "profile_qualification",
                "release_approval",
            ],
            "authorization_effect": "development_governance_only",
        }
        return claims, bundle_claim

    def s2_plan(self, request: Mapping[str, Any]) -> dict[str, Any]:
        data = _closed(dict(request), {"action", "successor_verification", "out"})
        out = str(data["out"])
        verification = self._recheck_successor(
            str(data["successor_verification"]), out + "/successor-recheck"
        )
        decisions, bundle = self._s2_claims(verification)
        for index, claim in enumerate([*decisions, bundle]):
            _signing_output(
                self.root,
                out + f"/signing-{index:02d}",
                claim,
                HUMAN_DOMAIN + core.canonical_bytes(claim),
            )
        plan = {
            "format": "agent-assure-s2-acceptance-plan/1",
            "verification": self._last_verification_path,
            "claims": decisions,
            "bundle_claim": bundle,
            "status": "pending_human_signatures",
            "authorization_effect": "none",
        }
        write_json(self.root, out + "/plan.json", plan)
        return {
            "result": "s2_exact_design_and_bundle_signatures_pending",
            "signing_claim_count": len(decisions) + 1,
            "authorization_effect": "none",
        }

    def s2_import(self, request: Mapping[str, Any]) -> dict[str, Any]:
        data = _closed(dict(request), {"action", "plan", "signed_decisions", "out"})
        plan = read_json(self.source_root, str(data["plan"]))
        _require(plan.get("format") == "agent-assure-s2-acceptance-plan/1", "unknown S2 plan")
        documents = read_json(self.root, str(data["signed_decisions"]))
        _closed(documents, {"documents"})
        _require(
            type(plan.get("claims")) is list
            and len(plan["claims"]) == len(DECISIONS) * 2 + 2
            and type(documents["documents"]) is list
            and len(documents["documents"]) == len(plan["claims"]) + 1,
            "exact S2 receipt set and aggregate signature are required",
        )
        # Reject missing/forged human inputs before expensive replay. These
        # preliminary comparisons confer no acceptance: actual subjects are
        # independently reconstructed after the fresh successor verification.
        for proposed, document in zip(
            [*plan["claims"], plan["bundle_claim"]], documents["documents"], strict=True
        ):
            _require(
                self._verify_human(core._object(document), proposed["purpose"]) == proposed,
                "S2 signed decision differs from the proposed exact subject",
            )
        verification = self._recheck_successor(
            str(plan["verification"]), str(data["out"]) + "/successor-recheck"
        )
        decisions, bundle = self._s2_claims(verification)
        _require(
            plan["claims"] == decisions and plan["bundle_claim"] == bundle,
            "S2 plan source bytes or prerequisites changed",
        )
        _require(
            type(documents["documents"]) is list
            and len(documents["documents"]) == len(decisions) + 1,
            "exact S2 receipt set and aggregate signature are required",
        )
        for expected, document in zip([*decisions, bundle], documents["documents"], strict=True):
            actual = self._verify_human(core._object(document), expected["purpose"])
            _require(
                actual == expected, "S2 signed decision differs from its reviewed exact subject"
            )
        accepted = {
            "format": "agent-assure-s2-accepted-governance-bundle/1",
            "bundle": documents["documents"][-1],
            "decisions": documents["documents"][:-1],
            "verification": verification,
            "status": "accepted_for_development",
            "authorization_effect": "development_governance_only",
            "independence": "NO_INDEPENDENT_REVIEW",
        }
        write_json(self.root, str(data["out"]) + "/accepted-bundle.json", accepted)
        return {
            "result": "s2_accepted_for_development",
            "s2_dispatch_ready": True,
            "authorization_effect": "development_governance_only",
            "qualified": False,
        }

    def s2_verify(self, request: Mapping[str, Any]) -> dict[str, Any]:
        data = _closed(dict(request), {"action", "bundle", "successor_verification"})
        bundle = read_json(self.source_root, str(data["bundle"]))
        _closed(
            bundle,
            {
                "format",
                "bundle",
                "decisions",
                "verification",
                "status",
                "authorization_effect",
                "independence",
            },
        )
        _require(
            bundle["format"] == "agent-assure-s2-accepted-governance-bundle/1"
            and bundle["status"] == "accepted_for_development"
            and bundle["authorization_effect"] == "development_governance_only"
            and bundle["independence"] == "NO_INDEPENDENT_REVIEW",
            "unknown S2 lifecycle/effect",
        )
        # Verify signatures before using the aggregate's source locators.
        aggregate = self._verify_human(bundle["bundle"], "s2-bundle/v1")
        _require(
            type(bundle["decisions"]) is list
            and len(bundle["decisions"]) == len(DECISIONS) * 2 + 2
            and len(aggregate["decision_claim_digests"]) == len(bundle["decisions"]),
            "S2 decision receipt set is incomplete",
        )
        for digest, document in zip(
            aggregate["decision_claim_digests"], bundle["decisions"], strict=True
        ):
            claim = core._object(document["claim"])
            verified = self._verify_human(document, str(claim["purpose"]))
            _require(
                core.content_digest(HUMAN_DOMAIN + core.canonical_bytes(verified)) == digest,
                "S2 receipt differs from the signed aggregate digest",
            )
        import uuid

        fresh = PRIVATE_PREFIX + "s2-readback-" + uuid.uuid4().hex
        verification = self._recheck_successor(str(data["successor_verification"]), fresh)
        decisions, expected = self._s2_claims(verification)
        _require(
            aggregate == expected and len(bundle["decisions"]) == len(decisions),
            "S2 aggregate/source bindings changed",
        )
        for wanted, document in zip(decisions, bundle["decisions"], strict=True):
            _require(
                self._verify_human(document, wanted["purpose"]) == wanted,
                "S2 decision signature or source differs",
            )
        return {
            "result": "s2_accepted_for_development",
            "s2_dispatch_ready": True,
            "authorization_effect": "development_governance_only",
            "qualified": False,
        }


def _schema_references(value: object) -> list[str]:
    result: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key in {"$ref", "$dynamicRef", "$recursiveRef"}:
                _require(type(item) is str, "schema reference must be a string")
                result.append(str(item))
            result.extend(_schema_references(item))
    elif isinstance(value, list):
        for item in value:
            result.extend(_schema_references(item))
    return result


def _validate_host_schema(
    root: Path,
    document: Mapping[str, Any],
    definition: str,
    *,
    inventory: Sequence[Mapping[str, Any]],
) -> None:
    raw = read_bytes(root, HOST_SCHEMA)
    bindings = {row["path"]: row for row in inventory}
    _require(
        HOST_SCHEMA in bindings
        and bindings[HOST_SCHEMA]["sha256"] == core.content_digest(raw)
        and bindings[HOST_SCHEMA]["size_bytes"] == len(raw),
        "host schema differs from the externally authenticated bootstrap bytes",
    )
    schema = parse_json(raw)

    def references(value: Any) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if key in {"$ref", "$dynamicRef", "$recursiveRef"}:
                    _require(
                        type(item) is str and item.startswith("#/"),
                        "external schema resolution is forbidden",
                    )
                references(item)
        elif isinstance(value, list):
            for item in value:
                references(item)

    references(schema)
    selected = {
        "$schema": schema["$schema"],
        "$defs": schema["$defs"],
        "$ref": "#/$defs/" + definition,
    }
    try:
        jsonschema.Draft202012Validator.check_schema(selected)
        jsonschema.Draft202012Validator(selected).validate(dict(document))
    except (jsonschema.ValidationError, jsonschema.SchemaError) as exc:
        raise HostError("closed host wire contract rejected the request") from exc


def run_frozen(
    legacy: Any,
    root: Path,
    bootstrap: Mapping[str, Any],
    request: Mapping[str, Any],
    *,
    ci_token_environment: str | None = None,
) -> int:
    _require(legacy._main_has_active_runtime_bootstrap() is True, "frozen runtime is required")
    inventory = bootstrap["claim"]["implementation_inventory"]
    _validate_host_schema(root, bootstrap, "bootstrap", inventory=inventory)
    _validate_host_schema(root, request, "request", inventory=inventory)
    host = FrozenHost(legacy, root, bootstrap)
    action = request["action"]
    if action not in {"verify-replay"}:
        _require(
            host.root == host.source_root,
            "mutating/preparing operations require the adopted capture checkout",
        )
    token: str | None = None
    if action == "collect":
        _require(
            type(ci_token_environment) is str
            and re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", ci_token_environment) is not None,
            "collect requires an explicit CI-token environment name",
        )
        token = os.environ.get(str(ci_token_environment))
        _require(type(token) is str and bool(token), "the explicitly selected CI token is absent")
    else:
        _require(ci_token_environment is None, "CI credentials are not used for this operation")
    routes: dict[str, Callable[[Mapping[str, Any]], dict[str, Any]]] = {
        "kickoff-plan": host.kickoff_plan,
        "kickoff-import": host.kickoff_import,
        "start-work": host.start_work,
        "observe-result": host.observe_result,
        "forecast-plan": host.forecast_plan,
        "forecast-recalculate": host.forecast_recalculate,
        "forecast-acceptance-plan": host.forecast_acceptance_plan,
        "receipt-import": host.receipt_import,
        "tag-plan": host.tag_plan,
        "tag-finalize": host.tag_finalize,
        "publication-plan": host.publication_plan,
        "verify-replay": host.verify_replay,
        "s2-plan": host.s2_plan,
        "s2-import": host.s2_import,
        "s2-verify": host.s2_verify,
    }
    if action == "collect":
        result = host.collect(request, token=cast(str, token))
    elif action == "verify":
        result = host.verify(request, bootstrap_path="authenticated_bootstrap")
    else:
        _require(action in routes, "unknown host action")
        result = routes[str(action)](request)
    print(json.dumps(result, sort_keys=True))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=(
            "profile-template",
            "plan-bootstrap",
            "wrap-signature",
            "decision-plan",
            "assemble-s2",
        ),
    )
    parser.add_argument("--repository-root", type=Path, default=Path.cwd())
    parser.add_argument("--profile")
    parser.add_argument("--claim")
    parser.add_argument("--signature")
    parser.add_argument("--plan")
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    try:
        root = args.repository_root.absolute()
        if args.command == "profile-template":
            current = utc_now()
            profile = {
                "person_id": ROOT_PERSON,
                "public_key": ROOT_PUBLIC_KEY,
                "key_id": git_io.public_key_fingerprint(ROOT_PUBLIC_KEY),
                "roles": ["repository_maintainer", "technical_lead"],
                "competence_scopes": ["planning_governance:s1_successor", "schema_compatibility"],
                "conflicts": [
                    "Same maintainer directs and accepts development; no independent review"
                ],
                # Deliberately incomplete. No capacity or competence is inferred
                # from key possession; the accountable person must adopt it.
                "review_capacity": None,
                "valid_from_utc": timestamp(current),
                "valid_until_utc": timestamp(current + timedelta(days=30)),
                "mode": "maintainer_development",
                "independence": "NO_INDEPENDENT_REVIEW",
            }
            write_json(root, args.out + "/profile.json", profile)
        elif args.command == "decision-plan":
            _require(type(args.claim) is str, "decision-plan requires --claim")
            claim = read_json(root, args.claim)
            decisions = {
                "agent-assure-successor-forecast-decision/3": "accept_reestimated_proposal",
                "agent-assure-successor-forecast-acceptance/3": "accept",
                "agent-assure-s1-successor-publication-acceptance/3": "accept",
            }
            _require(
                claim.get("format") in decisions
                and claim.get("decision") == "HUMAN_REVIEW_REQUIRED",
                "only a known untouched pending human decision can be prepared",
            )
            if claim["format"] == "agent-assure-successor-forecast-decision/3":
                claim["estimate_summary"] = human_estimate_summary(
                    claim["authoring_ledger"], claim["human_estimates"]
                )
                previous = core._object(claim["delivery_forecast"])
                claim["delivery_forecast"] = forecast.build_projection(
                    authoring_ledger=core._object(claim["authoring_ledger"]),
                    human_estimates=claim["human_estimates"],
                    source=core._object(previous["source"]),
                    issued_at_utc=previous["issued_at_utc"],
                    valid_until_utc=previous["valid_until_utc"],
                    now=utc_now(),
                )
            claim["decision"] = decisions[claim["format"]]
            _signing_output(root, args.out, claim, HUMAN_DOMAIN + core.canonical_bytes(claim))
        elif args.command == "assemble-s2":
            _require(type(args.plan) is str, "assemble-s2 requires --plan")
            plan = read_json(root, args.plan)
            _require(
                plan.get("format") == "agent-assure-s2-acceptance-plan/1"
                and len(plan["claims"]) == len(DECISIONS) * 2 + 2,
                "unknown or incomplete S2 plan",
            )
            base = Path(args.plan).parent
            documents = []
            for index, claim in enumerate([*plan["claims"], plan["bundle_claim"]]):
                directory = base / f"signing-{index:02d}"
                _require(
                    read_json(root, (directory / "claim.json").as_posix()) == claim
                    and read_bytes(root, (directory / "claim").as_posix())
                    == HUMAN_DOMAIN + core.canonical_bytes(claim),
                    "S2 signing source differs from the plan",
                )
                raw = read_bytes(root, (directory / "claim.sig").as_posix(), maximum=16_384)
                _require(
                    raw.startswith(b"-----BEGIN SSH SIGNATURE-----\n")
                    and raw.endswith(b"-----END SSH SIGNATURE-----\n")
                    and b"\r" not in raw,
                    "S2 public signature is not canonical LF armor",
                )
                documents.append(
                    {
                        "claim": claim,
                        "signature_envelope": {
                            "profile": core.SIGNATURE_PROFILE,
                            "namespace": core.SIGNATURE_NAMESPACE,
                            "signer_person_id": ROOT_PERSON,
                            "key_id": git_io.public_key_fingerprint(ROOT_PUBLIC_KEY),
                            "signature": base64.b64encode(raw).decode("ascii"),
                        },
                    }
                )
            write_json(root, args.out + "/documents.json", {"documents": documents})
        elif args.command == "wrap-signature":
            _require(
                type(args.claim) is str and type(args.signature) is str,
                "wrap-signature requires --claim JSON and --signature public SSHSIG",
            )
            claim = read_json(root, args.claim)
            raw = read_bytes(root, args.signature, maximum=16_384)
            _require(
                raw.startswith(b"-----BEGIN SSH SIGNATURE-----\n")
                and raw.endswith(b"-----END SSH SIGNATURE-----\n")
                and b"\r" not in raw,
                "public SSHSIG file must use canonical LF armor",
            )
            envelope = {
                "profile": core.SIGNATURE_PROFILE,
                "namespace": core.SIGNATURE_NAMESPACE,
                "signer_person_id": ROOT_PERSON,
                "key_id": git_io.public_key_fingerprint(ROOT_PUBLIC_KEY),
                "signature": base64.b64encode(raw).decode("ascii"),
            }
            write_json(
                root, args.out + "/document.json", {"claim": claim, "signature_envelope": envelope}
            )
            write_json(root, args.out + "/envelope.json", envelope)
        else:
            _require(type(args.profile) is str, "plan-bootstrap requires --profile")
            claim = prepare_bootstrap(root, read_json(root, args.profile), now=utc_now())
            _signing_output(root, args.out, claim, bootstrap_claim_bytes(claim))
        print(
            json.dumps(
                {"result": "nonaccepting_preparation_complete", "authorization_effect": "none"}
            )
        )
        return 0
    except (core.SuccessorError, OSError, jsonschema.ValidationError) as exc:
        print(f"successor host error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
