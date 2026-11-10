from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from email import policy as email_policy
from email.parser import BytesParser
from enum import StrEnum
from functools import lru_cache
from importlib.metadata import PackageNotFoundError, distribution
from importlib.resources import files
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, TypeVar, cast

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError as JsonSchemaSchemaError
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import BaseModel
from pydantic import ValidationError as PydanticValidationError
from referencing import Registry
from referencing.exceptions import Unresolvable

import agent_assure
import agent_assure.schema_resources as schema_resources
from agent_assure.io_limits import (
    MAX_ARTIFACT_JSON_BYTES,
    MAX_JOURNAL_BEARING_RUNSET_JSON_BYTES,
    load_json_bounded,
    load_json_bounded_from_filesystem_root,
    load_json_bytes_bounded,
    loads_json_bounded,
    read_file_bounded_at,
    read_file_bounded_from_filesystem_root,
)
from agent_assure.schema.base import SCHEMA_VERSION, validate_rfc8785_safe_integers
from agent_assure.schema.common import (
    FRACTION_6_PATTERN,
    NONNEGATIVE_DECIMAL_6_PATTERN,
    SIGNED_DECIMAL_6_PATTERN,
    SIGNED_UNIT_INTERVAL_6_PATTERN,
    UNIT_INTERVAL_6_PATTERN,
    UNIT_INTERVAL_12_PATTERN,
    harden_json_schema_pattern_ends,
)
from agent_assure.schema.v1_compatibility import (
    MAX_COMPATIBILITY_MATRIX_BYTES,
    CompatibilityDecision,
    CompatibilityFailure,
    CompatibilityKey,
    assess_compatibility,
    load_compatibility_matrix,
    version_order,
)
from agent_assure.source_layout import source_checkout_component

MAX_FROZEN_SCHEMA_BYTES = 1 * 1024 * 1024
FROZEN_SCHEMA_VERSIONS = frozenset(
    {
        "0.1.0",
        "0.2.0",
        "0.3.1",
        "0.4.3",
        "0.5.0",
        "0.6.0",
        "0.6.1",
        "0.6.2",
        "0.6.3",
        "0.6.4",
        "0.6.5",
        "0.6.6",
    }
)
_DRAFT_2020_12_URI = "https://json-schema.org/draft/2020-12/schema"
_NO_REMOTE_SCHEMA_REGISTRY: Registry[Any] = Registry()
ArtifactModelT = TypeVar("ArtifactModelT", bound=BaseModel)
_FROZEN_DECIMAL_PATTERN_REPLACEMENTS = {
    r"^0\.[0-9]{6}$": FRACTION_6_PATTERN,
    r"^(0|[1-9][0-9]*)\.[0-9]{6}$": NONNEGATIVE_DECIMAL_6_PATTERN,
    r"^-?(0|[1-9][0-9]*)\.[0-9]{6}$": SIGNED_DECIMAL_6_PATTERN,
    r"^(0|1)\.[0-9]{6}$": UNIT_INTERVAL_6_PATTERN,
    r"^(0\.[0-9]{6}|1\.000000)$": UNIT_INTERVAL_6_PATTERN,
    r"^-?(0|1)\.[0-9]{6}$": SIGNED_UNIT_INTERVAL_6_PATTERN,
    r"^(0|1)\.[0-9]{12}$": UNIT_INTERVAL_12_PATTERN,
}
_V060_SEMANTIC_ARTIFACT_KINDS = frozenset(
    {
        "assurance-evidence-descriptor",
        "assurance-mutation-operator",
        "assurance-mutation-result",
        "expected-detection-contract",
        "live-comparison-report",
        "live-drift-report",
        "live-evaluation-report",
        "live-protocol-record",
        "live-trajectory-report",
    }
)
_V061_SEMANTIC_ARTIFACT_KINDS = _V060_SEMANTIC_ARTIFACT_KINDS | {
    "assurance-mutation-catalog",
    "assurance-mutation-campaign",
}
_V062_SEMANTIC_ARTIFACT_KINDS = _V061_SEMANTIC_ARTIFACT_KINDS | {
    "control-efficacy-report",
    "threat-applicability-manifest",
}
_V063_SEMANTIC_ARTIFACT_KINDS = _V062_SEMANTIC_ARTIFACT_KINDS | {
    "assurance-evidence-graph",
}
_V064_SEMANTIC_ARTIFACT_KINDS = _V063_SEMANTIC_ARTIFACT_KINDS | {
    "evidence-sensitivity-protocol",
    "evidence-sensitivity-report",
    "process-equivalence-reproduction-index",
    "rag-sensitivity-corpus-manifest",
    "rag-sensitivity-corpus-snapshot",
    "rag-sensitivity-knowledge-contract",
    "rag-sensitivity-synthetic-data-attestation",
}
_V065_SEMANTIC_ARTIFACT_KINDS = _V064_SEMANTIC_ARTIFACT_KINDS | {
    "repeated-evidence-sensitivity-protocol",
    "statistical-sufficiency-report",
    "stochastic-evidence-sensitivity-report",
}
_LEGACY_SEMANTIC_ARTIFACT_KINDS = {
    "0.6.0": _V060_SEMANTIC_ARTIFACT_KINDS,
    "0.6.1": _V061_SEMANTIC_ARTIFACT_KINDS,
    "0.6.2": _V062_SEMANTIC_ARTIFACT_KINDS,
    "0.6.3": _V063_SEMANTIC_ARTIFACT_KINDS,
    "0.6.4": _V064_SEMANTIC_ARTIFACT_KINDS,
    "0.6.5": _V065_SEMANTIC_ARTIFACT_KINDS,
    "0.6.6": frozenset({"usage-pricing-snapshot"}),
}
_HISTORICAL_SCHEMA_VERSIONS = FROZEN_SCHEMA_VERSIONS - {SCHEMA_VERSION}


class FrozenRootValidationPolicy(StrEnum):
    """Trust policy for one exact exported frozen root schema."""

    semantic_replay = "semantic-replay"
    archival_only = "archival-only"
    current_semantic = "current-semantic"


# This inventory is intentionally independent of the models registered by the
# current writer.  It represents roots that are reachable through the exact
# frozen dispatch path ``schemas/v{wire_version}/{kind}.schema.json`` *and*
# whose root schema admits that same wire version.  Merely having a file at the
# dispatch path is insufficient: several historical usage exports retained an
# older root-version vocabulary and therefore cannot validate the directory
# version.  Conversely, a later root that broadly declares an earlier version
# does not make that pair reachable when the exact earlier dispatch file is
# absent.  Tests reconcile this inventory against both parts of that contract.
# Newly reachable roots default to archival-only until a complete semantic
# replay is explicitly allowlisted below.
_USAGE_FROZEN_ARTIFACT_KINDS = frozenset(
    {
        "usage-ledger",
        "usage-pricing-snapshot",
        "usage-segment",
        "usage-summary",
        "usage-summary-delta",
    }
)
_V010_FROZEN_ARTIFACT_KINDS = frozenset(
    {
        "agent-run-record",
        "comparison-report",
        "comparison-summary",
        "compiled-suite",
        "environment-info",
        "evaluation-report",
        "evaluation-summary",
        "evidence-packet",
        "expectation",
        "expectation-change-record",
        "fixture-manifest",
        "live-comparison-report",
        "live-evaluation-report",
        "live-protocol-record",
        "release-artifact-manifest",
        "release-digest-replay",
        "run-set",
        "span-plan",
    }
)
_V020_FROZEN_ARTIFACT_KINDS = _V010_FROZEN_ARTIFACT_KINDS | {
    "emergency-process-record",
    "live-drift-report",
    "live-trajectory-report",
}
_V031_FROZEN_ARTIFACT_KINDS = _V020_FROZEN_ARTIFACT_KINDS | {
    "usage-ledger",
    "usage-segment",
    "usage-summary",
    "usage-summary-delta",
}
_V043_FROZEN_ARTIFACT_KINDS = _V031_FROZEN_ARTIFACT_KINDS | {
    "control-coverage-report",
    "usage-pricing-snapshot",
}
_V050_FROZEN_ARTIFACT_KINDS = (_V043_FROZEN_ARTIFACT_KINDS - _USAGE_FROZEN_ARTIFACT_KINDS) | {
    "stream-event-record",
    "stream-ingestion-diagnostics",
    "stream-run",
}
_V060_FROZEN_ARTIFACT_KINDS = _V050_FROZEN_ARTIFACT_KINDS | {
    "assurance-evidence-descriptor",
    "assurance-mutation-operator",
    "assurance-mutation-result",
    "expected-detection-contract",
}
_V061_FROZEN_ARTIFACT_KINDS = _V060_FROZEN_ARTIFACT_KINDS | {
    "assurance-mutation-campaign",
    "assurance-mutation-catalog",
}
_V062_FROZEN_ARTIFACT_KINDS = _V061_FROZEN_ARTIFACT_KINDS | {
    "control-efficacy-report",
    "threat-applicability-manifest",
}
_V063_FROZEN_ARTIFACT_KINDS = _V062_FROZEN_ARTIFACT_KINDS | {
    "assurance-evidence-graph",
}
_V064_FROZEN_ARTIFACT_KINDS = _V063_FROZEN_ARTIFACT_KINDS | {
    "evidence-sensitivity-protocol",
    "evidence-sensitivity-report",
    "process-equivalence-reproduction-index",
    "rag-sensitivity-corpus-manifest",
    "rag-sensitivity-corpus-snapshot",
    "rag-sensitivity-knowledge-contract",
    "rag-sensitivity-synthetic-data-attestation",
}
_V065_FROZEN_ARTIFACT_KINDS = _V064_FROZEN_ARTIFACT_KINDS | {
    "repeated-evidence-sensitivity-protocol",
    "statistical-sufficiency-report",
    "stochastic-evidence-sensitivity-report",
}
_V066_FROZEN_ARTIFACT_KINDS = (_V065_FROZEN_ARTIFACT_KINDS | _USAGE_FROZEN_ARTIFACT_KINDS) | {
    "external-pilot-evidence",
    "external-pilot-independence-review",
    "external-pilot-input-manifest",
    "process-equivalence-benchmark",
    "real-model-study-execution-review",
    "real-model-study-manifest",
    "real-model-study-registration-review",
    "real-model-study-report",
    "real-model-study-statistical-method-review",
}
_FROZEN_ARTIFACT_KINDS_BY_VERSION = {
    "0.1.0": _V010_FROZEN_ARTIFACT_KINDS,
    "0.2.0": _V020_FROZEN_ARTIFACT_KINDS,
    "0.3.1": _V031_FROZEN_ARTIFACT_KINDS,
    "0.4.3": _V043_FROZEN_ARTIFACT_KINDS,
    "0.5.0": _V050_FROZEN_ARTIFACT_KINDS,
    "0.6.0": _V060_FROZEN_ARTIFACT_KINDS,
    "0.6.1": _V061_FROZEN_ARTIFACT_KINDS,
    "0.6.2": _V062_FROZEN_ARTIFACT_KINDS,
    "0.6.3": _V063_FROZEN_ARTIFACT_KINDS,
    "0.6.4": _V064_FROZEN_ARTIFACT_KINDS,
    "0.6.5": _V065_FROZEN_ARTIFACT_KINDS,
    "0.6.6": _V066_FROZEN_ARTIFACT_KINDS,
}
_HISTORICAL_ALWAYS_ARCHIVAL_ARTIFACT_KINDS = frozenset(
    {
        # Decision-bearing roots lack complete historical arithmetic and source
        # projections. A successful shape check cannot authenticate a verdict.
        "comparison-report",
        "comparison-summary",
        "evaluation-report",
        "evaluation-summary",
        "evidence-packet",
        # These wires do not retain the complete plans and exact source
        # bindings needed to prove that no diagnostic or governance finding
        # was removed, even where a compatibility model can recheck a subset.
        "live-drift-report",
        "live-trajectory-report",
        # Release roots have a deliberately separate integrity-only digest
        # reproduction path. They are not assurance-valid historical evidence.
        "release-artifact-manifest",
        "release-digest-replay",
    }
)
_PRE_V06_ARCHIVAL_LIVE_ARTIFACT_KINDS = frozenset(
    {"live-comparison-report", "live-evaluation-report", "live-protocol-record"}
)
_PRE_V06_SCHEMA_VERSIONS = frozenset({"0.1.0", "0.2.0", "0.3.1", "0.4.3", "0.5.0"})
_COMPLETE_HISTORICAL_MODEL_REPLAY_ARTIFACT_KINDS = frozenset(
    {
        "agent-run-record",
        "compiled-suite",
        "control-coverage-report",
        "emergency-process-record",
        "environment-info",
        "expectation",
        "expectation-change-record",
        "fixture-manifest",
        "run-set",
        "span-plan",
        "stream-event-record",
        "stream-ingestion-diagnostics",
        "stream-run",
        "usage-ledger",
        "usage-pricing-snapshot",
        "usage-segment",
        "usage-summary",
        "usage-summary-delta",
    }
)


def _build_frozen_validation_policy() -> dict[tuple[str, str], FrozenRootValidationPolicy]:
    if set(_FROZEN_ARTIFACT_KINDS_BY_VERSION) != set(FROZEN_SCHEMA_VERSIONS):
        raise RuntimeError("frozen artifact inventory does not cover every frozen version")
    policy: dict[tuple[str, str], FrozenRootValidationPolicy] = {}
    for schema_version, artifact_kinds in _FROZEN_ARTIFACT_KINDS_BY_VERSION.items():
        semantic_kinds = _LEGACY_SEMANTIC_ARTIFACT_KINDS.get(schema_version, frozenset())
        if not semantic_kinds <= artifact_kinds:
            raise RuntimeError(
                f"semantic replay allowlist contains unknown {schema_version} artifact kinds"
            )
        for artifact_kind in artifact_kinds:
            if schema_version == SCHEMA_VERSION:
                disposition = FrozenRootValidationPolicy.current_semantic
            elif schema_version == "0.1.0":
                # The current typed vocabulary intentionally begins at v0.2.0.
                disposition = FrozenRootValidationPolicy.archival_only
            elif (
                artifact_kind in _HISTORICAL_ALWAYS_ARCHIVAL_ARTIFACT_KINDS
                or schema_version in _PRE_V06_SCHEMA_VERSIONS
                and artifact_kind in _PRE_V06_ARCHIVAL_LIVE_ARTIFACT_KINDS
            ):
                disposition = FrozenRootValidationPolicy.archival_only
            elif (
                artifact_kind in semantic_kinds
                or artifact_kind in _COMPLETE_HISTORICAL_MODEL_REPLAY_ARTIFACT_KINDS
            ):
                # The current compatibility model is the complete semantic
                # replay for this exact pair. Frozen shape validation always
                # runs first, preserving the historical vocabulary boundary.
                disposition = FrozenRootValidationPolicy.semantic_replay
            else:
                # New frozen roots are denied by default until maintainers
                # explicitly classify their replay as complete.
                disposition = FrozenRootValidationPolicy.archival_only
            policy[(artifact_kind, schema_version)] = disposition
    return policy


FROZEN_ROOT_VALIDATION_POLICY: Mapping[tuple[str, str], FrozenRootValidationPolicy] = (
    MappingProxyType(_build_frozen_validation_policy())
)
_INSTALLED_COMPATIBILITY_MATRIX_PATH = "v1.0.0rc1/compatibility-matrix.json"
_MAX_INSTALLED_READER_RECORD_ENTRIES = 10_000
_MAX_INSTALLED_READER_RECORD_NAME_CHARS = 512
_MAX_INSTALLED_READER_MODULE_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True)
class _InstalledReaderIdentity:
    package_version: str
    resource_root: Path
    record_names: frozenset[str]


@dataclass(frozen=True)
class _InstalledRecordEntry:
    digest: str | None
    size: int | None


def _parse_installed_record(data: bytes) -> dict[str, _InstalledRecordEntry]:
    """Parse bounded strings only; never stat or follow arbitrary RECORD rows."""
    if len(data) > MAX_COMPATIBILITY_MATRIX_BYTES:
        raise ValueError("installed reader RECORD exceeds maximum supported size")
    result: dict[str, _InstalledRecordEntry] = {}
    try:
        rows = csv.reader(io.StringIO(data.decode("utf-8"), newline=""), strict=True)
        for row in rows:
            if len(result) >= _MAX_INSTALLED_READER_RECORD_ENTRIES or len(row) != 3:
                raise ValueError("installed reader RECORD inventory is malformed or oversized")
            name, digest, size = row
            if (
                not name
                or len(name) > _MAX_INSTALLED_READER_RECORD_NAME_CHARS
                or any(ord(character) < 32 or ord(character) == 127 for character in name)
                or "\\" in name
                or PurePosixPath(name).is_absolute()
                or re.match(r"^[A-Za-z]:", name) is not None
                or name in result
            ):
                raise ValueError("installed reader RECORD path is malformed or duplicated")
            if digest or size:
                if re.fullmatch(r"sha256=[A-Za-z0-9_-]{43}", digest, flags=re.ASCII) is None:
                    raise ValueError("installed reader RECORD requires a canonical SHA-256 digest")
                if re.fullmatch(r"(?:0|[1-9][0-9]{0,8})", size, flags=re.ASCII) is None:
                    raise ValueError("installed reader RECORD size is malformed or unbounded")
                result[name] = _InstalledRecordEntry(digest, int(size))
            else:
                result[name] = _InstalledRecordEntry(None, None)
    except (csv.Error, UnicodeError) as exc:
        raise ValueError("installed reader RECORD is not valid bounded UTF-8 CSV") from exc
    return result


def _require_installed_record_bytes(
    record: Mapping[str, _InstalledRecordEntry], relative: str, data: bytes
) -> None:
    entry = record.get(relative)
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")
    if entry is None or entry.digest != f"sha256={digest}" or entry.size != len(data):
        raise ValueError("installed reader bytes do not match their owned RECORD row")


def _read_installed_reader_identity() -> _InstalledReaderIdentity:
    """Bind modules using bounded raw metadata for one unpacked wheel.

    PathDistribution's metadata/files accessors are deliberately not used: they
    read unbounded text and files() may stat every candidate-controlled row.
    Only its guarded metadata-directory anchor is used. Other installation
    backends and editable/directory installs are unsupported by this profile.
    """
    try:
        installed = distribution("agent-assure")
    except PackageNotFoundError as exc:
        raise ValueError("installed reader distribution is unavailable") from exc
    anchor = getattr(installed, "_path", None)
    if (
        not isinstance(anchor, Path)
        or not anchor.is_absolute()
        or not anchor.name.endswith(".dist-info")
    ):
        raise ValueError("installed reader requires an unpacked wheel metadata anchor")
    raw_metadata = read_file_bounded_at(
        anchor, "METADATA", max_bytes=MAX_COMPATIBILITY_MATRIX_BYTES, label="installed METADATA"
    ).data
    raw_metadata.decode("utf-8")
    headers = BytesParser(policy=email_policy.compat32).parsebytes(raw_metadata, headersonly=True)
    names = headers.get_all("Name", [])
    versions = headers.get_all("Version", [])
    if headers.defects or len(names) != 1 or len(versions) != 1:
        raise ValueError("installed reader METADATA requires one exact Name and Version")
    if names[0] != "agent-assure":
        raise ValueError("installed reader distribution name does not match")
    reader_version = versions[0]
    if not isinstance(reader_version, str):
        raise ValueError("installed reader METADATA version is not a canonical string")
    version_order(reader_version)
    if reader_version != agent_assure.__version__:
        raise ValueError("installed reader version does not match the loaded package")
    if anchor.name != f"agent_assure-{reader_version}.dist-info":
        raise ValueError("installed reader metadata anchor does not match its exact identity")
    raw_record = read_file_bounded_at(
        anchor, "RECORD", max_bytes=MAX_COMPATIBILITY_MATRIX_BYTES, label="installed RECORD"
    ).data
    record = _parse_installed_record(raw_record)
    metadata_relative = f"{anchor.name}/METADATA"
    _require_installed_record_bytes(record, metadata_relative, raw_metadata)
    if record.get(f"{anchor.name}/RECORD") != _InstalledRecordEntry(None, None):
        raise ValueError("installed reader RECORD does not own its exact metadata directory")
    installation_root = anchor.parent
    owned_modules = (
        ("agent_assure/__init__.py", agent_assure.__file__),
        ("agent_assure/schema/validation.py", __file__),
        ("agent_assure/schema_resources/__init__.py", schema_resources.__file__),
    )
    for relative, actual in owned_modules:
        located = installation_root / relative
        if (
            relative not in record
            or actual is None
            or not Path(actual).is_absolute()
            or located.absolute() != Path(actual).absolute()
        ):
            raise ValueError("installed reader does not own the loaded module paths")
        raw_module = read_file_bounded_at(
            installation_root,
            relative,
            max_bytes=_MAX_INSTALLED_READER_MODULE_BYTES,
            label="installed reader module",
        ).data
        _require_installed_record_bytes(record, relative, raw_module)
    resource_module_file = schema_resources.__file__
    if resource_module_file is None:  # Kept explicit for the checked optional module attribute.
        raise ValueError("installed reader resource package has no filesystem identity")
    resource_root = Path(resource_module_file).absolute().parent
    direct_urls = tuple(name for name in record if PurePosixPath(name).name == "direct_url.json")
    expected_provenance = f"{anchor.name}/direct_url.json"
    if any(name != expected_provenance for name in direct_urls):
        raise ValueError("installed reader provenance does not belong to its metadata directory")
    if direct_urls:
        raw_provenance = read_file_bounded_at(
            anchor,
            "direct_url.json",
            max_bytes=MAX_COMPATIBILITY_MATRIX_BYTES,
            label="installed reader provenance",
        ).data
        _require_installed_record_bytes(record, expected_provenance, raw_provenance)
        provenance = load_json_bytes_bounded(
            raw_provenance,
            max_bytes=MAX_COMPATIBILITY_MATRIX_BYTES,
            label="installed reader provenance",
        )
        if (
            "dir_info" in provenance
            or "vcs_info" in provenance
            or not isinstance(provenance.get("archive_info"), dict)
            or not isinstance(provenance.get("url"), str)
        ):
            raise ValueError("installed reader provenance is not a wheel installation")
    return _InstalledReaderIdentity(reader_version, resource_root, frozenset(record))


def _installed_reader_identity() -> _InstalledReaderIdentity:
    try:
        return _read_installed_reader_identity()
    except OSError as exc:
        raise ValueError("installed reader metadata or owned module bytes are unavailable") from exc


def _require_frozen_identity_admission(
    schema: dict[str, Any], *, schema_version: str, kind: str
) -> None:
    """Check actual identity admission in its offline full-schema reference context."""
    if schema.get("type") != "object":
        raise ValueError("installed frozen schema must have an object root")
    validator = _compiled_json_schema_validator(_serialized_schema_cache_key(schema))
    identities = {"artifact_kind": kind, "schema_version": schema_version}
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        raise ValueError("installed frozen schema has no root properties")
    for field_name, expected in identities.items():
        declaration = properties.get(field_name)
        if not isinstance(declaration, dict):
            raise ValueError("installed frozen schema lacks an identity declaration")
        validator.evolve(schema=declaration).validate(expected)
    # Required nonidentity fields are intentionally absent from this probe.
    # Retain errors that actually contradict one of the supplied identities,
    # including constraints contributed by root-level allOf/not declarations.
    pending = list(validator.iter_errors(identities))
    while pending:
        error = pending.pop()
        if error.path:
            if error.path[0] in identities:
                raise ValueError("installed frozen schema rejects its declared identity pair")
        elif error.context:
            pending.extend(error.context)
        elif error.validator in {"type", "const", "enum", "not", "maxProperties", "oneOf"}:
            raise ValueError("installed frozen schema rejects its declared identity pair")


def _read_installed_compatibility_resource(
    reader: _InstalledReaderIdentity,
    relative: str,
    *,
    max_bytes: int,
) -> bytes | None:
    parts = PurePosixPath(relative).parts
    if len(parts) != 2 or any(part in {".", ".."} for part in parts) or "\\" in relative:
        raise ValueError("installed compatibility resource path is malformed")
    if f"agent_assure/schema_resources/{relative}" not in reader.record_names:
        return None
    resource_root = files("agent_assure.schema_resources")
    if not isinstance(resource_root, Path) or resource_root.absolute() != reader.resource_root:
        raise ValueError("installed compatibility resource package identity does not match")
    try:
        return read_file_bounded_at(
            reader.resource_root,
            relative,
            max_bytes=max_bytes,
            label="installed compatibility resource",
        ).data
    except FileNotFoundError:
        return None


def _frozen_root_semantic_replay_identity(kind: str, schema_version: str) -> str | None:
    policy = FROZEN_ROOT_VALIDATION_POLICY.get((kind, schema_version))
    if policy is None or policy is FrozenRootValidationPolicy.archival_only:
        return None
    return f"agent-assure:frozen-root/{schema_version}/{kind}/{policy.value}"


def inspect_installed_reader_compatibility(
    *,
    producer_package_version: str,
    writer_schema_version: str,
    artifact_kind: str,
    expected_matrix_digest: str,
) -> CompatibilityDecision:
    """Inspect exact installed-resource compatibility, with no authorization effect.

    The caller supplies independently bound producer provenance and a matrix
    digest from the verifier-owned candidate inventory. Neither is inferred
    from an artifact or accepted from an unverified candidate success flag.
    Reader identity comes only from the installed distribution. This function
    validates registry/schema resources, not an artifact or an assurance claim.
    It never projects artifact data, downloads resources, or consults a checkout.
    """
    if (
        not isinstance(expected_matrix_digest, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", expected_matrix_digest, flags=re.ASCII) is None
    ):
        raise ValueError("expected compatibility matrix digest must be exact lowercase SHA-256")
    reader = _installed_reader_identity()
    key = CompatibilityKey(
        producer_package_version=producer_package_version,
        writer_schema_version=writer_schema_version,
        artifact_kind=artifact_kind,
        reader_package_version=reader.package_version,
    )

    def unsupported(
        reason: CompatibilityFailure,
        *,
        minimum_reader_satisfied: bool = False,
        schema_integrity_verified: bool = False,
    ) -> CompatibilityDecision:
        return CompatibilityDecision(
            key=key,
            disposition="unsupported",
            reason=reason,
            minimum_reader_satisfied=minimum_reader_satisfied,
            schema_integrity_verified=schema_integrity_verified,
            authorization_effect="none",
        )

    try:
        raw_matrix = _read_installed_compatibility_resource(
            reader,
            _INSTALLED_COMPATIBILITY_MATRIX_PATH,
            max_bytes=MAX_COMPATIBILITY_MATRIX_BYTES,
        )
    except (OSError, ValueError, ModuleNotFoundError):
        return unsupported("SCHEMA_COMPATIBILITY_MATRIX_UNAVAILABLE")
    if raw_matrix is None:
        return unsupported("SCHEMA_COMPATIBILITY_MATRIX_UNAVAILABLE")
    if len(raw_matrix) > MAX_COMPATIBILITY_MATRIX_BYTES:
        return unsupported("SCHEMA_COMPATIBILITY_MATRIX_INVALID")
    if f"sha256:{hashlib.sha256(raw_matrix).hexdigest()}" != expected_matrix_digest:
        return unsupported("SCHEMA_COMPATIBILITY_MATRIX_DIGEST_MISMATCH")
    try:
        matrix = load_compatibility_matrix(raw_matrix)
    except ValueError:
        return unsupported("SCHEMA_COMPATIBILITY_MATRIX_INVALID")
    preflight = assess_compatibility(matrix, key, schema_resource=None)
    if preflight.reason != "SCHEMA_RESOURCE_UNAVAILABLE":
        return preflight
    cell = matrix.lookup(key)
    if cell is None:  # The preflight guarantees this, without interpreting candidate flags.
        raise AssertionError("compatibility preflight did not retain its exact cell")
    policy = FROZEN_ROOT_VALIDATION_POLICY.get((artifact_kind, writer_schema_version))
    if policy is None:
        return unsupported("SCHEMA_COMPATIBILITY_CELL_ABSENT", minimum_reader_satisfied=True)
    if (
        policy is FrozenRootValidationPolicy.archival_only
        and cell.disposition == "semantic_replay_and_authorization_eligible"
    ):
        return unsupported("SCHEMA_COMPATIBILITY_POLICY_MISMATCH", minimum_reader_satisfied=True)
    replay_identity = _frozen_root_semantic_replay_identity(artifact_kind, writer_schema_version)
    replays = frozenset({replay_identity}) if replay_identity is not None else frozenset()
    if cell.semantic_replay_identity is not None and cell.semantic_replay_identity not in replays:
        return unsupported("SCHEMA_SEMANTIC_REPLAY_UNAVAILABLE", minimum_reader_satisfied=True)
    if cell.migration_identity is not None or (
        cell.disposition == "semantic_replay_and_authorization_eligible" and cell.losses
    ):
        return unsupported("SCHEMA_MIGRATION_UNSUPPORTED", minimum_reader_satisfied=True)
    try:
        raw_schema = _read_installed_compatibility_resource(
            reader, cell.schema_resource_path, max_bytes=MAX_FROZEN_SCHEMA_BYTES
        )
    except (OSError, ValueError, ModuleNotFoundError):
        return unsupported("SCHEMA_RESOURCE_UNAVAILABLE", minimum_reader_satisfied=True)
    result = assess_compatibility(
        matrix,
        key,
        schema_resource=raw_schema,
        available_semantic_replays=replays,
    )
    if result.disposition == "unsupported":
        return result
    if raw_schema is None:  # A supported assessment requires the original immutable bytes.
        raise AssertionError("compatibility assessment did not retain its schema resource")
    try:
        schema = load_json_bytes_bounded(
            raw_schema, max_bytes=MAX_FROZEN_SCHEMA_BYTES, label="frozen JSON Schema"
        )
        _prepare_frozen_schema(schema, schema_version=writer_schema_version, kind=artifact_kind)
        _harden_frozen_decimal_patterns(schema)
        harden_json_schema_pattern_ends(schema)
        _require_frozen_identity_admission(
            schema, schema_version=writer_schema_version, kind=artifact_kind
        )
    except (
        ValueError,
        JsonSchemaSchemaError,
        JsonSchemaValidationError,
        Unresolvable,
        RecursionError,
    ):
        return unsupported(
            "SCHEMA_RESOURCE_INVALID",
            minimum_reader_satisfied=True,
            schema_integrity_verified=True,
        )
    return result


_LEGACY_RELEASE_IDENTITY_ARTIFACT_KINDS = frozenset(
    {"release-artifact-manifest", "release-digest-replay"}
)


class ArchivalOnlyArtifactError(ValueError):
    """A frozen wire form is structurally inspectable but not decision-valid."""


def load_json(path: Path) -> dict[str, Any]:
    return load_json_bounded_from_filesystem_root(path)


def validate_artifact(path: Path, kind: str) -> str:
    payload = load_json_bounded_from_filesystem_root(
        path,
        max_bytes=maximum_artifact_json_bytes(kind),
        label=f"{kind} artifact JSON",
    )
    return validate_artifact_payload(payload, kind)


def load_validated_artifact_payload(
    path: Path,
    kind: str,
    *,
    max_bytes: int | None = None,
    label: str | None = None,
) -> dict[str, Any]:
    """Load and validate persisted bytes before any current-model projection."""
    payload, _, _ = _load_validated_artifact_payload_snapshot(
        path,
        kind,
        max_bytes=max_bytes,
        label=label,
    )
    return payload


def load_validated_artifact_payload_with_size(
    path: Path,
    kind: str,
    *,
    max_bytes: int | None = None,
    label: str | None = None,
) -> tuple[dict[str, Any], int]:
    """Load once, validate, and return the exact bounded raw byte count."""

    payload, size, _ = _load_validated_artifact_payload_snapshot(
        path,
        kind,
        max_bytes=max_bytes,
        label=label,
    )
    return payload, size


def load_validated_artifact_payload_with_sha256(
    path: Path,
    kind: str,
    *,
    max_bytes: int | None = None,
    label: str | None = None,
) -> tuple[dict[str, Any], str]:
    """Load once and return validation plus the digest of those exact bytes."""

    payload, _, digest = _load_validated_artifact_payload_snapshot(
        path,
        kind,
        max_bytes=max_bytes,
        label=label,
    )
    return payload, digest


def load_validated_artifact_model(
    path: Path,
    model: type[ArtifactModelT],
    *,
    kind: str,
    max_bytes: int | None = None,
    label: str | None = None,
) -> ArtifactModelT:
    """Boundedly load, schema-validate, and project an artifact exactly once.

    Current artifacts retain writer-schema and Pydantic validation. Historical
    artifacts are projected only when their exact kind/version pair has a
    complete, explicitly registered semantic replay. Structural-only pairs are
    archival and fail closed at this public assurance boundary.
    """

    parsed, _ = load_validated_artifact_model_with_size(
        path,
        model,
        kind=kind,
        max_bytes=max_bytes,
        label=label,
    )
    return parsed


def load_validated_artifact_model_with_size(
    path: Path,
    model: type[ArtifactModelT],
    *,
    kind: str,
    max_bytes: int | None = None,
    label: str | None = None,
) -> tuple[ArtifactModelT, int]:
    """Load one exact byte snapshot and return its sole projection and size."""

    from agent_assure.schema.export import model_for_kind

    expected_model = model_for_kind(kind)
    if model is not expected_model:
        raise ValueError(f"model does not match registered artifact kind {kind!r}")
    effective_max = maximum_artifact_json_bytes(kind) if max_bytes is None else max_bytes
    effective_label = "artifact JSON" if label is None else label
    contents = read_file_bounded_from_filesystem_root(
        path,
        max_bytes=effective_max,
        label=effective_label,
    )
    payload = load_json_bytes_bounded(
        contents.data,
        max_bytes=effective_max,
        label=effective_label,
    )
    try:
        _, parsed = _validate_artifact_payload_internal(
            payload,
            kind,
            projection_model=model,
            require_frozen_projection=True,
        )
    except JsonSchemaValidationError as exc:
        raise ValueError(f"{kind} artifact failed JSON Schema validation") from exc
    if parsed is None:  # pragma: no cover - internal invariant
        raise AssertionError("validated artifact model projection was not produced")
    return parsed, contents.size


def _load_validated_artifact_payload_snapshot(
    path: Path,
    kind: str,
    *,
    max_bytes: int | None,
    label: str | None,
) -> tuple[dict[str, Any], int, str]:
    """Read one bounded byte snapshot and derive every trust decision from it."""

    effective_max = maximum_artifact_json_bytes(kind) if max_bytes is None else max_bytes
    effective_label = "artifact JSON" if label is None else label
    contents = read_file_bounded_from_filesystem_root(
        path,
        max_bytes=effective_max,
        label=effective_label,
    )
    payload = load_json_bytes_bounded(
        contents.data,
        max_bytes=effective_max,
        label=effective_label,
    )
    validate_loaded_artifact_payload(payload, kind)
    return payload, contents.size, hashlib.sha256(contents.data).hexdigest()


def maximum_artifact_json_bytes(kind: str) -> int:
    """Return the trusted-kind JSON input limit used by public artifact readers."""

    if kind == "run-set":
        return MAX_JOURNAL_BEARING_RUNSET_JSON_BYTES
    return MAX_ARTIFACT_JSON_BYTES


def validate_loaded_artifact_payload(payload: dict[str, Any], kind: str) -> str:
    """Validate a loaded artifact and normalize data errors for runtime callers."""
    try:
        return validate_artifact_payload(payload, kind)
    except JsonSchemaValidationError as exc:
        raise ValueError(f"{kind} artifact failed JSON Schema validation") from exc


def validate_loaded_artifact_model(
    payload: dict[str, Any],
    model: type[ArtifactModelT],
    *,
    kind: str,
) -> ArtifactModelT:
    """Validate loaded bytes and return their single semantic projection.

    This is the in-memory counterpart to :func:`load_validated_artifact_model`.
    It keeps JSON Schema and Pydantic validation in one trust-boundary pass so
    callers do not need to validate the same potentially expensive semantic
    model a second time merely to recover the projection already produced by
    the validator.
    """

    try:
        _, parsed = _validate_artifact_payload_internal(
            payload,
            kind,
            projection_model=model,
            require_frozen_projection=True,
        )
    except JsonSchemaValidationError as exc:
        raise ValueError(f"{kind} artifact failed JSON Schema validation") from exc
    if parsed is None:  # pragma: no cover - internal invariant
        raise AssertionError("validated artifact model projection was not produced")
    return parsed


def project_validated_artifact_payload(
    payload: dict[str, Any],
    model: type[ArtifactModelT],
    *,
    kind: str,
) -> ArtifactModelT:
    """Project frozen-schema-valid bytes without exposing Pydantic input values."""
    try:
        return model.model_validate(payload)
    except PydanticValidationError as exc:
        raise ValueError(f"{kind} artifact failed model validation") from exc


def validate_artifact_payload(payload: dict[str, Any], kind: str) -> str:
    """Validate one artifact for assurance use, failing closed on archival roots."""

    result, _ = _validate_artifact_payload_internal(payload, kind)
    return result


def validate_historical_artifact_payload_for_release_replay(
    payload: dict[str, Any],
    kind: str,
) -> str:
    """Validate historical shape for bounded digest reproduction only.

    This deliberately separate API is not an assurance validator. It proves
    only that a historical release input matches the immutable schema selected
    by the trusted caller, plus the role/path uniqueness relation retained by
    historical release roots. It must be used only to reproduce digests of an
    already published bundle and must never authorize an assurance decision.
    """

    from agent_assure.schema.export import model_for_kind

    # Resolve the trusted kind before consulting any artifact-controlled value.
    model_for_kind(kind)
    validate_rfc8785_safe_integers(payload, owner=f"{kind} release-replay artifact")
    schema_version = payload.get("schema_version")
    if not isinstance(schema_version, str):
        raise ValueError("historical release-replay artifact requires schema_version")
    if schema_version not in _HISTORICAL_SCHEMA_VERSIONS:
        raise ValueError("release integrity-only validation requires a historical schema_version")
    _frozen_root_policy(kind=kind, schema_version=schema_version)
    try:
        result = _validate_legacy_frozen_schema(payload, kind)
    except JsonSchemaValidationError as exc:
        raise ValueError(f"{kind} release-replay artifact failed frozen schema validation") from exc
    if result is None:  # pragma: no cover - guarded by the historical version check
        raise AssertionError("historical frozen-schema validation was not selected")
    if kind in _LEGACY_RELEASE_IDENTITY_ARTIFACT_KINDS:
        try:
            _validate_legacy_release_artifact_identities(payload, kind=kind)
        except ValueError as exc:
            raise ValueError(f"{kind} release-replay artifact failed integrity validation") from exc
    return "frozen-jsonschema+release-integrity-only"


def _validate_artifact_payload_internal(
    payload: dict[str, Any],
    kind: str,
    *,
    projection_model: type[ArtifactModelT] | None = None,
    require_frozen_projection: bool = False,
) -> tuple[str, ArtifactModelT | None]:
    from agent_assure.schema.export import model_for_kind

    # Resolve the requested kind before any artifact-controlled value is used
    # to select a frozen schema filename.
    registered_model = model_for_kind(kind)
    if projection_model is not None and projection_model is not registered_model:
        raise ValueError(f"model does not match registered artifact kind {kind!r}")
    model = cast(type[ArtifactModelT], registered_model)
    validate_rfc8785_safe_integers(payload, owner=f"{kind} artifact")
    _require_matching_historical_artifact_kind(payload, kind=kind)
    # Archival disposition is a trust-boundary decision, not a claim that the
    # supplied bytes are a well-formed archival record.  Once a present root
    # identity is known not to contradict the trusted requested kind, reject
    # the exact historical pair before attempting a full structural parse.
    # This preserves fail-closed behavior for omitted optional legacy identity
    # fields and avoids exposing schema-shape details as a route around policy.
    _reject_archival_only_artifact(payload, kind=kind)
    legacy_result = _validate_legacy_frozen_schema(payload, kind)
    if legacy_result is not None:
        parsed = _validate_legacy_semantics(payload, model, kind=kind)
        if require_frozen_projection and parsed is None:
            parsed = project_validated_artifact_payload(payload, model, kind=kind)
            _require_projected_artifact_kind(parsed, kind)
        return f"{legacy_result}+semantic-replay", parsed
    _require_raw_persisted_identity(payload, kind)
    _validate_current_writer_schema(payload, kind=kind, model=model)
    parsed = project_validated_artifact_payload(payload, model, kind=kind)
    _require_projected_artifact_kind(parsed, kind)
    return "pydantic+jsonschema", parsed


def _require_matching_historical_artifact_kind(
    payload: dict[str, Any],
    *,
    kind: str,
) -> None:
    """Reject a contradictory legacy root identity without trusting its value.

    Some frozen schemas made ``artifact_kind`` optional, so absence cannot
    select or bypass archival policy.  A present contradictory value is still
    malformed and must not be reported merely as an archival artifact.
    """

    schema_version = payload.get("schema_version")
    if not isinstance(schema_version, str) or schema_version not in _HISTORICAL_SCHEMA_VERSIONS:
        return
    artifact_kind = payload.get("artifact_kind")
    if artifact_kind is not None and artifact_kind != kind:
        raise JsonSchemaValidationError(
            "historical artifact_kind does not match the trusted requested kind"
        )


def _validate_legacy_semantics(
    payload: dict[str, Any],
    model: type[ArtifactModelT],
    *,
    kind: str,
) -> ArtifactModelT | None:
    """Apply explicit historical semantic checks after immutable shape validation.

    Evidence-carrying roots introduced from v0.6.0 through v0.6.5 are
    shape-compatible with their current projection for values admitted by the
    corresponding frozen schema. Projecting only after frozen validation
    retains each historical vocabulary while restoring self-digest and
    relational checks that JSON Schema cannot express. Older artifact families
    retain their established loader-specific compatibility projections.

    Archival-only live roots are rejected before this function. Their frozen
    schemas remain available as immutable shape descriptions, but their wire
    forms do not retain enough evidence for a complete semantic replay.
    """
    schema_version = payload.get("schema_version")
    if not isinstance(schema_version, str):  # pragma: no cover - frozen schema invariant
        raise AssertionError("frozen artifact has no string schema_version")
    policy = _frozen_root_policy(kind=kind, schema_version=schema_version)
    if policy not in {
        FrozenRootValidationPolicy.semantic_replay,
        FrozenRootValidationPolicy.current_semantic,
    }:
        raise AssertionError("archival-only artifact reached semantic replay")
    parsed = project_validated_artifact_payload(payload, model, kind=kind)
    _require_projected_artifact_kind(parsed, kind)
    _require_replayable_historical_live_protocol(
        payload,
        kind=kind,
        schema_version=schema_version,
    )
    return parsed


def _require_replayable_historical_live_protocol(
    payload: Mapping[str, Any],
    *,
    kind: str,
    schema_version: str,
) -> None:
    """Reject legacy protocol settings unsupported by the semantic replay.

    Historical compatibility models intentionally preserve old live-analysis
    vocabulary for archival parsing.  The assurance validator has a stronger
    contract: every accepted setting must be executable by the versioned
    semantic replay.  Required-review evaluation currently implements only the
    ``human_review`` state, while two declared drift orderings lack authenticated
    ordering keys. Accepting either case would turn a successful shape/model
    projection into false assurance.
    """

    if kind != "live-protocol-record" or schema_version not in _HISTORICAL_SCHEMA_VERSIONS:
        return
    drift_plan = payload.get("drift_monitoring_plan")
    if isinstance(drift_plan, Mapping):
        ordering_variable = drift_plan.get("ordering_variable")
        if ordering_variable in {"release_sequence", "provider_version_window"}:
            raise ValueError(
                f"{kind} schema_version {schema_version!r} cannot be semantically replayed: "
                f"drift ordering_variable={ordering_variable!r} has no authenticated "
                "ordering-key implementation"
            )
    trajectory_plan = payload.get("trajectory_analysis_plan")
    if not isinstance(trajectory_plan, Mapping):
        return
    invariants = trajectory_plan.get("invariants")
    if not isinstance(invariants, list):
        return
    for invariant in invariants:
        if not isinstance(invariant, Mapping):  # pragma: no cover - frozen schema invariant
            continue
        if (
            invariant.get("invariant_type") == "required_review_for_approval"
            and invariant.get("required_state") != "human_review"
        ):
            raise ValueError(
                f"{kind} schema_version {schema_version!r} cannot be semantically replayed: "
                "required_review_for_approval supports only "
                "required_state='human_review'"
            )


def _reject_archival_only_artifact(payload: dict[str, Any], *, kind: str) -> None:
    """Keep structural-only historical assurance roots outside the trust boundary.

    ``agent-assure validate`` is an assurance validator, and its successful
    return value is commonly consumed as a decision-bearing trust signal. A
    matching frozen JSON Schema proves only shape. It must therefore not turn
    an artifact whose arithmetic, source projection, or omitted findings cannot
    be replayed into a plain ``valid`` result.
    """

    schema_version = payload.get("schema_version")
    if not isinstance(schema_version, str) or schema_version not in _HISTORICAL_SCHEMA_VERSIONS:
        return
    policy = _frozen_root_policy(kind=kind, schema_version=schema_version)
    if policy is FrozenRootValidationPolicy.archival_only:
        raise ArchivalOnlyArtifactError(
            f"{kind} schema_version {schema_version!r} is archival-only: its frozen "
            "JSON Schema can support structural inspection, but this wire form lacks "
            "a complete version-specific semantic replay contract and is not valid "
            "for an assurance decision; regenerate current evidence"
        )


def _frozen_root_policy(
    *,
    kind: str,
    schema_version: str,
) -> FrozenRootValidationPolicy:
    """Return the exact pair policy; absence is a trust-boundary failure."""

    try:
        return FROZEN_ROOT_VALIDATION_POLICY[(kind, schema_version)]
    except KeyError as exc:
        raise ValueError(
            "no frozen validation policy is registered for artifact kind "
            f"{kind!r} at schema_version {schema_version!r}"
        ) from exc


def _validate_legacy_release_artifact_identities(
    payload: dict[str, Any],
    *,
    kind: str,
) -> None:
    """Replay the complete release-root identity relation retained on old wires."""

    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, list):  # pragma: no cover - frozen schema invariant
        raise ValueError(f"{kind} artifacts must be an array")
    seen_roles: set[str] = set()
    seen_paths: set[str] = set()
    label = (
        "release artifact manifest"
        if kind == "release-artifact-manifest"
        else "release digest replay"
    )
    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict):  # pragma: no cover - frozen schema invariant
            raise ValueError(f"{kind} artifact at index {index} must be an object")
        role = artifact.get("role")
        path = artifact.get("path")
        if not isinstance(role, str) or not isinstance(path, str):  # pragma: no cover
            raise ValueError(f"{kind} artifact at index {index} has an invalid identity")
        if role in seen_roles:
            raise ValueError(f"{label} contains a duplicate artifact role")
        if path in seen_paths:
            raise ValueError(f"{label} contains a duplicate artifact path")
        seen_roles.add(role)
        seen_paths.add(path)


def _require_projected_artifact_kind(parsed: BaseModel, kind: str) -> None:
    artifact_kind = getattr(parsed, "artifact_kind", None)
    if artifact_kind != kind:
        raise ValueError(f"artifact_kind {artifact_kind!r} does not match requested kind {kind!r}")


def _require_raw_persisted_identity(payload: dict[str, Any], kind: str) -> None:
    from agent_assure.schema.export import persisted_identity_fields_for_kind

    required = persisted_identity_fields_for_kind(kind)
    missing = [field_name for field_name in required if field_name not in payload]
    if missing:
        raise ValueError(
            "persisted artifact requires explicit identity fields before parsing: "
            + ", ".join(missing)
        )


def _validate_legacy_frozen_schema(payload: dict[str, Any], kind: str) -> str | None:
    schema_version = payload.get("schema_version")
    if not isinstance(schema_version, str):
        return None
    if schema_version == SCHEMA_VERSION and kind != "usage-pricing-snapshot":
        return None
    if schema_version not in FROZEN_SCHEMA_VERSIONS:
        raise ValueError(f"unsupported frozen schema_version {schema_version!r}")
    schema = _legacy_frozen_schema(schema_version, kind)
    if schema is None:
        raise ValueError(
            f"no frozen schema is available for artifact kind {kind!r} "
            f"at schema_version {schema_version!r}"
        )
    _prepare_frozen_schema(schema, schema_version=schema_version, kind=kind)
    _harden_frozen_decimal_patterns(schema)
    harden_json_schema_pattern_ends(schema)
    _validate_json_schema(schema, payload)
    return "frozen-jsonschema"


def _legacy_frozen_schema(schema_version: str, kind: str) -> dict[str, Any] | None:
    from agent_assure.schema.export import model_for_kind

    if schema_version not in FROZEN_SCHEMA_VERSIONS:
        raise ValueError(f"unsupported frozen schema_version {schema_version!r}")
    # model_for_kind is an explicit allowlist for the filename component.
    model_for_kind(kind)
    relative_path = f"schemas/v{schema_version}/{kind}.schema.json"
    schema_path = source_checkout_component(__file__, relative_path)
    if schema_path is not None and schema_path.is_file():
        return load_json_bounded(
            schema_path,
            max_bytes=MAX_FROZEN_SCHEMA_BYTES,
            label="frozen JSON Schema",
        )
    try:
        resource = files("agent_assure.schema_resources").joinpath(
            f"v{schema_version}", f"{kind}.schema.json"
        )
    except ModuleNotFoundError:
        return None
    if not resource.is_file():
        return None
    try:
        with resource.open("rb") as handle:
            raw = handle.read(MAX_FROZEN_SCHEMA_BYTES + 1)
    except FileNotFoundError:
        return None
    if len(raw) > MAX_FROZEN_SCHEMA_BYTES:
        raise ValueError("frozen JSON Schema exceeds maximum supported size")
    loaded = loads_json_bounded(raw.decode("utf-8"), label="frozen JSON Schema")
    if not isinstance(loaded, dict):
        raise ValueError("frozen JSON Schema root must be an object")
    return cast(dict[str, Any], loaded)


def _prepare_frozen_schema(
    schema: dict[str, Any],
    *,
    schema_version: str,
    kind: str,
) -> None:
    expected_id = (
        f"https://acblabs.github.io/agent-assure/schemas/v{schema_version}/{kind}.schema.json"
    )
    if schema.get("$schema") != _DRAFT_2020_12_URI:
        raise ValueError("frozen schema has an unexpected JSON Schema dialect")
    if schema.get("$id") != expected_id:
        raise ValueError("frozen schema has an unexpected canonical identity")
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        raise ValueError("frozen schema has no root properties")
    _require_property_accepts_identity(properties, "artifact_kind", kind)
    _require_property_accepts_identity(properties, "schema_version", schema_version)
    _reject_nonlocal_schema_references(schema)


def _harden_frozen_decimal_patterns(schema: object) -> None:
    """Tighten known fixed-decimal patterns without changing frozen bytes.

    Historical generated schemas used ``(0|1)`` as the whole-number branch,
    which admits every fixed-precision value below two rather than only the
    closed unit interval. Their other fixed-decimal patterns also used JSON
    Schema's newline-permissive ``$`` assertion. Apply narrow in-memory
    corrections only to the exact known patterns. The final negative lookahead
    is a true end-of-string assertion, including for a trailing newline.
    """

    pending = [schema]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            for key, child in value.items():
                if key == "pattern" and isinstance(child, str):
                    replacement = _FROZEN_DECIMAL_PATTERN_REPLACEMENTS.get(child)
                    if replacement is not None:
                        value[key] = replacement
                        continue
                pending.append(child)
        elif isinstance(value, list):
            pending.extend(value)


def _require_property_accepts_identity(
    properties: dict[str, Any],
    field_name: str,
    expected: str,
) -> None:
    declaration = properties.get(field_name)
    if not isinstance(declaration, dict) or not _schema_declaration_accepts_identity(
        declaration, expected
    ):
        raise ValueError(f"frozen schema has an invalid {field_name} identity constraint")


def _schema_declaration_accepts_identity(declaration: dict[str, Any], expected: str) -> bool:
    if declaration.get("const") == expected:
        return True
    enum = declaration.get("enum")
    if isinstance(enum, list) and expected in enum:
        return True
    for keyword in ("anyOf", "oneOf"):
        alternatives = declaration.get(keyword)
        if isinstance(alternatives, list) and any(
            isinstance(alternative, dict)
            and _schema_declaration_accepts_identity(alternative, expected)
            for alternative in alternatives
        ):
            return True
    return False


def _reject_nonlocal_schema_references(schema: object) -> None:
    pending = [schema]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            for key, child in value.items():
                if key in {"$ref", "$dynamicRef"} and (
                    not isinstance(child, str) or not child.startswith("#")
                ):
                    raise ValueError("frozen schema contains a non-local schema reference")
                pending.append(child)
        elif isinstance(value, list):
            pending.extend(value)


def _validate_json_schema(schema: dict[str, Any], payload: dict[str, Any]) -> None:
    validator = _compiled_json_schema_validator(_serialized_schema_cache_key(schema))
    validator.validate(payload)


def _validate_current_writer_schema(
    payload: dict[str, Any],
    *,
    kind: str,
    model: type[BaseModel],
) -> None:
    """Validate against the cached schema selected by a trusted kind/model pair."""

    _current_writer_schema_validator(kind, model).validate(payload)


@lru_cache(maxsize=128)
def _current_writer_schema_validator(
    kind: str,
    model: type[BaseModel],
) -> Draft202012Validator:
    """Compile one current writer schema once without trusting artifact fields.

    ``kind`` is resolved through the closed writer registry before compilation,
    and the model identity is part of the cache key.  Artifact-controlled
    ``artifact_kind`` and ``schema_version`` values therefore cannot select or
    poison a cached validator.
    """

    from agent_assure.schema.export import (
        model_for_kind,
        require_persisted_identity_in_schema,
        writer_json_schema,
    )

    if model_for_kind(kind) is not model:
        raise ValueError(f"model does not match registered artifact kind {kind!r}")
    schema = writer_json_schema(model)
    require_persisted_identity_in_schema(schema, kind)
    schema["$schema"] = _DRAFT_2020_12_URI
    return _compiled_json_schema_validator(_serialized_schema_cache_key(schema))


def _serialized_schema_cache_key(schema: dict[str, Any]) -> str:
    """Return an exact, mutation-sensitive key for one JSON-compatible schema."""

    return json.dumps(
        schema,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


@lru_cache(maxsize=128)
def _compiled_json_schema_validator(serialized_schema: str) -> Draft202012Validator:
    """Check and compile an immutable snapshot of a schema at most once."""

    schema = json.loads(serialized_schema)
    Draft202012Validator.check_schema(schema)
    # Supplying an explicit empty registry prevents jsonschema's deprecated
    # network retrieval fallback. Frozen schemas are intentionally self-contained.
    return Draft202012Validator(
        schema,
        registry=_NO_REMOTE_SCHEMA_REGISTRY,
    )
