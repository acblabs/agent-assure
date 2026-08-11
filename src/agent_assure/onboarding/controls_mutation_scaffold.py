from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from agent_assure import __version__
from agent_assure.authoring.compiler import compile_loaded_suite
from agent_assure.authoring.yaml_nodes import load_yaml_nodes_text
from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.fixtures.loader import compiled_suite_digest
from agent_assure.onboarding.controls_mutation import (
    CONFIG_FILENAME,
    DEFAULT_ONBOARDING_OPERATOR_ID,
    MANAGED_FILENAMES,
    MUTATION_OUTPUT_DIRECTORY,
    RUNSET_FILENAME,
    SUITE_FILENAME,
    THREAT_MANIFEST_FILENAME,
    ControlsMutationOnboardingConfig,
    ScaffoldConflictError,
    ScaffoldResult,
)
from agent_assure.onboarding.path_safety import (
    UnsafeDirectoryChainError,
    require_regular_directory_chain,
)
from agent_assure.onboarding.path_safety import (
    is_explicit_network_path as _is_explicit_network_path,
)
from agent_assure.onboarding.path_safety import (
    is_regular_directory as _is_regular_directory,
)
from agent_assure.onboarding.path_safety import (
    metadata_is_regular_directory as _metadata_is_regular_directory,
)
from agent_assure.onboarding.path_safety import (
    metadata_is_regular_file as _metadata_is_regular_file,
)
from agent_assure.onboarding.path_safety import (
    path_entry_exists as _path_entry_exists,
)
from agent_assure.onboarding.path_safety import (
    read_confined_file as _read_confined_file,
)
from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.schema.campaign import CORE_MUTATION_CATALOG_ID
from agent_assure.schema.common import MACHINE_IDENTIFIER_SCHEMA_VERSION
from agent_assure.schema.efficacy import ThreatApplicabilityManifest
from agent_assure.schema.provenance import Provenance
from agent_assure.schema.run import (
    AgentRunRecord,
    ClaimEvidenceLink,
    ClaimRecord,
    EvidenceItem,
    EvidenceRef,
    RunSet,
)
from agent_assure.schema.suite import CompiledSuite

_CONFIG_ARTIFACT_KIND = "controls-mutation-onboarding-config"
_SCAFFOLD_SUITE_ID = "controls-mutation-quickstart"
_SCAFFOLD_SUITE_VERSION = "1.0.0"
_SCAFFOLD_CASE_ID = "material-evidence-case"
_SCAFFOLD_CLAIM_ID = "material-claim"
_SCAFFOLD_REF_ID = "synthetic-evidence"
_SCAFFOLD_SOURCE_ID = "synthetic-source"
_SCAFFOLD_FIXTURE_DIGEST = sha256_hexdigest(
    "agent-assure controls-mutation synthetic onboarding fixture/v1"
)


@dataclass(frozen=True)
class _CreatedFile:
    path: Path
    device: int
    inode: int
    pin_descriptor: int | None


@dataclass(frozen=True)
class _CreatedDirectory:
    path: Path
    device: int
    inode: int


def scaffold_controls_mutation(directory: Path) -> ScaffoldResult:
    """Create or safely resume the deterministic scaffold without replacing a path."""
    expected = expected_scaffold_files()
    destination = directory.absolute()
    if destination == Path(destination.anchor):
        raise ScaffoldConflictError("refusing to scaffold into a filesystem root")
    if _is_explicit_network_path(destination):
        raise ScaffoldConflictError("refusing to scaffold through a network filesystem path")
    if _path_entry_exists(destination) and not _is_regular_directory(destination):
        raise ScaffoldConflictError("output directory is not a regular directory")

    existing = {
        name: path
        for name in MANAGED_FILENAMES
        if (path := destination / name).exists() or path.is_symlink()
    }
    exact = {
        name for name, path in existing.items() if _matches_expected_file(path, expected[name])
    }
    conflicts = sorted(set(existing) - exact)
    if conflicts:
        raise ScaffoldConflictError(
            "managed scaffold differs; no files were written (conflicting: "
            + ", ".join(conflicts)
            + ")"
        )
    if len(exact) == len(MANAGED_FILENAMES):
        return ScaffoldResult(
            status="unchanged",
            directory=destination,
            paths=tuple(destination / name for name in MANAGED_FILENAMES),
        )
    missing = tuple(name for name in MANAGED_FILENAMES if name not in exact)

    created_directories: list[_CreatedDirectory] = []
    created: list[_CreatedFile] = []
    try:
        if not destination.exists():
            created_directories.extend(_create_directory_chain(destination))
        for name in missing:
            _require_regular_directory_chain(destination)
            path = destination / name
            created.append(_write_new_file(path, expected[name]))
    except Exception:
        for created_file in reversed(created):
            _unlink_created_file(created_file)
        for created_directory in reversed(created_directories):
            _remove_created_directory(created_directory)
        raise
    else:
        for created_file in created:
            _release_created_file(created_file)
    return ScaffoldResult(
        status="created",
        directory=destination,
        paths=tuple(destination / name for name in MANAGED_FILENAMES),
    )


def expected_scaffold_files() -> dict[str, bytes]:
    """Return the complete byte-stable managed generation."""
    suite_bytes = _suite_yaml().encode("utf-8")
    threat_manifest_text = _threat_manifest_yaml()
    loaded = load_yaml_nodes_text(suite_bytes.decode("utf-8"), label="onboarding suite YAML")
    suite = compile_loaded_suite(loaded, source_digest=sha256_hexdigest(loaded.data))
    runset = _scaffold_runset(suite)
    runset_bytes = (
        json.dumps(runset.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    config_bytes = _config_yaml().encode("utf-8")
    # Keep generator errors local: every emitted document must parse under the
    # same strict models used by doctor before any destination is touched.
    ControlsMutationOnboardingConfig.model_validate(
        load_yaml_nodes_text(config_bytes.decode("utf-8"), label="controls-mutation config").data
    )
    RunSet.model_validate(json.loads(runset_bytes))
    threat_manifest = load_yaml_nodes_text(
        threat_manifest_text,
        label="threat applicability manifest",
    )
    ThreatApplicabilityManifest.build(**threat_manifest.data)
    return {
        CONFIG_FILENAME: config_bytes,
        SUITE_FILENAME: suite_bytes,
        RUNSET_FILENAME: runset_bytes,
        THREAT_MANIFEST_FILENAME: threat_manifest_text.encode("utf-8"),
    }


def _suite_yaml() -> str:
    return """\
suite_id: controls-mutation-quickstart
suite_version: "1.0.0"
defaults:
  execution_mode: fixture
  runner_id: controls-mutation.quickstart
  fixture_roots: []
cases:
  - case_id: material-evidence-case
    title: Synthetic material evidence linkage
    expectation:
      material_claim_ids:
        - material-claim
"""


def _config_yaml() -> str:
    return f"""\
artifact_kind: {_CONFIG_ARTIFACT_KIND}
schema_version: "{MACHINE_IDENTIFIER_SCHEMA_VERSION}"
package_version: "{__version__}"
catalog_id: {CORE_MUTATION_CATALOG_ID}
suite_path: {SUITE_FILENAME}
runset_path: {RUNSET_FILENAME}
output_dir: {MUTATION_OUTPUT_DIRECTORY}
threat_applicability_manifest: {THREAT_MANIFEST_FILENAME}
operator_ids:
  - {DEFAULT_ONBOARDING_OPERATOR_ID}
control_efficacy:
  required_catalog: {CORE_MUTATION_CATALOG_ID}
  required_operators:
    - {DEFAULT_ONBOARDING_OPERATOR_ID}
  surviving_required_operator: block
  surviving_critical_operator: block
  surviving_applicable_operator: review
  critical_threat_uncovered: review
  applicable_threat_uncovered: review
  unevaluated_required_operator: block
  invalid_or_error_operator: block
  unknown_threat_applicability: review
  unscoped_catalog_threat_reference: review
"""


def _threat_manifest_yaml() -> str:
    return """\
threat_source:
  name: mitre-atlas
  version: "2026.06"
present_control_ids:
  - material_claims_have_evidence
items:
  - threat_id: AML.T0067.000
    applicability: applicable
    critical: true
    rationale: Synthetic evidence-link challenge is in scope for this quickstart.
    owner: onboarding-user
    reviewed_at: "2026-08-08"
  - threat_id: material-claim-link-regression
    applicability: applicable
    critical: false
    rationale: The selected operator's project-local regression reference is in scope.
    owner: onboarding-user
    reviewed_at: "2026-08-08"
limitations:
  - This synthetic quickstart declares two applicable threat references and one present control.
"""


def _scaffold_runset(suite: CompiledSuite) -> RunSet:
    return RunSet(
        runset_id="controls-mutation-quickstart-runset",
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        suite_id=_SCAFFOLD_SUITE_ID,
        suite_version=_SCAFFOLD_SUITE_VERSION,
        suite_digest=compiled_suite_digest(suite),
        fixture_manifest_digest=_SCAFFOLD_FIXTURE_DIGEST,
        runs=(
            AgentRunRecord(
                run_id="material-evidence-case-run",
                case_id=_SCAFFOLD_CASE_ID,
                pipeline_id="controls-mutation.quickstart",
                recommendation="approve",
                outcome="approved",
                input_summary="Synthetic fixture input.",
                output_summary="Synthetic fixture output supported by local evidence.",
                evidence_refs=(
                    EvidenceRef(
                        ref_id=_SCAFFOLD_REF_ID,
                        source_id=_SCAFFOLD_SOURCE_ID,
                        claim_ids=(_SCAFFOLD_CLAIM_ID,),
                    ),
                ),
                evidence_items=(
                    EvidenceItem(
                        ref_id=_SCAFFOLD_REF_ID,
                        source_id=_SCAFFOLD_SOURCE_ID,
                        content_digest=sha256_hexdigest("synthetic local evidence content/v1"),
                    ),
                ),
                claims=(ClaimRecord(claim_id=_SCAFFOLD_CLAIM_ID),),
                claim_evidence_links=(
                    ClaimEvidenceLink(
                        claim_id=_SCAFFOLD_CLAIM_ID,
                        evidence_ref_id=_SCAFFOLD_REF_ID,
                    ),
                ),
                provenance=Provenance(fixture_manifest_digest=_SCAFFOLD_FIXTURE_DIGEST),
            ),
        ),
    )


def _write_new_file(path: Path, content: bytes) -> _CreatedFile:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    created_file: _CreatedFile | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        metadata = os.fstat(descriptor)
        if not _metadata_is_regular_file(metadata) or metadata.st_nlink != 1:
            raise OSError("new scaffold asset is not an unlinked regular file")
        created_file = _CreatedFile(path, metadata.st_dev, metadata.st_ino, None)
        # POSIX may immediately recycle an inode after unlink. Keep a duplicate
        # descriptor open for the full scaffold transaction so rollback cannot
        # mistake a concurrently replaced path for the file that we created.
        # Windows CRT descriptors prevent unlink while open, so retain the
        # existing file-identity check there instead of changing that behavior.
        pin_descriptor = os.dup(descriptor) if os.name != "nt" else None
        created_file = _CreatedFile(
            path,
            metadata.st_dev,
            metadata.st_ino,
            pin_descriptor,
        )
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
            metadata = os.fstat(handle.fileno())
            if not _metadata_matches(metadata, created_file) or metadata.st_nlink != 1:
                raise OSError("new scaffold asset changed while it was being written")
        if not _path_matches_created_file(created_file, require_single_link=True):
            raise OSError("new scaffold asset changed after it was written")
        return created_file
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
            descriptor = -1
        if created_file is not None:
            _unlink_created_file(created_file)
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _create_directory_chain(destination: Path) -> tuple[_CreatedDirectory, ...]:
    missing: list[Path] = []
    current = destination
    while not _path_entry_exists(current):
        missing.append(current)
        if current == current.parent:
            raise OSError("output directory has no existing parent")
        current = current.parent
    _require_regular_directory_chain(current)

    created: list[_CreatedDirectory] = []
    try:
        for path in reversed(missing):
            _require_regular_directory_chain(path.parent)
            path.mkdir(mode=0o700, exist_ok=False)
            metadata = os.lstat(path)
            if not _metadata_is_regular_directory(metadata):
                raise ScaffoldConflictError("created output path is not a regular directory")
            created.append(_CreatedDirectory(path, metadata.st_dev, metadata.st_ino))
    except Exception:
        for created_directory in reversed(created):
            _remove_created_directory(created_directory)
        raise
    return tuple(created)


def _matches_expected_file(path: Path, expected: bytes) -> bool:
    try:
        observed = _read_confined_file(
            path,
            root=path.parent,
            max_bytes=len(expected),
            label="managed scaffold asset",
        )
        return observed == expected
    except (OSError, UnicodeError, ValueError):
        return False


def _metadata_matches(metadata: os.stat_result, created: _CreatedFile) -> bool:
    return metadata.st_dev == created.device and metadata.st_ino == created.inode


def _require_regular_directory_chain(path: Path) -> None:
    try:
        require_regular_directory_chain(path)
    except UnsafeDirectoryChainError as exc:
        raise ScaffoldConflictError(str(exc)) from exc


def _path_matches_created_file(
    created: _CreatedFile,
    *,
    require_single_link: bool,
) -> bool:
    try:
        metadata = os.lstat(created.path)
        pinned_metadata = (
            os.fstat(created.pin_descriptor)
            if created.pin_descriptor is not None
            else metadata
        )
    except OSError:
        return False
    return (
        _metadata_is_regular_file(metadata)
        and _metadata_matches(metadata, created)
        and _metadata_matches(pinned_metadata, created)
        and (not require_single_link or metadata.st_nlink == 1)
    )


def _unlink_created_file(created: _CreatedFile) -> None:
    try:
        if _path_matches_created_file(created, require_single_link=False):
            created.path.unlink()
    except OSError:
        pass
    finally:
        _release_created_file(created)


def _release_created_file(created: _CreatedFile) -> None:
    if created.pin_descriptor is None:
        return
    try:
        os.close(created.pin_descriptor)
    except OSError:
        pass


def _remove_created_directory(created: _CreatedDirectory) -> None:
    try:
        metadata = os.lstat(created.path)
        if (
            _metadata_is_regular_directory(metadata)
            and metadata.st_dev == created.device
            and metadata.st_ino == created.inode
        ):
            created.path.rmdir()
    except OSError:
        pass
