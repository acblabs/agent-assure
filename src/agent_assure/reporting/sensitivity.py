from __future__ import annotations

import hashlib
import html
import json
import os
import platform
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import BaseModel

from agent_assure.artifact_io import ensure_unlinked_directory
from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.evaluation.evaluator import evaluate_runset
from agent_assure.fixtures.loader import compiled_suite_digest
from agent_assure.fixtures.manifest import fixture_manifest_digest
from agent_assure.io_limits import (
    MAX_ARTIFACT_JSON_BYTES,
    BoundedFileContents,
    load_json_bytes_bounded,
    read_file_bounded,
)
from agent_assure.onboarding.path_safety import (
    metadata_is_regular_file,
    metadata_is_reparse,
)
from agent_assure.privacy.redaction import redact_packet_payload
from agent_assure.reporting.environment import build_release_manifest
from agent_assure.reporting.graph import evidence_graph_json_text
from agent_assure.reporting.markdown_safety import markdown_code_span, markdown_text
from agent_assure.reporting.packet import (
    DEFAULT_PACKET_LIMITATIONS,
    build_evidence_packet,
    build_privacy_filtered_evidence_graph,
    packet_summary_files_binding_error,
    packet_summary_snapshots_binding_error,
    render_evidence_packet_markdown,
)
from agent_assure.reporting.text_safety import sanitize_display_text
from agent_assure.rooted_io import (
    RootedDirectoryClaim,
    RootedDirectoryDescriptor,
    claim_rooted_directory,
    open_rooted_directory,
)
from agent_assure.schema.comparison import ComparisonSummary
from agent_assure.schema.environment import EnvironmentInfo
from agent_assure.schema.graph import AssuranceEvidenceGraph
from agent_assure.schema.packet import EvidencePacket, PacketArtifactDigest, PacketArtifactRole
from agent_assure.schema.release import ReleaseArtifact, ReleaseArtifactManifest
from agent_assure.schema.sensitivity import (
    EvidenceSensitivityState,
    RAGSensitivityArmResult,
    RAGSensitivityReport,
    validate_exact_sensitivity_arm_runset_projection,
)
from agent_assure.schema.validation import validate_loaded_artifact_payload
from agent_assure.sensitivity_comparison import (
    derive_sensitivity_comparison,
    sensitivity_comparison_binding_error,
)
from agent_assure.sensitivity_contract import (
    SENSITIVITY_EVALUATION_DATE,
    SENSITIVITY_HARNESS_NOTICE,
)

if TYPE_CHECKING:
    from agent_assure.rag.sensitivity import SensitivityExecutionArtifacts

SENSITIVITY_OUTPUT_FILENAMES = (
    "compiled-suite.json",
    "fixture-manifest.json",
    "protocol.json",
    "baseline-corpus-snapshot.json",
    "counterfactual-corpus-snapshot.json",
    "baseline.runset.json",
    "counterfactual.runset.json",
    "baseline-evaluation-summary.json",
    "counterfactual-evaluation-summary.json",
    "comparison-summary.json",
    "evidence-sensitivity.json",
    "evidence-sensitivity.md",
    "evidence-sensitivity.html",
    "assurance-evidence-graph.json",
    "release-artifact-manifest.json",
    "evidence-packet.json",
    "evidence-packet.md",
)
_SENSITIVITY_OUTPUT_SCAN_LIMIT = 4_096
_SENSITIVITY_OUTPUT_READ_CHUNK_BYTES = 1024 * 1024
_SENSITIVITY_MANIFEST_BOUND_FILES = (
    ("compiled-suite", "compiled-suite.json"),
    ("fixture-manifest", "fixture-manifest.json"),
    ("evidence-sensitivity-protocol", "protocol.json"),
    ("baseline-corpus-snapshot", "baseline-corpus-snapshot.json"),
    ("counterfactual-corpus-snapshot", "counterfactual-corpus-snapshot.json"),
    ("baseline-runset", "baseline.runset.json"),
    ("candidate-runset", "counterfactual.runset.json"),
    ("baseline-evaluation-summary", "baseline-evaluation-summary.json"),
    ("evaluation-summary", "counterfactual-evaluation-summary.json"),
    ("comparison-summary", "comparison-summary.json"),
    ("evidence-sensitivity-report", "evidence-sensitivity.json"),
    ("evidence-sensitivity-markdown", "evidence-sensitivity.md"),
    ("evidence-sensitivity-html", "evidence-sensitivity.html"),
    ("assurance-evidence-graph", "assurance-evidence-graph.json"),
)
_SENSITIVITY_PACKET_BOUND_FILES: tuple[tuple[PacketArtifactRole, str], ...] = (
    ("evaluation-summary", "counterfactual-evaluation-summary.json"),
    ("comparison-summary", "comparison-summary.json"),
    ("evidence-sensitivity-report", "evidence-sensitivity.json"),
    ("assurance-evidence-graph", "assurance-evidence-graph.json"),
)


class SensitivityPrivacyError(ValueError):
    """Raised when a declared input is unsafe for sensitivity persistence."""


class SensitivityOutputConflictError(ValueError):
    """Raised when an owned output belongs to a different artifact generation."""


@dataclass
class _CreatedSensitivityOutput:
    path: Path
    device: int
    inode: int
    size: int
    sha256: str
    pin_descriptor: int | None


@dataclass(frozen=True)
class _ClaimedSensitivityDirectory:
    path: Path
    device: int
    inode: int
    parent_lease: RootedDirectoryDescriptor
    claim: RootedDirectoryClaim


def ensure_sensitivity_output_namespace(out_dir: Path) -> None:
    """Reject mixed artifact generations before sensitivity publication."""
    if not out_dir.exists():
        return
    ensure_unlinked_directory(out_dir)
    allowed = {os.path.normcase(name) for name in SENSITIVITY_OUTPUT_FILENAMES}
    with os.scandir(out_dir) as entries:
        for index, entry in enumerate(entries):
            if index >= _SENSITIVITY_OUTPUT_SCAN_LIMIT:
                raise ValueError(
                    "sensitivity output directory contains too many entries to validate"
                )
            if os.path.normcase(entry.name) not in allowed:
                raise ValueError(
                    "sensitivity output directory contains a foreign artifact namespace"
                )
            metadata = entry.stat(follow_symlinks=False)
            if metadata_is_reparse(metadata) or not metadata_is_regular_file(metadata):
                raise ValueError(
                    "sensitivity output directory contains a non-regular artifact entry"
                )


def write_sensitivity_execution_artifacts(
    artifacts: SensitivityExecutionArtifacts,
    out_dir: Path,
) -> dict[str, Path]:
    ensure_sensitivity_output_namespace(out_dir)
    comparison = derive_sensitivity_comparison(artifacts.report)
    _validate_execution_artifacts(artifacts, comparison)
    texts = {
        "compiled-suite.json": _model_json_text(artifacts.compiled_suite),
        "fixture-manifest.json": _model_json_text(artifacts.fixture_manifest),
        "protocol.json": _model_json_text(artifacts.protocol),
        "baseline-corpus-snapshot.json": _model_json_text(
            artifacts.report.baseline_corpus_snapshot
        ),
        "counterfactual-corpus-snapshot.json": _model_json_text(
            artifacts.report.counterfactual_corpus_snapshot
        ),
        "baseline.runset.json": _model_json_text(artifacts.baseline_runset),
        "counterfactual.runset.json": _model_json_text(artifacts.counterfactual_runset),
        "baseline-evaluation-summary.json": _model_json_text(artifacts.baseline_evaluation),
        "counterfactual-evaluation-summary.json": _model_json_text(
            artifacts.counterfactual_evaluation
        ),
        "comparison-summary.json": _model_json_text(comparison),
        "evidence-sensitivity.json": sensitivity_report_json_text(artifacts.report),
        "evidence-sensitivity.md": render_sensitivity_markdown(artifacts.report),
        "evidence-sensitivity.html": render_sensitivity_html(artifacts.report),
    }
    graph = build_privacy_filtered_evidence_graph(
        artifacts.counterfactual_evaluation,
        comparison=comparison,
        evidence_sensitivity=artifacts.report,
        limitations=DEFAULT_PACKET_LIMITATIONS,
    )
    texts["assurance-evidence-graph.json"] = evidence_graph_json_text(graph)
    environment = EnvironmentInfo(
        platform=platform.platform(),
        python_version=platform.python_version(),
    )
    manifest = build_release_manifest(
        tuple(
            ReleaseArtifact(
                role=role,
                path=name,
                sha256=_text_sha256(texts[name]),
            )
            for role, name in _SENSITIVITY_MANIFEST_BOUND_FILES
        ),
        environment=environment,
    )
    packet = build_evidence_packet(
        artifacts.counterfactual_evaluation,
        comparison=comparison,
        evidence_sensitivity=artifacts.report,
        environment=environment,
        release_manifest=manifest,
        evidence_graph_digest=graph.graph_digest,
        artifact_digests=tuple(
            PacketArtifactDigest(
                role=role,
                sha256=_text_sha256(texts[name]),
            )
            for role, name in _SENSITIVITY_PACKET_BOUND_FILES
        ),
        limitations=DEFAULT_PACKET_LIMITATIONS,
    )
    texts.update(
        {
            "release-artifact-manifest.json": _model_json_text(manifest),
            "evidence-packet.json": _evidence_packet_json_text(packet),
            "evidence-packet.md": render_evidence_packet_markdown(packet),
        }
    )
    if set(texts) != set(SENSITIVITY_OUTPUT_FILENAMES):
        raise ValueError("sensitivity publication output inventory is inconsistent")
    if _complete_existing_generation_matches(out_dir, texts):
        _validate_finished_publication(
            out_dir,
            expected_texts=texts,
            expected_graph=graph,
            expected_manifest=manifest,
            expected_packet=packet,
        )
        return {name: out_dir / name for name in SENSITIVITY_OUTPUT_FILENAMES}

    claimed_directory = _claim_sensitivity_output_directory(out_dir)
    created_outputs: list[_CreatedSensitivityOutput] = []
    try:
        for name in SENSITIVITY_OUTPUT_FILENAMES:
            created_outputs.append(
                _write_sensitivity_output_exclusive(
                    claimed_directory,
                    name,
                    texts[name].encode("utf-8"),
                )
            )
        observed_snapshots = {
            created.path.name: _read_created_output_snapshot(
                claimed_directory,
                created,
            )
            for created in created_outputs
        }
        _require_claimed_directory_identity(claimed_directory)
        _validate_finished_publication(
            out_dir,
            expected_texts=texts,
            expected_graph=graph,
            expected_manifest=manifest,
            expected_packet=packet,
            observed_snapshots=observed_snapshots,
        )
        _require_claimed_directory_identity(claimed_directory)
    except BaseException as exc:
        rollback_errors = _rollback_sensitivity_publication(
            claimed_directory,
            tuple(created_outputs),
        )
        if rollback_errors:
            raise OSError(
                "evidence sensitivity publication failed and rollback was incomplete: "
                + "; ".join(rollback_errors)
            ) from exc
        raise
    _close_output_pins(tuple(created_outputs))
    _close_claimed_directory(claimed_directory)
    return {name: out_dir / name for name in SENSITIVITY_OUTPUT_FILENAMES}


def _text_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _evidence_packet_json_text(packet: EvidencePacket) -> str:
    payload = packet.model_dump(mode="json")
    if redact_packet_payload(payload) != payload:
        raise SensitivityPrivacyError(
            "evidence sensitivity packet contains sensitive-looking content"
        )
    EvidencePacket.model_validate(payload)
    validate_loaded_artifact_payload(payload, "evidence-packet")
    return _bounded_json_text(payload, label="evidence sensitivity packet")


def _complete_existing_generation_matches(
    out_dir: Path,
    texts: dict[str, str],
) -> bool:
    try:
        os.lstat(out_dir)
    except FileNotFoundError:
        return False
    ensure_sensitivity_output_namespace(out_dir)
    with os.scandir(out_dir) as entries:
        observed_names = {entry.name for entry in entries}
    if observed_names != set(SENSITIVITY_OUTPUT_FILENAMES):
        raise SensitivityOutputConflictError(
            "sensitivity output directory contains a partial artifact generation"
        )
    for name in SENSITIVITY_OUTPUT_FILENAMES:
        path = out_dir / name
        expected = texts[name].encode("utf-8")
        try:
            current = read_file_bounded(
                path,
                max_bytes=MAX_ARTIFACT_JSON_BYTES,
                label="owned sensitivity output",
            ).data
        except (OSError, ValueError) as exc:
            raise SensitivityOutputConflictError(
                "owned sensitivity output cannot be safely verified: " + name
            ) from exc
        if current != expected:
            raise SensitivityOutputConflictError(
                "owned sensitivity output does not match this deterministic generation: " + name
            )
    return True


def _claim_sensitivity_output_directory(out_dir: Path) -> _ClaimedSensitivityDirectory:
    ensure_unlinked_directory(out_dir.parent)
    parent_metadata = os.lstat(out_dir.parent)
    parent_lease = open_rooted_directory(
        out_dir.parent,
        ".",
        label="sensitivity output parent",
    )
    claim: RootedDirectoryClaim | None = None
    try:
        if (parent_lease.device, parent_lease.inode) != (
            parent_metadata.st_dev,
            parent_metadata.st_ino,
        ):
            raise OSError("sensitivity output parent changed while it was being claimed")
        try:
            claim = claim_rooted_directory(
                parent_lease,
                out_dir.name,
                label="sensitivity output directory",
                mode=0o700,
            )
        except FileExistsError as exc:
            raise SensitivityOutputConflictError(
                "sensitivity output directory was created concurrently"
            ) from exc
        return _ClaimedSensitivityDirectory(
            path=out_dir,
            device=claim.device,
            inode=claim.inode,
            parent_lease=parent_lease,
            claim=claim,
        )
    except BaseException:
        if claim is not None:
            try:
                claim.remove_empty()
            except OSError:
                claim.close()
        parent_lease.close()
        raise


def _write_sensitivity_output_exclusive(
    claimed_directory: _ClaimedSensitivityDirectory,
    name: str,
    payload: bytes,
) -> _CreatedSensitivityOutput:
    if Path(name).name != name or name not in SENSITIVITY_OUTPUT_FILENAMES:
        raise ValueError("invalid sensitivity output filename")
    if len(payload) > MAX_ARTIFACT_JSON_BYTES:
        raise ValueError("evidence sensitivity artifact exceeds maximum supported size")
    _require_claimed_directory_identity(claimed_directory)
    path = claimed_directory.path / name
    descriptor = -1
    created_entry = False
    created: _CreatedSensitivityOutput | None = None
    try:
        try:
            descriptor = claimed_directory.claim.open_regular_file_exclusive(
                name,
                mode=0o600,
            )
        except FileExistsError as exc:
            raise SensitivityOutputConflictError(
                "owned sensitivity output was created concurrently: " + name
            ) from exc
        created_entry = True
        metadata = os.fstat(descriptor)
        created = _CreatedSensitivityOutput(
            path=path,
            device=metadata.st_dev,
            inode=metadata.st_ino,
            size=len(payload),
            sha256=hashlib.sha256(payload).hexdigest(),
            pin_descriptor=None,
        )
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata_is_reparse(metadata)
            or metadata.st_nlink != 1
        ):
            raise OSError("new sensitivity output is not an unlinked regular file")
        pin_descriptor = os.dup(descriptor)
        created = _CreatedSensitivityOutput(
            path=path,
            device=created.device,
            inode=created.inode,
            size=created.size,
            sha256=created.sha256,
            pin_descriptor=pin_descriptor,
        )
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
            written = os.fstat(handle.fileno())
            if (
                (written.st_dev, written.st_ino) != (created.device, created.inode)
                or written.st_size != created.size
                or written.st_nlink != 1
            ):
                raise OSError("new sensitivity output changed while it was being written")
        if not _created_output_matches(claimed_directory, created):
            raise OSError("new sensitivity output changed after it was written")
        _require_claimed_directory_identity(claimed_directory)
        return created
    except BaseException as exc:
        cleanup_error: str | None = None
        if created is None and created_entry and descriptor >= 0:
            try:
                metadata = os.fstat(descriptor)
                created = _CreatedSensitivityOutput(
                    path=path,
                    device=metadata.st_dev,
                    inode=metadata.st_ino,
                    size=len(payload),
                    sha256=hashlib.sha256(payload).hexdigest(),
                    pin_descriptor=None,
                )
            except OSError:
                cleanup_error = "new output identity could not be recovered: " + name
        if descriptor >= 0:
            os.close(descriptor)
            descriptor = -1
        if created is not None:
            cleanup_error = _remove_created_output(
                claimed_directory,
                created,
                require_expected_bytes=False,
            )
            _close_output_pins((created,))
        if cleanup_error is not None:
            raise OSError(
                "evidence sensitivity publication failed and rollback was incomplete: "
                + cleanup_error
            ) from exc
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _require_claimed_directory_identity(
    claimed_directory: _ClaimedSensitivityDirectory,
) -> None:
    try:
        metadata = os.lstat(claimed_directory.path)
    except OSError as exc:
        raise OSError("sensitivity output directory changed during publication") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata_is_reparse(metadata)
        or (metadata.st_dev, metadata.st_ino) != (claimed_directory.device, claimed_directory.inode)
    ):
        raise OSError("sensitivity output directory changed during publication")


def _read_created_output_snapshot(
    claimed_directory: _ClaimedSensitivityDirectory,
    created: _CreatedSensitivityOutput,
) -> BoundedFileContents:
    if created.pin_descriptor is None:
        raise OSError("created sensitivity output is not pinned")
    try:
        entry_before = claimed_directory.claim.stat_entry_no_follow(created.path.name)
        opened_before = os.fstat(created.pin_descriptor)
    except (OSError, ValueError) as exc:
        raise OSError("created sensitivity output could not be safely inspected") from exc
    if not _created_output_metadata_matches(
        entry_before,
        created,
        require_expected_size=True,
    ) or not _created_output_metadata_matches(
        opened_before,
        created,
        require_expected_size=True,
    ):
        raise OSError("created sensitivity output changed concurrently")
    os.lseek(created.pin_descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    digest = hashlib.sha256()
    size = 0
    while True:
        remaining_with_sentinel = (MAX_ARTIFACT_JSON_BYTES - size) + 1
        chunk = os.read(
            created.pin_descriptor,
            min(_SENSITIVITY_OUTPUT_READ_CHUNK_BYTES, remaining_with_sentinel),
        )
        if not chunk:
            break
        size += len(chunk)
        if size > MAX_ARTIFACT_JSON_BYTES:
            raise OSError("created sensitivity output exceeds the verification limit")
        chunks.append(chunk)
        digest.update(chunk)
    try:
        opened_after = os.fstat(created.pin_descriptor)
        entry_after = claimed_directory.claim.stat_entry_no_follow(created.path.name)
    except (OSError, ValueError) as exc:
        raise OSError("created sensitivity output could not be safely inspected") from exc
    stable_fields = ("st_size", "st_mtime_ns", "st_ctime_ns", "st_nlink")
    if any(
        getattr(opened_before, field) != getattr(opened_after, field) for field in stable_fields
    ):
        raise OSError("created sensitivity output changed while it was being verified")
    if not _created_output_metadata_matches(
        opened_after,
        created,
        require_expected_size=True,
    ) or not _created_output_metadata_matches(
        entry_after,
        created,
        require_expected_size=True,
    ):
        raise OSError("created sensitivity output changed while it was being verified")
    if size != created.size:
        raise OSError("created sensitivity output size changed while it was being verified")
    return BoundedFileContents(
        data=b"".join(chunks),
        sha256=digest.hexdigest(),
        device=opened_after.st_dev,
        inode=opened_after.st_ino,
        size=opened_after.st_size,
        modified_ns=opened_after.st_mtime_ns,
        changed_ns=opened_after.st_ctime_ns,
    )


def _created_output_matches(
    claimed_directory: _ClaimedSensitivityDirectory,
    created: _CreatedSensitivityOutput,
) -> bool:
    try:
        contents = _read_created_output_snapshot(claimed_directory, created)
        return contents.sha256 == created.sha256
    except (OSError, ValueError):
        return False


def _created_output_identity_matches(
    claimed_directory: _ClaimedSensitivityDirectory,
    created: _CreatedSensitivityOutput,
) -> bool:
    try:
        metadata = claimed_directory.claim.stat_entry_no_follow(created.path.name)
    except (OSError, ValueError):
        return False
    return _created_output_metadata_matches(
        metadata,
        created,
        require_expected_size=False,
    )


def _created_output_metadata_matches(
    metadata: os.stat_result,
    created: _CreatedSensitivityOutput,
    *,
    require_expected_size: bool,
) -> bool:
    return (
        stat.S_ISREG(metadata.st_mode)
        and not metadata_is_reparse(metadata)
        and metadata.st_nlink == 1
        and (metadata.st_dev, metadata.st_ino) == (created.device, created.inode)
        and (not require_expected_size or metadata.st_size == created.size)
    )


def _remove_created_output(
    claimed_directory: _ClaimedSensitivityDirectory,
    created: _CreatedSensitivityOutput,
    *,
    require_expected_bytes: bool = True,
) -> str | None:
    try:
        matches = (
            _created_output_matches(claimed_directory, created)
            if require_expected_bytes
            else _created_output_identity_matches(claimed_directory, created)
        )
    except (OSError, ValueError):
        matches = False
    if not matches:
        return "created output changed concurrently: " + created.path.name
    if created.pin_descriptor is not None:
        pin_descriptor = created.pin_descriptor
        created.pin_descriptor = None
        try:
            os.close(pin_descriptor)
        except OSError as exc:
            return f"could not release {created.path.name}: {type(exc).__name__}"
    try:
        claimed_directory.claim.unlink_entry_no_follow(
            created.path.name,
            expected_device=created.device,
            expected_inode=created.inode,
        )
    except (OSError, ValueError) as exc:
        return f"could not remove {created.path.name}: {type(exc).__name__}"
    return None


def _rollback_sensitivity_publication(
    claimed_directory: _ClaimedSensitivityDirectory,
    created_outputs: tuple[_CreatedSensitivityOutput, ...],
) -> tuple[str, ...]:
    errors: list[str] = []
    output_cleanup_failed = False
    try:
        for created in reversed(created_outputs):
            if not _created_output_matches(claimed_directory, created):
                errors.append("created output changed concurrently: " + created.path.name)
                output_cleanup_failed = True
                continue
            error = _remove_created_output(claimed_directory, created)
            if error is not None:
                errors.append(error)
                output_cleanup_failed = True
        if not output_cleanup_failed:
            try:
                claimed_directory.claim.remove_empty()
            except (OSError, ValueError) as exc:
                errors.append("could not remove claimed output directory: " + type(exc).__name__)
    finally:
        try:
            _close_output_pins(created_outputs)
        finally:
            _close_claimed_directory(claimed_directory)
    return tuple(errors)


def _close_output_pins(created_outputs: tuple[_CreatedSensitivityOutput, ...]) -> None:
    for created in created_outputs:
        if created.pin_descriptor is None:
            continue
        pin_descriptor = created.pin_descriptor
        created.pin_descriptor = None
        try:
            os.close(pin_descriptor)
        except OSError:
            pass


def _close_claimed_directory(
    claimed_directory: _ClaimedSensitivityDirectory,
) -> None:
    try:
        claimed_directory.claim.close()
    finally:
        claimed_directory.parent_lease.close()


def _validate_finished_publication(
    out_dir: Path,
    *,
    expected_texts: dict[str, str],
    expected_graph: AssuranceEvidenceGraph,
    expected_manifest: ReleaseArtifactManifest,
    expected_packet: EvidencePacket,
    observed_snapshots: dict[str, BoundedFileContents] | None = None,
) -> None:
    if observed_snapshots is None:
        snapshots = {
            name: read_file_bounded(
                out_dir / name,
                max_bytes=MAX_ARTIFACT_JSON_BYTES,
                label="persisted evidence sensitivity artifact",
            )
            for name in SENSITIVITY_OUTPUT_FILENAMES
        }
    else:
        snapshots = observed_snapshots
    if set(snapshots) != set(SENSITIVITY_OUTPUT_FILENAMES):
        raise ValueError("persisted sensitivity artifact inventory changed during publication")
    observed: dict[str, bytes] = {}
    for name in SENSITIVITY_OUTPUT_FILENAMES:
        contents = snapshots[name]
        expected = expected_texts[name].encode("utf-8")
        if contents.data != expected:
            raise ValueError(
                "persisted evidence sensitivity artifact changed during publication: " + name
            )
        observed[name] = contents.data

    graph_payload = load_json_bytes_bounded(
        observed["assurance-evidence-graph.json"],
        max_bytes=MAX_ARTIFACT_JSON_BYTES,
        label="sensitivity assurance evidence graph",
    )
    validate_loaded_artifact_payload(graph_payload, "assurance-evidence-graph")
    persisted_graph = AssuranceEvidenceGraph.model_validate(graph_payload)
    if persisted_graph != expected_graph:
        raise ValueError("persisted sensitivity evidence graph changed during publication")
    packet_payload = load_json_bytes_bounded(
        observed["evidence-packet.json"],
        max_bytes=MAX_ARTIFACT_JSON_BYTES,
        label="sensitivity evidence packet",
    )
    validate_loaded_artifact_payload(packet_payload, "evidence-packet")
    persisted_packet = EvidencePacket.model_validate(packet_payload)
    if persisted_packet != expected_packet:
        raise ValueError("persisted sensitivity evidence packet changed during publication")
    manifest_payload = load_json_bytes_bounded(
        observed["release-artifact-manifest.json"],
        max_bytes=MAX_ARTIFACT_JSON_BYTES,
        label="sensitivity release artifact manifest",
    )
    validate_loaded_artifact_payload(manifest_payload, "release-artifact-manifest")
    persisted_manifest = ReleaseArtifactManifest.model_validate(manifest_payload)
    if (
        persisted_manifest != expected_manifest
        or persisted_packet.release_manifest != persisted_manifest
    ):
        raise ValueError("persisted sensitivity release manifest changed during publication")
    if observed["evidence-packet.md"].decode("utf-8") != render_evidence_packet_markdown(
        persisted_packet
    ):
        raise ValueError("persisted evidence packet Markdown changed during publication")
    if observed_snapshots is None:
        binding_error = packet_summary_files_binding_error(
            persisted_packet,
            artifact_root=out_dir,
        )
    else:
        binding_error = packet_summary_snapshots_binding_error(
            persisted_packet,
            snapshots_by_path={
                artifact.path: snapshots[artifact.path] for artifact in persisted_manifest.artifacts
            },
        )
    if binding_error is not None:
        raise ValueError(binding_error)


def _validate_execution_artifacts(
    artifacts: SensitivityExecutionArtifacts,
    comparison: ComparisonSummary,
) -> None:
    models = (
        ("compiled suite", artifacts.compiled_suite),
        ("fixture manifest", artifacts.fixture_manifest),
        ("sensitivity protocol", artifacts.protocol),
        ("baseline corpus snapshot", artifacts.report.baseline_corpus_snapshot),
        (
            "counterfactual corpus snapshot",
            artifacts.report.counterfactual_corpus_snapshot,
        ),
        ("baseline RunSet", artifacts.baseline_runset),
        ("counterfactual RunSet", artifacts.counterfactual_runset),
        ("baseline evaluation summary", artifacts.baseline_evaluation),
        ("counterfactual evaluation summary", artifacts.counterfactual_evaluation),
        ("comparison summary", comparison),
        ("sensitivity report", artifacts.report),
    )
    for label, model in models:
        payload = model.model_dump(mode="json")
        type(model).model_validate(payload)
        if redact_packet_payload(payload) != payload:
            raise SensitivityPrivacyError(
                f"{label} contains sensitive-looking content and cannot be published"
            )

    protocol = artifacts.protocol
    report = artifacts.report
    comparison_error = sensitivity_comparison_binding_error(comparison, report)
    if comparison_error is not None:
        raise ValueError(comparison_error)
    if report.protocol != protocol:
        raise ValueError("sensitivity report protocol must match the published protocol")
    if report.compiled_suite != artifacts.compiled_suite:
        raise ValueError("sensitivity report compiled suite must match the published suite")
    if (
        report.baseline_runset,
        report.counterfactual_runset,
        report.baseline_evaluation,
        report.counterfactual_evaluation,
    ) != (
        artifacts.baseline_runset,
        artifacts.counterfactual_runset,
        artifacts.baseline_evaluation,
        artifacts.counterfactual_evaluation,
    ):
        raise ValueError(
            "sensitivity report nested executions must match all published arm sidecars"
        )
    suite_digest = compiled_suite_digest(artifacts.compiled_suite)
    manifest_digest = fixture_manifest_digest(artifacts.fixture_manifest)
    if (
        artifacts.compiled_suite.suite_id,
        suite_digest,
    ) != (
        protocol.suite_id,
        protocol.suite_digest,
    ):
        raise ValueError("compiled suite must match the sensitivity protocol")
    if (
        artifacts.fixture_manifest.suite_id,
        artifacts.fixture_manifest.suite_version,
        manifest_digest,
    ) != (
        artifacts.compiled_suite.suite_id,
        artifacts.compiled_suite.suite_version,
        protocol.fixture_manifest_digest,
    ):
        raise ValueError("fixture manifest must match the compiled suite and protocol")
    if artifacts.fixture_manifest != protocol.fixture_manifest:
        raise ValueError("published fixture manifest must equal the protocol fixture snapshot")

    arm_sidecars = (
        (
            "baseline",
            report.baseline_arm,
            artifacts.baseline_runset,
            artifacts.baseline_evaluation,
        ),
        (
            "counterfactual",
            report.counterfactual_arm,
            artifacts.counterfactual_runset,
            artifacts.counterfactual_evaluation,
        ),
    )
    for label, arm, runset, evaluation in arm_sidecars:
        canonical_runset_digest = sha256_hexdigest(runset.model_dump(mode="json"))
        if (runset.runset_id, canonical_runset_digest) != (
            arm.runset_id,
            arm.runset_digest,
        ):
            raise ValueError(f"{label} RunSet must match the sensitivity report arm")
        if (
            runset.suite_id,
            runset.suite_version,
            runset.suite_digest,
            runset.fixture_manifest_digest,
            runset.protocol_id,
            runset.protocol_digest,
        ) != (
            artifacts.compiled_suite.suite_id,
            artifacts.compiled_suite.suite_version,
            protocol.suite_digest,
            protocol.fixture_manifest_digest,
            protocol.protocol_id,
            protocol.protocol_digest,
        ):
            raise ValueError(
                f"{label} RunSet must preserve the suite, fixture, and protocol identities"
            )
        recomputed_evaluation = evaluate_runset(
            artifacts.compiled_suite,
            runset,
            today=SENSITIVITY_EVALUATION_DATE,
        ).candidate_vs_expectations
        if evaluation != recomputed_evaluation:
            raise ValueError(
                f"{label} evaluation summary must equal a fresh evaluation of the published RunSet"
            )
        validate_exact_sensitivity_arm_runset_projection(
            label=label,
            arm=arm,
            runset=runset,
            protocol=protocol,
            authority_contract=report.authority_contract,
        )
        canonical_evaluation_digest = sha256_hexdigest(evaluation.model_dump(mode="json"))
        if (
            evaluation.runset_id,
            evaluation.runset_digest,
            canonical_evaluation_digest,
            evaluation.state,
        ) != (
            arm.runset_id,
            arm.runset_digest,
            arm.evaluation_summary_digest,
            arm.evaluation_state,
        ):
            raise ValueError(f"{label} evaluation summary must match the sensitivity report arm")


def sensitivity_report_json_text(report: RAGSensitivityReport) -> str:
    payload = report.model_dump(mode="json")
    if redact_packet_payload(payload) != payload:
        raise SensitivityPrivacyError(
            "evidence sensitivity report contains sensitive-looking content"
        )
    return _bounded_json_text(payload, label="evidence sensitivity report")


def render_sensitivity_markdown(report: RAGSensitivityReport) -> str:
    lines = [
        "# Controlled Evidence Sensitivity",
        "",
        "This report is a **synthetic detector contract test**. It measures a declared "
        "controlled evidence-response relation; it is not a causal guarantee and does not "
        "estimate failure prevalence in real models.",
        "",
        f"> **Scope limit:** {markdown_text(SENSITIVITY_HARNESS_NOTICE)}",
        "",
        "## Result",
        "",
        f"- State: {markdown_code_span(report.state.value)}",
        f"- Gate effect: {markdown_code_span(report.gate_effect.value)}",
        f"- Verdict-bearing: {markdown_code_span(str(report.verdict_bearing).lower())}",
        f"- Endpoint: {markdown_code_span(report.endpoint)}",
        f"- Endpoint value: {markdown_code_span(_optional_bool(report.endpoint_value))}",
        f"- Outcome classification: {markdown_code_span(report.outcome_classification.value)}",
        f"- Outcome: {markdown_text(report.outcome_message)}",
        f"- Expected relation: {markdown_code_span(report.expected_relation.value)}",
        f"- Observed relation: {markdown_code_span(report.observed_relation.value)}",
        f"- Deterministic: {markdown_code_span(str(report.deterministic).lower())}",
        f"- Detector status: {markdown_code_span(report.detector_test_status.value)}",
        f"- Subject execution scope: {markdown_code_span(report.subject_execution_scope)}",
        f"- Provenance binding: {markdown_code_span(report.provenance_binding)}",
        "- Synthetic data provenance: "
        f"{markdown_code_span(report.synthetic_data_provenance.value)}",
        "- Synthetic data attestation digest: "
        f"{markdown_code_span(report.synthetic_data_attestation_digest or 'not_applicable')}",
        f"- Raw content persistence: {markdown_code_span(report.raw_content_persistence)}",
        f"- Claim scope: {markdown_code_span(report.claim_scope)}",
        f"- Population claim: {markdown_code_span(report.population_claim)}",
        f"- Protocol digest: {markdown_code_span(report.protocol.protocol_digest)}",
        "- Authority contract digest: "
        f"{markdown_code_span(report.authority_contract.knowledge_contract_digest)}",
        "- Reason codes: " + _markdown_reasons(report),
        "",
        "## Arm Decisions",
        "",
        "| Arm | Corpus digest | Retrieval | Governing support | Evidence link | Decision | "
        "Expected | Expected match |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
        _markdown_arm_row("baseline", report.baseline_arm),
        _markdown_arm_row("counterfactual", report.counterfactual_arm),
        "",
        "## Decision-Inertia Finding",
        "",
        f"- Detected: {markdown_code_span(str(report.decision_inertia_finding.detected).lower())}",
        f"- State: {markdown_code_span(report.decision_inertia_finding.state.value)}",
        f"- Message: {markdown_text(report.decision_inertia_finding.message)}",
        "",
        "## Controlled-Difference Manifest",
        "",
        "`protocol_fixed` rows are structural protocol controls. `arm_observed` rows are "
        "derived independently from each corpus arm and carry the discriminating evidence.",
        "",
        "| Dimension | Basis | Baseline | Counterfactual | Contract | State |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    lines.extend(
        "| "
        f"{markdown_code_span(item.dimension)} | "
        f"{markdown_code_span(item.basis)} | "
        f"{markdown_code_span(item.baseline_value)} | "
        f"{markdown_code_span(item.counterfactual_value)} | "
        f"{markdown_code_span('equal' if item.expected_equal else 'different')} | "
        f"{markdown_code_span(item.state.value)} |"
        for item in report.protocol.controlled_difference_manifest.checks
    )
    lines.extend(["", "## Prerequisites", ""])
    lines.extend(
        "- "
        f"{markdown_code_span(item.check_id)}: {markdown_code_span(item.state.value)}"
        + (
            "; " + ", ".join(markdown_code_span(code.value) for code in item.reason_codes)
            if item.reason_codes
            else ""
        )
        for item in report.prerequisite_checks
    )
    lines.extend(["", "## Assumptions", ""])
    lines.extend(f"- {markdown_text(item)}" for item in report.assumptions)
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {markdown_text(item)}" for item in report.limitations)
    return "\n".join(lines) + "\n"


def render_sensitivity_html(report: RAGSensitivityReport) -> str:
    status_class = {
        EvidenceSensitivityState.responsive: "pass",
        EvidenceSensitivityState.evidence_insensitive: "fail",
        EvidenceSensitivityState.confounded: "invalid",
        EvidenceSensitivityState.prerequisites_unmet: "invalid",
    }[report.state]
    differences = "".join(
        "<tr>"
        f"<td><code>{_h(item.dimension)}</code></td>"
        f"<td><code>{_h(item.basis)}</code></td>"
        f"<td><code>{_h(item.baseline_value)}</code></td>"
        f"<td><code>{_h(item.counterfactual_value)}</code></td>"
        f"<td>{'equal' if item.expected_equal else 'different'}</td>"
        f"<td>{_h(item.state.value)}</td>"
        "</tr>"
        for item in report.protocol.controlled_difference_manifest.checks
    )
    prerequisites = "".join(
        "<tr>"
        f"<td><code>{_h(item.check_id)}</code></td>"
        f"<td>{_h(item.state.value)}</td>"
        f"<td>{_h(', '.join(code.value for code in item.reason_codes) or 'none')}</td>"
        "</tr>"
        for item in report.prerequisite_checks
    )
    limitations = "".join(f"<li>{_h(item)}</li>" for item in report.limitations)
    assumptions = "".join(f"<li>{_h(item)}</li>" for item in report.assumptions)
    reasons = ", ".join(item.value for item in report.reason_codes) or "none"
    rendered = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Controlled Evidence Sensitivity</title>
  <style>
    :root {{ --ink:#172033; --muted:#5c667a; --line:#d9deea; --panel:#f7f8fb;
      --pass:#16784a; --fail:#b42318; --invalid:#805400; }}
    body {{ margin:0; color:var(--ink); font:15px/1.55 system-ui,sans-serif; }}
    main {{ max-width:1120px; margin:auto; padding:36px 24px 64px; }}
    h1 {{ margin:0 0 8px; font-size:32px; }} h2 {{ margin-top:34px; }}
    .lede {{ color:var(--muted); max-width:850px; }}
    .status {{ border-left:6px solid currentColor; background:var(--panel); padding:18px 20px;
      margin:24px 0; }} .status.pass {{ color:var(--pass); }}
    .status.fail {{ color:var(--fail); }} .status.invalid {{ color:var(--invalid); }}
    .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:16px; }}
    .card {{ border:1px solid var(--line); border-radius:10px; padding:16px; }}
    table {{ width:100%; border-collapse:collapse; display:block; overflow-x:auto; }}
    th,td {{ border-bottom:1px solid var(--line); padding:9px 10px; text-align:left; }}
    code {{ overflow-wrap:anywhere; }}
  </style>
</head>
<body><main>
  <h1>Controlled Evidence Sensitivity</h1>
  <p class="lede">Synthetic detector contract test. This report measures a declared controlled
  evidence-response relation. It is not a causal guarantee and does not estimate real-model
  failure prevalence.</p>
  <p class="lede"><strong>Scope limit:</strong> {_h(SENSITIVITY_HARNESS_NOTICE)}</p>
  <section class="status {status_class}">
    <strong>{_h(report.state.value)}</strong> · gate {_h(report.gate_effect.value)} · endpoint
    {_h(_optional_bool(report.endpoint_value))}<br>
    <strong>{_h(report.outcome_classification.value)}</strong>:
    {_h(report.outcome_message)}<br>
    Relation category: expected {_h(report.expected_relation.value)}; observed
    {_h(report.observed_relation.value)}.
  </section>
  <div class="grid">
    {_html_arm_card("Baseline", report.baseline_arm)}
    {_html_arm_card("Counterfactual", report.counterfactual_arm)}
  </div>
  <h2>Detector contract</h2>
  <ul>
    <li>Endpoint: <code>{_h(report.endpoint)}</code></li>
    <li>Detector status: <code>{_h(report.detector_test_status.value)}</code></li>
    <li>Subject execution scope:
      <code>{_h(report.subject_execution_scope)}</code></li>
    <li>Provenance binding: <code>{_h(report.provenance_binding)}</code></li>
    <li>Synthetic data provenance:
      <code>{_h(report.synthetic_data_provenance.value)}</code></li>
    <li>Synthetic data attestation digest:
      <code>{_h(report.synthetic_data_attestation_digest or "not_applicable")}</code></li>
    <li>Raw content persistence:
      <code>{_h(report.raw_content_persistence)}</code></li>
    <li>Deterministic: <code>{str(report.deterministic).lower()}</code></li>
    <li>Decision inertia detected:
      <code>{str(report.decision_inertia_finding.detected).lower()}</code></li>
    <li>Reason codes: <code>{_h(reasons)}</code></li>
    <li>Protocol digest: <code>{_h(report.protocol.protocol_digest)}</code></li>
    <li>Authority contract:
      <code>{_h(report.authority_contract.knowledge_contract_digest)}</code></li>
  </ul>
  <h2>Controlled-difference manifest</h2>
  <p><code>protocol_fixed</code> rows are structural protocol controls.
  <code>arm_observed</code> rows are independently derived from each corpus arm and carry
  the discriminating evidence.</p>
  <table><thead><tr><th>Dimension</th><th>Basis</th><th>Baseline</th><th>Counterfactual</th>
    <th>Contract</th><th>State</th></tr></thead><tbody>{differences}</tbody></table>
  <h2>Prerequisites</h2>
  <table><thead><tr><th>Check</th><th>State</th><th>Reason</th></tr></thead>
    <tbody>{prerequisites}</tbody></table>
  <h2>Assumptions</h2><ul>{assumptions}</ul>
  <h2>Limitations</h2><ul>{limitations}</ul>
</main></body></html>
"""
    if len(rendered.encode("utf-8")) > MAX_ARTIFACT_JSON_BYTES:
        raise ValueError("evidence sensitivity HTML exceeds the artifact byte limit")
    return rendered


def _html_arm_card(label: str, arm: RAGSensitivityArmResult) -> str:
    expected = (
        f"{arm.expected_decision.value}/{arm.expected_outcome.value}"
        if arm.expected_decision is not None and arm.expected_outcome is not None
        else "unbound"
    )
    return (
        '<section class="card">'
        f"<h2>{_h(label)}</h2>"
        f"<p>Observed: <strong>{_h(arm.decision.value)}/{_h(arm.outcome.value)}</strong><br>"
        f"Expected: <strong>{_h(expected)}</strong><br>"
        f"Expected match: {_h(_optional_bool(arm.expected_decision_match))}</p>"
        f"<p>Retrieved: {_h(str(arm.retrieval_succeeded).lower())}<br>"
        f"Governing support: {_h(str(arm.governing_evidence_supported).lower())}<br>"
        f"Evidence link: {_h(str(arm.evidence_link_present).lower())}</p>"
        f"<p><code>{_h(arm.corpus_digest)}</code></p>"
        "</section>"
    )


def _model_json_text(model: BaseModel) -> str:
    return _bounded_json_text(model.model_dump(mode="json"), label=model.__class__.__name__)


def _bounded_json_text(payload: object, *, label: str) -> str:
    rendered = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if len(rendered.encode("utf-8")) > MAX_ARTIFACT_JSON_BYTES:
        raise ValueError(f"{label} exceeds the artifact JSON byte limit")
    return rendered


def _markdown_arm_row(label: str, arm: RAGSensitivityArmResult) -> str:
    expected = (
        f"{arm.expected_decision.value}/{arm.expected_outcome.value}"
        if arm.expected_decision is not None and arm.expected_outcome is not None
        else "unbound"
    )
    return (
        f"| {label} | {markdown_code_span(arm.corpus_digest)} | "
        f"{markdown_code_span(str(arm.retrieval_succeeded).lower())} | "
        f"{markdown_code_span(str(arm.governing_evidence_supported).lower())} | "
        f"{markdown_code_span(str(arm.evidence_link_present).lower())} | "
        f"{markdown_code_span(f'{arm.decision.value}/{arm.outcome.value}')} | "
        f"{markdown_code_span(expected)} | "
        f"{markdown_code_span(_optional_bool(arm.expected_decision_match))} |"
    )


def _markdown_reasons(report: RAGSensitivityReport) -> str:
    if not report.reason_codes:
        return "none"
    return ", ".join(markdown_code_span(item.value) for item in report.reason_codes)


def _optional_bool(value: bool | None) -> str:
    return "not_evaluated" if value is None else str(value).lower()


def _h(value: object) -> str:
    return html.escape(sanitize_display_text(value), quote=True)


__all__ = [
    "SENSITIVITY_OUTPUT_FILENAMES",
    "SensitivityOutputConflictError",
    "SensitivityPrivacyError",
    "ensure_sensitivity_output_namespace",
    "render_sensitivity_html",
    "render_sensitivity_markdown",
    "sensitivity_report_json_text",
    "write_sensitivity_execution_artifacts",
]
