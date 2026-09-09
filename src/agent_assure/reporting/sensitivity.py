from __future__ import annotations

import hashlib
import html
import json
import os
import platform
import secrets
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, cast

from pydantic import BaseModel

from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.evaluation.evaluator import evaluate_runset
from agent_assure.fixtures.loader import compiled_suite_digest
from agent_assure.fixtures.manifest import fixture_manifest_digest
from agent_assure.io_limits import (
    MAX_ARTIFACT_JSON_BYTES,
    BoundedFileContents,
    load_json_bytes_bounded,
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
    packet_summary_snapshots_binding_error,
    render_evidence_packet_markdown,
)
from agent_assure.reporting.text_safety import sanitize_display_text
from agent_assure.rooted_io import (
    PinnedDirectoryFile,
    RootedDirectoryClaim,
    RootedDirectoryDescriptor,
    acquire_publication_lock,
    claim_rooted_directory,
    open_or_create_rooted_directory_from_filesystem_root,
    open_rooted_directory,
    open_rooted_directory_from_filesystem_root,
    release_publication_lock,
    retry_windows_sharing_violation,
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
_STAGING_NAME_PREFIX = ".agent-assure-sensitivity-"
_PUBLICATION_LOCK_PREFIX = ".agent-assure-sensitivity-lock-"
_BEST_EFFORT_LOCK_TIMEOUT_SECONDS = 0.001
_CONCURRENT_GENERATION_RETRY_TIMEOUT_SECONDS = 0.25
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


class _ExistingSensitivityForeignEntryError(ValueError):
    """Internal typed classification for a statically foreign output entry."""


@dataclass
class _CreatedSensitivityOutput:
    path: Path
    device: int
    inode: int
    size: int
    sha256: str
    pin_descriptor: int | None


@dataclass
class _PinnedExistingSensitivityGeneration:
    lease: RootedDirectoryDescriptor
    files: list[PinnedDirectoryFile]
    snapshots: dict[str, BoundedFileContents]

    def revalidate(self) -> None:
        names = self.lease.entry_names(
            max_entries=_SENSITIVITY_OUTPUT_SCAN_LIMIT,
            label="existing evidence sensitivity output",
        )
        if len(names) != len(SENSITIVITY_OUTPUT_FILENAMES) or set(names) != set(
            SENSITIVITY_OUTPUT_FILENAMES
        ):
            raise SensitivityOutputConflictError(
                "sensitivity output directory changed during verification"
            )
        for opened in self.files:
            opened.revalidate()
        self.lease.revalidate_path(label="existing evidence sensitivity output")

    def close(self) -> None:
        try:
            for opened in reversed(self.files):
                opened.close()
        finally:
            self.lease.close()


def ensure_sensitivity_output_namespace(out_dir: Path) -> None:
    """Reject mixed artifact generations before sensitivity publication."""
    try:
        lease = open_rooted_directory_from_filesystem_root(
            out_dir,
            label="sensitivity output directory",
        )
    except FileNotFoundError:
        return
    with lease:
        names = lease.entry_names(
            max_entries=_SENSITIVITY_OUTPUT_SCAN_LIMIT,
            label="sensitivity output directory",
        )
        allowed = {os.path.normcase(name) for name in SENSITIVITY_OUTPUT_FILENAMES}
        for name in names:
            if os.path.normcase(name) not in allowed:
                raise ValueError(
                    "sensitivity output directory contains a foreign artifact namespace"
                )
            metadata = lease.stat_entry_no_follow(name)
            if metadata_is_reparse(metadata) or not metadata_is_regular_file(metadata):
                raise ValueError(
                    "sensitivity output directory contains a non-regular artifact entry"
                )
        lease.revalidate_path(label="sensitivity output directory")


def write_sensitivity_execution_artifacts(
    artifacts: SensitivityExecutionArtifacts,
    out_dir: Path,
) -> dict[str, Path]:
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
    return _publish_sensitivity_generation(
        out_dir,
        texts=texts,
        expected_graph=graph,
        expected_manifest=manifest,
        expected_packet=packet,
    )


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


def _publish_sensitivity_generation(
    out_dir: Path,
    *,
    texts: dict[str, str],
    expected_graph: AssuranceEvidenceGraph,
    expected_manifest: ReleaseArtifactManifest,
    expected_packet: EvidencePacket,
) -> dict[str, Path]:
    target = _validate_sensitivity_output_target(out_dir)
    if len({os.path.normcase(name) for name in SENSITIVITY_OUTPUT_FILENAMES}) != len(
        SENSITIVITY_OUTPUT_FILENAMES
    ):
        raise ValueError("sensitivity output filenames alias on this filesystem")
    payloads = {name: text.encode("utf-8") for name, text in texts.items()}
    if any(len(payload) > MAX_ARTIFACT_JSON_BYTES for payload in payloads.values()):
        raise ValueError("evidence sensitivity artifact exceeds maximum supported size")

    with open_or_create_rooted_directory_from_filesystem_root(
        target.parent,
        label="sensitivity output parent",
    ) as parent_lease:
        parent_lease.revalidate_path(label="sensitivity output parent")
        with _best_effort_sensitivity_publication_lock(parent_lease, target.name):
            parent_lease.revalidate_path(label="sensitivity output parent")
            existing = _open_existing_sensitivity_generation_with_transient_share_retry(
                parent_lease,
                target,
            )
            if existing is not None:
                try:
                    _validate_existing_sensitivity_generation(
                        existing,
                        texts=texts,
                        expected_graph=expected_graph,
                        expected_manifest=expected_manifest,
                        expected_packet=expected_packet,
                    )
                    existing.revalidate()
                finally:
                    existing.close()
                return {name: target / name for name in SENSITIVITY_OUTPUT_FILENAMES}

            claim = _claim_private_sensitivity_staging_directory(
                parent_lease,
                target.name,
            )
            private_stage_name = claim.name
            created_outputs: list[_CreatedSensitivityOutput] = []
            final_child_pins: tuple[PinnedDirectoryFile, ...] = ()
            committed = False
            try:
                for name in SENSITIVITY_OUTPUT_FILENAMES:
                    created_outputs.append(
                        _write_sensitivity_output_exclusive(
                            claim,
                            name,
                            payloads[name],
                        )
                    )
                snapshots = {
                    created.path.name: _read_created_output_snapshot(claim, created)
                    for created in created_outputs
                }
                _require_exact_staged_inventory(claim)
                _validate_finished_publication(
                    expected_texts=texts,
                    expected_graph=expected_graph,
                    expected_manifest=expected_manifest,
                    expected_packet=expected_packet,
                    observed_snapshots=snapshots,
                )
                for created in created_outputs:
                    observed = _read_created_output_snapshot(claim, created)
                    if observed.data != payloads[created.path.name]:
                        raise OSError(
                            "staged evidence sensitivity output changed during validation: "
                            + created.path.name
                        )
                _require_exact_staged_inventory(claim)
                close_errors = _close_output_pins(tuple(created_outputs))
                if close_errors:
                    raise OSError(
                        "could not close staged sensitivity output descriptors: "
                        + "; ".join(close_errors)
                    )
                _fsync_staged_sensitivity_generation(claim)
                final_child_pins = (
                    _validate_staged_sensitivity_generation_immediately_before_commit(
                        claim,
                        payloads,
                    )
                )
                if os.name == "nt":
                    close_errors = _close_final_sensitivity_child_pins(final_child_pins)
                    final_child_pins = ()
                    if close_errors:
                        raise OSError(
                            "could not close final staged sensitivity output pins: "
                            + "; ".join(close_errors)
                        )
                try:
                    claim.install_no_replace(target.name)
                except FileExistsError as commit_error:
                    close_errors = _close_final_sensitivity_child_pins(final_child_pins)
                    final_child_pins = ()
                    if close_errors:
                        raise OSError(
                            "could not close final staged sensitivity output pins: "
                            + "; ".join(close_errors)
                        ) from commit_error
                    try:
                        _after_sensitivity_generation_commit(parent_lease)
                        existing = _open_existing_sensitivity_generation_with_transient_share_retry(
                            parent_lease,
                            target,
                        )
                        if existing is None:
                            raise SensitivityOutputConflictError(
                                "concurrent sensitivity output disappeared before validation"
                            )
                        try:
                            _validate_existing_sensitivity_generation(
                                existing,
                                texts=texts,
                                expected_graph=expected_graph,
                                expected_manifest=expected_manifest,
                                expected_packet=expected_packet,
                            )
                            existing.revalidate()
                        finally:
                            existing.close()
                    except (OSError, UnicodeError, ValueError) as verification_error:
                        raise SensitivityOutputConflictError(
                            "sensitivity output was committed concurrently but does not form "
                            "the exact expected generation"
                        ) from verification_error
                    return {name: target / name for name in SENSITIVITY_OUTPUT_FILENAMES}
                except BaseException:
                    committed = claim.name == target.name
                    raise
                else:
                    committed = True
                    if os.name == "nt":
                        # The claim owns DELETE access, so a separately pinned
                        # installed-generation lease cannot coexist with it on
                        # Windows. Release the committed claim, then verify the
                        # target through fresh no-follow directory and child pins.
                        claim.close()
                        installed = (
                            _open_existing_sensitivity_generation_with_transient_share_retry(
                                parent_lease,
                                target,
                            )
                        )
                        if installed is None:
                            raise OSError(
                                "committed evidence sensitivity output disappeared before "
                                "post-commit verification"
                            )
                        try:
                            _validate_existing_sensitivity_generation(
                                installed,
                                texts=texts,
                                expected_graph=expected_graph,
                                expected_manifest=expected_manifest,
                                expected_packet=expected_packet,
                            )
                            installed.revalidate()
                        finally:
                            installed.close()
                    else:
                        _revalidate_installed_sensitivity_generation_pins(
                            claim,
                            payloads,
                            final_child_pins,
                        )
                    close_errors = _close_final_sensitivity_child_pins(final_child_pins)
                    final_child_pins = ()
                    if close_errors:
                        raise OSError(
                            "could not close installed sensitivity output pins: "
                            + "; ".join(close_errors)
                        )
            except Exception as exc:
                final_pin_close_errors = _close_final_sensitivity_child_pins(final_child_pins)
                final_child_pins = ()
                close_errors = _close_output_pins(tuple(created_outputs))
                if final_pin_close_errors or close_errors:
                    raise OSError(
                        "sensitivity staging failed and descriptor cleanup was incomplete: "
                        + "; ".join(final_pin_close_errors + close_errors)
                    ) from exc
                if committed or claim.name == target.name:
                    raise OSError(
                        "evidence sensitivity generation committed; target retained despite "
                        "post-commit validation failure"
                    ) from exc
                raise OSError(
                    "evidence sensitivity publication failed before commit; "
                    f"private staging retained at {claim.path}"
                ) from exc
            except BaseException as exc:
                _close_final_sensitivity_child_pins(final_child_pins)
                _close_output_pins(tuple(created_outputs))
                if claim.name == target.name and hasattr(exc, "add_note"):
                    exc.add_note("Evidence sensitivity generation committed; target retained.")
                raise
            finally:
                _close_final_sensitivity_child_pins(final_child_pins)
                _close_output_pins(tuple(created_outputs))
                claim.close()

            if not committed or claim.name != target.name:
                raise OSError(
                    "evidence sensitivity publication did not reach its commit point; "
                    f"private staging retained at {target.parent / private_stage_name}"
                )
            try:
                _after_sensitivity_generation_commit(parent_lease)
                installed = _open_existing_sensitivity_generation_with_transient_share_retry(
                    parent_lease,
                    target,
                )
                if installed is None:
                    raise OSError(
                        "committed evidence sensitivity output disappeared before final "
                        "post-commit verification"
                    )
                try:
                    if (installed.lease.device, installed.lease.inode) != (
                        claim.device,
                        claim.inode,
                    ):
                        raise OSError(
                            "committed evidence sensitivity target name no longer resolves "
                            "to the installed generation"
                        )
                    _validate_existing_sensitivity_generation(
                        installed,
                        texts=texts,
                        expected_graph=expected_graph,
                        expected_manifest=expected_manifest,
                        expected_packet=expected_packet,
                    )
                    installed.revalidate()
                finally:
                    installed.close()
            except Exception as exc:
                raise OSError(
                    "evidence sensitivity generation committed; target retained despite "
                    "post-commit durability or exact-generation validation failure"
                ) from exc
            except BaseException as exc:
                if hasattr(exc, "add_note"):
                    exc.add_note("Evidence sensitivity generation committed; target retained.")
                raise
    return {name: target / name for name in SENSITIVITY_OUTPUT_FILENAMES}


def _validate_sensitivity_output_target(out_dir: Path) -> Path:
    target = Path(os.path.abspath(out_dir))
    if target == Path(target.anchor):
        raise ValueError("sensitivity output must not be a filesystem root")
    if not target.name:
        raise ValueError("sensitivity output must name a directory")
    return target


def _open_existing_sensitivity_generation(
    parent: RootedDirectoryDescriptor,
    out_dir: Path,
) -> _PinnedExistingSensitivityGeneration | None:
    try:
        lease = open_rooted_directory(
            out_dir.parent,
            out_dir.name,
            label="existing evidence sensitivity output",
        )
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        raise SensitivityOutputConflictError(
            "sensitivity output destination is not an unlinked regular directory"
        ) from exc

    opened_files: list[PinnedDirectoryFile] = []
    try:
        if (lease.root_device, lease.root_inode) != (parent.device, parent.inode):
            raise SensitivityOutputConflictError(
                "sensitivity output parent changed during verification"
            )
        names = lease.entry_names(
            max_entries=_SENSITIVITY_OUTPUT_SCAN_LIMIT,
            label="existing evidence sensitivity output",
        )
        expected_by_normalized_name = {
            os.path.normcase(name): name for name in SENSITIVITY_OUTPUT_FILENAMES
        }
        if any(expected_by_normalized_name.get(os.path.normcase(name)) != name for name in names):
            raise SensitivityOutputConflictError(
                "sensitivity output directory contains a foreign or non-regular artifact entry"
            )
        if len(names) != len(SENSITIVITY_OUTPUT_FILENAMES) or set(names) != set(
            SENSITIVITY_OUTPUT_FILENAMES
        ):
            raise SensitivityOutputConflictError(
                "sensitivity output directory contains a partial artifact generation"
            )
        snapshots: dict[str, BoundedFileContents] = {}
        for name in SENSITIVITY_OUTPUT_FILENAMES:
            try:
                metadata = lease.stat_entry_no_follow(name)
            except (OSError, ValueError) as exc:
                raise _ExistingSensitivityForeignEntryError(name) from exc
            if (
                not metadata_is_regular_file(metadata)
                or metadata_is_reparse(metadata)
                or metadata.st_nlink != 1
            ):
                raise _ExistingSensitivityForeignEntryError(name)
            opened = lease.open_file_bounded(
                name,
                max_bytes=MAX_ARTIFACT_JSON_BYTES,
                label="existing evidence sensitivity output",
                require_single_link=True,
            )
            opened_files.append(opened)
            snapshots[name] = opened.contents
        result = _PinnedExistingSensitivityGeneration(
            lease=lease,
            files=opened_files,
            snapshots=snapshots,
        )
        result.revalidate()
        return result
    except SensitivityOutputConflictError:
        for opened in reversed(opened_files):
            opened.close()
        lease.close()
        raise
    except _ExistingSensitivityForeignEntryError as exc:
        for opened in reversed(opened_files):
            opened.close()
        lease.close()
        raise SensitivityOutputConflictError(
            "sensitivity output directory contains a foreign or non-regular artifact entry"
        ) from exc
    except (OSError, UnicodeError, ValueError) as exc:
        for opened in reversed(opened_files):
            opened.close()
        lease.close()
        raise SensitivityOutputConflictError(
            "existing sensitivity output cannot be safely verified"
        ) from exc


def _open_existing_sensitivity_generation_with_transient_share_retry(
    parent: RootedDirectoryDescriptor,
    out_dir: Path,
) -> _PinnedExistingSensitivityGeneration | None:
    """Re-open exactly while an honest Windows winner releases its rename pin."""

    return retry_windows_sharing_violation(
        lambda: _open_existing_sensitivity_generation(parent, out_dir),
        timeout_seconds=_CONCURRENT_GENERATION_RETRY_TIMEOUT_SECONDS,
    )


def _validate_existing_sensitivity_generation(
    existing: _PinnedExistingSensitivityGeneration,
    *,
    texts: dict[str, str],
    expected_graph: AssuranceEvidenceGraph,
    expected_manifest: ReleaseArtifactManifest,
    expected_packet: EvidencePacket,
) -> None:
    for name in SENSITIVITY_OUTPUT_FILENAMES:
        if existing.snapshots[name].data != texts[name].encode("utf-8"):
            raise SensitivityOutputConflictError(
                "owned sensitivity output does not match this deterministic generation: " + name
            )
    try:
        _validate_finished_publication(
            expected_texts=texts,
            expected_graph=expected_graph,
            expected_manifest=expected_manifest,
            expected_packet=expected_packet,
            observed_snapshots=existing.snapshots,
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise SensitivityOutputConflictError(
            "existing sensitivity output does not form a valid deterministic generation"
        ) from exc


def _claim_private_sensitivity_staging_directory(
    parent: RootedDirectoryDescriptor,
    target_name: str,
) -> RootedDirectoryClaim:
    target_digest = hashlib.sha256(os.path.normcase(target_name).encode("utf-8")).hexdigest()[:16]
    target_prefix = f"{_STAGING_NAME_PREFIX}{target_digest}-"
    for _ in range(8):
        name = f"{target_prefix}{secrets.token_hex(16)}.tmp"
        try:
            return claim_rooted_directory(
                parent,
                name,
                label="private evidence sensitivity staging directory",
                mode=0o700,
            )
        except FileExistsError:
            continue
    raise OSError("could not reserve a private sensitivity staging directory")


@contextmanager
def _best_effort_sensitivity_publication_lock(
    parent: RootedDirectoryDescriptor,
    target_name: str,
) -> Iterator[None]:
    """Coordinate opportunistically; no-replace installation is the integrity boundary.

    A caller that can write the output parent can pre-create or hold the stable
    lock name. Such an entry must not become an availability gate. A safe,
    uncontended lock avoids duplicate staging; otherwise publication proceeds
    to the atomic commit and exact-generation reconciliation path.
    """
    target_digest = hashlib.sha256(os.path.normcase(target_name).encode("utf-8")).hexdigest()[:32]
    lock_name = f"{_PUBLICATION_LOCK_PREFIX}{target_digest}.lock"
    descriptor: int | None = None
    acquired = False
    try:
        try:
            descriptor, metadata = parent.open_regular_lock_file(lock_name, mode=0o600)
            if os.name == "nt":
                _ensure_sensitivity_lock_byte(descriptor)
            acquired = _lock_sensitivity_descriptor(descriptor)
            if acquired:
                if os.name != "nt":
                    _ensure_sensitivity_lock_byte(descriptor)
                current = parent.stat_entry_no_follow(lock_name)
                _require_unlinked_regular_output(current, name=lock_name)
                if (current.st_dev, current.st_ino) != (metadata.st_dev, metadata.st_ino):
                    raise OSError("sensitivity publication lock identity changed")
        except (OSError, ValueError):
            if acquired and descriptor is not None:
                _unlock_sensitivity_descriptor(descriptor)
            acquired = False
            if descriptor is not None:
                os.close(descriptor)
                descriptor = None
        yield
    finally:
        try:
            if acquired and descriptor is not None:
                _unlock_sensitivity_descriptor(descriptor)
        finally:
            if descriptor is not None:
                os.close(descriptor)


def _ensure_sensitivity_lock_byte(descriptor: int) -> None:
    if os.fstat(descriptor).st_size >= 1:
        return
    os.lseek(descriptor, 0, os.SEEK_SET)
    if os.write(descriptor, b"\x00") != 1:
        raise OSError("sensitivity publication lock initialization failed")
    os.fsync(descriptor)


def _lock_sensitivity_descriptor(descriptor: int) -> bool:
    try:
        acquire_publication_lock(
            descriptor,
            label="evidence sensitivity publication",
            timeout_seconds=_BEST_EFFORT_LOCK_TIMEOUT_SECONDS,
        )
    except TimeoutError:
        return False
    return True


def _unlock_sensitivity_descriptor(descriptor: int) -> None:
    release_publication_lock(descriptor)


def _write_sensitivity_output_exclusive(
    claim: RootedDirectoryClaim,
    name: str,
    payload: bytes,
) -> _CreatedSensitivityOutput:
    if Path(name).name != name or name not in SENSITIVITY_OUTPUT_FILENAMES:
        raise ValueError("invalid sensitivity output filename")
    if len(payload) > MAX_ARTIFACT_JSON_BYTES:
        raise ValueError("evidence sensitivity artifact exceeds maximum supported size")
    descriptor = -1
    try:
        descriptor, metadata = claim.open_regular_file_exclusive_with_metadata(
            name,
            mode=0o600,
        )
        _require_unlinked_regular_output(metadata, name=name)
        created = _CreatedSensitivityOutput(
            path=claim.path / name,
            device=metadata.st_dev,
            inode=metadata.st_ino,
            size=len(payload),
            sha256=hashlib.sha256(payload).hexdigest(),
            pin_descriptor=descriptor,
        )
        _write_descriptor_all(descriptor, payload)
        os.fsync(descriptor)
        if _read_created_output_snapshot(claim, created).data != payload:
            raise OSError("new sensitivity output changed after it was written")
        return created
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise


def _read_created_output_snapshot(
    claim: RootedDirectoryClaim,
    created: _CreatedSensitivityOutput,
) -> BoundedFileContents:
    if created.pin_descriptor is None:
        raise OSError("created sensitivity output is not pinned")
    try:
        entry_before = claim.stat_entry_no_follow(created.path.name)
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
        entry_after = claim.stat_entry_no_follow(created.path.name)
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
    observed_sha256 = digest.hexdigest()
    if observed_sha256 != created.sha256:
        raise OSError("created sensitivity output bytes changed while being verified")
    return BoundedFileContents(
        data=b"".join(chunks),
        sha256=observed_sha256,
        device=opened_after.st_dev,
        inode=opened_after.st_ino,
        size=opened_after.st_size,
        modified_ns=opened_after.st_mtime_ns,
        changed_ns=opened_after.st_ctime_ns,
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


def _close_output_pins(
    created_outputs: tuple[_CreatedSensitivityOutput, ...],
) -> tuple[str, ...]:
    errors: list[str] = []
    for created in created_outputs:
        if created.pin_descriptor is None:
            continue
        pin_descriptor = created.pin_descriptor
        created.pin_descriptor = None
        try:
            os.close(pin_descriptor)
        except OSError as exc:
            errors.append(f"could not close {created.path.name}: {type(exc).__name__}")
    return tuple(errors)


def _validate_staged_sensitivity_generation_immediately_before_commit(
    claim: RootedDirectoryClaim,
    payloads: dict[str, bytes],
    *,
    label: str = "final staged sensitivity output",
) -> tuple[PinnedDirectoryFile, ...]:
    """Validate every child and return pins whose caller owns transactionally."""
    _require_exact_staged_inventory(claim)
    opened_files: list[PinnedDirectoryFile] = []
    pending_error: BaseException | None = None
    try:
        for name in SENSITIVITY_OUTPUT_FILENAMES:
            opened = claim.open_file_bounded(
                name,
                max_bytes=MAX_ARTIFACT_JSON_BYTES,
                label=label,
                require_single_link=True,
            )
            opened_files.append(opened)
            if opened.contents.data != payloads[name]:
                raise OSError(f"{label} bytes are not exact: {name}")
        _require_exact_staged_inventory(claim)
        for opened in opened_files:
            opened.revalidate()
        return tuple(opened_files)
    except BaseException as exc:
        pending_error = exc
        raise
    finally:
        close_errors = (
            _close_final_sensitivity_child_pins(tuple(opened_files))
            if pending_error is not None
            else ()
        )
        if pending_error is not None and close_errors:
            error = OSError(f"could not close {label} pins: " + "; ".join(close_errors))
            raise error from pending_error


def _revalidate_installed_sensitivity_generation_pins(
    claim: RootedDirectoryClaim,
    payloads: dict[str, bytes],
    opened_files: tuple[PinnedDirectoryFile, ...],
) -> None:
    """Bind POSIX pre-commit child pins to their installed names before close."""
    if len(opened_files) != len(payloads):
        raise OSError("installed sensitivity output pin inventory is incomplete")
    _require_exact_staged_inventory(claim)
    for opened in opened_files:
        expected = payloads.get(opened.path.name)
        if expected is None or opened.contents.data != expected:
            raise OSError("installed sensitivity output pin is not expected: " + opened.path.name)
        opened.revalidate()
    _require_exact_staged_inventory(claim)


def _close_final_sensitivity_child_pins(
    opened_files: tuple[PinnedDirectoryFile, ...],
) -> tuple[str, ...]:
    errors: list[str] = []
    for opened in reversed(opened_files):
        try:
            opened.close()
        except OSError as exc:
            errors.append(f"could not close {opened.path.name}: {type(exc).__name__}")
    return tuple(errors)


def _require_unlinked_regular_output(
    metadata: os.stat_result,
    *,
    name: str,
) -> None:
    if (
        not metadata_is_regular_file(metadata)
        or metadata_is_reparse(metadata)
        or metadata.st_nlink != 1
    ):
        raise OSError("sensitivity publication entry is not an unlinked regular file: " + name)


def _write_descriptor_all(descriptor: int, payload: bytes) -> None:
    remaining = memoryview(payload)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise OSError("sensitivity output write made no progress")
        remaining = remaining[written:]


def _require_exact_staged_inventory(claim: RootedDirectoryClaim) -> None:
    names = claim.entry_names(
        max_entries=_SENSITIVITY_OUTPUT_SCAN_LIMIT,
        label="staged evidence sensitivity output",
    )
    expected_by_normalized_name = {
        os.path.normcase(name): name for name in SENSITIVITY_OUTPUT_FILENAMES
    }
    if (
        len(names) != len(SENSITIVITY_OUTPUT_FILENAMES)
        or {os.path.normcase(name): name for name in names} != expected_by_normalized_name
    ):
        raise OSError("staged sensitivity output contains an unexpected entry")


def _fsync_staged_sensitivity_generation(claim: RootedDirectoryClaim) -> None:
    if os.name == "nt":
        return
    flags = os.O_RDONLY | cast(int, vars(os)["O_DIRECTORY"])
    flags |= cast(int, vars(os)["O_NOFOLLOW"])
    flags |= getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(claim.path, flags)
    try:
        metadata = os.fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino) != (claim.device, claim.inode):
            raise OSError("private sensitivity staging identity changed")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _after_sensitivity_generation_commit(parent: RootedDirectoryDescriptor) -> None:
    parent.revalidate_path(label="sensitivity output parent")
    if os.name != "nt" and parent.descriptor is not None:
        os.fsync(parent.descriptor)
    parent.revalidate_path(label="sensitivity output parent")


def _require_directory_identity(
    path: Path,
    *,
    device: int,
    inode: int,
    label: str,
) -> None:
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise OSError(f"{label} directory changed") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata_is_reparse(metadata)
        or (metadata.st_dev, metadata.st_ino) != (device, inode)
    ):
        raise OSError(f"{label} directory changed")


def _validate_finished_publication(
    *,
    expected_texts: dict[str, str],
    expected_graph: AssuranceEvidenceGraph,
    expected_manifest: ReleaseArtifactManifest,
    expected_packet: EvidencePacket,
    observed_snapshots: dict[str, BoundedFileContents],
) -> None:
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
