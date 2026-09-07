from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from pydantic import BaseModel

from agent_assure.artifact_io import ensure_unlinked_directory
from agent_assure.io_limits import (
    MAX_ARTIFACT_JSON_BYTES,
    MAX_JOURNAL_BEARING_RUNSET_JSON_BYTES,
)
from agent_assure.onboarding.path_safety import (
    metadata_is_regular_file,
    metadata_is_reparse,
)
from agent_assure.privacy.redaction import (
    assert_runset_payload_safe_for_persistence,
    redact_packet_payload,
    redact_runset_payload,
)
from agent_assure.reporting.markdown_safety import markdown_code_span, markdown_text
from agent_assure.rooted_io import (
    PinnedDirectoryFile,
    RootedDirectoryClaim,
    RootedDirectoryDescriptor,
    acquire_publication_lock,
    claim_rooted_directory,
    open_rooted_directory,
    release_publication_lock,
    retry_windows_sharing_violation,
)
from agent_assure.schema.run import RunSet
from agent_assure.schema.stochastic_sensitivity import (
    RepeatedEvidenceSensitivityProtocol,
    StatisticalSufficiencyReport,
    StochasticEvidenceSensitivityReport,
)

REPEATED_ANALYSIS_OUTPUT_FILENAMES = (
    "repeated-evidence-sensitivity-protocol.json",
    "baseline.source.runset.json",
    "counterfactual.source.runset.json",
    "statistical-sufficiency-report.json",
    "stochastic-evidence-sensitivity.json",
    "stochastic-evidence-sensitivity.md",
)
REPEATED_RUN_OUTPUT_FILENAMES = (
    "repeated-evidence-sensitivity-protocol.json",
    "baseline.runset.json",
    "counterfactual.runset.json",
)
# Keep the existing Sprint 5/6 publication surface at its reviewed bound.
# Larger internal publishers must opt in explicitly, and may not exceed the
# separately reviewed transaction hard limit.
_MAX_OUTPUT_ENTRIES = 32
_MAX_OUTPUT_ENTRIES_HARD_LIMIT = 384
_PUBLICATION_ARTIFACT_BYTES_HARD_LIMIT = MAX_JOURNAL_BEARING_RUNSET_JSON_BYTES
_STAGING_NAME_PREFIX = ".agent-assure-stochastic-"
_PUBLICATION_LOCK_PREFIX = ".agent-assure-stochastic-lock-"
_BEST_EFFORT_LOCK_TIMEOUT_SECONDS = 0.001
_CONCURRENT_GENERATION_RETRY_TIMEOUT_SECONDS = 0.25


@dataclass
class _CreatedRepeatedOutput:
    name: str
    device: int
    inode: int
    size: int
    descriptor: int


class RepeatedSensitivityOutputConflictError(ValueError):
    """Raised when a destination contains another artifact generation."""


class RepeatedSensitivityPrivacyError(ValueError):
    """Raised when protocol-bound evidence is unsafe to persist unchanged."""


class _ExistingGenerationForeignEntryError(ValueError):
    """Internal typed classification for a statically foreign output entry."""


def write_repeated_analysis_artifacts(
    *,
    protocol: RepeatedEvidenceSensitivityProtocol,
    baseline_source: RunSet,
    counterfactual_source: RunSet,
    sufficiency: StatisticalSufficiencyReport,
    report: StochasticEvidenceSensitivityReport,
    out_dir: Path,
) -> dict[str, Path]:
    """Publish one coherent, inspectable analysis generation."""
    protocol = RepeatedEvidenceSensitivityProtocol.model_validate(protocol.model_dump(mode="json"))
    sufficiency = StatisticalSufficiencyReport.model_validate(sufficiency.model_dump(mode="json"))
    report = StochasticEvidenceSensitivityReport.model_validate(report.model_dump(mode="json"))
    if sufficiency.protocol != protocol:
        raise ValueError("sufficiency artifact does not embed the exact supplied protocol")
    if report.sufficiency_report != sufficiency:
        raise ValueError("stochastic result does not embed the exact supplied sufficiency report")
    baseline_source = _unchanged_safe_runset_for_analysis(baseline_source)
    counterfactual_source = _unchanged_safe_runset_for_analysis(counterfactual_source)
    from agent_assure.rag.repeated_sensitivity import (
        assemble_paired_observations,
        build_paired_runset_dependencies,
    )

    expected_sources = (
        ()
        if protocol.execution_mode.value == "deterministic_fixture"
        else build_paired_runset_dependencies(
            protocol,
            baseline_source,
            counterfactual_source,
        )
    )
    if sufficiency.source_runsets != expected_sources:
        raise ValueError(
            "sufficiency source dependencies do not match the supplied RunSet snapshots"
        )
    expected_observations = assemble_paired_observations(
        protocol,
        baseline_source,
        counterfactual_source,
    )
    if sufficiency.observations != expected_observations:
        raise ValueError(
            "sufficiency observations do not exactly reassemble from the supplied RunSet snapshots"
        )

    texts = {
        "repeated-evidence-sensitivity-protocol.json": _safe_model_json_text(protocol),
        "baseline.source.runset.json": _model_json_text(baseline_source),
        "counterfactual.source.runset.json": _model_json_text(counterfactual_source),
        "statistical-sufficiency-report.json": _safe_model_json_text(sufficiency),
        "stochastic-evidence-sensitivity.json": _safe_model_json_text(report),
        "stochastic-evidence-sensitivity.md": render_stochastic_sensitivity_markdown(report),
    }
    _assert_text_safe(texts["stochastic-evidence-sensitivity.md"])
    return publish_generation(
        out_dir,
        texts,
        expected_filenames=REPEATED_ANALYSIS_OUTPUT_FILENAMES,
        artifact_max_bytes={
            "baseline.source.runset.json": MAX_JOURNAL_BEARING_RUNSET_JSON_BYTES,
            "counterfactual.source.runset.json": MAX_JOURNAL_BEARING_RUNSET_JSON_BYTES,
        },
    )


def write_repeated_run_artifacts(
    *,
    protocol: RepeatedEvidenceSensitivityProtocol,
    baseline: RunSet,
    counterfactual: RunSet,
    out_dir: Path,
) -> dict[str, Path]:
    """Publish paired RunSets only after applying the established privacy filter."""
    protocol = RepeatedEvidenceSensitivityProtocol.model_validate(protocol.model_dump(mode="json"))
    baseline = _safe_runset_for_persistence(baseline)
    counterfactual = _safe_runset_for_persistence(counterfactual)
    texts = {
        "repeated-evidence-sensitivity-protocol.json": _safe_model_json_text(protocol),
        "baseline.runset.json": _model_json_text(baseline),
        "counterfactual.runset.json": _model_json_text(counterfactual),
    }
    return publish_generation(
        out_dir,
        texts,
        expected_filenames=REPEATED_RUN_OUTPUT_FILENAMES,
        artifact_max_bytes={
            "baseline.runset.json": MAX_JOURNAL_BEARING_RUNSET_JSON_BYTES,
            "counterfactual.runset.json": MAX_JOURNAL_BEARING_RUNSET_JSON_BYTES,
        },
    )


def render_stochastic_sensitivity_markdown(
    report: StochasticEvidenceSensitivityReport,
) -> str:
    report = StochasticEvidenceSensitivityReport.model_validate(report.model_dump(mode="json"))
    sufficiency = report.sufficiency_report
    protocol = sufficiency.protocol
    analysis = sufficiency.analysis
    dependency = (
        "none (non-verdict result)"
        if report.dependency is None
        else (
            f"{report.dependency.edge_kind} "
            f"{report.dependency.target_artifact_id} "
            f"sha256:{report.dependency.target_digest}"
        )
    )
    rate = report.estimated_response_rate or "not estimated"
    analysis_lines = (
        [
            f"- Analysis method: {markdown_code_span(analysis.method)}",
            f"- Adjusted p-value threshold: {markdown_code_span(analysis.adjusted_alpha)}",
            "- Exact p-value definition: "
            + markdown_code_span(
                "P[X >= "
                f"{analysis.exact_p_value_expression.threshold}] for X ~ "
                f"Binomial({analysis.exact_p_value_expression.trials}, "
                f"{analysis.exact_p_value_expression.probability_numerator}/"
                f"{analysis.exact_p_value_expression.probability_denominator})"
            ),
            "- Conservative six-place exact p-value upper bound: "
            f"{markdown_code_span(analysis.p_value_upper_bound)}",
            "- Gate arithmetic: exact binomial rejection region is recomputed; "
            "the rounded display bound is not a gate input.",
            f"- Compared clusters: {analysis.compared_clusters}",
            f"- Responding clusters: {analysis.responding_clusters}",
            f"- Monte Carlo diagnostic resamples: {analysis.monte_carlo_resamples}",
            (
                "- Monte Carlo diagnostic estimate: "
                f"{markdown_code_span(analysis.monte_carlo_estimate or 'not run')}"
            ),
        ]
        if analysis is not None
        else ["- Analysis: not run"]
    )
    prerequisite_lines = [
        (
            f"- {markdown_code_span(item.check_id)}: "
            f"{markdown_code_span(item.state.value)}"
            + (f" ({markdown_code_span(item.reason_code)})" if item.reason_code is not None else "")
        )
        for item in sufficiency.prerequisites
    ]
    limitation_lines = [
        f"- {markdown_text(item)}"
        for item in tuple(dict.fromkeys(report.limitations + sufficiency.limitations))
    ]
    lines = [
        "# Repeated evidence-sensitivity result",
        "",
        "## Decision",
        "",
        f"- State: {markdown_code_span(report.state.value)}",
        f"- Gate effect: {markdown_code_span(report.gate_effect.value)}",
        f"- Verdict-bearing: {str(report.verdict_bearing).lower()}",
        f"- Population claim: {markdown_code_span(report.population_claim)}",
        f"- Dependency: {markdown_code_span(dependency)}",
        "",
        "## Endpoint observations",
        "",
        f"- Endpoint: {markdown_code_span(report.endpoint)}",
        f"- Included pairs: {report.observed_pair_count}",
        f"- Observed responses: {report.observed_response_count}",
        f"- Observed counterexamples: {report.observed_counterexample_count}",
        f"- Complete clusters: {report.observed_cluster_count}",
        f"- Responding clusters: {report.observed_cluster_response_count}",
        f"- Estimated independent-cluster response rate: {markdown_code_span(rate)}",
        "",
        "Observed pair counterexamples are sample facts. The estimated independent-"
        "cluster response rate is a separate inferential summary and is absent in "
        "deterministic fixture mode or when structural prerequisites fail.",
        "",
        "## Design sufficiency",
        "",
        f"- Sufficiency state: {markdown_code_span(sufficiency.state.value)}",
        f"- Planned / actual / included pairs: "
        f"{sufficiency.planned_pairs} / {sufficiency.actual_pairs} / "
        f"{sufficiency.included_pairs}",
        f"- Missing / excluded pairs: {sufficiency.missing_pairs} / {sufficiency.excluded_pairs}",
        f"- Planned / actual / analyzable clusters: "
        f"{sufficiency.planned_clusters} / {sufficiency.actual_clusters} / "
        f"{sufficiency.analyzable_clusters}",
        f"- Source RunSet dependencies: {len(sufficiency.source_runsets)}",
        f"- Coupling classification: {markdown_code_span(protocol.coupling.classification.value)}",
        f"- Variance-reduction claim permitted: "
        f"{str(protocol.coupling.variance_reduction_claim_permitted).lower()}",
        *analysis_lines,
        "",
        "### Prerequisites",
        "",
        *prerequisite_lines,
        "",
        "## Limitations",
        "",
        *limitation_lines,
        "",
    ]
    return "\n".join(lines)


def _safe_model_json_text(model: BaseModel) -> str:
    payload = model.model_dump(mode="json", warnings="error")
    if redact_packet_payload(payload) != payload:
        raise RepeatedSensitivityPrivacyError(
            "protocol-bound statistical evidence contains sensitive values"
        )
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def _model_json_text(model: BaseModel) -> str:
    return (
        json.dumps(
            model.model_dump(mode="json", warnings="error"),
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def _safe_runset_for_persistence(runset: RunSet) -> RunSet:
    runset = RunSet.model_validate(runset.model_dump(mode="json"))
    payload = redact_runset_payload(runset.model_dump(mode="json"))
    assert_runset_payload_safe_for_persistence(payload)
    return RunSet.model_validate(payload)


def _unchanged_safe_runset_for_analysis(runset: RunSet) -> RunSet:
    runset = RunSet.model_validate(runset.model_dump(mode="json"))
    original = runset.model_dump(mode="json", warnings="error")
    filtered = redact_runset_payload(original)
    assert_runset_payload_safe_for_persistence(filtered)
    if filtered != original:
        raise RepeatedSensitivityPrivacyError(
            "analysis source RunSets must already be privacy-filtered because "
            "redaction would invalidate their cryptographic dependencies"
        )
    return runset


def _assert_text_safe(value: str) -> None:
    payload = {"content": value}
    if redact_packet_payload(payload) != payload:
        raise RepeatedSensitivityPrivacyError(
            "rendered statistical evidence contains sensitive values"
        )


def publish_generation(
    out_dir: Path,
    texts: Mapping[str, str],
    *,
    expected_filenames: tuple[str, ...],
    max_output_entries: int = _MAX_OUTPUT_ENTRIES,
    artifact_max_bytes: Mapping[str, int] | None = None,
) -> dict[str, Path]:
    if not 1 <= max_output_entries <= _MAX_OUTPUT_ENTRIES_HARD_LIMIT:
        raise ValueError("publication output-entry bound is outside the reviewed limits")
    if len(expected_filenames) > max_output_entries:
        raise ValueError("publication output inventory exceeds its declared entry bound")
    if tuple(texts) != expected_filenames:
        raise ValueError("repeated sensitivity output inventory is inconsistent")
    if len({os.path.normcase(name) for name in expected_filenames}) != len(expected_filenames):
        raise ValueError("repeated sensitivity output filenames alias on this filesystem")
    target = _validate_output_target(out_dir)
    payloads = {name: text.encode("utf-8") for name, text in texts.items()}
    byte_limits = _publication_byte_limits(expected_filenames, artifact_max_bytes)
    if any(len(payload) > byte_limits[name] for name, payload in payloads.items()):
        raise ValueError("repeated sensitivity artifact exceeds the maximum supported size")

    parent = ensure_unlinked_directory(target.parent)
    parent_metadata = os.lstat(parent)
    with open_rooted_directory(
        parent,
        ".",
        label="repeated sensitivity output parent",
    ) as parent_lease:
        if (parent_lease.device, parent_lease.inode) != (
            parent_metadata.st_dev,
            parent_metadata.st_ino,
        ):
            raise OSError("repeated sensitivity output parent changed while opening")
        _require_directory_identity(
            parent_lease.path,
            device=parent_lease.device,
            inode=parent_lease.inode,
            label="repeated sensitivity output parent",
        )
        with _best_effort_publication_lock(parent_lease, target.name):
            existing = _existing_generation_with_transient_share_retry(
                parent_lease,
                target,
                expected_filenames,
                max_output_entries=max_output_entries,
                artifact_max_bytes=byte_limits,
            )
            if existing is not None:
                if existing == dict(texts):
                    return {name: target / name for name in expected_filenames}
                raise RepeatedSensitivityOutputConflictError(
                    "destination contains a different or incomplete artifact generation"
                )

            claim = _claim_private_staging_directory(parent_lease, target.name)
            created: list[_CreatedRepeatedOutput] = []
            try:
                try:
                    for name in expected_filenames:
                        descriptor, metadata = claim.open_regular_file_exclusive_with_metadata(
                            name,
                            mode=0o600,
                        )
                        created_output = _CreatedRepeatedOutput(
                            name=name,
                            device=metadata.st_dev,
                            inode=metadata.st_ino,
                            size=len(payloads[name]),
                            descriptor=descriptor,
                        )
                        created.append(created_output)
                        _require_unlinked_regular_output(metadata, name=name)
                        _write_descriptor_all(descriptor, payloads[name])
                        os.fsync(descriptor)
                        _verify_created_output(claim, created_output, payloads[name])
                    names = claim.entry_names(
                        max_entries=max_output_entries,
                        label="staged repeated sensitivity output",
                    )
                    expected_by_normalized_name = {
                        os.path.normcase(name): name for name in expected_filenames
                    }
                    if (
                        len(names) != len(expected_filenames)
                        or {os.path.normcase(name): name for name in names}
                        != expected_by_normalized_name
                    ):
                        raise OSError(
                            "staged repeated sensitivity output contains an unexpected entry"
                        )
                    for output in created:
                        _verify_created_output(claim, output, payloads[output.name])
                    close_errors = _close_created_output_descriptors(created)
                    if close_errors:
                        raise OSError(
                            "could not close staged repeated sensitivity output descriptors: "
                            + "; ".join(close_errors)
                        )
                    _fsync_staged_generation(claim)
                except Exception as exc:
                    close_errors = _close_created_output_descriptors(created)
                    if close_errors:
                        raise OSError(
                            "repeated sensitivity staging failed and descriptor cleanup was "
                            "incomplete: " + "; ".join(close_errors)
                        ) from exc
                    # A private random staging directory is never an adoptable
                    # generation. Retaining it avoids identity-racy rollback and
                    # lets a later invocation recover without deleting entries it
                    # cannot prove it still owns. Surface the exact recovery path.
                    raise OSError(
                        "repeated sensitivity publication failed before commit; "
                        f"private staging retained at {claim.path}"
                    ) from exc
                except BaseException:
                    _close_created_output_descriptors(created)
                    raise
                finally:
                    _close_created_output_descriptors(created)

                final_child_pins: tuple[PinnedDirectoryFile, ...] = ()
                try:
                    final_child_pins = _validate_staged_generation_immediately_before_commit(
                        claim,
                        payloads,
                        max_output_entries=max_output_entries,
                        artifact_max_bytes=byte_limits,
                    )
                except Exception as exc:
                    raise OSError(
                        "repeated sensitivity publication failed before commit; "
                        f"private staging retained at {claim.path}"
                    ) from exc
                try:
                    if os.name == "nt":
                        close_errors = _close_final_child_pins(final_child_pins)
                        final_child_pins = ()
                        if close_errors:
                            raise OSError(
                                "could not close final staged repeated sensitivity output pins: "
                                + "; ".join(close_errors)
                            )
                    _install_staged_generation_no_replace(claim, target)
                    if os.name == "nt":
                        # The claim owns DELETE access, so a separately pinned
                        # installed-generation lease cannot coexist with it on
                        # Windows. Release the committed claim, then verify the
                        # target through fresh no-follow directory and child pins.
                        claim.close()
                        installed = _existing_generation_with_transient_share_retry(
                            parent_lease,
                            target,
                            expected_filenames,
                            max_output_entries=max_output_entries,
                            artifact_max_bytes=byte_limits,
                        )
                        if installed != dict(texts):
                            raise OSError(
                                "committed repeated sensitivity output is not the exact "
                                "expected generation"
                            )
                    else:
                        _revalidate_installed_generation_pins(
                            claim,
                            payloads,
                            final_child_pins,
                            max_output_entries=max_output_entries,
                        )
                    close_errors = _close_final_child_pins(final_child_pins)
                    final_child_pins = ()
                    if close_errors:
                        raise OSError(
                            "could not close installed repeated sensitivity output pins: "
                            + "; ".join(close_errors)
                        )
                except FileExistsError as exc:
                    close_errors = _close_final_child_pins(final_child_pins)
                    final_child_pins = ()
                    if close_errors:
                        raise OSError(
                            "could not close final staged repeated sensitivity output pins: "
                            + "; ".join(close_errors)
                        ) from exc
                    try:
                        _after_generation_commit(parent_lease)
                        installed = _existing_generation_with_transient_share_retry(
                            parent_lease,
                            target,
                            expected_filenames,
                            max_output_entries=max_output_entries,
                            artifact_max_bytes=byte_limits,
                        )
                    except (OSError, UnicodeError, ValueError) as verification_error:
                        raise RepeatedSensitivityOutputConflictError(
                            "repeated sensitivity output was committed concurrently but "
                            f"could not be safely adopted; private staging retained at {claim.path}"
                        ) from verification_error
                    if installed == dict(texts):
                        return {name: target / name for name in expected_filenames}
                    raise RepeatedSensitivityOutputConflictError(
                        "repeated sensitivity output was committed concurrently with different "
                        "or incomplete content; "
                        f"private staging retained at {claim.path}"
                    ) from exc
                except Exception as exc:
                    if claim.name == target.name:
                        raise OSError(
                            "repeated sensitivity output committed, but post-commit identity "
                            f"validation failed; committed target retained at {target}"
                        ) from exc
                    raise OSError(
                        "repeated sensitivity publication failed before commit; "
                        f"private staging retained at {claim.path}"
                    ) from exc
                finally:
                    _close_final_child_pins(final_child_pins)
            finally:
                claim.close()

            # The rename above is the commit point. Every possible late error
            # is reported without deleting or replacing the installed target.
            try:
                _after_generation_commit(parent_lease)
                installed = _existing_generation_with_transient_share_retry(
                    parent_lease,
                    target,
                    expected_filenames,
                    max_output_entries=max_output_entries,
                    artifact_max_bytes=byte_limits,
                )
                if installed != dict(texts):
                    raise OSError("committed repeated sensitivity output could not be revalidated")
            except Exception as exc:
                raise OSError(
                    "repeated sensitivity output committed, but post-commit durability or "
                    f"validation failed; committed target retained at {target}"
                ) from exc
    return {name: target / name for name in expected_filenames}


def _publication_byte_limits(
    expected_filenames: tuple[str, ...],
    overrides: Mapping[str, int] | None,
) -> dict[str, int]:
    limits = {name: MAX_ARTIFACT_JSON_BYTES for name in expected_filenames}
    if overrides is None:
        return limits
    unknown = set(overrides) - set(expected_filenames)
    if unknown:
        raise ValueError("publication byte-limit inventory contains an unknown artifact")
    for name, value in overrides.items():
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 1 <= value <= _PUBLICATION_ARTIFACT_BYTES_HARD_LIMIT
        ):
            raise ValueError("publication artifact byte limit is outside the reviewed bounds")
        limits[name] = value
    return limits


def _claim_private_staging_directory(
    parent: RootedDirectoryDescriptor,
    target_name: str,
) -> RootedDirectoryClaim:
    target_digest = hashlib.sha256(os.path.normcase(target_name).encode("utf-8")).hexdigest()[:16]
    target_staging_prefix = f"{_STAGING_NAME_PREFIX}{target_digest}-"
    for _ in range(8):
        staging_name = f"{target_staging_prefix}{secrets.token_hex(16)}.tmp"
        try:
            return claim_rooted_directory(
                parent,
                staging_name,
                label="private repeated sensitivity staging directory",
                mode=0o700,
            )
        except FileExistsError:
            continue
    raise OSError("could not reserve a private repeated sensitivity staging directory")


@contextmanager
def _best_effort_publication_lock(
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
                _ensure_lock_byte(descriptor)
            acquired = _lock_descriptor(descriptor)
            if acquired:
                if os.name != "nt":
                    _ensure_lock_byte(descriptor)
                current = parent.stat_entry_no_follow(lock_name)
                _require_unlinked_regular_output(current, name=lock_name)
                if (current.st_dev, current.st_ino) != (metadata.st_dev, metadata.st_ino):
                    raise OSError("repeated sensitivity publication lock identity changed")
        except (OSError, ValueError):
            if acquired and descriptor is not None:
                _unlock_descriptor(descriptor)
            acquired = False
            if descriptor is not None:
                os.close(descriptor)
                descriptor = None
        yield
    finally:
        try:
            if acquired and descriptor is not None:
                _unlock_descriptor(descriptor)
        finally:
            if descriptor is not None:
                os.close(descriptor)


def _ensure_lock_byte(descriptor: int) -> None:
    if os.fstat(descriptor).st_size >= 1:
        return
    os.lseek(descriptor, 0, os.SEEK_SET)
    if os.write(descriptor, b"\x00") != 1:
        raise OSError("repeated sensitivity publication lock initialization failed")
    os.fsync(descriptor)


def _lock_descriptor(descriptor: int) -> bool:
    try:
        acquire_publication_lock(
            descriptor,
            label="repeated sensitivity publication",
            timeout_seconds=_BEST_EFFORT_LOCK_TIMEOUT_SECONDS,
        )
    except TimeoutError:
        return False
    return True


def _unlock_descriptor(descriptor: int) -> None:
    release_publication_lock(descriptor)


def _fsync_staged_generation(claim: RootedDirectoryClaim) -> None:
    if os.name == "nt":
        return
    flags = os.O_RDONLY | cast(int, vars(os)["O_DIRECTORY"])
    flags |= cast(int, vars(os)["O_NOFOLLOW"])
    flags |= getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(claim.path, flags)
    try:
        metadata = os.fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino) != (claim.device, claim.inode):
            raise OSError("private repeated sensitivity staging identity changed")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _install_staged_generation_no_replace(
    claim: RootedDirectoryClaim,
    target: Path,
) -> None:
    claim.install_no_replace(target.name)


def _after_generation_commit(parent: RootedDirectoryDescriptor) -> None:
    _require_directory_identity(
        parent.path,
        device=parent.device,
        inode=parent.inode,
        label="repeated sensitivity output parent",
    )
    if os.name != "nt" and parent.descriptor is not None:
        os.fsync(parent.descriptor)
    _require_directory_identity(
        parent.path,
        device=parent.device,
        inode=parent.inode,
        label="repeated sensitivity output parent",
    )


def _validate_output_target(out_dir: Path) -> Path:
    target = Path(os.path.abspath(out_dir))
    if target == Path(target.anchor):
        raise ValueError("repeated sensitivity output must not be a filesystem root")
    if not target.name:
        raise ValueError("repeated sensitivity output must name a directory")
    return target


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


def _existing_generation(
    parent: RootedDirectoryDescriptor,
    out_dir: Path,
    expected_filenames: tuple[str, ...],
    *,
    max_output_entries: int = _MAX_OUTPUT_ENTRIES,
    artifact_max_bytes: Mapping[str, int] | None = None,
) -> dict[str, str] | None:
    byte_limits = _publication_byte_limits(expected_filenames, artifact_max_bytes)
    _require_directory_identity(
        parent.path,
        device=parent.device,
        inode=parent.inode,
        label="repeated sensitivity output parent",
    )
    try:
        lease = open_rooted_directory(
            parent.path,
            out_dir.name,
            label="existing repeated sensitivity output",
        )
    except FileNotFoundError:
        _require_directory_identity(
            parent.path,
            device=parent.device,
            inode=parent.inode,
            label="repeated sensitivity output parent",
        )
        return None
    except (OSError, ValueError) as exc:
        raise RepeatedSensitivityOutputConflictError(
            "destination is not an unlinked regular directory"
        ) from exc
    expected_by_normalized_name = {os.path.normcase(name): name for name in expected_filenames}
    try:
        with lease:
            if (lease.root_device, lease.root_inode) != (parent.device, parent.inode):
                raise RepeatedSensitivityOutputConflictError(
                    "repeated sensitivity output parent changed during verification"
                )
            names = lease.entry_names(
                max_entries=max_output_entries,
                label="existing repeated sensitivity output",
            )
            if any(
                expected_by_normalized_name.get(os.path.normcase(name)) != name for name in names
            ):
                raise RepeatedSensitivityOutputConflictError(
                    "destination contains a foreign or non-regular artifact entry"
                )
            observed: dict[str, str] = {}
            opened_files: list[PinnedDirectoryFile] = []
            try:
                for name in names:
                    try:
                        metadata = lease.stat_entry_no_follow(name)
                    except (OSError, ValueError) as exc:
                        raise _ExistingGenerationForeignEntryError(name) from exc
                    if (
                        not metadata_is_regular_file(metadata)
                        or metadata_is_reparse(metadata)
                        or metadata.st_nlink != 1
                    ):
                        raise _ExistingGenerationForeignEntryError(name)
                    opened = lease.open_file_bounded(
                        name,
                        max_bytes=byte_limits[name],
                        label="existing repeated sensitivity output",
                        require_single_link=True,
                    )
                    opened_files.append(opened)
                    observed[name] = opened.contents.data.decode("utf-8")
                verified_names = lease.entry_names(
                    max_entries=max_output_entries,
                    label="existing repeated sensitivity output",
                )
                if len(verified_names) != len(names) or set(verified_names) != set(names):
                    raise ValueError("destination inventory changed during verification")
                for opened in opened_files:
                    opened.revalidate()
                _require_directory_identity(
                    parent.path,
                    device=parent.device,
                    inode=parent.inode,
                    label="repeated sensitivity output parent",
                )
                _require_claimed_output_identity(
                    parent.path / out_dir.name,
                    device=lease.device,
                    inode=lease.inode,
                )
            finally:
                for opened in reversed(opened_files):
                    opened.close()
    except RepeatedSensitivityOutputConflictError:
        raise
    except _ExistingGenerationForeignEntryError as exc:
        raise RepeatedSensitivityOutputConflictError(
            "destination contains a foreign or non-regular artifact entry"
        ) from exc
    except (OSError, UnicodeError, ValueError) as exc:
        raise RepeatedSensitivityOutputConflictError(
            "existing repeated sensitivity output cannot be safely verified"
        ) from exc
    _require_directory_identity(
        parent.path,
        device=parent.device,
        inode=parent.inode,
        label="repeated sensitivity output parent",
    )
    if set(names) != set(expected_filenames):
        return {}
    return {name: observed[name] for name in expected_filenames}


def _existing_generation_with_transient_share_retry(
    parent: RootedDirectoryDescriptor,
    out_dir: Path,
    expected_filenames: tuple[str, ...],
    *,
    max_output_entries: int = _MAX_OUTPUT_ENTRIES,
    artifact_max_bytes: Mapping[str, int] | None = None,
) -> dict[str, str] | None:
    """Re-run exact verification while an honest Windows winner releases its pin."""

    return retry_windows_sharing_violation(
        lambda: _existing_generation(
            parent,
            out_dir,
            expected_filenames,
            max_output_entries=max_output_entries,
            artifact_max_bytes=artifact_max_bytes,
        ),
        timeout_seconds=_CONCURRENT_GENERATION_RETRY_TIMEOUT_SECONDS,
    )


def _require_unlinked_regular_output(metadata: os.stat_result, *, name: str) -> None:
    if (
        not metadata_is_regular_file(metadata)
        or metadata_is_reparse(metadata)
        or metadata.st_nlink != 1
    ):
        raise OSError("new repeated sensitivity output is not an unlinked regular file: " + name)


def _require_created_output_identity(
    metadata: os.stat_result,
    created: _CreatedRepeatedOutput,
) -> None:
    _require_unlinked_regular_output(metadata, name=created.name)
    if (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
    ) != (
        created.device,
        created.inode,
        created.size,
    ):
        raise OSError("new repeated sensitivity output changed concurrently: " + created.name)


def _verify_created_output(
    claim: RootedDirectoryClaim,
    created: _CreatedRepeatedOutput,
    payload: bytes,
) -> None:
    opened = os.fstat(created.descriptor)
    _require_created_output_identity(opened, created)
    _require_created_output_identity(
        claim.stat_entry_no_follow(created.name),
        created,
    )
    os.lseek(created.descriptor, 0, os.SEEK_SET)
    if _read_descriptor_exact(created.descriptor, len(payload)) != payload:
        raise OSError("repeated sensitivity output changed while being written: " + created.name)


def _write_descriptor_all(descriptor: int, payload: bytes) -> None:
    remaining = memoryview(payload)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise OSError("repeated sensitivity output write made no progress")
        remaining = remaining[written:]


def _read_descriptor_exact(descriptor: int, expected_size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = expected_size + 1
    while remaining > 0:
        chunk = os.read(descriptor, min(1024 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _close_created_output_descriptors(
    created: list[_CreatedRepeatedOutput],
) -> tuple[str, ...]:
    errors: list[str] = []
    for output in created:
        if output.descriptor < 0:
            continue
        try:
            os.close(output.descriptor)
        except OSError as exc:
            errors.append(f"could not close {output.name}: {type(exc).__name__}")
        else:
            output.descriptor = -1
    return tuple(errors)


def _validate_staged_generation_immediately_before_commit(
    claim: RootedDirectoryClaim,
    payloads: Mapping[str, bytes],
    *,
    max_output_entries: int = _MAX_OUTPUT_ENTRIES,
    artifact_max_bytes: Mapping[str, int] | None = None,
    label: str = "final staged repeated sensitivity output",
) -> tuple[PinnedDirectoryFile, ...]:
    """Validate every child and return pins whose caller owns transactionally."""
    names = claim.entry_names(
        max_entries=max_output_entries,
        label=label,
    )
    if len(names) != len(payloads) or set(names) != set(payloads):
        raise OSError(f"{label} inventory is not exact")
    opened_files: list[PinnedDirectoryFile] = []
    byte_limits = _publication_byte_limits(tuple(payloads), artifact_max_bytes)
    pending_error: BaseException | None = None
    try:
        for name in payloads:
            opened = claim.open_file_bounded(
                name,
                max_bytes=byte_limits[name],
                label=label,
                require_single_link=True,
            )
            opened_files.append(opened)
            if opened.contents.data != payloads[name]:
                raise OSError(f"{label} bytes are not exact: {name}")
        verified_names = claim.entry_names(
            max_entries=max_output_entries,
            label=label,
        )
        if len(verified_names) != len(names) or set(verified_names) != set(names):
            raise OSError(f"{label} inventory changed during verification")
        for opened in opened_files:
            opened.revalidate()
        return tuple(opened_files)
    except BaseException as exc:
        pending_error = exc
        raise
    finally:
        close_errors = (
            _close_final_child_pins(tuple(opened_files)) if pending_error is not None else ()
        )
        if pending_error is not None and close_errors:
            error = OSError(f"could not close {label} pins: " + "; ".join(close_errors))
            raise error from pending_error


def _revalidate_installed_generation_pins(
    claim: RootedDirectoryClaim,
    payloads: Mapping[str, bytes],
    opened_files: tuple[PinnedDirectoryFile, ...],
    *,
    max_output_entries: int = _MAX_OUTPUT_ENTRIES,
) -> None:
    """Bind POSIX pre-commit child pins to their installed names before close."""
    if len(opened_files) != len(payloads):
        raise OSError("installed repeated sensitivity output pin inventory is incomplete")
    names = claim.entry_names(
        max_entries=max_output_entries,
        label="installed repeated sensitivity output",
    )
    if len(names) != len(payloads) or set(names) != set(payloads):
        raise OSError("installed repeated sensitivity output inventory changed after commit")
    for opened in opened_files:
        expected = payloads.get(opened.path.name)
        if expected is None or opened.contents.data != expected:
            raise OSError(
                "installed repeated sensitivity output pin is not expected: " + opened.path.name
            )
        opened.revalidate()
    verified_names = claim.entry_names(
        max_entries=max_output_entries,
        label="installed repeated sensitivity output",
    )
    if len(verified_names) != len(names) or set(verified_names) != set(names):
        raise OSError("installed repeated sensitivity output inventory changed after commit")


def _close_final_child_pins(
    opened_files: tuple[PinnedDirectoryFile, ...],
) -> tuple[str, ...]:
    errors: list[str] = []
    for opened in reversed(opened_files):
        try:
            opened.close()
        except OSError as exc:
            errors.append(f"could not close {opened.path.name}: {type(exc).__name__}")
    return tuple(errors)


def _require_claimed_output_identity(
    path: Path,
    *,
    device: int,
    inode: int,
) -> None:
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise OSError("repeated sensitivity output directory changed") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata_is_reparse(metadata)
        or (metadata.st_dev, metadata.st_ino) != (device, inode)
    ):
        raise OSError("repeated sensitivity output directory changed")


__all__ = [
    "REPEATED_ANALYSIS_OUTPUT_FILENAMES",
    "REPEATED_RUN_OUTPUT_FILENAMES",
    "RepeatedSensitivityOutputConflictError",
    "RepeatedSensitivityPrivacyError",
    "publish_generation",
    "render_stochastic_sensitivity_markdown",
    "write_repeated_analysis_artifacts",
    "write_repeated_run_artifacts",
]
