from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from agent_assure.mutation.catalog import (
    RegisteredOperator,
    implementation_component_sha256,
    lf_normalized_sha256,
    registered_operators,
    target_control_component_path,
)
from agent_assure.schema.mutation import (
    OperatorProvenance,
    TargetControlProvenance,
    mutation_implementation_digest,
)
from scripts.build_release_bundle import main as build_release_bundle
from scripts.check_mutation_release_provenance import (
    _git_creation_source,
    registered_release_provenance_failures,
    release_provenance_failures,
)

_INTRODUCTION_COMMIT = "git:" + "a" * 40
_RELEASE_COMMIT = "git:" + "b" * 40
_AUTHORED_INTRODUCTION_COMMIT = "git:208f304574fc7bb3b7ed7b821c745b951f2783c8"
_PRE_EVIDENCE_PROVENANCE_COMMIT = "git:441fc73793fd9154a2830613dfe2a521ca3eeaa1"
_SPRINT2_INTRODUCTION_COMMIT = "git:820621d1e42862cfa4356468b4de24d0138165c3"
_REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


def _introduction_source(relative_path: str) -> bytes:
    return _git_creation_source(_AUTHORED_INTRODUCTION_COMMIT, relative_path)


def _checkout_source(relative_path: str) -> bytes:
    source_path = (
        _REPOSITORY_ROOT / "src" / relative_path
        if relative_path.startswith("agent_assure/")
        else _REPOSITORY_ROOT / relative_path
    )
    return source_path.read_bytes()


def _frozen_source_loader(
    requested_sources: list[tuple[str, str]],
    sources: dict[str, bytes],
    commit: str,
    relative_path: str,
) -> bytes:
    requested_sources.append((commit, relative_path))
    return sources[relative_path]


def _simulated_stamped_provenance(
    provenance: OperatorProvenance,
    *,
    first_seen_commit: str | None = None,
) -> tuple[OperatorProvenance, dict[str, bytes]]:
    sources = {
        component.relative_path: _checkout_source(component.relative_path)
        for component in provenance.introduction_components
    }
    for target in provenance.target_controls:
        relative_path = target_control_component_path(target.control_id)
        sources[relative_path] = _checkout_source(relative_path)

    introduction_components = tuple(
        component.model_copy(
            update={
                "sha256": implementation_component_sha256(
                    component.relative_path,
                    sources[component.relative_path],
                )
            }
        )
        for component in provenance.introduction_components
    )
    target_controls: list[TargetControlProvenance] = []
    for target in provenance.target_controls:
        relative_path = target_control_component_path(target.control_id)
        update = {"digest_at_operator_creation": lf_normalized_sha256(sources[relative_path])}
        if first_seen_commit is not None:
            update["first_seen_commit"] = first_seen_commit
        target_controls.append(target.model_copy(update=update))

    stamped = provenance.model_copy(
        update={
            "introduced_at_commit": _INTRODUCTION_COMMIT,
            "introduction_components": introduction_components,
            "target_controls": tuple(target_controls),
        }
    )
    sources["agent_assure/mutation/introduction_snapshots.json"] = json.dumps(
        {
            provenance.operator_id: [
                component.model_dump(mode="json") for component in introduction_components
            ]
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return stamped, sources


def _release_ready_provenance(
    *,
    introduced_in_release: str = "0.6.0",
) -> OperatorProvenance:
    provenance = registered_operators()[0].descriptor.provenance
    target_controls = tuple(
        target.model_copy(
            update={
                "digest_at_operator_creation": lf_normalized_sha256(
                    _introduction_source(target_control_component_path(target.control_id))
                )
            }
        )
        for target in provenance.target_controls
    )
    return provenance.model_copy(
        update={
            "introduced_at_commit": _INTRODUCTION_COMMIT,
            "introduced_in_release": introduced_in_release,
            "target_controls": target_controls,
        }
    )


def _v060_registered_operators() -> tuple[RegisteredOperator, ...]:
    return tuple(
        item
        for item in registered_operators()
        if item.descriptor.provenance.introduced_in_release == "0.6.0"
    )


def test_registered_operator_provenance_accepts_sprint2_stamp() -> None:
    failures = registered_release_provenance_failures(
        expected_release="0.6.1",
        release_commit="git:"
        + subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=_REPOSITORY_ROOT,
            text=True,
        ).strip(),
    )

    assert failures == ()


def test_each_sprint2_operator_carries_immutable_introduction_provenance() -> None:
    sprint2_provenance = tuple(
        item.descriptor.provenance
        for item in registered_operators()
        if item.descriptor.provenance.introduced_at_commit
        == _SPRINT2_INTRODUCTION_COMMIT
    )
    assert tuple(provenance.operator_id for provenance in sprint2_provenance) == (
        "inject-synthetic-sensitive-summary",
        "mark-incomplete-budget-stop",
        "replay-duplicate-case-observation",
        "skew-evidence-source-identity",
    )

    for provenance in sprint2_provenance:
        assert provenance.introduced_at_commit == _SPRINT2_INTRODUCTION_COMMIT
        assert provenance.introduced_in_release == "0.6.1rc1"
        assert provenance.implementation_components
        assert provenance.introduction_components
        assert provenance.target_controls


def test_release_validation_accepts_immutable_introduction_commits() -> None:
    provenances: list[OperatorProvenance] = []
    for item in _v060_registered_operators():
        provenance = item.descriptor.provenance
        target_controls = tuple(
            target.model_copy(
                update={
                    "digest_at_operator_creation": lf_normalized_sha256(
                        _introduction_source(target_control_component_path(target.control_id))
                    )
                }
            )
            for target in provenance.target_controls
        )
        provenances.append(
            provenance.model_copy(
                update={
                    "introduced_at_commit": _INTRODUCTION_COMMIT,
                    "target_controls": target_controls,
                }
            )
        )

    expected_sources = (
        {
            (_INTRODUCTION_COMMIT, component.relative_path)
            for provenance in provenances
            for component in provenance.introduction_components
        }
        | {(_INTRODUCTION_COMMIT, "agent_assure/mutation/introduction_snapshots.json")}
        | {
            (_INTRODUCTION_COMMIT, target_control_component_path(target.control_id))
            for provenance in provenances
            for target in provenance.target_controls
        }
        | {
            (target.first_seen_commit, target_control_component_path(target.control_id))
            for provenance in provenances
            for target in provenance.target_controls
        }
    )

    requests: list[tuple[str, str]] = []

    def creation_source_loader(commit: str, relative_path: str) -> bytes:
        requests.append((commit, relative_path))
        return _introduction_source(relative_path)

    assert (
        release_provenance_failures(
            provenances,
            expected_release="0.6.0",
            release_commit=_RELEASE_COMMIT,
            creation_source_loader=creation_source_loader,
            ancestry_checker=lambda _ancestor, _descendant: True,
        )
        == ()
    )
    assert set(requests) == expected_sources
    assert len(requests) == len(expected_sources)
    assert requests[:3] == [
        (_INTRODUCTION_COMMIT, "agent_assure/mutation/introduction_snapshots.json"),
        (_INTRODUCTION_COMMIT, "agent_assure/mutation/catalog.py"),
        (_INTRODUCTION_COMMIT, "agent_assure/mutation/operators.py"),
    ]


def test_release_validation_requires_revision_source_verification() -> None:
    provenances = tuple(
        item.descriptor.provenance.model_copy(update={"introduced_at_commit": "git:" + "a" * 40})
        for item in _v060_registered_operators()
    )

    failures = release_provenance_failures(
        provenances,
        expected_release="0.6.0",
        release_commit=_RELEASE_COMMIT,
        ancestry_checker=lambda _ancestor, _descendant: True,
    )

    assert len(failures) == 9
    assert (
        sum(failure.endswith("introduction snapshot was not verified") for failure in failures) == 3
    )
    assert (
        sum(failure.endswith("first-seen declaration was not verified") for failure in failures)
        == 3
    )
    assert sum(failure.endswith("creation digest was not verified") for failure in failures) == 3


def test_release_validation_rejects_creation_digest_mismatch() -> None:
    provenance = registered_operators()[0].descriptor.provenance.model_copy(
        update={"introduced_at_commit": "git:" + "a" * 40}
    )

    target_path = target_control_component_path(provenance.target_controls[0].control_id)

    def source_loader(commit: str, relative_path: str) -> bytes:
        if commit == _INTRODUCTION_COMMIT and relative_path == target_path:
            return b"changed target control\n"
        return _introduction_source(relative_path)

    failures = release_provenance_failures(
        (provenance,),
        expected_release="0.6.0",
        release_commit=_RELEASE_COMMIT,
        creation_source_loader=source_loader,
        ancestry_checker=lambda _ancestor, _descendant: True,
    )

    assert failures == (
        f"operator {provenance.operator_id!r} target control "
        f"{provenance.target_controls[0].control_id!r} creation digest does not match "
        "the introduction commit",
    )


def test_release_validation_rejects_commit_that_predates_mutation_implementation() -> None:
    provenance = registered_operators()[0].descriptor.provenance.model_copy(
        update={"introduced_at_commit": _INTRODUCTION_COMMIT}
    )

    def pre_mutation_source_loader(_commit: str, relative_path: str) -> bytes:
        if relative_path.startswith("agent_assure/mutation/"):
            raise FileNotFoundError(relative_path)
        return _introduction_source(relative_path)

    failures = release_provenance_failures(
        (provenance,),
        expected_release="0.6.0",
        release_commit=_RELEASE_COMMIT,
        creation_source_loader=pre_mutation_source_loader,
        ancestry_checker=lambda _ancestor, _descendant: True,
    )

    assert failures == (
        f"operator {provenance.operator_id!r} authored introduction snapshot is "
        "unavailable at the introduction commit",
    )


def test_release_validation_requires_catalog_and_operator_binding_components() -> None:
    provenance = registered_operators()[0].descriptor.provenance
    provenance = provenance.model_copy(
        update={
            "introduced_at_commit": _INTRODUCTION_COMMIT,
            "introduction_components": tuple(
                component
                for component in provenance.introduction_components
                if component.relative_path != "agent_assure/mutation/catalog.py"
            ),
        }
    )

    failures = release_provenance_failures(
        (provenance,),
        expected_release="0.6.0",
        release_commit=_RELEASE_COMMIT,
        creation_source_loader=lambda _commit, relative_path: _introduction_source(relative_path),
        ancestry_checker=lambda _ancestor, _descendant: True,
    )

    assert failures == (
        f"operator {provenance.operator_id!r} introduction snapshot does not bind "
        "'agent_assure/mutation/catalog.py'",
    )


def test_release_validation_rejects_rewritten_introduction_snapshot() -> None:
    provenance = _release_ready_provenance()
    changed_snapshot = tuple(
        component.model_copy(update={"sha256": "0" * 64})
        if component.relative_path == "agent_assure/mutation/catalog.py"
        else component
        for component in provenance.introduction_components
    )
    provenance = provenance.model_copy(update={"introduction_components": changed_snapshot})

    failures = release_provenance_failures(
        (provenance,),
        expected_release="0.6.0",
        release_commit=_RELEASE_COMMIT,
        creation_source_loader=lambda _commit, relative_path: _introduction_source(relative_path),
        ancestry_checker=lambda _ancestor, _descendant: True,
    )

    assert failures == (
        f"operator {provenance.operator_id!r} introduction components do not match "
        "the snapshot authored at introduction",
    )


def test_later_release_accepts_evolved_current_implementation() -> None:
    provenance = _release_ready_provenance(introduced_in_release="0.6.0")
    evolved_source = b"later catalog implementation\n"
    evolved_components = tuple(
        component.model_copy(
            update={
                "sha256": implementation_component_sha256(
                    component.relative_path,
                    evolved_source,
                )
            }
        )
        if component.relative_path == "agent_assure/mutation/catalog.py"
        else component
        for component in provenance.implementation_components
    )
    evolved = OperatorProvenance.model_validate(
        {
            **provenance.model_dump(mode="json"),
            "implementation_components": [
                component.model_dump(mode="json") for component in evolved_components
            ],
            "implementation_digest": mutation_implementation_digest(
                operator_id=provenance.operator_id,
                operator_version=provenance.operator_version,
                components=evolved_components,
            ),
        }
    )

    introduction_catalog = next(
        component
        for component in evolved.introduction_components
        if component.relative_path == "agent_assure/mutation/catalog.py"
    )
    current_catalog = next(
        component
        for component in evolved.implementation_components
        if component.relative_path == "agent_assure/mutation/catalog.py"
    )
    assert introduction_catalog.sha256 != current_catalog.sha256
    assert (
        release_provenance_failures(
            (evolved,),
            expected_release="0.7.0",
            release_commit=_RELEASE_COMMIT,
            creation_source_loader=lambda _commit, relative_path: _introduction_source(
                relative_path
            ),
            ancestry_checker=lambda _ancestor, _descendant: True,
        )
        == ()
    )


def test_release_validation_rejects_future_introduction_release() -> None:
    provenance = _release_ready_provenance(introduced_in_release="0.7.0")

    failures = release_provenance_failures(
        (provenance,),
        expected_release="0.6.0",
        release_commit=_RELEASE_COMMIT,
        creation_source_loader=lambda _commit, relative_path: _introduction_source(relative_path),
        ancestry_checker=lambda _ancestor, _descendant: True,
    )

    assert failures == (
        f"operator {provenance.operator_id!r} introduction release '0.7.0' "
        "is newer than expected release '0.6.0'",
    )


def test_release_validation_rejects_introduction_outside_release_ancestry() -> None:
    provenance = _release_ready_provenance()

    def ancestry_checker(ancestor: str, descendant: str) -> bool:
        return (ancestor, descendant) != (_INTRODUCTION_COMMIT, _RELEASE_COMMIT)

    failures = release_provenance_failures(
        (provenance,),
        expected_release="0.6.0",
        release_commit=_RELEASE_COMMIT,
        creation_source_loader=lambda _commit, relative_path: _introduction_source(relative_path),
        ancestry_checker=ancestry_checker,
    )

    assert failures == (
        f"operator {provenance.operator_id!r} introduction commit is not an ancestor "
        "of the release commit",
    )


def test_release_validation_rejects_first_seen_commit_after_introduction() -> None:
    provenance = _release_ready_provenance()
    first_seen = provenance.target_controls[0].first_seen_commit

    def ancestry_checker(ancestor: str, descendant: str) -> bool:
        return (ancestor, descendant) != (first_seen, _INTRODUCTION_COMMIT)

    failures = release_provenance_failures(
        (provenance,),
        expected_release="0.6.0",
        release_commit=_RELEASE_COMMIT,
        creation_source_loader=lambda _commit, relative_path: _introduction_source(relative_path),
        ancestry_checker=ancestry_checker,
    )

    assert failures == (
        f"operator {provenance.operator_id!r} target control "
        f"{provenance.target_controls[0].control_id!r} first-seen commit is not an "
        "ancestor of the operator introduction commit",
    )


def test_release_validation_rejects_first_seen_source_without_control_declaration() -> None:
    provenance = next(
        item.descriptor.provenance
        for item in registered_operators()
        if item.descriptor.operator_id == "skew-evidence-source-identity"
    )
    provenance, simulated_sources = _simulated_stamped_provenance(
        provenance,
        first_seen_commit=_PRE_EVIDENCE_PROVENANCE_COMMIT,
    )
    current_requests: list[tuple[str, str]] = []

    def source_loader(commit: str, relative_path: str) -> bytes:
        if commit == _PRE_EVIDENCE_PROVENANCE_COMMIT:
            return _git_creation_source(commit, relative_path)
        return _frozen_source_loader(
            current_requests,
            simulated_sources,
            commit,
            relative_path,
        )

    failures = release_provenance_failures(
        (provenance,),
        expected_release="0.6.1",
        release_commit=_RELEASE_COMMIT,
        creation_source_loader=source_loader,
        ancestry_checker=lambda _ancestor, _descendant: True,
    )

    assert failures == (
        "operator 'skew-evidence-source-identity' target control "
        "'evidence_provenance_identity' is not declared by an exact ControlResult "
        "control_id keyword literal in mapped function "
        "'evaluate_evidence_provenance_identity' at the first-seen commit",
    )


@pytest.mark.parametrize(
    ("first_seen_source", "expected_suffix"),
    (
        pytest.param(
            None,
            "source is unavailable at the first-seen commit",
            id="unavailable",
        ),
        pytest.param(
            b"ControlResult(control_id=\n",
            "source is unparseable at the first-seen commit",
            id="unparseable",
        ),
        pytest.param(
            b'CONTROL = "human_review_required"\nControlResult(control_id=CONTROL)\n',
            "is not declared by an exact ControlResult control_id keyword literal in "
            "mapped function 'evaluate_human_review_requirement' at the first-seen commit",
            id="nonliteral",
        ),
        pytest.param(
            b'def evaluate_human_review_requirement():\n    return ()\n\n'
            b'decoy(control_id="human_review_required")\n',
            "is not declared by an exact ControlResult control_id keyword literal in "
            "mapped function 'evaluate_human_review_requirement' at the first-seen commit",
            id="decoy-call",
        ),
        pytest.param(
            b'def evaluate_human_review_requirement():\n    return ()\n\n'
            b'def unrelated():\n    return ControlResult('
            b'control_id="human_review_required")\n',
            "is not declared by an exact ControlResult control_id keyword literal in "
            "mapped function 'evaluate_human_review_requirement' at the first-seen commit",
            id="wrong-function",
        ),
        pytest.param(
            b'def evaluate_human_review_requirement():\n    if False:\n'
            b'        return ControlResult(control_id="human_review_required")\n'
            b'    return ()\n',
            "is not declared by an exact ControlResult control_id keyword literal in "
            "mapped function 'evaluate_human_review_requirement' at the first-seen commit",
            id="dead-branch",
        ),
        pytest.param(
            b'def evaluate_human_review_requirement():\n    return ()\n'
            b'    ControlResult(control_id="human_review_required")\n',
            "is not declared by an exact ControlResult control_id keyword literal in "
            "mapped function 'evaluate_human_review_requirement' at the first-seen commit",
            id="after-return",
        ),
    ),
)
def test_release_validation_fails_closed_for_invalid_first_seen_source(
    first_seen_source: bytes | None,
    expected_suffix: str,
) -> None:
    provenance = _release_ready_provenance()
    target = provenance.target_controls[0]
    target_path = target_control_component_path(target.control_id)

    def source_loader(commit: str, relative_path: str) -> bytes:
        if commit == target.first_seen_commit and relative_path == target_path:
            if first_seen_source is None:
                raise FileNotFoundError(relative_path)
            return first_seen_source
        return _introduction_source(relative_path)

    failures = release_provenance_failures(
        (provenance,),
        expected_release="0.6.0",
        release_commit=_RELEASE_COMMIT,
        creation_source_loader=source_loader,
        ancestry_checker=lambda _ancestor, _descendant: True,
    )

    assert failures == (
        f"operator {provenance.operator_id!r} target control {target.control_id!r} "
        f"{expected_suffix}",
    )


def test_release_validation_requires_a_concrete_expected_release() -> None:
    with pytest.raises(ValueError, match="invalid expected release version"):
        release_provenance_failures((), expected_release="current")


@pytest.mark.parametrize(
    ("introduced_in_release", "expected_release"),
    (
        ("0.5.0", "0.6.0"),
        ("0.6.0", "0.6.1"),
        ("0.6.0", "0.7.0"),
        ("0.6.0rc1", "0.6.0rc2"),
        ("0.6.0rc2", "0.6.0"),
    ),
)
def test_release_validation_accepts_historical_introduction_release(
    introduced_in_release: str,
    expected_release: str,
) -> None:
    provenance = _release_ready_provenance(introduced_in_release=introduced_in_release)

    assert (
        release_provenance_failures(
            (provenance,),
            expected_release=expected_release,
            release_commit=_RELEASE_COMMIT,
            creation_source_loader=lambda _commit, relative_path: _introduction_source(
                relative_path
            ),
            ancestry_checker=lambda _ancestor, _descendant: True,
        )
        == ()
    )


def test_stable_introduction_is_newer_than_release_candidate() -> None:
    provenance = _release_ready_provenance(introduced_in_release="0.6.0")

    failures = release_provenance_failures(
        (provenance,),
        expected_release="0.6.0rc2",
        release_commit=_RELEASE_COMMIT,
        creation_source_loader=lambda _commit, relative_path: _introduction_source(relative_path),
        ancestry_checker=lambda _ancestor, _descendant: True,
    )

    assert failures == (
        f"operator {provenance.operator_id!r} introduction release '0.6.0' is newer "
        "than expected release '0.6.0rc2'",
    )


def test_git_creation_source_maps_package_and_schema_components_from_repo_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[tuple[Path, str, str]] = []

    def fake_git_file_bytes(
        project_root: Path,
        revision: str,
        repository_path: str,
    ) -> bytes:
        requests.append((project_root, revision, repository_path))
        return b"component\n"

    monkeypatch.setattr(
        "scripts.check_mutation_release_provenance.git_file_bytes",
        fake_git_file_bytes,
    )

    assert _git_creation_source(_INTRODUCTION_COMMIT, "agent_assure/mutation/catalog.py")
    assert _git_creation_source(
        _INTRODUCTION_COMMIT,
        "schemas/v0.6.0/run-set.schema.json",
    )
    assert requests == [
        (_REPOSITORY_ROOT, "a" * 40, "src/agent_assure/mutation/catalog.py"),
        (_REPOSITORY_ROOT, "a" * 40, "schemas/v0.6.0/run-set.schema.json"),
    ]


def test_release_bundle_fails_before_creating_output_with_invalid_provenance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    out = tmp_path / "release"
    monkeypatch.setattr(
        "scripts.build_release_bundle.registered_release_provenance_failures",
        lambda **_kwargs: ("operator provenance is incomplete",),
    )

    assert not out.exists()
    assert (
        build_release_bundle(
            [
                "--expected-release",
                "0.6.0",
                "--out",
                str(out),
                "--skip-build",
            ]
        )
        == 2
    )
    assert not out.exists()
