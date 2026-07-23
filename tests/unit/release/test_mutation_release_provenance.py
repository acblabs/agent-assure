from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from agent_assure.mutation.catalog import (
    implementation_component_sha256,
    lf_normalized_sha256,
    registered_operators,
    target_control_component_path,
)
from agent_assure.schema.mutation import (
    OperatorProvenance,
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
_REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


def _introduction_source(relative_path: str) -> bytes:
    return _git_creation_source(_AUTHORED_INTRODUCTION_COMMIT, relative_path)


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


def test_registered_operator_provenance_replays_at_introduction_commit() -> None:
    failures = registered_release_provenance_failures(
        expected_release="0.6.0",
        release_commit="git:" + subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=_REPOSITORY_ROOT,
            text=True,
        ).strip(),
    )

    assert failures == ()


def test_release_validation_accepts_immutable_introduction_commits() -> None:
    provenances: list[OperatorProvenance] = []
    for item in registered_operators():
        provenance = item.descriptor.provenance
        target_controls = tuple(
            target.model_copy(
                update={
                    "digest_at_operator_creation": lf_normalized_sha256(
                        _introduction_source(
                            target_control_component_path(target.control_id)
                        )
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

    expected_paths = {
        component.relative_path
        for provenance in provenances
        for component in provenance.introduction_components
    } | {"agent_assure/mutation/introduction_snapshots.json"} | {
        target_control_component_path(target.control_id)
        for provenance in provenances
        for target in provenance.target_controls
    }

    requests: list[tuple[str, str]] = []

    def creation_source_loader(commit: str, relative_path: str) -> bytes:
        assert commit == _INTRODUCTION_COMMIT
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
    assert {path for _, path in requests} == expected_paths
    assert len(requests) == len(expected_paths)
    assert requests[:3] == [
        (_INTRODUCTION_COMMIT, "agent_assure/mutation/introduction_snapshots.json"),
        (_INTRODUCTION_COMMIT, "agent_assure/mutation/catalog.py"),
        (_INTRODUCTION_COMMIT, "agent_assure/mutation/operators.py"),
    ]


def test_release_validation_requires_revision_source_verification() -> None:
    provenances = tuple(
        item.descriptor.provenance.model_copy(update={"introduced_at_commit": "git:" + "a" * 40})
        for item in registered_operators()
    )

    failures = release_provenance_failures(
        provenances,
        expected_release="0.6.0",
        release_commit=_RELEASE_COMMIT,
        ancestry_checker=lambda _ancestor, _descendant: True,
    )

    assert len(failures) == 6
    assert sum(
        failure.endswith("introduction snapshot was not verified")
        for failure in failures
    ) == 3
    assert sum(failure.endswith("creation digest was not verified") for failure in failures) == 3


def test_release_validation_rejects_creation_digest_mismatch() -> None:
    provenance = registered_operators()[0].descriptor.provenance.model_copy(
        update={"introduced_at_commit": "git:" + "a" * 40}
    )

    target_path = target_control_component_path(provenance.target_controls[0].control_id)

    def source_loader(_commit: str, relative_path: str) -> bytes:
        if relative_path == target_path:
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
        creation_source_loader=lambda _commit, relative_path: _introduction_source(
            relative_path
        ),
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
    provenance = provenance.model_copy(
        update={"introduction_components": changed_snapshot}
    )

    failures = release_provenance_failures(
        (provenance,),
        expected_release="0.6.0",
        release_commit=_RELEASE_COMMIT,
        creation_source_loader=lambda _commit, relative_path: _introduction_source(
            relative_path
        ),
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
        creation_source_loader=lambda _commit, relative_path: _introduction_source(
            relative_path
        ),
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
        creation_source_loader=lambda _commit, relative_path: _introduction_source(
            relative_path
        ),
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
        creation_source_loader=lambda _commit, relative_path: _introduction_source(
            relative_path
        ),
        ancestry_checker=ancestry_checker,
    )

    assert failures == (
        f"operator {provenance.operator_id!r} target control "
        f"{provenance.target_controls[0].control_id!r} first-seen commit is not an "
        "ancestor of the operator introduction commit",
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
    provenance = _release_ready_provenance(
        introduced_in_release=introduced_in_release
    )

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
        creation_source_loader=lambda _commit, relative_path: _introduction_source(
            relative_path
        ),
        ancestry_checker=lambda _ancestor, _descendant: True,
    )

    assert failures == (
        f"operator {provenance.operator_id!r} introduction release '0.6.0' is newer "
        "than expected release '0.6.0rc2'",
    )


def test_git_creation_source_maps_package_and_schema_components_from_repo_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[list[str]] = []

    def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        requests.append(args)
        return subprocess.CompletedProcess(args, 0, stdout=b"component\n", stderr=b"")

    monkeypatch.setattr(
        "scripts.check_mutation_release_provenance.subprocess.run",
        fake_run,
    )

    assert _git_creation_source(_INTRODUCTION_COMMIT, "agent_assure/mutation/catalog.py")
    assert _git_creation_source(
        _INTRODUCTION_COMMIT,
        "schemas/v0.6.0/run-set.schema.json",
    )
    assert requests == [
        ["git", "show", f"{'a' * 40}:src/agent_assure/mutation/catalog.py"],
        ["git", "show", f"{'a' * 40}:schemas/v0.6.0/run-set.schema.json"],
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
