from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

import scripts.update_process_equivalence_reproduction_index as reproduction_index_updater
from agent_assure.cli.main import app
from agent_assure.schema.export import model_for_kind
from agent_assure.schema.reproduction_index import (
    ProcessEquivalenceExpectedObservation,
    ProcessEquivalenceReproductionIndex,
    ProcessEquivalenceReproductionIndexCase,
    ProcessEquivalenceReproductionIndexReplay,
    ProcessEquivalenceReproductionIndexSourceArtifact,
    ProcessEquivalenceReproductionIndexSourceClosure,
    ProcessEquivalenceStratum,
)
from scripts.update_process_equivalence_reproduction_index import (
    SOURCE_ROOTS,
    render_updated_reproduction_index,
)

ROOT = Path(__file__).resolve().parents[3]
REPRODUCTION_INDEX_PATH = ROOT / "examples" / "process_equivalence_reproduction_index.json"
PACKAGED_REPRODUCTION_INDEX_PATH = (
    ROOT / "src" / "agent_assure" / "examples" / "process_equivalence_reproduction_index.json"
)
RUNNER = CliRunner()


def _payload() -> dict[str, object]:
    loaded = json.loads(REPRODUCTION_INDEX_PATH.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def test_committed_reproduction_index_is_self_digested_and_reproducible() -> None:
    reproduction_index = ProcessEquivalenceReproductionIndex.model_validate(_payload())

    assert model_for_kind(reproduction_index.artifact_kind) is ProcessEquivalenceReproductionIndex
    assert {item.stratum for item in reproduction_index.cases} == set(ProcessEquivalenceStratum)
    assert reproduction_index.leaderboard_supported is False
    assert reproduction_index.prevalence_claim_supported is False
    assert reproduction_index.real_model_measurement is False
    assert PACKAGED_REPRODUCTION_INDEX_PATH.read_bytes() == REPRODUCTION_INDEX_PATH.read_bytes()
    for case in reproduction_index.cases:
        assert case.source_closure.source_root == SOURCE_ROOTS[case.stratum]
        assert case.subject_designation == "synthetic_detector_contract_test"
        expected_entries = _source_entries(case.source_closure.source_root)
        assert case.source_closure.entries == expected_entries
        assert "__pycache__" not in {
            part for item in case.source_closure.entries for part in Path(item.path).parts
        }
        assert all(Path(item.path).suffix != ".pyc" for item in case.source_closure.entries)
        for source in case.source_artifacts:
            path = ROOT / source.path
            assert path.is_file(), source.path
            assert hashlib.sha256(path.read_bytes()).hexdigest() == source.sha256
            relative = path.relative_to(ROOT / case.source_closure.source_root).as_posix()
            closure_entry = {item.path: item.sha256 for item in case.source_closure.entries}[
                relative
            ]
            assert closure_entry == source.sha256


def test_updater_reproduces_committed_reproduction_index_exactly() -> None:
    assert render_updated_reproduction_index(
        REPRODUCTION_INDEX_PATH
    ) == REPRODUCTION_INDEX_PATH.read_text(encoding="utf-8")


def test_updater_walks_each_stratum_source_root_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _payload()
    cases = cast(list[dict[str, Any]], payload["cases"])
    repeated_case = cast(dict[str, Any], json.loads(json.dumps(cases[0])))
    repeated_case["case_id"] = "evidence-insensitivity-authority-flip-repeat"
    cases.insert(1, repeated_case)
    path = tmp_path / "repeated-stratum.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    original = reproduction_index_updater.build_source_closure
    calls: list[str] = []

    def tracked_build_source_closure(
        repository_root: Path,
        source_root: str,
    ) -> ProcessEquivalenceReproductionIndexSourceClosure:
        calls.append(source_root)
        return original(repository_root, source_root)

    monkeypatch.setattr(
        reproduction_index_updater,
        "build_source_closure",
        tracked_build_source_closure,
    )

    render_updated_reproduction_index(path)

    assert calls == sorted(set(SOURCE_ROOTS.values()))


def test_updater_rejects_excess_cases_before_walking_sources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _payload()
    cases = cast(list[dict[str, Any]], payload["cases"])
    payload["cases"] = [cases[0] for _ in range(257)]
    path = tmp_path / "oversized-index.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    def unexpected_source_walk(
        _repository_root: Path,
        _source_root: str,
    ) -> ProcessEquivalenceReproductionIndexSourceClosure:
        raise AssertionError("source closure was walked before case-count validation")

    monkeypatch.setattr(
        reproduction_index_updater,
        "build_source_closure",
        unexpected_source_walk,
    )

    with pytest.raises(ValueError, match="between 2 and 256"):
        render_updated_reproduction_index(path)


def test_reproduction_index_freshness_is_wired_into_ci_and_release_checks() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    ci_workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    publish_workflow = (ROOT / ".github" / "workflows" / "publish-testpypi.yml").read_text(
        encoding="utf-8"
    )

    assert "reproduction-index-check:" in makefile
    assert "scripts/update_process_equivalence_reproduction_index.py" in makefile
    assert "reproduction-index-check" in makefile[makefile.index("check:") :]
    assert "make release-check" in ci_workflow
    assert publish_workflow.count("make release-publish-check") == 2


def test_source_closure_enforces_file_and_byte_limits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "examples" / "bounded"
    source.mkdir(parents=True)
    (source / "one.txt").write_text("a", encoding="utf-8")
    (source / "two.txt").write_text("b", encoding="utf-8")
    monkeypatch.setattr(reproduction_index_updater, "MAX_SOURCE_FILES", 1)

    with pytest.raises(ValueError, match="file limit"):
        reproduction_index_updater.build_source_closure(tmp_path, "examples/bounded")

    monkeypatch.setattr(reproduction_index_updater, "MAX_SOURCE_FILES", 4096)
    monkeypatch.setattr(reproduction_index_updater, "MAX_SOURCE_FILE_BYTES", 0)
    with pytest.raises(ValueError, match="source file exceeds"):
        reproduction_index_updater.build_source_closure(tmp_path, "examples/bounded")


def test_source_closure_streamingly_bounds_all_directory_entries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "examples" / "bounded"
    source.mkdir(parents=True)
    for index in range(3):
        (source / f"ignored-{index}.pyc").write_bytes(b"")
    monkeypatch.setattr(reproduction_index_updater, "MAX_SOURCE_TREE_ENTRIES", 2)

    with pytest.raises(ValueError, match="tree entry limit 2"):
        reproduction_index_updater.build_source_closure(tmp_path, "examples/bounded")


def test_source_closure_rejects_linked_files(
    tmp_path: Path,
) -> None:
    source = tmp_path / "examples" / "bounded"
    source.mkdir(parents=True)
    target = tmp_path / "outside.txt"
    target.write_text("outside", encoding="utf-8")
    linked = source / "linked.txt"
    try:
        linked.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")

    with pytest.raises(ValueError, match="refuses links"):
        reproduction_index_updater.build_source_closure(tmp_path, "examples/bounded")


def test_updater_enforces_the_repository_stratum_root_mapping(tmp_path: Path) -> None:
    payload = _payload()
    cases = cast(list[dict[str, Any]], payload["cases"])
    closure = cast(dict[str, Any], cases[0]["source_closure"])
    closure["source_root"] = "portable/relocated-detector-contract"
    path = tmp_path / "relocated.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    updated = json.loads(render_updated_reproduction_index(path))
    updated_cases = cast(list[dict[str, Any]], updated["cases"])

    assert [
        cast(dict[str, Any], case["source_closure"])["source_root"] for case in updated_cases
    ] == [SOURCE_ROOTS[ProcessEquivalenceStratum(str(case["stratum"]))] for case in updated_cases]


def test_cli_validates_the_reproduction_index_kind() -> None:
    result = RUNNER.invoke(
        app,
        [
            "validate",
            str(REPRODUCTION_INDEX_PATH),
            "--kind",
            "process-equivalence-reproduction-index",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "valid process-equivalence-reproduction-index" in result.output


def test_updater_write_self_heals_stale_source_artifact_digest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _payload()
    cases = cast(list[dict[str, Any]], payload["cases"])
    sources = cast(list[dict[str, Any]], cases[0]["source_artifacts"])
    expected_sha256 = sources[0]["sha256"]
    sources[0]["sha256"] = "0" * 64
    public_path = tmp_path / "public.json"
    packaged_path = tmp_path / "packaged.json"
    public_path.write_text(json.dumps(payload), encoding="utf-8")
    packaged_path.write_text("stale", encoding="utf-8")
    monkeypatch.setattr(
        reproduction_index_updater,
        "PUBLIC_REPRODUCTION_INDEX",
        public_path,
    )
    monkeypatch.setattr(
        reproduction_index_updater,
        "PACKAGED_REPRODUCTION_INDEX",
        packaged_path,
    )

    assert reproduction_index_updater.main(["--write"]) == 0

    repaired = json.loads(public_path.read_text(encoding="utf-8"))
    repaired_cases = cast(list[dict[str, Any]], repaired["cases"])
    repaired_sources = cast(
        list[dict[str, Any]],
        repaired_cases[0]["source_artifacts"],
    )
    assert repaired_sources[0]["sha256"] == expected_sha256
    assert packaged_path.read_bytes() == public_path.read_bytes()
    ProcessEquivalenceReproductionIndex.model_validate(repaired)


def test_committed_index_cases_execute_and_reproduce_expected_observations(
    tmp_path: Path,
) -> None:
    reproduction_index = ProcessEquivalenceReproductionIndex.model_validate(_payload())

    for case in reproduction_index.cases:
        replay = case.replay
        result = RUNNER.invoke(
            app,
            [
                replay.command,
                replay.demo,
                "--out",
                str(tmp_path / case.case_id),
                "--clean",
                "--format",
                replay.output_format,
            ],
        )
        assert result.exit_code == replay.expected_exit_code, result.output
        summary = json.loads(result.output)
        assert isinstance(summary, dict)
        _assert_expected_observation(
            cast(dict[str, Any], summary),
            replay.expected_observation,
        )


def test_process_equivalence_reproduction_index_rejects_tampering() -> None:
    payload = _payload()
    limitations = payload["limitations"]
    assert isinstance(limitations, list)
    limitations[0] = "Tampered but structurally valid limitation."

    with pytest.raises(ValidationError, match="reproduction_index_digest"):
        ProcessEquivalenceReproductionIndex.model_validate(payload)


def test_process_equivalence_reproduction_index_requires_both_strata() -> None:
    reproduction_index = ProcessEquivalenceReproductionIndex.model_validate(_payload())
    evidence_case = reproduction_index.cases[0]
    second_evidence_case = evidence_case.model_copy(
        update={"case_id": "second-evidence-insensitivity-case"}
    )

    with pytest.raises(ValidationError, match="every required process-equivalence stratum"):
        ProcessEquivalenceReproductionIndex.build(
            cases=(evidence_case, second_evidence_case),
            limitations=reproduction_index.limitations,
        )


def test_index_source_artifacts_reject_noncanonical_path_traversal() -> None:
    with pytest.raises(ValidationError, match="unsafe path segments"):
        ProcessEquivalenceReproductionIndexSourceArtifact(
            path="examples/../pyproject.toml",
            sha256="0" * 64,
        )


def test_index_source_closure_rejects_digest_forgery() -> None:
    entry = ProcessEquivalenceReproductionIndexSourceArtifact(
        path="fixture.json",
        sha256="1" * 64,
    )

    with pytest.raises(ValidationError, match="closure digest"):
        ProcessEquivalenceReproductionIndexSourceClosure(
            source_root="examples/evidence_sensitivity",
            closure_digest="0" * 64,
            entries=(entry,),
        )


def test_index_case_requires_anchors_to_resolve_inside_full_closure() -> None:
    reproduction_index = ProcessEquivalenceReproductionIndex.model_validate(_payload())
    case = reproduction_index.cases[0]
    anchored_path = case.source_artifacts[0].path.removeprefix(
        case.source_closure.source_root + "/"
    )
    closure = ProcessEquivalenceReproductionIndexSourceClosure.build(
        source_root=case.source_closure.source_root,
        entries=tuple(item for item in case.source_closure.entries if item.path != anchored_path),
    )
    payload = case.model_dump(mode="json")
    payload["source_closure"] = closure.model_dump(mode="json")

    with pytest.raises(ValidationError, match="anchors must resolve exactly"):
        ProcessEquivalenceReproductionIndexCase.model_validate(payload)


def test_index_case_schema_accepts_a_portable_relocated_source_root() -> None:
    reproduction_index = ProcessEquivalenceReproductionIndex.model_validate(_payload())
    case = reproduction_index.cases[0]
    payload = case.model_dump(mode="json")
    original_root = case.source_closure.source_root
    relocated_root = "portable/detector-contract"
    closure = cast(dict[str, object], payload["source_closure"])
    closure["source_root"] = relocated_root
    sources = cast(list[dict[str, object]], payload["source_artifacts"])
    for source in sources:
        path = source["path"]
        assert isinstance(path, str)
        source["path"] = path.replace(original_root, relocated_root, 1)

    relocated = ProcessEquivalenceReproductionIndexCase.model_validate(payload)

    assert relocated.source_closure.source_root == relocated_root
    assert all(item.path.startswith(f"{relocated_root}/") for item in relocated.source_artifacts)


def test_index_replay_uses_a_closed_demo_vocabulary() -> None:
    with pytest.raises(ValidationError, match="Input should be"):
        ProcessEquivalenceReproductionIndexReplay.model_validate(
            {
                "demo": "command-that-does-not-exist",
                "expected_observation": "evidence_insensitivity_blocked",
            }
        )


def _assert_expected_observation(
    summary: dict[str, Any],
    observation: ProcessEquivalenceExpectedObservation,
) -> None:
    if observation is ProcessEquivalenceExpectedObservation.evidence_insensitivity_blocked:
        experiments = cast(dict[str, dict[str, Any]], summary["experiments"])
        inertial = experiments["evidence_inertial"]
        assert summary["expected_behavior_observed"] is True
        assert inertial["state"] == "evidence_insensitive"
        assert inertial["gate_effect"] == "block"
        assert inertial["evidence_prerequisites"] == "pass"
        assert inertial["arm_evaluations"] == "pass"
        return
    assert observation is (
        ProcessEquivalenceExpectedObservation.same_output_different_process_detected
    )
    process = cast(dict[str, Any], summary["process_regression"])
    assert summary["output_equivalence"] == "preserved"
    assert summary["expected_regression_caught"] is True
    assert process["candidate_state"] == "fail"
    assert process["missing_evidence_links"] == ["claim-duration"]


def _source_entries(
    source_root: str,
) -> tuple[ProcessEquivalenceReproductionIndexSourceArtifact, ...]:
    root = ROOT / source_root
    entries: list[ProcessEquivalenceReproductionIndexSourceArtifact] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        relative = path.relative_to(root)
        if "__pycache__" in relative.parts or relative.suffix == ".pyc":
            continue
        assert not path.is_symlink(), relative
        if path.is_dir():
            continue
        assert path.is_file(), relative
        entries.append(
            ProcessEquivalenceReproductionIndexSourceArtifact(
                path=relative.as_posix(),
                sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
            )
        )
    return tuple(entries)
