"""Host composition tests; ephemeral authorities and collectors are synthetic.

The signing tests use fresh test-only OpenSSH keys, not the maintainer's key.
These tests exercise real signatures and file/Git boundaries where practical;
their fake runtime/source collectors do not establish frozen-host acceptance.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import v1_architecture_governance as architecture  # noqa: E402
from scripts import v1_s1_governance as legacy  # noqa: E402
from scripts import v1_s1_successor as core  # noqa: E402
from scripts import v1_successor_checks as checks  # noqa: E402
from scripts import v1_successor_ci as ci  # noqa: E402
from scripts import v1_successor_host as host  # noqa: E402
from scripts import v1_successor_io as io  # noqa: E402

NOW = datetime(2026, 11, 7, 12, tzinfo=UTC)
DIGEST = "sha256:" + "a" * 64


@pytest.fixture(autouse=True)
def _synthetic_powershell_on_nonwindows(monkeypatch: pytest.MonkeyPatch) -> None:
    if os.name != "nt":
        # Hosted Linux tests exercise composition, never claim a Windows host.
        monkeypatch.setattr(
            host,
            "powershell_identity",
            lambda: {
                "path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "size_bytes": 1,
                "sha256": DIGEST,
            },
        )


@pytest.fixture
def public_root(tmp_path: Path) -> Path:
    """Only public source/schema inputs; no private roadmap or prior acceptance."""
    root = tmp_path / "repository"
    root.mkdir()
    paths = set(host.BOOTSTRAP_FILES) | {
        "Makefile",
        ".github/workflows/ci.yml",
        "docs/governance/v1/delivery-forecast.estimation-catalog.json",
    }
    for relative in paths:
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / relative).read_bytes())
    for _, _, relative in host.DECISIONS:
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / relative).read_bytes())
    return root


def _profile() -> dict[str, Any]:
    return {
        "person_id": host.ROOT_PERSON,
        "key_id": io.public_key_fingerprint(host.ROOT_PUBLIC_KEY),
        "public_key": host.ROOT_PUBLIC_KEY,
        "competence_scopes": ["planning_governance:s1_successor", "schema_compatibility"],
        "conflicts": ["Synthetic single-person development acceptance; not independent"],
        "review_capacity": "Synthetic test-only declared capacity",
        "valid_from_utc": "2026-11-07T00:00:00Z",
        "valid_until_utc": "2026-11-17T00:00:00Z",
        "mode": "maintainer_development",
        "independence": "NO_INDEPENDENT_REVIEW",
        "roles": ["repository_maintainer", "technical_lead"],
    }


@pytest.mark.parametrize(
    "raw",
    [b'{"x":1,"x":2}', b'{"x":3.0}', b'{"x":NaN}', b'{"x":Infinity}', b"[]", b"\xff", b'{"x":'],
)
def test_host_json_rejects_ambiguous_or_unsupported_inputs(raw: bytes) -> None:
    with pytest.raises(core.SuccessorError):
        host.parse_json(raw)


def test_host_json_depth_is_bounded_before_recursive_parsing() -> None:
    with pytest.raises(core.SuccessorError, match="nesting"):
        host.parse_json(b'{"x":' * 50 + b"0" + b"}" * 50)


def test_host_json_retains_exact_integer_and_string_semantics() -> None:
    assert host.parse_json(b'{"x":3,"label":"abc"}') == {"x": 3, "label": "abc"}


def test_pinned_private_publication_is_no_clobber(tmp_path: Path) -> None:
    path = host.PRIVATE_PREFIX + "run-001/record.json"
    host.write_new(tmp_path, path, b"exact original")
    with pytest.raises((FileExistsError, OSError)):
        host.write_new(tmp_path, path, b"replacement")
    assert host.read_bytes(tmp_path, path) == b"exact original"


@pytest.mark.parametrize(
    "path",
    [
        "../outside.json",
        ".tmp/outside.json",
        host.PRIVATE_PREFIX + "run/../escape.json",
        host.PRIVATE_PREFIX + "run//escape.json",
    ],
)
def test_host_outputs_cannot_leave_the_owned_namespace(tmp_path: Path, path: str) -> None:
    with pytest.raises((core.SuccessorError, OSError, ValueError)):
        host.write_new(tmp_path, path, b"value")


def test_host_output_limit_is_explicit_and_does_not_create_a_partial_file(tmp_path: Path) -> None:
    path = host.PRIVATE_PREFIX + "run-001/record.json"
    with pytest.raises(core.SuccessorError, match="byte"):
        host.write_new(tmp_path, path, b"x" * (host.MAX_BYTES + 1))
    assert not (tmp_path / path).exists()


def test_host_binary_log_profile_keeps_json_limit_separate(tmp_path: Path) -> None:
    data = b"x" * (host.MAX_BYTES + 1)
    path = host.PRIVATE_PREFIX + "run-001/child.stdout.bin"
    host.write_new(tmp_path, path, data, maximum=16 * 1024 * 1024)
    assert host.read_bytes(tmp_path, path, maximum=16 * 1024 * 1024) == data


def _symlink(target: Path, link: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=target.is_dir())
    except (OSError, NotImplementedError):
        pytest.skip("this host does not permit creating synthetic symlinks")


def test_linked_private_parent_never_receives_output(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    root = tmp_path / "root"
    root.mkdir()
    (root / ".tmp/s1-acceptance").mkdir(parents=True)
    _symlink(outside, root / ".tmp/s1-acceptance/successor-v3")
    with pytest.raises((core.SuccessorError, OSError, ValueError)):
        host.write_new(root, host.PRIVATE_PREFIX + "run-001/record.json", b"secret")
    assert not list(outside.iterdir())


def test_bootstrap_binds_every_module_policy_workflow_and_expansion(public_root: Path) -> None:
    claim = host.prepare_bootstrap(public_root, _profile(), now=NOW)
    policy = host.validate_bootstrap_claim(public_root, claim, NOW)
    assert claim["policy_digest"] == core.successor_policy_digest(policy)
    assert {row["path"] for row in claim["implementation_inventory"]} == set(host.BOOTSTRAP_FILES)
    assert claim["trust"]["capture_repository_root"] == str(public_root.absolute())
    assert claim["actual_signature_time_claimed"] is False
    assert claim["exclusions"] == [
        "no_independent_review",
        "no_method_admission",
        "no_runtime_or_release_authorization",
    ]
    assert b"signature_envelope" not in host.bootstrap_claim_bytes(claim)


@pytest.mark.parametrize(
    "relative",
    [
        "scripts/v1_successor_host.py",
        "scripts/v1_s1_successor.py",
        ".github/workflows/ci.yml",
        "Makefile",
        host.CORE_SCHEMA,
    ],
)
def test_bootstrap_refuses_code_schema_workflow_or_graph_drift(
    public_root: Path, relative: str
) -> None:
    claim = host.prepare_bootstrap(public_root, _profile(), now=NOW)
    target = public_root / relative
    target.write_bytes(target.read_bytes() + b"\n ")
    with pytest.raises(core.SuccessorError):
        host.validate_bootstrap_claim(public_root, claim, NOW)


@pytest.mark.parametrize(
    "field,value",
    [
        ("mode", "qualified_admission"),
        ("independence", "INDEPENDENT"),
        ("competence_scopes", ["planning_governance:s1_successor"]),
        ("conflicts", []),
        ("review_capacity", ""),
        ("roles", ["repository_maintainer"]),
        ("public_key", "ssh-ed25519 not-the-confirmed-root"),
        ("person_id", "other-person"),
        ("valid_until_utc", "2027-11-07T00:00:00Z"),
    ],
)
def test_bootstrap_cannot_infer_authority_or_remove_development_limitations(
    public_root: Path,
    field: str,
    value: Any,
) -> None:
    profile = _profile()
    profile[field] = value
    with pytest.raises(core.SuccessorError):
        host.prepare_bootstrap(public_root, profile, now=NOW)


def test_bootstrap_creation_does_not_modify_human_profile(public_root: Path) -> None:
    profile = _profile()
    before = copy.deepcopy(profile)
    host.prepare_bootstrap(public_root, profile, now=NOW)
    assert profile == before


def test_host_refuses_accepting_operation_without_actual_bootstrap(public_root: Path) -> None:
    class Ordinary:
        @staticmethod
        def _main_has_active_runtime_bootstrap() -> bool:
            return False

    with pytest.raises(core.SuccessorError, match="frozen"):
        host.FrozenHost(Ordinary(), public_root, {}, clock=lambda: NOW)


class FakeReader:
    def resolve_commit(self, oid: str) -> core.GitCommit:
        return core.GitCommit(oid, ("b" * 40,))

    def require_ancestor(self, ancestor: str, descendant: str) -> None:
        assert ancestor != descendant


def test_evidence_registry_cannot_load_unregistered_passed_json(public_root: Path) -> None:
    claim = host.prepare_bootstrap(public_root, _profile(), now=NOW)
    boundary = host.HostBoundary(
        root=public_root,
        reader=FakeReader(),  # type: ignore[arg-type]
        key=host.trusted_key(claim),
        verify_callback=lambda **kw: None,
        policy=host.policy_from_claim(claim),
        trust=claim["trust"],
        now=lambda: NOW,
    )
    with pytest.raises(core.SuccessorError, match="not produced"):
        boundary.resolve_evidence(DIGEST, "hosted-ci")
    assert not hasattr(boundary, "register_passed_json")


def test_host_signature_cache_is_bound_to_exact_bytes_envelope_and_purpose(
    public_root: Path,
) -> None:
    claim = host.prepare_bootstrap(public_root, _profile(), now=NOW)
    boundary = host.HostBoundary(
        root=public_root,
        reader=FakeReader(),  # type: ignore[arg-type]
        key=host.trusted_key(claim),
        verify_callback=lambda **kw: None,
        policy=host.policy_from_claim(claim),
        trust=claim["trust"],
        now=lambda: NOW,
    )
    with pytest.raises(core.SuccessorError, match="cryptographically"):
        boundary.verify_signature(b"payload", {"signature": "passed"}, "s2-bundle/v1")


@pytest.fixture
def ephemeral_signer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    ssh = shutil.which("ssh-keygen")
    if ssh is None:
        pytest.skip("OpenSSH unavailable for test-only ephemeral signatures")
    executable = Path(ssh).resolve()
    raw = executable.read_bytes()
    monkeypatch.setitem(
        legacy.TRUSTED_EXECUTABLE_IDENTITIES,
        "ssh-keygen",
        legacy.TrustedExecutableIdentity(
            str(executable), len(raw), hashlib.sha256(raw).hexdigest()
        ),
    )
    key = tmp_path / "test-only-signing-key"
    subprocess.run(
        [ssh, "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True, capture_output=True
    )
    public = (key.with_suffix(".pub")).read_text().strip().split()
    public_key = " ".join(public[:2])
    monkeypatch.setattr(host, "ROOT_PUBLIC_KEY", public_key)
    counter = 0

    def sign(payload: bytes) -> dict[str, Any]:
        nonlocal counter
        counter += 1
        source = tmp_path / f"test-payload-{counter}.bin"
        source.write_bytes(payload)
        subprocess.run(
            [
                ssh,
                "-Y",
                "sign",
                "-n",
                core.SIGNATURE_NAMESPACE,
                "-f",
                str(key),
                "-O",
                "hashalg=sha512",
                str(source),
            ],
            check=True,
            capture_output=True,
        )
        armor = legacy._canonical_sshsig_armor(
            source.with_suffix(source.suffix + ".sig").read_bytes()
        )
        return {
            "profile": core.SIGNATURE_PROFILE,
            "namespace": core.SIGNATURE_NAMESPACE,
            "signer_person_id": host.ROOT_PERSON,
            "key_id": io.public_key_fingerprint(public_key),
            "signature": base64.b64encode(armor).decode(),
        }

    return sign


def test_real_ephemeral_signature_populates_only_exact_verified_cache_entry(
    public_root: Path,
    ephemeral_signer: Any,
) -> None:
    claim = host.prepare_bootstrap(public_root, _profile(), now=NOW)
    boundary = host.HostBoundary(
        root=public_root,
        reader=FakeReader(),  # type: ignore[arg-type]
        key=host.trusted_key(claim),
        verify_callback=legacy._verify_sshsig,
        policy=host.policy_from_claim(claim),
        trust=claim["trust"],
        now=lambda: NOW,
    )
    payload = b"exact human test decision"
    envelope = ephemeral_signer(payload)
    verified = boundary.preverify_signature(payload, envelope, "s2-bundle/v1")
    assert boundary.verify_signature(payload, envelope, "s2-bundle/v1") is verified
    for changed_payload, changed_envelope, purpose in (
        (payload + b"x", envelope, "s2-bundle/v1"),
        (payload, {**envelope, "key_id": "other"}, "s2-bundle/v1"),
        (payload, envelope, "s2-drafting/v1"),
    ):
        with pytest.raises(core.SuccessorError):
            boundary.verify_signature(changed_payload, changed_envelope, purpose)


def test_real_signature_is_not_a_producer_verification_boolean(
    public_root: Path,
    ephemeral_signer: Any,
) -> None:
    claim = host.prepare_bootstrap(public_root, _profile(), now=NOW)
    boundary = host.HostBoundary(
        root=public_root,
        reader=FakeReader(),  # type: ignore[arg-type]
        key=host.trusted_key(claim),
        verify_callback=legacy._verify_sshsig,
        policy=host.policy_from_claim(claim),
        trust=claim["trust"],
        now=lambda: NOW,
    )
    with pytest.raises((io.SuccessorIOError, legacy.GovernanceError)):
        boundary.preverify_signature(
            b"changed actual bytes", ephemeral_signer(b"original"), "s2-bundle/v1"
        )


class TickClock:
    def __init__(self) -> None:
        self.value = NOW

    def __call__(self) -> datetime:
        result = self.value
        self.value += timedelta(milliseconds=10)
        return result


class Pipeline:
    """Real Git/SSHSIG, synthetic frozen runtime, native suite and CI sources."""

    def __init__(self, root: Path, signer: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        git = shutil.which("git")
        if git is None:
            pytest.skip("Git unavailable for a synthetic local-object integration")
        self.root, self.signer, self.clock = root, signer, TickClock()
        self.git = git
        self.hooks = root.parent / "empty-hooks"
        self.hooks.mkdir()
        self.events: list[str] = []
        self._immutable_object_reads: dict[tuple[str, ...], subprocess.CompletedProcess[bytes]] = {}
        self.native_calls = 0
        self.checked_specs: list[str] = []
        self._git(("init", "--quiet"))
        self._git(("config", "user.name", "Synthetic Maintainer"))
        self._git(("config", "user.email", "synthetic@example.invalid"))
        self._git(("config", "commit.gpgSign", "false"))
        (root / ".gitignore").write_text(".tmp/\n", encoding="utf-8")
        (root / "notes.txt").write_text("before\n", encoding="utf-8")
        (root / "synthetic-roadmap.json").write_text(
            '{"scope":"synthetic only"}\n', encoding="utf-8", newline="\n"
        )
        monkeypatch.setattr(
            host,
            "ROADMAP_DIGEST",
            core.content_digest((root / "synthetic-roadmap.json").read_bytes()),
        )
        self.baseline = self.commit("synthetic C2 baseline")
        monkeypatch.setattr(core, "PREDECESSOR_CLOSURE", self.baseline)
        tags = []
        for name in ("agent-assure-s1-1.0.0a1-acceptance", "agent-assure-s1-1.0.0a1-acceptance-v2"):
            self._git(("-c", "tag.gpgSign=false", "tag", "-a", name, "-m", "synthetic predecessor"))
            tags.append((name, self._git(("rev-parse", name)).decode().strip()))
        monkeypatch.setattr(host, "PREDECESSOR_TAGS", tuple(tags))
        (root / "preparation.txt").write_text(
            "reviewed engineering preparation\n", encoding="utf-8"
        )
        self.base = self.commit("reviewed preparation")
        self.publisher = io.TagPublisher(root, self.runner, preflight=lambda root: None)
        monkeypatch.setattr(io, "frozen_tag_publisher", lambda legacy, root: self.publisher)
        monkeypatch.setattr(io, "frozen_signature_callback", lambda legacy: legacy._verify_sshsig)
        fixture = self

        class SyntheticLegacy:
            @staticmethod
            def _main_has_active_runtime_bootstrap() -> bool:
                return True

            _verify_sshsig = staticmethod(legacy._verify_sshsig)
            validate_estimation_catalog_v2 = staticmethod(legacy.validate_estimation_catalog_v2)
            _resolve_aggregation_method_v2 = staticmethod(legacy._resolve_aggregation_method_v2)

            @staticmethod
            def _require_clean_corrective_result_checkout(
                root: Path, *, result_commit: str, owner: str
            ) -> None:
                assert root == fixture.root and owner
                assert fixture._git(("rev-parse", "HEAD")).decode().strip() == result_commit
                assert fixture._git(("status", "--porcelain=v1", "--untracked-files=all")) == b""
                fixture.events.append("clean-result")

            @staticmethod
            def validate_local_only_roadmap(root: Path, path: Path) -> None:
                assert root == fixture.root and path == root / "synthetic-roadmap.json"
                assert path.is_file() and path.is_relative_to(root)
                fixture.events.append("synthetic-roadmap-source")

            @staticmethod
            def load_roadmap(path: Path) -> Any:
                class Snapshot:
                    raw_digest = core.content_digest(path.read_bytes())
                    ticket_set_digest = core.content_digest(b"synthetic exact two-ticket set")
                    dependency_graph_digest = core.content_digest(
                        b"synthetic exact dependency graph"
                    )
                    release_train_digest = core.content_digest(
                        b"synthetic exact release occurrences"
                    )

                return Snapshot()

            @staticmethod
            def build_authoring_ledger_v2(
                snapshot: Any, catalog: Any, **kwargs: Any
            ) -> dict[str, Any]:
                assert (
                    snapshot.raw_digest and catalog and kwargs["baseline_observations_digest_value"]
                )
                ledger = {
                    "format": "agent-assure-delivery-forecast-authoring-ledger/2",
                    "spec_revision": "6.5",
                    "source_digest": snapshot.raw_digest,
                    "roadmap_digest": snapshot.raw_digest,
                    "ticket_set_digest": snapshot.ticket_set_digest,
                    "release_train_digest": snapshot.release_train_digest,
                    "inventory_digest": kwargs["baseline_observations_digest_value"],
                    "baseline_observations_digest": kwargs["baseline_observations_digest_value"],
                    "inventory_completed_at": kwargs["inventory_completed_at"],
                    "inventory_completed_at_utc": kwargs["inventory_completed_at"],
                    "estimation_catalog_digest": catalog["catalog_digest"],
                    "file_scope_observation": {
                        "ticket_count": 2,
                        "resolved_ticket_count": 0,
                        "unresolved_ticket_count": 2,
                        "evidence_basis": "roadmap_resolved_allowed_files_cardinality",
                        "interpretation": "unresolved_scope_not_zero_implementation_work",
                        "estimate_status": (
                            "nonbinding_placeholders_pending_dispatch_scope_resolution"
                        ),
                        "rebaseline_trigger": (
                            "resolve_approved_file_scope_at_ticket_dispatch_and_reestimate_"
                            "when_concrete_surface_count_differs"
                        ),
                    },
                    "rows": [
                        {
                            "ticket_id": ticket,
                            "estimate_scope": "ticket_completion",
                            "execution_proposals": [
                                {
                                    "occurrence_id": f"{ticket}/remaining-{number}",
                                    "sprint": f"S{number + 1}",
                                    "release": f"1.0.0a{number + 1}",
                                    "scenario_class": (
                                        "stable_core_committed"
                                        if number == 1
                                        else "optional_profile_planned"
                                    ),
                                    "workload_vector_digest": core.content_digest(
                                        f"synthetic workload {ticket}/{number}".encode()
                                    ),
                                    "proposal_digest": core.content_digest(
                                        f"synthetic proposal {ticket}/{number}".encode()
                                    ),
                                    "effort_proposal": {
                                        "p50_effort_hours": number,
                                        "p90_effort_hours": 2 * number,
                                        "reviewer_p50_effort_hours": 1,
                                    },
                                    "elapsed_time": {
                                        "included_in_effort_quantiles": False,
                                        "maximum_single_known_wait_hours": 12 * number,
                                        "serial_sum_known_wait_hours": 18 * number,
                                        "unquantified_wait_dependency_count": number,
                                        "critical_path_status": "not_modeled_pending_human_review",
                                    },
                                }
                                for number in range(1, count + 1)
                            ],
                        }
                        for ticket, count in (("V1-SYN-01", 2), ("V1-SYN-02", 1))
                    ],
                }
                for row in ledger["rows"]:
                    for proposal in row["execution_proposals"]:
                        proposal["proposal_digest"] = legacy._occurrence_proposal_v2_digest(
                            proposal
                        )
                ledger["ledger_digest"] = legacy.domain_digest(legacy.LEDGER_V2_DOMAIN, ledger)
                return ledger

            @staticmethod
            def capture_post_v2_control_suite_evidence(
                root: Path, *, roadmap_path: Path, subject_commit: str, evidence_directory: str
            ) -> None:
                assert root == fixture.root and roadmap_path == root / "synthetic-roadmap.json"
                assert subject_commit == fixture.result
                destination = root / evidence_directory
                destination.mkdir(parents=True, exist_ok=False)
                stdout, stderr = b"1 passed in synthetic collector\n", b""
                record = {
                    "format": "agent-assure-s1-post-r2-suite-evidence/4",
                    "subject_commit": subject_commit,
                    "time_evidence": {
                        "started_at_utc": host.timestamp(fixture.clock()),
                        "completed_at_utc": host.timestamp(fixture.clock()),
                    },
                    "execution": {
                        "exit_code": 0,
                        "pytest_totals": {
                            "collected": 1,
                            "passed": 1,
                            "skipped": 0,
                            "failed": 0,
                            "errors": 0,
                            "deselected": 0,
                        },
                        "stdout_sha256": core.content_digest(stdout),
                        "stderr_sha256": core.content_digest(stderr),
                    },
                }
                record["evidence_digest"] = core.content_digest(core.canonical_bytes(record))
                (destination / "post-v2-control-suite-evidence.json").write_bytes(
                    core.canonical_bytes(record)
                )
                (destination / "pytest.stdout.bin").write_bytes(stdout)
                (destination / "pytest.stderr.bin").write_bytes(stderr)
                fixture.events.append("native-captured")

            @staticmethod
            def validate_post_v2_control_suite_evidence_source(
                path: Path, **kwargs: Any
            ) -> dict[str, Any]:
                assert kwargs == {
                    "expected_subject_commit": fixture.result,
                    "expected_subject_parent_commit": fixture.base,
                    "expected_repository_root": fixture.root,
                    "require_passed": True,
                }
                assert {p.name for p in path.parent.iterdir()} == {
                    "post-v2-control-suite-evidence.json",
                    "pytest.stdout.bin",
                    "pytest.stderr.bin",
                }
                record = host.parse_json(path.read_bytes())
                assert record["subject_commit"] == fixture.result
                for stream in ("stdout", "stderr"):
                    assert (
                        core.content_digest(
                            (path.parent / ("pytest." + stream + ".bin")).read_bytes()
                        )
                        == record["execution"][stream + "_sha256"]
                    )
                assert fixture._git(("rev-parse", "HEAD")).decode().strip() == fixture.result
                fixture.native_calls += 1
                fixture.events.append("native-source-revalidated")
                return record

        self.legacy = SyntheticLegacy()
        bootstrap_claim = host.prepare_bootstrap(root, _profile(), now=self.clock())
        self.bootstrap = {
            "claim": bootstrap_claim,
            "signature_envelope": signer(host.bootstrap_claim_bytes(bootstrap_claim)),
        }
        self.session = host.FrozenHost(self.legacy, root, self.bootstrap, clock=self.clock)

        class SyntheticCheckBackend:
            def __init__(
                self, legacy: Any, root: Path, result_commit: str, generated_root: Path
            ) -> None:
                assert (
                    legacy is fixture.legacy
                    and root == fixture.root
                    and result_commit == fixture.result
                )
                assert generated_root.is_relative_to(root / ".tmp/s1-acceptance")
                self.makefile_digest = checks.validate_makefile_projection(
                    (root / "Makefile").read_bytes()
                )

            def execute(self, spec: checks.CheckSpec) -> checks.CommandResult:
                fixture.checked_specs.append(spec.check_id)
                return checks.CommandResult(
                    spec.check_id,
                    host.timestamp(fixture.clock()),
                    host.timestamp(fixture.clock()),
                    0,
                    b"synthetic trusted collector\n",
                    b"",
                    {
                        "spec": checks._spec_record(spec),
                        "native_tool": (
                            dict(checks.RUFF_BINARY_IDENTITY) if spec.module == "ruff" else None
                        ),
                        "collector": "synthetic-test-only",
                    },
                )

        def synthetic_native_identity(root: Path, **kwargs: Any) -> dict[str, Any]:
            assert root == fixture.root
            fixture.events.append("synthetic-native-tool-identity-revalidated")
            return dict(checks.RUFF_BINARY_IDENTITY)

        monkeypatch.setattr(checks, "FrozenCheckBackend", SyntheticCheckBackend)
        monkeypatch.setattr(checks, "validate_ruff_binary", synthetic_native_identity)
        monkeypatch.setattr(ci, "AuthenticatedGitHubTransport", self.transport_factory)

    def _git(self, args: Any, *, input_bytes: bytes | None = None) -> bytes:
        environment = {
            **os.environ,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
        }
        completed = subprocess.run(
            [self.git, "-c", f"core.hooksPath={self.hooks}", "-C", str(self.root), *args],
            input=input_bytes,
            check=True,
            capture_output=True,
            env=environment,
            timeout=30,
        )
        return completed.stdout

    def runner(self, args: Any, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        # This fixture never mutates loose/packed object bytes. Memoize only
        # real Git reads of content-addressed objects, not refs/worktree/config.
        identity = tuple(args)
        if args[0] == "cat-file" and identity in self._immutable_object_reads:
            return self._immutable_object_reads[identity]
        environment = {
            **os.environ,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
        }
        result = subprocess.run(
            [self.git, "-c", f"core.hooksPath={self.hooks}", "-C", str(self.root), *args],
            input=kwargs.get("input_bytes"),
            check=False,
            capture_output=True,
            env=environment,
            timeout=30,
        )
        assert len(result.stdout) <= kwargs["max_stdout_bytes"]
        assert len(result.stderr) <= kwargs["max_stderr_bytes"]
        if "clone" in args or "status" in args:
            assert result.returncode == 0, (
                tuple(args),
                result.stderr.decode("utf-8", errors="replace"),
            )
        if args[0] == "cat-file" and result.returncode == 0:
            self._immutable_object_reads[identity] = result
        return result

    def commit(self, message: str) -> str:
        self._git(("add", "--all"))
        self._git(("commit", "--quiet", "-m", message))
        return self._git(("rev-parse", "HEAD")).decode().strip()

    def write_document(
        self, path: str, claim: dict[str, Any], *, domain: bytes = host.HUMAN_DOMAIN
    ) -> str:
        host.write_json(
            self.root,
            path,
            {
                "claim": claim,
                "signature_envelope": self.signer(domain + core.canonical_bytes(claim)),
            },
        )
        return path

    def stage_signed_kickoff_and_result(self) -> None:
        prefix = host.PRIVATE_PREFIX
        self.session.kickoff_plan(
            {
                "action": "kickoff-plan",
                "base_commit": self.base,
                "allowed_paths": ["notes.txt", host.START_MARKER_PATH],
                "work_limits": {
                    "maximum_changed_files": 2,
                    "maximum_diff_lines": 10,
                    "maximum_wall_clock_seconds": 7200,
                },
                "out": prefix + "kickoff-plan",
            }
        )
        payload = host.read_bytes(self.root, prefix + "kickoff-plan/claim")
        envelope_path = prefix + "inputs/kickoff-envelope.json"
        host.write_json(self.root, envelope_path, self.signer(payload))
        self.session.kickoff_import(
            {
                "action": "kickoff-import",
                "claim": prefix + "kickoff-plan/claim.json",
                "signature_envelope": envelope_path,
                "out": prefix + "kickoff-import",
            }
        )
        self.kickoff_path = prefix + "kickoff-import/kickoff-import.json"
        self.session.start_work(
            {"action": "start-work", "kickoff": self.kickoff_path, "out": prefix + "start"}
        )
        (self.root / "notes.txt").write_text("after\n", encoding="utf-8")
        self.result = self.commit("synthetic governed result")
        self.session.observe_result(
            {
                "action": "observe-result",
                "kickoff": self.kickoff_path,
                "work_start": prefix + "start/work-start.json",
                "result_commit": self.result,
                "out": prefix + "result",
            }
        )
        self.session.forecast_plan(
            {
                "action": "forecast-plan",
                "kickoff": self.kickoff_path,
                "result_commit": self.result,
                "roadmap": "synthetic-roadmap.json",
                "out": prefix + "forecast-plan",
            }
        )
        producer = host.read_json(self.root, prefix + "forecast-plan/claim.json")
        selected = producer["human_estimates"][0]["execution_estimates"][0]
        selected.update(
            p50_effort_hours=3,
            p90_effort_hours=5,
            rationale="Synthetic explicit human revision of remaining scoped design work",
        )
        host.write_json(self.root, prefix + "inputs/edited-forecast.json", producer)
        result = self.session.forecast_recalculate(
            {
                "action": "forecast-recalculate",
                "claim": prefix + "inputs/edited-forecast.json",
                "out": prefix + "forecast-recalculated",
            }
        )
        assert result["authorization_effect"] == "none"
        producer = host.read_json(self.root, prefix + "forecast-recalculated/claim.json")
        assert producer["estimate_summary"]["engineering_p50_effort_hours"] == 6
        assert producer["estimate_summary"]["engineering_p90_effort_hours"] == 11
        assert producer["estimate_summary"]["reviewer_p50_effort_hours"] == 3
        producer["decision"] = "accept_reestimated_proposal"
        self.forecast_producer = self.write_document(
            prefix + "inputs/forecast-producer.json", producer
        )
        acceptance = {
            "format": "agent-assure-successor-forecast-acceptance/3",
            "purpose": "successor-forecast-acceptance/v3",
            "issuer_role": "repository_maintainer",
            "policy_digest": self.session.claim["policy_digest"],
            "contract_id": "delivery-forecast/v1",
            "forecast_record_digest": producer["delivery_forecast"]["record_digest"],
            "forecast_digest": core.content_digest(
                host.HUMAN_DOMAIN + core.canonical_bytes(producer)
            ),
            "decision": "accept",
        }
        self.forecast_acceptance = self.write_document(
            prefix + "inputs/forecast-acceptance.json", acceptance
        )
        observation = host.read_json(self.root, prefix + "result/result-observation.json")
        committed = core._time(observation["commit_observed_at_utc"])
        self.ci_start, self.ci_end = (
            committed + timedelta(seconds=1),
            committed + timedelta(seconds=2),
        )
        self.clock.value = self.ci_end + timedelta(seconds=1)

    def transport_factory(self, token: str) -> Any:
        assert token == "synthetic-read-only-token-never-persist"
        # The bounded HTTP deadline starts at construction. Native execution
        # and every local check must finish before that network budget starts.
        assert self.checked_specs == [spec.check_id for spec in checks.make_check_expansion()]
        assert self.native_calls >= 1
        self.events.append("ci-transport-created-after-local-completion")
        fixture = self

        def transport(path: str) -> ci.HttpResponse:
            if "/jobs?" in path:
                data = {
                    "total_count": len(ci.EXPECTED_DISPLAY_NAMES),
                    "jobs": [
                        {
                            "id": index,
                            "run_id": 123,
                            "run_attempt": 1,
                            "head_sha": fixture.result,
                            "name": name,
                            "status": "completed",
                            "conclusion": "success",
                            "started_at": host.timestamp(fixture.ci_start),
                            "completed_at": host.timestamp(fixture.ci_end),
                        }
                        for index, name in enumerate(ci.EXPECTED_DISPLAY_NAMES, 1)
                    ],
                }
            else:
                data = {
                    "id": 123,
                    "run_attempt": 1,
                    "head_sha": fixture.result,
                    "event": "push",
                    "status": "completed",
                    "conclusion": "success",
                    "path": ci.WORKFLOW_PATH,
                    "repository": {"full_name": ci.REPOSITORY},
                    "head_repository": {"full_name": ci.REPOSITORY},
                    "created_at": host.timestamp(fixture.ci_start),
                    "run_started_at": host.timestamp(fixture.ci_start),
                    "updated_at": host.timestamp(fixture.ci_end),
                }
            fixture.events.append("authenticated-test-transport")
            return ci.HttpResponse(
                200, {"content-type": "application/json"}, json.dumps(data).encode()
            )

        return transport

    def collection_request(self) -> dict[str, Any]:
        return {
            "action": "collect",
            "kickoff": self.kickoff_path,
            "result_observation": host.PRIVATE_PREFIX + "result/result-observation.json",
            "roadmap": "synthetic-roadmap.json",
            "native_dir": ".tmp/s1-acceptance/post-v2-control-synthetic",
            "checks_dir": ".tmp/s1-acceptance/v3-checks-synthetic",
            "forecast_producer": self.forecast_producer,
            "forecast_acceptance": self.forecast_acceptance,
            "run_id": 123,
            "run_attempt": 1,
            "out": host.PRIVATE_PREFIX + "collection",
        }

    def collect(self) -> None:
        self.session.collect(
            self.collection_request(), token="synthetic-read-only-token-never-persist"
        )

    def sign_receipt(self) -> str:
        pending = host.read_json(self.root, host.PRIVATE_PREFIX + "collection/pending-receipt.json")
        _, payload = core.accepted_signing_claim(pending)
        path = host.PRIVATE_PREFIX + "inputs/receipt-envelope.json"
        host.write_json(self.root, path, self.signer(payload))
        return path

    def import_receipt(self, signature: str) -> dict[str, Any]:
        return self.session.receipt_import(
            {
                "action": "receipt-import",
                "collection": host.PRIVATE_PREFIX + "collection",
                "signature_envelope": signature,
                "out": host.PRIVATE_PREFIX + "closure",
            }
        )


def test_real_git_and_signatures_compose_source_collectors_to_pending_receipt(
    public_root: Path,
    ephemeral_signer: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pipeline = Pipeline(public_root, ephemeral_signer, monkeypatch)
    pipeline.stage_signed_kickoff_and_result()
    result = pipeline.session.collect(
        pipeline.collection_request(), token="synthetic-read-only-token-never-persist"
    )
    assert result["result"] == "authenticated_checks_collected_human_acceptance_pending"
    pending = host.read_json(public_root, host.PRIVATE_PREFIX + "collection/pending-receipt.json")
    assert pending["status"] == "pending_human_review" and pending["signature_envelope"] is None
    assert pipeline.native_calls >= 2
    assert pipeline.checked_specs == [spec.check_id for spec in checks.make_check_expansion()]
    assert "authenticated-test-transport" in pipeline.events
    assert pipeline.events.index("native-source-revalidated") < pipeline.events.index(
        "authenticated-test-transport"
    )
    assert pipeline._git(("rev-parse", "HEAD")).decode().strip() == pipeline.result
    for path in (public_root / ".tmp").rglob("*"):
        if path.is_file():
            assert b"synthetic-read-only-token-never-persist" not in path.read_bytes()


def test_host_collection_missing_token_stops_before_execution(
    public_root: Path,
    ephemeral_signer: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pipeline = Pipeline(public_root, ephemeral_signer, monkeypatch)
    pipeline.stage_signed_kickoff_and_result()
    with pytest.raises(core.SuccessorError, match="token"):
        pipeline.session.collect(pipeline.collection_request(), token="")
    assert not pipeline.native_calls and not pipeline.checked_specs


@pytest.mark.parametrize("mutation", ["fabricated-diff", "changed-roadmap"])
def test_human_signature_cannot_bless_fabricated_source_facts(
    public_root: Path,
    ephemeral_signer: Any,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    pipeline = Pipeline(public_root, ephemeral_signer, monkeypatch)
    pipeline.stage_signed_kickoff_and_result()
    producer = host.read_json(public_root, pipeline.forecast_producer)["claim"]
    if mutation == "fabricated-diff":
        producer["inventory"]["changed_paths"] = ["invented-unobserved-change.txt"]
    else:
        (public_root / "synthetic-roadmap.json").write_bytes(b'{"scope":"changed proposal"}\n')
        producer["roadmap_digest"] = core.content_digest(
            (public_root / "synthetic-roadmap.json").read_bytes()
        )
    # Recompute the machine proposal and sign both exact claims, so rejection
    # must come from independent source validation rather than a stale digest.
    producer["authoring_ledger"] = pipeline.legacy.build_authoring_ledger_v2(
        pipeline.legacy.load_roadmap(public_root / "synthetic-roadmap.json"),
        host.read_json(public_root, "docs/governance/v1/delivery-forecast.estimation-catalog.json"),
        baseline_observations_digest_value=core.content_digest(
            core.canonical_bytes(producer["inventory"])
        ),
        inventory_completed_at=producer["inventory_observed_at_utc"],
    )
    producer["estimate_summary"] = host.human_estimate_summary(
        producer["authoring_ledger"], producer["human_estimates"]
    )
    pipeline.forecast_producer = pipeline.write_document(
        host.PRIVATE_PREFIX + "inputs/source-fabricated-producer.json", producer
    )
    acceptance = host.read_json(public_root, pipeline.forecast_acceptance)["claim"]
    acceptance["forecast_digest"] = core.content_digest(
        host.HUMAN_DOMAIN + core.canonical_bytes(producer)
    )
    pipeline.forecast_acceptance = pipeline.write_document(
        host.PRIVATE_PREFIX + "inputs/source-fabricated-acceptance.json", acceptance
    )
    with pytest.raises(core.SuccessorError, match="inventory|roadmap"):
        pipeline.collect()
    assert not pipeline.native_calls and not pipeline.checked_specs
    assert not (public_root / (host.PRIVATE_PREFIX + "collection/pending-receipt.json")).exists()


def test_forecast_recalculation_preserves_validity_and_cannot_renew_expired_subject(
    public_root: Path,
    ephemeral_signer: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pipeline = Pipeline(public_root, ephemeral_signer, monkeypatch)
    pipeline.stage_signed_kickoff_and_result()
    prefix = host.PRIVATE_PREFIX
    original = host.read_json(public_root, prefix + "forecast-plan/claim.json")
    initial = original["delivery_forecast"]
    pipeline.clock.value += timedelta(hours=1)
    pipeline.session.forecast_recalculate(
        {
            "action": "forecast-recalculate",
            "claim": prefix + "forecast-plan/claim.json",
            "out": prefix + "forecast-later-recalculation",
        }
    )
    later = host.read_json(public_root, prefix + "forecast-later-recalculation/claim.json")
    assert later["delivery_forecast"]["issued_at_utc"] == initial["issued_at_utc"]
    assert later["delivery_forecast"]["valid_until_utc"] == initial["valid_until_utc"]
    assert later["delivery_forecast"]["record_digest"] == initial["record_digest"]
    pipeline.clock.value = core._time(initial["valid_until_utc"])
    with pytest.raises(core.SuccessorError, match="interval|stale"):
        pipeline.session.forecast_recalculate(
            {
                "action": "forecast-recalculate",
                "claim": prefix + "forecast-plan/claim.json",
                "out": prefix + "forecast-expired-recalculation",
            }
        )
    assert not (public_root / (prefix + "forecast-expired-recalculation/claim.json")).exists()
    monkeypatch.setattr(host, "utc_now", pipeline.clock)
    assert (
        host.main(
            [
                "decision-plan",
                "--repository-root",
                str(public_root),
                "--claim",
                prefix + "forecast-plan/claim.json",
                "--out",
                prefix + "expired-decision-preparation",
            ]
        )
        == 2
    )
    assert not (public_root / (prefix + "expired-decision-preparation/claim.json")).exists()


@pytest.mark.parametrize(
    "mutation",
    [
        "aggregate",
        "method",
        "source-graph",
        "wrong-acceptance-record",
        "producer-only",
        "unsigned-edit",
    ],
)
def test_signed_forecast_requires_recomputed_math_sources_and_exact_separate_acceptance(
    public_root: Path,
    ephemeral_signer: Any,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    pipeline = Pipeline(public_root, ephemeral_signer, monkeypatch)
    pipeline.stage_signed_kickoff_and_result()
    producer_document = host.read_json(public_root, pipeline.forecast_producer)
    producer = producer_document["claim"]
    projection = producer["delivery_forecast"]
    if mutation in {"aggregate", "unsigned-edit"}:
        projection["portfolio_aggregate"]["engineering_p90_effort_hours"] += 1
    elif mutation == "method":
        projection["aggregation_method"]["definition_digest"] = DIGEST
    elif mutation == "source-graph":
        projection["source"]["dependency_graph_digest"] = DIGEST
    projection["record_digest"] = core.content_digest(
        host.forecast.RECORD_DOMAIN
        + core.canonical_bytes(
            {key: value for key, value in projection.items() if key != "record_digest"}
        )
    )
    prefix = host.PRIVATE_PREFIX
    if mutation == "unsigned-edit":
        pipeline.forecast_producer = prefix + "inputs/forecast-unsigned-edit.json"
        host.write_json(public_root, pipeline.forecast_producer, producer_document)
    else:
        pipeline.forecast_producer = pipeline.write_document(
            prefix + "inputs/forecast-altered-producer.json", producer
        )
    acceptance = host.read_json(public_root, pipeline.forecast_acceptance)["claim"]
    acceptance["forecast_digest"] = core.content_digest(
        host.HUMAN_DOMAIN + core.canonical_bytes(producer)
    )
    acceptance["forecast_record_digest"] = (
        DIGEST if mutation == "wrong-acceptance-record" else projection["record_digest"]
    )
    pipeline.forecast_acceptance = pipeline.write_document(
        prefix + "inputs/forecast-altered-acceptance.json", acceptance
    )
    if mutation == "producer-only":
        path = public_root / pipeline.forecast_acceptance
        document = host.parse_json(path.read_bytes())
        document["signature_envelope"] = None
        path.write_bytes(core.canonical_bytes(document))
    with pytest.raises((core.SuccessorError, io.SuccessorIOError, legacy.GovernanceError)):
        pipeline.collect()
    assert not pipeline.native_calls and not pipeline.checked_specs
    assert not (public_root / (prefix + "collection/pending-receipt.json")).exists()


def test_forecast_planning_inputs_are_authenticated_before_use_against_tested_git_bytes(
    public_root: Path,
    ephemeral_signer: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pipeline = Pipeline(public_root, ephemeral_signer, monkeypatch)
    pipeline.stage_signed_kickoff_and_result()
    for index, binding in enumerate(host.forecast.PLANNING_INPUT_BINDINGS):
        path = public_root / binding["path"]
        original = path.read_bytes()
        path.write_bytes(original + b"\n")
        try:
            with pytest.raises(core.SuccessorError, match="planning input"):
                pipeline.session.forecast_plan(
                    {
                        "action": "forecast-plan",
                        "kickoff": pipeline.kickoff_path,
                        "result_commit": pipeline.result,
                        "roadmap": "synthetic-roadmap.json",
                        "out": host.PRIVATE_PREFIX + f"altered-planning-input-{index}",
                    }
                )
        finally:
            path.write_bytes(original)


def test_forecast_expiry_caps_receipt_and_tag_window_and_stops_expired_publication(
    public_root: Path,
    ephemeral_signer: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pipeline = Pipeline(public_root, ephemeral_signer, monkeypatch)
    pipeline.stage_signed_kickoff_and_result()
    producer = host.read_json(public_root, pipeline.forecast_producer)["claim"]
    previous = producer["delivery_forecast"]
    expiry = core._time(previous["issued_at_utc"]) + timedelta(minutes=5)
    producer["delivery_forecast"] = host.forecast.build_projection(
        authoring_ledger=producer["authoring_ledger"],
        human_estimates=producer["human_estimates"],
        source=previous["source"],
        issued_at_utc=previous["issued_at_utc"],
        valid_until_utc=host.timestamp(expiry),
        now=pipeline.clock(),
    )
    prefix = host.PRIVATE_PREFIX
    pipeline.forecast_producer = pipeline.write_document(
        prefix + "inputs/short-forecast-producer.json", producer
    )
    acceptance = host.read_json(public_root, pipeline.forecast_acceptance)["claim"]
    acceptance.update(
        forecast_digest=core.content_digest(host.HUMAN_DOMAIN + core.canonical_bytes(producer)),
        forecast_record_digest=producer["delivery_forecast"]["record_digest"],
    )
    pipeline.forecast_acceptance = pipeline.write_document(
        prefix + "inputs/short-forecast-acceptance.json", acceptance
    )
    pipeline.collect()
    pending = host.read_json(public_root, prefix + "collection/pending-receipt.json")
    assert core._time(pending["valid_until_utc"]) == expiry
    pipeline.import_receipt(pipeline.sign_receipt())
    common = {
        "accepted_receipt": prefix + "closure/accepted-receipt.json",
        "evidence": prefix + "collection/evidence.json",
    }
    pipeline.clock.value = expiry - timedelta(seconds=10)
    pipeline.session.tag_plan({"action": "tag-plan", **common, "out": prefix + "short-tag-plan"})
    claim = host.read_json(public_root, prefix + "short-tag-plan/claim.json")
    assert core._time(claim["finalize_by_utc"]) == expiry
    signature = prefix + "inputs/short-tag-signature.json"
    host.write_json(public_root, signature, ephemeral_signer(core.canonical_bytes(claim)))
    calls = []

    def forbidden_publication(*args: Any, **kwargs: Any) -> Any:
        calls.append((args, kwargs))
        pytest.fail("expired prerequisite reached immutable fixed-tag publication")

    monkeypatch.setattr(pipeline.publisher, "publish_fixed_tag", forbidden_publication)
    pipeline.clock.value = expiry
    with pytest.raises(core.SuccessorError, match="stale|interval|expiry|expired"):
        pipeline.session.tag_finalize(
            {
                "action": "tag-finalize",
                **common,
                "tag_claim": prefix + "short-tag-plan/claim.json",
                "signature_envelope": signature,
                "out": prefix + "expired-tag-attempt",
            }
        )
    assert calls == []
    assert pipeline._git(("tag", "--list", core.SUCCESSOR_TAG)) == b""


def test_unsigned_result_observation_cannot_widen_the_signed_file_scope(
    public_root: Path,
    ephemeral_signer: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pipeline = Pipeline(public_root, ephemeral_signer, monkeypatch)
    pipeline.stage_signed_kickoff_and_result()
    path = public_root / (host.PRIVATE_PREFIX + "result/result-observation.json")
    observed = host.parse_json(path.read_bytes())
    observed["allowed_paths"].append("src/agent_assure/forbidden.py")
    path.write_bytes(core.canonical_bytes(observed))
    with pytest.raises(core.SuccessorError):
        pipeline.session.collect(
            pipeline.collection_request(), token="synthetic-read-only-token-never-persist"
        )
    assert not pipeline.native_calls and not pipeline.checked_specs


def test_real_signature_import_creates_only_receipt_c3_and_keeps_capture_checkout_clean(
    public_root: Path,
    ephemeral_signer: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pipeline = Pipeline(public_root, ephemeral_signer, monkeypatch)
    pipeline.stage_signed_kickoff_and_result()
    pipeline.collect()
    result = pipeline.import_receipt(pipeline.sign_receipt())
    closure = result["closure_commit"]
    assert result["authorization_effect"] == "none"
    assert pipeline.publisher.resolve_commit(closure).parents == (pipeline.result,)
    assert pipeline.publisher.changed_paths(pipeline.result, closure) == (core.RECEIPT_PATH,)
    accepted = core.load_successor_receipt(
        pipeline.publisher.read_commit_artifact(closure, core.RECEIPT_PATH)
    )
    assert accepted["status"] == "accepted_for_development"
    assert pipeline._git(("rev-parse", "HEAD")).decode().strip() == pipeline.result
    assert pipeline._git(("status", "--porcelain=v1", "--untracked-files=all")) == b""
    assert not (public_root / core.RECEIPT_PATH).exists()
    pipeline.session.tag_plan(
        {
            "action": "tag-plan",
            "accepted_receipt": host.PRIVATE_PREFIX + "closure/accepted-receipt.json",
            "evidence": host.PRIVATE_PREFIX + "collection/evidence.json",
            "out": host.PRIVATE_PREFIX + "tag-plan",
        }
    )
    claim = host.read_json(public_root, host.PRIVATE_PREFIX + "tag-plan/claim.json")
    assert claim["closure_commit"] == closure
    assert claim["receipt_sha256"] == core.content_digest(
        pipeline.publisher.read_commit_artifact(closure, core.RECEIPT_PATH)
    )


def test_failed_persisted_source_admission_restores_empty_registry_and_does_not_create_closure(
    public_root: Path,
    ephemeral_signer: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pipeline = Pipeline(public_root, ephemeral_signer, monkeypatch)
    pipeline.stage_signed_kickoff_and_result()
    pipeline.collect()
    envelope = pipeline.sign_receipt()
    path = public_root / (host.PRIVATE_PREFIX + "collection/evidence.json")
    source = host.parse_json(path.read_bytes())
    last = next(reversed(source))
    source[last]["source"]["type"] = "unverified JSON success"
    path.write_bytes(core.canonical_bytes(source))
    fresh = host.FrozenHost(pipeline.legacy, public_root, pipeline.bootstrap, clock=pipeline.clock)
    original = fresh.boundary._evidence
    with pytest.raises(core.SuccessorError):
        fresh.receipt_import(
            {
                "action": "receipt-import",
                "collection": host.PRIVATE_PREFIX + "collection",
                "signature_envelope": envelope,
                "out": host.PRIVATE_PREFIX + "rejected-closure",
            }
        )
    assert fresh.boundary._evidence is original and original == {}
    assert not (public_root / (host.PRIVATE_PREFIX + "rejected-closure/closure.json")).exists()
    assert pipeline._git(("rev-parse", "HEAD")).decode().strip() == pipeline.result


@pytest.mark.parametrize("mutation", ["missing", "altered"])
def test_even_signed_local_ledger_requires_exact_native_tool_identity(
    public_root: Path,
    ephemeral_signer: Any,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    pipeline = Pipeline(public_root, ephemeral_signer, monkeypatch)
    pipeline.stage_signed_kickoff_and_result()
    trusted_test_backend = checks.FrozenCheckBackend

    class BrokenNativeMetadata(trusted_test_backend):  # type: ignore[misc,valid-type]
        def execute(self, spec: checks.CheckSpec) -> checks.CommandResult:
            result = super().execute(spec)
            command = dict(result.command_record)
            if spec.module == "ruff":
                if mutation == "missing":
                    command.pop("native_tool")
                else:
                    command["native_tool"]["sha256"] = DIGEST
            return checks.CommandResult(
                result.check_id,
                result.started_at_utc,
                result.completed_at_utc,
                result.exit_code,
                result.stdout,
                result.stderr,
                command,
            )

    monkeypatch.setattr(checks, "FrozenCheckBackend", BrokenNativeMetadata)
    pipeline.collect()
    # The ledger/evidence hashes are internally consistent and a real test
    # authority signs them. Machine identity still needs independent validation.
    with pytest.raises(core.SuccessorError, match="local child command"):
        pipeline.import_receipt(pipeline.sign_receipt())
    assert not (public_root / (host.PRIVATE_PREFIX + "closure/accepted-receipt.json")).exists()
    assert "synthetic-native-tool-identity-revalidated" in pipeline.events


def test_real_fixed_tag_publication_is_fresh_but_can_be_verified_later_from_signed_observation(
    public_root: Path,
    ephemeral_signer: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pipeline = Pipeline(public_root, ephemeral_signer, monkeypatch)
    pipeline.stage_signed_kickoff_and_result()
    pipeline.collect()
    imported = pipeline.import_receipt(pipeline.sign_receipt())
    prefix = host.PRIVATE_PREFIX
    common = {
        "accepted_receipt": prefix + "closure/accepted-receipt.json",
        "evidence": prefix + "collection/evidence.json",
    }
    pipeline.session.tag_plan({"action": "tag-plan", **common, "out": prefix + "tag-plan"})
    claim = host.read_json(public_root, prefix + "tag-plan/claim.json")
    envelope_path = prefix + "inputs/tag-envelope.json"
    host.write_json(public_root, envelope_path, ephemeral_signer(core.canonical_bytes(claim)))
    request = {
        "action": "tag-finalize",
        **common,
        "tag_claim": prefix + "tag-plan/claim.json",
        "signature_envelope": envelope_path,
        "out": prefix + "tag-finalization",
    }
    published = pipeline.session.tag_finalize(request)
    assert (
        published["authorization_effect"] == "none"
        and published["remote_publication"] == "not_performed"
    )
    raw_tag = pipeline.publisher.read_annotated_tag(core.SUCCESSOR_TAG)
    assert (
        raw_tag.object_oid == published["tag_object"]
        and raw_tag.target_commit == imported["closure_commit"]
    )
    assert pipeline._git(("rev-parse", "HEAD")).decode().strip() == pipeline.result
    pipeline.clock.value += timedelta(hours=2)
    with pytest.raises(core.SuccessorError, match="window"):
        pipeline.session.tag_finalize({**request, "out": prefix + "too-late-retry"})
    assert (
        pipeline.publisher.read_annotated_tag(core.SUCCESSOR_TAG).object_oid == raw_tag.object_oid
    )
    pipeline.session.publication_plan(
        {
            "action": "publication-plan",
            "publication": prefix + "tag-finalization/publication-observation.json",
            "out": prefix + "publication-plan",
        }
    )
    publication = host.read_json(public_root, prefix + "publication-plan/claim.json")
    publication["decision"] = "accept"
    countersigned = pipeline.write_document(
        prefix + "inputs/publication-accepted.json", publication
    )
    accepted = pipeline.session._accepted(common["accepted_receipt"], common["evidence"])
    tag = pipeline.session.boundary.preverify_tag()
    pipeline.session._publication(countersigned)
    subject = core.validate_successor_subject(
        accepted,
        closure_commit=tag.target_commit,
        policy=pipeline.session.policy,
        boundary=pipeline.session.boundary,
        now=pipeline.clock(),
    )
    assert subject.closure_commit == imported["closure_commit"]
    assert subject.publication_evidence_digest
    # This is subject/publication verification only, never standalone replay
    # or a completed frozen-host acceptance claim.
    assert not isinstance(subject, core.AcceptedSuccessor)


def _stage_architecture_sources(root: Path) -> None:
    """Build a real public architecture projection before the synthetic base."""
    for relative in {
        *architecture.SUPPLEMENTARY,
        *architecture.TOOLING,
        *("docs/governance/v1/" + name for name in architecture.HISTORICAL_FILES),
    }:
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / relative).read_bytes())
    package = architecture.build_package(root)
    (root / architecture.DIRECTORY / "architecture-package.json").write_bytes(
        core.canonical_bytes(package)
    )
    assert architecture.check_package(root) == package


class ControlledReplay:
    """Execution seam only: real clone and subject, synthetic child execution.

    This deliberately cannot qualify the native frozen Windows launcher. It
    checks the host's exact dispatch and credential scrubbing while obtaining
    the child response from the actual signed-subject validator.
    """

    def __init__(self, pipeline: Pipeline, monkeypatch: pytest.MonkeyPatch) -> None:
        self.pipeline = pipeline
        self.calls: list[dict[str, Any]] = []
        monkeypatch.setattr(
            pipeline.session, "_copy_replay_runtime", lambda destination: self.copied(destination)
        )
        monkeypatch.setattr(checks, "run_bounded", self.run)
        monkeypatch.setenv("GH_TOKEN", "synthetic-secret-must-not-reach-replay")
        monkeypatch.setenv("PYTHONPATH", "synthetic-untrusted-search-path")
        self.copied_paths: list[Path] = []

    def copied(self, destination: Path) -> None:
        assert destination.is_dir()
        self.copied_paths.append(destination)

    def run(self, command: Any, **kwargs: Any) -> tuple[int, bytes, bytes]:
        p = self.pipeline
        destination = kwargs["cwd"]
        assert destination == self.copied_paths[-1]
        assert command == [
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
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
        assert kwargs["payload"] == b""
        assert kwargs["timeout_seconds"] == 900
        assert kwargs["max_stream_bytes"] == 1024 * 1024
        environment = kwargs["environment"]
        assert environment["PATH"] == r"C:\Windows\System32;C:\Windows"
        assert environment["NoDefaultCurrentDirectoryInExePath"] == "1"
        assert not any("TOKEN" in key or key.startswith("PYTHON") for key in environment)
        assert (
            host.read_json(destination, ".tmp/s1-acceptance/successor-v3/replay/bootstrap.json")
            == p.bootstrap
        )
        request = host.read_json(destination, ".tmp/s1-acceptance/successor-v3/replay/request.json")
        assert request["action"] == "verify-replay"
        accepted = p.session._accepted(request["accepted_receipt"], request["evidence"])
        tag = p.session.boundary.preverify_tag()
        p.session._publication(request["publication"])
        subject = core.validate_successor_subject(
            accepted,
            closure_commit=tag.target_commit,
            policy=p.session.policy,
            boundary=p.session.boundary,
            now=p.clock(),
        )
        assert p._git(("-C", str(destination), "rev-parse", "HEAD")).decode().strip() == (
            subject.closure_commit
        )
        assert (destination / core.RECEIPT_PATH).read_bytes() == p.publisher.read_commit_artifact(
            subject.closure_commit, core.RECEIPT_PATH
        )
        assert p._git(("-C", str(destination), "rev-parse", "--is-shallow-repository")) == (
            b"false\n"
        )
        assert not (destination / ".git/objects/info/alternates").exists()
        self.calls.append({"command": command, "request": request, "subject": subject})
        return (
            0,
            core.canonical_bytes(
                {
                    "result": "standalone_subject_verified",
                    "subject": host.asdict(subject),
                    "validator_digest": p.session.policy.expected_validator_digest,
                    "authorization_effect": "none",
                }
            )
            + b"\n",
            b"",
        )


@pytest.fixture
def replay_pipeline(
    public_root: Path,
    ephemeral_signer: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Pipeline, ControlledReplay, str]:
    # Pin synthetic executable bytes for this controlled seam on every OS.
    # No real platform acceptance is asserted by this test fixture.
    raw_power = b"synthetic native interpreter identity for execution seam"
    power = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    monkeypatch.setattr(
        host,
        "powershell_identity",
        lambda: {
            "path": power,
            "size_bytes": len(raw_power),
            "sha256": core.content_digest(raw_power),
        },
    )
    original_read = Path.read_bytes
    monkeypatch.setattr(
        Path, "read_bytes", lambda path: raw_power if str(path) == power else original_read(path)
    )
    _stage_architecture_sources(public_root)
    pipeline = Pipeline(public_root, ephemeral_signer, monkeypatch)
    pipeline.stage_signed_kickoff_and_result()
    pipeline.collect()
    pipeline.import_receipt(pipeline.sign_receipt())
    prefix = host.PRIVATE_PREFIX
    common = {
        "accepted_receipt": prefix + "closure/accepted-receipt.json",
        "evidence": prefix + "collection/evidence.json",
    }
    pipeline.session.tag_plan({"action": "tag-plan", **common, "out": prefix + "tag-plan"})
    claim = host.read_json(public_root, prefix + "tag-plan/claim.json")
    envelope = prefix + "inputs/tag-envelope.json"
    host.write_json(public_root, envelope, ephemeral_signer(core.canonical_bytes(claim)))
    pipeline.session.tag_finalize(
        {
            "action": "tag-finalize",
            **common,
            "tag_claim": prefix + "tag-plan/claim.json",
            "signature_envelope": envelope,
            "out": prefix + "tag-finalization",
        }
    )
    pipeline.session.publication_plan(
        {
            "action": "publication-plan",
            "publication": prefix + "tag-finalization/publication-observation.json",
            "out": prefix + "publication-plan",
        }
    )
    publication = host.read_json(public_root, prefix + "publication-plan/claim.json")
    publication["decision"] = "accept"
    publication_path = pipeline.write_document(
        prefix + "inputs/publication-accepted.json", publication
    )
    replay = ControlledReplay(pipeline, monkeypatch)
    pipeline.session.verify(
        {
            "action": "verify",
            **common,
            "publication": publication_path,
            "out": prefix + "verification",
        },
        bootstrap_path="synthetic-already-authenticated",
    )
    return pipeline, replay, prefix + "verification/verification.json"


def _s2_signatures(pipeline: Pipeline, plan: dict[str, Any]) -> dict[str, Any]:
    return {
        "documents": [
            {
                "claim": claim,
                "signature_envelope": pipeline.signer(
                    host.HUMAN_DOMAIN + core.canonical_bytes(claim)
                ),
            }
            for claim in [*plan["claims"], plan["bundle_claim"]]
        ]
    }


def test_controlled_replay_then_real_signed_s2_plan_import_and_reverification(
    replay_pipeline: tuple[Pipeline, ControlledReplay, str],
) -> None:
    pipeline, replay, verification = replay_pipeline
    prefix = host.PRIVATE_PREFIX
    original = host.read_json(pipeline.root, verification)
    result = pipeline.session.s2_plan(
        {"action": "s2-plan", "successor_verification": verification, "out": prefix + "s2-plan"}
    )
    assert result["signing_claim_count"] == 15 and result["authorization_effect"] == "none"
    plan = host.read_json(pipeline.root, prefix + "s2-plan/plan.json")
    assert len(plan["claims"]) == 14
    assert [row["purpose"] for row in plan["claims"]].count("s2-drafting/v1") == 6
    assert [row["purpose"] for row in plan["claims"]].count("s2-design-acceptance/v1") == 8
    assert "historical_replay_digest" not in plan["bundle_claim"]["successor_basis"]
    fresh = host.read_json(pipeline.root, plan["verification"])
    assert (
        original["accepted_successor"]["historical_replay_digest"]
        != (fresh["accepted_successor"]["historical_replay_digest"])
    )
    signed_path = prefix + "inputs/s2-signed.json"
    host.write_json(pipeline.root, signed_path, _s2_signatures(pipeline, plan))
    accepted = pipeline.session.s2_import(
        {
            "action": "s2-import",
            "plan": prefix + "s2-plan/plan.json",
            "signed_decisions": signed_path,
            "out": prefix + "s2-accepted",
        }
    )
    assert accepted == {
        "result": "s2_accepted_for_development",
        "s2_dispatch_ready": True,
        "authorization_effect": "development_governance_only",
        "qualified": False,
    }
    assert (
        pipeline.session.s2_verify(
            {
                "action": "s2-verify",
                "bundle": prefix + "s2-accepted/accepted-bundle.json",
                "successor_verification": verification,
            }
        )
        == accepted
    )
    assert len(replay.calls) == 4
    accepted_bundle = host.read_json(pipeline.root, prefix + "s2-accepted/accepted-bundle.json")
    for index in range(15):
        corrupt = copy.deepcopy(accepted_bundle)
        document = corrupt["bundle"] if index == 14 else corrupt["decisions"][index]
        document["signature_envelope"] = None
        path = prefix + f"inputs/s2-readback-missing-signature-{index}.json"
        host.write_json(pipeline.root, path, corrupt)
        with pytest.raises((core.SuccessorError, io.SuccessorIOError)):
            pipeline.session.s2_verify(
                {
                    "action": "s2-verify",
                    "bundle": path,
                    "successor_verification": verification,
                }
            )
    assert len(replay.calls) == 4
    assert pipeline._git(("rev-parse", "HEAD")).decode().strip() == pipeline.result
    assert pipeline._git(("status", "--porcelain=v1", "--untracked-files=all")) == b""


def test_every_s2_decision_and_aggregate_signature_is_mandatory(
    replay_pipeline: tuple[Pipeline, ControlledReplay, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pipeline, replay, verification = replay_pipeline
    prefix = host.PRIVATE_PREFIX
    pipeline.session.s2_plan(
        {"action": "s2-plan", "successor_verification": verification, "out": prefix + "s2-plan"}
    )
    plan = host.read_json(pipeline.root, prefix + "s2-plan/plan.json")
    signed = _s2_signatures(pipeline, plan)

    # Invalid signatures must stop before any additional expensive replay.
    def unexpected_replay(locator: str, out: str) -> Any:
        pytest.fail("an incomplete or invalid signed S2 set reached historical execution")

    monkeypatch.setattr(pipeline.session, "_recheck_successor", unexpected_replay)
    for index in range(15):
        for mutation in ("omitted", "unsigned", "subject-changed"):
            documents = copy.deepcopy(signed)
            if mutation == "omitted":
                documents["documents"].pop(index)
            elif mutation == "unsigned":
                documents["documents"][index]["signature_envelope"] = None
            else:
                documents["documents"][index]["claim"]["authorization_effect"] = "release"
            path = prefix + f"inputs/s2-{index}-{mutation}.json"
            host.write_json(pipeline.root, path, documents)
            out = prefix + f"rejected-s2-{index}-{mutation}"
            with pytest.raises((core.SuccessorError, io.SuccessorIOError, legacy.GovernanceError)):
                pipeline.session.s2_import(
                    {
                        "action": "s2-import",
                        "plan": prefix + "s2-plan/plan.json",
                        "signed_decisions": path,
                        "out": out,
                    }
                )
            assert not (pipeline.root / out / "accepted-bundle.json").exists()
    assert len(replay.calls) == 2


def test_s2_rejects_changed_public_sources_and_forged_s1_status_before_authority(
    replay_pipeline: tuple[Pipeline, ControlledReplay, str],
) -> None:
    pipeline, replay, verification = replay_pipeline
    prefix = host.PRIVATE_PREFIX
    for index, relative in enumerate(
        [host.DECISIONS[0][2], architecture.SUPPLEMENTARY[0], architecture.TOOLING[0]]
    ):
        path = pipeline.root / relative
        original = path.read_bytes()
        path.write_bytes(original + b"\n")
        try:
            with pytest.raises(core.SuccessorError):
                pipeline.session.s2_plan(
                    {
                        "action": "s2-plan",
                        "successor_verification": verification,
                        "out": prefix + f"changed-source-{index}",
                    }
                )
        finally:
            path.write_bytes(original)
    forged = prefix + "inputs/forged-s1-verification.json"
    host.write_json(
        pipeline.root,
        forged,
        {
            "format": "agent-assure-s1-successor-host-verification/3",
            "accepted_successor": {"status": "accepted_for_development"},
            "accepted_receipt": prefix + "collection/pending-receipt.json",
            "evidence": prefix + "collection/evidence.json",
            "publication": prefix + "inputs/publication-accepted.json",
            "authorization_effect": "development_governance_only",
        },
    )
    before = len(replay.calls)
    with pytest.raises((core.SuccessorError, io.SuccessorIOError)):
        pipeline.session.s2_plan(
            {"action": "s2-plan", "successor_verification": forged, "out": prefix + "forged-s2"}
        )
    assert len(replay.calls) == before
    assert not (pipeline.root / (prefix + "forged-s2/plan.json")).exists()


@pytest.mark.parametrize(
    ("action", "fields"),
    [
        (
            "verify",
            {
                "accepted_receipt": "receipt",
                "evidence": "evidence",
                "publication": "publication",
                "out": "out",
            },
        ),
        (
            "verify-replay",
            {
                "accepted_receipt": "receipt",
                "evidence": "evidence",
                "publication": "publication",
                "out": "out",
            },
        ),
        ("s2-plan", {"successor_verification": "verification", "out": "out"}),
        ("s2-import", {"plan": "plan", "signed_decisions": "signed", "out": "out"}),
        ("s2-verify", {"bundle": "bundle", "successor_verification": "verification"}),
        ("forecast-recalculate", {"claim": "claim", "out": "out"}),
    ],
)
def test_actual_frozen_dispatch_schema_routes_new_host_operations(
    public_root: Path,
    ephemeral_signer: Any,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    action: str,
    fields: dict[str, str],
) -> None:
    # Bind the copied schema to the fixture's ephemeral authority before its
    # inventory is signed; the public schema keeps the real authority pinned.
    schema_path = public_root / host.HOST_SCHEMA
    schema_value = host.parse_json(schema_path.read_bytes())
    schema_value["$defs"]["profile"]["properties"]["public_key"]["const"] = host.ROOT_PUBLIC_KEY
    trust_properties = schema_value["$defs"]["bootstrap"]["properties"]["claim"]["properties"][
        "trust"
    ]["properties"]
    trust_properties["public_key"]["const"] = host.ROOT_PUBLIC_KEY
    schema_path.write_bytes(core.canonical_bytes(schema_value))
    claim = host.prepare_bootstrap(public_root, _profile(), now=NOW)
    bootstrap = {
        "claim": claim,
        "signature_envelope": ephemeral_signer(host.bootstrap_claim_bytes(claim)),
    }
    observed: list[str] = []

    class TestRuntime:
        _main_has_active_runtime_bootstrap = staticmethod(lambda: True)

    class RouteOnlyHost:
        def __init__(self, runtime: Any, root: Path, adopted: Any) -> None:
            assert runtime is TestRuntime and adopted is bootstrap
            self.root = self.source_root = root

        def __getattr__(self, name: str) -> Any:
            def dispatch(request: Any, **kwargs: Any) -> dict[str, str]:
                assert name == action.replace("-", "_")
                assert request == {"action": action, **fields}
                assert kwargs == (
                    {"bootstrap_path": "authenticated_bootstrap"} if action == "verify" else {}
                )
                observed.append(name)
                return {"result": "synthetic-route-only", "authorization_effect": "none"}

            return dispatch

    monkeypatch.setattr(host, "FrozenHost", RouteOnlyHost)
    assert host.run_frozen(TestRuntime, public_root, bootstrap, {"action": action, **fields}) == 0
    assert observed == [action.replace("-", "_")]
    assert json.loads(capsys.readouterr().out)["authorization_effect"] == "none"
    with pytest.raises(core.SuccessorError, match="wire contract"):
        host.run_frozen(
            TestRuntime,
            public_root,
            bootstrap,
            {"action": action, **fields, "unreviewed_authority": True},
        )
    assert len(observed) == 1
    schema = public_root / host.HOST_SCHEMA
    schema.write_bytes(schema.read_bytes() + b"\n")
    with pytest.raises(core.SuccessorError, match="schema.*authenticated bootstrap"):
        host.run_frozen(TestRuntime, public_root, bootstrap, {"action": action, **fields})
    assert len(observed) == 1


def _quantile_ledger() -> dict[str, Any]:
    return {
        "rows": [
            {
                "ticket_id": ticket,
                "estimate_scope": "synthetic_remaining_execution_work",
                "execution_proposals": [
                    {
                        "occurrence_id": f"{ticket}/{index}",
                        "effort_proposal": {
                            "p50_effort_hours": p50,
                            "p90_effort_hours": p90,
                            "reviewer_p50_effort_hours": reviewer,
                        },
                    }
                    for index, (p50, p90, reviewer) in enumerate(values)
                ],
            }
            for ticket, values in (
                ("SYN-01", ((2, 9, 1), (3, 10, 2))),
                ("SYN-02", ((4, 14, 3),)),
            )
        ]
    }


def test_forecast_named_quantiles_match_comonotonic_reference_and_separate_review() -> None:
    ledger = _quantile_ledger()
    original = copy.deepcopy(ledger)
    selected = host.proposed_human_estimates(ledger)
    summary = host.human_estimate_summary(ledger, selected)
    # Three discrete work distributions share the same ranked state. The
    # generalized-inverse 50th/90th percentiles of their sum are exact here.
    joint = [
        sum(
            effort["p50_effort_hours"]
            if rank < 5
            else effort["p90_effort_hours"] * (1 if rank < 9 else 2)
            for row in ledger["rows"]
            for occurrence in row["execution_proposals"]
            for effort in [occurrence["effort_proposal"]]
        )
        for rank in range(10)
    ]
    assert summary["engineering_p50_effort_hours"] == joint[4] == 9
    assert summary["engineering_p90_effort_hours"] == joint[8] == 33
    assert summary["reviewer_p50_effort_hours"] == 6
    assert summary["method_id"] == "comonotonic-quantile-sum/v1"
    assert summary["combined_p90_effort_hours"] is None
    assert summary["elapsed_waits_included"] is False
    assert summary["calendar_commitment"] is False
    assert "uncalibrated" in summary["confidence_basis"]
    assert ledger == original
    # Humans can change subjective estimates without silently editing the
    # trusted source proposal, and the declared arithmetic is recomputed.
    selected[0]["execution_estimates"][0].update(
        p50_effort_hours=5,
        p90_effort_hours=12,
        rationale="Synthetic human revision after reviewing the remaining scope",
    )
    revised = host.human_estimate_summary(ledger, selected)
    assert revised["engineering_p50_effort_hours"] == 12
    assert revised["engineering_p90_effort_hours"] == 36
    assert revised["reviewer_p50_effort_hours"] == 6
    assert ledger == original


@pytest.mark.parametrize(
    "mutation",
    [
        "missing-ticket",
        "duplicate-ticket",
        "reordered-tickets",
        "changed-scope",
        "missing-occurrence",
        "duplicate-occurrence",
        "reordered-occurrences",
        "boolean-hours",
        "float-hours",
        "zero-hours",
        "inverted-quantiles",
        "oversized-quantiles",
        "zero-review",
        "empty-rationale",
        "invented-actuals",
    ],
)
def test_forecast_requires_exact_source_coverage_and_valid_separate_quantiles(
    mutation: str,
) -> None:
    ledger = _quantile_ledger()
    selected = host.proposed_human_estimates(ledger)
    first = selected[0]["execution_estimates"][0]
    if mutation == "missing-ticket":
        selected.pop()
    elif mutation == "duplicate-ticket":
        selected[1]["ticket_id"] = selected[0]["ticket_id"]
    elif mutation == "reordered-tickets":
        selected.reverse()
    elif mutation == "changed-scope":
        selected[0]["estimate_scope"] = "all_work_completed"
    elif mutation == "missing-occurrence":
        selected[0]["execution_estimates"].pop()
    elif mutation == "duplicate-occurrence":
        selected[0]["execution_estimates"][1]["occurrence_id"] = first["occurrence_id"]
    elif mutation == "reordered-occurrences":
        selected[0]["execution_estimates"].reverse()
    elif mutation == "boolean-hours":
        first["p50_effort_hours"] = True
    elif mutation == "float-hours":
        first["p50_effort_hours"] = 2.0
    elif mutation == "zero-hours":
        first["p50_effort_hours"] = 0
    elif mutation == "inverted-quantiles":
        first["p90_effort_hours"] = first["p50_effort_hours"] - 1
    elif mutation == "oversized-quantiles":
        first["p90_effort_hours"] = 10_000_001
    elif mutation == "zero-review":
        first["reviewer_p50_effort_hours"] = 0
    elif mutation == "empty-rationale":
        first["rationale"] = ""
    else:
        first["actual_hours"] = 1
    with pytest.raises(core.SuccessorError):
        host.human_estimate_summary(ledger, selected)


def test_actual_replay_runtime_copy_handles_large_binary_and_root_relative_identity(
    tmp_path: Path,
) -> None:
    """Exercise copying only, without constructing any acceptance authority."""
    source = tmp_path / "source"
    (source / ".venv/Lib/site-packages").mkdir(parents=True)
    (source / ".venv/pyvenv.cfg").write_bytes(b"synthetic test-only base configuration\n")
    binary = source / ".venv/Lib/site-packages/synthetic_large_extension.pyd"
    with binary.open("wb") as stream:
        for _ in range(17):
            stream.write(b"x" * (1024 * 1024))
    cache = source / ".venv/Lib/site-packages/__pycache__"
    cache.mkdir()
    (cache / "ignored.pyc").write_bytes(b"inert test-only cache")
    destination = source / (host.PRIVATE_PREFIX + "runtime-copy/clone")
    (destination / ".git").mkdir(parents=True)
    calls: list[Path] = []

    class SourceIdentityOnly:
        POST_V2_CONTROL_GIT_EXCLUDE_BYTES = legacy.POST_V2_CONTROL_GIT_EXCLUDE_BYTES

        @staticmethod
        def _post_r2_test_runtime_evidence(root: Path) -> dict[str, Any]:
            calls.append(root)
            configuration = root / ".venv/pyvenv.cfg"
            extension = root / ".venv/Lib/site-packages/synthetic_large_extension.pyd"
            with extension.open("rb") as stream:
                digest = "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest()
            return {
                "format": "agent-assure-s1-post-r2-test-runtime/2",
                "pyvenv_configuration": {
                    "absolute_path": str(configuration),
                    "relative_path": ".venv/pyvenv.cfg",
                    "size_bytes": configuration.stat().st_size,
                    "sha256": core.content_digest(configuration.read_bytes()),
                },
                "site_packages_inventory": {
                    "relative_root": ".venv/Lib/site-packages",
                    "file_count": 1,
                    "size_bytes": extension.stat().st_size,
                    "sha256": digest,
                },
                "base_runtime": {"absolute_path": "synthetic-pinned-external-base"},
            }

    session = object.__new__(host.FrozenHost)
    session.root = source
    session.claim = {"trust": {"capture_repository_root": str(source)}}
    session.legacy = SourceIdentityOnly()
    session._copy_replay_runtime(destination)
    assert calls == [source, destination]
    assert (destination / ".venv/pyvenv.cfg").read_bytes() == (
        source / ".venv/pyvenv.cfg"
    ).read_bytes()
    with (destination / ".venv/Lib/site-packages/synthetic_large_extension.pyd").open(
        "rb"
    ) as stream:
        assert (
            hashlib.file_digest(stream, "sha256").hexdigest()
            == hashlib.sha256(b"x" * (17 * 1024 * 1024)).hexdigest()
        )
    assert not (destination / ".venv/Lib/site-packages/__pycache__").exists()
    assert (destination / ".git/info/exclude").read_bytes() == (
        legacy.POST_V2_CONTROL_GIT_EXCLUDE_BYTES
    )
