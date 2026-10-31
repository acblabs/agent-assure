from __future__ import annotations

import base64
import copy
import hashlib
import inspect
import json
import os
import shutil
import stat
import subprocess
import sys
from argparse import Namespace
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import scripts.v1_s1_governance as governance  # noqa: E402, I001


GOVERNANCE_ROOT = ROOT / "docs" / "governance" / "v1"
ROADMAP = ROOT / "Agent_Assure_Implementation_Roadmap.md"
PERSON_ID = "H1"
ISSUED_AT = "2026-10-15T15:00:00Z"
INVENTORY_COMPLETED_AT = "2026-10-15T14:00:00Z"
VALID_UNTIL = "2026-11-14T15:00:00Z"
SYNTHETIC_LEGACY_V3_GIT_EXCLUDE_BYTES = (
    b"# Hermetic synthetic legacy-v3 local-exclude policy.\n"
    b"/Agent_Assure_Implementation_Roadmap.md\n"
    b"/.venv/\n"
    b"/.tmp/\n"
    b"/synthetic-legacy-v3-only/\n"
)


def _host_test_tool_identities() -> dict[str, governance.TrustedExecutableIdentity]:
    identities: dict[str, governance.TrustedExecutableIdentity] = {}
    for name in ("git", "ssh-keygen"):
        executable = shutil.which(name)
        if executable is None:
            continue
        path = Path(executable).resolve()
        payload = path.read_bytes()
        identities[name] = governance.TrustedExecutableIdentity(
            path=str(path),
            size_bytes=len(payload),
            sha256=hashlib.sha256(payload).hexdigest(),
        )
    return identities


HOST_TEST_TOOL_IDENTITIES = _host_test_tool_identities()


@pytest.fixture(autouse=True)
def _use_test_host_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    """Exercise logic with the current test host while records retain frozen identities.

    Runtime tests separately verify the accepted host's byte identities.  Unit
    and synthetic integration tests must also run on a fresh hosted-Windows
    image, whose Git/OpenSSH paths and bytes are intentionally not asserted to
    be the maintainer workstation's frozen tools.
    """

    monkeypatch.setattr(
        governance,
        "TRUSTED_EXECUTABLE_IDENTITIES",
        HOST_TEST_TOOL_IDENTITIES,
    )


def _digest(byte: str) -> str:
    return f"sha256:{byte * 64}"


def _independent_python_test_executable() -> str:
    """Return a Python process whose launch policy will not rewrite the test probe.

    The governed full-suite process installs a recursive launch guard around its
    descendant interpreter.  A few tests below intentionally compare raw
    CPython behavior or execute a separately generated bootstrap, so allowing
    that outer guard to rewrite their argv would test the outer run instead of
    the probe.  The guard contract already treats the frozen base interpreter
    as an independent absolute executable; ordinary test runs retain their
    current interpreter for cross-platform coverage.
    """

    guard = getattr(subprocess, "_agent_assure_s1_post_r2_launch_guard", None)
    if guard is None:
        return sys.executable
    assert guard == (
        sys.executable,
        sys.pycache_prefix,
    ), "the governed test harness marker does not match this interpreter"
    executable = governance._FROZEN_PYTHON_EXECUTABLE
    assert executable.is_file(), "the governed test harness requires its frozen base Python"
    assert executable.is_absolute()
    assert os.path.normcase(str(executable.resolve())) != os.path.normcase(
        str(Path(sys.executable).resolve())
    )
    return str(executable)


def _install_synthetic_legacy_v3_git_exclude_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> bytes:
    """Replace only the in-memory legacy pin for hermetic synthetic tests."""

    payload = SYNTHETIC_LEGACY_V3_GIT_EXCLUDE_BYTES
    monkeypatch.setattr(governance, "POST_R2_GIT_EXCLUDE_SIZE_BYTES", len(payload))
    monkeypatch.setattr(
        governance,
        "POST_R2_GIT_EXCLUDE_SHA256",
        hashlib.sha256(payload).hexdigest(),
    )
    return payload


def _install_synthetic_legacy_v3_git_exclude_fixture(
    monkeypatch: pytest.MonkeyPatch,
) -> bytes:
    """Use sentinel bytes while retaining schema-pinned historical metadata."""

    payload = SYNTHETIC_LEGACY_V3_GIT_EXCLUDE_BYTES
    historical_evidence = {
        "path": ".git/info/exclude",
        "size_bytes": governance.POST_R2_GIT_EXCLUDE_SIZE_BYTES,
        "sha256": "sha256:" + governance.POST_R2_GIT_EXCLUDE_SHA256,
    }
    original = governance._post_r2_git_exclude_evidence

    def synthetic_evidence(
        repository_root: Path,
        *,
        legacy_v3_policy: bool = False,
    ) -> dict[str, Any]:
        if not legacy_v3_policy:
            return original(repository_root, legacy_v3_policy=False)
        exclude = repository_root / ".git" / "info" / "exclude"
        try:
            observed = exclude.read_bytes()
        except OSError as exc:
            raise governance.GovernanceError(
                "synthetic post-R2 .git/info/exclude cannot be read"
            ) from exc
        if observed != payload:
            raise governance.GovernanceError("synthetic post-R2 .git/info/exclude policy changed")
        return copy.deepcopy(historical_evidence)

    monkeypatch.setattr(governance, "_post_r2_git_exclude_evidence", synthetic_evidence)
    return payload


class _SyntheticCaptureRecord(dict[str, Any]):
    def __init__(self, value: dict[str, Any], *, reused: bool) -> None:
        super().__init__(value)
        self.reused = reused


def _minimal_snapshot(*, raw_digest: str | None = None) -> governance.RoadmapSnapshot:
    ticket = {
        "id": "V1-TEST-01",
        "title": "Exercise the governance calculations",
        "depends_on": [],
        "stop_conditions": ["Stop if the frozen contract changes."],
        "delivery": {
            "estimate": {
                "scope": "ticket_completion",
                "unit": "focused_engineer_day",
                "p50": 1.125,
                "p90": 2,
                "confidence": "medium",
                "basis": "A deterministic test prior.",
            },
            "review_effort_p50_days": 0.375,
        },
    }
    release_train = {
        "entries": [
            {"sprint": "S1", "release": "1.0.0a1", "ticket_ids": ["V1-TEST-01"]},
            {"sprint": "S2", "release": "1.0.0a2", "ticket_ids": ["V1-TEST-01"]},
        ]
    }
    return governance.RoadmapSnapshot(
        raw_digest=raw_digest or _digest("1"),
        tickets=(ticket,),
        release_train=release_train,
        approval_roster_template={},
        ticket_set_digest=_digest("2"),
        dependency_graph_digest=_digest("3"),
        release_train_digest=_digest("4"),
    )


def _baseline_observations() -> dict[str, Any]:
    return {
        "observations_digest": _digest("5"),
        "inventory_completed_at_utc": INVENTORY_COMPLETED_AT,
    }


def _ledger() -> tuple[governance.RoadmapSnapshot, dict[str, Any], dict[str, Any]]:
    snapshot = _minimal_snapshot()
    baseline = _baseline_observations()
    ledger = governance.build_authoring_ledger(
        snapshot,
        issued_at=ISSUED_AT,
        producer_person_id=PERSON_ID,
        baseline_observations_digest_value=baseline["observations_digest"],
        inventory_completed_at=baseline["inventory_completed_at_utc"],
    )
    return snapshot, baseline, ledger


def _refresh_ledger_digest(ledger: dict[str, Any]) -> None:
    ledger["ledger_digest"] = governance._ledger_digest(ledger)


def _schema(name: str) -> dict[str, Any]:
    return governance._read_json(GOVERNANCE_ROOT / name)


def _record(name: str) -> dict[str, Any]:
    return governance._read_json(GOVERNANCE_ROOT / name)


def _generation_1_record(name: str) -> dict[str, Any]:
    return governance._read_json_from_commit(
        ROOT,
        governance.S1_ACCEPTANCE_V1_CLOSURE_COMMIT,
        f"docs/governance/v1/{name}",
    )


def _set_pending_signature(envelope: dict[str, Any]) -> None:
    """Make a copied envelope explicitly pending, independent of repository state."""

    envelope["status"] = "pending_human_signature"
    envelope["signed_at_utc"] = None
    envelope["signature"] = None


@pytest.mark.parametrize(
    "payload, expected",
    [
        ('{"outer":{"member":1,"member":2}}', "duplicate JSON member: member"),
        ('{"value":NaN}', "non-finite JSON constant is forbidden"),
        ('{"value":9007199254740992}', "integer outside RFC 8785 safe range"),
        ('{"value":"e\\u0301"}', "non-NFC string"),
        ('{"value":"\\u0000"}', "control or surrogate character"),
        ('{"value":', "malformed JSON"),
    ],
)
def test_strict_json_rejects_ambiguous_or_noncanonical_input(payload: str, expected: str) -> None:
    with pytest.raises(governance.GovernanceError, match=expected):
        governance.strict_json_loads(payload)


def test_canonical_bytes_and_domain_digest_are_order_independent_and_domain_separated() -> None:
    left = {"z": [True, None], "a": {"number": 1}}
    right = {"a": {"number": 1}, "z": [True, None]}

    assert governance.canonical_bytes(left) == b'{"a":{"number":1},"z":[true,null]}'
    assert governance.canonical_bytes(left) == governance.canonical_bytes(right)

    expected = (
        "sha256:"
        + hashlib.sha256(b"example-domain/v1\x00" + governance.canonical_bytes(left)).hexdigest()
    )
    assert governance.domain_digest("example-domain/v1", left) == expected
    assert governance.domain_digest("another-domain/v1", left) != expected


def test_validity_interval_accepts_exactly_thirty_days() -> None:
    issued_at, valid_until = governance._validate_validity_interval(
        ISSUED_AT, VALID_UNTIL, owner="test record"
    )

    assert (valid_until - issued_at) == governance.MAX_S1_VALIDITY


@pytest.mark.parametrize(
    "issued_at, valid_until, expected",
    [
        (ISSUED_AT, "2026-11-14T15:00:00.000001Z", "exceeds 30 days"),
        (ISSUED_AT, ISSUED_AT, "must be nonempty"),
        (ISSUED_AT, "2026-10-15T14:59:59Z", "must be nonempty"),
        ("2026-10-15T15:00:00+00:00", VALID_UNTIL, "canonical RFC 3339 UTC"),
        ("2026-02-30T15:00:00Z", VALID_UNTIL, "is not RFC 3339 UTC"),
    ],
)
def test_validity_interval_rejects_expansive_or_noncanonical_windows(
    issued_at: str, valid_until: str, expected: str
) -> None:
    with pytest.raises(governance.GovernanceError, match=expected):
        governance._validate_validity_interval(issued_at, valid_until, owner="test record")


def test_aggregation_registry_is_self_authenticating_and_frozen() -> None:
    registry = governance.aggregation_method_registry()
    projection = {key: value for key, value in registry.items() if key != "registry_digest"}
    method = registry["methods"][0]
    definition = {key: value for key, value in method.items() if key != "definition_digest"}

    assert registry["registry_digest"] == governance.domain_digest(
        governance.METHOD_REGISTRY_DOMAIN, projection
    )
    assert method["definition_digest"] == governance.domain_digest(
        governance.METHOD_DOMAIN, definition
    )
    assert governance._resolve_aggregation_method(registry) == method

    tampered = copy.deepcopy(registry)
    tampered["methods"][0]["dependence_model"]["independence_claimed"] = True
    with pytest.raises(governance.GovernanceError, match="differs from the frozen definition"):
        governance._resolve_aggregation_method(tampered)


def test_authoring_ledger_front_loads_integer_remainders_without_losing_effort() -> None:
    snapshot, baseline, ledger = _ledger()

    governance.validate_authoring_ledger(
        snapshot,
        ledger,
        {},
        expected_person_id=PERSON_ID,
        baseline_observations=baseline,
    )
    proposals = ledger["rows"][0]["execution_proposals"]
    assert [proposal["proposed_p50_effort_hours"] for proposal in proposals] == [5, 4]
    assert [proposal["proposed_p90_effort_hours"] for proposal in proposals] == [8, 8]
    assert [proposal["proposed_reviewer_effort_hours"] for proposal in proposals] == [2, 1]


def test_forecast_uses_tail_aligned_additive_aggregation() -> None:
    snapshot, _, ledger = _ledger()

    forecast = governance.build_forecast(
        snapshot,
        ledger,
        governance.aggregation_method_registry(),
        issued_at=ISSUED_AT,
        valid_until=VALID_UNTIL,
        producer_person_id=PERSON_ID,
        approval_roster_digest_value=_digest("6"),
    )

    row = forecast["rows"][0]
    assert row["aggregate_p50_effort_hours"] == 9
    assert row["aggregate_p90_effort_hours"] == 16
    assert row["aggregate_reviewer_effort_hours"] == 3
    assert forecast["portfolio_aggregate"]["occurrence_count"] == 2
    assert forecast["forecast_status"] == "proposed"
    assert forecast["signature_envelope"]["status"] == "pending_human_signature"
    assert row["trusted_issue_time"] == ledger["issued_at_utc"]


@pytest.mark.parametrize(
    "tamper",
    [
        "row_aggregate",
        "portfolio_aggregate",
        "missing_occurrence",
        "reordered_occurrences",
    ],
)
def test_forecast_validation_rejects_aggregate_and_occurrence_tampering(
    tamper: str,
) -> None:
    snapshot, _, ledger = _ledger()
    registry = governance.aggregation_method_registry()
    forecast = governance.build_forecast(
        snapshot,
        ledger,
        registry,
        issued_at=ISSUED_AT,
        valid_until=VALID_UNTIL,
        producer_person_id=PERSON_ID,
        approval_roster_digest_value=_digest("6"),
    )
    row = forecast["rows"][0]

    if tamper == "row_aggregate":
        row["aggregate_p50_effort_hours"] += 1
    elif tamper == "portfolio_aggregate":
        forecast["portfolio_aggregate"]["aggregate_p90_effort_hours"] += 1
    elif tamper == "missing_occurrence":
        row["execution_estimates"].pop()
    else:
        row["execution_estimates"].reverse()

    with pytest.raises(
        governance.GovernanceError,
        match="forecast projection does not recompute from trusted inputs",
    ):
        governance.validate_forecast(
            snapshot,
            ledger,
            registry,
            forecast,
            _generation_1_record("delivery-forecast.schema.json"),
            expected_person_id=PERSON_ID,
            approval_roster_digest_value=_digest("6"),
            allow_pending=True,
        )


def test_forecast_row_preserves_earliest_actual_confirmation_time() -> None:
    snapshot, _, ledger = _ledger()
    row = ledger["rows"][0]
    row["row_decision"] = "affirmatively_reconfirmed_after_inventory"
    row["row_confirmed_by_person_id"] = PERSON_ID
    row["row_confirmed_at_utc"] = "2026-10-15T14:35:00Z"
    confirmation_times = ["2026-10-15T14:10:00Z", "2026-10-15T14:20:00Z"]
    for proposal, confirmed_at in zip(row["execution_proposals"], confirmation_times, strict=True):
        proposal["decision"] = "affirmatively_reconfirmed_after_inventory"
        proposal["confirmed_by_person_id"] = PERSON_ID
        proposal["confirmed_at_utc"] = confirmed_at
    _refresh_ledger_digest(ledger)

    forecast = governance.build_forecast(
        snapshot,
        ledger,
        governance.aggregation_method_registry(),
        issued_at=ISSUED_AT,
        valid_until="2026-11-14T14:10:00Z",
        producer_person_id=PERSON_ID,
        approval_roster_digest_value=_digest("6"),
    )

    assert forecast["rows"][0]["trusted_issue_time"] == confirmation_times[0]
    assert forecast["forecast_status"] == "ready_for_acceptance"


def test_forecast_rejects_rewrapping_a_stale_pending_ledger() -> None:
    snapshot, _, ledger = _ledger()

    with pytest.raises(
        governance.GovernanceError,
        match="valid_until_utc exceeds 30 days after its oldest decision",
    ):
        governance.build_forecast(
            snapshot,
            ledger,
            governance.aggregation_method_registry(),
            issued_at="2026-11-13T15:00:00Z",
            valid_until="2026-11-15T15:00:00Z",
            producer_person_id=PERSON_ID,
            approval_roster_digest_value=_digest("6"),
        )


def test_forecast_validation_recomputes_the_oldest_decision_expiry_bound() -> None:
    snapshot, _, ledger = _ledger()
    forecast = governance.build_forecast(
        snapshot,
        ledger,
        governance.aggregation_method_registry(),
        issued_at=ISSUED_AT,
        valid_until=VALID_UNTIL,
        producer_person_id=PERSON_ID,
        approval_roster_digest_value=_digest("6"),
    )
    forecast["issued_at_utc"] = "2026-11-13T15:00:00Z"
    forecast["valid_until_utc"] = "2026-11-15T15:00:00Z"

    with pytest.raises(
        governance.GovernanceError,
        match="valid_until_utc exceeds 30 days after its oldest decision",
    ):
        governance.validate_forecast(
            snapshot,
            ledger,
            governance.aggregation_method_registry(),
            forecast,
            _generation_1_record("delivery-forecast.schema.json"),
            expected_person_id=PERSON_ID,
            approval_roster_digest_value=_digest("6"),
            allow_pending=True,
        )


def test_authoring_ledger_rejects_digest_tampering() -> None:
    snapshot, baseline, ledger = _ledger()
    ledger["rows"][0]["selected_confidence"] = "high"

    with pytest.raises(governance.GovernanceError, match="ledger digest mismatch"):
        governance.validate_authoring_ledger(
            snapshot,
            ledger,
            {},
            expected_person_id=PERSON_ID,
            baseline_observations=baseline,
        )


def test_authoring_ledger_rejects_tampered_source_proposal_even_with_fresh_digest() -> None:
    snapshot, baseline, ledger = _ledger()
    proposal = ledger["rows"][0]["execution_proposals"][0]
    proposal["proposed_p50_effort_hours"] += 1
    _refresh_ledger_digest(ledger)

    with pytest.raises(governance.GovernanceError, match="changed source proposal field"):
        governance.validate_authoring_ledger(
            snapshot,
            ledger,
            {},
            expected_person_id=PERSON_ID,
            baseline_observations=baseline,
        )


def test_authoring_ledger_rejects_p90_below_p50_even_with_fresh_digest() -> None:
    snapshot, baseline, ledger = _ledger()
    proposal = ledger["rows"][0]["execution_proposals"][0]
    proposal["selected_p90_effort_hours"] = proposal["selected_p50_effort_hours"] - 1
    _refresh_ledger_digest(ledger)

    with pytest.raises(governance.GovernanceError, match="P90 is below P50"):
        governance.validate_authoring_ledger(
            snapshot,
            ledger,
            {},
            expected_person_id=PERSON_ID,
            baseline_observations=baseline,
        )


def test_authoring_ledger_rejects_unacknowledged_reestimate() -> None:
    snapshot, baseline, ledger = _ledger()
    proposal = ledger["rows"][0]["execution_proposals"][0]
    proposal["selected_p50_effort_hours"] += 1
    _refresh_ledger_digest(ledger)

    with pytest.raises(governance.GovernanceError, match="cannot alter the source proposal"):
        governance.validate_authoring_ledger(
            snapshot,
            ledger,
            {},
            expected_person_id=PERSON_ID,
            baseline_observations=baseline,
        )


def test_authoring_ledger_rejects_confirmation_before_inventory() -> None:
    snapshot, baseline, ledger = _ledger()
    row = ledger["rows"][0]
    row["row_decision"] = "affirmatively_reconfirmed_after_inventory"
    row["row_confirmed_by_person_id"] = PERSON_ID
    row["row_confirmed_at_utc"] = "2026-10-15T13:59:59Z"
    _refresh_ledger_digest(ledger)

    with pytest.raises(governance.GovernanceError, match="predates completed inventory"):
        governance.validate_authoring_ledger(
            snapshot,
            ledger,
            {},
            expected_person_id=PERSON_ID,
            baseline_observations=baseline,
        )


def test_forecast_schema_rejects_accepted_state_with_pending_signatures() -> None:
    forecast = _generation_1_record("delivery-forecast.json")
    forecast["forecast_status"] = "accepted"
    _set_pending_signature(forecast["signature_envelope"])
    _set_pending_signature(forecast["acceptance_receipt"]["signature_envelope"])

    with pytest.raises(governance.GovernanceError, match="schema validation failed"):
        governance._validate_json_schema(
            forecast,
            _generation_1_record("delivery-forecast.schema.json"),
            owner="delivery forecast",
        )


def test_forecast_schema_rejects_accepting_receipt_with_pending_signature() -> None:
    forecast = _generation_1_record("delivery-forecast.json")
    forecast["acceptance_receipt"]["receipt_status"] = "accepted_for_development"
    _set_pending_signature(forecast["acceptance_receipt"]["signature_envelope"])

    with pytest.raises(governance.GovernanceError, match="schema validation failed"):
        governance._validate_json_schema(
            forecast,
            _generation_1_record("delivery-forecast.schema.json"),
            owner="delivery forecast",
        )


def test_kickoff_schema_rejects_authorized_state_without_identity_bound_signature() -> None:
    kickoff = _record("kickoff-authorization-v1-base-01.json")
    kickoff["authorization_status"] = "authorized"
    _set_pending_signature(kickoff["signature_envelope"])

    with pytest.raises(governance.GovernanceError, match="schema validation failed"):
        governance._validate_json_schema(
            kickoff,
            _schema("kickoff-authorization.schema.json"),
            owner="kickoff authorization",
        )


def test_signature_schema_rejects_data_on_a_pending_envelope() -> None:
    forecast = _generation_1_record("delivery-forecast.json")
    _set_pending_signature(forecast["signature_envelope"])
    forecast["signature_envelope"]["signature"] = "ZmFrZQ=="

    with pytest.raises(governance.GovernanceError, match="schema validation failed"):
        governance._validate_json_schema(
            forecast,
            _generation_1_record("delivery-forecast.schema.json"),
            owner="delivery forecast",
        )


def test_signing_key_schema_rejects_confirmation_without_out_of_band_evidence() -> None:
    signing_key = _record("maintainer-signing-key.json")
    signing_key["key_status"] = "confirmed_by_human"
    signing_key["out_of_band_confirmation_evidence"] = None

    with pytest.raises(governance.GovernanceError, match="schema validation failed"):
        governance._validate_json_schema(
            signing_key,
            _schema("maintainer-signing-key.schema.json"),
            owner="maintainer signing key",
        )


def test_baseline_observations_bind_the_frozen_external_tool_identities() -> None:
    record = _record("baseline-observations.json")
    snapshot = _minimal_snapshot()
    snapshot = governance.RoadmapSnapshot(
        raw_digest=record["roadmap"]["raw_digest"],
        tickets=snapshot.tickets,
        release_train=snapshot.release_train,
        approval_roster_template=snapshot.approval_roster_template,
        ticket_set_digest=snapshot.ticket_set_digest,
        dependency_graph_digest=snapshot.dependency_graph_digest,
        release_train_digest=snapshot.release_train_digest,
    )
    governance.validate_baseline_observations(
        snapshot,
        record,
        _schema("baseline-observations.schema.json"),
        repository_root=ROOT,
    )

    tampered = copy.deepcopy(record)
    tampered["environment"]["trusted_executables"]["artifacts"][0]["sha256"] = _digest("0")
    tampered["observations_digest"] = governance.domain_digest(
        governance.BASELINE_OBSERVATIONS_V2_DOMAIN,
        governance._record_projection(tampered, "observations_digest"),
    )
    with pytest.raises(governance.GovernanceError, match="trusted executable changed"):
        governance.validate_baseline_observations(
            snapshot,
            tampered,
            _schema("baseline-observations.schema.json"),
            repository_root=ROOT,
        )


def test_corrective_kickoff_authorization_verifies_exact_claim_and_signature(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("PROGRAMDATA", raising=False)
    record = _record("corrective-kickoff-authorization.json")
    schema = _schema("corrective-kickoff-authorization.schema.json")
    expected_roadmap_digest = record["signed_claim"]["evidence"]["roadmap_raw_sha256"]

    assert (
        governance.validate_corrective_kickoff_authorization(
            record,
            schema,
            expected_roadmap_digest=expected_roadmap_digest,
        )
        == governance.CORRECTIVE_KICKOFF_CLAIM_DIGEST
    )

    tampered_claim = copy.deepcopy(record)
    tampered_claim["signed_claim"]["nonce"] = "00000000-0000-0000-0000-000000000000"
    with pytest.raises(governance.GovernanceError, match="signed claim bytes changed"):
        governance.validate_corrective_kickoff_authorization(
            tampered_claim,
            schema,
            expected_roadmap_digest=expected_roadmap_digest,
        )


def test_sshsig_verification_replaces_hostile_programdata_and_removes_its_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hostile = tmp_path / "hostile-program-data"
    hostile_config = hostile / "ssh/ssh_config"
    hostile_config.parent.mkdir(parents=True)
    hostile_config.write_bytes(b"Host *\n    ProxyCommand false\n")
    monkeypatch.setenv("PROGRAMDATA", str(hostile))
    actual_run = subprocess.run
    observed: list[Path] = []

    def capture_run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        environment = kwargs["env"]
        matches = [key for key in environment if key.casefold() == "programdata"]
        assert matches == ["PROGRAMDATA"]
        program_data = Path(environment["PROGRAMDATA"])
        assert program_data != hostile
        assert program_data.name == "program-data"
        assert program_data.is_dir()
        assert list(program_data.iterdir()) == []
        observed.append(program_data)
        return actual_run(*args, **kwargs)

    monkeypatch.setattr(governance.subprocess, "run", capture_run)
    record = _record("corrective-kickoff-authorization.json")
    assert (
        governance.validate_corrective_kickoff_authorization(
            record,
            _schema("corrective-kickoff-authorization.schema.json"),
            expected_roadmap_digest=record["signed_claim"]["evidence"]["roadmap_raw_sha256"],
        )
        == governance.CORRECTIVE_KICKOFF_CLAIM_DIGEST
    )
    assert len(observed) == 1
    assert not observed[0].parent.exists()


def test_sshsig_verification_rejects_programdata_side_effects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[Path] = []

    def dirty_run(arguments: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        program_data = Path(kwargs["env"]["PROGRAMDATA"])
        observed.append(program_data)
        (program_data / "unexpected").write_bytes(b"side effect")
        return subprocess.CompletedProcess(arguments, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(governance.subprocess, "run", dirty_run)
    record = _record("corrective-kickoff-authorization.json")
    with pytest.raises(governance.GovernanceError, match="modified its isolated PROGRAMDATA"):
        governance.validate_corrective_kickoff_authorization(
            record,
            _schema("corrective-kickoff-authorization.schema.json"),
            expected_roadmap_digest=record["signed_claim"]["evidence"]["roadmap_raw_sha256"],
        )
    assert len(observed) == 1
    assert not observed[0].parent.exists()


def test_sshsig_failure_reports_status_when_openssh_is_silent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def silent_failure(arguments: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(arguments, 255, stdout=b"", stderr=b"")

    monkeypatch.setattr(governance.subprocess, "run", silent_failure)
    record = _record("corrective-kickoff-authorization.json")
    with pytest.raises(
        governance.GovernanceError,
        match=r"OpenSSH exited with status 255: <no stdout/stderr>",
    ):
        governance.validate_corrective_kickoff_authorization(
            record,
            _schema("corrective-kickoff-authorization.schema.json"),
            expected_roadmap_digest=record["signed_claim"]["evidence"]["roadmap_raw_sha256"],
        )


def test_corrective_kickoff_authorization_rejects_tampered_sshsig() -> None:
    record = _record("corrective-kickoff-authorization.json")
    signature_evidence = record["signature_evidence"]
    armor = base64.b64decode(signature_evidence["armored_signature_base64"], validate=True).decode(
        "ascii"
    )
    armor_lines = armor.splitlines()
    signature_blob = bytearray(base64.b64decode("".join(armor_lines[1:-1]), validate=True))
    signature_blob[-1] ^= 1
    encoded = base64.b64encode(signature_blob).decode("ascii")
    tampered_armor = (
        "-----BEGIN SSH SIGNATURE-----\n"
        + "\n".join(encoded[index : index + 70] for index in range(0, len(encoded), 70))
        + "\n-----END SSH SIGNATURE-----\n"
    )
    signature_evidence["armored_signature_base64"] = base64.b64encode(
        tampered_armor.encode("ascii")
    ).decode("ascii")

    with pytest.raises(governance.GovernanceError, match="signature evidence changed"):
        governance.validate_corrective_kickoff_authorization(
            record,
            _schema("corrective-kickoff-authorization.schema.json"),
            expected_roadmap_digest=record["signed_claim"]["evidence"]["roadmap_raw_sha256"],
        )


def test_governance_schemas_use_only_the_closed_canonical_format_set() -> None:
    schema_paths = sorted(GOVERNANCE_ROOT.rglob("*.schema.json"))
    schemas = [json.loads(path.read_text(encoding="utf-8")) for path in schema_paths]

    declared_formats = set().union(
        *(governance._schema_declared_formats(schema) for schema in schemas)
    )
    assert "date-time" in declared_formats
    assert declared_formats <= {"date-time", "uri", "uuid"}

    date_schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["observed_at"],
        "properties": {
            "observed_at": {"type": "string", "format": "date-time"},
        },
        "additionalProperties": False,
    }
    uri_schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["source"],
        "properties": {"source": {"type": "string", "format": "uri"}},
        "additionalProperties": False,
    }
    uuid_schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["claim_nonce"],
        "properties": {"claim_nonce": {"type": "string", "format": "uuid"}},
        "additionalProperties": False,
    }

    governance._validate_json_schema(
        {"observed_at": "2026-10-15T15:00:00.123456Z"},
        date_schema,
        owner="canonical UTC fixture",
    )
    governance._validate_json_schema(
        {"source": "https://example.invalid/governance?revision=1"},
        uri_schema,
        owner="absolute URI fixture",
    )
    governance._validate_json_schema(
        {"claim_nonce": "c5bac25e-b075-4d50-84b6-97703e341dbb"},
        uuid_schema,
        owner="canonical UUID fixture",
    )
    for invalid in (
        "2026-10-15T15:00:00+00:00",
        "2026-10-15T15:00:00z",
        "2026-02-30T15:00:00Z",
    ):
        with pytest.raises(governance.GovernanceError, match="schema validation failed"):
            governance._validate_json_schema(
                {"observed_at": invalid},
                date_schema,
                owner="noncanonical UTC fixture",
            )
    for invalid in (
        "relative/path",
        "https:///missing-authority",
        "https://example.invalid:bad",
        "https://user@",
        "https://example.invalid/%ZZ",
        "https://example.invalid/naïve",
        r"https:\\example.invalid\escape",
    ):
        with pytest.raises(governance.GovernanceError, match="schema validation failed"):
            governance._validate_json_schema(
                {"source": invalid},
                uri_schema,
                owner="non-absolute URI fixture",
            )
    for invalid in (
        "C5BAC25E-B075-4D50-84B6-97703E341DBB",
        "c5bac25eb0754d5084b697703e341dbb",
        "{c5bac25e-b075-4d50-84b6-97703e341dbb}",
        "not-a-uuid",
    ):
        with pytest.raises(governance.GovernanceError, match="schema validation failed"):
            governance._validate_json_schema(
                {"claim_nonce": invalid},
                uuid_schema,
                owner="noncanonical UUID fixture",
            )

    unsupported_schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "string",
        "format": "email",
    }
    with pytest.raises(governance.GovernanceError, match="unsupported formats: email"):
        governance._closed_schema_format_checker(unsupported_schema)

    opaque_instance = {
        "format": "agent-assure-instance-record/1",
        "$ref": "https://instance.example.invalid/not-a-schema-reference",
    }
    valid_instance = {"payload": opaque_instance}
    instance_valued_keywords_schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["payload"],
        "properties": {"payload": {"const": opaque_instance}},
        "default": {"format": "agent-assure-default-record/1"},
        "enum": [valid_instance, {"format": "agent-assure-enum-record/1"}],
        "examples": [{"$ref": "https://instance.example.invalid/example"}],
    }
    assert governance._schema_declared_formats(instance_valued_keywords_schema) == set()
    assert governance._schema_external_references(instance_valued_keywords_schema) == set()
    governance._validate_json_schema(
        valid_instance,
        instance_valued_keywords_schema,
        owner="instance-valued schema keyword fixture",
    )
    contradictory_enum_schema = copy.deepcopy(instance_valued_keywords_schema)
    contradictory_enum_schema["enum"] = [{"format": "agent-assure-enum-record/1"}]
    with pytest.raises(governance.GovernanceError, match="schema validation failed"):
        governance._validate_json_schema(
            valid_instance,
            contradictory_enum_schema,
            owner="contradictory instance-valued enum fixture",
        )

    nested_unsupported_schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$defs": {"address": {"type": "string", "format": "email"}},
        "allOf": [{"$ref": "#/$defs/address"}],
    }
    with pytest.raises(governance.GovernanceError, match="unsupported formats: email"):
        governance._closed_schema_format_checker(nested_unsupported_schema)

    external_reference_schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$defs": {
            "external": {"$ref": "file:///untrusted/external.schema.json"},
        },
        "properties": {"payload": {"$ref": "#/$defs/external"}},
    }
    with pytest.raises(governance.GovernanceError, match="nonlocal references"):
        governance._validate_json_schema({}, external_reference_schema, owner="adversarial")


@dataclass(frozen=True)
class SshKey:
    private_key: Path
    public_key: str
    fingerprint: str


def _run_test_ssh_keygen(arguments: list[str]) -> subprocess.CompletedProcess[bytes]:
    with governance._isolated_openssh_environment() as environment:
        return subprocess.run(
            arguments,
            capture_output=True,
            check=False,
            env=environment,
            timeout=10,
        )


def _generate_key(executable: str, root: Path, name: str) -> SshKey:
    private_key = root / name
    completed = _run_test_ssh_keygen(
        [executable, "-q", "-t", "ed25519", "-N", "", "-f", str(private_key)]
    )
    if completed.returncode != 0:
        pytest.skip(
            "ssh-keygen cannot generate the ephemeral test key: "
            + completed.stderr.decode("utf-8", errors="replace")
        )
    public_parts = private_key.with_suffix(".pub").read_text(encoding="ascii").split()
    public_key = " ".join(public_parts[:2])
    return SshKey(
        private_key=private_key,
        public_key=public_key,
        fingerprint=governance._public_key_fingerprint(public_key),
    )


@pytest.fixture(scope="module")
def ssh_key_material(tmp_path_factory: pytest.TempPathFactory) -> tuple[str, SshKey, SshKey]:
    executable = shutil.which("ssh-keygen")
    if executable is None:
        pytest.skip("OpenSSH ssh-keygen is unavailable")
    root = tmp_path_factory.mktemp("s1-sshsig-keys")
    return (
        executable,
        _generate_key(executable, root, "signing-key"),
        _generate_key(executable, root, "other-key"),
    )


def _unsigned_envelope(key: SshKey) -> dict[str, Any]:
    return {
        "profile": governance.SIGNATURE_PROFILE,
        "status": "signed",
        "namespace": governance.SIGNATURE_NAMESPACE,
        "signed_payload_encoding": governance.SIGNATURE_PAYLOAD_ENCODING,
        "signature_encoding": governance.SIGNATURE_ENCODING,
        "signer_person_id": PERSON_ID,
        "signer_role": "repository_maintainer",
        "subject_digest": _digest("7"),
        "public_key_fingerprint": key.fingerprint,
        "signed_at_utc": "2026-10-15T15:05:00Z",
        "signature": None,
    }


def _canonicalize_armor(raw: bytes) -> bytes:
    text = raw.decode("ascii").replace("\r\n", "\n")
    lines = text.splitlines()
    encoded = "".join(lines[1:-1])
    wrapped = "\n".join(encoded[index : index + 70] for index in range(0, len(encoded), 70))
    return ("-----BEGIN SSH SIGNATURE-----\n" + wrapped + "\n-----END SSH SIGNATURE-----\n").encode(
        "ascii"
    )


def _sign_envelope(
    executable: str,
    key: SshKey,
    envelope: dict[str, Any],
    root: Path,
    *,
    sshsig_namespace: str = governance.SIGNATURE_NAMESPACE,
) -> dict[str, Any]:
    signed = copy.deepcopy(envelope)
    payload_path = root / f"claim-{len(list(root.glob('claim-*')))}.json"
    payload_path.write_bytes(governance._signature_claim_bytes(signed))
    completed = _run_test_ssh_keygen(
        [
            executable,
            "-Y",
            "sign",
            "-f",
            str(key.private_key),
            "-n",
            sshsig_namespace,
            "-O",
            "hashalg=sha512",
            str(payload_path),
        ]
    )
    if completed.returncode != 0:
        pytest.fail(
            "ssh-keygen could not create the test sshsig: "
            + completed.stderr.decode("utf-8", errors="replace")
        )
    armor = _canonicalize_armor(Path(f"{payload_path}.sig").read_bytes())
    signed["signature"] = base64.b64encode(armor).decode("ascii")
    return signed


def _trust_key(monkeypatch: pytest.MonkeyPatch, key: SshKey) -> None:
    monkeypatch.setattr(governance, "MAINTAINER_PUBLIC_KEY", key.public_key)
    monkeypatch.setattr(governance, "MAINTAINER_KEY_FINGERPRINT", key.fingerprint)


def _validate_signed_envelope(envelope: dict[str, Any]) -> None:
    governance._validate_signature_envelope(
        envelope,
        expected_person_id=PERSON_ID,
        expected_role="repository_maintainer",
        expected_subject_digest=envelope["subject_digest"],
        allow_pending=False,
        not_before=governance._parse_utc(ISSUED_AT, owner="issued_at"),
        not_after=governance._parse_utc(VALID_UNTIL, owner="valid_until"),
        validation_time=governance._parse_utc("2026-10-15T15:06:00Z", owner="validation_time"),
    )


def test_signature_envelope_rejects_unsigned_extension_fields() -> None:
    forecast = _record("delivery-forecast.json")
    envelope = copy.deepcopy(forecast["signature_envelope"])
    envelope["unsigned_note"] = "this field is outside the signed claim"

    with pytest.raises(
        governance.GovernanceError, match="signature envelope has unexpected fields"
    ):
        governance._validate_signature_envelope(
            envelope,
            expected_person_id=envelope["signer_person_id"],
            expected_role=envelope["signer_role"],
            expected_subject_digest=envelope["subject_digest"],
            allow_pending=True,
        )


def test_real_ed25519_sshsig_round_trip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    ssh_key_material: tuple[str, SshKey, SshKey],
) -> None:
    executable, signing_key, _ = ssh_key_material
    _trust_key(monkeypatch, signing_key)
    envelope = _sign_envelope(executable, signing_key, _unsigned_envelope(signing_key), tmp_path)

    signed_at = governance._validate_signature_envelope(
        envelope,
        expected_person_id=PERSON_ID,
        expected_role="repository_maintainer",
        expected_subject_digest=envelope["subject_digest"],
        allow_pending=False,
    )

    assert signed_at == governance._parse_utc(
        envelope["signed_at_utc"], owner="signature signed_at_utc"
    )


def test_sshsig_rejects_subject_changed_after_signing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    ssh_key_material: tuple[str, SshKey, SshKey],
) -> None:
    executable, signing_key, _ = ssh_key_material
    _trust_key(monkeypatch, signing_key)
    envelope = _sign_envelope(executable, signing_key, _unsigned_envelope(signing_key), tmp_path)
    envelope["subject_digest"] = _digest("8")

    with pytest.raises(governance.GovernanceError, match="signature verification failed"):
        _validate_signed_envelope(envelope)


def test_sshsig_rejects_a_signature_from_another_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    ssh_key_material: tuple[str, SshKey, SshKey],
) -> None:
    executable, signing_key, other_key = ssh_key_material
    envelope = _sign_envelope(executable, signing_key, _unsigned_envelope(signing_key), tmp_path)
    _trust_key(monkeypatch, other_key)
    envelope["public_key_fingerprint"] = other_key.fingerprint

    with pytest.raises(governance.GovernanceError, match="embeds another public key"):
        _validate_signed_envelope(envelope)


def test_sshsig_rejects_another_embedded_namespace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    ssh_key_material: tuple[str, SshKey, SshKey],
) -> None:
    executable, signing_key, _ = ssh_key_material
    _trust_key(monkeypatch, signing_key)
    envelope = _sign_envelope(
        executable,
        signing_key,
        _unsigned_envelope(signing_key),
        tmp_path,
        sshsig_namespace="agent-assure-wrong-namespace",
    )

    with pytest.raises(governance.GovernanceError, match="embeds another namespace"):
        _validate_signed_envelope(envelope)


def test_sshsig_rejects_noncanonical_outer_base64(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    ssh_key_material: tuple[str, SshKey, SshKey],
) -> None:
    executable, signing_key, _ = ssh_key_material
    _trust_key(monkeypatch, signing_key)
    envelope = _sign_envelope(executable, signing_key, _unsigned_envelope(signing_key), tmp_path)
    envelope["signature"] += "\n"

    with pytest.raises(governance.GovernanceError, match="canonical base64-encoded ASCII"):
        _validate_signed_envelope(envelope)


def test_sshsig_rejects_noncanonical_armor_wrapping(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    ssh_key_material: tuple[str, SshKey, SshKey],
) -> None:
    executable, signing_key, _ = ssh_key_material
    _trust_key(monkeypatch, signing_key)
    envelope = _sign_envelope(executable, signing_key, _unsigned_envelope(signing_key), tmp_path)
    armor = base64.b64decode(envelope["signature"], validate=True).decode("ascii")
    lines = armor.splitlines()
    encoded = "".join(lines[1:-1])
    noncanonical = (
        "-----BEGIN SSH SIGNATURE-----\n"
        + "\n".join(encoded[index : index + 64] for index in range(0, len(encoded), 64))
        + "\n-----END SSH SIGNATURE-----\n"
    )
    envelope["signature"] = base64.b64encode(noncanonical.encode("ascii")).decode("ascii")

    with pytest.raises(governance.GovernanceError, match="noncanonical line wrapping"):
        _validate_signed_envelope(envelope)


def test_sshsig_rejects_noncanonical_inner_base64_padding_bits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    ssh_key_material: tuple[str, SshKey, SshKey],
) -> None:
    executable, signing_key, _ = ssh_key_material
    _trust_key(monkeypatch, signing_key)
    envelope = _sign_envelope(executable, signing_key, _unsigned_envelope(signing_key), tmp_path)
    armor = base64.b64decode(envelope["signature"], validate=True).decode("ascii")
    lines = armor.splitlines()
    encoded = "".join(lines[1:-1])
    padding = len(encoded) - len(encoded.rstrip("="))
    assert padding in {1, 2}
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    final_index = len(encoded) - padding - 1
    original_value = alphabet.index(encoded[final_index])
    unused_bits = 2 if padding == 1 else 4
    replacement_value = (original_value & ~((1 << unused_bits) - 1)) | 1
    assert replacement_value != original_value
    noncanonical_encoded = (
        encoded[:final_index] + alphabet[replacement_value] + encoded[final_index + 1 :]
    )
    assert base64.b64decode(noncanonical_encoded, validate=True) == base64.b64decode(
        encoded, validate=True
    )
    wrapped = "\n".join(
        noncanonical_encoded[index : index + 70]
        for index in range(0, len(noncanonical_encoded), 70)
    )
    noncanonical_armor = (
        "-----BEGIN SSH SIGNATURE-----\n" + wrapped + "\n-----END SSH SIGNATURE-----\n"
    )
    envelope["signature"] = base64.b64encode(noncanonical_armor.encode("ascii")).decode("ascii")

    with pytest.raises(governance.GovernanceError, match="armor base64 is not canonical"):
        _validate_signed_envelope(envelope)


def test_write_json_batch_installs_every_rendered_record(tmp_path: Path) -> None:
    existing = tmp_path / "existing.json"
    created = tmp_path / "nested" / "created.json"
    existing.write_bytes(b'{"old":true}\n')

    governance._write_json_batch(
        {
            existing: {"status": "replaced", "sequence": 1},
            created: {"status": "created", "sequence": 2},
        }
    )

    assert existing.read_bytes() == governance._render_json_bytes(
        {"status": "replaced", "sequence": 1}
    )
    assert created.read_bytes() == governance._render_json_bytes(
        {"status": "created", "sequence": 2}
    )
    assert list(tmp_path.rglob("*.tmp")) == []


def test_write_json_batch_rolls_back_an_earlier_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    first_before = b'{"version":"first-before"}\n'
    second_before = b'{"version":"second-before"}\n'
    first.write_bytes(first_before)
    second.write_bytes(second_before)
    real_replace = Path.replace

    def fail_second_install(source: Path, target: Path) -> Path:
        destination = Path(target)
        if destination == second and source.name.startswith(f".{second.name}."):
            raise OSError("injected second-install failure")
        return real_replace(source, target)

    monkeypatch.setattr(Path, "replace", fail_second_install)

    with pytest.raises(governance.GovernanceError, match="unable to install governance JSON batch"):
        governance._write_json_batch(
            {
                first: {"version": "first-after"},
                second: {"version": "second-after"},
            }
        )

    assert first.read_bytes() == first_before
    assert second.read_bytes() == second_before
    assert list(tmp_path.rglob("*.tmp")) == []


def test_write_json_batch_renders_every_record_before_touching_disk(tmp_path: Path) -> None:
    existing = tmp_path / "existing.json"
    never_created = tmp_path / "never-created.json"
    original = b'{"preserved":true}\n'
    existing.write_bytes(original)

    with pytest.raises(governance.GovernanceError, match="non-finite number"):
        governance._write_json_batch(
            {
                existing: {"preserved": False},
                never_created: {"invalid": float("nan")},
            }
        )

    assert existing.read_bytes() == original
    assert not never_created.exists()


def _git(repository: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    executable = shutil.which("git")
    if executable is None:
        pytest.skip("Git is unavailable")
    completed = subprocess.run(
        [executable, "-c", "core.longpaths=true", "-C", str(repository), *arguments],
        capture_output=True,
        check=False,
        text=True,
        timeout=10,
    )
    if completed.returncode != 0:
        pytest.fail(
            f"Git command failed ({' '.join(arguments)}): {completed.stderr or completed.stdout}"
        )
    return completed


def _initialize_git_repository(repository: Path) -> None:
    repository.mkdir(parents=True)
    _git(repository, "init", "--quiet")
    _git(repository, "config", "user.name", "Agent Assure Tests")
    _git(repository, "config", "user.email", "agent-assure-tests@example.invalid")


def test_trusted_executable_ignores_path_and_rejects_identity_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_directory = tmp_path / "untrusted-bin"
    fake_directory.mkdir()
    fake_name = "git.exe" if os.name == "nt" else "git"
    (fake_directory / fake_name).write_bytes(b"untrusted executable")
    monkeypatch.setenv("PATH", str(fake_directory))

    trusted_path = governance._trusted_executable("git")
    assert Path(trusted_path).resolve().parent != fake_directory.resolve()

    identity = governance.TRUSTED_EXECUTABLE_IDENTITIES["git"]
    tampered = dict(governance.TRUSTED_EXECUTABLE_IDENTITIES)
    tampered["git"] = governance.TrustedExecutableIdentity(
        path=identity.path,
        size_bytes=identity.size_bytes,
        sha256="0" * 64,
    )
    monkeypatch.setattr(governance, "TRUSTED_EXECUTABLE_IDENTITIES", tampered)
    with pytest.raises(governance.GovernanceError, match="executable identity changed"):
        governance._trusted_executable("git")


def test_local_git_configuration_accepts_only_the_governed_benign_profile(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    _initialize_git_repository(repository)
    _git(repository, "remote", "add", "origin", governance.APPROVED_ORIGIN_URL)
    _git(repository, "config", "gpg.format", "ssh")
    _git(repository, "config", "tag.gpgSign", "true")
    _git(repository, "config", "branch.main.remote", "origin")
    _git(repository, "config", "branch.main.merge", "refs/heads/main")

    governance._validate_repository_identity(repository)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("include.path", "../attacker-controlled-config"),
        ("core.fsmonitor", "attacker-monitor"),
        ("core.hooksPath", "attacker-hooks"),
        ("core.sshCommand", "attacker-transport"),
        ("credential.helper", "attacker-credential-helper"),
        ("http.proxy", "http://attacker.invalid"),
        ("http.sslVerify", "false"),
        ("protocol.file.allow", "always"),
        ("url.https://attacker.invalid/.insteadOf", "https://github.com/"),
        ("filter.attacker.clean", "attacker-filter"),
        ("diff.attacker.command", "attacker-diff"),
        ("remote.origin.proxy", "http://attacker.invalid"),
    ],
)
def test_local_git_configuration_rejects_integrity_affecting_options(
    tmp_path: Path, key: str, value: str
) -> None:
    repository = tmp_path / "repository"
    _initialize_git_repository(repository)
    _git(repository, "config", key, value)

    with pytest.raises(governance.GovernanceError, match="configuration forbids"):
        governance._validate_repository_identity(repository)


def _commit_all(repository: Path, message: str) -> str:
    _git(repository, "add", "--all")
    _git(repository, "commit", "--quiet", "--message", message)
    return _git(repository, "rev-parse", "HEAD^{commit}").stdout.strip()


def test_read_commit_blob_handles_a_long_exact_repository_path(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    _initialize_git_repository(repository)
    if os.name == "nt":
        _git(repository, "config", "core.longpaths", "true")
    relative_path = (
        "governance-artifacts-with-a-deliberately-long-directory-name/"
        "nested-evidence-with-a-deliberately-long-directory-name/"
        "another-nested-governance-directory-for-windows-long-path-coverage/"
        "one-more-level-to-exceed-the-legacy-windows-max-path-boundary/"
        "immutable-artifact-with-a-deliberately-long-filename.json"
    )
    artifact = repository / relative_path
    assert len(str(artifact.resolve())) > 260
    artifact.parent.mkdir(parents=True)
    payload = b'{"long_path":"read by immutable blob object id"}\n'
    artifact.write_bytes(payload)
    commit = _commit_all(repository, "long path fixture")

    assert (
        governance._read_commit_blob(
            repository,
            commit,
            relative_path,
            owner="long-path test artifact",
        )
        == payload
    )
    if os.name == "nt":
        # Long artifact names alone do not exercise Git's object-store paths.
        # Retain a sub-MAX_PATH repository root whose loose and packed objects
        # cross that boundary, as in the retained node-7 integration failures.
        padding = max(1, 230 - len(str(tmp_path.resolve())) - len("/repository-"))
        deep_repository = tmp_path / ("repository-" + "r" * padding)
        _initialize_git_repository(deep_repository)
        assert len(str(deep_repository.resolve())) >= 230
        deep_artifact = deep_repository / "evidence.json"
        deep_artifact.write_bytes(payload)
        deep_commit = _commit_all(deep_repository, "deep object-store fixture")
        for packed in (False, True):
            if packed:
                _git(deep_repository, "repack", "-a", "-d")
            assert governance._read_commit_blob(
                deep_repository,
                deep_commit,
                "evidence.json",
                owner="deep object-store test artifact",
            ) == payload


def test_read_commit_blob_treats_pathspec_metacharacters_as_literal(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    _initialize_git_repository(repository)
    literal_path = "evidence[1].json"
    literal_payload = b'{"selected":"literal bracketed path"}\n'
    (repository / literal_path).write_bytes(literal_payload)
    (repository / "evidence1.json").write_bytes(b'{"selected":"pathspec match"}\n')
    commit = _commit_all(repository, "literal pathspec fixture")

    assert (
        governance._read_commit_blob(
            repository,
            commit,
            literal_path,
            owner="literal-pathspec test artifact",
        )
        == literal_payload
    )


def test_read_commit_blob_surfaces_bounded_cat_file_diagnostics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    blob_id = b"a" * 40
    results = iter(
        [
            subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=b"100644 blob " + blob_id + b"\tevidence.json\x00",
                stderr=b"",
            ),
            subprocess.CompletedProcess(
                args=[],
                returncode=128,
                stdout=b"",
                stderr=b"fatal: " + b"diagnostic " * 1_000,
            ),
        ]
    )
    monkeypatch.setattr(governance, "_run_git", lambda *_args, **_kwargs: next(results))

    with pytest.raises(governance.GovernanceError) as captured:
        governance._read_commit_blob(
            tmp_path,
            "1" * 40,
            "evidence.json",
            owner="test artifact",
        )

    message = str(captured.value)
    assert "unable to read test artifact: evidence.json" in message
    assert "Git exited with status 128: fatal:" in message
    assert message.endswith("...)")
    assert len(message) < governance.MAX_GIT_DIAGNOSTIC_CHARS + 100


def test_shared_git_subprocess_policy_neutralizes_excludes_and_attributes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hooks_directory = tmp_path / "hooks"
    hooks_directory.mkdir()
    monkeypatch.setenv("GIT_CONFIG_COUNT", "3")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.excludesFile")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", str(tmp_path / "hostile-excludes"))
    monkeypatch.setenv("GIT_CONFIG_KEY_1", "core.attributesFile")
    monkeypatch.setenv("GIT_CONFIG_VALUE_1", str(tmp_path / "hostile-attributes"))
    monkeypatch.setenv("GIT_CONFIG_KEY_2", "core.longpaths")
    monkeypatch.setenv("GIT_CONFIG_VALUE_2", "false")
    monkeypatch.setenv("GIT_ATTR_NOSYSTEM", "0")

    environment = governance._governance_subprocess_environment()
    prefix = governance._git_invocation_prefix("trusted-git", hooks_directory)

    assert environment["GIT_ATTR_NOSYSTEM"] == "1"
    assert environment["GIT_CONFIG_GLOBAL"] == os.devnull
    assert environment["GIT_CONFIG_SYSTEM"] == os.devnull
    assert "GIT_CONFIG_COUNT" not in environment
    assert "GIT_CONFIG_KEY_0" not in environment
    assert "GIT_CONFIG_VALUE_0" not in environment
    assert "GIT_CONFIG_KEY_2" not in environment
    assert "GIT_CONFIG_VALUE_2" not in environment
    assert prefix == [
        "trusted-git",
        "--no-replace-objects",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.untrackedCache=false",
        "-c",
        "core.longpaths=true",
        "-c",
        "core.excludesFile=",
        "-c",
        "core.attributesFile=",
        "-c",
        f"core.hooksPath={hooks_directory.resolve()}",
        "-c",
        "credential.helper=",
        "-c",
        "http.proxy=",
        "-c",
        "http.sslVerify=true",
        "-c",
        "protocol.allow=never",
        "-c",
        "protocol.https.allow=always",
    ]


def _closure_bundle() -> dict[str, Any]:
    receipts = {
        "docs/governance/v1/completion-receipt-v1-base-01.json": {"ticket_id": "V1-BASE-01"},
        "docs/governance/v1/completion-receipt-v1-boot-01.json": {"ticket_id": "V1-BOOT-01"},
    }
    inventory = [
        {
            "path": path,
            "kind": "completion_receipt",
            "size_bytes": len(governance._render_json_bytes(receipt)),
            "sha256": governance.raw_digest(governance._render_json_bytes(receipt)),
        }
        for path, receipt in sorted(receipts.items())
    ]
    bundle: dict[str, Any] = {
        "release": "1.0.0a1",
        "status": "accepted",
        "artifact_inventory": inventory,
    }
    bundle["bundle_digest"] = governance.domain_digest(
        governance.BUNDLE_DOMAIN, governance._bundle_projection(bundle)
    )
    return bundle


def _create_result_commit(repository: Path) -> str:
    (repository / "base.txt").write_text("base\n", encoding="utf-8")
    _commit_all(repository, "base")
    (repository / "result.txt").write_text("reviewed result\n", encoding="utf-8")
    return _commit_all(repository, "result")


def _write_closure_files(repository: Path, bundle: dict[str, Any]) -> None:
    governance_root = repository / "docs" / "governance" / "v1"
    governance._write_json(
        governance_root / "completion-receipt-v1-base-01.json",
        {"ticket_id": "V1-BASE-01"},
    )
    governance._write_json(
        governance_root / "completion-receipt-v1-boot-01.json",
        {"ticket_id": "V1-BOOT-01"},
    )
    governance._write_json(governance_root / "governance-bundle.json", bundle)


def test_s1_closure_remains_verifiable_after_a_later_descendant(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    _initialize_git_repository(repository)
    result_commit = _create_result_commit(repository)
    bundle = _closure_bundle()
    _write_closure_files(repository, bundle)
    closure_commit = _commit_all(repository, "S1 closure")

    (repository / "later-sprint.txt").write_text("S2 work\n", encoding="utf-8")
    _commit_all(repository, "later descendant")

    governance._validate_s1_closure_checkout(
        repository,
        result_commit=result_commit,
        bundle=bundle,
    )
    with pytest.raises(
        governance.GovernanceError, match="acceptance checkout is not at the closure commit"
    ):
        governance._validate_s1_closure_checkout(
            repository,
            result_commit=result_commit,
            bundle=bundle,
            require_current_checkout=True,
        )

    _git(repository, "checkout", "--quiet", "--detach", closure_commit)
    governance._validate_s1_closure_checkout(
        repository,
        result_commit=result_commit,
        bundle=bundle,
        require_current_checkout=True,
    )


def test_s1_closure_rejects_a_commit_with_extra_paths(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    _initialize_git_repository(repository)
    result_commit = _create_result_commit(repository)
    bundle = _closure_bundle()
    _write_closure_files(repository, bundle)
    (repository / "unauthorized.txt").write_text("not closure evidence\n", encoding="utf-8")
    _commit_all(repository, "contaminated closure")

    with pytest.raises(
        governance.GovernanceError,
        match="exactly one reachable linear closure commit",
    ):
        governance._validate_s1_closure_checkout(
            repository,
            result_commit=result_commit,
            bundle=bundle,
        )


def test_s1_closure_must_be_on_the_current_head_lineage(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    _initialize_git_repository(repository)
    result_commit = _create_result_commit(repository)
    bundle = _closure_bundle()
    _write_closure_files(repository, bundle)
    closure_commit = _commit_all(repository, "S1 closure")
    _git(repository, "branch", "stale-s1-closure", closure_commit)
    _git(repository, "checkout", "--quiet", "--detach", result_commit)

    with pytest.raises(
        governance.GovernanceError,
        match="exactly one reachable linear closure commit",
    ):
        governance._validate_s1_closure_checkout(
            repository,
            result_commit=result_commit,
            bundle=bundle,
        )


def test_reviewed_commit_rejects_false_artifact_size(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    _initialize_git_repository(repository)
    (repository / "artifact.txt").write_bytes(b"reviewed\n")
    result_commit = _commit_all(repository, "reviewed artifact")
    payload = b"reviewed\n"

    with pytest.raises(governance.GovernanceError, match="artifact size differs"):
        governance._validate_reviewed_commit(
            repository,
            base_commit=result_commit,
            result_commit=result_commit,
            artifacts=[
                {
                    "path": "artifact.txt",
                    "kind": "verification",
                    "size_bytes": len(payload) + 1,
                    "sha256": governance.raw_digest(payload),
                }
            ],
        )


def test_s1_result_commit_must_be_the_direct_child_of_the_pinned_base(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    _initialize_git_repository(repository)
    (repository / "base.txt").write_text("base\n", encoding="utf-8")
    base_commit = _commit_all(repository, "base")
    artifact = repository / "artifact.txt"
    artifact.write_text("intermediate\n", encoding="utf-8")
    _commit_all(repository, "intermediate S1 commit")
    artifact.write_text("final\n", encoding="utf-8")
    result_commit = _commit_all(repository, "result")
    payload = artifact.read_bytes()

    with pytest.raises(
        governance.GovernanceError,
        match="direct, non-merge child of the pinned base",
    ):
        governance._validate_s1_commit_scope(
            repository,
            base_commit=base_commit,
            result_commit=result_commit,
            inventory=[
                {
                    "path": "artifact.txt",
                    "kind": "verification",
                    "size_bytes": len(payload),
                    "sha256": governance.raw_digest(payload),
                }
            ],
        )


def _corrective_authorization_for_test(paths: list[str]) -> dict[str, Any]:
    return {
        "format": "agent-assure-s1-corrective-kickoff-authorization/1",
        "authorization_status": "authorized",
        "signed_claim_artifact": {
            "sha256": governance.CORRECTIVE_KICKOFF_CLAIM_DIGEST,
        },
        "signed_claim": {"tracked_allowed_paths": sorted(paths)},
    }


def test_corrective_result_topology_binds_direct_c1_child_and_exact_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    _initialize_git_repository(repository)
    (repository / "base.txt").write_bytes(b"generation one closure\n")
    c1 = _commit_all(repository, "C1")
    monkeypatch.setattr(governance, "S1_ACCEPTANCE_V1_CLOSURE_COMMIT", c1)
    result_path = "docs/governance/v1/corrected.json"
    authorization = _corrective_authorization_for_test(
        [result_path, *governance.S1_CORRECTIVE_CLOSURE_PATHS]
    )
    target = repository / result_path
    target.parent.mkdir(parents=True)
    target.write_bytes(b'{"corrected":true}\n')
    r2 = _commit_all(repository, "R2")

    inventory = governance._corrective_result_artifact_inventory(
        repository,
        result_commit=r2,
        corrective_authorization=authorization,
        expected_result_parent=c1,
    )

    assert inventory == [
        {
            "path": result_path,
            "kind": "governance_record",
            "change_status": "A",
            "size_bytes": len(b'{"corrected":true}\n'),
            "sha256": governance.raw_digest(b'{"corrected":true}\n'),
        }
    ]


def test_corrective_result_topology_rejects_unsigned_path_and_non_direct_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    _initialize_git_repository(repository)
    (repository / "base.txt").write_text("generation one closure\n", encoding="utf-8")
    c1 = _commit_all(repository, "C1")
    monkeypatch.setattr(governance, "S1_ACCEPTANCE_V1_CLOSURE_COMMIT", c1)
    allowed_path = "docs/governance/v1/corrected.json"
    authorization = _corrective_authorization_for_test(
        [allowed_path, *governance.S1_CORRECTIVE_CLOSURE_PATHS]
    )
    (repository / "unauthorized.txt").write_text("not authorized\n", encoding="utf-8")
    unauthorized_r2 = _commit_all(repository, "unauthorized R2")

    with pytest.raises(governance.GovernanceError, match="unauthorized paths"):
        governance._corrective_result_artifact_inventory(
            repository,
            result_commit=unauthorized_r2,
            corrective_authorization=authorization,
            expected_result_parent=c1,
        )

    target = repository / allowed_path
    target.parent.mkdir(parents=True)
    target.write_text('{"corrected":true}\n', encoding="utf-8")
    later = _commit_all(repository, "second corrective commit")
    with pytest.raises(governance.GovernanceError, match="direct, non-merge child"):
        governance._corrective_result_artifact_inventory(
            repository,
            result_commit=later,
            corrective_authorization=authorization,
            expected_result_parent=c1,
        )


def test_post_v2_control_topology_binds_a_proper_nonmerge_descendant_of_c2(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    _initialize_git_repository(repository)
    artifact = repository / "control.txt"
    artifact.write_text("base\n", encoding="utf-8")
    base = _commit_all(repository, "base")
    artifact.write_text("accepted generation two\n", encoding="utf-8")
    c2 = _commit_all(repository, "C2")
    artifact.write_text("post-v2 controls\n", encoding="utf-8")
    subject = _commit_all(repository, "post-v2 controls")
    monkeypatch.setattr(governance, "S1_ACCEPTANCE_V2_CLOSURE_COMMIT", c2)

    assert governance._post_v2_control_topology(
        repository,
        subject_commit=subject,
    ) == {
        "scope": "post_v2_control_verification_only",
        "authorization_effect": "none",
        "history_policy": "full_history_without_replacements_grafts_or_alternates/v1",
        "immutable_acceptance_v2_closure_commit": c2,
        "relationship": "proper_non_merge_descendant",
        "subject_commit": subject,
        "subject_parent_commit": c2,
    }
    with pytest.raises(governance.GovernanceError, match="proper descendant"):
        governance._post_v2_control_topology(repository, subject_commit=c2)
    with pytest.raises(governance.GovernanceError, match="does not descend"):
        governance._post_v2_control_topology(repository, subject_commit=base)

    alternate_repository = tmp_path / "alternate-repository"
    _initialize_git_repository(alternate_repository)
    alternates = repository / ".git/objects/info/alternates"
    alternates.write_text(
        (alternate_repository / ".git/objects").resolve().as_posix() + "\n",
        encoding="utf-8",
    )
    with pytest.raises(governance.GovernanceError, match="alternate object stores"):
        governance._post_v2_control_topology(repository, subject_commit=subject)


def _install_synthetic_frozen_runtime(
    runtime_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, Path]:
    runtime_root.mkdir(parents=True)
    python_file = runtime_root / "python.exe"
    python_dll = runtime_root / "python312.dll"
    python_file.write_bytes(b"synthetic-frozen-python")
    python_dll.write_bytes(b"synthetic-frozen-python-dll")
    base_count, base_size, base_digest = governance._base_runtime_inventory(runtime_root)
    monkeypatch.setattr(governance, "_FROZEN_PYTHON_ROOT", runtime_root)
    monkeypatch.setattr(governance, "_FROZEN_PYTHON_EXECUTABLE", python_file)
    monkeypatch.setattr(governance, "_FROZEN_PYTHON_EXECUTABLE_SIZE", python_file.stat().st_size)
    monkeypatch.setattr(
        governance,
        "_FROZEN_PYTHON_EXECUTABLE_SHA256",
        hashlib.sha256(python_file.read_bytes()).hexdigest(),
    )
    monkeypatch.setattr(governance, "_FROZEN_PYTHON_DLL", python_dll)
    monkeypatch.setattr(governance, "_FROZEN_PYTHON_DLL_SIZE", python_dll.stat().st_size)
    monkeypatch.setattr(
        governance,
        "_FROZEN_PYTHON_DLL_SHA256",
        hashlib.sha256(python_dll.read_bytes()).hexdigest(),
    )
    monkeypatch.setattr(governance, "_FROZEN_BASE_RUNTIME_FILE_COUNT", base_count)
    monkeypatch.setattr(governance, "_FROZEN_BASE_RUNTIME_SIZE_BYTES", base_size)
    monkeypatch.setattr(governance, "_FROZEN_BASE_RUNTIME_SHA256", base_digest)
    return python_file, python_dll


def _post_r2_evidence_fixture(
    tmp_path: Path,
    result_commit: str,
    monkeypatch: pytest.MonkeyPatch,
    *,
    legacy_v3_policy: bool = True,
    subject_parent_commit: str | None = None,
) -> tuple[Path, dict[str, Any]]:
    root = tmp_path.resolve()
    local_exclude_bytes = (
        _install_synthetic_legacy_v3_git_exclude_fixture(monkeypatch)
        if legacy_v3_policy
        else governance.POST_V2_CONTROL_GIT_EXCLUDE_BYTES
    )
    evidence_root = tmp_path / (
        governance.POST_R2_SUITE_EVIDENCE_DIRECTORY
        if legacy_v3_policy
        else ".tmp/s1-acceptance/post-v2-control-fixture"
    )
    evidence_root.mkdir(parents=True)
    stdout = (
        b"....                                                                     [100%]\n"
        b"4 passed, 1 skipped, 1 xfailed in 1.25s\n"
    )
    stderr = b""
    (evidence_root / "pytest.stdout.bin").write_bytes(stdout)
    (evidence_root / "pytest.stderr.bin").write_bytes(stderr)
    runtime_root = (tmp_path / "synthetic-base-runtime").resolve()
    _install_synthetic_frozen_runtime(runtime_root, monkeypatch)
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "pyvenv.cfg").write_bytes(b"home = synthetic-base\n")
    site_packages = tmp_path / ".venv" / "Lib" / "site-packages" / "pytest"
    site_packages.mkdir(parents=True)
    runtime_source = site_packages / "__init__.py"
    runtime_source.write_bytes(b"# synthetic pytest runtime\n")
    expected_runtime_source = runtime_source.read_bytes()
    frozen_site_inventory = {
        "format": "agent-assure-s1-post-r2-test-runtime-inventory/1",
        "relative_root": ".venv/Lib/site-packages",
        "exclusion_policy": {
            "directory_names": ["__pycache__"],
            "forbidden_direct_file_suffixes": [".pyc", ".pyo"],
            "reason": "cache_directories_inert_under_fresh_pycache_prefix",
        },
        "file_count": governance.POST_R2_TEST_RUNTIME_FILE_COUNT,
        "size_bytes": governance.POST_R2_TEST_RUNTIME_SIZE_BYTES,
        "sha256": "sha256:" + governance.POST_R2_TEST_RUNTIME_SHA256,
    }

    def synthetic_site_inventory(
        _root: Path,
        _site_packages: Path,
        *,
        expected_identity: tuple[int, int, str] = governance.POST_R2_TEST_RUNTIME_IDENTITY,
    ) -> dict[str, Any]:
        assert expected_identity == governance.POST_R2_TEST_RUNTIME_IDENTITY
        if runtime_source.read_bytes() != expected_runtime_source:
            raise governance.GovernanceError("post-R2 pytest site-packages inventory changed")
        return copy.deepcopy(frozen_site_inventory)

    monkeypatch.setattr(
        governance,
        "_post_r2_test_runtime_inventory",
        synthetic_site_inventory,
    )
    test_runtime = governance._post_r2_test_runtime_evidence(tmp_path)
    roadmap = tmp_path / "Agent_Assure_Implementation_Roadmap.md"
    roadmap.write_bytes(b"synthetic private roadmap\n")
    governance_directory = tmp_path / "docs" / "governance" / "v1"
    governance_directory.mkdir(parents=True, exist_ok=True)
    (governance_directory / "corrective-kickoff-authorization.json").write_bytes(
        b'{"synthetic":"authorization"}\n'
    )
    (governance_directory / "corrective-kickoff-authorization.schema.json").write_bytes(
        b'{"synthetic":"schema"}\n'
    )
    governance_sources = (
        governance._post_r2_governance_source_evidence(tmp_path, roadmap)
        if legacy_v3_policy
        else governance._post_v2_control_source_evidence(tmp_path, roadmap)
    )
    git_info = tmp_path / ".git" / "info"
    git_info.mkdir(parents=True, exist_ok=True)
    (git_info / "exclude").write_bytes(local_exclude_bytes)
    test_surface: dict[str, Any] = {
        "format": (
            "agent-assure-s1-post-r2-test-surface/1"
            if legacy_v3_policy
            else "agent-assure-s1-post-r2-test-surface/2"
        ),
        "subject_result_commit": result_commit,
        "directory_roots": list(governance.POST_R2_TEST_AFFECTING_DIRECTORIES),
        "tracked_root_files": list(governance.POST_R2_TRACKED_ROOT_FILES),
        "root_config_paths": list(
            governance._post_r2_root_test_config_paths(legacy_v3_policy=legacy_v3_policy)
        ),
        "cache_policy": {
            "excluded_directory_name": "__pycache__",
            "reason": "fresh_absolute_pycache_prefix_makes_source_adjacent_caches_inert",
            "forbidden_direct_file_suffixes": [".pyc", ".pyo"],
        },
        "local_exclude": governance._post_r2_git_exclude_evidence(
            root,
            legacy_v3_policy=legacy_v3_policy,
        ),
        "file_count": 1,
        "size_bytes": 1,
        "sha256": _digest("c"),
    }
    if not legacy_v3_policy:
        test_surface["root_import_policy"] = {
            "repository_root_on_initial_python_path": False,
            "forbidden_file_suffixes": list(governance.POST_R2_ROOT_IMPORTABLE_FILE_SUFFIXES),
            "allowed_local_root_entries": list(
                governance.POST_V2_CONTROL_ALLOWED_LOCAL_ROOT_ENTRIES
            ),
            "unexpected_top_level_entries": "rejected",
            "top_level_reparse_points": "rejected",
        }
        test_surface["local_attributes"] = {
            "path": ".git/info/attributes",
            "status": "absent",
        }
    monkeypatch.setattr(
        governance,
        "_post_r2_test_surface_evidence",
        lambda *_args, **_kwargs: copy.deepcopy(test_surface),
    )
    process_temp_root = (tmp_path / "external-process-temp-root").resolve()
    process_temp_root.mkdir()
    monkeypatch.setattr(governance, "POST_R2_PROCESS_TEMP_ROOT", process_temp_root)
    process_temp = (
        process_temp_root / f"{governance.POST_R2_PROCESS_TEMP_PREFIX}fixture"
    ).resolve()
    basetemp_path = process_temp / governance.POST_R2_PYTEST_BASETEMP_DIRECTORY
    environment = governance._post_r2_subprocess_environment(
        root,
        basetemp_path,
        process_temp=process_temp,
        legacy_v3_policy=legacy_v3_policy,
    )
    state = {
        "head_commit": result_commit,
        "clean": True,
        "status_command": ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        "status_stdout_size_bytes": 0,
        "status_stdout_sha256": governance.raw_digest(b""),
    }
    projection: dict[str, Any] = {
        "format": (
            "agent-assure-s1-post-r2-suite-evidence/3"
            if legacy_v3_policy
            else "agent-assure-s1-post-r2-suite-evidence/4"
        ),
        "acceptance_generation": 2 if legacy_v3_policy else None,
        "corrective_authorization_claim_digest": (
            governance.CORRECTIVE_KICKOFF_CLAIM_DIGEST if legacy_v3_policy else None
        ),
        "governance_sources": governance_sources,
        "repository_test_surface": test_surface,
        "command": {
            "argv": governance._post_r2_pytest_argv(
                root,
                basetemp=basetemp_path,
                process_temp=process_temp,
                test_surface=test_surface,
            ),
            "working_directory": str(tmp_path.resolve()),
            "environment": environment,
            "python_executable": test_runtime["base_runtime"]["python_executable"],
            "descendant_runtime": governance._post_r2_descendant_runtime_record(
                root,
                basetemp=basetemp_path,
                process_temp=process_temp,
                legacy_v3_policy=legacy_v3_policy,
            ),
            "bootstrap_input": governance._post_r2_bootstrap_input(
                root,
                basetemp=basetemp_path,
                process_temp=process_temp,
                legacy_v3_policy=legacy_v3_policy,
            )[1],
            "bytecode_policy": governance._post_r2_bytecode_policy(
                basetemp_path,
                legacy_v3_policy=legacy_v3_policy,
            ),
            "test_runtime": test_runtime,
        },
        "time_evidence": {
            **governance.ATTESTATION_V2_TIME_EVIDENCE,
            "started_at_utc": "2026-10-15T15:00:00Z",
            "completed_at_utc": "2026-10-15T15:01:00Z",
        },
        "repository_precondition": state,
        "repository_postcondition": copy.deepcopy(state),
        "execution": {
            "exit_code": 0,
            "outcome": "passed",
            "pytest_totals": {
                "collected": 6,
                "passed": 4,
                "failed": 0,
                "skipped": 1,
                "xfailed": 1,
                "xpassed": 0,
                "errors": 0,
            },
            "stdout": {
                "file_name": "pytest.stdout.bin",
                "size_bytes": len(stdout),
                "sha256": governance.raw_digest(stdout),
            },
            "stderr": {
                "file_name": "pytest.stderr.bin",
                "size_bytes": len(stderr),
                "sha256": governance.raw_digest(stderr),
            },
        },
    }
    if legacy_v3_policy:
        projection.update(
            {
                "subject_result_parent_commit": governance.S1_ACCEPTANCE_V1_CLOSURE_COMMIT,
                "subject_result_commit": result_commit,
            }
        )
    else:
        if subject_parent_commit is None:
            subject_parent_commit = "b" * 40
        projection["control_basis"] = {
            "scope": "post_v2_control_verification_only",
            "authorization_effect": "none",
            "history_policy": "full_history_without_replacements_grafts_or_alternates/v1",
            "immutable_acceptance_v2_closure_commit": governance.S1_ACCEPTANCE_V2_CLOSURE_COMMIT,
            "relationship": "proper_non_merge_descendant",
            "subject_commit": result_commit,
            "subject_parent_commit": subject_parent_commit,
        }
    record = {
        **projection,
        "evidence_digest": governance.domain_digest(
            (
                governance.POST_R2_SUITE_EVIDENCE_DOMAIN
                if legacy_v3_policy
                else governance.POST_R2_SUITE_EVIDENCE_V4_DOMAIN
            ),
            projection,
        ),
    }
    evidence_path = evidence_root / (
        "post-r2-suite-evidence.json" if legacy_v3_policy else "post-v2-control-suite-evidence.json"
    )
    governance._write_json(evidence_path, record)
    return evidence_path, record


def test_post_v2_control_capture_preserves_a_fresh_failed_run_with_nonacceptance_basis(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = (tmp_path / "repository").resolve()
    repository.mkdir()
    evidence_root = repository / ".tmp/s1-acceptance/post-v2-control-fresh-failed-suite"
    basetemp = tmp_path / "external-process-temp/synthetic-basetemp"
    subject_commit = "a" * 40
    subject_parent_commit = "b" * 40
    topology = {
        "scope": "post_v2_control_verification_only",
        "authorization_effect": "none",
        "history_policy": "full_history_without_replacements_grafts_or_alternates/v1",
        "immutable_acceptance_v2_closure_commit": governance.S1_ACCEPTANCE_V2_CLOSURE_COMMIT,
        "relationship": "proper_non_merge_descendant",
        "subject_commit": subject_commit,
        "subject_parent_commit": subject_parent_commit,
    }
    state = {
        "head_commit": subject_commit,
        "clean": True,
        "status_command": ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        "status_stdout_size_bytes": 0,
        "status_stdout_sha256": governance.raw_digest(b""),
    }
    test_runtime = {
        "base_runtime": {
            "python_executable": {
                "absolute_path": str(repository / "synthetic-python.exe"),
                "size_bytes": 1,
                "sha256": _digest("1"),
            }
        }
    }
    test_surface = {"file_count": 1, "size_bytes": 1, "sha256": _digest("2")}
    completed = subprocess.CompletedProcess(
        ["pytest"],
        1,
        stdout=b"1 failed in 0.01s\n",
        stderr=b"",
    )
    ordering: list[str] = []
    original_publish = governance._publish_post_r2_suite_evidence_directory

    def inspect_topology(*_args: Any, **_kwargs: Any) -> dict[str, str]:
        ordering.append("topology")
        return copy.deepcopy(topology)

    def validate_roadmap(*_args: Any, **_kwargs: Any) -> None:
        ordering.append("roadmap_check_ignore")

    def preflight_metadata(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        ordering.append("metadata_preflight")
        return {}

    def inspect_repository_state(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        ordering.append("git_status")
        return copy.deepcopy(state)

    def validate_embedded(
        record: dict[str, Any],
        **kwargs: Any,
    ) -> dict[str, Any]:
        ordering.append("embedded_validation")
        assert kwargs == {
            "expected_subject_commit": subject_commit,
            "expected_subject_parent_commit": subject_parent_commit,
            "require_passed": False,
        }
        assert record["execution"]["exit_code"] == 1
        assert record["execution"]["outcome"] == "failed"
        return copy.deepcopy(record)

    def publish(evidence_directory: Path, **kwargs: Any) -> None:
        ordering.append("publish")
        original_publish(evidence_directory, **kwargs)

    monkeypatch.setattr(
        governance,
        "_post_v2_control_topology",
        inspect_topology,
    )
    monkeypatch.setattr(governance, "validate_local_only_roadmap", validate_roadmap)
    monkeypatch.setattr(
        governance,
        "_post_v2_control_source_evidence",
        lambda *_args, **_kwargs: [],
    )
    monkeypatch.setattr(
        governance,
        "_post_v2_control_git_metadata_preflight",
        preflight_metadata,
    )
    monkeypatch.setattr(
        governance,
        "_post_r2_repository_state",
        inspect_repository_state,
    )
    monkeypatch.setattr(
        governance,
        "_post_v2_control_private_path",
        lambda _root, value, **_kwargs: Path(value).resolve(),
    )
    monkeypatch.setattr(
        governance,
        "_post_r2_test_runtime_evidence",
        lambda *_args, **_kwargs: copy.deepcopy(test_runtime),
    )
    monkeypatch.setattr(
        governance,
        "_post_r2_test_surface_evidence",
        lambda *_args, **_kwargs: copy.deepcopy(test_surface),
    )
    monkeypatch.setattr(
        governance,
        "_execute_post_r2_pytest",
        lambda *_args, **_kwargs: (
            basetemp,
            ["pytest"],
            {},
            {},
            {},
            "2026-10-15T15:00:00Z",
            completed,
            "2026-10-15T15:00:01Z",
        ),
    )
    monkeypatch.setattr(
        governance,
        "_validate_embedded_post_v2_control_suite_evidence",
        validate_embedded,
    )
    monkeypatch.setattr(
        governance,
        "_publish_post_r2_suite_evidence_directory",
        publish,
    )

    captured = governance.capture_post_v2_control_suite_evidence(
        repository,
        roadmap_path=repository / "Agent_Assure_Implementation_Roadmap.md",
        subject_commit=subject_commit,
        evidence_directory=evidence_root,
    )

    assert captured.reused is False
    assert captured["format"] == "agent-assure-s1-post-r2-suite-evidence/4"
    assert captured["acceptance_generation"] is None
    assert captured["corrective_authorization_claim_digest"] is None
    assert captured["control_basis"] == topology
    assert ordering[:5] == [
        "metadata_preflight",
        "topology",
        "roadmap_check_ignore",
        "metadata_preflight",
        "git_status",
    ]
    assert captured["execution"]["exit_code"] == 1
    assert captured["execution"]["outcome"] == "failed"
    assert captured["execution"]["pytest_totals"] == {
        "collected": 1,
        "passed": 0,
        "failed": 1,
        "skipped": 0,
        "xfailed": 0,
        "xpassed": 0,
        "errors": 0,
    }
    assert ordering.index("embedded_validation") < ordering.index("publish")
    assert (evidence_root / "post-v2-control-suite-evidence.json").is_file()
    assert (evidence_root / "pytest.stdout.bin").read_bytes() == completed.stdout
    assert (evidence_root / "pytest.stderr.bin").read_bytes() == completed.stderr


def _install_post_v2_capture_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    completed: subprocess.CompletedProcess[bytes],
) -> tuple[Path, Path, str, str, list[str]]:
    subject_commit = "a" * 40
    subject_parent_commit = "b" * 40
    _fixture_path, fixture = _post_r2_evidence_fixture(
        tmp_path,
        subject_commit,
        monkeypatch,
        legacy_v3_policy=False,
        subject_parent_commit=subject_parent_commit,
    )
    repository = tmp_path.resolve()
    evidence_root = repository / ".tmp/s1-acceptance/post-v2-control-capture-under-test"
    topology = copy.deepcopy(fixture["control_basis"])
    governance_sources = copy.deepcopy(fixture["governance_sources"])
    state = copy.deepcopy(fixture["repository_precondition"])
    test_runtime = copy.deepcopy(fixture["command"]["test_runtime"])
    test_surface = copy.deepcopy(fixture["repository_test_surface"])
    command = copy.deepcopy(fixture["command"])
    basetemp = Path(command["argv"][-1])
    ordering: list[str] = []
    original_validate = governance._validate_embedded_post_v2_control_suite_evidence
    original_publish = governance._publish_post_r2_suite_evidence_directory

    def validate_embedded(record: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        ordering.append("embedded_validation")
        return original_validate(record, **kwargs)

    def publish(evidence_directory: Path, **kwargs: Any) -> None:
        ordering.append("publish")
        original_publish(evidence_directory, **kwargs)

    monkeypatch.setattr(
        governance,
        "_post_v2_control_git_metadata_preflight",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        governance,
        "_post_v2_control_topology",
        lambda *_args, **_kwargs: copy.deepcopy(topology),
    )
    monkeypatch.setattr(governance, "validate_local_only_roadmap", lambda *_args: None)
    monkeypatch.setattr(
        governance,
        "_post_v2_control_private_path",
        lambda _root, value, **_kwargs: Path(value).resolve(),
    )
    monkeypatch.setattr(
        governance,
        "_post_v2_control_source_evidence",
        lambda *_args, **_kwargs: copy.deepcopy(governance_sources),
    )
    monkeypatch.setattr(
        governance,
        "_post_r2_repository_state",
        lambda *_args, **_kwargs: copy.deepcopy(state),
    )
    monkeypatch.setattr(
        governance,
        "_post_r2_test_runtime_evidence",
        lambda *_args, **_kwargs: copy.deepcopy(test_runtime),
    )
    monkeypatch.setattr(
        governance,
        "_post_r2_test_surface_evidence",
        lambda *_args, **_kwargs: copy.deepcopy(test_surface),
    )
    monkeypatch.setattr(
        governance,
        "_execute_post_r2_pytest",
        lambda *_args, **_kwargs: (
            basetemp,
            copy.deepcopy(command["argv"]),
            copy.deepcopy(command["environment"]),
            copy.deepcopy(command["descendant_runtime"]),
            copy.deepcopy(command["bootstrap_input"]),
            "2026-10-15T15:00:00Z",
            completed,
            "2026-10-15T15:00:01Z",
        ),
    )
    monkeypatch.setattr(
        governance,
        "_validate_embedded_post_v2_control_suite_evidence",
        validate_embedded,
    )
    monkeypatch.setattr(
        governance,
        "_publish_post_r2_suite_evidence_directory",
        publish,
    )
    return repository, evidence_root, subject_commit, subject_parent_commit, ordering


def test_post_v2_control_capture_publishes_valid_failed_evidence_after_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    completed = subprocess.CompletedProcess(
        ["pytest"],
        1,
        stdout=b"3 passed, 1 failed, 1 skipped, 1 xfailed in 0.01s\n",
        stderr=b"",
    )
    repository, evidence_root, subject_commit, _parent_commit, ordering = (
        _install_post_v2_capture_fixture(
            tmp_path,
            monkeypatch,
            completed=completed,
        )
    )

    captured = governance.capture_post_v2_control_suite_evidence(
        repository,
        roadmap_path=repository / "Agent_Assure_Implementation_Roadmap.md",
        subject_commit=subject_commit,
        evidence_directory=evidence_root,
    )

    assert captured.reused is False
    assert captured["execution"]["outcome"] == "failed"
    assert captured["execution"]["pytest_totals"]["failed"] == 1
    assert ordering == ["embedded_validation", "publish"]
    assert (evidence_root / "post-v2-control-suite-evidence.json").is_file()


def test_post_v2_control_capture_cannot_publish_deselected_totals(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    completed = subprocess.CompletedProcess(
        ["pytest"],
        0,
        stdout=b"1 passed, 1 deselected in 0.01s\n",
        stderr=b"",
    )
    repository, evidence_root, subject_commit, _parent_commit, ordering = (
        _install_post_v2_capture_fixture(
            tmp_path,
            monkeypatch,
            completed=completed,
        )
    )

    with pytest.raises(governance.GovernanceError, match="collected count"):
        governance.capture_post_v2_control_suite_evidence(
            repository,
            roadmap_path=repository / "Agent_Assure_Implementation_Roadmap.md",
            subject_commit=subject_commit,
            evidence_directory=evidence_root,
        )

    assert ordering == ["embedded_validation"]
    assert not evidence_root.exists()


def test_post_v2_control_capture_cannot_publish_errors_only_totals(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    completed = subprocess.CompletedProcess(
        ["pytest"],
        1,
        stdout=b"1 error in 0.01s\n",
        stderr=b"",
    )
    repository, evidence_root, subject_commit, _parent_commit, ordering = (
        _install_post_v2_capture_fixture(
            tmp_path,
            monkeypatch,
            completed=completed,
        )
    )

    with pytest.raises(
        governance.GovernanceError,
        match=r"reports no collected tests; .*stdout_size_bytes=.*stdout_sha256=sha256:",
    ):
        governance.capture_post_v2_control_suite_evidence(
            repository,
            roadmap_path=repository / "Agent_Assure_Implementation_Roadmap.md",
            subject_commit=subject_commit,
            evidence_directory=evidence_root,
        )

    assert ordering == []
    assert not evidence_root.exists()


@pytest.mark.parametrize(
    ("exit_code", "outcome"),
    ((1, "failed"), (0, "passed")),
)
def test_post_r2_capture_marks_failed_and_passing_existing_evidence_as_reused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    exit_code: int,
    outcome: str,
) -> None:
    repository = (tmp_path / "repository").resolve()
    repository.mkdir()
    evidence_root = repository / ".tmp/s1-acceptance/existing-suite"
    evidence_root.mkdir(parents=True)
    evidence_path = evidence_root / "post-r2-suite-evidence.json"
    record = {
        "evidence_digest": _digest("3"),
        "execution": {
            "exit_code": exit_code,
            "outcome": outcome,
            "pytest_totals": {
                "collected": 1,
                "passed": int(exit_code == 0),
                "failed": int(exit_code != 0),
                "skipped": 0,
                "xfailed": 0,
                "xpassed": 0,
                "errors": 0,
            },
        },
    }

    monkeypatch.setattr(
        governance,
        "_corrective_private_acceptance_path",
        lambda *_args, **_kwargs: evidence_root,
    )

    def validate_existing(path: Path, **kwargs: Any) -> dict[str, Any]:
        assert path == evidence_path
        assert kwargs["require_passed"] is False
        return copy.deepcopy(record)

    monkeypatch.setattr(
        governance,
        "validate_post_r2_suite_evidence_source",
        validate_existing,
    )
    monkeypatch.setattr(
        governance,
        "_execute_post_r2_pytest",
        lambda *_args, **_kwargs: pytest.fail("existing evidence must not rerun pytest"),
    )

    reused = governance.capture_post_r2_suite_evidence(
        repository,
        roadmap_path=repository / "Agent_Assure_Implementation_Roadmap.md",
        result_commit="a" * 40,
        corrective_authorization={},
        evidence_directory=evidence_root,
    )

    assert reused == record
    assert reused.reused is True


def test_post_r2_summary_parser_accepts_pass_and_skip_counts() -> None:
    totals = governance._parse_post_r2_pytest_totals(
        b"243 passed, 1 skipped in 90.25s\n",
        b"",
    )
    assert totals == {
        "collected": 244,
        "passed": 243,
        "failed": 0,
        "skipped": 1,
        "xfailed": 0,
        "xpassed": 0,
        "errors": 0,
    }
    governance._validate_successor_v3_native_pytest_result(
        subprocess.CompletedProcess(args=[], returncode=0, stdout=b"", stderr=b""),
        totals,
    )
    with pytest.raises(
        governance.GovernanceError,
        match="Generation-3 native full suite did not meet its exact pass rule",
    ):
        governance._validate_successor_v3_native_pytest_result(
            subprocess.CompletedProcess(args=[], returncode=0, stdout=b"", stderr=b""),
            {**totals, "errors": 1},
        )

    with pytest.raises(governance.GovernanceError, match="terminal summary"):
        governance._parse_post_r2_pytest_totals(
            b"." + b" " * 72 + b"[100%]\n",
            b"",
        )


@pytest.mark.parametrize(
    ("stdout", "stderr", "message"),
    (
        (
            b"243 passed, 1 skipped in 90.25s (0:01:30)\n",
            b"1 passed in 0.01s\n",
            "ambiguous terminal summaries",
        ),
        (
            b"1 passed in 0.01s\n2 passed in 0.02s\n",
            b"",
            "ambiguous terminal summaries",
        ),
        (
            b"243 passed,\n1 skipped in 90.25s (0:01:30)\n",
            b"",
            "ambiguous terminal summaries",
        ),
        (
            b"===== diagnostic: 243 passed in 90.25s =====\n",
            b"",
            "lacks a parseable terminal summary",
        ),
        (b"", b"1 passed in 0.01s\n", "terminal summary is not on stdout"),
    ),
)
def test_post_r2_summary_parser_rejects_ambiguous_or_nonterminal_candidates(
    stdout: bytes,
    stderr: bytes,
    message: str,
) -> None:
    with pytest.raises(governance.GovernanceError, match=message):
        governance._parse_post_r2_pytest_totals(stdout, stderr)


def test_post_r2_summary_failure_reports_execution_identity() -> None:
    completed = subprocess.CompletedProcess(
        ["pytest"],
        3,
        stdout=b"." + b" " * 72 + b"[100%]\n",
        stderr=b"bootstrap failed\n",
    )

    with pytest.raises(governance.GovernanceError) as raised:
        governance._parse_post_r2_pytest_execution_totals(completed)

    message = str(raised.value)
    assert "lacks a parseable terminal summary" in message
    assert "exit_code=3" in message
    assert "outcome=internal_error" in message
    assert f"stdout_size_bytes={len(completed.stdout)}" in message
    assert f"stdout_sha256={governance.raw_digest(completed.stdout)}" in message
    assert f"stderr_size_bytes={len(completed.stderr)}" in message
    assert f"stderr_sha256={governance.raw_digest(completed.stderr)}" in message


def test_post_r2_governed_verbosity_overrides_repository_quiet_addopt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from _pytest.config import get_config

    verbosity_arguments = [
        argument
        for argument in governance.POST_R2_PYTEST_ARGUMENTS
        if argument.startswith("--verbosity=")
    ]
    assert verbosity_arguments == ["--verbosity=-1"]

    monkeypatch.setenv("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")
    monkeypatch.chdir(ROOT)
    config = get_config()
    try:
        # The root pyproject contributes ``-q --disable-socket`` before these
        # CLI arguments, exactly as it does for the governed capture.
        config.parse(["-p", "pytest_socket", *verbosity_arguments])
        assert config.option.verbose == -1
        assert config.getoption("--disable-socket") is True
    finally:
        config._ensure_unconfigure()


def _fresh_post_r2_process_temp(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    suffix: str,
) -> tuple[Path, Path]:
    process_temp_root = (tmp_path / "external-process-temp-root").resolve()
    process_temp_root.mkdir()
    monkeypatch.setattr(governance, "POST_R2_PROCESS_TEMP_ROOT", process_temp_root)
    process_temp = (
        process_temp_root / f"{governance.POST_R2_PROCESS_TEMP_PREFIX}{suffix}"
    ).resolve()
    process_temp.mkdir()
    return process_temp_root, process_temp


def _simulate_reparse_metadata(
    monkeypatch: pytest.MonkeyPatch,
    attacked: Path,
) -> None:
    original_lstat = Path.lstat

    class ReparseMetadata:
        def __init__(self, metadata: os.stat_result) -> None:
            self._metadata = metadata
            self.st_file_attributes = (
                getattr(metadata, "st_file_attributes", 0) | stat.FILE_ATTRIBUTE_REPARSE_POINT
            )

        def __getattr__(self, name: str) -> Any:
            return getattr(self._metadata, name)

    def adversarial_lstat(path: Path) -> os.stat_result:
        metadata = original_lstat(path)
        if path == attacked:
            return ReparseMetadata(metadata)  # type: ignore[return-value]
        return metadata

    monkeypatch.setattr(Path, "lstat", adversarial_lstat)


def _post_r2_bootstrap_descendant_section(
    *,
    repository_root: Path,
    basetemp: Path,
    process_temp: Path,
) -> str:
    import ast

    command = governance._post_r2_pytest_bootstrap_source(
        repository_root,
        basetemp=basetemp,
        process_temp=process_temp,
    )
    body = ast.literal_eval(command.removeprefix("exec(").removesuffix(")"))
    start = body.index("process_temp_root = Path(")
    end = body.index("\nsys.executable = str(descendant_python)", start)
    return body[start:end]


def test_post_r2_suite_evidence_reparses_counts_and_binds_exact_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result_commit = "a" * 40
    evidence_path, record = _post_r2_evidence_fixture(tmp_path, result_commit, monkeypatch)

    assert (
        governance.validate_post_r2_suite_evidence_source(
            evidence_path,
            expected_result_commit=result_commit,
        )
        == record
    )

    tampered = copy.deepcopy(record)
    tampered["execution"]["pytest_totals"]["passed"] = 5
    projection = {key: value for key, value in tampered.items() if key != "evidence_digest"}
    tampered["evidence_digest"] = governance.domain_digest(
        governance.POST_R2_SUITE_EVIDENCE_DOMAIN, projection
    )
    governance._write_json(evidence_path, tampered)
    with pytest.raises(governance.GovernanceError, match="collected count|captured output"):
        governance.validate_post_r2_suite_evidence_source(
            evidence_path,
            expected_result_commit=result_commit,
        )


def test_post_v2_control_v4_evidence_validates_as_embedded_and_source_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result_commit = "a" * 40
    subject_parent_commit = "b" * 40
    evidence_path, record = _post_r2_evidence_fixture(
        tmp_path,
        result_commit,
        monkeypatch,
        legacy_v3_policy=False,
        subject_parent_commit=subject_parent_commit,
    )
    control_basis = copy.deepcopy(record["control_basis"])
    state = copy.deepcopy(record["repository_precondition"])
    monkeypatch.setattr(
        governance,
        "_post_v2_control_topology",
        lambda *_args, **_kwargs: copy.deepcopy(control_basis),
    )
    monkeypatch.setattr(
        governance,
        "_post_v2_control_git_metadata_preflight",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        governance,
        "_post_r2_repository_state",
        lambda *_args, **_kwargs: copy.deepcopy(state),
    )
    monkeypatch.setattr(
        governance,
        "_post_v2_control_private_path",
        lambda _root, value, **_kwargs: Path(value).resolve(),
    )
    monkeypatch.setattr(governance, "validate_local_only_roadmap", lambda *_args: None)

    assert (
        governance._validate_embedded_post_v2_control_suite_evidence(
            record,
            expected_subject_commit=result_commit,
            expected_subject_parent_commit=subject_parent_commit,
            require_passed=True,
        )
        == record
    )
    assert (
        governance.validate_post_v2_control_suite_evidence_source(
            evidence_path,
            expected_subject_commit=result_commit,
            expected_subject_parent_commit=subject_parent_commit,
            expected_repository_root=tmp_path.resolve(),
            require_passed=True,
        )
        == record
    )

    dirty_state = copy.deepcopy(record)
    dirty_state["repository_precondition"]["clean"] = False
    with pytest.raises(
        governance.GovernanceError,
        match=(
            rf"post-v2 control repository_precondition is not clean at subject commit "
            rf"{result_commit}"
        ),
    ):
        governance._validate_embedded_post_v2_control_suite_evidence(
            dirty_state,
            expected_subject_commit=result_commit,
            expected_subject_parent_commit=subject_parent_commit,
            require_passed=True,
        )

    with pytest.raises(governance.GovernanceError, match="wrong policy version"):
        governance.validate_post_r2_suite_evidence_source(
            evidence_path,
            expected_result_commit=result_commit,
            expected_repository_root=tmp_path.resolve(),
            require_passed=True,
        )


@pytest.mark.parametrize(
    ("field_path", "replacement"),
    (
        (
            (
                "repository_test_surface",
                "root_import_policy",
                "repository_root_on_initial_python_path",
            ),
            0,
        ),
        (("time_evidence", "actual_signature_time_claimed"), 0),
        (("repository_precondition", "clean"), 1),
        (("repository_postcondition", "status_stdout_size_bytes"), False),
        (("command", "test_runtime", "pyvenv_configuration", "size_bytes"), True),
        (("execution", "pytest_totals", "errors"), False),
        (("execution", "stdout", "size_bytes"), True),
        (("execution", "stderr", "size_bytes"), False),
    ),
    ids=(
        "surface-boolean-as-zero",
        "time-boolean-as-zero",
        "state-boolean-as-one",
        "state-size-as-false",
        "pyvenv-size-as-true",
        "total-as-false",
        "stdout-size-as-true",
        "stderr-size-as-false",
    ),
)
def test_post_v2_control_v4_rejects_json_boolean_integer_aliases(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field_path: tuple[str, ...],
    replacement: object,
) -> None:
    result_commit = "a" * 40
    subject_parent_commit = "b" * 40
    _evidence_path, record = _post_r2_evidence_fixture(
        tmp_path,
        result_commit,
        monkeypatch,
        legacy_v3_policy=False,
        subject_parent_commit=subject_parent_commit,
    )
    altered = copy.deepcopy(record)
    owner: dict[str, Any] = altered
    for component in field_path[:-1]:
        owner = owner[component]
    owner[field_path[-1]] = replacement
    projection = {key: value for key, value in altered.items() if key != "evidence_digest"}
    altered["evidence_digest"] = governance.domain_digest(
        governance.POST_R2_SUITE_EVIDENCE_V4_DOMAIN,
        projection,
    )

    with pytest.raises(governance.GovernanceError):
        governance._validate_embedded_post_v2_control_suite_evidence(
            altered,
            expected_subject_commit=result_commit,
            expected_subject_parent_commit=subject_parent_commit,
            require_passed=True,
        )


def test_post_v2_control_source_preflights_git_metadata_before_path_resolution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    def reject_metadata(repository_root: Path) -> None:
        assert repository_root == tmp_path.resolve()
        events.append("metadata_preflight")
        raise governance.GovernanceError("synthetic metadata rejection")

    def forbidden_path_resolution(*_args: Any, **_kwargs: Any) -> Path:
        events.append("private_path")
        raise AssertionError("path resolution ran before Git metadata preflight")

    monkeypatch.setattr(
        governance,
        "_post_v2_control_git_metadata_preflight",
        reject_metadata,
    )
    monkeypatch.setattr(
        governance,
        "_post_v2_control_private_path",
        forbidden_path_resolution,
    )

    with pytest.raises(governance.GovernanceError, match="synthetic metadata rejection"):
        governance.validate_post_v2_control_suite_evidence_source(
            tmp_path / "post-v2-control-suite-evidence.json",
            expected_subject_commit="a" * 40,
            expected_subject_parent_commit="b" * 40,
            expected_repository_root=tmp_path,
        )

    assert events == ["metadata_preflight"]


def test_post_r2_environment_removes_inherited_git_and_hypothesis_controls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    basetemp = (tmp_path / ".tmp/s1-acceptance/correction-v2-post-r2-pytest-environment").resolve()
    process_temp = (
        tmp_path / "external-process-temp-root/agent-assure-s1-post-r2-process-temp-environment"
    ).resolve()
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "hostile-git-dir"))
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(tmp_path / "hostile-global-config"))
    monkeypatch.setenv("GIT_ATTR_NOSYSTEM", "0")
    monkeypatch.setenv("GIT_CONFIG_KEY_2", "include.path")
    monkeypatch.setenv("GIT_CONFIG_VALUE_2", str(tmp_path / "hostile-included-config"))
    monkeypatch.setenv("git_work_tree", str(tmp_path / "hostile-work-tree"))
    monkeypatch.setenv("HYPOTHESIS_STORAGE_DIRECTORY", str(tmp_path / "hostile-db"))
    monkeypatch.setenv("AGENT_ASSURE_TEST_SENTINEL", "preserved")

    environment = governance._post_r2_subprocess_environment(
        tmp_path.resolve(),
        basetemp,
        process_temp=process_temp,
    )

    assert "GIT_DIR" not in environment
    assert environment["GIT_CONFIG_COUNT"] == "4"
    assert environment["GIT_CONFIG_GLOBAL"] == "NUL"
    assert environment["GIT_CONFIG_NOSYSTEM"] == "1"
    assert environment["GIT_CONFIG_KEY_0"] == "core.autocrlf"
    assert environment["GIT_CONFIG_VALUE_0"] == "true"
    assert environment["GIT_CONFIG_KEY_1"] == "safe.directory"
    assert environment["GIT_CONFIG_VALUE_1"] == str(tmp_path.resolve())
    assert environment["GIT_CONFIG_KEY_2"] == "core.excludesFile"
    assert environment["GIT_CONFIG_VALUE_2"] == "NUL"
    assert environment["GIT_CONFIG_KEY_3"] == "core.attributesFile"
    assert environment["GIT_CONFIG_VALUE_3"] == "NUL"
    assert environment["GIT_ATTR_NOSYSTEM"] == "1"
    assert "git_work_tree" not in environment
    assert "AGENT_ASSURE_TEST_SENTINEL" not in environment
    expected_hypothesis = str(basetemp / "hypothesis")
    assert environment["HYPOTHESIS_STORAGE_DIRECTORY"] == expected_hypothesis
    assert environment["TEMP"] == environment["TMP"] == str(process_temp / "temp")
    assert environment["PROCESSOR_ARCHITECTURE"] == "AMD64"
    assert "PROGRAMDATA" not in environment


@pytest.mark.skipif(os.name != "nt", reason="NUL is the Windows null device")
def test_post_r2_windows_null_git_policy_is_parseable_and_preserves_repository_policy(
    tmp_path: Path,
) -> None:
    basetemp = (tmp_path / "governed-basetemp").resolve()
    process_temp = (tmp_path / "governed-process-temp").resolve()
    (process_temp / "temp").mkdir(parents=True)
    environment = governance._post_r2_subprocess_environment(
        tmp_path.resolve(),
        basetemp,
        process_temp=process_temp,
    )
    git_identity = governance.TRUSTED_EXECUTABLE_IDENTITIES.get("git")
    if git_identity is None:
        pytest.skip("Git is unavailable")

    nested_repository = tmp_path / "nested-repository"
    nested_repository.mkdir()
    git_prefix = [git_identity.path, "-C", str(nested_repository)]

    def run_git(*arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [*git_prefix, *arguments],
            env=environment,
            capture_output=True,
            check=False,
            text=True,
        )

    initialized = run_git("init", "--quiet")
    assert initialized.returncode == 0, initialized.stderr

    excludes_file = nested_repository / ".git" / "info" / "exclude"
    excludes_file.write_text("/info-local-ignore.txt\n", encoding="utf-8", newline="\n")
    (nested_repository / ".gitattributes").write_text(
        "/tracked-attribute.txt agent-assure-test=set\n",
        encoding="utf-8",
        newline="\n",
    )
    for name in ("info-local-ignore.txt", "tracked-attribute.txt", "ordinary.txt"):
        (nested_repository / name).write_text(name, encoding="utf-8")

    excludes_config = run_git("config", "--get", "core.excludesFile")
    attributes_config = run_git("config", "--get", "core.attributesFile")
    assert excludes_config.returncode == 0, excludes_config.stderr
    assert excludes_config.stdout.strip() == "NUL"
    assert attributes_config.returncode == 0, attributes_config.stderr
    assert attributes_config.stdout.strip() == "NUL"

    ignored = run_git("check-ignore", "--verbose", "info-local-ignore.txt")
    ordinary = run_git("check-ignore", "--verbose", "ordinary.txt")
    attributed = run_git("check-attr", "agent-assure-test", "--", "tracked-attribute.txt")
    unattributed = run_git("check-attr", "agent-assure-test", "--", "ordinary.txt")
    assert ignored.returncode == 0, ignored.stderr
    assert ".git/info/exclude" in ignored.stdout.replace("\\", "/")
    assert ordinary.returncode == 1, ordinary.stderr
    assert attributed.returncode == 0, attributed.stderr
    assert attributed.stdout.rstrip().endswith("agent-assure-test: set")
    assert unattributed.returncode == 0, unattributed.stderr
    assert unattributed.stdout.rstrip().endswith("agent-assure-test: unspecified")


def test_post_r2_suite_evidence_rejects_subject_or_argv_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result_commit = "a" * 40
    _path, record = _post_r2_evidence_fixture(tmp_path, result_commit, monkeypatch)

    rebound = copy.deepcopy(record)
    rebound["subject_result_commit"] = "b" * 40
    with pytest.raises(governance.GovernanceError, match="subject_result_commit"):
        governance._validate_embedded_post_r2_suite_evidence(
            rebound,
            expected_result_commit=result_commit,
            require_passed=True,
        )

    altered_command = copy.deepcopy(record)
    altered_command["command"]["argv"][2] = "unittest"
    with pytest.raises(governance.GovernanceError, match="pytest argv"):
        governance._validate_embedded_post_r2_suite_evidence(
            altered_command,
            expected_result_commit=result_commit,
            require_passed=True,
        )

    altered_descendant = copy.deepcopy(record)
    altered_descendant["command"]["descendant_runtime"]["startup_guard"]["sha256"] = _digest("e")
    with pytest.raises(governance.GovernanceError, match="descendant runtime evidence"):
        governance._validate_embedded_post_r2_suite_evidence(
            altered_descendant,
            expected_result_commit=result_commit,
            require_passed=True,
        )

    altered_bootstrap = copy.deepcopy(record)
    altered_bootstrap["command"]["bootstrap_input"]["sha256"] = _digest("d")
    with pytest.raises(governance.GovernanceError, match="bootstrap stdin identity"):
        governance._validate_embedded_post_r2_suite_evidence(
            altered_bootstrap,
            expected_result_commit=result_commit,
            require_passed=True,
        )

    altered_architecture = copy.deepcopy(record)
    altered_architecture["command"]["environment"]["PROCESSOR_ARCHITECTURE"] = "x86"
    with pytest.raises(governance.GovernanceError, match="exact environment"):
        governance._validate_embedded_post_r2_suite_evidence(
            altered_architecture,
            expected_result_commit=result_commit,
            require_passed=True,
        )

    rebound_basetemp = copy.deepcopy(record)
    rebound_basetemp["command"]["argv"][-1] = str((tmp_path / "detached-pytest-basetemp").resolve())
    with pytest.raises(governance.GovernanceError, match="basetemp is not bound"):
        governance._validate_embedded_post_r2_suite_evidence(
            rebound_basetemp,
            expected_result_commit=result_commit,
            require_passed=True,
        )

    dirty_state = copy.deepcopy(record)
    dirty_state["repository_postcondition"]["clean"] = False
    with pytest.raises(
        governance.GovernanceError,
        match="post-R2 repository_postcondition is not clean R2",
    ):
        governance._validate_embedded_post_r2_suite_evidence(
            dirty_state,
            expected_result_commit=result_commit,
            require_passed=True,
        )


def test_post_r2_suite_evidence_source_binds_python_executable_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result_commit = "a" * 40
    evidence_path, record = _post_r2_evidence_fixture(tmp_path, result_commit, monkeypatch)
    executable = Path(record["command"]["python_executable"]["absolute_path"])
    executable.write_bytes(b"changed-python")

    with pytest.raises(governance.GovernanceError, match="executable source bytes changed"):
        governance.validate_post_r2_suite_evidence_source(
            evidence_path,
            expected_result_commit=result_commit,
        )


def test_post_r2_runtime_inventory_excludes_only_cache_directories_and_rejects_direct_pyc(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    site_packages = repository / ".venv/Lib/site-packages"
    package = site_packages / "synthetic_package"
    cache = package / "__pycache__"
    cache.mkdir(parents=True)
    (package / "__init__.py").write_bytes(b"VALUE = 'trusted'\n")
    (cache / "__init__.cpython-312.pyc").write_bytes(b"hostile ignored cache")

    measured = governance._measure_post_r2_test_runtime_inventory(
        repository,
        site_packages,
    )
    assert measured["file_count"] == 1
    expected_identity = (
        measured["file_count"],
        measured["size_bytes"],
        measured["sha256"].removeprefix("sha256:"),
    )
    assert (
        governance._post_r2_test_runtime_inventory(
            repository,
            site_packages,
            expected_identity=expected_identity,
        )
        == measured
    )

    (site_packages / "sourceless.pyc").write_bytes(b"direct bytecode")
    with pytest.raises(governance.GovernanceError, match="direct sourceless bytecode"):
        governance._post_r2_test_runtime_inventory(
            repository,
            site_packages,
            expected_identity=expected_identity,
        )


def test_post_r2_bootstrap_authenticates_runtime_and_surface_before_pytest_import() -> None:
    import ast

    basetemp = ROOT / ".tmp/s1-acceptance/correction-v2-post-r2-pytest-bootstrap"
    process_temp = (
        governance.POST_R2_PROCESS_TEMP_ROOT / f"{governance.POST_R2_PROCESS_TEMP_PREFIX}bootstrap"
    )
    command = governance._post_r2_pytest_bootstrap_source(
        ROOT,
        basetemp=basetemp,
        process_temp=process_temp,
    )
    assert not any(ord(character) < 0x20 for character in command)
    assert command.startswith("exec(") and command.endswith(")")
    body = ast.literal_eval(command.removeprefix("exec(").removesuffix(")"))
    site_gate = body.index("post-R2 authenticated site-packages inventory changed")
    surface_gate = body.index("post-R2 authenticated repository test surface changed")
    descendant_gate = body.index("post-R2 descendant runtime file set changed")
    executable_assignment = body.index("sys.executable = str(descendant_python)")
    launch_guard = body.index("descendant_guard_source =", executable_assignment)
    path_admission = body.index("sys.path[:0] = [str(source_root), str(site_packages)]")
    pytest_import = body.index('runpy.run_module("pytest"')
    assert site_gate < descendant_gate < executable_assignment < launch_guard
    assert surface_gate < descendant_gate < path_admission < pytest_import
    assert "str(repository_root)" not in body[path_admission:pytest_import]
    assert "_agent_assure_guarded_arguments" in body
    assert "pytest_basetemp.parent != process_temp" in body
    assert "pytest_basetemp.exists()" in body
    assert "import pytest" not in body

    descendant_payloads = governance._post_r2_descendant_runtime_payloads(
        ROOT,
        basetemp=basetemp,
        process_temp=process_temp,
    )
    authenticated_paths = descendant_payloads[
        f"Lib/site-packages/{governance.POST_R2_DESCENDANT_RUNTIME_PATHS_FILE}"
    ].decode("utf-8")
    assert authenticated_paths.splitlines() == [
        str(ROOT.resolve() / "src"),
        str(ROOT.resolve() / ".venv/Lib/site-packages"),
    ]

    bootstrap_payload, bootstrap_record = governance._post_r2_bootstrap_input(
        ROOT,
        basetemp=basetemp,
        process_temp=process_temp,
    )
    argv = governance._post_r2_pytest_argv(
        ROOT,
        basetemp=basetemp,
        process_temp=process_temp,
        test_surface={
            "format": "agent-assure-s1-post-r2-test-surface/2",
            "file_count": 1,
            "size_bytes": 1,
            "sha256": _digest("f"),
        },
    )
    assert bootstrap_payload == command.encode("utf-8")
    assert bootstrap_record == {
        "transport": "python_stdin_utf8",
        "size_bytes": len(bootstrap_payload),
        "sha256": governance.raw_digest(bootstrap_payload),
    }
    assert argv[8] == "-"
    assert command not in argv
    assert "-q" not in governance.POST_R2_PYTEST_ARGUMENTS
    assert argv.count("--verbosity=-1") == 1
    assert sum(len(value) for value in argv) < 8_192


def test_post_v2_root_config_inventory_extends_v3_exactly_in_parent_and_bootstrap() -> None:
    import ast

    basetemp = ROOT / ".tmp/s1-acceptance/post-v2-root-config-bootstrap"
    process_temp = (
        governance.POST_R2_PROCESS_TEMP_ROOT
        / f"{governance.POST_R2_PROCESS_TEMP_PREFIX}root-config-bootstrap"
    )
    legacy_paths = governance._post_r2_root_test_config_paths(legacy_v3_policy=True)
    hardened_paths = governance._post_r2_root_test_config_paths(legacy_v3_policy=False)

    assert legacy_paths == governance.POST_R2_ROOT_TEST_CONFIG_PATHS
    assert hardened_paths == (
        *legacy_paths,
        ".pytest.ini",
        ".pytest.toml",
    )

    legacy_source = governance._post_r2_pytest_bootstrap_source(
        ROOT,
        basetemp=basetemp,
        process_temp=process_temp,
        legacy_v3_policy=True,
    )
    hardened_source = governance._post_r2_pytest_bootstrap_source(
        ROOT,
        basetemp=basetemp,
        process_temp=process_temp,
    )
    legacy_body = ast.literal_eval(legacy_source.removeprefix("exec(").removesuffix(")"))
    hardened_body = ast.literal_eval(hardened_source.removeprefix("exec(").removesuffix(")"))
    assert f"root_configs = {legacy_paths!r}" in legacy_body
    assert f"root_configs = {hardened_paths!r}" in hardened_body
    assert ".pytest.ini" not in legacy_body
    assert ".pytest.toml" not in legacy_body
    assert "post-R2 unexpected top-level entry" in hardened_body
    assert hardened_body.index("candidate_metadata = candidate.lstat()") < hardened_body.index(
        "candidate.name not in allowed_root_entries"
    )


def test_post_v2_pytest_argv_is_hermetic_while_v3_remains_value_exact(
    tmp_path: Path,
) -> None:
    root = (tmp_path / "repository").resolve()
    basetemp = (tmp_path / "external-process-temp/pytest").resolve()
    process_temp = basetemp.parent
    common_surface = {
        "file_count": 7,
        "size_bytes": 11,
        "sha256": _digest("f"),
    }
    legacy = governance._post_r2_pytest_argv(
        root,
        basetemp=basetemp,
        process_temp=process_temp,
        test_surface={
            **common_surface,
            "format": "agent-assure-s1-post-r2-test-surface/1",
        },
    )
    hardened = governance._post_r2_pytest_argv(
        root,
        basetemp=basetemp,
        process_temp=process_temp,
        test_surface={
            **common_surface,
            "format": "agent-assure-s1-post-r2-test-surface/2",
        },
    )
    shared_prefix = [
        str(governance._FROZEN_PYTHON_EXECUTABLE),
        *governance.POST_R2_PYTHON_ARGUMENTS,
        "-X",
        f"pycache_prefix={basetemp / 'python-bytecode-cache'}",
        "-",
        str(root),
        str(root / "src"),
        str(root / ".venv/Lib/site-packages"),
        str(basetemp / "python-bytecode-cache"),
        "7",
        "11",
        _digest("f"),
    ]
    assert legacy == [
        *shared_prefix,
        *governance.POST_R2_PYTEST_ARGUMENTS,
        "--basetemp",
        str(basetemp),
    ]
    assert hardened == [
        *shared_prefix,
        *governance.POST_R2_PYTEST_ARGUMENTS,
        "-c",
        str(root / "pyproject.toml"),
        f"--rootdir={root}",
        f"--confcutdir={root}",
        "-o",
        "addopts=",
        "-o",
        "pythonpath=src",
        "-o",
        "norecursedirs=__pycache__",
        "-o",
        "python_files=test_*.py *_test.py",
        "-o",
        "python_classes=Test",
        "-o",
        "python_functions=test",
        "--import-mode=importlib",
        "--strict-config",
        "--strict-markers",
        "--disable-socket",
        str(root / "tests"),
        "--basetemp",
        str(basetemp),
    ]


def test_post_v2_pytest_argv_overrides_hostile_collection_and_path_configuration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from _pytest.config import get_config

    parent = tmp_path / "parent"
    root = (parent / "repository").resolve()
    (root / "src").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "tests/test_smoke.py").write_text("def test_ok(): pass\n", encoding="utf-8")
    (root / "tests/suffix_test.py").write_text(
        "def test_suffix_style_collection(): pass\n",
        encoding="utf-8",
    )
    hidden_cache = root / "tests/nested/__pycache__"
    hidden_cache.mkdir(parents=True)
    (hidden_cache / "test_hidden.py").write_text(
        "raise RuntimeError('cache-resident tests must remain inert')\n",
        encoding="utf-8",
    )
    (root / "pyproject.toml").write_text(
        "[tool.pytest.ini_options]\n"
        'addopts = "--maxfail=1 --collect-only"\n'
        'pythonpath = ["hostile-source"]\n'
        'testpaths = ["hostile-tests"]\n',
        encoding="utf-8",
    )
    (parent / "pytest.ini").write_text(
        "[pytest]\naddopts = --maxfail=2 --collect-only\npythonpath = parent-hostile\n",
        encoding="utf-8",
    )
    basetemp = (tmp_path / "external-process-temp/pytest").resolve()
    argv = governance._post_r2_pytest_argv(
        root,
        basetemp=basetemp,
        process_temp=basetemp.parent,
        test_surface={
            "format": "agent-assure-s1-post-r2-test-surface/2",
            "file_count": 1,
            "size_bytes": 1,
            "sha256": _digest("f"),
        },
    )
    pytest_arguments = argv[argv.index(_digest("f")) + 1 :]
    monkeypatch.setenv("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")
    monkeypatch.chdir(parent)
    config = get_config()
    try:
        config.parse(pytest_arguments)
        assert config.rootpath == root
        assert config.args == [str(root / "tests")]
        assert config.option.collectonly is False
        assert config.option.maxfail is None
        assert config.option.importmode == "importlib"
        assert config.getoption("--disable-socket") is True
        assert config.getini("pythonpath") == [root / "src"]
        assert config.getini("norecursedirs") == ["__pycache__"]
        assert config.getini("python_files") == ["test_*.py", "*_test.py"]
        assert config.getini("python_classes") == ["Test"]
        assert config.getini("python_functions") == ["test"]
    finally:
        config._ensure_unconfigure()

    environment = os.environ.copy()
    for name in ("PYTEST_ADDOPTS", "PYTEST_PLUGINS"):
        environment.pop(name, None)
    environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    completed = subprocess.run(
        [sys.executable, "-B", "-m", "pytest", *pytest_arguments],
        cwd=parent,
        env=environment,
        capture_output=True,
        check=False,
        text=True,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "2 passed" in completed.stdout


def test_post_r2_legacy_v3_bootstrap_and_runtime_bytes_reconstruct_under_explicit_policy() -> None:
    import ast

    basetemp = ROOT / ".tmp/s1-acceptance/synthetic-v3-basetemp"
    process_temp = (
        governance.POST_R2_PROCESS_TEMP_ROOT
        / f"{governance.POST_R2_PROCESS_TEMP_PREFIX}synthetic-v3"
    )
    legacy_command = governance._post_r2_pytest_bootstrap_source(
        ROOT,
        basetemp=basetemp,
        process_temp=process_temp,
        legacy_v3_policy=True,
    )
    current_command = governance._post_r2_pytest_bootstrap_source(
        ROOT,
        basetemp=basetemp,
        process_temp=process_temp,
    )
    legacy_body = ast.literal_eval(legacy_command.removeprefix("exec(").removesuffix(")"))
    current_body = ast.literal_eval(current_command.removeprefix("exec(").removesuffix(")"))
    compile(legacy_body, "<post-r2-legacy-v3-bootstrap>", "exec")
    compile(current_body, "<post-r2-hardened-v4-bootstrap>", "exec")
    canonical_exclude_guard = (
        f"if exclude_payload != {governance.POST_V2_CONTROL_GIT_EXCLUDE_BYTES!r}:"
    )
    assert canonical_exclude_guard not in legacy_body
    assert canonical_exclude_guard in current_body
    assert governance.POST_R2_GIT_EXCLUDE_SHA256 in legacy_body
    assert 'repository_root / ".git/info/attributes"' not in legacy_body
    assert 'repository_root / ".git/info/attributes"' in current_body
    assert "post-v2 local attributes must be absent" not in legacy_body
    assert "post-v2 local attributes must be absent" in current_body
    assert "sys.path[:0] = [str(source_root), str(repository_root), str(site_packages)]" in (
        legacy_body
    )
    assert "sys.path[:0] = [str(source_root), str(site_packages)]" in current_body
    assert legacy_command != current_command

    legacy_payload, legacy_record = governance._post_r2_bootstrap_input(
        ROOT,
        basetemp=basetemp,
        process_temp=process_temp,
        legacy_v3_policy=True,
    )
    assert legacy_payload == legacy_command.encode("utf-8")
    assert legacy_record == {
        "transport": "python_stdin_utf8",
        "size_bytes": len(legacy_payload),
        "sha256": governance.raw_digest(legacy_payload),
    }
    legacy_runtime_payloads = governance._post_r2_descendant_runtime_payloads(
        ROOT,
        basetemp=basetemp,
        process_temp=process_temp,
        legacy_v3_policy=True,
    )
    current_runtime_payloads = governance._post_r2_descendant_runtime_payloads(
        ROOT,
        basetemp=basetemp,
        process_temp=process_temp,
    )
    runtime_guard = f"Lib/site-packages/{governance.POST_R2_DESCENDANT_RUNTIME_GUARD_FILE}"
    compile(
        legacy_runtime_payloads[runtime_guard].decode("utf-8"),
        "<post-r2-legacy-v3-sitecustomize>",
        "exec",
    )
    compile(
        current_runtime_payloads[runtime_guard].decode("utf-8"),
        "<post-r2-hardened-v4-sitecustomize>",
        "exec",
    )
    path_payload = legacy_runtime_payloads[
        f"Lib/site-packages/{governance.POST_R2_DESCENDANT_RUNTIME_PATHS_FILE}"
    ].decode("utf-8")
    assert path_payload.splitlines() == [
        str(ROOT.resolve() / "src"),
        str(ROOT.resolve()),
        str(ROOT.resolve() / ".venv/Lib/site-packages"),
    ]
    legacy_environment = governance._post_r2_subprocess_environment(
        ROOT,
        basetemp,
        process_temp=process_temp,
        legacy_v3_policy=True,
    )
    assert legacy_environment["GIT_CONFIG_COUNT"] == "2"
    assert "GIT_ATTR_NOSYSTEM" not in legacy_environment
    assert "repository_root_import_policy" not in governance._post_r2_bytecode_policy(
        basetemp,
        legacy_v3_policy=True,
    )


@pytest.mark.skipif(
    os.name != "nt" or not governance._FROZEN_PYTHON_EXECUTABLE.is_file(),
    reason="the accepted S1 runtime is bound to the recorded Windows host",
)
def test_post_r2_descendant_runtime_enforces_recursive_isolated_launch_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    basetemp = (tmp_path / "governed-basetemp").resolve()
    _process_temp_root, process_temp = _fresh_post_r2_process_temp(
        tmp_path,
        monkeypatch,
        suffix="recursive-policy",
    )
    runtime = governance._prepare_post_r2_descendant_runtime(
        ROOT,
        basetemp=basetemp,
        process_temp=process_temp,
    )
    descendant = Path(runtime["python_executable"]["absolute_path"])
    pycache_prefix = basetemp / "python-bytecode-cache"
    environment = governance._post_r2_subprocess_environment(
        ROOT,
        basetemp,
        process_temp=process_temp,
    )
    environment["PYTHONPATH"] = str(Path(runtime["startup_guard"]["absolute_path"]).parent)
    environment[governance.POST_R2_DESCENDANT_NO_SITE_ENV] = "0"
    environment[governance.POST_R2_DESCENDANT_ORIGINAL_PYTHONPATH_ENV] = ""
    environment[governance.POST_R2_DESCENDANT_ORIGINAL_PYTHONPATH_PRESENT_ENV] = "0"
    probe = (
        "import json,platform,sys;"
        "import agent_assure;"
        "from packaging.markers import default_environment;"
        "print(json.dumps({"
        "'dont_write_bytecode':sys.dont_write_bytecode,"
        "'executable':sys.executable,"
        "'platform_machine':platform.machine(),"
        "'marker_machine':default_environment()['platform_machine'],"
        "'pycache_prefix':sys.pycache_prefix},sort_keys=True))"
    )
    program = f"""
import json
import os
import subprocess
import sys

isolated = subprocess.run(
    [sys.executable, "-I", "-c", {probe!r}],
    check=False,
    capture_output=True,
    text=True,
)
explicit = subprocess.run(
    ["python.exe", "-I", "-c", {probe!r}],
    executable=sys.executable,
    check=False,
    capture_output=True,
    text=True,
)
alias_environment = os.environ.copy()
alias_environment["PATH"] = (
    {str(governance._FROZEN_PYTHON_ROOT)!r}
    + os.pathsep
    + alias_environment["PATH"]
)
bare_alias = subprocess.run(
    ["python", "-I", "-c", {probe!r}],
    env=alias_environment,
    check=False,
    capture_output=True,
    text=True,
)
absolute_other = subprocess.run(
    [
        {str(governance._FROZEN_PYTHON_EXECUTABLE)!r},
        "-I",
        "-c",
        "import json,sys;print(json.dumps(sys.executable))",
    ],
    env=alias_environment,
    check=False,
    capture_output=True,
    text=True,
)
built = subprocess.run(
    [sys.executable, "-m", "build", "--help"],
    check=False,
    capture_output=True,
    text=True,
)
try:
    subprocess.run(
        [sys.executable, "-X", "pycache_prefix=hostile", "-c", "pass"],
        check=False,
    )
except RuntimeError as exc:
    conflict = str(exc)
else:
    conflict = "not-rejected"
print(json.dumps({{
    "absolute_other": {{
        "returncode": absolute_other.returncode,
        "stderr": absolute_other.stderr,
        "stdout": absolute_other.stdout,
        "value": json.loads(absolute_other.stdout) if absolute_other.returncode == 0 else None,
    }},
    "bare_alias": {{
        "returncode": bare_alias.returncode,
        "stderr": bare_alias.stderr,
        "stdout": bare_alias.stdout,
        "value": json.loads(bare_alias.stdout) if bare_alias.returncode == 0 else None,
    }},
    "build_returncode": built.returncode,
    "conflict": conflict,
    "explicit": {{
        "returncode": explicit.returncode,
        "stderr": explicit.stderr,
        "stdout": explicit.stdout,
        "value": json.loads(explicit.stdout) if explicit.returncode == 0 else None,
    }},
    "isolated": {{
        "returncode": isolated.returncode,
        "stderr": isolated.stderr,
        "stdout": isolated.stdout,
        "value": json.loads(isolated.stdout) if isolated.returncode == 0 else None,
    }},
}}, sort_keys=True))
"""
    completed = subprocess.run(
        [
            str(descendant),
            "-B",
            "-X",
            f"pycache_prefix={pycache_prefix}",
            "-c",
            program,
        ],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result["build_returncode"] == 0
    assert "cannot override" in result["conflict"]
    for invocation in (
        result["isolated"],
        result["explicit"],
        result["bare_alias"],
    ):
        assert invocation["returncode"] == 0, invocation["stderr"]
        value = invocation["value"]
        assert value == {
            "dont_write_bytecode": True,
            "executable": str(descendant),
            "marker_machine": "AMD64",
            "platform_machine": "AMD64",
            "pycache_prefix": str(pycache_prefix),
        }
    assert result["absolute_other"]["returncode"] == 0, result["absolute_other"]["stderr"]
    assert Path(result["absolute_other"]["value"]).resolve() == (
        governance._FROZEN_PYTHON_EXECUTABLE.resolve()
    )
    assert (
        governance._verify_post_r2_descendant_runtime(
            ROOT,
            basetemp=basetemp,
            process_temp=process_temp,
            require_empty_user_temp=False,
        )
        == runtime
    )
    startup_guard = Path(runtime["startup_guard"]["absolute_path"])
    startup_guard.write_bytes(startup_guard.read_bytes() + b"# tampered\n")
    with pytest.raises(governance.GovernanceError, match="runtime bytes changed"):
        governance._verify_post_r2_descendant_runtime(
            ROOT,
            basetemp=basetemp,
            process_temp=process_temp,
            require_empty_user_temp=False,
        )


@pytest.mark.parametrize("mutation", ("empty-directory", "reparse-directory"))
def test_post_r2_parent_rejects_nonexact_descendant_runtime_directories(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    basetemp = (tmp_path / "governed-basetemp").resolve()
    _process_temp_root, process_temp = _fresh_post_r2_process_temp(
        tmp_path,
        monkeypatch,
        suffix="parent-directory-regression",
    )
    _install_synthetic_frozen_runtime(
        (tmp_path / "synthetic-base-runtime").resolve(),
        monkeypatch,
    )
    runtime = governance._prepare_post_r2_descendant_runtime(
        ROOT,
        basetemp=basetemp,
        process_temp=process_temp,
    )
    unexpected = Path(runtime["root"]) / "unexpected-empty-directory"
    unexpected.mkdir()
    expected_error = "directory set changed"
    if mutation == "reparse-directory":
        _simulate_reparse_metadata(monkeypatch, unexpected)
        expected_error = "reparse point"

    with pytest.raises(governance.GovernanceError, match=expected_error):
        governance._verify_post_r2_descendant_runtime(
            ROOT,
            basetemp=basetemp,
            process_temp=process_temp,
            require_empty_user_temp=False,
        )


@pytest.mark.skipif(os.name != "nt", reason="8.3 aliases are a Windows filesystem feature")
def test_post_r2_safe_directory_does_not_treat_a_lexical_8dot3_alias_as_a_reparse(
    tmp_path: Path,
) -> None:
    import ctypes

    long_directory = tmp_path / "agent-assure-post-r2-long-directory-component"
    long_directory.mkdir()
    get_short_path_name = ctypes.windll.kernel32.GetShortPathNameW
    get_short_path_name.argtypes = [
        ctypes.c_wchar_p,
        ctypes.POINTER(ctypes.c_wchar),
        ctypes.c_ulong,
    ]
    get_short_path_name.restype = ctypes.c_ulong
    required = get_short_path_name(str(long_directory), None, 0)
    if required == 0:
        pytest.skip("the test volume does not expose an 8.3 alias")
    short_buffer = ctypes.create_unicode_buffer(required)
    written = get_short_path_name(str(long_directory), short_buffer, required)
    if written == 0 or written >= required:
        pytest.skip("the test volume could not return a stable 8.3 alias")
    short_directory = Path(short_buffer.value)
    if os.path.normcase(os.path.abspath(short_directory)) == os.path.normcase(
        os.path.abspath(long_directory)
    ):
        pytest.skip("8.3 name creation is disabled for the test directory")

    metadata = short_directory.lstat()
    assert stat.S_ISDIR(metadata.st_mode)
    assert not bool(getattr(metadata, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)
    assert (
        governance._post_r2_safe_directory(
            short_directory,
            owner="synthetic 8.3 directory",
        ).st_ino
        == metadata.st_ino
    )


@pytest.mark.parametrize(
    ("mutation", "expected_error"),
    (
        ("empty-directory", "directory set changed"),
        ("reparse-directory", "reparse point"),
        ("reparse-root", "process temporary root.*reparse point"),
        ("reparse-process-temp", "process temporary directory.*reparse point"),
    ),
)
def test_post_r2_bootstrap_rejects_runtime_directory_and_path_component_regressions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    expected_error: str,
) -> None:
    process_temp_root, process_temp = _fresh_post_r2_process_temp(
        tmp_path,
        monkeypatch,
        suffix="bootstrap-directory-regression",
    )
    _install_synthetic_frozen_runtime(
        (tmp_path / "synthetic-base-runtime").resolve(),
        monkeypatch,
    )
    basetemp = process_temp / governance.POST_R2_PYTEST_BASETEMP_DIRECTORY
    runtime = governance._prepare_post_r2_descendant_runtime(
        ROOT,
        basetemp=basetemp,
        process_temp=process_temp,
    )
    unexpected = Path(runtime["root"]) / "unexpected-empty-directory"
    if mutation in {"empty-directory", "reparse-directory"}:
        unexpected.mkdir()
    descendant_section = _post_r2_bootstrap_descendant_section(
        repository_root=ROOT,
        basetemp=basetemp,
        process_temp=process_temp,
    )
    monkeypatch.setenv(
        "TEMP",
        str(process_temp / governance.POST_R2_PROCESS_USER_TEMP_DIRECTORY),
    )
    monkeypatch.setenv(
        "TMP",
        str(process_temp / governance.POST_R2_PROCESS_USER_TEMP_DIRECTORY),
    )
    if mutation != "empty-directory":
        attacked = {
            "reparse-directory": unexpected,
            "reparse-root": process_temp_root,
            "reparse-process-temp": process_temp,
        }[mutation]
        _simulate_reparse_metadata(monkeypatch, attacked)

    namespace = {
        "Path": Path,
        "expected_pycache": basetemp / "python-bytecode-cache",
        "hashlib": hashlib,
        "os": os,
        "stat": governance.stat,
    }
    with pytest.raises(RuntimeError, match=expected_error):
        exec(descendant_section, namespace)  # noqa: S102 - execute the generated verifier


@pytest.mark.skipif(
    os.name != "nt" or not governance._FROZEN_PYTHON_EXECUTABLE.is_file(),
    reason="the accepted S1 runtime is bound to the recorded Windows host",
)
def test_post_r2_descendant_guard_survives_no_site_shadow_and_keyword_args(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    basetemp = (tmp_path / "governed-basetemp").resolve()
    _process_temp_root, process_temp = _fresh_post_r2_process_temp(
        tmp_path,
        monkeypatch,
        suffix="guard-recursion",
    )
    runtime = governance._prepare_post_r2_descendant_runtime(
        ROOT,
        basetemp=basetemp,
        process_temp=process_temp,
    )
    descendant = Path(runtime["python_executable"]["absolute_path"])
    pycache_prefix = basetemp / "python-bytecode-cache"
    environment = governance._post_r2_subprocess_environment(
        ROOT,
        basetemp,
        process_temp=process_temp,
    )
    environment["PYTHONPATH"] = str(Path(runtime["startup_guard"]["absolute_path"]).parent)
    environment[governance.POST_R2_DESCENDANT_NO_SITE_ENV] = "0"
    environment[governance.POST_R2_DESCENDANT_ORIGINAL_PYTHONPATH_ENV] = ""
    environment[governance.POST_R2_DESCENDANT_ORIGINAL_PYTHONPATH_PRESENT_ENV] = "0"

    shadow = tmp_path / "shadow"
    shadow.mkdir()
    (shadow / "sitecustomize.py").write_text(
        'import os\nos.environ["AGENT_ASSURE_SHADOW_LOADED"] = "yes"\n',
        encoding="utf-8",
    )
    (shadow / "shadow_target.py").write_text(
        "VALUE = 'caller-path'\n",
        encoding="utf-8",
    )
    hostile_cwd = tmp_path / "hostile-cwd"
    hostile_cwd.mkdir()
    cwd_marker = tmp_path / "hostile-cwd-loaded"
    (hostile_cwd / "sitecustomize.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(cwd_marker)!r}).write_text('loaded', encoding='utf-8')\n",
        encoding="utf-8",
    )
    warning_marker = tmp_path / "hostile-warning-loaded"
    (hostile_cwd / "evil.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(warning_marker)!r}).write_text('loaded', encoding='utf-8')\n"
        "class CustomWarning(Warning):\n"
        "    pass\n",
        encoding="utf-8",
    )
    pth_marker = tmp_path / "hostile-pth-loaded"
    pth_payload = (
        "import pathlib; "
        f"pathlib.Path({str(pth_marker)!r}).write_text('loaded', encoding='utf-8')\n"
    )
    python_user_directory = f"Python{sys.version_info.major}{sys.version_info.minor}"
    appdata = tmp_path / "hostile-appdata"
    user_base = tmp_path / "hostile-user-base"
    for user_site in (
        appdata / "Python" / python_user_directory / "site-packages",
        user_base / python_user_directory / "site-packages",
    ):
        user_site.mkdir(parents=True)
        (user_site / "hostile.pth").write_text(pth_payload, encoding="utf-8")
    leaf_probe = (
        "import json,subprocess,sys;"
        "print(json.dumps({"
        "'dont_write_bytecode':sys.dont_write_bytecode,"
        "'guarded':getattr(subprocess,'_agent_assure_s1_post_r2_launch_guard',None) "
        "is not None,"
        "'no_user_site':sys.flags.no_user_site,"
        "'pycache_prefix':sys.pycache_prefix},sort_keys=True))"
    )
    recursive_probe = f"""
import json
import os
import subprocess
import sys

try:
    import shadow_target
except ModuleNotFoundError:
    shadow_module = None
else:
    shadow_module = shadow_target.VALUE

stripped = subprocess.run(
    args=[sys.executable, "-c", {leaf_probe!r}],
    env={{}},
    check=False,
    capture_output=True,
    text=True,
)
print(json.dumps({{
    "guarded": getattr(
        subprocess,
        "_agent_assure_s1_post_r2_launch_guard",
        None,
    ) is not None,
    "python_environment": sorted(
        (key, value)
        for key, value in os.environ.items()
        if key.casefold() in {{
            "pythoncaseok",
            "pythondontwritebytecode",
            "pythonhome",
            "pythonnousersite",
            "pythonplatlibdir",
            "pythonpycacheprefix",
            "pythonsafepath",
            "pythonuserbase",
            "pythonwarnings",
        }}
    ),
    "safe_path": sys.flags.safe_path,
    "shadow_loaded": os.environ.get("AGENT_ASSURE_SHADOW_LOADED"),
    "shadow_module": shadow_module,
    "site_paths": [
        value for value in sys.path if value.casefold().endswith("site-packages")
    ],
    "sys_path_first": sys.path[0],
    "stripped": {{
        "returncode": stripped.returncode,
        "stderr": stripped.stderr,
        "value": json.loads(stripped.stdout) if stripped.returncode == 0 else None,
    }},
}}, sort_keys=True))
"""
    program = f"""
import json
import os
import subprocess
import sys

no_site = subprocess.run(
    args=[sys.executable, "-S", "-c", {recursive_probe!r}],
    check=False,
    capture_output=True,
    text=True,
)
shadow_environment = os.environ.copy()
shadow_environment["PYTHONPATH"] = {str(shadow)!r}
shadowed = subprocess.run(
    args=[sys.executable, "-c", {recursive_probe!r}],
    env=shadow_environment,
    check=False,
    capture_output=True,
    text=True,
)
shadowed_no_site = subprocess.run(
    args=[sys.executable, "-S", "-c", {recursive_probe!r}],
    env=shadow_environment,
    check=False,
    capture_output=True,
    text=True,
)
hostile_environment = os.environ.copy()
hostile_environment["APPDATA"] = {str(appdata)!r}
hostile_environment["pythondontwritebytecode"] = "0"
hostile_environment["pythonnousersite"] = "0"
hostile_environment["pythonpycacheprefix"] = {str(tmp_path / "hostile-cache")!r}
hostile_environment["pythonsafepath"] = "0"
hostile_environment["pythoncaseok"] = "1"
hostile_environment["pythonhome"] = {str(tmp_path / "hostile-home")!r}
hostile_environment["pythonplatlibdir"] = "hostile-lib"
hostile_environment["pythonuserbase"] = {str(user_base)!r}
hostile_environment["pythonwarnings"] = "default::evil.CustomWarning"
hostile = subprocess.run(
    args=[sys.executable, "-E", "-c", {recursive_probe!r}],
    cwd={str(hostile_cwd)!r},
    env=hostile_environment,
    check=False,
    capture_output=True,
    text=True,
)
safe_warning = subprocess.run(
    args=[sys.executable, "-W", "ignore::UserWarning", "-c", {leaf_probe!r}],
    check=False,
    capture_output=True,
    text=True,
)
explicit_keyword = subprocess.run(
    args=["caller-argv-zero", "-E", "-c", {leaf_probe!r}],
    executable="python.exe",
    check=False,
    capture_output=True,
    text=True,
)
explicit_positional_process = subprocess.Popen(
    ["caller-argv-zero", "-E", "-c", {leaf_probe!r}],
    -1,
    "python",
    None,
    subprocess.PIPE,
    subprocess.PIPE,
    None,
    True,
    False,
    None,
    os.environ.copy(),
    text=True,
)
explicit_positional_stdout, explicit_positional_stderr = (
    explicit_positional_process.communicate()
)
try:
    subprocess.run(args="python.exe -c pass", shell=True, check=False)
except RuntimeError as exc:
    shell_conflict = str(exc)
else:
    shell_conflict = "not-rejected"
try:
    subprocess.run(
        args=[
            sys.executable,
            "-W",
            "default::evil.CustomWarning",
            "-c",
            "pass",
        ],
        check=False,
    )
except RuntimeError as exc:
    warning_conflict = str(exc)
else:
    warning_conflict = "not-rejected"
option_conflicts = []
for options in (
    ["-W", "ignore"],
    ["--check-hash-based-pycs", "default"],
):
    try:
        subprocess.run(
            args=[
                sys.executable,
                *options,
                "-X",
                "pycache_prefix=hostile",
                "-c",
                "pass",
            ],
            check=False,
        )
    except RuntimeError as exc:
        option_conflicts.append(str(exc))
    else:
        option_conflicts.append("not-rejected")
print(json.dumps({{
    "no_site": {{
        "returncode": no_site.returncode,
        "stderr": no_site.stderr,
        "value": json.loads(no_site.stdout) if no_site.returncode == 0 else None,
    }},
    "option_conflicts": option_conflicts,
    "hostile": {{
        "returncode": hostile.returncode,
        "stderr": hostile.stderr,
        "value": json.loads(hostile.stdout) if hostile.returncode == 0 else None,
    }},
    "explicit_keyword": {{
        "returncode": explicit_keyword.returncode,
        "stderr": explicit_keyword.stderr,
        "value": (
            json.loads(explicit_keyword.stdout)
            if explicit_keyword.returncode == 0
            else None
        ),
    }},
    "explicit_positional": {{
        "returncode": explicit_positional_process.returncode,
        "stderr": explicit_positional_stderr,
        "value": (
            json.loads(explicit_positional_stdout)
            if explicit_positional_process.returncode == 0
            else None
        ),
    }},
    "safe_warning": {{
        "returncode": safe_warning.returncode,
        "stderr": safe_warning.stderr,
        "value": (
            json.loads(safe_warning.stdout) if safe_warning.returncode == 0 else None
        ),
    }},
    "shadowed": {{
        "returncode": shadowed.returncode,
        "stderr": shadowed.stderr,
        "value": json.loads(shadowed.stdout) if shadowed.returncode == 0 else None,
    }},
    "shadowed_no_site": {{
        "returncode": shadowed_no_site.returncode,
        "stderr": shadowed_no_site.stderr,
        "value": (
            json.loads(shadowed_no_site.stdout)
            if shadowed_no_site.returncode == 0
            else None
        ),
    }},
    "shell_conflict": shell_conflict,
    "warning_conflict": warning_conflict,
}}, sort_keys=True))
"""
    completed = subprocess.run(
        [
            str(descendant),
            "-B",
            "-X",
            f"pycache_prefix={pycache_prefix}",
            "-c",
            program,
        ],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert "must be a sequence" in result["shell_conflict"]
    assert "builtin warning class" in result["warning_conflict"]
    assert all("cannot override" in value for value in result["option_conflicts"])
    for name in ("hostile", "no_site", "shadowed", "shadowed_no_site"):
        invocation = result[name]
        assert invocation["returncode"] == 0, invocation["stderr"]
        value = invocation["value"]
        assert value["guarded"] is True
        assert value["stripped"]["returncode"] == 0, value["stripped"]["stderr"]
        assert value["stripped"]["value"] == {
            "dont_write_bytecode": True,
            "guarded": True,
            "no_user_site": 1,
            "pycache_prefix": str(pycache_prefix),
        }
    assert result["hostile"]["value"]["shadow_loaded"] is None
    assert result["hostile"]["value"]["safe_path"] is True
    assert result["hostile"]["value"]["python_environment"] == [
        ["PYTHONDONTWRITEBYTECODE", "1"],
        ["PYTHONNOUSERSITE", "1"],
        ["PYTHONPYCACHEPREFIX", str(pycache_prefix)],
        ["PYTHONSAFEPATH", "1"],
    ]
    assert result["no_site"]["value"]["site_paths"] == []
    assert result["no_site"]["value"]["shadow_loaded"] is None
    assert result["shadowed"]["value"]["shadow_loaded"] == "yes"
    for name in ("shadowed", "shadowed_no_site"):
        value = result[name]["value"]
        assert value["shadow_module"] == "caller-path"
        assert Path(value["sys_path_first"]).resolve() == shadow.resolve()
    assert result["shadowed_no_site"]["value"]["shadow_loaded"] is None
    expected_leaf = {
        "dont_write_bytecode": True,
        "guarded": True,
        "no_user_site": 1,
        "pycache_prefix": str(pycache_prefix),
    }
    for name in ("explicit_keyword", "explicit_positional"):
        assert result[name]["returncode"] == 0, result[name]["stderr"]
        assert result[name]["value"] == expected_leaf
    assert result["safe_warning"]["returncode"] == 0, result["safe_warning"]["stderr"]
    assert result["safe_warning"]["value"] == expected_leaf
    assert not cwd_marker.exists()
    assert not pth_marker.exists()
    assert not warning_marker.exists()


def test_fresh_pycache_prefix_defeats_hostile_unchecked_hash_bytecode(tmp_path: Path) -> None:
    import py_compile

    module_root = tmp_path / "module-root"
    module_root.mkdir()
    source = module_root / "hostile_cache_target.py"
    source.write_text("VALUE = 'hostile-cache'\n", encoding="utf-8")
    adjacent_cache = (
        source.parent / "__pycache__" / f"{source.stem}.{sys.implementation.cache_tag}.pyc"
    )
    adjacent_cache.parent.mkdir()
    py_compile.compile(
        str(source),
        cfile=str(adjacent_cache),
        doraise=True,
        invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
    )
    source.write_text("VALUE = 'trusted-source'\n", encoding="utf-8")
    bootstrap = (
        "import sys;"
        f"sys.path.insert(0, {str(module_root)!r});"
        "import hostile_cache_target;"
        "print(hostile_cache_target.VALUE)"
    )

    ungoverned_environment = os.environ.copy()
    for name in (
        "PYTHONDONTWRITEBYTECODE",
        "PYTHONNOUSERSITE",
        "PYTHONPYCACHEPREFIX",
        "PYTHONSAFEPATH",
    ):
        for candidate in tuple(ungoverned_environment):
            if candidate.casefold() == name.casefold():
                ungoverned_environment.pop(candidate)
    ungoverned = subprocess.run(
        [
            _independent_python_test_executable(),
            *governance.POST_R2_PYTHON_ARGUMENTS,
            "-c",
            bootstrap,
        ],
        capture_output=True,
        check=False,
        env=ungoverned_environment,
        text=True,
    )
    assert ungoverned.returncode == 0
    assert ungoverned.stdout.strip() == "hostile-cache"

    fresh_prefix = tmp_path / "fresh-bytecode-prefix"
    assert not fresh_prefix.exists()
    governed = subprocess.run(
        [
            _independent_python_test_executable(),
            *governance.POST_R2_PYTHON_ARGUMENTS,
            "-X",
            f"pycache_prefix={fresh_prefix}",
            "-c",
            bootstrap,
        ],
        capture_output=True,
        check=False,
        text=True,
    )
    assert governed.returncode == 0
    assert governed.stdout.strip() == "trusted-source"
    assert not fresh_prefix.exists()


def _minimal_post_v2_surface_repository(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    ignored_root_entry: str | None = None,
) -> tuple[Path, str]:
    repository = tmp_path / "repository"
    _initialize_git_repository(repository)
    _git(repository, "config", "core.autocrlf", "false")
    monkeypatch.setattr(governance, "POST_R2_TEST_AFFECTING_DIRECTORIES", ("tests",))
    monkeypatch.setattr(
        governance,
        "POST_R2_TRACKED_ROOT_FILES",
        (".gitignore", "pyproject.toml"),
    )
    monkeypatch.setattr(
        governance,
        "POST_R2_ROOT_TEST_CONFIG_PATHS",
        ("pyproject.toml",),
    )
    monkeypatch.setattr(
        governance,
        "POST_V2_CONTROL_ADDITIONAL_ROOT_TEST_CONFIG_PATHS",
        (".pytest.ini", ".pytest.toml"),
    )
    (repository / "tests").mkdir()
    (repository / "tests/test_sample.py").write_bytes(b"def test_ok(): pass\n")
    (repository / "pyproject.toml").write_bytes(b"[tool.pytest.ini_options]\n")
    (repository / ".gitignore").write_text(
        f"/{ignored_root_entry}\n" if ignored_root_entry is not None else "",
        encoding="utf-8",
    )
    (repository / ".git/info/exclude").write_bytes(governance.POST_V2_CONTROL_GIT_EXCLUDE_BYTES)
    return repository, _commit_all(repository, "synthetic post-v2 surface")


@pytest.mark.parametrize(
    ("config_name", "ignored"),
    ((".pytest.ini", False), (".pytest.toml", True)),
)
def test_post_v2_surface_rejects_untracked_or_ignored_hidden_pytest_configuration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_name: str,
    ignored: bool,
) -> None:
    repository, result_commit = _minimal_post_v2_surface_repository(
        tmp_path,
        monkeypatch,
        ignored_root_entry=config_name if ignored else None,
    )
    (repository / config_name).write_text(
        "[pytest]\naddopts = --collect-only\npythonpath = hostile\ntestpaths = hostile\n",
        encoding="utf-8",
    )
    if ignored:
        assert _git(repository, "check-ignore", "--", config_name).stdout.strip() == config_name
    else:
        assert (
            _git(
                repository,
                "ls-files",
                "--others",
                "--exclude-standard",
                "--",
                config_name,
            ).stdout.strip()
            == config_name
        )

    with pytest.raises(
        governance.GovernanceError,
        match=(
            "unexpected top-level entry|"
            rf"post-v2 control test surface differs from subject commit {result_commit}"
        ),
    ):
        governance._post_r2_test_surface_evidence(
            repository,
            result_commit=result_commit,
        )


@pytest.mark.parametrize(
    ("entry_name", "entry_kind"),
    (
        (".pytest.ini", "file"),
        (".pytest.toml", "file"),
        ("hostile.egg-info", "directory"),
        ("hostile.dist-info", "directory"),
    ),
)
def test_post_v2_generated_bootstrap_rejects_every_unexpected_root_attack(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    entry_name: str,
    entry_kind: str,
) -> None:
    repository = (tmp_path / "repository").resolve()
    site_packages = repository / ".venv/Lib/site-packages"
    site_packages.mkdir(parents=True)
    (repository / ".git/info").mkdir(parents=True)
    (repository / "src").mkdir()
    (repository / "tests").mkdir()
    (repository / "pyproject.toml").write_bytes(b"[tool.pytest.ini_options]\n")
    (repository / ".git/info/exclude").write_bytes(governance.POST_V2_CONTROL_GIT_EXCLUDE_BYTES)
    attacked = repository / entry_name
    if entry_kind == "directory":
        attacked.mkdir()
    else:
        attacked.write_bytes(b"[pytest]\naddopts = --collect-only\n")

    monkeypatch.setattr(governance, "POST_R2_TEST_AFFECTING_DIRECTORIES", ("src", "tests"))
    monkeypatch.setattr(governance, "POST_R2_TRACKED_ROOT_FILES", ("pyproject.toml",))
    monkeypatch.setattr(governance, "POST_R2_ROOT_TEST_CONFIG_PATHS", ("pyproject.toml",))
    empty_runtime_identity = (
        0,
        0,
        hashlib.sha256(governance.POST_R2_TEST_RUNTIME_INVENTORY_DOMAIN).hexdigest(),
    )
    process_temp_root = (tmp_path / "process-temp-root").resolve()
    process_temp_root.mkdir()
    monkeypatch.setattr(governance, "POST_R2_PROCESS_TEMP_ROOT", process_temp_root)
    process_temp = process_temp_root / f"{governance.POST_R2_PROCESS_TEMP_PREFIX}bootstrap"
    basetemp = process_temp / governance.POST_R2_PYTEST_BASETEMP_DIRECTORY
    pycache_prefix = basetemp / "python-bytecode-cache"
    command = governance._post_r2_pytest_bootstrap_source(
        repository,
        basetemp=basetemp,
        process_temp=process_temp,
        expected_runtime_identity=empty_runtime_identity,
    )

    completed = subprocess.run(
        [
            _independent_python_test_executable(),
            *governance.POST_R2_PYTHON_ARGUMENTS,
            "-X",
            f"pycache_prefix={pycache_prefix}",
            "-",
            str(repository),
            str(repository / "src"),
            str(site_packages),
            str(pycache_prefix),
            "0",
            "0",
            _digest("0"),
        ],
        capture_output=True,
        check=False,
        input=command,
        text=True,
    )

    assert completed.returncode != 0
    assert f"post-R2 unexpected top-level entry: {entry_name}" in completed.stderr


@pytest.mark.parametrize(
    ("entry_name", "simulate_reparse", "expected_error"),
    (
        ("hostile.egg-info", False, "unexpected top-level entry"),
        ("hostile.dist-info", False, "unexpected top-level entry"),
        (".tmp", True, "top-level reparse point"),
    ),
)
def test_post_v2_surface_rejects_packaging_metadata_and_every_top_level_reparse(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    entry_name: str,
    simulate_reparse: bool,
    expected_error: str,
) -> None:
    repository, result_commit = _minimal_post_v2_surface_repository(tmp_path, monkeypatch)
    attacked = repository / entry_name
    attacked.mkdir()
    if simulate_reparse:
        _simulate_reparse_metadata(monkeypatch, attacked)

    with pytest.raises(governance.GovernanceError, match=expected_error):
        governance._post_r2_test_surface_evidence(
            repository,
            result_commit=result_commit,
        )


def test_post_r2_test_surface_rejects_ignored_files_and_import_capable_root_dirs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    _initialize_git_repository(repository)
    _git(repository, "config", "core.autocrlf", "false")
    monkeypatch.setattr(governance, "POST_R2_TEST_AFFECTING_DIRECTORIES", ("tests",))
    monkeypatch.setattr(governance, "POST_R2_TRACKED_ROOT_FILES", ("pyproject.toml",))
    monkeypatch.setattr(
        governance,
        "POST_R2_ROOT_TEST_CONFIG_PATHS",
        ("pyproject.toml", "pytest.ini"),
    )
    (repository / "tests").mkdir()
    (repository / "tests/.gitignore").write_bytes(b"ignored.py\n")
    (repository / "tests/test_sample.py").write_bytes(b"def test_ok(): pass\n")
    (repository / "pyproject.toml").write_bytes(b"[tool.pytest.ini_options]\n")
    exclude = repository / ".git/info/exclude"
    exclude.write_bytes(governance.POST_V2_CONTROL_GIT_EXCLUDE_BYTES)
    exclude_payload = exclude.read_bytes()
    result_commit = _commit_all(repository, "synthetic R2")

    evidence = governance._post_r2_test_surface_evidence(
        repository,
        result_commit=result_commit,
    )

    attributes = repository / ".git/info/attributes"
    attributes.write_bytes(b"*.py filter=hostile\n")
    with pytest.raises(
        governance.GovernanceError,
        match=r"\.git/info/attributes must be absent",
    ):
        governance._post_r2_test_surface_evidence(
            repository,
            result_commit=result_commit,
        )
    attributes.unlink()

    cache = repository / "tests/__pycache__"
    cache.mkdir()
    (cache / "test_sample.cpython-312.pyc").write_bytes(b"hostile but inert cache")
    assert (
        governance._post_r2_test_surface_evidence(
            repository,
            result_commit=result_commit,
        )
        == evidence
    )

    tracked_test = repository / "tests/test_sample.py"
    tracked_test.write_bytes(b"def test_changed(): pass\n")
    with pytest.raises(
        governance.GovernanceError,
        match=rf"post-v2 control test-surface bytes differ from subject commit {result_commit}",
    ):
        governance._post_r2_test_surface_evidence(
            repository,
            result_commit=result_commit,
        )
    tracked_test.write_bytes(b"def test_ok(): pass\n")

    ignored = repository / "tests/ignored.py"
    ignored.write_text("raise RuntimeError('must not load')\n", encoding="utf-8")
    with pytest.raises(
        governance.GovernanceError,
        match=rf"post-v2 control test surface differs from subject commit {result_commit}",
    ):
        governance._post_r2_test_surface_evidence(
            repository,
            result_commit=result_commit,
        )
    ignored.unlink()

    untracked_config = repository / "pytest.ini"
    untracked_config.write_text("[pytest]\naddopts = -x\n", encoding="utf-8")
    with pytest.raises(governance.GovernanceError, match="unexpected top-level entry"):
        governance._post_r2_test_surface_evidence(
            repository,
            result_commit=result_commit,
        )
    untracked_config.unlink()

    exclude.write_bytes(exclude_payload + b"/host-specific-extra/\n")
    with pytest.raises(governance.GovernanceError, match="info/exclude policy changed"):
        governance._post_r2_test_surface_evidence(
            repository,
            result_commit=result_commit,
        )
    exclude.write_bytes(exclude_payload)

    build_surface = repository / "dist"
    build_surface.mkdir()
    (build_surface / "pytest.py").write_text("raise RuntimeError('shadow')\n", encoding="utf-8")
    with pytest.raises(governance.GovernanceError, match="unexpected top-level entry"):
        governance._post_r2_test_surface_evidence(
            repository,
            result_commit=result_commit,
        )


def test_legacy_v3_test_surface_diagnostics_keep_the_historical_r2_wording(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, result_commit = _minimal_post_v2_surface_repository(tmp_path, monkeypatch)
    legacy_exclude = _install_synthetic_legacy_v3_git_exclude_policy(monkeypatch)
    (repository / ".git/info/exclude").write_bytes(legacy_exclude)
    tracked_test = repository / "tests/test_sample.py"
    tracked_test.write_bytes(b"def test_changed(): pass\n")

    with pytest.raises(
        governance.GovernanceError,
        match=r"post-R2 test-surface bytes differ from R2: tests/test_sample\.py",
    ):
        governance._post_r2_test_surface_evidence(
            repository,
            result_commit=result_commit,
            legacy_v3_policy=True,
        )

    tracked_test.write_bytes(b"def test_ok(): pass\n")
    (repository / "tests/test_extra.py").write_bytes(b"def test_extra(): pass\n")
    with pytest.raises(
        governance.GovernanceError,
        match=r"post-R2 test surface differs from immutable R2",
    ):
        governance._post_r2_test_surface_evidence(
            repository,
            result_commit=result_commit,
            legacy_v3_policy=True,
        )


@pytest.mark.parametrize("attack_kind", ("directory", "symlink", "simulated_reparse"))
def test_post_v2_local_attributes_absence_rejects_nonregular_and_reparse_entries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    attack_kind: str,
) -> None:
    repository = tmp_path / "repository"
    info_directory = repository / ".git/info"
    info_directory.mkdir(parents=True)
    attributes = info_directory / "attributes"
    if attack_kind == "directory":
        attributes.mkdir()
    elif attack_kind == "symlink":
        target = repository / "hostile-attributes"
        target.write_bytes(b"*.py filter=hostile\n")
        try:
            os.symlink(target, attributes)
        except OSError as exc:
            pytest.skip(f"file symlinks are unavailable on this host: {exc}")
    else:
        attributes.write_bytes(b"*.py filter=hostile\n")
        _simulate_reparse_metadata(monkeypatch, attributes)

    with pytest.raises(
        governance.GovernanceError,
        match=r"\.git/info/attributes must be absent",
    ):
        governance._post_v2_git_attributes_absence_evidence(repository)


def test_post_v2_local_exclude_requires_canonical_bytes_while_v3_keeps_its_pin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    info_directory = repository / ".git/info"
    info_directory.mkdir(parents=True)
    exclude = info_directory / "exclude"
    canonical = b"/Agent_Assure_Implementation_Roadmap.md\n/.venv/\n/.tmp/\n"
    assert governance.POST_V2_CONTROL_GIT_EXCLUDE_BYTES == canonical

    exclude.write_bytes(canonical)
    assert governance._post_r2_git_exclude_evidence(repository) == {
        "path": ".git/info/exclude",
        "size_bytes": len(canonical),
        "sha256": governance.raw_digest(canonical),
    }
    with pytest.raises(governance.GovernanceError, match="exclude policy changed"):
        governance._post_r2_git_exclude_evidence(repository, legacy_v3_policy=True)

    synthetic_legacy_v3_bytes = _install_synthetic_legacy_v3_git_exclude_policy(monkeypatch)
    for noncanonical in (
        canonical + b"/host-specific-extra/\n",
        synthetic_legacy_v3_bytes,
        canonical.replace(b"\n", b"\r\n"),
        b"\xef\xbb\xbf" + canonical,
    ):
        exclude.write_bytes(noncanonical)
        with pytest.raises(governance.GovernanceError, match="exclude policy changed"):
            governance._post_r2_git_exclude_evidence(repository)

    exclude.write_bytes(synthetic_legacy_v3_bytes)
    assert governance._post_r2_git_exclude_evidence(
        repository,
        legacy_v3_policy=True,
    ) == {
        "path": ".git/info/exclude",
        "size_bytes": governance.POST_R2_GIT_EXCLUDE_SIZE_BYTES,
        "sha256": "sha256:" + governance.POST_R2_GIT_EXCLUDE_SHA256,
    }


def test_legacy_v3_local_exclude_pin_matches_schemas_and_accepted_records() -> None:
    expected = {
        "path": ".git/info/exclude",
        "size_bytes": 2368,
        "sha256": ("sha256:7c13bf60842aceead989daabbab30e5ae8fc3e4cf2100af9781e692790265060"),
    }
    assert governance.POST_R2_GIT_EXCLUDE_SIZE_BYTES == 2368
    assert (
        governance.POST_R2_GIT_EXCLUDE_SHA256
        == "7c13bf60842aceead989daabbab30e5ae8fc3e4cf2100af9781e692790265060"
    )

    def local_exclude_values(value: object) -> list[object]:
        found: list[object] = []
        if isinstance(value, dict):
            for key, child in value.items():
                if key == "local_exclude" and isinstance(child, dict):
                    found.append(child.get("const", child))
                found.extend(local_exclude_values(child))
        elif isinstance(value, list):
            for child in value:
                found.extend(local_exclude_values(child))
        return found

    for name in (
        "ticket-completion-receipt.schema.json",
        "governance-bundle.schema.json",
        "completion-receipt-v1-boot-01.json",
        "governance-bundle.json",
    ):
        assert local_exclude_values(_record(name)) == [expected], name


def test_post_v2_repository_state_preflights_git_metadata_before_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    expected_state = {"head_commit": "a" * 40, "clean": True}
    events: list[str] = []

    def preflight(_repository: Path) -> dict[str, dict[str, Any]]:
        events.append("metadata_preflight")
        return {}

    def inspect_status(_repository: Path) -> dict[str, Any]:
        events.append("git_status")
        return copy.deepcopy(expected_state)

    monkeypatch.setattr(governance, "_post_v2_control_git_metadata_preflight", preflight)
    monkeypatch.setattr(governance, "_post_r2_repository_state", inspect_status)

    assert governance._post_v2_control_repository_state(repository) == expected_state
    assert events == ["metadata_preflight", "git_status"]

    events.clear()

    def reject_metadata(_repository: Path) -> dict[str, dict[str, Any]]:
        events.append("metadata_preflight")
        raise governance.GovernanceError("synthetic local Git metadata rejection")

    monkeypatch.setattr(
        governance,
        "_post_v2_control_git_metadata_preflight",
        reject_metadata,
    )
    with pytest.raises(governance.GovernanceError, match="metadata rejection"):
        governance._post_v2_control_repository_state(repository)
    assert events == ["metadata_preflight"]


def test_post_r2_test_surface_rejects_an_ignored_native_extension_at_repository_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    native_suffix = next(
        (
            suffix
            for suffix in governance.POST_R2_ROOT_IMPORTABLE_FILE_SUFFIXES
            if suffix.endswith((".pyd", ".so"))
        ),
        None,
    )
    if native_suffix is None:
        pytest.skip("this interpreter does not declare a native extension suffix")
    artifact_name = f"hostile_root_extension{native_suffix}"
    repository = tmp_path / "repository"
    _initialize_git_repository(repository)
    _git(repository, "config", "core.autocrlf", "false")
    monkeypatch.setattr(governance, "POST_R2_TEST_AFFECTING_DIRECTORIES", ("tests",))
    monkeypatch.setattr(
        governance,
        "POST_R2_TRACKED_ROOT_FILES",
        (".gitignore", "pyproject.toml"),
    )
    monkeypatch.setattr(
        governance,
        "POST_R2_ROOT_TEST_CONFIG_PATHS",
        ("pyproject.toml",),
    )
    (repository / "tests").mkdir()
    (repository / "tests/test_sample.py").write_bytes(b"def test_ok(): pass\n")
    (repository / ".gitignore").write_text(f"/{artifact_name}\n", encoding="utf-8")
    (repository / "pyproject.toml").write_bytes(b"[tool.pytest.ini_options]\n")
    exclude = repository / ".git/info/exclude"
    exclude.write_bytes(governance.POST_V2_CONTROL_GIT_EXCLUDE_BYTES)
    result_commit = _commit_all(repository, "synthetic R2")
    artifact = repository / artifact_name
    artifact.write_bytes(b"ignored native extension payload")
    assert _git(repository, "check-ignore", "--", artifact_name).stdout.strip() == artifact_name

    with pytest.raises(
        governance.GovernanceError,
        match="unexpected top-level entry",
    ):
        governance._post_r2_test_surface_evidence(
            repository,
            result_commit=result_commit,
        )


def test_post_r2_test_surface_rejects_a_reparse_top_level_surface_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    _initialize_git_repository(repository)
    _git(repository, "config", "core.autocrlf", "false")
    monkeypatch.setattr(governance, "POST_R2_TEST_AFFECTING_DIRECTORIES", ("tests",))
    monkeypatch.setattr(governance, "POST_R2_TRACKED_ROOT_FILES", ("pyproject.toml",))
    monkeypatch.setattr(
        governance,
        "POST_R2_ROOT_TEST_CONFIG_PATHS",
        ("pyproject.toml",),
    )
    surface_root = repository / "tests"
    surface_root.mkdir()
    (surface_root / "test_sample.py").write_bytes(b"def test_ok(): pass\n")
    (repository / "pyproject.toml").write_bytes(b"[tool.pytest.ini_options]\n")
    exclude = repository / ".git/info/exclude"
    exclude.write_bytes(governance.POST_V2_CONTROL_GIT_EXCLUDE_BYTES)
    result_commit = _commit_all(repository, "synthetic R2")
    _simulate_reparse_metadata(monkeypatch, surface_root)

    with pytest.raises(
        governance.GovernanceError,
        match="top-level reparse point",
    ):
        governance._post_r2_test_surface_evidence(
            repository,
            result_commit=result_commit,
        )


def test_post_r2_preparation_failure_removes_the_allocated_process_temp(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    basetemp = (tmp_path / "governed-basetemp").resolve()
    _process_temp_root, process_temp = _fresh_post_r2_process_temp(
        tmp_path,
        monkeypatch,
        suffix="preparation-failure",
    )
    monkeypatch.setattr(
        governance,
        "_FROZEN_PYTHON_EXECUTABLE",
        tmp_path / "missing-frozen-python.exe",
    )

    with pytest.raises(FileNotFoundError):
        governance._prepare_post_r2_descendant_runtime(
            ROOT,
            basetemp=basetemp,
            process_temp=process_temp,
        )

    assert not process_temp.exists()


def test_post_r2_allocator_cleans_a_directory_that_fails_freshness_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    process_temp_root = (tmp_path / "external-process-temp-root").resolve()
    process_temp_root.mkdir()
    monkeypatch.setattr(governance, "POST_R2_PROCESS_TEMP_ROOT", process_temp_root)
    _initialize_git_repository(repository)
    (repository / ".gitignore").write_text(".tmp/\n", encoding="utf-8")
    _commit_all(repository, "governed local storage")
    original_mkdtemp = governance.tempfile.mkdtemp
    allocated_process_temps: list[Path] = []

    def dirty_process_temp(*args: Any, **kwargs: Any) -> str:
        allocated = Path(original_mkdtemp(*args, **kwargs))
        directory = kwargs.get("dir", args[2] if len(args) > 2 else None)
        if directory is not None and Path(directory) == process_temp_root:
            allocated_process_temps.append(allocated)
            (allocated / "unexpected-entry").write_bytes(b"adversarial residue")
        return str(allocated)

    monkeypatch.setattr(governance.tempfile, "mkdtemp", dirty_process_temp)

    with pytest.raises(governance.GovernanceError, match="not fresh"):
        governance._allocate_post_r2_run_paths(repository)

    assert len(allocated_process_temps) == 1
    assert not allocated_process_temps[0].exists()


def test_post_r2_cleanup_uses_strict_deletion_and_proves_absence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _process_temp_root, process_temp = _fresh_post_r2_process_temp(
        tmp_path,
        monkeypatch,
        suffix="strict-cleanup",
    )
    calls: list[tuple[Path, tuple[Any, ...], dict[str, Any]]] = []

    def retained_directory(path: Path, *args: Any, **kwargs: Any) -> None:
        calls.append((path, args, kwargs))

    monkeypatch.setattr(governance.shutil, "rmtree", retained_directory)

    with pytest.raises(governance.GovernanceError, match="left the directory present"):
        governance._cleanup_post_r2_process_temp(process_temp)

    assert len(calls) == 1
    assert calls[0][0] == process_temp
    assert calls[0][1] == ()
    expected_callback = "onexc" if sys.version_info >= (3, 12) else "onerror"
    assert set(calls[0][2]) == {expected_callback}
    assert callable(calls[0][2][expected_callback])


@pytest.mark.skipif(os.name != "nt", reason="Windows read-only deletion semantics")
def test_post_r2_cleanup_retries_only_contained_readonly_regular_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _process_temp_root, process_temp = _fresh_post_r2_process_temp(
        tmp_path,
        monkeypatch,
        suffix="readonly-cleanup",
    )
    readonly = process_temp / "pytest/repository/.git/objects/12/object"
    readonly.parent.mkdir(parents=True)
    readonly.write_bytes(b"synthetic git object")
    readonly.chmod(stat.S_IREAD)
    assert readonly.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_READONLY

    governance._cleanup_post_r2_process_temp(process_temp)

    assert not process_temp.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows hard-link and read-only semantics")
def test_post_r2_cleanup_does_not_clear_readonly_on_an_outside_hardlink_peer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _process_temp_root, process_temp = _fresh_post_r2_process_temp(
        tmp_path,
        monkeypatch,
        suffix="readonly-hardlink-cleanup",
    )
    outside = tmp_path / "outside-hardlink-peer"
    outside.write_bytes(b"shared synthetic git object")
    inside = process_temp / "pytest/repository/.git/objects/34/object"
    inside.parent.mkdir(parents=True)
    os.link(outside, inside)
    inside.chmod(stat.S_IREAD)

    try:
        assert outside.lstat().st_nlink == 2
        assert outside.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_READONLY
        assert inside.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_READONLY

        governance._cleanup_post_r2_process_temp(process_temp)

        assert not process_temp.exists()
        assert outside.read_bytes() == b"shared synthetic git object"
        assert outside.lstat().st_nlink == 1
        assert outside.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_READONLY
    finally:
        if outside.exists():
            outside.chmod(stat.S_IWRITE)


@pytest.mark.skipif(os.name != "nt", reason="Windows junction semantics")
def test_post_r2_readonly_cleanup_retry_rejects_an_ancestor_junction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import ctypes

    _process_temp_root, process_temp = _fresh_post_r2_process_temp(
        tmp_path,
        monkeypatch,
        suffix="ancestor-junction",
    )
    outside = tmp_path / "outside-junction-target"
    outside.mkdir()
    victim = outside / "victim"
    victim.write_bytes(b"must remain outside")
    victim.chmod(stat.S_IREAD)
    junction = process_temp / "redirect"
    completed = subprocess.run(
        [os.environ["COMSPEC"], "/d", "/c", "mklink", "/J", str(junction), str(outside)],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        victim.chmod(stat.S_IWRITE)
        governance._cleanup_post_r2_process_temp(process_temp)
        pytest.skip(f"directory junctions are unavailable: {completed.stderr.strip()}")

    try:
        with pytest.raises(governance.GovernanceError, match="traverses a reparse point"):
            governance._post_r2_retry_readonly_unlink(
                process_temp,
                os.unlink,
                str(junction / victim.name),
                ctypes.WinError(5),
            )

        assert victim.read_bytes() == b"must remain outside"
        assert victim.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_READONLY
    finally:
        try:
            junction.lstat()
        except FileNotFoundError:
            pass
        else:
            os.rmdir(junction)
        if victim.exists():
            victim.chmod(stat.S_IWRITE)
        governance._cleanup_post_r2_process_temp(process_temp)


@pytest.mark.skipif(os.name != "nt", reason="Windows file-symlink semantics")
def test_post_r2_readonly_cleanup_retry_rejects_a_leaf_reparse_point(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import ctypes

    _process_temp_root, process_temp = _fresh_post_r2_process_temp(
        tmp_path,
        monkeypatch,
        suffix="leaf-reparse",
    )
    outside = tmp_path / "outside-symlink-target"
    outside.write_bytes(b"must remain outside")
    outside.chmod(stat.S_IREAD)
    leaf = process_temp / "redirect"
    try:
        leaf.symlink_to(outside)
    except OSError as exc:
        outside.chmod(stat.S_IWRITE)
        governance._cleanup_post_r2_process_temp(process_temp)
        pytest.skip(f"file symlinks are unavailable: {exc}")

    try:
        with pytest.raises(governance.GovernanceError, match="not a regular file"):
            governance._post_r2_retry_readonly_unlink(
                process_temp,
                os.unlink,
                str(leaf),
                ctypes.WinError(5),
            )

        assert outside.read_bytes() == b"must remain outside"
        assert outside.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_READONLY
    finally:
        try:
            leaf.unlink()
        except FileNotFoundError:
            pass
        if outside.exists():
            outside.chmod(stat.S_IWRITE)
        governance._cleanup_post_r2_process_temp(process_temp)


def test_post_r2_readonly_cleanup_retry_rejects_an_outside_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _process_temp_root, process_temp = _fresh_post_r2_process_temp(
        tmp_path,
        monkeypatch,
        suffix="readonly-containment",
    )
    outside = tmp_path / "outside-file"
    outside.write_bytes(b"must remain")

    with pytest.raises(governance.GovernanceError, match="leaves its governed root"):
        governance._post_r2_retry_readonly_unlink(
            process_temp,
            os.unlink,
            str(outside.resolve()),
            PermissionError("synthetic access denial"),
        )

    assert outside.read_bytes() == b"must remain"
    governance._cleanup_post_r2_process_temp(process_temp)


@pytest.mark.skipif(os.name != "nt", reason="Windows sharing-violation semantics")
def test_post_r2_readonly_cleanup_retry_does_not_reclassify_a_sharing_violation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import ctypes

    _process_temp_root, process_temp = _fresh_post_r2_process_temp(
        tmp_path,
        monkeypatch,
        suffix="sharing-violation",
    )
    candidate = process_temp / "locked-file"
    candidate.write_bytes(b"must remain")
    sharing_violation = ctypes.WinError(32)
    assert isinstance(sharing_violation, PermissionError)

    with pytest.raises(PermissionError) as raised:
        governance._post_r2_retry_readonly_unlink(
            process_temp,
            os.unlink,
            str(candidate),
            sharing_violation,
        )

    assert raised.value is sharing_violation
    assert candidate.read_bytes() == b"must remain"
    governance._cleanup_post_r2_process_temp(process_temp)


def test_post_r2_cleanup_rejects_a_reparse_root_before_deletion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process_temp_root, process_temp = _fresh_post_r2_process_temp(
        tmp_path,
        monkeypatch,
        suffix="reparse-root-cleanup",
    )
    _simulate_reparse_metadata(monkeypatch, process_temp_root)

    deletion_attempted = False

    def forbidden_deletion(*_args: Any, **_kwargs: Any) -> None:
        nonlocal deletion_attempted
        deletion_attempted = True

    monkeypatch.setattr(governance.shutil, "rmtree", forbidden_deletion)

    with pytest.raises(governance.GovernanceError, match="root.*reparse point"):
        governance._cleanup_post_r2_process_temp(process_temp)

    assert not deletion_attempted


def test_post_r2_execution_preserves_primary_failure_and_notes_cleanup_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _process_temp_root, process_temp = _fresh_post_r2_process_temp(
        tmp_path,
        monkeypatch,
        suffix="primary-and-cleanup-failure",
    )
    basetemp = process_temp / governance.POST_R2_PYTEST_BASETEMP_DIRECTORY
    primary = RuntimeError("synthetic preparation failure")
    monkeypatch.setattr(
        governance,
        "_allocate_post_r2_run_paths",
        lambda _root: (basetemp, process_temp),
    )

    def fail_preparation(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        raise primary

    def fail_cleanup(_path: Path, **_kwargs: Any) -> None:
        raise PermissionError("synthetic cleanup denial")

    monkeypatch.setattr(governance, "_prepare_post_r2_descendant_runtime", fail_preparation)
    monkeypatch.setattr(governance.shutil, "rmtree", fail_cleanup)

    with pytest.raises(RuntimeError, match="synthetic preparation failure") as raised:
        governance._execute_post_r2_pytest(ROOT, test_surface={})

    assert raised.value is primary
    assert any(
        "cleanup also failed" in note and "synthetic cleanup denial" in note
        for note in getattr(raised.value, "__notes__", ())
    )


def test_post_r2_execution_cleans_when_command_construction_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _process_temp_root, process_temp = _fresh_post_r2_process_temp(
        tmp_path,
        monkeypatch,
        suffix="command-construction-failure",
    )
    basetemp = process_temp / governance.POST_R2_PYTEST_BASETEMP_DIRECTORY
    primary = RuntimeError("synthetic argv failure")
    monkeypatch.setattr(
        governance,
        "_allocate_post_r2_run_paths",
        lambda _root: (basetemp, process_temp),
    )

    def fail_argv(*_args: Any, **_kwargs: Any) -> list[str]:
        raise primary

    monkeypatch.setattr(governance, "_post_r2_pytest_argv", fail_argv)

    with pytest.raises(RuntimeError, match="synthetic argv failure") as raised:
        governance._execute_post_r2_pytest(ROOT, test_surface={})

    assert raised.value is primary
    assert not process_temp.exists()


def test_post_r2_execution_passes_exact_authenticated_bootstrap_over_stdin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _process_temp_root, process_temp = _fresh_post_r2_process_temp(
        tmp_path,
        monkeypatch,
        suffix="authenticated-bootstrap-stdin",
    )
    basetemp = process_temp / governance.POST_R2_PYTEST_BASETEMP_DIRECTORY
    descendant_runtime = {"format": "synthetic-descendant-runtime"}
    test_surface = {
        "format": "agent-assure-s1-post-r2-test-surface/2",
        "file_count": 1,
        "size_bytes": 1,
        "sha256": _digest("f"),
    }
    expected_payload, expected_record = governance._post_r2_bootstrap_input(
        ROOT,
        basetemp=basetemp,
        process_temp=process_temp,
    )
    captured: dict[str, Any] = {}

    monkeypatch.setattr(
        governance,
        "_allocate_post_r2_run_paths",
        lambda _root: (basetemp, process_temp),
    )
    monkeypatch.setattr(
        governance,
        "_prepare_post_r2_descendant_runtime",
        lambda *_args, **_kwargs: descendant_runtime,
    )
    monkeypatch.setattr(
        governance,
        "_verify_post_r2_descendant_runtime",
        lambda *_args, **_kwargs: descendant_runtime,
    )
    observations = iter(("2026-10-15T15:00:00Z", "2026-10-15T15:01:00Z"))
    monkeypatch.setattr(governance, "_canonical_host_utc_now", lambda: next(observations))

    def capture_run(arguments: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        captured["arguments"] = arguments
        captured.update(kwargs)
        return subprocess.CompletedProcess(arguments, 0, stdout=b"passed", stderr=b"")

    monkeypatch.setattr(governance.subprocess, "run", capture_run)

    result = governance._execute_post_r2_pytest(ROOT, test_surface=test_surface)

    assert captured["arguments"] == result[1]
    assert captured["input"] == expected_payload
    assert captured["cwd"] == ROOT.resolve()
    assert captured["env"] == result[2]
    assert captured["capture_output"] is True
    assert captured["check"] is False
    assert result[4] == expected_record
    assert result[6].returncode == 0
    assert not process_temp.exists()


def test_post_r2_execution_rejects_unbound_basetemp_and_cleans_process_temp(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unbound_basetemp = (tmp_path / "unbound-basetemp").resolve()
    _process_temp_root, process_temp = _fresh_post_r2_process_temp(
        tmp_path,
        monkeypatch,
        suffix="unbound-basetemp",
    )
    monkeypatch.setattr(
        governance,
        "_allocate_post_r2_run_paths",
        lambda _root: (unbound_basetemp, process_temp),
    )

    with pytest.raises(governance.GovernanceError, match="basetemp path binding changed"):
        governance._execute_post_r2_pytest(ROOT, test_surface={})

    assert not process_temp.exists()


def test_post_r2_path_allocator_reserves_absent_external_governed_basetemp(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    process_temp_root = tmp_path / "external-process-temp-root"
    process_temp_root.mkdir()
    monkeypatch.setattr(governance, "POST_R2_PROCESS_TEMP_ROOT", process_temp_root)
    _initialize_git_repository(repository)
    (repository / ".gitignore").write_text(".tmp/\n", encoding="utf-8")
    _commit_all(repository, "governed local storage")

    basetemp, process_temp = governance._allocate_post_r2_run_paths(repository)

    assert not basetemp.exists()
    assert process_temp.is_dir()
    assert process_temp.parent == process_temp_root
    assert process_temp.name.startswith(governance.POST_R2_PROCESS_TEMP_PREFIX)
    assert basetemp == process_temp / governance.POST_R2_PYTEST_BASETEMP_DIRECTORY
    assert not basetemp.is_relative_to(repository)
    assert not (repository / ".tmp").exists()
    governance._cleanup_post_r2_process_temp(process_temp)
    assert not process_temp.exists()


def test_corrective_local_only_path_prefixes_are_exact_and_exhaustive() -> None:
    claim = {"local_only_path_prefixes": list(governance.CORRECTIVE_LOCAL_ONLY_PATH_PREFIXES)}
    assert governance._validate_corrective_local_only_path_prefixes(claim) == (
        governance.CORRECTIVE_LOCAL_ONLY_PATH_PREFIXES
    )
    for prefix in governance.CORRECTIVE_LOCAL_ONLY_PATH_PREFIXES:
        governance._require_corrective_local_only_path(
            prefix + "synthetic-artifact",
            owner="synthetic corrective artifact",
        )

    for altered in (
        list(reversed(governance.CORRECTIVE_LOCAL_ONLY_PATH_PREFIXES)),
        list(governance.CORRECTIVE_LOCAL_ONLY_PATH_PREFIXES[:-1]),
        [*governance.CORRECTIVE_LOCAL_ONLY_PATH_PREFIXES, ".tmp/s1-acceptance/other-"],
    ):
        with pytest.raises(governance.GovernanceError, match="prefixes changed"):
            governance._validate_corrective_local_only_path_prefixes(
                {"local_only_path_prefixes": altered}
            )
    for forbidden in (
        ".tmp/s1-acceptance/plan",
        ".tmp/s1-acceptance/post-r2-suite-evidence",
        ".tmp/s1-acceptance/forecast-v2-plan",
        ".tmp/s1-acceptance/current-gate-v2",
    ):
        with pytest.raises(governance.GovernanceError, match="signed corrective"):
            governance._require_corrective_local_only_path(
                forbidden,
                owner="synthetic corrective artifact",
            )


@pytest.mark.parametrize(
    "schema_name", ["ticket-completion-receipt.schema.json", "governance-bundle.schema.json"]
)
def test_generation_2_closure_signature_schema_forbids_claimed_signing_time(
    schema_name: str,
) -> None:
    schema = _schema(schema_name)
    signature_schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$defs": schema["$defs"],
        "$ref": "#/$defs/signature",
    }
    envelope = governance._pending_signature_v2(PERSON_ID, "repository_maintainer", _digest("7"))
    governance._validate_json_schema(envelope, signature_schema, owner="v2 signature")

    envelope["signed_at_utc"] = ISSUED_AT
    with pytest.raises(governance.GovernanceError, match="schema validation failed"):
        governance._validate_json_schema(envelope, signature_schema, owner="v2 signature")


def test_corrective_receipt_schema_requires_roadmap_section_2_5_metadata() -> None:
    schema = _schema("ticket-completion-receipt.schema.json")
    required = set(schema["required"])

    assert {
        "receipt_purpose",
        "receipt_digest",
        "issuer_person_id",
        "issuer_role",
        "owner_role",
        "reviewer_role",
        "issuer_competence_scopes",
        "issuer_conflicts",
        "issuer_mode",
        "approval_mode",
        "author_reviewer_relationship",
        "independence_claimed",
        "independence_basis",
        "allowed_operations",
        "exclusions",
        "review_evidence",
        "validity_context",
        "limitations",
    } <= required
    assert schema["properties"]["receipt_purpose"] == {"const": "development_design_acceptance"}


def test_corrective_receipt_review_partition_covers_each_r2_change_once() -> None:
    receipts = {
        "V1-BASE-01": {
            "subject_report": {"path": "base-report.md"},
            "reviewed_artifacts": [{"path": "base-change.py"}],
        },
        "V1-BOOT-01": {
            "subject_report": {"path": "boot-report.md"},
            "reviewed_artifacts": [{"path": "boot-change.yml"}],
        },
    }
    inventory = [
        {"path": path}
        for path in (
            "base-report.md",
            "base-change.py",
            "boot-report.md",
            "boot-change.yml",
        )
    ]

    governance._validate_corrective_review_partition(
        receipts,
        result_artifact_inventory=inventory,
    )

    duplicate = copy.deepcopy(receipts)
    duplicate["V1-BOOT-01"]["reviewed_artifacts"].append({"path": "base-change.py"})
    with pytest.raises(governance.GovernanceError, match="more than once"):
        governance._validate_corrective_review_partition(
            duplicate,
            result_artifact_inventory=inventory,
        )

    missing = copy.deepcopy(receipts)
    missing["V1-BOOT-01"]["reviewed_artifacts"] = []
    with pytest.raises(governance.GovernanceError, match="differs from R2 changes"):
        governance._validate_corrective_review_partition(
            missing,
            result_artifact_inventory=inventory,
        )


@pytest.mark.parametrize(
    "schema_name", ["ticket-completion-receipt.schema.json", "governance-bundle.schema.json"]
)
def test_generation_2_import_evidence_schema_forbids_claimed_signing_time(
    schema_name: str,
) -> None:
    schema = _schema(schema_name)
    evidence_schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$defs": schema["$defs"],
        "$ref": "#/$defs/signatureImportEvidence",
    }
    evidence = governance._pending_signature_import_evidence()
    governance._validate_json_schema(
        evidence,
        evidence_schema,
        owner="v2 signature import evidence",
    )

    evidence["signed_at_utc"] = ISSUED_AT
    with pytest.raises(governance.GovernanceError, match="schema validation failed"):
        governance._validate_json_schema(
            evidence,
            evidence_schema,
            owner="v2 signature import evidence",
        )


def _sign_v2_envelope(
    executable: str,
    key: SshKey,
    envelope: dict[str, Any],
    root: Path,
) -> dict[str, Any]:
    signed = copy.deepcopy(envelope)
    signed["status"] = "signed"
    payload_path = root / f"closure-v2-{len(list(root.glob('closure-v2-*.claim')))}.claim"
    payload_path.write_bytes(governance._signature_claim_bytes_v2(signed))
    completed = _run_test_ssh_keygen(
        [
            executable,
            "-Y",
            "sign",
            "-f",
            str(key.private_key),
            "-n",
            governance.SIGNATURE_NAMESPACE,
            "-O",
            "hashalg=sha512",
            str(payload_path),
        ]
    )
    if completed.returncode != 0:
        pytest.fail(
            "ssh-keygen could not create the v2 test sshsig: "
            + completed.stderr.decode("utf-8", errors="replace")
        )
    armor = _canonicalize_armor(Path(f"{payload_path}.sig").read_bytes())
    signed["signature"] = base64.b64encode(armor).decode("ascii")
    return signed


def test_v2_signature_import_captures_host_observation_only_after_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    ssh_key_material: tuple[str, SshKey, SshKey],
) -> None:
    executable, signing_key, _ = ssh_key_material
    _trust_key(monkeypatch, signing_key)
    subject_digest = _digest("7")
    envelope = governance._pending_signature_v2(
        PERSON_ID,
        "repository_maintainer",
        subject_digest,
    )
    signed_envelope = _sign_v2_envelope(
        executable,
        signing_key,
        envelope,
        tmp_path,
    )
    record = {
        "format": "agent-assure-ticket-completion-receipt/2",
        "receipt_digest": subject_digest,
        "issuer_person_id": PERSON_ID,
        "issuer_role": "repository_maintainer",
        "claim_prepared_at_utc": "2026-10-15T15:01:00Z",
        "signature_envelope": signed_envelope,
        "signature_import_evidence": governance._pending_signature_import_evidence(),
    }
    monkeypatch.setattr(
        governance,
        "_canonical_host_utc_now",
        lambda: "2026-10-15T15:02:00Z",
    )

    observed = governance.record_v2_signature_import_observation(record)

    assert observed["receipt_digest"] == subject_digest
    assert "signed_at_utc" not in observed["signature_envelope"]
    assert observed["signature_import_evidence"] == {
        "status": "verified_after_import",
        "verification_recorded_at_utc": "2026-10-15T15:02:00Z",
        "clock_basis": "maintainer_host_utc_externally_unattested",
        "sshsig_timestamp_capability": "none",
        "actual_signature_time_claimed": False,
        "verification_result": "valid_exact_payload_key_and_namespace",
    }

    tampered = copy.deepcopy(record)
    tampered["signature_envelope"]["subject_digest"] = _digest("8")
    with pytest.raises(governance.GovernanceError, match="subject_digest changed"):
        governance.record_v2_signature_import_observation(tampered)


def test_v2_closure_observation_times_are_not_caller_supplied() -> None:
    assert (
        "claim_prepared_at"
        not in inspect.signature(governance.build_ticket_completion_receipt_v2).parameters
    )
    assert (
        "claim_prepared_at"
        not in inspect.signature(governance.build_governance_bundle_v2).parameters
    )
    assert (
        "verification_recorded_at"
        not in inspect.signature(governance.record_v2_signature_import_observation).parameters
    )


def test_corrective_receipt_and_bundle_v2_round_trip_recomputes_exact_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    ssh_key_material: tuple[str, SshKey, SshKey],
) -> None:
    executable, signing_key, _ = ssh_key_material
    _trust_key(monkeypatch, signing_key)
    repository = tmp_path / "repository"
    _initialize_git_repository(repository)
    (repository / ".gitignore").write_text(
        ".tmp/\n.venv/\n",
        encoding="utf-8",
    )
    original_predecessor = governance.S1_ACCEPTANCE_V1_CLOSURE_COMMIT
    original_receipt_digests = dict(governance.S1_ACCEPTANCE_V1_RECEIPT_DIGESTS)
    receipt_digests: dict[str, str] = {}
    for ticket_id in ("V1-BASE-01", "V1-BOOT-01"):
        projection = {
            "format": "agent-assure-ticket-completion-receipt/1",
            "subject_ticket_id": ticket_id,
        }
        digest = governance.domain_digest(governance.TICKET_RECEIPT_DOMAIN, projection)
        receipt_digests[ticket_id] = digest
        governance._write_json(
            repository
            / "docs"
            / "governance"
            / "v1"
            / f"completion-receipt-{ticket_id.lower()}.json",
            {
                **projection,
                "receipt_digest": digest,
                "signature_envelope": {},
            },
        )
    predecessor = _commit_all(repository, "synthetic generation-1 closure")
    monkeypatch.setattr(governance, "S1_ACCEPTANCE_V1_CLOSURE_COMMIT", predecessor)
    monkeypatch.setattr(
        governance,
        "S1_ACCEPTANCE_V1_RECEIPT_DIGESTS",
        receipt_digests,
    )

    result_paths = {
        path
        for ticket_id in ("V1-BASE-01", "V1-BOOT-01")
        for path, _kind in governance._completion_review_paths_v2(ticket_id)
    }
    result_paths.update(
        {
            "docs/governance/v1/completion-report-v1-base-01.md",
            "docs/governance/v1/completion-report-v1-boot-01.md",
        }
    )
    for path in sorted(result_paths):
        artifact = repository / path
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text(f"reviewed {path}\n", encoding="utf-8")
    result_commit = _commit_all(repository, "synthetic corrective result")

    authorized_paths = sorted(
        result_paths | governance.S1_CORRECTIVE_CLOSURE_PATHS,
        key=governance._utf8_sort_key,
    )
    authorization = {
        "format": "agent-assure-s1-corrective-kickoff-authorization/1",
        "authorization_status": "authorized",
        "signed_claim_artifact": {
            "sha256": governance.CORRECTIVE_KICKOFF_CLAIM_DIGEST,
        },
        "signed_claim": {
            "authorization_kind": "prospective_corrective_implementation",
            "authorization_effect": "corrective_s1_development_governance_only",
            "authorized_person_id": PERSON_ID,
            "authorized_role": "repository_maintainer",
            "tracked_allowed_paths": authorized_paths,
        },
    }
    roster = {
        "selection_status": "approved",
        "selected_mode": "maintainer_development",
        "maintainer_person_id": PERSON_ID,
        "people": [
            {
                "person_id": PERSON_ID,
                "competence_scopes": [
                    "planning_governance:s1",
                    "repository_maintenance:bounded_development",
                    "technical_direction:s1",
                ],
                "conflicts": ["Sole maintainer self-acceptance"],
            }
        ],
        "role_assignments": [
            {"role": "repository_maintainer", "person_id": PERSON_ID},
            {"role": "technical_lead", "person_id": PERSON_ID},
        ],
    }
    forecast = {
        "format": "agent-assure-delivery-forecast/2",
        "forecast_status": "accepted",
        "human_review_status": "complete",
        "record_digest": _digest("3"),
        "estimation_catalog_digest": _digest("4"),
        "aggregation_method_registry_digest": _digest("5"),
        "authoring_ledger_digest": _digest("6"),
        "signature_envelope": {"status": "signed"},
        "acceptance_receipt": {
            "receipt_status": "accepted_for_development",
            "receipt_digest": _digest("7"),
            "signature_envelope": {"status": "signed"},
        },
    }
    snapshot = governance.RoadmapSnapshot(
        raw_digest=_digest("8"),
        tickets=(
            {
                "id": "V1-BASE-01",
                "dispatch_kind": "inventory",
                "owner_role": "technical_lead",
                "reviewer_role": "repository_maintainer",
            },
            {
                "id": "V1-BOOT-01",
                "dispatch_kind": "kickoff",
                "owner_role": "technical_lead",
                "reviewer_role": "repository_maintainer",
            },
        ),
        release_train={},
        approval_roster_template={},
        ticket_set_digest=_digest("9"),
        dependency_graph_digest=_digest("a"),
        release_train_digest=_digest("b"),
    )
    monkeypatch.setattr(
        governance,
        "_load_corrective_authorization_from_result",
        lambda *_args, **_kwargs: authorization,
    )
    monkeypatch.setattr(
        governance,
        "_load_forecast_from_result",
        lambda *_args, **_kwargs: forecast,
    )
    monkeypatch.setattr(
        governance,
        "_load_roster_from_result",
        lambda *_args, **_kwargs: roster,
    )
    monkeypatch.setattr(
        governance,
        "_canonical_host_utc_now",
        lambda: "2026-10-15T15:02:00Z",
    )
    roster_digest = governance.approval_roster_digest(roster)

    suite_evidence_path, _suite_evidence = _post_r2_evidence_fixture(
        repository,
        result_commit,
        monkeypatch,
    )
    base_receipt = governance.build_ticket_completion_receipt_v2(
        snapshot,
        repository_root=repository,
        ticket_id="V1-BASE-01",
        roster_digest=roster_digest,
        person_id=PERSON_ID,
        result_commit=result_commit,
        status="accepted_for_development",
    )
    boot_receipt = governance.build_ticket_completion_receipt_v2(
        snapshot,
        repository_root=repository,
        ticket_id="V1-BOOT-01",
        roster_digest=roster_digest,
        person_id=PERSON_ID,
        result_commit=result_commit,
        post_r2_suite_evidence_path=suite_evidence_path,
        status="accepted_for_development",
    )

    schema = copy.deepcopy(_schema("ticket-completion-receipt.schema.json"))
    schema_fingerprint = schema["$defs"]["signature"]["properties"]["public_key_fingerprint"][
        "const"
    ]
    replacements = {
        original_predecessor: predecessor,
        original_receipt_digests["V1-BASE-01"]: receipt_digests["V1-BASE-01"],
        original_receipt_digests["V1-BOOT-01"]: receipt_digests["V1-BOOT-01"],
        schema_fingerprint: signing_key.fingerprint,
    }

    def rewrite_schema(value: Any) -> Any:
        if isinstance(value, dict):
            return {key: rewrite_schema(item) for key, item in value.items()}
        if isinstance(value, list):
            return [rewrite_schema(item) for item in value]
        return replacements.get(value, value) if isinstance(value, str) else value

    monkeypatch.setattr(
        governance,
        "_canonical_host_utc_now",
        lambda: "2026-10-15T15:03:00Z",
    )
    completion_receipts: dict[str, dict[str, Any]] = {}
    for ticket_id, receipt in (
        ("V1-BASE-01", base_receipt),
        ("V1-BOOT-01", boot_receipt),
    ):
        receipt["signature_envelope"] = _sign_v2_envelope(
            executable,
            signing_key,
            receipt["signature_envelope"],
            tmp_path,
        )
        signed_receipt = governance.record_v2_signature_import_observation(receipt)
        governance.validate_ticket_completion_receipt_v2(
            snapshot,
            signed_receipt,
            rewrite_schema(schema),
            repository_root=repository,
            expected_ticket_id=ticket_id,
            expected_roster_digest=roster_digest,
            expected_corrective_authorization_digest=(governance.CORRECTIVE_KICKOFF_CLAIM_DIGEST),
            expected_person_id=PERSON_ID,
            expected_result_parent=predecessor,
            allow_pending=False,
        )
        completion_receipts[ticket_id] = signed_receipt

    receipt = completion_receipts["V1-BASE-01"]
    assert receipt["receipt_purpose"] == "development_design_acceptance"
    assert receipt["reviewer_role"] == "repository_maintainer"
    assert receipt["issuer_competence_scopes"] == roster["people"][0]["competence_scopes"]
    assert receipt["issuer_conflicts"] == roster["people"][0]["conflicts"]
    assert receipt["change_control"]["result_commit"] == result_commit
    assert receipt["replacement_for"]["disposition"] == "superseded_nonconforming"
    assert completion_receipts["V1-BOOT-01"]["post_result_verification"] is not None

    predecessor_binding = {
        "acceptance_generation": 1,
        "disposition": "superseded_nonconforming",
        "noncurrent_reason": "forecast_and_governance_provenance_nonconformance",
        "tag_name": governance.S1_ACCEPTANCE_TAG_NAME,
        "tag_object": governance.S1_ACCEPTANCE_V1_TAG_OBJECT,
        "baseline_commit": governance.PINNED_BASE_COMMIT,
        "result_commit": governance.S1_ACCEPTANCE_V1_RESULT_COMMIT,
        "closure_commit": predecessor,
        "bundle_digest": governance.S1_ACCEPTANCE_V1_BUNDLE_DIGEST,
        "forecast_digest": governance.S1_ACCEPTANCE_V1_FORECAST_DIGEST,
        "objects_remain_immutable": True,
    }
    monkeypatch.setattr(
        governance,
        "_generation_1_supersession_binding",
        lambda *_args, **_kwargs: predecessor_binding,
    )
    monkeypatch.setattr(
        governance,
        "_canonical_host_utc_now",
        lambda: "2026-10-15T15:04:00Z",
    )
    bundle = governance.build_governance_bundle_v2(
        snapshot,
        repository_root=repository,
        roster=roster,
        completion_receipts=completion_receipts,
        forecast=forecast,
        baseline_observations={"observations_digest": _digest("c")},
        person_id=PERSON_ID,
        result_commit=result_commit,
        issued_at="2026-10-15T15:00:00Z",
        valid_until="2026-10-16T15:00:00Z",
        status="accepted_for_development",
    )
    unsigned_bundle_digest = bundle["bundle_digest"]
    bundle["signature_envelope"] = _sign_v2_envelope(
        executable,
        signing_key,
        bundle["signature_envelope"],
        tmp_path,
    )
    monkeypatch.setattr(
        governance,
        "_canonical_host_utc_now",
        lambda: "2026-10-15T15:05:00Z",
    )
    signed_bundle = governance.record_v2_signature_import_observation(bundle)
    bundle_schema = copy.deepcopy(_schema("governance-bundle.schema.json"))
    bundle_schema_fingerprint = bundle_schema["$defs"]["signature"]["properties"][
        "public_key_fingerprint"
    ]["const"]
    bundle_replacements = {
        original_predecessor: predecessor,
        original_receipt_digests["V1-BASE-01"]: receipt_digests["V1-BASE-01"],
        original_receipt_digests["V1-BOOT-01"]: receipt_digests["V1-BOOT-01"],
        bundle_schema_fingerprint: signing_key.fingerprint,
    }

    def rewrite_bundle_schema(value: Any) -> Any:
        if isinstance(value, dict):
            return {key: rewrite_bundle_schema(item) for key, item in value.items()}
        if isinstance(value, list):
            return [rewrite_bundle_schema(item) for item in value]
        return bundle_replacements.get(value, value) if isinstance(value, str) else value

    governance._validate_json_schema(
        signed_bundle,
        rewrite_bundle_schema(bundle_schema),
        owner="synthetic corrective governance bundle",
    )
    assert signed_bundle["bundle_digest"] == unsigned_bundle_digest
    assert signed_bundle["signature_import_evidence"]["actual_signature_time_claimed"] is False
    assert signed_bundle["predecessor_acceptance"] == predecessor_binding
    assert signed_bundle["artifact_inventory"] == (
        governance._corrective_receipt_artifact_inventory(completion_receipts)
    )


def test_generation_2_closure_uses_v2_bundle_digest_domain(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    _initialize_git_repository(repository)
    result_commit = _create_result_commit(repository)
    bundle = _closure_bundle()
    bundle["format"] = "agent-assure-governance-bundle/2"
    bundle["bundle_digest"] = governance.domain_digest(
        governance.BUNDLE_V2_DOMAIN, governance._bundle_projection(bundle)
    )
    _write_closure_files(repository, bundle)
    closure_commit = _commit_all(repository, "C2")

    assert (
        governance._validate_s1_closure_checkout(
            repository,
            result_commit=result_commit,
            bundle=bundle,
            expected_closure_commit=closure_commit,
        )
        == closure_commit
    )


def test_generation_2_transition_requires_byte_exact_c1_closure_placeholders(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    _initialize_git_repository(repository)
    governance_root = repository / "docs" / "governance" / "v1"
    records = {
        "docs/governance/v1/completion-receipt-v1-base-01.json": {
            "format": "agent-assure-ticket-completion-receipt/1",
            "receipt_digest": _digest("1"),
        },
        "docs/governance/v1/completion-receipt-v1-boot-01.json": {
            "format": "agent-assure-ticket-completion-receipt/1",
            "receipt_digest": _digest("2"),
        },
        "docs/governance/v1/governance-bundle.json": {
            "format": "agent-assure-governance-bundle/1",
            "bundle_digest": _digest("3"),
        },
    }
    for relative, record in records.items():
        governance._write_json(repository / relative, record)
    closure_commit = _commit_all(repository, "synthetic C1")
    monkeypatch.setattr(
        governance,
        "S1_ACCEPTANCE_V1_CLOSURE_COMMIT",
        closure_commit,
    )

    observed = governance._validate_generation_1_closure_placeholders(
        repository,
        governance_root,
    )

    assert set(observed) == governance.S1_CORRECTIVE_CLOSURE_PATHS
    assert (
        "result_commit"
        not in inspect.signature(governance._validate_generation_1_closure_placeholders).parameters
    )

    target = governance_root / "governance-bundle.json"
    target.write_bytes(target.read_bytes() + b" ")
    with pytest.raises(governance.GovernanceError, match="differs from immutable C1"):
        governance._validate_generation_1_closure_placeholders(
            repository,
            governance_root,
        )


def _protect_local_roadmap(repository: Path) -> Path:
    roadmap = repository / "Agent_Assure_Implementation_Roadmap.md"
    exclude = repository / ".git" / "info" / "exclude"
    exclude.write_text("Agent_Assure_Implementation_Roadmap.md\n", encoding="utf-8")
    roadmap.write_text("private roadmap\n", encoding="utf-8")
    return roadmap


def _prepare_successor_v3_surface_fixture(
    repository: Path, monkeypatch: pytest.MonkeyPatch,
) -> str:
    """Keep real Git/native prerequisites while isolating the full file inventory."""
    _git(repository, "checkout", "--quiet", "-b", governance.S1_SUCCESSOR_V3_BRANCH_NAME)
    (repository / ".git/info/exclude").write_bytes(
        governance.POST_V2_CONTROL_GIT_EXCLUDE_BYTES,
    )
    readme = (repository / "README.md").read_bytes()
    assert b"\r" not in readme and readme.endswith(b"\n"), "fixture README must use LF bytes"
    committed_readme = governance._run_git(repository, ["cat-file", "blob", "HEAD:README.md"])
    assert committed_readme.returncode == 0
    assert committed_readme.stdout == readme, "fixture README differs from its raw Git blob"
    monkeypatch.setattr(
        governance, "_post_r2_test_surface_evidence",
        lambda *_args, **_kwargs: {"fixture": "synthetic tracked-file inventory"},
    )
    return _git(repository, "rev-parse", "HEAD^{commit}").stdout.strip()


def test_local_only_roadmap_requires_local_exclusion_and_an_untracked_index(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    _initialize_git_repository(repository)
    (repository / "README.md").write_text("repository\n", encoding="utf-8", newline="\n")
    _commit_all(repository, "base")
    roadmap = _protect_local_roadmap(repository)

    assert governance.validate_local_only_roadmap(repository, roadmap) == roadmap.name
    r3 = _prepare_successor_v3_surface_fixture(repository, monkeypatch)
    _git(
        repository, "-c", "tag.gpgSign=false", "tag", "--annotate",
        "--message", "public annotated tag", "synthetic-native-predecessor",
    )
    tag_oid = _git(repository, "rev-parse", "refs/tags/synthetic-native-predecessor").stdout.strip()
    assert _git(repository, "cat-file", "-t", tag_oid).stdout.strip() == "tag"
    # The old predicate returned this unrelated tag even for a nonexistent
    # path. Exercise that real Git behavior, rather than fabricating stdout.
    for path in (roadmap.name, "nonexistent-private-path-control.md"):
        object_rows = _git(repository, "rev-list", "--all", "--objects", "--", path)
        assert object_rows.stdout.splitlines() == [f"{tag_oid} synthetic-native-predecessor"]

    surface = governance._successor_v3_repository_surface(repository, r3=r3)
    assert surface["state"]["head_commit"] == r3
    assert surface["branch"] == governance.S1_SUCCESSOR_V3_BRANCH_NAME
    assert surface["test_surface"] == {"fixture": "synthetic tracked-file inventory"}
    roadmap.unlink()
    assert governance._successor_v3_repository_surface(repository, r3=r3) == surface

    readme = repository / "README.md"
    clean_readme = readme.read_bytes()
    readme.write_bytes(clean_readme + b"intentional dirty-worktree negative control\n")
    try:
        with pytest.raises(governance.GovernanceError, match="requires clean exact R3"):
            governance._successor_v3_repository_surface(repository, r3=r3)
    finally:
        readme.write_bytes(clean_readme)
    assert governance._successor_v3_repository_surface(repository, r3=r3) == surface

    expected_history_argv = [
        "log", "--all", "--full-history", "--format=%H", "--",
        ":(top,literal)Agent_Assure_Implementation_Roadmap.md",
    ]
    original_run_git = governance._run_git

    def failed_history_inspection(
        repository_root: Path, arguments: Any, **kwargs: Any,
    ) -> subprocess.CompletedProcess[bytes]:
        if list(arguments) == expected_history_argv:
            return subprocess.CompletedProcess(
                args=arguments, returncode=128, stdout=b"", stderr=b"synthetic history failure",
            )
        return original_run_git(repository_root, arguments, **kwargs)

    with monkeypatch.context() as failure_patch:
        failure_patch.setattr(governance, "_run_git", failed_history_inspection)
        with pytest.raises(
            governance.GovernanceError,
            match="unable to inspect reachable Git history.*Git exited with status 128",
        ):
            governance._successor_v3_repository_surface(repository, r3=r3)

    roadmap.write_text("private roadmap\n", encoding="utf-8")
    _git(repository, "add", "--force", roadmap.name)
    with pytest.raises(governance.GovernanceError, match="tracked or staged"):
        governance.validate_local_only_roadmap(repository, roadmap)


def test_local_only_roadmap_rejects_reachable_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    _initialize_git_repository(repository)
    (repository / "README.md").write_text("public repository\n", encoding="utf-8", newline="\n")
    _commit_all(repository, "public base")
    r3 = _prepare_successor_v3_surface_fixture(repository, monkeypatch)
    _git(repository, "checkout", "--quiet", "-b", "retained-private-history")
    roadmap = repository / "Agent_Assure_Implementation_Roadmap.md"
    roadmap.write_text("historical roadmap\n", encoding="utf-8")
    _git(repository, "add", "--force", roadmap.name)
    _git(repository, "commit", "--quiet", "--message", "mistaken roadmap commit")
    roadmap.unlink()
    _commit_all(repository, "remove roadmap")
    _git(repository, "checkout", "--quiet", governance.S1_SUCCESSOR_V3_BRANCH_NAME)
    assert _git(repository, "rev-parse", "HEAD^{commit}").stdout.strip() == r3
    assert not roadmap.exists()
    with pytest.raises(
        governance.GovernanceError, match="private roadmap path.*reachable Git history",
    ):
        governance._successor_v3_repository_surface(repository, r3=r3)
    roadmap = _protect_local_roadmap(repository)

    with pytest.raises(governance.GovernanceError, match="reachable local Git history"):
        governance.validate_local_only_roadmap(repository, roadmap)


def test_local_only_roadmap_rejects_identical_unreachable_blob(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    _initialize_git_repository(repository)
    (repository / "README.md").write_text("repository\n", encoding="utf-8", newline="\n")
    _commit_all(repository, "base")
    roadmap = _protect_local_roadmap(repository)

    assert governance.validate_local_only_roadmap(repository, roadmap) == roadmap.name
    r3 = _prepare_successor_v3_surface_fixture(repository, monkeypatch)
    governance._successor_v3_repository_surface(repository, r3=r3)
    _git(repository, "hash-object", "-w", "--no-filters", "--", roadmap.name)

    with pytest.raises(governance.GovernanceError, match="Git object database"):
        governance.validate_local_only_roadmap(repository, roadmap)
    with pytest.raises(governance.GovernanceError, match="Git object database"):
        governance._successor_v3_repository_surface(repository, r3=r3)


def test_generation_2_historical_checkout_requires_exact_clean_closure(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    _initialize_git_repository(repository)
    tracked = repository / "tracked.txt"
    tracked.write_bytes(b"closure\n")
    closure_commit = _commit_all(repository, "C2")
    (repository / ".git" / "info" / "exclude").write_text(
        "/Agent_Assure_Implementation_Roadmap.md\n/.venv/\n/.tmp/\n",
        encoding="utf-8",
    )
    (repository / "Agent_Assure_Implementation_Roadmap.md").write_text(
        "private\n", encoding="utf-8"
    )
    (repository / ".venv").mkdir()
    (repository / ".venv" / "runtime.txt").write_text("frozen\n", encoding="utf-8")
    (repository / ".tmp").mkdir()
    (repository / ".tmp" / "local.txt").write_text("local\n", encoding="utf-8")

    governance._validate_historical_v2_checkout_state(
        repository,
        expected_closure_commit=closure_commit,
    )

    tracked.write_bytes(b"dirty\n")
    with pytest.raises(governance.GovernanceError, match="clean closure worktree"):
        governance._validate_historical_v2_checkout_state(
            repository,
            expected_closure_commit=closure_commit,
        )

    tracked.write_bytes(b"successor\n")
    _commit_all(repository, "successor")
    with pytest.raises(governance.GovernanceError, match="exact closure commit"):
        governance._validate_historical_v2_checkout_state(
            repository,
            expected_closure_commit=closure_commit,
        )


def test_pending_check_reports_nonaccepting_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository = tmp_path / "repository"
    governance_root = repository / "docs" / "governance" / "v1"
    governance_root.mkdir(parents=True)
    records: dict[str, dict[str, Any]] = {
        "approval-roster.json": {},
        "approval-roster.schema.json": {},
        "maintainer-signing-key.json": {},
        "baseline-observations.json": {},
        "kickoff-authorization.schema.json": {},
        "kickoff-authorization-v1-base-01.json": {
            "authorization_digest": _digest("a"),
            "issued_at_utc": ISSUED_AT,
            "valid_until_utc": VALID_UNTIL,
        },
        "kickoff-authorization-v1-boot-01.json": {
            "authorization_digest": _digest("b"),
            "issued_at_utc": ISSUED_AT,
            "valid_until_utc": VALID_UNTIL,
        },
        "delivery-forecast.aggregation-registry.json": {},
        "delivery-forecast.aggregation-registry.schema.json": {},
        "delivery-forecast.authoring-ledger.json": {},
        "delivery-forecast.authoring-ledger.schema.json": {},
        "delivery-forecast.json": {
            "forecast_status": "proposed",
            "record_digest": _digest("c"),
            "issued_at_utc": ISSUED_AT,
            "valid_until_utc": VALID_UNTIL,
        },
        "delivery-forecast.schema.json": {},
        "ticket-completion-receipt.schema.json": {},
        "completion-receipt-v1-base-01.json": {},
        "completion-receipt-v1-boot-01.json": {},
        "governance-bundle.json": {
            "format": "agent-assure-governance-bundle/1",
            "bundle_status": "pending_human_acceptance",
            "bundle_digest": _digest("d"),
        },
        "governance-bundle.schema.json": {},
    }
    monkeypatch.setattr(governance, "validate_local_only_roadmap", lambda *_: "roadmap")
    monkeypatch.setattr(governance, "load_roadmap", lambda *_: _minimal_snapshot())
    monkeypatch.setattr(governance, "_read_json", lambda path: records[path.name])
    monkeypatch.setattr(
        governance,
        "validate_approval_roster",
        lambda *_args, **_kwargs: (_digest("e"), PERSON_ID),
    )
    for validator_name in (
        "validate_kickoff_authorization",
        "_validate_json_schema",
        "_resolve_aggregation_method",
        "validate_authoring_ledger",
        "validate_forecast",
        "validate_ticket_completion_receipt",
        "validate_governance_bundle",
    ):
        monkeypatch.setattr(governance, validator_name, lambda *_args, **_kwargs: None)

    exit_code = governance.check.__wrapped__(
        Namespace(
            repository_root=str(repository),
            governance_dir=str(governance_root),
            roadmap=str(repository / "Agent_Assure_Implementation_Roadmap.md"),
            allow_pending=True,
            accept_now=False,
            historical=False,
            fetch_authoritative_refs=False,
            commitment_time=None,
        )
    )

    assert exit_code == 0
    assert '"result": "valid_pending_nonaccepting"' in capsys.readouterr().out


def _minimal_acceptance_plan(
    tmp_path: Path,
) -> tuple[Path, Path, dict[str, Any], str]:
    repository = tmp_path / "repository"
    repository.mkdir()
    source = repository / "source.json"
    source.write_bytes(b'{"source":"original"}\n')
    plan_directory = repository / ".tmp" / "s1-acceptance" / "plan"
    target_path = "docs/governance/v1/example.json"
    target = {
        "purpose": "acceptance-plan-test",
        "signature_envelope": governance._pending_signature(
            PERSON_ID, "repository_maintainer", _digest("7")
        ),
    }
    plan = governance._write_acceptance_plan(
        repository,
        plan_directory,
        phase="predecessors",
        source_paths=[source],
        targets={target_path: target},
        claim_specs=[
            (
                "example-claim",
                target_path,
                ["signature_envelope"],
                "2026-10-15T15:05:00Z",
            )
        ],
    )
    return plan_directory, source, plan, target_path


def test_acceptance_plan_rejects_plan_digest_tampering(tmp_path: Path) -> None:
    plan_directory, _, plan, _ = _minimal_acceptance_plan(tmp_path)
    plan["phase"] = "bundle"
    governance._write_json(plan_directory / "plan.json", plan)

    with pytest.raises(governance.GovernanceError, match="acceptance plan digest mismatch"):
        governance._read_acceptance_plan(plan_directory)


def test_acceptance_plan_rejects_source_tampering_after_export(tmp_path: Path) -> None:
    plan_directory, source, _, _ = _minimal_acceptance_plan(tmp_path)
    plan = governance._read_acceptance_plan(plan_directory)
    source.write_bytes(b'{"source":"tampered"}\n')

    with pytest.raises(governance.GovernanceError, match="source file changed after plan creation"):
        governance._verify_plan_sources(plan_directory.parents[2], plan)


def test_acceptance_plan_rejects_claim_tampering(tmp_path: Path) -> None:
    plan_directory, _, _, _ = _minimal_acceptance_plan(tmp_path)
    claim = plan_directory / "claims" / "example-claim.claim"
    claim.write_bytes(claim.read_bytes() + b"tampered")

    with pytest.raises(governance.GovernanceError, match="acceptance claim file changed"):
        governance._read_acceptance_plan(plan_directory)


def test_acceptance_import_rejects_a_missing_signature(tmp_path: Path) -> None:
    plan_directory, _, _, _ = _minimal_acceptance_plan(tmp_path)
    plan = governance._read_acceptance_plan(plan_directory)

    with pytest.raises(governance.GovernanceError, match="missing human SSHSIG"):
        governance._materialize_signed_plan_targets(plan_directory, plan)


def test_acceptance_import_rejects_an_unexpected_signature(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan_directory, _, _, _ = _minimal_acceptance_plan(tmp_path)
    plan = governance._read_acceptance_plan(plan_directory)
    canonical_fake_armor = b"-----BEGIN SSH SIGNATURE-----\neA==\n-----END SSH SIGNATURE-----\n"
    claims = plan_directory / "claims"
    (claims / "example-claim.claim.sig").write_bytes(canonical_fake_armor)
    (claims / "unexpected.sig").write_bytes(canonical_fake_armor)
    monkeypatch.setattr(governance, "_verify_sshsig", lambda **_kwargs: None)

    with pytest.raises(
        governance.GovernanceError,
        match="acceptance plan contains missing or unexpected SSHSIG files",
    ):
        governance._materialize_signed_plan_targets(plan_directory, plan)


def test_acceptance_import_parser_requires_the_human_confirmed_plan_digest() -> None:
    with pytest.raises(SystemExit) as exc_info:
        governance._parser().parse_args(
            [
                "acceptance-import",
                "--roadmap",
                "Agent_Assure_Implementation_Roadmap.md",
                "--governance-dir",
                "docs/governance/v1",
                "--plan-dir",
                ".tmp/s1-acceptance/plan",
                "--commitment-time",
                ISSUED_AT,
            ]
        )

    assert exc_info.value.code == 2


def _acceptance_import_namespace(
    repository: Path, governance_root: Path, plan_directory: Path, expected_digest: str
) -> Namespace:
    return Namespace(
        repository_root=str(repository),
        governance_dir=str(governance_root),
        roadmap=str(repository / "Agent_Assure_Implementation_Roadmap.md"),
        plan_dir=str(plan_directory),
        commitment_time=ISSUED_AT,
        expected_plan_digest=expected_digest,
    )


def _mock_acceptance_import_prelude(
    monkeypatch: pytest.MonkeyPatch,
    plan_directory: Path,
    plan_digest: str,
) -> None:
    monkeypatch.setattr(
        governance,
        "_private_acceptance_path",
        lambda *_args, **_kwargs: plan_directory,
    )
    monkeypatch.setattr(governance, "validate_local_only_roadmap", lambda *_args: "roadmap")
    monkeypatch.setattr(governance, "load_roadmap", lambda *_args: _minimal_snapshot())
    monkeypatch.setattr(
        governance,
        "_read_acceptance_plan",
        lambda *_args: {
            "plan_digest": plan_digest,
            "targets": [],
            "source_files": [],
            "claims": [],
        },
    )


def test_acceptance_import_rejects_a_different_human_confirmed_plan_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    governance_root = repository / "docs" / "governance" / "v1"
    governance_root.mkdir(parents=True)
    plan_directory = repository / ".tmp" / "s1-acceptance" / "plan"
    plan_directory.mkdir(parents=True)
    actual_digest = _digest("a")
    _mock_acceptance_import_prelude(monkeypatch, plan_directory, plan_digest=actual_digest)

    def source_verification_must_not_run(*_args: Any, **_kwargs: Any) -> None:
        pytest.fail("source verification ran before the expected plan digest check")

    monkeypatch.setattr(governance, "_verify_plan_sources", source_verification_must_not_run)

    with pytest.raises(
        governance.GovernanceError,
        match="differs from the human-confirmed expected digest",
    ):
        governance.acceptance_import.__wrapped__(
            _acceptance_import_namespace(
                repository,
                governance_root,
                plan_directory,
                expected_digest=_digest("b"),
            )
        )


def test_acceptance_import_proceeds_only_after_the_expected_plan_digest_matches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    governance_root = repository / "docs" / "governance" / "v1"
    governance_root.mkdir(parents=True)
    plan_directory = repository / ".tmp" / "s1-acceptance" / "plan"
    plan_directory.mkdir(parents=True)
    plan_digest = _digest("a")
    _mock_acceptance_import_prelude(monkeypatch, plan_directory, plan_digest=plan_digest)

    def reached_source_verification(*_args: Any, **_kwargs: Any) -> None:
        raise governance.GovernanceError("reached source verification")

    monkeypatch.setattr(governance, "_verify_plan_sources", reached_source_verification)

    with pytest.raises(governance.GovernanceError, match="reached source verification"):
        governance.acceptance_import.__wrapped__(
            _acceptance_import_namespace(
                repository,
                governance_root,
                plan_directory,
                expected_digest=plan_digest,
            )
        )


def test_acceptance_import_rejects_a_signature_over_another_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    ssh_key_material: tuple[str, SshKey, SshKey],
) -> None:
    executable, signing_key, _ = ssh_key_material
    _trust_key(monkeypatch, signing_key)
    plan_directory, _, _, _ = _minimal_acceptance_plan(tmp_path)
    plan = governance._read_acceptance_plan(plan_directory)
    wrong_claim = plan_directory / "claims" / "wrong.claim"
    wrong_claim.write_bytes(b"different signed payload")
    completed = _run_test_ssh_keygen(
        [
            executable,
            "-Y",
            "sign",
            "-f",
            str(signing_key.private_key),
            "-n",
            governance.SIGNATURE_NAMESPACE,
            "-O",
            "hashalg=sha512",
            str(wrong_claim),
        ]
    )
    if completed.returncode != 0:
        pytest.fail(
            "ssh-keygen could not create the adversarial test signature: "
            + completed.stderr.decode("utf-8", errors="replace")
        )
    wrong_signature = Path(f"{wrong_claim}.sig")
    expected_signature = plan_directory / "claims" / "example-claim.claim.sig"
    expected_signature.write_bytes(wrong_signature.read_bytes())

    with pytest.raises(governance.GovernanceError, match="signature verification failed"):
        governance._materialize_signed_plan_targets(plan_directory, plan)


@pytest.mark.parametrize(
    "validator_name, expected_error",
    [
        ("_validate_predecessor_plan_targets", "predecessor plan target set is not exact"),
        ("_validate_completion_plan_targets", "completion plan target set is not exact"),
        ("_validate_bundle_plan_targets", "bundle plan target set is not exact"),
    ],
)
def test_acceptance_phase_validators_require_an_exact_target_set(
    validator_name: str, expected_error: str
) -> None:
    validator = getattr(governance, validator_name)
    arguments: dict[str, Any] = {
        "repository_root": ROOT,
        "governance_root": GOVERNANCE_ROOT,
        "validation_time": governance._parse_utc(ISSUED_AT, owner="test validation time"),
    }
    if validator_name != "_validate_predecessor_plan_targets":
        arguments["result_commit"] = "0" * 40

    with pytest.raises(governance.GovernanceError, match=expected_error):
        validator(_minimal_snapshot(), {"unexpected.json": {}}, **arguments)


def test_check_accept_now_requires_an_authoritative_fetch_before_artifact_access(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    governance_root = repository / "docs" / "governance" / "v1"

    with pytest.raises(
        governance.GovernanceError,
        match="--accept-now requires --fetch-authoritative-refs",
    ):
        governance.check.__wrapped__(
            Namespace(
                repository_root=str(repository),
                governance_dir=str(governance_root),
                roadmap=str(repository / "Agent_Assure_Implementation_Roadmap.md"),
                allow_pending=False,
                accept_now=True,
                historical=False,
                fetch_authoritative_refs=False,
                commitment_time=ISSUED_AT,
            )
        )


def test_check_generation_2_rejects_the_generation_1_signature_time(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    governance_root = repository / "docs" / "governance" / "v1"

    with pytest.raises(
        governance.GovernanceError,
        match="generation-2 --accept-now does not accept --attestation-signed-at",
    ):
        governance.check.__wrapped__(
            Namespace(
                repository_root=str(repository),
                governance_dir=str(governance_root),
                roadmap=str(repository / "Agent_Assure_Implementation_Roadmap.md"),
                allow_pending=False,
                accept_now=True,
                historical=False,
                closure_commit=None,
                acceptance_tag_object=None,
                fetch_authoritative_refs=True,
                acceptance_generation=2,
                commitment_time=None,
                attestation_plan_dir=str(
                    repository / ".tmp/s1-acceptance/current-gate-v2-attestation"
                ),
                attestation_signed_at="2026-10-15T15:03:00Z",
            )
        )


def test_check_generation_2_pending_rejects_caller_supplied_commitment_time(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    governance_root = repository / "docs" / "governance" / "v1"

    with pytest.raises(
        governance.GovernanceError,
        match="generation-2 --allow-pending does not accept --commitment-time",
    ):
        governance.check.__wrapped__(
            Namespace(
                repository_root=str(repository),
                governance_dir=str(governance_root),
                roadmap=str(repository / "Agent_Assure_Implementation_Roadmap.md"),
                allow_pending=True,
                accept_now=False,
                historical=False,
                fetch_authoritative_refs=False,
                acceptance_generation=2,
                commitment_time=ISSUED_AT,
            )
        )


def test_check_generation_2_rejects_caller_supplied_event_times(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    governance_root = repository / "docs" / "governance" / "v1"

    with pytest.raises(
        governance.GovernanceError,
        match="event times are captured internally",
    ):
        governance.check.__wrapped__(
            Namespace(
                repository_root=str(repository),
                governance_dir=str(governance_root),
                roadmap=str(repository / "Agent_Assure_Implementation_Roadmap.md"),
                allow_pending=False,
                accept_now=True,
                historical=False,
                closure_commit=None,
                acceptance_tag_object=None,
                fetch_authoritative_refs=True,
                acceptance_generation=2,
                commitment_time=None,
                gate_checked_at=ISSUED_AT,
                attestation_plan_dir=str(
                    repository / ".tmp/s1-acceptance/current-gate-v2-attestation"
                ),
                attestation_signed_at=None,
            )
        )


def test_check_historical_requires_an_explicit_closure_commit(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    governance_root = repository / "docs" / "governance" / "v1"

    with pytest.raises(
        governance.GovernanceError,
        match="--historical requires --closure-commit",
    ):
        governance.check.__wrapped__(
            Namespace(
                repository_root=str(repository),
                governance_dir=str(governance_root),
                roadmap=str(repository / "Agent_Assure_Implementation_Roadmap.md"),
                allow_pending=False,
                accept_now=False,
                historical=True,
                closure_commit=None,
                fetch_authoritative_refs=False,
                commitment_time=ISSUED_AT,
            )
        )


def test_check_rejects_a_closure_commit_outside_historical_mode(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    governance_root = repository / "docs" / "governance" / "v1"

    with pytest.raises(
        governance.GovernanceError,
        match="--closure-commit is valid only with --historical",
    ):
        governance.check.__wrapped__(
            Namespace(
                repository_root=str(repository),
                governance_dir=str(governance_root),
                roadmap=str(repository / "Agent_Assure_Implementation_Roadmap.md"),
                allow_pending=False,
                accept_now=True,
                historical=False,
                closure_commit="0" * 40,
                fetch_authoritative_refs=True,
                commitment_time=ISSUED_AT,
            )
        )


def test_historical_closure_must_match_the_selected_commit(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    _initialize_git_repository(repository)
    result_commit = _create_result_commit(repository)
    bundle = _closure_bundle()
    _write_closure_files(repository, bundle)
    closure_commit = _commit_all(repository, "S1 closure")
    (repository / "later-sprint.txt").write_text("S2 work\n", encoding="utf-8")
    _commit_all(repository, "later descendant")

    assert (
        governance._validate_s1_closure_checkout(
            repository,
            result_commit=result_commit,
            bundle=bundle,
            expected_closure_commit=closure_commit,
        )
        == closure_commit
    )
    with pytest.raises(
        governance.GovernanceError,
        match="selected historical closure is not the unique valid S1 closure",
    ):
        governance._validate_s1_closure_checkout(
            repository,
            result_commit=result_commit,
            bundle=bundle,
            expected_closure_commit="0" * 40,
        )


def _current_acceptance_attestation_fixture(
    repository: Path,
) -> tuple[governance.RoadmapSnapshot, dict[str, Any], dict[str, Any], str]:
    _initialize_git_repository(repository)
    (repository / ".gitignore").write_text(".tmp/\n", encoding="utf-8")
    validator = repository / "scripts" / "v1_s1_governance.py"
    validator.parent.mkdir(parents=True)
    validator.write_text("# governed validator fixture\n", encoding="utf-8")
    launcher = repository / "scripts" / "v1_s1_governance.ps1"
    launcher.write_text("# governed launcher fixture\n", encoding="utf-8")
    result_commit = _commit_all(repository, "reviewed result")
    (repository / "closure.txt").write_text("signed closure fixture\n", encoding="utf-8")
    closure_commit = _commit_all(repository, "closure")
    bundle = {
        "issued_at_utc": ISSUED_AT,
        "valid_until_utc": VALID_UNTIL,
        "result_commit": result_commit,
        "bundle_digest": _digest("d"),
    }
    live_evidence = {
        "approved_remote_url": governance.APPROVED_ORIGIN_URL,
        "authoritative_remote_refs": {
            "refs/heads/main": governance.PINNED_BASE_COMMIT,
            "refs/tags/v0.7.0": governance.PINNED_TAG_OBJECT,
            "refs/tags/v0.7.0^{}": governance.PINNED_BASE_COMMIT,
        },
        "branch_name": governance.S1_BRANCH_NAME,
        "fetch_performed": True,
        "head_commit": closure_commit,
        "local_refs": {
            "refs/remotes/origin/main^{commit}": governance.PINNED_BASE_COMMIT,
            "refs/tags/v0.7.0^{tag}": governance.PINNED_TAG_OBJECT,
            "refs/tags/v0.7.0^{commit}": governance.PINNED_BASE_COMMIT,
        },
    }
    return _minimal_snapshot(), bundle, live_evidence, closure_commit


def test_current_acceptance_attestation_round_trip_is_durable_in_a_fixed_tag(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    ssh_key_material: tuple[str, SshKey, SshKey],
) -> None:
    executable, signing_key, _ = ssh_key_material
    _trust_key(monkeypatch, signing_key)
    repository = tmp_path / "repository"
    snapshot, bundle, live_evidence, closure_commit = _current_acceptance_attestation_fixture(
        repository
    )
    record = governance.build_current_acceptance_attestation(
        snapshot,
        repository_root=repository,
        bundle=bundle,
        live_repository_evidence=live_evidence,
        gate_checked_at=ISSUED_AT,
        signature_requested_at="2026-10-15T15:05:00Z",
        signer_person_id=PERSON_ID,
    )
    plan_directory = repository / ".tmp" / "s1-acceptance" / "attestation"
    plan = governance._write_current_acceptance_attestation_plan(plan_directory, record)
    claim = plan_directory / "attestation.claim"
    signed = _run_test_ssh_keygen(
        [
            executable,
            "-Y",
            "sign",
            "-f",
            str(signing_key.private_key),
            "-n",
            governance.SIGNATURE_NAMESPACE,
            "-O",
            "hashalg=sha512",
            str(claim),
        ]
    )
    assert signed.returncode == 0, signed.stderr.decode("utf-8", errors="replace")
    assert (
        governance.acceptance_attestation_finalize.__wrapped__(
            Namespace(
                repository_root=str(repository),
                plan_dir=str(plan_directory),
                expected_attestation_digest=plan["attestation_digest"],
            )
        )
        == 0
    )
    signed_record_path = plan_directory / "attestation.signed.json"
    _git(
        repository,
        "-c",
        "tag.gpgSign=false",
        "tag",
        "--annotate",
        "--cleanup=verbatim",
        f"--file={signed_record_path}",
        governance.S1_ACCEPTANCE_TAG_NAME,
        closure_commit,
    )
    tag_object = _git(
        repository,
        "rev-parse",
        f"refs/tags/{governance.S1_ACCEPTANCE_TAG_NAME}^{{tag}}",
    ).stdout.strip()
    tagged = governance._read_tagged_current_acceptance_attestation(
        repository,
        tag_object=tag_object,
        expected_closure_commit=closure_commit,
    )
    gate_time, signature_time = governance._validate_current_acceptance_attestation(
        tagged,
        repository_root=repository,
        expected_closure_commit=closure_commit,
        expected_roadmap_digest=snapshot.raw_digest,
        allow_pending=False,
    )

    assert gate_time == governance._parse_utc(ISSUED_AT, owner="test gate")
    assert signature_time == governance._parse_utc("2026-10-15T15:05:00Z", owner="test signature")

    reordered = dict(reversed(tagged.items()))
    reordered_payload = governance._render_json_bytes(reordered)
    assert reordered_payload != governance._render_acceptance_attestation_bytes(tagged)
    reordered_path = plan_directory / "attestation.reordered.json"
    reordered_path.write_bytes(reordered_payload)
    _git(
        repository,
        "-c",
        "tag.gpgSign=false",
        "tag",
        "--force",
        "--annotate",
        "--cleanup=verbatim",
        f"--file={reordered_path}",
        governance.S1_ACCEPTANCE_TAG_NAME,
        closure_commit,
    )
    reordered_tag_object = _git(
        repository,
        "rev-parse",
        f"refs/tags/{governance.S1_ACCEPTANCE_TAG_NAME}^{{tag}}",
    ).stdout.strip()
    with pytest.raises(
        governance.GovernanceError,
        match="acceptance tag message is not the canonical rendered record",
    ):
        governance._read_tagged_current_acceptance_attestation(
            repository,
            tag_object=reordered_tag_object,
            expected_closure_commit=closure_commit,
        )


def test_current_acceptance_attestation_rejects_stale_or_rebound_evidence(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    snapshot, bundle, live_evidence, _ = _current_acceptance_attestation_fixture(repository)
    with pytest.raises(governance.GovernanceError, match="more than one hour"):
        governance.build_current_acceptance_attestation(
            snapshot,
            repository_root=repository,
            bundle=bundle,
            live_repository_evidence=live_evidence,
            gate_checked_at=ISSUED_AT,
            signature_requested_at="2026-10-15T16:00:01Z",
            signer_person_id=PERSON_ID,
        )

    rebound = copy.deepcopy(live_evidence)
    rebound["authoritative_remote_refs"]["refs/heads/main"] = "0" * 40
    with pytest.raises(governance.GovernanceError, match="live repository evidence changed"):
        governance.build_current_acceptance_attestation(
            snapshot,
            repository_root=repository,
            bundle=bundle,
            live_repository_evidence=rebound,
            gate_checked_at=ISSUED_AT,
            signature_requested_at="2026-10-15T15:05:00Z",
            signer_person_id=PERSON_ID,
        )


def test_generation_2_attestation_uses_truthful_timestamp_free_sshsig_semantics(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    snapshot, bundle, live_evidence, closure_commit = _current_acceptance_attestation_fixture(
        repository
    )
    live_evidence["branch_name"] = governance.S1_CORRECTIVE_BRANCH_NAME
    record = governance.build_current_acceptance_attestation_v2(
        snapshot,
        repository_root=repository,
        bundle=bundle,
        live_repository_evidence=live_evidence,
        validation_started_at=ISSUED_AT,
        gate_completed_at="2026-10-15T15:01:00Z",
        attestation_preparation_started_at="2026-10-15T15:02:00Z",
        signer_person_id="acblabs",
    )

    schema = _schema("current-acceptance-attestation.schema.json")
    schema["properties"]["full_roadmap_digest"]["const"] = snapshot.raw_digest
    governance._validate_json_schema(
        record,
        schema,
        owner="generation-2 current acceptance attestation",
    )

    assert record["format"] == governance.CURRENT_ACCEPTANCE_ATTESTATION_V2_FORMAT
    assert record["time_evidence"] == governance.ATTESTATION_V2_TIME_EVIDENCE
    assert record["finalization_deadline_at_utc"] == "2026-10-15T16:01:00Z"
    assert "signature_requested_at_utc" not in record
    assert "declared_signing_time_utc" not in record
    assert "signed_at_utc" not in record["signature_envelope"]
    assert (
        record["signature_envelope"]["signed_payload_encoding"]
        == governance.ATTESTATION_V2_SIGNATURE_PAYLOAD_ENCODING
    )
    gate_time, ordering_time = governance._validate_current_acceptance_attestation(
        record,
        repository_root=repository,
        expected_closure_commit=closure_commit,
        expected_roadmap_digest=snapshot.raw_digest,
        allow_pending=True,
    )
    assert gate_time == governance._parse_utc("2026-10-15T15:01:00Z", owner="test gate")
    assert ordering_time is None


def test_generation_2_attestation_deadline_is_bundle_capped_and_host_now_fresh() -> None:
    gate = governance._parse_utc("2026-10-15T15:01:00Z", owner="test gate")
    bundle = {
        "issued_at_utc": ISSUED_AT,
        "valid_until_utc": "2026-10-15T15:30:00Z",
    }
    record = {
        "gate_completed_at_utc": "2026-10-15T15:01:00Z",
        "attestation_preparation_started_at_utc": "2026-10-15T15:02:00Z",
        "finalization_deadline_at_utc": "2026-10-15T15:30:00Z",
    }

    deadline_value, deadline_time = governance._derive_generation_2_finalization_deadline(
        gate_time=gate,
        bundle=bundle,
    )
    assert deadline_value == record["finalization_deadline_at_utc"]
    assert deadline_time == governance._parse_utc(
        "2026-10-15T15:30:00Z",
        owner="test deadline",
    )
    assert (
        governance._validate_generation_2_finalization_freshness(
            record,
            bundle=bundle,
            observed_at=governance._parse_utc(
                "2026-10-15T15:29:59.999999Z",
                owner="test finalization host now",
            ),
        )
        == deadline_time
    )

    with pytest.raises(governance.GovernanceError, match="deadline has expired"):
        governance._validate_generation_2_finalization_freshness(
            record,
            bundle=bundle,
            observed_at=deadline_time,
        )
    with pytest.raises(governance.GovernanceError, match="predates attestation preparation"):
        governance._validate_generation_2_finalization_freshness(
            record,
            bundle=bundle,
            observed_at=governance._parse_utc(
                "2026-10-15T15:01:59Z",
                owner="test reversed host now",
            ),
        )

    rebound = {**record, "finalization_deadline_at_utc": "2026-10-15T15:29:59Z"}
    with pytest.raises(governance.GovernanceError, match=r"min\(gate completion \+ one hour"):
        governance._validate_generation_2_finalization_deadline_binding(
            rebound,
            bundle=bundle,
        )


def test_generation_2_finalization_requires_exact_current_local_repository_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    _snapshot, _bundle, live_evidence, closure_commit = _current_acceptance_attestation_fixture(
        repository
    )
    live_evidence["branch_name"] = governance.S1_CORRECTIVE_BRANCH_NAME
    record = {
        "closure_commit": closure_commit,
        "live_repository_evidence": live_evidence,
    }
    current_local_state = copy.deepcopy(live_evidence)
    current_local_state["authoritative_remote_refs"] = {}
    current_local_state["fetch_performed"] = False
    monkeypatch.setattr(
        governance,
        "validate_live_acceptance_repository",
        lambda *_args, **_kwargs: copy.deepcopy(current_local_state),
    )

    governance._validate_generation_2_finalization_local_repository(
        repository,
        record=record,
    )

    moved = copy.deepcopy(current_local_state)
    moved["head_commit"] = "f" * 40
    monkeypatch.setattr(
        governance,
        "validate_live_acceptance_repository",
        lambda *_args, **_kwargs: copy.deepcopy(moved),
    )
    with pytest.raises(governance.GovernanceError, match="changed head_commit"):
        governance._validate_generation_2_finalization_local_repository(
            repository,
            record=record,
        )

    wrong_semantics = copy.deepcopy(current_local_state)
    wrong_semantics["fetch_performed"] = True
    monkeypatch.setattr(
        governance,
        "validate_live_acceptance_repository",
        lambda *_args, **_kwargs: copy.deepcopy(wrong_semantics),
    )
    with pytest.raises(governance.GovernanceError, match="local-ref check changed semantics"):
        governance._validate_generation_2_finalization_local_repository(
            repository,
            record=record,
        )


def test_generation_2_finalization_revalidates_live_records_c2_and_local_refs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = (tmp_path / "repository").resolve()
    governance_root = repository / "docs" / "governance" / "v1"
    governance_root.mkdir(parents=True)
    snapshot = _minimal_snapshot()
    bundle = {
        "format": "agent-assure-governance-bundle/2",
        "bundle_digest": _digest("b"),
        "result_commit": "2" * 40,
    }
    record = {
        "bundle_digest": bundle["bundle_digest"],
        "result_commit": bundle["result_commit"],
        "closure_commit": "3" * 40,
        "full_roadmap_digest": snapshot.raw_digest,
        "validation_started_at_utc": "2026-10-15T15:00:00Z",
    }
    records = {
        "governance-bundle.json": bundle,
        "governance-bundle.schema.json": {},
        "maintainer-signing-key.json": {},
        "corrective-kickoff-authorization.json": {},
        "kickoff-authorization.schema.json": {},
        "kickoff-authorization-v1-boot-01.json": {"ticket": "boot"},
        "kickoff-authorization-v1-base-01.json": {"ticket": "base"},
        "delivery-forecast.json": {},
        "completion-receipt-v1-boot-01.json": {"receipt": "boot"},
        "completion-receipt-v1-base-01.json": {"receipt": "base"},
    }
    monkeypatch.setattr(
        governance,
        "_read_json",
        lambda path: copy.deepcopy(records[Path(path).name]),
    )
    monkeypatch.setattr(
        governance,
        "_load_forecast_v2_workspace",
        lambda **_kwargs: (snapshot, {}, {}, {}, {}, {}, _digest("r")),
    )
    monkeypatch.setattr(governance, "validate_kickoff_authorization", lambda *_a, **_k: None)
    bundle_calls: list[dict[str, Any]] = []
    monkeypatch.setattr(
        governance,
        "validate_governance_bundle",
        lambda *_args, **kwargs: bundle_calls.append(kwargs),
    )
    freshness_observations: list[Any] = []
    deadline = governance._parse_utc("2026-10-15T16:00:00Z", owner="test deadline")

    def validate_freshness(
        _record: dict[str, Any],
        *,
        bundle: dict[str, Any],
        observed_at: Any,
    ) -> Any:
        assert bundle == records["governance-bundle.json"]
        freshness_observations.append(observed_at)
        return deadline

    monkeypatch.setattr(
        governance,
        "_validate_generation_2_finalization_freshness",
        validate_freshness,
    )
    final_gate_calls: list[dict[str, Any]] = []
    monkeypatch.setattr(
        governance,
        "_validate_generation_2_final_gate_validity",
        lambda **kwargs: final_gate_calls.append(kwargs),
    )
    local_state_calls: list[dict[str, Any]] = []
    monkeypatch.setattr(
        governance,
        "_validate_generation_2_finalization_local_repository",
        lambda _root, *, record: local_state_calls.append(record),
    )
    closure_calls: list[dict[str, Any]] = []
    monkeypatch.setattr(
        governance,
        "_validate_s1_closure_checkout",
        lambda _root, **kwargs: closure_calls.append(kwargs) or record["closure_commit"],
    )
    host_times = iter(
        [
            "2026-10-15T15:03:00Z",
            "2026-10-15T15:04:00Z",
        ]
    )
    monkeypatch.setattr(governance, "_canonical_host_utc_now", lambda: next(host_times))

    assert (
        governance._revalidate_generation_2_finalization_state(
            repository,
            record=record,
        )
        == "2026-10-15T16:00:00Z"
    )
    assert len(freshness_observations) == 2
    assert final_gate_calls[0]["gate_time"] == freshness_observations[-1]
    assert bundle_calls[0]["require_current_closure"] is True
    assert bundle_calls[0]["expected_closure_commit"] == record["closure_commit"]
    assert local_state_calls == [record]
    assert closure_calls == [
        {
            "result_commit": bundle["result_commit"],
            "bundle": bundle,
            "require_current_checkout": True,
            "expected_closure_commit": record["closure_commit"],
        }
    ]


def test_check_generation_2_dispatches_to_corrective_branch_builder_and_schema(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository = tmp_path / "repository"
    governance_root = repository / "docs" / "governance" / "v1"
    repository.mkdir()
    forecast_import_evidence = governance._forecast_v2_signature_import_evidence(
        signature_plan_digest=_digest("9"),
        claim_preparation_started_at_utc=ISSUED_AT,
        import_verification_started_at_utc=ISSUED_AT,
        import_verification_completed_at_utc=ISSUED_AT,
        issued_at_utc=ISSUED_AT,
        valid_until_utc=VALID_UNTIL,
    )
    records: dict[str, dict[str, Any]] = {
        "approval-roster.json": {},
        "approval-roster.schema.json": {},
        "maintainer-signing-key.json": {},
        "maintainer-signing-key.schema.json": {},
        "corrective-kickoff-authorization.json": {
            "import_verification": {"verification_recorded_at_utc": ISSUED_AT}
        },
        "corrective-kickoff-authorization.schema.json": {},
        "baseline-observations.json": {"inventory_started_at_utc": ISSUED_AT},
        "baseline-observations.schema.json": {},
        "kickoff-authorization.schema.json": {},
        "kickoff-authorization-v1-base-01.json": {
            "authorization_digest": _digest("a"),
            "issued_at_utc": ISSUED_AT,
            "valid_until_utc": VALID_UNTIL,
        },
        "kickoff-authorization-v1-boot-01.json": {
            "authorization_digest": _digest("b"),
            "issued_at_utc": ISSUED_AT,
            "valid_until_utc": VALID_UNTIL,
        },
        "delivery-forecast.aggregation-registry.json": {},
        "delivery-forecast.aggregation-registry.schema.json": {},
        "delivery-forecast.authoring-ledger.json": {},
        "delivery-forecast.authoring-ledger.schema.json": {},
        "delivery-forecast.json": {
            "format": "agent-assure-delivery-forecast/2",
            "forecast_status": "accepted",
            "record_digest": _digest("c"),
            "issued_at_utc": ISSUED_AT,
            "valid_until_utc": VALID_UNTIL,
            "signature_envelope": {
                "verification_evidence": copy.deepcopy(forecast_import_evidence)
            },
            "acceptance_receipt": {
                "signature_envelope": {
                    "verification_evidence": copy.deepcopy(forecast_import_evidence)
                }
            },
        },
        "delivery-forecast.schema.json": {},
        "ticket-completion-receipt.schema.json": {},
        "completion-receipt-v1-base-01.json": {
            "format": "agent-assure-ticket-completion-receipt/2"
        },
        "completion-receipt-v1-boot-01.json": {
            "format": "agent-assure-ticket-completion-receipt/2"
        },
        "governance-bundle.json": {
            "format": "agent-assure-governance-bundle/2",
            "bundle_status": "accepted",
            "bundle_digest": _digest("d"),
            "issued_at_utc": ISSUED_AT,
            "valid_until_utc": VALID_UNTIL,
            "claim_prepared_at_utc": ISSUED_AT,
            "signature_import_evidence": {"verification_recorded_at_utc": ISSUED_AT},
        },
        "governance-bundle.schema.json": {},
        "current-acceptance-attestation.schema.json": {"schema": "v2"},
    }
    live_evidence = {"head_commit": "f" * 40}
    attestation = {
        "format": governance.CURRENT_ACCEPTANCE_ATTESTATION_V2_FORMAT,
        "attestation_digest": _digest("f"),
    }
    observed: dict[str, Any] = {"schema_calls": [], "events": []}

    monkeypatch.setattr(governance, "validate_local_only_roadmap", lambda *_: "roadmap")
    monkeypatch.setattr(governance, "load_roadmap", lambda *_: _minimal_snapshot())
    monkeypatch.setattr(governance, "_read_json", lambda path: records[path.name])
    monkeypatch.setattr(
        governance,
        "_corrective_private_acceptance_path",
        lambda *_args, **_kwargs: repository / ".tmp/s1-acceptance/current-gate-v2-attestation",
    )
    monkeypatch.setattr(
        governance,
        "validate_approval_roster",
        lambda *_args, **_kwargs: (_digest("e"), PERSON_ID),
    )

    def validate_signing_key(*_args: Any, **_kwargs: Any) -> str:
        observed["events"].append("signing-key")
        return _digest("7")

    monkeypatch.setattr(
        governance,
        "validate_maintainer_signing_key",
        validate_signing_key,
    )

    def validate_corrective_authorization(*_args: Any, **_kwargs: Any) -> str:
        observed["events"].append("corrective-authorization")
        return governance.CORRECTIVE_KICKOFF_CLAIM_DIGEST

    monkeypatch.setattr(
        governance,
        "validate_corrective_kickoff_authorization",
        validate_corrective_authorization,
    )

    def validate_corrective_allowlist(*_args: Any, **_kwargs: Any) -> tuple[str, ...]:
        observed["events"].append("corrective-allowlist")
        return tuple(sorted(governance.S1_CORRECTIVE_CLOSURE_PATHS))

    monkeypatch.setattr(
        governance,
        "_corrective_authorized_paths",
        validate_corrective_allowlist,
    )

    def validate_baseline(*_args: Any, **_kwargs: Any) -> str:
        observed["events"].append("baseline")
        return _digest("8")

    monkeypatch.setattr(governance, "validate_baseline_observations", validate_baseline)
    validate_authorization_order = governance._validate_corrective_authorization_precedes_baseline

    def observe_authorization_order(**kwargs: Any) -> None:
        observed["events"].append("authorization-before-baseline")
        validate_authorization_order(**kwargs)

    monkeypatch.setattr(
        governance,
        "_validate_corrective_authorization_precedes_baseline",
        observe_authorization_order,
    )
    for validator_name in (
        "_resolve_aggregation_method",
        "validate_authoring_ledger",
        "_validate_current_acceptance_attestation",
    ):
        monkeypatch.setattr(governance, validator_name, lambda *_args, **_kwargs: None)

    def validate_kickoff(*_args: Any, **kwargs: Any) -> None:
        observed["events"].append(f"kickoff:{kwargs['expected_ticket_id']}")
        observed.setdefault("kickoff_times", []).append(kwargs["validation_time"])

    monkeypatch.setattr(governance, "validate_kickoff_authorization", validate_kickoff)

    def validate_receipt(*_args: Any, **kwargs: Any) -> None:
        observed["events"].append(f"receipt:{kwargs['expected_ticket_id']}")
        observed.setdefault("receipt_times", []).append(kwargs["validation_time"])

    monkeypatch.setattr(governance, "validate_ticket_completion_receipt", validate_receipt)

    def validate_bundle(*_args: Any, **kwargs: Any) -> None:
        observed["events"].append("bundle-and-current-closure")
        observed["bundle_validation_time"] = kwargs["validation_time"]

    monkeypatch.setattr(governance, "validate_governance_bundle", validate_bundle)

    def validate_schema(record: dict[str, Any], schema: dict[str, Any], *, owner: str) -> None:
        observed["schema_calls"].append((record, schema, owner))

    monkeypatch.setattr(governance, "_validate_json_schema", validate_schema)

    def validate_forecast(*_args: Any, **kwargs: Any) -> None:
        observed["events"].append("forecast")
        observed["forecast_commitment_time"] = kwargs["commitment_time"]

    monkeypatch.setattr(governance, "validate_forecast", validate_forecast)

    def validate_live(
        _repository_root: Path, *, fetch: bool, expected_branch_name: str
    ) -> dict[str, Any]:
        observed["events"].append("live-repository")
        observed["fetch"] = fetch
        observed["branch"] = expected_branch_name
        return live_evidence

    monkeypatch.setattr(governance, "validate_live_acceptance_repository", validate_live)

    def build_v2(*_args: Any, **kwargs: Any) -> dict[str, Any]:
        observed["events"].append("build-attestation")
        observed["builder_kwargs"] = kwargs
        return attestation

    monkeypatch.setattr(governance, "build_current_acceptance_attestation_v2", build_v2)
    captured_event_times = iter(
        [
            ISSUED_AT,
            "2026-10-15T15:01:00Z",
            "2026-10-15T15:02:00Z",
        ]
    )

    def capture_time() -> str:
        value = next(captured_event_times)
        observed["events"].append(f"clock:{value}")
        return value

    monkeypatch.setattr(governance, "_canonical_host_utc_now", capture_time)
    validate_final_gate = governance._validate_generation_2_final_gate_validity

    def observe_final_gate(**kwargs: Any) -> None:
        observed["events"].append("final-gate-validity")
        validate_final_gate(**kwargs)

    monkeypatch.setattr(
        governance,
        "_validate_generation_2_final_gate_validity",
        observe_final_gate,
    )
    monkeypatch.setattr(
        governance,
        "_write_current_acceptance_attestation_plan",
        lambda path, record: {
            "attestation_digest": record["attestation_digest"],
            "plan_directory": str(path),
        },
    )

    assert (
        governance.check.__wrapped__(
            Namespace(
                repository_root=str(repository),
                governance_dir=str(governance_root),
                roadmap=str(repository / "Agent_Assure_Implementation_Roadmap.md"),
                allow_pending=False,
                accept_now=True,
                historical=False,
                closure_commit=None,
                acceptance_tag_object=None,
                fetch_authoritative_refs=True,
                acceptance_generation=2,
                commitment_time=None,
                attestation_plan_dir=str(
                    repository / ".tmp/s1-acceptance/current-gate-v2-attestation"
                ),
                attestation_signed_at=None,
            )
        )
        == 0
    )

    assert observed["fetch"] is True
    assert observed["branch"] == governance.S1_CORRECTIVE_BRANCH_NAME
    assert observed["forecast_commitment_time"] == governance._parse_utc(
        ISSUED_AT, owner="test preliminary validation"
    )
    assert observed["bundle_validation_time"] == observed["forecast_commitment_time"]
    assert observed["kickoff_times"] == [
        observed["forecast_commitment_time"],
        observed["forecast_commitment_time"],
    ]
    assert observed["receipt_times"] == observed["kickoff_times"]
    assert observed["builder_kwargs"]["validation_started_at"] == ISSUED_AT
    assert observed["builder_kwargs"]["gate_completed_at"] == "2026-10-15T15:01:00Z"
    assert (
        observed["builder_kwargs"]["attestation_preparation_started_at"] == "2026-10-15T15:02:00Z"
    )
    assert observed["events"] == [
        f"clock:{ISSUED_AT}",
        "live-repository",
        "signing-key",
        "corrective-authorization",
        "corrective-allowlist",
        "baseline",
        "authorization-before-baseline",
        "kickoff:V1-BOOT-01",
        "kickoff:V1-BASE-01",
        "forecast",
        "receipt:V1-BOOT-01",
        "receipt:V1-BASE-01",
        "bundle-and-current-closure",
        "clock:2026-10-15T15:01:00Z",
        "final-gate-validity",
        "clock:2026-10-15T15:02:00Z",
        "build-attestation",
    ]
    assert (
        attestation,
        records["current-acceptance-attestation.schema.json"],
        "generation-2 current acceptance attestation",
    ) in observed["schema_calls"]
    check_output = json.loads(capsys.readouterr().out)
    assert check_output["result"] == "valid_current_closure_attestation_prepared"
    assert check_output["attestation_plan"]["attestation_digest"] == _digest("f")
    assert "attestation_digest" not in check_output


@pytest.mark.parametrize(
    ("mutation", "expected_error"),
    [
        ("signing-key", "unexpected public_key"),
        (
            "corrective-authorization",
            "corrective kickoff authorization schema validation failed",
        ),
        ("baseline", "baseline repository changed cached_origin_main_commit"),
        ("missing-corrective-authorization", "missing corrective kickoff authorization"),
    ],
)
def test_check_generation_2_rejects_tampered_or_missing_validated_predecessors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    expected_error: str,
) -> None:
    records = {
        name: _record(name)
        for name in (
            "approval-roster.json",
            "approval-roster.schema.json",
            "maintainer-signing-key.json",
            "maintainer-signing-key.schema.json",
            "corrective-kickoff-authorization.json",
            "corrective-kickoff-authorization.schema.json",
            "baseline-observations.json",
            "baseline-observations.schema.json",
        )
    }
    snapshot = _minimal_snapshot(
        raw_digest=records["corrective-kickoff-authorization.json"]["signed_claim"]["evidence"][
            "roadmap_raw_sha256"
        ]
    )
    if mutation == "signing-key":
        records["maintainer-signing-key.json"]["public_key"] = "ssh-ed25519 tampered"
    elif mutation == "corrective-authorization":
        records["corrective-kickoff-authorization.json"]["signed_claim"]["authorized_person_id"] = (
            "tampered"
        )
    elif mutation == "baseline":
        records["baseline-observations.json"]["repository"]["cached_origin_main_commit"] = "0" * 40
    else:
        records.pop("corrective-kickoff-authorization.json")

    def read_record(path: Path) -> dict[str, Any]:
        if path.name not in records:
            raise governance.GovernanceError("missing corrective kickoff authorization")
        return copy.deepcopy(records[path.name])

    monkeypatch.setattr(governance, "_read_json", read_record)
    monkeypatch.setattr(governance, "validate_local_only_roadmap", lambda *_: None)
    monkeypatch.setattr(governance, "load_roadmap", lambda *_: snapshot)
    monkeypatch.setattr(
        governance,
        "_corrective_private_acceptance_path",
        lambda *_args, **_kwargs: tmp_path / "attestation-plan",
    )
    monkeypatch.setattr(
        governance,
        "validate_live_acceptance_repository",
        lambda *_args, **_kwargs: {"head_commit": "f" * 40},
    )
    monkeypatch.setattr(
        governance,
        "validate_approval_roster",
        lambda *_args, **_kwargs: (
            governance.approval_roster_digest(records["approval-roster.json"]),
            "acblabs",
        ),
    )
    monkeypatch.setattr(governance, "_canonical_host_utc_now", lambda: ISSUED_AT)

    with pytest.raises(governance.GovernanceError, match=expected_error):
        governance.check.__wrapped__(
            Namespace(
                repository_root=str(ROOT),
                governance_dir=str(GOVERNANCE_ROOT),
                roadmap=str(ROADMAP),
                allow_pending=False,
                accept_now=True,
                historical=False,
                closure_commit=None,
                acceptance_tag_object=None,
                fetch_authoritative_refs=True,
                acceptance_generation=2,
                commitment_time=None,
                attestation_plan_dir=str(tmp_path / "attestation-plan"),
                attestation_signed_at=None,
            )
        )


def test_generation_2_attestation_enforces_runtime_event_ordering() -> None:
    with pytest.raises(governance.GovernanceError, match="validation start <= gate completion"):
        governance._validate_attestation_v2_event_times(
            validation_started_at="2026-10-15T15:00:00Z",
            gate_completed_at="2026-10-15T14:59:59Z",
            attestation_preparation_started_at="2026-10-15T15:01:00Z",
        )
    with pytest.raises(governance.GovernanceError, match="more than one hour"):
        governance._validate_attestation_v2_event_times(
            validation_started_at="2026-10-15T15:00:00Z",
            gate_completed_at="2026-10-15T15:00:00Z",
            attestation_preparation_started_at="2026-10-15T16:00:01Z",
        )


@pytest.mark.parametrize(
    ("expired_owner", "expected_error"),
    [
        ("V1-BASE-01", "V1-BASE-01 kickoff"),
        ("forecast", "forecast observations violate"),
        ("bundle", "generation-2 governance bundle"),
    ],
)
def test_generation_2_final_gate_rejects_records_that_expired_during_validation(
    expired_owner: str,
    expected_error: str,
) -> None:
    gate_value = "2026-10-15T15:02:00Z"
    validation_started = "2026-10-15T15:01:00Z"
    kickoff_records = {
        ticket_id: {
            "issued_at_utc": ISSUED_AT,
            "valid_until_utc": VALID_UNTIL,
        }
        for ticket_id in ("V1-BOOT-01", "V1-BASE-01")
    }
    forecast = {
        "format": "agent-assure-delivery-forecast/2",
        "forecast_status": "accepted",
        "issued_at_utc": ISSUED_AT,
        "valid_until_utc": VALID_UNTIL,
    }
    forecast_evidence = governance._forecast_v2_signature_import_evidence(
        signature_plan_digest=_digest("9"),
        claim_preparation_started_at_utc=ISSUED_AT,
        import_verification_started_at_utc=ISSUED_AT,
        import_verification_completed_at_utc=ISSUED_AT,
        issued_at_utc=ISSUED_AT,
        valid_until_utc=VALID_UNTIL,
    )
    forecast["signature_envelope"] = {"verification_evidence": copy.deepcopy(forecast_evidence)}
    forecast["acceptance_receipt"] = {
        "signature_envelope": {"verification_evidence": copy.deepcopy(forecast_evidence)}
    }
    bundle = {
        "format": "agent-assure-governance-bundle/2",
        "issued_at_utc": ISSUED_AT,
        "valid_until_utc": VALID_UNTIL,
        "claim_prepared_at_utc": ISSUED_AT,
        "signature_import_evidence": {"verification_recorded_at_utc": ISSUED_AT},
    }
    corrective_authorization = {"import_verification": {"verification_recorded_at_utc": ISSUED_AT}}
    if expired_owner in kickoff_records:
        kickoff_records[expired_owner]["valid_until_utc"] = gate_value
    elif expired_owner == "forecast":
        forecast["valid_until_utc"] = gate_value
    else:
        bundle["valid_until_utc"] = gate_value

    with pytest.raises(governance.GovernanceError, match=expected_error):
        governance._validate_generation_2_final_gate_validity(
            validation_started_time=governance._parse_utc(
                validation_started, owner="test validation start"
            ),
            gate_time=governance._parse_utc(gate_value, owner="test final gate"),
            kickoff_records=kickoff_records,
            corrective_authorization=corrective_authorization,
            forecast=forecast,
            bundle=bundle,
        )


def _generation_2_gate_ordering_fixture() -> tuple[
    dict[str, dict[str, Any]],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    evidence = governance._forecast_v2_signature_import_evidence(
        signature_plan_digest=_digest("9"),
        claim_preparation_started_at_utc=ISSUED_AT,
        import_verification_started_at_utc=ISSUED_AT,
        import_verification_completed_at_utc=ISSUED_AT,
        issued_at_utc=ISSUED_AT,
        valid_until_utc=VALID_UNTIL,
    )
    return (
        {
            ticket_id: {
                "issued_at_utc": ISSUED_AT,
                "valid_until_utc": VALID_UNTIL,
            }
            for ticket_id in ("V1-BOOT-01", "V1-BASE-01")
        },
        {"import_verification": {"verification_recorded_at_utc": ISSUED_AT}},
        {
            "format": "agent-assure-delivery-forecast/2",
            "forecast_status": "accepted",
            "issued_at_utc": ISSUED_AT,
            "valid_until_utc": VALID_UNTIL,
            "signature_envelope": {"verification_evidence": copy.deepcopy(evidence)},
            "acceptance_receipt": {
                "signature_envelope": {"verification_evidence": copy.deepcopy(evidence)}
            },
        },
        {
            "format": "agent-assure-governance-bundle/2",
            "issued_at_utc": ISSUED_AT,
            "valid_until_utc": VALID_UNTIL,
            "claim_prepared_at_utc": ISSUED_AT,
            "signature_import_evidence": {"verification_recorded_at_utc": ISSUED_AT},
        },
    )


@pytest.mark.parametrize(
    ("mutation", "expected_error"),
    [
        (
            lambda _auth, _forecast, bundle: (
                bundle.__setitem__("claim_prepared_at_utc", "2026-10-15T15:00:02Z")
                or bundle["signature_import_evidence"].__setitem__(
                    "verification_recorded_at_utc", "2026-10-15T15:00:01Z"
                )
            ),
            "governance bundle observations violate",
        ),
        (
            lambda _auth, _forecast, bundle: bundle["signature_import_evidence"].__setitem__(
                "verification_recorded_at_utc", "2026-10-15T15:01:01Z"
            ),
            "governance bundle observations violate",
        ),
        (
            lambda _auth, forecast, _bundle: (
                forecast["signature_envelope"]["verification_evidence"].__setitem__(
                    "import_verification_completed_at_utc", "2026-10-15T15:01:01Z"
                ),
                forecast["acceptance_receipt"]["signature_envelope"][
                    "verification_evidence"
                ].__setitem__("import_verification_completed_at_utc", "2026-10-15T15:01:01Z"),
            ),
            "forecast observations violate",
        ),
        (
            lambda _auth, forecast, _bundle: forecast["acceptance_receipt"]["signature_envelope"][
                "verification_evidence"
            ].__setitem__("import_verification_completed_at_utc", "2026-10-15T15:00:01Z"),
            "import observations do not match",
        ),
        (
            lambda authorization, _forecast, _bundle: authorization[
                "import_verification"
            ].__setitem__("verification_recorded_at_utc", "2026-10-15T15:01:01Z"),
            "authorization verification occurs after",
        ),
    ],
)
def test_generation_2_final_gate_rejects_reversed_or_late_import_observations(
    mutation: Any,
    expected_error: str,
) -> None:
    kickoffs, authorization, forecast, bundle = _generation_2_gate_ordering_fixture()
    mutation(authorization, forecast, bundle)

    with pytest.raises(governance.GovernanceError, match=expected_error):
        governance._validate_generation_2_final_gate_validity(
            validation_started_time=governance._parse_utc(
                "2026-10-15T15:01:00Z", owner="test validation start"
            ),
            gate_time=governance._parse_utc("2026-10-15T15:02:00Z", owner="test final gate"),
            kickoff_records=kickoffs,
            corrective_authorization=authorization,
            forecast=forecast,
            bundle=bundle,
        )


def test_corrective_authorization_must_precede_baseline_inventory() -> None:
    authorization = {
        "import_verification": {"verification_recorded_at_utc": "2026-10-15T15:00:00.0000001Z"}
    }
    baseline = {"inventory_started_at_utc": "2026-10-15T15:00:00Z"}

    with pytest.raises(governance.GovernanceError, match="inventory predates"):
        governance._validate_corrective_authorization_precedes_baseline(
            corrective_authorization=authorization,
            baseline=baseline,
        )


def test_historical_generation_2_attestation_rejects_late_bundle_import_observation() -> None:
    _, _, _, bundle = _generation_2_gate_ordering_fixture()
    bundle["signature_import_evidence"]["verification_recorded_at_utc"] = "2026-10-15T15:01:01Z"
    record = {
        "validation_started_at_utc": "2026-10-15T15:01:00Z",
        "time_evidence": governance.ATTESTATION_V2_TIME_EVIDENCE,
    }

    with pytest.raises(governance.GovernanceError, match="observations violate"):
        governance._validate_historical_attestation_bundle_time_evidence(
            record,
            acceptance_generation=2,
            gate_time=governance._parse_utc("2026-10-15T15:02:00Z", owner="test historical gate"),
            attestation_evidence_time=governance._parse_utc(
                "2026-10-15T15:03:00Z", owner="test historical preparation"
            ),
            bundle=bundle,
        )


def test_generation_2_attestation_signature_round_trip_claims_no_signature_time(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    ssh_key_material: tuple[str, SshKey, SshKey],
) -> None:
    executable, signing_key, _ = ssh_key_material
    _trust_key(monkeypatch, signing_key)
    repository = tmp_path / "repository"
    snapshot, bundle, live_evidence, closure_commit = _current_acceptance_attestation_fixture(
        repository
    )
    live_evidence["branch_name"] = governance.S1_CORRECTIVE_BRANCH_NAME
    record = governance.build_current_acceptance_attestation_v2(
        snapshot,
        repository_root=repository,
        bundle=bundle,
        live_repository_evidence=live_evidence,
        validation_started_at=ISSUED_AT,
        gate_completed_at="2026-10-15T15:01:00Z",
        attestation_preparation_started_at="2026-10-15T15:02:00Z",
        signer_person_id=PERSON_ID,
    )
    plan_directory = repository / ".tmp/s1-acceptance/current-gate-v2-attestation"
    plan = governance._write_current_acceptance_attestation_plan(plan_directory, record)
    claim = plan_directory / "attestation.claim"
    signed = _run_test_ssh_keygen(
        [
            executable,
            "-Y",
            "sign",
            "-f",
            str(signing_key.private_key),
            "-n",
            governance.SIGNATURE_NAMESPACE,
            "-O",
            "hashalg=sha512",
            str(claim),
        ]
    )
    assert signed.returncode == 0, signed.stderr.decode("utf-8", errors="replace")
    monkeypatch.setattr(
        governance,
        "_revalidate_generation_2_finalization_state",
        lambda _repository_root, *, record: record["finalization_deadline_at_utc"],
    )

    assert (
        governance.acceptance_attestation_finalize.__wrapped__(
            Namespace(
                repository_root=str(repository),
                plan_dir=str(plan_directory),
                expected_attestation_digest=plan["attestation_digest"],
            )
        )
        == 0
    )
    signed_record = governance._read_json(plan_directory / "attestation.signed.json")
    assert "signed_at_utc" not in signed_record["signature_envelope"]
    gate_time, ordering_time = governance._validate_current_acceptance_attestation(
        signed_record,
        repository_root=repository,
        expected_closure_commit=closure_commit,
        expected_roadmap_digest=snapshot.raw_digest,
        allow_pending=False,
    )
    assert gate_time == governance._parse_utc("2026-10-15T15:01:00Z", owner="test gate")
    assert ordering_time == governance._parse_utc(
        "2026-10-15T15:02:00Z", owner="test preparation start"
    )


def test_attestation_finalize_recovers_after_atomic_publication_and_rejects_partial_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    ssh_key_material: tuple[str, SshKey, SshKey],
) -> None:
    executable, signing_key, _ = ssh_key_material
    _trust_key(monkeypatch, signing_key)
    repository = tmp_path / "repository"
    snapshot, bundle, live_evidence, _ = _current_acceptance_attestation_fixture(repository)
    live_evidence["branch_name"] = governance.S1_CORRECTIVE_BRANCH_NAME
    record = governance.build_current_acceptance_attestation_v2(
        snapshot,
        repository_root=repository,
        bundle=bundle,
        live_repository_evidence=live_evidence,
        validation_started_at=ISSUED_AT,
        gate_completed_at="2026-10-15T15:01:00Z",
        attestation_preparation_started_at="2026-10-15T15:02:00Z",
        signer_person_id=PERSON_ID,
    )
    plan_directory = repository / ".tmp/s1-acceptance/current-gate-v2-attestation-recovery"
    plan = governance._write_current_acceptance_attestation_plan(plan_directory, record)
    claim = plan_directory / "attestation.claim"
    signed = _run_test_ssh_keygen(
        [
            executable,
            "-Y",
            "sign",
            "-f",
            str(signing_key.private_key),
            "-n",
            governance.SIGNATURE_NAMESPACE,
            "-O",
            "hashalg=sha512",
            str(claim),
        ]
    )
    assert signed.returncode == 0, signed.stderr.decode("utf-8", errors="replace")
    args = Namespace(
        repository_root=str(repository),
        plan_dir=str(plan_directory),
        expected_attestation_digest=plan["attestation_digest"],
    )
    output = plan_directory / "attestation.signed.json"

    def reject_stale_reuse(*_args: Any, **_kwargs: Any) -> str:
        raise governance.GovernanceError(
            "generation-2 attestation finalization deadline has expired"
        )

    monkeypatch.setattr(
        governance,
        "_revalidate_generation_2_finalization_state",
        reject_stale_reuse,
    )
    with pytest.raises(governance.GovernanceError, match="deadline has expired"):
        governance.acceptance_attestation_finalize.__wrapped__(args)
    assert not output.exists()

    state_revalidations = 0

    def revalidate_current_state(
        _repository_root: Path,
        *,
        record: dict[str, Any],
    ) -> str:
        nonlocal state_revalidations
        state_revalidations += 1
        return record["finalization_deadline_at_utc"]

    monkeypatch.setattr(
        governance,
        "_revalidate_generation_2_finalization_state",
        revalidate_current_state,
    )
    real_publish = governance._publish_new_file_atomically

    def publish_then_interrupt(
        path: Path,
        payload: bytes,
        *,
        staging_directory: Path,
    ) -> None:
        real_publish(path, payload, staging_directory=staging_directory)
        raise OSError("simulated interruption after atomic publication")

    monkeypatch.setattr(
        governance,
        "_publish_new_file_atomically",
        publish_then_interrupt,
    )
    with pytest.raises(
        governance.GovernanceError,
        match="unable to atomically publish signed current acceptance attestation",
    ):
        governance.acceptance_attestation_finalize.__wrapped__(args)

    published_payload = output.read_bytes()
    assert governance._read_json(output)["attestation_digest"] == plan["attestation_digest"]

    monkeypatch.setattr(governance, "_publish_new_file_atomically", real_publish)
    capsys.readouterr()
    assert governance.acceptance_attestation_finalize.__wrapped__(args) == 0
    retry_result = json.loads(capsys.readouterr().out)
    assert retry_result["idempotent_recovery"] is True
    assert retry_result["finalization_deadline_at_utc"] == record["finalization_deadline_at_utc"]
    assert state_revalidations == 2
    assert output.read_bytes() == published_payload

    monkeypatch.setattr(
        governance,
        "_revalidate_generation_2_finalization_state",
        reject_stale_reuse,
    )
    with pytest.raises(governance.GovernanceError, match="deadline has expired"):
        governance.acceptance_attestation_finalize.__wrapped__(args)
    assert output.read_bytes() == published_payload

    monkeypatch.setattr(
        governance,
        "_revalidate_generation_2_finalization_state",
        revalidate_current_state,
    )
    partial_payload = published_payload[: len(published_payload) // 2]
    output.write_bytes(partial_payload)
    with pytest.raises(
        governance.GovernanceError,
        match="differs from the reverified exact output",
    ):
        governance.acceptance_attestation_finalize.__wrapped__(args)
    assert state_revalidations == 2
    assert output.read_bytes() == partial_payload


def test_generation_2_historical_binding_checks_executing_validator_and_launcher_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    validator = repository / "scripts" / "v1_s1_governance.py"
    validator.parent.mkdir(parents=True)
    validator.write_bytes(Path(governance.__file__).read_bytes())
    launcher = repository / "scripts" / "v1_s1_governance.ps1"
    launcher.write_text("# exact launcher fixture\n", encoding="utf-8")
    record = {
        "validator_artifact": governance._artifact_evidence(
            repository,
            "scripts/v1_s1_governance.py",
            kind="governance_validator",
        ),
        "launcher_artifact": governance._artifact_evidence(
            repository,
            "scripts/v1_s1_governance.ps1",
            kind="governance_runtime_launcher",
        ),
    }

    with pytest.raises(governance.GovernanceError, match="selected worktree validator"):
        governance._validate_executing_acceptance_artifacts(
            record,
            repository_root=repository,
        )

    monkeypatch.setattr(governance, "__file__", str(validator))
    governance._validate_executing_acceptance_artifacts(
        record,
        repository_root=repository,
    )
    launcher.write_text("# tampered launcher fixture\n", encoding="utf-8")
    with pytest.raises(governance.GovernanceError, match="launcher bytes differ"):
        governance._validate_executing_acceptance_artifacts(
            record,
            repository_root=repository,
        )


def test_historical_check_requires_the_signed_acceptance_tag_object(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    governance_root = repository / "docs" / "governance" / "v1"

    with pytest.raises(
        governance.GovernanceError,
        match="--historical requires --acceptance-tag-object",
    ):
        governance.check.__wrapped__(
            Namespace(
                repository_root=str(repository),
                governance_dir=str(governance_root),
                roadmap=str(repository / "Agent_Assure_Implementation_Roadmap.md"),
                allow_pending=False,
                accept_now=False,
                historical=True,
                closure_commit="0" * 40,
                acceptance_tag_object=None,
                fetch_authoritative_refs=False,
                commitment_time=None,
                attestation_plan_dir=None,
                attestation_signed_at=None,
            )
        )


def _create_synthetic_generation_1_acceptance_tag(
    repository: Path,
    *,
    target_commit: str,
    force: bool = False,
) -> str:
    record = {
        "format": governance.CURRENT_ACCEPTANCE_ATTESTATION_V1_FORMAT,
        "acceptance_tag_name": governance.S1_ACCEPTANCE_TAG_NAME,
    }
    message_path = repository / "generation-1-attestation.json"
    message_path.write_bytes(governance._render_acceptance_attestation_bytes(record))
    arguments = [
        "-c",
        "tag.gpgSign=false",
        "tag",
        "--annotate",
        "--cleanup=verbatim",
        f"--file={message_path}",
    ]
    if force:
        arguments.append("--force")
    arguments.extend([governance.S1_ACCEPTANCE_TAG_NAME, target_commit])
    _git(repository, *arguments)
    return _git(
        repository,
        "rev-parse",
        f"refs/tags/{governance.S1_ACCEPTANCE_TAG_NAME}^{{tag}}",
    ).stdout.strip()


def _generation_1_tag_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, str, str]:
    repository = tmp_path / "repository"
    _initialize_git_repository(repository)
    (repository / "generation-1.txt").write_text("result\n", encoding="utf-8")
    closure_commit = _commit_all(repository, "generation-1 closure")
    tag_object = _create_synthetic_generation_1_acceptance_tag(
        repository,
        target_commit=closure_commit,
    )
    monkeypatch.setattr(
        governance,
        "S1_ACCEPTANCE_V1_CLOSURE_COMMIT",
        closure_commit,
    )
    monkeypatch.setattr(governance, "S1_ACCEPTANCE_V1_TAG_OBJECT", tag_object)
    return repository, closure_commit, tag_object


def test_generation_2_historical_predecessor_requires_a1_ref(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, _closure_commit, _tag_object = _generation_1_tag_fixture(
        tmp_path,
        monkeypatch,
    )
    _git(repository, "tag", "--delete", governance.S1_ACCEPTANCE_TAG_NAME)

    with pytest.raises(
        governance.GovernanceError,
        match="fixed S1 acceptance tag does not resolve",
    ):
        governance._validate_generation_1_predecessor_acceptance(
            repository,
            expected_roadmap_digest=_digest("1"),
        )


def test_generation_2_historical_predecessor_rejects_moved_a1_ref(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, _closure_commit, original_tag_object = _generation_1_tag_fixture(
        tmp_path,
        monkeypatch,
    )
    (repository / "generation-2.txt").write_text("later\n", encoding="utf-8")
    later_commit = _commit_all(repository, "later commit")
    moved_tag_object = _create_synthetic_generation_1_acceptance_tag(
        repository,
        target_commit=later_commit,
        force=True,
    )
    assert moved_tag_object != original_tag_object

    with pytest.raises(
        governance.GovernanceError,
        match="fixed S1 acceptance tag does not resolve",
    ):
        governance._validate_generation_1_predecessor_acceptance(
            repository,
            expected_roadmap_digest=_digest("1"),
        )


def test_generation_2_historical_predecessor_rejects_wrong_a1_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, closure_commit, _tag_object = _generation_1_tag_fixture(
        tmp_path,
        monkeypatch,
    )
    (repository / "wrong-target.txt").write_text("wrong\n", encoding="utf-8")
    wrong_commit = _commit_all(repository, "wrong target")
    wrong_tag_object = _create_synthetic_generation_1_acceptance_tag(
        repository,
        target_commit=wrong_commit,
        force=True,
    )
    monkeypatch.setattr(governance, "S1_ACCEPTANCE_V1_TAG_OBJECT", wrong_tag_object)
    monkeypatch.setattr(
        governance,
        "S1_ACCEPTANCE_V1_CLOSURE_COMMIT",
        closure_commit,
    )

    with pytest.raises(
        governance.GovernanceError,
        match="targets another closure commit",
    ):
        governance._validate_generation_1_predecessor_acceptance(
            repository,
            expected_roadmap_digest=_digest("1"),
        )


def test_generation_2_preflight_enforces_and_reports_the_corrective_branch_and_tag(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    observed: dict[str, Any] = {}

    def validate_live(
        repository_root: Path, *, fetch: bool, expected_branch_name: str
    ) -> dict[str, Any]:
        observed.update(
            repository_root=repository_root,
            fetch=fetch,
            expected_branch_name=expected_branch_name,
        )
        return {}

    monkeypatch.setattr(governance, "validate_live_acceptance_repository", validate_live)

    assert (
        governance.acceptance_preflight.__wrapped__(
            Namespace(
                repository_root=str(repository),
                fetch=True,
                acceptance_generation=2,
            )
        )
        == 0
    )
    output = capsys.readouterr().out
    assert observed == {
        "repository_root": repository.resolve(),
        "fetch": True,
        "expected_branch_name": governance.S1_CORRECTIVE_BRANCH_NAME,
    }
    assert f'"branch": "{governance.S1_CORRECTIVE_BRANCH_NAME}"' in output
    assert f'"acceptance_tag_name": "{governance.S1_ACCEPTANCE_V2_TAG_NAME}"' in output


def test_corrective_preflight_requires_fixed_predecessor_and_unused_successor_tag(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    _initialize_git_repository(repository)
    (repository / "result.txt").write_text("generation 1 result\n", encoding="utf-8")
    predecessor_closure = _commit_all(repository, "generation 1 closure")
    _git(
        repository,
        "-c",
        "tag.gpgSign=false",
        "tag",
        "--annotate",
        "--message",
        "generation 1 acceptance",
        governance.S1_ACCEPTANCE_TAG_NAME,
        predecessor_closure,
    )
    predecessor_tag_object = _git(
        repository,
        "rev-parse",
        f"refs/tags/{governance.S1_ACCEPTANCE_TAG_NAME}^{{tag}}",
    ).stdout.strip()
    monkeypatch.setattr(
        governance,
        "S1_ACCEPTANCE_V1_CLOSURE_COMMIT",
        predecessor_closure,
    )
    monkeypatch.setattr(
        governance,
        "S1_ACCEPTANCE_V1_TAG_OBJECT",
        predecessor_tag_object,
    )
    (repository / "corrective.txt").write_text("corrective result\n", encoding="utf-8")
    corrective_head = _commit_all(repository, "corrective result")

    governance._validate_corrective_acceptance_tag_state(
        repository,
        head_commit=corrective_head,
    )

    _git(repository, "tag", governance.S1_ACCEPTANCE_V2_TAG_NAME, corrective_head)
    with pytest.raises(
        governance.GovernanceError,
        match="successor acceptance tag already exists and must never be moved",
    ):
        governance._validate_corrective_acceptance_tag_state(
            repository,
            head_commit=corrective_head,
        )


def test_corrective_preflight_requires_head_reachable_from_predecessor_closure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    _initialize_git_repository(repository)
    (repository / "result.txt").write_text("generation 1 result\n", encoding="utf-8")
    predecessor_closure = _commit_all(repository, "generation 1 closure")
    _git(
        repository,
        "-c",
        "tag.gpgSign=false",
        "tag",
        "--annotate",
        "--message",
        "generation 1 acceptance",
        governance.S1_ACCEPTANCE_TAG_NAME,
        predecessor_closure,
    )
    predecessor_tag_object = _git(
        repository,
        "rev-parse",
        f"refs/tags/{governance.S1_ACCEPTANCE_TAG_NAME}^{{tag}}",
    ).stdout.strip()
    monkeypatch.setattr(
        governance,
        "S1_ACCEPTANCE_V1_CLOSURE_COMMIT",
        predecessor_closure,
    )
    monkeypatch.setattr(
        governance,
        "S1_ACCEPTANCE_V1_TAG_OBJECT",
        predecessor_tag_object,
    )
    tree = _git(repository, "rev-parse", f"{predecessor_closure}^{{tree}}").stdout.strip()
    unrelated_head = _git(
        repository,
        "commit-tree",
        tree,
        "-m",
        "unrelated root",
    ).stdout.strip()

    with pytest.raises(
        governance.GovernanceError,
        match="does not descend from the predecessor acceptance closure",
    ):
        governance._validate_corrective_acceptance_tag_state(
            repository,
            head_commit=unrelated_head,
        )


def _exercise_successor_v3_validator_output_transport() -> None:
    """Exercise the real byte consumer without adding collected test identities."""

    result = {
        "status": "passed",
        "profile": "preparation",
        "package_id": governance.S1_SUCCESSOR_V3_PACKAGE_ID,
    }
    raw = (json.dumps(result, sort_keys=True) + "\n").encode("utf-8")
    parse_output = governance._successor_v3_parse_package_validation_stdout
    assert parse_output(raw, profile="preparation") == result

    invalid_vectors = (
        (raw.replace(b"\n", b"\r\n"), "canonical LF JSON"),
        (b"\xef\xbb\xbf" + raw, "canonical LF JSON"),
        (raw[:-1] + b"\xff\n", "not UTF-8"),
        (raw[:-1], "canonical LF JSON"),
        (b"", "canonical LF JSON"),
        (raw[:-2] + b', "status": "passed"}\n', "duplicate JSON member"),
        (raw + b"{}\n", "malformed JSON"),
        (raw.replace(b'"preparation"', b'"r3-installed"'), "returned another result"),
        (
            raw.replace(
                governance.S1_SUCCESSOR_V3_PACKAGE_ID.encode("ascii"),
                b"00000000-0000-4000-8000-000000000000",
            ),
            "returned another result",
        ),
        (raw.replace(b'"passed"', b'"failed"'), "returned another result"),
        (
            b" " * (governance._SUCCESSOR_V3_MAX_SEMANTIC_OUTPUT_BYTES + 1),
            "exceeded its output bound",
        ),
    )
    for invalid, message in invalid_vectors:
        with pytest.raises(governance.GovernanceError, match=message):
            parse_output(invalid, profile="preparation")

    if os.name != "nt":
        return
    powershell = governance._SUCCESSOR_V3_POWERSHELL_EXECUTABLE
    assert powershell.is_file(), "Windows transport regression requires PowerShell 5.1"
    interpreter = _independent_python_test_executable().replace("'", "''")
    for emitted in (raw, raw.replace(b"\n", b"\r\n")):
        program = (
            "import sys;sys.stdout.buffer.write(bytes.fromhex("
            + repr(emitted.hex())
            + "));sys.stdout.buffer.flush()"
        )
        encoded_program = base64.b64encode(program.encode("utf-8")).decode("ascii")
        entry = (
            "import base64;exec(base64.b64decode("
            + repr(encoded_program)
            + "))"
        ).replace("'", "''")
        script = f"& '{interpreter}' -I -S -B -X utf8 -c '{entry}'"
        encoded_script = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        completed = subprocess.run(
            [
                str(powershell), "-NoLogo", "-NoProfile", "-NonInteractive",
                "-EncodedCommand", encoded_script,
            ],
            cwd=ROOT,
            capture_output=True,
            check=False,
            timeout=30,
        )
        assert completed.returncode == 0, completed.stderr
        assert completed.stderr == b""
        assert completed.stdout == emitted
        if emitted == raw:
            assert parse_output(completed.stdout, profile="preparation") == result
        else:
            with pytest.raises(governance.GovernanceError, match="canonical LF JSON"):
                parse_output(completed.stdout, profile="preparation")


def _synthetic_successor_v3_signed_package(
    root: Path,
    executable: str,
    key: SshKey,
) -> dict[str, Any]:
    """Build test-only structural evidence, signed solely by a disposable test key.

    These inert artifacts and closed test schemas are never a governance package
    or acceptance record.  The production verifier runs under temporary test-key
    trust; preparation independently checks the real unsigned protocol and schemas.
    """

    repository = root / "s"
    package = repository / governance.S1_SUCCESSOR_V3_PACKAGE_RELATIVE
    (package / "claims").mkdir(parents=True)
    (package / "tools").mkdir()
    scope = "synthetic_test_only_no_acceptance_effect"

    def closed(properties: dict[str, Any]) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": properties,
            "required": list(properties),
            "additionalProperties": False,
        }

    string = {"type": "string"}
    strings = {"type": "array", "items": string}
    descriptor = closed(
        {"path": string, "bytes": {"type": "integer", "minimum": 0}, "sha256": string}
    )
    tool_descriptor = closed(
        {
            **descriptor["properties"],
            "private_key_access": {"const": False},
        }
    )
    contracts_schema = closed(
        {
            "fixture_scope": {"const": scope},
            "format": string,
            "digest_domain": string,
            "package_id": string,
            "tooling": {"type": "array", "items": tool_descriptor},
            "check_contracts_digest": string,
        }
    )
    claim_schema = closed(
        {
            "fixture_scope": {"const": scope},
            "format": string,
            "digest_domain": string,
            "package_id": string,
            "proposed_acceptance_generation": {"type": "integer"},
            "change_partition": closed(
                {
                    "r3_exact_allowlist": strings,
                    "c3_exact_paths": strings,
                    "canonical_commit_messages": closed(
                        {"k3": string, "r3": string, "c3": string}
                    ),
                }
            ),
            "protocol_bundle": closed(
                {
                    "check_contracts_digest": string,
                    "artifacts": {"type": "array", "items": descriptor},
                    "schema_set": closed(
                        {"schemas": {"type": "array", "items": descriptor}}
                    ),
                }
            ),
        }
    )
    authorization_schema = closed(
        {
            "fixture_scope": {"const": scope},
            "format": string,
            "digest_domain": string,
            "package_id": string,
            "state": string,
            "authorization_effect": string,
            "claim": closed(
                {
                    "path": string,
                    "bytes": {"type": "integer", "minimum": 0},
                    "raw_sha256": string,
                    "semantic_digest": string,
                }
            ),
            "signature": closed(
                {
                    "path": string,
                    "bytes": {"type": "integer", "minimum": 0},
                    "sha256": string,
                    "principal": string,
                    "fingerprint": string,
                    "namespace": string,
                    "verified": {"type": "boolean"},
                    "signing_time_claimed": {"type": "boolean"},
                }
            ),
            "authorization_record_digest": string,
        }
    )
    schemas = {
        "check-contracts.schema.json": contracts_schema,
        "successor-kickoff-claim.schema.json": claim_schema,
        "successor-kickoff-authorization.schema.json": authorization_schema,
    }

    def write_json(relative: str, value: dict[str, Any]) -> bytes:
        raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
        (package / relative).write_bytes(raw)
        return raw

    for name in governance.S1_SUCCESSOR_V3_SCHEMA_FILES:
        write_json(
            name,
            {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$comment": scope,
                **schemas.get(name, closed({})),
            },
        )

    def describe(relative: str) -> dict[str, Any]:
        raw = (package / relative).read_bytes()
        return {"path": relative, "bytes": len(raw), "sha256": governance.raw_digest(raw)}

    tools = (
        "tools/successor_v3_launcher.ps1",
        "tools/build_design_package.py",
        "tools/successor_v3_tool.py",
    )
    for relative in tools:
        (package / relative).write_bytes(b"# Inert synthetic test artifact; never executed.\n")
    contracts = {
        "fixture_scope": scope,
        "format": governance.S1_SUCCESSOR_V3_CHECK_CONTRACTS_FORMAT,
        "digest_domain": "agent-assure:s1-successor-check-contract-set/v2",
        "package_id": governance.S1_SUCCESSOR_V3_PACKAGE_ID,
        "tooling": [{**describe(relative), "private_key_access": False} for relative in tools],
    }
    contracts["check_contracts_digest"] = governance.domain_digest(
        contracts["digest_domain"], contracts
    )
    write_json("check-contracts.json", contracts)
    claim = {
        "fixture_scope": scope,
        "format": governance.S1_SUCCESSOR_V3_KICKOFF_CLAIM_FORMAT,
        "digest_domain": "agent-assure:s1-successor-kickoff-claim/v"
        + governance.S1_SUCCESSOR_V3_KICKOFF_CLAIM_FORMAT.rsplit("/", 1)[1],
        "package_id": governance.S1_SUCCESSOR_V3_PACKAGE_ID,
        "proposed_acceptance_generation": 3,
        "change_partition": {
            "r3_exact_allowlist": list(governance.S1_SUCCESSOR_V3_R3_PATHS),
            "c3_exact_paths": list(governance.S1_SUCCESSOR_V3_C3_PATHS),
            "canonical_commit_messages": {
                "k3": governance.S1_SUCCESSOR_V3_K3_MESSAGE,
                "r3": governance.S1_SUCCESSOR_V3_R3_MESSAGE,
                "c3": governance.S1_SUCCESSOR_V3_C3_MESSAGE,
            },
        },
        "protocol_bundle": {
            "check_contracts_digest": contracts["check_contracts_digest"],
            "artifacts": [describe(relative) for relative in (*tools, "check-contracts.json")],
            "schema_set": {
                "schemas": [describe(name) for name in governance.S1_SUCCESSOR_V3_SCHEMA_FILES]
            },
        },
    }

    def sign(relative: str) -> bytes:
        message = package / relative
        signature = Path(f"{message}.sig")
        signature.unlink(missing_ok=True)
        completed = _run_test_ssh_keygen(
            [
                executable, "-Y", "sign", "-f", str(key.private_key),
                "-n", governance.SIGNATURE_NAMESPACE, "-O", "hashalg=sha512", str(message),
            ]
        )
        assert completed.returncode == 0, completed.stderr
        raw = _canonicalize_armor(signature.read_bytes())
        signature.write_bytes(raw)
        return raw

    def write_signed_records(value: dict[str, Any]) -> dict[str, Any]:
        claim_raw = write_json("claims/kickoff.claim", value)
        claim_signature = sign("claims/kickoff.claim")
        authorization = {
            "fixture_scope": scope,
            "format": governance.S1_SUCCESSOR_V3_KICKOFF_AUTHORIZATION_FORMAT,
            "digest_domain": "agent-assure:s1-successor-kickoff-authorization-record/v"
            + governance.S1_SUCCESSOR_V3_KICKOFF_AUTHORIZATION_FORMAT.rsplit("/", 1)[1],
            "package_id": governance.S1_SUCCESSOR_V3_PACKAGE_ID,
            "state": "accepted_after_verified_human_signature",
            "authorization_effect": "prospective_only_from_import",
            "claim": {
                "path": "claims/kickoff.claim",
                "bytes": len(claim_raw),
                "raw_sha256": governance.raw_digest(claim_raw),
                "semantic_digest": governance.domain_digest(value["digest_domain"], value),
            },
            "signature": {
                "path": "claims/kickoff.claim.sig",
                "bytes": len(claim_signature),
                "sha256": governance.raw_digest(claim_signature),
                "principal": "acblabs",
                "fingerprint": key.fingerprint,
                "namespace": governance.SIGNATURE_NAMESPACE,
                "verified": True,
                "signing_time_claimed": False,
            },
        }
        authorization["authorization_record_digest"] = governance.domain_digest(
            authorization["digest_domain"], authorization
        )
        write_json("successor-kickoff-authorization.json", authorization)
        sign("successor-kickoff-authorization.json")
        return authorization

    authorization = write_signed_records(claim)
    return {
        "repository": repository,
        "package": package,
        "claim": claim,
        "authorization": authorization,
        "write_signed_records": write_signed_records,
    }


def test_parser_supports_generation_2_timestamp_free_acceptance_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    ssh_key_material: tuple[str, SshKey, SshKey],
) -> None:
    parsed = governance._parser().parse_args(
        [
            "check",
            "--roadmap",
            "roadmap.md",
            "--governance-dir",
            "docs/governance/v1",
            "--accept-now",
            "--fetch-authoritative-refs",
            "--acceptance-generation",
            "2",
            "--attestation-plan-dir",
            ".tmp/s1-acceptance/current-gate-v2-attestation",
        ]
    )

    assert parsed.acceptance_generation == 2
    assert not hasattr(parsed, "gate_checked_at")
    assert not hasattr(parsed, "plan_created_at")
    assert not hasattr(parsed, "claim_prepared_at")
    assert parsed.attestation_signed_at is None

    with pytest.raises(SystemExit):
        governance._parser().parse_args(
            [
                "check",
                "--roadmap",
                "roadmap.md",
                "--governance-dir",
                "docs/governance/v1",
                "--gate-checked-at",
                ISSUED_AT,
            ]
        )

    legacy = governance._parser().parse_args(
        [
            "check",
            "--roadmap",
            "roadmap.md",
            "--governance-dir",
            "docs/governance/v1",
            "--accept-now",
            "--fetch-authoritative-refs",
            "--commitment-time",
            ISSUED_AT,
            "--attestation-signed-at",
            "2026-10-15T15:05:00Z",
            "--attestation-plan-dir",
            ".tmp/s1-acceptance/attestation-v1",
        ]
    )
    assert legacy.acceptance_generation is None
    assert legacy.commitment_time == ISSUED_AT
    assert legacy.attestation_signed_at == "2026-10-15T15:05:00Z"

    successor_node = governance._parser().parse_args(
        [
            "successor-v3-run-node",
            "--node",
            "g3.result.r3_topology_scope",
            "--subject-role",
            "R3",
            "--output",
            r"C:\tmp\s3-00000000000040008000000000000000\semantic-output.json",
        ]
    )
    assert successor_node.node == "g3.result.r3_topology_scope"
    assert successor_node.subject_role == "R3"
    assert successor_node.handler is governance.successor_v3_run_node
    assert not hasattr(successor_node, "repository_root")
    assert not hasattr(successor_node, "package")

    native_suite = governance._parser().parse_args(
        [
            "successor-v3-native-suite",
            "--subject",
            "0" * 40,
            "--output",
            r"C:\tmp\s3-00000000000040008000000000000000\semantic-output.json",
        ]
    )
    assert native_suite.subject == "0" * 40
    assert native_suite.handler is governance.successor_v3_native_suite
    assert not hasattr(native_suite, "repository_root")
    assert not hasattr(native_suite, "package")

    historical = governance._parser().parse_args(
        [
            "successor-v3-historical-check",
            "--expected-c3",
            "1" * 40,
            "--expected-a3",
            "2" * 40,
            "--output",
            r"C:\tmp\s3-00000000000040008000000000000000\semantic-output.json",
        ]
    )
    assert historical.expected_c3 == "1" * 40
    assert historical.expected_a3 == "2" * 40
    assert historical.handler is governance.successor_v3_historical_check
    assert not hasattr(historical, "repository_root")
    assert not hasattr(historical, "package")

    with pytest.raises(SystemExit):
        governance._parser().parse_args(
            [
                "successor-v3-run-node",
                "--node",
                "not-a-signed-node",
                "--subject-role",
                "R3",
                "--output",
                "semantic-output.json",
            ]
        )

    valid_token = "00000000000040008000000000000000"
    root_name_is_valid = governance._successor_v3_execution_root_name_is_valid
    for variant in "89ab":
        assert root_name_is_valid("s3-" + valid_token[:16] + variant + valid_token[17:])
    for invalid in (
        "",
        "s3-" + valid_token[:-1],
        "s3-" + valid_token + "0",
        "s3-" + valid_token[:12] + "3" + valid_token[13:],
        "s3-" + valid_token[:16] + "7" + valid_token[17:],
        "s3-" + valid_token[:-1] + "A",
        "s3-00000000-0000-4000-8000-000000000000",
        "s3-" + valid_token + "\n",
        "prefix-s3-" + valid_token,
    ):
        assert not root_name_is_valid(invalid)

    executable, key, other_key = ssh_key_material
    _trust_key(monkeypatch, key)
    fixture = _synthetic_successor_v3_signed_package(tmp_path, executable, key)
    synthetic_root = fixture["repository"]
    package = fixture["package"]
    signed = governance._successor_v3_validate_signed_package(synthetic_root)
    _exercise_successor_v3_validator_output_transport()
    assert signed["contracts"]["package_id"] == governance.S1_SUCCESSOR_V3_PACKAGE_ID
    assert (
        signed["contracts"]["format"]
        == governance.S1_SUCCESSOR_V3_CHECK_CONTRACTS_FORMAT
    )
    assert (
        signed["claim"]["format"]
        == governance.S1_SUCCESSOR_V3_KICKOFF_CLAIM_FORMAT
    )
    assert (
        signed["authorization"]["format"]
        == governance.S1_SUCCESSOR_V3_KICKOFF_AUTHORIZATION_FORMAT
    )

    for symbol, message in [
        ("S1_SUCCESSOR_V3_PACKAGE_ID", "Generation-3 check-contract identity mismatch"),
        (
            "S1_SUCCESSOR_V3_CHECK_CONTRACTS_FORMAT",
            "Generation-3 check-contract identity mismatch",
        ),
        ("S1_SUCCESSOR_V3_KICKOFF_CLAIM_FORMAT", "Generation-3 kickoff claim identity mismatch"),
        (
            "S1_SUCCESSOR_V3_KICKOFF_AUTHORIZATION_FORMAT",
            "Generation-3 kickoff authorization identity/state mismatch",
        ),
    ]:
        with monkeypatch.context() as context:
            context.setattr(governance, symbol, "invalid-stale-binding")
            with pytest.raises(governance.GovernanceError, match=message):
                governance._successor_v3_validate_signed_package(synthetic_root)

    for relative in ("claims/kickoff.claim", "successor-kickoff-authorization.json"):
        payload = package / relative
        original = payload.read_bytes()
        try:
            payload.write_bytes(original[:-1] + b" \n")
            with pytest.raises(governance.GovernanceError, match="signature verification failed"):
                governance._successor_v3_validate_signed_package(synthetic_root)
        finally:
            payload.write_bytes(original)

    with monkeypatch.context() as context:
        _trust_key(context, other_key)
        with pytest.raises(governance.GovernanceError, match="embeds another public key"):
            governance._successor_v3_validate_signed_package(synthetic_root)

    tool = package / "tools/successor_v3_tool.py"
    original_tool = tool.read_bytes()
    try:
        tool.write_bytes(b"!" + original_tool[1:])
        with pytest.raises(
            governance.GovernanceError,
            match="protocol artifact .* SHA-256 changed",
        ):
            governance._successor_v3_validate_signed_package(synthetic_root)
    finally:
        tool.write_bytes(original_tool)

    invalid_claim = copy.deepcopy(fixture["claim"])
    invalid_claim["protocol_bundle"]["artifacts"] = [
        descriptor
        for descriptor in invalid_claim["protocol_bundle"]["artifacts"]
        if descriptor["path"] != "tools/build_design_package.py"
    ]
    fixture["write_signed_records"](invalid_claim)
    with pytest.raises(governance.GovernanceError, match="missing required executable artifacts"):
        governance._successor_v3_validate_signed_package(synthetic_root)

    invalid_claim = copy.deepcopy(fixture["claim"])
    invalid_claim["unsigned_extension"] = "rejected even when signed by the disposable test key"
    fixture["write_signed_records"](invalid_claim)
    with pytest.raises(governance.GovernanceError, match="kickoff claim schema validation failed"):
        governance._successor_v3_validate_signed_package(synthetic_root)

    fixture["write_signed_records"](fixture["claim"])
    restored = governance._successor_v3_validate_signed_package(synthetic_root)
    assert restored["claim"] == signed["claim"]


def test_cli_rejects_execution_without_isolated_mode() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-B",
            str(ROOT / "scripts" / "v1_s1_governance.py"),
            "--help",
        ],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
        timeout=10,
    )

    assert completed.returncode != 0
    assert "invoke the frozen launcher with its exact Python -I -S -B profile" in completed.stderr


@pytest.mark.parametrize(
    "arguments",
    [
        ["--help"],
        ["acceptance-preflight", "--repository-root", str(ROOT)],
    ],
)
def test_imported_main_cannot_bypass_the_frozen_runtime(arguments: list[str]) -> None:
    program = (
        "import sys; "
        f"sys.path.insert(0, {str(ROOT)!r}); "
        "import scripts.v1_s1_governance as governance; "
        f"raise SystemExit(governance.main({arguments!r}))"
    )
    completed = subprocess.run(
        [sys.executable, "-B", "-c", program],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 2
    assert completed.stdout == ""
    assert "commands require successful frozen runtime bootstrap" in completed.stderr


def test_every_parser_handler_fails_closed_without_the_frozen_runtime() -> None:
    parser = governance._parser()
    handlers: set[Any] = set()
    for action in parser._actions:
        choices = getattr(action, "choices", None)
        if isinstance(choices, dict):
            handlers.update(
                command_parser.get_default("handler") for command_parser in choices.values()
            )

    assert {handler.__name__ for handler in handlers} == {
        "acceptance_attestation_finalize",
        "acceptance_decision_template",
        "acceptance_import",
        "acceptance_preflight",
        "acceptance_prepare",
        "acceptance_result_paths",
        "assemble_draft",
        "check",
        "corrective_v2_bundle_import",
        "corrective_v2_bundle_plan",
        "corrective_v2_receipt_import",
        "corrective_v2_receipt_plan",
        "corrective_v2_suite_capture",
        "forecast_v2_decision_import",
        "forecast_v2_decision_plan",
        "forecast_v2_documentation_check",
        "forecast_v2_signature_import",
        "forecast_v2_signature_plan",
        "generate_draft",
        "post_v2_control_suite_capture",
        "successor_v3_historical_check",
        "successor_v3_native_suite",
        "successor_v3_run_node",
    }
    for handler in handlers:
        assert handler.__dict__.get("__requires_frozen_runtime__") is True
        assert callable(handler.__wrapped__)
        with pytest.raises(
            governance.GovernanceError,
            match="commands require successful frozen runtime bootstrap",
        ):
            handler(Namespace())


def test_make_governance_targets_require_explicit_trust_inputs() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    historical = makefile.split("v1-governance-check:\n", maxsplit=1)[1].split("\n\n", maxsplit=1)[
        0
    ]
    nonaccepting = makefile.split("v1-governance-check-nonaccepting:\n", maxsplit=1)[1].split(
        "\n\n", maxsplit=1
    )[0]

    assert "--historical" in historical
    assert '--closure-commit "$(V1_GOVERNANCE_CLOSURE_COMMIT)"' in historical
    assert '--acceptance-tag-object "$(V1_GOVERNANCE_ACCEPTANCE_TAG_OBJECT)"' in historical
    assert "--allow-pending" in nonaccepting
    assert "V1_GOVERNANCE_ACCEPTANCE_GENERATION ?= 2" in makefile
    assert '--acceptance-generation "$(V1_GOVERNANCE_ACCEPTANCE_GENERATION)"' in nonaccepting
    assert "$(V1_GOVERNANCE_PENDING_TIME_ARG)" in nonaccepting
    assert (
        "V1_GOVERNANCE_PENDING_TIME_ARG = "
        "$(if $(filter 1,$(V1_GOVERNANCE_ACCEPTANCE_GENERATION)),--commitment-time "
        '"$(V1_GOVERNANCE_COMMITMENT_TIME)")'
    ) in makefile


def test_historical_bootstrap_docs_require_a_standalone_runtime_clone() -> None:
    documentation = (GOVERNANCE_ROOT / "README.md").read_text(encoding="utf-8")
    bootstrap = documentation.split("### Historical-verifier bootstrap boundary", maxsplit=1)[
        1
    ].split("## Local draft generation and validation", maxsplit=1)[0]

    assert "clone --no-local --no-checkout" in bootstrap
    assert "worktree add" not in bootstrap
    assert "rev-parse --is-shallow-repository" in bootstrap
    assert ".git\\objects\\info\\alternates" in bootstrap
    assert "$InfoPath = Join-Path $VerificationRoot '.git\\info'" in bootstrap
    assert "New-Item -ItemType Directory -Path $InfoPath" in bootstrap
    assert "$InfoDirectory.PSIsContainer" in bootstrap
    assert "$SourceExcludePath = Join-Path $SourceRepository '.git\\info\\exclude'" in bootstrap
    assert "$ExpectedLegacyExcludeSizeBytes = 2368" in bootstrap
    assert governance.POST_R2_GIT_EXCLUDE_SHA256 in bootstrap
    assert "$SourceExcludeFile.PSIsContainer" in bootstrap
    assert "$SourceExcludeFile.Length -ne $ExpectedLegacyExcludeSizeBytes" in bootstrap
    assert "$ObservedSourceExcludeSha256 -cne $ExpectedLegacyExcludeSha256" in bootstrap
    assert "$AttributesPath = Join-Path $InfoPath 'attributes'" in bootstrap
    assert "Test-Path -LiteralPath $AttributesPath" in bootstrap
    assert ".git\\info\\attributes to be absent" in bootstrap
    assert "$ExcludeFile.PSIsContainer" in bootstrap
    assert "[IO.File]::Copy($SourceExcludePath, $ExcludePath, $false)" in bootstrap
    assert "$ExcludeFile.Length -ne $ExpectedLegacyExcludeSizeBytes" in bootstrap
    assert "$ObservedExcludeSha256 -cne $ExpectedLegacyExcludeSha256" in bootstrap
    assert "[IO.File]::AppendAllText(" not in bootstrap
    assert "Copy-Item -LiteralPath $SourceVenv" in bootstrap
    assert "& $VerifiedLauncher --help" in bootstrap
    assert "status --porcelain=v1 --untracked-files=all" in bootstrap
    assert "function Remove-HistoricalVerificationRoadmap" in bootstrap
    assert "$ErrorActionPreference = 'Stop'" in bootstrap
    assert "$HistoricalRoadmapCopyOwned = $false" in bootstrap
    assert "if ($HistoricalRoadmapCopyOwned)" in bootstrap
    assert "finally {" in bootstrap
    assert "$VerifiedRoadmapStream = [IO.File]::Open(" in bootstrap
    assert "$SourceRoadmapStream.CopyTo($VerifiedRoadmapStream)" in bootstrap
    assert "$VerifiedRoadmapStream.Flush($true)" in bootstrap
    assert "$VerifiedRoadmapItem.Attributes -band [IO.FileAttributes]::ReparsePoint" in bootstrap
    assert "Remove-Item -LiteralPath $ExpectedPath -Force -ErrorAction Stop" in bootstrap
    assert "catch [System.Management.Automation.ItemNotFoundException]" in bootstrap
    assert bootstrap.index("New-Item -ItemType Directory -Path $InfoPath") < bootstrap.index(
        "[IO.File]::Copy($SourceExcludePath, $ExcludePath, $false)"
    )
    assert bootstrap.index("$AttributesPath = Join-Path $InfoPath 'attributes'") < (
        bootstrap.index("$ExcludePath = Join-Path $VerificationRoot '.git\\info\\exclude'")
    )


@pytest.mark.skipif(os.name != "nt", reason="the documented bootstrap is PowerShell on Windows")
def test_historical_bootstrap_exclude_setup_handles_an_empty_template_and_rejects_nonregular_paths(
    tmp_path: Path,
) -> None:
    documentation = (GOVERNANCE_ROOT / "README.md").read_text(encoding="utf-8")
    bootstrap = documentation.split("### Historical-verifier bootstrap boundary", maxsplit=1)[
        1
    ].split("## Local draft generation and validation", maxsplit=1)[0]
    powershell_block = bootstrap.split("```powershell", maxsplit=1)[1].split("```", maxsplit=1)[0]
    exclude_setup = powershell_block[
        powershell_block.index("$ExpectedLegacyExcludeSizeBytes") : powershell_block.index(
            "$SourceVenvItem = Get-Item"
        )
    ]
    synthetic_policy_prefix = b"# Hermetic historical local-exclude policy fixture.\n"
    synthetic_legacy_policy = synthetic_policy_prefix + b"x" * (
        governance.POST_R2_GIT_EXCLUDE_SIZE_BYTES - len(synthetic_policy_prefix)
    )
    assert len(synthetic_legacy_policy) == governance.POST_R2_GIT_EXCLUDE_SIZE_BYTES
    synthetic_policy_sha256 = hashlib.sha256(synthetic_legacy_policy).hexdigest()
    exclude_setup = exclude_setup.replace(
        governance.POST_R2_GIT_EXCLUDE_SHA256,
        synthetic_policy_sha256,
    )
    powershell = Path(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
    assert powershell.is_file()

    def run_setup(root: Path, source_exclude: Path) -> subprocess.CompletedProcess[str]:
        escaped_root = str(root).replace("'", "''")
        escaped_source_exclude = str(source_exclude).replace("'", "''")
        return subprocess.run(
            [
                str(powershell),
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                f"$ErrorActionPreference = 'Stop'\n"
                f"$VerificationRoot = '{escaped_root}'\n"
                f"$SourceExcludePath = '{escaped_source_exclude}'\n"
                f"{exclude_setup}",
            ],
            capture_output=True,
            check=False,
            text=True,
            timeout=30,
        )

    source_repository = tmp_path / "source-repository"
    _initialize_git_repository(source_repository)
    source_exclude = source_repository / ".git/info/exclude"
    source_exclude.write_bytes(synthetic_legacy_policy)
    (source_repository / "tracked.txt").write_bytes(b"standalone clone source\n")
    _commit_all(source_repository, "synthetic standalone source")
    empty_template = tmp_path / "empty-git-template"
    empty_template.mkdir()
    fresh = tmp_path / "fresh-empty-template-clone"
    git_executable = shutil.which("git")
    assert git_executable is not None
    clone_environment = os.environ.copy()
    clone_environment.update(
        {
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "NUL",
            "GIT_CONFIG_NOSYSTEM": "1",
        }
    )
    cloned = subprocess.run(
        [
            git_executable,
            "clone",
            "--no-local",
            "--no-checkout",
            f"--template={empty_template}",
            str(source_repository),
            str(fresh),
        ],
        env=clone_environment,
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )
    assert cloned.returncode == 0, cloned.stderr
    assert (fresh / ".git").is_dir()
    assert not (fresh / ".git/info").exists()
    completed = run_setup(fresh, source_exclude)
    assert completed.returncode == 0, completed.stderr
    exclude_path = fresh / ".git/info/exclude"
    assert exclude_path.is_file() and not exclude_path.is_symlink()
    assert exclude_path.read_bytes() == synthetic_legacy_policy

    corrupt_source = tmp_path / "corrupt-source-exclude"
    corrupt_source.write_bytes(b"!" + synthetic_legacy_policy[1:])
    corrupt_target = tmp_path / "corrupt-source-target"
    (corrupt_target / ".git").mkdir(parents=True)
    rejected_corrupt_source = run_setup(corrupt_target, corrupt_source)
    assert rejected_corrupt_source.returncode != 0
    assert "does not match the immutable v3 policy" in rejected_corrupt_source.stderr
    assert not (corrupt_target / ".git/info/exclude").exists()

    directory_source = tmp_path / "directory-source-exclude"
    directory_source.mkdir()
    directory_source_target = tmp_path / "directory-source-target"
    (directory_source_target / ".git").mkdir(parents=True)
    rejected_directory_source = run_setup(directory_source_target, directory_source)
    assert rejected_directory_source.returncode != 0
    assert "regular non-reparse source .git\\info\\exclude file" in (
        rejected_directory_source.stderr
    )

    non_directory_info = tmp_path / "non-directory-info"
    (non_directory_info / ".git").mkdir(parents=True)
    (non_directory_info / ".git/info").write_bytes(b"not a directory")
    rejected_info = run_setup(non_directory_info, source_exclude)
    assert rejected_info.returncode != 0
    assert "regular non-reparse .git\\info directory" in rejected_info.stderr

    directory_exclude = tmp_path / "directory-exclude"
    (directory_exclude / ".git/info/exclude").mkdir(parents=True)
    rejected_exclude = run_setup(directory_exclude, source_exclude)
    assert rejected_exclude.returncode != 0
    assert "clone-local .git\\info\\exclude to be absent" in rejected_exclude.stderr

    reparse_info = tmp_path / "reparse-info"
    (reparse_info / ".git").mkdir(parents=True)
    reparse_target = tmp_path / "reparse-info-target"
    reparse_target.mkdir()
    try:
        os.symlink(reparse_target, reparse_info / ".git/info", target_is_directory=True)
    except OSError:
        pass
    else:
        rejected_reparse = run_setup(reparse_info, source_exclude)
        assert rejected_reparse.returncode != 0
        assert "regular non-reparse .git\\info directory" in rejected_reparse.stderr


def test_post_v2_control_docs_preserve_the_accepted_checkout_and_exact_local_policy() -> None:
    documentation = (GOVERNANCE_ROOT / "README.md").read_text(encoding="utf-8")

    assert "Preserve the accepted checkout" in documentation
    assert "and its local metadata unchanged." in documentation
    assert "from a separate `clone --no-local`" in documentation
    assert "empty Git template at that exact subject" in documentation
    assert "`/Agent_Assure_Implementation_Roadmap.md\\n/.venv/\\n/.tmp/\\n`" in documentation
    assert governance.POST_V2_CONTROL_GIT_EXCLUDE_SHA256 in documentation
    assert ".git/info/attributes` must be absent" in documentation
    assert "function Remove-PostV2ControlRoadmap" in documentation
    assert "$PostV2RoadmapCopyOwned = $false" in documentation
    assert "if ($PostV2RoadmapCopyOwned)" in documentation
    assert "$PostV2RoadmapStream = [IO.File]::Open(" in documentation
    assert "$SourceRoadmapStream.CopyTo($PostV2RoadmapStream)" in documentation
    assert "$PostV2RoadmapStream.Flush($true)" in documentation
    assert "$PostV2RoadmapItem.Attributes -band [IO.FileAttributes]::ReparsePoint" in documentation
    assert "Remove-Item -LiteralPath $ExpectedPath -Force -ErrorAction Stop" in documentation


@pytest.mark.skipif(os.name != "nt", reason="the documented cleanup requires PowerShell")
def test_documented_private_roadmap_cleanup_is_exact_and_runs_on_failure(
    tmp_path: Path,
) -> None:
    documentation = (GOVERNANCE_ROOT / "README.md").read_text(encoding="utf-8")
    powershell = Path(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
    assert powershell.is_file()
    configurations = (
        (
            "historical",
            "VerificationRoot",
            "Remove-HistoricalVerificationRoadmap",
            "$HistoricalRoadmapCopyOwned",
        ),
        (
            "post-v2",
            "PostV2RepositoryRoot",
            "Remove-PostV2ControlRoadmap",
            "$PostV2RoadmapCopyOwned",
        ),
    )

    for label, root_variable, function_name, owned_variable in configurations:
        function_start = documentation.index(f"function {function_name}")
        function_end = documentation.index(
            "$HistoricalRoadmapCopyOwned" if label == "historical" else "$PostV2ControlEvidenceDir",
            function_start,
        )
        function_source = documentation[function_start:function_end]
        root = tmp_path / label
        root.mkdir()
        source = tmp_path / f"{label}-source-roadmap.md"
        source.write_bytes(b"private roadmap fixture\n")
        adjacent = root / "adjacent.txt"
        adjacent.write_bytes(b"must remain\n")
        target = root / "Agent_Assure_Implementation_Roadmap.md"

        def run(
            script: str,
            *,
            root: Path = root,
            root_variable: str = root_variable,
            function_source: str = function_source,
        ) -> subprocess.CompletedProcess[str]:
            escaped_root = str(root).replace("'", "''")
            return subprocess.run(
                [
                    str(powershell),
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    f"${root_variable} = '{escaped_root}'\n{function_source}\n{script}",
                ],
                capture_output=True,
                check=False,
                text=True,
                timeout=30,
            )

        escaped_source = str(source).replace("'", "''")
        escaped_target = str(target).replace("'", "''")
        escaped_adjacent = str(adjacent).replace("'", "''")
        failed = run(
            f"{owned_variable} = $false\n"
            "try {\n"
            f"  $SourceStream = [IO.File]::Open('{escaped_source}', "
            "[IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)\n"
            "  try {\n"
            f"    $TargetStream = [IO.File]::Open('{escaped_target}', "
            "[IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)\n"
            f"    {owned_variable} = $true\n"
            "    try {\n"
            "      $PartialBytes = [byte[]] @(1, 2, 3)\n"
            "      $TargetStream.Write($PartialBytes, 0, $PartialBytes.Length)\n"
            "      throw 'synthetic governed mid-copy failure'\n"
            "    }\n"
            "    finally { $TargetStream.Dispose() }\n"
            "  }\n"
            "  finally { $SourceStream.Dispose() }\n"
            "}\n"
            "finally {\n"
            f"  if ({owned_variable}) {{\n"
            f"    {function_name} -CandidatePath '{escaped_target}'\n"
            "  }\n"
            "}\n"
        )
        assert failed.returncode != 0
        assert "synthetic governed mid-copy failure" in failed.stderr
        assert not target.exists()
        assert source.read_bytes() == b"private roadmap fixture\n"
        assert adjacent.read_bytes() == b"must remain\n"

        target.write_bytes(b"must remain after mismatch\n")
        mismatched = run(f"{function_name} -CandidatePath '{escaped_adjacent}'")
        assert mismatched.returncode != 0
        assert "not the exact clone-local path" in mismatched.stderr
        assert target.read_bytes() == b"must remain after mismatch\n"
        assert adjacent.read_bytes() == b"must remain\n"

        inspection_denied = run(
            "function Get-Item {\n"
            "  [CmdletBinding()]\n"
            "  param([string] $LiteralPath, [switch] $Force)\n"
            "  throw [UnauthorizedAccessException]::new('synthetic inspection denied')\n"
            "}\n"
            f"{function_name} -CandidatePath '{escaped_target}'"
        )
        assert inspection_denied.returncode != 0
        assert "synthetic inspection denied" in inspection_denied.stderr
        assert target.read_bytes() == b"must remain after mismatch\n"

        target.unlink()
        target.mkdir()
        directory = run(f"{function_name} -CandidatePath '{escaped_target}'")
        assert directory.returncode != 0
        assert "requires a regular non-reparse file" in directory.stderr
        assert target.is_dir()
        target.rmdir()

        reparse_target = tmp_path / f"{label}-reparse-target"
        reparse_target.mkdir()
        try:
            os.symlink(reparse_target, target, target_is_directory=True)
        except OSError:
            pass
        else:
            reparse = run(f"{function_name} -CandidatePath '{escaped_target}'")
            assert reparse.returncode != 0
            assert "requires a regular non-reparse file" in reparse.stderr
            assert target.is_symlink()
            assert reparse_target.is_dir()
            target.unlink()


@pytest.mark.skipif(os.name != "nt", reason="the documented setup requires Windows PowerShell 5.1")
def test_post_v2_documented_exclude_setup_creates_exact_bytes_once(
    tmp_path: Path,
) -> None:
    documentation = (GOVERNANCE_ROOT / "README.md").read_text(encoding="utf-8")
    section = documentation.split(
        "The canonical v4 exclude policy and the accepted host's 2,368-byte v3 exclude",
        maxsplit=1,
    )[1].split("The following block is retained", maxsplit=1)[0]
    powershell_block = section.split("```powershell", maxsplit=1)[1].split("```", maxsplit=1)[0]
    exclude_setup = powershell_block[
        powershell_block.index("$PostV2InfoPath") : powershell_block.index(
            "function Invoke-PostV2Governance"
        )
    ]
    powershell = Path(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
    assert powershell.is_file()
    repository = tmp_path / "post-v2-clone"
    (repository / ".git").mkdir(parents=True)
    escaped_root = str(repository).replace("'", "''")
    command = (
        "$ErrorActionPreference = 'Stop'\n"
        f"$PostV2RepositoryRoot = '{escaped_root}'\n"
        f"{exclude_setup}"
    )

    first = subprocess.run(
        [
            str(powershell),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            command,
        ],
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )
    assert first.returncode == 0, first.stderr
    exclude_path = repository / ".git/info/exclude"
    assert exclude_path.read_bytes() == governance.POST_V2_CONTROL_GIT_EXCLUDE_BYTES

    second = subprocess.run(
        [
            str(powershell),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            command,
        ],
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )
    assert second.returncode != 0
    assert "refuses to overwrite an existing local-exclude path" in second.stderr
    assert exclude_path.read_bytes() == governance.POST_V2_CONTROL_GIT_EXCLUDE_BYTES


@pytest.mark.skipif(
    os.name != "nt" or not governance._FROZEN_PYTHON_EXECUTABLE.is_file(),
    reason="the accepted S1 runtime is bound to the recorded Windows host",
)
def test_cli_accepts_only_the_exact_frozen_isolated_runtime() -> None:
    completed = subprocess.run(
        [
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(ROOT / "scripts" / "v1_s1_governance.ps1"),
            "--help",
        ],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
        timeout=120,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.startswith("usage: v1_s1_governance.py")
    assert "acceptance-preflight" in completed.stdout


@pytest.mark.skipif(
    os.name != "nt" or not governance._FROZEN_PYTHON_EXECUTABLE.is_file(),
    reason="the accepted S1 runtime is bound to the recorded Windows host",
)
@pytest.mark.parametrize(
    ("extra_flags", "expected_error"),
    [
        ([], "did not pass the frozen external launcher"),
        (["-O"], "invoke the frozen launcher with its exact Python -I -S -B profile"),
    ],
)
def test_direct_base_python_cannot_bypass_the_external_launcher(
    extra_flags: list[str], expected_error: str
) -> None:
    completed = subprocess.run(
        [
            str(governance._FROZEN_PYTHON_EXECUTABLE),
            *extra_flags,
            "-I",
            "-S",
            "-B",
            str(ROOT / "scripts" / "v1_s1_governance.py"),
            "--help",
        ],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )

    assert completed.returncode != 0
    assert expected_error in completed.stderr


@pytest.mark.skipif(
    os.name != "nt" or not governance._FROZEN_PYTHON_EXECUTABLE.is_file(),
    reason="the accepted S1 runtime is bound to the recorded Windows host",
)
def test_frozen_third_party_runtime_inventory_matches_every_reviewed_byte() -> None:
    assert governance._base_runtime_inventory(governance._FROZEN_PYTHON_ROOT) == (
        governance._FROZEN_BASE_RUNTIME_FILE_COUNT,
        governance._FROZEN_BASE_RUNTIME_SIZE_BYTES,
        governance._FROZEN_BASE_RUNTIME_SHA256,
    )
    assert governance._runtime_inventory(ROOT / ".venv" / "Lib" / "site-packages") == (
        governance._FROZEN_RUNTIME_FILE_COUNT,
        governance._FROZEN_RUNTIME_SIZE_BYTES,
        governance._FROZEN_RUNTIME_SHA256,
    )


def test_replace_pristine_drafts_never_overwrites_a_confirmed_forecast() -> None:
    forecast = _record("delivery-forecast.json")
    forecast["rows"][0]["rebaseline_status"] = "affirmatively_reconfirmed_after_inventory"

    assert not governance._is_pristine_machine_draft(
        GOVERNANCE_ROOT / "delivery-forecast.json", forecast
    )


def test_acceptance_attestation_renderer_is_insertion_order_independent() -> None:
    left = {"z": {"second": 2, "first": 1}, "a": [True, None]}
    right = {"a": [True, None], "z": {"first": 1, "second": 2}}

    assert governance._render_acceptance_attestation_bytes(left) == (
        governance._render_acceptance_attestation_bytes(right)
    )
    assert governance._render_acceptance_attestation_bytes(left) == (
        b'{\n  "a": [\n    true,\n    null\n  ],\n  "z": {\n'
        b'    "first": 1,\n    "second": 2\n  }\n}\n'
    )


def test_guarded_acceptance_reader_rejects_an_outstanding_import_transaction(
    tmp_path: Path,
) -> None:
    repository = (tmp_path / "repository").resolve()
    journal = governance._acceptance_transaction_journal(repository)
    journal.parent.mkdir(parents=True)
    journal.write_bytes(b"incomplete transaction sentinel\n")

    with pytest.raises(
        governance.GovernanceError,
        match="incomplete S1 acceptance transaction exists",
    ):
        governance.acceptance_result_paths.__wrapped__(Namespace(repository_root=str(repository)))


def test_corrective_suite_capture_releases_acceptance_lock_for_child_tests(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = (tmp_path / "repository").resolve()
    governance_root = repository / "docs" / "governance" / "v1"
    governance_root.mkdir(parents=True)
    evidence_path = (
        repository
        / ".tmp"
        / "s1-acceptance"
        / "correction-v2-post-r2-suite-evidence"
        / "post-r2-suite-evidence.json"
    )
    result_commit = "a" * 40
    monkeypatch.setattr(
        governance,
        "_load_corrective_v2_workspace",
        lambda **_kwargs: {"authorization": {}},
    )
    monkeypatch.setattr(
        governance,
        "_require_clean_corrective_result_checkout",
        lambda *_args, **_kwargs: {},
    )
    monkeypatch.setattr(
        governance,
        "_corrective_private_acceptance_path",
        lambda *_args, **_kwargs: evidence_path,
    )

    def capture_without_parent_lock(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        lock_path = repository / ".tmp/s1-acceptance/correction-v2-import.lock"
        program = f"""
import os
from pathlib import Path
path = Path({str(lock_path)!r})
path.parent.mkdir(parents=True, exist_ok=True)
handle = path.open('a+b')
handle.seek(0, os.SEEK_END)
if handle.tell() == 0:
    handle.write(b'\\x00')
    handle.flush()
handle.seek(0)
if os.name == 'nt':
    import msvcrt
    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
    handle.seek(0)
    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
else:
    import fcntl
    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
handle.close()
"""
        completed = subprocess.run(
            [sys.executable, "-c", program],
            cwd=repository,
            capture_output=True,
            check=False,
            text=True,
            timeout=10,
        )
        assert completed.returncode == 0, completed.stderr
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        evidence_path.write_text("{}\n", encoding="utf-8")
        return _SyntheticCaptureRecord(
            {
                "evidence_digest": _digest("e"),
                "execution": {
                    "exit_code": 0,
                    "outcome": "passed",
                    "pytest_totals": {
                        "collected": 1,
                        "passed": 1,
                        "failed": 0,
                        "skipped": 0,
                        "xfailed": 0,
                        "xpassed": 0,
                        "errors": 0,
                    },
                },
            },
            reused=False,
        )

    monkeypatch.setattr(
        governance,
        "capture_post_r2_suite_evidence",
        capture_without_parent_lock,
    )

    assert (
        governance.corrective_v2_suite_capture.__wrapped__(
            Namespace(
                repository_root=str(repository),
                governance_dir=str(governance_root),
                roadmap=str(repository / "Agent_Assure_Implementation_Roadmap.md"),
                result_commit=result_commit,
                evidence_dir=str(evidence_path.parent),
            )
        )
        == 0
    )


@pytest.mark.parametrize(
    (
        "reused",
        "exit_code",
        "outcome",
        "evidence_format",
        "acceptance_eligible",
        "expected_return_code",
    ),
    (
        (True, 0, "passed", "agent-assure-s1-post-r2-suite-evidence/3", True, 0),
        (True, 1, "failed", "agent-assure-s1-post-r2-suite-evidence/3", False, 1),
    ),
)
def test_corrective_suite_capture_reports_capture_disposition_and_suite_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    reused: bool,
    exit_code: int,
    outcome: str,
    evidence_format: str,
    acceptance_eligible: bool,
    expected_return_code: int,
) -> None:
    repository = (tmp_path / "repository").resolve()
    governance_root = repository / "docs/governance/v1"
    governance_root.mkdir(parents=True)
    evidence_path = (
        repository / ".tmp/s1-acceptance/synthetic-suite" / "post-r2-suite-evidence.json"
    )
    totals = {
        "collected": 1,
        "passed": int(exit_code == 0),
        "failed": int(exit_code != 0),
        "skipped": 0,
        "xfailed": 0,
        "xpassed": 0,
        "errors": 0,
    }
    record = _SyntheticCaptureRecord(
        {
            "evidence_digest": _digest("e"),
            "format": evidence_format,
            "execution": {
                "exit_code": exit_code,
                "outcome": outcome,
                "pytest_totals": totals,
            },
        },
        reused=reused,
    )

    @contextmanager
    def unlocked(_repository: Path) -> Any:
        yield

    monkeypatch.setattr(governance, "_acceptance_import_lock", unlocked)
    monkeypatch.setattr(
        governance,
        "_load_corrective_v2_workspace",
        lambda **_kwargs: {"authorization": {}},
    )
    monkeypatch.setattr(
        governance,
        "_require_clean_corrective_result_checkout",
        lambda *_args, **_kwargs: {},
    )
    monkeypatch.setattr(
        governance,
        "_corrective_private_acceptance_path",
        lambda *_args, **_kwargs: evidence_path,
    )
    monkeypatch.setattr(
        governance,
        "capture_post_r2_suite_evidence",
        lambda *_args, **_kwargs: record,
    )

    result = governance.corrective_v2_suite_capture.__wrapped__(
        Namespace(
            repository_root=str(repository),
            governance_dir=str(governance_root),
            roadmap=str(repository / "Agent_Assure_Implementation_Roadmap.md"),
            result_commit="a" * 40,
            evidence_dir=str(evidence_path.parent),
        )
    )

    assert result == expected_return_code
    output = json.loads(capsys.readouterr().out)
    disposition = "reused" if reused else "captured"
    status = "passed" if exit_code == 0 else "failed"
    assert output == {
        "acceptance_eligible": acceptance_eligible,
        "authorization_effect": "none",
        "capture_disposition": disposition,
        "evidence_digest": _digest("e"),
        "evidence_path": str(evidence_path),
        "execution_outcome": outcome,
        "pytest_exit_code": exit_code,
        "pytest_totals": totals,
        "result": f"clean_r2_full_suite_evidence_{disposition}_{status}",
        "result_commit": "a" * 40,
        "suite_passed": exit_code == 0,
    }


@pytest.mark.parametrize(
    ("reused", "exit_code", "outcome", "expected_return_code"),
    (
        (False, 0, "passed", 0),
        (False, 1, "failed", 1),
        (True, 0, "passed", 0),
        (True, 1, "failed", 1),
    ),
)
def test_post_v2_control_suite_command_reports_nonaccepting_capture_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    reused: bool,
    exit_code: int,
    outcome: str,
    expected_return_code: int,
) -> None:
    repository = (tmp_path / "repository").resolve()
    repository.mkdir()
    evidence_directory = repository / ".tmp/s1-acceptance/post-v2-control-cli"
    evidence_path = evidence_directory / "post-v2-control-suite-evidence.json"
    subject_commit = "a" * 40
    subject_parent_commit = "b" * 40
    topology = {
        "scope": "post_v2_control_verification_only",
        "authorization_effect": "none",
        "history_policy": "full_history_without_replacements_grafts_or_alternates/v1",
        "immutable_acceptance_v2_closure_commit": governance.S1_ACCEPTANCE_V2_CLOSURE_COMMIT,
        "relationship": "proper_non_merge_descendant",
        "subject_commit": subject_commit,
        "subject_parent_commit": subject_parent_commit,
    }
    totals = {
        "collected": 1,
        "passed": int(exit_code == 0),
        "failed": int(exit_code != 0),
        "skipped": 0,
        "xfailed": 0,
        "xpassed": 0,
        "errors": 0,
    }
    record = _SyntheticCaptureRecord(
        {
            "evidence_digest": _digest("e"),
            "execution": {
                "exit_code": exit_code,
                "outcome": outcome,
                "pytest_totals": totals,
            },
        },
        reused=reused,
    )
    state = {"head_commit": subject_commit, "clean": True}
    ordering: list[str] = []

    @contextmanager
    def unlocked(_repository: Path) -> Any:
        yield

    monkeypatch.setattr(governance, "_acceptance_import_lock", unlocked)

    def observed_topology(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        ordering.append("topology")
        return copy.deepcopy(topology)

    def observed_metadata(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        ordering.append("metadata")
        return {}

    monkeypatch.setattr(governance, "_post_v2_control_topology", observed_topology)
    monkeypatch.setattr(
        governance,
        "_post_v2_control_git_metadata_preflight",
        observed_metadata,
    )
    monkeypatch.setattr(
        governance,
        "_post_r2_repository_state",
        lambda *_args, **_kwargs: copy.deepcopy(state),
    )
    monkeypatch.setattr(
        governance,
        "capture_post_v2_control_suite_evidence",
        lambda *_args, **_kwargs: record,
    )
    monkeypatch.setattr(
        governance,
        "_post_v2_control_private_path",
        lambda *_args, **_kwargs: evidence_path,
    )

    parsed = governance._parser().parse_args(
        [
            "post-v2-control-suite-capture",
            "--roadmap",
            str(repository / "Agent_Assure_Implementation_Roadmap.md"),
            "--subject-commit",
            subject_commit,
            "--evidence-dir",
            str(evidence_directory),
            "--repository-root",
            str(repository),
        ]
    )
    assert parsed.handler is governance.post_v2_control_suite_capture
    result = governance.post_v2_control_suite_capture.__wrapped__(parsed)

    assert result == expected_return_code
    assert ordering == [
        "metadata",
        "topology",
        "metadata",
        "metadata",
        "topology",
        "metadata",
    ]
    disposition = "reused" if reused else "captured"
    status = "passed" if exit_code == 0 else "failed"
    assert json.loads(capsys.readouterr().out) == {
        "acceptance_eligible": False,
        "acceptance_generation": None,
        "authorization_effect": "none",
        "capture_disposition": disposition,
        "control_scope": "post_v2_control_verification_only",
        "evidence_digest": _digest("e"),
        "evidence_path": str(evidence_path),
        "execution_outcome": outcome,
        "pytest_exit_code": exit_code,
        "pytest_totals": totals,
        "result": f"post_v2_control_suite_evidence_{disposition}_{status}",
        "subject_commit": subject_commit,
        "subject_parent_commit": subject_parent_commit,
        "suite_passed": exit_code == 0,
    }


def test_interrupted_acceptance_transaction_rolls_back_exact_prior_bytes(
    tmp_path: Path,
) -> None:
    repository = (tmp_path / "repository").resolve()
    governance_root = repository / "docs" / "governance" / "v1"
    governance_root.mkdir(parents=True)
    target = governance_root / "approval-roster.json"
    prior = b'{"state":"prior"}\n'
    next_payload = b'{"state":"next"}\n'
    target.write_bytes(next_payload)
    plan_digest = _digest("a")
    stage = governance._acceptance_stage_path(repository, target, plan_digest=plan_digest)
    stage.parent.mkdir(parents=True)
    stage.write_bytes(next_payload)
    target_relative = target.relative_to(repository).as_posix()
    journal_path = governance._acceptance_transaction_journal(repository)
    journal_path.parent.mkdir(parents=True, exist_ok=True)
    journal_path.write_bytes(
        governance._render_json_bytes(
            {
                "format": "agent-assure-s1-acceptance-import-transaction/1",
                "plan_digest": plan_digest,
                "records": [
                    {
                        "path": target_relative,
                        "prior_present": True,
                        "prior_size_bytes": len(prior),
                        "prior_sha256": governance.raw_digest(prior),
                        "prior_bytes_base64": base64.b64encode(prior).decode("ascii"),
                        "next_size_bytes": len(next_payload),
                        "next_sha256": governance.raw_digest(next_payload),
                        "stage_path": stage.relative_to(repository).as_posix(),
                    }
                ],
            }
        )
    )

    governance._recover_acceptance_transaction(
        repository,
        expected_plan_digest=plan_digest,
        expected_prior_evidence={target_relative: (len(prior), governance.raw_digest(prior))},
        expected_next_payloads={target_relative: next_payload},
    )

    assert target.read_bytes() == prior
    assert not stage.exists()
    assert not journal_path.exists()


def test_interrupted_acceptance_transaction_rejects_a_different_plan(
    tmp_path: Path,
) -> None:
    repository = (tmp_path / "repository").resolve()
    journal_path = governance._acceptance_transaction_journal(repository)
    journal_path.parent.mkdir(parents=True, exist_ok=True)
    journal_bytes = governance._render_json_bytes(
        {
            "format": "agent-assure-s1-acceptance-import-transaction/1",
            "plan_digest": _digest("a"),
            "records": [],
        }
    )
    journal_path.write_bytes(journal_bytes)

    with pytest.raises(
        governance.GovernanceError,
        match="interrupted acceptance import exists for a different plan digest",
    ):
        governance._recover_acceptance_transaction(
            repository,
            expected_plan_digest=_digest("b"),
            expected_prior_evidence={},
            expected_next_payloads={},
        )

    assert journal_path.read_bytes() == journal_bytes


def test_acceptance_target_install_is_exact_and_clears_its_journal(
    tmp_path: Path,
) -> None:
    repository = (tmp_path / "repository").resolve()
    governance_root = repository / "docs" / "governance" / "v1"
    governance_root.mkdir(parents=True)
    target = governance_root / "approval-roster.json"
    governance._write_json(target, {"state": "prior"})
    prior = target.read_bytes()
    expected = {"state": "next"}
    target_relative = target.relative_to(repository).as_posix()

    governance._install_acceptance_targets(
        repository,
        {target: expected},
        plan_digest=_digest("a"),
        expected_prior_evidence={target_relative: (len(prior), governance.raw_digest(prior))},
    )

    assert governance._read_json(target) == expected
    assert not governance._acceptance_transaction_journal(repository).exists()
    assert not list(governance_root.glob("*.s1-accept-*.tmp"))


@pytest.mark.parametrize("crash_after_target", [1, 2, 3])
def test_three_target_closure_install_recovers_crash_at_every_replace_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    crash_after_target: int,
) -> None:
    repository = (tmp_path / "repository").resolve()
    records: dict[Path, dict[str, Any]] = {}
    prior_bytes: dict[str, bytes] = {}
    prior_evidence: dict[str, tuple[int, str]] = {}
    for index, relative in enumerate(sorted(governance.S1_CORRECTIVE_CLOSURE_PATHS), start=1):
        target = repository / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        prior = governance._render_json_bytes({"generation": 1, "index": index})
        target.write_bytes(prior)
        records[target] = {"generation": 2, "index": index}
        prior_bytes[relative] = prior
        prior_evidence[relative] = (len(prior), governance.raw_digest(prior))
    plan_digest = _digest("d")
    real_replace = Path.replace
    replacements = 0

    def crash_after_install(source: Path, target: Path) -> Path:
        nonlocal replacements
        result = real_replace(source, target)
        if source.parent.name == "correction-v2-install-staging":
            replacements += 1
            if replacements == crash_after_target:
                raise KeyboardInterrupt("simulated process death")
        return result

    with monkeypatch.context() as crash_patch:
        crash_patch.setattr(Path, "replace", crash_after_install)
        with pytest.raises(KeyboardInterrupt, match="simulated process death"):
            governance._install_acceptance_targets(
                repository,
                records,
                plan_digest=plan_digest,
                expected_prior_evidence=prior_evidence,
            )

    journal = governance._acceptance_transaction_journal(repository)
    assert journal.is_file()
    expected_next = {
        path.relative_to(repository).as_posix(): governance._render_json_bytes(record)
        for path, record in records.items()
    }
    governance._recover_acceptance_transaction(
        repository,
        expected_plan_digest=plan_digest,
        expected_prior_evidence=prior_evidence,
        expected_next_payloads=expected_next,
    )

    assert not journal.exists()
    for relative, prior in prior_bytes.items():
        assert (repository / relative).read_bytes() == prior
    assert not list((repository / "docs" / "governance" / "v1").glob("*.tmp"))


def test_corrective_bundle_import_reports_completed_install_idempotently(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository = (tmp_path / "repository").resolve()
    governance_root = repository / "docs" / "governance" / "v1"
    governance_root.mkdir(parents=True)
    plan_directory = repository / ".tmp/s1-acceptance/phase-v2-bundle"
    plan_directory.mkdir(parents=True)
    for name in (
        "plan.json",
        "governance-bundle.claim",
        "governance-bundle.claim.sig",
        "verified-closure-import.json",
    ):
        (plan_directory / name).write_bytes(b"placeholder\n")
    result_commit = "a" * 40
    plan_digest = _digest("d")
    targets = {
        relative: {
            "format": (
                "agent-assure-governance-bundle/2"
                if relative.endswith("governance-bundle.json")
                else "agent-assure-ticket-completion-receipt/2"
            ),
            **(
                {"bundle_digest": _digest("b")}
                if relative.endswith("governance-bundle.json")
                else {"receipt_digest": _digest("c")}
            ),
        }
        for relative in governance.S1_CORRECTIVE_CLOSURE_PATHS
    }
    plan = {
        "result_commit": result_commit,
        "corrective_authorization_claim_digest": (governance.CORRECTIVE_KICKOFF_CLAIM_DIGEST),
        "targets": [],
        "source_files": [],
    }
    monkeypatch.setattr(
        governance,
        "_corrective_private_acceptance_path",
        lambda *_args, **_kwargs: plan_directory,
    )
    monkeypatch.setattr(
        governance,
        "_read_corrective_v2_plan",
        lambda *_args, **_kwargs: plan,
    )
    monkeypatch.setattr(
        governance,
        "_require_corrective_v2_plan_source_set",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        governance,
        "_corrective_v2_plan_targets",
        lambda *_args, **_kwargs: targets,
    )
    monkeypatch.setattr(
        governance,
        "_acceptance_plan_target_prior_evidence",
        lambda *_args, **_kwargs: {
            relative: (1, _digest("1")) for relative in governance.S1_CORRECTIVE_CLOSURE_PATHS
        },
    )
    monkeypatch.setattr(
        governance,
        "_read_corrective_closure_import_artifact",
        lambda *_args, **_kwargs: ({}, targets),
    )
    monkeypatch.setattr(
        governance,
        "_recover_acceptance_transaction",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        governance,
        "_corrective_target_payload_state",
        lambda *_args, **_kwargs: (True, True),
    )
    monkeypatch.setattr(
        governance,
        "_verify_corrective_plan_sources_after_install",
        lambda *_args, **_kwargs: None,
    )

    def load_materialized(**kwargs: Any) -> dict[str, Any]:
        assert kwargs["allow_materialized_closure"] is True
        return {"snapshot": _minimal_snapshot()}

    monkeypatch.setattr(
        governance,
        "_load_corrective_v2_workspace",
        load_materialized,
    )
    monkeypatch.setattr(
        governance,
        "_validate_materialized_corrective_closure",
        lambda **_kwargs: (targets["docs/governance/v1/governance-bundle.json"], {}),
    )
    real_lock = governance._acceptance_import_lock
    lock_active = False

    @contextmanager
    def tracked_lock(root: Path) -> Any:
        nonlocal lock_active
        with real_lock(root):
            lock_active = True
            try:
                yield
            finally:
                lock_active = False

    monkeypatch.setattr(governance, "_acceptance_import_lock", tracked_lock)

    def validate_while_serialized(*_args: Any, **_kwargs: Any) -> dict[str, str]:
        assert lock_active
        return {relative: "M" for relative in governance.S1_CORRECTIVE_CLOSURE_PATHS}

    monkeypatch.setattr(
        governance,
        "_validate_corrective_closure_worktree",
        validate_while_serialized,
    )
    monkeypatch.setattr(
        governance,
        "_install_acceptance_targets",
        lambda *_args, **_kwargs: pytest.fail(
            "completed closure must not be installed a second time"
        ),
    )

    assert (
        governance.corrective_v2_bundle_import.__wrapped__(
            Namespace(
                repository_root=str(repository),
                governance_dir=str(governance_root),
                roadmap=str(repository / "Agent_Assure_Implementation_Roadmap.md"),
                plan_dir=str(plan_directory),
                expected_plan_digest=plan_digest,
            )
        )
        == 0
    )
    output = json.loads(capsys.readouterr().out)
    assert output["idempotent_recovery"] is True
    assert output["result"] == "three_c2_records_atomically_installed_not_committed"


def test_interrupted_acceptance_transaction_refuses_unknown_target_bytes(
    tmp_path: Path,
) -> None:
    repository = (tmp_path / "repository").resolve()
    governance_root = repository / "docs" / "governance" / "v1"
    governance_root.mkdir(parents=True)
    target = governance_root / "approval-roster.json"
    prior = b'{"state":"prior"}\n'
    next_payload = b'{"state":"next"}\n'
    target.write_bytes(b'{"state":"unknown"}\n')
    plan_digest = _digest("a")
    stage = governance._acceptance_stage_path(repository, target, plan_digest=plan_digest)
    stage.parent.mkdir(parents=True)
    stage.write_bytes(next_payload)
    target_relative = target.relative_to(repository).as_posix()
    journal_path = governance._acceptance_transaction_journal(repository)
    journal_path.parent.mkdir(parents=True, exist_ok=True)
    journal_path.write_bytes(
        governance._render_json_bytes(
            {
                "format": "agent-assure-s1-acceptance-import-transaction/1",
                "plan_digest": plan_digest,
                "records": [
                    {
                        "path": target_relative,
                        "prior_present": True,
                        "prior_size_bytes": len(prior),
                        "prior_sha256": governance.raw_digest(prior),
                        "prior_bytes_base64": base64.b64encode(prior).decode("ascii"),
                        "next_size_bytes": len(next_payload),
                        "next_sha256": governance.raw_digest(next_payload),
                        "stage_path": stage.relative_to(repository).as_posix(),
                    }
                ],
            }
        )
    )

    with pytest.raises(governance.GovernanceError, match="unknown bytes"):
        governance._recover_acceptance_transaction(
            repository,
            expected_plan_digest=plan_digest,
            expected_prior_evidence={target_relative: (len(prior), governance.raw_digest(prior))},
            expected_next_payloads={target_relative: next_payload},
        )

    assert target.read_bytes() == b'{"state":"unknown"}\n'
    assert stage.exists()
    assert journal_path.exists()


def test_interrupted_acceptance_transaction_rejects_forged_staging_path(
    tmp_path: Path,
) -> None:
    repository = (tmp_path / "repository").resolve()
    governance_root = repository / "docs" / "governance" / "v1"
    governance_root.mkdir(parents=True)
    target = governance_root / "approval-roster.json"
    unrelated = governance_root / "must-not-delete.json"
    prior = b'{"state":"prior"}\n'
    next_payload = b'{"state":"next"}\n'
    unrelated_payload = b'{"important":true}\n'
    target.write_bytes(next_payload)
    unrelated.write_bytes(unrelated_payload)
    plan_digest = _digest("a")
    target_relative = target.relative_to(repository).as_posix()
    journal_path = governance._acceptance_transaction_journal(repository)
    journal_path.parent.mkdir(parents=True, exist_ok=True)
    journal_path.write_bytes(
        governance._render_json_bytes(
            {
                "format": "agent-assure-s1-acceptance-import-transaction/1",
                "plan_digest": plan_digest,
                "records": [
                    {
                        "path": target_relative,
                        "prior_present": True,
                        "prior_size_bytes": len(prior),
                        "prior_sha256": governance.raw_digest(prior),
                        "prior_bytes_base64": base64.b64encode(prior).decode("ascii"),
                        "next_size_bytes": len(next_payload),
                        "next_sha256": governance.raw_digest(next_payload),
                        "stage_path": unrelated.relative_to(repository).as_posix(),
                    }
                ],
            }
        )
    )

    with pytest.raises(governance.GovernanceError, match="staging path is not deterministic"):
        governance._recover_acceptance_transaction(
            repository,
            expected_plan_digest=plan_digest,
            expected_prior_evidence={target_relative: (len(prior), governance.raw_digest(prior))},
            expected_next_payloads={target_relative: next_payload},
        )

    assert target.read_bytes() == next_payload
    assert unrelated.read_bytes() == unrelated_payload
    assert journal_path.exists()


def test_interrupted_acceptance_transaction_rejects_forged_prior_bytes(
    tmp_path: Path,
) -> None:
    repository = (tmp_path / "repository").resolve()
    governance_root = repository / "docs" / "governance" / "v1"
    governance_root.mkdir(parents=True)
    target = governance_root / "approval-roster.json"
    plan_prior = b'{"state":"plan-prior"}\n'
    forged_prior = b'{"state":"attacker-prior"}\n'
    next_payload = b'{"state":"next"}\n'
    target.write_bytes(next_payload)
    plan_digest = _digest("a")
    stage = governance._acceptance_stage_path(repository, target, plan_digest=plan_digest)
    stage.parent.mkdir(parents=True)
    stage.write_bytes(next_payload)
    target_relative = target.relative_to(repository).as_posix()
    journal_path = governance._acceptance_transaction_journal(repository)
    journal_path.parent.mkdir(parents=True, exist_ok=True)
    journal_path.write_bytes(
        governance._render_json_bytes(
            {
                "format": "agent-assure-s1-acceptance-import-transaction/1",
                "plan_digest": plan_digest,
                "records": [
                    {
                        "path": target_relative,
                        "prior_present": True,
                        "prior_size_bytes": len(forged_prior),
                        "prior_sha256": governance.raw_digest(forged_prior),
                        "prior_bytes_base64": base64.b64encode(forged_prior).decode("ascii"),
                        "next_size_bytes": len(next_payload),
                        "next_sha256": governance.raw_digest(next_payload),
                        "stage_path": stage.relative_to(repository).as_posix(),
                    }
                ],
            }
        )
    )

    with pytest.raises(
        governance.GovernanceError,
        match="prior evidence differs from its plan",
    ):
        governance._recover_acceptance_transaction(
            repository,
            expected_plan_digest=plan_digest,
            expected_prior_evidence={
                target_relative: (len(plan_prior), governance.raw_digest(plan_prior))
            },
            expected_next_payloads={target_relative: next_payload},
        )

    assert target.read_bytes() == next_payload
    assert stage.exists()
    assert journal_path.exists()


@pytest.fixture(scope="module")
def frozen_forecast_v2_evidence() -> dict[str, Any]:
    if not ROADMAP.is_file():
        pytest.skip(
            "the frozen forecast artifacts can only be recomputed with the local private roadmap"
        )
    snapshot = governance.load_roadmap(ROADMAP)
    catalog = _record("delivery-forecast.estimation-catalog.json")
    baseline = _record("baseline-observations.json")
    pending_ledger = governance.build_authoring_ledger_v2(
        snapshot,
        catalog,
        baseline_observations_digest_value=baseline["observations_digest"],
        inventory_completed_at=baseline["inventory_completed_at_utc"],
    )
    return {
        "snapshot": snapshot,
        "catalog": catalog,
        "registry": _record("delivery-forecast.aggregation-registry.json"),
        "baseline": baseline,
        "pending_ledger": pending_ledger,
        "ledger": _record("delivery-forecast.authoring-ledger.json"),
        "forecast": _record("delivery-forecast.json"),
        "roster": _record("approval-roster.json"),
    }


def test_host_specific_reads_are_confined_to_the_local_frozen_fixture() -> None:
    import ast

    syntax = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    roadmap_readers: set[tuple[str, str]] = set()
    root_git_uses: set[tuple[str, str]] = set()

    def assigned_names(node: ast.AST) -> set[str]:
        return {
            child.id
            for child in ast.walk(node)
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store)
        }

    def referenced_names(node: ast.AST) -> set[str]:
        return {
            child.id
            for child in ast.walk(node)
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load)
        }

    def has_git_path_component(node: ast.AST) -> bool:
        return any(
            isinstance(child, ast.Constant)
            and isinstance(child.value, str)
            and ".git" in child.value.replace("\\", "/").split("/")
            for child in ast.walk(node)
        )

    def scope_nodes(scope: ast.AST) -> list[ast.AST]:
        nodes: list[ast.AST] = []
        pending = list(ast.iter_child_nodes(scope))
        while pending:
            node = pending.pop()
            if isinstance(
                node,
                (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda),
            ):
                continue
            nodes.append(node)
            pending.extend(ast.iter_child_nodes(node))
        return nodes

    scopes: list[tuple[str, ast.AST]] = [("<module>", syntax)]
    scopes.extend(
        (node.name, node)
        for node in ast.walk(syntax)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    )
    git_metadata_helpers = {
        "_post_r2_git_exclude_evidence",
        "_post_v2_git_attributes_absence_evidence",
        "_post_v2_control_git_metadata_preflight",
    }
    for scope_name, scope in scopes:
        nodes = scope_nodes(scope)
        root_derived_names = {"ROOT"}
        root_git_names: set[str] = set()
        assignments = [
            node
            for node in nodes
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr))
            and node.value is not None
        ]
        changed = True
        while changed:
            changed = False
            for assignment in assignments:
                value = assignment.value
                names = referenced_names(value)
                targets = assigned_names(assignment)
                is_root_derived = bool(names & root_derived_names)
                is_root_git = bool(names & root_git_names) or (
                    is_root_derived and has_git_path_component(value)
                )
                if is_root_derived and not targets <= root_derived_names:
                    root_derived_names.update(targets)
                    changed = True
                if is_root_git and not targets <= root_git_names:
                    root_git_names.update(targets)
                    changed = True

        for assignment in assignments:
            value = assignment.value
            if bool(referenced_names(value) & root_git_names) or (
                bool(referenced_names(value) & root_derived_names) and has_git_path_component(value)
            ):
                root_git_uses.add((scope_name, "assignment"))

        for returned in (node for node in nodes if isinstance(node, ast.Return)):
            if returned.value is not None and (
                bool(referenced_names(returned.value) & root_git_names)
                or (
                    bool(referenced_names(returned.value) & root_derived_names)
                    and has_git_path_component(returned.value)
                )
            ):
                root_git_uses.add((scope_name, "return"))

        for call in (node for node in nodes if isinstance(node, ast.Call)):
            call_name = call.func.attr if isinstance(call.func, ast.Attribute) else None
            if isinstance(call.func, ast.Name):
                call_name = call.func.id
            inputs = [*call.args, *[item.value for item in call.keywords]]
            if isinstance(call.func, ast.Attribute):
                inputs.append(call.func.value)
            reads_roadmap = any(
                isinstance(node, ast.Name) and node.id == "ROADMAP"
                for argument in inputs
                for node in ast.walk(argument)
            )
            if reads_roadmap and call_name in {
                "load_roadmap",
                "open",
                "read_bytes",
                "read_text",
            }:
                roadmap_readers.add((scope_name, call_name))

            reads_root_git = any(
                bool(referenced_names(argument) & root_git_names)
                or (
                    bool(referenced_names(argument) & root_derived_names)
                    and has_git_path_component(argument)
                )
                for argument in inputs
            )
            reads_root_git_indirectly = (
                isinstance(call.func, ast.Attribute)
                and isinstance(call.func.value, ast.Name)
                and call.func.value.id == "governance"
                and call.func.attr in git_metadata_helpers
                and any(
                    bool(referenced_names(argument) & root_derived_names) for argument in inputs
                )
            )
            if reads_root_git or reads_root_git_indirectly:
                root_git_uses.add((scope_name, call_name or "call"))

    assert roadmap_readers == {("frozen_forecast_v2_evidence", "load_roadmap")}
    assert root_git_uses == set()


def _synthetic_forecast_v2_snapshot() -> governance.RoadmapSnapshot:
    """Build the exact aggregate shape without consulting the private roadmap."""

    entry_count = 39
    rel02_trains = (
        "oscal-1.1",
        "otel-1.2",
        "otel-1.2",
        "statistics-1.3",
        "statistics-1.3",
        "structural-1.4",
        "structural-1.4",
        "formal-1.5",
        "formal-1.5",
        "intervention-1.6",
        "intervention-1.6",
    )
    entries = [
        {
            "sprint": f"S{index + 1}",
            "release": f"1.0.0a{index + 1}",
            "train": rel02_trains[index] if index < len(rel02_trains) else "stable-1.0",
            "artifact_kind": "governance-bundle",
            "ticket_ids": [],
        }
        for index in range(entry_count)
    ]
    ticket_specs: list[tuple[str, tuple[int, ...], int, str]] = [
        ("V1-REL-02", tuple(range(11)), 5, "per_release_or_gate_execution")
    ]
    for index in range(43):
        ticket_specs.append(
            (
                f"V1-SYN-{index + 1:02d}",
                (index % entry_count, (index + 13) % entry_count),
                8 if index < 34 else 7,
                "per_candidate_execution",
            )
        )
    for index in range(24):
        ticket_specs.append(
            (
                f"V1-ONE-{index + 1:02d}",
                ((index + 7) % entry_count,),
                1 if index < 20 else 0,
                "ticket_completion",
            )
        )

    for ticket_id, entry_indices, _criterion_count, _scope in ticket_specs:
        for entry_index in entry_indices:
            entries[entry_index]["ticket_ids"].append(ticket_id)

    remaining_unquantified_wait_criteria = 175
    tickets: list[dict[str, Any]] = []
    for ticket_index, (ticket_id, entry_indices, criterion_count, scope) in enumerate(ticket_specs):
        criteria: list[str] = []
        for criterion_index in range(criterion_count):
            contains_wait = ticket_id.startswith("V1-SYN-") and (
                remaining_unquantified_wait_criteria > 0
            )
            criteria.append(
                f"Synthetic wait obligation {criterion_index + 1}."
                if contains_wait
                else f"Synthetic obligation {criterion_index + 1}."
            )
            if contains_wait:
                remaining_unquantified_wait_criteria -= 1

        packages: list[dict[str, Any]] = []
        if ticket_index == 0:
            package_ordinal = 0
            for occurrence_index, component_count in zip(
                (0, 2, 4, 6, 8, 10),
                (2, 3, 5, 6, 7, 8),
                strict=True,
            ):
                for _component_index in range(component_count):
                    package_ordinal += 1
                    package = {
                        "id": f"WP-{package_ordinal:02d}",
                        "planned_sprint": entries[entry_indices[occurrence_index]]["sprint"],
                        "depends_on_work_package_ids": [],
                        "profile_admission_instance_id": f"SYNTHETIC-{package_ordinal:02d}",
                    }
                    if package_ordinal <= 2:
                        package["minimum_observation_window_days"] = 7 * package_ordinal
                    packages.append(package)
        elif 1 <= ticket_index <= 36:
            planned_sprint = entries[entry_indices[0]]["sprint"]
            package_count = 2 if ticket_index <= 35 else 1
            for package_index in range(package_count):
                package: dict[str, Any] = {
                    "id": f"WP-{package_index + 1:02d}",
                    "planned_sprint": planned_sprint,
                    "depends_on_work_package_ids": [],
                }
                packages.append(package)

        tickets.append(
            {
                "id": ticket_id,
                "depends_on": [],
                "acceptance_criteria": criteria,
                "work_packages": packages,
                "delivery": {
                    "estimate": {
                        "scope": scope,
                        "unit": "focused_engineer_day",
                        "p50": 1,
                        "p90": 2,
                        "confidence": "low",
                        "basis": "synthetic_private-roadmap-independent_control",
                    },
                    "review_effort_p50_days": 1,
                },
                "acceptance_commands": ["pytest synthetic-control"],
                "existing_anchors_to_verify": [],
                "golden_case_ids": [],
                "normative_sections": [],
                "proposed_change_roles": [],
                "resolved_allowed_files": [],
                "required_completion_receipts": (
                    ["synthetic_receipt"] if ticket_index == 0 else []
                ),
            }
        )

    assert remaining_unquantified_wait_criteria == 0
    assert all(entry["ticket_ids"] for entry in entries)
    return governance.RoadmapSnapshot(
        raw_digest="sha256:" + "1" * 64,
        tickets=tuple(tickets),
        release_train={"entries": entries},
        approval_roster_template={},
        ticket_set_digest="sha256:" + "2" * 64,
        dependency_graph_digest="sha256:" + "3" * 64,
        release_train_digest="sha256:" + "4" * 64,
    )


@pytest.fixture(scope="module")
def synthetic_forecast_v2_evidence() -> dict[str, Any]:
    snapshot = _synthetic_forecast_v2_snapshot()
    catalog = _record("delivery-forecast.estimation-catalog.json")
    baseline = _record("baseline-observations.json")
    pending_ledger = governance.build_authoring_ledger_v2(
        snapshot,
        catalog,
        baseline_observations_digest_value=baseline["observations_digest"],
        inventory_completed_at=baseline["inventory_completed_at_utc"],
    )
    governance.validate_authoring_ledger_v2(
        snapshot,
        pending_ledger,
        _record("delivery-forecast.authoring-ledger.schema.json"),
        catalog,
        baseline_observations=baseline,
        allow_pending=True,
    )
    decision_manifest = governance.build_forecast_decision_manifest_v2(pending_ledger)
    signature_envelope = governance._pending_signature_v2(
        "acblabs", "repository_maintainer", decision_manifest["manifest_digest"]
    )
    signature_envelope.update(status="signed", signature="test-signature")
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(
            governance,
            "_validate_signature_envelope_v2",
            lambda *_args, **_kwargs: True,
        )
        ledger = governance._apply_forecast_decision_manifest_v2(
            pending_ledger,
            decision_manifest,
            signature_envelope,
        )
    registry = governance.aggregation_method_registry_v2()
    roster = _record("approval-roster.json")
    roster_digest = governance.approval_roster_digest(roster)
    forecast = governance.build_forecast_v2(
        snapshot,
        ledger,
        registry,
        approval_roster=roster,
        approval_roster_digest_value=roster_digest,
        issued_at="2026-10-16T03:00:00Z",
        valid_until="2026-11-15T03:00:00Z",
        trusted_time_basis=(
            "maintainer-trusted host UTC; Windows Time attestation unavailable; "
            "OpenSSH SSHSIG carries no timestamp"
        ),
    )
    return {
        "snapshot": snapshot,
        "catalog": catalog,
        "registry": registry,
        "baseline": baseline,
        "pending_ledger": pending_ledger,
        "ledger": ledger,
        "forecast": forecast,
        "roster": roster,
    }


@pytest.fixture
def forecast_v2_evidence(
    synthetic_forecast_v2_evidence: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> dict[str, Any]:
    monkeypatch.setattr(
        governance,
        "_validate_signature_envelope_v2",
        lambda *_args, **_kwargs: True,
    )
    return copy.deepcopy(synthetic_forecast_v2_evidence)


def _validate_v2_ledger(evidence: dict[str, Any], ledger: dict[str, Any]) -> None:
    governance.validate_authoring_ledger_v2(
        evidence["snapshot"],
        ledger,
        _record("delivery-forecast.authoring-ledger.schema.json"),
        evidence["catalog"],
        baseline_observations=evidence["baseline"],
        allow_pending=True,
    )


def _validate_v2_forecast(evidence: dict[str, Any], forecast: dict[str, Any]) -> None:
    governance.validate_forecast_v2(
        evidence["snapshot"],
        evidence["ledger"],
        evidence["registry"],
        forecast,
        _record("delivery-forecast.schema.json"),
        approval_roster=evidence["roster"],
        approval_roster_digest_value=evidence["forecast"]["approval_roster_digest"],
        allow_pending=True,
    )


def test_frozen_v2_forecast_artifacts_recompute_exactly(
    frozen_forecast_v2_evidence: dict[str, Any],
) -> None:
    evidence = frozen_forecast_v2_evidence
    governance.validate_estimation_catalog_v2(
        evidence["catalog"],
        _record("delivery-forecast.estimation-catalog.schema.json"),
    )
    assert evidence["registry"] == governance.aggregation_method_registry_v2()
    rebuilt_ledger = governance.build_authoring_ledger_v2(
        evidence["snapshot"],
        evidence["catalog"],
        baseline_observations_digest_value=evidence["baseline"]["observations_digest"],
        inventory_completed_at=evidence["baseline"]["inventory_completed_at_utc"],
    )
    assert rebuilt_ledger == evidence["pending_ledger"]
    decision_manifest = governance.build_forecast_decision_manifest_v2(rebuilt_ledger)
    decision_evidence = evidence["ledger"]["decision_evidence"]
    assert decision_manifest["manifest_digest"] == decision_evidence["decision_manifest_digest"]
    rebuilt_ledger = governance._apply_forecast_decision_manifest_v2(
        rebuilt_ledger,
        decision_manifest,
        decision_evidence["signature_envelope"],
    )
    assert rebuilt_ledger == evidence["ledger"]
    rebuilt_forecast = governance.build_forecast_v2(
        evidence["snapshot"],
        rebuilt_ledger,
        evidence["registry"],
        approval_roster=evidence["roster"],
        approval_roster_digest_value=evidence["forecast"]["approval_roster_digest"],
        issued_at=evidence["forecast"]["issued_at_utc"],
        valid_until=evidence["forecast"]["valid_until_utc"],
        trusted_time_basis=evidence["forecast"]["trusted_time_basis"],
        accepted_candidate=True,
    )
    rebuilt_forecast["signature_envelope"] = copy.deepcopy(
        evidence["forecast"]["signature_envelope"]
    )
    rebuilt_forecast["acceptance_receipt"]["signature_envelope"] = copy.deepcopy(
        evidence["forecast"]["acceptance_receipt"]["signature_envelope"]
    )
    assert rebuilt_forecast == evidence["forecast"]
    _validate_v2_ledger(evidence, evidence["ledger"])
    _validate_v2_forecast(evidence, evidence["forecast"])


def _assert_v2_inventory_partition_slots_waits_and_rel02_sequence(
    evidence: dict[str, Any],
) -> None:
    rows = evidence["ledger"]["rows"]
    proposals = [proposal for row in rows for proposal in row["execution_proposals"]]
    assert (len(rows), len(proposals)) == (68, 121)
    assert sum(row["source_anchors"]["acceptance_criteria_count"] for row in rows) == 360
    assert sum(row["source_anchors"]["work_package_count"] for row in rows) == 102
    assert (
        sum(len(proposal["obligation_coverage"]["acceptance_criteria"]) for proposal in proposals)
        == 745
    )
    assert (
        sum(len(proposal["obligation_coverage"]["work_packages"]) for proposal in proposals) == 102
    )
    for proposal in proposals:
        coverage = proposal["obligation_coverage"]
        acceptance_ordinals = [
            item["primary_work_unit_ordinal"] for item in coverage["acceptance_criteria"]
        ]
        assert acceptance_ordinals == list(range(1, len(acceptance_ordinals) + 1))
        package_ordinals = [item["primary_work_unit_ordinal"] for item in coverage["work_packages"]]
        assert package_ordinals == list(range(1, len(package_ordinals) + 1))
        assert coverage["occurrence_anchor_work_unit_ordinal"] == 1
    waits = [
        wait
        for proposal in proposals
        for wait in proposal["elapsed_time"]["known_wait_requirements"]
    ]
    assert [wait["minimum_elapsed_hours"] for wait in waits] == [168, 336]
    assert (
        sum(
            proposal["elapsed_time"]["unquantified_wait_dependency_count"] for proposal in proposals
        )
        == 350
    )
    assert all(not row["resolved_allowed_files"] for row in evidence["snapshot"].tickets)
    rel02 = next(row for row in rows if row["ticket_id"] == "V1-REL-02")
    assert [
        proposal["workload_vector"]["cumulative_optional_profile_count"]
        for proposal in rel02["execution_proposals"]
    ] == [1, 2, 2, 4, 4, 5, 5, 6, 6, 7, 7]
    assert [
        proposal["workload_vector"]["evidence_receipt_instance_count"]
        for proposal in rel02["execution_proposals"]
    ] == [3, 1, 4, 1, 6, 1, 7, 1, 8, 1, 9]


def test_v2_forecast_inventory_partition_slots_waits_and_rel02_sequence(
    frozen_forecast_v2_evidence: dict[str, Any],
) -> None:
    _assert_v2_inventory_partition_slots_waits_and_rel02_sequence(frozen_forecast_v2_evidence)


def test_synthetic_v2_forecast_exercises_the_exact_inventory_shape(
    forecast_v2_evidence: dict[str, Any],
) -> None:
    _assert_v2_inventory_partition_slots_waits_and_rel02_sequence(forecast_v2_evidence)
    snapshot = forecast_v2_evidence["snapshot"]
    signed_roadmap_identity = governance.RoadmapSnapshot(
        raw_digest=governance.CORRECTIVE_ROADMAP_DIGEST,
        tickets=snapshot.tickets,
        release_train=snapshot.release_train,
        approval_roster_template=snapshot.approval_roster_template,
        ticket_set_digest=snapshot.ticket_set_digest,
        dependency_graph_digest=snapshot.dependency_graph_digest,
        release_train_digest=snapshot.release_train_digest,
    )
    baseline = forecast_v2_evidence["baseline"]
    targeted_pending_ledger = governance.build_authoring_ledger_v2(
        signed_roadmap_identity,
        forecast_v2_evidence["catalog"],
        baseline_observations_digest_value=baseline["observations_digest"],
        inventory_completed_at=baseline["inventory_completed_at_utc"],
    )
    with pytest.raises(
        governance.GovernanceError,
        match="ledger must contain exactly one V1-BASE-06 row",
    ):
        governance.validate_authoring_ledger_v2(
            signed_roadmap_identity,
            targeted_pending_ledger,
            _record("delivery-forecast.authoring-ledger.schema.json"),
            forecast_v2_evidence["catalog"],
            baseline_observations=forecast_v2_evidence["baseline"],
            allow_pending=True,
        )


def test_v2_proposal_digest_has_a_verifiable_finalized_state_projection() -> None:
    ledger = _record("delivery-forecast.authoring-ledger.json")
    proposal = ledger["rows"][0]["execution_proposals"][0]
    assert proposal["decision"]["status"] == "human_accepted"
    assert (
        proposal["elapsed_time"]["critical_path_status"] == "not_modeled_scope_rebaseline_required"
    )
    assert governance._occurrence_proposal_v2_digest(proposal) == proposal["proposal_digest"]
    governance._validate_occurrence_proposal_v2_digest(proposal)

    altered = copy.deepcopy(proposal)
    altered["effort_proposal"]["p90_effort_hours"] += 1
    assert governance._occurrence_proposal_v2_digest(altered) != proposal["proposal_digest"]
    with pytest.raises(
        governance.GovernanceError,
        match="generation-2 occurrence proposal digest mismatch",
    ):
        governance._validate_occurrence_proposal_v2_digest(altered)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value["rows"][0]["execution_proposals"][0]["workload_vector"].__setitem__(
            "golden_case_count", 999
        ),
        lambda value: value["rows"][0]["execution_proposals"][0]["obligation_coverage"][
            "acceptance_criteria"
        ].reverse(),
        lambda value: value["rows"][0]["execution_proposals"][0]["work_breakdown"][0].__setitem__(
            "quantity", 999
        ),
        lambda value: value["rows"].reverse(),
    ],
)
def test_v2_ledger_mutations_fail_closed(
    forecast_v2_evidence: dict[str, Any], mutation: Any
) -> None:
    altered = copy.deepcopy(forecast_v2_evidence["ledger"])
    mutation(altered)
    altered["ledger_digest"] = governance._ledger_v2_digest(altered)
    with pytest.raises(governance.GovernanceError):
        _validate_v2_ledger(forecast_v2_evidence, altered)


def test_v2_catalog_rule_id_and_rate_mutations_fail_closed(
    forecast_v2_evidence: dict[str, Any],
) -> None:
    altered_rule = copy.deepcopy(forecast_v2_evidence["catalog"])
    altered_rule["workload_derivation"]["input_count_rules"][0]["rule_id"] = "evil/v1"
    altered_rate = copy.deepcopy(forecast_v2_evidence["catalog"])
    altered_rate["work_unit_catalog"][0]["p90_effort_hours"] += 1
    for altered in (altered_rule, altered_rate):
        altered["catalog_digest"] = governance.domain_digest(
            governance.ESTIMATION_CATALOG_V2_DOMAIN,
            {key: value for key, value in altered.items() if key != "catalog_digest"},
        )
        with pytest.raises(governance.GovernanceError):
            governance.validate_estimation_catalog_v2(
                altered,
                _record("delivery-forecast.estimation-catalog.schema.json"),
            )


def _decided_v2_ledger(
    evidence: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> tuple[dict[str, Any], dict[str, Any]]:
    manifest = governance.build_forecast_decision_manifest_v2(evidence["pending_ledger"])
    envelope = governance._pending_signature_v2(
        "acblabs", "repository_maintainer", manifest["manifest_digest"]
    )
    envelope.update(status="signed", signature="test-signature")
    monkeypatch.setattr(governance, "_validate_signature_envelope_v2", lambda *args, **kwargs: True)
    decided = governance._apply_forecast_decision_manifest_v2(
        evidence["pending_ledger"], manifest, envelope
    )
    return manifest, decided


def test_v2_timestamp_free_batch_decision_binds_every_item_and_epistemic_state(
    forecast_v2_evidence: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence = forecast_v2_evidence
    manifest, decided = _decided_v2_ledger(evidence, monkeypatch)
    assert manifest["ticket_row_count"] == 68
    assert manifest["execution_occurrence_count"] == 121
    assert len(manifest["items"]) == 189
    serialized = json.dumps(manifest)
    assert "reviewed_at" not in serialized and "signed_at" not in serialized
    occurrence = next(
        item for item in manifest["items"] if item["item_kind"] == "execution_occurrence"
    )
    assert {
        "coverage_digest",
        "workload_vector_digest",
        "work_breakdown_digest",
        "proposal_digest",
        "selected_p50_effort_hours",
        "selected_p90_effort_hours",
        "selected_reviewer_effort_hours",
        "decision_status",
    } <= set(occurrence)
    assert all(row["row_decision"]["reviewed_at_utc"] is None for row in decided["rows"])
    assert all(
        row["proposal_epistemic_status"].startswith("human_adopted_subjective")
        for row in decided["rows"]
    )
    assert all(
        proposal["elapsed_time"]["critical_path_status"] == "not_modeled_scope_rebaseline_required"
        for row in decided["rows"]
        for proposal in row["execution_proposals"]
    )
    altered = copy.deepcopy(manifest)
    altered["items"][1]["selected_p90_effort_hours"] += 1
    envelope = decided["decision_evidence"]["signature_envelope"]
    with pytest.raises(governance.GovernanceError, match="exact itemized proposal"):
        governance._apply_forecast_decision_manifest_v2(
            evidence["pending_ledger"], altered, envelope
        )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value["portfolio_aggregate"].__setitem__(
            "aggregate_p90_effort_hours",
            value["portfolio_aggregate"]["aggregate_p90_effort_hours"] + 1,
        ),
        lambda value: value["portfolio_scenarios"][0].__setitem__("ticket_count", 999),
        lambda value: value["rows"][0]["execution_estimates"][0].__setitem__(
            "elapsed_wait_included", True
        ),
        lambda value: value["rows"][0]["execution_estimates"][0].__setitem__(
            "proposed_p90_effort_hours", 0
        ),
    ],
)
def test_v2_forecast_relational_and_aggregate_mutations_fail_closed(
    forecast_v2_evidence: dict[str, Any], mutation: Any
) -> None:
    altered = copy.deepcopy(forecast_v2_evidence["forecast"])
    mutation(altered)
    altered["record_digest"] = governance.domain_digest(
        governance.FORECAST_V2_DOMAIN,
        governance._forecast_v2_projection(altered),
    )
    altered["signature_envelope"]["subject_digest"] = altered["record_digest"]
    altered["acceptance_receipt"]["subject_record_digest"] = altered["record_digest"]
    with pytest.raises(governance.GovernanceError):
        _validate_v2_forecast(forecast_v2_evidence, altered)


def test_v2_acceptance_receipt_binds_exact_roster_and_import_observations(
    forecast_v2_evidence: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence = forecast_v2_evidence
    manifest, decided = _decided_v2_ledger(evidence, monkeypatch)
    candidate = governance.build_forecast_v2(
        evidence["snapshot"],
        decided,
        evidence["registry"],
        approval_roster=evidence["roster"],
        approval_roster_digest_value=evidence["forecast"]["approval_roster_digest"],
        issued_at="2026-10-16T03:00:00Z",
        valid_until="2026-11-15T03:00:00Z",
        trusted_time_basis=(
            "maintainer-trusted host UTC; Windows Time attestation unavailable; "
            "OpenSSH SSHSIG carries no timestamp"
        ),
        accepted_candidate=True,
    )
    receipt = candidate["acceptance_receipt"]
    person = evidence["roster"]["people"][0]
    roster_digest = evidence["forecast"]["approval_roster_digest"]
    assert receipt["competence_basis"] == {
        "approval_roster_digest": roster_digest,
        "issuer_person_id": "acblabs",
        "issuer_role_assignments": ["repository_maintainer", "technical_lead"],
        "issuer_competence_scopes": person["competence_scopes"],
    }
    assert receipt["conflicts"] == {
        "approval_roster_digest": roster_digest,
        "issuer_person_id": "acblabs",
        "issuer_conflict_disclosures": person["conflicts"],
        "independence_limitation": "NO_INDEPENDENT_REVIEW",
    }
    assert receipt["review_evidence"]["decision_manifest_digest"] == manifest["manifest_digest"]
    assert receipt["review_evidence"]["approval_roster_digest"] == roster_digest
    assert "signed_at_utc" not in candidate["signature_envelope"]
    assert "signed_at_utc" not in receipt["signature_envelope"]

    evidence_record = governance._forecast_v2_signature_import_evidence(
        signature_plan_digest="sha256:" + "0" * 64,
        claim_preparation_started_at_utc="2026-10-16T03:00:00.000001Z",
        import_verification_started_at_utc="2026-10-16T03:00:00.000002Z",
        import_verification_completed_at_utc="2026-10-16T03:00:00.000003Z",
        issued_at_utc="2026-10-16T03:00:00Z",
        valid_until_utc="2026-11-15T03:00:00Z",
    )
    for envelope in (
        candidate["signature_envelope"],
        receipt["signature_envelope"],
    ):
        before = governance._signature_claim_bytes_v2(envelope)
        envelope.update(
            status="signed",
            signature="schema-valid-placeholder",
            verification_evidence=copy.deepcopy(evidence_record),
        )
        assert governance._signature_claim_bytes_v2(envelope) == before
    governance._validate_json_schema(
        candidate,
        _record("delivery-forecast.schema.json"),
        owner="signed forecast-v2 test candidate",
    )
    governance.validate_forecast_v2(
        evidence["snapshot"],
        decided,
        evidence["registry"],
        candidate,
        _record("delivery-forecast.schema.json"),
        approval_roster=evidence["roster"],
        approval_roster_digest_value=roster_digest,
        allow_pending=False,
    )

    tampered = copy.deepcopy(candidate)
    tampered["acceptance_receipt"]["signature_envelope"]["verification_evidence"][
        "import_verification_completed_at_utc"
    ] = "2026-10-16T03:00:00.000004Z"
    with pytest.raises(governance.GovernanceError, match="do not match"):
        governance.validate_forecast_v2(
            evidence["snapshot"],
            decided,
            evidence["registry"],
            tampered,
            _record("delivery-forecast.schema.json"),
            approval_roster=evidence["roster"],
            approval_roster_digest_value=roster_digest,
            allow_pending=False,
        )


def test_v2_roster_mutations_cannot_rebind_a_frozen_forecast(
    forecast_v2_evidence: dict[str, Any],
) -> None:
    altered = copy.deepcopy(forecast_v2_evidence["roster"])
    altered["people"][0]["competence_scopes"].append("invented_scope")
    with pytest.raises(governance.GovernanceError, match="roster digest mismatch"):
        governance.validate_forecast_v2(
            forecast_v2_evidence["snapshot"],
            forecast_v2_evidence["ledger"],
            forecast_v2_evidence["registry"],
            forecast_v2_evidence["forecast"],
            _record("delivery-forecast.schema.json"),
            approval_roster=altered,
            approval_roster_digest_value=forecast_v2_evidence["forecast"]["approval_roster_digest"],
            allow_pending=False,
        )


def test_v2_host_time_observations_are_captured_internally_and_ordered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed = iter(
        [
            "2026-10-16T03:00:00.000001Z",
            "2026-10-16T03:00:00.000002Z",
            "2026-10-16T02:59:59.999999Z",
        ]
    )
    monkeypatch.setattr(governance, "_canonical_host_utc_now", lambda: next(observed))
    issue = governance._parse_utc("2026-10-16T03:00:00Z", owner="issue")
    expiry = governance._parse_utc("2026-11-15T03:00:00Z", owner="expiry")
    started = governance._capture_forecast_v2_host_utc(
        owner="claim preparation start", not_before=(issue,), before=expiry
    )
    completed = governance._capture_forecast_v2_host_utc(
        owner="import verification completion",
        not_before=(governance._parse_utc(started, owner="start"),),
        before=expiry,
    )
    assert completed.endswith("000002Z")
    with pytest.raises(governance.GovernanceError, match="earlier than"):
        governance._capture_forecast_v2_host_utc(
            owner="reversed observation",
            not_before=(governance._parse_utc(completed, owner="completion"),),
            before=expiry,
        )


def test_v2_signature_import_evidence_rejects_reversed_or_signing_time_claims() -> None:
    with pytest.raises(governance.GovernanceError, match="validity ordering"):
        governance._forecast_v2_signature_import_evidence(
            signature_plan_digest="sha256:" + "0" * 64,
            claim_preparation_started_at_utc="2026-10-16T03:00:00.000003Z",
            import_verification_started_at_utc="2026-10-16T03:00:00.000002Z",
            import_verification_completed_at_utc="2026-10-16T03:00:00.000004Z",
            issued_at_utc="2026-10-16T03:00:00Z",
            valid_until_utc="2026-11-15T03:00:00Z",
        )
    record = governance._forecast_v2_signature_import_evidence(
        signature_plan_digest="sha256:" + "0" * 64,
        claim_preparation_started_at_utc="2026-10-16T03:00:00.000001Z",
        import_verification_started_at_utc="2026-10-16T03:00:00.000002Z",
        import_verification_completed_at_utc="2026-10-16T03:00:00.000003Z",
        issued_at_utc="2026-10-16T03:00:00Z",
        valid_until_utc="2026-11-15T03:00:00Z",
    )
    assert record["actual_signature_time_claimed"] is False
    assert "signed_at_utc" not in record
    assert record["sshsig_timestamp_capability"] == "none"


def test_v2_sign_command_uses_absolute_frozen_executable_and_claim_path() -> None:
    claim = Path(r"C:\tmp\agent-assure-test\producer.claim")
    command = governance._forecast_v2_sign_command(claim)
    assert command == (
        f'"{governance.FROZEN_S1_EXECUTABLE_IDENTITIES["ssh-keygen"].path}" '
        '-Y sign -f "<ABSOLUTE_PRIVATE_KEY_PATH>" '
        f'-n "{governance.SIGNATURE_NAMESPACE}" -O "hashalg=sha512" '
        f'"{claim.resolve()}"'
    )


@pytest.mark.parametrize(
    "relative_path",
    [
        "verified-receipt-import.json",
        "bundle-plan/verified-closure-import.json",
    ],
)
def test_private_import_artifact_publication_is_atomic_and_retryable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative_path: str,
) -> None:
    acceptance_root = tmp_path / ".tmp" / "s1-acceptance"
    target = acceptance_root / relative_path
    value = {"format": "synthetic-import/1", "digest": _digest("a")}
    expected = governance._render_json_bytes(value)
    publish = governance._publish_new_file_atomically
    crashed = False

    def publish_then_crash(*args: Any, **kwargs: Any) -> None:
        nonlocal crashed
        publish(*args, **kwargs)
        if not crashed:
            crashed = True
            raise OSError("synthetic crash after atomic publication")

    monkeypatch.setattr(
        governance,
        "_publish_new_file_atomically",
        publish_then_crash,
    )
    with pytest.raises(governance.GovernanceError, match="unable to write"):
        governance._write_new_private_json(target, value, owner="synthetic import")
    assert target.read_bytes() == expected

    # The retry must reuse the exact complete payload without invoking the
    # publisher again or changing any bytes.
    governance._write_new_private_json(target, value, owner="synthetic import")
    assert target.read_bytes() == expected


def test_private_import_artifact_refuses_unknown_partial_publication(
    tmp_path: Path,
) -> None:
    target = tmp_path / ".tmp" / "s1-acceptance" / "verified-import.json"
    target.parent.mkdir(parents=True)
    partial = b'{"format":"truncated"'
    target.write_bytes(partial)

    with pytest.raises(governance.GovernanceError, match="refusing to overwrite"):
        governance._write_new_private_json(
            target,
            {"format": "complete"},
            owner="synthetic import",
        )
    assert target.read_bytes() == partial


def test_post_r2_evidence_revalidates_runtime_and_private_governance_sources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result_commit = "a" * 40
    evidence_path, record = _post_r2_evidence_fixture(tmp_path, result_commit, monkeypatch)
    runtime_source = tmp_path / ".venv" / "Lib" / "site-packages" / "pytest" / "__init__.py"
    runtime_source.write_bytes(b"# changed runtime\n")
    with pytest.raises(
        governance.GovernanceError,
        match="site-packages inventory changed|test runtime source bytes changed",
    ):
        governance.validate_post_r2_suite_evidence_source(
            evidence_path,
            expected_result_commit=result_commit,
        )

    runtime_source.write_bytes(b"# synthetic pytest runtime\n")
    roadmap = tmp_path / "Agent_Assure_Implementation_Roadmap.md"
    roadmap.write_bytes(b"changed private roadmap\n")
    with pytest.raises(governance.GovernanceError, match="governance source bytes changed"):
        governance.validate_post_r2_suite_evidence_source(
            evidence_path,
            expected_result_commit=result_commit,
        )

    # The original evidence remains self-authenticating; only mutable source
    # revalidation fails, and its digest cannot be repaired without a new run.
    assert record["evidence_digest"].startswith("sha256:")


@pytest.mark.parametrize(
    ("target_count", "crash_after_target"),
    [(1, 1), (2, 1), (2, 2)],
)
def test_forecast_import_transactions_recover_every_replace_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target_count: int,
    crash_after_target: int,
) -> None:
    repository = tmp_path / "repository"
    relatives = [
        "docs/governance/v1/delivery-forecast.json",
        "docs/governance/v1/delivery-forecast.authoring-ledger.json",
    ][:target_count]
    records: dict[Path, dict[str, Any]] = {}
    prior_evidence: dict[str, tuple[int, str]] = {}
    prior_payloads: dict[str, bytes] = {}
    for index, relative in enumerate(relatives):
        target = repository / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        prior = governance._render_json_bytes({"state": "prior", "index": index})
        target.write_bytes(prior)
        records[target] = {"state": "next", "index": index}
        prior_payloads[relative] = prior
        prior_evidence[relative] = (len(prior), governance.raw_digest(prior))
    plan_digest = _digest("e")
    real_replace = Path.replace
    replacements = 0

    def crash_after_install(source: Path, target: Path) -> Path:
        nonlocal replacements
        result = real_replace(source, target)
        if source.parent.name == "correction-v2-install-staging":
            replacements += 1
            if replacements == crash_after_target:
                raise KeyboardInterrupt("synthetic forecast import process death")
        return result

    with monkeypatch.context() as crash_patch:
        crash_patch.setattr(Path, "replace", crash_after_install)
        with pytest.raises(KeyboardInterrupt, match="process death"):
            governance._install_acceptance_targets(
                repository,
                records,
                plan_digest=plan_digest,
                expected_prior_evidence=prior_evidence,
            )

    expected_next = {
        path.relative_to(repository).as_posix(): governance._render_json_bytes(record)
        for path, record in records.items()
    }
    governance._recover_acceptance_transaction(
        repository,
        expected_plan_digest=plan_digest,
        expected_prior_evidence=prior_evidence,
        expected_next_payloads=expected_next,
    )
    assert not governance._acceptance_transaction_journal(repository).exists()
    for relative, prior in prior_payloads.items():
        assert (repository / relative).read_bytes() == prior


def test_forecast_decision_import_retries_completed_two_target_install(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository = tmp_path / "repository"
    governance_root = repository / "docs" / "governance" / "v1"
    governance_root.mkdir(parents=True)
    plan_directory = repository / ".tmp/s1-acceptance/correction-v2-forecast-decision"
    plan_directory.mkdir(parents=True)
    for name in (
        "plan.json",
        "decision.claim",
        "decision.claim.sig",
        "verified-decision-import.json",
    ):
        (plan_directory / name).write_bytes(b"placeholder\n")
    plan_digest = _digest("d")
    ledger = {"ledger_digest": _digest("1"), "decision_evidence": {"verified": True}}
    forecast = {
        "record_digest": _digest("2"),
        "issued_at_utc": "2026-10-15T15:00:00Z",
        "valid_until_utc": "2026-11-14T15:00:00Z",
    }
    targets = {
        "docs/governance/v1/delivery-forecast.authoring-ledger.json": ledger,
        "docs/governance/v1/delivery-forecast.json": forecast,
    }
    for relative, record in targets.items():
        governance._write_json(repository / relative, record)
    plan = {
        "manifest": {"manifest_digest": _digest("3")},
        "source_files": [],
        "plan_digest": plan_digest,
    }
    monkeypatch.setattr(
        governance,
        "_corrective_private_acceptance_path",
        lambda *_args, **_kwargs: plan_directory,
    )
    monkeypatch.setattr(governance, "_read_forecast_v2_plan", lambda *_args, **_kwargs: plan)
    monkeypatch.setattr(
        governance,
        "_require_forecast_v2_plan_source_set",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        governance,
        "_acceptance_plan_target_prior_evidence",
        lambda *_args, **_kwargs: {relative: (1, _digest("4")) for relative in targets},
    )
    monkeypatch.setattr(
        governance,
        "_read_forecast_v2_import_artifact",
        lambda *_args, **_kwargs: ({}, targets),
    )
    monkeypatch.setattr(governance, "_recover_acceptance_transaction", lambda *_a, **_k: None)
    monkeypatch.setattr(
        governance,
        "_verify_plan_sources_after_target_install",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        governance,
        "_load_forecast_v2_workspace",
        lambda **_kwargs: (_minimal_snapshot(), {}, {}, {}, ledger, {}, _digest("5")),
    )
    monkeypatch.setattr(
        governance,
        "_install_acceptance_targets",
        lambda *_args, **_kwargs: pytest.fail("completed decision import was reinstalled"),
    )

    assert (
        governance.forecast_v2_decision_import.__wrapped__(
            Namespace(
                repository_root=str(repository),
                governance_dir=str(governance_root),
                roadmap=str(repository / "Agent_Assure_Implementation_Roadmap.md"),
                plan_dir=str(plan_directory),
                expected_plan_digest=plan_digest,
            )
        )
        == 0
    )
    output = json.loads(capsys.readouterr().out)
    assert output["idempotent_recovery"] is True


def test_forecast_signature_import_retries_completed_single_target_install(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository = tmp_path / "repository"
    governance_root = repository / "docs" / "governance" / "v1"
    governance_root.mkdir(parents=True)
    plan_directory = repository / ".tmp/s1-acceptance/correction-v2-forecast-final"
    plan_directory.mkdir(parents=True)
    for name in (
        "plan.json",
        "producer.claim",
        "producer.claim.sig",
        "acceptance-receipt.claim",
        "acceptance-receipt.claim.sig",
        "verified-final-signature-import.json",
    ):
        (plan_directory / name).write_bytes(b"placeholder\n")
    plan_digest = _digest("d")
    verification = {
        "import_verification_started_at_utc": "2026-10-15T15:01:00Z",
        "import_verification_completed_at_utc": "2026-10-15T15:02:00Z",
    }
    candidate = {
        "record_digest": _digest("1"),
        "signature_envelope": {"verification_evidence": verification},
        "acceptance_receipt": {"receipt_digest": _digest("2")},
    }
    target = governance_root / "delivery-forecast.json"
    governance._write_json(target, candidate)
    plan = {
        "time_evidence": {
            "claim_preparation_started_at_utc": "2026-10-15T15:00:00Z",
            "clock_basis": "maintainer_host_utc_externally_unattested",
            "sshsig_timestamp_capability": "none",
            "actual_signature_time_claimed": False,
            "import_verification_semantics": (
                "internally_captured_completion_observation_must_be_not_before_claim_"
                "preparation_start_and_within_forecast_validity"
            ),
        },
        "source_files": [],
        "plan_digest": plan_digest,
    }
    monkeypatch.setattr(
        governance,
        "_corrective_private_acceptance_path",
        lambda *_args, **_kwargs: plan_directory,
    )
    monkeypatch.setattr(governance, "_read_forecast_v2_plan", lambda *_args, **_kwargs: plan)
    monkeypatch.setattr(
        governance,
        "_require_forecast_v2_plan_source_set",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        governance,
        "_acceptance_plan_target_prior_evidence",
        lambda *_args, **_kwargs: {"docs/governance/v1/delivery-forecast.json": (1, _digest("3"))},
    )
    monkeypatch.setattr(
        governance,
        "_read_forecast_v2_import_artifact",
        lambda *_args, **_kwargs: (
            {},
            {"docs/governance/v1/delivery-forecast.json": candidate},
        ),
    )
    monkeypatch.setattr(governance, "_recover_acceptance_transaction", lambda *_a, **_k: None)
    monkeypatch.setattr(
        governance,
        "_verify_plan_sources_after_target_install",
        lambda *_args, **_kwargs: None,
    )
    decided_ledger = {"decision_evidence": {"verified": True}}
    monkeypatch.setattr(
        governance,
        "_load_forecast_v2_workspace",
        lambda **_kwargs: (
            _minimal_snapshot(),
            {},
            {},
            {},
            decided_ledger,
            {},
            _digest("4"),
        ),
    )
    monkeypatch.setattr(
        governance,
        "_install_acceptance_targets",
        lambda *_args, **_kwargs: pytest.fail("completed signature import was reinstalled"),
    )

    assert (
        governance.forecast_v2_signature_import.__wrapped__(
            Namespace(
                repository_root=str(repository),
                governance_dir=str(governance_root),
                roadmap=str(repository / "Agent_Assure_Implementation_Roadmap.md"),
                plan_dir=str(plan_directory),
                expected_plan_digest=plan_digest,
            )
        )
        == 0
    )
    output = json.loads(capsys.readouterr().out)
    assert output["idempotent_recovery"] is True


@pytest.mark.parametrize(
    "missing_name",
    [
        "maintainer-signing-key.json",
        "maintainer-signing-key.schema.json",
        "corrective-kickoff-authorization.json",
        "corrective-kickoff-authorization.schema.json",
        "baseline-observations.json",
        "baseline-observations.schema.json",
    ],
)
def test_forecast_v2_workspace_fails_closed_on_missing_trust_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    missing_name: str,
) -> None:
    repository = tmp_path / "repository"
    governance_root = repository / "docs" / "governance" / "v1"
    governance_root.mkdir(parents=True)
    roadmap = repository / "Agent_Assure_Implementation_Roadmap.md"
    observed_reads: list[str] = []

    def read_record(path: Path) -> dict[str, Any]:
        observed_reads.append(path.name)
        if path.name == missing_name:
            raise governance.GovernanceError(f"synthetic missing trust source: {path.name}")
        return {}

    monkeypatch.setattr(governance, "validate_local_only_roadmap", lambda *_args: None)
    monkeypatch.setattr(governance, "load_roadmap", lambda *_args: _minimal_snapshot())
    monkeypatch.setattr(governance, "_read_json", read_record)
    monkeypatch.setattr(
        governance, "validate_maintainer_signing_key", lambda *_args, **_kwargs: _digest("1")
    )
    monkeypatch.setattr(
        governance,
        "validate_corrective_kickoff_authorization",
        lambda *_args, **_kwargs: _digest("2"),
    )
    monkeypatch.setattr(
        governance, "validate_baseline_observations", lambda *_args, **_kwargs: _digest("3")
    )
    monkeypatch.setattr(
        governance,
        "_validate_corrective_authorization_precedes_baseline",
        lambda **_kwargs: None,
    )

    with pytest.raises(governance.GovernanceError, match="missing trust source"):
        governance._load_forecast_v2_workspace(
            repository_root=repository.resolve(),
            governance_root=governance_root.resolve(),
            roadmap_path=roadmap.resolve(),
            allow_pending=True,
        )

    assert observed_reads[-1] == missing_name
    assert "delivery-forecast.authoring-ledger.json" not in observed_reads


@pytest.mark.parametrize(
    ("mutation", "expected_error"),
    [
        ("signing-key", "maintainer signing key"),
        ("corrective-authorization", "corrective kickoff"),
        ("baseline", "baseline observations"),
    ],
)
def test_forecast_v2_workspace_rejects_tampered_trust_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    expected_error: str,
) -> None:
    repository = (tmp_path / "repository").resolve()
    governance_root = repository / "docs/governance/v1"
    governance_root.mkdir(parents=True)
    roadmap = repository / "Agent_Assure_Implementation_Roadmap.md"
    records = {
        name: _record(name)
        for name in (
            "maintainer-signing-key.json",
            "maintainer-signing-key.schema.json",
            "corrective-kickoff-authorization.json",
            "corrective-kickoff-authorization.schema.json",
            "baseline-observations.json",
            "baseline-observations.schema.json",
        )
    }
    snapshot = _minimal_snapshot(
        raw_digest=records["corrective-kickoff-authorization.json"]["signed_claim"]["evidence"][
            "roadmap_raw_sha256"
        ]
    )

    def read_record(path: Path) -> dict[str, Any]:
        record = copy.deepcopy(records[path.name])
        if mutation == "signing-key" and path.name == "maintainer-signing-key.json":
            record["public_key"] = "ssh-ed25519 tampered"
        elif (
            mutation == "corrective-authorization"
            and path.name == "corrective-kickoff-authorization.json"
        ):
            record["signed_claim"]["authorized_person_id"] = "tampered"
        elif mutation == "baseline" and path.name == "baseline-observations.json":
            record["format"] = "agent-assure-baseline-observations/tampered"
        return record

    monkeypatch.setattr(governance, "validate_local_only_roadmap", lambda *_args: None)
    monkeypatch.setattr(governance, "load_roadmap", lambda *_args: snapshot)
    monkeypatch.setattr(governance, "_read_json", read_record)
    monkeypatch.setattr(governance, "_verify_sshsig", lambda **_kwargs: None)

    with pytest.raises(governance.GovernanceError, match=expected_error):
        governance._load_forecast_v2_workspace(
            repository_root=repository,
            governance_root=governance_root.resolve(),
            roadmap_path=roadmap.resolve(),
            allow_pending=True,
        )


def test_forecast_v2_workspace_rejects_retroactive_corrective_authorization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    governance_root = repository / "docs" / "governance" / "v1"
    governance_root.mkdir(parents=True)
    roadmap = repository / "Agent_Assure_Implementation_Roadmap.md"
    records = {
        "maintainer-signing-key.json": {},
        "maintainer-signing-key.schema.json": {},
        "corrective-kickoff-authorization.json": {
            "import_verification": {"verification_recorded_at_utc": "2026-10-16T02:05:13.6734471Z"}
        },
        "corrective-kickoff-authorization.schema.json": {},
        "baseline-observations.json": {"inventory_started_at_utc": "2026-10-16T02:05:13.673447Z"},
        "baseline-observations.schema.json": {},
    }
    monkeypatch.setattr(governance, "validate_local_only_roadmap", lambda *_args: None)
    monkeypatch.setattr(governance, "load_roadmap", lambda *_args: _minimal_snapshot())
    monkeypatch.setattr(governance, "_read_json", lambda path: copy.deepcopy(records[path.name]))
    monkeypatch.setattr(
        governance, "validate_maintainer_signing_key", lambda *_args, **_kwargs: _digest("1")
    )
    monkeypatch.setattr(
        governance,
        "validate_corrective_kickoff_authorization",
        lambda *_args, **_kwargs: _digest("2"),
    )
    monkeypatch.setattr(
        governance, "validate_baseline_observations", lambda *_args, **_kwargs: _digest("3")
    )

    with pytest.raises(
        governance.GovernanceError,
        match="baseline inventory predates corrective authorization verification",
    ):
        governance._load_forecast_v2_workspace(
            repository_root=repository.resolve(),
            governance_root=governance_root.resolve(),
            roadmap_path=roadmap.resolve(),
            allow_pending=True,
        )


def test_forecast_v2_workspace_validates_trust_basis_before_ledger_and_roster_is_final(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    governance_root = repository / "docs" / "governance" / "v1"
    governance_root.mkdir(parents=True)
    roadmap = repository / "Agent_Assure_Implementation_Roadmap.md"
    reads: list[str] = []
    roster_options: list[bool] = []

    def read_record(path: Path) -> dict[str, Any]:
        reads.append(path.name)
        return {}

    def validate_roster(*_args: Any, **kwargs: Any) -> tuple[str, str]:
        roster_options.append(kwargs["allow_pending"])
        return _digest("4"), "acblabs"

    monkeypatch.setattr(governance, "validate_local_only_roadmap", lambda *_args: None)
    monkeypatch.setattr(governance, "load_roadmap", lambda *_args: _minimal_snapshot())
    monkeypatch.setattr(governance, "_read_json", read_record)
    monkeypatch.setattr(
        governance, "validate_maintainer_signing_key", lambda *_args, **_kwargs: _digest("1")
    )
    monkeypatch.setattr(
        governance,
        "validate_corrective_kickoff_authorization",
        lambda *_args, **_kwargs: _digest("2"),
    )
    monkeypatch.setattr(
        governance, "validate_baseline_observations", lambda *_args, **_kwargs: _digest("3")
    )
    monkeypatch.setattr(
        governance,
        "_validate_corrective_authorization_precedes_baseline",
        lambda **_kwargs: None,
    )
    monkeypatch.setattr(governance, "validate_estimation_catalog_v2", lambda *_args: None)
    monkeypatch.setattr(governance, "_validate_json_schema", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(governance, "_resolve_aggregation_method_v2", lambda *_args: {})
    monkeypatch.setattr(governance, "validate_authoring_ledger_v2", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(governance, "validate_approval_roster", validate_roster)
    monkeypatch.setattr(governance, "validate_forecast_v2", lambda *_args, **_kwargs: None)

    governance._load_forecast_v2_workspace(
        repository_root=repository.resolve(),
        governance_root=governance_root.resolve(),
        roadmap_path=roadmap.resolve(),
        allow_pending=True,
    )

    assert roster_options == [False]
    assert reads.index("maintainer-signing-key.json") < reads.index(
        "delivery-forecast.authoring-ledger.json"
    )
    assert reads.index("corrective-kickoff-authorization.schema.json") < reads.index(
        "delivery-forecast.authoring-ledger.json"
    )
    assert reads.index("baseline-observations.schema.json") < reads.index(
        "delivery-forecast.authoring-ledger.json"
    )


def test_forecast_v2_source_set_is_exhaustive_and_byte_bound(tmp_path: Path) -> None:
    repository = (tmp_path / "repository").resolve()
    governance_root = repository / "docs/governance/v1"
    governance_root.mkdir(parents=True)
    roadmap = repository / "Agent_Assure_Implementation_Roadmap.md"
    roadmap.write_bytes(b"synthetic private roadmap contract\n")
    for name in governance._FORECAST_V2_GOVERNANCE_SOURCE_NAMES:
        (governance_root / name).write_bytes(b"{}\n")

    paths = governance._forecast_v2_source_paths(repository, governance_root, roadmap)
    relative_paths = [path.resolve().relative_to(repository).as_posix() for path in paths]
    assert relative_paths == [
        "Agent_Assure_Implementation_Roadmap.md",
        *[f"docs/governance/v1/{name}" for name in governance._FORECAST_V2_GOVERNANCE_SOURCE_NAMES],
    ]
    plan = {"source_files": [governance._source_file_evidence(repository, path) for path in paths]}
    governance._verify_forecast_v2_plan_sources(repository, plan, expected_paths=paths)

    tampered = copy.deepcopy(plan)
    tampered["source_files"][0]["sha256"] = _digest("0")
    with pytest.raises(governance.GovernanceError, match="source file changed"):
        governance._verify_forecast_v2_plan_sources(
            repository,
            tampered,
            expected_paths=paths,
        )


@pytest.mark.parametrize("mutation", ["omission", "substitution", "duplicate"])
def test_forecast_v2_source_set_rejects_inexact_membership(mutation: str) -> None:
    paths = governance._forecast_v2_source_paths(ROOT, GOVERNANCE_ROOT, ROADMAP)
    source_files = [{"path": path.resolve().relative_to(ROOT).as_posix()} for path in paths]
    if mutation == "omission":
        source_files.pop()
    elif mutation == "substitution":
        source_files[-1] = {"path": "pyproject.toml"}
    else:
        source_files.append(copy.deepcopy(source_files[-1]))

    with pytest.raises(governance.GovernanceError, match="source"):
        governance._require_forecast_v2_plan_source_set(
            ROOT,
            {"source_files": source_files},
            expected_paths=paths,
        )


@pytest.mark.parametrize(
    ("handler_name", "plan_names"),
    [
        (
            "forecast_v2_decision_import",
            {"plan.json", "decision.claim", "decision.claim.sig"},
        ),
        (
            "forecast_v2_signature_import",
            {
                "plan.json",
                "producer.claim",
                "producer.claim.sig",
                "acceptance-receipt.claim",
                "acceptance-receipt.claim.sig",
            },
        ),
    ],
)
def test_forecast_v2_imports_reject_source_substitution_before_import(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    handler_name: str,
    plan_names: set[str],
) -> None:
    repository = tmp_path / "repository"
    governance_root = repository / "docs" / "governance" / "v1"
    governance_root.mkdir(parents=True)
    roadmap = repository / "Agent_Assure_Implementation_Roadmap.md"
    plan_directory = repository / ".tmp/s1-acceptance/correction-v2-forecast-source-test"
    plan_directory.mkdir(parents=True)
    for name in plan_names:
        (plan_directory / name).write_bytes(b"placeholder\n")
    expected_paths = governance._forecast_v2_source_paths(
        repository,
        governance_root,
        roadmap,
    )
    source_files = [
        {"path": path.resolve().relative_to(repository).as_posix()} for path in expected_paths
    ]
    source_files[-1] = {"path": "pyproject.toml"}
    monkeypatch.setattr(
        governance,
        "_corrective_private_acceptance_path",
        lambda *_args, **_kwargs: plan_directory,
    )
    monkeypatch.setattr(
        governance,
        "_read_forecast_v2_plan",
        lambda *_args, **_kwargs: {"source_files": source_files},
    )

    with pytest.raises(governance.GovernanceError, match="source set is not exact"):
        getattr(governance, handler_name).__wrapped__(
            Namespace(
                repository_root=str(repository),
                governance_dir=str(governance_root),
                roadmap=str(roadmap),
                plan_dir=str(plan_directory),
                expected_plan_digest=_digest("1"),
            )
        )


def test_corrective_v2_sources_include_complete_forecast_trust_basis() -> None:
    forecast_paths = {
        path.resolve().relative_to(ROOT).as_posix()
        for path in governance._forecast_v2_source_paths(ROOT, GOVERNANCE_ROOT, ROADMAP)
    }
    corrective_paths = {
        path.resolve().relative_to(ROOT).as_posix()
        for path in governance._corrective_v2_source_paths(ROOT, ROADMAP)
    }
    assert forecast_paths <= corrective_paths
    assert {
        "docs/governance/v1/approval-roster.json",
        "docs/governance/v1/approval-roster.schema.json",
        "docs/governance/v1/maintainer-signing-key.json",
        "docs/governance/v1/maintainer-signing-key.schema.json",
    } <= corrective_paths

    private_input = ROOT / ".tmp" / "s1-acceptance" / "correction-v2-synthetic-input.json"
    source_files = [{"path": path} for path in sorted(corrective_paths)]
    source_files.append({"path": private_input.resolve().relative_to(ROOT).as_posix()})
    governance._require_corrective_v2_plan_source_set(
        ROOT,
        ROADMAP,
        {"source_files": source_files},
        expected_private_extra_count=1,
    )

    substituted = copy.deepcopy(source_files)
    substituted[0] = {"path": "pyproject.toml"}
    with pytest.raises(governance.GovernanceError, match="source set is not exact"):
        governance._require_corrective_v2_plan_source_set(
            ROOT,
            ROADMAP,
            {"source_files": substituted},
            expected_private_extra_count=1,
        )


def test_forecast_v2_final_documentation_requires_exact_accepted_digests(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    readme = repository / "docs" / "governance" / "v1" / "README.md"
    adr = repository / "docs" / "adr" / "0016-v1-repository-map.md"
    readme.parent.mkdir(parents=True)
    adr.parent.mkdir(parents=True)
    ledger = {"decision_evidence": {"verified": True}, "ledger_digest": _digest("1")}
    forecast = {"forecast_status": "accepted", "record_digest": _digest("2")}
    exact = governance._forecast_v2_final_documentation_block(ledger, forecast)
    readme.write_text(f"before\n{exact}\nafter\n", encoding="utf-8")
    adr.write_text(f"before\n{exact}\nafter\n", encoding="utf-8")

    governance._validate_forecast_v2_final_documentation(
        repository,
        ledger=ledger,
        forecast=forecast,
    )

    pending = exact.replace("human_decisions_imported", "pending_human_decision")
    adr.write_text(f"before\n{pending}\nafter\n", encoding="utf-8")
    with pytest.raises(governance.GovernanceError, match="not documented exactly"):
        governance._validate_forecast_v2_final_documentation(
            repository,
            ledger=ledger,
            forecast=forecast,
        )


def test_forecast_v2_documentation_check_is_a_pre_r2_dynamic_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository = tmp_path / "repository"
    governance_root = repository / "docs" / "governance" / "v1"
    readme = governance_root / "README.md"
    adr = repository / "docs" / "adr" / "0016-v1-repository-map.md"
    readme.parent.mkdir(parents=True)
    adr.parent.mkdir(parents=True)
    ledger = {"decision_evidence": {"verified": True}, "ledger_digest": _digest("3")}
    forecast = {"forecast_status": "accepted", "record_digest": _digest("4")}
    exact = governance._forecast_v2_final_documentation_block(ledger, forecast)
    readme.write_text(exact + "\n", encoding="utf-8")
    adr.write_text(exact + "\n", encoding="utf-8")
    validation_options: list[bool] = []
    monkeypatch.setattr(
        governance,
        "_load_forecast_v2_workspace",
        lambda **_kwargs: (_minimal_snapshot(), {}, {}, {}, ledger, {}, _digest("5")),
    )
    monkeypatch.setattr(
        governance,
        "_read_json",
        lambda path: forecast if path.name == "delivery-forecast.json" else {},
    )

    def validate_forecast(*_args: Any, **kwargs: Any) -> None:
        validation_options.append(kwargs["allow_pending"])

    monkeypatch.setattr(governance, "validate_forecast_v2", validate_forecast)
    args = Namespace(
        repository_root=str(repository),
        governance_dir=str(governance_root),
        roadmap=str(repository / "Agent_Assure_Implementation_Roadmap.md"),
    )
    assert governance.forecast_v2_documentation_check.__wrapped__(args) == 0
    assert validation_options == [False]
    assert json.loads(capsys.readouterr().out)["result"] == ("valid_final_forecast_documentation")

    adr.write_text(
        exact.replace("accepted", "proposed_pending_explicit_human_review") + "\n",
        encoding="utf-8",
    )
    with pytest.raises(governance.GovernanceError, match="not documented exactly"):
        governance.forecast_v2_documentation_check.__wrapped__(args)


def test_generation_2_operator_ceremony_is_absolute_ordered_and_fail_closed() -> None:
    documentation = (GOVERNANCE_ROOT / "README.md").read_text(encoding="utf-8")
    ceremony = documentation.split("### Absolute-path generation-2 operator ceremony", maxsplit=1)[
        1
    ].split("## Decision authority and limits", maxsplit=1)[0]
    assert "$RepositoryRoot = 'C:\\Users\\user\\.antigravity-ide\\agent-assure'" in ceremony
    assert "$PrivateKey = '<ABSOLUTE_PRIVATE_KEY_PATH>'" in ceremony
    assert "-O 'hashalg=sha512' $ClaimPath" in ceremony
    assert "--expected-plan-digest $DecisionPlanDigest" in ceremony
    assert "--expected-plan-digest $ForecastPlanDigest" in ceremony
    assert "--expected-receipt-plan-digest $ReceiptPlanDigest" in ceremony
    assert "--expected-attestation-digest $AttestationDigest" in ceremony
    assert "diff --cached --name-status --no-renames" in ceremony
    assert "diff --name-status --no-renames" in ceremony
    assert "ls-files --others --exclude-standard" in ceremony
    assert "$HeadBeforeR2Commit -cne $C1" in ceremony
    assert "$HeadBeforeC2Commit -cne $R2" in ceremony
    assert "$GatePrepared.attestation_plan.attestation_digest -cne $AttestationDigest" in ceremony
    assert "$GatePrepared.attestation_digest" not in ceremony
    assert "does **not** authorize or run `git push`" in ceremony
    assert "same plan directory and same confirmed" in ceremony

    ordered_commands = [
        "Invoke-S1Governance acceptance-preflight",
        "Invoke-S1Governance forecast-v2-decision-plan",
        "Invoke-S1Governance forecast-v2-decision-import",
        "Invoke-S1Governance forecast-v2-signature-plan",
        "Invoke-S1Governance forecast-v2-signature-import",
        "Invoke-S1Governance forecast-v2-documentation-check",
        "commit -m 'Correct S1 governed baseline'",
        "Invoke-S1Governance corrective-v2-suite-capture",
        "Invoke-S1Governance corrective-v2-receipt-plan",
        "Invoke-S1Governance corrective-v2-receipt-import",
        "Invoke-S1Governance corrective-v2-bundle-plan",
        "Invoke-S1Governance corrective-v2-bundle-import",
        "commit -m 'Close corrected S1 governed baseline'",
        "Invoke-S1Governance check `",
        "Invoke-S1Governance acceptance-attestation-finalize",
        "tag --annotate",
    ]
    positions = [ceremony.index(command) for command in ordered_commands]
    assert positions == sorted(positions)

    parsed = governance._parser().parse_args(
        [
            "forecast-v2-documentation-check",
            "--roadmap",
            str(ROADMAP),
            "--governance-dir",
            str(GOVERNANCE_ROOT),
        ]
    )
    assert parsed.handler is governance.forecast_v2_documentation_check
