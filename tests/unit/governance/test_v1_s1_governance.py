from __future__ import annotations

import base64
import copy
import hashlib
import os
import shutil
import subprocess
import sys
from argparse import Namespace
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import scripts.v1_s1_governance as governance  # noqa: E402, I001


GOVERNANCE_ROOT = ROOT / "docs" / "governance" / "v1"
PERSON_ID = "H1"
ISSUED_AT = "2026-10-15T15:00:00Z"
INVENTORY_COMPLETED_AT = "2026-10-15T14:00:00Z"
VALID_UNTIL = "2026-11-14T15:00:00Z"


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


NON_WINDOWS_TEST_TOOL_IDENTITIES = _host_test_tool_identities() if os.name != "nt" else None


@pytest.fixture(autouse=True)
def _use_system_tools_for_non_windows_tests(monkeypatch: pytest.MonkeyPatch) -> None:
    """The accepted S1 host is Windows; CI exercises logic with attested POSIX tools."""

    if NON_WINDOWS_TEST_TOOL_IDENTITIES is not None:
        monkeypatch.setattr(
            governance,
            "TRUSTED_EXECUTABLE_IDENTITIES",
            NON_WINDOWS_TEST_TOOL_IDENTITIES,
        )


def _digest(byte: str) -> str:
    return f"sha256:{byte * 64}"


def _minimal_snapshot() -> governance.RoadmapSnapshot:
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
        raw_digest=_digest("1"),
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
            _schema("delivery-forecast.schema.json"),
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
            _schema("delivery-forecast.schema.json"),
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
    forecast = _record("delivery-forecast.json")
    forecast["forecast_status"] = "accepted"
    _set_pending_signature(forecast["signature_envelope"])
    _set_pending_signature(forecast["acceptance_receipt"]["signature_envelope"])

    with pytest.raises(governance.GovernanceError, match="schema validation failed"):
        governance._validate_json_schema(
            forecast,
            _schema("delivery-forecast.schema.json"),
            owner="delivery forecast",
        )


def test_forecast_schema_rejects_accepting_receipt_with_pending_signature() -> None:
    forecast = _record("delivery-forecast.json")
    forecast["acceptance_receipt"]["receipt_status"] = "accepted_for_development"
    _set_pending_signature(forecast["acceptance_receipt"]["signature_envelope"])

    with pytest.raises(governance.GovernanceError, match="schema validation failed"):
        governance._validate_json_schema(
            forecast,
            _schema("delivery-forecast.schema.json"),
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
    forecast = _record("delivery-forecast.json")
    _set_pending_signature(forecast["signature_envelope"])
    forecast["signature_envelope"]["signature"] = "ZmFrZQ=="

    with pytest.raises(governance.GovernanceError, match="schema validation failed"):
        governance._validate_json_schema(
            forecast,
            _schema("delivery-forecast.schema.json"),
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
    tampered["environment"]["trusted_executables"][0]["sha256"] = _digest("0")
    tampered["observations_digest"] = governance.domain_digest(
        governance.BASELINE_OBSERVATIONS_DOMAIN,
        governance._record_projection(tampered, "observations_digest"),
    )
    with pytest.raises(governance.GovernanceError, match="trusted executable identity changed"):
        governance.validate_baseline_observations(
            snapshot,
            tampered,
            _schema("baseline-observations.schema.json"),
            repository_root=ROOT,
        )


def test_governance_schemas_use_only_the_closed_canonical_format_set() -> None:
    schemas = [_schema(path.name) for path in sorted(GOVERNANCE_ROOT.glob("*.schema.json"))]

    assert set().union(*(governance._schema_declared_formats(schema) for schema in schemas)) == {
        "date-time",
        "uri",
    }

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

    unsupported_schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "string",
        "format": "email",
    }
    with pytest.raises(governance.GovernanceError, match="unsupported formats: email"):
        governance._closed_schema_format_checker(unsupported_schema)

    external_reference_schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": "file:///untrusted/external.schema.json",
    }
    with pytest.raises(governance.GovernanceError, match="nonlocal references"):
        governance._validate_json_schema({}, external_reference_schema, owner="adversarial")


@dataclass(frozen=True)
class SshKey:
    private_key: Path
    public_key: str
    fingerprint: str


def _generate_key(executable: str, root: Path, name: str) -> SshKey:
    private_key = root / name
    completed = subprocess.run(
        [executable, "-q", "-t", "ed25519", "-N", "", "-f", str(private_key)],
        capture_output=True,
        check=False,
        timeout=10,
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
    completed = subprocess.run(
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
        ],
        capture_output=True,
        check=False,
        timeout=10,
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
        [executable, "-C", str(repository), *arguments],
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
    (repository / "artifact.txt").write_text("reviewed\n", encoding="utf-8")
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


def _protect_local_roadmap(repository: Path) -> Path:
    roadmap = repository / "Agent_Assure_Implementation_Roadmap.md"
    exclude = repository / ".git" / "info" / "exclude"
    exclude.write_text("Agent_Assure_Implementation_Roadmap.md\n", encoding="utf-8")
    roadmap.write_text("private roadmap\n", encoding="utf-8")
    return roadmap


def test_local_only_roadmap_requires_local_exclusion_and_an_untracked_index(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    _initialize_git_repository(repository)
    (repository / "README.md").write_text("repository\n", encoding="utf-8")
    _commit_all(repository, "base")
    roadmap = _protect_local_roadmap(repository)

    assert governance.validate_local_only_roadmap(repository, roadmap) == roadmap.name

    _git(repository, "add", "--force", roadmap.name)
    with pytest.raises(governance.GovernanceError, match="tracked or staged"):
        governance.validate_local_only_roadmap(repository, roadmap)


def test_local_only_roadmap_rejects_reachable_history(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    _initialize_git_repository(repository)
    roadmap = repository / "Agent_Assure_Implementation_Roadmap.md"
    roadmap.write_text("historical roadmap\n", encoding="utf-8")
    _git(repository, "add", "--force", roadmap.name)
    _git(repository, "commit", "--quiet", "--message", "mistaken roadmap commit")
    roadmap.unlink()
    _commit_all(repository, "remove roadmap")
    roadmap = _protect_local_roadmap(repository)

    with pytest.raises(governance.GovernanceError, match="reachable local Git history"):
        governance.validate_local_only_roadmap(repository, roadmap)


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
        "kickoff-authorization-v1-base-01.json": {"authorization_digest": _digest("a")},
        "kickoff-authorization-v1-boot-01.json": {"authorization_digest": _digest("b")},
        "delivery-forecast.aggregation-registry.json": {},
        "delivery-forecast.aggregation-registry.schema.json": {},
        "delivery-forecast.authoring-ledger.json": {},
        "delivery-forecast.authoring-ledger.schema.json": {},
        "delivery-forecast.json": {
            "forecast_status": "proposed",
            "record_digest": _digest("c"),
        },
        "delivery-forecast.schema.json": {},
        "ticket-completion-receipt.schema.json": {},
        "completion-receipt-v1-base-01.json": {},
        "completion-receipt-v1-boot-01.json": {},
        "governance-bundle.json": {
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

    exit_code = governance.check(
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
        governance.acceptance_import(
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
        governance.acceptance_import(
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
    completed = subprocess.run(
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
        ],
        capture_output=True,
        check=False,
        timeout=10,
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
        governance.check(
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


def test_check_historical_requires_an_explicit_closure_commit(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    governance_root = repository / "docs" / "governance" / "v1"

    with pytest.raises(
        governance.GovernanceError,
        match="--historical requires --closure-commit",
    ):
        governance.check(
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
        governance.check(
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
    signed = subprocess.run(
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
        ],
        capture_output=True,
        check=False,
        timeout=10,
    )
    assert signed.returncode == 0, signed.stderr.decode("utf-8", errors="replace")
    assert (
        governance.acceptance_attestation_finalize(
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


def test_historical_check_requires_the_signed_acceptance_tag_object(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    governance_root = repository / "docs" / "governance" / "v1"

    with pytest.raises(
        governance.GovernanceError,
        match="--historical requires --acceptance-tag-object",
    ):
        governance.check(
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
    assert '--commitment-time "$(V1_GOVERNANCE_COMMITMENT_TIME)"' in nonaccepting


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
        governance.acceptance_result_paths(Namespace(repository_root=str(repository)))


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
    stage.write_bytes(next_payload)
    target_relative = target.relative_to(repository).as_posix()
    journal_path = governance._acceptance_transaction_journal(repository)
    journal_path.parent.mkdir(parents=True)
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
    journal_path.parent.mkdir(parents=True)
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
    stage.write_bytes(next_payload)
    target_relative = target.relative_to(repository).as_posix()
    journal_path = governance._acceptance_transaction_journal(repository)
    journal_path.parent.mkdir(parents=True)
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
    journal_path.parent.mkdir(parents=True)
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
    stage.write_bytes(next_payload)
    target_relative = target.relative_to(repository).as_posix()
    journal_path = governance._acceptance_transaction_journal(repository)
    journal_path.parent.mkdir(parents=True)
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
