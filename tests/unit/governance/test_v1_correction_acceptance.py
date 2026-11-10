"""Correction composition tests use an explicit synthetic signature boundary.

Real SSHSIG cryptography and malformed-envelope cases are qualified separately
by test_v1_successor_io. The callback here accepts an independently held exact
payload set, allowing these tests to target role, scope, aggregation and time.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import shutil
import subprocess
import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import v1_correction_acceptance as correction  # noqa: E402
from scripts import v1_s1_governance as legacy  # noqa: E402
from scripts import v1_successor_io as io  # noqa: E402

NOW = datetime(2026, 11, 9, 12, tzinfo=UTC)
DIGEST = "sha256:" + "a" * 64


def _string(value: bytes) -> bytes:
    return len(value).to_bytes(4, "big") + value


def _signature() -> tuple[str, str]:
    key_blob = _string(b"ssh-ed25519") + _string(bytes(range(32)))
    public_key = "ssh-ed25519 " + base64.b64encode(key_blob).decode("ascii")
    # Syntactically valid, deliberately noncryptographic test-only SSHSIG.
    signature = _string(b"ssh-ed25519") + _string(bytes(64))
    fields = (key_blob, b"agent-assure-governance-v1", b"", b"sha512", signature)
    encoded = base64.b64encode(b"SSHSIG\0\0\0\1" + b"".join(_string(v) for v in fields)).decode()
    body = "\n".join(encoded[index : index + 70] for index in range(0, len(encoded), 70))
    armor = "-----BEGIN SSH SIGNATURE-----\n" + body + "\n-----END SSH SIGNATURE-----\n"
    return public_key, base64.b64encode(armor.encode("ascii")).decode("ascii")


def _claims() -> dict[str, dict[str, Any]]:
    claims = {
        claim_id: {
            "format": correction.CLAIM_FORMAT,
            "claim_id": claim_id,
            "purpose": spec.purpose,
            "issuer_role": spec.role,
            "subject_digest": "sha256:" + str(index + 1) * 64,
            "predecessor_bundle_digest": DIGEST,
            "roadmap_digest": "sha256:" + "b" * 64,
            "correction_package_digest": "sha256:" + "c" * 64,
            "issued_at_utc": "2026-11-09T11:00:00Z",
            "valid_until_utc": "2026-11-11T00:00:00Z",
            "independence": "NO_INDEPENDENT_REVIEW",
            "authorization_effect": "development_governance_only",
        }
        for index, (claim_id, spec) in enumerate(correction.CLAIM_SPECS.items())
    }
    claims["correction_close"]["subject_digest"] = correction.closure_subject_digest(
        {key: value for key, value in claims.items() if key != "correction_close"}
    )
    return claims


def _inputs() -> tuple[dict[str, Any], dict[str, Any], dict[str, io.TrustedKey], Any, list[bytes]]:
    public_key, signature = _signature()
    claims = _claims()
    roles = {spec.role for spec in correction.CLAIM_SPECS.values()}
    authorities = {
        role: io.TrustedKey(
            io.public_key_fingerprint(public_key),
            "test-maintainer",
            public_key,
            role,
            tuple(
                spec.competence_scope
                for spec in correction.CLAIM_SPECS.values()
                if spec.role == role
            ),
            tuple(spec.purpose for spec in correction.CLAIM_SPECS.values() if spec.role == role),
            DIGEST,
            "2026-11-08T00:00:00Z",
            "2026-11-12T00:00:00Z",
        )
        for role in roles
    }
    # Duplicate competence labels are not a valid adopted snapshot.
    authorities = {
        role: replace(key, competence_scopes=tuple(sorted(set(key.competence_scopes))))
        for role, key in authorities.items()
    }
    documents = {
        claim_id: {
            "claim": copy.deepcopy(claim),
            "signature_envelope": {
                "profile": "openssh-sshsig-ed25519/v1",
                "namespace": "agent-assure-governance-v1",
                "signer_person_id": "test-maintainer",
                "key_id": io.public_key_fingerprint(public_key),
                "signature": signature,
            },
        }
        for claim_id, claim in claims.items()
    }
    permitted = {correction.claim_bytes(claim) for claim in claims.values()}
    verified: list[bytes] = []

    def verifier(**arguments: Any) -> None:
        if arguments["payload"] not in permitted:
            raise io.SuccessorIOError("synthetic exact-payload verification failed")
        assert arguments["signer_person_id"] == "test-maintainer"
        assert arguments["public_key"] == public_key
        verified.append(arguments["payload"])

    return documents, claims, authorities, verifier, verified


def _verify(inputs: tuple[Any, ...], **changes: Any) -> correction.AcceptedCorrection:
    documents, claims, authorities, verifier, _ = inputs
    return correction.verify_correction_acceptance(
        changes.pop("documents", documents),
        changes.pop("expected_claims", claims),
        changes.pop("authorities", authorities),
        changes.pop("verify_signature", verifier),
        now=changes.pop("now", lambda: NOW),
        prerequisite_valid_until_utc=changes.pop(
            "prerequisite_valid_until_utc", "2026-11-12T00:00:00Z"
        ),
        **changes,
    )


def test_complete_exact_decisions_accept_only_scoped_correction() -> None:
    inputs = _inputs()
    result = _verify(inputs)
    assert len(result.claim_digests) == len(inputs[4]) == 6
    assert result.valid_until_utc == "2026-11-11T00:00:00Z"
    assert result.accepted_at_utc == "2026-11-09T12:00:00Z"
    assert set(dict(result.authority_snapshot_digests)) == set(inputs[2])


@pytest.mark.parametrize("mutation", ["missing", "extra", "success_flag", "claim_tamper"])
def test_submitted_documents_cannot_select_scope_or_success(mutation: str) -> None:
    inputs = _inputs()
    documents = inputs[0]
    if mutation == "missing":
        del documents["support_policy"]
    elif mutation == "extra":
        documents["unknown"] = documents["foundation_adoption"]
    elif mutation == "success_flag":
        documents["support_policy"]["passed"] = True
    else:
        documents["support_policy"]["claim"]["subject_digest"] = "sha256:" + "f" * 64
    with pytest.raises(correction.CorrectionError):
        _verify(inputs)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("purpose", "s2-bundle/v1"),
        ("issuer_role", "technical_lead"),
        ("subject_digest", "sha256:abc"),
        ("authorization_effect", "runtime_authorization"),
        ("independence", "INDEPENDENT_REVIEW"),
        ("issued_at_utc", "2026-11-10T00:00:00Z"),
        ("valid_until_utc", "2026-12-15T00:00:00Z"),
    ],
)
def test_even_reviewed_claims_must_meet_closed_correction_contract(field: str, value: str) -> None:
    inputs = _inputs()
    inputs[1]["support_policy"][field] = value
    with pytest.raises(correction.CorrectionError):
        _verify(inputs)


def test_aggregate_binds_all_exact_prerequisite_claims() -> None:
    inputs = _inputs()
    inputs[1]["forecast_producer"]["subject_digest"] = "sha256:" + "f" * 64
    with pytest.raises(correction.CorrectionError, match="aggregate"):
        _verify(inputs)


@pytest.mark.parametrize("mutation", ["role", "scope", "purpose", "person", "extra_role"])
def test_claim_and_envelope_cannot_supply_missing_external_authority(mutation: str) -> None:
    inputs = _inputs()
    authorities = inputs[2]
    key = authorities["release_policy_owner"]
    if mutation == "role":
        authorities["release_policy_owner"] = replace(key, role="repository_maintainer")
    elif mutation == "scope":
        authorities["release_policy_owner"] = replace(
            key, competence_scopes=("schema_compatibility",)
        )
    elif mutation == "purpose":
        authorities["release_policy_owner"] = replace(key, allowed_purposes=("s2-bundle/v1",))
    elif mutation == "person":
        inputs[0]["support_policy"]["signature_envelope"]["signer_person_id"] = "candidate"
    else:
        authorities["candidate"] = key
    with pytest.raises(correction.CorrectionError):
        _verify(inputs)


@pytest.mark.parametrize("position", ["start", "during", "after"])
def test_half_open_expiry_applies_through_entire_verification(position: str) -> None:
    inputs = _inputs()
    expiry = datetime(2026, 11, 11, tzinfo=UTC)
    calls = 0
    expire_at = {"start": 1, "during": 8, "after": 14}[position]

    def clock() -> datetime:
        nonlocal calls
        calls += 1
        return expiry if calls >= expire_at else expiry - timedelta(microseconds=1)

    with pytest.raises(correction.CorrectionError, match="expired|future"):
        _verify(inputs, now=clock)


def test_clock_regression_cannot_extend_acceptance() -> None:
    inputs = _inputs()
    values = iter([NOW, NOW, NOW - timedelta(microseconds=1)])
    with pytest.raises(correction.CorrectionError, match="regressed"):
        _verify(inputs, now=lambda: next(values))


def test_new_correction_cannot_extend_predecessor_freshness() -> None:
    with pytest.raises(correction.CorrectionError, match="prerequisites"):
        _verify(_inputs(), prerequisite_valid_until_utc="2026-11-10T00:00:00Z")


@pytest.mark.parametrize("mode", ["false_flag", "raise"])
def test_signature_boundary_must_authenticate_and_raise_on_failure(mode: str) -> None:
    def verifier(**arguments: Any) -> Any:
        if mode == "raise":
            raise io.SuccessorIOError("authentication failed")
        return False

    with pytest.raises(correction.CorrectionError):
        _verify(_inputs(), verify_signature=verifier)


def test_mixed_package_cannot_be_accepted_by_aggregate_signature() -> None:
    inputs = _inputs()
    inputs[1]["foundation_adoption"]["correction_package_digest"] = "sha256:" + "d" * 64
    with pytest.raises(correction.CorrectionError, match="mixed correction"):
        _verify(inputs)


def test_real_ephemeral_openssh_signatures_bind_all_correction_decisions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = shutil.which("ssh-keygen")
    if executable is None:
        pytest.skip("test host OpenSSH is unavailable")
    executable_path = Path(executable).resolve()
    executable_bytes = executable_path.read_bytes()
    monkeypatch.setattr(
        legacy,
        "TRUSTED_EXECUTABLE_IDENTITIES",
        {
            "ssh-keygen": legacy.TrustedExecutableIdentity(
                str(executable_path),
                len(executable_bytes),
                hashlib.sha256(executable_bytes).hexdigest(),
            )
        },
    )

    def openssh(arguments: list[str]) -> None:
        with legacy._isolated_openssh_environment() as environment:
            completed = subprocess.run(
                [str(executable_path), *arguments],
                cwd=tmp_path,
                env=environment,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=False,
                timeout=15,
            )
        assert completed.returncode == 0, repr(completed.stderr[:512])

    # This key is created inside pytest's fresh directory for this test only.
    private = tmp_path / "ephemeral-correction-test-key"
    openssh(["-t", "ed25519", "-N", "", "-C", "test-only", "-f", str(private)])
    public_key = " ".join(private.with_suffix(".pub").read_text().split()[:2])
    inputs = _inputs()
    documents, claims, authorities, _, _ = inputs
    authorities.update(
        {
            role: replace(key, public_key=public_key, key_id=io.public_key_fingerprint(public_key))
            for role, key in authorities.items()
        }
    )
    for claim_id, document in documents.items():
        subject = tmp_path / (claim_id + ".claim")
        subject.write_bytes(correction.claim_bytes(claims[claim_id]))
        openssh(
            [
                "-Y",
                "sign",
                "-f",
                str(private),
                "-n",
                "agent-assure-governance-v1",
                "-O",
                "hashalg=sha512",
                str(subject),
            ]
        )
        document["signature_envelope"].update(
            key_id=io.public_key_fingerprint(public_key),
            signature=base64.b64encode(Path(str(subject) + ".sig").read_bytes()).decode("ascii"),
        )
    accepted = _verify(inputs, verify_signature=legacy._verify_sshsig)
    assert len(accepted.claim_digests) == 6

    # Alter both the submitted and expected subject, and reconstruct a coherent
    # aggregate. Structural consistency alone must not preserve authenticity.
    claims["support_policy"]["subject_digest"] = "sha256:" + "e" * 64
    claims["correction_close"]["subject_digest"] = correction.closure_subject_digest(
        {key: value for key, value in claims.items() if key != "correction_close"}
    )
    documents["support_policy"]["claim"] = copy.deepcopy(claims["support_policy"])
    documents["correction_close"]["claim"] = copy.deepcopy(claims["correction_close"])
    with pytest.raises(ValueError, match="signature|verification|SSHSIG"):
        _verify(inputs, verify_signature=legacy._verify_sshsig)
