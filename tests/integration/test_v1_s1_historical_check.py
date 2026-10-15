from __future__ import annotations

import base64
import copy
import json
import os
import shutil
import subprocess
import sys
from argparse import Namespace
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import scripts.v1_s1_governance as governance  # noqa: E402, I001


@dataclass(frozen=True)
class SigningKey:
    private_key: Path
    public_key: str
    fingerprint: str


def _run(
    arguments: Sequence[str],
    *,
    cwd: Path,
    timeout: int = 30,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        list(arguments),
        cwd=cwd,
        capture_output=True,
        check=False,
        text=True,
        timeout=timeout,
    )
    if completed.returncode != 0:
        pytest.fail(
            f"command failed ({' '.join(arguments)}): {completed.stderr or completed.stdout}"
        )
    return completed


def _git(repository: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return _run(
        [governance._trusted_executable("git"), "-C", str(repository), *arguments],
        cwd=repository,
    )


def _commit_paths(repository: Path, message: str, paths: Sequence[str]) -> str:
    _git(repository, "add", "--", *paths)
    _git(repository, "commit", "--quiet", "--message", message, "--", *paths)
    return _git(repository, "rev-parse", "HEAD^{commit}").stdout.strip()


def _copy_file(source_root: Path, destination_root: Path, relative_path: str) -> None:
    destination = destination_root / relative_path
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source_root / relative_path, destination)


def _canonical_utc(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _generate_signing_key(repository: Path) -> SigningKey:
    ssh_keygen = governance._trusted_executable("ssh-keygen")
    private_key = repository / ".tmp" / "historical-check-signing-key"
    private_key.parent.mkdir(parents=True, exist_ok=True)
    _run(
        [
            ssh_keygen,
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "agent-assure-historical-check",
            "-f",
            str(private_key),
        ],
        cwd=repository,
    )
    public_parts = Path(f"{private_key}.pub").read_text(encoding="ascii").split()
    public_key = " ".join(public_parts[:2])
    return SigningKey(
        private_key=private_key,
        public_key=public_key,
        fingerprint=governance._public_key_fingerprint(public_key),
    )


def _sign_envelope(
    envelope: Mapping[str, Any],
    *,
    signed_at: str,
    signing_key: SigningKey,
    repository: Path,
    sequence: int,
) -> dict[str, Any]:
    signed = copy.deepcopy(dict(envelope))
    signed["status"] = "signed"
    signed["signed_at_utc"] = signed_at
    signed["signature"] = None
    claim = repository / ".tmp" / f"historical-check-claim-{sequence}.json"
    claim.write_bytes(governance._signature_claim_bytes(signed))
    _run(
        [
            governance._trusted_executable("ssh-keygen"),
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
        cwd=repository,
    )
    armor = governance._canonical_sshsig_armor(Path(f"{claim}.sig").read_bytes())
    signed["signature"] = base64.b64encode(armor).decode("ascii")
    return signed


def _write_json(repository: Path, relative_path: str, record: Mapping[str, Any]) -> None:
    governance._write_json(repository / relative_path, record)


def _accepted_roster() -> dict[str, Any]:
    roster = governance._read_json(ROOT / "docs/governance/v1/approval-roster.json")
    roster["selection_status"] = "approved"
    roster["limitations"] = [
        limitation
        for limitation in roster["limitations"]
        if limitation
        != "This roster is proposed until the named human signs the scoped kickoff authorizations"
    ]
    return roster


def _confirmed_signing_key(signing_key: SigningKey) -> dict[str, Any]:
    record = governance._read_json(ROOT / "docs/governance/v1/maintainer-signing-key.json")
    record.update(
        {
            "key_status": "confirmed_by_human",
            "public_key": signing_key.public_key,
            "public_key_fingerprint": signing_key.fingerprint,
            "out_of_band_confirmation_evidence": (
                "Ephemeral integration-test key generated and fingerprint-checked in-process."
            ),
        }
    )
    record["limitations"] = [
        limitation
        for limitation in record["limitations"]
        if limitation != "Pending explicit human affirmation of the displayed fingerprint"
    ]
    record["record_digest"] = governance.domain_digest(
        governance.SIGNING_KEY_DOMAIN,
        governance._record_projection(record, "record_digest"),
    )
    return record


def _repository_baseline(repository: Path) -> dict[str, Any]:
    baseline = governance._read_json(ROOT / "docs/governance/v1/baseline-observations.json")
    runtime = baseline["environment"]["trusted_python_runtime"]
    runtime["site_packages_path"] = str((repository / ".venv/Lib/site-packages").resolve())
    baseline["observations_digest"] = governance.domain_digest(
        governance.BASELINE_OBSERVATIONS_DOMAIN,
        governance._record_projection(baseline, "observations_digest"),
    )
    return baseline


def _bind_fixture_schemas_to_signing_key(
    repository: Path,
    *,
    signing_key: SigningKey,
) -> None:
    source_fingerprint = str(
        governance._read_json(ROOT / "docs/governance/v1/maintainer-signing-key.json")[
            "public_key_fingerprint"
        ]
    )
    for schema_path in (repository / "docs/governance/v1").glob("*.schema.json"):
        source = schema_path.read_text(encoding="utf-8")
        rendered = source.replace(source_fingerprint, signing_key.fingerprint)
        if rendered != source:
            schema_path.write_text(rendered, encoding="utf-8", newline="\n")


def _confirmed_ledger(
    snapshot: governance.RoadmapSnapshot,
    baseline: Mapping[str, Any],
    *,
    person_id: str,
    issued_at: str,
) -> dict[str, Any]:
    inventory_completed_at = str(baseline["inventory_completed_at_utc"])
    ledger = governance.build_authoring_ledger(
        snapshot,
        issued_at=issued_at,
        producer_person_id=person_id,
        baseline_observations_digest_value=str(baseline["observations_digest"]),
        inventory_completed_at=inventory_completed_at,
    )
    for row in ledger["rows"]:
        row["row_decision"] = "affirmatively_reconfirmed_after_inventory"
        row["row_confirmed_by_person_id"] = person_id
        row["row_confirmed_at_utc"] = inventory_completed_at
        for proposal in row["execution_proposals"]:
            proposal["decision"] = "affirmatively_reconfirmed_after_inventory"
            proposal["confirmed_by_person_id"] = person_id
            proposal["confirmed_at_utc"] = inventory_completed_at
    ledger["ledger_digest"] = governance._ledger_digest(ledger)
    return ledger


def _live_repository_evidence(closure_commit: str) -> dict[str, Any]:
    return {
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


@pytest.mark.skipif(os.name != "nt", reason="the governed S1 toolchain is Windows-host-bound")
def test_historical_check_validates_the_full_signed_closure_after_a_descendant(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository = tmp_path / "repository"
    _run(
        [
            governance._trusted_executable("git"),
            "clone",
            "--quiet",
            "--no-local",
            "--no-checkout",
            str(ROOT),
            str(repository),
        ],
        cwd=tmp_path,
        timeout=60,
    )
    _git(
        repository,
        "checkout",
        "--quiet",
        "-B",
        governance.S1_BRANCH_NAME,
        governance.PINNED_BASE_COMMIT,
    )
    _git(repository, "config", "user.name", "Agent Assure Historical Check")
    _git(repository, "config", "user.email", "historical-check@example.invalid")
    _git(repository, "remote", "set-url", "origin", governance.APPROVED_ORIGIN_URL)

    exclude = repository / ".git/info/exclude"
    with exclude.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write("\nAgent_Assure_Implementation_Roadmap.md\n.tmp/\n")
    roadmap = repository / "Agent_Assure_Implementation_Roadmap.md"
    shutil.copyfile(ROOT / roadmap.name, roadmap)

    for relative_path, kind in governance._bundle_inventory_paths():
        if kind != "completion_receipt":
            _copy_file(ROOT, repository, relative_path)

    signing_key = _generate_signing_key(repository)
    _bind_fixture_schemas_to_signing_key(repository, signing_key=signing_key)
    monkeypatch.setattr(governance, "MAINTAINER_PUBLIC_KEY", signing_key.public_key)
    monkeypatch.setattr(
        governance,
        "MAINTAINER_KEY_FINGERPRINT",
        signing_key.fingerprint,
    )

    snapshot = governance.load_roadmap(roadmap)
    baseline = _repository_baseline(repository)
    inventory_time = governance._parse_utc(
        str(baseline["inventory_completed_at_utc"]),
        owner="test baseline inventory",
    )
    ledger_issued = _canonical_utc(inventory_time + timedelta(minutes=1))
    record_issued = _canonical_utc(inventory_time + timedelta(minutes=2))
    valid_until = _canonical_utc(inventory_time + timedelta(days=30))
    kickoff_signed = _canonical_utc(inventory_time + timedelta(minutes=3))
    forecast_signed = _canonical_utc(inventory_time + timedelta(minutes=4))
    forecast_accepted = _canonical_utc(inventory_time + timedelta(minutes=5))
    base_completed = _canonical_utc(inventory_time + timedelta(minutes=6))
    boot_completed = _canonical_utc(inventory_time + timedelta(minutes=7))
    bundle_signed = _canonical_utc(inventory_time + timedelta(minutes=8))
    gate_checked = _canonical_utc(inventory_time + timedelta(minutes=9))
    attestation_signed = _canonical_utc(inventory_time + timedelta(minutes=10))

    roster = _accepted_roster()
    person_id = str(roster["maintainer_person_id"])
    roster_digest = governance.approval_roster_digest(roster)
    key_record = _confirmed_signing_key(signing_key)
    ledger = _confirmed_ledger(
        snapshot,
        baseline,
        person_id=person_id,
        issued_at=ledger_issued,
    )
    registry = governance._read_json(
        repository / "docs/governance/v1/delivery-forecast.aggregation-registry.json"
    )
    kickoffs: dict[str, dict[str, Any]] = {}
    for sequence, ticket_id in enumerate(("V1-BASE-01", "V1-BOOT-01"), start=1):
        kickoff = governance.build_kickoff_authorization(
            snapshot,
            ticket_id=ticket_id,
            roster_digest=roster_digest,
            person_id=person_id,
            issued_at=record_issued,
            valid_until=valid_until,
            status="authorized",
        )
        kickoff["signature_envelope"] = _sign_envelope(
            kickoff["signature_envelope"],
            signed_at=kickoff_signed,
            signing_key=signing_key,
            repository=repository,
            sequence=sequence,
        )
        kickoffs[ticket_id] = kickoff

    forecast = governance.build_forecast(
        snapshot,
        ledger,
        registry,
        issued_at=record_issued,
        valid_until=valid_until,
        producer_person_id=person_id,
        approval_roster_digest_value=roster_digest,
        requested_status="accepted",
    )
    forecast["signature_envelope"] = _sign_envelope(
        forecast["signature_envelope"],
        signed_at=forecast_signed,
        signing_key=signing_key,
        repository=repository,
        sequence=3,
    )
    forecast_receipt = forecast["acceptance_receipt"]
    forecast_receipt["signature_envelope"] = _sign_envelope(
        forecast_receipt["signature_envelope"],
        signed_at=forecast_accepted,
        signing_key=signing_key,
        repository=repository,
        sequence=4,
    )

    governed_records: dict[str, Mapping[str, Any]] = {
        "docs/governance/v1/approval-roster.json": roster,
        "docs/governance/v1/baseline-observations.json": baseline,
        "docs/governance/v1/delivery-forecast.authoring-ledger.json": ledger,
        "docs/governance/v1/delivery-forecast.json": forecast,
        "docs/governance/v1/kickoff-authorization-v1-base-01.json": kickoffs["V1-BASE-01"],
        "docs/governance/v1/kickoff-authorization-v1-boot-01.json": kickoffs["V1-BOOT-01"],
        "docs/governance/v1/maintainer-signing-key.json": key_record,
    }
    for relative_path, record in governed_records.items():
        _write_json(repository, relative_path, record)

    result_paths = [
        path for path, kind in governance._bundle_inventory_paths() if kind != "completion_receipt"
    ]
    result_commit = _commit_paths(repository, "S1 reviewed result", result_paths)
    assert (
        _git(repository, "rev-parse", f"{result_commit}^").stdout.strip()
        == governance.PINNED_BASE_COMMIT
    )
    nonreceipt_inventory = governance._result_artifact_inventory(repository, result_commit)
    result_evidence = {str(item["path"]): item for item in nonreceipt_inventory}

    receipts: dict[str, dict[str, Any]] = {}
    for sequence, (ticket_id, signed_at) in enumerate(
        (("V1-BASE-01", base_completed), ("V1-BOOT-01", boot_completed)),
        start=5,
    ):
        report_path = f"docs/governance/v1/completion-report-{ticket_id.lower()}.md"
        evidence = [result_evidence[report_path]] + [
            result_evidence[path] for path, _kind in governance._completion_review_paths(ticket_id)
        ]
        receipt = governance.build_ticket_completion_receipt(
            snapshot,
            repository_root=repository,
            ticket_id=ticket_id,
            roster_digest=roster_digest,
            kickoff_authorization_digest=str(kickoffs[ticket_id]["authorization_digest"]),
            person_id=person_id,
            base_commit=governance.PINNED_BASE_COMMIT,
            result_commit=result_commit,
            issued_at=record_issued,
            valid_until=valid_until,
            status="accepted_for_development",
            artifact_evidence_override=evidence,
        )
        receipt["signature_envelope"] = _sign_envelope(
            receipt["signature_envelope"],
            signed_at=signed_at,
            signing_key=signing_key,
            repository=repository,
            sequence=sequence,
        )
        receipts[ticket_id] = receipt
        _write_json(
            repository,
            f"docs/governance/v1/completion-receipt-{ticket_id.lower()}.json",
            receipt,
        )

    inventory = list(nonreceipt_inventory)
    inventory.extend(
        governance._artifact_evidence(repository, path, kind=kind)
        for path, kind in governance._bundle_inventory_paths()
        if kind == "completion_receipt"
    )
    bundle = governance.build_governance_bundle(
        snapshot,
        repository_root=repository,
        roster=roster,
        kickoff_records=kickoffs,
        completion_receipts=receipts,
        forecast=forecast,
        signing_key=key_record,
        baseline_observations=baseline,
        person_id=person_id,
        base_commit=governance.PINNED_BASE_COMMIT,
        issued_at=record_issued,
        valid_until=valid_until,
        status="accepted_for_development",
        artifact_inventory_override=inventory,
    )
    bundle["signature_envelope"] = _sign_envelope(
        bundle["signature_envelope"],
        signed_at=bundle_signed,
        signing_key=signing_key,
        repository=repository,
        sequence=7,
    )
    bundle_path = "docs/governance/v1/governance-bundle.json"
    _write_json(repository, bundle_path, bundle)

    closure_paths = [
        "docs/governance/v1/completion-receipt-v1-base-01.json",
        "docs/governance/v1/completion-receipt-v1-boot-01.json",
        bundle_path,
    ]
    closure_commit = _commit_paths(repository, "S1 accepted closure", closure_paths)
    assert _git(repository, "rev-parse", f"{closure_commit}^").stdout.strip() == result_commit

    attestation = governance.build_current_acceptance_attestation(
        snapshot,
        repository_root=repository,
        bundle=bundle,
        live_repository_evidence=_live_repository_evidence(closure_commit),
        gate_checked_at=gate_checked,
        signature_requested_at=attestation_signed,
        signer_person_id=person_id,
    )
    attestation["signature_envelope"] = _sign_envelope(
        attestation["signature_envelope"],
        signed_at=attestation_signed,
        signing_key=signing_key,
        repository=repository,
        sequence=8,
    )
    tag_message = repository / ".tmp" / "historical-check-attestation.json"
    tag_message.write_bytes(governance._render_acceptance_attestation_bytes(attestation))
    _git(
        repository,
        "-c",
        "tag.gpgSign=false",
        "tag",
        "--annotate",
        "--cleanup=verbatim",
        f"--file={tag_message}",
        governance.S1_ACCEPTANCE_TAG_NAME,
        closure_commit,
    )
    tag_object = _git(
        repository,
        "rev-parse",
        f"refs/tags/{governance.S1_ACCEPTANCE_TAG_NAME}^{{tag}}",
    ).stdout.strip()

    later = repository / "later-sprint.txt"
    later.write_text("later sprint descendant\n", encoding="utf-8", newline="\n")
    later_commit = _commit_paths(repository, "later sprint", [later.name])
    assert later_commit not in {result_commit, closure_commit}
    (repository / "docs/governance/v1/delivery-forecast.json").write_text(
        '{"working_tree":"deliberately invalid"}\n',
        encoding="utf-8",
        newline="\n",
    )

    assert (
        governance.check(
            Namespace(
                repository_root=str(repository),
                governance_dir=str(repository / "docs/governance/v1"),
                roadmap=str(roadmap),
                allow_pending=False,
                accept_now=False,
                historical=True,
                closure_commit=closure_commit,
                acceptance_tag_object=tag_object,
                fetch_authoritative_refs=False,
                commitment_time=None,
                attestation_plan_dir=None,
                attestation_signed_at=None,
            )
        )
        == 0
    )
    output = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert output == {
        "acceptance_tag_object": tag_object,
        "bundle_digest": bundle["bundle_digest"],
        "bundle_status": "accepted_for_development",
        "forecast_status": "accepted",
        "record_digest": forecast["record_digest"],
        "result": "valid_historical_accepted",
        "signatures": "all_required_verified",
    }
