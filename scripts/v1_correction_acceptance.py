"""Pure acceptance of the six Sprint 1/2 correction decisions.

This module is not a trust bootstrap or a signing CLI. The caller must
authenticate its implementation and supply adopted role authorities, a real
SSHSIG verifier and expected claims independently compiled from reviewed source
bytes. Loading ``expected_claims`` or authorities from the submitted documents
would defeat that boundary. Existing v3 signatures cannot admit this new code.

The result accepts only this correction package. It admits no mathematical
method, qualifies no implementation, authorizes no release or deployment, and
does not grant a future Sprint 3 editing scope. Operational support obligations
are established only by the explicitly scoped policy-owner decision.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from scripts import v1_s1_successor as core
from scripts import v1_successor_io as io

CLAIM_DOMAIN = b"agent-assure:sprint12-correction-decision/v1\x00"
CLOSURE_DOMAIN = b"agent-assure:sprint12-correction-close-subject/v1\x00"
CLAIM_FORMAT = "agent-assure-sprint12-correction-claim/1"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z\Z", re.ASCII)


@dataclass(frozen=True)
class ClaimSpec:
    purpose: str
    role: str
    competence_scope: str


CLAIM_SPECS = {
    "foundation_adoption": ClaimSpec(
        "sprint12-foundation-adoption/v1",
        "repository_maintainer",
        "planning_governance:s1_successor",
    ),
    "forecast_producer": ClaimSpec(
        "sprint12-forecast-producer/v1", "technical_lead", "planning_governance:s1_successor"
    ),
    "forecast_acceptance": ClaimSpec(
        "sprint12-forecast-acceptance/v1",
        "repository_maintainer",
        "planning_governance:s1_successor",
    ),
    "design_amendment": ClaimSpec(
        "sprint12-design-amendment/v1", "repository_maintainer", "schema_compatibility"
    ),
    "support_policy": ClaimSpec(
        "sprint12-support-policy/v1", "release_policy_owner", "operational_support:0.7.x"
    ),
    "correction_close": ClaimSpec(
        "sprint12-correction-close/v1",
        "repository_maintainer",
        "planning_governance:s1_successor",
    ),
}
CLAIM_FIELDS = frozenset(
    {
        "format",
        "claim_id",
        "purpose",
        "issuer_role",
        "subject_digest",
        "predecessor_bundle_digest",
        "roadmap_digest",
        "correction_package_digest",
        "issued_at_utc",
        "valid_until_utc",
        "independence",
        "authorization_effect",
    }
)


class CorrectionError(core.SuccessorError):
    """A correction decision is incomplete, stale or outside adopted authority."""


@dataclass(frozen=True)
class AcceptedCorrection:
    claim_digests: tuple[tuple[str, str], ...]
    accepted_at_utc: str
    valid_until_utc: str
    authority_snapshot_digests: tuple[tuple[str, str], ...]


def _require(value: bool, message: str) -> None:
    if not value:
        raise CorrectionError(message)


def _time(value: object) -> datetime:
    _require(type(value) is str and _UTC.fullmatch(value) is not None, "strict UTC time required")
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise CorrectionError("invalid UTC time") from exc


def _clock(now: Callable[[], datetime]) -> datetime:
    value = now()
    _require(
        type(value) is datetime and value.tzinfo is not None and value.utcoffset() == timedelta(0),
        "UTC verification clock required",
    )
    return value


def claim_bytes(claim: Mapping[str, Any]) -> bytes:
    """Exact SSHSIG input; never sign a human-readable JSON reserialization."""
    return CLAIM_DOMAIN + core.canonical_bytes(dict(claim))


def claim_digest(claim: Mapping[str, Any]) -> str:
    return core.content_digest(claim_bytes(claim))


def closure_subject_digest(claims: Mapping[str, Mapping[str, Any]]) -> str:
    """Bind all five preceding decisions, including their exact subject and scope."""
    required = set(CLAIM_SPECS) - {"correction_close"}
    _require(set(claims) == required, "exact five prerequisite correction claims required")
    projection = {claim_id: claim_digest(claims[claim_id]) for claim_id in sorted(required)}
    return core.content_digest(CLOSURE_DOMAIN + core.canonical_bytes(projection))


def _claims(expected_claims: Mapping[str, Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    _require(set(expected_claims) == set(CLAIM_SPECS), "exact six correction claims required")
    claims: dict[str, dict[str, Any]] = {}
    for claim_id, spec in CLAIM_SPECS.items():
        value = expected_claims[claim_id]
        _require(isinstance(value, Mapping), "correction claim must be an object")
        claim = dict(value)
        _require(set(claim) == CLAIM_FIELDS, "closed correction claim required")
        _require(
            claim["format"] == CLAIM_FORMAT
            and claim["claim_id"] == claim_id
            and claim["purpose"] == spec.purpose
            and claim["issuer_role"] == spec.role,
            "correction claim identity, purpose or role differs",
        )
        _require(
            claim["independence"] == "NO_INDEPENDENT_REVIEW"
            and claim["authorization_effect"] == "development_governance_only",
            "correction cannot claim qualification or runtime/release authority",
        )
        for field in (
            "subject_digest",
            "predecessor_bundle_digest",
            "roadmap_digest",
            "correction_package_digest",
        ):
            _require(
                type(claim[field]) is str and _DIGEST.fullmatch(claim[field]) is not None,
                "exact SHA-256 correction subject/source digest required",
            )
        issued, expiry = _time(claim["issued_at_utc"]), _time(claim["valid_until_utc"])
        _require(issued < expiry <= issued + timedelta(days=30), "invalid correction interval")
        claims[claim_id] = claim
    for field in ("predecessor_bundle_digest", "roadmap_digest", "correction_package_digest"):
        _require(len({claim[field] for claim in claims.values()}) == 1, "mixed correction subjects")
    _require(
        claims["correction_close"]["subject_digest"]
        == closure_subject_digest(
            {key: value for key, value in claims.items() if key != "correction_close"}
        ),
        "aggregate correction close omits or changes a prerequisite decision",
    )
    return claims


def verify_correction_acceptance(
    documents: Mapping[str, Mapping[str, Any]],
    expected_claims: Mapping[str, Mapping[str, Any]],
    authorities: Mapping[str, io.TrustedKey],
    verify_signature: io.SSHVerifier,
    *,
    now: Callable[[], datetime],
    prerequisite_valid_until_utc: str,
) -> AcceptedCorrection:
    """Verify the complete exact-byte decisions under separately adopted keys.

    Neither authorities nor expected claims may be derived from submitted
    envelopes or their success flags. The trusted caller is also responsible for
    current authentic predecessor verification and source reconstruction. The
    supplied prerequisite expiry caps, but can never refresh, that evidence.
    """
    _require(callable(now) and callable(verify_signature), "trusted verifier and clock required")
    claims = _claims(expected_claims)
    _require(set(documents) == set(CLAIM_SPECS), "exact six signed correction documents required")
    required_roles = {spec.role for spec in CLAIM_SPECS.values()}
    _require(
        set(authorities) == required_roles, "exact adopted correction role authorities required"
    )
    started = _clock(now)
    prerequisite_expiry = _time(prerequisite_valid_until_utc)
    expiries = [prerequisite_expiry]
    observed = started
    for claim_id, spec in CLAIM_SPECS.items():
        claim = claims[claim_id]
        key = authorities[spec.role]
        _require(
            type(key) is io.TrustedKey and key.role == spec.role, "adopted authority role differs"
        )
        _require(spec.competence_scope in key.competence_scopes, "adopted competence scope missing")
        issued, expiry = _time(claim["issued_at_utc"]), _time(claim["valid_until_utc"])
        _require(
            _time(key.valid_from_utc) <= issued <= started < expiry
            and expiry <= min(_time(key.valid_until_utc), prerequisite_expiry),
            "correction is future, expired or extends adopted prerequisites",
        )
        document = documents[claim_id]
        _require(
            isinstance(document, Mapping) and set(document) == {"claim", "signature_envelope"},
            "closed signed correction document required",
        )
        _require(document["claim"] == claim, "signed correction differs from reviewed exact claim")

        def checked_clock(claim_expiry: datetime = expiry) -> datetime:
            nonlocal observed
            current = _clock(now)
            _require(observed <= current < claim_expiry, "correction expired or clock regressed")
            observed = current
            return current

        try:
            io.verify(
                claim_bytes(claim),
                document["signature_envelope"],
                key,
                verify_signature,
                now=checked_clock,
                purpose=spec.purpose,
            )
        except io.SuccessorIOError as exc:
            raise CorrectionError(str(exc)) from exc
        expiries.append(expiry)
    completed = _clock(now)
    intersection_expiry = min(expiries)
    _require(observed <= completed < intersection_expiry, "correction expired or clock regressed")
    return AcceptedCorrection(
        tuple((claim_id, claim_digest(claim)) for claim_id, claim in claims.items()),
        completed.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        intersection_expiry.isoformat().replace("+00:00", "Z"),
        tuple((role, authorities[role].trust_snapshot_digest) for role in sorted(required_roles)),
    )
