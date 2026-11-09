# S1/S2 correction close and retained acceptance

The working branch now descends from the generation-3 receipt-only closure
`20a49c9c6c57ffa6096f5db9a466b472d7bc54fb` (C3). Its tested parent is
`6ad62f67825e2abbe97bcec32e90dcaa501900d4` (R3). The original v3 tag and
signed S1/S2 subjects remain unchanged. Earlier READMEs and proposal status
fields describe those immutable source records; detached acceptance lives in
the retained evidence, not in a rewritten proposal.

The [retention inventory](closure-handoff.json) records a verified, complete Git
bundle and selected exact acceptance records under `.governance-archive`.
That directory is excluded from Git because it contains private planning
material. This is another local copy, not an off-device backup or a portable
replay certificate. Preserve the original capture path, frozen host and private
witnesses. Make an operator-controlled off-device backup before relying on this
machine as the sole evidence custodian.

The [new amendment](../../../adr/0023-v1-governance-closure-corrections.md)
addresses the remaining forecast, support, distribution and scope obligations.
It has no authority until its exact bytes receive the required human acceptance.
The signed earlier records are history, not signatures over this correction.

## Engineering checks

```console
python -m scripts.v1_governance_corrections check
python -m pytest tests/unit/governance
python -m ruff check .
python -m mypy src scripts
```

`correction-source-bindings.json` is a machine-authored draft inventory. It binds
every replacement/addition without changing `architecture-package.json`. Both
the old architecture check and the correction check can establish draft byte
consistency only. Neither supplies human acceptance, operational support,
independent method admission, release approval or Sprint 3 editing authority.

After intentionally editing a correction source, use
`python -m scripts.v1_governance_corrections bind` to refresh only this unsigned
draft inventory, then rerun checks. Old private signing snapshots must not be
reused for newly changed bytes.

## Prepare the human decisions

Use a fresh direct child of `.governance-archive` for each output. `propose`
creates explicitly machine-authored, unadopted metadata suggestions and a null
support-owner template. Review all 68 ticket rows and their 121 occurrences;
change estimates, confidence, assumptions and status as appropriate. No
unresolved source scope represents zero work. Supply the actual support owner,
capacity, conflicts and limitations; the tool does not invent them. Public
individual names and contact destinations are not required. Under `acblabs`,
the adoption input records separate primary/fallback role references, an opaque
private roster reference and owner-supplied immutable revision, an independent
fallback-route reference, and explicit coverage/retention attestations. Keep the
actual on-duty people and destinations in the access-controlled incident-response
system, as `SECURITY.md` already requires. Different role labels do not prove
different people; the policy owner attests that the exact private revision
records distinct actual individuals and independent routes. These are
owner-attested staffing facts, not independently verified evidence. An
organizational label alone, unresolved revision, or absent coverage cannot close.

```console
python -m scripts.v1_governance_corrections propose --producer .governance-archive/s1-s2-v3-20261109/records/forecast-producer-signed/document.json --out .governance-archive/correction-proposals-001
python -m scripts.v1_governance_corrections prepare --producer .governance-archive/s1-s2-v3-20261109/records/forecast-producer-signed/document.json --bundle .governance-archive/s1-s2-v3-20261109/records/finish-i08/s2-import/accepted-bundle.json --rows .governance-archive/correction-proposals-001/selected-rows.proposal.json --support-adoption .governance-archive/correction-proposals-001/support-adoption.template.json --out .governance-archive/correction-review-001
```

The second command deliberately fails until actual ownership/capacity fields
replace the null template. Preparation does not accept the selected metadata.
It freezes a complete review snapshot and emits six domain-separated raw
`.claim` inputs, separate from their readable JSON representations:

1. Prospective adoption of the exact current foundation and scope deviation,
   without retrospectively authorizing earlier edits.
2. The complete generation-4 forecast producer decision.
3. Separate maintainer acceptance of that forecast.
4. Exact amendment acceptance.
5. Operational support-policy adoption by a separately scoped policy owner.
6. Aggregate correction closure binding all five preceding decisions.

## Verification boundary

Before signatures are used, an external reviewer must authenticate the new
implementation and reviewed source snapshot, adopt the three actual role
authorities and their key scopes, and freshly authenticate the retained v3
predecessor through its original host route. The old byte-bound bootstrap does
not admit new code. A trust file or success flag supplied by the candidate is
not evidence of adopted authority.

`scripts.v1_governance_corrections.verify_review_acceptance` is the acceptance
API for that trusted integration. Independently reconstruct the reviewed snapshot
with `build_review`, using its frozen original issue time for deterministic
reconstruction; use the actual current UTC clock during signature verification.
Do not regenerate signing claims with a new issue time after they were signed.
Supply actual `TrustedKey` authorities and the authenticated SSHSIG callback.
The high-level API checks every exact subject and inventory byte, the claim to
package links, and the policy owner's identity before calling the low-level
signature gate. Verify
the exact six signatures, purpose/competence, predecessor/source digests and the
intersection of all validity intervals. A missing policy owner or signature
leaves the close pending. No code here reads a private key or signs for a human.

The correction close remains development governance. Operational support is
limited to its separately adopted policy; mathematical qualification and
deployment authority are unchanged. Before each Sprint 3 ticket, approve its
exact source/generated files and consume the applicable design and amendment
receipts. `SCHEMA-01A` and `SCHEMA-01D` implementation receipts still precede
`TEMP-01A` implementation.
