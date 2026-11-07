# V1 Sprint 2 architecture and prerequisite review package

This is the concrete, noninstallable `1.0.0a2` architecture proposal. Six
decision drafts and four BASE-06 work packages are prepared for development
acceptance. No human signature, competence, independent qualification,
governed dispatch, release, or deployment approval is inferred from these
files. `NO_INDEPENDENT_REVIEW` applies to all LLM-authored work here.

The user's current instruction authorizes the engineering preparation. It does
not fabricate the signed S1 successor closure, extend the S1-only signing key,
or turn a repository handle into mathematical or schema-review competence.
The original signed S1 JSON records and fixed tags remain immutable.

## Review contents

| Ticket | Proposed design |
| --- | --- |
| `V1-BASE-02` | [Evidence, coverage, temporal semantics and allocation](../../../adr/0017-v1-evidence-temporal-semantics.md) |
| `V1-BASE-03` | [Verifier policy, authorization and signatures](../../../adr/0018-v1-verifier-authorization.md) |
| `V1-BASE-04` | [Numerical and statistical contracts](../../../adr/0019-v1-numerical-statistical-contracts.md) |
| `V1-BASE-05` | [Bounded artifact I/O and durability](../../../adr/0020-v1-bounded-artifact-io.md) |
| `V1-BASE-06` | [Release registry, support, dispatch and evidence transfer](../../../adr/0021-v1-release-registry-dispatch.md) |
| `V1-BASE-09` | [Schema compatibility and production wire inventory](../../../adr/0022-v1-schema-wire-contracts.md) |

`architecture-package.json` binds exact raw bytes, schema and validation code,
and historical source identities. `wire-contract-inventory.json` enumerates the
42 first-writer contracts; the current-subject digest graph is acyclic while
strictly earlier-generation references are represented separately. Detached
signatures exclude themselves from the subject projection.

`occurrence-graph-expectations.json` preserves the separately authored
expectation contract: typed node/edge maps, critical work-package dependencies,
and graph/order hashes. It is not generated from the graph under test. Its
independence is structural, not an independent human review claim. The full
source graph implementation and source-slice dispatch generator remain later
implementation work; a valid draft checksum does not establish their behavior.

The [forecast compatibility contract](forecast-compatibility.md) preserves
`delivery-forecast/v1` through an explicit successor wire format, immutable
method/catalog bindings, full occurrence coverage and two actual signatures.

`support-policy.json` proposes concrete response/remediation targets and a
90-day overlap. Capacity and policy acceptance are unresolved, so these are
not operational commitments. EOL is not inferred from a preview. The evidence
ADR's `PRODUCT-INCONCLUSIVE-01` proposes at least 30 applicable obligation
attempts and a ceiling of 1/10. These are unaccepted product-policy numbers,
not confidence bounds or an empirical result. The policy owner must ratify or
replace them before any eligible threshold evaluation.

## Engineering validation

From the checkout's locked development environment:

```console
python scripts/v1_architecture_governance.py check
python -m pytest tests/unit/governance/test_v1_architecture_governance.py tests/unit/governance/test_v1_s1_successor.py
python -m ruff check scripts tests
python -m mypy src scripts
```

`make v1-architecture-check` checks draft integrity without the private
roadmap. `make v1-architecture-readiness` returns nonzero while acceptance
gates are pending. A successful integrity check explicitly reports
`accepted=false` and `s2_dispatch_ready=false`. Neither command replaces the
frozen native Windows S1 launcher or performs trust bootstrap.

After intentionally editing a draft, refresh its content bindings:

```console
python scripts/v1_architecture_governance.py refresh
python scripts/v1_architecture_governance.py prepare-review --out .tmp/v1-s2-review-001
```

Use a new output identifier for each review. Existing output is never
overwritten. The snapshot captures exact ADR, policy, schema and tool bytes;
the final manifest appears only after consistency checks. `review-request.claim`
is a domain-separated RFC 8785 request for review acknowledgment only. Signing
it does not satisfy the separate kickoff, completion, roster, forecast, or
closure receipts. No tool here reads or uses a private signing key.

## S1 successor and human acceptance sequence

The [successor protocol](s1-successor-protocol.json) and closed acceptance
schema define a new generation; they do not relabel generation-2 evidence.
The sequence is deliberately acyclic:

1. Review and sign a prospective bounded successor kickoff. Extend key scope
   explicitly if needed; the existing S1 key is not automatically an S2 key.
2. Commit the reviewed successor implementation as `R3`, a proper non-merge
   descendant of immutable `C2`. Do not move the v1 or v2 fixed tags. Record
   exact file scope, human competence, conflicts and runtime/tool identities.
3. Run the full required local check graph and fresh native `/4` control
   capture on clean exact `R3`, after the authorization. Require every hosted
   CI matrix instance to succeed on the same subject and workflow bytes.
   Partial, skipped, stale, failed, or different-subject evidence is insufficient.
4. Review the fresh inventory and forecast against the resolved dispatch
   scopes. Keep engineering P50/P90 separate from reviewer P50; there is no
   combined P90 without reviewer P90 inputs. Preserve old estimates as history.
5. The human signs the exact aggregate successor acceptance claim. Store only
   `docs/governance/v1/sprint2/s1-successor-acceptance.json` in closure `C3`, a
   direct non-merge child of `R3`. This aggregate binds the scoped completion
   and evidence inputs to R3, not C3 itself. C3 cannot change tested code,
   schemas, workflow, or any other file. A separate fixed-tag attestation binds
   C3 and the exact aggregate receipt. Additional closure files require an
   explicitly reviewed protocol amendment before execution.
6. Verify the new fixed tag
   `agent-assure-s1-1.0.0a1-acceptance-v3` in a clean standalone clone using
   the externally reviewed bootstrap and exact evidence. Standalone replay
   follows the tag and is not reachable from the tag's own signed subject.
7. Adopt the scoped S2 roster/key/forecast and issue six drafting and six
   exact-digest development-design receipts. Accept the support and product
   metric policies explicitly. Only then close the signed architecture bundle.

The pure successor validator requires authenticated Git objects, signature
verification and execution evidence supplied by a trusted host integration.
JSON flags such as `passed=true` are not such an integration. It cannot supply
human decisions or authorize its own bootstrap. Ordinary development tests are
engineering evidence only; they are not the frozen-host capture, a hosted CI
result, an independent mathematical review, or the signed successor ceremony.

The frozen-host adapter, bounded local check runner, authenticated GitHub CI
read-back, receipt-only closure creation, fixed-tag publication, standalone
replay and fifteen-signature architecture acceptance are implemented. Follow
the [host runbook](host-runbook.md) for concrete requests and signing steps.
The externally authenticated legacy launcher verifies the scoped bootstrap and
all new implementation bytes before execution. Original source witnesses are
revalidated; unsigned JSON success flags have no authority.

Actual scoped human decisions and clean-host execution remain required. The
engineering tests exercise real Git objects and temporary SSH keys, with
explicit controlled seams for native execution and HTTPS responses; they do
not claim a live hosted run or accepted successor. Ordinary draft validation
continues to report no acceptance. Each S2 import or verification performs a
fresh standalone successor replay and checks every exact-byte human signature.

## Compatibility and next dispatch

Package `0.7.0`, writer `0.6.6`, released schema snapshots, existing CLI exit
semantics and runtime policies remain unchanged. S3 production schema writers
must consume the exact accepted schema/DAG receipts. Development acceptance of
these drafts never admits a method or qualifies a release. Missing future
independent admission does not prevent engineering preparation; it prevents
the corresponding qualified use.
