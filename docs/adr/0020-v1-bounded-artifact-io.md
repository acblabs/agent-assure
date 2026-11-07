# ADR 0020: Bounded trace artifacts and downstream read-back

- Identifier: `ADR-V1-IO`
- Ticket: `V1-BASE-05`
- Status: `proposed_for_development`
- Target profile: `stable-core/v1`
- Owner responsibility: `platform_lead`
- Reviewer responsibility: `security_reliability_reviewer`
- Approval mode proposed: `maintainer_development`
- Review limitation: `NO_INDEPENDENT_REVIEW`
- Start receipt: `drafting_authorization`; completion receipt: `development_design_acceptance`
- Dependencies: exact accepted `V1-BOOT-01` and `V1-BASE-01` development receipts

This is a decision draft. The current S1 roster does not assign its owner or
reviewer responsibilities. It does not claim a signed acceptance, qualified host,
measured capacity, or permission to bypass the successor S1 closure. An accepted
completion receipt must bind the exact bytes of this ADR, resolved assignments,
file scope, bounded work profile, conflicts, and remaining qualification work.

## Context and reuse

Large traces need a representation whose resource use can be checked before a
legacy in-memory envelope is constructed. Raising one global JSON limit would
also enlarge unrelated trust boundaries and would not solve unbounded sorting,
deduplication, monitor state, or downstream rendering.

The verified reuse anchors are `io_limits.py`, `artifact_io.py`, `rooted_io.py`,
`artifact_transaction.py`, the existing `schema/stream.py` records,
`schema/validation.py`, and canonical serialization under `canonical/`. Current
generic JSON artifacts are limited to 16 MiB; the explicitly scoped
journal-bearing RunSet allowance is 64 MiB. `MAX_PERSISTED_OBSERVATIONS=4096`
limits applicable run/statistical envelopes independently of the raw trace event
limit. This design changes none of those constants or historical semantics.

Optional OTLP JSON and MCP-over-OTel import require their own versioned mapping
and source qualification. A transport importer does not qualify its evidence.
Unknown mappings are unsupported. Protobuf and raw transcript decoding remain
disabled until separately specified and qualified.

## Decision: a byte-exact log with a small commit envelope

Use sharded privacy-filtered event logs and a digest-bound trace manifest for the
large-trace path. Preserve the existing small `StreamRunRecord` path. Consumers
must stream shards or use bounded external state; assembling the entire trace
into a legacy RunSet is not an implementation of this design.

`canonical-jsonl/v1` has the following single wire form:

1. UTF-8 without BOM; every string contains Unicode scalar values. Reject
   malformed UTF-8 and unpaired surrogates before canonicalization.
2. Each record is one strict I-JSON object serialized with RFC 8785. Reject
   duplicate names, nonfinite numbers, out-of-domain integers, and unknown
   executable encodings. Preserve existing stricter privacy and field bounds.
3. Append exactly one byte `0x0a` to each canonical object, including the last.
   Blank lines, CRLF, extra separators, trailing bytes, and an unterminated final
   record are invalid. A reader verifies this framing; it does not normalize it.
4. A record never spans shards. Names are contiguous, eight-digit, zero-based
   ASCII names: `events-00000000.jsonl`, `events-00000001.jsonl`, and so on.
   Numeric index determines manifest order. Gaps, aliases, repeated names,
   noncanonical padding, case variants, and path traversal are rejected.
5. The per-shard file digest is lowercase `sha256:<64 hex digits>` over the
   exact file bytes, including every LF. A semantic projection digest is a
   separately named value and cannot substitute for this file digest.

The manifest binds the exact writer/schema, mapping and privacy identities;
subject/run identity; ordered shard entries with name, size, count, first and
last transport ordinal and exact-file SHA-256; total counts and bytes; ordering
and closure sidecars; work/durability profiles; and finalization state. The
manifest's content identity excludes only its declared self-digest and detached
signature envelope. Sidecars precede the manifest in the digest DAG. The outer
release manifest may bind the trace manifest, packet, authorization and exports;
those children never bind that future outer manifest.

Transport ordinals identify deterministic storage positions. Shard order,
transport position, timestamps, parent spans, or generic OTel links do not imply
causal order. Qualified source sequence and explicit happens-before facts retain
their own authority, producer, epoch and scope. Removing a sensitive attribute
does not remove the event: the affected predicate becomes unavailable.

## Publication, concurrency and recovery

Use the existing rooted/no-clobber primitives. Authenticate and pin the output
root, reject symlink/reparse traversal and unexpected file types, and coordinate
publication through the existing lock boundary. A check-then-path-write sequence
is insufficient. An identical existing immutable file is an idempotent reuse; a
different file at its name is an immutable conflict.

The writer creates an exclusively owned `.partial` file under the approved root,
streams under all limits, flushes under its selected durability profile, closes
it, and fresh-reads it to verify framing, counts, length and digest. It publishes
the immutable shard with an atomic no-clobber operation. Only after every shard
and sidecar has been published and rechecked does it publish the finalized
manifest. Manifest publication is the logical visibility commit point, not a
claim that all operating systems provide one multi-file crash transaction.

A `.partial` file or unreferenced immutable shard is inert staging material. It
cannot be used by evaluation, packets or authorization. Cleanup is confined to
exact writer-owned entries under the verified root; it is never a recursive
deletion of a caller-derived path. On interruption, recovery verifies the
manifest and the longest immutable prefix it actually authenticates. A missing,
corrupt or substituted referenced shard invalidates the original finalized
artifact. Recovery never truncates a referenced shard, changes bytes in place,
skips a gap, or infers closure. A resumable or derived prefix has a new identity
and remains nonauthorizing until its own complete manifest and closure checks
succeed. Existing issued evidence remains immutable; any invalidation is a new
external record.

Durability is explicit and platform-specific:

| Profile | Required qualification and bounded claim |
| --- | --- |
| `posix-fsync-dir/v1` | Flush/fsync owned data and sidecars, publish with supported no-replace semantics, and fsync each affected directory in the specified order. Qualify filesystem and mount behavior. No claim about hardware that lies about stable writes. |
| `windows-flush-rename/v1` | Flush owned handles, verify handle identity and Windows no-replace rename behavior, then qualify the complete sequence on the supported filesystem/host. Do not infer POSIX directory-fsync guarantees. |
| `visibility-only/v1` | After successful publication, fresh-process replay may verify visible bytes. No power-loss durability claim. A verifier requiring stronger durability must reject this profile. |

Unsupported host/profile combinations fail closed. Selecting a named profile is
not evidence that its implementation or host has passed qualification.

## Bounded development profile

The following are proposed ceilings for `development_bounded`, not calibrated
release limits or promises of throughput. A human design acceptance may ratify
or lower them. All apply simultaneously; the event-count ceiling does not
promise that many maximum-sized records.

| Quantity | Maximum | Accounting boundary |
| --- | --- | --- |
| Decoded raw import | 268,435,456 bytes (256 MiB) | Total decoded source stream, including decompression output; enforce while decoding. |
| Events | 250,000 | All decoded events, including records later rejected or filtered; do not reset on shard boundaries. |
| Canonical event object | 262,144 bytes (256 KiB) | Canonical object bytes; LF framing is additionally charged to shard/aggregate budgets. |
| Shard | 8,388,608 bytes (8 MiB) | Exact published bytes including LF; close before a next record would exceed the cap. |
| Trace manifest | 1,048,576 bytes (1 MiB) | Complete serialized envelope; checked before publication and on read. |
| Attributes per event | 128 | Input attributes before filtering; duplicate keys are an error, not a way to reduce the count. |
| Raw string | 8,192 bytes (8 KiB) | UTF-8 encoded input value before allocation into an unbounded representation. |
| Nesting | 32 | Parser container depth; reject before constructing deeper containers. |
| Spill/index disk | 1,073,741,824 bytes (1 GiB) | Aggregate outstanding import-owned temporary sorting, deduplication and index files. |

The stricter existing per-field or privacy rule always wins. Memory, wall time,
sort work, reorder-window size, producer count, causal vertices/edges,
reachability operations, monitor states, action keys, and numeric operations
must additionally be finite values in the selected work profile before the
corresponding path is enabled. An unset work profile disables that path; it
does not mean unlimited. Reaching a capacity produces the method's typed
resource-limited/invalid disposition without favorable evidence. Input validity
failure is not a demonstrated process violation.

Arbitrarily shuffled input requires bounded external sorting or a declared
reorder window with explicit out-of-window rejection. Exact global deduplication
requires a bounded disk/index structure or rejection at capacity. Deduplication
uses source identity `(run, producer, epoch, event)`; identical content with
different identities can be distinct executions. Conflicting redelivery is
invalid. No fixed-memory claim is made for arbitrary exact global deduplication.

## Reader inventory and qualification plan

Every producer maximum must survive all its intended consumers. The downstream
qualification owner must enumerate actual functions when implementation lands;
the existing module anchors below are the scoped integration points.

| Reader/consumer | Required maximum-artifact read-back check | Owning work |
| --- | --- | --- |
| Rooted decoder and stream ingestion | Fresh-process load of a full allowed manifest/shard set; bounded reads, aggregate limits, exact deduplication and missing/substituted shard rejection. | `V1-IO-01`, `V1-ING-01` |
| Coverage and partial order | Cross-shard source identities and references; predicate closure; no causal edge from transport order; resource exhaustion cannot support a claim. | `V1-EVID-01`, `V1-EVID-02`, `V1-IO-02` |
| Temporal monitor | Incremental exposure, action/approval state and late-event invalidation; bounded states; support and violation agree with the tiny independent oracle in its domain. | `V1-TEMP-01`, `V1-TEMP-02`, `V1-IO-02` |
| Evaluation and evidence descriptors | Preserve exact source manifest digest, missingness, status and limitations without materializing all events in a small legacy envelope. | `V1-IO-02` and applicable evidence producer |
| Packet and CI/authorization | Fresh process revalidates source linkage and finalization through the complete evaluation/packet/gate path; tamper emits no eligible authorization. | `V1-IO-02`, `V1-AUTH-01`, `V1-AUTH-02` |
| Human/machine reporting | Bounded excerpts and pagination with full source references; no silent event truncation that changes a conclusion; final reports reload. | `V1-IO-02` and reporting owner |
| Optional exports | Consume finalized packet/context, respect their own caps and never strengthen missing observations or reverse the digest DAG. | Selected optional profile |

The qualification matrix covers maximum aggregate size, maximum count with
small records, maximum single record, all simultaneous-limit boundaries,
highly duplicated and shuffled data, high fan-out references, missing and
conflicting chunks, truncated final LF, invalid encodings, path substitution,
disk exhaustion, denied writes, interrupted publication, concurrent writers,
and clean installed-wheel replay outside the checkout. Run separately on each
supported host/durability profile and record peak memory, peak disk, elapsed
time, operation counts and exact environment. Release limits remain unratified
until measured evidence and the designated review accept that matrix. A smaller
host profile may lower caps; silently raising a cap or dropping a consumer is a
new profile/version decision.

## Seed dispositions and acceptance evidence

These are reviewed design meanings, not converted production fixtures:

| Seed | Required disposition | Downstream conversion |
| --- | --- | --- |
| `IO-001` | Missing any manifest-referenced chunk makes the evidence invalid. | `V1-IO-01`, replayed by `V1-IO-02` |
| `CAP-001` | Missing finite limits prevents bounded-development dispatch. | `V1-BASE-05` governance validation, then `V1-IO-01` |
| `CAP-002` | Calibration without accepted release limits is not release qualification. | `V1-BASE-05`, `V1-PROC-02`, `V1-QUAL-03` |
| `AUTH-003` | Missing supported required evidence means `release_authorized=false`. | `V1-AUTH-01` |
| `TEMP-006` | An open approval channel that may contain an earlier approval remains `inconclusive`. | `V1-EVID-02` |
| `TRUST-001` | Signed self-report remains `model_self_report` and is not independently approval-eligible. | `V1-TRUST-01` |
| `STAT-010` | Moments-only restart cannot establish historical crossing; it is invalid with `REPLAY_STATE_INSUFFICIENT`. | `V1-STAT-01` |

Read-only inspection for this draft used `Get-Content` on roadmap sections 2.3,
5.1-5.3 and `V1-BASE-05`; `rg` of `io_limits.py`, `schema/run.py`,
`schema/stochastic_sensitivity.py`; and source inspection of the rooted I/O,
artifact transaction, export and validation anchors. This is no assertion that
future sharded implementations or capacity tests passed.

Design acceptance validates the ADR identity, dependency receipts, exact file
scope, all seed references, resource-profile completeness and consistency with
`ADR-V1-SCHEMA`, `ADR-V1-EVIDENCE` and `ADR-V1-AUTH`. It binds the exact ADR digest
in a signed scoped completion receipt. Implementation later requires schema-first
receipts, byte goldens, fault injection, fresh-process read-back and measured host
qualification. Unknown platform guarantees, contradictory seed meanings,
unbounded required work, or a reader whose maximum is smaller than the producer's
accepted maximum stop the affected dispatch. Development acceptance does not
resolve independent security, durability, method or release admission.
