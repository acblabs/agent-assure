# Minimal Assurance Evidence Graph

Status: development RFC for the v0.6.3 writer surface.

AssuranceEvidenceGraph/v1 is a deterministic, digest-bound projection of
existing Agent Assure artifacts. It gives evaluation, comparison, mutation,
control-efficacy, gate, and limitation evidence one small machine-readable
shape without claiming that the graph proves adequacy, authenticity, safety,
or compliance.

## Vocabulary

The contract is intentionally closed:

| Kind | Allowed values |
| --- | --- |
| Node | subject, requirement, evidence, finding |
| Edge | supports, contradicts, targets, derived_from, scoped_to |

An edge is valid only for its declared endpoint shape. For example, a finding
may target a requirement and be derived from evidence; an evidence or finding
node may support or contradict a requirement; and requirements, evidence, and
findings may be scoped to a subject. Unknown kinds and invalid endpoint pairs
are rejected.

Adding a node or edge kind requires a concrete artifact that cannot be
represented with this vocabulary and an explicit contract amendment. The graph
is not a general ontology.

## Identity and canonical digest

Node IDs are `<kind>:<sha256>`, where the digest is RFC 8785 SHA-256 over
`{"domain":"agent-assure/assurance-evidence-graph-node/v1","kind":<kind>,
"identity":<identity projection>}`. Display text is payload, never identity.
Editing a finding message therefore changes its payload digest and the graph
digest while preserving the node ID.

Every node persists its typed `identity` projection. Validation recomputes the
node ID from that projection, verifies its fields against the typed payload,
and verifies topology-bearing subject and parent IDs against the node's actual
`scoped_to` and `derived_from` edges. A producer cannot substitute an arbitrary
same-kind SHA-256 ID while leaving the declared identity unchanged.

The identity projections are closed and schema-owned:

| Projection | Identity fields |
| --- | --- |
| subject | subject_type, subject_id, subject_digest (including explicit null) |
| requirement | scoped subject node ID, requirement type, requirement ID |
| evidence | scoped subject node ID, evidence type, source artifact kind, source ID |
| finding | scoped subject node ID, parent evidence node ID, finding type, source artifact kind, source ID, source path |

Source IDs are non-empty. Current v0.6.3 run sets, evaluation summaries,
comparison summaries, and evaluation findings reject empty identifiers before
first-party graph projection. Older artifacts retain their historical parsing
contract, but an older artifact with an empty projected identifier cannot be
represented in `AssuranceEvidenceGraph/v1`; the builder rejects it explicitly
instead of constructing an ambiguous node identity.

Requirement type and ID distinguish typed origins such as a control from a
reason-code fallback. Finding identity includes its stable source location but
not messages. Mutation evidence uses the self-digested mutation result as its
source ID, so evaluator identity changes still change that node ID.

Every node carries the RFC 8785 canonical SHA-256 digest of its typed payload.
The graph digest covers the complete canonical artifact except graph_digest
itself. Nodes sort lexically by kind and then node ID; edges sort lexically by
kind, source ID, and target ID. Set-like references, reason codes, limitations,
nodes, and edges must be unique and sorted.

Persisted input fails closed on an invalid self-digest or payload digest,
duplicate node IDs or edges, dangling edges, self-edges, invalid digest syntax,
unsafe numeric input, noncanonical ordering, or an endpoint-kind mismatch.
The public digest helper rejects a mapping that still contains graph_digest so
the digest cannot accidentally include itself.

## Projection semantics

The pure builder accepts typed artifacts and does not perform I/O or invoke a
model:

- evaluation summaries become evaluation evidence and first-class
  findings targeting declared controls;
- comparison verdicts and provenance changes remain visible without using
  mutable prose as node identity;
- mutation outcomes retain caught, survived, inapplicable, invalid, and error
  reasons, their typed evaluator evaluation basis, plus matched and observed
  findings. Caught and survived results are verdict-bearing only when the basis
  is deterministic; stochastic and human-reviewed outcomes remain
  inconclusive and non-verdict until their typed sufficiency prerequisite is
  represented;
- control-efficacy outcomes and threat coverage preserve their semantic state;
- gate profiles preserve non-verdict policy provenance, while gate decisions
  preserve authoritative verdicts and exact gate effects without recalculating
  or changing CI behavior; and
- every supplied limitation becomes a non-verdict-bearing finding as well as
  remaining attached to its source evidence.

Evaluation summaries identify a run set by text, while mutation and
control-efficacy artifacts identify their source by canonical digest. The
builder does not invent a join between those different identifiers. Unless the
caller explicitly supplies the same subject digest, digest-only evidence is
scoped to a separate subject labeled by that digest; missing-digest mutation
evidence is scoped to an explicit unbound subject.

The resulting graph may therefore contain multiple weakly disconnected
components. `primary_subject_node_id` is the graph's primary identity anchor,
not a complete traversal root or a claim that every verdict is reachable from
that subject. In a graph whose textual run-set subject has no authenticated
digest join, the authoritative gate-decision evidence is scoped to the
control-efficacy source-digest subject and is outside the primary subject's
component. Consumers must inspect all typed subject and evidence nodes (or
maintain an all-node index); they must not infer graph-wide completeness from
the primary component. The contract does not add an unauthenticated connecting
edge merely to make traversal convenient.

Supported and violated source states may produce supports or contradicts
edges. Other states remain visible in payloads without being collapsed into a
binary edge. The graph is descriptive evidence transport; the existing typed
gate decision remains authoritative.

Comparison acceptability is verdict-bearing only after fixture equivalence
passes. Fixture-equivalence failure projects as error, warning as inconclusive,
and not-evaluated as not evaluated; none emits a semantic comparison edge.

For threat scope, `supports` means an applicable threat category was exercised
by at least one completed challenger. It does not mean the detector caught the
challenge or that the threat was mitigated. A survived-only challenge therefore
supports threat-challenge coverage while its detector outcome contradicts the
mutation-detector requirement.

## Packet compatibility and binding

Each graph includes EvidencePacketGraphProjection/v1, an exhaustive
top-level decision-field manifest for legacy packet schemas v0.5.0 through
v0.6.2. Its `projection_scope` is `decision_fields`: a represented
top-level object means its verdict-bearing decision projection is carried, not
that every nested display, environment, usage, or envelope field is copied.
Represented verdict-bearing fields name their target node kinds. Unsupported
fields are limited to non-verdict envelope, exact-file, environment, release,
usage, or display concerns and carry a reason code. A verdict-bearing field
cannot be marked unsupported.

Current Agent Assure packet generation can bind both:

- evidence_graph_digest, the graph's semantic RFC 8785 digest; and
- one assurance-evidence-graph artifact digest, the raw SHA-256 of the exact
  JSON file included in the release manifest.

These serve different purposes. The semantic digest identifies the canonical
graph; the raw digest binds the exact transported bytes. Graph binding remains
optional at the schema level so compatible third-party v0.6 packet producers
are not forced to emit a graph. When one binding is present, the corresponding
binding must be complete and exact.

The first-party bound graph is the exact canonical projection of the packet's
nested evaluation, comparison, control-efficacy, gate, and limitation fields.
Trusted verification reconstructs that projection and rejects a structurally
valid graph for different evidence. Optional mutation results are not nested
packet fields, so they do not alter the packet-bound digest. Supplying
`--mutation-result` to `packet graph` first verifies the packet-bound base
digest and then emits a separate enriched graph with its own digest.

The graph deliberately excludes packet identity and exact packet-file digests,
avoiding a graph-to-packet-to-graph digest cycle.

## CLI inspection

    agent-assure graph validate assurance-evidence-graph.json
    agent-assure graph digest assurance-evidence-graph.json

Packet projection is available through packet graph, and the first-party
packet builder writes a graph beside new packets. Packet publication restores
all pre-existing owned outputs when an ordinary late write fails; this is
best-effort rollback, not a multi-file crash-atomic transaction. Loaders are
bounded, validate JSON Schema before current-model projection, and return
value-free validation errors at the CLI boundary.

## Privacy and non-goals

First-party packet commands privacy-filter typed source projections before
graph node IDs or digests are computed. Persistence also fails closed if
redaction would alter any graph payload; it never redacts after digest
construction. Graphs can still contain identifiers and bounded reviewer
messages, so normal artifact access controls apply. A digest supplies integrity
identity, not secrecy, a signature, or external attestation.

The contract does not provide assurance-case authoring, OSCAL export,
attestation, inference, a query language, a graph database, or a hosted graph
service.
