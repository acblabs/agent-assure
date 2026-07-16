# Provenance And Hashing

Hashes answer which material participated in a run. They do not decide whether a
behavior is correct.

Current digest behavior:

- values are projected through `digest_projection`;
- digest-relevant configuration decimals are quantized to six places and
  represented as JSON strings in digest projections;
- strings must be NFC-normalized;
- RFC 8785 JCS bytes are produced by one implementation path;
- SHA-256 is used for content digests;
- fixture manifests hash file bytes and use canonical digests for the manifest
  artifact;
- the RAG provenance demo records `provenance.retrieval_corpus_digest` from a
  committed corpus manifest covering corpus identity, version, chunking, chunk
  source IDs, and chunk content digests;
- cached RAG vectors use scaled integers, and the vector-manifest digest is an
  exact file-byte SHA-256 rather than a parsed floating-point projection;
- RAG retrieval scores are computed with deterministic `Decimal` arithmetic and
  quantized before persistence;
- counterfactual RAG reports persist stable query variant IDs and normalized
  query digests, not raw query text, while committed query-vector keys select
  the offline fixture vectors used for retrieval;
- HMAC-SHA256 is used for sensitive low-entropy correlations.
- privacy detector semantics are represented by a versioned profile ID and a
  SHA-256 digest over an RFC 8785 canonical manifest containing the ordered
  patterns, flags, detection/redaction algorithms, and replacement text.

The current schema keeps fixture-mode provenance narrow while allowing live
records to carry optional operational metadata such as timestamps, token counts,
latency, and estimated cost as schema-normalized strings and integers. RunSet
digests are exact artifact digests over persisted fields, not a separate
observed-value-free provenance projection. Release replay is the place where
environment-bearing review artifacts use explicit stable projections.
Privacy profile digests participate in ordinary artifact digests because the
profile ID and digest are persisted fields. On a bound RunSet, they identify
the declared persistence-time detector semantics; on an evaluation summary,
they identify the detector semantics applied by that evaluation. A current
summary produced from an unbound legacy RunSet does not recover the RunSet's
unknown original redaction profile. Profile bindings determine whether current
evidence can be compared; they do not prove that the implementation ran, that
redaction is complete, or that an artifact was produced by a trusted party.
