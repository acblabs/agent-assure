# ADR 0012: Signature Claim Boundary

Status: accepted

## Context

Cryptographic signatures and content digests are important integrity controls,
but they are easily mistaken for evidence that the signed conclusion is
correct.

## Decision

A digest identifies content. A verified signature can establish that exact
bytes were signed by an identity accepted under a declared verification
policy. A transparency receipt can establish inclusion under that service's
rules.

None of these mechanisms establishes that an artifact is correct, sufficient,
safe, compliant, or suitable for a particular release decision. Those
conclusions remain bounded by the underlying evidence method and accountable
review process.

## Consequences

- User-facing wording distinguishes digest, signature, signer identity, and
  transparency inclusion.
- Verification output reports integrity and identity facts without upgrading
  the source evidence state.
- Release review continues to inspect prerequisites, findings, assumptions,
  and limitations.
