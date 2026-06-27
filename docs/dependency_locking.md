# Dependency Locking

Release bundles include environment provenance, a dependency inventory, and an
SBOM that records the local release build environment and distribution file
hashes. If a checked-in lockfile exists, its path and digest are also captured
in the evidence packet environment section.

A hash-pinned dependency lock should be generated with one of these approved
paths before using release evidence as a long-lived supply-chain reference:

- `uv lock` plus a hash-verified export for CI installation;
- `pip-compile --generate-hashes` for a checked-in requirements lock.

The RFC 8785 dependency is part of the digest trust core and is pinned exactly in
`pyproject.toml`.
