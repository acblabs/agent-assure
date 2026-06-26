# Dependency Locking

The current implementation documents the lockfile approach but does not publish
a release bundle. Before a public release, generate a hash-pinned dependency
lock using one of these approved paths:

- `uv lock` plus a hash-verified export for CI installation;
- `pip-compile --generate-hashes` for a checked-in requirements lock.

The RFC 8785 dependency is part of the digest trust core and is pinned exactly in
`pyproject.toml`.
