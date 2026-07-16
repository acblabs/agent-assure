# Dependency Locking

Release bundles include environment provenance, a dependency inventory, and an
SBOM that records the local release build environment and distribution file
hashes. Release workflows, TestPyPI candidate builds, and local release runbooks
install from the checked-in `requirements.lock` with
`pip install --require-hashes` before installing the package with `--no-deps`.
The lockfile path and digest are captured in the evidence packet environment
section.

`requirements.lock` is generated from `pyproject.toml` with Python 3.14 and
`pip-compile --all-build-deps --extra=dev --generate-hashes`. Python 3.14 is
part of the supported CI matrix and is the canonical release environment until
a cross-OS reproducibility matrix exists.

To refresh the lockfile:

```bash
pip-compile pyproject.toml --extra dev --all-build-deps --generate-hashes --output-file requirements.lock
```

The RFC 8785 dependency is part of the digest trust core and is pinned exactly in
`pyproject.toml`.

Optional framework smoke jobs use dedicated Python 3.11/Linux lockfiles so the
real framework dependency is installed instead of allowing an import-gated test
to skip:

- `requirements-langgraph.lock` covers the development and LangGraph extras;
- `requirements-adk.lock` covers the development and Google ADK extras.

Refresh the ADK smoke lock with:

```bash
uv --cache-dir .tmp/uv-cache pip compile pyproject.toml \
  --extra dev \
  --extra adk \
  --generate-hashes \
  --python-version 3.11 \
  --python-platform x86_64-unknown-linux-gnu \
  --output-file requirements-adk.lock
```

The ADK CI job also performs an unconditional `google.adk.events.event` import
before pytest. A missing optional dependency therefore fails the compatibility
job instead of producing a green skip.
