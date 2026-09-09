# Dependency Locking

Release bundles include environment provenance, a dependency inventory, and an
SBOM that records the local release build environment and distribution file
hashes. Release workflows, TestPyPI candidate builds, and local release runbooks
install from the checked-in `requirements.lock` with
`pip install --require-hashes` before installing the package with `--no-deps`.
The lockfile path and digest are captured in the evidence packet environment
section.

`requirements.lock` is generated from `pyproject.toml` with Python 3.14.6 and
`pip-compile --all-build-deps --extra=dev --generate-hashes`. Python 3.14 is
part of the supported CI matrix. Python 3.14.6 is the canonical producer for
release and evidence workflows until an intentional runtime-identity update or
a cross-OS reproducibility matrix is reviewed. Compatibility CI continues to
exercise the supported minor versions independently.

To refresh the lockfile:

```bash
pip-compile pyproject.toml --extra dev --all-build-deps --generate-hashes --output-file requirements.lock
```

The RFC 8785 dependency is part of the digest trust core and is pinned exactly in
`pyproject.toml`.

Optional framework smoke jobs use dedicated lockfiles so the real framework
dependency is installed instead of allowing an import-gated test to skip. The
ADK and OpenTelemetry locks target CPython 3.11 on x86-64 Linux. The LangGraph
lock uses a universal Python 3.11 resolution so the same checked-in file also
supports cross-platform integration development; its CI job installs the Linux
branch:

- `requirements-langgraph.lock` covers the development and LangGraph extras;
- `requirements-adk.lock` covers the development and Google ADK extras; and
- `requirements-otel.lock` covers the development and OpenTelemetry extras.

Refresh the LangGraph smoke lock with:

```bash
uv --cache-dir .tmp/uv-cache pip compile pyproject.toml \
  --extra dev \
  --extra langgraph \
  --generate-hashes \
  --python-version 3.11 \
  --universal \
  --output-file requirements-langgraph.lock
```

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

The OpenTelemetry extra is intentionally pinned to the exact tested 1.44.0
API, SDK, and OTLP HTTP exporter tuple because transport isolation verifies
private OTLP HTTP exporter state before export. Refresh its Python 3.11/Linux
lock with:

```bash
uv --cache-dir .tmp/uv-cache pip compile pyproject.toml \
  --extra dev \
  --extra otel \
  --generate-hashes \
  --python-version 3.11 \
  --python-platform x86_64-unknown-linux-gnu \
  --output-file requirements-otel.lock
```

The dedicated OTel contract job unconditionally imports the API, SDK, and OTLP
HTTP exporter before running the complete telemetry SDK and OTel CLI test files
against the real SDK and exporter. Its pytest policy converts every skip into a
failure. Missing or incompatible optional dependencies therefore cannot turn
those contract tests into a successful skip.

## Source freshness and controlled regeneration

Each checked-in Python lock carries a
`source-dependency-input-sha256` header. The digest covers a canonical
projection of only the dependency-resolution inputs in `pyproject.toml`:
`build-system.requires`, `project.requires-python`, `project.dependencies`, and
`project.optional-dependencies`. Unrelated formatter, coverage, or tool
configuration changes therefore do not stale every lock. Run the offline check
with:

```bash
python scripts/check_dependency_lock_freshness.py
```

The unit regression runs under the normal `make check` test suite. A declared
dependency or supported-Python change without a corresponding marker refresh
fails repository checks. The marker is a review aid, not proof that a resolver
produced the lock: reviewers must still inspect the resolved diff, generator
identity, hashes, platform/Python targets, hash-required installs, audits, and
release reproduction evidence.

Dependabot may propose changes to declared Python dependencies, but it does not
reliably regenerate these project-specific `pip-compile` and `uv` hash locks
across their distinct Python and platform targets. Agent Assure therefore does
not let a bot rewrite and commit transitive lock output automatically. The
strongest safe partial automation is advisory discovery plus the offline source
freshness failure; a maintainer performs the documented controlled regeneration
commands and reviews the resulting lock diffs. This deliberate limitation
avoids presenting an unaudited resolver rewrite as an approved dependency
update.

## Automated security monitoring

Dependabot checks both Python and GitHub Actions dependencies weekly. The
`security` workflow runs SHA-pinned CodeQL analysis on pushes, pull requests,
and a weekly schedule; reviews dependency changes on pull requests; and audits
all four hash-locked Python dependency sets on direct updates to `main`, manual
dispatches, and a weekly schedule. Each lockfile is passed to a separate pinned
audit-action invocation using only supported action inputs. Dependency auditing
disables dependency resolution for each lock; the pinned action may still
create an isolated audit environment while processing it.

For a targeted advisory remediation, add
`--upgrade-package <distribution-name>` to each applicable compile command,
review the resulting diff to confirm that unrelated version pins did not move,
and retain only resolver- or downloader-produced hashes. Validate every changed
lock with a hash-required install and dependency audit before committing it.

These controls report published advisories; they do not prove that dependencies
are vulnerability-free. A lock update remains subject to normal tests,
CODEOWNER review, hash review, and release reproducibility checks.
