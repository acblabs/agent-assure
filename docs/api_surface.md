# API Surface

The current stable public surface is intentionally narrow:

- the `agent-assure` CLI;
- versioned persisted JSON schemas under `schemas/v0.1.0`;
- importable schema models under `agent_assure.schema`;
- fixture-mode helpers used by the bundled examples.

The wheel also includes `agent_assure.examples.*` modules so the offline example
suites remain reproducible after installation. These modules are bundled
demonstration subjects, not a stable extension API. Their runner identifiers are
registered for the repository's fixed examples and may change before a public
adapter API is introduced.

External projects should treat persisted artifacts and CLI behavior as the
primary integration points for v0.1.
