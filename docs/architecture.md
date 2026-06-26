# Architecture

The current implementation establishes the trust core:

- strict schemas in `src/agent_assure/schema`;
- YAML authoring and compilation in `src/agent_assure/authoring`;
- digest projection and RFC 8785 canonical bytes in `src/agent_assure/canonical`;
- privacy filters in `src/agent_assure/privacy`;
- OpenTelemetry-aligned span-plan preview in `src/agent_assure/telemetry`.

Future releases add fixture execution, evaluation, reporting, comparison, and
release evidence workflows.
