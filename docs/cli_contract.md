# CLI Contract

Current commands:

- `agent-assure --help`
- `agent-assure validate PATH --kind KIND`
- `agent-assure schema export --out DIR`
- `agent-assure suite lint PATH`
- `agent-assure suite compile PATH --out PATH [--manifest PATH]`
- `agent-assure suite run COMPILED_SUITE_JSON --variant VARIANT_YAML --out RUNSET_JSON [--manifest PATH] [--suite-digest DIGEST] [--source SUITE_YAML]`
- `agent-assure otel preview PATH [--out PATH]`

Evaluation, comparison, CI gating, and packet generation command groups exist as
placeholders and do not claim completed behavior.
