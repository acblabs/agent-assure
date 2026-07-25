# Security

Please report suspected vulnerabilities through GitHub Private Vulnerability
Reporting at
<https://github.com/acblabs/agent-assure/security/advisories/new>. Do not open a
public issue for an unremediated vulnerability. If that private form is
unavailable, contact the repository owner listed in `.github/CODEOWNERS`
through an established private channel. If no private channel is available,
request one without including exploit details in a public channel.

Maintainers should acknowledge a private report within three business days,
provide an initial severity and remediation assessment within seven business
days, and coordinate disclosure after a fix is available. These are response
targets rather than a guarantee.

Do not place production secrets, raw prompts, raw model outputs, tool arguments,
or sensitive identifiers in fixtures or persisted artifacts.

## Supported Surfaces

Security review should assume `agent-assure` is an offline-first assurance tool,
not a sandbox for untrusted repositories, untrusted scripts, untrusted live
adapters, or malicious CI jobs.

Report issues privately when they allow unexpected code execution, data
exfiltration, secret persistence, path escape, artifact forgery across a stated
trust boundary, or network egress beyond the documented adapter and telemetry
controls.

## Intentional Boundaries

- The external-script live adapter intentionally executes configured host code
  with caller privileges. Only run it for trusted configs and trusted
  repositories.
- Live adapters and providers are trusted producers of observation records; the
  tool evaluates the records but does not attest provider behavior.
- Pattern redaction is a guardrail, not comprehensive DLP or PHI
  de-identification.
- The bundled demo's Python `sitecustomize` network guard is advisory
  defense-in-depth for trusted bundled code, not a sandbox or network-isolation
  boundary. Demo subprocess environments are minimized, but hostile code can
  bypass Python-level monkeypatches.
- HTTPS, endpoint allowlisting, and DNS safety screening reduce SSRF risk but do
  not provide TLS pinning, socket-level IP pinning, or protection from a fully
  compromised resolver.

## Operator Guidance

- Prefer fixture and static JSONL modes for untrusted pull requests.
- Do not enable `external-script`, `allow_network`, or `script_env_allowlist`
  for forked or otherwise untrusted CI jobs.
- In non-interactive live CI, require `--trust-config` plus the matching
  risk-specific flags and keep endpoint DNS screening strict.
- Treat `requirements*.lock`, release manifests, and generated evidence packets
  as part of the reviewed release material.
