# MITRE ATLAS Crosswalk

This is a planning crosswalk only. It maps `agent-assure` controls to MITRE
ATLAS adversary tactics and techniques for review, triage, and gap analysis.
It is not an ATLAS coverage claim, endorsement, or validation result.

The current mapping is pinned to:

- Source: `https://github.com/mitre-atlas/atlas-data/releases/download/v2026.06/ATLAS-2026.06.yaml`
- Release tag: `v2026.06`
- Release commit: `651dad90d3c007e797c89356fa1f4d8732f90c8d`
- Release asset SHA-256: `b771de8b1489564b2838a709c7429849a9575dbd94073928817fe1a21661e70a`
- ATLAS release: `2026.06`
- Release date: `2026-06-30`
- Artifact modified date: `2026-05-27`
- Format version: `6.0.0`
- Release announcement inventory: 16 tactics, 104 techniques, 69
  sub-techniques
- Authenticated asset inventory: 16 tactics, 103 base techniques, 70
  sub-techniques (173 technique IDs)

The release date comes from the ATLAS manifest entry for release `2026.06`.
The artifact modified date comes from the pinned YAML collection metadata.
The upstream announcement's 104/69 technique split differs by one from the
authenticated asset. The asset contains 103 undotted base IDs and 70 dotted
sub-technique IDs; those 103/70 counts are the runtime validation pin.

The machine-readable mapping lives in `docs/threat_coverage_matrix.yaml`.
ATLAS uses richer strength, tactic, and technique fields than the OWASP, NIST,
and ISO tags because ATLAS is an adversary technique catalog.

The offline ATLAS ID catalog at
`mappings/mitre_atlas_2026_06_catalog.yaml` is a production-packaged validation
input, not a test-only fixture. Runtime validation authenticates its pinned
digest and rejects tactic, technique, and MITRE control identifiers absent from
the catalog. It also requires the catalog's official name for each control ID,
self-anchors every row to that ID, and applies the subject-only
`not_applicable` contract. Default validation does not fetch the upstream URL;
update the catalog, release metadata, upstream asset pin, and runtime catalog
digest together when the matrix adopts a new ATLAS release.

## Mapping Strength

| Strength | Meaning |
| --- | --- |
| `direct` | The local control directly evaluates a boundary that is named by the ATLAS technique. |
| `partial` | The local control evaluates a deterministic artifact or report subset of a broader ATLAS technique. |
| `adjacent` | The local control supports review of a related failure mode but does not emulate the ATLAS technique. |
| `gap` | The ATLAS-relevant behavior is explicitly not evaluated by the current project scope. |
| `not_applicable` | No meaningful ATLAS adversary-technique crosswalk is declared. A MITRE report row retains exactly its own `control_id` as the sole technique subject, with no tactic IDs; that self-ID identifies the row and is not an asserted crosswalk. |

Tactics and techniques are listed as control-level unions. A row does not imply
that every listed technique maps to every listed tactic. The same ATLAS
technique can also appear as partially evaluated for one local boundary while
remaining a gap for another boundary.

`partial` and `adjacent` rows usually identify related artifact surfaces. They
are not ATLAS technique emulations and should not be summarized as full ATLAS
coverage.

## Current Control Mapping

| Control | Strength | ATLAS Tactics | ATLAS Techniques |
| --- | --- | --- | --- |
| `runtime_success_required` | `adjacent` | Impact | `AML.T0029` Denial of AI Service |
| `runset_completion_required` | `not_applicable` | None | None |
| `structured_output_required` | `not_applicable` | None | None |
| `valid_record_required` | `not_applicable` | None | None |
| `evidence_required` | `partial` | Resource Development; Defense Evasion | `AML.T0066` Retrieval Content Crafting; `AML.T0067.000` Citations |
| `material_claims_have_evidence` | `partial` | Defense Evasion | `AML.T0067.000` Citations |
| `evidence_provenance_identity` | `not_applicable` | None | None |
| `tool_allowlist` | `direct` | Execution; Collection; Exfiltration; Privilege Escalation | `AML.T0053` AI Agent Tool Invocation; `AML.T0085.001` AI Agent Tools; `AML.T0086` Exfiltration via AI Agent Tool Invocation |
| `provider_review_boundary` | `partial` | AI Model Access; Command and Control | `AML.T0040` AI Model Inference API Access; `AML.T0096` AI Service API |
| `human_review_required` | `adjacent` | Execution; Defense Evasion; Privilege Escalation | `AML.T0051` LLM Prompt Injection; `AML.T0053` AI Agent Tool Invocation; `AML.T0054` LLM Jailbreak |
| `redaction_required` | `partial` | Exfiltration | `AML.T0024` Exfiltration via AI Inference API; `AML.T0057` LLM Data Leakage; `AML.T0086` Exfiltration via AI Agent Tool Invocation |
| `prompt_injection_control_boundary` | `partial` | Initial Access; Execution; Persistence | `AML.T0051` LLM Prompt Injection; `AML.T0051.000` Direct; `AML.T0051.001` Indirect; `AML.T0051.002` Triggered; `AML.T0093` Prompt Infiltration via Public-Facing Application |
| `live_persisted_policy_results` | `partial` | Execution; Defense Evasion; Privilege Escalation | `AML.T0051` LLM Prompt Injection; `AML.T0053` AI Agent Tool Invocation; `AML.T0054` LLM Jailbreak |
| `live_config_path_confinement` | `partial` | Persistence; Discovery; Credential Access | `AML.T0081` Modify AI Agent Configuration; `AML.T0083` Credentials from AI Agent Configuration; `AML.T0084` Discover AI Agent Configuration |
| `live_openai_endpoint_allowlist` | `partial` | AI Model Access; Command and Control | `AML.T0040` AI Model Inference API Access; `AML.T0096` AI Service API |
| `external_script_output_limit` | `partial` | Execution; Impact | `AML.T0029` Denial of AI Service; `AML.T0034.001` Resource-Intensive Queries; `AML.T0034.002` Agentic Resource Consumption; `AML.T0050` Command and Scripting Interpreter |

## Current Gaps

The matrix keeps unsupported ATLAS-relevant capabilities visible instead of
turning absence of evidence into a positive result.

Gap labels below are reviewer-facing summaries. The exact machine IDs live in
`docs/threat_coverage_matrix.yaml`.

| Gap | Strength | ATLAS Techniques |
| --- | --- | --- |
| `raw_payload_persistence_forbidden` | `gap` | `AML.T0024`, `AML.T0025`, `AML.T0057`, `AML.T0086` |
| `live adapter producer verification` | `gap` | `AML.T0010`, `AML.T0010.005`, `AML.T0109`, `AML.T0110` |
| `live-stochastic-model-quality-regression` | `gap` | `AML.T0031`, `AML.T0076` |
| `context-discovery-and-stakeholder-impact-mapping` | `not_applicable` | None |
| `production-runtime-isolation` | `gap` | `AML.T0050`, `AML.T0105`, `AML.T0112`, `AML.T0112.000` |
| `safety or regulatory status` | `not_applicable` | None |

## Interpretation Boundary

`agent-assure` evaluates deterministic fixture-mode and declared live-protocol
evidence around agent pipeline behavior. It does not execute ATLAS adversary
emulations, establish that a system resists ATLAS techniques, inspect
production storage outside its own artifacts, or independently verify live
providers and adapters.
