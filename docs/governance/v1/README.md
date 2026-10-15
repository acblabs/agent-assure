# Agent Assure v1 S1 governance records

This directory contains the noninstallable S1 `governed-baseline` records for
release `1.0.0a1` on train `stable-1.0`. They are planning and development
governance only: they do not change package behavior, admit a method, qualify a
profile, authorize a release, or authorize deployment/runtime activity.

Lifecycle statement: the result commit contains the human-approved roster and
signing key, signed kickoff authorizations, confirmed forecast decisions, and
the twice-signed forecast. `NO_INDEPENDENT_REVIEW` is explicit. Those records
alone are not final acceptance: authoritative accepted status additionally
requires signed completion receipts, the signed bundle, the exact Git closure,
and the separately signed current-gate attestation stored in the fixed annotated
acceptance tag.

## Record set

- `approval-roster.json` records all 38 roadmap roles. Only `technical_lead` and
  `repository_maintainer` are staffed by `acblabs`; every future or independent
  responsibility is explicitly unfilled.
- `maintainer-signing-key.json` declares the S1-only Ed25519 public key and
  fingerprint, with the human confirmation evidence and narrow trust scope.
- `baseline-observations.json` binds the fetched Git base, local environment,
  lock digests, CLI reservation probe, baseline checks, and their limitations.
- The two signed `kickoff-authorization-*.json` files are separate, bounded
  authorizations for `V1-BOOT-01` and `V1-BASE-01`.
- `delivery-forecast.aggregation-registry.json` freezes the only admitted
  planning calculation, `comonotonic-quantile-sum/v1`, and its immutable
  definition digest.
- `delivery-forecast.authoring-ledger.json` contains 68 ticket rows and 121
  ordered occurrence proposals with accountable human confirmations.
- `delivery-forecast.json` is the recomputable, twice-signed planning forecast
  accepted only for the recorded bounded-development scope.
- `completion-report-*.md`, `completion-receipt-*.json`, and
  `governance-bundle.json` report and bind the two-ticket S1 result. Any receipt
  or bundle whose status or signature remains pending has no authorization
  effect.
- Every JSON record type has a colocated Draft 2020-12 schema. Semantic checks,
  digest recomputation, Git provenance checks, and SSH signature verification
  are implemented by `scripts/v1_s1_governance.py`.

All domain-separated JSON digests use RFC 8785. Signed envelopes use OpenSSH
SSHSIG with Ed25519, namespace `agent-assure-governance-v1`, SHA-512 message
hashing, canonical LF armor, and canonical outer base64. Record validity is a
half-open interval no longer than 30 days. Forecast expiry is additionally
bounded to 30 days after the oldest row-level decision time, so regenerating a
wrapper cannot make stale estimate decisions current.

Governed Git and SSHSIG operations do not resolve tools through `PATH`. They
verify the absolute path, byte length, SHA-256 digest, and absence of reparse
points for the three Windows baseline executables recorded in
`baseline-observations.json`: Git, its HTTPS transport helper, and
`ssh-keygen`. Repository-local Git configuration is restricted to a benign
allowlist; includes, hooks, fsmonitor, credentials, URL rewrites, custom
transports, proxy/TLS overrides, filters, external diffs, alternate object
stores, grafts, and replacement refs fail closed. Every Git subprocess also
uses a fresh empty hooks directory and closed protocol policy.

Strict acceptance paths remeasure executable identity and rederive repository,
ref, signature, and time-bound decisions from the current trusted inputs;
caller-supplied trust booleans or executable names are never evidence. The
current-gate attestation is rendered as deterministic canonical JSON, and the
historical validator requires the annotated-tag message to contain those exact
signed bytes.

Before running any command below, verify the frozen executable identities in
the same PowerShell process. The three Git/OpenSSH identities match
`baseline-observations.json`; the base interpreter and its Python DLL match the
validator bootstrap. A relative path, virtual-environment shim, or `PATH`
lookup is not a substitute.

```powershell
$BasePythonRoot = 'C:\Users\user\AppData\Roaming\uv\python\cpython-3.12.13-windows-x86_64-none'
$BasePython = Join-Path $BasePythonRoot 'python.exe'
$BasePythonDll = Join-Path $BasePythonRoot 'python312.dll'
$PowerShellExe = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
$GovernanceLauncher = Join-Path (Get-Location) 'scripts\v1_s1_governance.ps1'
$GitExe = 'C:\Program Files\Git\mingw64\bin\git.exe'
$GitHttpsExe = 'C:\Program Files\Git\mingw64\libexec\git-core\git-remote-https.exe'
$SshKeygenExe = 'C:\Windows\System32\OpenSSH\ssh-keygen.exe'

$ExpectedTools = @(
  [pscustomobject]@{ Path = $BasePython; Size = 91648; Sha256 = '88b9e780cfdc38597c7f53e20f7165262befa28d9a5e9470360d349e172ecf37' },
  [pscustomobject]@{ Path = $BasePythonDll; Size = 6969856; Sha256 = 'cf1be428af1ee607d8015e27411912276b9b02815a080457a1ece46c59d9b314' },
  [pscustomobject]@{ Path = $GitExe; Size = 4422544; Sha256 = 'cab4c4eea1d869cf9f7be73868dc9a90ad2df1b1b673e5f8c8714a576c25ea96' },
  [pscustomobject]@{ Path = $GitHttpsExe; Size = 2629024; Sha256 = 'f4c9d7f2f85b795603f501c25ad63fff82fce233ae0fc3d48e4e3c8669e5d788' },
  [pscustomobject]@{ Path = $SshKeygenExe; Size = 861184; Sha256 = 'c9dc170cd161db87e75eb6cf282f1325005b9e35628b9a36cb19883a8be1a34f' }
)

foreach ($Tool in $ExpectedTools) {
  $Item = Get-Item -LiteralPath $Tool.Path -Force -ErrorAction Stop
  $Hash = (Get-FileHash -LiteralPath $Tool.Path -Algorithm SHA256 `
    -ErrorAction Stop).Hash.ToLowerInvariant()
  $IsReparsePoint = ($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
  if (-not $Item.PSIsContainer -and -not $IsReparsePoint -and
      $Item.Length -eq $Tool.Size -and $Hash -eq $Tool.Sha256) { continue }
  throw "Frozen executable identity mismatch: $($Tool.Path)"
}

function Invoke-S1Governance {
  & $PowerShellExe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass `
    -File $GovernanceLauncher @args
  if ($LASTEXITCODE -ne 0) { throw "S1 governance command failed: $LASTEXITCODE" }
}
```

Run that verification immediately before starting the ceremony and again after
resuming any paused ceremony. All examples below use only the verified absolute
paths retained in `$PowerShellExe`, `$GitExe`, and `$SshKeygenExe`. Windows
PowerShell, .NET cryptography, and the Windows loader are part of the explicit
OS trust base. Before Python starts, the launcher rejects reparse points,
clears OpenSSL code-loading variables, constrains child executable search,
creates a fresh pre-start bytecode-cache prefix, and verifies the closed base
runtime inventory (2,766 non-cache files, 54,224,916 bytes,
domain-separated SHA-256
`4e2b76aeadc0f328a00b520b2dc6cb4991486eaa9496b18d5035bac7b63ea152`).
It rejects sourceless bytecode outside excluded `__pycache__` directories.
The governance program rechecks that inventory and the closed third-party
runtime inventory (116 files, 1,581,377 bytes, domain-separated SHA-256
`a8a4451bde03104cc2a6dae38a30ae0bef63f717a39e5b996e05c10b83fdae02`)
before importing it. The only admitted runtime roots are `attr`, `attrs`,
`jsonschema`, `jsonschema_specifications`, `referencing`, `rfc8785`, `rpds`,
and `typing_extensions.py`.

## Local draft generation and validation

The private roadmap is an input only. The validator requires it at the exact
repository-root path, absent from the index and reachable history, and excluded
through `.git/info/exclude`. Every supported CLI command goes through the frozen
external launcher, which starts the absolute base interpreter in
isolated/no-site mode with suppressed bytecode writes and the exact `-I -S -B`
flag profile. Direct script execution and imported calls to `main()` are
rejected. Imported internal functions are unit-test seams, not a supported or
authoritative command interface and not a Python-process security boundary.

```powershell
Invoke-S1Governance generate-draft `
  --roadmap Agent_Assure_Implementation_Roadmap.md `
  --output docs\governance\v1 `
  --issued-at <trusted-UTC-time> `
  --valid-until <trusted-UTC-time-no-more-than-30-days-later> `
  --person-id acblabs `
  --repository-root .

Invoke-S1Governance assemble-draft `
  --roadmap Agent_Assure_Implementation_Roadmap.md `
  --governance-dir docs\governance\v1 `
  --issued-at <trusted-UTC-time> `
  --valid-until <trusted-UTC-time-no-more-than-30-days-later> `
  --repository-root .

Invoke-S1Governance check `
  --roadmap Agent_Assure_Implementation_Roadmap.md `
  --governance-dir docs\governance\v1 `
  --repository-root . `
  --allow-pending `
  --commitment-time <trusted-UTC-time>
```

`--replace-pristine-drafts` may replace only wholly unsigned machine drafts
whose human decision fields are untouched. `--allow-pending` is solely a
non-accepting check of a self-consistent draft or in-progress record set. The
equivalent `make v1-governance-check-nonaccepting` target requires
`V1_GOVERNANCE_COMMITMENT_TIME=<trusted-UTC-time>` explicitly. Strict checking
instead requires exactly one of `--accept-now` or `--historical`. Current
checking requires an explicit trusted gate time; historical checking derives
that time from the signed fixed-tag attestation and rejects a caller-supplied
substitute.

## Human-only acceptance and signing boundary

The three ordered record phases require seven human signatures. A final,
eighth SSHSIG attests the successful live closure gate before acceptance can be
historically claimed. The acceptance commands prepare immutable claim bytes,
verify externally created SSHSIG files against the repository public key, and
install verified record batches under a process lock with a plan-bound recovery
journal. This establishes process serialization and recovery after a process
crash; Windows sudden-power-loss atomicity or durability is not established.
The commands never read, receive, generate, or use the maintainer's private key,
and they never sign or make a human decision. The private key must remain in
human-controlled storage outside the repository. The human signs each reviewed
`*.claim` file separately with the verified absolute OpenSSH executable:

```powershell
& $SshKeygenExe -Y sign -f <human-controlled-private-key-path> `
  -n agent-assure-governance-v1 -O hashalg=sha512 <reviewed-claim-file>
```

OpenSSH writes `<reviewed-claim-file>.sig` next to the claim. The human must
inspect the claim and its plan, confirm the displayed plan digest out of band,
and supply that exact digest to `acceptance-import`. A plan directory, decision
worksheet, pathspec, claim, or signature under `.tmp/s1-acceptance/` is local
ceremony material: it must remain outside the Git index. Each preparation
command requires a new path and refuses to overwrite an existing plan.

The commands below define the ceremony mechanics. Current status is asserted
only by the signed JSON, exact Git objects, and fixed-tag attestation—not by the
illustrative command sequence.

### Ceremony preparation

Immediately before the ceremony, the human requires a live authoritative
repository preflight. The network observation uses the literal approved HTTPS
URL in a temporary bare repository with system, global, and worktree Git
configuration excluded; it queries and fetches the exact main and annotated-tag
objects without mutating the working repository's tracking refs:

```powershell
Invoke-S1Governance acceptance-preflight `
  --repository-root . `
  --fetch

Invoke-S1Governance acceptance-decision-template `
  --roadmap Agent_Assure_Implementation_Roadmap.md `
  --governance-dir docs\governance\v1 `
  --output .tmp\s1-acceptance\human-decisions.json `
  --repository-root .
```

The worksheet has no authorization effect. The accountable human must review
and deliberately complete it: set the roster to `approved` only after reviewing
identity, conflicts, capacity and lack of a backup; set the key to
`confirmed_by_human` only after verifying control of the displayed fingerprint,
recording out-of-band evidence, and removing the now-false pending limitation;
accept the unattested-host-UTC limitation; and review every ticket row and every
release occurrence. Each row and occurrence needs either
`affirmatively_reconfirmed_after_inventory` or
`reestimated_after_inventory`, the accountable identity and time, and a
specific rationale wherever re-estimated. All six affirmations and all
human-controlled decision fields must reflect the human's own judgment before
phase 1 can validate.

Set the ledger's `issued_at_utc` to a trusted time at or after every
row/occurrence confirmation and no later than the phase-1 forecast issue time;
do not backdate confirmations to the machine-draft issue time.

### Phase 1 — signed predecessors

```powershell
Invoke-S1Governance acceptance-prepare `
  --phase predecessors `
  --roadmap Agent_Assure_Implementation_Roadmap.md `
  --governance-dir docs\governance\v1 `
  --plan-dir .tmp\s1-acceptance\phase-1-predecessors `
  --decisions .tmp\s1-acceptance\human-decisions.json `
  --issued-at <trusted-UTC-time> `
  --valid-until <trusted-UTC-time-no-more-than-30-days-later> `
  --signed-at <human-signature-UTC-time> `
  --repository-root .
```

After inspecting `plan.json` and recording its `plan_digest`, the human must not
alter the plan, exported claims, or hashed source records. The human signs
exactly four exported claims: `kickoff-base.claim`, `kickoff-boot.claim`,
`forecast-producer.claim`, and `forecast-acceptance.claim`. The same no-mutation
rule applies between preparation and import in every
phase; source drift, claim drift, a plan-digest mismatch, or an extra/missing
signature fails closed. Place each SSHSIG at the adjacent `.claim.sig` path,
then import the phase:

```powershell
Invoke-S1Governance acceptance-import `
  --roadmap Agent_Assure_Implementation_Roadmap.md `
  --governance-dir docs\governance\v1 `
  --plan-dir .tmp\s1-acceptance\phase-1-predecessors `
  --expected-plan-digest <phase-1-plan-digest> `
  --commitment-time <trusted-UTC-time> `
  --repository-root .
```

The import verifies and installs the approved roster, confirmed public-key
record, reviewed authoring ledger, two signed kickoffs, and twice-signed
forecast. It cannot create any of those four signatures itself.

### Reviewed result commit R

After phase 1, generate and use the exact NUL-delimited staging pathspec:

```powershell
Invoke-S1Governance acceptance-result-paths `
  --roadmap Agent_Assure_Implementation_Roadmap.md `
  --governance-dir docs\governance\v1 `
  --output .tmp\s1-acceptance\result-paths.nul `
  --commitment-time <trusted-UTC-time> `
  --repository-root .

& $GitExe add --pathspec-from-file=.tmp/s1-acceptance/result-paths.nul --pathspec-file-nul
& $GitExe diff --cached --name-status
& $GitExe commit -m "Complete governed S1 baseline result"
$R = & $GitExe rev-parse HEAD
```

The human must review the staged bytes before creating `R`. The exact net scope
from pinned base `3b060f4da94f4d0d80e7ae507580fce82ef9bf96` through `R` is these 29
regular-file additions or modifications, with no other path:

```text
.github/workflows/ci.yml
Makefile
docs/adr/0016-v1-repository-map.md
docs/governance/v1/README.md
docs/governance/v1/approval-roster.json
docs/governance/v1/approval-roster.schema.json
docs/governance/v1/baseline-observations.json
docs/governance/v1/baseline-observations.schema.json
docs/governance/v1/completion-report-v1-base-01.md
docs/governance/v1/completion-report-v1-boot-01.md
docs/governance/v1/delivery-forecast.aggregation-registry.json
docs/governance/v1/delivery-forecast.aggregation-registry.schema.json
docs/governance/v1/delivery-forecast.authoring-ledger.json
docs/governance/v1/delivery-forecast.authoring-ledger.schema.json
docs/governance/v1/delivery-forecast.json
docs/governance/v1/delivery-forecast.schema.json
docs/governance/v1/governance-bundle.schema.json
docs/governance/v1/kickoff-authorization-v1-base-01.json
docs/governance/v1/kickoff-authorization-v1-boot-01.json
docs/governance/v1/kickoff-authorization.schema.json
docs/governance/v1/maintainer-signing-key.json
docs/governance/v1/maintainer-signing-key.schema.json
docs/governance/v1/ticket-completion-receipt.schema.json
mkdocs.yml
scripts/v1_s1_governance.ps1
scripts/v1_s1_governance.py
tests/integration/test_v1_s1_historical_check.py
tests/unit/governance/test_v1_s1_governance.py
tests/unit/release/test_coverage_gate.py
```

`R` must be the direct, non-merge child of the pinned base. Its diff must use
only Git `A` or `M` status and contain every and only the 29 paths above.
Neither completion receipt nor `governance-bundle.json` belongs in `R` because
each must bind the already reviewed result commit.

### Phase 2 — signed completion receipts

Only after the human has reviewed and created `R` may phase 2 bind it:

```powershell
Invoke-S1Governance acceptance-prepare `
  --phase completions `
  --roadmap Agent_Assure_Implementation_Roadmap.md `
  --governance-dir docs\governance\v1 `
  --plan-dir .tmp\s1-acceptance\phase-2-completions `
  --result-commit $R `
  --issued-at <trusted-UTC-time> `
  --valid-until <trusted-UTC-time-no-more-than-30-days-later> `
  --signed-at <human-signature-UTC-time> `
  --commitment-time <trusted-UTC-time> `
  --repository-root .
```

The human reviews the result inventory and signs `completion-base.claim` and
then `completion-boot.claim`, preserving the canonical BASE-before-BOOT close
order. Import the phase with its separately confirmed plan digest:

```powershell
Invoke-S1Governance acceptance-import `
  --roadmap Agent_Assure_Implementation_Roadmap.md `
  --governance-dir docs\governance\v1 `
  --plan-dir .tmp\s1-acceptance\phase-2-completions `
  --expected-plan-digest <phase-2-plan-digest> `
  --commitment-time <trusted-UTC-time> `
  --repository-root .
```

### Phase 3 — signed governance bundle

Only after both signed completion receipts verify may phase 3 derive and bind
the complete bundle:

```powershell
Invoke-S1Governance acceptance-prepare `
  --phase bundle `
  --roadmap Agent_Assure_Implementation_Roadmap.md `
  --governance-dir docs\governance\v1 `
  --plan-dir .tmp\s1-acceptance\phase-3-bundle `
  --issued-at <trusted-UTC-time> `
  --valid-until <trusted-UTC-time-no-more-than-30-days-later> `
  --signed-at <human-signature-UTC-time> `
  --commitment-time <trusted-UTC-time> `
  --repository-root .
```

The human reviews and signs exactly `governance-bundle.claim`, then imports it:

```powershell
Invoke-S1Governance acceptance-import `
  --roadmap Agent_Assure_Implementation_Roadmap.md `
  --governance-dir docs\governance\v1 `
  --plan-dir .tmp\s1-acceptance\phase-3-bundle `
  --expected-plan-digest <phase-3-plan-digest> `
  --commitment-time <trusted-UTC-time> `
  --repository-root .
```

### Closure commit C and strict checks

Create `C` as the direct child of `R`. Its diff from `R` must add or modify
exactly the two signed receipts and signed bundle, and no other path:

```powershell
& $GitExe add -- `
  docs/governance/v1/completion-receipt-v1-base-01.json `
  docs/governance/v1/completion-receipt-v1-boot-01.json `
  docs/governance/v1/governance-bundle.json
& $GitExe diff --cached --name-status
& $GitExe commit -m "Close governed S1 baseline acceptance"
$C = & $GitExe rev-parse HEAD
```

Current acceptance starts with a one-time gate at a clean checkout whose `HEAD`
is exactly `C`. The isolated authoritative query and fetch are mandatory and
are performed again by the strict command. `--accept-now` is rejected without
`--fetch-authoritative-refs`, a new ignored attestation-plan directory, and a
planned human-signature time no earlier than and no more than one hour after
the gate:

The clean-checkout gate includes all unignored untracked files. Preserve the
user-owned `.claude/settings.local.json`; if it is intentionally retained for
the ceremony, exclude `.claude/` locally in `.git/info/exclude` rather than
staging, deleting, or adding it to the versioned `.gitignore`. Confirm the
resulting status is otherwise empty before running the gate.

```powershell
Invoke-S1Governance check `
  --roadmap Agent_Assure_Implementation_Roadmap.md `
  --governance-dir docs\governance\v1 `
  --repository-root . `
  --accept-now `
  --fetch-authoritative-refs `
  --commitment-time <trusted-current-gate-UTC-time> `
  --attestation-plan-dir .tmp\s1-acceptance\current-gate-attestation `
  --attestation-signed-at <planned-human-signature-UTC-time>
```

This command does **not** yet return an accepted result. It returns
`valid_current_closure_attestation_prepared`, plus the attestation digest, only
after validating the signed records, exact closure, clean checkout, pinned
tools/configuration, and authoritative refs. The plan contains
`attestation.pending.json` and `attestation.claim`. The human reviews both,
records the displayed attestation digest out of band, and signs exactly the
claim:

```powershell
& $SshKeygenExe -Y sign -f <human-controlled-private-key-path> `
  -n agent-assure-governance-v1 -O hashalg=sha512 `
  .tmp\s1-acceptance\current-gate-attestation\attestation.claim

Invoke-S1Governance `
  acceptance-attestation-finalize `
  --plan-dir .tmp\s1-acceptance\current-gate-attestation `
  --expected-attestation-digest <human-confirmed-attestation-digest> `
  --repository-root .
```

The finalizer verifies the eighth external SSHSIG and writes
`attestation.signed.json`; it cannot sign. Store that exact signed record as the
message of the fixed annotated tag. The repository enables automatic tag
signing, so explicitly disable the redundant Git-level signature: the
attestation inside the message is already signed under the frozen S1 namespace
and binds the tag name and `C`.

```powershell
& $GitExe -c tag.gpgSign=false tag --annotate --cleanup=verbatim `
  --file=.tmp/s1-acceptance/current-gate-attestation/attestation.signed.json `
  agent-assure-s1-1.0.0a1-acceptance $C
$A = & $GitExe rev-parse 'refs/tags/agent-assure-s1-1.0.0a1-acceptance^{tag}'
```

Record the full 40-hex `C` and tag object `$A`. Final acceptance is established
only when historical validation verifies that immutable tag object. The
validator derives the trusted commitment time from the signed attestation; a
caller-supplied historical time is forbidden. After later commits, it reads the
governed JSON from explicit `C` and requires `C` to remain the unique valid
closure on the current `HEAD` lineage:

```powershell
Invoke-S1Governance check `
  --roadmap Agent_Assure_Implementation_Roadmap.md `
  --governance-dir docs\governance\v1 `
  --repository-root . `
  --historical `
  --closure-commit <full-40-hex-C> `
  --acceptance-tag-object <full-40-hex-A>
```

Historical checking does not substitute a guessed closure and does not accept
the mutable worktree as evidence. It verifies the explicit commit's signed
records, exact `R`/`C` scopes, ancestry and uniqueness, plus the fixed tag's
embedded SSHSIG, closure/bundle/result bindings, authoritative-ref evidence,
validator digest, and one-hour gate-to-signature bound. The signed attestation
is accountable human evidence that the live check occurred; it is not an
independent attestation of the host clock or remote service.

The durable Make wrapper requires the same two immutable Git object IDs:

```powershell
make v1-governance-check `
  V1_GOVERNANCE_CLOSURE_COMMIT=<full-40-hex-C> `
  V1_GOVERNANCE_ACCEPTANCE_TAG_OBJECT=<full-40-hex-A>
```
