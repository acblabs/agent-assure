# Agent Assure v1 S1 governance records

This directory contains the noninstallable S1 `governed-baseline` records for
release `1.0.0a1` on train `stable-1.0`. They are planning and development
governance only: they do not change package behavior, admit a method, qualify a
profile, authorize a release, or authorize deployment/runtime activity.

Lifecycle statement: the generation-1 result commit contains the human-approved
roster and signing key, signed kickoff authorizations, forecast decisions, and
the twice-signed forecast. `NO_INDEPENDENT_REVIEW` is explicit. A subsequent
audit found that the forecast decisions mechanically retained stale roadmap
priors and identified time-evidence, verifier-bootstrap, path-diagnostic, and
post-amendment verification gaps. Generation 2 corrected those defects and its
fixed annotated tag, signatures, and digest bindings remain immutable
historical evidence. A later adversarial review found that the generation-2
validator did not parse on the declared Python 3.11 floor, that hosted-CI tests
depended on the unavailable private roadmap, and that an ignored native Python
extension at the repository root was outside the authenticated test-surface
inventory while remaining importable. Those findings do not rewrite or prove
tampering of either earlier generation, but they make generation 2
insufficient as the current acceptance basis for S2. S2 remains blocked until
a separately authorized successor result and closure capture the repaired
controls, the complete required check graph, and new signed evidence. The tag
`agent-assure-s1-1.0.0a1-acceptance-v2` must never be moved or replaced.

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
- `corrective-kickoff-authorization.json` preserves the prospectively signed,
  bounded authorization for generation-2 remediation. It authorizes engineering
  work but no estimate, completion decision, bundle, or final acceptance.
- `delivery-forecast.aggregation-registry.json` freezes the only admitted
  planning calculation, `comonotonic-quantile-sum/v1` version `1.1.0`, under
  the generation-2 method and registry formats.
- `delivery-forecast.estimation-catalog.json` defines versioned work units and
  obligation-coverage rules for nonbinding, bottom-up generation-2 proposals;
  it cannot supply the maintainer's estimate decisions.
- `delivery-forecast.authoring-ledger.json` contains all 68 ticket rows and 121
  ordered occurrence proposals. Generation 2 requires every one to be
  `reestimated_after_inventory` from digest-bound work breakdown evidence. The
  checked-in generation-2 ledger contains the installed batch decision; the
  pending machine proposal is its immutable, digest-bound input state rather
  than the current decision status.
- `delivery-forecast.json` is the recomputable, signed generation-2 planning
  forecast. Its accepted status is historical evidence and has no S2 effect
  until a later corrective generation closes the post-v2 control findings.
- `completion-report-*.md`, `completion-receipt-*.json`, and
  `governance-bundle.json` report and bind the two-ticket S1 result. Any receipt
  or bundle whose status or signature remains pending has no authorization
  effect.
- Every JSON record type has a colocated Draft 2020-12 schema. Semantic checks,
  digest recomputation, Git provenance checks, and SSH signature verification
  are implemented by `scripts/v1_s1_governance.py`.

The generation-2 method definition, registry, and estimation-catalog digests
are, respectively,
`sha256:028ff736a0d4c7ac37a5fb15ba1ee733401a8be453569fc07b37fae6b27517f7`,
`sha256:7cac700d33f41f97156f459bf48bae5e4c65d36505aab6cb7e5c2df4acae1ba6`,
and `sha256:33cee0874eecf79f36a0dadcafa831525df206c9fdc67d9ab4759138475da439`.
The pre-decision authoring-ledger digest was
`sha256:c65573f5b9045c08b926e739c1e4491fc038bc203df80454697a23c36d4d9fbf`;
the pre-signature forecast digest was
`sha256:66d1e5a2b29f0405bbd4ef0c10c74d17c7930fd5c7f93a9140b0abc0438d0220`.
They are historical inputs, not the final installed record digests shown
below. The ledger and forecast use record format generation `/2` while
retaining the external `delivery-forecast/v1` planning-contract identity.

In those immutable v2 records, `aggregate_p50_effort_hours` and
`aggregate_p90_effort_hours` are engineering-only aggregates;
`aggregate_reviewer_effort_hours` is a separate reviewer P50 aggregate. A
combined P50 is arithmetically available under the declared shared-rank model
as `aggregate_p50_effort_hours + aggregate_reviewer_effort_hours`, or
`7,695 + 7,310 = 15,005` focused person-hours. The engineering P90 is `19,766`
person-hours, but a combined P90 is not identified because no reviewer P90
inputs were authored. The historical portfolio P90 must not be described as
including review effort; a successor must preserve that explicit separation or
add the missing reviewer quantile before claiming a combined total.

The following machine-readable block records the final installed generation-2
state. It is not a pending-work instruction. The corrective receipt planner
used it, together with the matching block in ADR 0016, to bind the accepted v2
files. A successor must preserve these values as historical facts rather than
silently regenerating or relabeling them.

<!-- agent-assure:forecast-v2-final:start -->
- Generation-2 authoring ledger status: `human_decisions_imported`; digest: `sha256:825e811fa5a0dc841e8f8a316b4fb5be1183dc5793bce90506928237ad7020ca`.
- Generation-2 delivery forecast status: `accepted`; digest: `sha256:61858dd4aaa04ee6dc202fba8384a2b264e9374e24eed7c7936793e331068b5b`.
<!-- agent-assure:forecast-v2-final:end -->

All domain-separated JSON digests use RFC 8785. Signed envelopes use OpenSSH
SSHSIG with Ed25519, namespace `agent-assure-governance-v1`, SHA-512 message
hashing, canonical LF armor, and canonical outer base64. Human-accepted record
validity is a half-open interval no longer than 30 days. A generation-2 machine
proposal leaves human decision, signature, issue, and expiry fields null until
the corresponding human step occurs. One timestamp-free, ordered batch
decision binds all 68 rows and 121 occurrences without inventing per-item
review times. Verified decision import captures issuance from host UTC at the
truthful post-verification boundary and derives expiry exactly 30 days later.

The forecast acceptance receipt does not treat key control, repository access,
or a generic role label as evidence of competence. It binds approval-roster
digest
`sha256:3959beb1e485be1d030540585e7d1cbd77e4b93fd487a5ae4ba7f8a98a3a1ca5`,
the `acblabs` identity, both staffed assignments (`repository_maintainer` and
`technical_lead`), and the roster's exact three competence scopes. It also
copies the exact three conflict disclosures and `NO_INDEPENDENT_REVIEW` into
the receipt. Schema and semantic validation reject any substitution, omission,
or roster-digest mismatch.

SSHSIG does not contain a trusted timestamp. A time inside a signed claim is a
signer-declared, host-unattested statement whose integrity is protected by the
signature; it is not proof of the instant when `ssh-keygen` performed the
signature operation. Generation-2 current-acceptance and forecast signature
envelopes therefore contain no signature-time field. Forecast plans internally
capture claim-preparation start. Final forecast import persists that observation
together with import-verification start and completion inside both forecast
signature envelopes, after both exact claims have passed SSHSIG verification.
The two evidence objects must match, and validation enforces
`issue <= preparation <= import start <= import completion < expiry`. These are
externally unattested host-UTC operational observations, not signature times;
the evidence expressly says it is excluded from the SSHSIG claim, that SSHSIG
has no timestamp capability, and that no actual signature time is claimed.
The later corrective closure inventory and signed current-acceptance
attestation bind the final forecast bytes, providing the durable integrity
boundary for those post-signature observations. Generation-1
`signed_at_utc` fields must be interpreted as signed declarations only.
Interval checks compare declarations and observations and must not be described
as independent timestamp verification.

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
ref, signature, and time-bound decisions from the current explicitly accepted
inputs;
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

### Historical-verifier bootstrap boundary

Generation-2 historical verification is run from a clean, standalone clone at
the selected corrective closure `C2`, not a linked worktree and not a validator
imported from a later checkout. A linked worktree has a `.git` indirection file
and shares mutable repository state; both violate the verifier's repository
identity contract. The operator supplies the full `C2` and generation-2
annotated-tag object identities out of band.

The standalone-clone procedure is therefore:

1. verify the supplied tag object and `C2` identities in the source repository;
2. use `clone --no-local --no-checkout` into a new absolute path, with an empty
   template, then detach exactly at `C2`;
3. prove that `.git` is a local directory, no alternate object store is active,
   the repository is not shallow, `HEAD == C2`, and status is empty;
4. install local excludes, copy the private roadmap and frozen `.venv`, and run
   the verified launcher's `--help` bootstrap to validate both pinned runtime
   inventories before any historical decision;
5. externally hash both governance entry points against the values bound by the
   v2 attestation, invoke only that launcher, and preserve the result before
   removing the disposable clone.

The accepted-host pre-run uses absolute paths. Populate the expected artifact
hashes from the supplied v2 attestation only after independently verifying its
public signature, tag-object identity, and C2 binding; do not copy them from the
files being checked. `$VerificationRoot` must be absent, and the template and
hooks directories must be empty:

```powershell
$ErrorActionPreference = 'Stop'
$SourceRepository = 'C:\Users\user\.antigravity-ide\agent-assure'
$VerificationRoot = 'C:\tmp\agent-assure-s1-v2-verify'
$EmptyTemplate = 'C:\tmp\agent-assure-empty-git-template'
$EmptyHooks = 'C:\tmp\agent-assure-empty-git-hooks'
$GitExe = 'C:\Program Files\Git\mingw64\bin\git.exe'
$C2 = '<full-40-hex-C2>'
$A2 = '<full-40-hex-generation-2-annotated-tag-object>'
$ExpectedValidatorSha256 = 'sha256:<64-lowercase-hex-from-v2-attestation>'
$ExpectedLauncherSha256 = 'sha256:<64-lowercase-hex-from-v2-attestation>'
$SourceRoadmap = Join-Path $SourceRepository 'Agent_Assure_Implementation_Roadmap.md'
$SourceVenv = Join-Path $SourceRepository '.venv'
$SourceExcludePath = Join-Path $SourceRepository '.git\info\exclude'
$VerifiedValidator = Join-Path $VerificationRoot 'scripts\v1_s1_governance.py'
$VerifiedLauncher = Join-Path $VerificationRoot 'scripts\v1_s1_governance.ps1'
$VerifiedRoadmap = Join-Path $VerificationRoot 'Agent_Assure_Implementation_Roadmap.md'
$VerifiedGovernance = Join-Path $VerificationRoot 'docs\governance\v1'

if (Test-Path -LiteralPath $VerificationRoot) {
  throw "Verification root must be absent: $VerificationRoot"
}
foreach ($EmptyDirectory in @($EmptyTemplate, $EmptyHooks)) {
  if (Test-Path -LiteralPath $EmptyDirectory) {
    if (Get-ChildItem -LiteralPath $EmptyDirectory -Force) {
      throw "Required empty directory is not empty: $EmptyDirectory"
    }
  } else {
    [void](New-Item -ItemType Directory -Path $EmptyDirectory)
  }
}

$GitPrefix = @(
  '--no-replace-objects',
  '-c', 'core.excludesFile=',
  '-c', 'core.attributesFile=',
  '-c', "core.hooksPath=$EmptyHooks"
)
$env:GIT_CONFIG_NOSYSTEM = '1'
$env:GIT_CONFIG_GLOBAL = 'NUL'
$env:GIT_ATTR_NOSYSTEM = '1'

$TagType = (& $GitExe @GitPrefix -C $SourceRepository cat-file -t $A2).Trim()
if ($LASTEXITCODE -ne 0 -or $TagType -cne 'tag') {
  throw 'A2 is not the supplied annotated-tag object.'
}
$TaggedCommit = (& $GitExe @GitPrefix -C $SourceRepository rev-parse "$A2^{commit}").Trim()
if ($LASTEXITCODE -ne 0 -or $TaggedCommit -cne $C2) {
  throw "A2 does not target C2: $TaggedCommit"
}

& $GitExe @GitPrefix clone --no-local --no-checkout `
  "--template=$EmptyTemplate" $SourceRepository $VerificationRoot
if ($LASTEXITCODE -ne 0) { throw "Standalone clone failed: $LASTEXITCODE" }
& $GitExe @GitPrefix -C $VerificationRoot remote set-url origin `
  'https://github.com/acblabs/agent-assure.git'
if ($LASTEXITCODE -ne 0) { throw 'Unable to pin the approved origin URL.' }
& $GitExe @GitPrefix -C $VerificationRoot checkout --detach $C2
if ($LASTEXITCODE -ne 0) { throw "C2 checkout failed: $LASTEXITCODE" }

$GitDirectory = Get-Item -LiteralPath (Join-Path $VerificationRoot '.git') -Force
if (-not $GitDirectory.PSIsContainer -or
    (($GitDirectory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
  throw 'Historical verification requires a local non-reparse .git directory.'
}
$Alternates = Join-Path $VerificationRoot '.git\objects\info\alternates'
if (Test-Path -LiteralPath $Alternates) {
  if ((Get-Content -LiteralPath $Alternates -Raw).Trim()) {
    throw 'Historical verification forbids alternate object stores.'
  }
}
$IsShallow = (& $GitExe @GitPrefix -C $VerificationRoot `
  rev-parse --is-shallow-repository).Trim()
if ($LASTEXITCODE -ne 0 -or $IsShallow -cne 'false') {
  throw 'Historical verification requires complete Git history.'
}
$ObservedHead = (& $GitExe @GitPrefix -C $VerificationRoot `
  rev-parse 'HEAD^{commit}').Trim()
if ($LASTEXITCODE -ne 0 -or $ObservedHead -cne $C2) {
  throw "Standalone clone HEAD does not equal C2: $ObservedHead"
}
$ClonedTagType = (& $GitExe @GitPrefix -C $VerificationRoot cat-file -t $A2).Trim()
$ClonedTaggedCommit = (& $GitExe @GitPrefix -C $VerificationRoot `
  rev-parse "$A2^{commit}").Trim()
if ($ClonedTagType -cne 'tag' -or $ClonedTaggedCommit -cne $C2) {
  throw 'Standalone clone does not contain the exact A2 -> C2 binding.'
}
$InitialStatus = & $GitExe @GitPrefix -C $VerificationRoot `
  status --porcelain=v1 --untracked-files=all
if ($LASTEXITCODE -ne 0 -or $InitialStatus) {
  throw 'Initial standalone C2 checkout is not clean.'
}

$ExpectedLegacyExcludeSizeBytes = 2368
$ExpectedLegacyExcludeSha256 = `
  '7c13bf60842aceead989daabbab30e5ae8fc3e4cf2100af9781e692790265060'
$SourceExcludeFile = Get-Item -LiteralPath $SourceExcludePath -Force -ErrorAction Stop
if ($SourceExcludeFile.PSIsContainer -or
    (($SourceExcludeFile.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
  throw 'Historical verification requires a regular non-reparse source .git\info\exclude file.'
}
$ObservedSourceExcludeSha256 = (Get-FileHash -LiteralPath $SourceExcludePath `
  -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
if ($SourceExcludeFile.Length -ne $ExpectedLegacyExcludeSizeBytes -or
    $ObservedSourceExcludeSha256 -cne $ExpectedLegacyExcludeSha256) {
  throw 'Accepted-host historical .git\info\exclude does not match the immutable v3 policy.'
}

$InfoPath = Join-Path $VerificationRoot '.git\info'
if (-not (Test-Path -LiteralPath $InfoPath)) {
  [void](New-Item -ItemType Directory -Path $InfoPath)
}
$InfoDirectory = Get-Item -LiteralPath $InfoPath -Force -ErrorAction Stop
if (-not $InfoDirectory.PSIsContainer -or
    (($InfoDirectory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
  throw 'Historical verification requires a regular non-reparse .git\info directory.'
}
$AttributesPath = Join-Path $InfoPath 'attributes'
if (Test-Path -LiteralPath $AttributesPath) {
  throw 'Historical verification requires .git\info\attributes to be absent.'
}
$ExcludePath = Join-Path $VerificationRoot '.git\info\exclude'
if (Test-Path -LiteralPath $ExcludePath) {
  throw 'Historical verification requires clone-local .git\info\exclude to be absent.'
}
[IO.File]::Copy($SourceExcludePath, $ExcludePath, $false)
$ExcludeFile = Get-Item -LiteralPath $ExcludePath -Force -ErrorAction Stop
if ($ExcludeFile.PSIsContainer -or
    (($ExcludeFile.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
  throw 'Historical verification requires a regular non-reparse clone-local .git\info\exclude file.'
}
$ObservedExcludeSha256 = (Get-FileHash -LiteralPath $ExcludePath `
  -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
if ($ExcludeFile.Length -ne $ExpectedLegacyExcludeSizeBytes -or
    $ObservedExcludeSha256 -cne $ExpectedLegacyExcludeSha256) {
  throw 'Copied historical .git\info\exclude does not match the immutable v3 policy.'
}
$SourceVenvItem = Get-Item -LiteralPath $SourceVenv -Force -ErrorAction Stop
if (-not $SourceVenvItem.PSIsContainer -or
    (($SourceVenvItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
  throw 'Historical verification requires a non-reparse source .venv directory.'
}
$VerifiedVenv = Join-Path $VerificationRoot '.venv'
if (Test-Path -LiteralPath $VerifiedVenv) {
  throw 'Historical verification refuses to overwrite the clone-local .venv path.'
}
Copy-Item -LiteralPath $SourceVenv -Destination $VerifiedVenv -Recurse
$VerifiedVenvItem = Get-Item -LiteralPath $VerifiedVenv -Force -ErrorAction Stop
if (-not $VerifiedVenvItem.PSIsContainer -or
    (($VerifiedVenvItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
  throw 'Historical verification requires a non-reparse clone-local .venv directory.'
}
```

The guarded bootstrap preflight below rejects any drift from the pinned base-Python inventory
(2,766 files, 54,224,916 bytes, SHA-256
`4e2b76aeadc0f328a00b520b2dc6cb4991486eaa9496b18d5035bac7b63ea152`)
or copied third-party inventory (116 files, 1,581,377 bytes, SHA-256
`a8a4451bde03104cc2a6dae38a30ae0bef63f717a39e5b996e05c10b83fdae02`).
Then run the historical command through the verified launcher with absolute
paths rooted at the standalone clone. The private roadmap is copied only inside
the `try` and its exact clone-local copy is removed by `finally`, including when
copy verification, bootstrap, or historical validation fails:

```powershell
$ErrorActionPreference = 'Stop'
function Remove-HistoricalVerificationRoadmap {
  param([Parameter(Mandatory = $true)][string] $CandidatePath)

  $ExpectedPath = [IO.Path]::GetFullPath(
    (Join-Path $VerificationRoot 'Agent_Assure_Implementation_Roadmap.md')
  )
  if ([IO.Path]::GetFullPath($CandidatePath) -cne $ExpectedPath) {
    throw 'Historical-verification roadmap cleanup path is not the exact clone-local path.'
  }
  try {
    $RoadmapItem = Get-Item -LiteralPath $ExpectedPath -Force -ErrorAction Stop
  }
  catch [System.Management.Automation.ItemNotFoundException] {
    return
  }
  if ($RoadmapItem.PSIsContainer -or
      (($RoadmapItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
    throw 'Historical-verification roadmap cleanup requires a regular non-reparse file.'
  }
  Remove-Item -LiteralPath $ExpectedPath -Force -ErrorAction Stop
  try {
    [void](Get-Item -LiteralPath $ExpectedPath -Force -ErrorAction Stop)
  }
  catch [System.Management.Automation.ItemNotFoundException] {
    return
  }
  throw 'Historical-verification private-roadmap cleanup did not complete.'
}

$HistoricalRoadmapCopyOwned = $false
try {
  $ExpectedRoadmapSizeBytes = 2390013
  $ExpectedRoadmapSha256 = `
    '8fc2e6e6f83b6a6ac6c27492473de8690b9360eac584131b6e8b42785f4386eb'
  $SourceRoadmapItem = Get-Item -LiteralPath $SourceRoadmap -Force -ErrorAction Stop
  if ($SourceRoadmapItem.PSIsContainer -or
      (($SourceRoadmapItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
    throw 'Historical verification requires a regular non-reparse source roadmap file.'
  }
  $SourceRoadmapSha256 = (Get-FileHash -LiteralPath $SourceRoadmap `
    -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
  if ($SourceRoadmapItem.Length -ne $ExpectedRoadmapSizeBytes -or
      $SourceRoadmapSha256 -cne $ExpectedRoadmapSha256) {
    throw 'Historical verification source roadmap does not match generation 2.'
  }
  if (Test-Path -LiteralPath $VerifiedRoadmap) {
    throw 'Historical verification refuses to overwrite the clone-local roadmap path.'
  }
  $SourceRoadmapStream = [IO.File]::Open(
    $SourceRoadmap,
    [IO.FileMode]::Open,
    [IO.FileAccess]::Read,
    [IO.FileShare]::Read
  )
  try {
    $VerifiedRoadmapStream = [IO.File]::Open(
      $VerifiedRoadmap,
      [IO.FileMode]::CreateNew,
      [IO.FileAccess]::Write,
      [IO.FileShare]::None
    )
    $HistoricalRoadmapCopyOwned = $true
    try {
      $SourceRoadmapStream.CopyTo($VerifiedRoadmapStream)
      $VerifiedRoadmapStream.Flush($true)
    }
    finally {
      $VerifiedRoadmapStream.Dispose()
    }
  }
  finally {
    $SourceRoadmapStream.Dispose()
  }
  $VerifiedRoadmapItem = Get-Item -LiteralPath $VerifiedRoadmap -Force -ErrorAction Stop
  if ($VerifiedRoadmapItem.PSIsContainer -or
      (($VerifiedRoadmapItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
    throw 'Historical verification requires a regular non-reparse clone-local roadmap file.'
  }
  $VerifiedRoadmapSha256 = (Get-FileHash -LiteralPath $VerifiedRoadmap `
    -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
  if ($VerifiedRoadmapItem.Length -ne $ExpectedRoadmapSizeBytes -or
      $VerifiedRoadmapSha256 -cne $ExpectedRoadmapSha256) {
    throw 'Historical verification clone-local roadmap copy does not match generation 2.'
  }

  $Status = & $GitExe @GitPrefix -C $VerificationRoot `
    status --porcelain=v1 --untracked-files=all
  if ($LASTEXITCODE -ne 0 -or $Status) {
    throw 'Standalone C2 checkout is not clean after installing ignored private inputs.'
  }

  $ObservedValidatorSha256 = 'sha256:' + (Get-FileHash -LiteralPath `
    $VerifiedValidator -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
  $ObservedLauncherSha256 = 'sha256:' + (Get-FileHash -LiteralPath `
    $VerifiedLauncher -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
  if ($ObservedValidatorSha256 -cne $ExpectedValidatorSha256) {
    throw 'Standalone-clone validator does not match the v2 attestation.'
  }
  if ($ObservedLauncherSha256 -cne $ExpectedLauncherSha256) {
    throw 'Standalone-clone launcher does not match the v2 attestation.'
  }

  & $VerifiedLauncher --help | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw 'Frozen runtime inventory bootstrap preflight failed.'
  }
  & $VerifiedLauncher check `
    --roadmap $VerifiedRoadmap `
    --governance-dir $VerifiedGovernance `
    --repository-root $VerificationRoot `
    --historical `
    --closure-commit $C2 `
    --acceptance-tag-object $A2
  if ($LASTEXITCODE -ne 0) {
    throw "Generation-2 historical validation failed: $LASTEXITCODE"
  }
}
finally {
  if ($HistoricalRoadmapCopyOwned) {
    Remove-HistoricalVerificationRoadmap -CandidatePath $VerifiedRoadmap
  }
}
```

The validator rechecks that the roadmap is ignored through `.git/info/exclude`,
absent from the index and reachable history, and that its exact blob ID is
absent from the complete local Git object database. Never stage, upload, or
copy it to a hosted runner.

Preserve any required validation transcript outside `$VerificationRoot`. The
`finally` path above is deliberately exact-file, non-recursive, and
reparse-resistant; it runs before any broader disposable-clone cleanup.

A validator reporting its own hash is useful consistency evidence, but is not a
trust root: unverified code can lie about its own bytes. The external pre-run
comparison, immutable Git objects, fixed tag-object identity, and internal blob
equality checks form the bootstrap chain. Likewise, the `main()` import guard
below catches ordinary unsupported Python use; it is not a defense against an
attacker who already controls the interpreter process.

## Local draft generation and validation

The private roadmap is an input only. The validator requires it at the exact
repository-root path, absent from the index and reachable history, and excluded
through `.git/info/exclude`. Every supported CLI command goes through the frozen
external launcher, which starts the absolute base interpreter in
isolated/no-site mode with suppressed bytecode writes and the exact `-I -S -B`
flag profile. Direct script execution and imported calls to `main()` are
rejected, as are ordinary imported calls to every parser-exposed handler. The
decorators retain explicit `__wrapped__` unit/integration-test seams; those
seams are not a supported or authoritative command interface and are not a
Python-process security boundary.

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
non-accepting check of a self-consistent draft or in-progress record set. For
generation 1, the equivalent `make v1-governance-check-nonaccepting` target
requires `V1_GOVERNANCE_COMMITMENT_TIME=<trusted-UTC-time>` explicitly. Its
default generation 2 invocation omits that argument and rejects any supplied
commitment time; it samples host UTC internally for the non-accepting validity
check. Strict checking instead requires exactly one of `--accept-now` or
`--historical`. Generation 1 requires an explicit operator-accepted,
host-unattested gate time. Generation 2 accepts no caller-supplied event times:
the validator captures validation start,
live-gate completion, and attestation-preparation start from the host UTC clock
in their actual execution order. Historical checking derives those observations
from the signed fixed-tag attestation and rejects caller-supplied substitutes.
These records do not turn the host clock into an independently attested time
source.

## Human-only acceptance and signing boundary

The three ordered generation-1 record phases require seven human signatures. A
final, eighth SSHSIG binds the human's declaration about the successful live
closure gate before generation-1 acceptance can be historically evaluated. The
acceptance commands prepare immutable claim bytes,
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

The commands below preserve the generation-1 ceremony mechanics. Current
generation-2 status is asserted only by replacement signed JSON, exact successor
Git objects, and the v2 fixed-tag attestation—not by this illustrative
historical sequence.

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

That two-disposition worksheet describes generation 1 only. For generation 2,
`affirmatively_reconfirmed_after_inventory` is forbidden: every row and
occurrence must be `reestimated_after_inventory` from its digest-bound bottom-up
work breakdown and remain pending until the maintainer signs the exact generated,
itemized batch-adoption manifest. The signature binds every selected value and
generated rationale, but does not represent separately authored per-item prose
or independently observed cognitive review.

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
  --signed-at <signer-declared-host-unattested-UTC-time> `
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
  --signed-at <signer-declared-host-unattested-UTC-time> `
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
  --signed-at <signer-declared-host-unattested-UTC-time> `
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

Generation-1 current checking starts with a one-time gate at a clean checkout
whose `HEAD` is exactly `C`. The isolated authoritative query and fetch are mandatory and
are performed again by the strict command. `--accept-now` is rejected without
`--fetch-authoritative-refs`, a new ignored attestation-plan directory, and a
planned signer-declared time no earlier than and no more than one hour after the
gate. This is a policy relation between recorded declarations, not proof of the
signature operation time:

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
  --commitment-time <operator-accepted-host-unattested-gate-UTC-time> `
  --attestation-plan-dir .tmp\s1-acceptance\current-gate-attestation `
  --attestation-signed-at <planned-signer-declared-host-unattested-UTC-time>
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

Record the full 40-hex `C` and tag object `$A`. Generation-1 acceptance is
evaluated only when historical validation verifies that immutable tag object.
The validator derives the commitment-time declaration from the signed
attestation; a caller-supplied historical time is forbidden. After later
commits, it reads the
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
validator digest, and one-hour gate-to-declared-time policy relation. The
signed attestation is accountable human evidence of the declaration that the
live check occurred; it does not independently establish the host clock, the
remote service, or the instant of signing.

The durable Make wrapper requires the same two immutable Git object IDs:

```powershell
make v1-governance-check `
  V1_GOVERNANCE_CLOSURE_COMMIT=<full-40-hex-C> `
  V1_GOVERNANCE_ACCEPTANCE_TAG_OBJECT=<full-40-hex-A>
```

## Corrective generation 2

The original lineage and tag are immutable historical evidence and must not be
moved, deleted, or force-updated:

- result `R1`: `038b1a8c80fc419106eecd43f4a70b14ba026106`;
- closure `C1`: `6165bc6436aada6cbeb4fc4119eafa9b5dfdb000`;
- acceptance tag object `A1`:
  `1f7bfe058dfb84d8cf4afaf971a57e5c3a12a5fb`; and
- tag name `agent-assure-s1-1.0.0a1-acceptance`.

The corrective lineage is strictly linear: `C1 -> R2 -> C2`. `R2` is the
direct, non-merge child of `C1` and contains the authorized corrective
implementation, including the prospectively signed
`corrective-kickoff-authorization.json`. `C2` is the direct, non-merge child of
`R2` and contains the replacement signed completion and bundle evidence. The
generation-2 attestation format is
`agent-assure-s1-current-acceptance-attestation/2`; its exact signed bytes are
the message of the new fixed annotated tag
`agent-assure-s1-1.0.0a1-acceptance-v2`.

### Absolute-path generation-2 operator ceremony

This ceremony is local-only. It creates local commits and the fixed local tag,
but it does **not** authorize or run `git push`, publication, a pull request, or
a package release. Run the frozen-tool verification above first. Use a private
key path known only to the human operator; the governance program never receives
that path or reads the key.

Define every mutable location as an absolute path. Each plan directory must be
new and must remain under the ignored `.tmp\s1-acceptance` root. The signed
corrective kickoff authorizes exactly three local-only relative prefixes:
`.tmp/s1-acceptance/correction-v2-`,
`.tmp/s1-acceptance/phase-v2-`, and
`.tmp/s1-acceptance/current-gate-v2-`. Every generation-2 plan, imported
private artifact, suite-evidence directory, lock, journal, staging directory,
and atomic publication file must begin with one of those exact prefixes. The
validator rejects reordered, missing, additional, or substituted prefixes and
rejects any generation-2 repository-local artifact outside them. Ephemeral
process, pytest, user-temp, and bytecode storage instead lives beneath one
fresh governed external process directory and is removed before capture can
publish evidence.

```powershell
$RepositoryRoot = 'C:\Users\user\.antigravity-ide\agent-assure'
$Roadmap = Join-Path $RepositoryRoot 'Agent_Assure_Implementation_Roadmap.md'
$GovernanceRoot = Join-Path $RepositoryRoot 'docs\governance\v1'
$CorrectiveAuthorization = Join-Path $GovernanceRoot 'corrective-kickoff-authorization.json'
$PrivateKey = '<ABSOLUTE_PRIVATE_KEY_PATH>'
$DecisionPlanDir = Join-Path $RepositoryRoot '.tmp\s1-acceptance\correction-v2-forecast-decision'
$ForecastPlanDir = Join-Path $RepositoryRoot '.tmp\s1-acceptance\correction-v2-forecast-final'
$PreservedFailedPostR2EvidenceDir = Join-Path $RepositoryRoot '.tmp\s1-acceptance\correction-v2-post-r2-suite-evidence'
$PostR2EvidenceDir = Join-Path $RepositoryRoot '.tmp\s1-acceptance\correction-v2-post-r2-suite-evidence-retry-01'
$PostR2Evidence = Join-Path $PostR2EvidenceDir 'post-r2-suite-evidence.json'
$ReceiptPlanDir = Join-Path $RepositoryRoot '.tmp\s1-acceptance\phase-v2-receipts'
$ReceiptImport = Join-Path $RepositoryRoot '.tmp\s1-acceptance\phase-v2-receipt-import.json'
$BundlePlanDir = Join-Path $RepositoryRoot '.tmp\s1-acceptance\phase-v2-bundle'
$AttestationPlanDir = Join-Path $RepositoryRoot '.tmp\s1-acceptance\current-gate-v2-attestation'
$C1 = '6165bc6436aada6cbeb4fc4119eafa9b5dfdb000'

foreach ($Path in @(
    $RepositoryRoot, $Roadmap, $GovernanceRoot, $CorrectiveAuthorization,
    $PrivateKey, $DecisionPlanDir, $ForecastPlanDir, $PostR2EvidenceDir,
    $ReceiptPlanDir, $ReceiptImport, $BundlePlanDir, $AttestationPlanDir
  )) {
  if (-not [IO.Path]::IsPathRooted($Path)) { throw "Path is not absolute: $Path" }
}
if (-not (Test-Path -LiteralPath $PrivateKey -PathType Leaf)) {
  throw 'The human-supplied private-key path is not a file.'
}

function Invoke-HumanSshsig([string]$ClaimPath) {
  if (-not [IO.Path]::IsPathRooted($ClaimPath)) {
    throw "Claim path is not absolute: $ClaimPath"
  }
  & $SshKeygenExe -Y sign -f $PrivateKey `
    -n 'agent-assure-governance-v1' -O 'hashalg=sha512' $ClaimPath
  if ($LASTEXITCODE -ne 0) { throw "Human SSHSIG failed: $ClaimPath" }
}
```

The directory without the `-retry-01` suffix is the preserved initial failed
run (`outcome=failed`, six failures); it is not acceptance evidence and must
not be overwritten or supplied to receipt planning. The authoritative v2
record is the `-retry-01` record above, has evidence digest
`sha256:bb11ae69b1a5791ed817fe23e23fd755a00a03182d34b8b3d39e8eb236ece5fe`,
and is the record embedded in the signed replacement BOOT receipt and bundle.
Every later corrective run must use a new, explicitly selected directory so a
failed or historical record cannot be mistaken for the current candidate.

First revalidate the corrective branch and authoritative refs. Then prepare the
single itemized decision claim. Review all 68 row decisions and 121 occurrence
decisions before copying the displayed digest into `$DecisionPlanDigest`:

```powershell
Invoke-S1Governance acceptance-preflight `
  --repository-root $RepositoryRoot `
  --fetch `
  --acceptance-generation 2
$DecisionPrepared = Invoke-S1Governance forecast-v2-decision-plan `
  --roadmap $Roadmap --governance-dir $GovernanceRoot `
  --repository-root $RepositoryRoot --plan-dir $DecisionPlanDir |
  ConvertFrom-Json
$DecisionPlanDigest = 'sha256:<human-confirmed-decision-plan-digest>'
if ($DecisionPrepared.plan_digest -cne $DecisionPlanDigest) {
  throw 'Decision plan digest was not copied exactly.'
}
Invoke-HumanSshsig (Join-Path $DecisionPlanDir 'decision.claim')
$DecisionImported = Invoke-S1Governance forecast-v2-decision-import `
  --roadmap $Roadmap --governance-dir $GovernanceRoot `
  --repository-root $RepositoryRoot --plan-dir $DecisionPlanDir `
  --expected-plan-digest $DecisionPlanDigest | ConvertFrom-Json
```

Next review and sign both final forecast claims. `producer.claim` is the
technical-lead claim; `acceptance-receipt.claim` is the repository-maintainer
acceptance claim.

```powershell
$ForecastPrepared = Invoke-S1Governance forecast-v2-signature-plan `
  --roadmap $Roadmap --governance-dir $GovernanceRoot `
  --repository-root $RepositoryRoot --plan-dir $ForecastPlanDir |
  ConvertFrom-Json
$ForecastPlanDigest = 'sha256:<human-confirmed-final-forecast-plan-digest>'
if ($ForecastPrepared.plan_digest -cne $ForecastPlanDigest) {
  throw 'Final forecast plan digest was not copied exactly.'
}
Invoke-HumanSshsig (Join-Path $ForecastPlanDir 'producer.claim')
Invoke-HumanSshsig (Join-Path $ForecastPlanDir 'acceptance-receipt.claim')
$ForecastImported = Invoke-S1Governance forecast-v2-signature-import `
  --roadmap $Roadmap --governance-dir $GovernanceRoot `
  --repository-root $RepositoryRoot --plan-dir $ForecastPlanDir `
  --expected-plan-digest $ForecastPlanDigest | ConvertFrom-Json
```

Before creating `R2`, replace the delimited `forecast-v2-final` blocks in this
README and ADR 0016. Both must say `human_decisions_imported` with
`$DecisionImported.ledger_digest`, and `accepted` with
`$ForecastImported.record_digest`. The receipt planner enforces exact agreement
with the installed JSON. Run the read-only documentation check before staging;
it validates the accepted records and both exact blocks, preventing a bad block
from being sealed into `R2`. Stage only signed-allowlisted paths other than the
three `C2` records, then create the direct child `R2`:

```powershell
Invoke-S1Governance forecast-v2-documentation-check `
  --roadmap $Roadmap --governance-dir $GovernanceRoot `
  --repository-root $RepositoryRoot
$ClosurePaths = @(
  'docs/governance/v1/completion-receipt-v1-base-01.json',
  'docs/governance/v1/completion-receipt-v1-boot-01.json',
  'docs/governance/v1/governance-bundle.json'
)
$Authorization = Get-Content -LiteralPath $CorrectiveAuthorization -Raw |
  ConvertFrom-Json
$R2Paths = @($Authorization.signed_claim.tracked_allowed_paths |
  Where-Object { $_ -notin $ClosurePaths })
$HeadBeforeR2 = (& $GitExe -C $RepositoryRoot rev-parse 'HEAD^{commit}').Trim()
if ($LASTEXITCODE -ne 0 -or $HeadBeforeR2 -cne $C1) {
  throw 'R2 must be prepared from exact C1.'
}
& $GitExe -C $RepositoryRoot add -- @R2Paths
if ($LASTEXITCODE -ne 0) { throw 'Unable to stage the bounded R2 path set.' }
$R2Allowed = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($Path in $R2Paths) { [void]$R2Allowed.Add($Path) }
$R2Seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$R2Rows = @(& $GitExe -C $RepositoryRoot diff --cached --name-status --no-renames)
if ($LASTEXITCODE -ne 0 -or $R2Rows.Count -eq 0) {
  throw 'R2 staged change audit failed or found no changes.'
}
foreach ($Row in $R2Rows) {
  $Fields = @($Row -split "`t")
  if ($Fields.Count -ne 2 -or $Fields[0] -cnotin @('A', 'M') -or
      -not $R2Allowed.Contains($Fields[1]) -or -not $R2Seen.Add($Fields[1])) {
    throw "R2 staged change is deleted, renamed, duplicated, or unauthorized: $Row"
  }
}
$R2Unstaged = @(& $GitExe -C $RepositoryRoot diff --name-status --no-renames)
if ($LASTEXITCODE -ne 0 -or $R2Unstaged.Count -ne 0) {
  throw 'R2 has unstaged tracked changes.'
}
$R2Untracked = @(& $GitExe -C $RepositoryRoot ls-files --others --exclude-standard)
if ($LASTEXITCODE -ne 0 -or $R2Untracked.Count -ne 0) {
  throw 'R2 has untracked, non-ignored files.'
}
$HeadBeforeR2Commit = (& $GitExe -C $RepositoryRoot rev-parse 'HEAD^{commit}').Trim()
if ($LASTEXITCODE -ne 0 -or $HeadBeforeR2Commit -cne $C1) {
  throw 'HEAD changed before the R2 commit.'
}
& $GitExe -C $RepositoryRoot commit -m 'Correct S1 governed baseline'
if ($LASTEXITCODE -ne 0) { throw 'R2 commit failed.' }
$R2 = (& $GitExe -C $RepositoryRoot rev-parse 'HEAD^{commit}').Trim()
$R2Fields = ((& $GitExe -C $RepositoryRoot rev-list --parents -n 1 $R2).Trim()) -split ' '
if ($R2Fields.Count -ne 2 -or $R2Fields[1] -cne $C1) {
  throw 'R2 is not the direct, non-merge child of C1.'
}
```

The following technical description records the immutable historical `/3`
ceremony; it is not a current replay instruction. At clean `R2`, that completed
ceremony captured the full suite, prepared and signed both replacement
receipts, and passed the confirmed receipt-plan digest to both receipt import
and bundle planning. The descendant `corrective-v2-suite-capture` command is
reuse-only, as specified below.

The historical capture command's main pytest process did not execute either the checked-in
virtual-environment Python shim or the ephemeral descendant executable. Its
process image is the frozen base interpreter, launched by absolute path with
`-I -S -B -X utf8` and a fresh, unique, absolute `-X pycache_prefix` beneath an
absent governed pytest basetemp. That frozen identity remains the `/3` evidence
record's `command.python_executable`. `-B` alone prevents writes but still
permits bytecode reads; the fresh prefix is what makes source-adjacent
`__pycache__` content inert. Direct `.pyc` and `.pyo` files remain forbidden in
both the repository test surface and site-packages. A hostile unchecked-hash
cache therefore cannot replace reviewed source bytes.

Before that main spawn, capture allocates a fresh external process directory
directly beneath `C:\tmp`, using the governed
`agent-assure-s1-post-r2-process-temp-` prefix. Its absent `pytest` child is the
exact `--basetemp`; keeping pytest temporary paths outside the Git checkout
preserves the suite's ordinary producer-root semantics. Capture also derives
an exact, ephemeral descendant virtual environment there directly from the
authenticated frozen base and test runtime: a copied base
`Scripts/python.exe`, a `pyvenv.cfg` whose home is the frozen base, an
authenticated-paths `.pth` file, and a `sitecustomize.py` startup guard. The
`.pth` admits only repository `src`, the repository root, and the already
authenticated `.venv/Lib/site-packages`.
The `/3` evidence records the descendant root, derivation and exact-tree
policies, plus the path, relative path, size, and digest of all four files.
The exact runtime directory set (`Scripts`, `Lib`, and `Lib/site-packages`) is
verified along with the exact file set; an unexpected directory, even an empty
one, or any reparse point fails verification. The separate user-temp directory
must also be fresh, and the pytest basetemp must be absent before spawn. The
runtime is verified before and after pytest. Cleanup is fail-closed on
preparation, execution, and verification exits: capture cannot return or
publish evidence unless removal of the external process directory—including
pytest, Hypothesis, user-temp, and runtime descendants—is successful and its
absence is confirmed. If Windows rejects deletion of a contained read-only
regular file, cleanup pins the governed root, process directory, every parent,
with non-delete-sharing handles and opens the candidate exclusively. It rejects
reparse points, requires each fully resolved handle path to be Windows-ordinal
equal to its lexical governed path, and deletes only the candidate's opened
link through that same handle while instructing Windows to ignore the read-only
attribute. The disposition also rejects a still-mapped executable image. The
attribute itself is not changed, so an outside hard-link peer remains
read-only. Every other deletion error remains fatal.

The fixed bootstrap source is supplied to the frozen interpreter as exact
UTF-8 bytes over standard input, rather than embedded in the Windows command
line. This keeps the launch below Windows command-line limits without weakening
identity binding: the `/3` evidence records the `python_stdin_utf8` transport,
byte length, and SHA-256 digest, and validation recomputes all three from the
governed inputs and rejects drift.

Before importing pytest, that fixed stdlib-only bootstrap authenticates the full
non-cache `.venv/Lib/site-packages` inventory: 5,473 files, 92,718,636 bytes,
and domain-separated SHA-256
`a1fc3961699a2eed1fdbeccba871a55b760f3764da3e54c1a638fc18bafb7f2c`.
It also authenticates the historically defined `/3` R2 test surface: every
tracked top-level directory and tracked root file, all known root test
configuration names, and the exact local `.git/info/exclude` bytes. Raw
filesystem enumeration rejects ignored or untracked files under those roots,
including configuration files; source-adjacent cache directories are the only
exclusion. Untracked import-capable root directories such as `build` or `dist`
are rejected. The parent process performs the same authentication before and
after pytest and verifies every byte admitted to that historical surface
against immutable R2. That surface was later shown to be incomplete: the
repository root remained importable; ignored root-level native extension
modules were not admitted to the inventory; and pytest 9's hidden
`.pytest.ini` and `.pytest.toml` configuration names were absent from the known
configuration list.

The successor `/4` control closes that gap without rewriting `/3`: it removes
the repository root from the initial Python import path; admits only the exact
tracked top-level set plus `.git`, `.venv`, `.tmp`, and the private roadmap;
rejects every other top-level entry and every top-level reparse point; and
enumerates both hidden pytest configuration names. It explicitly pins
`pyproject.toml`, the repository root, `src`, importlib import mode, the socket
guard, and the absolute `tests` tree on pytest's command line while clearing
configuration-supplied `addopts`, restoring pytest's complete default file,
class, and function selectors, and pinning `norecursedirs=__pycache__` so the
sole inventory exclusion cannot become a collection surface. Canonical
Git-metadata preflights run before every governed Git read or test execution.

After authenticating those bytes, the stdlib-only bootstrap loads that exact
startup guard into the main process, identifies `sys.executable` as the
ephemeral descendant interpreter, and wraps `subprocess.Popen`. Every governed
Python launch recursively receives explicit `-B -s -P -X
pycache_prefix=<fresh prefix>` arguments at the `Popen` boundary. The wrapper
covers both positional
argv and the supported `Popen(args=...)` form. Bare `python` and `python.exe`
aliases are rewritten to the exact authenticated descendant executable rather
than resolved through a caller-supplied `PATH`. Governed launches require a
sequence argv: scalar/string command forms, shell execution, conflicting
executable selection, and caller attempts to override the prefix are rejected.
A `-W` filter's category, when present, must name a built-in warning class;
dotted or otherwise importable custom categories are rejected before startup.
A requested `-S` is remembered and removed before startup so the authenticated
guard can load; after installing the recursive boundary, the guard removes the
governed site-package admissions to preserve the requested no-site import
paths. The caller's `PYTHONPATH` is deferred while child startup exposes only
the authenticated guard path, so neither it nor a hostile `sitecustomize.py`
can precede or shadow the guard. The caller's original `PYTHONPATH` semantics
are restored only after that guard is installed. A launch that requested `-S`
does not chain `sitecustomize`; any original `sitecustomize` for an ordinary
launch is chained only after the authenticated guard. A descendant installs
that same exact guard for its own descendants. It fails closed if the exact
no-write and fresh-prefix CLI policy
is not already active or if a conflicting guard marker exists. The governed
prefix must still be absent after suite execution.

The child receives a complete allowlisted environment rather than inherited
host variables. `PATH` begins with the ephemeral descendant `Scripts`
directory; `TEMP` and `TMP` name its separate fresh directory under the
external process root. The environment fixes `HOME=C:\Users\user` and
`PROCESSOR_ARCHITECTURE=AMD64` for deterministic platform behavior.
Policy-variable handling is case-insensitive: every casing of
`PYTHONDONTWRITEBYTECODE`, `PYTHONNOUSERSITE`, `PYTHONPYCACHEPREFIX`, and
`PYTHONSAFEPATH` is removed before exactly one canonical uppercase setting is
installed with values `1`, `1`, the fresh governed prefix, and `1`,
respectively. Every casing of `PYTHONCASEOK`, `PYTHONHOME`,
`PYTHONPLATLIBDIR`, `PYTHONUSERBASE`, and `PYTHONWARNINGS` is removed before a
governed launch. The accepted historical `/3` record used the exact in-memory
Git list `GIT_CONFIG_COUNT=2`, containing `core.autocrlf=true` and the exact
`safe.directory`, with `GIT_CONFIG_GLOBAL=NUL` and `GIT_CONFIG_NOSYSTEM=1`.
The repaired `/4` capture policy extends that list with Windows null-device
(`NUL`) `core.excludesFile` and `core.attributesFile` values and also fixes
`GIT_ATTR_NOSYSTEM=1`, so per-user global and system-level ignore/attribute
files cannot alter the governed inventory. Repository-local `.git/info/exclude`
and tracked `.gitignore`/`.gitattributes` policies remain active and are
separately pinned or authenticated. Empty process-environment values are not
used because, unlike CLI `-c key=` entries, Git for Windows treats a counted empty
`GIT_CONFIG_VALUE_*` entry as missing and rejects ordinary repository operations
during config parsing. Because pytest prepends the authenticated repository
`addopts`, the governed command then assigns terminal verbosity exactly `-1`;
this prevents stacked quiet flags from suppressing the terminal totals parsed
into evidence. The exact environment, plugin list, Hypothesis
storage, bytecode controls, working directory, both interpreter identities,
command arguments, runtime inventory, test-surface inventory, and raw
stdout/stderr hashes are bound into the evidence record. The pytest
basetemp and bytecode prefix must be absent immediately before the main spawn.
Every governed execution, including a retry, allocates a new governed external
parent. If cleanup itself fails or the host terminates abnormally, any external
residue is a failed-run artifact: capture does not publish it, and the exact
fresh-parent requirement prevents its reuse as later-run evidence.

Capture and suite success are separate facts. The historical v2 command only
reuses an existing `/3` record and reports
`clean_r2_full_suite_evidence_reused_passed` or
`clean_r2_full_suite_evidence_reused_failed`. A fresh failed `/4` run is
published for diagnosis only when its UTF-8 terminal output contains exactly
one parseable totals summary with at least one executed outcome, zero
deselected tests, and `collected == executed`, and the complete candidate
record passes the same embedded validator used for replay. Those conditions
are cumulative: one parseable summary is necessary but not sufficient. A
published failed capture reports `post_v2_control_suite_evidence_captured_failed`;
a later replay reports the corresponding `reused` token. A summary-parsing
failure, including absence of an executed outcome, fails with the exit code,
outcome, and bounded stream hashes and sizes in its diagnostic. Any
deselection, collected/executed mismatch, or other embedded-validation failure
also fails before publication, but its validator diagnostic does not claim that
the unpublished stream metadata was durably preserved. Both commands expose
the original `pytest_exit_code`, `execution_outcome`, and `suite_passed` for a
published record. Every published failed record returns nonzero, whether newly
captured or reused; only a passing record returns zero.

A published `/4` evidence directory is immutable regardless of whether its
suite passed or failed. Supplying that directory again validates and reuses the
record; it does not execute pytest again. Preserve a published failed record as
diagnostic evidence. Every later execution or retry must use another
operator-selected run identifier and a different evidence path that is absent
before invocation.

Eligibility is a separate fail-closed property. The already accepted `/3`
retry record remains verifiable and reports `acceptance_eligible=true` when it
passes. `corrective-v2-suite-capture` is now deliberately reuse-only: it
requires an existing historical `/3` evidence directory, validates its exact
three-file contents against clean R2, and never executes pytest or manufactures
new generation-2 evidence.

The repaired controls are exercised separately with
`post-v2-control-suite-capture`. Its subject must be the clean exact `HEAD`, a
proper non-merge descendant of immutable `C2`; its evidence directory must use
the distinct `.tmp/s1-acceptance/post-v2-control-*` prefix; and
`.git/info/attributes` must be absent. Its `.git/info/exclude` must contain the
exact 55 LF/no-BOM bytes
`/Agent_Assure_Implementation_Roadmap.md\n/.venv/\n/.tmp/\n`, whose SHA-256 is
`ade798e909c6129d230fb91281883f0d07b83a97ad0b60ff673da0857914cfff`.
The command executes the governed full suite and persists a `/4` record that
binds the actual subject parent and C2 ancestry, stores
`acceptance_generation=null` and
`corrective_authorization_claim_digest=null`, and carries
`authorization_effect=none` inside its `control_basis`. Its separate CLI
response reports `acceptance_eligible=false`. The record is
control-implementation evidence only. Generation-2 receipt planning rejects it
even when its suite passes, and it cannot unblock S2. A prospectively authorized
successor must define its own result/closure lineage and acceptance schema
before new evidence can become acceptance-eligible.

Before publishing a new `/4` directory, capture validates the complete record
with the same embedded validator used for replay. JSON booleans are rejected in
integer fields, and terminal totals must account for every collected item;
any deselection prevents publication, regardless of the suite label or pytest
exit code. The v4 pytest invocation forces `-c <root>/pyproject.toml`,
`--rootdir=<root>`, `--confcutdir=<root>`, `pythonpath=src`, canonical collection
patterns, `--import-mode=importlib`, `--disable-socket`, and the absolute
`<root>/tests` path. Repository `addopts`, `testpaths`, hidden or ancestor
configuration, and ignored external test trees cannot redirect the governed
collection.

The canonical v4 exclude policy and the accepted host's 2,368-byte v3 exclude
policy are intentionally mutually exclusive. Preserve the accepted checkout
and its local metadata unchanged. Run the control-only command only after the
repaired files have been committed, from a separate `clone --no-local` with an
empty Git template at that exact subject. Apply the standalone procedure's
local non-reparse `.git`, no-alternates, non-shallow, isolated-Git, clean-status,
and approved-origin checks (including resetting `origin` to
`https://github.com/acblabs/agent-assure.git`). Copy the already verified
frozen `.venv` using the non-reparse source/destination checks above. Supply
the byte-identical roadmap source through `$PostV2SourceRoadmap`; the guarded
block verifies and copies it immediately before capture, then removes the exact
clone-local copy in `finally`. Then create the canonical local policy and
invoke that clone's launcher as follows. For every execution, including a
retry, replace `$PostV2RunId` with a never-before-used identifier containing
one to 64 lowercase ASCII letters, digits, or hyphens, beginning with a letter
or digit. Do not pre-create the resulting evidence directory. An uncommitted,
dirty, merge, C2-exact, unrelated, or already-used evidence target correctly
fails:

Run the ceremony directly on the frozen native Windows host, outside a
restricted filesystem sandbox. The control verifies rooted Windows paths,
reparse metadata, ACL-sensitive traversal, and exact host binaries; sandbox
redirection or access filtering is not part of the attested runtime and can
produce non-representative failures. The launcher buffers pytest output until
the child exits. The accepted `/3` full suite took approximately 76 minutes on
this host, so an otherwise quiet process is not by itself evidence of a hang.
If the host or process terminates before a record is published, retain any
diagnostics and retry only with a fresh run identifier and an absent evidence
target as required above.

```powershell
$ErrorActionPreference = 'Stop'
$PostV2RepositoryRoot = '<ABSOLUTE_SEPARATE_POST_V2_CLONE_PATH>'
$PostV2SourceRoadmap = '<ABSOLUTE_VERIFIED_PRIVATE_ROADMAP_SOURCE_PATH>'
$PostV2RunId = '<FRESH_OPERATOR_SELECTED_RUN_ID>'
if ($PostV2RunId -cnotmatch '^[a-z0-9][a-z0-9-]{0,63}$') {
  throw 'Post-v2 run identifier must be 1-64 lowercase letters, digits, or hyphens and start with a letter or digit.'
}
$PostV2Roadmap = Join-Path $PostV2RepositoryRoot 'Agent_Assure_Implementation_Roadmap.md'
$PostV2Launcher = Join-Path $PostV2RepositoryRoot 'scripts\v1_s1_governance.ps1'
$ImmutableC2 = 'db5133e09860d292047b963b0fb81b3e7385b7fa'
$PostV2Subject = (& $GitExe @GitPrefix -C $PostV2RepositoryRoot `
  rev-parse --verify 'HEAD^{commit}').Trim()
if ($LASTEXITCODE -ne 0 -or $PostV2Subject -ceq $ImmutableC2) {
  throw 'Post-v2 control subject must be a proper descendant of immutable C2.'
}
$PostV2ParentRow = @(& $GitExe @GitPrefix -C $PostV2RepositoryRoot `
  rev-list --parents -n 1 $PostV2Subject)
if ($LASTEXITCODE -ne 0 -or $PostV2ParentRow.Count -ne 1) {
  throw 'Post-v2 control subject parent lookup failed.'
}
$PostV2ParentFields = @($PostV2ParentRow[0].Split(
  [char[]] @(' '),
  [StringSplitOptions]::RemoveEmptyEntries
))
if ($PostV2ParentFields.Count -ne 2 -or
    $PostV2ParentFields[0] -cne $PostV2Subject) {
  throw 'Post-v2 control subject must be one non-merge commit.'
}
& $GitExe @GitPrefix -C $PostV2RepositoryRoot merge-base --is-ancestor `
  $ImmutableC2 $PostV2Subject
if ($LASTEXITCODE -ne 0) {
  throw 'Post-v2 control subject does not descend from immutable C2.'
}
$PostV2InfoPath = Join-Path $PostV2RepositoryRoot '.git\info'
if (-not (Test-Path -LiteralPath $PostV2InfoPath)) {
  [void](New-Item -ItemType Directory -Path $PostV2InfoPath)
}
$PostV2Info = Get-Item -LiteralPath $PostV2InfoPath -Force -ErrorAction Stop
if (-not $PostV2Info.PSIsContainer -or
    (($PostV2Info.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
  throw 'Post-v2 control capture requires a regular non-reparse .git\info directory.'
}
$PostV2Attributes = Join-Path $PostV2InfoPath 'attributes'
if (Test-Path -LiteralPath $PostV2Attributes) {
  throw 'Post-v2 control capture requires .git\info\attributes to be absent.'
}
$PostV2Exclude = Join-Path $PostV2InfoPath 'exclude'
if (Test-Path -LiteralPath $PostV2Exclude) {
  throw 'Post-v2 control setup refuses to overwrite an existing local-exclude path.'
}
$PostV2ExcludeBytes = [Text.UTF8Encoding]::new($false).GetBytes(
  "/Agent_Assure_Implementation_Roadmap.md`n/.venv/`n/.tmp/`n"
)
$PostV2ExcludeStream = [IO.File]::Open(
  $PostV2Exclude,
  [IO.FileMode]::CreateNew,
  [IO.FileAccess]::Write,
  [IO.FileShare]::None
)
try {
  $PostV2ExcludeStream.Write(
    $PostV2ExcludeBytes,
    0,
    $PostV2ExcludeBytes.Length
  )
  $PostV2ExcludeStream.Flush($true)
}
finally {
  $PostV2ExcludeStream.Dispose()
}

function Invoke-PostV2Governance {
  & $PowerShellExe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass `
    -File $PostV2Launcher @args
  if ($LASTEXITCODE -ne 0) { throw "Post-v2 governance command failed: $LASTEXITCODE" }
}

function Remove-PostV2ControlRoadmap {
  param([Parameter(Mandatory = $true)][string] $CandidatePath)

  $ExpectedPath = [IO.Path]::GetFullPath(
    (Join-Path $PostV2RepositoryRoot 'Agent_Assure_Implementation_Roadmap.md')
  )
  if ([IO.Path]::GetFullPath($CandidatePath) -cne $ExpectedPath) {
    throw 'Post-v2 roadmap cleanup path is not the exact clone-local path.'
  }
  try {
    $RoadmapItem = Get-Item -LiteralPath $ExpectedPath -Force -ErrorAction Stop
  }
  catch [System.Management.Automation.ItemNotFoundException] {
    return
  }
  if ($RoadmapItem.PSIsContainer -or
      (($RoadmapItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
    throw 'Post-v2 roadmap cleanup requires a regular non-reparse file.'
  }
  Remove-Item -LiteralPath $ExpectedPath -Force -ErrorAction Stop
  try {
    [void](Get-Item -LiteralPath $ExpectedPath -Force -ErrorAction Stop)
  }
  catch [System.Management.Automation.ItemNotFoundException] {
    return
  }
  throw 'Post-v2 private-roadmap cleanup did not complete.'
}

$PostV2ControlEvidenceDir = Join-Path $PostV2RepositoryRoot `
  ".tmp\s1-acceptance\post-v2-control-$($PostV2Subject.Substring(0, 12))-$PostV2RunId"
$PostV2RoadmapCopyOwned = $false
try {
  $ExpectedRoadmapSizeBytes = 2390013
  $ExpectedRoadmapSha256 = `
    '8fc2e6e6f83b6a6ac6c27492473de8690b9360eac584131b6e8b42785f4386eb'
  $SourceRoadmapItem = Get-Item -LiteralPath $PostV2SourceRoadmap `
    -Force -ErrorAction Stop
  if ($SourceRoadmapItem.PSIsContainer -or
      (($SourceRoadmapItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
    throw 'Post-v2 control capture requires a regular non-reparse source roadmap file.'
  }
  $SourceRoadmapSha256 = (Get-FileHash -LiteralPath $PostV2SourceRoadmap `
    -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
  if ($SourceRoadmapItem.Length -ne $ExpectedRoadmapSizeBytes -or
      $SourceRoadmapSha256 -cne $ExpectedRoadmapSha256) {
    throw 'Post-v2 source roadmap does not match generation 2.'
  }
  if (Test-Path -LiteralPath $PostV2Roadmap) {
    throw 'Post-v2 control capture refuses to overwrite the clone-local roadmap path.'
  }
  $SourceRoadmapStream = [IO.File]::Open(
    $PostV2SourceRoadmap,
    [IO.FileMode]::Open,
    [IO.FileAccess]::Read,
    [IO.FileShare]::Read
  )
  try {
    $PostV2RoadmapStream = [IO.File]::Open(
      $PostV2Roadmap,
      [IO.FileMode]::CreateNew,
      [IO.FileAccess]::Write,
      [IO.FileShare]::None
    )
    $PostV2RoadmapCopyOwned = $true
    try {
      $SourceRoadmapStream.CopyTo($PostV2RoadmapStream)
      $PostV2RoadmapStream.Flush($true)
    }
    finally {
      $PostV2RoadmapStream.Dispose()
    }
  }
  finally {
    $SourceRoadmapStream.Dispose()
  }
  $PostV2RoadmapItem = Get-Item -LiteralPath $PostV2Roadmap `
    -Force -ErrorAction Stop
  if ($PostV2RoadmapItem.PSIsContainer -or
      (($PostV2RoadmapItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
    throw 'Post-v2 control capture requires a regular non-reparse clone-local roadmap file.'
  }
  $PostV2RoadmapSha256 = (Get-FileHash -LiteralPath $PostV2Roadmap `
    -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
  if ($PostV2RoadmapItem.Length -ne $ExpectedRoadmapSizeBytes -or
      $PostV2RoadmapSha256 -cne $ExpectedRoadmapSha256) {
    throw 'Post-v2 clone-local roadmap copy does not match generation 2.'
  }
  if (Test-Path -LiteralPath $PostV2ControlEvidenceDir) {
    throw 'Fresh post-v2 control evidence directory must be absent before invocation.'
  }

  $ControlResult = Invoke-PostV2Governance post-v2-control-suite-capture `
    --roadmap $PostV2Roadmap --repository-root $PostV2RepositoryRoot `
    --subject-commit $PostV2Subject `
    --evidence-dir $PostV2ControlEvidenceDir | ConvertFrom-Json
  if ($ControlResult.acceptance_eligible -or
      $null -ne $ControlResult.acceptance_generation -or
      $ControlResult.authorization_effect -cne 'none' -or
      $ControlResult.capture_disposition -cne 'captured' -or
      -not $ControlResult.suite_passed -or
      $ControlResult.execution_outcome -cne 'passed' -or
      $ControlResult.pytest_exit_code -ne 0) {
    throw 'Post-v2 control evidence did not produce a passing non-accepting result.'
  }
}
finally {
  if ($PostV2RoadmapCopyOwned) {
    Remove-PostV2ControlRoadmap -CandidatePath $PostV2Roadmap
  }
}
```

Preserve the control result and evidence outside `$PostV2RepositoryRoot` before
broader disposable-clone cleanup. The `finally` path is exact-file,
non-recursive, and reparse-resistant, and runs for both success and failure.

The following block is retained solely as the immutable generation-2 ceremony
transcript, not as current replay instructions. During that ceremony,
`$GovernanceLauncher` came from clean exact R2, whose then-current handler ran
pytest and created the accepted retry record. The descendant validator has
since made the same command name reuse-only and ties source validation to the
preserved record's captured absolute repository path as well as clean exact R2.
It is not a portable replay procedure and never recreates the historical run.
The signed receipt, bundle, and standalone historical-closure paths remain the
portable validation route for `/3`; none of the receipt/signature steps below
should be repeated or used to alter v2:

```powershell
$SuiteResult = Invoke-S1Governance corrective-v2-suite-capture `
  --roadmap $Roadmap --governance-dir $GovernanceRoot `
  --repository-root $RepositoryRoot --result-commit $R2 `
  --evidence-dir $PostR2EvidenceDir | ConvertFrom-Json
$ReceiptPrepared = Invoke-S1Governance corrective-v2-receipt-plan `
  --roadmap $Roadmap --governance-dir $GovernanceRoot `
  --repository-root $RepositoryRoot --result-commit $R2 `
  --post-r2-evidence $PostR2Evidence --plan-dir $ReceiptPlanDir |
  ConvertFrom-Json
$ReceiptPlanDigest = 'sha256:<human-confirmed-receipt-plan-digest>'
if ($ReceiptPrepared.plan_digest -cne $ReceiptPlanDigest) {
  throw 'Receipt plan digest was not copied exactly.'
}
Invoke-HumanSshsig (Join-Path $ReceiptPlanDir 'completion-base-01.claim')
Invoke-HumanSshsig (Join-Path $ReceiptPlanDir 'completion-boot-01.claim')
$ReceiptImported = Invoke-S1Governance corrective-v2-receipt-import `
  --roadmap $Roadmap --governance-dir $GovernanceRoot `
  --repository-root $RepositoryRoot --plan-dir $ReceiptPlanDir `
  --expected-plan-digest $ReceiptPlanDigest --output $ReceiptImport |
  ConvertFrom-Json
$BundlePrepared = Invoke-S1Governance corrective-v2-bundle-plan `
  --roadmap $Roadmap --governance-dir $GovernanceRoot `
  --repository-root $RepositoryRoot --result-commit $R2 `
  --receipt-import $ReceiptImport `
  --expected-receipt-plan-digest $ReceiptPlanDigest `
  --plan-dir $BundlePlanDir | ConvertFrom-Json
$BundlePlanDigest = 'sha256:<human-confirmed-bundle-plan-digest>'
if ($BundlePrepared.plan_digest -cne $BundlePlanDigest) {
  throw 'Bundle plan digest was not copied exactly.'
}
Invoke-HumanSshsig (Join-Path $BundlePlanDir 'governance-bundle.claim')
Invoke-S1Governance corrective-v2-bundle-import `
  --roadmap $Roadmap --governance-dir $GovernanceRoot `
  --repository-root $RepositoryRoot --plan-dir $BundlePlanDir `
  --expected-plan-digest $BundlePlanDigest
```

The bundle import installs only the three closure records. Commit exactly those
paths as direct child `C2`:

```powershell
$HeadBeforeC2 = (& $GitExe -C $RepositoryRoot rev-parse 'HEAD^{commit}').Trim()
if ($LASTEXITCODE -ne 0 -or $HeadBeforeC2 -cne $R2) {
  throw 'C2 must be prepared from exact R2.'
}
$C2Expected = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($Path in $ClosurePaths) { [void]$C2Expected.Add($Path) }
$C2Materialized = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$C2Rows = @(& $GitExe -C $RepositoryRoot diff --name-status --no-renames $R2 --)
if ($LASTEXITCODE -ne 0 -or $C2Rows.Count -ne $ClosurePaths.Count) {
  throw 'The materialized C2 change count is not exact.'
}
foreach ($Row in $C2Rows) {
  $Fields = @($Row -split "`t")
  if ($Fields.Count -ne 2 -or $Fields[0] -cne 'M' -or
      -not $C2Expected.Contains($Fields[1]) -or
      -not $C2Materialized.Add($Fields[1])) {
    throw "C2 materialized change is added, deleted, renamed, duplicated, or unauthorized: $Row"
  }
}
& $GitExe -C $RepositoryRoot add -- @ClosurePaths
if ($LASTEXITCODE -ne 0) { throw 'Unable to stage the three C2 records.' }
$C2Staged = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$C2StagedRows = @(& $GitExe -C $RepositoryRoot diff --cached --name-status --no-renames)
if ($LASTEXITCODE -ne 0 -or $C2StagedRows.Count -ne $ClosurePaths.Count) {
  throw 'The staged C2 change count is not exact.'
}
foreach ($Row in $C2StagedRows) {
  $Fields = @($Row -split "`t")
  if ($Fields.Count -ne 2 -or $Fields[0] -cne 'M' -or
      -not $C2Expected.Contains($Fields[1]) -or -not $C2Staged.Add($Fields[1])) {
    throw "C2 staged change is added, deleted, renamed, duplicated, or unauthorized: $Row"
  }
}
$C2Unstaged = @(& $GitExe -C $RepositoryRoot diff --name-status --no-renames)
if ($LASTEXITCODE -ne 0 -or $C2Unstaged.Count -ne 0) {
  throw 'C2 has unstaged tracked changes.'
}
$C2Untracked = @(& $GitExe -C $RepositoryRoot ls-files --others --exclude-standard)
if ($LASTEXITCODE -ne 0 -or $C2Untracked.Count -ne 0) {
  throw 'C2 has untracked, non-ignored files.'
}
$HeadBeforeC2Commit = (& $GitExe -C $RepositoryRoot rev-parse 'HEAD^{commit}').Trim()
if ($LASTEXITCODE -ne 0 -or $HeadBeforeC2Commit -cne $R2) {
  throw 'HEAD changed before the C2 commit.'
}
& $GitExe -C $RepositoryRoot commit -m 'Close corrected S1 governed baseline'
if ($LASTEXITCODE -ne 0) { throw 'C2 commit failed.' }
$C2 = (& $GitExe -C $RepositoryRoot rev-parse 'HEAD^{commit}').Trim()
$C2Fields = ((& $GitExe -C $RepositoryRoot rev-list --parents -n 1 $C2).Trim()) -split ' '
if ($C2Fields.Count -ne 2 -or $C2Fields[1] -cne $R2) {
  throw 'C2 is not the direct, non-merge child of R2.'
}
```

At exact clean `C2`, run the live gate, confirm its attestation digest, sign the
one claim, finalize the exact tag message, and create the fixed annotated tag.
Then execute the mandatory standalone-clone historical procedure above.

```powershell
$GatePrepared = Invoke-S1Governance check `
  --roadmap $Roadmap --governance-dir $GovernanceRoot `
  --repository-root $RepositoryRoot --accept-now `
  --fetch-authoritative-refs --acceptance-generation 2 `
  --attestation-plan-dir $AttestationPlanDir | ConvertFrom-Json
$AttestationDigest = 'sha256:<human-confirmed-current-attestation-digest>'
if ($GatePrepared.attestation_plan.attestation_digest -cne $AttestationDigest) {
  throw 'Current-attestation digest was not copied exactly.'
}
Invoke-HumanSshsig (Join-Path $AttestationPlanDir 'attestation.claim')
$Finalized = Invoke-S1Governance acceptance-attestation-finalize `
  --repository-root $RepositoryRoot --plan-dir $AttestationPlanDir `
  --expected-attestation-digest $AttestationDigest | ConvertFrom-Json
$TagName = $Finalized.acceptance_tag_name
$SignedAttestation = $Finalized.output
& $GitExe -C $RepositoryRoot -c 'tag.gpgSign=false' tag --annotate `
  --cleanup=verbatim --file $SignedAttestation $TagName $C2
if ($LASTEXITCODE -ne 0) { throw 'Generation-2 fixed tag creation failed.' }
$A2 = (& $GitExe -C $RepositoryRoot rev-parse "refs/tags/$TagName^{tag}").Trim()
```

The finalized generation-2 attestation signs
`finalization_deadline_at_utc`, derived exactly as the earlier of one hour after
`gate_completed_at_utc` and the governance bundle's exclusive expiry. The
finalizer samples the unattested host clock before and after revalidation,
rejects backward movement between those observations, and requires
`attestation_preparation_started_at_utc <= host now < finalization deadline`.
It then reloads and verifies the live forecast, authorization, kickoff,
completion, and bundle evidence; re-proves the exact clean linear
`C1 -> R2 -> C2` checkout; and re-resolves the governed branch, `HEAD`, origin,
predecessor tag, and pinned local refs without making a second remote-freshness
claim. Those checks run immediately before first publication and again before
an exact idempotent reuse. A stale, dirty, moved, mixed, or differently signed
state produces no successful finalization result.

Exact finalizer reuse is a pre-tag crash-recovery path only. Once the fixed
generation-2 successor tag exists, do not rerun finalization; use the historical
check to verify the immutable tag and closure instead.

Every import is retryable only with the same plan directory and same confirmed
digest. Forecast decision/final imports and bundle import keep a verified local
import artifact and transaction journal; rerunning the identical command
performs bounded recovery or reports idempotent success. Never delete a journal,
overwrite a plan, regenerate a plan after signing, or continue after a
partial-install error. Preserve the directory, stop, and rerun the same import.
Receipt import likewise revalidates and reuses its exact local output artifact.
No recovery path broadens the signed source or target set.

The generation-2 current gate accepts no operator-entered event timestamps.
Run it at the exact clean `C2`. The validator first records
`validation_started_at_utc` as the preliminary observation used by its live,
forecast, receipt, bundle, and current-closure checks. Before forecast or
closure validation, it also validates the checked-in signing-key declaration,
generation-2 baseline, and exact corrective kickoff schema, SSHSIG, import
evidence, and path allowlist. The corrective authorization verification
observation must be no later than baseline inventory start.

Only after all substantive checks succeed does the validator sample
`gate_completed_at_utc`. It then confirms the exact chain
`bundle issue <= bundle claim preparation <= bundle import verification <=
validation start <= final gate < bundle expiry`. Corrective-authorization
verification and the identical forecast producer/acceptance import-completion
observation must be no later than validation start. Both kickoff
authorizations and the accepted forecast must remain current through the final
gate. Only after those confirmations does the validator record
`attestation_preparation_started_at_utc` and begin preparing the attestation,
as shown in the absolute-path ceremony above.

These values and the finalizer's freshness comparison are truthful host-clock
observations of validator events, not OpenSSH signing timestamps and not
independently attested time. OpenSSH SSHSIG carries no signing timestamp, so the
deadline proves only that this validator accepted the signature and current
repository state within the bounded finalization window; it does not assert
when the human created the signature.

The earlier `101 passed` governance-unit result in the completion reports is an
accurate generation-1 observation only. It does not verify the amendments in
`R2`. Before `C2`, the full post-amendment verification must execute against
the exact `R2` subject. The replacement BOOT completion receipt, and therefore
the generation-2 bundle, records the exact command, `subject_commit=R2`, start
and completion times with their host-unattested observation basis, collected,
passed, skipped, and failed counts, and process exit code. A result run against
a dirty tree, another commit, or an unrecorded command is not a substitute.

The generation-2 replacement evidence, `C2`, v2 tag, and historical replay were
completed and remain immutable historical facts. They are not, however, a
current authorization to begin S2 after the post-v2 control findings described
at the top of this document. S2 planning or implementation remains prohibited
until a successor corrective result passes the complete required check graph,
new evidence is captured with the repaired import and repository-surface
controls, and a separately signed successor closure and fixed tag pass their
own standalone historical verification.

The GitHub-hosted workflow is configured so Linux CI imports and compiles the
governance module on the declared Python 3.11 floor and executes the
private-input-free governance tests, while Windows CI exercises the
private-input-free governance unit suite, long-path blob regression,
generation-1 historical validation, and a generation-2
topology/tag/self-binding integration. This describes configured coverage, not
a completed verification claim: a green hosted run of the final successor
commit remains mandatory before successor closure. Tests that recompute exact
private-roadmap-derived artifacts are explicitly local-only and are skipped
when that file is absent; synthetic tests still exercise their control flow.
The generation-2 CI test deliberately substitutes synthetic record validators,
so hosted CI is neither accepted-host configuration proof nor a full
generation-2 end-to-end closure. CI never receives or uploads the private
implementation roadmap and does not reproduce the maintainer host or its
unattested clock.
