[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $GovernanceArguments
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$LauncherProfile = 'agent-assure-s1-powershell-runtime-launcher/v1'
$ExpectedRuntimeFileCount = 2766
$ExpectedRuntimeSizeBytes = [UInt64] 54224916
$ExpectedRuntimeSha256 = '4e2b76aeadc0f328a00b520b2dc6cb4991486eaa9496b18d5035bac7b63ea152'
$RuntimeRoot = 'C:\Users\user\AppData\Roaming\uv\python\cpython-3.12.13-windows-x86_64-none'
$PythonExecutable = Join-Path $RuntimeRoot 'python.exe'
$RepositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$PythonValidator = Join-Path $RepositoryRoot 'scripts\v1_s1_governance.py'
$ExpectedLauncher = Join-Path $RepositoryRoot 'scripts\v1_s1_governance.ps1'

function Assert-NoReparsePath {
    param(
        [Parameter(Mandatory = $true)] [string] $LiteralPath,
        [Parameter(Mandatory = $true)] [string] $Owner
    )

    $Absolute = [IO.Path]::GetFullPath($LiteralPath)
    $Root = [IO.Path]::GetPathRoot($Absolute)
    $Cursor = $Root
    $Remainder = $Absolute.Substring($Root.Length)
    foreach ($Component in $Remainder.Split([char[]] @('\'), [StringSplitOptions]::RemoveEmptyEntries)) {
        $Cursor = Join-Path $Cursor $Component
        $Item = Get-Item -LiteralPath $Cursor -Force -ErrorAction Stop
        if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Owner contains a reparse point: $Cursor"
        }
    }
}

function Write-UInt64BigEndian {
    param(
        [Parameter(Mandatory = $true)] [IO.Stream] $Stream,
        [Parameter(Mandatory = $true)] [UInt64] $Value
    )

    [byte[]] $Bytes = [BitConverter]::GetBytes($Value)
    if ([BitConverter]::IsLittleEndian) {
        [Array]::Reverse($Bytes)
    }
    $Stream.Write($Bytes, 0, $Bytes.Length)
}

if (-not [StringComparer]::OrdinalIgnoreCase.Equals(
        [IO.Path]::GetFullPath($PSCommandPath),
        [IO.Path]::GetFullPath($ExpectedLauncher)
    )) {
    throw 'The S1 launcher path changed.'
}

Assert-NoReparsePath -LiteralPath $PSCommandPath -Owner 'S1 governance launcher'
Assert-NoReparsePath -LiteralPath $PythonValidator -Owner 'S1 governance validator'
Assert-NoReparsePath -LiteralPath $RuntimeRoot -Owner 'S1 base Python runtime'

$Entries = @(Get-ChildItem -LiteralPath $RuntimeRoot -Recurse -Force -ErrorAction Stop)
foreach ($Entry in $Entries) {
    if (($Entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "S1 base Python runtime contains a reparse point: $($Entry.FullName)"
    }
}

$RuntimePrefix = $RuntimeRoot.TrimEnd('\') + '\'
$RelativePaths = New-Object 'System.Collections.Generic.List[string]'
foreach ($Entry in $Entries) {
    if (-not $Entry.PSIsContainer) {
        $Relative = $Entry.FullName.Substring($RuntimePrefix.Length).Replace('\', '/')
        $Parts = $Relative.Split([char[]] @('/'), [StringSplitOptions]::RemoveEmptyEntries)
        if ($Parts.Contains('__pycache__')) {
            continue
        }
        if ($Relative.EndsWith('.pyc', [StringComparison]::OrdinalIgnoreCase)) {
            throw "S1 base Python runtime contains sourceless bytecode: $Relative"
        }
        else {
            [void] $RelativePaths.Add($Relative)
        }
    }
}
$RelativePaths.Sort([StringComparer]::Ordinal)

$Utf8 = New-Object Text.UTF8Encoding($false)
$InventoryBytes = New-Object IO.MemoryStream
$Sha256 = [Security.Cryptography.SHA256]::Create()
[UInt64] $TotalSize = 0
try {
    [byte[]] $Domain = $Utf8.GetBytes('agent-assure:s1-base-python-runtime-inventory/v1')
    $InventoryBytes.Write($Domain, 0, $Domain.Length)
    $InventoryBytes.WriteByte(0)

    foreach ($RelativePath in $RelativePaths) {
        [byte[]] $EncodedPath = $Utf8.GetBytes($RelativePath)
        Write-UInt64BigEndian -Stream $InventoryBytes -Value ([UInt64] $EncodedPath.Length)
        $InventoryBytes.Write($EncodedPath, 0, $EncodedPath.Length)

        $FullPath = Join-Path $RuntimeRoot $RelativePath.Replace('/', '\')
        $FileStream = [IO.File]::Open(
            $FullPath,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read
        )
        try {
            [UInt64] $FileSize = $FileStream.Length
            [byte[]] $FileDigest = $Sha256.ComputeHash($FileStream)
        }
        finally {
            $FileStream.Dispose()
        }
        Write-UInt64BigEndian -Stream $InventoryBytes -Value $FileSize
        $InventoryBytes.Write($FileDigest, 0, $FileDigest.Length)
        $TotalSize += $FileSize
    }

    $InventoryBytes.Position = 0
    [byte[]] $AggregateDigest = $Sha256.ComputeHash($InventoryBytes)
    $ObservedSha256 = -join ($AggregateDigest | ForEach-Object { $_.ToString('x2') })
}
finally {
    $Sha256.Dispose()
    $InventoryBytes.Dispose()
}

if ($RelativePaths.Count -ne $ExpectedRuntimeFileCount -or
    $TotalSize -ne $ExpectedRuntimeSizeBytes -or
    $ObservedSha256 -cne $ExpectedRuntimeSha256) {
    throw 'The frozen S1 base Python runtime inventory changed.'
}

$ProfileVariable = 'AGENT_ASSURE_S1_LAUNCHER_PROFILE'
$DigestVariable = 'AGENT_ASSURE_S1_BASE_RUNTIME_SHA256'
$PriorProfile = [Environment]::GetEnvironmentVariable($ProfileVariable, 'Process')
$PriorDigest = [Environment]::GetEnvironmentVariable($DigestVariable, 'Process')
$ConstrainedVariables = @(
    'OPENSSL_CONF',
    'OPENSSL_ENGINES',
    'OPENSSL_MODULES',
    'PATH',
    'NoDefaultCurrentDirectoryInExePath'
)
$PriorEnvironment = @{}
foreach ($Name in $ConstrainedVariables) {
    $PriorEnvironment[$Name] = [Environment]::GetEnvironmentVariable($Name, 'Process')
}
$PrivateRoot = Join-Path $RepositoryRoot '.tmp'
if (Test-Path -LiteralPath $PrivateRoot) {
    Assert-NoReparsePath -LiteralPath $PrivateRoot -Owner 'S1 private runtime root'
}
else {
    [void] (New-Item -ItemType Directory -Path $PrivateRoot -ErrorAction Stop)
    Assert-NoReparsePath -LiteralPath $PrivateRoot -Owner 'S1 private runtime root'
}
$CacheParent = Join-Path $PrivateRoot 's1-runtime-pycache'
if (Test-Path -LiteralPath $CacheParent) {
    Assert-NoReparsePath -LiteralPath $CacheParent -Owner 'S1 runtime pycache parent'
}
else {
    [void] (New-Item -ItemType Directory -Path $CacheParent -ErrorAction Stop)
    Assert-NoReparsePath -LiteralPath $CacheParent -Owner 'S1 runtime pycache parent'
}
$CacheDirectory = Join-Path $CacheParent ('run-' + [Guid]::NewGuid().ToString('N'))
[void] (New-Item -ItemType Directory -Path $CacheDirectory -ErrorAction Stop)
Assert-NoReparsePath -LiteralPath $CacheDirectory -Owner 'S1 runtime pycache directory'
$ChildExitCode = 1
try {
    [Environment]::SetEnvironmentVariable($ProfileVariable, $LauncherProfile, 'Process')
    [Environment]::SetEnvironmentVariable($DigestVariable, $ObservedSha256, 'Process')
    [Environment]::SetEnvironmentVariable('OPENSSL_CONF', $null, 'Process')
    [Environment]::SetEnvironmentVariable('OPENSSL_ENGINES', $null, 'Process')
    [Environment]::SetEnvironmentVariable('OPENSSL_MODULES', $null, 'Process')
    [Environment]::SetEnvironmentVariable(
        'PATH',
        "$RuntimeRoot;$RuntimeRoot\DLLs;C:\Windows\System32;C:\Windows",
        'Process'
    )
    [Environment]::SetEnvironmentVariable(
        'NoDefaultCurrentDirectoryInExePath',
        '1',
        'Process'
    )
    & $PythonExecutable -X "pycache_prefix=$CacheDirectory" -I -S -B `
        $PythonValidator @GovernanceArguments
    $ChildExitCode = $LASTEXITCODE
}
finally {
    [Environment]::SetEnvironmentVariable($ProfileVariable, $PriorProfile, 'Process')
    [Environment]::SetEnvironmentVariable($DigestVariable, $PriorDigest, 'Process')
    foreach ($Name in $ConstrainedVariables) {
        [Environment]::SetEnvironmentVariable($Name, $PriorEnvironment[$Name], 'Process')
    }
    if (Test-Path -LiteralPath $CacheDirectory) {
        Assert-NoReparsePath -LiteralPath $CacheDirectory -Owner 'S1 runtime pycache directory'
        [IO.Directory]::Delete($CacheDirectory, $true)
    }
}

exit $ChildExitCode
