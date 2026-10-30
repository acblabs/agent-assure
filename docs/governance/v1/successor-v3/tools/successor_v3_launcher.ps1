[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('build', 'tool')]
    [string] $Mode,

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $SuccessorArguments
)

$ExpectedPowerShell = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
$PowerShellProcess = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
if (-not [StringComparer]::OrdinalIgnoreCase.Equals(
        [IO.Path]::GetFullPath($PowerShellProcess),
        [IO.Path]::GetFullPath($ExpectedPowerShell)
    )) {
    throw 'The Generation-3 launcher requires exact Windows PowerShell.'
}
$ProcessArguments = [Environment]::GetCommandLineArgs()
$RequiredHostArguments = @(
    '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File'
)
if ($ProcessArguments.Count -lt 8) {
    throw 'The Generation-3 launcher requires the complete isolated host command line.'
}
for ($Index = 0; $Index -lt $RequiredHostArguments.Count; $Index++) {
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals(
            $ProcessArguments[$Index + 1], $RequiredHostArguments[$Index]
        )) {
        throw 'Invoke the Generation-3 launcher with -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File.'
    }
}
if (-not [StringComparer]::OrdinalIgnoreCase.Equals(
        [IO.Path]::GetFullPath($ProcessArguments[7]),
        [IO.Path]::GetFullPath($PSCommandPath)
    )) {
    throw 'The Generation-3 launcher script argument changed.'
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$LauncherProfile = 'agent-assure-s1-successor-v3-powershell-runtime-launcher/v1'
$ExpectedRuntimeFileCount = 2766
$ExpectedRuntimeSizeBytes = [UInt64] 54224916
$ExpectedRuntimeSha256 = '4e2b76aeadc0f328a00b520b2dc6cb4991486eaa9496b18d5035bac7b63ea152'
$MaximumRuntimeTreeEntries = $ExpectedRuntimeFileCount + 4096
$ExpectedBuilderBytes = [UInt64] 1060101
$ExpectedBuilderSha256 = 'e5c69e7c19d13b3db605e9c4e1d216f6442adf3f11e62d0b8a8083ae14b7976d'
$ExpectedToolBytes = [UInt64] 1602254
$ExpectedToolSha256 = '1c83395d85e4eb49379467fd2f8020c515d3fa17f3d5632462dc7efbe4eddf24'
$RuntimeRoot = 'C:\Users\user\AppData\Roaming\uv\python\cpython-3.12.13-windows-x86_64-none'
$PythonExecutable = Join-Path $RuntimeRoot 'python.exe'
$PackageRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$RepositoryRoot = $PackageRoot
while (-not (Test-Path -LiteralPath (Join-Path $RepositoryRoot '.git') -PathType Container)) {
    $Parent = [IO.Directory]::GetParent($RepositoryRoot)
    if ($null -eq $Parent) {
        throw 'Repository root not found.'
    }
    $RepositoryRoot = $Parent.FullName
}
$ExpectedLauncher = Join-Path $PackageRoot 'tools\successor_v3_launcher.ps1'
$PythonTarget = if ($Mode -ceq 'build') {
    $ExpectedPythonTargetBytes = $ExpectedBuilderBytes
    $ExpectedPythonTargetSha256 = $ExpectedBuilderSha256
    Join-Path $PackageRoot 'tools\build_design_package.py'
}
else {
    $ExpectedPythonTargetBytes = $ExpectedToolBytes
    $ExpectedPythonTargetSha256 = $ExpectedToolSha256
    Join-Path $PackageRoot 'tools\successor_v3_tool.py'
}

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
        $Attributes = [IO.File]::GetAttributes($Cursor)
        if (($Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
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

function Get-ExactFileSha256 {
    param(
        [Parameter(Mandatory = $true)] [string] $LiteralPath,
        [Parameter(Mandatory = $true)] [UInt64] $ExpectedSize,
        [Parameter(Mandatory = $true)] [string] $Owner,
        [Parameter(Mandatory = $true)] [byte[]] $Buffer,
        [Parameter(Mandatory = $true)] [Security.Cryptography.HashAlgorithm] $Hasher
    )
    $FileStream = [IO.File]::Open(
        $LiteralPath,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    try {
        if ([UInt64] $FileStream.Length -ne $ExpectedSize) {
            throw "$Owner size changed before hashing: $LiteralPath"
        }
        $Hasher.Initialize()
        [UInt64] $Remaining = $ExpectedSize
        while ($Remaining -ne 0) {
            $Requested = [int] [Math]::Min([UInt64] $Buffer.Length, $Remaining)
            $Read = $FileStream.Read($Buffer, 0, $Requested)
            if ($Read -le 0) {
                throw "$Owner was truncated while hashing: $LiteralPath"
            }
            [void] $Hasher.TransformBlock($Buffer, 0, $Read, $null, 0)
            $Remaining -= [UInt64] $Read
        }
        if ($FileStream.ReadByte() -ne -1) {
            throw "$Owner grew beyond its exact hash bound: $LiteralPath"
        }
        [byte[]] $Empty = @()
        [void] $Hasher.TransformFinalBlock($Empty, 0, 0)
        [byte[]] $Digest = $Hasher.Hash.Clone()
        return ,$Digest
    }
    finally {
        $FileStream.Dispose()
    }
}

function Get-BoundedRuntimeSurface {
    param(
        [Parameter(Mandatory = $true)] [string] $LiteralRoot,
        [Parameter(Mandatory = $true)] [int] $MaximumEntries
    )
    Assert-NoReparsePath -LiteralPath $LiteralRoot -Owner 'Generation-3 base Python runtime'
    $AbsoluteRoot = [IO.Path]::GetFullPath($LiteralRoot).TrimEnd('\')
    $Prefix = $AbsoluteRoot + '\'
    $Pending = New-Object 'System.Collections.Generic.Stack[string]'
    $Rows = New-Object 'System.Collections.Generic.List[string]'
    $Pending.Push($AbsoluteRoot)
    while ($Pending.Count -ne 0) {
        $Directory = $Pending.Pop()
        $Enumerator = [IO.Directory]::EnumerateFileSystemEntries($Directory).GetEnumerator()
        try {
            while ($Enumerator.MoveNext()) {
                if ($Rows.Count -ge $MaximumEntries) {
                    throw "Base Python runtime exceeds its $MaximumEntries-entry tree bound."
                }
                $EntryPath = [IO.Path]::GetFullPath([string] $Enumerator.Current)
                if (-not $EntryPath.StartsWith($Prefix, [StringComparison]::OrdinalIgnoreCase)) {
                    throw "Base Python runtime enumeration escaped its root: $EntryPath"
                }
                $EntryAttributes = [IO.File]::GetAttributes($EntryPath)
                if (($EntryAttributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    throw "Base Python runtime contains a reparse point: $EntryPath"
                }
                $Relative = $EntryPath.Substring($Prefix.Length).Replace('\', '/')
                if ([String]::IsNullOrEmpty($Relative)) {
                    throw 'Base Python runtime contains an empty relative path.'
                }
                $IsDirectory = ($EntryAttributes -band [IO.FileAttributes]::Directory) -ne 0
                $Kind = if ($IsDirectory) { 'D' } else { 'F' }
                [void] $Rows.Add($Kind + "`t" + $Relative)
                if ($IsDirectory) {
                    $Pending.Push($EntryPath)
                }
            }
        }
        finally {
            if ($Enumerator -is [IDisposable]) {
                $Enumerator.Dispose()
            }
        }
    }
    $Rows.Sort([StringComparer]::Ordinal)
    return $Rows.ToArray()
}

function Get-RuntimeInventoryPass {
    param(
        [Parameter(Mandatory = $true)] [string] $LiteralRoot,
        [Parameter(Mandatory = $true)] [string[]] $Surface,
        [Parameter(Mandatory = $true)] [byte[]] $HashBuffer,
        [Parameter(Mandatory = $true)] [Security.Cryptography.HashAlgorithm] $FileHasher
    )
    $AbsoluteRoot = [IO.Path]::GetFullPath($LiteralRoot).TrimEnd('\')
    $Utf8 = New-Object Text.UTF8Encoding($false)
    $InventoryBytes = New-Object IO.MemoryStream
    $Sha256 = [Security.Cryptography.SHA256]::Create()
    $ContentRows = New-Object 'System.Collections.Generic.List[string]'
    [UInt64] $TotalSize = 0
    try {
        [byte[]] $Domain = $Utf8.GetBytes('agent-assure:s1-base-python-runtime-inventory/v1')
        $InventoryBytes.Write($Domain, 0, $Domain.Length)
        $InventoryBytes.WriteByte(0)
        foreach ($SurfaceRow in $Surface) {
            $Separator = $SurfaceRow.IndexOf("`t", [StringComparison]::Ordinal)
            if ($Separator -ne 1) {
                throw "Base Python runtime surface row is malformed: $SurfaceRow"
            }
            $Kind = $SurfaceRow.Substring(0, 1)
            $RelativePath = $SurfaceRow.Substring(2)
            if ($Kind -ceq 'D') {
                continue
            }
            if ($Kind -cne 'F') {
                throw "Base Python runtime surface has an unsupported entry kind: $SurfaceRow"
            }
            $Parts = $RelativePath.Split([char[]] @('/'), [StringSplitOptions]::RemoveEmptyEntries)
            if ($Parts.Contains('__pycache__')) {
                continue
            }
            if ($RelativePath.EndsWith('.pyc', [StringComparison]::OrdinalIgnoreCase)) {
                throw "Base Python runtime contains sourceless bytecode: $RelativePath"
            }
            if ($ContentRows.Count -ge $ExpectedRuntimeFileCount) {
                throw 'Base Python runtime exceeds its exact file-count bound.'
            }
            $FullPath = Join-Path $AbsoluteRoot $RelativePath.Replace('/', '\')
            $BeforeAttributes = [IO.File]::GetAttributes($FullPath)
            if (($BeforeAttributes -band [IO.FileAttributes]::Directory) -ne 0 -or
                ($BeforeAttributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Base Python runtime file changed type: $RelativePath"
            }
            $BeforeWriteTicks = [IO.File]::GetLastWriteTimeUtc($FullPath).Ticks
            $FileStream = [IO.File]::Open(
                $FullPath,
                [IO.FileMode]::Open,
                [IO.FileAccess]::Read,
                [IO.FileShare]::Read
            )
            try {
                [UInt64] $FileSize = $FileStream.Length
                if ($TotalSize + $FileSize -gt $ExpectedRuntimeSizeBytes) {
                    throw 'Base Python runtime exceeds its exact inventory byte bound.'
                }
                $FileHasher.Initialize()
                [UInt64] $Remaining = $FileSize
                while ($Remaining -ne 0) {
                    $Requested = [int] [Math]::Min([UInt64] $HashBuffer.Length, $Remaining)
                    $Read = $FileStream.Read($HashBuffer, 0, $Requested)
                    if ($Read -le 0) {
                        throw "Base Python runtime file was truncated while hashing: $RelativePath"
                    }
                    [void] $FileHasher.TransformBlock($HashBuffer, 0, $Read, $null, 0)
                    $Remaining -= [UInt64] $Read
                }
                if ($FileStream.ReadByte() -ne -1) {
                    throw "Base Python runtime file grew beyond its exact hash bound: $RelativePath"
                }
                [byte[]] $Empty = @()
                [void] $FileHasher.TransformFinalBlock($Empty, 0, 0)
                [byte[]] $FileDigest = $FileHasher.Hash.Clone()
                $AfterAttributes = [IO.File]::GetAttributes($FullPath)
                $AfterWriteTicks = [IO.File]::GetLastWriteTimeUtc($FullPath).Ticks
                if ([UInt64] $FileStream.Length -ne $FileSize -or
                    $AfterWriteTicks -ne $BeforeWriteTicks -or
                    $AfterAttributes -ne $BeforeAttributes) {
                    throw "Base Python runtime entry changed while hashed: $RelativePath"
                }
            }
            finally {
                $FileStream.Dispose()
            }
            [byte[]] $EncodedPath = $Utf8.GetBytes($RelativePath)
            Write-UInt64BigEndian -Stream $InventoryBytes -Value ([UInt64] $EncodedPath.Length)
            $InventoryBytes.Write($EncodedPath, 0, $EncodedPath.Length)
            Write-UInt64BigEndian -Stream $InventoryBytes -Value $FileSize
            $InventoryBytes.Write($FileDigest, 0, $FileDigest.Length)
            $FileDigestText = [Convert]::ToBase64String($FileDigest)
            [void] $ContentRows.Add($RelativePath + "`t" + $FileSize + "`t" + $FileDigestText)
            $TotalSize += $FileSize
        }
        $InventoryBytes.Position = 0
        [byte[]] $AggregateDigest = $Sha256.ComputeHash($InventoryBytes)
        $ObservedSha256 = -join ($AggregateDigest | ForEach-Object { $_.ToString('x2') })
        return [PSCustomObject] @{
            ContentRows = $ContentRows.ToArray()
            FileCount = $ContentRows.Count
            TotalSize = $TotalSize
            Sha256 = $ObservedSha256
        }
    }
    finally {
        $Sha256.Dispose()
        $InventoryBytes.Dispose()
    }
}

function Test-OrdinalSequenceEqual {
    param(
        [Parameter(Mandatory = $true)] [string[]] $Left,
        [Parameter(Mandatory = $true)] [string[]] $Right
    )
    if ($Left.Count -ne $Right.Count) {
        return $false
    }
    for ($Index = 0; $Index -lt $Left.Count; $Index++) {
        if (-not [StringComparer]::Ordinal.Equals($Left[$Index], $Right[$Index])) {
            return $false
        }
    }
    return $true
}

if (-not [StringComparer]::OrdinalIgnoreCase.Equals(
        [IO.Path]::GetFullPath($PSCommandPath),
        [IO.Path]::GetFullPath($ExpectedLauncher)
    )) {
    throw 'The Generation-3 successor launcher path changed.'
}
Assert-NoReparsePath -LiteralPath $PSCommandPath -Owner 'Generation-3 successor launcher'
Assert-NoReparsePath -LiteralPath $PythonTarget -Owner 'Generation-3 successor Python target'
Assert-NoReparsePath -LiteralPath $RuntimeRoot -Owner 'Generation-3 successor base Python runtime'
Assert-NoReparsePath -LiteralPath $ExpectedPowerShell -Owner 'Generation-3 Windows PowerShell runtime'

$HashBuffer = New-Object byte[] (1024 * 1024)
$FileHasher = [Security.Cryptography.SHA256]::Create()
try {
$PowerShellAttributes = [IO.File]::GetAttributes($ExpectedPowerShell)
$PowerShellItem = [IO.FileInfo]::new($ExpectedPowerShell)
$PowerShellItem.Refresh()
$ExpectedPowerShellBytes = [UInt64] 495616
if (-not $PowerShellItem.Exists -or
    ($PowerShellAttributes -band [IO.FileAttributes]::Directory) -ne 0 -or
    ($PowerShellAttributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
    [UInt64] $PowerShellItem.Length -ne $ExpectedPowerShellBytes) {
    throw 'The Windows PowerShell executable type or size changed.'
}
$PowerShellDigest = Get-ExactFileSha256 `
    -LiteralPath $ExpectedPowerShell `
    -ExpectedSize $ExpectedPowerShellBytes `
    -Owner 'Windows PowerShell executable' `
    -Buffer $HashBuffer `
    -Hasher $FileHasher
$PowerShellHash = -join ($PowerShellDigest | ForEach-Object { $_.ToString('x2') })
$PowerShellAfterAttributes = [IO.File]::GetAttributes($ExpectedPowerShell)
$PowerShellAfter = [IO.FileInfo]::new($ExpectedPowerShell)
$PowerShellAfter.Refresh()
if (-not $PowerShellAfter.Exists -or
    ($PowerShellAfterAttributes -band [IO.FileAttributes]::Directory) -ne 0 -or
    ($PowerShellAfterAttributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
    [UInt64] $PowerShellItem.Length -ne $ExpectedPowerShellBytes -or
    $PowerShellAfter.Length -ne $PowerShellItem.Length -or
    $PowerShellAfter.LastWriteTimeUtc.Ticks -ne $PowerShellItem.LastWriteTimeUtc.Ticks -or
    $PowerShellAfterAttributes -ne $PowerShellAttributes -or
    $PowerShellHash -cne '60c9b29843624dd8af6b6a7b26147753be6aeef65098b9a503cc50850afe410f') {
    throw 'The Windows PowerShell executable identity changed.'
}

$FirstSurface = @(Get-BoundedRuntimeSurface -LiteralRoot $RuntimeRoot -MaximumEntries $MaximumRuntimeTreeEntries)
$FirstInventory = Get-RuntimeInventoryPass `
    -LiteralRoot $RuntimeRoot -Surface $FirstSurface `
    -HashBuffer $HashBuffer -FileHasher $FileHasher
$SecondSurface = @(Get-BoundedRuntimeSurface -LiteralRoot $RuntimeRoot -MaximumEntries $MaximumRuntimeTreeEntries)
if (-not (Test-OrdinalSequenceEqual -Left $FirstSurface -Right $SecondSurface)) {
    throw 'The frozen Generation-3 base Python runtime surface changed between complete passes.'
}
$SecondInventory = Get-RuntimeInventoryPass `
    -LiteralRoot $RuntimeRoot -Surface $SecondSurface `
    -HashBuffer $HashBuffer -FileHasher $FileHasher
if (-not (Test-OrdinalSequenceEqual -Left $FirstInventory.ContentRows -Right $SecondInventory.ContentRows)) {
    throw 'The frozen Generation-3 base Python runtime bytes changed between complete passes.'
}
$ObservedSha256 = $SecondInventory.Sha256
if ($SecondInventory.FileCount -ne $ExpectedRuntimeFileCount -or
    $SecondInventory.TotalSize -ne $ExpectedRuntimeSizeBytes -or
    $ObservedSha256 -cne $ExpectedRuntimeSha256) {
    throw 'The frozen Generation-3 base Python runtime inventory changed.'
}

# Authenticate the selected top-level Python program only after the expensive
# runtime closure checks, immediately before preparing and starting the child.
$PythonTargetAttributes = [IO.File]::GetAttributes($PythonTarget)
$PythonTargetItem = [IO.FileInfo]::new($PythonTarget)
$PythonTargetItem.Refresh()
if (-not $PythonTargetItem.Exists -or
    ($PythonTargetAttributes -band [IO.FileAttributes]::Directory) -ne 0 -or
    ($PythonTargetAttributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
    [UInt64] $PythonTargetItem.Length -ne $ExpectedPythonTargetBytes) {
    throw 'The Generation-3 successor Python target type or size changed.'
}
$PythonTargetDigest = Get-ExactFileSha256 `
    -LiteralPath $PythonTarget `
    -ExpectedSize $ExpectedPythonTargetBytes `
    -Owner 'Generation-3 successor Python target' `
    -Buffer $HashBuffer `
    -Hasher $FileHasher
$PythonTargetHash = -join ($PythonTargetDigest | ForEach-Object { $_.ToString('x2') })
$PythonTargetAfterAttributes = [IO.File]::GetAttributes($PythonTarget)
$PythonTargetAfter = [IO.FileInfo]::new($PythonTarget)
$PythonTargetAfter.Refresh()
if (-not $PythonTargetAfter.Exists -or
    ($PythonTargetAfterAttributes -band [IO.FileAttributes]::Directory) -ne 0 -or
    ($PythonTargetAfterAttributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
    [UInt64] $PythonTargetItem.Length -ne $ExpectedPythonTargetBytes -or
    $PythonTargetAfter.Length -ne $PythonTargetItem.Length -or
    $PythonTargetAfter.LastWriteTimeUtc.Ticks -ne $PythonTargetItem.LastWriteTimeUtc.Ticks -or
    $PythonTargetAfterAttributes -ne $PythonTargetAttributes -or
    $PythonTargetHash -cne $ExpectedPythonTargetSha256) {
    throw 'The Generation-3 successor Python target identity changed.'
}
}
finally {
    $FileHasher.Dispose()
}

$PrivateRoot = 'C:\tmp'
if (-not (Test-Path -LiteralPath $PrivateRoot -PathType Container)) {
    [void] (New-Item -ItemType Directory -Path $PrivateRoot -ErrorAction Stop)
}
Assert-NoReparsePath -LiteralPath $PrivateRoot -Owner 'Generation-3 private runtime root'
$CacheParent = Join-Path $PrivateRoot 'agent-assure-s1-successor-v3-runtime-pycache'
if (-not (Test-Path -LiteralPath $CacheParent -PathType Container)) {
    [void] (New-Item -ItemType Directory -Path $CacheParent -ErrorAction Stop)
}
Assert-NoReparsePath -LiteralPath $CacheParent -Owner 'Generation-3 runtime pycache parent'
$PriorEnvironment = @{}
foreach ($Entry in [Environment]::GetEnvironmentVariables('Process').GetEnumerator()) {
    $PriorEnvironment[[string] $Entry.Key] = [string] $Entry.Value
}
$CacheDirectory = $null
$TempDirectory = $null
$CacheDirectoryCreated = $false
$TempDirectoryCreated = $false
$ChildExitCode = 1
try {
    $CacheDirectory = Join-Path $CacheParent ('run-' + [Guid]::NewGuid().ToString('N'))
    [void] (New-Item -ItemType Directory -Path $CacheDirectory -ErrorAction Stop)
    $CacheDirectoryCreated = $true
    Assert-NoReparsePath -LiteralPath $CacheDirectory -Owner 'Generation-3 runtime pycache directory'
    $TempParent = Join-Path $PrivateRoot 'agent-assure-s1-successor-v3-runtime-temp'
    if (-not (Test-Path -LiteralPath $TempParent -PathType Container)) {
        [void] (New-Item -ItemType Directory -Path $TempParent -ErrorAction Stop)
    }
    Assert-NoReparsePath -LiteralPath $TempParent -Owner 'Generation-3 runtime temporary parent'
    $TempDirectory = Join-Path $TempParent ('run-' + [Guid]::NewGuid().ToString('N'))
    [void] (New-Item -ItemType Directory -Path $TempDirectory -ErrorAction Stop)
    $TempDirectoryCreated = $true
    Assert-NoReparsePath -LiteralPath $TempDirectory -Owner 'Generation-3 runtime temporary directory'
    foreach ($Name in @([Environment]::GetEnvironmentVariables('Process').Keys)) {
        [Environment]::SetEnvironmentVariable([string] $Name, $null, 'Process')
    }
    [Environment]::SetEnvironmentVariable('COMSPEC', 'C:\Windows\System32\cmd.exe', 'Process')
    [Environment]::SetEnvironmentVariable('SYSTEMROOT', 'C:\Windows', 'Process')
    [Environment]::SetEnvironmentVariable('WINDIR', 'C:\Windows', 'Process')
    [Environment]::SetEnvironmentVariable('PATHEXT', '.COM;.EXE;.BAT;.CMD', 'Process')
    [Environment]::SetEnvironmentVariable('AGENT_ASSURE_S1_SUCCESSOR_V3_LAUNCHER_PROFILE', $LauncherProfile, 'Process')
    [Environment]::SetEnvironmentVariable('AGENT_ASSURE_S1_SUCCESSOR_V3_BASE_RUNTIME_SHA256', $ObservedSha256, 'Process')
    [Environment]::SetEnvironmentVariable('PATH', "$RuntimeRoot;$RuntimeRoot\DLLs;C:\Windows\System32;C:\Windows", 'Process')
    [Environment]::SetEnvironmentVariable('NODEFAULTCURRENTDIRECTORYINEXEPATH', '1', 'Process')
    [Environment]::SetEnvironmentVariable('TEMP', $TempDirectory, 'Process')
    [Environment]::SetEnvironmentVariable('TMP', $TempDirectory, 'Process')
    & $PythonExecutable -X "pycache_prefix=$CacheDirectory" -I -S -B -X utf8 $PythonTarget @SuccessorArguments
    $ChildExitCode = $LASTEXITCODE
}
finally {
    foreach ($Name in @([Environment]::GetEnvironmentVariables('Process').Keys)) {
        [Environment]::SetEnvironmentVariable([string] $Name, $null, 'Process')
    }
    foreach ($Entry in $PriorEnvironment.GetEnumerator()) {
        [Environment]::SetEnvironmentVariable([string] $Entry.Key, [string] $Entry.Value, 'Process')
    }
    if ($TempDirectoryCreated -and (Test-Path -LiteralPath $TempDirectory)) {
        Assert-NoReparsePath -LiteralPath $TempDirectory -Owner 'Generation-3 runtime temporary directory'
        [IO.Directory]::Delete($TempDirectory, $true)
    }
    if ($CacheDirectoryCreated -and (Test-Path -LiteralPath $CacheDirectory)) {
        Assert-NoReparsePath -LiteralPath $CacheDirectory -Owner 'Generation-3 runtime pycache directory'
        [IO.Directory]::Delete($CacheDirectory, $true)
    }
}

exit $ChildExitCode
