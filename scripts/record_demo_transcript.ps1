$ErrorActionPreference = "Stop"

# PowerShell helper for refreshing the checked-in flagship transcript.
$outDir = Join-Path ".tmp" "demo-recording"
if (Test-Path $outDir) {
    Remove-Item -LiteralPath $outDir -Recurse -Force
}
New-Item -ItemType Directory -Force docs/assets | Out-Null
agent-assure demo flagship --out $outDir --clean |
    Tee-Object -FilePath (Join-Path "docs/assets" "flagship_demo_transcript.txt")
