[CmdletBinding()]
param(
    [ValidateSet("Debug", "Profile", "Release")]
    [string]$Mode = "Debug"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$uiRoot = Join-Path $repoRoot "ui\flutter"
$nativeConfiguration = if ($Mode -eq "Debug") { "Debug" } else { "Release" }
$flutterMode = $Mode.ToLowerInvariant()

if (-not (Get-Command fvm -ErrorAction SilentlyContinue)) {
    throw "fvm was not found on PATH. Install FVM before running the Flutter UI."
}

& (Join-Path $PSScriptRoot "stage-ui-native.ps1") `
    -Configuration $nativeConfiguration

Push-Location $uiRoot
try {
    & fvm flutter pub get
    if ($LASTEXITCODE -ne 0) {
        throw "Resolving Flutter dependencies failed with exit code $LASTEXITCODE."
    }
    & fvm flutter run -d windows "--$flutterMode"
    if ($LASTEXITCODE -ne 0) {
        throw "Running the Flutter Windows app failed with exit code $LASTEXITCODE."
    }
} finally {
    Pop-Location
}
