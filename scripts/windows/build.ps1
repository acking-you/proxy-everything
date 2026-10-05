[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug",
    [switch]$Offline,
    [string]$VisualStudioPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$uiRoot = Join-Path $repoRoot "ui\flutter"
$flutterMode = $Configuration.ToLowerInvariant()
$usedExplicitToolchain = $false
$architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
$flutterArchitecture = switch ($architecture) {
    "X64" { "x64" }
    "Arm64" { "arm64" }
    default { throw "Unsupported Windows architecture: $architecture" }
}

foreach ($command in @("cargo", "fvm")) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "$command was not found on PATH."
    }
}

Push-Location $repoRoot
try {
    $cargoArgs = @("build", "--workspace", "--locked")
    if ($Offline) {
        $cargoArgs += "--offline"
    }
    if ($Configuration -eq "Release") {
        $cargoArgs += "--release"
    }
    & cargo @cargoArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Building the Rust workspace failed with exit code $LASTEXITCODE."
    }

    & (Join-Path $PSScriptRoot "stage-ui-native.ps1") `
        -Configuration $Configuration -SkipBuild

    Push-Location $uiRoot
    try {
        $pubArgs = @("flutter", "pub", "get")
        if ($Offline) {
            $pubArgs += "--offline"
        }
        & fvm @pubArgs
        if ($LASTEXITCODE -ne 0) {
            throw "Resolving Flutter dependencies failed with exit code $LASTEXITCODE."
        }
        & fvm flutter build windows "--$flutterMode" --no-pub
        if ($LASTEXITCODE -ne 0) {
            if (-not $VisualStudioPath) {
                throw "Building Flutter failed. If VS discovery alone is broken, pass -VisualStudioPath pointing to an existing VS 2022 Build Tools installation."
            }
            $usedExplicitToolchain = $true
            & (Join-Path $PSScriptRoot "build-ui-explicit-msvc.ps1") `
                -Configuration $Configuration -VisualStudioPath $VisualStudioPath
        }
    } finally {
        Pop-Location
    }

    $cargoProfile = if ($Configuration -eq "Release") { "release" } else { "debug" }
    $flutterExe = Join-Path $uiRoot `
        "build\windows\$flutterArchitecture\runner\$Configuration\proxy_ui.exe"
    if ($usedExplicitToolchain) {
        $flutterExe = Join-Path $uiRoot "build\windows\$flutterArchitecture-explicit-msvc\runner\$Configuration\proxy_ui.exe"
    }
    Write-Host "Rust binaries: $repoRoot\target\$cargoProfile"
    Write-Host "Flutter app: $flutterExe"
} finally {
    Pop-Location
}
