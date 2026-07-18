[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug",

    [switch]$SkipBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$cargoProfile = if ($Configuration -eq "Release") { "release" } else { "debug" }
$architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
$flutterArchitecture = switch ($architecture) {
    "X64" { "x64" }
    "Arm64" { "arm64" }
    default { throw "Unsupported Windows architecture: $architecture" }
}

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    throw "cargo was not found. Install Rust with the MSVC toolchain first."
}

Push-Location $repoRoot
try {
    if (-not $SkipBuild) {
        $cargoArgs = @("build", "-p", "proxy-ffi")
        if ($Configuration -eq "Release") {
            $cargoArgs += "--release"
        }
        & cargo @cargoArgs
        if ($LASTEXITCODE -ne 0) {
            throw "Building proxy-ffi failed with exit code $LASTEXITCODE."
        }
    }

    $sourceDll = Join-Path $repoRoot "target\$cargoProfile\http_proxy.dll"
    if (-not (Test-Path -LiteralPath $sourceDll)) {
        throw "Native library was not produced: $sourceDll"
    }
    $sourceWintunDll = Join-Path $repoRoot "target\$cargoProfile\wintun.dll"
    if (-not (Test-Path -LiteralPath $sourceWintunDll)) {
        throw "Wintun runtime was not produced: $sourceWintunDll"
    }

    $nativeDir = Join-Path $repoRoot "ui\flutter\native\windows\$flutterArchitecture"
    New-Item -ItemType Directory -Force -Path $nativeDir | Out-Null
    $destinationDll = Join-Path $nativeDir "http_proxy.dll"
    Copy-Item -LiteralPath $sourceDll -Destination $destinationDll -Force
    Write-Host "Staged Flutter native library: $destinationDll"
    $destinationWintunDll = Join-Path $nativeDir "wintun.dll"
    Copy-Item -LiteralPath $sourceWintunDll -Destination $destinationWintunDll -Force
    Write-Host "Staged Wintun runtime: $destinationWintunDll"
} finally {
    Pop-Location
}
