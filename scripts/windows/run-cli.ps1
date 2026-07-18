[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateSet("server", "client", "admin", "tui")]
    [string]$Component,

    [Parameter(ValueFromRemainingArguments)]
    [string[]]$CommandArguments = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$target = switch ($Component) {
    "server" { @("proxy-server", "http-proxy-server") }
    "client" { @("proxy-client", "http-proxy-cli") }
    "admin" { @("proxy-server", "http-proxy-admin") }
    "tui" { @("proxy-tui", "proxy-tui") }
}

if ($CommandArguments.Count -gt 0 -and $CommandArguments[0] -eq "--") {
    $CommandArguments = if ($CommandArguments.Count -eq 1) {
        @()
    } else {
        $CommandArguments[1..($CommandArguments.Count - 1)]
    }
}

$cargoArgs = @(
    "run",
    "-p", $target[0],
    "--bin", $target[1],
    "--"
) + $CommandArguments

Push-Location $repoRoot
try {
    & cargo @cargoArgs
    if ($LASTEXITCODE -ne 0) {
        throw "$Component exited with code $LASTEXITCODE."
    }
} finally {
    Pop-Location
}
