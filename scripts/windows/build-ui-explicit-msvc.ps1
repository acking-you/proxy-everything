[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",
    [Parameter(Mandatory = $true)]
    [string]$VisualStudioPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$uiRoot = Join-Path $repoRoot "ui\flutter"
$visualStudio = (Resolve-Path $VisualStudioPath).Path
$vcvars = Join-Path $visualStudio "VC\Auxiliary\Build\vcvars64.bat"
$cmake = Join-Path $visualStudio "Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
$ninja = Join-Path $visualStudio "Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe"
$generatedConfig = Join-Path $uiRoot "windows\flutter\ephemeral\generated_config.cmake"
foreach ($required in @($vcvars, $cmake, $ninja, $generatedConfig)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required build input is missing: $required. Run build.ps1 first to generate Flutter's configuration."
    }
}
if ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() -ne "X64") {
    throw "Explicit MSVC fallback currently supports Windows x64 only."
}
# This is a real MSVC/CMake build, not replacement VS-discovery output. vcvars
# changes only the owned child process environment; no SDK/registry repair.
$buildDir = Join-Path $uiRoot "build\windows\x64-explicit-msvc"
New-Item -ItemType Directory -Force $buildDir | Out-Null
$script = Join-Path $buildDir "build.cmd"
# Reject cmd metacharacters rather than interpolate untrusted path syntax.
foreach ($value in @($vcvars, $cmake, $ninja, $uiRoot, $buildDir)) {
    if ($value.IndexOfAny([char[]]'"%&|<>^!') -ge 0) { throw "Unsupported build path: $value" }
}
$commands = @(
    '@echo off',
    "call `"$vcvars`" >nul",
    'if errorlevel 1 exit /b %errorlevel%',
    "`"$cmake`" -S `"$uiRoot\windows`" -B `"$buildDir`" -G `"Ninja Multi-Config`" -DCMAKE_MAKE_PROGRAM=`"$ninja`" -DFLUTTER_TARGET_PLATFORM=windows-x64",
    'if errorlevel 1 exit /b %errorlevel%',
    # Flutter's generated import library is a side effect of flutter_assemble;
    # generate it before Ninja walks plugins that link against that file.
    "`"$cmake`" --build `"$buildDir`" --config $Configuration --target flutter_assemble --parallel 4",
    'if errorlevel 1 exit /b %errorlevel%',
    "`"$cmake`" --build `"$buildDir`" --config $Configuration --target install --parallel 4",
    'exit /b %errorlevel%'
)
[System.IO.File]::WriteAllLines($script, $commands, [System.Text.Encoding]::Default)
& $env:ComSpec /d /c "`"$script`""
if ($LASTEXITCODE -ne 0) { throw "Explicit MSVC build failed with exit code $LASTEXITCODE." }
$bundle = Join-Path $buildDir "runner\$Configuration"
foreach ($file in @("proxy_ui.exe", "http_proxy.dll", "wintun.dll", "flutter_windows.dll", "data\flutter_assets\AssetManifest.bin")) {
    if (-not (Test-Path -LiteralPath (Join-Path $bundle $file))) { throw "Incomplete Windows bundle: missing $file" }
}
Write-Host "Complete Windows bundle: $bundle"
