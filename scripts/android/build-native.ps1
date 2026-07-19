param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug",
    [ValidateSet("x86_64", "aarch64", "armv7")]
    [string[]]$Architectures = @("x86_64", "aarch64", "armv7"),
    [ValidateRange(24, 35)]
    [int]$ApiLevel = 24,
    [string]$NdkVersion = "28.2.13676358"
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$androidHome = if ($env:ANDROID_HOME) {
    $env:ANDROID_HOME
} elseif ($env:ANDROID_SDK_ROOT) {
    $env:ANDROID_SDK_ROOT
} else {
    Join-Path $env:LOCALAPPDATA "Android\Sdk"
}
$ndkHome = if ($env:ANDROID_NDK_HOME) {
    $env:ANDROID_NDK_HOME
} else {
    Join-Path $androidHome "ndk\$NdkVersion"
}
$toolchain = Join-Path $ndkHome "toolchains\llvm\prebuilt\windows-x86_64\bin"

if (-not (Test-Path -LiteralPath $toolchain)) {
    throw "Android NDK toolchain was not found at $toolchain"
}

$targets = @{
    x86_64 = @{
        RustTarget = "x86_64-linux-android"
        ClangPrefix = "x86_64-linux-android"
        Abi = "x86_64"
    }
    aarch64 = @{
        RustTarget = "aarch64-linux-android"
        ClangPrefix = "aarch64-linux-android"
        Abi = "arm64-v8a"
    }
    armv7 = @{
        RustTarget = "armv7-linux-androideabi"
        ClangPrefix = "armv7a-linux-androideabi"
        Abi = "armeabi-v7a"
    }
}

$env:ANDROID_HOME = $androidHome
$env:ANDROID_NDK_HOME = $ndkHome
if (($env:Path -split ";") -notcontains $toolchain) {
    $env:Path = "$toolchain;$env:Path"
}

Push-Location $repoRoot
try {
    foreach ($architecture in $Architectures) {
        $target = $targets[$architecture]
        $rustTarget = $target.RustTarget
        $clang = Join-Path $toolchain "$($target.ClangPrefix)$ApiLevel-clang.cmd"
        if (-not (Test-Path -LiteralPath $clang)) {
            throw "Android linker was not found at $clang"
        }

        & rustup target add $rustTarget
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to install Rust target $rustTarget"
        }

        $targetKey = $rustTarget.Replace("-", "_")
        [Environment]::SetEnvironmentVariable(
            "CARGO_TARGET_$($targetKey.ToUpperInvariant())_LINKER",
            $clang,
            "Process"
        )
        [Environment]::SetEnvironmentVariable("CC_$targetKey", $clang, "Process")
        [Environment]::SetEnvironmentVariable(
            "AR_$targetKey",
            (Join-Path $toolchain "llvm-ar.exe"),
            "Process"
        )

        $cargoArguments = @("build", "-p", "proxy-ffi", "--target", $rustTarget, "-j", "1")
        if ($Configuration -eq "Release") {
            $cargoArguments += "--release"
        }
        & cargo @cargoArguments
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to build proxy-ffi for $rustTarget"
        }

        $profile = $Configuration.ToLowerInvariant()
        $source = Join-Path $repoRoot "target\$rustTarget\$profile\libhttp_proxy.so"
        $destination = Join-Path $repoRoot "ui\flutter\native\android\$($target.Abi)"
        New-Item -ItemType Directory -Force -Path $destination | Out-Null
        Copy-Item -LiteralPath $source -Destination $destination -Force
        Write-Host "Staged $rustTarget native library in $destination"
    }
} finally {
    Pop-Location
}
