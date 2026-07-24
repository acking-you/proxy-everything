param(
    [string]$AvdName = "proxy_google_play_35",
    [ValidateRange(5554, 5680)]
    [int]$Port = 5556,
    [string]$ProxyHost = "10.0.2.2",
    [ValidateRange(1, 65535)]
    [int]$ProxyPort = 10811,
    [string]$PackageId = "",
    [string]$SearchQuery = "",
    [ValidateRange(30, 600)]
    [int]$BootTimeoutSeconds = 300
)

$ErrorActionPreference = "Stop"

if ($Port % 2 -ne 0) {
    throw "Android emulator ports must be even numbers."
}
if ($PackageId -and $SearchQuery) {
    throw "Use either PackageId or SearchQuery, not both."
}

$androidHome = if ($env:ANDROID_HOME) {
    $env:ANDROID_HOME
} elseif ($env:ANDROID_SDK_ROOT) {
    $env:ANDROID_SDK_ROOT
} else {
    Join-Path $env:LOCALAPPDATA "Android\Sdk"
}
$emulator = Join-Path $androidHome "emulator\emulator.exe"
$adb = Join-Path $androidHome "platform-tools\adb.exe"

if (-not (Test-Path -LiteralPath $emulator)) {
    throw "Android emulator was not found at $emulator"
}
if (-not (Test-Path -LiteralPath $adb)) {
    throw "ADB was not found at $adb"
}

if ($ProxyHost -eq "10.0.2.2") {
    $proxyListener = Get-NetTCPConnection `
        -State Listen `
        -LocalPort $ProxyPort `
        -ErrorAction SilentlyContinue
    if (-not $proxyListener) {
        Write-Warning (
            "No host listener was found on port $ProxyPort. " +
            "Keep proxy_ui running and confirm its local proxy port."
        )
    }
}

$availableAvds = @(& $emulator -list-avds)
if ($AvdName -notin $availableAvds) {
    throw "AVD '$AvdName' was not found. Available AVDs: $($availableAvds -join ', ')"
}

function Get-RunningAvdName {
    param([string]$Serial)

    $output = @(& $adb -s $Serial emu avd name 2>$null)
    if ($LASTEXITCODE -ne 0) {
        return $null
    }

    return $output |
        Where-Object { $_ -and $_.Trim() -ne "OK" } |
        Select-Object -First 1
}

$serial = $null
$deviceLines = @(& $adb devices)
foreach ($line in $deviceLines) {
    if ($line -match "^(emulator-\d+)\s+device$") {
        $candidateSerial = $Matches[1]
        $candidateAvd = Get-RunningAvdName -Serial $candidateSerial
        if ($candidateAvd -and $candidateAvd.Trim() -eq $AvdName) {
            $serial = $candidateSerial
            break
        }
    }
}

if ($serial) {
    Write-Host "AVD '$AvdName' is already running as $serial."
} else {
    $serial = "emulator-$Port"
    $portOwner = Get-RunningAvdName -Serial $serial
    if ($portOwner) {
        throw "Port $Port is already used by AVD '$($portOwner.Trim())'."
    }

    Write-Host "Starting AVD '$AvdName' as $serial..."
    Start-Process -FilePath $emulator -ArgumentList @(
        "-avd", $AvdName,
        "-port", $Port,
        "-gpu", "host"
    ) | Out-Null
}

$deadline = (Get-Date).AddSeconds($BootTimeoutSeconds)
do {
    Start-Sleep -Seconds 2
    $stateOutput = @(& $adb -s $serial get-state 2>$null)
    $state = if ($stateOutput.Count -gt 0) {
        ([string]$stateOutput[-1]).Trim()
    } else {
        ""
    }
    $bootCompleted = if ($state -eq "device") {
        $bootOutput = @(
            & $adb -s $serial shell getprop sys.boot_completed 2>$null
        )
        if ($bootOutput.Count -gt 0) {
            ([string]$bootOutput[-1]).Trim()
        } else {
            ""
        }
    } else {
        ""
    }
} while ($bootCompleted -ne "1" -and (Get-Date) -lt $deadline)

if ($bootCompleted -ne "1") {
    throw "AVD '$AvdName' did not finish booting within $BootTimeoutSeconds seconds."
}

# A strict Private DNS endpoint can become unvalidated behind TUN and make
# every Play download fail DNS resolution. The explicit HTTP proxy also keeps
# Play's Cronet downloader on TCP instead of the proxied QUIC path.
& $adb -s $serial shell settings put global private_dns_mode opportunistic
& $adb -s $serial shell settings delete global private_dns_specifier |
    Out-Null
& $adb -s $serial shell settings put global http_proxy `
    "$ProxyHost`:$ProxyPort"

if ($PackageId) {
    & $adb -s $serial shell am start `
        -a android.intent.action.VIEW `
        -d "market://details?id=$PackageId" `
        -p com.android.vending | Out-Null
    Write-Host (
        "AVD '$AvdName' is ready as $serial and the Play Store page " +
        "for '$PackageId' has been opened."
    )
} elseif ($SearchQuery) {
    $encodedQuery = [Uri]::EscapeDataString($SearchQuery)
    & $adb -s $serial shell am start `
        -a android.intent.action.VIEW `
        -d "market://search?q=$encodedQuery" `
        -p com.android.vending | Out-Null
    Write-Host (
        "AVD '$AvdName' is ready as $serial and Google Play is " +
        "searching for '$SearchQuery'."
    )
} else {
    & $adb -s $serial shell monkey `
        -p com.android.vending `
        -c android.intent.category.LAUNCHER `
        1 2>$null | Out-Null
    Write-Host "AVD '$AvdName' is ready as $serial and Google Play has been opened."
}
