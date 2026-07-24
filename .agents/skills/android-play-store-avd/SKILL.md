---
name: android-play-store-avd
description: Start or reuse this repository's persistent Google Play Android Virtual Device, route it through proxy_ui, open an app listing or search in Google Play, and diagnose stalled downloads without erasing emulator data. Use when asked to launch the local Android emulator, download or install a Play Store app, reopen the saved Google Play device, or troubleshoot Play downloads stuck at pending.
---

# Android Play Store AVD

Use the checked-in PowerShell launcher as the source of truth. Preserve the
Google account, installed apps, and payment-channel state in the existing AVD.

## Launch

Run commands from the repository root:

```powershell
.\scripts\android\start-google-play-avd.ps1
```

The launcher defaults to AVD `proxy_google_play_35`, serial `emulator-5556`,
and host proxy `10.0.2.2:10811`. It reuses the AVD when it is already running
and prints the actual serial. Always use that serial for later ADB commands
because other emulators may be active.

Open a known package listing:

```powershell
.\scripts\android\start-google-play-avd.ps1 -PackageId "com.openai.chatgpt"
```

Search Google Play when only the display name is known:

```powershell
.\scripts\android\start-google-play-avd.ps1 -SearchQuery "Claude"
```

Use the Play Store UI for installation so purchases and subscriptions remain
associated with Google Play. Do not substitute `adb install` for this workflow.
After opening the listing, use visible UI control when available and leave
password, biometric, purchase, and subscription confirmations to the user.

## Verify

Resolve the SDK path in the same order as the launcher, then inspect the target
serial explicitly:

```powershell
$androidHome = if ($env:ANDROID_HOME) {
    $env:ANDROID_HOME
} elseif ($env:ANDROID_SDK_ROOT) {
    $env:ANDROID_SDK_ROOT
} else {
    Join-Path $env:LOCALAPPDATA "Android\Sdk"
}
$adb = Join-Path $androidHome "platform-tools\adb.exe"

& $adb devices -l
& $adb -s emulator-5556 emu avd name
& $adb -s emulator-5556 shell settings get global http_proxy
& $adb -s emulator-5556 shell settings get global private_dns_mode
```

Expect `proxy_google_play_35`, `10.0.2.2:10811`, and `opportunistic`. Confirm
that the host proxy remains available without restarting it:

```powershell
Get-Process proxy_ui -ErrorAction SilentlyContinue
Get-NetTCPConnection -State Listen -LocalPort 10811
```

To verify that an installation completed:

```powershell
& $adb -s emulator-5556 shell pm path <package-id>
```

## Diagnose Pending Downloads

1. Confirm the launcher-reported serial and AVD name. Do not inspect an
   unrelated headless development emulator.
2. Confirm `proxy_ui` is still running and port `10811` is listening. Never
   stop or restart it merely to launch the AVD.
3. Re-run the launcher to restore opportunistic Private DNS and the explicit
   emulator HTTP proxy.
4. Check recent Play logs without dumping unrelated long-running logs:

```powershell
& $adb -s emulator-5556 logcat -d -T 10m |
    Select-String "Finsky|DownloadManager|Cronet|restriction=|not available"
```

Distinguish a transport failure from a Play eligibility failure. Messages such
as `not available` or `restriction=` can indicate account region or emulator
compatibility even when browsing works.

## Preserve State

Never use `-wipe-data`, delete the AVD, clear Google Play or Play Services data,
remove the Google account, or uninstall apps unless the user explicitly asks
and accepts the data-loss impact. Do not run untargeted `adb shell` commands
when multiple devices are listed. Normal emulator shutdown preserves the AVD
under `%USERPROFILE%\.android\avd\proxy_google_play_35.avd`.
