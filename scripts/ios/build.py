#!/usr/bin/env python3
"""Build the iOS app and its packet tunnel locally, optionally install them."""

import argparse
import datetime
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
FLUTTER = ROOT / "ui/flutter"


def run(args, *, cwd=ROOT, env=None):
    subprocess.run(
        [str(arg) for arg in args],
        cwd=cwd,
        env=dict(os.environ if env is None else env, LANG="en_US.UTF-8", LC_ALL="en_US.UTF-8"),
        check=True,
    )


def output(*args):
    return subprocess.check_output([str(arg) for arg in args], stderr=subprocess.DEVNULL)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify(app, *, simulator, unsigned):
    extension = app / "PlugIns/PacketTunnel.appex"
    infos = [plistlib.loads((bundle / "Info.plist").read_bytes()) for bundle in [app, extension]]
    require(infos[0]["CFBundleIdentifier"] == "com.proxyui.proxyUi", "Unexpected iOS app identifier")
    require(infos[1]["CFBundleIdentifier"] == infos[0]["CFBundleIdentifier"] + ".PacketTunnel",
            "Extension identifier does not belong to the app")
    require(infos[1]["NSExtension"]["NSExtensionPointIdentifier"] == "com.apple.networkextension.packet-tunnel",
            "Missing packet tunnel extension point")
    for key in ["CFBundleVersion", "CFBundleShortVersionString"]:
        require(infos[0][key] == infos[1][key], f"App and extension {key} differ")
    binaries = [bundle / info["CFBundleExecutable"] for bundle, info in zip([app, extension], infos)]
    architectures = [output("lipo", "-archs", binary).decode().split() for binary in binaries]
    require(architectures[0] == architectures[1], "App and extension architectures differ")
    # Xcode can put Debug code in a dylib beside a small launcher executable.
    # Dart must find the FFI exports in that library or the Release executable.
    debug_library = app / (infos[0]["CFBundleExecutable"] + ".debug.dylib")
    ffi_binary = debug_library if debug_library.exists() else binaries[0]
    symbols = output("nm", "-gU", ffi_binary)
    for symbol in [b"_proxy_create", b"_proxy_get_server_nodes", b"_proxy_galaxy_project_segments_v1"]:
        require(symbol in symbols, f"Missing Dart FFI symbol: {symbol.decode()}")
    require(not list(app.rglob("http-proxy-tun-helper")), "Desktop helper in iOS bundle")
    profiles = []
    if not unsigned and not simulator:
        groups = []
        teams = []
        for bundle, info in zip([app, extension], infos):
            output("codesign", "--verify", "--strict", bundle)
            policy = plistlib.loads(output("codesign", "-d", "--entitlements", ":-", bundle))
            profile = plistlib.loads(output("security", "cms", "-D", "-i", bundle / "embedded.mobileprovision"))
            require(profile["ExpirationDate"] > datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None),
                    "Provisioning profile expired")
            allowed = profile["Entitlements"]
            entitlement = "com.apple.developer.networking.networkextension"
            require("packet-tunnel-provider" in policy.get(entitlement, []), "Signed VPN entitlement missing")
            require("packet-tunnel-provider" in allowed.get(entitlement, []), "Profile does not permit VPN")
            team = policy.get("com.apple.developer.team-identifier")
            require(team in profile.get("TeamIdentifier", []), "Team and profile mismatch")
            require(policy.get("application-identifier", "").endswith("." + info["CFBundleIdentifier"]),
                    "Signed application identifier mismatch")
            for group in policy.get("keychain-access-groups", []):
                require(any(fnmatch.fnmatchcase(group, pattern) for pattern in allowed.get("keychain-access-groups", [])),
                        "Profile does not allow shared Keychain group")
            group = info["ProxyUIKeychainAccessGroup"]
            require(group in policy.get("keychain-access-groups", []), "Runtime Keychain group missing from signature")
            groups.append(group)
            teams.append(team)
            profiles.append({"bundle": info["CFBundleIdentifier"], "expires": profile["ExpirationDate"].isoformat()})
        require(groups[0] == groups[1] and teams[0] == teams[1], "App and extension cannot share credentials")
        output("codesign", "--verify", "--deep", "--strict", app)
    return {
        "app": str(app),
        "version": infos[0]["CFBundleShortVersionString"],
        "build": infos[0]["CFBundleVersion"],
        "architectures": architectures[0],
        "simulator": simulator,
        "device_signature_verified": not unsigned and not simulator,
        "profiles": profiles,
        "executable_sha256": hashlib.sha256(binaries[0].read_bytes()).hexdigest(),
        "ffi_binary_sha256": hashlib.sha256(ffi_binary.read_bytes()).hexdigest(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--simulator", action="store_true")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default=None)
    parser.add_argument("--team", help="Apple Developer team ID for development signing")
    parser.add_argument("--unsigned", action="store_true", help="Device compile check only; cannot install")
    parser.add_argument("--install", metavar="UDID", help="Install and launch on this simulator UUID or paired device UDID")
    args = parser.parse_args()
    if platform.system() != "Darwin":
        parser.error("macOS and Xcode are required")
    configuration = args.configuration or ("Debug" if args.simulator else "Release")
    if args.simulator and configuration != "Debug":
        parser.error("Flutter simulator builds require Debug")
    if args.unsigned and args.install:
        parser.error("Unsigned device builds cannot be installed")
    if not args.simulator and not args.unsigned and not args.team:
        parser.error("Supply --team for device signing or --unsigned for a compile check")
    arch = platform.machine() if args.simulator else "arm64"
    sdk = "iphonesimulator" if args.simulator else "iphoneos"
    triple = (
        ("aarch64-apple-ios-sim" if arch == "arm64" else "x86_64-apple-ios")
        if args.simulator else "aarch64-apple-ios"
    )
    cargo_target = ROOT / "target/ios-development"
    native = FLUTTER / "native/ios" / sdk
    native.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, CARGO_TARGET_DIR=str(cargo_target), IPHONEOS_DEPLOYMENT_TARGET="15.0",
               CC="/usr/bin/clang", CXX="/usr/bin/clang++")
    run(["rustup", "target", "add", triple])
    run(["cargo", "build", "--locked", "-p", "proxy-ffi", "--features", "network-extension",
         "--target", triple, "--release"], env=env)
    shutil.copyfile(cargo_target / triple / "release/libhttp_proxy.a", native / "libhttp_proxy.a")
    run(["fvm", "flutter", "pub", "get"], cwd=FLUTTER)
    run(["fvm", "flutter", "build", "ios", "--config-only", "--no-codesign",
         "--" + configuration.lower(), *(["--simulator"] if args.simulator else [])], cwd=FLUTTER)
    run(["pod", "install"], cwd=FLUTTER / "ios")
    build = FLUTTER / ("build/ios-vpn-simulator" if args.simulator else "build/ios-vpn-device")
    command = [
        "xcodebuild", "-workspace", FLUTTER / "ios/Runner.xcworkspace", "-scheme", "Runner",
        "-configuration", configuration, "-sdk", sdk,
        "-destination", (
            "generic/platform=iOS Simulator" if args.simulator
            else "id=" + args.install if args.install else "generic/platform=iOS"
        ),
        "-derivedDataPath", build, "ARCHS=" + arch, "ONLY_ACTIVE_ARCH=YES",
    ]
    if args.unsigned or args.simulator:
        command += ["CODE_SIGNING_ALLOWED=NO"]
    else:
        command += ["DEVELOPMENT_TEAM=" + args.team, "-allowProvisioningUpdates"]
        if args.install:
            command += ["-allowProvisioningDeviceRegistration"]
        # Optional App Store Connect API authentication remains outside the repo.
        auth = [os.environ.get(key) for key in ["APPLE_API_KEY_PATH", "APPLE_API_KEY_ID", "APPLE_API_ISSUER_ID"]]
        if any(auth):
            require(all(auth), "Set all three APPLE_API_* variables together")
            command += ["-authenticationKeyPath", auth[0], "-authenticationKeyID", auth[1],
                        "-authenticationKeyIssuerID", auth[2]]
    run([*command, "build"])
    app = build / f"Build/Products/{configuration}-{sdk}/CipherRelay.app"
    result = verify(app, simulator=args.simulator, unsigned=args.unsigned)
    (build / "verification.json").write_text(json.dumps(result, indent=2) + "\n")
    if args.install:
        if args.simulator:
            run(["xcrun", "simctl", "install", args.install, app])
            run(["xcrun", "simctl", "launch", args.install, "com.proxyui.proxyUi"])
        else:
            run(["xcrun", "devicectl", "device", "install", "app", "--device", args.install, app])
            run(["xcrun", "devicectl", "device", "process", "launch", "--device", args.install, "com.proxyui.proxyUi"])
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
