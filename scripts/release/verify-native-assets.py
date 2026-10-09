#!/usr/bin/env python3
"""Reject incomplete or mixed-source native releases and write their checksums."""
import argparse
import hashlib
import json
from pathlib import Path
import tarfile
import zipfile

BINARIES = ("http-proxy-server", "http-proxy-cli", "http-proxy-admin", "proxy-tui")
BINARY_TARGETS = (
    "x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl",
    "armv7-unknown-linux-musleabi", "s390x-unknown-linux-gnu",
    "x86_64-apple-darwin", "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc",
)
FFI_TARGETS = (
    "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu",
    "x86_64-apple-darwin", "aarch64-apple-darwin",
    "aarch64-apple-ios", "x86_64-apple-ios", "aarch64-apple-ios-sim",
    "aarch64-linux-android", "armv7-linux-androideabi", "x86_64-linux-android",
    "x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc",
)


def verify(directory, version, source_commit):
    expected = []
    for binary, targets in [(b, BINARY_TARGETS) for b in BINARIES] + [("libhttp_proxy", FFI_TARGETS)]:
        for target in targets:
            stem = f"{binary}-{version}-{target}"
            extension = ".zip" if "windows" in target else ".tar.gz"
            expected.append((stem, extension, binary, target))
    found = {p.name for p in directory.iterdir() if p.suffix == ".zip" or p.name.endswith(".tar.gz")}
    wanted = {stem + ext for stem, ext, _, _ in expected}
    if found != wanted:
        raise ValueError(f"Release assets differ: missing={sorted(wanted-found)}, unexpected={sorted(found-wanted)}")
    manifest = {"version": version, "source_commit": source_commit, "assets": []}
    for stem, extension, binary, target in expected:
        path = directory / (stem + extension)
        if binary != "libhttp_proxy":
            required = [binary + (".exe" if "windows" in target else "")]
            if "windows" in target and binary == "http-proxy-cli":
                required.append("wintun.dll")
        elif "windows" in target:
            required = ["http_proxy.dll", "http_proxy.lib", "wintun.dll"]
        else:
            required = ["libhttp_proxy.a"]
            if "apple-darwin" in target:
                required += ["libhttp_proxy.dylib", "http-proxy-tun-helper"]
            elif "apple-ios" not in target:
                required += ["libhttp_proxy.so"]
        with (zipfile.ZipFile(path) if extension == ".zip" else tarfile.open(path)) as archive:
            def read(name):
                member = f"{stem}/{name}"
                if extension == ".zip":
                    return archive.read(member)
                info = archive.getmember(member)
                if not info.isfile():
                    raise ValueError(f"{path.name}: {member} is not a regular file")
                return archive.extractfile(info).read()
            provenance = json.loads(read("build-info.json"))
            expected_info = {"version": version, "source_commit": source_commit, "target": target, "component": binary}
            if provenance != expected_info:
                raise ValueError(f"{path.name}: build provenance mismatch")
            for name in required:
                if not read(name):
                    raise ValueError(f"{path.name}: empty {name}")
        with path.open("rb") as file:
            digest = hashlib.file_digest(file, "sha256").hexdigest()
        manifest["assets"].append({"name": path.name, "size": path.stat().st_size,
                                   "sha256": digest,
                                   "target": target, "component": binary})
    (directory / "release-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (directory / "SHA256SUMS").write_text("".join(f"{a['sha256']}  {a['name']}\n" for a in manifest["assets"]))
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("version")
    parser.add_argument("source_commit")
    args = parser.parse_args()
    result = verify(args.directory, args.version, args.source_commit)
    print(f"Verified {len(result['assets'])} fresh native archives for {args.version} at {args.source_commit}")
