#!/usr/bin/env python3
"""Compare existing TCP/QUIC local proxies against a controlled HTTP(S) origin.

The origin must implement GET /bytes/<n> with repeated bytes(range(256)), and
POST with a response containing the uploaded body's lowercase SHA-256 digest.
Use a private loopback origin reached through the remote proxy; TLS verification
is enabled. The script never starts proxies or changes system proxy settings.
"""

import argparse
import hashlib
import json
from pathlib import Path
import statistics
import subprocess
import tempfile
import time


def measure(args, directory, label, proxy, size, upload, round_number):
    payload = directory / "payload"
    output = directory / "response"
    expected = hashlib.sha256()
    block = bytes(range(256)) * 4096
    remaining = size
    with payload.open("wb") as destination:
        while remaining:
            data = block[:min(remaining, len(block))]
            expected.update(data)
            destination.write(data)
            remaining -= len(data)
    command = [
        "curl", "--noproxy", "", "--fail", "--silent", "--show-error",
        "--max-time", str(args.timeout), "--proxy", proxy,
        f"{args.origin.rstrip('/')}/bytes/{size}",
        "--output", str(output), "--write-out", "%{json}",
    ]
    if args.ca:
        command += ["--cacert", args.ca]
    if upload:
        command += ["--data-binary", f"@{payload}", "--header", "Expect:"]
    started = time.monotonic()
    result = subprocess.run(command, capture_output=True, text=True, timeout=args.timeout + 5)
    record = {
        "carrier": label,
        "round": round_number,
        "direction": "upload" if upload else "download",
        "bytes": size,
        "wall_seconds": time.monotonic() - started,
        "success": False,
    }
    if result.returncode:
        record["error"] = result.stderr.strip()
        return record
    stats = json.loads(result.stdout)
    if upload:
        verified = output.read_text() == expected.hexdigest()
    else:
        with output.open("rb") as source:
            verified = (
                output.stat().st_size == size
                and hashlib.file_digest(source, "sha256").hexdigest() == expected.hexdigest()
            )
    record.update(
        success=verified,
        seconds=stats["time_total"],
        ttfb_seconds=stats["time_starttransfer"],
        sha256=expected.hexdigest(),
    )
    if not verified:
        record["error"] = "payload checksum mismatch"
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tcp-proxy", required=True, help="e.g. http://127.0.0.1:18080")
    parser.add_argument("--quic-proxy", required=True, help="e.g. http://127.0.0.1:18081")
    parser.add_argument("--origin", required=True, help="controlled HTTP(S) origin URL")
    parser.add_argument("--ca", help="additional HTTPS origin CA PEM (never disables verification)")
    parser.add_argument("--mib", type=int, default=8)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.mib < 1 or args.rounds < 1 or args.timeout < 1:
        parser.error("mib, rounds and timeout must be positive")
    proxies = [("tcp", args.tcp_proxy), ("quic", args.quic_proxy)]
    records = []
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="proxy-carrier-bench-") as temp:
        directory = Path(temp)
        # A small first request distinguishes connection setup from later reuse.
        for label, proxy in proxies:
            records.append(measure(args, directory, label, proxy, 1024, False, -1))
        for round_number in range(args.rounds):
            # Alternate ordering; never run competing bulk transfers concurrently.
            order = proxies if round_number % 2 == 0 else list(reversed(proxies))
            for upload in [False, True]:
                for label, proxy in order:
                    record = measure(
                        args, directory, label, proxy, args.mib * 1024 * 1024,
                        upload, round_number,
                    )
                    records.append(record)
                    print(json.dumps(record), flush=True)
                    args.output.write_text(json.dumps(records, indent=2) + "\n")
    for label, _ in proxies:
        for direction in ["download", "upload"]:
            samples = [
                r["seconds"] for r in records
                if r["carrier"] == label and r["direction"] == direction
                and r["round"] >= 0 and r["success"]
            ]
            if samples:
                median = statistics.median(samples)
                print(f"{label} {direction}: median {median:.3f}s, {args.mib / median:.2f} MiB/s")
    if not all(record["success"] for record in records):
        raise SystemExit("One or more transfers failed; see the result JSON.")


if __name__ == "__main__":
    main()
