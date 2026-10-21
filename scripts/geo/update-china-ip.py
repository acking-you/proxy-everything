#!/usr/bin/env python3
"""Refresh the bundled CN ranges from a pinned china-operator-ip revision."""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'crates/proxy-core/data/china-ip'
REPO = 'https://github.com/gaoyifan/china-operator-ip.git'

def download(revision, name):
    return subprocess.check_output(['curl', '-fsSL', '--retry', '2', '--max-time', '60',
        f'https://raw.githubusercontent.com/gaoyifan/china-operator-ip/{revision}/{name}'])

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--revision', required=True, help='Full immutable ip-lists commit SHA')
    args = parser.parse_args()
    if len(args.revision) != 40 or any(c not in '0123456789abcdef' for c in args.revision):
        parser.error('revision must be a full lowercase commit SHA')
    OUT.mkdir(parents=True, exist_ok=True)
    manifest = {'source': REPO, 'revision': args.revision, 'files': {}}
    for version, name, width in [(4, 'china.txt', 4), (6, 'china6.txt', 16)]:
        source = download(args.revision, name)
        nets = [ipaddress.ip_network(line) for line in source.decode().splitlines() if line.strip()]
        if len(nets) < 100 or any(n.version != version or n.prefixlen == 0 for n in nets):
            raise ValueError('invalid or unexpectedly small country list')
        # Nonoverlapping sorted intervals allow allocation-free binary search in iOS.
        nets = list(ipaddress.collapse_addresses(nets))
        data = b''.join(int(bound).to_bytes(width, 'big') for n in nets
                        for bound in (n.network_address, n.broadcast_address))
        filename = f'ipv{version}.bin'
        (OUT / filename).write_bytes(data)
        manifest['files'][filename] = {'ranges': len(nets), 'sha256': hashlib.sha256(data).hexdigest(),
                                      'source_sha256': hashlib.sha256(source).hexdigest()}
    (OUT / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(manifest, indent=2))

if __name__ == '__main__':
    main()
