#!/usr/bin/env python3
"""Export a signed Store archive, or upload it to App Store Connect explicitly."""
import argparse
import os
from pathlib import Path
import plistlib
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--team', required=True)
    parser.add_argument('--app-profile', default='CipherRelay Mac App Store')
    parser.add_argument('--extension-profile', default='CipherRelay Mac App Store Packet Tunnel')
    parser.add_argument('--signing-certificate', default='Mac App Distribution')
    parser.add_argument('--installer-certificate', default='Mac Installer Distribution')
    parser.add_argument('--upload', action='store_true', help='Validate and upload the build to App Store Connect; does not submit App Review.')
    args = parser.parse_args()
    archive = args.archive.resolve()
    output = args.output.resolve()
    app = archive / 'Products/Applications/CipherRelay Store.app'
    if not app.is_dir():
        parser.error('Archive must contain CipherRelay Store.app.')
    info = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
    if info.get('CFBundleIdentifier') != 'com.proxyui.proxyUi.store':
        parser.error('Refusing to export the direct-download application as a Store app.')
    if output.exists() and any(output.iterdir()):
        parser.error('Output directory must be empty to preserve earlier exports.')
    auth = [os.environ.get(name) for name in ('APPLE_API_KEY_PATH', 'APPLE_API_KEY_ID', 'APPLE_API_ISSUER_ID')]
    if any(auth) and not all(auth):
        parser.error('Set APPLE_API_KEY_PATH, APPLE_API_KEY_ID and APPLE_API_ISSUER_ID together.')
    if args.upload and not all(auth):
        parser.error('Upload requires the three APPLE_API_* variables. Keep the private key outside the repository.')
    options = {
        'method': 'app-store-connect',
        'destination': 'upload' if args.upload else 'export',
        'teamID': args.team,
        'signingStyle': 'manual',
        'signingCertificate': args.signing_certificate,
        'installerSigningCertificate': args.installer_certificate,
        'manageAppVersionAndBuildNumber': False,
        'uploadSymbols': True,
        'provisioningProfiles': {
            'com.proxyui.proxyUi.store': args.app_profile,
            'com.proxyui.proxyUi.store.PacketTunnel': args.extension_profile,
        },
    }
    with tempfile.TemporaryDirectory(prefix='cipherrelay-store-export-') as directory:
        settings = Path(directory) / 'ExportOptions.plist'
        settings.write_bytes(plistlib.dumps(options))
        command = ['xcodebuild', '-exportArchive', '-archivePath', str(archive),
                   '-exportPath', str(output), '-exportOptionsPlist', str(settings)]
        if all(auth):
            command += ['-authenticationKeyPath', auth[0], '-authenticationKeyID', auth[1],
                        '-authenticationKeyIssuerID', auth[2]]
        result = subprocess.run(command, env=dict(os.environ, LANG='en_US.UTF-8', LC_ALL='en_US.UTF-8'))
        if result.returncode:
            raise SystemExit(result.returncode)
    print('Build uploaded; App Review submission is a separate step.' if args.upload else f'Store export: {output}')


if __name__ == '__main__':
    main()
