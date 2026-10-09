#!/usr/bin/env python3
"""Build a separate sandboxed macOS app and Packet Tunnel extension locally."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
FLUTTER = ROOT / 'ui/flutter'


def run(args, *, cwd=ROOT, env=None):
    build_env = dict(os.environ if env is None else env)
    # CocoaPods rejects ASCII locales used by noninteractive build shells.
    build_env.update(LANG='en_US.UTF-8', LC_ALL='en_US.UTF-8')
    subprocess.run([str(arg) for arg in args], cwd=cwd, env=build_env, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--configuration', choices=['Debug', 'Release'], default='Release')
    parser.add_argument('--architectures', choices=['arm64', 'x86_64', 'universal'], default='universal')
    parser.add_argument('--unsigned', action='store_true', help='Compile/inspect only; unsigned VPN extensions cannot run.')
    parser.add_argument('--team', help='Apple team for automatic development signing. Distribution export is performed in Xcode.')
    parser.add_argument('--archive', action='store_true', help='Create an xcarchive for Xcode validation and App Store export.')
    args = parser.parse_args()
    if platform.system() != 'Darwin':
        parser.error('This build requires macOS and Xcode.')
    if not args.unsigned and not args.team:
        parser.error('Provide --team for signing, or --unsigned for compile-only verification.')
    if args.unsigned and args.archive:
        parser.error('An unsigned archive is not a distributable App Store archive.')
    if args.archive and (args.configuration != 'Release' or args.architectures != 'universal'):
        parser.error('Store archives require a Release universal build.')

    rust_profile = args.configuration.lower()
    architectures = ['arm64', 'x86_64'] if args.architectures == 'universal' else [args.architectures]
    triples = {'arm64': 'aarch64-apple-darwin', 'x86_64': 'x86_64-apple-darwin'}
    cargo_target = ROOT / 'target/macos-app-store'
    native = FLUTTER / 'native/macos-app-store' / rust_profile
    native.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, MACOSX_DEPLOYMENT_TARGET='13.0', CARGO_TARGET_DIR=str(cargo_target))
    env.setdefault('CC', '/usr/bin/clang')
    env.setdefault('CXX', '/usr/bin/clang++')
    for arch in architectures:
        run(['rustup', 'target', 'add', triples[arch]])
        command = ['cargo', 'build', '--locked', '-p', 'proxy-ffi', '--features', 'mac-app-store', '--target', triples[arch]]
        if args.configuration == 'Release':
            command.append('--release')
        run(command, env=env)
    for name in ['libhttp_proxy.a', 'libhttp_proxy.dylib']:
        sources = [cargo_target / triples[arch] / rust_profile / name for arch in architectures]
        if len(sources) == 1:
            shutil.copyfile(sources[0], native / name)
        else:
            run(['lipo', '-create', *sources, '-output', native / name])
    run(['install_name_tool', '-id', '@rpath/libhttp_proxy.dylib', native / 'libhttp_proxy.dylib'])
    run(['codesign', '--force', '--sign', '-', native / 'libhttp_proxy.dylib'])
    manifest = {'features': ['mac-app-store'], 'architectures': architectures, 'configuration': args.configuration,
                'sha256': {name: hashlib.sha256((native / name).read_bytes()).hexdigest()
                           for name in ['libhttp_proxy.a', 'libhttp_proxy.dylib']}}
    (native / 'build.json').write_text(json.dumps(manifest, indent=2) + '\n')

    run(['fvm', 'install'], cwd=FLUTTER)
    run(['fvm', 'flutter', 'pub', 'get'], cwd=FLUTTER)
    run(['fvm', 'flutter', 'build', 'macos', '--config-only', '--flavor', 'appstore',
         '--' + rust_profile, '--dart-define=MAC_APP_STORE=true'], cwd=FLUTTER)
    # config-only does not run CocoaPods on every Flutter version.
    run(['pod', 'install'], cwd=FLUTTER / 'macos')
    output = FLUTTER / 'build/macos-app-store'
    command = ['xcodebuild', '-workspace', FLUTTER / 'macos/Runner.xcworkspace', '-scheme', 'appstore',
               '-configuration', args.configuration + '-appstore', '-derivedDataPath', output,
               'ARCHS=' + ' '.join(architectures), 'ONLY_ACTIVE_ARCH=NO']
    if args.unsigned:
        command += ['CODE_SIGNING_ALLOWED=NO', 'CODE_SIGNING_REQUIRED=NO']
    else:
        command += ['DEVELOPMENT_TEAM=' + args.team, '-allowProvisioningUpdates']
    if args.archive:
        command += ['archive', '-archivePath', output / 'CipherRelay.xcarchive']
    else:
        command += ['build']
    run(command)
    app = output / ('CipherRelay.xcarchive/Products/Applications/CipherRelay.app' if args.archive else
                    'Build/Products/' + args.configuration + '-appstore/CipherRelay.app')
    verification = ['python3', FLUTTER / 'scripts/macos/verify_store_bundle.py', app]
    if args.unsigned:
        verification.append('--unsigned')
    run(verification)
    print(f'Store app: {app}')
    if args.unsigned:
        print('Compile-only output: provision and sign both targets before trying to connect the VPN.')


if __name__ == '__main__':
    main()
