"""Exercise the actual update button in an installed Android release APK.

Requires a connected test device with an English or Chinese UI and working
Internet access. Does not install, clear app data, or change network settings.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import time
import xml.etree.ElementTree as ET

PACKAGE = 'com.proxyui.proxy_ui'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adb', required=True)
    parser.add_argument('--serial', required=True)
    parser.add_argument('--expected-code', required=True, type=int)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()

    def adb(*command):
        return subprocess.check_output(
            [args.adb, '-s', args.serial, *command], text=True,
            encoding='utf-8', errors='replace', timeout=30).strip()

    def nodes():
        adb('shell', 'uiautomator', 'dump', '/sdcard/cipherrelay-update-check.xml')
        return list(ET.fromstring(adb('shell', 'cat', '/sdcard/cipherrelay-update-check.xml')).iter('node'))

    def label(node):
        return node.get('content-desc', '') or node.get('text', '')

    def tap(node):
        x1, y1, x2, y2 = map(int, re.findall(r'\d+', node.attrib['bounds']))
        adb('shell', 'input', 'tap', str((x1 + x2) // 2), str((y1 + y2) // 2))

    package = adb('shell', 'dumpsys', 'package', PACKAGE)
    code = int(re.search(r'versionCode=(\d+)', package)[1])
    assert code == args.expected_code, (code, args.expected_code)
    adb('shell', 'am', 'start', '-W', '-n', f'{PACKAGE}/.MainActivity')
    pid = adb('shell', 'pidof', PACKAGE)
    assert pid
    checks = []
    for index in range(3):
        if index == 1:
            adb('shell', 'input', 'keyevent', 'KEYCODE_HOME')
            time.sleep(2)
            adb('shell', 'am', 'start', '-W', '-n', f'{PACKAGE}/.MainActivity')
        button = next(n for n in nodes() if label(n) in ('Check for updates', '检查更新'))
        tap(button)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            assert adb('shell', 'pidof', PACKAGE) == pid, 'Application exited or restarted during update check'
            current = nodes()
            status = next((label(n) for n in current if
                           "You're on the latest version." in label(n)
                           or '已是最新版本' in label(n)), None)
            if status:
                checks.append({'check': index + 1, 'status': status, 'pid': pid})
                close = next(n for n in current if label(n) in ('Close', '关闭'))
                tap(close)
                break
            if any('Could not reach' in label(n) or '无法连接发布服务器' in label(n)
                   or 'could not be verified' in label(n) or '无法验证发布签名' in label(n)
                   for n in current):
                raise AssertionError('Update failed instead of verifying the signed manifest')
            time.sleep(0.25)
        else:
            raise AssertionError('Timed out checking for updates')
    result = {'serial': args.serial, 'version_code': code, 'checks': checks,
              'background_foreground_verified': True}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
