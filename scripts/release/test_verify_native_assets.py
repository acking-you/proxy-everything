import importlib.util
import io
import json
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest
import zipfile

spec = importlib.util.spec_from_file_location("verify_assets", Path(__file__).with_name("verify-native-assets.py"))
verify_assets = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify_assets)


def elf_with_load_alignment(alignment):
    """A minimal little-endian ELF64 file with one PT_LOAD segment."""
    header = b"\x7fELF\x02\x01\x01" + bytes(9) + struct.pack("<HHIQQQIHHHHHH", 3, 183, 1, 0, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    return header + struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, 0, 0, alignment)


class ReleaseAssetsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.version, self.commit = "0.4.37", "a" * 40
        for component, targets in [(b, verify_assets.BINARY_TARGETS) for b in verify_assets.BINARIES] + [("libhttp_proxy", verify_assets.FFI_TARGETS)]:
            for target in targets:
                stem = f"{component}-{self.version}-{target}"
                files = {"build-info.json": json.dumps({"version": self.version, "source_commit": self.commit, "target": target, "component": component}).encode()}
                if component == "libhttp_proxy":
                    names = ["http_proxy.dll", "http_proxy.lib", "wintun.dll", "libhttp_proxy.a", "libhttp_proxy.dylib", "libhttp_proxy.so", "http-proxy-tun-helper", "cipherrelay-app-launcher", "cipherrelay-app-launcher.exe"]
                else:
                    names = [component, component + ".exe", "wintun.dll"]
                files.update({name: b"fixture" for name in names})
                if target in verify_assets.ANDROID_16K_TARGETS:
                    files["libhttp_proxy.so"] = elf_with_load_alignment(16 * 1024)
                if "windows" in target:
                    with zipfile.ZipFile(self.directory / (stem + ".zip"), "w") as archive:
                        for name, content in files.items():
                            archive.writestr(f"{stem}/{name}", content)
                else:
                    with tarfile.open(self.directory / (stem + ".tar.gz"), "w:gz") as archive:
                        for name, content in files.items():
                            member = tarfile.TarInfo(f"{stem}/{name}")
                            member.size = len(content)
                            archive.addfile(member, io.BytesIO(content))

    def test_complete_same_source_matrix_writes_hashes(self):
        result = verify_assets.verify(self.directory, self.version, self.commit)
        self.assertEqual(len(result["assets"]), 44)
        self.assertEqual(len((self.directory / "SHA256SUMS").read_text().splitlines()), 44)

    def test_missing_component_prevents_publication(self):
        next(self.directory.glob("http-proxy-admin-*.zip")).unlink()
        with self.assertRaisesRegex(ValueError, "missing="):
            verify_assets.verify(self.directory, self.version, self.commit)

    def test_another_source_commit_prevents_publication(self):
        with self.assertRaisesRegex(ValueError, "provenance mismatch"):
            verify_assets.verify(self.directory, self.version, "b" * 40)

    def test_4k_aligned_android_library_prevents_publication(self):
        stem = f"libhttp_proxy-{self.version}-aarch64-linux-android"
        content = elf_with_load_alignment(4 * 1024)
        with tarfile.open(self.directory / f"{stem}.tar.gz") as archive:
            members = [(m, archive.extractfile(m).read()) for m in archive.getmembers()]
        with tarfile.open(self.directory / f"{stem}.tar.gz", "w:gz") as archive:
            for member, data in members:
                if member.name.endswith("/libhttp_proxy.so"):
                    member.size, data = len(content), content
                archive.addfile(member, io.BytesIO(data))
        with self.assertRaisesRegex(ValueError, "below 16 KB"):
            verify_assets.verify(self.directory, self.version, self.commit)

    def test_old_archive_prevents_publication(self):
        (self.directory / "http-proxy-cli-0.4.35-old.tar.gz").write_bytes(b"stale")
        with self.assertRaisesRegex(ValueError, "unexpected="):
            verify_assets.verify(self.directory, self.version, self.commit)


if __name__ == "__main__":
    unittest.main()
