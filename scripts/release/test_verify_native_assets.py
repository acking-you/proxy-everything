import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
import zipfile

spec = importlib.util.spec_from_file_location("verify_assets", Path(__file__).with_name("verify-native-assets.py"))
verify_assets = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify_assets)


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
                    names = ["http_proxy.dll", "http_proxy.lib", "wintun.dll", "libhttp_proxy.a", "libhttp_proxy.dylib", "libhttp_proxy.so", "http-proxy-tun-helper"]
                else:
                    names = [component, component + ".exe", "wintun.dll"]
                files.update({name: b"fixture" for name in names})
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

    def test_old_archive_prevents_publication(self):
        (self.directory / "http-proxy-cli-0.4.35-old.tar.gz").write_bytes(b"stale")
        with self.assertRaisesRegex(ValueError, "unexpected="):
            verify_assets.verify(self.directory, self.version, self.commit)


if __name__ == "__main__":
    unittest.main()
