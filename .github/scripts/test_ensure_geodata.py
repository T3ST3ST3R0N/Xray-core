import hashlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "ensure_geodata", Path(__file__).with_name("ensure-geodata.py")
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class GeodataTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.payload = b"verified fixture"
        self.asset = {
            "name": "geoip.dat",
            "path": "geoip/geoip-lite.dat",
            "sha256": hashlib.sha256(self.payload).hexdigest(),
        }

    def test_cache_miss_downloads_pinned_fixture(self):
        with patch.object(module.urllib.request, "urlopen", return_value=io.BytesIO(self.payload)) as request:
            module.ensure_asset(self.directory, self.asset, "a" * 40)
        self.assertEqual((self.directory / "geoip.dat").read_bytes(), self.payload)
        request.assert_called_once_with(
            "https://raw.githubusercontent.com/XTLS/Xray-rules-dat/" + "a" * 40 + "/geoip/geoip-lite.dat",
            timeout=30,
        )
        self.assertEqual(list(self.directory.iterdir()), [self.directory / "geoip.dat"])

    def test_verified_cache_needs_no_network(self):
        (self.directory / "geoip.dat").write_bytes(self.payload)
        with patch.object(module.urllib.request, "urlopen") as request:
            module.ensure_asset(self.directory, self.asset, "a" * 40)
        request.assert_not_called()

    def test_bad_download_preserves_existing_file(self):
        (self.directory / "geoip.dat").write_bytes(b"old fixture")
        with patch.object(module.urllib.request, "urlopen", return_value=io.BytesIO(b"invalid")):
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                module.ensure_asset(self.directory, self.asset, "a" * 40)
        self.assertEqual((self.directory / "geoip.dat").read_bytes(), b"old fixture")
        self.assertEqual(list(self.directory.iterdir()), [self.directory / "geoip.dat"])


if __name__ == "__main__":
    unittest.main()
