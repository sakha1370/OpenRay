import hashlib
import io
import os
import ssl
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

from tools.install_cores import download, install


class Response(io.BytesIO):
    def __init__(self, data, *, length=None):
        super().__init__(data)
        self.headers = {"Content-Length": str(len(data) if length is None else length)}


class InstallCoreTests(unittest.TestCase):
    def asset(self, body):
        return {"url": "https://example.test/core.zip", "sha256": hashlib.sha256(body).hexdigest()}

    def test_connection_reset_and_truncated_download_restart(self):
        body = b"verified archive content"
        responses = [
            urllib.error.URLError(ConnectionResetError("connection reset by peer")),
            Response(body[:5], length=len(body)),
            Response(body),
        ]
        with (
            patch("tools.install_cores.urllib.request.urlopen", side_effect=responses) as request,
            patch("tools.install_cores.time.sleep") as sleep,
            patch("builtins.print"),
            tempfile.TemporaryFile() as archive,
        ):
            download(self.asset(body), archive)
            self.assertEqual(archive.read(), body)
            self.assertEqual(request.call_count, 3)
            self.assertEqual([call.args[0] for call in sleep.call_args_list], [1, 2])

    def test_transient_http_retry_and_permanent_errors(self):
        body = b"verified archive"
        asset = self.asset(body)
        transient = [
            urllib.error.HTTPError(asset["url"], 503, "unavailable", {}, None),
            urllib.error.HTTPError(asset["url"], 429, "rate limited", {}, None),
            Response(body),
        ]
        with (
            patch("tools.install_cores.urllib.request.urlopen", side_effect=transient),
            patch("tools.install_cores.time.sleep"),
            patch("builtins.print"),
            tempfile.TemporaryFile() as archive,
        ):
            download(asset, archive)
            self.assertEqual(archive.read(), body)
        for error in (
            urllib.error.HTTPError(asset["url"], 404, "missing", {}, None),
            urllib.error.URLError(ssl.SSLCertVerificationError("untrusted certificate")),
        ):
            with (
                self.subTest(error=type(error).__name__),
                patch("tools.install_cores.urllib.request.urlopen", side_effect=error) as request,
                patch("tools.install_cores.time.sleep") as sleep,
                tempfile.TemporaryFile() as archive,
            ):
                with self.assertRaises(urllib.error.URLError):
                    download(asset, archive)
                self.assertEqual(request.call_count, 1)
                sleep.assert_not_called()

    def test_checksum_and_size_fail_closed_without_retry(self):
        for body, maximum, message in ((b"altered", 100, "checksum"), (b"oversized", 4, "exceeds limit")):
            with (
                self.subTest(message=message),
                patch("tools.install_cores.urllib.request.urlopen", return_value=Response(body)) as request,
                patch("tools.install_cores.MAX_DOWNLOAD", maximum),
                patch("tools.install_cores.time.sleep") as sleep,
                tempfile.TemporaryFile() as archive,
            ):
                with self.assertRaisesRegex(ValueError, message):
                    download(self.asset(b"expected"), archive)
                self.assertEqual(request.call_count, 1)
                sleep.assert_not_called()

    def test_exhausted_retries_preserve_installed_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / ("xray.exe" if os.name == "nt" else "xray")
            binary.write_bytes(b"previous verified binary")
            asset = self.asset(b"archive")
            manifest = {
                "xray": {"version": "test", "assets": {"core-windows.zip": asset, "core-linux.zip": asset}}
            }
            with (
                patch("tools.install_cores.json.loads", return_value=manifest),
                patch("tools.install_cores.platform.machine", return_value="AMD64"),
                patch(
                    "tools.install_cores.urllib.request.urlopen",
                    side_effect=urllib.error.URLError(ConnectionResetError()),
                ) as request,
                patch("tools.install_cores.time.sleep") as sleep,
                patch("builtins.print"),
            ):
                with self.assertRaises(urllib.error.URLError):
                    install(root, ["xray"])
                self.assertEqual(request.call_count, 4)
                self.assertEqual(sleep.call_count, 3)
            self.assertEqual(binary.read_bytes(), b"previous verified binary")
