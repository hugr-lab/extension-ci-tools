#!/usr/bin/env python3
"""Tests of kista_publish.py against a local fake kista (python3 -m unittest scripts/test_kista_publish.py)."""

import http.server
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kista_publish  # noqa: E402


def extension(path, platform="linux_amd64", version="1.2.0", magic="4"):
    """Writes a fake extension: a body, DuckDB's metadata block, and an empty signature."""
    fields = [magic, platform, "v2.0.0", version, "CPP", "", "", ""]
    block = b"".join(f.encode().ljust(32, b"\0") for f in reversed(fields))
    with open(path, "wb") as f:
        f.write(b"\x7fELF" + b"x" * 600 + block + b"\0" * 256)


class Fake(http.server.BaseHTTPRequestHandler):
    answers = []  # statuses to answer, in order; then 201
    requests = []

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        u = urllib.parse.urlparse(self.path)
        Fake.requests.append((u.path, urllib.parse.parse_qs(u.query), self.headers["Authorization"], len(body)))
        status = Fake.answers.pop(0) if Fake.answers else 201
        self.send_response(status)
        if status == 429:
            self.send_header("Retry-After", "0")
        self.end_headers()
        self.wfile.write(json.dumps({"error": "status %d" % status}).encode())

    def do_GET(self):  # the OIDC token endpoint
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        Fake.requests.append(("token", q, self.headers["Authorization"], 0))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(json.dumps({"value": "oidc-for-" + q["audience"][0]}).encode())

    def log_message(self, *a):
        pass


class Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.HTTPServer(("127.0.0.1", 0), Fake)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = "http://127.0.0.1:%d" % cls.srv.server_port

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def setUp(self):
        Fake.answers, Fake.requests = [], []
        self.dir = tempfile.mkdtemp()
        os.environ.pop("KISTA_API_KEY", None)
        os.environ.pop("ACTIONS_ID_TOKEN_REQUEST_URL", None)
        os.environ.pop("ACTIONS_ID_TOKEN_REQUEST_TOKEN", None)
        kista_publish.time.sleep = lambda s: None

    def run_main(self, *paths, key="k-1"):
        if key:
            os.environ["KISTA_API_KEY"] = key
        summary = os.path.join(self.dir, "summary.md")
        code = kista_publish.main(["--url", self.url + "/", "--tenant", "acme", "--channel", "prod", "--summary", summary, *paths])
        if not os.path.exists(summary):
            return code, ""
        with open(summary) as f:
            text = f.read()
        os.remove(summary)
        return code, text

    def test_footer(self):
        p = os.path.join(self.dir, "myext.duckdb_extension")
        extension(p, "osx_arm64", "0.3.1")
        self.assertEqual(kista_publish.footer(p), ("myext", "0.3.1", "osx_arm64"))
        extension(p, magic="3")
        self.assertRaises(kista_publish.Refused, kista_publish.footer, p)
        with open(p, "wb") as f:
            f.write(b"short")
        self.assertRaises(kista_publish.Refused, kista_publish.footer, p)

    def test_publish_and_skip_wasm(self):
        for arch in ["linux_amd64", "osx_arm64"]:
            os.makedirs(os.path.join(self.dir, "myext-v2.0.0-extension-" + arch))
            extension(os.path.join(self.dir, "myext-v2.0.0-extension-" + arch, "myext.duckdb_extension"), arch)
        os.makedirs(os.path.join(self.dir, "myext-v2.0.0-extension-wasm_eh"))
        with open(os.path.join(self.dir, "myext-v2.0.0-extension-wasm_eh", "myext.duckdb_extension.wasm"), "wb") as f:
            f.write(b"wasm")
        Fake.answers = [201, 200]
        code, summary = self.run_main(self.dir)
        self.assertEqual(code, 0)
        self.assertEqual(len(Fake.requests), 2)
        path, q, auth, n = Fake.requests[0]
        self.assertEqual(path, "/api/v1/tenants/acme/channels/prod/extensions/myext/releases")
        self.assertEqual((q["version"], q["platform"], q["visibility"], auth, n), (["1.2.0"], ["linux_amd64"], ["private"], "Bearer k-1", 1116))
        self.assertIn("| published |", summary)
        self.assertIn("| already published |", summary)
        self.assertIn("skipped: kista does not take wasm builds yet", summary)

    def test_retries(self):
        p = os.path.join(self.dir, "myext.duckdb_extension")
        extension(p)
        Fake.answers = [429, 503, 201]
        self.assertEqual(self.run_main(p)[0], 0)
        self.assertEqual(len(Fake.requests), 3)

    def test_failures(self):
        p = os.path.join(self.dir, "myext.duckdb_extension")
        extension(p)
        for status in [400, 409, 401]:
            Fake.answers, Fake.requests = [status], []
            code, summary = self.run_main(p)
            self.assertEqual(code, 1, status)
            self.assertEqual(len(Fake.requests), 1)
            self.assertIn("kista answered %d" % status, summary)
        Fake.answers, Fake.requests = [503] * 4, []
        self.assertEqual(self.run_main(p)[0], 1)
        self.assertEqual(len(Fake.requests), 4)

    def test_oidc(self):
        p = os.path.join(self.dir, "myext.duckdb_extension")
        extension(p)
        os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"] = self.url + "/token?api-version=2.0"
        os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = "runner"
        self.assertEqual(self.run_main(p, key="")[0], 0)
        kind, q, auth, _ = Fake.requests[0]
        self.assertEqual((kind, q["audience"], auth), ("token", [self.url + "/acme"], "Bearer runner"))
        self.assertEqual(Fake.requests[1][2], "Bearer oidc-for-" + self.url + "/acme")

    def test_no_token(self):
        p = os.path.join(self.dir, "myext.duckdb_extension")
        extension(p)
        code, summary = self.run_main(p, key="")
        self.assertEqual(code, 1)
        self.assertIn("no GitHub OIDC token", summary)
        self.assertEqual(Fake.requests, [])

    def test_nothing_found(self):
        self.assertEqual(self.run_main(self.dir)[0], 1)


if __name__ == "__main__":
    unittest.main()
