#!/usr/bin/env python3
"""Tests of kista_publish.py against a local fake kista (python3 -m unittest scripts/test_kista_publish.py)."""

import http.server
import json
import os
import socket
import sys
import tempfile
import threading
import unittest
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kista_publish  # noqa: E402


def extension(path, platform="linux_amd64", version="1.2.0", magic="4", abi="CPP", duckdb="v2.0.0"):
    """Writes a fake extension: a body, DuckDB's metadata block, and an empty signature; returns it."""
    fields = [magic, platform, duckdb, version, abi, "", "", ""]
    block = b"".join(f.encode().ljust(32, b"\0") for f in reversed(fields))
    data = b"\x7fELF" + os.urandom(600) + block + b"\0" * 256
    with open(path, "wb") as f:
        f.write(data)
    return data


class Fake(http.server.BaseHTTPRequestHandler):
    answers = []  # statuses to answer, in order; then 201
    requests = []
    bodies = []
    retry_after = "0"
    token_status = 200

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        u = urllib.parse.urlparse(self.path)
        Fake.requests.append((u.path, urllib.parse.parse_qs(u.query), self.headers["Authorization"], len(body)))
        Fake.bodies.append((body, self.headers["Content-Type"]))
        status = Fake.answers.pop(0) if Fake.answers else 201
        self.send_response(status)
        if status == 429:
            self.send_header("Retry-After", Fake.retry_after)
        if status in (301, 302, 307):
            self.send_header("Location", "http://127.0.0.2:9/elsewhere")
        self.end_headers()
        self.wfile.write(json.dumps({"error": "status %d" % status}).encode())

    def do_GET(self):  # the OIDC token endpoint
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        Fake.requests.append(("token", q, self.headers["Authorization"], 0))
        self.send_response(Fake.token_status)
        self.end_headers()
        n = sum(1 for r in Fake.requests if r[0] == "token")
        self.wfile.write(json.dumps({"value": "oidc-%d-for-%s" % (n, q["audience"][0])}).encode())

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
        Fake.answers, Fake.requests, Fake.bodies, Fake.retry_after, Fake.token_status = [], [], [], "0", 200
        self.sleeps = []
        self.dir = tempfile.mkdtemp()
        os.environ.pop("KISTA_API_KEY", None)
        os.environ.pop("ACTIONS_ID_TOKEN_REQUEST_URL", None)
        os.environ.pop("ACTIONS_ID_TOKEN_REQUEST_TOKEN", None)
        self._sleep = kista_publish.time.sleep
        kista_publish.time.sleep = self.sleeps.append

    def tearDown(self):
        kista_publish.time.sleep = self._sleep

    def run_main(self, *paths, key="k-1", url=None, extra=()):
        if key:
            os.environ["KISTA_API_KEY"] = key
        summary = os.path.join(self.dir, "summary.md")
        code = kista_publish.main(["--url", (url or self.url) + "/", "--tenant", "acme", "--channel", "prod", "--summary", summary,
                                   *extra, *paths])
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
        # a C API build: field 2 is the C API version, the extension version is field 3 as ever
        extension(p, version="0.4.0", abi="C_STRUCT", duckdb="v1.2.0")
        self.assertEqual(kista_publish.footer(p), ("myext", "0.4.0", "linux_amd64"))
        extension(p, version="")
        self.assertRaises(kista_publish.Refused, kista_publish.footer, p)
        extension(p, magic="3")
        self.assertRaises(kista_publish.Refused, kista_publish.footer, p)
        with open(p, "wb") as f:
            f.write(b"short")
        self.assertRaises(kista_publish.Refused, kista_publish.footer, p)

    def test_publish_and_skip_wasm(self):
        sent = {}
        for arch in ["linux_amd64", "osx_arm64"]:
            os.makedirs(os.path.join(self.dir, "myext-v2.0.0-extension-" + arch))
            sent[arch] = extension(os.path.join(self.dir, "myext-v2.0.0-extension-" + arch, "myext.duckdb_extension"), arch)
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
        self.assertEqual(Fake.requests[1][1]["platform"], ["osx_arm64"])
        # the build goes as it is
        self.assertEqual(Fake.bodies, [(sent["linux_amd64"], "application/octet-stream"), (sent["osx_arm64"], "application/octet-stream")])
        self.assertIn("| published |", summary)
        self.assertIn("| already published |", summary)
        self.assertIn("skipped: kista does not take wasm builds yet", summary)

    def test_retries(self):
        p = os.path.join(self.dir, "myext.duckdb_extension")
        extension(p)
        Fake.answers, Fake.retry_after = [429, 503, 201], "3"
        self.assertEqual(self.run_main(p)[0], 0)
        self.assertEqual(len(Fake.requests), 3)
        self.assertEqual(self.sleeps, [3, 4])  # Retry-After, then the backoff
        Fake.answers, Fake.requests, Fake.retry_after, self.sleeps[:] = [429, 201], [], "3600", []
        self.assertEqual(self.run_main(p)[0], 0)
        self.assertEqual(self.sleeps, [kista_publish.MAX_RETRY_AFTER])

    def test_no_connection(self):
        p = os.path.join(self.dir, "myext.duckdb_extension")
        extension(p)
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()  # nothing listens there
        code, summary = self.run_main(p, url="http://127.0.0.1:%d" % port)
        self.assertEqual(code, 1)
        self.assertEqual(self.sleeps, [2, 4, 8])
        self.assertIn("failed", summary)

    def test_redirect_refused(self):
        p = os.path.join(self.dir, "myext.duckdb_extension")
        extension(p)
        for status in [301, 302, 307]:
            Fake.answers, Fake.requests = [status], []
            code, summary = self.run_main(p)
            self.assertEqual((code, len(Fake.requests)), (1, 1), status)
            self.assertIn("refused", summary)

    def test_only_2xx_known(self):
        p = os.path.join(self.dir, "myext.duckdb_extension")
        extension(p)
        Fake.answers = [202]
        code, summary = self.run_main(p)
        self.assertEqual(code, 1)
        self.assertIn("kista answered 202", summary)

    def test_url(self):
        p = os.path.join(self.dir, "myext.duckdb_extension")
        extension(p)
        for url in ["http://kista.example.org", "ftp://kista.example.org", "kista.example.org"]:
            self.assertEqual(self.run_main(p, url=url)[0], 1, url)
        self.assertEqual(Fake.requests, [])
        kista_publish.check_url("https://kista.example.org")
        kista_publish.check_url("http://localhost:8080")

    def test_selection(self):
        # an extension named like wasm is no wasm build; another extension and a postfixed artifact are left
        for d, n in [("wasm_udf-v2.0.0-extension-linux_amd64", "wasm_udf"), ("wasm_udf-v2.0.0-extension-linux_amd64-debug", "wasm_udf"),
                     ("wasm_udf-v2.0.0-extension-linux_amd64", "json")]:
            os.makedirs(os.path.join(self.dir, d), exist_ok=True)
            extension(os.path.join(self.dir, d, n + ".duckdb_extension"))
        code, _ = self.run_main(self.dir, extra=["--name", "wasm_udf", "--postfix="])
        self.assertEqual(code, 0)
        self.assertEqual([r[0].rsplit("/", 1)[-1] for r in Fake.requests], ["releases"])
        self.assertIn("/extensions/wasm_udf/", Fake.requests[0][0])
        Fake.requests = []
        self.assertEqual(self.run_main(self.dir, extra=["--name", "wasm_udf", "--postfix=-debug"])[0], 0)
        self.assertEqual(len(Fake.requests), 1)
        # a file given by path must be a built extension
        other = os.path.join(self.dir, "notes.txt")
        with open(other, "w") as f:
            f.write("x")
        self.assertEqual(self.run_main(other)[0], 1)

    def test_visibility_and_key_env(self):
        p = os.path.join(self.dir, "myext.duckdb_extension")
        extension(p)
        os.environ["OTHER_KEY"] = "k-2"
        try:
            self.assertEqual(self.run_main(p, key="", extra=["--visibility", "public", "--api-key-env", "OTHER_KEY"])[0], 0)
        finally:
            del os.environ["OTHER_KEY"]
        self.assertEqual((Fake.requests[0][1]["visibility"], Fake.requests[0][2]), (["public"], "Bearer k-2"))

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
        for arch in ["linux_amd64", "osx_arm64"]:
            os.makedirs(os.path.join(self.dir, "myext-v2.0.0-extension-" + arch))
            extension(os.path.join(self.dir, "myext-v2.0.0-extension-" + arch, "myext.duckdb_extension"), arch)
        os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"] = self.url + "/token?api-version=2.0"
        os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = "runner"
        self.assertEqual(self.run_main(self.dir, key="")[0], 0)
        kind, q, auth, _ = Fake.requests[0]
        self.assertEqual((kind, q["audience"], q["api-version"], auth), ("token", [self.url + "/acme"], ["2.0"], "Bearer runner"))
        # a fresh token for each file
        self.assertEqual([r[2] for r in Fake.requests if r[0] != "token"],
                         ["Bearer oidc-1-for-" + self.url + "/acme", "Bearer oidc-2-for-" + self.url + "/acme"])
        # the token endpoint failing fails the file, with a summary
        Fake.requests, Fake.token_status = [], 500
        code, summary = self.run_main(self.dir, key="")
        self.assertEqual(code, 1)
        self.assertIn("GitHub's OIDC token", summary)

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
