#!/usr/bin/env python3
"""Tests of kista_publish.py against a local fake kista (python3 -m unittest scripts/test_kista_publish.py).

They need OpenSSH 8.1 or later: the fake kista checks each signature with ssh-keygen -Y verify."""

import base64
import contextlib
import hashlib
import http.server
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kista_publish  # noqa: E402
import time  # noqa: E402


class _Clock:
    """The time module, with sleep recorded instead of slept."""

    def __init__(self, sleep):
        self.sleep = sleep

    def __getattr__(self, name):
        return getattr(time, name)


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
    signed = []  # (method, path, body, Kista-Statement, Kista-Signature)
    retry_after = "0"
    whoami = {}

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        u = urllib.parse.urlparse(self.path)
        Fake.requests.append((u.path, urllib.parse.parse_qs(u.query), self.headers["Authorization"], len(body)))
        Fake.bodies.append((body, self.headers["Content-Type"]))
        Fake.signed.append(("POST", self.path, body, self.headers["Kista-Statement"], self.headers["Kista-Signature"]))
        status = Fake.answers.pop(0) if Fake.answers else 201
        self.send_response(status)
        if status == 429:
            self.send_header("Retry-After", Fake.retry_after)
        if status in (301, 302, 307):
            self.send_header("Location", "http://127.0.0.2:9/elsewhere")
        self.end_headers()
        self.wfile.write(json.dumps({"error": "status %d" % status}).encode())

    def do_GET(self):  # whoami
        Fake.requests.append((self.path, {}, self.headers["Authorization"], 0))
        Fake.signed.append(("GET", self.path, b"", self.headers["Kista-Statement"], self.headers["Kista-Signature"]))
        status = Fake.answers.pop(0) if Fake.answers else 200
        self.send_response(status)
        self.end_headers()
        self.wfile.write(json.dumps(Fake.whoami).encode())

    def log_message(self, *a):
        pass


class Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.HTTPServer(("127.0.0.1", 0), Fake)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = "http://127.0.0.1:%d" % cls.srv.server_port
        # the publisher's key, and the allowed-signers file ssh-keygen -Y verify reads
        cls.keys = tempfile.mkdtemp()
        cls.key_file = os.path.join(cls.keys, "publisher_key")
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "ci", "-f", cls.key_file], check=True)
        with open(cls.key_file) as f:
            cls.key = f.read()
        with open(cls.key_file + ".pub") as f:
            pub = f.read().split()
        cls.allowed = os.path.join(cls.keys, "allowed")
        with open(cls.allowed, "w") as f:
            f.write("ci %s %s\n" % (pub[0], pub[1]))
        cls.fingerprint = subprocess.run(["ssh-keygen", "-l", "-f", cls.key_file + ".pub"], check=True, capture_output=True,
                                         text=True).stdout.split()[1]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        shutil.rmtree(cls.keys, ignore_errors=True)

    def setUp(self):
        Fake.answers, Fake.requests, Fake.bodies, Fake.signed, Fake.retry_after = [], [], [], [], "0"
        Fake.whoami = {"tenant": "acme", "provider": "key", "grants": [{"principal": "publisher:ci", "verbs": ["publish"], "channel": "prod"}]}
        self.sleeps = []
        self.dir = tempfile.mkdtemp()
        # the key's private files go here, so a test sees what is left behind
        self.runner_temp = os.path.join(self.dir, "runner-temp")
        os.mkdir(self.runner_temp)
        os.environ["RUNNER_TEMP"] = self.runner_temp
        os.environ.pop("KISTA_PUBLISHER_KEY", None)
        # kista_publish's own clock only: the time module's sleep is shared (the test server's
        # thread, Python's own) and a global patch records their sleeps too
        self._time = kista_publish.time
        kista_publish.time = _Clock(self.sleeps.append)

    def tearDown(self):
        kista_publish.time = self._time
        os.environ.pop("RUNNER_TEMP", None)
        self.assertEqual(os.listdir(self.runner_temp), [], "a copy of the key left behind")
        shutil.rmtree(self.dir, ignore_errors=True)

    def verify(self, method, path, body, st, sig):
        """What kista checks: the statement names this request, and the signature is the key's."""
        text = base64.b64decode(st).decode("ascii")
        lines = text.split("\n")
        self.assertEqual(lines[:4], ["kista-request v1", "method " + method, "path " + path, "sha256 " + hashlib.sha256(body).hexdigest()])
        self.assertRegex(lines[4], r"^signed-at \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertEqual((len(lines), lines[5]), (6, ""))
        armored = "-----BEGIN SSH SIGNATURE-----\n" + sig + "\n-----END SSH SIGNATURE-----\n"
        sig_file = os.path.join(self.dir, "sig")
        with open(sig_file, "w") as f:
            f.write(armored)
        r = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", self.allowed, "-I", "ci", "-n", "kista-request@v1", "-s", sig_file],
                           input=text.encode("ascii"), capture_output=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def run_main(self, *paths, key=None, url=None, extra=()):
        os.environ["KISTA_PUBLISHER_KEY"] = self.key if key is None else key
        summary = os.path.join(self.dir, "summary.md")
        with contextlib.redirect_stdout(io.StringIO()):
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
        self.assertEqual((q["version"], q["platform"], q["visibility"], auth, n), (["1.2.0"], ["linux_amd64"], ["private"], None, 1116))
        # each request signed with the key: kista's checks pass
        for signed in Fake.signed:
            self.verify(*signed)
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
        for signed in Fake.signed:  # signed again for each attempt
            self.verify(*signed)
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
        os.environ["OTHER_KEY"] = self.key
        try:
            self.assertEqual(self.run_main(p, key="", extra=["--visibility", "public", "--key-env", "OTHER_KEY"])[0], 0)
        finally:
            del os.environ["OTHER_KEY"]
        self.assertEqual(Fake.requests[0][1]["visibility"], ["public"])
        self.verify(*Fake.signed[0])

    def test_key_forms(self):
        # the key, its base64, a file; CRLF endings, no final newline (as CI secret stores keep it)
        p = os.path.join(self.dir, "myext.duckdb_extension")
        extension(p)
        crlf = self.key.strip("\n").replace("\n", "\r\n")
        for name, value in [("text", self.key), ("base64", base64.b64encode(self.key.encode()).decode()), ("file", self.key_file),
                            ("CRLF, no final newline", crlf)]:
            Fake.requests, Fake.signed = [], []
            self.assertEqual(self.run_main(p, key=value)[0], 0, name)
            self.verify(*Fake.signed[0])
        # no key, or something else: nothing is sent
        for value, says in [("", "KISTA_PUBLISHER_KEY is empty"), ("not a key", "neither a private key"),
                            (base64.b64encode(b"not a key").decode(), "neither a private key"),
                            (os.path.join(self.dir, "missing"), "neither a private key")]:
            Fake.requests = []
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertEqual(self.run_main(p, key=value)[0], 1, value)
            self.assertEqual(Fake.requests, [])
            self.assertIn(says, err.getvalue())

    def test_key_never_shown(self):
        p = os.path.join(self.dir, "myext.duckdb_extension")
        extension(p)
        Fake.answers = [400]
        os.environ["KISTA_PUBLISHER_KEY"] = self.key
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = kista_publish.main(["--url", self.url, "--tenant", "acme", "--channel", "prod", p])
        secret = self.key.splitlines()[1]
        self.assertEqual(code, 1)
        for text in (out.getvalue(), err.getvalue()):
            self.assertNotIn(secret, text)
        # a key refused when it is read: its text is not echoed either
        broken = self.key.replace(secret, secret[:-8] + "AAAAAAAA")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(self.run_main(p, key=broken)[0], 1)
        self.assertNotIn(secret[:-8], err.getvalue())

    def test_passphrase_key(self):
        p = os.path.join(self.dir, "myext.duckdb_extension")
        extension(p)
        locked = os.path.join(self.dir, "locked")
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "secret phrase", "-f", locked], check=True)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(self.run_main(p, key=locked)[0], 1)
        self.assertIn("passphrase", err.getvalue())
        self.assertEqual(Fake.requests, [])

    def stub_ssh_keygen(self, script):
        """Puts a stub ssh-keygen first on PATH (None: no ssh-keygen at all) for the test's run."""
        bin_dir = os.path.join(self.dir, "bin")
        os.mkdir(bin_dir)
        if script is not None:
            with open(os.path.join(bin_dir, "ssh-keygen"), "w") as f:
                f.write("#!/bin/sh\n" + script)
            os.chmod(os.path.join(bin_dir, "ssh-keygen"), 0o755)
        path = os.environ["PATH"]
        os.environ["PATH"] = bin_dir if script is None else bin_dir + os.pathsep + path
        self.addCleanup(os.environ.__setitem__, "PATH", path)

    def test_no_ssh_keygen(self):
        p = os.path.join(self.dir, "myext.duckdb_extension")
        extension(p)
        self.stub_ssh_keygen(None)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(self.run_main(p, extra=["--dry-run"])[0], 1)
        self.assertIn("install OpenSSH 8.1", err.getvalue())

    # the stub is a shell script on PATH, which Windows does not run as ssh-keygen
    @unittest.skipIf(os.name == "nt", "a shell script stands in for ssh-keygen")
    def test_old_openssh(self):
        # ssh-keygen before 8.1 reads keys but has no -Y: refused before anything is sent, a dry run too
        p = os.path.join(self.dir, "myext.duckdb_extension")
        extension(p)
        real = shutil.which("ssh-keygen")
        self.stub_ssh_keygen('case "$1" in -Y) echo "ssh-keygen: unknown option -- Y" >&2; exit 1;; esac\nexec %s "$@"\n' % real)
        for extra in ([], ["--dry-run"]):
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertEqual(self.run_main(p, extra=extra)[0], 1)
            self.assertIn("OpenSSH 8.1 or later is needed", err.getvalue())
        self.assertEqual(Fake.requests, [])

    def test_bad_url(self):
        p = os.path.join(self.dir, "myext.duckdb_extension")
        extension(p)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(self.run_main(p, url=self.url + "\n")[0], 1)
        self.assertEqual(Fake.requests, [])

    def test_path_segments(self):
        # a "/" in the tenant stays in its segment
        p = os.path.join(self.dir, "myext.duckdb_extension")
        extension(p)
        url = kista_publish.release_url("https://k", "a/../b", "prod", "private", p)
        self.assertTrue(url.startswith("https://k/api/v1/tenants/a%2F..%2Fb/channels/prod/"), url)

    def test_check(self):
        os.environ["KISTA_PUBLISHER_KEY"] = self.key
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = kista_publish.main(["--url", self.url, "--tenant", "acme", "--check"])
        self.assertEqual(code, 0)
        self.assertEqual(Fake.signed[0][:3], ("GET", "/api/v1/tenants/acme/whoami", b""))
        self.verify(*Fake.signed[0])
        self.assertIn('"provider": "key"', out.getvalue())
        # with a channel: a publish grant there, or one for the whole tenant
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(kista_publish.main(["--url", self.url, "--tenant", "acme", "--channel", "prod", "--check"]), 0)
        for grants in ([], [{"verbs": ["publish"], "channel": "staging"}], [{"verbs": ["promote"], "channel": "prod"}]):
            Fake.whoami = {"grants": grants}
            err = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                self.assertEqual(kista_publish.main(["--url", self.url, "--tenant", "acme", "--channel", "prod", "--check"]), 1, grants)
            self.assertIn("no publish grant in prod", err.getvalue())
        Fake.whoami = {"grants": [{"verbs": ["publish"]}]}
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(kista_publish.main(["--url", self.url, "--tenant", "acme", "--channel", "prod", "--check"]), 0)
        # a key kista does not know: one request, the answer named
        Fake.answers, Fake.requests = [401], []
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(kista_publish.main(["--url", self.url, "--tenant", "acme", "--check"]), 1)
        self.assertIn("kista answered 401", err.getvalue())
        self.assertEqual(len(Fake.requests), 1)

    def test_dry_run(self):
        p = os.path.join(self.dir, "myext.duckdb_extension")
        extension(p)
        out = io.StringIO()
        os.environ["KISTA_PUBLISHER_KEY"] = self.key
        summary = os.path.join(self.dir, "summary.md")
        with contextlib.redirect_stdout(out):
            code = kista_publish.main(["--url", self.url, "--tenant", "acme", "--channel", "prod", "--summary", summary, "--dry-run", p])
        self.assertEqual((code, Fake.requests), (0, []))
        self.assertIn("kista-request v1\nmethod POST\npath /api/v1/tenants/acme/channels/prod/extensions/myext/releases?", out.getvalue())
        with open(summary) as f:
            self.assertIn("dry run: would be signed by " + self.fingerprint, f.read())

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
        Fake.answers, Fake.requests = [408, 500, 502, 201], []
        self.assertEqual(self.run_main(p)[0], 0)
        self.assertEqual(len(Fake.requests), 4)

    def test_nothing_found(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(self.run_main(self.dir)[0], 1)


if __name__ == "__main__":
    unittest.main()
