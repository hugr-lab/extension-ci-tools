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
import unicodedata
import unittest
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kista_publish  # noqa: E402
import time  # noqa: E402


class _Clock:
    """The time module, with sleep recorded instead of slept, and the monotonic clock moved by it."""

    def __init__(self, sleep):
        self.record, self.offset = sleep, 0

    def sleep(self, seconds):
        self.record(seconds)
        self.offset += seconds

    def monotonic(self):
        return time.monotonic() + self.offset

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
    answers = []  # statuses to answer, in order, or (status, problem type); then 201 (POST) or 200
    requests = []
    bodies = []
    signed = []  # (method, path, body, Kista-Statement, Kista-Signature)
    retry_after = "0"
    whoami = {}
    build = {}  # a catalogue publication's answer
    meta = None  # the catalogue entry's metadata (kista's answer); None: no entry (404)
    puts = []  # the metadata writes' bodies, decoded
    detail = ""  # a problem's detail (else the fake's own)

    def answer(self, default, body):
        status = Fake.answers.pop(0) if Fake.answers else default
        status, kind = status if isinstance(status, tuple) else (status, None)
        self.send_response(status)
        if status == 429:
            self.send_header("Retry-After", Fake.retry_after)
        if status in (301, 302, 307):
            self.send_header("Location", "http://127.0.0.2:9/elsewhere")
        self.end_headers()
        if kind:
            body = {"type": "urn:kista:problem:" + kind, "status": status, "detail": Fake.detail or "the fake's " + kind}
        elif status >= 300:
            body = {"error": "status %d" % status}
        self.wfile.write(json.dumps(body).encode())
        return status

    def record(self, method):
        n = int(self.headers["Content-Length"] or 0)
        body = self.rfile.read(n) if n else b""
        u = urllib.parse.urlparse(self.path)
        Fake.requests.append((u.path, urllib.parse.parse_qs(u.query), self.headers["Authorization"], len(body)))
        Fake.signed.append((method, self.path, body, self.headers["Kista-Statement"], self.headers["Kista-Signature"]))
        return u.path, body

    def do_POST(self):
        path, body = self.record("POST")
        Fake.bodies.append((body, self.headers["Content-Type"]))
        self.answer(201, Fake.build if "/catalogue/" in path else {"id": "r1"})

    def do_GET(self):  # whoami, or an entry's metadata
        path, _ = self.record("GET")
        if path.endswith("/meta"):
            if Fake.meta is None:
                Fake.answers.insert(0, 404)
            self.answer(200, Fake.meta or {})
        else:
            self.answer(200, Fake.whoami)

    def do_PUT(self):  # an entry's metadata
        _, body = self.record("PUT")
        want = json.loads(body)
        Fake.puts.append((want, self.headers["Content-Type"]))
        # as kista: the summary stored trimmed and NFC, at most 160 code points; an icon is a PNG
        if want.get("summary") is not None:
            want["summary"] = unicodedata.normalize("NFC", want["summary"].strip())
        icon = want.get("icon")
        if want.get("summary") and len(want["summary"]) > 160 or \
                icon and "data" in icon and not base64.b64decode(icon["data"]).startswith(b"\x89PNG"):
            Fake.answers.insert(0, (400, "invalid"))
        if self.answer(200, {}) == 200:
            icon = want.get("icon")
            if icon and "data" in icon:
                icon = {"sha256": hashlib.sha256(base64.b64decode(icon["data"])).hexdigest(), "width": 64, "height": 64}
            Fake.meta = dict(Fake.meta or {}, summary=want.get("summary") or None, icon=icon, signed_at="2026-10-30T10:00:00Z")

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
        Fake.build, Fake.meta, Fake.puts, Fake.detail = {"state": "available"}, {"summary": None, "icon": None}, [], ""
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

    def run_main(self, *paths, key=None, url=None, extra=(), where=("--channel", "prod")):
        os.environ["KISTA_PUBLISHER_KEY"] = self.key if key is None else key
        summary = os.path.join(self.dir, "summary.md")
        with contextlib.redirect_stdout(io.StringIO()):
            code = kista_publish.main(["--url", (url or self.url) + "/", "--tenant", "acme", *where, "--summary", summary,
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
        self.assertIn("--check tests the key and its grant, a publisher with a hold publishes with --catalogue, or the file is "
                      "over kista's size limit (413)", summary)

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

    def icon(self, size=600, width=64, height=64, name="icon.png"):
        """A fake icon: PNG's signature, an IHDR of the size, and bytes (kista checks the rest, the fake
        does not)."""
        path = os.path.join(self.dir, name)
        data = b"\x89PNG\r\n\x1a\n" + b"\0\0\0\x0dIHDR" + width.to_bytes(4, "big") + height.to_bytes(4, "big") + os.urandom(size)
        with open(path, "wb") as f:
            f.write(data)
        return path, data

    def test_catalogue(self):
        p = os.path.join(self.dir, "myext.duckdb_extension")
        extension(p)
        Fake.build = {"state": "held", "available_at": "2026-10-31T10:00:00Z", "publisher_id": "p1"}
        code, summary = self.run_main(p, where=("--catalogue",), extra=["--visibility", "public"])
        self.assertEqual(code, 0)
        path, q, auth, _ = Fake.requests[0]
        self.assertEqual(path, "/api/v1/tenants/acme/catalogue/extensions/myext/builds")
        self.assertEqual((q["version"], q["platform"], q["visibility"], auth), (["1.2.0"], ["linux_amd64"], ["public"], None))
        self.verify(*Fake.signed[0])
        self.assertIn("### kista: %s acme catalogue" % self.url, summary)
        self.assertIn("| published (held until 2026-10-31T10:00:00Z) |", summary)
        # an available build, and one the source has already
        Fake.build, Fake.answers, Fake.requests = {"state": "available"}, [201, 200], []
        code, summary = self.run_main(p, p, where=("--catalogue",))
        self.assertIn("| published |", summary)
        self.assertIn("| already published |", summary)
        # --channel and --catalogue are one or the other
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            kista_publish.main(["--url", self.url, "--tenant", "acme", "--channel", "prod", "--catalogue", p])

    def test_held_on_a_channel(self):
        p = os.path.join(self.dir, "myext.duckdb_extension")
        extension(p)
        # kista's two causes, told apart by its text: the publisher has a hold, or the build is held
        Fake.detail = "the publisher has a hold (24h): it publishes into the catalogue"
        Fake.answers = [(409, "held")]
        code, summary = self.run_main(p)
        self.assertEqual((code, len(Fake.requests)), (1, 1))
        self.assertIn("publishes into the catalogue only (--catalogue)", summary)
        Fake.detail, Fake.answers = "myext 1.2.0 linux_amd64 is held until 2026-10-31T10:00:00Z", [(409, "held")]
        code, summary = self.run_main(p)
        self.assertIn("this build is held (or revoked) in the catalogue", summary)

    def test_stops_without_room(self):
        # a 429 typed catalogue-full or tenant-limit is not retried, and nothing more is sent
        paths = []
        for arch in ["linux_amd64", "osx_arm64"]:
            d = os.path.join(self.dir, "myext-v2.0.0-extension-" + arch)
            os.makedirs(d)
            paths.append(os.path.join(d, "myext.duckdb_extension"))
            extension(paths[-1], arch)
        icon, _ = self.icon()
        for kind in ["catalogue-full", "tenant-limit"]:
            Fake.answers, Fake.requests, self.sleeps[:] = [(429, kind)], [], []
            code, summary = self.run_main(self.dir, where=("--catalogue",), extra=["--icon", icon])
            self.assertEqual((code, len(Fake.requests), self.sleeps), (1, 1, []), kind)
            self.assertIn("429 (%s)" % kind, summary)
            self.assertEqual(summary.count("not sent: kista has no room"), 2, summary)  # the other build, the metadata
        # a busy kista's 429 is retried after its Retry-After
        Fake.answers, Fake.requests, Fake.retry_after, self.sleeps[:] = [(429, "upload-slots"), (429, "rate-limited")], [], "5", []
        self.assertEqual(self.run_main(paths[0], where=("--catalogue",))[0], 0)
        self.assertEqual((len(Fake.requests), self.sleeps), (3, [5, 5]))

    def test_entry_metadata(self):
        p = os.path.join(self.dir, "myext.duckdb_extension")
        extension(p)
        icon, data = self.icon()
        # the key's publishers: its builds are the first's by id, as kista takes it
        Fake.whoami = {"publishers": [{"publisher": "ci", "id": "0b"}, {"publisher": "other", "id": "0a"}], "grants": []}
        code, summary = self.run_main(p, where=("--catalogue",), extra=["--entry-summary", "Geometry tools", "--icon", icon])
        self.assertEqual(code, 0, summary)
        M = "/api/v1/tenants/acme/catalogue/publisher-id:0a/extensions/myext/meta"
        self.assertEqual([(m, path) for m, path, *_ in Fake.signed],
                         [("POST", Fake.signed[0][1]), ("GET", "/api/v1/tenants/acme/whoami"), ("GET", M), ("PUT", M)])
        for signed in Fake.signed:
            self.verify(*signed)
        want, ctype = Fake.puts[0]
        self.assertEqual(ctype, "application/json")
        self.assertEqual(want, {"summary": "Geometry tools",
                                "icon": {"content_type": "image/png", "data": base64.b64encode(data).decode()}})
        self.assertIn("| myext |  | metadata | summary and icon: set |", summary)
        sha = hashlib.sha256(data).hexdigest()

        # the same again: read, nothing to write
        Fake.signed, Fake.puts = [], []
        code, summary = self.run_main(p, where=("--catalogue",), extra=["--entry-summary", "Geometry tools", "--icon", icon])
        self.assertEqual((code, Fake.puts), (0, []))
        self.assertIn("summary and icon: unchanged", summary)
        # the summary alone: the icon kept by its hash, never sent again
        code, summary = self.run_main(p, where=("--catalogue",), extra=["--entry-summary", "Geometry tools, 2D"])
        self.assertEqual(Fake.puts[-1][0], {"summary": "Geometry tools, 2D", "icon": {"sha256": sha}})
        # the same icon by file: kept by its hash; another summary kept as it is
        Fake.puts = []
        code, summary = self.run_main(p, where=("--catalogue",), extra=["--icon", icon, "--entry-summary", "Geo"])
        self.assertEqual(Fake.puts[-1][0], {"summary": "Geo", "icon": {"sha256": sha}})
        code, summary = self.run_main(p, where=("--catalogue",), extra=["--icon", icon])
        self.assertIn("icon: unchanged", summary)
        # empty values clear
        code, summary = self.run_main(p, where=("--catalogue",), extra=["--icon=", "--entry-summary="])
        self.assertEqual(Fake.puts[-1][0], {"summary": "", "icon": None})
        self.assertEqual(Fake.meta["icon"], None)

    def test_entry_metadata_retries(self):
        p = os.path.join(self.dir, "myext.duckdb_extension")
        extension(p)
        Fake.whoami = {"publishers": [{"publisher": "ci", "id": "p1"}]}
        # stale: read again and write once the clock passes the entry's signed_at; conflict: read again
        # POST, whoami, the read, a stale write; the read, a conflicting write; the read, the write
        Fake.answers = [201, 200, 200, (409, "stale"), 200, (409, "conflict"), 200, 200]
        code, summary = self.run_main(p, where=("--catalogue",), extra=["--entry-summary", "Geo"])
        self.assertEqual(code, 0, summary)
        self.assertEqual([m for m, *_ in Fake.signed], ["POST", "GET", "GET", "PUT", "GET", "PUT", "GET", "PUT"])
        self.assertEqual(self.sleeps, [1])
        # a full catalogue or tenant stops; a metadata write's rate is waited for
        for kind in ["catalogue-full", "tenant-limit"]:
            Fake.answers, Fake.meta = [201, 200, 200, (429, kind)], {"summary": None, "icon": None}
            code, summary = self.run_main(p, where=("--catalogue",), extra=["--entry-summary", "Geo"])
            self.assertEqual(code, 1)
            self.assertIn("metadata: kista answered 429 (%s)" % kind, summary)
        Fake.answers, Fake.retry_after, self.sleeps[:] = [201, 200, 200, (429, "rate-limited"), 200, 200], "2", []
        self.assertEqual(self.run_main(p, where=("--catalogue",), extra=["--entry-summary", "Geo2"])[0], 0)
        self.assertEqual(self.sleeps, [2])
        # no entry of the key's source: refused, named
        Fake.meta = None
        code, summary = self.run_main(p, where=("--catalogue",), extra=["--entry-summary", "Geo"])
        self.assertEqual(code, 1)
        self.assertIn("no catalogue entry of publisher-id:p1 for myext", summary)

    def test_entry_metadata_only_after_its_builds(self):
        p = os.path.join(self.dir, "myext.duckdb_extension")
        extension(p)
        Fake.answers = [400]
        code, summary = self.run_main(p, extra=["--entry-summary", "Geo"])  # on a channel's publication too
        self.assertEqual(code, 1)
        self.assertIn("not set: no build of myext was published", summary)
        self.assertEqual(len(Fake.requests), 1)

    def test_icon_checked_first(self):
        p = os.path.join(self.dir, "myext.duckdb_extension")
        extension(p)
        not_png = os.path.join(self.dir, "icon.svg")
        with open(not_png, "w") as f:
            f.write("<svg/>")
        big, _ = self.icon(256 * 1024, name="big.png")
        oblong, _ = self.icon(width=64, height=128, name="oblong.png")
        tiny, _ = self.icon(width=32, height=32, name="tiny.png")
        link = os.path.join(self.dir, "link.png")
        os.symlink(self.icon(name="real.png")[0], link)
        for path, says in [(not_png, "the icon is a PNG"), (big, "at most 256 KiB"), (oblong, "square, 64 to 512 pixels a side (this "
                           "one is 64x128)"), (tiny, "this one is 32x32"), (link, "symbolic link"),
                           (os.path.join(self.dir, "none.png"), "none.png")]:
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertEqual(self.run_main(p, where=("--catalogue",), extra=["--icon", path])[0], 1)
            self.assertIn(says, err.getvalue())
        self.assertEqual(Fake.requests, [])

    def test_check_catalogue(self):
        os.environ["KISTA_PUBLISHER_KEY"] = self.key

        def check(whoami):
            Fake.whoami = whoami
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                return kista_publish.main(["--url", self.url, "--tenant", "acme", "--catalogue", "--check"])
        self.assertEqual(check({"publishers": [{"id": "p1"}], "grants": [{"verbs": ["publish"]}]}), 0)
        self.assertEqual(check({"publishers": [{"id": "p1"}], "grants": [{"verbs": ["publish"], "channel": "prod"}]}), 1)
        # a distributor's publisher needs no grant
        self.assertEqual(check({"publishers": [{"id": "p1", "distributor": "enterest"}], "grants": []}), 0)

    def test_ahead(self):
        now = kista_publish.datetime.datetime(2026, 10, 30, 10, 0, 0, tzinfo=kista_publish.datetime.timezone.utc)
        # kista's RFC 3339 with nanoseconds, rounded up
        self.assertEqual(kista_publish.ahead("2026-10-30T10:00:05.123456789Z", now), 6)
        self.assertEqual(kista_publish.ahead("2026-10-30T10:00:05Z", now), 5)
        self.assertEqual(kista_publish.ahead("2026-10-30T12:00:00.5+02:00", now), 1)
        self.assertEqual(kista_publish.ahead("2026-10-30T09:59:00Z", now), 0)
        self.assertEqual(kista_publish.ahead(None, now), 0)
        self.assertEqual(kista_publish.ahead("soon", now), 0)

    def test_summary_checked_and_normalised(self):
        p = os.path.join(self.dir, "myext.duckdb_extension")
        extension(p)
        # a bad summary is refused before anything is published
        for value, says in [("line\nbreak", "plain text on one line"), ("x" * 161, "at most 160 characters"),
                            ("x" + "\u0301" * 5, "more than 4 combining marks"), ("\u3164", "invisible filler"),
                            ("a\u200bb", "control, format or separator")]:
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertEqual(self.run_main(p, where=("--catalogue",), extra=["--entry-summary", value])[0], 1, value)
            self.assertIn(says, err.getvalue())
        self.assertEqual(Fake.requests, [])
        # sent as kista stores it (trimmed, NFC); the same text in another form is no change
        Fake.build = {"state": "available", "publisher_id": "p1"}
        code, _ = self.run_main(p, where=("--catalogue",), extra=["--entry-summary", "  Cafe\u0301 tools "])
        self.assertEqual((code, Fake.puts[-1][0]["summary"]), (0, "Caf\u00e9 tools"))
        Fake.puts = []
        code, summary = self.run_main(p, where=("--catalogue",), extra=["--entry-summary", "Cafe\u0301 tools"])
        self.assertEqual((code, Fake.puts), (0, []))
        self.assertIn("summary: unchanged", summary)
        # kista refuses what the script let through: named, the build published
        Fake.answers = [201, 200, (400, "invalid")]
        code, summary = self.run_main(p, where=("--catalogue",), extra=["--entry-summary", "Other"])
        self.assertEqual(code, 1)
        self.assertIn("metadata: kista answered 400", summary)

    def test_metadata_source(self):
        p = os.path.join(self.dir, "myext.duckdb_extension")
        extension(p)
        # the publisher a catalogue publication's answer names: no whoami
        Fake.build = {"state": "available", "publisher_id": "p9"}
        self.assertEqual(self.run_main(p, where=("--catalogue",), extra=["--entry-summary", "Geo"])[0], 0)
        self.assertEqual([path for path, *_ in Fake.requests][1:],
                         ["/api/v1/tenants/acme/catalogue/publisher-id:p9/extensions/myext/meta"] * 2)
        # a channel's publication: whoami's, retried when kista is busy
        Fake.requests, Fake.whoami = [], {"publishers": [{"id": "p1"}]}
        Fake.answers, Fake.retry_after = [201, (429, "rate-limited"), 503, 200], "4"
        self.sleeps[:] = []
        self.assertEqual(self.run_main(p, extra=["--entry-summary", "Geo2"])[0], 0)
        self.assertEqual([path for path, *_ in Fake.requests][1:4], ["/api/v1/tenants/acme/whoami"] * 3)
        self.assertEqual(self.sleeps, [4, 4])
        self.assertIn("publisher-id:p1", Fake.requests[-1][0])

    def test_stale_bounded_by_time(self):
        p = os.path.join(self.dir, "myext.duckdb_extension")
        extension(p)
        Fake.build = {"publisher_id": "p1"}
        # another writer's clock is 100 s ahead: kista takes a signed request for five minutes, so the
        # script waits for it up to then, and names both clocks when it gives up
        ahead = (kista_publish.datetime.datetime.now(kista_publish.datetime.timezone.utc)
                 + kista_publish.datetime.timedelta(seconds=100)).strftime("%Y-%m-%dT%H:%M:%S.5Z")
        Fake.meta = {"summary": None, "icon": None, "signed_at": ahead}
        Fake.answers = [201] + [200, (409, "stale")] * 5
        code, summary = self.run_main(p, where=("--catalogue",), extra=["--entry-summary", "Geo"])
        self.assertEqual(code, 1)
        self.assertEqual(len(self.sleeps), 3)
        self.assertTrue(all(99 <= w <= 102 for w in self.sleeps), self.sleeps)
        self.assertIn("signed at " + ahead + " and this clock says", summary)
        # a write of the same second again and again: a second each, at most STALE_TRIES tries
        Fake.meta = {"summary": None, "icon": None, "signed_at": "2026-01-01T00:00:00Z"}
        Fake.answers, self.sleeps[:] = [201] + [200, (409, "stale")] * 30, []
        self.assertEqual(self.run_main(p, where=("--catalogue",), extra=["--entry-summary", "Geo"])[0], 1)
        self.assertEqual(self.sleeps, [1] * kista_publish.STALE_TRIES)

    def test_check_names_the_extension(self):
        os.environ["KISTA_PUBLISHER_KEY"] = self.key

        def check(grants, *extra):
            Fake.whoami = {"publishers": [{"id": "p1"}], "grants": grants}
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                return kista_publish.main(["--url", self.url, "--tenant", "acme", "--catalogue", "--name", "myext", "--check", *extra])
        self.assertEqual(check([{"verbs": ["publish"], "extension": "myext"}]), 0)
        self.assertEqual(check([{"verbs": ["publish"], "extension_group": "ours"}]), 0)  # its members are not shown
        self.assertEqual(check([{"verbs": ["publish"], "extension": "other"}]), 1)
        self.assertEqual(check([{"verbs": ["publish"], "package_type": "adbc_driver"}]), 1)
        # a nameless grant of DuckDB extensions: whoami shows its type, and it reaches every extension
        self.assertEqual(check([{"verbs": ["publish"], "package_type": "duckdb_extension"}]), 0)

    def test_one_entry_without_name(self):
        for n in ["one", "two"]:
            extension(os.path.join(self.dir, n + ".duckdb_extension"))
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(self.run_main(self.dir, where=("--catalogue",), extra=["--icon", self.icon()[0]])[0], 1)
        self.assertIn("give --name (found one, two)", err.getvalue())
        self.assertEqual(Fake.requests, [])
        # with --name, its own entry
        Fake.whoami = {"publishers": [{"id": "p1"}]}
        self.assertEqual(self.run_main(self.dir, where=("--catalogue",), extra=["--name", "one", "--entry-summary", "One"])[0], 0)

    def test_stop_rows_name_each_build(self):
        # a build published, then the catalogue full: every row names its build's version and platform
        for arch in ["linux_amd64", "linux_arm64", "osx_arm64"]:
            d = os.path.join(self.dir, "myext-v2.0.0-extension-" + arch)
            os.makedirs(d)
            extension(os.path.join(d, "myext.duckdb_extension"), arch)
        Fake.answers = [201, (429, "catalogue-full")]
        code, summary = self.run_main(self.dir, where=("--catalogue",))
        self.assertEqual((code, len(Fake.requests)), (1, 2))
        self.assertIn("| myext | 1.2.0 | linux_amd64 | published |", summary)
        self.assertIn("| myext | 1.2.0 | linux_arm64 | failed: myext 1.2.0 linux_arm64: kista answered 429 (catalogue-full)", summary)
        self.assertIn("| myext | 1.2.0 | osx_arm64 | not sent: kista has no room", summary)

    def test_dry_run_catalogue(self):
        p = os.path.join(self.dir, "myext.duckdb_extension")
        extension(p)
        icon, _ = self.icon()
        out = io.StringIO()
        os.environ["KISTA_PUBLISHER_KEY"] = self.key
        summary = os.path.join(self.dir, "summary.md")
        with contextlib.redirect_stdout(out):
            code = kista_publish.main(["--url", self.url, "--tenant", "acme", "--catalogue", "--summary", summary, "--dry-run",
                                       "--icon", icon, p])
        self.assertEqual((code, Fake.requests), (0, []))
        self.assertIn("path /api/v1/tenants/acme/catalogue/extensions/myext/builds?", out.getvalue())
        with open(summary) as f:
            self.assertIn("dry run: its icon would be read, merged and written", f.read())

    def test_nothing_found(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(self.run_main(self.dir)[0], 1)


if __name__ == "__main__":
    unittest.main()
