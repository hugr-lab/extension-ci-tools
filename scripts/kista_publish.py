#!/usr/bin/env python3
"""Publishes built DuckDB extensions to a kista channel or catalogue (kista specs 0022, 0023, 0033, 0036).

    kista_publish.py --url <kista> --tenant <t> (--channel <c> | --catalogue) [--visibility private|public]
                     [--name <extension>] [--postfix <artifact postfix>] [--key-env KISTA_PUBLISHER_KEY]
                     [--entry-summary <text>] [--icon <png>] [--summary <file>] [--dry-run] <file or directory>...
    kista_publish.py --url <kista> --tenant <t> [--channel <c> | --catalogue] --check

Each .duckdb_extension found is read for its footer (DuckDB's metadata block: the extension version
and platform) and posted, as built, to kista's publication route, a channel's:

    POST <kista>/api/v1/tenants/<t>/channels/<c>/extensions/<name>/releases?version=…&platform=…

kista checks the build and signs it with the channel's key. With --catalogue, it goes into the
tenant's catalogue only, placed in no channel, for the channels' rules to take (kista spec 0033): a
publisher with a hold publishes so, and its builds are held until their time.

    POST <kista>/api/v1/tenants/<t>/catalogue/extensions/<name>/builds?version=…&platform=…

wasm builds are skipped: kista refuses them (its spec 0008). With --name, only that extension's
files are taken; with --postfix (as the distribution's artifact_postfix, empty by default), only
those of artifact directories that end in -extension-<arch><postfix>.

--entry-summary and --icon set the catalogue entry's summary and icon (a square PNG, kista spec
0036), once for each extension published, after its builds: the entry's metadata is read and merged
(what is not given is kept; an icon kista has already is kept by its hash, not sent again), and
written only when it changes. An empty value clears that field.

Each request is signed with the publisher's SSH key (kista spec 0023), from the environment variable
--key-env names: the private key itself, its base64, or a file holding it. The key is written to a
private file of its own (mode 0600, LF endings, a final newline: CI secret stores strip them, and
ssh-keygen then fails), removed at the end, and never printed. The request carries Kista-Statement
(the method, the path and query, the body's SHA-256 and the time) and Kista-Signature (ssh-keygen
-Y sign -n kista-request@v1 over it); a retry signs again. --check signs a whoami instead, to test
the key and its grants; --dry-run prints the statements and the key's fingerprint, sending nothing.

The URL must be https (http only to a loopback address), and redirects are refused. 201 is published
and 200 already published with the same body; 408, 5xx, a broken connection and a 429 for a busy
kista are retried (rate-limited, upload-slots, ingest-busy: after its Retry-After); a 429 typed
catalogue-full or tenant-limit stops the run, since it clears only when room is made in kista;
anything else fails.

Standard library and OpenSSH 8.1 or later only: it runs in any CI.
"""

import argparse
import base64
import binascii
import datetime
import hashlib
import http.client
import ipaddress
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request

SIGNATURE_SIZE = 256
METADATA_SIZE = 256
FIELD_SIZE = 32
FIELD_COUNT = 8
MAGIC = "4"
RETRIES = 3
TIMEOUT = 300
MAX_RETRY_AFTER = 60
SUFFIXES = (".duckdb_extension", ".duckdb_extension.wasm")
NAMESPACE = "kista-request@v1"
PROBLEM = "urn:kista:problem:"
# a 429 of these types clears only when room is made in kista: a client stops (kista specs 0033, 0038)
STOP_TYPES = ("catalogue-full", "tenant-limit")
PNG = b"\x89PNG\r\n\x1a\n"
MAX_ICON = 256 * 1024
MAX_SUMMARY = 160  # code points, after NFC (kista's CheckSummary)
MAX_MARKS = 4  # combining marks after a character
FILLERS = {0x115F, 0x1160, 0x3164, 0xFFA0, 0x2800}  # printable, but show nothing
# kista takes a signed request within five minutes of its signed-at: a stale write waits at most so long
STALE_WAIT = 310
STALE_TRIES = 20  # and at most so many tries (a write of the same second waits a second each)


class Refused(Exception):
    """A file this script will not publish, or kista refused."""


class Stopped(Refused):
    """kista has no room (catalogue-full, tenant-limit): nothing more is sent."""


def problem_type(text):
    """The type of a kista problem answer (urn:kista:problem:<type>), "" for anything else."""
    try:
        t = json.loads(text).get("type") or ""
    except (ValueError, AttributeError):
        return ""
    return t[len(PROBLEM):] if isinstance(t, str) and t.startswith(PROBLEM) else ""


def check_summary(text):
    """A summary as kista stores it (spec 0036): trimmed, NFC; at most 160 code points, each printable
    or a space, at most 4 combining marks after a character, no invisible filler. kista decides; this
    refuses before anything is published."""
    s = unicodedata.normalize("NFC", text.strip())
    if len(s) > MAX_SUMMARY:
        raise Refused(f"the summary is at most {MAX_SUMMARY} characters (this one has {len(s)})")
    marks = 0
    for c in s:
        cat = unicodedata.category(c)
        if c != " " and cat[0] not in "LMNPS":
            raise Refused("the summary is plain text on one line: it has a control, format or separator character "
                          "(U+%04X)" % ord(c))
        if ord(c) in FILLERS:
            raise Refused("the summary has an invisible filler (U+%04X)" % ord(c))
        if cat[0] == "M":
            marks += 1
            if marks > MAX_MARKS:
                raise Refused(f"the summary has more than {MAX_MARKS} combining marks after a character")
        else:
            marks = 0
    return s


def footer(path):
    """The (name, extension version, platform) of a built extension, from its file name and footer."""
    size = os.path.getsize(path)
    if size < METADATA_SIZE + SIGNATURE_SIZE:
        raise Refused(f"{path}: {size} bytes, too small for an extension")
    with open(path, "rb") as f:
        f.seek(size - METADATA_SIZE - SIGNATURE_SIZE)
        block = f.read(METADATA_SIZE)
    fields = []
    for i in range(FIELD_COUNT):
        # field i is stored at position FIELD_COUNT-1-i, zero-padded
        raw = block[(FIELD_COUNT - 1 - i) * FIELD_SIZE:(FIELD_COUNT - i) * FIELD_SIZE]
        value = raw.split(b"\0", 1)[0]
        try:
            fields.append(value.decode("ascii"))
        except UnicodeDecodeError:
            fields.append("")
    if fields[0] != MAGIC or not fields[1] or not fields[3]:
        raise Refused(f"{path}: no DuckDB extension footer (magic, platform and version)")
    return extension_name(path), fields[3], fields[1]


def extension_name(path):
    """The extension's name, from its file name (<name>.duckdb_extension, as DuckDB's build names it)."""
    base = os.path.basename(path)
    for suffix in SUFFIXES:
        if base.endswith(suffix) and len(base) > len(suffix):
            return base[: -len(suffix)]
    raise Refused(f"{path}: not a <name>.duckdb_extension file")


def is_wasm(path):
    # the distribution names a wasm build <name>.duckdb_extension.wasm
    return path.endswith(".duckdb_extension.wasm")


def files(paths, name=None, postfix=None):
    """The extensions under the paths: .duckdb_extension files, and wasm builds to skip. A directory's
    files are those of name (all without it) in artifact directories ending -extension-<arch><postfix>
    (any without postfix); a file given explicitly is taken as it is."""
    out = []
    artifact = re.compile(r"-extension-[a-z0-9_]+" + re.escape(postfix) + "$") if postfix is not None else None
    for p in paths:
        if not os.path.isdir(p):
            extension_name(p)
            out.append(p)
            continue
        for root, _, names in os.walk(p):
            if artifact is not None and root != p and not artifact.search(os.path.basename(root)):
                continue
            for n in sorted(names):
                if n.endswith(SUFFIXES) and (name is None or n in (name + s for s in SUFFIXES)):
                    out.append(os.path.join(root, n))
    return sorted(out)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuses redirects: a signed request goes to the URL it was signed for, and nowhere else."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, f"redirected to {newurl}: refused", headers, fp)


OPENER = urllib.request.build_opener(NoRedirect)


def check_url(url):
    """An https URL, or http to a loopback address (a test server: kista's API is https only)."""
    if any(ord(c) < 0x21 or ord(c) > 0x7e for c in url):
        raise Refused(f"{url!r}: kista's URL is printable ASCII, without spaces or line ends")
    u = urllib.parse.urlparse(url)
    if u.scheme == "https" and u.hostname:
        return
    if u.scheme == "http" and u.hostname:
        try:
            if u.hostname == "localhost" or ipaddress.ip_address(u.hostname).is_loopback:
                return
        except ValueError:
            pass
    raise Refused(f"{url}: kista's URL must be https (http only to a loopback address)")


# ssh-keygen signs with the key file it is given, never through an agent or a passphrase prompt
SSH_ENV_DROPPED = ("SSH_AUTH_SOCK", "SSH_AGENT_PID", "SSH_ASKPASS", "DISPLAY")


class Signer:
    """The publisher's SSH key, in a private file of its own, signing statements with ssh-keygen."""

    def __init__(self, value, key_env="KISTA_PUBLISHER_KEY"):
        self.dir = None
        text = self.load(value, key_env)
        self.env = {k: v for k, v in os.environ.items() if k not in SSH_ENV_DROPPED and k != key_env}
        self.env["SSH_ASKPASS_REQUIRE"] = "never"
        try:
            # RUNNER_TEMP is wiped after a GitHub Actions job, whatever ends it
            self.dir = tempfile.mkdtemp(prefix="kista-key-", dir=os.environ.get("RUNNER_TEMP") or None)
            self.path = os.path.join(self.dir, "key")
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", newline="\n") as f:
                f.write(text)
            # the public half from the private one, without a passphrase: a key with one fails here
            try:
                pub = self.ssh_keygen(["-y", "-P", "", "-f", self.path])
            except Refused as e:
                if "passphrase" in str(e):
                    raise Refused("the publisher key cannot be read without a passphrase: make it with ssh-keygen -N ''")
                raise
            fd = os.open(self.path + ".pub", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", newline="\n") as f:
                f.write(pub)
            fields = self.ssh_keygen(["-l", "-f", self.path + ".pub"]).split()
            self.fingerprint = fields[1] if len(fields) > 1 else "?"
            self.sign(b"kista_publish.py: a key that cannot sign fails before anything is sent\n")
        except BaseException:
            self.close()
            raise

    @staticmethod
    def load(value, key_env="KISTA_PUBLISHER_KEY"):
        """The key's text: the key itself, its base64, or a file's content; LF endings and a final newline."""
        value = value or ""
        if not value.strip():
            raise Refused(f"{key_env} is empty: the publisher key's secret is not set for this job (an environment's "
                          "secret needs the environment)")
        if "-----BEGIN" in value:
            text = value
        else:
            try:
                text = base64.b64decode("".join(value.split()), validate=True).decode("ascii")
            except (binascii.Error, UnicodeDecodeError):
                text = ""
            if "-----BEGIN" not in text and os.path.isfile(value):
                with open(value) as f:
                    text = f.read()
            if "-----BEGIN" not in text:
                raise Refused(f"{key_env}: the publisher key is neither a private key, its base64, nor a file holding one")
        return text.replace("\r\n", "\n").replace("\r", "\n").strip("\n") + "\n"

    def ssh_keygen(self, args, data=None):
        try:
            r = subprocess.run(["ssh-keygen", *args], input=data, stdin=None if data is not None else subprocess.DEVNULL,
                               capture_output=True, timeout=60, env=self.env)
        except FileNotFoundError:
            raise Refused("no ssh-keygen: install OpenSSH 8.1 or later (openssh-client, or openssh-keygen on Alpine)")
        except subprocess.TimeoutExpired:
            raise Refused("ssh-keygen did not answer")
        err = r.stderr.decode("utf-8", "replace")
        if r.returncode != 0:
            if "-Y" in args and any(m in err for m in ("illegal option", "unknown option", "invalid option")):
                raise Refused("ssh-keygen cannot sign (-Y): OpenSSH 8.1 or later is needed")
            # never the key: ssh-keygen's message names the file, not its content
            raise Refused("ssh-keygen: " + (err.strip().splitlines() or ["failed"])[-1])
        return r.stdout.decode("utf-8", "replace")

    def sign(self, statement):
        """The SSHSIG of a statement, standard base64 on one line, without its armor."""
        armored = self.ssh_keygen(["-Y", "sign", "-q", "-f", self.path, "-n", NAMESPACE], statement)
        return "".join(line.strip() for line in armored.splitlines() if line.strip() and not line.startswith("-----"))

    def close(self):
        if self.dir:
            shutil.rmtree(self.dir, ignore_errors=True)
            self.dir = None


def statement(method, url, body, now=None):
    """A request's statement: the method, the path and query as urllib sends them, the body's SHA-256
    and the signing time (UTC, to the second)."""
    u = urllib.parse.urlsplit(url)
    path = (u.path or "/") + ("?" + u.query if u.query else "")
    at = (now or datetime.datetime.now(datetime.timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return ("kista-request v1\nmethod %s\npath %s\nsha256 %s\nsigned-at %s\n"
            % (method, path, hashlib.sha256(body).hexdigest(), at)).encode("ascii")


def signed_headers(signer, method, url, body):
    st = statement(method, url, body)
    return {"Kista-Statement": base64.b64encode(st).decode("ascii"), "Kista-Signature": signer.sign(st)}


def release_url(base, tenant, channel, visibility, path):
    """The publication's URL: a channel's (channel given), or the catalogue's (channel None)."""
    name, version, platform = footer(path)
    q = urllib.parse.urlencode({"version": version, "platform": platform, "visibility": visibility})
    if channel is None:
        return f"{base}/api/v1/tenants/{seg(tenant)}/catalogue/extensions/{seg(name)}/builds?{q}"
    return (f"{base}/api/v1/tenants/{seg(tenant)}/channels/{seg(channel)}/extensions/{seg(name)}/releases?{q}")


def meta_url(base, tenant, source, name):
    """A catalogue entry's metadata (kista spec 0036); the source keeps its ":" as kista names it."""
    return f"{base}/api/v1/tenants/{seg(tenant)}/catalogue/{seg(source, ':')}/extensions/{seg(name)}/meta"


def seg(x, safe=""):
    """One path segment: a "/" in it stays in it."""
    return urllib.parse.quote(x, safe=safe)


def wait_for(headers, attempt):
    """How long to wait before a retry: the answer's Retry-After (at most MAX_RETRY_AFTER), else a backoff."""
    wait = headers.get("Retry-After") if headers else None
    return min(int(wait), MAX_RETRY_AFTER) if wait and wait.isdigit() else 2 ** (attempt + 1)


def build_answer(text):
    """A catalogue build's answer: its note (" (held until <time>)" for a held build, "" otherwise) and
    the publisher that published it (its id, "" when not named)."""
    try:
        b = json.loads(text)
    except ValueError:
        b = None
    if not isinstance(b, dict):
        return "", ""
    note = " (held until %s)" % (b.get("available_at") or "its hold ends") if b.get("state") == "held" else ""
    return note, b.get("publisher_id") or ""


def publish(base, tenant, channel, visibility, signer, path, sleep=None):
    """Posts one file, to a channel or (channel None) the catalogue; returns 'published' or 'already
    published' (a held catalogue build says until when) and, for the catalogue, the id of the publisher
    kista names in its answer; raises Refused (Stopped: no room) otherwise."""
    sleep = sleep or time.sleep
    name, version, platform = footer(path)
    url = release_url(base, tenant, channel, visibility, path)
    with open(path, "rb") as f:
        body = f.read()
    for attempt in range(RETRIES + 1):
        # signed for each attempt: a retry never outlives its signed-at
        headers = signed_headers(signer, "POST", url, body)
        headers.update({"Content-Type": "application/octet-stream", "Content-Length": str(len(body))})
        req = urllib.request.Request(url, data=body, method="POST", headers=headers)
        try:
            with OPENER.open(req, timeout=TIMEOUT) as r:
                if r.status in (200, 201):
                    note, pub = build_answer(r.read(100000).decode("utf-8", "replace")) if channel is None else ("", "")
                    return ("published" if r.status == 201 else "already published") + note, pub
                raise Refused(f"{name} {version} {platform}: kista answered {r.status}")
        except urllib.error.HTTPError as e:
            if 300 <= e.code < 400:
                raise Refused(f"{name} {version} {platform}: kista answered {e.code} ({e.reason}): give the URL kista "
                              "is served at, without redirects")
            with e:
                text = (e.read(2000) if e.fp else b"").decode("utf-8", "replace").strip() or str(e.reason)
            kind = problem_type(text)
            if e.code == 429 and kind in STOP_TYPES:
                raise Stopped(f"{name} {version} {platform}: kista answered 429 ({kind}): {text}")
            if (e.code in (408, 429) or e.code >= 500) and attempt < RETRIES:
                sleep(wait_for(e.headers, attempt))
                continue
            if e.code == 409 and kind == "held" and channel is not None:
                why = ("the publisher has a hold, so it publishes into the catalogue only (--catalogue)"
                       if "has a hold" in text else
                       "this build is held (or revoked) in the catalogue: a channel administrator may place it early")
                raise Refused(f"{name} {version} {platform}: kista answered 409 (held): {why}: {text}")
            raise Refused(f"{name} {version} {platform}: kista answered {e.code}: {text}")
        except http.client.InvalidURL as e:
            raise Refused(f"{name} {version} {platform}: {e}")
        except (OSError, http.client.HTTPException) as e:
            # no answer: the connection failed, dropped or timed out; the same body again is harmless
            if attempt < RETRIES:
                sleep(2 ** (attempt + 1))
                continue
            # kista answers some refusals before it reads the file (a key it does not know, no grant,
            # a publisher with a hold on a channel), and closes: a large upload then sees only the close
            raise Refused(f"{name} {version} {platform}: no answer ({getattr(e, 'reason', e)}); kista may have refused it "
                          "before reading the file: --check tests the key and its grant"
                          + ("" if channel is None else ", a publisher with a hold publishes with --catalogue")
                          + ", or the file is over kista's size limit (413)")
    raise Refused(f"{name} {version} {platform}: no answer")


def whoami(base, tenant, signer, sleep=None):
    """A signed whoami: the key, its publishers and their grants, as kista sees them (its text). A busy
    kista is retried as a publication is."""
    sleep = sleep or time.sleep
    url = f"{base}/api/v1/tenants/{seg(tenant)}/whoami"
    for attempt in range(RETRIES + 1):
        # signed for each attempt: a retry never outlives its signed-at
        req = urllib.request.Request(url, method="GET", headers=signed_headers(signer, "GET", url, b""))
        try:
            with OPENER.open(req, timeout=60) as r:
                return r.read(100000).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            with e:
                body = (e.read(2000) if e.fp else b"").decode("utf-8", "replace").strip() or str(e.reason)
            if (e.code == 408 or e.code == 429 and problem_type(body) not in STOP_TYPES or e.code >= 500) and attempt < RETRIES:
                sleep(wait_for(e.headers, attempt))
                continue
            raise Refused(f"whoami: kista answered {e.code}: {body}")
        except http.client.InvalidURL as e:
            raise Refused(f"whoami: {e}")
        except (OSError, http.client.HTTPException) as e:
            if attempt < RETRIES:
                sleep(2 ** (attempt + 1))
                continue
            raise Refused(f"whoami: {getattr(e, 'reason', e)}")
    raise Refused("whoami: no answer")


def parsed(text):
    try:
        w = json.loads(text)
    except ValueError:
        w = None
    if not isinstance(w, dict):
        raise Refused("whoami: kista's answer is not a JSON object")
    return w


def publishes(g, channel, name):
    """Whether a grant lets publish a DuckDB extension (name, when given) in the channel ("" for the
    catalogue: a tenant-wide grant only). An extension group's grant is taken as it is (its members are
    not shown); a grant of another package type does not reach an extension (whoami shows a nameless
    grant's type when it is not every type: duckdb_extension reaches every extension)."""
    return ("publish" in (g.get("verbs") or []) and (g.get("package_type") or "") in ("", "duckdb_extension")
            and (g.get("channel") or "") in ("", channel)
            and (not name or (g.get("extension") or "") in ("", name)))


def check(base, tenant, signer, channel=None, catalogue=False, name=None):
    """A signed whoami. With a channel, a publish grant there (or tenant-wide) is required too; with
    catalogue, a tenant-wide publish grant, or a distributor's publisher (which needs none); with a
    name, a grant reaching that extension."""
    text = whoami(base, tenant, signer)
    if channel or catalogue:
        w = parsed(text)
        grants = w.get("grants") or []
        what = f" on {name}" if name else ""
        if channel and not any(publishes(g, channel, name) for g in grants):
            raise Refused(f"whoami: the publisher holds no publish grant{what} in {channel}: {text}")
        if catalogue and not (any(publishes(g, "", name) for g in grants)
                              or any(p.get("distributor") for p in w.get("publishers") or [])):
            raise Refused(f"whoami: the publisher holds no tenant-wide publish grant{what}, which the catalogue needs: {text}")
    return text


def source_of(text):
    """The catalogue source the key's builds land in, as kista names it: publisher-id:<id> of its
    publisher (of the first by id, when the key is several publishers', as kista takes it)."""
    ids = sorted(p.get("id") for p in parsed(text).get("publishers") or [] if p.get("id"))
    if not ids:
        raise Refused("whoami: the key names no publisher, so its catalogue entries cannot be named")
    return "publisher-id:" + ids[0]


def icon_of(path):
    """An icon file's bytes: a PNG of at most 256 KiB whose IHDR is square, 64 to 512 pixels (kista
    checks the rest: its chunks). A symbolic link is refused: the file is the caller's own."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as f:
            if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                raise Refused(f"{path}: the icon is a regular file")
            data = f.read(MAX_ICON + 1)
    except OSError as e:
        raise Refused(f"{path}: {e.strerror}" + (" (a symbolic link is refused)" if os.path.islink(path) else ""))
    if not data.startswith(PNG) or data[12:16] != b"IHDR" or len(data) < 24:
        raise Refused(f"{path}: the icon is a PNG")
    if len(data) > MAX_ICON:
        raise Refused(f"{path}: the icon is at most 256 KiB")
    width, height = int.from_bytes(data[16:20], "big"), int.from_bytes(data[20:24], "big")
    if width != height or not 64 <= width <= 512:
        raise Refused(f"{path}: the icon is square, 64 to 512 pixels a side (this one is {width}x{height})")
    return data


def signed_json(signer, method, url, payload):
    """A signed JSON request (GET without a body); its answer as a dict. HTTPError is raised to the caller."""
    body = b"" if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
    headers = signed_headers(signer, method, url, body)
    if payload is not None:
        headers.update({"Content-Type": "application/json", "Content-Length": str(len(body))})
    req = urllib.request.Request(url, data=body if payload is not None else None, method=method, headers=headers)
    with OPENER.open(req, timeout=60) as r:
        try:
            return json.loads(r.read(1000000).decode("utf-8", "replace"))
        except ValueError:
            raise Refused(f"{method} {url}: kista's answer is not JSON")


RFC3339 = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?(Z|[+-]\d\d:\d\d)$")


def ahead(signed_at, now=None):
    """Whole seconds, rounded up, until our clock passes kista's signed_at (RFC 3339 with up to
    nanoseconds, as kista writes it); 0 when it has, or when it cannot be read."""
    m = RFC3339.match(signed_at or "")
    if not m:
        return 0
    zone = datetime.timezone.utc if m.group(3) == "Z" else datetime.datetime.strptime(m.group(3).replace(":", ""), "%z").tzinfo
    t = datetime.datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=zone)
    frac = m.group(2) or ""
    d = (t - (now or datetime.datetime.now(datetime.timezone.utc))).total_seconds() + (int(frac) / 10 ** len(frac) if frac else 0)
    return max(0, -int(-d // 1))


def set_meta(base, tenant, source, name, signer, summary=None, icon=None, sleep=None, clock=None):
    """Sets a catalogue entry's summary and icon (kista spec 0036): reads the entry's metadata, merges
    (None keeps a field, "" or b"" clears it; an icon kista has already is kept by its hash, not sent
    again), and writes it when it changes. summary is as kista stores it (check_summary's). Returns
    'set' or 'unchanged'; raises Refused otherwise. A stale write is tried again for as long as kista
    takes a signed request (STALE_WAIT); anything else as a publication is."""
    sleep, clock = sleep or time.sleep, clock or time.monotonic
    url = meta_url(base, tenant, source, name)
    new_icon = icon_sha = None
    if icon:
        new_icon = {"content_type": "image/png", "data": base64.b64encode(icon).decode("ascii")}
        icon_sha = hashlib.sha256(icon).hexdigest()
    attempt, stale, start, signed_at = 0, 0, clock(), None
    while True:
        try:
            cur = signed_json(signer, "GET", url, None)
            signed_at = cur.get("signed_at")
            have_icon = (cur.get("icon") or {}).get("sha256")
            want = {"summary": cur.get("summary") if summary is None else summary}
            if icon is None:
                want["icon"] = {"sha256": have_icon} if have_icon else None
            elif not icon:
                want["icon"] = None
            else:
                want["icon"] = {"sha256": have_icon} if have_icon == icon_sha else new_icon
            if (want["summary"] or None) == (cur.get("summary") or None) and \
                    (want["icon"] or {}).get("sha256") == have_icon and "data" not in (want["icon"] or {}):
                return "unchanged"
            signed_json(signer, "PUT", url, want)
            return "set"
        except urllib.error.HTTPError as e:
            if 300 <= e.code < 400:
                raise Refused(f"{name} metadata: kista answered {e.code} ({e.reason}): give the URL kista is served at, "
                              "without redirects")
            with e:
                text = (e.read(2000) if e.fp else b"").decode("utf-8", "replace").strip() or str(e.reason)
            kind = problem_type(text)
            if e.code == 429 and kind in STOP_TYPES:
                raise Stopped(f"{name} metadata: kista answered 429 ({kind}): {text}")
            if e.code == 404:
                raise Refused(f"{name} metadata: kista answered 404: no catalogue entry of {source} for {name} (its "
                              f"builds are published first), or the key may not set it: {text}")
            if e.code == 409 and kind == "stale":
                # a newer write, or another of the same second: write again once our clock passes the
                # entry's signed_at, for as long as kista takes a signed request
                wait, stale = max(ahead(signed_at), 1), stale + 1
                if clock() - start + wait > STALE_WAIT or stale > STALE_TRIES:
                    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                    raise Refused(f"{name} metadata: kista answered 409 (stale): the entry's last write is signed at "
                                  f"{signed_at or '?'} and this clock says {now}: check the clock, or wait and run again")
                sleep(wait)
                continue
            if attempt < RETRIES:
                attempt += 1
                if e.code == 409 and kind == "conflict":  # the icon changed meanwhile: read again
                    continue
                if e.code in (408, 429) or e.code >= 500:
                    sleep(wait_for(e.headers, attempt - 1))
                    continue
            raise Refused(f"{name} metadata: kista answered {e.code}: {text}")
        except http.client.InvalidURL as e:
            raise Refused(f"{name} metadata: {e}")
        except (OSError, http.client.HTTPException) as e:
            if attempt < RETRIES:
                attempt += 1
                sleep(2 ** attempt)
                continue
            raise Refused(f"{name} metadata: {getattr(e, 'reason', e)}")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Publish built DuckDB extensions to a kista channel or catalogue, signed with the "
                                             "publisher's key.")
    ap.add_argument("--url", required=True, help="the kista's public URL")
    ap.add_argument("--tenant", required=True)
    where = ap.add_mutually_exclusive_group()
    where.add_argument("--channel", help="publish into this channel")
    where.add_argument("--catalogue", action="store_true",
                       help="publish into the tenant's catalogue only (a publisher with a hold publishes so)")
    ap.add_argument("--visibility", default="private", choices=["private", "public"])
    ap.add_argument("--name", help="only this extension's files")
    ap.add_argument("--postfix", help="only artifact directories ending -extension-<arch><postfix> (as artifact_postfix)")
    ap.add_argument("--key-env", default="KISTA_PUBLISHER_KEY",
                    help="the environment variable holding the publisher's private SSH key, its base64, or a file holding it")
    ap.add_argument("--entry-summary", help="the catalogue entry's summary, set after its builds (empty: cleared)")
    ap.add_argument("--icon", help="the catalogue entry's icon, a square PNG of 64 to 512 pixels, set after its builds "
                                   "(empty: cleared)")
    ap.add_argument("--summary", help="a Markdown file to append the outcome to ($GITHUB_STEP_SUMMARY)")
    ap.add_argument("--check", action="store_true",
                    help="sign a whoami: test the key, and with --channel or --catalogue its publish grant; publish nothing")
    ap.add_argument("--dry-run", action="store_true", help="print the statements and the key's fingerprint, send nothing")
    ap.add_argument("paths", nargs="*")
    a = ap.parse_args(argv)
    if not a.check and (not (a.channel or a.catalogue) or not a.paths):
        ap.error("--channel or --catalogue, and at least one path, are required, unless --check")
    base = a.url.rstrip("/")
    channel = None if a.catalogue else a.channel
    meta = a.entry_summary is not None or a.icon is not None
    try:
        check_url(base)
        found = [] if a.check else files(a.paths, a.name, a.postfix)
        if not a.check and not found:
            raise Refused("no .duckdb_extension found")
        # the metadata is checked before anything is published: a bad value never leaves builds
        # published and the job failed
        summary = None if a.entry_summary is None else check_summary(a.entry_summary)
        icon = None if a.icon is None else (icon_of(a.icon) if a.icon else b"")
        names = list(dict.fromkeys(extension_name(p) for p in found if not is_wasm(p)))
        if meta and not a.name and len(names) > 1:
            raise Refused("--entry-summary and --icon set one extension's entry: give --name (found %s)" % ", ".join(names))
        # a cancelled CI job is sent SIGTERM: leave through finally, which removes the key's file
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
        signer = Signer(os.environ.get(a.key_env, ""), a.key_env)
    except Refused as e:
        print(e, file=sys.stderr)
        return 1
    try:
        if a.check:
            try:
                print(check(base, a.tenant, signer, a.channel, a.catalogue, a.name))
            except Refused as e:
                print(e, file=sys.stderr)
                return 1
            return 0
        rows, failed, stopped, published, publisher = [], False, None, [], ""

        def who(path):
            """A row's first three cells: the build's name, version and platform, or its path."""
            try:
                return footer(path)
            except Refused:
                return os.path.relpath(path), "", ""
        for path in found:
            if stopped:
                rows.append((*who(path), "not sent: " + stopped))
                continue
            if is_wasm(path):
                rows.append((os.path.basename(path), "", "wasm", "skipped: kista does not take wasm builds yet"))
                continue
            try:
                name, version, platform = footer(path)
                if a.dry_run:
                    url = release_url(base, a.tenant, channel, a.visibility, path)
                    with open(path, "rb") as f:
                        st = statement("POST", url, f.read())
                    print(st.decode("ascii"), end="")
                    rows.append((name, version, platform, "dry run: would be signed by " + signer.fingerprint))
                    published.append(name)
                    continue
                outcome, pub = publish(base, a.tenant, channel, a.visibility, signer, path)
                rows.append((name, version, platform, outcome))
                published.append(name)
                publisher = publisher or pub
            except Stopped as e:
                failed, stopped = True, "kista has no room (catalogue-full or tenant-limit): make room, then run again"
                rows.append((*who(path), f"failed: {e}"))
            except Refused as e:
                failed = True
                rows.append((*who(path), f"failed: {e}"))
        if meta:
            # the entry's source: the publisher kista named in a catalogue publication's answer, else
            # (a channel's publication) the key's, from whoami
            source = "publisher-id:" + publisher if publisher else None
            for name in names:
                what = "summary and icon" if a.entry_summary is not None and a.icon is not None else \
                    "summary" if a.entry_summary is not None else "icon"
                if stopped:
                    rows.append((name, "", "metadata", "not sent: " + stopped))
                    continue
                if name not in published:
                    rows.append((name, "", "metadata", f"not set: no build of {name} was published"))
                    continue
                if a.dry_run:
                    rows.append((name, "", "metadata", f"dry run: its {what} would be read, merged and written"))
                    continue
                try:
                    source = source or source_of(whoami(base, a.tenant, signer))
                    outcome = set_meta(base, a.tenant, source, name, signer, summary, icon)
                    rows.append((name, "", "metadata", f"{what}: {outcome}"))
                except Stopped as e:
                    failed, stopped = True, "kista has no room (catalogue-full or tenant-limit): make room, then run again"
                    rows.append((name, "", "metadata", f"failed: {e}"))
                except Refused as e:
                    failed = True
                    rows.append((name, "", "metadata", f"failed: {e}"))
        for r in rows:
            print("\t".join(r))
        if a.summary:
            where = f"{a.tenant}/{channel}" if channel else f"{a.tenant} catalogue"
            with open(a.summary, "a") as f:
                f.write(f"### kista: {base} {where}\n\n| extension | version | platform | outcome |\n| --- | --- | --- | --- |\n")
                for r in rows:
                    f.write("| " + " | ".join(x.replace("|", "\\|") for x in r) + " |\n")
        return 1 if failed else 0
    finally:
        signer.close()


if __name__ == "__main__":
    sys.exit(main())
