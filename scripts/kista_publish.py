#!/usr/bin/env python3
"""Publishes built DuckDB extensions to a kista channel (kista specs 0022 and 0023).

    kista_publish.py --url <kista> --tenant <t> --channel <c> [--visibility private|public]
                     [--name <extension>] [--postfix <artifact postfix>] [--key-env KISTA_PUBLISHER_KEY]
                     [--summary <file>] [--dry-run] <file or directory>...
    kista_publish.py --url <kista> --tenant <t> --check

Each .duckdb_extension found is read for its footer (DuckDB's metadata block: the extension version
and platform) and posted, as built, to kista's publication route:

    POST <kista>/api/v1/tenants/<t>/channels/<c>/extensions/<name>/releases?version=…&platform=…

kista checks the build and signs it with the channel's key. wasm builds are skipped: kista refuses
them (its spec 0008). With --name, only that extension's files are taken; with --postfix (as the
distribution's artifact_postfix, empty by default), only those of artifact directories that end in
-extension-<arch><postfix>.

Each request is signed with the publisher's SSH key (kista spec 0023), from the environment variable
--key-env names: the private key itself, its base64, or a file holding it. The key is written to a
private file of its own (mode 0600, LF endings, a final newline: CI secret stores strip them, and
ssh-keygen then fails), removed at the end, and never printed. The request carries Kista-Statement
(the method, the path and query, the body's SHA-256 and the time) and Kista-Signature (ssh-keygen
-Y sign -n kista-request@v1 over it); a retry signs again. --check signs a whoami instead, to test
the key and its grants; --dry-run prints the statements and the key's fingerprint, sending nothing.

The URL must be https (http only to a loopback address), and redirects are refused. 201 is published
and 200 already published with the same body; 429, 408, 5xx and a broken connection are retried;
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
import subprocess
import sys
import tempfile
import time
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


class Refused(Exception):
    """A file this script will not publish, or kista refused."""


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
    name, version, platform = footer(path)
    q = urllib.parse.urlencode({"version": version, "platform": platform, "visibility": visibility})
    return (f"{base}/api/v1/tenants/{seg(tenant)}/channels/{seg(channel)}/extensions/{seg(name)}/releases?{q}")


def seg(x):
    """One path segment: a "/" in it stays in it."""
    return urllib.parse.quote(x, safe="")


def publish(base, tenant, channel, visibility, signer, path, sleep=None):
    """Posts one file; returns 'published' or 'already published', raises Refused otherwise."""
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
                if r.status == 201:
                    return "published"
                if r.status == 200:
                    return "already published"
                raise Refused(f"{name} {version} {platform}: kista answered {r.status}")
        except urllib.error.HTTPError as e:
            if 300 <= e.code < 400:
                raise Refused(f"{name} {version} {platform}: kista answered {e.code} ({e.reason}): give the URL kista "
                              "is served at, without redirects")
            text = (e.read(2000) if e.fp else b"").decode("utf-8", "replace").strip() or str(e.reason)
            if (e.code in (408, 429) or e.code >= 500) and attempt < RETRIES:
                wait = e.headers.get("Retry-After") if e.headers else None
                sleep(min(int(wait), MAX_RETRY_AFTER) if wait and wait.isdigit() else 2 ** (attempt + 1))
                continue
            raise Refused(f"{name} {version} {platform}: kista answered {e.code}: {text}")
        except http.client.InvalidURL as e:
            raise Refused(f"{name} {version} {platform}: {e}")
        except (OSError, http.client.HTTPException) as e:
            # no answer: the connection failed, dropped or timed out; the same body again is harmless
            if attempt < RETRIES:
                sleep(2 ** (attempt + 1))
                continue
            raise Refused(f"{name} {version} {platform}: {getattr(e, 'reason', e)}")
    raise Refused(f"{name} {version} {platform}: no answer")


def check(base, tenant, signer, channel=None):
    """A signed whoami: the key, its publisher and its grants, as kista sees them. With a channel, a
    publish grant there (or tenant-wide) is required too."""
    url = f"{base}/api/v1/tenants/{seg(tenant)}/whoami"
    req = urllib.request.Request(url, method="GET", headers=signed_headers(signer, "GET", url, b""))
    try:
        with OPENER.open(req, timeout=60) as r:
            text = r.read(100000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        with e:
            body = (e.read(2000) if e.fp else b"").decode("utf-8", "replace").strip() or str(e.reason)
        raise Refused(f"whoami: kista answered {e.code}: {body}")
    except (OSError, http.client.HTTPException) as e:
        raise Refused(f"whoami: {getattr(e, 'reason', e)}")
    if channel:
        try:
            grants = json.loads(text).get("grants") or []
        except ValueError:
            raise Refused("whoami: kista's answer is not JSON")
        if not any("publish" in (g.get("verbs") or []) and g.get("channel") in (None, "", channel) for g in grants):
            raise Refused(f"whoami: the publisher holds no publish grant in {channel}: {text}")
    return text


def main(argv=None):
    ap = argparse.ArgumentParser(description="Publish built DuckDB extensions to a kista channel, signed with the publisher's key.")
    ap.add_argument("--url", required=True, help="the kista's public URL")
    ap.add_argument("--tenant", required=True)
    ap.add_argument("--channel")
    ap.add_argument("--visibility", default="private", choices=["private", "public"])
    ap.add_argument("--name", help="only this extension's files")
    ap.add_argument("--postfix", help="only artifact directories ending -extension-<arch><postfix> (as artifact_postfix)")
    ap.add_argument("--key-env", default="KISTA_PUBLISHER_KEY",
                    help="the environment variable holding the publisher's private SSH key, its base64, or a file holding it")
    ap.add_argument("--summary", help="a Markdown file to append the outcome to ($GITHUB_STEP_SUMMARY)")
    ap.add_argument("--check", action="store_true",
                    help="sign a whoami: test the key, and with --channel its publish grant there; publish nothing")
    ap.add_argument("--dry-run", action="store_true", help="print the statements and the key's fingerprint, send nothing")
    ap.add_argument("paths", nargs="*")
    a = ap.parse_args(argv)
    if not a.check and (not a.channel or not a.paths):
        ap.error("--channel and at least one path are required, unless --check")
    base = a.url.rstrip("/")
    try:
        check_url(base)
        found = [] if a.check else files(a.paths, a.name, a.postfix)
        if not a.check and not found:
            raise Refused("no .duckdb_extension found")
        # a cancelled CI job is sent SIGTERM: leave through finally, which removes the key's file
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
        signer = Signer(os.environ.get(a.key_env, ""), a.key_env)
    except Refused as e:
        print(e, file=sys.stderr)
        return 1
    try:
        if a.check:
            try:
                print(check(base, a.tenant, signer, a.channel))
            except Refused as e:
                print(e, file=sys.stderr)
                return 1
            return 0
        rows, failed = [], False
        for path in found:
            if is_wasm(path):
                rows.append((os.path.basename(path), "", "wasm", "skipped: kista does not take wasm builds yet"))
                continue
            try:
                name, version, platform = footer(path)
                if a.dry_run:
                    url = release_url(base, a.tenant, a.channel, a.visibility, path)
                    with open(path, "rb") as f:
                        st = statement("POST", url, f.read())
                    print(st.decode("ascii"), end="")
                    rows.append((name, version, platform, "dry run: would be signed by " + signer.fingerprint))
                    continue
                outcome = publish(base, a.tenant, a.channel, a.visibility, signer, path)
                rows.append((name, version, platform, outcome))
            except Refused as e:
                failed = True
                rows.append((os.path.basename(path), "", "", f"failed: {e}"))
        for r in rows:
            print("\t".join(r))
        if a.summary:
            with open(a.summary, "a") as f:
                f.write(f"### kista: {base} {a.tenant}/{a.channel}\n\n| extension | version | platform | outcome |\n| --- | --- | --- | --- |\n")
                for r in rows:
                    f.write("| " + " | ".join(x.replace("|", "\\|") for x in r) + " |\n")
        return 1 if failed else 0
    finally:
        signer.close()


if __name__ == "__main__":
    sys.exit(main())
