#!/usr/bin/env python3
"""Publishes built DuckDB extensions to a kista channel (kista spec 0022).

    kista_publish.py --url <kista> --tenant <t> --channel <c> [--visibility private|public]
                     [--name <extension>] [--postfix <artifact postfix>]
                     [--api-key-env KISTA_API_KEY] [--summary <file>] <file or directory>...

Each .duckdb_extension found is read for its footer (DuckDB's metadata block: the extension version
and platform) and posted, as built, to kista's publication route:

    POST <kista>/api/v1/tenants/<t>/channels/<c>/extensions/<name>/releases?version=…&platform=…

kista checks the build and signs it with the channel's key. wasm builds are skipped: kista refuses
them (its spec 0008). With --name, only that extension's files are taken; with --postfix (as the
distribution's artifact_postfix, empty by default), only those of artifact directories that end in
-extension-<arch><postfix>. The token is the API key in the named environment variable when it is
set; otherwise, inside GitHub Actions, a fresh OIDC token per file for the audience <kista>/<tenant>.
The URL must be https (http only to a loopback address), and redirects are refused, so a token
never goes elsewhere. 201 is published and 200 already published with the same body; 429, 5xx and
a broken connection are retried; anything else fails.

Standard library only: it runs wherever extension-ci-tools already runs Python.
"""

import argparse
import http.client
import ipaddress
import json
import os
import re
import sys
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
    """Refuses redirects: a token goes to the URL it was given for, and nowhere else."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, f"redirected to {newurl}: refused", headers, fp)


OPENER = urllib.request.build_opener(NoRedirect)


def check_url(url):
    """An https URL, or http to a loopback address (a local test kista)."""
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


def oidc_token(audience):
    """GitHub Actions' OIDC token for the audience (the job needs id-token: write)."""
    url, bearer = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL"), os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not url or not bearer:
        raise Refused("no API key, and no GitHub OIDC token: give the job id-token: write, or set the API key")
    sep = "&" if "?" in url else "?"
    req = urllib.request.Request(url + sep + urllib.parse.urlencode({"audience": audience}),
                                 headers={"Authorization": "Bearer " + bearer})
    try:
        with OPENER.open(req, timeout=60) as r:
            return json.load(r)["value"]
    except (OSError, http.client.HTTPException, ValueError, KeyError) as e:
        raise Refused(f"GitHub's OIDC token: {e}")


def publish(base, tenant, channel, visibility, token, path, sleep=None):
    """Posts one file; returns 'published' or 'already published', raises Refused otherwise."""
    sleep = sleep or time.sleep
    name, version, platform = footer(path)
    q = urllib.parse.urlencode({"version": version, "platform": platform, "visibility": visibility})
    url = (f"{base}/api/v1/tenants/{urllib.parse.quote(tenant)}/channels/{urllib.parse.quote(channel)}"
           f"/extensions/{urllib.parse.quote(name)}/releases?{q}")
    with open(path, "rb") as f:
        body = f.read()
    for attempt in range(RETRIES + 1):
        req = urllib.request.Request(url, data=body, method="POST", headers={
            "Authorization": "Bearer " + token, "Content-Type": "application/octet-stream",
            "Content-Length": str(len(body))})
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
            if (e.code == 429 or e.code >= 500) and attempt < RETRIES:
                wait = e.headers.get("Retry-After") if e.headers else None
                sleep(min(int(wait), MAX_RETRY_AFTER) if wait and wait.isdigit() else 2 ** (attempt + 1))
                continue
            raise Refused(f"{name} {version} {platform}: kista answered {e.code}: {text}")
        except (OSError, http.client.HTTPException) as e:
            # no answer: the connection failed, dropped or timed out; the same body again is harmless
            if attempt < RETRIES:
                sleep(2 ** (attempt + 1))
                continue
            raise Refused(f"{name} {version} {platform}: {getattr(e, 'reason', e)}")
    raise Refused(f"{name} {version} {platform}: no answer")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Publish built DuckDB extensions to a kista channel.")
    ap.add_argument("--url", required=True, help="the kista's public URL")
    ap.add_argument("--tenant", required=True)
    ap.add_argument("--channel", required=True)
    ap.add_argument("--visibility", default="private", choices=["private", "public"])
    ap.add_argument("--name", help="only this extension's files")
    ap.add_argument("--postfix", help="only artifact directories ending -extension-<arch><postfix> (as artifact_postfix)")
    ap.add_argument("--api-key-env", default="KISTA_API_KEY", help="the environment variable holding an API key")
    ap.add_argument("--summary", help="a Markdown file to append the outcome to ($GITHUB_STEP_SUMMARY)")
    ap.add_argument("paths", nargs="+")
    a = ap.parse_args(argv)
    base = a.url.rstrip("/")
    try:
        check_url(base)
        found = files(a.paths, a.name, a.postfix)
    except Refused as e:
        print(e, file=sys.stderr)
        return 1
    if not found:
        print("no .duckdb_extension found", file=sys.stderr)
        return 1
    key = os.environ.get(a.api_key_env, "")
    rows, failed = [], False
    for path in found:
        if is_wasm(path):
            rows.append((os.path.basename(path), "", "wasm", "skipped: kista does not take wasm builds yet"))
            continue
        try:
            name, version, platform = footer(path)
            # an OIDC token lives minutes: a fresh one for each file
            token = key or oidc_token(f"{base}/{a.tenant}")
            outcome = publish(base, a.tenant, a.channel, a.visibility, token, path)
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


if __name__ == "__main__":
    sys.exit(main())
