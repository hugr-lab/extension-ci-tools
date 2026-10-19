#!/usr/bin/env python3
"""Publishes built DuckDB extensions to a kista channel (kista spec 0022).

    kista_publish.py --url <kista> --tenant <t> --channel <c> [--visibility private|public]
                     [--api-key-env KISTA_API_KEY] [--summary <file>] <file or directory>...

Each .duckdb_extension found is read for its footer (DuckDB's metadata block: the extension version
and platform) and posted, as built, to kista's publication route:

    POST <kista>/api/v1/tenants/<t>/channels/<c>/extensions/<name>/releases?version=…&platform=…

kista checks the build and signs it with the channel's key. wasm builds are skipped: kista refuses
them (its spec 0008). The token is the API key in the named environment variable when it is set;
otherwise, inside GitHub Actions, an OIDC token for the audience <kista>/<tenant>. 201 is published
and 200 already published with the same body; 429 and 5xx are retried; anything else fails.

Standard library only: it runs wherever extension-ci-tools already runs Python.
"""

import argparse
import json
import os
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
    name = os.path.basename(path)[: -len(".duckdb_extension")]
    return name, fields[3], fields[1]


def is_wasm(path):
    return path.endswith(".wasm") or "wasm" in os.path.basename(os.path.dirname(path))


def files(paths):
    """Every extension under the paths: .duckdb_extension files, and wasm builds to skip."""
    out = []
    for p in paths:
        if os.path.isdir(p):
            for root, _, names in os.walk(p):
                for n in sorted(names):
                    if n.endswith(".duckdb_extension") or n.endswith(".duckdb_extension.wasm"):
                        out.append(os.path.join(root, n))
        else:
            out.append(p)
    return sorted(out)


def oidc_token(audience):
    """GitHub Actions' OIDC token for the audience (the job needs id-token: write)."""
    url, bearer = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL"), os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not url or not bearer:
        raise Refused("no API key, and no GitHub OIDC token: give the job id-token: write, or set the API key")
    sep = "&" if "?" in url else "?"
    req = urllib.request.Request(url + sep + urllib.parse.urlencode({"audience": audience}),
                                 headers={"Authorization": "Bearer " + bearer})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)["value"]


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
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                return {201: "published", 200: "already published"}.get(r.status, f"answered {r.status}")
        except urllib.error.HTTPError as e:
            text = e.read(2000).decode("utf-8", "replace").strip()
            if (e.code == 429 or e.code >= 500) and attempt < RETRIES:
                wait = e.headers.get("Retry-After")
                sleep(int(wait) if wait and wait.isdigit() else 2 ** (attempt + 1))
                continue
            raise Refused(f"{name} {version} {platform}: kista answered {e.code}: {text}")
        except urllib.error.URLError as e:
            if attempt < RETRIES:
                sleep(2 ** (attempt + 1))
                continue
            raise Refused(f"{name} {version} {platform}: {e.reason}")
    raise Refused(f"{name} {version} {platform}: no answer")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Publish built DuckDB extensions to a kista channel.")
    ap.add_argument("--url", required=True, help="the kista's public URL")
    ap.add_argument("--tenant", required=True)
    ap.add_argument("--channel", required=True)
    ap.add_argument("--visibility", default="private", choices=["private", "public"])
    ap.add_argument("--api-key-env", default="KISTA_API_KEY", help="the environment variable holding an API key")
    ap.add_argument("--summary", help="a Markdown file to append the outcome to ($GITHUB_STEP_SUMMARY)")
    ap.add_argument("paths", nargs="+")
    a = ap.parse_args(argv)
    base = a.url.rstrip("/")
    found = files(a.paths)
    if not found:
        print("no .duckdb_extension found", file=sys.stderr)
        return 1
    token = os.environ.get(a.api_key_env, "")
    rows, failed = [], False
    for path in found:
        if is_wasm(path):
            rows.append((os.path.basename(path), "", "wasm", "skipped: kista does not take wasm builds yet"))
            continue
        try:
            name, version, platform = footer(path)
            if not token:
                token = oidc_token(f"{base}/{a.tenant}")
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
