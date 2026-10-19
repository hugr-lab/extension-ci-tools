#!/usr/bin/env bash
# kista-vectors.sh <kista checkout> [check]: copies kista's licence vectors and test key
# (internal/license/testdata) into the SDK's test/vectors, recording kista's commit in FROM; with
# "check", only compares them and fails on a difference (kista spec 0022: kista's copy is the source).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
dst="$here/../sdk/cpp/test/vectors"
k=${1:?usage: kista-vectors.sh <kista checkout> [check]}
files=(vectors.json test-only-2048.pem)
if [ "${2:-}" = check ]; then
	for f in "${files[@]}"; do
		cmp -s "$k/internal/license/testdata/$f" "$dst/$f" || { echo "test/vectors/$f differs from kista's" >&2; exit 1; }
	done
	echo "the vectors are kista's ($(cat "$dst/FROM"))"
	exit 0
fi
for f in "${files[@]}"; do cp "$k/internal/license/testdata/$f" "$dst/$f"; done
git -C "$k" rev-parse HEAD > "$dst/FROM"
echo "copied the vectors from kista $(cat "$dst/FROM")"
