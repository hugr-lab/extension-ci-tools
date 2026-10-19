#!/usr/bin/env bash
# sdk-test.sh <out>: builds DuckDB at kista/DUCKDB_PIN with the SDK's test extension (kista_demo),
# then the kista C++ SDK's own tests against it (kista spec 0022).
#
# Fills in <out>: src/ (DuckDB's checkout), build/ (its cmake tree), sdk/ (DuckDB's headers and
# libraries for a standalone SDK build: include/, third_party/, lib/), sdk-build/ (the SDK's tests),
# and extensions/kista_demo.duckdb_extension. ccache is used when present.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
kista=$(cd "$here/.." && pwd)
out=${1:?usage: sdk-test.sh <out>}
mkdir -p "$out"
out=$(cd "$out" && pwd)
# shellcheck source=/dev/null
source "$kista/DUCKDB_PIN"

src="$out/src"
if [ ! -d "$src/.git" ]; then
	git init -q "$src"
	git -C "$src" remote add origin "${DUCKDB_GIT_URL:-https://github.com/duckdb/duckdb}"
fi
if [ "$(git -C "$src" rev-parse HEAD 2>/dev/null || true)" != "$DUCKDB_COMMIT" ]; then
	git -C "$src" fetch -q --depth 1 origin "$DUCKDB_COMMIT"
	git -C "$src" checkout -q --detach FETCH_HEAD
fi
[ "$(git -C "$src" rev-parse HEAD)" = "$DUCKDB_COMMIT" ] || { echo "the checkout is not $DUCKDB_COMMIT" >&2; exit 1; }

openssl_root=""
if [ "$(uname)" = Darwin ] && command -v brew >/dev/null; then
	openssl_root=$(brew --prefix openssl@3)
fi
launcher=()
if command -v ccache >/dev/null; then
	launcher=(-DCMAKE_C_COMPILER_LAUNCHER=ccache -DCMAKE_CXX_COMPILER_LAUNCHER=ccache)
fi

build="$out/build"
cmake -S "$src" -B "$build" -G Ninja \
	-DCMAKE_BUILD_TYPE=Release \
	-DSTATICALLY_LINK_EXTENSIONS=core_functions \
	-DDUCKDB_EXTENSION_CONFIGS="$kista/sdk/cpp/test/extension/config.cmake" \
	-DBUILD_UNITTESTS=OFF -DBUILD_SHELL=OFF \
	${openssl_root:+-DOPENSSL_ROOT_DIR="$openssl_root"} \
	${launcher[@]+"${launcher[@]}"}
ninja -C "$build" duckdb kista_demo_loadable_extension

mkdir -p "$out/extensions"
cp "$(find "$build" -name kista_demo.duckdb_extension -type f | head -1)" "$out/extensions/"
lib=$(find "$build/src" -maxdepth 1 \( -name 'libduckdb.so' -o -name 'libduckdb.dylib' \) | head -1)
[ -n "$lib" ] || { echo "libduckdb not built" >&2; exit 1; }
rm -rf "$out/sdk"
mkdir -p "$out/sdk/lib"
cp -R "$src/src/include" "$out/sdk/include"
(cd "$src" && find third_party -type f \( -name '*.h' -o -name '*.hpp' -o -name '*.hh' -o -name '*.ipp' -o -name '*.inc' \) |
	while read -r f; do mkdir -p "$out/sdk/$(dirname "$f")" && cp "$f" "$out/sdk/$f"; done)
cp "$build/third_party/mbedtls/libduckdb_mbedtls.a" "$lib" "$out/sdk/lib/"

cmake -S "$kista/sdk/cpp" -B "$out/sdk-build" -G Ninja -DKISTA_DUCKDB_DEPS="$out/sdk" ${launcher[@]+"${launcher[@]}"}
ninja -C "$out/sdk-build"
ctest --test-dir "$out/sdk-build" --output-on-failure
