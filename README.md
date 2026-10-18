# kista SDK for C++ DuckDB extensions

An extension embeds this library to check its licence and to report how it is used (spec 0012,
`specs/0012-licensing/spec.md`). Apache-2.0, like the rest of this repository.

**Status: part 1.** The licence verifier is here: `include/kista/license.hpp`.

- `kista::Verify(token, keys, ext, version, now)` reads a licence by every rule of the spec: the
  compact JWS, strict JSON, the claims, the key and the RS256 signature.
- It returns the status (`valid`, `grace`, `expired`, `not_yet_valid`, `not_covered`, `invalid`),
  the rule an invalid licence breaks, and the claims (plan, limits, expiry, holder).
- It gives the same answer as kista's Go verifier (`internal/license`) on every test vector.

The DuckDB side comes in part 2: `License::Register`, the licence fetched from the repository and
kept beside the extension, `Check()`, the `<name>_license()` table function, and usage reports.

## Building

From an extension built with DuckDB's CMake (the extension template, or DuckDB's own tree):

```cmake
add_subdirectory(path/to/sdk/cpp kista_sdk)
target_link_libraries(my_extension_loadable_extension kista_sdk)
```

The library uses DuckDB's bundled mbedtls (`duckdb_mbedtls`) for SHA-256 and the signature, and
DuckDB itself; nothing else.

## Trust

The keys a licence must be signed with are compiled in (`src/keys.cpp`): the issuer's, never a
run-time setting.

- **Issuer keys.** Enterest's keys are added there when they are published. Until then a build
  trusts none, and every licence is `invalid` (`kid_untrusted`).
- **Test key.** The `kista_sdk_testkey` library also trusts the licence vectors' test-only key
  (`internal/license/testdata/test-only-2048.pem`, whose private half is in this repository). A
  test extension links it instead of `kista_sdk`, and `go run ./internal/license/vectorgen sign
  -claims <file>` signs licences for it. No option puts the test key into `kista_sdk`;
  `kista::TrustsTestKey()` lets a release build assert it.
- **Callers** verify with `kista::Keys::Trusted()` and the extension's own version.

## Tests

```bash
make e2e-duckdb   # DuckDB at e2e/DUCKDB_PIN; also fills e2e/.build/sdk
make sdk-test     # every licence vector through the C++ verifier; kista_sdk trusts no test key
```
