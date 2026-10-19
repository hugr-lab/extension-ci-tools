# kista SDK for C++ DuckDB extensions

An extension embeds this library to check its licence and to report how it is used (spec 0012,
`specs/0012-licensing/spec.md`). Apache-2.0, like the rest of this repository. Written against
DuckDB at `e2e/DUCKDB_PIN`; tested on Linux and macOS.

## Using it

In the extension's Load:

```cpp
#include "kista/kista.hpp"

kista::License::Register(loader, "myext");
```

Where a licence matters (a table function's bind, a scalar function's first call):

```cpp
auto lic = kista::License::Get(context, "myext");    // cached; never throws for status
lic.Check();                                          // throws unless valid or grace: the one-line gate
lic.Status();                                         // kista::Status::Valid, Grace, Expired, Missing, …
lic.Plan();                                           // "pro"
lic.Limit<int64_t>("max_attached_sources", 1);        // the developer's controls, with a default
kista::Usage::Send(context, "myext", "attach", {{"sources", 3}});       // now; true when taken
kista::Usage::SendAsync(context, "myext", "attach", {{"sources", 3}});  // from a thread of its own
```

- **`Check()`** throws a DuckDB `PermissionException` unless the status is `valid` or `grace`. The
  message names the extension, the status and what to do. In `grace` it also logs a warning, once.
- **`Limit<T>()` and `Plan()`** answer the default and `""` unless the licence is valid or in
  grace. What each status allows (refuse, degrade, warn) is the extension's decision: the SDK never
  stops DuckDB by itself.
- **`myext_license()`** is a table function `Register` adds: status, plan, holder, holder id,
  licence id, issuer, issue and expiry times, end of grace, source (`file` or `repository`), limits
  (JSON) and a message saying why. **`myext_license_refresh()`** fetches the licence again now and
  returns the same row.
- **Usage** goes to the repository the extension was installed from
  (`<prefix>/-/usage/myext`), with the http secret matching that URL (normally the one `INSTALL`
  used). One call is one report of one
  event (a count of 1) with its counters, under the licence status of the moment.
  - **`Usage::Send`** posts with the caller's context, with a 5-second connect and stall timeout and no retries, and
    waits for the answer. It answers `true` when the repository answered 2xx. kista answers `204`
    to reports it drops silently too (an unserved version, usage turned off), so `true` means
    delivered, not counted. Call it from the thread running the context's query (a function's bind
    or execution) or with no query running, never from a `ClientContextState` callback such as
    `QueryEnd`: DuckDB holds the context's lock there. Use `SendAsync` there.
  - **`Usage::SendAsync`** posts from a thread of its own and returns at once. Its connection sees
    the http secret and global settings, not the caller's session settings (a session's
    `ca_cert_file`, say), nor a connection- or transaction-scoped secret. With 16 of the extension's reports on their way in the process, it drops
    the new one, silently. A report keeps the database open until it is sent (a database closed
    meanwhile closes after it); at exit the process waits up to 6 seconds for them.
  - **The extension decides** what to report, when, how often, whether to aggregate first, and
    what to do when a report fails. The SDK keeps nothing, retries nothing and reports nothing by
    itself: installs and downloads are counted by kista already.
  - **Rules.** Event and counter names are `[a-z][a-z0-9_.]{0,63}`, at most 16 counters, values
    within 0..2^53-1. A report that breaks them is not sent. Nothing is sent when `Register` was
    not called, the extension has no version, or the extension was not installed from an http repository.
  - **Status.** It is what the SDK knows at the time. After a load whose fetch was deferred (see
    below), it settles at the first `License::Get`, so call `Get` first when the status matters.
  - **Users.** kista counts a principal as a user on a day its extension sent a report, so an
    extension that reports nothing has no users there.

## Where the licence comes from

When the extension finishes loading:

1. **The file** `myext.kista-license` beside the extension's module. This is also how an
   air-gapped user without a kista places one.
2. **The repository** the extension was installed from (`INSTALL myext FROM <repository>`). The
   SDK asks `<prefix>/-/licenses/myext` with the http secret `INSTALL` used, conditionally
   (`If-None-Match`): an unchanged licence costs a `304`. A new licence is used and written beside
   the module, unless it would replace a usable licence with one that is not usable or is older.
   A failure or a `404` keeps the file.
   - **Session settings.** The load hook has no user session, so it fetches with a connection of
     its own. That connection sees global settings and the secret, not session-only settings such
     as a session's `ca_cert_file`. Such a fetch is made again on the first `Get`, with the user's
     session.
   - **Renewal.** `Get` fetches again at most hourly while there is no usable licence or the
     licence is past half its lifetime, and `myext_license_refresh()` fetches at once.

## Building

From an extension built with DuckDB's CMake (the extension template, or DuckDB's own tree):

```cmake
add_subdirectory(path/to/sdk/cpp kista_sdk)
target_link_libraries(myext_loadable_extension kista_sdk)
target_link_libraries(myext_extension kista_sdk)
kista_sdk_license_keys(myext_loadable_extension ${CMAKE_CURRENT_SOURCE_DIR}/license-key.pem)
kista_sdk_license_keys(myext_extension          ${CMAKE_CURRENT_SOURCE_DIR}/license-key.pem)
```

`kista_sdk_license_keys` names the target's licence keys (below). The library uses DuckDB's
bundled mbedtls (`duckdb_mbedtls`) for SHA-256 and the signature, and DuckDB itself; nothing else.
`test/extension` is a complete example: `kista_demo`, which the e2e cases run.

## Trust

The SDK holds no keys: each build names the keys its licences are signed with (spec 0021,
`specs/0021-licence-keys/spec.md`), and trusts those alone, never a run-time setting.

- **`kista_sdk_license_keys(<target> <pem>…)`** takes one to four public keys, each a file as
  `openssl pkey -pubout` writes it: one `PUBLIC KEY` PEM block, 64-column base64. Take them from the
  issuer that signs the extension's licences. It writes them into the target as the **key block**,
  which the SDK reads at run time and kista reads from the binary (`kista ext inspect` prints them).
  - Call it once for each target that links `kista_sdk`. A target that links `kista_sdk` without
    it does not link, with an error naming `kista_sdk_license_keys`. The one exception is a macOS
    build with `-undefined dynamic_lookup` (DuckDB's non-static extension builds), which links and
    then fails to load, with the same name.
  - The block and the SDK are hidden in the module: an extension trusts its own block, never
    another loaded extension's.
  - Configuring checks the files' form (CRLF line ends are normalised) and refuses a key given
    twice. The SDK and kista check the keys themselves: RSA-2048, `e = 65537`. A key that fails is
    skipped by the SDK, and makes kista read the block as malformed (`kista ext inspect` says so).
  - Several extensions in one tree each name their own keys. Two licensed extensions cannot be
    linked statically into one DuckDB: the link fails on the duplicate symbol.
  - Changing a key means a new build, so a new version: the licences of the old key stay with the
    old version's binaries.
- **Test key.** The `kista_sdk_testkey` library is the key block of the licence vectors' test-only
  key (`test/keys/test-only-2048.pub.pem`; its private half is
  `internal/license/testdata/test-only-2048.pem`, in this repository).
  - A test extension links `kista_sdk_testkey` instead of calling `kista_sdk_license_keys`, as
    `kista_demo` does.
  - `go run ./internal/license/vectorgen sign -claims <file>` signs licences for it.
  - `kista::TrustsTestKey()` lets a release build assert that it does not trust the test key, and
    `Register` logs a warning when it does.

## Tests

```bash
make e2e-duckdb   # DuckDB at e2e/DUCKDB_PIN, kista_demo with it; fills e2e/.build/sdk
make sdk-test     # every licence vector through the C++ verifier; key blocks and their checks
make e2e          # kista_demo against kista serve (e2e/sdk_test.go), with the rest of the e2e
```
