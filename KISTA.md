# hugr-lab's extension-ci-tools: the kista developer kit

This is a fork of [duckdb/extension-ci-tools](https://github.com/duckdb/extension-ci-tools).
Everything of DuckDB's works as upstream. The fork adds what an extension needs to be licensed with
[kista](https://github.com/hugr-lab/duckdb-extension-repository) and to be published to a kista from
CI. The design is kista's spec 0022 (`specs/0022-developer-kit/spec.md`).

## Which extensions use the fork

- **An open extension** (MIT, Apache, also in DuckDB's community repository) builds with DuckDB's
  own `duckdb/extension-ci-tools`, as the community builds it. The community's build puts DuckDB's
  ci-tools over an extension's `extension-ci-tools` directory, so an open extension depends on
  nothing here for its build.
  - It uses only this fork's publication workflow, after its build.
- **A licensed extension** has this fork as its `extension-ci-tools` submodule. It builds with the
  kista C++ SDK and carries its licence keys.
  - It is not built by the community.
  - Enterest builds it from git with the same Makefile.

[hugr-lab/extension-template](https://github.com/hugr-lab/extension-template) sets up either kind
(`./bootstrap.sh <name> [--licensed]`).

## What the fork adds

| Path | What |
| --- | --- |
| `kista/sdk/cpp` | The kista C++ SDK: licences and usage reports. See its [README](kista/sdk/cpp/README.md). |
| `kista/sdk/cpp/VERSION` | The SDK's version, tagged `sdk-v<version>`. |
| `kista/sdk/cpp/test/vectors` | A copy of kista's licence vectors, from the kista commit in `FROM`. |
| `kista/DUCKDB_PIN` | The DuckDB commit the SDK is tested against. |
| `kista/scripts/sdk-test.sh` | Builds DuckDB at the pin with the SDK's test extension, then runs the SDK's tests. |
| `kista/scripts/kista-vectors.sh` | Copies or checks the vectors against a kista checkout. |
| `makefiles/kista.Makefile` | Passes `KISTA_LICENSE_KEYS` to the extension's CMake. |
| `scripts/kista_publish.py` | Publishes built extensions to a kista channel, each request signed with the publisher's SSH key (standard-library Python and OpenSSH). |
| `.github/workflows/_kista_publish.yml` | The reusable publication job. |
| `.github/workflows/kista.yml` | This fork's own CI for the above. |
| `.github/workflows/_extension_distribution.yml` | Inputs for Enterest's builders (below). |
| `scripts/ci_phase.py` | Writes the licence keys of `license_keys` and names them in `KISTA_LICENSE_KEYS`, in the Linux builds' container too. |

**DuckDB's files.** The fork changes two of DuckDB's files, in blocks marked `kista`: the
distribution workflow (its inputs and the extension's checkout) and `scripts/ci_phase.py`. Merges
from upstream conflict only where both sides changed those blocks, so they stay simple.

## Building for Enterest

Enterest builds an extension's version from its repository with the distribution workflow (its
build repository calls it; Enterest's spec 0003). Two inputs serve it:

- **`override_repository_url`**: the repository by its https git URL, on any git host, checked out
  at `override_ref` (a commit) with its submodules. It takes the place of `override_repository`,
  which reaches GitHub only.
- **`license_keys`**: the licence keys to build with, as one to four PEM public keys. They are
  written to `kista-license-keys/` beside the sources and passed as `KISTA_LICENSE_KEYS`, so the
  build takes them, not the committed `license-key.pem`. Anything else in the input fails the
  build.
- **`restore_cache: false`**: no cache is restored (ccache, Go's modules), while ccache itself is
  still installed (the native builds call it). A build of untrusted code could write a cache entry
  that another build would then read, so each starts clean (with `save_cache: false`).
- **`timeout_minutes`**: a build job's longest run (GitHub's default, 360, otherwise).
- **`duckdb_version` as a full commit**: a development build of DuckDB (Enterest's builds for the
  next release). DuckDB is checked out at the commit and names the build itself (`vX.Y.0-devN`, its
  source id, the commit's first 10 hex digits, in the extension's footer, as a DuckDB built from
  that commit expects), since `DUCKDB_VERSION` is left empty for its CMake; the artifact is named
  by the commit, `<extension>-<commit>-extension-<platform>`.
- **`duckdb_commit`** (upstream has the same input; the fork uses it this way): the commit DuckDB
  is checked out at, beside a release's tag in `duckdb_version` (which still names the version): a
  tag in the extension's `duckdb` submodule cannot redirect what is built. Given without
  `duckdb_version`, the version is the highest version tag at the commit
  (`vX.Y.Z[-alphaN|-rcN|-devN]`); a commit without one is a development build, as above.

The platform lists (`exclude_archs`, `opt_in_archs`) reach the matrix step's shell as variables,
since a caller may pass values a developer wrote.

## The build contract

A licensed extension builds anywhere (its CI, Enterest's builders, a laptop) with:

```text
git clone --recurse-submodules <repo> && cd <repo>
make release KISTA_LICENSE_KEYS='/path/key1.pem;/path/key2.pem'
make test
```

- `KISTA_LICENSE_KEYS` is optional: without it (or empty), the extension takes its committed
  `license-key.pem`. `kista.Makefile` always passes it, so a build directory configured with keys
  before does not keep them.
- The extension's `Makefile` includes `makefiles/kista.Makefile` after `duckdb_extension.Makefile`.
- Its CMake passes `${KISTA_LICENSE_KEYS}` to `kista_sdk_license_keys`.
- Enterest sets the keys to the extension's registered ones, then reads them back from the binary.

## Publishing from GitHub Actions

```yaml
jobs:
  build:   # an open extension: DuckDB's own build
    uses: duckdb/extension-ci-tools/.github/workflows/_extension_distribution.yml@<commit>
    with: {extension_name: myext, ci_tools_version: <the same commit>}
  # build:   a licensed extension: this fork's build, which must also check this fork out as
  #          extension-ci-tools (the workflow's default is DuckDB's, which has no SDK)
  #   uses: hugr-lab/extension-ci-tools/.github/workflows/_extension_distribution.yml@<commit>
  #   with: {extension_name: myext, ci_tools_version: <the same commit>,
  #          override_ci_tools_repository: hugr-lab/extension-ci-tools}
  kista:
    needs: build
    if: startsWith(github.ref, 'refs/tags/v')
    uses: hugr-lab/extension-ci-tools/.github/workflows/_kista_publish.yml@<commit>
    with:
      extension_name: myext
      ci_tools_version: <the same commit>        # the script the job runs
      environment: release                       # whose secret holds the key, behind its rules
      kista_url: ${{ vars.KISTA_URL }}
      tenant: ${{ vars.KISTA_TENANT }}
      channel: ${{ vars.KISTA_CHANNEL }}
    secrets:
      KISTA_PUBLISHER_KEY: ${{ secrets.KISTA_PUBLISHER_KEY }}
```

**What the job does.**
- It checks the key first (a signed `whoami`), so a key kista does not know fails before any upload.
- It uploads each platform's build as it is. kista checks it and signs it with the channel's key,
  so no signing key is needed in CI.
- It skips wasm builds while kista does not take them, and says so in the job summary.

**The publisher key** (kista spec 0023). Each request is signed with the publisher's SSH key, like
an SSH key on GitHub: kista holds only the public half. Once, for a repository:

```text
# the developer: a key for CI, without a passphrase, outside the repository
cd "$(mktemp -d)" && ssh-keygen -t ed25519 -N '' -C myext-ci -f publisher_key

# kista's administrator: the publisher, what it may publish, and its key
kista admin publisher add <tenant> <publisher>
kista admin grant add <tenant> -principal publisher:<publisher> -verb publish -channel <channel> -extension myext
kista admin publisher key add <tenant> <publisher> publisher_key.pub -expires 365d

# the developer: check it, then keep the private half as an environment's secret and delete the file
KISTA_PUBLISHER_KEY=publisher_key python3 <this repository>/scripts/kista_publish.py --url <kista URL> --tenant <tenant> --channel <channel> --check
# an environment only v* tags may deploy to: a workflow pushed on a branch cannot read its secret
gh api -X PUT repos/<owner>/<repo>/environments/release --input - \
  <<< '{"deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":true}}'
gh api -X POST repos/<owner>/<repo>/environments/release/deployment-branch-policies -f name='v*' -f type=tag
gh secret set KISTA_PUBLISHER_KEY --env release < publisher_key
gh variable set KISTA_URL --body <kista URL>; gh variable set KISTA_TENANT --body <tenant>; gh variable set KISTA_CHANNEL --body <channel>
rm publisher_key
```

`--check` signs a `whoami`: it fails on a key kista does not know, and, with `--channel`, on a
publisher without a `publish` grant there. To replace the key, register the new one, replace the
secret, and remove the old one in kista (`kista admin publisher key list|remove`).

For a licensed extension whose keys kista should record, a server administrator marks the publisher
(`kista admin publisher license-keys <tenant> <publisher> on`, kista spec 0021) before registering
its key.

**Pinning.** Pin the workflow to a commit, as for any third-party workflow, and give the same commit
as `ci_tools_version`: it is the publication script the job checks out and hands the key to, so
never a branch or a tag that can move.

**Environments.** A job that calls a reusable workflow cannot set `environment`: pass it as the
`environment` input. Keep `KISTA_PUBLISHER_KEY` an environment secret, so the environment's
protection rules (only `v*` tags, required reviewers) gate who can publish, and protect `v*` tags
with a ruleset. Without an environment, or with one that allows any branch, any workflow of the
repository can read the key; the job warns when there is none.

**What is published.** Only `<extension_name>.duckdb_extension` files, of the artifacts named as the
distribution names them (`<name>-<duckdb version>-extension-<arch><artifact_postfix>`). The kista URL
must be https, and redirects are refused.

**Any other CI** runs the script on built files: it needs only Python 3 and OpenSSH 8.1 or later, on
the CI host (DuckDB's build containers may have an older OpenSSH). The key is in the environment
variable `KISTA_PUBLISHER_KEY` (`--key-env` names another): the key itself, its base64 (GitLab's
masked variables hold no newlines), or a file holding it (a GitLab File variable is one). The script
copies it to a private file of its own, in `RUNNER_TEMP` when set, and removes it at the end.

```text
python3 extension-ci-tools/scripts/kista_publish.py --url https://kista.example.org --tenant acme --check
python3 extension-ci-tools/scripts/kista_publish.py --url https://kista.example.org \
  --tenant acme --channel prod build/release/extension/myext/myext.duckdb_extension
```

`--dry-run` prints the statements it would sign and the key's fingerprint, and sends nothing.

## Upstream

The `main` branch is DuckDB's `main` with this fork's commits, merged from upstream when we take a
change. When DuckDB cuts a branch for a DuckDB line, the fork follows with the same name.
