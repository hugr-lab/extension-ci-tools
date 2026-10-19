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
| `scripts/kista_publish.py` | Publishes built extensions to a kista channel (standard-library Python). |
| `.github/workflows/_kista_publish.yml` | The reusable publication job. |
| `.github/workflows/kista.yml` | This fork's own CI for the above. |

**DuckDB's files.** The fork changes none of DuckDB's files. Merges from upstream conflict only
where both sides changed a file, so they stay simple.

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
    permissions: {id-token: write, contents: read}
    uses: hugr-lab/extension-ci-tools/.github/workflows/_kista_publish.yml@<commit>
    with:
      extension_name: myext
      ci_tools_version: <the same commit>        # the script the job runs
      # environment: release                     # when the publisher's binding names an environment
      kista_url: ${{ vars.KISTA_URL }}
      tenant: ${{ vars.KISTA_TENANT }}
      channel: ${{ vars.KISTA_CHANNEL }}
    secrets:
      KISTA_API_KEY: ${{ secrets.KISTA_API_KEY }}   # optional: without it, GitHub's OIDC token
```

**What the job does.**
- It uploads each platform's build as it is. kista checks it and signs it with the channel's key,
  so no signing key is needed in CI.
- It skips wasm builds while kista does not take them, and says so in the job summary.

**Authentication.** Without `KISTA_API_KEY`, the job uses GitHub's OIDC token for the audience
`<kista_url>/<tenant>`. Bind the calling workflow to a publisher in kista:

```text
kista admin publisher github add <tenant> <publisher> -owner-id <id> -repository-id <id> \
  -workflow <owner>/<repo>/.github/workflows/<file> -ref 'refs/tags/v*'
```

The token's `workflow_ref` names the calling workflow, not this reusable one. For a licensed
extension whose keys kista should record, a server administrator also marks the publisher
(`kista admin publisher license-keys <tenant> <publisher> on`, kista spec 0021).

**Pinning.** Pin the workflow to a commit, as for any third-party workflow, and give the same commit
as `ci_tools_version`: it is the publication script the job checks out.

**Environments.** A job that calls a reusable workflow cannot set `environment`. When the
publisher's GitHub binding names one (`-environment release`), pass it as the `environment` input.

**What is published.** Only `<extension_name>.duckdb_extension` files, of the artifacts named as the
distribution names them (`<name>-<duckdb version>-extension-<arch><artifact_postfix>`). The kista URL
must be https, and redirects are refused, so a token never goes to another host.

**Outside GitHub Actions**, the script runs on built files with an API key:

```text
KISTA_API_KEY=… python3 extension-ci-tools/scripts/kista_publish.py --url https://kista.example.org \
  --tenant acme --channel prod build/release/extension/myext/myext.duckdb_extension
```

## Upstream

The `main` branch is DuckDB's `main` with this fork's commits, merged from upstream when we take a
change. When DuckDB cuts a branch for a DuckDB line, the fork follows with the same name.
