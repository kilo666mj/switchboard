# Review archives

Build review archives from the exact audited source candidate with Go 1.26 or
newer and Python 3. These commands only create local files; they do not upload,
tag, push or change repository visibility.

```sh
python3 scripts/build-release.py --version 0.1.0-review --output dist/review
python3 scripts/smoke-release.py dist/review --version 0.1.0-review
```

The output directory must be new. By default the builder creates Linux amd64
and arm64 tar archives plus `SHA256SUMS`. Use `--target linux/amd64` or
`--target linux/arm64` to select a target. Each archive contains exactly:

- `switchboard`: a static Go binary with the candidate version in MCP server info.
- `modules/switchboard-module-log-watcher`: the static Log Watcher MCP module
  with the same candidate version.
- `README.md` and the project's MIT `LICENSE`.
- `THIRD_PARTY_NOTICES.txt`: verbatim notices from the target's compiled module
  graph and Go toolchain, including nested notices conservatively.
- `DEPENDENCIES.json`: pinned module versions/checksums, target and notice hashes.

Builds omit VCS metadata and source paths, and use fixed archive timestamps and
neutral owners. Compare independent builds made from the same source with the
same toolchain. The smoke verifier checks archive hashes, exact entries,
metadata, both executable permissions and each notice against its recorded hash.
It also starts the native gateway and module binaries, checks their embedded
versions via MCP initialization, and retrieves both tool catalogs. The gateway
uses a temporary empty stdio profile; the module receives a non-listening test
URL and is not asked to call it. Neither contacts an upstream service.

The smoke verifier needs an archive for its native Linux amd64 or arm64 host.
Cross-compilation and archive inspection do not prove native arm64 execution.
The builder uses read-only module resolution and rejects replaced dependencies,
missing module versions/checksums, missing notices, symlinks and invalid text.
If your OS packages Go's license outside GOROOT, supply its installed directory:

```sh
python3 scripts/build-release.py --version 0.1.0-review --output dist/review \
  --go-notices /usr/share/licenses/golang
```

This collects attribution; it is not a completed license compatibility review.
Check obligations against the exact final artifacts. Upstream copyright and
notice text must remain intact even when it contains attribution email addresses;
review those separately from private contributor metadata and operational data.

These archives contain the Go gateway and its reviewed Log Watcher module. They
do not bundle the pi extension, its npm dependencies, deployment configuration,
capability manifests or operator state.
The pi extension has a separate source review workflow below; licensing acceptance
remains required before distribution.
Follow the [privacy release gate](privacy-release.md) for all publication refs and
coordinate the release with Agent Relay. Hosted CI, final candidate review,
licensing acceptance and native target verification remain release requirements.


## Pi source review bundle

Use Node.js 22.19.0 or newer, npm and Python 3:

```sh
python3 scripts/build-pi-review.py --output dist/pi-review
python3 scripts/smoke-pi-review.py dist/pi-review
```

The builder uses a new temporary `npm ci --omit=dev --ignore-scripts` installation
and the checked-in lockfile to collect all runtime dependency versions, integrity
values, declared licenses and verbatim notice files. Missing notices, changed
versions, linked packages and incomplete lock entries fail the build for review.
No lifecycle scripts run and no installed workspace modules are trusted. Package
installation requires access to the locked registry dependencies or a populated
npm cache.

The source archive contains exactly the extension, package metadata, lockfile,
standalone README, project MIT license, dependency inventory and notices. It does
not contain node_modules, local configuration, credentials or development tests.
Users install the runtime dependencies from the included lockfile. The verifier
checks every locked runtime package against the inventory, validates notice
hashes and neutral archive metadata, then installs the extracted bundle in a new
directory and imports its MCP and HTTP dependencies. This proves bundle integrity
and dependency installation, not compatibility with every installed pi host.

The pi package remains private; these commands do not publish it to npm. A
separate review must decide license compatibility and any further obligations.

The repository's opt-in `clients/pi/host-smoke.mjs` additionally checks tool
registration and refresh in an installed pi CLI using an isolated RPC session and
local HTTPS fixture. See the [pi README](../clients/pi/README.md). With `--execute`, it also verifies native tool execution and RPC approval
denial/acceptance through a synthetic model. A separate installed pi 0.84.4 TUI
check passed read, No, Yes and Escape flows with synthetic fixtures; see the pi
README. Relay's separate opt-in `TestSwitchboardRelayPiTUIWorkflow` now also
passes the complete task flow with native terminal approvals and independent
identity/audit checks. Public deployment remains unverified.

## Dependency security

The dependency-security workflow checks Go code with pinned `govulncheck` v1.7.0
and installs the pi lockfile with lifecycle scripts disabled before running
`npm audit --audit-level=low`. It checks runtime and development dependencies.
The workflow runs on pushes, pull requests, manual dispatch and weekly schedules,
with read-only repository permissions and immutable action references.

Local Go and npm checks reported no vulnerabilities on 6 September 2026. These
are dated advisory-database results; recheck the final candidate before release.
Hosted workflow execution remains unverified until these files are reviewed and
available on GitHub. A clean scan does not replace application security review.

## Continuous integration

The CI workflow runs Go race tests, vet, formatting checks, Python release-tool
tests and a source privacy scan. It builds both Linux gateway archives and
checks native MCP startup from the extracted archive. The pi jobs run the
synthetic HTTPS adapter tests and build and install the source bundle on Node
22.19.0 (the minimum supported version) and Node 24. These fixtures require no
operator credentials or real model provider.

These checks run on pushes, pull requests and manual dispatch with read-only
repository permissions. They do not publish artifacts or repositories. Hosted
execution, real-provider/deployed client access, native arm64 execution and final release
review remain separate requirements.

## Inline source attribution

The Go archive builder also scans the selected Go source files for comment groups
containing copyright, license, permission, redistribution or public-domain text.
It uses Go's lexer to distinguish comments from string literals and preserves
original comment bytes, including line endings. The target package graph selects
the inputs; the helper runs on the build host, including for cross-compilation.
Collected groups appear as `SELECTED_GO_SOURCE_NOTICES.txt` sections inside
`THIRD_PARTY_NOTICES.txt`, with hashes in `DEPENDENCIES.json`.

This covers attribution carried in generated Go files in addition to standalone
license files. It is conservative evidence, not an automatic license classifier
or clearance. It does not determine which compiled functions survive linking,
or trace generated code back to all upstream inputs.
The helper's tests cover string-literal exclusion, complete comment groups,
original line endings and malformed-input rejection.

## Native architecture CI

The Go CI jobs use a two-runner matrix: `ubuntu-24.04` for amd64 and
`ubuntu-24.04-arm` for arm64, both listed in the
[GitHub runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).
Each job verifies `GOHOSTARCH`, runs the source checks on that architecture,
builds only its matching release archive, and executes the extracted binary
through the archive smoke verifier. Neither job uses emulation.

This prepares native acceptance for both release targets. Workflow parsing and
the amd64 archive command have local validation; the arm64 job still needs a
successful hosted run against the exact publication candidate. Merely adding
the matrix does not satisfy that release requirement.

## Assembly and header attribution

The selected `SFiles` and `HFiles` from each target's Go package graph also pass
through a C-style comment lexer. It skips quoted literals, preserves complete
adjacent comment groups and original line endings, and records license-bearing
groups as `SELECTED_ASSEMBLY_HEADER_NOTICES.txt` with hashes in the inventory.
Malformed comments, symlinks and invalid UTF-8 fail for review.

This closes a verified omission in the earlier amd64 candidates: Go runtime
`memmove_amd64.s` contains a separate MIT notice naming Lucent Technologies and
Vita Nuova, absent verbatim from the earlier combined notices. Preserve that
complete notice with the binary. Earlier binary candidates are superseded and
must be rebuilt; a checksum check alone did not detect the missing attribution.
The client source bundles do not contain that Go runtime code.
