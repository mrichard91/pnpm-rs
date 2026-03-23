# pnpm-rs

A safety-first, limited **pure Rust** pnpm replacement. This build uses the npm registry directly and installs packages into a flat `node_modules` layout. It never executes lifecycle scripts, never creates `node_modules/.bin` shims, and prints what would have been run instead. Compatible with a small, intentional subset of pnpm (init/add/install/update/remove/list, basic dependency types, and a minimal `pnpm-lock.yaml`). Existing pnpm workspaces are supported in read-only mode for inspection commands; mutating commands fail closed inside workspaces.

## Goals

- Safe parsing of config/manifest/lock inputs.
- Install packages from the npm registry (default registry only).
- Generate a minimal `pnpm-lock.yaml` for the supported feature set.
- Never execute install scripts (preinstall/install/postinstall/prepare). Instead, print a notice.
- Never expose package binaries via `node_modules/.bin`.
- Reject exotic dependency sources (git, file, ssh, workspace, etc.).
- Provide optional security scanning of installed packages and lockfile metadata.

## Non-goals

- Running lifecycle scripts.
- Supporting exotic protocol dependencies.
- Full compatibility with all pnpm features (only supported subset is implemented).

## Usage

Build:

```
cargo build
```

Run:

```
./target/debug/pnpm-rs init
./target/debug/pnpm-rs add react@19
./target/debug/pnpm-rs install
./target/debug/pnpm-rs remove react
./target/debug/pnpm-rs list
./target/debug/pnpm-rs security-scan
```

Version:

```
./target/debug/pnpm-rs -v
./target/debug/pnpm-rs --version
```

Unsupported commands are accepted and ignored with a notice.

Containerized safety check:

```bash
make safety-check @teale.io/eslin1234
make safety-check react@19 OLDER_THAN_YEARS=3
make safety-check react@19 NO_DEPS=1
make safety-check react@19 NO_DEPS=1 INSPECT=1
make safety-check react@19 NO_DEPS=1 OUT_DIR=artifacts
make safety-check react@19 YARA=rules.yar
make safety-check '@opengov/*' YARA=rules.yar NO_DEPS=1 OUT_DIR=artifacts
make safety-check PACKAGE='@opengov/*' YARA=rules.yar NO_DEPS=1
```

The `safety-check` target builds a Docker image containing `pnpm-rs` and `pnpm-rs-pre-scan`, then runs the scan inside a constrained container with a read-only root filesystem, dropped capabilities, and a tmpfs-backed `/tmp`.
The binaries are built inside the Docker image, so the scan path does not depend on host-compiled artifacts.
Set `NO_DEPS=1` for a faster fetch-only analysis of just the named package; transitive dependencies are not downloaded in that mode.
For scope wildcard scans such as `@scope/*`, `NO_DEPS=1` is required and you should quote the package pattern or pass it as `PACKAGE='@scope/*'`.
Set `INSPECT=1` to drop into `/bin/sh` inside the same temp project after the scan completes so you can inspect `package.json`, extracted files, and `node_modules` before the temp directory is cleaned up.
Set `OUT_DIR=artifacts` to copy the full temporary analysis project to a host directory after the run completes. Saved projects are written under a timestamped subdirectory such as `artifacts/scan-react-19-<unix-seconds>/`.
When a wildcard scan expands to multiple packages, `pnpm-rs-pre-scan` prints a final aggregate synopsis with total files scanned, YARA match counts, and the packages/files that matched.

## Compatibility (intentional subset)

Supported commands and flags:

- `init` (supports `--name`)
- `add <pkg...>`
- `add <pkg...> --no-deps` (isolated analysis projects only; skips transitive dependency download)
- `install`
- `update [pkg...]` (no args = update from manifest)
- `remove <pkg...>`
- `list` (supports `--json`, `--long`, `--parseable`, `--prod`, `--dev`, `--optional`, `--only`, `--global`, `--recursive`, `--depth` and package filters)
- `security-scan` (supports `--older-than-years`, `--yara`)
- `pnpm-rs-pre-scan <pkg>` (helper binary; supports `--older-than-years`, `--yara`, `--no-deps`, `--inspect-shell`, `--out-dir`)
- `pnpm-rs-pre-scan '@scope/*' --no-deps` (expands public npm scope packages through the registry metadata mirror and scans each package separately)

Intentionally left out:

- pnpm store and symlinked `node_modules` layout.
- Workspace mutation, global installs, and the full `pnpm` CLI surface.
- Lifecycle scripts (preinstall/install/postinstall/prepare).
- Package binary shims in `node_modules/.bin`.
- Non-registry dependency protocols (git, file, link, workspace, etc.).
- Existing pnpm workspaces can be inspected via `list`, `why`, and `security-scan`, but `add`/`install`/`update`/`remove` are intentionally blocked there in safe mode.
- Flags accepted but only partially implemented: `list --global` prints a notice and falls back to local; `list --recursive` traverses pnpm workspaces for read-only inspection.

## Security scanning

`pnpm-rs` includes an offline security inspection mode that scans the lockfile, installed packages, and workspace importers.

```
./target/debug/pnpm-rs security-scan
./target/debug/pnpm-rs security-scan --older-than-years=3
./target/debug/pnpm-rs security-scan --yara rules.yar
```

Checks include:

- Workspace importer manifests, including local scripts, `bin`, and dependency specs.
- Lifecycle scripts defined in package.json (preinstall/install/postinstall/prepare), including invoked-command analysis, likely actions, and local script source signals for common file/network/process behaviors.
- Packages that expose binaries via `bin`.
- Exotic dependency specs inside package.json (git/file/link/workspace/etc.).
- Registry metadata issues (missing version entries or publish timestamps).
- Versions older than the configurable age cutoff (default 5 years).
- Optional YARA scanning across installed package files and workspace source trees (excluding `node_modules`, `.git`, and `target`).

There is also a helper that scans a single package in a temporary project:

```
./target/debug/pnpm-rs-pre-scan react@19
./target/debug/pnpm-rs-pre-scan react@19 --no-deps
./target/debug/pnpm-rs-pre-scan react@19 --inspect-shell
./target/debug/pnpm-rs-pre-scan react@19 --out-dir ./artifacts
./target/debug/pnpm-rs-pre-scan react@19 --older-than-years=3 --yara rules.yar
./target/debug/pnpm-rs-pre-scan '@opengov/*' --no-deps --yara rules.yar --out-dir ./artifacts
```

`--no-deps` is intended for isolated analysis projects and the containerized safety-check flow. It installs only the explicitly requested package and intentionally does not attempt to keep an existing multi-package project consistent.
`--inspect-shell` opens an interactive shell in the temporary analysis project after the install and scan steps complete. Exiting the shell cleans up that temp directory.
`--out-dir` copies the full temporary analysis project, including the installed `node_modules` tree and symlinks, into a timestamped directory under the requested path before cleanup.
`@scope/*` scans enumerate exact package names from the public npm CouchDB metadata mirror, then run the normal temp-project scan flow once per package. That mode requires `--no-deps`, and `--inspect-shell` is only allowed when the wildcard expands to exactly one package.
Multi-package wildcard scans end with an aggregate summary that includes total YARA file counts, total rule matches, and a concise list of matched packages and files.

Bulk scan examples:

```bash
make safety-check '@opengov/*' NO_DEPS=1
make safety-check '@opengov/*' YARA=test.yara NO_DEPS=1
make safety-check '@opengov/*' YARA=test.yara NO_DEPS=1 OUT_DIR=artifacts
./target/debug/pnpm-rs-pre-scan '@opengov/*' --no-deps --yara test.yara
```

Recommended pattern for large namespace sweeps:

1. Start with `NO_DEPS=1` so each package is inspected in isolation.
2. Add `YARA=...` only when you want file-content scanning.
3. Add `OUT_DIR=artifacts` when you want to preserve suspicious packages for offline inspection.
4. Quote `@scope/*` or pass it as `PACKAGE='@scope/*'` to avoid accidental shell glob expansion.

## Tests

```
cargo test
```
