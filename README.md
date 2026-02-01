# pnpm-rs

A safety-first, limited **pure Rust** pnpm replacement. This build uses the npm registry directly and installs packages into a flat `node_modules` layout. It never executes lifecycle scripts and prints what would have been run instead. Compatible with a small, intentional subset of pnpm (init/add/install/update/remove/list, basic dependency types, and a minimal `pnpm-lock.yaml`). Intentionally left out: the pnpm store + symlinked node_modules layout, workspaces, global installs, lifecycle scripts, and non-registry dependency protocols (git/file/link/workspace/etc.).

## Goals

- Safe parsing of config/manifest/lock inputs.
- Install packages from the npm registry (default registry only).
- Generate a minimal `pnpm-lock.yaml` for the supported feature set.
- Never execute install scripts (preinstall/install/postinstall/prepare). Instead, print a notice.
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

## Compatibility (intentional subset)

Supported commands and flags:

- `init` (supports `--name`)
- `add <pkg...>`
- `install`
- `update [pkg...]` (no args = update from manifest)
- `remove <pkg...>`
- `list` (supports `--json`, `--long`, `--parseable`, `--prod`, `--dev`, `--optional`, `--only`, `--global`, `--recursive`, `--depth` and package filters)
- `security-scan` (supports `--older-than-years`, `--yara`)
- `pnpm-rs-pre-scan <pkg>` (helper binary; supports `--older-than-years`, `--yara`)

Intentionally left out:

- pnpm store and symlinked `node_modules` layout.
- Workspaces, global installs, and the full `pnpm` CLI surface.
- Lifecycle scripts (preinstall/install/postinstall/prepare).
- Non-registry dependency protocols (git, file, link, workspace, etc.).
- Flags accepted but only partially implemented: `list --global` prints a notice and falls back to local; `list --recursive` only traverses pnpm workspaces.

## Security scanning

`pnpm-rs` includes an offline security inspection mode that scans the lockfile and installed packages.

```
./target/debug/pnpm-rs security-scan
./target/debug/pnpm-rs security-scan --older-than-years=3
./target/debug/pnpm-rs security-scan --yara rules.yar
```

Checks include:

- Lifecycle scripts defined in package.json (preinstall/install/postinstall/prepare).
- Packages that expose binaries via `bin`.
- Exotic dependency specs inside package.json (git/file/link/workspace/etc.).
- Registry metadata issues (missing version entries or publish timestamps).
- Versions older than the configurable age cutoff (default 5 years).
- Optional YARA scanning across installed package files.

There is also a helper that scans a single package in a temporary project:

```
./target/debug/pnpm-rs-pre-scan react@19
./target/debug/pnpm-rs-pre-scan react@19 --older-than-years=3 --yara rules.yar
```

## Tests

```
cargo test
```
