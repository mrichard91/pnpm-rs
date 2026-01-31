# pnpm-rs

A safety-first, limited **pure Rust** pnpm replacement. This build uses the npm registry directly and installs packages into a flat `node_modules` layout. It never executes lifecycle scripts and prints what would have been run instead.

## Goals

- Safe parsing of config/manifest/lock inputs.
- Install packages from the npm registry (default registry only).
- Generate a minimal `pnpm-lock.yaml` for the supported feature set.
- Never execute install scripts (preinstall/install/postinstall/prepare). Instead, print a notice.
- Reject exotic dependency sources (git, file, ssh, workspace, etc.).

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
```

Version:

```
./target/debug/pnpm-rs -v
./target/debug/pnpm-rs --version
```

Unsupported commands are accepted and ignored with a notice.

## Tests

```
cargo test
```
