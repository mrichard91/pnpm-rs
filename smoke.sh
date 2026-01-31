#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN="$ROOT_DIR/target/debug/pnpm-rs"

if [[ ! -x "$BIN" ]]; then
  echo "pnpm-rs binary not found. Run: $ROOT_DIR/build.sh" >&2
  exit 1
fi

TEMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

cd "$TEMP_DIR"
"$BIN" init
"$BIN" add react@19

if [[ ! -f "$TEMP_DIR/node_modules/react/package.json" ]]; then
  echo "react package.json missing" >&2
  exit 1
fi

node -e "const fs = require('fs'); const p = JSON.parse(fs.readFileSync('node_modules/react/package.json','utf8')); if(!p.version){ process.exit(1);}"

echo "pnpm-rs smoke test OK: $TEMP_DIR"
