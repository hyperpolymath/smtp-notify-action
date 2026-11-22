#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# Build and run the NNTP sink fixture (scripts/nntp-sink.rs, std only).
#   bash scripts/nntp-sink.sh build            compile once (callers do this first)
#   bash scripts/nntp-sink.sh <port> ...        run it; arguments as in nntp-sink.rs
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
bin="${NNTP_SINK_BIN:-${TMPDIR:-/tmp}/nntp-sink-$(id -u)}"

build() {
  if [ ! -x "$bin" ] || [ "$here/nntp-sink.rs" -nt "$bin" ]; then
    rustc --edition 2021 -O -o "$bin" "$here/nntp-sink.rs"
  fi
}

if [ "${1:-}" = "build" ]; then
  build
  exit 0
fi
build
exec "$bin" "$@"
