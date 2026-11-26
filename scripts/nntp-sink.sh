#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# Build and run the NNTP sink fixture (scripts/nntp-sink.rs, std only).
#   bash scripts/nntp-sink.sh build            compile once (callers do this first)
#   bash scripts/nntp-sink.sh <port> ...        run it; arguments as in nntp-sink.rs
# The binary lives in an owner-private cache directory and its name carries the
# hash of the source, so another worktree or another account cannot supply it.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
src="$here/nntp-sink.rs"

if [ -n "${NNTP_SINK_BIN:-}" ]; then
  bin="$NNTP_SINK_BIN"          # explicit choice by the caller; built as before
else
  dir="${NNTP_SINK_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/nntp-sink}"
  mkdir -p "$dir"
  chmod 700 "$dir"
  if [ ! -O "$dir" ] || [ -L "$dir" ]; then
    echo "nntp-sink: $dir is not a private directory owned by you" >&2
    exit 1
  fi
  sum="$( (sha256sum "$src" 2>/dev/null || shasum -a 256 "$src") | cut -c1-16)"
  bin="$dir/nntp-sink-$sum"
fi

build() {
  if [ ! -x "$bin" ]; then
    tmp="$bin.$$"
    rustc --edition 2021 -O -o "$tmp" "$src"
    mv -f "$tmp" "$bin"
  fi
}

if [ "${1:-}" = "build" ]; then
  build
  exit 0
fi
build
exec "$bin" "$@"
