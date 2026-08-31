#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# CI drift gate: the committed src/generated/smtp_fsm.zig must be byte-equal
# to a fresh generation from the proven spec. Run with --selftest to first
# prove the comparison can actually fail (a gate that cannot fail is not a
# gate).
set -euo pipefail
cd "$(dirname "$0")/.."

fresh="$(mktemp)"
trap 'rm -f "$fresh"' EXIT

(cd spec && idris2 --build smtp-spec.ipkg)
spec/build/exec/emit-zig > "$fresh"

if [ "${1:-}" = "--selftest" ]; then
  corrupted="$(mktemp)"
  cat "$fresh" > "$corrupted"
  printf 'X' >> "$corrupted"
  if diff -q "$corrupted" "$fresh" > /dev/null; then
    echo "SELFTEST FAILED: diff did not detect a corrupted generation" >&2
    rm -f "$corrupted"
    exit 1
  fi
  rm -f "$corrupted"
  echo "selftest ok: the drift comparison can fail"
fi

if ! diff -u src/generated/smtp_fsm.zig "$fresh"; then
  echo "DRIFT: src/generated/smtp_fsm.zig does not match the spec." >&2
  echo "Run scripts/gen-fsm.sh and commit the result." >&2
  exit 1
fi
echo "no drift: committed FSM matches the proven contract"
