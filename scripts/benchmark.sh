#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
#
# Cold-start benchmark: this action's static binary against a Node-based
# mail action (dawidd6/action-send-mail), each delivering ONE real message
# to the same local SMTP sink, N times, with nothing cached between runs
# except what the OS page cache keeps for both alike.
#
# What is measured, per run: wall time from process spawn to process exit
# (nanosecond clock, `date +%s%N`), and peak resident set size (GNU time
# `%M`). Every run is a full delivery — greeting, EHLO, AUTH, MAIL, RCPT,
# DATA, QUIT — not a handshake, so both sides do the same protocol work.
#
# What is NOT measured, stated so the numbers are not read as more than they
# are: the runner's download of either action (both are fetched as repository
# tarballs by the runner), this action's `curl` of its release asset, and
# network latency to a real provider. Those are properties of the runner and
# the network, not of the two programs.
#
# Usage:
#   scripts/benchmark.sh [runs]
# Environment:
#   BIN           smtp-notify binary        (default zig-out/bin/smtp-notify)
#   NODE          node >= 24 executable     (default: node on PATH)
#   DAWIDD6_DIR   checkout of dawidd6/action-send-mail (optional; skipped if unset)
#   SMTP_ADDR / SMTP_PORT  a local plaintext sink, e.g. mailpit on 1025
#
# Output: a Markdown table on stdout, raw samples under $OUT (default
# ./bench-out), and the exact versions measured.
set -euo pipefail

runs=${1:-30}
warmup=3
bin=${BIN:-zig-out/bin/smtp-notify}
node=${NODE:-node}
out=${OUT:-bench-out}
: "${SMTP_ADDR:?set SMTP_ADDR to a local SMTP sink (e.g. mailpit)}"
: "${SMTP_PORT:?set SMTP_PORT to the sink port}"
[ -x /usr/bin/time ] || { echo "needs GNU time at /usr/bin/time" >&2; exit 1; }
[ -x "$bin" ] || { echo "no binary at $bin; run zig build -Doptimize=ReleaseSafe" >&2; exit 1; }
mkdir -p "$out"
# Only series run by THIS invocation are reported: stale samples from an
# earlier run (e.g. a dawidd6 series when DAWIDD6_DIR is now unset) must not
# reach the table.
rm -f "$out"/*.samples
ran=()

# One sample: prints "<wall_ms> <rss_kib>".
sample() {
  local rss_file t0 t1
  rss_file=$(mktemp)
  t0=$(date +%s%N)
  /usr/bin/time -o "$rss_file" -f '%M' "$@" >/dev/null 2>&1
  t1=$(date +%s%N)
  printf '%s %s\n' "$(( (t1 - t0) / 1000 ))" "$(cat "$rss_file")"
  rm -f "$rss_file"
}

# Median and p95 of column $2 of file $1 (integer microseconds or KiB).
stats() {
  sort -n -k"$2","$2" "$1" | awk -v c="$2" '
    { v[NR] = $c }
    END {
      med = (NR % 2) ? v[(NR + 1) / 2] : (v[NR / 2] + v[NR / 2 + 1]) / 2
      p95 = v[int(0.95 * NR + 0.999999)]
      printf "%s %s %s %s", med, p95, v[1], v[NR]
    }'
}

# Series $1: $warmup discarded warm-up samples, then $runs samples of the
# command in the remaining args, written to "$out/$1.samples".
run_series() {
  local name=$1; shift
  local f="$out/$name.samples"
  : > "$f"
  for _ in $(seq "$warmup"); do sample "$@" >/dev/null; done
  for _ in $(seq "$runs"); do sample "$@" >> "$f"; done
  ran+=("$name")
}

# --- this action ----------------------------------------------------------
# Every run must be a full delivery: an inherited SMTP_DIAGNOSE or
# SMTP_HANDSHAKE_ONLY would silently turn samples into non-delivery probes.
export SMTP_DIAGNOSE=false SMTP_HANDSHAKE_ONLY=false
export SMTP_SECURE=plaintext SMTP_USER=bench SMTP_PASS=bench \
  MAIL_FROM='Bench <bench@example.test>' MAIL_TO='sink@example.test' \
  MAIL_SUBJECT='smtp-notify benchmark' MAIL_BODY='benchmark body'
run_series smtp-notify "$bin"

# --- Node action, invoked the way the runner invokes a `node24` action ----
if [ -n "${DAWIDD6_DIR:-}" ]; then
  run_series dawidd6 env \
    INPUT_SERVER_ADDRESS="$SMTP_ADDR" INPUT_SERVER_PORT="$SMTP_PORT" \
    INPUT_SECURE=false INPUT_IGNORE_CERT=true \
    INPUT_USERNAME=bench INPUT_PASSWORD=bench \
    INPUT_FROM='Bench <bench@example.test>' INPUT_TO='sink@example.test' \
    INPUT_SUBJECT='dawidd6 benchmark' INPUT_BODY='benchmark body' \
    "$node" "$DAWIDD6_DIR/main.js"
fi

# --- report ---------------------------------------------------------------
host_cpu=$(awk -F: '/model name/ {gsub(/^ +/, "", $2); print $2; exit}' /proc/cpuinfo 2>/dev/null || echo unknown)
echo "Runs: $runs per program (after $warmup warm-up runs discarded); full delivery to ${SMTP_ADDR}:${SMTP_PORT}"
echo "Host: $(uname -srm); CPU: ${host_cpu}; $(nproc) vCPU"
echo "smtp-notify: $(sha256sum "$bin" | cut -c1-16)… ($(stat -c %s "$bin") bytes, static)"
if [ -n "${DAWIDD6_DIR:-}" ]; then
  echo "dawidd6/action-send-mail: $(git -C "$DAWIDD6_DIR" rev-parse --short=12 HEAD) ($(git -C "$DAWIDD6_DIR" describe --tags 2>/dev/null || echo untagged)); node $("$node" --version); node_modules $(du -sb "$DAWIDD6_DIR/node_modules" | cut -f1) bytes"
fi
echo
echo "| Program | wall median (ms) | wall p95 (ms) | wall min–max (ms) | peak RSS median (MiB) |"
echo "|---|---:|---:|---:|---:|"
for name in "${ran[@]}"; do
  f="$out/$name.samples"
  read -r wmed wp95 wmin wmax <<<"$(stats "$f" 1)"
  read -r rmed _ _ _ <<<"$(stats "$f" 2)"
  awk -v n="$name" -v a="$wmed" -v b="$wp95" -v c="$wmin" -v d="$wmax" -v r="$rmed" \
    'BEGIN { printf "| %s | %.1f | %.1f | %.1f–%.1f | %.1f |\n", n, a/1000, b/1000, c/1000, d/1000, r/1024 }'
done
