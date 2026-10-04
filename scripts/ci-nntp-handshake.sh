#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# CI: handshake_only proves reachability and the capability dialogue without
# authenticating or posting — the news form of the canary the tls-handshake job
# runs for SMTP.
set -euo pipefail
cd "$(dirname "$0")/.."
bin="${SMTP_NOTIFY_BIN:-./zig-out/bin/smtp-notify}"
port=1181

rm -f "$port.transcript" "sink.$port.log"
python3 scripts/nntp-sink.py "$port" "200 sink ready" "240 ok" > "sink.$port.log" 2>&1 &
sink=$!
for _ in $(seq 1 50); do grep -q ready "sink.$port.log" 2>/dev/null && break; sleep 0.1; done

env SMTP_ADDR=127.0.0.1 SMTP_PORT="$port" SMTP_SECURE=plaintext SMTP_PROTOCOL=nntp \
    SMTP_HANDSHAKE_ONLY=true MAIL_NEWSGROUPS=alt.test "$bin"
wait "$sink"

grep -qx 'C: CAPABILITIES' "$port.transcript"
grep -qx 'C: QUIT' "$port.transcript"
if grep -q 'AUTHINFO\|POST' "$port.transcript"; then
  echo "handshake-only authenticated or posted" >&2
  exit 1
fi
echo "handshake-only ok: CAPABILITIES then QUIT, nothing else"
