#!/usr/bin/env bash
# Cold-start benchmark for the action binary. Requires a built binary and /usr/bin/time.
set -euo pipefail
bin=${1:-zig-out/bin/smtp-notify}
: "${SMTP_ADDR:?set SMTP_ADDR to a test SMTP sink}"
: "${SMTP_PORT:?set SMTP_PORT to a test SMTP sink}"
export SMTP_SECURE=${SMTP_SECURE:-plaintext} SMTP_HANDSHAKE_ONLY=true
export SMTP_TIMEOUT_SECONDS=${SMTP_TIMEOUT_SECONDS:-10}
/usr/bin/time -f 'cold_start_seconds=%e rss_kib=%M' "$bin" >/dev/null
