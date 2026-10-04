#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# CI: inputs that cannot be right are refused, and refused with the right
# reason. Nothing listens on the port used here, so a refusal that happened
# only after connecting would surface as ConnectionRefused instead — which is
# exactly the defect this step exists to catch.
set -euo pipefail
cd "$(dirname "$0")/.."
bin="${SMTP_NOTIFY_BIN:-./zig-out/bin/smtp-notify}"

# $1 expected fragment; the rest are env assignments.
expect() {
  local frag="$1"
  shift
  if out="$(env "$@" "$bin" 2>&1)"; then
    echo "expected a refusal, got success (looking for: $frag)" >&2
    exit 1
  fi
  echo "$out"
  echo "$out" | grep -qF "$frag" || { echo "refused for the wrong reason (wanted: $frag)" >&2; exit 1; }
}

news=(SMTP_ADDR=127.0.0.1 SMTP_PORT=1180 SMTP_SECURE=plaintext SMTP_PROTOCOL=nntp
      SMTP_USER=u SMTP_PASS=p MAIL_FROM=ci@example.test MAIL_SUBJECT=s
      MAIL_NEWSGROUPS=alt.test MAIL_BODY=b)

expect "not a comma-separated list of well-formed newsgroup names" "${news[@]}" MAIL_NEWSGROUPS=control
expect "not a comma-separated list of well-formed newsgroup names" "${news[@]}" MAIL_NEWSGROUPS=alt..test
expect "not a comma-separated list of well-formed newsgroup names" "${news[@]}" MAIL_NEWSGROUPS='alt test'
expect "CR/LF in a header-bound input" "${news[@]}" MAIL_NEWSGROUPS=$'alt.test\r\nX-Injected: 1'
expect "CR/LF in a header-bound input" "${news[@]}" MAIL_SUBJECT=$'s\r\nBcc: victim@example.test'
expect "is not a comma-separated list of RFC 5646 language tags" "${news[@]}" MAIL_CONTENT_LANGUAGE=en_GB
expect "SMTP_PROTOCOL is nntp but MAIL_NEWSGROUPS is empty" \
  SMTP_ADDR=127.0.0.1 SMTP_PORT=1180 SMTP_SECURE=plaintext SMTP_PROTOCOL=nntp
expect "MAIL_NEWSGROUPS is set but SMTP_PROTOCOL is smtp" \
  SMTP_ADDR=127.0.0.1 SMTP_PORT=1180 SMTP_SECURE=plaintext MAIL_NEWSGROUPS=alt.test \
  MAIL_TO=x@example.test MAIL_FROM=ci@example.test MAIL_SUBJECT=s MAIL_BODY=b
expect 'SMTP_PROTOCOL is "nntps", which is neither' "${news[@]}" SMTP_PROTOCOL=nntps
expect "SMTP_DIAGNOSE is an SMTP probe and is not implemented for NNTP" "${news[@]}" SMTP_DIAGNOSE=true
expect "posting to a newsgroup authenticates (AUTHINFO USER/PASS)" \
  "${news[@]}" SMTP_USER= SMTP_PASS=
echo "input refusals ok: all named their reason, none opened a connection"
