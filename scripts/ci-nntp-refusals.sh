#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# CI: every server-side refusal must name its own reason, and none of them may
# put a credential on the wire. Each case starts the fixture sink with a
# different behaviour on its own port, so the assertion is on the specific
# message rather than on "the step failed".
set -euo pipefail
cd "$(dirname "$0")/.."
bin="${SMTP_NOTIFY_BIN:-./zig-out/bin/smtp-notify}"

# Values without spaces on purpose: `env $base` word-splits, and a display-name
# From: would silently become two arguments.
user="SMTP_ADDR=127.0.0.1 SMTP_PROTOCOL=nntp SMTP_SECURE=plaintext SMTP_USER=ci SMTP_PASS=ci"
msg="MAIL_FROM=ci@example.test MAIL_SUBJECT=s MAIL_NEWSGROUPS=alt.test MAIL_BODY=b"

start_sink() { # $1 port, $2 greeting, $3 post-reply, $4 caps
  rm -f "$1.transcript"
  python3 scripts/nntp-sink.py "$1" "$2" "$3" "$4" > "sink.$1.log" 2>&1 &
  for _ in $(seq 1 50); do grep -q ready "sink.$1.log" 2>/dev/null && break; sleep 0.1; done
}

check() { # $1 port, $2 expected fragment
  if out="$(env $user SMTP_PORT="$1" $msg "$bin" 2>&1)"; then
    echo "port $1: expected a refusal, got success" >&2
    echo "$out" >&2
    exit 1
  fi
  echo "$out"
  echo "$out" | grep -qF "$2" || { echo "port $1: refused for the wrong reason" >&2; exit 1; }
  wait || true
}

start_sink 1171 "201 sink posting prohibited" "240 ok" "VERSION 2,POST,AUTHINFO USER"
check 1171 "will not accept posts"

start_sink 1172 "200 sink ready" "440 Posting not permitted" "VERSION 2,POST,AUTHINFO USER"
check 1172 "will not accept posts"

start_sink 1173 "200 sink ready" "441 Posting failed: rejected by the news administrator" "VERSION 2,POST,AUTHINFO USER"
check 1173 "refused the article itself (441)"

# A server that names only SASL: refused BEFORE a credential is written, so the
# transcript must show CAPABILITIES and QUIT and nothing else.
start_sink 1174 "200 sink ready" "240 ok" "VERSION 2,POST,AUTHINFO SASL PLAIN"
check 1174 "offers no AUTHINFO mechanism this client can drive"
if grep -q 'AUTHINFO USER' 1174.transcript; then
  echo "a credential was sent to the SASL-only sink" >&2
  exit 1
fi

# STARTTLS selected and not advertised: no command, no fallback, no credential.
start_sink 1175 "200 sink ready" "240 ok" "VERSION 2,POST,AUTHINFO USER"
if out="$(env SMTP_ADDR=127.0.0.1 SMTP_PORT=1175 SMTP_PROTOCOL=nntp SMTP_SECURE=starttls \
        SMTP_USER=ci SMTP_PASS=ci $msg "$bin" 2>&1)"; then
  echo "STARTTLS not offered: expected a refusal, got success" >&2
  exit 1
fi
echo "$out"
echo "$out" | grep -qF "does not advertise STARTTLS" || { echo "wrong refusal for a missing STARTTLS" >&2; exit 1; }
if grep -q 'AUTHINFO' 1175.transcript; then
  echo "a credential was sent over the cleartext stream" >&2
  exit 1
fi
wait || true

echo "refusals ok: each named its own reason, no credential went out"
