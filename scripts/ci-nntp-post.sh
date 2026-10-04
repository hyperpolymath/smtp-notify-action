#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# CI: post one article through the built binary and assert what went on the
# wire. Driven by the fixture in scripts/nntp-sink.py; keep the shell here
# rather than inline in the workflow so it can be run by hand against a local
# build (`zig build && bash scripts/ci-nntp-post.sh`).
set -euo pipefail
cd "$(dirname "$0")/.."
bin="${SMTP_NOTIFY_BIN:-./zig-out/bin/smtp-notify}"
port=1161

rm -f "$port.transcript" sink.log
python3 scripts/nntp-sink.py "$port" "200 sink ready" "240 Article received" > sink.log 2>&1 &
sink=$!
for _ in $(seq 1 50); do grep -q ready sink.log 2>/dev/null && break; sleep 0.1; done

env SMTP_ADDR=127.0.0.1 SMTP_PORT="$port" SMTP_SECURE=plaintext SMTP_PROTOCOL=nntp \
    SMTP_USER=ci SMTP_PASS=ci \
    MAIL_FROM='CI <ci@example.test>' \
    MAIL_SUBJECT='smtp-notify nntp e2e — ŵ 🎉' \
    MAIL_NEWSGROUPS='alt.test, uk.rec.cycling' \
    MAIL_CONTENT_LANGUAGE='en-GB' \
    MAIL_BODY=$'line one\n.a line starting with a dot must survive stuffing\nlast line' \
    "$bin"
wait "$sink"

t="$port.transcript"
# The dialogue, in order: CAPABILITIES, then AUTHINFO USER/PASS, then POST,
# then QUIT. RFC 3977 §5.2 makes the capability list mandatory.
grep -qx 'C: CAPABILITIES' "$t"
grep -qx 'C: AUTHINFO USER ci' "$t"
grep -qx 'C: AUTHINFO PASS ci' "$t"
grep -qx 'C: POST' "$t"
grep -qx 'C: QUIT' "$t"
awk '/^C: CAPABILITIES/{c=1} /^C: AUTHINFO USER/{if(!c) exit 1} /^C: POST/{p++} /^C: QUIT/{if(!p) exit 1} END{exit !c}' "$t"

# The article: the newsgroup list is canonicalised, the subject is an
# encoded-word (article headers are ASCII, RFC 5536 §3.1), and the
# Message-ID is generated for this run.
grep -qx 'A: Newsgroups: alt.test, uk.rec.cycling' "$t"
grep -qx 'A: Content-Language: en-GB' "$t"
grep -q '^A: Subject: =?UTF-8?B?' "$t"
grep -Eq '^A: Message-ID: <[0-9]+\.[0-9a-f]+@[A-Za-z0-9.-]+>$' "$t"
# Dot-stuffing, asserted on the raw wire: the stuffed form is present and the
# unstuffed form is absent. A body line of "." would end the article early.
grep -qx 'A: ..a line starting with a dot must survive stuffing' "$t"
if grep -qx 'A: .a line starting with a dot must survive stuffing' "$t"; then
  echo "unstuffed dot line found on the wire" >&2
  exit 1
fi
echo "e2e ok: posted, dot-stuffing on the wire, headers intact"
