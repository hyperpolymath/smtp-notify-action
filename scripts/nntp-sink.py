#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""A one-shot NNTP sink for end-to-end verification — a test fixture, nothing more.

The action ships one static Zig binary and no runtime dependencies; this file
is not part of it, is never installed, and exists only so CI and a developer
can point the built binary at a real socket and inspect what it actually sent.
It is deliberately the same shape as the Mailpit sink CI already uses for SMTP:
a server that answers the dialogue, records the article, and lets the shell
assert on it.

Usage:
    nntp-sink.py <port> <greeting> <post-reply> [caps] [--closes-after-post]

    greeting   first line, e.g. "200 sink ready" or "201 posting prohibited"
    post-reply answered to POST, or to the article if it is a 240
    caps       comma-separated capability lines; default is a usable server
    --closes-after-post
               close the connection after the article is accepted, instead of
               answering QUIT — a server behaviour the client must survive
               (the article is already filed by then)

Everything it received is written to `<port>.transcript` as:

    C: <a line the client sent>
    A: <a line of the article the client sent>

It serves exactly one connection and exits.
"""

import socket
import sys

port = int(sys.argv[1])
greeting = sys.argv[2] if len(sys.argv) > 2 else "200 sink ready"
post_reply = sys.argv[3] if len(sys.argv) > 3 else "240 Article received"
caps = (
    sys.argv[4].split(",")
    if len(sys.argv) > 4 and sys.argv[4]
    else ["VERSION 2", "READER", "POST", "AUTHINFO USER"]
)
closes_after_post = "--closes-after-post" in sys.argv

transcript: list[str] = []
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(1)
print("ready", flush=True)
conn, _ = srv.accept()
f = conn.makefile("rwb", buffering=0)


def send(line: str) -> None:
    f.write((line + "\r\n").encode())


def dump() -> None:
    with open(f"{port}.transcript", "w", encoding="utf-8") as out:
        out.write("\n".join(transcript) + "\n")


send(greeting)
while True:
    raw = f.readline()
    if not raw:
        break
    line = raw.decode("utf-8", "replace").rstrip("\r\n")
    transcript.append("C: " + line)
    verb = line.upper()
    if verb == "CAPABILITIES":
        send("101 Capability list:")
        for cap in caps:
            send(cap)
        send(".")
    elif verb.startswith("AUTHINFO USER"):
        send("381 Password required")
    elif verb.startswith("AUTHINFO PASS"):
        send("281 Authentication accepted")
    elif verb == "POST":
        # A refusal at POST itself (440, 480, 5xx) is answered without reading
        # an article, because the server has not invited one.
        if post_reply[:1] in ("4", "5") and post_reply[:3] != "441":
            send(post_reply)
            continue
        send("340 Send article to be posted. End with <CRLF>.<CRLF>")
        while True:
            a = f.readline()
            if not a:
                break
            al = a.decode("utf-8", "replace").rstrip("\r\n")
            if al == ".":
                break
            transcript.append("A: " + al)
        send(post_reply)
        if closes_after_post:
            break
    elif verb == "QUIT":
        send("205 Closing connection")
        break

conn.close()
srv.close()
dump()
print(f"transcript written to {port}.transcript", flush=True)
