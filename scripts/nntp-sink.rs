// SPDX-License-Identifier: MPL-2.0
//! A one-shot NNTP sink for end-to-end verification: a test fixture, nothing more.
//!
//! The action ships one static Zig binary and no runtime dependencies; this file
//! is not part of it, is never installed, and exists only so CI and a developer
//! can point the built binary at a real socket and inspect what it actually sent.
//! It is deliberately the same shape as the Mailpit sink CI already uses for SMTP:
//! a server that answers the dialogue, records the article, and lets the shell
//! assert on it.
//!
//! Build and run through `scripts/nntp-sink.sh` (std only, plain `rustc`).
//!
//! Usage:
//!     nntp-sink <port> <greeting> <post-reply> [caps] [--closes-after-post]
//!
//!     greeting   first line, e.g. "200 sink ready" or "201 posting prohibited"
//!     post-reply answered to POST, or to the article if it is a 240
//!     caps       comma-separated capability lines; default is a usable server
//!     --closes-after-post
//!                close the connection after the article is accepted, instead of
//!                answering QUIT: a server behaviour the client must survive
//!                (the article is already filed by then)
//!
//! Everything it received is written to `<port>.transcript` as:
//!
//!     C: <a line the client sent>
//!     A: <a line of the article the client sent>
//!
//! It serves exactly one connection and exits.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::process::exit;

fn send(conn: &mut TcpStream, line: &str) {
    // A client that has already gone is not an error for a fixture.
    let _ = conn.write_all(format!("{line}\r\n").as_bytes());
}

fn read_line(r: &mut BufReader<TcpStream>) -> Option<String> {
    let mut buf = Vec::new();
    match r.read_until(b'\n', &mut buf) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(
            String::from_utf8_lossy(&buf)
                .trim_end_matches(['\r', '\n'])
                .to_string(),
        ),
    }
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let port: u16 = match argv.get(1).and_then(|p| p.parse().ok()) {
        Some(p) => p,
        None => {
            eprintln!("usage: nntp-sink <port> <greeting> <post-reply> [caps] [--closes-after-post]");
            exit(2);
        }
    };
    let greeting = argv.get(2).map_or("200 sink ready", String::as_str);
    let post_reply = argv.get(3).map_or("240 Article received", String::as_str);
    let caps: Vec<&str> = match argv.get(4) {
        Some(c) if !c.is_empty() => c.split(',').collect(),
        _ => vec!["VERSION 2", "READER", "POST", "AUTHINFO USER"],
    };
    let closes_after_post = argv.iter().any(|a| a == "--closes-after-post");

    let mut transcript: Vec<String> = Vec::new();
    // std sets SO_REUSEADDR on Unix listeners, as the Python fixture did.
    let srv = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).unwrap_or_else(|e| {
        eprintln!("bind 127.0.0.1:{port}: {e}");
        exit(1);
    });
    println!("ready");
    let _ = std::io::stdout().flush();
    let (mut conn, _) = srv.accept().expect("accept");
    let mut rd = BufReader::new(conn.try_clone().expect("clone"));

    send(&mut conn, greeting);
    while let Some(line) = read_line(&mut rd) {
        transcript.push(format!("C: {line}"));
        let verb = line.to_uppercase();
        if verb == "CAPABILITIES" {
            send(&mut conn, "101 Capability list:");
            for cap in &caps {
                send(&mut conn, cap);
            }
            send(&mut conn, ".");
        } else if verb.starts_with("AUTHINFO USER") {
            send(&mut conn, "381 Password required");
        } else if verb.starts_with("AUTHINFO PASS") {
            send(&mut conn, "281 Authentication accepted");
        } else if verb == "POST" {
            // A refusal at POST itself (440, 480, 5xx) is answered without reading
            // an article, because the server has not invited one.
            if matches!(post_reply.chars().next(), Some('4' | '5')) && !post_reply.starts_with("441") {
                send(&mut conn, post_reply);
                continue;
            }
            send(&mut conn, "340 Send article to be posted. End with <CRLF>.<CRLF>");
            while let Some(al) = read_line(&mut rd) {
                if al == "." {
                    break;
                }
                transcript.push(format!("A: {al}"));
            }
            send(&mut conn, post_reply);
            if closes_after_post {
                break;
            }
        } else if verb == "QUIT" {
            send(&mut conn, "205 Closing connection");
            break;
        }
    }

    drop(conn);
    drop(srv);
    let path = format!("{port}.transcript");
    fs::write(&path, transcript.join("\n") + "\n").expect("write transcript");
    println!("transcript written to {path}");
}
