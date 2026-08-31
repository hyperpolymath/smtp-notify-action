// SPDX-License-Identifier: MPL-2.0
//! smtp-notify — send one plain-text notification mail over implicit TLS
//! (SMTPS, typically port 465), or plaintext for containerized test sinks.
//!
//! ALL configuration comes from environment variables, never argv, so the
//! credential cannot leak into process listings:
//!
//!   SMTP_ADDR            server host name (required)
//!   SMTP_PORT            server port (required)
//!   SMTP_SECURE          "true" (default) = implicit TLS; anything else = plaintext
//!   SMTP_USER            AUTH PLAIN username
//!   SMTP_PASS            AUTH PLAIN password
//!   MAIL_FROM            From: value, e.g. "GitHub Push <bot@example.org>"
//!   MAIL_TO              recipients, separated by commas and/or whitespace
//!   MAIL_SUBJECT         Subject: value (CR/LF rejected, never sanitized)
//!   MAIL_BODY            plain-text body (dot-stuffed on the wire)
//!   SMTP_HANDSHAKE_ONLY  "true" = greeting + EHLO + QUIT, no auth, no mail

const std = @import("std");
const smtp = @import("smtp.zig");
// Vendored std TLS client + certificate_request patch (ziglang/zig#19521);
// see the provenance header in that file. Swap back to std.crypto.tls.Client
// when upstream can answer a client-certificate request.
const TlsClient = @import("tls/Client.zig");

const tls_buf_len = std.crypto.tls.max_ciphertext_record_len;

fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("smtp-notify: " ++ fmt ++ "\n", args);
    std.process.exit(1);
}

const Env = std.process.Environ.Map;

fn env(map: *const Env, name: []const u8) ?[]const u8 {
    return map.get(name);
}

fn envRequired(map: *const Env, name: []const u8) []const u8 {
    // Empty counts as missing: a composite action maps an unset input to an
    // empty env var, and passing "" through (e.g. as the password) would
    // surface as a baffling 535 from the server instead of a config error.
    const v = env(map, name) orelse fatal("missing required environment variable {s}", .{name});
    if (v.len == 0) fatal("required environment variable {s} is empty", .{name});
    return v;
}

fn envIsTrue(map: *const Env, name: []const u8, default: bool) bool {
    const v = env(map, name) orelse return default;
    return std.mem.eql(u8, v, "true");
}

pub fn main(init: std.process.Init.Minimal) !void {
    const gpa = std.heap.smp_allocator;

    var threaded: std.Io.Threaded = .init(gpa, .{ .environ = init.environ });
    defer threaded.deinit();
    const io = threaded.io();

    var env_map = init.environ.createMap(gpa) catch |err| fatal("{t}", .{err});
    const envs = &env_map;

    const addr = envRequired(envs, "SMTP_ADDR");
    const port_str = envRequired(envs, "SMTP_PORT");
    const port = std.fmt.parseInt(u16, port_str, 10) catch
        fatal("SMTP_PORT is not a port number: {s}", .{port_str});
    const secure = envIsTrue(envs, "SMTP_SECURE", true);
    const handshake_only = envIsTrue(envs, "SMTP_HANDSHAKE_ONLY", false);

    const now: std.Io.Timestamp = .now(io, .real);

    const cfg: smtp.Config = if (handshake_only) .{
        .ehlo_domain = "github-actions",
        .username = "",
        .password = "",
        .from = "",
        .recipients = &.{},
        .subject = "",
        .body = "",
        .date_epoch_seconds = 0,
        .handshake_only = true,
    } else cfg: {
        var recipients: std.ArrayList([]const u8) = .empty;
        var it = std.mem.tokenizeAny(u8, envRequired(envs, "MAIL_TO"), ", \t");
        while (it.next()) |rcpt| recipients.append(gpa, rcpt) catch |err| fatal("{t}", .{err});
        break :cfg .{
            .ehlo_domain = "github-actions",
            .username = envRequired(envs, "SMTP_USER"),
            .password = envRequired(envs, "SMTP_PASS"),
            .from = envRequired(envs, "MAIL_FROM"),
            .recipients = recipients.items,
            .subject = envRequired(envs, "MAIL_SUBJECT"),
            .body = envRequired(envs, "MAIL_BODY"),
            .date_epoch_seconds = now.toSeconds(),
            .handshake_only = false,
        };
    };

    const host = std.Io.net.HostName.init(addr) catch
        fatal("invalid host name: {s}", .{addr});
    var stream = host.connect(io, port, .{ .mode = .stream }) catch |err|
        fatal("cannot connect to {s}:{d}: {t}", .{ addr, port, err });
    defer stream.close(io);

    const socket_read_buf = gpa.alloc(u8, tls_buf_len) catch |err| fatal("{t}", .{err});
    const stream_write_buf = gpa.alloc(u8, tls_buf_len) catch |err| fatal("{t}", .{err});
    var stream_reader = stream.reader(io, socket_read_buf);
    var stream_writer = stream.writer(io, stream_write_buf);

    if (!secure) {
        smtp.runSession(cfg, .{
            .r = &stream_reader.interface,
            .w = &stream_writer.interface,
        }) catch |err| fatalSession(err, addr, port);
        std.debug.print("smtp-notify: delivered via {s}:{d} (plaintext)\n", .{ addr, port });
        return;
    }

    const tls_read_buf = gpa.alloc(u8, tls_buf_len + 4096) catch |err| fatal("{t}", .{err});
    const tls_write_buf = gpa.alloc(u8, 4096) catch |err| fatal("{t}", .{err});

    var entropy: [TlsClient.Options.entropy_len]u8 = undefined;
    io.random(&entropy);

    var bundle: std.crypto.Certificate.Bundle = .empty;
    bundle.rescan(gpa, io, now) catch |err|
        fatal("cannot load the system CA bundle: {t}", .{err});
    var bundle_lock: std.Io.RwLock = .init;

    var tls_client = TlsClient.init(
        &stream_reader.interface,
        &stream_writer.interface,
        .{
            .host = .{ .explicit = addr },
            .ca = .{ .bundle = .{
                .gpa = gpa,
                .io = io,
                .lock = &bundle_lock,
                .bundle = &bundle,
            } },
            .read_buffer = tls_read_buf,
            .write_buffer = tls_write_buf,
            .entropy = &entropy,
            .realtime_now = now,
            // SMTP replies carry no length framing, so keep truncation-attack
            // detection on (the default) — unlike HTTP, we cannot detect a
            // cut-off stream at the application layer.
        },
    ) catch |err| fatal("TLS handshake with {s}:{d} failed: {t}", .{ addr, port, err });

    smtp.runSession(cfg, .{
        .r = &tls_client.reader,
        .w = &tls_client.writer,
        .below = &stream_writer.interface,
    }) catch |err| fatalSession(err, addr, port);

    tls_client.end() catch {}; // close_notify, best effort — QUIT already got 221
    stream_writer.interface.flush() catch {};

    if (handshake_only) {
        std.debug.print("smtp-notify: TLS handshake + EHLO ok via {s}:{d}\n", .{ addr, port });
    } else {
        std.debug.print("smtp-notify: delivered via {s}:{d} (TLS)\n", .{ addr, port });
    }
}

fn fatalSession(err: smtp.Error, addr: []const u8, port: u16) noreturn {
    switch (err) {
        error.TransientFailure => fatal("{s}:{d} replied 4xx (transient failure) — retry later", .{ addr, port }),
        error.PermanentFailure => fatal("{s}:{d} replied 5xx (permanent failure) — check credentials/addresses", .{ addr, port }),
        error.ProtocolError => fatal("{s}:{d} sent a reply outside the proven protocol table", .{ addr, port }),
        error.HeaderInjection => fatal("CR/LF in a header-bound input (from/to/subject) — refusing to send", .{}),
        error.NoRecipients => fatal("MAIL_TO contains no recipients", .{}),
        else => fatal("session with {s}:{d} failed: {t}", .{ addr, port, err }),
    }
}
