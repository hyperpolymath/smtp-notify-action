// SPDX-License-Identifier: MPL-2.0
//! smtp-notify — send one plain-text notification mail over implicit TLS
//! (SMTPS, typically port 465), or plaintext for containerized test sinks.
//!
//! ALL configuration comes from environment variables, never argv, so the
//! credential cannot leak into process listings:
//!
//!   SMTP_ADDR            server host name (required)
//!   SMTP_PORT            server port (required)
//!   SMTP_SECURE          transport: "true"/"implicit" (default) = TLS from the
//!                        first byte; "false"/"starttls" = STARTTLS, mandatory;
//!                        "plaintext" = no TLS. Anything else is fatal.
//!   SMTP_TIMEOUT_SECONDS whole-run deadline, default 60
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

/// A boolean env var, fail-closed: exactly `true` or `false`, case-insensitive,
/// and anything else is fatal rather than quietly taken as one of them.
fn envFlag(map: *const Env, name: []const u8, default: bool) bool {
    const v = env(map, name) orelse return default;
    if (v.len == 0) return default;
    if (std.ascii.eqlIgnoreCase(v, "true")) return true;
    if (std.ascii.eqlIgnoreCase(v, "false")) return false;
    fatal("{s} is \"{s}\", which is neither true nor false", .{ name, v });
}

/// How the session is protected on the wire.
pub const Transport = enum {
    /// TLS from the first byte (SMTPS, normally port 465).
    implicit_tls,
    /// Plain connection upgraded by STARTTLS. *Mandatory*, never opportunistic:
    /// if the server does not offer the upgrade, the run fails rather than
    /// continuing in the clear.
    starttls,
    /// No TLS at all, by explicit opt-in only — local test sinks.
    plaintext,
};

/// Parse `SMTP_SECURE` into a transport, fail-closed.
///
/// `true`/`false` are dawidd6/action-send-mail's spellings and keep their
/// meaning there, so a migrated workflow reads the same: `false` selects
/// STARTTLS, *not* plaintext. Cleartext now requires naming it.
///
/// The old behaviour compared for the exact string "true" and fell through to
/// a plaintext session otherwise, so `secure: 1`, `yes` or `TRUE` sent AUTH
/// PLAIN credentials in the clear (issue #1). Refusing to guess is the fix;
/// accepting more spellings for "on" would only move the same trap.
fn parseTransport(map: *const Env) Transport {
    const v = env(map, "SMTP_SECURE") orelse return .implicit_tls;
    if (v.len == 0) return .implicit_tls;
    if (std.ascii.eqlIgnoreCase(v, "true")) return .implicit_tls;
    if (std.ascii.eqlIgnoreCase(v, "implicit")) return .implicit_tls;
    if (std.ascii.eqlIgnoreCase(v, "false")) return .starttls;
    if (std.ascii.eqlIgnoreCase(v, "starttls")) return .starttls;
    if (std.ascii.eqlIgnoreCase(v, "plaintext")) return .plaintext;
    fatal(
        "SMTP_SECURE is \"{s}\", which is not one of: true, implicit, false, starttls, plaintext. " ++
            "Refusing to guess: an unrecognised value used to mean plaintext, which put the " ++
            "password on the wire in the clear.",
        .{v},
    );
}

const default_timeout_seconds: u32 = 60;

fn envSeconds(map: *const Env, name: []const u8, default: u32) u32 {
    const v = env(map, name) orelse return default;
    if (v.len == 0) return default;
    const n = std.fmt.parseInt(u32, v, 10) catch
        fatal("{s} is \"{s}\", not a whole number of seconds", .{ name, v });
    if (n == 0) fatal("{s} is 0; a run with no deadline is not offered", .{name});
    return n;
}

/// Whole-run deadline.
///
/// Zig 0.16 gives `connect` an `Io.Timeout`, but `Stream.Reader`/`Stream.Writer`
/// carry no per-operation deadline, so a server that accepts the connection and
/// then falls silent would hold the step until the runner's own six-hour limit.
/// One watchdog thread bounds the whole run, which is both the honest guarantee
/// and far less invasive than threading deadlines through the vendored TLS
/// client (issue #4).
fn watchdog(io: std.Io, seconds: u32) void {
    io.sleep(.fromSeconds(seconds), .awake) catch return;
    std.debug.print(
        "smtp-notify: run exceeded {d}s with no result — aborting " ++
            "(raise SMTP_TIMEOUT_SECONDS if the server is legitimately this slow)\n",
        .{seconds},
    );
    std.process.exit(1);
}

/// Connect without the ability to ask for a connect timeout.
///
/// `IpAddress.ConnectOptions` carries a `timeout` field that aborts the process
/// on any value other than `.none`, in every Zig 0.16.0 backend that implements
/// connect at all (ziglang/zig#25747; BUSTFILE.adoc, BUST-2026-001):
///
///   std/Io/Threaded.zig:12077  @panic("TODO implement netConnectIpPosix with timeout")
///   std/Io/Threaded.zig:12096  @panic("TODO implement netConnectIpWindows with timeout")
///   std/Io/Kqueue.zig:1037     @panic("TODO")
///
/// The guard upstream is `options.timeout != .none` — an inhabitance test, not
/// a magnitude test — so no "very small" or "very large" duration escapes it.
///
/// This type exists so the defect is *eliminated* rather than documented: it
/// has no `timeout` field, so the hazardous value cannot be named at the call
/// site. A comment saying "do not set this" is an administrative control that
/// lasts exactly as long as the next person who does not read it. A type with
/// no such field is a structural one, and re-adding the timeout then requires
/// deliberately bypassing this function — a visible act in review rather than
/// one more field in a struct literal.
///
/// The connect phase is bounded by `watchdog` above, which covers strictly more
/// than this field would have: the handshake and every read and write too.
const SafeConnectOptions = struct {
    mode: std.Io.net.Socket.Mode,
    protocol: ?std.Io.net.Protocol = null,
};

comptime {
    // Fires if the hazardous field is ever added to the wrapper. This covers
    // one of the two ways the elimination can be undone; the other — calling
    // `host.connect` directly and bypassing `connectNoTimeout` — is not
    // machine-checkable here and is caught in review. Say which is which
    // rather than implying the check is total.
    if (@hasField(SafeConnectOptions, "timeout"))
        @compileError("SafeConnectOptions must not carry a timeout: see BUSTFILE.adoc BUST-2026-001");
}

fn connectNoTimeout(
    host: std.Io.net.HostName,
    io: std.Io,
    port: u16,
    options: SafeConnectOptions,
) std.Io.net.HostName.ConnectError!std.Io.net.Stream {
    // The single place `IpAddress.ConnectOptions` is constructed in this
    // program. `.timeout` is left at its `.none` default, which is its only
    // non-aborting inhabitant.
    return host.connect(io, port, .{
        .mode = options.mode,
        .protocol = options.protocol,
    });
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
    const transport = parseTransport(envs);
    if (transport == .starttls) fatal(
        "SMTP_SECURE selects STARTTLS, which is not implemented yet " ++
            "(https://github.com/hyperpolymath/smtp-notify-action/issues/5). " ++
            "Failing rather than falling back to an unencrypted session.",
        .{},
    );
    const handshake_only = envFlag(envs, "SMTP_HANDSHAKE_ONLY", false);
    const timeout_seconds = envSeconds(envs, "SMTP_TIMEOUT_SECONDS", default_timeout_seconds);

    // Detached: it either fires and exits the process, or the process exits
    // first and takes it with it.
    if (std.Thread.spawn(.{}, watchdog, .{ io, timeout_seconds })) |t| {
        t.detach();
    } else |err| {
        fatal("cannot start the timeout watchdog: {t}", .{err});
    }

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
    // No connect timeout: `connectNoTimeout` cannot express one, deliberately.
    // See its doc comment and BUSTFILE.adoc / BUST-2026-001.
    var stream = connectNoTimeout(host, io, port, .{ .mode = .stream }) catch |err|
        fatal("cannot connect to {s}:{d}: {t}", .{ addr, port, err });
    defer stream.close(io);

    const socket_read_buf = gpa.alloc(u8, tls_buf_len) catch |err| fatal("{t}", .{err});
    const stream_write_buf = gpa.alloc(u8, tls_buf_len) catch |err| fatal("{t}", .{err});
    var stream_reader = stream.reader(io, socket_read_buf);
    var stream_writer = stream.writer(io, stream_write_buf);

    var diag: smtp.Diagnostic = .{};

    if (transport == .plaintext) {
        smtp.runSessionDiag(cfg, .{
            .r = &stream_reader.interface,
            .w = &stream_writer.interface,
        }, &diag) catch |err| fatalSession(err, addr, port, &diag);
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

    smtp.runSessionDiag(cfg, .{
        .r = &tls_client.reader,
        .w = &tls_client.writer,
        .below = &stream_writer.interface,
    }, &diag) catch |err| fatalSession(err, addr, port, &diag);

    tls_client.end() catch {}; // close_notify, best effort — QUIT already got 221
    stream_writer.interface.flush() catch {};

    if (handshake_only) {
        std.debug.print("smtp-notify: TLS handshake + EHLO ok via {s}:{d}\n", .{ addr, port });
    } else {
        std.debug.print("smtp-notify: delivered via {s}:{d} (TLS)\n", .{ addr, port });
    }
}

fn fatalSession(err: smtp.Error, addr: []const u8, port: u16, diag: *const smtp.Diagnostic) noreturn {
    // The server's own words, when it got as far as saying any. Without this a
    // 535, a 550 and a 554 are one indistinguishable failure in the log
    // (issue #3). Only server bytes reach `diag`; no credential can.
    if (diag.code != 0) {
        std.debug.print(
            "smtp-notify: {s}:{d} replied {d} at the {t} step: {s}{s}\n",
            .{ addr, port, diag.code, diag.phase, diag.text(), if (diag.truncated) " […]" else "" },
        );
    }
    switch (err) {
        error.TransientFailure => fatal("{s}:{d} replied 4xx (transient failure) — retry later", .{ addr, port }),
        error.PermanentFailure => fatal("{s}:{d} replied 5xx (permanent failure) — check credentials/addresses", .{ addr, port }),
        error.ProtocolError => fatal("{s}:{d} sent a reply outside the proven protocol table", .{ addr, port }),
        error.HeaderInjection => fatal("CR/LF in a header-bound input (from/to/subject) — refusing to send", .{}),
        error.NoRecipients => fatal("MAIL_TO contains no recipients", .{}),
        error.ReplyMalformed => fatal("{s}:{d} sent something that is not an SMTP reply line", .{ addr, port }),
        else => fatal("session with {s}:{d} failed: {t}", .{ addr, port, err }),
    }
}
