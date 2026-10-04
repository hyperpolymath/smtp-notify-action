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
//!   MAIL_SUBJECT         Subject: value (non-ASCII sent as RFC 2047 UTF-8
//!                        encoded-words; CR/LF and invalid UTF-8 rejected)
//!   MAIL_CONTENT_LANGUAGE optional RFC 3282 list of RFC 5646 tags ("en-GB",
//!                        "en, cy"); malformed values rejected, never repaired
//!   MAIL_BODY            plain-text body (dot-stuffed on the wire)
//!   SMTP_HANDSHAKE_ONLY  "true" = greeting + EHLO + QUIT, no auth, no mail
//!   SMTP_DIAGNOSE        "true" = non-delivery probe reporting DNS, TCP, TLS,
//!                        EHLO and AUTH as separate stages; no credential is
//!                        sent and no mail is sent

const std = @import("std");
const smtp = @import("smtp.zig");
const nntp = @import("nntp.zig");
// Vendored std TLS client + certificate_request patch (ziglang/zig#19521);
// see the provenance header in that file. Swap back to std.crypto.tls.Client
// when upstream can answer a client-certificate request.
const TlsClient = @import("tls/Client.zig");

const tls_buf_len = std.crypto.tls.max_ciphertext_record_len;

/// Print one prefixed line to stderr and exit 1. Every configuration and
/// session failure ends here, so the step fails loudly and says why.
fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("smtp-notify: " ++ fmt ++ "\n", args);
    std.process.exit(1);
}

const Env = std.process.Environ.Map;

/// Look up an environment variable; null when it is unset.
fn env(map: *const Env, name: []const u8) ?[]const u8 {
    return map.get(name);
}

/// A required environment variable. Unset and empty are both fatal.
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

/// Which protocol this run speaks.
///
/// Chosen by name, never inferred from which inputs happen to be set. A
/// workflow that sets `newsgroups` by mistake while meaning to send mail
/// should be told so, not quietly switched onto a different wire protocol —
/// and vice versa.
pub const Protocol = enum { smtp, nntp };

/// Parse `SMTP_PROTOCOL`, fail-closed. Unset or empty means SMTP, which is
/// what every existing workflow means.
fn parseProtocol(map: *const Env) Protocol {
    const v = env(map, "SMTP_PROTOCOL") orelse return .smtp;
    if (v.len == 0) return .smtp;
    if (std.ascii.eqlIgnoreCase(v, "smtp")) return .smtp;
    if (std.ascii.eqlIgnoreCase(v, "nntp")) return .nntp;
    fatal("SMTP_PROTOCOL is \"{s}\", which is neither \"smtp\" nor \"nntp\"", .{v});
}

/// The port a transport implies when the workflow did not name one.
///
/// These are the registered defaults, not guesses: 465/587/25 for SMTP
/// (RFC 8314 §3.3 and the submission port) and 563/119 for NNTP
/// (RFC 3977 §4, RFC 4642 §3). Naming one explicitly always wins.
fn defaultPort(protocol: Protocol, transport: Transport) u16 {
    return switch (protocol) {
        .smtp => switch (transport) {
            .implicit_tls => 465,
            .starttls => 587,
            .plaintext => 25,
        },
        .nntp => switch (transport) {
            .implicit_tls => 563,
            .starttls, .plaintext => 119,
        },
    };
}

/// `SMTP_PORT` when the workflow set one, otherwise the transport's default.
///
/// The action's own `server_port` input defaults to empty now, precisely so
/// this choice can be made by protocol: a fixed 465 in action.yml would send
/// an NNTP run to the SMTP port unless the user knew to override it.
fn resolvePort(map: *const Env, protocol: Protocol, transport: Transport) u16 {
    const v = env(map, "SMTP_PORT") orelse return defaultPort(protocol, transport);
    if (v.len == 0) return defaultPort(protocol, transport);
    return std.fmt.parseInt(u16, v, 10) catch
        fatal("SMTP_PORT is not a port number: {s}", .{v});
}

const default_timeout_seconds: u32 = 60;

/// A positive whole number of seconds from the environment, or `default`
/// when unset or empty. Zero is refused: a run with no deadline is not offered.
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
    // In a diagnose run, a deadline is itself a stage result: say which stage
    // was in flight, so "the TLS handshake never finished" (e.g. implicit TLS
    // aimed at a STARTTLS port) does not read as a generic hang.
    const in_flight = diagnose_stage.load(.acquire);
    if (in_flight != no_stage) {
        const stage: Stage = @enumFromInt(in_flight);
        stageFail(stage, "no result within {d}s{s}", .{ seconds, timeoutHint(stage) });
    }
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

/// Open a TCP stream to `host:port` without a connect timeout. The only
/// place `IpAddress.ConnectOptions` is built; see `SafeConnectOptions`.
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

/// Entry point: read configuration from the environment, start the whole-run
/// watchdog, then run a delivery, a handshake-only probe, or a diagnose probe.
pub fn main(init: std.process.Init.Minimal) !void {
    const gpa = std.heap.smp_allocator;

    var threaded: std.Io.Threaded = .init(gpa, .{ .environ = init.environ });
    defer threaded.deinit();
    const io = threaded.io();

    var env_map = init.environ.createMap(gpa) catch |err| fatal("{t}", .{err});
    const envs = &env_map;

    const addr = envRequired(envs, "SMTP_ADDR");
    const transport = parseTransport(envs);
    const protocol = parseProtocol(envs);
    const port = resolvePort(envs, protocol, transport);
    const diagnose = envFlag(envs, "SMTP_DIAGNOSE", false);
    // Both flags are parsed before either is used, so a malformed value is
    // rejected even when the other one would have decided the run.
    const handshake_flag = envFlag(envs, "SMTP_HANDSHAKE_ONLY", false);
    // A diagnose run never authenticates and never sends: it walks the same
    // handshake-only session, and reports each stage as it is reached.
    const handshake_only = diagnose or handshake_flag;
    const timeout_seconds = envSeconds(envs, "SMTP_TIMEOUT_SECONDS", default_timeout_seconds);

    // Each protocol's inputs are checked against the protocol, not against
    // the other one's, so a workflow that mixes them is told which mistake it
    // made. Both checks happen before the watchdog starts: a configuration
    // error is not a timeout.
    const newsgroups = env(envs, "MAIL_NEWSGROUPS");
    switch (protocol) {
        .smtp => if (newsgroups != null and newsgroups.?.len != 0) fatal(
            "MAIL_NEWSGROUPS is set but SMTP_PROTOCOL is smtp (the default). " ++
                "Refusing to guess whether you meant mail or news; set SMTP_PROTOCOL: nntp, " ++
                "or use MAIL_TO for mail.",
            .{},
        ),
        .nntp => {
            if (newsgroups == null or newsgroups.?.len == 0) fatal(
                "SMTP_PROTOCOL is nntp but MAIL_NEWSGROUPS is empty. " ++
                    "One or more newsgroup names are required, e.g. \"alt.test\".",
                .{},
            );
            if (diagnose) fatal(
                "SMTP_DIAGNOSE is an SMTP probe and is not implemented for NNTP. " ++
                    "For a news-server reachability probe use SMTP_HANDSHAKE_ONLY: true, " ++
                    "which performs the TLS handshake, CAPABILITIES, and QUIT.",
                .{},
            );
        },
    }

    // Detached: it either fires and exits the process, or the process exits
    // first and takes it with it.
    if (std.Thread.spawn(.{}, watchdog, .{ io, timeout_seconds })) |t| {
        t.detach();
    } else |err| {
        fatal("cannot start the timeout watchdog: {t}", .{err});
    }

    const now: std.Io.Timestamp = .now(io, .real);

    if (protocol == .nntp) {
        return runNews(gpa, io, envs, addr, port, transport, handshake_only, now);
    }

    var cfg: smtp.Config = if (handshake_only) .{
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
            .content_language = env(envs, "MAIL_CONTENT_LANGUAGE") orelse "",
            .body = envRequired(envs, "MAIL_BODY"),
            .date_epoch_seconds = now.toSeconds(),
            .handshake_only = false,
        };
    };

    const host = std.Io.net.HostName.init(addr) catch
        fatal("invalid host name: {s}", .{addr});

    if (diagnose) runDiagnose(gpa, io, envs, host, addr, port, transport, cfg, now);

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
        if (handshake_only) {
            std.debug.print("smtp-notify: handshake + EHLO ok via {s}:{d} (plaintext)\n", .{ addr, port });
        } else {
            std.debug.print("smtp-notify: delivered via {s}:{d} (plaintext)\n", .{ addr, port });
        }
        return;
    }

    // TLS resources for BOTH encrypted transports. A STARTTLS session needs
    // them ready before the upgrade — the driver calls back mid-session and
    // there is nowhere to report an allocation failure from inside it.
    var tls_env: TlsEnv = undefined;
    tls_env.init(gpa, io, now);
    const tls_options = tls_env.options(gpa, io, addr, now);

    // Certificate verification is identical on both paths: the same CA
    // bundle, the same explicit host name, the same defaults. STARTTLS
    // differs only in WHEN the handshake happens, never in how strictly it
    // is checked — a "starttls is the lenient one" asymmetry is how
    // opportunistic TLS becomes no TLS.
    var tls_client: TlsClient = undefined;

    if (transport == .starttls) {
        var upgrade: TlsUpgrade = .{
            .client = &tls_client,
            .options = tls_options,
            .input = &stream_reader.interface,
            .output = &stream_writer.interface,
            .addr = addr,
            .port = port,
        };
        cfg.use_starttls = true;
        cfg.upgrader = .{ .ctx = &upgrade, .upgradeFn = TlsUpgrade.run };

        // Starts on the bare socket; the driver replaces its own wire when
        // the server accepts STARTTLS, and refuses to go on if it does not.
        smtp.runSessionDiag(cfg, .{
            .r = &stream_reader.interface,
            .w = &stream_writer.interface,
        }, &diag) catch |err| fatalSession(err, addr, port, &diag);

        if (upgrade.handshook) tls_client.end() catch {};
        stream_writer.interface.flush() catch {};

        if (handshake_only) {
            std.debug.print("smtp-notify: STARTTLS handshake + EHLO ok via {s}:{d}\n", .{ addr, port });
        } else {
            std.debug.print("smtp-notify: delivered via {s}:{d} (STARTTLS)\n", .{ addr, port });
        }
        return;
    }

    tls_client = TlsClient.init(
        &stream_reader.interface,
        &stream_writer.interface,
        tls_options,
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

/// Everything a TLS client needs that must outlive the handshake: buffers,
/// entropy, and the system CA bundle. One definition for every path that
/// speaks TLS — delivery on 465, delivery on 587, and the diagnose probe —
/// so verification cannot quietly differ between them. The options returned
/// point into this struct, so it must stay where it was initialised.
const TlsEnv = struct {
    read_buf: []u8,
    write_buf: []u8,
    entropy: [TlsClient.Options.entropy_len]u8,
    bundle: std.crypto.Certificate.Bundle,
    lock: std.Io.RwLock,

    /// Allocate the buffers, draw entropy and load the system CA bundle. Fatal on failure.
    fn init(self: *TlsEnv, gpa: std.mem.Allocator, io: std.Io, now: std.Io.Timestamp) void {
        self.read_buf = gpa.alloc(u8, tls_buf_len + 4096) catch |err| fatal("{t}", .{err});
        self.write_buf = gpa.alloc(u8, 4096) catch |err| fatal("{t}", .{err});
        io.random(&self.entropy);
        self.bundle = .empty;
        self.bundle.rescan(gpa, io, now) catch |err|
            fatal("cannot load the system CA bundle: {t}", .{err});
        self.lock = .init;
    }

    /// Client options for `addr`: explicit host, system CA bundle, default checks.
    fn options(self: *TlsEnv, gpa: std.mem.Allocator, io: std.Io, addr: []const u8, now: std.Io.Timestamp) TlsClient.Options {
        return .{
            .host = .{ .explicit = addr },
            .ca = .{ .bundle = .{
                .gpa = gpa,
                .io = io,
                .lock = &self.lock,
                .bundle = &self.bundle,
            } },
            .read_buffer = self.read_buf,
            .write_buffer = self.write_buf,
            .entropy = &self.entropy,
            .realtime_now = now,
            // SMTP replies carry no length framing, so keep truncation-attack
            // detection on (the default) — unlike HTTP, we cannot detect a
            // cut-off stream at the application layer.
        };
    }
};

// ---------------------------------------------------------------------------
// Diagnose: a non-delivery probe that names the stage that failed.
// ---------------------------------------------------------------------------

const Stage = enum(u8) { DNS, TCP, TLS, EHLO, AUTH, MSG };

/// The transport under diagnosis, for the watchdog's hint.
var diagnose_transport: Transport = .implicit_tls;

/// What a stall at `stage` most often means, so a timeout names a likely
/// cause instead of only a stage.
fn timeoutHint(stage: Stage) []const u8 {
    return switch (stage) {
        .DNS => " (the resolver did not answer)",
        .TCP => " (packets to that port are being dropped, e.g. by a firewall)",
        .TLS => if (diagnose_transport == .starttls)
            " (the STARTTLS handshake never completed)"
        else
            " (the TLS handshake never completed: implicit TLS aimed at a plaintext or STARTTLS port such as 587? use secure: starttls there)",
        .EHLO => if (diagnose_transport == .implicit_tls)
            " (the server went quiet after the handshake)"
        else
            " (no greeting: a cleartext client aimed at an implicit-TLS port such as 465? use secure: true there)",
        .AUTH, .MSG => "",
    };
}

/// The diagnose stage in flight, for the watchdog. `no_stage` outside a
/// diagnose run, so ordinary delivery keeps its ordinary timeout message.
const no_stage: u8 = 0xff;
var diagnose_stage: std.atomic.Value(u8) = .init(no_stage);

/// Record the diagnose stage now in flight, for the watchdog to report.
fn enter(stage: Stage) void {
    diagnose_stage.store(@intFromEnum(stage), .release);
}

/// Stages already given a line, so a failure lists exactly the ones left.
/// Order matters less than completeness: on STARTTLS the EHLO precedes the
/// TLS upgrade, so "everything after the failed enum value" would drop TLS.
var reported_stages: std.atomic.Value(u8) = .init(0);

/// Print one diagnose stage line and mark the stage as reported.
fn stageLine(stage: Stage, status: []const u8, comptime fmt: []const u8, args: anytype) void {
    _ = reported_stages.fetchOr(@as(u8, 1) << @as(u3, @intCast(@intFromEnum(stage))), .acq_rel);
    if (fmt.len == 0) {
        std.debug.print("smtp-notify: diagnose: {s:<4} {s}\n", .{ @tagName(stage), status });
    } else {
        std.debug.print("smtp-notify: diagnose: {s:<4} {s:<11} " ++ fmt ++ "\n", .{ @tagName(stage), status } ++ args);
    }
}

/// Report `failed` and every later stage as not reached, then exit 1. Each
/// line is one stage, so a log reader (or a screen reader) gets the answer
/// from the first word that is not "ok" without parsing a sentence.
fn stageFail(failed: Stage, comptime fmt: []const u8, args: anytype) noreturn {
    stageLine(failed, "FAIL", fmt, args);
    inline for (@typeInfo(Stage).@"enum".fields) |f| {
        if (reported_stages.load(.acquire) & (@as(u8, 1) << f.value) == 0)
            stageLine(@enumFromInt(f.value), "not-reached", "", .{});
    }
    std.debug.print("smtp-notify: diagnose: FAILED at {s}; nothing was authenticated or sent\n", .{@tagName(failed)});
    std.process.exit(1);
}

/// Print the capabilities the server advertised at EHLO, one line.
fn capsSummary(caps: *const smtp.Capabilities) void {
    var size_buf: [32]u8 = undefined;
    // RFC 1870: SIZE 0 means "no fixed limit", and no SIZE line means the
    // server did not say. Neither is a limit of zero bytes.
    const size: []const u8 = if (caps.size) |n|
        (if (n == 0) "no-limit" else std.fmt.bufPrint(&size_buf, "{d}", .{n}) catch "?")
    else
        "unstated";
    std.debug.print(
        "smtp-notify: diagnose:      capabilities: STARTTLS={s} 8BITMIME={s} SIZE={s} AUTH=[{s}]\n",
        .{
            if (caps.starttls) "yes" else "no",
            if (caps.eight_bit_mime) "yes" else "no",
            size,
            caps.authMechanisms(),
        },
    );
}

/// Walk DNS, TCP, TLS, EHLO and AUTH as separate, individually reported
/// stages, then exit. Never returns: success exits 0, any failure exits 1
/// naming the stage.
///
/// What each stage actually establishes, stated so the output is not read
/// as more than it is:
///   DNS  — the name resolved, and to what.
///   TCP  — a connection to that port was accepted.
///   TLS  — a verified handshake (implicit, or STARTTLS on the cleartext
///          session); "skipped" when the transport is plaintext by choice.
///   EHLO — the server greeted and answered EHLO (the post-upgrade EHLO on
///          STARTTLS); its capabilities are printed.
///   AUTH — which mechanism this client WOULD use, from the advertisement
///          that survived TLS. No credential is sent, so this stage cannot
///          tell a right password from a wrong one; it tells "this client can
///          talk to this server's AUTH" from "it cannot".
fn runDiagnose(
    gpa: std.mem.Allocator,
    io: std.Io,
    envs: *const Env,
    host: std.Io.net.HostName,
    addr: []const u8,
    port: u16,
    transport: Transport,
    cfg_in: smtp.Config,
    now: std.Io.Timestamp,
) noreturn {
    var cfg = cfg_in;
    std.debug.assert(cfg.handshake_only);
    diagnose_transport = transport;
    std.debug.print("smtp-notify: diagnose: probing {s}:{d} ({t}); no credential and no mail will be sent\n", .{ addr, port, transport });

    // The message inputs are checked now (no server needed) and reported
    // last, so a local refusal never hides the server's answer.
    const msg_verdict = checkMessageInputs(gpa, envs);

    // ---- DNS -------------------------------------------------------------
    enter(.DNS);
    var canonical: [std.Io.net.HostName.max_len]u8 = undefined;
    var lookup_buf: [32]std.Io.net.HostName.LookupResult = undefined;
    var lookup_q: std.Io.Queue(std.Io.net.HostName.LookupResult) = .init(&lookup_buf);
    // Resolve concurrently with draining, as std's own connectMany does: a
    // synchronous lookup blocks forever once a name has more results than
    // the queue holds (observed at 32 /etc/hosts entries for one name).
    var lookup_future = io.async(std.Io.net.HostName.lookup, .{
        host, io, &lookup_q, std.Io.net.HostName.LookupOptions{ .port = port, .canonical_name_buffer = &canonical },
    });
    var shown: [256]u8 = undefined;
    var shown_w: std.Io.Writer = .fixed(&shown);
    var n_addr: usize = 0;
    while (lookup_q.getOne(io)) |r| switch (r) {
        .address => |a| {
            if (n_addr < 4) {
                if (n_addr != 0) shown_w.writeAll(", ") catch {};
                a.format(&shown_w) catch {};
            }
            n_addr += 1;
        },
        .canonical_name => {},
    } else |err| switch (err) {
        error.Closed => {},
        error.Canceled => stageFail(.DNS, "lookup was cancelled", .{}),
    }
    lookup_future.await(io) catch |err|
        stageFail(.DNS, "{s} did not resolve: {t}", .{ addr, err });
    if (n_addr == 0) stageFail(.DNS, "{s} resolved to no address", .{addr});
    stageLine(.DNS, "ok", "{s} -> {s}{s}", .{ addr, shown_w.buffered(), if (n_addr > 4) " …" else "" });

    // ---- TCP -------------------------------------------------------------
    enter(.TCP);
    var stream = connectNoTimeout(host, io, port, .{ .mode = .stream }) catch |err|
        stageFail(.TCP, "cannot connect to {s}:{d}: {t}", .{ addr, port, err });
    defer stream.close(io);
    stageLine(.TCP, "ok", "connected to port {d}", .{port});

    const socket_read_buf = gpa.alloc(u8, tls_buf_len) catch |err| fatal("{t}", .{err});
    const stream_write_buf = gpa.alloc(u8, tls_buf_len) catch |err| fatal("{t}", .{err});
    var stream_reader = stream.reader(io, socket_read_buf);
    var stream_writer = stream.writer(io, stream_write_buf);
    var diag: smtp.Diagnostic = .{};

    // Implicit TLS handshakes before the greeting; STARTTLS and plaintext
    // meet the greeting and EHLO first. The in-flight stage follows that.
    enter(if (transport == .implicit_tls) .TLS else .EHLO);
    switch (transport) {
        .plaintext => {
            smtp.runSessionDiag(cfg, .{
                .r = &stream_reader.interface,
                .w = &stream_writer.interface,
            }, &diag) catch |err| {
                stageLine(.TLS, "skipped", "plaintext transport selected (SMTP_SECURE=plaintext)", .{});
                stageFail(.EHLO, "{t}{s}", .{ err, replySuffix(&diag) });
            };
            stageLine(.TLS, "skipped", "plaintext transport selected (SMTP_SECURE=plaintext)", .{});
        },
        .implicit_tls => {
            var tls_env: TlsEnv = undefined;
            tls_env.init(gpa, io, now);
            var tls_client = TlsClient.init(
                &stream_reader.interface,
                &stream_writer.interface,
                tls_env.options(gpa, io, addr, now),
            ) catch |err| stageFail(.TLS, "handshake failed: {t} (is this an implicit-TLS port? 465 is; 587 needs SMTP_SECURE: starttls)", .{err});
            stageLine(.TLS, "ok", "implicit TLS, certificate verified for {s}", .{addr});
            enter(.EHLO);
            smtp.runSessionDiag(cfg, .{
                .r = &tls_client.reader,
                .w = &tls_client.writer,
                .below = &stream_writer.interface,
            }, &diag) catch |err| stageFail(.EHLO, "{t}{s}", .{ err, replySuffix(&diag) });
            tls_client.end() catch {};
            stream_writer.interface.flush() catch {};
        },
        .starttls => {
            var tls_env: TlsEnv = undefined;
            tls_env.init(gpa, io, now);
            var tls_client: TlsClient = undefined;
            var upgrade: TlsUpgrade = .{
                .client = &tls_client,
                .options = tls_env.options(gpa, io, addr, now),
                .input = &stream_reader.interface,
                .output = &stream_writer.interface,
                .addr = addr,
                .port = port,
                .diagnosing = true,
            };
            cfg.use_starttls = true;
            cfg.upgrader = .{ .ctx = &upgrade, .upgradeFn = TlsUpgrade.run };
            smtp.runSessionDiag(cfg, .{
                .r = &stream_reader.interface,
                .w = &stream_writer.interface,
            }, &diag) catch |err| switch (err) {
                error.StartTlsNotOffered => {
                    stageLine(.EHLO, "ok", "server answered the cleartext EHLO", .{});
                    stageFail(.TLS, "server did not advertise STARTTLS (advertised: STARTTLS=no, AUTH=[{s}])", .{diag.caps.authMechanisms()});
                },
                error.StartTlsUpgradeFailed => {
                    stageLine(.EHLO, "ok", "server answered the cleartext EHLO", .{});
                    stageFail(.TLS, "server accepted STARTTLS but the handshake failed: {s}", .{
                        if (upgrade.failure) |e| @errorName(e) else "unknown",
                    });
                },
                else => if (upgrade.handshook) {
                    // The upgrade worked; whatever failed came after it,
                    // even if no post-upgrade reply was read yet.
                    stageLine(.TLS, "ok", "STARTTLS upgrade, certificate verified for {s}", .{addr});
                    stageFail(.EHLO, "post-upgrade EHLO failed: {t}{s}", .{ err, replySuffix(&diag) });
                } else switch (diag.phase) {
                    .starttls => {
                        stageLine(.EHLO, "ok", "server answered the cleartext EHLO", .{});
                        stageFail(.TLS, "server refused STARTTLS: {t}{s}", .{ err, replySuffix(&diag) });
                    },
                    .ehlo_tls => {
                        stageLine(.TLS, "ok", "STARTTLS upgrade, certificate verified for {s}", .{addr});
                        stageFail(.EHLO, "post-upgrade EHLO failed: {t}{s}", .{ err, replySuffix(&diag) });
                    },
                    else => stageFail(.EHLO, "{t}{s}", .{ err, replySuffix(&diag) }),
                },
            };
            stageLine(.TLS, "ok", "STARTTLS upgrade, certificate verified for {s}", .{addr});
            if (upgrade.handshook) tls_client.end() catch {};
            stream_writer.interface.flush() catch {};
        },
    }

    // ---- EHLO ------------------------------------------------------------
    stageLine(.EHLO, "ok", "server answered EHLO{s}", .{if (transport == .starttls) " (after the upgrade)" else ""});
    capsSummary(&diag.caps);

    // ---- AUTH ------------------------------------------------------------
    enter(.AUTH);
    if (smtp.chooseMechanism(&diag.caps)) |m| {
        if (diag.caps.authMechanisms().len == 0) {
            stageLine(.AUTH, "ok", "server lists no mechanisms; this client would try PLAIN (credentials not sent, not verified)", .{});
        } else {
            stageLine(.AUTH, "ok", "this client would use {s} (credentials not sent, not verified)", .{switch (m) {
                .plain => "PLAIN",
                .login => "LOGIN",
            }});
        }
    } else {
        stageFail(.AUTH, "no mechanism this client speaks (PLAIN, LOGIN); advertised: {s}. XOAUTH2 needs an OAuth token, which no password secret can supply", .{diag.caps.authMechanisms()});
    }
    // ---- MSG -------------------------------------------------------------
    enter(.MSG);
    switch (msg_verdict) {
        .ok => stageLine(.MSG, "ok", "from/to/subject/content_language would be accepted", .{}),
        .none => stageLine(.MSG, "skipped", "no message inputs set", .{}),
        .refused => |e| stageFail(.MSG, "a real send would be refused before connecting: {s}", .{msgReason(e)}),
    }
    std.debug.print("smtp-notify: diagnose: all stages ok; nothing was authenticated or sent\n", .{});
    std.process.exit(0);
}

const MsgVerdict = union(enum) { ok, none, refused: smtp.SessionError };

/// Validate whatever message inputs are present with the same predicate the
/// delivery path runs, without requiring any of them.
fn checkMessageInputs(gpa: std.mem.Allocator, envs: *const Env) MsgVerdict {
    const from = env(envs, "MAIL_FROM") orelse "";
    const to = env(envs, "MAIL_TO") orelse "";
    const subject = env(envs, "MAIL_SUBJECT") orelse "";
    const lang = env(envs, "MAIL_CONTENT_LANGUAGE") orelse "";
    if (from.len + to.len + subject.len + lang.len == 0) return .none;
    // Split on the same separators as delivery. CR/LF are not separators, so
    // an injected recipient stays inside one token and is caught below.
    var recipients: std.ArrayList([]const u8) = .empty;
    var it = std.mem.tokenizeAny(u8, to, ", \t");
    while (it.next()) |rcpt| recipients.append(gpa, rcpt) catch |err| fatal("{t}", .{err});
    smtp.validateMessage(.{
        .ehlo_domain = "github-actions",
        .username = "",
        .password = "",
        .from = from,
        .recipients = recipients.items,
        .subject = subject,
        .content_language = lang,
        .body = "",
        .date_epoch_seconds = 0,
    }) catch |err| return .{ .refused = err };
    return .ok;
}

/// Plain-language reason for a message-input refusal, for the MSG stage.
fn msgReason(err: smtp.SessionError) []const u8 {
    return switch (err) {
        error.HeaderInjection => "CR/LF in from, to, subject or content_language",
        error.ContentLanguageInvalid => "content_language is not a comma-separated list of language tags",
        error.SubjectNotUtf8 => "subject has non-ASCII bytes that are not valid UTF-8",
        else => @errorName(err),
    };
}

/// The server's last words, when it said any, for a stage failure line.
fn replySuffix(diag: *const smtp.Diagnostic) []const u8 {
    if (diag.code == 0) return "";
    const S = struct {
        var clean: [smtp.reply_text_max * 3]u8 = undefined;
        var buf: [smtp.reply_text_max * 3 + 64]u8 = undefined;
    };
    const text = smtp.sanitizeServerText(&S.clean, diag.text());
    return std.fmt.bufPrint(&S.buf, " — last server reply {d}: {s}", .{ diag.code, text }) catch " — (server reply too long to show)";
}

/// Performs the in-place TLS handshake the SMTP driver asks for once the
/// server has accepted STARTTLS.
///
/// src/smtp.zig deliberately knows nothing about TLS, so the handshake
/// arrives as a callback. Everything it needs is captured before the session
/// starts: by the time this runs, the socket is mid-dialogue and there is no
/// way to report a setup failure other than aborting the session.
const TlsUpgrade = struct {
    /// Storage owned by `main`, so the client outlives this callback.
    client: *TlsClient,
    options: TlsClient.Options,
    input: *std.Io.Reader,
    output: *std.Io.Writer,
    addr: []const u8,
    port: u16,
    /// Set once the handshake succeeds, so main knows whether a close_notify
    /// is owed. Sending one over a client that never handshook is undefined.
    handshook: bool = false,
    /// In a diagnose run the failure is reported on the TLS stage line
    /// instead of printed here, and the in-flight stage follows the upgrade.
    diagnosing: bool = false,
    failure: ?anyerror = null,

    /// The upgrade callback: handshake over the existing socket and hand back the
    /// encrypted stream, or fail the session.
    fn run(ctx: *anyopaque) anyerror!smtp.Wire {
        const self: *TlsUpgrade = @ptrCast(@alignCast(ctx));
        if (self.diagnosing) enter(.TLS);
        self.client.* = TlsClient.init(self.input, self.output, self.options) catch |err| {
            self.failure = err;
            if (self.diagnosing) return err;
            // Distinguish "the server would not upgrade" from "the upgrade
            // itself failed": they need opposite fixes, and the session error
            // that follows cannot tell them apart on its own.
            std.debug.print(
                "smtp-notify: {s}:{d} accepted STARTTLS but the TLS handshake failed: {t}\n",
                .{ self.addr, self.port, err },
            );
            return err;
        };
        self.handshook = true;
        if (self.diagnosing) enter(.EHLO);
        return .{
            .r = &self.client.reader,
            .w = &self.client.writer,
            // Encrypted records still have to reach the socket.
            .below = self.output,
        };
    }
};

/// Report a failed session — the server's own words where it gave any, the
/// AUTH mechanisms on offer where AUTH failed — and exit 1.
/// A Message-ID for the one article this run posts: `<epoch.nonce@host>`.
///
/// RFC 5536 §3.1.2 requires a posted article to carry one, and requires it to
/// be unique worldwide — a server that has seen the identifier before may
/// silently drop the second article as a duplicate. The epoch part orders
/// posts; the nonce is what makes two runs in the same second distinct, which
/// matters because concurrent workflow runs are ordinary. Without the nonce a
/// retry or a second job in the same second could be discarded by the server
/// while this step reported success.
fn newsMessageId(gpa: std.mem.Allocator, io: std.Io, now: i64) []const u8 {
    var nonce: [8]u8 = undefined;
    io.random(&nonce);

    // The right-hand side is by convention a domain the poster can be reached
    // at; for a runner, that is its own host name. If it cannot be read, or
    // contains nothing usable, say so in the identifier rather than inventing
    // a domain that belongs to someone else — `.invalid` is reserved for
    // exactly this (RFC 2606 §2).
    var host_buf: [std.posix.HOST_NAME_MAX]u8 = undefined;
    var host: []const u8 = "unknown.invalid";
    if (std.posix.gethostname(&host_buf)) |name| {
        var kept: usize = 0;
        for (name) |c| {
            if (std.ascii.isAlphanumeric(c) or c == '-' or c == '.') {
                host_buf[kept] = c;
                kept += 1;
            }
        }
        if (kept > 0) host = host_buf[0..kept];
    } else |_| {}

    return std.fmt.allocPrint(gpa, "<{d}.{x}@{s}>", .{ now, nonce, host }) catch |err|
        fatal("cannot build a Message-ID: {t}", .{err});
}

/// Run an NNTP posting session over the transport `SMTP_SECURE` selected.
///
/// Mirrors the SMTP path deliberately: the same connection, the same TLS
/// verification, the same watchdog, the same fail-closed rule that a server
/// which will not encrypt is an error rather than a downgrade. What differs
/// is only the dialogue, which lives in src/nntp.zig and is driven by the
/// proven tables in spec/Nntp/.
fn runNews(
    gpa: std.mem.Allocator,
    io: std.Io,
    envs: *const Env,
    addr: []const u8,
    port: u16,
    transport: Transport,
    handshake_only: bool,
    now: std.Io.Timestamp,
) void {
    // NNTP always authenticates here. A server that permits anonymous posting
    // is a server this client cannot drive — stated in README and
    // KNOWN-DEFECTS rather than papered over with an empty AUTHINFO pair,
    // which would put a blank username on the wire and still fail.
    const user = env(envs, "SMTP_USER") orelse "";
    const pass = env(envs, "SMTP_PASS") orelse "";
    if (!handshake_only and (user.len == 0 or pass.len == 0)) fatal(
        "posting to a newsgroup authenticates (AUTHINFO USER/PASS), and " ++
            "SMTP_USER or SMTP_PASS is empty. Anonymous posting is not implemented.",
        .{},
    );

    var cfg: nntp.Config = if (handshake_only) .{
        .username = "",
        .password = "",
        .from = "",
        .newsgroups = envRequired(envs, "MAIL_NEWSGROUPS"),
        .subject = "",
        .body = "",
        .date_epoch_seconds = 0,
        .message_id = "<handshake-only@invalid>",
        .handshake_only = true,
    } else .{
        .username = user,
        .password = pass,
        .from = envRequired(envs, "MAIL_FROM"),
        .newsgroups = envRequired(envs, "MAIL_NEWSGROUPS"),
        .subject = envRequired(envs, "MAIL_SUBJECT"),
        .content_language = env(envs, "MAIL_CONTENT_LANGUAGE") orelse "",
        .body = envRequired(envs, "MAIL_BODY"),
        .date_epoch_seconds = now.toSeconds(),
        .message_id = newsMessageId(gpa, io, now.toSeconds()),
        .handshake_only = false,
    };
    cfg.use_starttls = transport == .starttls;

    // Everything checkable without a server is checked BEFORE the socket is
    // opened. The driver checks again (it is the last line of defence against
    // a caller that skipped this), but doing it here means a typo in a
    // newsgroup name is reported as a typo rather than as a connection
    // failure to a server that is merely unreachable, and an injecting input
    // never causes a TCP connection to a news server at all.
    nntp.validateArticle(cfg) catch |err| fatalNewsSession(err, addr, port, null);

    const host = std.Io.net.HostName.init(addr) catch
        fatal("invalid host name: {s}", .{addr});

    var stream = connectNoTimeout(host, io, port, .{ .mode = .stream }) catch |err|
        fatal("cannot connect to {s}:{d}: {t}", .{ addr, port, err });
    defer stream.close(io);

    const socket_read_buf = gpa.alloc(u8, tls_buf_len) catch |err| fatal("{t}", .{err});
    const stream_write_buf = gpa.alloc(u8, tls_buf_len) catch |err| fatal("{t}", .{err});
    var stream_reader = stream.reader(io, socket_read_buf);
    var stream_writer = stream.writer(io, stream_write_buf);

    var diag: nntp.Diagnostic = .{};

    if (transport == .plaintext) {
        nntp.runSessionDiag(cfg, .{
            .r = &stream_reader.interface,
            .w = &stream_writer.interface,
        }, &diag) catch |err| fatalNewsSession(err, addr, port, &diag);
        if (handshake_only) {
            std.debug.print("smtp-notify: NNTP handshake + CAPABILITIES ok via {s}:{d} (plaintext)\n", .{ addr, port });
        } else {
            std.debug.print("smtp-notify: posted to {s} via {s}:{d} (plaintext)\n", .{ cfg.newsgroups, addr, port });
        }
        return;
    }

    var tls_env: TlsEnv = undefined;
    tls_env.init(gpa, io, now);
    const tls_options = tls_env.options(gpa, io, addr, now);

    var tls_client: TlsClient = undefined;

    if (transport == .starttls) {
        var upgrade: TlsUpgrade = .{
            .client = &tls_client,
            .options = tls_options,
            .input = &stream_reader.interface,
            .output = &stream_writer.interface,
            .addr = addr,
            .port = port,
        };
        cfg.upgrader = .{ .ctx = &upgrade, .upgradeFn = TlsUpgrade.run };

        nntp.runSessionDiag(cfg, .{
            .r = &stream_reader.interface,
            .w = &stream_writer.interface,
        }, &diag) catch |err| fatalNewsSession(err, addr, port, &diag);

        if (upgrade.handshook) tls_client.end() catch {};
        stream_writer.interface.flush() catch {};

        if (handshake_only) {
            std.debug.print("smtp-notify: NNTP STARTTLS handshake + CAPABILITIES ok via {s}:{d}\n", .{ addr, port });
        } else {
            std.debug.print("smtp-notify: posted to {s} via {s}:{d} (STARTTLS)\n", .{ cfg.newsgroups, addr, port });
        }
        return;
    }

    tls_client = TlsClient.init(
        &stream_reader.interface,
        &stream_writer.interface,
        tls_options,
    ) catch |err| fatal("TLS handshake with {s}:{d} failed: {t}", .{ addr, port, err });

    nntp.runSessionDiag(cfg, .{
        .r = &tls_client.reader,
        .w = &tls_client.writer,
        .below = &stream_writer.interface,
    }, &diag) catch |err| fatalNewsSession(err, addr, port, &diag);

    tls_client.end() catch {}; // close_notify, best effort — QUIT already got 205
    stream_writer.interface.flush() catch {};

    if (handshake_only) {
        std.debug.print("smtp-notify: NNTP TLS handshake + CAPABILITIES ok via {s}:{d}\n", .{ addr, port });
    } else {
        std.debug.print("smtp-notify: posted to {s} via {s}:{d} (TLS)\n", .{ cfg.newsgroups, addr, port });
    }
}

/// Report an NNTP session failure the way `fatalSession` reports an SMTP one:
/// the server's own words when it said any, what it advertised when the
/// failure was at authentication, then the one line that names the fix.
fn fatalNewsSession(err: nntp.Error, addr: []const u8, port: u16, maybe_diag: ?*const nntp.Diagnostic) noreturn {
    // Null is the pre-connect case: nothing has been said to or heard from a
    // server, so there is no reply and no capability list to report.
    var empty: nntp.Diagnostic = .{};
    const diag = maybe_diag orelse &empty;
    if (diag.code != 0) {
        var clean: [nntp.reply_text_max * 3]u8 = undefined;
        std.debug.print(
            "smtp-notify: {s}:{d} replied {d} at the {t} step: {s}{s}\n",
            .{ addr, port, diag.code, diag.phase, smtp.sanitizeServerText(&clean, diag.text()), if (diag.truncated) " […]" else "" },
        );
    }
    // The agent/user distinction is the one an operator cannot recover from
    // the exit code alone: 481 wants a different password, "no mechanism we
    // speak" wants a different server or an implementation.
    if (diag.phase == .auth and diag.code != 0) {
        if (diag.caps.authInfoRaw().len > 0) {
            std.debug.print(
                "smtp-notify: this client used AUTHINFO {s}; {s}:{d} advertised: {s}\n",
                .{
                    if (diag.mechanism) |m| @tagName(m) else "(none chosen)",
                    addr,
                    port,
                    diag.caps.authInfoRaw(),
                },
            );
            if (diag.mechanism == null) std.debug.print(
                "smtp-notify: none of those can be driven by this client (USER/PASS only).\n" ++
                    "  SASL needs the 383 continuation exchange, which is not implemented.\n",
                .{},
            );
        } else {
            std.debug.print(
                "smtp-notify: {s}:{d} advertised no AUTHINFO line at all — it may require the\n" ++
                    "  credentials to be sent after STARTTLS. Set SMTP_SECURE: starttls (port 119).\n",
                .{ addr, port },
            );
        }
    }
    switch (err) {
        error.PostingNotPermitted => fatal(
            "{s}:{d} will not accept posts from this session (201 greeting or 440 reply) — " ++
                "posting prohibited for this account or server",
            .{ addr, port },
        ),
        error.ArticleRejected => fatal(
            "{s}:{d} refused the article itself (441) — see its words above; too many groups, " ++
                "a moderated group, or a policy rejection are the usual causes",
            .{ addr, port },
        ),
        error.TransientFailure => fatal("{s}:{d} replied 4xx (transient failure) — retry later", .{ addr, port }),
        error.PermanentFailure => fatal("{s}:{d} replied 5xx (permanent failure) — check credentials/newsgroup", .{ addr, port }),
        error.ProtocolError => fatal("{s}:{d} sent a reply outside the proven protocol table", .{ addr, port }),
        error.HeaderInjection => fatal(
            "CR/LF in a header-bound input (from/newsgroups/subject/content_language/message-id) — refusing to post",
            .{},
        ),
        error.NewsgroupsInvalid => fatal(
            "MAIL_NEWSGROUPS is not a comma-separated list of well-formed newsgroup names " ++
                "(RFC 5536 §3.1.4; `control` and `control.*` are reserved) — refusing to post rather than repair it",
            .{},
        ),
        error.ContentLanguageInvalid => fatal(
            "MAIL_CONTENT_LANGUAGE is not a comma-separated list of RFC 5646 language tags " ++
                "(e.g. \"en-GB\" or \"en, cy\") — refusing to post rather than repair it",
            .{},
        ),
        error.SubjectNotUtf8 => fatal("MAIL_SUBJECT contains non-ASCII bytes that are not valid UTF-8 — refusing to mislabel it", .{}),
        error.MessageIdInvalid => fatal("internal: the generated Message-ID is not a well-formed identifier", .{}),
        error.ReplyMalformed => fatal("{s}:{d} sent something that is not an NNTP reply line", .{ addr, port }),
        error.AuthTooLong => fatal("SMTP_USER plus SMTP_PASS exceeds the 512-byte AUTHINFO limit", .{}),
        // The three STARTTLS outcomes need three different fixes, so they do
        // not collapse into one message.
        error.StartTlsNotOffered => fatal(
            "{s}:{d} does not advertise STARTTLS, and SMTP_SECURE selects it. " ++
                "Refusing to continue unencrypted. Check the port (119 for a cleartext news port, " ++
                "563 for implicit TLS with SMTP_SECURE: true).",
            .{ addr, port },
        ),
        error.StartTlsUpgradeFailed => fatal(
            "the TLS handshake with {s}:{d} failed after it accepted STARTTLS (reason above)",
            .{ addr, port },
        ),
        error.StartTlsUnconfigured => fatal("internal: STARTTLS selected with no upgrader wired", .{}),
        error.AuthMechanismUnsupported => fatal(
            "{s}:{d} offers no AUTHINFO mechanism this client can drive (see the advertised list above). " ++
                "No credential was sent. AUTHINFO USER/PASS is supported; AUTHINFO SASL is not.",
            .{ addr, port },
        ),
        else => fatal("news session with {s}:{d} failed: {t}", .{ addr, port, err }),
    }
}

fn fatalSession(err: smtp.Error, addr: []const u8, port: u16, diag: *const smtp.Diagnostic) noreturn {
    // The server's own words, when it got as far as saying any. Without this a
    // 535, a 550 and a 554 are one indistinguishable failure in the log
    // (issue #3). Only server bytes reach `diag`; no credential can.
    if (diag.code != 0) {
        var clean: [smtp.reply_text_max * 3]u8 = undefined;
        std.debug.print(
            "smtp-notify: {s}:{d} replied {d} at the {t} step: {s}{s}\n",
            .{ addr, port, diag.code, diag.phase, smtp.sanitizeServerText(&clean, diag.text()), if (diag.truncated) " […]" else "" },
        );
    }
    // D-006: an auth failure that does not say what was on offer leaves the
    // operator guessing between a wrong password and an unsupported
    // mechanism. Those need opposite fixes, so they must not look alike.
    if (diag.phase == .auth) {
        if (diag.caps.authMechanisms().len > 0) {
            // Name the mechanism this client actually chose. Hardcoding
            // "AUTH PLAIN" here was true only until AUTH LOGIN existed, and a
            // diagnostic that misreports the mechanism sends the operator to
            // the wrong fix.
            std.debug.print(
                "smtp-notify: this client used AUTH {s}; {s}:{d} advertised: {s}\n",
                .{
                    if (diag.mechanism) |m| @tagName(m) else "(none chosen)",
                    addr,
                    port,
                    diag.caps.authMechanisms(),
                },
            );
            if (diag.mechanism == null) std.debug.print(
                "smtp-notify: none of those is a mechanism this client speaks (PLAIN, LOGIN).\n" ++
                    "  XOAUTH2 needs an OAuth token, which no password secret can supply.\n",
                .{},
            );
        } else {
            std.debug.print(
                "smtp-notify: {s}:{d} advertised no AUTH mechanisms at all — it likely requires\n" ++
                    "  STARTTLS first. Set SMTP_SECURE: starttls (port 587).\n",
                .{ addr, port },
            );
        }
    }
    switch (err) {
        error.TransientFailure => fatal("{s}:{d} replied 4xx (transient failure) — retry later", .{ addr, port }),
        error.PermanentFailure => fatal("{s}:{d} replied 5xx (permanent failure) — check credentials/addresses", .{ addr, port }),
        error.ProtocolError => fatal("{s}:{d} sent a reply outside the proven protocol table", .{ addr, port }),
        error.HeaderInjection => fatal("CR/LF in a header-bound input (from/to/subject/content_language) — refusing to send", .{}),
        error.ContentLanguageInvalid => fatal(
            "MAIL_CONTENT_LANGUAGE is not a comma-separated list of RFC 5646 language tags " ++
                "(e.g. \"en-GB\" or \"en, cy\") — refusing to send rather than repair it",
            .{},
        ),
        error.SubjectNotUtf8 => fatal("MAIL_SUBJECT contains non-ASCII bytes that are not valid UTF-8 — refusing to mislabel it", .{}),
        error.NoRecipients => fatal("MAIL_TO contains no recipients", .{}),
        error.ReplyMalformed => fatal("{s}:{d} sent something that is not an SMTP reply line", .{ addr, port }),
        // The three STARTTLS failures need three different actions, so
        // they must not collapse into one message.
        error.StartTlsNotOffered => fatal(
            "{s}:{d} does not advertise STARTTLS, and SMTP_SECURE selects it. " ++
                "Refusing to continue unencrypted. Check the port (587 for submission, " ++
                "465 for implicit TLS with SMTP_SECURE: true).",
            .{ addr, port },
        ),
        error.StartTlsUpgradeFailed => fatal(
            "the TLS handshake with {s}:{d} failed after it accepted STARTTLS (reason above)",
            .{ addr, port },
        ),
        error.StartTlsUnconfigured => fatal("internal: STARTTLS selected with no upgrader wired", .{}),
        error.AuthMechanismUnsupported => fatal(
            "{s}:{d} offers no AUTH mechanism this client can drive (see the advertised list above). " ++
                "No credential was sent. PLAIN and LOGIN are supported; XOAUTH2 is not.",
            .{ addr, port },
        ),
        else => fatal("session with {s}:{d} failed: {t}", .{ addr, port, err }),
    }
}

// ---------------------------------------------------------------------------
// Tests: the environment-to-policy layer.
//
// These live here rather than in src/smtp.zig because they are about the
// action's *policy* decisions — which transport, which protocol, which port —
// and the fail-closed rule for each. The protocol dialogues are tested in
// src/smtp.zig and src/nntp.zig.
// ---------------------------------------------------------------------------

const testing = std.testing;

/// A `Map` built from literal pairs, so a test can describe an environment
/// without touching the process's own.
fn testEnv(pairs: []const [2][]const u8) std.process.Environ.Map {
    var map = std.process.Environ.Map.init(testing.allocator);
    for (pairs) |kv| map.put(kv[0], kv[1]) catch @panic("OOM in test");
    return map;
}

test "SMTP_SECURE: the fail-closed spellings, and nothing else" {
    {
        var e = testEnv(&.{});
        defer e.deinit();
        try testing.expectEqual(Transport.implicit_tls, parseTransport(&e));
    }
    {
        // The dawidd6 spelling, read the way dawidd6 means it.
        var e = testEnv(&.{.{ "SMTP_SECURE", "false" }});
        defer e.deinit();
        try testing.expectEqual(Transport.starttls, parseTransport(&e));
    }
    {
        // Case and the explicit names, which are the documented additions.
        var e = testEnv(&.{.{ "SMTP_SECURE", "StArTtLs" }});
        defer e.deinit();
        try testing.expectEqual(Transport.starttls, parseTransport(&e));
    }
    {
        var e = testEnv(&.{.{ "SMTP_SECURE", "implicit" }});
        defer e.deinit();
        try testing.expectEqual(Transport.implicit_tls, parseTransport(&e));
    }
    {
        // Cleartext has to be named. `1`, `yes`, `on` and `TRUE` are NOT
        // spellings of "true" here: that conflation is exactly issue #1, where
        // anything but the exact string "true" meant plaintext.
        var e = testEnv(&.{.{ "SMTP_SECURE", "plaintext" }});
        defer e.deinit();
        try testing.expectEqual(Transport.plaintext, parseTransport(&e));
    }
    // An empty value is the default, not an error: `${{ inputs.secure }}`
        // with the default applied yields "true", but a caller passing an empty
    // string means "unset" and gets the safe default.
    {
        var e = testEnv(&.{.{ "SMTP_SECURE", "" }});
        defer e.deinit();
        try testing.expectEqual(Transport.implicit_tls, parseTransport(&e));
    }
}

test "SMTP_PROTOCOL: unset or empty means SMTP; the two names are recognised" {
    {
        var e = testEnv(&.{});
        defer e.deinit();
        try testing.expectEqual(Protocol.smtp, parseProtocol(&e));
    }
    {
        var e = testEnv(&.{.{ "SMTP_PROTOCOL", "" }});
        defer e.deinit();
        try testing.expectEqual(Protocol.smtp, parseProtocol(&e));
    }
    {
        var e = testEnv(&.{.{ "SMTP_PROTOCOL", "smtp" }});
        defer e.deinit();
        try testing.expectEqual(Protocol.smtp, parseProtocol(&e));
    }
    {
        var e = testEnv(&.{.{ "SMTP_PROTOCOL", "NNTP" }});
        defer e.deinit();
        try testing.expectEqual(Protocol.nntp, parseProtocol(&e));
    }
}

test "default ports: what each protocol and transport means when none is named" {
    // The registered defaults, so a workflow of just `server_address` +
    // `secure` reaches the right port in both protocols.
    try testing.expectEqual(@as(u16, 465), defaultPort(.smtp, .implicit_tls));
    try testing.expectEqual(@as(u16, 587), defaultPort(.smtp, .starttls));
    try testing.expectEqual(@as(u16, 25), defaultPort(.smtp, .plaintext));
    try testing.expectEqual(@as(u16, 563), defaultPort(.nntp, .implicit_tls));
    try testing.expectEqual(@as(u16, 119), defaultPort(.nntp, .starttls));
    try testing.expectEqual(@as(u16, 119), defaultPort(.nntp, .plaintext));
}

test "SMTP_PORT: an explicit port always wins, empty and unset fall through" {
    {
        var e = testEnv(&.{.{ "SMTP_PORT", "1025" }});
        defer e.deinit();
        try testing.expectEqual(@as(u16, 1025), resolvePort(&e, .smtp, .plaintext));
    }
    {
        var e = testEnv(&.{.{ "SMTP_PORT", "563" }});
        defer e.deinit();
        try testing.expectEqual(@as(u16, 563), resolvePort(&e, .nntp, .implicit_tls));
    }
    {
        var e = testEnv(&.{.{ "SMTP_PORT", "" }});
        defer e.deinit();
        try testing.expectEqual(@as(u16, 119), resolvePort(&e, .nntp, .starttls));
    }
    {
        var e = testEnv(&.{});
        defer e.deinit();
        try testing.expectEqual(@as(u16, 465), resolvePort(&e, .smtp, .implicit_tls));
    }
}

test "the generated Message-ID is well-formed, and two runs never collide" {
    const io = testing.io;
    const a = newsMessageId(testing.allocator, io, 1_000_000_000);
    defer testing.allocator.free(a);
    const b = newsMessageId(testing.allocator, io, 1_000_000_000);
    defer testing.allocator.free(b);

    // Shaped the way the driver will accept it.
    try testing.expect(nntp.messageIdOk(a));
    try testing.expect(nntp.messageIdOk(b));
    // Same second, different identifier — the nonce is the whole point: two
    // concurrent runs must not produce the same id, or the server may discard
    // the second article while this step reports success.
    try testing.expect(!std.mem.eql(u8, a, b));
    // The epoch part is this run's clock, not a constant.
    try testing.expect(std.mem.startsWith(u8, a, "<1000000000."));
    // No stray bytes from the host name, whatever the runner is called.
    for (a) |c| try testing.expect(c != ' ' and c > 0x20);
}
