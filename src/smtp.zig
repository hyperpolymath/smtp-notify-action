// SPDX-License-Identifier: MPL-2.0
//! Table-driven SMTP client session.
//!
//! The `script` table in src/generated/smtp_fsm.zig — generated from the
//! proven Idris2 spec — is the ONLY protocol authority here: this module
//! walks it phase by phase and refuses any reply the current row does not
//! list. It talks to generic `std.Io.Reader`/`std.Io.Writer`, so the unit
//! tests below drive whole sessions against scripted in-memory replies with
//! no network involved; main.zig supplies TLS- or TCP-backed streams.

const std = @import("std");
pub const fsm = @import("generated/smtp_fsm.zig");
const message = @import("message.zig");

pub const Config = struct {
    ehlo_domain: []const u8,
    username: []const u8,
    password: []const u8,
    /// Display form, e.g. "GitHub Push <bot@example.org>" — used verbatim in
    /// the From: header; the envelope MAIL FROM uses the angle-addr inside.
    from: []const u8,
    recipients: []const []const u8,
    subject: []const u8,
    body: []const u8,
    /// Unix seconds for the Date: header.
    date_epoch_seconds: i64,
    /// Greeting + EHLO + QUIT only — proves reachability and TLS without
    /// authenticating or sending mail.
    handshake_only: bool = false,
};

pub const SessionError = error{
    TransientFailure, // 4xx reply
    PermanentFailure, // 5xx reply
    ProtocolError, // reply the script row does not list and no class matches
    HeaderInjection, // CR/LF in a header-bound input — rejected, never sanitized
    NoRecipients,
    ReplyMalformed,
    AuthTooLong,
};

pub const Error = SessionError || std.Io.Reader.DelimiterError || std.Io.Writer.Error;

/// How much of a server reply is retained. Enough for a multi-line EHLO
/// capability list from a large provider; anything past it is truncated
/// rather than allocated for, and the truncation is reported, not hidden.
pub const reply_text_max = 2048;

/// A reply may not carry more continuation lines than this. Without a cap a
/// server that never sends a final line holds the client in `readReply`
/// forever, which no timeout at the transport layer can distinguish from a
/// merely slow server.
const reply_line_max = 128;

/// One SMTP reply: its three-digit code plus the server's own words.
///
/// Retaining the text is what makes a 535, a 550 and a 554 different things
/// in the log instead of three indistinguishable failures (#3), and it is the
/// prerequisite for reading EHLO capabilities (#9) rather than guessing at
/// them. Multi-line replies keep every line, '\n'-separated, with the code
/// and its separator stripped.
pub const Reply = struct {
    code: u16,
    text: []const u8,
    /// The server said more than `reply_text_max`; `text` is a prefix.
    truncated: bool = false,
};

/// Carries the last reply out of a failed session so the caller can print the
/// server's explanation. Only ever holds bytes the *server* sent — no
/// credential can reach it.
pub const Diagnostic = struct {
    /// The phase whose reply was last read. `code == 0` means no reply was
    /// read at all, so the failure preceded the first one.
    phase: fsm.Phase = .connect,
    code: u16 = 0,
    buf: [reply_text_max]u8 = undefined,
    len: usize = 0,
    truncated: bool = false,

    pub fn text(d: *const Diagnostic) []const u8 {
        return d.buf[0..d.len];
    }

    fn record(d: *Diagnostic, phase: fsm.Phase, reply: Reply) void {
        d.phase = phase;
        d.code = reply.code;
        const n = @min(reply.text.len, d.buf.len);
        @memcpy(d.buf[0..n], reply.text[0..n]);
        d.len = n;
        d.truncated = reply.truncated or n < reply.text.len;
    }
};

/// The byte streams a session rides on.
pub const Wire = struct {
    r: *std.Io.Reader,
    w: *std.Io.Writer,
    /// For layered transports (TLS over TCP): flushing `w` only encrypts
    /// buffered plaintext into the transport writer below — that writer must
    /// then be flushed itself for the records to reach the socket.
    below: ?*std.Io.Writer = null,

    pub fn flush(wire: Wire) std.Io.Writer.Error!void {
        try wire.w.flush();
        if (wire.below) |b| try b.flush();
    }
};

/// Walk the generated script from .connect to .done, sending each row's
/// action and demanding a listed reply code before advancing.
pub fn runSession(cfg: Config, wire: Wire) Error!void {
    return runSessionDiag(cfg, wire, null);
}

/// As `runSession`, but records the last reply read into `diag` so a failure
/// can be reported with the server's own explanation rather than a bare code.
pub fn runSessionDiag(cfg: Config, wire: Wire, diag: ?*Diagnostic) Error!void {
    const r = wire.r;
    const w = wire.w;
    if (!message.headerValueOk(cfg.subject)) return error.HeaderInjection;
    if (!message.headerValueOk(cfg.from)) return error.HeaderInjection;
    for (cfg.recipients) |rcpt| {
        if (!message.headerValueOk(rcpt)) return error.HeaderInjection;
    }
    if (!cfg.handshake_only and cfg.recipients.len == 0) return error.NoRecipients;

    // Best-effort abort courtesy: on any failure mid-session, try to QUIT so
    // the server does not hold a half-open transaction.
    errdefer {
        w.writeAll("QUIT\r\n") catch {};
        wire.flush() catch {};
    }

    var phase: fsm.Phase = .connect;
    var rcpt_index: usize = 0;
    var reply_buf: [reply_text_max]u8 = undefined;
    while (phase != .done) {
        // Coverage of every non-terminal phase is proven in the spec
        // (deterministicCoverage), so a missing row is unreachable.
        const step = lookupStep(phase) orelse return error.ProtocolError;
        try sendAction(cfg, step.send, rcpt_index, w);
        try wire.flush();
        const reply = try readReply(r, &reply_buf);
        if (diag) |d| d.record(phase, reply);
        try checkReply(step, reply.code);
        if (step.repeats) {
            rcpt_index += 1;
            if (rcpt_index < cfg.recipients.len) continue; // same row, next recipient
        }
        // handshake_only: once EHLO succeeded, skip straight to QUIT.
        phase = if (cfg.handshake_only and step.next == .auth) .quit else step.next;
    }
}

fn lookupStep(phase: fsm.Phase) ?fsm.Step {
    for (fsm.script) |s| {
        if (s.phase == phase) return s;
    }
    return null;
}

fn sendAction(cfg: Config, action: fsm.Action, rcpt_index: usize, w: *std.Io.Writer) Error!void {
    switch (action) {
        .none => {}, // server speaks first (greeting)
        .ehlo => try w.print("EHLO {s}\r\n", .{cfg.ehlo_domain}),
        .auth_plain => try writeAuthPlain(w, cfg.username, cfg.password),
        .mail_from => try w.print("MAIL FROM:<{s}>\r\n", .{angleAddr(cfg.from)}),
        .rcpt_to => try w.print("RCPT TO:<{s}>\r\n", .{angleAddr(cfg.recipients[rcpt_index])}),
        .data => try w.writeAll("DATA\r\n"),
        .payload => try writePayload(cfg, w),
        .quit => try w.writeAll("QUIT\r\n"),
    }
}

/// Read one (possibly multi-line) reply: its 3-digit code, plus the server's
/// own words accumulated into `buf`.
///
/// Continuation lines have '-' as the 4th character ("250-..."); the final
/// line has ' ' or nothing after the code. Every line's text is kept,
/// '\n'-separated, with the code and its separator stripped. That is what
/// makes a 535 distinguishable from a 550 in the log, and it is the same
/// mechanism an EHLO capability list will be read through.
fn readReply(r: *std.Io.Reader, buf: []u8) (SessionError || std.Io.Reader.DelimiterError)!Reply {
    var len: usize = 0;
    var truncated = false;
    var lines: usize = 0;
    while (true) {
        // Inclusive, not Exclusive: the Exclusive variant leaves the '\n' in
        // the stream, so the next read would see an empty line.
        const raw = try r.takeDelimiterInclusive('\n');
        const line = std.mem.trimEnd(u8, raw, "\r\n");
        if (line.len < 3) return error.ReplyMalformed;
        // Three literal ASCII digits. `parseInt` on its own accepts "+12"
        // and a leading space, so a line that is not a reply line at all
        // could otherwise be read as one.
        for (line[0..3]) |c| {
            if (c < '0' or c > '9') return error.ReplyMalformed;
        }
        const code = std.fmt.parseInt(u16, line[0..3], 10) catch return error.ReplyMalformed;
        // RFC 5321 §4.2.1: the 4th character is '-' on a continuation line
        // and ' ' on the last one. Anything else is malformed, not a reply
        // to be silently accepted.
        const more = line.len >= 4 and line[3] == '-';
        if (line.len >= 4 and !more and line[3] != ' ') return error.ReplyMalformed;

        const text = if (line.len > 4) line[4..] else line[0..0];
        if (len > 0 and len < buf.len) {
            buf[len] = '\n';
            len += 1;
        }
        const n = @min(text.len, buf.len - len);
        @memcpy(buf[len..][0..n], text[0..n]);
        len += n;
        if (n < text.len) truncated = true;

        if (!more) return .{ .code = code, .text = buf[0..len], .truncated = truncated };

        lines += 1;
        // A server that never sends a final line would otherwise hold us
        // here forever, which no transport timeout can tell apart from a
        // server that is merely slow.
        if (lines >= reply_line_max) return error.ReplyMalformed;
    }
}

/// A reply is accepted only if the current script row lists it. Unlisted
/// codes classify as transient (4xx), permanent (5xx), or protocol error.
fn checkReply(step: fsm.Step, code: u16) SessionError!void {
    for (step.expect) |ok| {
        if (code == ok) return;
    }
    if (code >= 400 and code < 500) return error.TransientFailure;
    if (code >= 500 and code < 600) return error.PermanentFailure;
    return error.ProtocolError;
}

/// AUTH PLAIN is a single round trip: base64("\0username\0password").
/// The credential never appears on argv; main.zig reads it from the env.
fn writeAuthPlain(w: *std.Io.Writer, username: []const u8, password: []const u8) Error!void {
    var plain_buf: [512]u8 = undefined;
    var b64_buf: [684]u8 = undefined; // ceil(512 / 3) * 4
    const needed = username.len + password.len + 2;
    if (needed > plain_buf.len) return error.AuthTooLong;
    plain_buf[0] = 0;
    @memcpy(plain_buf[1..][0..username.len], username);
    plain_buf[1 + username.len] = 0;
    @memcpy(plain_buf[2 + username.len ..][0..password.len], password);
    const encoded = std.base64.standard.Encoder.encode(&b64_buf, plain_buf[0..needed]);
    try w.print("AUTH PLAIN {s}\r\n", .{encoded});
}

/// RFC 5322 headers + dot-stuffed body + terminating "." line.
fn writePayload(cfg: Config, w: *std.Io.Writer) Error!void {
    try w.print("From: {s}\r\n", .{cfg.from});
    try w.writeAll("To: ");
    for (cfg.recipients, 0..) |rcpt, i| {
        if (i != 0) try w.writeAll(", ");
        try w.writeAll(rcpt);
    }
    try w.writeAll("\r\n");
    try w.print("Subject: {s}\r\n", .{cfg.subject});
    try w.writeAll("Date: ");
    try message.writeRfc5322Date(w, cfg.date_epoch_seconds);
    try w.writeAll("\r\n");
    try w.writeAll("MIME-Version: 1.0\r\n");
    try w.writeAll("Content-Type: text/plain; charset=utf-8\r\n");
    try w.writeAll("Content-Transfer-Encoding: 8bit\r\n");
    try w.writeAll("\r\n");
    var it = std.mem.splitScalar(u8, cfg.body, '\n');
    while (it.next()) |raw_line| {
        const line = std.mem.trimEnd(u8, raw_line, "\r");
        try message.writeStuffedLine(w, line);
    }
    try w.writeAll(".\r\n");
}

/// Extract the address for the SMTP envelope: the text inside the last
/// "<...>" if present ("GitHub Push <a@b>" -> "a@b"), else the whole value
/// trimmed.
pub fn angleAddr(s: []const u8) []const u8 {
    const open = std.mem.lastIndexOfScalar(u8, s, '<') orelse
        return std.mem.trim(u8, s, " \t");
    const close = std.mem.indexOfScalarPos(u8, s, open + 1, '>') orelse
        return std.mem.trim(u8, s, " \t");
    return s[open + 1 .. close];
}

// ---------------------------------------------------------------------------
// Tests: whole scripted sessions, no network.
// ---------------------------------------------------------------------------

const test_cfg: Config = .{
    .ehlo_domain = "github-actions",
    .username = "u",
    .password = "p",
    .from = "GitHub Push <bot@example.org>",
    .recipients = &.{ "one@example.com", "two@example.net" },
    .subject = "[repo] push to main by owner",
    .body = "line one\n.\n.hidden\nlast line",
    .date_epoch_seconds = 1_000_000_000,
};

fn runScripted(cfg: Config, replies: []const u8, out: []u8) Error!usize {
    var r: std.Io.Reader = .fixed(replies);
    var w: std.Io.Writer = .fixed(out);
    try runSession(cfg, .{ .r = &r, .w = &w });
    return w.end;
}

test "happy path: full session in wire order, both recipients, stuffed body" {
    const replies =
        "220 mail.example.org ESMTP\r\n" ++
        "250-mail.example.org\r\n250-PIPELINING\r\n250 AUTH PLAIN LOGIN\r\n" ++
        "235 2.7.0 Authentication successful\r\n" ++
        "250 2.1.0 Ok\r\n" ++
        "250 2.1.5 Ok\r\n" ++
        "251 User not local; will forward\r\n" ++
        "354 End data with <CR><LF>.<CR><LF>\r\n" ++
        "250 2.0.0 Ok: queued\r\n" ++
        "221 2.0.0 Bye\r\n";
    var out: [8192]u8 = undefined;
    const n = try runScripted(test_cfg, replies, &out);
    const sent = out[0..n];

    // base64("\x00u\x00p") == "AHUAcA=="
    const expected_order = [_][]const u8{
        "EHLO github-actions\r\n",
        "AUTH PLAIN AHUAcA==\r\n",
        "MAIL FROM:<bot@example.org>\r\n",
        "RCPT TO:<one@example.com>\r\n",
        "RCPT TO:<two@example.net>\r\n",
        "DATA\r\n",
        "From: GitHub Push <bot@example.org>\r\n",
        "To: one@example.com, two@example.net\r\n",
        "Subject: [repo] push to main by owner\r\n",
        "Date: Sun, 9 Sep 2001 01:46:40 +0000\r\n",
        "\r\nline one\r\n..\r\n..hidden\r\nlast line\r\n.\r\n",
        "QUIT\r\n",
    };
    var cursor: usize = 0;
    for (expected_order) |fragment| {
        const idx = std.mem.indexOfPos(u8, sent, cursor, fragment) orelse {
            std.debug.print("missing (after byte {d}): {s}\n", .{ cursor, fragment });
            return error.TestUnexpectedResult;
        };
        cursor = idx + fragment.len;
    }
}

test "5xx at RCPT is a permanent failure and the client QUITs" {
    const replies =
        "220 ok\r\n" ++ "250 ok\r\n" ++ "235 ok\r\n" ++ "250 ok\r\n" ++
        "550 5.1.1 No such user\r\n";
    var out: [4096]u8 = undefined;
    var r: std.Io.Reader = .fixed(replies);
    var w: std.Io.Writer = .fixed(&out);
    try std.testing.expectError(error.PermanentFailure, runSession(test_cfg, .{ .r = &r, .w = &w }));
    try std.testing.expect(std.mem.endsWith(u8, out[0..w.end], "QUIT\r\n"));
}

test "4xx at greeting is a transient failure" {
    var out: [1024]u8 = undefined;
    var r: std.Io.Reader = .fixed("421 4.3.2 Service not available\r\n");
    var w: std.Io.Writer = .fixed(&out);
    try std.testing.expectError(error.TransientFailure, runSession(test_cfg, .{ .r = &r, .w = &w }));
}

test "unlisted success code is a protocol error (250 where 354 is required)" {
    const replies =
        "220 ok\r\n" ++ "250 ok\r\n" ++ "235 ok\r\n" ++ "250 ok\r\n" ++
        "250 ok\r\n" ++ "250 ok\r\n" ++ "250 not-354\r\n";
    var out: [4096]u8 = undefined;
    var r: std.Io.Reader = .fixed(replies);
    var w: std.Io.Writer = .fixed(&out);
    try std.testing.expectError(error.ProtocolError, runSession(test_cfg, .{ .r = &r, .w = &w }));
}

test "CRLF in subject is rejected before anything reaches the wire" {
    var cfg = test_cfg;
    cfg.subject = "bad\r\ninjected: header";
    var out: [1024]u8 = undefined;
    var r: std.Io.Reader = .fixed("220 ok\r\n");
    var w: std.Io.Writer = .fixed(&out);
    try std.testing.expectError(error.HeaderInjection, runSession(cfg, .{ .r = &r, .w = &w }));
}

test "empty recipient list is rejected" {
    var cfg = test_cfg;
    cfg.recipients = &.{};
    var out: [1024]u8 = undefined;
    var r: std.Io.Reader = .fixed("220 ok\r\n");
    var w: std.Io.Writer = .fixed(&out);
    try std.testing.expectError(error.NoRecipients, runSession(cfg, .{ .r = &r, .w = &w }));
}

test "handshake-only: EHLO then QUIT, no AUTH, no mail" {
    var cfg = test_cfg;
    cfg.handshake_only = true;
    const replies =
        "220 mail.example.org ESMTP\r\n" ++
        "250-mail.example.org\r\n250 STARTTLS\r\n" ++
        "221 2.0.0 Bye\r\n";
    var out: [2048]u8 = undefined;
    const n = try runScripted(cfg, replies, &out);
    const sent = out[0..n];
    try std.testing.expect(std.mem.indexOf(u8, sent, "EHLO github-actions\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, sent, "QUIT\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, sent, "AUTH") == null);
    try std.testing.expect(std.mem.indexOf(u8, sent, "MAIL FROM") == null);
}

test "angleAddr extraction" {
    try std.testing.expectEqualStrings("a@b.c", angleAddr("Name Person <a@b.c>"));
    try std.testing.expectEqualStrings("a@b.c", angleAddr("a@b.c"));
    try std.testing.expectEqualStrings("a@b.c", angleAddr("  a@b.c "));
}

test {
    _ = message; // pull in message.zig's golden-vector tests
}

// ---------------------------------------------------------------------------
// Tests: reply text and diagnostics (issue #3).
// ---------------------------------------------------------------------------

fn readOne(replies: []const u8, buf: []u8) !Reply {
    var r: std.Io.Reader = .fixed(replies);
    return readReply(&r, buf);
}

test "readReply keeps the server's words, not only the code" {
    var buf: [reply_text_max]u8 = undefined;
    const reply = try readOne("535 5.7.8 Username and Password not accepted\r\n", &buf);
    try std.testing.expectEqual(@as(u16, 535), reply.code);
    try std.testing.expectEqualStrings("5.7.8 Username and Password not accepted", reply.text);
    try std.testing.expect(!reply.truncated);
}

test "readReply accumulates every line of a multi-line reply" {
    var buf: [reply_text_max]u8 = undefined;
    const reply = try readOne(
        "250-mail.example.org\r\n250-PIPELINING\r\n250-STARTTLS\r\n250 AUTH LOGIN XOAUTH2\r\n",
        &buf,
    );
    try std.testing.expectEqual(@as(u16, 250), reply.code);
    try std.testing.expectEqualStrings(
        "mail.example.org\nPIPELINING\nSTARTTLS\nAUTH LOGIN XOAUTH2",
        reply.text,
    );
    try std.testing.expect(!reply.truncated);
}

test "readReply refuses an endless continuation" {
    var buf: [reply_text_max]u8 = undefined;
    var stream: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&stream);
    for (0..reply_line_max + 2) |_| try w.writeAll("250-x\r\n");
    try std.testing.expectError(error.ReplyMalformed, readOne(stream[0..w.end], &buf));
}

test "readReply rejects a line whose code is not three digits" {
    var buf: [reply_text_max]u8 = undefined;
    try std.testing.expectError(error.ReplyMalformed, readOne("+12 hello\r\n", &buf));
    try std.testing.expectError(error.ReplyMalformed, readOne(" 50 hello\r\n", &buf));
    try std.testing.expectError(error.ReplyMalformed, readOne("250x hello\r\n", &buf));
}

test "readReply reports truncation rather than hiding it" {
    var small: [8]u8 = undefined;
    const reply = try readOne("250 abcdefghijklmnop\r\n", &small);
    try std.testing.expectEqual(@as(u16, 250), reply.code);
    try std.testing.expectEqualStrings("abcdefgh", reply.text);
    try std.testing.expect(reply.truncated);
}

test "runSessionDiag carries the failing reply out to the caller" {
    const replies =
        "220 mail.example.org ESMTP\r\n" ++
        "250 mail.example.org\r\n" ++
        "535 5.7.8 Username and Password not accepted\r\n";
    var r: std.Io.Reader = .fixed(replies);
    var out: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    var diag: Diagnostic = .{};
    try std.testing.expectError(
        error.PermanentFailure,
        runSessionDiag(test_cfg, .{ .r = &r, .w = &w }, &diag),
    );
    try std.testing.expectEqual(fsm.Phase.auth, diag.phase);
    try std.testing.expectEqual(@as(u16, 535), diag.code);
    try std.testing.expectEqualStrings("5.7.8 Username and Password not accepted", diag.text());
}
