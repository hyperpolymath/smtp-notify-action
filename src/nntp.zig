// SPDX-License-Identifier: MPL-2.0
//! Table-driven NNTP client session: post ONE article (RFC 3977), over
//! implicit TLS (NNTPS, normally port 563), STARTTLS (RFC 4642), or plaintext
//! for a containerized test sink.
//!
//! The script tables in src/generated/smtp_fsm.zig (the `nntp_*` section) —
//! generated from the proven Idris2 spec in spec/Nntp/ — are the ONLY protocol
//! authority here: this module walks one phase at a time and refuses any reply
//! the current row does not list. There are two shapes, chosen by
//! `Config.use_starttls`: one over an already-encrypted stream, and one that
//! begins in cleartext on the news port and upgrades in place. Each is proven
//! separately, including that the upgrade is on the walked path.
//!
//! What this client deliberately does NOT do, stated so the scope of the
//! proofs is not read as more than it is:
//!   * It posts; it never reads news. No GROUP, ARTICLE, HDR, or LIST.
//!   * It drives AUTHINFO USER/PASS (RFC 4643 §2) only. AUTHINFO SASL needs
//!     the 383 continuation exchange and is refused *before* a credential is
//!     written, by the same rule the SMTP client applies to XOAUTH2.
//!   * One article per session; no crosspost batching, no repeat loop (the
//!     spec's `nNoRepeats` is what makes that a property rather than a habit).
//!
//! It talks to generic `std.Io.Reader`/`std.Io.Writer`, so the unit tests
//! below drive whole sessions against scripted in-memory replies with no
//! network involved; main.zig supplies TLS- or TCP-backed streams.

const std = @import("std");
pub const fsm = @import("generated/smtp_fsm.zig");
const message = @import("message.zig");

pub const Config = struct {
    username: []const u8,
    password: []const u8,
    /// Display form, e.g. "GitHub Push <bot@example.org>" — used verbatim in
    /// the From: header. A posted article carries no envelope, so there is no
    /// second, angle-addr form to disagree with it.
    from: []const u8,
    /// Newsgroups value: one or more comma-separated group names. Anything
    /// that fails `message.newsgroupsOk` is refused before the session starts,
    /// and `control`/`control.*` are refused with it (RFC 5536 §3.1.4).
    newsgroups: []const u8,
    subject: []const u8,
    /// RFC 3282 Content-Language value: one or more RFC 5646 tags,
    /// comma-separated. Empty omits the header.
    content_language: []const u8 = "",
    body: []const u8,
    /// Unix seconds for the Date: header.
    date_epoch_seconds: i64,
    /// The Message-ID header. A posted article requires one (RFC 5536 §3.1.2),
    /// and the server adds one only if the poster did not — so the client
    /// writes its own rather than depending on the server's. It must be unique
    /// per post, so main.zig draws entropy for it; the tests pass a literal.
    message_id: []const u8,
    /// Greeting + CAPABILITIES + QUIT only — proves reachability, TLS and the
    /// capability dialogue without authenticating or posting.
    handshake_only: bool = false,
    /// Begin in cleartext and issue STARTTLS after the first CAPABILITIES
    /// (RFC 4642), rather than expecting an already-encrypted stream.
    /// Selects the other proven table; requires `upgrader`.
    use_starttls: bool = false,
    /// Performs the TLS handshake once the server accepts STARTTLS.
    /// Required when `use_starttls` is set, ignored otherwise.
    upgrader: ?@import("wire.zig").Upgrader = null,
};

pub const SessionError = error{
    TransientFailure, // 4xx reply
    PermanentFailure, // 5xx reply
    ProtocolError, // reply the script row does not list and no class matches
    HeaderInjection, // CR/LF in a header-bound input — rejected, never sanitized
    NewsgroupsInvalid, // not an RFC 5536 name list — rejected, never repaired
    ContentLanguageInvalid, // not an RFC 3282 list of RFC 5646 tags — rejected, never repaired
    SubjectNotUtf8, // non-ASCII subject that is not valid UTF-8 — cannot be labelled honestly
    MessageIdInvalid, // not a bounded, angle-bracketed, one-'@' Message-ID
    ReplyMalformed,
    AuthTooLong,
    StartTlsNotOffered, // asked to upgrade, but CAPABILITIES never advertised it
    StartTlsUnconfigured, // use_starttls set with no upgrader to call
    StartTlsUpgradeFailed, // the server said 382 and the handshake still failed
    AuthMechanismUnsupported, // server named its mechanisms; none is one we speak
    PostingNotPermitted, // greeting 201, or POST 440: this server will not post
    ArticleRejected, // POST 441: the article itself was refused
};

pub const Error = SessionError || std.Io.Reader.DelimiterError || std.Io.Writer.Error;

/// How much of a server reply is retained. Same policy, and the same number,
/// as the SMTP driver: enough for a real capability list from a large
/// provider, anything past it truncated rather than allocated for, and the
/// truncation reported rather than hidden.
pub const reply_text_max = 2048;

/// A reply may not carry more continuation lines than this. Without a cap a
/// server that never sends a final line holds the client in `readReply`
/// forever, which no timeout at the transport layer can distinguish from a
/// merely slow server.
const reply_line_max = 128;

/// Cap on the retained AUTHINFO parameter list, for diagnostics only.
const auth_raw_max = 128;

/// One NNTP reply: its three-digit status plus the server's own words.
///
/// NNTP uses the same `<code><sep>text` framing as SMTP, so the same reader
/// serves both — which is why a 480 and a 502, or a 440 and a 441, are
/// different lines in the log instead of one indistinguishable failure.
pub const Reply = struct {
    code: u16,
    text: []const u8,
    /// The server said more than `reply_text_max`; `text` is a prefix.
    truncated: bool = false,
};

/// What the server advertised in its CAPABILITIES list (RFC 3977 §5.2,
/// RFC 4642 §2.2, RFC 4643 §2.1).
///
/// The post-upgrade list is the one that counts: RFC 4642 requires the client
/// to discard everything learned before the handshake, so a capabilitity list
/// read on a cleartext wire is never used to decide anything.
pub const Capabilities = struct {
    starttls: bool = false,
    post: bool = false,
    authinfo_user: bool = false,
    authinfo_sasl: bool = false,
    reader: bool = false,
    /// The VERSION capability's number, when the server gave a parseable one.
    version: ?u16 = null,
    /// The AUTHINFO parameter list, verbatim and bounded, for diagnostics.
    /// Server bytes only — no credential can reach it.
    authinfo_raw: [auth_raw_max]u8 = undefined,
    authinfo_raw_len: usize = 0,

    /// The parameters the server named after AUTHINFO, as it spelled them.
    /// Empty when the server advertised no AUTHINFO line at all.
    pub fn authInfoRaw(c: *const Capabilities) []const u8 {
        return c.authinfo_raw[0..c.authinfo_raw_len];
    }
};

/// Parse a 101 reply's accumulated text into `Capabilities`.
///
/// Unlike EHLO there is no greeting line to skip: a 101 is followed directly
/// by the capability list, one per line, terminated by "." which the reader
/// never surfaces. Keywords fold case (RFC 3977 §5.2 leaves them
/// case-insensitive); the AUTHINFO parameters are also kept verbatim for
/// diagnostics, as the SMTP client keeps its AUTH mechanism list.
pub fn parseCapabilities(text: []const u8) Capabilities {
    var caps: Capabilities = .{};
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0) continue;
        const kw_end = std.mem.indexOfAny(u8, line, " \t") orelse line.len;
        const keyword = line[0..kw_end];
        const rest = if (kw_end < line.len) std.mem.trim(u8, line[kw_end + 1 ..], " \t") else "";
        if (std.ascii.eqlIgnoreCase(keyword, "STARTTLS")) {
            caps.starttls = true;
        } else if (std.ascii.eqlIgnoreCase(keyword, "POST")) {
            caps.post = true;
        } else if (std.ascii.eqlIgnoreCase(keyword, "READER") or
            std.ascii.eqlIgnoreCase(keyword, "MODE-READER"))
        {
            caps.reader = true;
        } else if (std.ascii.eqlIgnoreCase(keyword, "VERSION")) {
            // An unparseable VERSION is "unstated", not two.
            caps.version = std.fmt.parseInt(u16, rest, 10) catch null;
        } else if (std.ascii.eqlIgnoreCase(keyword, "AUTHINFO")) {
            const n = @min(rest.len, caps.authinfo_raw.len);
            @memcpy(caps.authinfo_raw[0..n], rest[0..n]);
            caps.authinfo_raw_len = n;
            var params = std.mem.tokenizeAny(u8, rest, " \t");
            while (params.next()) |p| {
                if (std.ascii.eqlIgnoreCase(p, "USER")) {
                    caps.authinfo_user = true;
                } else if (std.ascii.eqlIgnoreCase(p, "SASL")) {
                    caps.authinfo_sasl = true;
                }
            }
        }
    }
    return caps;
}

/// The authentication exchanges this client can drive.
pub const Mechanism = enum { user_pass };

/// Pick the mechanism from what the server advertised.
///
/// The choice is made from `caps`, which is refreshed by BOTH capability
/// exchanges — after a STARTTLS upgrade the encrypted list is the only one
/// that has not passed through an attacker's hands.
///
/// Returns null when the server named its parameters and none of them is a
/// mechanism this client speaks (advertising SASL alone is exactly that case:
/// it needs the 383 continuation exchange, which is not implemented). The
/// caller must then fail BEFORE writing a credential.
pub fn chooseMechanism(caps: *const Capabilities) ?Mechanism {
    if (caps.authinfo_user) return .user_pass;
    // No AUTHINFO line at all. Try USER/PASS anyway: this mirrors the SMTP
    // client's treatment of a server that never enumerates its AUTH
    // mechanisms, and refusing here would break every server that simply
    // does not list what it supports. The password still only follows a 381.
    if (caps.authinfo_raw_len == 0 and !caps.authinfo_sasl) return .user_pass;
    return null;
}

/// Carries the last reply out of a failed session so the caller can print the
/// server's explanation. Only ever holds bytes the *server* sent — no
/// credential can reach it.
pub const Diagnostic = struct {
    /// The phase whose reply was last read. `code == 0` means no reply was
    /// read at all, so the failure preceded the first one.
    phase: fsm.NPhase = .connect,
    code: u16 = 0,
    buf: [reply_text_max]u8 = undefined,
    len: usize = 0,
    truncated: bool = false,

    /// What the server advertised at CAPABILITIES. Refreshed by the second
    /// exchange on the STARTTLS path, so a later AUTHINFO failure names what
    /// the encrypted server offered, not what the cleartext one claimed.
    caps: Capabilities = .{},

    /// Which mechanism this client actually chose from `caps`. Null when AUTH
    /// was never reached, or when nothing on offer could be driven.
    mechanism: ?Mechanism = null,

    /// The retained reply text: server bytes only, possibly truncated.
    pub fn text(d: *const Diagnostic) []const u8 {
        return d.buf[0..d.len];
    }

    /// Store `reply` (and the capability set in force) as the last one read.
    fn record(d: *Diagnostic, phase: fsm.NPhase, reply: Reply, caps: Capabilities) void {
        d.phase = phase;
        d.code = reply.code;
        const n = @min(reply.text.len, d.buf.len);
        @memcpy(d.buf[0..n], reply.text[0..n]);
        d.len = n;
        d.truncated = reply.truncated or n < reply.text.len;
        d.caps = caps;
    }
};

/// Every check on the article that can be made without a server: header
/// injection, subject encodability, the Content-Language grammar, the
/// Newsgroups grammar, the Message-ID shape. Run before any byte is written.
pub fn validateArticle(cfg: Config) SessionError!void {
    if (!message.headerValueOk(cfg.subject)) return error.HeaderInjection;
    if (!message.subjectEncodable(cfg.subject)) return error.SubjectNotUtf8;
    if (!message.headerValueOk(cfg.from)) return error.HeaderInjection;
    if (cfg.content_language.len != 0) {
        // Injection first, so a CR/LF reports as what it is.
        if (!message.headerValueOk(cfg.content_language)) return error.HeaderInjection;
        if (!message.contentLanguageOk(cfg.content_language)) return error.ContentLanguageInvalid;
    }
    // Injection first here too: a CR/LF in the group list is an injection
    // attempt, not a misspelled newsgroup.
    if (!message.headerValueOk(cfg.newsgroups)) return error.HeaderInjection;
    if (!message.newsgroupsOk(cfg.newsgroups)) return error.NewsgroupsInvalid;
    if (!message.headerValueOk(cfg.message_id)) return error.HeaderInjection;
    if (!messageIdOk(cfg.message_id)) return error.MessageIdInvalid;
}

/// A Message-ID as this client writes it: angle-bracketed, exactly one '@',
/// no spaces, no control bytes, bounded. Shape only — the right-hand side is
/// a domain by convention, not a name this client resolves or checks against
/// the DNS.
pub fn messageIdOk(s: []const u8) bool {
    if (s.len < 5 or s.len > 250) return false;
    if (s[0] != '<' or s[s.len - 1] != '>') return false;
    const inner = s[1 .. s.len - 1];
    const at = std.mem.indexOfScalar(u8, inner, '@') orelse return false;
    // Empty local part or empty domain: "<@example.org>" and "<id@>" are not
    // Message-IDs, they are bracket-wrapped fragments.
    if (at == 0 or at + 1 == inner.len) return false;
    // Exactly one '@'. A second one is a malformed identifier, not a domain
    // this client should hand to a server to puzzle over.
    if (std.mem.indexOfScalarPos(u8, inner, at + 1, '@') != null) return false;
    for (inner) |c| {
        if (c <= 0x20 or c == 0x7f or c == '<' or c == '>') return false;
    }
    return true;
}

/// Walk the generated script for this transport from .connect to .done,
/// sending each row's action and demanding a listed reply code before
/// advancing.
pub fn runSession(cfg: Config, w: @import("wire.zig").Wire) Error!void {
    return runSessionDiag(cfg, w, null);
}

/// As `runSession`, but records the last reply read into `diag` so a failure
/// can be reported with the server's own explanation rather than a bare code.
pub fn runSessionDiag(cfg: Config, wire_in: @import("wire.zig").Wire, diag: ?*Diagnostic) Error!void {
    // Mutable: a STARTTLS session replaces this with the encrypted stream
    // partway through, and everything after the upgrade — including the
    // courtesy QUIT below — must ride on the new one.
    var wire = wire_in;
    try validateArticle(cfg);
    if (cfg.use_starttls and cfg.upgrader == null) return error.StartTlsUnconfigured;

    // Best-effort abort courtesy: on any failure mid-session, try to QUIT so
    // the server does not hold a half-open posting transaction.
    errdefer {
        wire.w.writeAll("QUIT\r\n") catch {};
        wire.flush() catch {};
    }

    // Which of the two proven tables this session walks. Both are generated
    // from the same spec and each is proven separately; nothing here may
    // reach across from one shape to the other.
    const table = fsm.nntpScriptFor(cfg.use_starttls);

    var phase: fsm.NPhase = .connect;
    var caps: Capabilities = .{};
    var reply_buf: [reply_text_max]u8 = undefined;
    while (phase != .done) {
        // Coverage of every phase a table uses is proven in the spec
        // (nDeterministicCoverage), so a missing row is unreachable.
        const step = lookupStep(table, phase) orelse return error.ProtocolError;

        // RFC 4642 §2.2: do not issue STARTTLS to a server that never offered
        // it. Checked BEFORE the command goes out, because the alternative to
        // upgrading is not "carry on unencrypted" — it is to stop.
        if (step.nphase == .starttls and !caps.starttls) return error.StartTlsNotOffered;

        // AUTHINFO is not a single write: the 381 demand for a password is
        // consumed by runAuthInfo, which is the exact analogue of the SMTP
        // driver's 334 challenges — the protocol's intermediate reply stays
        // off the proven table, and the TERMINAL reply is still read by the
        // line below and checked against the row.
        if (step.nsend == .authinfo) {
            try runAuthInfo(cfg, &wire, &caps, &reply_buf, diag);
        } else {
            try sendAction(cfg, step.nsend, wire.w);
        }
        try wire.flush();
        const is_caps = step.nphase == .capabilities or step.nphase == .caps_tls;
        const reply = (if (is_caps) readCapsReply(wire.r, &reply_buf) else readReply(wire.r, &reply_buf)) catch |err| {
            // RFC 3977 §5.4 has the server answer QUIT with 205 and then
            // close. A few close first, and if it does, the article was
            // accepted long ago (240) — failing the step here would report a
            // posted article as a failure, which is the one outcome certain
            // to make a caller post it again. Only end-of-stream, only at
            // this row, and only for a session that got that far.
            if (step.nphase == .quit and err == error.EndOfStream) {
                if (diag) |d| d.record(step.nphase, .{ .code = 0, .text = "" }, caps);
                return;
            }
            return err;
        };

        // Both capability exchanges refresh the set. RFC 4642 §2.2 requires
        // the post-upgrade list to REPLACE the cleartext one.
        if (is_caps) caps = parseCapabilities(reply.text);
        if (diag) |d| d.record(phase, reply, caps);

        // NNTP's greeting has two success codes and only one is usable: 200
        // means posting is permitted, 201 means it is not. The table lists
        // 200 alone (201 is not a success for what this client came to do),
        // so it is named here rather than surfacing as a generic protocol
        // error about a 2xx the row did not list.
        if (step.nphase == .connect and reply.code == 201) return error.PostingNotPermitted;
        // 440/441 are 4xx, so the class rule alone would call them transient
        // and tell the operator to retry. They are not retries: 440 says this
        // server will not post, 441 says it would not post *this* article.
        //
        // They are tested at two rows, not one, because they answer different
        // things: 440 is the reply to POST itself, and 441 is the reply to
        // the article that follows the 340. A client that only special-cased
        // the POST row would classify a rejected article as a transient
        // failure — and then tell the operator to post it again, which is
        // exactly the advice that duplicates an article.
        if ((step.nphase == .post or step.nphase == .payload) and reply.code == 440)
            return error.PostingNotPermitted;
        if ((step.nphase == .post or step.nphase == .payload) and reply.code == 441)
            return error.ArticleRejected;

        try checkReply(step, reply.code);

        // The handshake itself: the server has said 382 and is waiting for a
        // TLS ClientHello, not for another NNTP verb.
        if (step.nphase == .starttls) {
            const up = cfg.upgrader orelse return error.StartTlsUnconfigured;
            wire = up.upgrade() catch return error.StartTlsUpgradeFailed;
        }

        // handshake_only stops before authenticating. `step.nnext == .auth`
        // says exactly that, and says it in BOTH tables: the implicit table
        // reaches .auth from .capabilities, the STARTTLS table from
        // .caps_tls. So a handshake-only probe on the news port still
        // performs the upgrade and the second capability exchange — which is
        // the point, since a reachability probe that skipped the upgrade
        // would prove nothing about TLS.
        phase = if (cfg.handshake_only and step.nnext == .auth) .quit else step.nnext;
    }
}

/// The table row for `phase`, or null when this table has none.
fn lookupStep(table: []const fsm.NStep, phase: fsm.NPhase) ?fsm.NStep {
    for (table) |s| {
        if (s.nphase == phase) return s;
    }
    return null;
}

/// Write the command a table row sends. AUTHINFO is driven by `runAuthInfo`
/// instead, because it is an exchange rather than one line.
fn sendAction(cfg: Config, action: fsm.NAction, w: *std.Io.Writer) Error!void {
    switch (action) {
        .none => {}, // server speaks first (greeting)
        .capabilities => try w.writeAll("CAPABILITIES\r\n"),
        .starttls => try w.writeAll("STARTTLS\r\n"),
        // AUTHINFO is not one write — the 381 challenge is consumed by
        // `runAuthInfo`, which owns the exchange. A call arriving here is a
        // table the code does not match.
        .authinfo => return error.ProtocolError,
        .post => try w.writeAll("POST\r\n"),
        .payload => try writeArticle(cfg, w),
        .quit => try w.writeAll("QUIT\r\n"),
    }
}

/// Read one capability exchange: the status line, and for 101 also the
/// dot-terminated block of capabilities that follows it.
///
/// This is where NNTP's framing parts company with SMTP's. An SMTP multi-line
/// reply continues with '-' on the same 3-digit code; NNTP's 101 announces a
/// *block* whose lines carry no status at all and end with a lone ".". The
/// generic `readReply` below cannot know that, so it reads the status line and
/// this routine drains the block — otherwise the first capability line would
/// be read as though it were a status and reported as a malformed reply, which
/// is exactly what a server's VERSION line looks like.
fn readCapsReply(r: *std.Io.Reader, buf: []u8) (SessionError || std.Io.Reader.DelimiterError)!Reply {
    const first = try readReply(r, buf);
    if (first.code != 101) return first;

    var len = first.text.len;
    var truncated = first.truncated;
    var lines: usize = 0;
    while (true) {
        const raw = try r.takeDelimiterInclusive('\n');
        var line = std.mem.trimEnd(u8, raw, "\r\n");
        if (std.mem.eql(u8, line, ".")) break;
        // The block's own sentinel rule (RFC 3977 §3.1.1): a doubled leading
        // dot stands for a literal one. No real capability name starts with
        // '.', so this costs nothing and silently mangling one is not an
        // option either.
        if (line.len > 0 and line[0] == '.') line = line[1..];

        if (len > 0 and len < buf.len) {
            buf[len] = '\n';
            len += 1;
        }
        const n = @min(line.len, buf.len - len);
        @memcpy(buf[len..][0..n], line[0..n]);
        len += n;
        if (n < line.len) truncated = true;

        lines += 1;
        if (lines >= reply_line_max) return error.ReplyMalformed;
    }
    return .{ .code = first.code, .text = buf[0..len], .truncated = truncated };
}

/// Read one reply's status line: its 3-digit code plus the server's own words
/// accumulated into `buf`.
///
/// NNTP frames a single status line exactly as SMTP does — three digits, then
/// '-' on a continuation line and ' ' on the final one — so this is the same
/// reader the SMTP driver uses, including its refusal of lines that are not
/// reply lines at all and its cap on continuation lines. Multi-line *blocks*
/// are `readCapsReply`'s job, one level up.
fn readReply(r: *std.Io.Reader, buf: []u8) (SessionError || std.Io.Reader.DelimiterError)!Reply {
    var len: usize = 0;
    var truncated = false;
    var lines: usize = 0;
    while (true) {
        const raw = try r.takeDelimiterInclusive('\n');
        const line = std.mem.trimEnd(u8, raw, "\r\n");
        if (line.len < 3) return error.ReplyMalformed;
        for (line[0..3]) |c| {
            if (c < '0' or c > '9') return error.ReplyMalformed;
        }
        const code = std.fmt.parseInt(u16, line[0..3], 10) catch return error.ReplyMalformed;
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
        if (lines >= reply_line_max) return error.ReplyMalformed;
    }
}

/// A reply is accepted only if the current script row lists it. Unlisted
/// codes classify as transient (4xx), permanent (5xx), or protocol error.
/// The two codes that are 4xx but not retryable are named by the driver
/// before this is consulted; nothing else in an NNTP session is.
fn checkReply(step: fsm.NStep, code: u16) SessionError!void {
    for (step.nexpect) |ok| {
        if (code == ok) return;
    }
    if (code >= 400 and code < 500) return error.TransientFailure;
    if (code >= 500 and code < 600) return error.PermanentFailure;
    return error.ProtocolError;
}

/// Drive the AUTHINFO exchange for the mechanism the server actually offers.
///
/// USER/PASS (RFC 4643 §2) is three writes with a `381` demand in between, and
/// that demand is consumed HERE, deliberately off the proven table: admitting
/// 381 to the state machine would either break the invariant that 340 is its
/// sole intermediate reply, or force one table per transport x mechanism pair.
/// The exchange is corpus-tested, not proved — the same boundary KNOWN-DEFECTS
/// draws around the SMTP client's AUTH LOGIN.
///
/// The TERMINAL reply is not read here. It is left for the driver to check
/// against the row's `expect` list, so the thing that decides success or
/// failure stays on the proven path.
fn runAuthInfo(
    cfg: Config,
    wire: *@import("wire.zig").Wire,
    caps: *const Capabilities,
    buf: []u8,
    diag: ?*Diagnostic,
) Error!void {
    // Fail before a single credential byte is written. A server advertising
    // SASL alone needs a 383 continuation exchange this client does not
    // drive, and guessing USER at it would put the username on the wire for
    // nothing (the password follows only a 381).
    const mech = chooseMechanism(caps) orelse return error.AuthMechanismUnsupported;
    if (diag) |d| d.mechanism = mech;

    switch (mech) {
        .user_pass => {
            try wire.w.print("AUTHINFO USER {s}\r\n", .{cfg.username});
            try wire.flush();
            const challenge = try readReply(wire.r, buf);
            if (diag) |d| d.record(.auth, challenge, d.caps);
            if (challenge.code != 381) {
                // The interesting case: a server that rejects the username
                // outright does it HERE, and the reply that says why is the
                // one this branch is holding.
                if (challenge.code >= 400 and challenge.code < 500) return error.TransientFailure;
                if (challenge.code >= 500 and challenge.code < 600) return error.PermanentFailure;
                return error.ProtocolError;
            }
            try wire.w.print("AUTHINFO PASS {s}\r\n", .{cfg.password});
            if (cfg.username.len + cfg.password.len > 1024) return error.AuthTooLong;
        },
    }
}

/// RFC 5536 article: headers, blank line, dot-stuffed body, terminating ".".
///
/// Dot-stuffing is the whole reason the body goes through
/// `message.writeStuffedLine`: a body line of "." would otherwise end the
/// article early and truncate it silently, exactly as it would end DATA in
/// SMTP. The unstuffing rule is the same one RFC 3977 §3.1.1 inherits from
/// RFC 5321 §4.5.2, and the spec's `stuffSafe` theorem covers it for all
/// inputs.
fn writeArticle(cfg: Config, w: *std.Io.Writer) Error!void {
    try w.print("From: {s}\r\n", .{cfg.from});
    try w.writeAll("Newsgroups: ");
    try message.writeNewsgroups(w, cfg.newsgroups);
    try w.writeAll("\r\n");
    try w.writeAll("Subject: ");
    // ASCII is byte-for-byte what an ASCII subject should be; non-ASCII
    // becomes folded RFC 2047 encoded-words, because article headers are
    // ASCII (RFC 5536 §3.1) even though the body is 8-bit clean. Validity was
    // checked before the session started, so the error arm is defence in
    // depth.
    message.writeSubjectValue(w, "Subject: ".len, cfg.subject) catch |err| switch (err) {
        error.SubjectNotUtf8 => return error.SubjectNotUtf8,
        error.WriteFailed => return error.WriteFailed,
    };
    try w.writeAll("\r\n");
    try w.writeAll("Date: ");
    try message.writeRfc5322Date(w, cfg.date_epoch_seconds);
    try w.writeAll("\r\n");
    try w.print("Message-ID: {s}\r\n", .{cfg.message_id});
    if (cfg.content_language.len != 0) {
        try w.writeAll("Content-Language: ");
        try message.writeContentLanguage(w, cfg.content_language);
        try w.writeAll("\r\n");
    }
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

// ---------------------------------------------------------------------------
// Tests: whole scripted sessions, no network.
// ---------------------------------------------------------------------------

const test_cfg: Config = .{
    .username = "u",
    .password = "p",
    .from = "GitHub Push <bot@example.org>",
    .newsgroups = "alt.test",
    .subject = "[repo] push to main by owner",
    .body = "line one\n.\n.hidden\nlast line",
    .date_epoch_seconds = 1_000_000_000,
    .message_id = "<1000000000.deadbeef@example.org>",
};

/// Test helper: run a whole session against scripted replies; returns bytes written.
fn runScripted(cfg: Config, replies: []const u8, out: []u8) Error!usize {
    var r: std.Io.Reader = .fixed(replies);
    var w: std.Io.Writer = .fixed(out);
    try runSession(cfg, .{ .r = &r, .w = &w });
    return w.end;
}

/// Swaps in a *different* pair of in-memory streams when the driver calls for
/// the upgrade, for the reason the SMTP driver's copy gives: if the driver
/// forgot to replace its wire, the post-upgrade dialogue would be read from —
/// and written to — the cleartext pair, and every assertion would fail.
const TestUpgrade = struct {
    r: *std.Io.Reader,
    w: *std.Io.Writer,
    calls: usize = 0,

    fn upgrade(ctx: *anyopaque) anyerror!@import("wire.zig").Wire {
        const self: *TestUpgrade = @ptrCast(@alignCast(ctx));
        self.calls += 1;
        return .{ .r = self.r, .w = self.w };
    }

    fn upgrader(self: *TestUpgrade) @import("wire.zig").Upgrader {
        return .{ .ctx = self, .upgradeFn = TestUpgrade.upgrade };
    }
};

test "happy path: greeting, capability list, authinfo, post, article, quit" {
    const replies =
        "200 news.example.org NNTP ready\r\n" ++
        "101 Capability list:\r\nVERSION 2\r\nREADER\r\nPOST\r\nAUTHINFO USER SASL\r\nSTARTTLS\r\n.\r\n" ++
        "381 Password required\r\n" ++
        "281 Authentication accepted\r\n" ++
        "340 Send article to be posted. End with <CRLF>.<CRLF>\r\n" ++
        "240 Article received\r\n" ++
        "205 Closing connection\r\n";
    var out: [8192]u8 = undefined;
    const n = try runScripted(test_cfg, replies, &out);
    const sent = out[0..n];

    try std.testing.expectEqualStrings(
        "CAPABILITIES\r\nAUTHINFO USER u\r\nAUTHINFO PASS p\r\nPOST\r\n",
        sent[0.."CAPABILITIES\r\nAUTHINFO USER u\r\nAUTHINFO PASS p\r\nPOST\r\n".len],
    );
    try std.testing.expect(std.mem.indexOf(u8, sent, "From: GitHub Push <bot@example.org>\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, sent, "Newsgroups: alt.test\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, sent, "Subject: [repo] push to main by owner\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, sent, "Date: Sun, 9 Sep 2001 01:46:40 +0000\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, sent, "Message-ID: <1000000000.deadbeef@example.org>\r\n") != null);
    // The body is dot-stuffed and terminated, or the article would be
    // truncated on the wire with no error anywhere.
    try std.testing.expect(std.mem.indexOf(u8, sent, "\r\n..\r\n..hidden\r\nlast line\r\n.\r\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, sent, "QUIT\r\n"));
}

test "capabilities: a real 101 list is parsed, and the post-upgrade one replaces it" {
    const caps = parseCapabilities("VERSION 2\r\nREADER\r\nPOST\r\nAUTHINFO USER SASL\r\nSTARTTLS\r\nIMPLEMENTATION INN 2.8");
    try std.testing.expect(caps.starttls);
    try std.testing.expect(caps.post);
    try std.testing.expect(caps.reader);
    try std.testing.expect(caps.authinfo_user);
    try std.testing.expect(caps.authinfo_sasl);
    try std.testing.expectEqual(@as(?u16, 2), caps.version);
    try std.testing.expectEqualStrings("USER SASL", caps.authInfoRaw());

    // An unparseable VERSION is unstated, not zero — the same rule the SMTP
    // client applies to SIZE.
    const odd = parseCapabilities("VERSION two\r\nAUTHINFO SASL");
    try std.testing.expectEqual(@as(?u16, null), odd.version);
    try std.testing.expect(!odd.authinfo_user);

    // A list that names no AUTHINFO at all is distinguishable from one that
    // names SASL alone, which is what the mechanism choice turns on.
    const none = parseCapabilities("VERSION 2\r\nPOST");
    try std.testing.expectEqual(@as(usize, 0), none.authInfoRaw().len);
}

test "the implicit table has no upgrade rows to walk" {
    // The proof is in the spec; this is the code-side reading of it, so a
    // generated table that grew a STARTTLS row on the wrong shape cannot pass
    // unnoticed even if the drift gate were skipped.
    const table = fsm.nntpScriptFor(false);
    for (table) |s| {
        try std.testing.expect(s.nphase != .starttls);
        try std.testing.expect(s.nphase != .caps_tls);
    }
}

test "a 201 greeting is a refusal to post, not an unlisted reply" {
    const replies = "201 news.example.org posting prohibited\r\n";
    var out: [256]u8 = [_]u8{0} ** 256;
    try std.testing.expectError(error.PostingNotPermitted, runScripted(test_cfg, replies, &out));
    // Nothing but the abort courtesy went out: no CAPABILITIES, no POST, and
    // above all no article.
    try std.testing.expectEqualStrings("QUIT\r\n", out[0..6]);
    for (out[6..]) |c| try std.testing.expectEqual(@as(u8, 0), c);
}

test "440 at POST is a refusal to post, not a transient failure to retry" {
    // 440 answers POST itself: the server will not take an article from this
    // session at all.
    const replies =
        "200 news.example.org ready\r\n" ++
        "101 Capability list:\r\nVERSION 2\r\nPOST\r\nAUTHINFO USER\r\n.\r\n" ++
        "381 Password required\r\n281 Accepted\r\n" ++
        "440 Posting not permitted\r\n";
    var out: [1024]u8 = undefined;
    var r: std.Io.Reader = .fixed(replies);
    var w: std.Io.Writer = .fixed(&out);
    var diag: Diagnostic = .{};
    try std.testing.expectError(error.PostingNotPermitted, runSessionDiag(test_cfg, .{ .r = &r, .w = &w }, &diag));
    try std.testing.expectEqual(fsm.NPhase.post, diag.phase);
    try std.testing.expectEqual(@as(u16, 440), diag.code);
}

test "440 or 441 after the article is sent is still a refusal, not a retry" {
    // The article has already gone out when the server answers; a 4xx class
    // rule would say "transient, retry" and duplicate the post. Both codes
    // must be recognised at the payload row too, or that is exactly the
    // advice the operator gets.
    inline for (.{ .{ "440 Posting not permitted", error.PostingNotPermitted }, .{ "441 Posting failed: rejected by the news administrator", error.ArticleRejected } }) |case| {
        const replies = "200 news.example.org ready\r\n" ++
            "101 Capability list:\r\nVERSION 2\r\nPOST\r\nAUTHINFO USER\r\n.\r\n" ++
            "381 Password required\r\n281 Accepted\r\n" ++
            "340 Send article\r\n" ++ case[0] ++ "\r\n";
        var out: [4096]u8 = undefined;
        var r: std.Io.Reader = .fixed(replies);
        var w: std.Io.Writer = .fixed(&out);
        var diag: Diagnostic = .{};
        try std.testing.expectError(case[1], runSessionDiag(test_cfg, .{ .r = &r, .w = &w }, &diag));
        try std.testing.expectEqual(fsm.NPhase.payload, diag.phase);
    }
}

test "a server that closes instead of answering QUIT does not fail a posted article" {
    // The article was accepted (240); the connection then just ends. Reporting
    // this as a failure would tell the caller to post again, which is worse
    // than the missing courtesy reply.
    const replies =
        "200 news.example.org ready\r\n" ++
        "101 Capability list:\r\nVERSION 2\r\nPOST\r\nAUTHINFO USER\r\n.\r\n" ++
        "381 Password required\r\n281 Accepted\r\n" ++
        "340 Send article\r\n" ++
        "240 Article received\r\n";
    var out: [4096]u8 = undefined;
    const n = try runScripted(test_cfg, replies, &out);
    try std.testing.expect(std.mem.endsWith(u8, out[0..n], "QUIT\r\n"));
}

test "QUIT that is answered 205 is the ordinary ending" {
    const replies =
        "200 ready\r\n" ++
        "101 Capability list:\r\nVERSION 2\r\nPOST\r\nAUTHINFO USER\r\n.\r\n" ++
        "381 Password required\r\n281 Accepted\r\n" ++
        "340 Send article\r\n240 Article received\r\n205 Closing\r\n";
    var out: [4096]u8 = undefined;
    var r: std.Io.Reader = .fixed(replies);
    var w: std.Io.Writer = .fixed(&out);
    var diag: Diagnostic = .{};
    try runSessionDiag(test_cfg, .{ .r = &r, .w = &w }, &diag);
    try std.testing.expectEqual(fsm.NPhase.quit, diag.phase);
    try std.testing.expectEqual(@as(u16, 205), diag.code);
    try std.testing.expect(std.mem.endsWith(u8, out[0..w.end], "QUIT\r\n"));
}

test "STARTTLS: the session moves onto the upgraded stream and re-advertises" {
    var clear_r: std.Io.Reader = .fixed(
        "200 news.example.org ready\r\n" ++
            "101 Capability list:\r\nVERSION 2\r\nSTARTTLS\r\n.\r\n" ++
            "382 Continue with TLS negotiation\r\n",
    );
    var clear_buf: [4096]u8 = undefined;
    var clear_w: std.Io.Writer = .fixed(&clear_buf);

    var tls_r: std.Io.Reader = .fixed(
        "101 Capability list:\r\nVERSION 2\r\nPOST\r\nAUTHINFO USER\r\n.\r\n" ++
            "381 Password required\r\n281 Accepted\r\n" ++
            "340 Send article\r\n240 Article received\r\n205 Closing\r\n",
    );
    var tls_buf: [8192]u8 = undefined;
    var tls_w: std.Io.Writer = .fixed(&tls_buf);

    var up: TestUpgrade = .{ .r = &tls_r, .w = &tls_w };
    var cfg = test_cfg;
    cfg.use_starttls = true;
    cfg.upgrader = up.upgrader();

    var diag: Diagnostic = .{};
    try runSessionDiag(cfg, .{ .r = &clear_r, .w = &clear_w }, &diag);

    try std.testing.expectEqual(@as(usize, 1), up.calls);
    // Cleartext: the capability exchange and the upgrade, and nothing that
    // carries a secret.
    try std.testing.expectEqualStrings("CAPABILITIES\r\nSTARTTLS\r\n", clear_buf[0..clear_w.end]);
    // Encrypted: the mandatory second capability exchange (RFC 4642 §2.2)
    // and the whole article.
    const tls = tls_buf[0..tls_w.end];
    try std.testing.expect(std.mem.startsWith(u8, tls, "CAPABILITIES\r\nAUTHINFO USER u\r\n"));
    try std.testing.expect(std.mem.endsWith(u8, tls, "QUIT\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, tls, "Newsgroups: alt.test\r\n") != null);
    try std.testing.expectEqual(fsm.NPhase.quit, diag.phase);
}

test "STARTTLS: a server that does not advertise it gets no command and no fallback" {
    var clear_r: std.Io.Reader = .fixed(
        "200 news.example.org ready\r\n" ++
            "101 Capability list:\r\nVERSION 2\r\nPOST\r\nAUTHINFO USER\r\n.\r\n",
    );
    var clear_buf: [512]u8 = undefined;
    var clear_w: std.Io.Writer = .fixed(&clear_buf);
    // A second pair that must never be reached: if the driver upgraded
    // without being offered it, this is where the session would continue.
    var tls_r: std.Io.Reader = .fixed("");
    var tls_buf: [512]u8 = undefined;
    var tls_w: std.Io.Writer = .fixed(&tls_buf);
    var up: TestUpgrade = .{ .r = &tls_r, .w = &tls_w };
    var cfg = test_cfg;
    cfg.use_starttls = true;
    cfg.upgrader = up.upgrader();

    try std.testing.expectError(error.StartTlsNotOffered, runSession(cfg, .{ .r = &clear_r, .w = &clear_w }));

    // The capability exchange and the abort courtesy; no STARTTLS was sent,
    // and no credential went anywhere near the cleartext stream.
    try std.testing.expectEqualStrings("CAPABILITIES\r\nQUIT\r\n", clear_buf[0..clear_w.end]);
    try std.testing.expectEqual(@as(usize, 0), up.calls);
}

test "STARTTLS: selected without an upgrader is refused before anything is sent" {
    var r: std.Io.Reader = .fixed("200 ready\r\n");
    var out: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    var cfg = test_cfg;
    cfg.use_starttls = true;
    try std.testing.expectError(error.StartTlsUnconfigured, runSession(cfg, .{ .r = &r, .w = &w }));
    try std.testing.expectEqual(@as(usize, 0), w.end);
}

test "handshake-only: capabilities then quit, no authinfo, no article" {
    const replies =
        "200 news.example.org ready\r\n" ++
        "101 Capability list:\r\nVERSION 2\r\nPOST\r\nAUTHINFO USER\r\n.\r\n" ++
        "205 Closing\r\n";
    var out: [512]u8 = undefined;
    var cfg = test_cfg;
    cfg.handshake_only = true;
    const n = try runScripted(cfg, replies, &out);
    try std.testing.expectEqualStrings("CAPABILITIES\r\nQUIT\r\n", out[0..n]);
}

test "handshake-only on the STARTTLS path still upgrades before quitting" {
    var clear_r: std.Io.Reader = .fixed(
        "200 ready\r\n101 Capability list:\r\nVERSION 2\r\nSTARTTLS\r\n.\r\n" ++
            "382 Continue\r\n",
    );
    var clear_buf: [512]u8 = undefined;
    var clear_w: std.Io.Writer = .fixed(&clear_buf);
    var tls_r: std.Io.Reader = .fixed("101 Capability list:\r\nVERSION 2\r\nPOST\r\n.\r\n205 Closing\r\n");
    var tls_buf: [512]u8 = undefined;
    var tls_w: std.Io.Writer = .fixed(&tls_buf);
    var up: TestUpgrade = .{ .r = &tls_r, .w = &tls_w };
    var cfg = test_cfg;
    cfg.use_starttls = true;
    cfg.handshake_only = true;
    cfg.upgrader = up.upgrader();
    try runSession(cfg, .{ .r = &clear_r, .w = &clear_w });
    try std.testing.expectEqual(@as(usize, 1), up.calls);
    try std.testing.expectEqualStrings("CAPABILITIES\r\nQUIT\r\n", tls_buf[0..tls_w.end]);
}

test "AUTHINFO: a server advertising only SASL is refused before a credential is written" {
    const replies =
        "200 ready\r\n" ++
        "101 Capability list:\r\nVERSION 2\r\nPOST\r\nAUTHINFO SASL PLAIN\r\n.\r\n";
    const sent = "CAPABILITIES\r\nQUIT\r\n";
    var out: [512]u8 = [_]u8{0} ** 512;
    try std.testing.expectError(error.AuthMechanismUnsupported, runScripted(test_cfg, replies, &out));
    // The capability exchange and the abort courtesy — and not one byte of
    // credential.
    try std.testing.expectEqualStrings(sent, out[0..sent.len]);
    for (out[sent.len..]) |c| try std.testing.expectEqual(@as(u8, 0), c);
}

test "AUTHINFO: a server that advertises nothing still gets USER/PASS" {
    // The same rule the SMTP client applies to a server with no AUTH line:
    // not listing a mechanism is not the same as not supporting one, and the
    // password still only follows a 381.
    const replies =
        "200 ready\r\n" ++
        "101 Capability list:\r\nVERSION 2\r\nPOST\r\n.\r\n" ++
        "381 Password required\r\n281 Accepted\r\n" ++
        "340 Send article\r\n240 Article received\r\n205 Closing\r\n";
    var out: [4096]u8 = undefined;
    const n = try runScripted(test_cfg, replies, &out);
    try std.testing.expect(std.mem.indexOf(u8, out[0..n], "AUTHINFO USER u\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out[0..n], "AUTHINFO PASS p\r\n") != null);
}

test "AUTHINFO: a rejection at USER never sends the password" {
    const replies =
        "200 ready\r\n" ++
        "101 Capability list:\r\nVERSION 2\r\nPOST\r\nAUTHINFO USER\r\n.\r\n" ++
        "481 Authentication failed\r\n";
    var out: [1024]u8 = undefined;
    var r: std.Io.Reader = .fixed(replies);
    var w: std.Io.Writer = .fixed(&out);
    var diag: Diagnostic = .{};
    try std.testing.expectError(error.TransientFailure, runSessionDiag(test_cfg, .{ .r = &r, .w = &w }, &diag));
    try std.testing.expect(std.mem.indexOf(u8, out[0..w.end], "PASS") == null);
    try std.testing.expectEqual(@as(u16, 481), diag.code);
    try std.testing.expectEqual(fsm.NPhase.auth, diag.phase);
}

test "CRLF in newsgroups, subject or message-id is refused before any byte reaches the wire" {
    var out: [512]u8 = undefined;
    const replies = "200 ready\r\n";
    var cfg = test_cfg;
    cfg.newsgroups = "alt.test\r\nX-Injected: 1";
    try std.testing.expectError(error.HeaderInjection, runScripted(cfg, replies, &out));
    cfg = test_cfg;
    cfg.subject = "hello\r\nBcc: victim@example.org";
    try std.testing.expectError(error.HeaderInjection, runScripted(cfg, replies, &out));
    cfg = test_cfg;
    cfg.message_id = "<id@example.org>\r\nX-Injected: 1";
    try std.testing.expectError(error.HeaderInjection, runScripted(cfg, replies, &out));
}

test "a malformed newsgroup name is refused, not repaired" {
    var out: [512]u8 = undefined;
    const replies = "200 ready\r\n";
    var cfg = test_cfg;
    cfg.newsgroups = "alt..test";
    try std.testing.expectError(error.NewsgroupsInvalid, runScripted(cfg, replies, &out));
    cfg.newsgroups = "control";
    try std.testing.expectError(error.NewsgroupsInvalid, runScripted(cfg, replies, &out));
}

test "an invalid Content-Language is refused for the NNTP transport too" {
    var out: [512]u8 = undefined;
    const replies = "200 ready\r\n";
    var cfg = test_cfg;
    cfg.content_language = "en_GB";
    try std.testing.expectError(error.ContentLanguageInvalid, runScripted(cfg, replies, &out));
}

test "Message-ID shape" {
    try std.testing.expect(messageIdOk("<1000.ab@example.org>"));
    try std.testing.expect(messageIdOk("<a@b>"));
    try std.testing.expect(!messageIdOk("1000.ab@example.org")); // not bracketed
    try std.testing.expect(!messageIdOk("<@example.org>")); // empty local part
    try std.testing.expect(!messageIdOk("<id@>")); // empty domain
    try std.testing.expect(!messageIdOk("<a@@b>")); // two '@'
    try std.testing.expect(!messageIdOk("<a b@example.org>")); // space inside
    try std.testing.expect(!messageIdOk("<>"));
    try std.testing.expect(!messageIdOk("<a@b><c@d>"));
}

test "the reply-buffer policy is the SMTP driver's, not a second opinion" {
    const smtp = @import("smtp.zig");
    try std.testing.expectEqual(smtp.reply_text_max, reply_text_max);
}

test "a session records the server's capabilities, not only its failures" {
    const replies =
        "200 ready\r\n" ++
        "101 Capability list:\r\nVERSION 2\r\nPOST\r\nAUTHINFO USER SASL\r\nSTARTTLS\r\n.\r\n" ++
        "381 Password required\r\n281 Accepted\r\n" ++
        "340 Send article\r\n240 Article received\r\n205 Closing\r\n";
    var out: [4096]u8 = undefined;
    var r: std.Io.Reader = .fixed(replies);
    var w: std.Io.Writer = .fixed(&out);
    var diag: Diagnostic = .{};
    try runSessionDiag(test_cfg, .{ .r = &r, .w = &w }, &diag);
    try std.testing.expect(diag.caps.starttls);
    try std.testing.expect(diag.caps.post);
    try std.testing.expect(diag.caps.authinfo_user);
    try std.testing.expectEqual(Mechanism.user_pass, diag.mechanism.?);
}
