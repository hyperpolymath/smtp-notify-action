// SPDX-License-Identifier: MPL-2.0
//! Message serialization per the proven contract in spec/Smtp/Serialize.idr:
//! DATA dot-stuffing (RFC 5321 §4.5.2), CRLF rejection in header-bound
//! values (header-injection defense), the Content-Language grammar
//! (RFC 3282 / RFC 5646), RFC 2047 subject encoding, and RFC 5322 dates.
//!
//! The tests at the bottom run against golden vectors that the Idris2 spec
//! COMPUTED with its own functions at generation time — so this file is
//! checked against the spec's evaluation, not a hand-written copy of it.

const std = @import("std");
const fsm = @import("generated/smtp_fsm.zig");

/// True when a body line starts with "." and so must be dot-stuffed.
pub fn needsStuffing(line: []const u8) bool {
    return line.len > 0 and line[0] == '.';
}

/// Write one body line in transmit encoding: dot-stuffed, CRLF-terminated.
/// A line beginning with '.' is sent with the dot doubled; otherwise a body
/// line of "." would terminate DATA early (silent message truncation).
pub fn writeStuffedLine(w: *std.Io.Writer, line: []const u8) std.Io.Writer.Error!void {
    if (needsStuffing(line)) try w.writeByte('.');
    try w.writeAll(line);
    try w.writeAll("\r\n");
}

/// A value interpolated into a header line (From, To, Subject) must contain
/// no CR and no LF. The client REJECTS bad values, never sanitizes them —
/// silent rewriting is how injection bugs hide.
pub fn headerValueOk(value: []const u8) bool {
    for (value) |c| {
        if (c == '\r' or c == '\n') return false;
    }
    return true;
}

/// ASCII letter test; RFC 5646 subtags are ASCII only.
fn isAsciiAlpha(c: u8) bool {
    return (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z');
}

/// ASCII letter-or-digit test; RFC 5646 subtags are ASCII only.
fn isAsciiAlphaNum(c: u8) bool {
    return isAsciiAlpha(c) or (c >= '0' and c <= '9');
}

/// One subtag: 1-8 ASCII letters or digits. Mirrors `subtagOk` in the spec.
fn subtagOk(s: []const u8) bool {
    if (s.len < 1 or s.len > 8) return false;
    for (s) |c| if (!isAsciiAlphaNum(c)) return false;
    return true;
}

/// One RFC 5646 tag, by shape only (no IANA registry lookup): primary
/// subtag alphabetic, every subtag 1-8 ASCII alphanumerics, no empty subtag.
/// Mirrors `langTagOk` in spec/Smtp/Serialize.idr.
pub fn langTagOk(tag: []const u8) bool {
    var it = std.mem.splitScalar(u8, tag, '-');
    const primary = it.next() orelse return false;
    if (!subtagOk(primary)) return false;
    for (primary) |c| if (!isAsciiAlpha(c)) return false;
    while (it.next()) |sub| if (!subtagOk(sub)) return false;
    return true;
}

/// An RFC 3282 Content-Language value: comma-separated tags, optional
/// spaces around each. Mirrors `contentLanguageOk` in the spec, including
/// its explicit header-injection conjunct — the theorem
/// `contentLanguageNoInjection` is stated over exactly this conjunction.
pub fn contentLanguageOk(value: []const u8) bool {
    var it = std.mem.splitScalar(u8, value, ',');
    while (it.next()) |raw| {
        if (!langTagOk(std.mem.trim(u8, raw, " "))) return false;
    }
    return headerValueOk(value);
}

/// RFC 2047 §2: an encoded-word is at most 75 characters, and a header line
/// that contains one is at most 76. "=?UTF-8?B?" plus "?=" is 12 of those.
const ew_line_max = 76;
const ew_overhead = 12;

/// Largest input chunk whose encoded-word fits in `room` characters: whole
/// base64 quanta only (4 chars per 3 bytes), so padding never lands mid-run.
fn chunkBytesFor(room: usize) usize {
    return ((room - ew_overhead) / 4) * 3;
}

/// True when the subject can go on the wire as-is (pure ASCII) or be
/// RFC 2047 encoded (valid UTF-8). Anything else is refused before the
/// session starts: labelling invalid bytes "UTF-8" would be a lie the
/// recipient's client then has to guess its way around.
pub fn subjectEncodable(subject: []const u8) bool {
    return std.unicode.utf8ValidateSlice(subject);
}

/// True when every byte is 7-bit, so the subject can go out unencoded.
fn isAscii(s: []const u8) bool {
    for (s) |c| if (c >= 0x80) return false;
    return true;
}

pub const SubjectError = error{SubjectNotUtf8} || std.Io.Writer.Error;

/// Write a Subject: value, `prefix_len` characters into its header line
/// ("Subject: " is 9). ASCII goes out byte-for-byte, unchanged from earlier
/// releases. Anything else becomes RFC 2047 "B" encoded-words holding whole
/// code points, folded onto continuation lines (CRLF SP) so that EVERY line
/// — the first, which shares its line with the field name, included — stays
/// within the 76 characters RFC 2047 §2 allows a line carrying an
/// encoded-word. No buffer scales with the input: each chunk is encoded
/// through a fixed scratch sized for the largest chunk.
pub fn writeSubjectValue(w: *std.Io.Writer, prefix_len: usize, subject: []const u8) SubjectError!void {
    if (isAscii(subject)) return w.writeAll(subject);
    if (!subjectEncodable(subject)) return error.SubjectNotUtf8;
    std.debug.assert(prefix_len + ew_overhead + 4 <= ew_line_max);
    const later_max = chunkBytesFor(ew_line_max - 1); // continuation lines start with one SP
    var b64: [std.base64.standard.Encoder.calcSize(chunkBytesFor(ew_line_max - 1))]u8 = undefined;
    var i: usize = 0;
    var first = true;
    while (i < subject.len) {
        const max = if (first) chunkBytesFor(ew_line_max - prefix_len) else later_max;
        var end = @min(i + max, subject.len);
        // Back off to the start of a code point. A UTF-8 sequence is at most
        // four bytes and every chunk budget is at least six, so this retreats
        // at most three and always progresses.
        while (end < subject.len and (subject[end] & 0xC0) == 0x80) end -= 1;
        std.debug.assert(end > i);
        if (!first) try w.writeAll("\r\n ");
        first = false;
        try w.writeAll("=?UTF-8?B?");
        try w.writeAll(std.base64.standard.Encoder.encode(&b64, subject[i..end]));
        try w.writeAll("?=");
        i = end;
    }
}

/// Write a validated comma-separated value in canonical form: items trimmed
/// and joined with ", ". Validation accepts optional spaces around each item;
/// they are not worth carrying onto the wire.
fn writeCommaSeparated(w: *std.Io.Writer, value: []const u8) std.Io.Writer.Error!void {
    var it = std.mem.splitScalar(u8, value, ',');
    var first = true;
    while (it.next()) |raw| {
        if (!first) try w.writeAll(", ");
        first = false;
        try w.writeAll(std.mem.trim(u8, raw, " "));
    }
}

/// Write a validated Content-Language value in canonical form.
pub fn writeContentLanguage(w: *std.Io.Writer, value: []const u8) std.Io.Writer.Error!void {
    return writeCommaSeparated(w, value);
}

/// Write a validated Newsgroups value in canonical form. Same shape as
/// Content-Language because RFC 5536 §3.1.4 also makes Newsgroups a
/// comma-separated list with optional spaces — the dot in a name separates
/// hierarchy components, not entries.
pub fn writeNewsgroups(w: *std.Io.Writer, value: []const u8) std.Io.Writer.Error!void {
    return writeCommaSeparated(w, value);
}

/// Character set a newsgroup name component may use. Mirrors `isGroupChar` in
/// spec/Nntp/Serialize.idr: RFC 5536 §3.1.4 restricts the field to 7-bit
/// printable ASCII and forbids '*'; this client admits only the set the
/// hierarchy actually uses (letters, digits, '+', '-', '_').
fn isGroupChar(c: u8) bool {
    return (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or
        (c >= '0' and c <= '9') or c == '+' or c == '-' or c == '_';
}

const group_component_max = 32;
const group_name_max = 255;

/// One dot-separated component: 1-32 characters, none of them a separator.
fn groupComponentOk(s: []const u8) bool {
    if (s.len < 1 or s.len > group_component_max) return false;
    for (s) |c| if (!isGroupChar(c)) return false;
    return true;
}

/// A newsgroup name: dot-separated well-formed components, so no leading,
/// trailing or doubled '.' (each of which yields an empty component).
fn groupNameShaped(s: []const u8) bool {
    var it = std.mem.splitScalar(u8, s, '.');
    while (it.next()) |comp| {
        if (!groupComponentOk(comp)) return false;
    }
    return true;
}

/// RFC 5536 §3.1.4: `control` and `control.*` are reserved for control
/// messages and MUST NOT be used for normal articles.
fn groupReserved(s: []const u8) bool {
    return std.mem.eql(u8, s, "control") or std.mem.startsWith(u8, s, "control.");
}

/// One newsgroup name as this client accepts it. Shape only — whether the
/// group exists, or is carried by the server, is the server's answer, not
/// this predicate's.
pub fn newsgroupOk(s: []const u8) bool {
    return groupNameShaped(s) and !groupReserved(s) and s.len <= group_name_max;
}

/// A Newsgroups value: comma-separated names, optional spaces around each,
/// plus the header-injection conjunct. Mirrors `newsgroupsOk` in
/// spec/Nntp/Serialize.idr, whose theorem `newsgroupsNoInjection` is stated
/// over exactly this conjunction.
pub fn newsgroupsOk(value: []const u8) bool {
    var it = std.mem.splitScalar(u8, value, ',');
    while (it.next()) |raw| {
        if (!newsgroupOk(std.mem.trim(u8, raw, " "))) return false;
    }
    return headerValueOk(value);
}

const day_names = [7][]const u8{ "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
const month_names = [12][]const u8{
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
};

/// RFC 5322 date-time (UTC) from Unix seconds, e.g.
/// "Sun, 9 Sep 2001 01:46:40 +0000".
pub fn writeRfc5322Date(w: *std.Io.Writer, epoch_seconds: i64) std.Io.Writer.Error!void {
    const secs: u64 = if (epoch_seconds > 0) @intCast(epoch_seconds) else 0;
    const es: std.time.epoch.EpochSeconds = .{ .secs = secs };
    const epoch_day = es.getEpochDay();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_secs = es.getDaySeconds();
    const weekday: usize = @intCast((epoch_day.day + 4) % 7); // 1970-01-01 = Thursday
    try w.print("{s}, {d} {s} {d} {d:0>2}:{d:0>2}:{d:0>2} +0000", .{
        day_names[weekday],
        month_day.day_index + 1,
        month_names[month_day.month.numeric() - 1],
        year_day.year,
        day_secs.getHoursIntoDay(),
        day_secs.getMinutesIntoHour(),
        day_secs.getSecondsIntoMinute(),
    });
}

test "dot-stuffing agrees with the spec's golden vectors" {
    for (fsm.stuff_vectors) |v| {
        var buf: [128]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        try writeStuffedLine(&w, v.input);
        const got = w.buffer[0..w.end];
        try std.testing.expect(got.len >= 2);
        try std.testing.expectEqualStrings("\r\n", got[got.len - 2 ..]);
        try std.testing.expectEqualStrings(v.expected, got[0 .. got.len - 2]);
    }
}

test "header-injection verdicts agree with the spec's golden vectors" {
    for (fsm.header_vectors) |v| {
        try std.testing.expectEqual(v.ok, headerValueOk(v.input));
    }
}

test "Content-Language verdicts agree with the spec's golden vectors" {
    for (fsm.lang_vectors) |v| {
        std.testing.expectEqual(v.ok, contentLanguageOk(v.input)) catch |err| {
            std.debug.print("lang vector disagreed: \"{s}\"\n", .{v.input});
            return err;
        };
    }
}

/// Decode a folded run of encoded-words back to the original bytes, checking
/// every structural rule on the way. Test-only: the client never decodes.
fn decodeEncodedWords(encoded: []const u8, out: []u8) ![]const u8 {
    var len: usize = 0;
    var words = std.mem.splitSequence(u8, encoded, "\r\n ");
    while (words.next()) |word| {
        try std.testing.expect(word.len <= 75);
        try std.testing.expect(std.mem.startsWith(u8, word, "=?UTF-8?B?"));
        try std.testing.expect(std.mem.endsWith(u8, word, "?="));
        const payload = word[10 .. word.len - 2];
        const n = try std.base64.standard.Decoder.calcSizeForSlice(payload);
        try std.base64.standard.Decoder.decode(out[len..][0..n], payload);
        // Each word must hold whole code points on its own (RFC 2047 §5).
        try std.testing.expect(std.unicode.utf8ValidateSlice(out[len..][0..n]));
        len += n;
    }
    return out[0..len];
}

test "RFC 2047: an ASCII subject is written unchanged" {
    var buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeSubjectValue(&w, 9, "[repo] push to main by owner");
    try std.testing.expectEqualStrings("[repo] push to main by owner", w.buffer[0..w.end]);
}

test "RFC 2047: a short non-ASCII subject is one encoded-word" {
    var buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeSubjectValue(&w, 9, "Café");
    // base64("Café") = "Q2Fmw6k="
    try std.testing.expectEqualStrings("=?UTF-8?B?Q2Fmw6k=?=", w.buffer[0..w.end]);
}

test "RFC 2047: long subjects fold into words of <= 75 chars holding whole code points" {
    // 4-byte (emoji), 3-byte (CJK), 2-byte (Welsh ŵ) and ASCII mixed, far
    // past one word and far past the 2048-byte buffer the first attempt at
    // this used — which overflowed rather than failing.
    const unit = "Llongyfarchiadau ŵyr 🎉 推送到主分支 ";
    var subject_buf: [unit.len * 80]u8 = undefined;
    for (0..80) |k| @memcpy(subject_buf[k * unit.len ..][0..unit.len], unit);
    const subject = subject_buf[0..];

    var out: [16384]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    try writeSubjectValue(&w, 9, subject);
    const wire = w.buffer[0..w.end];
    try std.testing.expect(std.mem.indexOfScalar(u8, wire, '\n') != null); // it folded

    var dec: [unit.len * 80]u8 = undefined;
    const round = try decodeEncodedWords(wire, &dec);
    try std.testing.expectEqualStrings(subject, round);
}

test "RFC 2047: no line of a folded Subject header exceeds 76 characters" {
    var subj: [600]u8 = undefined;
    for (0..150) |k| @memcpy(subj[k * 4 ..][0..4], "🎉");
    for ([_]usize{ 1, 2, 3, 38, 39, 40, 44, 45, 46, 200, 600 }) |len| {
        // Cut to whole code points (4-byte emoji) plus an ASCII tail.
        const s = subj[0 .. len - (len % 4)];
        if (s.len == 0) continue;
        var out: [2048]u8 = undefined;
        var w: std.Io.Writer = .fixed(&out);
        try w.writeAll("Subject: ");
        try writeSubjectValue(&w, 9, s);
        var lines = std.mem.splitSequence(u8, w.buffer[0..w.end], "\r\n");
        while (lines.next()) |line| try std.testing.expect(line.len <= 76);
    }
}

test "Content-Language is written trimmed and ', '-joined" {
    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeContentLanguage(&w, " en ,cy ");
    try std.testing.expectEqualStrings("en, cy", w.buffer[0..w.end]);
}

test "Newsgroups verdicts agree with the spec's golden vectors" {
    for (fsm.newsgroup_vectors) |v| {
        std.testing.expectEqual(v.ok, newsgroupsOk(v.input)) catch |err| {
            std.debug.print("newsgroup vector disagreed: \"{s}\" (spec says {s})\n", .{ v.input, if (v.ok) "ok" else "refused" });
            return err;
        };
    }
}

test "Newsgroups is written trimmed and ', '-joined" {
    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeNewsgroups(&w, " alt.test ,uk.rec.cycling ");
    try std.testing.expectEqualStrings("alt.test, uk.rec.cycling", w.buffer[0..w.end]);
}

test "RFC 2047: every chunk boundary position round-trips" {
    // Slide a 4-byte code point across the 45-byte chunk boundary.
    var out: [1024]u8 = undefined;
    var dec: [256]u8 = undefined;
    var subj: [64]u8 = undefined;
    for (34..50) |pad| {
        @memset(subj[0..pad], 'a');
        @memcpy(subj[pad..][0..4], "🎉");
        subj[pad + 4] = 'z';
        const s = subj[0 .. pad + 5];
        var w: std.Io.Writer = .fixed(&out);
        try writeSubjectValue(&w, 9, s);
        try std.testing.expectEqualStrings(s, try decodeEncodedWords(w.buffer[0..w.end], &dec));
    }
}

test "RFC 2047: invalid UTF-8 is refused, not mislabelled" {
    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try std.testing.expectError(error.SubjectNotUtf8, writeSubjectValue(&w, 9, "bad \xff byte"));
    try std.testing.expect(!subjectEncodable("bad \xc3"));
}

test "RFC 5322 date formatting" {
    var buf: [64]u8 = undefined;

    var w: std.Io.Writer = .fixed(&buf);
    try writeRfc5322Date(&w, 0);
    try std.testing.expectEqualStrings("Thu, 1 Jan 1970 00:00:00 +0000", w.buffer[0..w.end]);

    var w2: std.Io.Writer = .fixed(&buf);
    try writeRfc5322Date(&w2, 1_000_000_000);
    try std.testing.expectEqualStrings("Sun, 9 Sep 2001 01:46:40 +0000", w2.buffer[0..w2.end]);
}
