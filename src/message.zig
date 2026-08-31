// SPDX-License-Identifier: MPL-2.0
//! Message serialization per the proven contract in spec/Smtp/Serialize.idr:
//! DATA dot-stuffing (RFC 5321 §4.5.2), CRLF rejection in header-bound
//! values (header-injection defense), and RFC 5322 date formatting.
//!
//! The tests at the bottom run against golden vectors that the Idris2 spec
//! COMPUTED with its own functions at generation time — so this file is
//! checked against the spec's evaluation, not a hand-written copy of it.

const std = @import("std");
const fsm = @import("generated/smtp_fsm.zig");

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

test "RFC 5322 date formatting" {
    var buf: [64]u8 = undefined;

    var w: std.Io.Writer = .fixed(&buf);
    try writeRfc5322Date(&w, 0);
    try std.testing.expectEqualStrings("Thu, 1 Jan 1970 00:00:00 +0000", w.buffer[0..w.end]);

    var w2: std.Io.Writer = .fixed(&buf);
    try writeRfc5322Date(&w2, 1_000_000_000);
    try std.testing.expectEqualStrings("Sun, 9 Sep 2001 01:46:40 +0000", w2.buffer[0..w2.end]);
}
