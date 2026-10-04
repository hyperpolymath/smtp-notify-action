// SPDX-License-Identifier: MPL-2.0
//! The byte streams a protocol session rides on, and the in-place upgrade
//! callback that swaps them for encrypted ones.
//!
//! These types began inside `src/smtp.zig`. They live in their own module now
//! that a second driver uses them, so that "the same wire" is one definition
//! rather than two that happen to agree — and so that anything the NNTP
//! driver learns about flushing a layered transport (see `Wire.flush`) is
//! necessarily true of the SMTP driver too.
//!
//! Nothing here knows about SMTP or NNTP: it is readers, writers, and a
//! callback that returns a different pair of them once a server has accepted
//! an upgrade.

const std = @import("std");

/// The byte streams a session rides on.
pub const Wire = struct {
    r: *std.Io.Reader,
    w: *std.Io.Writer,
    /// For layered transports (TLS over TCP): flushing `w` only encrypts
    /// buffered plaintext into the transport writer below — that writer must
    /// then be flushed itself for the records to reach the socket.
    below: ?*std.Io.Writer = null,

    /// Flush this layer and, for TLS, the transport writer beneath it.
    pub fn flush(wire: Wire) std.Io.Writer.Error!void {
        try wire.w.flush();
        if (wire.below) |b| try b.flush();
    }
};

/// Turns the current stream into an encrypted one, in place, after the server
/// has accepted the protocol's upgrade command (STARTTLS in both protocols
/// this client speaks).
///
/// A driver deliberately knows nothing about TLS — it talks to generic readers
/// and writers so the tests can drive whole sessions against in-memory
/// scripts. The upgrade is therefore a callback the caller supplies: main.zig
/// hands over one backed by `src/tls/Client.zig`, and a test hands over one
/// that simply swaps in a different in-memory stream, which is enough to
/// prove the driver really does switch streams.
pub const Upgrader = struct {
    ctx: *anyopaque,
    upgradeFn: *const fn (ctx: *anyopaque) anyerror!Wire,

    /// Run the caller's handshake and return the encrypted stream.
    pub fn upgrade(u: Upgrader) anyerror!Wire {
        return u.upgradeFn(u.ctx);
    }
};
