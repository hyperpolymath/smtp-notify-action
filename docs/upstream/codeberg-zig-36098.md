<!-- SPDX-License-Identifier: MPL-2.0 -->

# Prepared comment for Codeberg ziglang/zig#36098

Markdown on purpose: this is the verbatim body of a Codeberg comment on
<https://codeberg.org/ziglang/zig/issues/36098> ("TlsUnexpectedMessage on
TLSv1.3"). Posting needs a Codeberg account.

**Status: not yet posted** (prepared 2026-09-30). When posted, record the URL
in `BUSTFILE.adoc` under BUST-2026-003. If upstream asks for a PR instead, the
diff below applies to `lib/std/crypto/tls/Client.zig` at the 0.16.0 tag
(drop the vendoring header hunk and the `@import("std")` line change, which
exist only because the file is vendored).

---

Same root cause as diagnosed above (the server sends `CertificateRequest`;
RFC 8446 §4.4.2 says a client without a certificate answers with an empty
`Certificate` message). We hit it against `smtp.gmail.com:465` and have been
running a patched copy of the 0.16.0 client in a released action since
2026-08-31,
exercised by a live CI canary on every push, so offering it here in case it
saves someone the work.

What the patch does:

1. Accepts `certificate_request` in the TLS 1.3 handshake loop (it currently
   falls through to `error.TlsUnexpectedMessage`), adding it to the
   transcript and noting that a certificate was requested.
2. When a certificate was requested, sends an empty `Certificate` message
   (context echoed, zero-length list) in the client's encrypted flight,
   before `Finished`, with the transcript hash updated accordingly so the
   client `Finished` verifies.
3. Keeps every other path byte-identical; the client still never presents a
   certificate.

Not done here (and probably wanted upstream): an option to *supply* a client
certificate, and the server-side counterpart, as discussed in #19521. This
patch is only the "no certificate" answer, which is the one every client
needs.

<details><summary>Diff against 0.16.0 <code>lib/std/crypto/tls/Client.zig</code></summary>

```diff
--- a/lib/std/crypto/tls/Client.zig
+++ b/lib/std/crypto/tls/Client.zig
@@ -1,7 +1,19 @@
+// SPDX-License-Identifier: MIT
+// Vendored from Zig 0.16.0 `lib/std/crypto/tls/Client.zig` (MIT, © Zig
+// contributors), verbatim EXCEPT for one patch: TLS 1.3 CertificateRequest
+// handling (ziglang/zig#19521). Upstream's handshake loop rejects the
+// certificate_request message, so any server that requests a client
+// certificate — smtp.gmail.com:465 does — kills the handshake with
+// TlsUnexpectedMessage. The patch accepts the request and declines it with
+// an empty Certificate message per RFC 8446 §4.4.2, which is the correct
+// no-client-cert behavior. Patched regions are marked "// PATCH(#19521)".
+// DELETE THIS FILE and revert to std.crypto.tls.Client once upstream lands
+// certificate_request support.
+
 const builtin = @import("builtin");
 const native_endian = builtin.cpu.arch.endian();
 
-const std = @import("../../std.zig");
+const std = @import("std");
 const tls = std.crypto.tls;
 const Client = @This();
 const mem = std.mem;
@@ -329,6 +341,9 @@
         finished,
     };
     var handshake_state: HandshakeState = .hello;
+    // PATCH(#19521): set when the server sends certificate_request; makes the
+    // client Finished flight carry an empty Certificate message before it.
+    var client_cert_requested = false;
     var handshake_cipher: tls.HandshakeCipher = undefined;
     var main_cert_pub_key: CertificatePublicKey = undefined;
     var tls12_negotiated_group: ?tls.NamedGroup = null;
@@ -856,30 +871,79 @@
                                     p.transcript_hash.update(wrapped_handshake);
                                     const expected_server_verify_data = tls.hmac(P.Hmac, &finished_digest, pv.server_finished_key);
                                     if (!std.crypto.timing_safe.eql([P.Hmac.mac_length]u8, expected_server_verify_data, hsd.array(P.Hmac.mac_length).*)) return error.TlsDecryptError;
-                                    const handshake_hash = p.transcript_hash.finalResult();
-                                    const verify_data = tls.hmac(P.Hmac, &handshake_hash, pv.client_finished_key);
-                                    const out_cleartext = .{@intFromEnum(tls.HandshakeType.finished)} ++
-                                        array(u24, u8, verify_data) ++
-                                        .{@intFromEnum(tls.ContentType.handshake)};
-
-                                    const wrapped_len = out_cleartext.len + P.AEAD.tag_length;
-
-                                    var finished_msg = .{@intFromEnum(tls.ContentType.application_data)} ++
-                                        int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
-                                        array(u16, u8, @as([wrapped_len]u8, undefined));
-
-                                    const ad = finished_msg[0..tls.record_header_len];
-                                    const ciphertext = finished_msg[tls.record_header_len..][0..out_cleartext.len];
-                                    const auth_tag = finished_msg[finished_msg.len - P.AEAD.tag_length ..];
-                                    const nonce = pv.client_handshake_iv;
-                                    P.AEAD.encrypt(ciphertext, auth_tag, &out_cleartext, ad, nonce, pv.client_handshake_key);
-
-                                    var all_msgs_vec: [2][]const u8 = .{
-                                        &client_change_cipher_spec_msg,
-                                        &finished_msg,
-                                    };
-                                    try output.writeVecAll(&all_msgs_vec);
-                                    try output.flush();
+                                    // PATCH(#19521): ap-traffic secrets are
+                                    // derived from the transcript through the
+                                    // *server* Finished (RFC 8446 §7.1), while
+                                    // the client Finished MAC also covers any
+                                    // client Certificate sent after it (§4.4.4)
+                                    // — so peek() here, and extend the
+                                    // transcript with the empty Certificate
+                                    // reply when one was requested. With no
+                                    // request the two hashes coincide and this
+                                    // is byte-identical to upstream std.
+                                    const handshake_hash = p.transcript_hash.peek();
+                                    // Empty Certificate message: type 11,
+                                    // u24 body len 4, u8 context len 0 (echoing
+                                    // the empty context enforced at
+                                    // certificate_request), u24 list len 0 —
+                                    // declining per §4.4.2, no CertificateVerify.
+                                    const empty_cert_msg = [8]u8{ @intFromEnum(tls.HandshakeType.certificate), 0, 0, 4, 0, 0, 0, 0 };
+                                    if (client_cert_requested) p.transcript_hash.update(&empty_cert_msg);
+                                    const client_finished_hash = p.transcript_hash.finalResult();
+                                    const verify_data = tls.hmac(P.Hmac, &client_finished_hash, pv.client_finished_key);
+                                    if (client_cert_requested) {
+                                        // Certificate and Finished coalesced
+                                        // into ONE encrypted record (legal per
+                                        // §5.1): the write sequence stays 0, so
+                                        // the handshake nonce and key are used
+                                        // exactly as in the unpatched path.
+                                        const out_cleartext = empty_cert_msg ++
+                                            .{@intFromEnum(tls.HandshakeType.finished)} ++
+                                            array(u24, u8, verify_data) ++
+                                            .{@intFromEnum(tls.ContentType.handshake)};
+
+                                        const wrapped_len = out_cleartext.len + P.AEAD.tag_length;
+
+                                        var finished_msg = .{@intFromEnum(tls.ContentType.application_data)} ++
+                                            int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
+                                            array(u16, u8, @as([wrapped_len]u8, undefined));
+
+                                        const ad = finished_msg[0..tls.record_header_len];
+                                        const ciphertext = finished_msg[tls.record_header_len..][0..out_cleartext.len];
+                                        const auth_tag = finished_msg[finished_msg.len - P.AEAD.tag_length ..];
+                                        const nonce = pv.client_handshake_iv;
+                                        P.AEAD.encrypt(ciphertext, auth_tag, &out_cleartext, ad, nonce, pv.client_handshake_key);
+
+                                        var all_msgs_vec: [2][]const u8 = .{
+                                            &client_change_cipher_spec_msg,
+                                            &finished_msg,
+                                        };
+                                        try output.writeVecAll(&all_msgs_vec);
+                                        try output.flush();
+                                    } else {
+                                        const out_cleartext = .{@intFromEnum(tls.HandshakeType.finished)} ++
+                                            array(u24, u8, verify_data) ++
+                                            .{@intFromEnum(tls.ContentType.handshake)};
+
+                                        const wrapped_len = out_cleartext.len + P.AEAD.tag_length;
+
+                                        var finished_msg = .{@intFromEnum(tls.ContentType.application_data)} ++
+                                            int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
+                                            array(u16, u8, @as([wrapped_len]u8, undefined));
+
+                                        const ad = finished_msg[0..tls.record_header_len];
+                                        const ciphertext = finished_msg[tls.record_header_len..][0..out_cleartext.len];
+                                        const auth_tag = finished_msg[finished_msg.len - P.AEAD.tag_length ..];
+                                        const nonce = pv.client_handshake_iv;
+                                        P.AEAD.encrypt(ciphertext, auth_tag, &out_cleartext, ad, nonce, pv.client_handshake_key);
+
+                                        var all_msgs_vec: [2][]const u8 = .{
+                                            &client_change_cipher_spec_msg,
+                                            &finished_msg,
+                                        };
+                                        try output.writeVecAll(&all_msgs_vec);
+                                        try output.flush();
+                                    }
 
                                     const client_secret = hkdfExpandLabel(P.Hkdf, pv.master_secret, "c ap traffic", &handshake_hash, P.Hash.digest_length);
                                     const server_secret = hkdfExpandLabel(P.Hkdf, pv.master_secret, "s ap traffic", &handshake_hash, P.Hash.digest_length);
@@ -952,6 +1016,33 @@
                             .ssl_key_log = options.ssl_key_log,
                         };
                     },
+                    // PATCH(#19521): a server may request a client certificate
+                    // between EncryptedExtensions and its own Certificate
+                    // (RFC 8446 §4.3.2). Record the request; the reply — an
+                    // empty Certificate, declining — is sent with the client
+                    // Finished flight below.
+                    .certificate_request => {
+                        if (tls_version != .tls_1_3) return error.TlsUnexpectedMessage;
+                        if (cipher_state != .handshake) return error.TlsUnexpectedMessage;
+                        if (handshake_state != .certificate) return error.TlsUnexpectedMessage;
+                        switch (handshake_cipher) {
+                            inline else => |*p| p.transcript_hash.update(wrapped_handshake),
+                        }
+                        try hsd.ensure(1);
+                        const cert_req_ctx_len = hsd.decode(u8);
+                        // RFC 8446 §4.3.2: the certificate_request_context
+                        // SHALL be zero length except in post-handshake
+                        // authentication, which this client never offers.
+                        if (cert_req_ctx_len != 0) return error.TlsIllegalParameter;
+                        // The extensions body is deliberately unparsed: we
+                        // decline with an empty Certificate no matter which
+                        // algorithms the server lists, and the outer loop
+                        // advances by handshake-message length, not by how
+                        // much of `hsd` was consumed.
+                        client_cert_requested = true;
+                        // handshake_state stays .certificate — the server's
+                        // own Certificate message is still expected next.
+                    },
                     else => return error.TlsUnexpectedMessage,
                 }
                 if (ctd.eof()) break;
```

</details>
