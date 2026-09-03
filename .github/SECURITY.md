<!-- SPDX-License-Identifier: MPL-2.0 -->
# Security policy

## Reporting a vulnerability

Use **[private vulnerability reporting](https://github.com/hyperpolymath/smtp-notify-action/security/advisories/new)**
on this repository. It is enabled, and it is the only channel.

No email address is published here on purpose. A security address that is not
monitored is worse than none, because it silently absorbs reports; the GitHub
advisory workflow notifies the maintainer, keeps the report private until it is
fixed, and produces a citable advisory at the end.

Please report privately, rather than in a public issue, anything that could let a
third party read credentials or mail contents, forge a message, or downgrade the
transport. Ordinary defects — a wrong error message, a missing input — belong in
a normal issue.

Expect an acknowledgement and, where the report is valid, an advisory rather than
a bare commit. `KNOWN-DEFECTS.adoc` explains why this project publishes its own
defects instead of waiting to be asked about them.

## Supported versions

| Version | Supported |
|---|---|
| `v0.1.0` | Yes — the only release |
| `main` | Yes, but unreleased and unpinned; not for production use |

There is one release. Pin a tag or a commit SHA; never `@main`.

## The vendored TLS client — read this before adopting

`src/tls/Client.zig` is a **vendored copy of the Zig standard library's TLS
client**, carried in-tree because the action builds a static binary against a
pinned toolchain.

Three facts about it, stated plainly because they are the most security-relevant
properties of this action:

1. **It is 91 KB — about 69% of all Zig source in this repository.** The majority
   of the code you run is TLS code this project did not write.
2. **It has no tests of its own.** All 18 test blocks live in `src/smtp.zig` (15)
   and `src/message.zig` (3). `Client.zig` has zero.
3. **It is outside the proof boundary.** The Idris2 specification covers
   dot-stuffing (a theorem over all inputs) and the protocol state machine (a
   `Refl` proof over the eight rows that exist). TLS is explicitly *not covered
   at all* — see "Scope of the proof, stated exactly" in `KNOWN-DEFECTS.adoc`.

The consequence: this action's formal claims are about the SMTP layer, not about
the cryptography underneath it. A TLS defect here would be inherited from the
upstream implementation, and a fix means re-vendoring rather than patching.
Vendoring also means an upstream fix does **not** reach you automatically.

## What the action does protect

- **Certificate verification is always on.** There is no `ignore_cert` input and
  there will not be one. `dawidd6/action-send-mail` has one; parity would be a
  regression, and this is a deliberate incompatibility.
- **Transport selection is fail-closed.** An unrecognised `secure` value is
  rejected outright rather than falling back to plaintext. `secure: false`
  (STARTTLS) is accepted but not yet implemented, so it *fails* rather than
  silently sending in the clear. Plaintext requires typing `plaintext`.
- **The password never reaches `argv`.** It is passed through the environment, so
  it cannot leak into a process listing on a shared runner.
- **The binary is pinned by SHA-256** in `action.yml`, and `release.yml` refuses
  to publish unless a rebuild from source reproduces those hashes. The action ref
  you pin therefore determines the exact bytes that run.
- **CR/LF in headers is rejected, never sanitised.** Header injection fails the
  step instead of being silently repaired into something the caller did not write.

## Known limitations with security relevance

These are not vulnerabilities; they are boundaries you should know before you
depend on the action.

- **Linux only.** The released binaries are static `linux-musl` builds. The action
  gates on `uname -s` and fails with a clear message on Windows and macOS runners.
- **AUTH PLAIN only.** `AUTH LOGIN` is not implemented (issue #10) and EHLO
  capabilities are not parsed (issue #9), so mechanism selection is blind. This is
  why Microsoft 365 cannot currently be authenticated to.
- **No per-operation network deadlines.** A whole-run watchdog bounds the entire
  run instead. It is a deadline, not an idle timer: a server that dribbles bytes
  slowly will run to the deadline rather than being cut off at the first stall.
  See `BUSTFILE.adoc`, BUST-2026-001 and BUST-2026-002, for why the per-operation
  form is unavailable in Zig 0.16.0.
- **Header-value validation is corpus-tested, not proved.** An injection vector
  outside the golden-vector corpus is not excluded by a theorem. A universal
  theorem for `headerValueOk` is tracked in issue #5.

## Scope

This policy covers the action, the Zig binary and the release workflow in this
repository. It does not cover your SMTP provider, your workflow secrets, or the
contents of the mail you choose to send.
