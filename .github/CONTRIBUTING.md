<!-- SPDX-License-Identifier: MPL-2.0 -->
# Contributing

Thanks for looking. This is a small, single-purpose action, and the rules below
are short because most of them exist to protect one property: **the Idris2
specification is the source of truth for the SMTP state machine, and the Zig is
downstream of it.**

## Getting set up

You need **Zig 0.16.0** — exactly that version. CI installs it from a
SHA-256-pinned tarball (`ZIG_TARBALL` / `ZIG_SHA256` in
`.github/workflows/ci.yml`); using a different release will produce diffs in
generated code and may not compile at all, because this project works around
version-specific standard-library defects (see `BUSTFILE.adoc`).

```sh
git clone https://github.com/hyperpolymath/smtp-notify-action.git
cd smtp-notify-action
zig build test                                   # the 18 unit tests
zig build -Doptimize=ReleaseSafe -Dtarget=x86_64-linux-musl
```

There are no package dependencies to fetch: `build.zig.zon` declares
`.dependencies = .{}` and that is a property worth keeping.

Idris2 is needed only if you change the specification. It is a build-time
specification and code generator; **it does not ship in the binary.**

## Three places not to edit by hand

1. **`src/generated/smtp_fsm.zig`** — emitted from `spec/`. Change the Idris2
   source and regenerate. `scripts/check-fsm-drift.sh` runs in CI as the
   *FSM drift gate* and will fail the build if the generated file and the
   specification disagree. That gate is the whole point of the architecture; if
   it is ever in your way, the fix is upstream in `spec/`, never in the output.
2. **`src/tls/Client.zig`** — a vendored copy of the Zig standard library's TLS
   client. Patching it locally forks us off upstream silently. If it needs a fix,
   re-vendor and say so in the commit message. See `.github/SECURITY.md` for why
   this file gets special treatment.
3. **`action.yml`'s SHA-256 pins and asset URL** — these are release artefacts.
   `release.yml` *verifies* rebuilt binaries against them and cannot mint them, so
   correct hashes can only exist in the release commit itself.

## Where a defect gets written down

This project keeps two registers, and putting an entry in the wrong one loses it.

- **`KNOWN-DEFECTS.adoc`** — defects in *our* code. Published rather than hidden.
- **`BUSTFILE.adoc`** — defects in things we depend on but do not control: the Zig
  standard library, the toolchain, an upstream action. Every entry carries a
  disposition on the hazard-control hierarchy and, crucially, a **re-check
  trigger** naming the event that would let us delete the workaround. A workaround
  with no re-check trigger becomes permanent by accident.

If you work around an upstream bug, the Bustfile entry is part of the change, not
follow-up work.

## Tests, and what counts as one

`zig build test` runs 18 test blocks. Note what they do *not* do: they drive
scripted in-memory streams and never open a socket. That is why the CI workflow
also runs an end-to-end job against a containerised sink and a live TLS handshake
canary — and why BUST-2026-001, a process abort on any connect timeout, was
invisible to every unit test until the real binary met a real socket.

So: **if your change touches the network path, a passing `zig build test` is not
evidence it works.** Say in the PR which instrument you actually used.

A new gate must be able to fail. If you add a check, include the case that makes
it go red; a check with no recorded failure is decoration until proven otherwise.

## Pull requests

- Branch from `main`; one topic per PR.
- **Commits must be signed.** Merges are squash-only, so the history stays linear.
- Keep the SPDX identifier on line 1 of every new file (`MPL-2.0`, matching
  `LICENSE`). Do not introduce a second licence into the repository.
- Prefer plain text in any user-facing output. Plain-text-only is a deliberate
  accessibility property of this action, not an accident of implementation.

## Reporting

Ordinary defects: open an issue. Anything that could expose credentials or mail
contents: use private vulnerability reporting, per `.github/SECURITY.md`.
