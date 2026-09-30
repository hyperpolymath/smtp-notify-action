<!-- SPDX-License-Identifier: MPL-2.0 -->

# Prepared comment for ziglang/zig#25747

This file is Markdown rather than AsciiDoc on purpose: it is the verbatim body
of a GitHub comment, and GitHub comments are Markdown. Paste it unchanged.

**Status: not yet posted — and the original target no longer accepts
comments, for a different reason than first recorded.**

The 2026-09-03 attempt failed with "Interactions on this repository have been
restricted to collaborators only". That was read as a temporary interaction
limit. It is not: Zig moved to Codeberg on 2025-11-26 and made
`ziglang/zig` on GitHub read-only, leaving existing issues open but frozen
("copy-on-write"; https://ziglang.org/news/migrating-from-github-to-codeberg/).

**Where to post instead (re-checked 2026-09-30):** the fix is in review on
Codeberg as **ziglang/zig#36488**, "std.Io: migrate netConnectIp and
netConnectUnix to std.Io.Operation" (opened 2026-08-13, "Closes #25747 #31410
#31305"). Post the text below as a comment on that PR, reframed as review
input: the most useful part for the reviewer is the `Kqueue.zig` guard, which
a change scoped to `Threaded.zig` would leave behind. Posting needs a Codeberg
account; nothing here can do it on the owner's behalf.

When it is posted, record the comment URL in `BUSTFILE.adoc` under
BUST-2026-001 and delete this file.

---

Confirming this on the 0.16.0 release, and adding three things the issue body does not cover — a third panic site, a survey of the other backends, and a note on how it presents to a caller.

**A third site, outside `Threaded.zig`**

`Kqueue.zig` has the same guard, so this is not confined to the threaded backend:

```
lib/std/Io/Kqueue.zig:1037:  if (options.timeout != .none) @panic("TODO");
```

**No backend in 0.16.0 implements it**

There are five providers of `netConnectIp` in the vtable, and none of them honours `options.timeout`:

| Provider | `netConnectIp` | On a non-`.none` timeout |
|---|---|---|
| `Threaded.zig:1932` | `netConnectIpPosix` / `netConnectIpWindows` | `@panic` at `12077` / `12096` |
| `Kqueue.zig:651` | `netConnectIp` | `@panic("TODO")` at `1037` |
| `Uring.zig:777` | `netConnectIpUnavailable` | connect unimplemented; returns `error.NetworkDown` |
| `Dispatch.zig:457` | `netConnectIpUnavailable` | connect unimplemented; returns `error.NetworkDown` |
| `Io.zig:2624` | `failingNetConnectIp` | the deliberately-failing test `Io` |

So `IpAddress.ConnectOptions.timeout` is, in practice, uninhabitable on every platform in this release: the field exists and type-checks, and every value other than the default aborts.

**The signature already promises the error**

`net.IpAddress.ConnectError` includes `Io.Timeout.Error` (`lib/std/Io/net.zig:330`), i.e. `error{Timeout}`. So `connect` advertises in its type that it can return `error.Timeout`, no implementation ever does, and the two that implement connect at all abort the process instead. A caller reading the error set — which is the natural place to look for "can this time out?" — is told yes.

**How it presents**

`timeout` defaults to `.none`, so setting it is an ordinary struct-literal field. It compiles, and it passes tests: a test suite that drives scripted in-memory streams never reaches `netConnectIp`, so there is no compile-time and no test-time signal. The abort happens the first time the program connects to a real host, which for a lot of programs means the first run in production. In our case a green build and a green test suite produced a binary that aborted with exit 134 on its first real socket; it was caught by a local probe against a listener, before release.

The workaround is easy once you know (don't set the field; bound the operation from outside), but there is nothing to know it *from* short of reading the backend source.

**One small suggestion, offered rather than urged**

There is precedent for this a few files over: `Uring.zig` and `Dispatch.zig` handle *their* unimplemented connect by returning `error.NetworkDown` rather than aborting. Since `error.Timeout` is already in `ConnectError`, returning it — or `error.Unexpected`, or anything at all — while the feature is unimplemented would make this recoverable and discoverable at the point of use, rather than a process abort. A `@compileError` would also be strictly better than a runtime one, though I appreciate the option is runtime data, so that may not be reachable.

The `enhancement` label reads as "a feature not yet added", which is accurate for the work itself, but the current state is also a reachable abort from ordinary safe code with no diagnostic before it fires. That may be worth weighing separately from the implementation work.

