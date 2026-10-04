// SPDX-License-Identifier: MPL-2.0
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "smtp-notify",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            // Strip release binaries: debug info embeds absolute build paths,
            // which is what stands between us and byte-reproducible assets —
            // the release gate rebuilds in CI and requires hash equality with
            // the SHA-256 pins in action.yml.
            .strip = optimize != .Debug,
        }),
    });
    b.installArtifact(exe);

    // Two roots, because there are two protocol drivers and Zig compiles a
    // test root's imports only: src/smtp.zig transitively pulls in message.zig
    // and the generated FSM (whose golden-vector tests live in message.zig),
    // and src/nntp.zig pulls in the same shared modules plus its own tables.
    // src/main.zig is the third: the environment-to-policy layer (transport,
    // protocol, port, Message-ID) is the security surface for the action, and
    // it should not be the one module nothing tests.
    // A test reachable from no root would silently not run, so anything new
    // goes on one of these three.
    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/smtp.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const tests_nntp = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/nntp.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const tests_main = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_tests = b.addRunArtifact(tests);
    const run_tests_nntp = b.addRunArtifact(tests_nntp);
    const run_tests_main = b.addRunArtifact(tests_main);
    const test_step = b.step("test", "Run unit tests (scripted sessions + spec golden vectors)");
    test_step.dependOn(&run_tests.step);
    test_step.dependOn(&run_tests_nntp.step);
    test_step.dependOn(&run_tests_main.step);
}
