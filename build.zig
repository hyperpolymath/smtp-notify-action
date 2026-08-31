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

    // src/smtp.zig transitively pulls in message.zig and the generated FSM,
    // so this one test root covers every unit test in the tree.
    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/smtp.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests (scripted sessions + spec golden vectors)");
    test_step.dependOn(&run_tests.step);
}
