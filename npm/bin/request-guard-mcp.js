#!/usr/bin/env node
"use strict";

const path = require("node:path");
const fs = require("node:fs");
const { spawn } = require("node:child_process");

const targets = {
  "linux:x64": ["linux-x64", "request-guard-mcp"],
  "darwin:x64": ["macos-x64", "request-guard-mcp"],
  "darwin:arm64": ["macos-arm64", "request-guard-mcp"],
  "win32:x64": ["windows-x64", "request-guard-mcp.exe"],
};
let glibcVersion;
if (process.platform === "linux" && process.arch === "x64") {
  try {
    glibcVersion = process.report?.getReport?.().header?.glibcVersionRuntime;
  } catch {
    // A missing or disabled report is not evidence that this host uses musl.
  }
}
const isMusl = process.platform === "linux" && process.arch === "x64" &&
  !glibcVersion && fs.existsSync("/lib/ld-musl-x86_64.so.1");
const target = isMusl
  ? ["linux-x64-musl", "request-guard-mcp"]
  : targets[`${process.platform}:${process.arch}`];
if (!target) {
  console.error(`Request Guard MCP has no binary for ${process.platform}/${process.arch}`);
  process.exit(1);
}
const binary = path.join(__dirname, "..", "vendor", target[0], target[1]);
const child = spawn(binary, process.argv.slice(2), { stdio: "inherit", env: process.env });
for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => child.kill(signal));
}
child.on("error", (error) => {
  console.error(`Could not start Request Guard MCP: ${error.message}`);
  process.exitCode = 1;
});
child.on("exit", (code, signal) => {
  process.exitCode = code ?? (signal === "SIGINT" ? 130 : 143);
});
