#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

if (process.platform !== "linux" || process.arch !== "x64") {
  console.log("SKIP npm launcher signal test: requires Linux x64");
  process.exit(0);
}

const root = fs.mkdtempSync(path.join(os.tmpdir(), "request-guard-launcher-"));
const bin = path.join(root, "bin");
const vendor = path.join(root, "vendor", "linux-x64");
fs.mkdirSync(bin);
fs.mkdirSync(vendor, { recursive: true });
const launcher = path.join(bin, "request-guard-mcp.js");
const childBinary = path.join(vendor, "request-guard-mcp");
fs.copyFileSync(path.join(__dirname, "..", "npm", "bin", "request-guard-mcp.js"), launcher);
fs.chmodSync(launcher, 0o755);
fs.writeFileSync(childBinary, "#!/usr/bin/env node\nconst fs = require('node:fs');\nfs.writeFileSync(process.env.TEST_PID_FILE + '.tmp', String(process.pid));\nfs.renameSync(process.env.TEST_PID_FILE + '.tmp', process.env.TEST_PID_FILE);\nsetInterval(() => {}, 1000);\n");
fs.chmodSync(childBinary, 0o755);

async function waitForPid(file) {
  for (let attempt = 0; attempt < 100; attempt++) {
    if (fs.existsSync(file)) {
      const pid = Number(fs.readFileSync(file, "utf8"));
      if (Number.isInteger(pid) && pid > 0) return pid;
    }
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  throw new Error("synthetic child did not start");
}

function waitForExit(processHandle) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("launcher did not exit")), 5000);
    processHandle.once("error", error => { clearTimeout(timer); reject(error); });
    processHandle.once("exit", (code, signal) => { clearTimeout(timer); resolve({ code, signal }); });
  });
}

async function checkSignal(signal, target) {
  const pidFile = path.join(root, `${signal}.pid`);
  const wrapper = spawn(launcher, ["--stdio"], {
    env: { ...process.env, TEST_PID_FILE: pidFile },
    stdio: "ignore",
  });
  let childPid;
  let childConfirmedDead = false;
  try {
    childPid = await waitForPid(pidFile);
    const exited = waitForExit(wrapper);
    process.kill(target === "wrapper" ? wrapper.pid : childPid, signal);
    const result = await exited;
    assert.equal(result.signal, null, "wrapper must report a numeric exit code");
    assert.equal(result.code, 128 + os.constants.signals[signal], signal);
    if (target === "wrapper") {
      let childAlive = true;
      for (let attempt = 0; attempt < 100; attempt++) {
        try { process.kill(childPid, 0); } catch (error) {
          if (error.code !== "ESRCH") throw error;
          childAlive = false;
          break;
        }
        await new Promise(resolve => setTimeout(resolve, 20));
      }
      childConfirmedDead = !childAlive;
      assert.equal(childAlive, false, `${signal} must not orphan the child`);
    } else {
      childConfirmedDead = true;
    }
  } finally {
    if (wrapper.exitCode === null) wrapper.kill("SIGKILL");
    if (childPid && !childConfirmedDead) {
      try { process.kill(childPid, "SIGKILL"); } catch (error) {
        if (error.code !== "ESRCH") throw error;
      }
    }
  }
}

(async () => {
  try {
    await checkSignal("SIGTERM", "wrapper");
    await checkSignal("SIGINT", "wrapper");
    await checkSignal("SIGHUP", "wrapper");
    await checkSignal("SIGKILL", "child");
    fs.unlinkSync(childBinary);
    const missing = spawn(launcher, [], { stdio: "ignore" });
    const missingResult = await waitForExit(missing);
    assert.equal(missingResult.code, 1, "missing binary must report launcher failure");
    console.log("PASS npm launcher: forwarded SIGTERM 143/SIGINT 130/SIGHUP 129, child SIGKILL 137, missing binary 1");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
