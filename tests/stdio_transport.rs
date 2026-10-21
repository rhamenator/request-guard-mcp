use serde_json::Value;
use std::io::Write;
use std::process::{Command, Stdio};

fn stdio_command(cwd: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_request-guard-mcp"));
    command
        .arg("--stdio")
        .current_dir(cwd)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for key in [
        "PATH",
        "SYSTEMROOT",
        "WINDIR",
        "TEMP",
        "TMPDIR",
        "USERPROFILE",
    ] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    command
}

#[test]
fn stdio_stdout_contains_only_json_rpc_without_network_auth_config() {
    let cwd = tempfile::tempdir().unwrap();
    let mut child = stdio_command(cwd.path()).spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let lines: Vec<&[u8]> = output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .collect();
    assert_eq!(lines.len(), 1);
    let response: Value = serde_json::from_slice(lines[0]).unwrap();
    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 1);
    assert!(response["result"].is_object());
}

#[test]
fn stdio_rejects_nonexpiring_postgres_scope_before_protocol_output() {
    let cwd = tempfile::tempdir().unwrap();
    let mut child = stdio_command(cwd.path())
        .env("MCP__POSTGRES__URL", "postgres://lab.invalid/test")
        .spawn()
        .unwrap();
    drop(child.stdin.take());
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("PostgreSQL is not yet supported"));
}
