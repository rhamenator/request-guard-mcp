//! Process-local MCP stdio transport. Each input line is one JSON-RPC message;
//! stdout contains only JSON-RPC responses. Diagnostics go to stderr.

use crate::mcp::protocol::McpMessage;
use crate::mcp::tool_registry::{build_registry, ToolRegistry};
use crate::mcp::transport_ws::process_message;
use crate::state::AppState;
use anyhow::Result;
use serde_json::Value;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

pub async fn run_stdio(app: AppState) -> Result<()> {
    // A fresh scope prevents unrelated local launches from sharing cached
    // classifications, even when they use the same Redis or PostgreSQL store.
    let scope = format!("stdio:{}", uuid::Uuid::new_v4());
    run_stream(
        tokio::io::stdin(),
        tokio::io::stdout(),
        Arc::new(app),
        Arc::new(build_registry()),
        &scope,
    )
    .await
}

async fn run_stream<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    input: R,
    mut output: W,
    app: Arc<AppState>,
    registry: Arc<ToolRegistry>,
    scope: &str,
) -> Result<()> {
    let mut input = BufReader::new(input);
    let max = app.config.limits.max_request_bytes;
    let mut line = Vec::with_capacity(max.min(8192));
    let mut oversized = false;
    loop {
        let available = input.fill_buf().await?;
        let eof = available.is_empty();
        if eof && line.is_empty() && !oversized {
            break;
        }
        let end = available.iter().position(|byte| *byte == b'\n');
        let take = end.map_or(available.len(), |index| index + 1);
        let payload = &available[..end.unwrap_or(take)];
        if !oversized {
            if payload.len() > max.saturating_sub(line.len()) {
                oversized = true;
                line.clear();
            } else {
                line.extend_from_slice(payload);
            }
        }
        input.consume(take);
        if end.is_none() && !eof {
            continue;
        }

        let response = if oversized {
            Some(serde_json::to_string(&McpMessage::error(
                Value::Null,
                -413,
                "REQUEST_TOO_LARGE",
            ))?)
        } else {
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            match std::str::from_utf8(&line) {
                Ok(text) => process_message(text, &app, &registry, scope).await,
                Err(_) => Some(serde_json::to_string(&McpMessage::error(
                    Value::Null,
                    -32700,
                    "Parse error: MCP messages must be UTF-8",
                ))?),
            }
        };
        if let Some(response) = response {
            output.write_all(response.as_bytes()).await?;
            output.write_all(b"\n").await?;
            output.flush().await?;
        }
        line.clear();
        oversized = false;
        if eof {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn stdio_handles_requests_notifications_and_bounded_input() {
        let mut config = Config::default();
        config.limits.max_request_bytes = 512;
        let app = Arc::new(AppState::new(config));
        let registry = Arc::new(build_registry());
        let (mut writer, reader) = duplex(4096);
        let (response_writer, mut response_reader) = duplex(4096);
        writer
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\r\n")
            .await
            .unwrap();
        writer
            .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n")
            .await
            .unwrap();
        writer.write_all(&vec![b'x'; 513]).await.unwrap();
        writer.write_all(b"\n").await.unwrap();
        writer.write_all(b"\xff\n").await.unwrap();
        writer
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n")
            .await
            .unwrap();
        drop(writer);
        run_stream(reader, response_writer, app, registry, "stdio:test")
            .await
            .unwrap();
        let mut output = String::new();
        response_reader.read_to_string(&mut output).await.unwrap();
        let responses: Vec<Value> = output
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(responses.len(), 4);
        assert_eq!(responses[0]["id"], 1);
        assert_eq!(responses[1]["error"]["code"], -413);
        assert_eq!(responses[2]["error"]["code"], -32700);
        assert_eq!(responses[3]["id"], 2);
    }
}
