#!/usr/bin/env python3
"""Bounded running-binary check of multi-bearer WebSocket admission fairness.

Requires the optional Python websockets 15.x package. Uses only loopback and
synthetic credentials; no backend, Docker, or VM is required.
"""

import argparse
import asyncio
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile

import websockets
from websockets.exceptions import InvalidStatus


async def run(binary):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    first = secrets.token_urlsafe(48)
    second = secrets.token_urlsafe(48)
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "AUTH_TOKENS": first + "," + second,
        "MCP__AUTH__ENABLED": "true",
        "MCP__HOST": "127.0.0.1",
        "MCP__PORT": str(port),
        "MCP__LIMITS__MAX_CONNECTIONS": "2",
        "MCP__LIMITS__WEBSOCKET_IDLE_TIMEOUT_SECS": "2",
    }

    async def connect(token):
        return await websockets.connect(
            f"ws://127.0.0.1:{port}/mcp",
            additional_headers={"Authorization": "Bearer " + token},
            subprotocols=["mcp"],
            ping_interval=None,
            open_timeout=3,
        )

    async def ping_until_stopped(connection, stop):
        while not stop.is_set():
            pong = await connection.ping()
            await asyncio.wait_for(pong, 1)
            await asyncio.sleep(0.3)

    with tempfile.TemporaryDirectory() as cwd, tempfile.TemporaryFile() as log:
        process = subprocess.Popen(
            [str(binary)], cwd=cwd, env=environment,
            stdout=log, stderr=subprocess.STDOUT,
        )
        try:
            for _ in range(60):
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        break
                except OSError:
                    await asyncio.sleep(0.05)
            else:
                raise RuntimeError("listener did not start")

            held = await connect(first)
            stop = asyncio.Event()
            pings = asyncio.create_task(ping_until_stopped(held, stop))
            try:
                await asyncio.sleep(2.5)  # exceed configured idle timeout
                try:
                    extra = await connect(first)
                    await extra.close()
                    same_status, same_body = 101, ""
                except InvalidStatus as error:
                    same_status = error.response.status_code
                    same_body = error.response.body.decode("utf-8", "replace")
                other = await connect(second)
                other_status = other.response.status_code
                await other.close()
                await asyncio.sleep(0.2)
                if pings.done():
                    raise RuntimeError("ordinary Ping/Pong client disconnected")
            finally:
                stop.set()
                await pings
                await held.close()

            # The peer may see its close handshake before the server task has
            # returned and dropped its permit. Allow only a bounded cleanup lag.
            for attempt in range(20):
                try:
                    recovered = await connect(first)
                    break
                except InvalidStatus as error:
                    if error.response.status_code != 503 or attempt == 19:
                        raise
                    await asyncio.sleep(0.1)
            recovered_status = recovered.response.status_code
            await recovered.close()
            result = {
                "same_bearer_extra_status": same_status,
                "same_bearer_limit_body": same_body,
                "distinct_bearer_status": other_status,
                "same_bearer_recovered_status": recovered_status,
                "process_alive": process.poll() is None,
            }
            print(json.dumps(result), flush=True)
            assert same_status == 503
            assert same_body == "WebSocket caller connection limit reached"
            assert other_status == recovered_status == 101
            assert process.poll() is None
        finally:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    args = parser.parse_args()
    asyncio.run(run(args.binary.resolve(strict=True)))
