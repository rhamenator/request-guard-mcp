#!/usr/bin/env python3
"""Bounded loopback reproduction of authenticated WebSocket slot retention.

Requires the optional Python websockets 15.x package. This probe records the
current fairness gap; it is not a stable-release qualification test.
"""

import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time

import websockets
from websockets.exceptions import ConnectionClosed, InvalidStatus


async def run(binary):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    token = secrets.token_urlsafe(48)
    other_token = secrets.token_urlsafe(48)
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "AUTH_TOKENS": token + "," + other_token,
        "MCP__AUTH__ENABLED": "true",
        "MCP__HOST": "127.0.0.1",
        "MCP__PORT": str(port),
        "MCP__LIMITS__MAX_CONNECTIONS": "2",
        "MCP__LIMITS__WEBSOCKET_IDLE_TIMEOUT_SECS": "2",
    }

    async def connect(bearer):
        return await websockets.connect(
            f"ws://127.0.0.1:{port}/mcp",
            additional_headers={"Authorization": "Bearer " + bearer},
            subprotocols=["mcp"], ping_interval=None, open_timeout=3,
        )

    async def keepalive(connection):
        for _ in range(12):
            pong = await connection.ping()
            await asyncio.wait_for(pong, 1)
            await asyncio.sleep(0.5)

    with tempfile.TemporaryDirectory() as working_directory:
        with tempfile.TemporaryFile() as log:
            process = subprocess.Popen(
                [str(binary)], cwd=working_directory, env=environment,
                stdout=log, stderr=subprocess.STDOUT,
            )
            try:
                for _ in range(50):
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                            break
                    except OSError:
                        await asyncio.sleep(0.05)
                else:
                    raise RuntimeError("listener did not start")

                if process.poll() is not None:
                    raise RuntimeError("server exited before WebSocket probe")
                silent = [await connect(token), await connect(token)]
                try:
                    async def wait_for_idle_close(connection):
                        start = time.monotonic()
                        try:
                            await asyncio.wait_for(connection.recv(), 3.5)
                            return None
                        except ConnectionClosed:
                            return round(time.monotonic() - start, 3)

                    silent_elapsed = await asyncio.gather(
                        *(wait_for_idle_close(connection) for connection in silent)
                    )
                finally:
                    await asyncio.gather(*(connection.close() for connection in silent))
                control_recovered = await connect(other_token)
                control_recovered_status = control_recovered.response.status_code
                await control_recovered.close()

                held = []
                pings = []
                try:
                    held.append(await connect(token))
                    held.append(await connect(token))
                    pings = [asyncio.create_task(keepalive(connection))
                             for connection in held]
                    ping_start = time.monotonic()
                    await asyncio.sleep(3)
                    probe_after_seconds = round(time.monotonic() - ping_start, 3)
                    try:
                        third = await connect(other_token)
                        third_upgrade = 101
                        third_limit_body_match = False
                        await third.close()
                    except InvalidStatus as error:
                        third_upgrade = error.response.status_code
                        third_limit_body_match = (
                            error.response.body == b"WebSocket connection limit reached"
                        )
                    await asyncio.gather(*pings)
                finally:
                    for task in pings:
                        task.cancel()
                    await asyncio.gather(*pings, return_exceptions=True)
                    await asyncio.gather(*(connection.close() for connection in held))

                for attempt in range(3):
                    try:
                        recovered = await connect(other_token)
                        break
                    except InvalidStatus:
                        if attempt == 2:
                            raise
                        await asyncio.sleep(0.1)
                await recovered.close()
                result = {
                    "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                    "silent_control_close_seconds": silent_elapsed,
                    "control_recovered_upgrade": control_recovered_status,
                    "ping_clients": len(held),
                    "ping_interval_seconds": 0.5,
                    "idle_timeout_seconds": 2,
                    "probe_after_seconds": probe_after_seconds,
                    "third_upgrade": third_upgrade,
                    "third_limit_body_match": third_limit_body_match,
                    "third_used_distinct_token": other_token != token,
                    "recovered_upgrade": recovered.response.status_code,
                    "process_alive": process.poll() is None,
                }
                print(json.dumps(result), flush=True)
                if (any(elapsed is None or not 1.5 <= elapsed <= 3.5
                        for elapsed in silent_elapsed)
                        or third_upgrade != 503 or not third_limit_body_match
                        or process.poll() is not None):
                    raise RuntimeError("WebSocket slot behavior changed")
            finally:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    args = parser.parse_args()
    asyncio.run(run(args.binary.resolve(strict=True)))


if __name__ == "__main__":
    main()
