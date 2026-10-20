#!/usr/bin/env python3
"""Exercise gRPC OTLP TLS trust with disposable Alpine-local collectors."""

from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import secrets
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request

import grpc


MCP_PORT = 18781
MAX_LOG_BYTES = 64 * 1024
CERT_DIR = Path("/tmp/otlp-certs")


def openssl(*args: str) -> None:
    subprocess.run(["openssl", *args], check=True, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, timeout=15)


def make_certificate(label: str) -> tuple[Path, Path, Path]:
    ca_key = CERT_DIR / f"{label}-ca.key"
    ca_cert = CERT_DIR / f"{label}-ca.crt"
    key = CERT_DIR / f"{label}.key"
    csr = CERT_DIR / f"{label}.csr"
    cert = CERT_DIR / f"{label}.crt"
    ext = CERT_DIR / f"{label}.ext"
    ext.write_text("subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n")
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", f"/CN={label} test CA", "-keyout", str(ca_key), "-out", str(ca_cert))
    openssl("req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
            "-keyout", str(key), "-out", str(csr))
    openssl("x509", "-req", "-in", str(csr), "-CA", str(ca_cert),
            "-CAkey", str(ca_key), "-CAcreateserial", "-days", "1",
            "-extfile", str(ext), "-out", str(cert))
    return ca_cert, key, cert


def collector(key: Path, cert: Path, port: int) -> tuple[grpc.Server, list[bytes]]:
    received: list[bytes] = []

    def export(request: bytes, context: grpc.ServicerContext) -> bytes:
        received.append(request)
        return b""  # An empty ExportTraceServiceResponse protobuf.

    server = grpc.server(ThreadPoolExecutor(max_workers=2))
    handler = grpc.method_handlers_generic_handler(
        "opentelemetry.proto.collector.trace.v1.TraceService",
        {"Export": grpc.unary_unary_rpc_method_handler(
            export, request_deserializer=lambda data: data,
            response_serializer=lambda data: data)})
    server.add_generic_rpc_handlers((handler,))
    credentials = grpc.ssl_server_credentials(((key.read_bytes(), cert.read_bytes()),))
    if server.add_secure_port(f"127.0.0.1:{port}", credentials) != port:
        raise RuntimeError("collector failed to bind")
    server.start()
    return server, received


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise RuntimeError("WebSocket closed before response")
        data += chunk
    return data


def ws_call(token: str, marker: str, expected_version: str) -> None:
    with socket.create_connection(("127.0.0.1", MCP_PORT), timeout=5) as sock:
        sock.settimeout(5)
        key = base64.b64encode(os.urandom(16)).decode()
        headers = ["GET /mcp HTTP/1.1", f"Host: localhost:{MCP_PORT}",
                   "Upgrade: websocket", "Connection: Upgrade",
                   f"Sec-WebSocket-Key: {key}", "Sec-WebSocket-Version: 13",
                   "Sec-WebSocket-Protocol: mcp", f"Authorization: Bearer {token}"]
        sock.sendall(("\r\n".join(headers) + "\r\n\r\n").encode())
        handshake = b""
        while b"\r\n\r\n" not in handshake and len(handshake) < 8192:
            handshake += sock.recv(4096)
        if b" 101 " not in handshake.split(b"\r\n", 1)[0]:
            raise RuntimeError("authenticated WebSocket upgrade failed")

        def call(request_id: int, method: str, params: dict | None = None) -> dict:
            payload = {"jsonrpc": "2.0", "id": request_id, "method": method}
            if params is not None:
                payload["params"] = params
            encoded = json.dumps(payload).encode()
            mask = os.urandom(4)
            header = bytes([0x81, 0x80 | len(encoded)]) if len(encoded) < 126 else (
                bytes([0x81, 0xfe]) + struct.pack("!H", len(encoded)))
            sock.sendall(header + mask + bytes(value ^ mask[i % 4]
                                                 for i, value in enumerate(encoded)))
            first, second = recv_exact(sock, 2)
            length = second & 127
            if length == 126:
                length = struct.unpack("!H", recv_exact(sock, 2))[0]
            elif length == 127:
                length = struct.unpack("!Q", recv_exact(sock, 8))[0]
            if length > 65536 or first & 15 != 1:
                raise RuntimeError("unexpected WebSocket response frame")
            result = json.loads(recv_exact(sock, length))
            if result.get("id") != request_id or "error" in result:
                raise RuntimeError(f"{method} failed over WebSocket")
            return result

        initialized = call(1, "initialize", {"protocolVersion": "2025-06-18",
                                            "capabilities": {},
                                            "clientInfo": {"name": "alpine-otlp-ci", "version": "1"}})
        if initialized.get("result", {}).get("protocolVersion") != "2025-06-18":
            raise RuntimeError("MCP initialization failed")
        if initialized.get("result", {}).get("serverInfo", {}).get("version") != expected_version:
            raise RuntimeError("packaged MCP server version mismatch")
        classified = call(2, "tools/call", {"name": "classify", "arguments": {
            "ip": "192.0.2.42", "user_agent": "Mozilla/5.0", "path": f"/{marker}"}})
        if classified.get("result", {}).get("isError") is not False:
            raise RuntimeError("MCP classify failed")


def run_case(binary: Path, expected_version: str, token: str, cache_key: str,
             marker: str, port: int, trusted: bool, received: list[bytes]) -> None:
    server = None
    with tempfile.TemporaryFile() as log_file:
        try:
            env = os.environ.copy()
            env.update({"AUTH_TOKENS": token, "CACHE_SCOPE_HMAC_KEY": cache_key,
                        "MCP__HOST": "127.0.0.1", "MCP__PORT": str(MCP_PORT),
                        "MCP__TELEMETRY__OTLP_ENDPOINT": f"https://localhost:{port}"})
            server = subprocess.Popen([str(binary)], env=env, stdout=log_file,
                                      stderr=subprocess.STDOUT)
            for _ in range(100):
                if server.poll() is not None:
                    raise RuntimeError("packaged musl server exited before readiness")
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{MCP_PORT}/health", timeout=1):
                        break
                except (OSError, TimeoutError):
                    time.sleep(0.1)
            else:
                raise RuntimeError("packaged musl server did not become ready")
            ws_call(token, marker, expected_version)
            if trusted:
                for _ in range(150):
                    if received:
                        break
                    if server.poll() is not None:
                        raise RuntimeError("packaged musl server exited before OTLP export")
                    time.sleep(0.1)
            else:
                # Allow the batch exporter to attempt TLS before checking its
                # bounded log for the certificate error.
                time.sleep(7)
        finally:
            if server is not None and server.poll() is None:
                server.terminate()
                try:
                    server.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=5)
                    raise RuntimeError("packaged musl server failed to stop")
            log_file.seek(0)
            captured = log_file.read(MAX_LOG_BYTES + 1)
            if len(captured) > MAX_LOG_BYTES or not captured:
                raise RuntimeError("Alpine OTLP MCP log was empty or exceeded 64 KiB")
            for secret in (token, cache_key, marker):
                if secret.encode() in captured:
                    raise RuntimeError("Alpine OTLP MCP log disclosed a synthetic secret")
            if not trusted and b"UnknownIssuer" not in captured:
                raise RuntimeError("untrusted collector did not yield a TLS trust failure")


def main() -> None:
    binary = Path(sys.argv[1]).resolve(strict=True)
    expected_version = sys.argv[2]
    token = secrets.token_hex(32)
    cache_key = secrets.token_hex(32)
    CERT_DIR.mkdir(mode=0o700)
    trusted_ca, trusted_key, trusted_cert = make_certificate("trusted")
    _, untrusted_key, untrusted_cert = make_certificate("untrusted")
    Path("/usr/local/share/ca-certificates/request-guard-ci.crt").write_bytes(
        trusted_ca.read_bytes())
    subprocess.run(["update-ca-certificates"], check=True, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, timeout=15)
    for trusted, key, cert, port in ((True, trusted_key, trusted_cert, 4318),
                                     (False, untrusted_key, untrusted_cert, 4319)):
        grpc_server, received = collector(key, cert, port)
        try:
            run_case(binary, expected_version, token, cache_key,
                     f"otlp-{secrets.token_hex(8)}", port, trusted, received)
            # No retry loop can turn zero exports into a passing trusted case.
            if trusted and (not received or any(not payload for payload in received)):
                raise RuntimeError("trusted collector received no nonempty trace export")
            if not trusted and received:
                raise RuntimeError("untrusted collector received a trace export")
        finally:
            grpc_server.stop(grace=2).wait(timeout=5)
    print("PASS Alpine OTLP TLS: trusted export received, untrusted CA rejected, private MCP logs")


if __name__ == "__main__":
    main()
