#!/usr/bin/env python3
"""Regression tests for the lab probe's request boundaries."""

import http.server
import threading
import unittest

import adversarial_probe


class ProbeServer(http.server.BaseHTTPRequestHandler):
    hits = 0
    last_length = None
    redirect_to = None
    max_request_bytes = 1024 * 1024

    def do_POST(self):
        type(self).hits += 1
        type(self).last_length = int(self.headers["Content-Length"])
        if type(self).redirect_to:
            self.send_response(302)
            self.send_header("Location", type(self).redirect_to)
        elif type(self).last_length > type(self).max_request_bytes:
            self.send_response(413)
        else:
            self.send_response(204)
        self.end_headers()

    def log_message(self, format, *args):
        pass


def serve(handler):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


class ProbeBoundariesTest(unittest.TestCase):
    def test_redirect_is_not_followed_with_bearer_token(self):
        class Destination(ProbeServer):
            pass

        class Redirector(ProbeServer):
            pass

        destination = serve(Destination)
        Redirector.redirect_to = f"http://127.0.0.1:{destination.server_port}/mcp"
        redirector = serve(Redirector)
        try:
            status, _ = adversarial_probe.post(
                f"http://127.0.0.1:{redirector.server_port}",
                "lab-only-token",
                adversarial_probe.rpc("health"),
            )
            self.assertEqual(status, 302)
            self.assertEqual(Destination.hits, 0)
        finally:
            redirector.shutdown()
            redirector.server_close()
            destination.shutdown()
            destination.server_close()

    def test_oversized_length_uses_configured_limit(self):
        class Target(ProbeServer):
            max_request_bytes = 2 * 1024 * 1024

        target = serve(Target)
        try:
            status = adversarial_probe.oversized_request(
                f"http://127.0.0.1:{target.server_port}",
                "lab-only-token",
                Target.max_request_bytes,
            )
            self.assertEqual(status, 413)
            self.assertEqual(Target.last_length, Target.max_request_bytes + 1)
        finally:
            target.shutdown()
            target.server_close()


if __name__ == "__main__":
    unittest.main()
