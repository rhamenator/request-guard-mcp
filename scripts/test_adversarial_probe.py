#!/usr/bin/env python3
"""Regression tests for the lab probe's request boundaries."""

import http.server
import json
import random
import threading
import unittest

import adversarial_probe
import adversarial_classifier_probe
import adversarial_envelope_fuzz_probe


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
    def test_malformed_cases_require_specific_error_codes_and_ids(self):
        rng = random.Random(0xA11CE)
        seen = set()
        for number in range(128):
            name, body, expected_code, expected_id = (
                adversarial_envelope_fuzz_probe.malformed_case(number, rng)
            )
            seen.add(name)
            with self.subTest(number=number, name=name):
                correct = json.dumps({"jsonrpc": "2.0", "id": expected_id,
                                      "error": {"code": expected_code}}).encode()
                wrong = json.dumps({"jsonrpc": "2.0", "id": expected_id,
                                    "error": {"code": -500}}).encode()
                wrong_id = json.dumps({"jsonrpc": "2.0", "id": "wrong",
                                       "error": {"code": expected_code}}).encode()
                self.assertTrue(adversarial_envelope_fuzz_probe.response_matches(
                    200, correct, expected_code, expected_id))
                self.assertFalse(adversarial_envelope_fuzz_probe.response_matches(
                    200, wrong, expected_code, expected_id))
                self.assertFalse(adversarial_envelope_fuzz_probe.response_matches(
                    200, wrong_id, expected_code, expected_id))
                self.assertFalse(adversarial_envelope_fuzz_probe.response_matches(
                    500, correct, expected_code, expected_id))
                self.assertLess(len(body), 4096)
                if name == "truncated_json":
                    with self.assertRaises(json.JSONDecodeError):
                        json.loads(body)
                else:
                    envelope = json.loads(body)
                    self.assertIsInstance(envelope, dict)
                    if name in {"missing_tool_name", "invalid_tool_name",
                                "invalid_classify_arguments", "unknown_tool"}:
                        self.assertEqual(envelope["method"], "tools/call")
        self.assertEqual(len(seen), 8)

    def test_response_id_must_match_json_type(self):
        response = adversarial_envelope_fuzz_probe.response_matches
        self.assertFalse(response(200, b'{"jsonrpc":"2.0","id":true,"error":{"code":-400}}',
                                  -400, 1))
        self.assertFalse(response(200, b'{"jsonrpc":"2.0","id":1.0,"error":{"code":-400}}',
                                  -400, 1))

    def test_benign_classifier_control_rejects_scraper_signal(self):
        name, _, _, required, absent = adversarial_classifier_probe.CASES[0]
        self.assertEqual(name, "benign_browser")
        self.assertFalse(adversarial_classifier_probe.signals_match(
            {"ua_scraper"}, required, absent))
        self.assertFalse(adversarial_classifier_probe.response_id_matches(True, 1))

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
