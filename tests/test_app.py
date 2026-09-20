from __future__ import annotations

import json
import unittest

from provenance_api.app import application


def request(method: str, path: str) -> tuple[str, list[tuple[str, str]], dict[str, object]]:
    captured: dict[str, object] = {}

    def start_response(status: str, headers: list[tuple[str, str]]) -> None:
        captured["status"] = status
        captured["headers"] = headers

    chunks = application(
        {"REQUEST_METHOD": method, "PATH_INFO": path}, start_response
    )
    body = json.loads(b"".join(chunks).decode("utf-8"))
    return str(captured["status"]), list(captured["headers"]), body


class ApplicationTests(unittest.TestCase):
    def test_health(self) -> None:
        status, headers, body = request("GET", "/health")

        self.assertEqual(status, "200 OK")
        self.assertIn(("Content-Type", "application/json; charset=utf-8"), headers)
        self.assertEqual(body, {"status": "ok"})

    def test_unknown_path(self) -> None:
        status, _headers, body = request("GET", "/missing")

        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "not_found")


if __name__ == "__main__":
    unittest.main()

