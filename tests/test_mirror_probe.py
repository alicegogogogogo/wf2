from __future__ import annotations

import io
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock

from provenance_api.app import application, reset_state
from provenance_api.mirrors import ProbeResult, probe_upstream

UPSTREAM = "https://registry.example.invalid"


def call(
    method: str,
    path: str,
    body: bytes = b"",
    *,
    headers: dict[str, str] | None = None,
    query_string: str | None = None,
) -> tuple[str, list[tuple[str, str]], bytes]:
    environ: dict[str, object] = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "CONTENT_LENGTH": str(len(body)),
        "wsgi.input": io.BytesIO(body),
    }
    for key, value in (headers or {}).items():
        environ[key] = value
    if query_string is not None:
        environ["QUERY_STRING"] = query_string
    captured: dict[str, object] = {}

    def start_response(status: str, resp_headers: list[tuple[str, str]]) -> None:
        captured["status"] = status
        captured["headers"] = resp_headers

    parts = application(environ, start_response)
    return str(captured["status"]), list(captured["headers"]), b"".join(parts)


def call_json(
    method: str,
    path: str,
    body: bytes = b"",
    **kwargs: object,
) -> tuple[str, list[tuple[str, str]], dict[str, object]]:
    status, headers, raw = call(method, path, body, **kwargs)  # type: ignore[arg-type]
    return status, headers, json.loads(raw.decode("utf-8"))


def register(
    name: str = "primary", upstream: str = UPSTREAM
) -> dict[str, object]:
    status, _h, body = call_json(
        "POST",
        "/mirrors",
        json.dumps({"name": name, "upstream": upstream}).encode("utf-8"),
        headers={"CONTENT_TYPE": "application/json"},
    )
    assert status == "201 Created", (status, body)
    return body


def patch_probe(result: ProbeResult):
    return mock.patch(
        "provenance_api.app.probe_upstream", return_value=result
    )


def patch_probe_side_effect(side_effect):
    return mock.patch(
        "provenance_api.app.probe_upstream", side_effect=side_effect
    )


class ProbePostTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.mirror = register()
        self.mirror_id = str(self.mirror["id"])

    def test_reachable_probe_shape_and_framing(self) -> None:
        result = ProbeResult(reachable=True, status_code=200, latency_ms=7)
        with patch_probe(result) as probe:
            status, headers, raw = call(
                "POST", f"/mirrors/{self.mirror_id}/probe"
            )
        self.assertEqual(status, "200 OK")
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )
        expected = (
            b'{"id":"' + self.mirror_id.encode()
            + b'","reachable":true,"status_code":200,"latency_ms":7}\n'
        )
        self.assertEqual(raw, expected)
        probe.assert_called_once_with(UPSTREAM)

    def test_non_2xx_status_is_still_reachable_business_success(self) -> None:
        result = ProbeResult(reachable=True, status_code=503, latency_ms=0)
        with patch_probe(result):
            status, _h, body = call_json(
                "POST", f"/mirrors/{self.mirror_id}/probe"
            )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["reachable"], True)
        self.assertEqual(body["status_code"], 503)
        self.assertIsInstance(body["latency_ms"], int)
        self.assertGreaterEqual(body["latency_ms"], 0)
        self.assertNotIn("error", body)

    def test_unreachable_probe_shape(self) -> None:
        result = ProbeResult(reachable=False, status_code=None, latency_ms=None)
        with patch_probe(result) as probe:
            status, _h, raw = call(
                "POST", f"/mirrors/{self.mirror_id}/probe"
            )
        self.assertEqual(status, "200 OK")
        expected = (
            b'{"id":"' + self.mirror_id.encode()
            + b'","reachable":false,"status_code":null,"latency_ms":null,'
            b'"error":"probe_failed"}\n'
        )
        self.assertEqual(raw, expected)
        probe.assert_called_once_with(UPSTREAM)

    def test_post_overwrites_previous_result(self) -> None:
        failed = ProbeResult(reachable=False, status_code=None, latency_ms=None)
        with patch_probe(failed):
            call("POST", f"/mirrors/{self.mirror_id}/probe")
        status, _h, body = call_json("GET", f"/mirrors/{self.mirror_id}/probe")
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["reachable"], False)

        ok = ProbeResult(reachable=True, status_code=200, latency_ms=3)
        with patch_probe(ok):
            status, _h, body = call_json(
                "POST", f"/mirrors/{self.mirror_id}/probe"
            )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["reachable"], True)
        # The most recent probe replaced the earlier failure exactly.
        status, _h, body = call_json(
            "GET", f"/mirrors/{self.mirror_id}/probe"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            body,
            {
                "id": self.mirror_id,
                "reachable": True,
                "status_code": 200,
                "latency_ms": 3,
            },
        )

    def test_post_with_body_is_rejected_without_probing(self) -> None:
        result = ProbeResult(reachable=True, status_code=200, latency_ms=1)
        with patch_probe(result) as probe:
            status, _h, body = call_json(
                "POST",
                f"/mirrors/{self.mirror_id}/probe",
                b"{}",
                headers={"CONTENT_TYPE": "application/json"},
            )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        probe.assert_not_called()
        # Nothing was recorded.
        status, _h, body = call_json(
            "GET", f"/mirrors/{self.mirror_id}/probe"
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "probe_not_found")

    def test_probe_does_not_touch_cache_entries_or_counters(self) -> None:
        status, _h, before = call_json("GET", "/cache/status")
        self.assertEqual(status, "200 OK")
        result = ProbeResult(reachable=True, status_code=200, latency_ms=1)
        with patch_probe(result):
            for _ in range(3):
                call("POST", f"/mirrors/{self.mirror_id}/probe")
        status, _h, after = call_json("GET", "/cache/status")
        self.assertEqual(status, "200 OK")
        self.assertEqual(before, after)


class ProbeGetTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.mirror = register()
        self.mirror_id = str(self.mirror["id"])

    def test_get_before_any_probe_returns_404_probe_not_found(self) -> None:
        status, _h, body = call_json(
            "GET", f"/mirrors/{self.mirror_id}/probe"
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "probe_not_found")

    def test_get_returns_last_result_and_never_contacts_upstream(self) -> None:
        result = ProbeResult(reachable=True, status_code=404, latency_ms=12)
        with patch_probe(result):
            call("POST", f"/mirrors/{self.mirror_id}/probe")
        with patch_probe_side_effect(
            lambda upstream: (_ for _ in ()).throw(
                AssertionError("GET must not trigger a probe")
            )
        ) as probe:
            status, _h, body_a = call_json(
                "GET", f"/mirrors/{self.mirror_id}/probe"
            )
            status, _h, body_b = call_json(
                "GET", f"/mirrors/{self.mirror_id}/probe"
            )
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            body_a,
            {
                "id": self.mirror_id,
                "reachable": True,
                "status_code": 404,
                "latency_ms": 12,
            },
        )
        self.assertEqual(body_a, body_b)
        probe.assert_not_called()


class ProbeErrorTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.mirror = register()
        self.mirror_id = str(self.mirror["id"])

    def test_unknown_mirror_returns_404_for_both_methods(self) -> None:
        result = ProbeResult(reachable=True, status_code=200, latency_ms=1)
        with patch_probe(result) as probe:
            status, _h, body = call_json("POST", "/mirrors/missing/probe")
            self.assertEqual(status, "404 Not Found")
            self.assertEqual(body["error"], "mirror_not_found")
            status, _h, body = call_json("GET", "/mirrors/missing/probe")
            self.assertEqual(status, "404 Not Found")
            self.assertEqual(body["error"], "mirror_not_found")
        probe.assert_not_called()

    def test_invalid_id_returns_400_for_both_methods(self) -> None:
        result = ProbeResult(reachable=True, status_code=200, latency_ms=1)
        for path in (
            "/mirrors//probe",
            "/mirrors/a/b/probe",
            "/mirrors/a\\b/probe",
        ):
            with patch_probe(result) as probe:
                status, _h, body = call_json("POST", path)
                self.assertEqual(status, "400 Bad Request", path)
                self.assertEqual(body["error"], "invalid_request")
                status, _h, body = call_json("GET", path)
                self.assertEqual(status, "400 Bad Request", path)
                self.assertEqual(body["error"], "invalid_request")
            probe.assert_not_called()

    def test_query_parameters_return_400_for_both_methods(self) -> None:
        result = ProbeResult(reachable=True, status_code=200, latency_ms=1)
        with patch_probe(result) as probe:
            for method in ("GET", "POST"):
                status, _h, body = call_json(
                    method,
                    f"/mirrors/{self.mirror_id}/probe",
                    query_string="x=1",
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")
        probe.assert_not_called()

    def test_other_methods_return_405_with_allow_header(self) -> None:
        for path in (
            f"/mirrors/{self.mirror_id}/probe",
            "/mirrors//probe",
        ):
            for method in ("PUT", "DELETE", "PATCH"):
                status, headers, body = call_json(method, path)
                self.assertEqual(status, "405 Method Not Allowed", path)
                self.assertIn(("Allow", "GET, POST"), headers)
                self.assertEqual(body["error"], "method_not_allowed")


class ProbeLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def test_deleting_mirror_discards_its_probe(self) -> None:
        mirror = register()
        result = ProbeResult(reachable=True, status_code=200, latency_ms=1)
        with patch_probe(result):
            status, _h, _raw = call(
                "POST", f"/mirrors/{mirror['id']}/probe"
            )
        self.assertEqual(status, "200 OK")
        status, _h, _raw = call("DELETE", f"/mirrors/{mirror['id']}")
        self.assertEqual(status, "200 OK")
        status, _h, body = call_json("GET", f"/mirrors/{mirror['id']}/probe")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "mirror_not_found")

    def test_reset_clears_probe_results(self) -> None:
        mirror = register()
        result = ProbeResult(reachable=True, status_code=200, latency_ms=1)
        with patch_probe(result):
            call("POST", f"/mirrors/{mirror['id']}/probe")
        reset_state()
        status, _h, body = call_json("GET", f"/mirrors/{mirror['id']}/probe")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "mirror_not_found")


class _RecordingHandler(BaseHTTPRequestHandler):
    last_path: str | None = None

    def do_GET(self) -> None:  # noqa: N802 - http.server naming
        type(self).last_path = self.path
        if self.path == "/boom":
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"error")
            return
        self.send_response(204)
        self.end_headers()

    def log_message(self, *args: object) -> None:
        pass


class ProbeUpstreamIntegrationTests(unittest.TestCase):
    def _direct_open(self):
        # Loopback targets must be contacted directly: an ambient HTTP
        # proxy would otherwise answer for every closed local port and
        # make reachability environment-dependent. The opener's ``open``
        # is handed to the probe as a call-local stand-in, so the
        # process-global ``urllib.request.urlopen`` is never replaced and
        # no other test can be affected.
        import urllib.request

        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        return opener.open

    def test_probe_against_real_local_server(self) -> None:
        server = HTTPServer(("127.0.0.1", 0), _RecordingHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            result = probe_upstream(
                f"http://127.0.0.1:{port}/", timeout=5,
                urlopen=self._direct_open(),
            )
            self.assertTrue(result.reachable)
            self.assertEqual(result.status_code, 204)
            self.assertIsInstance(result.latency_ms, int)
            self.assertGreaterEqual(result.latency_ms, 0)
            self.assertEqual(_RecordingHandler.last_path, "/")

            result = probe_upstream(
                f"http://127.0.0.1:{port}/boom", timeout=5,
                urlopen=self._direct_open(),
            )
            self.assertTrue(result.reachable)
            self.assertEqual(result.status_code, 500)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_probe_unreachable_port(self) -> None:
        # A socket bound but never listening reliably refuses connections;
        # unlike a closed server port, its number cannot be reused mid-test.
        import socket

        holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        holder.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        holder.bind(("127.0.0.1", 0))
        port = holder.getsockname()[1]
        try:
            result = probe_upstream(
                f"http://127.0.0.1:{port}/", timeout=1,
                urlopen=self._direct_open(),
            )
        finally:
            holder.close()
        self.assertFalse(result.reachable)
        self.assertIsNone(result.status_code)
        self.assertIsNone(result.latency_ms)
        self.assertEqual(
            result.to_dict("mirror-1"),
            {
                "id": "mirror-1",
                "reachable": False,
                "status_code": None,
                "latency_ms": None,
                "error": "probe_failed",
            },
        )


if __name__ == "__main__":
    unittest.main()
