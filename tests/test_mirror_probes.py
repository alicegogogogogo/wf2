from __future__ import annotations

import hashlib
import hmac
import http.server
import io
import json
import threading
import unittest
from unittest import mock

from provenance_api.app import application, reset_state
from provenance_api.mirror_probes import ProbeResult, probe_upstream

UPSTREAM = "https://registry.example.invalid"
MIRROR_ID = "mirror-1"


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


def register(name: str = "primary", upstream: str = UPSTREAM) -> dict[str, object]:
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


class ProbeHandlerTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.mirror = register()
        self.mirror_id = str(self.mirror["id"])
        self.reachable = ProbeResult(
            id=self.mirror_id, reachable=True, status_code=200, latency_ms=12
        )
        self.failed = ProbeResult(
            id=self.mirror_id, reachable=False, status_code=None, latency_ms=7
        )

    def probe_path(self) -> str:
        return f"/mirrors/{self.mirror_id}/probe"

    def test_post_reachable_returns_compact_fixed_order_body(self) -> None:
        with patch_probe(self.reachable) as run:
            status, headers, raw = call("POST", self.probe_path())
        self.assertEqual(status, "200 OK")
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )
        self.assertEqual(
            raw,
            b'{"id":"' + self.mirror_id.encode()
            + b'","reachable":true,"status_code":200,"latency_ms":12}\n',
        )
        run.assert_called_once_with(UPSTREAM, self.mirror_id)

    def test_post_unreachable_is_still_200_with_error_field(self) -> None:
        with patch_probe(self.failed):
            status, _h, raw = call("POST", self.probe_path())
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            raw,
            b'{"id":"' + self.mirror_id.encode()
            + b'","reachable":false,"status_code":null,"latency_ms":7'
            + b',"error":"probe_failed"}\n',
        )

    def test_get_never_probed_returns_404_probe_not_found(self) -> None:
        must_not_run = mock.Mock(side_effect=AssertionError("must not probe"))
        with mock.patch("provenance_api.app.probe_upstream", must_not_run):
            status, _h, body = call_json("GET", self.probe_path())
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "probe_not_found")
        must_not_run.assert_not_called()

    def test_get_returns_most_recent_result_without_probing(self) -> None:
        with patch_probe(self.reachable):
            call("POST", self.probe_path())
        must_not_run = mock.Mock(side_effect=AssertionError("must not probe"))
        with mock.patch("provenance_api.app.probe_upstream", must_not_run):
            status, _h, body = call_json("GET", self.probe_path())
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            body,
            {"id": self.mirror_id, "reachable": True,
             "status_code": 200, "latency_ms": 12},
        )
        must_not_run.assert_not_called()

    def test_post_overwrites_the_previous_result(self) -> None:
        with patch_probe(self.reachable):
            call("POST", self.probe_path())
        with patch_probe(self.failed):
            status, _h, body = call_json("POST", self.probe_path())
        self.assertEqual(status, "200 OK")
        self.assertFalse(body["reachable"])
        self.assertIsNone(body["status_code"])
        self.assertEqual(body["error"], "probe_failed")
        status, _h, body = call_json("GET", self.probe_path())
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["error"], "probe_failed")

    def test_get_after_reachable_post_has_same_shape(self) -> None:
        with patch_probe(self.reachable):
            post_status, _h, post_raw = call("POST", self.probe_path())
        get_status, _h, get_raw = call("GET", self.probe_path())
        self.assertEqual(post_status, "200 OK")
        self.assertEqual(get_status, "200 OK")
        self.assertEqual(post_raw, get_raw)

    def test_unknown_mirror_returns_404_for_both_methods(self) -> None:
        must_not_run = mock.Mock(side_effect=AssertionError("must not probe"))
        with mock.patch("provenance_api.app.probe_upstream", must_not_run):
            for method in ("GET", "POST"):
                status, _h, body = call_json(method, "/mirrors/missing/probe")
                self.assertEqual(status, "404 Not Found", method)
                self.assertEqual(body["error"], "mirror_not_found", method)
        must_not_run.assert_not_called()

    def test_invalid_id_returns_400_for_both_methods(self) -> None:
        must_not_run = mock.Mock(side_effect=AssertionError("must not probe"))
        with mock.patch("provenance_api.app.probe_upstream", must_not_run):
            for path in ("/mirrors//probe", "/mirrors/a/b/probe"):
                for method in ("GET", "POST"):
                    status, _h, body = call_json(method, path)
                    self.assertEqual(status, "400 Bad Request", (method, path))
                    self.assertEqual(body["error"], "invalid_request")
        must_not_run.assert_not_called()

    def test_query_parameters_return_400(self) -> None:
        must_not_run = mock.Mock(side_effect=AssertionError("must not probe"))
        with mock.patch("provenance_api.app.probe_upstream", must_not_run):
            for method in ("GET", "POST"):
                status, _h, body = call_json(
                    method, self.probe_path(), query_string="x=1"
                )
                self.assertEqual(status, "400 Bad Request", method)
                self.assertEqual(body["error"], "invalid_request")
        must_not_run.assert_not_called()
        # No probe result was recorded.
        status, _h, body = call_json("GET", self.probe_path())
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "probe_not_found")

    def test_post_with_body_returns_400_and_does_not_probe(self) -> None:
        must_not_run = mock.Mock(side_effect=AssertionError("must not probe"))
        with mock.patch("provenance_api.app.probe_upstream", must_not_run):
            status, _h, body = call_json(
                "POST",
                self.probe_path(),
                b"{}",
                headers={"CONTENT_TYPE": "application/json"},
            )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        must_not_run.assert_not_called()
        status, _h, body = call_json("GET", self.probe_path())
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "probe_not_found")

    def test_post_with_explicit_empty_body_is_accepted(self) -> None:
        with patch_probe(self.reachable) as run:
            status, _h, _raw = call(
                "POST",
                self.probe_path(),
                b"",
                headers={"CONTENT_LENGTH": "0"},
            )
        self.assertEqual(status, "200 OK")
        run.assert_called_once()

    def test_other_methods_return_405_with_allow_header(self) -> None:
        for method in ("PUT", "DELETE", "PATCH"):
            status, headers, body = call_json(method, self.probe_path())
            self.assertEqual(status, "405 Method Not Allowed", method)
            self.assertIn(("Allow", "GET, POST"), headers)
            self.assertEqual(body["error"], "method_not_allowed")

    def test_deleting_mirror_drops_its_probe_result(self) -> None:
        with patch_probe(self.reachable):
            call("POST", self.probe_path())
        status, _h, _body = call("DELETE", f"/mirrors/{self.mirror_id}")
        self.assertEqual(status, "200 OK")
        status, _h, body = call_json("GET", self.probe_path())
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "mirror_not_found")
        # A same-name re-registration starts without any probe result.
        reborn = register()
        status, _h, body = call_json(
            "GET", f"/mirrors/{reborn['id']}/probe"
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "probe_not_found")


class _QuietHandler(http.server.BaseHTTPRequestHandler):
    code = 200

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        self.send_response(self.code)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args: object) -> None:
        pass


def _local_server(code: int) -> tuple[http.server.ThreadingHTTPServer, str]:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), type(
        "Handler", (_QuietHandler,), {"code": code}
    ))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


class ProbeUpstreamTests(unittest.TestCase):
    def test_reachable_200_records_status_and_non_negative_latency(self) -> None:
        server, url = _local_server(200)
        try:
            result = probe_upstream(url, MIRROR_ID, timeout=5.0)
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(result.id, MIRROR_ID)
        self.assertTrue(result.reachable)
        self.assertEqual(result.status_code, 200)
        self.assertIsInstance(result.latency_ms, int)
        self.assertGreaterEqual(result.latency_ms, 0)
        self.assertNotIn("error", result.to_dict())

    def test_http_error_status_is_still_reachable(self) -> None:
        server, url = _local_server(404)
        try:
            result = probe_upstream(url, MIRROR_ID, timeout=5.0)
        finally:
            server.shutdown()
            server.server_close()
        self.assertTrue(result.reachable)
        self.assertEqual(result.status_code, 404)
        self.assertGreaterEqual(result.latency_ms, 0)
        self.assertNotIn("error", result.to_dict())

    def test_closed_port_is_unreachable(self) -> None:
        server, url = _local_server(500)
        server.shutdown()
        server.server_close()
        result = probe_upstream(url, MIRROR_ID, timeout=1.0)
        self.assertFalse(result.reachable)
        self.assertIsNone(result.status_code)
        self.assertGreaterEqual(result.latency_ms, 0)
        self.assertEqual(result.to_dict()["error"], "probe_failed")


LAYER_A = b"alpha-layer-bytes"
LAYER_B = b"beta-layer-bytes-larger"
DIGEST_A = hashlib.sha256(LAYER_A).hexdigest()
DIGEST_B = hashlib.sha256(LAYER_B).hexdigest()

POLICY = {
    "algorithm": "hmac-sha256",
    "keys": ["key-one", "key-two"],
    "cover_digest": True,
}


def sign(key_id: str, signed_digest: str) -> str:
    return hmac.new(
        key_id.encode("utf-8"),
        signed_digest.lower().encode("ascii"),
        hashlib.sha256,
    ).hexdigest()


def fake_fetch(upstream: str, digest: str) -> bytes:
    if digest == DIGEST_A:
        return LAYER_A
    if digest == DIGEST_B:
        return LAYER_B
    raise AssertionError(f"unexpected digest {digest}")


def prefetch_json(mirror_id: str, headers: dict[str, str]):
    body = json.dumps({"digests": [DIGEST_A]}).encode("utf-8")
    return call_json(
        "POST", f"/mirrors/{mirror_id}/prefetch", body, headers=headers
    )


class PrefetchSignatureOrderTests(unittest.TestCase):
    """Multiple signature conditions must report only the earliest code.

    The canonical order is missing headers, key trust, coverage, then
    signature value; an untrusted key wins over malformed other headers.
    """

    def setUp(self) -> None:
        reset_state()
        mirror = register()
        self.mirror_id = str(mirror["id"])
        status, _h, body = call_json(
            "POST",
            f"/mirrors/{self.mirror_id}/signature-policy",
            json.dumps(POLICY).encode("utf-8"),
            headers={"CONTENT_TYPE": "application/json"},
        )
        assert status == "201 Created", (status, body)

    def test_untrusted_key_beats_malformed_other_headers(self) -> None:
        # Key is untrusted *and* the signed digest is not hex and the
        # signature is empty: key trust must be the only reported code.
        headers = {
            "HTTP_X_KEY_ID": "stranger",
            "HTTP_X_SIGNED_DIGEST": "not-a-digest",
            "HTTP_X_SIGNATURE": "",
        }
        with mock.patch(
            "provenance_api.app.fetch_upstream_layer", side_effect=fake_fetch
        ):
            status, _h, body = prefetch_json(self.mirror_id, headers)
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["results"][0]["status"], "failed")
        self.assertEqual(body["results"][0]["error"], "key_not_trusted")

    def test_untrusted_key_beats_uncovered_digest(self) -> None:
        # The key is untrusted and the otherwise-valid signed digest does
        # not cover the pulled layer: key trust comes first.
        headers = {
            "HTTP_X_KEY_ID": "stranger",
            "HTTP_X_SIGNED_DIGEST": DIGEST_B,
            "HTTP_X_SIGNATURE": sign("stranger", DIGEST_B),
        }
        with mock.patch(
            "provenance_api.app.fetch_upstream_layer", side_effect=fake_fetch
        ):
            status, _h, body = prefetch_json(self.mirror_id, headers)
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["results"][0]["error"], "key_not_trusted")

    def test_uncovered_digest_beats_bad_signature(self) -> None:
        # Trusted key, valid header formats, but the signed digest does not
        # cover the layer and the signature also fails: coverage first.
        headers = {
            "HTTP_X_KEY_ID": "key-one",
            "HTTP_X_SIGNED_DIGEST": DIGEST_B,
            "HTTP_X_SIGNATURE": sign("key-two", DIGEST_B),
        }
        with mock.patch(
            "provenance_api.app.fetch_upstream_layer", side_effect=fake_fetch
        ):
            status, _h, body = prefetch_json(self.mirror_id, headers)
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["results"][0]["error"], "digest_uncovered")

    def test_missing_headers_still_win_over_everything(self) -> None:
        with mock.patch(
            "provenance_api.app.fetch_upstream_layer", side_effect=fake_fetch
        ):
            status, _h, body = prefetch_json(self.mirror_id, {})
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["results"][0]["error"], "signature_missing")

    def test_single_pull_uses_same_order(self) -> None:
        headers = {
            "HTTP_X_KEY_ID": "stranger",
            "HTTP_X_SIGNED_DIGEST": "not-a-digest",
            "HTTP_X_SIGNATURE": "",
        }
        with mock.patch(
            "provenance_api.app.fetch_upstream_layer", return_value=LAYER_A
        ):
            status, _h, body = call_json(
                "POST",
                f"/mirrors/{self.mirror_id}/pull/{DIGEST_A}",
                headers=headers,
            )
        self.assertEqual(status, "403 Forbidden")
        self.assertEqual(body["error"], "key_not_trusted")


if __name__ == "__main__":
    unittest.main()
