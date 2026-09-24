from __future__ import annotations

import hashlib
import io
import json
import unittest
from unittest import mock

from provenance_api.app import application, cache_store, reset_state
from provenance_api.mirrors import MirrorFetchError

LAYER_A = b"alpha-layer-bytes"
LAYER_B = b"beta-layer-bytes-larger"
DIGEST_A = hashlib.sha256(LAYER_A).hexdigest()
DIGEST_B = hashlib.sha256(LAYER_B).hexdigest()
DIGEST_C = "c" * 64

UPSTREAM = "https://registry.example.invalid"
UPSTREAM_SLASH = UPSTREAM + "/"


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
) -> tuple[str, dict[str, object]]:
    status, _h, body = call_json(
        "POST",
        "/mirrors",
        json.dumps({"name": name, "upstream": upstream}).encode("utf-8"),
        headers={"CONTENT_TYPE": "application/json"},
    )
    assert status == "201 Created", (status, body)
    return status, body


def put_cache_layer(data: bytes = LAYER_A) -> None:
    status, _h, _raw = call(
        "POST",
        f"/cache/layers/{hashlib.sha256(data).hexdigest()}",
        data,
        headers={"CONTENT_TYPE": "application/octet-stream"},
    )
    assert status == "201 Created", status


def patch_fetch(data: bytes | None = None, error: MirrorFetchError | None = None):
    if error is not None:
        return mock.patch(
            "provenance_api.app.fetch_upstream_layer", side_effect=error
        )
    return mock.patch(
        "provenance_api.app.fetch_upstream_layer", return_value=data
    )


class MirrorRegistrationTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def test_register_returns_201_with_compact_echo(self) -> None:
        status, headers, raw = call(
            "POST",
            "/mirrors",
            json.dumps({"name": "primary", "upstream": UPSTREAM_SLASH}).encode(),
            headers={"CONTENT_TYPE": "application/json"},
        )
        self.assertEqual(status, "201 Created")
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )
        body = json.loads(raw)
        self.assertEqual(set(body), {"id", "name", "upstream"})
        self.assertIsInstance(body["id"], str)
        self.assertTrue(body["id"])
        self.assertEqual(body["name"], "primary")
        self.assertEqual(body["upstream"], UPSTREAM_SLASH)
        # Compact JSON with a single trailing newline.
        self.assertEqual(
            raw,
            json.dumps(body, separators=(",", ":")).encode("utf-8") + b"\n",
        )

    def test_empty_registry_lists_empty_array(self) -> None:
        status, _h, raw = call("GET", "/mirrors")
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b'{"mirrors":[]}\n')

    def test_list_returns_registration_order(self) -> None:
        _, first = register("first")
        _, second = register("second", "https://b.example.invalid")
        status, _h, body = call_json("GET", "/mirrors")
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            [m["id"] for m in body["mirrors"]], [first["id"], second["id"]]
        )
        for item in body["mirrors"]:
            self.assertEqual(set(item), {"id", "name", "upstream"})

    def test_get_single_mirror_echoes_three_fields(self) -> None:
        _s, created = register()
        status, _h, body = call_json("GET", f"/mirrors/{created['id']}")
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, created)

    def test_duplicate_name_returns_409_and_keeps_original(self) -> None:
        _s, original = register("primary", UPSTREAM)
        status, _h, body = call_json(
            "POST",
            "/mirrors",
            json.dumps(
                {"name": "primary", "upstream": "https://other.example.invalid"}
            ).encode("utf-8"),
            headers={"CONTENT_TYPE": "application/json"},
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "duplicate_mirror")
        _s, _h, listed = call_json("GET", "/mirrors")
        self.assertEqual(len(listed["mirrors"]), 1)
        self.assertEqual(listed["mirrors"][0], original)

    def test_different_names_are_separate_mirrors(self) -> None:
        register("primary")
        register("secondary", "https://other.example.invalid")
        _s, _h, body = call_json("GET", "/mirrors")
        self.assertEqual(len(body["mirrors"]), 2)

    def test_empty_body_returns_400(self) -> None:
        status, _h, body = call_json("POST", "/mirrors", b"")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_bad_json_returns_400(self) -> None:
        status, _h, body = call_json(
            "POST",
            "/mirrors",
            b"{not json",
            headers={"CONTENT_TYPE": "application/json"},
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_non_object_top_level_returns_400(self) -> None:
        for payload in (b"[1,2]", b'"x"', b"42", b"null"):
            status, _h, body = call_json(
                "POST",
                "/mirrors",
                payload,
                headers={"CONTENT_TYPE": "application/json"},
            )
            self.assertEqual(status, "400 Bad Request", payload)
            self.assertEqual(body["error"], "invalid_request")

    def test_field_errors_return_400_and_leave_no_record(self) -> None:
        payloads = [
            b'{"name":"primary"}',
            b'{"upstream":"https://x.example.invalid"}',
            b'{"name":"primary","upstream":"https://x.example.invalid","extra":1}',
            b'{"name":"","upstream":"https://x.example.invalid"}',
            b'{"name":"   ","upstream":"https://x.example.invalid"}',
            b'{"name":123,"upstream":"https://x.example.invalid"}',
            b'{"name":"primary","upstream":""}',
            b'{"name":"primary","upstream":42}',
            b'{"name":"primary","upstream":null}',
        ]
        for payload in payloads:
            status, _h, body = call_json(
                "POST",
                "/mirrors",
                payload,
                headers={"CONTENT_TYPE": "application/json"},
            )
            self.assertEqual(status, "400 Bad Request", payload)
            self.assertEqual(body["error"], "invalid_request")
        _s, _h, listed = call_json("GET", "/mirrors")
        self.assertEqual(listed["mirrors"], [])

    def test_upstream_must_be_absolute_http_or_https(self) -> None:
        for upstream in (
            "ftp://x.example.invalid",
            "example.invalid/path",
            "/just/a/path",
            "http://",
            "https://",
            "mailto:a@b.invalid",
        ):
            status, _h, body = call_json(
                "POST",
                "/mirrors",
                json.dumps({"name": "m", "upstream": upstream}).encode("utf-8"),
                headers={"CONTENT_TYPE": "application/json"},
            )
            self.assertEqual(status, "400 Bad Request", upstream)
            self.assertEqual(body["error"], "invalid_request")

    def test_query_parameters_return_400(self) -> None:
        register()
        status, _h, body = call_json("GET", "/mirrors", query_string="x=1")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        status, _h, body = call_json(
            "POST",
            "/mirrors",
            b'{"name":"x","upstream":"https://x.example.invalid"}',
            headers={"CONTENT_TYPE": "application/json"},
            query_string="x=1",
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_collection_method_not_allowed_has_allow_header(self) -> None:
        for method in ("PUT", "DELETE", "PATCH"):
            status, headers, body = call_json(method, "/mirrors")
            self.assertEqual(status, "405 Method Not Allowed")
            self.assertIn(("Allow", "GET, POST"), headers)
            self.assertEqual(body["error"], "method_not_allowed")

    def test_item_method_not_allowed_has_allow_header(self) -> None:
        _s, created = register()
        for method in ("POST", "PUT", "DELETE"):
            status, headers, body = call_json(method, f"/mirrors/{created['id']}")
            self.assertEqual(status, "405 Method Not Allowed")
            self.assertIn(("Allow", "GET"), headers)
            self.assertEqual(body["error"], "method_not_allowed")


class MirrorItemErrorTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def test_unknown_id_returns_404(self) -> None:
        status, _h, body = call_json("GET", "/mirrors/does-not-exist")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "mirror_not_found")

    def test_empty_id_returns_400(self) -> None:
        status, _h, body = call_json("GET", "/mirrors/")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_id_with_separator_returns_400(self) -> None:
        for path in ("/mirrors/a/b", "/mirrors/a\\b"):
            status, _h, body = call_json("GET", path)
            self.assertEqual(status, "400 Bad Request", path)
            self.assertEqual(body["error"], "invalid_request")

    def test_item_query_parameters_return_400(self) -> None:
        _s, created = register()
        status, _h, body = call_json(
            "GET", f"/mirrors/{created['id']}", query_string="x=1"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")


class MirrorPullTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def test_cache_hit_returns_raw_bytes_without_upstream_or_counter_change(
        self,
    ) -> None:
        _s, created = register()
        put_cache_layer(LAYER_A)
        with patch_fetch() as fetch:
            status, headers, raw = call(
                "POST", f"/mirrors/{created['id']}/pull/{DIGEST_A}"
            )
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, LAYER_A)
        self.assertIn(("Content-Type", "application/octet-stream"), headers)
        self.assertIn(("Content-Length", str(len(LAYER_A))), headers)
        fetch.assert_not_called()
        _s, _h, status_body = call_json("GET", "/cache/status")
        self.assertEqual(status_body["hits"], 0)
        self.assertEqual(status_body["misses"], 0)
        self.assertEqual(status_body["entries"], 1)

    def test_miss_fetches_verifies_caches_and_returns_bytes(self) -> None:
        _s, created = register(upstream=UPSTREAM_SLASH)
        with patch_fetch(LAYER_A) as fetch:
            status, headers, raw = call(
                "POST", f"/mirrors/{created['id']}/pull/{DIGEST_A}"
            )
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, LAYER_A)
        self.assertIn(("Content-Length", str(len(LAYER_A))), headers)
        # The stored upstream's trailing slash is stripped before joining.
        fetch.assert_called_once_with(UPSTREAM_SLASH, DIGEST_A)
        # The layer is now cached.
        status, _h, cached = call("GET", f"/cache/layers/{DIGEST_A}")
        self.assertEqual(status, "200 OK")
        self.assertEqual(cached, LAYER_A)
        _s, _h, status_body = call_json("GET", "/cache/status")
        self.assertEqual(status_body["entries"], 1)
        self.assertEqual(status_body["used_bytes"], len(LAYER_A))

    def test_digest_is_normalized_to_lowercase(self) -> None:
        _s, created = register()
        with patch_fetch(LAYER_A) as fetch:
            status, _h, raw = call(
                "POST", f"/mirrors/{created['id']}/pull/{DIGEST_A.upper()}"
            )
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, LAYER_A)
        fetch.assert_called_once_with(UPSTREAM, DIGEST_A)

    def test_upstream_failure_returns_502_and_changes_nothing(self) -> None:
        _s, created = register()
        error = MirrorFetchError(
            "mirror_fetch_failed", "Upstream mirror could not be reached."
        )
        with patch_fetch(error=error):
            status, _h, body = call_json(
                "POST", f"/mirrors/{created['id']}/pull/{DIGEST_A}"
            )
        self.assertEqual(status, "502 Bad Gateway")
        self.assertEqual(body["error"], "mirror_fetch_failed")
        _s, _h, status_body = call_json("GET", "/cache/status")
        self.assertEqual(status_body["entries"], 0)
        self.assertEqual(status_body["used_bytes"], 0)
        self.assertEqual(status_body["misses"], 0)

    def test_digest_mismatch_returns_502_and_does_not_cache(self) -> None:
        _s, created = register()
        with patch_fetch(b"tampered bytes"):
            status, _h, body = call_json(
                "POST", f"/mirrors/{created['id']}/pull/{DIGEST_A}"
            )
        self.assertEqual(status, "502 Bad Gateway")
        self.assertEqual(body["error"], "mirror_digest_mismatch")
        _s, _h, status_body = call_json("GET", "/cache/status")
        self.assertEqual(status_body["entries"], 0)
        self.assertEqual(status_body["used_bytes"], 0)

    def test_quota_exceeded_returns_409_and_keeps_cache(self) -> None:
        _s, created = register()
        cache_store.configure(len(LAYER_A))
        put_cache_layer(LAYER_A)
        with patch_fetch(LAYER_B):
            status, _h, body = call_json(
                "POST", f"/mirrors/{created['id']}/pull/{DIGEST_B}"
            )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "cache_quota_exceeded")
        _s, _h, status_body = call_json("GET", "/cache/status")
        self.assertEqual(status_body["entries"], 1)
        self.assertEqual(status_body["used_bytes"], len(LAYER_A))
        self.assertEqual(status_body["quota"], len(LAYER_A))

    def test_unknown_mirror_returns_404_without_fetching(self) -> None:
        with patch_fetch(LAYER_A) as fetch:
            status, _h, body = call_json(
                "POST", f"/mirrors/missing/pull/{DIGEST_A}"
            )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "mirror_not_found")
        fetch.assert_not_called()

    def test_invalid_mirror_id_returns_400(self) -> None:
        for path in (
            f"/mirrors//pull/{DIGEST_A}",
            f"/mirrors/a/b/pull/{DIGEST_A}",
            "/mirrors/a/pull/",
        ):
            with patch_fetch(LAYER_A) as fetch:
                status, _h, body = call_json("POST", path)
            self.assertEqual(status, "400 Bad Request", path)
            self.assertEqual(body["error"], "invalid_request")
            fetch.assert_not_called()

    def test_invalid_digest_returns_400(self) -> None:
        _s, created = register()
        for digest in ("xyz", "g" * 64, "a" * 63, "a" * 65):
            with patch_fetch(LAYER_A) as fetch:
                status, _h, body = call_json(
                    "POST", f"/mirrors/{created['id']}/pull/{digest}"
                )
            self.assertEqual(status, "400 Bad Request", digest)
            self.assertEqual(body["error"], "invalid_request")
            fetch.assert_not_called()

    def test_query_parameters_return_400(self) -> None:
        _s, created = register()
        with patch_fetch(LAYER_A) as fetch:
            status, _h, body = call_json(
                "POST",
                f"/mirrors/{created['id']}/pull/{DIGEST_A}",
                query_string="x=1",
            )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        fetch.assert_not_called()

    def test_get_on_pull_path_returns_405_with_allow_header(self) -> None:
        _s, created = register()
        with patch_fetch(LAYER_A) as fetch:
            status, headers, body = call_json(
                "GET", f"/mirrors/{created['id']}/pull/{DIGEST_A}"
            )
        self.assertEqual(status, "405 Method Not Allowed")
        self.assertIn(("Allow", "POST"), headers)
        self.assertEqual(body["error"], "method_not_allowed")
        fetch.assert_not_called()

    def test_successful_pull_does_not_change_counters(self) -> None:
        # A miss-driven pull must populate the cache without recording a miss.
        _s, created = register()
        with patch_fetch(LAYER_A):
            status, _h, _raw = call(
                "POST", f"/mirrors/{created['id']}/pull/{DIGEST_A}"
            )
        self.assertEqual(status, "200 OK")
        _s, _h, status_body = call_json("GET", "/cache/status")
        self.assertEqual(status_body["hits"], 0)
        self.assertEqual(status_body["misses"], 0)


class UpstreamFetchTests(unittest.TestCase):
    def test_layer_url_strips_trailing_slash(self) -> None:
        from provenance_api.mirrors import _layer_url

        self.assertEqual(
            _layer_url("https://x.example.invalid/", DIGEST_A),
            f"https://x.example.invalid/layers/{DIGEST_A}",
        )
        self.assertEqual(
            _layer_url("https://x.example.invalid", DIGEST_A),
            f"https://x.example.invalid/layers/{DIGEST_A}",
        )


if __name__ == "__main__":
    unittest.main()
