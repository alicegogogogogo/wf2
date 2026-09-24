from __future__ import annotations

import hashlib
import io
import json
import unittest
from unittest import mock

from provenance_api import mirrors
from provenance_api.app import application, cache_store, mirror_store, reset_state

LAYER_A = b"mirror-layer-alpha"
LAYER_B = b"mirror-layer-beta-longer"
DIGEST_A = hashlib.sha256(LAYER_A).hexdigest()
DIGEST_B = hashlib.sha256(LAYER_B).hexdigest()
DIGEST_C = "c" * 64
UPSTREAM = "https://upstream.example.invalid/"

JSON_HEADERS = {"CONTENT_TYPE": "application/json"}


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
        "wsgi.input": io.BytesIO(body),
        "CONTENT_LENGTH": str(len(body)),
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
    method: str, path: str, body: object = None
) -> tuple[str, list[tuple[str, str]], dict[str, object]]:
    raw = b"" if body is None else json.dumps(body).encode("utf-8")
    status, headers, data = call(
        method, path, raw, headers=None if body is None else JSON_HEADERS
    )
    return status, headers, json.loads(data.decode("utf-8"))


def register(name: str = "m1", upstream: str = UPSTREAM) -> dict[str, object]:
    status, _h, body = call_json("POST", "/mirrors", {"name": name, "upstream": upstream})
    assert status == "201 Created", body
    return body


def cache_status() -> dict[str, object]:
    _s, _h, body = call_json("GET", "/cache/status")
    return body


def pull(mirror_id: str, digest: str = DIGEST_A) -> tuple[str, list[tuple[str, str]], bytes]:
    return call("POST", f"/mirrors/{mirror_id}/pull/{digest}")


class MirrorRegistrationTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def test_empty_list_is_legal_compact_json_with_newline(self) -> None:
        status, headers, raw = call("GET", "/mirrors")
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b'{"mirrors":[]}\n')
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )

    def test_registration_returns_201_with_id_name_upstream(self) -> None:
        status, headers, body = call_json(
            "POST", "/mirrors", {"name": "m1", "upstream": UPSTREAM}
        )
        self.assertEqual(status, "201 Created")
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )
        self.assertEqual(set(body), {"id", "name", "upstream"})
        self.assertTrue(isinstance(body["id"], str) and len(body["id"]) == 32)
        self.assertEqual(body["name"], "m1")
        self.assertEqual(body["upstream"], UPSTREAM)

    def test_item_echoes_the_same_three_fields(self) -> None:
        created = register()
        status, _h, body = call_json("GET", f"/mirrors/{created['id']}")
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, created)

    def test_list_follows_registration_order(self) -> None:
        first = register("first")
        second = register("second", "https://b.example.invalid")
        status, _h, body = call_json("GET", "/mirrors")
        self.assertEqual(status, "200 OK")
        self.assertEqual([m["id"] for m in body["mirrors"]], [first["id"], second["id"]])

    def test_duplicate_name_returns_409_and_keeps_original(self) -> None:
        original = register("dup", "https://original.example.invalid")
        status, _h, body = call_json(
            "POST",
            "/mirrors",
            {"name": "dup", "upstream": "https://replacement.example.invalid"},
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "duplicate_mirror")
        status, _h, body = call_json("GET", "/mirrors")
        self.assertEqual(len(body["mirrors"]), 1)
        self.assertEqual(body["mirrors"][0], original)

    def test_names_are_case_sensitive_distinct_strings(self) -> None:
        register("Name")
        status, _h, body = call_json(
            "POST", "/mirrors", {"name": "name", "upstream": "https://x/"}
        )
        self.assertEqual(status, "201 Created", body)

    def test_trailing_slash_is_preserved_in_echo(self) -> None:
        body = register("m", "https://host.example.invalid/base/")
        self.assertEqual(body["upstream"], "https://host.example.invalid/base/")


class MirrorRegistrationValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def _assert_invalid(self, raw: bytes, *, headers: dict[str, str] | None) -> None:
        status, _h, body = call("POST", "/mirrors", raw, headers=headers)
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(json.loads(body)["error"], "invalid_request")
        _s, _h, listing = call_json("GET", "/mirrors")
        self.assertEqual(listing["mirrors"], [])

    def test_empty_body_is_invalid(self) -> None:
        status, _h, body = call("POST", "/mirrors", b"")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(json.loads(body)["error"], "invalid_request")

    def test_bad_json_and_non_object_are_invalid(self) -> None:
        for raw in (b"{", b"\xff\xfe", b"[1,2]", b'"str"', b"12", b"null"):
            self._assert_invalid(raw, headers=JSON_HEADERS)

    def test_missing_fields_are_invalid(self) -> None:
        self._assert_invalid(b'{"name":"m"}', headers=JSON_HEADERS)
        self._assert_invalid(b'{"upstream":"https://x/"}', headers=JSON_HEADERS)
        self._assert_invalid(b"{}", headers=JSON_HEADERS)

    def test_unknown_fields_are_invalid(self) -> None:
        self._assert_invalid(
            b'{"name":"m","upstream":"https://x/","extra":1}',
            headers=JSON_HEADERS,
        )

    def test_wrong_types_and_empty_values_are_invalid(self) -> None:
        for raw in (
            b'{"name":"","upstream":"https://x/"}',
            b'{"name":null,"upstream":"https://x/"}',
            b'{"name":7,"upstream":"https://x/"}',
            b'{"name":["m"],"upstream":"https://x/"}',
            b'{"name":"m","upstream":""}',
            b'{"name":"m","upstream":null}',
            b'{"name":"m","upstream":443}',
        ):
            self._assert_invalid(raw, headers=JSON_HEADERS)

    def test_upstream_must_be_absolute_http_or_https(self) -> None:
        for raw in (
            b'{"name":"m","upstream":"ftp://host/layer"}',
            b'{"name":"m","upstream":"file:///etc/passwd"}',
            b'{"name":"m","upstream":"http:/host/path"}',
            b'{"name":"m","upstream":"//host/path"}',
            b'{"name":"m","upstream":"localhost:8000"}',
            b'{"name":"m","upstream":"/just/a/path"}',
        ):
            self._assert_invalid(raw, headers=JSON_HEADERS)

    def test_http_and_https_are_accepted(self) -> None:
        for upstream in (
            "http://host.example.invalid",
            "https://host.example.invalid/path",
        ):
            reset_state()
            status, _h, body = call_json(
                "POST", "/mirrors", {"name": "m", "upstream": upstream}
            )
            self.assertEqual(status, "201 Created", body)

    def test_query_parameters_return_400(self) -> None:
        for method in ("GET", "POST"):
            raw = b'{"name":"m","upstream":"https://x/"}'
            status, _h, body = call(
                method, "/mirrors", raw, headers=JSON_HEADERS, query_string="x=1"
            )
            self.assertEqual(status, "400 Bad Request", method)
            self.assertEqual(json.loads(body)["error"], "invalid_request")


class MirrorItemMethodTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.mirror = register()

    def test_unknown_id_returns_404(self) -> None:
        status, _h, body = call_json("GET", "/mirrors/does-not-exist")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "mirror_not_found")

    def test_empty_id_returns_400(self) -> None:
        status, _h, body = call("GET", "/mirrors/")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(json.loads(body)["error"], "invalid_request")

    def test_id_with_separator_returns_400(self) -> None:
        for raw_id in ("a/b", "a\\b", "a/b/c"):
            status, _h, body = call("GET", f"/mirrors/{raw_id}")
            self.assertEqual(status, "400 Bad Request", raw_id)
            self.assertEqual(json.loads(body)["error"], "invalid_request")

    def test_item_query_parameters_return_400(self) -> None:
        status, _h, body = call(
            "GET", f"/mirrors/{self.mirror['id']}", query_string="x=1"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(json.loads(body)["error"], "invalid_request")

    def test_collection_and_item_methods(self) -> None:
        for method in ("PUT", "DELETE", "PATCH"):
            status, headers, body = call(method, "/mirrors")
            self.assertEqual(status, "405 Method Not Allowed", method)
            self.assertIn(("Allow", "GET, POST"), headers)
            self.assertEqual(json.loads(body)["error"], "method_not_allowed")

            status, headers, body = call(method, f"/mirrors/{self.mirror['id']}")
            self.assertEqual(status, "405 Method Not Allowed", method)
            self.assertIn(("Allow", "GET"), headers)
            self.assertEqual(json.loads(body)["error"], "method_not_allowed")


class MirrorPullCacheTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.mirror = register()

    def test_cache_hit_returns_raw_bytes_without_fetching_or_counting(self) -> None:
        # Pre-populate the cache through the existing write endpoint.
        status, _h, _b = call(
            "POST",
            f"/cache/layers/{DIGEST_A}",
            LAYER_A,
            headers={"CONTENT_TYPE": "application/octet-stream"},
        )
        self.assertEqual(status, "201 Created")

        with mock.patch.object(mirrors, "fetch_layer") as fetch:
            status, headers, body = pull(self.mirror["id"])
        self.assertEqual(status, "200 OK")
        self.assertFalse(fetch.called)
        self.assertEqual(body, LAYER_A)
        self.assertIn(("Content-Type", "application/octet-stream"), headers)
        self.assertIn(("Content-Length", str(len(LAYER_A))), headers)

        status_after = cache_status()
        self.assertEqual(status_after["entries"], 1)
        self.assertEqual(status_after["hits"], 0)
        self.assertEqual(status_after["misses"], 0)

    def test_uppercase_digest_matches_lowercase_cache_entry(self) -> None:
        call(
            "POST",
            f"/cache/layers/{DIGEST_A}",
            LAYER_A,
            headers={"CONTENT_TYPE": "application/octet-stream"},
        )
        with mock.patch.object(mirrors, "fetch_layer") as fetch:
            status, _h, body = pull(self.mirror["id"], DIGEST_A.upper())
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, LAYER_A)
        self.assertFalse(fetch.called)

    def test_miss_fetches_verifies_caches_and_returns_bytes(self) -> None:
        with mock.patch.object(
            mirrors, "fetch_layer", return_value=LAYER_A
        ) as fetch:
            status, headers, body = pull(self.mirror["id"])
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, LAYER_A)
        self.assertIn(("Content-Length", str(len(LAYER_A))), headers)
        # Trailing slashes are stripped before /layers/<digest> is appended.
        self.assertEqual(
            fetch.call_args[0],
            ("https://upstream.example.invalid/", DIGEST_A),
        )

        status_after = cache_status()
        self.assertEqual(status_after["entries"], 1)
        self.assertEqual(status_after["used_bytes"], len(LAYER_A))
        self.assertEqual(status_after["hits"], 0)
        self.assertEqual(status_after["misses"], 0)

        # A second pull is served from the cache, without contacting upstream.
        with mock.patch.object(mirrors, "fetch_layer") as fetch:
            status, _h, body = pull(self.mirror["id"])
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, LAYER_A)
        self.assertFalse(fetch.called)
        self.assertEqual(cache_status()["entries"], 1)

    def test_digest_mismatch_returns_502_and_does_not_cache(self) -> None:
        with mock.patch.object(mirrors, "fetch_layer", return_value=b"tampered"):
            status, _h, body = pull(self.mirror["id"])
        self.assertEqual(status, "502 Bad Gateway")
        self.assertEqual(json.loads(body)["error"], "mirror_digest_mismatch")
        self.assertEqual(cache_status()["entries"], 0)
        self.assertEqual(cache_status()["used_bytes"], 0)

    def test_upstream_failure_returns_502_and_does_not_cache(self) -> None:
        error = mirrors.MirrorError("mirror_fetch_failed", "boom")
        with mock.patch.object(mirrors, "fetch_layer", side_effect=error):
            status, _h, body = pull(self.mirror["id"])
        self.assertEqual(status, "502 Bad Gateway")
        self.assertEqual(json.loads(body)["error"], "mirror_fetch_failed")
        self.assertEqual(cache_status()["entries"], 0)

    def test_quota_exceeded_returns_409_and_keeps_cache(self) -> None:
        cache_store.configure(1)
        with mock.patch.object(mirrors, "fetch_layer", return_value=LAYER_A):
            status, _h, body = pull(self.mirror["id"])
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(json.loads(body)["error"], "cache_quota_exceeded")
        self.assertEqual(cache_status()["entries"], 0)
        self.assertEqual(cache_status()["used_bytes"], 0)


class FetchLayerTests(unittest.TestCase):
    def _fake_response(self, status: int = 200, data: bytes = LAYER_A):
        response = mock.MagicMock()
        response.status = status
        response.getcode.return_value = status
        response.read.return_value = data
        response.__enter__.return_value = response
        response.__exit__.return_value = False
        return response

    def test_url_strips_trailing_slashes_before_appending_path(self) -> None:
        with mock.patch.object(
            mirrors.urllib.request, "urlopen", return_value=self._fake_response()
        ) as urlopen:
            data = mirrors.fetch_layer("https://host/x///", DIGEST_A)
        self.assertEqual(data, LAYER_A)
        request = urlopen.call_args[0][0]
        self.assertEqual(
            request.full_url, f"https://host/x/layers/{DIGEST_A}"
        )

    def test_non_200_answer_maps_to_mirror_fetch_failed(self) -> None:
        with mock.patch.object(
            mirrors.urllib.request,
            "urlopen",
            return_value=self._fake_response(status=404),
        ):
            with self.assertRaises(mirrors.MirrorError) as ctx:
                mirrors.fetch_layer(UPSTREAM, DIGEST_A)
        self.assertEqual(ctx.exception.code, "mirror_fetch_failed")

    def test_unreachable_upstream_maps_to_mirror_fetch_failed(self) -> None:
        import urllib.error

        for error in (
            OSError("connection refused"),
            urllib.error.URLError("name resolution failed"),
        ):
            with mock.patch.object(
                mirrors.urllib.request, "urlopen", side_effect=error
            ):
                with self.assertRaises(mirrors.MirrorError) as ctx:
                    mirrors.fetch_layer(UPSTREAM, DIGEST_A)
            self.assertEqual(ctx.exception.code, "mirror_fetch_failed")


class MirrorPullValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.mirror = register()

    def test_invalid_digest_returns_400(self) -> None:
        for digest in ("abc", "g" * 64, "a" * 63, "a" * 65, ""):
            status, _h, body = call(
                "POST", f"/mirrors/{self.mirror['id']}/pull/{digest}"
            )
            self.assertEqual(status, "400 Bad Request", digest)
            self.assertEqual(json.loads(body)["error"], "invalid_request")

    def test_missing_digest_segment_returns_400(self) -> None:
        status, _h, body = call("POST", f"/mirrors/{self.mirror['id']}/pull")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(json.loads(body)["error"], "invalid_request")

    def test_empty_or_separator_id_returns_400(self) -> None:
        for path in (
            f"/mirrors//pull/{DIGEST_A}",
            f"/mirrors/a/b/pull/{DIGEST_A}",
        ):
            status, _h, body = call("POST", path)
            self.assertEqual(status, "400 Bad Request", path)
            self.assertEqual(json.loads(body)["error"], "invalid_request")

    def test_query_parameters_return_400(self) -> None:
        status, _h, body = call(
            "POST",
            f"/mirrors/{self.mirror['id']}/pull/{DIGEST_A}",
            query_string="x=1",
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(json.loads(body)["error"], "invalid_request")

    def test_unknown_mirror_returns_404_without_fetching(self) -> None:
        with mock.patch.object(mirrors, "fetch_layer") as fetch:
            status, _h, body = pull("missing-id", DIGEST_C)
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(json.loads(body)["error"], "mirror_not_found")
        self.assertFalse(fetch.called)
        self.assertEqual(cache_status()["entries"], 0)

    def test_other_methods_return_405_with_allow_header(self) -> None:
        for method in ("GET", "PUT", "DELETE", "PATCH"):
            status, headers, body = call(
                method, f"/mirrors/{self.mirror['id']}/pull/{DIGEST_A}"
            )
            self.assertEqual(status, "405 Method Not Allowed", method)
            self.assertIn(("Allow", "POST"), headers)
            self.assertEqual(json.loads(body)["error"], "method_not_allowed")

    def test_failed_pulls_never_move_cache_counters(self) -> None:
        fetch_error = mirrors.MirrorError("mirror_fetch_failed", "x")
        with mock.patch.object(mirrors, "fetch_layer", side_effect=fetch_error):
            call("POST", f"/mirrors/{self.mirror['id']}/pull/{DIGEST_A}")
        with mock.patch.object(mirrors, "fetch_layer", return_value=b"bad"):
            call("POST", f"/mirrors/{self.mirror['id']}/pull/{DIGEST_A}")
        status_after = cache_status()
        self.assertEqual(status_after["entries"], 0)
        self.assertEqual(status_after["hits"], 0)
        self.assertEqual(status_after["misses"], 0)


if __name__ == "__main__":
    unittest.main()
