from __future__ import annotations

import hashlib
import io
import json
import unittest
from unittest import mock

from provenance_api.app import application, cache_store, reset_state
from provenance_api.cache import DEFAULT_CACHE_QUOTA, CacheError
from provenance_api.__main__ import build_parser

LAYER_A = b"alpha-layer-bytes"
LAYER_B = b"beta-layer-bytes-larger"
DIGEST_A = hashlib.sha256(LAYER_A).hexdigest()
DIGEST_B = hashlib.sha256(LAYER_B).hexdigest()
DIGEST_C = "c" * 64

OCTET_HEADERS = {"CONTENT_TYPE": "application/octet-stream"}


class ExplodingStream:
    """A wsgi.input stand-in that fails the test if anything reads it."""

    def read(self, *_args: object, **_kwargs: object) -> bytes:
        raise AssertionError("request body must not be read")


def call(
    method: str,
    path: str,
    body: bytes = b"",
    *,
    headers: dict[str, str] | None = None,
    content_length: int | str | None = None,
    omit_content_length: bool = False,
    query_string: str | None = None,
    stream: object | None = None,
) -> tuple[str, list[tuple[str, str]], bytes]:
    environ: dict[str, object] = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "wsgi.input": stream if stream is not None else io.BytesIO(body),
    }
    if not omit_content_length:
        environ["CONTENT_LENGTH"] = (
            str(len(body)) if content_length is None else str(content_length)
        )
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


def put_layer(
    data: bytes, digest: str | None = None, **kwargs: object
) -> tuple[str, list[tuple[str, str]], bytes]:
    path = f"/cache/layers/{digest or hashlib.sha256(data).hexdigest()}"
    return call("POST", path, data, headers=OCTET_HEADERS, **kwargs)  # type: ignore[arg-type]


class LayerWriteTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def test_first_write_returns_201_with_compact_echo(self) -> None:
        status, headers, raw = put_layer(LAYER_A)
        self.assertEqual(status, "201 Created")
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )
        self.assertEqual(
            raw,
            json.dumps(
                {"digest": DIGEST_A, "size": len(LAYER_A), "entries": 1},
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n",
        )

    def test_resubmitting_same_bytes_returns_200_and_changes_nothing(self) -> None:
        put_layer(LAYER_A)
        status, _h, raw = put_layer(LAYER_A)
        self.assertEqual(status, "200 OK")
        body = json.loads(raw)
        self.assertEqual(body["entries"], 1)
        _s, _h, status_body = call_json("GET", "/cache/status")
        self.assertEqual(status_body["entries"], 1)
        self.assertEqual(status_body["used_bytes"], len(LAYER_A))

    def test_second_layer_increments_entries(self) -> None:
        put_layer(LAYER_A)
        status, _h, raw = put_layer(LAYER_B)
        self.assertEqual(status, "201 Created")
        body = json.loads(raw)
        self.assertEqual(body["entries"], 2)

    def test_digest_mismatch_returns_409_and_stores_nothing(self) -> None:
        status, _h, raw = put_layer(LAYER_A, digest=DIGEST_C)
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(json.loads(raw)["error"], "digest_mismatch")
        _s, _h, status_body = call_json("GET", "/cache/status")
        self.assertEqual(status_body["entries"], 0)
        self.assertEqual(status_body["used_bytes"], 0)

    def test_quota_exceeded_returns_409_and_keeps_cache(self) -> None:
        cache_store.configure(len(LAYER_A))
        status, _h, raw = put_layer(LAYER_B)
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(json.loads(raw)["error"], "cache_quota_exceeded")
        status, _h, raw = put_layer(LAYER_A)
        self.assertEqual(status, "201 Created")
        status, _h, raw = put_layer(LAYER_B)
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(json.loads(raw)["error"], "cache_quota_exceeded")
        _s, _h, status_body = call_json("GET", "/cache/status")
        self.assertEqual(status_body["entries"], 1)
        self.assertEqual(status_body["used_bytes"], len(LAYER_A))
        self.assertEqual(status_body["quota"], len(LAYER_A))

    def test_quota_exact_fit_is_accepted(self) -> None:
        cache_store.configure(len(LAYER_A))
        status, _h, _raw = put_layer(LAYER_A)
        self.assertEqual(status, "201 Created")

    def test_idempotent_repeat_ignores_quota_headroom(self) -> None:
        cache_store.configure(len(LAYER_A))
        put_layer(LAYER_A)
        status, _h, _raw = put_layer(LAYER_A)
        self.assertEqual(status, "200 OK")

    def test_conflicting_bytes_return_409_and_keep_original(self) -> None:
        # A real SHA-256 collision cannot be crafted, so force one at the
        # store boundary to prove the original entry is never overwritten.
        cache_store.put(DIGEST_A, LAYER_A)
        with mock.patch(
            "provenance_api.cache.hashlib.sha256",
            return_value=mock.Mock(hexdigest=lambda: DIGEST_A),
        ):
            with self.assertRaises(CacheError) as ctx:
                cache_store.put(DIGEST_A, LAYER_B)
        self.assertEqual(ctx.exception.code, "cache_conflict")
        self.assertEqual(cache_store.get(DIGEST_A), LAYER_A)

    def test_invalid_path_digest_returns_400_without_reading_body(self) -> None:
        for digest in ("abc", "g" * 64, "a" * 63, "a" * 65, "", "a" * 32 + "/" + "a" * 32):
            status, _h, raw = call(
                "POST",
                f"/cache/layers/{digest}",
                LAYER_A,
                headers=OCTET_HEADERS,
                stream=ExplodingStream(),
            )
            self.assertEqual(status, "400 Bad Request", digest)
            self.assertEqual(json.loads(raw)["error"], "invalid_request")

    def test_uppercase_path_digest_is_accepted_and_stored_lowercase(self) -> None:
        status, _h, raw = put_layer(LAYER_A, digest=DIGEST_A.upper())
        self.assertEqual(status, "201 Created")
        self.assertEqual(json.loads(raw)["digest"], DIGEST_A)

    def test_query_parameters_return_400_and_change_nothing(self) -> None:
        put_layer(LAYER_A)
        status, _h, raw = call(
            "POST",
            f"/cache/layers/{DIGEST_B}",
            LAYER_B,
            headers=OCTET_HEADERS,
            query_string="x=1",
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(json.loads(raw)["error"], "invalid_request")
        _s, _h, status_body = call_json("GET", "/cache/status")
        self.assertEqual(status_body["entries"], 1)

    def test_non_octet_stream_content_type_returns_400(self) -> None:
        for content_type in ("application/json", "text/plain", ""):
            headers = {"CONTENT_TYPE": content_type} if content_type else {}
            status, _h, raw = call(
                "POST", f"/cache/layers/{DIGEST_A}", LAYER_A, headers=headers
            )
            self.assertEqual(status, "400 Bad Request", content_type)
            self.assertEqual(json.loads(raw)["error"], "invalid_request")

    def test_missing_content_length_returns_400(self) -> None:
        status, _h, raw = call(
            "POST",
            f"/cache/layers/{DIGEST_A}",
            LAYER_A,
            headers=OCTET_HEADERS,
            omit_content_length=True,
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(json.loads(raw)["error"], "invalid_request")

    def test_malformed_content_length_returns_400(self) -> None:
        for content_length in ("abc", "-1", "1.5", ""):
            status, _h, raw = call(
                "POST",
                f"/cache/layers/{DIGEST_A}",
                LAYER_A,
                headers=OCTET_HEADERS,
                content_length=content_length,
            )
            self.assertEqual(status, "400 Bad Request", content_length)
            self.assertEqual(json.loads(raw)["error"], "invalid_request")

    def test_incomplete_body_returns_400(self) -> None:
        status, _h, raw = call(
            "POST",
            f"/cache/layers/{DIGEST_A}",
            LAYER_A,
            headers=OCTET_HEADERS,
            content_length=len(LAYER_A) + 5,
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(json.loads(raw)["error"], "invalid_request")
        _s, _h, status_body = call_json("GET", "/cache/status")
        self.assertEqual(status_body["entries"], 0)


class LayerReadTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def test_hit_returns_raw_bytes_with_accurate_length(self) -> None:
        put_layer(LAYER_A)
        status, headers, raw = call("GET", f"/cache/layers/{DIGEST_A}")
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, LAYER_A)
        self.assertIn(("Content-Type", "application/octet-stream"), headers)
        self.assertIn(("Content-Length", str(len(LAYER_A))), headers)

    def test_hit_increments_hit_counter(self) -> None:
        put_layer(LAYER_A)
        call("GET", f"/cache/layers/{DIGEST_A}")
        call("GET", f"/cache/layers/{DIGEST_A}")
        _s, _h, status_body = call_json("GET", "/cache/status")
        self.assertEqual(status_body["hits"], 2)
        self.assertEqual(status_body["misses"], 0)

    def test_miss_returns_404_and_increments_miss_counter(self) -> None:
        status, _h, raw = call("GET", f"/cache/layers/{DIGEST_C}")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(json.loads(raw)["error"], "cache_miss")
        _s, _h, status_body = call_json("GET", "/cache/status")
        self.assertEqual(status_body["misses"], 1)
        self.assertEqual(status_body["hits"], 0)

    def test_invalid_path_digest_returns_400_and_counts_nothing(self) -> None:
        status, _h, raw = call("GET", "/cache/layers/not-a-digest")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(json.loads(raw)["error"], "invalid_request")
        _s, _h, status_body = call_json("GET", "/cache/status")
        self.assertEqual(status_body["hits"], 0)
        self.assertEqual(status_body["misses"], 0)

    def test_query_parameters_return_400_and_count_nothing(self) -> None:
        put_layer(LAYER_A)
        status, _h, raw = call(
            "GET", f"/cache/layers/{DIGEST_A}", query_string="x=1"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(json.loads(raw)["error"], "invalid_request")
        _s, _h, status_body = call_json("GET", "/cache/status")
        self.assertEqual(status_body["hits"], 0)
        self.assertEqual(status_body["misses"], 0)


class CacheStatusTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def test_empty_cache_status(self) -> None:
        status, _h, raw = call("GET", "/cache/status")
        self.assertEqual(status, "200 OK")
        self.assertTrue(raw.endswith(b"\n"))
        self.assertEqual(
            json.loads(raw),
            {
                "entries": 0,
                "used_bytes": 0,
                "quota": DEFAULT_CACHE_QUOTA,
                "hits": 0,
                "misses": 0,
            },
        )

    def test_status_reports_usage_quota_and_counters(self) -> None:
        cache_store.configure(4096)
        put_layer(LAYER_A)
        call("GET", f"/cache/layers/{DIGEST_A}")
        call("GET", f"/cache/layers/{DIGEST_C}")
        _s, _h, body = call_json("GET", "/cache/status")
        self.assertEqual(
            body,
            {
                "entries": 1,
                "used_bytes": len(LAYER_A),
                "quota": 4096,
                "hits": 1,
                "misses": 1,
            },
        )

    def test_status_is_read_only(self) -> None:
        put_layer(LAYER_A)
        call("GET", "/cache/status")
        call("GET", "/cache/status")
        _s, _h, body = call_json("GET", "/cache/status")
        self.assertEqual(body["hits"], 0)
        self.assertEqual(body["misses"], 0)
        self.assertEqual(body["entries"], 1)

    def test_query_parameters_return_400(self) -> None:
        status, _h, raw = call("GET", "/cache/status", query_string="x=1")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(json.loads(raw)["error"], "invalid_request")


class CacheMethodTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def test_layer_path_rejects_other_methods_with_allow(self) -> None:
        put_layer(LAYER_A)
        for method in ("PUT", "DELETE", "PATCH"):
            status, headers, raw = call(method, f"/cache/layers/{DIGEST_A}")
            self.assertEqual(status, "405 Method Not Allowed", method)
            self.assertIn(("Allow", "GET, POST"), headers)
            self.assertEqual(json.loads(raw)["error"], "method_not_allowed")
        _s, _h, body = call_json("GET", "/cache/status")
        self.assertEqual(body["entries"], 1)
        self.assertEqual(body["hits"], 0)
        self.assertEqual(body["misses"], 0)

    def test_status_path_rejects_other_methods_with_allow(self) -> None:
        for method in ("POST", "PUT", "DELETE"):
            status, headers, raw = call(method, "/cache/status")
            self.assertEqual(status, "405 Method Not Allowed", method)
            self.assertIn(("Allow", "GET"), headers)
            self.assertEqual(json.loads(raw)["error"], "method_not_allowed")

    def test_reset_clears_entries_counters_and_quota(self) -> None:
        cache_store.configure(4096)
        put_layer(LAYER_A)
        call("GET", f"/cache/layers/{DIGEST_A}")
        call("GET", f"/cache/layers/{DIGEST_C}")
        reset_state()
        _s, _h, body = call_json("GET", "/cache/status")
        self.assertEqual(
            body,
            {
                "entries": 0,
                "used_bytes": 0,
                "quota": DEFAULT_CACHE_QUOTA,
                "hits": 0,
                "misses": 0,
            },
        )


class CacheQuotaArgumentTests(unittest.TestCase):
    def test_default_quota(self) -> None:
        args = build_parser().parse_args([])
        self.assertEqual(args.cache_quota, DEFAULT_CACHE_QUOTA)

    def test_valid_quota_is_parsed(self) -> None:
        args = build_parser().parse_args(["--cache-quota", "4096"])
        self.assertEqual(args.cache_quota, 4096)

    def test_invalid_quota_refuses_startup_with_usage(self) -> None:
        for value in ("0", "-1", "1.5", "abc", "0x10", "007", "", "+5"):
            parser = build_parser()
            with self.assertRaises(SystemExit) as ctx, mock.patch(
                "sys.stderr", new_callable=io.StringIO
            ) as stderr:
                parser.parse_args(["--cache-quota", value])
            self.assertEqual(ctx.exception.code, 2, value)
            self.assertIn("usage:", stderr.getvalue(), value)


if __name__ == "__main__":
    unittest.main()
