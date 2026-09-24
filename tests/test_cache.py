from __future__ import annotations

import hashlib
import io
import json
import unittest

from provenance_api.app import (
    application,
    cache_store,
    configure_cache_quota,
    reset_state,
)
from provenance_api.cache import DEFAULT_CACHE_QUOTA, CacheError

LAYER_A = b"hello image layer"
LAYER_B = b"another layer payload"
DIGEST_A = hashlib.sha256(LAYER_A).hexdigest()
DIGEST_B = hashlib.sha256(LAYER_B).hexdigest()
DIGEST_C = "c" * 64

OCTET_HEADERS = {"CONTENT_TYPE": "application/octet-stream"}


def call(
    method: str,
    path: str,
    body: bytes = b"",
    *,
    headers: dict[str, str] | None = None,
    content_length: int | str | None = None,
    omit_content_length: bool = False,
    query_string: str | None = None,
) -> tuple[str, list[tuple[str, str]], bytes]:
    environ: dict[str, object] = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "wsgi.input": io.BytesIO(body),
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


def put_layer(digest: str, data: bytes, **kwargs: object):
    return call(
        "POST", f"/cache/layers/{digest}", data, headers=OCTET_HEADERS, **kwargs
    )


def status_payload() -> dict[str, object]:
    status, _h, body = call_json("GET", "/cache/status")
    assert status == "200 OK"
    return body


class CacheWriteTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def test_put_returns_201_with_digest_size_and_entries(self) -> None:
        status, headers, raw = put_layer(DIGEST_A, LAYER_A)
        self.assertEqual(status, "201 Created")
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )
        self.assertTrue(raw.endswith(b"\n"))
        body = json.loads(raw)
        self.assertEqual(
            body, {"digest": DIGEST_A, "size": len(LAYER_A), "entries": 1}
        )

    def test_put_second_layer_increments_entries(self) -> None:
        put_layer(DIGEST_A, LAYER_A)
        status, _h, raw = put_layer(DIGEST_B, LAYER_B)
        self.assertEqual(status, "201 Created")
        body = json.loads(raw)
        self.assertEqual(body["entries"], 2)
        self.assertEqual(body["size"], len(LAYER_B))

    def test_uppercase_path_digest_is_normalized(self) -> None:
        status, _h, raw = put_layer(DIGEST_A.upper(), LAYER_A)
        self.assertEqual(status, "201 Created")
        self.assertEqual(json.loads(raw)["digest"], DIGEST_A)

    def test_idempotent_replay_returns_200_and_changes_nothing(self) -> None:
        put_layer(DIGEST_A, LAYER_A)
        status, _h, raw = put_layer(DIGEST_A, LAYER_A)
        self.assertEqual(status, "200 OK")
        body = json.loads(raw)
        self.assertEqual(
            body, {"digest": DIGEST_A, "size": len(LAYER_A), "entries": 1}
        )
        snapshot = status_payload()
        self.assertEqual(snapshot["entries"], 1)
        self.assertEqual(snapshot["used_bytes"], len(LAYER_A))

    def test_store_conflict_on_same_digest_different_bytes(self) -> None:
        # A real SHA-256 collision cannot be produced over HTTP (the digest
        # check rejects it first), so exercise the store conflict directly.
        cache_store.put(DIGEST_A, LAYER_A)
        with self.assertRaises(CacheError) as ctx:
            cache_store.put(DIGEST_A, LAYER_B)
        self.assertEqual(ctx.exception.code, "cache_conflict")
        self.assertEqual(cache_store.get(DIGEST_A), LAYER_A)

    def test_digest_mismatch_returns_409_and_writes_nothing(self) -> None:
        status, _h, body = call_json(
            "POST", f"/cache/layers/{DIGEST_C}", LAYER_A, headers=OCTET_HEADERS
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "digest_mismatch")
        snapshot = status_payload()
        self.assertEqual(snapshot["entries"], 0)
        self.assertEqual(snapshot["used_bytes"], 0)

    def test_invalid_path_digest_returns_400_without_reading_body(self) -> None:
        for bad in ("", "abc", "g" * 64, "a" * 63, "a" * 65):
            status, _h, body = call_json(
                "POST",
                f"/cache/layers/{bad}",
                LAYER_A,
                headers=OCTET_HEADERS,
                # A stream that would fail if read: declared length exceeds
                # the body, so any read attempt surfaces as a different error.
                content_length=len(LAYER_A) + 10,
            )
            self.assertEqual(status, "400 Bad Request", bad)
            self.assertEqual(body["error"], "invalid_request")
        self.assertEqual(status_payload()["entries"], 0)

    def test_wrong_content_type_returns_400(self) -> None:
        status, _h, body = call_json(
            "POST",
            f"/cache/layers/{DIGEST_A}",
            LAYER_A,
            headers={"CONTENT_TYPE": "application/json"},
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        self.assertEqual(status_payload()["entries"], 0)

    def test_content_type_accepts_case_variation(self) -> None:
        status, _h, _b = call(
            "POST",
            f"/cache/layers/{DIGEST_A}",
            LAYER_A,
            headers={"CONTENT_TYPE": "Application/Octet-Stream"},
        )
        self.assertEqual(status, "201 Created")

    def test_missing_content_length_returns_400(self) -> None:
        status, _h, body = call_json(
            "POST",
            f"/cache/layers/{DIGEST_A}",
            LAYER_A,
            headers=OCTET_HEADERS,
            omit_content_length=True,
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_invalid_content_length_returns_400(self) -> None:
        for bad in ("-1", "1.5", "abc", ""):
            status, _h, body = call_json(
                "POST",
                f"/cache/layers/{DIGEST_A}",
                LAYER_A,
                headers=OCTET_HEADERS,
                content_length=bad,
            )
            self.assertEqual(status, "400 Bad Request", bad)
            self.assertEqual(body["error"], "invalid_request")

    def test_incomplete_body_returns_400(self) -> None:
        status, _h, body = call_json(
            "POST",
            f"/cache/layers/{DIGEST_A}",
            LAYER_A,
            headers=OCTET_HEADERS,
            content_length=len(LAYER_A) + 5,
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        self.assertEqual(status_payload()["entries"], 0)

    def test_query_parameters_return_400_and_change_nothing(self) -> None:
        put_layer(DIGEST_A, LAYER_A)
        status, _h, body = call_json(
            "POST",
            f"/cache/layers/{DIGEST_B}",
            LAYER_B,
            headers=OCTET_HEADERS,
            query_string="x=1",
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        snapshot = status_payload()
        self.assertEqual(snapshot["entries"], 1)
        self.assertEqual(snapshot["used_bytes"], len(LAYER_A))

    def test_empty_layer_is_valid(self) -> None:
        digest = hashlib.sha256(b"").hexdigest()
        status, _h, raw = put_layer(digest, b"")
        self.assertEqual(status, "201 Created")
        self.assertEqual(json.loads(raw)["size"], 0)


class CacheQuotaTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def test_default_quota_is_reported(self) -> None:
        self.assertEqual(status_payload()["quota"], DEFAULT_CACHE_QUOTA)

    def test_write_exceeding_quota_returns_409_and_keeps_cache(self) -> None:
        configure_cache_quota(len(LAYER_A))
        put_layer(DIGEST_A, LAYER_A)
        status, _h, body = call_json(
            "POST", f"/cache/layers/{DIGEST_B}", LAYER_B, headers=OCTET_HEADERS
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "cache_quota_exceeded")
        snapshot = status_payload()
        self.assertEqual(snapshot["entries"], 1)
        self.assertEqual(snapshot["used_bytes"], len(LAYER_A))

    def test_write_exactly_at_quota_is_allowed(self) -> None:
        configure_cache_quota(len(LAYER_A))
        status, _h, _b = put_layer(DIGEST_A, LAYER_A)
        self.assertEqual(status, "201 Created")
        self.assertEqual(status_payload()["used_bytes"], len(LAYER_A))

    def test_idempotent_replay_is_not_blocked_by_quota(self) -> None:
        configure_cache_quota(len(LAYER_A))
        put_layer(DIGEST_A, LAYER_A)
        status, _h, _b = put_layer(DIGEST_A, LAYER_A)
        self.assertEqual(status, "200 OK")


class CacheReadTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def test_hit_returns_raw_bytes_with_accurate_length(self) -> None:
        put_layer(DIGEST_A, LAYER_A)
        status, headers, raw = call("GET", f"/cache/layers/{DIGEST_A}")
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, LAYER_A)
        self.assertIn(("Content-Type", "application/octet-stream"), headers)
        self.assertIn(("Content-Length", str(len(LAYER_A))), headers)

    def test_hit_increments_hit_counter(self) -> None:
        put_layer(DIGEST_A, LAYER_A)
        call("GET", f"/cache/layers/{DIGEST_A}")
        call("GET", f"/cache/layers/{DIGEST_A}")
        snapshot = status_payload()
        self.assertEqual(snapshot["hits"], 2)
        self.assertEqual(snapshot["misses"], 0)

    def test_miss_returns_404_cache_miss_and_counts(self) -> None:
        status, _h, body = call_json("GET", f"/cache/layers/{DIGEST_C}")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "cache_miss")
        snapshot = status_payload()
        self.assertEqual(snapshot["hits"], 0)
        self.assertEqual(snapshot["misses"], 1)

    def test_invalid_path_digest_returns_400_without_counting(self) -> None:
        status, _h, body = call_json("GET", "/cache/layers/not-a-digest")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        snapshot = status_payload()
        self.assertEqual(snapshot["hits"], 0)
        self.assertEqual(snapshot["misses"], 0)

    def test_query_parameters_return_400_without_counting(self) -> None:
        put_layer(DIGEST_A, LAYER_A)
        status, _h, body = call_json(
            "GET", f"/cache/layers/{DIGEST_A}", query_string="x=1"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        snapshot = status_payload()
        self.assertEqual(snapshot["hits"], 0)
        self.assertEqual(snapshot["misses"], 0)


class CacheStatusTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def test_status_reports_entries_usage_quota_and_counters(self) -> None:
        put_layer(DIGEST_A, LAYER_A)
        call("GET", f"/cache/layers/{DIGEST_A}")
        call("GET", f"/cache/layers/{DIGEST_C}")
        status, headers, raw = call("GET", "/cache/status")
        self.assertEqual(status, "200 OK")
        self.assertTrue(raw.endswith(b"\n"))
        body = json.loads(raw)
        self.assertEqual(
            body,
            {
                "entries": 1,
                "used_bytes": len(LAYER_A),
                "quota": DEFAULT_CACHE_QUOTA,
                "hits": 1,
                "misses": 1,
            },
        )

    def test_status_is_read_only(self) -> None:
        put_layer(DIGEST_A, LAYER_A)
        before = status_payload()
        status_payload()
        self.assertEqual(status_payload(), before)

    def test_status_rejects_query_parameters(self) -> None:
        status, _h, body = call_json(
            "GET", "/cache/status", query_string="verbose=1"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_status_rejects_other_methods(self) -> None:
        status, headers, body = call_json("POST", "/cache/status")
        self.assertEqual(status, "405 Method Not Allowed")
        self.assertEqual(body["error"], "method_not_allowed")
        self.assertIn(("Allow", "GET"), headers)


class CacheMethodTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def test_layer_path_rejects_other_methods_with_allow_header(self) -> None:
        for method in ("PUT", "DELETE", "PATCH"):
            status, headers, body = call_json(
                method, f"/cache/layers/{DIGEST_A}"
            )
            self.assertEqual(status, "405 Method Not Allowed", method)
            self.assertEqual(body["error"], "method_not_allowed")
            self.assertIn(("Allow", "GET, POST"), headers)
        snapshot = status_payload()
        self.assertEqual(snapshot["entries"], 0)
        self.assertEqual(snapshot["hits"], 0)
        self.assertEqual(snapshot["misses"], 0)


class CacheCliTests(unittest.TestCase):
    def test_invalid_quota_values_are_rejected(self) -> None:
        import subprocess
        import sys

        for bad in ("0", "-5", "1.5", "abc", "", " 10", "010"):
            result = subprocess.run(
                [sys.executable, "-m", "provenance_api", "--cache-quota", bad],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertNotEqual(result.returncode, 0, bad)
            self.assertIn("usage", result.stderr.lower(), bad)


if __name__ == "__main__":
    unittest.main()
