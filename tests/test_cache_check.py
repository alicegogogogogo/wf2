from __future__ import annotations

import hashlib
import io
import json
import unittest
from unittest import mock

from provenance_api.app import application, cache_store, reset_state
from provenance_api.cache import DEFAULT_CACHE_QUOTA

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


def check_layer(
    data: bytes, digest: str | None = None, **kwargs: object
) -> tuple[str, list[tuple[str, str]], bytes]:
    path = f"/cache/layers/{digest or hashlib.sha256(data).hexdigest()}/check"
    return call("POST", path, data, headers=OCTET_HEADERS, **kwargs)  # type: ignore[arg-type]


def cache_status() -> dict[str, object]:
    _s, _h, body = call_json("GET", "/cache/status")
    return body


class LayerCheckDecisionTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def test_writable_returns_compact_ordered_json_line(self) -> None:
        status, headers, raw = check_layer(LAYER_A)
        self.assertEqual(status, "200 OK")
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )
        self.assertEqual(
            raw,
            json.dumps(
                {"digest": DIGEST_A, "size": len(LAYER_A), "decision": "writable"},
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n",
        )
        self.assertEqual(list(json.loads(raw)), ["digest", "size", "decision"])

    def test_already_cached_when_same_bytes_are_cached(self) -> None:
        put_layer(LAYER_A)
        status, _h, raw = check_layer(LAYER_A)
        self.assertEqual(status, "200 OK")
        body = json.loads(raw)
        self.assertEqual(body["decision"], "already_cached")
        self.assertEqual(body["digest"], DIGEST_A)
        self.assertEqual(body["size"], len(LAYER_A))

    def test_cache_conflict_when_digest_is_cached_with_different_bytes(
        self,
    ) -> None:
        # A real SHA-256 collision cannot be crafted, so force one at the
        # store boundary to prove the conflict decision is reported.
        cache_store.put(DIGEST_A, LAYER_A)
        with mock.patch(
            "provenance_api.cache.hashlib.sha256",
            return_value=mock.Mock(hexdigest=lambda: DIGEST_A),
        ):
            self.assertEqual(cache_store.check(DIGEST_A, LAYER_B), "cache_conflict")
        self.assertEqual(cache_store.peek(DIGEST_A), LAYER_A)

    def test_cache_quota_exceeded_when_write_would_not_fit(self) -> None:
        cache_store.configure(len(LAYER_A))
        status, _h, raw = check_layer(LAYER_B)
        self.assertEqual(status, "200 OK")
        self.assertEqual(json.loads(raw)["decision"], "cache_quota_exceeded")
        put_layer(LAYER_A)
        status, _h, raw = check_layer(LAYER_B)
        self.assertEqual(status, "200 OK")
        self.assertEqual(json.loads(raw)["decision"], "cache_quota_exceeded")

    def test_quota_exact_fit_is_writable(self) -> None:
        cache_store.configure(len(LAYER_A))
        status, _h, raw = check_layer(LAYER_A)
        self.assertEqual(status, "200 OK")
        self.assertEqual(json.loads(raw)["decision"], "writable")

    def test_digest_mismatch_is_judged_on_submitted_bytes_only(self) -> None:
        status, _h, raw = check_layer(LAYER_A, digest=DIGEST_C)
        self.assertEqual(status, "200 OK")
        body = json.loads(raw)
        self.assertEqual(body["decision"], "digest_mismatch")
        self.assertEqual(body["digest"], DIGEST_C)
        self.assertEqual(body["size"], len(LAYER_A))

    def test_digest_mismatch_wins_over_quota(self) -> None:
        cache_store.configure(1)
        status, _h, raw = check_layer(LAYER_A, digest=DIGEST_C)
        self.assertEqual(status, "200 OK")
        self.assertEqual(json.loads(raw)["decision"], "digest_mismatch")

    def test_conflict_wins_over_quota(self) -> None:
        cache_store.configure(len(LAYER_A))
        cache_store.put(DIGEST_A, LAYER_A)
        cache_store.configure(0)
        with mock.patch(
            "provenance_api.cache.hashlib.sha256",
            return_value=mock.Mock(hexdigest=lambda: DIGEST_A),
        ):
            self.assertEqual(cache_store.check(DIGEST_A, LAYER_B), "cache_conflict")

    def test_already_cached_ignores_quota_headroom(self) -> None:
        cache_store.configure(len(LAYER_A))
        put_layer(LAYER_A)
        status, _h, raw = check_layer(LAYER_A)
        self.assertEqual(status, "200 OK")
        self.assertEqual(json.loads(raw)["decision"], "already_cached")

    def test_uppercase_path_digest_is_accepted_and_echoed_lowercase(self) -> None:
        status, _h, raw = check_layer(LAYER_A, digest=DIGEST_A.upper())
        self.assertEqual(status, "200 OK")
        body = json.loads(raw)
        self.assertEqual(body["digest"], DIGEST_A)
        self.assertEqual(body["decision"], "writable")


class LayerCheckSideEffectTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def test_check_stores_nothing_and_counts_nothing(self) -> None:
        check_layer(LAYER_A)
        check_layer(LAYER_A, digest=DIGEST_C)
        self.assertEqual(
            cache_status(),
            {
                "entries": 0,
                "used_bytes": 0,
                "quota": DEFAULT_CACHE_QUOTA,
                "hits": 0,
                "misses": 0,
            },
        )

    def test_check_leaves_entries_usage_and_counters_untouched(self) -> None:
        cache_store.configure(4096)
        put_layer(LAYER_A)
        call("GET", f"/cache/layers/{DIGEST_A}")
        call("GET", f"/cache/layers/{DIGEST_C}")
        before = cache_status()
        check_layer(LAYER_A)
        check_layer(LAYER_B)
        check_layer(LAYER_A, digest=DIGEST_C)
        self.assertEqual(cache_status(), before)

    def test_check_is_only_a_rehearsal_real_write_still_follows(self) -> None:
        status, _h, raw = check_layer(LAYER_A)
        self.assertEqual(json.loads(raw)["decision"], "writable")
        status, _h, _raw = put_layer(LAYER_A)
        self.assertEqual(status, "201 Created")
        status, _h, raw = check_layer(LAYER_A)
        self.assertEqual(json.loads(raw)["decision"], "already_cached")


class LayerCheckRejectionTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def test_invalid_path_digest_returns_400_without_reading_body(self) -> None:
        for digest in (
            "abc",
            "g" * 64,
            "a" * 63,
            "a" * 65,
            "",
            "a" * 32 + "/" + "a" * 32,
        ):
            status, _h, raw = call(
                "POST",
                f"/cache/layers/{digest}/check",
                LAYER_A,
                headers=OCTET_HEADERS,
                stream=ExplodingStream(),
            )
            self.assertEqual(status, "400 Bad Request", digest)
            self.assertEqual(json.loads(raw)["error"], "invalid_request")

    def test_query_parameters_return_400_without_reading_body(self) -> None:
        status, _h, raw = call(
            "POST",
            f"/cache/layers/{DIGEST_A}/check",
            LAYER_A,
            headers=OCTET_HEADERS,
            query_string="x=1",
            stream=ExplodingStream(),
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(json.loads(raw)["error"], "invalid_request")

    def test_non_octet_stream_content_type_returns_400(self) -> None:
        for content_type in ("application/json", "text/plain", ""):
            headers = {"CONTENT_TYPE": content_type} if content_type else {}
            status, _h, raw = call(
                "POST",
                f"/cache/layers/{DIGEST_A}/check",
                LAYER_A,
                headers=headers,
            )
            self.assertEqual(status, "400 Bad Request", content_type)
            self.assertEqual(json.loads(raw)["error"], "invalid_request")

    def test_missing_content_length_returns_400(self) -> None:
        status, _h, raw = call(
            "POST",
            f"/cache/layers/{DIGEST_A}/check",
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
                f"/cache/layers/{DIGEST_A}/check",
                LAYER_A,
                headers=OCTET_HEADERS,
                content_length=content_length,
            )
            self.assertEqual(status, "400 Bad Request", content_length)
            self.assertEqual(json.loads(raw)["error"], "invalid_request")

    def test_incomplete_body_returns_400(self) -> None:
        status, _h, raw = call(
            "POST",
            f"/cache/layers/{DIGEST_A}/check",
            LAYER_A,
            headers=OCTET_HEADERS,
            content_length=len(LAYER_A) + 5,
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(json.loads(raw)["error"], "invalid_request")
        self.assertEqual(cache_status()["entries"], 0)

    def test_non_post_methods_return_405_with_allow_post(self) -> None:
        for method in ("GET", "PUT", "PATCH", "DELETE"):
            status, headers, raw = call(
                method, f"/cache/layers/{DIGEST_A}/check"
            )
            self.assertEqual(status, "405 Method Not Allowed", method)
            self.assertIn(("Allow", "POST"), headers)
            self.assertEqual(json.loads(raw)["error"], "method_not_allowed")


if __name__ == "__main__":
    unittest.main()
