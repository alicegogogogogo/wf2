from __future__ import annotations

import hashlib
import hmac
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

POLICY = {
    "algorithm": "hmac-sha256",
    "keys": ["key-one"],
    "cover_digest": True,
}


def sign(algorithm: str, key_id: str, signed_digest: str) -> str:
    digestmod = {
        "hmac-sha256": hashlib.sha256,
        "hmac-sha512": hashlib.sha512,
    }[algorithm]
    return hmac.new(
        key_id.encode("utf-8"),
        signed_digest.lower().encode("ascii"),
        digestmod,
    ).hexdigest()


def signature_headers(
    key_id: str = "key-one",
    signed_digest: str = DIGEST_A,
    *,
    algorithm: str = "hmac-sha256",
) -> dict[str, str]:
    return {
        "HTTP_X_KEY_ID": key_id,
        "HTTP_X_SIGNED_DIGEST": signed_digest,
        "HTTP_X_SIGNATURE": sign(algorithm, key_id, signed_digest),
    }


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


def register(name: str = "primary") -> dict[str, object]:
    status, _h, body = call_json(
        "POST",
        "/mirrors",
        json.dumps({"name": name, "upstream": UPSTREAM}).encode("utf-8"),
        headers={"CONTENT_TYPE": "application/json"},
    )
    assert status == "201 Created", (status, body)
    return body


def register_policy(mirror_id: str, policy: dict[str, object] | None = None) -> None:
    status, _h, body = call_json(
        "POST",
        f"/mirrors/{mirror_id}/signature-policy",
        json.dumps(policy if policy is not None else POLICY).encode("utf-8"),
        headers={"CONTENT_TYPE": "application/json"},
    )
    assert status == "201 Created", (status, body)


def prefetch(
    mirror_id: str,
    digests: list[str] | object,
    *,
    raw_body: bytes | None = None,
    headers: dict[str, str] | None = None,
    query_string: str | None = None,
):
    body = (
        raw_body
        if raw_body is not None
        else json.dumps({"digests": digests}).encode("utf-8")
    )
    return call_json(
        "POST",
        f"/mirrors/{mirror_id}/prefetch",
        body,
        headers=headers,
        query_string=query_string,
    )


def prefetch_raw(
    mirror_id: str,
    digests: list[str],
    *,
    headers: dict[str, str] | None = None,
):
    body = json.dumps({"digests": digests}).encode("utf-8")
    return call(
        "POST",
        f"/mirrors/{mirror_id}/prefetch",
        body,
        headers=headers,
    )


def layered_fetch():
    """Fetch A and B from "upstream"; C fails like a non-200 upstream."""

    def _fetch(upstream: str, digest: str) -> bytes:
        if digest == DIGEST_A:
            return LAYER_A
        if digest == DIGEST_B:
            return LAYER_B
        raise MirrorFetchError(
            "mirror_fetch_failed", "Upstream mirror did not return the layer."
        )

    return mock.patch(
        "provenance_api.app.fetch_upstream_layer", side_effect=_fetch
    )


def cache_status() -> dict[str, object]:
    _s, _h, body = call_json("GET", "/cache/status")
    return body


class MirrorPrefetchTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def test_mixed_batch_reports_cached_fetched_failed_in_order(self) -> None:
        mirror = register()
        mirror_id = str(mirror["id"])
        # Seed A directly into the cache so the first item is a hit.
        status, _h, _raw = call(
            "POST",
            f"/cache/layers/{DIGEST_A}",
            LAYER_A,
            headers={"CONTENT_TYPE": "application/octet-stream"},
        )
        self.assertEqual(status, "201 Created")

        with layered_fetch() as fetch:
            status, headers, raw = prefetch_raw(mirror_id, [DIGEST_A, DIGEST_B, DIGEST_C])

        self.assertEqual(status, "200 OK")
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )
        body = json.loads(raw)
        self.assertEqual(
            body,
            {
                "id": mirror_id,
                "results": [
                    {"digest": DIGEST_A, "status": "cached", "size": len(LAYER_A)},
                    {"digest": DIGEST_B, "status": "fetched", "size": len(LAYER_B)},
                    {"digest": DIGEST_C, "status": "failed",
                     "error": "mirror_fetch_failed"},
                ],
            },
        )
        # Compact one-line UTF-8 JSON ending in exactly one newline, with
        # the fixed top-level and per-item key order.
        expected = (
            b'{"id":"' + mirror_id.encode("ascii") + b'","results":['
            b'{"digest":"' + DIGEST_A.encode("ascii") + b'","status":"cached",'
            b'"size":' + str(len(LAYER_A)).encode("ascii") + b'},'
            b'{"digest":"' + DIGEST_B.encode("ascii") + b'","status":"fetched",'
            b'"size":' + str(len(LAYER_B)).encode("ascii") + b'},'
            b'{"digest":"' + DIGEST_C.encode("ascii") + b'","status":"failed",'
            b'"error":"mirror_fetch_failed"}]}'
            b"\n"
        )
        self.assertEqual(raw, expected)
        # Only A skipped the upstream (cached); B was fetched and C was
        # attempted before the upstream raised.
        fetch.assert_has_calls(
            [
                mock.call(UPSTREAM, DIGEST_B),
                mock.call(UPSTREAM, DIGEST_C),
            ],
            any_order=False,
        )
        self.assertEqual(fetch.call_count, 2)

    def test_all_fetched_then_all_cached_without_upstream_contact(self) -> None:
        mirror_id = str(register()["id"])
        with layered_fetch():
            status, _h, body = prefetch(mirror_id, [DIGEST_B, DIGEST_A])
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            [item["status"] for item in body["results"]], ["fetched", "fetched"]
        )
        with layered_fetch() as fetch:
            status, _h, body = prefetch(mirror_id, [DIGEST_A, DIGEST_B])
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            [item["status"] for item in body["results"]], ["cached", "cached"]
        )
        self.assertEqual(
            [item["size"] for item in body["results"]],
            [len(LAYER_A), len(LAYER_B)],
        )
        fetch.assert_not_called()

    def test_digest_mismatch_fails_item_but_others_continue(self) -> None:
        mirror_id = str(register()["id"])

        def _fetch(upstream: str, digest: str) -> bytes:
            if digest == DIGEST_C:
                # Upstream hands back bytes that do not hash to C.
                return b"tampered bytes"
            return LAYER_A

        with mock.patch(
            "provenance_api.app.fetch_upstream_layer", side_effect=_fetch
        ):
            status, _h, body = prefetch(mirror_id, [DIGEST_C, DIGEST_A])
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["results"][0]["status"], "failed")
        self.assertEqual(
            body["results"][0]["error"], "mirror_digest_mismatch"
        )
        self.assertNotIn("size", body["results"][0])
        self.assertEqual(body["results"][1]["status"], "fetched")
        # The mismatched bytes never entered the cache; A did.
        snapshot = cache_status()
        self.assertEqual(snapshot["entries"], 1)

    def test_quota_failure_is_per_item_without_rollback(self) -> None:
        mirror_id = str(register()["id"])
        cache_store.configure(len(LAYER_A))
        with layered_fetch():
            # A fills the cache; B is refused but A stays written.
            status, _h, body = prefetch(mirror_id, [DIGEST_A, DIGEST_B])
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            [item["status"] for item in body["results"]],
            ["fetched", "failed"],
        )
        self.assertEqual(body["results"][1]["error"], "cache_quota_exceeded")
        self.assertEqual(cache_status()["entries"], 1)
        self.assertEqual(cache_status()["used_bytes"], len(LAYER_A))

    def test_failure_does_not_roll_back_later_success(self) -> None:
        mirror_id = str(register()["id"])
        with layered_fetch():
            status, _h, body = prefetch(
                mirror_id, [DIGEST_A, DIGEST_C, DIGEST_B]
            )
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            [item["status"] for item in body["results"]],
            ["fetched", "failed", "fetched"],
        )
        self.assertEqual(cache_status()["entries"], 2)

    def test_prefetch_does_not_change_hit_miss_counters(self) -> None:
        mirror_id = str(register()["id"])
        with layered_fetch():
            prefetch(mirror_id, [DIGEST_A, DIGEST_C])
        snapshot = cache_status()
        self.assertEqual(snapshot["hits"], 0)
        self.assertEqual(snapshot["misses"], 0)
        with layered_fetch():
            prefetch(mirror_id, [DIGEST_A])
        snapshot = cache_status()
        self.assertEqual(snapshot["hits"], 0)
        self.assertEqual(snapshot["misses"], 0)

    def test_digests_are_normalized_to_lowercase(self) -> None:
        mirror_id = str(register()["id"])
        with layered_fetch():
            status, _h, body = prefetch(mirror_id, [DIGEST_A.upper()])
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["results"][0]["digest"], DIGEST_A)
        self.assertEqual(body["results"][0]["status"], "fetched")

    def test_unknown_fields_and_bad_bodies_return_400(self) -> None:
        mirror_id = str(register()["id"])
        bad_payloads: list[bytes] = [
            b"",
            b"{not json",
            b"[1,2,3]",
            b'"a string"',
            b"42",
            b"null",
            b"{}",
            b'{"digests":"' + DIGEST_A.encode() + b'"}',
            b'{"digests":[]}',
            b'{"digests":["' + b"a" * 63 + b'"]}',
            b'{"digests":["z" * 64]}',
            b'{"digests":[123]}',
            b'{"digests":[null]}',
            b'{"digests":[' + DIGEST_A.encode() + b"]}",  # unquoted element
            b'{"digests":["' + DIGEST_A.encode() + b'","'
            + DIGEST_A.encode() + b'"]}',
            b'{"digests":["' + DIGEST_A.encode() + b'","'
            + DIGEST_A.upper().encode() + b'"]}',
            b'{"digests":["' + DIGEST_A.encode() + b'"],"extra":1}',
        ]
        for raw in bad_payloads:
            status, _h, body = prefetch(
                mirror_id, None, raw_body=raw,
                headers={"CONTENT_TYPE": "application/json"},
            )
            self.assertEqual(status, "400 Bad Request", raw)
            self.assertEqual(body["error"], "invalid_request", raw)
        self.assertEqual(cache_status()["entries"], 0)

    def test_query_parameters_return_400_and_write_nothing(self) -> None:
        mirror_id = str(register()["id"])
        with layered_fetch() as fetch:
            status, _h, body = prefetch(
                mirror_id, [DIGEST_A], query_string="x=1"
            )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        fetch.assert_not_called()
        self.assertEqual(cache_status()["entries"], 0)

    def test_invalid_id_returns_400_and_unknown_mirror_returns_404(self) -> None:
        for path in ("/mirrors//prefetch", "/mirrors/a/b/prefetch"):
            status, _h, body = call_json(
                "POST",
                path,
                b'{"digests":["' + DIGEST_A.encode() + b'"]}',
                headers={"CONTENT_TYPE": "application/json"},
            )
            self.assertEqual(status, "400 Bad Request", path)
            self.assertEqual(body["error"], "invalid_request")
        status, _h, body = call_json(
            "POST",
            "/mirrors/missing/prefetch",
            b'{"digests":["' + DIGEST_A.encode() + b'"]}',
            headers={"CONTENT_TYPE": "application/json"},
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "mirror_not_found")

    def test_non_post_returns_405_with_allow_header(self) -> None:
        mirror_id = str(register()["id"])
        for method in ("GET", "PUT", "DELETE", "PATCH"):
            status, headers, body = call_json(method, f"/mirrors/{mirror_id}/prefetch")
            self.assertEqual(status, "405 Method Not Allowed", method)
            self.assertIn(("Allow", "POST"), headers)
            self.assertEqual(body["error"], "method_not_allowed")

    def test_without_policy_signature_headers_are_ignored(self) -> None:
        mirror_id = str(register()["id"])
        with layered_fetch():
            status, _h, body = prefetch(
                mirror_id,
                [DIGEST_A],
                headers={
                    "HTTP_X_KEY_ID": "anything",
                    "HTTP_X_SIGNED_DIGEST": "not-a-digest",
                    "HTTP_X_SIGNATURE": "junk",
                },
            )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["results"][0]["status"], "fetched")


class MirrorPrefetchSignatureTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.mirror_id = str(register()["id"])
        register_policy(self.mirror_id)

    def test_missing_headers_fail_every_item(self) -> None:
        with layered_fetch():
            status, _h, body = prefetch(
                self.mirror_id, [DIGEST_A, DIGEST_B]
            )
        self.assertEqual(status, "200 OK")
        for item in body["results"]:
            self.assertEqual(item["status"], "failed")
            self.assertEqual(item["error"], "signature_missing")
        self.assertEqual(cache_status()["entries"], 0)

    def test_same_headers_checked_against_each_pulled_digest(self) -> None:
        # cover_digest is true: headers covering A pass A but fail B with
        # digest_uncovered, even though the same headers are reused.
        with layered_fetch():
            status, _h, body = prefetch(
                self.mirror_id,
                [DIGEST_A, DIGEST_B],
                headers=signature_headers("key-one", DIGEST_A),
            )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["results"][0]["status"], "fetched")
        self.assertEqual(body["results"][1]["status"], "failed")
        self.assertEqual(body["results"][1]["error"], "digest_uncovered")
        # Only A passed the gate and was cached.
        self.assertEqual(cache_status()["entries"], 1)

    def test_cover_digest_false_reuses_headers_for_all_digests(self) -> None:
        mirror_id = str(register("no-cover")["id"])
        register_policy(
            mirror_id,
            {
                "algorithm": "hmac-sha256",
                "keys": ["key-one"],
                "cover_digest": False,
            },
        )
        with layered_fetch():
            status, _h, body = prefetch(
                mirror_id,
                [DIGEST_A, DIGEST_B],
                headers=signature_headers("key-one", DIGEST_A),
            )
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            [item["status"] for item in body["results"]],
            ["fetched", "fetched"],
        )

    def test_untrusted_key_and_bad_signature_are_reported_per_item(self) -> None:
        with layered_fetch():
            status, _h, body = prefetch(
                self.mirror_id,
                [DIGEST_A],
                headers=signature_headers("stranger", DIGEST_A),
            )
        self.assertEqual(body["results"][0]["error"], "key_not_trusted")

        headers = signature_headers("key-one", DIGEST_A)
        headers["HTTP_X_SIGNATURE"] = sign(
            "hmac-sha256", "key-one", DIGEST_B
        )
        with layered_fetch():
            status, _h, body = prefetch(
                self.mirror_id, [DIGEST_A], headers=headers
            )
        self.assertEqual(body["results"][0]["error"], "signature_invalid")
        self.assertEqual(cache_status()["entries"], 0)

    def test_invalid_header_value_is_invalid_request_per_item(self) -> None:
        headers = signature_headers("key-one", DIGEST_A)
        headers["HTTP_X_KEY_ID"] = ""
        with layered_fetch():
            status, _h, body = prefetch(
                self.mirror_id, [DIGEST_A], headers=headers
            )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["results"][0]["status"], "failed")
        self.assertEqual(body["results"][0]["error"], "invalid_request")
        self.assertEqual(cache_status()["entries"], 0)

    def test_cached_item_still_requires_signature(self) -> None:
        # Prime the cache through a valid signed single pull.
        with layered_fetch():
            status, _h, _raw = call(
                "POST",
                f"/mirrors/{self.mirror_id}/pull/{DIGEST_A}",
                headers=signature_headers(),
            )
        self.assertEqual(status, "200 OK")
        # A batch without signature headers fails the cached item too and
        # never contacts the upstream.
        with layered_fetch() as fetch:
            status, _h, body = prefetch(self.mirror_id, [DIGEST_A])
        self.assertEqual(body["results"][0]["error"], "signature_missing")
        fetch.assert_not_called()
        # The same cached item is reported as a hit with valid headers.
        with layered_fetch() as fetch:
            status, _h, body = prefetch(
                self.mirror_id, [DIGEST_A], headers=signature_headers()
            )
        self.assertEqual(body["results"][0]["status"], "cached")
        fetch.assert_not_called()

    def test_all_failed_batch_still_returns_200(self) -> None:
        with layered_fetch():
            status, _h, body = prefetch(
                self.mirror_id, [DIGEST_A, DIGEST_B]
            )
        self.assertEqual(status, "200 OK")
        self.assertTrue(
            all(item["status"] == "failed" for item in body["results"])
        )


if __name__ == "__main__":
    unittest.main()
