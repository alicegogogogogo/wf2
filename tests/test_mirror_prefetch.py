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

UPSTREAM = "https://registry.example.invalid"

POLICY = {
    "algorithm": "hmac-sha256",
    "keys": ["key-one", "key-two"],
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


def register_policy(
    mirror_id: str, policy: dict[str, object] | None = None
) -> None:
    status, _h, body = call_json(
        "POST",
        f"/mirrors/{mirror_id}/signature-policy",
        json.dumps(policy if policy is not None else POLICY).encode("utf-8"),
        headers={"CONTENT_TYPE": "application/json"},
    )
    assert status == "201 Created", (status, body)


def patch_fetch(side_effect=None):
    if side_effect is None:
        def must_not_fetch(upstream: str, digest: str) -> bytes:
            raise AssertionError(f"upstream must not be contacted for {digest}")

        side_effect = must_not_fetch
    return mock.patch(
        "provenance_api.app.fetch_upstream_layer", side_effect=side_effect
    )


def fake_fetch(upstream: str, digest: str) -> bytes:
    if digest == DIGEST_A:
        return LAYER_A
    if digest == DIGEST_B:
        return LAYER_B
    raise MirrorFetchError(
        "mirror_fetch_failed", "Upstream mirror could not be reached."
    )


def prefetch(mirror_id: str, digests: list[str], **kwargs: object):
    body = json.dumps({"digests": digests}).encode("utf-8")
    return call("POST", f"/mirrors/{mirror_id}/prefetch", body, **kwargs)


def prefetch_json(mirror_id: str, digests: list[str], **kwargs: object):
    body = json.dumps({"digests": digests}).encode("utf-8")
    return call_json("POST", f"/mirrors/{mirror_id}/prefetch", body, **kwargs)


def cache_status() -> dict[str, object]:
    _s, _h, body = call_json("GET", "/cache/status")
    return body


class PrefetchValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def test_invalid_bodies_return_400(self) -> None:
        mirror = register()
        duplicate = json.dumps({"digests": [DIGEST_A, DIGEST_A]}).encode()
        case_only_duplicate = json.dumps(
            {"digests": [DIGEST_A, DIGEST_A.upper()]}
        ).encode()
        bodies = [
            b"",
            b"{not json",
            b"[1,2]",
            b"42",
            b'"hello"',
            b"{}",
            json.dumps({"digests": [DIGEST_A], "extra": 1}).encode(),
            json.dumps({"digests": DIGEST_A}).encode(),
            json.dumps({"digests": []}).encode(),
            json.dumps({"digests": [1]}).encode(),
            json.dumps({"digests": [None]}).encode(),
            json.dumps({"digests": ["not-a-digest"]}).encode(),
            json.dumps({"digests": ["a" * 63]}).encode(),
            duplicate,
            case_only_duplicate,
        ]
        for body in bodies:
            status, _h, parsed = call_json(
                "POST",
                f"/mirrors/{mirror['id']}/prefetch",
                body,
                headers={"CONTENT_TYPE": "application/json"},
            )
            self.assertEqual(status, "400 Bad Request", body)
            self.assertEqual(parsed["error"], "invalid_request", body)
        self.assertEqual(cache_status()["entries"], 0)

    def test_query_parameters_return_400_and_write_nothing(self) -> None:
        mirror = register()
        with patch_fetch(fake_fetch) as fetch:
            status, _h, body = prefetch_json(
                str(mirror["id"]), [DIGEST_A], query_string="x=1"
            )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        fetch.assert_not_called()
        self.assertEqual(cache_status()["entries"], 0)

    def test_invalid_id_returns_400(self) -> None:
        register()
        for path in ("/mirrors//prefetch", "/mirrors/a/b/prefetch"):
            body = json.dumps({"digests": [DIGEST_A]}).encode()
            status, _h, parsed = call_json("POST", path, body)
            self.assertEqual(status, "400 Bad Request", path)
            self.assertEqual(parsed["error"], "invalid_request")

    def test_unknown_mirror_returns_404(self) -> None:
        status, _h, body = prefetch_json("missing", [DIGEST_A])
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "mirror_not_found")

    def test_non_post_method_returns_405_with_allow_header(self) -> None:
        mirror = register()
        for method in ("GET", "PUT", "DELETE"):
            status, headers, body = call_json(
                method, f"/mirrors/{mirror['id']}/prefetch"
            )
            self.assertEqual(status, "405 Method Not Allowed")
            self.assertIn(("Allow", "POST"), headers)
            self.assertEqual(body["error"], "method_not_allowed")


class PrefetchProcessingTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.mirror = register()
        self.mirror_id = str(self.mirror["id"])

    def test_miss_is_fetched_cached_and_compact_encoded(self) -> None:
        with patch_fetch(fake_fetch) as fetch:
            status, headers, raw = prefetch(self.mirror_id, [DIGEST_A])
        self.assertEqual(status, "200 OK")
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )
        expected = (
            b'{"id":"' + self.mirror_id.encode()
            + b'","results":[{"digest":"' + DIGEST_A.encode()
            + b'","status":"fetched","size":' + str(len(LAYER_A)).encode()
            + b"}]}\n"
        )
        self.assertEqual(raw, expected)
        fetch.assert_called_once_with(UPSTREAM, DIGEST_A)
        # The fetched layer is now in the cache.
        status, _h, cached = call("GET", f"/cache/layers/{DIGEST_A}")
        self.assertEqual(status, "200 OK")
        self.assertEqual(cached, LAYER_A)

    def test_hit_is_cached_without_upstream_contact(self) -> None:
        with patch_fetch(fake_fetch):
            prefetch(self.mirror_id, [DIGEST_A])
        with patch_fetch(fake_fetch) as fetch:
            status, _h, body = prefetch_json(self.mirror_id, [DIGEST_A])
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            body["results"],
            [{"digest": DIGEST_A, "status": "cached", "size": len(LAYER_A)}],
        )
        fetch.assert_not_called()

    def test_uppercase_digest_is_normalized_and_order_preserved(self) -> None:
        with patch_fetch(fake_fetch) as fetch:
            status, _h, body = prefetch_json(
                self.mirror_id, [DIGEST_B.upper(), DIGEST_A.upper()]
            )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["id"], self.mirror_id)
        self.assertEqual(
            [item["digest"] for item in body["results"]],
            [DIGEST_B, DIGEST_A],
        )
        self.assertEqual(
            [(item["status"], item["size"]) for item in body["results"]],
            [("fetched", len(LAYER_B)), ("fetched", len(LAYER_A))],
        )
        self.assertEqual(
            [call_args.args for call_args in fetch.call_args_list],
            [(UPSTREAM, DIGEST_B), (UPSTREAM, DIGEST_A)],
        )

    def test_mixed_success_and_failure_keeps_processing(self) -> None:
        missing = hashlib.sha256(b"never available").hexdigest()
        with patch_fetch(fake_fetch):
            status, _h, body = prefetch_json(
                self.mirror_id, [DIGEST_A, missing, DIGEST_B]
            )
        self.assertEqual(status, "200 OK")
        results = body["results"]
        self.assertEqual(results[0]["status"], "fetched")
        self.assertNotIn("error", results[0])
        self.assertEqual(
            results[1],
            {"digest": missing, "status": "failed", "size": 0,
             "error": "mirror_fetch_failed"},
        )
        self.assertEqual(results[2]["status"], "fetched")
        # The failed item was not cached but the successful ones were.
        status, _h, _raw = call("GET", f"/cache/layers/{missing}")
        self.assertEqual(status, "404 Not Found")
        status, _h, cached = call("GET", f"/cache/layers/{DIGEST_A}")
        self.assertEqual(status, "200 OK")
        self.assertEqual(cached, LAYER_A)

    def test_all_failed_still_returns_200(self) -> None:
        missing = hashlib.sha256(b"never available").hexdigest()
        with patch_fetch(fake_fetch):
            status, _h, body = prefetch_json(self.mirror_id, [missing])
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            body["results"],
            [{"digest": missing, "status": "failed", "size": 0,
              "error": "mirror_fetch_failed"}],
        )

    def test_digest_mismatch_fails_item_and_does_not_cache(self) -> None:
        def mismatch(upstream: str, digest: str) -> bytes:
            return b"tampered bytes"

        with patch_fetch(mismatch):
            status, _h, body = prefetch_json(self.mirror_id, [DIGEST_A])
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["results"][0]["status"], "failed")
        self.assertEqual(body["results"][0]["error"], "mirror_digest_mismatch")
        status, _h, _raw = call("GET", f"/cache/layers/{DIGEST_A}")
        self.assertEqual(status, "404 Not Found")

    def test_quota_failure_does_not_roll_back_earlier_items(self) -> None:
        cache_store.configure(len(LAYER_A))
        with patch_fetch(fake_fetch):
            status, _h, body = prefetch_json(
                self.mirror_id, [DIGEST_A, DIGEST_B]
            )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["results"][0]["status"], "fetched")
        self.assertEqual(body["results"][1]["status"], "failed")
        self.assertEqual(
            body["results"][1]["error"], "cache_quota_exceeded"
        )
        snapshot = cache_status()
        self.assertEqual(snapshot["entries"], 1)
        self.assertEqual(snapshot["used_bytes"], len(LAYER_A))

    def test_prefetch_does_not_change_hit_miss_counters(self) -> None:
        with patch_fetch(fake_fetch):
            prefetch_json(self.mirror_id, [DIGEST_A])
            prefetch_json(self.mirror_id, [DIGEST_A])
        snapshot = cache_status()
        self.assertEqual(snapshot["hits"], 0)
        self.assertEqual(snapshot["misses"], 0)

    def test_cached_and_fetched_mix_within_one_batch(self) -> None:
        with patch_fetch(fake_fetch):
            prefetch_json(self.mirror_id, [DIGEST_A])
        with patch_fetch(fake_fetch):
            status, _h, body = prefetch_json(
                self.mirror_id, [DIGEST_A, DIGEST_B]
            )
        self.assertEqual(
            [item["status"] for item in body["results"]],
            ["cached", "fetched"],
        )


class PrefetchSignatureTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        mirror = register()
        self.mirror_id = str(mirror["id"])
        register_policy(self.mirror_id)

    def test_same_headers_checked_against_every_digest(self) -> None:
        # The single X-Signed-Digest covers only A; B is uncovered even
        # though the very same headers carried A successfully.
        with patch_fetch(fake_fetch):
            status, _h, body = prefetch_json(
                self.mirror_id,
                [DIGEST_A, DIGEST_B],
                headers=signature_headers("key-one", DIGEST_A),
            )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["results"][0]["status"], "fetched")
        self.assertEqual(body["results"][1]["status"], "failed")
        self.assertEqual(body["results"][1]["error"], "digest_uncovered")
        status, _h, _raw = call("GET", f"/cache/layers/{DIGEST_B}")
        self.assertEqual(status, "404 Not Found")

    def test_cover_digest_false_allows_one_signed_digest_for_all(self) -> None:
        # A separate mirror with a non-covering policy: one signed digest
        # authorizes every pulled layer.
        reset_state()
        mirror = register()
        mirror_id = str(mirror["id"])
        register_policy(
            mirror_id,
            {
                "algorithm": "hmac-sha256",
                "keys": ["key-one"],
                "cover_digest": False,
            },
        )
        with patch_fetch(fake_fetch):
            status, _h, body = prefetch_json(
                mirror_id,
                [DIGEST_A, DIGEST_B],
                headers=signature_headers("key-one", DIGEST_B),
            )
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            [item["status"] for item in body["results"]],
            ["fetched", "fetched"],
        )

    def test_missing_headers_fail_every_item(self) -> None:
        with patch_fetch(fake_fetch):
            status, _h, body = prefetch_json(
                self.mirror_id, [DIGEST_A, DIGEST_B]
            )
        self.assertEqual(status, "200 OK")
        for item in body["results"]:
            self.assertEqual(item["status"], "failed")
            self.assertEqual(item["error"], "signature_missing")
        self.assertEqual(cache_status()["entries"], 0)

    def test_untrusted_key_fails_items(self) -> None:
        with patch_fetch(fake_fetch):
            status, _h, body = prefetch_json(
                self.mirror_id,
                [DIGEST_A],
                headers=signature_headers("stranger", DIGEST_A),
            )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["results"][0]["error"], "key_not_trusted")

    def test_invalid_header_value_is_item_invalid_request(self) -> None:
        headers = signature_headers("key-one", DIGEST_A)
        headers["HTTP_X_SIGNATURE"] = ""
        with patch_fetch(fake_fetch):
            status, _h, body = prefetch_json(
                self.mirror_id, [DIGEST_A], headers=headers
            )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["results"][0]["status"], "failed")
        self.assertEqual(body["results"][0]["error"], "invalid_request")

    def test_wrong_signature_fails_item(self) -> None:
        headers = signature_headers("key-one", DIGEST_A)
        headers["HTTP_X_SIGNATURE"] = sign(
            "hmac-sha256", "key-two", DIGEST_A
        )
        with patch_fetch(fake_fetch):
            status, _h, body = prefetch_json(
                self.mirror_id, [DIGEST_A], headers=headers
            )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["results"][0]["error"], "signature_invalid")

    def test_cached_hit_still_requires_signature(self) -> None:
        with patch_fetch(fake_fetch):
            prefetch_json(
                self.mirror_id, [DIGEST_A],
                headers=signature_headers("key-one", DIGEST_A),
            )
        with patch_fetch() as fetch:
            status, _h, body = prefetch_json(self.mirror_id, [DIGEST_A])
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["results"][0]["status"], "failed")
        self.assertEqual(body["results"][0]["error"], "signature_missing")
        fetch.assert_not_called()
        snapshot = cache_status()
        self.assertEqual(snapshot["hits"], 0)
        self.assertEqual(snapshot["misses"], 0)
        # A correctly signed batch reports the cached item.
        with patch_fetch() as fetch:
            status, _h, body = prefetch_json(
                self.mirror_id, [DIGEST_A],
                headers=signature_headers("key-one", DIGEST_A),
            )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["results"][0]["status"], "cached")
        fetch.assert_not_called()

    def test_signature_failure_does_not_block_later_items(self) -> None:
        # Headers cover B, so A fails uncovered while B succeeds; the
        # ordering proves later items keep running after a failure.
        with patch_fetch(fake_fetch):
            status, _h, body = prefetch_json(
                self.mirror_id,
                [DIGEST_A, DIGEST_B],
                headers=signature_headers("key-one", DIGEST_B),
            )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["results"][0]["error"], "digest_uncovered")
        self.assertEqual(body["results"][1]["status"], "fetched")


if __name__ == "__main__":
    unittest.main()
