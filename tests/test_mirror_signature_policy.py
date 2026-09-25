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
) -> tuple[str, dict[str, object]]:
    status, _h, body = call_json(
        "POST",
        f"/mirrors/{mirror_id}/signature-policy",
        json.dumps(policy if policy is not None else POLICY).encode("utf-8"),
        headers={"CONTENT_TYPE": "application/json"},
    )
    return status, body


def patch_fetch(data: bytes | None = None, error: MirrorFetchError | None = None):
    if error is not None:
        return mock.patch(
            "provenance_api.app.fetch_upstream_layer", side_effect=error
        )
    return mock.patch(
        "provenance_api.app.fetch_upstream_layer", return_value=data
    )


def cache_status() -> dict[str, object]:
    _s, _h, body = call_json("GET", "/cache/status")
    return body


class MirrorPolicyRegistrationTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def test_first_registration_returns_201_with_echo(self) -> None:
        mirror = register()
        status, headers, raw = call(
            "POST",
            f"/mirrors/{mirror['id']}/signature-policy",
            json.dumps(POLICY).encode("utf-8"),
            headers={"CONTENT_TYPE": "application/json"},
        )
        self.assertEqual(status, "201 Created")
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )
        body = json.loads(raw)
        self.assertEqual(
            body,
            {
                "id": mirror["id"],
                "algorithm": "hmac-sha256",
                "keys": ["key-one", "key-two"],
                "cover_digest": True,
            },
        )
        self.assertEqual(
            raw,
            json.dumps(body, separators=(",", ":")).encode("utf-8") + b"\n",
        )

    def test_identical_repeat_returns_200(self) -> None:
        mirror = register()
        status, _ = register_policy(str(mirror["id"]))
        self.assertEqual(status, "201 Created")
        status, body = register_policy(str(mirror["id"]))
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["id"], mirror["id"])

    def test_different_policy_returns_409_and_keeps_original(self) -> None:
        mirror = register()
        register_policy(str(mirror["id"]))
        changed = dict(POLICY, keys=["other-key"])
        status, body = register_policy(str(mirror["id"]), changed)
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "mirror_policy_conflict")
        _s, _h, current = call_json(
            "GET", f"/mirrors/{mirror['id']}/signature-policy"
        )
        self.assertEqual(current["keys"], ["key-one", "key-two"])

    def test_get_returns_registered_policy(self) -> None:
        mirror = register()
        register_policy(str(mirror["id"]))
        status, _h, body = call_json(
            "GET", f"/mirrors/{mirror['id']}/signature-policy"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            body,
            {
                "id": mirror["id"],
                "algorithm": "hmac-sha256",
                "keys": ["key-one", "key-two"],
                "cover_digest": True,
            },
        )

    def test_get_without_policy_returns_404(self) -> None:
        mirror = register()
        status, _h, body = call_json(
            "GET", f"/mirrors/{mirror['id']}/signature-policy"
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "mirror_policy_not_found")

    def test_unknown_mirror_returns_404(self) -> None:
        status, body = register_policy("missing")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "mirror_not_found")
        status, _h, body = call_json(
            "GET", "/mirrors/missing/signature-policy"
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "mirror_not_found")

    def test_field_errors_return_400_and_leave_no_policy(self) -> None:
        mirror = register()
        payloads = [
            b"{}",
            b'{"algorithm":"hmac-sha256","keys":["k"]}',
            b'{"algorithm":"hmac-sha256","cover_digest":true}',
            b'{"keys":["k"],"cover_digest":true}',
            b'{"algorithm":"hmac-sha256","keys":["k"],"cover_digest":true,"x":1}',
            b'{"algorithm":"HMAC-SHA256","keys":["k"],"cover_digest":true}',
            b'{"algorithm":"hmac-sha1","keys":["k"],"cover_digest":true}',
            b'{"algorithm":1,"keys":["k"],"cover_digest":true}',
            b'{"algorithm":"hmac-sha256","keys":"k","cover_digest":true}',
            b'{"algorithm":"hmac-sha256","keys":[],"cover_digest":true}',
            b'{"algorithm":"hmac-sha256","keys":[""],"cover_digest":true}',
            b'{"algorithm":"hmac-sha256","keys":[1],"cover_digest":true}',
            b'{"algorithm":"hmac-sha256","keys":["k","k"],"cover_digest":true}',
            b'{"algorithm":"hmac-sha256","keys":["k"],"cover_digest":"yes"}',
            b'{"algorithm":"hmac-sha256","keys":["k"],"cover_digest":1}',
            b"[1,2]",
            b"42",
        ]
        for payload in payloads:
            status, _h, body = call_json(
                "POST",
                f"/mirrors/{mirror['id']}/signature-policy",
                payload,
                headers={"CONTENT_TYPE": "application/json"},
            )
            self.assertEqual(status, "400 Bad Request", payload)
            self.assertEqual(body["error"], "invalid_request")
        status, _h, body = call_json(
            "GET", f"/mirrors/{mirror['id']}/signature-policy"
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "mirror_policy_not_found")

    def test_empty_body_and_bad_json_return_400(self) -> None:
        mirror = register()
        status, _h, body = call_json(
            "POST", f"/mirrors/{mirror['id']}/signature-policy", b""
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        status, _h, body = call_json(
            "POST",
            f"/mirrors/{mirror['id']}/signature-policy",
            b"{not json",
            headers={"CONTENT_TYPE": "application/json"},
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_invalid_id_and_query_parameters_return_400(self) -> None:
        for path in (
            "/mirrors//signature-policy",
            "/mirrors/a/b/signature-policy",
        ):
            status, _h, body = call_json("GET", path)
            self.assertEqual(status, "400 Bad Request", path)
            self.assertEqual(body["error"], "invalid_request")
        mirror = register()
        status, _h, body = call_json(
            "GET",
            f"/mirrors/{mirror['id']}/signature-policy",
            query_string="x=1",
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_method_not_allowed_has_allow_header(self) -> None:
        mirror = register()
        for method in ("PUT", "DELETE", "PATCH"):
            status, headers, body = call_json(
                method, f"/mirrors/{mirror['id']}/signature-policy"
            )
            self.assertEqual(status, "405 Method Not Allowed")
            self.assertIn(("Allow", "GET, POST"), headers)
            self.assertEqual(body["error"], "method_not_allowed")

    def test_policies_are_independent_per_mirror(self) -> None:
        first = register("first")
        second = register("second")
        register_policy(str(first["id"]))
        status, _h, body = call_json(
            "GET", f"/mirrors/{second['id']}/signature-policy"
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "mirror_policy_not_found")


class MirrorPullSignatureTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def mirror_with_policy(
        self, policy: dict[str, object] | None = None
    ) -> str:
        mirror = register()
        status, _ = register_policy(str(mirror["id"]), policy)
        assert status == "201 Created", status
        return str(mirror["id"])

    def test_pull_without_policy_ignores_signature_headers(self) -> None:
        mirror = register()
        with patch_fetch(LAYER_A) as fetch:
            status, _h, raw = call(
                "POST",
                f"/mirrors/{mirror['id']}/pull/{DIGEST_A}",
                headers={
                    "HTTP_X_KEY_ID": "anything",
                    "HTTP_X_SIGNED_DIGEST": "not-a-digest",
                    "HTTP_X_SIGNATURE": "junk",
                },
            )
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, LAYER_A)
        fetch.assert_called_once_with(UPSTREAM, DIGEST_A)

    def test_valid_signature_returns_bytes_and_caches(self) -> None:
        mirror_id = self.mirror_with_policy()
        with patch_fetch(LAYER_A):
            status, _h, raw = call(
                "POST",
                f"/mirrors/{mirror_id}/pull/{DIGEST_A}",
                headers=signature_headers(),
            )
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, LAYER_A)
        status, _h, cached = call("GET", f"/cache/layers/{DIGEST_A}")
        self.assertEqual(status, "200 OK")
        self.assertEqual(cached, LAYER_A)

    def test_missing_headers_return_403_and_change_nothing(self) -> None:
        mirror_id = self.mirror_with_policy()
        variants = [
            {},
            {"HTTP_X_KEY_ID": "key-one"},
            {
                "HTTP_X_KEY_ID": "key-one",
                "HTTP_X_SIGNED_DIGEST": DIGEST_A,
            },
            {"HTTP_X_SIGNATURE": "x", "HTTP_X_SIGNED_DIGEST": DIGEST_A},
        ]
        for headers in variants:
            with patch_fetch(LAYER_A):
                status, _h, body = call_json(
                    "POST",
                    f"/mirrors/{mirror_id}/pull/{DIGEST_A}",
                    headers=headers,
                )
            self.assertEqual(status, "403 Forbidden", headers)
            self.assertEqual(body["error"], "signature_missing")
        status_body = cache_status()
        self.assertEqual(status_body["entries"], 0)
        self.assertEqual(status_body["hits"], 0)
        self.assertEqual(status_body["misses"], 0)

    def test_invalid_header_values_return_400(self) -> None:
        mirror_id = self.mirror_with_policy()
        variants = [
            {
                "HTTP_X_KEY_ID": "",
                "HTTP_X_SIGNED_DIGEST": DIGEST_A,
                "HTTP_X_SIGNATURE": sign("hmac-sha256", "key-one", DIGEST_A),
            },
            {
                "HTTP_X_KEY_ID": "key-one",
                "HTTP_X_SIGNED_DIGEST": "not-a-digest",
                "HTTP_X_SIGNATURE": sign("hmac-sha256", "key-one", DIGEST_A),
            },
            {
                "HTTP_X_KEY_ID": "key-one",
                "HTTP_X_SIGNED_DIGEST": DIGEST_A,
                "HTTP_X_SIGNATURE": "",
            },
        ]
        for headers in variants:
            with patch_fetch(LAYER_A):
                status, _h, body = call_json(
                    "POST",
                    f"/mirrors/{mirror_id}/pull/{DIGEST_A}",
                    headers=headers,
                )
            self.assertEqual(status, "400 Bad Request", headers)
            self.assertEqual(body["error"], "invalid_request")
        self.assertEqual(cache_status()["entries"], 0)

    def test_untrusted_key_returns_403(self) -> None:
        mirror_id = self.mirror_with_policy()
        with patch_fetch(LAYER_A):
            status, _h, body = call_json(
                "POST",
                f"/mirrors/{mirror_id}/pull/{DIGEST_A}",
                headers=signature_headers("stranger", DIGEST_A),
            )
        self.assertEqual(status, "403 Forbidden")
        self.assertEqual(body["error"], "key_not_trusted")
        self.assertEqual(cache_status()["entries"], 0)

    def test_uncovered_digest_returns_403_when_cover_digest(self) -> None:
        mirror_id = self.mirror_with_policy()
        with patch_fetch(LAYER_A):
            status, _h, body = call_json(
                "POST",
                f"/mirrors/{mirror_id}/pull/{DIGEST_A}",
                headers=signature_headers("key-one", DIGEST_B),
            )
        self.assertEqual(status, "403 Forbidden")
        self.assertEqual(body["error"], "digest_uncovered")
        self.assertEqual(cache_status()["entries"], 0)

    def test_cover_digest_false_allows_other_signed_digest(self) -> None:
        mirror_id = self.mirror_with_policy(
            {
                "algorithm": "hmac-sha256",
                "keys": ["key-one"],
                "cover_digest": False,
            }
        )
        with patch_fetch(LAYER_A):
            status, _h, raw = call(
                "POST",
                f"/mirrors/{mirror_id}/pull/{DIGEST_A}",
                headers=signature_headers("key-one", DIGEST_B),
            )
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, LAYER_A)

    def test_wrong_signature_returns_403(self) -> None:
        mirror_id = self.mirror_with_policy()
        headers = signature_headers()
        headers["HTTP_X_SIGNATURE"] = sign(
            "hmac-sha256", "key-two", DIGEST_A
        )
        with patch_fetch(LAYER_A):
            status, _h, body = call_json(
                "POST",
                f"/mirrors/{mirror_id}/pull/{DIGEST_A}",
                headers=headers,
            )
        self.assertEqual(status, "403 Forbidden")
        self.assertEqual(body["error"], "signature_invalid")
        self.assertEqual(cache_status()["entries"], 0)

    def test_signature_comparison_ignores_case(self) -> None:
        mirror_id = self.mirror_with_policy()
        headers = signature_headers()
        headers["HTTP_X_SIGNATURE"] = headers["HTTP_X_SIGNATURE"].upper()
        headers["HTTP_X_SIGNED_DIGEST"] = DIGEST_A.upper()
        with patch_fetch(LAYER_A):
            status, _h, raw = call(
                "POST",
                f"/mirrors/{mirror_id}/pull/{DIGEST_A}",
                headers=headers,
            )
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, LAYER_A)

    def test_second_trusted_key_and_sha512_policy(self) -> None:
        mirror_id = self.mirror_with_policy(
            {
                "algorithm": "hmac-sha512",
                "keys": ["key-one", "key-two"],
                "cover_digest": True,
            }
        )
        with patch_fetch(LAYER_A):
            status, _h, raw = call(
                "POST",
                f"/mirrors/{mirror_id}/pull/{DIGEST_A}",
                headers=signature_headers(
                    "key-two", DIGEST_A, algorithm="hmac-sha512"
                ),
            )
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, LAYER_A)

    def test_failed_check_happens_after_content_is_ready(self) -> None:
        # Existing upstream and digest errors keep their codes and take
        # precedence over the signature gate.
        mirror_id = self.mirror_with_policy()
        error = MirrorFetchError(
            "mirror_fetch_failed", "Upstream mirror could not be reached."
        )
        with patch_fetch(error=error):
            status, _h, body = call_json(
                "POST", f"/mirrors/{mirror_id}/pull/{DIGEST_A}"
            )
        self.assertEqual(status, "502 Bad Gateway")
        self.assertEqual(body["error"], "mirror_fetch_failed")
        with patch_fetch(b"tampered bytes"):
            status, _h, body = call_json(
                "POST", f"/mirrors/{mirror_id}/pull/{DIGEST_A}"
            )
        self.assertEqual(status, "502 Bad Gateway")
        self.assertEqual(body["error"], "mirror_digest_mismatch")

    def test_quota_error_unchanged_with_valid_signature(self) -> None:
        mirror_id = self.mirror_with_policy()
        cache_store.configure(len(LAYER_A))
        with patch_fetch(LAYER_A):
            status, _h, _raw = call(
                "POST",
                f"/mirrors/{mirror_id}/pull/{DIGEST_A}",
                headers=signature_headers(),
            )
        self.assertEqual(status, "200 OK")
        with patch_fetch(LAYER_B):
            status, _h, body = call_json(
                "POST",
                f"/mirrors/{mirror_id}/pull/{DIGEST_B}",
                headers=signature_headers("key-one", DIGEST_B),
            )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "cache_quota_exceeded")

    def test_cache_hit_still_requires_signature(self) -> None:
        mirror_id = self.mirror_with_policy()
        with patch_fetch(LAYER_A):
            status, _h, _raw = call(
                "POST",
                f"/mirrors/{mirror_id}/pull/{DIGEST_A}",
                headers=signature_headers(),
            )
        self.assertEqual(status, "200 OK")
        # The layer is cached now; a pull without headers is still rejected
        # and the counters stay untouched.
        with patch_fetch() as fetch:
            status, _h, body = call_json(
                "POST", f"/mirrors/{mirror_id}/pull/{DIGEST_A}"
            )
        self.assertEqual(status, "403 Forbidden")
        self.assertEqual(body["error"], "signature_missing")
        fetch.assert_not_called()
        status_body = cache_status()
        self.assertEqual(status_body["hits"], 0)
        self.assertEqual(status_body["misses"], 0)
        # A signed pull is served from the cache without upstream contact.
        with patch_fetch() as fetch:
            status, _h, raw = call(
                "POST",
                f"/mirrors/{mirror_id}/pull/{DIGEST_A}",
                headers=signature_headers(),
            )
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, LAYER_A)
        fetch.assert_not_called()

    def test_reset_clears_policies(self) -> None:
        mirror_id = self.mirror_with_policy()
        reset_state()
        mirror = register()
        self.assertNotEqual(mirror["id"], mirror_id)
        status, _h, body = call_json(
            "GET", f"/mirrors/{mirror['id']}/signature-policy"
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "mirror_policy_not_found")


if __name__ == "__main__":
    unittest.main()
