from __future__ import annotations

import hashlib
import hmac
import io
import json
import unittest
from unittest import mock

from provenance_api.app import application, reset_state
from provenance_api.mirrors import MirrorFetchError

LAYER_A = b"alpha-layer-bytes"
DIGEST_A = hashlib.sha256(LAYER_A).hexdigest()
DIGEST_B = hashlib.sha256(b"beta-layer-bytes-larger").hexdigest()

UPSTREAM = "https://registry.example.invalid"

POLICY = {
    "algorithm": "hmac-sha256",
    "keys": ["key-one", "key-two"],
    "cover_digest": True,
}


def sign(key_id: str, digest: str, algorithm: str = "hmac-sha256") -> str:
    hashmod = (
        hashlib.sha256 if algorithm == "hmac-sha256" else hashlib.sha512
    )
    return hmac.new(
        key_id.encode("utf-8"), digest.encode("ascii"), hashmod
    ).hexdigest()


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


def pull(
    mirror_id: str,
    digest: str = DIGEST_A,
    *,
    headers: dict[str, str] | None = None,
) -> tuple[str, list[tuple[str, str]], bytes]:
    return call("POST", f"/mirrors/{mirror_id}/pull/{digest}", headers=headers)


def good_headers(
    key_id: str = "key-one",
    digest: str = DIGEST_A,
    algorithm: str = "hmac-sha256",
) -> dict[str, str]:
    return {
        "HTTP_X_KEY_ID": key_id,
        "HTTP_X_SIGNED_DIGEST": digest,
        "HTTP_X_SIGNATURE": sign(key_id, digest, algorithm),
    }


class MirrorPolicyRegistrationTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def test_register_returns_201_and_echoes_id_and_three_fields(self) -> None:
        mirror = register()
        status, _h, raw = call(
            "POST",
            f"/mirrors/{mirror['id']}/signature-policy",
            json.dumps(POLICY).encode("utf-8"),
            headers={"CONTENT_TYPE": "application/json"},
        )
        self.assertEqual(status, "201 Created")
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

    def test_identical_resubmission_returns_200(self) -> None:
        mirror = register()
        status, first = register_policy(mirror["id"])
        self.assertEqual(status, "201 Created")
        status, second = register_policy(mirror["id"])
        self.assertEqual(status, "200 OK")
        self.assertEqual(first, second)

    def test_different_policy_returns_409_and_keeps_original(self) -> None:
        mirror = register()
        status, _ = register_policy(mirror["id"])
        self.assertEqual(status, "201 Created")
        changed = dict(POLICY, keys=["other-key"])
        status, body = register_policy(mirror["id"], changed)
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "mirror_policy_conflict")
        status, fetched = self._get(mirror["id"])
        self.assertEqual(status, "200 OK")
        self.assertEqual(fetched["keys"], ["key-one", "key-two"])

    def test_get_returns_registered_policy(self) -> None:
        mirror = register()
        register_policy(mirror["id"])
        status, body = self._get(mirror["id"])
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["id"], mirror["id"])
        self.assertEqual(body["algorithm"], "hmac-sha256")

    def test_get_unregistered_returns_404(self) -> None:
        mirror = register()
        status, body = self._get(mirror["id"])
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "mirror_policy_not_found")

    def test_unknown_mirror_returns_404(self) -> None:
        status, body = register_policy("missing")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "mirror_not_found")
        status, body = self._get("missing")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "mirror_not_found")

    def _get(self, mirror_id: str) -> tuple[str, dict[str, object]]:
        status, _h, body = call_json(
            "GET", f"/mirrors/{mirror_id}/signature-policy"
        )
        return status, body

    def test_field_errors_return_400_and_leave_no_policy(self) -> None:
        mirror = register()
        payloads = [
            b"{}",
            b'{"algorithm":"hmac-sha256","keys":["k"]}',
            b'{"algorithm":"hmac-sha256","cover_digest":true}',
            b'{"keys":["k"],"cover_digest":true}',
            b'{"algorithm":"HMAC-SHA256","keys":["k"],"cover_digest":true}',
            b'{"algorithm":"sha256","keys":["k"],"cover_digest":true}',
            b'{"algorithm":1,"keys":["k"],"cover_digest":true}',
            b'{"algorithm":"hmac-sha256","keys":[],"cover_digest":true}',
            b'{"algorithm":"hmac-sha256","keys":"k","cover_digest":true}',
            b'{"algorithm":"hmac-sha256","keys":["k","k"],"cover_digest":true}',
            b'{"algorithm":"hmac-sha256","keys":[""],"cover_digest":true}',
            b'{"algorithm":"hmac-sha256","keys":[1],"cover_digest":true}',
            b'{"algorithm":"hmac-sha256","keys":["k"],"cover_digest":"yes"}',
            b'{"algorithm":"hmac-sha256","keys":["k"],"cover_digest":1}',
            b'{"algorithm":"hmac-sha256","keys":["k"],"cover_digest":true,"x":1}',
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
        status, body = self._get(mirror["id"])
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

    def test_bad_id_and_query_parameters_return_400(self) -> None:
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


class MirrorPullSignatureTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def _mirror_with_policy(
        self, policy: dict[str, object] | None = None
    ) -> str:
        mirror = register()
        status, _ = register_policy(mirror["id"], policy)
        assert status == "201 Created"
        return str(mirror["id"])

    def test_valid_signature_returns_bytes_and_caches(self) -> None:
        mirror_id = self._mirror_with_policy()
        with patch_fetch(LAYER_A) as fetch:
            status, _h, raw = pull(
                mirror_id, headers=good_headers()
            )
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, LAYER_A)
        fetch.assert_called_once_with(UPSTREAM, DIGEST_A)
        status, _h, cached = call("GET", f"/cache/layers/{DIGEST_A}")
        self.assertEqual(status, "200 OK")
        self.assertEqual(cached, LAYER_A)

    def test_missing_headers_return_403_and_change_nothing(self) -> None:
        mirror_id = self._mirror_with_policy()
        variants = [
            {},
            {"HTTP_X_KEY_ID": "key-one"},
            {
                "HTTP_X_KEY_ID": "key-one",
                "HTTP_X_SIGNATURE": sign("key-one", DIGEST_A),
            },
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
        _s, _h, status_body = call_json("GET", "/cache/status")
        self.assertEqual(status_body["entries"], 0)
        self.assertEqual(status_body["hits"], 0)
        self.assertEqual(status_body["misses"], 0)

    def test_untrusted_key_returns_403(self) -> None:
        mirror_id = self._mirror_with_policy()
        with patch_fetch(LAYER_A):
            status, _h, body = call_json(
                "POST",
                f"/mirrors/{mirror_id}/pull/{DIGEST_A}",
                headers=good_headers(key_id="stranger"),
            )
        self.assertEqual(status, "403 Forbidden")
        self.assertEqual(body["error"], "key_not_trusted")
        _s, _h, status_body = call_json("GET", "/cache/status")
        self.assertEqual(status_body["entries"], 0)

    def test_second_trusted_key_is_accepted(self) -> None:
        mirror_id = self._mirror_with_policy()
        with patch_fetch(LAYER_A):
            status, _h, raw = pull(
                mirror_id, headers=good_headers(key_id="key-two")
            )
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, LAYER_A)

    def test_uncovered_digest_returns_403(self) -> None:
        mirror_id = self._mirror_with_policy()
        headers = good_headers(digest=DIGEST_B)
        with patch_fetch(LAYER_A):
            status, _h, body = call_json(
                "POST",
                f"/mirrors/{mirror_id}/pull/{DIGEST_A}",
                headers=headers,
            )
        self.assertEqual(status, "403 Forbidden")
        self.assertEqual(body["error"], "digest_uncovered")

    def test_cover_digest_false_ignores_signed_digest_value(self) -> None:
        mirror_id = self._mirror_with_policy(
            {
                "algorithm": "hmac-sha256",
                "keys": ["key-one"],
                "cover_digest": False,
            }
        )
        # The signature is still computed over the signed digest text,
        # but the signed digest need not match the pulled layer digest.
        headers = good_headers(digest=DIGEST_B)
        with patch_fetch(LAYER_A):
            status, _h, raw = call(
                "POST",
                f"/mirrors/{mirror_id}/pull/{DIGEST_A}",
                headers=headers,
            )
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, LAYER_A)

    def test_invalid_signature_returns_403_and_does_not_cache(self) -> None:
        mirror_id = self._mirror_with_policy()
        headers = good_headers()
        headers["HTTP_X_SIGNATURE"] = "0" * 64
        with patch_fetch(LAYER_A):
            status, _h, body = call_json(
                "POST",
                f"/mirrors/{mirror_id}/pull/{DIGEST_A}",
                headers=headers,
            )
        self.assertEqual(status, "403 Forbidden")
        self.assertEqual(body["error"], "signature_invalid")
        _s, _h, status_body = call_json("GET", "/cache/status")
        self.assertEqual(status_body["entries"], 0)

    def test_signature_comparison_ignores_case(self) -> None:
        mirror_id = self._mirror_with_policy()
        headers = good_headers()
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

    def test_sha512_policy_uses_sha512_signature(self) -> None:
        mirror_id = self._mirror_with_policy(
            {
                "algorithm": "hmac-sha512",
                "keys": ["key-one"],
                "cover_digest": True,
            }
        )
        with patch_fetch(LAYER_A):
            status, _h, raw = call(
                "POST",
                f"/mirrors/{mirror_id}/pull/{DIGEST_A}",
                headers=good_headers(algorithm="hmac-sha512"),
            )
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, LAYER_A)
        # A sha256-shaped signature no longer matches the policy shape.
        layer_b = b"beta-layer-bytes-larger"
        with patch_fetch(layer_b):
            status, _h, body = call_json(
                "POST",
                f"/mirrors/{mirror_id}/pull/{DIGEST_B}",
                headers=good_headers(digest=DIGEST_B),
            )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_invalid_header_values_return_400(self) -> None:
        mirror_id = self._mirror_with_policy()
        variants = [
            dict(good_headers(), HTTP_X_KEY_ID=""),
            dict(good_headers(), HTTP_X_SIGNED_DIGEST="xyz"),
            dict(good_headers(), HTTP_X_SIGNED_DIGEST="g" * 64),
            dict(good_headers(), HTTP_X_SIGNATURE="not-hex"),
            dict(good_headers(), HTTP_X_SIGNATURE="ab" * 16),
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

    def test_cache_hit_still_requires_valid_signature(self) -> None:
        mirror_id = self._mirror_with_policy()
        status, _h, _raw = call(
            "POST",
            f"/cache/layers/{DIGEST_A}",
            LAYER_A,
            headers={"CONTENT_TYPE": "application/octet-stream"},
        )
        self.assertEqual(status, "201 Created")
        with patch_fetch() as fetch:
            status, _h, body = call_json(
                "POST", f"/mirrors/{mirror_id}/pull/{DIGEST_A}"
            )
        self.assertEqual(status, "403 Forbidden")
        self.assertEqual(body["error"], "signature_missing")
        fetch.assert_not_called()
        with patch_fetch() as fetch:
            status, _h, raw = pull(mirror_id, headers=good_headers())
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, LAYER_A)
        fetch.assert_not_called()
        _s, _h, status_body = call_json("GET", "/cache/status")
        self.assertEqual(status_body["hits"], 0)
        self.assertEqual(status_body["misses"], 0)

    def test_failed_check_reports_only_one_error(self) -> None:
        # An untrusted key with a bad signature reports the key only.
        mirror_id = self._mirror_with_policy()
        headers = {
            "HTTP_X_KEY_ID": "stranger",
            "HTTP_X_SIGNED_DIGEST": DIGEST_B,
            "HTTP_X_SIGNATURE": "0" * 64,
        }
        with patch_fetch(LAYER_A):
            status, _h, body = call_json(
                "POST",
                f"/mirrors/{mirror_id}/pull/{DIGEST_A}",
                headers=headers,
            )
        self.assertEqual(status, "403 Forbidden")
        self.assertEqual(body["error"], "key_not_trusted")

    def test_pull_without_policy_ignores_signature_headers(self) -> None:
        mirror = register()
        with patch_fetch(LAYER_A):
            status, _h, raw = pull(
                str(mirror["id"]),
                headers={
                    "HTTP_X_KEY_ID": "anything",
                    "HTTP_X_SIGNED_DIGEST": "not-a-digest",
                    "HTTP_X_SIGNATURE": "not-a-signature",
                },
            )
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, LAYER_A)

    def test_pull_without_policy_still_works(self) -> None:
        mirror = register()
        with patch_fetch(LAYER_A):
            status, _h, raw = pull(str(mirror["id"]))
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, LAYER_A)

    def test_upstream_failure_and_digest_mismatch_codes_unchanged(self) -> None:
        mirror_id = self._mirror_with_policy()
        error = MirrorFetchError(
            "mirror_fetch_failed", "Upstream mirror could not be reached."
        )
        with patch_fetch(error=error):
            status, _h, body = call_json(
                "POST",
                f"/mirrors/{mirror_id}/pull/{DIGEST_A}",
                headers=good_headers(),
            )
        self.assertEqual(status, "502 Bad Gateway")
        self.assertEqual(body["error"], "mirror_fetch_failed")
        with patch_fetch(b"tampered bytes"):
            status, _h, body = call_json(
                "POST",
                f"/mirrors/{mirror_id}/pull/{DIGEST_A}",
                headers=good_headers(),
            )
        self.assertEqual(status, "502 Bad Gateway")
        self.assertEqual(body["error"], "mirror_digest_mismatch")

    def test_quota_error_unchanged_with_policy(self) -> None:
        from provenance_api.app import cache_store

        mirror_id = self._mirror_with_policy()
        cache_store.configure(1)
        with patch_fetch(LAYER_A):
            status, _h, body = call_json(
                "POST",
                f"/mirrors/{mirror_id}/pull/{DIGEST_A}",
                headers=good_headers(),
            )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "cache_quota_exceeded")

    def test_reset_clears_policies(self) -> None:
        mirror_id = self._mirror_with_policy()
        reset_state()
        mirror = register()
        status, body = self._get(str(mirror["id"]))
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "mirror_policy_not_found")
        # And the pull is back to the unsigned baseline behavior.
        with patch_fetch(LAYER_A):
            status, _h, raw = pull(str(mirror["id"]))
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, LAYER_A)

    def _get(self, mirror_id: str) -> tuple[str, dict[str, object]]:
        status, _h, body = call_json(
            "GET", f"/mirrors/{mirror_id}/signature-policy"
        )
        return status, body


if __name__ == "__main__":
    unittest.main()
