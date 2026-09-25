from __future__ import annotations

import hashlib
import hmac
import io
import json
import unittest

from provenance_api.app import application, reset_state

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "C" * 64


def sign(algorithm: str, key_id: str, digest: str) -> str:
    digestmod = hashlib.sha256 if algorithm == "hmac-sha256" else hashlib.sha512
    return hmac.new(
        key_id.encode("utf-8"), digest.lower().encode("ascii"), digestmod
    ).hexdigest()


SIG256 = sign("hmac-sha256", "key-1", DIGEST_A)
SIG512 = sign("hmac-sha512", "key-1", DIGEST_A)


def call(
    method: str,
    path: str,
    body: bytes | str | dict[str, object] | None = None,
    *,
    query_string: str | None = None,
) -> tuple[str, list[tuple[str, str]], bytes]:
    if body is None:
        payload = b""
    elif isinstance(body, dict):
        payload = json.dumps(body).encode("utf-8")
    else:
        payload = body.encode("utf-8") if isinstance(body, str) else body

    environ: dict[str, object] = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": query_string if query_string is not None else "",
        "CONTENT_LENGTH": str(len(payload)),
        "CONTENT_TYPE": "application/json",
        "wsgi.input": io.BytesIO(payload),
    }
    captured: dict[str, object] = {}

    def start_response(status: str, headers: list[tuple[str, str]]) -> None:
        captured["status"] = status
        captured["headers"] = headers

    chunks = application(environ, start_response)
    return str(captured["status"]), list(captured["headers"]), b"".join(chunks)


def call_json(
    method: str,
    path: str,
    body: bytes | str | dict[str, object] | None = None,
    *,
    query_string: str | None = None,
) -> tuple[str, list[tuple[str, str]], dict[str, object]]:
    status, headers, raw = call(method, path, body, query_string=query_string)
    return status, headers, json.loads(raw.decode("utf-8"))


def signature_payload(
    *,
    signer: object = "release-bot",
    algorithm: object = "hmac-sha256",
    key_id: object = "key-1",
    signature: object = SIG256,
    digest: object = DIGEST_A,
) -> dict[str, object]:
    return {
        "signer": signer,
        "algorithm": algorithm,
        "key_id": key_id,
        "signature": signature,
        "digest": digest,
    }


class SignatureTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.resource_id = self._create(DIGEST_A)
        self.other_id = self._create(DIGEST_B, name="other")

    def _create(self, digest: str, name: str = "r") -> str:
        _s, _h, body = call_json(
            "POST",
            "/resources",
            {"name": name, "category": "code", "digest": digest},
        )
        return str(body["id"])

    def _register(
        self,
        resource_id: str | None = None,
        *,
        payload: dict[str, object] | None = None,
    ):
        target = self.resource_id if resource_id is None else resource_id
        return call_json(
            "POST",
            f"/resources/{target}/signatures",
            payload if payload is not None else signature_payload(),
        )

    def _verify(self, resource_id: str | None = None):
        target = self.resource_id if resource_id is None else resource_id
        return call_json("POST", f"/resources/{target}/signatures/verify")

    # --- Registration ------------------------------------------------------

    def test_register_returns_201_and_echoes_fields(self) -> None:
        status, headers, body = self._register()
        self.assertEqual(status, "201 Created")
        self.assertEqual(
            headers[0], ("Content-Type", "application/json; charset=utf-8")
        )
        self.assertEqual(
            set(body),
            {"id", "signer", "algorithm", "key_id", "signature", "digest"},
        )
        self.assertEqual(body["id"], self.resource_id)
        self.assertEqual(body["signer"], "release-bot")
        self.assertEqual(body["algorithm"], "hmac-sha256")
        self.assertEqual(body["key_id"], "key-1")
        self.assertEqual(body["signature"], SIG256)
        self.assertEqual(body["digest"], DIGEST_A)

    def test_id_comes_first_then_the_five_fields(self) -> None:
        _s, _h, raw = call(
            "POST",
            f"/resources/{self.resource_id}/signatures",
            signature_payload(signer="签名者"),
        )
        self.assertTrue(raw.endswith(b"\n"))
        text = raw.decode("utf-8").rstrip("\n")
        keys = ['"id"', '"signer"', '"algorithm"',
                '"key_id"', '"signature"', '"digest"']
        positions = [text.index(k) for k in keys]
        self.assertEqual(positions, sorted(positions))

    def test_mixed_case_signature_and_digest_stored_lowercase(self) -> None:
        _s, _h, body = self._register(payload=signature_payload(
            signature=SIG256.upper(), digest="A" * 64,
        ))
        self.assertEqual(body["signature"], SIG256)
        self.assertEqual(body["digest"], DIGEST_A)

    def test_hmac_sha512_accepted(self) -> None:
        status, _h, body = self._register(payload=signature_payload(
            algorithm="hmac-sha512", signature=SIG512,
        ))
        self.assertEqual(status, "201 Created")
        self.assertEqual(body["algorithm"], "hmac-sha512")
        self.assertEqual(body["signature"], SIG512)
        self.assertEqual(len(body["signature"]), 128)

    def test_unknown_algorithm_rejected(self) -> None:
        for algorithm in ("sha256", "HMAC-SHA256", "hmac-sha1", "", 1, None):
            with self.subTest(algorithm=algorithm):
                status, _h, body = self._register(
                    payload=signature_payload(algorithm=algorithm)
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_signature_length_must_match_algorithm(self) -> None:
        # 64 hex characters is right for hmac-sha256 but not hmac-sha512.
        status, _h, body = self._register(payload=signature_payload(
            algorithm="hmac-sha512", signature=SIG256,
        ))
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        # 128 hex characters is not valid for hmac-sha256 either.
        status, _h, body = self._register(payload=signature_payload(
            algorithm="hmac-sha256", signature=SIG512,
        ))
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_signature_must_be_hexadecimal(self) -> None:
        for value in ("g" * 64, "z" * 64, "", 1, None, True, SIG256 + "0"):
            with self.subTest(value=value):
                status, _h, body = self._register(
                    payload=signature_payload(signature=value)
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_text_field_errors(self) -> None:
        for field in ("signer", "key_id"):
            for value in (1, None, True, "", [], {}):
                with self.subTest(field=field, value=value):
                    status, _h, body = self._register(
                        payload=signature_payload(**{field: value})
                    )
                    self.assertEqual(status, "400 Bad Request")
                    self.assertEqual(body["error"], "invalid_request")

    def test_text_fields_limit_256_code_points(self) -> None:
        fresh = 0

        def fresh_id() -> str:
            nonlocal fresh
            fresh += 1
            return self._create(f"{fresh:064x}", name=f"r{fresh}")

        def payload_for(resource_id: str, **overrides: object) -> dict:
            # The signed digest must match the resource's own digest.
            resource = call_json("GET", f"/resources/{resource_id}")[2]
            digest = str(resource["digest"])
            return signature_payload(
                digest=digest,
                signature=sign("hmac-sha256", "key-1", digest),
                **overrides,
            )

        for field in ("signer", "key_id"):
            with self.subTest(field=field):
                resource_id = fresh_id()
                status, _h, body = self._register(
                    resource_id=resource_id,
                    payload=payload_for(resource_id, **{field: "あ" * 257}),
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")
            with self.subTest(field=field, ok=True):
                resource_id = fresh_id()
                status, _h, _body = self._register(
                    resource_id=resource_id,
                    payload=payload_for(resource_id, **{field: "あ" * 256}),
                )
                self.assertEqual(status, "201 Created")

    def test_digest_errors(self) -> None:
        for value in ("a" * 63, "g" * 64, "A" * 65, "", 1, None, True):
            with self.subTest(value=value):
                status, _h, body = self._register(
                    payload=signature_payload(digest=value)
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    # --- Query -------------------------------------------------------------

    def test_get_returns_registered_signature(self) -> None:
        post = self._register()[2]
        status, _h, body = call_json(
            "GET", f"/resources/{self.resource_id}/signatures"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, post)

    def test_get_without_registration_is_404(self) -> None:
        status, _h, body = call_json(
            "GET", f"/resources/{self.resource_id}/signatures"
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "signature_not_found")

    # --- Idempotency and conflicts ----------------------------------------

    def test_same_content_resubmitted_is_idempotent_200(self) -> None:
        first = self._register()
        self.assertEqual(first[0], "201 Created")
        second = self._register()
        self.assertEqual(second[0], "200 OK")
        self.assertEqual(second[2], first[2])

        # Mixed-case hex normalizing to the same record is the same.
        status, _h, _body = self._register(payload=signature_payload(
            signature=SIG256.upper(), digest="A" * 64,
        ))
        self.assertEqual(status, "200 OK")

    def test_different_signature_conflicts(self) -> None:
        original = self._register()[2]
        variants = [
            signature_payload(signer="other"),
            signature_payload(algorithm="hmac-sha512", signature=SIG512),
            signature_payload(key_id="key-2"),
            signature_payload(signature=sign("hmac-sha256", "key-1", DIGEST_B),
                              digest=DIGEST_A),
        ]
        for payload in variants:
            with self.subTest(payload=payload):
                status, _h, body = self._register(payload=payload)
                self.assertEqual(status, "409 Conflict")
                self.assertEqual(body["error"], "signature_conflict")

        # The original record is untouched.
        _s, _h, body = call_json(
            "GET", f"/resources/{self.resource_id}/signatures"
        )
        self.assertEqual(body, original)

    def test_one_record_per_resource_is_scoped(self) -> None:
        self._register(self.resource_id)
        self._register(
            self.other_id,
            payload=signature_payload(
                digest=DIGEST_B,
                signature=sign("hmac-sha256", "key-1", DIGEST_B),
            ),
        )
        _s, _h, first = call_json(
            "GET", f"/resources/{self.resource_id}/signatures"
        )
        _s, _h, second = call_json(
            "GET", f"/resources/{self.other_id}/signatures"
        )
        self.assertEqual(first["digest"], DIGEST_A)
        self.assertEqual(second["digest"], DIGEST_B)

    def test_signed_digest_mismatch_is_409(self) -> None:
        status, _h, body = self._register(payload=signature_payload(
            digest=DIGEST_B,
            signature=sign("hmac-sha256", "key-1", DIGEST_B),
        ))
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "signed_digest_mismatch")
        # Nothing was recorded.
        _s, _h, get = call_json(
            "GET", f"/resources/{self.resource_id}/signatures"
        )
        self.assertEqual(get["error"], "signature_not_found")

    # --- Verification ------------------------------------------------------

    def test_verify_valid_signature(self) -> None:
        self._register()
        status, _h, body = self._verify()
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, {"id": self.resource_id, "valid": True})

    def test_verify_hmac_sha512(self) -> None:
        self._register(payload=signature_payload(
            algorithm="hmac-sha512", signature=SIG512,
        ))
        status, _h, body = self._verify()
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["valid"], True)

    def test_verify_invalid_signature(self) -> None:
        # A well-formed signature that does not match the key/digest.
        self._register(payload=signature_payload(signature="0" * 64))
        status, _h, body = self._verify()
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["valid"], False)

    def test_verify_response_is_newline_terminated(self) -> None:
        self._register()
        status, _h, raw = call(
            "POST", f"/resources/{self.resource_id}/signatures/verify"
        )
        self.assertEqual(status, "200 OK")
        self.assertTrue(raw.endswith(b"\n"))
        body = json.loads(raw.decode("utf-8"))
        self.assertEqual(set(body), {"id", "valid"})

    def test_verify_without_registration_is_404(self) -> None:
        status, _h, body = self._verify()
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "signature_not_found")

    def test_verify_leaves_no_record(self) -> None:
        self._verify()
        _s, _h, body = call_json(
            "GET", f"/resources/{self.resource_id}/signatures"
        )
        self.assertEqual(body["error"], "signature_not_found")

    # --- Missing resource ---------------------------------------------------

    def test_missing_resource_is_404(self) -> None:
        for method, path, payload in (
            ("POST", "/resources/missing/signatures", signature_payload()),
            ("GET", "/resources/missing/signatures", None),
            ("POST", "/resources/missing/signatures/verify", None),
        ):
            with self.subTest(method=method, path=path):
                status, _h, body = call_json(method, path, payload)
                self.assertEqual(status, "404 Not Found")
                self.assertEqual(body["error"], "resource_not_found")

    # --- Bad request: body --------------------------------------------------

    def test_missing_body_is_bad_request(self) -> None:
        status, _h, body = call_json(
            "POST", f"/resources/{self.resource_id}/signatures", None
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_malformed_or_bad_utf8_body_is_bad_request(self) -> None:
        path = f"/resources/{self.resource_id}/signatures"
        for raw in (b"{bad", b"\xff\xfe"):
            with self.subTest(raw=raw):
                status, _h, body = call_json("POST", path, raw)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_non_object_body_is_bad_request(self) -> None:
        for raw in (b"[]", b'"x"', b"42", b"null"):
            with self.subTest(raw=raw):
                status, _h, body = call_json(
                    "POST", f"/resources/{self.resource_id}/signatures", raw
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_missing_required_fields(self) -> None:
        for field in ("signer", "algorithm", "key_id", "signature", "digest"):
            payload = signature_payload()
            del payload[field]
            with self.subTest(field=field):
                status, _h, body = self._register(payload=payload)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_empty_object_is_bad_request(self) -> None:
        status, _h, body = self._register(payload={})
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_unknown_field_rejected(self) -> None:
        payload = signature_payload()
        payload["extra"] = 1
        status, _h, body = self._register(payload=payload)
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_bad_request_leaves_no_record(self) -> None:
        self._register(payload={})
        _s, _h, body = call_json(
            "GET", f"/resources/{self.resource_id}/signatures"
        )
        self.assertEqual(body["error"], "signature_not_found")

    # --- Path, query, method ------------------------------------------------

    def test_path_separator_in_id_is_bad_request(self) -> None:
        for method in ("GET", "POST"):
            with self.subTest(path="signatures", method=method):
                status, _h, body = call_json(
                    method, "/resources/a/b/signatures", signature_payload()
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")
        # The verify endpoint is POST-only; a POST with a separator in the
        # id is a bad request.
        status, _h, body = call_json(
            "POST", "/resources/a/b/signatures/verify", signature_payload()
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_query_parameters_rejected(self) -> None:
        for method, path, payload in (
            ("POST", f"/resources/{self.resource_id}/signatures",
             signature_payload()),
            ("GET", f"/resources/{self.resource_id}/signatures", None),
            ("POST", f"/resources/{self.resource_id}/signatures/verify", None),
        ):
            with self.subTest(method=method, path=path):
                status, _h, body = call_json(
                    method, path, payload, query_string="x=1"
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_unsupported_methods_return_405_with_allow(self) -> None:
        for method in ("PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, headers, body = call_json(
                    method, f"/resources/{self.resource_id}/signatures"
                )
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")
                self.assertIn(("Allow", "GET, POST"), headers)

    def test_verify_only_accepts_post(self) -> None:
        for method in ("GET", "PUT", "DELETE"):
            with self.subTest(method=method):
                status, headers, body = call_json(
                    method, f"/resources/{self.resource_id}/signatures/verify"
                )
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")
                self.assertIn(("Allow", "POST"), headers)


if __name__ == "__main__":
    unittest.main()
