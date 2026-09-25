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


def sign(
    algorithm: str, key_id: str, digest: str = DIGEST_A
) -> str:
    """Reference HMAC over the lowercase digest text, keyed by key bytes."""

    return hmac.new(
        key_id.encode("utf-8"),
        digest.lower().encode("ascii"),
        hashlib.sha512 if algorithm == "hmac-sha512" else hashlib.sha256,
    ).hexdigest()


def signature_payload(
    *,
    signer: object = "alice",
    algorithm: object = "hmac-sha256",
    key_id: object = "key-001",
    signature: object = ...,  # type: ignore[assignment]
    digest: object = DIGEST_A,
) -> dict[str, object]:
    if signature is ...:
        signature = sign(str(algorithm), str(key_id), str(digest))
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

    # --- Registration ------------------------------------------------------

    def test_register_returns_201_and_echoes_fields(self) -> None:
        sig = sign("hmac-sha256", "k1", DIGEST_C)
        payload = signature_payload(
            signer="signer-1",
            algorithm="hmac-sha256",
            key_id="k1",
            signature=sig,
            digest=DIGEST_C,
        )
        status, headers, body = self._register(payload=payload)
        self.assertEqual(status, "201 Created")
        self.assertEqual(
            headers[0], ("Content-Type", "application/json; charset=utf-8")
        )
        self.assertEqual(
            set(body),
            {"id", "signer", "algorithm", "key_id", "signature", "digest"},
        )
        self.assertEqual(body["id"], self.resource_id)
        self.assertEqual(body["signer"], "signer-1")
        self.assertEqual(body["algorithm"], "hmac-sha256")
        self.assertEqual(body["key_id"], "k1")
        self.assertEqual(body["signature"], sig)
        self.assertEqual(body["digest"], "c" * 64)

    def test_response_is_compact_utf8_newline_terminated_with_key_order(
        self,
    ) -> None:
        status, _headers, raw = call(
            "POST",
            f"/resources/{self.resource_id}/signatures",
            signature_payload(signer="签名者", key_id="密钥"),
        )
        self.assertEqual(status, "201 Created")
        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(b" ", raw[:-1])
        text = raw.decode("utf-8").rstrip("\n")
        keys = [
            '"id"',
            '"signer"',
            '"algorithm"',
            '"key_id"',
            '"signature"',
            '"digest"',
        ]
        positions = [text.index(key) for key in keys]
        self.assertEqual(positions, sorted(positions))

    def test_hex_values_normalized_to_lowercase(self) -> None:
        sig = sign("hmac-sha256", "k", DIGEST_A)
        # Flip some hex digits to upper case; the stored record is lowercase.
        mixed_sig = "".join(
            ch.upper() if i % 2 == 0 else ch for i, ch in enumerate(sig)
        )
        status, _h, body = self._register(
            payload=signature_payload(
                signature=mixed_sig, digest="AbC" + "0" * 61
            )
        )
        self.assertEqual(status, "201 Created")
        self.assertEqual(body["signature"], sig)
        self.assertEqual(body["digest"], "abc" + "0" * 61)

    def test_register_hmac_sha512(self) -> None:
        payload = signature_payload(
            algorithm="hmac-sha512",
            key_id="k512",
            signature=sign("hmac-sha512", "k512"),
        )
        status, _h, body = self._register(payload=payload)
        self.assertEqual(status, "201 Created")
        self.assertEqual(body["algorithm"], "hmac-sha512")
        self.assertEqual(len(str(body["signature"])), 128)

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
        first = self._register(payload=signature_payload(key_id="k"))
        self.assertEqual(first[0], "201 Created")
        second = self._register(payload=signature_payload(key_id="k"))
        self.assertEqual(second[0], "200 OK")
        self.assertEqual(second[2], first[2])

        # Mixed-case hex normalizing to the same record is the same content.
        sig = sign("hmac-sha256", "k")
        status, _h, _body = self._register(
            payload=signature_payload(
                key_id="k",
                signature=sig.upper(),
                digest="A" * 64,
            )
        )
        self.assertEqual(status, "200 OK")

    def test_different_signature_conflicts(self) -> None:
        base = signature_payload(key_id="k")
        original = self._register(payload=base)[2]
        variants = [
            signature_payload(signer="other"),
            signature_payload(algorithm="hmac-sha512",
                               signature=sign("hmac-sha512", "key-001")),
            signature_payload(key_id="other-key"),
            signature_payload(
                signature="1" * 64
            ),  # well-formed hex, different value
            signature_payload(digest=DIGEST_B,
                              signature=sign("hmac-sha256", "key-001",
                                             DIGEST_B)),
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
                signature=sign("hmac-sha256", "key-001", DIGEST_B),
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

    def test_registration_does_not_check_resource_digest(self) -> None:
        # A signature may be registered over any well-formed digest; the
        # mismatch with the resource digest only surfaces on verification.
        status, _h, body = self._register(
            payload=signature_payload(
                digest=DIGEST_B,
                signature=sign("hmac-sha256", "key-001", DIGEST_B),
            )
        )
        self.assertEqual(status, "201 Created")
        self.assertEqual(body["digest"], DIGEST_B)

    # --- Verification ------------------------------------------------------

    def test_verify_valid_signature(self) -> None:
        for algorithm in ("hmac-sha256", "hmac-sha512"):
            with self.subTest(algorithm=algorithm):
                rid = self._create(
                    f"{len(algorithm):064x}", name=algorithm
                )
                call_json(
                    "POST",
                    f"/resources/{rid}/signatures",
                    signature_payload(
                        algorithm=algorithm,
                        key_id="verify-key",
                        signature=sign(algorithm, "verify-key",
                                       f"{len(algorithm):064x}"),
                        digest=f"{len(algorithm):064x}",
                    ),
                )
                status, headers, body = call_json(
                    "POST", f"/resources/{rid}/signatures/verify"
                )
                self.assertEqual(status, "200 OK")
                self.assertEqual(body, {"id": rid, "valid": True})
                self.assertEqual(
                    headers[0],
                    ("Content-Type", "application/json; charset=utf-8"),
                )

    def test_verify_response_is_newline_terminated(self) -> None:
        self._register()
        status, _h, raw = call(
            "POST", f"/resources/{self.resource_id}/signatures/verify"
        )
        self.assertEqual(status, "200 OK")
        self.assertTrue(raw.endswith(b"\n"))
        self.assertEqual(
            json.loads(raw.decode("utf-8")),
            {"id": self.resource_id, "valid": True},
        )

    def test_verify_invalid_signature(self) -> None:
        # A well-formed but wrong HMAC value registers fine; verification
        # recomputes and reports invalid without it being a service error.
        self._register(payload=signature_payload(signature="1" * 64))
        status, _h, body = call_json(
            "POST", f"/resources/{self.resource_id}/signatures/verify"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, {"id": self.resource_id, "valid": False})

    def test_verify_signed_digest_mismatch_is_409(self) -> None:
        self._register(
            payload=signature_payload(
                digest=DIGEST_B,
                signature=sign("hmac-sha256", "key-001", DIGEST_B),
            )
        )
        status, _h, body = call_json(
            "POST", f"/resources/{self.resource_id}/signatures/verify"
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "signed_digest_mismatch")

    def test_verify_is_read_only(self) -> None:
        before = self._register()[2]
        for _ in range(2):
            call_json(
                "POST", f"/resources/{self.resource_id}/signatures/verify"
            )
        _s, _h, after = call_json(
            "GET", f"/resources/{self.resource_id}/signatures"
        )
        self.assertEqual(after, before)

    def test_verify_without_signature_is_404(self) -> None:
        status, _h, body = call_json(
            "POST", f"/resources/{self.resource_id}/signatures/verify"
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "signature_not_found")

    # --- Bad request: body -------------------------------------------------

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

    # --- Bad request: fields -----------------------------------------------

    def test_missing_required_fields(self) -> None:
        fields = ("signer", "algorithm", "key_id", "signature", "digest")
        for field in fields:
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

        for field in ("signer", "key_id"):
            with self.subTest(field=field, too_long=True):
                status, _h, body = self._register(
                    resource_id=fresh_id(),
                    payload=signature_payload(**{field: "あ" * 257}),
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")
            with self.subTest(field=field, ok=True):
                status, _h, _body = self._register(
                    resource_id=fresh_id(),
                    payload=signature_payload(**{field: "😀" * 256}),
                )
                self.assertEqual(status, "201 Created")

    def test_algorithm_must_be_allowed_value(self) -> None:
        for value in ("HMAC-SHA256", "sha256", "hmac-md5", "", 1, None, True):
            with self.subTest(value=value):
                status, _h, body = self._register(
                    payload=signature_payload(
                        algorithm=value,
                        signature="0" * 64,
                    )
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_digest_errors(self) -> None:
        for value in (
            "a" * 63, "g" * 64, "A" * 65, "", 1, None, True,
        ):
            with self.subTest(value=value):
                status, _h, body = self._register(
                    payload=signature_payload(digest=value)
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_signature_length_must_match_algorithm(self) -> None:
        bad_values = [
            ("hmac-sha256", "a" * 63),
            ("hmac-sha256", "a" * 65),
            ("hmac-sha256", "g" * 64),
            ("hmac-sha256", "a" * 128),
            ("hmac-sha512", "a" * 64),
            ("hmac-sha512", "a" * 127),
            ("hmac-sha512", "a" * 129),
            ("hmac-sha512", "g" * 128),
        ]
        for algorithm, value in bad_values:
            with self.subTest(algorithm=algorithm, length=len(value)):
                status, _h, body = self._register(
                    payload=signature_payload(
                        algorithm=algorithm, signature=value
                    )
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_signature_wrong_type(self) -> None:
        for value in (1, None, True, [], {}):
            with self.subTest(value=value):
                status, _h, body = self._register(
                    payload=signature_payload(signature=value)
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    # --- Path, query, method, missing resource -----------------------------

    def test_empty_path_id_is_bad_request(self) -> None:
        for method, body in [
            ("GET", None),
            ("POST", signature_payload()),
            ("POST", None),
        ]:
            path = "/resources//signatures"
            if method == "POST" and body is None:
                path += "/verify"
            with self.subTest(method=method, path=path):
                status, _h, payload = call_json(method, path, body)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(payload["error"], "invalid_request")

    def test_path_id_with_separator_is_bad_request(self) -> None:
        for raw in ("a/b", "a\\b"):
            for method, suffix, body in [
                ("GET", "signatures", None),
                ("POST", "signatures", signature_payload()),
                ("POST", "signatures/verify", None),
            ]:
                with self.subTest(raw=raw, method=method, suffix=suffix):
                    status, _h, body_resp = call_json(
                        method, f"/resources/{raw}/{suffix}", body
                    )
                    self.assertIn(status[:3], {"400", "404"})
                    self.assertEqual(body_resp["error"], "invalid_request")

    def test_query_parameters_rejected(self) -> None:
        cases = [
            ("GET", f"/resources/{self.resource_id}/signatures", None),
            ("POST", f"/resources/{self.resource_id}/signatures",
             signature_payload()),
            ("POST", f"/resources/{self.resource_id}/signatures/verify", None),
        ]
        for method, path, body in cases:
            with self.subTest(method=method, path=path):
                status, _h, payload = call_json(
                    method, path, body, query_string="x=1"
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(payload["error"], "invalid_request")

    def test_missing_resource_is_404(self) -> None:
        cases = [
            ("GET", "/resources/missing/signatures", None),
            ("POST", "/resources/missing/signatures", signature_payload()),
            ("POST", "/resources/missing/signatures/verify", None),
        ]
        for method, path, body in cases:
            with self.subTest(method=method, path=path):
                status, _h, payload = call_json(method, path, body)
                self.assertEqual(status, "404 Not Found")
                self.assertEqual(payload["error"], "resource_not_found")

    def test_unsupported_methods_return_405_with_allow(self) -> None:
        for method in ("PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, headers, body = call_json(
                    method, f"/resources/{self.resource_id}/signatures"
                )
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")
                self.assertIn(("Allow", "GET, POST"), headers)

    def test_verify_unsupported_methods_return_405_with_allow(self) -> None:
        for method in ("GET", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, headers, body = call_json(
                    method,
                    f"/resources/{self.resource_id}/signatures/verify",
                )
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")
                self.assertIn(("Allow", "POST"), headers)

    def test_failed_requests_leave_no_record(self) -> None:
        call_json(
            "POST", f"/resources/{self.resource_id}/signatures", b"not json"
        )
        self._register(payload=signature_payload(signer=""))
        self._register(payload=signature_payload(algorithm="hmac-md5"))
        self._register(payload=signature_payload(signature="x"))
        self._register(payload={"signer": "a"})
        call_json("GET", "/resources/missing/signatures")
        call_json("POST", "/resources/missing/signatures/verify")
        _s, _h, body = call_json(
            "GET", f"/resources/{self.resource_id}/signatures"
        )
        self.assertEqual(body["error"], "signature_not_found")

    def test_failed_conflict_does_not_change_other_state(self) -> None:
        self._register(payload=signature_payload(signer="first"))
        self._register(payload=signature_payload(signer="second"))
        status, _h, body = call_json(
            "GET", f"/resources/{self.resource_id}"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["id"], self.resource_id)
        _s, _h, record = call_json(
            "GET", f"/resources/{self.resource_id}/signatures"
        )
        self.assertEqual(record["signer"], "first")

    def test_key_id_bytes_are_utf8(self) -> None:
        # Non-ASCII key id: the HMAC key is its UTF-8 byte sequence.
        key_id = "密钥🔑"
        expected = hmac.new(
            key_id.encode("utf-8"),
            DIGEST_A.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        self._register(
            payload=signature_payload(key_id=key_id, signature=expected)
        )
        status, _h, body = call_json(
            "POST", f"/resources/{self.resource_id}/signatures/verify"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["valid"], True)


if __name__ == "__main__":
    unittest.main()
