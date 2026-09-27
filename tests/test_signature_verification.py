from __future__ import annotations

import hashlib
import hmac
import io
import json
import unittest

from provenance_api.app import application, reset_state

PATH = "/signature-verification"

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64


def call(
    method: str,
    path: str = PATH,
    body: bytes | str | dict[str, object] | None = None,
    *,
    query_string: str | None = None,
    content_type: str | None = None,
    content_length: int | str | None = None,
    omit_content_length: bool = False,
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
        "wsgi.input": io.BytesIO(payload),
    }
    if not omit_content_length:
        environ["CONTENT_LENGTH"] = (
            str(len(payload)) if content_length is None else str(content_length)
        )
    if content_type is not None:
        environ["CONTENT_TYPE"] = content_type
    captured: dict[str, object] = {}

    def start_response(status: str, headers: list[tuple[str, str]]) -> None:
        captured["status"] = status
        captured["headers"] = headers

    chunks = application(environ, start_response)
    return str(captured["status"]), list(captured["headers"]), b"".join(chunks)


def call_json(
    method: str,
    path: str = PATH,
    body: bytes | str | dict[str, object] | None = None,
    *,
    query_string: str | None = None,
    content_type: str | None = None,
    content_length: int | str | None = None,
    omit_content_length: bool = False,
) -> tuple[str, list[tuple[str, str]], object]:
    status, headers, raw = call(
        method,
        path,
        body,
        query_string=query_string,
        content_type=content_type,
        content_length=content_length,
        omit_content_length=omit_content_length,
    )
    return status, headers, json.loads(raw.decode("utf-8"))


def sign(algorithm: str, key_id: str, digest: str) -> str:
    """Reference HMAC over the lowercase digest text, keyed by key bytes."""

    return hmac.new(
        key_id.encode("utf-8"),
        digest.lower().encode("ascii"),
        hashlib.sha512 if algorithm == "hmac-sha512" else hashlib.sha256,
    ).hexdigest()


class GlobalSignatureVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def _create(self, digest: str, name: str) -> str:
        _s, _h, body = call_json(
            "POST",
            "/resources",
            {"name": name, "category": "code", "digest": digest},
        )
        return str(body["id"])  # type: ignore[index]

    def _register_signature(
        self,
        resource_id: str,
        *,
        signer: str = "alice",
        algorithm: str = "hmac-sha256",
        key_id: str = "key-001",
        digest: str = DIGEST_A,
        signature: str | None = None,
    ) -> None:
        payload = {
            "signer": signer,
            "algorithm": algorithm,
            "key_id": key_id,
            "signature": (
                signature
                if signature is not None
                else sign(algorithm, key_id, digest)
            ),
            "digest": digest,
        }
        status, _h, body = call_json(
            "POST", f"/resources/{resource_id}/signatures", payload
        )
        assert status == "201 Created", body

    def _summary(self) -> list[dict[str, object]]:
        status, headers, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )
        self.assertTrue(raw.endswith(b"\n"))
        body = json.loads(raw)
        self.assertIsInstance(body, list)
        return body  # type: ignore[return-value]

    # --- Shape -------------------------------------------------------------

    def test_empty_when_no_resources(self) -> None:
        status, headers, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )

    def test_resource_without_signature_gets_null_fields(self) -> None:
        resource_id = self._create(DIGEST_A, "r1")
        entry = self._summary()[0]
        self.assertEqual(
            entry,
            {
                "id": resource_id,
                "signer": None,
                "algorithm": None,
                "key_id": None,
                "valid": False,
                "reason": "signature_not_found",
            },
        )

    def test_record_key_order_is_fixed(self) -> None:
        resource_id = self._create(DIGEST_A, "r1")
        self._register_signature(resource_id, digest=DIGEST_A)

        status, _h, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        text = raw.decode("utf-8").rstrip("\n")
        # Compact UTF-8: no added whitespace.
        self.assertNotIn(" ", text)
        self.assertLess(text.index('"id"'), text.index('"signer"'))
        self.assertLess(text.index('"signer"'), text.index('"algorithm"'))
        self.assertLess(text.index('"algorithm"'), text.index('"key_id"'))
        self.assertLess(text.index('"key_id"'), text.index('"valid"'))
        self.assertLess(text.index('"valid"'), text.index('"reason"'))

        entry = self._summary()[0]
        self.assertEqual(
            list(entry),
            ["id", "signer", "algorithm", "key_id", "valid", "reason"],
        )
        self.assertEqual(
            entry,
            {
                "id": resource_id,
                "signer": "alice",
                "algorithm": "hmac-sha256",
                "key_id": "key-001",
                "valid": True,
                "reason": None,
            },
        )

    def test_valid_signature_verifies_true(self) -> None:
        resource_id = self._create(DIGEST_B, "r1")
        self._register_signature(
            resource_id,
            signer="bob",
            algorithm="hmac-sha512",
            key_id="key-9",
            digest=DIGEST_B,
        )
        entry = self._summary()[0]
        self.assertEqual(entry["valid"], True)
        self.assertEqual(entry["reason"], None)
        self.assertEqual(entry["signer"], "bob")
        self.assertEqual(entry["algorithm"], "hmac-sha512")
        self.assertEqual(entry["key_id"], "key-9")

    def test_invalid_signature_verifies_false_with_null_reason(self) -> None:
        resource_id = self._create(DIGEST_A, "r1")
        # A well-formed signature that does not match the recomputed HMAC.
        self._register_signature(
            resource_id, digest=DIGEST_A, signature="0" * 64
        )
        entry = self._summary()[0]
        self.assertEqual(entry["valid"], False)
        self.assertEqual(entry["reason"], None)

    def test_signed_digest_mismatch_is_per_entry_false(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        # r1's signature signs a digest different from the registered one.
        self._register_signature(r1, digest=DIGEST_C)
        self._register_signature(r2, digest=DIGEST_B)

        summary = self._summary()
        self.assertEqual(len(summary), 2)
        self.assertEqual(summary[0]["id"], r1)
        self.assertEqual(summary[0]["valid"], False)
        self.assertEqual(summary[0]["reason"], "signed_digest_mismatch")
        # The signature fields are still echoed from the record.
        self.assertEqual(summary[0]["signer"], "alice")
        self.assertEqual(summary[0]["algorithm"], "hmac-sha256")
        self.assertEqual(summary[0]["key_id"], "key-001")
        # The mismatch is a finding, not a summary-level error.
        self.assertEqual(summary[1]["id"], r2)
        self.assertEqual(summary[1]["valid"], True)
        self.assertEqual(summary[1]["reason"], None)

    # --- Ordering ----------------------------------------------------------

    def test_entries_follow_resource_registration_order(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        r3 = self._create(DIGEST_C, "r3")

        # Signatures are registered in the opposite resource order; the
        # summary must still unfold in resource registration order.
        self._register_signature(r3, digest=DIGEST_C)
        self._register_signature(r1, digest=DIGEST_A)

        summary = self._summary()
        self.assertEqual(
            [item["id"] for item in summary], [r1, r2, r3]
        )
        self.assertEqual(summary[1]["reason"], "signature_not_found")

    def test_each_resource_appears_exactly_once(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        self._register_signature(r1)
        # An idempotent repeat registration must not create a second entry.
        payload = {
            "signer": "alice",
            "algorithm": "hmac-sha256",
            "key_id": "key-001",
            "signature": sign("hmac-sha256", "key-001", DIGEST_A),
            "digest": DIGEST_A,
        }
        status, _h, _b = call("POST", f"/resources/{r1}/signatures", payload)
        self.assertEqual(status, "200 OK")
        self.assertEqual([item["id"] for item in self._summary()], [r1])

    # --- Recomputation -----------------------------------------------------

    def test_recomputes_after_new_registration(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        self.assertEqual(
            [item["reason"] for item in self._summary()],
            ["signature_not_found"],
        )
        self._register_signature(r1, digest=DIGEST_A)
        entry = self._summary()[0]
        self.assertEqual(entry["valid"], True)
        self.assertEqual(entry["reason"], None)

    def test_resource_deregistration_removes_its_entry(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        self._register_signature(r1, digest=DIGEST_A)
        self._register_signature(r2, digest=DIGEST_B)

        status, _h, _b = call("DELETE", f"/resources/{r1}")
        self.assertEqual(status, "200 OK")

        summary = self._summary()
        self.assertEqual([item["id"] for item in summary], [r2])
        self.assertEqual(summary[0]["valid"], True)

    def test_view_is_read_only(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        self._register_signature(r1, digest=DIGEST_A)
        first_status, _h, first = call("GET", PATH)
        second_status, _h, second = call("GET", PATH)
        self.assertEqual(first_status, second_status)
        self.assertEqual(first, second)

    def test_per_resource_views_unchanged(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        self._register_signature(r1, digest=DIGEST_A, key_id="secret")

        # The global summary does not disturb the per-resource signature.
        self._summary()
        status, _h, body = call_json("GET", f"/resources/{r1}/signatures")
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["id"], r1)  # type: ignore[index]
        self.assertEqual(body["key_id"], "secret")  # type: ignore[index]

        # Per-resource verification keeps its existing behavior, including
        # the 409 on a signed digest conflict.
        status, _h, body = call_json("POST", f"/resources/{r1}/signatures/verify")
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, {"id": r1, "valid": True})

        r2 = self._create(DIGEST_B, "r2")
        self._register_signature(r2, digest=DIGEST_C)
        status, _h, body = call_json("POST", f"/resources/{r2}/signatures/verify")
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "signed_digest_mismatch")  # type: ignore[index]

    # --- Errors ------------------------------------------------------------

    def test_non_get_methods_return_405_with_allow_get(self) -> None:
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            with self.subTest(method=method):
                status, headers, body = call_json(method, PATH)
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")  # type: ignore[index]
                allow_values = [
                    value for name, value in headers if name == "Allow"
                ]
                self.assertEqual(allow_values, ["GET"])

    def test_non_get_rejected_before_business_data(self) -> None:
        # A malformed body on POST must not leak into a 400: the method is
        # rejected first, without consulting any store.
        status, headers, body = call_json(
            "POST", PATH, body=b"nonsense", content_type="application/json"
        )
        self.assertEqual(status, "405 Method Not Allowed")
        self.assertEqual(body["error"], "method_not_allowed")  # type: ignore[index]
        self.assertEqual(
            [value for name, value in headers if name == "Allow"], ["GET"]
        )

    def test_non_empty_body_rejected(self) -> None:
        # A declared positive length is rejected even when GET carries no body.
        for kwargs in (
            {"body": b"{}"},
            {"body": b"", "content_length": 3},
            {"body": b"", "content_length": "abc"},
        ):
            with self.subTest(kwargs=kwargs):
                status, _h, raw = call("GET", PATH, **kwargs)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(json.loads(raw)["error"], "invalid_request")
                self.assertTrue(raw.endswith(b"\n"))

    def test_empty_body_accepted(self) -> None:
        # Omitted Content-Length and an explicit zero length are both fine.
        status, _h, raw = call("GET", PATH, omit_content_length=True)
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

        status, _h, raw = call("GET", PATH, body=b"", content_length=0)
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

        # An empty-string Content-Length (as some WSGI servers seed it) is
        # treated the same as an omitted header.
        status, _h, raw = call("GET", PATH, body=b"", content_length="")
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

    def test_any_query_parameter_rejected(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        self._register_signature(r1, digest=DIGEST_A)
        for query in ("signer=alice", "limit=1", "x=", "id=%s" % r1):
            with self.subTest(query=query):
                status, _h, body = call_json(
                    "GET", PATH, query_string=query
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")  # type: ignore[index]

    def test_error_body_uses_existing_shape(self) -> None:
        status, _h, raw = call("GET", PATH, query_string="x=1")
        self.assertEqual(status, "400 Bad Request")
        self.assertTrue(raw.endswith(b"\n"))
        text = raw.decode("utf-8").rstrip("\n")
        decoded = json.loads(text)
        self.assertEqual(set(decoded), {"error", "message"})
        self.assertEqual(decoded["error"], "invalid_request")
        # Compact separators: re-dumping with the service's separators
        # reproduces the body byte-for-byte.
        self.assertEqual(
            text,
            json.dumps(decoded, ensure_ascii=False, separators=(",", ":")),
        )


if __name__ == "__main__":
    unittest.main()
