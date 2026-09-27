from __future__ import annotations

import hashlib
import hmac
import io
import json
import unittest

from provenance_api.app import application, reset_state
from provenance_api.signatures import SignatureRecord, summarize_key_usage

PATH = "/signature-keys"

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_D = "d" * 64


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


class GlobalSignatureKeysSummaryTests(unittest.TestCase):
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
    ) -> None:
        payload = {
            "signer": signer,
            "algorithm": algorithm,
            "key_id": key_id,
            "signature": sign(algorithm, key_id, digest),
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

    def test_empty_when_no_signatures(self) -> None:
        self._create(DIGEST_A, "r1")
        self._create(DIGEST_B, "r2")
        status, _h, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

    def test_record_key_order_is_fixed(self) -> None:
        resource_id = self._create(DIGEST_A, "r1")
        self._register_signature(resource_id, key_id="secret")

        status, _h, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        text = raw.decode("utf-8").rstrip("\n")
        # Compact UTF-8: no added whitespace.
        self.assertNotIn(" ", text)
        self.assertLess(text.index('"key_id"'), text.index('"algorithms"'))
        self.assertLess(text.index('"algorithms"'), text.index('"signers"'))
        self.assertLess(
            text.index('"signers"'), text.index('"signature_count"')
        )
        self.assertLess(
            text.index('"signature_count"'), text.index('"resources"')
        )

        entry = self._summary()[0]
        self.assertEqual(
            list(entry),
            [
                "key_id",
                "algorithms",
                "signers",
                "signature_count",
                "resources",
            ],
        )
        self.assertEqual(entry["key_id"], "secret")
        self.assertEqual(entry["algorithms"], ["hmac-sha256"])
        self.assertEqual(entry["signers"], ["alice"])
        self.assertEqual(entry["signature_count"], 1)
        self.assertEqual(entry["resources"], [resource_id])

    def test_aggregates_records_by_key_id(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        r3 = self._create(DIGEST_C, "r3")
        self._register_signature(r1, key_id="k1", digest=DIGEST_A)
        self._register_signature(
            r2,
            signer="bob",
            algorithm="hmac-sha512",
            key_id="k2",
            digest=DIGEST_B,
        )
        self._register_signature(
            r3,
            signer="carol",
            algorithm="hmac-sha512",
            key_id="k1",
            digest=DIGEST_C,
        )

        summary = self._summary()
        self.assertEqual([entry["key_id"] for entry in summary], ["k1", "k2"])

        k1, k2 = summary
        self.assertEqual(
            k1,
            {
                "key_id": "k1",
                "algorithms": ["hmac-sha256", "hmac-sha512"],
                "signers": ["alice", "carol"],
                "signature_count": 2,
                "resources": [r1, r3],
            },
        )
        self.assertEqual(
            k2,
            {
                "key_id": "k2",
                "algorithms": ["hmac-sha512"],
                "signers": ["bob"],
                "signature_count": 1,
                "resources": [r2],
            },
        )

    def test_lists_deduplicate_in_first_appearance_order(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        r3 = self._create(DIGEST_C, "r3")
        r4 = self._create(DIGEST_D, "r4")
        self._register_signature(
            r1, signer="alice", algorithm="hmac-sha256", key_id="k",
            digest=DIGEST_A,
        )
        self._register_signature(
            r2, signer="bob", algorithm="hmac-sha512", key_id="k",
            digest=DIGEST_B,
        )
        # Repeat signer and algorithm: neither list gains a second item.
        self._register_signature(
            r3, signer="alice", algorithm="hmac-sha256", key_id="k",
            digest=DIGEST_C,
        )
        self._register_signature(
            r4, signer="bob", algorithm="hmac-sha256", key_id="k",
            digest=DIGEST_D,
        )

        entry = self._summary()[0]
        self.assertEqual(entry["algorithms"], ["hmac-sha256", "hmac-sha512"])
        self.assertEqual(entry["signers"], ["alice", "bob"])
        self.assertEqual(entry["signature_count"], 4)
        self.assertEqual(entry["resources"], [r1, r2, r3, r4])

    def test_signer_text_is_echoed_verbatim(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        self._register_signature(r1, signer=" 签名者-X ", key_id="密钥-1")

        entry = self._summary()[0]
        self.assertEqual(entry["key_id"], "密钥-1")
        self.assertEqual(entry["signers"], [" 签名者-X "])

    # --- Ordering ----------------------------------------------------------

    def test_entries_follow_first_key_appearance_in_resource_order(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        r3 = self._create(DIGEST_C, "r3")

        # Signatures are registered out of resource order: r3 (key-beta)
        # first, then r1 (key-alpha), then r2 (key-beta again). The
        # summary iterates resources in registration order, so key-alpha
        # first appears at r1 and sorts ahead of key-beta first seen at r3.
        self._register_signature(
            r3, signer="s3", key_id="key-beta", digest=DIGEST_C
        )
        self._register_signature(
            r1, signer="s1", key_id="key-alpha", digest=DIGEST_A
        )
        self._register_signature(
            r2, signer="s2", key_id="key-beta", digest=DIGEST_B
        )

        summary = self._summary()
        self.assertEqual(
            [entry["key_id"] for entry in summary], ["key-alpha", "key-beta"]
        )
        alpha, beta = summary
        self.assertEqual(alpha["resources"], [r1])
        self.assertEqual(beta["resources"], [r2, r3])
        self.assertEqual(beta["signers"], ["s2", "s3"])
        self.assertEqual(beta["signature_count"], 2)

    def test_resources_follow_resource_registration_order(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        r3 = self._create(DIGEST_C, "r3")
        self._register_signature(r2, key_id="k", digest=DIGEST_B)
        self._register_signature(r3, key_id="k", digest=DIGEST_C)
        self._register_signature(r1, key_id="k", digest=DIGEST_A)

        entry = self._summary()[0]
        self.assertEqual(entry["resources"], [r1, r2, r3])

    def test_each_key_appears_at_most_once(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        self._register_signature(r1, key_id="k")
        # An idempotent repeat registration creates no second signature.
        payload = {
            "signer": "alice",
            "algorithm": "hmac-sha256",
            "key_id": "k",
            "signature": sign("hmac-sha256", "k", DIGEST_A),
            "digest": DIGEST_A,
        }
        status, _h, _b = call("POST", f"/resources/{r1}/signatures", payload)
        self.assertEqual(status, "200 OK")
        summary = self._summary()
        self.assertEqual(len(summary), 1)
        self.assertEqual(summary[0]["signature_count"], 1)
        self.assertEqual(summary[0]["resources"], [r1])

    # --- Recomputation -----------------------------------------------------

    def test_recomputes_after_new_registration(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        self._register_signature(r1, key_id="k1", digest=DIGEST_A)
        self.assertEqual(
            [e["key_id"] for e in self._summary()], ["k1"]
        )

        self._register_signature(
            r2, signer="bob", key_id="k2", digest=DIGEST_B
        )
        self.assertEqual(
            [e["key_id"] for e in self._summary()], ["k1", "k2"]
        )

    def test_resource_deregistration_updates_counts_and_drops_empty_keys(
        self,
    ) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        r3 = self._create(DIGEST_C, "r3")
        self._register_signature(r1, key_id="k1", digest=DIGEST_A)
        self._register_signature(
            r2,
            signer="bob",
            algorithm="hmac-sha512",
            key_id="k2",
            digest=DIGEST_B,
        )
        self._register_signature(r3, key_id="k1", digest=DIGEST_C)

        status, _h, _b = call("DELETE", f"/resources/{r2}")
        self.assertEqual(status, "200 OK")

        # k2 has no signature left: its entry disappears entirely; k1 is
        # recomputed from the remaining data without any trace of r2.
        summary = self._summary()
        self.assertEqual([e["key_id"] for e in summary], ["k1"])
        self.assertEqual(
            summary[0],
            {
                "key_id": "k1",
                "algorithms": ["hmac-sha256"],
                "signers": ["alice"],
                "signature_count": 2,
                "resources": [r1, r3],
            },
        )

        # Removing the last k1 signature empties the whole view.
        status, _h, _b = call("DELETE", f"/resources/{r1}")
        self.assertEqual(status, "200 OK")
        status, _h, _b = call("DELETE", f"/resources/{r3}")
        self.assertEqual(status, "200 OK")
        status, _h, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

    def test_view_is_read_only(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        self._register_signature(r1, key_id="secret")
        first_status, _h, first = call("GET", PATH)
        second_status, _h, second = call("GET", PATH)
        self.assertEqual(first_status, second_status)
        self.assertEqual(first, second)

    def test_signature_endpoints_unchanged(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        self._register_signature(r1, key_id="secret")

        # Querying the new view leaves the per-resource signature intact.
        self._summary()
        status, _h, body = call_json("GET", f"/resources/{r1}/signatures")
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["id"], r1)  # type: ignore[index]
        self.assertEqual(body["key_id"], "secret")  # type: ignore[index]

        status, _h, body = call_json(
            "POST", f"/resources/{r1}/signatures/verify"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, {"id": r1, "valid": True})

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
        self._register_signature(r1)
        for query in ("x=1", "key_id=k", "?", "limit=50", "signer=alice"):
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


def _record(
    signer: str, algorithm: str, key_id: str = "k"
) -> SignatureRecord:
    digest = "a" * 64
    return SignatureRecord(
        signer=signer,
        algorithm=algorithm,
        key_id=key_id,
        signature=sign(algorithm, key_id, digest),
        digest=digest,
    )


class SummarizeKeyUsageUnitTests(unittest.TestCase):
    """Direct coverage of the pure aggregation semantics."""

    def test_empty_input_returns_empty_list(self) -> None:
        self.assertEqual(summarize_key_usage([]), [])

    def test_groups_and_orders_by_first_key_appearance(self) -> None:
        entries = [
            ("r1", _record("alice", "hmac-sha256", "beta")),
            ("r2", _record("bob", "hmac-sha512", "alpha")),
            ("r3", _record("carol", "hmac-sha256", "beta")),
        ]
        result = summarize_key_usage(entries)
        self.assertEqual([item["key_id"] for item in result], ["beta", "alpha"])
        self.assertEqual(
            result[0],
            {
                "key_id": "beta",
                "algorithms": ["hmac-sha256"],
                "signers": ["alice", "carol"],
                "signature_count": 2,
                "resources": ["r1", "r3"],
            },
        )

    def test_algorithms_and_signers_dedup_in_first_seen_order(self) -> None:
        entries = [
            ("r1", _record("alice", "hmac-sha256")),
            ("r2", _record("bob", "hmac-sha512")),
            ("r3", _record("alice", "hmac-sha512")),
            ("r4", _record("bob", "hmac-sha256")),
        ]
        result = summarize_key_usage(entries)
        self.assertEqual(
            result[0]["algorithms"], ["hmac-sha256", "hmac-sha512"]
        )
        self.assertEqual(result[0]["signers"], ["alice", "bob"])
        self.assertEqual(result[0]["signature_count"], 4)
        self.assertEqual(result[0]["resources"], ["r1", "r2", "r3", "r4"])

    def test_values_are_copied_so_callers_cannot_mutate_summary(self) -> None:
        result = summarize_key_usage([("r1", _record("alice", "hmac-sha256"))])
        result[0]["algorithms"].append("hmac-sha512")
        result[0]["resources"].append("r2")
        again = summarize_key_usage(
            [("r1", _record("alice", "hmac-sha256"))]
        )
        self.assertEqual(again[0]["algorithms"], ["hmac-sha256"])
        self.assertEqual(again[0]["resources"], ["r1"])


if __name__ == "__main__":
    unittest.main()
