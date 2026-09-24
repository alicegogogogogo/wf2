from __future__ import annotations

import hashlib
import io
import json
import unittest

from provenance_api.app import application, store

DIGEST_A = "a" * 64


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

    chunks = application(environ, start_response)
    return str(captured["status"]), list(captured["headers"]), b"".join(chunks)


def chunk_headers(total: str | int, digest: str) -> dict[str, str]:
    return {
        "CONTENT_TYPE": "application/octet-stream",
        "HTTP_X_CHUNK_TOTAL": str(total),
        "HTTP_X_CONTENT_DIGEST": digest,
    }


class ContentLayerTests(unittest.TestCase):
    def setUp(self) -> None:
        store.reset()

    def _create(self, digest: str) -> str:
        body = json.dumps(
            {"name": "r", "category": "code", "digest": digest}
        ).encode("utf-8")
        environ: dict[str, object] = {
            "REQUEST_METHOD": "POST",
            "PATH_INFO": "/resources",
            "CONTENT_LENGTH": str(len(body)),
            "CONTENT_TYPE": "application/json",
            "wsgi.input": io.BytesIO(body),
        }
        captured: dict[str, object] = {}
        raw = b"".join(
            application(
                environ,
                lambda s, h: captured.update(status=s, headers=h),
            )
        )
        return str(json.loads(raw)["id"])

    def _put_chunk(
        self,
        resource_id: str,
        index: int | str,
        data: bytes,
        total: str | int = "3",
        digest: str | None = None,
        **kwargs: object,
    ) -> tuple[str, list[tuple[str, str]], bytes]:
        return call(
            "PUT",
            f"/resources/{resource_id}/chunks/{index}",
            data,
            headers=chunk_headers(total, digest if digest is not None else self.digest),
            **kwargs,
        )

    parts = (b"hello ", b"chunked ", b"world")

    @property
    def content(self) -> bytes:
        return b"".join(self.parts)

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.content).hexdigest()

    # --- Upload -------------------------------------------------------------

    def test_first_chunks_return_201_with_metadata(self) -> None:
        rid = self._create(self.digest)
        status, headers, raw = self._put_chunk(rid, 0, self.parts[0])
        self.assertEqual(status, "201 Created")
        self.assertEqual(
            headers[0], ("Content-Type", "application/json; charset=utf-8")
        )
        body = json.loads(raw)
        self.assertEqual(
            body,
            {
                "id": rid,
                "chunk_index": 0,
                "total_chunks": 3,
                "digest": self.digest,
            },
        )
        self.assertTrue(raw.endswith(b"\n"))

    def test_response_is_compact_with_stable_key_order(self) -> None:
        rid = self._create(self.digest)
        _s, _h, raw = self._put_chunk(rid, 0, self.parts[0])
        text = raw.decode("utf-8").rstrip("\n")
        self.assertNotIn(" ", text)
        self.assertLess(text.index('"id"'), text.index('"chunk_index"'))
        self.assertLess(text.index('"chunk_index"'), text.index('"total_chunks"'))
        self.assertLess(text.index('"total_chunks"'), text.index('"digest"'))

    def test_zero_length_chunk_is_accepted(self) -> None:
        rid = self._create(self.digest)
        status, _h, raw = self._put_chunk(rid, 0, b"")
        self.assertEqual(status, "201 Created")
        self.assertEqual(json.loads(raw)["chunk_index"], 0)

    def test_uppercase_digest_header_is_normalized(self) -> None:
        rid = self._create(self.digest)
        status, _h, raw = self._put_chunk(
            rid, 0, self.parts[0], digest=self.digest.upper()
        )
        self.assertEqual(status, "201 Created")
        self.assertEqual(json.loads(raw)["digest"], self.digest)

    # --- Idempotency and conflicts -----------------------------------------

    def test_identical_resubmission_is_idempotent_200(self) -> None:
        rid = self._create(self.digest)
        self._put_chunk(rid, 1, self.parts[1])
        status, _h, raw = self._put_chunk(rid, 1, self.parts[1])
        self.assertEqual(status, "200 OK")
        body = json.loads(raw)
        self.assertEqual(body["chunk_index"], 1)
        self.assertEqual(body["digest"], self.digest)

    def test_different_bytes_same_index_is_chunk_conflict(self) -> None:
        rid = self._create(self.digest)
        self._put_chunk(rid, 1, self.parts[1])
        status, _h, body = self._put_chunk(rid, 1, b"different bytes!!")
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(json.loads(body)["error"], "chunk_conflict")

    def test_later_metadata_difference_is_chunk_conflict(self) -> None:
        rid = self._create(self.digest)
        self._put_chunk(rid, 0, self.parts[0])
        # A different total must be rejected; the stored fragment is untouched.
        status, _h, body = self._put_chunk(
            rid, 1, self.parts[1], total=4
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(json.loads(body)["error"], "chunk_conflict")
        # Same index/bytes with matching metadata remains idempotent.
        status, _h, _raw = self._put_chunk(rid, 0, self.parts[0])
        self.assertEqual(status, "200 OK")

    def test_digest_differing_from_registry_is_digest_conflict_even_later(self) -> None:
        rid = self._create(self.digest)
        self._put_chunk(rid, 0, self.parts[0])
        # A later header digest that disagrees with the registered digest is a
        # digest_conflict, never a chunk_conflict, and stores nothing.
        status, _h, body = self._put_chunk(
            rid, 1, self.parts[1], digest=hashlib.sha256(b"other").hexdigest()
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(json.loads(body)["error"], "digest_conflict")

    def test_declared_digest_differing_from_registry_is_digest_conflict(self) -> None:
        rid = self._create(DIGEST_A)
        status, _h, body = self._put_chunk(
            rid, 0, self.parts[0], digest=self.digest
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(json.loads(body)["error"], "digest_conflict")
        # No fragment stored: assembly cannot progress.
        status, _h, body = call("POST", f"/resources/{rid}/assemble")
        self.assertEqual(json.loads(body)["error"], "chunks_incomplete")

    # --- Assembly -----------------------------------------------------------

    def test_assemble_concatenates_in_order_and_reports_digest_size(self) -> None:
        rid = self._create(self.digest)
        # Submit out of order; assembly must still concatenate by index.
        for index in (2, 0, 1):
            status, _h, _b = self._put_chunk(rid, index, self.parts[index])
            self.assertEqual(status, "201 Created")
        status, headers, raw = call("POST", f"/resources/{rid}/assemble")
        self.assertEqual(status, "201 Created")
        self.assertEqual(
            headers[0], ("Content-Type", "application/json; charset=utf-8")
        )
        body = json.loads(raw)
        self.assertEqual(body, {"id": rid, "digest": self.digest, "size": 19})
        self.assertTrue(raw.endswith(b"\n"))

    def test_assemble_before_all_chunks_is_incomplete_and_keeps_fragments(self) -> None:
        rid = self._create(self.digest)
        self._put_chunk(rid, 0, self.parts[0])
        self._put_chunk(rid, 2, self.parts[2])
        status, _h, body = call("POST", f"/resources/{rid}/assemble")
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(json.loads(body)["error"], "chunks_incomplete")
        # Received fragments are retained and still idempotent afterwards.
        status, _h, _raw = self._put_chunk(rid, 0, self.parts[0])
        self.assertEqual(status, "200 OK")
        # Completing the missing chunk now assembles successfully.
        self._put_chunk(rid, 1, self.parts[1])
        status, _h, body = call("POST", f"/resources/{rid}/assemble")
        self.assertEqual(status, "201 Created")
        self.assertEqual(json.loads(body)["digest"], self.digest)

    def test_assemble_digest_mismatch_does_not_finish_content(self) -> None:
        rid = self._create(hashlib.sha256(b"promised").hexdigest())
        self._put_chunk(
            rid, 0, b"actual",
            total=1, digest=hashlib.sha256(b"promised").hexdigest(),
        )
        status, _h, body = call("POST", f"/resources/{rid}/assemble")
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(json.loads(body)["error"], "digest_mismatch")
        # Fragments remain, content is not readable and assembly can be retried.
        status, _h, body = call("GET", f"/resources/{rid}/content")
        self.assertEqual(json.loads(body)["error"], "content_not_complete")
        status, _h, body = call("POST", f"/resources/{rid}/assemble")
        self.assertEqual(json.loads(body)["error"], "digest_mismatch")

    def test_post_complete_upload_and_assemble_are_rejected(self) -> None:
        rid = self._create(self.digest)
        for index, part in enumerate(self.parts):
            self._put_chunk(rid, index, part)
        status, _h, _b = call("POST", f"/resources/{rid}/assemble")
        self.assertEqual(status, "201 Created")

        status, _h, body = self._put_chunk(rid, 0, self.parts[0])
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(json.loads(body)["error"], "content_already_complete")
        # Even a stale digest header on a finished resource reports completion.
        status, _h, body = self._put_chunk(
            rid, 0, self.parts[0], digest=DIGEST_A
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(json.loads(body)["error"], "content_already_complete")
        status, _h, body = call("POST", f"/resources/{rid}/assemble")
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(json.loads(body)["error"], "content_already_complete")

    # --- Reading ------------------------------------------------------------

    def test_read_returns_exact_raw_bytes(self) -> None:
        rid = self._create(self.digest)
        for index, part in enumerate(self.parts):
            self._put_chunk(rid, index, part)
        call("POST", f"/resources/{rid}/assemble")
        status, headers, raw = call("GET", f"/resources/{rid}/content")
        self.assertEqual(status, "200 OK")
        self.assertIn(("Content-Type", "application/octet-stream"), headers)
        self.assertIn(("Content-Length", str(len(self.content))), headers)
        self.assertEqual(raw, self.content)
        # Raw bytes only: no JSON framing or trailing newline.
        self.assertFalse(raw.endswith(b"\n"))

    def test_read_empty_content_round_trips(self) -> None:
        empty_digest = hashlib.sha256(b"").hexdigest()
        rid = self._create(empty_digest)
        status, _h, _b = self._put_chunk(
            rid, 0, b"", total=1, digest=empty_digest
        )
        self.assertEqual(status, "201 Created")
        status, _h, body = call("POST", f"/resources/{rid}/assemble")
        self.assertEqual(status, "201 Created")
        self.assertEqual(json.loads(body), {"id": rid, "digest": empty_digest, "size": 0})
        status, headers, raw = call("GET", f"/resources/{rid}/content")
        self.assertEqual(status, "200 OK")
        self.assertIn(("Content-Length", "0"), headers)
        self.assertEqual(raw, b"")

    def test_read_before_completion_is_content_not_complete(self) -> None:
        rid = self._create(self.digest)
        status, _h, body = call("GET", f"/resources/{rid}/content")
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(json.loads(body)["error"], "content_not_complete")

    def test_read_unknown_resource_is_not_found(self) -> None:
        status, _h, body = call("GET", "/resources/missing/content")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(json.loads(body)["error"], "resource_not_found")

    # --- Bad requests -------------------------------------------------------

    def test_missing_or_illegal_identifier_is_bad_request(self) -> None:
        for method, path in [
            ("PUT", "/resources//chunks/0"),
            ("POST", "/resources//assemble"),
            ("GET", "/resources//content"),
        ]:
            with self.subTest(path=path):
                status, _h, body = call(method, path, b"x")
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(json.loads(body)["error"], "invalid_request")

    def test_query_parameters_are_bad_request(self) -> None:
        rid = self._create(self.digest)
        for method, path, body in [
            ("PUT", f"/resources/{rid}/chunks/0", b"x"),
            ("POST", f"/resources/{rid}/assemble", b""),
            ("GET", f"/resources/{rid}/content", b""),
        ]:
            with self.subTest(path=path):
                status, _h, payload = call(
                    method, path, body, query_string="bogus=1"
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(json.loads(payload)["error"], "invalid_request")

    def test_illegal_chunk_index_is_bad_request(self) -> None:
        rid = self._create(self.digest)
        for index in ("", "-1", "1.5", "01", "abc", " 1"):
            with self.subTest(index=index):
                status, _h, body = self._put_chunk(rid, index, b"x")  # type: ignore[arg-type]
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(json.loads(body)["error"], "invalid_request")
        # Out of range relative to the declared positive total is also 400.
        status, _h, body = self._put_chunk(rid, 3, b"x", total=3)
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(json.loads(body)["error"], "invalid_request")

    def test_missing_or_illegal_total_header_is_bad_request(self) -> None:
        rid = self._create(self.digest)
        base = chunk_headers(3, self.digest)
        for value in (None, "", "0", "-1", "1.5", "abc", "01"):
            with self.subTest(value=value):
                headers = dict(base)
                if value is None:
                    del headers["HTTP_X_CHUNK_TOTAL"]
                else:
                    headers["HTTP_X_CHUNK_TOTAL"] = value
                status, _h, body = call(
                    "PUT", f"/resources/{rid}/chunks/0", b"x", headers=headers
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(json.loads(body)["error"], "invalid_request")

    def test_missing_or_illegal_digest_header_is_bad_request(self) -> None:
        rid = self._create(self.digest)
        for value in (None, "", "z" * 64, "a" * 63, "g" * 64):
            with self.subTest(value=value):
                headers = {
                    "CONTENT_TYPE": "application/octet-stream",
                    "HTTP_X_CHUNK_TOTAL": "3",
                }
                if value is not None:
                    headers["HTTP_X_CONTENT_DIGEST"] = value
                status, _h, body = call(
                    "PUT", f"/resources/{rid}/chunks/0", b"x", headers=headers
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(json.loads(body)["error"], "invalid_request")

    def test_content_type_must_be_octet_stream(self) -> None:
        rid = self._create(self.digest)
        for content_type in (
            "application/json",
            "text/plain",
            "application/octet-stream; charset=binary",
        ):
            with self.subTest(content_type=content_type):
                headers = chunk_headers(3, self.digest)
                headers["CONTENT_TYPE"] = content_type
                status, _h, body = call(
                    "PUT", f"/resources/{rid}/chunks/0", b"x", headers=headers
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(json.loads(body)["error"], "invalid_request")

    def test_content_length_problems_are_bad_request(self) -> None:
        rid = self._create(self.digest)
        # Missing.
        status, _h, body = self._put_chunk(
            rid, 0, self.parts[0], omit_content_length=True
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(json.loads(body)["error"], "invalid_request")
        # Malformed.
        status, _h, body = self._put_chunk(
            rid, 0, self.parts[0], content_length="nope"
        )
        self.assertEqual(status, "400 Bad Request")
        # Declared longer than the available stream.
        status, _h, body = self._put_chunk(
            rid, 0, self.parts[0], content_length=999
        )
        self.assertEqual(status, "400 Bad Request")

    def test_chunk_upload_to_unknown_resource_is_not_found(self) -> None:
        status, _h, body = call(
            "PUT",
            "/resources/missing/chunks/0",
            b"x",
            headers=chunk_headers(1, DIGEST_A),
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(json.loads(body)["error"], "resource_not_found")

    def test_assemble_unknown_resource_is_not_found(self) -> None:
        status, _h, body = call("POST", "/resources/missing/assemble")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(json.loads(body)["error"], "resource_not_found")

    def test_failed_upload_leaves_no_fragment(self) -> None:
        rid = self._create(self.digest)
        # Illegal index: rejected before any state is touched.
        self._put_chunk(rid, "bad", b"x")  # type: ignore[arg-type]
        # Conflicting digest: nothing is stored for any index.
        self._put_chunk(rid, 0, b"x", digest=DIGEST_A)
        status, _h, body = call("POST", f"/resources/{rid}/assemble")
        self.assertEqual(json.loads(body)["error"], "chunks_incomplete")
        # A valid chunk 0 still returns 201 (the failed attempts stored nothing).
        status, _h, _b = self._put_chunk(rid, 0, self.parts[0])
        self.assertEqual(status, "201 Created")

    # --- Method handling ----------------------------------------------------

    def test_unsupported_methods_return_405_with_allow(self) -> None:
        rid = self._create(self.digest)
        cases = [
            ("POST", f"/resources/{rid}/chunks/0", "PUT"),
            ("GET", f"/resources/{rid}/chunks/0", "PUT"),
            ("GET", f"/resources/{rid}/assemble", "POST"),
            ("DELETE", f"/resources/{rid}/assemble", "POST"),
            ("POST", f"/resources/{rid}/content", "GET"),
            ("DELETE", f"/resources/{rid}/content", "GET"),
        ]
        for method, path, allow in cases:
            with self.subTest(method=method, path=path):
                status, headers, body = call(method, path)
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(json.loads(body)["error"], "method_not_allowed")
                self.assertIn(("Allow", allow), headers)


if __name__ == "__main__":
    unittest.main()
