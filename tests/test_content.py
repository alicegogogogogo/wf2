from __future__ import annotations

import hashlib
import io
import json
import unittest

from provenance_api.app import application, content_store, reset_state, store

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64


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


OCTET_HEADERS = {
    "CONTENT_TYPE": "application/octet-stream",
}


def chunk_headers(total: int | str, digest: str) -> dict[str, str]:
    return {
        "CONTENT_TYPE": "application/octet-stream",
        "HTTP_X_TOTAL_CHUNKS": str(total),
        "HTTP_X_CONTENT_DIGEST": digest,
    }


class ChunkFlowTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def _create(self, digest: str) -> str:
        body = json.dumps(
            {"name": "r", "category": "code", "digest": digest}
        ).encode("utf-8")
        _s, _h, raw = call("POST", "/resources", body, headers={"CONTENT_TYPE": "application/json"})
        return str(json.loads(raw)["id"])

    def _chunks(
        self, parts: list[bytes], resource_id: str | None = None
    ) -> tuple[str, str]:
        """Register and upload ``parts`` in order; return (resource id, digest)."""

        content = b"".join(parts)
        digest = hashlib.sha256(content).hexdigest()
        resource_id = resource_id or self._create(digest)
        total = len(parts)
        for index, part in enumerate(parts):
            status, _h, _b = call(
                "POST",
                f"/resources/{resource_id}/chunks/{index}",
                part,
                headers=chunk_headers(total, digest),
            )
            self.assertEqual(status, "201 Created")
        return resource_id, digest

    # --- Chunk upload ------------------------------------------------------

    def test_first_chunk_returns_201_with_fixed_shape(self) -> None:
        resource_id = self._create(DIGEST_A)
        status, headers, raw = call(
            "POST",
            f"/resources/{resource_id}/chunks/0",
            b"hello",
            headers=chunk_headers(2, DIGEST_A),
        )
        self.assertEqual(status, "201 Created")
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )
        body = json.loads(raw)
        self.assertEqual(body["id"], resource_id)
        self.assertEqual(body["index"], 0)
        self.assertEqual(body["total_chunks"], 2)
        self.assertEqual(body["received_chunks"], 1)
        self.assertEqual(body["digest"], DIGEST_A)
        self.assertTrue(raw.endswith(b"\n"))
        # Stable key order and compact JSON.
        text = raw.decode("utf-8").rstrip("\n")
        self.assertNotIn(" ", text)
        self.assertLess(text.index('"id"'), text.index('"index"'))
        self.assertLess(text.index('"index"'), text.index('"total_chunks"'))
        self.assertLess(text.index('"total_chunks"'), text.index('"received_chunks"'))
        self.assertLess(text.index('"received_chunks"'), text.index('"digest"'))

    def test_chunks_accepted_out_of_order(self) -> None:
        digest = hashlib.sha256(b"abcdef").hexdigest()
        resource_id = self._create(digest)
        for index, part in ((2, b"ef"), (0, b"ab"), (1, b"cd")):
            status, _h, body = call_json(
                "POST",
                f"/resources/{resource_id}/chunks/{index}",
                part,
                headers=chunk_headers(3, digest),
            )
            self.assertEqual(status, "201 Created")
            self.assertEqual(body["index"], index)
            self.assertEqual(body["received_chunks"], {2: 1, 0: 2, 1: 3}[index])

        status, _h, body = call_json(
            "POST", f"/resources/{resource_id}/assemble"
        )
        self.assertEqual(status, "201 Created")
        self.assertEqual(body["size"], 6)
        _s, _h, raw = call("GET", f"/resources/{resource_id}/content")
        self.assertEqual(raw, b"abcdef")

    def test_repeated_same_bytes_are_200_and_idempotent(self) -> None:
        resource_id = self._create(DIGEST_A)
        first = call_json(
            "POST",
            f"/resources/{resource_id}/chunks/0",
            b"same",
            headers=chunk_headers(2, DIGEST_A),
        )
        self.assertEqual(first[0], "201 Created")
        second = call_json(
            "POST",
            f"/resources/{resource_id}/chunks/0",
            b"same",
            headers=chunk_headers(2, DIGEST_A),
        )
        self.assertEqual(second[0], "200 OK")
        self.assertEqual(second[2], first[2])
        # No duplicate index is counted.
        self.assertEqual(second[2]["received_chunks"], 1)

    def test_same_index_different_bytes_conflicts_and_keeps_original(self) -> None:
        resource_id = self._create(DIGEST_A)
        call(
            "POST",
            f"/resources/{resource_id}/chunks/0",
            b"original",
            headers=chunk_headers(2, DIGEST_A),
        )
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/chunks/0",
            b"different",
            headers=chunk_headers(2, DIGEST_A),
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "chunk_conflict")
        # Original bytes are still what a repeat sees (200, not 409).
        status, _h, _b = call(
            "POST",
            f"/resources/{resource_id}/chunks/0",
            b"original",
            headers=chunk_headers(2, DIGEST_A),
        )
        self.assertEqual(status, "200 OK")

    def test_later_total_change_is_chunk_conflict(self) -> None:
        resource_id = self._create(DIGEST_A)
        call(
            "POST",
            f"/resources/{resource_id}/chunks/0",
            b"a",
            headers=chunk_headers(2, DIGEST_A),
        )
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/chunks/1",
            b"b",
            headers=chunk_headers(3, DIGEST_A),
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "chunk_conflict")
        # The rejected chunk was not stored: assembly is still incomplete.
        status, _h, body = call_json(
            "POST", f"/resources/{resource_id}/assemble"
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "chunks_incomplete")

    def test_later_digest_change_is_chunk_conflict(self) -> None:
        resource_id = self._create(DIGEST_A)
        call(
            "POST",
            f"/resources/{resource_id}/chunks/0",
            b"a",
            headers=chunk_headers(2, DIGEST_A),
        )
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/chunks/1",
            b"b",
            headers=chunk_headers(2, DIGEST_B),
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "chunk_conflict")

    def test_first_chunk_digest_mismatch_is_digest_conflict_without_fragment(
        self,
    ) -> None:
        resource_id = self._create(DIGEST_A)
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/chunks/0",
            b"x",
            headers=chunk_headers(1, DIGEST_B),
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "digest_conflict")
        # No session was created and nothing was written.
        self.assertNotIn(resource_id, content_store._sessions)
        status, _h, body = call_json(
            "POST", f"/resources/{resource_id}/assemble"
        )
        self.assertEqual(body["error"], "chunks_incomplete")

    def test_uppercase_digest_header_is_normalized(self) -> None:
        resource_id = self._create(DIGEST_A)
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/chunks/0",
            b"x",
            headers=chunk_headers(2, DIGEST_A.upper()),
        )
        self.assertEqual(status, "201 Created")
        self.assertEqual(body["digest"], DIGEST_A)

    def test_empty_chunk_is_valid(self) -> None:
        empty_digest = hashlib.sha256(b"").hexdigest()
        resource_id = self._create(empty_digest)
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/chunks/0",
            b"",
            headers=chunk_headers(1, empty_digest),
        )
        self.assertEqual(status, "201 Created")
        status, _h, body = call_json(
            "POST", f"/resources/{resource_id}/assemble"
        )
        self.assertEqual(status, "201 Created")
        self.assertEqual(body["size"], 0)

    # --- Upload validation -------------------------------------------------

    def test_bad_chunk_index_is_bad_request(self) -> None:
        resource_id = self._create(DIGEST_A)
        for raw_index in ("", "-1", "1.0", "x", "01", " 1"):
            with self.subTest(raw_index=raw_index):
                status, _h, body = call_json(
                    "POST",
                    f"/resources/{resource_id}/chunks/{raw_index}",
                    b"x",
                    headers=chunk_headers(2, DIGEST_A),
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_index_equal_or_above_total_is_bad_request(self) -> None:
        resource_id = self._create(DIGEST_A)
        for raw_index in ("1", "2", "12"):
            with self.subTest(raw_index=raw_index):
                status, _h, body = call_json(
                    "POST",
                    f"/resources/{resource_id}/chunks/{raw_index}",
                    b"x",
                    headers=chunk_headers(1, DIGEST_A),
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_missing_or_bad_total_header_is_bad_request(self) -> None:
        resource_id = self._create(DIGEST_A)
        base = {
            "CONTENT_TYPE": "application/octet-stream",
            "HTTP_X_CONTENT_DIGEST": DIGEST_A,
        }
        for headers in (
            dict(base),
            {**base, "HTTP_X_TOTAL_CHUNKS": ""},
            {**base, "HTTP_X_TOTAL_CHUNKS": "0"},
            {**base, "HTTP_X_TOTAL_CHUNKS": "-1"},
            {**base, "HTTP_X_TOTAL_CHUNKS": "1.5"},
            {**base, "HTTP_X_TOTAL_CHUNKS": "two"},
        ):
            with self.subTest(headers=headers):
                status, _h, body = call_json(
                    "POST",
                    f"/resources/{resource_id}/chunks/0",
                    b"x",
                    headers=headers,
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_missing_or_bad_digest_header_is_bad_request(self) -> None:
        resource_id = self._create(DIGEST_A)
        base = {"CONTENT_TYPE": "application/octet-stream", "HTTP_X_TOTAL_CHUNKS": "2"}
        for digest in ("", "z" * 64, "a" * 63, "g" * 64):
            with self.subTest(digest=digest):
                status, _h, body = call_json(
                    "POST",
                    f"/resources/{resource_id}/chunks/0",
                    b"x",
                    headers={**base, "HTTP_X_CONTENT_DIGEST": digest},
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/chunks/0",
            b"x",
            headers=dict(base),
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_wrong_content_type_is_bad_request(self) -> None:
        resource_id = self._create(DIGEST_A)
        for content_type in (
            "text/plain",
            "application/json",
            "application/octet-stream; charset=binary",
        ):
            with self.subTest(content_type=content_type):
                status, _h, body = call_json(
                    "POST",
                    f"/resources/{resource_id}/chunks/0",
                    b"x",
                    headers={
                        "CONTENT_TYPE": content_type,
                        "HTTP_X_TOTAL_CHUNKS": "2",
                        "HTTP_X_CONTENT_DIGEST": DIGEST_A,
                    },
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_content_type_case_insensitive(self) -> None:
        resource_id = self._create(DIGEST_A)
        status, _h, _b = call(
            "POST",
            f"/resources/{resource_id}/chunks/0",
            b"x",
            headers={
                "CONTENT_TYPE": "Application/Octet-Stream",
                "HTTP_X_TOTAL_CHUNKS": "2",
                "HTTP_X_CONTENT_DIGEST": DIGEST_A,
            },
        )
        self.assertEqual(status, "201 Created")

    def test_bad_or_missing_content_length_is_bad_request_and_leaves_nothing(
        self,
    ) -> None:
        resource_id = self._create(DIGEST_A)
        # A new session whose body cannot be read correctly is never opened.
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/chunks/0",
            b"abcd",
            headers=chunk_headers(2, DIGEST_A),
            omit_content_length=True,
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        self.assertNotIn(resource_id, content_store._sessions)

        for declared in ("-1", "1.5", "abc"):
            with self.subTest(declared=declared):
                status, _h, body = call_json(
                    "POST",
                    f"/resources/{resource_id}/chunks/0",
                    b"abcd",
                    headers=chunk_headers(2, DIGEST_A),
                    content_length=declared,
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

        # Declares more bytes than are actually available.
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/chunks/0",
            b"abcd",
            headers=chunk_headers(2, DIGEST_A),
            content_length=10,
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

        # Once a valid session exists, a failed read does not add the index.
        call(
            "POST",
            f"/resources/{resource_id}/chunks/0",
            b"ok",
            headers=chunk_headers(3, DIGEST_A),
        )
        call(
            "POST",
            f"/resources/{resource_id}/chunks/1",
            b"abcd",
            headers=chunk_headers(3, DIGEST_A),
            content_length=99,
        )
        status, _h, _b = call(
            "POST",
            f"/resources/{resource_id}/chunks/1",
            b"later",
            headers=chunk_headers(3, DIGEST_A),
        )
        self.assertEqual(status, "201 Created")

    def test_query_parameters_rejected(self) -> None:
        resource_id = self._create(DIGEST_A)
        for method, path in (
            ("POST", f"/resources/{resource_id}/chunks/0"),
            ("POST", f"/resources/{resource_id}/assemble"),
            ("GET", f"/resources/{resource_id}/content"),
        ):
            with self.subTest(path=path):
                body = b"x" if "chunks" in path else b""
                kwargs: dict[str, object] = {"query_string": "x=1"}
                if "chunks" in path:
                    kwargs["headers"] = chunk_headers(2, DIGEST_A)
                status, _h, payload = call_json(method, path, body, **kwargs)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(payload["error"], "invalid_request")

    def test_invalid_path_id_is_bad_request(self) -> None:
        for path in (
            "/resources//chunks/0",
            "/resources/a/b/chunks/0",
            "/resources/a\\b/chunks/0",
            "/resources//assemble",
            "/resources//content",
        ):
            with self.subTest(path=path):
                method = "GET" if path.endswith("content") else "POST"
                status, _h, body = call_json(method, path, b"x")
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_resource_not_found(self) -> None:
        for method, path in (
            ("POST", "/resources/missing/chunks/0"),
            ("POST", "/resources/missing/assemble"),
            ("GET", "/resources/missing/content"),
        ):
            with self.subTest(path=path):
                kwargs: dict[str, object] = {}
                if "chunks" in path:
                    kwargs["headers"] = chunk_headers(1, DIGEST_A)
                status, _h, body = call_json(method, path, b"x", **kwargs)
                self.assertEqual(status, "404 Not Found")
                self.assertEqual(body["error"], "resource_not_found")

    def test_unsupported_methods_return_405_with_allow(self) -> None:
        resource_id = self._create(DIGEST_A)
        cases = [
            ("GET", f"/resources/{resource_id}/chunks/0", "POST"),
            ("PUT", f"/resources/{resource_id}/chunks/0", "POST"),
            ("DELETE", f"/resources/{resource_id}/chunks/0", "POST"),
            ("GET", f"/resources/{resource_id}/assemble", "POST"),
            ("POST", f"/resources/{resource_id}/content", "GET"),
            ("DELETE", f"/resources/{resource_id}/content", "GET"),
        ]
        for method, path, allow in cases:
            with self.subTest(method=method, path=path):
                status, headers, body = call_json(method, path)
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")
                self.assertIn(("Allow", allow), headers)

    def test_chunk_collection_without_index_is_bad_request_on_post(self) -> None:
        resource_id = self._create(DIGEST_A)
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/chunks",
            b"x",
            headers=chunk_headers(2, DIGEST_A),
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        status, headers, body = call_json(
            "GET", f"/resources/{resource_id}/chunks"
        )
        self.assertEqual(status, "405 Method Not Allowed")
        self.assertIn(("Allow", "POST"), headers)

    # --- Assembly ----------------------------------------------------------

    def test_assemble_incomplete_keeps_chunks(self) -> None:
        resource_id = self._create(hashlib.sha256(b"ab").hexdigest())
        # Never uploaded at all.
        status, _h, body = call_json(
            "POST", f"/resources/{resource_id}/assemble"
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "chunks_incomplete")

        # One of two chunks present.
        call(
            "POST",
            f"/resources/{resource_id}/chunks/0",
            b"a",
            headers=chunk_headers(2, hashlib.sha256(b"ab").hexdigest()),
        )
        status, _h, body = call_json(
            "POST", f"/resources/{resource_id}/assemble"
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "chunks_incomplete")
        # Received chunk survives: uploading the missing one then works.
        call(
            "POST",
            f"/resources/{resource_id}/chunks/1",
            b"b",
            headers=chunk_headers(2, hashlib.sha256(b"ab").hexdigest()),
        )
        status, _h, body = call_json(
            "POST", f"/resources/{resource_id}/assemble"
        )
        self.assertEqual(status, "201 Created")
        self.assertEqual(body["digest"], hashlib.sha256(b"ab").hexdigest())
        self.assertEqual(body["size"], 2)

    def test_assemble_digest_mismatch_produces_no_content(self) -> None:
        # Registered digest is that of b"abc", but the chunks concatenate to
        # bytes with a different digest while repeating the registered digest
        # header (so intake accepts them; assembly is where it must fail).
        registered = hashlib.sha256(b"abc").hexdigest()
        resource_id = self._create(registered)
        call(
            "POST",
            f"/resources/{resource_id}/chunks/0",
            b"abd",
            headers=chunk_headers(1, registered),
        )
        status, _h, body = call_json(
            "POST", f"/resources/{resource_id}/assemble"
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "digest_mismatch")
        # No finalized content; chunks are retained.
        status, _h, body = call_json(
            "GET", f"/resources/{resource_id}/content"
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "content_not_complete")
        status, _h, _b = call(
            "POST",
            f"/resources/{resource_id}/chunks/0",
            b"abd",
            headers=chunk_headers(1, registered),
        )
        self.assertEqual(status, "200 OK")

    def test_assemble_success_response_shape(self) -> None:
        resource_id, digest = self._chunks([b"ab", b"cd", b"ef"])
        status, headers, raw = call(
            "POST", f"/resources/{resource_id}/assemble"
        )
        self.assertEqual(status, "201 Created")
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )
        self.assertTrue(raw.endswith(b"\n"))
        body = json.loads(raw)
        self.assertEqual(body["id"], resource_id)
        self.assertEqual(body["digest"], digest)
        self.assertEqual(body["size"], 6)
        text = raw.decode("utf-8").rstrip("\n")
        self.assertLess(text.index('"id"'), text.index('"digest"'))
        self.assertLess(text.index('"digest"'), text.index('"size"'))

    def test_repeat_assemble_and_upload_after_complete_conflict(self) -> None:
        resource_id, digest = self._chunks([b"ab", b"cd"])
        call("POST", f"/resources/{resource_id}/assemble")
        status, _h, body = call_json(
            "POST", f"/resources/{resource_id}/assemble"
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "content_already_complete")

        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/chunks/0",
            b"ab",
            headers=chunk_headers(2, digest),
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "content_already_complete")

    # --- Content read ------------------------------------------------------

    def test_read_completed_content_is_raw_octet_stream(self) -> None:
        payload = bytes(range(256)) + b"tail"
        resource_id, digest = self._chunks([payload[:100], payload[100:]])
        call("POST", f"/resources/{resource_id}/assemble")
        status, headers, raw = call(
            "GET", f"/resources/{resource_id}/content"
        )
        self.assertEqual(status, "200 OK")
        self.assertIn(("Content-Type", "application/octet-stream"), headers)
        self.assertIn(("Content-Length", str(len(payload))), headers)
        self.assertEqual(raw, payload)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), digest)
        # Exactly the raw bytes: no JSON envelope and no trailing newline.
        self.assertFalse(raw.endswith(b"\n"))

    def test_read_empty_completed_content(self) -> None:
        empty_digest = hashlib.sha256(b"").hexdigest()
        resource_id = self._create(empty_digest)
        call(
            "POST",
            f"/resources/{resource_id}/chunks/0",
            b"",
            headers=chunk_headers(1, empty_digest),
        )
        call("POST", f"/resources/{resource_id}/assemble")
        status, headers, raw = call(
            "GET", f"/resources/{resource_id}/content"
        )
        self.assertEqual(status, "200 OK")
        self.assertIn(("Content-Length", "0"), headers)
        self.assertEqual(raw, b"")

    def test_read_before_completion_is_content_not_complete(self) -> None:
        resource_id = self._create(DIGEST_A)
        status, _h, body = call_json(
            "GET", f"/resources/{resource_id}/content"
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "content_not_complete")

        call(
            "POST",
            f"/resources/{resource_id}/chunks/0",
            b"x",
            headers=chunk_headers(2, DIGEST_A),
        )
        status, _h, body = call_json(
            "GET", f"/resources/{resource_id}/content"
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "content_not_complete")

    # --- Isolation ---------------------------------------------------------

    def test_sessions_are_isolated_per_resource(self) -> None:
        first = self._chunks([b"aa"], resource_id=None)
        resource_a, digest_a = first
        resource_b = self._create(hashlib.sha256(b"bb").hexdigest())
        call(
            "POST",
            f"/resources/{resource_b}/chunks/0",
            b"bb",
            headers=chunk_headers(1, hashlib.sha256(b"bb").hexdigest()),
        )
        # Resource B completing does not finalize A (which was never assembled).
        status, _h, _b = call(
            "POST", f"/resources/{resource_b}/assemble"
        )
        self.assertEqual(status, "201 Created")
        status, _h, body = call_json(
            "GET", f"/resources/{resource_a}/content"
        )
        self.assertEqual(body["error"], "content_not_complete")
        call("POST", f"/resources/{resource_a}/assemble")
        _s, _h, raw_a = call("GET", f"/resources/{resource_a}/content")
        _s, _h, raw_b = call("GET", f"/resources/{resource_b}/content")
        self.assertEqual(raw_a, b"aa")
        self.assertEqual(raw_b, b"bb")
        self.assertEqual(digest_a, hashlib.sha256(b"aa").hexdigest())

    def test_completion_does_not_touch_resource_record_or_verify(self) -> None:
        payload = b"registry-unchanged"
        digest = hashlib.sha256(payload).hexdigest()
        resource_id = self._create(digest)
        call(
            "POST",
            f"/resources/{resource_id}/chunks/0",
            payload,
            headers=chunk_headers(1, digest),
        )
        call("POST", f"/resources/{resource_id}/assemble")
        _s, _h, record = call_json("GET", f"/resources/{resource_id}")
        self.assertEqual(record["digest"], digest)
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/verify",
            payload,
            headers=OCTET_HEADERS,
        )
        self.assertEqual(status, "200 OK")
        self.assertIs(body["valid"], True)

    def test_reset_state_clears_sessions_and_content(self) -> None:
        resource_id, _digest = self._chunks([b"zz"])
        call("POST", f"/resources/{resource_id}/assemble")
        reset_state()
        self.assertEqual(store.list_all(), [])
        self.assertEqual(content_store._sessions, {})


class ChunkStatusTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def _create(self, digest: str) -> str:
        body = json.dumps(
            {"name": "r", "category": "code", "digest": digest}
        ).encode("utf-8")
        _s, _h, raw = call(
            "POST", "/resources", body,
            headers={"CONTENT_TYPE": "application/json"},
        )
        return str(json.loads(raw)["id"])

    def _upload(self, resource_id: str, index: int, total: int,
                digest: str, data: bytes) -> tuple[str, list, dict]:
        return call_json(
            "POST",
            f"/resources/{resource_id}/chunks/{index}",
            data,
            headers=chunk_headers(total, digest),
        )

    def _status(self, resource_id: str, **kwargs: object):
        return call_json(
            "GET", f"/resources/{resource_id}/chunks/status", **kwargs
        )

    # --- Not started -------------------------------------------------------

    def test_not_started_is_conflict_and_creates_no_session(self) -> None:
        resource_id = self._create(DIGEST_A)
        status, _h, body = self._status(resource_id)
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "chunks_not_started")
        # The read-only query must not open a session.
        self.assertNotIn(resource_id, content_store._sessions)
        status, _h, body = self._status(resource_id)
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "chunks_not_started")

    def test_digest_conflicting_first_chunk_leaves_not_started(self) -> None:
        resource_id = self._create(DIGEST_A)
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/chunks/0",
            b"x",
            headers=chunk_headers(1, DIGEST_B),
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "digest_conflict")
        status, _h, body = self._status(resource_id)
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "chunks_not_started")

    # --- In progress -------------------------------------------------------

    def test_in_progress_reports_missing_in_ascending_order(self) -> None:
        resource_id = self._create(DIGEST_A)
        # Arrive out of order with index 1 missing for a while.
        self._upload(resource_id, 2, 4, DIGEST_A, b"c")
        self._upload(resource_id, 0, 4, DIGEST_A, b"a")
        status, headers, body = self._status(resource_id)
        self.assertEqual(status, "200 OK")
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )
        self.assertEqual(body["id"], resource_id)
        self.assertEqual(body["digest"], DIGEST_A)
        self.assertEqual(body["total_chunks"], 4)
        self.assertEqual(body["received_chunks"], 2)
        self.assertEqual(body["missing_chunks"], [1, 3])
        self.assertIs(body["complete"], False)
        self.assertIsNone(body["size"])

        # Filling one gap shrinks the missing list, still ascending.
        self._upload(resource_id, 3, 4, DIGEST_A, b"d")
        _s, _h, body = self._status(resource_id)
        self.assertEqual(body["received_chunks"], 3)
        self.assertEqual(body["missing_chunks"], [1])
        self.assertIs(body["complete"], False)
        self.assertIsNone(body["size"])

    def test_response_is_compact_ordered_and_newline_terminated(self) -> None:
        resource_id = self._create(DIGEST_A)
        self._upload(resource_id, 0, 2, DIGEST_A, b"a")
        status, _h, raw = call(
            "GET", f"/resources/{resource_id}/chunks/status"
        )
        self.assertEqual(status, "200 OK")
        self.assertTrue(raw.endswith(b"\n"))
        text = raw.decode("utf-8").rstrip("\n")
        self.assertNotIn(" ", text)
        keys = [
            "id", "digest", "total_chunks", "received_chunks",
            "missing_chunks", "complete", "size",
        ]
        positions = [text.index(f'"{key}"') for key in keys]
        self.assertEqual(positions, sorted(positions))

    # --- Failed assembly ---------------------------------------------------

    def test_failed_assembly_keeps_chunks_and_reports_not_complete(self) -> None:
        # Registered digest is that of b"abc"; the single chunk is b"abd".
        registered = hashlib.sha256(b"abc").hexdigest()
        resource_id = self._create(registered)
        self._upload(resource_id, 0, 1, registered, b"abd")
        status, _h, body = call_json(
            "POST", f"/resources/{resource_id}/assemble"
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "digest_mismatch")

        status, _h, body = self._status(resource_id)
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["digest"], registered)
        self.assertEqual(body["total_chunks"], 1)
        self.assertEqual(body["received_chunks"], 1)
        # All chunks present, so missing is empty even though digest failed.
        self.assertEqual(body["missing_chunks"], [])
        self.assertIs(body["complete"], False)
        self.assertIsNone(body["size"])
        # No finalized content was produced.
        status, _h, body = call_json(
            "GET", f"/resources/{resource_id}/content"
        )
        self.assertEqual(body["error"], "content_not_complete")

    # --- Completed ---------------------------------------------------------

    def test_completed_reports_true_and_actual_size(self) -> None:
        content = bytes(range(256)) + b"tail"
        digest = hashlib.sha256(content).hexdigest()
        resource_id = self._create(digest)
        self._upload(resource_id, 0, 2, digest, content[:100])
        self._upload(resource_id, 1, 2, digest, content[100:])
        call("POST", f"/resources/{resource_id}/assemble")

        status, _h, body = self._status(resource_id)
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["digest"], digest)
        self.assertEqual(body["total_chunks"], 2)
        self.assertEqual(body["received_chunks"], 2)
        self.assertEqual(body["missing_chunks"], [])
        self.assertIs(body["complete"], True)
        self.assertEqual(body["size"], len(content))

    def test_completed_empty_content_reports_size_zero(self) -> None:
        empty_digest = hashlib.sha256(b"").hexdigest()
        resource_id = self._create(empty_digest)
        self._upload(resource_id, 0, 1, empty_digest, b"")
        call("POST", f"/resources/{resource_id}/assemble")
        _s, _h, body = self._status(resource_id)
        self.assertIs(body["complete"], True)
        self.assertEqual(body["size"], 0)
        self.assertEqual(body["missing_chunks"], [])

    # --- Read-only ---------------------------------------------------------

    def test_status_query_is_read_only(self) -> None:
        resource_id = self._create(DIGEST_A)
        # A query before any upload creates nothing.
        self._status(resource_id)
        self.assertNotIn(resource_id, content_store._sessions)

        self._upload(resource_id, 0, 3, DIGEST_A, b"a")
        before = content_store._sessions[resource_id]
        chunks_before = dict(before.chunks)
        # Repeated queries never change the snapshot or stored bytes.
        for _ in range(3):
            status, _h, body = self._status(resource_id)
            self.assertEqual(status, "200 OK")
            self.assertEqual(body["missing_chunks"], [1, 2])
        self.assertIs(content_store._sessions[resource_id], before)
        self.assertEqual(before.chunks, chunks_before)

        # Resource record, other endpoints and restart isolation are intact:
        # status must not finalize content or mark completion.
        status, _h, body = call_json(
            "GET", f"/resources/{resource_id}/content"
        )
        self.assertEqual(body["error"], "content_not_complete")
        _s, _h, record = call_json("GET", f"/resources/{resource_id}")
        self.assertEqual(record["digest"], DIGEST_A)

    # --- Errors ------------------------------------------------------------

    def test_unknown_resource_is_not_found(self) -> None:
        status, _h, body = self._status("missing")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

    def test_empty_or_separator_id_is_bad_request(self) -> None:
        for path in (
            "/resources//chunks/status",
            "/resources/a/b/chunks/status",
            "/resources/a\\b/chunks/status",
        ):
            with self.subTest(path=path):
                status, _h, body = call_json("GET", path)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_query_parameters_rejected(self) -> None:
        resource_id = self._create(DIGEST_A)
        status, _h, body = call_json(
            "GET",
            f"/resources/{resource_id}/chunks/status",
            query_string="x=1",
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_non_get_methods_return_405_with_allow_get(self) -> None:
        resource_id = self._create(DIGEST_A)
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, headers, body = call_json(
                    method, f"/resources/{resource_id}/chunks/status"
                )
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")
                self.assertIn(("Allow", "GET"), headers)


if __name__ == "__main__":
    unittest.main()
