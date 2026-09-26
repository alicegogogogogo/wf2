from __future__ import annotations

import hashlib
import io
import json
import unittest

from provenance_api.app import application, content_store, reset_state, store

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


def chunk_headers(total: int | str, digest: str) -> dict[str, str]:
    return {
        "CONTENT_TYPE": "application/octet-stream",
        "HTTP_X_TOTAL_CHUNKS": str(total),
        "HTTP_X_CONTENT_DIGEST": digest,
    }


class ChunkResetTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def _create(self, digest: str) -> str:
        body = json.dumps(
            {"name": "r", "category": "code", "digest": digest}
        ).encode("utf-8")
        _s, _h, raw = call(
            "POST", "/resources", body, headers={"CONTENT_TYPE": "application/json"}
        )
        return str(json.loads(raw)["id"])

    def _upload(self, resource_id: str, total: int, digest: str, *parts: bytes) -> None:
        for index, part in enumerate(parts):
            status, _h, _b = call(
                "POST",
                f"/resources/{resource_id}/chunks/{index}",
                part,
                headers=chunk_headers(total, digest),
            )
            self.assertEqual(status, "201 Created")

    # --- Success -----------------------------------------------------------

    def test_reset_in_progress_returns_echo_shape(self) -> None:
        resource_id = self._create(DIGEST_A)
        self._upload(resource_id, 3, DIGEST_A, b"a", b"b")
        status, headers, raw = call(
            "DELETE", f"/resources/{resource_id}/chunks"
        )
        self.assertEqual(status, "200 OK")
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        body = json.loads(raw)
        self.assertEqual(body["id"], resource_id)
        self.assertEqual(body["digest"], DIGEST_A)
        self.assertEqual(body["removed_chunks"], 2)
        text = raw.decode("utf-8").rstrip("\n")
        self.assertNotIn(" ", text)
        self.assertLess(text.index('"id"'), text.index('"digest"'))
        self.assertLess(text.index('"digest"'), text.index('"removed_chunks"'))
        # No half record remains.
        self.assertNotIn(resource_id, content_store._sessions)

    def test_reset_clears_session_back_to_not_started(self) -> None:
        resource_id = self._create(DIGEST_A)
        self._upload(resource_id, 2, DIGEST_A, b"a")
        status, _h, _b = call("DELETE", f"/resources/{resource_id}/chunks")
        self.assertEqual(status, "200 OK")
        status, _h, body = call_json(
            "GET", f"/resources/{resource_id}/chunks/status"
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "chunks_not_started")
        # Resetting again is the not-started conflict, not a second success.
        status, _h, body = call_json(
            "DELETE", f"/resources/{resource_id}/chunks"
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "chunks_not_started")

    def test_reset_allows_new_total_and_digest_from_index_zero(self) -> None:
        # The registered digest is that of the final single-chunk body; the
        # first (abandoned) plan never reaches assembly.
        final_digest = hashlib.sha256(b"x").hexdigest()
        resource_id = self._create(final_digest)
        # Start with a 2-chunk plan that never finishes.
        self._upload(resource_id, 2, final_digest, b"a")
        status, _h, _b = call("DELETE", f"/resources/{resource_id}/chunks")
        self.assertEqual(status, "200 OK")

        # A digest conflicting with the registered one is still rejected on
        # the fresh session, and still creates nothing.
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/chunks/0",
            b"x",
            headers=chunk_headers(1, "b" * 64),
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "digest_conflict")
        self.assertNotIn(resource_id, content_store._sessions)

        # New plan: single chunk, different total; indices restart at zero.
        status, _h, _b = call(
            "POST",
            f"/resources/{resource_id}/chunks/0",
            b"x",
            headers=chunk_headers(1, final_digest),
        )
        self.assertEqual(status, "201 Created")
        status, _h, body = call_json(
            "POST", f"/resources/{resource_id}/assemble"
        )
        self.assertEqual(status, "201 Created")
        self.assertEqual(body["size"], 1)
        _s, _h, raw = call("GET", f"/resources/{resource_id}/content")
        self.assertEqual(raw, b"x")

    def test_reset_after_digest_mismatch_failure(self) -> None:
        registered = hashlib.sha256(b"abc").hexdigest()
        resource_id = self._create(registered)
        self._upload(resource_id, 1, registered, b"abd")
        status, _h, body = call_json(
            "POST", f"/resources/{resource_id}/assemble"
        )
        self.assertEqual(body["error"], "digest_mismatch")
        # The failed assembly retains chunks; reset reports that count.
        status, headers, raw = call(
            "DELETE", f"/resources/{resource_id}/chunks"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(json.loads(raw)["removed_chunks"], 1)
        status, _h, body = call_json(
            "GET", f"/resources/{resource_id}/chunks/status"
        )
        self.assertEqual(body["error"], "chunks_not_started")
        # No content was ever finalized.
        status, _h, body = call_json(
            "GET", f"/resources/{resource_id}/content"
        )
        self.assertEqual(body["error"], "content_not_complete")

    def test_reset_without_any_chunk_is_not_started(self) -> None:
        resource_id = self._create(DIGEST_A)
        status, _h, body = call_json(
            "DELETE", f"/resources/{resource_id}/chunks"
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "chunks_not_started")
        self.assertNotIn(resource_id, content_store._sessions)

    def test_reset_after_completion_is_refused_and_bytes_unchanged(self) -> None:
        digest = hashlib.sha256(b"abcd").hexdigest()
        resource_id = self._create(digest)
        self._upload(resource_id, 2, digest, b"ab", b"cd")
        status, _h, _b = call("POST", f"/resources/{resource_id}/assemble")
        self.assertEqual(status, "201 Created")

        status, _h, body = call_json(
            "DELETE", f"/resources/{resource_id}/chunks"
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "content_already_complete")

        # Finalized bytes and the session-status view are unaffected.
        _s, _h, raw = call("GET", f"/resources/{resource_id}/content")
        self.assertEqual(raw, b"abcd")
        status, _h, body = call_json(
            "GET", f"/resources/{resource_id}/chunks/status"
        )
        self.assertEqual(status, "200 OK")
        self.assertIs(body["complete"], True)
        self.assertEqual(body["received_chunks"], 2)
        self.assertEqual(body["size"], 4)

    def test_reset_touches_only_this_resource(self) -> None:
        digest_a = hashlib.sha256(b"aa").hexdigest()
        digest_b = hashlib.sha256(b"bb").hexdigest()
        resource_a = self._create(digest_a)
        resource_b = self._create(digest_b)
        self._upload(resource_a, 1, digest_a, b"aa")
        self._upload(resource_b, 1, digest_b, b"bb")
        status, _h, _b = call("DELETE", f"/resources/{resource_a}/chunks")
        self.assertEqual(status, "200 OK")
        self.assertNotIn(resource_a, content_store._sessions)
        status, _h, body = call_json(
            "GET", f"/resources/{resource_b}/chunks/status"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["received_chunks"], 1)

    # --- Validation and method limits --------------------------------------

    def test_reset_resource_not_found_changes_nothing(self) -> None:
        status, _h, body = call_json("DELETE", "/resources/missing/chunks")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

    def test_reset_invalid_path_id_is_bad_request(self) -> None:
        for path in (
            "/resources//chunks",
            "/resources/a/b/chunks",
            "/resources/a\\b/chunks",
        ):
            with self.subTest(path=path):
                status, _h, body = call_json("DELETE", path)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_reset_query_parameters_rejected(self) -> None:
        resource_id = self._create(DIGEST_A)
        self._upload(resource_id, 1, DIGEST_A, b"a")
        status, _h, body = call_json(
            "DELETE",
            f"/resources/{resource_id}/chunks",
            query_string="x=1",
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        # The rejected reset left the session intact.
        self.assertIn(resource_id, content_store._sessions)

    def test_reset_nonempty_or_malformed_body_is_bad_request(self) -> None:
        resource_id = self._create(DIGEST_A)
        self._upload(resource_id, 1, DIGEST_A, b"a")
        status, _h, body = call_json(
            "DELETE", f"/resources/{resource_id}/chunks", b"x"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        for declared in ("-1", "1.5", "abc"):
            with self.subTest(declared=declared):
                status, _h, body = call_json(
                    "DELETE",
                    f"/resources/{resource_id}/chunks",
                    b"",
                    content_length=declared,
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")
        # Explicit zero and a missing Content-Length header are both fine.
        status, _h, _b = call(
            "DELETE",
            f"/resources/{resource_id}/chunks",
            b"",
            content_length=0,
        )
        self.assertEqual(status, "200 OK")
        reset_state()
        resource_id = self._create(DIGEST_A)
        self._upload(resource_id, 1, DIGEST_A, b"a")
        status, _h, _b = call(
            "DELETE",
            f"/resources/{resource_id}/chunks",
            b"",
            omit_content_length=True,
        )
        self.assertEqual(status, "200 OK")

    def test_non_delete_methods_405_with_allow_delete_only(self) -> None:
        resource_id = self._create(DIGEST_A)
        self._upload(resource_id, 1, DIGEST_A, b"a")
        # POST on the collection is the chunk-upload path with a missing
        # index and stays a 400; every other method is the reset endpoint's
        # 405 with Allow listing only DELETE.
        for method in ("GET", "PUT", "PATCH"):
            with self.subTest(method=method):
                status, headers, body = call_json(
                    method, f"/resources/{resource_id}/chunks"
                )
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")
                allow = [value for name, value in headers if name == "Allow"]
                self.assertEqual(allow, ["DELETE"])

    def test_chunk_collection_post_still_bad_request_for_missing_index(
        self,
    ) -> None:
        # Existing collection behavior is unchanged: POST without an index is
        # not routed to the reset and stays a bad request.
        resource_id = self._create(DIGEST_A)
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/chunks",
            b"x",
            headers=chunk_headers(2, DIGEST_A),
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_reset_resource_record_and_registry_unchanged(self) -> None:
        resource_id = self._create(DIGEST_A)
        self._upload(resource_id, 1, DIGEST_A, b"x")
        status, _h, _b = call("DELETE", f"/resources/{resource_id}/chunks")
        self.assertEqual(status, "200 OK")
        record = store.get(resource_id)
        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual(record.digest, DIGEST_A)


if __name__ == "__main__":
    unittest.main()
