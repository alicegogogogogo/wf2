from __future__ import annotations

import hashlib
import io
import json
import unittest

from provenance_api.app import application, reset_state

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64


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
        "wsgi.input": io.BytesIO(body),
        "CONTENT_LENGTH": str(len(body)),
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


JSON_HEADERS = {"CONTENT_TYPE": "application/json"}
OCTET_HEADERS = {"CONTENT_TYPE": "application/octet-stream"}


def chunk_headers(total: int, digest: str) -> dict[str, str]:
    return {
        "CONTENT_TYPE": "application/octet-stream",
        "HTTP_X_TOTAL_CHUNKS": str(total),
        "HTTP_X_CONTENT_DIGEST": digest,
    }


class ChunkStartTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def _create(self, digest: str = DIGEST_A) -> str:
        body = json.dumps(
            {"name": "r", "category": "code", "digest": digest}
        ).encode("utf-8")
        _s, _h, raw = call("POST", "/resources", body, headers=JSON_HEADERS)
        return str(json.loads(raw)["id"])

    def _start(
        self, resource_id: str, total: object = 3, digest: object = DIGEST_A
    ) -> tuple[str, list[tuple[str, str]], dict[str, object]]:
        body = json.dumps({"total_chunks": total, "digest": digest}).encode(
            "utf-8"
        )
        return call_json(
            "POST",
            f"/resources/{resource_id}/chunks/start",
            body,
            headers=JSON_HEADERS,
        )

    def test_start_creates_session_without_chunks(self) -> None:
        resource_id = self._create()
        body = json.dumps({"total_chunks": 3, "digest": DIGEST_A}).encode(
            "utf-8"
        )
        status, headers, raw = call(
            "POST",
            f"/resources/{resource_id}/chunks/start",
            body,
            headers=JSON_HEADERS,
        )
        self.assertEqual(status, "201 Created")
        self.assertTrue(raw.endswith(b"\n"))
        payload = json.loads(raw)
        self.assertEqual(
            list(payload),
            [
                "id",
                "digest",
                "total_chunks",
                "received_chunks",
                "missing_chunks",
                "complete",
                "size",
            ],
        )
        self.assertEqual(payload["id"], resource_id)
        self.assertEqual(payload["digest"], DIGEST_A)
        self.assertEqual(payload["total_chunks"], 3)
        self.assertEqual(payload["received_chunks"], 0)
        self.assertEqual(payload["missing_chunks"], [0, 1, 2])
        self.assertIs(payload["complete"], False)
        self.assertIsNone(payload["size"])

    def test_start_normalizes_digest_case(self) -> None:
        resource_id = self._create()
        status, _h, payload = self._start(resource_id, digest=DIGEST_A.upper())
        self.assertEqual(status, "201 Created")
        self.assertEqual(payload["digest"], DIGEST_A)

    def test_status_reports_started_session(self) -> None:
        resource_id = self._create()
        self._start(resource_id)
        status, _h, payload = call_json(
            "GET", f"/resources/{resource_id}/chunks/status"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(payload["received_chunks"], 0)
        self.assertEqual(payload["missing_chunks"], [0, 1, 2])
        self.assertIs(payload["complete"], False)
        self.assertIsNone(payload["size"])

    def test_status_without_start_is_still_not_started(self) -> None:
        resource_id = self._create()
        status, _h, payload = call_json(
            "GET", f"/resources/{resource_id}/chunks/status"
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(payload["error"], "chunks_not_started")

    def test_repeat_start_is_idempotent(self) -> None:
        resource_id = self._create()
        self._start(resource_id)
        # Upload one chunk so the repeat must prove it keeps received bytes.
        status, _h, _raw = call(
            "POST",
            f"/resources/{resource_id}/chunks/0",
            b"chunk-0",
            headers=chunk_headers(3, DIGEST_A),
        )
        self.assertEqual(status, "201 Created")

        status, _h, payload = self._start(resource_id)
        self.assertEqual(status, "200 OK")
        self.assertEqual(payload["received_chunks"], 1)
        self.assertEqual(payload["missing_chunks"], [1, 2])
        # The received chunk survived the idempotent repeat.
        status, _h, payload = call_json(
            "GET", f"/resources/{resource_id}/chunks/status"
        )
        self.assertEqual(payload["received_chunks"], 1)
        self.assertEqual(payload["missing_chunks"], [1, 2])

    def test_repeat_start_with_different_parameters_conflicts(self) -> None:
        resource_id = self._create()
        self._start(resource_id)
        call(
            "POST",
            f"/resources/{resource_id}/chunks/0",
            b"chunk-0",
            headers=chunk_headers(3, DIGEST_A),
        )
        status, _h, payload = self._start(resource_id, total=4)
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(payload["error"], "chunk_conflict")
        # Received chunks are untouched.
        status, _h, payload = call_json(
            "GET", f"/resources/{resource_id}/chunks/status"
        )
        self.assertEqual(payload["total_chunks"], 3)
        self.assertEqual(payload["received_chunks"], 1)

    def test_digest_mismatch_with_registration_conflicts(self) -> None:
        resource_id = self._create()
        status, _h, payload = self._start(resource_id, digest=DIGEST_B)
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(payload["error"], "digest_conflict")
        # No session was established.
        status, _h, payload = call_json(
            "GET", f"/resources/{resource_id}/chunks/status"
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(payload["error"], "chunks_not_started")

    def test_chunks_after_start_must_match_declaration(self) -> None:
        resource_id = self._create()
        self._start(resource_id)
        status, _h, payload = call_json(
            "POST",
            f"/resources/{resource_id}/chunks/0",
            b"chunk-0",
            headers=chunk_headers(4, DIGEST_A),
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(payload["error"], "chunk_conflict")
        status, _h, payload = call_json(
            "POST",
            f"/resources/{resource_id}/chunks/0",
            b"chunk-0",
            headers=chunk_headers(3, DIGEST_B),
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(payload["error"], "chunk_conflict")
        # A matching chunk is accepted.
        status, _h, payload = call_json(
            "POST",
            f"/resources/{resource_id}/chunks/0",
            b"chunk-0",
            headers=chunk_headers(3, DIGEST_A),
        )
        self.assertEqual(status, "201 Created")

    def test_start_after_completion_conflicts(self) -> None:
        resource_id = self._create()
        content = b"hello"
        digest = hashlib.sha256(content).hexdigest()
        resource_id = self._create(digest)
        call(
            "POST",
            f"/resources/{resource_id}/chunks/0",
            content,
            headers=chunk_headers(1, digest),
        )
        status, _h, _payload = call_json(
            "POST", f"/resources/{resource_id}/assemble"
        )
        self.assertEqual(status, "201 Created")
        status, _h, payload = self._start(resource_id, total=1, digest=digest)
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(payload["error"], "content_already_complete")

    def test_reset_after_start_clears_zero_chunks(self) -> None:
        resource_id = self._create()
        self._start(resource_id)
        status, _h, payload = call_json(
            "DELETE", f"/resources/{resource_id}/chunks"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(payload["digest"], DIGEST_A)
        self.assertEqual(payload["removed_chunks"], 0)
        # The session is back to the unstarted state.
        status, _h, payload = call_json(
            "GET", f"/resources/{resource_id}/chunks/status"
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(payload["error"], "chunks_not_started")

    def test_reset_without_start_is_still_not_started(self) -> None:
        resource_id = self._create()
        status, _h, payload = call_json(
            "DELETE", f"/resources/{resource_id}/chunks"
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(payload["error"], "chunks_not_started")

    def test_missing_body_is_rejected(self) -> None:
        resource_id = self._create()
        status, _h, payload = call_json(
            "POST",
            f"/resources/{resource_id}/chunks/start",
            b"",
            headers=JSON_HEADERS,
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(payload["error"], "invalid_request")

    def test_undecodable_body_is_rejected(self) -> None:
        resource_id = self._create()
        status, _h, payload = call_json(
            "POST",
            f"/resources/{resource_id}/chunks/start",
            b"\xff\xfe{",
            headers=JSON_HEADERS,
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(payload["error"], "invalid_request")

    def test_non_object_body_is_rejected(self) -> None:
        resource_id = self._create()
        for body in (b"[1,2]", b'"text"', b"3"):
            status, _h, payload = call_json(
                "POST",
                f"/resources/{resource_id}/chunks/start",
                body,
                headers=JSON_HEADERS,
            )
            self.assertEqual(status, "400 Bad Request")
            self.assertEqual(payload["error"], "invalid_request")

    def test_invalid_fields_are_rejected_without_session(self) -> None:
        resource_id = self._create()
        bad_bodies = [
            {},  # missing both fields
            {"total_chunks": 3},  # missing digest
            {"digest": DIGEST_A},  # missing total_chunks
            {"total_chunks": 0, "digest": DIGEST_A},
            {"total_chunks": -1, "digest": DIGEST_A},
            {"total_chunks": "3", "digest": DIGEST_A},
            {"total_chunks": 3.0, "digest": DIGEST_A},
            {"total_chunks": True, "digest": DIGEST_A},
            {"total_chunks": 3, "digest": DIGEST_A[:-1]},
            {"total_chunks": 3, "digest": "g" * 64},
            {"total_chunks": 3, "digest": 7},
            {"total_chunks": 3, "digest": DIGEST_A, "extra": 1},
        ]
        for body in bad_bodies:
            status, _h, payload = call_json(
                "POST",
                f"/resources/{resource_id}/chunks/start",
                json.dumps(body).encode("utf-8"),
                headers=JSON_HEADERS,
            )
            self.assertEqual(status, "400 Bad Request", body)
            self.assertEqual(payload["error"], "invalid_request", body)
        # None of the rejected attempts established a session.
        status, _h, payload = call_json(
            "GET", f"/resources/{resource_id}/chunks/status"
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(payload["error"], "chunks_not_started")

    def test_unknown_resource_is_not_found(self) -> None:
        status, _h, payload = self._start("no-such-resource")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(payload["error"], "resource_not_found")

    def test_invalid_id_and_query_parameters_are_rejected(self) -> None:
        resource_id = self._create()
        body = json.dumps(
            {"total_chunks": 3, "digest": DIGEST_A}
        ).encode("utf-8")
        status, _h, payload = call_json(
            "POST",
            "/resources/bad%2Fid/chunks/start",
            body,
            headers=JSON_HEADERS,
        )
        # The encoded slash reaches the app as a path separator.
        self.assertIn(status, ("400 Bad Request", "404 Not Found"))

        status, _h, payload = call_json(
            "POST",
            f"/resources/a/b/chunks/start",
            body,
            headers=JSON_HEADERS,
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(payload["error"], "invalid_request")

        status, _h, payload = call_json(
            "POST",
            f"/resources/{resource_id}/chunks/start",
            body,
            headers=JSON_HEADERS,
            query_string="x=1",
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(payload["error"], "invalid_request")

    def test_other_methods_are_not_allowed(self) -> None:
        resource_id = self._create()
        for method in ("GET", "PUT", "DELETE", "PATCH"):
            status, headers, payload = call_json(
                method, f"/resources/{resource_id}/chunks/start"
            )
            self.assertEqual(status, "405 Method Not Allowed", method)
            self.assertEqual(payload["error"], "method_not_allowed")
            allow = dict(headers).get("Allow")
            self.assertEqual(allow, "POST")


if __name__ == "__main__":
    unittest.main()
