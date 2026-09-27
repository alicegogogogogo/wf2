from __future__ import annotations

import hashlib
import io
import json
import unittest

from provenance_api.app import application, content_store, reset_state

PATH = "/upload-sessions"


def call(
    method: str,
    path: str = PATH,
    body: bytes | str | dict[str, object] | None = None,
    *,
    headers: dict[str, str] | None = None,
    query_string: str | None = None,
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
    for key, value in (headers or {}).items():
        environ[key] = value
    captured: dict[str, object] = {}

    def start_response(status: str, resp_headers: list[tuple[str, str]]) -> None:
        captured["status"] = status
        captured["headers"] = resp_headers

    parts = application(environ, start_response)
    return str(captured["status"]), list(captured["headers"]), b"".join(parts)


def call_json(
    method: str,
    path: str = PATH,
    body: bytes | str | dict[str, object] | None = None,
    **kwargs: object,
) -> tuple[str, list[tuple[str, str]], object]:
    status, resp_headers, raw = call(method, path, body, **kwargs)  # type: ignore[arg-type]
    return status, resp_headers, json.loads(raw.decode("utf-8"))


def chunk_headers(total: int | str, digest: str) -> dict[str, str]:
    return {
        "CONTENT_TYPE": "application/octet-stream",
        "HTTP_X_TOTAL_CHUNKS": str(total),
        "HTTP_X_CONTENT_DIGEST": digest,
    }


class UploadSessionsSummaryTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    # --- Setup helpers -----------------------------------------------------

    def _register(self, name: str, digest: str) -> str:
        _s, _h, body = call_json(
            "POST",
            "/resources",
            {"name": name, "category": "code", "digest": digest},
            headers={"CONTENT_TYPE": "application/json"},
        )
        assert isinstance(body, dict)
        return str(body["id"])

    def _start(self, resource_id: str, total: int, digest: str) -> None:
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/chunks/start",
            {"total_chunks": total, "digest": digest},
            headers={"CONTENT_TYPE": "application/json"},
        )
        assert status in ("200 OK", "201 Created"), body

    def _chunk(
        self, resource_id: str, index: int, total: int, digest: str, data: bytes
    ) -> None:
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/chunks/{index}",
            data,
            headers=chunk_headers(total, digest),
        )
        assert status in ("200 OK", "201 Created"), body

    def _assemble(self, resource_id: str) -> tuple[str, object]:
        status, _h, body = call_json(
            "POST", f"/resources/{resource_id}/assemble"
        )
        return status, body

    def _reset(self, resource_id: str) -> None:
        status, _h, body = call_json(
            "DELETE", f"/resources/{resource_id}/chunks"
        )
        assert status == "200 OK", body

    def _summary(self) -> list[dict[str, object]]:
        status, _h, body = call_json("GET", PATH)
        assert status == "200 OK", body
        assert isinstance(body, list)
        return body  # type: ignore[return-value]

    # --- Shape -------------------------------------------------------------

    def test_no_sessions_is_empty_array(self) -> None:
        status, headers, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            ("Content-Type", "application/json; charset=utf-8"), headers[0]
        )
        self.assertEqual(raw, b"[]\n")

    def test_body_is_compact_utf8_with_a_single_newline(self) -> None:
        resource_id = self._register("r", "a" * 64)
        self._start(resource_id, 2, "a" * 64)
        _s, _h, raw = call("GET", PATH)
        self.assertTrue(raw.endswith(b"\n"))
        self.assertEqual(raw.count(b"\n"), 1)
        self.assertNotIn(b" ", raw[:-1])

    def test_top_level_is_an_array_without_a_wrapper(self) -> None:
        first = self._register("first", "a" * 64)
        second = self._register("second", "b" * 64)
        self._start(first, 1, "a" * 64)
        self._start(second, 1, "b" * 64)

        status, _h, body = call_json("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertIsInstance(body, list)
        self.assertEqual(
            [record["resource_id"] for record in body], [first, second]  # type: ignore[index]
        )

    def test_record_keys_and_order_match_single_resource_status(self) -> None:
        content = b"hello world"
        digest = hashlib.sha256(content).hexdigest()
        resource_id = self._register("r", digest)
        self._chunk(resource_id, 0, 2, digest, b"hello ")
        self._chunk(resource_id, 1, 2, digest, b"world")

        _s, _h, raw = call("GET", PATH)
        text = raw.decode("utf-8").rstrip("\n")
        keys = [
            '"resource_id"',
            '"digest"',
            '"total_chunks"',
            '"received_chunks"',
            '"missing_chunks"',
            '"complete"',
            '"size"',
        ]
        positions = [text.index(key) for key in keys]
        self.assertEqual(positions, sorted(positions))

        # The fields after resource_id are byte-for-byte the single
        # resource status fields in the same order.
        _s, _h, single = call_json(
            "GET", f"/resources/{resource_id}/chunks/status"
        )
        expected = {"resource_id": resource_id, **{k: v for k, v in single.items() if k != "id"}}  # type: ignore[union-attr]
        self.assertEqual(self._summary(), [expected])

    def test_in_progress_session_is_reported_incomplete(self) -> None:
        resource_id = self._register("r", "a" * 64)
        self._chunk(resource_id, 1, 3, "a" * 64, b"x")
        self.assertEqual(
            self._summary(),
            [
                {
                    "resource_id": resource_id,
                    "digest": "a" * 64,
                    "total_chunks": 3,
                    "received_chunks": 1,
                    "missing_chunks": [0, 2],
                    "complete": False,
                    "size": None,
                }
            ],
        )

    def test_explicitly_started_session_without_chunks_is_reported(self) -> None:
        resource_id = self._register("r", "a" * 64)
        self._start(resource_id, 3, "a" * 64)
        self.assertEqual(
            self._summary(),
            [
                {
                    "resource_id": resource_id,
                    "digest": "a" * 64,
                    "total_chunks": 3,
                    "received_chunks": 0,
                    "missing_chunks": [0, 1, 2],
                    "complete": False,
                    "size": None,
                }
            ],
        )

    def test_completed_session_is_reported_complete_with_actual_size(self) -> None:
        parts = [b"hello ", b"world"]
        content = b"".join(parts)
        digest = hashlib.sha256(content).hexdigest()
        resource_id = self._register("r", digest)
        for index, part in enumerate(parts):
            self._chunk(resource_id, index, len(parts), digest, part)
        status, assembled = self._assemble(resource_id)
        self.assertEqual(status, "201 Created")
        assert isinstance(assembled, dict)
        self.assertEqual(assembled["size"], len(content))

        [record] = self._summary()
        self.assertEqual(record["missing_chunks"], [])
        self.assertIs(record["complete"], True)
        self.assertEqual(record["size"], len(content))

    def test_failed_assembly_session_stays_incomplete_with_null_size(self) -> None:
        # All chunks present, but the assembled bytes hash to something
        # other than the registered target digest.
        resource_id = self._register("r", "a" * 64)
        self._chunk(resource_id, 0, 1, "a" * 64, b"not the target")
        status, body = self._assemble(resource_id)
        self.assertEqual(status, "409 Conflict")
        assert isinstance(body, dict)
        self.assertEqual(body["error"], "digest_mismatch")

        [record] = self._summary()
        self.assertEqual(record["missing_chunks"], [])
        self.assertIs(record["complete"], False)
        self.assertIsNone(record["size"])
        # The received chunks are still counted.
        self.assertEqual(record["received_chunks"], 1)

    # --- Skipping ----------------------------------------------------------

    def test_resource_without_started_session_is_skipped(self) -> None:
        started = self._register("started", "a" * 64)
        self._register("never", "b" * 64)
        self._start(started, 1, "a" * 64)
        self.assertEqual(
            [r["resource_id"] for r in self._summary()], [started]
        )

    def test_reset_session_is_skipped_without_residue(self) -> None:
        resource_id = self._register("r", "a" * 64)
        self._chunk(resource_id, 0, 2, "a" * 64, b"x")
        self.assertEqual(len(self._summary()), 1)
        self._reset(resource_id)
        self.assertEqual(self._summary(), [])
        self.assertNotIn(resource_id, content_store._sessions)

    def test_deregistered_resource_session_is_skipped(self) -> None:
        first = self._register("first", "a" * 64)
        second = self._register("second", "b" * 64)
        self._start(first, 1, "a" * 64)
        self._start(second, 1, "b" * 64)

        status, _h, body = call_json("DELETE", f"/resources/{first}")
        assert status == "200 OK", body

        self.assertEqual(
            [r["resource_id"] for r in self._summary()], [second]
        )
        self.assertNotIn(first, content_store._sessions)

    # --- Ordering ----------------------------------------------------------

    def test_entries_follow_session_registration_order(self) -> None:
        a = self._register("a", "1" * 64)
        b = self._register("b", "2" * 64)
        c = self._register("c", "3" * 64)
        # Sessions appear in an order unrelated to resource registration.
        self._start(c, 1, "3" * 64)
        self._chunk(a, 0, 1, "1" * 64, b"x")
        self._start(b, 1, "2" * 64)
        self.assertEqual(
            [r["resource_id"] for r in self._summary()], [c, a, b]
        )

    def test_uploads_and_assembly_never_reorder_entries(self) -> None:
        digest_c = hashlib.sha256(b"c").hexdigest()
        digest_a = hashlib.sha256(b"aa").hexdigest()
        c = self._register("c", digest_c)
        a = self._register("a", digest_a)
        self._chunk(c, 0, 1, digest_c, b"c")
        self._start(a, 2, digest_a)
        order = [c, a]

        self._chunk(a, 0, 2, digest_a, b"a")
        self._chunk(a, 1, 2, digest_a, b"a")
        self._assemble(c)
        self.assertEqual(
            [r["resource_id"] for r in self._summary()], order
        )

    def test_each_resource_appears_exactly_once(self) -> None:
        digest = hashlib.sha256(b"abc").hexdigest()
        resource_id = self._register("r", digest)
        self._chunk(resource_id, 0, 3, digest, b"a")
        # Idempotent resubmission and further chunks must not duplicate.
        self._chunk(resource_id, 0, 3, digest, b"a")
        self._chunk(resource_id, 2, 3, digest, b"c")
        records = self._summary()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["received_chunks"], 2)

    # --- Immediate recomputation ------------------------------------------

    def test_summary_recomputes_after_every_mutation(self) -> None:
        digest = hashlib.sha256(b"ab").hexdigest()
        resource_id = self._register("r", digest)
        self.assertEqual(self._summary(), [])

        self._chunk(resource_id, 0, 2, digest, b"a")
        self.assertEqual(
            self._summary()[0]["missing_chunks"], [1]
        )
        self._chunk(resource_id, 1, 2, digest, b"b")
        self.assertEqual(self._summary()[0]["missing_chunks"], [])
        self.assertFalse(self._summary()[0]["complete"])

        self._assemble(resource_id)
        record = self._summary()[0]
        self.assertTrue(record["complete"])
        self.assertEqual(record["size"], 2)

    def test_empty_result_is_still_success_after_last_session_disappears(
        self,
    ) -> None:
        resource_id = self._register("r", "a" * 64)
        self._start(resource_id, 1, "a" * 64)
        self.assertEqual(len(self._summary()), 1)
        self._reset(resource_id)
        status, _headers, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

    # --- Read-only ---------------------------------------------------------

    def test_query_does_not_modify_any_state(self) -> None:
        digest = hashlib.sha256(b"a").hexdigest()
        resource_id = self._register("r", digest)
        self._start(resource_id, 2, digest)
        before = {
            key: (
                session.total,
                session.digest,
                dict(session.chunks),
                session.complete,
                session.content,
            )
            for key, session in content_store._sessions.items()
        }
        for _ in range(3):
            call("GET", PATH)
        after = {
            key: (
                session.total,
                session.digest,
                dict(session.chunks),
                session.complete,
                session.content,
            )
            for key, session in content_store._sessions.items()
        }
        self.assertEqual(before, after)
        self.assertEqual(set(content_store._sessions), {resource_id})

    # --- Empty body handling ----------------------------------------------

    def test_omitted_body_is_accepted(self) -> None:
        status, _h, body = call_json("GET", PATH, omit_content_length=True)
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, [])

    def test_explicit_zero_length_is_accepted(self) -> None:
        status, _h, body = call_json("GET", PATH, content_length="0")
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, [])

    def test_empty_string_content_length_is_accepted(self) -> None:
        status, _h, body = call_json("GET", PATH, content_length="")
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, [])

    def test_declared_non_empty_body_is_bad_request(self) -> None:
        status, _h, body = call_json("GET", PATH, b"x")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")  # type: ignore[index]

    def test_malformed_content_length_is_bad_request(self) -> None:
        for raw in ("abc", "-1", "1.5"):
            with self.subTest(raw=raw):
                status, _h, body = call_json(
                    "GET", PATH, content_length=raw
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")  # type: ignore[index]

    # --- Query parameters --------------------------------------------------

    def test_any_query_parameter_is_bad_request(self) -> None:
        resource_id = self._register("r", "a" * 64)
        self._start(resource_id, 1, "a" * 64)
        for qs in ("x=1", "pretty=true", "resource_id=r", "limit=1"):
            with self.subTest(qs=qs):
                status, _h, body = call_json("GET", PATH, query_string=qs)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")  # type: ignore[index]

    def test_bad_request_does_not_read_business_data(self) -> None:
        # Rejected purely on the request envelope even with no sessions.
        status, _h, body = call_json("GET", PATH, query_string="x=1")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")  # type: ignore[index]
        status, _h, body = call_json("GET", PATH, b"data")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")  # type: ignore[index]

    def test_error_body_is_compact_json_with_single_newline(self) -> None:
        _s, _h, raw = call("GET", PATH, query_string="x=1")
        payload = json.loads(raw.decode("utf-8"))
        self.assertEqual(set(payload), {"error", "message"})
        self.assertTrue(raw.endswith(b"\n"))
        self.assertEqual(raw.count(b"\n"), 1)

    # --- Methods -----------------------------------------------------------

    def test_non_get_methods_return_405_with_get_only_allow(self) -> None:
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, headers, body = call_json(method, PATH)
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")  # type: ignore[index]
                self.assertIn(("Allow", "GET"), headers)
                self.assertNotIn(("Allow", "GET, POST"), headers)

    def test_method_check_precedes_body_and_query_checks(self) -> None:
        status, headers, body = call_json(
            "POST", PATH, {"unexpected": True}, query_string="x=1"
        )
        self.assertEqual(status, "405 Method Not Allowed")
        self.assertEqual(body["error"], "method_not_allowed")  # type: ignore[index]
        self.assertIn(("Allow", "GET"), headers)


if __name__ == "__main__":
    unittest.main()
