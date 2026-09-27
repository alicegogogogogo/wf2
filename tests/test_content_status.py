from __future__ import annotations

import hashlib
import io
import json
import unittest

from provenance_api.app import application, reset_state

PATH = "/content-status"

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64


def digest_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def call(
    method: str,
    path: str = PATH,
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
        "QUERY_STRING": query_string if query_string is not None else "",
        "wsgi.input": io.BytesIO(body),
    }
    if not omit_content_length:
        environ["CONTENT_LENGTH"] = (
            str(len(body)) if content_length is None else str(content_length)
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
    body: bytes = b"",
    **kwargs: object,
) -> tuple[str, list[tuple[str, str]], object]:
    status, headers, raw = call(method, path, body, **kwargs)  # type: ignore[arg-type]
    return status, headers, json.loads(raw.decode("utf-8"))


def chunk_headers(total: int | str, digest: str) -> dict[str, str]:
    return {
        "CONTENT_TYPE": "application/octet-stream",
        "HTTP_X_TOTAL_CHUNKS": str(total),
        "HTTP_X_CONTENT_DIGEST": digest,
    }


class ContentStatusSummaryTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.ids: dict[str, str] = {}

    def _create(self, label: str, digest: str) -> str:
        body = json.dumps(
            {"name": label, "category": "code", "digest": digest}
        ).encode("utf-8")
        status, _h, raw = call(
            "POST",
            "/resources",
            body,
            headers={"CONTENT_TYPE": "application/json"},
        )
        self.assertEqual(status, "201 Created")
        resource_id = str(json.loads(raw)["id"])
        self.ids[label] = resource_id
        return resource_id

    def _start(self, resource_id: str, total: int, digest: str) -> None:
        body = json.dumps({"total_chunks": total, "digest": digest}).encode()
        status, _h, _b = call(
            "POST",
            f"/resources/{resource_id}/chunks/start",
            body,
            headers={"CONTENT_TYPE": "application/json"},
        )
        self.assertEqual(status, "201 Created")

    def _chunk(
        self, resource_id: str, index: int, total: int, digest: str, data: bytes
    ) -> None:
        status, _h, _b = call(
            "POST",
            f"/resources/{resource_id}/chunks/{index}",
            data,
            headers=chunk_headers(total, digest),
        )
        self.assertEqual(status, "201 Created")

    def _summary(self) -> list[dict[str, object]]:
        status, headers, body = call_json("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertIsInstance(body, list)
        return body  # type: ignore[return-value]

    # --- Shape -------------------------------------------------------------

    def test_empty_array_when_no_resources(self) -> None:
        status, headers, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )

    def test_unstarted_resources_are_listed_as_incomplete(self) -> None:
        first = self._create("a", DIGEST_A)
        second = self._create("b", DIGEST_B)
        self.assertEqual(
            self._summary(),
            [
                {"id": first, "complete": False, "size": None},
                {"id": second, "complete": False, "size": None},
            ],
        )

    def test_entries_follow_resource_registration_order(self) -> None:
        first = digest_of(b"first")
        second = digest_of(b"second")
        third = digest_of(b"third")
        self._create("first", first)
        self._create("second", second)
        self._create("third", third)
        # Complete the uploads out of registration order; the summary must
        # still follow the resource order.
        self._chunk(self.ids["third"], 0, 1, third, b"third")
        self._chunk(self.ids["first"], 0, 1, first, b"first")

        body = self._summary()
        self.assertEqual(
            [entry["id"] for entry in body],
            [self.ids["first"], self.ids["second"], self.ids["third"]],
        )

    def test_entry_has_exactly_three_keys_in_fixed_order(self) -> None:
        digest = digest_of(b"ab")
        resource_id = self._create("a", digest)
        self._chunk(resource_id, 0, 1, digest, b"ab")
        status, _h, _b = call("POST", f"/resources/{resource_id}/assemble")
        self.assertEqual(status, "201 Created")

        (entry,) = self._summary()
        self.assertEqual(list(entry), ["id", "complete", "size"])

    def test_response_is_compact_utf8_newline_terminated(self) -> None:
        self._create("a", DIGEST_A)

        status, _headers, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertTrue(raw.endswith(b"\n"))
        self.assertEqual(raw.count(b"\n"), 1)
        self.assertNotIn(b" ", raw[:-1])
        text = raw.decode("utf-8").rstrip("\n")
        keys = ['"id"', '"complete"', '"size"']
        positions = [text.index(key) for key in keys]
        self.assertEqual(positions, sorted(positions))

    # --- Content states ----------------------------------------------------

    def test_incomplete_chunks_report_false_and_null_size(self) -> None:
        self._create("a", DIGEST_A)
        self._start(self.ids["a"], 3, DIGEST_A)
        self._chunk(self.ids["a"], 0, 3, DIGEST_A, b"x")

        (entry,) = self._summary()
        self.assertEqual(entry["id"], self.ids["a"])
        self.assertIs(entry["complete"], False)
        self.assertIsNone(entry["size"])

    def test_assembled_content_reports_true_and_actual_size(self) -> None:
        digest = digest_of(b"abcdef")
        resource_id = self._create("a", digest)
        for index, part in ((1, b"cd"), (2, b"ef"), (0, b"ab")):
            self._chunk(resource_id, index, 3, digest, part)
        status, _h, _b = call("POST", f"/resources/{resource_id}/assemble")
        self.assertEqual(status, "201 Created")

        (entry,) = self._summary()
        self.assertIs(entry["complete"], True)
        self.assertEqual(entry["size"], 6)

    def test_empty_assembled_content_reports_size_zero(self) -> None:
        empty_digest = digest_of(b"")
        resource_id = self._create("empty", empty_digest)
        self._chunk(resource_id, 0, 1, empty_digest, b"")
        status, _h, _b = call("POST", f"/resources/{resource_id}/assemble")
        self.assertEqual(status, "201 Created")

        (entry,) = self._summary()
        self.assertIs(entry["complete"], True)
        self.assertEqual(entry["size"], 0)

    def test_digest_mismatch_failure_reports_false_and_null_size(self) -> None:
        registered = digest_of(b"abc")
        resource_id = self._create("a", registered)
        self._chunk(resource_id, 0, 1, registered, b"abd")
        status, _h, body = call_json(
            "POST", f"/resources/{resource_id}/assemble"
        )
        self.assertEqual(body["error"], "digest_mismatch")

        (entry,) = self._summary()
        self.assertIs(entry["complete"], False)
        self.assertIsNone(entry["size"])

    # --- Recomputation and read-only behavior ------------------------------

    def test_recomputes_after_upload_and_assembly(self) -> None:
        digest = digest_of(b"ab")
        resource_id = self._create("a", digest)

        (entry,) = self._summary()
        self.assertIs(entry["complete"], False)
        self.assertIsNone(entry["size"])

        self._chunk(resource_id, 0, 2, digest, b"a")
        self._chunk(resource_id, 1, 2, digest, b"b")
        (entry,) = self._summary()
        self.assertIs(entry["complete"], False)

        status, _h, _b = call("POST", f"/resources/{resource_id}/assemble")
        self.assertEqual(status, "201 Created")
        (entry,) = self._summary()
        self.assertIs(entry["complete"], True)
        self.assertEqual(entry["size"], 2)

    def test_reset_returns_entry_to_incomplete(self) -> None:
        digest = digest_of(b"ab")
        resource_id = self._create("a", digest)
        self._chunk(resource_id, 0, 2, digest, b"a")
        (entry,) = self._summary()
        self.assertIs(entry["complete"], False)

        status, _h, _b = call("DELETE", f"/resources/{resource_id}/chunks")
        self.assertEqual(status, "200 OK")

        # The resource stays listed, back to the unstarted state.
        (entry,) = self._summary()
        self.assertEqual(
            entry, {"id": resource_id, "complete": False, "size": None}
        )

    def test_resource_deregistration_removes_its_entry(self) -> None:
        first_digest = digest_of(b"aa")
        second_digest = digest_of(b"bb")
        first = self._create("first", first_digest)
        second = self._create("second", second_digest)
        self._chunk(first, 0, 1, first_digest, b"aa")
        self._chunk(second, 0, 1, second_digest, b"bb")
        call("POST", f"/resources/{first}/assemble")
        call("POST", f"/resources/{second}/assemble")
        self.assertEqual(len(self._summary()), 2)

        status, _h, _b = call("DELETE", f"/resources/{first}")
        self.assertEqual(status, "200 OK")

        body = self._summary()
        self.assertEqual(
            body, [{"id": second, "complete": True, "size": 2}]
        )

    def test_view_is_read_only(self) -> None:
        digest = digest_of(b"ab")
        resource_id = self._create("a", digest)
        self._chunk(resource_id, 0, 2, digest, b"a")

        first_status, _h, first = call("GET", PATH)
        second_status, _h, second = call("GET", PATH)
        self.assertEqual(first_status, second_status)
        self.assertEqual(first, second)

        # The session is exactly as it was before the queries.
        _s, _h, status_body = call_json(
            "GET", f"/resources/{resource_id}/chunks/status"
        )
        self.assertEqual(status_body["received_chunks"], 1)
        self.assertEqual(status_body["missing_chunks"], [1])

    def test_per_resource_endpoints_are_unchanged(self) -> None:
        digest = digest_of(b"ab")
        resource_id = self._create("a", digest)
        self._chunk(resource_id, 0, 2, digest, b"a")

        self._summary()
        status, _h, body = call_json(
            "GET", f"/resources/{resource_id}/chunks/status"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            body,
            {
                "id": resource_id,
                "digest": digest,
                "total_chunks": 2,
                "received_chunks": 1,
                "missing_chunks": [1],
                "complete": False,
                "size": None,
            },
        )
        # The per-resource session summary keeps skipping unstarted
        # resources while this view lists them.
        other = self._create("b", DIGEST_B)
        status, _h, sessions_body = call_json("GET", "/upload-sessions")
        self.assertEqual(status, "200 OK")
        self.assertEqual([entry["id"] for entry in sessions_body], [resource_id])
        self.assertEqual(
            [entry["id"] for entry in self._summary()],
            [resource_id, other],
        )

    # --- Errors ------------------------------------------------------------

    def test_non_get_methods_return_405_with_allow_get(self) -> None:
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            with self.subTest(method=method):
                status, headers, body = call_json(method, PATH)
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")
                allow_values = [
                    value for name, value in headers if name == "Allow"
                ]
                self.assertEqual(allow_values, ["GET"])

    def test_non_empty_body_rejected(self) -> None:
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
        for kwargs in (
            {"omit_content_length": True},
            {"content_length": 0},
            {"content_length": ""},
        ):
            with self.subTest(kwargs=kwargs):
                status, _h, raw = call("GET", PATH, **kwargs)
                self.assertEqual(status, "200 OK")
                self.assertEqual(raw, b"[]\n")

    def test_query_parameters_return_400(self) -> None:
        for query_string in (
            "x=1",
            "resource_id=anything",
            "page=2",
            "complete=true",
            "=",
        ):
            with self.subTest(query_string=query_string):
                status, _h, body = call_json(
                    "GET", PATH, query_string=query_string
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_bad_request_does_not_read_business_data(self) -> None:
        digest = digest_of(b"ab")
        resource_id = self._create("a", digest)
        self._chunk(resource_id, 0, 2, digest, b"a")

        status, _h, body = call_json("GET", PATH, body=b"{}")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

        status, _h, body = call_json("GET", PATH, query_string="x=1")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

        # The session is exactly as it was before the rejected queries.
        self.assertEqual(
            self._summary(),
            [{"id": resource_id, "complete": False, "size": None}],
        )

    def test_error_body_uses_existing_shape(self) -> None:
        status, _h, raw = call("GET", PATH, query_string="x=1")
        self.assertEqual(status, "400 Bad Request")
        self.assertTrue(raw.endswith(b"\n"))
        text = raw.decode("utf-8").rstrip("\n")
        decoded = json.loads(text)
        self.assertEqual(set(decoded), {"error", "message"})
        self.assertEqual(decoded["error"], "invalid_request")
        self.assertEqual(
            text,
            json.dumps(decoded, ensure_ascii=False, separators=(",", ":")),
        )


if __name__ == "__main__":
    unittest.main()
