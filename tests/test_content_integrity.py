from __future__ import annotations

import hashlib
import io
import json
import unittest

from provenance_api.app import application, content_store, reset_state

PATH = "/content-integrity"

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


class ContentIntegritySummaryTests(unittest.TestCase):
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

    def _assemble(self, resource_id: str) -> None:
        status, _h, _b = call("POST", f"/resources/{resource_id}/assemble")
        self.assertEqual(status, "201 Created")

    def _summary(self) -> list[dict[str, object]]:
        status, headers, body = call_json("GET", PATH)
        self.assertEqual(status, "200 OK")
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

    def test_entries_follow_resource_registration_order(self) -> None:
        first = digest_of(b"first")
        second = digest_of(b"second")
        third = digest_of(b"third")
        self._create("first", first)
        self._create("second", second)
        self._create("third", third)
        # Finish sessions out of registration order; the inspection must
        # still follow the resource order.
        self._chunk(self.ids["third"], 0, 1, third, b"third")
        self._assemble(self.ids["third"])
        self._chunk(self.ids["first"], 0, 1, first, b"first")
        self._assemble(self.ids["first"])

        body = self._summary()
        self.assertEqual(
            [entry["id"] for entry in body],
            [self.ids["first"], self.ids["second"], self.ids["third"]],
        )

    def test_one_entry_per_resource_with_fixed_fields(self) -> None:
        self._create("a", DIGEST_A)
        self._create("b", DIGEST_B)
        self._start(self.ids["a"], 2, DIGEST_A)
        self._chunk(self.ids["b"], 0, 1, DIGEST_B, b"x")

        body = self._summary()
        self.assertEqual(len(body), 2)
        self.assertEqual(
            [list(entry) for entry in body],
            [
                ["id", "digest", "actual", "valid"],
                ["id", "digest", "actual", "valid"],
            ],
        )

    def test_response_is_compact_utf8_newline_terminated(self) -> None:
        self._create("a", DIGEST_A)
        self._start(self.ids["a"], 2, DIGEST_A)

        status, _headers, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertTrue(raw.endswith(b"\n"))
        self.assertEqual(raw.count(b"\n"), 1)
        self.assertNotIn(b" ", raw[:-1])
        text = raw.decode("utf-8").rstrip("\n")
        keys = ['"id"', '"digest"', '"actual"', '"valid"']
        positions = [text.index(key) for key in keys]
        self.assertEqual(positions, sorted(positions))

    # --- Inspection results ------------------------------------------------

    def test_never_started_resource_is_empty_and_invalid(self) -> None:
        self._create("a", DIGEST_A)

        (entry,) = self._summary()
        self.assertEqual(entry["id"], self.ids["a"])
        self.assertEqual(entry["digest"], DIGEST_A)
        self.assertEqual(entry["actual"], "")
        self.assertIs(entry["valid"], False)

    def test_in_progress_resource_is_empty_and_invalid(self) -> None:
        digest = digest_of(b"abcd")
        resource_id = self._create("a", digest)
        self._chunk(resource_id, 2, 4, digest, b"c")
        self._chunk(resource_id, 0, 4, digest, b"a")

        (entry,) = self._summary()
        self.assertEqual(entry["digest"], digest)
        self.assertEqual(entry["actual"], "")
        self.assertIs(entry["valid"], False)

    def test_explicit_start_without_chunks_is_empty_and_invalid(self) -> None:
        self._create("a", DIGEST_A)
        self._start(self.ids["a"], 3, DIGEST_A)

        (entry,) = self._summary()
        self.assertEqual(entry["actual"], "")
        self.assertIs(entry["valid"], False)

    def test_completed_content_recomputes_and_matches(self) -> None:
        digest = digest_of(b"abcdef")
        resource_id = self._create("a", digest)
        for index, part in ((1, b"cd"), (2, b"ef"), (0, b"ab")):
            self._chunk(resource_id, index, 3, digest, part)
        self._assemble(resource_id)

        (entry,) = self._summary()
        self.assertEqual(entry["id"], resource_id)
        self.assertEqual(entry["digest"], digest)
        self.assertEqual(entry["actual"], digest)
        self.assertIs(entry["valid"], True)

    def test_empty_completed_content_matches(self) -> None:
        empty_digest = digest_of(b"")
        resource_id = self._create("empty", empty_digest)
        self._chunk(resource_id, 0, 1, empty_digest, b"")
        self._assemble(resource_id)

        (entry,) = self._summary()
        self.assertEqual(entry["actual"], empty_digest)
        self.assertIs(entry["valid"], True)

    def test_digest_mismatch_assembly_stays_empty_and_invalid(self) -> None:
        registered = digest_of(b"abc")
        resource_id = self._create("a", registered)
        self._chunk(resource_id, 0, 1, registered, b"abd")
        status, _h, body = call_json(
            "POST", f"/resources/{resource_id}/assemble"
        )
        self.assertEqual(body["error"], "digest_mismatch")

        (entry,) = self._summary()
        self.assertEqual(entry["digest"], registered)
        self.assertEqual(entry["actual"], "")
        self.assertIs(entry["valid"], False)

    def test_mixed_resources_report_independent_results(self) -> None:
        done_digest = digest_of(b"aa")
        idle = self._create("idle", DIGEST_B)
        doing = self._create("doing", DIGEST_A)
        done = self._create("done", done_digest)
        self._start(doing, 2, DIGEST_A)
        self._chunk(done, 0, 1, done_digest, b"aa")
        self._assemble(done)

        body = self._summary()
        self.assertEqual([entry["id"] for entry in body], [idle, doing, done])
        self.assertEqual(body[0]["actual"], "")
        self.assertIs(body[0]["valid"], False)
        self.assertEqual(body[1]["actual"], "")
        self.assertIs(body[1]["valid"], False)
        self.assertEqual(body[2]["actual"], done_digest)
        self.assertIs(body[2]["valid"], True)

    def test_registered_digest_is_echoed(self) -> None:
        digest = digest_of(b"abc")
        resource_id = self._create("a", digest.upper())
        self._chunk(resource_id, 0, 1, digest.upper(), b"abc")
        self._assemble(resource_id)

        # Registration normalizes hex digests to lowercase, so both the
        # registered echo and the recomputed digest are lowercase and equal.
        (entry,) = self._summary()
        self.assertEqual(entry["digest"], digest)
        self.assertEqual(entry["actual"], digest)
        self.assertIs(entry["valid"], True)

    # --- Recomputation and read-only behavior ------------------------------

    def test_recomputes_after_assembly_reset_and_deregistration(self) -> None:
        digest = digest_of(b"ab")
        resource_id = self._create("a", digest)

        (entry,) = self._summary()
        self.assertEqual(entry["actual"], "")
        self.assertIs(entry["valid"], False)

        self._chunk(resource_id, 0, 2, digest, b"a")
        (entry,) = self._summary()
        self.assertEqual(entry["actual"], "")
        self.assertIs(entry["valid"], False)

        self._chunk(resource_id, 1, 2, digest, b"b")
        self._assemble(resource_id)
        (entry,) = self._summary()
        self.assertEqual(entry["actual"], digest)
        self.assertIs(entry["valid"], True)

        other_digest = digest_of(b"xy")
        other = self._create("b", other_digest)
        self._chunk(other, 0, 1, other_digest, b"xy")
        self._assemble(other)
        status, _h, _b = call("DELETE", f"/resources/{other}")
        self.assertEqual(status, "200 OK")

        body = self._summary()
        self.assertEqual([entry["id"] for entry in body], [resource_id])
        self.assertEqual(body[0]["actual"], digest)
        self.assertIs(body[0]["valid"], True)

    def test_reset_session_flips_entry_back_to_empty(self) -> None:
        digest = digest_of(b"ab")
        resource_id = self._create("a", digest)
        self._chunk(resource_id, 0, 2, digest, b"a")

        status, _h, _b = call("DELETE", f"/resources/{resource_id}/chunks")
        self.assertEqual(status, "200 OK")

        self.assertEqual(
            self._summary(),
            [{"id": resource_id, "digest": digest, "actual": "", "valid": False}],
        )

    def test_entry_appears_immediately_after_registration(self) -> None:
        self.assertEqual(self._summary(), [])
        resource_id = self._create("a", DIGEST_A)
        self.assertEqual(
            self._summary(),
            [
                {
                    "id": resource_id,
                    "digest": DIGEST_A,
                    "actual": "",
                    "valid": False,
                }
            ],
        )

    def test_view_is_read_only(self) -> None:
        digest = digest_of(b"ab")
        resource_id = self._create("a", digest)
        self._chunk(resource_id, 0, 2, digest, b"a")
        self._chunk(resource_id, 1, 2, digest, b"b")
        self._assemble(resource_id)

        first_status, _h, first = call("GET", PATH)
        second_status, _h, second = call("GET", PATH)
        self.assertEqual(first_status, second_status)
        self.assertEqual(first, second)

        # Sessions and finalized bytes are untouched; the content itself is
        # still readable byte-for-byte.
        status, _h, content = call("GET", f"/resources/{resource_id}/content")
        self.assertEqual(status, "200 OK")
        self.assertEqual(content, b"ab")

    def test_existing_endpoints_are_unchanged(self) -> None:
        digest = digest_of(b"ab")
        resource_id = self._create("a", digest)
        self._chunk(resource_id, 0, 2, digest, b"a")

        self._summary()

        # The readiness summary keeps its three-field shape.
        status, _h, body = call_json("GET", "/content-status")
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            body,
            [{"id": resource_id, "complete": False, "size": None}],
        )

        # The per-resource session status keeps its seven-field shape.
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
        resource_id = self._create("a", DIGEST_A)
        expected = (
            b'[{"id":"'
            + resource_id.encode("ascii")
            + b'","digest":"'
            + DIGEST_A.encode("ascii")
            + b'","actual":"","valid":false}]\n'
        )
        for kwargs in (
            {"omit_content_length": True},
            {"content_length": 0},
            {"content_length": ""},
        ):
            with self.subTest(kwargs=kwargs):
                status, _h, raw = call("GET", PATH, **kwargs)
                self.assertEqual(status, "200 OK")
                self.assertEqual(raw, expected)

    def test_query_parameters_return_400(self) -> None:
        for query_string in (
            "x=1",
            "resource_id=anything",
            "valid=true",
            "page=2",
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
        self._chunk(resource_id, 1, 2, digest, b"b")
        self._assemble(resource_id)

        status, _h, body = call_json("GET", PATH, body=b"{}")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

        status, _h, body = call_json("GET", PATH, query_string="x=1")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

        # The finalized bytes are exactly as they were before.
        (entry,) = self._summary()
        self.assertEqual(entry["actual"], digest)
        self.assertIs(entry["valid"], True)

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


class RecomputedDigestStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def test_none_without_session_or_completion(self) -> None:
        from provenance_api.content import _Session

        self.assertIsNone(content_store.recomputed_digest("missing"))
        # An in-progress session without finalized bytes has no digest.
        content_store._sessions["r"] = _Session(total=1, digest=DIGEST_A)  # noqa: SLF001
        self.assertIsNone(content_store.recomputed_digest("r"))

    def test_recomputes_stored_bytes_even_if_tampered(self) -> None:
        # A mismatch between finalized bytes and the bound digest cannot
        # arise through normal assembly, but the inspection must still
        # report it verbatim rather than treating it as an error.
        from provenance_api.content import _Session

        actual_digest = digest_of(b"actual bytes")
        session = _Session(total=1, digest=DIGEST_A)
        session.complete = True
        session.content = b"actual bytes"
        content_store._sessions["r"] = session  # noqa: SLF001

        self.assertEqual(content_store.recomputed_digest("r"), actual_digest)
        self.assertNotEqual(actual_digest, DIGEST_A)


if __name__ == "__main__":
    unittest.main()
