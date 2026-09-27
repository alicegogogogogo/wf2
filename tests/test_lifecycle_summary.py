from __future__ import annotations

import hashlib
import io
import json
import unittest

from provenance_api.app import application, lifecycle_store, reset_state

PATH = "/lifecycle"


def call(
    method: str,
    path: str = PATH,
    body: bytes | str | dict[str, object] | None = None,
    *,
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
        "CONTENT_TYPE": "application/json",
        "wsgi.input": io.BytesIO(payload),
    }
    if not omit_content_length:
        environ["CONTENT_LENGTH"] = (
            str(len(payload)) if content_length is None else str(content_length)
        )
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
    content_length: int | str | None = None,
    omit_content_length: bool = False,
) -> tuple[str, list[tuple[str, str]], object]:
    status, headers, raw = call(
        method,
        path,
        body,
        query_string=query_string,
        content_length=content_length,
        omit_content_length=omit_content_length,
    )
    return status, headers, json.loads(raw.decode("utf-8"))


class LifecycleSummaryTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    # --- Setup helpers -----------------------------------------------------

    def _register(self, name: str) -> str:
        digest = hashlib.sha256(name.encode()).hexdigest()
        _s, _h, body = call_json(
            "POST",
            "/resources",
            {"name": name, "category": "artifact", "digest": digest},
        )
        return str(body["id"])  # type: ignore[index]

    def _lifecycle(
        self, resource_id: str, state: str, reason: str | None = None
    ) -> None:
        payload: dict[str, object] = {"state": state}
        if reason is not None:
            payload["reason"] = reason
        status, _h, body = call_json(
            "POST", f"/resources/{resource_id}/lifecycle", payload
        )
        assert status == "200 OK", body

    def _summary(self) -> list[dict[str, object]]:
        status, _h, body = call_json("GET", PATH)
        assert status == "200 OK"
        assert isinstance(body, list)
        return body  # type: ignore[return-value]

    # --- Shape -------------------------------------------------------------

    def test_empty_registry_is_empty_array(self) -> None:
        status, headers, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            ("Content-Type", "application/json; charset=utf-8"), headers[0]
        )
        self.assertEqual(raw, b"[]\n")

    def test_body_is_compact_utf8_with_a_single_newline(self) -> None:
        self._register("root")
        _s, _h, raw = call("GET", PATH)
        self.assertTrue(raw.endswith(b"\n"))
        self.assertEqual(raw.count(b"\n"), 1)
        self.assertNotIn(b" ", raw[:-1])

    def test_top_level_is_an_array_without_a_wrapper(self) -> None:
        first = self._register("first")
        second = self._register("second")

        status, _h, body = call_json("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertIsInstance(body, list)
        self.assertEqual([record["id"] for record in body], [first, second])  # type: ignore[index]

    def test_new_resources_default_to_staged_with_null_reason(self) -> None:
        resource_id = self._register("root")
        self.assertEqual(
            self._summary(),
            [{"id": resource_id, "state": "staged", "reason": None}],
        )
        # Reading the summary must not materialize a stored lifecycle record.
        self.assertNotIn(resource_id, lifecycle_store._records)

    def test_record_fields_and_key_order_match_single_resource_view(self) -> None:
        root = self._register("root")
        self._lifecycle(root, "quarantined", "hold")

        _s, _h, raw = call("GET", PATH)
        text = raw.decode("utf-8").rstrip("\n")
        keys = ['"id"', '"state"', '"reason"']
        positions = [text.index(k) for k in keys]
        self.assertEqual(positions, sorted(positions))

        _s, _h, single = call_json("GET", f"/resources/{root}/lifecycle")
        self.assertEqual(self._summary(), [single])

    def test_reason_is_echoed_or_null_but_field_is_never_omitted(self) -> None:
        held = self._register("held")
        plain = self._register("plain")
        self._lifecycle(held, "quarantined", "investigating")

        records = {record["id"]: record for record in self._summary()}
        self.assertEqual(
            records[held],
            {"id": held, "state": "quarantined", "reason": "investigating"},
        )
        self.assertEqual(
            records[plain],
            {"id": plain, "state": "staged", "reason": None},
        )

    # --- Ordering ----------------------------------------------------------

    def test_records_follow_resource_registration_order(self) -> None:
        ids = [self._register(f"r{i}") for i in range(5)]
        # State changes in an unrelated order must not reorder the summary.
        self._lifecycle(ids[3], "quarantined", "x")
        self._lifecycle(ids[1], "quarantined", "y")
        self.assertEqual([record["id"] for record in self._summary()], ids)

    def test_each_resource_appears_exactly_once(self) -> None:
        ids = [self._register(f"r{i}") for i in range(5)]
        records = self._summary()
        self.assertEqual(len(records), len(ids))
        self.assertEqual(
            sorted(record["id"] for record in records), sorted(ids)
        )

    # --- Immediate recomputation ------------------------------------------

    def test_lifecycle_commit_is_reflected_immediately(self) -> None:
        resource_id = self._register("root")

        def record() -> dict[str, object]:
            return [r for r in self._summary() if r["id"] == resource_id][0]

        self.assertEqual(record()["state"], "staged")
        self._lifecycle(resource_id, "quarantined", "hold")
        self.assertEqual(record()["state"], "quarantined")
        self.assertEqual(record()["reason"], "hold")
        # Back to staged clears the reason at once.
        self._lifecycle(resource_id, "staged")
        self.assertEqual(record()["state"], "staged")
        self.assertIsNone(record()["reason"])

    def test_resource_deregistration_leaves_no_residue(self) -> None:
        first = self._register("first")
        second = self._register("second")
        self._lifecycle(second, "quarantined", "hold")

        status, _h, body = call_json("DELETE", f"/resources/{second}")
        assert status == "200 OK", body

        self.assertEqual(
            self._summary(),
            [{"id": first, "state": "staged", "reason": None}],
        )
        self.assertNotIn(second, lifecycle_store._records)

    # --- Read-only ---------------------------------------------------------

    def test_query_does_not_modify_any_state(self) -> None:
        held = self._register("held")
        plain = self._register("plain")
        self._lifecycle(held, "quarantined", "hold")
        stored_before = dict(lifecycle_store._records)

        for _ in range(2):
            self.assertEqual(
                [r["id"] for r in self._summary()], [held, plain]
            )
        self.assertEqual(set(lifecycle_store._records), set(stored_before))
        self.assertNotIn(plain, lifecycle_store._records)

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
                status, _h, body = call_json("GET", PATH, content_length=raw)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")  # type: ignore[index]

    # --- Query parameters --------------------------------------------------

    def test_any_query_parameter_is_bad_request(self) -> None:
        self._register("root")
        for qs in ("x=1", "pretty=true", "state=staged", "limit=1"):
            with self.subTest(qs=qs):
                status, _h, body = call_json("GET", PATH, query_string=qs)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")  # type: ignore[index]

    def test_bad_request_does_not_read_business_data(self) -> None:
        # No resources exist, yet a query parameter / declared body is
        # rejected purely on the request envelope.
        status, _h, body = call_json("GET", PATH, query_string="x=1")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")  # type: ignore[index]
        status, _h, body = call_json("GET", PATH, b"data")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")  # type: ignore[index]

    def test_error_body_is_compact_json_with_single_newline(self) -> None:
        _s, _h, raw = call("GET", PATH, query_string="x=1")
        payload = json.loads(raw.decode("utf-8"))
        self.assertEqual(
            set(payload), {"error", "message"}
        )
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
        # A non-GET request carrying a body and a query string still answers
        # 405, and the Allow header names GET alone.
        status, headers, body = call_json(
            "POST", PATH, {"unexpected": True}, query_string="x=1"
        )
        self.assertEqual(status, "405 Method Not Allowed")
        self.assertEqual(body["error"], "method_not_allowed")  # type: ignore[index]
        self.assertIn(("Allow", "GET"), headers)


if __name__ == "__main__":
    unittest.main()
