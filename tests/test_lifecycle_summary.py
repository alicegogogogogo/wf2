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

    def _register(self, name: str = "r") -> str:
        digest = hashlib.sha256(name.encode()).hexdigest()
        _s, _h, body = call_json(
            "POST",
            "/resources",
            {"name": name, "category": "artifact", "digest": digest},
        )
        assert _s == "201 Created", body
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
        resource_id = self._register()
        status, _h, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            raw,
            f'[{{"id":"{resource_id}","state":"staged","reason":null}}]\n'.encode(),
        )
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        # Compact JSON: no whitespace outside strings.
        self.assertNotIn(b", ", raw)
        self.assertNotIn(b": ", raw)

    def test_top_level_is_an_array_without_a_wrapper(self) -> None:
        self._register()
        status, _h, body = call_json("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertIsInstance(body, list)
        self.assertEqual(len(body), 1)  # type: ignore[arg-type]

    def test_record_fields_and_key_order_match_single_resource_view(self) -> None:
        resource_id = self._register()
        status, _h, single = call(
            "GET", f"/resources/{resource_id}/lifecycle"
        )
        self.assertEqual(status, "200 OK")
        status, _h, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[" + single.rstrip(b"\n") + b"]\n")

    def test_new_resource_is_staged_with_empty_reason(self) -> None:
        resource_id = self._register()
        records = self._summary()
        self.assertEqual(
            records,
            [{"id": resource_id, "state": "staged", "reason": None}],
        )
        # Reading the summary must not materialize any stored record.
        self.assertNotIn(resource_id, lifecycle_store._records)

    def test_reason_is_echoed_and_null_is_never_omitted(self) -> None:
        held = self._register("held")
        self._lifecycle(held, "quarantined", "调查中")
        plain = self._register("plain")

        records = self._summary()
        self.assertEqual(
            records,
            [
                {"id": held, "state": "quarantined", "reason": "调查中"},
                {"id": plain, "state": "staged", "reason": None},
            ],
        )
        for record in records:
            self.assertEqual(
                list(record), ["id", "state", "reason"]
            )

    def test_records_follow_resource_registration_order(self) -> None:
        first = self._register("first")
        second = self._register("second")
        third = self._register("third")
        self.assertEqual([r["id"] for r in self._summary()], [first, second, third])

    def test_each_resource_appears_exactly_once(self) -> None:
        first = self._register("first")
        second = self._register("second")
        for _ in range(3):
            records = self._summary()
            ids = [r["id"] for r in records]
            self.assertEqual(ids, [first, second])
            self.assertEqual(len(ids), len(set(ids)))

    # --- Freshness ---------------------------------------------------------

    def test_lifecycle_commit_is_reflected_immediately(self) -> None:
        resource_id = self._register()
        self._lifecycle(resource_id, "quarantined", "hold")
        self.assertEqual(
            self._summary(),
            [{"id": resource_id, "state": "quarantined", "reason": "hold"}],
        )
        self._lifecycle(resource_id, "staged")
        self.assertEqual(
            self._summary(),
            [{"id": resource_id, "state": "staged", "reason": None}],
        )

    def test_resource_deregistration_is_reflected_immediately(self) -> None:
        first = self._register("first")
        second = self._register("second")
        self._lifecycle(second, "quarantined", "hold")

        status, _h, body = call_json("DELETE", f"/resources/{first}")
        self.assertEqual(status, "200 OK", body)
        self.assertEqual(
            self._summary(),
            [{"id": second, "state": "quarantined", "reason": "hold"}],
        )

        status, _h, body = call_json("DELETE", f"/resources/{second}")
        self.assertEqual(status, "200 OK", body)
        self.assertEqual(self._summary(), [])
        # No residual record keyed by the removed resources.
        self.assertEqual(lifecycle_store._records, {})

    def test_query_does_not_modify_any_state(self) -> None:
        first = self._register("first")
        second = self._register("second")
        self._lifecycle(second, "quarantined", "hold")

        for _ in range(2):
            self.assertEqual(
                self._summary(),
                [
                    {"id": first, "state": "staged", "reason": None},
                    {"id": second, "state": "quarantined", "reason": "hold"},
                ],
            )
        _s, _h, lifecycle = call_json("GET", f"/resources/{first}/lifecycle")
        self.assertEqual(lifecycle["state"], "staged")  # type: ignore[index]
        self.assertNotIn(first, lifecycle_store._records)

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
        # Real WSGI servers seed CONTENT_LENGTH with '' when the header is
        # absent; that reads as an empty body, like the other summary views.
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
        self._register()
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
