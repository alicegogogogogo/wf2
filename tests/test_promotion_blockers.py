from __future__ import annotations

import hashlib
import io
import json
import unittest

from provenance_api.app import application, reset_state

PATH = "/promotion/blockers"


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


class PromotionBlockersSummaryTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    # --- Setup helpers -----------------------------------------------------

    def _register(self, name: str, data: bytes | None) -> str:
        """Register a resource; complete its content when ``data`` is given."""

        digest = hashlib.sha256(
            data if data is not None else name.encode()
        ).hexdigest()
        _s, _h, body = call_json(
            "POST",
            "/resources",
            {"name": name, "category": "artifact", "digest": digest},
        )
        resource_id = str(body["id"])  # type: ignore[index]
        if data is not None:
            self._upload_and_assemble(resource_id, data)
        return resource_id

    def _upload_and_assemble(self, resource_id: str, data: bytes) -> None:
        digest = hashlib.sha256(data).hexdigest()
        environ: dict[str, object] = {
            "REQUEST_METHOD": "POST",
            "PATH_INFO": f"/resources/{resource_id}/chunks/0",
            "QUERY_STRING": "",
            "CONTENT_LENGTH": str(len(data)),
            "CONTENT_TYPE": "application/octet-stream",
            "HTTP_X_TOTAL_CHUNKS": "1",
            "HTTP_X_CONTENT_DIGEST": digest,
            "wsgi.input": io.BytesIO(data),
        }
        captured: dict[str, object] = {}

        def start_response(status: str, headers: list[tuple[str, str]]) -> None:
            captured["status"] = status
            captured["headers"] = headers

        b"".join(application(environ, start_response))
        assert captured["status"] == "201 Created", captured["status"]

        status, _h, resp = call_json(
            "POST", f"/resources/{resource_id}/assemble"
        )
        assert status == "201 Created", resp

    def _dependency(self, resource_id: str, dependency_id: str) -> None:
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/dependencies",
            {"dependency_id": dependency_id},
        )
        assert status == "201 Created", body

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

    def _quarantine(self, resource_id: str) -> None:
        self._lifecycle(resource_id, "quarantined", "bad build")

    def _withdraw(self, resource_id: str) -> None:
        # Withdrawal requires released first.
        self._lifecycle(resource_id, "released")
        self._lifecycle(resource_id, "withdrawn", "recalled")

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
        self._register("root", None)
        _s, _h, raw = call("GET", PATH)
        self.assertTrue(raw.endswith(b"\n"))
        self.assertEqual(raw.count(b"\n"), 1)
        self.assertNotIn(b" ", raw[:-1])

    def test_top_level_is_an_array_without_a_wrapper(self) -> None:
        first = self._register("first", None)
        second = self._register("second", b"second-bytes")

        status, _h, body = call_json("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertIsInstance(body, list)
        self.assertEqual([record["id"] for record in body], [first, second])  # type: ignore[index]

    def test_record_fields_and_key_order_match_single_resource_view(self) -> None:
        root = self._register("root", None)

        _s, _h, raw = call("GET", PATH)
        text = raw.decode("utf-8").rstrip("\n")
        keys = [
            '"id"',
            '"blocked"',
            '"reasons"',
            '"blockers"',
            '"content_complete"',
        ]
        positions = [text.index(k) for k in keys]
        self.assertEqual(positions, sorted(positions))

        _s, _h, single = call_json(
            "GET", f"/resources/{root}/release-blockers"
        )
        self.assertEqual(self._summary(), [single])

    # --- Ordering ----------------------------------------------------------

    def test_records_follow_resource_registration_order(self) -> None:
        ids = [self._register(f"r{i}", None) for i in range(5)]
        self.assertEqual([record["id"] for record in self._summary()], ids)

    def test_blockers_follow_dependency_registration_order(self) -> None:
        # Registration order: root, quarantined, healthy, withdrawn.
        root = self._register("root", b"root-bytes")
        quarantined = self._register("quarantined", None)
        healthy = self._register("healthy", b"healthy-bytes")
        withdrawn = self._register("withdrawn", b"withdrawn-bytes")
        self._quarantine(quarantined)
        self._withdraw(withdrawn)

        # Edges added in an order unrelated to registration order, and the
        # quarantined dependency is only transitively reachable.
        self._dependency(root, withdrawn)
        self._dependency(root, healthy)
        self._dependency(healthy, quarantined)

        [record] = [r for r in self._summary() if r["id"] == root]
        self.assertEqual(record["reasons"], ["dependency_blocked"])
        self.assertEqual(
            record["blockers"],
            [
                {"resource_id": quarantined, "state": "quarantined"},
                {"resource_id": withdrawn, "state": "withdrawn"},
            ],
        )

    def test_healthy_dependencies_are_not_listed(self) -> None:
        root = self._register("root", b"root-bytes")
        staged = self._register("staged", None)
        released = self._register("released", b"released-bytes")
        self._dependency(root, staged)
        self._dependency(root, released)
        self._lifecycle(released, "released")

        [record] = [r for r in self._summary() if r["id"] == root]
        self.assertFalse(record["blocked"])
        self.assertEqual(record["reasons"], [])
        self.assertEqual(record["blockers"], [])

    # --- Reasons and content state ----------------------------------------

    def test_reasons_keep_content_first_then_dependency_order(self) -> None:
        root = self._register("root", None)
        dep = self._register("dep", None)
        self._dependency(root, dep)
        self._quarantine(dep)

        self.assertEqual(
            [r for r in self._summary() if r["id"] == root][0]["reasons"],
            ["content_not_complete", "dependency_blocked"],
        )

    def test_content_incomplete_only(self) -> None:
        root = self._register("root", None)
        [record] = [r for r in self._summary() if r["id"] == root]
        self.assertTrue(record["blocked"])
        self.assertEqual(record["reasons"], ["content_not_complete"])
        self.assertEqual(record["blockers"], [])
        self.assertFalse(record["content_complete"])

    def test_content_complete_is_a_plain_boolean(self) -> None:
        root = self._register("root", None)
        _s, _h, raw = call("GET", PATH)
        # The incomplete value is the JSON literal false, not null.
        self.assertIn(b'"content_complete":false', raw)

        self._upload_and_assemble(root, b"root")
        _s, _h, raw = call("GET", PATH)
        self.assertIn(b'"content_complete":true', raw)

    # --- Immediate recomputation ------------------------------------------

    def test_lifecycle_change_is_reflected_immediately(self) -> None:
        root = self._register("root", b"root-bytes")
        dep = self._register("dep", b"dep-bytes")
        self._dependency(root, dep)

        def root_record() -> dict[str, object]:
            return [r for r in self._summary() if r["id"] == root][0]

        self.assertFalse(root_record()["blocked"])
        self._quarantine(dep)
        self.assertEqual(root_record()["reasons"], ["dependency_blocked"])
        # Moving the dependency back to staged clears the blocker at once.
        self._lifecycle(dep, "staged")
        self.assertFalse(root_record()["blocked"])
        self.assertEqual(root_record()["blockers"], [])

    def test_assembly_is_reflected_immediately(self) -> None:
        root = self._register("root", None)
        self.assertFalse(
            [r for r in self._summary() if r["id"] == root][0][
                "content_complete"
            ]
        )
        self._upload_and_assemble(root, b"root")
        self.assertTrue(
            [r for r in self._summary() if r["id"] == root][0][
                "content_complete"
            ]
        )

    def test_dependency_add_and_delete_are_reflected_immediately(self) -> None:
        root = self._register("root", b"root-bytes")
        dep = self._register("dep", None)
        self._quarantine(dep)

        self.assertEqual(
            [r for r in self._summary() if r["id"] == root][0]["blockers"],
            [],
        )
        self._dependency(root, dep)
        self.assertEqual(
            [r for r in self._summary() if r["id"] == root][0]["blockers"],
            [{"resource_id": dep, "state": "quarantined"}],
        )

        status, _h, body = call_json(
            "DELETE", f"/resources/{root}/dependencies/{dep}"
        )
        assert status == "200 OK", body
        self.assertEqual(
            [r for r in self._summary() if r["id"] == root][0]["blockers"],
            [],
        )

    def test_resource_deregistration_is_reflected_immediately(self) -> None:
        root = self._register("root", b"root-bytes")
        dep = self._register("dep", None)
        self._dependency(root, dep)
        self._quarantine(dep)

        status, _h, body = call_json("DELETE", f"/resources/{dep}")
        assert status == "200 OK", body

        records = self._summary()
        self.assertEqual([r["id"] for r in records], [root])
        self.assertEqual(records[0]["blockers"], [])
        self.assertFalse(records[0]["blocked"])

    # --- Long chains -------------------------------------------------------

    def test_long_dependency_chain_does_not_fail(self) -> None:
        size = 2000
        ids = [self._register(f"n{i}", None) for i in range(size)]
        for i in range(size - 1):
            self._dependency(ids[i], ids[i + 1])
        self._quarantine(ids[-1])

        status, _h, body = call_json("GET", PATH)
        self.assertEqual(status, "200 OK")
        assert isinstance(body, list)
        self.assertEqual(len(body), size)

        root_record = body[0]
        self.assertEqual(
            root_record["reasons"],
            ["content_not_complete", "dependency_blocked"],
        )
        self.assertEqual(
            root_record["blockers"],
            [{"resource_id": ids[-1], "state": "quarantined"}],
        )
        # A mid-chain resource reaches the blocked leaf transitively and the
        # blocker is listed once in registration order.
        mid = body[size // 2]
        self.assertEqual(
            mid["reasons"],
            ["content_not_complete", "dependency_blocked"],
        )
        self.assertEqual(
            mid["blockers"],
            [{"resource_id": ids[-1], "state": "quarantined"}],
        )
        # The leaf itself has no dependencies: no dependency blocker even
        # though its own lifecycle state is quarantined.
        leaf = body[-1]
        self.assertEqual(leaf["id"], ids[-1])
        self.assertEqual(leaf["reasons"], ["content_not_complete"])
        self.assertEqual(leaf["blockers"], [])

    # --- Read-only ---------------------------------------------------------

    def test_query_does_not_modify_any_state(self) -> None:
        root = self._register("root", None)
        dep = self._register("dep", None)
        self._dependency(root, dep)
        self._quarantine(dep)

        for _ in range(2):
            records = self._summary()
            self.assertEqual(
                [r["id"] for r in records], [root, dep]
            )

        _s, _h, lifecycle = call_json(
            "GET", f"/resources/{root}/lifecycle"
        )
        self.assertEqual(lifecycle["state"], "staged")  # type: ignore[index]
        _s, _h, lifecycle = call_json(
            "GET", f"/resources/{dep}/lifecycle"
        )
        self.assertEqual(lifecycle["state"], "quarantined")  # type: ignore[index]
        _s, _h, deps = call_json(
            "GET", f"/resources/{root}/dependencies"
        )
        self.assertEqual(deps["dependencies"], [dep])  # type: ignore[index]

    # --- Empty body handling ----------------------------------------------

    def test_omitted_body_is_accepted(self) -> None:
        status, _h, body = call_json(
            "GET", PATH, omit_content_length=True
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, [])

    def test_explicit_zero_length_is_accepted(self) -> None:
        status, _h, body = call_json("GET", PATH, content_length="0")
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, [])

    def test_empty_string_content_length_is_accepted(self) -> None:
        # Real WSGI servers seed CONTENT_LENGTH with '' when the header is
        # absent; that reads as an empty body, like the per-resource views.
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
        self._register("root", None)
        for qs in ("x=1", "pretty=true", "page=2", "focus=root"):
            with self.subTest(qs=qs):
                status, _h, body = call_json(
                    "GET", PATH, query_string=qs
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")  # type: ignore[index]

    def test_bad_request_does_not_read_business_data(self) -> None:
        # No resources exist, yet a query parameter / declared body is
        # rejected purely on the request envelope.
        status, _h, body = call_json(
            "GET", PATH, query_string="x=1"
        )
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
