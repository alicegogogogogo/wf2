from __future__ import annotations

import hashlib
import io
import json
import unittest

from provenance_api.app import application, reset_state

PATH = "release-blockers"


def call(
    method: str,
    path: str,
    body: bytes | str | dict[str, object] | None = None,
    *,
    query_string: str | None = None,
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
        "CONTENT_LENGTH": str(len(payload)),
        "CONTENT_TYPE": "application/json",
        "wsgi.input": io.BytesIO(payload),
    }
    captured: dict[str, object] = {}

    def start_response(status: str, headers: list[tuple[str, str]]) -> None:
        captured["status"] = status
        captured["headers"] = headers

    chunks = application(environ, start_response)
    return str(captured["status"]), list(captured["headers"]), b"".join(chunks)


def call_json(
    method: str,
    path: str,
    body: bytes | str | dict[str, object] | None = None,
    *,
    query_string: str | None = None,
) -> tuple[str, list[tuple[str, str]], dict[str, object]]:
    status, headers, raw = call(method, path, body, query_string=query_string)
    return status, headers, json.loads(raw.decode("utf-8"))


class ReleaseBlockersTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    # --- Setup helpers -----------------------------------------------------

    def _register(self, name: str, data: bytes | None) -> str:
        """Register a resource; complete its content when ``data`` is given."""

        digest = hashlib.sha256(data if data is not None else name.encode()).hexdigest()
        _s, _h, body = call_json(
            "POST",
            "/resources",
            {"name": name, "category": "artifact", "digest": digest},
        )
        resource_id = str(body["id"])
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

        status, _h, body = call_json(
            "POST", f"/resources/{resource_id}/assemble"
        )
        assert status == "201 Created", body

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

    def _view(
        self, resource_id: str, **kwargs: object
    ) -> tuple[str, list[tuple[str, str]], dict[str, object]]:
        return call_json(
            "GET", f"/resources/{resource_id}/{PATH}", **kwargs
        )

    # --- Happy path --------------------------------------------------------

    def test_promotable_resource_reports_empty(self) -> None:
        root = self._register("root", b"root-bytes")

        status, _h, body = self._view(root)
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            body,
            {
                "id": root,
                "blocked": False,
                "reasons": [],
                "blockers": [],
                "content_complete": True,
            },
        )

    def test_healthy_dependencies_are_not_blockers(self) -> None:
        root = self._register("root", b"root-bytes")
        mid = self._register("mid", b"mid-bytes")
        leaf = self._register("leaf", b"leaf-bytes")
        self._dependency(root, mid)
        self._dependency(mid, leaf)
        # A released dependency is healthy too.
        self._lifecycle(leaf, "released")

        _s, _h, body = self._view(root)
        self.assertFalse(body["blocked"])
        self.assertEqual(body["reasons"], [])
        self.assertEqual(body["blockers"], [])
        self.assertTrue(body["content_complete"])

    # --- Reasons -----------------------------------------------------------

    def test_missing_content_only(self) -> None:
        root = self._register("root", None)

        _s, _h, body = self._view(root)
        self.assertTrue(body["blocked"])
        self.assertEqual(body["reasons"], ["content_not_complete"])
        self.assertEqual(body["blockers"], [])
        self.assertFalse(body["content_complete"])

    def test_quarantined_dependency_only(self) -> None:
        root = self._register("root", b"root-bytes")
        dep = self._register("dep", None)
        self._dependency(root, dep)
        self._quarantine(dep)

        _s, _h, body = self._view(root)
        self.assertTrue(body["blocked"])
        self.assertEqual(body["reasons"], ["dependency_blocked"])
        self.assertEqual(
            body["blockers"],
            [{"resource_id": dep, "state": "quarantined"}],
        )
        self.assertTrue(body["content_complete"])

    def test_withdrawn_dependency_only(self) -> None:
        root = self._register("root", b"root-bytes")
        dep = self._register("dep", b"dep-bytes")
        self._dependency(root, dep)
        self._withdraw(dep)

        _s, _h, body = self._view(root)
        self.assertEqual(body["reasons"], ["dependency_blocked"])
        self.assertEqual(
            body["blockers"],
            [{"resource_id": dep, "state": "withdrawn"}],
        )

    def test_both_reasons_in_fixed_order(self) -> None:
        # Content incomplete AND a blocked dependency: both codes appear,
        # content_not_complete first, and blockers are still listed.
        root = self._register("root", None)
        dep = self._register("dep", None)
        self._dependency(root, dep)
        self._quarantine(dep)

        _s, _h, body = self._view(root)
        self.assertTrue(body["blocked"])
        self.assertEqual(
            body["reasons"], ["content_not_complete", "dependency_blocked"]
        )
        self.assertEqual(
            body["blockers"],
            [{"resource_id": dep, "state": "quarantined"}],
        )
        self.assertFalse(body["content_complete"])

    def test_blockers_follow_registration_order_over_the_closure(self) -> None:
        # Registration order: root, quarantined, healthy, withdrawn.
        root = self._register("root", b"root-bytes")
        quarantined = self._register("quarantined", None)
        healthy = self._register("healthy", b"healthy-bytes")
        withdrawn = self._register("withdrawn", b"withdrawn-bytes")
        self._quarantine(quarantined)
        self._withdraw(withdrawn)

        # Add edges in an order unrelated to registration order, and make the
        # quarantined dependency only transitively reachable.
        self._dependency(root, withdrawn)
        self._dependency(root, healthy)
        self._dependency(healthy, quarantined)

        _s, _h, body = self._view(root)
        self.assertEqual(body["reasons"], ["dependency_blocked"])
        self.assertEqual(
            body["blockers"],
            [
                {"resource_id": quarantined, "state": "quarantined"},
                {"resource_id": withdrawn, "state": "withdrawn"},
            ],
        )

    def test_diamond_dependency_listed_once(self) -> None:
        root = self._register("root", b"root-bytes")
        left = self._register("left", b"left-bytes")
        right = self._register("right", b"right-bytes")
        dep = self._register("dep", None)
        self._dependency(root, left)
        self._dependency(root, right)
        self._dependency(left, dep)
        self._dependency(right, dep)
        self._quarantine(dep)

        _s, _h, body = self._view(root)
        self.assertEqual(
            body["blockers"],
            [{"resource_id": dep, "state": "quarantined"}],
        )

    def test_view_agrees_with_actual_promotion(self) -> None:
        root = self._register("root", b"root-bytes")
        dep = self._register("dep", b"dep-bytes")
        self._dependency(root, dep)

        # Clear to promote.
        _s, _h, report = self._view(root)
        self.assertFalse(report["blocked"])
        status, _h, resp = call_json(
            "POST", f"/resources/{root}/lifecycle", {"state": "released"}
        )
        self.assertEqual(status, "200 OK", resp)

        # Once the dependency is quarantined the same gate reports blocked;
        # the existing promotion error code is unchanged for a fresh resource.
        self._quarantine(dep)
        _s, _h, report = self._view(root)
        self.assertEqual(report["reasons"], ["dependency_blocked"])

        other = self._register("other", b"other-bytes")
        self._dependency(other, dep)
        status, _h, resp = call_json(
            "POST",
            f"/resources/{other}/lifecycle",
            {"state": "released"},
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(resp["error"], "dependency_blocked")

    # --- Shape -------------------------------------------------------------

    def test_top_level_key_order_is_fixed(self) -> None:
        root = self._register("root", None)

        status, _headers, raw = call("GET", f"/resources/{root}/{PATH}")
        self.assertEqual(status, "200 OK")
        self.assertTrue(raw.endswith(b"\n"))
        self.assertEqual(raw.count(b"\n"), 1)
        self.assertNotIn(b" ", raw[:-1])
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

    def test_blocker_entry_key_order(self) -> None:
        root = self._register("root", b"root-bytes")
        dep = self._register("dep", None)
        self._dependency(root, dep)
        self._quarantine(dep)

        _s, _headers, raw = call("GET", f"/resources/{root}/{PATH}")
        entry = raw.decode("utf-8").rstrip("\n")
        entry = entry[entry.index('"blockers"'):]
        self.assertLess(entry.index('"resource_id"'), entry.index('"state"'))

    def test_content_complete_reflects_completion(self) -> None:
        # data=None registers the digest of the name bytes, so uploading
        # those exact bytes completes the content without re-registering.
        root = self._register("root", None)
        _s, _h, body = self._view(root)
        self.assertFalse(body["content_complete"])

        self._upload_and_assemble(root, b"root")

        _s, _h, body = self._view(root)
        self.assertTrue(body["content_complete"])
        self.assertFalse(body["blocked"])
        self.assertEqual(body["reasons"], [])

    # --- Read-only ---------------------------------------------------------

    def test_query_does_not_modify_any_state(self) -> None:
        root = self._register("root", None)
        dep = self._register("dep", None)
        self._dependency(root, dep)
        self._quarantine(dep)

        for _ in range(2):
            status, _h, body = self._view(root)
            self.assertEqual(status, "200 OK")
            self.assertEqual(
                body["reasons"],
                ["content_not_complete", "dependency_blocked"],
            )

        _s, _h, lifecycle = call_json(
            "GET", f"/resources/{root}/lifecycle"
        )
        self.assertEqual(lifecycle["state"], "staged")
        _s, _h, lifecycle = call_json(
            "GET", f"/resources/{dep}/lifecycle"
        )
        self.assertEqual(lifecycle["state"], "quarantined")
        _s, _h, deps = call_json(
            "GET", f"/resources/{root}/dependencies"
        )
        self.assertEqual(deps["dependencies"], [dep])
        _s, _h, chunk_status = call_json(
            "GET", f"/resources/{root}/chunks/status"
        )
        self.assertEqual(chunk_status["error"], "chunks_not_started")

    # --- Errors ------------------------------------------------------------

    def test_unknown_resource_returns_404(self) -> None:
        status, _h, body = self._view("no-such-resource")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

    def test_empty_path_id_is_bad_request(self) -> None:
        status, _h, body = call_json("GET", f"/resources//{PATH}")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_id_with_separator_returns_400(self) -> None:
        for raw in ("a/b", "a\\b"):
            with self.subTest(raw=raw):
                status, _h, body = call_json(
                    "GET", f"/resources/{raw}/{PATH}"
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_query_parameters_return_400(self) -> None:
        root = self._register("root", None)
        for qs in ("x=1", "pretty=true", "page=2"):
            with self.subTest(qs=qs):
                status, _h, body = self._view(root, query_string=qs)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_bad_request_does_not_read_business_data(self) -> None:
        status, _h, body = self._view(
            "no-such-resource", query_string="x=1"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_non_get_methods_return_405_with_allow(self) -> None:
        root = self._register("root", None)
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, headers, body = call_json(
                    method, f"/resources/{root}/{PATH}"
                )
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")
                self.assertIn(("Allow", "GET"), headers)


if __name__ == "__main__":
    unittest.main()
