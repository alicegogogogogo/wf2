from __future__ import annotations

import hashlib
import io
import json
import unittest

from provenance_api.app import application, reset_state

PATH = "/promotion/blockers"


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
) -> tuple[str, list[tuple[str, str]], object]:
    status, headers, raw = call(method, path, body, query_string=query_string)
    return status, headers, json.loads(raw.decode("utf-8"))


class PromotionBlockersTests(unittest.TestCase):
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

    def _summary(
        self, **kwargs: object
    ) -> tuple[str, list[tuple[str, str]], object]:
        return call_json("GET", PATH, **kwargs)

    # --- Happy path --------------------------------------------------------

    def test_empty_registry_returns_empty_array(self) -> None:
        status, _h, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

    def test_summary_covers_all_resources_in_registration_order(self) -> None:
        first = self._register("first", b"first-bytes")
        second = self._register("second", None)
        third = self._register("third", b"third-bytes")

        status, _h, body = self._summary()
        self.assertEqual(status, "200 OK")
        self.assertEqual([entry["id"] for entry in body], [first, second, third])
        self.assertEqual(
            body[0],
            {
                "id": first,
                "blocked": False,
                "reasons": [],
                "blockers": [],
                "content_complete": True,
            },
        )
        self.assertEqual(
            body[1],
            {
                "id": second,
                "blocked": True,
                "reasons": ["content_not_complete"],
                "blockers": [],
                "content_complete": False,
            },
        )
        self.assertFalse(body[2]["blocked"])

    def test_entry_matches_single_resource_view(self) -> None:
        root = self._register("root", None)
        dep = self._register("dep", None)
        self._dependency(root, dep)
        self._quarantine(dep)

        _s, _h, summary = self._summary()
        _s, _h, single = call_json(
            "GET", f"/resources/{root}/release-blockers"
        )
        by_id = {entry["id"]: entry for entry in summary}
        self.assertEqual(by_id[root], single)
        self.assertEqual(
            by_id[root]["reasons"],
            ["content_not_complete", "dependency_blocked"],
        )
        self.assertEqual(
            by_id[root]["blockers"],
            [{"resource_id": dep, "state": "quarantined"}],
        )

    def test_healthy_dependencies_are_not_blockers(self) -> None:
        root = self._register("root", b"root-bytes")
        dep = self._register("dep", b"dep-bytes")
        self._dependency(root, dep)
        self._lifecycle(dep, "released")

        _s, _h, summary = self._summary()
        by_id = {entry["id"]: entry for entry in summary}
        self.assertFalse(by_id[root]["blocked"])
        self.assertEqual(by_id[root]["blockers"], [])

    def test_long_dependency_chain_is_reported(self) -> None:
        ids = [self._register(f"chain-{i}", b"chain-bytes") for i in range(200)]
        for current, nxt in zip(ids, ids[1:]):
            self._dependency(current, nxt)
        self._quarantine(ids[-1])

        status, _h, summary = self._summary()
        self.assertEqual(status, "200 OK")
        by_id = {entry["id"]: entry for entry in summary}
        for resource_id in ids[:-1]:
            self.assertEqual(by_id[resource_id]["reasons"], ["dependency_blocked"])
            self.assertEqual(
                by_id[resource_id]["blockers"],
                [{"resource_id": ids[-1], "state": "quarantined"}],
            )
        self.assertEqual(by_id[ids[-1]]["reasons"], [])

    # --- Shape -------------------------------------------------------------

    def test_top_level_is_compact_array_with_trailing_newline(self) -> None:
        self._register("root", None)

        status, _h, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertTrue(raw.endswith(b"\n"))
        self.assertEqual(raw.count(b"\n"), 1)
        self.assertNotIn(b" ", raw[:-1])
        self.assertTrue(raw.startswith(b"[{"))

    def test_entry_key_order_is_fixed(self) -> None:
        self._register("root", None)

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

    # --- Recomputation -----------------------------------------------------

    def test_recomputed_after_state_changes(self) -> None:
        root = self._register("root", None)
        dep = self._register("dep", None)
        self._dependency(root, dep)

        def entry_for(resource_id: str) -> dict[str, object]:
            _s, _h, summary = self._summary()
            return {e["id"]: e for e in summary}[resource_id]

        # Assembling the content clears content_not_complete.
        self._upload_and_assemble(root, b"root")
        self.assertEqual(entry_for(root)["reasons"], [])

        # A lifecycle commit on the dependency blocks promotion at once.
        self._quarantine(dep)
        self.assertEqual(entry_for(root)["reasons"], ["dependency_blocked"])

        # Removing the dependency clears the blocker again.
        status, _h, _b = call_json(
            "DELETE", f"/resources/{root}/dependencies/{dep}"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(entry_for(root)["reasons"], [])

        # Re-adding and quarantining, then deleting the dependency resource
        # itself, drops it from the summary entirely.
        self._dependency(root, dep)
        self.assertEqual(entry_for(root)["reasons"], ["dependency_blocked"])
        status, _h, _b = call_json("DELETE", f"/resources/{dep}")
        self.assertEqual(status, "200 OK")
        _s, _h, summary = self._summary()
        self.assertEqual([e["id"] for e in summary], [root])
        self.assertEqual(summary[0]["reasons"], [])

    # --- Read-only ---------------------------------------------------------

    def test_query_does_not_modify_any_state(self) -> None:
        root = self._register("root", None)
        dep = self._register("dep", None)
        self._dependency(root, dep)
        self._quarantine(dep)

        for _ in range(2):
            status, _h, summary = self._summary()
            self.assertEqual(status, "200 OK")
            self.assertEqual(len(summary), 2)

        _s, _h, lifecycle = call_json("GET", f"/resources/{root}/lifecycle")
        self.assertEqual(lifecycle["state"], "staged")
        _s, _h, lifecycle = call_json("GET", f"/resources/{dep}/lifecycle")
        self.assertEqual(lifecycle["state"], "quarantined")
        _s, _h, deps = call_json("GET", f"/resources/{root}/dependencies")
        self.assertEqual(deps["dependencies"], [dep])
        _s, _h, chunk_status = call_json(
            "GET", f"/resources/{root}/chunks/status"
        )
        self.assertEqual(chunk_status["error"], "chunks_not_started")

    # --- Errors ------------------------------------------------------------

    def test_declared_non_empty_body_returns_400(self) -> None:
        self._register("root", None)
        for body in (b"{}", b"x", {"unexpected": True}):
            with self.subTest(body=body):
                status, _h, payload = call_json("GET", PATH, body)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(payload["error"], "invalid_request")

    def test_zero_length_body_is_accepted(self) -> None:
        self._register("root", None)
        status, _h, summary = call_json("GET", PATH, b"")
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(summary), 1)

    def test_query_parameters_return_400(self) -> None:
        self._register("root", None)
        for qs in ("x=1", "pretty=true", "page=2"):
            with self.subTest(qs=qs):
                status, _h, payload = self._summary(query_string=qs)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(payload["error"], "invalid_request")

    def test_non_get_methods_return_405_with_allow(self) -> None:
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, headers, payload = call_json(method, PATH)
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(payload["error"], "method_not_allowed")
                self.assertIn(("Allow", "GET"), headers)


if __name__ == "__main__":
    unittest.main()
