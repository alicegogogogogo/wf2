from __future__ import annotations

import hashlib
import io
import json
import unittest

from provenance_api.app import application, content_store, lifecycle_store, store


def call(
    method: str,
    path: str,
    body: bytes | str | dict[str, object] | None = None,
    *,
    headers: dict[str, str] | None = None,
    query_string: str | None = None,
) -> tuple[str, list[tuple[str, str]], bytes]:
    if body is None:
        payload = b""
    elif isinstance(body, dict):
        payload = json.dumps(body).encode("utf-8")
    elif isinstance(body, str):
        payload = body.encode("utf-8")
    else:
        payload = body
    environ: dict[str, object] = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "CONTENT_LENGTH": str(len(payload)),
        "wsgi.input": io.BytesIO(payload),
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
    body: bytes | str | dict[str, object] | None = None,
    **kwargs: object,
) -> tuple[str, list[tuple[str, str]], dict[str, object]]:
    status, headers, raw = call(method, path, body, **kwargs)  # type: ignore[arg-type]
    return status, headers, json.loads(raw.decode("utf-8"))


def register(name: str = "r", digest: str | None = None) -> str:
    digest = digest if digest is not None else hashlib.sha256(b"data").hexdigest()
    status, _, body = call_json(
        "POST",
        "/resources",
        {"name": name, "category": "artifact", "digest": digest},
    )
    assert status == "201 Created", body
    return str(body["id"])


def add_dependency(resource_id: str, dependency_id: str) -> None:
    status, _, body = call_json(
        "POST",
        f"/resources/{resource_id}/dependencies",
        {"dependency_id": dependency_id},
    )
    assert status == "201 Created", body


def assemble_single_chunk(resource_id: str, data: bytes = b"data") -> None:
    digest = hashlib.sha256(data).hexdigest()
    headers = {
        "CONTENT_TYPE": "application/octet-stream",
        "HTTP_X_TOTAL_CHUNKS": "1",
        "HTTP_X_CONTENT_DIGEST": digest,
    }
    status, _, body = call(
        "POST", f"/resources/{resource_id}/chunks/0", data, headers=headers
    )
    assert status == "201 Created", body
    status, _, body = call_json("POST", f"/resources/{resource_id}/assemble")
    assert status == "201 Created", body


def set_state(resource_id: str, state: str, reason: str | None = None) -> None:
    payload: dict[str, object] = {"state": state}
    if reason is not None:
        payload["reason"] = reason
    status, _, body = call_json(
        "POST", f"/resources/{resource_id}/lifecycle", payload
    )
    assert status == "200 OK", body


class ReleaseBlockersTests(unittest.TestCase):
    def setUp(self) -> None:
        store.reset()
        content_store.reset()
        lifecycle_store.reset()

    # --- Happy path ---------------------------------------------------------

    def test_promotable_resource_is_unblocked(self) -> None:
        resource_id = register()
        assemble_single_chunk(resource_id)
        status, headers, raw = call(
            "GET", f"/resources/{resource_id}/release-blockers"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            raw,
            (
                f'{{"id":"{resource_id}","blocked":false,"reasons":[],'
                f'"blockers":[],"content_complete":true}}\n'
            ).encode(),
        )
        self.assertIn(("Content-Type", "application/json; charset=utf-8"), headers)

    def test_key_order_is_stable(self) -> None:
        resource_id = register()
        _, _, raw = call("GET", f"/resources/{resource_id}/release-blockers")
        body = json.loads(raw.decode("utf-8"))
        self.assertEqual(
            list(body), ["id", "blocked", "reasons", "blockers", "content_complete"]
        )

    def test_incomplete_content_is_the_only_reason(self) -> None:
        resource_id = register()
        status, _, body = call_json(
            "GET", f"/resources/{resource_id}/release-blockers"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            body,
            {
                "id": resource_id,
                "blocked": True,
                "reasons": ["content_not_complete"],
                "blockers": [],
                "content_complete": False,
            },
        )

    # --- Dependency blockers ------------------------------------------------

    def test_quarantined_dependency_blocks(self) -> None:
        dep = register("dep")
        assemble_single_chunk(dep)
        target = register("target")
        assemble_single_chunk(target)
        add_dependency(target, dep)
        set_state(dep, "quarantined", "hold")

        status, _, body = call_json(
            "GET", f"/resources/{target}/release-blockers"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["blocked"], True)
        self.assertEqual(body["reasons"], ["dependency_blocked"])
        self.assertEqual(
            body["blockers"], [{"resource_id": dep, "state": "quarantined"}]
        )
        self.assertEqual(body["content_complete"], True)

    def test_withdrawn_dependency_blocks(self) -> None:
        dep = register("dep")
        assemble_single_chunk(dep)
        target = register("target")
        assemble_single_chunk(target)
        add_dependency(target, dep)
        set_state(dep, "released")
        set_state(dep, "withdrawn", "recall")

        _, _, body = call_json("GET", f"/resources/{target}/release-blockers")
        self.assertEqual(body["reasons"], ["dependency_blocked"])
        self.assertEqual(
            body["blockers"], [{"resource_id": dep, "state": "withdrawn"}]
        )

    def test_both_reasons_are_listed_in_check_order(self) -> None:
        dep = register("dep")
        target = register("target")
        # The target's content is deliberately not assembled.
        add_dependency(target, dep)
        set_state(dep, "quarantined", "hold")

        _, _, body = call_json("GET", f"/resources/{target}/release-blockers")
        self.assertEqual(body["blocked"], True)
        self.assertEqual(
            body["reasons"], ["content_not_complete", "dependency_blocked"]
        )
        # Blocked dependencies are still listed even without assembled content.
        self.assertEqual(
            body["blockers"], [{"resource_id": dep, "state": "quarantined"}]
        )
        self.assertEqual(body["content_complete"], False)

    def test_blockers_follow_registration_order(self) -> None:
        first = register("first")
        second = register("second")
        healthy = register("healthy")
        target = register("target")
        assemble_single_chunk(target)
        add_dependency(target, second)
        add_dependency(target, healthy)
        add_dependency(target, first)
        set_state(first, "quarantined", "hold")
        set_state(second, "quarantined", "hold")

        _, _, body = call_json("GET", f"/resources/{target}/release-blockers")
        # Registration order of the resources, not dependency-add order, and
        # the healthy dependency is excluded.
        self.assertEqual(
            body["blockers"],
            [
                {"resource_id": first, "state": "quarantined"},
                {"resource_id": second, "state": "quarantined"},
            ],
        )

    def test_transitive_blocked_dependency_is_listed(self) -> None:
        leaf = register("leaf")
        mid = register("mid")
        target = register("target")
        assemble_single_chunk(target)
        add_dependency(mid, leaf)
        add_dependency(target, mid)
        set_state(leaf, "quarantined", "hold")

        _, _, body = call_json("GET", f"/resources/{target}/release-blockers")
        self.assertEqual(body["reasons"], ["dependency_blocked"])
        self.assertEqual(
            body["blockers"], [{"resource_id": leaf, "state": "quarantined"}]
        )

    def test_healthy_dependencies_yield_empty_blockers(self) -> None:
        dep = register("dep")
        assemble_single_chunk(dep)
        target = register("target")
        assemble_single_chunk(target)
        add_dependency(target, dep)
        set_state(dep, "released")

        _, _, body = call_json("GET", f"/resources/{target}/release-blockers")
        self.assertEqual(body["blocked"], False)
        self.assertEqual(body["reasons"], [])
        self.assertEqual(body["blockers"], [])

    def test_staged_dependency_does_not_block(self) -> None:
        dep = register("dep")
        target = register("target")
        assemble_single_chunk(target)
        add_dependency(target, dep)

        _, _, body = call_json("GET", f"/resources/{target}/release-blockers")
        self.assertEqual(body["blocked"], False)
        self.assertEqual(body["blockers"], [])

    # --- Read-only behaviour --------------------------------------------------

    def test_view_records_nothing_and_changes_nothing(self) -> None:
        dep = register("dep")
        target = register("target")
        add_dependency(target, dep)
        set_state(dep, "quarantined", "hold")

        records_before = dict(lifecycle_store._records)
        status, _, body = call_json(
            "GET", f"/resources/{target}/release-blockers"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["blocked"], True)
        # No lifecycle record is materialized for the target.
        self.assertEqual(set(lifecycle_store._records), set(records_before))
        self.assertNotIn(target, lifecycle_store._records)
        # The view does not promote anything.
        _, _, lifecycle = call_json("GET", f"/resources/{target}/lifecycle")
        self.assertEqual(lifecycle["state"], "staged")

    # --- Request validation ---------------------------------------------------

    def test_unknown_resource_is_404(self) -> None:
        status, _, body = call_json("GET", "/resources/deadbeef/release-blockers")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

    def test_empty_id_is_400(self) -> None:
        status, _, body = call_json("GET", "/resources//release-blockers")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_separator_in_id_is_400(self) -> None:
        status, _, body = call_json("GET", "/resources/a/b/release-blockers")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_query_parameters_are_400_without_touching_state(self) -> None:
        resource_id = register()
        records_before = dict(lifecycle_store._records)
        status, _, body = call_json(
            "GET",
            f"/resources/{resource_id}/release-blockers",
            query_string="x=1",
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        self.assertEqual(set(lifecycle_store._records), set(records_before))

    def test_method_not_allowed(self) -> None:
        resource_id = register()
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            status, headers, body = call_json(
                method, f"/resources/{resource_id}/release-blockers"
            )
            self.assertEqual(status, "405 Method Not Allowed")
            self.assertEqual(body["error"], "method_not_allowed")
            self.assertIn(("Allow", "GET"), headers)


if __name__ == "__main__":
    unittest.main()
