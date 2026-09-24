from __future__ import annotations

import hashlib
import io
import json
import unittest

from provenance_api.app import application, content_store, lifecycle_store, store

OCTET_HEADERS = {
    "CONTENT_TYPE": "application/octet-stream",
}


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


class LifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        store.reset()
        content_store.reset()
        lifecycle_store.reset()

    # --- Reading state ------------------------------------------------------

    def test_first_read_is_staged_with_empty_reason(self) -> None:
        resource_id = register()
        status, headers, raw = call("GET", f"/resources/{resource_id}/lifecycle")

        self.assertEqual(status, "200 OK")
        self.assertEqual(
            raw,
            f'{{"id":"{resource_id}","state":"staged","reason":null}}\n'.encode(),
        )
        self.assertIn(("Content-Type", "application/json; charset=utf-8"), headers)
        # Reading must not materialize any stored record.
        self.assertNotIn(resource_id, lifecycle_store._records)

    def test_get_unknown_resource_is_404(self) -> None:
        status, _, body = call_json("GET", "/resources/deadbeef/lifecycle")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

    def test_get_rejects_empty_id_and_query_params(self) -> None:
        status, _, body = call_json("GET", "/resources//lifecycle")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

        resource_id = register()
        status, _, body = call_json(
            "GET", f"/resources/{resource_id}/lifecycle", query_string="x=1"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_method_not_allowed(self) -> None:
        resource_id = register()
        for method in ("PUT", "DELETE", "PATCH"):
            status, headers, body = call_json(method, f"/resources/{resource_id}/lifecycle")
            self.assertEqual(status, "405 Method Not Allowed")
            self.assertEqual(body["error"], "method_not_allowed")
            self.assertIn(("Allow", "GET, POST"), headers)

    # --- Release gating -----------------------------------------------------

    def test_release_before_assembly_is_content_not_complete(self) -> None:
        resource_id = register()
        status, _, body = call_json(
            "POST", f"/resources/{resource_id}/lifecycle", {"state": "released"}
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "content_not_complete")
        # State is unchanged.
        _, _, after = call_json("GET", f"/resources/{resource_id}/lifecycle")
        self.assertEqual(after["state"], "staged")
        self.assertIsNone(after["reason"])

    def test_release_after_assembly_succeeds(self) -> None:
        resource_id = register()
        assemble_single_chunk(resource_id)
        status, headers, raw = call(
            "POST",
            f"/resources/{resource_id}/lifecycle",
            {"state": "released"},
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            raw,
            f'{{"id":"{resource_id}","state":"released","reason":null}}\n'.encode(),
        )

    def test_release_blocked_by_quarantined_dependency(self) -> None:
        dep = register("dep")
        assemble_single_chunk(dep)
        target = register("target")
        assemble_single_chunk(target)
        add_dependency(target, dep)

        status, _, body = call_json(
            "POST", f"/resources/{dep}/lifecycle",
            {"state": "quarantined", "reason": "bad"},
        )
        self.assertEqual(status, "200 OK")

        status, _, body = call_json(
            "POST", f"/resources/{target}/lifecycle", {"state": "released"}
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "dependency_blocked")
        _, _, after = call_json("GET", f"/resources/{target}/lifecycle")
        self.assertEqual(after["state"], "staged")

    def test_release_blocked_by_withdrawn_dependency(self) -> None:
        dep = register("dep")
        assemble_single_chunk(dep)
        target = register("target")
        assemble_single_chunk(target)
        add_dependency(target, dep)

        call_json(
            "POST", f"/resources/{dep}/lifecycle", {"state": "released"}
        )
        status, _, body = call_json(
            "POST", f"/resources/{dep}/lifecycle",
            {"state": "withdrawn", "reason": "recall"},
        )
        self.assertEqual(status, "200 OK")

        status, _, body = call_json(
            "POST", f"/resources/{target}/lifecycle", {"state": "released"}
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "dependency_blocked")

    def test_released_resources_do_not_block_dependents(self) -> None:
        dep = register("dep")
        assemble_single_chunk(dep)
        target = register("target")
        assemble_single_chunk(target)
        add_dependency(target, dep)

        call_json("POST", f"/resources/{dep}/lifecycle", {"state": "released"})
        status, _, body = call_json(
            "POST", f"/resources/{target}/lifecycle", {"state": "released"}
        )
        self.assertEqual(status, "200 OK", body)
        self.assertEqual(body["state"], "released")

    # --- Quarantine, withdrawal and recovery --------------------------------

    def test_staged_can_be_quarantined_with_reason(self) -> None:
        resource_id = register()
        status, _, body = call_json(
            "POST", f"/resources/{resource_id}/lifecycle",
            {"state": "quarantined", "reason": "investigating"},
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["state"], "quarantined")
        self.assertEqual(body["reason"], "investigating")

    def test_quarantine_requires_reason(self) -> None:
        resource_id = register()
        status, _, body = call_json(
            "POST", f"/resources/{resource_id}/lifecycle",
            {"state": "quarantined"},
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_released_can_be_withdrawn_with_reason(self) -> None:
        resource_id = register()
        assemble_single_chunk(resource_id)
        call_json(
            "POST", f"/resources/{resource_id}/lifecycle", {"state": "released"}
        )
        status, _, body = call_json(
            "POST", f"/resources/{resource_id}/lifecycle",
            {"state": "withdrawn", "reason": "recall"},
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["state"], "withdrawn")
        self.assertEqual(body["reason"], "recall")

    def test_withdrawal_requires_reason(self) -> None:
        resource_id = register()
        assemble_single_chunk(resource_id)
        call_json(
            "POST", f"/resources/{resource_id}/lifecycle", {"state": "released"}
        )
        status, _, body = call_json(
            "POST", f"/resources/{resource_id}/lifecycle",
            {"state": "withdrawn"},
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_withdrawn_back_to_staged_then_rechecked(self) -> None:
        resource_id = register()
        assemble_single_chunk(resource_id)
        call_json(
            "POST", f"/resources/{resource_id}/lifecycle", {"state": "released"}
        )
        call_json(
            "POST", f"/resources/{resource_id}/lifecycle",
            {"state": "withdrawn", "reason": "recall"},
        )

        # Back to staged; no reason needed for this direction.
        status, _, body = call_json(
            "POST", f"/resources/{resource_id}/lifecycle", {"state": "staged"}
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["state"], "staged")
        self.assertIsNone(body["reason"])

        # Content is still assembled, so release is immediately possible.
        status, _, body = call_json(
            "POST", f"/resources/{resource_id}/lifecycle", {"state": "released"}
        )
        self.assertEqual(status, "200 OK", body)
        self.assertEqual(body["state"], "released")

    def test_quarantined_must_pass_through_staged_before_release(self) -> None:
        dep = register("dep")
        assemble_single_chunk(dep)
        call_json(
            "POST", f"/resources/{dep}/lifecycle",
            {"state": "quarantined", "reason": "hold"},
        )
        status, _, body = call_json(
            "POST", f"/resources/{dep}/lifecycle", {"state": "released"}
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "invalid_state_transition")

        status, _, _ = call_json(
            "POST", f"/resources/{dep}/lifecycle", {"state": "staged"}
        )
        self.assertEqual(status, "200 OK")
        status, _, body = call_json(
            "POST", f"/resources/{dep}/lifecycle", {"state": "released"}
        )
        self.assertEqual(status, "200 OK", body)
        self.assertEqual(body["state"], "released")

    def test_illegal_transitions(self) -> None:
        resource_id = register()
        # staged -> withdrawn is not allowed.
        status, _, body = call_json(
            "POST", f"/resources/{resource_id}/lifecycle",
            {"state": "withdrawn", "reason": "x"},
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "invalid_state_transition")
        _, _, after = call_json("GET", f"/resources/{resource_id}/lifecycle")
        self.assertEqual(after["state"], "staged")

        assemble_single_chunk(resource_id)
        call_json(
            "POST", f"/resources/{resource_id}/lifecycle", {"state": "released"}
        )
        # released -> staged directly is not allowed.
        status, _, body = call_json(
            "POST", f"/resources/{resource_id}/lifecycle", {"state": "staged"}
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "invalid_state_transition")

    def test_reason_cannot_be_changed(self) -> None:
        resource_id = register()
        call_json(
            "POST", f"/resources/{resource_id}/lifecycle",
            {"state": "quarantined", "reason": "first"},
        )
        status, _, body = call_json(
            "POST", f"/resources/{resource_id}/lifecycle",
            {"state": "quarantined", "reason": "second"},
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "invalid_state_transition")
        _, _, after = call_json("GET", f"/resources/{resource_id}/lifecycle")
        self.assertEqual(after["reason"], "first")

    # --- Idempotency --------------------------------------------------------

    def test_resubmit_same_state_and_reason_is_idempotent(self) -> None:
        resource_id = register()
        payload = {"state": "quarantined", "reason": "same"}
        status1, _, body1 = call_json(
            "POST", f"/resources/{resource_id}/lifecycle", payload
        )
        self.assertEqual(status1, "200 OK")

        records_before = dict(lifecycle_store._records)
        status2, _, body2 = call_json(
            "POST", f"/resources/{resource_id}/lifecycle", payload
        )
        self.assertEqual(status2, "200 OK")
        self.assertEqual(body1, body2)
        # No new record is stored by the repeat.
        self.assertEqual(set(lifecycle_store._records), set(records_before))
        self.assertIs(
            lifecycle_store._records[resource_id],
            records_before[resource_id],
        )

    def test_resubmit_staged_without_reason_is_idempotent(self) -> None:
        resource_id = register()
        status, _, body = call_json(
            "POST", f"/resources/{resource_id}/lifecycle", {"state": "staged"}
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["state"], "staged")
        self.assertIsNone(body["reason"])
        # An idempotent no-op on a never-transitioned resource stores nothing.
        self.assertNotIn(resource_id, lifecycle_store._records)

    def test_resubmit_released_with_same_reason_is_idempotent(self) -> None:
        resource_id = register()
        assemble_single_chunk(resource_id)
        payload = {"state": "released"}
        call_json("POST", f"/resources/{resource_id}/lifecycle", payload)
        status, _, body = call_json(
            "POST", f"/resources/{resource_id}/lifecycle", payload
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["state"], "released")

    # --- Request validation -------------------------------------------------

    def test_invalid_bodies(self) -> None:
        resource_id = register()
        path = f"/resources/{resource_id}/lifecycle"

        # Missing body.
        status, _, body = call_json("POST", path, b"")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

        # Bad UTF-8.
        status, _, raw_body = call("POST", path, b"\xff\xfe{")
        self.assertEqual(status, "400 Bad Request")
        decoded = json.loads(raw_body)
        self.assertEqual(decoded["error"], "invalid_request")

        # Top-level non-object.
        status, _, body = call_json("POST", path, b"[1,2]")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

        # Unknown field.
        status, _, body = call_json(
            "POST", path, {"state": "staged", "bogus": 1}
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_invalid_state(self) -> None:
        resource_id = register()
        path = f"/resources/{resource_id}/lifecycle"
        for state in (None, 1, "", "STAGED", "Staged", "archived"):
            status, _, body = call_json("POST", path, {"state": state})
            self.assertEqual(status, "400 Bad Request", state)
            self.assertEqual(body["error"], "invalid_request")

    def test_invalid_reason(self) -> None:
        resource_id = register()
        path = f"/resources/{resource_id}/lifecycle"
        for reason in (123, True, "", "x" * 1025, "中" * 1025):
            status, _, body = call_json(
                "POST", path, {"state": "staged", "reason": reason}
            )
            self.assertEqual(status, "400 Bad Request", reason)
            self.assertEqual(body["error"], "invalid_request")

    def test_reason_length_boundary_in_code_points(self) -> None:
        resource_id = register()
        path = f"/resources/{resource_id}/lifecycle"
        # 1024 non-ASCII code points (3 UTF-8 bytes each) is accepted.
        status, _, body = call_json(
            "POST",
            path,
            {"state": "quarantined", "reason": "中" * 1024},
        )
        self.assertEqual(status, "200 OK", body)
        self.assertEqual(len(body["reason"]), 1024)

    def test_post_unknown_resource_is_404(self) -> None:
        status, _, body = call_json(
            "POST", "/resources/deadbeef/lifecycle", {"state": "staged"}
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

    def test_post_rejects_bad_id_and_query_params(self) -> None:
        status, _, body = call_json(
            "POST", "/resources//lifecycle", {"state": "staged"}
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

        resource_id = register()
        status, _, body = call_json(
            "POST",
            f"/resources/{resource_id}/lifecycle",
            {"state": "staged"},
            query_string="x=1",
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    # --- Failure isolation --------------------------------------------------

    def test_failed_transition_keeps_content_readable(self) -> None:
        resource_id = register()
        assemble_single_chunk(resource_id)
        call_json(
            "POST", f"/resources/{resource_id}/lifecycle", {"state": "released"}
        )
        # Illegal transition must not disturb finalized content.
        status, _, _ = call_json(
            "POST", f"/resources/{resource_id}/lifecycle", {"state": "staged"}
        )
        self.assertEqual(status, "409 Conflict")
        status, _, raw = call("GET", f"/resources/{resource_id}/content")
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"data")

    def test_failed_release_keeps_dependencies_and_chunks(self) -> None:
        dep = register("dep")
        assemble_single_chunk(dep)
        target = register("target")
        assemble_single_chunk(target)
        add_dependency(target, dep)

        # Block the dependency; return the staged target for a release attempt.
        call_json(
            "POST", f"/resources/{dep}/lifecycle",
            {"state": "quarantined", "reason": "hold"},
        )
        status, _, body = call_json(
            "POST", f"/resources/{target}/lifecycle", {"state": "released"}
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "dependency_blocked")

        # The dependency relation, finalized content and state all survive.
        status, _, body = call_json("GET", f"/resources/{target}/dependencies")
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["dependencies"], [dep])
        status, _, raw = call("GET", f"/resources/{target}/content")
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"data")
        _, _, after = call_json("GET", f"/resources/{target}/lifecycle")
        self.assertEqual(after["state"], "staged")


if __name__ == "__main__":
    unittest.main()
