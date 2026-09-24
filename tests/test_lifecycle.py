from __future__ import annotations

import hashlib
import io
import json
import unittest

from provenance_api.app import application, reset_state

CONTENT = b"lifecycle payload"
DIGEST = hashlib.sha256(CONTENT).hexdigest()


def call(
    method: str,
    path: str,
    body: bytes | str | dict[str, object] | None = None,
    *,
    content_type: str | None = None,
    headers: dict[str, str] | None = None,
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
        "wsgi.input": io.BytesIO(payload),
        "CONTENT_LENGTH": str(len(payload)),
    }
    if content_type is not None:
        environ["CONTENT_TYPE"] = content_type
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


def register(name: str = "res", digest: str = DIGEST) -> str:
    status, _, body = call_json(
        "POST",
        "/resources",
        {"name": name, "category": "model", "digest": digest},
    )
    assert status == "201 Created", body
    return str(body["id"])


def assemble(resource_id: str, content: bytes = CONTENT) -> None:
    status, _, _ = call(
        "POST",
        f"/resources/{resource_id}/chunks/0",
        content,
        content_type="application/octet-stream",
        headers={
            "HTTP_X_TOTAL_CHUNKS": "1",
            "HTTP_X_CONTENT_DIGEST": hashlib.sha256(content).hexdigest(),
        },
    )
    assert status == "201 Created"
    status, _, _ = call_json("POST", f"/resources/{resource_id}/assemble")
    assert status == "201 Created"


def get_lifecycle(resource_id: str) -> dict[str, object]:
    status, _, body = call_json("GET", f"/resources/{resource_id}/lifecycle")
    assert status == "200 OK", body
    return body


class LifecycleReadTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def test_first_read_reports_staged_with_empty_reason(self) -> None:
        resource_id = register()

        status, headers, raw = call("GET", f"/resources/{resource_id}/lifecycle")

        self.assertEqual(status, "200 OK")
        self.assertEqual(
            raw,
            b'{"id":"%s","state":"staged","reason":null}\n'
            % resource_id.encode("ascii"),
        )
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )

    def test_read_unknown_resource_returns_404(self) -> None:
        status, _, body = call_json("GET", "/resources/missing/lifecycle")

        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

    def test_read_rejects_query_parameters(self) -> None:
        resource_id = register()

        status, _, body = call_json(
            "GET",
            f"/resources/{resource_id}/lifecycle",
            query_string="state=staged",
        )

        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_read_rejects_separator_in_id(self) -> None:
        status, _, body = call_json("GET", "/resources/a/b/lifecycle")

        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_undeclared_method_returns_405_with_allow(self) -> None:
        resource_id = register()

        status, headers, body = call_json(
            "PUT", f"/resources/{resource_id}/lifecycle", {"state": "staged"}
        )

        self.assertEqual(status, "405 Method Not Allowed")
        self.assertEqual(body["error"], "method_not_allowed")
        self.assertIn(("Allow", "GET, POST"), headers)


class LifecycleRequestValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.resource_id = register()

    def assert_bad_request(self, body: object, **kwargs: object) -> None:
        status, _, payload = call_json(
            "POST",
            f"/resources/{self.resource_id}/lifecycle",
            body,  # type: ignore[arg-type]
            **kwargs,
        )
        self.assertEqual(status, "400 Bad Request", payload)
        self.assertEqual(payload["error"], "invalid_request")

    def test_missing_body(self) -> None:
        self.assert_bad_request(None)

    def test_bad_utf8(self) -> None:
        self.assert_bad_request(b"\xff\xfe")

    def test_non_object_top_level(self) -> None:
        self.assert_bad_request('["staged"]')

    def test_unknown_field(self) -> None:
        self.assert_bad_request({"state": "staged", "extra": 1})

    def test_missing_state(self) -> None:
        self.assert_bad_request({"reason": "why"})

    def test_state_not_a_string(self) -> None:
        self.assert_bad_request({"state": 1})

    def test_state_empty(self) -> None:
        self.assert_bad_request({"state": ""})

    def test_state_undeclared(self) -> None:
        self.assert_bad_request({"state": "pending"})

    def test_state_is_case_sensitive(self) -> None:
        self.assert_bad_request({"state": "STAGED"})
        self.assert_bad_request({"state": "Released"})

    def test_reason_not_a_string(self) -> None:
        self.assert_bad_request({"state": "staged", "reason": 7})

    def test_reason_empty(self) -> None:
        self.assert_bad_request({"state": "staged", "reason": ""})
        self.assert_bad_request({"state": "staged", "reason": "   "})

    def test_reason_too_long(self) -> None:
        self.assert_bad_request({"state": "staged", "reason": "x" * 1025})

    def test_reason_at_limit_is_accepted(self) -> None:
        status, _, body = call_json(
            "POST",
            f"/resources/{self.resource_id}/lifecycle",
            {"state": "quarantined", "reason": "界" * 1024},
        )

        self.assertEqual(status, "201 Created")
        self.assertEqual(body["reason"], "界" * 1024)

    def test_quarantine_requires_reason(self) -> None:
        self.assert_bad_request({"state": "quarantined"})

    def test_withdraw_requires_reason(self) -> None:
        assemble(self.resource_id)
        call_json(
            "POST",
            f"/resources/{self.resource_id}/lifecycle",
            {"state": "released"},
        )
        self.assert_bad_request({"state": "withdrawn"})

    def test_query_parameters_rejected(self) -> None:
        self.assert_bad_request({"state": "staged"}, query_string="a=b")

    def test_unknown_resource_returns_404(self) -> None:
        status, _, body = call_json(
            "POST", "/resources/missing/lifecycle", {"state": "staged"}
        )

        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

    def test_validation_failures_leave_state_unchanged(self) -> None:
        self.assert_bad_request({"state": "RELEASED"})
        self.assert_bad_request({"state": "quarantined"})

        self.assertEqual(
            get_lifecycle(self.resource_id),
            {"id": self.resource_id, "state": "staged", "reason": None},
        )


class LifecycleTransitionTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.resource_id = register()

    def submit(
        self, target: str, reason: str | None = None
    ) -> tuple[str, dict[str, object]]:
        payload: dict[str, object] = {"state": target}
        if reason is not None:
            payload["reason"] = reason
        status, _, body = call_json(
            "POST", f"/resources/{self.resource_id}/lifecycle", payload
        )
        return status, body

    def test_release_requires_complete_content(self) -> None:
        status, body = self.submit("released")

        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "content_not_complete")
        self.assertEqual(get_lifecycle(self.resource_id)["state"], "staged")

    def test_release_after_assembly(self) -> None:
        assemble(self.resource_id)

        status, body = self.submit("released")

        self.assertEqual(status, "201 Created")
        self.assertEqual(
            body,
            {"id": self.resource_id, "state": "released", "reason": None},
        )

    def test_idempotent_resubmission_returns_200(self) -> None:
        assemble(self.resource_id)
        self.submit("released")

        status, body = self.submit("released")

        self.assertEqual(status, "200 OK")
        self.assertEqual(body["state"], "released")

    def test_same_state_with_different_reason_is_rejected(self) -> None:
        assemble(self.resource_id)
        self.submit("released")

        status, body = self.submit("released", reason="different")

        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "invalid_state_transition")
        self.assertEqual(get_lifecycle(self.resource_id)["reason"], None)

    def test_staged_quarantine_and_return(self) -> None:
        status, body = self.submit("quarantined", reason="bad supply chain")

        self.assertEqual(status, "201 Created")
        self.assertEqual(body["state"], "quarantined")
        self.assertEqual(body["reason"], "bad supply chain")

        # A quarantined resource must not jump straight to released.
        assemble(self.resource_id)
        status, body = self.submit("released")
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "invalid_state_transition")

        status, body = self.submit("staged")
        self.assertEqual(status, "201 Created")
        self.assertEqual(body["state"], "staged")
        self.assertEqual(body["reason"], None)

        status, _ = self.submit("released")
        self.assertEqual(status, "201 Created")

    def test_released_withdraw_and_return(self) -> None:
        assemble(self.resource_id)
        self.submit("released")

        status, body = self.submit("withdrawn", reason="recalled")

        self.assertEqual(status, "201 Created")
        self.assertEqual(body["state"], "withdrawn")
        self.assertEqual(body["reason"], "recalled")

        # Withdrawn goes back through staged before any new release.
        status, body = self.submit("released")
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "invalid_state_transition")

        status, _ = self.submit("staged")
        self.assertEqual(status, "201 Created")
        status, _ = self.submit("released")
        self.assertEqual(status, "201 Created")

    def test_released_quarantine(self) -> None:
        assemble(self.resource_id)
        self.submit("released")

        status, body = self.submit("quarantined", reason="audit")

        self.assertEqual(status, "201 Created")
        self.assertEqual(body["state"], "quarantined")

    def test_staged_cannot_withdraw_directly(self) -> None:
        status, body = self.submit("withdrawn", reason="why")

        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "invalid_state_transition")
        self.assertEqual(get_lifecycle(self.resource_id)["state"], "staged")

    def test_withdrawn_cannot_be_quarantined_directly(self) -> None:
        assemble(self.resource_id)
        self.submit("released")
        self.submit("withdrawn", reason="recalled")

        status, body = self.submit("quarantined", reason="audit")

        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "invalid_state_transition")


class LifecycleDependencyTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.dependent_content = b"dependent bytes"
        self.dependency = register("dep")
        self.dependent = register(
            "app", hashlib.sha256(self.dependent_content).hexdigest()
        )
        status, _, _ = call_json(
            "POST",
            f"/resources/{self.dependent}/dependencies",
            {"dependency_id": self.dependency},
        )
        assert status == "201 Created"
        assemble(self.dependency)
        assemble(self.dependent, self.dependent_content)

    def test_quarantined_dependency_blocks_release(self) -> None:
        call_json(
            "POST",
            f"/resources/{self.dependency}/lifecycle",
            {"state": "quarantined", "reason": "tainted"},
        )

        status, _, body = call_json(
            "POST", f"/resources/{self.dependent}/lifecycle", {"state": "released"}
        )

        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "dependency_blocked")
        self.assertEqual(get_lifecycle(self.dependent)["state"], "staged")

    def test_withdrawn_dependency_blocks_release(self) -> None:
        call_json(
            "POST", f"/resources/{self.dependency}/lifecycle", {"state": "released"}
        )
        call_json(
            "POST",
            f"/resources/{self.dependency}/lifecycle",
            {"state": "withdrawn", "reason": "recalled"},
        )

        status, _, body = call_json(
            "POST", f"/resources/{self.dependent}/lifecycle", {"state": "released"}
        )

        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "dependency_blocked")

    def test_healthy_dependencies_allow_release(self) -> None:
        call_json(
            "POST", f"/resources/{self.dependency}/lifecycle", {"state": "released"}
        )

        status, _, body = call_json(
            "POST", f"/resources/{self.dependent}/lifecycle", {"state": "released"}
        )

        self.assertEqual(status, "201 Created")
        self.assertEqual(body["state"], "released")

    def test_transitive_dependency_blocks_release(self) -> None:
        leaf = register("leaf", hashlib.sha256(b"leaf bytes").hexdigest())
        assemble(leaf, b"leaf bytes")
        status, _, _ = call_json(
            "POST",
            f"/resources/{self.dependency}/dependencies",
            {"dependency_id": leaf},
        )
        assert status == "201 Created"
        call_json(
            "POST",
            f"/resources/{leaf}/lifecycle",
            {"state": "quarantined", "reason": "tainted"},
        )

        status, _, body = call_json(
            "POST", f"/resources/{self.dependent}/lifecycle", {"state": "released"}
        )

        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "dependency_blocked")


class LifecycleIsolationTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def test_resource_and_content_behavior_is_unchanged(self) -> None:
        resource_id = register()
        call_json(
            "POST",
            f"/resources/{resource_id}/lifecycle",
            {"state": "quarantined", "reason": "audit"},
        )

        # The resource record itself carries no lifecycle fields.
        status, _, body = call_json("GET", f"/resources/{resource_id}")
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            set(body), {"id", "name", "category", "digest", "source"}
        )

        # Content reads still follow the baseline contract.
        status, _, body = call_json("GET", f"/resources/{resource_id}/content")
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "content_not_complete")

    def test_failed_transition_preserves_content_and_dependencies(self) -> None:
        dependency = register("dep")
        dependent = register("app", "b" * 64)
        call_json(
            "POST",
            f"/resources/{dependent}/dependencies",
            {"dependency_id": dependency},
        )

        status, _, _ = call_json(
            "POST", f"/resources/{dependent}/lifecycle", {"state": "released"}
        )
        self.assertEqual(status, "409 Conflict")

        status, _, body = call_json("GET", f"/resources/{dependent}/dependencies")
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["dependencies"], [dependency])

    def test_reset_state_clears_lifecycle(self) -> None:
        resource_id = register()
        call_json(
            "POST",
            f"/resources/{resource_id}/lifecycle",
            {"state": "quarantined", "reason": "audit"},
        )

        reset_state()
        resource_id = register()

        self.assertEqual(get_lifecycle(resource_id)["state"], "staged")


if __name__ == "__main__":
    unittest.main()
