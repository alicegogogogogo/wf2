from __future__ import annotations

import hashlib
import hmac
import io
import json
import unittest
from unittest import mock

from provenance_api.app import application, reset_state
from provenance_api.cross_references import Resolution

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_D = "d" * 64

UPSTREAM = "https://repo.example.invalid"


def call(
    method: str,
    path: str,
    body: bytes | str | dict[str, object] | None = None,
    *,
    query_string: str | None = None,
    content_type: str | None = "application/json",
    omit_content_length: bool = False,
    content_length: int | str | None = None,
    extra_headers: dict[str, str] | None = None,
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
        "wsgi.input": io.BytesIO(payload),
    }
    if not omit_content_length:
        environ["CONTENT_LENGTH"] = (
            str(len(payload)) if content_length is None else str(content_length)
        )
    if content_type is not None:
        environ["CONTENT_TYPE"] = content_type
    for key, value in (extra_headers or {}).items():
        environ[key] = value
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
    **kwargs: object,
) -> tuple[str, list[tuple[str, str]], dict[str, object]]:
    status, headers, raw = call(
        method, path, body, query_string=query_string, **kwargs
    )
    return status, headers, json.loads(raw.decode("utf-8"))


def create_resource(
    name: str, digest: str, category: str = "code"
) -> dict[str, object]:
    status, _h, body = call_json(
        "POST",
        "/resources",
        {"name": name, "category": category, "digest": digest},
    )
    assert status == "201 Created", (status, body)
    return body


def patch_resolve(
    *,
    name: str = "remote-model",
    category: str = "model",
    digest: str = DIGEST_D,
    source: str = "https://repo.example.invalid/sources/remote-42",
):
    raw = json.dumps(
        {"name": name, "category": category, "digest": digest, "source": source},
        separators=(",", ":"),
    ).encode("utf-8")
    resolution = Resolution(
        name=name,
        category=category,
        digest=digest,
        source=source,
        raw=raw,
    )
    return mock.patch(
        "provenance_api.app.resolve_remote", return_value=resolution
    )


class ResourceDeleteTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def _delete(
        self, raw_id: str, **kwargs: object
    ) -> tuple[str, list[tuple[str, str]], bytes]:
        return call("DELETE", f"/resources/{raw_id}", **kwargs)

    # --- Success path ------------------------------------------------------

    def test_delete_returns_200_and_echoes_full_record(self) -> None:
        created = create_resource("model-a", DIGEST_A, category="Model")

        status, headers, raw = self._delete(created["id"])

        self.assertEqual(status, "200 OK")
        self.assertTrue(raw.endswith(b"\n"))
        self.assertEqual(raw, raw.rstrip(b"\n") + b"\n")
        self.assertNotIn(b": ", raw)
        self.assertEqual(json.loads(raw.decode("utf-8")), created)
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )

    def test_deleted_resource_is_gone(self) -> None:
        created = create_resource("r", DIGEST_A)
        self._delete(created["id"])

        status, _h, body = call_json("GET", f"/resources/{created['id']}")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

        _s, _h, listing = call_json("GET", "/resources")
        self.assertEqual(listing, {"resources": []})

    def test_second_delete_is_not_found(self) -> None:
        created = create_resource("r", DIGEST_A)
        self._delete(created["id"])

        status, _h, body = call_json("DELETE", f"/resources/{created['id']}")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

    def test_delete_unknown_id_is_not_found(self) -> None:
        status, _h, body = call_json("DELETE", "/resources/does-not-exist")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

    def test_reregister_after_delete_gets_fresh_id_and_default_state(
        self,
    ) -> None:
        created = create_resource("r", DIGEST_A)
        call_json(
            "POST",
            f"/resources/{created['id']}/lifecycle",
            {"state": "released"},
        )
        self._delete(created["id"])

        again = create_resource("r", DIGEST_A)
        self.assertNotEqual(again["id"], created["id"])

        _s, _h, lifecycle = call_json(
            "GET", f"/resources/{again['id']}/lifecycle"
        )
        self.assertEqual(lifecycle["state"], "staged")
        self.assertIsNone(lifecycle["reason"])

    # --- Validation ----------------------------------------------------------

    def test_empty_id_is_bad_request(self) -> None:
        status, _h, body = call_json("DELETE", "/resources/")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_id_with_separator_is_bad_request(self) -> None:
        for raw_id in ("a/b", "a\\b"):
            with self.subTest(raw_id=raw_id):
                status, _h, body = call_json(
                    "DELETE", f"/resources/{raw_id}"
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_query_parameter_is_bad_request(self) -> None:
        created = create_resource("r", DIGEST_A)
        status, _h, body = call_json(
            "DELETE",
            f"/resources/{created['id']}",
            query_string="force=yes",
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        # The failed request changed nothing.
        get_status, _h, _b = call_json("GET", f"/resources/{created['id']}")
        self.assertEqual(get_status, "200 OK")

    def test_declared_body_is_bad_request(self) -> None:
        created = create_resource("r", DIGEST_A)
        status, _h, body = call_json(
            "DELETE", f"/resources/{created['id']}", body={"x": 1}
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        get_status, _h, _b = call_json("GET", f"/resources/{created['id']}")
        self.assertEqual(get_status, "200 OK")

    def test_malformed_content_length_is_bad_request(self) -> None:
        created = create_resource("r", DIGEST_A)
        status, _h, body = call_json(
            "DELETE",
            f"/resources/{created['id']}",
            content_length="abc",
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_zero_content_length_is_accepted(self) -> None:
        created = create_resource("r", DIGEST_A)
        status, _h, _b = call(
            "DELETE", f"/resources/{created['id']}", content_length="0"
        )
        self.assertEqual(status, "200 OK")

    def test_unsupported_methods_return_405_with_allow(self) -> None:
        created = create_resource("r", DIGEST_A)
        for method in ("PUT", "PATCH", "POST"):
            with self.subTest(method=method):
                status, headers, body = call_json(
                    method, f"/resources/{created['id']}"
                )
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")
                self.assertIn(("Allow", "DELETE, GET"), headers)
        # The failed requests changed nothing.
        get_status, _h, _b = call_json("GET", f"/resources/{created['id']}")
        self.assertEqual(get_status, "200 OK")

    def test_get_still_works_after_delete_of_other_resource(self) -> None:
        first = create_resource("a", DIGEST_A)
        second = create_resource("b", DIGEST_B)
        self._delete(first["id"])

        status, _h, body = call_json("GET", f"/resources/{second['id']}")
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, second)

    # --- Cascade ------------------------------------------------------------

    def test_cascade_removes_alerts_exemptions_and_global_summary(self):
        created = create_resource("r", DIGEST_A)
        rid = str(created["id"])
        alert = {
            "advisory": "CVE-2026-0001",
            "component": "openssl",
            "severity": "high",
            "summary": "s",
        }
        status, _h, _b = call_json(
            "POST", f"/resources/{rid}/vulnerabilities", alert
        )
        self.assertEqual(status, "201 Created")
        status, _h, _b = call_json(
            "POST",
            f"/resources/{rid}/vulnerability-exceptions",
            {
                "advisory": "CVE-2026-0001",
                "component": "openssl",
                "reason": "accepted",
            },
        )
        self.assertEqual(status, "201 Created")

        _s, _h, summary = call_json("GET", "/advisories")
        self.assertNotEqual(summary, [])

        self._delete(rid)

        _s, _h, summary = call_json("GET", "/advisories")
        self.assertEqual(summary, [])
        for path in ("vulnerabilities", "vulnerability-exceptions"):
            status, _h, body = call_json("GET", f"/resources/{rid}/{path}")
            self.assertEqual(status, "404 Not Found", path)
            self.assertEqual(body["error"], "resource_not_found")

    def test_cascade_removes_sbom_license_provenance_policy_signature(
        self,
    ) -> None:
        created = create_resource("r", DIGEST_A)
        rid = str(created["id"])

        registrations = [
            (
                "sbom",
                {
                    "format": "cyclonedx",
                    "components": [
                        {"name": "openssl", "version": "3.0", "digest": DIGEST_B}
                    ],
                },
            ),
            ("license", {"spdx_id": "Apache-2.0"}),
            (
                "provenance",
                {
                    "builder": "ci-bot",
                    "build_number": "build-001",
                    "source_digest": DIGEST_A,
                    "materials": [],
                },
            ),
            (
                "policies",
                {
                    "name": "gate",
                    "evidence_requirements": [],
                    "license_allowlist": [],
                    "max_severity": "high",
                },
            ),
            (
                "signatures",
                {
                    "signer": "alice",
                    "algorithm": "hmac-sha256",
                    "key_id": "key-001",
                    "signature": hmac.new(
                        b"key-001", DIGEST_A.encode("ascii"), hashlib.sha256
                    ).hexdigest(),
                    "digest": DIGEST_A,
                },
            ),
            (
                "notifications",
                {
                    "channel": "email",
                    "target": "alerts@example.invalid",
                    "message": "hello",
                },
            ),
        ]
        for path, payload in registrations:
            status, _h, body = call_json(
                "POST", f"/resources/{rid}/{path}", payload
            )
            self.assertIn(status, ("200 OK", "201 Created"), (path, body))

        self._delete(rid)

        for path, _payload in registrations:
            status, _h, body = call_json("GET", f"/resources/{rid}/{path}")
            self.assertEqual(status, "404 Not Found", path)
            self.assertEqual(body["error"], "resource_not_found")

    def test_cascade_removes_lifecycle_state(self) -> None:
        created = create_resource("r", DIGEST_A)
        rid = str(created["id"])
        call_json("POST", f"/resources/{rid}/lifecycle", {"state": "released"})

        self._delete(rid)

        status, _h, body = call_json("GET", f"/resources/{rid}/lifecycle")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

    def test_cascade_discards_chunk_sessions_and_content(self) -> None:
        content = b"hello world"
        digest = hashlib.sha256(content).hexdigest()
        created = create_resource("r", digest)
        rid = str(created["id"])
        headers = {
            "CONTENT_TYPE": "application/octet-stream",
            "HTTP_X_TOTAL_CHUNKS": "1",
            "HTTP_X_CONTENT_DIGEST": digest,
        }
        status, _h, _b = call(
            "POST", f"/resources/{rid}/chunks/0", content,
            extra_headers=headers, content_type=None,
        )
        self.assertEqual(status, "201 Created")
        status, _h, _b = call_json("POST", f"/resources/{rid}/assemble")
        self.assertEqual(status, "201 Created")

        self._delete(rid)

        # The session and its assembled bytes are unqueryable afterwards.
        status, _h, body = call_json("GET", f"/resources/{rid}/chunks/status")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")
        status, _h, body = call(
            "GET", f"/resources/{rid}/content", content_type=None
        )
        self.assertEqual(status, "404 Not Found")

    def test_cascade_removes_dependency_edges_in_both_directions(self):
        a = create_resource("a", DIGEST_A)
        b = create_resource("b", DIGEST_B)
        c = create_resource("c", DIGEST_C)
        # a -> b and b -> c
        for source, target in ((a, b), (b, c)):
            status, _h, _b = call_json(
                "POST",
                f"/resources/{source['id']}/dependencies",
                {"dependency_id": target["id"]},
            )
            self.assertEqual(status, "201 Created")

        self._delete(str(b["id"]))

        _s, _h, deps = call_json("GET", f"/resources/{a['id']}/dependencies")
        self.assertEqual(deps, {"dependencies": []})
        _s, _h, impact = call_json("GET", f"/resources/{c['id']}/impact")
        self.assertEqual(impact, {"resources": []})

    def test_cascade_removes_cross_references_but_keeps_remote_resource(
        self,
    ) -> None:
        local = create_resource("local", DIGEST_A)
        rid = str(local["id"])
        reference = {
            "repository": "partner",
            "upstream": UPSTREAM,
            "remote_id": "remote-42",
            "digest": DIGEST_D,
        }
        with patch_resolve():
            status, _h, _b = call_json(
                "POST", f"/resources/{rid}/cross-references", reference
            )
        self.assertEqual(status, "201 Created")

        # The resolution created a remote local resource plus an edge.
        _s, _h, listing = call_json("GET", "/resources")
        remote = next(
            r for r in listing["resources"] if r["id"] != rid  # type: ignore[index]
        )

        self._delete(rid)

        # The remote local resource stays; the edge and reference are gone.
        status, _h, body = call_json("GET", f"/resources/{remote['id']}")  # type: ignore[index]
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["name"], "remote-model")
        _s, _h, impact = call_json(
            "GET", f"/resources/{remote['id']}/impact"  # type: ignore[index]
        )
        self.assertEqual(impact, {"resources": []})

        # A new resource may register the same reference again.
        fresh = create_resource("local-2", DIGEST_B)
        with patch_resolve():
            status, _h, body = call_json(
                "POST",
                f"/resources/{fresh['id']}/cross-references",
                reference,
            )
        self.assertEqual(status, "201 Created", body)

    def test_delete_leaves_other_resources_untouched(self) -> None:
        keep = create_resource("keep", DIGEST_A)
        drop = create_resource("drop", DIGEST_B)
        for rid in (keep["id"], drop["id"]):
            call_json(
                "POST",
                f"/resources/{rid}/vulnerabilities",
                {
                    "advisory": "CVE-2026-0001",
                    "component": "openssl",
                    "severity": "high",
                    "summary": "s",
                },
            )

        self._delete(str(drop["id"]))

        _s, _h, alerts = call_json(
            "GET", f"/resources/{keep['id']}/vulnerabilities"
        )
        self.assertEqual(len(alerts["vulnerabilities"]), 1)
        _s, _h, summary = call_json("GET", "/advisories")
        self.assertEqual(len(summary), 1)

    # --- Listing cursors ------------------------------------------------------

    def test_issued_cursor_still_works_and_excludes_deleted(self) -> None:
        first = create_resource("a", DIGEST_A)
        second = create_resource("b", DIGEST_B)
        third = create_resource("c", DIGEST_C)

        _s, _h, page = call_json(
            "GET", "/resources", query_string="limit=2"
        )
        cursor = page["next_cursor"]
        self.assertIsNotNone(cursor)

        self._delete(str(first["id"]))

        _s, _h, page = call_json(
            "GET", "/resources", query_string=f"limit=2&cursor={cursor}"
        )
        # The previously issued cursor is still accepted and never leaks
        # the unregistered resource into a page.
        self.assertIn("resources", page)
        self.assertIn("next_cursor", page)
        remaining_ids = [r["id"] for r in page["resources"]]
        self.assertNotIn(first["id"], remaining_ids)

        _s, _h, listing = call_json("GET", "/resources")
        self.assertEqual(
            [r["id"] for r in listing["resources"]],
            [second["id"], third["id"]],
        )


if __name__ == "__main__":
    unittest.main()
