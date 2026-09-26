from __future__ import annotations

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


def add_dependency(source: str, target: str) -> str:
    status, _h, body = call_json(
        "POST",
        f"/resources/{source}/dependencies",
        {"dependency_id": target},
    )
    assert status == "201 Created", (status, body)
    return status


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


class DependencyDeleteTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def _delete(
        self, source: str, target: str, **kwargs: object
    ) -> tuple[str, list[tuple[str, str]], bytes]:
        return call(
            "DELETE",
            f"/resources/{source}/dependencies/{target}",
            **kwargs,
        )

    # --- Success path ------------------------------------------------------

    def test_delete_returns_200_echo_in_registration_key_order(self) -> None:
        a = create_resource("a", DIGEST_A)["id"]
        b = create_resource("b", DIGEST_B)["id"]
        add_dependency(a, b)

        status, headers, raw = self._delete(a, b)

        self.assertEqual(status, "200 OK")
        self.assertEqual(
            raw,
            (
                b'{"resource_id":"'
                + a.encode("ascii")
                + b'","dependency_id":"'
                + b.encode("ascii")
                + b'"}\n'
            ),
        )
        # A single trailing newline, compact JSON throughout.
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        self.assertNotIn(b": ", raw)
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )

    def test_only_the_direct_edge_is_removed(self) -> None:
        a = create_resource("a", DIGEST_A)["id"]
        c = create_resource("c", DIGEST_C)["id"]
        b = create_resource("b", DIGEST_B)["id"]
        add_dependency(a, b)
        add_dependency(a, c)
        add_dependency(c, b)

        self._delete(a, b)

        # b stays reachable through c; both resources themselves remain.
        _s, _h, deps = call_json("GET", f"/resources/{a}/dependencies")
        self.assertEqual(deps["dependencies"], [c, b])
        for rid in (a, b):
            status, _h, _body = call_json("GET", f"/resources/{rid}")
            self.assertEqual(status, "200 OK")
        # The reverse view is recomputed the same way.
        _s, _h, impact = call_json("GET", f"/resources/{b}/impact")
        self.assertEqual(impact["resources"], [a, c])

    def test_other_edges_relations_and_resources_are_untouched(self) -> None:
        a = create_resource("a", DIGEST_A)["id"]
        b = create_resource("b", DIGEST_B)["id"]
        c = create_resource("c", DIGEST_C)["id"]
        add_dependency(a, b)
        add_dependency(b, c)

        self._delete(a, b)

        # The other edge b -> c survives unchanged.
        _s, _h, deps = call_json("GET", f"/resources/{b}/dependencies")
        self.assertEqual(deps["dependencies"], [c])
        _s, _h, listing = call_json("GET", "/resources")
        self.assertEqual(
            [r["id"] for r in listing["resources"]], [a, b, c]
        )

    def test_re_register_same_direction_recreates_edge_with_201(self) -> None:
        a = create_resource("a", DIGEST_A)["id"]
        b = create_resource("b", DIGEST_B)["id"]
        add_dependency(a, b)
        self._delete(a, b)

        status, _h, body = call_json(
            "POST",
            f"/resources/{a}/dependencies",
            {"dependency_id": b},
        )
        self.assertEqual(status, "201 Created", body)
        _s, _h, deps = call_json("GET", f"/resources/{a}/dependencies")
        self.assertEqual(deps["dependencies"], [b])

    # --- The four derived views are recomputed ----------------------------

    def test_release_blockers_recomputed_after_edge_delete(self) -> None:
        a = create_resource("a", DIGEST_A)["id"]
        b = create_resource("b", DIGEST_B)["id"]
        add_dependency(a, b)
        status, _h, _body = call_json(
            "POST",
            f"/resources/{b}/lifecycle",
            {"state": "quarantined", "reason": "under review"},
        )
        self.assertEqual(status, "200 OK")

        status, _h, before = call_json(
            "GET", f"/resources/{a}/release-blockers"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            before["blockers"],
            [{"resource_id": b, "state": "quarantined"}],
        )

        self._delete(a, b)

        _s, _h, after = call_json(
            "GET", f"/resources/{a}/release-blockers"
        )
        self.assertEqual(after["blocked"], True)
        self.assertEqual(after["reasons"], ["content_not_complete"])
        self.assertEqual(after["blockers"], [])

    def test_dependency_vulnerability_impact_recomputed_after_delete(
        self,
    ) -> None:
        a = create_resource("a", DIGEST_A)["id"]
        b = create_resource("b", DIGEST_B)["id"]
        add_dependency(a, b)
        status, _h, _body = call_json(
            "POST",
            f"/resources/{b}/vulnerabilities",
            {
                "advisory": "CVE-2026-0001",
                "component": "openssl",
                "severity": "high",
                "summary": "s",
            },
        )
        self.assertEqual(status, "201 Created")

        self._delete(a, b)

        _s, _h, impacts = call_json(
            "GET", f"/resources/{a}/dependency-vulnerability-impact"
        )
        self.assertEqual(
            impacts["impacts"],
            [
                {
                    "resource_id": a,
                    "advisory_count": 0,
                    "max_severity": None,
                }
            ],
        )

    # --- Cross-repository references --------------------------------------

    def test_cross_reference_edge_removed_but_record_and_remote_remain(
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

        _s, _h, listing = call_json("GET", "/resources")
        remote = next(
            r for r in listing["resources"] if r["id"] != rid
        )
        remote_id = str(remote["id"])

        status, _h, raw = self._delete(rid, remote_id)
        self.assertEqual(status, "200 OK", raw)

        # The reference record and the resolved remote local resource are
        # left exactly as they were.
        _s, _h, refs = call_json(
            "GET", f"/resources/{rid}/cross-references"
        )
        self.assertEqual(len(refs["cross_references"]), 1)
        status, _h, body = call_json("GET", f"/resources/{remote_id}")
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["name"], "remote-model")
        _s, _h, deps = call_json(f"GET", f"/resources/{rid}/dependencies")
        self.assertEqual(deps["dependencies"], [])

        # Repeating the same reference is still the baseline duplicate
        # rejection and never rebuilds the removed edge on its own.
        with patch_resolve():
            status, _h, body = call_json(
                "POST",
                f"/resources/{rid}/cross-references",
                reference,
            )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "duplicate_reference")
        _s, _h, deps = call_json("GET", f"/resources/{rid}/dependencies")
        self.assertEqual(deps["dependencies"], [])

    # --- Not found ----------------------------------------------------------

    def test_missing_start_resource_is_not_found(self) -> None:
        b = create_resource("b", DIGEST_B)["id"]
        status, _h, body = call_json(
            "DELETE", f"/resources/does-not-exist/dependencies/{b}"
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

        # No existing state changed.
        _s, _h, resource = call_json("GET", f"/resources/{b}")
        self.assertEqual(resource["id"], b)

    def test_missing_edge_is_dependency_not_found(self) -> None:
        a = create_resource("a", DIGEST_A)["id"]
        b = create_resource("b", DIGEST_B)["id"]

        status, _h, body = call_json(
            "DELETE", f"/resources/{a}/dependencies/{b}"
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "dependency_not_found")

    def test_unknown_dependency_id_is_dependency_not_found(self) -> None:
        a = create_resource("a", DIGEST_A)["id"]
        status, _h, body = call_json(
            "DELETE", f"/resources/{a}/dependencies/does-not-exist"
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "dependency_not_found")

    def test_unregistered_dependency_is_dependency_not_found(self) -> None:
        a = create_resource("a", DIGEST_A)["id"]
        b = create_resource("b", DIGEST_B)["id"]
        add_dependency(a, b)
        # Unregistering the dependency cascades its edges away.
        status, _h, _body = call("DELETE", f"/resources/{b}")
        self.assertEqual(status, "200 OK")

        status, _h, body = call_json(
            "DELETE", f"/resources/{a}/dependencies/{b}"
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "dependency_not_found")

    def test_repeat_delete_is_dependency_not_found(self) -> None:
        a = create_resource("a", DIGEST_A)["id"]
        b = create_resource("b", DIGEST_B)["id"]
        c = create_resource("c", DIGEST_C)["id"]
        add_dependency(a, b)
        add_dependency(a, c)

        self.assertEqual(self._delete(a, b)[0], "200 OK")
        status, _h, body = call_json(
            "DELETE", f"/resources/{a}/dependencies/{b}"
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "dependency_not_found")

        # The other relation and every resource are still there.
        _s, _h, deps = call_json("GET", f"/resources/{a}/dependencies")
        self.assertEqual(deps["dependencies"], [c])
        _s, _h, listing = call_json("GET", "/resources")
        self.assertEqual(len(listing["resources"]), 3)

    # --- Validation ---------------------------------------------------------

    def test_empty_start_id_is_bad_request(self) -> None:
        status, _h, body = call_json(
            "DELETE", "/resources//dependencies/x"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_empty_dependency_id_is_bad_request(self) -> None:
        a = create_resource("a", DIGEST_A)["id"]
        status, _h, body = call_json(
            "DELETE", f"/resources/{a}/dependencies/"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_separator_in_either_id_is_bad_request(self) -> None:
        a = create_resource("a", DIGEST_A)["id"]
        b = create_resource("b", DIGEST_B)["id"]
        add_dependency(a, b)

        for path in (
            f"/resources/{a}/dependencies/x/y",
            f"/resources/{a}/dependencies/x\\y",
            f"/resources/x/y/dependencies/{b}",
            f"/resources/x\\y/dependencies/{b}",
        ):
            with self.subTest(path=path):
                status, _h, body = call_json("DELETE", path)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

        # The rejected requests removed nothing.
        _s, _h, deps = call_json("GET", f"/resources/{a}/dependencies")
        self.assertEqual(deps["dependencies"], [b])

    def test_query_parameter_is_bad_request(self) -> None:
        a = create_resource("a", DIGEST_A)["id"]
        b = create_resource("b", DIGEST_B)["id"]
        add_dependency(a, b)

        for query in ("force=yes", "="):
            with self.subTest(query=query):
                status, _h, body = call_json(
                    "DELETE",
                    f"/resources/{a}/dependencies/{b}",
                    query_string=query,
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

        _s, _h, deps = call_json("GET", f"/resources/{a}/dependencies")
        self.assertEqual(deps["dependencies"], [b])

    def test_declared_body_is_bad_request(self) -> None:
        a = create_resource("a", DIGEST_A)["id"]
        b = create_resource("b", DIGEST_B)["id"]
        add_dependency(a, b)

        status, _h, body = call_json(
            "DELETE",
            f"/resources/{a}/dependencies/{b}",
            body={"x": 1},
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        _s, _h, deps = call_json("GET", f"/resources/{a}/dependencies")
        self.assertEqual(deps["dependencies"], [b])

    def test_malformed_content_length_is_bad_request(self) -> None:
        a = create_resource("a", DIGEST_A)["id"]
        b = create_resource("b", DIGEST_B)["id"]
        add_dependency(a, b)

        status, _h, body = call_json(
            "DELETE",
            f"/resources/{a}/dependencies/{b}",
            content_length="abc",
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_zero_content_length_is_accepted(self) -> None:
        a = create_resource("a", DIGEST_A)["id"]
        b = create_resource("b", DIGEST_B)["id"]
        add_dependency(a, b)

        status, _h, _body = self._delete(a, b, content_length="0")
        self.assertEqual(status, "200 OK")

    def test_other_methods_return_405_with_allow(self) -> None:
        a = create_resource("a", DIGEST_A)["id"]
        b = create_resource("b", DIGEST_B)["id"]
        add_dependency(a, b)

        for method in ("GET", "POST", "PUT", "PATCH"):
            with self.subTest(method=method):
                status, headers, body = call_json(
                    method, f"/resources/{a}/dependencies/{b}"
                )
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")
                self.assertIn(("Allow", "DELETE"), headers)

        # Method rejection changed nothing.
        _s, _h, deps = call_json("GET", f"/resources/{a}/dependencies")
        self.assertEqual(deps["dependencies"], [b])

    # --- Listing cursors ---------------------------------------------------

    def test_listing_order_and_prior_cursor_survive_edge_delete(self) -> None:
        first = create_resource("a", DIGEST_A)["id"]
        second = create_resource("b", DIGEST_B)["id"]
        third = create_resource("c", DIGEST_C)["id"]
        add_dependency(first, second)

        _s, _h, page = call_json(
            "GET", "/resources", query_string="limit=2"
        )
        cursor = page["next_cursor"]
        self.assertIsNotNone(cursor)

        self._delete(first, second)

        _s, _h, page = call_json(
            "GET", "/resources", query_string=f"limit=2&cursor={cursor}"
        )
        self.assertEqual([r["id"] for r in page["resources"]], [third])

        _s, _h, listing = call_json("GET", "/resources")
        self.assertEqual(
            [r["id"] for r in listing["resources"]],
            [first, second, third],
        )


if __name__ == "__main__":
    unittest.main()
