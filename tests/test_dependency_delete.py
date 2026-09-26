from __future__ import annotations

import io
import json
import unittest

from provenance_api.app import application, reset_state
from provenance_api.cross_references import Resolution

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_D = "d" * 64

UPSTREAM = "https://repo.example.invalid"
REMOTE_ID = "remote-42"
REMOTE_NAME = "remote-model"
DIGEST_REMOTE = "f" * 64
SOURCE = "https://repo.example.invalid/sources/remote-42"


def call(
    method: str,
    path: str,
    body: bytes | str | dict[str, object] | None = None,
    *,
    query_string: str | None = None,
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
        "wsgi.input": io.BytesIO(payload),
    }
    if not omit_content_length:
        environ["CONTENT_LENGTH"] = str(len(payload))
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
    **kwargs: object,
) -> tuple[str, list[tuple[str, str]], dict[str, object]]:
    status, headers, raw = call(method, path, body, **kwargs)  # type: ignore[arg-type]
    return status, headers, json.loads(raw.decode("utf-8"))


class DependencyDeleteTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def _create(self, name: str, digest: str) -> str:
        _s, _h, body = call_json(
            "POST",
            "/resources",
            {"name": name, "category": "code", "digest": digest},
        )
        return str(body["id"])

    def _add(self, resource_id: str, dependency_id: str) -> None:
        status, _h, _b = call_json(
            "POST",
            f"/resources/{resource_id}/dependencies",
            {"dependency_id": dependency_id},
        )
        self.assertEqual(status, "201 Created")

    def _delete(
        self, resource_id: str, dependency_id: str
    ) -> tuple[str, list[tuple[str, str]], dict[str, object]]:
        return call_json(
            "DELETE",
            f"/resources/{resource_id}/dependencies/{dependency_id}",
        )

    # --- Success and response shape ----------------------------------------

    def test_delete_returns_200_echoing_relation_in_registration_key_order(
        self,
    ) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        self._add(a, b)

        status, headers, body = self._delete(a, b)
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            list(body), ["resource_id", "dependency_id"]
        )
        self.assertEqual(body, {"resource_id": a, "dependency_id": b})
        self.assertEqual(
            headers[0], ("Content-Type", "application/json; charset=utf-8")
        )

    def test_delete_body_is_compact_json_ending_with_single_newline(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        self._add(a, b)

        _s, _h, raw = call(
            "DELETE", f"/resources/{a}/dependencies/{b}"
        )
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        self.assertNotIn(b" ", raw[:-1])
        self.assertEqual(
            raw,
            b'{"resource_id":"' + a.encode() + b'","dependency_id":"'
            + b.encode() + b'"}\n',
        )

    # --- Graph semantics ----------------------------------------------------

    def test_only_the_direct_edge_is_removed(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        self._add(a, b)
        self._add(b, c)
        self._add(a, c)

        status, _h, _b = self._delete(a, c)
        self.assertEqual(status, "200 OK")

        # a still reaches c through a -> b -> c.
        _s, _h, deps = call_json("GET", f"/resources/{a}/dependencies")
        self.assertEqual(deps["dependencies"], [b, c])
        # The direct edge itself is gone from b's inbound view.
        _s, _h, impact_c = call_json("GET", f"/resources/{c}/impact")
        self.assertEqual(impact_c["resources"], [a, b])

    def test_removing_edge_on_one_path_leaves_other_direct_edges_intact(
        self,
    ) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        self._add(a, b)
        self._add(a, c)
        self._add(b, c)

        self._delete(a, c)

        _s, _h, deps_a = call_json("GET", f"/resources/{a}/dependencies")
        self.assertEqual(deps_a["dependencies"], [b, c])
        _s, _h, deps_b = call_json("GET", f"/resources/{b}/dependencies")
        self.assertEqual(deps_b["dependencies"], [c])

    def test_re_registering_same_direction_recreates_edge_as_201(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        self._add(a, b)
        self._delete(a, b)

        status, _h, body = call_json(
            "POST",
            f"/resources/{a}/dependencies",
            {"dependency_id": b},
        )
        self.assertEqual(status, "201 Created")
        self.assertEqual(body, {"resource_id": a, "dependency_id": b})

        _s, _h, deps = call_json("GET", f"/resources/{a}/dependencies")
        self.assertEqual(deps["dependencies"], [b])

    def test_resource_records_are_not_touched(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        self._add(a, b)
        self._delete(a, b)

        _s, _h, listing = call_json("GET", "/resources")
        self.assertEqual(
            sorted(r["id"] for r in listing["resources"]), sorted([a, b])
        )
        for resource_id in (a, b):
            status, _h, _r = call_json("GET", f"/resources/{resource_id}")
            self.assertEqual(status, "200 OK")

    def test_deleted_edge_drops_from_release_blockers(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        self._add(a, b)
        status, _h, _b = call_json(
            "POST",
            f"/resources/{b}/lifecycle",
            {"state": "quarantined", "reason": "suspect"},
        )
        self.assertEqual(status, "200 OK")

        _s, _h, blockers = call_json(
            "GET", f"/resources/{a}/release-blockers"
        )
        self.assertEqual(
            blockers["blockers"],
            [{"resource_id": b, "state": "quarantined"}],
        )

        self._delete(a, b)

        _s, _h, blockers = call_json(
            "GET", f"/resources/{a}/release-blockers"
        )
        self.assertEqual(blockers["blockers"], [])
        self.assertNotIn("dependency_blocked", blockers["reasons"])

    def test_deleted_edge_drops_from_vulnerability_impact_closure(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        self._add(a, b)
        self._add(b, c)
        status, _h, _b = call_json(
            "POST",
            f"/resources/{c}/vulnerabilities",
            {
                "advisory": "CVE-1",
                "component": "lib",
                "severity": "high",
                "summary": "a bug",
            },
        )
        self.assertEqual(status, "201 Created")

        self._delete(b, c)

        _s, _h, impacts = call_json(
            "GET", f"/resources/{a}/dependency-vulnerability-impact"
        )
        self.assertEqual(
            [entry["resource_id"] for entry in impacts["impacts"]], [a, b]
        )
        # b itself still surfaces the edge's absence by reaching nothing.
        _s, _h, b_impacts = call_json(
            "GET", f"/resources/{b}/dependency-vulnerability-impact"
        )
        self.assertEqual(
            [entry["resource_id"] for entry in b_impacts["impacts"]], [b]
        )

    # --- Not found ----------------------------------------------------------

    def test_missing_edge_returns_dependency_not_found(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)

        status, _h, body = self._delete(a, b)
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "dependency_not_found")

    def test_repeat_delete_returns_dependency_not_found(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        self._add(a, b)
        self._add(a, c)

        first, _h, _b = self._delete(a, b)
        self.assertEqual(first, "200 OK")
        second, _h, body = self._delete(a, b)
        self.assertEqual(second, "404 Not Found")
        self.assertEqual(body["error"], "dependency_not_found")

        # Other relations and resources are unaffected by the repeated delete.
        _s, _h, deps = call_json("GET", f"/resources/{a}/dependencies")
        self.assertEqual(deps["dependencies"], [c])

    def test_missing_start_resource_returns_resource_not_found(self) -> None:
        b = self._create("b", DIGEST_B)
        phantom = "0" * 32

        status, _h, body = self._delete(phantom, b)
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

        _s, _h, listing = call_json("GET", "/resources")
        self.assertEqual(len(listing["resources"]), 1)

    def test_edge_to_deregistered_dependency_returns_dependency_not_found(
        self,
    ) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        self._add(a, b)
        # Deregistering b cascades its edges away.
        status, _h, _b = call("DELETE", f"/resources/{b}")
        self.assertEqual(status, "200 OK")

        status, _h, body = self._delete(a, b)
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "dependency_not_found")

    # --- Validation ---------------------------------------------------------

    def test_empty_dependency_segment_is_bad_request(self) -> None:
        a = self._create("a", DIGEST_A)
        status, _h, body = call_json(
            "DELETE", f"/resources/{a}/dependencies/"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_separator_in_dependency_id_is_bad_request(self) -> None:
        a = self._create("a", DIGEST_A)
        for raw_id in ("x/y", "x\\y"):
            status, _h, body = call_json(
                "DELETE", f"/resources/{a}/dependencies/{raw_id}"
            )
            self.assertEqual(status, "400 Bad Request")
            self.assertEqual(body["error"], "invalid_request")

    def test_separator_in_start_id_is_bad_request(self) -> None:
        b = self._create("b", DIGEST_B)
        status, _h, body = call_json(
            "DELETE", f"/resources/a/x/dependencies/{b}"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_query_parameters_are_rejected(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        self._add(a, b)
        status, _h, body = call_json(
            "DELETE",
            f"/resources/{a}/dependencies/{b}",
            query_string="x=1",
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

        # The edge survives the rejected request.
        _s, _h, deps = call_json("GET", f"/resources/{a}/dependencies")
        self.assertEqual(deps["dependencies"], [b])

    def test_declared_non_empty_body_is_rejected(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        self._add(a, b)
        status, _h, body = call_json(
            "DELETE", f"/resources/{a}/dependencies/{b}", b"{}"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

        _s, _h, deps = call_json("GET", f"/resources/{a}/dependencies")
        self.assertEqual(deps["dependencies"], [b])

    def test_explicit_zero_length_body_is_accepted(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        self._add(a, b)
        status, _h, body = call_json(
            "DELETE", f"/resources/{a}/dependencies/{b}", b""
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, {"resource_id": a, "dependency_id": b})

    # --- Method handling ----------------------------------------------------

    def test_other_methods_return_405_with_allow_header(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        for method in ("GET", "POST", "PUT", "PATCH"):
            status, headers, body = call_json(
                method, f"/resources/{a}/dependencies/{b}"
            )
            self.assertEqual(status, "405 Method Not Allowed")
            self.assertEqual(body["error"], "method_not_allowed")
            self.assertIn(("Allow", "DELETE"), headers)

    def test_collection_still_rejects_delete(self) -> None:
        a = self._create("a", DIGEST_A)
        status, headers, body = call_json(
            "DELETE", f"/resources/{a}/dependencies"
        )
        self.assertEqual(status, "405 Method Not Allowed")
        self.assertEqual(body["error"], "method_not_allowed")
        self.assertIn(("Allow", "GET, POST"), headers)

    # --- Listing order and cursors -----------------------------------------

    def test_listing_order_and_cursors_survive_delete(self) -> None:
        ids = [
            self._create(f"r{i}", f"{chr(ord('a') + i)}" * 64)
            for i in range(4)
        ]
        self._add(ids[0], ids[1])

        status, _h, first_page = call_json(
            "GET", "/resources", query_string="limit=2"
        )
        self.assertEqual(status, "200 OK")
        cursor = first_page["next_cursor"]
        self.assertEqual([r["id"] for r in first_page["resources"]], ids[:2])

        self._delete(ids[0], ids[1])

        status, _h, second_page = call_json(
            "GET", "/resources", query_string=f"limit=2&cursor={cursor}"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            [r["id"] for r in second_page["resources"]], ids[2:]
        )

        _s, _h, full = call_json("GET", "/resources")
        self.assertEqual([r["id"] for r in full["resources"]], ids)


class CrossReferenceEdgeDeleteTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def _local(self) -> str:
        _s, _h, body = call_json(
            "POST",
            "/resources",
            {"name": "local-a", "category": "code", "digest": "1" * 64},
        )
        return str(body["id"])

    def test_cross_reference_edge_is_removed_but_record_remains(self) -> None:
        from unittest import mock

        resource_id = self._local()
        resolution = Resolution(
            name=REMOTE_NAME,
            category="model",
            digest=DIGEST_REMOTE,
            source=SOURCE,
            raw=b"{}",
        )
        reference_body = {
            "repository": "partner",
            "upstream": UPSTREAM,
            "remote_id": REMOTE_ID,
            "digest": DIGEST_REMOTE,
        }
        with mock.patch(
            "provenance_api.app.resolve_remote", return_value=resolution
        ):
            status, _h, _b = call_json(
                "POST",
                f"/resources/{resource_id}/cross-references",
                reference_body,
            )
        self.assertEqual(status, "201 Created")

        _s, _h, listing = call_json("GET", "/resources")
        self.assertEqual(len(listing["resources"]), 2)
        remote_id = next(
            r["id"] for r in listing["resources"] if r["id"] != resource_id
        )

        # The edge participates in the topology before deletion.
        _s, _h, deps = call_json(
            "GET", f"/resources/{resource_id}/dependencies"
        )
        self.assertEqual(deps["dependencies"], [remote_id])

        status, _h, body = call_json(
            "DELETE",
            f"/resources/{resource_id}/dependencies/{remote_id}",
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            body, {"resource_id": resource_id, "dependency_id": remote_id}
        )

        # The reference record and the resolved local resource are untouched.
        _s, _h, refs = call_json(
            "GET", f"/resources/{resource_id}/cross-references"
        )
        self.assertEqual(len(refs["cross_references"]), 1)
        _s, _h, listing = call_json("GET", "/resources")
        self.assertEqual(len(listing["resources"]), 2)

        # The edge is gone from every graph view.
        _s, _h, deps = call_json(
            "GET", f"/resources/{resource_id}/dependencies"
        )
        self.assertEqual(deps["dependencies"], [])
        _s, _h, impact = call_json(
            "GET", f"/resources/{remote_id}/impact"
        )
        self.assertEqual(impact["resources"], [])

        # Re-submitting the same reference is still rejected as a duplicate
        # reference and does not rebuild the edge.
        with mock.patch(
            "provenance_api.app.resolve_remote", return_value=resolution
        ):
            status, _h, body = call_json(
                "POST",
                f"/resources/{resource_id}/cross-references",
                reference_body,
            )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "duplicate_reference")
        _s, _h, deps = call_json(
            "GET", f"/resources/{resource_id}/dependencies"
        )
        self.assertEqual(deps["dependencies"], [])


if __name__ == "__main__":
    unittest.main()
