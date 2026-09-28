from __future__ import annotations

import io
import json
import unittest
from unittest import mock

from provenance_api.app import application, reset_state

UPSTREAM = "https://repo.example.invalid"
REMOTE_ID = "remote-42"
REMOTE_NAME = "remote-model"
REMOTE_CATEGORY = "Model"
DIGEST = "a" * 64
SOURCE = "https://repo.example.invalid/sources/remote-42"

REFERENCE_BODY = {
    "repository": "partner",
    "upstream": UPSTREAM,
    "remote_id": REMOTE_ID,
    "digest": DIGEST,
}

FIVE_FIELDS = ["resource_id", "repository", "upstream", "remote_id", "digest"]


def call(
    method: str,
    path: str,
    body: bytes = b"",
    *,
    headers: dict[str, str] | None = None,
    query_string: str | None = None,
    omit_content_length: bool = False,
) -> tuple[str, list[tuple[str, str]], bytes]:
    environ: dict[str, object] = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "wsgi.input": io.BytesIO(body),
    }
    if not omit_content_length:
        environ["CONTENT_LENGTH"] = str(len(body))
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
    body: bytes = b"",
    **kwargs: object,
) -> tuple[str, list[tuple[str, str]], dict[str, object]]:
    status, headers, raw = call(method, path, body, **kwargs)  # type: ignore[arg-type]
    return status, headers, json.loads(raw.decode("utf-8"))


def register_local(
    name: str = "local-a",
    category: str = "code",
    digest: str = "b" * 64,
    source: str | None = None,
) -> str:
    payload: dict[str, object] = {
        "name": name,
        "category": category,
        "digest": digest,
    }
    if source is not None:
        payload["source"] = source
    status, _h, body = call_json(
        "POST",
        "/resources",
        json.dumps(payload).encode("utf-8"),
        headers={"CONTENT_TYPE": "application/json"},
    )
    assert status == "201 Created", (status, body)
    return str(body["id"])


def patch_resolve(
    *,
    name: str = REMOTE_NAME,
    category: str = REMOTE_CATEGORY,
    digest: str = DIGEST,
    source: str = SOURCE,
):
    from provenance_api.cross_references import Resolution

    resolution = Resolution(
        name=name,
        category=category.lower(),
        digest=digest.lower(),
        source=source,
        raw=json.dumps(
            {
                "name": name,
                "category": category,
                "digest": digest,
                "source": source,
            },
            separators=(",", ":"),
        ).encode("utf-8"),
    )
    return mock.patch(
        "provenance_api.app.resolve_remote", return_value=resolution
    )


def post_reference(resource_id: str, body: object = None):
    payload = REFERENCE_BODY if body is None else body
    return call_json(
        "POST",
        f"/resources/{resource_id}/cross-references",
        json.dumps(payload).encode("utf-8"),
        headers={"CONTENT_TYPE": "application/json"},
    )


def delete_reference(
    resource_id: str,
    repository: str = "partner",
    remote_id: str = REMOTE_ID,
    **kwargs: object,
):
    return call_json(
        "DELETE",
        f"/resources/{resource_id}/cross-references/{repository}/{remote_id}",
        **kwargs,
    )


def reference_path(repository: str, remote_id: str) -> str:
    return f"/cross-references/{repository}/{remote_id}"


def register_one() -> tuple[str, str]:
    """Register a local resource plus one reference; return (start, local)."""
    resource_id = register_local()
    with patch_resolve():
        status, _h, body = post_reference(resource_id)
    assert status == "201 Created", (status, body)
    resources = call_json("GET", "/resources")[2]["resources"]
    local_id = next(r["id"] for r in resources if r["id"] != resource_id)
    return resource_id, str(local_id)


class CrossReferenceDeleteSuccessTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def test_delete_returns_200_and_echoes_five_fields_in_order(self) -> None:
        resource_id, _local_id = register_one()
        status, headers, raw = call(
            "DELETE",
            f"/resources/{resource_id}"
            + reference_path("partner", REMOTE_ID),
        )
        self.assertEqual(status, "200 OK")
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )
        body = json.loads(raw)
        self.assertEqual(list(body), FIVE_FIELDS)
        self.assertEqual(body["resource_id"], resource_id)
        self.assertEqual(body["repository"], "partner")
        self.assertEqual(body["upstream"], UPSTREAM)
        self.assertEqual(body["remote_id"], REMOTE_ID)
        self.assertEqual(body["digest"], DIGEST)
        # Compact JSON ending in exactly one newline.
        self.assertEqual(
            raw,
            (
                json.dumps(body, separators=(",", ":"), ensure_ascii=False)
            ).encode("utf-8") + b"\n",
        )
        self.assertEqual(raw.count(b"\n"), 1)

    def test_delete_removes_only_the_reference_record(self) -> None:
        resource_id, local_id = register_one()
        status, _h, _b = delete_reference(resource_id)
        self.assertEqual(status, "200 OK")

        # Gone from the per-resource listing.
        status, _h, listing = call_json(
            "GET", f"/resources/{resource_id}/cross-references"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(listing["cross_references"], [])

        # Gone, wholesale, from the global summary.
        status, _h, summary = call_json("GET", "/")
        self.assertEqual(status, "200 OK")
        self.assertEqual(summary, [])

    def test_delete_keeps_resolved_resource_and_edge(self) -> None:
        resource_id, local_id = register_one()
        status, _h, _b = delete_reference(resource_id)
        self.assertEqual(status, "200 OK")

        # The resolved local resource survives.
        status, _h, resource = call_json("GET", f"/resources/{local_id}")
        self.assertEqual(status, "200 OK")
        self.assertEqual(resource["digest"], DIGEST)

        # The dependency edge survives in the dependency query.
        status, _h, deps = call_json(
            "GET", f"/resources/{resource_id}/dependencies"
        )
        self.assertEqual(deps["dependencies"], [local_id])

        # ... in the reverse impact view ...
        status, _h, impact = call_json(
            "GET", f"/resources/{local_id}/impact"
        )
        self.assertEqual(impact["resources"], [resource_id])

        # ... and in the graph view, with no reference record left behind.
        status, _h, graph = call_json("GET", "/graph")
        edge_ids = {
            (edge["resource_id"], edge["dependency_id"])
            for edge in graph["edges"]
        }
        self.assertIn((resource_id, local_id), edge_ids)
        self.assertEqual(call_json("GET", "/")[2], [])

    def test_deleting_one_reference_keeps_the_others(self) -> None:
        first, _local = register_one()
        second = register_local(name="second", digest="c" * 64)
        with patch_resolve(
            digest="d" * 64,
            name="second-remote",
            source="https://repo.example.invalid/second",
        ):
            status, _h, _b = post_reference(
                second,
                dict(REFERENCE_BODY, remote_id="remote-7", digest="d" * 64),
            )
        self.assertEqual(status, "201 Created")
        with patch_resolve(
            digest="e" * 64,
            name="third-remote",
            source="https://repo.example.invalid/third",
        ):
            status, _h, _b = post_reference(
                first,
                dict(REFERENCE_BODY, remote_id="remote-8", digest="e" * 64),
            )
        self.assertEqual(status, "201 Created")

        status, _h, _b = delete_reference(first)
        self.assertEqual(status, "200 OK")

        # The global summary is recomputed from the remaining records.
        status, _h, summary = call_json("GET", "/")
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            [(r["resource_id"], r["remote_id"]) for r in summary],
            [(second, "remote-7"), (first, "remote-8")],
        )
        # The first resource's listing lost only remote-42.
        status, _h, listing = call_json(
            "GET", f"/resources/{first}/cross-references"
        )
        self.assertEqual(
            [r["remote_id"] for r in listing["cross_references"]],
            ["remote-8"],
        )

    def test_delete_releases_repository_binding_and_pair(self) -> None:
        resource_id, _local_id = register_one()
        other = register_local(name="other", digest="c" * 64)

        status, _h, _b = delete_reference(resource_id)
        self.assertEqual(status, "200 OK")

        # The pair is free again; even a different upstream for the same
        # repository name is accepted, since deleting the last reference
        # released the binding.
        with patch_resolve():
            status, _h, body = post_reference(
                other,
                dict(REFERENCE_BODY, upstream="https://other.example.invalid"),
            )
        self.assertEqual(status, "201 Created", body)


class CrossReferenceDeleteReregistrationTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def test_reregister_same_pair_succeeds_201_with_retained_edge(self) -> None:
        resource_id, local_id = register_one()
        status, _h, _b = delete_reference(resource_id)
        self.assertEqual(status, "200 OK")

        # The edge is still present; re-registering re-adopts it rather than
        # failing with duplicate_dependency.
        with patch_resolve() as resolve:
            status, _h, body = post_reference(resource_id)
        self.assertEqual(status, "201 Created", body)
        resolve.assert_called_once_with(UPSTREAM, REMOTE_ID, DIGEST)
        self.assertEqual(list(body), FIVE_FIELDS)
        self.assertEqual(body["resource_id"], resource_id)

        status, _h, summary = call_json("GET", "/")
        self.assertEqual(len(summary), 1)
        self.assertEqual(summary[0]["local_id"], local_id)
        self.assertIs(summary[0]["edge_present"], True)

        # Still a single direct edge, not a duplicated one.
        status, _h, deps = call_json(
            "GET", f"/resources/{resource_id}/dependencies"
        )
        self.assertEqual(deps["dependencies"], [local_id])

    def test_reregister_after_edge_was_also_removed_succeeds_201(self) -> None:
        resource_id, local_id = register_one()
        status, _h, _b = delete_reference(resource_id)
        self.assertEqual(status, "200 OK")
        status, _h, _b = call(
            "DELETE",
            f"/resources/{resource_id}/dependencies/{local_id}",
        )
        self.assertEqual(status, "200 OK")

        with patch_resolve():
            status, _h, body = post_reference(resource_id)
        self.assertEqual(status, "201 Created", body)
        status, _h, deps = call_json(
            "GET", f"/resources/{resource_id}/dependencies"
        )
        self.assertEqual(deps["dependencies"], [local_id])

    def test_unrelated_existing_edge_still_conflicts(self) -> None:
        # A retained edge does not relax duplicate detection for a different
        # reference that resolves to the same local resource.
        resource_id, _local_id = register_one()
        status, _h, _b = delete_reference(resource_id)
        self.assertEqual(status, "200 OK")
        with patch_resolve():
            status, _h, body = post_reference(
                resource_id,
                dict(REFERENCE_BODY, remote_id="remote-99"),
            )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "duplicate_dependency")


class CrossReferenceDeleteNotFoundTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def test_unknown_reference_returns_404(self) -> None:
        resource_id, _local_id = register_one()
        status, _h, body = delete_reference(resource_id, remote_id="missing")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "reference_not_found")
        self.assertEqual(set(body), {"error", "message"})

    def test_unknown_repository_returns_404(self) -> None:
        resource_id, _local_id = register_one()
        status, _h, body = delete_reference(resource_id, repository="elsewhere")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "reference_not_found")

    def test_repeat_delete_is_consistent(self) -> None:
        resource_id, _local_id = register_one()
        status, _h, first = delete_reference(resource_id)
        self.assertEqual(status, "200 OK")
        # Every subsequent delete answers identically: 404 reference_not_found.
        status, _h, second = delete_reference(resource_id)
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(second["error"], "reference_not_found")
        status, _h, third = delete_reference(resource_id)
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(third["error"], "reference_not_found")

    def test_missing_resource_precedes_reference_lookup(self) -> None:
        register_one()
        # A resource that does not exist names a reference that also does
        # not; resource_not_found must win.
        status, _h, body = call_json(
            "DELETE",
            "/resources/missing" + reference_path("partner", REMOTE_ID),
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

    def test_deleted_reference_does_not_match_other_resource(self) -> None:
        resource_id, _local_id = register_one()
        other = register_local(name="other", digest="c" * 64)
        status, _h, _b = delete_reference(resource_id)
        self.assertEqual(status, "200 OK")
        status, _h, body = delete_reference(other)
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "reference_not_found")


class CrossReferenceDeleteRequestValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.resource_id, self.local_id = register_one()
        self.item_path = (
            f"/resources/{self.resource_id}"
            + reference_path("partner", REMOTE_ID)
        )

    def _assert_reference_still_present(self) -> None:
        status, _h, summary = call_json("GET", "/")
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(summary), 1)

    def test_empty_path_segments_return_400(self) -> None:
        paths = [
            f"/resources/{self.resource_id}/cross-references//remote-42",
            f"/resources/{self.resource_id}/cross-references/partner/",
            f"/resources/{self.resource_id}/cross-references/",
        ]
        for path in paths:
            with self.subTest(path=path):
                status, _h, body = call_json("DELETE", path)
                self.assertEqual(status, "400 Bad Request", path)
                self.assertEqual(body["error"], "invalid_request")
        self._assert_reference_still_present()

    def test_separator_segments_return_400(self) -> None:
        paths = [
            # A literal slash splits the segment.
            f"/resources/{self.resource_id}/cross-references/partner/a/b",
            f"/resources/{self.resource_id}/cross-references/a%2Fb/remote-42",
            f"/resources/{self.resource_id}/cross-references/a%5Cb/remote-42",
            f"/resources/{self.resource_id}/cross-references/partner/a%2Fb",
            f"/resources/{self.resource_id}/cross-references/partner/a%5Cb",
            f"/resources/{self.resource_id}/cross-references/a/b/remote-42",
        ]
        for path in paths:
            with self.subTest(path=path):
                status, _h, body = call_json("DELETE", path)
                self.assertEqual(status, "400 Bad Request", path)
                self.assertEqual(body["error"], "invalid_request")
        self._assert_reference_still_present()

    def test_percent_decoded_segment_matches_verbatim(self) -> None:
        # A space in a stored remote id is addressed percent-encoded; the
        # decoded segment must match the stored value character for
        # character.
        resource_id = register_local(name="spaced", digest="c" * 64)
        with patch_resolve():
            status, _h, _b = post_reference(
                resource_id, dict(REFERENCE_BODY, remote_id="a b")
            )
        self.assertEqual(status, "201 Created")
        status, _h, body = call_json(
            "DELETE",
            f"/resources/{resource_id}/cross-references/partner/a%20b",
        )
        self.assertEqual(status, "200 OK", body)
        self.assertEqual(body["remote_id"], "a b")
        # An undecoded literal must not match the stored value.
        resource_id2 = register_local(name="spaced2", digest="d" * 64)
        with patch_resolve():
            status, _h, _b = post_reference(
                resource_id2, dict(REFERENCE_BODY, remote_id="a%20b")
            )
        self.assertEqual(status, "201 Created")
        status, _h, body = call_json(
            "DELETE",
            f"/resources/{resource_id2}/cross-references/partner/a%2520b",
        )
        self.assertEqual(status, "200 OK", body)
        self.assertEqual(body["remote_id"], "a%20b")

    def test_malformed_resource_id_returns_400(self) -> None:
        for path in (
            "/resources//cross-references/partner/remote-42",
            "/resources/a/b/cross-references/partner/remote-42",
        ):
            with self.subTest(path=path):
                status, _h, body = call_json("DELETE", path)
                self.assertEqual(status, "400 Bad Request", path)
                self.assertEqual(body["error"], "invalid_request")
        self._assert_reference_still_present()

    def test_query_parameters_return_400(self) -> None:
        for query in ("x=1", "x=", "a=b&c=d"):
            with self.subTest(query=query):
                status, _h, body = call_json(
                    "DELETE", self.item_path, query_string=query
                )
                self.assertEqual(status, "400 Bad Request", query)
                self.assertEqual(body["error"], "invalid_request")
        self._assert_reference_still_present()

    def test_declared_non_empty_body_returns_400(self) -> None:
        status, _h, body = call(
            "DELETE", self.item_path, b"x"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(json.loads(body)["error"], "invalid_request")
        self._assert_reference_still_present()

    def test_malformed_content_length_returns_400(self) -> None:
        status, _h, body = call(
            "DELETE",
            self.item_path,
            headers={"CONTENT_LENGTH": "abc"},
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(json.loads(body)["error"], "invalid_request")
        self._assert_reference_still_present()

    def test_empty_bodies_are_accepted(self) -> None:
        # Explicit zero length.
        status, _h, _b = call(
            "DELETE",
            self.item_path,
            headers={"CONTENT_LENGTH": "0"},
        )
        self.assertEqual(status, "200 OK")
        # The reference is gone, so an omitted header on a repeat delete is a
        # well-shaped 404 rather than a 400.
        status, _h, body = call_json(
            "DELETE", self.item_path, omit_content_length=True
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "reference_not_found")
        status, _h, body = call_json(
            "DELETE",
            self.item_path,
            headers={"CONTENT_LENGTH": ""},
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "reference_not_found")


class CrossReferenceDeleteMethodTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.resource_id, _local_id = register_one()
        self.item_path = (
            f"/resources/{self.resource_id}"
            + reference_path("partner", REMOTE_ID)
        )

    def test_only_delete_is_allowed(self) -> None:
        for method in ("GET", "POST", "PUT", "PATCH", "HEAD"):
            with self.subTest(method=method):
                status, headers, body = call_json(method, self.item_path)
                self.assertEqual(status, "405 Method Not Allowed", method)
                allow = [value for key, value in headers if key == "Allow"]
                self.assertEqual(allow, ["DELETE"])
                self.assertEqual(body["error"], "method_not_allowed")

    def test_non_delete_with_query_still_returns_405(self) -> None:
        # Method is decided before the request shape is examined.
        status, headers, body = call_json(
            "GET", self.item_path, query_string="x=1"
        )
        self.assertEqual(status, "405 Method Not Allowed")
        self.assertIn(("Allow", "DELETE"), headers)
        self.assertEqual(body["error"], "method_not_allowed")

    def test_non_delete_does_not_delete(self) -> None:
        status, _h, _b = call_json("POST", self.item_path)
        self.assertEqual(status, "405 Method Not Allowed")
        status, _h, summary = call_json("GET", "/")
        self.assertEqual(len(summary), 1)


if __name__ == "__main__":
    unittest.main()
