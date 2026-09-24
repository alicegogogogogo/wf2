from __future__ import annotations

import hashlib
import io
import json
import unittest
from unittest import mock

from provenance_api.app import application, cache_store, reset_state
from provenance_api.cross_references import (
    CrossReferenceError,
    Resolution,
    build_cross_reference_fields,
    fetch_remote_resource,
    parse_remote_metadata,
    resolve_remote,
)

UPSTREAM = "https://repo.example.invalid"
UPSTREAM_SLASH = UPSTREAM + "/"
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


def call(
    method: str,
    path: str,
    body: bytes = b"",
    *,
    headers: dict[str, str] | None = None,
    query_string: str | None = None,
) -> tuple[str, list[tuple[str, str]], bytes]:
    environ: dict[str, object] = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "CONTENT_LENGTH": str(len(body)),
        "wsgi.input": io.BytesIO(body),
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


def remote_metadata(
    *,
    name: str = REMOTE_NAME,
    category: str = REMOTE_CATEGORY,
    digest: str = DIGEST,
    source: str = SOURCE,
) -> tuple[dict[str, object], bytes]:
    payload = {
        "name": name,
        "category": category,
        "digest": digest,
        "source": source,
    }
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return payload, raw


def patch_resolve(
    *,
    name: str = REMOTE_NAME,
    category: str = REMOTE_CATEGORY,
    digest: str = DIGEST,
    source: str = SOURCE,
    raw: bytes | None = None,
    error: CrossReferenceError | None = None,
):
    if error is not None:
        return mock.patch(
            "provenance_api.app.resolve_remote", side_effect=error
        )
    if raw is None:
        raw = json.dumps(
            {
                "name": name,
                "category": category,
                "digest": digest,
                "source": source,
            },
            separators=(",", ":"),
        ).encode("utf-8")
    resolution = Resolution(
        name=name,
        category=category.lower(),
        digest=digest.lower(),
        source=source,
        raw=raw,
    )
    return mock.patch(
        "provenance_api.app.resolve_remote", return_value=resolution
    )


def post_reference(
    resource_id: str,
    body: object = None,
    *,
    query_string: str | None = None,
):
    payload = REFERENCE_BODY if body is None else body
    return call_json(
        "POST",
        f"/resources/{resource_id}/cross-references",
        json.dumps(payload).encode("utf-8"),
        headers={"CONTENT_TYPE": "application/json"},
        query_string=query_string,
    )


def list_references(resource_id: str):
    return call_json(
        "GET", f"/resources/{resource_id}/cross-references"
    )


class CrossReferenceRegistrationTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def test_success_returns_201_and_echoes_five_keys(self) -> None:
        resource_id = register_local()
        with patch_resolve() as resolve:
            status, headers, body = post_reference(resource_id)
        self.assertEqual(status, "201 Created")
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )
        self.assertEqual(
            list(body),
            ["resource_id", "repository", "upstream", "remote_id", "digest"],
        )
        self.assertEqual(body["resource_id"], resource_id)
        self.assertEqual(body["repository"], "partner")
        self.assertEqual(body["upstream"], UPSTREAM)
        self.assertEqual(body["remote_id"], REMOTE_ID)
        self.assertEqual(body["digest"], DIGEST)
        resolve.assert_called_once_with(UPSTREAM, REMOTE_ID, DIGEST)

    def test_digest_is_normalized_to_lowercase(self) -> None:
        resource_id = register_local()
        body = dict(REFERENCE_BODY, digest=DIGEST.upper())
        with patch_resolve() as resolve:
            status, _h, response = post_reference(resource_id, body)
        self.assertEqual(status, "201 Created")
        self.assertEqual(response["digest"], DIGEST)
        resolve.assert_called_once_with(UPSTREAM, REMOTE_ID, DIGEST)

    def test_success_caches_remote_metadata_bytes_under_digest(self) -> None:
        resource_id = register_local()
        _payload, raw = remote_metadata()
        with patch_resolve(raw=raw):
            status, _h, _body = post_reference(resource_id)
        self.assertEqual(status, "201 Created")
        status, _h, cached = call("GET", f"/cache/layers/{DIGEST}")
        self.assertEqual(status, "200 OK")
        self.assertEqual(cached, raw)

    def test_success_creates_local_resource_and_edge(self) -> None:
        resource_id = register_local()
        with patch_resolve():
            status, _h, _body = post_reference(resource_id)
        self.assertEqual(status, "201 Created")

        status, _h, listing = call_json("GET", "/resources")
        resources = listing["resources"]
        self.assertEqual(len(resources), 2)
        created = next(r for r in resources if r["id"] != resource_id)
        self.assertEqual(created["name"], REMOTE_NAME)
        self.assertEqual(created["category"], "model")
        self.assertEqual(created["digest"], DIGEST)
        self.assertEqual(created["source"], SOURCE)

        status, _h, deps = call_json(
            "GET", f"/resources/{resource_id}/dependencies"
        )
        self.assertEqual(deps["dependencies"], [created["id"]])
        status, _h, impact = call_json(
            "GET", f"/resources/{created['id']}/impact"
        )
        self.assertEqual(impact["resources"], [resource_id])

    def test_resolved_edges_participate_in_topology_in_registration_order(
        self,
    ) -> None:
        # One dependent resolves two remote resources from two different
        # repositories; the resolved edges take part in the topology and
        # are ordered by resource registration order.
        dependent = register_local(name="root", digest="1" * 64)
        with patch_resolve():
            status, _h, _b = post_reference(dependent)
        self.assertEqual(status, "201 Created")
        second_body = dict(
            REFERENCE_BODY,
            repository="other-partner",
            remote_id="remote-7",
            digest="d" * 64,
        )
        with patch_resolve(
            digest="d" * 64,
            name="other-remote",
            source="https://repo.example.invalid/other",
        ):
            status, _h, _b = post_reference(dependent, second_body)
        self.assertEqual(status, "201 Created")

        status, _h, listing = call_json("GET", "/resources")
        resources = listing["resources"]
        self.assertEqual(len(resources), 3)
        r1, r2 = resources[1], resources[2]
        self.assertEqual((r1["digest"], r2["digest"]), (DIGEST, "d" * 64))

        status, _h, deps = call_json(
            "GET", f"/resources/{dependent}/dependencies"
        )
        self.assertEqual(deps["dependencies"], [r1["id"], r2["id"]])
        for remote_id in (r1["id"], r2["id"]):
            status, _h, impact = call_json(
                "GET", f"/resources/{remote_id}/impact"
            )
            self.assertEqual(impact["resources"], [dependent])

    def test_reuses_identical_local_resource(self) -> None:
        existing_id = register_local(
            name=REMOTE_NAME, category=REMOTE_CATEGORY, digest=DIGEST,
            source=SOURCE,
        )
        dependent = register_local(name="dependent", digest="e" * 64)
        with patch_resolve() as resolve:
            status, _h, body = post_reference(dependent)
        self.assertEqual(status, "201 Created")
        resolve.assert_called_once()
        status, _h, listing = call_json("GET", "/resources")
        self.assertEqual(len(listing["resources"]), 2)
        status, _h, deps = call_json(
            "GET", f"/resources/{dependent}/dependencies"
        )
        self.assertEqual(deps["dependencies"], [existing_id])
        self.assertEqual(body["resource_id"], dependent)

    def test_reuse_ignores_source_difference(self) -> None:
        # Same digest, name and category but a different local source still
        # identifies the same resource.
        register_local(
            name=REMOTE_NAME,
            category=REMOTE_CATEGORY,
            digest=DIGEST,
            source="https://local.example/different",
        )
        dependent = register_local(name="dependent", digest="e" * 64)
        with patch_resolve():
            status, _h, _body = post_reference(dependent)
        self.assertEqual(status, "201 Created")
        status, _h, listing = call_json("GET", "/resources")
        self.assertEqual(len(listing["resources"]), 2)


class CrossReferenceConflictTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def test_repository_conflict_returns_409_without_fetching(self) -> None:
        first = register_local()
        second = register_local(name="second", digest="c" * 64)
        with patch_resolve():
            status, _h, _body = post_reference(first)
        self.assertEqual(status, "201 Created")
        body = dict(
            REFERENCE_BODY,
            upstream="https://other.example.invalid",
            remote_id="remote-99",
        )
        with patch_resolve(error=AssertionError("must not resolve")) as fetch:
            status, _h, response = post_reference(second, body)
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(response["error"], "repository_conflict")
        fetch.assert_not_called()
        status, _h, refs = list_references(second)
        self.assertEqual(refs["cross_references"], [])

    def test_duplicate_reference_returns_409_without_fetching(self) -> None:
        resource_id = register_local()
        with patch_resolve():
            status, _h, _body = post_reference(resource_id)
        self.assertEqual(status, "201 Created")
        with patch_resolve(error=AssertionError("must not resolve")) as fetch:
            status, _h, response = post_reference(resource_id)
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(response["error"], "duplicate_reference")
        fetch.assert_not_called()
        status, _h, refs = list_references(resource_id)
        self.assertEqual(len(refs["cross_references"]), 1)

    def test_same_repository_remote_id_elsewhere_is_also_duplicate(self) -> None:
        first = register_local()
        second = register_local(name="second", digest="c" * 64)
        with patch_resolve():
            status, _h, _b = post_reference(first)
        self.assertEqual(status, "201 Created")
        with patch_resolve(error=AssertionError("must not resolve")) as fetch:
            status, _h, response = post_reference(second)
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(response["error"], "duplicate_reference")
        fetch.assert_not_called()

    def test_identity_conflict_on_different_name(self) -> None:
        register_local(name="different-name", digest=DIGEST)
        resource_id = register_local(name="dependent", digest="e" * 64)
        with patch_resolve():
            status, _h, body = post_reference(resource_id)
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "identity_conflict")
        # No reference, no new resource, no edge, no cache entry.
        status, _h, refs = list_references(resource_id)
        self.assertEqual(refs["cross_references"], [])
        status, _h, listing = call_json("GET", "/resources")
        self.assertEqual(len(listing["resources"]), 2)
        status, _h, cached = call("GET", f"/cache/layers/{DIGEST}")
        self.assertEqual(status, "404 Not Found")

    def test_identity_conflict_on_different_category(self) -> None:
        register_local(
            name=REMOTE_NAME, category="dataset", digest=DIGEST
        )
        resource_id = register_local(name="dependent", digest="e" * 64)
        with patch_resolve():
            status, _h, body = post_reference(resource_id)
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "identity_conflict")

    def test_self_loop_returns_dependency_cycle(self) -> None:
        # The remote identity resolves to the dependent itself.
        resource_id = register_local(
            name=REMOTE_NAME, category=REMOTE_CATEGORY, digest=DIGEST
        )
        with patch_resolve():
            status, _h, body = post_reference(resource_id)
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "dependency_cycle")
        status, _h, refs = list_references(resource_id)
        self.assertEqual(refs["cross_references"], [])
        status, _h, cached = call("GET", f"/cache/layers/{DIGEST}")
        self.assertEqual(status, "404 Not Found")

    def test_would_be_cycle_returns_dependency_cycle(self) -> None:
        # B already depends on A; resolving B as a dependency of A would
        # close a cycle.
        a_id = register_local(name="a", digest="1" * 64)
        b_id = register_local(
            name=REMOTE_NAME, category=REMOTE_CATEGORY, digest=DIGEST
        )
        status, _h, _b = call_json(
            "POST",
            f"/resources/{b_id}/dependencies",
            json.dumps({"dependency_id": a_id}).encode("utf-8"),
            headers={"CONTENT_TYPE": "application/json"},
        )
        self.assertEqual(status, "201 Created")
        with patch_resolve():
            status, _h, body = post_reference(a_id)
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "dependency_cycle")
        status, _h, refs = list_references(a_id)
        self.assertEqual(refs["cross_references"], [])
        status, _h, listing = call_json("GET", "/resources")
        self.assertEqual(len(listing["resources"]), 2)

    def test_existing_same_direction_edge_returns_duplicate_dependency(
        self,
    ) -> None:
        dependent = register_local(name="a", digest="1" * 64)
        target = register_local(
            name=REMOTE_NAME, category=REMOTE_CATEGORY, digest=DIGEST
        )
        status, _h, _b = call_json(
            "POST",
            f"/resources/{dependent}/dependencies",
            json.dumps({"dependency_id": target}).encode("utf-8"),
            headers={"CONTENT_TYPE": "application/json"},
        )
        self.assertEqual(status, "201 Created")
        with patch_resolve():
            status, _h, body = post_reference(dependent)
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "duplicate_dependency")
        status, _h, refs = list_references(dependent)
        self.assertEqual(refs["cross_references"], [])

    def test_indirectly_reachable_edge_is_still_created(self) -> None:
        # Mirrors manual dependency semantics: an edge to an already
        # indirectly reachable resource is not a duplicate.
        a_id = register_local(name="a", digest="1" * 64)
        b_id = register_local(name="b", digest="2" * 64)
        status, _h, _b = call_json(
            "POST",
            f"/resources/{a_id}/dependencies",
            json.dumps({"dependency_id": b_id}).encode("utf-8"),
            headers={"CONTENT_TYPE": "application/json"},
        )
        self.assertEqual(status, "201 Created")
        with patch_resolve():
            body = dict(REFERENCE_BODY, digest=DIGEST)
            status, _h, _b = post_reference(b_id, body)
        self.assertEqual(status, "201 Created")
        # a -> b -> remote, so the remote is transitively reachable from a
        # without an a -> remote edge yet.
        status, _h, deps = call_json(
            "GET", f"/resources/{a_id}/dependencies"
        )
        self.assertIn(
            call_json("GET", "/resources")[2]["resources"][-1]["id"],
            deps["dependencies"],
        )

    def test_cache_conflict_returns_409_and_changes_nothing(self) -> None:
        resource_id = register_local()
        other_bytes = b"different cached bytes"
        other_digest = hashlib.sha256(other_bytes).hexdigest()
        status, _h, _raw = call(
            "POST",
            f"/cache/layers/{other_digest}",
            other_bytes,
            headers={"CONTENT_TYPE": "application/octet-stream"},
        )
        self.assertEqual(status, "201 Created")
        _payload, raw = remote_metadata(digest=other_digest)
        with patch_resolve(raw=raw, digest=other_digest):
            body = dict(REFERENCE_BODY, digest=other_digest)
            status, _h, response = post_reference(resource_id, body)
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(response["error"], "cache_conflict")
        status, _h, refs = list_references(resource_id)
        self.assertEqual(refs["cross_references"], [])
        status, _h, listing = call_json("GET", "/resources")
        self.assertEqual(len(listing["resources"]), 1)
        status, _h, deps = call_json(
            "GET", f"/resources/{resource_id}/dependencies"
        )
        self.assertEqual(deps["dependencies"], [])

    def test_same_cached_bytes_are_idempotent(self) -> None:
        resource_id = register_local()
        _payload, raw = remote_metadata()
        # The metadata cache is content-addressed by the verified resource
        # digest, so seed it the same way the resolution path does rather
        # than through the digest-checking layer upload.
        cache_store.put_verified(DIGEST, raw)
        with patch_resolve(raw=raw):
            status, _h, _body = post_reference(resource_id)
        self.assertEqual(status, "201 Created")
        status, _h, cached = call("GET", f"/cache/layers/{DIGEST}")
        self.assertEqual(status, "200 OK")
        self.assertEqual(cached, raw)

    def test_cache_quota_exceeded_returns_409_and_changes_nothing(self) -> None:
        resource_id = register_local()
        cache_store.configure(1)
        try:
            with patch_resolve():
                status, _h, body = post_reference(resource_id)
            self.assertEqual(status, "409 Conflict")
            self.assertEqual(body["error"], "cache_quota_exceeded")
            status, _h, refs = list_references(resource_id)
            self.assertEqual(refs["cross_references"], [])
            status, _h, listing = call_json("GET", "/resources")
            self.assertEqual(len(listing["resources"]), 1)
        finally:
            cache_store.reset()


class CrossReferenceRemoteErrorTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def _assert_unchanged(self, resource_id: str) -> None:
        status, _h, refs = list_references(resource_id)
        self.assertEqual(refs["cross_references"], [])
        status, _h, listing = call_json("GET", "/resources")
        self.assertEqual(len(listing["resources"]), 1)
        status, _h, deps = call_json(
            "GET", f"/resources/{resource_id}/dependencies"
        )
        self.assertEqual(deps["dependencies"], [])
        status, _h, cached = call("GET", f"/cache/layers/{DIGEST}")
        self.assertEqual(status, "404 Not Found")

    def test_remote_unreachable_returns_502(self) -> None:
        resource_id = register_local()
        error = CrossReferenceError(
            "remote_unreachable", "x", http_status=502
        )
        with patch_resolve(error=error):
            status, _h, body = post_reference(resource_id)
        self.assertEqual(status, "502 Bad Gateway")
        self.assertEqual(body["error"], "remote_unreachable")
        self._assert_unchanged(resource_id)

    def test_resolution_failed_returns_502(self) -> None:
        resource_id = register_local()
        error = CrossReferenceError(
            "resolution_failed", "x", http_status=502
        )
        with patch_resolve(error=error):
            status, _h, body = post_reference(resource_id)
        self.assertEqual(status, "502 Bad Gateway")
        self.assertEqual(body["error"], "resolution_failed")
        self._assert_unchanged(resource_id)

    def test_remote_digest_mismatch_returns_502(self) -> None:
        resource_id = register_local()
        error = CrossReferenceError(
            "remote_digest_mismatch", "x", http_status=502
        )
        with patch_resolve(error=error):
            status, _h, body = post_reference(resource_id)
        self.assertEqual(status, "502 Bad Gateway")
        self.assertEqual(body["error"], "remote_digest_mismatch")
        self._assert_unchanged(resource_id)


class CrossReferenceRequestValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.resource_id = register_local()

    def _assert_rejected_without_fetch(self, payload: object) -> None:
        with patch_resolve(error=AssertionError("must not resolve")) as fetch:
            status, _h, body = post_reference(self.resource_id, payload)
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        fetch.assert_not_called()

    def test_empty_body_returns_400(self) -> None:
        status, _h, body = call_json(
            "POST", f"/resources/{self.resource_id}/cross-references"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_bad_json_returns_400(self) -> None:
        status, _h, body = call_json(
            "POST",
            f"/resources/{self.resource_id}/cross-references",
            b"{not json",
            headers={"CONTENT_TYPE": "application/json"},
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_non_object_top_level_returns_400(self) -> None:
        for payload in (b"[1,2]", b'"x"', b"42", b"null"):
            status, _h, body = call_json(
                "POST",
                f"/resources/{self.resource_id}/cross-references",
                payload,
                headers={"CONTENT_TYPE": "application/json"},
            )
            self.assertEqual(status, "400 Bad Request", payload)
            self.assertEqual(body["error"], "invalid_request")

    def test_field_errors_return_400(self) -> None:
        valid = dict(REFERENCE_BODY)
        cases = [
            {},
            {"repository": "partner"},
            {k: v for k, v in valid.items() if k != "digest"},
            dict(valid, extra=1),
            dict(valid, repository=""),
            dict(valid, repository="   "),
            dict(valid, repository=123),
            dict(valid, repository=None),
            dict(valid, upstream=""),
            dict(valid, upstream=42),
            dict(valid, upstream=None),
            dict(valid, upstream="ftp://repo.example.invalid"),
            dict(valid, upstream="example.invalid/path"),
            dict(valid, upstream="/just/a/path"),
            dict(valid, upstream="http://"),
            dict(valid, remote_id=""),
            dict(valid, remote_id=7),
            dict(valid, remote_id=None),
            dict(valid, remote_id="a/b"),
            dict(valid, remote_id="a\\b"),
            dict(valid, digest=""),
            dict(valid, digest=123),
            dict(valid, digest=None),
            dict(valid, digest="z" * 64),
            dict(valid, digest="a" * 63),
        ]
        for payload in cases:
            self._assert_rejected_without_fetch(payload)

    def test_query_parameters_return_400(self) -> None:
        with patch_resolve(error=AssertionError("must not resolve")) as fetch:
            status, _h, body = post_reference(
                self.resource_id, query_string="x=1"
            )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        fetch.assert_not_called()

    def test_unknown_resource_returns_404_without_fetching(self) -> None:
        with patch_resolve(error=AssertionError("must not resolve")) as fetch:
            status, _h, body = post_reference("missing")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")
        fetch.assert_not_called()

    def test_invalid_path_id_returns_400(self) -> None:
        for path in (
            "/resources//cross-references",
            "/resources/a/b/cross-references",
        ):
            status, _h, body = call_json(
                "POST",
                path,
                json.dumps(REFERENCE_BODY).encode("utf-8"),
                headers={"CONTENT_TYPE": "application/json"},
            )
            self.assertEqual(status, "400 Bad Request", path)
            self.assertEqual(body["error"], "invalid_request")

    def test_method_not_allowed_has_allow_header(self) -> None:
        for method in ("PUT", "DELETE", "PATCH"):
            status, headers, body = call_json(
                method, f"/resources/{self.resource_id}/cross-references"
            )
            self.assertEqual(status, "405 Method Not Allowed")
            self.assertIn(("Allow", "GET, POST"), headers)
            self.assertEqual(body["error"], "method_not_allowed")


class CrossReferenceListTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def test_empty_list(self) -> None:
        resource_id = register_local()
        status, _h, body = list_references(resource_id)
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, {"cross_references": []})

    def test_list_is_per_resource_and_registration_ordered(self) -> None:
        first = register_local(name="first")
        second = register_local(name="second", digest="c" * 64)
        with patch_resolve():
            status, _h, one = post_reference(first)
        self.assertEqual(status, "201 Created")
        with patch_resolve(
            digest="d" * 64,
            name="second-remote",
            source="https://repo.example.invalid/second",
        ):
            body = dict(REFERENCE_BODY, remote_id="remote-7", digest="d" * 64)
            status, _h, two = post_reference(second, body)
        self.assertEqual(status, "201 Created")
        with patch_resolve(
            digest="e" * 64,
            name="third-remote",
            source="https://repo.example.invalid/third",
        ):
            body = dict(REFERENCE_BODY, remote_id="remote-8", digest="e" * 64)
            status, _h, three = post_reference(first, body)
        self.assertEqual(status, "201 Created")

        status, _h, listing = list_references(first)
        self.assertEqual(status, "200 OK")
        records = listing["cross_references"]
        self.assertEqual([r["remote_id"] for r in records], ["remote-42", "remote-8"])
        for record in records:
            self.assertEqual(
                set(record),
                {
                    "resource_id",
                    "repository",
                    "upstream",
                    "remote_id",
                    "digest",
                },
            )
        status, _h, second_refs = list_references(second)
        self.assertEqual(
            [r["remote_id"] for r in second_refs["cross_references"]],
            ["remote-7"],
        )
        self.assertEqual(one["resource_id"], first)
        self.assertEqual(two["resource_id"], second)
        self.assertEqual(three["resource_id"], first)

    def test_get_unknown_resource_returns_404(self) -> None:
        status, _h, body = list_references("missing")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

    def test_get_rejects_query_parameters(self) -> None:
        resource_id = register_local()
        status, _h, body = call_json(
            "GET",
            f"/resources/{resource_id}/cross-references",
            query_string="x=1",
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_same_upstream_second_registration_binds_repository(self) -> None:
        first = register_local()
        second = register_local(name="second", digest="c" * 64)
        with patch_resolve():
            status, _h, _b = post_reference(first)
        self.assertEqual(status, "201 Created")
        body = dict(REFERENCE_BODY, remote_id="remote-7", digest="d" * 64)
        with patch_resolve(
            digest="d" * 64,
            name="other",
            source="https://repo.example.invalid/other",
        ):
            status, _h, _b = post_reference(second, body)
        self.assertEqual(status, "201 Created")


class FieldBuilderTests(unittest.TestCase):
    def test_valid_fields_normalized(self) -> None:
        repository, upstream, remote_id, digest = (
            build_cross_reference_fields(
                dict(REFERENCE_BODY, digest=DIGEST.upper())
            )
        )
        self.assertEqual(repository, "partner")
        self.assertEqual(upstream, UPSTREAM)
        self.assertEqual(remote_id, REMOTE_ID)
        self.assertEqual(digest, DIGEST)

    def test_trailing_slash_upstream_is_accepted(self) -> None:
        payload = dict(REFERENCE_BODY, upstream=UPSTREAM_SLASH)
        _repository, upstream, _remote_id, _digest = (
            build_cross_reference_fields(payload)
        )
        self.assertEqual(upstream, UPSTREAM_SLASH)


class RemoteMetadataParsingTests(unittest.TestCase):
    def _resolution_failure(self, raw: bytes) -> None:
        with self.assertRaises(CrossReferenceError) as caught:
            parse_remote_metadata(raw)
        self.assertEqual(caught.exception.code, "resolution_failed")
        self.assertEqual(caught.exception.http_status, 502)

    def test_valid_document_is_normalized(self) -> None:
        _payload, raw = remote_metadata(category="MODEL", digest=DIGEST.upper())
        metadata = parse_remote_metadata(raw)
        self.assertEqual(metadata["name"], REMOTE_NAME)
        self.assertEqual(metadata["category"], "model")
        self.assertEqual(metadata["digest"], DIGEST)
        self.assertEqual(metadata["source"], SOURCE)

    def test_bad_documents_fail_resolution(self) -> None:
        good = {
            "name": REMOTE_NAME,
            "category": REMOTE_CATEGORY,
            "digest": DIGEST,
            "source": SOURCE,
        }
        self._resolution_failure(b"not json")
        self._resolution_failure(b"[1,2]")
        self._resolution_failure(b"null")
        for field in ("name", "category", "digest", "source"):
            payload = dict(good)
            del payload[field]
            self._resolution_failure(
                json.dumps(payload).encode("utf-8")
            )
        for field in ("name", "category", "digest", "source"):
            payload = dict(good, **{field: None})
            self._resolution_failure(
                json.dumps(payload).encode("utf-8")
            )
        for field in ("name", "category", "digest", "source"):
            payload = dict(good, **{field: 7})
            self._resolution_failure(
                json.dumps(payload).encode("utf-8")
            )
        self._resolution_failure(
            json.dumps(dict(good, name="")).encode("utf-8")
        )
        self._resolution_failure(
            json.dumps(dict(good, category="widget")).encode("utf-8")
        )
        self._resolution_failure(
            json.dumps(dict(good, digest="z" * 64)).encode("utf-8")
        )
        self._resolution_failure(
            json.dumps(dict(good, source="")).encode("utf-8")
        )

    def test_extra_remote_fields_are_accepted(self) -> None:
        # The remote document may carry more than the four required keys;
        # only their presence and types matter.
        raw = json.dumps(
            {
                "name": REMOTE_NAME,
                "category": REMOTE_CATEGORY,
                "digest": DIGEST,
                "source": SOURCE,
                "id": "remote-42",
            }
        ).encode("utf-8")
        metadata = parse_remote_metadata(raw)
        self.assertEqual(metadata["digest"], DIGEST)


class RemoteFetchTests(unittest.TestCase):
    def _response(self, status: int = 200, data: bytes = b"{}"):
        response = mock.MagicMock()
        response.status = status
        response.getcode.return_value = status
        response.read.return_value = data
        response.__enter__.return_value = response
        response.__exit__.return_value = False
        return response

    def test_fetch_joins_url_like_mirror_pulls(self) -> None:
        from provenance_api import cross_references

        response = self._response(data=b"{}")
        with mock.patch.object(
            cross_references.urllib.request, "urlopen", return_value=response
        ) as urlopen:
            raw = fetch_remote_resource(UPSTREAM_SLASH, REMOTE_ID)
        self.assertEqual(raw, b"{}")
        request = urlopen.call_args.args[0]
        self.assertEqual(
            request.full_url,
            f"{UPSTREAM}/resources/{REMOTE_ID}",
        )

    def test_fetch_percent_encodes_separator_like_characters(self) -> None:
        from provenance_api import cross_references

        response = self._response()
        with mock.patch.object(
            cross_references.urllib.request, "urlopen", return_value=response
        ) as urlopen:
            fetch_remote_resource(UPSTREAM, "a b")
        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url, f"{UPSTREAM}/resources/a%20b")

    def test_non_200_status_is_remote_unreachable(self) -> None:
        from provenance_api import cross_references

        with mock.patch.object(
            cross_references.urllib.request,
            "urlopen",
            return_value=self._response(status=500),
        ):
            with self.assertRaises(CrossReferenceError) as caught:
                fetch_remote_resource(UPSTREAM, REMOTE_ID)
        self.assertEqual(caught.exception.code, "remote_unreachable")

    def test_http_error_is_remote_unreachable(self) -> None:
        import urllib.error

        from provenance_api import cross_references

        error = urllib.error.HTTPError(
            UPSTREAM, 404, "Not Found", {}, io.BytesIO(b"")
        )
        with mock.patch.object(
            cross_references.urllib.request, "urlopen", side_effect=error
        ):
            with self.assertRaises(CrossReferenceError) as caught:
                fetch_remote_resource(UPSTREAM, REMOTE_ID)
        self.assertEqual(caught.exception.code, "remote_unreachable")

    def test_connection_failure_is_remote_unreachable(self) -> None:
        import urllib.error

        from provenance_api import cross_references

        with mock.patch.object(
            cross_references.urllib.request,
            "urlopen",
            side_effect=urllib.error.URLError("boom"),
        ):
            with self.assertRaises(CrossReferenceError) as caught:
                fetch_remote_resource(UPSTREAM, REMOTE_ID)
        self.assertEqual(caught.exception.code, "remote_unreachable")


class ResolveRemoteTests(unittest.TestCase):
    def test_digest_mismatch_is_reported(self) -> None:
        _payload, raw = remote_metadata(digest="f" * 64)
        with mock.patch(
            "provenance_api.cross_references.fetch_remote_resource",
            return_value=raw,
        ):
            with self.assertRaises(CrossReferenceError) as caught:
                resolve_remote(UPSTREAM, REMOTE_ID, DIGEST)
        self.assertEqual(caught.exception.code, "remote_digest_mismatch")
        self.assertEqual(caught.exception.http_status, 502)

    def test_success_returns_resolution(self) -> None:
        _payload, raw = remote_metadata()
        with mock.patch(
            "provenance_api.cross_references.fetch_remote_resource",
            return_value=raw,
        ):
            resolution = resolve_remote(UPSTREAM, REMOTE_ID, DIGEST)
        self.assertEqual(resolution.name, REMOTE_NAME)
        self.assertEqual(resolution.category, "model")
        self.assertEqual(resolution.digest, DIGEST)
        self.assertEqual(resolution.source, SOURCE)
        self.assertEqual(resolution.raw, raw)


if __name__ == "__main__":
    unittest.main()
