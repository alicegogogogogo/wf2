from __future__ import annotations

import io
import json
import unittest
from unittest import mock

from provenance_api.app import application, reset_state
from provenance_api.cross_references import (
    RemoteResolutionError,
    RemoteResource,
)

UPSTREAM = "https://repo.example.invalid"
UPSTREAM_SLASH = UPSTREAM + "/"
REPOSITORY = "primary"
REMOTE_ID = "remote-model-1"

NAME = "model-a"
CATEGORY = "model"
SOURCE = "https://repo.example.invalid/sources/model-a"
DIGEST = "a" * 64
DIGEST_B = "b" * 64

ANCHOR_NAME = "pipeline"
ANCHOR_CATEGORY = "artifact"
ANCHOR_DIGEST = "1" * 64


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


def register_resource(
    name: str = ANCHOR_NAME,
    category: str = ANCHOR_CATEGORY,
    digest: str = ANCHOR_DIGEST,
    source: str | None = None,
) -> dict[str, object]:
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
    return body


def reference_body(
    *,
    repository: str = REPOSITORY,
    upstream: str = UPSTREAM,
    remote_id: str = REMOTE_ID,
    digest: str = DIGEST,
) -> dict[str, object]:
    return {
        "repository": repository,
        "upstream": upstream,
        "remote_id": remote_id,
        "digest": digest,
    }


def remote_metadata_bytes(
    *,
    name: object = NAME,
    category: object = CATEGORY,
    digest: object = DIGEST,
    source: object = SOURCE,
) -> bytes:
    return json.dumps(
        {"name": name, "category": category, "digest": digest, "source": source}
    ).encode("utf-8")


def patch_fetch(
    *,
    name: object = NAME,
    category: object = CATEGORY,
    digest: object = DIGEST,
    source: object = SOURCE,
    raw: bytes | None = None,
    error: RemoteResolutionError | None = None,
):
    if error is not None:
        return mock.patch(
            "provenance_api.app.fetch_remote_resource", side_effect=error
        )
    if raw is None:
        raw = remote_metadata_bytes(
            name=name, category=category, digest=digest, source=source
        )
    parsed = RemoteResource(
        name=str(name),
        category=str(category).lower(),
        digest=str(digest).lower(),
        source=source if isinstance(source, str) else None,
    )
    return mock.patch(
        "provenance_api.app.fetch_remote_resource",
        return_value=(parsed, raw),
    )


def xref_path(resource_id: str) -> str:
    return f"/resources/{resource_id}/cross-references"


class CrossReferenceSuccessTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def test_resolve_creates_resource_edge_reference_and_caches(self) -> None:
        anchor = register_resource()
        raw_metadata = remote_metadata_bytes()
        parsed = RemoteResource(
            name=NAME, category=CATEGORY, digest=DIGEST, source=SOURCE
        )
        with mock.patch(
            "provenance_api.app.fetch_remote_resource",
            return_value=(parsed, raw_metadata),
        ) as fetch:
            status, headers, body = call_json(
                "POST",
                xref_path(anchor["id"]),
                json.dumps(reference_body()).encode("utf-8"),
                headers={"CONTENT_TYPE": "application/json"},
            )
        self.assertEqual(status, "201 Created")
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )
        self.assertEqual(
            set(body),
            {"repository", "upstream", "remote_id", "digest", "resource_id"},
        )
        self.assertEqual(body["repository"], REPOSITORY)
        self.assertEqual(body["upstream"], UPSTREAM)
        self.assertEqual(body["remote_id"], REMOTE_ID)
        self.assertEqual(body["digest"], DIGEST)
        self.assertEqual(body["resource_id"], anchor["id"])
        fetch.assert_called_once_with(UPSTREAM, REMOTE_ID, DIGEST)

        # A new local resource was created from the remote metadata.
        _s, _h, listed = call_json("GET", "/resources")
        resources = listed["resources"]
        self.assertEqual(len(resources), 2)
        created = resources[1]
        self.assertEqual(created["name"], NAME)
        self.assertEqual(created["category"], CATEGORY)
        self.assertEqual(created["digest"], DIGEST)
        self.assertEqual(created["source"], SOURCE)

        # The anchor now depends on the resolved resource.
        _s, _h, deps = call_json(
            "GET", f"/resources/{anchor['id']}/dependencies"
        )
        self.assertEqual(deps["dependencies"], [created["id"]])
        _s, _h, impact = call_json(
            "GET", f"/resources/{created['id']}/impact"
        )
        self.assertEqual(impact["resources"], [anchor["id"]])

        # The metadata JSON was cached under the resource digest.
        status, _h, cached = call("GET", f"/cache/layers/{DIGEST}")
        self.assertEqual(status, "200 OK")
        self.assertEqual(cached, raw_metadata)

    def test_trailing_slash_is_stripped_when_joining(self) -> None:
        anchor = register_resource()
        with patch_fetch() as fetch:
            status, _h, _body = call_json(
                "POST",
                xref_path(anchor["id"]),
                json.dumps(
                    reference_body(upstream=UPSTREAM_SLASH)
                ).encode("utf-8"),
                headers={"CONTENT_TYPE": "application/json"},
            )
        self.assertEqual(status, "201 Created")
        fetch.assert_called_once_with(UPSTREAM_SLASH, REMOTE_ID, DIGEST)

    def test_digest_is_normalized_to_lowercase(self) -> None:
        anchor = register_resource()
        mixed = DIGEST.upper()
        with patch_fetch(digest=mixed) as fetch:
            status, _h, body = call_json(
                "POST",
                xref_path(anchor["id"]),
                json.dumps(reference_body(digest=mixed)).encode("utf-8"),
                headers={"CONTENT_TYPE": "application/json"},
            )
        self.assertEqual(status, "201 Created")
        self.assertEqual(body["digest"], DIGEST)
        fetch.assert_called_once_with(UPSTREAM, REMOTE_ID, DIGEST)

    def test_category_is_normalized_to_lowercase(self) -> None:
        anchor = register_resource()
        with patch_fetch(category="MoDeL"):
            status, _h, _body = call_json(
                "POST",
                xref_path(anchor["id"]),
                json.dumps(reference_body()).encode("utf-8"),
                headers={"CONTENT_TYPE": "application/json"},
            )
        self.assertEqual(status, "201 Created")
        _s, _h, listed = call_json("GET", "/resources")
        self.assertEqual(listed["resources"][1]["category"], "model")

    def test_null_source_is_stored_as_null(self) -> None:
        anchor = register_resource()
        with patch_fetch(source=None):
            status, _h, _body = call_json(
                "POST",
                xref_path(anchor["id"]),
                json.dumps(reference_body()).encode("utf-8"),
                headers={"CONTENT_TYPE": "application/json"},
            )
        self.assertEqual(status, "201 Created")
        _s, _h, listed = call_json("GET", "/resources")
        self.assertIsNone(listed["resources"][1]["source"])

    def test_existing_same_identity_resource_is_reused(self) -> None:
        anchor = register_resource()
        existing = register_resource(
            name=NAME, category=CATEGORY, digest=DIGEST, source=SOURCE
        )
        with patch_fetch() as fetch:
            status, _h, body = call_json(
                "POST",
                xref_path(anchor["id"]),
                json.dumps(reference_body()).encode("utf-8"),
                headers={"CONTENT_TYPE": "application/json"},
            )
        self.assertEqual(status, "201 Created")
        self.assertEqual(body["resource_id"], anchor["id"])
        fetch.assert_called_once()
        # No additional resource was created.
        _s, _h, listed = call_json("GET", "/resources")
        self.assertEqual(len(listed["resources"]), 2)
        # The edge points at the pre-existing resource.
        _s, _h, deps = call_json(
            "GET", f"/resources/{anchor['id']}/dependencies"
        )
        self.assertEqual(deps["dependencies"], [existing["id"]])

    def test_same_metadata_bytes_are_idempotent_in_cache(self) -> None:
        anchor_a = register_resource(name="a", digest="11" * 32)
        with patch_fetch():
            status, _h, _b = call_json(
                "POST",
                xref_path(anchor_a["id"]),
                json.dumps(reference_body()).encode("utf-8"),
                headers={"CONTENT_TYPE": "application/json"},
            )
        self.assertEqual(status, "201 Created")

        # A second repository/remote pair resolves the same digest with the
        # exact same metadata bytes: cache write is an idempotent no-op.
        anchor_b = register_resource(name="b", digest="22" * 32)
        with patch_fetch():
            status, _h, _b = call_json(
                "POST",
                xref_path(anchor_b["id"]),
                json.dumps(
                    reference_body(
                        repository="secondary",
                        upstream="https://other.example.invalid",
                        remote_id="other-id",
                    )
                ).encode("utf-8"),
                headers={"CONTENT_TYPE": "application/json"},
            )
        self.assertEqual(status, "201 Created")
        _s, _h, status_body = call_json("GET", "/cache/status")
        self.assertEqual(status_body["entries"], 1)


class CrossReferenceListTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.anchor = register_resource()

    def _add(
        self,
        remote_id: str,
        digest: str,
        *,
        repository: str = REPOSITORY,
        upstream: str = UPSTREAM,
        name: str = NAME,
    ) -> None:
        with mock.patch(
            "provenance_api.app.fetch_remote_resource",
            return_value=(
                RemoteResource(
                    name=name,
                    category="model",
                    digest=digest,
                    source=None,
                ),
                remote_metadata_bytes(
                    name=name, digest=digest, source=None
                ),
            ),
        ):
            status, _h, body = call_json(
                "POST",
                xref_path(self.anchor["id"]),
                json.dumps(
                    reference_body(
                        repository=repository,
                        upstream=upstream,
                        remote_id=remote_id,
                        digest=digest,
                    )
                ).encode("utf-8"),
                headers={"CONTENT_TYPE": "application/json"},
            )
        assert status == "201 Created", (status, body)

    def test_empty_list(self) -> None:
        status, _h, body = call_json("GET", xref_path(self.anchor["id"]))
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, {"cross_references": []})

    def test_list_follows_registration_order(self) -> None:
        self._add("remote-1", "a" * 64)
        self._add("remote-2", "b" * 64)
        status, _h, body = call_json("GET", xref_path(self.anchor["id"]))
        self.assertEqual(status, "200 OK")
        records = body["cross_references"]
        self.assertEqual([r["remote_id"] for r in records], ["remote-1", "remote-2"])
        for record in records:
            self.assertEqual(
                set(record),
                {"repository", "upstream", "remote_id", "digest", "resource_id"},
            )
            self.assertEqual(record["resource_id"], self.anchor["id"])

    def test_list_is_scoped_to_the_resource(self) -> None:
        self._add("remote-1", "a" * 64)
        other = register_resource(name="other", digest="33" * 32)
        status, _h, body = call_json("GET", xref_path(other["id"]))
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["cross_references"], [])


class CrossReferenceConflictTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.anchor = register_resource()

    def _post(self, body: dict[str, object]) -> dict[str, object]:
        status, _h, parsed = call_json(
            "POST",
            xref_path(self.anchor["id"]),
            json.dumps(body).encode("utf-8"),
            headers={"CONTENT_TYPE": "application/json"},
        )
        assert status.startswith("4") or status.startswith("5"), (
            status,
            parsed,
        )
        parsed["_status"] = status
        return parsed

    def test_duplicate_repository_and_remote_id_is_409(self) -> None:
        with patch_fetch():
            status, _h, _b = call_json(
                "POST",
                xref_path(self.anchor["id"]),
                json.dumps(reference_body()).encode("utf-8"),
                headers={"CONTENT_TYPE": "application/json"},
            )
        self.assertEqual(status, "201 Created")
        with patch_fetch() as fetch:
            body = self._post(reference_body())
        self.assertEqual(body["_status"], "409 Conflict")
        self.assertEqual(body["error"], "duplicate_reference")
        fetch.assert_not_called()

    def test_duplicate_pair_takes_precedence_over_upstream_string(self) -> None:
        # The pair identifies the reference, so re-registering the same
        # (repository, remote_id) is a duplicate even when the upstream is
        # written with a different trailing slash.
        with patch_fetch():
            status, _h, _b = call_json(
                "POST",
                xref_path(self.anchor["id"]),
                json.dumps(
                    reference_body(upstream=UPSTREAM_SLASH)
                ).encode("utf-8"),
                headers={"CONTENT_TYPE": "application/json"},
            )
        self.assertEqual(status, "201 Created")
        with patch_fetch() as fetch:
            body = self._post(reference_body(upstream=UPSTREAM))
        self.assertEqual(body["_status"], "409 Conflict")
        self.assertEqual(body["error"], "duplicate_reference")
        fetch.assert_not_called()

    def test_same_repository_different_upstream_is_409(self) -> None:
        with patch_fetch():
            status, _h, _b = call_json(
                "POST",
                xref_path(self.anchor["id"]),
                json.dumps(reference_body()).encode("utf-8"),
                headers={"CONTENT_TYPE": "application/json"},
            )
        self.assertEqual(status, "201 Created")
        other_upstream = "https://mirror.example.invalid"
        with mock.patch(
            "provenance_api.app.fetch_remote_resource"
        ) as fetch:
            body = self._post(
                reference_body(
                    upstream=other_upstream, remote_id="different-remote"
                )
            )
        self.assertEqual(body["_status"], "409 Conflict")
        self.assertEqual(body["error"], "repository_conflict")
        fetch.assert_not_called()

    def test_identity_conflict_same_digest_other_name_is_409(self) -> None:
        register_resource(
            name="different-name", category=CATEGORY, digest=DIGEST
        )
        with patch_fetch() as fetch:
            body = self._post(reference_body())
        self.assertEqual(body["_status"], "409 Conflict")
        self.assertEqual(body["error"], "identity_conflict")
        fetch.assert_called_once()
        self._assert_unchanged_after_failure()

    def test_identity_conflict_same_digest_other_category_is_409(self) -> None:
        register_resource(name=NAME, category="code", digest=DIGEST)
        with patch_fetch():
            body = self._post(reference_body())
        self.assertEqual(body["_status"], "409 Conflict")
        self.assertEqual(body["error"], "identity_conflict")
        self._assert_unchanged_after_failure()

    def test_self_loop_is_409_dependency_cycle(self) -> None:
        # The anchor itself carries the resolved digest and identity.
        anchor = register_resource(
            name=NAME, category=CATEGORY, digest=DIGEST
        )
        with patch_fetch():
            status, _h, body = call_json(
                "POST",
                xref_path(anchor["id"]),
                json.dumps(reference_body()).encode("utf-8"),
                headers={"CONTENT_TYPE": "application/json"},
            )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "dependency_cycle")

    def test_closing_edge_is_409_dependency_cycle(self) -> None:
        # B already depends on the anchor A; resolving B from A closes a
        # cycle A -> B -> A.
        b = register_resource(name=NAME, category=CATEGORY, digest=DIGEST)
        status, _h, _body = call_json(
            "POST",
            f"/resources/{b['id']}/dependencies",
            json.dumps({"dependency_id": self.anchor["id"]}).encode("utf-8"),
            headers={"CONTENT_TYPE": "application/json"},
        )
        self.assertEqual(status, "201 Created")
        with patch_fetch():
            body = self._post(reference_body())
        self.assertEqual(body["_status"], "409 Conflict")
        self.assertEqual(body["error"], "dependency_cycle")
        # The graph is unchanged.
        _s, _h, deps = call_json(
            "GET", f"/resources/{self.anchor['id']}/dependencies"
        )
        self.assertEqual(deps["dependencies"], [])

    def test_existing_same_direction_edge_is_duplicate_dependency(self) -> None:
        # Same digest/identity resource is referenced from a second anchor
        # (different repository pair): the first anchor already has the edge.
        with patch_fetch():
            status, _h, _b = call_json(
                "POST",
                xref_path(self.anchor["id"]),
                json.dumps(reference_body()).encode("utf-8"),
                headers={"CONTENT_TYPE": "application/json"},
            )
        self.assertEqual(status, "201 Created")
        second_anchor = register_resource(name="second", digest="44" * 32)
        with patch_fetch():
            status, _h, body = call_json(
                "POST",
                xref_path(second_anchor["id"]),
                json.dumps(
                    reference_body(
                        repository="secondary",
                        upstream="https://other.example.invalid",
                        remote_id="other-id",
                    )
                ).encode("utf-8"),
                headers={"CONTENT_TYPE": "application/json"},
            )
        self.assertEqual(status, "201 Created")
        # Referencing the same resolved resource once more from the first
        # anchor via another repository pair is a duplicate dependency.
        with patch_fetch():
            status, _h, body = call_json(
                "POST",
                xref_path(self.anchor["id"]),
                json.dumps(
                    reference_body(
                        repository="tertiary",
                        upstream="https://third.example.invalid",
                        remote_id="third-id",
                    )
                ).encode("utf-8"),
                headers={"CONTENT_TYPE": "application/json"},
            )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "duplicate_dependency")
        # The rejected reference was not recorded.
        _s, _h, listed = call_json("GET", xref_path(self.anchor["id"]))
        self.assertEqual(len(listed["cross_references"]), 1)

    def test_identity_match_preferred_when_multiple_resources_share_digest(
        self,
    ) -> None:
        # Registration dedups on (category, name, digest), so two resources
        # with the same digest but different identities can coexist.
        register_resource(
            name="other-identity", category="code", digest=DIGEST
        )
        exact = register_resource(
            name=NAME, category=CATEGORY, digest=DIGEST, source=SOURCE
        )
        with patch_fetch() as fetch:
            status, _h, body = call_json(
                "POST",
                xref_path(self.anchor["id"]),
                json.dumps(reference_body()).encode("utf-8"),
                headers={"CONTENT_TYPE": "application/json"},
            )
        self.assertEqual(status, "201 Created")
        fetch.assert_called_once()
        _s, _h, deps = call_json(
            "GET", f"/resources/{self.anchor['id']}/dependencies"
        )
        self.assertEqual(deps["dependencies"], [exact["id"]])

    def test_cache_conflict_same_digest_other_bytes_is_409(self) -> None:
        # Seed a same-digest cache entry with different bytes directly
        # through the store; metadata caching must refuse to overwrite.
        from provenance_api.app import cache_store

        other_bytes = b"entirely different cached content"
        cache_store._layers[DIGEST] = other_bytes  # type: ignore[attr-defined]
        cache_store._used += len(other_bytes)  # type: ignore[attr-defined]
        with patch_fetch():
            body = self._post(reference_body())
        self.assertEqual(body["_status"], "409 Conflict")
        self.assertEqual(body["error"], "cache_conflict")
        self._assert_unchanged_after_failure()
        # The original cache entry survives (peek, to avoid a hit counter).
        from provenance_api.app import cache_store as cs

        self.assertEqual(cs.peek(DIGEST), other_bytes)

    def _assert_unchanged_after_failure(self) -> None:
        # No reference, no edge and no extra local resource.
        _s, _h, listed = call_json("GET", xref_path(self.anchor["id"]))
        self.assertEqual(listed["cross_references"], [])
        _s, _h, deps = call_json(
            "GET", f"/resources/{self.anchor['id']}/dependencies"
        )
        self.assertEqual(deps["dependencies"], [])
        _s, _h, resources = call_json("GET", "/resources")
        # Only the anchor plus the seeded identity-conflict resource.
        self.assertLessEqual(len(resources["resources"]), 2)


class CrossReferenceRemoteFailureTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.anchor = register_resource()

    def _post_expect_502(self, error: RemoteResolutionError, code: str) -> None:
        with patch_fetch(error=error):
            status, _h, body = call_json(
                "POST",
                xref_path(self.anchor["id"]),
                json.dumps(reference_body()).encode("utf-8"),
                headers={"CONTENT_TYPE": "application/json"},
            )
        self.assertEqual(status, "502 Bad Gateway")
        self.assertEqual(body["error"], code)

    def test_remote_unreachable_connection_failure(self) -> None:
        self._post_expect_502(
            RemoteResolutionError(
                "remote_unreachable",
                "Upstream repository could not be reached.",
            ),
            "remote_unreachable",
        )
        self._assert_no_state_change()

    def test_remote_unreachable_non_200(self) -> None:
        self._post_expect_502(
            RemoteResolutionError(
                "remote_unreachable",
                "Upstream repository did not return the resource.",
            ),
            "remote_unreachable",
        )
        self._assert_no_state_change()

    def test_remote_digest_mismatch(self) -> None:
        self._post_expect_502(
            RemoteResolutionError(
                "remote_digest_mismatch",
                "Upstream resource digest does not match the expected digest.",
            ),
            "remote_digest_mismatch",
        )
        self._assert_no_state_change()

    def test_malformed_json_metadata_is_resolution_failed(self) -> None:
        from provenance_api.cross_references import parse_remote_metadata

        def fake_fetch(*_args: object, **_kwargs: object):
            return parse_remote_metadata(b"{not json", DIGEST)

        with mock.patch(
            "provenance_api.app.fetch_remote_resource",
            side_effect=fake_fetch,
        ):
            status, _h, body = call_json(
                "POST",
                xref_path(self.anchor["id"]),
                json.dumps(reference_body()).encode("utf-8"),
                headers={"CONTENT_TYPE": "application/json"},
            )
        self.assertEqual(status, "502 Bad Gateway")
        self.assertEqual(body["error"], "resolution_failed")
        self._assert_no_state_change()

    def test_metadata_not_an_object_is_resolution_failed(self) -> None:
        from provenance_api.cross_references import parse_remote_metadata

        def fake_fetch(*_args: object, **_kwargs: object):
            return parse_remote_metadata(b"[1,2,3]", DIGEST)

        with mock.patch(
            "provenance_api.app.fetch_remote_resource",
            side_effect=fake_fetch,
        ):
            status, _h, body = call_json(
                "POST",
                xref_path(self.anchor["id"]),
                json.dumps(reference_body()).encode("utf-8"),
                headers={"CONTENT_TYPE": "application/json"},
            )
        self.assertEqual(status, "502 Bad Gateway")
        self.assertEqual(body["error"], "resolution_failed")
        self._assert_no_state_change()

    def test_metadata_field_failures_are_resolution_failed(self) -> None:
        from provenance_api.cross_references import parse_remote_metadata

        cases = [
            {"name": None},
            {"name": ""},
            {"category": None},
            {"category": "not-a-category"},
            {"digest": None},
            {"digest": "xyz"},
            {"source": ""},
            {"source": 42},
        ]
        for overrides in cases:
            fields = {
                "name": NAME,
                "category": CATEGORY,
                "digest": DIGEST,
                "source": SOURCE,
            }
            fields.update(overrides)
            raw = json.dumps(fields).encode("utf-8")

            def fake_fetch(*_a: object, _raw: bytes = raw, **_k: object):
                return parse_remote_metadata(_raw, DIGEST)

            with mock.patch(
                "provenance_api.app.fetch_remote_resource",
                side_effect=fake_fetch,
            ):
                status, _h, body = call_json(
                    "POST",
                    xref_path(self.anchor["id"]),
                    json.dumps(reference_body()).encode("utf-8"),
                    headers={"CONTENT_TYPE": "application/json"},
                )
            self.assertEqual(status, "502 Bad Gateway", overrides)
            self.assertEqual(body["error"], "resolution_failed", overrides)
        self._assert_no_state_change()

    def test_digest_mismatch_through_real_parse(self) -> None:
        from provenance_api.cross_references import parse_remote_metadata

        raw = remote_metadata_bytes(digest=DIGEST_B)

        def fake_fetch(*_a: object, **_k: object):
            return parse_remote_metadata(raw, DIGEST)

        with mock.patch(
            "provenance_api.app.fetch_remote_resource",
            side_effect=fake_fetch,
        ):
            status, _h, body = call_json(
                "POST",
                xref_path(self.anchor["id"]),
                json.dumps(reference_body()).encode("utf-8"),
                headers={"CONTENT_TYPE": "application/json"},
            )
        self.assertEqual(status, "502 Bad Gateway")
        self.assertEqual(body["error"], "remote_digest_mismatch")
        self._assert_no_state_change()

    def _assert_no_state_change(self) -> None:
        _s, _h, listed = call_json("GET", xref_path(self.anchor["id"]))
        self.assertEqual(listed["cross_references"], [])
        _s, _h, resources = call_json("GET", "/resources")
        self.assertEqual(len(resources["resources"]), 1)
        _s, _h, status_body = call_json("GET", "/cache/status")
        self.assertEqual(status_body["entries"], 0)


class CrossReferenceRequestValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.anchor = register_resource()

    def _expect_400(self, raw_body: bytes | None, **kwargs: object) -> None:
        if raw_body is None:
            status, _h, body = call_json(
                "POST", xref_path(self.anchor["id"]), **kwargs
            )
        else:
            status, _h, body = call_json(
                "POST",
                xref_path(self.anchor["id"]),
                raw_body,
                headers={"CONTENT_TYPE": "application/json"},
                **kwargs,
            )
        self.assertEqual(status, "400 Bad Request", raw_body)
        self.assertEqual(body["error"], "invalid_request")

    def test_empty_body(self) -> None:
        self._expect_400(b"")

    def test_bad_json(self) -> None:
        self._expect_400(b"{not json")

    def test_non_object(self) -> None:
        for payload in (b"[1,2]", b'"x"', b"42", b"null"):
            self._expect_400(payload)

    def test_field_errors(self) -> None:
        base = reference_body()
        bad_payloads: list[bytes] = []
        for field in ("repository", "upstream", "remote_id", "digest"):
            missing = dict(base)
            del missing[field]
            bad_payloads.append(json.dumps(missing).encode("utf-8"))
            nulled = dict(base)
            nulled[field] = None
            bad_payloads.append(json.dumps(nulled).encode("utf-8"))
        bad_payloads.append(
            json.dumps(dict(base, extra=1)).encode("utf-8")
        )
        bad_payloads.append(
            json.dumps(dict(base, repository="")).encode("utf-8")
        )
        bad_payloads.append(
            json.dumps(dict(base, repository="   ")).encode("utf-8")
        )
        bad_payloads.append(
            json.dumps(dict(base, remote_id="")).encode("utf-8")
        )
        bad_payloads.append(
            json.dumps(dict(base, remote_id="a/b")).encode("utf-8")
        )
        bad_payloads.append(
            json.dumps(dict(base, remote_id="a\\b")).encode("utf-8")
        )
        bad_payloads.append(
            json.dumps(dict(base, digest="xyz")).encode("utf-8")
        )
        bad_payloads.append(
            json.dumps(dict(base, digest="g" * 64)).encode("utf-8")
        )
        for bad_upstream in (
            "ftp://repo.example.invalid",
            "example.invalid/path",
            "/just/a/path",
            "http://",
            "https://repo.example.invalid?x=1",
        ):
            bad_payloads.append(
                json.dumps(dict(base, upstream=bad_upstream)).encode("utf-8")
            )
        for payload in bad_payloads:
            self._expect_400(payload)

    def test_query_parameters_rejected(self) -> None:
        with patch_fetch():
            status, _h, body = call_json(
                "POST",
                xref_path(self.anchor["id"]),
                json.dumps(reference_body()).encode("utf-8"),
                headers={"CONTENT_TYPE": "application/json"},
                query_string="x=1",
            )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        status, _h, body = call_json(
            "GET", xref_path(self.anchor["id"]), query_string="x=1"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_bad_body_on_missing_resource_is_still_400(self) -> None:
        with mock.patch(
            "provenance_api.app.fetch_remote_resource"
        ) as fetch:
            status, _h, body = call_json(
                "POST",
                "/resources/does-not-exist/cross-references",
                b"{}",
                headers={"CONTENT_TYPE": "application/json"},
            )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        fetch.assert_not_called()

    def test_missing_resource_is_404_without_fetching(self) -> None:
        with mock.patch(
            "provenance_api.app.fetch_remote_resource"
        ) as fetch:
            status, _h, body = call_json(
                "POST",
                "/resources/does-not-exist/cross-references",
                json.dumps(reference_body()).encode("utf-8"),
                headers={"CONTENT_TYPE": "application/json"},
            )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")
        fetch.assert_not_called()

    def test_get_missing_resource_is_404(self) -> None:
        status, _h, body = call_json(
            "GET", "/resources/does-not-exist/cross-references"
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

    def test_separator_in_path_id_is_400(self) -> None:
        for path in (
            "/resources/a/b/cross-references",
            "/resources/a\\b/cross-references",
        ):
            status, _h, body = call_json("POST", path, b"{}")
            self.assertEqual(status, "400 Bad Request", path)
            self.assertEqual(body["error"], "invalid_request")

    def test_method_not_allowed_has_allow_header(self) -> None:
        for method in ("PUT", "DELETE", "PATCH"):
            status, headers, body = call_json(
                method, xref_path(self.anchor["id"])
            )
            self.assertEqual(status, "405 Method Not Allowed")
            self.assertIn(("Allow", "GET, POST"), headers)
            self.assertEqual(body["error"], "method_not_allowed")


class GraphIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def test_resolved_edge_participates_in_topology_ordering(self) -> None:
        # Manually registered dependency R1, then a cross-resolved R2: the
        # transitive dependency listing follows resource registration order,
        # not edge creation order.
        anchor = register_resource(name="anchor", digest="aa" * 32)
        manual = register_resource(name="manual", category="code", digest="cc" * 32)
        status, _h, _b = call_json(
            "POST",
            f"/resources/{anchor['id']}/dependencies",
            json.dumps({"dependency_id": manual["id"]}).encode("utf-8"),
            headers={"CONTENT_TYPE": "application/json"},
        )
        self.assertEqual(status, "201 Created")

        resolved_digest = "dd" * 32
        with mock.patch(
            "provenance_api.app.fetch_remote_resource",
            return_value=(
                RemoteResource(
                    name="resolved",
                    category="model",
                    digest=resolved_digest,
                    source=None,
                ),
                remote_metadata_bytes(
                    name="resolved",
                    category="model",
                    digest=resolved_digest,
                    source=None,
                ),
            ),
        ):
            status, _h, _b = call_json(
                "POST",
                xref_path(anchor["id"]),
                json.dumps(
                    reference_body(
                        remote_id="r2", digest=resolved_digest
                    )
                ).encode("utf-8"),
                headers={"CONTENT_TYPE": "application/json"},
            )
        self.assertEqual(status, "201 Created")

        _s, _h, listed = call_json("GET", "/resources")
        ids = [r["id"] for r in listed["resources"]]
        self.assertEqual(ids, [anchor["id"], manual["id"], ids[2]])

        _s, _h, deps = call_json(
            "GET", f"/resources/{anchor['id']}/dependencies"
        )
        # Registration order: manual (created first) before resolved.
        self.assertEqual(deps["dependencies"], [manual["id"], ids[2]])

        # Impact analysis traverses resolved edges in reverse.
        _s, _h, impact = call_json(
            "GET", f"/resources/{ids[2]}/impact"
        )
        self.assertEqual(impact["resources"], [anchor["id"]])


if __name__ == "__main__":
    unittest.main()
