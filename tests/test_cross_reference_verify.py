from __future__ import annotations

import io
import json
import unittest
from unittest import mock

from provenance_api.app import application, cache_store, reset_state
from provenance_api.cross_references import CrossReferenceError

UPSTREAM = "https://repo.example.invalid"
REMOTE_ID = "remote-42"
REMOTE_NAME = "remote-model"
REMOTE_CATEGORY = "Model"
DIGEST = "a" * 64
OTHER_DIGEST = "d" * 64
THIRD_DIGEST = "e" * 64
SOURCE = "https://repo.example.invalid/sources/remote-42"

FIELDS = [
    "resource_id",
    "repository",
    "upstream",
    "remote_id",
    "digest",
    "status",
    "remote",
    "local_id",
]
REMOTE_FIELDS = ["name", "category", "digest", "source"]


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


def remote_document(
    *,
    name: str = REMOTE_NAME,
    category: str = REMOTE_CATEGORY,
    digest: str = DIGEST,
    source: str = SOURCE,
) -> bytes:
    return json.dumps(
        {
            "name": name,
            "category": category,
            "digest": digest,
            "source": source,
        },
        separators=(",", ":"),
    ).encode("utf-8")


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
        raw=remote_document(
            name=name, category=category, digest=digest, source=source
        ),
    )
    return mock.patch(
        "provenance_api.app.resolve_remote", return_value=resolution
    )


def post_reference(
    resource_id: str,
    *,
    repository: str = "partner",
    upstream: str = UPSTREAM,
    remote_id: str = REMOTE_ID,
    digest: str = DIGEST,
    name: str = REMOTE_NAME,
    category: str = REMOTE_CATEGORY,
    source: str = SOURCE,
) -> None:
    body = {
        "repository": repository,
        "upstream": upstream,
        "remote_id": remote_id,
        "digest": digest,
    }
    with patch_resolve(
        name=name, category=category, digest=digest, source=source
    ):
        status, _h, response = call_json(
            "POST",
            f"/resources/{resource_id}/cross-references",
            json.dumps(body).encode("utf-8"),
            headers={"CONTENT_TYPE": "application/json"},
        )
    assert status == "201 Created", (status, response)


def verify_path(resource_id: str) -> str:
    return f"/resources/{resource_id}/cross-references/verify"


def local_id_for(remote_id: str) -> str:
    status, _h, raw = call("GET", "/")
    assert status == "200 OK"
    for record in json.loads(raw):
        if record["remote_id"] == remote_id:
            return str(record["local_id"])
    raise KeyError(remote_id)


def patch_fetch(side_effect=None, return_value=None):
    if side_effect is not None:
        return mock.patch(
            "provenance_api.cross_references.fetch_remote_resource",
            side_effect=side_effect,
        )
    return mock.patch(
        "provenance_api.cross_references.fetch_remote_resource",
        return_value=return_value if return_value is not None else remote_document(),
    )


class CrossReferenceVerifyRequestTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.resource_id = register_local()

    def test_empty_references_returns_empty_results_with_newline(self) -> None:
        status, headers, raw = call("POST", verify_path(self.resource_id))
        self.assertEqual(status, "200 OK")
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )
        self.assertEqual(raw, b'{"results":[]}\n')

    def test_top_level_has_only_results(self) -> None:
        post_reference(self.resource_id)
        with patch_fetch():
            status, _h, body = call_json(
                "POST", verify_path(self.resource_id)
            )
        self.assertEqual(status, "200 OK")
        self.assertEqual(list(body), ["results"])

    def test_omitted_content_length_is_ok(self) -> None:
        status, _h, raw = call(
            "POST",
            verify_path(self.resource_id),
            omit_content_length=True,
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b'{"results":[]}\n')

    def test_explicit_zero_length_is_ok(self) -> None:
        status, _h, raw = call(
            "POST",
            verify_path(self.resource_id),
            headers={"CONTENT_LENGTH": "0"},
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b'{"results":[]}\n')

    def test_empty_string_content_length_is_ok(self) -> None:
        status, _h, raw = call(
            "POST",
            verify_path(self.resource_id),
            headers={"CONTENT_LENGTH": ""},
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b'{"results":[]}\n')

    def test_non_empty_body_returns_400_without_fetching(self) -> None:
        for payload in (b"x", b"{}", b"null"):
            with patch_fetch(
                side_effect=AssertionError("must not fetch")
            ) as fetch:
                status, _h, body = call_json(
                    "POST",
                    verify_path(self.resource_id),
                    payload,
                    headers={"CONTENT_TYPE": "application/json"},
                )
            self.assertEqual(status, "400 Bad Request", payload)
            self.assertEqual(body["error"], "invalid_request")
            fetch.assert_not_called()

    def test_malformed_content_length_returns_400(self) -> None:
        status, _h, body = call_json(
            "POST",
            verify_path(self.resource_id),
            headers={"CONTENT_LENGTH": "abc"},
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_query_parameters_return_400(self) -> None:
        for query_string in ("x=1", "x=", "a=b&c=d"):
            with patch_fetch(
                side_effect=AssertionError("must not fetch")
            ) as fetch:
                status, _h, body = call_json(
                    "POST",
                    verify_path(self.resource_id),
                    query_string=query_string,
                )
            self.assertEqual(status, "400 Bad Request", query_string)
            self.assertEqual(body["error"], "invalid_request")
            fetch.assert_not_called()

    def test_empty_or_separator_id_returns_400(self) -> None:
        for path in (
            "/resources//cross-references/verify",
            "/resources/a/b/cross-references/verify",
        ):
            with patch_fetch(
                side_effect=AssertionError("must not fetch")
            ) as fetch:
                status, _h, body = call_json("POST", path)
            self.assertEqual(status, "400 Bad Request", path)
            self.assertEqual(body["error"], "invalid_request")
            fetch.assert_not_called()

    def test_unknown_resource_returns_404_without_fetching(self) -> None:
        with patch_fetch(
            side_effect=AssertionError("must not fetch")
        ) as fetch:
            status, _h, body = call_json(
                "POST", verify_path("missing")
            )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")
        fetch.assert_not_called()

    def test_other_methods_return_405_with_post_allow(self) -> None:
        for method in ("GET", "PUT", "DELETE", "PATCH", "HEAD"):
            status, headers, body = call_json(
                method, verify_path(self.resource_id)
            )
            self.assertEqual(status, "405 Method Not Allowed", method)
            self.assertIn(("Allow", "POST"), headers)
            allow_values = [v for k, v in headers if k == "Allow"]
            self.assertEqual(allow_values, ["POST"], method)
            self.assertEqual(body["error"], "method_not_allowed")

    def test_non_post_with_query_or_body_still_returns_405(self) -> None:
        # Method is decided before request shape and business data.
        with patch_fetch(
            side_effect=AssertionError("must not fetch")
        ) as fetch:
            status, headers, body = call_json(
                "DELETE",
                verify_path(self.resource_id),
                query_string="x=1",
            )
        self.assertEqual(status, "405 Method Not Allowed")
        self.assertEqual([v for k, v in headers if k == "Allow"], ["POST"])
        self.assertEqual(body["error"], "method_not_allowed")
        fetch.assert_not_called()

        with patch_fetch(
            side_effect=AssertionError("must not fetch")
        ) as fetch:
            status, headers, body = call_json(
                "GET", verify_path(self.resource_id), b"x"
            )
        self.assertEqual(status, "405 Method Not Allowed")
        self.assertEqual([v for k, v in headers if k == "Allow"], ["POST"])
        self.assertEqual(body["error"], "method_not_allowed")
        fetch.assert_not_called()


class CrossReferenceVerifyStatusTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def test_matched_result_shape_and_field_order(self) -> None:
        start_id = register_local()
        post_reference(start_id)
        resolved_id = local_id_for(REMOTE_ID)
        with patch_fetch() as fetch:
            status, _h, body = call_json("POST", verify_path(start_id))
        self.assertEqual(status, "200 OK")
        results = body["results"]
        self.assertEqual(len(results), 1)
        entry = results[0]
        self.assertEqual(list(entry), FIELDS)
        self.assertEqual(entry["resource_id"], start_id)
        self.assertEqual(entry["repository"], "partner")
        self.assertEqual(entry["upstream"], UPSTREAM)
        self.assertEqual(entry["remote_id"], REMOTE_ID)
        self.assertEqual(entry["digest"], DIGEST)
        self.assertEqual(entry["status"], "matched")
        self.assertEqual(entry["local_id"], resolved_id)
        self.assertEqual(list(entry["remote"]), REMOTE_FIELDS)
        self.assertEqual(
            entry["remote"],
            {
                "name": REMOTE_NAME,
                "category": "model",
                "digest": DIGEST,
                "source": SOURCE,
            },
        )
        fetch.assert_called_once_with(UPSTREAM, REMOTE_ID)

    def test_registered_digest_is_normalized_and_echoed(self) -> None:
        start_id = register_local()
        post_reference(start_id, digest=DIGEST.upper())
        with patch_fetch(return_value=remote_document(digest=DIGEST.upper())):
            status, _h, body = call_json("POST", verify_path(start_id))
        self.assertEqual(status, "200 OK")
        entry = body["results"][0]
        self.assertEqual(entry["digest"], DIGEST)
        self.assertEqual(entry["status"], "matched")
        self.assertEqual(entry["remote"]["digest"], DIGEST)

    def test_remote_unreachable_keeps_remote_null(self) -> None:
        start_id = register_local()
        post_reference(start_id)

        def boom(upstream: str, remote_id: str, **_kwargs: object) -> bytes:
            raise CrossReferenceError(
                "remote_unreachable", "x", http_status=502
            )

        with patch_fetch(side_effect=boom):
            status, _h, body = call_json("POST", verify_path(start_id))
        self.assertEqual(status, "200 OK")
        entry = body["results"][0]
        self.assertEqual(entry["status"], "remote_unreachable")
        self.assertIsNone(entry["remote"])

    def test_resolution_failed_keeps_remote_null(self) -> None:
        start_id = register_local()
        post_reference(start_id)
        with patch_fetch(return_value=b"not json"):
            status, _h, body = call_json("POST", verify_path(start_id))
        self.assertEqual(status, "200 OK")
        entry = body["results"][0]
        self.assertEqual(entry["status"], "resolution_failed")
        self.assertIsNone(entry["remote"])

    def test_malformed_document_is_resolution_failed(self) -> None:
        start_id = register_local()
        post_reference(start_id)
        # Decodable JSON but not the established four-field document.
        raw = json.dumps({"name": REMOTE_NAME, "category": "model"}).encode()
        with patch_fetch(return_value=raw):
            status, _h, body = call_json("POST", verify_path(start_id))
        self.assertEqual(status, "200 OK")
        entry = body["results"][0]
        self.assertEqual(entry["status"], "resolution_failed")
        self.assertIsNone(entry["remote"])

    def test_digest_mismatch_still_exposes_remote_document(self) -> None:
        start_id = register_local()
        post_reference(start_id)
        changed = remote_document(digest="f" * 64)
        with patch_fetch(return_value=changed):
            status, _h, body = call_json("POST", verify_path(start_id))
        self.assertEqual(status, "200 OK")
        entry = body["results"][0]
        self.assertEqual(entry["status"], "remote_digest_mismatch")
        # The registered digest is echoed even though the remote differs.
        self.assertEqual(entry["digest"], DIGEST)
        self.assertEqual(entry["remote"]["digest"], "f" * 64)
        self.assertEqual(list(entry["remote"]), REMOTE_FIELDS)

    def test_deregistered_local_is_local_resource_missing(self) -> None:
        start_id = register_local()
        post_reference(start_id)
        resolved_id = local_id_for(REMOTE_ID)
        self.assertEqual(call("DELETE", f"/resources/{resolved_id}")[0], "200 OK")
        with patch_fetch():
            status, _h, body = call_json("POST", verify_path(start_id))
        self.assertEqual(status, "200 OK")
        entry = body["results"][0]
        self.assertEqual(entry["status"], "local_resource_missing")
        # local_id is retained verbatim after deregistration.
        self.assertEqual(entry["local_id"], resolved_id)
        self.assertIsNotNone(entry["remote"])

    def test_name_difference_is_identity_mismatch(self) -> None:
        start_id = register_local()
        post_reference(start_id)
        with patch_fetch(return_value=remote_document(name="changed-name")):
            status, _h, body = call_json("POST", verify_path(start_id))
        self.assertEqual(status, "200 OK")
        entry = body["results"][0]
        self.assertEqual(entry["status"], "identity_mismatch")
        self.assertEqual(entry["remote"]["name"], "changed-name")

    def test_name_is_case_sensitive(self) -> None:
        start_id = register_local()
        post_reference(start_id, name="remote-model")
        with patch_fetch(return_value=remote_document(name="REMOTE-MODEL")):
            status, _h, body = call_json("POST", verify_path(start_id))
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            body["results"][0]["status"], "identity_mismatch"
        )

    def test_category_is_compared_case_insensitively(self) -> None:
        start_id = register_local()
        post_reference(start_id, category="Model")
        with patch_fetch(return_value=remote_document(category="MODEL")):
            status, _h, body = call_json("POST", verify_path(start_id))
        self.assertEqual(status, "200 OK")
        entry = body["results"][0]
        self.assertEqual(entry["status"], "matched")
        self.assertEqual(entry["remote"]["category"], "model")

    def test_category_difference_is_identity_mismatch(self) -> None:
        start_id = register_local()
        post_reference(start_id, category="Model")
        with patch_fetch(return_value=remote_document(category="code")):
            status, _h, body = call_json("POST", verify_path(start_id))
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            body["results"][0]["status"], "identity_mismatch"
        )

    def test_source_difference_still_matches(self) -> None:
        # source never participates in identity; the local source is kept.
        start_id = register_local()
        post_reference(start_id, source="https://local/original")
        with patch_fetch(
            return_value=remote_document(source="https://remote/changed")
        ):
            status, _h, body = call_json("POST", verify_path(start_id))
        self.assertEqual(status, "200 OK")
        entry = body["results"][0]
        self.assertEqual(entry["status"], "matched")
        self.assertEqual(entry["remote"]["source"], "https://remote/changed")

    def test_missing_local_outranks_identity_difference(self) -> None:
        start_id = register_local()
        post_reference(start_id)
        resolved_id = local_id_for(REMOTE_ID)
        self.assertEqual(call("DELETE", f"/resources/{resolved_id}")[0], "200 OK")
        # Same digest, but the remote now also reports a different name.
        with patch_fetch(return_value=remote_document(name="changed")):
            status, _h, body = call_json("POST", verify_path(start_id))
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            body["results"][0]["status"], "local_resource_missing"
        )

    def test_digest_mismatch_outranks_missing_local(self) -> None:
        start_id = register_local()
        post_reference(start_id)
        resolved_id = local_id_for(REMOTE_ID)
        self.assertEqual(call("DELETE", f"/resources/{resolved_id}")[0], "200 OK")
        with patch_fetch(return_value=remote_document(digest="f" * 64)):
            status, _h, body = call_json("POST", verify_path(start_id))
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            body["results"][0]["status"], "remote_digest_mismatch"
        )

    def test_remote_failure_outranks_everything_local(self) -> None:
        start_id = register_local()
        post_reference(start_id)
        resolved_id = local_id_for(REMOTE_ID)
        self.assertEqual(call("DELETE", f"/resources/{resolved_id}")[0], "200 OK")

        def boom(upstream: str, remote_id: str, **_kwargs: object) -> bytes:
            raise CrossReferenceError(
                "remote_unreachable", "x", http_status=502
            )

        with patch_fetch(side_effect=boom):
            status, _h, body = call_json("POST", verify_path(start_id))
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            body["results"][0]["status"], "remote_unreachable"
        )

    def test_edge_removal_does_not_change_match(self) -> None:
        start_id = register_local()
        post_reference(start_id)
        resolved_id = local_id_for(REMOTE_ID)
        self.assertEqual(
            call(
                "DELETE",
                f"/resources/{start_id}/dependencies/{resolved_id}",
            )[0],
            "200 OK",
        )
        with patch_fetch():
            status, _h, body = call_json("POST", verify_path(start_id))
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["results"][0]["status"], "matched")


class CrossReferenceVerifyOrderAndIndependenceTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def test_results_follow_registration_order_and_checks_are_independent(
        self,
    ) -> None:
        start_id = register_local(name="root", digest="1" * 64)
        post_reference(
            start_id,
            repository="partner",
            remote_id="remote-42",
            digest=DIGEST,
        )
        post_reference(
            start_id,
            repository="other",
            upstream="https://other.invalid",
            remote_id="remote-7",
            digest=OTHER_DIGEST,
            name="other-remote",
            source="https://other.invalid/source",
        )
        post_reference(
            start_id,
            repository="third",
            upstream="https://third.invalid",
            remote_id="remote-8",
            digest=THIRD_DIGEST,
            name="third-remote",
            source="https://third.invalid/source",
        )

        def fake_fetch(
            upstream: str, remote_id: str, **_kwargs: object
        ) -> bytes:
            if remote_id == "remote-42":
                # The first reference is unreachable but must not stop the
                # remaining verifications.
                raise CrossReferenceError(
                    "remote_unreachable", "x", http_status=502
                )
            if remote_id == "remote-8":
                return b"not json"
            return remote_document(
                name="other-remote",
                category="Model",
                digest=OTHER_DIGEST,
                source="https://other.invalid/source",
            )

        with patch_fetch(side_effect=fake_fetch) as fetch:
            status, _h, body = call_json("POST", verify_path(start_id))
        self.assertEqual(status, "200 OK")
        results = body["results"]
        self.assertEqual(
            [entry["remote_id"] for entry in results],
            ["remote-42", "remote-7", "remote-8"],
        )
        self.assertEqual(
            [entry["status"] for entry in results],
            ["remote_unreachable", "matched", "resolution_failed"],
        )
        self.assertEqual(
            [entry["repository"] for entry in results],
            ["partner", "other", "third"],
        )
        self.assertIsNone(results[0]["remote"])
        self.assertIsNone(results[2]["remote"])
        self.assertEqual(fetch.call_count, 3)
        fetch.assert_any_call(UPSTREAM, "remote-42")
        fetch.assert_any_call("https://other.invalid", "remote-7")
        fetch.assert_any_call("https://third.invalid", "remote-8")

    def test_only_this_resources_references_are_verified(self) -> None:
        first = register_local(name="first")
        second = register_local(name="second", digest="c" * 64)
        post_reference(first, remote_id="remote-1")
        post_reference(
            second,
            repository="other",
            upstream="https://other.invalid",
            remote_id="remote-2",
            digest=OTHER_DIGEST,
            name="other-remote",
        )

        with patch_fetch(
            side_effect=AssertionError("must not fetch")
        ) as fetch:
            # A resource without references of its own contacts nobody.
            status, _h, body = call_json(
                "POST",
                verify_path(register_local(name="third", digest="f" * 64)),
            )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["results"], [])
        fetch.assert_not_called()

        def fake_fetch(
            upstream: str, remote_id: str, **_kwargs: object
        ) -> bytes:
            self.assertEqual(remote_id, "remote-1")
            raise CrossReferenceError(
                "remote_unreachable", "x", http_status=502
            )

        with patch_fetch(side_effect=fake_fetch) as fetch:
            status, _h, body = call_json("POST", verify_path(first))
        self.assertEqual(status, "200 OK")
        self.assertEqual([r["remote_id"] for r in body["results"]], ["remote-1"])
        fetch.assert_called_once_with(UPSTREAM, "remote-1")

    def test_remote_id_is_used_as_registered(self) -> None:
        start_id = register_local()
        post_reference(start_id, remote_id="remote 1")
        with patch_fetch() as fetch:
            status, _h, body = call_json("POST", verify_path(start_id))
        self.assertEqual(status, "200 OK")
        # The stored value is passed verbatim; percent-encoding stays
        # inside fetch_remote_resource, as at registration.
        fetch.assert_called_once_with(UPSTREAM, "remote 1")
        self.assertEqual(body["results"][0]["remote_id"], "remote 1")


class CrossReferenceVerifyRecomputationTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def test_result_is_recomputed_from_current_data_each_call(self) -> None:
        start_id = register_local()
        post_reference(start_id)
        resolved_id = local_id_for(REMOTE_ID)

        with patch_fetch():
            status, _h, body = call_json("POST", verify_path(start_id))
        self.assertEqual(body["results"][0]["status"], "matched")

        # Deregistering the resolved local flips the status immediately.
        self.assertEqual(call("DELETE", f"/resources/{resolved_id}")[0], "200 OK")
        with patch_fetch():
            status, _h, body = call_json("POST", verify_path(start_id))
        self.assertEqual(
            body["results"][0]["status"], "local_resource_missing"
        )

    def test_verify_is_read_only(self) -> None:
        start_id = register_local()
        post_reference(start_id)
        resolved_id = local_id_for(REMOTE_ID)

        status, _h, summary_before = call("GET", "/")
        self.assertEqual(status, "200 OK")
        status, _h, resources_before = call("GET", "/resources")
        self.assertEqual(status, "200 OK")

        with patch_fetch() as fetch:
            put_spy = mock.Mock(wraps=cache_store.put_verified)
            with mock.patch.object(cache_store, "put_verified", put_spy):
                status, _h, _body = call_json(
                    "POST", verify_path(start_id)
                )
        self.assertEqual(status, "200 OK")
        fetch.assert_called_once()
        # Verification never writes the layer cache.
        put_spy.assert_not_called()

        # References, resources and edges are untouched.
        status, _h, summary_after = call("GET", "/")
        self.assertEqual(summary_after, summary_before)
        status, _h, resources_after = call("GET", "/resources")
        self.assertEqual(resources_after, resources_before)
        status, _h, deps = call_json(
            "GET", f"/resources/{start_id}/dependencies"
        )
        self.assertEqual(deps["dependencies"], [resolved_id])

        # Repeating the verification yields the identical body.
        with patch_fetch():
            _s, _h, first_raw = call("POST", verify_path(start_id))
        with patch_fetch():
            _s, _h, second_raw = call("POST", verify_path(start_id))
        self.assertEqual(first_raw, second_raw)

    def test_verify_does_not_use_registration_resolution_path(self) -> None:
        start_id = register_local()
        post_reference(start_id)
        # Verification reuses fetch + parse directly and never invokes the
        # registration resolution that enforces the digest before caching.
        with mock.patch(
            "provenance_api.app.resolve_remote",
            side_effect=AssertionError("must not resolve"),
        ):
            with patch_fetch(return_value=b"not json"):
                status, _h, body = call_json(
                    "POST", verify_path(start_id)
                )
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            body["results"][0]["status"], "resolution_failed"
        )


if __name__ == "__main__":
    unittest.main()
