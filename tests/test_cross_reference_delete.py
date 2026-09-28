from __future__ import annotations

import io
import json
import unittest
from urllib.parse import quote

from provenance_api.app import application, reset_state
from provenance_api.cross_references import CrossReferenceStore

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

DELETE_FIELDS = ["resource_id", "repository", "upstream", "remote_id", "digest"]


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
) -> tuple[str, list[tuple[str, str]], object]:
    status, headers, raw = call(method, path, body, **kwargs)  # type: ignore[arg-type]
    return status, headers, json.loads(raw.decode("utf-8"))


def register_local(
    name: str = "local-a",
    category: str = "code",
    digest: str = "b" * 64,
) -> str:
    payload = {"name": name, "category": category, "digest": digest}
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
    digest: str = DIGEST,
    source: str = SOURCE,
):
    from unittest import mock

    from provenance_api.cross_references import Resolution

    resolution = Resolution(
        name=name,
        category="model",
        digest=digest,
        source=source,
        raw=json.dumps(
            {
                "name": name,
                "category": REMOTE_CATEGORY,
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


def delete_path(resource_id: str, repository: str, remote_id: str, **kwargs):
    return call(
        "DELETE",
        f"/resources/{resource_id}/cross-references/"
        f"{quote(repository, safe='')}/{quote(remote_id, safe='')}",
        **kwargs,
    )


def delete_reference(resource_id: str, repository: str = "partner", remote_id: str = REMOTE_ID):
    return call_json(
        "DELETE",
        f"/resources/{resource_id}/cross-references/"
        f"{quote(repository, safe='')}/{quote(remote_id, safe='')}",
    )


class CrossReferenceDeleteTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def _register_one(self) -> tuple[str, str]:
        resource_id = register_local()
        with patch_resolve():
            status, _h, body = post_reference(resource_id)
        self.assertEqual(status, "201 Created", body)
        status, _h, deps = call_json(
            "GET", f"/resources/{resource_id}/dependencies"
        )
        local_id = deps["dependencies"][0]
        return resource_id, local_id

    def test_success_returns_200_with_five_fields_in_order(self) -> None:
        resource_id, local_id = self._register_one()
        status, headers, raw = delete_path(resource_id, "partner", REMOTE_ID)
        self.assertEqual(status, "200 OK")
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )
        body = json.loads(raw.decode("utf-8"))
        self.assertEqual(list(body), DELETE_FIELDS)
        self.assertEqual(body["resource_id"], resource_id)
        self.assertEqual(body["repository"], "partner")
        self.assertEqual(body["upstream"], UPSTREAM)
        self.assertEqual(body["remote_id"], REMOTE_ID)
        self.assertEqual(body["digest"], DIGEST)
        # Compact JSON ending in exactly one newline.
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        self.assertNotIn(b" ", raw)
        self.assertEqual(
            raw,
            (
                json.dumps(body, separators=(",", ":")).encode("utf-8")
                + b"\n"
            ),
        )
        self.assertNotIn(b"local_id", raw)

    def test_only_reference_record_is_removed(self) -> None:
        resource_id, local_id = self._register_one()

        status, _h, body = delete_reference(resource_id)
        self.assertEqual(status, "200 OK", body)

        # The reference disappears from the per-resource listing.
        status, _h, refs = call_json(
            "GET", f"/resources/{resource_id}/cross-references"
        )
        self.assertEqual(refs, {"cross_references": []})

        # The resolved local resource survives.
        status, _h, resolved = call_json("GET", f"/resources/{local_id}")
        self.assertEqual(status, "200 OK")

        # The dependency edge survives: direct query, impact and graph view.
        status, _h, deps = call_json(
            "GET", f"/resources/{resource_id}/dependencies"
        )
        self.assertEqual(deps["dependencies"], [local_id])
        status, _h, impact = call_json(
            "GET", f"/resources/{local_id}/impact"
        )
        self.assertEqual(impact["resources"], [resource_id])
        status, _h, graph = call_json("GET", "/graph")
        self.assertIn(
            {"resource_id": resource_id, "dependency_id": local_id},
            graph["edges"],
        )

    def test_global_summary_recomputes_without_the_record(self) -> None:
        resource_id, local_id = self._register_one()
        status, _h, summary = call_json("GET", "/")
        self.assertEqual(len(summary), 1)

        status, _h, body = delete_reference(resource_id)
        self.assertEqual(status, "200 OK", body)

        status, _h, summary = call_json("GET", "/")
        self.assertEqual(summary, [])

    def test_deleting_one_keeps_other_references(self) -> None:
        first, _local = self._register_one()
        second = register_local(name="second", digest="c" * 64)
        second_body = dict(
            REFERENCE_BODY,
            repository="other",
            remote_id="remote-7",
            digest="d" * 64,
        )
        with patch_resolve(
            name="other-remote",
            digest="d" * 64,
            source="https://repo.example.invalid/other",
        ):
            status, _h, body = post_reference(second, second_body)
        self.assertEqual(status, "201 Created", body)

        status, _h, body = delete_reference(first)
        self.assertEqual(status, "200 OK", body)

        status, _h, summary = call_json("GET", "/")
        self.assertEqual(len(summary), 1)
        self.assertEqual(summary[0]["resource_id"], second)
        self.assertEqual(summary[0]["repository"], "other")
        status, _h, refs = call_json(
            "GET", f"/resources/{second}/cross-references"
        )
        self.assertEqual(len(refs["cross_references"]), 1)

    def test_repeat_delete_is_identical_404(self) -> None:
        resource_id, _local = self._register_one()
        status, _h, body = delete_reference(resource_id)
        self.assertEqual(status, "200 OK", body)
        for _ in range(2):
            status, _h, body = delete_reference(resource_id)
            self.assertEqual(status, "404 Not Found")
            self.assertEqual(body["error"], "reference_not_found")

    def test_never_registered_pair_is_404(self) -> None:
        resource_id = register_local()
        status, _h, body = delete_reference(resource_id)
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "reference_not_found")

    def test_other_resource_pair_mismatch_is_404(self) -> None:
        owner, _local = self._register_one()
        other = register_local(name="other", digest="c" * 64)
        status, _h, body = delete_reference(other)
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "reference_not_found")
        # The owner's reference is untouched.
        status, _h, refs = call_json(
            "GET", f"/resources/{owner}/cross-references"
        )
        self.assertEqual(len(refs["cross_references"]), 1)

    def test_missing_start_resource_is_404_before_reference(self) -> None:
        # Even a pair that exists for another resource reports the missing
        # start first.
        owner, _local = self._register_one()
        status, _h, body = delete_reference("missing")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")
        status, _h, refs = call_json(
            "GET", f"/resources/{owner}/cross-references"
        )
        self.assertEqual(len(refs["cross_references"]), 1)

    def test_reregistration_after_delete_returns_201(self) -> None:
        resource_id, local_id = self._register_one()
        status, _h, body = delete_reference(resource_id)
        self.assertEqual(status, "200 OK", body)

        with patch_resolve() as resolve:
            status, _h, body = post_reference(resource_id)
        self.assertEqual(status, "201 Created", body)
        resolve.assert_called_once_with(UPSTREAM, REMOTE_ID, DIGEST)
        self.assertEqual(body["resource_id"], resource_id)
        self.assertEqual(list(body), DELETE_FIELDS)

        # Exactly one edge, still pointing at the same local resource.
        status, _h, deps = call_json(
            "GET", f"/resources/{resource_id}/dependencies"
        )
        self.assertEqual(deps["dependencies"], [local_id])

        # The reference is back in the global summary.
        status, _h, summary = call_json("GET", "/")
        self.assertEqual(len(summary), 1)
        self.assertEqual(summary[0]["local_id"], local_id)
        self.assertEqual(summary[0]["edge_present"], True)

    def test_reregistration_after_delete_and_edge_removal_rebuilds_edge(
        self,
    ) -> None:
        resource_id, local_id = self._register_one()
        status, _h, _b = delete_reference(resource_id)
        self.assertEqual(status, "200 OK")
        # The retained edge is separately removed in the meantime.
        status, _h, body = call_json(
            "DELETE", f"/resources/{resource_id}/dependencies/{local_id}"
        )
        self.assertEqual(status, "200 OK", body)

        with patch_resolve():
            status, _h, body = post_reference(resource_id)
        self.assertEqual(status, "201 Created", body)
        status, _h, deps = call_json(
            "GET", f"/resources/{resource_id}/dependencies"
        )
        self.assertEqual(deps["dependencies"], [local_id])

    def test_reregistration_frees_pair_and_repository_binding(self) -> None:
        resource_id, _local = self._register_one()
        status, _h, _b = delete_reference(resource_id)
        self.assertEqual(status, "200 OK")

        # The repository name is unbound once it has no records left, so it
        # can bind to a different upstream; the pair is free as well.
        body = dict(REFERENCE_BODY, upstream="https://other.example.invalid")
        with patch_resolve():
            status, _h, created = post_reference(resource_id, body)
        self.assertEqual(status, "201 Created", created)
        self.assertEqual(created["upstream"], "https://other.example.invalid")

    def test_binding_is_kept_while_another_reference_uses_it(self) -> None:
        first, _local = self._register_one()
        second = register_local(name="second", digest="c" * 64)
        second_body = dict(REFERENCE_BODY, remote_id="remote-7", digest="d" * 64)
        with patch_resolve(
            name="other-remote",
            digest="d" * 64,
            source="https://repo.example.invalid/other",
        ):
            status, _h, body = post_reference(second, second_body)
        self.assertEqual(status, "201 Created", body)

        status, _h, _b = delete_reference(first)
        self.assertEqual(status, "200 OK")

        # "partner" is still bound to UPSTREAM by the second record.
        body = dict(
            REFERENCE_BODY,
            remote_id="remote-42",
            upstream="https://other.example.invalid",
        )
        with patch_resolve():
            status, _h, body = post_reference(first, body)
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "repository_conflict")

    def test_percent_encoded_segments_are_matched_verbatim(self) -> None:
        resource_id = register_local()
        body = dict(
            REFERENCE_BODY,
            repository="part ner",
            remote_id="a b",
        )
        with patch_resolve():
            status, _h, created = post_reference(resource_id, body)
        self.assertEqual(status, "201 Created", created)
        status, _h, raw = delete_path(resource_id, "part ner", "a b")
        self.assertEqual(status, "200 OK", raw)
        decoded = json.loads(raw.decode("utf-8"))
        self.assertEqual(decoded["repository"], "part ner")
        self.assertEqual(decoded["remote_id"], "a b")

    def test_empty_segments_return_400(self) -> None:
        resource_id = register_local()
        for path in (
            f"/resources/{resource_id}/cross-references//remote-42",
            f"/resources/{resource_id}/cross-references/partner/",
        ):
            status, _h, body = call_json("DELETE", path)
            self.assertEqual(status, "400 Bad Request", path)
            self.assertEqual(body["error"], "invalid_request", path)

    def test_separator_segments_return_400(self) -> None:
        resource_id, _local = self._register_one()
        for path in (
            f"/resources/{resource_id}/cross-references/a%2Fb/remote-42",
            f"/resources/{resource_id}/cross-references/a%5Cb/remote-42",
            f"/resources/{resource_id}/cross-references/partner/a%2Fb",
            f"/resources/{resource_id}/cross-references/partner/a%5Cb",
        ):
            status, _h, body = call_json("DELETE", path)
            self.assertEqual(status, "400 Bad Request", path)
            self.assertEqual(body["error"], "invalid_request", path)
        # Nothing was deleted.
        status, _h, summary = call_json("GET", "/")
        self.assertEqual(len(summary), 1)

    def test_query_parameters_return_400(self) -> None:
        resource_id, _local = self._register_one()
        path = f"/resources/{resource_id}/cross-references/partner/remote-42"
        status, _h, body = call_json(
            "DELETE", path, query_string="x=1"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        status, _h, summary = call_json("GET", "/")
        self.assertEqual(len(summary), 1)

    def test_declared_non_empty_body_returns_400(self) -> None:
        resource_id, _local = self._register_one()
        path = f"/resources/{resource_id}/cross-references/partner/remote-42"
        status, _h, body = call_json(
            "DELETE",
            path,
            b"x",
            headers={"CONTENT_TYPE": "text/plain"},
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_zero_length_and_omitted_body_succeed(self) -> None:
        for index, omit in enumerate((False, True)):
            resource_id = register_local(name=f"local-{index}", digest=("1" * 63) + str(index + 1))
            with patch_resolve():
                status, _h, created = post_reference(resource_id)
            self.assertEqual(status, "201 Created", created)
            path = (
                f"/resources/{resource_id}/cross-references/partner/remote-42"
            )
            status, _h, body = call(
                "DELETE", path, b"", omit_content_length=omit
            )
            self.assertEqual(status, "200 OK", (omit, body))

    def test_other_methods_return_405_without_deleting(self) -> None:
        resource_id, _local = self._register_one()
        path = f"/resources/{resource_id}/cross-references/partner/remote-42"
        for method in ("GET", "POST", "PUT", "PATCH"):
            status, headers, body = call_json(method, path)
            self.assertEqual(status, "405 Method Not Allowed", method)
            self.assertIn(("Allow", "DELETE"), headers)
            self.assertEqual(body["error"], "method_not_allowed")
        status, _h, summary = call_json("GET", "/")
        self.assertEqual(len(summary), 1)

    def test_collection_delete_still_405_get_post_only(self) -> None:
        resource_id = register_local()
        status, headers, body = call_json(
            "DELETE", f"/resources/{resource_id}/cross-references"
        )
        self.assertEqual(status, "405 Method Not Allowed")
        self.assertIn(("Allow", "GET, POST"), headers)
        self.assertEqual(body["error"], "method_not_allowed")

    def test_invalid_start_id_returns_400(self) -> None:
        for path in (
            "/resources//cross-references/partner/remote-42",
            "/resources/a/b/cross-references/partner/remote-42",
        ):
            status, _h, body = call_json("DELETE", path)
            self.assertEqual(status, "400 Bad Request", path)
            self.assertEqual(body["error"], "invalid_request", path)


class CrossReferenceStoreRemovalTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def test_remove_missing_pair_is_none(self) -> None:
        store = CrossReferenceStore()
        self.assertIsNone(store.remove_one("nope", "partner", "remote-42"))


if __name__ == "__main__":
    unittest.main()
