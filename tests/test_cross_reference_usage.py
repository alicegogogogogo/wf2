from __future__ import annotations

import io
import json
import unittest
from unittest import mock

from provenance_api.app import application, reset_state

PATH = "/cross-reference-usage"

UPSTREAM = "https://repo.example.invalid"
REMOTE_NAME = "remote-model"
DIGEST = "a" * 64
SOURCE = "https://repo.example.invalid/sources/remote-42"

FIELDS = [
    "repository",
    "upstream",
    "reference_count",
    "resources",
    "resource_count",
    "local_ids",
]


def call(
    method: str,
    path: str = PATH,
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


def call_usage(
    method: str = "GET",
    body: bytes = b"",
    **kwargs: object,
) -> tuple[str, list[tuple[str, str]], object]:
    status, headers, raw = call(method, PATH, body, **kwargs)  # type: ignore[arg-type]
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
    status, _h, body = call(
        "POST",
        "/resources",
        json.dumps(payload).encode("utf-8"),
        headers={"CONTENT_TYPE": "application/json"},
    )
    assert status == "201 Created", (status, body)
    return str(json.loads(body)["id"])


def patch_resolve(
    *,
    name: str = REMOTE_NAME,
    category: str = "Model",
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


def reference_body(
    repository: str = "partner",
    upstream: str = UPSTREAM,
    remote_id: str = "remote-42",
    digest: str = DIGEST,
) -> dict[str, object]:
    return {
        "repository": repository,
        "upstream": upstream,
        "remote_id": remote_id,
        "digest": digest,
    }


def post_reference(
    resource_id: str,
    body: dict[str, object],
) -> tuple[str, object]:
    status, headers, raw = call(
        "POST",
        f"/resources/{resource_id}/cross-references",
        json.dumps(body).encode("utf-8"),
        headers={"CONTENT_TYPE": "application/json"},
    )
    return status, json.loads(raw.decode("utf-8"))


def local_id_for(remote_id: str) -> str:
    status, _h, raw = call("GET", "/")
    assert status == "200 OK"
    for record in json.loads(raw):
        if record["remote_id"] == remote_id:
            return str(record["local_id"])
    raise KeyError(remote_id)


def delete_reference(resource_id: str, repository: str, remote_id: str) -> str:
    status, _h, _body = call(
        "DELETE",
        f"/resources/{resource_id}/cross-references/"
        f"{repository}/{remote_id}",
    )
    return status


def delete_resource(resource_id: str) -> str:
    status, _h, _body = call("DELETE", f"/resources/{resource_id}")
    return status


def delete_edge(resource_id: str, dependency_id: str) -> str:
    status, _h, _body = call(
        "DELETE", f"/resources/{resource_id}/dependencies/{dependency_id}"
    )
    return status


class CrossReferenceUsageViewTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    # --- Shape -------------------------------------------------------------

    def test_empty_view_is_empty_array_with_newline(self) -> None:
        status, headers, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            ("Content-Type", "application/json; charset=utf-8"),
            next(h for h in headers if h[0] == "Content-Type"),
        )
        self.assertEqual(raw, b"[]\n")

    def test_one_reference_one_entry_with_six_fields_in_order(self) -> None:
        start_id = register_local()
        with patch_resolve():
            status, _created = post_reference(start_id, reference_body())
        self.assertEqual(status, "201 Created")
        resolved_id = local_id_for("remote-42")

        status, _h, usage = call_usage()
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(usage), 1)
        entry = usage[0]
        self.assertEqual(list(entry), FIELDS)
        self.assertEqual(entry["repository"], "partner")
        self.assertEqual(entry["upstream"], UPSTREAM)
        self.assertEqual(entry["reference_count"], 1)
        self.assertEqual(entry["resources"], [start_id])
        self.assertEqual(entry["resource_count"], 1)
        self.assertEqual(entry["local_ids"], [resolved_id])

    def test_compact_json_single_trailing_newline(self) -> None:
        start_id = register_local()
        with patch_resolve():
            post_reference(start_id, reference_body())
        status, _h, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertTrue(raw.endswith(b"\n"))
        self.assertEqual(raw.count(b"\n"), 1)
        self.assertNotIn(b" ", raw)

    # --- Grouping, order, counting and deduplication -----------------------

    def test_entries_follow_first_repository_occurrence(self) -> None:
        s1 = register_local(name="s1")
        s2 = register_local(name="s2", digest="c1" * 32)
        s3 = register_local(name="s3", digest="c2" * 32)

        # "beta" is seen first, then "alpha": entry order follows reference
        # registration order, never the alphabet.
        with patch_resolve(digest="d" * 64, name="m-beta", source="u-b"):
            self.assertEqual(
                post_reference(
                    s1,
                    reference_body(
                        repository="beta",
                        upstream="https://beta.invalid",
                        remote_id="rb-1",
                        digest="d" * 64,
                    ),
                )[0],
                "201 Created",
            )
        with patch_resolve(digest="e" * 64, name="m-a1", source="u-a1"):
            self.assertEqual(
                post_reference(
                    s2,
                    reference_body(
                        repository="alpha",
                        upstream="https://alpha.invalid",
                        remote_id="ra-1",
                        digest="e" * 64,
                    ),
                )[0],
                "201 Created",
            )
        with patch_resolve(digest="e" * 64, name="m-a1", source="u-a1"):
            # Same digest/name/category as the previous remote: the resolved
            # local resource is reused, while another start resource joins.
            self.assertEqual(
                post_reference(
                    s3,
                    reference_body(
                        repository="alpha",
                        upstream="https://alpha.invalid",
                        remote_id="ra-2",
                        digest="e" * 64,
                    ),
                )[0],
                "201 Created",
            )

        status, _h, usage = call_usage()
        self.assertEqual(status, "200 OK")
        self.assertEqual([entry["repository"] for entry in usage], ["beta", "alpha"])

        beta, alpha = usage
        self.assertEqual(beta["upstream"], "https://beta.invalid")
        self.assertEqual(beta["reference_count"], 1)
        self.assertEqual(beta["resources"], [s1])
        self.assertEqual(beta["resource_count"], 1)

        # Two records across two resources accumulate; the shared resolved
        # local appears once.
        alpha_local = local_id_for("ra-1")
        self.assertEqual(alpha_local, local_id_for("ra-2"))
        self.assertEqual(alpha["upstream"], "https://alpha.invalid")
        self.assertEqual(alpha["reference_count"], 2)
        self.assertEqual(alpha["resources"], [s2, s3])
        self.assertEqual(alpha["resource_count"], 2)
        self.assertEqual(alpha["local_ids"], [alpha_local])

    def test_resources_deduplicated_in_resource_registration_order(self) -> None:
        s1 = register_local(name="s1")
        s2 = register_local(name="s2", digest="c1" * 32)
        s3 = register_local(name="s3", digest="c2" * 32)

        # References arrive interleaved across the three resources.
        with patch_resolve(digest="d" * 64, name="m1", source="u1"):
            post_reference(
                s3,
                reference_body(repository="repo", remote_id="r1", digest="d" * 64),
            )
        with patch_resolve(digest="e" * 64, name="m2", source="u2"):
            post_reference(
                s1,
                reference_body(repository="repo", remote_id="r2", digest="e" * 64),
            )
        with patch_resolve(digest="f" * 64, name="m3", source="u3"):
            post_reference(
                s2,
                reference_body(repository="repo", remote_id="r3", digest="f" * 64),
            )
        with patch_resolve(digest="0" * 64, name="m4", source="u4"):
            # A second reference from s1: the resource is still listed once.
            post_reference(
                s1,
                reference_body(repository="repo", remote_id="r4", digest="0" * 64),
            )

        status, _h, usage = call_usage()
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(usage), 1)
        entry = usage[0]
        self.assertEqual(entry["reference_count"], 4)
        self.assertEqual(entry["resources"], [s1, s2, s3])
        self.assertEqual(entry["resource_count"], 3)

    def test_local_ids_deduplicated_and_registration_ordered(self) -> None:
        # A resource with the remote digest pre-registered locally, before
        # the reference flow starts.
        existing = register_local(
            name=REMOTE_NAME, category="Model", digest=DIGEST, source=SOURCE
        )
        start = register_local(name="start", digest="c1" * 32)

        # First reference resolves to a brand-new local (registered now,
        # i.e. after ``existing``); the second reuses the older existing
        # resource. First reference appearance would list them in the other
        # order, so this proves the local list follows registration order.
        with patch_resolve(digest="e" * 64, name="m-new", source="u-new"):
            post_reference(
                start,
                reference_body(repository="repo", remote_id="r-new", digest="e" * 64),
            )
        with patch_resolve():
            post_reference(
                start,
                reference_body(repository="repo", remote_id="r-old"),
            )

        status, _h, usage = call_usage()
        self.assertEqual(status, "200 OK")
        entry = usage[0]
        self.assertEqual(entry["local_ids"], [existing, local_id_for("r-new")])
        self.assertEqual(entry["reference_count"], 2)
        self.assertEqual(entry["resources"], [start])

    def test_name_and_upstream_echoed_verbatim(self) -> None:
        start_id = register_local()
        raw_name = " PaRtNeR "
        raw_upstream = "https://repo.example.invalid/ "
        with patch_resolve():
            status, _body = post_reference(
                start_id,
                reference_body(
                    repository=raw_name,
                    upstream=raw_upstream,
                ),
            )
        self.assertEqual(status, "201 Created")

        status, _h, usage = call_usage()
        self.assertEqual(status, "200 OK")
        self.assertEqual(usage[0]["repository"], raw_name)
        self.assertEqual(usage[0]["upstream"], raw_upstream)

    # --- Recomputation -----------------------------------------------------

    def test_recomputes_after_single_reference_deletion(self) -> None:
        s1 = register_local(name="s1")
        s2 = register_local(name="s2", digest="c1" * 32)
        with patch_resolve():
            post_reference(s1, reference_body(repository="alpha", remote_id="a1"))
        with patch_resolve(digest="e" * 64, name="m-b", source="u-b"):
            post_reference(
                s2,
                reference_body(
                    repository="beta",
                    upstream="https://beta.invalid",
                    remote_id="b1",
                    digest="e" * 64,
                ),
            )
        with patch_resolve(digest="f" * 64, name="m-a2", source="u-a2"):
            post_reference(
                s1,
                reference_body(
                    repository="alpha", remote_id="a2", digest="f" * 64
                ),
            )

        status = delete_reference(s1, "alpha", "a1")
        self.assertEqual(status, "200 OK")

        status, _h, usage = call_usage()
        self.assertEqual(status, "200 OK")
        alpha = next(entry for entry in usage if entry["repository"] == "alpha")
        self.assertEqual(alpha["reference_count"], 1)
        self.assertEqual(alpha["local_ids"], [local_id_for("a2")])

        # Deleting the last reference of a repository drops the whole entry;
        # the other entry stays in its first-appearance position.
        status = delete_reference(s1, "alpha", "a2")
        self.assertEqual(status, "200 OK")
        status, _h, usage = call_usage()
        self.assertEqual(status, "200 OK")
        self.assertEqual([entry["repository"] for entry in usage], ["beta"])

    def test_start_resource_deregistration_recomputes_aggregates(self) -> None:
        s1 = register_local(name="s1")
        s2 = register_local(name="s2", digest="c1" * 32)
        with patch_resolve():
            post_reference(s1, reference_body(repository="shared", remote_id="r1"))
        with patch_resolve(digest="e" * 64, name="m2", source="u2"):
            post_reference(
                s2,
                reference_body(
                    repository="shared", remote_id="r2", digest="e" * 64
                ),
            )

        status = delete_resource(s1)
        self.assertEqual(status, "200 OK")

        status, _h, usage = call_usage()
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(usage), 1)
        entry = usage[0]
        self.assertEqual(entry["repository"], "shared")
        self.assertEqual(entry["reference_count"], 1)
        self.assertEqual(entry["resources"], [s2])
        self.assertEqual(entry["resource_count"], 1)
        self.assertEqual(entry["local_ids"], [local_id_for("r2")])

        # Deregistering the last start resource leaves an empty array.
        self.assertEqual(delete_resource(s2), "200 OK")
        status, _h, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

    def test_dependency_edge_removal_does_not_change_usage(self) -> None:
        start_id = register_local()
        with patch_resolve():
            post_reference(start_id, reference_body())
        _status, _h, before = call_usage()

        self.assertEqual(
            delete_edge(start_id, local_id_for("remote-42")), "200 OK"
        )

        status, _h, after = call_usage()
        self.assertEqual(status, "200 OK")
        self.assertEqual(after, before)

    def test_deregistered_resolved_local_still_listed_in_local_ids(self) -> None:
        # Dependency removal or deregistration of the resolved local
        # resource never rewrites historical references.
        s1 = register_local(name="s1")
        s2 = register_local(name="s2", digest="c1" * 32)
        with patch_resolve():
            post_reference(s1, reference_body(repository="repo", remote_id="r1"))
        with patch_resolve(digest="e" * 64, name="m2", source="u2"):
            post_reference(
                s2,
                reference_body(
                    repository="repo", remote_id="r2", digest="e" * 64
                ),
            )
        first_local = local_id_for("r1")
        second_local = local_id_for("r2")

        # The first resolved local was registered first; deregistering it
        # leaves its reference (started by s1) intact. The surviving id keeps
        # registration ordering while the dangling id is still listed once.
        self.assertEqual(delete_resource(first_local), "200 OK")

        status, _h, usage = call_usage()
        self.assertEqual(status, "200 OK")
        entry = usage[0]
        self.assertEqual(entry["reference_count"], 2)
        self.assertEqual(entry["resources"], [s1, s2])
        self.assertEqual(entry["local_ids"], [second_local, first_local])

    def test_view_never_contacts_upstream_and_is_read_only(self) -> None:
        with mock.patch(
            "provenance_api.app.resolve_remote",
            side_effect=AssertionError("must not resolve"),
        ):
            status, _h, usage = call_usage()
        self.assertEqual(status, "200 OK")
        self.assertEqual(usage, [])

        # Repeated reads are identical.
        self.assertEqual(call("GET", PATH)[2], call("GET", PATH)[2])

    def test_existing_global_summary_unchanged(self) -> None:
        start_id = register_local()
        with patch_resolve():
            post_reference(start_id, reference_body())
        status, _h, raw = call("GET", "/")
        self.assertEqual(status, "200 OK")
        records = json.loads(raw)
        self.assertEqual(len(records), 1)
        self.assertEqual(
            list(records[0]),
            [
                "resource_id",
                "repository",
                "upstream",
                "remote_id",
                "digest",
                "local_id",
                "edge_present",
            ],
        )


class CrossReferenceUsageRequestTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def test_omitted_content_length_is_ok(self) -> None:
        status, _h, raw = call("GET", PATH, omit_content_length=True)
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

    def test_explicit_zero_length_is_ok(self) -> None:
        status, _h, raw = call(
            "GET", PATH, headers={"CONTENT_LENGTH": "0"}
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

    def test_empty_string_content_length_is_ok(self) -> None:
        status, _h, raw = call(
            "GET", PATH, headers={"CONTENT_LENGTH": ""}
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

    def test_declared_non_empty_body_returns_400(self) -> None:
        status, _h, body = call_usage(body=b"x")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_malformed_content_length_returns_400(self) -> None:
        status, _h, raw = call(
            "GET", PATH, headers={"CONTENT_LENGTH": "abc"}
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(json.loads(raw)["error"], "invalid_request")

    def test_query_parameters_return_400(self) -> None:
        for query_string in ("x=1", "x=", "a=b&c=d", "x=1&x=2"):
            status, _h, body = call_usage(query_string=query_string)
            self.assertEqual(status, "400 Bad Request", query_string)
            self.assertEqual(body["error"], "invalid_request")

    def test_methods_other_than_get_return_405_with_get_only_allow(self) -> None:
        for method in ("POST", "PUT", "DELETE", "PATCH", "HEAD"):
            status, headers, body = call_usage(method)
            self.assertEqual(status, "405 Method Not Allowed", method)
            self.assertIn(("Allow", "GET"), headers)
            allow_values = [value for key, value in headers if key == "Allow"]
            self.assertEqual(allow_values, ["GET"])
            self.assertEqual(body["error"], "method_not_allowed")

    def test_non_get_method_with_body_or_query_still_returns_405(self) -> None:
        # Method is decided before the request shape is examined.
        status, headers, body = call_usage("DELETE", query_string="x=1")
        self.assertEqual(status, "405 Method Not Allowed")
        self.assertEqual(headers and [v for k, v in headers if k == "Allow"], ["GET"])
        self.assertEqual(body["error"], "method_not_allowed")

        status, headers, body = call_usage("POST", body=b"{}")
        self.assertEqual(status, "405 Method Not Allowed")
        self.assertEqual([v for k, v in headers if k == "Allow"], ["GET"])
        self.assertEqual(body["error"], "method_not_allowed")


if __name__ == "__main__":
    unittest.main()
