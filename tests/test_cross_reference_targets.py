from __future__ import annotations

import io
import json
import unittest
from unittest import mock

from provenance_api.app import application, reset_state

PATH = "/cross-reference-targets"

UPSTREAM = "https://repo.example.invalid"
REMOTE_NAME = "remote-model"
DIGEST = "a" * 64
SOURCE = "https://repo.example.invalid/sources/remote-42"

FIELDS = [
    "local_id",
    "repositories",
    "remote_ids",
    "reference_count",
    "resources",
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


def call_targets(
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


class CrossReferenceTargetsViewTests(unittest.TestCase):
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

    def test_one_reference_one_entry_with_five_fields_in_order(self) -> None:
        start_id = register_local()
        with patch_resolve():
            status, _created = post_reference(start_id, reference_body())
        self.assertEqual(status, "201 Created")
        resolved_id = local_id_for("remote-42")

        status, _h, usage = call_targets()
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(usage), 1)
        entry = usage[0]
        self.assertEqual(list(entry), FIELDS)
        self.assertEqual(entry["local_id"], resolved_id)
        self.assertEqual(entry["repositories"], ["partner"])
        self.assertEqual(entry["remote_ids"], ["remote-42"])
        self.assertEqual(entry["reference_count"], 1)
        self.assertEqual(entry["resources"], [start_id])

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

    def test_entries_follow_first_local_id_occurrence(self) -> None:
        s1 = register_local(name="s1")
        s2 = register_local(name="s2", digest="c1" * 32)
        s3 = register_local(name="s3", digest="c2" * 32)

        # Resolved locals appear in registration order beta, then two
        # references reusing the same alpha local: one entry only.
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
            # Same digest/name/category: the resolved local resource is
            # reused, while another start resource joins.
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

        beta_local = local_id_for("rb-1")
        alpha_local = local_id_for("ra-1")
        self.assertEqual(alpha_local, local_id_for("ra-2"))

        status, _h, usage = call_targets()
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            [entry["local_id"] for entry in usage], [beta_local, alpha_local]
        )

        beta, alpha = usage
        self.assertEqual(beta["repositories"], ["beta"])
        self.assertEqual(beta["remote_ids"], ["rb-1"])
        self.assertEqual(beta["reference_count"], 1)
        self.assertEqual(beta["resources"], [s1])

        # Two records into one resolved local accumulate one by one.
        self.assertEqual(alpha["repositories"], ["alpha"])
        self.assertEqual(alpha["remote_ids"], ["ra-1", "ra-2"])
        self.assertEqual(alpha["reference_count"], 2)
        self.assertEqual(alpha["resources"], [s2, s3])

    def test_repositories_deduplicated_in_reference_order(self) -> None:
        s1 = register_local(name="s1")
        s2 = register_local(name="s2", digest="c1" * 32)
        s3 = register_local(name="s3", digest="c2" * 32)
        s4 = register_local(name="s4", digest="c3" * 32)
        # Each start resource can place at most one reference at a given
        # resolved local (a second would duplicate the dependency edge),
        # so four distinct starts are needed. All references resolve to
        # the same local (same digest/name/category); the repositories
        # arrive in the order gamma, beta, gamma, alpha.
        with patch_resolve():
            post_reference(
                s1,
                reference_body(
                    repository="gamma",
                    upstream="https://gamma.invalid",
                    remote_id="r1",
                ),
            )
        with patch_resolve():
            post_reference(
                s2,
                reference_body(
                    repository="beta",
                    upstream="https://beta.invalid",
                    remote_id="r2",
                ),
            )
        with patch_resolve():
            # gamma again from another start: listed once, keeps its
            # first-appearance slot.
            post_reference(
                s3,
                reference_body(
                    repository="gamma",
                    upstream="https://gamma.invalid",
                    remote_id="r3",
                ),
            )
        with patch_resolve():
            post_reference(
                s4,
                reference_body(
                    repository="alpha",
                    upstream="https://alpha.invalid",
                    remote_id="r4",
                ),
            )

        status, _h, usage = call_targets()
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(usage), 1)
        entry = usage[0]
        self.assertEqual(entry["repositories"], ["gamma", "beta", "alpha"])
        # Remote ids are never deduplicated: one per reference, in order.
        self.assertEqual(entry["remote_ids"], ["r1", "r2", "r3", "r4"])
        self.assertEqual(entry["reference_count"], 4)
        self.assertEqual(entry["resources"], [s1, s2, s3, s4])

    def test_repeated_remote_ids_listed_per_record_not_merged(self) -> None:
        s1 = register_local(name="s1")
        s2 = register_local(name="s2", digest="c1" * 32)
        # The same remote id via two different repositories resolves to
        # the same local (same digest/name/category): remote_ids keeps
        # both entries and the count follows suit.
        with patch_resolve():
            post_reference(
                s1,
                reference_body(
                    repository="first",
                    upstream="https://first.invalid",
                    remote_id="shared",
                ),
            )
        with patch_resolve():
            post_reference(
                s2,
                reference_body(
                    repository="second",
                    upstream="https://second.invalid",
                    remote_id="shared",
                ),
            )

        status, _h, usage = call_targets()
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(usage), 1)
        entry = usage[0]
        self.assertEqual(entry["repositories"], ["first", "second"])
        self.assertEqual(entry["remote_ids"], ["shared", "shared"])
        self.assertEqual(entry["reference_count"], 2)
        self.assertEqual(entry["resources"], [s1, s2])

    def test_resources_deduplicated_in_resource_registration_order(self) -> None:
        s1 = register_local(name="s1")
        s2 = register_local(name="s2", digest="c1" * 32)
        s3 = register_local(name="s3", digest="c2" * 32)
        s4 = register_local(name="s4", digest="c3" * 32)

        # All four references resolve to the same local (same
        # digest/name/category); each needs a distinct start because one
        # start cannot hold two edges at the same local. They arrive in
        # a shuffled start order (s4, s1, s3, s2): the resources list
        # follows resource registration order, not first appearance.
        with patch_resolve():
            post_reference(s4, reference_body(repository="repo", remote_id="r1"))
        with patch_resolve():
            post_reference(s1, reference_body(repository="repo", remote_id="r2"))
        with patch_resolve():
            post_reference(s3, reference_body(repository="repo", remote_id="r3"))
        with patch_resolve():
            post_reference(s2, reference_body(repository="repo", remote_id="r4"))

        status, _h, usage = call_targets()
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(usage), 1)
        entry = usage[0]
        self.assertEqual(entry["reference_count"], 4)
        self.assertEqual(entry["resources"], [s1, s2, s3, s4])
        # Remote ids stay in reference registration order.
        self.assertEqual(entry["remote_ids"], ["r1", "r2", "r3", "r4"])

    def test_local_id_echoed_verbatim(self) -> None:
        start_id = register_local()
        with patch_resolve():
            post_reference(start_id, reference_body())
        status, _h, usage = call_targets()
        self.assertEqual(status, "200 OK")
        self.assertEqual(usage[0]["local_id"], local_id_for("remote-42"))

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

        a1_local = local_id_for("a1")
        b1_local = local_id_for("b1")
        a2_local = local_id_for("a2")

        # Delete the first record of the alpha-a1 local; its entry drops
        # entirely, and the first-appearance order is re-derived from the
        # remaining records (b1 now precedes a2).
        status = delete_reference(s1, "alpha", "a1")
        self.assertEqual(status, "200 OK")

        status, _h, usage = call_targets()
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            [entry["local_id"] for entry in usage], [b1_local, a2_local]
        )
        self.assertNotIn(a1_local, [entry["local_id"] for entry in usage])

        a2_entry = next(
            entry for entry in usage if entry["local_id"] == a2_local
        )
        self.assertEqual(a2_entry["reference_count"], 1)
        self.assertEqual(a2_entry["remote_ids"], ["a2"])
        self.assertEqual(a2_entry["repositories"], ["alpha"])
        self.assertEqual(a2_entry["resources"], [s1])

        # Deleting the last record of the surviving local leaves an empty
        # array.
        self.assertEqual(delete_reference(s2, "beta", "b1"), "200 OK")
        self.assertEqual(delete_reference(s1, "alpha", "a2"), "200 OK")
        status, _h, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

    def test_first_appearance_order_redetermined_when_earlier_local_drops(self) -> None:
        # Three distinct locals L1, L2, L3 registered in that order.
        s1 = register_local(name="s1")
        with patch_resolve(digest="1" * 64, name="m1", source="u1"):
            post_reference(s1, reference_body(repository="repo", remote_id="x1", digest="1" * 64))
        with patch_resolve(digest="2" * 64, name="m2", source="u2"):
            post_reference(s1, reference_body(repository="repo", remote_id="x2", digest="2" * 64))
        with patch_resolve(digest="3" * 64, name="m3", source="u3"):
            post_reference(s1, reference_body(repository="repo", remote_id="x3", digest="3" * 64))

        l1, l2, l3 = (local_id_for(rid) for rid in ("x1", "x2", "x3"))
        status, _h, usage = call_targets()
        self.assertEqual([e["local_id"] for e in usage], [l1, l2, l3])

        # Remove the middle local's only reference: L2 drops, L3 keeps
        # its re-derived first-appearance slot, nothing is re-sorted.
        self.assertEqual(delete_reference(s1, "repo", "x2"), "200 OK")
        status, _h, usage = call_targets()
        self.assertEqual([e["local_id"] for e in usage], [l1, l3])

        # Remove the first local: L3 is now first, re-derived from the
        # remaining records rather than pinned at its old slot.
        self.assertEqual(delete_reference(s1, "repo", "x1"), "200 OK")
        status, _h, usage = call_targets()
        self.assertEqual([e["local_id"] for e in usage], [l3])

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

        status, _h, usage = call_targets()
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(usage), 1)
        entry = usage[0]
        self.assertEqual(entry["local_id"], local_id_for("r2"))
        self.assertEqual(entry["reference_count"], 1)
        self.assertEqual(entry["remote_ids"], ["r2"])
        self.assertEqual(entry["repositories"], ["shared"])
        self.assertEqual(entry["resources"], [s2])

        # Deregistering the last start resource leaves an empty array.
        self.assertEqual(delete_resource(s2), "200 OK")
        status, _h, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

    def test_dependency_edge_removal_does_not_change_usage(self) -> None:
        start_id = register_local()
        with patch_resolve():
            post_reference(start_id, reference_body())
        _status, _h, before = call_targets()

        self.assertEqual(
            delete_edge(start_id, local_id_for("remote-42")), "200 OK"
        )

        status, _h, after = call_targets()
        self.assertEqual(status, "200 OK")
        self.assertEqual(after, before)

    def test_deregistered_resolved_local_still_listed(self) -> None:
        # Dependency removal or deregistration of the resolved local
        # resource never rewrites historical references: the local id is
        # still echoed verbatim.
        s1 = register_local(name="s1")
        with patch_resolve():
            post_reference(s1, reference_body(repository="repo", remote_id="r1"))
        first_local = local_id_for("r1")

        self.assertEqual(delete_resource(first_local), "200 OK")

        status, _h, usage = call_targets()
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(usage), 1)
        entry = usage[0]
        self.assertEqual(entry["local_id"], first_local)
        self.assertEqual(entry["reference_count"], 1)
        self.assertEqual(entry["remote_ids"], ["r1"])
        self.assertEqual(entry["repositories"], ["repo"])
        self.assertEqual(entry["resources"], [s1])

    def test_view_never_contacts_upstream_and_is_read_only(self) -> None:
        with mock.patch(
            "provenance_api.app.resolve_remote",
            side_effect=AssertionError("must not resolve"),
        ):
            status, _h, usage = call_targets()
        self.assertEqual(status, "200 OK")
        self.assertEqual(usage, [])

        # Repeated reads are identical.
        self.assertEqual(call("GET", PATH)[2], call("GET", PATH)[2])

    def test_existing_views_unchanged(self) -> None:
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

        status, _h, usage = call(
            "GET", "/cross-reference-usage"
        )
        self.assertEqual(status, "200 OK")
        repository_usage = json.loads(usage)
        self.assertEqual(
            list(repository_usage[0]),
            [
                "repository",
                "upstream",
                "reference_count",
                "resources",
                "resource_count",
                "local_ids",
            ],
        )


class CrossReferenceTargetsRequestTests(unittest.TestCase):
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
        status, _h, body = call_targets(body=b"x")
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
            status, _h, body = call_targets(query_string=query_string)
            self.assertEqual(status, "400 Bad Request", query_string)
            self.assertEqual(body["error"], "invalid_request")

    def test_methods_other_than_get_return_405_with_get_only_allow(self) -> None:
        for method in ("POST", "PUT", "DELETE", "PATCH", "HEAD"):
            status, headers, body = call_targets(method)
            self.assertEqual(status, "405 Method Not Allowed", method)
            self.assertIn(("Allow", "GET"), headers)
            allow_values = [value for key, value in headers if key == "Allow"]
            self.assertEqual(allow_values, ["GET"])
            self.assertEqual(body["error"], "method_not_allowed")

    def test_non_get_method_with_body_or_query_still_returns_405(self) -> None:
        # Method is decided before the request shape is examined.
        status, headers, body = call_targets("DELETE", query_string="x=1")
        self.assertEqual(status, "405 Method Not Allowed")
        self.assertEqual(headers and [v for k, v in headers if k == "Allow"], ["GET"])
        self.assertEqual(body["error"], "method_not_allowed")

        status, headers, body = call_targets("POST", body=b"{}")
        self.assertEqual(status, "405 Method Not Allowed")
        self.assertEqual([v for k, v in headers if k == "Allow"], ["GET"])
        self.assertEqual(body["error"], "method_not_allowed")


if __name__ == "__main__":
    unittest.main()
