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

        status, _h, targets = call_targets()
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(targets), 1)
        entry = targets[0]
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

    def test_entries_follow_first_local_occurrence(self) -> None:
        s1 = register_local(name="s1")
        s2 = register_local(name="s2", digest="c1" * 32)
        s3 = register_local(name="s3", digest="c2" * 32)

        # The local resolved for "beta" appears first; the shared local for
        # "alpha" is created second and reused for the third reference.
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
            # local resource is reused, so both references share one entry.
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

        status, _h, targets = call_targets()
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            [entry["local_id"] for entry in targets],
            [beta_local, alpha_local],
        )

        beta, alpha = targets
        self.assertEqual(beta["repositories"], ["beta"])
        self.assertEqual(beta["remote_ids"], ["rb-1"])
        self.assertEqual(beta["reference_count"], 1)
        self.assertEqual(beta["resources"], [s1])

        # Two records reuse one local: remote ids accumulate one per
        # reference, repositories stay deduplicated.
        self.assertEqual(alpha["repositories"], ["alpha"])
        self.assertEqual(alpha["remote_ids"], ["ra-1", "ra-2"])
        self.assertEqual(alpha["reference_count"], 2)
        self.assertEqual(alpha["resources"], [s2, s3])

    def test_repositories_deduplicated_in_reference_order(self) -> None:
        s1 = register_local(name="s1")
        s2 = register_local(name="s2", digest="c1" * 32)
        s3 = register_local(name="s3", digest="c2" * 32)

        # Three references all resolve to the same local. "beta" points at
        # it first, then "alpha" from two remote ids: the repository list
        # must follow reference first-appearance, never the alphabet.
        with patch_resolve():
            post_reference(
                s1,
                reference_body(
                    repository="beta",
                    upstream="https://beta.invalid",
                    remote_id="rb-1",
                ),
            )
        with patch_resolve():
            post_reference(
                s2,
                reference_body(repository="alpha", remote_id="ra-1"),
            )
        with patch_resolve():
            post_reference(
                s3,
                reference_body(repository="alpha", remote_id="ra-2"),
            )

        status, _h, targets = call_targets()
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(targets), 1)
        entry = targets[0]
        self.assertEqual(entry["repositories"], ["beta", "alpha"])
        self.assertEqual(entry["remote_ids"], ["rb-1", "ra-1", "ra-2"])
        self.assertEqual(entry["reference_count"], 3)

    def test_remote_ids_listed_per_reference_without_dedup(self) -> None:
        # The same remote id string under two different repositories is a
        # distinct pair; both resolve to one local (identical metadata) and
        # the remote id appears twice, once per reference.
        s1 = register_local(name="s1")
        s2 = register_local(name="s2", digest="c1" * 32)
        with patch_resolve():
            post_reference(
                s1,
                reference_body(
                    repository="alpha",
                    upstream="https://alpha.invalid",
                    remote_id="shared-rid",
                ),
            )
        with patch_resolve():
            post_reference(
                s2,
                reference_body(
                    repository="beta",
                    upstream="https://beta.invalid",
                    remote_id="shared-rid",
                ),
            )

        status, _h, targets = call_targets()
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(targets), 1)
        entry = targets[0]
        self.assertEqual(entry["remote_ids"], ["shared-rid", "shared-rid"])
        self.assertEqual(entry["reference_count"], 2)
        self.assertEqual(entry["repositories"], ["alpha", "beta"])
        self.assertEqual(entry["resources"], [s1, s2])

    def test_resources_deduplicated_in_resource_registration_order(self) -> None:
        s1 = register_local(name="s1")
        s2 = register_local(name="s2", digest="c1" * 32)
        s3 = register_local(name="s3", digest="c2" * 32)

        # References to the same resolved local arrive interleaved across
        # the three resources: s3 references first, s1 last, so first
        # appearance would order them s3, s2, s1 while the result follows
        # resource registration order.
        with patch_resolve():
            post_reference(
                s3, reference_body(repository="repo", remote_id="r1")
            )
        with patch_resolve():
            post_reference(
                s2, reference_body(repository="repo", remote_id="r2")
            )
        with patch_resolve():
            post_reference(
                s1, reference_body(repository="repo", remote_id="r3")
            )

        status, _h, targets = call_targets()
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(targets), 1)
        entry = targets[0]
        self.assertEqual(entry["reference_count"], 3)
        self.assertEqual(entry["remote_ids"], ["r1", "r2", "r3"])
        self.assertEqual(entry["resources"], [s1, s2, s3])

    def test_local_id_echoed_verbatim(self) -> None:
        start_id = register_local()
        with patch_resolve():
            post_reference(start_id, reference_body())
        before = call("GET", PATH)[2]

        # Deregistration of the resolved local and removal of the dependency
        # edge never rewrite historical references: the grouping key,
        # repository, remote id and start resource all stay as recorded.
        resolved_id = local_id_for("remote-42")
        self.assertEqual(delete_edge(start_id, resolved_id), "200 OK")
        self.assertEqual(delete_resource(resolved_id), "200 OK")

        status, _h, after_raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertEqual(after_raw, before)
        targets = json.loads(after_raw)
        self.assertEqual(targets[0]["local_id"], resolved_id)

    # --- Recomputation -----------------------------------------------------

    def test_entry_order_redetermined_after_single_reference_deletion(self) -> None:
        s1 = register_local(name="s1")
        s2 = register_local(name="s2", digest="c1" * 32)
        s3 = register_local(name="s3", digest="c2" * 32)
        with patch_resolve(digest="e" * 64, name="m-a", source="u-a"):
            post_reference(
                s1,
                reference_body(
                    repository="alpha",
                    upstream="https://alpha.invalid",
                    remote_id="a1",
                    digest="e" * 64,
                ),
            )
        with patch_resolve(digest="d" * 64, name="m-b", source="u-b"):
            post_reference(
                s2,
                reference_body(
                    repository="beta",
                    upstream="https://beta.invalid",
                    remote_id="b1",
                    digest="d" * 64,
                ),
            )
        with patch_resolve(digest="e" * 64, name="m-a", source="u-a"):
            # Same metadata as a1: the alpha local is reused from s3.
            post_reference(
                s3,
                reference_body(
                    repository="alpha",
                    upstream="https://alpha.invalid",
                    remote_id="a2",
                    digest="e" * 64,
                ),
            )

        alpha_local = local_id_for("a1")
        beta_local = local_id_for("b1")

        status, _h, targets = call_targets()
        self.assertEqual(
            [entry["local_id"] for entry in targets],
            [alpha_local, beta_local],
        )

        # Deleting the first-occurrence reference moves alpha behind beta:
        # the order is redetermined from the remaining records.
        self.assertEqual(delete_reference(s1, "alpha", "a1"), "200 OK")
        status, _h, targets = call_targets()
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            [entry["local_id"] for entry in targets],
            [beta_local, alpha_local],
        )
        alpha_entry = next(
            entry for entry in targets if entry["local_id"] == alpha_local
        )
        self.assertEqual(alpha_entry["remote_ids"], ["a2"])
        self.assertEqual(alpha_entry["reference_count"], 1)
        self.assertEqual(alpha_entry["repositories"], ["alpha"])
        self.assertEqual(alpha_entry["resources"], [s3])

        # Deleting the last reference at that local drops the whole entry.
        self.assertEqual(delete_reference(s3, "alpha", "a2"), "200 OK")
        status, _h, targets = call_targets()
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            [entry["local_id"] for entry in targets], [beta_local]
        )

    def test_start_resource_deregistration_recomputes_aggregates(self) -> None:
        s1 = register_local(name="s1")
        s2 = register_local(name="s2", digest="c1" * 32)
        with patch_resolve():
            post_reference(
                s1, reference_body(repository="shared", remote_id="r1")
            )
        with patch_resolve(digest="e" * 64, name="m2", source="u2"):
            post_reference(
                s2,
                reference_body(
                    repository="shared", remote_id="r2", digest="e" * 64
                ),
            )
        second_local = local_id_for("r2")

        status = delete_resource(s1)
        self.assertEqual(status, "200 OK")

        status, _h, targets = call_targets()
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(targets), 1)
        entry = targets[0]
        self.assertEqual(entry["local_id"], second_local)
        self.assertEqual(entry["reference_count"], 1)
        self.assertEqual(entry["remote_ids"], ["r2"])
        self.assertEqual(entry["repositories"], ["shared"])
        self.assertEqual(entry["resources"], [s2])

        # Deregistering the last start resource leaves an empty array.
        self.assertEqual(delete_resource(s2), "200 OK")
        status, _h, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

    def test_dependency_edge_removal_does_not_change_targets(self) -> None:
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

    def test_view_never_contacts_upstream_and_is_read_only(self) -> None:
        with mock.patch(
            "provenance_api.app.resolve_remote",
            side_effect=AssertionError("must not resolve"),
        ):
            status, _h, targets = call_targets()
        self.assertEqual(status, "200 OK")
        self.assertEqual(targets, [])

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
