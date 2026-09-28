from __future__ import annotations

import io
import json
import unittest
from unittest import mock

from provenance_api.app import application, reset_state

PATH = "/cross-reference-usage"

UPSTREAM = "https://repo.example.invalid"
REMOTE_ID = "remote-42"
REMOTE_NAME = "remote-model"
DIGEST = "a" * 64
SOURCE = "https://repo.example.invalid/sources/remote-42"

REFERENCE_BODY = {
    "repository": "partner",
    "upstream": UPSTREAM,
    "remote_id": REMOTE_ID,
    "digest": DIGEST,
}

USAGE_FIELDS = [
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


def post_reference(
    resource_id: str,
    body: object | None = None,
):
    payload = REFERENCE_BODY if body is None else body
    status, headers, raw = call(
        "POST",
        f"/resources/{resource_id}/cross-references",
        json.dumps(payload).encode("utf-8"),
        headers={"CONTENT_TYPE": "application/json"},
    )
    return status, headers, json.loads(raw.decode("utf-8"))


def add_reference(
    resource_id: str,
    *,
    repository: str = "partner",
    upstream: str = UPSTREAM,
    remote_id: str = REMOTE_ID,
    digest: str = DIGEST,
    remote_name: str = REMOTE_NAME,
    source: str = SOURCE,
) -> None:
    with patch_resolve(
        name=remote_name, digest=digest, source=source
    ):
        status, _h, body = post_reference(
            resource_id,
            {
                "repository": repository,
                "upstream": upstream,
                "remote_id": remote_id,
                "digest": digest,
            },
        )
    assert status == "201 Created", (status, body)


def delete_reference(resource_id: str, repository: str, remote_id: str):
    return call(
        "DELETE",
        f"/resources/{resource_id}/cross-references/"
        f"{repository}/{remote_id}",
    )


def delete_resource(resource_id: str):
    return call("DELETE", f"/resources/{resource_id}")


def delete_edge(resource_id: str, dependency_id: str):
    return call(
        "DELETE", f"/resources/{resource_id}/dependencies/{dependency_id}"
    )


class CrossReferenceUsageViewTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def test_empty_usage_is_empty_array_with_newline(self) -> None:
        status, headers, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            ("Content-Type", "application/json; charset=utf-8"),
            next(h for h in headers if h[0] == "Content-Type"),
        )
        self.assertEqual(raw, b"[]\n")

    def test_one_reference_rolls_up_six_fields_in_order(self) -> None:
        start_id = register_local()
        add_reference(start_id)
        local_id = next(
            r["id"]
            for r in json.loads(call("GET", "/resources")[2])["resources"]
            if r["id"] != start_id
        )

        status, _h, usage = call_usage()
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(usage), 1)
        entry = usage[0]
        self.assertEqual(list(entry), USAGE_FIELDS)
        self.assertEqual(entry["repository"], "partner")
        self.assertEqual(entry["upstream"], UPSTREAM)
        self.assertEqual(entry["reference_count"], 1)
        self.assertEqual(entry["resources"], [start_id])
        self.assertEqual(entry["resource_count"], 1)
        self.assertEqual(entry["local_ids"], [local_id])

        # Compact JSON with a single trailing newline.
        _status, _h, raw = call("GET", PATH)
        self.assertEqual(raw.count(b"\n"), 1)
        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(b" ", raw.rstrip(b"\n"))
        self.assertEqual(json.loads(raw), usage)

    def test_repository_and_upstream_echoed_verbatim(self) -> None:
        # No case folding and no whitespace trimming on either field.
        start_id = register_local()
        add_reference(
            start_id,
            repository=" PartNer ",
            upstream="https://Repo.Example.invalid/",
        )

        entry = call_usage()[2][0]
        self.assertEqual(entry["repository"], " PartNer ")
        self.assertEqual(entry["upstream"], "https://Repo.Example.invalid/")

    def test_entries_follow_first_repository_occurrence(self) -> None:
        r1 = register_local(name="r1")
        r2 = register_local(name="r2", digest="c" * 64)
        add_reference(r1, repository="zeta", remote_id="z-1", digest="d" * 64,
                      remote_name="z-remote",
                      source="https://zeta.example.invalid/z-1")
        add_reference(r2, repository="alpha", remote_id="a-1", digest="e" * 64,
                      remote_name="a-remote",
                      source="https://alpha.example.invalid/a-1")
        add_reference(r1, repository="alpha", remote_id="a-2", digest="f" * 64,
                      remote_name="a2-remote",
                      source="https://alpha.example.invalid/a-2")

        usage = call_usage()[2]
        self.assertEqual([e["repository"] for e in usage], ["zeta", "alpha"])
        # The repeated alpha reference never reorders or splits the entry.
        alpha = usage[1]
        self.assertEqual(alpha["reference_count"], 2)
        # Start resources follow resource registration order (r1 first),
        # even though r2 started alpha's first reference.
        self.assertEqual(alpha["resources"], [r1, r2])
        self.assertEqual(alpha["resource_count"], 2)

    def test_reference_count_counts_every_record_without_dedup(self) -> None:
        r1 = register_local(name="r1")
        r2 = register_local(name="r2", digest="c" * 64)
        # Same repository, distinct remote ids: three records from two
        # resources (including two started by one resource).
        add_reference(r1, remote_id="remote-1", digest="d" * 64,
                      remote_name="m1",
                      source="https://repo.example.invalid/m1")
        add_reference(r1, remote_id="remote-2", digest="e" * 64,
                      remote_name="m2",
                      source="https://repo.example.invalid/m2")
        add_reference(r2, remote_id="remote-3", digest="f" * 64,
                      remote_name="m3",
                      source="https://repo.example.invalid/m3")

        entry = call_usage()[2][0]
        self.assertEqual(entry["reference_count"], 3)
        self.assertEqual(entry["resources"], [r1, r2])
        self.assertEqual(entry["resource_count"], 2)

    def test_resources_deduplicated_in_resource_registration_order(self) -> None:
        r1 = register_local(name="r1")
        r2 = register_local(name="r2", digest="c" * 64)
        r3 = register_local(name="r3", digest="1" * 64)
        # References are started in reverse resource order; the rollup must
        # still list starts by resource registration order, each once.
        add_reference(r3, remote_id="remote-3", digest="2" * 64,
                      remote_name="m3",
                      source="https://repo.example.invalid/m3")
        add_reference(r2, remote_id="remote-2", digest="3" * 64,
                      remote_name="m2",
                      source="https://repo.example.invalid/m2")
        add_reference(r1, remote_id="remote-1", digest="4" * 64,
                      remote_name="m1",
                      source="https://repo.example.invalid/m1")
        add_reference(r1, remote_id="remote-4", digest="5" * 64,
                      remote_name="m4",
                      source="https://repo.example.invalid/m4")

        entry = call_usage()[2][0]
        self.assertEqual(entry["resources"], [r1, r2, r3])
        self.assertEqual(entry["resource_count"], 3)

    def test_local_ids_deduplicated_in_resource_registration_order(self) -> None:
        r1 = register_local(name="r1")
        r2 = register_local(name="r2", digest="c" * 64)
        # r2's reference resolves first and creates local L1; r1's later
        # reference to a different remote id with the same digest reuses L1,
        # then another reference resolves fresh local L2. (The
        # (repository, remote_id) pair is globally unique, so reuse happens
        # through matching resolved identities, not identical remote ids.)
        add_reference(r2, remote_id="shared-2", digest="d" * 64,
                      remote_name="shared",
                      source="https://repo.example.invalid/shared")
        add_reference(r1, remote_id="shared-1", digest="d" * 64,
                      remote_name="shared",
                      source="https://repo.example.invalid/shared")
        add_reference(r1, remote_id="remote-2", digest="e" * 64,
                      remote_name="other",
                      source="https://repo.example.invalid/other")

        locals_ = call_usage()[2][0]["local_ids"]
        # L1 registered before L2; reuse never duplicates an id.
        self.assertEqual(len(set(locals_)), len(locals_))
        self.assertEqual(len(locals_), 2)
        # Both resolved locals appear in current resource registration order.
        all_resources = json.loads(call("GET", "/resources")[2])["resources"]
        order = [r["id"] for r in all_resources]
        self.assertEqual(locals_, sorted(locals_, key=order.index))

    def test_reused_existing_local_resource_is_listed_once(self) -> None:
        existing = register_local(
            name=REMOTE_NAME, category="Model", digest=DIGEST, source=SOURCE
        )
        dependent = register_local(name="dependent", digest="c" * 64)
        add_reference(dependent)

        entry = call_usage()[2][0]
        self.assertEqual(entry["local_ids"], [existing])
        self.assertEqual(entry["reference_count"], 1)

    def test_edge_removal_leaves_rollup_unchanged(self) -> None:
        start_id = register_local()
        add_reference(start_id)
        before = call_usage()[2][0]
        local_id = before["local_ids"][0]

        status, _h, _body = delete_edge(start_id, local_id)
        self.assertEqual(status, "200 OK")

        after = call_usage()[2][0]
        self.assertEqual(after, before)

    def test_deregistered_local_id_still_listed_in_first_seen_order(self) -> None:
        r1 = register_local(name="r1")
        r2 = register_local(name="r2", digest="c" * 64)
        r3 = register_local(name="r3", digest="1" * 64)
        add_reference(r1, remote_id="remote-1", digest="2" * 64,
                      remote_name="m1",
                      source="https://repo.example.invalid/m1")
        add_reference(r2, remote_id="remote-2", digest="3" * 64,
                      remote_name="m2",
                      source="https://repo.example.invalid/m2")
        add_reference(r3, remote_id="remote-3", digest="4" * 64,
                      remote_name="m3",
                      source="https://repo.example.invalid/m3")
        l1, l2, l3 = call_usage()[2][0]["local_ids"]

        # Deregister the middle resolved resource; its historical reference
        # survives. Remaining ids keep registration order, the missing id is
        # appended last (its first-seen position among missing ids).
        status, _h, _body = delete_resource(l2)
        self.assertEqual(status, "200 OK")

        entry = call_usage()[2][0]
        self.assertEqual(entry["reference_count"], 3)
        self.assertEqual(entry["local_ids"], [l1, l3, l2])
        self.assertEqual(entry["resources"], [r1, r2, r3])

    def test_start_resource_deregistration_recomputes_rollup(self) -> None:
        r1 = register_local(name="r1")
        r2 = register_local(name="r2", digest="c" * 64)
        add_reference(r1, repository="alpha", remote_id="a-1",
                      digest="d" * 64, remote_name="a1",
                      source="https://alpha.example.invalid/a1")
        add_reference(r2, repository="beta", remote_id="b-1",
                      digest="e" * 64, remote_name="b1",
                      source="https://beta.example.invalid/b1")
        add_reference(r1, repository="beta", remote_id="b-2",
                      digest="f" * 64, remote_name="b2",
                      source="https://beta.example.invalid/b2")
        usage = call_usage()[2]
        self.assertEqual([e["repository"] for e in usage], ["alpha", "beta"])
        self.assertEqual(usage[1]["reference_count"], 2)

        # Removing r1 takes its records (alpha's only one and one beta one)
        # with it; the alpha entry disappears entirely.
        status, _h, _body = delete_resource(r1)
        self.assertEqual(status, "200 OK")

        usage = call_usage()[2]
        self.assertEqual(len(usage), 1)
        self.assertEqual(usage[0]["repository"], "beta")
        self.assertEqual(usage[0]["reference_count"], 1)
        self.assertEqual(usage[0]["resources"], [r2])
        self.assertEqual(usage[0]["resource_count"], 1)

    def test_single_reference_deletion_recomputes_rollup(self) -> None:
        r1 = register_local(name="r1")
        add_reference(r1, remote_id="remote-1", digest="d" * 64,
                      remote_name="m1",
                      source="https://repo.example.invalid/m1")
        l1 = call_usage()[2][0]["local_ids"][0]

        # Deleting the sole reference drops the repository entry; the local
        # resource and edge are retained.
        status, _h, _body = delete_reference(r1, "partner", "remote-1")
        self.assertEqual(status, "200 OK")
        self.assertEqual(call_usage()[2], [])
        _status, _h, resources = call("GET", "/resources")
        self.assertIn(l1, {r["id"] for r in json.loads(resources)["resources"]})

    def test_view_never_contacts_upstream(self) -> None:
        with mock.patch(
            "provenance_api.app.resolve_remote",
            side_effect=AssertionError("must not resolve"),
        ):
            status, _h, usage = call_usage()
        self.assertEqual(status, "200 OK")
        self.assertEqual(usage, [])

    def test_root_summary_view_is_unchanged(self) -> None:
        # The new rollup must not alter the per-record global summary.
        start_id = register_local()
        add_reference(start_id)
        status, _h, raw = call("GET", "/")
        summary = json.loads(raw)
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            list(summary[0]),
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
        status, _h, usage = call_usage(omit_content_length=True)
        self.assertEqual(status, "200 OK")
        self.assertEqual(usage, [])

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

    def test_any_or_repeated_query_parameters_return_400(self) -> None:
        for query_string in ("x=1", "x=", "a=b&c=d", "x=1&x=2"):
            status, _h, body = call_usage(query_string=query_string)
            self.assertEqual(status, "400 Bad Request", query_string)
            self.assertEqual(body["error"], "invalid_request")

    def test_methods_other_than_get_return_405_with_get_only_allow(self) -> None:
        for method in ("POST", "PUT", "DELETE", "PATCH", "HEAD"):
            status, headers, body = call_usage(method)
            self.assertEqual(status, "405 Method Not Allowed", method)
            self.assertIn(("Allow", "GET"), headers)
            self.assertEqual(
                [value for key, value in headers if key == "Allow"],
                ["GET"],
            )
            self.assertEqual(body["error"], "method_not_allowed")

    def test_non_get_method_with_query_or_body_still_returns_405(self) -> None:
        # Method is decided before the request shape is examined.
        status, headers, body = call_usage(
            "DELETE", query_string="x=1"
        )
        self.assertEqual(status, "405 Method Not Allowed")
        self.assertIn(("Allow", "GET"), headers)
        self.assertEqual(body["error"], "method_not_allowed")

        status, headers, body = call_usage("POST", body=b"x")
        self.assertEqual(status, "405 Method Not Allowed")
        self.assertIn(("Allow", "GET"), headers)
        self.assertEqual(body["error"], "method_not_allowed")


if __name__ == "__main__":
    unittest.main()
