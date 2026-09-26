from __future__ import annotations

import io
import json
import unittest
from unittest import mock

from provenance_api.app import application, reset_state

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

SUMMARY_FIELDS = [
    "resource_id",
    "repository",
    "upstream",
    "remote_id",
    "digest",
    "local_id",
    "edge_present",
]


def call(
    method: str,
    path: str = "/",
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


def call_summary(
    method: str = "GET",
    body: bytes = b"",
    **kwargs: object,
) -> tuple[str, list[tuple[str, str]], object]:
    status, headers, raw = call(method, "/", body, **kwargs)  # type: ignore[arg-type]
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
    body: object = None,
):
    payload = REFERENCE_BODY if body is None else body
    status, headers, raw = call(
        "POST",
        f"/resources/{resource_id}/cross-references",
        json.dumps(payload).encode("utf-8"),
        headers={"CONTENT_TYPE": "application/json"},
    )
    return status, headers, json.loads(raw.decode("utf-8"))


def delete_resource(resource_id: str):
    return call("DELETE", f"/resources/{resource_id}")


def delete_edge(resource_id: str, dependency_id: str):
    return call(
        "DELETE", f"/resources/{resource_id}/dependencies/{dependency_id}"
    )


class GlobalSummaryViewTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def test_empty_summary_is_empty_array_with_newline(self) -> None:
        status, headers, raw = call("GET", "/")
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            ("Content-Type", "application/json; charset=utf-8"),
            next(h for h in headers if h[0] == "Content-Type"),
        )
        self.assertEqual(raw, b"[]\n")

    def test_one_reference_lists_seven_fields_in_order(self) -> None:
        start_id = register_local()
        with patch_resolve():
            status, _h, created = post_reference(start_id)
        self.assertEqual(status, "201 Created")
        local_id = next(
            r["id"]
            for r in json.loads(call("GET", "/resources")[2])["resources"]
            if r["id"] != start_id
        )

        status, _h, summary = call_summary()
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(summary), 1)
        record = summary[0]
        self.assertEqual(list(record), SUMMARY_FIELDS)
        self.assertEqual(record["resource_id"], start_id)
        self.assertEqual(record["repository"], "partner")
        self.assertEqual(record["upstream"], UPSTREAM)
        self.assertEqual(record["remote_id"], REMOTE_ID)
        self.assertEqual(record["digest"], DIGEST)
        self.assertEqual(record["local_id"], local_id)
        self.assertIs(record["edge_present"], True)

        # Compact JSON with a single trailing newline.
        _status, _h, raw = call("GET", "/")
        self.assertTrue(raw.endswith(b"\n"))
        self.assertEqual(raw.count(b"\n"), 1)
        self.assertEqual(json.loads(raw), summary)

    def test_records_follow_global_registration_order(self) -> None:
        first = register_local(name="first")
        second = register_local(name="second", digest="c" * 64)
        with patch_resolve():
            post_reference(first)
        with patch_resolve(
            digest="d" * 64,
            name="second-remote",
            source="https://repo.example.invalid/second",
        ):
            post_reference(
                second,
                dict(REFERENCE_BODY, remote_id="remote-7", digest="d" * 64),
            )
        with patch_resolve(
            digest="e" * 64,
            name="third-remote",
            source="https://repo.example.invalid/third",
        ):
            post_reference(
                first,
                dict(REFERENCE_BODY, remote_id="remote-8", digest="e" * 64),
            )

        status, _h, summary = call_summary()
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            [(r["resource_id"], r["remote_id"]) for r in summary],
            [
                (first, "remote-42"),
                (second, "remote-7"),
                (first, "remote-8"),
            ],
        )
        # The two references started by "first" keep their own order and are
        # never regrouped away from the global sequence.
        first_records = [r for r in summary if r["resource_id"] == first]
        self.assertEqual(
            [r["remote_id"] for r in first_records],
            ["remote-42", "remote-8"],
        )

    def test_reused_local_resource_is_reported_as_local_id(self) -> None:
        existing = register_local(
            name=REMOTE_NAME, category="Model", digest=DIGEST, source=SOURCE
        )
        dependent = register_local(name="dependent", digest="f" * 64)
        with patch_resolve():
            post_reference(dependent)

        status, _h, summary = call_summary()
        self.assertEqual(status, "200 OK")
        self.assertEqual(summary[0]["local_id"], existing)
        self.assertIs(summary[0]["edge_present"], True)

    def test_edge_removal_keeps_record_with_edge_present_false(self) -> None:
        start_id = register_local()
        with patch_resolve():
            post_reference(start_id)
        local_id = call_summary()[2][0]["local_id"]

        status, _h, _body = delete_edge(start_id, local_id)
        self.assertEqual(status, "200 OK")

        status, _h, summary = call_summary()
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(summary), 1)
        record = summary[0]
        self.assertEqual(record["local_id"], local_id)
        self.assertIs(record["edge_present"], False)
        # The historical reference fields are untouched.
        self.assertEqual(record["resource_id"], start_id)
        self.assertEqual(record["remote_id"], REMOTE_ID)
        self.assertEqual(record["digest"], DIGEST)

        # Re-adding the same edge by hand flips the column back to true.
        status, _h, _body = call(
            "POST",
            f"/resources/{start_id}/dependencies",
            json.dumps({"dependency_id": local_id}).encode("utf-8"),
            headers={"CONTENT_TYPE": "application/json"},
        )
        self.assertEqual(status, "201 Created")
        self.assertIs(call_summary()[2][0]["edge_present"], True)

    def test_deregistered_resolved_resource_leaves_record_with_false(self) -> None:
        start_id = register_local()
        with patch_resolve():
            post_reference(start_id)
        local_id = call_summary()[2][0]["local_id"]

        # Deregister the resolved (target) resource; the reference was
        # started by another resource, so the record survives while the
        # edge cascades away.
        status, _h, _body = delete_resource(local_id)
        self.assertEqual(status, "200 OK")

        status, _h, summary = call_summary()
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(summary), 1)
        self.assertEqual(summary[0]["local_id"], local_id)
        self.assertIs(summary[0]["edge_present"], False)

    def test_start_resource_deregistration_removes_its_records(self) -> None:
        first = register_local(name="first")
        second = register_local(name="second", digest="c" * 64)
        with patch_resolve():
            post_reference(first)
        with patch_resolve(
            digest="d" * 64,
            name="second-remote",
            source="https://repo.example.invalid/second",
        ):
            post_reference(
                second,
                dict(REFERENCE_BODY, remote_id="remote-7", digest="d" * 64),
            )
        with patch_resolve(
            digest="e" * 64,
            name="third-remote",
            source="https://repo.example.invalid/third",
        ):
            post_reference(
                first,
                dict(REFERENCE_BODY, remote_id="remote-8", digest="e" * 64),
            )
        self.assertEqual(len(call_summary()[2]), 3)

        status, _h, _body = delete_resource(first)
        self.assertEqual(status, "200 OK")

        status, _h, summary = call_summary()
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            [(r["resource_id"], r["remote_id"]) for r in summary],
            [(second, "remote-7")],
        )

    def test_view_never_contacts_upstream(self) -> None:
        with mock.patch(
            "provenance_api.app.resolve_remote",
            side_effect=AssertionError("must not resolve"),
        ):
            status, _h, summary = call_summary()
        self.assertEqual(status, "200 OK")
        self.assertEqual(summary, [])

    def test_per_resource_listing_keeps_five_fields(self) -> None:
        # The new local_id column must not leak into the existing
        # per-resource listing shape.
        start_id = register_local()
        with patch_resolve():
            post_reference(start_id)
        status, _h, raw = call(
            "GET", f"/resources/{start_id}/cross-references"
        )
        listing = json.loads(raw)
        self.assertEqual(
            list(listing["cross_references"][0]),
            ["resource_id", "repository", "upstream", "remote_id", "digest"],
        )


class GlobalSummaryRequestTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def test_omitted_content_length_is_ok(self) -> None:
        status, _h, summary = call_summary(omit_content_length=True)
        self.assertEqual(status, "200 OK")
        self.assertEqual(summary, [])

    def test_explicit_zero_length_is_ok(self) -> None:
        status, _h, raw = call(
            "GET", "/", headers={"CONTENT_LENGTH": "0"}
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

    def test_declared_non_empty_body_returns_400(self) -> None:
        status, _h, body = call_summary(body=b"x")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_malformed_content_length_returns_400(self) -> None:
        status, _h, raw = call(
            "GET", "/", headers={"CONTENT_LENGTH": "abc"}
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(json.loads(raw)["error"], "invalid_request")

    def test_empty_string_content_length_is_ok(self) -> None:
        # Real WSGI servers seed CONTENT_LENGTH with '' for bodyless
        # requests; that counts as no body.
        status, _h, raw = call(
            "GET", "/", headers={"CONTENT_LENGTH": ""}
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

    def test_query_parameters_return_400(self) -> None:
        for query_string in ("x=1", "x=", "a=b&c=d"):
            status, _h, body = call_summary(query_string=query_string)
            self.assertEqual(status, "400 Bad Request", query_string)
            self.assertEqual(body["error"], "invalid_request")

    def test_methods_other_than_get_return_405_with_get_only_allow(self) -> None:
        for method in ("POST", "PUT", "DELETE", "PATCH", "HEAD"):
            status, headers, body = call_summary(method)
            self.assertEqual(status, "405 Method Not Allowed", method)
            self.assertIn(("Allow", "GET"), headers)
            allow_values = [value for key, value in headers if key == "Allow"]
            self.assertEqual(allow_values, ["GET"])
            self.assertEqual(body["error"], "method_not_allowed")

    def test_non_get_method_with_query_still_returns_405(self) -> None:
        # Method is decided before the request shape is examined.
        status, headers, body = call_summary(
            "DELETE", query_string="x=1"
        )
        self.assertEqual(status, "405 Method Not Allowed")
        self.assertIn(("Allow", "GET"), headers)
        self.assertEqual(body["error"], "method_not_allowed")


if __name__ == "__main__":
    unittest.main()
