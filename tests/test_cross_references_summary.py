from __future__ import annotations

import io
import json
import unittest

from provenance_api.app import application, reset_state

from test_cross_references import (
    DIGEST,
    REFERENCE_BODY,
    REMOTE_NAME,
    SOURCE,
    UPSTREAM,
    patch_resolve,
    register_local,
)

SUMMARY_KEYS = [
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
    path: str,
    body: bytes = b"",
    *,
    headers: dict[str, str] | None = None,
    query_string: str | None = None,
    content_length: str | None = None,
) -> tuple[str, list[tuple[str, str]], bytes]:
    environ: dict[str, object] = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "CONTENT_LENGTH": (
            content_length if content_length is not None else str(len(body))
        ),
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
) -> tuple[str, list[tuple[str, str]], object]:
    status, headers, raw = call(method, path, body, **kwargs)  # type: ignore[arg-type]
    return status, headers, json.loads(raw.decode("utf-8"))


def get_summary(**kwargs: object):
    return call_json("GET", "/cross-references", **kwargs)


def post_reference(resource_id: str, body: object):
    return call_json(
        "POST",
        f"/resources/{resource_id}/cross-references",
        json.dumps(body).encode("utf-8"),
        headers={"CONTENT_TYPE": "application/json"},
    )


def delete_dependency(resource_id: str, dependency_id: str):
    return call_json(
        "DELETE", f"/resources/{resource_id}/dependencies/{dependency_id}"
    )


def delete_resource(resource_id: str):
    return call_json("DELETE", f"/resources/{resource_id}")


def list_resource_ids() -> list[str]:
    _status, _h, listing = call_json("GET", "/resources")
    return [r["id"] for r in listing["resources"]]  # type: ignore[index]


class CrossReferenceSummaryTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def _register_reference(
        self,
        resource_id: str,
        *,
        remote_id: str = "remote-42",
        digest: str = DIGEST,
        name: str = REMOTE_NAME,
        source: str = SOURCE,
        repository: str = "partner",
    ) -> dict[str, object]:
        body = dict(
            REFERENCE_BODY,
            repository=repository,
            remote_id=remote_id,
            digest=digest,
        )
        with patch_resolve(digest=digest, name=name, source=source):
            status, _h, response = post_reference(resource_id, body)
        assert status == "201 Created", (status, response)
        return response  # type: ignore[return-value]

    def test_empty_summary_is_an_empty_array(self) -> None:
        status, headers, body = get_summary()
        self.assertEqual(status, "200 OK")
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )
        self.assertEqual(body, [])

    def test_empty_summary_raw_body_is_compact_with_newline(self) -> None:
        status, _h, raw = call("GET", "/cross-references")
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

    def test_summary_lists_records_in_registration_order(self) -> None:
        first = register_local(name="first")
        second = register_local(name="second", digest="c" * 64)
        self._register_reference(first)
        self._register_reference(
            second,
            remote_id="remote-7",
            digest="d" * 64,
            name="second-remote",
            source="https://repo.example.invalid/second",
        )
        self._register_reference(
            first,
            remote_id="remote-8",
            digest="e" * 64,
            name="third-remote",
            source="https://repo.example.invalid/third",
        )

        status, _h, summary = get_summary()
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            [r["remote_id"] for r in summary],  # type: ignore[index]
            ["remote-42", "remote-7", "remote-8"],
        )
        self.assertEqual(
            [r["resource_id"] for r in summary],  # type: ignore[index]
            [first, second, first],
        )
        for record in summary:  # type: ignore[union-attr]
            self.assertEqual(list(record), SUMMARY_KEYS)
            self.assertEqual(record["repository"], "partner")
            self.assertEqual(record["upstream"], UPSTREAM)
            self.assertEqual(record["edge_present"], True)

    def test_local_id_is_the_created_or_reused_resource(self) -> None:
        dependent = register_local(name="dependent", digest="1" * 64)
        self._register_reference(dependent)
        created_id = next(
            rid for rid in list_resource_ids() if rid != dependent
        )
        _status, _h, summary = get_summary()
        self.assertEqual(summary[0]["local_id"], created_id)  # type: ignore[index]

        # A second reference resolving to an identical existing resource
        # reuses that resource's id.
        reused = register_local(
            name="other-remote",
            category="model",
            digest="d" * 64,
            source="https://repo.example.invalid/other",
        )
        self._register_reference(
            dependent,
            remote_id="remote-7",
            digest="d" * 64,
            name="other-remote",
            source="https://repo.example.invalid/other",
        )
        _status, _h, summary = get_summary()
        self.assertEqual(summary[1]["local_id"], reused)  # type: ignore[index]

    def test_removed_edge_flips_edge_present_and_keeps_the_record(self) -> None:
        dependent = register_local()
        self._register_reference(dependent)
        _status, _h, summary = get_summary()
        local_id = summary[0]["local_id"]  # type: ignore[index]

        status, _h, _body = delete_dependency(dependent, local_id)
        self.assertEqual(status, "200 OK")

        status, _h, summary = get_summary()
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(summary), 1)  # type: ignore[arg-type]
        record = summary[0]  # type: ignore[index]
        self.assertEqual(list(record), SUMMARY_KEYS)
        self.assertEqual(record["local_id"], local_id)
        self.assertEqual(record["edge_present"], False)
        self.assertEqual(record["remote_id"], "remote-42")

    def test_deregistered_resolved_resource_keeps_record_and_local_id(
        self,
    ) -> None:
        dependent = register_local()
        self._register_reference(dependent)
        _status, _h, summary = get_summary()
        local_id = summary[0]["local_id"]  # type: ignore[index]

        status, _h, _body = delete_resource(local_id)
        self.assertEqual(status, "200 OK")

        status, _h, summary = get_summary()
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(summary), 1)  # type: ignore[arg-type]
        record = summary[0]  # type: ignore[index]
        self.assertEqual(record["local_id"], local_id)
        self.assertEqual(record["edge_present"], False)
        self.assertEqual(record["digest"], DIGEST)

    def test_deregistered_dependent_removes_its_references(self) -> None:
        first = register_local(name="first")
        second = register_local(name="second", digest="c" * 64)
        self._register_reference(first)
        self._register_reference(
            second,
            remote_id="remote-7",
            digest="d" * 64,
            name="second-remote",
            source="https://repo.example.invalid/second",
        )

        status, _h, _body = delete_resource(first)
        self.assertEqual(status, "200 OK")

        status, _h, summary = get_summary()
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(summary), 1)  # type: ignore[arg-type]
        self.assertEqual(summary[0]["resource_id"], second)  # type: ignore[index]
        self.assertEqual(summary[0]["remote_id"], "remote-7")  # type: ignore[index]

        status, _h, _body = delete_resource(second)
        self.assertEqual(status, "200 OK")
        status, _h, summary = get_summary()
        self.assertEqual(summary, [])

    def test_per_resource_listing_is_unchanged(self) -> None:
        dependent = register_local()
        self._register_reference(dependent)
        status, _h, listing = call_json(
            "GET", f"/resources/{dependent}/cross-references"
        )
        self.assertEqual(status, "200 OK")
        records = listing["cross_references"]  # type: ignore[index]
        self.assertEqual(len(records), 1)
        self.assertEqual(
            list(records[0]),
            ["resource_id", "repository", "upstream", "remote_id", "digest"],
        )


class CrossReferenceSummaryRequestTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def test_non_get_methods_return_405_with_allow_get(self) -> None:
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            status, headers, body = call_json(method, "/cross-references")
            self.assertEqual(status, "405 Method Not Allowed", method)
            self.assertIn(("Allow", "GET"), headers)
            self.assertEqual(body["error"], "method_not_allowed")  # type: ignore[index]

    def test_declared_body_returns_400(self) -> None:
        status, _h, body = call_json(
            "GET",
            "/cross-references",
            b"{}",
            headers={"CONTENT_TYPE": "application/json"},
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")  # type: ignore[index]

    def test_malformed_content_length_returns_400(self) -> None:
        status, _h, body = call_json(
            "GET", "/cross-references", content_length="abc"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")  # type: ignore[index]

    def test_explicit_zero_length_is_an_empty_body(self) -> None:
        status, _h, body = get_summary(content_length="0")
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, [])

    def test_any_query_parameter_returns_400(self) -> None:
        for query_string in ("x=1", "focus=abc", "x"):
            status, _h, body = get_summary(query_string=query_string)
            self.assertEqual(status, "400 Bad Request", query_string)
            self.assertEqual(body["error"], "invalid_request")  # type: ignore[index]

    def test_bad_requests_do_not_touch_business_data(self) -> None:
        dependent = register_local()
        with patch_resolve():
            status, _h, _b = post_reference(dependent, REFERENCE_BODY)
        self.assertEqual(status, "201 Created")

        status, _h, _body = call_json(
            "GET", "/cross-references", query_string="x=1"
        )
        self.assertEqual(status, "400 Bad Request")
        status, _h, summary = get_summary()
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(summary), 1)  # type: ignore[arg-type]
        self.assertEqual(summary[0]["edge_present"], True)  # type: ignore[index]


if __name__ == "__main__":
    unittest.main()
