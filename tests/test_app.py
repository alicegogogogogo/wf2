from __future__ import annotations

import io
import json
import unittest

from provenance_api import app
from provenance_api.app import application

DIGEST_A = "a" * 64
DIGEST_B = "B" * 64
DIGEST_C = "c" * 64


def request(
    method: str, path: str, body: object = None
) -> tuple[str, list[tuple[str, str]], bytes]:
    captured: dict[str, object] = {}

    def start_response(status: str, headers: list[tuple[str, str]]) -> None:
        captured["status"] = status
        captured["headers"] = headers

    environ: dict[str, object] = {"REQUEST_METHOD": method, "PATH_INFO": path}
    if body is not None:
        raw = body if isinstance(body, bytes) else str(body).encode("utf-8")
        environ["wsgi.input"] = io.BytesIO(raw)
        environ["CONTENT_LENGTH"] = str(len(raw))

    chunks = application(environ, start_response)
    raw_body = b"".join(chunks)
    return str(captured["status"]), list(captured["headers"]), raw_body


def request_json(
    method: str, path: str, body: object = None
) -> tuple[str, list[tuple[str, str]], object]:
    status, headers, raw = request(method, path, body)
    return status, headers, json.loads(raw.decode("utf-8"))


def create_resource(
    name: str = "example",
    category: str = "code",
    digest: str = DIGEST_A,
    **extra: object,
) -> tuple[str, list[tuple[str, str]], object]:
    payload = {"name": name, "category": category, "digest": digest}
    payload.update(extra)
    return request_json("POST", "/resources", json.dumps(payload))


class ApplicationTests(unittest.TestCase):
    def setUp(self) -> None:
        app._STORE = app._ResourceStore()

    def test_health(self) -> None:
        status, headers, body = request_json("GET", "/health")

        self.assertEqual(status, "200 OK")
        self.assertIn(("Content-Type", "application/json; charset=utf-8"), headers)
        self.assertEqual(body, {"status": "ok"})

    def test_unknown_path(self) -> None:
        status, _headers, body = request_json("GET", "/missing")

        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "not_found")


class ResourceCreateTests(unittest.TestCase):
    def setUp(self) -> None:
        app._STORE = app._ResourceStore()

    def test_create_returns_new_resource_with_id(self) -> None:
        status, headers, body = create_resource(origin="https://example.com/repo")

        self.assertEqual(status, "201 Created")
        self.assertIn(("Content-Type", "application/json; charset=utf-8"), headers)
        self.assertEqual(
            body,
            {
                "id": "res-000001",
                "name": "example",
                "category": "code",
                "digest": DIGEST_A,
                "origin": "https://example.com/repo",
            },
        )

    def test_create_response_is_compact_and_newline_terminated(self) -> None:
        _status, _headers, raw = request(
            "POST",
            "/resources",
            json.dumps({"name": "example", "category": "code", "digest": DIGEST_A}),
        )

        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(b" ", raw.strip())

    def test_category_is_case_insensitive_and_normalized(self) -> None:
        status, _headers, body = create_resource(category="Model")

        self.assertEqual(status, "201 Created")
        self.assertEqual(body["category"], "model")

    def test_digest_is_normalized_to_lowercase(self) -> None:
        status, _headers, body = create_resource(digest=DIGEST_B)

        self.assertEqual(status, "201 Created")
        self.assertEqual(body["digest"], DIGEST_B.lower())

    def test_duplicate_registration_conflicts(self) -> None:
        first_status, _headers, first = create_resource()
        second_status, _headers, second = create_resource()

        self.assertEqual(first_status, "201 Created")
        self.assertEqual(second_status, "409 Conflict")
        self.assertEqual(second["error"], "duplicate_resource")
        # The original record is untouched and still fetchable.
        status, _headers, fetched = request_json("GET", f"/resources/{first['id']}")
        self.assertEqual(status, "200 OK")
        self.assertEqual(fetched, first)

    def test_same_name_different_digest_is_allowed(self) -> None:
        self.assertEqual(create_resource()[0], "201 Created")
        self.assertEqual(create_resource(digest=DIGEST_C)[0], "201 Created")

    def test_missing_required_fields_rejected(self) -> None:
        for payload in (
            {"category": "code", "digest": DIGEST_A},
            {"name": "example", "digest": DIGEST_A},
            {"name": "example", "category": "code"},
        ):
            status, _headers, body = request_json("POST", "/resources", json.dumps(payload))
            self.assertEqual(status, "400 Bad Request")
            self.assertEqual(body["error"], "missing_field")

    def test_missing_body_rejected(self) -> None:
        status, _headers, body = request_json("POST", "/resources")

        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_json")

    def test_undecodable_body_rejected(self) -> None:
        status, _headers, body = request_json("POST", "/resources", b"{not json")

        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_json")

    def test_non_object_body_rejected(self) -> None:
        for raw in ("[1,2]", '"text"', "42", "null", "true"):
            status, _headers, body = request_json("POST", "/resources", raw)
            self.assertEqual(status, "400 Bad Request", raw)
            self.assertEqual(body["error"], "invalid_json")

    def test_trailing_data_rejected(self) -> None:
        raw = '{"name":"a","category":"code","digest":"%s"} {"name":"b"}' % DIGEST_A
        status, _headers, body = request_json("POST", "/resources", raw)

        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_json")

    def test_wrong_field_types_rejected(self) -> None:
        cases = (
            ({"name": 1, "category": "code", "digest": DIGEST_A}, "invalid_field"),
            ({"name": "example", "category": 2, "digest": DIGEST_A}, "invalid_field"),
            ({"name": "example", "category": "code", "digest": 3}, "invalid_digest"),
            (
                {"name": "example", "category": "code", "digest": DIGEST_A, "origin": 4},
                "invalid_field",
            ),
        )
        for payload, code in cases:
            status, _headers, body = request_json("POST", "/resources", json.dumps(payload))
            self.assertEqual(status, "400 Bad Request", payload)
            self.assertEqual(body["error"], code, payload)

    def test_empty_name_rejected(self) -> None:
        for name in ("", "   "):
            status, _headers, body = create_resource(name=name)
            self.assertEqual(status, "400 Bad Request")
            self.assertEqual(body["error"], "invalid_field")

    def test_unknown_field_rejected(self) -> None:
        status, _headers, body = create_resource(extra="nope")

        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "unknown_field")

    def test_unknown_category_rejected(self) -> None:
        status, _headers, body = create_resource(category="firmware")

        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_category")

    def test_all_four_categories_accepted(self) -> None:
        for index, category in enumerate(("code", "model", "dataset", "build-artifact")):
            status, _headers, _body = create_resource(
                name=f"res-{index}", category=category
            )
            self.assertEqual(status, "201 Created", category)

    def test_invalid_digest_rejected(self) -> None:
        for digest in ("", "abc", "g" * 64, "a" * 63, "a" * 65):
            status, _headers, body = create_resource(digest=digest)
            self.assertEqual(status, "400 Bad Request", digest)
            self.assertEqual(body["error"], "invalid_digest")

    def test_failed_creation_leaves_no_partial_record(self) -> None:
        create_resource(category="nope")
        create_resource(name="")

        status, _headers, body = request_json("GET", "/resources")
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, [])


class ResourceQueryTests(unittest.TestCase):
    def setUp(self) -> None:
        app._STORE = app._ResourceStore()

    def test_list_empty_is_valid_json_array(self) -> None:
        status, _headers, raw = request("GET", "/resources")

        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")
        self.assertEqual(json.loads(raw.decode("utf-8")), [])

    def test_list_returns_creation_order(self) -> None:
        create_resource(name="first", digest=DIGEST_A)
        create_resource(name="second", digest=DIGEST_B)
        create_resource(name="third", digest=DIGEST_C)

        status, _headers, body = request_json("GET", "/resources")

        self.assertEqual(status, "200 OK")
        self.assertEqual([item["name"] for item in body], ["first", "second", "third"])

    def test_get_by_id(self) -> None:
        _status, _headers, created = create_resource()

        status, _headers, body = request_json("GET", f"/resources/{created['id']}")

        self.assertEqual(status, "200 OK")
        self.assertEqual(body, created)

    def test_get_unknown_id_returns_404(self) -> None:
        status, _headers, body = request_json("GET", "/resources/res-999999")

        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "not_found")

    def test_empty_id_returns_400(self) -> None:
        status, _headers, body = request_json("GET", "/resources/")

        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_id")

    def test_id_with_path_separator_returns_400(self) -> None:
        status, _headers, body = request_json("GET", "/resources/a/b")

        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_id")

    def test_undeclared_methods_return_405(self) -> None:
        for method, path in (
            ("PUT", "/resources"),
            ("DELETE", "/resources"),
            ("POST", "/resources/res-000001"),
            ("DELETE", "/resources/res-000001"),
        ):
            status, _headers, body = request_json(method, path)
            self.assertEqual(status, "405 Method Not Allowed", (method, path))
            self.assertEqual(body["error"], "method_not_allowed")

    def test_failed_queries_do_not_change_state(self) -> None:
        create_resource()
        request_json("GET", "/resources/res-999999")
        request_json("DELETE", "/resources/res-000001")

        _status, _headers, body = request_json("GET", "/resources")
        self.assertEqual(len(body), 1)


if __name__ == "__main__":
    unittest.main()
