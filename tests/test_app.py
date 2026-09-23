from __future__ import annotations

import io
import json
import unittest

from provenance_api.app import application, store

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64


def call(
    method: str,
    path: str,
    body: bytes | str | dict[str, object] | None = None,
    *,
    content_length: int | None = None,
) -> tuple[str, list[tuple[str, str]], bytes]:
    if body is None:
        payload = b""
        length = "0"
    elif isinstance(body, dict):
        payload = json.dumps(body).encode("utf-8")
        length = str(len(payload))
    else:
        payload = body.encode("utf-8") if isinstance(body, str) else body
        length = str(len(payload))

    environ: dict[str, object] = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "wsgi.input": io.BytesIO(payload),
        "CONTENT_LENGTH": length if content_length is None else str(content_length),
    }
    captured: dict[str, object] = {}

    def start_response(status: str, headers: list[tuple[str, str]]) -> None:
        captured["status"] = status
        captured["headers"] = headers

    chunks = application(environ, start_response)
    return str(captured["status"]), list(captured["headers"]), b"".join(chunks)


def call_json(
    method: str, path: str, body: bytes | str | dict[str, object] | None = None
) -> tuple[str, list[tuple[str, str]], dict[str, object]]:
    status, headers, raw = call(method, path, body)
    return status, headers, json.loads(raw.decode("utf-8"))


class ApplicationTests(unittest.TestCase):
    def setUp(self) -> None:
        store.reset()

    # --- Baseline behavior -------------------------------------------------

    def test_health(self) -> None:
        status, headers, body = call_json("GET", "/health")

        self.assertEqual(status, "200 OK")
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )
        self.assertEqual(body, {"status": "ok"})

    def test_health_body_unchanged(self) -> None:
        _status, _headers, raw = call("GET", "/health")
        self.assertEqual(raw, b'{"status":"ok"}')

    def test_unknown_path(self) -> None:
        status, _headers, body = call_json("GET", "/missing")

        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "not_found")

    # --- Registration ------------------------------------------------------

    def test_create_resource(self) -> None:
        status, headers, body = call_json(
            "POST",
            "/resources",
            {
                "name": "model-a",
                "category": "Model",
                "digest": "A" + "0" * 63,
                "source": "https://example.invalid/a",
            },
        )

        self.assertEqual(status, "201 Created")
        self.assertEqual(headers[0][1], "application/json; charset=utf-8")
        self.assertIsInstance(body["id"], str)
        self.assertEqual(len(body["id"]), 32)
        self.assertEqual(body["name"], "model-a")
        # Category is case-insensitive; digest casing is normalized.
        self.assertEqual(body["category"], "model")
        self.assertEqual(body["digest"], "a" + "0" * 63)
        self.assertEqual(body["source"], "https://example.invalid/a")

    def test_create_without_source_defaults_to_null(self) -> None:
        _status, _headers, body = call_json(
            "POST",
            "/resources",
            {"name": "x", "category": "code", "digest": DIGEST_A},
        )
        self.assertIsNone(body["source"])

    def test_response_ends_with_newline_and_compact(self) -> None:
        status, _headers, raw = call(
            "POST",
            "/resources",
            {"name": "x", "category": "code", "digest": DIGEST_A},
        )
        self.assertEqual(status, "201 Created")
        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(b" ", raw[:-1])

    def test_each_resource_gets_stable_id(self) -> None:
        _s, _h, first = call_json(
            "POST",
            "/resources",
            {"name": "x", "category": "code", "digest": DIGEST_A},
        )
        _s, _h, second = call_json(
            "POST",
            "/resources",
            {"name": "x", "category": "code", "digest": DIGEST_B},
        )
        _s, _h, fetched = call_json(
            "GET", f"/resources/{first['id']}"
        )
        self.assertEqual(fetched["id"], first["id"])
        self.assertNotEqual(first["id"], second["id"])

    # --- Duplicates --------------------------------------------------------

    def test_duplicate_returns_conflict_and_keeps_original(self) -> None:
        _s, _h, original = call_json(
            "POST",
            "/resources",
            {
                "name": "x",
                "category": "MODEL",
                "digest": "A" * 64,
                "source": "origin",
            },
        )
        status, _headers, body = call_json(
            "POST",
            "/resources",
            {
                "name": "x",
                "category": "model",
                "digest": "a" * 64,
                "source": "changed-origin",
            },
        )

        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "duplicate_resource")

        _s, _h, fetched = call_json(
            "GET", f"/resources/{original['id']}"
        )
        self.assertEqual(fetched["source"], "origin")

        _s, _h, listing = call_json("GET", "/resources")
        self.assertEqual(len(listing["resources"]), 1)

    def test_duplicate_different_source_is_still_conflict(self) -> None:
        call_json(
            "POST",
            "/resources",
            {"name": "x", "category": "code", "digest": DIGEST_A},
        )
        status, _h, body = call_json(
            "POST",
            "/resources",
            {
                "name": "x",
                "category": "code",
                "digest": DIGEST_A,
                "source": "elsewhere",
            },
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "duplicate_resource")

    # --- Bad requests ------------------------------------------------------

    def test_missing_body_is_bad_request(self) -> None:
        status, _headers, body = call_json("POST", "/resources", None)
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_malformed_json_is_bad_request(self) -> None:
        status, _headers, body = call_json(
            "POST", "/resources", b"{not json"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_non_object_top_level_is_bad_request(self) -> None:
        for bad in (b"[]", b'"x"', b"42", b"null"):
            with self.subTest(bad=bad):
                status, _headers, body = call_json(
                    "POST", "/resources", bad
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_missing_required_fields(self) -> None:
        cases = [
            {"category": "code", "digest": DIGEST_A},
            {"name": "x", "digest": DIGEST_A},
            {"name": "x", "category": "code"},
        ]
        for payload in cases:
            with self.subTest(payload=payload):
                status, _headers, body = call_json(
                    "POST", "/resources", payload
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_wrong_field_types(self) -> None:
        valid = {"name": "x", "category": "code", "digest": DIGEST_A}
        for field, bad_value in [
            ("name", 12),
            ("category", 4),
            ("digest", 5),
            ("source", 9),
        ]:
            payload = dict(valid)
            payload[field] = bad_value
            with self.subTest(field=field):
                status, _headers, body = call_json(
                    "POST", "/resources", payload
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_empty_name_and_empty_source(self) -> None:
        for payload in [
            {"name": "   ", "category": "code", "digest": DIGEST_A},
            {
                "name": "x",
                "category": "code",
                "digest": DIGEST_A,
                "source": "  ",
            },
        ]:
            with self.subTest(payload=payload):
                status, _headers, body = call_json(
                    "POST", "/resources", payload
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_unknown_category(self) -> None:
        status, _headers, body = call_json(
            "POST",
            "/resources",
            {"name": "x", "category": "image", "digest": DIGEST_A},
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_bad_digest(self) -> None:
        for digest in ["", "z" * 64, "a" * 63, "a" * 65, "g" * 64]:
            with self.subTest(digest=digest):
                status, _headers, body = call_json(
                    "POST",
                    "/resources",
                    {"name": "x", "category": "code", "digest": digest},
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_unknown_field_rejected(self) -> None:
        status, _headers, body = call_json(
            "POST",
            "/resources",
            {
                "name": "x",
                "category": "code",
                "digest": DIGEST_A,
                "extra": 1,
            },
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_failed_create_leaves_no_records(self) -> None:
        call_json(
            "POST",
            "/resources",
            {"name": "x", "category": "nope", "digest": DIGEST_A},
        )
        _s, _h, listing = call_json("GET", "/resources")
        self.assertEqual(listing["resources"], [])

    # --- Item lookup -------------------------------------------------------

    def test_get_unknown_id_is_not_found(self) -> None:
        status, _headers, body = call_json(
            "GET", "/resources/does-not-exist"
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

    def test_get_with_path_separator_is_bad_request(self) -> None:
        _s, _h, created = call_json(
            "POST",
            "/resources",
            {"name": "x", "category": "code", "digest": DIGEST_A},
        )
        for raw_id in ["a/b", "a\\b", f"{created['id']}/x"]:
            with self.subTest(raw_id=raw_id):
                status, _headers, body = call_json(
                    "GET", f"/resources/{raw_id}"
                )
                # PATH_INFO with an embedded slash is a different path shape;
                # either way it must be 4xx JSON and never 200.
                self.assertIn(status[:3], {"400", "404"})
                self.assertIn("error", body)

    def test_item_unsupported_method(self) -> None:
        status, headers, body = call_json(
            "DELETE", "/resources/anything"
        )
        self.assertEqual(status, "405 Method Not Allowed")
        self.assertEqual(body["error"], "method_not_allowed")
        self.assertIn(("Allow", "GET"), headers)

    # --- Collection --------------------------------------------------------

    def test_empty_listing_is_valid_json(self) -> None:
        status, _headers, body = call_json("GET", "/resources")
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, {"resources": []})

    def test_listing_preserves_insertion_order(self) -> None:
        _s, _h, first = call_json(
            "POST",
            "/resources",
            {"name": "first", "category": "code", "digest": DIGEST_A},
        )
        _s, _h, second = call_json(
            "POST",
            "/resources",
            {"name": "second", "category": "dataset", "digest": DIGEST_B},
        )

        _s, _h, body = call_json("GET", "/resources")
        ids = [r["id"] for r in body["resources"]]
        self.assertEqual(ids, [first["id"], second["id"]])
        self.assertTrue(all(r["category"] in {"code", "model", "dataset", "artifact"} for r in body["resources"]))

    def test_collection_unsupported_method(self) -> None:
        status, headers, body = call_json("PUT", "/resources")
        self.assertEqual(status, "405 Method Not Allowed")
        self.assertEqual(body["error"], "method_not_allowed")
        self.assertIn(("Allow", "GET, POST"), headers)


if __name__ == "__main__":
    unittest.main()
