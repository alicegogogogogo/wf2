from __future__ import annotations

import hashlib
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
    query_string: str | None = None,
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
    if query_string is not None:
        environ["QUERY_STRING"] = query_string
    captured: dict[str, object] = {}

    def start_response(status: str, headers: list[tuple[str, str]]) -> None:
        captured["status"] = status
        captured["headers"] = headers

    chunks = application(environ, start_response)
    return str(captured["status"]), list(captured["headers"]), b"".join(chunks)


def call_json(
    method: str,
    path: str,
    body: bytes | str | dict[str, object] | None = None,
    *,
    query_string: str | None = None,
) -> tuple[str, list[tuple[str, str]], dict[str, object]]:
    status, headers, raw = call(
        method, path, body, query_string=query_string
    )
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

    # --- Filtering ---------------------------------------------------------

    def _create(
        self,
        name: str,
        category: str,
        digest: str,
        source: str | None = None,
    ) -> str:
        payload: dict[str, object] = {
            "name": name,
            "category": category,
            "digest": digest,
        }
        if source is not None:
            payload["source"] = source
        _s, _h, body = call_json("POST", "/resources", payload)
        return str(body["id"])

    def _seed(self) -> list[str]:
        # Four resources in a known order, with mixed categories/digests.
        ids = [
            self._create("a", "Model", "A" + "0" * 63),
            self._create("b", "code", "B" + "0" * 63),
            self._create("a", "MODEL", "C" + "0" * 63),
            self._create("a", "code", "A" + "0" * 63),
        ]
        return ids

    def test_unfiltered_shape_is_unchanged(self) -> None:
        self._seed()
        status, _headers, raw = call("GET", "/resources")
        self.assertEqual(status, "200 OK")
        body = json.loads(raw.decode("utf-8"))
        self.assertNotIn("next_cursor", body)
        self.assertEqual(len(body["resources"]), 4)
        self.assertTrue(raw.endswith(b"\n"))

    def test_filter_category_is_case_insensitive(self) -> None:
        ids = self._seed()
        for value in ("model", "MODEL", "MoDeL"):
            with self.subTest(value=value):
                _s, _h, body = call_json(
                    "GET", "/resources", query_string=f"category={value}"
                )
                self.assertEqual(
                    [r["id"] for r in body["resources"]], [ids[0], ids[2]]
                )
                self.assertTrue(
                    all(r["category"] == "model" for r in body["resources"])
                )
                self.assertIn("next_cursor", body)
                self.assertIsNone(body["next_cursor"])

    def test_filter_name_is_exact(self) -> None:
        ids = self._seed()
        _s, _h, body = call_json(
            "GET", "/resources", query_string="name=a"
        )
        self.assertEqual(
            [r["id"] for r in body["resources"]], [ids[0], ids[2], ids[3]]
        )
        # No folding or trimming: near-matches produce an empty result.
        _s, _h, miss = call_json(
            "GET", "/resources", query_string="name=A"
        )
        self.assertEqual(miss["resources"], [])
        self.assertIsNone(miss["next_cursor"])

    def test_filter_digest_accepts_mixed_case(self) -> None:
        ids = self._seed()
        _s, _h, body = call_json(
            "GET", "/resources",
            query_string="digest=" + "a" + "0" * 63,
        )
        self.assertEqual(
            [r["id"] for r in body["resources"]], [ids[0], ids[3]]
        )

    def test_filters_are_combined_with_and(self) -> None:
        ids = self._seed()
        _s, _h, body = call_json(
            "GET", "/resources",
            query_string="category=model&name=a&digest=" + "c" + "0" * 63,
        )
        self.assertEqual(
            [r["id"] for r in body["resources"]], [ids[2]]
        )

    def test_no_match_is_empty_not_error(self) -> None:
        self._seed()
        _s, _h, body = call_json(
            "GET", "/resources", query_string="category=dataset"
        )
        self.assertEqual(body, {"resources": [], "next_cursor": None})

    def test_filter_does_not_mutate_store(self) -> None:
        self._seed()
        call_json("GET", "/resources", query_string="category=model")
        _s, _h, body = call_json("GET", "/resources")
        self.assertEqual(len(body["resources"]), 4)

    # --- Pagination --------------------------------------------------------

    def test_default_limit_is_fifty(self) -> None:
        for i in range(55):
            self._create(f"r{i}", "code", f"{i:064x}")
        _s, _h, first = call_json("GET", "/resources", query_string="limit=100")
        self.assertEqual(len(first["resources"]), 55)
        self.assertIsNone(first["next_cursor"])

        _s, _h, default = call_json(
            "GET", "/resources", query_string="category=code"
        )
        self.assertEqual(len(default["resources"]), 50)
        self.assertIsNotNone(default["next_cursor"])

    def test_limit_max_is_one_hundred(self) -> None:
        for i in range(3):
            self._create(f"r{i}", "code", f"{i:064x}")
        status, _h, body = call_json(
            "GET", "/resources", query_string="limit=100"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(body["resources"]), 3)
        self.assertIsNone(body["next_cursor"])

    def test_pagination_walks_all_without_gaps_or_dupes(self) -> None:
        ids = [self._create(f"r{i}", "code", f"{i:064x}") for i in range(7)]
        seen: list[str] = []
        cursor: str | None = None
        pages = 0
        while True:
            qs = "limit=3"
            if cursor is not None:
                qs += "&cursor=" + cursor
            _s, _h, body = call_json(
                "GET", "/resources", query_string=qs
            )
            page = [r["id"] for r in body["resources"]]
            self.assertLessEqual(len(page), 3)
            seen.extend(page)
            pages += 1
            cursor = body["next_cursor"]
            if cursor is None:
                break
        self.assertEqual(pages, 3)
        self.assertEqual(seen, ids)

    def test_cursor_continues_after_last_page_item(self) -> None:
        ids = [self._create(f"r{i}", "code", f"{i:064x}") for i in range(5)]
        _s, _h, first = call_json(
            "GET", "/resources", query_string="limit=2"
        )
        self.assertEqual([r["id"] for r in first["resources"]], ids[0:2])
        _s, _h, second = call_json(
            "GET", "/resources",
            query_string="limit=2&cursor=" + first["next_cursor"],
        )
        self.assertEqual([r["id"] for r in second["resources"]], ids[2:4])
        _s, _h, third = call_json(
            "GET", "/resources",
            query_string="limit=2&cursor=" + second["next_cursor"],
        )
        self.assertEqual([r["id"] for r in third["resources"]], ids[4:])
        self.assertIsNone(third["next_cursor"])

    def test_cursor_respects_filter_and_keeps_order(self) -> None:
        ids = self._seed()
        _s, _h, first = call_json(
            "GET", "/resources",
            query_string="category=model&limit=1",
        )
        self.assertEqual([r["id"] for r in first["resources"]], [ids[0]])
        _s, _h, second = call_json(
            "GET", "/resources",
            query_string="category=MODEL&limit=1&cursor="
            + first["next_cursor"],
        )
        self.assertEqual([r["id"] for r in second["resources"]], [ids[2]])
        self.assertIsNone(second["next_cursor"])

    def test_repeating_cursor_request_is_stable(self) -> None:
        for i in range(4):
            self._create(f"r{i}", "code", f"{i:064x}")
        _s, _h, first = call_json(
            "GET", "/resources", query_string="limit=2"
        )
        qs = "limit=2&cursor=" + first["next_cursor"]
        _s, _h, again = call_json("GET", "/resources", query_string=qs)
        _s, _h, again2 = call_json("GET", "/resources", query_string=qs)
        self.assertEqual(
            [r["id"] for r in again["resources"]],
            [r["id"] for r in again2["resources"]],
        )

    def test_paged_response_key_order(self) -> None:
        self._create("r", "code", "0" * 64)
        _s, _h, raw = call(
            "GET", "/resources", query_string="limit=1"
        )
        text = raw.decode("utf-8").rstrip("\n")
        self.assertLess(text.index("resources"), text.index("next_cursor"))

    # --- Invalid list requests ---------------------------------------------

    def assert_invalid_request(self, query_string: str) -> None:
        status, _headers, body = call_json(
            "GET", "/resources", query_string=query_string
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_unknown_query_parameter_rejected(self) -> None:
        self.assert_invalid_request("limit=2&bogus=1")

    def test_repeated_query_parameter_rejected(self) -> None:
        self.assert_invalid_request("category=code&category=model")
        self.assert_invalid_request("limit=2&limit=3")

    def test_empty_category_and_name_rejected(self) -> None:
        self.assert_invalid_request("category=")
        self.assert_invalid_request("name=")

    def test_illegal_category_rejected(self) -> None:
        self.assert_invalid_request("category=image")

    def test_bad_digest_rejected(self) -> None:
        for digest in ("", "z" * 64, "a" * 63, "g" * 64):
            with self.subTest(digest=digest):
                self.assert_invalid_request("digest=" + digest)

    def test_bad_limit_rejected(self) -> None:
        for limit in ("0", "-1", "1.5", "abc", "101", "1e2", " 2", ""):
            with self.subTest(limit=limit):
                self.assert_invalid_request("limit=" + limit)

    def test_forged_or_corrupt_cursor_rejected(self) -> None:
        self._create("r", "code", "0" * 64)
        for cursor in (
            "not-a-cursor",
            "AAAA",
            "AAAA.",
            ".AAAA",
            "%%%",
            "MQ%3D%3D.aaaa",
        ):
            with self.subTest(cursor=cursor):
                self.assert_invalid_request("cursor=" + cursor)

    def test_cursor_bound_to_filter_conditions(self) -> None:
        for i in range(4):
            self._create(f"r{i}", "code", f"{i:064x}")
            self._create(f"m{i}", "model", f"{i + 10:064x}")
        _s, _h, first = call_json(
            "GET", "/resources", query_string="category=code&limit=2"
        )
        cursor = first["next_cursor"]
        # Same cursor with a changed filter or limit must be rejected.
        self.assert_invalid_request("category=model&limit=2&cursor=" + cursor)
        self.assert_invalid_request("limit=3&cursor=" + cursor)
        self.assert_invalid_request("cursor=" + cursor)

        # A cursor issued in one process must not validate after the store's
        # process-local key rotates (simulated by re-issuing with a new key).
        from provenance_api import app as app_module

        original_key = app_module._cursor_key
        try:
            app_module._cursor_key = b"k" * 32
            self.assert_invalid_request(
                "category=code&limit=2&cursor=" + cursor
            )
        finally:
            app_module._cursor_key = original_key

    def test_invalid_list_request_keeps_resources(self) -> None:
        self._create("r", "code", "0" * 64)
        self.assert_invalid_request("category=bad&limit=0")
        _s, _h, body = call_json("GET", "/resources")
        self.assertEqual(len(body["resources"]), 1)


class DependencyTests(unittest.TestCase):
    def setUp(self) -> None:
        store.reset()

    def _create(self, name: str = "r", digest: str | None = None) -> str:
        payload = {
            "name": name,
            "category": "code",
            "digest": digest if digest is not None else name * 64,
        }
        _s, _h, body = call_json("POST", "/resources", payload)
        return str(body["id"])

    def _add(self, resource_id: str, dependency_id: str):
        return call_json(
            "POST",
            f"/resources/{resource_id}/dependencies",
            {"dependency_id": dependency_id},
        )

    # --- Creating relations ------------------------------------------------

    def test_create_dependency_returns_relation(self) -> None:
        a = self._create("a")
        b = self._create("b")
        status, headers, body = self._add(a, b)

        self.assertEqual(status, "201 Created")
        self.assertEqual(
            headers[0], ("Content-Type", "application/json; charset=utf-8")
        )
        self.assertEqual(
            body, {"resource_id": a, "dependency_id": b}
        )

    def test_create_response_is_compact_utf8_and_newline_terminated(self) -> None:
        a = self._create("a")
        b = self._create("b")
        status, _headers, raw = call(
            "POST",
            f"/resources/{a}/dependencies",
            {"dependency_id": b},
        )
        self.assertEqual(status, "201 Created")
        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(b" ", raw[:-1])
        self.assertEqual(
            raw,
            b'{"resource_id":"' + a.encode() + b'","dependency_id":"'
            + b.encode() + b'"}\n',
        )

    def test_duplicate_same_direction_is_conflict(self) -> None:
        a = self._create("a")
        b = self._create("b")
        self._add(a, b)
        status, _headers, body = self._add(a, b)

        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "duplicate_dependency")

        # The relation and resources are untouched: still exactly one edge.
        _s, _h, deps = call_json("GET", f"/resources/{a}/dependencies")
        self.assertEqual(deps["dependencies"], [b])

    def test_reverse_direction_is_a_distinct_relation(self) -> None:
        a = self._create("a")
        b = self._create("b")
        self._add(a, b)
        # b -> a is not a duplicate (and would be a cycle), so it must be
        # rejected as a cycle, not a duplicate.
        status, _headers, body = self._add(b, a)
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "dependency_cycle")

    def test_self_loop_is_cycle(self) -> None:
        a = self._create("a")
        status, _headers, body = self._add(a, a)
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "dependency_cycle")

        _s, _h, deps = call_json("GET", f"/resources/{a}/dependencies")
        self.assertEqual(deps["dependencies"], [])

    def test_indirect_cycle_is_rejected(self) -> None:
        # a -> b -> c ; closing with c -> a must fail and change nothing.
        a = self._create("a")
        b = self._create("b")
        c = self._create("c")
        self._add(a, b)
        self._add(b, c)
        status, _headers, body = self._add(c, a)
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "dependency_cycle")

        _s, _h, deps_c = call_json("GET", f"/resources/{c}/dependencies")
        self.assertEqual(deps_c["dependencies"], [])
        _s, _h, impact_a = call_json("GET", f"/resources/{a}/impact")
        self.assertEqual(impact_a["resources"], [])

    def test_diamond_does_not_trigger_cycle_or_duplicate(self) -> None:
        a = self._create("a")
        b = self._create("b")
        c = self._create("c")
        d = self._create("d")
        self._add(a, b)
        self._add(a, c)
        self._add(b, d)
        self._add(c, d)  # second inbound edge to d is fine
        status, _h, deps = call_json("GET", f"/resources/{a}/dependencies")
        self.assertEqual(status, "200 OK")
        self.assertEqual(deps["dependencies"], [b, c, d])

    def test_adding_existing_transitive_dependency_directly_is_allowed(self) -> None:
        a = self._create("a")
        b = self._create("b")
        c = self._create("c")
        self._add(a, b)
        self._add(b, c)
        # a already reaches c transitively; the direct edge is new, not a dup.
        status, _h, body = self._add(a, c)
        self.assertEqual(status, "201 Created")
        self.assertEqual(body, {"resource_id": a, "dependency_id": c})

    # --- Listing / impact --------------------------------------------------

    def test_dependencies_listed_transitively_in_registration_order(self) -> None:
        a = self._create("a")
        b = self._create("b")
        c = self._create("c")
        d = self._create("d")
        self._add(a, d)  # edge to the latest resource registered first
        self._add(a, b)
        self._add(b, c)

        _s, _h, body = call_json("GET", f"/resources/{a}/dependencies")
        # Reachable set {b,c,d} expanded in registration order, each once.
        self.assertEqual(body["dependencies"], [b, c, d])

    def test_each_resource_appears_once_even_with_multiple_paths(self) -> None:
        a = self._create("a")
        b = self._create("b")
        c = self._create("c")
        d = self._create("d")
        e = self._create("e")
        self._add(a, b)
        self._add(a, c)
        self._add(b, d)
        self._add(c, d)
        self._add(d, e)

        _s, _h, deps = call_json("GET", f"/resources/{a}/dependencies")
        self.assertEqual(deps["dependencies"], [b, c, d, e])
        self.assertEqual(len(deps["dependencies"]), len(set(deps["dependencies"])))

    def test_empty_dependencies_is_success(self) -> None:
        a = self._create("a")
        status, _headers, body = call_json(
            "GET", f"/resources/{a}/dependencies"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, {"dependencies": []})

    def test_impact_lists_dependents_excluding_start_in_registration_order(self) -> None:
        a = self._create("a")
        b = self._create("b")
        c = self._create("c")
        d = self._create("d")
        self._add(a, b)
        self._add(b, c)
        self._add(d, b)  # d also reaches c through b

        _s, _h, impact = call_json("GET", f"/resources/{c}/impact")
        # Direct/indirect dependents of c: a, b, d; start c excluded.
        self.assertEqual(impact["resources"], [a, b, d])

    def test_impact_empty_for_leaf_resource(self) -> None:
        a = self._create("a")
        b = self._create("b")
        self._add(a, b)
        _s, _h, impact = call_json("GET", f"/resources/{a}/impact")
        self.assertEqual(impact["resources"], [])

    def test_query_responses_are_newline_terminated(self) -> None:
        a = self._create("a")
        _s, _h, raw_deps = call("GET", f"/resources/{a}/dependencies")
        _s, _h, raw_impact = call("GET", f"/resources/{a}/impact")
        self.assertTrue(raw_deps.endswith(b"\n"))
        self.assertTrue(raw_impact.endswith(b"\n"))
        self.assertEqual(raw_deps, b'{"dependencies":[]}\n')
        self.assertEqual(raw_impact, b'{"resources":[]}\n')

    # --- Not found ---------------------------------------------------------

    def test_missing_start_returns_404_for_all_queries(self) -> None:
        for method, path in [
            ("GET", "/resources/missing/dependencies"),
            ("GET", "/resources/missing/impact"),
        ]:
            with self.subTest(path=path):
                status, _headers, body = call_json(method, path)
                self.assertEqual(status, "404 Not Found")
                self.assertEqual(body["error"], "resource_not_found")

    def test_create_with_missing_start_is_not_found(self) -> None:
        b = self._create("b")
        status, _headers, body = self._add("missing", b)
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

    def test_create_with_missing_dependency_is_not_found(self) -> None:
        a = self._create("a")
        status, _headers, body = self._add(a, "missing")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")
        # No half-created relation.
        _s, _h, deps = call_json("GET", f"/resources/{a}/dependencies")
        self.assertEqual(deps["dependencies"], [])

    # --- Bad requests ------------------------------------------------------

    def test_empty_path_id_is_bad_request(self) -> None:
        for method, path in [
            ("GET", "/resources//dependencies"),
            ("GET", "/resources//impact"),
            ("POST", "/resources//dependencies"),
        ]:
            with self.subTest(method=method, path=path):
                body = {"dependency_id": "x"} if method == "POST" else None
                status, _headers, payload = call_json(method, path, body)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(payload["error"], "invalid_request")

    def test_path_id_with_separator_is_bad_request(self) -> None:
        for raw in ("a/b", "a\\b"):
            with self.subTest(raw=raw):
                status, _headers, body = call_json(
                    "GET", f"/resources/{raw}/dependencies"
                )
                self.assertIn(status[:3], {"400", "404"})
                self.assertIn("error", body)

    def test_missing_body_is_bad_request(self) -> None:
        a = self._create("a")
        status, _headers, body = call_json(
            "POST", f"/resources/{a}/dependencies", None
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_malformed_or_non_utf8_json_is_bad_request(self) -> None:
        a = self._create("a")
        status, _headers, body = call_json(
            "POST", f"/resources/{a}/dependencies", b"{bad"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

        _status, _headers, raw = call(
            "POST", f"/resources/{a}/dependencies", b"\xff\xfe"
        )
        self.assertEqual(_status, "400 Bad Request")
        self.assertEqual(json.loads(raw)["error"], "invalid_request")

    def test_non_object_body_is_bad_request(self) -> None:
        a = self._create("a")
        for bad in (b"[]", b'"x"', b"42", b"null"):
            with self.subTest(bad=bad):
                status, _headers, body = call_json(
                    "POST", f"/resources/{a}/dependencies", bad
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_missing_dependency_id_is_bad_request(self) -> None:
        a = self._create("a")
        status, _headers, body = call_json(
            "POST", f"/resources/{a}/dependencies", {}
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_bad_dependency_id_value_is_bad_request(self) -> None:
        a = self._create("a")
        for bad in (5, True, None, ["x"], "", "x/y", "x\\y"):
            with self.subTest(bad=bad):
                status, _headers, body = call_json(
                    "POST",
                    f"/resources/{a}/dependencies",
                    {"dependency_id": bad},
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")
        # Relation never created despite the rejected attempts.
        _s, _h, deps = call_json("GET", f"/resources/{a}/dependencies")
        self.assertEqual(deps["dependencies"], [])

    def test_whitespace_dependency_id_names_no_resource(self) -> None:
        # Non-empty and separator-free, so it is syntactically an id but
        # simply does not exist -> 404, not 400.
        a = self._create("a")
        status, _headers, body = call_json(
            "POST",
            f"/resources/{a}/dependencies",
            {"dependency_id": "   "},
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

    def test_unknown_body_field_is_bad_request(self) -> None:
        a = self._create("a")
        b = self._create("b")
        status, _headers, body = call_json(
            "POST",
            f"/resources/{a}/dependencies",
            {"dependency_id": b, "extra": 1},
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_unknown_query_parameter_is_bad_request(self) -> None:
        a = self._create("a")
        b = self._create("b")
        for method, path, body in [
            ("GET", f"/resources/{a}/dependencies", None),
            ("GET", f"/resources/{a}/impact", None),
            ("POST", f"/resources/{a}/dependencies", {"dependency_id": b}),
        ]:
            with self.subTest(method=method, path=path):
                status, _headers, payload = call_json(
                    method, path, body, query_string="bogus=1"
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(payload["error"], "invalid_request")

    # --- Method handling ---------------------------------------------------

    def test_unsupported_methods_return_405_with_allow(self) -> None:
        a = self._create("a")
        b = self._create("b")
        cases = [
            ("DELETE", f"/resources/{a}/dependencies", "GET, POST"),
            ("PUT", f"/resources/{a}/dependencies", "GET, POST"),
            ("POST", f"/resources/{a}/impact", "GET"),
            ("DELETE", f"/resources/{a}/impact", "GET"),
        ]
        for method, path, allow in cases:
            with self.subTest(method=method, path=path):
                body = (
                    {"dependency_id": b}
                    if path.endswith("dependencies") and method == "PUT"
                    else None
                )
                status, headers, payload = call_json(method, path, body)
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(payload["error"], "method_not_allowed")
                self.assertIn(("Allow", allow), headers)

    def test_failed_requests_leave_graph_and_resources_unchanged(self) -> None:
        a = self._create("a")
        b = self._create("b")
        self._add(a, b)
        # A rejected closing edge and assorted bad requests.
        self._add(b, a)
        call_json("POST", f"/resources/{a}/dependencies", {"dependency_id": 1})
        call_json("GET", f"/resources/missing/impact")
        _s, _h, listing = call_json("GET", "/resources")
        self.assertEqual(len(listing["resources"]), 2)
        _s, _h, deps = call_json("GET", f"/resources/{a}/dependencies")
        self.assertEqual(deps["dependencies"], [b])
        _s, _h, impact = call_json("GET", f"/resources/{b}/impact")
        self.assertEqual(impact["resources"], [a])


_AUTO = object()


def call_verify(
    method: str,
    path: str,
    body: bytes = b"",
    *,
    content_type: str | None = "application/octet-stream",
    content_length: int | None | object = _AUTO,
    query_string: str | None = None,
) -> tuple[str, list[tuple[str, str]], bytes]:
    environ: dict[str, object] = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "wsgi.input": io.BytesIO(body),
    }
    if content_length is _AUTO:
        environ["CONTENT_LENGTH"] = str(len(body))
    elif content_length is not None:
        environ["CONTENT_LENGTH"] = str(content_length)
    if content_type is not None:
        environ["CONTENT_TYPE"] = content_type
    if query_string is not None:
        environ["QUERY_STRING"] = query_string
    captured: dict[str, object] = {}

    def start_response(status: str, headers: list[tuple[str, str]]) -> None:
        captured["status"] = status
        captured["headers"] = headers

    chunks = application(environ, start_response)
    return str(captured["status"]), list(captured["headers"]), b"".join(chunks)


class VerifyTests(unittest.TestCase):
    def setUp(self) -> None:
        store.reset()

    def _create(self, name: str, digest: str) -> str:
        status, _headers, body = call_json(
            "POST",
            "/resources",
            {"name": name, "category": "code", "digest": digest},
        )
        self.assertEqual(status, "201 Created")
        return str(body["id"])

    def test_verify_matching_content_is_valid(self) -> None:
        content = b"hello supply chain"
        resource_id = self._create("a", hashlib.sha256(content).hexdigest())

        status, _headers, raw = call_verify(
            "POST", f"/resources/{resource_id}/verify", content
        )

        self.assertEqual(status, "200 OK")
        payload = json.loads(raw.decode("utf-8"))
        self.assertEqual(
            payload,
            {
                "id": resource_id,
                "digest": hashlib.sha256(content).hexdigest(),
                "valid": True,
            },
        )
        # Compact JSON, stable key order, newline terminated.
        self.assertTrue(raw.endswith(b"\n"))
        self.assertEqual(
            raw.decode("utf-8"),
            '{"id":"%s","digest":"%s","valid":true}\n'
            % (resource_id, hashlib.sha256(content).hexdigest()),
        )

    def test_verify_mismatched_content_is_invalid_but_200(self) -> None:
        resource_id = self._create("a", DIGEST_A)

        status, _headers, raw = call_verify(
            "POST", f"/resources/{resource_id}/verify", b"other bytes"
        )

        self.assertEqual(status, "200 OK")
        payload = json.loads(raw.decode("utf-8"))
        self.assertEqual(payload["id"], resource_id)
        self.assertEqual(
            payload["digest"], hashlib.sha256(b"other bytes").hexdigest()
        )
        self.assertIs(payload["valid"], False)

    def test_verify_empty_body_is_legal(self) -> None:
        empty_digest = hashlib.sha256(b"").hexdigest()
        resource_id = self._create("a", empty_digest)

        status, _headers, raw = call_verify(
            "POST", f"/resources/{resource_id}/verify", b"", content_length=0
        )

        self.assertEqual(status, "200 OK")
        payload = json.loads(raw.decode("utf-8"))
        self.assertEqual(payload["digest"], empty_digest)
        self.assertIs(payload["valid"], True)

    def test_verify_missing_content_length_is_bad_request(self) -> None:
        resource_id = self._create("a", DIGEST_A)

        status, _headers, raw = call_verify(
            "POST", f"/resources/{resource_id}/verify", b"data",
            content_length=None,
        )

        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(json.loads(raw.decode("utf-8"))["error"], "invalid_request")

    def test_verify_incomplete_body_is_bad_request(self) -> None:
        resource_id = self._create("a", DIGEST_A)

        status, _headers, raw = call_verify(
            "POST",
            f"/resources/{resource_id}/verify",
            b"short",
            content_length=100,
        )

        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(json.loads(raw.decode("utf-8"))["error"], "invalid_request")

    def test_verify_wrong_content_type_is_bad_request(self) -> None:
        resource_id = self._create("a", DIGEST_A)

        for content_type in ("application/json", "text/plain", None):
            with self.subTest(content_type=content_type):
                status, _headers, raw = call_verify(
                    "POST",
                    f"/resources/{resource_id}/verify",
                    b"data",
                    content_type=content_type,
                    content_length=4,
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(
                    json.loads(raw.decode("utf-8"))["error"], "invalid_request"
                )

    def test_verify_bad_path_id_is_bad_request(self) -> None:
        for raw_id in ("", "a/b", "a\\b"):
            path = f"/resources/{raw_id}/verify"
            with self.subTest(path=path):
                status, _headers, raw = call_verify(
                    "POST", path, b"data", content_length=4
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(
                    json.loads(raw.decode("utf-8"))["error"], "invalid_request"
                )

    def test_verify_unknown_resource_is_not_found(self) -> None:
        status, _headers, raw = call_verify(
            "POST", "/resources/missing/verify", b"data", content_length=4
        )

        self.assertEqual(status, "404 Not Found")
        self.assertEqual(
            json.loads(raw.decode("utf-8"))["error"], "resource_not_found"
        )

    def test_verify_query_parameters_are_bad_request(self) -> None:
        resource_id = self._create("a", DIGEST_A)

        status, _headers, raw = call_verify(
            "POST",
            f"/resources/{resource_id}/verify",
            b"data",
            content_length=4,
            query_string="bogus=1",
        )

        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(json.loads(raw.decode("utf-8"))["error"], "invalid_request")

    def test_verify_unsupported_methods_return_405_with_allow_post(self) -> None:
        resource_id = self._create("a", DIGEST_A)

        for method in ("GET", "PUT", "DELETE"):
            with self.subTest(method=method):
                status, headers, raw = call_verify(
                    method, f"/resources/{resource_id}/verify"
                )
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(
                    json.loads(raw.decode("utf-8"))["error"],
                    "method_not_allowed",
                )
                self.assertIn(("Allow", "POST"), headers)

    def test_failed_verify_requests_leave_state_unchanged(self) -> None:
        resource_id = self._create("a", DIGEST_A)
        call_verify("POST", f"/resources/{resource_id}/verify", b"x")
        call_verify(
            "POST",
            f"/resources/{resource_id}/verify",
            b"x",
            content_length=1,
            query_string="q=1",
        )
        call_verify("POST", "/resources/missing/verify", b"x", content_length=1)

        _s, _h, listing = call_json("GET", "/resources")
        self.assertEqual(len(listing["resources"]), 1)
        self.assertEqual(listing["resources"][0]["id"], resource_id)


if __name__ == "__main__":
    unittest.main()
