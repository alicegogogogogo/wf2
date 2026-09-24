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

    def _create(self, name: str = "x", digest_char: str = "a") -> str:
        _s, _h, body = call_json(
            "POST",
            "/resources",
            {
                "name": name,
                "category": "code",
                "digest": digest_char * 64,
            },
        )
        return str(body["id"])

    def _add_edge(self, resource_id: str, dependency_id: str) -> tuple[str, dict[str, object]]:
        status, headers, body = call_json(
            "POST",
            f"/resources/{resource_id}/dependencies",
            {"dependency_id": dependency_id},
        )
        return status, body

    # --- Creating edges ----------------------------------------------------

    def test_add_dependency_returns_201_relationship(self) -> None:
        a = self._create("a", "a")
        b = self._create("b", "b")
        status, headers, raw = call(
            "POST",
            f"/resources/{a}/dependencies",
            {"dependency_id": b},
        )
        self.assertEqual(status, "201 Created")
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )
        self.assertEqual(
            raw,
            f'{{"resource_id":"{a}","dependency_id":"{b}"}}\n'.encode(),
        )

    def test_dependency_edge_does_not_change_resources(self) -> None:
        a = self._create("a", "a")
        b = self._create("b", "b")
        self._add_edge(a, b)
        _s, _h, listing = call_json("GET", "/resources")
        self.assertEqual([r["id"] for r in listing["resources"]], [a, b])

    def test_duplicate_same_direction_is_conflict(self) -> None:
        a = self._create("a", "a")
        b = self._create("b", "b")
        self.assertEqual(self._add_edge(a, b)[0], "201 Created")
        status, body = self._add_edge(a, b)
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "duplicate_dependency")

        # The edge set is unchanged: still a single edge, not duplicated.
        _s, _h, dependencies = call_json(
            "GET", f"/resources/{a}/dependencies"
        )
        self.assertEqual(
            [r["id"] for r in dependencies["dependencies"]], [b]
        )

    def test_reverse_direction_closes_a_two_node_cycle(self) -> None:
        a = self._create("a", "a")
        b = self._create("b", "b")
        self._add_edge(a, b)
        # The reverse edge is not a duplicate of the directed edge, but it
        # closes a cycle a -> b -> a and must be reported as such.
        status, body = self._add_edge(b, a)
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "dependency_cycle")

    def test_self_loop_is_cycle(self) -> None:
        a = self._create("a", "a")
        status, body = self._add_edge(a, a)
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "dependency_cycle")
        _s, _h, dependencies = call_json(
            "GET", f"/resources/{a}/dependencies"
        )
        self.assertEqual(dependencies["dependencies"], [])

    def test_indirect_cycle_is_rejected(self) -> None:
        a = self._create("a", "a")
        b = self._create("b", "b")
        c = self._create("c", "c")
        self.assertEqual(self._add_edge(a, b)[0], "201 Created")
        self.assertEqual(self._add_edge(b, c)[0], "201 Created")
        status, body = self._add_edge(c, a)
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "dependency_cycle")

        # State unchanged: c still only reaches nothing; a reaches b and c.
        _s, _h, deps_c = call_json(
            "GET", f"/resources/{c}/dependencies"
        )
        self.assertEqual(deps_c["dependencies"], [])
        _s, _h, impact_a = call_json("GET", f"/resources/{a}/impact")
        self.assertEqual(impact_a["resources"], [])

    def test_failed_edge_does_not_affect_unrelated_state(self) -> None:
        a = self._create("a", "a")
        b = self._create("b", "b")
        c = self._create("c", "c")
        self._add_edge(a, b)
        self._add_edge(c, a)  # 201: c -> a -> b
        # Closing c -> b is fine (already reachable transitively but not
        # directly); closing b -> c is a cycle and must be rejected.
        status, _body = self._add_edge(b, c)
        self.assertEqual(status, "409 Conflict")
        _s, _h, deps_b = call_json(
            "GET", f"/resources/{b}/dependencies"
        )
        self.assertEqual(deps_b["dependencies"], [])
        _s, _h, deps_c = call_json(
            "GET", f"/resources/{c}/dependencies"
        )
        self.assertEqual(
            [r["id"] for r in deps_c["dependencies"]], [a, b]
        )

    # --- Transitive dependency listing ------------------------------------

    def test_list_empty_dependencies(self) -> None:
        a = self._create("a", "a")
        status, _headers, raw = call(
            "GET", f"/resources/{a}/dependencies"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b'{"dependencies":[]}\n')

    def test_list_transitive_dependencies_in_registration_order(self) -> None:
        # Registration order: top, l, r, leaf. Edges form a diamond so
        # "leaf" is reachable two ways and must appear exactly once.
        top = self._create("top", "1")
        l = self._create("l", "2")
        r = self._create("r", "3")
        leaf = self._create("leaf", "4")
        self._add_edge(top, l)
        self._add_edge(top, r)
        self._add_edge(l, leaf)
        self._add_edge(r, leaf)

        _s, _h, body = call_json(
            "GET", f"/resources/{top}/dependencies"
        )
        self.assertEqual(
            [r["id"] for r in body["dependencies"]], [l, r, leaf]
        )
        # Entries are full resource objects in the documented key order.
        first = body["dependencies"][0]
        self.assertEqual(
            list(first.keys()),
            ["id", "name", "category", "digest", "source"],
        )

    def test_dependency_listing_excludes_origin(self) -> None:
        a = self._create("a", "a")
        b = self._create("b", "b")
        self._add_edge(a, b)
        _s, _h, deps_a = call_json("GET", f"/resources/{a}/dependencies")
        self.assertNotIn(a, [r["id"] for r in deps_a["dependencies"]])

    # --- Impact ------------------------------------------------------------

    def test_empty_impact(self) -> None:
        a = self._create("a", "a")
        status, _headers, raw = call("GET", f"/resources/{a}/impact")
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b'{"resources":[]}\n')

    def test_impact_lists_direct_and_indirect_dependents(self) -> None:
        top = self._create("top", "1")
        l = self._create("l", "2")
        r = self._create("r", "3")
        leaf = self._create("leaf", "4")
        self._add_edge(top, l)
        self._add_edge(top, r)
        self._add_edge(l, leaf)
        self._add_edge(r, leaf)

        _s, _h, body = call_json("GET", f"/resources/{leaf}/impact")
        self.assertEqual(
            [r["id"] for r in body["resources"]], [top, l, r]
        )

    def test_impact_excludes_origin(self) -> None:
        a = self._create("a", "a")
        b = self._create("b", "b")
        self._add_edge(a, b)
        _s, _h, body = call_json("GET", f"/resources/{b}/impact")
        self.assertEqual([r["id"] for r in body["resources"]], [a])
        self.assertNotIn(b, [r["id"] for r in body["resources"]])

    # --- Missing resources -------------------------------------------------

    def test_get_dependencies_unknown_origin_is_404(self) -> None:
        status, _h, body = call_json(
            "GET", "/resources/missing/dependencies"
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

    def test_get_impact_unknown_origin_is_404(self) -> None:
        status, _h, body = call_json(
            "GET", "/resources/missing/impact"
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

    def test_post_dependency_unknown_origin_is_404(self) -> None:
        b = self._create("b", "b")
        status, _h, body = call_json(
            "POST",
            "/resources/missing/dependencies",
            {"dependency_id": b},
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

    def test_post_dependency_unknown_target_is_404(self) -> None:
        a = self._create("a", "a")
        status, _h, body = call_json(
            "POST",
            f"/resources/{a}/dependencies",
            {"dependency_id": "missing"},
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")
        _s, _h, deps = call_json(
            "GET", f"/resources/{a}/dependencies"
        )
        self.assertEqual(deps["dependencies"], [])

    # --- Bad requests ------------------------------------------------------

    def test_path_id_with_separator_is_bad_request(self) -> None:
        a = self._create("a", "a")
        b = self._create("b", "b")
        for suffix, method, body in [
            ("dependencies", "GET", None),
            ("impact", "GET", None),
            ("dependencies", "POST", {"dependency_id": b}),
        ]:
            with self.subTest(suffix=suffix, method=method):
                status, _h, resp = call_json(
                    method,
                    f"/resources/{a}/x/{suffix}",
                    body,
                )
                self.assertEqual(status[:3], "400")
                self.assertEqual(resp["error"], "invalid_request")

    def test_missing_body_is_bad_request(self) -> None:
        a = self._create("a", "a")
        status, _h, body = call_json(
            "POST", f"/resources/{a}/dependencies", None
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_malformed_or_non_utf8_body_is_bad_request(self) -> None:
        a = self._create("a", "a")
        for raw in (b"{not json", b"\xff\xfe"):
            with self.subTest(raw=raw):
                status, _h, body = call_json(
                    "POST", f"/resources/{a}/dependencies", raw
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_non_object_top_level_is_bad_request(self) -> None:
        a = self._create("a", "a")
        for raw in (b"[]", b'"x"', b"42", b"null"):
            with self.subTest(raw=raw):
                status, _h, body = call_json(
                    "POST", f"/resources/{a}/dependencies", raw
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_missing_dependency_id_is_bad_request(self) -> None:
        a = self._create("a", "a")
        status, _h, body = call_json(
            "POST", f"/resources/{a}/dependencies", {}
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_bad_dependency_id_values(self) -> None:
        a = self._create("a", "a")
        for value in (12, True, None, ["x"], "", "a/b", "a\\b"):
            with self.subTest(value=value):
                status, _h, body = call_json(
                    "POST",
                    f"/resources/{a}/dependencies",
                    {"dependency_id": value},
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_unknown_field_is_bad_request(self) -> None:
        a = self._create("a", "a")
        b = self._create("b", "b")
        status, _h, body = call_json(
            "POST",
            f"/resources/{a}/dependencies",
            {"dependency_id": b, "extra": 1},
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_query_parameters_rejected(self) -> None:
        a = self._create("a", "a")
        b = self._create("b", "b")
        for method, path, body in [
            ("GET", f"/resources/{a}/dependencies", None),
            ("GET", f"/resources/{a}/impact", None),
            (
                "POST",
                f"/resources/{a}/dependencies",
                {"dependency_id": b},
            ),
        ]:
            with self.subTest(method=method, path=path):
                status, _h, resp = call_json(
                    method, path, body, query_string="unused=1"
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(resp["error"], "invalid_request")

    # --- Methods -----------------------------------------------------------

    def test_unsupported_methods(self) -> None:
        a = self._create("a", "a")
        status, headers, body = call_json(
            "DELETE", f"/resources/{a}/dependencies"
        )
        self.assertEqual(status, "405 Method Not Allowed")
        self.assertEqual(body["error"], "method_not_allowed")
        self.assertIn(("Allow", "GET, POST"), headers)

        status, headers, body = call_json(
            "POST", f"/resources/{a}/impact", {}
        )
        self.assertEqual(status, "405 Method Not Allowed")
        self.assertEqual(body["error"], "method_not_allowed")
        self.assertIn(("Allow", "GET"), headers)

    # --- Baseline compatibility --------------------------------------------

    def test_existing_item_route_still_supported(self) -> None:
        a = self._create("a", "a")
        status, _h, body = call_json("GET", f"/resources/{a}")
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["id"], a)

    def test_dependency_named_resource_is_not_matched_as_graph_route(self) -> None:
        # An id literally ending in "/dependencies" carries a separator and
        # must never resolve as a resource or bypass validation.
        status, _h, body = call_json(
            "GET", "/resources/abc/dependencies/impact"
        )
        self.assertIn(status[:3], {"400", "404"})
        self.assertIn("error", body)


if __name__ == "__main__":
    unittest.main()
