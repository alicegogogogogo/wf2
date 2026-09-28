from __future__ import annotations

import io
import json
import unittest

from provenance_api.app import application, reset_state, store

DIGESTS = {ch: ch * 64 for ch in "abcdefgh"}


def call(
    method: str,
    path: str,
    body: bytes | str | dict[str, object] | None = None,
    *,
    query_string: str | None = None,
) -> tuple[str, list[tuple[str, str]], bytes]:
    if body is None:
        payload = b""
    elif isinstance(body, dict):
        payload = json.dumps(body).encode("utf-8")
    else:
        payload = body.encode("utf-8") if isinstance(body, str) else body

    environ: dict[str, object] = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": query_string if query_string is not None else "",
        "CONTENT_LENGTH": str(len(payload)),
        "CONTENT_TYPE": "application/json",
        "wsgi.input": io.BytesIO(payload),
    }
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
    status, headers, raw = call(method, path, body, query_string=query_string)
    return status, headers, json.loads(raw.decode("utf-8"))


class DependencyBatchDeleteTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def _create(self, ch: str) -> str:
        _s, _h, body = call_json(
            "POST",
            "/resources",
            {"name": f"r-{ch}", "category": "code", "digest": DIGESTS[ch]},
        )
        return str(body["id"])

    def _register_batch(self, start: str, items: list[str]) -> None:
        status, _h, _b = call_json(
            "POST",
            f"/resources/{start}/dependencies/batch",
            {"dependencies": items},
        )
        self.assertEqual(status, "201 Created")

    def _delete_batch(
        self,
        start: str,
        items: object,
        *,
        query_string: str | None = None,
    ) -> tuple[str, list[tuple[str, str]], dict[str, object]]:
        return call_json(
            "DELETE",
            f"/resources/{start}/dependencies/batch",
            {"dependencies": items},
            query_string=query_string,
        )

    # --- Success -----------------------------------------------------------

    def test_batch_removes_every_edge_and_echoes_in_submission_order(
        self,
    ) -> None:
        a = self._create("a")
        b = self._create("b")
        c = self._create("c")
        self._register_batch(a, [b, c])

        status, headers, body = self._delete_batch(a, [c, b])
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            headers[0], ("Content-Type", "application/json; charset=utf-8")
        )
        self.assertEqual(
            body,
            {
                "dependencies": [
                    {"resource_id": a, "dependency_id": c},
                    {"resource_id": a, "dependency_id": b},
                ]
            },
        )
        # Every entry keeps the single-edge fixed key order.
        self.assertEqual(
            [list(entry) for entry in body["dependencies"]],
            [["resource_id", "dependency_id"], ["resource_id", "dependency_id"]],
        )
        self.assertEqual(store.list_direct_dependencies(a), [])

    def test_response_is_compact_json_with_single_newline(self) -> None:
        a = self._create("a")
        b = self._create("b")
        c = self._create("c")
        self._register_batch(a, [b, c])
        _s, _h, raw = call(
            "DELETE",
            f"/resources/{a}/dependencies/batch",
            {"dependencies": [c, b]},
        )
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        self.assertNotIn(b" ", raw[:-1])
        self.assertEqual(
            raw,
            b'{"dependencies":[{"resource_id":"' + a.encode()
            + b'","dependency_id":"' + c.encode()
            + b'"},{"resource_id":"' + a.encode()
            + b'","dependency_id":"' + b.encode() + b'"}]}\n',
        )

    def test_surviving_edges_keep_established_order(self) -> None:
        a = self._create("a")
        b, c, d = self._create("b"), self._create("c"), self._create("d")
        self._register_batch(a, [d, b, c])

        status, _h, _b = self._delete_batch(a, [b])
        self.assertEqual(status, "200 OK")
        self.assertEqual(store.list_direct_dependencies(a), [d, c])

    def test_removal_order_need_not_match_established_order(self) -> None:
        a = self._create("a")
        b, c, d = self._create("b"), self._create("c"), self._create("d")
        self._register_batch(a, [d, b, c])

        status, _h, _b = self._delete_batch(a, [c, d, b])
        self.assertEqual(status, "200 OK")
        self.assertEqual(store.list_direct_dependencies(a), [])

    def test_only_named_direct_edges_are_removed(self) -> None:
        a = self._create("a")
        b = self._create("b")
        c = self._create("c")
        d = self._create("d")
        self._register_batch(a, [b, d])
        self.assertEqual(
            call_json(
                "POST", f"/resources/{b}/dependencies", {"dependency_id": c}
            )[0],
            "201 Created",
        )

        status, _h, _b = self._delete_batch(a, [d])
        self.assertEqual(status, "200 OK")
        self.assertEqual(store.list_direct_dependencies(a), [b])
        # The untouched start's edges and other starts' edges are intact.
        self.assertEqual(store.list_direct_dependencies(b), [c])
        self.assertTrue(store.has_dependency(b, c))

    def test_transitive_reachability_survives_through_other_paths(self) -> None:
        a = self._create("a")
        b = self._create("b")
        c = self._create("c")
        self.assertEqual(
            call_json(
                "POST", f"/resources/{a}/dependencies", {"dependency_id": b}
            )[0],
            "201 Created",
        )
        self.assertEqual(
            call_json(
                "POST", f"/resources/{b}/dependencies", {"dependency_id": c}
            )[0],
            "201 Created",
        )
        self._register_batch(a, [c])

        status, _h, _b = self._delete_batch(a, [c])
        self.assertEqual(status, "200 OK")
        self.assertFalse(store.has_dependency(a, c))
        # c is still reached transitively through a -> b -> c.
        _s, _h, deps = call_json("GET", f"/resources/{a}/dependencies")
        self.assertEqual(deps["dependencies"], [b, c])
        _s, _h, impact = call_json("GET", f"/resources/{c}/impact")
        self.assertEqual(impact["resources"], [a, b])

    def test_views_recompute_from_remaining_edges_immediately(self) -> None:
        a = self._create("a")
        b = self._create("b")
        c = self._create("c")
        self._register_batch(a, [b, c])

        status, _h, _b = self._delete_batch(a, [b])
        self.assertEqual(status, "200 OK")

        _s, _h, deps = call_json("GET", f"/resources/{a}/dependencies")
        self.assertEqual(deps["dependencies"], [c])
        _s, _h, impact_b = call_json("GET", f"/resources/{b}/impact")
        self.assertEqual(impact_b["resources"], [])
        _s, _h, impact_c = call_json("GET", f"/resources/{c}/impact")
        self.assertEqual(impact_c["resources"], [a])
        _s, _h, graph = call_json("GET", "/graph")
        self.assertEqual(
            graph["edges"], [{"resource_id": a, "dependency_id": c}]
        )

    def test_batch_of_one_hundred_edges_is_removed(self) -> None:
        start = self._create("a")
        others = [
            str(
                call_json(
                    "POST",
                    "/resources",
                    {
                        "name": f"r-{index}",
                        "category": "code",
                        "digest": f"{index:064x}",
                    },
                )[2]["id"]
            )
            for index in range(100)
        ]
        self._register_batch(start, others)
        status, _h, body = self._delete_batch(start, others)
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            [entry["dependency_id"] for entry in body["dependencies"]], others
        )
        self.assertEqual(store.list_direct_dependencies(start), [])

    def test_reregistering_after_batch_delete_creates_edges_again(self) -> None:
        a = self._create("a")
        b = self._create("b")
        c = self._create("c")
        self._register_batch(a, [b, c])
        self.assertEqual(self._delete_batch(a, [b, c])[0], "200 OK")

        status, _h, body = call_json(
            "POST",
            f"/resources/{a}/dependencies/batch",
            {"dependencies": [c, b]},
        )
        self.assertEqual(status, "201 Created")
        self.assertEqual(
            [entry["dependency_id"] for entry in body["dependencies"]], [c, b]
        )
        self.assertEqual(store.list_direct_dependencies(a), [c, b])

    def test_resource_records_are_not_touched(self) -> None:
        a = self._create("a")
        b = self._create("b")
        self._register_batch(a, [b])
        self._delete_batch(a, [b])

        _s, _h, listing = call_json("GET", "/resources")
        self.assertEqual(
            sorted(r["id"] for r in listing["resources"]), sorted([a, b])
        )
        for resource_id in (a, b):
            status, _h, _r = call_json("GET", f"/resources/{resource_id}")
            self.assertEqual(status, "200 OK")

    # --- Body / parameter validation (400) --------------------------------

    def test_missing_body_is_bad_request(self) -> None:
        a = self._create("a")
        status, _h, body = call_json(
            "DELETE", f"/resources/{a}/dependencies/batch", None
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_malformed_or_non_utf8_body_is_bad_request(self) -> None:
        a = self._create("a")
        status, _h, body = call(
            "DELETE", f"/resources/{a}/dependencies/batch", b"{bad"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(json.loads(body)["error"], "invalid_request")

        status, _h, raw = call(
            "DELETE", f"/resources/{a}/dependencies/batch", b"\xff\xfe"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(json.loads(raw)["error"], "invalid_request")

    def test_non_object_top_level_is_bad_request(self) -> None:
        a = self._create("a")
        for bad in (b"[]", b'"x"', b"42", b"null"):
            with self.subTest(bad=bad):
                status, _h, body = call_json(
                    "DELETE", f"/resources/{a}/dependencies/batch", bad
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_missing_or_unknown_field_is_bad_request(self) -> None:
        a = self._create("a")
        b = self._create("b")
        for payload in ({}, {"extra": 1}, {"dependencies": [b], "extra": 1}):
            with self.subTest(payload=payload):
                status, _h, body = call_json(
                    "DELETE",
                    f"/resources/{a}/dependencies/batch",
                    payload,
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_dependencies_not_an_array_is_bad_request(self) -> None:
        a = self._create("a")
        for bad in ("x", 5, True, None, {"id": "x"}):
            with self.subTest(bad=bad):
                status, _h, body = call_json(
                    "DELETE",
                    f"/resources/{a}/dependencies/batch",
                    {"dependencies": bad},
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_empty_array_is_bad_request(self) -> None:
        a = self._create("a")
        status, _h, body = self._delete_batch(a, [])
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_more_than_one_hundred_entries_is_bad_request(self) -> None:
        a = self._create("a")
        status, _h, body = self._delete_batch(a, [f"x{i:03d}" for i in range(101)])
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_invalid_entry_values_are_bad_request(self) -> None:
        a = self._create("a")
        for bad in (5, True, None, ["x"], {"id": "x"}, "", "x/y", "x\\y"):
            with self.subTest(bad=bad):
                status, _h, body = self._delete_batch(a, [bad])
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_whitespace_entry_is_syntactically_an_id_so_missing_edge_404(
        self,
    ) -> None:
        a = self._create("a")
        status, _h, body = self._delete_batch(a, ["   "])
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "dependency_not_found")

    def test_in_batch_duplicate_is_bad_request_and_removes_nothing(self) -> None:
        a = self._create("a")
        b = self._create("b")
        c = self._create("c")
        self._register_batch(a, [b, c])
        status, _h, body = self._delete_batch(a, [c, b, c])
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        self.assertEqual(store.list_direct_dependencies(a), [b, c])

    def test_duplicate_that_names_the_start_is_still_bad_request(self) -> None:
        # On removal the repeat is a body-shape violation: unlike batch
        # registration, no self-loop precedence promotes it to 409.
        a = self._create("a")
        status, _h, body = self._delete_batch(a, [a, a])
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_self_named_entry_without_edge_is_dependency_not_found(self) -> None:
        # A self edge can never exist, so a syntactically valid single
        # self entry misses at the edge lookup.
        a = self._create("a")
        status, _h, body = self._delete_batch(a, [a])
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "dependency_not_found")

    def test_query_parameters_are_rejected_before_business_data(self) -> None:
        a = self._create("a")
        b = self._create("b")
        self._register_batch(a, [b])
        status, _h, body = self._delete_batch(a, [b], query_string="x=1")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        self.assertTrue(store.has_dependency(a, b))

    def test_separator_in_start_id_is_bad_request(self) -> None:
        b = self._create("b")
        for raw in ("a/b", "a\\b"):
            status, _h, body = call_json(
                "DELETE",
                f"/resources/{raw}/dependencies/batch",
                {"dependencies": [b]},
            )
            self.assertEqual(status, "400 Bad Request")
            self.assertEqual(body["error"], "invalid_request")

    def test_body_validation_outranks_missing_start(self) -> None:
        status, _h, body = call_json(
            "DELETE",
            "/resources/missing/dependencies/batch",
            {"dependencies": ["bad/id"]},
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    # --- Not found (404) ---------------------------------------------------

    def test_missing_start_returns_resource_not_found_even_when_edge_missing(
        self,
    ) -> None:
        status, _h, body = call_json(
            "DELETE",
            "/resources/missing/dependencies/batch",
            {"dependencies": ["also-missing"]},
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

    def test_missing_edge_returns_dependency_not_found_and_removes_nothing(
        self,
    ) -> None:
        a = self._create("a")
        b = self._create("b")
        c = self._create("c")
        self._register_batch(a, [b])
        # The valid earlier edge must not be left half-removed.
        status, _h, body = self._delete_batch(a, [b, c])
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "dependency_not_found")
        self.assertTrue(store.has_dependency(a, b))
        self.assertEqual(store.list_direct_dependencies(a), [b])

    def test_dependency_resource_existence_is_not_separately_reported(
        self,
    ) -> None:
        # A registered start and an id that never named a resource fail at
        # the edge lookup, never with resource_not_found for the target.
        a = self._create("a")
        phantom = "0" * 32
        status, _h, body = self._delete_batch(a, [phantom])
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "dependency_not_found")

    def test_edge_to_deregistered_resource_returns_dependency_not_found(
        self,
    ) -> None:
        a = self._create("a")
        b = self._create("b")
        self._register_batch(a, [b])
        status, _h, _b = call("DELETE", f"/resources/{b}")
        self.assertEqual(status, "200 OK")

        status, _h, body = self._delete_batch(a, [b])
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "dependency_not_found")

    def test_repeat_delete_is_consistently_not_found(self) -> None:
        a = self._create("a")
        b = self._create("b")
        c = self._create("c")
        self._register_batch(a, [b, c])
        self.assertEqual(self._delete_batch(a, [b])[0], "200 OK")
        status, _h, body = self._delete_batch(a, [b])
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "dependency_not_found")
        # The edge from the same batch that did exist is untouched.
        self.assertTrue(store.has_dependency(a, c))

    def test_failed_delete_leaves_graph_and_views_unchanged(self) -> None:
        a = self._create("a")
        b = self._create("b")
        c = self._create("c")
        self._register_batch(a, [b, c])
        # Missing edge among otherwise valid entries: atomic failure.
        self._delete_batch(a, [c, b, "phantom-id"])
        self.assertEqual(store.list_direct_dependencies(a), [b, c])
        _s, _h, deps = call_json("GET", f"/resources/{a}/dependencies")
        self.assertEqual(set(deps["dependencies"]), {b, c})
        _s, _h, graph = call_json("GET", "/graph")
        self.assertEqual(
            sorted(
                (edge["resource_id"], edge["dependency_id"])
                for edge in graph["edges"]
            ),
            sorted([(a, b), (a, c)]),
        )

    # --- Method handling ---------------------------------------------------

    def test_other_methods_return_405_with_post_delete_allow(self) -> None:
        a = self._create("a")
        for method in ("GET", "PUT", "PATCH"):
            with self.subTest(method=method):
                status, headers, body = call_json(
                    method, f"/resources/{a}/dependencies/batch"
                )
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")
                self.assertEqual(
                    [h for h in headers if h[0] == "Allow"],
                    [("Allow", "POST, DELETE")],
                )

    # --- Cursors -----------------------------------------------------------

    def test_batch_delete_does_not_invalidate_listing_cursors(self) -> None:
        ids = [
            str(
                call_json(
                    "POST",
                    "/resources",
                    {
                        "name": f"r{index}",
                        "category": "code",
                        "digest": f"{index:064x}",
                    },
                )[2]["id"]
            )
            for index in range(4)
        ]
        self._register_batch(ids[0], [ids[2], ids[3]])
        status, _h, first = call_json(
            "GET", "/resources", query_string="limit=2"
        )
        self.assertEqual(status, "200 OK")
        cursor = first["next_cursor"]
        self.assertEqual([r["id"] for r in first["resources"]], ids[:2])

        self.assertEqual(
            self._delete_batch(ids[0], [ids[2], ids[3]])[0], "200 OK"
        )

        status, _h, second = call_json(
            "GET", "/resources", query_string=f"limit=2&cursor={cursor}"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual([r["id"] for r in second["resources"]], ids[2:])


if __name__ == "__main__":
    unittest.main()
