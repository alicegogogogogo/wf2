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


class DependencyBatchTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def _create(self, ch: str) -> str:
        _s, _h, body = call_json(
            "POST",
            "/resources",
            {"name": f"r-{ch}", "category": "code", "digest": DIGESTS[ch]},
        )
        return str(body["id"])

    def _batch(
        self,
        start: str,
        items: object,
        *,
        query_string: str | None = None,
    ) -> tuple[str, list[tuple[str, str]], dict[str, object]]:
        return call_json(
            "POST",
            f"/resources/{start}/dependencies/batch",
            {"dependencies": items},
            query_string=query_string,
        )

    # --- Success -----------------------------------------------------------

    def test_batch_creates_every_edge_and_echoes_in_submission_order(self) -> None:
        a = self._create("a")
        b = self._create("b")
        c = self._create("c")

        status, headers, body = self._batch(a, [c, b])
        self.assertEqual(status, "201 Created")
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
        # Every entry keeps the single-registration fixed key order.
        self.assertEqual(
            [list(entry) for entry in body["dependencies"]],
            [["resource_id", "dependency_id"], ["resource_id", "dependency_id"]],
        )

        # The edges land in the graph views immediately.
        _s, _h, deps = call_json("GET", f"/resources/{a}/dependencies")
        self.assertEqual(set(deps["dependencies"]), {b, c})
        for target in (b, c):
            _s, _h, impact = call_json("GET", f"/resources/{target}/impact")
            self.assertEqual(impact["resources"], [a])

    def test_response_is_compact_json_with_single_newline(self) -> None:
        a = self._create("a")
        b = self._create("b")
        _s, _h, raw = call(
            "POST",
            f"/resources/{a}/dependencies/batch",
            {"dependencies": [b]},
        )
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        self.assertNotIn(b" ", raw[:-1])
        self.assertEqual(
            raw,
            b'{"dependencies":[{"resource_id":"' + a.encode()
            + b'","dependency_id":"' + b.encode() + b'"}]}\n',
        )

    def test_edges_keep_submission_order_in_direct_listing(self) -> None:
        a = self._create("a")
        b, c, d = self._create("b"), self._create("c"), self._create("d")

        status, _h, _b = self._batch(a, [d, b, c])
        self.assertEqual(status, "201 Created")
        self.assertEqual(store.list_direct_dependencies(a), [d, b, c])

    def test_indirectly_reachable_missing_direct_edge_is_still_created(self) -> None:
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
        # c is already reachable from a transitively, but no direct edge.
        self.assertFalse(store.has_dependency(a, c))
        status, _h, body = self._batch(a, [c])
        self.assertEqual(status, "201 Created")
        self.assertEqual(
            body,
            {"dependencies": [{"resource_id": a, "dependency_id": c}]},
        )
        self.assertTrue(store.has_dependency(a, c))

    def test_batch_of_one_hundred_existing_resources_succeeds(self) -> None:
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
        status, _h, body = self._batch(start, others)
        self.assertEqual(status, "201 Created")
        self.assertEqual(
            [entry["dependency_id"] for entry in body["dependencies"]], others
        )
        self.assertEqual(len(store.list_direct_dependencies(start)), 100)

    def test_successive_batches_accumulate_without_duplicates(self) -> None:
        a = self._create("a")
        b = self._create("b")
        c = self._create("c")
        self.assertEqual(self._batch(a, [b])[0], "201 Created")
        self.assertEqual(self._batch(a, [c])[0], "201 Created")
        self.assertEqual(store.list_direct_dependencies(a), [b, c])

    # --- Body / parameter validation (400) --------------------------------

    def test_missing_body_is_bad_request(self) -> None:
        a = self._create("a")
        status, _h, body = call_json(
            "POST", f"/resources/{a}/dependencies/batch", None
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_malformed_or_non_utf8_body_is_bad_request(self) -> None:
        a = self._create("a")
        status, _h, body = call_json(
            "POST", f"/resources/{a}/dependencies/batch", b"{bad"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

        status, _h, raw = call(
            "POST", f"/resources/{a}/dependencies/batch", b"\xff\xfe"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(json.loads(raw)["error"], "invalid_request")

    def test_non_object_top_level_is_bad_request(self) -> None:
        a = self._create("a")
        for bad in (b"[]", b'"x"', b"42", b"null"):
            with self.subTest(bad=bad):
                status, _h, body = call_json(
                    "POST", f"/resources/{a}/dependencies/batch", bad
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_missing_or_unknown_field_is_bad_request(self) -> None:
        a = self._create("a")
        b = self._create("b")
        for payload in ({}, {"extra": 1}, {"dependencies": [b], "extra": 1}):
            with self.subTest(payload=payload):
                status, _h, body = call_json(
                    "POST", f"/resources/{a}/dependencies/batch", payload
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_dependencies_not_an_array_is_bad_request(self) -> None:
        a = self._create("a")
        for bad in ("x", 5, True, None, {"id": "x"}):
            with self.subTest(bad=bad):
                status, _h, body = call_json(
                    "POST",
                    f"/resources/{a}/dependencies/batch",
                    {"dependencies": bad},
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_empty_array_is_bad_request(self) -> None:
        a = self._create("a")
        status, _h, body = self._batch(a, [])
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_more_than_one_hundred_entries_is_bad_request(self) -> None:
        a = self._create("a")
        status, _h, body = self._batch(a, [f"x{i:03d}" for i in range(101)])
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_invalid_entry_values_are_bad_request(self) -> None:
        a = self._create("a")
        for bad in (5, True, None, ["x"], {"id": "x"}, "", "x/y", "x\\y"):
            with self.subTest(bad=bad):
                status, _h, body = self._batch(a, [bad])
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_whitespace_entry_is_syntactically_an_id_so_missing_not_400(self) -> None:
        a = self._create("a")
        status, _h, body = self._batch(a, ["   "])
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

    def test_in_batch_duplicate_is_bad_request_and_creates_nothing(self) -> None:
        a = self._create("a")
        b = self._create("b")
        c = self._create("c")
        status, _h, body = self._batch(a, [c, b, c])
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        self.assertEqual(store.list_direct_dependencies(a), [])

    def test_query_parameters_are_rejected_before_business_data(self) -> None:
        a = self._create("a")
        b = self._create("b")
        status, _h, body = self._batch(a, [b], query_string="x=1")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        self.assertEqual(store.list_direct_dependencies(a), [])

    def test_separator_in_start_id_is_bad_request(self) -> None:
        b = self._create("b")
        for raw in ("a/b", "a\\b"):
            status, _h, body = call_json(
                "POST",
                f"/resources/{raw}/dependencies/batch",
                {"dependencies": [b]},
            )
            self.assertEqual(status, "400 Bad Request")
            self.assertEqual(body["error"], "invalid_request")

    # --- Existence (404) ---------------------------------------------------

    def test_missing_start_returns_not_found_even_when_dep_missing(self) -> None:
        status, _h, body = call_json(
            "POST",
            "/resources/missing/dependencies/batch",
            {"dependencies": ["also-missing"]},
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

    def test_missing_dependency_returns_not_found_and_builds_nothing(self) -> None:
        a = self._create("a")
        b = self._create("b")
        phantom = "0" * 32
        # The valid earlier entry must not be left half-created.
        status, _h, body = self._batch(a, [b, phantom])
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")
        self.assertEqual(store.list_direct_dependencies(a), [])

    def test_body_validation_outranks_missing_resources(self) -> None:
        status, _h, body = call_json(
            "POST",
            "/resources/missing/dependencies/batch",
            {"dependencies": ["bad/id"]},
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    # --- Conflicts (409) ---------------------------------------------------

    def test_self_loop_is_dependency_cycle(self) -> None:
        a = self._create("a")
        b = self._create("b")
        status, _h, body = self._batch(a, [b, a])
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "dependency_cycle")
        self.assertEqual(store.list_direct_dependencies(a), [])

    def test_self_loop_outranks_in_batch_duplicate(self) -> None:
        a = self._create("a")
        # The repeated entry is itself the start id; self loop reports first.
        status, _h, body = self._batch(a, [a, a])
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "dependency_cycle")

    def test_self_loop_anywhere_outranks_earlier_existing_edge(self) -> None:
        # Fixed rule order, not submission position: an existing edge at
        # position 0 must not mask the self loop at position 2.
        a = self._create("a")
        b = self._create("b")
        c = self._create("c")
        self.assertEqual(self._batch(a, [b])[0], "201 Created")
        status, _h, body = self._batch(a, [b, c, a])
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "dependency_cycle")
        self.assertEqual(store.list_direct_dependencies(a), [b])

    def test_self_loop_after_an_in_batch_repeat_still_reports_cycle(self) -> None:
        # The repeat at position 1 used to fail first; the fixed rule
        # order reports the self loop found later in the batch.
        a = self._create("a")
        b = self._create("b")
        status, _h, body = self._batch(a, [b, b, a])
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "dependency_cycle")
        self.assertEqual(store.list_direct_dependencies(a), [])

    def test_in_batch_duplicate_outranks_earlier_existing_edge(self) -> None:
        # Rule order puts repeats (400) before same-direction duplicates
        # (409), regardless of which position hits first.
        a = self._create("a")
        b = self._create("b")
        c = self._create("c")
        self.assertEqual(self._batch(a, [b])[0], "201 Created")
        status, _h, body = self._batch(a, [b, c, b])
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        self.assertEqual(store.list_direct_dependencies(a), [b])

    def test_existing_edge_outranks_later_cycle_introduction(self) -> None:
        # Same-direction duplication (rule 3) precedes cycle introduction
        # (rule 4) even though the cycle-closing entry comes later.
        a = self._create("a")
        b = self._create("b")
        c = self._create("c")
        d = self._create("d")
        self.assertEqual(self._batch(a, [b])[0], "201 Created")
        # d -> a means adding a -> d would close a cycle.
        self.assertEqual(
            call_json(
                "POST", f"/resources/{d}/dependencies", {"dependency_id": a}
            )[0],
            "201 Created",
        )
        status, _h, body = self._batch(a, [b, d])
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "duplicate_dependency")
        self.assertEqual(store.list_direct_dependencies(a), [b])

    def test_existing_same_direction_edge_is_duplicate_dependency(self) -> None:
        a = self._create("a")
        b = self._create("b")
        c = self._create("c")
        self.assertEqual(self._batch(a, [b])[0], "201 Created")
        # c earlier in the same request must not survive the conflict on b.
        status, _h, body = self._batch(a, [c, b])
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "duplicate_dependency")
        self.assertEqual(store.list_direct_dependencies(a), [b])

    def test_duplicate_outranks_cycle_for_the_same_entry(self) -> None:
        a = self._create("a")
        b = self._create("b")
        # b -> a makes adding a -> b both an existing edge (none yet) ... set
        # up an existing edge a -> b first, plus the reverse path.
        self.assertEqual(
            call_json(
                "POST", f"/resources/{a}/dependencies", {"dependency_id": b}
            )[0],
            "201 Created",
        )
        self.assertEqual(
            call_json(
                "POST", f"/resources/{b}/dependencies", {"dependency_id": a}
            )[0],
            "409 Conflict",
        )
        # a -> b already exists, so re-adding via batch is duplicate, even
        # though the reverse edge could never coexist either.
        status, _h, body = self._batch(a, [b])
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "duplicate_dependency")

    def test_edge_that_would_introduce_cycle_is_rejected_atomically(self) -> None:
        a = self._create("a")
        b = self._create("b")
        c = self._create("c")
        d = self._create("d")
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
        # Closing c -> a cycles; an earlier valid d edge must not persist.
        status, _h, body = self._batch(c, [d, a])
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "dependency_cycle")
        self.assertEqual(store.list_direct_dependencies(c), [])
        _s, _h, impact_d = call_json("GET", f"/resources/{d}/impact")
        self.assertEqual(impact_d["resources"], [])

    def test_transitive_cycle_across_batch_candidate_is_detected(self) -> None:
        # x -> y -> z committed; batch z -> x closes a multi-hop cycle.
        x = self._create("a")
        y = self._create("b")
        z = self._create("c")
        for start, end in ((x, y), (y, z)):
            self.assertEqual(
                call_json(
                    "POST",
                    f"/resources/{start}/dependencies",
                    {"dependency_id": end},
                )[0],
                "201 Created",
            )
        status, _h, body = self._batch(z, [x])
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "dependency_cycle")

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

    # --- Views and cursors -------------------------------------------------

    def test_failed_batch_changes_nothing_and_views_keep_old_graph(self) -> None:
        a = self._create("a")
        b = self._create("b")
        c = self._create("c")
        self._batch(a, [b])
        # Invalid follow-up batch.
        self._batch(a, [b, c])  # duplicate existing -> 409
        _s, _h, deps = call_json("GET", f"/resources/{a}/dependencies")
        self.assertEqual(deps["dependencies"], [b])
        _s, _h, impact_c = call_json("GET", f"/resources/{c}/impact")
        self.assertEqual(impact_c["resources"], [])
        _s, _h, listing = call_json("GET", "/resources")
        self.assertEqual(
            sorted(r["id"] for r in listing["resources"]), sorted([a, b, c])
        )

    def test_batch_does_not_invalidate_listing_cursors(self) -> None:
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
        status, _h, first = call_json(
            "GET", "/resources", query_string="limit=2"
        )
        self.assertEqual(status, "200 OK")
        cursor = first["next_cursor"]
        self.assertEqual([r["id"] for r in first["resources"]], ids[:2])

        self.assertEqual(self._batch(ids[0], [ids[2], ids[3]])[0], "201 Created")

        status, _h, second = call_json(
            "GET", "/resources", query_string=f"limit=2&cursor={cursor}"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual([r["id"] for r in second["resources"]], ids[2:])


if __name__ == "__main__":
    unittest.main()
