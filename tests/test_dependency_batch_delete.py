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

    def _add_edges(self, start: str, items: list[str]) -> None:
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

    def test_batch_removes_every_edge_and_echoes_in_submission_order(self) -> None:
        a = self._create("a")
        b = self._create("b")
        c = self._create("c")
        d = self._create("d")
        self._add_edges(a, [b, c, d])

        status, headers, body = self._delete_batch(a, [d, b])
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            headers[0], ("Content-Type", "application/json; charset=utf-8")
        )
        self.assertEqual(
            body,
            {
                "dependencies": [
                    {"resource_id": a, "dependency_id": d},
                    {"resource_id": a, "dependency_id": b},
                ]
            },
        )
        # Every entry keeps the single-registration fixed key order.
        self.assertEqual(
            [list(entry) for entry in body["dependencies"]],
            [["resource_id", "dependency_id"], ["resource_id", "dependency_id"]],
        )

        # Only the remaining edge survives in the graph views.
        self.assertEqual(store.list_direct_dependencies(a), [c])
        _s, _h, deps = call_json("GET", f"/resources/{a}/dependencies")
        self.assertEqual(deps["dependencies"], [c])
        for removed, kept in ((b, c), (d, c)):
            _s, _h, impact = call_json(
                "GET", f"/resources/{removed}/impact"
            )
            self.assertEqual(impact["resources"], [])
        _s, _h, impact_c = call_json("GET", f"/resources/{c}/impact")
        self.assertEqual(impact_c["resources"], [a])

    def test_response_is_compact_json_with_single_newline(self) -> None:
        a = self._create("a")
        b = self._create("b")
        self._add_edges(a, [b])
        _s, _h, raw = call(
            "DELETE",
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

    def test_remaining_edges_keep_their_established_order(self) -> None:
        a = self._create("a")
        b, c, d = self._create("b"), self._create("c"), self._create("d")
        self._add_edges(a, [d, b, c])

        status, _h, _b = self._delete_batch(a, [b])
        self.assertEqual(status, "200 OK")
        self.assertEqual(store.list_direct_dependencies(a), [d, c])

    def test_batch_of_one_hundred_edges_succeeds(self) -> None:
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
        self._add_edges(start, others)

        status, _h, body = self._delete_batch(start, others)
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            [entry["dependency_id"] for entry in body["dependencies"]], others
        )
        self.assertEqual(store.list_direct_dependencies(start), [])

    def test_transitive_relation_via_surviving_path_stays_visible(self) -> None:
        a = self._create("a")
        b = self._create("b")
        c = self._create("c")
        self._add_edges(a, [b])
        self.assertEqual(
            call_json(
                "POST", f"/resources/{b}/dependencies", {"dependency_id": c}
            )[0],
            "201 Created",
        )
        self._add_edges(a, [c])

        # Remove the direct edge a -> c; a still reaches c through b.
        status, _h, _b = self._delete_batch(a, [c])
        self.assertEqual(status, "200 OK")
        self.assertFalse(store.has_dependency(a, c))
        _s, _h, deps = call_json("GET", f"/resources/{a}/dependencies")
        self.assertEqual(deps["dependencies"], [b, c])
        _s, _h, impact = call_json("GET", f"/resources/{c}/impact")
        self.assertEqual(impact["resources"], [a, b])

    def test_graph_snapshot_drops_the_removed_edges_immediately(self) -> None:
        a = self._create("a")
        b = self._create("b")
        c = self._create("c")
        self._add_edges(a, [b, c])

        status, _h, _b = self._delete_batch(a, [b])
        self.assertEqual(status, "200 OK")

        _s, _h, graph = call_json("GET", "/graph")
        self.assertEqual(
            graph["edges"],
            [{"resource_id": a, "dependency_id": c}],
        )

    def test_other_resources_edges_are_untouched(self) -> None:
        a = self._create("a")
        b = self._create("b")
        c = self._create("c")
        self._add_edges(a, [b, c])
        self._add_edges(b, [c])

        status, _h, _b = self._delete_batch(a, [c])
        self.assertEqual(status, "200 OK")
        self.assertEqual(store.list_direct_dependencies(a), [b])
        self.assertEqual(store.list_direct_dependencies(b), [c])

    def test_resource_records_are_not_touched(self) -> None:
        a = self._create("a")
        b = self._create("b")
        self._add_edges(a, [b])
        self._delete_batch(a, [b])

        _s, _h, listing = call_json("GET", "/resources")
        self.assertEqual(
            sorted(r["id"] for r in listing["resources"]), sorted([a, b])
        )

    def test_successful_delete_keeps_listing_cursors_usable(self) -> None:
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
        self._add_edges(ids[0], [ids[2], ids[3]])

        status, _h, first = call_json(
            "GET", "/resources", query_string="limit=2"
        )
        self.assertEqual(status, "200 OK")
        cursor = first["next_cursor"]
        self.assertEqual([r["id"] for r in first["resources"]], ids[:2])

        self.assertEqual(self._delete_batch(ids[0], [ids[3]])[0], "200 OK")

        status, _h, second = call_json(
            "GET", "/resources", query_string=f"limit=2&cursor={cursor}"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual([r["id"] for r in second["resources"]], ids[2:])

    # --- Not found and atomicity ------------------------------------------

    def test_missing_edge_returns_dependency_not_found(self) -> None:
        a = self._create("a")
        b = self._create("b")
        # The edge was never registered.
        status, _h, body = self._delete_batch(a, [b])
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "dependency_not_found")

    def test_unknown_dependency_id_is_dependency_not_found(self) -> None:
        a = self._create("a")
        status, _h, body = self._delete_batch(a, ["0" * 32])
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "dependency_not_found")

    def test_one_missing_edge_aborts_the_whole_batch_atomically(self) -> None:
        a = self._create("a")
        b = self._create("b")
        c = self._create("c")
        d = self._create("d")
        self._add_edges(a, [b, c, d])

        # c is listed in the middle but its edge is absent after this setup
        # guard: remove it one-by-one first to create the gap.
        self.assertEqual(
            call_json("DELETE", f"/resources/{a}/dependencies/{c}")[0],
            "200 OK",
        )
        status, _h, body = self._delete_batch(a, [b, c, d])
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "dependency_not_found")
        # Neither the earlier b nor the later d edge was removed.
        self.assertEqual(store.list_direct_dependencies(a), [b, d])

    def test_repeat_request_after_failure_reports_same_missing_relation(
        self,
    ) -> None:
        a = self._create("a")
        b = self._create("b")
        c = self._create("c")
        self._add_edges(a, [b])
        body = {"dependencies": [b, c]}

        first, _h, parsed = call_json(
            "DELETE", f"/resources/{a}/dependencies/batch", body
        )
        self.assertEqual(first, "404 Not Found")
        self.assertEqual(parsed["error"], "dependency_not_found")
        second, _h, parsed = call_json(
            "DELETE", f"/resources/{a}/dependencies/batch", body
        )
        self.assertEqual(second, "404 Not Found")
        self.assertEqual(parsed["error"], "dependency_not_found")
        # The present edge survives both attempts.
        self.assertEqual(store.list_direct_dependencies(a), [b])

    def test_repeat_of_successful_delete_is_dependency_not_found(self) -> None:
        a = self._create("a")
        b = self._create("b")
        self._add_edges(a, [b])
        body = {"dependencies": [b]}

        first, _h, _b = call_json(
            "DELETE", f"/resources/{a}/dependencies/batch", body
        )
        self.assertEqual(first, "200 OK")
        second, _h, parsed = call_json(
            "DELETE", f"/resources/{a}/dependencies/batch", body
        )
        self.assertEqual(second, "404 Not Found")
        self.assertEqual(parsed["error"], "dependency_not_found")

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

    def test_start_existence_outranks_direct_edge_existence(self) -> None:
        b = self._create("b")
        phantom = "0" * 32
        status, _h, body = self._delete_batch(phantom, [b])
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")
        # The two not-found codes are never mixed.
        _s, _h, listing = call_json("GET", "/resources")
        self.assertEqual(len(listing["resources"]), 1)

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
        status, _h, body = call_json(
            "DELETE", f"/resources/{a}/dependencies/batch", b"{bad"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

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
        self._add_edges(a, [b])
        for payload in ({}, {"extra": 1}, {"dependencies": [b], "extra": 1}):
            with self.subTest(payload=payload):
                status, _h, body = call_json(
                    "DELETE",
                    f"/resources/{a}/dependencies/batch",
                    payload,
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")
                # A shape error must not have touched the graph.
                self.assertEqual(store.list_direct_dependencies(a), [b])

    def test_dependencies_not_an_array_is_bad_request(self) -> None:
        a = self._create("a")
        for bad in ("x", 5, True, None, {"id": "x"}):
            with self.subTest(bad=bad):
                status, _h, body = self._delete_batch(a, bad)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_empty_array_is_bad_request(self) -> None:
        a = self._create("a")
        status, _h, body = self._delete_batch(a, [])
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_more_than_one_hundred_entries_is_bad_request(self) -> None:
        a = self._create("a")
        status, _h, body = self._delete_batch(
            a, [f"x{i:03d}" for i in range(101)]
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_invalid_entry_values_are_bad_request(self) -> None:
        a = self._create("a")
        for bad in (5, True, None, ["x"], {"id": "x"}, "", "x/y", "x\\y"):
            with self.subTest(bad=bad):
                status, _h, body = self._delete_batch(a, [bad])
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_in_batch_duplicate_is_bad_request_and_removes_nothing(self) -> None:
        a = self._create("a")
        b = self._create("b")
        c = self._create("c")
        self._add_edges(a, [b, c])
        status, _h, body = self._delete_batch(a, [c, b, c])
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        self.assertEqual(store.list_direct_dependencies(a), [b, c])

    def test_duplicate_self_reference_still_rejected_at_request_level(self) -> None:
        # The self-loop rule belongs to registration; removal only knows
        # existing edges, and a self edge can never exist. A repeated entry
        # (even naming the start) is still a request-level 400, checked
        # before any business data is read.
        a = self._create("a")
        b = self._create("b")
        self._add_edges(a, [b])
        status, _h, body = self._delete_batch(a, [a, a])
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        self.assertEqual(store.list_direct_dependencies(a), [b])

    def test_query_parameters_are_rejected_before_business_data(self) -> None:
        a = self._create("a")
        b = self._create("b")
        self._add_edges(a, [b])
        status, _h, body = self._delete_batch(
            a, [b], query_string="x=1"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        self.assertEqual(store.list_direct_dependencies(a), [b])

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

    def test_body_validation_outranks_missing_resources(self) -> None:
        status, _h, body = call_json(
            "DELETE",
            "/resources/missing/dependencies/batch",
            {"dependencies": ["bad/id"]},
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    # --- Method handling ---------------------------------------------------

    def test_other_methods_return_405_with_post_and_delete_allow(self) -> None:
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

    # --- Failure leaves views and cursors intact --------------------------

    def test_failed_batch_changes_nothing_and_views_keep_old_graph(self) -> None:
        a = self._create("a")
        b = self._create("b")
        c = self._create("c")
        self._add_edges(a, [b])

        self._delete_batch(a, [b, c])  # c edge missing -> 404
        _s, _h, deps = call_json("GET", f"/resources/{a}/dependencies")
        self.assertEqual(deps["dependencies"], [b])
        _s, _h, impact_c = call_json("GET", f"/resources/{c}/impact")
        self.assertEqual(impact_c["resources"], [])
        _s, _h, graph = call_json("GET", "/graph")
        self.assertEqual(
            graph["edges"],
            [{"resource_id": a, "dependency_id": b}],
        )


class DependencyBatchRegistrationPrecedenceTests(unittest.TestCase):
    """The fixed registration rule order ignores submission position."""

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
        self, start: str, items: object
    ) -> tuple[str, list[tuple[str, str]], dict[str, object]]:
        return call_json(
            "POST",
            f"/resources/{start}/dependencies/batch",
            {"dependencies": items},
        )

    def test_self_loop_rule_beats_earlier_duplicate_edge(self) -> None:
        # The existing-edge conflict sits at position 0 and the self loop
        # at position 1; the fixed rule order reports the self loop.
        a = self._create("a")
        b = self._create("b")
        self.assertEqual(self._batch(a, [b])[0], "201 Created")
        status, _h, body = self._batch(a, [b, a])
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "dependency_cycle")
        self.assertEqual(store.list_direct_dependencies(a), [b])

    def test_self_loop_rule_beats_earlier_in_batch_repeat(self) -> None:
        a = self._create("a")
        b = self._create("b")
        # b repeats before the self-referential entry; the cycle rule wins.
        status, _h, body = self._batch(a, [b, b, a])
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "dependency_cycle")

    def test_in_batch_repeat_beats_later_existing_edge(self) -> None:
        a = self._create("a")
        b = self._create("b")
        c = self._create("c")
        self.assertEqual(self._batch(a, [c])[0], "201 Created")
        # b is repeated before the pre-existing edge c is reached.
        status, _h, body = self._batch(a, [b, b, c])
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        self.assertEqual(store.list_direct_dependencies(a), [c])

    def test_existing_edge_rule_beats_earlier_cycle(self) -> None:
        # Position 0 closes a cycle and position 1 is an existing edge; a
        # per-position check would report the cycle, but the fixed rule
        # order reports the duplicate regardless of submission position.
        a = self._create("a")
        b = self._create("b")
        c = self._create("c")
        self.assertEqual(self._batch(a, [b])[0], "201 Created")
        # c -> a makes a later a -> c close a cycle, but is acyclic itself.
        self.assertEqual(self._batch(c, [a])[0], "201 Created")
        status, _h, body = self._batch(a, [c, b])
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "duplicate_dependency")
        self.assertEqual(store.list_direct_dependencies(a), [b])

    def test_self_loop_is_reported_when_it_is_the_last_entry(self) -> None:
        # Every earlier rule is also violated, but later in the list: a
        # repeat at position 1 and an existing edge at position 2, while
        # the self loop sits last and must still win.
        a = self._create("a")
        b = self._create("b")
        c = self._create("c")
        self.assertEqual(self._batch(a, [c])[0], "201 Created")
        status, _h, body = self._batch(a, [b, b, c, a])
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "dependency_cycle")
        self.assertEqual(store.list_direct_dependencies(a), [c])


if __name__ == "__main__":
    unittest.main()
