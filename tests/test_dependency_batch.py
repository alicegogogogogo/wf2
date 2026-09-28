from __future__ import annotations

import io
import json
import unittest

from provenance_api.app import application, reset_state

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_D = "d" * 64
DIGEST_E = "e" * 64


def call(
    method: str,
    path: str,
    body: bytes | str | dict[str, object] | None = None,
    *,
    query_string: str | None = None,
    omit_content_length: bool = False,
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
        "wsgi.input": io.BytesIO(payload),
    }
    if not omit_content_length:
        environ["CONTENT_LENGTH"] = str(len(payload))
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
    **kwargs: object,
) -> tuple[str, list[tuple[str, str]], dict[str, object]]:
    status, headers, raw = call(method, path, body, **kwargs)  # type: ignore[arg-type]
    return status, headers, json.loads(raw.decode("utf-8"))


class DependencyBatchTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def _create(self, name: str, digest: str) -> str:
        _s, _h, body = call_json(
            "POST",
            "/resources",
            {"name": name, "category": "code", "digest": digest},
        )
        return str(body["id"])

    def _add(self, resource_id: str, dependency_id: str) -> None:
        status, _h, _b = call_json(
            "POST",
            f"/resources/{resource_id}/dependencies",
            {"dependency_id": dependency_id},
        )
        self.assertEqual(status, "201 Created")

    def _batch(
        self,
        items: object,
        resource_id: str | None = None,
        *,
        start: str | None = None,
        query_string: str | None = None,
    ) -> tuple[str, list[tuple[str, str]], dict[str, object]]:
        target = start if start is not None else (
            resource_id if resource_id is not None else self.a
        )
        return call_json(
            "POST",
            f"/resources/{target}/dependencies/batch",
            {"dependencies": items},
            query_string=query_string,
        )

    def _batch_raw(
        self,
        body: bytes | str | dict[str, object] | None,
        *,
        start: str | None = None,
        query_string: str | None = None,
        method: str = "POST",
    ) -> tuple[str, list[tuple[str, str]], dict[str, object]]:
        target = start if start is not None else self.a
        return call_json(
            method,
            f"/resources/{target}/dependencies/batch",
            body,
            query_string=query_string,
        )

    def setUpResources(self) -> None:
        self.a = self._create("a", DIGEST_A)
        self.b = self._create("b", DIGEST_B)
        self.c = self._create("c", DIGEST_C)
        self.d = self._create("d", DIGEST_D)
        self.e = self._create("e", DIGEST_E)

    # --- Success and response shape ----------------------------------------

    def test_batch_creates_every_edge_and_echoes_in_submission_order(self) -> None:
        self.setUpResources()
        status, headers, body = self._batch([self.b, self.c, self.d])

        self.assertEqual(status, "201 Created")
        self.assertEqual(
            headers[0], ("Content-Type", "application/json; charset=utf-8")
        )
        self.assertEqual(list(body), ["dependencies"])
        self.assertEqual(
            body,
            {
                "dependencies": [
                    {"resource_id": self.a, "dependency_id": self.b},
                    {"resource_id": self.a, "dependency_id": self.c},
                    {"resource_id": self.a, "dependency_id": self.d},
                ]
            },
        )

    def test_response_body_is_compact_json_ending_with_single_newline(
        self,
    ) -> None:
        self.setUpResources()
        status, _h, raw = call(
            "POST",
            f"/resources/{self.a}/dependencies/batch",
            {"dependencies": [self.b, self.c]},
        )
        self.assertEqual(status, "201 Created")
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        self.assertNotIn(b" ", raw[:-1])
        self.assertEqual(
            raw,
            b'{"dependencies":[{"resource_id":"'
            + self.a.encode()
            + b'","dependency_id":"'
            + self.b.encode()
            + b'"},{"resource_id":"'
            + self.a.encode()
            + b'","dependency_id":"'
            + self.c.encode()
            + b'"}]}\n',
        )

    def test_single_item_batch_is_accepted(self) -> None:
        self.setUpResources()
        status, _h, body = self._batch([self.b])
        self.assertEqual(status, "201 Created")
        self.assertEqual(
            body,
            {
                "dependencies": [
                    {"resource_id": self.a, "dependency_id": self.b}
                ]
            },
        )

    def test_batch_of_one_hundred_succeeds_and_one_hundred_one_is_rejected(
        self,
    ) -> None:
        start = self._create("start", DIGEST_A)
        targets = [
            self._create(f"r{i:03}", f"{i % 16:01x}" * 64)
            for i in range(101)
        ]
        # Exactly the limit goes through atomically.
        status, _h, body = call_json(
            "POST",
            f"/resources/{start}/dependencies/batch",
            {"dependencies": targets[:100]},
        )
        self.assertEqual(status, "201 Created")
        self.assertEqual(len(body["dependencies"]), 100)
        _s, _h, direct = call_json(
            "GET", f"/resources/{start}/dependencies"
        )
        self.assertEqual(sorted(direct["dependencies"]), sorted(targets[:100]))

        # One over the limit is rejected before any data is read, even with
        # a fresh start that has no edges yet.
        other = self._create("other", DIGEST_B)
        status, _h, parsed = call_json(
            "POST",
            f"/resources/{other}/dependencies/batch",
            {"dependencies": targets},
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(parsed["error"], "invalid_request")
        _s, _h, other_direct = call_json(
            "GET", f"/resources/{other}/dependencies"
        )
        self.assertEqual(other_direct["dependencies"], [])

    # --- Graph semantics ----------------------------------------------------

    def test_edges_are_visible_in_every_graph_view_immediately(self) -> None:
        self.setUpResources()
        self._add(self.b, self.c)
        status, _h, _b = self._batch([self.b, self.d])
        self.assertEqual(status, "201 Created")

        # Direct edges, in submission order.
        _s, _h, direct = call_json(
            "GET", f"/resources/{self.a}/dependencies"
        )
        self.assertEqual(direct["dependencies"], [self.b, self.c, self.d])

        # Reverse view: both b and d are directly impacted by a; c is reached
        # through a -> b -> c.
        for target, expected in (
            (self.b, [self.a]),
            (self.c, [self.a, self.b]),
            (self.d, [self.a]),
        ):
            _s, _h, impact = call_json(
                "GET", f"/resources/{target}/impact"
            )
            self.assertEqual(impact["resources"], expected, target)

        _s, _h, graph = call_json("GET", "/graph")
        pairs = {
            (edge["resource_id"], edge["dependency_id"])
            for edge in graph["edges"]
        }
        self.assertIn((self.a, self.b), pairs)
        self.assertIn((self.a, self.d), pairs)
        self.assertIn((self.b, self.c), pairs)

    def test_indirectly_reachable_missing_direct_edge_is_still_created(
        self,
    ) -> None:
        self.setUpResources()
        self._add(self.a, self.b)
        self._add(self.b, self.c)
        # a already reaches c indirectly; the direct edge is still new.
        status, _h, body = self._batch([self.c])
        self.assertEqual(status, "201 Created")
        self.assertEqual(
            body["dependencies"],
            [{"resource_id": self.a, "dependency_id": self.c}],
        )
        _s, _h, graph = call_json("GET", "/graph")
        self.assertIn(
            (self.a, self.c),
            {
                (edge["resource_id"], edge["dependency_id"])
                for edge in graph["edges"]
            },
        )

    def test_edges_land_in_submission_order(self) -> None:
        self.setUpResources()
        status, _h, _b = self._batch([self.d, self.b, self.c])
        self.assertEqual(status, "201 Created")
        _s, _h, graph = call_json("GET", "/graph")
        outgoing = [
            edge["dependency_id"]
            for edge in graph["edges"]
            if edge["resource_id"] == self.a
        ]
        self.assertEqual(outgoing, [self.d, self.b, self.c])

    # --- Request validation -------------------------------------------------

    def test_missing_body_is_invalid_request(self) -> None:
        self.setUpResources()
        status, _h, body = self._batch_raw(b"")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_undecodable_body_is_invalid_request(self) -> None:
        self.setUpResources()
        status, _h, _b = call(
            "POST",
            f"/resources/{self.a}/dependencies/batch",
            b"{not json",
        )
        self.assertEqual(status, "400 Bad Request")
        status, _h, body = call_json(
            "POST",
            f"/resources/{self.a}/dependencies/batch",
            b"\xff\xfe",
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_non_object_top_level_is_invalid_request(self) -> None:
        self.setUpResources()
        for raw_body in (b"[]", b'["x"]', b'"x"', b"1", b"null"):
            status, _h, parsed = call_json(
                "POST",
                f"/resources/{self.a}/dependencies/batch",
                raw_body,
            )
            self.assertEqual(status, "400 Bad Request")
            self.assertEqual(parsed["error"], "invalid_request")

    def test_unknown_field_is_invalid_request(self) -> None:
        self.setUpResources()
        status, _h, body = self._batch_raw(
            {"dependencies": [self.b], "extra": 1}
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_missing_dependencies_field_is_invalid_request(self) -> None:
        self.setUpResources()
        status, _h, body = self._batch_raw({})
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_non_array_dependencies_is_invalid_request(self) -> None:
        self.setUpResources()
        for value in ("x", 1, True, {"a": 1}, None):
            status, _h, body = self._batch_raw({"dependencies": value})
            self.assertEqual(status, "400 Bad Request")
            self.assertEqual(body["error"], "invalid_request")

    def test_empty_array_is_invalid_request(self) -> None:
        self.setUpResources()
        status, _h, body = self._batch([])
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_more_than_one_hundred_entries_is_invalid_request(self) -> None:
        self.setUpResources()
        status, _h, body = self._batch(
            [f"{i:032x}"[-32:] for i in range(101)]
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_non_string_entry_is_invalid_request(self) -> None:
        self.setUpResources()
        for value in (1, 1.5, True, None, ["x"], {"x": 1}):
            status, _h, body = self._batch([self.b, value])
            self.assertEqual(status, "400 Bad Request")
            self.assertEqual(body["error"], "invalid_request")

    def test_empty_entry_is_invalid_request(self) -> None:
        self.setUpResources()
        status, _h, body = self._batch([self.b, ""])
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_separator_entry_is_invalid_request(self) -> None:
        self.setUpResources()
        for value in ("a/b", "a\\b"):
            status, _h, body = self._batch([self.b, value])
            self.assertEqual(status, "400 Bad Request")
            self.assertEqual(body["error"], "invalid_request")

    def test_in_batch_duplicate_is_invalid_request(self) -> None:
        self.setUpResources()
        status, _h, body = self._batch([self.b, self.c, self.b])
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_query_parameters_are_rejected(self) -> None:
        self.setUpResources()
        status, _h, body = self._batch(
            [self.b], query_string="x=1"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_separator_in_start_id_is_invalid_request(self) -> None:
        self.setUpResources()
        for raw_id in ("a/b", "a\\b"):
            status, _h, body = self._batch([self.b], start=raw_id)
            self.assertEqual(status, "400 Bad Request")
            self.assertEqual(body["error"], "invalid_request")

    def test_empty_start_id_segment_is_invalid_request(self) -> None:
        self.setUpResources()
        status, _h, body = call_json(
            "POST",
            "/resources//dependencies/batch",
            {"dependencies": [self.b]},
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    # --- Not found ----------------------------------------------------------

    def test_missing_start_resource_returns_not_found(self) -> None:
        self.setUpResources()
        phantom = "0" * 32
        status, _h, body = self._batch([self.b], start=phantom)
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

    def test_missing_dependency_returns_not_found(self) -> None:
        self.setUpResources()
        phantom = "0" * 32
        status, _h, body = self._batch([self.b, phantom])
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

    def test_start_existence_is_checked_before_dependency_existence(
        self,
    ) -> None:
        self.setUpResources()
        status, _h, body = self._batch(
            ["f" * 32], start="0" * 32
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

    def test_request_validation_precedes_existence_checks(self) -> None:
        # Missing start plus an empty array: 400 wins and no data is read.
        status, _h, body = self._batch([], start="0" * 32)
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    # --- Conflicts ----------------------------------------------------------

    def test_self_loop_returns_dependency_cycle(self) -> None:
        self.setUpResources()
        status, _h, body = self._batch([self.b, self.a])
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "dependency_cycle")

    def test_existing_same_direction_edge_returns_duplicate(self) -> None:
        self.setUpResources()
        self._add(self.a, self.b)
        status, _h, body = self._batch([self.c, self.b])
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "duplicate_dependency")

    def test_batch_induced_cycle_returns_dependency_cycle(self) -> None:
        self.setUpResources()
        # a -> b exists; a batch out of b containing a must fail.
        self._add(self.a, self.b)
        status, _h, body = self._batch([self.c, self.a], start=self.b)
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "dependency_cycle")

    def test_cycle_introduced_only_by_overlaying_batch_edges_is_rejected(
        self,
    ) -> None:
        self.setUpResources()
        # c -> a already exists. On its own a -> b is harmless, but the
        # batch also adds a -> c, overlaying which c reaches a; the batch
        # must detect the cycle across its own pending edges and reject all.
        self._add(self.c, self.a)
        status, _h, body = self._batch([self.b, self.c])
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "dependency_cycle")

    def test_self_loop_outranks_duplicate_and_cycle(self) -> None:
        self.setUpResources()
        self._add(self.a, self.b)  # existing duplicate
        self._add(self.c, self.a)  # c would cycle back to a
        # Self (a), duplicate (b) and cycle (c) all present: self loop wins.
        status, _h, body = self._batch([self.b, self.a, self.c])
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "dependency_cycle")

    def test_duplicate_outranks_cycle(self) -> None:
        self.setUpResources()
        # a -> b exists (duplicate); c -> a exists, so a -> c would cycle.
        self._add(self.a, self.b)
        self._add(self.c, self.a)
        status, _h, body = self._batch([self.c, self.b])
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "duplicate_dependency")

    # --- Atomicity ----------------------------------------------------------

    def test_failed_batch_creates_no_edge(self) -> None:
        self.setUpResources()
        self._add(self.c, self.a)
        # b would be new, c closes a cycle.
        status, _h, _b = self._batch([self.b, self.c])
        self.assertEqual(status, "409 Conflict")

        _s, _h, deps = call_json(
            "GET", f"/resources/{self.a}/dependencies"
        )
        self.assertEqual(deps["dependencies"], [])
        _s, _h, impact_b = call_json(
            "GET", f"/resources/{self.b}/impact"
        )
        self.assertEqual(impact_b["resources"], [])
        _s, _h, graph = call_json("GET", "/graph")
        self.assertEqual(
            [
                (edge["resource_id"], edge["dependency_id"])
                for edge in graph["edges"]
            ],
            [(self.c, self.a)],
        )

    def test_invalid_batch_creates_no_edge(self) -> None:
        self.setUpResources()
        status, _h, _b = self._batch([self.b, "x/y"])
        self.assertEqual(status, "400 Bad Request")
        _s, _h, deps = call_json(
            "GET", f"/resources/{self.a}/dependencies"
        )
        self.assertEqual(deps["dependencies"], [])

    def test_not_found_batch_creates_no_edge(self) -> None:
        self.setUpResources()
        status, _h, _b = self._batch([self.b, "0" * 32])
        self.assertEqual(status, "404 Not Found")
        _s, _h, deps = call_json(
            "GET", f"/resources/{self.a}/dependencies"
        )
        self.assertEqual(deps["dependencies"], [])

    def test_failed_batch_does_not_move_cursors(self) -> None:
        self.setUpResources()
        status, _h, first_page = call_json(
            "GET", "/resources", query_string="limit=2"
        )
        self.assertEqual(status, "200 OK")
        cursor = first_page["next_cursor"]

        status, _h, _b = self._batch([self.b, self.c, self.a])
        self.assertEqual(status, "409 Conflict")

        status, _h, second_page = call_json(
            "GET",
            "/resources",
            query_string=f"limit=2&cursor={cursor}",
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            [r["id"] for r in second_page["resources"]],
            [self.c, self.d],
        )

    # --- Method handling ----------------------------------------------------

    def test_non_post_methods_return_405_with_post_only_allow(self) -> None:
        self.setUpResources()
        for method in ("GET", "PUT", "PATCH", "DELETE"):
            status, headers, body = self._batch_raw(
                {"dependencies": [self.b]}, method=method
            )
            self.assertEqual(status, "405 Method Not Allowed")
            self.assertEqual(body["error"], "method_not_allowed")
            self.assertEqual(
                [value for name, value in headers if name == "Allow"],
                ["POST"],
            )

    def test_batch_path_is_not_treated_as_dependency_item(self) -> None:
        self.setUpResources()
        # GET would otherwise reach the item handler (Allow: DELETE); the
        # batch route owns this suffix and answers POST-only.
        status, headers, body = call_json(
            "GET", f"/resources/{self.a}/dependencies/batch"
        )
        self.assertEqual(status, "405 Method Not Allowed")
        self.assertEqual(body["error"], "method_not_allowed")
        self.assertIn(("Allow", "POST"), headers)


if __name__ == "__main__":
    unittest.main()
