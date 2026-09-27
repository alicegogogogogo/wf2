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
    content_length: int | str | None = None,
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
        environ["CONTENT_LENGTH"] = (
            str(len(payload)) if content_length is None else str(content_length)
        )
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


class GraphPathAllTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def _create(self, name: str, digest: str) -> str:
        status, _h, body = call_json(
            "POST",
            "/resources",
            {"name": name, "category": "code", "digest": digest},
        )
        self.assertEqual(status, "201 Created")
        return str(body["id"])

    def _add(self, resource_id: str, dependency_id: str) -> None:
        status, _h, _b = call_json(
            "POST",
            f"/resources/{resource_id}/dependencies",
            {"dependency_id": dependency_id},
        )
        self.assertEqual(status, "201 Created")

    def _all(self, from_id: str, to_id: str, **kwargs: object):
        return call(
            "GET",
            "/graph/path/all",
            query_string=f"from={from_id}&to={to_id}",
            **kwargs,
        )

    # --- Successful enumerations -------------------------------------------

    def test_direct_edge_single_path(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        self._add(a, b)

        status, headers, raw = self._all(a, b)
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            headers[0], ("Content-Type", "application/json; charset=utf-8")
        )
        self.assertEqual(
            raw,
            (
                '{"from":"%s","to":"%s","found":true,'
                '"paths":[["%s","%s"]],"count":1}\n' % (a, b, a, b)
            ).encode("utf-8"),
        )

    def test_top_level_key_order_is_fixed(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        self._add(a, b)

        _s, _h, body = call_json(
            "GET", "/graph/path/all", query_string=f"from={a}&to={b}"
        )
        self.assertEqual(list(body), ["from", "to", "found", "paths", "count"])

    def test_all_equal_shortest_paths_are_returned(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        d = self._create("d", DIGEST_D)
        # Two equally short paths a -> b -> d and a -> c -> d, plus a
        # longer one through e that must not be reported.
        e = self._create("e", DIGEST_E)
        self._add(a, c)
        self._add(a, b)
        self._add(b, d)
        self._add(c, d)
        self._add(a, e)
        self._add(e, b)

        _s, _h, body = call_json(
            "GET", "/graph/path/all", query_string=f"from={a}&to={d}"
        )
        self.assertEqual(body["found"], True)
        # b was registered before c, so the path through b comes first
        # even though the a -> c edge was registered first.
        self.assertEqual(body["paths"], [[a, b, d], [a, c, d]])
        self.assertEqual(body["count"], 2)

    def test_ordering_uses_later_nodes_as_well(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        d = self._create("d", DIGEST_D)
        e = self._create("e", DIGEST_E)
        # a -> e -> {c, b} -> d: the second node is forced, the third node
        # orders the paths by registration order (b before c).
        self._add(a, e)
        self._add(e, c)
        self._add(e, b)
        self._add(b, d)
        self._add(c, d)

        _s, _h, body = call_json(
            "GET", "/graph/path/all", query_string=f"from={a}&to={d}"
        )
        self.assertEqual(body["paths"], [[a, e, b, d], [a, e, c, d]])
        self.assertEqual(body["count"], 2)

    def test_same_resource_is_found_with_single_node_path(self) -> None:
        a = self._create("a", DIGEST_A)
        _s, _h, body = call_json(
            "GET", "/graph/path/all", query_string=f"from={a}&to={a}"
        )
        self.assertEqual(body["found"], True)
        self.assertEqual(body["paths"], [[a]])
        self.assertEqual(body["count"], 1)

    def test_unreachable_target_is_a_successful_not_found_result(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        status, _h, body = call_json(
            "GET", "/graph/path/all", query_string=f"from={a}&to={b}"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["found"], False)
        self.assertEqual(body["paths"], [])
        self.assertEqual(body["count"], 0)

    def test_reverse_direction_walks_no_edges(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        self._add(a, b)

        _s, _h, body = call_json(
            "GET", "/graph/path/all", query_string=f"from={b}&to={a}"
        )
        self.assertEqual(body["found"], False)
        self.assertEqual(body["paths"], [])
        self.assertEqual(body["count"], 0)

    # --- limit --------------------------------------------------------------

    def test_limit_truncates_in_stable_order(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        d = self._create("d", DIGEST_D)
        self._add(a, c)
        self._add(a, b)
        self._add(b, d)
        self._add(c, d)

        _s, _h, body = call_json(
            "GET", "/graph/path/all", query_string=f"from={a}&to={d}&limit=1"
        )
        self.assertEqual(body["found"], True)
        self.assertEqual(body["paths"], [[a, b, d]])
        self.assertEqual(body["count"], 1)

        # A limit beyond the number of paths returns all of them.
        _s, _h, body = call_json(
            "GET", "/graph/path/all", query_string=f"from={a}&to={d}&limit=100"
        )
        self.assertEqual(body["paths"], [[a, b, d], [a, c, d]])
        self.assertEqual(body["count"], 2)

    def test_illegal_limit_is_bad_request(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        self._add(a, b)
        for limit in ("0", "01", "1.5", "abc", "-1", "101", ""):
            with self.subTest(limit=limit):
                status, _h, body = call_json(
                    "GET",
                    "/graph/path/all",
                    query_string=f"from={a}&to={b}&limit={limit}",
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_repeated_limit_is_bad_request(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        status, _h, body = call_json(
            "GET",
            "/graph/path/all",
            query_string=f"from={a}&to={b}&limit=1&limit=2",
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    # --- Recomputation and read-only behavior ---------------------------------

    def test_paths_recompute_after_dependency_changes(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        d = self._create("d", DIGEST_D)
        self._add(a, b)
        self._add(a, c)
        self._add(b, d)
        self._add(c, d)

        status, _h, _b = call_json("DELETE", f"/resources/{a}/dependencies/{c}")
        self.assertEqual(status, "200 OK")

        _s, _h, body = call_json(
            "GET", "/graph/path/all", query_string=f"from={a}&to={d}"
        )
        self.assertEqual(body["paths"], [[a, b, d]])
        self.assertEqual(body["count"], 1)

        # Re-registering the edge restores both paths immediately.
        self._add(a, c)
        _s, _h, body = call_json(
            "GET", "/graph/path/all", query_string=f"from={a}&to={d}"
        )
        self.assertEqual(body["paths"], [[a, b, d], [a, c, d]])
        self.assertEqual(body["count"], 2)

    def test_paths_recompute_after_resource_delete(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        self._add(a, b)
        self._add(b, c)

        status, _h, _b = call_json("DELETE", f"/resources/{b}")
        self.assertEqual(status, "200 OK")

        _s, _h, body = call_json(
            "GET", "/graph/path/all", query_string=f"from={a}&to={c}"
        )
        self.assertEqual(body["found"], False)
        self.assertEqual(body["paths"], [])
        self.assertEqual(body["count"], 0)

    def test_enumeration_is_read_only(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        self._add(a, b)

        call_json("GET", "/graph/path/all", query_string=f"from={a}&to={b}")
        call_json("GET", "/graph/path/all", query_string=f"from={a}&to={b}")

        _s, _h, graph = call_json("GET", "/graph")
        self.assertEqual(len(graph["nodes"]), 2)
        self.assertEqual(len(graph["edges"]), 1)
        _s, _h, stats = call_json("GET", "/graph/stats")
        self.assertEqual(stats["nodes"], 2)
        self.assertEqual(stats["edges"], 1)

    # --- Validation -------------------------------------------------------------

    def test_missing_either_parameter_is_bad_request(self) -> None:
        a = self._create("a", DIGEST_A)
        for query_string in ("", f"from={a}", f"to={a}", "limit=1"):
            with self.subTest(query_string=query_string):
                status, _h, body = call_json(
                    "GET", "/graph/path/all", query_string=query_string
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_repeated_parameter_is_bad_request(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        for query_string in (
            f"from={a}&from={a}&to={b}",
            f"from={a}&to={b}&to={b}",
        ):
            with self.subTest(query_string=query_string):
                status, _h, body = call_json(
                    "GET", "/graph/path/all", query_string=query_string
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_unknown_parameter_is_bad_request(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        status, _h, body = call_json(
            "GET", "/graph/path/all", query_string=f"from={a}&to={b}&focus={a}"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_empty_value_is_bad_request(self) -> None:
        a = self._create("a", DIGEST_A)
        for query_string in (f"from=&to={a}", f"from={a}&to="):
            with self.subTest(query_string=query_string):
                status, _h, body = call_json(
                    "GET", "/graph/path/all", query_string=query_string
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_path_separator_in_value_is_bad_request(self) -> None:
        a = self._create("a", DIGEST_A)
        for query_string in (
            f"from=a/b&to={a}",
            f"from={a}&to=a\\b",
            f"from=a%2Fb&to={a}",
            f"from={a}&to=a%5Cb",
        ):
            with self.subTest(query_string=query_string):
                status, _h, body = call_json(
                    "GET", "/graph/path/all", query_string=query_string
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_bad_requests_do_not_read_or_change_state(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        self._add(a, b)

        call_json("GET", "/graph/path/all", query_string="bogus=1")
        call_json("GET", "/graph/path/all", query_string=f"from={a}")

        _s, _h, body = call_json(
            "GET", "/graph/path/all", query_string=f"from={a}&to={b}"
        )
        self.assertEqual(body["found"], True)
        self.assertEqual(body["paths"], [[a, b]])
        self.assertEqual(body["count"], 1)

    def test_unknown_resource_returns_404(self) -> None:
        a = self._create("a", DIGEST_A)
        missing = "0" * 32
        for query_string in (f"from={missing}&to={a}", f"from={a}&to={missing}"):
            with self.subTest(query_string=query_string):
                status, _h, body = call_json(
                    "GET", "/graph/path/all", query_string=query_string
                )
                self.assertEqual(status, "404 Not Found")
                self.assertEqual(body["error"], "resource_not_found")

    def test_declared_non_empty_body_is_bad_request(self) -> None:
        a = self._create("a", DIGEST_A)
        status, _h, body = call_json(
            "GET", "/graph/path/all", b"{}", query_string=f"from={a}&to={a}"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_malformed_content_length_is_bad_request(self) -> None:
        a = self._create("a", DIGEST_A)
        status, _h, body = call_json(
            "GET",
            "/graph/path/all",
            query_string=f"from={a}&to={a}",
            content_length="abc",
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_explicit_zero_length_body_is_accepted(self) -> None:
        a = self._create("a", DIGEST_A)
        status, _h, body = call_json(
            "GET", "/graph/path/all", b"", query_string=f"from={a}&to={a}"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["found"], True)

    # --- Method handling --------------------------------------------------------

    def test_other_methods_return_405_with_allow_get(self) -> None:
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, headers, body = call_json(method, "/graph/path/all")
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")
                self.assertEqual(
                    [value for name, value in headers if name == "Allow"],
                    ["GET"],
                )

    def test_subpath_is_not_the_enumeration_view(self) -> None:
        status, _h, body = call_json("GET", "/graph/path/all/anything")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "not_found")


if __name__ == "__main__":
    unittest.main()
