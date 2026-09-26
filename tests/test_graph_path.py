from __future__ import annotations

import io
import json
import unittest
from unittest import mock

from provenance_api.app import application, reset_state
from provenance_api.cross_references import Resolution

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_D = "d" * 64
DIGEST_E = "e" * 64
DIGEST_REMOTE = "f" * 64

UPSTREAM = "https://repo.example.invalid"
REMOTE_ID = "remote-42"
REMOTE_NAME = "remote-model"
REMOTE_SOURCE = "https://repo.example.invalid/sources/remote-42"


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


class GraphPathTests(unittest.TestCase):
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

    def _path(self, from_id: str, to_id: str, **kwargs: object):
        return call(
            "GET",
            "/graph/path",
            query_string=f"from={from_id}&to={to_id}",
            **kwargs,
        )

    # --- Successful queries ---------------------------------------------------

    def test_direct_edge_path(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        self._add(a, b)

        status, headers, raw = self._path(a, b)
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            headers[0], ("Content-Type", "application/json; charset=utf-8")
        )
        self.assertEqual(
            raw,
            (
                '{"from":"%s","to":"%s","found":true,'
                '"path":["%s","%s"],"length":2}\n' % (a, b, a, b)
            ).encode("utf-8"),
        )

    def test_top_level_key_order_is_fixed(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        self._add(a, b)

        _s, _h, body = call_json(
            "GET", "/graph/path", query_string=f"from={a}&to={b}"
        )
        self.assertEqual(list(body), ["from", "to", "found", "path", "length"])

    def test_transitive_path_follows_edge_direction(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        self._add(a, b)
        self._add(b, c)

        _s, _h, body = call_json(
            "GET", "/graph/path", query_string=f"from={a}&to={c}"
        )
        self.assertEqual(body["found"], True)
        self.assertEqual(body["path"], [a, b, c])
        self.assertEqual(body["length"], 3)

        # The reverse direction walks no edges: c depends on nothing.
        _s, _h, body = call_json(
            "GET", "/graph/path", query_string=f"from={c}&to={a}"
        )
        self.assertEqual(body["found"], False)
        self.assertEqual(body["path"], [])
        self.assertEqual(body["length"], 0)

    def test_same_resource_is_found_with_single_node_path(self) -> None:
        a = self._create("a", DIGEST_A)
        _s, _h, body = call_json(
            "GET", "/graph/path", query_string=f"from={a}&to={a}"
        )
        self.assertEqual(body["found"], True)
        self.assertEqual(body["path"], [a])
        self.assertEqual(body["length"], 1)

    def test_unreachable_target_is_a_successful_not_found_result(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        status, _h, body = call_json(
            "GET", "/graph/path", query_string=f"from={a}&to={b}"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["found"], False)
        self.assertEqual(body["path"], [])
        self.assertEqual(body["length"], 0)

    def test_shortest_path_is_preferred_over_longer_one(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        d = self._create("d", DIGEST_D)
        # a reaches d directly and through b and c; the direct edge wins.
        self._add(a, b)
        self._add(b, c)
        self._add(c, d)
        self._add(a, d)

        _s, _h, body = call_json(
            "GET", "/graph/path", query_string=f"from={a}&to={d}"
        )
        self.assertEqual(body["path"], [a, d])
        self.assertEqual(body["length"], 2)

    def test_tie_break_picks_earliest_registered_second_node(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        d = self._create("d", DIGEST_D)
        # Two equally short paths a -> b -> d and a -> c -> d; b was
        # registered before c, so the path through b is picked even though
        # the a -> c edge was registered first.
        self._add(a, c)
        self._add(a, b)
        self._add(b, d)
        self._add(c, d)

        _s, _h, body = call_json(
            "GET", "/graph/path", query_string=f"from={a}&to={d}"
        )
        self.assertEqual(body["path"], [a, b, d])
        self.assertEqual(body["length"], 3)

    def test_tie_break_applies_to_later_nodes_as_well(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        d = self._create("d", DIGEST_D)
        e = self._create("e", DIGEST_E)
        # a -> e -> {c, b} -> d: the second node is forced, the third node
        # tie is broken by registration order (b before c).
        self._add(a, e)
        self._add(e, c)
        self._add(e, b)
        self._add(b, d)
        self._add(c, d)

        _s, _h, body = call_json(
            "GET", "/graph/path", query_string=f"from={a}&to={d}"
        )
        self.assertEqual(body["path"], [a, e, b, d])
        self.assertEqual(body["length"], 4)

    def test_cross_reference_edges_participate(self) -> None:
        local = self._create("local", DIGEST_A)
        resolution = Resolution(
            name=REMOTE_NAME,
            category="model",
            digest=DIGEST_REMOTE,
            source=REMOTE_SOURCE,
            raw=b"{}",
        )
        with mock.patch(
            "provenance_api.app.resolve_remote", return_value=resolution
        ):
            status, _h, _b = call_json(
                "POST",
                f"/resources/{local}/cross-references",
                {
                    "repository": "partner",
                    "upstream": UPSTREAM,
                    "remote_id": REMOTE_ID,
                    "digest": DIGEST_REMOTE,
                },
            )
        self.assertEqual(status, "201 Created")

        _s, _h, listing = call_json("GET", "/resources")
        remote = next(r["id"] for r in listing["resources"] if r["id"] != local)

        _s, _h, body = call_json(
            "GET", "/graph/path", query_string=f"from={local}&to={remote}"
        )
        self.assertEqual(body["found"], True)
        self.assertEqual(body["path"], [local, remote])
        self.assertEqual(body["length"], 2)

    # --- Recomputation and read-only behavior ---------------------------------

    def test_path_recomputes_after_dependency_changes(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        self._add(a, b)
        self._add(b, c)

        status, _h, _b = call_json("DELETE", f"/resources/{a}/dependencies/{b}")
        self.assertEqual(status, "200 OK")

        _s, _h, body = call_json(
            "GET", "/graph/path", query_string=f"from={a}&to={c}"
        )
        self.assertEqual(body["found"], False)
        self.assertEqual(body["path"], [])
        self.assertEqual(body["length"], 0)

        # Re-registering the edge restores the path immediately.
        self._add(a, b)
        _s, _h, body = call_json(
            "GET", "/graph/path", query_string=f"from={a}&to={c}"
        )
        self.assertEqual(body["found"], True)
        self.assertEqual(body["path"], [a, b, c])

    def test_path_recomputes_after_resource_delete(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        self._add(a, b)
        self._add(b, c)

        status, _h, _b = call_json("DELETE", f"/resources/{b}")
        self.assertEqual(status, "200 OK")

        _s, _h, body = call_json(
            "GET", "/graph/path", query_string=f"from={a}&to={c}"
        )
        self.assertEqual(body["found"], False)
        self.assertEqual(body["path"], [])

        # The deregistered middle resource itself is gone for good.
        status, _h, body = call_json(
            "GET", "/graph/path", query_string=f"from={a}&to={b}"
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

    def test_path_query_is_read_only(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        self._add(a, b)

        call_json("GET", "/graph/path", query_string=f"from={a}&to={b}")
        call_json("GET", "/graph/path", query_string=f"from={a}&to={b}")

        _s, _h, graph = call_json("GET", "/graph")
        self.assertEqual(len(graph["nodes"]), 2)
        self.assertEqual(len(graph["edges"]), 1)
        _s, _h, stats = call_json("GET", "/graph/stats")
        self.assertEqual(stats["nodes"], 2)
        self.assertEqual(stats["edges"], 1)

    # --- Validation -------------------------------------------------------------

    def test_missing_either_parameter_is_bad_request(self) -> None:
        a = self._create("a", DIGEST_A)
        for query_string in ("", f"from={a}", f"to={a}"):
            with self.subTest(query_string=query_string):
                status, _h, body = call_json(
                    "GET", "/graph/path", query_string=query_string
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
                    "GET", "/graph/path", query_string=query_string
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_unknown_parameter_is_bad_request(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        status, _h, body = call_json(
            "GET", "/graph/path", query_string=f"from={a}&to={b}&focus={a}"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_empty_value_is_bad_request(self) -> None:
        a = self._create("a", DIGEST_A)
        for query_string in (f"from=&to={a}", f"from={a}&to="):
            with self.subTest(query_string=query_string):
                status, _h, body = call_json(
                    "GET", "/graph/path", query_string=query_string
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
                    "GET", "/graph/path", query_string=query_string
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_bad_requests_do_not_read_or_change_state(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        self._add(a, b)

        call_json("GET", "/graph/path", query_string="bogus=1")
        call_json("GET", "/graph/path", query_string=f"from={a}")

        _s, _h, body = call_json(
            "GET", "/graph/path", query_string=f"from={a}&to={b}"
        )
        self.assertEqual(body["found"], True)
        self.assertEqual(body["path"], [a, b])

    def test_unknown_resource_returns_404(self) -> None:
        a = self._create("a", DIGEST_A)
        missing = "0" * 32
        for query_string in (f"from={missing}&to={a}", f"from={a}&to={missing}"):
            with self.subTest(query_string=query_string):
                status, _h, body = call_json(
                    "GET", "/graph/path", query_string=query_string
                )
                self.assertEqual(status, "404 Not Found")
                self.assertEqual(body["error"], "resource_not_found")

    def test_declared_non_empty_body_is_bad_request(self) -> None:
        a = self._create("a", DIGEST_A)
        status, _h, body = call_json(
            "GET", "/graph/path", b"{}", query_string=f"from={a}&to={a}"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_malformed_content_length_is_bad_request(self) -> None:
        a = self._create("a", DIGEST_A)
        status, _h, body = call_json(
            "GET",
            "/graph/path",
            query_string=f"from={a}&to={a}",
            content_length="abc",
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_explicit_zero_length_body_is_accepted(self) -> None:
        a = self._create("a", DIGEST_A)
        status, _h, body = call_json(
            "GET", "/graph/path", b"", query_string=f"from={a}&to={a}"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["found"], True)

    # --- Method handling --------------------------------------------------------

    def test_other_methods_return_405_with_allow_get(self) -> None:
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, headers, body = call_json(method, "/graph/path")
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")
                self.assertEqual(
                    [value for name, value in headers if name == "Allow"],
                    ["GET"],
                )

    def test_path_subpath_is_not_the_path_view(self) -> None:
        status, _h, body = call_json("GET", "/graph/path/anything")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "not_found")


if __name__ == "__main__":
    unittest.main()
