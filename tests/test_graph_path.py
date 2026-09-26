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
DIGEST_F = "f" * 64
DIGEST_REMOTE = "9" * 64

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

    def _path(self, source_id: str, target_id: str, **kwargs: object):
        return call_json(
            "GET",
            "/graph/path",
            query_string=f"from={source_id}&to={target_id}",
            **kwargs,
        )

    # --- Found paths ---------------------------------------------------------

    def test_direct_and_chained_paths(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        d = self._create("d", DIGEST_D)
        self._add(a, b)
        self._add(b, c)
        self._add(c, d)
        # A direct edge that is longer in nodes to traverse around.
        self._add(a, c)

        status, headers, body = self._path(a, d)
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            headers[0], ("Content-Type", "application/json; charset=utf-8")
        )
        self.assertEqual(
            list(body), ["from", "to", "found", "path", "length"]
        )
        self.assertEqual(body["from"], a)
        self.assertEqual(body["to"], d)
        self.assertTrue(body["found"])
        # Shortest is a -> c -> d (3 nodes), not the full chain.
        self.assertEqual(body["path"], [a, c, d])
        self.assertEqual(body["length"], 3)
        self.assertEqual(body["length"], len(body["path"]))

    def test_direct_edge_path(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        self._add(a, b)

        _s, _h, body = self._path(a, b)
        self.assertTrue(body["found"])
        self.assertEqual(body["path"], [a, b])
        self.assertEqual(body["length"], 2)

    def test_path_to_self_is_single_node(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        self._add(a, b)

        _s, _h, body = self._path(a, a)
        self.assertTrue(body["found"])
        self.assertEqual(body["path"], [a])
        self.assertEqual(body["length"], 1)
        # An isolated resource queries against itself the same way.
        _s, _h, body = self._path(b, b)
        self.assertTrue(body["found"])
        self.assertEqual(body["path"], [b])
        self.assertEqual(body["length"], 1)

    def test_response_is_compact_json_with_single_newline(self) -> None:
        a = self._create("a", DIGEST_A)
        status, headers, raw = call(
            "GET", "/graph/path", query_string=f"from={a}&to={a}"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, (
            f'{{"from":"{a}","to":"{a}","found":true,'
            f'"path":["{a}"],"length":1}}\n'
        ).encode("utf-8"))
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))

    # --- Not found -----------------------------------------------------------

    def test_unreachable_target_is_successful_empty_path(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)

        status, _h, body = self._path(a, b)
        self.assertEqual(status, "200 OK")
        self.assertFalse(body["found"])
        self.assertEqual(body["path"], [])
        self.assertEqual(body["length"], 0)
        self.assertEqual(body["length"], len(body["path"]))

    def test_path_follows_dependency_direction_only(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        # b depends on a: the reverse direction has no path.
        self._add(b, a)

        _s, _h, body = self._path(a, b)
        self.assertFalse(body["found"])
        self.assertEqual(body["path"], [])
        self.assertEqual(body["length"], 0)

        _s, _h, body = self._path(b, a)
        self.assertTrue(body["found"])
        self.assertEqual(body["path"], [b, a])

    # --- Tie-break on registration order ------------------------------------

    def test_tie_breaks_by_second_node_registration_order(self) -> None:
        # Registration order: a, m, n, x, y, t. Two equally short paths
        # a -> m -> y -> t and a -> n -> x -> t. m is registered before n,
        # so the m path wins even though y is registered after x and even
        # though the a -> n edge is established first.
        a = self._create("a", DIGEST_A)
        m = self._create("m", DIGEST_B)
        n = self._create("n", DIGEST_C)
        x = self._create("x", DIGEST_D)
        y = self._create("y", DIGEST_E)
        t = self._create("t", DIGEST_F)
        self._add(a, n)
        self._add(a, m)
        self._add(m, y)
        self._add(n, x)
        self._add(x, t)
        self._add(y, t)

        _s, _h, body = self._path(a, t)
        self.assertTrue(body["found"])
        self.assertEqual(body["path"], [a, m, y, t])
        self.assertEqual(body["length"], 4)

    def test_tie_breaks_by_later_node_registration_order(self) -> None:
        # Same second node m; the choice is between x and y. x is
        # registered before y, so the x path wins even though the m -> y
        # edge is established first.
        a = self._create("a", DIGEST_A)
        m = self._create("m", DIGEST_B)
        x = self._create("x", DIGEST_C)
        y = self._create("y", DIGEST_D)
        t = self._create("t", DIGEST_E)
        self._add(m, y)
        self._add(m, x)
        self._add(x, t)
        self._add(y, t)
        self._add(a, m)

        _s, _h, body = self._path(a, t)
        self.assertTrue(body["found"])
        self.assertEqual(body["path"], [a, m, x, t])
        self.assertEqual(body["length"], 4)

    def test_path_nodes_do_not_repeat(self) -> None:
        # Diamond: the chosen shortest path visits each node once.
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        d = self._create("d", DIGEST_D)
        self._add(a, b)
        self._add(a, c)
        self._add(b, d)
        self._add(c, d)

        _s, _h, body = self._path(a, d)
        self.assertEqual(body["path"], [a, b, d])
        self.assertEqual(len(body["path"]), len(set(body["path"])))

    # --- Query parameter validation -----------------------------------------

    def test_missing_parameter_is_bad_request(self) -> None:
        a = self._create("a", DIGEST_A)
        for query_string in (f"from={a}", f"to={a}", ""):
            with self.subTest(query_string=query_string):
                status, _h, body = call_json(
                    "GET", "/graph/path", query_string=query_string
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_repeated_parameter_is_bad_request(self) -> None:
        a = self._create("a", DIGEST_A)
        for query_string in (
            f"from={a}&from={a}&to={a}",
            f"from={a}&to={a}&to={a}",
        ):
            with self.subTest(query_string=query_string):
                status, _h, body = call_json(
                    "GET", "/graph/path", query_string=query_string
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_unknown_parameter_is_bad_request(self) -> None:
        a = self._create("a", DIGEST_A)
        for query_string in (
            f"from={a}&to={a}&bogus=1",
            f"from={a}&to={a}&focus={a}",
        ):
            with self.subTest(query_string=query_string):
                status, _h, body = call_json(
                    "GET", "/graph/path", query_string=query_string
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_empty_parameter_value_is_bad_request(self) -> None:
        a = self._create("a", DIGEST_A)
        for query_string in (f"from=&to={a}", f"from={a}&to="):
            with self.subTest(query_string=query_string):
                status, _h, body = call_json(
                    "GET", "/graph/path", query_string=query_string
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_path_separator_values_are_bad_request(self) -> None:
        a = self._create("a", DIGEST_A)
        for query_string in (
            f"from={a}/x&to={a}",
            f"from={a}&to=x\\{a}",
            # Percent-encoded separators are decoded before validation.
            f"from=%2F&to={a}",
            f"from={a}&to=x%5Cy",
            f"from={a}&to=x%2fy",
        ):
            with self.subTest(query_string=query_string):
                status, _h, body = call_json(
                    "GET", "/graph/path", query_string=query_string
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    # --- Missing resources ---------------------------------------------------

    def test_missing_resource_is_not_found(self) -> None:
        a = self._create("a", DIGEST_A)
        for query_string in (
            "from=does-not-exist&to=also-missing",
            f"from={a}&to=does-not-exist",
            f"from=does-not-exist&to={a}",
        ):
            with self.subTest(query_string=query_string):
                status, _h, body = call_json(
                    "GET", "/graph/path", query_string=query_string
                )
                self.assertEqual(status, "404 Not Found")
                self.assertEqual(body["error"], "resource_not_found")

    def test_bad_request_is_reported_before_missing_resource(self) -> None:
        # Validation errors never read business data: an empty value wins
        # over the missing endpoint, and the registry is untouched.
        status, _h, body = call_json(
            "GET", "/graph/path", query_string="from=&to=does-not-exist"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    # --- Body handling -------------------------------------------------------

    def test_declared_non_empty_body_is_bad_request(self) -> None:
        a = self._create("a", DIGEST_A)
        status, _h, body = call_json(
            "GET",
            "/graph/path",
            b"{}",
            query_string=f"from={a}&to={a}",
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

        # The rejected request changed nothing.
        _s, _h, again = self._path(a, a)
        self.assertTrue(again["found"])

    def test_malformed_content_length_is_bad_request(self) -> None:
        a = self._create("a", DIGEST_A)
        status, _h, body = call_json(
            "GET",
            "/graph/path",
            content_length="abc",
            query_string=f"from={a}&to={a}",
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_empty_body_variants_are_accepted(self) -> None:
        a = self._create("a", DIGEST_A)
        status, _h, body = call_json(
            "GET",
            "/graph/path",
            b"",
            query_string=f"from={a}&to={a}",
        )
        self.assertEqual(status, "200 OK")
        self.assertTrue(body["found"])

        status, _h, body = call_json(
            "GET",
            "/graph/path",
            query_string=f"from={a}&to={a}",
            omit_content_length=True,
        )
        self.assertEqual(status, "200 OK")
        self.assertTrue(body["found"])

    # --- Method handling -----------------------------------------------------

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

    # --- Recomputation -------------------------------------------------------

    def test_path_recomputes_after_dependency_delete(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        self._add(a, b)
        self._add(a, c)
        self._add(c, b)

        # Shortest is the direct edge a -> b.
        _s, _h, body = self._path(a, b)
        self.assertEqual(body["path"], [a, b])

        status, _h, _b = call_json("DELETE", f"/resources/{a}/dependencies/{b}")
        self.assertEqual(status, "200 OK")

        _s, _h, body = self._path(a, b)
        self.assertEqual(body["path"], [a, c, b])
        self.assertEqual(body["length"], 3)

    def test_path_recomputes_after_resource_delete(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        self._add(a, b)
        self._add(b, c)

        status, _h, _b = call_json("DELETE", f"/resources/{b}")
        self.assertEqual(status, "200 OK")

        _s, _h, body = self._path(a, c)
        self.assertFalse(body["found"])
        self.assertEqual(body["path"], [])
        self.assertEqual(body["length"], 0)

        _s, _h, body = self._path(a, a)
        self.assertTrue(body["found"])

    def test_cross_reference_edge_is_traversable(self) -> None:
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

        _s, _h, body = self._path(local, remote)
        self.assertTrue(body["found"])
        self.assertEqual(body["path"], [local, remote])
        self.assertEqual(body["length"], 2)

    def test_path_query_is_read_only(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        self._add(a, b)

        self._path(a, b)
        self._path(b, a)
        self._path(a, a)

        _s, _h, graph = call_json("GET", "/graph")
        self.assertEqual(len(graph["nodes"]), 2)
        self.assertEqual(len(graph["edges"]), 1)


if __name__ == "__main__":
    unittest.main()
