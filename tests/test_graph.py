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


class GraphTests(unittest.TestCase):
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

    def _graph(self, **kwargs: object):
        return call("GET", "/graph", **kwargs)

    # --- Empty graph --------------------------------------------------------

    def test_empty_graph_returns_empty_collections(self) -> None:
        status, headers, raw = self._graph()
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            headers[0], ("Content-Type", "application/json; charset=utf-8")
        )
        self.assertEqual(raw, b'{"nodes":[],"edges":[]}\n')

    # --- Whole-graph snapshot ------------------------------------------------

    def test_nodes_in_registration_order_with_fixed_keys(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)

        status, _h, body = call_json("GET", "/graph")
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            body["nodes"],
            [
                {"id": a, "name": "a", "category": "code", "digest": DIGEST_A},
                {"id": b, "name": "b", "category": "code", "digest": DIGEST_B},
            ],
        )
        for node in body["nodes"]:
            self.assertEqual(list(node), ["id", "name", "category", "digest"])
        self.assertEqual(body["edges"], [])
        self.assertEqual(list(body), ["nodes", "edges"])

    def test_edges_follow_start_registration_then_creation_order(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        d = self._create("d", DIGEST_D)
        # b's edges are registered before a's, but a was registered first.
        self._add(b, d)
        self._add(a, c)
        self._add(b, c)
        self._add(a, d)

        _s, _h, body = call_json("GET", "/graph")
        self.assertEqual(
            body["edges"],
            [
                {"resource_id": a, "dependency_id": c},
                {"resource_id": a, "dependency_id": d},
                {"resource_id": b, "dependency_id": d},
                {"resource_id": b, "dependency_id": c},
            ],
        )
        for edge in body["edges"]:
            self.assertEqual(list(edge), ["resource_id", "dependency_id"])

    def test_response_is_compact_utf8_and_newline_terminated(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        self._add(a, b)

        status, _h, raw = self._graph()
        self.assertEqual(status, "200 OK")
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        self.assertNotIn(b" ", raw[:-1])
        self.assertEqual(
            raw,
            b'{"nodes":[{"id":"' + a.encode() + b'","name":"a",'
            b'"category":"code","digest":"' + DIGEST_A.encode() + b'"},'
            b'{"id":"' + b.encode() + b'","name":"b","category":"code",'
            b'"digest":"' + DIGEST_B.encode() + b'"}],'
            b'"edges":[{"resource_id":"' + a.encode()
            + b'","dependency_id":"' + b.encode() + b'"}]}\n',
        )

    def test_cross_reference_edges_are_included(self) -> None:
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

        _s, _h, body = call_json("GET", "/graph")
        self.assertEqual([node["id"] for node in body["nodes"]], [local, remote])
        self.assertEqual(
            body["edges"], [{"resource_id": local, "dependency_id": remote}]
        )

    def test_graph_recomputes_after_dependency_delete(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        self._add(a, b)
        self._add(a, c)

        status, _h, _b = call_json("DELETE", f"/resources/{a}/dependencies/{b}")
        self.assertEqual(status, "200 OK")

        _s, _h, body = call_json("GET", "/graph")
        self.assertEqual(
            body["edges"], [{"resource_id": a, "dependency_id": c}]
        )
        self.assertEqual(len(body["nodes"]), 3)

    def test_graph_recomputes_after_resource_delete(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        self._add(a, b)
        self._add(c, b)

        status, _h, _b = call_json("DELETE", f"/resources/{b}")
        self.assertEqual(status, "200 OK")

        _s, _h, body = call_json("GET", "/graph")
        self.assertEqual([node["id"] for node in body["nodes"]], [a, c])
        self.assertEqual(body["edges"], [])

    def test_graph_is_read_only(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        self._add(a, b)

        call_json("GET", "/graph")
        call_json("GET", "/graph", query_string=f"focus={a}")

        _s, _h, listing = call_json("GET", "/resources")
        self.assertEqual(len(listing["resources"]), 2)
        _s, _h, deps = call_json("GET", f"/resources/{a}/dependencies")
        self.assertEqual(deps["dependencies"], [b])

    # --- Focus neighborhood --------------------------------------------------

    def test_focus_returns_one_hop_neighborhood(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        d = self._create("d", DIGEST_D)
        e = self._create("e", DIGEST_E)
        # a -> b -> c -> d, and e -> b as an inbound edge of the focus.
        self._add(a, b)
        self._add(b, c)
        self._add(c, d)
        self._add(e, b)

        status, _h, body = call_json(
            "GET", "/graph", query_string=f"focus={b}"
        )
        self.assertEqual(status, "200 OK")
        # Focus, its direct dependency and its direct dependents; the
        # indirectly reachable d and edges beyond the one-hop ring are out.
        self.assertEqual(
            [node["id"] for node in body["nodes"]], [a, b, c, e]
        )
        self.assertEqual(
            body["edges"],
            [
                {"resource_id": a, "dependency_id": b},
                {"resource_id": b, "dependency_id": c},
                {"resource_id": e, "dependency_id": b},
            ],
        )

    def test_focus_isolated_resource_returns_only_itself(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        self._add(a, b)
        c = self._create("c", DIGEST_C)

        status, _h, body = call_json(
            "GET", "/graph", query_string=f"focus={c}"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual([node["id"] for node in body["nodes"]], [c])
        self.assertEqual(body["edges"], [])

    def test_focus_edges_keep_global_ordering(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        d = self._create("d", DIGEST_D)
        # Two inbound edges to c: a -> c and b -> c; a outranks b.
        self._add(b, c)
        self._add(a, c)
        self._add(c, d)

        _s, _h, body = call_json("GET", "/graph", query_string=f"focus={c}")
        self.assertEqual(
            body["edges"],
            [
                {"resource_id": a, "dependency_id": c},
                {"resource_id": b, "dependency_id": c},
                {"resource_id": c, "dependency_id": d},
            ],
        )

    def test_focus_reflects_latest_state(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        self._add(a, b)

        status, _h, _b = call_json("DELETE", f"/resources/{a}/dependencies/{b}")
        self.assertEqual(status, "200 OK")

        _s, _h, body = call_json("GET", "/graph", query_string=f"focus={a}")
        self.assertEqual([node["id"] for node in body["nodes"]], [a])
        self.assertEqual(body["edges"], [])

    def test_focus_unknown_resource_is_not_found(self) -> None:
        self._create("a", DIGEST_A)
        status, _h, body = call_json(
            "GET", "/graph", query_string="focus=does-not-exist"
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

        # The failed lookup changes nothing.
        _s, _h, graph = call_json("GET", "/graph")
        self.assertEqual(len(graph["nodes"]), 1)

    # --- Validation ----------------------------------------------------------

    def test_empty_focus_is_bad_request(self) -> None:
        self._create("a", DIGEST_A)
        status, _h, body = call_json("GET", "/graph", query_string="focus=")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_focus_with_path_separator_is_bad_request(self) -> None:
        self._create("a", DIGEST_A)
        for value in ("a/b", "a%2Fb", "a%5Cb", "a\\b"):
            with self.subTest(value=value):
                status, _h, body = call_json(
                    "GET", "/graph", query_string=f"focus={value}"
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_unknown_query_parameter_is_bad_request(self) -> None:
        status, _h, body = call_json("GET", "/graph", query_string="bogus=1")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_repeated_focus_is_bad_request(self) -> None:
        a = self._create("a", DIGEST_A)
        status, _h, body = call_json(
            "GET", "/graph", query_string=f"focus={a}&focus={a}"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_declared_non_empty_body_is_bad_request(self) -> None:
        a = self._create("a", DIGEST_A)
        status, _h, body = call_json(
            "GET", "/graph", b"{}", query_string=f"focus={a}"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

        # The rejected request read nothing: the graph is still intact.
        _s, _h, graph = call_json("GET", "/graph")
        self.assertEqual(len(graph["nodes"]), 1)

    def test_malformed_content_length_is_bad_request(self) -> None:
        status, _h, body = call_json(
            "GET", "/graph", content_length="abc"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_explicit_zero_length_body_is_accepted(self) -> None:
        status, _h, body = call_json("GET", "/graph", b"")
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, {"nodes": [], "edges": []})

    # --- Method handling -----------------------------------------------------

    def test_other_methods_return_405_with_allow_get(self) -> None:
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, headers, body = call_json(method, "/graph")
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")
                self.assertIn(("Allow", "GET"), headers)

    def test_graph_subpath_is_not_the_snapshot(self) -> None:
        status, _h, body = call_json("GET", "/graph/anything")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "not_found")


if __name__ == "__main__":
    unittest.main()
