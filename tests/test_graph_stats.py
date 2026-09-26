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


class GraphStatsTests(unittest.TestCase):
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

    def _stats(self, **kwargs: object):
        return call("GET", "/graph/stats", **kwargs)

    # --- Empty graph ---------------------------------------------------------

    def test_empty_graph_stats(self) -> None:
        status, headers, raw = self._stats()
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            headers[0], ("Content-Type", "application/json; charset=utf-8")
        )
        self.assertEqual(
            raw,
            b'{"nodes":0,"edges":0,"isolated":[],'
            b'"out_degree":[],"in_degree":[],"max_depth":0}\n',
        )

    # --- Counts, isolation and rankings --------------------------------------

    def test_top_level_key_order_is_fixed(self) -> None:
        self._create("a", DIGEST_A)
        _s, _h, body = call_json("GET", "/graph/stats")
        self.assertEqual(
            list(body),
            [
                "nodes",
                "edges",
                "isolated",
                "out_degree",
                "in_degree",
                "max_depth",
            ],
        )

    def test_counts_isolation_and_rankings(self) -> None:
        # a -> c, a -> d, b -> d ; c and d have no outgoing edges;
        # e is registered afterwards and stays isolated.
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        d = self._create("d", DIGEST_D)
        e = self._create("e", DIGEST_E)
        self._add(a, c)
        self._add(a, d)
        self._add(b, d)

        status, _h, body = call_json("GET", "/graph/stats")
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["nodes"], 5)
        self.assertEqual(body["edges"], 3)
        self.assertEqual(body["isolated"], [e])
        self.assertEqual(
            body["out_degree"],
            [
                {"resource_id": a, "degree": 2},
                {"resource_id": b, "degree": 1},
            ],
        )
        self.assertEqual(
            body["in_degree"],
            [
                {"resource_id": d, "degree": 2},
                {"resource_id": c, "degree": 1},
            ],
        )
        self.assertEqual(body["max_depth"], 2)
        for entry in body["out_degree"] + body["in_degree"]:
            self.assertEqual(list(entry), ["resource_id", "degree"])

    def test_zero_degree_resources_never_ranked(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        self._add(a, b)

        _s, _h, body = call_json("GET", "/graph/stats")
        ranked_out = {entry["resource_id"] for entry in body["out_degree"]}
        ranked_in = {entry["resource_id"] for entry in body["in_degree"]}
        self.assertEqual(ranked_out, {a})
        self.assertEqual(ranked_in, {b})
        # c has neither edge kind and is isolated, not ranked.
        self.assertEqual(body["isolated"], [c])

    def test_equal_degrees_keep_registration_order(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        d = self._create("d", DIGEST_D)
        # Out-degree 1 ties between a, b, c in registration order; d
        # receives all three edges and tops the in-degree ranking.
        self._add(a, d)
        self._add(b, d)
        self._add(c, d)

        _s, _h, body = call_json("GET", "/graph/stats")
        self.assertEqual(
            [entry["resource_id"] for entry in body["out_degree"]], [a, b, c]
        )
        self.assertTrue(
            all(entry["degree"] == 1 for entry in body["out_degree"])
        )
        self.assertEqual(body["in_degree"], [{"resource_id": d, "degree": 3}])

    def test_isolated_resources_follow_registration_order(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        self._add(a, b)

        _s, _h, body = call_json("GET", "/graph/stats")
        self.assertEqual(body["isolated"], [c])

        d = self._create("d", DIGEST_D)
        _s, _h, body = call_json("GET", "/graph/stats")
        self.assertEqual(body["isolated"], [c, d])

    # --- Maximum depth --------------------------------------------------------

    def test_max_depth_counts_nodes_on_longest_chain(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        d = self._create("d", DIGEST_D)
        e = self._create("e", DIGEST_E)
        # Longest chain a -> b -> c -> d (4 nodes); e is isolated (1).
        self._add(a, b)
        self._add(b, c)
        self._add(c, d)

        _s, _h, body = call_json("GET", "/graph/stats")
        self.assertEqual(body["max_depth"], 4)

    def test_max_depth_takes_longest_path_in_diamond(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        d = self._create("d", DIGEST_D)
        # a reaches d directly (2 nodes) and through b/c (3 via b or c).
        self._add(a, b)
        self._add(a, c)
        self._add(b, d)
        self._add(c, d)
        self._add(a, d)

        _s, _h, body = call_json("GET", "/graph/stats")
        self.assertEqual(body["max_depth"], 3)

    def test_single_isolated_node_has_depth_one(self) -> None:
        self._create("a", DIGEST_A)
        _s, _h, body = call_json("GET", "/graph/stats")
        self.assertEqual(body["nodes"], 1)
        self.assertEqual(body["edges"], 0)
        self.assertEqual(body["max_depth"], 1)

    # --- Edge provenance ------------------------------------------------------

    def test_cross_reference_edges_are_counted(self) -> None:
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

        _s, _h, body = call_json("GET", "/graph/stats")
        self.assertEqual(body["nodes"], 2)
        self.assertEqual(body["edges"], 1)
        self.assertEqual(body["isolated"], [])
        self.assertEqual(body["out_degree"], [{"resource_id": local, "degree": 1}])
        self.assertEqual(body["in_degree"], [{"resource_id": remote, "degree": 1}])
        self.assertEqual(body["max_depth"], 2)

    # --- Recomputation and read-only behavior --------------------------------

    def test_stats_recompute_after_dependency_delete(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        self._add(a, b)
        self._add(a, c)

        status, _h, _b = call_json("DELETE", f"/resources/{a}/dependencies/{b}")
        self.assertEqual(status, "200 OK")

        _s, _h, body = call_json("GET", "/graph/stats")
        self.assertEqual(body["edges"], 1)
        self.assertEqual(body["nodes"], 3)
        self.assertEqual(body["in_degree"], [{"resource_id": c, "degree": 1}])
        self.assertEqual(body["isolated"], [b])
        self.assertEqual(body["max_depth"], 2)

    def test_stats_recompute_after_resource_delete(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        self._add(a, b)
        self._add(c, b)

        status, _h, _b = call_json("DELETE", f"/resources/{b}")
        self.assertEqual(status, "200 OK")

        _s, _h, body = call_json("GET", "/graph/stats")
        self.assertEqual(body["nodes"], 2)
        self.assertEqual(body["edges"], 0)
        self.assertEqual(body["isolated"], [a, c])
        self.assertEqual(body["out_degree"], [])
        self.assertEqual(body["in_degree"], [])
        self.assertEqual(body["max_depth"], 1)

    def test_stats_are_read_only(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        self._add(a, b)

        call_json("GET", "/graph/stats")
        call_json("GET", "/graph/stats")

        _s, _h, graph = call_json("GET", "/graph")
        self.assertEqual(len(graph["nodes"]), 2)
        self.assertEqual(len(graph["edges"]), 1)
        _s, _h, stats = call_json("GET", "/graph/stats")
        self.assertEqual(stats["nodes"], 2)
        self.assertEqual(stats["edges"], 1)

    # --- Validation -----------------------------------------------------------

    def test_query_parameters_are_bad_request(self) -> None:
        self._create("a", DIGEST_A)
        for query_string in ("bogus=1", "focus=a", "=", "x=&y=2"):
            with self.subTest(query_string=query_string):
                status, _h, body = call_json(
                    "GET", "/graph/stats", query_string=query_string
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_declared_non_empty_body_is_bad_request(self) -> None:
        self._create("a", DIGEST_A)
        status, _h, body = call_json("GET", "/graph/stats", b"{}")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

        # The rejected request changed nothing: the lone node is still
        # registered and isolated.
        _s, _h, stats = call_json("GET", "/graph/stats")
        self.assertEqual(stats["nodes"], 1)
        self.assertEqual(len(stats["isolated"]), 1)

    def test_malformed_content_length_is_bad_request(self) -> None:
        status, _h, body = call_json(
            "GET", "/graph/stats", content_length="abc"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_explicit_zero_length_body_is_accepted(self) -> None:
        status, _h, body = call_json("GET", "/graph/stats", b"")
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["nodes"], 0)

    # --- Method handling ------------------------------------------------------

    def test_other_methods_return_405_with_allow_get(self) -> None:
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, headers, body = call_json(method, "/graph/stats")
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")
                self.assertEqual(
                    [value for name, value in headers if name == "Allow"],
                    ["GET"],
                )

    def test_stats_subpath_is_not_the_stats_view(self) -> None:
        status, _h, body = call_json("GET", "/graph/stats/anything")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "not_found")


if __name__ == "__main__":
    unittest.main()
