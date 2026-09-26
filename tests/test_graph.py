from __future__ import annotations

import io
import json
import unittest
from unittest import mock

from provenance_api.app import application, reset_state

DIGEST_A = "1" * 64
DIGEST_B = "2" * 64
DIGEST_C = "3" * 64
DIGEST_D = "4" * 64
DIGEST_REMOTE = "a" * 64


def call(
    method: str,
    path: str,
    body: bytes = b"",
    *,
    query_string: str | None = None,
    content_type: str | None = None,
    content_length: str | None = None,
    omit_content_length: bool = False,
) -> tuple[str, list[tuple[str, str]], bytes]:
    environ: dict[str, object] = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "CONTENT_LENGTH": (
            str(len(body)) if content_length is None else content_length
        ),
        "wsgi.input": io.BytesIO(body),
    }
    if omit_content_length:
        environ.pop("CONTENT_LENGTH")
    if content_type is not None:
        environ["CONTENT_TYPE"] = content_type
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
    body: bytes = b"",
    *,
    query_string: str | None = None,
) -> tuple[str, list[tuple[str, str]], dict[str, object]]:
    status, headers, raw = call(
        method, path, body, query_string=query_string
    )
    return status, headers, json.loads(raw.decode("utf-8"))


def register_json(
    name: str,
    digest: str,
    *,
    category: str = "code",
    source: str | None = None,
) -> str:
    payload: dict[str, object] = {
        "name": name,
        "category": category,
        "digest": digest,
    }
    if source is not None:
        payload["source"] = source
    raw = json.dumps(payload).encode("utf-8")
    status, _h, parsed = call_json("POST", "/resources", raw)
    assert status == "201 Created", (status, parsed)
    return str(parsed["id"])


def add_dependency(resource_id: str, dependency_id: str) -> None:
    raw = json.dumps({"dependency_id": dependency_id}).encode("utf-8")
    status, _h, body = call(
        "POST",
        f"/resources/{resource_id}/dependencies",
        raw,
        content_type="application/json",
    )
    assert status == "201 Created", (status, body)


def patch_resolve() -> mock._patch:
    from provenance_api.cross_references import Resolution

    resolution = Resolution(
        name="remote-model",
        category="model",
        digest=DIGEST_REMOTE,
        source="https://repo.example.invalid/sources/remote-42",
        raw=b"{}",
    )
    return mock.patch(
        "provenance_api.app.resolve_remote", return_value=resolution
    )


def add_cross_reference(resource_id: str) -> str:
    body = json.dumps(
        {
            "repository": "partner",
            "upstream": "https://repo.example.invalid",
            "remote_id": "remote-42",
            "digest": DIGEST_REMOTE,
        }
    ).encode("utf-8")
    with patch_resolve():
        status, _h, parsed = call_json(
            "POST",
            f"/resources/{resource_id}/cross-references",
            body,
        )
    assert status == "201 Created", (status, parsed)
    # The resolved remote resource is the edge target; find it via graph.
    _s, _h, graph = call_json("GET", "/graph")
    edges = graph["edges"]
    targets = [
        str(e["dependency_id"])
        for e in edges
        if str(e["resource_id"]) == resource_id
    ]
    assert targets, edges
    return targets[0]


class GraphSnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def test_empty_graph_is_valid_set(self) -> None:
        status, headers, raw = call("GET", "/graph")

        self.assertEqual(status, "200 OK")
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )
        self.assertEqual(raw, b'{"nodes":[],"edges":[]}\n')

    def test_node_shape_and_registration_order(self) -> None:
        first = register_json("α-model", DIGEST_A, category="model")
        second = register_json(
            "data-set", DIGEST_B, category="dataset", source="origin"
        )
        third = register_json("artifact-x", DIGEST_C, category="artifact")

        status, _h, body = call_json("GET", "/graph")
        self.assertEqual(status, "200 OK")

        nodes = body["nodes"]
        self.assertEqual([n["id"] for n in nodes], [first, second, third])
        for node in nodes:
            # Exactly four keys, in fixed order.
            self.assertEqual(
                list(node), ["id", "name", "category", "digest"]
            )
        # Non-ASCII names survive the compact UTF-8 encoding.
        self.assertEqual(nodes[0]["name"], "α-model")
        self.assertEqual(nodes[0]["category"], "model")
        self.assertEqual(nodes[0]["digest"], DIGEST_A)
        self.assertNotIn("source", nodes[0])

    def test_edges_follow_start_registration_and_establishment_order(self) -> None:
        a = register_json("a", DIGEST_A)
        b = register_json("b", DIGEST_B)
        c = register_json("c", DIGEST_C)
        d = register_json("d", DIGEST_D)

        # a's edges are established out of target registration order.
        add_dependency(a, d)
        add_dependency(a, b)
        add_dependency(b, c)
        add_dependency(d, c)

        _s, _h, body = call_json("GET", "/graph")
        edges = [
            (str(e["resource_id"]), str(e["dependency_id"]))
            for e in body["edges"]
        ]
        self.assertEqual(
            edges,
            [(a, d), (a, b), (b, c), (d, c)],
        )
        for edge in body["edges"]:
            self.assertEqual(list(edge), ["resource_id", "dependency_id"])

    def test_snapshot_is_compact_utf8_newline_terminated(self) -> None:
        register_json("a", DIGEST_A)
        register_json("b", DIGEST_B)

        _s, _h, raw = call("GET", "/graph")
        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(b" ", raw[:-1])
        self.assertNotIn(b"\t", raw[:-1])

    def test_snapshot_is_read_only(self) -> None:
        a = register_json("a", DIGEST_A)
        b = register_json("b", DIGEST_B)
        add_dependency(a, b)

        call("GET", "/graph")
        call("GET", "/graph", query_string=f"focus={a}")

        _s, _h, body = call_json("GET", "/graph")
        self.assertEqual(len(body["nodes"]), 2)
        self.assertEqual(len(body["edges"]), 1)
        _s, _h, listing = call_json("GET", "/resources")
        self.assertEqual(len(listing["resources"]), 2)


class GraphFocusTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def _diamond(self) -> tuple[str, str, str, str]:
        # a -> b -> d ; a -> c -> d ; c -> b as well.
        a = register_json("a", DIGEST_A)
        b = register_json("b", DIGEST_B)
        c = register_json("c", DIGEST_C)
        d = register_json("d", DIGEST_D)
        add_dependency(a, b)
        add_dependency(a, c)
        add_dependency(b, d)
        add_dependency(c, d)
        add_dependency(c, b)
        return a, b, c, d

    def test_focus_includes_self_and_direct_neighbors_only(self) -> None:
        a, b, c, d = self._diamond()

        _s, _h, body = call_json("GET", "/graph", query_string=f"focus={c}")

        # Only the focus node is returned, never the neighbor records.
        self.assertEqual([n["id"] for n in body["nodes"]], [c])
        self.assertEqual(
            list(body["nodes"][0]), ["id", "name", "category", "digest"]
        )

        edges = [
            (str(e["resource_id"]), str(e["dependency_id"]))
            for e in body["edges"]
        ]
        # Direct outgoing (establishment order) then direct incoming.
        # Indirectly reachable d and the edge a->b are excluded; edges among
        # neighbors (b->d) never appear either.
        self.assertEqual(edges, [(c, d), (c, b), (a, c)])

    def test_focus_incoming_edges_keep_global_edge_order(self) -> None:
        a, b, c, d = self._diamond()

        _s, _h, body = call_json("GET", "/graph", query_string=f"focus={d}")
        self.assertEqual([n["id"] for n in body["nodes"]], [d])
        edges = [
            (str(e["resource_id"]), str(e["dependency_id"]))
            for e in body["edges"]
        ]
        # d has no outgoing edges; inbound edges arrive in global order:
        # b is registered before c, so b->d precedes c->d.
        self.assertEqual(edges, [(b, d), (c, d)])

    def test_focus_on_isolated_resource(self) -> None:
        a = register_json("a", DIGEST_A)
        _other = register_json("b", DIGEST_B)

        _s, _h, body = call_json("GET", "/graph", query_string=f"focus={a}")
        self.assertEqual(
            body,
            {
                "nodes": [
                    {"id": a, "name": "a", "category": "code", "digest": DIGEST_A}
                ],
                "edges": [],
            },
        )

    def test_focus_response_is_newline_terminated_compact(self) -> None:
        a = register_json("a", DIGEST_A)
        _s, _h, raw = call("GET", "/graph", query_string=f"focus={a}")
        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(b" ", raw[:-1])

    def test_focus_unknown_resource_is_not_found(self) -> None:
        register_json("a", DIGEST_A)
        status, _h, body = call_json(
            "GET", "/graph", query_string="focus=does-not-exist"
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

    def test_focus_404_does_not_change_state(self) -> None:
        a = register_json("a", DIGEST_A)
        call_json("GET", "/graph", query_string="focus=missing")
        _s, _h, body = call_json("GET", "/graph")
        self.assertEqual([n["id"] for n in body["nodes"]], [a])


class GraphResolvedEdgeTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def test_cross_repository_edge_appears_in_snapshot_and_neighborhood(
        self,
    ) -> None:
        local = register_json("local-a", "b" * 64)
        remote = add_cross_reference(local)

        _s, _h, body = call_json("GET", "/graph")
        ids = [n["id"] for n in body["nodes"]]
        self.assertEqual(ids, [local, remote])
        self.assertEqual(body["nodes"][1]["digest"], DIGEST_REMOTE)
        edges = [
            (str(e["resource_id"]), str(e["dependency_id"]))
            for e in body["edges"]
        ]
        self.assertEqual(edges, [(local, remote)])

        _s, _h, local_view = call_json(
            "GET", "/graph", query_string=f"focus={local}"
        )
        self.assertEqual([n["id"] for n in local_view["nodes"]], [local])
        self.assertEqual(
            [
                (str(e["resource_id"]), str(e["dependency_id"]))
                for e in local_view["edges"]
            ],
            [(local, remote)],
        )

        _s, _h, remote_view = call_json(
            "GET", "/graph", query_string=f"focus={remote}"
        )
        self.assertEqual([n["id"] for n in remote_view["nodes"]], [remote])
        self.assertEqual(
            [
                (str(e["resource_id"]), str(e["dependency_id"]))
                for e in remote_view["edges"]
            ],
            [(local, remote)],
        )


class GraphErrorTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.resource_id = register_json("a", DIGEST_A)

    def test_non_get_method_returns_405_with_allow_get(self) -> None:
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, headers, body = call_json(method, "/graph")
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")
                self.assertIn(("Allow", "GET"), headers)

    def test_empty_focus_is_bad_request(self) -> None:
        status, _h, body = call_json("GET", "/graph", query_string="focus=")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_focus_with_path_separator_is_bad_request(self) -> None:
        for query in ("focus=a/b", "focus=a%5Cb"):
            with self.subTest(query=query):
                status, _h, body = call_json(
                    "GET", "/graph", query_string=query
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_unknown_query_parameter_is_bad_request(self) -> None:
        for query in ("bogus=1", "focus=" + self.resource_id + "&bogus=1"):
            with self.subTest(query=query):
                status, _h, body = call_json(
                    "GET", "/graph", query_string=query
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_repeated_focus_is_bad_request(self) -> None:
        status, _h, body = call_json(
            "GET",
            "/graph",
            query_string="focus=x&focus=y",
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_non_empty_body_is_bad_request(self) -> None:
        status, _h, raw = call(
            "GET",
            "/graph",
            b"data",
            content_length="4",
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(
            json.loads(raw.decode("utf-8"))["error"], "invalid_request"
        )

    def test_malformed_content_length_is_bad_request(self) -> None:
        status, _h, body = call(
            "GET", "/graph", b"x", content_length="abc"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(
            json.loads(body.decode("utf-8"))["error"], "invalid_request"
        )

    def test_bad_requests_do_not_read_or_change_data(self) -> None:
        for query in ("focus=", "focus=a/b", "bogus=1", "focus=x&focus=y"):
            with self.subTest(query=query):
                call_json("GET", "/graph", query_string=query)
        call("GET", "/graph", b"data", content_length="4")

        _s, _h, body = call_json("GET", "/graph")
        self.assertEqual(len(body["nodes"]), 1)
        self.assertEqual(body["edges"], [])
        # The valid focus still resolves after the rejected requests.
        _s, _h, focused = call_json(
            "GET", "/graph", query_string="focus=" + self.resource_id
        )
        self.assertEqual(
            [n["id"] for n in focused["nodes"]], [self.resource_id]
        )


class GraphRecomputeTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def test_snapshot_recomputes_after_edge_deletion(self) -> None:
        a = register_json("a", DIGEST_A)
        b = register_json("b", DIGEST_B)
        c = register_json("c", DIGEST_C)
        add_dependency(a, b)
        add_dependency(a, c)
        add_dependency(b, c)

        status, _h, _body = call(
            "DELETE", f"/resources/{a}/dependencies/{b}"
        )
        self.assertEqual(status, "200 OK")

        _s, _h, body = call_json("GET", "/graph")
        self.assertEqual(
            [
                (str(e["resource_id"]), str(e["dependency_id"]))
                for e in body["edges"]
            ],
            [(a, c), (b, c)],
        )

        _s, _h, focus_a = call_json(
            "GET", "/graph", query_string=f"focus={a}"
        )
        self.assertEqual(
            [
                (str(e["resource_id"]), str(e["dependency_id"]))
                for e in focus_a["edges"]
            ],
            [(a, c)],
        )
        _s, _h, focus_b = call_json(
            "GET", "/graph", query_string=f"focus={b}"
        )
        self.assertEqual(
            [
                (str(e["resource_id"]), str(e["dependency_id"]))
                for e in focus_b["edges"]
            ],
            [(b, c)],
        )

    def test_snapshot_recomputes_after_resource_deregistration(self) -> None:
        a = register_json("a", DIGEST_A)
        b = register_json("b", DIGEST_B)
        c = register_json("c", DIGEST_C)
        add_dependency(a, b)
        add_dependency(b, c)
        add_dependency(a, c)

        status, _h, _body = call("DELETE", f"/resources/{b}")
        self.assertEqual(status, "200 OK")

        _s, _h, body = call_json("GET", "/graph")
        self.assertEqual([n["id"] for n in body["nodes"]], [a, c])
        self.assertEqual(
            [
                (str(e["resource_id"]), str(e["dependency_id"]))
                for e in body["edges"]
            ],
            [(a, c)],
        )

        _s, _h, focus_c = call_json(
            "GET", "/graph", query_string=f"focus={c}"
        )
        self.assertEqual([n["id"] for n in focus_c["nodes"]], [c])
        self.assertEqual(
            [
                (str(e["resource_id"]), str(e["dependency_id"]))
                for e in focus_c["edges"]
            ],
            [(a, c)],
        )

    def test_deleting_referencing_resource_keeps_resolved_node_drops_edge(
        self,
    ) -> None:
        local = register_json("local-a", "b" * 64)
        remote = add_cross_reference(local)

        status, _h, _body = call("DELETE", f"/resources/{local}")
        self.assertEqual(status, "200 OK")

        _s, _h, body = call_json("GET", "/graph")
        self.assertEqual([n["id"] for n in body["nodes"]], [remote])
        self.assertEqual(body["edges"], [])


if __name__ == "__main__":
    unittest.main()
