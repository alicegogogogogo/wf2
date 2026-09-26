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

    def test_empty_graph_reports_zeros_and_empty_collections(self) -> None:
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

    # --- Counts and isolated set ---------------------------------------------

    def test_counts_and_isolated_follow_registration_order(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        d = self._create("d", DIGEST_D)
        self._add(a, b)

        _s, _h, body = call_json("GET", "/graph/stats")
        self.assertEqual(body["nodes"], 4)
        self.assertEqual(body["edges"], 1)
        self.assertEqual(body["isolated"], [c, d])
        self.assertEqual(
            list(body),
            ["nodes", "edges", "isolated",
             "out_degree", "in_degree", "max_depth"],
        )

    def test_all_isolated_when_no_edges(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)

        _s, _h, body = call_json("GET", "/graph/stats")
        self.assertEqual(body["isolated"], [a, b])
        self.assertEqual(body["out_degree"], [])
        self.assertEqual(body["in_degree"], [])
        self.assertEqual(body["max_depth"], 1)

    # --- Degree rankings -------------------------------------------------------

    def test_rankings_sort_by_degree_then_registration_order(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        d = self._create("d", DIGEST_D)
        e = self._create("e", DIGEST_E)
        # a and c both have out-degree 2; a was registered first.
        self._add(a, d)
        self._add(a, e)
        self._add(c, d)
        self._add(c, e)
        self._add(b, d)

        _s, _h, body = call_json("GET", "/graph/stats")
        self.assertEqual(
            body["out_degree"],
            [
                {"resource_id": a, "degree": 2},
                {"resource_id": c, "degree": 2},
                {"resource_id": b, "degree": 1},
            ],
        )
        self.assertEqual(
            body["in_degree"],
            [
                {"resource_id": d, "degree": 3},
                {"resource_id": e, "degree": 2},
            ],
        )
        for entry in body["out_degree"] + body["in_degree"]:
            self.assertEqual(list(entry), ["resource_id", "degree"])

    def test_zero_degree_resources_are_excluded_from_rankings(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        self._create("c", DIGEST_C)
        self._add(a, b)

        _s, _h, body = call_json("GET", "/graph/stats")
        self.assertEqual(
            body["out_degree"], [{"resource_id": a, "degree": 1}]
        )
        self.assertEqual(
            body["in_degree"], [{"resource_id": b, "degree": 1}]
        )

    # --- Max depth -------------------------------------------------------------

    def test_max_depth_counts_nodes_on_longest_chain(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        d = self._create("d", DIGEST_D)
        self._add(a, b)
        self._add(b, c)
        self._add(a, d)

        _s, _h, body = call_json("GET", "/graph/stats")
        self.assertEqual(body["max_depth"], 3)

    def test_max_depth_uses_longest_chain_not_longest_branch_sum(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        d = self._create("d", DIGEST_D)
        e = self._create("e", DIGEST_E)
        # Diamond: a -> b -> d and a -> c -> d, plus d -> e.
        self._add(a, b)
        self._add(a, c)
        self._add(b, d)
        self._add(c, d)
        self._add(d, e)

        _s, _h, body = call_json("GET", "/graph/stats")
        self.assertEqual(body["max_depth"], 4)

    # --- Cross-reference edges ---------------------------------------------------

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
        self.assertEqual(
            body["out_degree"], [{"resource_id": local, "degree": 1}]
        )
        self.assertEqual(
            body["in_degree"], [{"resource_id": remote, "degree": 1}]
        )
        self.assertEqual(body["max_depth"], 2)

    # --- Recomputation after mutation --------------------------------------------

    def test_stats_recompute_after_dependency_delete(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        self._add(a, b)

        status, _h, _b = call_json("DELETE", f"/resources/{a}/dependencies/{b}")
        self.assertEqual(status, "200 OK")

        _s, _h, body = call_json("GET", "/graph/stats")
        self.assertEqual(body["edges"], 0)
        self.assertEqual(body["isolated"], [a, b])
        self.assertEqual(body["out_degree"], [])
        self.assertEqual(body["in_degree"], [])
        self.assertEqual(body["max_depth"], 1)

    def test_stats_recompute_after_resource_delete(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        self._add(a, b)
        self._add(b, c)

        status, _h, _b = call_json("DELETE", f"/resources/{b}")
        self.assertEqual(status, "200 OK")

        _s, _h, body = call_json("GET", "/graph/stats")
        self.assertEqual(body["nodes"], 2)
        self.assertEqual(body["edges"], 0)
        self.assertEqual(body["isolated"], [a, c])
        self.assertEqual(body["max_depth"], 1)

    # --- Response shape ------------------------------------------------------------

    def test_response_is_compact_utf8_and_newline_terminated(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        self._add(a, b)

        status, _h, raw = self._stats()
        self.assertEqual(status, "200 OK")
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        self.assertNotIn(b" ", raw[:-1])
        self.assertEqual(
            raw,
            b'{"nodes":2,"edges":1,"isolated":[],'
            b'"out_degree":[{"resource_id":"' + a.encode() + b'","degree":1}],'
            b'"in_degree":[{"resource_id":"' + b.encode() + b'","degree":1}],'
            b'"max_depth":2}\n',
        )

    # --- Errors ---------------------------------------------------------------------

    def test_non_get_methods_are_rejected_with_allow_get(self) -> None:
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            status, headers, body = call_json(method, "/graph/stats")
            self.assertEqual(status, "405 Method Not Allowed")
            self.assertEqual(body["error"], "method_not_allowed")
            self.assertIn(("Allow", "GET"), headers)

    def test_declared_body_is_rejected(self) -> None:
        status, _h, body = call_json(
            "GET", "/graph/stats", b"{}", content_length=2
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_malformed_content_length_is_rejected(self) -> None:
        status, _h, body = call_json(
            "GET", "/graph/stats", content_length="abc"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_query_parameters_are_rejected(self) -> None:
        status, _h, body = call_json(
            "GET", "/graph/stats", query_string="focus=x"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_zero_content_length_and_omitted_header_are_accepted(self) -> None:
        status, _h, _b = self._stats(content_length=0)
        self.assertEqual(status, "200 OK")
        status, _h, _b = self._stats(omit_content_length=True)
        self.assertEqual(status, "200 OK")

    def test_rejected_requests_do_not_consume_state(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        self._add(a, b)

        call_json("GET", "/graph/stats", b"x", content_length=1)
        call_json("POST", "/graph/stats")

        _s, _h, body = call_json("GET", "/graph/stats")
        self.assertEqual(body["nodes"], 2)
        self.assertEqual(body["edges"], 1)


if __name__ == "__main__":
    unittest.main()
