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
DIGEST_G = "01" * 32
DIGEST_REMOTE = "0f" * 32

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


class GraphPathAllTests(unittest.TestCase):
    PATH = "/graph/path/all"

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

    def _all(
        self, from_id: str, to_id: str, extra: str = ""
    ) -> tuple[str, list[tuple[str, str]], dict[str, object]]:
        query_string = f"from={from_id}&to={to_id}"
        if extra:
            query_string = f"{query_string}&{extra}"
        return call_json("GET", self.PATH, query_string=query_string)

    # --- Successful queries ---------------------------------------------------

    def test_direct_edge_is_single_path(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        self._add(a, b)

        status, headers, raw = call(
            "GET", self.PATH, query_string=f"from={a}&to={b}"
        )
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
            "GET", self.PATH, query_string=f"from={a}&to={b}"
        )
        self.assertEqual(list(body), ["from", "to", "found", "paths", "count"])

    def test_all_equally_short_paths_are_enumerated(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        d = self._create("d", DIGEST_D)
        # Edges to c are registered first to prove edge order never decides
        # the result ordering: b was registered before c.
        self._add(a, c)
        self._add(a, b)
        self._add(c, d)
        self._add(b, d)

        _s, _h, body = self._all(a, d)
        self.assertEqual(body["found"], True)
        self.assertEqual(body["paths"], [[a, b, d], [a, c, d]])
        self.assertEqual(body["count"], 2)

    def test_ordering_applies_to_every_node(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        d = self._create("d", DIGEST_D)
        e = self._create("e", DIGEST_E)
        f = self._create("f", DIGEST_F)
        # Four equally long paths a -> {b,c} -> {e,f} -> d. Nodes are
        # created b, c, e, f in that registration order; edges to the
        # later-registered node are added first where possible.
        self._add(a, c)
        self._add(a, b)
        self._add(c, f)
        self._add(c, e)
        self._add(b, f)
        self._add(b, e)
        self._add(f, d)
        self._add(e, d)

        _s, _h, body = self._all(a, d)
        self.assertEqual(
            body["paths"],
            [
                [a, b, e, d],
                [a, b, f, d],
                [a, c, e, d],
                [a, c, f, d],
            ],
        )
        self.assertEqual(body["count"], 4)

    def test_third_node_tie_uses_registration_order_not_edge_order(self) -> None:
        a = self._create("a", DIGEST_A)
        x = self._create("x", DIGEST_G)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        d = self._create("d", DIGEST_D)
        self._add(a, x)
        # Edge to the later-registered c first; b must still win.
        self._add(x, c)
        self._add(x, b)
        self._add(b, d)
        self._add(c, d)

        _s, _h, body = self._all(a, d)
        self.assertEqual(body["paths"], [[a, x, b, d], [a, x, c, d]])

    def test_longer_paths_are_never_included(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        d = self._create("d", DIGEST_D)
        # a reaches d directly and through b and c; only the direct edge is
        # shortest.
        self._add(a, b)
        self._add(b, c)
        self._add(c, d)
        self._add(a, d)

        _s, _h, body = self._all(a, d)
        self.assertEqual(body["paths"], [[a, d]])
        self.assertEqual(body["count"], 1)

    def test_reverse_direction_has_no_paths(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        self._add(a, b)
        self._add(b, c)

        _s, _h, body = self._all(c, a)
        self.assertEqual(body["found"], False)
        self.assertEqual(body["paths"], [])
        self.assertEqual(body["count"], 0)

    def test_same_resource_is_one_single_node_path(self) -> None:
        a = self._create("a", DIGEST_A)
        _s, _h, body = self._all(a, a)
        self.assertEqual(body["found"], True)
        self.assertEqual(body["paths"], [[a]])
        self.assertEqual(body["count"], 1)

    def test_unreachable_target_is_a_successful_empty_result(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        status, _h, body = self._all(a, b)
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["found"], False)
        self.assertEqual(body["paths"], [])
        self.assertEqual(body["count"], 0)

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

        _s, _h, body = self._all(local, remote)
        self.assertEqual(body["found"], True)
        self.assertEqual(body["paths"], [[local, remote]])
        self.assertEqual(body["count"], 1)

    # --- limit ----------------------------------------------------------------

    def test_limit_takes_the_first_paths_of_the_stable_order(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        d = self._create("d", DIGEST_D)
        e = self._create("e", DIGEST_E)
        f = self._create("f", DIGEST_F)
        self._add(a, b)
        self._add(a, c)
        self._add(b, e)
        self._add(b, f)
        self._add(c, e)
        self._add(c, f)
        self._add(e, d)
        self._add(f, d)

        _s, _h, body = self._all(a, d, extra="limit=2")
        self.assertEqual(
            body["paths"], [[a, b, e, d], [a, b, f, d]]
        )
        self.assertEqual(body["count"], 2)

    def test_limit_one(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        d = self._create("d", DIGEST_D)
        self._add(a, c)
        self._add(a, b)
        self._add(b, d)
        self._add(c, d)

        _s, _h, body = self._all(a, d, extra="limit=1")
        self.assertEqual(body["paths"], [[a, b, d]])
        self.assertEqual(body["count"], 1)

    def test_limit_equal_to_and_above_total_returns_everything(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        d = self._create("d", DIGEST_D)
        self._add(a, b)
        self._add(a, c)
        self._add(b, d)
        self._add(c, d)

        for limit in ("2", "100"):
            with self.subTest(limit=limit):
                _s, _h, body = self._all(a, d, extra=f"limit={limit}")
                self.assertEqual(body["paths"], [[a, b, d], [a, c, d]])
                self.assertEqual(body["count"], 2)

    def test_limit_on_unreachable_target_stays_empty(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        _s, _h, body = self._all(a, b, extra="limit=1")
        self.assertEqual(body["found"], False)
        self.assertEqual(body["paths"], [])
        self.assertEqual(body["count"], 0)

    def test_limit_on_same_resource(self) -> None:
        a = self._create("a", DIGEST_A)
        _s, _h, body = self._all(a, a, extra="limit=1")
        self.assertEqual(body["paths"], [[a]])
        self.assertEqual(body["count"], 1)

    # --- Recomputation and read-only behavior ---------------------------------

    def test_enumeration_recomputes_after_dependency_changes(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        d = self._create("d", DIGEST_D)
        self._add(a, b)
        self._add(a, c)
        self._add(b, d)
        self._add(c, d)

        status, _h, _b = call_json(
            "DELETE", f"/resources/{a}/dependencies/{b}"
        )
        self.assertEqual(status, "200 OK")

        _s, _h, body = self._all(a, d)
        self.assertEqual(body["paths"], [[a, c, d]])

        # Re-registering the edge restores both paths immediately.
        self._add(a, b)
        _s, _h, body = self._all(a, d)
        self.assertEqual(body["paths"], [[a, b, d], [a, c, d]])
        self.assertEqual(body["count"], 2)

    def test_enumeration_recomputes_after_resource_delete(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        d = self._create("d", DIGEST_D)
        self._add(a, b)
        self._add(a, c)
        self._add(b, d)
        self._add(c, d)

        status, _h, _b = call_json("DELETE", f"/resources/{b}")
        self.assertEqual(status, "200 OK")

        _s, _h, body = self._all(a, d)
        self.assertEqual(body["paths"], [[a, c, d]])

        # The deregistered middle resource is gone for good.
        status, _h, body = self._all(a, b)
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

    def test_query_is_read_only(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        d = self._create("d", DIGEST_D)
        self._add(a, b)
        self._add(a, c)
        self._add(b, d)
        self._add(c, d)

        self._all(a, d)
        self._all(a, d, extra="limit=1")

        _s, _h, graph = call_json("GET", "/graph")
        self.assertEqual(len(graph["nodes"]), 4)
        self.assertEqual(len(graph["edges"]), 4)
        _s, _h, stats = call_json("GET", "/graph/stats")
        self.assertEqual(stats["nodes"], 4)
        self.assertEqual(stats["edges"], 4)

    # --- Validation -------------------------------------------------------------

    def test_missing_either_parameter_is_bad_request(self) -> None:
        a = self._create("a", DIGEST_A)
        for query_string in ("", f"from={a}", f"to={a}", "limit=3"):
            with self.subTest(query_string=query_string):
                status, _h, body = call_json(
                    "GET", self.PATH, query_string=query_string
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_repeated_parameter_is_bad_request(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        for query_string in (
            f"from={a}&from={a}&to={b}",
            f"from={a}&to={b}&to={b}",
            f"from={a}&to={b}&limit=1&limit=2",
        ):
            with self.subTest(query_string=query_string):
                status, _h, body = call_json(
                    "GET", self.PATH, query_string=query_string
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_unknown_parameter_is_bad_request(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        status, _h, body = call_json(
            "GET",
            self.PATH,
            query_string=f"from={a}&to={b}&focus={a}",
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_empty_value_is_bad_request(self) -> None:
        a = self._create("a", DIGEST_A)
        for query_string in (
            f"from=&to={a}",
            f"from={a}&to=",
            f"from={a}&to={a}&limit=",
        ):
            with self.subTest(query_string=query_string):
                status, _h, body = call_json(
                    "GET", self.PATH, query_string=query_string
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
                    "GET", self.PATH, query_string=query_string
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_invalid_limit_is_bad_request(self) -> None:
        a = self._create("a", DIGEST_A)
        for raw_limit in ("0", "01", "101", "-1", "1.5", "3  ", "abc", "2%20"):
            with self.subTest(limit=raw_limit):
                status, _h, body = call_json(
                    "GET",
                    self.PATH,
                    query_string=f"from={a}&to={a}&limit={raw_limit}",
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_boundary_limits_are_accepted(self) -> None:
        a = self._create("a", DIGEST_A)
        for raw_limit in ("1", "100"):
            with self.subTest(limit=raw_limit):
                status, _h, _body = call_json(
                    "GET",
                    self.PATH,
                    query_string=f"from={a}&to={a}&limit={raw_limit}",
                )
                self.assertEqual(status, "200 OK")

    def test_bad_requests_do_not_read_or_change_state(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        self._add(a, b)

        call_json("GET", self.PATH, query_string="bogus=1")
        call_json(
            "GET",
            self.PATH,
            query_string=f"from={a}&to={b}&limit=0",
        )

        _s, _h, body = self._all(a, b)
        self.assertEqual(body["found"], True)
        self.assertEqual(body["paths"], [[a, b]])

    def test_unknown_resource_returns_404(self) -> None:
        a = self._create("a", DIGEST_A)
        missing = "0" * 32
        for query_string in (
            f"from={missing}&to={a}",
            f"from={a}&to={missing}",
            f"from={missing}&to={missing}",
        ):
            with self.subTest(query_string=query_string):
                status, _h, body = call_json(
                    "GET", self.PATH, query_string=query_string
                )
                self.assertEqual(status, "404 Not Found")
                self.assertEqual(body["error"], "resource_not_found")

    def test_declared_non_empty_body_is_bad_request(self) -> None:
        a = self._create("a", DIGEST_A)
        status, _h, raw = call(
            "GET",
            self.PATH,
            b"{}",
            query_string=f"from={a}&to={a}",
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(json.loads(raw)["error"], "invalid_request")

    def test_malformed_content_length_is_bad_request(self) -> None:
        a = self._create("a", DIGEST_A)
        status, _h, raw = call(
            "GET",
            self.PATH,
            query_string=f"from={a}&to={a}",
            content_length="abc",
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(json.loads(raw)["error"], "invalid_request")

    def test_explicit_zero_length_body_is_accepted(self) -> None:
        a = self._create("a", DIGEST_A)
        status, _h, raw = call(
            "GET", self.PATH, b"", query_string=f"from={a}&to={a}"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(json.loads(raw)["found"], True)

    # --- Method handling --------------------------------------------------------

    def test_other_methods_return_405_with_allow_get(self) -> None:
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, headers, body = call_json(method, self.PATH)
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")
                self.assertEqual(
                    [value for name, value in headers if name == "Allow"],
                    ["GET"],
                )

    def test_subpath_is_not_the_all_paths_view(self) -> None:
        status, _h, body = call_json("GET", "/graph/path/all/anything")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "not_found")


if __name__ == "__main__":
    unittest.main()
