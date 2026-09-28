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

SUMMARY_PATH = "/dependency-closure-summary"
FIELD_ORDER = ["id", "direct_count", "closure_count", "max_chain"]


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
) -> tuple[str, list[tuple[str, str]], object]:
    status, headers, raw = call(method, path, body, **kwargs)  # type: ignore[arg-type]
    return status, headers, json.loads(raw.decode("utf-8"))


class DependencyClosureSummaryTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def _create(self, name: str, digest: str) -> str:
        status, _h, body = call_json(
            "POST",
            "/resources",
            {"name": name, "category": "code", "digest": digest},
        )
        self.assertEqual(status, "201 Created")
        return str(body["id"])  # type: ignore[index]

    def _add(self, resource_id: str, dependency_id: str) -> None:
        status, _h, _b = call_json(
            "POST",
            f"/resources/{resource_id}/dependencies",
            {"dependency_id": dependency_id},
        )
        self.assertEqual(status, "201 Created")

    def _summary(self, **kwargs: object):
        return call("GET", SUMMARY_PATH, **kwargs)

    def _entries(self) -> dict[str, dict[str, object]]:
        status, _h, body = call_json("GET", SUMMARY_PATH)
        self.assertEqual(status, "200 OK")
        assert isinstance(body, list)
        return {str(entry["id"]): entry for entry in body}  # type: ignore[index]

    # --- Empty registry ------------------------------------------------------

    def test_empty_registry_is_empty_array_with_newline(self) -> None:
        status, headers, raw = self._summary()
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            headers[0], ("Content-Type", "application/json; charset=utf-8")
        )
        self.assertEqual(raw, b"[]\n")

    # --- Entry and key order -------------------------------------------------

    def test_entries_follow_registration_order_and_key_order_fixed(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        self._add(a, b)

        status, _h, body = call_json("GET", SUMMARY_PATH)
        self.assertEqual(status, "200 OK")
        assert isinstance(body, list)
        self.assertEqual([entry["id"] for entry in body], [a, b, c])  # type: ignore[index]
        for entry in body:
            self.assertEqual(list(entry), FIELD_ORDER)  # type: ignore[arg-type]

    def test_resources_without_dependencies_are_included(self) -> None:
        a = self._create("a", DIGEST_A)
        body = self._entries()
        self.assertEqual(
            body[a],
            {"id": a, "direct_count": 0, "closure_count": 0, "max_chain": 1},
        )

    # --- Count semantics ------------------------------------------------------

    def test_direct_closure_and_chain_counts(self) -> None:
        # a -> b -> c -> d ; a -> c ; b and c share d through the chain;
        # e is registered afterwards and stays isolated.
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        d = self._create("d", DIGEST_D)
        e = self._create("e", DIGEST_E)
        self._add(a, b)
        self._add(a, c)
        self._add(b, c)
        self._add(c, d)

        body = self._entries()
        self.assertEqual(body[a]["direct_count"], 2)
        self.assertEqual(body[a]["closure_count"], 3)  # b, c, d
        self.assertEqual(body[a]["max_chain"], 4)  # a -> b -> c -> d
        self.assertEqual(body[b]["direct_count"], 1)
        self.assertEqual(body[b]["closure_count"], 2)  # c, d
        self.assertEqual(body[b]["max_chain"], 3)
        self.assertEqual(body[c]["direct_count"], 1)
        self.assertEqual(body[c]["closure_count"], 1)  # d
        self.assertEqual(body[c]["max_chain"], 2)
        self.assertEqual(
            body[d],
            {"id": d, "direct_count": 0, "closure_count": 0, "max_chain": 1},
        )
        self.assertEqual(
            body[e],
            {"id": e, "direct_count": 0, "closure_count": 0, "max_chain": 1},
        )

    def test_max_chain_takes_longest_branch_in_diamond(self) -> None:
        # a -> d directly is 2 nodes; a -> b -> d and a -> c -> d are 3;
        # the longer b -> e -> d branch reaches 4 nodes.
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        d = self._create("d", DIGEST_D)
        e = self._create("e", DIGEST_E)
        self._add(a, b)
        self._add(a, c)
        self._add(a, d)
        self._add(b, e)
        self._add(e, d)
        self._add(c, d)

        body = self._entries()
        self.assertEqual(body[a]["direct_count"], 3)
        self.assertEqual(body[a]["closure_count"], 4)  # b, c, d, e
        self.assertEqual(body[a]["max_chain"], 4)  # a -> b -> e -> d

    def test_closure_deduplicates_diamond_dependencies(self) -> None:
        # d is reachable from a directly and through b and c, but counts
        # only once; b and c reachable once each.
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        d = self._create("d", DIGEST_D)
        self._add(a, b)
        self._add(a, c)
        self._add(a, d)
        self._add(b, d)
        self._add(c, d)

        body = self._entries()
        self.assertEqual(body[a]["direct_count"], 3)
        self.assertEqual(body[a]["closure_count"], 3)
        self.assertEqual(body[a]["max_chain"], 3)

    def test_long_chain_does_not_blow_the_stack(self) -> None:
        ids = [
            self._create(f"r{index:04d}", f"{index:064x}") for index in range(400)
        ]
        for earlier, later in zip(ids, ids[1:]):
            self._add(earlier, later)

        body = self._entries()
        self.assertEqual(body[ids[0]]["max_chain"], 400)
        self.assertEqual(body[ids[0]]["closure_count"], 399)
        self.assertEqual(body[ids[-1]]["max_chain"], 1)

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
        assert isinstance(listing, dict)
        remote = next(
            r["id"] for r in listing["resources"] if r["id"] != local
        )

        body = self._entries()
        self.assertEqual(body[local]["direct_count"], 1)
        self.assertEqual(body[local]["closure_count"], 1)
        self.assertEqual(body[local]["max_chain"], 2)
        self.assertEqual(body[remote]["direct_count"], 0)
        self.assertEqual(body[remote]["closure_count"], 0)
        self.assertEqual(body[remote]["max_chain"], 1)

    # --- Recomputation and read-only behavior --------------------------------

    def test_summary_recomputes_after_dependency_delete(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        self._add(a, b)
        self._add(a, c)
        self._add(b, c)

        status, _h, _b = call("DELETE", f"/resources/{a}/dependencies/{b}")
        self.assertEqual(status, "200 OK")

        body = self._entries()
        # The direct edge is gone and b is no longer reachable from a;
        # c survives as a direct dependency of a.
        self.assertEqual(body[a]["direct_count"], 1)
        self.assertEqual(body[a]["closure_count"], 1)
        self.assertEqual(body[a]["max_chain"], 2)
        self.assertEqual(body[b]["direct_count"], 1)
        self.assertEqual(body[b]["closure_count"], 1)

    def test_summary_recomputes_after_resource_delete(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        self._add(a, b)
        self._add(c, b)

        status, _h, _b = call("DELETE", f"/resources/{b}")
        self.assertEqual(status, "200 OK")

        body = self._entries()
        self.assertEqual(set(body), {a, c})
        self.assertEqual(body[a]["direct_count"], 0)
        self.assertEqual(body[a]["closure_count"], 0)
        self.assertEqual(body[a]["max_chain"], 1)
        self.assertEqual(body[c]["direct_count"], 0)
        self.assertEqual(body[c]["max_chain"], 1)

    def test_summary_is_read_only(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        self._add(a, b)

        call_json("GET", SUMMARY_PATH)
        call_json("GET", SUMMARY_PATH)

        _s, _h, graph = call_json("GET", "/graph")
        assert isinstance(graph, dict)
        self.assertEqual(len(graph["nodes"]), 2)
        self.assertEqual(len(graph["edges"]), 1)
        body = self._entries()
        self.assertEqual(body[a]["closure_count"], 1)
        self.assertEqual(body[b]["max_chain"], 1)

    # --- Validation -----------------------------------------------------------

    def test_query_parameters_are_bad_request(self) -> None:
        self._create("a", DIGEST_A)
        for query_string in ("bogus=1", "x=", "=", "x=1&y=2", "x=1&x=2"):
            with self.subTest(query_string=query_string):
                status, _h, body = call_json(
                    "GET", SUMMARY_PATH, query_string=query_string
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")  # type: ignore[index]

    def test_declared_non_empty_body_is_bad_request(self) -> None:
        self._create("a", DIGEST_A)
        status, _h, body = call_json("GET", SUMMARY_PATH, b"{}")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")  # type: ignore[index]

        # The rejected request changed nothing: the lone resource still
        # reports its isolated entry.
        entries = self._entries()
        self.assertEqual(len(entries), 1)
        self.assertEqual(next(iter(entries.values()))["direct_count"], 0)

    def test_malformed_content_length_is_bad_request(self) -> None:
        status, _h, body = call_json(
            "GET", SUMMARY_PATH, content_length="abc"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")  # type: ignore[index]

    def test_omitted_length_is_treated_as_empty_body(self) -> None:
        self._create("a", DIGEST_A)
        status, _h, raw = self._summary(omit_content_length=True)
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(json.loads(raw)), 1)

    def test_explicit_zero_length_body_is_accepted(self) -> None:
        status, _h, raw = self._summary(body=b"")
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

    # --- Method handling ------------------------------------------------------

    def test_other_methods_return_405_with_allow_get(self) -> None:
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, headers, body = call_json(method, SUMMARY_PATH)
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")  # type: ignore[index]
                self.assertEqual(
                    [value for name, value in headers if name == "Allow"],
                    ["GET"],
                )

    def test_summary_subpath_is_not_the_summary_view(self) -> None:
        status, _h, body = call_json("GET", f"{SUMMARY_PATH}/anything")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "not_found")  # type: ignore[index]


if __name__ == "__main__":
    unittest.main()
