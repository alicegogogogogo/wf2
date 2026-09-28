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

PATH = "/dependency-usage"


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


class DependencyUsageTests(unittest.TestCase):
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

    def _usage(self, **kwargs: object):
        return call("GET", PATH, **kwargs)

    def _usage_json(self, body: object = None, **kwargs: object):
        status, headers, parsed = call_json("GET", PATH, body, **kwargs)
        return status, headers, parsed

    # --- Empty graph ---------------------------------------------------------

    def test_empty_graph_is_empty_array_success(self) -> None:
        status, headers, raw = self._usage()
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            headers[0], ("Content-Type", "application/json; charset=utf-8")
        )
        self.assertEqual(raw, b"[]\n")

    # --- Entry shape and ordering -------------------------------------------

    def test_only_depended_on_resources_get_entries_in_registration_order(
        self,
    ) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        self._add(a, b)

        _s, _h, body = self._usage_json()
        # b is depended on; a (only a dependent) and c (isolated) are not.
        self.assertEqual([entry["id"] for entry in body], [b])  # type: ignore[index]

    def test_entry_key_order_is_fixed(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        self._add(a, b)
        _s, _h, body = self._usage_json()
        for entry in body:  # type: ignore[union-attr]
            self.assertEqual(
                list(entry),
                ["id", "dependents", "dependent_count", "max_dependent_chain"],
            )

    def test_directly_depended_on_resource(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        self._add(a, b)

        _s, _h, body = self._usage_json()
        self.assertEqual(
            body,  # type: ignore[arg-type]
            [
                {
                    "id": b,
                    "dependents": [a],
                    "dependent_count": 1,
                    "max_dependent_chain": 2,
                }
            ],
        )

    # --- Dependents, counts and longest chain --------------------------------

    def test_chain_unfolds_transitive_dependents_in_registration_order(self) -> None:
        # a -> b -> c -> d
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        d = self._create("d", DIGEST_D)
        self._add(a, b)
        self._add(b, c)
        self._add(c, d)

        _s, _h, body = self._usage_json()
        self.assertEqual(
            body,  # type: ignore[arg-type]
            [
                {
                    "id": b,
                    "dependents": [a],
                    "dependent_count": 1,
                    "max_dependent_chain": 2,
                },
                {
                    "id": c,
                    "dependents": [a, b],
                    "dependent_count": 2,
                    "max_dependent_chain": 3,
                },
                {
                    "id": d,
                    "dependents": [a, b, c],
                    "dependent_count": 3,
                    "max_dependent_chain": 4,
                },
            ],
        )

    def test_dependents_follow_registration_order_not_edge_order(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        # Establish the edge from the later-registered dependent first.
        self._add(c, a)
        self._add(b, a)

        _s, _h, body = self._usage_json()
        self.assertEqual(
            body,  # type: ignore[arg-type]
            [
                {
                    "id": a,
                    "dependents": [b, c],
                    "dependent_count": 2,
                    "max_dependent_chain": 2,
                }
            ],
        )

    def test_longest_of_multiple_paths_from_same_dependent_wins(self) -> None:
        # a reaches d directly (2 nodes) and through b/c (3 nodes); the
        # longest path scores three.
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        d = self._create("d", DIGEST_D)
        self._add(a, b)
        self._add(a, c)
        self._add(b, d)
        self._add(c, d)
        self._add(a, d)

        _s, _h, body = self._usage_json()
        entries = {entry["id"]: entry for entry in body}  # type: ignore[union-attr]
        self.assertEqual(entries[d]["dependents"], [a, b, c])
        self.assertEqual(entries[d]["dependent_count"], 3)
        self.assertEqual(entries[d]["max_dependent_chain"], 3)
        self.assertEqual(entries[b]["max_dependent_chain"], 2)
        self.assertEqual(entries[c]["max_dependent_chain"], 2)

    def test_longest_chain_takes_longest_dependent_branch(self) -> None:
        # a -> b -> e (3 nodes) and a -> c -> d -> e (4 nodes).
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        d = self._create("d", DIGEST_D)
        e = self._create("e", DIGEST_E)
        self._add(a, b)
        self._add(b, e)
        self._add(a, c)
        self._add(c, d)
        self._add(d, e)

        _s, _h, body = self._usage_json()
        entries = {entry["id"]: entry for entry in body}  # type: ignore[union-attr]
        self.assertEqual(entries[e]["dependents"], [a, b, c, d])
        self.assertEqual(entries[e]["max_dependent_chain"], 4)

    # --- Edge provenance -----------------------------------------------------

    def test_cross_reference_edges_are_listed(self) -> None:
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
        remote = next(
            r["id"] for r in listing["resources"] if r["id"] != local  # type: ignore[index]
        )

        _s, _h, body = self._usage_json()
        self.assertEqual(
            body,  # type: ignore[arg-type]
            [
                {
                    "id": remote,
                    "dependents": [local],
                    "dependent_count": 1,
                    "max_dependent_chain": 2,
                }
            ],
        )

    # --- Recomputation and read-only behavior --------------------------------

    def test_recompute_after_dependency_delete(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        self._add(a, b)
        self._add(a, c)
        self._add(b, c)

        status, _h, _b = call("DELETE", f"/resources/{b}/dependencies/{c}")
        self.assertEqual(status, "200 OK")

        _s, _h, body = self._usage_json()
        entries = {entry["id"]: entry for entry in body}  # type: ignore[union-attr]
        # b is still depended on by a; c is now only depended on by a.
        self.assertEqual(entries[b]["dependents"], [a])
        self.assertEqual(entries[b]["max_dependent_chain"], 2)
        self.assertEqual(entries[c]["dependents"], [a])
        self.assertEqual(entries[c]["max_dependent_chain"], 2)

    def test_entry_disappears_when_last_edge_is_deleted(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        self._add(a, b)

        status, _h, _b = call("DELETE", f"/resources/{a}/dependencies/{b}")
        self.assertEqual(status, "200 OK")

        _s, _h, body = self._usage_json()
        self.assertEqual(body, [])  # type: ignore[arg-type]

    def test_recompute_after_resource_delete(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)
        self._add(a, b)
        self._add(b, c)

        status, _h, _b = call("DELETE", f"/resources/{a}")
        self.assertEqual(status, "200 OK")

        _s, _h, body = self._usage_json()
        # Only the edge b -> c survives.
        self.assertEqual(
            body,  # type: ignore[arg-type]
            [
                {
                    "id": c,
                    "dependents": [b],
                    "dependent_count": 1,
                    "max_dependent_chain": 2,
                }
            ],
        )

    def test_view_is_read_only(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        self._add(a, b)

        self._usage()
        self._usage()

        _s, _h, graph = call_json("GET", "/graph")
        self.assertEqual(len(graph["nodes"]), 2)  # type: ignore[index]
        self.assertEqual(len(graph["edges"]), 1)  # type: ignore[index]
        _s, _h, body = self._usage_json()
        self.assertEqual(len(body), 1)  # type: ignore[arg-type]

    # --- Response body -------------------------------------------------------

    def test_body_is_compact_json_with_single_trailing_newline(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        self._add(a, b)
        _s, _h, raw = self._usage()
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        self.assertEqual(
            raw,
            b'[{"id":"'
            + b.encode("ascii")
            + b'","dependents":["'
            + a.encode("ascii")
            + b'"],"dependent_count":1,"max_dependent_chain":2}]\n',
        )

    def test_no_persistence_files_created(self) -> None:
        import pathlib

        root = pathlib.Path(__file__).resolve().parents[1]
        before = {
            str(p.relative_to(root))
            for p in root.rglob("*")
            if ".git" not in p.parts and p.is_file()
        }
        self._usage()
        after = {
            str(p.relative_to(root))
            for p in root.rglob("*")
            if ".git" not in p.parts and p.is_file()
        }
        self.assertEqual(before, after)

    # --- Validation ----------------------------------------------------------

    def test_query_parameters_are_bad_request(self) -> None:
        self._create("a", DIGEST_A)
        for query_string in (
            "bogus=1",
            "focus=a",
            "=",
            "x=&y=2",
            "x=1&x=2",
            "foo",
        ):
            with self.subTest(query_string=query_string):
                status, _h, body = call_json(
                    "GET", PATH, query_string=query_string
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")  # type: ignore[index]

    def test_declared_non_empty_body_is_bad_request(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        self._add(a, b)
        status, _h, body = call_json("GET", PATH, b"{}")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")  # type: ignore[index]

        # The rejected request changed nothing.
        _s, _h, usage = self._usage_json()
        self.assertEqual(len(usage), 1)  # type: ignore[arg-type]

    def test_malformed_content_length_is_bad_request(self) -> None:
        status, _h, body = call_json("GET", PATH, content_length="abc")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")  # type: ignore[index]

    def test_bad_request_does_not_read_business_data(self) -> None:
        self._create("a", DIGEST_A)
        status, _h, _raw = call("GET", PATH, b'{"not": "consumed"}')
        self.assertEqual(status, "400 Bad Request")

    def test_omitted_length_header_is_accepted(self) -> None:
        status, _h, raw = self._usage(omit_content_length=True)
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

    def test_explicit_zero_length_body_is_accepted(self) -> None:
        status, _h, body = self._usage_json(b"")
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, [])  # type: ignore[arg-type]

    # --- Method handling -----------------------------------------------------

    def test_other_methods_return_405_with_allow_get(self) -> None:
        for method in ("POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
            with self.subTest(method=method):
                status, headers, body = call_json(method, PATH)
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")  # type: ignore[index]
                self.assertEqual(
                    [value for name, value in headers if name == "Allow"],
                    ["GET"],
                )

    def test_non_get_method_with_query_still_returns_405(self) -> None:
        status, headers, body = call_json(
            "DELETE", PATH, query_string="x=1"
        )
        self.assertEqual(status, "405 Method Not Allowed")
        self.assertEqual(body["error"], "method_not_allowed")  # type: ignore[index]
        self.assertEqual(
            [value for name, value in headers if name == "Allow"], ["GET"]
        )

    def test_subpath_is_not_the_usage_view(self) -> None:
        status, _h, body = call_json("GET", PATH + "/anything")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "not_found")  # type: ignore[index]


if __name__ == "__main__":
    unittest.main()
