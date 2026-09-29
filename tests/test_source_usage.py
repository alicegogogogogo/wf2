from __future__ import annotations

import io
import json
import unittest

from provenance_api.app import application, reset_state

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64

PATH = "/source-usage"


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


class SourceUsageTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def _create(
        self,
        name: str,
        digest: str = DIGEST_A,
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
        status, _h, body = call_json("POST", "/resources", payload)
        self.assertEqual(status, "201 Created")
        return str(body["id"])  # type: ignore[index]

    def _usage(self, **kwargs: object):
        return call("GET", PATH, **kwargs)

    def _usage_json(self, body: object = None, **kwargs: object):
        status, headers, parsed = call_json("GET", PATH, body, **kwargs)
        return status, headers, parsed

    # --- Empty registry ------------------------------------------------------

    def test_empty_registry_is_empty_array_success(self) -> None:
        status, headers, raw = self._usage()
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            headers[0], ("Content-Type", "application/json; charset=utf-8")
        )
        self.assertEqual(raw, b"[]\n")

    # --- Entry shape and ordering -------------------------------------------

    def test_one_entry_per_source_in_first_appearance_order(self) -> None:
        # b first, then a twice with source a: entries must follow
        # [b, a], never sorted.
        b1 = self._create("n-b", DIGEST_B, source="b-src")
        a1 = self._create("n-a", DIGEST_A, source="a-src")
        a2 = self._create("n-a2", DIGEST_B, category="model", source="a-src")

        _s, _h, body = self._usage_json()
        self.assertEqual(  # type: ignore[index]
            [entry["source"] for entry in body], ["b-src", "a-src"]
        )
        entries = {entry["source"]: entry for entry in body}  # type: ignore[union-attr]
        self.assertEqual(entries["b-src"]["resources"], [b1])
        self.assertEqual(entries["b-src"]["resource_count"], 1)
        self.assertEqual(entries["b-src"]["names"], ["n-b"])
        self.assertEqual(entries["b-src"]["categories"], ["code"])
        self.assertEqual(entries["a-src"]["resources"], [a1, a2])
        self.assertEqual(entries["a-src"]["resource_count"], 2)
        self.assertEqual(entries["a-src"]["names"], ["n-a", "n-a2"])
        self.assertEqual(entries["a-src"]["categories"], ["code", "model"])

    def test_entry_key_order_is_fixed(self) -> None:
        self._create("a", source="src")
        _s, _h, body = self._usage_json()
        for entry in body:  # type: ignore[union-attr]
            self.assertEqual(
                list(entry),
                ["source", "resources", "resource_count", "names", "categories"],
            )

    def test_missing_source_collapses_into_null_entry(self) -> None:
        sourced = self._create("sourced", DIGEST_A, source="src")
        missing_one = self._create("m1", DIGEST_B)
        missing_two = self._create(
            "m2", DIGEST_C, category="model"
        )

        _s, _h, body = self._usage_json()
        self.assertEqual(  # type: ignore[index]
            [entry["source"] for entry in body], ["src", None]
        )
        null_entry = body[1]  # type: ignore[index]
        self.assertEqual(null_entry["source"], None)
        self.assertEqual(null_entry["resources"], [missing_one, missing_two])
        self.assertEqual(null_entry["resource_count"], 2)
        self.assertEqual(null_entry["names"], ["m1", "m2"])
        self.assertEqual(null_entry["categories"], ["code", "model"])
        self.assertEqual(body[0]["resources"], [sourced])  # type: ignore[index]

    def test_null_entry_leads_when_first_resource_has_no_source(self) -> None:
        first = self._create("m1", DIGEST_A)
        second = self._create("s1", DIGEST_B, source="src")

        _s, _h, body = self._usage_json()
        self.assertEqual(  # type: ignore[index]
            [entry["source"] for entry in body], [None, "src"]
        )
        self.assertIn("source", body[0])  # type: ignore[operator]
        self.assertIsNone(body[0]["source"])  # type: ignore[index]
        self.assertEqual(body[0]["resources"], [first])  # type: ignore[index]
        self.assertEqual(body[1]["resources"], [second])  # type: ignore[index]

    def test_source_is_echoed_verbatim_case_and_whitespace_preserved(
        self,
    ) -> None:
        one = self._create("n", DIGEST_A, source="Mirror")
        two = self._create("n", DIGEST_B, category="model", source="mirror")
        three = self._create(
            "n", DIGEST_C, category="dataset", source=" Mirror "
        )

        _s, _h, body = self._usage_json()
        self.assertEqual(  # type: ignore[index]
            [entry["source"] for entry in body],
            ["Mirror", "mirror", " Mirror "],
        )
        entries = {  # type: ignore[union-attr]
            entry["source"]: entry for entry in body
        }
        self.assertEqual(entries["Mirror"]["resources"], [one])
        self.assertEqual(entries["mirror"]["resources"], [two])
        self.assertEqual(entries[" Mirror "]["resources"], [three])

    def test_names_deduplicated_verbatim_in_registration_order(self) -> None:
        r1 = self._create("shared", DIGEST_A, source="src")
        r2 = self._create("Shared", DIGEST_B, category="model", source="src")
        r3 = self._create("shared", DIGEST_C, category="dataset", source="src")

        _s, _h, body = self._usage_json()
        entry = body[0]  # type: ignore[index]
        self.assertEqual(entry["source"], "src")
        self.assertEqual(entry["resources"], [r1, r2, r3])
        self.assertEqual(entry["resource_count"], 3)
        # Case is significant; the repeated exact name is listed once.
        self.assertEqual(entry["names"], ["shared", "Shared"])
        self.assertEqual(entry["categories"], ["code", "model", "dataset"])

    def test_categories_deduplicated_and_lowercased(self) -> None:
        r1 = self._create("a", DIGEST_A, category="CODE", source="src")
        r2 = self._create("b", DIGEST_B, category="model", source="src")
        r3 = self._create("c", DIGEST_C, category="code", source="src")

        _s, _h, body = self._usage_json()
        entry = body[0]  # type: ignore[index]
        self.assertEqual(entry["resources"], [r1, r2, r3])
        self.assertEqual(entry["resource_count"], 3)
        self.assertEqual(entry["categories"], ["code", "model"])

    def test_resource_count_matches_resources_length(self) -> None:
        self._create("a", DIGEST_A, source="x")
        self._create("b", DIGEST_B, category="model", source="x")
        self._create("c", DIGEST_C, category="dataset")
        self._create("d", "d" * 64, category="artifact", source="y")
        _s, _h, body = self._usage_json()
        for entry in body:  # type: ignore[union-attr]
            self.assertEqual(
                entry["resource_count"], len(entry["resources"])
            )

    # --- Recomputation and read-only behavior --------------------------------

    def test_recompute_after_registration(self) -> None:
        a = self._create("a", DIGEST_A, source="x")
        _s, _h, body = self._usage_json()
        self.assertEqual([entry["source"] for entry in body], ["x"])  # type: ignore[index]

        # Another resource of an existing source appends to that group.
        a2 = self._create("a2", DIGEST_B, category="model", source="x")
        # A new source gets a fresh trailing entry.
        b = self._create("b", DIGEST_C, source="y")
        # A resource without a source adds the null entry.
        c = self._create("c", "d" * 64)

        _s, _h, body = self._usage_json()
        self.assertEqual(  # type: ignore[index]
            [entry["source"] for entry in body], ["x", "y", None]
        )
        entries = {  # type: ignore[union-attr]
            str(entry["source"]): entry for entry in body
        }
        self.assertEqual(entries["x"]["resources"], [a, a2])
        self.assertEqual(entries["x"]["names"], ["a", "a2"])
        self.assertEqual(entries["x"]["categories"], ["code", "model"])
        self.assertEqual(entries["y"]["resources"], [b])
        self.assertEqual(entries["None"]["resources"], [c])

    def test_entry_disappears_when_source_loses_every_resource(self) -> None:
        a = self._create("a", DIGEST_A, source="x")
        b = self._create("b", DIGEST_B, source="y")
        c = self._create("c", DIGEST_C, source="z")

        status, _h, _raw = call("DELETE", f"/resources/{b}")
        self.assertEqual(status, "200 OK")

        _s, _h, body = self._usage_json()
        self.assertEqual(  # type: ignore[index]
            [entry["source"] for entry in body], ["x", "z"]
        )
        entries = {entry["source"]: entry for entry in body}  # type: ignore[union-attr]
        self.assertEqual(entries["x"]["resources"], [a])
        self.assertEqual(entries["z"]["resources"], [c])

    def test_null_entry_disappears_when_last_sourceless_resource_removed(
        self,
    ) -> None:
        a = self._create("a", DIGEST_A, source="x")
        no_source = self._create("b", DIGEST_B)

        status, _h, _raw = call("DELETE", f"/resources/{no_source}")
        self.assertEqual(status, "200 OK")

        _s, _h, body = self._usage_json()
        self.assertEqual(  # type: ignore[index]
            [entry["source"] for entry in body], ["x"]
        )
        self.assertEqual(body[0]["resources"], [a])  # type: ignore[index]

    def test_delete_first_resource_redetermines_entry_order(self) -> None:
        # x holds positions 1 and 3, y position 2. Deleting the first x
        # resource redetermines first-appearance order from the remaining
        # registry: y is now earlier than the surviving x, so the y entry
        # moves to the front and no stale slot is left behind.
        first_x = self._create("a-one", DIGEST_A, source="x")
        y = self._create("b-one", DIGEST_B, source="y")
        second_x = self._create(
            "a-two", DIGEST_C, category="model", source="x"
        )

        status, _h, _raw = call("DELETE", f"/resources/{first_x}")
        self.assertEqual(status, "200 OK")

        _s, _h, body = self._usage_json()
        self.assertEqual(  # type: ignore[index]
            [entry["source"] for entry in body], ["y", "x"]
        )
        self.assertEqual(body[0]["resources"], [y])  # type: ignore[index]
        entry_x = body[1]  # type: ignore[index]
        self.assertEqual(entry_x["resources"], [second_x])
        self.assertEqual(entry_x["resource_count"], 1)
        self.assertEqual(entry_x["names"], ["a-two"])
        self.assertEqual(entry_x["categories"], ["model"])

    def test_delete_first_group_shifts_remaining_entries_forward(self) -> None:
        first = self._create("a", DIGEST_A, source="x")
        b = self._create("b", DIGEST_B, source="y")
        c = self._create("c", DIGEST_C)

        status, _h, _raw = call("DELETE", f"/resources/{first}")
        self.assertEqual(status, "200 OK")

        _s, _h, body = self._usage_json()
        self.assertEqual(  # type: ignore[index]
            [entry["source"] for entry in body], ["y", None]
        )
        self.assertEqual(body[0]["resources"], [b])  # type: ignore[index]
        self.assertEqual(body[1]["resources"], [c])  # type: ignore[index]

    def test_names_and_categories_shrink_with_deleted_resource(self) -> None:
        a1 = self._create("only", DIGEST_A, category="code", source="src")
        a2 = self._create("other", DIGEST_B, category="model", source="src")

        status, _h, _raw = call("DELETE", f"/resources/{a1}")
        self.assertEqual(status, "200 OK")

        _s, _h, body = self._usage_json()
        entry = body[0]  # type: ignore[index]
        self.assertEqual(entry["resources"], [a2])
        self.assertEqual(entry["names"], ["other"])
        self.assertEqual(entry["categories"], ["model"])

    def test_view_is_read_only(self) -> None:
        self._create("a", DIGEST_A, source="x")
        self._create("b", DIGEST_B, category="model")

        self._usage()
        self._usage()

        _s, _h, listing = call_json("GET", "/resources")
        self.assertEqual(len(listing["resources"]), 2)  # type: ignore[index]
        _s, _h, body = self._usage_json()
        self.assertEqual(len(body), 2)  # type: ignore[arg-type]

    def test_existing_usage_views_are_unchanged(self) -> None:
        self._create("a", DIGEST_A, source="x")
        self._create("a", DIGEST_B, category="model", source="y")
        self._create("b", DIGEST_A, category="dataset")

        _s, _h, digest_body = call_json("GET", "/digest-usage")
        self.assertEqual(  # type: ignore[index]
            [entry["digest"] for entry in digest_body], [DIGEST_A, DIGEST_B]
        )
        for entry in digest_body:  # type: ignore[union-attr]
            self.assertEqual(
                list(entry),
                ["digest", "resources", "resource_count", "names"],
            )

        _s, _h, name_body = call_json("GET", "/name-usage")
        self.assertEqual(  # type: ignore[index]
            [entry["name"] for entry in name_body], ["a", "b"]
        )
        for entry in name_body:  # type: ignore[union-attr]
            self.assertEqual(
                list(entry),
                ["name", "resources", "resource_count", "digests", "categories"],
            )

    def test_existing_resource_entry_points_keep_their_behavior(self) -> None:
        # Registration, query and pagination are untouched by the view.
        resource = self._create(
            "a", DIGEST_A, category="artifact", source="src"
        )
        _s, _h, item = call_json("GET", f"/resources/{resource}")
        self.assertEqual(item["digest"], DIGEST_A)  # type: ignore[index]
        self.assertEqual(item["source"], "src")  # type: ignore[index]
        _s, _h, page = call_json(
            "GET", "/resources", query_string="limit=1"
        )
        self.assertEqual(len(page["resources"]), 1)  # type: ignore[index]
        self.assertEqual(page["resources"][0]["id"], resource)  # type: ignore[index]

    # --- Response body -------------------------------------------------------

    def test_body_is_compact_json_with_single_trailing_newline(self) -> None:
        rid = self._create("a", DIGEST_A, source="src")
        _s, _h, raw = self._usage()
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        self.assertEqual(
            raw,
            b'[{"source":"src","resources":["'
            + rid.encode("ascii")
            + b'"],"resource_count":1,"names":["a"],"categories":["code"]}]\n',
        )

    def test_null_source_body_is_compact_json(self) -> None:
        rid = self._create("a", DIGEST_A)
        _s, _h, raw = self._usage()
        self.assertEqual(
            raw,
            b'[{"source":null,"resources":["'
            + rid.encode("ascii")
            + b'"],"resource_count":1,"names":["a"],"categories":["code"]}]\n',
        )

    def test_non_ascii_source_is_utf8_encoded(self) -> None:
        rid = self._create("a", DIGEST_A, source="来源-α")
        _s, _h, raw = self._usage()
        expected_source = "来源-α".encode("utf-8")
        self.assertEqual(
            raw,
            b'[{"source":"'
            + expected_source
            + b'","resources":["'
            + rid.encode("ascii")
            + b'"],"resource_count":1,"names":["a"],"categories":["code"]}]\n',
        )

    def test_no_persistence_files_created(self) -> None:
        import pathlib

        root = pathlib.Path(__file__).resolve().parents[1]
        before = {
            str(p.relative_to(root))
            for p in root.rglob("*")
            if ".git" not in p.parts and p.is_file()
        }
        self._create("a", DIGEST_A, source="src")
        self._usage()
        after = {
            str(p.relative_to(root))
            for p in root.rglob("*")
            if ".git" not in p.parts and p.is_file()
        }
        self.assertEqual(before, after)

    # --- Validation ----------------------------------------------------------

    def test_query_parameters_are_bad_request(self) -> None:
        self._create("a", DIGEST_A, source="src")
        for query_string in (
            "bogus=1",
            "=",
            "x=&y=2",
            "x=1&x=2",
            "source=a",
            "foo",
        ):
            with self.subTest(query_string=query_string):
                status, _h, body = call_json(
                    "GET", PATH, query_string=query_string
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")  # type: ignore[index]

    def test_declared_non_empty_body_is_bad_request(self) -> None:
        self._create("a", DIGEST_A, source="src")
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
        self._create("a", DIGEST_A, source="src")
        status, _h, _raw = call("GET", PATH, b'{"not": "consumed"}')
        self.assertEqual(status, "400 Bad Request")

    def test_omitted_length_header_is_accepted(self) -> None:
        status, _h, raw = self._usage(omit_content_length=True)
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

    def test_explicit_zero_length_body_is_accepted(self) -> None:
        self._create("a", DIGEST_A, source="src")
        status, _h, body = self._usage_json(b"")
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(body), 1)  # type: ignore[arg-type]

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

    def test_non_get_method_with_query_and_body_still_returns_405(self) -> None:
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
