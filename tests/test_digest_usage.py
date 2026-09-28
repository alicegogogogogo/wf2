from __future__ import annotations

import io
import json
import unittest

from provenance_api.app import application, reset_state

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64

PATH = "/digest-usage"


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


class DigestUsageTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def _create(
        self,
        name: str,
        digest: str,
        *,
        category: str = "code",
    ) -> str:
        status, _h, body = call_json(
            "POST",
            "/resources",
            {"name": name, "category": category, "digest": digest},
        )
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

    def test_one_entry_per_digest_in_first_appearance_order(self) -> None:
        # b first, then a twice: entries must follow [b, a], never sorted.
        b1 = self._create("b-one", DIGEST_B)
        a1 = self._create("a-one", DIGEST_A)
        a2 = self._create("a-two", DIGEST_A, category="model")

        _s, _h, body = self._usage_json()
        self.assertEqual(  # type: ignore[index]
            [entry["digest"] for entry in body], [DIGEST_B, DIGEST_A]
        )
        entries = {entry["digest"]: entry for entry in body}  # type: ignore[union-attr]
        self.assertEqual(entries[DIGEST_B]["resources"], [b1])
        self.assertEqual(entries[DIGEST_A]["resources"], [a1, a2])
        self.assertEqual(entries[DIGEST_A]["resource_count"], 2)
        self.assertEqual(entries[DIGEST_A]["names"], ["a-one", "a-two"])

    def test_entry_key_order_is_fixed(self) -> None:
        self._create("a", DIGEST_A)
        _s, _h, body = self._usage_json()
        for entry in body:  # type: ignore[union-attr]
            self.assertEqual(
                list(entry),
                ["digest", "resources", "resource_count", "names"],
            )

    def test_digest_is_echoed_as_normalized_lowercase(self) -> None:
        self._create("upper", "A" * 64)
        self._create("mixed", "Ab" + "0" * 62)
        _s, _h, body = self._usage_json()
        self.assertEqual(  # type: ignore[index]
            [entry["digest"] for entry in body],
            [DIGEST_A, "ab" + "0" * 62],
        )

    def test_uppercase_digest_merges_with_lowercase_group(self) -> None:
        lower = self._create("lower", DIGEST_A)
        upper = self._create("upper", "A" * 64, category="model")
        _s, _h, body = self._usage_json()
        self.assertEqual(len(body), 1)  # type: ignore[arg-type]
        entry = body[0]  # type: ignore[index]
        self.assertEqual(entry["digest"], DIGEST_A)
        self.assertEqual(entry["resources"], [lower, upper])
        self.assertEqual(entry["resource_count"], 2)
        self.assertEqual(entry["names"], ["lower", "upper"])

    def test_names_deduplicated_but_case_and_whitespace_preserved(self) -> None:
        # Same (name, digest) pair under two categories yields two resources;
        # the name must appear in ``names`` only once.
        one = self._create("Model", DIGEST_A)
        two = self._create("Model", DIGEST_A, category="model")
        # Case and surrounding whitespace are significant.
        three = self._create("model", DIGEST_A, category="dataset")
        four = self._create(" Model ", DIGEST_A, category="artifact")

        _s, _h, body = self._usage_json()
        entry = body[0]  # type: ignore[index]
        self.assertEqual(entry["resources"], [one, two, three, four])
        self.assertEqual(entry["resource_count"], 4)
        self.assertEqual(entry["names"], ["Model", "model", " Model "])

    def test_resource_count_matches_resources_length(self) -> None:
        self._create("a1", DIGEST_A)
        self._create("a2", DIGEST_A, category="model")
        self._create("same", DIGEST_A, category="dataset")
        self._create("same", DIGEST_A, category="artifact")
        self._create("b1", DIGEST_B)
        _s, _h, body = self._usage_json()
        for entry in body:  # type: ignore[union-attr]
            self.assertEqual(
                entry["resource_count"], len(entry["resources"])
            )

    # --- Recomputation and read-only behavior --------------------------------

    def test_recompute_after_registration(self) -> None:
        a = self._create("a", DIGEST_A)
        _s, _h, body = self._usage_json()
        self.assertEqual([entry["digest"] for entry in body], [DIGEST_A])  # type: ignore[index]

        # A resource of an existing digest appends to that group.
        a2 = self._create("a2", DIGEST_A, category="model")
        # A new digest gets a fresh trailing entry.
        b = self._create("b", DIGEST_B)

        _s, _h, body = self._usage_json()
        self.assertEqual(  # type: ignore[index]
            [entry["digest"] for entry in body], [DIGEST_A, DIGEST_B]
        )
        entries = {entry["digest"]: entry for entry in body}  # type: ignore[union-attr]
        self.assertEqual(entries[DIGEST_A]["resources"], [a, a2])
        self.assertEqual(entries[DIGEST_A]["names"], ["a", "a2"])
        self.assertEqual(entries[DIGEST_B]["resources"], [b])

    def test_entry_disappears_when_digest_loses_every_resource(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)

        status, _h, _raw = call("DELETE", f"/resources/{b}")
        self.assertEqual(status, "200 OK")

        _s, _h, body = self._usage_json()
        self.assertEqual(  # type: ignore[index]
            [entry["digest"] for entry in body], [DIGEST_A, DIGEST_C]
        )
        self.assertNotIn(DIGEST_B, [entry["digest"] for entry in body])
        entries = {entry["digest"]: entry for entry in body}  # type: ignore[union-attr]
        self.assertEqual(entries[DIGEST_A]["resources"], [a])
        self.assertEqual(entries[DIGEST_C]["resources"], [c])

    def test_delete_first_resource_redetermines_entry_order(self) -> None:
        # a holds positions 1 and 3, b position 2. Deleting the first a
        # resource redetermines first-appearance order from the remaining
        # registry: b is now earlier than the surviving a, so the b entry
        # moves to the front and no stale slot is left behind.
        first_a = self._create("a-one", DIGEST_A)
        b = self._create("b-one", DIGEST_B)
        second_a = self._create("a-two", DIGEST_A, category="model")

        status, _h, _raw = call("DELETE", f"/resources/{first_a}")
        self.assertEqual(status, "200 OK")

        _s, _h, body = self._usage_json()
        self.assertEqual(  # type: ignore[index]
            [entry["digest"] for entry in body], [DIGEST_B, DIGEST_A]
        )
        self.assertEqual(body[0]["resources"], [b])  # type: ignore[index]
        entry_a = body[1]  # type: ignore[index]
        self.assertEqual(entry_a["resources"], [second_a])
        self.assertEqual(entry_a["resource_count"], 1)
        self.assertEqual(entry_a["names"], ["a-two"])

    def test_delete_first_group_shifts_remaining_entries_forward(self) -> None:
        first = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_C)

        status, _h, _raw = call("DELETE", f"/resources/{first}")
        self.assertEqual(status, "200 OK")

        _s, _h, body = self._usage_json()
        self.assertEqual(  # type: ignore[index]
            [entry["digest"] for entry in body], [DIGEST_B, DIGEST_C]
        )
        self.assertEqual(body[0]["resources"], [b])  # type: ignore[index]
        self.assertEqual(body[1]["resources"], [c])  # type: ignore[index]

    def test_name_disappears_with_its_last_resource(self) -> None:
        a1 = self._create("shared", DIGEST_A)
        a2 = self._create("other", DIGEST_A, category="model")

        status, _h, _raw = call("DELETE", f"/resources/{a1}")
        self.assertEqual(status, "200 OK")

        _s, _h, body = self._usage_json()
        self.assertEqual(body[0]["names"], ["other"])  # type: ignore[index]
        self.assertEqual(body[0]["resources"], [a2])  # type: ignore[index]

    def test_view_is_read_only(self) -> None:
        self._create("a", DIGEST_A)
        self._create("b", DIGEST_B, category="model")

        self._usage()
        self._usage()

        _s, _h, listing = call_json("GET", "/resources")
        self.assertEqual(len(listing["resources"]), 2)  # type: ignore[index]
        _s, _h, body = self._usage_json()
        self.assertEqual(len(body), 2)  # type: ignore[arg-type]

    def test_existing_resource_entry_points_keep_their_behavior(self) -> None:
        # Registration query and list pagination are untouched by the view.
        resource = self._create("a", DIGEST_A, category="artifact")
        _s, _h, item = call_json("GET", f"/resources/{resource}")
        self.assertEqual(item["digest"], DIGEST_A)  # type: ignore[index]
        _s, _h, page = call_json(
            "GET", "/resources", query_string="limit=1"
        )
        self.assertEqual(len(page["resources"]), 1)  # type: ignore[index]
        self.assertEqual(page["resources"][0]["id"], resource)  # type: ignore[index]

    # --- Response body -------------------------------------------------------

    def test_body_is_compact_json_with_single_trailing_newline(self) -> None:
        rid = self._create("a", DIGEST_A)
        _s, _h, raw = self._usage()
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        self.assertEqual(
            raw,
            b'[{"digest":"'
            + DIGEST_A.encode("ascii")
            + b'","resources":["'
            + rid.encode("ascii")
            + b'"],"resource_count":1,"names":["a"]}]\n',
        )

    def test_no_persistence_files_created(self) -> None:
        import pathlib

        root = pathlib.Path(__file__).resolve().parents[1]
        before = {
            str(p.relative_to(root))
            for p in root.rglob("*")
            if ".git" not in p.parts and p.is_file()
        }
        self._create("a", DIGEST_A)
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
            "=",
            "x=&y=2",
            "x=1&x=2",
            "digest=" + DIGEST_A,
            "foo",
        ):
            with self.subTest(query_string=query_string):
                status, _h, body = call_json(
                    "GET", PATH, query_string=query_string
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")  # type: ignore[index]

    def test_declared_non_empty_body_is_bad_request(self) -> None:
        self._create("a", DIGEST_A)
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
        self._create("a", DIGEST_A)
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
