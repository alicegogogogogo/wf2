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

    def _create(self, name: str, digest: str, *, category: str = "code") -> str:
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
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_A, category="model")
        d = self._create("d", DIGEST_B, category="dataset")

        _s, _h, body = self._usage_json()
        self.assertEqual([entry["digest"] for entry in body], [DIGEST_A, DIGEST_B])  # type: ignore[index]
        self.assertEqual(
            [entry["resources"] for entry in body],  # type: ignore[index]
            [[a, c], [b, d]],
        )

    def test_entry_key_order_is_fixed(self) -> None:
        self._create("a", DIGEST_A)
        self._create("b", DIGEST_A, category="model")
        _s, _h, body = self._usage_json()
        for entry in body:  # type: ignore[union-attr]
            self.assertEqual(
                list(entry), ["digest", "resources", "resource_count", "names"]
            )

    def test_digest_is_echoed_as_normalized_lowercase(self) -> None:
        self._create("a", "A" * 64)
        _s, _h, body = self._usage_json()
        self.assertEqual(  # type: ignore[union-attr]
            body[0]["digest"], DIGEST_A
        )

    def test_resource_count_matches_resources_length(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_B)
        c = self._create("c", DIGEST_A, category="model")
        d = self._create("d", DIGEST_A, category="dataset")

        _s, _h, body = self._usage_json()
        by_digest = {entry["digest"]: entry for entry in body}  # type: ignore[union-attr]
        self.assertEqual(by_digest[DIGEST_A]["resources"], [a, c, d])
        self.assertEqual(by_digest[DIGEST_A]["resource_count"], 3)
        self.assertEqual(by_digest[DIGEST_B]["resources"], [b])
        self.assertEqual(by_digest[DIGEST_B]["resource_count"], 1)

    # --- Names ---------------------------------------------------------------

    def test_names_deduplicated_in_registration_order_and_verbatim(self) -> None:
        # Same digest, categories vary so each triple is a distinct resource.
        self._create("Alpha", DIGEST_A, category="code")
        self._create(" Alpha ", DIGEST_A, category="model")
        self._create("alpha", DIGEST_A, category="dataset")
        # Exact repeat (same name, different category) is listed only once.
        self._create("Alpha", DIGEST_A, category="artifact")

        _s, _h, body = self._usage_json()
        self.assertEqual(  # type: ignore[union-attr]
            body[0]["names"], ["Alpha", " Alpha ", "alpha"]
        )

    def test_names_contract_when_named_resources_leave(self) -> None:
        self._create("Alpha", DIGEST_A, category="code")
        beta = self._create("Beta", DIGEST_A, category="model")
        self._create("Gamma", DIGEST_B, category="code")

        status, _h, _b = call("DELETE", f"/resources/{beta}")
        self.assertEqual(status, "200 OK")

        _s, _h, body = self._usage_json()
        by_digest = {entry["digest"]: entry for entry in body}  # type: ignore[union-attr]
        self.assertEqual(by_digest[DIGEST_A]["names"], ["Alpha"])
        self.assertEqual(by_digest[DIGEST_A]["resource_count"], 1)
        self.assertEqual(by_digest[DIGEST_B]["names"], ["Gamma"])

    # --- Recomputation and ordering after deregistration ---------------------

    def test_digest_losing_all_resources_drops_the_entry(self) -> None:
        a = self._create("a", DIGEST_A)
        self._create("b", DIGEST_B)

        status, _h, _b = call("DELETE", f"/resources/{a}")
        self.assertEqual(status, "200 OK")

        _s, _h, body = self._usage_json()
        self.assertEqual([entry["digest"] for entry in body], [DIGEST_B])  # type: ignore[index]

    def test_entries_reposition_when_earliest_resource_is_removed(self) -> None:
        # Registration order: a(D1), b(D2), c(D1), d(D2): D1 currently first.
        a = self._create("a", DIGEST_A)
        self._create("b", DIGEST_B)
        self._create("c", DIGEST_A, category="model")
        self._create("d", DIGEST_B, category="dataset")

        status, _h, _b = call("DELETE", f"/resources/{a}")
        self.assertEqual(status, "200 OK")

        # The first-appearance order is redetermined from the remaining
        # resources: D2's earliest survivor now precedes D1's, so D2 leads.
        _s, _h, body = self._usage_json()
        self.assertEqual([entry["digest"] for entry in body], [DIGEST_B, DIGEST_A])  # type: ignore[index]

    def test_view_is_read_only(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_A, category="model")

        self._usage()
        self._usage()

        _s, _h, listing = call_json("GET", "/resources")
        self.assertEqual(  # type: ignore[index]
            [resource["id"] for resource in listing["resources"]], [a, b]
        )
        _s, _h, body = self._usage_json()
        self.assertEqual(len(body), 1)  # type: ignore[arg-type]
        self.assertEqual(body[0]["resources"], [a, b])  # type: ignore[index]

    # --- Response body -------------------------------------------------------

    def test_body_is_compact_json_with_single_trailing_newline(self) -> None:
        a = self._create("a", DIGEST_A)
        b = self._create("b", DIGEST_A, category="model")
        _s, _h, raw = self._usage()
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        self.assertEqual(
            raw,
            b'[{"digest":"'
            + DIGEST_A.encode("ascii")
            + b'","resources":["'
            + a.encode("ascii")
            + b'","'
            + b.encode("ascii")
            + b'"],"resource_count":2,"names":["a","b"]}]\n',
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
            "digest=" + DIGEST_A,
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

    def test_non_get_method_with_body_or_query_still_returns_405(self) -> None:
        status, headers, body = call_json(
            "DELETE", PATH, b"{}", query_string="x=1"
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
