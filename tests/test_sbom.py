from __future__ import annotations

import io
import json
import unittest

from provenance_api.app import application, reset_state

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "C" * 64


def call(
    method: str,
    path: str,
    body: bytes | str | dict[str, object] | None = None,
    *,
    query_string: str | None = None,
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
        "CONTENT_LENGTH": str(len(payload)),
        "CONTENT_TYPE": "application/json",
        "wsgi.input": io.BytesIO(payload),
    }
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
    *,
    query_string: str | None = None,
) -> tuple[str, list[tuple[str, str]], dict[str, object]]:
    status, headers, raw = call(method, path, body, query_string=query_string)
    return status, headers, json.loads(raw.decode("utf-8"))


class SbomTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.resource_id = self._create(DIGEST_A)
        self.other_id = self._create(DIGEST_B, name="other")

    def _create(self, digest: str, name: str = "r") -> str:
        _s, _h, body = call_json(
            "POST",
            "/resources",
            {"name": name, "category": "code", "digest": digest},
        )
        return str(body["id"])

    def _components(self, *digests: str) -> list[dict[str, str]]:
        return [
            {"name": f"lib-{i}", "version": f"1.{i}", "digest": digest}
            for i, digest in enumerate(digests)
        ]

    def _sbom(
        self,
        resource_id: str | None = None,
        *,
        fmt: str = "spdx",
        components: object = ...,  # type: ignore[assignment]
    ):
        if components is ...:
            components = self._components(DIGEST_A, DIGEST_B)
        return call_json(
            "POST",
            f"/resources/{self.resource_id if resource_id is None else resource_id}/sbom",
            {"format": fmt, "components": components},
        )

    # --- Registration ------------------------------------------------------

    def test_register_returns_201_and_echoes_fields(self) -> None:
        status, headers, body = self._sbom(
            fmt="cyclonedx", components=self._components(DIGEST_C)
        )
        self.assertEqual(status, "201 Created")
        self.assertEqual(
            headers[0], ("Content-Type", "application/json; charset=utf-8")
        )
        self.assertEqual(set(body), {"id", "format", "components"})
        self.assertEqual(body["id"], self.resource_id)
        self.assertEqual(body["format"], "cyclonedx")
        self.assertEqual(
            body["components"],
            [{"name": "lib-0", "version": "1.0", "digest": "c" * 64}],
        )

    def test_digest_is_normalized_to_lowercase(self) -> None:
        _s, _h, body = self._sbom(components=self._components("AbC" + "0" * 61))
        self.assertEqual(body["components"][0]["digest"], "abc" + "0" * 61)

    def test_empty_components_is_valid(self) -> None:
        status, _h, body = self._sbom(components=[])
        self.assertEqual(status, "201 Created")
        self.assertEqual(body["components"], [])

    def test_components_keep_submission_order(self) -> None:
        components = self._components(DIGEST_C, DIGEST_A, DIGEST_B)
        _s, _h, body = self._sbom(components=components)
        self.assertEqual(
            [c["digest"] for c in body["components"]],
            ["c" * 64, DIGEST_A, DIGEST_B],
        )

    def test_response_is_compact_utf8_newline_terminated(self) -> None:
        status, _headers, raw = call(
            "POST",
            f"/resources/{self.resource_id}/sbom",
            {"format": "spdx",
             "components": [{"name": "库", "version": "1", "digest": DIGEST_A}]},
        )
        self.assertEqual(status, "201 Created")
        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(b" ", raw[:-1])
        text = raw.decode("utf-8").rstrip("\n")
        keys = ['"id"', '"format"', '"components"']
        positions = [text.index(k) for k in keys]
        self.assertEqual(positions, sorted(positions))

    # --- Query -------------------------------------------------------------

    def test_get_returns_registered_document(self) -> None:
        post = self._sbom(fmt="cyclonedx")[2]
        status, _h, body = call_json(
            "GET", f"/resources/{self.resource_id}/sbom"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, post)

    def test_get_without_registration_is_404(self) -> None:
        status, _h, body = call_json(
            "GET", f"/resources/{self.resource_id}/sbom"
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "sbom_not_found")

    # --- Idempotency and conflicts ----------------------------------------

    def test_same_document_resubmitted_is_idempotent_200(self) -> None:
        first = self._sbom(components=self._components(DIGEST_A, DIGEST_B))
        self.assertEqual(first[0], "201 Created")
        second = self._sbom(components=self._components(DIGEST_A, DIGEST_B))
        self.assertEqual(second[0], "200 OK")
        self.assertEqual(second[2], first[2])

        # Mixed-case digest that normalizes to the same document is the same.
        status, _h, _body = call_json(
            "POST",
            f"/resources/{self.resource_id}/sbom",
            {"format": "spdx", "components": self._components("A" * 64, "B" * 64)},
        )
        self.assertEqual(status, "200 OK")

    def test_different_document_conflicts(self) -> None:
        original = self._sbom(components=self._components(DIGEST_A))[2]
        for payload in [
            {"format": "cyclonedx", "components": self._components(DIGEST_A)},
            {"format": "spdx", "components": self._components(DIGEST_B)},
            {"format": "spdx", "components": []},
            {"format": "spdx",
             "components": [{"name": "lib-0", "version": "9.9",
                             "digest": DIGEST_A}]},
        ]:
            with self.subTest(payload=payload):
                status, _h, body = call_json(
                    "POST", f"/resources/{self.resource_id}/sbom", payload
                )
                self.assertEqual(status, "409 Conflict")
                self.assertEqual(body["error"], "sbom_conflict")

        # The original document is untouched.
        _s, _h, body = call_json("GET", f"/resources/{self.resource_id}/sbom")
        self.assertEqual(body, original)

    def test_duplicate_component_triple_is_409(self) -> None:
        component = {"name": "lib", "version": "1.0", "digest": DIGEST_A}
        status, _h, body = call_json(
            "POST",
            f"/resources/{self.resource_id}/sbom",
            {"format": "spdx", "components": [component, dict(component)]},
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "duplicate_component")
        # Nothing was stored.
        _s, _h, get = call_json("GET", f"/resources/{self.resource_id}/sbom")
        self.assertEqual(get["error"], "sbom_not_found")

    def test_same_name_version_but_different_digest_is_distinct(self) -> None:
        status, _h, _body = call_json(
            "POST",
            f"/resources/{self.resource_id}/sbom",
            {"format": "spdx",
             "components": [
                 {"name": "lib", "version": "1.0", "digest": DIGEST_A},
                 {"name": "lib", "version": "1.0", "digest": DIGEST_B},
             ]},
        )
        self.assertEqual(status, "201 Created")

    def test_only_one_document_per_resource(self) -> None:
        self._sbom(resource_id=self.resource_id)
        self._sbom(resource_id=self.other_id, fmt="cyclonedx")
        _s, _h, first = call_json("GET", f"/resources/{self.resource_id}/sbom")
        _s, _h, second = call_json("GET", f"/resources/{self.other_id}/sbom")
        self.assertEqual(first["format"], "spdx")
        self.assertEqual(second["format"], "cyclonedx")

    # --- Bad request: body -------------------------------------------------

    def test_missing_body_is_bad_request(self) -> None:
        status, _h, body = call_json(
            "POST", f"/resources/{self.resource_id}/sbom", None
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_malformed_or_bad_utf8_body_is_bad_request(self) -> None:
        path = f"/resources/{self.resource_id}/sbom"
        for raw in (b"{bad", b"\xff\xfe"):
            with self.subTest(raw=raw):
                status, _h, body = call_json("POST", path, raw)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_non_object_body_is_bad_request(self) -> None:
        for raw in (b"[]", b'"x"', b"42", b"null"):
            with self.subTest(raw=raw):
                status, _h, body = call_json(
                    "POST", f"/resources/{self.resource_id}/sbom", raw
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    # --- Bad request: fields -----------------------------------------------

    def test_missing_required_fields(self) -> None:
        for payload in (
            {"components": []},
            {"format": "spdx"},
            {},
        ):
            with self.subTest(payload=payload):
                status, _h, body = call_json(
                    "POST", f"/resources/{self.resource_id}/sbom", payload
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_unknown_field_rejected(self) -> None:
        status, _h, body = call_json(
            "POST",
            f"/resources/{self.resource_id}/sbom",
            {"format": "spdx", "components": [], "extra": 1},
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_bad_format_rejected(self) -> None:
        for fmt in ("SPDX", "spdx ", "cyclone", "", 1, None, True):
            with self.subTest(fmt=fmt):
                status, _h, body = call_json(
                    "POST",
                    f"/resources/{self.resource_id}/sbom",
                    {"format": fmt, "components": []},
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_components_must_be_array(self) -> None:
        for components in ({}, "x", 1, None, True):
            with self.subTest(components=components):
                status, _h, body = call_json(
                    "POST",
                    f"/resources/{self.resource_id}/sbom",
                    {"format": "spdx", "components": components},
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_component_must_be_object(self) -> None:
        for bad in ([[]], [[]], [["x"]], ["x"], [1], [None]):
            with self.subTest(bad=bad):
                status, _h, body = call_json(
                    "POST",
                    f"/resources/{self.resource_id}/sbom",
                    {"format": "spdx", "components": bad},
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_component_field_errors(self) -> None:
        good = {"name": "lib", "version": "1.0", "digest": DIGEST_A}
        cases = [
            {},
            {"version": "1.0", "digest": DIGEST_A},
            {"name": "lib", "digest": DIGEST_A},
            {"name": "lib", "version": "1.0"},
            {"name": "", "version": "1.0", "digest": DIGEST_A},
            {"name": "lib", "version": "", "digest": DIGEST_A},
            {"name": "lib", "version": "1.0", "digest": ""},
            {"name": 1, "version": "1.0", "digest": DIGEST_A},
            {"name": "lib", "version": 1, "digest": DIGEST_A},
            {"name": "lib", "version": "1.0", "digest": 1},
            {"name": "lib", "version": "1.0", "digest": None},
            {"name": "lib", "version": "1.0", "digest": "a" * 63},
            {"name": "lib", "version": "1.0", "digest": "g" * 64},
            {"name": "lib", "version": "1.0", "digest": "A" * 65},
            {"name": "lib", "version": "1.0", "digest": DIGEST_A,
             "extra": 1},
        ]
        for component in cases:
            with self.subTest(component=component):
                status, _h, body = call_json(
                    "POST",
                    f"/resources/{self.resource_id}/sbom",
                    {"format": "spdx", "components": [component]},
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    # --- Path, query, method, missing resource -----------------------------

    def test_empty_path_id_is_bad_request(self) -> None:
        for method, body in [
            ("GET", None),
            ("POST", {"format": "spdx", "components": []}),
        ]:
            with self.subTest(method=method):
                status, _h, payload = call_json(
                    method, "/resources//sbom", body
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(payload["error"], "invalid_request")

    def test_path_id_with_separator_is_bad_request(self) -> None:
        for raw in ("a/b", "a\\b"):
            for method in ("GET", "POST"):
                with self.subTest(raw=raw, method=method):
                    status, _h, body = call_json(
                        method, f"/resources/{raw}/sbom"
                    )
                    self.assertIn(status[:3], {"400", "404"})
                    self.assertEqual(body["error"], "invalid_request")

    def test_query_parameters_rejected(self) -> None:
        for method, body in [
            ("GET", None),
            ("POST", {"format": "spdx", "components": []}),
        ]:
            with self.subTest(method=method):
                status, _h, payload = call_json(
                    method,
                    f"/resources/{self.resource_id}/sbom",
                    body,
                    query_string="x=1",
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(payload["error"], "invalid_request")

    def test_missing_resource_is_404(self) -> None:
        for method, body in [
            ("GET", None),
            ("POST", {"format": "spdx", "components": []}),
        ]:
            with self.subTest(method=method):
                status, _h, payload = call_json(
                    method, "/resources/missing/sbom", body
                )
                self.assertEqual(status, "404 Not Found")
                self.assertEqual(payload["error"], "resource_not_found")

    def test_unsupported_methods_return_405_with_allow(self) -> None:
        for method in ("PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, headers, body = call_json(
                    method, f"/resources/{self.resource_id}/sbom"
                )
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")
                self.assertIn(("Allow", "GET, POST"), headers)

    def test_failed_requests_leave_no_document(self) -> None:
        call_json(
            "POST", f"/resources/{self.resource_id}/sbom",
            {"format": "bogus", "components": []},
        )
        call_json(
            "POST", f"/resources/{self.resource_id}/sbom",
            {"format": "spdx",
             "components": [{"name": "lib", "version": "1",
                             "digest": DIGEST_A},
                            {"name": "lib", "version": "1",
                             "digest": DIGEST_A}]},
        )
        call_json("POST", f"/resources/{self.resource_id}/sbom", b"not json")
        call_json("GET", "/resources/missing/sbom")
        _s, _h, body = call_json("GET", f"/resources/{self.resource_id}/sbom")
        self.assertEqual(body["error"], "sbom_not_found")


class LicenseTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.resource_id = self._create(DIGEST_A)
        self.other_id = self._create(DIGEST_B, name="other")

    def _create(self, digest: str, name: str = "r") -> str:
        _s, _h, body = call_json(
            "POST",
            "/resources",
            {"name": name, "category": "code", "digest": digest},
        )
        return str(body["id"])

    def _license(
        self,
        resource_id: str | None = None,
        *,
        spdx_id: str = "Apache-2.0",
        source: object = ...,  # type: ignore[assignment]
    ):
        payload: dict[str, object] = {"spdx_id": spdx_id}
        if source is not ...:
            payload["source"] = source
        target = self.resource_id if resource_id is None else resource_id
        return call_json("POST", f"/resources/{target}/license", payload)

    # --- Registration ------------------------------------------------------

    def test_register_returns_201_and_echoes_fields(self) -> None:
        status, headers, body = self._license(
            spdx_id="MIT", source="https://example.invalid/LICENSE"
        )
        self.assertEqual(status, "201 Created")
        self.assertEqual(
            headers[0], ("Content-Type", "application/json; charset=utf-8")
        )
        self.assertEqual(set(body), {"id", "spdx_id", "source"})
        self.assertEqual(body["id"], self.resource_id)
        self.assertEqual(body["spdx_id"], "MIT")
        self.assertEqual(body["source"], "https://example.invalid/LICENSE")

    def test_source_defaults_to_null(self) -> None:
        status, _h, body = self._license()
        self.assertEqual(status, "201 Created")
        self.assertIsNone(body["source"])

    def test_source_is_echoed_verbatim(self) -> None:
        _s, _h, body = self._license(source="  vendor portal  ")
        self.assertEqual(body["source"], "  vendor portal  ")

    def test_response_is_compact_with_fixed_key_order(self) -> None:
        status, _headers, raw = call(
            "POST",
            f"/resources/{self.resource_id}/license",
            {"spdx_id": "GPL-3.0-or-later"},
        )
        self.assertEqual(status, "201 Created")
        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(b" ", raw[:-1])
        text = raw.decode("utf-8").rstrip("\n")
        keys = ['"id"', '"spdx_id"', '"source"']
        positions = [text.index(k) for k in keys]
        self.assertEqual(positions, sorted(positions))

    # --- Query -------------------------------------------------------------

    def test_get_returns_declared_license(self) -> None:
        post = self._license(source="s")[2]
        status, _h, body = call_json(
            "GET", f"/resources/{self.resource_id}/license"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, post)

    def test_get_without_registration_is_404(self) -> None:
        status, _h, body = call_json(
            "GET", f"/resources/{self.resource_id}/license"
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "license_not_found")

    # --- Idempotency and conflicts ----------------------------------------

    def test_same_license_resubmitted_is_idempotent_200(self) -> None:
        first = self._license(source="s")
        self.assertEqual(first[0], "201 Created")
        second = self._license(source="s")
        self.assertEqual(second[0], "200 OK")
        self.assertEqual(second[2], first[2])

    def test_repeat_omitted_source_matches_null(self) -> None:
        self._license()
        status, _h, body = self._license()
        self.assertEqual(status, "200 OK")
        self.assertIsNone(body["source"])

    def test_different_license_conflicts(self) -> None:
        original = self._license(spdx_id="MIT", source="s")[2]
        for payload in (
            {"spdx_id": "Apache-2.0", "source": "s"},
            {"spdx_id": "MIT", "source": "other"},
            {"spdx_id": "MIT"},
        ):
            with self.subTest(payload=payload):
                status, _h, body = call_json(
                    "POST", f"/resources/{self.resource_id}/license", payload
                )
                self.assertEqual(status, "409 Conflict")
                self.assertEqual(body["error"], "license_conflict")

        _s, _h, body = call_json(
            "GET", f"/resources/{self.resource_id}/license"
        )
        self.assertEqual(body, original)

    def test_one_license_per_resource_is_scoped(self) -> None:
        self._license(resource_id=self.resource_id)
        self._license(resource_id=self.other_id, spdx_id="GPL-3.0-only")
        _s, _h, first = call_json(
            "GET", f"/resources/{self.resource_id}/license"
        )
        _s, _h, second = call_json("GET", f"/resources/{self.other_id}/license")
        self.assertEqual(first["spdx_id"], "Apache-2.0")
        self.assertEqual(second["spdx_id"], "GPL-3.0-only")

    # --- Bad request -------------------------------------------------------

    def test_missing_body_is_bad_request(self) -> None:
        status, _h, body = call_json(
            "POST", f"/resources/{self.resource_id}/license", None
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_malformed_or_bad_utf8_body_is_bad_request(self) -> None:
        path = f"/resources/{self.resource_id}/license"
        for raw in (b"{bad", b"\xff\xfe"):
            with self.subTest(raw=raw):
                status, _h, body = call_json("POST", path, raw)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_non_object_body_is_bad_request(self) -> None:
        for raw in (b"[]", b'"x"', b"42", b"null"):
            with self.subTest(raw=raw):
                status, _h, body = call_json(
                    "POST", f"/resources/{self.resource_id}/license", raw
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_field_errors(self) -> None:
        for payload in (
            {},
            {"source": "s"},
            {"spdx_id": ""},
            {"spdx_id": 1},
            {"spdx_id": None},
            {"spdx_id": True},
            {"spdx_id": "MIT", "source": ""},
            {"spdx_id": "MIT", "source": 1},
            {"spdx_id": "MIT", "source": None},
            {"spdx_id": "MIT", "extra": 1},
        ):
            with self.subTest(payload=payload):
                status, _h, body = call_json(
                    "POST",
                    f"/resources/{self.resource_id}/license",
                    payload,
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    # --- Path, query, method, missing resource -----------------------------

    def test_empty_path_id_is_bad_request(self) -> None:
        for method, body in [
            ("GET", None),
            ("POST", {"spdx_id": "MIT"}),
        ]:
            with self.subTest(method=method):
                status, _h, payload = call_json(
                    method, "/resources//license", body
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(payload["error"], "invalid_request")

    def test_path_id_with_separator_is_bad_request(self) -> None:
        for raw in ("a/b", "a\\b"):
            for method in ("GET", "POST"):
                with self.subTest(raw=raw, method=method):
                    status, _h, body = call_json(
                        method, f"/resources/{raw}/license"
                    )
                    self.assertIn(status[:3], {"400", "404"})
                    self.assertEqual(body["error"], "invalid_request")

    def test_query_parameters_rejected(self) -> None:
        for method, body in [
            ("GET", None),
            ("POST", {"spdx_id": "MIT"}),
        ]:
            with self.subTest(method=method):
                status, _h, payload = call_json(
                    method,
                    f"/resources/{self.resource_id}/license",
                    body,
                    query_string="x=1",
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(payload["error"], "invalid_request")

    def test_missing_resource_is_404(self) -> None:
        for method, body in [
            ("GET", None),
            ("POST", {"spdx_id": "MIT"}),
        ]:
            with self.subTest(method=method):
                status, _h, payload = call_json(
                    method, "/resources/missing/license", body
                )
                self.assertEqual(status, "404 Not Found")
                self.assertEqual(payload["error"], "resource_not_found")

    def test_unsupported_methods_return_405_with_allow(self) -> None:
        for method in ("PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, headers, body = call_json(
                    method, f"/resources/{self.resource_id}/license"
                )
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")
                self.assertIn(("Allow", "GET, POST"), headers)

    def test_failed_requests_leave_no_license(self) -> None:
        call_json(
            "POST", f"/resources/{self.resource_id}/license", {"source": "s"}
        )
        call_json(
            "POST", f"/resources/{self.resource_id}/license",
            {"spdx_id": ""},
        )
        call_json("POST", f"/resources/{self.resource_id}/license", b"nope")
        call_json("GET", "/resources/missing/license")
        _s, _h, body = call_json(
            "GET", f"/resources/{self.resource_id}/license"
        )
        self.assertEqual(body["error"], "license_not_found")


if __name__ == "__main__":
    unittest.main()
