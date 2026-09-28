from __future__ import annotations

import io
import json
import unittest

from provenance_api.app import application, reset_state

PATH = "/component-usage"

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
COMPONENT_DIGEST = "ab" * 32
OTHER_COMPONENT_DIGEST = "cd" * 32
THIRD_COMPONENT_DIGEST = "ef" * 32


def call(
    method: str,
    path: str = PATH,
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
    path: str = PATH,
    body: bytes | str | dict[str, object] | None = None,
    *,
    query_string: str | None = None,
    content_length: int | str | None = None,
    omit_content_length: bool = False,
) -> tuple[str, list[tuple[str, str]], object]:
    status, headers, raw = call(
        method,
        path,
        body,
        query_string=query_string,
        content_length=content_length,
        omit_content_length=omit_content_length,
    )
    return status, headers, json.loads(raw.decode("utf-8"))


class ComponentUsageTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def _create(self, digest: str = DIGEST_A, name: str = "r") -> str:
        _s, _h, body = call_json(
            "POST",
            "/resources",
            {"name": name, "category": "code", "digest": digest},
        )
        return str(body["id"])  # type: ignore[index]

    def _component(
        self,
        name: str,
        version: str,
        digest: str = COMPONENT_DIGEST,
    ) -> dict[str, str]:
        return {"name": name, "version": version, "digest": digest}

    def _sbom(
        self,
        resource_id: str,
        components: list[dict[str, str]] | None = None,
    ) -> None:
        if components is None:
            components = [self._component("openssl", "3.0.0")]
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/sbom",
            {"format": "spdx", "components": components},
        )
        assert status == "201 Created", body

    def _summary(
        self, query_string: str | None = None
    ) -> tuple[str, list[tuple[str, str]], list[dict[str, object]]]:
        status, headers, body = call_json(
            "GET", PATH, query_string=query_string
        )
        self.assertEqual(status, "200 OK")
        self.assertIsInstance(body, list)
        return status, headers, body  # type: ignore[return-value]

    # --- Shape -------------------------------------------------------------

    def test_empty_when_no_resources(self) -> None:
        status, headers, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )

    def test_empty_when_no_sboms(self) -> None:
        self._create(DIGEST_A, "r1")
        self._create(DIGEST_B, "r2")
        _s, _h, body = self._summary()
        self.assertEqual(body, [])

    def test_record_keys_and_order(self) -> None:
        resource_id = self._create()
        self._sbom(resource_id, [self._component("openssl", "3.0.0")])

        status, _h, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        text = raw.decode("utf-8").rstrip("\n")
        # Compact UTF-8: no added whitespace.
        self.assertNotIn(" ", text)
        keys = ['"name"', '"versions"', '"resources"', '"resource_count"']
        positions = [text.index(key) for key in keys]
        self.assertEqual(positions, sorted(positions))

        _s, _h, body = self._summary()
        self.assertEqual(
            list(body[0]),
            ["name", "versions", "resources", "resource_count"],
        )
        self.assertEqual(body[0]["name"], "openssl")
        self.assertEqual(body[0]["versions"], ["3.0.0"])
        self.assertEqual(body[0]["resources"], [resource_id])
        self.assertEqual(body[0]["resource_count"], 1)

    def test_name_echoed_verbatim(self) -> None:
        resource_id = self._create()
        self._sbom(
            resource_id,
            [self._component("OpenSSL ", " 3.0.0-RC ", "AB" * 32)],
        )
        _s, _h, body = self._summary()
        self.assertEqual(body[0]["name"], "OpenSSL ")
        self.assertEqual(body[0]["versions"], [" 3.0.0-RC "])

    def test_resource_count_matches_resources_length(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        self._sbom(r1, [self._component("openssl", "1")])
        self._sbom(r2, [self._component("openssl", "2")])
        _s, _h, body = self._summary()
        self.assertEqual(body[0]["resources"], [r1, r2])
        self.assertEqual(body[0]["resource_count"], 2)

    def test_response_is_utf8_and_newline_terminated(self) -> None:
        resource_id = self._create()
        self._sbom(resource_id, [self._component("组件", "1")])
        status, _headers, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertTrue(raw.endswith(b"\n"))
        raw.decode("utf-8")

    # --- Grouping, ordering and skipping -----------------------------------

    def test_one_entry_per_component_name(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        self._sbom(
            r1,
            [
                self._component("openssl", "3.0.0", "ab" * 32),
                self._component("zlib", "1.2.11", "cd" * 32),
                self._component("openssl", "3.0.1", "ef" * 32),
            ],
        )
        self._sbom(
            r2,
            [
                self._component("openssl", "3.0.0", "12" * 32),
                self._component("zlib", "1.2.12", "34" * 32),
            ],
        )

        _s, _h, body = self._summary()
        self.assertEqual(
            [entry["name"] for entry in body], ["openssl", "zlib"]
        )
        openssl = body[0]
        self.assertEqual(openssl["versions"], ["3.0.0", "3.0.1"])
        self.assertEqual(openssl["resources"], [r1, r2])
        self.assertEqual(openssl["resource_count"], 2)
        zlib = body[1]
        self.assertEqual(zlib["versions"], ["1.2.11", "1.2.12"])
        self.assertEqual(zlib["resources"], [r1, r2])
        self.assertEqual(zlib["resource_count"], 2)

    def test_versions_dedupe_by_first_occurrence(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        # The same version recurs later (in another resource and under a
        # different digest); it must appear only once, in first-seen order.
        self._sbom(
            r1,
            [
                self._component("lib", "2.0", "ab" * 32),
                self._component("lib", "1.0", "cd" * 32),
            ],
        )
        self._sbom(
            r2,
            [
                self._component("lib", "2.0", "ef" * 32),
                self._component("lib", "3.0", "12" * 32),
            ],
        )
        _s, _h, body = self._summary()
        self.assertEqual(body[0]["versions"], ["2.0", "1.0", "3.0"])

    def test_entries_follow_component_name_first_appearance(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")

        # SBOMs are registered in the opposite resource order; the summary
        # must still unfold r1's components first.
        self._sbom(r2, [self._component("zeta", "1", "cd" * 32)])
        self._sbom(
            r1,
            [
                self._component("alpha", "1", "ab" * 32),
                self._component("mid", "2", "ef" * 32),
            ],
        )

        _s, _h, body = self._summary()
        self.assertEqual(
            [entry["name"] for entry in body], ["alpha", "mid", "zeta"]
        )
        self.assertEqual(body[0]["resources"], [r1])
        self.assertEqual(body[2]["resources"], [r2])

    def test_resources_keep_registration_order_within_entry(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        r3 = self._create(DIGEST_C, "r3")
        # SBOMs are registered out of resource order; the traversal still
        # walks resources in registration order.
        self._sbom(r3, [self._component("openssl", "3", "ef" * 32)])
        self._sbom(r1, [self._component("openssl", "1", "ab" * 32)])
        self._sbom(r2, [self._component("openssl", "2", "cd" * 32)])

        _s, _h, body = self._summary()
        self.assertEqual(body[0]["resources"], [r1, r2, r3])
        # Traversal follows resource registration order, not SBOM
        # registration order, so versions are first-seen on r1, r2, r3.
        self.assertEqual(body[0]["versions"], ["1", "2", "3"])
        self.assertEqual(body[0]["resource_count"], 3)

    def test_resources_without_sbom_are_skipped_silently(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        self._create(DIGEST_B, "r2")
        self._sbom(r1)
        _s, _h, body = self._summary()
        self.assertEqual(
            [(entry["name"], entry["resources"]) for entry in body],
            [("openssl", [r1])],
        )

    def test_empty_component_list_yields_no_entries(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        self._sbom(r1, [])
        self._sbom(r2, [self._component("lib", "1")])
        _s, _h, body = self._summary()
        self.assertEqual(
            [entry["name"] for entry in body],
            ["lib"],
        )

    def test_resource_with_repeated_components_counts_once(self) -> None:
        resource_id = self._create()
        self._sbom(
            resource_id,
            [
                self._component("openssl", "3.0.0", "ab" * 32),
                self._component("openssl", "3.0.0", "cd" * 32),
            ],
        )
        _s, _h, body = self._summary()
        self.assertEqual(body[0]["versions"], ["3.0.0"])
        self.assertEqual(body[0]["resources"], [resource_id])
        self.assertEqual(body[0]["resource_count"], 1)

    # --- Name filter --------------------------------------------------------

    def test_name_filter_matches_exactly(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        self._sbom(
            r1,
            [
                self._component("openssl", "1", "ab" * 32),
                self._component("zlib", "2", "cd" * 32),
            ],
        )
        self._sbom(
            r2, [self._component("openssl", "3", "ef" * 32)]
        )

        _s, _h, body = self._summary("name=openssl")
        self.assertEqual([entry["name"] for entry in body], ["openssl"])
        self.assertEqual(body[0]["resources"], [r1, r2])
        self.assertEqual(body[0]["versions"], ["1", "3"])

    def test_name_filter_is_case_sensitive_and_untrimmed(self) -> None:
        resource_id = self._create()
        self._sbom(resource_id, [self._component("openssl", "1")])
        for query in ("name=OpenSSL", "name=OPENSSL", "name=%20openssl",
                      "name=openssl%20"):
            with self.subTest(query=query):
                _s, _h, body = self._summary(query)
                self.assertEqual(body, [])

    def test_name_filter_without_hits_returns_empty_array(self) -> None:
        resource_id = self._create()
        self._sbom(resource_id, [self._component("openssl", "1")])
        status, _h, raw = call("GET", PATH, query_string="name=nope")
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

    def test_unknown_repeated_bare_or_empty_name_rejected(self) -> None:
        resource_id = self._create()
        self._sbom(resource_id)
        for query in (
            "bogus=1",
            "x=",
            "name=openssl&bogus=1",
            "name=openssl&name=zlib",
            "name=",
            "name",  # bare parameter with no assignment
        ):
            with self.subTest(query=query):
                status, _h, body = call_json("GET", PATH, query_string=query)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    # --- Recomputation and read-only behavior -------------------------------

    def test_recomputes_after_sbom_registration(self) -> None:
        resource_id = self._create()
        _s, _h, body = self._summary()
        self.assertEqual(body, [])

        self._sbom(resource_id, [self._component("lib", "1")])
        _s, _h, body = self._summary()
        self.assertEqual(
            [entry["name"] for entry in body],
            ["lib"],
        )

    def test_resource_deregistration_shrinks_and_drops_entries(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        r3 = self._create(DIGEST_C, "r3")
        self._sbom(r1, [self._component("a", "1", "ab" * 32)])
        self._sbom(r2, [self._component("a", "2", "cd" * 32)])
        self._sbom(r3, [self._component("b", "1", "ef" * 32)])

        status, _h, _b = call_json("DELETE", f"/resources/{r2}")
        self.assertEqual(status, "200 OK")

        _s, _h, body = self._summary()
        self.assertEqual([entry["name"] for entry in body], ["a", "b"])
        self.assertEqual(body[0]["versions"], ["1"])
        self.assertEqual(body[0]["resources"], [r1])
        self.assertEqual(body[0]["resource_count"], 1)

        status, _h, _b = call_json("DELETE", f"/resources/{r1}")
        self.assertEqual(status, "200 OK")

        _s, _h, body = self._summary()
        self.assertEqual(
            [
                (entry["name"], entry["resources"])
                for entry in body
            ],
            [("b", [r3])],
        )

    def test_view_is_read_only(self) -> None:
        resource_id = self._create()
        self._sbom(resource_id, [self._component("lib", "1")])
        first_status, _h, first = call("GET", PATH)
        second_status, _h, second = call("GET", PATH)
        self.assertEqual(first_status, second_status)
        self.assertEqual(first, second)

        _s, _h, sbom = call_json("GET", f"/resources/{resource_id}/sbom")
        self.assertEqual(len(sbom["components"]), 1)

    def test_existing_views_unchanged(self) -> None:
        resource_id = self._create()
        self._sbom(resource_id, [self._component("lib", "1")])

        self._summary()
        status, _h, sbom = call_json(
            "GET", f"/resources/{resource_id}/sbom"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            sbom["components"],
            [{"name": "lib", "version": "1", "digest": COMPONENT_DIGEST}],
        )
        status, _h, inventory = call_json("GET", "/component-inventory")
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(inventory), 1)
        status, _h, licenses = call_json("GET", "/component-licenses")
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(licenses), 1)
        status, _h, risks = call_json(
            "GET", f"/resources/{resource_id}/component-risks"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(risks["components"]), 1)
        status, _h, fixes = call_json(
            "GET", f"/resources/{resource_id}/component-fixes"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(fixes["fixes"]), 1)

    # --- Errors --------------------------------------------------------------

    def test_non_get_methods_return_405_with_allow_get(self) -> None:
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            with self.subTest(method=method):
                status, headers, body = call_json(method, PATH)
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")
                allow_values = [
                    value for name, value in headers if name == "Allow"
                ]
                self.assertEqual(allow_values, ["GET"])

    def test_non_empty_body_rejected(self) -> None:
        for kwargs in (
            {"body": b"{}"},
            {"body": b"", "content_length": 3},
            {"body": b"", "content_length": "abc"},
        ):
            with self.subTest(kwargs=kwargs):
                status, _h, raw = call("GET", PATH, **kwargs)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(
                    json.loads(raw)["error"], "invalid_request"
                )
                self.assertTrue(raw.endswith(b"\n"))

    def test_empty_body_accepted(self) -> None:
        status, _h, raw = call("GET", PATH, omit_content_length=True)
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

        status, _h, raw = call("GET", PATH, body=b"", content_length=0)
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

        status, _h, raw = call("GET", PATH, body=b"", content_length="")
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

    def test_bad_request_does_not_read_business_data(self) -> None:
        resource_id = self._create()
        self._sbom(resource_id)
        # A valid name alongside an unknown parameter is 400 regardless of
        # whether the data would match.
        status, _h, body = call_json(
            "GET", PATH, query_string="name=openssl&x=1"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_error_body_uses_existing_shape(self) -> None:
        status, _h, raw = call("GET", PATH, query_string="x=1")
        self.assertEqual(status, "400 Bad Request")
        self.assertTrue(raw.endswith(b"\n"))
        text = raw.decode("utf-8").rstrip("\n")
        decoded = json.loads(text)
        self.assertEqual(set(decoded), {"error", "message"})
        self.assertEqual(decoded["error"], "invalid_request")
        self.assertEqual(
            text,
            json.dumps(decoded, ensure_ascii=False, separators=(",", ":")),
        )


if __name__ == "__main__":
    unittest.main()
