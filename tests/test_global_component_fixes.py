from __future__ import annotations

import io
import json
import unittest

from provenance_api.app import application, reset_state

PATH = "/component-fixes"

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_D = "d" * 64


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
    environ["CONTENT_TYPE"] = "application/json"
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


class GlobalComponentFixesTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        _s, _h, first = call_json(
            "POST",
            "/resources",
            {"name": "r1", "category": "code", "digest": DIGEST_A},
        )
        _s, _h, second = call_json(
            "POST",
            "/resources",
            {"name": "r2", "category": "code", "digest": DIGEST_B},
        )
        _s, _h, third = call_json(
            "POST",
            "/resources",
            {"name": "r3", "category": "code", "digest": DIGEST_C},
        )
        self.r1 = str(first["id"])
        self.r2 = str(second["id"])
        self.r3 = str(third["id"])

    def _component(
        self, name: str, version: str, digest: str = DIGEST_D
    ) -> dict[str, str]:
        return {"name": name, "version": version, "digest": digest}

    def _sbom(
        self,
        resource_id: str,
        components: list[dict[str, str]],
        document_format: str = "spdx",
    ) -> None:
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/sbom",
            {"format": document_format, "components": components},
        )
        self.assertEqual(status, "201 Created", body)

    def _alert(
        self,
        resource_id: str,
        *,
        advisory: str,
        component: str,
        severity: str = "high",
        summary: str = "a bug",
        fixed_version: str | None = None,
    ) -> None:
        payload: dict[str, object] = {
            "advisory": advisory,
            "component": component,
            "severity": severity,
            "summary": summary,
        }
        if fixed_version is not None:
            payload["fixed_version"] = fixed_version
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/vulnerabilities",
            payload,
        )
        self.assertEqual(status, "201 Created", body)

    def _summary(
        self, query_string: str | None = None
    ) -> list[dict[str, object]]:
        status, headers, raw = call("GET", PATH, query_string=query_string)
        self.assertEqual(status, "200 OK")
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )
        self.assertTrue(raw.endswith(b"\n"))
        body = json.loads(raw)
        self.assertIsInstance(body, list)
        return body  # type: ignore[return-value]

    # --- Shape -------------------------------------------------------------

    def test_empty_when_no_resources(self) -> None:
        reset_state()
        status, headers, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )

    def test_empty_when_no_sboms(self) -> None:
        self.assertEqual(self._summary(), [])

    def test_entry_keys_are_resource_id_then_per_resource_fields(self) -> None:
        self._sbom(self.r1, [self._component("openssl", "3.0.0")])
        self._alert(
            self.r1, advisory="CVE-1", component="openssl",
            fixed_version="3.0.10",
        )

        status, _h, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        text = raw.decode("utf-8").rstrip("\n")
        # Compact UTF-8: no added whitespace anywhere.
        self.assertNotIn(" ", text)
        quoted_keys = [
            '"resource_id"',
            '"name"',
            '"version"',
            '"recommended_version"',
            '"advisory_count"',
        ]
        positions = [text.index(key) for key in quoted_keys]
        self.assertEqual(positions, sorted(positions))

        entry = self._summary()[0]
        self.assertEqual(
            list(entry),
            [
                "resource_id",
                "name",
                "version",
                "recommended_version",
                "advisory_count",
            ],
        )
        self.assertEqual(
            entry,
            {
                "resource_id": self.r1,
                "name": "openssl",
                "version": "3.0.0",
                "recommended_version": "3.0.10",
                "advisory_count": 1,
            },
        )

    def test_unicode_component_name_is_compact_utf8(self) -> None:
        self._sbom(self.r1, [self._component("组件", "1")])
        status, _h, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(b" ", raw[:-1])
        raw.decode("utf-8")  # valid UTF-8
        self.assertEqual(
            json.loads(raw)[0]["name"], "组件"
        )

    def test_empty_component_list_still_yields_no_entries(self) -> None:
        self._sbom(self.r1, [])
        self._sbom(
            self.r2, [self._component("curl", "8.0")]
        )
        summary = self._summary()
        self.assertEqual(
            [(entry["resource_id"], entry["name"]) for entry in summary],
            [(self.r2, "curl")],
        )

    def test_no_alerts_yields_zero_count_and_null_recommendation(self) -> None:
        self._sbom(
            self.r1,
            [
                self._component("a", "1"),
                self._component("b", "2"),
            ],
        )
        summary = self._summary()
        self.assertEqual(
            summary,
            [
                {
                    "resource_id": self.r1,
                    "name": "a",
                    "version": "1",
                    "recommended_version": None,
                    "advisory_count": 0,
                },
                {
                    "resource_id": self.r1,
                    "name": "b",
                    "version": "2",
                    "recommended_version": None,
                    "advisory_count": 0,
                },
            ],
        )

    # --- Correlation and recommendation ------------------------------------

    def test_entries_span_all_resources_in_registration_order(self) -> None:
        self._sbom(
            self.r1,
            [
                self._component("zeta", "1", DIGEST_A),
                self._component("alpha", "2", DIGEST_B),
            ],
        )
        # SBOMs registered out of resource order; unfolding still follows
        # the resource registration order.
        self._sbom(
            self.r3,
            [self._component("curl", "8.0", DIGEST_C)],
        )
        self._sbom(
            self.r2,
            [self._component("openssl", "3.0.0", DIGEST_D)],
        )
        self._alert(
            self.r2, advisory="CVE-1", component="openssl",
            fixed_version="3.0.9",
        )
        self._alert(
            self.r2, advisory="CVE-2", component="openssl",
            fixed_version="3.0.10",
        )
        # Alerts on a component the SBOM does not list never create entries.
        self._alert(
            self.r2, advisory="CVE-X", component="unlisted",
            fixed_version="9.9.9",
        )

        summary = self._summary()
        self.assertEqual(
            [
                (entry["resource_id"], entry["name"], entry["version"])
                for entry in summary
            ],
            [
                (self.r1, "zeta", "1"),
                (self.r1, "alpha", "2"),
                (self.r2, "openssl", "3.0.0"),
                (self.r3, "curl", "8.0"),
            ],
        )
        self.assertEqual(
            [entry["advisory_count"] for entry in summary], [0, 0, 2, 0]
        )
        self.assertEqual(
            [entry["recommended_version"] for entry in summary],
            [None, None, "3.0.10", None],
        )

    def test_components_keep_sbom_submission_order_within_resource(self) -> None:
        self._sbom(
            self.r1,
            [
                self._component("zeta", "1"),
                self._component("alpha", "2"),
                self._component("mid", "3"),
            ],
        )
        self._alert(self.r1, advisory="A-1", component="alpha",
                    fixed_version="1")
        self._alert(self.r1, advisory="A-2", component="zeta",
                    fixed_version="1")
        summary = self._summary()
        self.assertEqual(
            [entry["name"] for entry in summary], ["zeta", "alpha", "mid"]
        )

    def test_advisory_count_is_not_deduplicated_or_merged(self) -> None:
        self._sbom(self.r1, [self._component("lib", "1")])
        self._alert(self.r1, advisory="A-1", component="lib",
                    fixed_version="2.0")
        self._alert(self.r1, advisory="A-2", component="lib",
                    fixed_version="2.0")
        self._alert(self.r1, advisory="A-3", component="lib")

        entry = self._summary()[0]
        self.assertEqual(entry["advisory_count"], 3)
        self.assertEqual(entry["recommended_version"], "2.0")

    def test_matching_is_case_sensitive_exact_string(self) -> None:
        self._sbom(
            self.r1,
            [
                self._component("openssl", "1"),
                self._component(" spacey", "1"),
            ],
        )
        self._alert(self.r1, advisory="A-1", component="OpenSSL",
                    fixed_version="9")
        self._alert(self.r1, advisory="A-2", component=" openssl",
                    fixed_version="9")
        self._alert(self.r1, advisory="A-3", component="spacey",
                    fixed_version="9")
        self._alert(self.r1, advisory="A-4", component=" spacey",
                    fixed_version="2.0")

        summary = self._summary()
        self.assertEqual(summary[0]["name"], "openssl")
        self.assertEqual(summary[0]["advisory_count"], 0)
        self.assertIsNone(summary[0]["recommended_version"])
        self.assertEqual(summary[1]["advisory_count"], 1)
        self.assertEqual(summary[1]["recommended_version"], "2.0")

    def test_recommended_version_uses_numeric_segment_order(self) -> None:
        self._sbom(self.r1, [self._component("lib", "1")])
        self._alert(self.r1, advisory="A-1", component="lib",
                    fixed_version="3.0.9")
        self._alert(self.r1, advisory="A-2", component="lib",
                    fixed_version="3.0.10")
        self._alert(self.r1, advisory="A-3", component="lib",
                    fixed_version="1.2")

        self.assertEqual(
            self._summary()[0]["recommended_version"], "3.0.10"
        )

    def test_non_numeric_fixed_versions_are_ignored(self) -> None:
        self._sbom(self.r1, [self._component("lib", "1")])
        self._alert(self.r1, advisory="A-1", component="lib",
                    fixed_version="9.9.9-rc")
        self._alert(self.r1, advisory="A-2", component="lib",
                    fixed_version="v2")
        self._alert(self.r1, advisory="A-3", component="lib")

        entry = self._summary()[0]
        self.assertEqual(entry["advisory_count"], 3)
        self.assertIsNone(entry["recommended_version"])

        self._alert(self.r1, advisory="A-4", component="lib",
                    fixed_version="1.0")
        self.assertEqual(
            self._summary()[0]["recommended_version"], "1.0"
        )

    def test_alerts_are_scoped_per_resource(self) -> None:
        self._sbom(self.r1, [self._component("openssl", "1")])
        self._sbom(self.r2, [self._component("openssl", "2")])
        self._alert(self.r2, advisory="A-1", component="openssl",
                    fixed_version="9.0")

        summary = self._summary()
        r1_entry = next(entry for entry in summary if entry["resource_id"] == self.r1)
        r2_entry = next(entry for entry in summary if entry["resource_id"] == self.r2)
        self.assertEqual(r1_entry["advisory_count"], 0)
        self.assertIsNone(r1_entry["recommended_version"])
        self.assertEqual(r2_entry["advisory_count"], 1)
        self.assertEqual(r2_entry["recommended_version"], "9.0")

    def test_resources_without_sbom_are_skipped_entirely(self) -> None:
        self._sbom(self.r1, [self._component("lib", "1")])
        # r2 has no SBOM at all; an alert on it must not surface an entry.
        self._alert(self.r2, advisory="A-1", component="lib",
                    fixed_version="9.0")

        summary = self._summary()
        self.assertEqual([entry["resource_id"] for entry in summary], [self.r1])

    # --- Name filter -------------------------------------------------------

    def test_name_filter_matches_exactly(self) -> None:
        self._sbom(
            self.r1,
            [
                self._component("openssl", "1"),
                self._component("curl", "2"),
            ],
        )
        self._sbom(
            self.r2,
            [self._component("openssl", "3")],
        )
        self._alert(self.r1, advisory="A-1", component="openssl",
                    fixed_version="2")

        summary = self._summary("name=openssl")
        self.assertEqual(
            [(entry["resource_id"], entry["name"]) for entry in summary],
            [(self.r1, "openssl"), (self.r2, "openssl")],
        )
        self.assertEqual(
            [entry["advisory_count"] for entry in summary], [1, 0]
        )

    def test_name_filter_is_case_sensitive_and_untrimmed(self) -> None:
        self._sbom(self.r1, [self._component("openssl", "1")])
        for query in ("name=OpenSSL", "name=%20openssl", "name=openssl%20"):
            with self.subTest(query=query):
                status, _h, raw = call(
                    "GET", PATH, query_string=query
                )
                self.assertEqual(status, "200 OK")
                self.assertEqual(raw, b"[]\n")

    def test_name_filter_without_hits_returns_empty_array(self) -> None:
        self._sbom(self.r1, [self._component("lib", "1")])
        status, _h, raw = call("GET", PATH, query_string="name=nope")
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

    def test_name_filter_keeps_name_value_untrimmed(self) -> None:
        self._sbom(self.r1, [self._component(" lib ", "1")])
        summary = self._summary("name=%20lib%20")
        self.assertEqual(len(summary), 1)
        self.assertEqual(summary[0]["name"], " lib ")

    def test_unknown_repeated_or_empty_name_rejected(self) -> None:
        self._sbom(self.r1, [self._component("lib", "1")])
        for query in (
            "bogus=1",
            "x=",
            "name=lib&bogus=1",
            "name=lib&name=curl",
            "name=",
        ):
            with self.subTest(query=query):
                status, _h, body = call_json(
                    "GET", PATH, query_string=query
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    # --- Recomputation and read-only behavior ------------------------------

    def test_recomputes_after_sbom_registration_and_alert_changes(self) -> None:
        self._sbom(self.r1, [self._component("lib", "1")])
        self.assertEqual(self._summary()[0]["advisory_count"], 0)

        self._alert(self.r1, advisory="A-1", component="lib",
                    fixed_version="2")
        entry = self._summary()[0]
        self.assertEqual(entry["advisory_count"], 1)
        self.assertEqual(entry["recommended_version"], "2")

        # Deleting the alert drops the hit immediately.
        status, _h, alerts = call_json(
            "GET", f"/resources/{self.r1}/vulnerabilities"
        )
        alert_id = str(alerts["vulnerabilities"][0]["id"])
        status, _h, _b = call_json(
            "DELETE", f"/resources/{self.r1}/vulnerabilities/{alert_id}"
        )
        self.assertEqual(status, "200 OK")
        entry = self._summary()[0]
        self.assertEqual(entry["advisory_count"], 0)
        self.assertIsNone(entry["recommended_version"])

    def test_resource_deregistration_removes_its_entries_keeps_rest(self) -> None:
        self._sbom(self.r1, [self._component("a", "1")])
        self._sbom(self.r2, [self._component("b", "2")])
        self._sbom(self.r3, [self._component("c", "3")])

        status, _h, _b = call("DELETE", f"/resources/{self.r2}")
        self.assertEqual(status, "200 OK")

        summary = self._summary()
        self.assertEqual(
            [(entry["resource_id"], entry["name"]) for entry in summary],
            [(self.r1, "a"), (self.r3, "c")],
        )

    def test_view_is_read_only(self) -> None:
        self._sbom(self.r1, [self._component("lib", "1")])
        self._alert(self.r1, advisory="A-1", component="lib",
                    fixed_version="2")
        first_status, _h, first = call("GET", PATH)
        second_status, _h, second = call("GET", PATH)
        self.assertEqual(first_status, second_status)
        self.assertEqual(first, second)

    def test_per_resource_views_unchanged(self) -> None:
        self._sbom(
            self.r1,
            [
                self._component("openssl", "3.0.0"),
                self._component("curl", "8.0"),
            ],
        )
        self._alert(self.r1, advisory="A-1", component="openssl",
                    fixed_version="3.0.10")

        # Querying the global view never alters the per-resource view.
        self._summary()
        status, _h, body = call_json(
            "GET", f"/resources/{self.r1}/component-fixes"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            body["fixes"],
            [
                {
                    "name": "openssl",
                    "version": "3.0.0",
                    "recommended_version": "3.0.10",
                    "advisory_count": 1,
                },
                {
                    "name": "curl",
                    "version": "8.0",
                    "recommended_version": None,
                    "advisory_count": 0,
                },
            ],
        )

    # --- Errors ------------------------------------------------------------

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

    def test_non_empty_or_malformed_body_rejected(self) -> None:
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
        # Omitted Content-Length and an explicit zero length are both fine.
        status, _h, raw = call("GET", PATH, omit_content_length=True)
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

        status, _h, raw = call("GET", PATH, body=b"", content_length=0)
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

        # An empty-string Content-Length (as some WSGI servers seed it) is
        # treated the same as an omitted header.
        status, _h, raw = call("GET", PATH, body=b"", content_length="")
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

    def test_bad_request_does_not_read_business_data(self) -> None:
        self._sbom(self.r1, [self._component("lib", "1")])
        # A malformed request is rejected even though the name itself would
        # match and data exists.
        status, _h, body = call_json(
            "GET", PATH, query_string="name=lib&bogus=1"
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
        # Compact separators: re-dumping with the service's separators
        # reproduces the body byte-for-byte.
        self.assertEqual(
            text,
            json.dumps(decoded, ensure_ascii=False, separators=(",", ":")),
        )


if __name__ == "__main__":
    unittest.main()
