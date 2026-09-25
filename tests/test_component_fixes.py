from __future__ import annotations

import io
import json
import unittest

from provenance_api.app import application, reset_state
from provenance_api.component_fixes import (
    compare_numeric_versions,
    numeric_version_segments,
    recommended_fix_version,
)

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64


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


class NumericVersionTests(unittest.TestCase):
    def test_numeric_segments(self) -> None:
        self.assertEqual(numeric_version_segments("1.2.3"), (1, 2, 3))
        self.assertEqual(numeric_version_segments("1.02.3"), (1, 2, 3))
        self.assertIsNone(numeric_version_segments("1.2.x"))
        self.assertIsNone(numeric_version_segments("1..3"))
        self.assertIsNone(numeric_version_segments("1.2-rc"))
        self.assertIsNone(numeric_version_segments("1.2."))
        self.assertIsNone(numeric_version_segments(""))

    def test_compare_pads_shorter_with_zeros(self) -> None:
        self.assertEqual(compare_numeric_versions("1.2", "1.2.0"), 0)
        self.assertEqual(compare_numeric_versions("1.2.0.0", "1.2"), 0)
        self.assertEqual(compare_numeric_versions("2.0", "1.9.9"), 1)
        self.assertEqual(compare_numeric_versions("10.0", "9.99"), 1)
        self.assertEqual(compare_numeric_versions("1.0.1", "1.1"), -1)

    def test_recommended_picks_max_and_ignores_invalid(self) -> None:
        self.assertEqual(
            recommended_fix_version(["1.0.0", "2.0.1", "1.10.0"]), "2.0.1"
        )
        # Non-numeric and missing candidates never participate.
        self.assertEqual(
            recommended_fix_version(["1.2.x", None, "1.0", ""]), "1.0"
        )
        self.assertIsNone(recommended_fix_version([None, "abc", ""]))
        self.assertIsNone(recommended_fix_version([]))


class ComponentFixesTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        _s, _h, body = call_json(
            "POST",
            "/resources",
            {"name": "r", "category": "code", "digest": DIGEST_A},
        )
        self.resource_id = str(body["id"])
        _s, _h, other = call_json(
            "POST",
            "/resources",
            {"name": "other", "category": "code", "digest": DIGEST_B},
        )
        self.other_id = str(other["id"])

    def _component(self, name: str, version: str, digest: str) -> dict[str, str]:
        return {"name": name, "version": version, "digest": digest}

    def _sbom(self, components: list[dict[str, str]]) -> None:
        status, _h, _b = call_json(
            "POST",
            f"/resources/{self.resource_id}/sbom",
            {"format": "spdx", "components": components},
        )
        self.assertEqual(status, "201 Created")

    def _alert(
        self,
        resource_id: str | None = None,
        *,
        advisory: str,
        component: str,
        severity: str = "high",
        summary: str = "a bug",
        fixed_version: str | None = None,
    ) -> dict[str, object]:
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
            f"/resources/{self.resource_id if resource_id is None else resource_id}/vulnerabilities",
            payload,
        )
        self.assertEqual(status, "201 Created")
        return body

    def _fixes(
        self, resource_id: str | None = None, **kwargs: object
    ) -> tuple[str, list[tuple[str, str]], dict[str, object]]:
        return call_json(
            "GET",
            f"/resources/{self.resource_id if resource_id is None else resource_id}/component-fixes",
            **kwargs,
        )

    # --- Correlation and recommendation -----------------------------------

    def test_fixes_correlated_with_alerts_by_exact_name(self) -> None:
        self._sbom(
            [
                self._component("openssl", "3.0.0", DIGEST_A),
                self._component("zlib", "1.2.11", DIGEST_B),
                self._component("curl", "8.0", DIGEST_C),
            ]
        )
        self._alert(advisory="CVE-1", component="openssl",
                    fixed_version="3.0.9")
        self._alert(advisory="CVE-2", component="zlib", severity="low",
                    fixed_version="1.3.0")
        self._alert(advisory="CVE-3", component="openssl", severity="critical",
                    fixed_version="3.0.10")
        # An alert for a component the SBOM does not list is dropped.
        self._alert(advisory="CVE-X", component="unlisted",
                    fixed_version="9.9.9")

        status, _h, body = self._fixes()

        self.assertEqual(status, "200 OK")
        self.assertEqual(set(body), {"fixes"})
        self.assertEqual(
            body["fixes"],
            [
                {
                    "name": "openssl",
                    "version": "3.0.0",
                    "recommended_version": "3.0.10",
                    "advisory_count": 2,
                },
                {
                    "name": "zlib",
                    "version": "1.2.11",
                    "recommended_version": "1.3.0",
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

    def test_components_keep_sbom_submission_order(self) -> None:
        self._sbom(
            [
                self._component("zeta", "1", DIGEST_A),
                self._component("alpha", "2", DIGEST_B),
                self._component("mid", "3", DIGEST_C),
            ]
        )
        self._alert(advisory="A-1", component="alpha", fixed_version="1")
        self._alert(advisory="A-2", component="zeta", fixed_version="1")

        _s, _h, body = self._fixes()
        self.assertEqual(
            [c["name"] for c in body["fixes"]],
            ["zeta", "alpha", "mid"],
        )

    def test_advisory_count_is_not_deduplicated_or_merged(self) -> None:
        self._sbom([self._component("lib", "1", DIGEST_A)])
        self._alert(advisory="A-1", component="lib", fixed_version="2.0")
        self._alert(advisory="A-2", component="lib", fixed_version="2.0")
        self._alert(advisory="A-3", component="lib")

        _s, _h, body = self._fixes()
        self.assertEqual(body["fixes"][0]["advisory_count"], 3)
        self.assertEqual(body["fixes"][0]["recommended_version"], "2.0")

    def test_matching_is_case_sensitive_exact_string(self) -> None:
        self._sbom(
            [
                self._component("openssl", "1", DIGEST_A),
                self._component(" spacey", "1", DIGEST_B),
            ]
        )
        self._alert(advisory="A-1", component="OpenSSL", fixed_version="9")
        self._alert(advisory="A-2", component=" openssl", fixed_version="9")
        self._alert(advisory="A-3", component="spacey", fixed_version="9")
        self._alert(advisory="A-4", component=" spacey", fixed_version="2.0")

        _s, _h, body = self._fixes()
        self.assertEqual(body["fixes"][0]["advisory_count"], 0)
        self.assertIsNone(body["fixes"][0]["recommended_version"])
        self.assertEqual(body["fixes"][1]["advisory_count"], 1)
        self.assertEqual(body["fixes"][1]["recommended_version"], "2.0")

    def test_version_and_summary_do_not_participate_in_match(self) -> None:
        self._sbom([self._component("openssl", "1.0", DIGEST_A)])
        self._alert(advisory="A-1", component="openssl",
                    summary="totally different", fixed_version="3.0.9")

        _s, _h, body = self._fixes()
        self.assertEqual(body["fixes"][0]["advisory_count"], 1)
        self.assertEqual(body["fixes"][0]["recommended_version"], "3.0.9")

    def test_recommended_version_uses_numeric_segment_order(self) -> None:
        self._sbom([self._component("lib", "1", DIGEST_A)])
        # 3.0.10 must beat 3.0.9; 1.2 must lose to 1.2.0-equivalent 1.2.1.
        self._alert(advisory="A-1", component="lib", fixed_version="3.0.9")
        self._alert(advisory="A-2", component="lib", fixed_version="3.0.10")
        self._alert(advisory="A-3", component="lib", fixed_version="1.2")

        _s, _h, body = self._fixes()
        self.assertEqual(body["fixes"][0]["recommended_version"], "3.0.10")

    def test_non_numeric_fixed_versions_are_ignored(self) -> None:
        self._sbom([self._component("lib", "1", DIGEST_A)])
        self._alert(advisory="A-1", component="lib", fixed_version="9.9.9-rc")
        self._alert(advisory="A-2", component="lib", fixed_version="v2")
        self._alert(advisory="A-3", component="lib")

        _s, _h, body = self._fixes()
        self.assertEqual(body["fixes"][0]["advisory_count"], 3)
        self.assertIsNone(body["fixes"][0]["recommended_version"])

        # A valid candidate still wins over otherwise higher-looking junk.
        self._alert(advisory="A-4", component="lib", fixed_version="1.0")
        _s, _h, body = self._fixes()
        self.assertEqual(body["fixes"][0]["recommended_version"], "1.0")

    def test_no_alerts_yields_zero_count_and_null_recommendation(self) -> None:
        self._sbom(
            [
                self._component("a", "1", DIGEST_A),
                self._component("b", "2", DIGEST_B),
            ]
        )

        status, _h, body = self._fixes()
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            body["fixes"],
            [
                {"name": "a", "version": "1", "recommended_version": None,
                 "advisory_count": 0},
                {"name": "b", "version": "2", "recommended_version": None,
                 "advisory_count": 0},
            ],
        )

    def test_empty_sbom_components_yields_empty_collection(self) -> None:
        self._sbom([])

        status, _h, body = self._fixes()
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, {"fixes": []})

    def test_alerts_are_scoped_per_resource(self) -> None:
        self._sbom([self._component("openssl", "1", DIGEST_A)])
        call_json(
            "POST",
            f"/resources/{self.other_id}/sbom",
            {"format": "spdx", "components": []},
        )
        self._alert(resource_id=self.other_id, advisory="A-1",
                    component="openssl", fixed_version="9.0")

        _s, _h, body = self._fixes()
        self.assertEqual(body["fixes"][0]["advisory_count"], 0)
        self.assertIsNone(body["fixes"][0]["recommended_version"])

        _s, _h, other_body = self._fixes(self.other_id)
        self.assertEqual(other_body, {"fixes": []})

    def test_each_fix_has_exactly_name_version_recommended_count(self) -> None:
        self._sbom([self._component("lib", "1", DIGEST_A)])
        self._alert(advisory="A-1", component="lib", fixed_version="2")

        _s, _h, body = self._fixes()
        self.assertEqual(
            set(body["fixes"][0]),
            {"name", "version", "recommended_version", "advisory_count"},
        )

    def test_response_is_compact_utf8_newline_terminated(self) -> None:
        self._sbom([self._component("组件", "1", DIGEST_A)])
        status, _headers, raw = call(
            "GET", f"/resources/{self.resource_id}/component-fixes"
        )
        self.assertEqual(status, "200 OK")
        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(b" ", raw[:-1])
        raw.decode("utf-8")  # valid UTF-8
        text = raw.decode("utf-8").rstrip("\n")
        keys = ['"name"', '"version"', '"recommended_version"',
                '"advisory_count"']
        positions = [text.index(k) for k in keys]
        self.assertEqual(positions, sorted(positions))

    # --- Read-only ---------------------------------------------------------

    def test_query_does_not_modify_sbom_or_alerts(self) -> None:
        self._sbom([self._component("lib", "1", DIGEST_A)])
        self._alert(advisory="A-1", component="lib", fixed_version="2")

        for _ in range(2):
            status, _h, body = self._fixes()
            self.assertEqual(status, "200 OK")
            self.assertEqual(body["fixes"][0]["advisory_count"], 1)

        _s, _h, alerts = call_json(
            "GET", f"/resources/{self.resource_id}/vulnerabilities"
        )
        self.assertEqual(len(alerts["vulnerabilities"]), 1)
        _s, _h, sbom = call_json(
            "GET", f"/resources/{self.resource_id}/sbom"
        )
        self.assertEqual(len(sbom["components"]), 1)

    # --- Errors ------------------------------------------------------------

    def test_unknown_resource_returns_404(self) -> None:
        status, _h, body = self._fixes("no-such-resource")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

    def test_resource_without_sbom_returns_404_sbom_not_found(self) -> None:
        status, _h, body = self._fixes()
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "sbom_not_found")

    def test_sbom_not_found_creates_no_records(self) -> None:
        for _ in range(2):
            self._fixes()
        _s, _h, alerts = call_json(
            "GET", f"/resources/{self.resource_id}/vulnerabilities"
        )
        self.assertEqual(alerts["vulnerabilities"], [])
        _s, _h, sbom = call_json(
            "GET", f"/resources/{self.resource_id}/sbom"
        )
        self.assertEqual(sbom["error"], "sbom_not_found")

    def test_empty_path_id_is_bad_request(self) -> None:
        status, _h, body = call_json(
            "GET", "/resources//component-fixes"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_id_with_separator_returns_400(self) -> None:
        for raw in ("a/b", "a\\b"):
            with self.subTest(raw=raw):
                status, _h, body = call_json(
                    "GET", f"/resources/{raw}/component-fixes"
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_query_parameters_return_400(self) -> None:
        for qs in ("x=1", "severity=high", "page=2"):
            with self.subTest(qs=qs):
                status, _h, body = self._fixes(query_string=qs)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_non_get_methods_return_405_with_allow(self) -> None:
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, headers, body = call_json(
                    method, f"/resources/{self.resource_id}/component-fixes"
                )
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")
                self.assertIn(("Allow", "GET"), headers)

    def test_bad_request_does_not_read_business_data(self) -> None:
        # An unknown resource with a query param is 400 rather than 404.
        status, _h, body = self._fixes("no-such-resource", query_string="x=1")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")


if __name__ == "__main__":
    unittest.main()
