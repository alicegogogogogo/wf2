from __future__ import annotations

import io
import json
import unittest

from provenance_api.app import application, reset_state

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


class ComponentRiskTests(unittest.TestCase):
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
    ) -> dict[str, object]:
        status, _h, body = call_json(
            "POST",
            f"/resources/{self.resource_id if resource_id is None else resource_id}/vulnerabilities",
            {
                "advisory": advisory,
                "component": component,
                "severity": severity,
                "summary": summary,
            },
        )
        self.assertEqual(status, "201 Created")
        return body

    def _risks(
        self, resource_id: str | None = None, **kwargs: object
    ) -> tuple[str, list[tuple[str, str]], dict[str, object]]:
        return call_json(
            "GET",
            f"/resources/{self.resource_id if resource_id is None else resource_id}/component-risks",
            **kwargs,
        )

    # --- Correlation -------------------------------------------------------

    def test_components_correlated_with_alerts_by_exact_name(self) -> None:
        self._sbom(
            [
                self._component("openssl", "3.0.0", DIGEST_A),
                self._component("zlib", "1.2.11", DIGEST_B),
                self._component("curl", "8.0", DIGEST_C),
            ]
        )
        a1 = self._alert(advisory="CVE-1", component="openssl", severity="HIGH")
        a2 = self._alert(advisory="CVE-2", component="zlib", severity="low")
        a3 = self._alert(advisory="CVE-3", component="openssl", severity="critical")
        # An alert for a component the SBOM does not list is dropped.
        self._alert(advisory="CVE-X", component="unlisted")

        status, _h, body = self._risks()

        self.assertEqual(status, "200 OK")
        self.assertEqual(set(body), {"components"})
        self.assertEqual(
            body["components"],
            [
                {
                    "name": "openssl",
                    "version": "3.0.0",
                    "digest": DIGEST_A,
                    "advisories": [
                        {"id": a1["id"], "severity": "high"},
                        {"id": a3["id"], "severity": "critical"},
                    ],
                },
                {
                    "name": "zlib",
                    "version": "1.2.11",
                    "digest": DIGEST_B,
                    "advisories": [
                        {"id": a2["id"], "severity": "low"},
                    ],
                },
                {
                    "name": "curl",
                    "version": "8.0",
                    "digest": DIGEST_C,
                    "advisories": [],
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
        # Register alerts out of SBOM order; component order must not change.
        self._alert(advisory="A-1", component="alpha")
        self._alert(advisory="A-2", component="zeta")

        _s, _h, body = self._risks()
        self.assertEqual(
            [c["name"] for c in body["components"]],
            ["zeta", "alpha", "mid"],
        )

    def test_advisories_keep_alert_registration_order_without_dedup(self) -> None:
        self._sbom([self._component("lib", "1", DIGEST_A)])
        first = self._alert(advisory="A-1", component="lib", severity="low")
        second = self._alert(advisory="A-2", component="lib", severity="high")
        third = self._alert(advisory="A-3", component="lib", severity="critical")

        _s, _h, body = self._risks()
        self.assertEqual(
            body["components"][0]["advisories"],
            [
                {"id": first["id"], "severity": "low"},
                {"id": second["id"], "severity": "high"},
                {"id": third["id"], "severity": "critical"},
            ],
        )

    def test_matching_is_case_sensitive_exact_string(self) -> None:
        self._sbom(
            [
                self._component("openssl", "1", DIGEST_A),
                self._component(" spacey", "1", DIGEST_B),
            ]
        )
        # Different case and whitespace-padded names never hit.
        self._alert(advisory="A-1", component="OpenSSL")
        self._alert(advisory="A-2", component="OPENSSL")
        self._alert(advisory="A-3", component=" openssl")
        self._alert(advisory="A-4", component="spacey")
        hit = self._alert(advisory="A-5", component=" spacey")

        _s, _h, body = self._risks()
        self.assertEqual(body["components"][0]["advisories"], [])
        self.assertEqual(
            [a["id"] for a in body["components"][1]["advisories"]],
            [hit["id"]],
        )

    def test_version_and_digest_are_not_compared(self) -> None:
        # The SBOM pins version 1.0 while alerts name completely different
        # versions; only the name participates in the join.
        self._sbom([self._component("openssl", "1.0", DIGEST_A)])
        alert = self._alert(advisory="A-1", component="openssl")

        _s, _h, body = self._risks()
        self.assertEqual(
            body["components"][0]["advisories"],
            [{"id": alert["id"], "severity": "high"}],
        )

    def test_no_alerts_yields_empty_advisories(self) -> None:
        self._sbom(
            [
                self._component("a", "1", DIGEST_A),
                self._component("b", "2", DIGEST_B),
            ]
        )

        status, _h, body = self._risks()
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            [c["advisories"] for c in body["components"]], [[], []]
        )

    def test_empty_sbom_components_yields_empty_collection(self) -> None:
        self._sbom([])

        status, _h, body = self._risks()
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, {"components": []})

    def test_alerts_are_scoped_per_resource(self) -> None:
        self._sbom([self._component("openssl", "1", DIGEST_A)])
        call_json(
            "POST",
            f"/resources/{self.other_id}/sbom",
            {"format": "spdx", "components": []},
        )
        other_alert = self._alert(
            resource_id=self.other_id, advisory="A-1", component="openssl"
        )

        _s, _h, body = self._risks()
        self.assertEqual(body["components"][0]["advisories"], [])

        _s, _h, other_body = self._risks(self.other_id)
        # The other resource has an empty SBOM, so even its own alert never
        # appears here.
        self.assertEqual(other_body, {"components": []})
        self.assertTrue(other_alert["id"])

    def test_each_component_has_exactly_name_version_digest_advisories(self) -> None:
        self._sbom([self._component("lib", "1", DIGEST_A)])
        self._alert(advisory="A-1", component="lib")

        _s, _h, body = self._risks()
        component = body["components"][0]
        self.assertEqual(
            set(component), {"name", "version", "digest", "advisories"}
        )
        self.assertEqual(set(component["advisories"][0]), {"id", "severity"})

    def test_response_is_compact_utf8_newline_terminated(self) -> None:
        self._sbom([self._component("组件", "1", DIGEST_A)])
        status, _headers, raw = call(
            "GET", f"/resources/{self.resource_id}/component-risks"
        )
        self.assertEqual(status, "200 OK")
        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(b" ", raw[:-1])
        raw.decode("utf-8")  # valid UTF-8
        text = raw.decode("utf-8").rstrip("\n")
        keys = ['"name"', '"version"', '"digest"', '"advisories"']
        positions = [text.index(k) for k in keys]
        self.assertEqual(positions, sorted(positions))

    # --- Read-only ---------------------------------------------------------

    def test_query_does_not_modify_sbom_or_alerts(self) -> None:
        self._sbom([self._component("lib", "1", DIGEST_A)])
        self._alert(advisory="A-1", component="lib")

        for _ in range(2):
            status, _h, body = self._risks()
            self.assertEqual(status, "200 OK")
            self.assertEqual(len(body["components"][0]["advisories"]), 1)

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
        status, _h, body = self._risks("no-such-resource")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

    def test_resource_without_sbom_returns_404_sbom_not_found(self) -> None:
        status, _h, body = self._risks()
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "sbom_not_found")

    def test_sbom_not_found_creates_no_records(self) -> None:
        for _ in range(2):
            self._risks()
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
            "GET", "/resources//component-risks"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_id_with_separator_returns_400(self) -> None:
        for raw in ("a/b", "a\\b"):
            with self.subTest(raw=raw):
                status, _h, body = call_json(
                    "GET", f"/resources/{raw}/component-risks"
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_query_parameters_return_400(self) -> None:
        for qs in ("x=1", "severity=high", "page=2"):
            with self.subTest(qs=qs):
                status, _h, body = self._risks(query_string=qs)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_non_get_methods_return_405_with_allow(self) -> None:
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, headers, body = call_json(
                    method, f"/resources/{self.resource_id}/component-risks"
                )
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")
                self.assertIn(("Allow", "GET"), headers)

    def test_bad_request_does_not_read_business_data(self) -> None:
        # A query parameter is rejected even though no resource state needs
        # to be consulted; an unknown resource with a query param is 400
        # rather than 404.
        status, _h, body = self._risks("no-such-resource", query_string="x=1")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")


if __name__ == "__main__":
    unittest.main()
