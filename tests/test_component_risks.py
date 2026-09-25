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
        "wsgi.input": io.BytesIO(payload),
        "CONTENT_LENGTH": str(len(payload)),
        "CONTENT_TYPE": "application/json",
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


def alert_payload(
    advisory: str, component: str, severity: str = "high"
) -> dict[str, object]:
    return {
        "advisory": advisory,
        "component": component,
        "severity": severity,
        "summary": "test alert",
    }


class ComponentRisksTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        _s, _h, body = call_json(
            "POST",
            "/resources",
            {"name": "r", "category": "code", "digest": DIGEST_A},
        )
        self.resource_id = str(body["id"])

    def _view(
        self, resource_id: str | None = None, **kwargs: object
    ) -> tuple[str, list[tuple[str, str]], dict[str, object]]:
        return call_json(
            "GET",
            f"/resources/{resource_id or self.resource_id}/component-risks",
            **kwargs,
        )

    def _add_sbom(self, components: list[dict[str, str]]) -> None:
        status, _h, _b = call_json(
            "POST",
            f"/resources/{self.resource_id}/sbom",
            {"format": "spdx", "components": components},
        )
        self.assertEqual(status, "201 Created")

    def _add_alert(
        self, advisory: str, component: str, severity: str = "high"
    ) -> str:
        status, _h, body = call_json(
            "POST",
            f"/resources/{self.resource_id}/vulnerabilities",
            alert_payload(advisory, component, severity),
        )
        self.assertEqual(status, "201 Created")
        return str(body["id"])

    # --- Correlation -------------------------------------------------------

    def test_components_in_sbom_order_with_matched_advisories(self) -> None:
        self._add_sbom(
            [
                {"name": "openssl", "version": "3.0.8", "digest": DIGEST_A},
                {"name": "zlib", "version": "1.3", "digest": DIGEST_B},
                {"name": "curl", "version": "8.0", "digest": DIGEST_C},
            ]
        )
        # Registration interleaves matching and non-matching alerts.
        id_ssl_1 = self._add_alert("CVE-1", "openssl", "critical")
        self._add_alert("CVE-2", "nss", "low")
        id_ssl_2 = self._add_alert("CVE-3", "openssl", "HIGH")
        id_curl = self._add_alert("CVE-4", "curl", "medium")

        status, _h, body = self._view()

        self.assertEqual(status, "200 OK")
        self.assertEqual(
            body,
            {
                "components": [
                    {
                        "name": "openssl",
                        "version": "3.0.8",
                        "digest": DIGEST_A,
                        "advisories": [
                            {"id": id_ssl_1, "severity": "critical"},
                            {"id": id_ssl_2, "severity": "high"},
                        ],
                    },
                    {
                        "name": "zlib",
                        "version": "1.3",
                        "digest": DIGEST_B,
                        "advisories": [],
                    },
                    {
                        "name": "curl",
                        "version": "8.0",
                        "digest": DIGEST_C,
                        "advisories": [
                            {"id": id_curl, "severity": "medium"}
                        ],
                    },
                ]
            },
        )

    def test_advisories_keep_registration_order_without_dedup(self) -> None:
        # The store rejects identical (advisory, component) pairs, so order
        # is exercised with distinct advisories; none may be dropped or
        # merged.
        self._add_sbom(
            [{"name": "lib", "version": "1", "digest": DIGEST_A}]
        )
        first = self._add_alert("CVE-1", "lib", "low")
        second = self._add_alert("CVE-2", "lib", "low")
        third = self._add_alert("CVE-3", "lib", "low")

        _s, _h, body = self._view()
        advisories = body["components"][0]["advisories"]
        self.assertEqual(
            [item["id"] for item in advisories], [first, second, third]
        )

    def test_name_match_is_verbatim_and_case_sensitive(self) -> None:
        self._add_sbom(
            [
                {"name": "openssl", "version": "1", "digest": DIGEST_A},
                {"name": " openssl ", "version": "1", "digest": DIGEST_B},
                {"name": "OpenSSL", "version": "1", "digest": DIGEST_C},
            ]
        )
        # Each alert matches only the component whose name is identical;
        # case and surrounding whitespace keep names distinct.
        plain_id = self._add_alert("CVE-1", "openssl", "high")
        padded_id = self._add_alert("CVE-2", " openssl ", "medium")
        capital_id = self._add_alert("CVE-3", "OpenSSL", "low")

        _s, _h, body = self._view()
        components = body["components"]
        self.assertEqual(
            components[0]["advisories"],
            [{"id": plain_id, "severity": "high"}],
        )
        self.assertEqual(
            components[1]["advisories"],
            [{"id": padded_id, "severity": "medium"}],
        )
        self.assertEqual(
            components[2]["advisories"],
            [{"id": capital_id, "severity": "low"}],
        )

    def test_version_and_digest_never_participate_in_match(self) -> None:
        self._add_sbom(
            [{"name": "lib", "version": "9.9", "digest": DIGEST_A}]
        )
        # Alert carries no version/digest; name alone must still match.
        match_id = self._add_alert("CVE-1", "lib", "critical")

        _s, _h, body = self._view()
        self.assertEqual(
            body["components"][0]["advisories"],
            [{"id": match_id, "severity": "critical"}],
        )

    def test_empty_components_is_success(self) -> None:
        self._add_sbom([])
        status, _h, body = self._view()
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, {"components": []})

    def test_no_alerts_is_success_with_empty_advisories(self) -> None:
        self._add_sbom(
            [{"name": "lib", "version": "1", "digest": DIGEST_A}]
        )
        status, _h, body = self._view()
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            body,
            {
                "components": [
                    {
                        "name": "lib",
                        "version": "1",
                        "digest": DIGEST_A,
                        "advisories": [],
                    }
                ]
            },
        )

    def test_response_is_compact_utf8_with_trailing_newline(self) -> None:
        self._add_sbom(
            [{"name": "库", "version": "1", "digest": DIGEST_A}]
        )
        _s, headers, raw = call(
            "GET", f"/resources/{self.resource_id}/component-risks"
        )
        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(b" ", raw.rstrip(b"\n"))
        self.assertIn("库".encode("utf-8"), raw)
        self.assertEqual(
            dict(headers)["Content-Type"], "application/json; charset=utf-8"
        )

    # --- Errors ------------------------------------------------------------

    def test_unknown_resource_returns_404(self) -> None:
        status, _h, body = self._view("no-such-resource")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

    def test_resource_without_sbom_returns_404(self) -> None:
        status, _h, body = self._view()
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "sbom_not_found")

    def test_alerts_without_sbom_still_404(self) -> None:
        self._add_alert("CVE-1", "lib")
        status, _h, body = self._view()
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "sbom_not_found")

    def test_id_with_separator_returns_400(self) -> None:
        for path in (
            "/resources/a/b/component-risks",
            "/resources/a\\component-risks",
        ):
            with self.subTest(path=path):
                status, _h, body = call_json("GET", path)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_query_parameters_return_400(self) -> None:
        status, _h, body = self._view(query_string="severity=high")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_non_get_methods_return_405_with_allow(self) -> None:
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, headers, body = call_json(
                    method,
                    f"/resources/{self.resource_id}/component-risks",
                )
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")
                self.assertIn(("Allow", "GET"), headers)

    def test_view_is_read_only(self) -> None:
        self._add_sbom(
            [{"name": "openssl", "version": "1", "digest": DIGEST_A}]
        )
        self._add_alert("CVE-1", "openssl", "high")

        call("GET", f"/resources/{self.resource_id}/component-risks")
        call("GET", f"/resources/{self.resource_id}/component-risks")

        # Alerts and the SBOM are untouched and still answer as before.
        _s, _h, alerts = call_json(
            "GET", f"/resources/{self.resource_id}/vulnerabilities"
        )
        self.assertEqual(len(alerts["vulnerabilities"]), 1)
        _s, _h, sbom = call_json(
            "GET", f"/resources/{self.resource_id}/sbom"
        )
        self.assertEqual(len(sbom["components"]), 1)


if __name__ == "__main__":
    unittest.main()
