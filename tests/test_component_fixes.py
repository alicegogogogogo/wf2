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


class ComponentFixTests(unittest.TestCase):
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

    # --- Correlation -------------------------------------------------------

    def test_fixes_correlated_with_alerts_by_exact_name(self) -> None:
        self._sbom(
            [
                self._component("openssl", "3.0.0", DIGEST_A),
                self._component("OpenSSL", "1.1.1", DIGEST_B),
                self._component("zlib", "1.2.13", DIGEST_C),
            ]
        )
        self._alert(
            advisory="CVE-1", component="openssl", fixed_version="3.0.1"
        )
        self._alert(
            advisory="CVE-2", component="openssl", fixed_version="3.0.2"
        )
        self._alert(advisory="CVE-3", component="OpenSSL")

        status, _h, body = self._fixes()
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            body,
            {
                "fixes": [
                    {
                        "name": "openssl",
                        "version": "3.0.0",
                        "recommended_version": "3.0.2",
                        "advisory_count": 2,
                    },
                    {
                        "name": "OpenSSL",
                        "version": "1.1.1",
                        "recommended_version": None,
                        "advisory_count": 1,
                    },
                    {
                        "name": "zlib",
                        "version": "1.2.13",
                        "recommended_version": None,
                        "advisory_count": 0,
                    },
                ]
            },
        )

    def test_components_keep_sbom_submission_order(self) -> None:
        self._sbom(
            [
                self._component("zeta", "1.0", DIGEST_A),
                self._component("alpha", "2.0", DIGEST_B),
            ]
        )
        status, _h, body = self._fixes()
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            [fix["name"] for fix in body["fixes"]], ["zeta", "alpha"]
        )

    def test_alerts_of_other_resources_are_not_counted(self) -> None:
        self._sbom([self._component("openssl", "3.0.0", DIGEST_A)])
        self._alert(
            resource_id=self.other_id,
            advisory="CVE-9",
            component="openssl",
            fixed_version="9.9.9",
        )
        status, _h, body = self._fixes()
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            body["fixes"],
            [
                {
                    "name": "openssl",
                    "version": "3.0.0",
                    "recommended_version": None,
                    "advisory_count": 0,
                }
            ],
        )

    def test_empty_sbom_and_no_alerts_still_succeed(self) -> None:
        self._sbom([])
        status, _h, body = self._fixes()
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, {"fixes": []})

    def test_no_alerts_yields_zero_counts_and_null_recommendations(self) -> None:
        self._sbom([self._component("openssl", "3.0.0", DIGEST_A)])
        status, _h, body = self._fixes()
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            body["fixes"],
            [
                {
                    "name": "openssl",
                    "version": "3.0.0",
                    "recommended_version": None,
                    "advisory_count": 0,
                }
            ],
        )

    # --- Recommended version ----------------------------------------------

    def test_recommended_version_is_numeric_maximum_not_lexicographic(self) -> None:
        self._sbom([self._component("openssl", "3.0.0", DIGEST_A)])
        self._alert(advisory="CVE-1", component="openssl", fixed_version="3.0.9")
        self._alert(advisory="CVE-2", component="openssl", fixed_version="3.0.10")
        _s, _h, body = self._fixes()
        self.assertEqual(body["fixes"][0]["recommended_version"], "3.0.10")

    def test_shorter_versions_are_zero_padded_for_comparison(self) -> None:
        self._sbom([self._component("openssl", "3.0.0", DIGEST_A)])
        self._alert(advisory="CVE-1", component="openssl", fixed_version="3.1")
        self._alert(advisory="CVE-2", component="openssl", fixed_version="3.0.9")
        _s, _h, body = self._fixes()
        self.assertEqual(body["fixes"][0]["recommended_version"], "3.1")

    def test_non_numeric_candidates_are_ignored(self) -> None:
        self._sbom([self._component("openssl", "3.0.0", DIGEST_A)])
        self._alert(
            advisory="CVE-1", component="openssl", fixed_version="9.9.9-rc1"
        )
        self._alert(advisory="CVE-2", component="openssl", fixed_version="1.2.3")
        _s, _h, body = self._fixes()
        self.assertEqual(body["fixes"][0]["recommended_version"], "1.2.3")

    def test_all_candidates_non_numeric_yields_null(self) -> None:
        self._sbom([self._component("openssl", "3.0.0", DIGEST_A)])
        self._alert(advisory="CVE-1", component="openssl", fixed_version="next")
        self._alert(advisory="CVE-2", component="openssl", fixed_version="1..2")
        _s, _h, body = self._fixes()
        self.assertEqual(body["fixes"][0]["recommended_version"], None)
        self.assertEqual(body["fixes"][0]["advisory_count"], 2)

    def test_alerts_without_fixed_version_still_count(self) -> None:
        self._sbom([self._component("openssl", "3.0.0", DIGEST_A)])
        self._alert(advisory="CVE-1", component="openssl")
        self._alert(advisory="CVE-2", component="openssl", fixed_version="3.0.5")
        _s, _h, body = self._fixes()
        self.assertEqual(body["fixes"][0]["advisory_count"], 2)
        self.assertEqual(body["fixes"][0]["recommended_version"], "3.0.5")

    # --- Response shape ----------------------------------------------------

    def test_response_is_compact_utf8_json_with_trailing_newline(self) -> None:
        self._sbom([self._component("opënssl", "3.0.0", DIGEST_A)])
        status, headers, raw = call(
            "GET", f"/resources/{self.resource_id}/component-fixes"
        )
        self.assertEqual(status, "200 OK")
        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(b": ", raw)
        self.assertIn("opënssl".encode("utf-8"), raw)
        content_types = [v for k, v in headers if k.lower() == "content-type"]
        self.assertEqual(content_types, ["application/json; charset=utf-8"])

    def test_query_is_read_only_and_repeatable(self) -> None:
        self._sbom([self._component("openssl", "3.0.0", DIGEST_A)])
        self._alert(advisory="CVE-1", component="openssl", fixed_version="3.0.1")
        first = self._fixes()
        second = self._fixes()
        self.assertEqual(first, second)
        _s, _h, alerts = call_json(
            "GET", f"/resources/{self.resource_id}/vulnerabilities"
        )
        self.assertEqual(len(alerts["vulnerabilities"]), 1)

    # --- Errors ------------------------------------------------------------

    def test_missing_resource_returns_404(self) -> None:
        status, _h, body = self._fixes("no-such-id")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

    def test_resource_without_sbom_returns_404(self) -> None:
        status, _h, body = self._fixes()
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "sbom_not_found")

    def test_empty_id_and_separators_return_400(self) -> None:
        for path in (
            "/resources//component-fixes",
            "/resources/a/b/component-fixes",
        ):
            status, _h, body = call_json("GET", path)
            self.assertEqual(status, "400 Bad Request", path)
            self.assertEqual(body["error"], "invalid_request", path)

    def test_backslash_in_id_returns_400(self) -> None:
        status, _h, body = call_json(
            "GET", "/resources/a\\b/component-fixes"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_any_query_parameter_returns_400(self) -> None:
        self._sbom([self._component("openssl", "3.0.0", DIGEST_A)])
        status, _h, body = self._fixes(query_string="severity=high")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        # The failed request must not change state: a clean query still works.
        status, _h, body = self._fixes()
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(body["fixes"]), 1)

    def test_non_get_methods_return_405(self) -> None:
        self._sbom([self._component("openssl", "3.0.0", DIGEST_A)])
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            status, headers, body = call_json(
                method, f"/resources/{self.resource_id}/component-fixes"
            )
            self.assertEqual(status, "405 Method Not Allowed", method)
            self.assertEqual(body["error"], "method_not_allowed", method)
            allow = [v for k, v in headers if k.lower() == "allow"]
            self.assertEqual(allow, ["GET"], method)


if __name__ == "__main__":
    unittest.main()
