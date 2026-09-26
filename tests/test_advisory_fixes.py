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
    content_length: str | None = None,
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
        "CONTENT_LENGTH": (
            str(len(payload)) if content_length is None else content_length
        ),
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
    content_length: str | None = None,
) -> tuple[str, list[tuple[str, str]], object]:
    status, headers, raw = call(
        method,
        path,
        body,
        query_string=query_string,
        content_length=content_length,
    )
    return status, headers, json.loads(raw.decode("utf-8"))


class AdvisoryFixesTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.ids: dict[str, str] = {}
        for name, digest in (
            ("first", DIGEST_A),
            ("second", DIGEST_B),
            ("third", DIGEST_C),
        ):
            _s, _h, body = call_json(
                "POST",
                "/resources",
                {"name": name, "category": "code", "digest": digest},
            )
            self.ids[name] = str(body["id"])

    def _alert(
        self,
        resource: str,
        *,
        advisory: str,
        severity: str,
        component: str = "lib",
        summary: str = "a bug",
        fixed_version: str | None = None,
    ) -> str:
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
            f"/resources/{self.ids[resource]}/vulnerabilities",
            payload,
        )
        self.assertEqual(status, "201 Created")
        return str(body["id"])

    def _fixes(
        self, advisory: str, *, query_string: str | None = None
    ) -> tuple[str, list[tuple[str, str]], object]:
        return call_json(
            "GET", f"/advisories/{advisory}/fixes", query_string=query_string
        )

    # --- Shape -------------------------------------------------------------

    def test_unknown_advisory_returns_empty_success(self) -> None:
        status, headers, body = self._fixes("NOPE-1")
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, {"advisory": "NOPE-1", "fixes": []})
        self.assertEqual(
            dict(headers)["Content-Type"], "application/json; charset=utf-8"
        )

    def test_response_is_compact_utf8_single_newline(self) -> None:
        self._alert("first", advisory="A-1", severity="high")
        status, _headers, raw = call("GET", "/advisories/A-1/fixes")
        self.assertEqual(status, "200 OK")
        self.assertTrue(raw.endswith(b"\n"))
        self.assertEqual(raw.count(b"\n"), 1)
        self.assertNotIn(b" ", raw[:-1])

    def test_top_level_key_order_is_fixed(self) -> None:
        self._alert("first", advisory="A-1", severity="high")
        text = call("GET", "/advisories/A-1/fixes")[2].decode("utf-8").rstrip("\n")
        keys = ['"advisory"', '"fixes"']
        positions = [text.index(key) for key in keys]
        self.assertEqual(positions, sorted(positions))

    def test_fix_entry_key_order_is_fixed(self) -> None:
        self._alert(
            "first", advisory="A-1", severity="high", fixed_version="1.2.3"
        )
        text = call("GET", "/advisories/A-1/fixes")[2].decode("utf-8").rstrip("\n")
        entry_text = text[text.index('"fixes":[{') + len('"fixes":') :]
        keys = [
            '"name"',
            '"affected_resources"',
            '"advisory_count"',
            '"recommended_version"',
        ]
        positions = [entry_text.index(key) for key in keys]
        self.assertEqual(positions, sorted(positions))

    def test_advisory_id_is_echoed_verbatim(self) -> None:
        self._alert("first", advisory="CVE-2026-0001 ", severity="low")
        _s, _h, body = self._fixes("CVE-2026-0001 ")
        self.assertEqual(body["advisory"], "CVE-2026-0001 ")
        self.assertEqual(len(body["fixes"]), 1)

    def test_advisory_match_is_case_sensitive(self) -> None:
        self._alert("first", advisory="adv-1", severity="low")
        _s, _h, body = self._fixes("ADV-1")
        self.assertEqual(body, {"advisory": "ADV-1", "fixes": []})

    def test_component_without_hits_is_not_listed(self) -> None:
        self._alert("first", advisory="ADV-A", severity="low", component="c1")
        self._alert("first", advisory="ADV-B", severity="low", component="c2")

        _s, _h, body = self._fixes("ADV-A")
        self.assertEqual([fix["name"] for fix in body["fixes"]], ["c1"])

    # --- Ordering and grouping ---------------------------------------------

    def test_components_expand_in_resource_registration_order(self) -> None:
        # "third" submits first, but "first" was registered first.
        self._alert("third", advisory="ADV-A", severity="high", component="zc")
        self._alert("first", advisory="ADV-A", severity="low", component="ac")
        self._alert("second", advisory="ADV-A", severity="medium", component="mc")

        _s, _h, body = self._fixes("ADV-A")
        self.assertEqual(
            [fix["name"] for fix in body["fixes"]], ["ac", "mc", "zc"]
        )

    def test_within_a_resource_components_follow_alert_submission_order(self) -> None:
        self._alert("first", advisory="ADV-A", severity="low", component="zz")
        self._alert("first", advisory="ADV-A", severity="low", component="aa")

        _s, _h, body = self._fixes("ADV-A")
        self.assertEqual(
            [fix["name"] for fix in body["fixes"]], ["zz", "aa"]
        )

    def test_component_appears_once_across_resources(self) -> None:
        self._alert("first", advisory="ADV-A", severity="low", component="lib")
        self._alert("third", advisory="ADV-A", severity="high", component="lib")
        self._alert("second", advisory="ADV-A", severity="low", component="other")

        _s, _h, body = self._fixes("ADV-A")
        self.assertEqual(
            [fix["name"] for fix in body["fixes"]], ["lib", "other"]
        )
        lib = body["fixes"][0]
        self.assertEqual(lib["advisory_count"], 2)
        self.assertEqual(
            lib["affected_resources"],
            [self.ids["first"], self.ids["third"]],
        )

    def test_affected_resources_follow_registration_order_not_submission(self) -> None:
        self._alert("third", advisory="ADV-A", severity="low", component="lib")
        self._alert("first", advisory="ADV-A", severity="low", component="lib")

        _s, _h, body = self._fixes("ADV-A")
        self.assertEqual(
            body["fixes"][0]["affected_resources"],
            [self.ids["first"], self.ids["third"]],
        )

    def test_count_is_raw_alert_count_without_dedup(self) -> None:
        # A (advisory, component) pair is unique within a resource, so raw
        # counts accumulate across the contributing resources.
        self._alert("first", advisory="ADV-A", severity="low", component="lib")
        self._alert("second", advisory="ADV-A", severity="high", component="lib")
        self._alert("third", advisory="ADV-A", severity="low", component="lib")

        _s, _h, body = self._fixes("ADV-A")
        self.assertEqual(len(body["fixes"]), 1)
        self.assertEqual(body["fixes"][0]["advisory_count"], 3)
        self.assertEqual(
            body["fixes"][0]["affected_resources"],
            [self.ids["first"], self.ids["second"], self.ids["third"]],
        )

    # --- Recommended version ------------------------------------------------

    def test_recommended_version_is_greatest_numeric_candidate(self) -> None:
        self._alert(
            "first",
            advisory="ADV-A",
            severity="low",
            component="lib",
            fixed_version="1.2.3",
        )
        self._alert(
            "second",
            advisory="ADV-A",
            severity="low",
            component="lib",
            fixed_version="1.10.0",
        )
        self._alert(
            "third",
            advisory="ADV-A",
            severity="low",
            component="lib",
            fixed_version="1.2",
        )

        _s, _h, body = self._fixes("ADV-A")
        self.assertEqual(body["fixes"][0]["recommended_version"], "1.10.0")

    def test_non_numeric_and_missing_candidates_are_ignored(self) -> None:
        self._alert(
            "first",
            advisory="ADV-A",
            severity="low",
            component="lib",
            fixed_version="1.2.x",
        )
        self._alert(
            "second",
            advisory="ADV-A",
            severity="low",
            component="lib",
        )
        self._alert(
            "third",
            advisory="ADV-A",
            severity="low",
            component="lib",
            fixed_version="0.9",
        )

        _s, _h, body = self._fixes("ADV-A")
        self.assertEqual(body["fixes"][0]["recommended_version"], "0.9")

    def test_no_usable_candidate_yields_null(self) -> None:
        self._alert(
            "first",
            advisory="ADV-A",
            severity="low",
            component="lib",
            fixed_version="v1.2",
        )
        self._alert("second", advisory="ADV-A", severity="low", component="lib")

        _s, _h, body = self._fixes("ADV-A")
        self.assertIsNone(body["fixes"][0]["recommended_version"])

    # --- Severity filter ----------------------------------------------------

    def test_severity_filter_shrinks_counts_and_resources(self) -> None:
        self._alert("first", advisory="ADV-A", severity="high", component="lib")
        self._alert("second", advisory="ADV-A", severity="low", component="lib")
        self._alert("third", advisory="ADV-A", severity="low", component="other")

        _s, _h, body = self._fixes("ADV-A", query_string="severity=LOW")
        self.assertEqual(
            body["fixes"],
            [
                {
                    "name": "lib",
                    "affected_resources": [self.ids["second"]],
                    "advisory_count": 1,
                    "recommended_version": None,
                },
                {
                    "name": "other",
                    "affected_resources": [self.ids["third"]],
                    "advisory_count": 1,
                    "recommended_version": None,
                },
            ],
        )

    def test_severity_filter_is_case_insensitive(self) -> None:
        self._alert(
            "first",
            advisory="ADV-A",
            severity="HIGH",
            component="openssl",
            fixed_version="3.0.8",
        )
        _s, _h, body = self._fixes("ADV-A", query_string="severity=HIGH")
        self.assertEqual(
            body,
            {
                "advisory": "ADV-A",
                "fixes": [
                    {
                        "name": "openssl",
                        "affected_resources": [self.ids["first"]],
                        "advisory_count": 1,
                        "recommended_version": "3.0.8",
                    }
                ],
            },
        )

    def test_severity_filter_no_match_is_success_empty_array(self) -> None:
        self._alert("first", advisory="ADV-A", severity="low")
        status, _h, body = self._fixes(
            "ADV-A", query_string="severity=critical"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, {"advisory": "ADV-A", "fixes": []})

    def test_component_counts_add_up_to_summary_and_detail_counts(self) -> None:
        # Inputs span resources, components and levels so every filter drops
        # at least one alert.
        self._alert("second", advisory="ADV-B", severity="medium")
        self._alert("third", advisory="ADV-A", severity="HIGH", component="o")
        self._alert("first", advisory="ADV-A", severity="critical", component="o")
        self._alert("first", advisory="ADV-A", severity="low", component="z")
        self._alert("second", advisory="ADV-A", severity="low", component="z")

        # Independent expectations from the documented aggregation: a
        # component keeps the position of its earliest matching alert under
        # resource-registration then submission order.
        expectations = {
            None: {
                "total": 4,
                "fixes": [
                    {
                        "name": "o",
                        "affected_resources": [
                            self.ids["first"],
                            self.ids["third"],
                        ],
                        "advisory_count": 2,
                        "recommended_version": None,
                    },
                    {
                        "name": "z",
                        "affected_resources": [
                            self.ids["first"],
                            self.ids["second"],
                        ],
                        "advisory_count": 2,
                        "recommended_version": None,
                    },
                ],
            },
            "severity=LOW": {
                "total": 2,
                "fixes": [
                    {
                        "name": "z",
                        "affected_resources": [
                            self.ids["first"],
                            self.ids["second"],
                        ],
                        "advisory_count": 2,
                        "recommended_version": None,
                    },
                ],
            },
            "severity=high": {
                "total": 1,
                "fixes": [
                    {
                        "name": "o",
                        "affected_resources": [self.ids["third"]],
                        "advisory_count": 1,
                        "recommended_version": None,
                    },
                ],
            },
        }

        for query_string, expected in expectations.items():
            with self.subTest(query_string=query_string):
                _s, _h, fixes = self._fixes("ADV-A", query_string=query_string)
                self.assertEqual(fixes["fixes"], expected["fixes"])
                total = sum(fix["advisory_count"] for fix in fixes["fixes"])
                self.assertEqual(total, expected["total"])

                _s, _h, summary = call_json(
                    "GET", "/advisories", query_string=query_string
                )
                row = next(r for r in summary if r["advisory"] == "ADV-A")
                self.assertEqual(row["advisory_count"], expected["total"])

                _s, _h, detail = call_json(
                    "GET", "/advisories/ADV-A", query_string=query_string
                )
                self.assertEqual(len(detail["alerts"]), expected["total"])

    # --- Read-only / recompute ----------------------------------------------

    def test_view_reflects_updates_and_deletes_immediately(self) -> None:
        alert_id = self._alert(
            "first",
            advisory="ADV-A",
            severity="low",
            component="lib",
            fixed_version="1.0",
        )
        _s, _h, body = self._fixes("ADV-A")
        self.assertEqual(body["fixes"][0]["recommended_version"], "1.0")

        status, _h, _b = call_json(
            "PUT",
            f"/resources/{self.ids['first']}/vulnerabilities/{alert_id}",
            {
                "advisory": "ADV-A",
                "component": "lib",
                "severity": "critical",
                "summary": "now worse",
                "fixed_version": "2.0",
            },
        )
        self.assertEqual(status, "200 OK")
        _s, _h, body = self._fixes("ADV-A")
        self.assertEqual(body["fixes"][0]["recommended_version"], "2.0")
        _s, _h, filtered = self._fixes("ADV-A", query_string="severity=low")
        self.assertEqual(filtered["fixes"], [])

        status, _h, _b = call_json(
            "DELETE",
            f"/resources/{self.ids['first']}/vulnerabilities/{alert_id}",
        )
        self.assertEqual(status, "200 OK")
        _s, _h, body = self._fixes("ADV-A")
        self.assertEqual(body, {"advisory": "ADV-A", "fixes": []})

    def test_view_does_not_modify_any_state(self) -> None:
        self._alert("first", advisory="ADV-A", severity="high")
        for _ in range(2):
            status, _h, body = self._fixes("ADV-A")
            self.assertEqual(status, "200 OK")
            self.assertEqual(len(body["fixes"]), 1)
        _s, _h, alerts = call_json(
            "GET", f"/resources/{self.ids['first']}/vulnerabilities"
        )
        self.assertEqual(len(alerts["vulnerabilities"]), 1)
        _s, _h, resources = call_json("GET", "/resources")
        self.assertEqual(len(resources["resources"]), 3)

    # --- Errors --------------------------------------------------------------

    def test_non_get_methods_return_405_with_allow_get_only(self) -> None:
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, headers, body = call_json(
                    method, "/advisories/ADV-A/fixes"
                )
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")
                self.assertEqual(
                    body["message"],
                    f"Method {method} is not allowed for this path.",
                )
                self.assertEqual(dict(headers)["Allow"], "GET")

    def test_empty_advisory_id_returns_400(self) -> None:
        status, _h, body = call_json("GET", "/advisories//fixes")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        self.assertEqual(body["message"], "Advisory id must not be empty.")

    def test_advisory_id_with_path_separator_returns_400(self) -> None:
        for path in ("/advisories/A/B/fixes", "/advisories/A\\B/fixes"):
            with self.subTest(path=path):
                status, _h, body = call_json("GET", path)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")
                self.assertEqual(
                    body["message"],
                    "Advisory id must not contain path separators.",
                )

    def test_bare_fixes_segment_is_detail_view_not_fixes(self) -> None:
        # "/advisories/fixes" addresses the advisory literally named "fixes"
        # through the detail view; the fix view requires the "/fixes" suffix.
        self._alert("first", advisory="fixes", severity="low")
        status, _h, body = call_json("GET", "/advisories/fixes")
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["advisory"], "fixes")
        self.assertEqual(len(body["alerts"]), 1)

    def test_declared_non_empty_body_returns_400(self) -> None:
        status, _h, body = call_json(
            "GET", "/advisories/ADV-A/fixes", {"unexpected": True}
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        self.assertEqual(
            body["message"], "This endpoint does not accept a request body."
        )

    def test_malformed_content_length_returns_400(self) -> None:
        status, _h, body = call_json(
            "GET", "/advisories/ADV-A/fixes", content_length="abc"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        self.assertEqual(
            body["message"], "This endpoint does not accept a request body."
        )

    def test_empty_body_declared_zero_is_accepted(self) -> None:
        status, _h, body = call_json(
            "GET", "/advisories/ADV-A/fixes", body={}, content_length="0"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["fixes"], [])

    def test_unknown_query_parameter_returns_400(self) -> None:
        for qs, message in (
            ("x=1", "Unknown query parameter: 'x'."),
            ("limit=10", "Unknown query parameter: 'limit'."),
            ("severity=high&foo=bar", "Unknown query parameter: 'foo'."),
        ):
            with self.subTest(qs=qs):
                status, _h, body = self._fixes("ADV-A", query_string=qs)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")
                self.assertEqual(body["message"], message)

    def test_repeated_severity_returns_400(self) -> None:
        status, _h, body = self._fixes(
            "ADV-A", query_string="severity=high&severity=low"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        self.assertEqual(
            body["message"], "Query parameter 'severity' must not be repeated."
        )

    def test_empty_or_unknown_severity_returns_400(self) -> None:
        for qs in ("severity=", "severity=urgent", "severity=HIG"):
            with self.subTest(qs=qs):
                status, _h, body = self._fixes("ADV-A", query_string=qs)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")
                self.assertEqual(
                    body["message"],
                    "Severity must be one of: critical, high, medium, low "
                    "(case-insensitive).",
                )

    def test_bad_request_does_not_read_business_data(self) -> None:
        # A bad query parameter is rejected before aggregation; record the
        # full business state beforehand and prove it is unchanged after.
        alert_id = self._alert(
            "first", advisory="ADV-A", severity="high", component="lib"
        )
        _s, _h, before_alerts = call_json(
            "GET", f"/resources/{self.ids['first']}/vulnerabilities"
        )
        _s, _h, before_advisories = call_json("GET", "/advisories")
        _s, _h, before_resources = call_json("GET", "/resources")

        status, _h, body = self._fixes("ADV-A", query_string="severity=urgent")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        self.assertEqual(
            body["message"],
            "Severity must be one of: critical, high, medium, low "
            "(case-insensitive).",
        )

        _s, _h, after_alerts = call_json(
            "GET", f"/resources/{self.ids['first']}/vulnerabilities"
        )
        _s, _h, after_advisories = call_json("GET", "/advisories")
        _s, _h, after_resources = call_json("GET", "/resources")
        self.assertEqual(after_alerts, before_alerts)
        self.assertEqual(after_advisories, before_advisories)
        self.assertEqual(after_resources, before_resources)
        self.assertEqual(len(after_alerts["vulnerabilities"]), 1)
        self.assertEqual(after_alerts["vulnerabilities"][0]["id"], alert_id)

    def test_error_body_shape_and_newline(self) -> None:
        status, headers, raw = call(
            "GET", "/advisories/ADV-A/fixes", query_string="x=1"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(
            dict(headers)["Content-Type"], "application/json; charset=utf-8"
        )
        self.assertTrue(raw.endswith(b"\n"))
        self.assertEqual(raw.count(b"\n"), 1)
        decoded = json.loads(raw.decode("utf-8"))
        self.assertEqual(set(decoded), {"error", "message"})
        self.assertEqual(decoded["error"], "invalid_request")


if __name__ == "__main__":
    unittest.main()
