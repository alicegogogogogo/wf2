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


class AdvisoryDetailTests(unittest.TestCase):
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

    def _detail(
        self, advisory: str, *, query_string: str | None = None
    ) -> tuple[str, list[tuple[str, str]], object]:
        return call_json(
            "GET", f"/advisories/{advisory}", query_string=query_string
        )

    # --- Shape -------------------------------------------------------------

    def test_unknown_advisory_returns_empty_success(self) -> None:
        status, headers, body = self._detail("NOPE-1")
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            body,
            {"advisory": "NOPE-1", "affected_resources": [], "alerts": []},
        )
        self.assertEqual(
            dict(headers)["Content-Type"], "application/json; charset=utf-8"
        )

    def test_response_is_compact_utf8_single_newline(self) -> None:
        self._alert("first", advisory="A-1", severity="high", summary="bug")
        status, _headers, raw = call("GET", "/advisories/A-1")
        self.assertEqual(status, "200 OK")
        self.assertTrue(raw.endswith(b"\n"))
        self.assertEqual(raw.count(b"\n"), 1)
        self.assertNotIn(b" ", raw[:-1])

    def test_top_level_key_order_is_fixed(self) -> None:
        self._alert("first", advisory="A-1", severity="high")
        text = call("GET", "/advisories/A-1")[2].decode("utf-8").rstrip("\n")
        keys = ['"advisory"', '"affected_resources"', '"alerts"']
        positions = [text.index(key) for key in keys]
        self.assertEqual(positions, sorted(positions))

    def test_alert_keys_start_with_resource_id_then_record_order(self) -> None:
        self._alert(
            "first", advisory="A-1", severity="high", fixed_version="1.2.3"
        )
        text = call("GET", "/advisories/A-1")[2].decode("utf-8").rstrip("\n")
        # Restrict to the single alert object inside the alerts array.
        alert_text = text[text.index('"alerts":[{') + len('"alerts":') :]
        keys = [
            '"resource_id"',
            '"id"',
            '"advisory"',
            '"component"',
            '"severity"',
            '"summary"',
            '"fixed_version"',
        ]
        positions = [alert_text.index(key) for key in keys]
        self.assertEqual(positions, sorted(positions))

    def test_alert_echoes_full_record_and_fixed_version(self) -> None:
        alert_id = self._alert(
            "first",
            advisory="A-1",
            severity="HIGH",
            component="openssl",
            summary="buffer overflow",
            fixed_version="3.0.8",
        )
        _s, _h, body = self._detail("A-1")
        self.assertEqual(
            body["alerts"],
            [
                {
                    "resource_id": self.ids["first"],
                    "id": alert_id,
                    "advisory": "A-1",
                    "component": "openssl",
                    "severity": "high",
                    "summary": "buffer overflow",
                    "fixed_version": "3.0.8",
                }
            ],
        )

    def test_advisory_id_is_echoed_verbatim(self) -> None:
        self._alert("first", advisory="CVE-2026-0001 ", severity="low")
        _s, _h, body = self._detail("CVE-2026-0001 ")
        self.assertEqual(body["advisory"], "CVE-2026-0001 ")
        self.assertEqual(len(body["alerts"]), 1)

    def test_advisory_match_is_case_sensitive(self) -> None:
        self._alert("first", advisory="adv-1", severity="low")
        _s, _h, body = self._detail("ADV-1")
        self.assertEqual(body["alerts"], [])
        self.assertEqual(body["affected_resources"], [])

    # --- Ordering and grouping ---------------------------------------------

    def test_alerts_expand_in_resource_registration_order(self) -> None:
        # "third" submits first, but "first" was registered first.
        self._alert("third", advisory="ADV-A", severity="high")
        self._alert("first", advisory="ADV-A", severity="low")
        self._alert("second", advisory="ADV-A", severity="medium")

        _s, _h, body = self._detail("ADV-A")
        self.assertEqual(
            [alert["resource_id"] for alert in body["alerts"]],
            [self.ids["first"], self.ids["second"], self.ids["third"]],
        )
        self.assertEqual(
            body["affected_resources"],
            [self.ids["first"], self.ids["second"], self.ids["third"]],
        )

    def test_resource_block_keeps_submission_order_and_appears_once(self) -> None:
        self._alert("first", advisory="ADV-A", severity="low", component="c1")
        self._alert("second", advisory="ADV-A", severity="low", component="c2")
        self._alert("first", advisory="ADV-A", severity="high", component="c3")

        _s, _h, body = self._detail("ADV-A")
        self.assertEqual(
            [
                (alert["resource_id"], alert["component"])
                for alert in body["alerts"]
            ],
            [
                (self.ids["first"], "c1"),
                (self.ids["first"], "c3"),
                (self.ids["second"], "c2"),
            ],
        )
        self.assertEqual(
            body["affected_resources"], [self.ids["first"], self.ids["second"]]
        )

    def test_other_advisories_are_not_included(self) -> None:
        alert_id = self._alert("first", advisory="ADV-A", severity="low")
        self._alert("first", advisory="ADV-B", severity="high", component="c2")

        _s, _h, body = self._detail("ADV-A")
        self.assertEqual(body["affected_resources"], [self.ids["first"]])
        self.assertEqual(
            body["alerts"],
            [
                {
                    "resource_id": self.ids["first"],
                    "id": alert_id,
                    "advisory": "ADV-A",
                    "component": "lib",
                    "severity": "low",
                    "summary": "a bug",
                    "fixed_version": None,
                }
            ],
        )

    def test_counts_and_max_severity_match_summary_view(self) -> None:
        self._alert("second", advisory="ADV-B", severity="medium")
        self._alert("third", advisory="ADV-A", severity="HIGH")
        self._alert("first", advisory="ADV-A", severity="critical", component="o")
        self._alert("first", advisory="ADV-A", severity="low", component="z")
        self._alert("second", advisory="ADV-A", severity="low", component="z")

        for query_string in (None, "severity=LOW", "severity=high"):
            with self.subTest(query_string=query_string):
                _s, _h, detail = self._detail("ADV-A", query_string=query_string)
                _s, _h, summary = call_json(
                    "GET", "/advisories", query_string=query_string
                )
                row = next(
                    r for r in summary if r["advisory"] == "ADV-A"
                )
                self.assertEqual(len(detail["alerts"]), row["advisory_count"])
                self.assertEqual(
                    detail["affected_resources"], row["affected_resources"]
                )
                severities = [a["severity"] for a in detail["alerts"]]
                expected_max = min(
                    severities,
                    key=lambda s: ("critical", "high", "medium", "low").index(s),
                )
                self.assertEqual(expected_max, row["max_severity"])

    # --- Severity filter ----------------------------------------------------

    def test_severity_filter_shrinks_alerts_and_resources(self) -> None:
        self._alert("first", advisory="ADV-A", severity="high")
        self._alert("second", advisory="ADV-A", severity="low", component="c2")
        self._alert("third", advisory="ADV-A", severity="low", component="c3")

        _s, _h, body = self._detail("ADV-A", query_string="severity=LOW")
        self.assertEqual(
            [alert["resource_id"] for alert in body["alerts"]],
            [self.ids["second"], self.ids["third"]],
        )
        self.assertEqual(
            body["affected_resources"], [self.ids["second"], self.ids["third"]]
        )

    def test_severity_filter_is_case_insensitive(self) -> None:
        alert_id = self._alert("first", advisory="ADV-A", severity="high")
        self._alert("second", advisory="ADV-A", severity="low", component="c2")
        # "HIGH" must match the stored lowercase "high" and nothing else.
        _s, _h, body = self._detail("ADV-A", query_string="severity=HIGH")
        self.assertEqual(
            body,
            {
                "advisory": "ADV-A",
                "affected_resources": [self.ids["first"]],
                "alerts": [
                    {
                        "resource_id": self.ids["first"],
                        "id": alert_id,
                        "advisory": "ADV-A",
                        "component": "lib",
                        "severity": "high",
                        "summary": "a bug",
                        "fixed_version": None,
                    }
                ],
            },
        )

    def test_severity_filter_no_match_is_success_empty_arrays(self) -> None:
        self._alert("first", advisory="ADV-A", severity="low")
        status, _h, body = self._detail(
            "ADV-A", query_string="severity=critical"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["alerts"], [])
        self.assertEqual(body["affected_resources"], [])
        self.assertEqual(body["advisory"], "ADV-A")

    # --- Read-only / recompute ----------------------------------------------

    def test_view_reflects_updates_and_deletes_immediately(self) -> None:
        alert_id = self._alert("first", advisory="ADV-A", severity="low")
        _s, _h, body = self._detail("ADV-A")
        self.assertEqual(len(body["alerts"]), 1)

        status, _h, _b = call_json(
            "PUT",
            f"/resources/{self.ids['first']}/vulnerabilities/{alert_id}",
            {
                "advisory": "ADV-A",
                "component": "lib",
                "severity": "critical",
                "summary": "now worse",
            },
        )
        self.assertEqual(status, "200 OK")
        _s, _h, body = self._detail("ADV-A")
        self.assertEqual(body["alerts"][0]["severity"], "critical")
        self.assertEqual(body["alerts"][0]["summary"], "now worse")

        status, _h, _b = call_json(
            "DELETE",
            f"/resources/{self.ids['first']}/vulnerabilities/{alert_id}",
        )
        self.assertEqual(status, "200 OK")
        _s, _h, body = self._detail("ADV-A")
        self.assertEqual(body["alerts"], [])
        self.assertEqual(body["affected_resources"], [])

    def test_view_does_not_modify_any_state(self) -> None:
        self._alert("first", advisory="ADV-A", severity="high")
        for _ in range(2):
            status, _h, body = self._detail("ADV-A")
            self.assertEqual(status, "200 OK")
            self.assertEqual(len(body["alerts"]), 1)
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
                status, headers, body = call_json(method, "/advisories/ADV-A")
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")
                self.assertEqual(
                    body["message"],
                    f"Method {method} is not allowed for this path.",
                )
                self.assertEqual(dict(headers)["Allow"], "GET")

    def test_empty_advisory_id_returns_400(self) -> None:
        status, _h, body = call_json("GET", "/advisories/")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        self.assertEqual(body["message"], "Advisory id must not be empty.")

    def test_advisory_id_with_path_separator_returns_400(self) -> None:
        for path in ("/advisories/A/B", "/advisories/A\\B"):
            with self.subTest(path=path):
                status, _h, body = call_json("GET", path)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")
                self.assertEqual(
                    body["message"],
                    "Advisory id must not contain path separators.",
                )

    def test_declared_non_empty_body_returns_400(self) -> None:
        status, _h, body = call_json(
            "GET", "/advisories/ADV-A", {"unexpected": True}
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        self.assertEqual(
            body["message"], "This endpoint does not accept a request body."
        )

    def test_malformed_content_length_returns_400(self) -> None:
        status, _h, body = call_json(
            "GET", "/advisories/ADV-A", content_length="abc"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        self.assertEqual(
            body["message"], "This endpoint does not accept a request body."
        )

    def test_empty_body_declared_zero_is_accepted(self) -> None:
        status, _h, body = call_json(
            "GET", "/advisories/ADV-A", body={}, content_length="0"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            body,
            {"advisory": "ADV-A", "affected_resources": [], "alerts": []},
        )

    def test_unknown_query_parameter_returns_400(self) -> None:
        cases = {
            "x=1": "Unknown query parameter: 'x'.",
            "limit=10": "Unknown query parameter: 'limit'.",
            "severity=high&foo=bar": "Unknown query parameter: 'foo'.",
        }
        for qs, message in cases.items():
            with self.subTest(qs=qs):
                status, _h, body = self._detail("ADV-A", query_string=qs)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")
                self.assertEqual(body["message"], message)

    def test_repeated_severity_returns_400(self) -> None:
        status, _h, body = self._detail(
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
                status, _h, body = self._detail("ADV-A", query_string=qs)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")
                self.assertEqual(
                    body["message"],
                    "Severity must be one of: critical, high, medium, low "
                    "(case-insensitive).",
                )

    def test_bad_request_does_not_read_business_data(self) -> None:
        # A bad query parameter is rejected before aggregation; the
        # business state is byte-for-byte identical before and after the
        # rejected request.
        self._alert("first", advisory="ADV-A", severity="high")
        before_detail = call("GET", "/advisories/ADV-A")
        before_summary = call("GET", "/advisories")
        before_alerts = call(
            "GET", f"/resources/{self.ids['first']}/vulnerabilities"
        )

        status, _h, body = self._detail("ADV-A", query_string="severity=urgent")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

        self.assertEqual(call("GET", "/advisories/ADV-A"), before_detail)
        self.assertEqual(call("GET", "/advisories"), before_summary)
        self.assertEqual(
            call("GET", f"/resources/{self.ids['first']}/vulnerabilities"),
            before_alerts,
        )

    def test_error_body_shape_and_newline(self) -> None:
        status, headers, raw = call(
            "GET", "/advisories/ADV-A", query_string="x=1"
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
