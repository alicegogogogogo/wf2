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


class AdvisorySummaryTests(unittest.TestCase):
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
    ) -> None:
        status, _h, _b = call_json(
            "POST",
            f"/resources/{self.ids[resource]}/vulnerabilities",
            {
                "advisory": advisory,
                "component": component,
                "severity": severity,
                "summary": "a bug",
            },
        )
        self.assertEqual(status, "201 Created")

    def _summaries(
        self, *, query_string: str | None = None
    ) -> tuple[str, list[tuple[str, str]], object]:
        return call_json(
            "GET", "/advisories", query_string=query_string
        )

    # --- Shape -------------------------------------------------------------

    def test_no_alerts_returns_empty_array(self) -> None:
        status, headers, body = self._summaries()
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, [])
        self.assertEqual(
            dict(headers)["Content-Type"], "application/json; charset=utf-8"
        )

    def test_response_is_compact_utf8_single_newline(self) -> None:
        self._alert("first", advisory="A-1", severity="high")
        status, _headers, raw = call("GET", "/advisories")
        self.assertEqual(status, "200 OK")
        self.assertTrue(raw.endswith(b"\n"))
        self.assertEqual(raw.count(b"\n"), 1)
        self.assertNotIn(b" ", raw[:-1])

    def test_record_keys_are_exactly_the_four_documented(self) -> None:
        self._alert("first", advisory="A-1", severity="high")
        _s, _h, body = self._summaries()
        self.assertEqual(
            set(body[0]),
            {"advisory", "affected_resources", "advisory_count", "max_severity"},
        )
        text = call("GET", "/advisories")[2].decode("utf-8").rstrip("\n")
        keys = [
            '"advisory"',
            '"affected_resources"',
            '"advisory_count"',
            '"max_severity"',
        ]
        positions = [text.index(key) for key in keys]
        self.assertEqual(positions, sorted(positions))

    # --- Ordering, counts and severity -------------------------------------

    def test_advisories_follow_first_alert_submission_order(self) -> None:
        # The first alert of ADV-B is submitted before ADV-A even though the
        # resource it lands on ("second") was registered after "first".
        self._alert("second", advisory="ADV-B", severity="medium")
        self._alert("third", advisory="ADV-A", severity="high")
        self._alert("first", advisory="ADV-A", severity="critical")

        _s, _h, body = self._summaries()
        self.assertEqual([row["advisory"] for row in body], ["ADV-B", "ADV-A"])

    def test_affected_resources_follow_registration_order(self) -> None:
        # ADV-A first appears on "third", later on "first" and "second"; the
        # affected list must follow resource registration order regardless.
        self._alert("third", advisory="ADV-A", severity="high")
        self._alert("first", advisory="ADV-A", severity="high", component="c1")
        self._alert("second", advisory="ADV-A", severity="high", component="c2")

        _s, _h, body = self._summaries()
        self.assertEqual(
            body[0]["affected_resources"],
            [self.ids["first"], self.ids["second"], self.ids["third"]],
        )

    def test_resource_appears_once_even_with_many_alerts(self) -> None:
        self._alert("first", advisory="ADV-A", severity="low", component="c1")
        self._alert("first", advisory="ADV-A", severity="low", component="c2")
        self._alert("first", advisory="ADV-A", severity="low", component="c3")

        _s, _h, body = self._summaries()
        self.assertEqual(body[0]["affected_resources"], [self.ids["first"]])

    def test_count_is_raw_alert_total_not_deduped_or_merged(self) -> None:
        self._alert("first", advisory="ADV-A", severity="low", component="c1")
        self._alert("second", advisory="ADV-A", severity="low", component="c2")
        self._alert("first", advisory="ADV-A", severity="low", component="c3")

        _s, _h, body = self._summaries()
        self.assertEqual(body[0]["advisory_count"], 3)

    def test_max_severity_uses_fixed_case_insensitive_order(self) -> None:
        self._alert("first", advisory="ADV-A", severity="LOW")
        self._alert("second", advisory="ADV-A", severity="MeDiUm")
        self._alert("third", advisory="ADV-A", severity="high", component="c2")

        _s, _h, body = self._summaries()
        self.assertEqual(body[0]["max_severity"], "high")

    def test_full_aggregation_example(self) -> None:
        # ADV-B appears first (on "second"), ADV-A afterwards. ADV-A has
        # alerts on "third" (high), "first" (critical, low) and "second"
        # (low); the resource carrying only a filtered-out alert must not
        # show up in affected_resources for the matching-level view.
        self._alert("second", advisory="ADV-B", severity="medium")
        self._alert("third", advisory="ADV-A", severity="HIGH")
        self._alert("first", advisory="ADV-A", severity="critical", component="o")
        self._alert("first", advisory="ADV-A", severity="low", component="z")
        self._alert("second", advisory="ADV-A", severity="low", component="z")

        _s, _h, body = self._summaries()
        self.assertEqual(
            body,
            [
                {
                    "advisory": "ADV-B",
                    "affected_resources": [self.ids["second"]],
                    "advisory_count": 1,
                    "max_severity": "medium",
                },
                {
                    "advisory": "ADV-A",
                    "affected_resources": [
                        self.ids["first"],
                        self.ids["second"],
                        self.ids["third"],
                    ],
                    "advisory_count": 4,
                    "max_severity": "critical",
                },
            ],
        )

    # --- Severity filter ---------------------------------------------------

    def test_severity_filter_counts_only_matching_alerts(self) -> None:
        self._alert("first", advisory="ADV-A", severity="high")
        self._alert("second", advisory="ADV-A", severity="low", component="c2")
        self._alert("third", advisory="ADV-B", severity="low", component="c3")

        _s, _h, body = self._summaries(query_string="severity=LOW")
        self.assertEqual(
            body,
            [
                {
                    "advisory": "ADV-A",
                    "affected_resources": [self.ids["second"]],
                    "advisory_count": 1,
                    "max_severity": "low",
                },
                {
                    "advisory": "ADV-B",
                    "affected_resources": [self.ids["third"]],
                    "advisory_count": 1,
                    "max_severity": "low",
                },
            ],
        )

    def test_severity_filter_is_case_insensitive(self) -> None:
        self._alert("first", advisory="ADV-A", severity="high")
        self._alert("second", advisory="ADV-B", severity="low")

        _s, _h, body = self._summaries(query_string="severity=HIGH")
        self.assertEqual([row["advisory"] for row in body], ["ADV-A"])

    def test_severity_filter_first_appearance_uses_matching_alerts(self) -> None:
        # ADV-A's first alert overall is low, but its first high-severity
        # alert lands after ADV-B's high alert.
        self._alert("first", advisory="ADV-A", severity="low")
        self._alert("second", advisory="ADV-B", severity="high")
        self._alert("third", advisory="ADV-A", severity="high", component="c2")

        _s, _h, body = self._summaries(query_string="severity=high")
        self.assertEqual([row["advisory"] for row in body], ["ADV-B", "ADV-A"])

    def test_severity_filter_no_match_is_success_empty_array(self) -> None:
        self._alert("first", advisory="ADV-A", severity="low")
        status, _h, body = self._summaries(query_string="severity=critical")
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, [])

    # --- Read-only ---------------------------------------------------------

    def test_view_does_not_modify_any_state(self) -> None:
        self._alert("first", advisory="ADV-A", severity="high")
        for _ in range(2):
            status, _h, body = self._summaries()
            self.assertEqual(status, "200 OK")
            self.assertEqual(len(body), 1)
        _s, _h, alerts = call_json(
            "GET", f"/resources/{self.ids['first']}/vulnerabilities"
        )
        self.assertEqual(len(alerts["vulnerabilities"]), 1)
        _s, _h, resources = call_json("GET", "/resources")
        self.assertEqual(len(resources["resources"]), 3)

    # --- Errors ------------------------------------------------------------

    def test_non_get_methods_return_405_with_allow_get_only(self) -> None:
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, headers, body = call_json(method, "/advisories")
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")
                self.assertEqual(dict(headers)["Allow"], "GET")

    def test_declared_non_empty_body_returns_400(self) -> None:
        status, _h, body = call_json("GET", "/advisories", {"unexpected": True})
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_malformed_content_length_returns_400(self) -> None:
        status, _h, body = call_json(
            "GET", "/advisories", content_length="abc"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_empty_body_declared_zero_is_accepted(self) -> None:
        status, _h, body = call_json(
            "GET", "/advisories", body={}, content_length="0"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, [])

    def test_unknown_query_parameter_returns_400(self) -> None:
        for qs in ("x=1", "limit=10", "severity=high&foo=bar"):
            with self.subTest(qs=qs):
                status, _h, body = self._summaries(query_string=qs)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_repeated_severity_returns_400(self) -> None:
        status, _h, body = self._summaries(
            query_string="severity=high&severity=low"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_empty_or_unknown_severity_returns_400(self) -> None:
        for qs in ("severity=", "severity=urgent", "severity=HIG"):
            with self.subTest(qs=qs):
                status, _h, body = self._summaries(query_string=qs)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_bad_request_does_not_read_business_data(self) -> None:
        # A bad query parameter is rejected before aggregation; the response
        # is the same with or without any recorded alerts.
        self._alert("first", advisory="ADV-A", severity="high")
        status, _h, body = self._summaries(query_string="severity=urgent")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_error_body_shape_and_newline(self) -> None:
        status, headers, raw = call("GET", "/advisories", query_string="x=1")
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
