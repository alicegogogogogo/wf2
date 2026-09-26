from __future__ import annotations

import io
import json
import unittest

from provenance_api.app import application, reset_state

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64

ALERT_KEYS = ("resource_id", "id", "advisory", "component", "severity",
              "summary", "fixed_version")


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
            f"/resources/{self.ids[resource]}/vulnerabilities",
            payload,
        )
        self.assertEqual(status, "201 Created")
        return dict(body)

    def _detail(
        self, advisory: str, *, query_string: str | None = None
    ) -> tuple[str, list[tuple[str, str]], object]:
        return call_json(
            "GET",
            f"/advisories/{advisory}",
            query_string=query_string,
        )

    # --- Shape -------------------------------------------------------------

    def test_unknown_advisory_is_success_with_empty_arrays(self) -> None:
        status, headers, body = self._detail("NOPE-2026-0000")
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            body,
            {"advisory": "NOPE-2026-0000", "affected_resources": [], "alerts": []},
        )
        self.assertEqual(
            dict(headers)["Content-Type"], "application/json; charset=utf-8"
        )

    def test_top_level_key_order_and_single_newline(self) -> None:
        self._alert("first", advisory="ADV-A", severity="high", summary="bug")
        status, _headers, raw = call("GET", "/advisories/ADV-A")
        self.assertEqual(status, "200 OK")
        self.assertTrue(raw.endswith(b"\n"))
        self.assertEqual(raw.count(b"\n"), 1)
        self.assertNotIn(b" ", raw[:-1])
        text = raw.decode("utf-8").rstrip("\n")
        keys = ['"advisory"', '"affected_resources"', '"alerts"']
        positions = [text.index(key) for key in keys]
        self.assertEqual(positions, sorted(positions))

    def test_alert_echoes_resource_id_first_then_registration_key_order(
        self,
    ) -> None:
        recorded = self._alert(
            "first",
            advisory="ADV-A",
            severity="HIGH",
            component="openssl",
            summary="overflow",
            fixed_version="3.0.9",
        )
        _s, _h, body = self._detail("ADV-A")
        self.assertEqual(len(body["alerts"]), 1)
        alert = body["alerts"][0]
        self.assertEqual(tuple(alert), ALERT_KEYS)
        self.assertEqual(alert["resource_id"], self.ids["first"])
        self.assertEqual(
            alert,
            {
                "resource_id": self.ids["first"],
                "id": recorded["id"],
                "advisory": "ADV-A",
                "component": "openssl",
                "severity": "high",
                "summary": "overflow",
                "fixed_version": "3.0.9",
            },
        )

    def test_advisory_is_echoed_verbatim_without_trimming(self) -> None:
        # The segment is echoed exactly as received; a trailing space does
        # not match a stored identifier but is still echoed unchanged.
        status, _h, body = call_json("GET", "/advisories/ADV-A ")
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["advisory"], "ADV-A ")
        self.assertEqual(body["alerts"], [])

    # --- Matching ----------------------------------------------------------

    def test_match_is_verbatim_case_sensitive_without_trimming(self) -> None:
        self._alert("first", advisory="ADV-A", severity="high")
        for requested in ("adv-a", "ADV-a", " ADV-A", "ADV-A "):
            with self.subTest(requested=requested):
                _s, _h, body = self._detail(requested)
                self.assertEqual(body["alerts"], [])
                self.assertEqual(body["affected_resources"], [])

    # --- Ordering ----------------------------------------------------------

    def test_detail_follows_resource_registration_order(self) -> None:
        # Alerts are submitted in an order unrelated to resource registration;
        # the detail must still expand by registration order.
        a1 = self._alert("third", advisory="ADV-A", severity="high", component="c1")
        a2 = self._alert("first", advisory="ADV-A", severity="low", component="c2")
        a3 = self._alert("second", advisory="ADV-A", severity="medium", component="c3")

        _s, _h, body = self._detail("ADV-A")
        self.assertEqual(
            [alert["resource_id"] for alert in body["alerts"]],
            [self.ids["first"], self.ids["second"], self.ids["third"]],
        )
        self.assertEqual(
            [alert["id"] for alert in body["alerts"]],
            [a2["id"], a3["id"], a1["id"]],
        )
        self.assertEqual(
            body["affected_resources"],
            [self.ids["first"], self.ids["second"], self.ids["third"]],
        )

    def test_alerts_within_a_resource_keep_submission_order(self) -> None:
        first = self._alert("first", advisory="ADV-A", severity="low", component="c1")
        self._alert("second", advisory="ADV-A", severity="low", component="c2")
        third = self._alert("first", advisory="ADV-A", severity="low", component="c3")

        _s, _h, body = self._detail("ADV-A")
        first_alerts = [
            alert for alert in body["alerts"]
            if alert["resource_id"] == self.ids["first"]
        ]
        self.assertEqual([alert["id"] for alert in first_alerts],
                         [first["id"], third["id"]])

    def test_each_resource_appears_once_even_with_several_alerts(self) -> None:
        for component in ("c1", "c2", "c3"):
            self._alert(
                "first", advisory="ADV-A", severity="low", component=component
            )
        _s, _h, body = self._detail("ADV-A")
        self.assertEqual(body["affected_resources"], [self.ids["first"]])
        self.assertEqual(len(body["alerts"]), 3)

    def test_only_alerts_of_the_requested_advisory_are_listed(self) -> None:
        keep = self._alert("first", advisory="ADV-A", severity="high")
        self._alert("first", advisory="ADV-B", severity="critical", component="x")
        self._alert("second", advisory="ADV-C", severity="low", component="y")

        _s, _h, body = self._detail("ADV-A")
        self.assertEqual([alert["id"] for alert in body["alerts"]], [keep["id"]])
        self.assertEqual(body["affected_resources"], [self.ids["first"]])

    # --- Severity filter ---------------------------------------------------

    def test_severity_filter_shrinks_detail_and_resource_list(self) -> None:
        kept = self._alert("first", advisory="ADV-A", severity="HIGH")
        self._alert("first", advisory="ADV-A", severity="low", component="c2")
        self._alert("second", advisory="ADV-A", severity="low", component="c3")

        _s, _h, body = self._detail("ADV-A", query_string="severity=high")
        self.assertEqual([alert["id"] for alert in body["alerts"]], [kept["id"]])
        self.assertEqual(body["affected_resources"], [self.ids["first"]])

    def test_severity_filter_is_consistent_with_summary(self) -> None:
        self._alert("second", advisory="ADV-A", severity="low", component="c2")
        self._alert("third", advisory="ADV-A", severity="HIGH", component="c3")
        self._alert("first", advisory="ADV-A", severity="high", component="c4")
        self._alert("first", advisory="ADV-A", severity="low", component="c5")
        self._alert("second", advisory="ADV-B", severity="critical", component="c6")

        for level in ("low", "medium", "high", "critical"):
            with self.subTest(level=level):
                _s, _h, summaries = call_json(
                    "GET", "/advisories", query_string=f"severity={level}"
                )
                rows = {row["advisory"]: row for row in summaries}
                _s, _h, detail = self._detail(
                    "ADV-A", query_string=f"severity={level}"
                )
                row = rows.get("ADV-A")
                if not detail["alerts"]:
                    self.assertIsNone(row)
                    continue
                assert row is not None
                self.assertEqual(row["advisory_count"], len(detail["alerts"]))
                self.assertEqual(
                    row["affected_resources"], detail["affected_resources"]
                )
                self.assertEqual(
                    row["max_severity"],
                    max(
                        (alert["severity"] for alert in detail["alerts"]),
                        key=lambda value: ("critical", "high", "medium", "low").index(value),
                    ),
                )

    def test_severity_filter_without_match_is_success_empty(self) -> None:
        self._alert("first", advisory="ADV-A", severity="low")
        status, _h, body = self._detail(
            "ADV-A", query_string="severity=critical"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["alerts"], [])
        self.assertEqual(body["affected_resources"], [])

    # --- Read-only and liveness --------------------------------------------

    def test_detail_recomputes_after_update_and_delete(self) -> None:
        record = self._alert("first", advisory="ADV-A", severity="low")
        _s, _h, body = self._detail("ADV-A")
        self.assertEqual(body["alerts"][0]["severity"], "low")

        status, _h, updated = call_json(
            "PUT",
            f"/resources/{self.ids['first']}/vulnerabilities/{record['id']}",
            {
                "advisory": "ADV-A",
                "component": record["component"],
                "severity": "critical",
                "summary": "new text",
            },
        )
        self.assertEqual(status, "200 OK")
        _s, _h, body = self._detail("ADV-A")
        self.assertEqual(body["alerts"][0]["severity"], "critical")
        self.assertEqual(body["alerts"][0]["summary"], "new text")

        status, _h, _deleted = call_json(
            "DELETE",
            f"/resources/{self.ids['first']}/vulnerabilities/{record['id']}",
        )
        self.assertEqual(status, "200 OK")
        _s, _h, body = self._detail("ADV-A")
        self.assertEqual(body["alerts"], [])
        self.assertEqual(body["affected_resources"], [])

    def test_detail_never_changes_state(self) -> None:
        self._alert("first", advisory="ADV-A", severity="high")
        for _ in range(2):
            status, _h, body = self._detail("ADV-A")
            self.assertEqual(status, "200 OK")
            self.assertEqual(len(body["alerts"]), 1)
        _s, _h, alerts = call_json(
            "GET", f"/resources/{self.ids['first']}/vulnerabilities"
        )
        self.assertEqual(len(alerts["vulnerabilities"]), 1)

    # --- Errors ------------------------------------------------------------

    def test_non_get_methods_return_405_with_allow_get(self) -> None:
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, headers, body = call_json(method, "/advisories/ADV-A")
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")
                self.assertEqual(dict(headers)["Allow"], "GET")

    def test_empty_or_separator_advisory_returns_400(self) -> None:
        for path in (
            "/advisories/",
            "/advisories//",
            "/advisories/A/B",
        ):
            with self.subTest(path=path):
                status, _h, body = call_json("GET", path)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_backslash_in_advisory_returns_400(self) -> None:
        status, _h, body = call_json("GET", "/advisories/A\\B")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_unknown_or_repeated_query_parameter_returns_400(self) -> None:
        for qs in ("x=1", "severity=high&foo=bar", "severity=high&severity=low"):
            with self.subTest(qs=qs):
                status, _h, body = self._detail("ADV-A", query_string=qs)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_empty_or_illegal_severity_returns_400(self) -> None:
        for qs in ("severity=", "severity=urgent", "severity=HIG"):
            with self.subTest(qs=qs):
                status, _h, body = self._detail("ADV-A", query_string=qs)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_declared_non_empty_body_returns_400(self) -> None:
        status, _h, body = call_json(
            "GET", "/advisories/ADV-A", {"unexpected": True}
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_malformed_content_length_returns_400(self) -> None:
        status, _h, body = call_json(
            "GET", "/advisories/ADV-A", content_length="abc"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_explicit_zero_content_length_is_accepted(self) -> None:
        status, _h, body = call_json(
            "GET", "/advisories/ADV-A", body={}, content_length="0"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["alerts"], [])

    def test_bad_request_does_not_read_business_data(self) -> None:
        self._alert("first", advisory="ADV-A", severity="high")
        status, _h, body = self._detail("ADV-A", query_string="severity=urgent")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        # State is untouched.
        _s, _h, alerts = call_json(
            "GET", f"/resources/{self.ids['first']}/vulnerabilities"
        )
        self.assertEqual(len(alerts["vulnerabilities"]), 1)


if __name__ == "__main__":
    unittest.main()
