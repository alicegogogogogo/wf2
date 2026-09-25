from __future__ import annotations

import io
import json
import unittest

from provenance_api.app import application, reset_state

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_D = "d" * 64

PATH = "/advisories"


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


class AdvisoriesTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.ids: dict[str, str] = {}
        # Registration order is deliberate: r-a, r-b, r-c, r-d; alerts are
        # committed in a different order so ordering semantics are exercised.
        for name, digest in (
            ("r-a", DIGEST_A),
            ("r-b", DIGEST_B),
            ("r-c", DIGEST_C),
            ("r-d", DIGEST_D),
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
        severity: str = "high",
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

    def _advisories(self, **kwargs: object):
        return call_json("GET", PATH, **kwargs)

    # --- Empty collection --------------------------------------------------

    def test_no_alerts_returns_empty_array(self) -> None:
        status, _h, body = self._advisories()
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, [])

    def test_empty_response_is_compact_json_with_single_newline(self) -> None:
        status, _h, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

    # --- Grouping, counts and ordering --------------------------------------

    def test_grouping_counts_max_severity_and_field_order(self) -> None:
        # ADV-1 first appears on r-c (registered last), then on r-a and r-b;
        # same resource r-a contributes two records, both counted.
        self._alert("r-c", advisory="ADV-1", severity="low")
        self._alert("r-a", advisory="ADV-2", severity="medium")
        self._alert("r-a", advisory="ADV-1", severity="critical", component="c1")
        self._alert("r-a", advisory="ADV-1", severity="low", component="c2")
        self._alert("r-b", advisory="ADV-1", severity="HIGH")
        self._alert("r-a", advisory="ADV-2", severity="LOW", component="c3")
        # r-d never carries an alert and must not appear anywhere.

        _s, _h, body = self._advisories()
        self.assertEqual(
            body,
            [
                {
                    "advisory": "ADV-1",
                    "affected_resources": [
                        self.ids["r-a"],
                        self.ids["r-b"],
                        self.ids["r-c"],
                    ],
                    "advisory_count": 4,
                    "max_severity": "critical",
                },
                {
                    "advisory": "ADV-2",
                    "affected_resources": [self.ids["r-a"]],
                    "advisory_count": 2,
                    "max_severity": "medium",
                },
            ],
        )
        self.assertEqual(
            list(body[0]),
            [
                "advisory",
                "affected_resources",
                "advisory_count",
                "max_severity",
            ],
        )

    def test_advisories_expand_by_first_appearance(self) -> None:
        self._alert("r-b", advisory="ADV-3", severity="low")
        self._alert("r-a", advisory="ADV-1", severity="low")
        self._alert("r-c", advisory="ADV-2", severity="low")

        _s, _h, body = self._advisories()
        self.assertEqual(
            [record["advisory"] for record in body],
            ["ADV-3", "ADV-1", "ADV-2"],
        )

    def test_affected_resources_follow_registration_order_and_are_unique(
        self,
    ) -> None:
        # Alerts arrive out of registration order; r-b contributes twice but
        # is listed once.
        self._alert("r-c", advisory="ADV-9", severity="low")
        self._alert("r-a", advisory="ADV-9", severity="low", component="x")
        self._alert("r-b", advisory="ADV-9", severity="low", component="y")
        self._alert("r-b", advisory="ADV-9", severity="low", component="z")

        _s, _h, body = self._advisories()
        self.assertEqual(len(body), 1)
        self.assertEqual(
            body[0]["affected_resources"],
            [self.ids["r-a"], self.ids["r-b"], self.ids["r-c"]],
        )
        self.assertEqual(body[0]["advisory_count"], 4)

    def test_count_never_deduplicates_or_merges(self) -> None:
        self._alert("r-a", advisory="ADV-1", severity="low", component="c1")
        self._alert("r-a", advisory="ADV-1", severity="low", component="c2")
        self._alert("r-a", advisory="ADV-1", severity="low", component="c3")

        _s, _h, body = self._advisories()
        self.assertEqual(body[0]["advisory_count"], 3)
        self.assertEqual(body[0]["affected_resources"], [self.ids["r-a"]])

    def test_max_severity_uses_fixed_order_case_insensitive(self) -> None:
        self._alert("r-a", advisory="ADV-1", severity="LOW")
        self._alert("r-b", advisory="ADV-1", severity="Medium")

        _s, _h, body = self._advisories()
        self.assertEqual(body[0]["max_severity"], "medium")

    def test_response_is_compact_utf8_newline_terminated(self) -> None:
        self._alert("r-a", advisory="ADV-1")

        _status, _headers, raw = call("GET", PATH)
        self.assertTrue(raw.endswith(b"\n"))
        self.assertEqual(raw.count(b"\n"), 1)
        self.assertNotIn(b" ", raw[:-1])

    # --- Severity filter ----------------------------------------------------

    def test_severity_filter_counts_only_matching_alerts(self) -> None:
        self._alert("r-a", advisory="ADV-1", severity="low")
        self._alert("r-a", advisory="ADV-1", severity="HIGH", component="c2")
        self._alert("r-b", advisory="ADV-1", severity="critical")
        self._alert("r-b", advisory="ADV-2", severity="low")

        _s, _h, body = self._advisories(query_string="severity=high")
        self.assertEqual(
            body,
            [
                {
                    "advisory": "ADV-1",
                    "affected_resources": [self.ids["r-a"]],
                    "advisory_count": 1,
                    "max_severity": "high",
                }
            ],
        )

    def test_severity_filter_groups_are_reordered_by_first_match(self) -> None:
        # ADV-1 appears first overall, but its first high-level match comes
        # after ADV-2's, so under severity=high ADV-2 leads.
        self._alert("r-a", advisory="ADV-1", severity="low")
        self._alert("r-b", advisory="ADV-2", severity="HIGH")
        self._alert("r-c", advisory="ADV-1", severity="critical")

        _s, _h, body = self._advisories(query_string="severity=HIGH")
        self.assertEqual([record["advisory"] for record in body], ["ADV-2"])

        _s, _h, body = self._advisories(query_string="severity=Critical")
        self.assertEqual(
            [record["advisory"] for record in body],
            ["ADV-1"],
        )
        self.assertEqual(body[0]["affected_resources"], [self.ids["r-c"]])
        self.assertEqual(body[0]["advisory_count"], 1)
        self.assertEqual(body[0]["max_severity"], "critical")

    def test_severity_filter_with_no_match_returns_empty_array(self) -> None:
        self._alert("r-a", advisory="ADV-1", severity="low")

        status, _h, body = self._advisories(query_string="severity=critical")
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, [])

    # --- Read-only ----------------------------------------------------------

    def test_view_is_read_only_and_repeatable(self) -> None:
        self._alert("r-a", advisory="ADV-1", severity="critical")

        for _ in range(3):
            status, _h, body = self._advisories()
            self.assertEqual(status, "200 OK")
            self.assertEqual(len(body), 1)

        _s, _h, alerts = call_json(
            "GET", f"/resources/{self.ids['r-a']}/vulnerabilities"
        )
        self.assertEqual(len(alerts["vulnerabilities"]), 1)
        _s, _h, resources = call_json("GET", "/resources")
        self.assertEqual(len(resources["resources"]), 4)

    # --- Errors -------------------------------------------------------------

    def test_non_get_methods_return_405_with_allow_get(self) -> None:
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, headers, body = call_json(method, PATH, {})
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")
                self.assertEqual(headers.count(("Allow", "GET")), 1)

    def test_declared_non_empty_body_returns_400(self) -> None:
        for declared in ("1", "5", "12", "abc"):
            with self.subTest(declared=declared):
                status, _h, body = call_json(
                    "GET",
                    PATH,
                    b"x",
                    content_length=declared,
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_explicit_zero_content_length_is_allowed(self) -> None:
        status, _h, raw = call(
            "GET", PATH, b"", content_length="0"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

    def test_empty_string_content_length_is_treated_as_bodyless(self) -> None:
        # Real WSGI servers seed CONTENT_LENGTH with '' for bodyless GETs.
        status, _h, body = self._advisories(content_length="")
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, [])

    def test_unknown_query_parameter_returns_400(self) -> None:
        for qs in ("x=1", "limit=10", "foo=", "severity=high&other=1"):
            with self.subTest(qs=qs):
                status, _h, body = self._advisories(query_string=qs)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_repeated_severity_returns_400(self) -> None:
        status, _h, body = self._advisories(
            query_string="severity=high&severity=low"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_invalid_severity_returns_400(self) -> None:
        for qs in ("severity=", "severity=urgent", "severity=HIGHER"):
            with self.subTest(qs=qs):
                status, _h, body = self._advisories(query_string=qs)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_bad_request_does_not_require_or_read_any_resource(self) -> None:
        # Invalid filtering is rejected regardless of stored data and never
        # turns into a 404 or an empty success.
        status, _h, body = self._advisories(query_string="severity=nope")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_error_body_uses_stable_json_shape_and_newline(self) -> None:
        _status, _headers, raw = call(
            "GET", PATH, query_string="severity=bad"
        )
        self.assertTrue(raw.endswith(b"\n"))
        self.assertEqual(raw.count(b"\n"), 1)
        decoded = json.loads(raw.decode("utf-8"))
        self.assertEqual(set(decoded), {"error", "message"})
        self.assertEqual(decoded["error"], "invalid_request")


if __name__ == "__main__":
    unittest.main()
