from __future__ import annotations

import io
import json
import unittest

from provenance_api.app import application, reset_state

PATH = "/alert-components"

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64


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


class AlertComponentsTests(unittest.TestCase):
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
        component: str,
        severity: str = "high",
    ) -> str:
        status, _h, body = call_json(
            "POST",
            f"/resources/{self.ids[resource]}/vulnerabilities",
            {
                "advisory": advisory,
                "component": component,
                "severity": severity,
                "summary": "a bug",
            },
        )
        assert status == "201 Created", body
        return str(body["id"])

    def _summary(
        self, query_string: str | None = None
    ) -> tuple[str, list[tuple[str, str]], list[dict[str, object]]]:
        status, headers, body = call_json(
            "GET", PATH, query_string=query_string
        )
        self.assertEqual(status, "200 OK")
        self.assertIsInstance(body, list)
        return status, headers, body  # type: ignore[return-value]

    # --- Shape -------------------------------------------------------------

    def test_no_alerts_returns_empty_array(self) -> None:
        status, headers, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )

    def test_response_is_compact_utf8_single_newline(self) -> None:
        self._alert("first", advisory="A-1", component="lib")
        status, _headers, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertTrue(raw.endswith(b"\n"))
        self.assertEqual(raw.count(b"\n"), 1)
        self.assertNotIn(b" ", raw[:-1])
        raw[:-1].decode("utf-8")

    def test_record_keys_are_exactly_the_six_documented_in_order(self) -> None:
        self._alert("first", advisory="A-1", component="lib")
        _s, _h, body = self._summary()
        self.assertEqual(
            list(body[0]),
            [
                "name",
                "advisories",
                "advisory_count",
                "max_severity",
                "resources",
                "resource_count",
            ],
        )
        text = call("GET", PATH)[2].decode("utf-8").rstrip("\n")
        keys = [
            '"name"',
            '"advisories"',
            '"advisory_count"',
            '"max_severity"',
            '"resources"',
            '"resource_count"',
        ]
        positions = [text.index(key) for key in keys]
        self.assertEqual(positions, sorted(positions))

    def test_single_alert_record_fields(self) -> None:
        self._alert("first", advisory="A-1", component="lib", severity="low")
        _s, _h, body = self._summary()
        self.assertEqual(
            body[0],
            {
                "name": "lib",
                "advisories": ["A-1"],
                "advisory_count": 1,
                "max_severity": "low",
                "resources": [self.ids["first"]],
                "resource_count": 1,
            },
        )

    # --- Ordering, dedup, counts and severity ------------------------------

    def test_entries_follow_first_component_occurrence(self) -> None:
        # Traversal follows resource registration order and alert submission
        # order within a resource; global submission order alone would put
        # zeta first.
        self._alert("second", advisory="A-2", component="zeta")
        self._alert("first", advisory="A-1", component="alpha")
        self._alert("first", advisory="A-3", component="mid")

        _s, _h, body = self._summary()
        self.assertEqual([row["name"] for row in body], ["alpha", "mid", "zeta"])

    def test_advisories_deduplicated_in_first_appearance_order(self) -> None:
        # First appearance follows the view traversal: resource
        # registration order first, then each resource's alert submission
        # order. ADV-A was submitted second globally but lands on "second",
        # so first's own ADV-C (submitted later in wall-clock terms) is
        # still listed ahead of it.
        self._alert("first", advisory="ADV-B", component="lib")
        self._alert("second", advisory="ADV-A", component="lib")
        self._alert("first", advisory="ADV-B", component="lib-x")
        self._alert("third", advisory="ADV-B", component="lib")
        self._alert("first", advisory="ADV-C", component="lib")

        _s, _h, body = self._summary()
        lib = body[0]
        self.assertEqual(lib["name"], "lib")
        self.assertEqual(lib["advisories"], ["ADV-B", "ADV-C", "ADV-A"])

    def test_advisories_echoed_verbatim(self) -> None:
        self._alert("first", advisory=" ADV-X ", component="Lib ")
        _s, _h, body = self._summary()
        self.assertEqual(body[0]["name"], "Lib ")
        self.assertEqual(body[0]["advisories"], [" ADV-X "])

    def test_alert_count_is_raw_total_not_deduped_or_merged(self) -> None:
        self._alert("first", advisory="ADV-A", component="lib")
        self._alert("first", advisory="ADV-A", component="lib-other")
        self._alert("second", advisory="ADV-A", component="lib")
        self._alert("first", advisory="ADV-B", component="lib")
        self._alert("third", advisory="ADV-C", component="lib")

        _s, _h, body = self._summary()
        lib = body[0]
        # Five alerts hit "lib" across the three resources even though the
        # same advisory/component shape recurs.
        self.assertEqual(lib["advisory_count"], 4)
        self.assertEqual(lib["advisories"], ["ADV-A", "ADV-B", "ADV-C"])

    def test_max_severity_case_insensitive_output_lowercase(self) -> None:
        self._alert("first", advisory="A-1", component="lib", severity="LOW")
        self._alert("second", advisory="A-2", component="lib", severity="MeDiUm")
        self._alert("third", advisory="A-3", component="lib", severity="high")

        _s, _h, body = self._summary()
        self.assertEqual(body[0]["max_severity"], "high")

    def test_resources_follow_registration_order_deduplicated(self) -> None:
        # "lib" first appears on "third", then on "first" and "second".
        self._alert("third", advisory="A-1", component="lib")
        self._alert("first", advisory="A-2", component="lib")
        self._alert("first", advisory="A-3", component="lib")
        self._alert("second", advisory="A-4", component="lib")

        _s, _h, body = self._summary()
        self.assertEqual(
            body[0]["resources"],
            [self.ids["first"], self.ids["second"], self.ids["third"]],
        )
        self.assertEqual(body[0]["resource_count"], 3)

    def test_full_aggregation_example(self) -> None:
        # Submission starts on "second" with zeta, but traversal follows
        # resource registration order: "lib" first appears on "first", so
        # its entry precedes zeta's even though zeta's alert was submitted
        # first in wall-clock terms.
        self._alert("second", advisory="ADV-B", component="zeta", severity="medium")
        self._alert("third", advisory="ADV-A", component="lib", severity="HIGH")
        self._alert("first", advisory="ADV-A", component="lib", severity="critical")
        self._alert("first", advisory="ADV-D", component="lib", severity="low")
        self._alert("second", advisory="ADV-A", component="lib", severity="low")

        _s, _h, body = self._summary()
        self.assertEqual(
            body,
            [
                {
                    "name": "lib",
                    "advisories": ["ADV-A", "ADV-D"],
                    "advisory_count": 4,
                    "max_severity": "critical",
                    "resources": [
                        self.ids["first"],
                        self.ids["second"],
                        self.ids["third"],
                    ],
                    "resource_count": 3,
                },
                {
                    "name": "zeta",
                    "advisories": ["ADV-B"],
                    "advisory_count": 1,
                    "max_severity": "medium",
                    "resources": [self.ids["second"]],
                    "resource_count": 1,
                },
            ],
        )

    # --- Name filter -------------------------------------------------------

    def test_name_filter_returns_single_aggregated_record(self) -> None:
        self._alert("first", advisory="A-1", component="openssl")
        self._alert("second", advisory="A-2", component="zlib")
        self._alert("third", advisory="A-3", component="openssl")

        _s, _h, body = self._summary("name=openssl")
        self.assertEqual(len(body), 1)
        self.assertEqual(body[0]["name"], "openssl")
        self.assertEqual(body[0]["advisories"], ["A-1", "A-3"])
        self.assertEqual(body[0]["advisory_count"], 2)
        self.assertEqual(body[0]["resources"], [self.ids["first"], self.ids["third"]])
        self.assertEqual(body[0]["resource_count"], 2)

    def test_name_filter_is_case_sensitive_and_untrimmed(self) -> None:
        self._alert("first", advisory="A-1", component="openssl")
        for query in ("name=OpenSSL", "name=OPENSSL", "name=%20openssl",
                      "name=openssl%20"):
            with self.subTest(query=query):
                status, _h, raw = call("GET", PATH, query_string=query)
                self.assertEqual(status, "200 OK")
                self.assertEqual(raw, b"[]\n")

    def test_name_filter_without_hits_returns_empty_array(self) -> None:
        self._alert("first", advisory="A-1", component="openssl")
        status, _h, raw = call("GET", PATH, query_string="name=nope")
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

    def test_unknown_repeated_bare_or_empty_name_rejected(self) -> None:
        self._alert("first", advisory="A-1", component="openssl")
        for query in (
            "bogus=1",
            "x=",
            "name=openssl&bogus=1",
            "name=openssl&name=zlib",
            "name=",
            "name",
        ):
            with self.subTest(query=query):
                status, _h, body = call_json("GET", PATH, query_string=query)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_filter_does_not_read_business_data_on_bad_request(self) -> None:
        self._alert("first", advisory="A-1", component="openssl")
        status, _h, body = call_json(
            "GET", PATH, query_string="name=openssl&x=1"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        # The view still answers normally afterwards.
        _s, _h, after = self._summary()
        self.assertEqual([row["name"] for row in after], ["openssl"])

    # --- Recomputation ------------------------------------------------------

    def test_recomputes_after_registration_batch_update_delete(self) -> None:
        first = self.ids["first"]
        alert_id = self._alert(
            "first", advisory="ADV-A", component="lib", severity="low"
        )
        _s, _h, body = self._summary()
        self.assertEqual(body[0]["advisory_count"], 1)
        self.assertEqual(body[0]["max_severity"], "low")

        # In-place update changes severity immediately; counts and order
        # stay the same.
        status, _h, updated = call_json(
            "PUT",
            f"/resources/{first}/vulnerabilities/{alert_id}",
            {
                "advisory": "ADV-A",
                "component": "lib",
                "severity": "CRITICAL",
                "summary": "a bug",
            },
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(updated["severity"], "critical")
        _s, _h, body = self._summary()
        self.assertEqual(body[0]["max_severity"], "critical")
        self.assertEqual(body[0]["advisory_count"], 1)

        # Single alert deletion drops the count and, when it was the only
        # alert for the name, the whole entry.
        status, _h, _b = call_json(
            "DELETE", f"/resources/{first}/vulnerabilities/{alert_id}"
        )
        self.assertEqual(status, "200 OK")
        status, _h, raw = call("GET", PATH)
        self.assertEqual(raw, b"[]\n")

        # Batch registration lands every entry in submission order.
        status, _h, batch = call_json(
            "POST",
            f"/resources/{first}/vulnerabilities/batch",
            {
                "vulnerabilities": [
                    {
                        "advisory": "ADV-A",
                        "component": "lib",
                        "severity": "high",
                        "summary": "a bug",
                    },
                    {
                        "advisory": "ADV-B",
                        "component": "lib",
                        "severity": "low",
                        "summary": "a bug",
                    },
                ]
            },
        )
        self.assertEqual(status, "201 Created")
        self.assertEqual(len(batch["vulnerabilities"]), 2)
        _s, _h, body = self._summary()
        self.assertEqual(body[0]["advisories"], ["ADV-A", "ADV-B"])
        self.assertEqual(body[0]["advisory_count"], 2)
        self.assertEqual(body[0]["max_severity"], "high")

    def test_resource_deregistration_recomputes_aggregates(self) -> None:
        self._alert("first", advisory="A-1", component="lib")
        self._alert("second", advisory="A-2", component="lib")
        self._alert("second", advisory="A-3", component="zeta")
        self._alert("third", advisory="A-4", component="lib")

        status, _h, _b = call_json("DELETE", f"/resources/{self.ids['second']}")
        self.assertEqual(status, "200 OK")

        _s, _h, body = self._summary()
        self.assertEqual([row["name"] for row in body], ["lib"])
        self.assertEqual(body[0]["advisories"], ["A-1", "A-4"])
        self.assertEqual(body[0]["advisory_count"], 2)
        self.assertEqual(
            body[0]["resources"], [self.ids["first"], self.ids["third"]]
        )
        self.assertEqual(body[0]["resource_count"], 2)

        # Removing the last resources carrying alerts leaves an empty array.
        status, _h, _b = call_json("DELETE", f"/resources/{self.ids['first']}")
        self.assertEqual(status, "200 OK")
        status, _h, _b = call_json("DELETE", f"/resources/{self.ids['third']}")
        self.assertEqual(status, "200 OK")
        status, _h, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

    # --- Read-only and scope -------------------------------------------------

    def test_view_is_read_only(self) -> None:
        self._alert("first", advisory="A-1", component="lib")
        first_status, _h, first = call("GET", PATH)
        second_status, _h, second = call("GET", PATH)
        self.assertEqual(first_status, second_status)
        self.assertEqual(first, second)

        _s, _h, alerts = call_json(
            "GET", f"/resources/{self.ids['first']}/vulnerabilities"
        )
        self.assertEqual(len(alerts["vulnerabilities"]), 1)

    def test_view_ignores_sbom_components_without_alerts(self) -> None:
        first = self.ids["first"]
        # An SBOM component that never appears on any alert must not show
        # up, even though component-risks and component-usage would list it.
        status, _h, sbom_body = call_json(
            "POST",
            f"/resources/{first}/sbom",
            {
                "format": "spdx",
                "components": [
                    {"name": "sbom-only", "version": "1.0", "digest": "ab" * 32}
                ],
            },
        )
        self.assertEqual(status, "201 Created", sbom_body)
        self._alert("first", advisory="A-1", component="alert-lib")

        _s, _h, body = self._summary()
        self.assertEqual([row["name"] for row in body], ["alert-lib"])

    def test_existing_advisory_views_unchanged(self) -> None:
        self._alert("first", advisory="A-1", component="lib")
        self._summary()
        status, _h, advisories = call_json("GET", "/advisories")
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(advisories), 1)
        status, _h, detail = call_json("GET", "/advisories/A-1")
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(detail["alerts"]), 1)

    # --- Errors --------------------------------------------------------------

    def test_non_get_methods_return_405_with_allow_get(self) -> None:
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            with self.subTest(method=method):
                status, headers, body = call_json(method, PATH)
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")
                self.assertEqual(
                    body["message"],
                    f"Method {method} is not allowed for this path.",
                )
                self.assertEqual(
                    [value for name, value in headers if name == "Allow"],
                    ["GET"],
                )

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
                self.assertEqual(
                    json.loads(raw)["message"],
                    "This endpoint does not accept a request body.",
                )
                self.assertTrue(raw.endswith(b"\n"))

    def test_empty_body_accepted(self) -> None:
        for kwargs in (
            {"omit_content_length": True},
            {"body": b"", "content_length": 0},
            {"body": b"", "content_length": ""},
        ):
            with self.subTest(kwargs=kwargs):
                status, _h, raw = call("GET", PATH, **kwargs)
                self.assertEqual(status, "200 OK")
                self.assertEqual(raw, b"[]\n")

    def test_error_body_shape_and_newline(self) -> None:
        status, headers, raw = call("GET", PATH, query_string="x=1")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(
            dict(headers)["Content-Type"], "application/json; charset=utf-8"
        )
        self.assertTrue(raw.endswith(b"\n"))
        self.assertEqual(raw.count(b"\n"), 1)
        decoded = json.loads(raw.decode("utf-8"))
        self.assertEqual(set(decoded), {"error", "message"})
        self.assertEqual(decoded["error"], "invalid_request")
        self.assertEqual(decoded["message"], "Unknown query parameter: 'x'.")


if __name__ == "__main__":
    unittest.main()
