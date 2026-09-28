from __future__ import annotations

import io
import json
import unittest

from provenance_api.app import application, reset_state

PATH = "/severity-coverage"

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


class SeverityCoverageTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def _create(self, digest: str = DIGEST_A, name: str = "r") -> str:
        _s, _h, body = call_json(
            "POST",
            "/resources",
            {"name": name, "category": "code", "digest": digest},
        )
        return str(body["id"])  # type: ignore[index]

    def _alert(
        self,
        resource_id: str,
        *,
        advisory: str = "CVE-2026-0001",
        component: str = "openssl",
        severity: str = "high",
        summary: str = "a bug",
        fixed_version: object = ...,  # type: ignore[assignment]
    ) -> str:
        payload: dict[str, object] = {
            "advisory": advisory,
            "component": component,
            "severity": severity,
            "summary": summary,
        }
        if fixed_version is not ...:
            payload["fixed_version"] = fixed_version
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/vulnerabilities",
            payload,
        )
        assert status == "201 Created", body
        return str(body["id"])  # type: ignore[index]

    def _batch(
        self, resource_id: str, items: list[dict[str, object]]
    ) -> list[str]:
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/vulnerabilities/batch",
            {"vulnerabilities": items},
        )
        assert status == "201 Created", body
        return [str(item["id"]) for item in body["vulnerabilities"]]  # type: ignore[index]

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

    def test_empty_when_no_resources(self) -> None:
        status, headers, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )

    def test_empty_when_resources_have_no_alerts(self) -> None:
        self._create(DIGEST_A, "r1")
        self._create(DIGEST_B, "r2")
        _s, _h, body = self._summary()
        self.assertEqual(body, [])

    def test_record_keys_and_order(self) -> None:
        resource_id = self._create()
        self._alert(
            resource_id, advisory="CVE-1", component="openssl",
            severity="HIGH", fixed_version="3.0.8",
        )

        status, _h, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        text = raw.decode("utf-8").rstrip("\n")
        # Compact UTF-8: no added whitespace.
        self.assertNotIn(" ", text)
        keys = [
            '"severity"',
            '"alert_count"',
            '"fixed_count"',
            '"unfixed_count"',
            '"advisories"',
            '"resources"',
            '"resource_count"',
        ]
        positions = [text.index(key) for key in keys]
        self.assertEqual(positions, sorted(positions))

        _s, _h, body = self._summary()
        self.assertEqual(
            list(body[0]),
            [
                "severity",
                "alert_count",
                "fixed_count",
                "unfixed_count",
                "advisories",
                "resources",
                "resource_count",
            ],
        )
        self.assertEqual(body[0]["severity"], "high")
        self.assertEqual(body[0]["alert_count"], 1)
        self.assertEqual(body[0]["fixed_count"], 1)
        self.assertEqual(body[0]["unfixed_count"], 0)
        self.assertEqual(body[0]["advisories"], ["CVE-1"])
        self.assertEqual(body[0]["resources"], [resource_id])
        self.assertEqual(body[0]["resource_count"], 1)

    def test_severity_grouped_on_lowercase_registration_value(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        self._alert(r1, advisory="CVE-1", component="lib", severity="HIGH")
        self._alert(r2, advisory="CVE-2", component="lib", severity="High")
        self._alert(r2, advisory="CVE-3", component="lib", severity="high")

        _s, _h, body = self._summary()
        self.assertEqual(len(body), 1)
        self.assertEqual(body[0]["severity"], "high")
        self.assertEqual(body[0]["alert_count"], 3)

    def test_advisory_values_echoed_verbatim(self) -> None:
        resource_id = self._create()
        self._alert(resource_id, advisory=" CVE-X ", severity="low")
        _s, _h, body = self._summary()
        self.assertEqual(body[0]["severity"], "low")
        self.assertEqual(body[0]["advisories"], [" CVE-X "])

    def test_response_is_utf8_and_newline_terminated(self) -> None:
        resource_id = self._create()
        self._alert(resource_id, advisory="公告-1", severity="low")
        status, _headers, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertTrue(raw.endswith(b"\n"))
        raw.decode("utf-8")

    # --- Aggregation, ordering and counts ----------------------------------

    def test_entries_follow_traversal_order(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")

        # Alerts are submitted in the opposite resource order: low lands
        # globally before medium. Traversal still follows resource
        # registration order, so medium comes out first.
        self._alert(r2, advisory="CVE-l", component="zeta", severity="low")
        self._alert(r1, advisory="CVE-m", component="alpha", severity="medium")
        self._alert(r1, advisory="CVE-c", component="mid", severity="critical")

        _s, _h, body = self._summary()
        self.assertEqual(
            [item["severity"] for item in body], ["medium", "critical", "low"]
        )

    def test_entries_not_severity_ranked(self) -> None:
        resource_id = self._create()
        # First appearance order is low then high then critical, not the
        # critical-high-medium-low ranking.
        self._alert(resource_id, advisory="CVE-1", component="a", severity="low")
        self._alert(resource_id, advisory="CVE-2", component="b", severity="high")
        self._alert(resource_id, advisory="CVE-3", component="c",
                    severity="critical")

        _s, _h, body = self._summary()
        self.assertEqual(
            [item["severity"] for item in body], ["low", "high", "critical"]
        )

    def test_first_seen_order_can_span_resources(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        self._alert(r1, advisory="CVE-a", component="alpha", severity="low",
                    fixed_version="1")
        self._alert(r1, advisory="CVE-b", component="beta", severity="medium")
        self._alert(r2, advisory="CVE-g", component="gamma", severity="high")
        self._alert(r2, advisory="CVE-c", component="alpha2", severity="low")

        _s, _h, body = self._summary()
        self.assertEqual(
            [item["severity"] for item in body], ["low", "medium", "high"]
        )
        low = body[0]
        self.assertEqual(low["alert_count"], 2)
        self.assertEqual(low["fixed_count"], 1)
        self.assertEqual(low["unfixed_count"], 1)
        self.assertEqual(low["advisories"], ["CVE-a", "CVE-c"])
        self.assertEqual(low["resources"], [r1, r2])
        self.assertEqual(low["resource_count"], 2)

    def test_counts_are_raw_without_dedup_or_merge(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        r3 = self._create(DIGEST_C, "r3")
        # The identical advisory/component triple repeats across resources;
        # each alert is counted separately.
        self._alert(r1, advisory="CVE-1", component="lib", severity="high",
                    fixed_version="1.0")
        self._alert(r2, advisory="CVE-1", component="lib", severity="high",
                    fixed_version="1.0")
        self._alert(r3, advisory="CVE-1", component="lib", severity="high")

        _s, _h, body = self._summary()
        self.assertEqual(len(body), 1)
        self.assertEqual(body[0]["alert_count"], 3)
        self.assertEqual(body[0]["fixed_count"], 2)
        self.assertEqual(body[0]["unfixed_count"], 1)
        self.assertEqual(body[0]["advisories"], ["CVE-1"])
        self.assertEqual(body[0]["resources"], [r1, r2, r3])
        self.assertEqual(body[0]["resource_count"], 3)

    def test_advisories_deduplicated_in_first_seen_order(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        r3 = self._create(DIGEST_C, "r3")
        self._alert(r1, advisory="CVE-3", component="openssl", severity="high",
                    fixed_version="3.0.8")
        self._alert(r1, advisory="CVE-1", component="zlib", severity="high",
                    fixed_version="3.1.0")
        self._alert(r2, advisory="CVE-3", component="openssl", severity="high",
                    fixed_version="3.0.8")
        self._alert(r3, advisory="CVE-2", component="curl", severity="high")

        _s, _h, body = self._summary()
        self.assertEqual(len(body), 1)
        self.assertEqual(body[0]["advisories"], ["CVE-3", "CVE-1", "CVE-2"])
        self.assertEqual(body[0]["alert_count"], 4)
        self.assertEqual(body[0]["fixed_count"], 3)
        self.assertEqual(body[0]["unfixed_count"], 1)
        self.assertEqual(body[0]["resources"], [r1, r2, r3])

    def test_advisories_deduplicated_case_sensitively(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        self._alert(r1, advisory="CVE-1", component="lib", severity="low",
                    fixed_version="1.0")
        self._alert(r2, advisory="cve-1", component="lib", severity="low")

        _s, _h, body = self._summary()
        self.assertEqual(body[0]["advisories"], ["CVE-1", "cve-1"])
        self.assertEqual(body[0]["fixed_count"], 1)
        self.assertEqual(body[0]["unfixed_count"], 1)

    def test_resources_deduplicated_in_registration_order(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        r3 = self._create(DIGEST_C, "r3")
        # r2 contributes before r1, but the resource list follows
        # registration order; multiple alerts for one resource count once.
        self._alert(r2, advisory="CVE-1", component="a", severity="low")
        self._alert(r2, advisory="CVE-2", component="b", severity="low",
                    fixed_version="1")
        self._alert(r1, advisory="CVE-3", component="c", severity="low")
        self._alert(r3, advisory="CVE-4", component="d", severity="low")

        _s, _h, body = self._summary()
        self.assertEqual(body[0]["resources"], [r1, r2, r3])
        self.assertEqual(body[0]["resource_count"], 3)
        self.assertEqual(body[0]["alert_count"], 4)

    def test_severity_buckets_share_neither_advisories_nor_resources(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        self._alert(r1, advisory="CVE-1", component="lib", severity="high",
                    fixed_version="1")
        self._alert(r1, advisory="CVE-2", component="lib", severity="low")
        self._alert(r2, advisory="CVE-1", component="lib", severity="medium")

        _s, _h, body = self._summary()
        entries = {item["severity"]: item for item in body}
        self.assertEqual(set(entries), {"high", "low", "medium"})
        self.assertEqual(entries["high"]["resources"], [r1])
        self.assertEqual(entries["low"]["resources"], [r1])
        self.assertEqual(entries["medium"]["resources"], [r2])
        self.assertEqual(entries["high"]["advisories"], ["CVE-1"])
        self.assertEqual(entries["medium"]["advisories"], ["CVE-1"])
        self.assertEqual(entries["high"]["alert_count"], 1)
        self.assertEqual(entries["medium"]["alert_count"], 1)
        self.assertEqual(entries["low"]["alert_count"], 1)

    def test_batch_registration_uses_array_order(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        self._batch(
            r1,
            [
                {"advisory": "CVE-2", "component": "zeta", "severity": "low",
                 "summary": "x", "fixed_version": "1"},
                {"advisory": "CVE-1", "component": "alpha", "severity": "high",
                 "summary": "x"},
            ],
        )
        _s, _h, body = self._summary()
        self.assertEqual(
            [item["severity"] for item in body], ["low", "high"]
        )

    def test_view_reads_alerts_only_not_sbom(self) -> None:
        resource_id = self._create()
        status, _h, _b = call_json(
            "POST",
            f"/resources/{resource_id}/sbom",
            {
                "format": "spdx",
                "components": [
                    {"name": "zlib", "version": "1", "digest": "ab" * 32}
                ],
            },
        )
        self.assertEqual(status, "201 Created")
        self._alert(resource_id, advisory="CVE-1", component="openssl",
                    severity="high")

        _s, _h, body = self._summary()
        self.assertEqual([item["severity"] for item in body], ["high"])

    # --- Recomputation and read-only behavior -------------------------------

    def test_recomputes_after_single_registration(self) -> None:
        resource_id = self._create()
        _s, _h, body = self._summary()
        self.assertEqual(body, [])

        self._alert(resource_id, advisory="CVE-1", component="lib",
                    severity="medium")
        _s, _h, body = self._summary()
        self.assertEqual([item["severity"] for item in body], ["medium"])
        self.assertEqual(body[0]["unfixed_count"], 1)

    def test_recomputes_after_in_place_update(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        alert_id = self._alert(
            r1, advisory="CVE-1", component="lib", severity="low",
            fixed_version="1.0",
        )
        self._alert(r2, advisory="CVE-2", component="lib", severity="low")

        # Dropping the fixed version moves the alert to the unfixed tally;
        # changing severity moves it to another bucket.
        status, _h, _b = call_json(
            "PUT",
            f"/resources/{r1}/vulnerabilities/{alert_id}",
            {
                "advisory": "CVE-1",
                "component": "lib",
                "severity": "high",
                "summary": "updated",
            },
        )
        self.assertEqual(status, "200 OK")

        _s, _h, body = self._summary()
        entries = {item["severity"]: item for item in body}
        self.assertEqual(set(entries), {"low", "high"})
        self.assertEqual(entries["high"]["fixed_count"], 0)
        self.assertEqual(entries["high"]["unfixed_count"], 1)
        self.assertEqual(entries["high"]["advisories"], ["CVE-1"])
        self.assertEqual(entries["low"]["unfixed_count"], 1)

    def test_recomputes_after_alert_delete(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        first = self._alert(
            r1, advisory="CVE-1", component="lib", severity="high",
            fixed_version="1.0",
        )
        self._alert(r1, advisory="CVE-2", component="lib", severity="high")
        low_id = self._alert(
            r2, advisory="CVE-1", component="other", severity="low"
        )

        status, _h, _b = call_json(
            "DELETE", f"/resources/{r1}/vulnerabilities/{first}"
        )
        self.assertEqual(status, "200 OK")

        _s, _h, body = self._summary()
        entries = {item["severity"]: item for item in body}
        self.assertEqual(set(entries), {"high", "low"})
        # The only remaining high alert is unfixed.
        self.assertEqual(entries["high"]["fixed_count"], 0)
        self.assertEqual(entries["high"]["unfixed_count"], 1)
        self.assertEqual(entries["high"]["advisories"], ["CVE-2"])
        self.assertEqual(entries["high"]["resources"], [r1])
        self.assertEqual(entries["low"]["resources"], [r2])

        # Deleting the last alert at a level drops the whole entry.
        status, _h, _b = call_json(
            "DELETE", f"/resources/{r2}/vulnerabilities/{low_id}"
        )
        self.assertEqual(status, "200 OK")
        _s, _h, body = self._summary()
        self.assertEqual([item["severity"] for item in body], ["high"])

    def test_recomputes_after_resource_deregistration(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        r3 = self._create(DIGEST_C, "r3")
        self._alert(r1, advisory="CVE-a", component="alpha", severity="high",
                    fixed_version="1")
        self._alert(r2, advisory="CVE-s1", component="shared", severity="high",
                    fixed_version="2")
        self._alert(r3, advisory="CVE-s2", component="shared", severity="high")
        self._alert(r3, advisory="CVE-c", component="gamma", severity="low",
                    fixed_version="3")

        status, _h, _b = call_json("DELETE", f"/resources/{r2}")
        self.assertEqual(status, "200 OK")

        _s, _h, body = self._summary()
        entries = {item["severity"]: item for item in body}
        self.assertEqual(set(entries), {"high", "low"})
        high = entries["high"]
        self.assertEqual(high["alert_count"], 2)
        self.assertEqual(high["fixed_count"], 1)
        self.assertEqual(high["unfixed_count"], 1)
        self.assertEqual(high["advisories"], ["CVE-a", "CVE-s2"])
        self.assertEqual(high["resources"], [r1, r3])
        self.assertEqual(high["resource_count"], 2)

        status, _h, _b = call_json("DELETE", f"/resources/{r1}")
        self.assertEqual(status, "200 OK")
        _s, _h, body = self._summary()
        entries = {item["severity"]: item for item in body}
        self.assertEqual(entries["high"]["resources"], [r3])
        self.assertEqual(entries["high"]["unfixed_count"], 1)

        status, _h, _b = call_json("DELETE", f"/resources/{r3}")
        self.assertEqual(status, "200 OK")
        status, _h, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

    def test_view_is_read_only(self) -> None:
        resource_id = self._create()
        self._alert(resource_id, advisory="CVE-1", component="lib",
                    severity="high")
        first_status, _h, first = call("GET", PATH)
        second_status, _h, second = call("GET", PATH)
        self.assertEqual(first_status, second_status)
        self.assertEqual(first, second)

        status, _h, alerts = call_json(
            "GET", f"/resources/{resource_id}/vulnerabilities"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(alerts), 1)

    def test_existing_views_unchanged(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        self._alert(r1, advisory="CVE-1", component="lib", severity="high")
        self._alert(r2, advisory="CVE-1", component="lib", severity="high")

        self._summary()
        status, _h, advisories = call_json("GET", "/advisories")
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(advisories), 1)
        self.assertEqual(advisories[0]["advisory_count"], 2)
        status, _h, detail = call_json("GET", "/advisories/CVE-1")
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(detail["alerts"]), 2)
        status, _h, coverage = call_json("GET", "/fix-coverage")
        self.assertEqual(status, "200 OK")
        self.assertEqual(coverage[0]["fixed_count"], 0)
        self.assertEqual(coverage[0]["unfixed_count"], 2)
        status, _h, progress = call_json("GET", "/fix-coverage-progress")
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(progress), 2)

    # --- Errors --------------------------------------------------------------

    def test_non_get_methods_return_405_with_allow_get(self) -> None:
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            with self.subTest(method=method):
                status, headers, body = call_json(method, PATH)
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")
                allow_values = [
                    value for name, value in headers if name == "Allow"
                ]
                self.assertEqual(allow_values, ["GET"])

    def test_any_query_parameter_rejected(self) -> None:
        resource_id = self._create()
        self._alert(resource_id, advisory="CVE-1", component="openssl",
                    severity="high")
        for query in (
            "x=1",
            "severity=high",
            "x=",
            "x",
            "x=1&y=2",
            "x=1&x=2",
        ):
            with self.subTest(query=query):
                status, _h, body = call_json("GET", PATH, query_string=query)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_non_empty_body_rejected(self) -> None:
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
                self.assertTrue(raw.endswith(b"\n"))

    def test_empty_body_accepted(self) -> None:
        status, _h, raw = call("GET", PATH, omit_content_length=True)
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

        status, _h, raw = call("GET", PATH, body=b"", content_length=0)
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

        status, _h, raw = call("GET", PATH, body=b"", content_length="")
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

    def test_bad_request_does_not_read_business_data(self) -> None:
        resource_id = self._create()
        self._alert(resource_id, advisory="CVE-1", component="openssl",
                    severity="high")
        status, _h, body = call_json("GET", PATH, query_string="x=1")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        # The view must still answer normally afterwards.
        _s, _h, after = self._summary()
        self.assertEqual([item["severity"] for item in after], ["high"])

    def test_error_body_uses_existing_shape(self) -> None:
        status, _h, raw = call("GET", PATH, query_string="x=1")
        self.assertEqual(status, "400 Bad Request")
        self.assertTrue(raw.endswith(b"\n"))
        text = raw.decode("utf-8").rstrip("\n")
        decoded = json.loads(text)
        self.assertEqual(set(decoded), {"error", "message"})
        self.assertEqual(decoded["error"], "invalid_request")
        self.assertEqual(
            text,
            json.dumps(decoded, ensure_ascii=False, separators=(",", ":")),
        )


if __name__ == "__main__":
    unittest.main()
