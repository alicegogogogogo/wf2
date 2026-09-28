from __future__ import annotations

import io
import json
import unittest

from provenance_api.app import application, reset_state

PATH = "/severity-coverage"

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_D = "d" * 64


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

    def test_resources_without_alerts_produce_no_entries(self) -> None:
        self._create(DIGEST_A, "r1")
        self._create(DIGEST_B, "r2")
        status, _h, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

    def test_record_keys_and_order(self) -> None:
        resource_id = self._create()
        self._alert(resource_id, fixed_version="3.0.8")

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
        self.assertEqual(body[0]["advisories"], ["CVE-2026-0001"])
        self.assertEqual(body[0]["resources"], [resource_id])
        self.assertEqual(body[0]["resource_count"], 1)

    def test_response_is_utf8_and_newline_terminated(self) -> None:
        resource_id = self._create()
        self._alert(resource_id, advisory="公告-1", component="组件")
        status, _headers, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertTrue(raw.endswith(b"\n"))
        raw.decode("utf-8")

    # --- Grouping, ordering, dedup and counts ------------------------------

    def test_one_entry_per_severity_echoed_lowercase(self) -> None:
        resource_id = self._create()
        self._alert(resource_id, advisory="CVE-1", component="a",
                    severity="high")
        self._alert(resource_id, advisory="CVE-2", component="b",
                    severity="HIGH", fixed_version="1")
        self._alert(resource_id, advisory="CVE-3", component="c",
                    severity="High")
        self._alert(resource_id, advisory="CVE-4", component="d",
                    severity="low", fixed_version="2")

        _s, _h, body = self._summary()
        self.assertEqual([item["severity"] for item in body], ["high", "low"])
        high = body[0]
        self.assertEqual(high["alert_count"], 3)
        self.assertEqual(high["fixed_count"], 1)
        self.assertEqual(high["unfixed_count"], 2)
        self.assertEqual(high["advisories"], ["CVE-1", "CVE-2", "CVE-3"])
        self.assertEqual(high["resources"], [resource_id])
        self.assertEqual(high["resource_count"], 1)

    def test_entries_follow_first_severity_occurrence(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        r3 = self._create(DIGEST_C, "r3")

        # Alerts are submitted starting from the last-registered resource,
        # but the traversal is fixed to resource registration order, so the
        # first occurrence of each level follows r1, r2, r3 -- not the
        # critical>high>... rank order and not submission wall-clock.
        self._alert(r3, advisory="CVE-z", component="zeta", severity="high")
        self._alert(r2, advisory="CVE-m", component="mid", severity="low")
        self._alert(r1, advisory="CVE-a", component="alpha",
                    severity="critical")

        _s, _h, body = self._summary()
        self.assertEqual(
            [item["severity"] for item in body], ["critical", "low", "high"]
        )

    def test_advisories_deduplicated_in_first_seen_order(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        self._alert(r1, advisory="CVE-3", component="c3", severity="high",
                    fixed_version="1")
        self._alert(r2, advisory="CVE-1", component="c1", severity="high")
        self._alert(r1, advisory="CVE-2", component="c2", severity="high")
        self._alert(r2, advisory="CVE-3", component="c3b", severity="high",
                    fixed_version="9")
        self._alert(r1, advisory="CVE-1", component="c1b",
                    severity="critical")

        _s, _h, body = self._summary()
        levels = {item["severity"]: item for item in body}
        # Traversal is r1 then r2, each in submission order:
        # high advisories visit r1's CVE-3, CVE-2 before r2's CVE-1
        # (r2's CVE-3 repeat drops), regardless of submission wall-clock.
        self.assertEqual(
            levels["high"]["advisories"], ["CVE-3", "CVE-2", "CVE-1"]
        )
        self.assertEqual(levels["critical"]["advisories"], ["CVE-1"])

    def test_advisories_are_case_sensitive(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        # Distinct (advisory, component) pairs, so both register; the
        # advisory strings differ only in case and must not fold together.
        self._alert(r1, advisory="CVE-1", component="lib-a", severity="high")
        self._alert(r1, advisory="cve-1", component="lib-b", severity="high")

        _s, _h, body = self._summary()
        self.assertEqual(body[0]["advisories"], ["CVE-1", "cve-1"])
        self.assertEqual(body[0]["alert_count"], 2)

    def test_resources_deduplicated_in_registration_order(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        r3 = self._create(DIGEST_C, "r3")
        # r3 alerts first; the high resource list must still read r1..r3.
        self._alert(r3, advisory="CVE-1", component="a", severity="high")
        self._alert(r3, advisory="CVE-2", component="b", severity="high",
                    fixed_version="1")
        self._alert(r1, advisory="CVE-3", component="c", severity="high")
        self._alert(r2, advisory="CVE-4", component="d", severity="low")

        _s, _h, body = self._summary()
        levels = {item["severity"]: item for item in body}
        self.assertEqual(levels["high"]["resources"], [r1, r3])
        self.assertEqual(levels["high"]["resource_count"], 2)
        self.assertEqual(levels["low"]["resources"], [r2])
        self.assertEqual(levels["low"]["resource_count"], 1)

    def test_counts_are_raw_without_dedup_or_merge(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        self._alert(r1, advisory="CVE-1", component="lib", severity="high",
                    fixed_version="1.0")
        self._alert(r1, advisory="CVE-2", component="other", severity="high")
        self._alert(r2, advisory="CVE-3", component="lib", severity="high",
                    fixed_version="2.0")
        self._alert(r2, advisory="CVE-4", component="yet", severity="low")

        _s, _h, body = self._summary()
        levels = {item["severity"]: item for item in body}
        self.assertEqual(levels["high"]["alert_count"], 3)
        self.assertEqual(levels["high"]["fixed_count"], 2)
        self.assertEqual(levels["high"]["unfixed_count"], 1)
        self.assertEqual(levels["low"]["alert_count"], 1)
        self.assertEqual(levels["low"]["fixed_count"], 0)
        self.assertEqual(levels["low"]["unfixed_count"], 1)

    def test_counts_always_sum_to_alert_total(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        for level in ("critical", "high", "medium", "low"):
            self._alert(
                r1,
                advisory=f"CVE-{level}",
                component=f"c-{level}",
                severity=level,
                fixed_version="1",
            )
            self._alert(
                r1,
                advisory=f"CVE-{level}-u",
                component=f"d-{level}",
                severity=level,
            )

        _s, _h, body = self._summary()
        self.assertEqual(
            [item["severity"] for item in body],
            ["critical", "high", "medium", "low"],
        )
        for item in body:
            self.assertEqual(
                item["alert_count"],
                item["fixed_count"] + item["unfixed_count"],
            )
            self.assertEqual(item["alert_count"], 2)
            self.assertEqual(item["fixed_count"], 1)
            self.assertEqual(item["unfixed_count"], 1)

    def test_batch_registration_uses_array_order(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        self._batch(
            r1,
            [
                {"advisory": "CVE-2", "component": "zeta", "severity": "low",
                 "summary": "x", "fixed_version": "1"},
                {"advisory": "CVE-1", "component": "alpha", "severity": "low",
                 "summary": "x"},
            ],
        )
        _s, _h, body = self._summary()
        self.assertEqual(len(body), 1)
        self.assertEqual(body[0]["severity"], "low")
        self.assertEqual(body[0]["advisories"], ["CVE-2", "CVE-1"])
        self.assertEqual(body[0]["alert_count"], 2)
        self.assertEqual(body[0]["fixed_count"], 1)
        self.assertEqual(body[0]["unfixed_count"], 1)

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
        # The SBOM contributes nothing: before the alert there is no entry.
        status, _h, raw = call("GET", PATH)
        self.assertEqual(raw, b"[]\n")
        self._alert(resource_id, advisory="CVE-1", component="openssl",
                    severity="medium")
        _s, _h, body = self._summary()
        self.assertEqual([item["severity"] for item in body], ["medium"])
        self.assertEqual(body[0]["advisories"], ["CVE-1"])

    # --- Recomputation and read-only behavior ------------------------------

    def test_recomputes_after_single_registration(self) -> None:
        resource_id = self._create()
        self.assertEqual(call("GET", PATH)[2], b"[]\n")

        self._alert(resource_id, advisory="CVE-1", component="lib",
                    severity="low")
        _s, _h, body = self._summary()
        self.assertEqual([item["severity"] for item in body], ["low"])
        self.assertEqual(body[0]["unfixed_count"], 1)
        self.assertEqual(body[0]["advisories"], ["CVE-1"])

    def test_recomputes_after_in_place_update(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        alert_id = self._alert(
            r1, advisory="CVE-1", component="lib", severity="low",
            fixed_version="1.0",
        )

        # Dropping the fixed version moves the alert to the unfixed tally.
        status, _h, _b = call_json(
            "PUT",
            f"/resources/{r1}/vulnerabilities/{alert_id}",
            {
                "advisory": "CVE-1",
                "component": "lib",
                "severity": "low",
                "summary": "updated",
            },
        )
        self.assertEqual(status, "200 OK")
        _s, _h, body = self._summary()
        self.assertEqual(len(body), 1)
        self.assertEqual(body[0]["severity"], "low")
        self.assertEqual(body[0]["fixed_count"], 0)
        self.assertEqual(body[0]["unfixed_count"], 1)

        # Changing the severity on update moves the alert to another level.
        status, _h, _b = call_json(
            "PUT",
            f"/resources/{r1}/vulnerabilities/{alert_id}",
            {
                "advisory": "CVE-1",
                "component": "lib",
                "severity": "critical",
                "summary": "updated",
                "fixed_version": "2.0",
            },
        )
        self.assertEqual(status, "200 OK")
        _s, _h, body = self._summary()
        self.assertEqual([item["severity"] for item in body], ["critical"])
        self.assertEqual(body[0]["fixed_count"], 1)
        self.assertEqual(body[0]["unfixed_count"], 0)
        self.assertEqual(body[0]["advisories"], ["CVE-1"])

    def test_level_disappears_after_last_alert_delete(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        first = self._alert(
            r1, advisory="CVE-1", component="lib", severity="high",
            fixed_version="1.0",
        )
        self._alert(r1, advisory="CVE-2", component="other", severity="low")

        status, _h, _b = call_json(
            "DELETE", f"/resources/{r1}/vulnerabilities/{first}"
        )
        self.assertEqual(status, "200 OK")
        _s, _h, body = self._summary()
        self.assertEqual([item["severity"] for item in body], ["low"])
        self.assertEqual(body[0]["alert_count"], 1)
        self.assertEqual(body[0]["unfixed_count"], 1)
        self.assertEqual(body[0]["advisories"], ["CVE-2"])

    def test_recomputes_after_resource_deregistration(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        r3 = self._create(DIGEST_C, "r3")
        self._alert(r1, advisory="CVE-a", component="alpha",
                    severity="critical", fixed_version="1")
        self._alert(r2, advisory="CVE-s", component="shared", severity="high")
        self._alert(r3, advisory="CVE-c", component="gamma", severity="high",
                    fixed_version="3")

        status, _h, _b = call_json("DELETE", f"/resources/{r2}")
        self.assertEqual(status, "200 OK")
        _s, _h, body = self._summary()
        levels = {item["severity"]: item for item in body}
        # The first severity seen is now critical (r1); high survives via r3.
        self.assertEqual(
            [item["severity"] for item in body], ["critical", "high"]
        )
        self.assertEqual(levels["high"]["resources"], [r3])
        self.assertEqual(levels["high"]["advisories"], ["CVE-c"])

        status, _h, _b = call_json("DELETE", f"/resources/{r1}")
        self.assertEqual(status, "200 OK")
        _s, _h, body = self._summary()
        self.assertEqual([item["severity"] for item in body], ["high"])

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
        self._alert(r1, advisory="CVE-1", component="lib")
        self._alert(r2, advisory="CVE-1", component="lib",
                    fixed_version="1.0")

        self._summary()
        status, _h, coverage = call_json("GET", "/fix-coverage")
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(coverage), 1)
        self.assertEqual(coverage[0]["name"], "lib")
        self.assertEqual(coverage[0]["fixed_count"], 1)
        self.assertEqual(coverage[0]["unfixed_count"], 1)

        status, _h, progress = call_json("GET", "/fix-coverage-progress")
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(progress), 2)

        status, _h, advisories = call_json("GET", "/advisories")
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(advisories), 1)
        status, _h, detail = call_json("GET", "/advisories/CVE-1")
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(detail["alerts"]), 2)
        status, _h, usage = call_json("GET", "/alert-components")
        self.assertEqual(status, "200 OK")
        self.assertEqual(usage[0]["alert_count"], 2)

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
        for query in ("x=1", "x=", "bogus=1", "page=2", "severity=high",
                      "name=openssl"):
            with self.subTest(query=query):
                status, _h, body = call_json(
                    "GET", PATH, query_string=query
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_repeated_query_parameter_rejected(self) -> None:
        for query in ("x=1&x=2", "a=&a=1"):
            with self.subTest(query=query):
                status, _h, body = call_json(
                    "GET", PATH, query_string=query
                )
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
        status, _h, body = call_json(
            "GET", PATH, query_string="x=1"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        # The view must still answer normally afterwards.
        _s, _h, after = self._summary()
        self.assertEqual(after[0]["severity"], "high")

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
