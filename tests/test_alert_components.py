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
        self._alert(resource_id, advisory="CVE-1", component="openssl")

        status, _h, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        text = raw.decode("utf-8").rstrip("\n")
        # Compact UTF-8: no added whitespace.
        self.assertNotIn(" ", text)
        keys = [
            '"name"',
            '"advisories"',
            '"alert_count"',
            '"max_severity"',
            '"resources"',
            '"resource_count"',
        ]
        positions = [text.index(key) for key in keys]
        self.assertEqual(positions, sorted(positions))

        _s, _h, body = self._summary()
        self.assertEqual(
            list(body[0]),
            [
                "name",
                "advisories",
                "alert_count",
                "max_severity",
                "resources",
                "resource_count",
            ],
        )
        self.assertEqual(body[0]["name"], "openssl")
        self.assertEqual(body[0]["advisories"], ["CVE-1"])
        self.assertEqual(body[0]["alert_count"], 1)
        self.assertEqual(body[0]["max_severity"], "high")
        self.assertEqual(body[0]["resources"], [resource_id])
        self.assertEqual(body[0]["resource_count"], 1)

    def test_name_and_advisories_echoed_verbatim(self) -> None:
        resource_id = self._create()
        self._alert(
            resource_id,
            advisory=" CVE-X ",
            component="OpenSSL ",
            severity="HIGH",
        )
        _s, _h, body = self._summary()
        self.assertEqual(len(body), 1)
        self.assertEqual(body[0]["name"], "OpenSSL ")
        self.assertEqual(body[0]["advisories"], [" CVE-X "])
        self.assertEqual(body[0]["max_severity"], "high")

    def test_response_is_utf8_and_newline_terminated(self) -> None:
        resource_id = self._create()
        self._alert(resource_id, advisory="公告-1", component="组件")
        status, _headers, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertTrue(raw.endswith(b"\n"))
        raw.decode("utf-8")

    # --- Aggregation, ordering and counts ----------------------------------

    def test_entries_follow_traversal_order(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")

        # Alerts are submitted in the opposite resource order: zeta lands
        # globally before alpha. Traversal still follows resource
        # registration order, so alpha comes out first.
        self._alert(r2, advisory="CVE-z", component="zeta")
        self._alert(r1, advisory="CVE-a", component="alpha")
        self._alert(r1, advisory="CVE-m", component="mid")

        _s, _h, body = self._summary()
        self.assertEqual([item["name"] for item in body], ["alpha", "mid", "zeta"])

    def test_advisories_deduplicated_in_first_seen_order(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        r3 = self._create(DIGEST_C, "r3")
        self._alert(r1, advisory="CVE-3", component="openssl")
        self._alert(r1, advisory="CVE-1", component="openssl")
        # Same advisory/component on another resource: the advisory stays
        # listed once, but the alert still counts.
        self._alert(r2, advisory="CVE-3", component="openssl")
        self._alert(r3, advisory="CVE-2", component="openssl")

        _s, _h, body = self._summary()
        self.assertEqual(len(body), 1)
        self.assertEqual(
            body[0]["advisories"], ["CVE-3", "CVE-1", "CVE-2"]
        )
        self.assertEqual(body[0]["alert_count"], 4)

    def test_alert_count_is_raw_without_dedup_or_merge(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        r3 = self._create(DIGEST_C, "r3")
        # The identical advisory/component pair repeats across resources;
        # each alert is counted separately.
        self._alert(r1, advisory="CVE-1", component="lib", severity="low")
        self._alert(r2, advisory="CVE-1", component="lib", severity="low")
        self._alert(r3, advisory="CVE-1", component="lib", severity="low")

        _s, _h, body = self._summary()
        self.assertEqual(body[0]["advisories"], ["CVE-1"])
        self.assertEqual(body[0]["alert_count"], 3)
        self.assertEqual(body[0]["max_severity"], "low")
        self.assertEqual(body[0]["resources"], [r1, r2, r3])
        self.assertEqual(body[0]["resource_count"], 3)

    def test_max_severity_case_insensitive_and_lowercase(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        self._alert(r1, advisory="CVE-1", component="lib", severity="LOW")
        self._alert(r1, advisory="CVE-2", component="lib", severity="Medium")
        self._alert(r2, advisory="CVE-3", component="lib", severity="HIGH")
        self._alert(r2, advisory="CVE-4", component="other", severity="low")

        _s, _h, body = self._summary()
        entries = {item["name"]: item for item in body}
        self.assertEqual(entries["lib"]["max_severity"], "high")
        self.assertEqual(entries["other"]["max_severity"], "low")

    def test_resources_deduplicated_in_registration_order(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        r3 = self._create(DIGEST_C, "r3")
        # r1 carries three alerts for the same component; it must still
        # appear once and stay first.
        self._alert(r1, advisory="CVE-1", component="lib")
        self._alert(r1, advisory="CVE-2", component="lib")
        self._alert(r1, advisory="CVE-3", component="lib")
        self._alert(r3, advisory="CVE-4", component="lib")
        self._alert(r2, advisory="CVE-5", component="lib")

        _s, _h, body = self._summary()
        self.assertEqual(body[0]["resources"], [r1, r2, r3])
        self.assertEqual(body[0]["resource_count"], 3)

    def test_first_seen_order_can_span_resources(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        self._alert(r1, advisory="CVE-a1", component="alpha")
        self._alert(r1, advisory="CVE-b1", component="beta")
        self._alert(r2, advisory="CVE-g1", component="gamma")
        self._alert(r2, advisory="CVE-a2", component="alpha")

        _s, _h, body = self._summary()
        self.assertEqual([item["name"] for item in body], ["alpha", "beta", "gamma"])
        alpha = body[0]
        self.assertEqual(alpha["advisories"], ["CVE-a1", "CVE-a2"])
        self.assertEqual(alpha["alert_count"], 2)
        self.assertEqual(alpha["resources"], [r1, r2])
        self.assertEqual(alpha["resource_count"], 2)

    def test_view_reads_alerts_only_not_sbom(self) -> None:
        resource_id = self._create()
        # An SBOM listing components, none of them named like the alert.
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
        # The alert component needs no SBOM presence to be aggregated.
        self._alert(resource_id, advisory="CVE-1", component="openssl")

        _s, _h, body = self._summary()
        self.assertEqual([item["name"] for item in body], ["openssl"])
        self.assertEqual(body[0]["resources"], [resource_id])

    def test_batch_registration_uses_array_order(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        self._batch(
            r1,
            [
                {"advisory": "CVE-2", "component": "zeta", "severity": "low",
                 "summary": "x"},
                {"advisory": "CVE-1", "component": "alpha", "severity": "low",
                 "summary": "x"},
            ],
        )
        _s, _h, body = self._summary()
        self.assertEqual([item["name"] for item in body], ["zeta", "alpha"])

    # --- Name filter --------------------------------------------------------

    def test_name_filter_returns_single_aggregated_record(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        self._alert(r1, advisory="CVE-1", component="openssl")
        self._alert(r1, advisory="CVE-2", component="zlib")
        self._alert(r2, advisory="CVE-3", component="openssl")

        _s, _h, body = self._summary("name=openssl")
        self.assertEqual(len(body), 1)
        self.assertEqual(body[0]["name"], "openssl")
        self.assertEqual(body[0]["advisories"], ["CVE-1", "CVE-3"])
        self.assertEqual(body[0]["alert_count"], 2)
        self.assertEqual(body[0]["resources"], [r1, r2])
        self.assertEqual(body[0]["resource_count"], 2)

    def test_name_filter_is_case_sensitive_and_untrimmed(self) -> None:
        resource_id = self._create()
        self._alert(resource_id, advisory="CVE-1", component="openssl")
        for query in ("name=OpenSSL", "name=OPENSSL", "name=%20openssl",
                      "name=openssl%20"):
            with self.subTest(query=query):
                status, _h, raw = call("GET", PATH, query_string=query)
                self.assertEqual(status, "200 OK")
                self.assertEqual(raw, b"[]\n")

    def test_name_filter_without_hits_returns_empty_array(self) -> None:
        resource_id = self._create()
        self._alert(resource_id, advisory="CVE-1", component="openssl")
        status, _h, raw = call("GET", PATH, query_string="name=nope")
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

    def test_unknown_or_repeated_or_empty_or_bare_name_rejected(self) -> None:
        resource_id = self._create()
        self._alert(resource_id, advisory="CVE-1", component="openssl")
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

    # --- Recomputation and read-only behavior -------------------------------

    def test_recomputes_after_single_registration(self) -> None:
        resource_id = self._create()
        _s, _h, body = self._summary()
        self.assertEqual(body, [])

        self._alert(resource_id, advisory="CVE-1", component="lib")
        _s, _h, body = self._summary()
        self.assertEqual([item["name"] for item in body], ["lib"])
        self.assertEqual(body[0]["resources"], [resource_id])

    def test_recomputes_after_in_place_update(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        alert_id = self._alert(
            r1, advisory="CVE-1", component="lib", severity="low"
        )
        self._alert(r2, advisory="CVE-2", component="lib", severity="medium")

        status, _h, _b = call_json(
            "PUT",
            f"/resources/{r1}/vulnerabilities/{alert_id}",
            {
                "advisory": "CVE-1",
                "component": "lib",
                "severity": "CRITICAL",
                "summary": "updated",
            },
        )
        self.assertEqual(status, "200 OK")

        _s, _h, body = self._summary()
        self.assertEqual(len(body), 1)
        self.assertEqual(body[0]["max_severity"], "critical")
        self.assertEqual(body[0]["alert_count"], 2)
        self.assertEqual(body[0]["advisories"], ["CVE-1", "CVE-2"])

    def test_recomputes_after_alert_delete(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        first = self._alert(r1, advisory="CVE-1", component="lib")
        self._alert(r1, advisory="CVE-2", component="lib")
        other = self._alert(r2, advisory="CVE-1", component="other")

        status, _h, _b = call_json(
            "DELETE", f"/resources/{r1}/vulnerabilities/{first}"
        )
        self.assertEqual(status, "200 OK")

        _s, _h, body = self._summary()
        entries = {item["name"]: item for item in body}
        self.assertEqual(set(entries), {"lib", "other"})
        # CVE-1 disappears from lib's advisory list once its last hit is
        # gone, and the count drops.
        self.assertEqual(entries["lib"]["advisories"], ["CVE-2"])
        self.assertEqual(entries["lib"]["alert_count"], 1)
        self.assertEqual(entries["lib"]["resources"], [r1])
        self.assertEqual(entries["lib"]["resource_count"], 1)

        # Deleting the last alert for a component drops the whole entry.
        status, _h, _b = call_json(
            "DELETE", f"/resources/{r2}/vulnerabilities/{other}"
        )
        self.assertEqual(status, "200 OK")
        _s, _h, body = self._summary()
        self.assertEqual([item["name"] for item in body], ["lib"])

    def test_recomputes_after_resource_deregistration(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        r3 = self._create(DIGEST_C, "r3")
        self._alert(r1, advisory="CVE-a", component="alpha")
        self._alert(r2, advisory="CVE-s1", component="shared")
        self._alert(r3, advisory="CVE-s2", component="shared")
        self._alert(r3, advisory="CVE-c", component="gamma")

        status, _h, _b = call_json("DELETE", f"/resources/{r2}")
        self.assertEqual(status, "200 OK")

        _s, _h, body = self._summary()
        self.assertEqual([item["name"] for item in body], ["alpha", "shared", "gamma"])
        shared = body[1]
        self.assertEqual(shared["advisories"], ["CVE-s2"])
        self.assertEqual(shared["alert_count"], 1)
        self.assertEqual(shared["resources"], [r3])
        self.assertEqual(shared["resource_count"], 1)

        status, _h, _b = call_json("DELETE", f"/resources/{r1}")
        self.assertEqual(status, "200 OK")
        _s, _h, body = self._summary()
        self.assertEqual([item["name"] for item in body], ["shared", "gamma"])

        status, _h, _b = call_json("DELETE", f"/resources/{r3}")
        self.assertEqual(status, "200 OK")
        status, _h, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

    def test_view_is_read_only(self) -> None:
        resource_id = self._create()
        self._alert(resource_id, advisory="CVE-1", component="lib")
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
        self._alert(r2, advisory="CVE-1", component="lib")

        self._summary()
        status, _h, advisories = call_json("GET", "/advisories")
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(advisories), 1)
        self.assertEqual(advisories[0]["advisory_count"], 2)
        status, _h, detail = call_json("GET", "/advisories/CVE-1")
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(detail["alerts"]), 2)
        status, _h, usage = call_json("GET", "/component-usage")
        self.assertEqual(status, "200 OK")
        self.assertEqual(usage, [])

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
        self._alert(resource_id, advisory="CVE-1", component="openssl")
        status, _h, body = call_json(
            "GET", PATH, query_string="name=openssl&x=1"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        # The view must still answer normally afterwards.
        _s, _h, after = self._summary()
        self.assertEqual([item["name"] for item in after], ["openssl"])

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
