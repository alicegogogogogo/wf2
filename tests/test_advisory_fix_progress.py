from __future__ import annotations

import io
import json
import unittest

from provenance_api.app import application, reset_state

PATH = "/advisory-fix-progress"

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


class AdvisoryFixProgressTests(unittest.TestCase):
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
    ) -> list[dict[str, object]]:
        status, headers, body = call_json(
            "GET", PATH, query_string=query_string
        )
        self.assertEqual(status, "200 OK")
        self.assertIsInstance(body, list)
        return body  # type: ignore[return-value]

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
        status, _h, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

    def test_record_keys_and_order(self) -> None:
        resource_id = self._create()
        self._alert(
            resource_id, advisory="CVE-1", component="openssl",
            fixed_version="3.0.8",
        )

        status, _h, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        text = raw.decode("utf-8").rstrip("\n")
        # Compact UTF-8: no added whitespace.
        self.assertNotIn(" ", text)
        keys = [
            '"advisory"',
            '"alert_count"',
            '"fixed_count"',
            '"unfixed_count"',
            '"components"',
            '"resources"',
            '"resource_count"',
        ]
        positions = [text.index(key) for key in keys]
        self.assertEqual(positions, sorted(positions))

        body = self._summary()
        self.assertEqual(
            list(body[0]),
            [
                "advisory",
                "alert_count",
                "fixed_count",
                "unfixed_count",
                "components",
                "resources",
                "resource_count",
            ],
        )
        self.assertEqual(body[0]["advisory"], "CVE-1")
        self.assertEqual(body[0]["alert_count"], 1)
        self.assertEqual(body[0]["fixed_count"], 1)
        self.assertEqual(body[0]["unfixed_count"], 0)
        self.assertEqual(body[0]["components"], ["openssl"])
        self.assertEqual(body[0]["resources"], [resource_id])
        self.assertEqual(body[0]["resource_count"], 1)

    def test_response_is_utf8_and_newline_terminated(self) -> None:
        resource_id = self._create()
        self._alert(
            resource_id, advisory="公告-1", component="组件",
            fixed_version="版本-一",
        )
        status, _headers, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertTrue(raw.endswith(b"\n"))
        raw.decode("utf-8")

    # --- Ordering -----------------------------------------------------------

    def test_entries_follow_first_occurrence_traversal(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        r3 = self._create(DIGEST_C, "r3")

        # Alerts arrive so later-registered resources introduce advisories
        # first; entries must still unfold by first occurrence in the
        # resource-registration / alert-submission traversal.
        self._alert(r3, advisory="CVE-z", component="zeta")
        self._alert(r2, advisory="CVE-m", component="mid")
        self._alert(r1, advisory="CVE-a", component="alpha")
        self._alert(r3, advisory="CVE-a", component="alpha")
        self._alert(r2, advisory="CVE-a", component="alpha")

        body = self._summary()
        self.assertEqual(
            [item["advisory"] for item in body],
            ["CVE-a", "CVE-m", "CVE-z"],
        )

    def test_each_advisory_appears_once(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        self._alert(r1, advisory="CVE-1", component="lib")
        self._alert(r1, advisory="CVE-1", component="other")
        self._alert(r1, advisory="CVE-2", component="lib")

        body = self._summary()
        self.assertEqual([item["advisory"] for item in body], ["CVE-1", "CVE-2"])
        self.assertEqual(len(body), 2)

    def test_advisory_echoed_verbatim_case_and_whitespace(self) -> None:
        resource_id = self._create()
        self._alert(resource_id, advisory=" CVE-1 ", component="a")
        self._alert(resource_id, advisory="cve-1", component="b")
        self._alert(resource_id, advisory="CVE-1", component="c")

        body = self._summary()
        self.assertEqual(
            [item["advisory"] for item in body],
            [" CVE-1 ", "cve-1", "CVE-1"],
        )

    # --- Components and resources ------------------------------------------

    def test_components_deduplicated_in_first_occurrence_order(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        self._alert(r1, advisory="CVE-1", component="zeta",
                    fixed_version="1")
        self._alert(r1, advisory="CVE-1", component="alpha",
                    fixed_version="3")
        self._alert(r2, advisory="CVE-1", component="alpha")
        self._alert(r2, advisory="CVE-1", component="mid",
                    fixed_version="2")
        self._alert(r2, advisory="CVE-1", component="zeta")

        body = self._summary()
        # r1 contributes zeta then alpha; r2's alpha and zeta are repeats,
        # so mid is the only new component and lands after alpha.
        self.assertEqual(body[0]["components"], ["zeta", "alpha", "mid"])

    def test_components_are_case_sensitive_and_untrimmed(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        self._alert(r1, advisory="CVE-1", component="openssl")
        self._alert(r1, advisory="CVE-1", component=" openssl ")
        self._alert(r2, advisory="CVE-1", component="OpenSSL")

        body = self._summary()
        # r1 is traversed in full before r2, so r2's component comes last.
        self.assertEqual(
            body[0]["components"], ["openssl", " openssl ", "OpenSSL"]
        )

    def test_resources_deduplicated_in_registration_order(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        r3 = self._create(DIGEST_C, "r3")
        # r3 mentions the advisory before earlier resources ever do; the
        # resource list must still follow registration order.
        self._alert(r3, advisory="CVE-1", component="c")
        self._alert(r2, advisory="CVE-1", component="b")
        self._alert(r3, advisory="CVE-1", component="c2")
        self._alert(r1, advisory="CVE-1", component="a")
        self._alert(r2, advisory="CVE-1", component="b2")

        body = self._summary()
        self.assertEqual(body[0]["resources"], [r1, r2, r3])
        self.assertEqual(body[0]["resource_count"], 3)

    def test_resources_without_alert_for_advisory_are_absent(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        r3 = self._create(DIGEST_C, "r3")
        self._alert(r1, advisory="CVE-1", component="a")
        self._alert(r3, advisory="CVE-1", component="c")
        # r2 has only an unrelated advisory.
        self._alert(r2, advisory="CVE-2", component="b")

        entries = {item["advisory"]: item for item in self._summary()}
        self.assertEqual(entries["CVE-1"]["resources"], [r1, r3])
        self.assertEqual(entries["CVE-1"]["resource_count"], 2)
        self.assertEqual(entries["CVE-2"]["resources"], [r2])
        self.assertEqual(entries["CVE-2"]["resource_count"], 1)

    def test_resource_count_matches_resources_length(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        self._alert(r1, advisory="CVE-1", component="a")
        self._alert(r1, advisory="CVE-1", component="b")
        self._alert(r2, advisory="CVE-1", component="a")
        for item in self._summary():
            self.assertEqual(
                item["resource_count"], len(item["resources"])
            )

    # --- Counts -------------------------------------------------------------

    def test_counts_are_raw_without_dedup_or_merge(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        # The same advisory/component pair repeats across resources; each
        # alert counts separately.
        self._alert(r1, advisory="CVE-1", component="lib",
                    fixed_version="1.0")
        self._alert(r1, advisory="CVE-1", component="lib2")
        self._alert(r2, advisory="CVE-1", component="lib",
                    fixed_version="2.0")
        self._alert(r2, advisory="CVE-1", component="other")

        body = self._summary()
        self.assertEqual(len(body), 1)
        entry = body[0]
        self.assertEqual(entry["alert_count"], 4)
        self.assertEqual(entry["fixed_count"], 2)
        self.assertEqual(entry["unfixed_count"], 2)
        self.assertEqual(entry["components"], ["lib", "lib2", "other"])
        self.assertEqual(entry["resources"], [r1, r2])

    def test_counts_always_sum_to_alert_total(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        self._alert(r1, advisory="CVE-a", component="lib")
        self._alert(r1, advisory="CVE-a", component="lib2")
        self._alert(r1, advisory="CVE-a", component="lib3")
        self._alert(r2, advisory="CVE-b", component="lib",
                    fixed_version="9.9.9")

        body = self._summary()
        for item in body:
            self.assertEqual(
                item["alert_count"],
                item["fixed_count"] + item["unfixed_count"],
            )
        entries = {item["advisory"]: item for item in body}
        self.assertEqual(entries["CVE-a"]["fixed_count"], 0)
        self.assertEqual(entries["CVE-a"]["unfixed_count"], 3)
        self.assertEqual(entries["CVE-b"]["fixed_count"], 1)
        self.assertEqual(entries["CVE-b"]["unfixed_count"], 0)

    def test_batch_registration_counted_per_item(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        self._batch(
            r1,
            [
                {"advisory": "CVE-1", "component": "zeta", "severity": "low",
                 "summary": "x", "fixed_version": "1"},
                {"advisory": "CVE-1", "component": "alpha", "severity": "low",
                 "summary": "x"},
                {"advisory": "CVE-2", "component": "alpha", "severity": "low",
                 "summary": "x"},
            ],
        )
        body = self._summary()
        self.assertEqual([item["advisory"] for item in body], ["CVE-1", "CVE-2"])
        self.assertEqual(body[0]["alert_count"], 2)
        self.assertEqual(body[0]["fixed_count"], 1)
        self.assertEqual(body[0]["unfixed_count"], 1)
        self.assertEqual(body[0]["components"], ["zeta", "alpha"])

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
        self._alert(resource_id, advisory="CVE-1", component="openssl")

        body = self._summary()
        self.assertEqual(body[0]["components"], ["openssl"])

    # --- Recomputation and read-only behavior ------------------------------

    def test_recomputes_after_single_registration(self) -> None:
        resource_id = self._create()
        self.assertEqual(call("GET", PATH)[2], b"[]\n")

        self._alert(resource_id, advisory="CVE-1", component="lib")
        body = self._summary()
        self.assertEqual(body[0]["advisory"], "CVE-1")
        self.assertEqual(body[0]["alert_count"], 1)
        self.assertEqual(body[0]["unfixed_count"], 1)
        self.assertEqual(body[0]["components"], ["lib"])

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
        body = self._summary()
        self.assertEqual(body[0]["fixed_count"], 0)
        self.assertEqual(body[0]["unfixed_count"], 1)

        # Adding a fixed version on update moves it back.
        status, _h, _b = call_json(
            "PUT",
            f"/resources/{r1}/vulnerabilities/{alert_id}",
            {
                "advisory": "CVE-1",
                "component": "lib",
                "severity": "low",
                "summary": "updated",
                "fixed_version": "2.0",
            },
        )
        self.assertEqual(status, "200 OK")
        body = self._summary()
        self.assertEqual([item["advisory"] for item in body], ["CVE-1"])
        self.assertEqual(body[0]["fixed_count"], 1)
        self.assertEqual(body[0]["unfixed_count"], 0)

    def test_recomputes_after_alert_delete(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        first = self._alert(
            r1, advisory="CVE-1", component="lib", fixed_version="1.0"
        )
        self._alert(r1, advisory="CVE-2", component="other")

        status, _h, _b = call_json(
            "DELETE", f"/resources/{r1}/vulnerabilities/{first}"
        )
        self.assertEqual(status, "200 OK")

        body = self._summary()
        self.assertEqual([item["advisory"] for item in body], ["CVE-2"])
        self.assertEqual(body[0]["alert_count"], 1)
        self.assertEqual(body[0]["fixed_count"], 0)
        self.assertEqual(body[0]["unfixed_count"], 1)

    def test_advisory_disappears_after_last_alert_gone(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        alert_id = self._alert(
            r1, advisory="CVE-1", component="lib", fixed_version="1.0"
        )
        status, _h, _b = call_json(
            "DELETE", f"/resources/{r1}/vulnerabilities/{alert_id}"
        )
        self.assertEqual(status, "200 OK")
        status, _h, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

    def test_components_list_resurrects_after_delete_and_readd(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        alert_id = self._alert(
            r1, advisory="CVE-1", component="lib", fixed_version="1.0"
        )
        status, _h, _b = call_json(
            "DELETE", f"/resources/{r1}/vulnerabilities/{alert_id}"
        )
        self.assertEqual(status, "200 OK")
        self._alert(r1, advisory="CVE-1", component="lib",
                    fixed_version="1.0")
        body = self._summary()
        self.assertEqual(body[0]["components"], ["lib"])
        self.assertEqual(body[0]["resources"], [r1])

    def test_recomputes_after_resource_deregistration(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        r3 = self._create(DIGEST_C, "r3")
        self._alert(r1, advisory="CVE-a", component="alpha",
                    fixed_version="1")
        self._alert(r2, advisory="CVE-s", component="shared")
        self._alert(r3, advisory="CVE-a", component="gamma",
                    fixed_version="3")

        status, _h, _b = call_json("DELETE", f"/resources/{r2}")
        self.assertEqual(status, "200 OK")
        body = self._summary()
        self.assertEqual([item["advisory"] for item in body], ["CVE-a"])
        self.assertEqual(body[0]["resources"], [r1, r3])
        self.assertEqual(body[0]["alert_count"], 2)

        status, _h, _b = call_json("DELETE", f"/resources/{r1}")
        self.assertEqual(status, "200 OK")
        body = self._summary()
        self.assertEqual(body[0]["resources"], [r3])

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
        self._alert(r2, advisory="CVE-1", component="lib",
                    fixed_version="1.0")

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
        self.assertEqual(coverage[0]["fixed_count"], 1)
        status, _h, progress = call_json("GET", "/fix-coverage-progress")
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(progress), 2)
        status, _h, severity = call_json("GET", "/severity-coverage")
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(severity), 1)
        status, _h, gaps = call_json("GET", "/advisory-fix-gaps")
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(gaps), 1)
        status, _h, components = call_json("GET", "/alert-components")
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(components), 1)

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
        for query in ("x=1", "x=", "bogus=1", "page=2", "advisory=CVE-1"):
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
        self._alert(resource_id, advisory="CVE-1", component="openssl")
        status, _h, body = call_json(
            "GET", PATH, query_string="x=1"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        # The view must still answer normally afterwards.
        after = self._summary()
        self.assertEqual(after[0]["components"], ["openssl"])

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
