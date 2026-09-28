from __future__ import annotations

import io
import json
import unittest

from provenance_api.app import application, reset_state

PATH = "/advisory-fix-gaps"

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


class AdvisoryFixGapsTests(unittest.TestCase):
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
            '"advisory"',
            '"component"',
            '"alert_count"',
            '"fixed_count"',
            '"unfixed_count"',
            '"fixed_versions"',
            '"resources"',
        ]
        positions = [text.index(key) for key in keys]
        self.assertEqual(positions, sorted(positions))

        _s, _h, body = self._summary()
        self.assertEqual(
            list(body[0]),
            [
                "advisory",
                "component",
                "alert_count",
                "fixed_count",
                "unfixed_count",
                "fixed_versions",
                "resources",
            ],
        )
        self.assertEqual(body[0]["advisory"], "CVE-2026-0001")
        self.assertEqual(body[0]["component"], "openssl")
        self.assertEqual(body[0]["alert_count"], 1)
        self.assertEqual(body[0]["fixed_count"], 1)
        self.assertEqual(body[0]["unfixed_count"], 0)
        self.assertEqual(body[0]["fixed_versions"], ["3.0.8"])
        self.assertEqual(body[0]["resources"], [resource_id])

    def test_response_is_utf8_and_newline_terminated(self) -> None:
        resource_id = self._create()
        self._alert(resource_id, advisory="公告-1", component="组件")
        status, _headers, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertTrue(raw.endswith(b"\n"))
        raw.decode("utf-8")

    # --- Grouping, ordering, dedup and counts ------------------------------

    def test_one_entry_per_advisory_component_pair(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        r3 = self._create(DIGEST_C, "r3")
        # The same (advisory, component) pair is spread across all three
        # resources and must collapse into a single entry.
        self._alert(r1, fixed_version="1.0")
        self._alert(r2)
        self._alert(r3, fixed_version="2.0")
        # A distinct component for the same advisory stays a separate entry.
        self._alert(r1, component="zlib", fixed_version="3.0")
        # A distinct advisory for the same component likewise.
        self._alert(r2, advisory="CVE-2026-0002", fixed_version="4.0")

        _s, _h, body = self._summary()
        self.assertEqual(
            [(item["advisory"], item["component"]) for item in body],
            [
                ("CVE-2026-0001", "openssl"),
                ("CVE-2026-0001", "zlib"),
                ("CVE-2026-0002", "openssl"),
            ],
        )
        first = body[0]
        self.assertEqual(first["alert_count"], 3)
        self.assertEqual(first["fixed_count"], 2)
        self.assertEqual(first["unfixed_count"], 1)
        self.assertEqual(first["fixed_versions"], ["1.0", "2.0"])
        self.assertEqual(first["resources"], [r1, r2, r3])

    def test_advisory_and_component_echoed_verbatim(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        # Case-only differences identify distinct pairs and must not fold.
        self._alert(r1, advisory="CVE-1", component="lib-a")
        self._alert(r2, advisory="cve-1", component="LIB-A")

        _s, _h, body = self._summary()
        self.assertEqual(
            [(item["advisory"], item["component"]) for item in body],
            [("CVE-1", "lib-a"), ("cve-1", "LIB-A")],
        )
        self.assertEqual(body[0]["resources"], [r1])
        self.assertEqual(body[1]["resources"], [r2])

    def test_entries_follow_first_pair_occurrence_under_registration_order(
        self,
    ) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        r3 = self._create(DIGEST_C, "r3")

        # Alerts are submitted starting from the last-registered resource,
        # but the traversal is fixed to resource registration order, so the
        # first occurrence of each pair follows r1, r2, r3 -- never the
        # submission wall-clock order.
        self._alert(r3, advisory="CVE-z", component="zeta")
        self._alert(r2, advisory="CVE-m", component="mid")
        self._alert(r1, advisory="CVE-a", component="alpha")

        _s, _h, body = self._summary()
        self.assertEqual(
            [(item["advisory"], item["component"]) for item in body],
            [
                ("CVE-a", "alpha"),
                ("CVE-m", "mid"),
                ("CVE-z", "zeta"),
            ],
        )

    def test_resources_deduplicated_in_registration_order(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        r3 = self._create(DIGEST_C, "r3")
        # r3 alerts first; the pair's resource list must still read r1..r3.
        self._alert(r3, fixed_version="1")
        self._alert(r1, fixed_version="2")
        self._alert(r2)

        _s, _h, body = self._summary()
        self.assertEqual(len(body), 1)
        self.assertEqual(body[0]["resources"], [r1, r2, r3])

    def test_fixed_versions_deduplicated_in_first_seen_order(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        r3 = self._create(DIGEST_C, "r3")
        # First-seen order under resource-registration traversal: r1's
        # "9" precedes r2's "10" -- values are never sorted or dotted, and
        # r3's repeat of "9" is dropped.
        self._alert(r3, fixed_version="9")
        self._alert(r2, fixed_version="10")
        self._alert(r1, fixed_version="9")

        _s, _h, body = self._summary()
        self.assertEqual(len(body), 1)
        self.assertEqual(body[0]["fixed_versions"], ["9", "10"])
        self.assertEqual(body[0]["fixed_count"], 3)
        self.assertEqual(body[0]["unfixed_count"], 0)

    def test_fixed_versions_keep_verbatim_values(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        self._alert(r1, fixed_version="1.0-rc.1+build.5")
        _s, _h, body = self._summary()
        self.assertEqual(
            body[0]["fixed_versions"], ["1.0-rc.1+build.5"]
        )

    def test_counts_are_raw_without_dedup_or_merge(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        r3 = self._create(DIGEST_C, "r3")
        self._alert(r1, component="lib", fixed_version="1.0")
        self._alert(r2, component="lib", fixed_version="2.0")
        self._alert(r3, component="lib")
        # Different pairs each get their own raw tallies.
        self._alert(r1, advisory="CVE-2", component="other")

        _s, _h, body = self._summary()
        pairs = {(item["advisory"], item["component"]): item for item in body}
        first = pairs[("CVE-2026-0001", "lib")]
        self.assertEqual(first["alert_count"], 3)
        self.assertEqual(first["fixed_count"], 2)
        self.assertEqual(first["unfixed_count"], 1)
        second = pairs[("CVE-2", "other")]
        self.assertEqual(second["alert_count"], 1)
        self.assertEqual(second["fixed_count"], 0)
        self.assertEqual(second["unfixed_count"], 1)

    def test_counts_always_sum_to_alert_total(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        # Two fixed alerts for one pair and two unfixed alerts for another;
        # every entry's tallies must satisfy fixed + unfixed == total.
        self._alert(r1, advisory="CVE-f", component="fixed",
                    fixed_version="1.0")
        self._alert(r2, advisory="CVE-f", component="fixed",
                    fixed_version="2.0")
        self._alert(r1, advisory="CVE-u", component="unfixed")
        self._alert(r2, advisory="CVE-u", component="unfixed")

        _s, _h, body = self._summary()
        self.assertEqual(len(body), 2)
        for item in body:
            self.assertEqual(
                item["alert_count"],
                item["fixed_count"] + item["unfixed_count"],
            )
        pairs = {(item["advisory"], item["component"]): item for item in body}
        self.assertEqual(pairs[("CVE-f", "fixed")]["fixed_count"], 2)
        self.assertEqual(pairs[("CVE-u", "unfixed")]["unfixed_count"], 2)

    def test_batch_registration_uses_array_order(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        self._batch(
            r1,
            [
                {"advisory": "CVE-2", "component": "zeta", "severity": "low",
                 "summary": "x", "fixed_version": "1"},
                {"advisory": "CVE-1", "component": "alpha", "severity": "low",
                 "summary": "x"},
                {"advisory": "CVE-1", "component": "zeta", "severity": "low",
                 "summary": "x"},
            ],
        )
        _s, _h, body = self._summary()
        self.assertEqual(
            [(item["advisory"], item["component"]) for item in body],
            [("CVE-2", "zeta"), ("CVE-1", "alpha"), ("CVE-1", "zeta")],
        )
        self.assertEqual(
            body[0]["fixed_versions"], ["1"]
        )
        self.assertEqual(body[2]["fixed_versions"], [])
        self.assertEqual(body[2]["unfixed_count"], 1)

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
        self.assertEqual(
            [(item["advisory"], item["component"]) for item in body],
            [("CVE-1", "openssl")],
        )

    # --- Recomputation and read-only behavior ------------------------------

    def test_recomputes_after_single_registration(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        self.assertEqual(call("GET", PATH)[2], b"[]\n")

        self._alert(r1, advisory="CVE-1", component="lib", severity="low")
        self._alert(r2, advisory="CVE-1", component="lib",
                    fixed_version="1.0")
        _s, _h, body = self._summary()
        self.assertEqual(len(body), 1)
        self.assertEqual(body[0]["alert_count"], 2)
        self.assertEqual(body[0]["unfixed_count"], 1)
        self.assertEqual(body[0]["fixed_versions"], ["1.0"])
        self.assertEqual(body[0]["resources"], [r1, r2])

    def test_recomputes_after_in_place_update(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        alert_id = self._alert(
            r1, advisory="CVE-1", component="lib", severity="low",
            fixed_version="1.0",
        )
        self._alert(r2, advisory="CVE-1", component="lib", severity="low")

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
        self.assertEqual(body[0]["fixed_count"], 0)
        self.assertEqual(body[0]["unfixed_count"], 2)
        self.assertEqual(body[0]["fixed_versions"], [])

        # A new fixed version is collected on recompute.
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
        _s, _h, body = self._summary()
        self.assertEqual(body[0]["fixed_count"], 1)
        self.assertEqual(body[0]["unfixed_count"], 1)
        self.assertEqual(body[0]["fixed_versions"], ["2.0"])
        # The update keeps the submission position, so ordering is unchanged.
        self.assertEqual(body[0]["resources"], [r1, r2])

    def test_pair_disappears_after_last_alert_delete(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        first = self._alert(
            r1, advisory="CVE-1", component="lib", severity="high",
            fixed_version="1.0",
        )
        second = self._alert(
            r2, advisory="CVE-2", component="other", severity="low"
        )

        status, _h, _b = call_json(
            "DELETE", f"/resources/{r1}/vulnerabilities/{first}"
        )
        self.assertEqual(status, "200 OK")
        _s, _h, body = self._summary()
        self.assertEqual(
            [(item["advisory"], item["component"]) for item in body],
            [("CVE-2", "other")],
        )

        status, _h, _b = call_json(
            "DELETE", f"/resources/{r2}/vulnerabilities/{second}"
        )
        self.assertEqual(status, "200 OK")
        status, _h, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

    def test_pair_can_be_registered_again_after_delete(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        alert_id = self._alert(
            r1, advisory="CVE-1", component="lib", severity="high"
        )
        status, _h, _b = call_json(
            "DELETE", f"/resources/{r1}/vulnerabilities/{alert_id}"
        )
        self.assertEqual(status, "200 OK")
        self._alert(r1, advisory="CVE-1", component="lib",
                    severity="high", fixed_version="1.0")
        _s, _h, body = self._summary()
        self.assertEqual(len(body), 1)
        self.assertEqual(body[0]["fixed_count"], 1)
        self.assertEqual(body[0]["fixed_versions"], ["1.0"])

    def test_recomputes_after_resource_deregistration(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        r3 = self._create(DIGEST_C, "r3")
        self._alert(r1, advisory="CVE-a", component="alpha",
                    fixed_version="1")
        self._alert(r2, advisory="CVE-s", component="shared")
        self._alert(r3, advisory="CVE-s", component="shared",
                    fixed_version="3")

        status, _h, _b = call_json("DELETE", f"/resources/{r2}")
        self.assertEqual(status, "200 OK")
        _s, _h, body = self._summary()
        # First-seen order is unchanged (CVE-a still precedes CVE-s); the
        # shared pair survives through r3 with its resource list trimmed.
        self.assertEqual(
            [(item["advisory"], item["component"]) for item in body],
            [("CVE-a", "alpha"), ("CVE-s", "shared")],
        )
        shared = body[1]
        self.assertEqual(shared["alert_count"], 1)
        self.assertEqual(shared["fixed_count"], 1)
        self.assertEqual(shared["resources"], [r3])

        status, _h, _b = call_json("DELETE", f"/resources/{r1}")
        self.assertEqual(status, "200 OK")
        _s, _h, body = self._summary()
        self.assertEqual(
            [(item["advisory"], item["component"]) for item in body],
            [("CVE-s", "shared")],
        )

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

        status, _h, advisories = call_json("GET", "/advisories")
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(advisories), 1)
        self.assertEqual(advisories[0]["advisory_count"], 2)

        status, _h, detail = call_json("GET", "/advisories/CVE-1")
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(detail["alerts"]), 2)

        status, _h, fixes = call_json("GET", "/advisories/CVE-1/fixes")
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(fixes["fixes"]), 1)
        self.assertEqual(fixes["fixes"][0]["advisory_count"], 2)

        status, _h, coverage = call_json("GET", "/fix-coverage")
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(coverage), 1)
        self.assertEqual(coverage[0]["fixed_count"], 1)

        status, _h, progress = call_json("GET", "/fix-coverage-progress")
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(progress), 2)

        status, _h, levels = call_json("GET", "/severity-coverage")
        self.assertEqual(status, "200 OK")
        self.assertEqual(levels[0]["alert_count"], 2)

        status, _h, alerts = call_json(
            "GET", f"/resources/{r1}/vulnerabilities"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(alerts), 1)

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
                      "name=openssl", "advisory=CVE-1", "component=lib"):
            with self.subTest(query=query):
                status, _h, body = call_json(
                    "GET", PATH, query_string=query
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_repeated_query_parameter_rejected(self) -> None:
        for query in ("x=1&x=2", "a=&a=1", "x=1&y=2"):
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
        self.assertEqual(after[0]["advisory"], "CVE-1")
        self.assertEqual(after[0]["component"], "openssl")

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
