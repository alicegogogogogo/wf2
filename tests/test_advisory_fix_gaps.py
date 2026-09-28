from __future__ import annotations

import io
import json
import unittest

from provenance_api.app import application, reset_state

PATH = "/advisory-fix-gaps"

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
        self,
    ) -> tuple[str, list[tuple[str, str]], list[dict[str, object]]]:
        status, headers, body = call_json("GET", PATH)
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
            fixed_version="3.0.8",
        )

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
        self.assertEqual(body[0]["advisory"], "CVE-1")
        self.assertEqual(body[0]["component"], "openssl")
        self.assertEqual(body[0]["alert_count"], 1)
        self.assertEqual(body[0]["fixed_count"], 1)
        self.assertEqual(body[0]["unfixed_count"], 0)
        self.assertEqual(body[0]["fixed_versions"], ["3.0.8"])
        self.assertEqual(body[0]["resources"], [resource_id])

    def test_advisory_and_component_echoed_verbatim(self) -> None:
        resource_id = self._create()
        self._alert(
            resource_id,
            advisory=" CVE-X ",
            component="OpenSSL ",
            fixed_version=" 3.0.8-RC ",
        )
        _s, _h, body = self._summary()
        self.assertEqual(len(body), 1)
        self.assertEqual(body[0]["advisory"], " CVE-X ")
        self.assertEqual(body[0]["component"], "OpenSSL ")
        self.assertEqual(body[0]["fixed_versions"], [" 3.0.8-RC "])
        self.assertEqual(body[0]["resources"], [resource_id])

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

    # --- Aggregation, ordering and counts ----------------------------------

    def test_one_entry_per_advisory_component_pair(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        # The same pair repeats across resources: one entry, raw counts.
        self._alert(r1, advisory="CVE-1", component="lib",
                    fixed_version="1.0")
        self._alert(r2, advisory="CVE-1", component="lib")
        # Same advisory, different component: its own entry.
        self._alert(r1, advisory="CVE-1", component="other")
        # Different advisory, same component: its own entry.
        self._alert(r2, advisory="CVE-2", component="lib",
                    fixed_version="2.0")

        _s, _h, body = self._summary()
        self.assertEqual(
            [(item["advisory"], item["component"]) for item in body],
            [("CVE-1", "lib"), ("CVE-1", "other"), ("CVE-2", "lib")],
        )
        first = body[0]
        self.assertEqual(first["alert_count"], 2)
        self.assertEqual(first["fixed_count"], 1)
        self.assertEqual(first["unfixed_count"], 1)
        self.assertEqual(first["fixed_versions"], ["1.0"])
        self.assertEqual(first["resources"], [r1, r2])

    def test_entries_follow_traversal_order(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")

        # Alerts are submitted in the opposite resource order: a pair on r2
        # is registered before a pair on r1. Traversal still follows
        # resource registration order, so the r1 pair comes out first.
        self._alert(r2, advisory="CVE-z", component="zeta")
        self._alert(r1, advisory="CVE-a", component="alpha")
        self._alert(r1, advisory="CVE-m", component="mid")

        _s, _h, body = self._summary()
        self.assertEqual(
            [(item["advisory"], item["component"]) for item in body],
            [("CVE-a", "alpha"), ("CVE-m", "mid"), ("CVE-z", "zeta")],
        )

    def test_pair_takes_position_of_earliest_alert(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        r3 = self._create(DIGEST_C, "r3")
        self._alert(r1, advisory="CVE-a", component="alpha")
        self._alert(r2, advisory="CVE-b", component="beta")
        # A later alert for the first pair never moves its entry; a new
        # alert on r3 lands at the end.
        self._alert(r3, advisory="CVE-a", component="alpha",
                    fixed_version="9")
        self._alert(r3, advisory="CVE-c", component="gamma")

        _s, _h, body = self._summary()
        self.assertEqual(
            [(item["advisory"], item["component"]) for item in body],
            [("CVE-a", "alpha"), ("CVE-b", "beta"), ("CVE-c", "gamma")],
        )
        self.assertEqual(body[0]["alert_count"], 2)
        self.assertEqual(body[0]["fixed_count"], 1)
        self.assertEqual(body[0]["unfixed_count"], 1)
        self.assertEqual(body[0]["fixed_versions"], ["9"])
        self.assertEqual(body[0]["resources"], [r1, r3])

    def test_fixed_versions_deduplicated_in_first_seen_order(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        r3 = self._create(DIGEST_C, "r3")
        # A resource may only register a given pair once, so repeated
        # versions arrive across resources: "1.0" on r1, "2.0" on r2,
        # "1.0" again on r3 plus an unfixed alert there.
        self._alert(r1, advisory="CVE-1", component="lib",
                    fixed_version="1.0")
        self._alert(r2, advisory="CVE-1", component="lib",
                    fixed_version="2.0")
        self._alert(r3, advisory="CVE-1", component="lib",
                    fixed_version="1.0")
        self._alert(r3, advisory="CVE-2", component="lib")

        _s, _h, body = self._summary()
        first = next(
            item for item in body
            if (item["advisory"], item["component"]) == ("CVE-1", "lib")
        )
        self.assertEqual(first["fixed_versions"], ["1.0", "2.0"])
        self.assertEqual(first["alert_count"], 3)
        self.assertEqual(first["fixed_count"], 3)
        self.assertEqual(first["unfixed_count"], 0)
        self.assertEqual(first["resources"], [r1, r2, r3])

    def test_counts_are_raw_without_dedup_or_merge(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        # The identical advisory/component/version triple repeats across
        # resources; each alert is counted separately.
        self._alert(r1, advisory="CVE-1", component="lib",
                    fixed_version="1.0")
        self._alert(r2, advisory="CVE-1", component="lib",
                    fixed_version="1.0")

        _s, _h, body = self._summary()
        self.assertEqual(body[0]["alert_count"], 2)
        self.assertEqual(body[0]["fixed_count"], 2)
        self.assertEqual(body[0]["unfixed_count"], 0)
        self.assertEqual(body[0]["fixed_versions"], ["1.0"])
        self.assertEqual(body[0]["resources"], [r1, r2])

    def test_versions_listed_verbatim_without_comparison_or_sorting(self) -> None:
        # A resource may only register a given pair once; four resources
        # each contribute one fixed alert, and first-seen order follows the
        # resource traversal. Versions that a dotted-decimal comparison
        # could not rank, and that would reorder under case folding or
        # trimming, must be preserved verbatim and unsorted.
        versions = ["v2", " 10 ", "V2", "1.2.3-beta"]
        for index, version in enumerate(versions):
            resource_id = self._create("0123456789abcdef"[index] * 64,
                                       f"r{index}")
            self._alert(resource_id, advisory="CVE-1", component="lib",
                        fixed_version=version)

        _s, _h, body = self._summary()
        self.assertEqual(
            body[0]["fixed_versions"],
            ["v2", " 10 ", "V2", "1.2.3-beta"],
        )
        self.assertEqual(body[0]["alert_count"], 4)
        self.assertEqual(body[0]["fixed_count"], 4)
        self.assertEqual(body[0]["unfixed_count"], 0)

    def test_advisory_and_component_pairing_is_case_sensitive(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        self._alert(r1, advisory="CVE-1", component="lib",
                    fixed_version="1.0")
        self._alert(r2, advisory="cve-1", component="LIB")

        _s, _h, body = self._summary()
        self.assertEqual(
            [(item["advisory"], item["component"]) for item in body],
            [("CVE-1", "lib"), ("cve-1", "LIB")],
        )

    def test_resources_deduplicated_in_registration_order(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        r3 = self._create(DIGEST_C, "r3")
        # r3 contributes the pair first in submission time, but traversal
        # follows resource registration order; every resource appears once
        # even though the pair spans all three.
        self._alert(r3, advisory="CVE-1", component="lib")
        self._alert(r1, advisory="CVE-1", component="lib",
                    fixed_version="2")
        self._alert(r2, advisory="CVE-1", component="lib",
                    fixed_version="1")

        _s, _h, body = self._summary()
        self.assertEqual(len(body), 1)
        self.assertEqual(body[0]["resources"], [r1, r2, r3])
        self.assertEqual(body[0]["alert_count"], 3)

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
        # The pair needs no SBOM presence to be aggregated.
        self._alert(resource_id, advisory="CVE-1", component="openssl")

        _s, _h, body = self._summary()
        self.assertEqual(
            [(item["advisory"], item["component"]) for item in body],
            [("CVE-1", "openssl")],
        )

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
        self.assertEqual(
            [(item["advisory"], item["component"]) for item in body],
            [("CVE-2", "zeta"), ("CVE-1", "alpha")],
        )

    # --- Recomputation and read-only behavior -------------------------------

    def test_recomputes_after_single_registration(self) -> None:
        resource_id = self._create()
        _s, _h, body = self._summary()
        self.assertEqual(body, [])

        self._alert(resource_id, advisory="CVE-1", component="lib")
        _s, _h, body = self._summary()
        self.assertEqual(
            [(item["advisory"], item["component"]) for item in body],
            [("CVE-1", "lib")],
        )
        self.assertEqual(body[0]["unfixed_count"], 1)

    def test_recomputes_after_batch_registration(self) -> None:
        resource_id = self._create()
        self._batch(
            resource_id,
            [
                {"advisory": "CVE-1", "component": "lib", "severity": "low",
                 "summary": "x"},
                {"advisory": "CVE-1", "component": "lib2", "severity": "low",
                 "summary": "x", "fixed_version": "1.0"},
            ],
        )
        _s, _h, body = self._summary()
        self.assertEqual(
            [(item["advisory"], item["component"]) for item in body],
            [("CVE-1", "lib"), ("CVE-1", "lib2")],
        )
        self.assertEqual(body[1]["alert_count"], 1)
        self.assertEqual(body[1]["fixed_count"], 1)
        self.assertEqual(body[1]["unfixed_count"], 0)
        self.assertEqual(body[1]["fixed_versions"], ["1.0"])

    def test_recomputes_after_in_place_update(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        alert_id = self._alert(
            r1, advisory="CVE-1", component="lib", severity="low",
            fixed_version="1.0",
        )
        self._alert(r2, advisory="CVE-1", component="lib", severity="medium")

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
        self.assertEqual(body[0]["fixed_versions"], [])
        self.assertEqual(body[0]["alert_count"], 2)
        self.assertEqual(body[0]["fixed_count"], 0)
        self.assertEqual(body[0]["unfixed_count"], 2)
        self.assertEqual(body[0]["resources"], [r1, r2])

    def test_recomputes_after_alert_delete(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        r3 = self._create(DIGEST_C, "r3")
        first = self._alert(
            r1, advisory="CVE-1", component="lib", fixed_version="1.0"
        )
        self._alert(r2, advisory="CVE-1", component="lib")
        other = self._alert(r3, advisory="CVE-2", component="other")

        status, _h, _b = call_json(
            "DELETE", f"/resources/{r1}/vulnerabilities/{first}"
        )
        self.assertEqual(status, "200 OK")

        _s, _h, body = self._summary()
        entries = {
            (item["advisory"], item["component"]): item for item in body
        }
        self.assertEqual(set(entries), {("CVE-1", "lib"), ("CVE-2", "other")})
        # The only remaining CVE-1/lib alert is unfixed.
        self.assertEqual(entries[("CVE-1", "lib")]["fixed_versions"], [])
        self.assertEqual(entries[("CVE-1", "lib")]["fixed_count"], 0)
        self.assertEqual(entries[("CVE-1", "lib")]["unfixed_count"], 1)
        self.assertEqual(entries[("CVE-1", "lib")]["resources"], [r2])

        # Deleting the last alert for a pair drops the whole entry.
        status, _h, _b = call_json(
            "DELETE", f"/resources/{r3}/vulnerabilities/{other}"
        )
        self.assertEqual(status, "200 OK")
        _s, _h, body = self._summary()
        self.assertEqual(
            [(item["advisory"], item["component"]) for item in body],
            [("CVE-1", "lib")],
        )

    def test_recomputes_after_resource_deregistration(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        r3 = self._create(DIGEST_C, "r3")
        self._alert(r1, advisory="CVE-a", component="alpha",
                    fixed_version="1")
        self._alert(r2, advisory="CVE-s", component="shared",
                    fixed_version="2")
        self._alert(r3, advisory="CVE-s", component="shared")
        self._alert(r3, advisory="CVE-c", component="gamma",
                    fixed_version="3")

        status, _h, _b = call_json("DELETE", f"/resources/{r2}")
        self.assertEqual(status, "200 OK")

        _s, _h, body = self._summary()
        self.assertEqual(
            [(item["advisory"], item["component"]) for item in body],
            [
                ("CVE-a", "alpha"),
                ("CVE-s", "shared"),
                ("CVE-c", "gamma"),
            ],
        )
        shared = body[1]
        self.assertEqual(shared["fixed_versions"], [])
        self.assertEqual(shared["alert_count"], 1)
        self.assertEqual(shared["fixed_count"], 0)
        self.assertEqual(shared["unfixed_count"], 1)
        self.assertEqual(shared["resources"], [r3])

        status, _h, _b = call_json("DELETE", f"/resources/{r1}")
        self.assertEqual(status, "200 OK")
        _s, _h, body = self._summary()
        self.assertEqual(
            [(item["advisory"], item["component"]) for item in body],
            [("CVE-s", "shared"), ("CVE-c", "gamma")],
        )

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
        resource_id = self._create()
        self._alert(resource_id, advisory="CVE-1", component="openssl")
        for query in ("x=1", "advisory=CVE-1", "component=openssl", "x="):
            with self.subTest(query=query):
                status, _h, body = call_json("GET", PATH, query_string=query)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_repeated_query_parameter_rejected(self) -> None:
        status, _h, body = call_json(
            "GET", PATH, query_string="x=1&x=2"
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
        status, _h, body = call_json("GET", PATH, query_string="x=1")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        # The view must still answer normally afterwards.
        _s, _h, after = self._summary()
        self.assertEqual(
            [(item["advisory"], item["component"]) for item in after],
            [("CVE-1", "openssl")],
        )

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
