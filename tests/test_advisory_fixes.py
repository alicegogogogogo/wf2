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


class AdvisoryFixesTests(unittest.TestCase):
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
        severity: str,
        summary: str = "a bug",
        fixed_version: str | None = None,
    ) -> str:
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
        return str(body["id"])

    def _fixes(
        self, advisory: str, *, query_string: str | None = None
    ) -> tuple[str, list[tuple[str, str]], object]:
        return call_json(
            "GET",
            f"/advisories/{advisory}/fixes",
            query_string=query_string,
        )

    # --- Shape -------------------------------------------------------------

    def test_unknown_advisory_returns_empty_success(self) -> None:
        status, headers, body = self._fixes("NOPE-1")
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, {"advisory": "NOPE-1", "fixes": []})
        self.assertEqual(
            dict(headers)["Content-Type"], "application/json; charset=utf-8"
        )

    def test_response_is_compact_utf8_single_newline(self) -> None:
        self._alert(
            "first", advisory="A-1", component="lib", severity="high"
        )
        status, _headers, raw = call("GET", "/advisories/A-1/fixes")
        self.assertEqual(status, "200 OK")
        self.assertTrue(raw.endswith(b"\n"))
        self.assertEqual(raw.count(b"\n"), 1)
        self.assertNotIn(b" ", raw[:-1])

    def test_top_level_key_order_is_fixed(self) -> None:
        self._alert(
            "first", advisory="A-1", component="lib", severity="high"
        )
        text = call("GET", "/advisories/A-1/fixes")[2].decode("utf-8").rstrip("\n")
        positions = [text.index('"advisory"'), text.index('"fixes"')]
        self.assertEqual(positions, sorted(positions))

    def test_component_entry_key_order_is_fixed(self) -> None:
        self._alert(
            "first",
            advisory="A-1",
            component="openssl",
            severity="high",
            fixed_version="3.0.9",
        )
        text = (
            call("GET", "/advisories/A-1/fixes")[2]
            .decode("utf-8")
            .rstrip("\n")
        )
        entry_text = text[text.index('"fixes":[{') + len('"fixes":') :]
        keys = [
            '"name"',
            '"affected_resources"',
            '"advisory_count"',
            '"recommended_version"',
        ]
        positions = [entry_text.index(key) for key in keys]
        self.assertEqual(positions, sorted(positions))

    def test_advisory_id_is_echoed_verbatim(self) -> None:
        self._alert(
            "first", advisory="CVE-2026-0001 ", component="lib", severity="low"
        )
        _s, _h, body = self._fixes("CVE-2026-0001 ")
        self.assertEqual(body["advisory"], "CVE-2026-0001 ")
        self.assertEqual(len(body["fixes"]), 1)

    def test_advisory_match_is_case_sensitive(self) -> None:
        self._alert(
            "first", advisory="adv-1", component="lib", severity="low"
        )
        _s, _h, body = self._fixes("ADV-1")
        self.assertEqual(body["fixes"], [])

    def test_components_without_hits_are_not_output(self) -> None:
        # Only an alert on "openssl" exists; no SBOM and no other data can
        # force a zero-count entry, and a different advisory does not bleed
        # its components in.
        self._alert(
            "first", advisory="ADV-A", component="openssl", severity="low"
        )
        self._alert(
            "first", advisory="ADV-B", component="zlib", severity="low"
        )
        _s, _h, body = self._fixes("ADV-A")
        self.assertEqual([fix["name"] for fix in body["fixes"]], ["openssl"])

    # --- Ordering, grouping and counting -----------------------------------

    def test_components_expand_in_resource_registration_order(self) -> None:
        # "third" submits first, but "first" was registered first.
        self._alert(
            "third", advisory="ADV-A", component="z", severity="high"
        )
        self._alert(
            "first", advisory="ADV-A", component="a", severity="low"
        )
        self._alert(
            "second", advisory="ADV-A", component="m", severity="medium"
        )

        _s, _h, body = self._fixes("ADV-A")
        self.assertEqual(
            [fix["name"] for fix in body["fixes"]], ["a", "m", "z"]
        )

    def test_components_aggregate_in_submission_order_within_resource(self) -> None:
        self._alert(
            "first", advisory="ADV-A", component="z", severity="low"
        )
        self._alert(
            "first", advisory="ADV-A", component="a", severity="low"
        )
        self._alert(
            "second", advisory="ADV-A", component="m", severity="low"
        )

        _s, _h, body = self._fixes("ADV-A")
        self.assertEqual(
            [fix["name"] for fix in body["fixes"]], ["z", "a", "m"]
        )

    def test_same_component_appears_once_with_resources_in_reg_order(self) -> None:
        # "third" hits first in submission order, yet its resource sorts last.
        self._alert(
            "third",
            advisory="ADV-A",
            component="openssl",
            severity="high",
            fixed_version="3.0.9",
        )
        self._alert(
            "first",
            advisory="ADV-A",
            component="openssl",
            severity="low",
            fixed_version="3.0.10",
        )

        _s, _h, body = self._fixes("ADV-A")
        self.assertEqual(len(body["fixes"]), 1)
        fix = body["fixes"][0]
        self.assertEqual(fix["name"], "openssl")
        self.assertEqual(
            fix["affected_resources"],
            [self.ids["first"], self.ids["third"]],
        )
        # One raw alert per contributing resource: counted, not deduped.
        self.assertEqual(fix["advisory_count"], 2)
        self.assertEqual(fix["recommended_version"], "3.0.10")

    def test_affected_resources_only_list_contributing_resources(self) -> None:
        self._alert(
            "first", advisory="ADV-A", component="openssl", severity="high"
        )
        self._alert(
            "second", advisory="ADV-B", component="openssl", severity="high"
        )

        _s, _h, body = self._fixes("ADV-A")
        self.assertEqual(
            body["fixes"][0]["affected_resources"], [self.ids["first"]]
        )

    def test_counts_add_up_to_summary_and_detail_alert_counts(self) -> None:
        self._alert(
            "second", advisory="ADV-A", component="c1", severity="medium"
        )
        self._alert(
            "third", advisory="ADV-A", component="c1", severity="high"
        )
        self._alert(
            "first", advisory="ADV-A", component="c2", severity="critical"
        )
        self._alert(
            "first", advisory="ADV-A", component="c1", severity="low"
        )
        self._alert(
            "first", advisory="ADV-B", component="c9", severity="low"
        )

        for query_string in (None, "severity=LOW", "severity=high",
                             "severity=critical"):
            with self.subTest(query_string=query_string):
                _s, _h, fixes = self._fixes(
                    "ADV-A", query_string=query_string
                )
                _s, _h, detail = call_json(
                    "GET",
                    "/advisories/ADV-A",
                    query_string=query_string,
                )
                _s, _h, summary = call_json(
                    "GET", "/advisories", query_string=query_string
                )
                row = next(
                    r for r in summary if r["advisory"] == "ADV-A"
                )
                self.assertEqual(
                    sum(fix["advisory_count"] for fix in fixes["fixes"]),
                    len(detail["alerts"]),
                )
                self.assertEqual(
                    sum(fix["advisory_count"] for fix in fixes["fixes"]),
                    row["advisory_count"],
                )
                # A resource can contribute hits to several components, so
                # it appears once per component entry; the advisory-wide
                # resource list is that union with duplicates removed.
                collected = sorted(
                    {
                        resource
                        for fix in fixes["fixes"]
                        for resource in fix["affected_resources"]
                    }
                )
                self.assertEqual(
                    collected, sorted(detail["affected_resources"])
                )
                self.assertEqual(
                    collected, sorted(row["affected_resources"])
                )

    # --- Recommended version -----------------------------------------------

    def test_recommended_version_is_greatest_numeric_candidate(self) -> None:
        self._alert(
            "first",
            advisory="ADV-A",
            component="openssl",
            severity="high",
            fixed_version="3.0.9",
        )
        self._alert(
            "second",
            advisory="ADV-A",
            component="openssl",
            severity="high",
            fixed_version="3.0.10",
        )
        _s, _h, body = self._fixes("ADV-A")
        self.assertEqual(
            body["fixes"][0]["recommended_version"], "3.0.10"
        )

    def test_non_numeric_and_empty_candidates_are_ignored(self) -> None:
        self._alert(
            "first",
            advisory="ADV-A",
            component="openssl",
            severity="low",
            fixed_version="3.0.10-rc",
        )
        self._alert(
            "second",
            advisory="ADV-A",
            component="openssl",
            severity="low",
            fixed_version="v2",
        )
        _s, _h, with_numeric = self._fixes("ADV-A")
        self.assertIsNone(
            with_numeric["fixes"][0]["recommended_version"]
        )

        self._alert(
            "third",
            advisory="ADV-A",
            component="openssl",
            severity="low",
            fixed_version="1.2",
        )
        _s, _h, body = self._fixes("ADV-A")
        self.assertEqual(body["fixes"][0]["recommended_version"], "1.2")

    def test_all_missing_fixed_versions_yield_null(self) -> None:
        self._alert(
            "first", advisory="ADV-A", component="openssl", severity="low"
        )
        self._alert(
            "second", advisory="ADV-A", component="openssl", severity="low"
        )
        _s, _h, body = self._fixes("ADV-A")
        self.assertIsNone(body["fixes"][0]["recommended_version"])

    # --- Severity filter ----------------------------------------------------

    def test_severity_filter_shrinks_components_and_resources(self) -> None:
        self._alert(
            "first",
            advisory="ADV-A",
            component="openssl",
            severity="high",
            fixed_version="3.0.9",
        )
        self._alert(
            "second",
            advisory="ADV-A",
            component="openssl",
            severity="low",
            fixed_version="9.9.9",
        )
        self._alert(
            "third",
            advisory="ADV-A",
            component="zlib",
            severity="low",
        )

        _s, _h, body = self._fixes("ADV-A", query_string="severity=HIGH")
        self.assertEqual([fix["name"] for fix in body["fixes"]], ["openssl"])
        fix = body["fixes"][0]
        self.assertEqual(fix["affected_resources"], [self.ids["first"]])
        self.assertEqual(fix["advisory_count"], 1)
        # The low-severity 9.9.9 candidate must not win under the filter.
        self.assertEqual(fix["recommended_version"], "3.0.9")

    def test_severity_filter_no_match_is_success_empty_list(self) -> None:
        self._alert(
            "first", advisory="ADV-A", component="openssl", severity="low"
        )
        status, _h, body = self._fixes(
            "ADV-A", query_string="severity=critical"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["fixes"], [])
        self.assertEqual(body["advisory"], "ADV-A")

    # --- Read-only / recompute ----------------------------------------------

    def test_view_reflects_updates_and_deletes_immediately(self) -> None:
        alert_id = self._alert(
            "first",
            advisory="ADV-A",
            component="openssl",
            severity="low",
        )
        _s, _h, body = self._fixes("ADV-A")
        self.assertEqual(len(body["fixes"]), 1)
        self.assertIsNone(body["fixes"][0]["recommended_version"])

        status, _h, _b = call_json(
            "PUT",
            f"/resources/{self.ids['first']}/vulnerabilities/{alert_id}",
            {
                "advisory": "ADV-A",
                "component": "openssl",
                "severity": "critical",
                "summary": "now worse",
                "fixed_version": "4.0.0",
            },
        )
        self.assertEqual(status, "200 OK")
        _s, _h, body = self._fixes("ADV-A")
        self.assertEqual(body["fixes"][0]["advisory_count"], 1)
        self.assertEqual(body["fixes"][0]["recommended_version"], "4.0.0")

        status, _h, _b = call_json(
            "DELETE",
            f"/resources/{self.ids['first']}/vulnerabilities/{alert_id}",
        )
        self.assertEqual(status, "200 OK")
        _s, _h, body = self._fixes("ADV-A")
        self.assertEqual(body["fixes"], [])

    def test_view_does_not_modify_any_state(self) -> None:
        self._alert(
            "first", advisory="ADV-A", component="openssl", severity="high"
        )
        for _ in range(2):
            status, _h, body = self._fixes("ADV-A")
            self.assertEqual(status, "200 OK")
            self.assertEqual(len(body["fixes"]), 1)
        _s, _h, alerts = call_json(
            "GET", f"/resources/{self.ids['first']}/vulnerabilities"
        )
        self.assertEqual(len(alerts["vulnerabilities"]), 1)
        _s, _h, resources = call_json("GET", "/resources")
        self.assertEqual(len(resources["resources"]), 3)

    # --- Errors --------------------------------------------------------------

    def test_non_get_methods_return_405_with_allow_get_only(self) -> None:
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, headers, body = call_json(
                    method, "/advisories/ADV-A/fixes"
                )
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")
                self.assertEqual(dict(headers)["Allow"], "GET")

    def test_empty_advisory_id_returns_400(self) -> None:
        status, _h, body = call_json("GET", "/advisories//fixes")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_advisory_id_with_path_separator_returns_400(self) -> None:
        for path in (
            "/advisories/A/B/fixes",
            "/advisories/A\\B/fixes",
        ):
            with self.subTest(path=path):
                status, _h, body = call_json("GET", path)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_declared_non_empty_body_returns_400(self) -> None:
        status, _h, body = call_json(
            "GET", "/advisories/ADV-A/fixes", {"unexpected": True}
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_malformed_content_length_returns_400(self) -> None:
        status, _h, body = call_json(
            "GET", "/advisories/ADV-A/fixes", content_length="abc"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_empty_body_declared_zero_is_accepted(self) -> None:
        status, _h, body = call_json(
            "GET",
            "/advisories/ADV-A/fixes",
            body={},
            content_length="0",
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["fixes"], [])

    def test_unknown_query_parameter_returns_400(self) -> None:
        for qs in ("x=1", "limit=10", "severity=high&foo=bar"):
            with self.subTest(qs=qs):
                status, _h, body = self._fixes("ADV-A", query_string=qs)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_repeated_severity_returns_400(self) -> None:
        status, _h, body = self._fixes(
            "ADV-A", query_string="severity=high&severity=low"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_empty_or_unknown_severity_returns_400(self) -> None:
        for qs in ("severity=", "severity=urgent", "severity=HIG"):
            with self.subTest(qs=qs):
                status, _h, body = self._fixes("ADV-A", query_string=qs)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_bad_request_does_not_read_business_data(self) -> None:
        self._alert(
            "first", advisory="ADV-A", component="openssl", severity="high"
        )
        status, _h, body = self._fixes(
            "ADV-A", query_string="severity=urgent"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_error_body_shape_and_newline(self) -> None:
        status, headers, raw = call(
            "GET", "/advisories/ADV-A/fixes", query_string="x=1"
        )
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
