from __future__ import annotations

import io
import json
import unittest

from provenance_api.app import application, reset_state

PATH = "/risk"
DIGEST_A = "a" * 64


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
        "CONTENT_TYPE": "application/json",
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


class GlobalRiskSummaryTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    # --- Setup helpers -----------------------------------------------------

    def _register(self, name: str = "r", digest: str = DIGEST_A) -> str:
        _s, _h, body = call_json(
            "POST",
            "/resources",
            {"name": name, "category": "code", "digest": digest},
        )
        return str(body["id"])  # type: ignore[index]

    def _add_vulnerability(
        self,
        resource_id: str,
        severity: str,
        advisory: str = "CVE-2026-0001",
        component: str = "openssl",
    ) -> None:
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/vulnerabilities",
            {
                "advisory": advisory,
                "component": component,
                "severity": severity,
                "summary": "test alert",
            },
        )
        assert status == "201 Created", body

    def _add_sbom(self, resource_id: str) -> None:
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/sbom",
            {"format": "spdx", "components": []},
        )
        assert status == "201 Created", body

    def _add_license(
        self, resource_id: str, spdx_id: str = "Apache-2.0"
    ) -> None:
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/license",
            {"spdx_id": spdx_id},
        )
        assert status == "201 Created", body

    def _add_provenance(self, resource_id: str) -> None:
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/provenance",
            {
                "builder": "ci-bot",
                "build_number": "b-1",
                "source_digest": DIGEST_A,
                "materials": [],
            },
        )
        assert status == "201 Created", body

    def _add_signature(self, resource_id: str) -> None:
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/signatures",
            {
                "signer": "alice",
                "algorithm": "hmac-sha256",
                "key_id": "secret",
                "signature": "0" * 64,
                "digest": DIGEST_A,
            },
        )
        assert status == "201 Created", body

    def _add_policy(
        self, resource_id: str, allowlist: list[str] | None = None
    ) -> None:
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/policies",
            {
                "name": "gate",
                "evidence_requirements": [],
                "license_allowlist": allowlist or [],
                "max_severity": "low",
            },
        )
        assert status == "201 Created", body

    def _add_default_policy(self, allowlist: list[str]) -> None:
        status, _h, body = call_json(
            "POST",
            "/policies",
            {
                "name": "default-gate",
                "evidence_requirements": [],
                "license_allowlist": allowlist,
                "max_severity": "low",
            },
        )
        assert status == "201 Created", body

    def _set_lifecycle(
        self, resource_id: str, state: str, reason: str | None = None
    ) -> None:
        payload: dict[str, object] = {"state": state}
        if reason is not None:
            payload["reason"] = reason
        status, _h, body = call_json(
            "POST", f"/resources/{resource_id}/lifecycle", payload
        )
        assert status == "200 OK", body

    def _add_exception(
        self,
        resource_id: str,
        advisory: str = "CVE-2026-0001",
        component: str = "openssl",
    ) -> None:
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/vulnerability-exceptions",
            {"advisory": advisory, "component": component, "reason": "accepted"},
        )
        assert status == "201 Created", body

    def _summary(self) -> list[dict[str, object]]:
        status, _h, body = call_json("GET", PATH)
        assert status == "200 OK"
        assert isinstance(body, list)
        return body  # type: ignore[return-value]

    # --- Shape -------------------------------------------------------------

    def test_empty_registry_is_empty_array(self) -> None:
        status, headers, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            ("Content-Type", "application/json; charset=utf-8"), headers[0]
        )
        self.assertEqual(raw, b"[]\n")

    def test_body_is_compact_utf8_with_a_single_newline(self) -> None:
        self._register()
        _s, _h, raw = call("GET", PATH)
        self.assertTrue(raw.endswith(b"\n"))
        self.assertEqual(raw.count(b"\n"), 1)
        self.assertNotIn(b" ", raw[:-1])

    def test_top_level_is_an_array_without_a_wrapper(self) -> None:
        first = self._register("first")
        second = self._register("second", "b" * 64)

        status, _h, body = call_json("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertIsInstance(body, list)
        self.assertEqual([record["id"] for record in body], [first, second])  # type: ignore[index]

    def test_record_fields_and_key_order_match_single_resource_view(self) -> None:
        resource_id = self._register()

        _s, _h, raw = call("GET", PATH)
        text = raw.decode("utf-8").rstrip("\n")
        keys = ['"id"', '"score"', '"level"']
        positions = [text.index(k) for k in keys]
        self.assertEqual(positions, sorted(positions))

        _s, _h, single = call_json(
            "GET", f"/resources/{resource_id}/risk"
        )
        self.assertEqual(self._summary(), [single])

    # --- Ordering ----------------------------------------------------------

    def test_records_follow_resource_registration_order(self) -> None:
        ids = [self._register(f"r{i}", f"{i:064x}") for i in range(5)]
        self.assertEqual([record["id"] for record in self._summary()], ids)

    def test_registration_order_never_reordered(self) -> None:
        # Alerts and lifecycle jumps never change the summary ordering.
        first = self._register("first")
        second = self._register("second", "b" * 64)
        third = self._register("third", "c" * 64)
        self._add_vulnerability(third, "critical", "CVE-3")
        self._set_lifecycle(second, "quarantined", "bad")

        self.assertEqual(
            [record["id"] for record in self._summary()],
            [first, second, third],
        )

    # --- Scoring parity with the per-resource view -------------------------

    def test_scores_match_single_resource_risk_view(self) -> None:
        clean = self._register("clean")
        for add in (
            self._add_sbom,
            self._add_license,
            self._add_provenance,
            self._add_signature,
        ):
            add(clean)

        alerted = self._register("alerted", "b" * 64)
        for add in (
            self._add_sbom,
            self._add_license,
            self._add_provenance,
            self._add_signature,
        ):
            add(alerted)
        self._add_vulnerability(alerted, "critical", "CVE-1")
        self._add_vulnerability(alerted, "low", "CVE-2")

        blocked = self._register("blocked", "c" * 64)
        self._set_lifecycle(blocked, "quarantined", "tainted")

        status, _h, body = call_json("GET", PATH)
        self.assertEqual(status, "200 OK")
        by_id = {record["id"]: record for record in body}  # type: ignore[index]
        self.assertEqual(by_id[clean], {"id": clean, "score": 0, "level": "low"})
        self.assertEqual(
            by_id[alerted],
            {"id": alerted, "score": 45, "level": "medium"},
        )
        # 20 for the blocked state + 20 for the four missing evidence items.
        self.assertEqual(
            by_id[blocked],
            {"id": blocked, "score": 40, "level": "medium"},
        )

    def test_default_policy_allowlist_counts_like_single_view(self) -> None:
        resource_id = self._register()
        self._add_sbom(resource_id)
        self._add_license(resource_id, "GPL-3.0")
        self._add_provenance(resource_id)
        self._add_signature(resource_id)
        self._add_default_policy(["Apache-2.0", "MIT"])

        _s, _h, single = call_json(
            "GET", f"/resources/{resource_id}/risk"
        )
        self.assertEqual(single["score"], 10)  # type: ignore[index]
        self.assertEqual(self._summary(), [single])

    def test_resource_policy_overrides_default_policy(self) -> None:
        resource_id = self._register()
        self._add_sbom(resource_id)
        self._add_license(resource_id, "GPL-3.0")
        self._add_provenance(resource_id)
        self._add_signature(resource_id)
        self._add_default_policy(["Apache-2.0"])
        self._add_policy(resource_id, [])

        self.assertEqual(self._summary()[0]["score"], 0)

    # --- Immediate recomputation ------------------------------------------

    def test_alert_register_update_delete_reflected_immediately(self) -> None:
        resource_id = self._register()
        for add in (
            self._add_sbom,
            self._add_license,
            self._add_provenance,
            self._add_signature,
        ):
            add(resource_id)
        self.assertEqual(self._summary()[0]["score"], 0)

        self._add_vulnerability(resource_id, "high", "CVE-1")
        self.assertEqual(self._summary()[0]["score"], 25)

        # Find the alert id and lower the severity in place.
        _s, _h, alerts = call_json(
            "GET", f"/resources/{resource_id}/vulnerabilities"
        )
        alert_id = str(alerts["vulnerabilities"][0]["id"])  # type: ignore[index]
        status, _h, _b = call_json(
            "PUT",
            f"/resources/{resource_id}/vulnerabilities/{alert_id}",
            {
                "advisory": "CVE-1",
                "component": "openssl",
                "severity": "low",
                "summary": "test alert",
            },
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(self._summary()[0]["score"], 5)

        status, _h, _b = call_json(
            "DELETE",
            f"/resources/{resource_id}/vulnerabilities/{alert_id}",
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(self._summary()[0]["score"], 0)

    def test_lifecycle_change_reflected_immediately(self) -> None:
        resource_id = self._register()
        for add in (
            self._add_sbom,
            self._add_license,
            self._add_provenance,
            self._add_signature,
        ):
            add(resource_id)
        self.assertEqual(self._summary()[0]["score"], 0)

        self._set_lifecycle(resource_id, "quarantined", "tainted")
        self.assertEqual(self._summary()[0]["score"], 20)

        self._set_lifecycle(resource_id, "staged")
        self.assertEqual(self._summary()[0]["score"], 0)

    def test_evidence_addition_reflected_immediately(self) -> None:
        resource_id = self._register()
        # Four missing evidence items -> 20 points.
        self.assertEqual(self._summary()[0]["score"], 20)

        self._add_sbom(resource_id)
        self.assertEqual(self._summary()[0]["score"], 15)
        self._add_license(resource_id)
        self.assertEqual(self._summary()[0]["score"], 10)
        self._add_provenance(resource_id)
        self.assertEqual(self._summary()[0]["score"], 5)
        self._add_signature(resource_id)
        self.assertEqual(self._summary()[0]["score"], 0)

    def test_evidence_removal_via_deregistration_reflected_immediately(
        self,
    ) -> None:
        # Evidence records are removed together with their resource; the
        # surviving resource keeps its own missing-evidence score.
        clean = self._register("clean")
        for add in (
            self._add_sbom,
            self._add_license,
            self._add_provenance,
            self._add_signature,
        ):
            add(clean)
        bare = self._register("bare", "b" * 64)

        status, _h, body = call_json("DELETE", f"/resources/{clean}")
        assert status == "200 OK", body

        records = self._summary()
        self.assertEqual([record["id"] for record in records], [bare])
        self.assertEqual(records[0]["score"], 20)

    def test_policy_changes_reflected_immediately(self) -> None:
        resource_id = self._register()
        self._add_sbom(resource_id)
        self._add_license(resource_id, "GPL-3.0")
        self._add_provenance(resource_id)
        self._add_signature(resource_id)
        self.assertEqual(self._summary()[0]["score"], 0)

        # Registering the global default policy changes the next query at
        # once; adding an overriding (empty-allowlist) resource policy
        # removes the license points just as immediately.
        self._add_default_policy(["Apache-2.0"])
        self.assertEqual(self._summary()[0]["score"], 10)

        self._add_policy(resource_id, [])
        self.assertEqual(self._summary()[0]["score"], 0)

    def test_exception_does_not_change_summary_score(self) -> None:
        resource_id = self._register()
        for add in (
            self._add_sbom,
            self._add_license,
            self._add_provenance,
            self._add_signature,
        ):
            add(resource_id)
        self._add_policy(resource_id, [])
        self._add_vulnerability(resource_id, "high")
        self._add_exception(resource_id)

        # The exemption only shapes the admission preview; the risk score
        # still counts the alert.
        _s, _h, preview = call_json(
            "GET", f"/resources/{resource_id}/admission-preview"
        )
        self.assertEqual(preview["exempted_count"], 1)  # type: ignore[index]
        self.assertEqual(self._summary()[0]["score"], 25)

    def test_resource_deregistration_reflected_immediately(self) -> None:
        first = self._register("first")
        second = self._register("second", "b" * 64)
        self._add_vulnerability(second, "critical", "CVE-1")

        status, _h, body = call_json("DELETE", f"/resources/{second}")
        assert status == "200 OK", body

        records = self._summary()
        self.assertEqual([record["id"] for record in records], [first])
        self.assertEqual(records[0]["score"], 20)

    # --- Read-only / idempotent --------------------------------------------

    def test_repeated_queries_are_identical_and_record_nothing(self) -> None:
        first = self._register("first")
        second = self._register("second", "b" * 64)
        self._add_vulnerability(second, "high", "CVE-1")

        _s, _h, first_raw = call("GET", PATH)
        for _ in range(3):
            _s, _h, raw = call("GET", PATH)
            self.assertEqual(raw, first_raw)
        self.assertEqual(
            [record["id"] for record in self._summary()], [first, second]
        )
        # The queries created no alerts or other records on either resource.
        _s, _h, alerts = call_json(
            "GET", f"/resources/{second}/vulnerabilities"
        )
        self.assertEqual(len(alerts["vulnerabilities"]), 1)  # type: ignore[index]

    # --- Empty body handling -----------------------------------------------

    def test_omitted_body_is_accepted(self) -> None:
        status, _h, body = call_json("GET", PATH, omit_content_length=True)
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, [])

    def test_explicit_zero_length_is_accepted(self) -> None:
        status, _h, body = call_json("GET", PATH, content_length="0")
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, [])

    def test_empty_string_content_length_is_accepted(self) -> None:
        status, _h, body = call_json("GET", PATH, content_length="")
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, [])

    def test_declared_non_empty_body_is_bad_request(self) -> None:
        status, _h, body = call_json("GET", PATH, b"x")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")  # type: ignore[index]

    def test_malformed_content_length_is_bad_request(self) -> None:
        for raw in ("abc", "-1", "1.5"):
            with self.subTest(raw=raw):
                status, _h, body = call_json(
                    "GET", PATH, content_length=raw
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")  # type: ignore[index]

    # --- Query parameters ---------------------------------------------------

    def test_any_query_parameter_is_bad_request(self) -> None:
        self._register()
        for qs in ("x=1", "pretty=true", "page=2", "severity=high"):
            with self.subTest(qs=qs):
                status, _h, body = call_json(
                    "GET", PATH, query_string=qs
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")  # type: ignore[index]

    def test_bad_request_does_not_read_business_data(self) -> None:
        # A query parameter / declared body is rejected purely on the
        # request envelope even with no resources registered.
        status, _h, body = call_json("GET", PATH, query_string="x=1")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")  # type: ignore[index]
        status, _h, body = call_json("GET", PATH, b"data")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")  # type: ignore[index]

    # --- Methods ------------------------------------------------------------

    def test_non_get_methods_return_405_with_get_only_allow(self) -> None:
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, headers, body = call_json(method, PATH)
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")  # type: ignore[index]
                self.assertIn(("Allow", "GET"), headers)
                self.assertNotIn(("Allow", "GET, POST"), headers)

    def test_method_check_precedes_body_and_query_checks(self) -> None:
        status, headers, body = call_json(
            "POST", PATH, {"unexpected": True}, query_string="x=1"
        )
        self.assertEqual(status, "405 Method Not Allowed")
        self.assertEqual(body["error"], "method_not_allowed")  # type: ignore[index]
        self.assertIn(("Allow", "GET"), headers)


if __name__ == "__main__":
    unittest.main()
