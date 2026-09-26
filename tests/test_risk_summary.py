from __future__ import annotations

import io
import json
import unittest

from provenance_api.app import application, reset_state

PATH = "/risk"
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64


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


def alert_payload(
    *,
    advisory: str = "CVE-2026-0001",
    component: str = "openssl",
    severity: str = "critical",
) -> dict[str, object]:
    return {
        "advisory": advisory,
        "component": component,
        "severity": severity,
        "summary": "test alert",
    }


def policy_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "name": "release-gate",
        "evidence_requirements": [],
        "license_allowlist": [],
        "max_severity": "high",
    }
    payload.update(overrides)
    return payload


class RiskSummaryTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    # --- Setup helpers -----------------------------------------------------

    def _register(
        self, name: str = "r", digest: str = DIGEST_A
    ) -> str:
        _s, _h, body = call_json(
            "POST",
            "/resources",
            {"name": name, "category": "code", "digest": digest},
        )
        assert _s == "201 Created", body
        return str(body["id"])  # type: ignore[index]

    def _add_alert(
        self,
        resource_id: str,
        *,
        advisory: str = "CVE-2026-0001",
        component: str = "openssl",
        severity: str = "critical",
    ) -> str:
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/vulnerabilities",
            alert_payload(
                advisory=advisory, component=component, severity=severity
            ),
        )
        assert status == "201 Created", body
        return str(body["id"])  # type: ignore[index]

    def _update_alert(
        self, resource_id: str, alert_id: str, **fields: object
    ) -> None:
        status, _h, body = call_json(
            "PUT",
            f"/resources/{resource_id}/vulnerabilities/{alert_id}",
            alert_payload(**fields),  # type: ignore[arg-type]
        )
        assert status == "200 OK", body

    def _delete_alert(self, resource_id: str, alert_id: str) -> None:
        status, _h, body = call_json(
            "DELETE",
            f"/resources/{resource_id}/vulnerabilities/{alert_id}",
        )
        assert status == "200 OK", body

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

    def _add_policy(self, resource_id: str, allowlist: list[str]) -> None:
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/policies",
            policy_payload(license_allowlist=allowlist),
        )
        assert status == "201 Created", body

    def _set_default_policy(self, allowlist: list[str]) -> None:
        status, _h, body = call_json(
            "POST", "/policies", policy_payload(license_allowlist=allowlist)
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

    def _add_exception(self, resource_id: str) -> None:
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/vulnerability-exceptions",
            {
                "advisory": "CVE-2026-0001",
                "component": "openssl",
                "reason": "accepted risk",
            },
        )
        assert status == "201 Created", body

    def _summary(self) -> list[dict[str, object]]:
        status, _h, body = call_json("GET", PATH)
        assert status == "200 OK"
        assert isinstance(body, list)
        return body  # type: ignore[return-value]

    def _record(self, resource_id: str) -> dict[str, object]:
        records = [r for r in self._summary() if r["id"] == resource_id]
        assert len(records) == 1
        return records[0]

    def _single(self, resource_id: str) -> dict[str, object]:
        status, _h, body = call_json(
            "GET", f"/resources/{resource_id}/risk"
        )
        assert status == "200 OK"
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
        second = self._register("second", DIGEST_B)

        status, _h, body = call_json("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertIsInstance(body, list)
        self.assertEqual(
            [record["id"] for record in body], [first, second]  # type: ignore[index]
        )

    def test_record_fields_and_key_order_match_single_resource_view(self) -> None:
        root = self._register()

        _s, _h, raw = call("GET", PATH)
        text = raw.decode("utf-8").rstrip("\n")
        keys = ['"id"', '"score"', '"level"']
        positions = [text.index(k) for k in keys]
        self.assertEqual(positions, sorted(positions))

        self.assertEqual(self._summary(), [self._single(root)])

    def test_records_are_identical_to_single_resource_views(self) -> None:
        first = self._register("first")
        second = self._register("second", DIGEST_B)
        self._add_alert(first, severity="high")
        self._add_sbom(second)
        self._set_lifecycle(second, "quarantined", "tainted")

        self.assertEqual(
            self._summary(), [self._single(first), self._single(second)]
        )

    # --- Ordering ----------------------------------------------------------

    def test_records_follow_resource_registration_order(self) -> None:
        ids = [
            self._register(f"r{i}", format(i, "064d"))
            for i in range(5)
        ]
        self.assertEqual(
            [record["id"] for record in self._summary()], ids
        )

    def test_order_never_changes_after_state_mutations(self) -> None:
        ids = [
            self._register(f"r{i}", format(i, "064d"))
            for i in range(5)
        ]
        # Mutate resources out of order; the summary order is untouched.
        self._add_alert(ids[3], severity="critical")
        self._add_sbom(ids[0])
        self._set_lifecycle(ids[4], "quarantined", "bad")
        self._add_alert(ids[1], severity="low")

        self.assertEqual(
            [record["id"] for record in self._summary()], ids
        )

    # --- Immediate recomputation ------------------------------------------

    def test_alert_registration_is_reflected_immediately(self) -> None:
        root = self._register()
        self.assertEqual(self._record(root)["score"], 20)

        self._add_alert(root, severity="high")
        self.assertEqual(self._record(root)["score"], 20 + 25)
        self.assertEqual(self._record(root)["level"], "medium")

    def test_alert_update_is_reflected_immediately(self) -> None:
        root = self._register()
        alert_id = self._add_alert(root, severity="low")
        self.assertEqual(self._record(root)["score"], 20 + 5)

        self._update_alert(alert_id=alert_id, resource_id=root, severity="high")
        self.assertEqual(self._record(root)["score"], 20 + 25)

    def test_alert_deletion_is_reflected_immediately(self) -> None:
        root = self._register()
        first = self._add_alert(root, advisory="CVE-1", severity="medium")
        second = self._add_alert(root, advisory="CVE-2", severity="low")

        self._delete_alert(root, first)
        self.assertEqual(
            self._record(root),
            {"id": root, "score": 20 + 5, "level": "medium"},
        )
        self._delete_alert(root, second)
        self.assertEqual(
            self._record(root),
            {"id": root, "score": 20, "level": "low"},
        )

    def test_resource_policy_registration_is_reflected_immediately(self) -> None:
        root = self._register()
        self._add_sbom(root)
        self._add_license(root, "GPL-3.0")
        self._add_provenance(root)
        self._add_signature(root)
        self.assertEqual(self._record(root)["score"], 0)

        # The resource's declared license is not on the new allowlist.
        self._add_policy(root, ["Apache-2.0"])
        self.assertEqual(self._record(root)["score"], 10)

    def test_default_policy_registration_is_reflected_immediately(self) -> None:
        root = self._register()
        self._add_sbom(root)
        self._add_license(root, "GPL-3.0")
        self._add_provenance(root)
        self._add_signature(root)
        self.assertEqual(self._record(root)["score"], 0)

        self._set_default_policy(["Apache-2.0"])
        self.assertEqual(self._record(root)["score"], 10)

    def test_resource_policy_takes_precedence_over_default_policy(self) -> None:
        root = self._register()
        self._add_sbom(root)
        self._add_license(root, "GPL-3.0")
        self._add_provenance(root)
        self._add_signature(root)
        self._set_default_policy(["Apache-2.0"])
        self.assertEqual(self._record(root)["score"], 10)

        # The resource's own empty allowlist overrides the restrictive
        # global default policy.
        self._add_policy(root, [])
        self.assertEqual(self._record(root)["score"], 0)

    def test_lifecycle_transition_is_reflected_immediately(self) -> None:
        root = self._register()
        self.assertEqual(self._record(root)["score"], 20)

        self._set_lifecycle(root, "quarantined", "tainted")
        self.assertEqual(self._record(root)["score"], 40)

        self._set_lifecycle(root, "staged")
        self.assertEqual(self._record(root)["score"], 20)

    def test_evidence_registration_is_reflected_immediately(self) -> None:
        root = self._register()
        self.assertEqual(self._record(root)["score"], 20)

        self._add_sbom(root)
        self.assertEqual(self._record(root)["score"], 15)
        self._add_license(root)
        self.assertEqual(self._record(root)["score"], 10)
        self._add_provenance(root)
        self.assertEqual(self._record(root)["score"], 5)
        self._add_signature(root)
        self.assertEqual(self._record(root)["score"], 0)
        self.assertEqual(self._record(root)["level"], "low")

    def test_resource_deregistration_removes_the_record(self) -> None:
        first = self._register("first")
        second = self._register("second", DIGEST_B)
        self._add_alert(second, severity="critical")

        status, _h, body = call_json("DELETE", f"/resources/{second}")
        assert status == "200 OK", body

        self.assertEqual(
            [record["id"] for record in self._summary()], [first]
        )

    # --- Exemptions never move the score ----------------------------------

    def test_exemption_does_not_change_summary_score(self) -> None:
        root = self._register()
        self._add_alert(root, severity="critical")
        before = self._record(root)

        self._add_exception(root)
        # The exemption only affects admission previews; the risk summary
        # still counts the exempted alert.
        self.assertEqual(self._record(root), before)
        self.assertEqual(self._record(root)["score"], 20 + 40)

        # And it matches the per-resource risk view byte-for-byte.
        self.assertEqual(self._record(root), self._single(root))

    # --- Read-only and repeatability --------------------------------------

    def test_repeated_queries_are_identical_and_record_nothing(self) -> None:
        first = self._register("first")
        second = self._register("second", DIGEST_B)
        self._add_alert(first, severity="medium")

        first_result = self._summary()
        for _ in range(3):
            self.assertEqual(self._summary(), first_result)

        # No alert, lifecycle or other hidden record appeared on either
        # resource from querying the summary.
        status, _h, alerts = call_json(
            "GET", f"/resources/{first}/vulnerabilities"
        )
        assert status == "200 OK"
        self.assertEqual(len(alerts["vulnerabilities"]), 1)  # type: ignore[index]
        status, _h, lifecycle = call_json(
            "GET", f"/resources/{second}/lifecycle"
        )
        self.assertEqual(lifecycle["state"], "staged")  # type: ignore[index]

    # --- Empty body handling ----------------------------------------------

    def test_omitted_body_is_accepted(self) -> None:
        status, _h, body = call_json(
            "GET", PATH, omit_content_length=True
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, [])

    def test_explicit_zero_length_is_accepted(self) -> None:
        status, _h, body = call_json("GET", PATH, content_length="0")
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, [])

    def test_empty_string_content_length_is_accepted(self) -> None:
        # Real WSGI servers seed CONTENT_LENGTH with '' when the header is
        # absent; that reads as an empty body, like the other global views.
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

    # --- Query parameters --------------------------------------------------

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
        # No resources exist, yet a query parameter / declared body is
        # rejected purely on the request envelope.
        status, _h, body = call_json(
            "GET", PATH, query_string="x=1"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")  # type: ignore[index]
        status, _h, body = call_json("GET", PATH, b"data")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")  # type: ignore[index]

    # --- Methods -----------------------------------------------------------

    def test_non_get_methods_return_405_with_get_only_allow(self) -> None:
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, headers, body = call_json(method, PATH)
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")  # type: ignore[index]
                self.assertIn(("Allow", "GET"), headers)
                self.assertNotIn(("Allow", "GET, POST"), headers)

    def test_method_check_precedes_body_and_query_checks(self) -> None:
        # A non-GET request carrying a body and a query string still answers
        # 405, and the Allow header names GET alone.
        status, headers, body = call_json(
            "POST", PATH, {"unexpected": True}, query_string="x=1"
        )
        self.assertEqual(status, "405 Method Not Allowed")
        self.assertEqual(body["error"], "method_not_allowed")  # type: ignore[index]
        self.assertIn(("Allow", "GET"), headers)


if __name__ == "__main__":
    unittest.main()
