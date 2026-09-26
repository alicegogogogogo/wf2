from __future__ import annotations

import io
import json
import unittest

from provenance_api.app import application, reset_state

PATH = "/admission-preview"
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


class AdmissionPreviewSummaryTests(unittest.TestCase):
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

    def _delete_alert(self, resource_id: str, alert_id: str) -> None:
        status, _h, body = call_json(
            "DELETE",
            f"/resources/{resource_id}/vulnerabilities/{alert_id}",
        )
        assert status == "200 OK", body

    def _add_policy(
        self, resource_id: str, **overrides: object
    ) -> None:
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/policies",
            policy_payload(**overrides),
        )
        assert status == "201 Created", body

    def _set_default_policy(self, **overrides: object) -> None:
        status, _h, body = call_json(
            "POST", "/policies", policy_payload(**overrides)
        )
        assert status == "201 Created", body

    def _add_exception(
        self,
        resource_id: str,
        *,
        advisory: str = "CVE-2026-0001",
        component: str = "openssl",
    ) -> str:
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/vulnerability-exceptions",
            {
                "advisory": advisory,
                "component": component,
                "reason": "accepted risk",
            },
        )
        assert status == "201 Created", body
        return str(body["id"])  # type: ignore[index]

    def _delete_exception(self, resource_id: str, exception_id: str) -> None:
        status, _h, body = call_json(
            "DELETE",
            f"/resources/{resource_id}/vulnerability-exceptions/"
            f"{exception_id}",
        )
        assert status == "200 OK", body

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
            "GET", f"/resources/{resource_id}/admission-preview"
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
        root = self._register()
        self._add_policy(root)
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
        self._add_policy(root)

        _s, _h, raw = call("GET", PATH)
        text = raw.decode("utf-8").rstrip("\n")
        keys = ['"id"', '"allowed"', '"reasons"', '"exempted_count"']
        positions = [text.index(k) for k in keys]
        self.assertEqual(positions, sorted(positions))

        self.assertEqual(self._summary(), [self._single(root)])

    def test_records_are_identical_to_single_resource_views(self) -> None:
        first = self._register("first")
        second = self._register("second", DIGEST_B)
        self._add_policy(first, evidence_requirements=["sbom"])
        self._add_alert(second, severity="critical")
        self._add_policy(second)

        self.assertEqual(
            self._summary(), [self._single(first), self._single(second)]
        )

    # --- Ordering ----------------------------------------------------------

    def test_records_follow_resource_registration_order(self) -> None:
        ids = [
            self._register(f"r{i}", format(i, "064d"))
            for i in range(5)
        ]
        self._set_default_policy()
        self.assertEqual(
            [record["id"] for record in self._summary()], ids
        )

    def test_order_never_changes_after_state_mutations(self) -> None:
        ids = [
            self._register(f"r{i}", format(i, "064d"))
            for i in range(5)
        ]
        self._set_default_policy()
        # Mutate resources out of order; the summary order is untouched.
        self._add_alert(ids[3], severity="critical")
        self._add_policy(ids[0])
        self._set_lifecycle(ids[4], "quarantined", "bad")
        self._add_exception(ids[3])

        self.assertEqual(
            [record["id"] for record in self._summary()], ids
        )

    # --- Decisions ---------------------------------------------------------

    def test_allowed_when_preview_would_allow(self) -> None:
        root = self._register()
        self._add_policy(root)
        self._add_alert(root, severity="low")
        self.assertEqual(
            self._record(root),
            {"id": root, "allowed": True, "reasons": [], "exempted_count": 0},
        )

    def test_denied_reasons_match_single_preview_order(self) -> None:
        root = self._register()
        # Missing sbom (required), denied license and an over-ceiling
        # alert all fire at once, in the fixed order.
        self._add_policy(
            root,
            evidence_requirements=["sbom"],
            license_allowlist=["Apache-2.0"],
            max_severity="low",
        )
        self._add_alert(root, severity="critical")
        self.assertEqual(
            self._record(root),
            {
                "id": root,
                "allowed": False,
                "reasons": ["no_sbom", "license_denied", "severity_exceeded"],
                "exempted_count": 0,
            },
        )

    def test_each_resource_uses_its_own_policy(self) -> None:
        strict = self._register("strict")
        relaxed = self._register("relaxed", DIGEST_B)
        self._add_policy(strict, max_severity="low")
        self._add_policy(relaxed, max_severity="critical")
        self._add_alert(strict, severity="high")
        self._add_alert(relaxed, severity="high")

        self.assertFalse(self._record(strict)["allowed"])
        self.assertEqual(
            self._record(strict)["reasons"], ["severity_exceeded"]
        )
        self.assertTrue(self._record(relaxed)["allowed"])

    def test_resource_without_policy_uses_global_default(self) -> None:
        root = self._register()
        self._add_alert(root, severity="critical")
        self._set_default_policy(max_severity="high")

        self.assertEqual(
            self._record(root),
            {
                "id": root,
                "allowed": False,
                "reasons": ["severity_exceeded"],
                "exempted_count": 0,
            },
        )
        self.assertEqual(self._record(root), self._single(root))

    def test_own_policy_takes_precedence_over_default(self) -> None:
        root = self._register()
        self._add_alert(root, severity="high")
        self._set_default_policy(max_severity="low")
        self._add_policy(root, max_severity="critical")
        self.assertTrue(self._record(root)["allowed"])

    # --- Missing policy entries -------------------------------------------

    def test_resource_without_any_policy_still_gets_an_entry(self) -> None:
        root = self._register()
        self._add_alert(root, severity="critical")
        self.assertEqual(
            self._record(root),
            {
                "id": root,
                "allowed": None,
                "reasons": ["policy_not_found"],
                "exempted_count": 0,
            },
        )

    def test_missing_policy_entry_is_json_null_not_missing_key(self) -> None:
        root = self._register()
        _s, _h, raw = call("GET", PATH)
        self.assertEqual(
            raw,
            b'[{"id":"' + root.encode("ascii")
            + b'","allowed":null,"reasons":["policy_not_found"],'
            b'"exempted_count":0}]\n',
        )

    def test_missing_policy_entry_still_counts_exempted_alerts(self) -> None:
        root = self._register()
        self._add_alert(root, severity="critical")
        self._add_alert(
            root, advisory="CVE-2026-0002", component="zlib", severity="high"
        )
        self._add_exception(root)
        self.assertEqual(
            self._record(root),
            {
                "id": root,
                "allowed": None,
                "reasons": ["policy_not_found"],
                "exempted_count": 1,
            },
        )

    def test_missing_policy_entry_has_no_other_keys_or_reasons(self) -> None:
        root = self._register()
        # A blocked lifecycle state must not surface: without a policy the
        # only reason is policy_not_found.
        self._set_lifecycle(root, "quarantined", "tainted")
        record = self._record(root)
        self.assertEqual(
            set(record), {"id", "allowed", "reasons", "exempted_count"}
        )
        self.assertIsNone(record["allowed"])
        self.assertEqual(record["reasons"], ["policy_not_found"])

    def test_mixed_entries_share_the_same_key_order(self) -> None:
        governed = self._register("governed")
        ungoverned = self._register("ungoverned", DIGEST_B)
        self._add_policy(governed)

        records = self._summary()
        self.assertEqual([r["id"] for r in records], [governed, ungoverned])
        for record in records:
            self.assertEqual(
                list(record), ["id", "allowed", "reasons", "exempted_count"]
            )
        self.assertTrue(records[0]["allowed"])
        self.assertIsNone(records[1]["allowed"])
        self.assertEqual(records[1]["reasons"], ["policy_not_found"])

    def test_registering_default_policy_fills_in_pending_entries(self) -> None:
        root = self._register()
        self.assertIsNone(self._record(root)["allowed"])

        self._set_default_policy()
        self.assertTrue(self._record(root)["allowed"])

    # --- Exemptions --------------------------------------------------------

    def test_exempting_blocking_alert_allows_and_counts(self) -> None:
        root = self._register()
        self._add_policy(root, max_severity="high")
        self._add_alert(root, severity="critical")
        self._add_exception(root)
        self.assertEqual(
            self._record(root),
            {"id": root, "allowed": True, "reasons": [], "exempted_count": 1},
        )

    def test_unexempted_alert_still_denies(self) -> None:
        root = self._register()
        self._add_policy(root, max_severity="high")
        self._add_alert(root, severity="critical")
        self._add_alert(
            root, advisory="CVE-2026-0002", component="zlib",
            severity="critical",
        )
        self._add_exception(root)
        self.assertEqual(
            self._record(root),
            {
                "id": root,
                "allowed": False,
                "reasons": ["severity_exceeded"],
                "exempted_count": 1,
            },
        )

    def test_state_blocked_short_circuits_but_keeps_exempted_count(self) -> None:
        root = self._register()
        self._add_policy(root, max_severity="high")
        self._add_alert(root, severity="critical")
        self._add_exception(root)
        self._set_lifecycle(root, "quarantined", "tainted")
        self.assertEqual(
            self._record(root),
            {
                "id": root,
                "allowed": False,
                "reasons": ["state_blocked"],
                "exempted_count": 1,
            },
        )

    # --- Immediate recomputation ------------------------------------------

    def test_alert_add_update_delete_are_reflected_immediately(self) -> None:
        root = self._register()
        self._add_policy(root, max_severity="high")
        self.assertTrue(self._record(root)["allowed"])

        alert_id = self._add_alert(root, severity="critical")
        self.assertFalse(self._record(root)["allowed"])

        # Downgrade the alert under the ceiling via an in-place update.
        status, _h, body = call_json(
            "PUT",
            f"/resources/{root}/vulnerabilities/{alert_id}",
            alert_payload(severity="medium"),
        )
        assert status == "200 OK", body
        self.assertTrue(self._record(root)["allowed"])

        self._delete_alert(root, alert_id)
        self.assertTrue(self._record(root)["allowed"])

    def test_exception_add_and_delete_are_reflected_immediately(self) -> None:
        root = self._register()
        self._add_policy(root, max_severity="high")
        self._add_alert(root, severity="critical")
        self.assertFalse(self._record(root)["allowed"])
        self.assertEqual(self._record(root)["exempted_count"], 0)

        exception_id = self._add_exception(root)
        self.assertTrue(self._record(root)["allowed"])
        self.assertEqual(self._record(root)["exempted_count"], 1)

        self._delete_exception(root, exception_id)
        self.assertFalse(self._record(root)["allowed"])
        self.assertEqual(self._record(root)["exempted_count"], 0)

    def test_lifecycle_transition_is_reflected_immediately(self) -> None:
        root = self._register()
        self._add_policy(root)
        self.assertTrue(self._record(root)["allowed"])

        self._set_lifecycle(root, "quarantined", "tainted")
        self.assertEqual(
            self._record(root)["reasons"], ["state_blocked"]
        )
        self._set_lifecycle(root, "staged")
        self.assertTrue(self._record(root)["allowed"])

    def test_resource_deregistration_removes_the_record(self) -> None:
        first = self._register("first")
        second = self._register("second", DIGEST_B)
        self._add_alert(second, severity="critical")

        status, _h, body = call_json("DELETE", f"/resources/{second}")
        assert status == "200 OK", body

        self.assertEqual(
            [record["id"] for record in self._summary()], [first]
        )

    # --- Read-only and repeatability --------------------------------------

    def test_repeated_queries_are_identical_and_record_nothing(self) -> None:
        first = self._register("first")
        second = self._register("second", DIGEST_B)
        self._add_policy(first)
        self._add_alert(second, severity="critical")

        first_result = self._summary()
        for _ in range(3):
            self.assertEqual(self._summary(), first_result)

        # The ungoverned 404 of the single-resource view is unchanged by
        # querying the summary.
        status, _h, single = call_json(
            "GET", f"/resources/{second}/admission-preview"
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(single["error"], "policy_not_found")  # type: ignore[index]

    def test_summary_does_not_change_admission_evaluation(self) -> None:
        root = self._register()
        self._add_policy(root, max_severity="high")
        self._add_alert(root, severity="critical")
        self._add_exception(root)

        self._summary()
        # Admission still counts the exempted alert and carries no count.
        status, _h, admission = call_json(
            "POST", f"/resources/{root}/admission"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            admission,  # type: ignore[arg-type]
            {"id": root, "allowed": False, "reasons": ["severity_exceeded"]},
        )

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
        root = self._register()
        self._add_policy(root)
        for qs in ("x=1", "pretty=true", "page=2", "focus=root", "="):
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
