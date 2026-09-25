from __future__ import annotations

import hashlib
import io
import json
import unittest

from provenance_api.app import application, reset_state

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
EMPTY_DIGEST = hashlib.sha256(b"").hexdigest()


def call(
    method: str,
    path: str,
    body: bytes | str | dict[str, object] | None = None,
    *,
    query_string: str | None = None,
    content_type: str | None = "application/json",
    omit_content_length: bool = False,
    content_length: int | str | None = None,
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
    if content_type is not None:
        environ["CONTENT_TYPE"] = content_type
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
) -> tuple[str, list[tuple[str, str]], dict[str, object]]:
    status, headers, raw = call(method, path, body, query_string=query_string)
    return status, headers, json.loads(raw.decode("utf-8"))


def policy_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "name": "release-gate",
        "evidence_requirements": ["sbom", "license", "provenance"],
        "license_allowlist": ["Apache-2.0", "MIT"],
        "max_severity": "high",
    }
    payload.update(overrides)
    return payload


class PolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.resource_id = self._create(DIGEST_A)

    def _create(self, digest: str = DIGEST_A, name: str = "r") -> str:
        _s, _h, body = call_json(
            "POST",
            "/resources",
            {"name": name, "category": "code", "digest": digest},
        )
        return str(body["id"])

    def _register(
        self, resource_id: str | None = None, **overrides: object
    ) -> tuple[str, list[tuple[str, str]], dict[str, object]]:
        return call_json(
            "POST",
            f"/resources/{resource_id or self.resource_id}/policies",
            policy_payload(**overrides),
        )

    # --- Registration ------------------------------------------------------

    def test_register_policy_returns_201_and_echoes(self) -> None:
        status, headers, body = self._register()

        self.assertEqual(status, "201 Created")
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )
        self.assertEqual(
            body,
            {
                "id": self.resource_id,
                "name": "release-gate",
                "evidence_requirements": ["sbom", "license", "provenance"],
                "license_allowlist": ["Apache-2.0", "MIT"],
                "max_severity": "high",
            },
        )

    def test_max_severity_is_case_insensitive_and_stored_lowercase(self) -> None:
        _s, _h, body = self._register(max_severity="CRITICAL")
        self.assertEqual(body["max_severity"], "critical")

    def test_response_is_compact_with_stable_key_order_and_newline(self) -> None:
        status, _headers, raw = call(
            "POST",
            f"/resources/{self.resource_id}/policies",
            policy_payload(),
        )
        self.assertEqual(status, "201 Created")
        self.assertTrue(raw.endswith(b"\n"))
        text = raw.decode("utf-8").rstrip("\n")
        self.assertNotIn(" ", text)
        self.assertLess(text.index('"id"'), text.index('"name"'))
        self.assertLess(
            text.index('"name"'), text.index('"evidence_requirements"')
        )
        self.assertLess(
            text.index('"evidence_requirements"'),
            text.index('"license_allowlist"'),
        )
        self.assertLess(
            text.index('"license_allowlist"'), text.index('"max_severity"')
        )

    def test_empty_arrays_are_valid(self) -> None:
        status, _h, body = self._register(
            evidence_requirements=[], license_allowlist=[]
        )
        self.assertEqual(status, "201 Created")
        self.assertEqual(body["evidence_requirements"], [])
        self.assertEqual(body["license_allowlist"], [])

    def test_same_content_resubmitted_returns_200(self) -> None:
        first_status, _h, first = self._register()
        self.assertEqual(first_status, "201 Created")

        status, _h, body = self._register()
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, first)

        # Submission-order differences in the arrays are still the same
        # content only when identical; an exact resubmission stays idempotent.
        status, _h, body = self._register(
            evidence_requirements=["sbom", "license", "provenance"]
        )
        self.assertEqual(status, "200 OK")

    def test_different_content_returns_conflict_and_keeps_original(self) -> None:
        _s, _h, original = self._register()

        for overrides in (
            {"name": "other"},
            {"evidence_requirements": ["sbom"]},
            {"license_allowlist": ["MIT"]},
            {"max_severity": "critical"},
            {"license_allowlist": ["MIT", "Apache-2.0"]},
        ):
            with self.subTest(overrides=overrides):
                status, _h, body = self._register(**overrides)
                self.assertEqual(status, "409 Conflict")
                self.assertEqual(body["error"], "policy_conflict")

        status, _h, fetched = call_json(
            "GET", f"/resources/{self.resource_id}/policies"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(fetched, original)

    # --- Query -------------------------------------------------------------

    def test_get_policy(self) -> None:
        _s, _h, registered = self._register()
        status, _h, body = call_json(
            "GET", f"/resources/{self.resource_id}/policies"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, registered)

    def test_get_without_policy_is_policy_not_found(self) -> None:
        status, _h, body = call_json(
            "GET", f"/resources/{self.resource_id}/policies"
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "policy_not_found")

    # --- Invalid requests --------------------------------------------------

    def assert_invalid(self, *args: object, **kwargs: object) -> None:
        status, _headers, body = call_json(*args, **kwargs)  # type: ignore[arg-type]
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_missing_body_is_bad_request(self) -> None:
        self.assert_invalid(
            "POST", f"/resources/{self.resource_id}/policies", None
        )

    def test_malformed_or_non_utf8_json_is_bad_request(self) -> None:
        self.assert_invalid(
            "POST", f"/resources/{self.resource_id}/policies", b"{bad"
        )
        status, _h, raw = call(
            "POST", f"/resources/{self.resource_id}/policies", b"\xff\xfe"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(json.loads(raw)["error"], "invalid_request")

    def test_non_object_body_is_bad_request(self) -> None:
        for bad in (b"[]", b'"x"', b"42", b"null"):
            with self.subTest(bad=bad):
                self.assert_invalid(
                    "POST", f"/resources/{self.resource_id}/policies", bad
                )

    def test_missing_required_fields(self) -> None:
        fields = (
            "name",
            "evidence_requirements",
            "license_allowlist",
            "max_severity",
        )
        for field in fields:
            with self.subTest(field=field):
                payload = policy_payload()
                del payload[field]
                self.assert_invalid(
                    "POST", f"/resources/{self.resource_id}/policies", payload
                )

    def test_unknown_field_is_bad_request(self) -> None:
        self.assert_invalid(
            "POST",
            f"/resources/{self.resource_id}/policies",
            policy_payload(extra=1),
        )

    def test_null_values_are_bad_request(self) -> None:
        for field in (
            "name",
            "evidence_requirements",
            "license_allowlist",
            "max_severity",
        ):
            with self.subTest(field=field):
                self.assert_invalid(
                    "POST",
                    f"/resources/{self.resource_id}/policies",
                    policy_payload(**{field: None}),
                )

    def test_name_validation(self) -> None:
        for bad_name in ("", 5, True, ["x"]):
            with self.subTest(bad_name=bad_name):
                self.assert_invalid(
                    "POST",
                    f"/resources/{self.resource_id}/policies",
                    policy_payload(name=bad_name),
                )
        status, _h, _b = self._register(name="x" * 256)
        self.assertEqual(status, "201 Created")
        self.assert_invalid(
            "POST",
            f"/resources/{self.resource_id}/policies",
            policy_payload(name="x" * 257),
        )

    def test_evidence_validation(self) -> None:
        for bad in (
            "sbom",
            ["SIGNATURE"],
            ["Signature"],
            ["sbom", 1],
            ["sbom", "sbom"],
            [""],
            [None],
        ):
            with self.subTest(bad=bad):
                self.assert_invalid(
                    "POST",
                    f"/resources/{self.resource_id}/policies",
                    policy_payload(evidence_requirements=bad),
                )

    def test_signature_is_a_valid_evidence_requirement(self) -> None:
        status, _h, body = self._register(
            evidence_requirements=["sbom", "signature"]
        )
        self.assertEqual(status, "201 Created")
        self.assertEqual(
            body["evidence_requirements"], ["sbom", "signature"]
        )

    def test_allowlist_validation(self) -> None:
        for bad in (
            "MIT",
            ["MIT", 1],
            ["MIT", "MIT"],
            [""],
            [None],
            [["MIT"]],
        ):
            with self.subTest(bad=bad):
                self.assert_invalid(
                    "POST",
                    f"/resources/{self.resource_id}/policies",
                    policy_payload(license_allowlist=bad),
                )

    def test_max_severity_validation(self) -> None:
        for bad in ("", "urgent", 3, True, ["high"]):
            with self.subTest(bad=bad):
                self.assert_invalid(
                    "POST",
                    f"/resources/{self.resource_id}/policies",
                    policy_payload(max_severity=bad),
                )

    def test_query_parameters_rejected(self) -> None:
        for method in ("POST", "GET"):
            with self.subTest(method=method):
                body = policy_payload() if method == "POST" else None
                status, _h, payload = call_json(
                    method,
                    f"/resources/{self.resource_id}/policies",
                    body,
                    query_string="bogus=1",
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(payload["error"], "invalid_request")

    def test_path_id_validation(self) -> None:
        for method in ("GET", "POST"):
            body = policy_payload() if method == "POST" else None
            with self.subTest(method=method):
                status, _h, payload = call_json(
                    method, "/resources//policies", body
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(payload["error"], "invalid_request")

    def test_resource_not_found(self) -> None:
        for method, path, body in (
            ("POST", "/resources/missing/policies", policy_payload()),
            ("GET", "/resources/missing/policies", None),
            ("POST", "/resources/missing/admission", None),
        ):
            with self.subTest(path=path):
                status, _h, payload = call_json(method, path, body)
                self.assertEqual(status, "404 Not Found")
                self.assertEqual(payload["error"], "resource_not_found")

    def test_bad_validation_leaves_no_policy(self) -> None:
        self._register(name="x" * 9999)
        self._register(max_severity="nope")
        _s, _h, body = call_json(
            "GET", f"/resources/{self.resource_id}/policies"
        )
        self.assertEqual(body["error"], "policy_not_found")

    def test_unsupported_methods_return_405_with_allow(self) -> None:
        for method in ("DELETE", "PUT", "PATCH"):
            with self.subTest(method=method):
                status, headers, body = call_json(
                    method, f"/resources/{self.resource_id}/policies"
                )
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")
                self.assertIn(("Allow", "GET, POST"), headers)


class AdmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.resource_id = self._create(DIGEST_A)

    def _create(self, digest: str = DIGEST_A, name: str = "r") -> str:
        _s, _h, body = call_json(
            "POST",
            "/resources",
            {"name": name, "category": "code", "digest": digest},
        )
        return str(body["id"])

    def _register(self, resource_id: str | None = None, **overrides: object):
        return call_json(
            "POST",
            f"/resources/{resource_id or self.resource_id}/policies",
            policy_payload(**overrides),
        )

    def _admission(
        self, resource_id: str | None = None
    ) -> tuple[str, list[tuple[str, str]], dict[str, object]]:
        return call_json(
            "POST", f"/resources/{resource_id or self.resource_id}/admission"
        )

    def _add_sbom(self, resource_id: str | None = None) -> None:
        call_json(
            "POST",
            f"/resources/{resource_id or self.resource_id}/sbom",
            {"format": "spdx", "components": []},
        )

    def _add_license(
        self, spdx_id: str = "Apache-2.0", resource_id: str | None = None
    ) -> None:
        call_json(
            "POST",
            f"/resources/{resource_id or self.resource_id}/license",
            {"spdx_id": spdx_id},
        )

    def _add_provenance(self, resource_id: str | None = None) -> None:
        call_json(
            "POST",
            f"/resources/{resource_id or self.resource_id}/provenance",
            {
                "builder": "ci",
                "build_number": "1",
                "source_digest": DIGEST_B,
                "materials": [],
            },
        )

    def _add_signature(self, resource_id: str | None = None) -> None:
        call_json(
            "POST",
            f"/resources/{resource_id or self.resource_id}/signatures",
            {
                "signer": "alice",
                "algorithm": "hmac-sha256",
                "key_id": "key-1",
                "signature": "c" * 64,
                "digest": DIGEST_A,
            },
        )

    def _add_alert(
        self, severity: str, resource_id: str | None = None
    ) -> None:
        call_json(
            "POST",
            f"/resources/{resource_id or self.resource_id}/vulnerabilities",
            {
                "advisory": f"CVE-{severity}",
                "component": "openssl",
                "severity": severity,
                "summary": "summary",
            },
        )

    def _assemble_empty_content(self, resource_id: str) -> None:
        # Register the empty single chunk with the required headers.
        environ = {
            "REQUEST_METHOD": "POST",
            "PATH_INFO": f"/resources/{resource_id}/chunks/0",
            "QUERY_STRING": "",
            "CONTENT_LENGTH": "0",
            "CONTENT_TYPE": "application/octet-stream",
            "HTTP_X_TOTAL_CHUNKS": "1",
            "HTTP_X_CONTENT_DIGEST": EMPTY_DIGEST,
            "wsgi.input": io.BytesIO(b""),
        }
        captured: dict[str, object] = {}
        list(
            application(
                environ,
                lambda s, h: captured.update(status=s, headers=h),
            )
        )
        self.assertEqual(captured["status"], "201 Created")
        status, _h, _b = call_json(
            "POST", f"/resources/{resource_id}/assemble"
        )
        self.assertEqual(status, "201 Created")

    # --- Request shape -----------------------------------------------------

    def test_admission_without_policy_is_not_found(self) -> None:
        status, _h, body = self._admission()
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "policy_not_found")

    def test_admission_rejects_body(self) -> None:
        self._register()
        cases = [
            {"body": b"{}"},
            {"body": None, "content_length": 5},
            {"body": None, "content_length": "abc"},
        ]
        for kwargs in cases:
            with self.subTest(kwargs=kwargs):
                status, _h, raw = call(
                    "POST",
                    f"/resources/{self.resource_id}/admission",
                    **kwargs,
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(
                    json.loads(raw)["error"], "invalid_request"
                )

    def test_admission_without_content_length_is_allowed(self) -> None:
        self._register(
            evidence_requirements=[], license_allowlist=[]
        )
        status, _h, body = call(
            "POST",
            f"/resources/{self.resource_id}/admission",
            omit_content_length=True,
            content_type=None,
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(json.loads(body)["allowed"], True)

    def test_admission_rejects_query_parameters(self) -> None:
        self._register()
        status, _h, body = call_json(
            "POST",
            f"/resources/{self.resource_id}/admission",
            query_string="x=1",
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_admission_only_allows_post(self) -> None:
        self._register()
        for method in ("GET", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, headers, body = call_json(
                    method, f"/resources/{self.resource_id}/admission"
                )
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")
                self.assertIn(("Allow", "POST"), headers)

    # --- Decisions ---------------------------------------------------------

    def test_allows_when_policy_demands_nothing(self) -> None:
        self._register(evidence_requirements=[], license_allowlist=[])
        status, headers, raw = call(
            "POST", f"/resources/{self.resource_id}/admission"
        )
        self.assertEqual(status, "200 OK")
        self.assertTrue(raw.endswith(b"\n"))
        body = json.loads(raw)
        self.assertEqual(
            body,
            {"id": self.resource_id, "allowed": True, "reasons": []},
        )
        text = raw.decode().rstrip("\n")
        self.assertNotIn(" ", text)
        self.assertLess(text.index('"id"'), text.index('"allowed"'))
        self.assertLess(text.index('"allowed"'), text.index('"reasons"'))
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )

    def test_missing_evidence_reported_in_order(self) -> None:
        self._register(license_allowlist=[])
        _s, _h, body = self._admission()
        self.assertIs(body["allowed"], False)
        self.assertEqual(
            body["reasons"],
            ["no_sbom", "no_license", "no_provenance"],
        )

    def test_required_evidence_present_passes_evidence_check(self) -> None:
        self._register(
            evidence_requirements=["sbom", "license", "provenance"],
            license_allowlist=[],
            max_severity="low",
        )
        self._add_sbom()
        self._add_license()
        self._add_provenance()
        _s, _h, body = self._admission()
        self.assertEqual(body["reasons"], [])
        self.assertIs(body["allowed"], True)

    def test_partial_evidence_only_reports_missing_items(self) -> None:
        self._register(license_allowlist=[])
        self._add_sbom()
        self._add_provenance()
        _s, _h, body = self._admission()
        self.assertEqual(body["reasons"], ["no_license"])

    def test_evidence_not_required_is_not_checked(self) -> None:
        self._register(
            evidence_requirements=["sbom"], license_allowlist=[]
        )
        self._add_sbom()
        _s, _h, body = self._admission()
        self.assertEqual(body["reasons"], [])

    def test_missing_signature_alone_reports_no_signature(self) -> None:
        self._register(
            evidence_requirements=["signature"], license_allowlist=[]
        )
        _s, _h, body = self._admission()
        self.assertIs(body["allowed"], False)
        self.assertEqual(body["reasons"], ["no_signature"])

    def test_registered_signature_satisfies_evidence(self) -> None:
        # Registration alone counts; verification plays no part here.
        self._register(
            evidence_requirements=["signature"], license_allowlist=[]
        )
        self._add_signature()
        _s, _h, body = self._admission()
        self.assertEqual(body["reasons"], [])
        self.assertIs(body["allowed"], True)

    def test_signature_orders_after_provenance_in_evidence_group(self) -> None:
        self._register(
            evidence_requirements=[
                "sbom", "license", "provenance", "signature"
            ],
            license_allowlist=[],
        )
        _s, _h, body = self._admission()
        self.assertEqual(
            body["reasons"],
            ["no_sbom", "no_license", "no_provenance", "no_signature"],
        )

    def test_license_denied_when_not_in_allowlist(self) -> None:
        self._register(
            evidence_requirements=[], license_allowlist=["MIT"]
        )
        self._add_license("Apache-2.0")
        _s, _h, body = self._admission()
        self.assertEqual(body["reasons"], ["license_denied"])

    def test_license_denied_when_no_license_declared(self) -> None:
        self._register(
            evidence_requirements=[], license_allowlist=["MIT"]
        )
        _s, _h, body = self._admission()
        self.assertEqual(body["reasons"], ["license_denied"])

    def test_license_in_allowlist_passes(self) -> None:
        self._register(
            evidence_requirements=[], license_allowlist=["Apache-2.0", "MIT"]
        )
        self._add_license("MIT")
        _s, _h, body = self._admission()
        self.assertEqual(body["reasons"], [])

    def test_empty_allowlist_skips_license_check(self) -> None:
        self._register(evidence_requirements=[], license_allowlist=[])
        _s, _h, body = self._admission()
        self.assertEqual(body["reasons"], [])

    def test_severity_at_or_below_ceiling_passes(self) -> None:
        self._register(
            evidence_requirements=[], license_allowlist=[],
            max_severity="high",
        )
        self._add_alert("HIGH")
        self._add_alert("medium")
        self._add_alert("low")
        _s, _h, body = self._admission()
        self.assertEqual(body["reasons"], [])

    def test_severity_above_ceiling_denied_case_insensitively(self) -> None:
        self._register(
            evidence_requirements=[], license_allowlist=[],
            max_severity="HIGH",
        )
        self._add_alert("Critical")
        _s, _h, body = self._admission()
        self.assertEqual(body["reasons"], ["severity_exceeded"])

    def test_severity_exceeded_reported_once(self) -> None:
        self._register(
            evidence_requirements=[], license_allowlist=[],
            max_severity="low",
        )
        self._add_alert("critical")
        self._add_alert("high")
        _s, _h, body = self._admission()
        self.assertEqual(body["reasons"], ["severity_exceeded"])

    def test_combined_reasons_follow_group_order(self) -> None:
        self._register()
        self._add_alert("critical")
        _s, _h, body = self._admission()
        self.assertIs(body["allowed"], False)
        self.assertEqual(
            body["reasons"],
            [
                "no_sbom",
                "no_license",
                "no_provenance",
                "license_denied",
                "severity_exceeded",
            ],
        )

    def test_quarantined_resource_is_state_blocked_and_short_circuits(self) -> None:
        self._register()
        self._add_alert("critical")  # would otherwise add more reasons
        status, _h, _b = call_json(
            "POST",
            f"/resources/{self.resource_id}/lifecycle",
            {"state": "quarantined", "reason": "incident"},
        )
        self.assertEqual(status, "200 OK")

        _s, _h, body = self._admission()
        self.assertIs(body["allowed"], False)
        self.assertEqual(body["reasons"], ["state_blocked"])

    def test_withdrawn_resource_is_state_blocked(self) -> None:
        # Reachable path to withdrawn: released content first, then withdraw.
        resource_id = self._create(EMPTY_DIGEST, name="empty")
        self._register(resource_id=resource_id)
        self._assemble_empty_content(resource_id)
        status, _h, _b = call_json(
            "POST", f"/resources/{resource_id}/lifecycle", {"state": "released"}
        )
        self.assertEqual(status, "200 OK")
        status, _h, _b = call_json(
            "POST",
            f"/resources/{resource_id}/lifecycle",
            {"state": "withdrawn", "reason": "obsolete"},
        )
        self.assertEqual(status, "200 OK")

        _s, _h, body = self._admission(resource_id)
        self.assertIs(body["allowed"], False)
        self.assertEqual(body["reasons"], ["state_blocked"])

    def test_staged_and_released_states_are_not_blocked(self) -> None:
        # Promotion to released requires assembled content, so use a
        # resource whose registered digest matches the empty payload.
        resource_id = self._create(EMPTY_DIGEST, name="releasable")
        self._register(
            resource_id=resource_id,
            evidence_requirements=[], license_allowlist=[]
        )
        _s, _h, body = self._admission(resource_id)
        self.assertEqual(body["reasons"], [])
        self._assemble_empty_content(resource_id)
        call_json(
            "POST",
            f"/resources/{resource_id}/lifecycle",
            {"state": "released"},
        )
        _s, _h, body = self._admission(resource_id)
        self.assertEqual(body["reasons"], [])

    def test_evaluation_is_read_only(self) -> None:
        self._register()
        first_status, _h, first = self._admission()
        second_status, _h, second = self._admission()
        self.assertEqual(first_status, second_status)
        self.assertEqual(first, second)

        # No policy is created for resources without one by evaluating.
        other = self._create(DIGEST_B, name="other")
        call("POST", f"/resources/{other}/admission")
        _s, _h, policies = call_json("GET", "/resources")
        self.assertEqual(
            call_json("GET", f"/resources/{other}/policies")[2]["error"],
            "policy_not_found",
        )
        self.assertEqual(len(policies["resources"]), 2)


if __name__ == "__main__":
    unittest.main()
