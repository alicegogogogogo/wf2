from __future__ import annotations

import io
import json
import unittest

from provenance_api.app import application, reset_state

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64


def call(
    method: str,
    path: str,
    body: bytes | str | dict[str, object] | None = None,
    *,
    query_string: str | None = None,
    content_type: str | None = "application/json",
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
        environ["CONTENT_LENGTH"] = str(len(payload))
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
        "name": "global-gate",
        "evidence_requirements": ["sbom", "license"],
        "license_allowlist": ["Apache-2.0", "MIT"],
        "max_severity": "high",
    }
    payload.update(overrides)
    return payload


class GlobalPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def _create_resource(self, digest: str = DIGEST_A, name: str = "r") -> str:
        _s, _h, body = call_json(
            "POST",
            "/resources",
            {"name": name, "category": "code", "digest": digest},
        )
        return str(body["id"])

    def _register_global(
        self, **overrides: object
    ) -> tuple[str, list[tuple[str, str]], dict[str, object]]:
        return call_json("POST", "/policies", policy_payload(**overrides))

    # --- Registration ------------------------------------------------------

    def test_register_returns_201_and_echoes_without_resource_id(self) -> None:
        status, headers, body = self._register_global()

        self.assertEqual(status, "201 Created")
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )
        self.assertEqual(
            body,
            {
                "name": "global-gate",
                "evidence_requirements": ["sbom", "license"],
                "license_allowlist": ["Apache-2.0", "MIT"],
                "max_severity": "high",
            },
        )
        self.assertNotIn("id", body)

    def test_response_is_compact_with_stable_key_order_and_newline(self) -> None:
        status, _headers, raw = call("POST", "/policies", policy_payload())

        self.assertEqual(status, "201 Created")
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        text = raw.decode("utf-8").rstrip("\n")
        self.assertNotIn(" ", text)
        self.assertLess(text.index('"name"'), text.index('"evidence_requirements"'))
        self.assertLess(
            text.index('"evidence_requirements"'),
            text.index('"license_allowlist"'),
        )
        self.assertLess(
            text.index('"license_allowlist"'), text.index('"max_severity"')
        )

    def test_max_severity_is_case_insensitive_and_stored_lowercase(self) -> None:
        _s, _h, body = self._register_global(max_severity="HIGH")
        self.assertEqual(body["max_severity"], "high")

    def test_identical_resubmission_returns_200_and_stays_idempotent(self) -> None:
        first_status, _h, first = self._register_global()
        self.assertEqual(first_status, "201 Created")

        status, _h, body = self._register_global()
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, first)

        status, _h, fetched = call_json("GET", "/policies")
        self.assertEqual(status, "200 OK")
        self.assertEqual(fetched, first)

    def test_different_content_conflicts_and_keeps_original(self) -> None:
        _s, _h, original = self._register_global()

        for overrides in (
            {"name": "other"},
            {"evidence_requirements": ["sbom"]},
            {"license_allowlist": ["MIT"]},
            {"max_severity": "critical"},
            {"license_allowlist": ["MIT", "Apache-2.0"]},
        ):
            with self.subTest(overrides=overrides):
                status, _h, body = self._register_global(**overrides)
                self.assertEqual(status, "409 Conflict")
                self.assertEqual(body["error"], "policy_conflict")

        status, _h, fetched = call_json("GET", "/policies")
        self.assertEqual(status, "200 OK")
        self.assertEqual(fetched, original)

    # --- Query ---------------------------------------------------------------

    def test_get_before_registration_is_not_found(self) -> None:
        status, _h, body = call_json("GET", "/policies")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "policy_not_found")

    def test_get_returns_the_single_global_policy(self) -> None:
        _s, _h, registered = self._register_global()
        status, _h, body = call_json("GET", "/policies")
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, registered)

    # --- Validation ------------------------------------------------------------

    def test_invalid_bodies_return_400_and_write_nothing(self) -> None:
        bad_bodies: list[bytes | str | dict[str, object] | None] = [
            None,
            b"",
            "not json",
            '["array"]',
            {"name": "x"},  # missing fields
            {**policy_payload(), "extra": 1},  # unknown field
            policy_payload(name=""),
            policy_payload(name="x" * 257),
            policy_payload(evidence_requirements=["sbom", "sbom"]),
            policy_payload(evidence_requirements=["audit"]),
            policy_payload(license_allowlist=["MIT", "MIT"]),
            policy_payload(license_allowlist=[""]),
            policy_payload(max_severity="fatal"),
        ]
        for bad in bad_bodies:
            with self.subTest(bad=bad):
                status, _h, body = call_json("POST", "/policies", bad)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

        status, _h, body = call_json("GET", "/policies")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "policy_not_found")

    def test_get_with_body_is_rejected(self) -> None:
        self._register_global()
        status, _h, body = call_json("GET", "/policies", policy_payload())
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_query_parameters_are_rejected_on_both_methods(self) -> None:
        status, _h, body = call_json(
            "POST", "/policies", policy_payload(), query_string="x=1"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

        status, _h, body = call_json("GET", "/policies", query_string="x=1")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

        # Nothing was written by the rejected registration attempt.
        status, _h, body = call_json("GET", "/policies")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "policy_not_found")

    def test_other_methods_return_405_with_allow(self) -> None:
        for method in ("PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, headers, body = call_json(
                    method, "/policies", policy_payload()
                )
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")
                self.assertIn(("Allow", "GET, POST"), headers)

        status, _h, body = call_json("GET", "/policies")
        self.assertEqual(status, "404 Not Found")

    # --- Admission evaluation and preview fall back to the global policy -------

    def _add_sbom(self, resource_id: str) -> None:
        call_json(
            "POST",
            f"/resources/{resource_id}/sbom",
            {"format": "spdx", "components": []},
        )

    def _add_license(self, resource_id: str, spdx_id: str = "Apache-2.0") -> None:
        call_json(
            "POST",
            f"/resources/{resource_id}/license",
            {"spdx_id": spdx_id},
        )

    def _add_alert(self, resource_id: str, severity: str) -> None:
        call_json(
            "POST",
            f"/resources/{resource_id}/vulnerabilities",
            {
                "advisory": f"CVE-{severity}",
                "component": "openssl",
                "severity": severity,
                "summary": "summary",
            },
        )

    def test_admission_uses_global_policy_when_resource_has_none(self) -> None:
        resource_id = self._create_resource()
        self._register_global()

        # The global policy requires sbom and license; neither is present,
        # and the non-empty allowlist denies the undeclared license.
        status, _h, body = call_json(
            "POST", f"/resources/{resource_id}/admission"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["allowed"], False)
        self.assertEqual(
            body["reasons"], ["no_sbom", "no_license", "license_denied"]
        )

        self._add_sbom(resource_id)
        self._add_license(resource_id)
        status, _h, body = call_json(
            "POST", f"/resources/{resource_id}/admission"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, {"id": resource_id, "allowed": True, "reasons": []})

    def test_admission_without_any_policy_is_still_not_found(self) -> None:
        resource_id = self._create_resource()
        status, _h, body = call_json(
            "POST", f"/resources/{resource_id}/admission"
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "policy_not_found")

    def test_resource_policy_takes_precedence_over_global(self) -> None:
        resource_id = self._create_resource()
        self._register_global()
        # The resource's own policy requires nothing and allows everything.
        call_json(
            "POST",
            f"/resources/{resource_id}/policies",
            policy_payload(
                name="own", evidence_requirements=[], license_allowlist=[]
            ),
        )

        status, _h, body = call_json(
            "POST", f"/resources/{resource_id}/admission"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, {"id": resource_id, "allowed": True, "reasons": []})

    def test_admission_preview_uses_global_policy(self) -> None:
        resource_id = self._create_resource()
        self._register_global()
        self._add_sbom(resource_id)
        self._add_license(resource_id)
        self._add_alert(resource_id, "critical")

        status, _h, body = call_json(
            "GET", f"/resources/{resource_id}/admission-preview"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["allowed"], False)
        self.assertEqual(body["reasons"], ["severity_exceeded"])
        self.assertEqual(body["exempted_count"], 0)

        # Exempting the alert restores admission under the global policy and
        # the exempted count still only reflects this resource's exemptions.
        call_json(
            "POST",
            f"/resources/{resource_id}/vulnerability-exceptions",
            {
                "advisory": "CVE-critical",
                "component": "openssl",
                "reason": "accepted risk",
            },
        )
        status, _h, body = call_json(
            "GET", f"/resources/{resource_id}/admission-preview"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["allowed"], True)
        self.assertEqual(body["reasons"], [])
        self.assertEqual(body["exempted_count"], 1)

    def test_admission_preview_without_any_policy_is_still_not_found(self) -> None:
        resource_id = self._create_resource()
        status, _h, body = call_json(
            "GET", f"/resources/{resource_id}/admission-preview"
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "policy_not_found")

    # --- Risk scoring ----------------------------------------------------------

    def test_risk_uses_global_allowlist_when_resource_has_no_policy(self) -> None:
        resource_id = self._create_resource()
        self._add_license(resource_id, "GPL-3.0")

        _s, _h, before = call_json("GET", f"/resources/{resource_id}/risk")

        self._register_global()
        _s, _h, after = call_json("GET", f"/resources/{resource_id}/risk")

        # GPL-3.0 is outside the global allowlist: +10 license-denied points.
        self.assertEqual(after["score"], before["score"] + 10)

    def test_risk_ignores_global_allowlist_when_resource_has_own_policy(self) -> None:
        resource_id = self._create_resource()
        self._add_license(resource_id, "GPL-3.0")
        call_json(
            "POST",
            f"/resources/{resource_id}/policies",
            policy_payload(
                name="own", evidence_requirements=[], license_allowlist=[]
            ),
        )
        _s, _h, before = call_json("GET", f"/resources/{resource_id}/risk")

        self._register_global()
        _s, _h, after = call_json("GET", f"/resources/{resource_id}/risk")

        self.assertEqual(after["score"], before["score"])

    # --- Isolation ----------------------------------------------------------------

    def test_global_policy_survives_resource_delete(self) -> None:
        resource_id = self._create_resource()
        self._register_global()
        call("DELETE", f"/resources/{resource_id}")

        status, _h, body = call_json("GET", "/policies")
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["name"], "global-gate")

    def test_health_and_resource_policy_endpoints_are_unchanged(self) -> None:
        status, _h, raw = call("GET", "/health")
        self.assertEqual(status, "200 OK")
        self.assertEqual(json.loads(raw.decode("utf-8")), {"status": "ok"})

        resource_id = self._create_resource()
        status, _h, body = call_json(
            "GET", f"/resources/{resource_id}/policies"
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "policy_not_found")


if __name__ == "__main__":
    unittest.main()
