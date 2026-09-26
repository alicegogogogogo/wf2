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
        "name": "default-gate",
        "evidence_requirements": ["sbom", "license"],
        "license_allowlist": ["Apache-2.0", "MIT"],
        "max_severity": "high",
    }
    payload.update(overrides)
    return payload


def alert_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "advisory": "CVE-2026-0001",
        "component": "openssl",
        "severity": "critical",
        "summary": "summary",
    }
    payload.update(overrides)
    return payload


class DefaultPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def _create(self, digest: str = DIGEST_A, name: str = "r") -> str:
        _s, _h, body = call_json(
            "POST",
            "/resources",
            {"name": name, "category": "code", "digest": digest},
        )
        return str(body["id"])

    def _register(
        self, **overrides: object
    ) -> tuple[str, list[tuple[str, str]], dict[str, object]]:
        return call_json("POST", "/policies", policy_payload(**overrides))

    # --- Registration ------------------------------------------------------

    def test_register_returns_201_and_echoes_without_id(self) -> None:
        status, _h, body = self._register()
        self.assertEqual(status, "201 Created")
        self.assertEqual(
            body,
            {
                "name": "default-gate",
                "evidence_requirements": ["sbom", "license"],
                "license_allowlist": ["Apache-2.0", "MIT"],
                "max_severity": "high",
            },
        )
        self.assertNotIn("id", body)

    def test_echo_is_compact_json_with_trailing_newline(self) -> None:
        _s, _h, raw = call("POST", "/policies", policy_payload())
        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(b" ", raw)
        self.assertEqual(raw.count(b"\n"), 1)

    def test_identical_resubmission_is_200_and_idempotent(self) -> None:
        self._register()
        status, _h, body = self._register()
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["name"], "default-gate")
        # Still a single policy; a different payload is still a conflict.
        status, _h, body = self._register(name="other")
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "policy_conflict")

    def test_different_content_conflicts_and_keeps_original(self) -> None:
        self._register()
        status, _h, body = self._register(max_severity="low")
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "policy_conflict")
        status, _h, body = call_json("GET", "/policies")
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["max_severity"], "high")

    def test_conflict_on_reordered_or_changed_lists(self) -> None:
        self._register()
        for changed in (
            policy_payload(license_allowlist=["MIT", "Apache-2.0"]),
            policy_payload(evidence_requirements=["sbom"]),
            policy_payload(license_allowlist=["Apache-2.0"]),
        ):
            status, _h, body = call_json("POST", "/policies", changed)
            self.assertEqual(status, "409 Conflict")
            self.assertEqual(body["error"], "policy_conflict")

    # --- Query -------------------------------------------------------------

    def test_get_before_registration_is_policy_not_found(self) -> None:
        status, _h, body = call_json("GET", "/policies")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "policy_not_found")

    def test_get_returns_the_single_policy(self) -> None:
        self._register()
        status, _h, body = call_json("GET", "/policies")
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["name"], "default-gate")
        self.assertNotIn("id", body)

    # --- Validation --------------------------------------------------------

    def test_missing_or_undecodable_body_is_400(self) -> None:
        for bad in (None, b"", b"{bad", b"\xff\xfe"):
            status, _h, body = call_json("POST", "/policies", bad)
            self.assertEqual(status, "400 Bad Request")
            self.assertEqual(body["error"], "invalid_request")

    def test_non_object_and_unknown_or_missing_fields_are_400(self) -> None:
        status, _h, body = call_json("POST", "/policies", '["not","an","object"]')
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        bad_payloads: list[object] = [
            policy_payload(extra="nope"),
            {k: v for k, v in policy_payload().items() if k != "name"},
            policy_payload(name=""),
        ]
        for bad in bad_payloads:
            status, _h, body = call_json("POST", "/policies", bad)
            self.assertEqual(status, "400 Bad Request")
            self.assertEqual(body["error"], "invalid_request")

    def test_duplicates_out_of_range_and_overlong_values_are_400(self) -> None:
        bad_payloads = [
            policy_payload(evidence_requirements=["sbom", "sbom"]),
            policy_payload(evidence_requirements=["audit"]),
            policy_payload(license_allowlist=["MIT", "MIT"]),
            policy_payload(license_allowlist=[""]),
            policy_payload(max_severity="fatal"),
            policy_payload(name="x" * 257),
        ]
        for bad in bad_payloads:
            status, _h, body = call_json("POST", "/policies", bad)
            self.assertEqual(status, "400 Bad Request")
            self.assertEqual(body["error"], "invalid_request")

    def test_failed_registration_writes_nothing(self) -> None:
        call_json("POST", "/policies", b"{bad")
        call_json("POST", "/policies", policy_payload(max_severity="fatal"))
        status, _h, body = call_json("GET", "/policies")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "policy_not_found")

    def test_query_parameters_are_400_on_both_methods(self) -> None:
        status, _h, body = call_json("GET", "/policies", query_string="a=1")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        status, _h, body = call_json(
            "POST", "/policies", policy_payload(), query_string="a=1"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        # Nothing was written by the rejected POST.
        status, _h, body = call_json("GET", "/policies")
        self.assertEqual(status, "404 Not Found")

    def test_get_with_body_is_400(self) -> None:
        status, _h, body = call_json("GET", "/policies", {"a": 1})
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_other_methods_are_405_with_allow(self) -> None:
        for method in ("PUT", "DELETE", "PATCH"):
            status, headers, body = call_json(method, "/policies")
            self.assertEqual(status, "405 Method Not Allowed")
            self.assertEqual(body["error"], "method_not_allowed")
            self.assertEqual(dict(headers).get("Allow"), "GET, POST")

    # --- Fallback into admission, preview and risk -------------------------

    def test_admission_and_preview_fall_back_to_default(self) -> None:
        resource_id = self._create()
        # Neither resource policy nor default: both entries 404 as before.
        status, _h, body = call_json("POST", f"/resources/{resource_id}/admission")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "policy_not_found")
        status, _h, body = call_json(
            "GET", f"/resources/{resource_id}/admission-preview"
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "policy_not_found")

        self._register()
        status, _h, body = call_json("POST", f"/resources/{resource_id}/admission")
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["allowed"], False)
        self.assertEqual(body["reasons"], ["no_sbom", "no_license", "license_denied"])
        status, _h, body = call_json(
            "GET", f"/resources/{resource_id}/admission-preview"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["allowed"], False)
        self.assertEqual(body["reasons"], ["no_sbom", "no_license", "license_denied"])
        self.assertEqual(body["exempted_count"], 0)

    def test_own_policy_still_wins_over_default(self) -> None:
        resource_id = self._create()
        self._register()
        call_json(
            "POST",
            f"/resources/{resource_id}/policies",
            policy_payload(
                name="own",
                evidence_requirements=[],
                license_allowlist=[],
                max_severity="critical",
            ),
        )
        status, _h, body = call_json("POST", f"/resources/{resource_id}/admission")
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["allowed"], True)
        self.assertEqual(body["reasons"], [])

    def test_preview_exemption_count_stays_per_resource(self) -> None:
        resource_id = self._create()
        self._register(
            evidence_requirements=[], license_allowlist=[], max_severity="low"
        )
        call_json(
            "POST", f"/resources/{resource_id}/vulnerabilities", alert_payload()
        )
        call_json(
            "POST",
            f"/resources/{resource_id}/vulnerability-exceptions",
            {
                "advisory": "CVE-2026-0001",
                "component": "openssl",
                "reason": "accepted risk",
            },
        )
        status, _h, body = call_json(
            "GET", f"/resources/{resource_id}/admission-preview"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["allowed"], True)
        self.assertEqual(body["exempted_count"], 1)
        # The plain admission evaluation still counts the alert.
        status, _h, body = call_json("POST", f"/resources/{resource_id}/admission")
        self.assertEqual(body["allowed"], False)
        self.assertEqual(body["reasons"], ["severity_exceeded"])

    def test_risk_uses_default_allowlist_without_own_policy(self) -> None:
        resource_id = self._create()
        _s, _h, before = call_json("GET", f"/resources/{resource_id}/risk")
        self._register(evidence_requirements=[], max_severity="critical")
        _s, _h, after = call_json("GET", f"/resources/{resource_id}/risk")
        # No license recorded while the default allowlist is non-empty: +10.
        self.assertEqual(after["score"], before["score"] + 10)
        # An own policy with an empty allowlist restores the old score.
        call_json(
            "POST",
            f"/resources/{resource_id}/policies",
            policy_payload(
                name="own",
                evidence_requirements=[],
                license_allowlist=[],
                max_severity="critical",
            ),
        )
        _s, _h, own = call_json("GET", f"/resources/{resource_id}/risk")
        self.assertEqual(own["score"], before["score"])

    def test_resource_delete_keeps_default_policy(self) -> None:
        resource_id = self._create()
        self._register()
        call_json("DELETE", f"/resources/{resource_id}")
        status, _h, body = call_json("GET", "/policies")
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["name"], "default-gate")

    def test_resource_policy_endpoints_unaffected(self) -> None:
        resource_id = self._create()
        self._register()
        # The per-resource policy query does not fall back to the default.
        status, _h, body = call_json("GET", f"/resources/{resource_id}/policies")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "policy_not_found")


if __name__ == "__main__":
    unittest.main()
