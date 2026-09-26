from __future__ import annotations

import io
import json
import unittest

from provenance_api.app import application, reset_state

PATH = "/admission-preview"

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64


def call(
    method: str,
    path: str = PATH,
    body: bytes | str | dict[str, object] | None = None,
    *,
    query_string: str | None = None,
    content_type: str | None = None,
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
    advisory: str = "CVE-2026-0001",
    component: str = "openssl",
    severity: str = "critical",
) -> dict[str, object]:
    return {
        "advisory": advisory,
        "component": component,
        "severity": severity,
        "summary": "summary",
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


def exception_payload(
    advisory: str = "CVE-2026-0001",
    component: str = "openssl",
    reason: str = "accepted risk",
) -> dict[str, object]:
    return {"advisory": advisory, "component": component, "reason": reason}


class GlobalAdmissionPreviewTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def _create(self, digest: str, name: str) -> str:
        _s, _h, body = call_json(
            "POST",
            "/resources",
            {"name": name, "category": "code", "digest": digest},
        )
        return str(body["id"])  # type: ignore[index]

    def _add_alert(
        self,
        resource_id: str,
        advisory: str,
        component: str = "openssl",
        severity: str = "critical",
    ) -> str:
        _s, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/vulnerabilities",
            alert_payload(
                advisory=advisory, component=component, severity=severity
            ),
        )
        return str(body["id"])  # type: ignore[index]

    def _register_policy(
        self, resource_id: str, **overrides: object
    ) -> None:
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/policies",
            policy_payload(**overrides),
        )
        self.assertIn(status, ("201 Created", "200 OK"), body)

    def _register_default_policy(self, **overrides: object) -> None:
        status, _h, body = call_json(
            "POST", "/policies", policy_payload(**overrides)
        )
        self.assertIn(status, ("201 Created", "200 OK"), body)

    def _exempt(
        self,
        resource_id: str,
        advisory: str,
        component: str = "openssl",
        reason: str = "accepted risk",
    ) -> str:
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/vulnerability-exceptions",
            exception_payload(
                advisory=advisory, component=component, reason=reason
            ),
        )
        self.assertEqual(status, "201 Created", body)
        return str(body["id"])  # type: ignore[index]

    def _summary(self) -> list[dict[str, object]]:
        status, headers, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )
        self.assertTrue(raw.endswith(b"\n"))
        body = json.loads(raw)
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

    def test_entry_key_order_matches_single_preview(self) -> None:
        resource_id = self._create(DIGEST_A, "r1")
        self._register_policy(resource_id)

        status, _h, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        text = raw.decode("utf-8").rstrip("\n")
        # Compact UTF-8 JSON: no added whitespace.
        self.assertNotIn(" ", text)
        self.assertLess(text.index('"id"'), text.index('"allowed"'))
        self.assertLess(text.index('"allowed"'), text.index('"reasons"'))
        self.assertLess(text.index('"reasons"'), text.index('"exempted_count"'))
        self.assertEqual(
            json.loads(text),
            [
                {
                    "id": resource_id,
                    "allowed": True,
                    "reasons": [],
                    "exempted_count": 0,
                }
            ],
        )

    def test_entries_unfold_in_resource_registration_order(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        r3 = self._create(DIGEST_C, "r3")
        # Policies registered in a different order than the resources.
        self._register_policy(r3)
        self._register_policy(r1)
        self._register_policy(r2)

        summary = self._summary()
        self.assertEqual([item["id"] for item in summary], [r1, r2, r3])

    def test_each_resource_uses_its_own_policy(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        # r1 tolerates critical; r2 rejects anything above low.
        self._register_policy(r1, max_severity="critical")
        self._register_policy(r2, max_severity="low")
        self._add_alert(r1, "CVE-1", severity="critical")
        self._add_alert(r2, "CVE-2", severity="high")

        summary = self._summary()
        self.assertEqual(len(summary), 2)
        self.assertIs(summary[0]["allowed"], True)
        self.assertEqual(summary[0]["reasons"], [])
        self.assertIs(summary[1]["allowed"], False)
        self.assertEqual(summary[1]["reasons"], ["severity_exceeded"])

    def test_resource_uses_global_default_without_own_policy(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        self._register_policy(r1, max_severity="critical")
        self._register_default_policy(max_severity="low")
        self._add_alert(r1, "CVE-1", severity="critical")
        self._add_alert(r2, "CVE-2", severity="high")

        summary = self._summary()
        # r1 follows its own (critical) policy; r2 falls back to the global
        # default (low) policy and is denied.
        self.assertEqual(
            summary,
            [
                {"id": r1, "allowed": True, "reasons": [], "exempted_count": 0},
                {
                    "id": r2,
                    "allowed": False,
                    "reasons": ["severity_exceeded"],
                    "exempted_count": 0,
                },
            ],
        )

    # --- Missing policy entry ---------------------------------------------

    def test_resource_without_any_policy_still_gets_entry(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        self._register_policy(r1, max_severity="high")
        # r2 has neither its own policy nor a global default; the summary
        # still succeeds and reports the policy_not_found entry for it.
        self._add_alert(r2, "CVE-1", severity="critical")

        summary = self._summary()
        self.assertEqual(len(summary), 2)
        self.assertIs(summary[0]["allowed"], True)
        self.assertEqual(summary[0]["reasons"], [])
        self.assertIsNone(summary[1]["allowed"])
        self.assertEqual(summary[1]["reasons"], ["policy_not_found"])
        self.assertEqual(summary[1]["exempted_count"], 0)
        self.assertEqual(set(summary[1]), {"id", "allowed", "reasons", "exempted_count"})

    def test_policy_not_found_entry_keeps_truthful_exempted_count(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        self._add_alert(r1, "CVE-1", severity="critical")
        self._add_alert(r1, "CVE-2", component="zlib", severity="high")
        self._exempt(r1, "CVE-1")

        # No resource policy and no global default policy.
        summary = self._summary()
        self.assertEqual(
            summary,
            [
                {
                    "id": r1,
                    "allowed": None,
                    "reasons": ["policy_not_found"],
                    "exempted_count": 1,
                }
            ],
        )

        # Registering a default policy recomputes the same entry into a
        # normal preview without changing the exemption tally.
        self._register_default_policy(max_severity="low")
        summary = self._summary()
        self.assertIs(summary[0]["allowed"], False)
        self.assertEqual(summary[0]["reasons"], ["severity_exceeded"])
        self.assertEqual(summary[0]["exempted_count"], 1)

    # --- Exemption semantics ----------------------------------------------

    def test_exemption_count_and_severity_match_single_preview(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        self._register_policy(r1, max_severity="high")
        self._add_alert(r1, "CVE-1", severity="critical")
        self._add_alert(r1, "CVE-2", severity="critical")
        self._add_alert(r1, "CVE-3", severity="low")
        self._exempt(r1, "CVE-1")
        self._exempt(r1, "CVE-3")

        _s, _h, single = call_json(
            "GET", f"/resources/{r1}/admission-preview"
        )
        summary = self._summary()
        self.assertEqual(summary, [single])
        self.assertIs(summary[0]["allowed"], False)
        self.assertEqual(summary[0]["reasons"], ["severity_exceeded"])
        self.assertEqual(summary[0]["exempted_count"], 2)

    def test_exempted_count_is_per_resource(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        self._register_policy(r1)
        self._register_policy(r2)
        # Identical advisory/component on both resources: an exemption on r1
        # must never count toward r2's entry.
        self._add_alert(r1, "CVE-1", severity="low")
        self._add_alert(r2, "CVE-1", severity="low")
        self._exempt(r1, "CVE-1")

        summary = self._summary()
        self.assertEqual(summary[0]["exempted_count"], 1)
        self.assertEqual(summary[1]["exempted_count"], 0)

    # --- Recomputation -----------------------------------------------------

    def test_recomputes_after_exemption_change(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        self._register_policy(r1, max_severity="high")
        self._add_alert(r1, "CVE-1", severity="critical")
        self.assertFalse(self._summary()[0]["allowed"])

        exemption_id = self._exempt(r1, "CVE-1")
        summary = self._summary()
        self.assertIs(summary[0]["allowed"], True)
        self.assertEqual(summary[0]["exempted_count"], 1)

        status, _h, _b = call(
            "DELETE", f"/resources/{r1}/vulnerability-exceptions/{exemption_id}"
        )
        self.assertEqual(status, "200 OK")
        summary = self._summary()
        self.assertIs(summary[0]["allowed"], False)
        self.assertEqual(summary[0]["exempted_count"], 0)

    def test_recomputes_after_alert_change(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        self._register_policy(r1, max_severity="high")
        alert_id = self._add_alert(r1, "CVE-1", severity="critical")
        self.assertFalse(self._summary()[0]["allowed"])

        status, _h, _b = call(
            "DELETE", f"/resources/{r1}/vulnerabilities/{alert_id}"
        )
        self.assertEqual(status, "200 OK")
        self.assertIs(self._summary()[0]["allowed"], True)

    def test_recomputes_after_lifecycle_transition(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        self._register_policy(r1, max_severity="critical")
        self.assertIs(self._summary()[0]["allowed"], True)

        status, _h, _b = call_json(
            "POST",
            f"/resources/{r1}/lifecycle",
            {"state": "quarantined", "reason": "incident"},
        )
        self.assertEqual(status, "200 OK")
        summary = self._summary()
        self.assertIs(summary[0]["allowed"], False)
        self.assertEqual(summary[0]["reasons"], ["state_blocked"])

    def test_resource_deregistration_removes_its_entry(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        self._register_policy(r1)
        self._register_policy(r2)

        status, _h, _b = call("DELETE", f"/resources/{r1}")
        self.assertEqual(status, "200 OK")
        self.assertEqual([item["id"] for item in self._summary()], [r2])

    def test_view_is_read_only(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        self._register_policy(r1, max_severity="high")
        self._add_alert(r1, "CVE-1", severity="critical")
        first_status, _h, first = call("GET", PATH)
        second_status, _h, second = call("GET", PATH)
        self.assertEqual(first_status, second_status)
        self.assertEqual(first, second)

    # --- Errors ------------------------------------------------------------

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

    def test_query_parameters_rejected(self) -> None:
        self._create(DIGEST_A, "r1")
        for query in ("bogus=1", "x=", "focus=abc", "limit=10"):
            with self.subTest(query=query):
                status, _h, body = call_json(
                    "GET", PATH, query_string=query
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_non_empty_or_malformed_body_rejected(self) -> None:
        self._create(DIGEST_A, "r1")
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
        # Omitted Content-Length and an explicit zero length are both fine.
        status, _h, raw = call("GET", PATH, omit_content_length=True)
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

        status, _h, raw = call("GET", PATH, body=b"", content_length=0)
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

        # An empty-string Content-Length (as some WSGI servers seed it) is
        # treated the same as an omitted header.
        status, _h, raw = call("GET", PATH, body=b"", content_length="")
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

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
