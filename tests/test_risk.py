from __future__ import annotations

import hashlib
import io
import json
import unittest

from provenance_api.app import application, reset_state

DIGEST_A = "a" * 64
EMPTY_DIGEST = hashlib.sha256(b"").hexdigest()


def call(
    method: str,
    path: str,
    body: bytes | str | dict[str, object] | None = None,
    *,
    query_string: str | None = None,
    content_type: str | None = "application/json",
    extra_environ: dict[str, object] | None = None,
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
        "CONTENT_LENGTH": str(len(payload)),
    }
    if content_type is not None:
        environ["CONTENT_TYPE"] = content_type
    if extra_environ:
        environ.update(extra_environ)
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


def vulnerability_payload(
    severity: str, advisory: str = "CVE-2026-0001"
) -> dict[str, object]:
    return {
        "advisory": advisory,
        "component": "openssl",
        "severity": severity,
        "summary": "test alert",
    }


class RiskTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        _s, _h, body = call_json(
            "POST",
            "/resources",
            {"name": "r", "category": "code", "digest": DIGEST_A},
        )
        self.resource_id = str(body["id"])

    def _risk(
        self, resource_id: str | None = None, **kwargs: object
    ) -> tuple[str, list[tuple[str, str]], dict[str, object]]:
        return call_json(
            "GET",
            f"/resources/{resource_id or self.resource_id}/risk",
            **kwargs,
        )

    def _add_vulnerability(self, severity: str, advisory: str) -> None:
        status, _h, _b = call_json(
            "POST",
            f"/resources/{self.resource_id}/vulnerabilities",
            vulnerability_payload(severity, advisory),
        )
        self.assertEqual(status, "201 Created")

    def _add_sbom(self) -> None:
        status, _h, _b = call_json(
            "POST",
            f"/resources/{self.resource_id}/sbom",
            {"format": "spdx", "components": []},
        )
        self.assertEqual(status, "201 Created")

    def _add_license(self, spdx_id: str = "Apache-2.0") -> None:
        status, _h, _b = call_json(
            "POST",
            f"/resources/{self.resource_id}/license",
            {"spdx_id": spdx_id},
        )
        self.assertEqual(status, "201 Created")

    def _add_provenance(self) -> None:
        status, _h, _b = call_json(
            "POST",
            f"/resources/{self.resource_id}/provenance",
            {
                "builder": "ci-bot",
                "build_number": "b-1",
                "source_digest": DIGEST_A,
                "materials": [],
            },
        )
        self.assertEqual(status, "201 Created")

    def _add_policy(self, allowlist: list[str]) -> None:
        status, _h, _b = call_json(
            "POST",
            f"/resources/{self.resource_id}/policies",
            {
                "name": "gate",
                "evidence_requirements": [],
                "license_allowlist": allowlist,
                "max_severity": "low",
            },
        )
        self.assertEqual(status, "201 Created")

    def _set_lifecycle(self, state: str, reason: str | None = None) -> None:
        payload: dict[str, object] = {"state": state}
        if reason is not None:
            payload["reason"] = reason
        status, _h, _b = call_json(
            "POST", f"/resources/{self.resource_id}/lifecycle", payload
        )
        self.assertEqual(status, "200 OK")

    # --- Scoring -----------------------------------------------------------

    def test_clean_resource_scores_zero_low(self) -> None:
        self._add_sbom()
        self._add_license()
        self._add_provenance()

        status, _h, body = self._risk()

        self.assertEqual(status, "200 OK")
        self.assertEqual(
            body, {"id": self.resource_id, "score": 0, "level": "low"}
        )

    def test_missing_evidence_adds_five_each(self) -> None:
        # Nothing registered at all: three missing evidence items.
        status, _h, body = self._risk()

        self.assertEqual(status, "200 OK")
        self.assertEqual(body["score"], 15)
        self.assertEqual(body["level"], "low")

    def test_severity_points_per_alert(self) -> None:
        self._add_sbom()
        self._add_license()
        self._add_provenance()
        self._add_vulnerability("CRITICAL", "CVE-1")
        self._add_vulnerability("High", "CVE-2")
        self._add_vulnerability("medium", "CVE-3")
        self._add_vulnerability("LOW", "CVE-4")

        _s, _h, body = self._risk()

        self.assertEqual(body["score"], 40 + 25 + 10 + 5)
        self.assertEqual(body["level"], "critical")

    def test_blocked_state_adds_twenty(self) -> None:
        self._add_sbom()
        self._add_license()
        self._add_provenance()
        self._set_lifecycle("quarantined", "tainted")

        _s, _h, body = self._risk()

        self.assertEqual(body["score"], 20)
        self.assertEqual(body["level"], "low")

    def test_withdrawn_state_also_adds_twenty(self) -> None:
        # released -> withdrawn requires assembled content first; register a
        # dedicated resource whose digest matches the empty byte stream.
        _s, _h, created = call_json(
            "POST",
            "/resources",
            {"name": "empty", "category": "code", "digest": EMPTY_DIGEST},
        )
        resource_id = str(created["id"])
        status, _h, _b = call(
            "POST",
            f"/resources/{resource_id}/chunks/0",
            b"",
            content_type="application/octet-stream",
            extra_environ={
                "HTTP_X_TOTAL_CHUNKS": "1",
                "HTTP_X_CONTENT_DIGEST": EMPTY_DIGEST,
            },
        )
        self.assertEqual(status, "201 Created")
        status, _h, _b = call_json("POST", f"/resources/{resource_id}/assemble")
        self.assertEqual(status, "201 Created")
        for state, reason in (("released", None), ("withdrawn", "recall")):
            payload: dict[str, object] = {"state": state}
            if reason is not None:
                payload["reason"] = reason
            status, _h, _b = call_json(
                "POST", f"/resources/{resource_id}/lifecycle", payload
            )
            self.assertEqual(status, "200 OK")

        _s, _h, body = self._risk(resource_id)

        # 20 for the withdrawn state + 15 for the three missing evidence
        # items (no SBOM, license or provenance registered).
        self.assertEqual(body["score"], 35)
        self.assertEqual(body["level"], "medium")

    def test_returning_to_staged_clears_state_points(self) -> None:
        self._add_sbom()
        self._add_license()
        self._add_provenance()
        self._set_lifecycle("quarantined", "tainted")
        self._set_lifecycle("staged")

        _s, _h, body = self._risk()

        self.assertEqual(body["score"], 0)

    def test_allowlist_miss_adds_ten(self) -> None:
        self._add_sbom()
        self._add_license("GPL-3.0")
        self._add_provenance()
        self._add_policy(["Apache-2.0", "MIT"])

        _s, _h, body = self._risk()

        self.assertEqual(body["score"], 10)
        self.assertEqual(body["level"], "low")

    def test_allowlist_miss_without_license_adds_ten(self) -> None:
        self._add_sbom()
        self._add_provenance()
        self._add_policy(["Apache-2.0"])

        _s, _h, body = self._risk()

        # 5 for the missing license + 10 for the allowlist miss.
        self.assertEqual(body["score"], 15)

    def test_empty_allowlist_imposes_no_license_points(self) -> None:
        self._add_sbom()
        self._add_license("GPL-3.0")
        self._add_provenance()
        self._add_policy([])

        _s, _h, body = self._risk()

        self.assertEqual(body["score"], 0)

    def test_score_is_capped_at_one_hundred(self) -> None:
        self._add_vulnerability("critical", "CVE-1")
        self._add_vulnerability("critical", "CVE-2")
        self._add_vulnerability("critical", "CVE-3")
        self._set_lifecycle("quarantined", "tainted")

        _s, _h, body = self._risk()

        # 3*40 + 15 (missing evidence) + 20 (state) = 155, capped at 100.
        self.assertEqual(body["score"], 100)
        self.assertEqual(body["level"], "critical")

    def test_level_thresholds(self) -> None:
        # 25 points exactly -> medium (one high alert, nothing else missing).
        self._add_sbom()
        self._add_license()
        self._add_provenance()
        self._add_vulnerability("high", "CVE-1")
        _s, _h, body = self._risk()
        self.assertEqual((body["score"], body["level"]), (25, "medium"))

    def test_response_has_trailing_newline(self) -> None:
        _s, _h, raw = call("GET", f"/resources/{self.resource_id}/risk")
        self.assertTrue(raw.endswith(b"\n"))

    # --- Errors ------------------------------------------------------------

    def test_unknown_resource_returns_404(self) -> None:
        status, _h, body = self._risk("no-such-resource")

        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

    def test_id_with_separator_returns_400(self) -> None:
        status, _h, body = call_json("GET", "/resources/a/b/risk")

        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_query_parameters_return_400(self) -> None:
        status, _h, body = self._risk(query_string="severity=high")

        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_non_get_methods_return_405(self) -> None:
        for method in ("POST", "PUT", "DELETE"):
            status, headers, body = call_json(
                method, f"/resources/{self.resource_id}/risk"
            )
            self.assertEqual(status, "405 Method Not Allowed")
            self.assertEqual(body["error"], "method_not_allowed")
            self.assertIn(("Allow", "GET"), headers)


if __name__ == "__main__":
    unittest.main()
