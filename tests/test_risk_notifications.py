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
        "CONTENT_LENGTH": str(len(payload)),
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
) -> tuple[str, list[tuple[str, str]], dict[str, object]]:
    status, headers, raw = call(method, path, body, query_string=query_string)
    return status, headers, json.loads(raw.decode("utf-8"))


class EndpointTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        _s, _h, body = call_json(
            "POST",
            "/resources",
            {"name": "r", "category": "code", "digest": DIGEST_A},
        )
        self.resource_id = str(body["id"])
        _s, _h, body = call_json(
            "POST",
            "/resources",
            {"name": "other", "category": "code", "digest": DIGEST_B},
        )
        self.other_id = str(body["id"])

    # --- Risk --------------------------------------------------------------

    def _risk(self, resource_id: str | None = None, **kwargs: object):
        return call_json(
            "GET",
            f"/resources/{self.resource_id if resource_id is None else resource_id}/risk",
            **kwargs,
        )

    def _alert(self, severity: str, *, advisory: str | None = None) -> None:
        call_json(
            "POST",
            f"/resources/{self.resource_id}/vulnerabilities",
            {
                "advisory": advisory if advisory is not None else f"CVE-{severity}",
                "component": "openssl",
                "severity": severity,
                "summary": "a bug",
            },
        )

    def test_risk_fresh_resource_missing_evidence(self) -> None:
        status, headers, body = self._risk()

        self.assertEqual(status, "200 OK")
        self.assertEqual(
            headers[0], ("Content-Type", "application/json; charset=utf-8")
        )
        # No SBOM, license or provenance: 3 * 5 = 15 -> low.
        self.assertEqual(body, {"id": self.resource_id, "score": 15, "level": "low"})

    def test_risk_response_order_and_trailing_newline(self) -> None:
        _status, _headers, raw = call("GET", f"/resources/{self.resource_id}/risk")
        self.assertEqual(
            raw,
            f'{{"id":"{self.resource_id}","score":15,"level":"low"}}\n'.encode(),
        )

    def test_risk_alert_points_and_case_insensitive_severity(self) -> None:
        self._alert("CRITICAL")
        self._alert("high")
        status, _h, body = self._risk()
        self.assertEqual(status, "200 OK")
        # 40 + 25 + 15 missing evidence = 80 -> critical.
        self.assertEqual(body["score"], 80)
        self.assertEqual(body["level"], "critical")

    def test_risk_level_bands(self) -> None:
        # Fill all evidence to isolate alert/state scoring.
        self._add_all_evidence()
        self._alert("low")  # 5 -> low
        self.assertEqual(self._risk()[2]["level"], "low")

    def test_risk_full_evidence_is_zero(self) -> None:
        self._add_all_evidence()
        status, _h, body = self._risk()
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, {"id": self.resource_id, "score": 0, "level": "low"})

    def test_risk_blocked_state_adds_twenty(self) -> None:
        self._add_all_evidence()
        for state in ("quarantined",):
            call_json(
                "POST",
                f"/resources/{self.resource_id}/lifecycle",
                {"state": state, "reason": "suspicious"},
            )
        _s, _h, body = self._risk()
        self.assertEqual(body["score"], 20)
        self.assertEqual(body["level"], "low")

    def test_risk_allowlist_denied_adds_ten(self) -> None:
        self._add_all_evidence(license_id="GPL-3.0")
        call_json(
            "POST",
            f"/resources/{self.resource_id}/policies",
            {
                "name": "p",
                "evidence_requirements": [],
                "license_allowlist": ["MIT"],
                "max_severity": "critical",
            },
        )
        _s, _h, body = self._risk()
        self.assertEqual(body["score"], 10)

    def test_risk_missing_license_with_allowlist(self) -> None:
        # SBOM and provenance present, license missing, non-empty allowlist.
        call_json(
            "POST",
            f"/resources/{self.resource_id}/sbom",
            {"format": "spdx", "components": []},
        )
        call_json(
            "POST",
            f"/resources/{self.resource_id}/provenance",
            {
                "builder": "ci",
                "build_number": "1",
                "source_digest": DIGEST_A,
                "materials": [],
            },
        )
        call_json(
            "POST",
            f"/resources/{self.resource_id}/policies",
            {
                "name": "p",
                "evidence_requirements": [],
                "license_allowlist": ["MIT"],
                "max_severity": "critical",
            },
        )
        _s, _h, body = self._risk()
        # 5 missing license evidence + 10 policy breach = 15.
        self.assertEqual(body["score"], 15)

    def test_risk_empty_allowlist_does_not_penalize(self) -> None:
        self._add_all_evidence(license_id="GPL-3.0")
        call_json(
            "POST",
            f"/resources/{self.resource_id}/policies",
            {
                "name": "p",
                "evidence_requirements": [],
                "license_allowlist": [],
                "max_severity": "critical",
            },
        )
        _s, _h, body = self._risk()
        self.assertEqual(body["score"], 0)

    def test_risk_capped_at_one_hundred(self) -> None:
        self._alert("critical", advisory="CVE-1")
        self._alert("critical", advisory="CVE-2")
        self._alert("critical", advisory="CVE-3")
        call_json(
            "POST",
            f"/resources/{self.resource_id}/lifecycle",
            {"state": "quarantined", "reason": "x"},
        )
        _s, _h, body = self._risk()
        self.assertEqual(body["score"], 100)
        self.assertEqual(body["level"], "critical")

    def test_risk_is_computed_live(self) -> None:
        self.assertEqual(self._risk()[2]["score"], 15)
        self._add_all_evidence()
        self.assertEqual(self._risk()[2]["score"], 0)
        self._alert("medium")
        self.assertEqual(self._risk()[2]["score"], 10)

    def test_risk_unknown_resource_404(self) -> None:
        status, _h, body = call_json("GET", "/resources/deadbeef/risk")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

    def test_risk_empty_or_separator_id_400(self) -> None:
        for path in ("/resources//risk", "/resources/a/b/risk"):
            with self.subTest(path=path):
                status, _h, body = call_json("GET", path)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_risk_query_params_400(self) -> None:
        status, _h, body = self._risk(query_string="x=1")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_risk_method_not_allowed(self) -> None:
        for method in ("POST", "PUT", "DELETE"):
            with self.subTest(method=method):
                status, headers, body = call_json(
                    method, f"/resources/{self.resource_id}/risk", {}
                )
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")
                self.assertIn(("Allow", "GET"), headers)

    # --- Notifications -----------------------------------------------------

    def _notify(
        self,
        payload: object = None,
        *,
        resource_id: str | None = None,
        method: str = "POST",
        query_string: str | None = None,
    ):
        if payload is None:
            payload = {
                "channel": "email",
                "target": "secops@example.invalid",
                "message": "please review",
            }
        return call_json(
            method,
            f"/resources/{self.resource_id if resource_id is None else resource_id}/notifications",
            payload if method != "GET" else None,
            query_string=query_string,
        )

    def _list(self, resource_id: str | None = None, **kwargs: object):
        return call_json(
            "GET",
            f"/resources/{self.resource_id if resource_id is None else resource_id}/notifications",
            **kwargs,
        )

    def test_register_notification_201(self) -> None:
        status, headers, body = self._notify()

        self.assertEqual(status, "201 Created")
        self.assertEqual(
            headers[0], ("Content-Type", "application/json; charset=utf-8")
        )
        self.assertEqual(set(body), {"id", "channel", "target", "message"})
        self.assertIsInstance(body["id"], str)
        self.assertEqual(len(body["id"]), 32)
        int(body["id"], 16)
        self.assertEqual(body["channel"], "email")
        self.assertEqual(body["target"], "secops@example.invalid")
        self.assertEqual(body["message"], "please review")

    def test_notification_response_trailing_newline(self) -> None:
        _status, _headers, raw = call(
            "POST",
            f"/resources/{self.resource_id}/notifications",
            {
                "channel": "email",
                "target": "a@example.invalid",
                "message": "hi",
            },
        )
        self.assertTrue(raw.endswith(b"\n"))

    def test_each_submission_is_independent_and_ordered(self) -> None:
        payload = {
            "channel": "email",
            "target": "a@example.invalid",
            "message": "same",
        }
        _s, _h, first = self._notify(payload)
        _s, _h, second = self._notify(payload)
        self.assertNotEqual(first["id"], second["id"])

        _s, _h, body = self._list()
        records = body["notifications"]
        self.assertEqual([r["id"] for r in records], [first["id"], second["id"]])
        self.assertEqual(len(records), 2)
        for record in records:
            self.assertEqual(record["message"], "same")

    def test_list_empty_collection_is_success(self) -> None:
        status, _h, body = self._list()
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, {"notifications": []})

    def test_notifications_are_scoped_per_resource(self) -> None:
        self._notify({"channel": "c1", "target": "t1", "message": "m1"})
        self._notify(
            {"channel": "c2", "target": "t2", "message": "m2"},
            resource_id=self.other_id,
        )

        _s, _h, body = self._list()
        self.assertEqual([r["channel"] for r in body["notifications"]], ["c1"])
        _s, _h, body = self._list(resource_id=self.other_id)
        self.assertEqual([r["channel"] for r in body["notifications"]], ["c2"])

    def test_notification_unicode_preserved(self) -> None:
        _s, _h, body = self._notify(
            {
                "channel": "webhook",
                "target": "https://example.invalid/hook",
                "message": "需要复核该资源 🔔",
            }
        )
        self.assertEqual(body["message"], "需要复核该资源 🔔")

    def test_notification_length_boundaries_accepted(self) -> None:
        payload = {
            "channel": "中" * 64,
            "target": "中" * 256,
            "message": "中" * 2048,
        }
        status, _h, _body = self._notify(payload)
        self.assertEqual(status, "201 Created")

    def test_notification_missing_body_400(self) -> None:
        status, _h, body = call_json(
            "POST", f"/resources/{self.resource_id}/notifications", b""
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_notification_bad_json_400(self) -> None:
        status, _h, body = call_json(
            "POST", f"/resources/{self.resource_id}/notifications", "{not json"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_notification_bad_utf8_400(self) -> None:
        status, _headers, raw = call(
            "POST",
            f"/resources/{self.resource_id}/notifications",
            b"\xff\xfe{invalid",
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(json.loads(raw.decode("utf-8"))["error"], "invalid_request")

    def test_notification_top_level_array_400(self) -> None:
        status, _h, body = call_json(
            "POST",
            f"/resources/{self.resource_id}/notifications",
            json.dumps(["channel", "target", "message"]),
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_notification_missing_field_400(self) -> None:
        for field in ("channel", "target", "message"):
            with self.subTest(field=field):
                payload = {
                    "channel": "c",
                    "target": "t",
                    "message": "m",
                }
                del payload[field]
                status, _h, body = self._notify(payload)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_notification_unknown_field_400(self) -> None:
        status, _h, body = self._notify(
            {
                "channel": "c",
                "target": "t",
                "message": "m",
                "priority": 1,
            }
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_notification_wrong_type_and_null_400(self) -> None:
        base = {"channel": "c", "target": "t", "message": "m"}
        for field, bad in (
            ("channel", 1),
            ("target", ["t"]),
            ("message", {"m": 1}),
            ("channel", None),
            ("target", None),
            ("message", None),
        ):
            with self.subTest(field=field, bad=bad):
                payload = dict(base)
                payload[field] = bad
                status, _h, body = self._notify(payload)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_notification_empty_string_400(self) -> None:
        for field in ("channel", "target", "message"):
            with self.subTest(field=field):
                payload = {"channel": "c", "target": "t", "message": "m"}
                payload[field] = ""
                status, _h, body = self._notify(payload)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_notification_overlong_fields_400(self) -> None:
        base = {"channel": "中", "target": "中", "message": "中"}
        for field, limit in (
            ("channel", 64),
            ("target", 256),
            ("message", 2048),
        ):
            with self.subTest(field=field):
                payload = dict(base)
                payload[field] = "中" * (limit + 1)
                status, _h, body = self._notify(payload)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_invalid_notification_is_not_stored(self) -> None:
        self._notify({"channel": "c1", "target": "t1", "message": "m1"})
        self._notify({"channel": "c2", "target": "t2"})  # missing message
        self._notify(
            {
                "channel": "c3",
                "target": "t3",
                "message": "m3",
                "extra": True,
            }
        )
        _s, _h, body = self._list()
        self.assertEqual(
            [r["channel"] for r in body["notifications"]], ["c1"]
        )

    def test_notification_unknown_resource_404_and_no_state(self) -> None:
        payload = {"channel": "c", "target": "t", "message": "m"}
        status, _h, body = call_json(
            "POST", "/resources/deadbeef/notifications", payload
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

        status, _h, body = call_json("GET", "/resources/deadbeef/notifications")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

    def test_notification_empty_or_separator_id_400(self) -> None:
        for path in (
            "/resources//notifications",
            "/resources/a/b/notifications",
        ):
            with self.subTest(path=path):
                status, _h, body = call_json(
                    "POST",
                    path,
                    {"channel": "c", "target": "t", "message": "m"},
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_notification_query_params_400(self) -> None:
        payload = {"channel": "c", "target": "t", "message": "m"}
        status, _h, body = self._notify(payload, query_string="x=1")
        self.assertEqual(status, "400 Bad Request")
        status, _h, body = self._list(query_string="x=1")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_notification_method_not_allowed(self) -> None:
        for method in ("PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, headers, body = call_json(
                    method,
                    f"/resources/{self.resource_id}/notifications",
                    {},
                )
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")
                self.assertIn(("Allow", "GET, POST"), headers)

    # --- Helpers -----------------------------------------------------------

    def _add_all_evidence(self, *, license_id: str = "MIT") -> None:
        call_json(
            "POST",
            f"/resources/{self.resource_id}/sbom",
            {"format": "spdx", "components": []},
        )
        call_json(
            "POST",
            f"/resources/{self.resource_id}/license",
            {"spdx_id": license_id},
        )
        call_json(
            "POST",
            f"/resources/{self.resource_id}/provenance",
            {
                "builder": "ci",
                "build_number": "1",
                "source_digest": DIGEST_A,
                "materials": [],
            },
        )


if __name__ == "__main__":
    unittest.main()
