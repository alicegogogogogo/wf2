from __future__ import annotations

import io
import json
import unittest

from provenance_api.app import application, reset_state, store

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
    elif isinstance(body, str):
        payload = body.encode("utf-8")
    else:
        payload = body
    environ: dict[str, object] = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "CONTENT_LENGTH": str(len(payload)),
        "wsgi.input": io.BytesIO(payload),
    }
    if query_string is not None:
        environ["QUERY_STRING"] = query_string
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
    status, headers, raw = call(
        method, path, body, query_string=query_string
    )
    return status, headers, json.loads(raw.decode("utf-8"))


def create_resource(digest: str = DIGEST_A) -> str:
    status, _headers, body = call_json(
        "POST",
        "/resources",
        {
            "name": "lib-" + digest[:4],
            "category": "code",
            "digest": digest,
        },
    )
    assert status == "201 Created", body
    return str(body["id"])


def alert(
    advisory_id: str = "CVE-2026-0001",
    component: str = "widget",
    severity: str = "high",
    summary: str = "A summary.",
    **extra: object,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "advisory_id": advisory_id,
        "component": component,
        "severity": severity,
        "summary": summary,
    }
    payload.update(extra)
    return payload


class VulnerabilityRegistrationTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.resource_id = create_resource()

    def test_register_returns_six_fields_in_order(self) -> None:
        status, headers, raw = call(
            "POST",
            f"/resources/{self.resource_id}/vulnerabilities",
            alert(),
        )

        self.assertEqual(status, "201 Created")
        self.assertEqual(
            headers[0], ("Content-Type", "application/json; charset=utf-8")
        )
        self.assertTrue(raw.endswith(b"\n"))
        body = json.loads(raw.decode("utf-8"))
        self.assertEqual(
            list(body),
            [
                "id",
                "advisory_id",
                "component",
                "severity",
                "summary",
                "fix_version",
            ],
        )
        self.assertEqual(len(body["id"]), 32)
        self.assertEqual(body["advisory_id"], "CVE-2026-0001")
        self.assertEqual(body["component"], "widget")
        self.assertEqual(body["severity"], "high")
        self.assertEqual(body["summary"], "A summary.")
        self.assertIsNone(body["fix_version"])

    def test_fix_version_is_echoed_when_provided(self) -> None:
        status, _headers, body = call_json(
            "POST",
            f"/resources/{self.resource_id}/vulnerabilities",
            alert(fix_version="1.2.3"),
        )
        self.assertEqual(status, "201 Created")
        self.assertEqual(body["fix_version"], "1.2.3")

    def test_severity_accepted_case_insensitively_and_stored_lowercase(
        self,
    ) -> None:
        status, _headers, body = call_json(
            "POST",
            f"/resources/{self.resource_id}/vulnerabilities",
            alert(severity="CRITICAL"),
        )
        self.assertEqual(status, "201 Created")
        self.assertEqual(body["severity"], "critical")

    def test_alerts_kept_in_submission_order(self) -> None:
        call_json(
            "POST",
            f"/resources/{self.resource_id}/vulnerabilities",
            alert(advisory_id="ADV-1", severity="low"),
        )
        call_json(
            "POST",
            f"/resources/{self.resource_id}/vulnerabilities",
            alert(advisory_id="ADV-2", severity="high"),
        )

        status, _headers, body = call_json(
            "GET", f"/resources/{self.resource_id}/vulnerabilities"
        )
        self.assertEqual(status, "200 OK")
        entries = body["vulnerabilities"]
        self.assertEqual([e["advisory_id"] for e in entries], ["ADV-1", "ADV-2"])

    def test_empty_collection_is_success(self) -> None:
        status, _headers, raw = call(
            "GET", f"/resources/{self.resource_id}/vulnerabilities"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b'{"vulnerabilities":[]}\n')

    def test_same_pair_scoped_per_resource(self) -> None:
        other_id = create_resource(DIGEST_B)
        status, _headers, body = call_json(
            "POST", f"/resources/{other_id}/vulnerabilities", alert()
        )
        self.assertEqual(status, "201 Created")
        self.assertEqual(body["advisory_id"], "CVE-2026-0001")

    def test_same_advisory_different_component_is_distinct(self) -> None:
        first = call_json(
            "POST",
            f"/resources/{self.resource_id}/vulnerabilities",
            alert(component="one"),
        )
        second = call_json(
            "POST",
            f"/resources/{self.resource_id}/vulnerabilities",
            alert(component="two"),
        )
        self.assertEqual(first[0], "201 Created")
        self.assertEqual(second[0], "201 Created")


class VulnerabilityDuplicateTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.resource_id = create_resource()
        self.first = call_json(
            "POST",
            f"/resources/{self.resource_id}/vulnerabilities",
            alert(severity="low", summary="original"),
        )
        self.assertEqual(self.first[0], "201 Created")

    def test_duplicate_advisory_and_component_conflicts(self) -> None:
        status, _headers, body = call_json(
            "POST",
            f"/resources/{self.resource_id}/vulnerabilities",
            alert(severity="high", summary="changed", fix_version="9.9.9"),
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "duplicate_vulnerability")

        status, _headers, body = call_json(
            "GET", f"/resources/{self.resource_id}/vulnerabilities"
        )
        entries = body["vulnerabilities"]
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["severity"], "low")
        self.assertEqual(entries[0]["summary"], "original")
        self.assertIsNone(entries[0]["fix_version"])
        self.assertEqual(entries[0]["id"], self.first[2]["id"])


class VulnerabilityFilterTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.resource_id = create_resource()
        for advisory_id, severity in (
            ("ADV-1", "low"),
            ("ADV-2", "high"),
            ("ADV-3", "HIGH"),
            ("ADV-4", "medium"),
        ):
            status, _headers, _body = call_json(
                "POST",
                f"/resources/{self.resource_id}/vulnerabilities",
                alert(advisory_id=advisory_id, severity=severity),
            )
            self.assertEqual(status, "201 Created")

    def test_filter_is_case_insensitive_and_preserves_order(self) -> None:
        status, _headers, body = call_json(
            "GET",
            f"/resources/{self.resource_id}/vulnerabilities",
            query_string="severity=HiGh",
        )
        self.assertEqual(status, "200 OK")
        entries = body["vulnerabilities"]
        self.assertEqual(
            [(e["advisory_id"], e["severity"]) for e in entries],
            [("ADV-2", "high"), ("ADV-3", "high")],
        )

    def test_filter_with_no_match_is_empty(self) -> None:
        status, _headers, body = call_json(
            "GET",
            f"/resources/{self.resource_id}/vulnerabilities",
            query_string="severity=critical",
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["vulnerabilities"], [])

    def test_invalid_severity_query(self) -> None:
        for query_string in ("severity=", "severity=urgent", "severity=high&severity=low"):
            status, _headers, body = call_json(
                "GET",
                f"/resources/{self.resource_id}/vulnerabilities",
                query_string=query_string,
            )
            self.assertEqual(status, "400 Bad Request", query_string)
            self.assertEqual(body["error"], "invalid_request")

    def test_unknown_query_parameter(self) -> None:
        status, _headers, body = call_json(
            "GET",
            f"/resources/{self.resource_id}/vulnerabilities",
            query_string="severity=high&limit=1",
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")


class VulnerabilityValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.resource_id = create_resource()
        self.path = f"/resources/{self.resource_id}/vulnerabilities"

    def post(self, body: object) -> tuple[str, dict[str, object]]:
        status, _headers, parsed = call_json("POST", self.path, body)
        return status, parsed

    def assert_invalid(self, body: object) -> None:
        status, parsed = self.post(body)
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(parsed["error"], "invalid_request")

    def test_empty_body(self) -> None:
        status, _headers, body = call("POST", self.path, b"")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(json.loads(body)["error"], "invalid_request")

    def test_bad_utf8(self) -> None:
        status, _headers, body = call(
            "POST", self.path, b"\xff\xfe{\"advisory_id\":"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(json.loads(body)["error"], "invalid_request")

    def test_malformed_json(self) -> None:
        status, _headers, body = call("POST", self.path, "{not json")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(json.loads(body)["error"], "invalid_request")

    def test_top_level_not_object(self) -> None:
        for body in ([1, 2], "string", 42, True, None):
            status, _headers, raw = call(
                "POST", self.path, json.dumps(body)
            )
            self.assertEqual(status, "400 Bad Request", body)
            self.assertEqual(json.loads(raw)["error"], "invalid_request")

    def test_missing_fields(self) -> None:
        for field in ("advisory_id", "component", "severity", "summary"):
            payload = alert()
            del payload[field]
            self.assert_invalid(payload)

    def test_wrong_types_and_empty_values(self) -> None:
        for field in ("advisory_id", "component", "severity", "summary"):
            for bad in (1, True, ["x"], None, ""):
                payload = alert()
                payload[field] = bad
                self.assert_invalid(payload)

    def test_unknown_field(self) -> None:
        payload = alert()
        payload["extra"] = "nope"
        self.assert_invalid(payload)

    def test_illegal_severity(self) -> None:
        self.assert_invalid(alert(severity="urgent"))

    def test_null_or_empty_fix_version(self) -> None:
        self.assert_invalid(alert(fix_version=None))
        self.assert_invalid(alert(fix_version=""))

    def test_fix_version_wrong_type(self) -> None:
        self.assert_invalid(alert(fix_version=7))

    def test_length_limits_in_code_points(self) -> None:
        self.assert_invalid(alert(advisory_id="é" * 257))
        self.assert_invalid(alert(component="é" * 257))
        self.assert_invalid(alert(summary="好" * 2049))
        self.assert_invalid(alert(fix_version="v" * 257))

    def test_boundary_lengths_accepted(self) -> None:
        status, body = self.post(
            alert(
                advisory_id="é" * 256,
                component="好" * 256,
                summary="日" * 2048,
                fix_version="v" * 256,
            )
        )
        self.assertEqual(status, "201 Created", body)

    def test_post_with_query_parameter(self) -> None:
        status, _headers, body = call_json(
            "POST",
            self.path,
            alert(),
            query_string="severity=high",
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_invalid_requests_leave_no_records(self) -> None:
        self.assert_invalid(alert(severity="nope"))
        self.assert_invalid(b'["oops"]')
        status, _headers, body = call_json("GET", self.path)
        self.assertEqual(body["vulnerabilities"], [])

    def test_resource_not_found_does_not_record(self) -> None:
        status, _headers, body = call_json(
            "POST", "/resources/missing/vulnerabilities", alert()
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

        status, _headers, body = call_json(
            "GET", "/resources/missing/vulnerabilities"
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

    def test_empty_path_id(self) -> None:
        status, _headers, raw = call(
            "POST", "/resources//vulnerabilities", alert()
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(json.loads(raw)["error"], "invalid_request")

    def test_separator_in_id_via_path_suffix(self) -> None:
        status, _headers, body = call_json(
            "POST",
            f"/resources/{self.resource_id}/x/vulnerabilities",
            alert(),
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_backslash_in_id(self) -> None:
        status, _headers, body = call_json(
            "POST", "/resources/a\\x00b/vulnerabilities", alert()
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")


class VulnerabilityMethodTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.resource_id = create_resource()
        self.path = f"/resources/{self.resource_id}/vulnerabilities"

    def test_put_delete_patch_not_allowed(self) -> None:
        for method in ("PUT", "DELETE", "PATCH"):
            status, headers, body = call(method, self.path)
            self.assertEqual(status, "405 Method Not Allowed", method)
            self.assertIn(("Allow", "GET, POST"), headers)
            self.assertEqual(
                json.loads(body)["error"], "method_not_allowed"
            )


class VulnerabilityIsolationTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.resource_id = create_resource()

    def test_baseline_state_untouched_by_vulnerability_workflow(self) -> None:
        call_json(
            "POST",
            f"/resources/{self.resource_id}/vulnerabilities",
            alert(),
        )
        status, _headers, body = call_json("GET", "/resources")
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(body["resources"]), 1)

        status, _headers, body = call_json(
            "GET", f"/resources/{self.resource_id}/lifecycle"
        )
        self.assertEqual(body["state"], "staged")
        self.assertIsNone(body["reason"])

    def test_unicode_round_trip(self) -> None:
        status, _headers, body = call_json(
            "POST",
            f"/resources/{self.resource_id}/vulnerabilities",
            alert(summary="存在安全漏洞：含非 ASCII 文本。"),
        )
        self.assertEqual(status, "201 Created")
        status, _headers, raw = call(
            "GET", f"/resources/{self.resource_id}/vulnerabilities"
        )
        self.assertIn("存在安全漏洞".encode("utf-8"), raw)
        self.assertTrue(raw.endswith(b"\n"))


if __name__ == "__main__":
    unittest.main()
