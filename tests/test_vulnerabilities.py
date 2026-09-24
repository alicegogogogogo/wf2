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


class VulnerabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.resource_id = self._create(DIGEST_A)
        self.other_id = self._create(DIGEST_B, name="other")

    def _create(self, digest: str, name: str = "r") -> str:
        _s, _h, body = call_json(
            "POST",
            "/resources",
            {"name": name, "category": "code", "digest": digest},
        )
        return str(body["id"])

    def _alert(
        self,
        resource_id: str | None = None,
        *,
        advisory: str = "CVE-2026-0001",
        component: str = "openssl",
        severity: str = "high",
        summary: str = "a bug",
        fixed_version: object = ...,  # type: ignore[assignment]
    ):
        payload: dict[str, object] = {
            "advisory": advisory,
            "component": component,
            "severity": severity,
            "summary": summary,
        }
        if fixed_version is not ...:
            payload["fixed_version"] = fixed_version
        return call_json(
            "POST",
            f"/resources/{self.resource_id if resource_id is None else resource_id}/vulnerabilities",
            payload,
        )

    def _list(self, resource_id: str | None = None, **kwargs: object):
        qs = (
            "severity=" + str(kwargs["severity"])
            if "severity" in kwargs
            else None
        )
        return call_json(
            "GET",
            f"/resources/{self.resource_id if resource_id is None else resource_id}/vulnerabilities",
            query_string=qs,
        )

    # --- Registration ------------------------------------------------------

    def test_register_returns_201_with_six_fields(self) -> None:
        status, headers, body = self._alert(fixed_version="3.0.9")

        self.assertEqual(status, "201 Created")
        self.assertEqual(
            headers[0], ("Content-Type", "application/json; charset=utf-8")
        )
        self.assertEqual(set(body), {"id", "advisory", "component",
                                     "severity", "summary", "fixed_version"})
        self.assertIsInstance(body["id"], str)
        self.assertEqual(len(body["id"]), 32)
        int(body["id"], 16)
        self.assertEqual(body["advisory"], "CVE-2026-0001")
        self.assertEqual(body["component"], "openssl")
        self.assertEqual(body["severity"], "high")
        self.assertEqual(body["summary"], "a bug")
        self.assertEqual(body["fixed_version"], "3.0.9")

    def test_fixed_version_defaults_to_null(self) -> None:
        _s, _h, body = self._alert()
        self.assertIsNone(body["fixed_version"])

    def test_severity_is_case_insensitive_and_normalized(self) -> None:
        for value in ("CRITICAL", "High", "MeDiUm", "low"):
            with self.subTest(value=value):
                _s, _h, body = self._alert(
                    advisory=f"ADV-{value}", severity=value
                )
                self.assertEqual(body["severity"], value.lower())

    def test_response_is_compact_utf8_newline_terminated(self) -> None:
        status, _headers, raw = call(
            "POST",
            f"/resources/{self.resource_id}/vulnerabilities",
            {"advisory": "A-1", "component": "openssl", "severity": "high",
             "summary": "溢出漏洞"},
        )
        self.assertEqual(status, "201 Created")
        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(b" ", raw[:-1])
        text = raw.decode("utf-8").rstrip("\n")
        keys = ['"id"', '"advisory"', '"component"', '"severity"',
                '"summary"', '"fixed_version"']
        positions = [text.index(k) for k in keys]
        self.assertEqual(positions, sorted(positions))

    def test_unicode_code_points_accepted(self) -> None:
        status, _h, body = self._alert(advisory="公告-😀", summary="摘要")
        self.assertEqual(status, "201 Created")
        self.assertEqual(body["advisory"], "公告-😀")

    # --- Listing -----------------------------------------------------------

    def test_empty_listing_is_success(self) -> None:
        status, _headers, body = self._list()
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, {"vulnerabilities": []})

    def test_listing_keeps_submission_order_without_duplicates(self) -> None:
        first = self._alert(advisory="A-1", component="c1")[2]
        second = self._alert(advisory="A-2", component="c2")[2]
        third = self._alert(advisory="A-1", component="c2")[2]

        _s, _h, body = self._list()
        ids = [item["id"] for item in body["vulnerabilities"]]
        self.assertEqual(ids, [first["id"], second["id"], third["id"]])
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(
            all(set(item) == {"id", "advisory", "component", "severity",
                              "summary", "fixed_version"}
                for item in body["vulnerabilities"])
        )

    def test_filter_by_severity_keeps_submission_order(self) -> None:
        h1 = self._alert(advisory="A-1", severity="high")[2]
        self._alert(advisory="A-2", severity="low")
        h2 = self._alert(advisory="A-3", severity="HIGH")[2]
        self._alert(advisory="A-4", severity="medium")

        _s, _h, body = self._list(severity="HIGH")
        self.assertEqual(
            [item["id"] for item in body["vulnerabilities"]],
            [h1["id"], h2["id"]],
        )
        self.assertTrue(
            all(item["severity"] == "high"
                for item in body["vulnerabilities"])
        )

    def test_filter_with_no_match_is_empty(self) -> None:
        self._alert(severity="low")
        _s, _h, body = self._list(severity="critical")
        self.assertEqual(body, {"vulnerabilities": []})

    def test_listing_is_scoped_per_resource(self) -> None:
        self._alert(resource_id=self.resource_id, advisory="A-1")
        self._alert(resource_id=self.other_id, advisory="A-1")
        _s, _h, first = self._list(self.resource_id)
        _s, _h, second = self._list(self.other_id)
        self.assertEqual(len(first["vulnerabilities"]), 1)
        self.assertEqual(len(second["vulnerabilities"]), 1)
        self.assertNotEqual(
            first["vulnerabilities"][0]["id"],
            second["vulnerabilities"][0]["id"],
        )

    # --- Duplicates --------------------------------------------------------

    def test_duplicate_advisory_and_component_conflicts(self) -> None:
        original = self._alert(
            advisory="CVE-X", component="lib", severity="low",
            fixed_version="1.0",
        )[2]
        # Same advisory+component but different severity/summary/fix is still
        # a duplicate; the original alert stays unchanged.
        status, _h, body = self._alert(
            advisory="CVE-X", component="lib", severity="critical",
            summary="different", fixed_version="2.0",
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "duplicate_vulnerability")

        _s, _h, listed = self._list()
        self.assertEqual(len(listed["vulnerabilities"]), 1)
        kept = listed["vulnerabilities"][0]
        self.assertEqual(kept["id"], original["id"])
        self.assertEqual(kept["severity"], "low")
        self.assertEqual(kept["fixed_version"], "1.0")

    def test_same_advisory_different_component_is_distinct(self) -> None:
        self._alert(advisory="CVE-X", component="lib-a")
        status, _h, _body = self._alert(advisory="CVE-X", component="lib-b")
        self.assertEqual(status, "201 Created")

    def test_same_component_different_advisory_is_distinct(self) -> None:
        self._alert(advisory="CVE-1", component="lib")
        status, _h, _body = self._alert(advisory="CVE-2", component="lib")
        self.assertEqual(status, "201 Created")

    def test_duplicate_does_not_leak_across_resources(self) -> None:
        self._alert(resource_id=self.resource_id, advisory="A-1")
        status, _h, _body = self._alert(resource_id=self.other_id,
                                        advisory="A-1")
        self.assertEqual(status, "201 Created")

    # --- Not found ---------------------------------------------------------

    def test_register_and_list_missing_resource_are_404(self) -> None:
        for method in ("POST", "GET"):
            with self.subTest(method=method):
                body = (
                    {"advisory": "a", "component": "c", "severity": "low",
                     "summary": "s"}
                    if method == "POST" else None
                )
                status, _h, payload = call_json(
                    method, "/resources/missing/vulnerabilities", body
                )
                self.assertEqual(status, "404 Not Found")
                self.assertEqual(payload["error"], "resource_not_found")

    def test_404_creates_no_alert_anywhere(self) -> None:
        call_json(
            "POST",
            "/resources/missing/vulnerabilities",
            {"advisory": "a", "component": "c", "severity": "low",
             "summary": "s"},
        )
        _s, _h, body = self._list(self.resource_id)
        self.assertEqual(body["vulnerabilities"], [])

    # --- Bad request: body -------------------------------------------------

    def test_missing_body_is_bad_request(self) -> None:
        status, _h, body = call_json(
            "POST", f"/resources/{self.resource_id}/vulnerabilities", None
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_malformed_or_bad_utf8_body_is_bad_request(self) -> None:
        path = f"/resources/{self.resource_id}/vulnerabilities"
        for raw in (b"{bad", b"\xff\xfe"):
            with self.subTest(raw=raw):
                status, _h, body = call_json("POST", path, raw)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_non_object_body_is_bad_request(self) -> None:
        for raw in (b"[]", b'"x"', b"42", b"null"):
            with self.subTest(raw=raw):
                status, _h, body = call_json(
                    "POST",
                    f"/resources/{self.resource_id}/vulnerabilities",
                    raw,
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    # --- Bad request: fields -----------------------------------------------

    def test_missing_required_fields(self) -> None:
        base = {"advisory": "a", "component": "c", "severity": "low",
                "summary": "s"}
        for field in ("advisory", "component", "severity", "summary"):
            payload = dict(base)
            del payload[field]
            with self.subTest(field=field):
                status, _h, body = self._alert_raw(payload)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def _alert_raw(self, payload: dict[str, object]):
        return call_json(
            "POST",
            f"/resources/{self.resource_id}/vulnerabilities",
            payload,
        )

    def test_wrong_field_types(self) -> None:
        base = {"advisory": "a", "component": "c", "severity": "low",
                "summary": "s"}
        for field, bad in [
            ("advisory", 1),
            ("component", 2),
            ("severity", 3),
            ("summary", 4),
            ("fixed_version", 5),
            ("advisory", True),
            ("severity", None),
            ("fixed_version", None),
            ("advisory", ["x"]),
        ]:
            payload = dict(base)
            payload[field] = bad
            with self.subTest(field=field, bad=bad):
                status, _h, body = self._alert_raw(payload)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_empty_strings_rejected(self) -> None:
        base = {"advisory": "a", "component": "c", "severity": "low",
                "summary": "s"}
        for field in ("advisory", "component", "severity", "summary",
                      "fixed_version"):
            payload = dict(base)
            payload[field] = ""
            with self.subTest(field=field):
                status, _h, body = self._alert_raw(payload)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_whitespace_only_is_nonempty_and_accepted(self) -> None:
        # Only the empty string is forbidden; whitespace is still content
        # (no trimming), mirroring the path-id convention elsewhere.
        status, _h, body = self._alert_raw(
            {"advisory": " ", "component": "\t", "severity": "low",
             "summary": "  ", "fixed_version": " "}
        )
        self.assertEqual(status, "201 Created")
        self.assertEqual(body["advisory"], " ")

    def test_unknown_field_rejected(self) -> None:
        status, _h, body = self._alert_raw(
            {"advisory": "a", "component": "c", "severity": "low",
             "summary": "s", "extra": 1}
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_illegal_severity_rejected(self) -> None:
        for bad in ("urgent", "HIGH ", " high", ""):
            with self.subTest(bad=bad):
                status, _h, body = self._alert_raw(
                    {"advisory": "a", "component": "c", "severity": bad,
                     "summary": "s"}
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_length_limits_enforced_in_code_points(self) -> None:
        # Boundary values are accepted.
        ok = self._alert_raw(
            {"advisory": "A" * 256, "component": "C" * 256,
             "severity": "low", "summary": "S" * 2048,
             "fixed_version": "V" * 256}
        )
        self.assertEqual(ok[0], "201 Created")

        # One code point over, per field, is rejected.
        base = {"advisory": "A" * 256, "component": "C" * 256,
                "severity": "low", "summary": "S" * 2048,
                "fixed_version": "V" * 256}
        for field, over in [
            ("advisory", "A" * 257),
            ("component", "C" * 257),
            ("summary", "S" * 2049),
            ("fixed_version", "V" * 257),
        ]:
            payload = dict(base)
            payload[field] = over
            with self.subTest(field=field):
                status, _h, body = self._alert_raw(payload)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_length_counts_code_points_not_bytes(self) -> None:
        # 256 emoji code points are far more than 256 UTF-8 bytes but valid.
        status, _h, _body = self._alert_raw(
            {"advisory": "😀" * 256, "component": "c", "severity": "low",
             "summary": "s"}
        )
        self.assertEqual(status, "201 Created")
        status, _h, _body = self._alert_raw(
            {"advisory": "😀" * 257, "component": "c", "severity": "low",
             "summary": "s"}
        )
        self.assertEqual(status, "400 Bad Request")

    # --- Bad request: path and query ---------------------------------------

    def test_empty_path_id_is_bad_request(self) -> None:
        for method, body in [
            ("GET", None),
            ("POST", {"advisory": "a", "component": "c", "severity": "low",
                      "summary": "s"}),
        ]:
            with self.subTest(method=method):
                status, _h, payload = call_json(
                    method, "/resources//vulnerabilities", body
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(payload["error"], "invalid_request")

    def test_path_id_with_separator_is_bad_request(self) -> None:
        for raw in ("a/b", "a\\b"):
            for method in ("GET", "POST"):
                with self.subTest(raw=raw, method=method):
                    status, _h, body = call_json(
                        method, f"/resources/{raw}/vulnerabilities"
                    )
                    self.assertIn(status[:3], {"400", "404"})
                    self.assertEqual(body["error"], "invalid_request")

    def test_post_rejects_any_query_parameter(self) -> None:
        status, _h, body = call_json(
            "POST",
            f"/resources/{self.resource_id}/vulnerabilities",
            {"advisory": "a", "component": "c", "severity": "low",
             "summary": "s"},
            query_string="severity=high",
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_get_rejects_bad_query_parameters(self) -> None:
        for qs in ("bogus=1", "severity=", "severity=urgent",
                   "severity=high&severity=low", "severity=HIGH&x=1"):
            with self.subTest(qs=qs):
                status, _h, body = call_json(
                    "GET",
                    f"/resources/{self.resource_id}/vulnerabilities",
                    query_string=qs,
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    # --- Method handling ---------------------------------------------------

    def test_unsupported_methods_return_405_with_allow(self) -> None:
        for method in ("PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, headers, body = call_json(
                    method, f"/resources/{self.resource_id}/vulnerabilities"
                )
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")
                self.assertIn(("Allow", "GET, POST"), headers)

    # --- State isolation ---------------------------------------------------

    def test_failed_requests_leave_no_alerts_and_keep_state(self) -> None:
        good = self._alert(advisory="A-1")[2]

        # A spread of rejected requests.
        self._alert_raw({"advisory": "A-1", "component": "openssl",
                         "severity": "bogus", "summary": "s"})
        self._alert_raw({"advisory": "A-1", "component": "openssl",
                         "severity": "low", "summary": "s", "x": 1})
        call_json(
            "POST", f"/resources/{self.resource_id}/vulnerabilities",
            b"not json",
        )
        call_json(
            "GET",
            f"/resources/{self.resource_id}/vulnerabilities",
            query_string="severity=nope",
        )
        call_json("GET", "/resources/missing/vulnerabilities")

        _s, _h, body = self._list()
        self.assertEqual([v["id"] for v in body["vulnerabilities"]],
                         [good["id"]])
        # Other stores are untouched as well.
        _s, _h, resources = call_json("GET", "/resources")
        self.assertEqual(len(resources["resources"]), 2)


if __name__ == "__main__":
    unittest.main()
