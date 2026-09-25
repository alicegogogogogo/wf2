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


def alert(
    advisory: str,
    component: str = "openssl",
    severity: str = "high",
    summary: str = "a bug",
    **extra: object,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "advisory": advisory,
        "component": component,
        "severity": severity,
        "summary": summary,
    }
    payload.update(extra)
    return payload


class VulnerabilityBatchTests(unittest.TestCase):
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

    def _batch(
        self,
        items: object,
        resource_id: str | None = None,
        **kwargs: object,
    ):
        payload = (
            items
            if isinstance(items, (bytes, str))
            else {"vulnerabilities": items}
        )
        return call_json(
            "POST",
            f"/resources/{self.resource_id if resource_id is None else resource_id}"
            "/vulnerabilities/batch",
            payload,
            **kwargs,
        )

    def _list(self, resource_id: str | None = None):
        return call_json(
            "GET",
            f"/resources/{self.resource_id if resource_id is None else resource_id}"
            "/vulnerabilities",
        )

    # --- Success path ------------------------------------------------------

    def test_batch_returns_201_with_records_in_array_order(self) -> None:
        items = [
            alert("CVE-2026-0001", severity="HIGH", fixed_version="3.0.9"),
            alert("CVE-2026-0002", component="zlib", severity="low"),
            alert("CVE-2026-0003", component="musl", severity="Medium"),
        ]
        status, headers, body = self._batch(items)

        self.assertEqual(status, "201 Created")
        self.assertEqual(
            headers[0], ("Content-Type", "application/json; charset=utf-8")
        )
        self.assertEqual(set(body), {"vulnerabilities"})
        records = body["vulnerabilities"]
        self.assertEqual(len(records), 3)
        self.assertEqual(
            [r["advisory"] for r in records],
            ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"],
        )
        self.assertEqual(
            [r["severity"] for r in records], ["high", "low", "medium"]
        )
        for record in records:
            self.assertEqual(
                list(record),
                ["id", "advisory", "component", "severity", "summary",
                 "fixed_version"],
            )
            self.assertEqual(len(record["id"]), 32)
            int(record["id"], 16)
        self.assertEqual(records[0]["fixed_version"], "3.0.9")
        self.assertIsNone(records[1]["fixed_version"])
        # Every record gets its own id.
        self.assertEqual(
            len({r["id"] for r in records}), 3
        )

    def test_batch_response_is_compact_utf8_newline_terminated(self) -> None:
        status, _headers, raw = call(
            "POST",
            f"/resources/{self.resource_id}/vulnerabilities/batch",
            {"vulnerabilities": [alert("A-1", summary="溢出漏洞")]},
        )
        self.assertEqual(status, "201 Created")
        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(b" ", raw[:-1])
        text = raw.decode("utf-8").rstrip("\n")
        keys = ['"id"', '"advisory"', '"component"', '"severity"',
                '"summary"', '"fixed_version"']
        positions = [text.index(k) for k in keys]
        self.assertEqual(positions, sorted(positions))

    def test_single_element_batch_is_accepted(self) -> None:
        status, _h, body = self._batch([alert("A-1")])
        self.assertEqual(status, "201 Created")
        self.assertEqual(len(body["vulnerabilities"]), 1)

    def test_batch_of_one_hundred_is_accepted(self) -> None:
        items = [alert(f"A-{i}") for i in range(100)]
        status, _h, body = self._batch(items)
        self.assertEqual(status, "201 Created")
        self.assertEqual(len(body["vulnerabilities"]), 100)

    def test_batch_alerts_appear_in_listing_in_order(self) -> None:
        self._batch([alert("A-1"), alert("A-2", component="zlib")])
        _s, _h, listed = self._list()
        self.assertEqual(
            [r["advisory"] for r in listed["vulnerabilities"]],
            ["A-1", "A-2"],
        )

    def test_batch_alerts_mix_with_single_registrations(self) -> None:
        call_json(
            "POST",
            f"/resources/{self.resource_id}/vulnerabilities",
            alert("A-0"),
        )
        self._batch([alert("A-1"), alert("A-2")])
        _s, _h, listed = self._list()
        self.assertEqual(
            [r["advisory"] for r in listed["vulnerabilities"]],
            ["A-0", "A-1", "A-2"],
        )

    def test_batch_alerts_match_severity_filter(self) -> None:
        self._batch(
            [alert("A-1", severity="critical"), alert("A-2", severity="low")]
        )
        _s, _h, body = call_json(
            "GET",
            f"/resources/{self.resource_id}/vulnerabilities",
            query_string="severity=LOW",
        )
        self.assertEqual(
            [r["advisory"] for r in body["vulnerabilities"]], ["A-2"]
        )

    def test_batch_alerts_participate_in_global_summary(self) -> None:
        self._batch([alert("A-1"), alert("A-2")])
        self._batch([alert("A-1")], resource_id=self.other_id)
        _s, _h, advisories = call_json("GET", "/advisories")
        entry = [a for a in advisories if a["advisory"] == "A-1"]
        self.assertEqual(len(entry), 1)
        self.assertEqual(len(entry[0]["affected_resources"]), 2)
        self.assertEqual(entry[0]["advisory_count"], 2)

    def test_batch_alerts_can_be_exempted(self) -> None:
        self._batch([alert("A-1"), alert("A-2")])
        status, _h, body = call_json(
            "POST",
            f"/resources/{self.resource_id}/vulnerability-exceptions",
            {"advisory": "A-1", "component": "openssl", "reason": "accepted"},
        )
        self.assertEqual(status, "201 Created")
        self.assertEqual(body["advisory"], "A-1")
        self.assertEqual(body["component"], "openssl")

    # --- Atomicity ---------------------------------------------------------

    def test_invalid_element_aborts_whole_batch(self) -> None:
        items = [alert("A-1"), alert("A-2", severity="bogus"), alert("A-3")]
        status, _h, body = self._batch(items)
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        _s, _h, listed = self._list()
        self.assertEqual(listed["vulnerabilities"], [])

    def test_duplicate_inside_batch_aborts_everything(self) -> None:
        items = [alert("A-1"), alert("A-2"), alert("A-1")]
        status, _h, body = self._batch(items)
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "duplicate_vulnerability")
        _s, _h, listed = self._list()
        self.assertEqual(listed["vulnerabilities"], [])

    def test_duplicate_against_existing_alert_aborts_everything(self) -> None:
        call_json(
            "POST",
            f"/resources/{self.resource_id}/vulnerabilities",
            alert("A-0"),
        )
        status, _h, body = self._batch([alert("A-1"), alert("A-0")])
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "duplicate_vulnerability")
        _s, _h, listed = self._list()
        self.assertEqual(
            [r["advisory"] for r in listed["vulnerabilities"]], ["A-0"]
        )

    def test_same_pair_on_other_resource_is_not_a_duplicate(self) -> None:
        self._batch([alert("A-1")], resource_id=self.other_id)
        status, _h, body = self._batch([alert("A-1")])
        self.assertEqual(status, "201 Created")
        self.assertEqual(len(body["vulnerabilities"]), 1)

    # --- Shape and element validation --------------------------------------

    def test_missing_body_returns_400(self) -> None:
        status, _h, body = call_json(
            "POST", f"/resources/{self.resource_id}/vulnerabilities/batch"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_undecodable_body_returns_400(self) -> None:
        status, _h, body = self._batch(b"\xff\xfe")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_non_object_top_level_returns_400(self) -> None:
        for payload in ("[1]", '"text"', "42", "null"):
            with self.subTest(payload=payload):
                status, _h, body = self._batch(payload)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_unknown_top_level_field_returns_400(self) -> None:
        status, _h, body = self._batch(
            {"vulnerabilities": [alert("A-1")], "extra": 1}
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_missing_vulnerabilities_field_returns_400(self) -> None:
        status, _h, body = self._batch({})
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_empty_array_returns_400(self) -> None:
        status, _h, body = self._batch([])
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_non_array_value_returns_400(self) -> None:
        status, _h, body = self._batch({"vulnerabilities": {"a": 1}})
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_more_than_one_hundred_entries_returns_400(self) -> None:
        items = [alert(f"A-{i}") for i in range(101)]
        status, _h, body = self._batch(items)
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        _s, _h, listed = self._list()
        self.assertEqual(listed["vulnerabilities"], [])

    def test_invalid_elements_return_400(self) -> None:
        bad_items = [
            {"component": "c", "severity": "high", "summary": "s"},
            {**alert("A-1"), "advisory": 1},
            alert("A-1", component=""),
            {**alert("A-1"), "advisory": "x" * 257},
            alert("A-1", severity="fatal"),
            alert("A-1", unknown="field"),
            alert("A-1", fixed_version=""),
            "not-an-object",
        ]
        for bad in bad_items:
            with self.subTest(bad=bad):
                status, _h, body = self._batch([alert("A-0"), bad])
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")
                _s, _h, listed = self._list()
                self.assertEqual(listed["vulnerabilities"], [])

    # --- Path, query and method handling -----------------------------------

    def test_query_parameter_returns_400(self) -> None:
        status, _h, body = self._batch(
            [alert("A-1")], query_string="severity=high"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_empty_id_returns_400(self) -> None:
        status, _h, body = call_json(
            "POST",
            "/resources//vulnerabilities/batch",
            {"vulnerabilities": [alert("A-1")]},
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_separator_in_id_returns_400(self) -> None:
        for raw_id in ("a/b", "a\\b"):
            with self.subTest(raw_id=raw_id):
                status, _h, body = call_json(
                    "POST",
                    f"/resources/{raw_id}/vulnerabilities/batch",
                    {"vulnerabilities": [alert("A-1")]},
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_unknown_resource_returns_404(self) -> None:
        status, _h, body = self._batch([alert("A-1")], resource_id="missing")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

    def test_invalid_body_returns_400_even_for_unknown_resource(self) -> None:
        status, _h, body = self._batch([], resource_id="missing")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_unsupported_methods_return_405_with_allow_post(self) -> None:
        for method in ("GET", "PUT", "PATCH", "DELETE"):
            with self.subTest(method=method):
                status, headers, body = call_json(
                    method,
                    f"/resources/{self.resource_id}/vulnerabilities/batch",
                )
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")
                self.assertIn(("Allow", "POST"), headers)


if __name__ == "__main__":
    unittest.main()
