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


class LicenseTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        _s, _h, body = call_json(
            "POST",
            "/resources",
            {"name": "r", "category": "code", "digest": DIGEST_A},
        )
        self.resource_id = str(body["id"])
        _s, _h, other = call_json(
            "POST",
            "/resources",
            {"name": "other", "category": "code", "digest": DIGEST_B},
        )
        self.other_id = str(other["id"])

    def _submit(
        self,
        resource_id: str | None = None,
        *,
        spdx_id: object = "MIT",
        source: object = ...,  # type: ignore[assignment]
    ):
        payload: dict[str, object] = {"spdx_id": spdx_id}
        if source is not ...:
            payload["source"] = source
        return call_json(
            "POST",
            f"/resources/{self.resource_id if resource_id is None else resource_id}/license",
            payload,
        )

    def _get(self, resource_id: str | None = None):
        return call_json(
            "GET",
            f"/resources/{self.resource_id if resource_id is None else resource_id}/license",
        )

    # --- Creation ----------------------------------------------------------

    def test_first_submission_returns_201_and_echoes_fields(self) -> None:
        status, headers, body = self._submit(spdx_id="Apache-2.0")
        self.assertEqual(status, "201 Created")
        self.assertEqual(
            headers[0], ("Content-Type", "application/json; charset=utf-8")
        )
        self.assertEqual(set(body), {"id", "spdx_id", "source"})
        self.assertEqual(body["id"], self.resource_id)
        self.assertEqual(body["spdx_id"], "Apache-2.0")
        self.assertIsNone(body["source"])

    def test_source_is_echoed_verbatim(self) -> None:
        status, _h, body = self._submit(
            spdx_id="MIT", source="https://example.invalid/LICENSE"
        )
        self.assertEqual(status, "201 Created")
        self.assertEqual(body["source"], "https://example.invalid/LICENSE")

    def test_response_is_compact_utf8_newline_terminated_with_key_order(
        self,
    ) -> None:
        status, _h, raw = call(
            "POST",
            f"/resources/{self.resource_id}/license",
            {"spdx_id": "MIT", "source": "许可证文件"},
        )
        self.assertEqual(status, "201 Created")
        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(b" ", raw[:-1])
        text = raw.decode("utf-8").rstrip("\n")
        keys = ['"id"', '"spdx_id"', '"source"']
        positions = [text.index(k) for k in keys]
        self.assertEqual(positions, sorted(positions))

    # --- Reading -----------------------------------------------------------

    def test_get_returns_same_content_as_submission(self) -> None:
        _s, _h, written = self._submit(spdx_id="MIT", source="LICENSE")
        status, _h, read = self._get()
        self.assertEqual(status, "200 OK")
        self.assertEqual(read, written)

    def test_get_without_declaration_is_404_license_not_found(self) -> None:
        status, _h, body = self._get()
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "license_not_found")

    # --- Idempotency and conflict ------------------------------------------

    def test_identical_resubmission_without_source_is_200(self) -> None:
        first = self._submit(spdx_id="MIT")[2]
        status, _h, body = self._submit(spdx_id="MIT")
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, first)
        self.assertEqual(self._get()[2], first)

    def test_identical_resubmission_with_source_is_200(self) -> None:
        first = self._submit(spdx_id="MIT", source="LICENSE")[2]
        status, _h, body = self._submit(spdx_id="MIT", source="LICENSE")
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, first)

    def test_different_spdx_id_conflicts_and_keeps_original(self) -> None:
        original = self._submit(spdx_id="MIT")[2]
        status, _h, body = self._submit(spdx_id="Apache-2.0")
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "license_conflict")
        self.assertEqual(self._get()[2], original)

    def test_added_source_conflicts_with_sourceless_original(self) -> None:
        original = self._submit(spdx_id="MIT")[2]
        status, _h, body = self._submit(spdx_id="MIT", source="LICENSE")
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "license_conflict")
        self.assertEqual(self._get()[2], original)

    def test_dropped_source_conflicts_with_original(self) -> None:
        original = self._submit(spdx_id="MIT", source="LICENSE")[2]
        status, _h, body = self._submit(spdx_id="MIT")
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "license_conflict")
        self.assertEqual(self._get()[2], original)

    def test_different_source_conflicts_and_keeps_original(self) -> None:
        original = self._submit(spdx_id="MIT", source="a")[2]
        status, _h, body = self._submit(spdx_id="MIT", source="b")
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "license_conflict")
        self.assertEqual(self._get()[2], original)

    def test_licenses_are_scoped_per_resource(self) -> None:
        self._submit(resource_id=self.resource_id, spdx_id="MIT")
        status, _h, body = self._get(self.other_id)
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "license_not_found")
        status2, _h, _b = self._submit(
            resource_id=self.other_id, spdx_id="Apache-2.0"
        )
        self.assertEqual(status2, "201 Created")

    # --- Resource resolution -----------------------------------------------

    def test_post_and_get_on_missing_resource_are_404(self) -> None:
        for method in ("POST", "GET"):
            with self.subTest(method=method):
                body = {"spdx_id": "MIT"} if method == "POST" else None
                status, _h, payload = call_json(
                    method, "/resources/nope/license", body
                )
                self.assertEqual(status, "404 Not Found")
                self.assertEqual(payload["error"], "resource_not_found")

    # --- Bad request: body -------------------------------------------------

    def test_missing_body_is_bad_request(self) -> None:
        status, _h, body = call_json(
            "POST", f"/resources/{self.resource_id}/license", None
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_malformed_or_bad_utf8_body_is_bad_request(self) -> None:
        path = f"/resources/{self.resource_id}/license"
        for raw in (b"{bad", b"\xff\xfe"):
            with self.subTest(raw=raw):
                status, _h, body = call_json("POST", path, raw)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_non_object_body_is_bad_request(self) -> None:
        for raw in (b"[]", b'"x"', b"42", b"null"):
            with self.subTest(raw=raw):
                status, _h, body = call_json(
                    "POST", f"/resources/{self.resource_id}/license", raw
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    # --- Bad request: fields -----------------------------------------------

    def test_missing_spdx_id_is_bad_request(self) -> None:
        status, _h, body = call_json(
            "POST", f"/resources/{self.resource_id}/license", {"source": "x"}
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_spdx_id_must_be_non_empty_string(self) -> None:
        for bad in ("", None, 1, True, [], {}):
            with self.subTest(bad=bad):
                status, _h, body = call_json(
                    "POST",
                    f"/resources/{self.resource_id}/license",
                    {"spdx_id": bad},
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_whitespace_only_spdx_id_is_nonempty_and_accepted(self) -> None:
        status, _h, body = self._submit(spdx_id=" ")
        self.assertEqual(status, "201 Created")
        self.assertEqual(body["spdx_id"], " ")

    def test_unknown_field_rejected(self) -> None:
        status, _h, body = call_json(
            "POST",
            f"/resources/{self.resource_id}/license",
            {"spdx_id": "MIT", "extra": 1},
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_source_must_be_non_empty_string_when_present(self) -> None:
        for bad in ("", None, 1, True, [], {}):
            with self.subTest(bad=bad):
                status, _h, body = call_json(
                    "POST",
                    f"/resources/{self.resource_id}/license",
                    {"spdx_id": "MIT", "source": bad},
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    # --- Path, query, method -----------------------------------------------

    def test_empty_path_id_is_bad_request(self) -> None:
        for method, body in [
            ("GET", None),
            ("POST", {"spdx_id": "MIT"}),
        ]:
            with self.subTest(method=method):
                status, _h, payload = call_json(
                    method, "/resources//license", body
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(payload["error"], "invalid_request")

    def test_path_id_with_separator_is_bad_request(self) -> None:
        for raw in ("a/b", "a\\b"):
            for method in ("GET", "POST"):
                with self.subTest(raw=raw, method=method):
                    status, _h, body = call_json(
                        method, f"/resources/{raw}/license"
                    )
                    self.assertEqual(status, "400 Bad Request")
                    self.assertEqual(body["error"], "invalid_request")

    def test_query_parameters_rejected(self) -> None:
        for method, body in [
            ("GET", None),
            ("POST", {"spdx_id": "MIT"}),
        ]:
            with self.subTest(method=method):
                status, _h, payload = call_json(
                    method,
                    f"/resources/{self.resource_id}/license",
                    body,
                    query_string="x=1",
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(payload["error"], "invalid_request")

    def test_unsupported_methods_return_405_with_allow(self) -> None:
        for method in ("PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, headers, body = call_json(
                    method, f"/resources/{self.resource_id}/license"
                )
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")
                self.assertIn(("Allow", "GET, POST"), headers)

    # --- State isolation ---------------------------------------------------

    def test_failures_never_change_stored_declaration(self) -> None:
        original = self._submit(spdx_id="MIT")[2]
        call("POST", f"/resources/{self.resource_id}/license", b"not json")
        call_json(
            "POST",
            f"/resources/{self.resource_id}/license",
            {"source": "x"},
        )
        self._submit(spdx_id="Apache-2.0")
        self.assertEqual(self._get()[2], original)


if __name__ == "__main__":
    unittest.main()
