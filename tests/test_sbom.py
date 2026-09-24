from __future__ import annotations

import io
import json
import unittest

from provenance_api.app import application, reset_state

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_UPPER = "A" * 64


def call(
    method: str,
    path: str,
    body: bytes | str | dict[str, object] | list[object] | None = None,
    *,
    query_string: str | None = None,
) -> tuple[str, list[tuple[str, str]], bytes]:
    if body is None:
        payload = b""
    elif isinstance(body, (dict, list)):
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
    body: bytes | str | dict[str, object] | list[object] | None = None,
    *,
    query_string: str | None = None,
) -> tuple[str, list[tuple[str, str]], dict[str, object]]:
    status, headers, raw = call(method, path, body, query_string=query_string)
    return status, headers, json.loads(raw.decode("utf-8"))


def component(
    name: str = "openssl",
    version: str = "3.0.0",
    digest: str = DIGEST_A,
) -> dict[str, str]:
    return {"name": name, "version": version, "digest": digest}


class SbomTests(unittest.TestCase):
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
        fmt: str = "spdx",
        components: object = ...,  # type: ignore[assignment]
    ):
        if components is ...:
            components = [component()]
        return call_json(
            "POST",
            f"/resources/{self.resource_id if resource_id is None else resource_id}/sbom",
            {"format": fmt, "components": components},
        )

    def _get(self, resource_id: str | None = None):
        return call_json(
            "GET",
            f"/resources/{self.resource_id if resource_id is None else resource_id}/sbom",
        )

    # --- Creation ----------------------------------------------------------

    def test_first_submission_returns_201_and_echoes_fields(self) -> None:
        status, headers, body = self._submit(
            fmt="cyclonedx",
            components=[
                component("openssl", "3.0.0", DIGEST_A),
                component("zlib", "1.3", DIGEST_B),
            ],
        )
        self.assertEqual(status, "201 Created")
        self.assertEqual(
            headers[0], ("Content-Type", "application/json; charset=utf-8")
        )
        self.assertEqual(set(body), {"id", "format", "components"})
        self.assertEqual(body["id"], self.resource_id)
        self.assertEqual(body["format"], "cyclonedx")
        self.assertEqual(
            body["components"],
            [
                {"name": "openssl", "version": "3.0.0", "digest": DIGEST_A},
                {"name": "zlib", "version": "1.3", "digest": DIGEST_B},
            ],
        )

    def test_empty_components_is_allowed(self) -> None:
        status, _h, body = self._submit(components=[])
        self.assertEqual(status, "201 Created")
        self.assertEqual(body["components"], [])

    def test_digest_is_normalized_to_lowercase(self) -> None:
        status, _h, body = self._submit(
            components=[component(digest=DIGEST_UPPER)]
        )
        self.assertEqual(status, "201 Created")
        self.assertEqual(body["components"][0]["digest"], "a" * 64)

    def test_components_keep_submission_order(self) -> None:
        ordered = [
            component("c0", "1", DIGEST_A),
            component("c1", "2", DIGEST_B),
            component("c2", "3", DIGEST_C),
        ]
        self._submit(components=ordered)
        _s, _h, body = self._get()
        self.assertEqual(
            [(c["name"], c["digest"]) for c in body["components"]],
            [("c0", DIGEST_A), ("c1", DIGEST_B), ("c2", DIGEST_C)],
        )

    def test_response_is_compact_utf8_newline_terminated_with_key_order(
        self,
    ) -> None:
        status, _h, raw = call(
            "POST",
            f"/resources/{self.resource_id}/sbom",
            {"format": "spdx", "components": [
                {"name": "组件", "version": "v1", "digest": DIGEST_A}
            ]},
        )
        self.assertEqual(status, "201 Created")
        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(b" ", raw[:-1])
        text = raw.decode("utf-8").rstrip("\n")
        keys = ['"id"', '"format"', '"components"']
        positions = [text.index(k) for k in keys]
        self.assertEqual(positions, sorted(positions))
        ckeys = ['"name"', '"version"', '"digest"']
        cpositions = [text.index(k) for k in ckeys]
        self.assertEqual(cpositions, sorted(cpositions))

    # --- Reading -----------------------------------------------------------

    def test_get_returns_same_content_as_submission(self) -> None:
        _s, _h, written = self._submit(
            fmt="cyclonedx",
            components=[component("openssl", "3.0.0", DIGEST_A)],
        )
        status, _h, read = self._get()
        self.assertEqual(status, "200 OK")
        self.assertEqual(read, written)

    def test_get_without_document_is_404_sbom_not_found(self) -> None:
        status, _h, body = self._get()
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "sbom_not_found")

    # --- Idempotency and conflict ------------------------------------------

    def test_identical_resubmission_is_idempotent_200(self) -> None:
        first = self._submit(
            components=[component("openssl", "1", DIGEST_A)]
        )[2]
        status, _h, body = self._submit(
            components=[component("openssl", "1", DIGEST_A)]
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, first)
        # Exactly one record remains.
        self.assertEqual(self._get()[2], first)

    def test_resubmission_with_uppercase_digest_is_still_idempotent(self) -> None:
        self._submit(components=[component(digest=DIGEST_UPPER)])
        status, _h, body = self._submit(components=[component(digest="a" * 64)])
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["components"][0]["digest"], "a" * 64)

    def test_different_format_conflicts_and_keeps_original(self) -> None:
        original = self._submit(fmt="spdx", components=[])[2]
        status, _h, body = self._submit(fmt="cyclonedx", components=[])
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "sbom_conflict")
        self.assertEqual(self._get()[2], original)

    def test_different_components_conflict_and_keep_original(self) -> None:
        original = self._submit(
            components=[component("openssl", "1", DIGEST_A)]
        )[2]
        status, _h, body = self._submit(
            components=[
                component("openssl", "1", DIGEST_A),
                component("zlib", "2", DIGEST_B),
            ]
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "sbom_conflict")
        self.assertEqual(self._get()[2], original)

    def test_duplicate_triple_in_submission_is_409_and_creates_nothing(
        self,
    ) -> None:
        status, _h, body = self._submit(
            components=[
                component("openssl", "1", DIGEST_A),
                component("openssl", "1", DIGEST_A),
            ]
        )
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body["error"], "duplicate_component")
        # No document was stored.
        miss_status, _h, miss = self._get()
        self.assertEqual(miss_status, "404 Not Found")
        self.assertEqual(miss["error"], "sbom_not_found")

    def test_same_name_version_different_digest_is_not_duplicate(self) -> None:
        status, _h, _b = self._submit(
            components=[
                component("openssl", "1", DIGEST_A),
                component("openssl", "1", DIGEST_B),
            ]
        )
        self.assertEqual(status, "201 Created")

    def test_documents_are_scoped_per_resource(self) -> None:
        self._submit(resource_id=self.resource_id, components=[])
        status, _h, body = self._get(self.other_id)
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "sbom_not_found")
        status2, _h, _b = self._submit(
            resource_id=self.other_id, components=[]
        )
        self.assertEqual(status2, "201 Created")

    # --- Resource resolution -----------------------------------------------

    def test_post_and_get_on_missing_resource_are_404(self) -> None:
        for method in ("POST", "GET"):
            with self.subTest(method=method):
                body = {"format": "spdx", "components": []} if method == "POST" else None
                status, _h, payload = call_json(method, "/resources/nope/sbom", body)
                self.assertEqual(status, "404 Not Found")
                self.assertEqual(payload["error"], "resource_not_found")

    # --- Bad request: body -------------------------------------------------

    def test_missing_body_is_bad_request(self) -> None:
        status, _h, body = call_json(
            "POST", f"/resources/{self.resource_id}/sbom", None
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_malformed_or_bad_utf8_body_is_bad_request(self) -> None:
        path = f"/resources/{self.resource_id}/sbom"
        for raw in (b"{bad", b"\xff\xfe"):
            with self.subTest(raw=raw):
                status, _h, body = call_json("POST", path, raw)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_non_object_body_is_bad_request(self) -> None:
        for raw in (b"[]", b'"x"', b"42", b"null"):
            with self.subTest(raw=raw):
                status, _h, body = call_json(
                    "POST", f"/resources/{self.resource_id}/sbom", raw
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    # --- Bad request: fields -----------------------------------------------

    def test_missing_required_fields(self) -> None:
        for field in ("format", "components"):
            payload = {"format": "spdx", "components": []}
            del payload[field]
            with self.subTest(field=field):
                status, _h, body = call_json(
                    "POST", f"/resources/{self.resource_id}/sbom", payload
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_unknown_field_rejected(self) -> None:
        status, _h, body = call_json(
            "POST",
            f"/resources/{self.resource_id}/sbom",
            {"format": "spdx", "components": [], "extra": 1},
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_format_must_be_spdx_or_cyclonedx(self) -> None:
        for bad in ("SPDX", "CycloneDX", "swid", "", 1, None, True):
            with self.subTest(bad=bad):
                status, _h, body = call_json(
                    "POST",
                    f"/resources/{self.resource_id}/sbom",
                    {"format": bad, "components": []},
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_components_must_be_an_array(self) -> None:
        for bad in ({}, "x", 1, None, True):
            with self.subTest(bad=bad):
                status, _h, body = call_json(
                    "POST",
                    f"/resources/{self.resource_id}/sbom",
                    {"format": "spdx", "components": bad},
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_component_must_be_an_object(self) -> None:
        for bad in ([], "x", 1, None):
            with self.subTest(bad=bad):
                status, _h, body = call_json(
                    "POST",
                    f"/resources/{self.resource_id}/sbom",
                    {"format": "spdx", "components": [bad]},
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_component_fields_required_non_empty_strings(self) -> None:
        good = component()
        for field in ("name", "version", "digest"):
            for bad in (None, "", 1, True, [], {}):
                payload = dict(good)
                payload[field] = bad
                with self.subTest(field=field, bad=bad):
                    status, _h, body = call_json(
                        "POST",
                        f"/resources/{self.resource_id}/sbom",
                        {"format": "spdx", "components": [payload]},
                    )
                    self.assertEqual(status, "400 Bad Request")
                    self.assertEqual(body["error"], "invalid_request")

    def test_component_missing_field_rejected(self) -> None:
        for field in ("name", "version", "digest"):
            payload = component()
            del payload[field]
            with self.subTest(field=field):
                status, _h, body = call_json(
                    "POST",
                    f"/resources/{self.resource_id}/sbom",
                    {"format": "spdx", "components": [payload]},
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_component_unknown_field_rejected(self) -> None:
        payload = component()
        payload["extra"] = "x"
        status, _h, body = call_json(
            "POST",
            f"/resources/{self.resource_id}/sbom",
            {"format": "spdx", "components": [payload]},
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_component_digest_must_be_64_hex(self) -> None:
        for bad in ("z" * 64, "a" * 63, "A" * 63, "0" * 65, "g" * 64):
            with self.subTest(bad=bad):
                status, _h, body = call_json(
                    "POST",
                    f"/resources/{self.resource_id}/sbom",
                    {"format": "spdx",
                     "components": [component(digest=bad)]},
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    # --- Path, query, method -----------------------------------------------

    def test_empty_path_id_is_bad_request(self) -> None:
        for method, body in [
            ("GET", None),
            ("POST", {"format": "spdx", "components": []}),
        ]:
            with self.subTest(method=method):
                status, _h, payload = call_json(method, "/resources//sbom", body)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(payload["error"], "invalid_request")

    def test_path_id_with_separator_is_bad_request(self) -> None:
        for raw in ("a/b", "a\\b"):
            for method in ("GET", "POST"):
                with self.subTest(raw=raw, method=method):
                    status, _h, body = call_json(
                        method, f"/resources/{raw}/sbom"
                    )
                    self.assertEqual(status, "400 Bad Request")
                    self.assertEqual(body["error"], "invalid_request")

    def test_query_parameters_rejected(self) -> None:
        for method, body in [
            ("GET", None),
            ("POST", {"format": "spdx", "components": []}),
        ]:
            with self.subTest(method=method):
                status, _h, payload = call_json(
                    method,
                    f"/resources/{self.resource_id}/sbom",
                    body,
                    query_string="x=1",
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(payload["error"], "invalid_request")

    def test_unsupported_methods_return_405_with_allow(self) -> None:
        for method in ("PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, headers, body = call_json(
                    method, f"/resources/{self.resource_id}/sbom"
                )
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")
                self.assertIn(("Allow", "GET, POST"), headers)

    # --- State isolation ---------------------------------------------------

    def test_failures_never_change_stored_document(self) -> None:
        original = self._submit(
            components=[component("openssl", "1", DIGEST_A)]
        )[2]
        # Invalid payloads and a conflicting replacement must not touch it.
        call("POST", f"/resources/{self.resource_id}/sbom", b"not json")
        call_json(
            "POST",
            f"/resources/{self.resource_id}/sbom",
            {"format": "nope", "components": []},
        )
        self._submit(fmt="cyclonedx", components=[])
        self.assertEqual(self._get()[2], original)


if __name__ == "__main__":
    unittest.main()
