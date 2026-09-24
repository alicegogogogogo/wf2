from __future__ import annotations

import io
import json
import unittest

from provenance_api.app import application, reset_state

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "C" * 64


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


def provenance_payload(
    *,
    builder: object = "ci-bot",
    build_number: object = "build-001",
    source_digest: object = DIGEST_A,
    materials: object = ...,  # type: ignore[assignment]
) -> dict[str, object]:
    if materials is ...:
        materials = []
    return {
        "builder": builder,
        "build_number": build_number,
        "source_digest": source_digest,
        "materials": materials,
    }


class ProvenanceTests(unittest.TestCase):
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

    def _register(
        self,
        resource_id: str | None = None,
        *,
        payload: dict[str, object] | None = None,
    ):
        target = self.resource_id if resource_id is None else resource_id
        return call_json(
            "POST",
            f"/resources/{target}/provenance",
            payload if payload is not None else provenance_payload(),
        )

    # --- Registration ------------------------------------------------------

    def test_register_returns_201_and_echoes_fields(self) -> None:
        payload = provenance_payload(
            builder="builder-1",
            build_number="42",
            source_digest=DIGEST_C,
            materials=[
                {"name": "openssl", "digest": DIGEST_B},
                {"name": "zlib", "digest": DIGEST_A},
            ],
        )
        status, headers, body = self._register(payload=payload)
        self.assertEqual(status, "201 Created")
        self.assertEqual(
            headers[0], ("Content-Type", "application/json; charset=utf-8")
        )
        self.assertEqual(
            set(body),
            {"id", "builder", "build_number", "source_digest", "materials"},
        )
        self.assertEqual(body["id"], self.resource_id)
        self.assertEqual(body["builder"], "builder-1")
        self.assertEqual(body["build_number"], "42")
        self.assertEqual(body["source_digest"], "c" * 64)
        self.assertEqual(
            body["materials"],
            [
                {"name": "openssl", "digest": DIGEST_B},
                {"name": "zlib", "digest": DIGEST_A},
            ],
        )

    def test_digests_normalized_to_lowercase(self) -> None:
        payload = provenance_payload(
            source_digest="AbC" + "0" * 61,
            materials=[{"name": "m", "digest": "DeF" + "0" * 61}],
        )
        _s, _h, body = self._register(payload=payload)
        self.assertEqual(body["source_digest"], "abc" + "0" * 61)
        self.assertEqual(body["materials"][0]["digest"], "def" + "0" * 61)

    def test_empty_materials_is_valid(self) -> None:
        status, _h, body = self._register(payload=provenance_payload(materials=[]))
        self.assertEqual(status, "201 Created")
        self.assertEqual(body["materials"], [])

    def test_materials_keep_submission_order(self) -> None:
        payload = provenance_payload(
            materials=[
                {"name": "third", "digest": DIGEST_C},
                {"name": "first", "digest": DIGEST_A},
                {"name": "second", "digest": DIGEST_B},
            ]
        )
        _s, _h, body = self._register(payload=payload)
        self.assertEqual(
            [m["name"] for m in body["materials"]],
            ["third", "first", "second"],
        )

    def test_response_is_compact_utf8_newline_terminated(self) -> None:
        status, _headers, raw = call(
            "POST",
            f"/resources/{self.resource_id}/provenance",
            provenance_payload(
                builder="构建机",
                materials=[{"name": "库", "digest": DIGEST_A}],
            ),
        )
        self.assertEqual(status, "201 Created")
        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(b" ", raw[:-1])
        text = raw.decode("utf-8").rstrip("\n")
        keys = ['"id"', '"builder"', '"build_number"',
                '"source_digest"', '"materials"']
        positions = [text.index(k) for k in keys]
        self.assertEqual(positions, sorted(positions))

    # --- Query -------------------------------------------------------------

    def test_get_returns_registered_provenance(self) -> None:
        post = self._register()[2]
        status, _h, body = call_json(
            "GET", f"/resources/{self.resource_id}/provenance"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, post)

    def test_get_without_registration_is_404(self) -> None:
        status, _h, body = call_json(
            "GET", f"/resources/{self.resource_id}/provenance"
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "provenance_not_found")

    # --- Idempotency and conflicts ----------------------------------------

    def test_same_content_resubmitted_is_idempotent_200(self) -> None:
        first = self._register(payload=provenance_payload(
            builder="b", build_number="1", source_digest=DIGEST_A,
            materials=[{"name": "m", "digest": DIGEST_B}],
        ))
        self.assertEqual(first[0], "201 Created")
        second = self._register(payload=provenance_payload(
            builder="b", build_number="1", source_digest=DIGEST_A,
            materials=[{"name": "m", "digest": DIGEST_B}],
        ))
        self.assertEqual(second[0], "200 OK")
        self.assertEqual(second[2], first[2])

        # Mixed-case digests normalizing to the same record are the same.
        status, _h, _body = self._register(payload=provenance_payload(
            builder="b", build_number="1", source_digest="A" * 64,
            materials=[{"name": "m", "digest": "B" * 64}],
        ))
        self.assertEqual(status, "200 OK")

    def test_different_provenance_conflicts(self) -> None:
        base = provenance_payload(
            builder="b", build_number="1", source_digest=DIGEST_A,
            materials=[{"name": "m", "digest": DIGEST_B}],
        )
        original = self._register(payload=base)[2]
        variants = [
            provenance_payload(builder="other", build_number="1",
                               source_digest=DIGEST_A,
                               materials=[{"name": "m", "digest": DIGEST_B}]),
            provenance_payload(builder="b", build_number="2",
                               source_digest=DIGEST_A,
                               materials=[{"name": "m", "digest": DIGEST_B}]),
            provenance_payload(builder="b", build_number="1",
                               source_digest=DIGEST_C,
                               materials=[{"name": "m", "digest": DIGEST_B}]),
            provenance_payload(builder="b", build_number="1",
                               source_digest=DIGEST_A, materials=[]),
            provenance_payload(builder="b", build_number="1",
                               source_digest=DIGEST_A,
                               materials=[{"name": "other",
                                           "digest": DIGEST_B}]),
            # Same materials in a different order is different content.
            provenance_payload(builder="b", build_number="1",
                               source_digest=DIGEST_A,
                               materials=[
                                   {"name": "m", "digest": DIGEST_B},
                                   {"name": "n", "digest": DIGEST_C},
                               ]),
            provenance_payload(builder="b", build_number="1",
                               source_digest=DIGEST_A,
                               materials=[
                                   {"name": "n", "digest": DIGEST_C},
                                   {"name": "m", "digest": DIGEST_B},
                               ]),
        ]
        for payload in variants:
            with self.subTest(payload=payload):
                status, _h, body = self._register(payload=payload)
                self.assertEqual(status, "409 Conflict")
                self.assertEqual(body["error"], "provenance_conflict")

        # The original record is untouched.
        _s, _h, body = call_json(
            "GET", f"/resources/{self.resource_id}/provenance"
        )
        self.assertEqual(body, original)

    def test_one_record_per_resource_is_scoped(self) -> None:
        self._register(self.resource_id)
        self._register(
            self.other_id, payload=provenance_payload(builder="other-bot")
        )
        _s, _h, first = call_json(
            "GET", f"/resources/{self.resource_id}/provenance"
        )
        _s, _h, second = call_json(
            "GET", f"/resources/{self.other_id}/provenance"
        )
        self.assertEqual(first["builder"], "ci-bot")
        self.assertEqual(second["builder"], "other-bot")

    # --- Materials ---------------------------------------------------------

    def test_duplicate_material_is_400_and_stores_nothing(self) -> None:
        material = {"name": "m", "digest": DIGEST_A}
        status, _h, body = self._register(payload=provenance_payload(
            materials=[material, dict(material)]
        ))
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        _s, _h, get = call_json(
            "GET", f"/resources/{self.resource_id}/provenance"
        )
        self.assertEqual(get["error"], "provenance_not_found")

    def test_duplicate_material_matches_case_insensitively(self) -> None:
        status, _h, body = self._register(payload=provenance_payload(
            materials=[
                {"name": "m", "digest": "A" * 64},
                {"name": "m", "digest": "a" * 64},
            ]
        ))
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_same_name_different_digest_is_distinct(self) -> None:
        status, _h, _body = self._register(payload=provenance_payload(
            materials=[
                {"name": "m", "digest": DIGEST_A},
                {"name": "m", "digest": DIGEST_B},
            ]
        ))
        self.assertEqual(status, "201 Created")

    # --- Bad request: body -------------------------------------------------

    def test_missing_body_is_bad_request(self) -> None:
        status, _h, body = call_json(
            "POST", f"/resources/{self.resource_id}/provenance", None
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_malformed_or_bad_utf8_body_is_bad_request(self) -> None:
        path = f"/resources/{self.resource_id}/provenance"
        for raw in (b"{bad", b"\xff\xfe"):
            with self.subTest(raw=raw):
                status, _h, body = call_json("POST", path, raw)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_non_object_body_is_bad_request(self) -> None:
        for raw in (b"[]", b'"x"', b"42", b"null"):
            with self.subTest(raw=raw):
                status, _h, body = call_json(
                    "POST", f"/resources/{self.resource_id}/provenance", raw
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    # --- Bad request: fields -----------------------------------------------

    def test_missing_required_fields(self) -> None:
        fields = ("builder", "build_number", "source_digest", "materials")
        for field in fields:
            payload = provenance_payload()
            del payload[field]
            with self.subTest(field=field):
                status, _h, body = self._register(payload=payload)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_empty_object_is_bad_request(self) -> None:
        status, _h, body = self._register(payload={})
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_unknown_field_rejected(self) -> None:
        payload = provenance_payload()
        payload["extra"] = 1
        status, _h, body = self._register(payload=payload)
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_text_field_errors(self) -> None:
        for field in ("builder", "build_number"):
            for value in (1, None, True, "", [], {}):
                with self.subTest(field=field, value=value):
                    status, _h, body = self._register(
                        payload=provenance_payload(**{field: value})
                    )
                    self.assertEqual(status, "400 Bad Request")
                    self.assertEqual(body["error"], "invalid_request")

    def test_text_fields_limit_256_code_points(self) -> None:
        fresh = 0

        def fresh_id() -> str:
            nonlocal fresh
            fresh += 1
            return self._create(
                f"{fresh:064x}", name=f"r{fresh}"
            )

        for field in ("builder", "build_number"):
            payload = provenance_payload(**{field: "あ" * 257})
            with self.subTest(field=field):
                status, _h, body = self._register(
                    resource_id=fresh_id(), payload=payload
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")
            payload = provenance_payload(**{field: "あ" * 256})
            with self.subTest(field=field, ok=True):
                status, _h, _body = self._register(
                    resource_id=fresh_id(), payload=payload
                )
                self.assertEqual(status, "201 Created")

    def test_source_digest_errors(self) -> None:
        for value in (
            "a" * 63, "g" * 64, "A" * 65, "", 1, None, True,
        ):
            with self.subTest(value=value):
                status, _h, body = self._register(
                    payload=provenance_payload(source_digest=value)
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_materials_must_be_array(self) -> None:
        for value in ({}, "x", 1, None, True):
            with self.subTest(value=value):
                status, _h, body = self._register(
                    payload=provenance_payload(materials=value)
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_material_must_be_object(self) -> None:
        for bad in ([[]], ["x"], [1], [None], [[]]):
            with self.subTest(bad=bad):
                status, _h, body = self._register(
                    payload=provenance_payload(materials=bad)
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_material_field_errors(self) -> None:
        cases = [
            {},
            {"digest": DIGEST_A},
            {"name": "m"},
            {"name": "", "digest": DIGEST_A},
            {"name": 1, "digest": DIGEST_A},
            {"name": None, "digest": DIGEST_A},
            {"name": True, "digest": DIGEST_A},
            {"name": "m", "digest": ""},
            {"name": "m", "digest": 1},
            {"name": "m", "digest": None},
            {"name": "m", "digest": "a" * 63},
            {"name": "m", "digest": "g" * 64},
            {"name": "m", "digest": "A" * 65},
            {"name": "m", "digest": DIGEST_A, "extra": 1},
            {"name": "x" * 257, "digest": DIGEST_A},
        ]
        for material in cases:
            with self.subTest(material=material):
                status, _h, body = self._register(
                    payload=provenance_payload(materials=[material])
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_material_name_limit_256_code_points(self) -> None:
        status, _h, _body = self._register(
            payload=provenance_payload(
                materials=[{"name": "😀" * 256, "digest": DIGEST_A}]
            )
        )
        self.assertEqual(status, "201 Created")

    # --- Path, query, method, missing resource -----------------------------

    def test_empty_path_id_is_bad_request(self) -> None:
        for method, body in [
            ("GET", None),
            ("POST", provenance_payload()),
        ]:
            with self.subTest(method=method):
                status, _h, payload = call_json(
                    method, "/resources//provenance", body
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(payload["error"], "invalid_request")

    def test_path_id_with_separator_is_bad_request(self) -> None:
        for raw in ("a/b", "a\\b"):
            for method in ("GET", "POST"):
                with self.subTest(raw=raw, method=method):
                    status, _h, body = call_json(
                        method, f"/resources/{raw}/provenance"
                    )
                    self.assertIn(status[:3], {"400", "404"})
                    self.assertEqual(body["error"], "invalid_request")

    def test_query_parameters_rejected(self) -> None:
        for method, body in [
            ("GET", None),
            ("POST", provenance_payload()),
        ]:
            with self.subTest(method=method):
                status, _h, payload = call_json(
                    method,
                    f"/resources/{self.resource_id}/provenance",
                    body,
                    query_string="x=1",
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(payload["error"], "invalid_request")

    def test_missing_resource_is_404(self) -> None:
        for method, body in [
            ("GET", None),
            ("POST", provenance_payload()),
        ]:
            with self.subTest(method=method):
                status, _h, payload = call_json(
                    method, "/resources/missing/provenance", body
                )
                self.assertEqual(status, "404 Not Found")
                self.assertEqual(payload["error"], "resource_not_found")

    def test_unsupported_methods_return_405_with_allow(self) -> None:
        for method in ("PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, headers, body = call_json(
                    method, f"/resources/{self.resource_id}/provenance"
                )
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")
                self.assertIn(("Allow", "GET, POST"), headers)

    def test_failed_requests_leave_no_record(self) -> None:
        call_json(
            "POST", f"/resources/{self.resource_id}/provenance", b"not json"
        )
        self._register(payload=provenance_payload(builder=""))
        self._register(payload=provenance_payload(source_digest="x"))
        self._register(
            payload=provenance_payload(
                materials=[{"name": "m", "digest": DIGEST_A},
                           {"name": "m", "digest": DIGEST_A}]
            )
        )
        call_json("GET", "/resources/missing/provenance")
        _s, _h, body = call_json(
            "GET", f"/resources/{self.resource_id}/provenance"
        )
        self.assertEqual(body["error"], "provenance_not_found")

    def test_failed_conflict_does_not_change_other_state(self) -> None:
        self._register(payload=provenance_payload(builder="first"))
        self._register(payload=provenance_payload(builder="second"))
        # Resource itself and unrelated endpoints remain intact.
        status, _h, body = call_json(
            "GET", f"/resources/{self.resource_id}"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["id"], self.resource_id)
        _s, _h, prov = call_json(
            "GET", f"/resources/{self.resource_id}/provenance"
        )
        self.assertEqual(prov["builder"], "first")


if __name__ == "__main__":
    unittest.main()
