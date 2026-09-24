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

    def _materials(self, *digests: str) -> list[dict[str, str]]:
        return [
            {"name": f"mat-{i}", "digest": digest}
            for i, digest in enumerate(digests)
        ]

    def _provenance(
        self,
        resource_id: str | None = None,
        *,
        builder: object = "ci-bot",
        build_id: object = "42",
        source_digest: object = ...,  # type: ignore[assignment]
        materials: object = ...,  # type: ignore[assignment]
    ):
        if source_digest is ...:
            source_digest = DIGEST_A
        if materials is ...:
            materials = self._materials(DIGEST_A, DIGEST_B)
        target = self.resource_id if resource_id is None else resource_id
        return call_json(
            "POST",
            f"/resources/{target}/provenance",
            {
                "builder": builder,
                "build_id": build_id,
                "source_digest": source_digest,
                "materials": materials,
            },
        )

    # --- Registration ------------------------------------------------------

    def test_register_returns_201_and_echoes_fields(self) -> None:
        status, headers, body = self._provenance(
            builder="release-bot",
            build_id="run-7",
            source_digest=DIGEST_C,
            materials=self._materials(DIGEST_C),
        )
        self.assertEqual(status, "201 Created")
        self.assertEqual(
            headers[0], ("Content-Type", "application/json; charset=utf-8")
        )
        self.assertEqual(
            set(body),
            {"id", "builder", "build_id", "source_digest", "materials"},
        )
        self.assertEqual(body["id"], self.resource_id)
        self.assertEqual(body["builder"], "release-bot")
        self.assertEqual(body["build_id"], "run-7")
        self.assertEqual(body["source_digest"], "c" * 64)
        self.assertEqual(
            body["materials"],
            [{"name": "mat-0", "digest": "c" * 64}],
        )

    def test_digests_are_normalized_to_lowercase(self) -> None:
        _s, _h, body = self._provenance(
            source_digest="AbC" + "0" * 61,
            materials=[{"name": "m", "digest": "AbC" + "0" * 61}],
        )
        self.assertEqual(body["source_digest"], "abc" + "0" * 61)
        self.assertEqual(body["materials"][0]["digest"], "abc" + "0" * 61)

    def test_empty_materials_is_valid(self) -> None:
        status, _h, body = self._provenance(materials=[])
        self.assertEqual(status, "201 Created")
        self.assertEqual(body["materials"], [])

    def test_materials_keep_submission_order(self) -> None:
        _s, _h, body = self._provenance(
            materials=self._materials(DIGEST_C, DIGEST_A, DIGEST_B)
        )
        self.assertEqual(
            [m["digest"] for m in body["materials"]],
            ["c" * 64, DIGEST_A, DIGEST_B],
        )

    def test_same_name_different_digest_is_distinct(self) -> None:
        status, _h, _body = self._provenance(
            materials=[
                {"name": "m", "digest": DIGEST_A},
                {"name": "m", "digest": DIGEST_B},
            ]
        )
        self.assertEqual(status, "201 Created")

    def test_response_is_compact_utf8_newline_terminated(self) -> None:
        status, _headers, raw = call(
            "POST",
            f"/resources/{self.resource_id}/provenance",
            {
                "builder": "构建者",
                "build_id": "1",
                "source_digest": DIGEST_A,
                "materials": [],
            },
        )
        self.assertEqual(status, "201 Created")
        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(b" ", raw[:-1])
        text = raw.decode("utf-8").rstrip("\n")
        keys = [
            '"id"',
            '"builder"',
            '"build_id"',
            '"source_digest"',
            '"materials"',
        ]
        positions = [text.index(k) for k in keys]
        self.assertEqual(positions, sorted(positions))

    def test_text_length_bound_is_code_points(self) -> None:
        # Each astral-plane code point is one code point but four UTF-8
        # bytes; the bound counts code points, so 256 is valid.
        long_text = "😀" * 256
        status, _h, body = self._provenance(builder=long_text)
        self.assertEqual(status, "201 Created")
        self.assertEqual(body["builder"], long_text)

    # --- Query -------------------------------------------------------------

    def test_get_returns_registered_record(self) -> None:
        post = self._provenance()[2]
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
        first = self._provenance(
            source_digest=DIGEST_A,
            materials=self._materials(DIGEST_A, DIGEST_B),
        )
        self.assertEqual(first[0], "201 Created")
        second = self._provenance(
            source_digest=DIGEST_A,
            materials=self._materials(DIGEST_A, DIGEST_B),
        )
        self.assertEqual(second[0], "200 OK")
        self.assertEqual(second[2], first[2])

        # Mixed-case digests that normalize to the same record are equal.
        status, _h, _body = self._provenance(
            source_digest="A" * 64,
            materials=[{"name": "mat-0", "digest": "A" * 64},
                       {"name": "mat-1", "digest": "B" * 64}],
        )
        self.assertEqual(status, "200 OK")

    def test_different_content_conflicts(self) -> None:
        original = self._provenance(
            source_digest=DIGEST_A,
            materials=self._materials(DIGEST_A, DIGEST_B),
        )[2]
        for payload in (
            {"builder": "other", "build_id": "42",
             "source_digest": DIGEST_A,
             "materials": self._materials(DIGEST_A, DIGEST_B)},
            {"builder": "ci-bot", "build_id": "43",
             "source_digest": DIGEST_A,
             "materials": self._materials(DIGEST_A, DIGEST_B)},
            {"builder": "ci-bot", "build_id": "42",
             "source_digest": DIGEST_B,
             "materials": self._materials(DIGEST_A, DIGEST_B)},
            # A different material digest.
            {"builder": "ci-bot", "build_id": "42",
             "source_digest": DIGEST_A,
             "materials": self._materials(DIGEST_A, DIGEST_C)},
            # An added material.
            {"builder": "ci-bot", "build_id": "42",
             "source_digest": DIGEST_A,
             "materials": self._materials(DIGEST_A)},
            # Empty vs non-empty materials.
            {"builder": "ci-bot", "build_id": "42",
             "source_digest": DIGEST_A, "materials": []},
            # Same materials but reordered: submission order is significant.
            {"builder": "ci-bot", "build_id": "42",
             "source_digest": DIGEST_A,
             "materials": self._materials(DIGEST_B, DIGEST_A)},
        ):
            with self.subTest(payload=payload):
                status, _h, body = call_json(
                    "POST",
                    f"/resources/{self.resource_id}/provenance",
                    payload,
                )
                self.assertEqual(status, "409 Conflict")
                self.assertEqual(body["error"], "provenance_conflict")

        # The original record is untouched.
        _s, _h, body = call_json(
            "GET", f"/resources/{self.resource_id}/provenance"
        )
        self.assertEqual(body, original)

    def test_one_record_per_resource_is_scoped(self) -> None:
        self._provenance(resource_id=self.resource_id, builder="a")
        self._provenance(resource_id=self.other_id, builder="b")
        _s, _h, first = call_json(
            "GET", f"/resources/{self.resource_id}/provenance"
        )
        _s, _h, second = call_json(
            "GET", f"/resources/{self.other_id}/provenance"
        )
        self.assertEqual(first["builder"], "a")
        self.assertEqual(second["builder"], "b")

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
                    "POST",
                    f"/resources/{self.resource_id}/provenance",
                    raw,
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    # --- Bad request: fields -----------------------------------------------

    def test_missing_required_fields(self) -> None:
        complete = {
            "builder": "b",
            "build_id": "1",
            "source_digest": DIGEST_A,
            "materials": [],
        }
        for field in ("builder", "build_id", "source_digest", "materials"):
            partial = dict(complete)
            del partial[field]
            with self.subTest(field=field):
                status, _h, body = call_json(
                    "POST",
                    f"/resources/{self.resource_id}/provenance",
                    partial,
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_unknown_field_rejected(self) -> None:
        status, _h, body = call_json(
            "POST",
            f"/resources/{self.resource_id}/provenance",
            {
                "builder": "b",
                "build_id": "1",
                "source_digest": DIGEST_A,
                "materials": [],
                "extra": 1,
            },
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_builder_and_build_id_errors(self) -> None:
        for bad in ("", 1, None, True, ["x"], "x" * 257, "😀" * 257):
            for field in ("builder", "build_id"):
                with self.subTest(field=field, bad=bad):
                    status, _h, body = self._provenance(**{field: bad})
                    self.assertEqual(status, "400 Bad Request")
                    self.assertEqual(body["error"], "invalid_request")

    def test_source_digest_errors(self) -> None:
        for bad in (
            "",
            "a" * 63,
            "a" * 65,
            "g" * 64,
            "A" * 63 + "G",
            1,
            None,
            True,
            ["x"],
        ):
            with self.subTest(bad=bad):
                status, _h, body = self._provenance(source_digest=bad)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_materials_must_be_array(self) -> None:
        for bad in ({}, "x", 1, None, True):
            with self.subTest(bad=bad):
                status, _h, body = self._provenance(materials=bad)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_material_must_be_object(self) -> None:
        for bad in ([[]], [["x"]], ["x"], [1], [None]):
            with self.subTest(bad=bad):
                status, _h, body = self._provenance(materials=bad)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_material_field_errors(self) -> None:
        good = {"name": "m", "digest": DIGEST_A}
        cases = [
            {},
            {"digest": DIGEST_A},
            {"name": "m"},
            {"name": "", "digest": DIGEST_A},
            {"name": 1, "digest": DIGEST_A},
            {"name": None, "digest": DIGEST_A},
            {"name": "x" * 257, "digest": DIGEST_A},
            {"name": "😀" * 257, "digest": DIGEST_A},
            {"name": "m", "digest": ""},
            {"name": "m", "digest": 1},
            {"name": "m", "digest": None},
            {"name": "m", "digest": "a" * 63},
            {"name": "m", "digest": "g" * 64},
            {"name": "m", "digest": "A" * 65},
            {"name": "m", "digest": DIGEST_A, "extra": 1},
        ]
        for material in cases:
            with self.subTest(material=material):
                status, _h, body = self._provenance(materials=[material])
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_duplicate_material_is_bad_request(self) -> None:
        material = {"name": "m", "digest": DIGEST_A}
        status, _h, body = self._provenance(
            materials=[material, dict(material)]
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        # Nothing was stored.
        _s, _h, get = call_json(
            "GET", f"/resources/{self.resource_id}/provenance"
        )
        self.assertEqual(get["error"], "provenance_not_found")

    def test_duplicate_material_with_mixed_case_is_bad_request(self) -> None:
        status, _h, body = self._provenance(
            materials=[
                {"name": "m", "digest": "A" * 64},
                {"name": "m", "digest": "a" * 64},
            ]
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    # --- Path, query, method, missing resource -----------------------------

    def test_empty_path_id_is_bad_request(self) -> None:
        for method, body in [
            ("GET", None),
            ("POST", {
                "builder": "b", "build_id": "1",
                "source_digest": DIGEST_A, "materials": [],
            }),
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
            ("POST", {
                "builder": "b", "build_id": "1",
                "source_digest": DIGEST_A, "materials": [],
            }),
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
        valid = {
            "builder": "b",
            "build_id": "1",
            "source_digest": DIGEST_A,
            "materials": [],
        }
        for method, body in [("GET", None), ("POST", valid)]:
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
        valid = {
            "builder": "b",
            "build_id": "1",
            "source_digest": DIGEST_A,
            "materials": [],
        }
        # Invalid body shapes and field errors.
        call_json(
            "POST", f"/resources/{self.resource_id}/provenance", b"not json"
        )
        bad = dict(valid)
        bad["builder"] = ""
        call_json("POST", f"/resources/{self.resource_id}/provenance", bad)
        call_json(
            "POST",
            f"/resources/{self.resource_id}/provenance",
            {
                "builder": "b", "build_id": "1",
                "source_digest": DIGEST_A,
                "materials": [
                    {"name": "m", "digest": DIGEST_A},
                    {"name": "m", "digest": DIGEST_A},
                ],
            },
        )
        call_json("GET", "/resources/missing/provenance")

        _s, _h, body = call_json(
            "GET", f"/resources/{self.resource_id}/provenance"
        )
        self.assertEqual(body["error"], "provenance_not_found")

    def test_conflict_does_not_overwrite_or_touch_other_state(self) -> None:
        first = self._provenance(builder="original")[2]
        # A conflicting write must not replace the record.
        self._provenance(builder="intruder")
        _s, _h, body = call_json(
            "GET", f"/resources/{self.resource_id}/provenance"
        )
        self.assertEqual(body, first)
        # The other resource still has no record.
        _s, _h, other = call_json(
            "GET", f"/resources/{self.other_id}/provenance"
        )
        self.assertEqual(other["error"], "provenance_not_found")


if __name__ == "__main__":
    unittest.main()
