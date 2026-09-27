from __future__ import annotations

import io
import json
import unittest

from provenance_api.app import application, reset_state

PATH = "/provenance"

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_M1 = "1" * 64
DIGEST_M2 = "2" * 64


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
    content_type: str | None = None,
    content_length: int | str | None = None,
    omit_content_length: bool = False,
) -> tuple[str, list[tuple[str, str]], object]:
    status, headers, raw = call(
        method,
        path,
        body,
        query_string=query_string,
        content_type=content_type,
        content_length=content_length,
        omit_content_length=omit_content_length,
    )
    return status, headers, json.loads(raw.decode("utf-8"))


class GlobalProvenanceSummaryTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def _create(self, digest: str, name: str) -> str:
        _s, _h, body = call_json(
            "POST",
            "/resources",
            {"name": name, "category": "code", "digest": digest},
        )
        return str(body["id"])  # type: ignore[index]

    def _register_provenance(
        self,
        resource_id: str,
        *,
        builder: str = "ci-bot",
        build_number: str = "build-1",
        source_digest: str = DIGEST_A,
        materials: list[dict[str, str]] | None = None,
    ) -> None:
        payload: dict[str, object] = {
            "builder": builder,
            "build_number": build_number,
            "source_digest": source_digest,
            "materials": materials if materials is not None else [],
        }
        status, _h, body = call_json(
            "POST", f"/resources/{resource_id}/provenance", payload
        )
        assert status in ("201 Created", "200 OK"), body

    def _summary(
        self, query_string: str | None = None
    ) -> list[dict[str, object]]:
        status, headers, raw = call("GET", PATH, query_string=query_string)
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

    def test_empty_when_no_provenance(self) -> None:
        self._create(DIGEST_A, "r1")
        self.assertEqual(self._summary(), [])

    def test_record_key_order_and_fields(self) -> None:
        resource_id = self._create(DIGEST_A, "r1")
        self._register_provenance(
            resource_id,
            builder="CI-Bot",
            build_number="42",
            source_digest="A" * 64,
            materials=[
                {"name": "openssl", "digest": "B" * 64},
                {"name": "zlib", "digest": "C" * 64},
            ],
        )

        status, _h, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        text = raw.decode("utf-8").rstrip("\n")
        # Compact UTF-8: no added whitespace.
        self.assertNotIn(" ", text)

        entry = self._summary()[0]
        self.assertEqual(
            list(entry),
            ["id", "builder", "build_number", "source_digest", "materials"],
        )
        self.assertEqual(entry["id"], resource_id)
        self.assertEqual(entry["builder"], "CI-Bot")
        self.assertEqual(entry["build_number"], "42")
        # Source digest is echoed back in lowercase.
        self.assertEqual(entry["source_digest"], "a" * 64)
        materials = entry["materials"]
        self.assertEqual(
            [list(material) for material in materials],  # type: ignore[arg-type]
            [["name", "digest"], ["name", "digest"]],
        )
        self.assertEqual(
            materials,
            [
                {"name": "openssl", "digest": "b" * 64},
                {"name": "zlib", "digest": "c" * 64},
            ],
        )

    def test_materials_keep_registration_order(self) -> None:
        resource_id = self._create(DIGEST_A, "r1")
        self._register_provenance(
            resource_id,
            materials=[
                {"name": "second", "digest": DIGEST_M2},
                {"name": "first", "digest": DIGEST_M1},
            ],
        )
        entry = self._summary()[0]
        self.assertEqual(
            [material["name"] for material in entry["materials"]],  # type: ignore[index]
            ["second", "first"],
        )

    # --- Ordering ----------------------------------------------------------

    def test_entries_follow_resource_registration_order(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")

        # Provenance is registered in the opposite resource order; the
        # summary must still unfold r1's record first.
        self._register_provenance(r2, builder="bot-2", build_number="2")
        self._register_provenance(r1, builder="bot-1", build_number="1")

        summary = self._summary()
        self.assertEqual(
            [(item["id"], item["builder"]) for item in summary],
            [(r1, "bot-1"), (r2, "bot-2")],
        )

    def test_resources_without_provenance_are_skipped_silently(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        self._create(DIGEST_B, "r2")
        self._register_provenance(r1)

        summary = self._summary()
        self.assertEqual([item["id"] for item in summary], [r1])

    def test_each_resource_appears_at_most_once(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        self._register_provenance(r1)
        # An idempotent repeat registration must not create a second entry.
        self._register_provenance(r1)
        summary = self._summary()
        self.assertEqual([item["id"] for item in summary], [r1])

    # --- builder filter ----------------------------------------------------

    def test_builder_filter_matches_exactly(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        r3 = self._create(DIGEST_C, "r3")
        self._register_provenance(r1, builder="ci-bot")
        self._register_provenance(r2, builder="release-bot")
        self._register_provenance(r3, builder="ci-bot")

        summary = self._summary("builder=ci-bot")
        self.assertEqual(
            [item["id"] for item in summary],
            [r1, r3],
        )

    def test_builder_filter_is_case_sensitive_and_untrimmed(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        self._register_provenance(r1, builder="CI-Bot")
        self.assertEqual(self._summary("builder=ci-bot"), [])
        self.assertEqual(self._summary("builder=CI-BOT"), [])
        self.assertEqual(self._summary("builder=%20CI-Bot"), [])
        self.assertEqual(self._summary("builder=CI-Bot%20"), [])

    def test_builder_filter_without_hits_returns_empty_array(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        self._register_provenance(r1, builder="ci-bot")
        status, _h, raw = call("GET", PATH, query_string="builder=nope")
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

    def test_empty_builder_value_rejected(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        self._register_provenance(r1)
        for query in ("builder=", "builder=&x=1"):
            with self.subTest(query=query):
                status, _h, body = call_json("GET", PATH, query_string=query)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_unknown_or_repeated_parameter_rejected(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        self._register_provenance(r1)
        for query in (
            "bogus=1",
            "x=",
            "builder=ci-bot&bogus=1",
            "builder=ci-bot&builder=ci-bot",
            "builder=ci-bot&builder=other",
        ):
            with self.subTest(query=query):
                status, _h, body = call_json("GET", PATH, query_string=query)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_invalid_request_does_not_read_business_data(self) -> None:
        # An illegal request is answered identically with no records at all.
        status, _h, raw = call("GET", PATH, query_string="bogus=1")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(json.loads(raw)["error"], "invalid_request")

    # --- Recomputation -----------------------------------------------------

    def test_recomputes_after_new_registration(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        self._register_provenance(r1)
        self.assertEqual([i["id"] for i in self._summary()], [r1])
        self._register_provenance(r2)
        self.assertEqual([i["id"] for i in self._summary()], [r1, r2])

    def test_resource_deregistration_removes_its_entries_keeps_rest(
        self,
    ) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        r3 = self._create(DIGEST_C, "r3")
        self._register_provenance(r1)
        self._register_provenance(r2)
        self._register_provenance(r3)

        status, _h, _b = call("DELETE", f"/resources/{r2}")
        self.assertEqual(status, "200 OK")

        summary = self._summary()
        self.assertEqual([item["id"] for item in summary], [r1, r3])

    def test_view_is_read_only(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        self._register_provenance(r1)
        first_status, _h, first = call("GET", PATH)
        second_status, _h, second = call("GET", PATH)
        self.assertEqual(first_status, second_status)
        self.assertEqual(first, second)

    def test_per_resource_views_unchanged(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        self._register_provenance(
            r1,
            builder="ci-bot",
            build_number="7",
            source_digest="A" * 64,
            materials=[{"name": "openssl", "digest": "B" * 64}],
        )

        # The global summary does not disturb the per-resource provenance.
        self._summary()
        status, _h, body = call_json(
            "GET", f"/resources/{r1}/provenance"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["id"], r1)  # type: ignore[index]
        self.assertEqual(body["builder"], "ci-bot")  # type: ignore[index]
        self.assertEqual(body["build_number"], "7")  # type: ignore[index]
        self.assertEqual(  # type: ignore[index]
            body["source_digest"], "a" * 64
        )
        self.assertEqual(  # type: ignore[index]
            body["materials"],
            [{"name": "openssl", "digest": "b" * 64}],
        )

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

    def test_non_empty_body_rejected(self) -> None:
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
        # Compact separators: re-dumping with the service's separators
        # reproduces the body byte-for-byte.
        self.assertEqual(
            text,
            json.dumps(decoded, ensure_ascii=False, separators=(",", ":")),
        )


if __name__ == "__main__":
    unittest.main()
