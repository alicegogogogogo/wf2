from __future__ import annotations

import io
import json
import unittest

from provenance_api.app import application, reset_state

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_D = "d" * 64


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


class ProvenanceMaterialsTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def _create(
        self, digest: str, name: str = "r", category: str = "code"
    ) -> str:
        _s, _h, body = call_json(
            "POST",
            "/resources",
            {"name": name, "category": category, "digest": digest},
        )
        return str(body["id"])

    def _register(
        self,
        resource_id: str,
        materials: list[dict[str, str]],
        *,
        builder: str = "ci-bot",
    ) -> None:
        status, _h, _body = call_json(
            "POST",
            f"/resources/{resource_id}/provenance",
            {
                "builder": builder,
                "build_number": "build-001",
                "source_digest": DIGEST_A,
                "materials": materials,
            },
        )
        self.assertEqual(status, "201 Created")

    def _depend(self, resource_id: str, dependency_id: str) -> None:
        status, _h, _body = call_json(
            "POST",
            f"/resources/{resource_id}/dependencies",
            {"dependency_id": dependency_id},
        )
        self.assertEqual(status, "201 Created")

    def _check(
        self, resource_id: str, **kwargs: object
    ) -> tuple[str, list[tuple[str, str]], dict[str, object]]:
        return call_json(
            "GET", f"/resources/{resource_id}/provenance/materials", **kwargs
        )

    # --- Happy path --------------------------------------------------------

    def test_empty_materials(self) -> None:
        root = self._create(DIGEST_A)
        self._register(root, [])
        status, _h, body = self._check(root)
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            body,
            {
                "id": root,
                "all_resolved": True,
                "material_count": 0,
                "resolved_count": 0,
                "materials": [],
            },
        )

    def test_resolved_material(self) -> None:
        dep = self._create(DIGEST_B, name="openssl")
        root = self._create(DIGEST_A)
        self._depend(root, dep)
        self._register(root, [{"name": "openssl", "digest": DIGEST_B}])
        status, _h, body = self._check(root)
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["all_resolved"], True)
        self.assertEqual(body["material_count"], 1)
        self.assertEqual(body["resolved_count"], 1)
        self.assertEqual(
            body["materials"],
            [
                {
                    "name": "openssl",
                    "digest": DIGEST_B,
                    "status": "resolved",
                    "candidates": [dep],
                    "dependency_matches": [dep],
                }
            ],
        )

    def test_transitive_dependency_resolves(self) -> None:
        leaf = self._create(DIGEST_C, name="zlib")
        mid = self._create(DIGEST_B, name="mid")
        root = self._create(DIGEST_A)
        self._depend(root, mid)
        self._depend(mid, leaf)
        self._register(root, [{"name": "zlib", "digest": DIGEST_C}])
        _s, _h, body = self._check(root)
        self.assertEqual(body["materials"][0]["status"], "resolved")
        self.assertEqual(body["materials"][0]["dependency_matches"], [leaf])
        self.assertEqual(body["all_resolved"], True)

    def test_missing_material(self) -> None:
        root = self._create(DIGEST_A)
        self._register(root, [{"name": "ghost", "digest": DIGEST_B}])
        _s, _h, body = self._check(root)
        self.assertEqual(
            body["materials"],
            [
                {
                    "name": "ghost",
                    "digest": DIGEST_B,
                    "status": "missing",
                    "candidates": [],
                    "dependency_matches": [],
                }
            ],
        )
        self.assertEqual(body["resolved_count"], 0)
        self.assertEqual(body["all_resolved"], False)

    def test_candidate_outside_dependency(self) -> None:
        other = self._create(DIGEST_B, name="openssl")
        root = self._create(DIGEST_A)
        self._register(root, [{"name": "openssl", "digest": DIGEST_B}])
        _s, _h, body = self._check(root)
        self.assertEqual(
            body["materials"][0],
            {
                "name": "openssl",
                "digest": DIGEST_B,
                "status": "outside_dependency",
                "candidates": [other],
                "dependency_matches": [],
            },
        )
        self.assertEqual(body["all_resolved"], False)

    def test_root_itself_is_not_a_dependency(self) -> None:
        root = self._create(DIGEST_A, name="selfish")
        self._register(root, [{"name": "selfish", "digest": DIGEST_A}])
        _s, _h, body = self._check(root)
        self.assertEqual(body["materials"][0]["status"], "outside_dependency")
        self.assertEqual(body["materials"][0]["candidates"], [root])
        self.assertEqual(body["materials"][0]["dependency_matches"], [])

    def test_ambiguous_material(self) -> None:
        # Same name and digest: distinct registrations need distinct
        # categories (the registry keys on category, name and digest).
        first = self._create(DIGEST_B, name="dup")
        second = self._create(DIGEST_B, name="dup", category="model")
        root = self._create(DIGEST_A)
        self._depend(root, first)
        self._depend(root, second)
        self._register(root, [{"name": "dup", "digest": DIGEST_B}])
        _s, _h, body = self._check(root)
        self.assertEqual(body["materials"][0]["status"], "ambiguous")
        self.assertEqual(
            body["materials"][0]["candidates"], [first, second]
        )
        self.assertEqual(
            body["materials"][0]["dependency_matches"], [first, second]
        )
        self.assertEqual(body["resolved_count"], 0)
        self.assertEqual(body["all_resolved"], False)

    def test_candidates_follow_registration_order(self) -> None:
        first = self._create(DIGEST_B, name="lib")
        second = self._create(DIGEST_B, name="lib", category="model")
        third = self._create(DIGEST_B, name="lib", category="dataset")
        root = self._create(DIGEST_A)
        self._register(root, [{"name": "lib", "digest": DIGEST_B}])
        _s, _h, body = self._check(root)
        self.assertEqual(
            body["materials"][0]["candidates"], [first, second, third]
        )
        self.assertEqual(body["materials"][0]["status"], "outside_dependency")

    def test_mixed_statuses_and_counts(self) -> None:
        dep = self._create(DIGEST_B, name="resolved-lib")
        outsider = self._create(DIGEST_C, name="outside-lib")
        root = self._create(DIGEST_A)
        self._depend(root, dep)
        self._register(
            root,
            [
                {"name": "resolved-lib", "digest": DIGEST_B},
                {"name": "missing-lib", "digest": DIGEST_D},
                {"name": "outside-lib", "digest": DIGEST_C},
            ],
        )
        _s, _h, body = self._check(root)
        self.assertEqual(body["material_count"], 3)
        self.assertEqual(body["resolved_count"], 1)
        self.assertEqual(body["all_resolved"], False)
        self.assertEqual(
            [m["status"] for m in body["materials"]],
            ["resolved", "missing", "outside_dependency"],
        )
        self.assertEqual(body["materials"][2]["candidates"], [outsider])

    def test_materials_keep_submission_order(self) -> None:
        root = self._create(DIGEST_A)
        self._register(
            root,
            [
                {"name": "third", "digest": DIGEST_C},
                {"name": "first", "digest": DIGEST_A},
                {"name": "second", "digest": DIGEST_B},
            ],
        )
        _s, _h, body = self._check(root)
        self.assertEqual(
            [m["name"] for m in body["materials"]],
            ["third", "first", "second"],
        )

    # --- Matching rules ----------------------------------------------------

    def test_name_matching_is_case_sensitive_and_untrimmed(self) -> None:
        dep = self._create(DIGEST_B, name="OpenSSL")
        spaced = self._create(DIGEST_C, name=" openssl")
        root = self._create(DIGEST_A)
        self._depend(root, dep)
        self._depend(root, spaced)
        self._register(
            root,
            [
                {"name": "openssl", "digest": DIGEST_B},
                {"name": "openssl", "digest": DIGEST_C},
            ],
        )
        _s, _h, body = self._check(root)
        # "OpenSSL" and " openssl" never match a verbatim "openssl".
        self.assertEqual(body["materials"][0]["status"], "missing")
        self.assertEqual(body["materials"][1]["status"], "missing")

    def test_digest_matching_is_case_insensitive(self) -> None:
        dep = self._create("B" * 64, name="openssl")
        root = self._create(DIGEST_A)
        self._depend(root, dep)
        self._register(root, [{"name": "openssl", "digest": DIGEST_B}])
        _s, _h, body = self._check(root)
        self.assertEqual(body["materials"][0]["status"], "resolved")
        self.assertEqual(body["materials"][0]["dependency_matches"], [dep])

    def test_same_name_different_digest_is_not_a_candidate(self) -> None:
        self._create(DIGEST_C, name="openssl")
        root = self._create(DIGEST_A)
        self._register(root, [{"name": "openssl", "digest": DIGEST_B}])
        _s, _h, body = self._check(root)
        self.assertEqual(body["materials"][0]["status"], "missing")
        self.assertEqual(body["materials"][0]["candidates"], [])

    # --- Recomputation -----------------------------------------------------

    def test_recomputed_after_dependency_changes(self) -> None:
        dep = self._create(DIGEST_B, name="openssl")
        root = self._create(DIGEST_A)
        self._register(root, [{"name": "openssl", "digest": DIGEST_B}])

        _s, _h, body = self._check(root)
        self.assertEqual(body["materials"][0]["status"], "outside_dependency")

        self._depend(root, dep)
        _s, _h, body = self._check(root)
        self.assertEqual(body["materials"][0]["status"], "resolved")
        self.assertEqual(body["all_resolved"], True)

        status, _h, _body = call_json(
            "DELETE", f"/resources/{root}/dependencies/{dep}"
        )
        self.assertEqual(status, "200 OK")
        _s, _h, body = self._check(root)
        self.assertEqual(body["materials"][0]["status"], "outside_dependency")
        self.assertEqual(body["all_resolved"], False)

    def test_recomputed_after_resource_removal(self) -> None:
        dep = self._create(DIGEST_B, name="openssl")
        root = self._create(DIGEST_A)
        self._depend(root, dep)
        self._register(root, [{"name": "openssl", "digest": DIGEST_B}])
        _s, _h, body = self._check(root)
        self.assertEqual(body["materials"][0]["status"], "resolved")

        status, _h, _body = call_json("DELETE", f"/resources/{dep}")
        self.assertEqual(status, "200 OK")
        _s, _h, body = self._check(root)
        self.assertEqual(body["materials"][0]["status"], "missing")
        self.assertEqual(body["materials"][0]["candidates"], [])

    def test_query_does_not_write_or_materialize(self) -> None:
        dep = self._create(DIGEST_B, name="openssl")
        root = self._create(DIGEST_A)
        self._depend(root, dep)
        self._register(root, [{"name": "openssl", "digest": DIGEST_B}])
        self._check(root)
        self._check(root)
        # The provenance record and the dependency graph are untouched.
        _s, _h, prov = call_json("GET", f"/resources/{root}/provenance")
        self.assertEqual(
            prov["materials"], [{"name": "openssl", "digest": DIGEST_B}]
        )
        _s, _h, deps = call_json("GET", f"/resources/{root}/dependencies")
        self.assertEqual(deps["dependencies"], [dep])

    # --- Envelope ------------------------------------------------------------

    def test_response_is_compact_utf8_newline_terminated(self) -> None:
        dep = self._create(DIGEST_B, name="库")
        root = self._create(DIGEST_A)
        self._depend(root, dep)
        self._register(root, [{"name": "库", "digest": DIGEST_B}])
        status, headers, raw = call(
            "GET", f"/resources/{root}/provenance/materials"
        )
        self.assertEqual(status, "200 OK")
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )
        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(b" ", raw[:-1])
        text = raw.decode("utf-8").rstrip("\n")
        keys = [
            '"id"',
            '"all_resolved"',
            '"material_count"',
            '"resolved_count"',
            '"materials"',
        ]
        positions = [text.index(k) for k in keys]
        self.assertEqual(positions, sorted(positions))
        item_keys = [
            '"name"',
            '"digest"',
            '"status"',
            '"candidates"',
            '"dependency_matches"',
        ]
        item_positions = [text.index(k) for k in item_keys]
        self.assertEqual(item_positions, sorted(item_positions))

    # --- Bad request, not found, method ------------------------------------

    def test_empty_path_id_is_bad_request(self) -> None:
        status, _h, body = call_json(
            "GET", "/resources//provenance/materials"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_path_id_with_separator_is_bad_request(self) -> None:
        for raw in ("a/b", "a\\b"):
            with self.subTest(raw=raw):
                status, _h, body = call_json(
                    "GET", f"/resources/{raw}/provenance/materials"
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_query_parameters_rejected(self) -> None:
        root = self._create(DIGEST_A)
        self._register(root, [])
        for query in ("x=1", "builder=ci-bot"):
            with self.subTest(query=query):
                status, _h, body = self._check(root, query_string=query)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_non_empty_body_rejected(self) -> None:
        root = self._create(DIGEST_A)
        self._register(root, [])
        for raw in (b"{}", b"not json", b"\xff\xfe"):
            with self.subTest(raw=raw):
                status, _h, body = call_json(
                    "GET", f"/resources/{root}/provenance/materials", raw
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_missing_resource_is_404(self) -> None:
        status, _h, body = call_json(
            "GET", "/resources/missing/provenance/materials"
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

    def test_missing_provenance_is_404(self) -> None:
        root = self._create(DIGEST_A)
        status, _h, body = self._check(root)
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "provenance_not_found")

    def test_unsupported_methods_return_405_with_allow(self) -> None:
        root = self._create(DIGEST_A)
        self._register(root, [])
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, headers, body = call_json(
                    method, f"/resources/{root}/provenance/materials"
                )
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")
                self.assertIn(("Allow", "GET"), headers)

    def test_failed_requests_leave_no_trace(self) -> None:
        root = self._create(DIGEST_A)
        call_json("GET", f"/resources/{root}/provenance/materials", b"{}")
        call_json(
            "GET", f"/resources/{root}/provenance/materials",
            query_string="x=1",
        )
        call_json("POST", f"/resources/{root}/provenance/materials")
        call_json("GET", "/resources/missing/provenance/materials")
        # Nothing was recorded: provenance is still unregistered.
        status, _h, body = self._check(root)
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "provenance_not_found")


if __name__ == "__main__":
    unittest.main()
