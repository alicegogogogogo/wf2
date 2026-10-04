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
    content_length: str | None = None,
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
        "CONTENT_LENGTH": (
            content_length if content_length is not None else str(len(payload))
        ),
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

    def _register_provenance(
        self, resource_id: str, materials: list[dict[str, str]]
    ) -> None:
        status, _h, _b = call_json(
            "POST",
            f"/resources/{resource_id}/provenance",
            {
                "builder": "ci-bot",
                "build_number": "build-001",
                "source_digest": DIGEST_A,
                "materials": materials,
            },
        )
        self.assertEqual(status, "201 Created")

    def _depend(self, resource_id: str, dependency_id: str) -> None:
        status, _h, _b = call_json(
            "POST",
            f"/resources/{resource_id}/dependencies",
            {"dependency_id": dependency_id},
        )
        self.assertEqual(status, "201 Created")

    def _get(
        self, resource_id: str, **kwargs: object
    ) -> tuple[str, list[tuple[str, str]], bytes]:
        return call(
            "GET", f"/resources/{resource_id}/provenance/materials", **kwargs
        )

    def _get_json(
        self, resource_id: str, **kwargs: object
    ) -> tuple[str, list[tuple[str, str]], dict[str, object]]:
        status, headers, raw = self._get(resource_id, **kwargs)
        return status, headers, json.loads(raw.decode("utf-8"))

    # --- Success shape ---------------------------------------------------

    def test_empty_materials_returns_zero_counts_and_all_resolved(self) -> None:
        root = self._create(DIGEST_A)
        self._register_provenance(root, [])

        status, headers, body = self._get_json(root)
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

    def test_top_level_key_order_and_trailing_newline(self) -> None:
        root = self._create(DIGEST_A)
        self._register_provenance(root, [])

        status, _h, raw = self._get(root)
        self.assertEqual(status, "200 OK")
        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(b" ", raw)
        self.assertEqual(
            list(json.loads(raw.decode("utf-8"))),
            ["id", "all_resolved", "material_count", "resolved_count", "materials"],
        )

    def test_resolved_material_inside_closure(self) -> None:
        dep = self._create(DIGEST_B, name="lib")
        root = self._create(DIGEST_A)
        self._depend(root, dep)
        self._register_provenance(root, [{"name": "lib", "digest": DIGEST_B}])

        status, _h, body = self._get_json(root)
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["all_resolved"], True)
        self.assertEqual(body["material_count"], 1)
        self.assertEqual(body["resolved_count"], 1)
        self.assertEqual(
            body["materials"],
            [
                {
                    "name": "lib",
                    "digest": DIGEST_B,
                    "status": "resolved",
                    "candidates": [dep],
                    "dependency_matches": [dep],
                }
            ],
        )

    def test_transitive_dependency_counts_as_inside_closure(self) -> None:
        leaf = self._create(DIGEST_C, name="lib")
        mid = self._create(DIGEST_B, name="mid")
        root = self._create(DIGEST_A)
        self._depend(root, mid)
        self._depend(mid, leaf)
        self._register_provenance(root, [{"name": "lib", "digest": DIGEST_C}])

        _s, _h, body = self._get_json(root)
        self.assertEqual(body["materials"][0]["status"], "resolved")
        self.assertEqual(body["materials"][0]["dependency_matches"], [leaf])

    def test_missing_material_has_no_candidates(self) -> None:
        root = self._create(DIGEST_A)
        self._register_provenance(root, [{"name": "ghost", "digest": DIGEST_B}])

        _s, _h, body = self._get_json(root)
        self.assertEqual(body["all_resolved"], False)
        self.assertEqual(body["resolved_count"], 0)
        self.assertEqual(
            body["materials"][0],
            {
                "name": "ghost",
                "digest": DIGEST_B,
                "status": "missing",
                "candidates": [],
                "dependency_matches": [],
            },
        )

    def test_candidate_outside_closure_is_outside_dependency(self) -> None:
        outsider = self._create(DIGEST_B, name="lib")
        root = self._create(DIGEST_A)
        self._register_provenance(root, [{"name": "lib", "digest": DIGEST_B}])

        _s, _h, body = self._get_json(root)
        self.assertEqual(
            body["materials"][0],
            {
                "name": "lib",
                "digest": DIGEST_B,
                "status": "outside_dependency",
                "candidates": [outsider],
                "dependency_matches": [],
            },
        )
        self.assertEqual(body["all_resolved"], False)

    def test_root_itself_is_not_a_dependency_match(self) -> None:
        root = self._create(DIGEST_A, name="lib")
        self._register_provenance(root, [{"name": "lib", "digest": DIGEST_A}])

        _s, _h, body = self._get_json(root)
        self.assertEqual(body["materials"][0]["candidates"], [root])
        self.assertEqual(body["materials"][0]["dependency_matches"], [])
        self.assertEqual(body["materials"][0]["status"], "outside_dependency")

    def test_ambiguous_when_closure_has_multiple_matches(self) -> None:
        first = self._create(DIGEST_B, name="lib")
        second = self._create(DIGEST_B, name="lib", category="model")
        root = self._create(DIGEST_A)
        self._depend(root, first)
        self._depend(root, second)
        self._register_provenance(root, [{"name": "lib", "digest": DIGEST_B}])

        _s, _h, body = self._get_json(root)
        self.assertEqual(body["resolved_count"], 0)
        self.assertEqual(body["all_resolved"], False)
        self.assertEqual(
            body["materials"][0],
            {
                "name": "lib",
                "digest": DIGEST_B,
                "status": "ambiguous",
                "candidates": [first, second],
                "dependency_matches": [first, second],
            },
        )

    def test_candidates_follow_registration_order(self) -> None:
        inside = self._create(DIGEST_B, name="lib")
        outside = self._create(DIGEST_B, name="lib", category="dataset")
        root = self._create(DIGEST_A)
        self._depend(root, inside)
        self._register_provenance(root, [{"name": "lib", "digest": DIGEST_B}])

        _s, _h, body = self._get_json(root)
        self.assertEqual(body["materials"][0]["candidates"], [inside, outside])
        self.assertEqual(body["materials"][0]["dependency_matches"], [inside])
        self.assertEqual(body["materials"][0]["status"], "resolved")

    def test_materials_keep_submission_order(self) -> None:
        dep = self._create(DIGEST_B, name="lib")
        root = self._create(DIGEST_A)
        self._depend(root, dep)
        self._register_provenance(
            root,
            [
                {"name": "ghost", "digest": DIGEST_C},
                {"name": "lib", "digest": DIGEST_B},
            ],
        )

        _s, _h, body = self._get_json(root)
        self.assertEqual(
            [m["name"] for m in body["materials"]], ["ghost", "lib"]
        )
        self.assertEqual(
            [m["status"] for m in body["materials"]], ["missing", "resolved"]
        )
        self.assertEqual(body["resolved_count"], 1)
        self.assertEqual(body["all_resolved"], False)

    def test_name_match_is_verbatim_and_digest_case_insensitive(self) -> None:
        # Same digest, but the resource name differs in case: no candidate.
        self._create(DIGEST_B, name="Lib")
        root = self._create(DIGEST_A)
        self._register_provenance(root, [{"name": "lib", "digest": DIGEST_B}])

        _s, _h, body = self._get_json(root)
        self.assertEqual(body["materials"][0]["status"], "missing")

    def test_recomputed_after_graph_and_registry_changes(self) -> None:
        dep = self._create(DIGEST_B, name="lib")
        root = self._create(DIGEST_A)
        self._register_provenance(root, [{"name": "lib", "digest": DIGEST_B}])

        _s, _h, body = self._get_json(root)
        self.assertEqual(body["materials"][0]["status"], "outside_dependency")

        self._depend(root, dep)
        _s, _h, body = self._get_json(root)
        self.assertEqual(body["materials"][0]["status"], "resolved")

        status, _h, _b = call_json(
            "DELETE", f"/resources/{root}/dependencies/{dep}"
        )
        self.assertEqual(status, "200 OK")
        _s, _h, body = self._get_json(root)
        self.assertEqual(body["materials"][0]["status"], "outside_dependency")

        status, _h, _b = call_json("DELETE", f"/resources/{dep}")
        self.assertEqual(status, "200 OK")
        _s, _h, body = self._get_json(root)
        self.assertEqual(body["materials"][0]["status"], "missing")

    # --- Request validation ------------------------------------------------

    def test_non_get_method_returns_405_with_allow_get(self) -> None:
        root = self._create(DIGEST_A)
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            status, headers, body = call_json(
                method, f"/resources/{root}/provenance/materials"
            )
            self.assertEqual(status, "405 Method Not Allowed")
            self.assertEqual(body["error"], "method_not_allowed")
            self.assertIn(("Allow", "GET"), headers)

    def test_empty_id_and_separator_id_rejected(self) -> None:
        for path in (
            "/resources//provenance/materials",
            "/resources/a/b/provenance/materials",
        ):
            status, _h, body = call_json("GET", path)
            self.assertEqual(status, "400 Bad Request")
            self.assertEqual(body["error"], "invalid_request")

    def test_query_parameter_rejected(self) -> None:
        root = self._create(DIGEST_A)
        status, _h, body = call_json(
            "GET",
            f"/resources/{root}/provenance/materials",
            query_string="x=1",
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_non_empty_body_rejected(self) -> None:
        root = self._create(DIGEST_A)
        status, _h, body = call_json(
            "GET", f"/resources/{root}/provenance/materials", body="{}"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_malformed_content_length_rejected(self) -> None:
        root = self._create(DIGEST_A)
        status, _h, raw = call(
            "GET",
            f"/resources/{root}/provenance/materials",
            content_length="abc",
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(json.loads(raw.decode("utf-8"))["error"], "invalid_request")

    def test_unknown_resource_returns_404(self) -> None:
        status, _h, body = call_json(
            "GET", "/resources/nope/provenance/materials"
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

    def test_resource_without_provenance_returns_404(self) -> None:
        root = self._create(DIGEST_A)
        status, _h, body = self._get_json(root)
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "provenance_not_found")

    def test_get_does_not_mutate_state(self) -> None:
        dep = self._create(DIGEST_B, name="lib")
        root = self._create(DIGEST_A)
        self._depend(root, dep)
        self._register_provenance(root, [{"name": "lib", "digest": DIGEST_B}])

        self._get_json(root)
        # The provenance record itself is unchanged and still echoed as
        # registered; the check materialized nothing.
        status, _h, record = call_json("GET", f"/resources/{root}/provenance")
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            record["materials"], [{"name": "lib", "digest": DIGEST_B}]
        )


if __name__ == "__main__":
    unittest.main()
