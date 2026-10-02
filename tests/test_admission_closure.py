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
        "CONTENT_TYPE": "application/json",
        "wsgi.input": io.BytesIO(payload),
    }
    if not omit_content_length:
        environ["CONTENT_LENGTH"] = (
            str(len(payload)) if content_length is None else str(content_length)
        )
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
    **kwargs: object,
) -> tuple[str, list[tuple[str, str]], object]:
    status, headers, raw = call(method, path, body, **kwargs)  # type: ignore[arg-type]
    return status, headers, json.loads(raw.decode("utf-8"))


def policy_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "name": "release-gate",
        "evidence_requirements": [],
        "license_allowlist": [],
        "max_severity": "high",
    }
    payload.update(overrides)
    return payload


class AdmissionClosureTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    # --- Setup helpers -----------------------------------------------------

    def _register(
        self, name: str = "r", digest: str = DIGEST_A
    ) -> str:
        _s, _h, body = call_json(
            "POST",
            "/resources",
            {"name": name, "category": "code", "digest": digest},
        )
        assert _s == "201 Created", body
        return str(body["id"])  # type: ignore[index]

    def _add_dependency(self, resource_id: str, dependency_id: str) -> None:
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/dependencies",
            {"dependency_id": dependency_id},
        )
        assert status == "201 Created", body

    def _add_alert(
        self,
        resource_id: str,
        *,
        advisory: str = "CVE-2026-0001",
        component: str = "openssl",
        severity: str = "critical",
    ) -> str:
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/vulnerabilities",
            {
                "advisory": advisory,
                "component": component,
                "severity": severity,
                "summary": "test alert",
            },
        )
        assert status == "201 Created", body
        return str(body["id"])  # type: ignore[index]

    def _add_policy(
        self, resource_id: str, **overrides: object
    ) -> None:
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/policies",
            policy_payload(**overrides),
        )
        assert status == "201 Created", body

    def _set_default_policy(self, **overrides: object) -> None:
        status, _h, body = call_json(
            "POST", "/policies", policy_payload(**overrides)
        )
        assert status == "201 Created", body

    def _add_exception(
        self,
        resource_id: str,
        *,
        advisory: str = "CVE-2026-0001",
        component: str = "openssl",
    ) -> str:
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/vulnerability-exceptions",
            {
                "advisory": advisory,
                "component": component,
                "reason": "accepted risk",
            },
        )
        assert status == "201 Created", body
        return str(body["id"])  # type: ignore[index]

    def _set_lifecycle(
        self, resource_id: str, state: str, reason: str | None = None
    ) -> None:
        payload: dict[str, object] = {"state": state}
        if reason is not None:
            payload["reason"] = reason
        status, _h, body = call_json(
            "POST", f"/resources/{resource_id}/lifecycle", payload
        )
        assert status == "200 OK", body

    def _closure(
        self, resource_id: str, **kwargs: object
    ) -> dict[str, object]:
        status, _h, body = call_json(
            "GET", f"/resources/{resource_id}/admission-closure", **kwargs
        )
        assert status == "200 OK", body
        return body  # type: ignore[return-value]

    def _node(
        self, resource_id: str, node_id: str
    ) -> dict[str, object]:
        result = self._closure(resource_id)
        nodes = [n for n in result["resources"] if n["id"] == node_id]
        assert len(nodes) == 1
        return nodes[0]  # type: ignore[return-value]

    # --- Shape -------------------------------------------------------------

    def test_single_root_without_dependencies_is_single_node_closure(self) -> None:
        root = self._register()
        result = self._closure(root)
        self.assertEqual(
            result,
            {
                "id": root,
                "allowed": None,
                "reasons": ["policy_not_found"],
                "resources": [
                    {
                        "id": root,
                        "policy_source": None,
                        "allowed": None,
                        "reasons": ["policy_not_found"],
                    }
                ],
            },
        )

    def test_top_level_and_node_key_order(self) -> None:
        root = self._register()
        self._add_policy(root)
        _s, _h, raw = call(
            "GET", f"/resources/{root}/admission-closure"
        )
        text = raw.decode("utf-8").rstrip("\n")
        top_keys = ['"id"', '"allowed"', '"reasons"', '"resources"']
        positions = [text.index(k) for k in top_keys]
        self.assertEqual(positions, sorted(positions))
        # Scope the node check to the first node object: the top-level
        # allowed/reasons precede it in the document.
        node_start = text.index('{"id"', text.index('"resources"'))
        node_text = text[node_start:]
        node_keys = [
            '"id"', '"policy_source"', '"allowed"', '"reasons"'
        ]
        node_positions = [node_text.index(k) for k in node_keys]
        self.assertEqual(node_positions, sorted(node_positions))
        self.assertTrue(raw.endswith(b"\n"))
        self.assertEqual(raw.count(b"\n"), 1)
        self.assertNotIn(b" ", raw[:-1])

    # --- Closure order -----------------------------------------------------

    def test_nodes_follow_dependency_query_order_with_root_first(self) -> None:
        a = self._register("a", DIGEST_A)
        b = self._register("b", DIGEST_B)
        c = self._register("c", DIGEST_C)
        d = self._register("d", DIGEST_D)
        self._add_dependency(a, b)
        self._add_dependency(a, c)
        self._add_dependency(b, d)
        self._add_dependency(c, d)

        _s, _h, deps = call_json(
            "GET", f"/resources/{a}/dependencies"
        )
        expected = [a, *deps["dependencies"]]  # type: ignore[index]

        result = self._closure(a)
        self.assertEqual(
            [node["id"] for node in result["resources"]], expected
        )
        # Each resource appears exactly once even when reachable twice.
        ids = [node["id"] for node in result["resources"]]
        self.assertEqual(len(ids), len(set(ids)))

    # --- Per-node decisions ------------------------------------------------

    def test_node_uses_own_policy_with_resource_source(self) -> None:
        root = self._register()
        self._add_policy(root, max_severity="low")
        self._add_alert(root, severity="high")
        self.assertEqual(
            self._node(root, root),
            {
                "id": root,
                "policy_source": "resource",
                "allowed": False,
                "reasons": ["severity_exceeded"],
            },
        )

    def test_node_without_own_policy_uses_default_source(self) -> None:
        root = self._register()
        self._add_alert(root, severity="critical")
        self._set_default_policy(max_severity="high")
        self.assertEqual(
            self._node(root, root),
            {
                "id": root,
                "policy_source": "default",
                "allowed": False,
                "reasons": ["severity_exceeded"],
            },
        )

    def test_node_without_any_policy_is_null_with_policy_not_found(self) -> None:
        root = self._register()
        self._add_alert(root, severity="critical")
        self._set_lifecycle(root, "quarantined", "tainted")
        self.assertEqual(
            self._node(root, root),
            {
                "id": root,
                "policy_source": None,
                "allowed": None,
                "reasons": ["policy_not_found"],
            },
        )

    def test_exempted_alert_does_not_count_toward_severity(self) -> None:
        root = self._register()
        self._add_policy(root, max_severity="high")
        self._add_alert(root, severity="critical")
        self._add_exception(root)
        node = self._node(root, root)
        self.assertTrue(node["allowed"])
        self.assertEqual(node["reasons"], [])

    def test_exemption_matches_advisory_and_component_verbatim(self) -> None:
        root = self._register()
        self._add_policy(root, max_severity="high")
        self._add_alert(
            root, advisory="CVE-2026-0001", component="openssl",
            severity="critical",
        )
        # An exemption only exists for the very same advisory *and*
        # component pair; this other critical alert is exempted, the
        # openssl one must still deny.
        self._add_alert(
            root, advisory="CVE-2026-0001", component="zlib",
            severity="critical",
        )
        self._add_exception(
            root, advisory="CVE-2026-0001", component="zlib"
        )
        node = self._node(root, root)
        self.assertFalse(node["allowed"])
        self.assertEqual(node["reasons"], ["severity_exceeded"])

    def test_state_blocked_evidence_license_and_severity_reasons(self) -> None:
        root = self._register()
        self._add_policy(
            root,
            evidence_requirements=["sbom", "license", "provenance"],
            license_allowlist=["Apache-2.0"],
            max_severity="low",
        )
        self._add_alert(root, severity="critical")
        self.assertEqual(
            self._node(root, root)["reasons"],
            [
                "no_sbom",
                "no_license",
                "no_provenance",
                "license_denied",
                "severity_exceeded",
            ],
        )
        self._set_lifecycle(root, "quarantined", "tainted")
        self.assertEqual(
            self._node(root, root)["reasons"], ["state_blocked"]
        )

    def test_each_node_independent_across_closure(self) -> None:
        root = self._register("root", DIGEST_A)
        dep = self._register("dep", DIGEST_B)
        self._add_dependency(root, dep)
        self._add_policy(root, max_severity="low")
        self._add_policy(dep, max_severity="critical")
        self._add_alert(root, severity="high")
        self._add_alert(dep, severity="high")
        result = self._closure(root)
        root_node, dep_node = result["resources"]
        self.assertFalse(root_node["allowed"])
        self.assertTrue(dep_node["allowed"])
        self.assertEqual(root_node["policy_source"], "resource")
        self.assertEqual(dep_node["policy_source"], "resource")

    # --- Top-level rollup --------------------------------------------------

    def test_top_allowed_true_when_every_node_allowed(self) -> None:
        root = self._register("root", DIGEST_A)
        dep = self._register("dep", DIGEST_B)
        self._add_dependency(root, dep)
        self._set_default_policy()
        result = self._closure(root)
        self.assertTrue(result["allowed"])
        self.assertEqual(result["reasons"], [])

    def test_top_allowed_false_when_any_node_denied(self) -> None:
        root = self._register("root", DIGEST_A)
        dep = self._register("dep", DIGEST_B)
        ungoverned = self._register("ungoverned", DIGEST_C)
        self._add_dependency(root, dep)
        self._add_dependency(dep, ungoverned)
        self._add_policy(root)
        self._add_policy(dep, max_severity="low")
        self._add_alert(dep, severity="critical")
        # Ungoverned node would make the answer unknown, but the explicit
        # denial wins and the top level is false.
        result = self._closure(root)
        self.assertFalse(result["allowed"])

    def test_top_allowed_null_when_no_denial_but_policy_missing(self) -> None:
        root = self._register("root", DIGEST_A)
        dep = self._register("dep", DIGEST_B)
        self._add_dependency(root, dep)
        self._add_policy(root)
        result = self._closure(root)
        self.assertIsNone(result["allowed"])

    def test_top_reasons_concatenate_in_node_order_first_occurrence_dedup(self) -> None:
        a = self._register("a", DIGEST_A)
        b = self._register("b", DIGEST_B)
        c = self._register("c", DIGEST_C)
        self._add_dependency(a, b)
        self._add_dependency(b, c)
        self._add_policy(a, evidence_requirements=["sbom"])
        self._add_policy(
            b,
            evidence_requirements=["sbom", "license"],
            license_allowlist=["MIT"],
        )
        self._add_policy(
            c,
            evidence_requirements=["provenance"],
            license_allowlist=["MIT"],
        )
        result = self._closure(a)
        # Node reasons keep the existing order; the top-level list drops
        # no_sbom after its first occurrence and keeps first-seen order.
        self.assertEqual(result["resources"][0]["reasons"], ["no_sbom"])
        self.assertEqual(
            result["resources"][1]["reasons"],
            ["no_sbom", "no_license", "license_denied"],
        )
        self.assertEqual(
            result["resources"][2]["reasons"],
            ["no_provenance", "license_denied"],
        )
        self.assertEqual(
            result["reasons"],
            ["no_sbom", "no_license", "license_denied", "no_provenance"],
        )

    def test_policy_not_found_dedups_across_nodes(self) -> None:
        a = self._register("a", DIGEST_A)
        b = self._register("b", DIGEST_B)
        self._add_dependency(a, b)
        result = self._closure(a)
        self.assertIsNone(result["allowed"])
        self.assertEqual(result["reasons"], ["policy_not_found"])

    # --- Immediate recomputation and read-only behavior --------------------

    def test_mutating_state_changes_next_query_without_records(self) -> None:
        root = self._register("root", DIGEST_A)
        dep = self._register("dep", DIGEST_B)
        self._add_dependency(root, dep)
        self._add_policy(root)
        self.assertIsNone(self._closure(root)["allowed"])

        self._set_default_policy()
        self.assertTrue(self._closure(root)["allowed"])

        self._add_alert(dep, severity="critical")
        self.assertFalse(self._closure(root)["allowed"])

        self._add_exception(dep)
        self.assertTrue(self._closure(root)["allowed"])

    def test_repeated_queries_are_identical(self) -> None:
        root = self._register("root", DIGEST_A)
        dep = self._register("dep", DIGEST_B)
        self._add_dependency(root, dep)
        self._add_policy(root, max_severity="low")
        self._add_alert(dep, severity="critical")
        _s, _h, first = call("GET", f"/resources/{root}/admission-closure")
        for _ in range(3):
            _s, _h, again = call(
                "GET", f"/resources/{root}/admission-closure"
            )
            self.assertEqual(again, first)

    def test_query_does_not_change_single_preview_or_admission(self) -> None:
        root = self._register()
        self._add_policy(root, max_severity="high")
        self._add_alert(root, severity="critical")
        self._add_exception(root)
        self._closure(root)
        status, _h, preview = call_json(
            "GET", f"/resources/{root}/admission-preview"
        )
        self.assertEqual(status, "200 OK")
        self.assertTrue(preview["allowed"])  # type: ignore[index]
        status, _h, admission = call_json(
            "POST", f"/resources/{root}/admission"
        )
        self.assertEqual(status, "200 OK")
        self.assertFalse(admission["allowed"])  # type: ignore[index]

    # --- Errors ------------------------------------------------------------

    def test_unknown_root_is_404(self) -> None:
        status, _h, body = call_json(
            "GET", "/resources/unknown/admission-closure"
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")  # type: ignore[index]

    def test_empty_id_is_bad_request(self) -> None:
        status, _h, body = call_json(
            "GET", "/resources//admission-closure"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")  # type: ignore[index]

    def test_id_with_slash_is_bad_request(self) -> None:
        status, _h, body = call_json(
            "GET", "/resources/a/b/admission-closure"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")  # type: ignore[index]

    def test_unknown_and_blank_query_parameters_are_bad_request(self) -> None:
        root = self._register()
        for qs in ("x=1", "pretty=true", "="):
            with self.subTest(qs=qs):
                status, _h, body = call_json(
                    "GET",
                    f"/resources/{root}/admission-closure",
                    query_string=qs,
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")  # type: ignore[index]

    def test_non_empty_and_malformed_bodies_are_bad_request(self) -> None:
        root = self._register()
        status, _h, body = call(
            "GET", f"/resources/{root}/admission-closure", b"x"
        )
        self.assertEqual(status, "400 Bad Request")
        for raw in ("abc", "-1", "1.5"):
            with self.subTest(raw=raw):
                status, _h, body = call(
                    "GET",
                    f"/resources/{root}/admission-closure",
                    content_length=raw,
                )
                self.assertEqual(status, "400 Bad Request")

    def test_omitted_and_zero_length_body_are_accepted(self) -> None:
        root = self._register()
        self._add_policy(root)
        status, _h, _b = call(
            "GET",
            f"/resources/{root}/admission-closure",
            omit_content_length=True,
        )
        self.assertEqual(status, "200 OK")
        status, _h, _b = call(
            "GET",
            f"/resources/{root}/admission-closure",
            content_length="0",
        )
        self.assertEqual(status, "200 OK")
        status, _h, _b = call(
            "GET",
            f"/resources/{root}/admission-closure",
            content_length="",
        )
        self.assertEqual(status, "200 OK")

    def test_non_get_methods_return_405_with_get_only_allow(self) -> None:
        root = self._register()
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, headers, body = call_json(
                    method, f"/resources/{root}/admission-closure"
                )
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")  # type: ignore[index]
                self.assertIn(("Allow", "GET"), headers)
                self.assertNotIn(("Allow", "GET, POST"), headers)

    def test_unknown_root_404_precedes_policy_lookup(self) -> None:
        # An existing path shape but missing resource is a resource 404,
        # never a policy error, even with no default policy registered.
        status, _h, body = call_json(
            "GET", "/resources/missing/admission-closure"
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")  # type: ignore[index]

    def test_failed_request_changes_nothing(self) -> None:
        root = self._register("root", DIGEST_A)
        dep = self._register("dep", DIGEST_B)
        self._add_dependency(root, dep)
        self._add_policy(root)
        _s, _h, expected = call(
            "GET", f"/resources/{root}/admission-closure"
        )
        call("POST", f"/resources/{root}/admission-closure", b"{}")
        call(
            "GET",
            f"/resources/{root}/admission-closure",
            query_string="x=1",
        )
        call("GET", f"/resources/{root}/admission-closure", b"body")
        call("GET", "/resources/missing/admission-closure")
        _s, _h, after = call(
            "GET", f"/resources/{root}/admission-closure"
        )
        self.assertEqual(after, expected)
        # The dependency edge and both resources are untouched.
        _s, _h, deps = call_json("GET", f"/resources/{root}/dependencies")
        self.assertEqual(deps["dependencies"], [dep])  # type: ignore[index]


if __name__ == "__main__":
    unittest.main()
