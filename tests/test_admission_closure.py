from __future__ import annotations

import io
import json
import pathlib
import unittest

from provenance_api.app import application, reset_state

PATH_TEMPLATE = "/resources/{id}/admission-closure"
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

    def _register(self, name: str, digest: str) -> str:
        status, _h, body = call_json(
            "POST",
            "/resources",
            {"name": name, "category": "code", "digest": digest},
        )
        assert status == "201 Created", body
        return str(body["id"])  # type: ignore[index]

    def _add(self, resource_id: str, dependency_id: str) -> None:
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/dependencies",
            {"dependency_id": dependency_id},
        )
        assert status == "201 Created", body

    def _add_policy(self, resource_id: str, **overrides: object) -> None:
        status, _h, body = call_json(
            "POST", f"/resources/{resource_id}/policies", policy_payload(**overrides)
        )
        assert status == "201 Created", body

    def _set_default_policy(self, **overrides: object) -> None:
        status, _h, body = call_json("POST", "/policies", policy_payload(**overrides))
        assert status == "201 Created", body

    def _add_alert(
        self,
        resource_id: str,
        *,
        advisory: str = "CVE-2026-0001",
        component: str = "openssl",
        severity: str = "critical",
    ) -> None:
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

    def _add_exception(
        self,
        resource_id: str,
        *,
        advisory: str = "CVE-2026-0001",
        component: str = "openssl",
    ) -> None:
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/vulnerability-exceptions",
            {"advisory": advisory, "component": component, "reason": "accepted"},
        )
        assert status == "201 Created", body

    def _set_lifecycle(self, resource_id: str, state: str, reason: str = "x") -> None:
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/lifecycle",
            {"state": state, "reason": reason},
        )
        assert status == "200 OK", body

    def _closure(self, root: str):
        status, headers, body = call_json(
            "GET", PATH_TEMPLATE.format(id=root)
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            headers[0], ("Content-Type", "application/json; charset=utf-8")
        )
        return body

    # --- Shape -------------------------------------------------------------

    def test_single_resource_without_dependencies_is_a_one_node_closure(self) -> None:
        root = self._register("root", DIGEST_A)
        self._add_policy(root)

        body = self._closure(root)
        self.assertEqual(
            body,  # type: ignore[arg-type]
            {
                "id": root,
                "allowed": True,
                "reasons": [],
                "resources": [
                    {
                        "id": root,
                        "policy_source": "resource",
                        "allowed": True,
                        "reasons": [],
                    }
                ],
            },
        )

    def test_fixed_top_level_and_node_key_order(self) -> None:
        root = self._register("root", DIGEST_A)
        self._add_policy(root)
        _s, _h, raw = call("GET", PATH_TEMPLATE.format(id=root))
        text = raw.decode("utf-8")
        top = ['"id"', '"allowed"', '"reasons"', '"resources"']
        self.assertEqual([text.index(k) for k in top], sorted(text.index(k) for k in top))
        node = ['"id"', '"policy_source"', '"allowed"', '"reasons"']
        positions = [text.rindex(k) for k in node]
        self.assertEqual(positions, sorted(positions))
        self.assertTrue(text.endswith("\n"))
        self.assertEqual(text.count("\n"), 1)
        self.assertNotIn(b" ", raw[:-1])

    # --- Closure order -----------------------------------------------------

    def test_nodes_follow_dependency_query_order_with_root_first(self) -> None:
        # a -> b, a -> c, b -> c, c -> d: dependency query order for a is
        # [b, c, d] in registration order.
        a = self._register("a", DIGEST_A)
        b = self._register("b", DIGEST_B)
        c = self._register("c", DIGEST_C)
        d = self._register("d", DIGEST_D)
        self._add(a, b)
        self._add(a, c)
        self._add(b, c)
        self._add(c, d)
        self._set_default_policy()

        body = self._closure(a)
        self.assertEqual(  # type: ignore[index]
            [node["id"] for node in body["resources"]], [a, b, c, d]
        )

    def test_diamond_closure_lists_every_resource_once(self) -> None:
        a = self._register("a", DIGEST_A)
        b = self._register("b", DIGEST_B)
        c = self._register("c", DIGEST_C)
        d = self._register("d", DIGEST_D)
        self._add(a, b)
        self._add(a, c)
        self._add(b, d)
        self._add(c, d)
        self._add(a, d)
        self._set_default_policy()

        body = self._closure(a)
        ids = [node["id"] for node in body["resources"]]  # type: ignore[index]
        self.assertEqual(ids, [a, b, c, d])
        self.assertEqual(len(ids), len(set(ids)))

    # --- Policy selection per node ----------------------------------------

    def test_each_node_uses_its_own_policy(self) -> None:
        root = self._register("root", DIGEST_A)
        dep = self._register("dep", DIGEST_B)
        self._add(root, dep)
        self._add_policy(root, max_severity="low")
        self._add_policy(dep, max_severity="critical")
        self._add_alert(root, severity="high")
        self._add_alert(dep, severity="high")

        body = self._closure(root)
        nodes = {node["id"]: node for node in body["resources"]}  # type: ignore[index]
        self.assertEqual(nodes[root]["policy_source"], "resource")
        self.assertFalse(nodes[root]["allowed"])
        self.assertEqual(nodes[dep]["policy_source"], "resource")
        self.assertTrue(nodes[dep]["allowed"])

    def test_node_without_own_policy_uses_global_default(self) -> None:
        root = self._register("root", DIGEST_A)
        dep = self._register("dep", DIGEST_B)
        self._add(root, dep)
        self._add_policy(root, max_severity="critical")
        self._set_default_policy(max_severity="high")
        self._add_alert(dep, severity="critical")

        body = self._closure(root)
        nodes = {node["id"]: node for node in body["resources"]}  # type: ignore[index]
        self.assertEqual(nodes[root]["policy_source"], "resource")
        self.assertTrue(nodes[root]["allowed"])
        self.assertEqual(nodes[dep]["policy_source"], "default")
        self.assertFalse(nodes[dep]["allowed"])
        self.assertEqual(nodes[dep]["reasons"], ["severity_exceeded"])

    def test_node_without_any_policy_is_null_policy_not_found(self) -> None:
        root = self._register("root", DIGEST_A)
        dep = self._register("dep", DIGEST_B)
        self._add(root, dep)
        self._add_policy(root, max_severity="high")
        # A blocked lifecycle state must not surface without a policy.
        self._set_lifecycle(dep, "quarantined")

        body = self._closure(root)
        nodes = {node["id"]: node for node in body["resources"]}  # type: ignore[index]
        self.assertIsNone(nodes[dep]["policy_source"])
        self.assertIsNone(nodes[dep]["allowed"])
        self.assertEqual(nodes[dep]["reasons"], ["policy_not_found"])
        self.assertEqual(
            set(nodes[dep]), {"id", "policy_source", "allowed", "reasons"}
        )

    # --- Exemptions --------------------------------------------------------

    def test_exempted_alert_does_not_participate_in_severity(self) -> None:
        root = self._register("root", DIGEST_A)
        dep = self._register("dep", DIGEST_B)
        self._add(root, dep)
        self._set_default_policy(max_severity="high")
        self._add_alert(dep, severity="critical")
        self._add_exception(dep)

        body = self._closure(root)
        nodes = {node["id"]: node for node in body["resources"]}  # type: ignore[index]
        self.assertTrue(nodes[dep]["allowed"])
        self.assertEqual(nodes[dep]["reasons"], [])

    def test_exemption_is_verbatim_advisory_and_component(self) -> None:
        root = self._register("root", DIGEST_A)
        self._add_policy(root, max_severity="high")
        self._add_alert(root, severity="critical")
        # The exemption matches an existing alert only verbatim; register
        # it against a different component so the openssl alert stays
        # active even though the advisory string is identical.
        self._add_alert(
            root, advisory="CVE-2026-0001", component="zlib", severity="low"
        )
        self._add_exception(root, component="zlib")

        body = self._closure(root)
        node = body["resources"][0]  # type: ignore[index]
        self.assertFalse(node["allowed"])
        self.assertEqual(node["reasons"], ["severity_exceeded"])

    # --- Aggregate decision and reasons -----------------------------------

    def test_top_level_true_when_every_node_allows(self) -> None:
        root = self._register("root", DIGEST_A)
        dep = self._register("dep", DIGEST_B)
        self._add(root, dep)
        self._set_default_policy()

        body = self._closure(root)
        self.assertTrue(body["allowed"])  # type: ignore[index]
        self.assertEqual(body["reasons"], [])  # type: ignore[index]

    def test_top_level_false_when_any_node_denied(self) -> None:
        root = self._register("root", DIGEST_A)
        dep = self._register("dep", DIGEST_B)
        self._add(root, dep)
        self._set_default_policy()
        self._add_alert(dep, severity="critical")

        body = self._closure(root)
        self.assertFalse(body["allowed"])  # type: ignore[index]
        self.assertEqual(body["reasons"], ["severity_exceeded"])  # type: ignore[index]

    def test_top_level_null_when_no_denial_but_a_node_lacks_policy(self) -> None:
        root = self._register("root", DIGEST_A)
        dep = self._register("dep", DIGEST_B)
        self._add(root, dep)
        self._add_policy(root)

        body = self._closure(root)
        self.assertIsNone(body["allowed"])  # type: ignore[index]
        self.assertEqual(body["reasons"], ["policy_not_found"])  # type: ignore[index]

    def test_explicit_denial_dominates_policy_not_found(self) -> None:
        root = self._register("root", DIGEST_A)
        denied = self._register("denied", DIGEST_B)
        ungoverned = self._register("ungoverned", DIGEST_C)
        self._add(root, denied)
        self._add(root, ungoverned)
        self._add_policy(root)
        self._add_policy(denied, max_severity="low")
        self._add_alert(denied, severity="high")

        body = self._closure(root)
        self.assertFalse(body["allowed"])  # type: ignore[index]
        # Node order is root, denied, ungoverned (registration order);
        # reasons follow that order with first-occurrence dedup.
        self.assertEqual(  # type: ignore[index]
            body["reasons"], ["severity_exceeded", "policy_not_found"]
        )

    def test_reasons_deduplicate_by_first_occurrence(self) -> None:
        root = self._register("root", DIGEST_A)
        first = self._register("first", DIGEST_B)
        second = self._register("second", DIGEST_C)
        self._add(root, first)
        self._add(root, second)
        self._set_default_policy(max_severity="low")
        self._add_alert(first, severity="high")
        self._add_alert(second, severity="critical")

        body = self._closure(root)
        self.assertFalse(body["allowed"])  # type: ignore[index]
        self.assertEqual(body["reasons"], ["severity_exceeded"])  # type: ignore[index]

    def test_node_reason_order_is_the_existing_admission_order(self) -> None:
        root = self._register("root", DIGEST_A)
        self._add_policy(
            root,
            evidence_requirements=["sbom"],
            license_allowlist=["Apache-2.0"],
            max_severity="low",
        )
        self._add_alert(root, severity="critical")

        body = self._closure(root)
        self.assertEqual(  # type: ignore[index]
            body["resources"][0]["reasons"],
            ["no_sbom", "license_denied", "severity_exceeded"],
        )
        self.assertEqual(  # type: ignore[index]
            body["reasons"],
            ["no_sbom", "license_denied", "severity_exceeded"],
        )

    # --- Read-only, recomputation -----------------------------------------

    def test_successful_query_records_nothing(self) -> None:
        root = self._register("root", DIGEST_A)
        dep = self._register("dep", DIGEST_B)
        self._add(root, dep)
        self._set_default_policy()

        self._closure(root)
        self._closure(root)

        _s, _h, graph = call_json("GET", "/graph")
        self.assertEqual(len(graph["nodes"]), 2)  # type: ignore[index]
        self.assertEqual(len(graph["edges"]), 1)  # type: ignore[index]
        _s, _h, preview = call_json("GET", "/admission-preview")
        self.assertEqual(len(preview), 2)  # type: ignore[index]

    def test_results_recompute_after_state_changes(self) -> None:
        root = self._register("root", DIGEST_A)
        self._add_policy(root)
        self.assertTrue(self._closure(root)["allowed"])  # type: ignore[index]

        self._set_lifecycle(root, "quarantined")
        body = self._closure(root)
        self.assertFalse(body["allowed"])  # type: ignore[index]
        self.assertEqual(body["reasons"], ["state_blocked"])  # type: ignore[index]

        self._set_lifecycle(root, "staged", "cleared")
        self.assertTrue(self._closure(root)["allowed"])  # type: ignore[index]

    def test_no_persistence_files_created(self) -> None:
        root = self._register("root", DIGEST_A)
        repo_root = pathlib.Path(__file__).resolve().parents[1]
        before = {
            str(p.relative_to(repo_root))
            for p in repo_root.rglob("*")
            if ".git" not in p.parts and p.is_file()
        }
        self._closure(root)
        after = {
            str(p.relative_to(repo_root))
            for p in repo_root.rglob("*")
            if ".git" not in p.parts and p.is_file()
        }
        self.assertEqual(before, after)

    # --- Request envelope --------------------------------------------------

    def test_omitted_or_zero_length_body_is_accepted(self) -> None:
        root = self._register("root", DIGEST_A)
        self._add_policy(root)
        for kwargs in (
            {"omit_content_length": True},
            {"content_length": "0"},
            {"content_length": ""},
        ):
            with self.subTest(kwargs=kwargs):
                status, _h, _b = call(
                    "GET", PATH_TEMPLATE.format(id=root), b"", **kwargs
                )
                self.assertEqual(status, "200 OK")

    def test_non_empty_or_malformed_body_is_bad_request(self) -> None:
        root = self._register("root", DIGEST_A)
        for body, kwargs in (
            (b"{}", {}),
            (b"data", {}),
            (b"", {"content_length": "abc"}),
            (b"", {"content_length": "-1"}),
            (b"", {"content_length": "1.5"}),
        ):
            with self.subTest(body=body, kwargs=kwargs):
                status, _h, parsed = call_json(
                    "GET", PATH_TEMPLATE.format(id=root), body, **kwargs
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(parsed["error"], "invalid_request")  # type: ignore[index]

    def test_query_parameters_are_bad_request(self) -> None:
        root = self._register("root", DIGEST_A)
        for query_string in ("x=1", "=", "x=&y=2", "x=1&x=2", "focus=root"):
            with self.subTest(query_string=query_string):
                status, _h, parsed = call_json(
                    "GET",
                    PATH_TEMPLATE.format(id=root),
                    query_string=query_string,
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(parsed["error"], "invalid_request")  # type: ignore[index]

    def test_empty_or_separator_id_is_bad_request(self) -> None:
        status, _h, parsed = call_json("GET", "/resources//admission-closure")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(parsed["error"], "invalid_request")  # type: ignore[index]

    def test_unknown_root_is_404(self) -> None:
        status, _h, parsed = call_json(
            "GET", "/resources/unknown/admission-closure"
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(parsed["error"], "resource_not_found")  # type: ignore[index]

    # --- Methods -----------------------------------------------------------

    def test_other_methods_return_405_with_allow_get(self) -> None:
        root = self._register("root", DIGEST_A)
        for method in ("POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
            with self.subTest(method=method):
                status, headers, parsed = call_json(
                    method, PATH_TEMPLATE.format(id=root)
                )
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(parsed["error"], "method_not_allowed")  # type: ignore[index]
                self.assertEqual(
                    [value for name, value in headers if name == "Allow"],
                    ["GET"],
                )

    def test_method_check_precedes_body_and_query_checks(self) -> None:
        root = self._register("root", DIGEST_A)
        status, headers, parsed = call_json(
            "POST",
            PATH_TEMPLATE.format(id=root),
            {"unexpected": True},
            query_string="x=1",
        )
        self.assertEqual(status, "405 Method Not Allowed")
        self.assertEqual(parsed["error"], "method_not_allowed")  # type: ignore[index]
        self.assertEqual(
            [value for name, value in headers if name == "Allow"], ["GET"]
        )


if __name__ == "__main__":
    unittest.main()
