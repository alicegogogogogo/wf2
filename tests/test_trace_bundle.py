from __future__ import annotations

import hashlib
import io
import json
import pathlib
import unittest

from provenance_api.app import application, reset_state

PATH_TEMPLATE = "/resources/{id}/trace-bundle"
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
    headers: dict[str, str] | None = None,
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
    for key, value in (headers or {}).items():
        environ[key] = value
    captured: dict[str, object] = {}

    def start_response(status: str, resp_headers: list[tuple[str, str]]) -> None:
        captured["status"] = status
        captured["headers"] = resp_headers

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


class TraceBundleTests(unittest.TestCase):
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

    def _add_sbom(self, resource_id: str) -> None:
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/sbom",
            {
                "format": "spdx",
                "components": [
                    {"name": "openssl", "version": "3.0.0", "digest": DIGEST_B}
                ],
            },
        )
        assert status == "201 Created", body

    def _add_license(self, resource_id: str) -> None:
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/license",
            {"spdx_id": "Apache-2.0"},
        )
        assert status == "201 Created", body

    def _add_provenance(self, resource_id: str) -> None:
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/provenance",
            {
                "builder": "ci",
                "build_number": "42",
                "source_digest": DIGEST_C,
                "materials": [{"name": "src", "digest": DIGEST_D}],
            },
        )
        assert status == "201 Created", body

    def _add_signature(self, resource_id: str) -> None:
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/signatures",
            {
                "signer": "release-bot",
                "algorithm": "hmac-sha256",
                "key_id": "key-1",
                "signature": "ab" * 32,
                "digest": DIGEST_A,
            },
        )
        assert status == "201 Created", body

    def _upload_and_assemble(self, resource_id: str, data: bytes) -> str:
        digest = hashlib.sha256(data).hexdigest()
        # Re-registering is impossible; the resource digest must match, so
        # this helper is only used with resources registered accordingly.
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/chunks/0",
            data,
            headers={
                "CONTENT_TYPE": "application/octet-stream",
                "HTTP_X_TOTAL_CHUNKS": "1",
                "HTTP_X_CONTENT_DIGEST": digest,
            },
        )
        assert status == "201 Created", body
        status, _h, body = call_json(
            "POST", f"/resources/{resource_id}/assemble"
        )
        assert status == "201 Created", body
        return digest

    def _bundle(self, root: str):
        status, headers, body = call_json("GET", PATH_TEMPLATE.format(id=root))
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            headers[0], ("Content-Type", "application/json; charset=utf-8")
        )
        return body

    # --- Shape -------------------------------------------------------------

    def test_single_resource_without_anything(self) -> None:
        root = self._register("root", DIGEST_A)

        body = self._bundle(root)
        self.assertEqual(
            body,  # type: ignore[arg-type]
            {
                "id": root,
                "bundle_digest": body["bundle_digest"],  # type: ignore[index]
                "resources": [
                    {
                        "resource": {
                            "id": root,
                            "name": "root",
                            "category": "code",
                            "digest": DIGEST_A,
                            "source": None,
                        },
                        "dependencies": [],
                        "content": {
                            "complete": False,
                            "size": None,
                            "digest": None,
                        },
                        "evidence": {
                            "sbom": None,
                            "license": None,
                            "provenance": None,
                            "signature": None,
                        },
                        "security": {
                            "vulnerabilities": [],
                            "vulnerability_exceptions": [],
                        },
                        "policy": {"source": None, "record": None},
                        "admission": {
                            "allowed": None,
                            "reasons": ["policy_not_found"],
                        },
                        "risk": {"score": 20, "level": "low"},
                        "cross_references": [],
                    }
                ],
            },
        )

    def test_fixed_top_level_and_node_key_order(self) -> None:
        root = self._register("root", DIGEST_A)
        _s, _h, raw = call("GET", PATH_TEMPLATE.format(id=root))
        text = raw.decode("utf-8")
        top = ['"id"', '"bundle_digest"', '"resources"']
        self.assertEqual(
            [text.index(k) for k in top],
            sorted(text.index(k) for k in top),
        )
        node = [
            '"resource"',
            '"dependencies"',
            '"content"',
            '"evidence"',
            '"security"',
            '"policy"',
            '"admission"',
            '"risk"',
            '"cross_references"',
        ]
        positions = [text.index(k) for k in node]
        self.assertEqual(positions, sorted(positions))
        # ``digest`` also appears inside the resource record, so the content
        # keys are located relative to the content object itself.
        content_start = text.index('"content"')
        content = ['"complete"', '"size"', '"digest"']
        content_positions = [text.index(k, content_start) for k in content]
        self.assertEqual(content_positions, sorted(content_positions))
        evidence = ['"sbom"', '"license"', '"provenance"', '"signature"']
        evidence_positions = [text.index(k) for k in evidence]
        self.assertEqual(evidence_positions, sorted(evidence_positions))
        security = ['"vulnerabilities"', '"vulnerability_exceptions"']
        security_positions = [text.index(k) for k in security]
        self.assertEqual(security_positions, sorted(security_positions))
        self.assertLess(text.index('"source"'), text.index('"record"'))
        self.assertTrue(text.endswith("\n"))
        self.assertEqual(text.count("\n"), 1)
        self.assertNotIn(b" ", raw[:-1])

    # --- bundle_digest ------------------------------------------------------

    def test_bundle_digest_matches_unsigned_compact_json(self) -> None:
        root = self._register("root", DIGEST_A)
        dep = self._register("dep", DIGEST_B)
        self._add(root, dep)

        body = self._bundle(root)
        unsigned = {
            "id": body["id"],  # type: ignore[index]
            "resources": body["resources"],  # type: ignore[index]
        }
        expected = hashlib.sha256(
            json.dumps(
                unsigned, ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()
        self.assertEqual(body["bundle_digest"], expected)  # type: ignore[index]
        self.assertEqual(len(body["bundle_digest"]), 64)  # type: ignore[index]

    def test_bundle_digest_is_stable_and_reflects_changes(self) -> None:
        root = self._register("root", DIGEST_A)
        first = self._bundle(root)["bundle_digest"]  # type: ignore[index]
        self.assertEqual(self._bundle(root)["bundle_digest"], first)  # type: ignore[index]

        self._add_alert(root)
        self.assertNotEqual(self._bundle(root)["bundle_digest"], first)  # type: ignore[index]

    # --- Closure order -------------------------------------------------------

    def test_nodes_follow_dependency_query_order_with_root_first(self) -> None:
        a = self._register("a", DIGEST_A)
        b = self._register("b", DIGEST_B)
        c = self._register("c", DIGEST_C)
        d = self._register("d", DIGEST_D)
        self._add(a, b)
        self._add(a, c)
        self._add(b, c)
        self._add(c, d)

        body = self._bundle(a)
        self.assertEqual(  # type: ignore[index]
            [node["resource"]["id"] for node in body["resources"]],
            [a, b, c, d],
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

        body = self._bundle(a)
        ids = [node["resource"]["id"] for node in body["resources"]]  # type: ignore[index]
        self.assertEqual(ids, [a, b, c, d])
        self.assertEqual(len(ids), len(set(ids)))

    def test_dependencies_list_direct_ids_in_registration_order(self) -> None:
        a = self._register("a", DIGEST_A)
        b = self._register("b", DIGEST_B)
        c = self._register("c", DIGEST_C)
        d = self._register("d", DIGEST_D)
        self._add(a, b)
        self._add(a, c)
        self._add(b, d)

        body = self._bundle(a)
        nodes = {  # type: ignore[index]
            node["resource"]["id"]: node for node in body["resources"]
        }
        # Direct edges only: the transitive reach to d is not listed for a.
        self.assertEqual(nodes[a]["dependencies"], [b, c])
        self.assertEqual(nodes[b]["dependencies"], [d])
        self.assertEqual(nodes[c]["dependencies"], [])
        self.assertEqual(nodes[d]["dependencies"], [])

    # --- Content --------------------------------------------------------------

    def test_content_reflects_assembled_artifact(self) -> None:
        data = b"trace-bundle-content"
        root = self._register("root", hashlib.sha256(data).hexdigest())
        self._upload_and_assemble(root, data)

        body = self._bundle(root)
        content = body["resources"][0]["content"]  # type: ignore[index]
        self.assertEqual(
            content,
            {
                "complete": True,
                "size": len(data),
                "digest": hashlib.sha256(data).hexdigest(),
            },
        )

    # --- Evidence, security, policy, admission, risk -------------------------

    def test_evidence_items_echo_their_registered_records(self) -> None:
        root = self._register("root", DIGEST_A)
        self._add_sbom(root)
        self._add_license(root)
        self._add_provenance(root)
        self._add_signature(root)

        evidence = self._bundle(root)["resources"][0]["evidence"]  # type: ignore[index]
        self.assertEqual(
            evidence["sbom"],
            {
                "id": root,
                "format": "spdx",
                "components": [
                    {"name": "openssl", "version": "3.0.0", "digest": DIGEST_B}
                ],
            },
        )
        self.assertEqual(
            evidence["license"],
            {"id": root, "spdx_id": "Apache-2.0", "source": None},
        )
        self.assertEqual(
            evidence["provenance"],
            {
                "id": root,
                "builder": "ci",
                "build_number": "42",
                "source_digest": DIGEST_C,
                "materials": [{"name": "src", "digest": DIGEST_D}],
            },
        )
        self.assertEqual(
            evidence["signature"],
            {
                "id": root,
                "signer": "release-bot",
                "algorithm": "hmac-sha256",
                "key_id": "key-1",
                "signature": "ab" * 32,
                "digest": DIGEST_A,
            },
        )

    def test_security_lists_alerts_and_exceptions(self) -> None:
        root = self._register("root", DIGEST_A)
        self._add_alert(root)
        self._add_exception(root)

        security = self._bundle(root)["resources"][0]["security"]  # type: ignore[index]
        self.assertEqual(len(security["vulnerabilities"]), 1)
        self.assertEqual(
            security["vulnerabilities"][0]["advisory"], "CVE-2026-0001"
        )
        self.assertEqual(len(security["vulnerability_exceptions"]), 1)
        self.assertEqual(
            security["vulnerability_exceptions"][0]["reason"], "accepted"
        )

    def test_policy_source_and_record_per_node(self) -> None:
        root = self._register("root", DIGEST_A)
        dep = self._register("dep", DIGEST_B)
        orphan = self._register("orphan", DIGEST_C)
        self._add(root, dep)
        self._add(root, orphan)
        self._add_policy(root, max_severity="low")
        self._set_default_policy(max_severity="medium")

        body = self._bundle(root)
        nodes = {  # type: ignore[index]
            node["resource"]["id"]: node for node in body["resources"]
        }
        self.assertEqual(nodes[root]["policy"]["source"], "resource")
        self.assertEqual(nodes[root]["policy"]["record"]["max_severity"], "low")
        self.assertEqual(nodes[dep]["policy"]["source"], "default")
        self.assertEqual(
            nodes[dep]["policy"]["record"],
            {
                "name": "release-gate",
                "evidence_requirements": [],
                "license_allowlist": [],
                "max_severity": "medium",
            },
        )
        self.assertEqual(
            list(nodes[dep]["policy"]["record"]),
            ["name", "evidence_requirements", "license_allowlist", "max_severity"],
        )

    def test_admission_and_risk_follow_the_existing_rules(self) -> None:
        root = self._register("root", DIGEST_A)
        dep = self._register("dep", DIGEST_B)
        self._add(root, dep)
        self._add_policy(root)
        self._set_default_policy(max_severity="high")
        self._add_alert(dep, severity="critical")

        body = self._bundle(root)
        nodes = {  # type: ignore[index]
            node["resource"]["id"]: node for node in body["resources"]
        }
        self.assertEqual(nodes[root]["admission"], {"allowed": True, "reasons": []})
        self.assertEqual(
            nodes[dep]["admission"],
            {"allowed": False, "reasons": ["severity_exceeded"]},
        )
        self.assertEqual(nodes[dep]["risk"], {"score": 60, "level": "high"})

    def test_exempted_alert_does_not_participate_in_admission(self) -> None:
        root = self._register("root", DIGEST_A)
        self._add_policy(root, max_severity="high")
        self._add_alert(root, severity="critical")
        self._add_exception(root)

        node = self._bundle(root)["resources"][0]  # type: ignore[index]
        self.assertEqual(node["admission"], {"allowed": True, "reasons": []})
        # The alert itself is still listed under security.
        self.assertEqual(len(node["security"]["vulnerabilities"]), 1)

    # --- Read-only, recomputation ---------------------------------------------

    def test_successful_query_records_nothing(self) -> None:
        root = self._register("root", DIGEST_A)
        dep = self._register("dep", DIGEST_B)
        self._add(root, dep)

        self._bundle(root)
        self._bundle(root)

        _s, _h, graph = call_json("GET", "/graph")
        self.assertEqual(len(graph["nodes"]), 2)  # type: ignore[index]
        self.assertEqual(len(graph["edges"]), 1)  # type: ignore[index]

    def test_results_recompute_after_state_changes(self) -> None:
        root = self._register("root", DIGEST_A)
        before = self._bundle(root)
        self.assertIsNone(before["resources"][0]["evidence"]["sbom"])  # type: ignore[index]

        self._add_sbom(root)
        after = self._bundle(root)
        self.assertIsNotNone(after["resources"][0]["evidence"]["sbom"])  # type: ignore[index]
        self.assertNotEqual(
            before["bundle_digest"], after["bundle_digest"]  # type: ignore[index]
        )

    def test_no_persistence_files_created(self) -> None:
        root = self._register("root", DIGEST_A)
        repo_root = pathlib.Path(__file__).resolve().parents[1]
        before = {
            str(p.relative_to(repo_root))
            for p in repo_root.rglob("*")
            if ".git" not in p.parts and p.is_file()
        }
        self._bundle(root)
        after = {
            str(p.relative_to(repo_root))
            for p in repo_root.rglob("*")
            if ".git" not in p.parts and p.is_file()
        }
        self.assertEqual(before, after)

    # --- Request envelope ------------------------------------------------------

    def test_omitted_or_zero_length_body_is_accepted(self) -> None:
        root = self._register("root", DIGEST_A)
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
        status, _h, parsed = call_json("GET", "/resources//trace-bundle")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(parsed["error"], "invalid_request")  # type: ignore[index]

        status, _h, parsed = call_json("GET", "/resources/a/b/trace-bundle")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(parsed["error"], "invalid_request")  # type: ignore[index]

        status, _h, parsed = call_json("GET", "/resources/a\\b/trace-bundle")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(parsed["error"], "invalid_request")  # type: ignore[index]

    def test_unknown_root_is_404(self) -> None:
        status, _h, parsed = call_json("GET", "/resources/unknown/trace-bundle")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(parsed["error"], "resource_not_found")  # type: ignore[index]

    # --- Methods ----------------------------------------------------------------

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
