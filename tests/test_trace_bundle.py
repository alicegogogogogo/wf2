from __future__ import annotations

import hashlib
import io
import json
import pathlib
import unittest
from unittest import mock

from provenance_api.app import application, reset_state
from provenance_api.cross_references import Resolution

PATH_TEMPLATE = "/resources/{id}/trace-bundle"
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_D = "d" * 64
CONTENT = b"trace-bundle-content"


def call(
    method: str,
    path: str,
    body: bytes | str | dict[str, object] | None = None,
    *,
    query_string: str | None = None,
    content_length: int | str | None = None,
    omit_content_length: bool = False,
    headers: dict[str, str] | None = None,
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


class TraceBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    # --- Setup helpers -----------------------------------------------------

    def _register(self, name: str, digest: str, **extra: object) -> str:
        payload: dict[str, object] = {
            "name": name,
            "category": "code",
            "digest": digest,
        }
        payload.update(extra)
        status, _h, body = call_json("POST", "/resources", payload)
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
                    {"name": "openssl", "version": "3.0.0", "digest": "e" * 64}
                ],
            },
        )
        assert status == "201 Created", body

    def _add_license(self, resource_id: str) -> None:
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/license",
            {"spdx_id": "Apache-2.0", "source": "scanner"},
        )
        assert status == "201 Created", body

    def _add_provenance(self, resource_id: str) -> None:
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/provenance",
            {
                "builder": "ci",
                "build_number": "42",
                "source_digest": "f" * 64,
                "materials": [{"name": "src", "digest": "0" * 64}],
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
                "signature": "1" * 64,
                "digest": DIGEST_A,
            },
        )
        assert status == "201 Created", body

    def _add_cross_reference(self, resource_id: str) -> dict[str, object]:
        resolution = Resolution(
            name="remote-model",
            category="model",
            digest=DIGEST_D,
            source="https://repo.example.invalid/sources/remote-42",
            raw=b"{}",
        )
        with mock.patch(
            "provenance_api.app.resolve_remote", return_value=resolution
        ):
            status, _h, body = call_json(
                "POST",
                f"/resources/{resource_id}/cross-references",
                {
                    "repository": "partner",
                    "upstream": "https://repo.example.invalid",
                    "remote_id": "remote-42",
                    "digest": DIGEST_D,
                },
            )
        assert status == "201 Created", body
        return body  # type: ignore[return-value]

    def _assemble_content(self, resource_id: str) -> None:
        status, _h, body = call(
            "POST",
            f"/resources/{resource_id}/chunks/0",
            CONTENT,
            headers={
                "CONTENT_TYPE": "application/octet-stream",
                "HTTP_X_TOTAL_CHUNKS": "1",
                "HTTP_X_CONTENT_DIGEST": hashlib.sha256(CONTENT).hexdigest(),
            },
        )
        assert status == "201 Created", body
        status, _h, body = call_json(
            "POST", f"/resources/{resource_id}/assemble"
        )
        assert status == "201 Created", body

    def _bundle(self, root: str):
        status, headers, body = call_json("GET", PATH_TEMPLATE.format(id=root))
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            headers[0], ("Content-Type", "application/json; charset=utf-8")
        )
        return body

    # --- Shape -------------------------------------------------------------

    def test_single_resource_without_any_records(self) -> None:
        root = self._register("root", DIGEST_A)

        body = self._bundle(root)
        self.assertEqual(body["id"], root)  # type: ignore[index]
        resources = body["resources"]  # type: ignore[index]
        self.assertEqual(len(resources), 1)
        node = resources[0]
        self.assertEqual(
            list(node),
            [
                "resource",
                "dependencies",
                "content",
                "evidence",
                "security",
                "policy",
                "admission",
                "risk",
                "cross_references",
            ],
        )
        self.assertEqual(
            node["resource"],
            {
                "id": root,
                "name": "root",
                "category": "code",
                "digest": DIGEST_A,
                "source": None,
            },
        )
        self.assertEqual(node["dependencies"], [])
        self.assertEqual(
            node["content"], {"complete": False, "size": None, "digest": None}
        )
        self.assertEqual(
            node["evidence"],
            {
                "sbom": None,
                "license": None,
                "provenance": None,
                "signature": None,
            },
        )
        self.assertEqual(
            node["security"],
            {"vulnerabilities": [], "vulnerability_exceptions": []},
        )
        self.assertEqual(node["policy"], {"source": None, "record": None})
        self.assertIsNone(node["admission"])
        self.assertEqual(node["risk"], {"id": root, "score": 20, "level": "low"})
        self.assertEqual(node["cross_references"], [])

    def test_fixed_key_order_and_compact_newline_terminated_body(self) -> None:
        root = self._register("root", DIGEST_A)
        _s, _h, raw = call("GET", PATH_TEMPLATE.format(id=root))
        text = raw.decode("utf-8")
        top = ['"id"', '"bundle_digest"', '"resources"']
        self.assertEqual(
            [text.index(k) for k in top], sorted(text.index(k) for k in top)
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
        content = ['"complete"', '"size"', '"digest"']
        content_positions = [
            text.index(k, text.index('"content"')) for k in content
        ]
        self.assertEqual(content_positions, sorted(content_positions))
        evidence = ['"sbom"', '"license"', '"provenance"', '"signature"']
        evidence_positions = [
            text.index(k, text.index('"evidence"')) for k in evidence
        ]
        self.assertEqual(evidence_positions, sorted(evidence_positions))
        security = ['"vulnerabilities"', '"vulnerability_exceptions"']
        security_positions = [
            text.index(k, text.index('"security"')) for k in security
        ]
        self.assertEqual(security_positions, sorted(security_positions))
        policy = ['"source"', '"record"']
        policy_positions = [
            text.index(k, text.index('"policy"')) for k in policy
        ]
        self.assertEqual(policy_positions, sorted(policy_positions))
        self.assertTrue(text.endswith("\n"))
        self.assertEqual(text.count("\n"), 1)
        self.assertNotIn(b" ", raw[:-1])

    # --- Bundle digest -----------------------------------------------------

    def test_bundle_digest_matches_sha256_of_body_without_digest(self) -> None:
        root = self._register("root", DIGEST_A)
        self._add_policy(root)

        body = self._bundle(root)
        unsigned = {
            "id": body["id"],  # type: ignore[index]
            "resources": body["resources"],  # type: ignore[index]
        }
        expected = hashlib.sha256(
            json.dumps(
                unsigned,
                ensure_ascii=False,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()
        self.assertEqual(body["bundle_digest"], expected)  # type: ignore[index]
        self.assertRegex(body["bundle_digest"], r"^[0-9a-f]{64}$")  # type: ignore[index]

    def test_bundle_digest_is_stable_for_unchanged_data(self) -> None:
        root = self._register("root", DIGEST_A)
        dep = self._register("dep", DIGEST_B)
        self._add(root, dep)
        self._set_default_policy()

        first = self._bundle(root)
        second = self._bundle(root)
        self.assertEqual(first, second)
        self.assertEqual(  # type: ignore[index]
            first["bundle_digest"], second["bundle_digest"]  # type: ignore[index]
        )

    def test_bundle_digest_reflects_changes_immediately(self) -> None:
        root = self._register("root", DIGEST_A)
        before = self._bundle(root)["bundle_digest"]  # type: ignore[index]

        self._add_alert(root, severity="low")
        after_alert = self._bundle(root)["bundle_digest"]  # type: ignore[index]
        self.assertNotEqual(before, after_alert)

        self._set_default_policy()
        after_policy = self._bundle(root)["bundle_digest"]  # type: ignore[index]
        self.assertNotEqual(after_alert, after_policy)

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

        body = self._bundle(a)
        self.assertEqual(  # type: ignore[index]
            [node["resource"]["id"] for node in body["resources"]],  # type: ignore[index]
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
        self._add(a, c)
        self._add(a, b)
        self._add(b, d)

        body = self._bundle(a)
        nodes = {node["resource"]["id"]: node for node in body["resources"]}  # type: ignore[index]
        self.assertEqual(nodes[a]["dependencies"], [c, b])
        self.assertEqual(nodes[b]["dependencies"], [d])
        self.assertEqual(nodes[c]["dependencies"], [])
        self.assertEqual(nodes[d]["dependencies"], [])

    # --- Content -----------------------------------------------------------

    def test_assembled_content_reports_recomputed_digest(self) -> None:
        root = self._register("root", hashlib.sha256(CONTENT).hexdigest())
        self._assemble_content(root)

        node = self._bundle(root)["resources"][0]  # type: ignore[index]
        self.assertEqual(
            node["content"],
            {
                "complete": True,
                "size": len(CONTENT),
                "digest": hashlib.sha256(CONTENT).hexdigest(),
            },
        )

    def test_unassembled_content_reports_false_null_null(self) -> None:
        root = self._register("root", DIGEST_A)
        status, _h, body = call(
            "POST",
            f"/resources/{root}/chunks/0",
            CONTENT,
            headers={
                "CONTENT_TYPE": "application/octet-stream",
                "HTTP_X_TOTAL_CHUNKS": "2",
                "HTTP_X_CONTENT_DIGEST": DIGEST_A,
            },
        )
        assert status == "201 Created", body

        node = self._bundle(root)["resources"][0]  # type: ignore[index]
        self.assertEqual(
            node["content"], {"complete": False, "size": None, "digest": None}
        )

    # --- Evidence and security ---------------------------------------------

    def test_evidence_records_reuse_the_existing_shapes(self) -> None:
        root = self._register("root", DIGEST_A)
        self._add_sbom(root)
        self._add_license(root)
        self._add_provenance(root)
        self._add_signature(root)

        node = self._bundle(root)["resources"][0]  # type: ignore[index]
        evidence = node["evidence"]
        self.assertEqual(
            evidence["sbom"],
            {
                "id": root,
                "format": "spdx",
                "components": [
                    {"name": "openssl", "version": "3.0.0", "digest": "e" * 64}
                ],
            },
        )
        self.assertEqual(
            evidence["license"],
            {"id": root, "spdx_id": "Apache-2.0", "source": "scanner"},
        )
        self.assertEqual(
            evidence["provenance"],
            {
                "id": root,
                "builder": "ci",
                "build_number": "42",
                "source_digest": "f" * 64,
                "materials": [{"name": "src", "digest": "0" * 64}],
            },
        )
        self.assertEqual(
            evidence["signature"],
            {
                "id": root,
                "signer": "release-bot",
                "algorithm": "hmac-sha256",
                "key_id": "key-1",
                "signature": "1" * 64,
                "digest": DIGEST_A,
            },
        )

    def test_security_lists_alerts_and_exemptions_in_order(self) -> None:
        root = self._register("root", DIGEST_A)
        self._add_alert(root, advisory="CVE-2026-0001", severity="critical")
        self._add_alert(root, advisory="CVE-2026-0002", severity="low")
        self._add_exception(root, advisory="CVE-2026-0001")

        node = self._bundle(root)["resources"][0]  # type: ignore[index]
        security = node["security"]
        self.assertEqual(
            [alert["advisory"] for alert in security["vulnerabilities"]],
            ["CVE-2026-0001", "CVE-2026-0002"],
        )
        self.assertEqual(
            [item["advisory"] for item in security["vulnerability_exceptions"]],
            ["CVE-2026-0001"],
        )
        alert = security["vulnerabilities"][0]
        self.assertEqual(
            list(alert),
            ["id", "advisory", "component", "severity", "summary", "fixed_version"],
        )
        exception = security["vulnerability_exceptions"][0]
        self.assertEqual(
            list(exception), ["id", "advisory", "component", "reason"]
        )

    # --- Policy, admission and risk ----------------------------------------

    def test_resource_policy_is_reported_with_admission(self) -> None:
        root = self._register("root", DIGEST_A)
        self._add_policy(root, max_severity="low")
        self._add_alert(root, severity="critical")

        node = self._bundle(root)["resources"][0]  # type: ignore[index]
        self.assertEqual(
            node["policy"],
            {
                "source": "resource",
                "record": {
                    "name": "release-gate",
                    "evidence_requirements": [],
                    "license_allowlist": [],
                    "max_severity": "low",
                },
            },
        )
        self.assertEqual(
            node["admission"],
            {"id": root, "allowed": False, "reasons": ["severity_exceeded"]},
        )

    def test_default_policy_applies_when_resource_has_none(self) -> None:
        root = self._register("root", DIGEST_A)
        self._set_default_policy()

        node = self._bundle(root)["resources"][0]  # type: ignore[index]
        self.assertEqual(node["policy"]["source"], "default")
        self.assertEqual(node["policy"]["record"]["name"], "release-gate")
        self.assertEqual(
            node["admission"], {"id": root, "allowed": True, "reasons": []}
        )

    def test_resource_policy_wins_over_default(self) -> None:
        root = self._register("root", DIGEST_A)
        self._add_policy(root, name="own")
        self._set_default_policy(name="fallback")

        node = self._bundle(root)["resources"][0]  # type: ignore[index]
        self.assertEqual(node["policy"]["source"], "resource")
        self.assertEqual(node["policy"]["record"]["name"], "own")

    def test_admission_counts_exempted_alerts_like_the_evaluation(self) -> None:
        root = self._register("root", DIGEST_A)
        self._add_policy(root, max_severity="high")
        self._add_alert(root, severity="critical")
        self._add_exception(root)

        node = self._bundle(root)["resources"][0]  # type: ignore[index]
        self.assertEqual(
            node["admission"],
            {"id": root, "allowed": False, "reasons": ["severity_exceeded"]},
        )

    def test_risk_reuses_the_existing_report(self) -> None:
        root = self._register("root", DIGEST_A)
        self._add_alert(root, severity="critical")

        node = self._bundle(root)["resources"][0]  # type: ignore[index]
        _s, _h, risk = call_json("GET", f"/resources/{root}/risk")
        self.assertEqual(node["risk"], risk)
        self.assertEqual(list(node["risk"]), ["id", "score", "level"])

    # --- Cross-references ----------------------------------------------------

    def test_cross_references_reuse_the_existing_listing_shape(self) -> None:
        root = self._register("root", DIGEST_A)
        self._add_cross_reference(root)

        node = self._bundle(root)["resources"][0]  # type: ignore[index]
        references = node["cross_references"]
        self.assertEqual(len(references), 1)
        self.assertEqual(
            references[0],
            {
                "resource_id": root,
                "repository": "partner",
                "upstream": "https://repo.example.invalid",
                "remote_id": "remote-42",
                "digest": DIGEST_D,
            },
        )

    # --- Read-only, recomputation -------------------------------------------

    def test_successful_query_records_nothing(self) -> None:
        root = self._register("root", DIGEST_A)
        dep = self._register("dep", DIGEST_B)
        self._add(root, dep)
        self._set_default_policy()

        self._bundle(root)
        self._bundle(root)

        _s, _h, graph = call_json("GET", "/graph")
        self.assertEqual(len(graph["nodes"]), 2)  # type: ignore[index]
        self.assertEqual(len(graph["edges"]), 1)  # type: ignore[index]
        _s, _h, resources = call_json("GET", "/resources")
        self.assertEqual(len(resources["resources"]), 2)  # type: ignore[index]

    def test_results_recompute_after_state_changes(self) -> None:
        root = self._register("root", DIGEST_A)
        dep = self._register("dep", DIGEST_B)
        self.assertEqual(len(self._bundle(root)["resources"]), 1)  # type: ignore[index]

        self._add(root, dep)
        self.assertEqual(len(self._bundle(root)["resources"]), 2)  # type: ignore[index]

        status, _h, body = call_json("DELETE", f"/resources/{dep}")
        assert status == "200 OK", body
        self.assertEqual(len(self._bundle(root)["resources"]), 1)  # type: ignore[index]

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

    # --- Request envelope ----------------------------------------------------

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
        for path in (
            "/resources//trace-bundle",
            "/resources/a/b/trace-bundle",
        ):
            with self.subTest(path=path):
                status, _h, parsed = call_json("GET", path)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(parsed["error"], "invalid_request")  # type: ignore[index]

    def test_unknown_root_is_404(self) -> None:
        status, _h, parsed = call_json("GET", "/resources/unknown/trace-bundle")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(parsed["error"], "resource_not_found")  # type: ignore[index]

    # --- Methods ---------------------------------------------------------------

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
