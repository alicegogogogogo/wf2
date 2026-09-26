from __future__ import annotations

import hashlib
import io
import json
import unittest

from provenance_api.app import (
    application,
    cross_reference_store,
    reset_state,
)
from provenance_api.cross_references import CrossReference

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_D = "d" * 64


def call(
    method: str,
    path: str,
    body: bytes | str | dict[str, object] | None = None,
    *,
    content_length: int | str | None = None,
    content_type: str | None = None,
    omit_content_length: bool = False,
    query_string: str | None = None,
) -> tuple[str, list[tuple[str, str]], bytes]:
    if body is None:
        payload = b""
        length = "0"
    elif isinstance(body, dict):
        payload = json.dumps(body).encode("utf-8")
        length = str(len(payload))
    else:
        payload = body.encode("utf-8") if isinstance(body, str) else body
        length = str(len(payload))

    environ: dict[str, object] = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "wsgi.input": io.BytesIO(payload),
    }
    if not omit_content_length:
        environ["CONTENT_LENGTH"] = (
            length if content_length is None else str(content_length)
        )
    if content_type is not None:
        environ["CONTENT_TYPE"] = content_type
    if query_string is not None:
        environ["QUERY_STRING"] = query_string
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
    **kwargs: object,
) -> tuple[str, list[tuple[str, str]], dict[str, object]]:
    status, headers, raw = call(
        method, path, body, query_string=query_string, **kwargs
    )
    return status, headers, json.loads(raw.decode("utf-8"))


class ResourceDeleteTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def _create(
        self,
        name: str = "r",
        digest: str = DIGEST_A,
        category: str = "code",
        source: str | None = None,
    ) -> dict[str, object]:
        payload: dict[str, object] = {
            "name": name,
            "category": category,
            "digest": digest,
        }
        if source is not None:
            payload["source"] = source
        status, _headers, body = call_json("POST", "/resources", payload)
        self.assertEqual(status, "201 Created")
        return body

    def _id(self, name: str = "r", digest: str = DIGEST_A) -> str:
        return str(self._create(name, digest)["id"])

    # --- Success path ------------------------------------------------------

    def test_delete_returns_full_record(self) -> None:
        created = self._create(
            "model-a",
            "A1B2" + "0" * 60,
            category="Model",
            source="https://example.invalid/a",
        )
        status, headers, body = call_json(
            "DELETE", f"/resources/{created['id']}"
        )
        self.assertEqual(status, "200 OK")
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )
        self.assertEqual(body, created)
        self.assertEqual(
            body["digest"], "a1b2" + "0" * 60
        )

    def test_delete_response_is_compact_and_newline_terminated(self) -> None:
        resource_id = self._id()
        status, _headers, raw = call("DELETE", f"/resources/{resource_id}")
        self.assertEqual(status, "200 OK")
        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(b" ", raw[:-1])
        self.assertEqual(raw.count(b"\n"), 1)

    def test_deleted_resource_is_gone_everywhere(self) -> None:
        resource_id = self._id()
        call_json("DELETE", f"/resources/{resource_id}")

        status, _h, body = call_json("GET", f"/resources/{resource_id}")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

        _s, _h, listing = call_json("GET", "/resources")
        self.assertEqual(listing["resources"], [])

        _s, _h, filtered = call_json(
            "GET", "/resources", query_string="name=r"
        )
        self.assertEqual(filtered["resources"], [])
        self.assertIsNone(filtered["next_cursor"])

    def test_second_delete_is_not_found(self) -> None:
        resource_id = self._id()
        call_json("DELETE", f"/resources/{resource_id}")
        status, _h, body = call_json("DELETE", f"/resources/{resource_id}")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

    def test_unknown_id_is_not_found(self) -> None:
        status, _h, body = call_json("DELETE", "/resources/does-not-exist")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

    def test_new_registration_gets_fresh_id_and_default_state(self) -> None:
        resource_id = self._id("x", DIGEST_A)
        # Move it out of the default state first.
        status, _h, _body = call_json(
            "POST",
            f"/resources/{resource_id}/lifecycle",
            {"state": "quarantined", "reason": "bad"},
        )
        self.assertEqual(status, "200 OK")
        call_json("DELETE", f"/resources/{resource_id}")

        # The same category/name/digest combination can be registered again
        # and receives a brand-new id.
        recreated = self._create("x", DIGEST_A)
        self.assertNotEqual(recreated["id"], resource_id)
        _s, _h, lifecycle = call_json(
            "GET", f"/resources/{recreated['id']}/lifecycle"
        )
        self.assertEqual(
            lifecycle,
            {"id": recreated["id"], "state": "staged", "reason": None},
        )

    # --- Request validation -------------------------------------------------

    def test_empty_or_separator_id_is_bad_request(self) -> None:
        resource_id = self._id()
        for path in ("/resources/", "/resources/a/b", "/resources/a\\b"):
            with self.subTest(path=path):
                status, _h, body = call_json("DELETE", path)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")
        # Nothing was touched.
        _s, _h, listing = call_json("GET", "/resources")
        self.assertEqual(len(listing["resources"]), 1)

    def test_any_query_parameter_is_bad_request(self) -> None:
        resource_id = self._id()
        status, _h, body = call_json(
            "DELETE", f"/resources/{resource_id}", query_string="anything=1"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        _s, _h, fetched = call_json("GET", f"/resources/{resource_id}")
        self.assertEqual(fetched["id"], resource_id)

    def test_declared_body_is_bad_request(self) -> None:
        resource_id = self._id()
        for kwargs in (
            {"body": b"{}"},
            {"body": b"x"},
            {"content_length": "abc"},
            {"content_length": "5"},
        ):
            with self.subTest(kwargs=kwargs):
                body = kwargs.pop("body", None)
                status, _h, payload = call_json(
                    "DELETE", f"/resources/{resource_id}", body, **kwargs
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(payload["error"], "invalid_request")
        _s, _h, fetched = call_json("GET", f"/resources/{resource_id}")
        self.assertEqual(fetched["id"], resource_id)

    def test_explicit_zero_length_body_is_accepted(self) -> None:
        resource_id = self._id()
        status, _h, body = call_json(
            "DELETE", f"/resources/{resource_id}", content_length="0"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["id"], resource_id)

    def test_unsupported_methods_return_405_with_allow(self) -> None:
        resource_id = self._id()
        for method in ("PUT", "PATCH", "POST"):
            with self.subTest(method=method):
                status, headers, body = call_json(
                    method, f"/resources/{resource_id}"
                )
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")
                self.assertIn(("Allow", "DELETE, GET"), headers)
        # Failed requests changed nothing.
        _s, _h, fetched = call_json("GET", f"/resources/{resource_id}")
        self.assertEqual(fetched["id"], resource_id)

    def test_failed_requests_leave_other_resources_untouched(self) -> None:
        first = self._id("a", DIGEST_A)
        second = self._id("b", DIGEST_B)
        call_json("DELETE", f"/resources/{first}", query_string="x=1")
        call_json("DELETE", f"/resources/{first}", b"{}")
        call_json("DELETE", "/resources/missing")
        _s, _h, listing = call_json("GET", "/resources")
        self.assertEqual(
            [r["id"] for r in listing["resources"]], [first, second]
        )

    # --- Cascade: per-resource records -------------------------------------

    def _register_everything(self, resource_id: str, digest: str) -> None:
        # Alerts and an exemption.
        status, _h, alert = call_json(
            "POST",
            f"/resources/{resource_id}/vulnerabilities",
            {
                "advisory": "CVE-2026-0001",
                "component": "openssl",
                "severity": "HIGH",
                "summary": "buffer overflow",
                "fixed_version": "3.0.9",
            },
        )
        self.assertEqual(status, "201 Created")
        status, _h, _body = call_json(
            "POST",
            f"/resources/{resource_id}/vulnerability-exceptions",
            {
                "advisory": "CVE-2026-0001",
                "component": "openssl",
                "reason": "accepted",
            },
        )
        self.assertEqual(status, "201 Created")
        # SBOM and license.
        status, _h, _body = call_json(
            "POST",
            f"/resources/{resource_id}/sbom",
            {
                "format": "spdx",
                "components": [
                    {"name": "openssl", "version": "3.0.8", "digest": digest}
                ],
            },
        )
        self.assertEqual(status, "201 Created")
        status, _h, _body = call_json(
            "POST",
            f"/resources/{resource_id}/license",
            {"spdx_id": "Apache-2.0"},
        )
        self.assertEqual(status, "201 Created")
        # Provenance.
        status, _h, _body = call_json(
            "POST",
            f"/resources/{resource_id}/provenance",
            {
                "builder": "ci",
                "build_number": "1",
                "source_digest": digest,
                "materials": [],
            },
        )
        self.assertEqual(status, "201 Created")
        # Policy.
        status, _h, _body = call_json(
            "POST",
            f"/resources/{resource_id}/policies",
            {
                "name": "gate",
                "evidence_requirements": ["sbom"],
                "license_allowlist": ["Apache-2.0"],
                "max_severity": "high",
            },
        )
        self.assertEqual(status, "201 Created")
        # Signature.
        status, _h, _body = call_json(
            "POST",
            f"/resources/{resource_id}/signatures",
            {
                "signer": "alice",
                "algorithm": "hmac-sha256",
                "key_id": "secret",
                "signature": "ab" * 32,
                "digest": digest,
            },
        )
        self.assertEqual(status, "201 Created")
        # Notification.
        status, _h, _body = call_json(
            "POST",
            f"/resources/{resource_id}/notifications",
            {
                "channel": "email",
                "target": "ops@example.invalid",
                "message": "hello",
            },
        )
        self.assertEqual(status, "201 Created")
        # Lifecycle out of the default.
        status, _h, _body = call_json(
            "POST",
            f"/resources/{resource_id}/lifecycle",
            {"state": "quarantined", "reason": "tainted"},
        )
        self.assertEqual(status, "200 OK")

    def test_delete_cascades_all_per_resource_records(self) -> None:
        resource_id = self._id("main", DIGEST_A)
        self._register_everything(resource_id, DIGEST_A)

        # A completed artifact: upload one chunk with the required headers
        # and assemble it.
        content = b"artifact-bytes"
        artifact_digest = hashlib.sha256(content).hexdigest()
        complete_id = self._id("complete", artifact_digest)
        environ = {
            "REQUEST_METHOD": "POST",
            "PATH_INFO": f"/resources/{complete_id}/chunks/0",
            "wsgi.input": io.BytesIO(content),
            "CONTENT_LENGTH": str(len(content)),
            "CONTENT_TYPE": "application/octet-stream",
            "HTTP_X_TOTAL_CHUNKS": "1",
            "HTTP_X_CONTENT_DIGEST": artifact_digest,
        }
        captured: dict[str, object] = {}

        def start_response(status_line: str, headers: list) -> None:
            captured["status"] = status_line

        b"".join(application(environ, start_response))
        self.assertEqual(captured["status"], "201 Created")
        status, _h, _body = call_json(
            "POST", f"/resources/{complete_id}/assemble"
        )
        self.assertEqual(status, "201 Created")

        # An incomplete upload session on the main resource.
        main_content = b"partial"
        environ = {
            "REQUEST_METHOD": "POST",
            "PATH_INFO": f"/resources/{resource_id}/chunks/0",
            "wsgi.input": io.BytesIO(main_content),
            "CONTENT_LENGTH": str(len(main_content)),
            "CONTENT_TYPE": "application/octet-stream",
            "HTTP_X_TOTAL_CHUNKS": "2",
            "HTTP_X_CONTENT_DIGEST": DIGEST_A,
        }
        captured2: dict[str, object] = {}

        def start_response2(status_line: str, headers: list) -> None:
            captured2["status"] = status_line

        b"".join(application(environ, start_response2))
        self.assertEqual(captured2["status"], "201 Created")

        status, _h, _body = call_json("DELETE", f"/resources/{resource_id}")
        self.assertEqual(status, "200 OK")
        status, _h, _body = call_json("DELETE", f"/resources/{complete_id}")
        self.assertEqual(status, "200 OK")

        # Every record is gone: each sub-resource now reports not found or
        # the not-started/not-registered state of a fresh resource.
        gone_expectations = [
            ("GET", f"/resources/{resource_id}/vulnerabilities", 404, "resource_not_found"),
            ("GET", f"/resources/{resource_id}/vulnerability-exceptions", 404, "resource_not_found"),
            ("GET", f"/resources/{resource_id}/sbom", 404, "resource_not_found"),
            ("GET", f"/resources/{resource_id}/license", 404, "resource_not_found"),
            ("GET", f"/resources/{resource_id}/provenance", 404, "resource_not_found"),
            ("GET", f"/resources/{resource_id}/policies", 404, "resource_not_found"),
            ("GET", f"/resources/{resource_id}/signatures", 404, "resource_not_found"),
            ("GET", f"/resources/{resource_id}/notifications", 404, "resource_not_found"),
            ("GET", f"/resources/{resource_id}/lifecycle", 404, "resource_not_found"),
            ("GET", f"/resources/{resource_id}/chunks/status", 404, "resource_not_found"),
            ("GET", f"/resources/{complete_id}/content", 404, "resource_not_found"),
            ("GET", f"/resources/{complete_id}/chunks/status", 404, "resource_not_found"),
        ]
        for method, path, expected_status, expected_error in gone_expectations:
            with self.subTest(path=path):
                status, _h, body = call_json(method, path)
                self.assertEqual(status, f"{expected_status} Not Found")
                self.assertEqual(body["error"], expected_error)

        # The global advisory summary no longer counts the deleted alerts.
        _s, _h, advisories = call_json("GET", "/advisories")
        self.assertEqual(advisories, [])

    def test_views_recompute_after_delete(self) -> None:
        first = self._id("first", DIGEST_A)
        second = self._id("second", DIGEST_B)
        for resource_id, advisory in (
            (first, "CVE-2026-0001"),
            (second, "CVE-2026-0001"),
            (second, "CVE-2026-0002"),
        ):
            status, _h, _body = call_json(
                "POST",
                f"/resources/{resource_id}/vulnerabilities",
                {
                    "advisory": advisory,
                    "component": "openssl",
                    "severity": "high",
                    "summary": "s",
                },
            )
            self.assertEqual(status, "201 Created")

        call_json("DELETE", f"/resources/{second}")

        _s, _h, advisories = call_json("GET", "/advisories")
        self.assertEqual(len(advisories), 1)
        self.assertEqual(advisories[0]["advisory"], "CVE-2026-0001")
        self.assertEqual(advisories[0]["affected_resources"], [first])
        self.assertEqual(advisories[0]["advisory_count"], 1)

        _s, _h, detail = call_json("GET", "/advisories/CVE-2026-0002")
        self.assertEqual(detail["alerts"], [])
        self.assertEqual(detail["affected_resources"], [])

    # --- Cascade: dependency edges ------------------------------------------

    def test_delete_removes_edges_in_both_directions(self) -> None:
        a = self._id("a", DIGEST_A)
        b = self._id("b", DIGEST_B)
        c = self._id("c", DIGEST_C)
        d = self._id("d", DIGEST_D)
        # a -> b, c -> b, b -> d
        for start, dep in ((a, b), (c, b), (b, d)):
            status, _h, _body = call_json(
                "POST",
                f"/resources/{start}/dependencies",
                {"dependency_id": dep},
            )
            self.assertEqual(status, "201 Created")

        call_json("DELETE", f"/resources/{b}")

        _s, _h, deps_a = call_json("GET", f"/resources/{a}/dependencies")
        self.assertEqual(deps_a["dependencies"], [])
        _s, _h, deps_c = call_json("GET", f"/resources/{c}/dependencies")
        self.assertEqual(deps_c["dependencies"], [])
        _s, _h, impact_d = call_json("GET", f"/resources/{d}/impact")
        self.assertEqual(impact_d["resources"], [])
        _s, _h, impact_a = call_json("GET", f"/resources/{a}/impact")
        self.assertEqual(impact_a["resources"], [])

        # The other resources themselves are untouched.
        _s, _h, listing = call_json("GET", "/resources")
        self.assertEqual(
            [r["id"] for r in listing["resources"]], [a, c, d]
        )

    def test_dependency_vulnerability_impact_drops_deleted_resource(self) -> None:
        a = self._id("a", DIGEST_A)
        b = self._id("b", DIGEST_B)
        call_json(
            "POST", f"/resources/{a}/dependencies", {"dependency_id": b}
        )
        status, _h, _body = call_json(
            "POST",
            f"/resources/{b}/vulnerabilities",
            {
                "advisory": "CVE-2026-0001",
                "component": "openssl",
                "severity": "critical",
                "summary": "s",
            },
        )
        self.assertEqual(status, "201 Created")

        call_json("DELETE", f"/resources/{b}")

        _s, _h, impact = call_json(
            "GET", f"/resources/{a}/dependency-vulnerability-impact"
        )
        self.assertEqual(
            impact["impacts"],
            [
                {
                    "resource_id": a,
                    "advisory_count": 0,
                    "max_severity": None,
                }
            ],
        )

    # --- Cascade: cross-references -------------------------------------------

    def test_delete_removes_registered_cross_references(self) -> None:
        local = self._id("local", DIGEST_A)
        remote = self._id("remote", DIGEST_B)
        # Simulate the record a successful resolution would have committed.
        cross_reference_store._records.append(
            CrossReference(
                resource_id=local,
                repository="partner",
                upstream="https://repo.example.invalid/",
                remote_id="remote-42",
                digest=DIGEST_B,
            )
        )
        cross_reference_store._repository_upstream.setdefault(
            "partner", "https://repo.example.invalid/"
        )
        cross_reference_store._pairs.add(("partner", "remote-42"))
        status, _h, _body = call_json(
            "POST", f"/resources/{local}/dependencies", {"dependency_id": remote}
        )
        self.assertEqual(status, "201 Created")

        _s, _h, refs = call_json("GET", f"/resources/{local}/cross-references")
        self.assertEqual(len(refs["cross_references"]), 1)

        call_json("DELETE", f"/resources/{local}")

        # The reference record is gone; the resolved remote resource stays.
        self.assertEqual(cross_reference_store.list_for(local), [])
        _s, _h, fetched = call_json("GET", f"/resources/{remote}")
        self.assertEqual(fetched["id"], remote)
        # The (repository, remote_id) pair is released for future use.
        self.assertNotIn(("partner", "remote-42"), cross_reference_store._pairs)

    # --- Isolation: cache, mirrors, cursors ----------------------------------

    def test_cache_entries_and_mirrors_are_untouched(self) -> None:
        resource_id = self._id("r", DIGEST_A)
        layer = b"layer-bytes"
        layer_digest = hashlib.sha256(layer).hexdigest()
        status, _h, _body = call(
            "POST",
            f"/cache/layers/{layer_digest}",
            layer,
            content_type="application/octet-stream",
        )
        self.assertEqual(status, "201 Created")
        status, _h, mirror = call_json(
            "POST",
            "/mirrors",
            {"name": "primary", "upstream": "https://registry.example.invalid/"},
        )
        self.assertEqual(status, "201 Created")

        call_json("DELETE", f"/resources/{resource_id}")

        status, _h, raw = call("GET", f"/cache/layers/{layer_digest}")
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, layer)
        _s, _h, mirrors = call_json("GET", "/mirrors")
        self.assertEqual(len(mirrors["mirrors"]), 1)
        self.assertEqual(mirrors["mirrors"][0]["id"], mirror["id"])

    def test_other_resources_records_survive(self) -> None:
        keep = self._id("keep", DIGEST_A)
        drop = self._id("drop", DIGEST_B)
        for resource_id in (keep, drop):
            status, _h, _body = call_json(
                "POST",
                f"/resources/{resource_id}/vulnerabilities",
                {
                    "advisory": "CVE-2026-0001",
                    "component": "openssl",
                    "severity": "low",
                    "summary": "s",
                },
            )
            self.assertEqual(status, "201 Created")

        call_json("DELETE", f"/resources/{drop}")

        _s, _h, alerts = call_json("GET", f"/resources/{keep}/vulnerabilities")
        self.assertEqual(len(alerts["vulnerabilities"]), 1)
        _s, _h, advisories = call_json("GET", "/advisories")
        self.assertEqual(len(advisories), 1)
        self.assertEqual(advisories[0]["affected_resources"], [keep])

    def test_issued_cursor_still_valid_and_skips_deleted(self) -> None:
        ids = [self._id(f"r{i}", f"{i:064x}") for i in range(4)]
        _s, _h, first = call_json(
            "GET", "/resources", query_string="limit=2"
        )
        self.assertEqual(
            [r["id"] for r in first["resources"]], ids[0:2]
        )
        cursor = first["next_cursor"]
        self.assertIsNotNone(cursor)

        # Delete one resource from the first page and one from the second.
        call_json("DELETE", f"/resources/{ids[1]}")
        call_json("DELETE", f"/resources/{ids[2]}")

        # The previously issued cursor is still accepted; the remaining
        # resources are the only ones listed.
        status, _h, second = call_json(
            "GET", "/resources", query_string=f"limit=2&cursor={cursor}"
        )
        self.assertEqual(status, "200 OK")
        self.assertNotIn(ids[1], [r["id"] for r in second["resources"]])
        self.assertNotIn(ids[2], [r["id"] for r in second["resources"]])

        _s, _h, listing = call_json("GET", "/resources")
        self.assertEqual(
            [r["id"] for r in listing["resources"]], [ids[0], ids[3]]
        )


if __name__ == "__main__":
    unittest.main()
