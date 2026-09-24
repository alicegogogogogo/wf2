from __future__ import annotations

import hashlib
import io
import json
import unittest

from provenance_api.app import application, policy_store, reset_state

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_D = "d" * 64
EMPTY_DIGEST = hashlib.sha256(b"").hexdigest()

POLICY_KEYS = [
    "id",
    "name",
    "evidence_requirements",
    "allowed_licenses",
    "max_severity",
]
ADMISSION_KEYS = ["id", "allowed", "reasons"]


def call(
    method: str,
    path: str,
    body: bytes | str | dict[str, object] | None = None,
    *,
    query_string: str | None = None,
    content_type: str | None = "application/json",
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
        "wsgi.input": io.BytesIO(payload),
    }
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
    path: str,
    body: bytes | str | dict[str, object] | None = None,
    *,
    query_string: str | None = None,
) -> tuple[str, list[tuple[str, str]], dict[str, object]]:
    status, headers, raw = call(
        method, path, body, query_string=query_string
    )
    return status, headers, json.loads(raw.decode("utf-8"))


def policy_payload(
    *,
    name: object = "release-gate",
    evidence_requirements: object = ...,  # type: ignore[assignment]
    allowed_licenses: object = ...,  # type: ignore[assignment]
    max_severity: object = "high",
) -> dict[str, object]:
    if evidence_requirements is ...:
        evidence_requirements = []
    if allowed_licenses is ...:
        allowed_licenses = []
    return {
        "name": name,
        "evidence_requirements": evidence_requirements,
        "allowed_licenses": allowed_licenses,
        "max_severity": max_severity,
    }


class PolicyRegistrationTests(unittest.TestCase):
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

    def _post(
        self, resource_id: str, payload: object
    ) -> tuple[str, list[tuple[str, str]], dict[str, object]]:
        return call_json(
            "POST", f"/resources/{resource_id}/policies", payload
        )

    def test_register_returns_201_and_echoes_policy(self) -> None:
        payload = policy_payload(
            evidence_requirements=["provenance", "sbom"],
            allowed_licenses=["Apache-2.0", "MIT"],
            max_severity="MEDIUM",
        )
        status, headers, body = self._post(self.resource_id, payload)

        self.assertEqual(status, "201 Created")
        self.assertEqual(
            headers[0], ("Content-Type", "application/json; charset=utf-8")
        )
        self.assertEqual(list(body), POLICY_KEYS)
        self.assertEqual(body["id"], self.resource_id)
        self.assertEqual(body["name"], "release-gate")
        self.assertEqual(body["evidence_requirements"], ["provenance", "sbom"])
        self.assertEqual(body["allowed_licenses"], ["Apache-2.0", "MIT"])
        # The cap is matched case-insensitively and stored in lowercase.
        self.assertEqual(body["max_severity"], "medium")

    def test_response_is_compact_utf8_and_newline_terminated(self) -> None:
        status, _headers, raw = call(
            "POST",
            f"/resources/{self.resource_id}/policies",
            policy_payload(name="策略-α"),
        )
        self.assertEqual(status, "201 Created")
        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(b" ", raw[:-1])
        body = json.loads(raw.decode("utf-8"))
        self.assertEqual(body["name"], "策略-α")

    def test_empty_collections_are_accepted(self) -> None:
        status, _h, body = self._post(
            self.resource_id,
            policy_payload(evidence_requirements=[], allowed_licenses=[]),
        )
        self.assertEqual(status, "201 Created")
        self.assertEqual(body["evidence_requirements"], [])
        self.assertEqual(body["allowed_licenses"], [])

    def test_evidence_order_is_preserved(self) -> None:
        payload = policy_payload(
            evidence_requirements=["license", "provenance", "sbom"]
        )
        _s, _h, body = self._post(self.resource_id, payload)
        self.assertEqual(
            body["evidence_requirements"],
            ["license", "provenance", "sbom"],
        )

    def test_name_bound_is_code_points(self) -> None:
        status, _h, body = self._post(
            self.resource_id, policy_payload(name="😀" * 256)
        )
        self.assertEqual(status, "201 Created")
        self.assertEqual(body["name"], "😀" * 256)

    def test_get_returns_the_unique_policy(self) -> None:
        _s, _h, created = self._post(
            self.resource_id, policy_payload(max_severity="low")
        )
        status, _headers, body = call_json(
            "GET", f"/resources/{self.resource_id}/policies"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, created)

    def test_get_without_policy_is_policy_not_found(self) -> None:
        status, _headers, body = call_json(
            "GET", f"/resources/{self.resource_id}/policies"
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "policy_not_found")

    def test_resource_missing_for_get_and_post(self) -> None:
        for method, path, payload in [
            ("GET", "/resources/missing/policies", None),
            (
                "POST",
                "/resources/missing/policies",
                policy_payload(),
            ),
        ]:
            with self.subTest(method=method):
                status, _headers, body = call_json(method, path, payload)
                self.assertEqual(status, "404 Not Found")
                self.assertEqual(body["error"], "resource_not_found")


class PolicyIdempotencyTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.resource_id = self._create(DIGEST_A)

    def _create(self, digest: str) -> str:
        _s, _h, body = call_json(
            "POST",
            "/resources",
            {"name": "r", "category": "code", "digest": digest},
        )
        return str(body["id"])

    def test_same_content_returns_200_byte_identical(self) -> None:
        payload = policy_payload(
            evidence_requirements=["sbom"],
            allowed_licenses=["MIT"],
            max_severity="high",
        )
        status, _h, first = call_json(
            "POST", f"/resources/{self.resource_id}/policies", payload
        )
        self.assertEqual(status, "201 Created")

        # Only the severity casing differs; normalization makes it equal.
        repeated = json.loads(json.dumps(payload))
        repeated["max_severity"] = "HIGH"
        status, _h, body = call_json(
            "POST", f"/resources/{self.resource_id}/policies", repeated
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, first)

    def test_different_content_returns_conflict_and_keeps_original(self) -> None:
        _s, _h, first = call_json(
            "POST",
            f"/resources/{self.resource_id}/policies",
            policy_payload(
                name="a",
                evidence_requirements=["sbom"],
                allowed_licenses=["MIT"],
                max_severity="high",
            ),
        )
        variants = [
            policy_payload(name="b"),
            policy_payload(evidence_requirements=["provenance"]),
            policy_payload(allowed_licenses=["Apache-2.0"]),
            policy_payload(max_severity="critical"),
            policy_payload(
                evidence_requirements=["sbom", "license"]
            ),
        ]
        for variant in variants:
            with self.subTest(variant=variant):
                status, _h, body = call_json(
                    "POST",
                    f"/resources/{self.resource_id}/policies",
                    variant,
                )
                self.assertEqual(status, "409 Conflict")
                self.assertEqual(body["error"], "policy_conflict")

        status, _h, fetched = call_json(
            "GET", f"/resources/{self.resource_id}/policies"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(fetched, first)

    def test_license_list_accepts_either_spelling_and_echoes_it(self) -> None:
        # The statement describes the list without pinning its key; both
        # natural spellings are accepted and echoed on the wire.
        for index, key in enumerate(
            ("allowed_licenses", "license_allowlist"), start=2
        ):
            with self.subTest(key=key):
                resource_id = self._create(chr(ord("a") + index) * 64)
                body = {
                    "name": "p",
                    "evidence_requirements": [],
                    key: ["MIT"],
                    "max_severity": "high",
                }
                status, _h, created = call_json(
                    "POST", f"/resources/{resource_id}/policies", body
                )
                self.assertEqual(status, "201 Created")
                self.assertEqual(
                    list(created),
                    [
                        "id",
                        "name",
                        "evidence_requirements",
                        key,
                        "max_severity",
                    ],
                )
                self.assertEqual(created[key], ["MIT"])

                status, _h, fetched = call_json(
                    "GET", f"/resources/{resource_id}/policies"
                )
                self.assertEqual(status, "200 OK")
                self.assertEqual(fetched, created)

    def test_same_content_repeated_under_either_key_is_idempotent(self) -> None:
        body = {
            "name": "p",
            "evidence_requirements": [],
            "license_allowlist": ["MIT"],
            "max_severity": "high",
        }
        status, _h, first = call_json(
            "POST", f"/resources/{self.resource_id}/policies", body
        )
        self.assertEqual(status, "201 Created")

        # Resubmitting under the other spelling is still a 200 repeat, and
        # the stored (original) wire key is returned unchanged.
        other = {
            "name": "p",
            "evidence_requirements": [],
            "allowed_licenses": ["MIT"],
            "max_severity": "HIGH",
        }
        status, _h, body_resp = call_json(
            "POST", f"/resources/{self.resource_id}/policies", other
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body_resp, first)

    def test_both_license_keys_together_are_rejected(self) -> None:
        body = {
            "name": "p",
            "evidence_requirements": [],
            "allowed_licenses": [],
            "license_allowlist": [],
            "max_severity": "high",
        }
        status, _h, resp = call_json(
            "POST", f"/resources/{self.resource_id}/policies", body
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(resp["error"], "invalid_request")


class PolicyValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.resource_id = self._create(DIGEST_A)

    def _create(self, digest: str) -> str:
        _s, _h, body = call_json(
            "POST",
            "/resources",
            {"name": "r", "category": "code", "digest": digest},
        )
        return str(body["id"])

    def assert_bad(self, payload: object, label: str) -> None:
        status, _headers, body = call_json(
            "POST", f"/resources/{self.resource_id}/policies", payload
        )
        self.assertEqual(status, "400 Bad Request", (label, status))
        self.assertEqual(body["error"], "invalid_request", (label, body))
        self.assertEqual(list(body), ["error", "message"])

    def test_body_level_errors(self) -> None:
        for raw_body in (b"", b"\xff\xfe", b"{bad", b"[]", b'"x"', b"42", b"null"):
            with self.subTest(raw_body=raw_body):
                status, _h, body = call_json(
                    "POST",
                    f"/resources/{self.resource_id}/policies",
                    raw_body,
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_missing_fields(self) -> None:
        valid = policy_payload()
        for field in (
            "name",
            "evidence_requirements",
            "allowed_licenses",
            "max_severity",
        ):
            body = dict(valid)
            del body[field]
            self.assert_bad(body, f"missing {field}")

    def test_unknown_field(self) -> None:
        body = policy_payload()
        body["extra"] = 1
        self.assert_bad(body, "unknown field")

    def test_name_must_be_non_empty_within_bound(self) -> None:
        for value in ("", 1, None, True, [], {}, "x" * 257, "😀" * 257):
            self.assert_bad(policy_payload(name=value), f"name={value!r}")

    def test_evidence_requirements_must_be_an_array_of_known_values(self) -> None:
        for value in ({}, "x", 1, None, True, ["x"], ["SBOM"], [1], [None], [[]]):
            self.assert_bad(
                policy_payload(evidence_requirements=value),
                f"evidence={value!r}",
            )

    def test_evidence_requirements_must_not_repeat(self) -> None:
        self.assert_bad(
            policy_payload(evidence_requirements=["sbom", "sbom"]),
            "duplicate evidence",
        )

    def test_allowed_licenses_must_be_an_array_of_non_empty_strings(self) -> None:
        for value in ({}, "x", 1, None, True, [""], [1], [None], [[]], ["x", "x"]):
            self.assert_bad(
                policy_payload(allowed_licenses=value),
                f"licenses={value!r}",
            )

    def test_max_severity_must_be_one_of_four_levels(self) -> None:
        for value in ("", "urgent", "crit", 1, None, True, []):
            self.assert_bad(
                policy_payload(max_severity=value), f"cap={value!r}"
            )

    def test_query_parameters_rejected(self) -> None:
        for method, path, body in [
            ("GET", f"/resources/{self.resource_id}/policies", None),
            ("POST", f"/resources/{self.resource_id}/policies", policy_payload()),
        ]:
            with self.subTest(method=method):
                status, _h, payload = call_json(
                    method, path, body, query_string="x=1"
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(payload["error"], "invalid_request")

    def test_invalid_path_id(self) -> None:
        for path in (
            "/resources//policies",
            "/resources/a/b/policies",
            "/resources/a\\b/policies",
        ):
            with self.subTest(path=path):
                status, _h, body = call_json("POST", path, policy_payload())
                self.assertIn(status[:3], {"400", "404"})
                self.assertIn("error", body)

    def test_bad_request_never_writes_a_policy(self) -> None:
        self.assert_bad(policy_payload(name=""), "invalid")
        _s, _h, body = call_json(
            "GET", f"/resources/{self.resource_id}/policies"
        )
        self.assertEqual(body["error"], "policy_not_found")
        self.assertEqual(policy_store.get(self.resource_id), None)


class PolicyRoutingTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.resource_id = self._create(DIGEST_A)

    def _create(self, digest: str) -> str:
        _s, _h, body = call_json(
            "POST",
            "/resources",
            {"name": "r", "category": "code", "digest": digest},
        )
        return str(body["id"])

    def test_policies_unsupported_methods_allow_get_post(self) -> None:
        for method in ("PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, headers, body = call_json(
                    method, f"/resources/{self.resource_id}/policies"
                )
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")
                self.assertIn(("Allow", "GET, POST"), headers)

    def test_admission_supports_only_post(self) -> None:
        # A policy must exist before method handling is observable; register.
        call_json(
            "POST",
            f"/resources/{self.resource_id}/policies",
            policy_payload(),
        )
        for method in ("GET", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, headers, body = call_json(
                    method, f"/resources/{self.resource_id}/admission"
                )
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")
                self.assertIn(("Allow", "POST"), headers)


class AdmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.resource_id = self._create(DIGEST_A, "r")

    def _create(self, digest: str, name: str = "r") -> str:
        _s, _h, body = call_json(
            "POST",
            "/resources",
            {"name": name, "category": "code", "digest": digest},
        )
        return str(body["id"])

    def _policy(self, resource_id: str | None = None, **kwargs: object) -> None:
        resource_id = resource_id or self.resource_id
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/policies",
            policy_payload(**kwargs),
        )
        self.assertEqual(status, "201 Created", body)

    def _admit(
        self, resource_id: str | None = None
    ) -> tuple[str, dict[str, object]]:
        resource_id = resource_id or self.resource_id
        status, _h, body = call_json(
            "POST", f"/resources/{resource_id}/admission"
        )
        return status, body

    def _sbom(self, resource_id: str | None = None) -> None:
        resource_id = resource_id or self.resource_id
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/sbom",
            {"format": "spdx", "components": []},
        )
        self.assertEqual(status, "201 Created", body)

    def _license(
        self, spdx_id: str, resource_id: str | None = None
    ) -> None:
        resource_id = resource_id or self.resource_id
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/license",
            {"spdx_id": spdx_id},
        )
        self.assertEqual(status, "201 Created", body)

    def _provenance(self, resource_id: str | None = None) -> None:
        resource_id = resource_id or self.resource_id
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/provenance",
            {
                "builder": "ci",
                "build_number": "1",
                "source_digest": DIGEST_B,
                "materials": [],
            },
        )
        self.assertEqual(status, "201 Created", body)

    def _vulnerability(
        self, severity: str, resource_id: str | None = None
    ) -> None:
        resource_id = resource_id or self.resource_id
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/vulnerabilities",
            {
                "advisory": f"ADV-{severity}",
                "component": "openssl",
                "severity": severity,
                "summary": "summary",
            },
        )
        self.assertEqual(status, "201 Created", body)

    # --- Missing policy / resource ----------------------------------------

    def test_admission_without_policy_is_not_found(self) -> None:
        status, body = self._admit()
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "policy_not_found")

    def test_admission_for_missing_resource_is_not_found(self) -> None:
        status, _h, body = call_json("POST", "/resources/missing/admission")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

    # --- Request shape -----------------------------------------------------

    def test_admission_rejects_a_body(self) -> None:
        self._policy()
        for raw_body in (b"{}", b"[]", b"x"):
            with self.subTest(raw_body=raw_body):
                status, _h, body = call_json(
                    "POST",
                    f"/resources/{self.resource_id}/admission",
                    raw_body,
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_admission_rejects_query_parameters(self) -> None:
        self._policy()
        status, _h, body = call_json(
            "POST",
            f"/resources/{self.resource_id}/admission",
            query_string="x=1",
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_admission_response_shape(self) -> None:
        self._policy()
        status, headers, raw = call(
            "POST", f"/resources/{self.resource_id}/admission"
        )
        self.assertEqual(status, "200 OK")
        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(b" ", raw[:-1])
        body = json.loads(raw.decode("utf-8"))
        self.assertEqual(list(body), ADMISSION_KEYS)
        self.assertEqual(body["id"], self.resource_id)
        self.assertIs(body["allowed"], True)
        self.assertEqual(body["reasons"], [])
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )

    # --- State -------------------------------------------------------------

    def test_withdrawn_or_quarantined_resources_are_blocked(self) -> None:
        for target in ("quarantined", "withdrawn"):
            with self.subTest(target=target):
                # The empty content digest lets promotion succeed so the
                # released -> withdrawn path can be exercised.
                resource_id = self._create(EMPTY_DIGEST, name=target)
                self._policy(
                    resource_id, evidence_requirements=["sbom", "license"]
                )
                if target == "quarantined":
                    status, _h, body = call_json(
                        "POST",
                        f"/resources/{resource_id}/lifecycle",
                        {"state": "quarantined", "reason": "bad"},
                    )
                else:
                    # staged cannot reach withdrawn directly; release first.
                    self._release(resource_id)
                    status, _h, body = call_json(
                        "POST",
                        f"/resources/{resource_id}/lifecycle",
                        {"state": "withdrawn", "reason": "bad"},
                    )
                self.assertEqual(status, "200 OK", body)
                status, body = self._admit(resource_id)
                self.assertEqual(status, "200 OK")
                self.assertIs(body["allowed"], False)
                self.assertEqual(body["reasons"], ["state_blocked"])

    def test_state_block_short_circuits_other_checks(self) -> None:
        # Missing every piece of evidence and a wrong license, but state
        # blocking is reported alone: later checks are not performed.
        resource_id = self._create(DIGEST_D, name="blocked")
        self._policy(
            resource_id,
            evidence_requirements=["sbom", "license", "provenance"],
            allowed_licenses=["MIT"],
            max_severity="low",
        )
        self._vulnerability("critical", resource_id)
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/lifecycle",
            {"state": "quarantined", "reason": "bad"},
        )
        self.assertEqual(status, "200 OK", body)
        status, body = self._admit(resource_id)
        self.assertEqual(body["reasons"], ["state_blocked"])

    # --- Evidence ----------------------------------------------------------

    def test_missing_evidence_reported_per_item(self) -> None:
        self._policy(
            evidence_requirements=["sbom", "license", "provenance"]
        )
        _status, body = self._admit()
        self.assertEqual(
            body["reasons"], ["no_sbom", "no_license", "no_provenance"]
        )

        self._sbom()
        _status, body = self._admit()
        self.assertEqual(body["reasons"], ["no_license", "no_provenance"])

        self._license("MIT")
        _status, body = self._admit()
        self.assertEqual(body["reasons"], ["no_provenance"])

        self._provenance()
        _status, body = self._admit()
        self.assertEqual(body["reasons"], [])
        self.assertIs(body["allowed"], True)

    def test_unrequired_evidence_does_not_matter(self) -> None:
        # Only SBOM is required; the absence of a license or provenance is
        # not an error on its own.
        self._policy(evidence_requirements=["sbom"])
        self._sbom()
        _status, body = self._admit()
        self.assertEqual(body["reasons"], [])

    # --- License allowlist -------------------------------------------------

    def test_license_not_in_nonempty_allowlist_is_denied(self) -> None:
        self._policy(allowed_licenses=["Apache-2.0"])
        self._license("GPL-3.0")
        _status, body = self._admit()
        self.assertEqual(body["reasons"], ["license_denied"])

        resource_id = self._create(DIGEST_C, "allowed")
        self._policy(resource_id, allowed_licenses=["Apache-2.0", "MIT"])
        self._license("MIT", resource_id)
        _status, body = self._admit(resource_id)
        self.assertEqual(body["reasons"], [])

    def test_empty_allowlist_does_not_deny_any_license(self) -> None:
        self._policy(allowed_licenses=[])
        self._license("Whatever-1.0")
        _status, body = self._admit()
        self.assertEqual(body["reasons"], [])

    def test_missing_license_with_nonempty_allowlist_is_denied(self) -> None:
        # No license registered at all: both the evidence reason (when
        # required) and the allowlist rejection apply; when not required,
        # the allowlist alone denies.
        self._policy(
            evidence_requirements=["license"], allowed_licenses=["MIT"]
        )
        _status, body = self._admit()
        self.assertEqual(body["reasons"], ["no_license", "license_denied"])

        resource_id = self._create(DIGEST_C, "no-evidence-required")
        self._policy(resource_id, allowed_licenses=["MIT"])
        _status, body = self._admit(resource_id)
        self.assertEqual(body["reasons"], ["license_denied"])

    # --- Severity ----------------------------------------------------------

    def test_severity_above_cap_is_exceeded_case_insensitive(self) -> None:
        self._policy(max_severity="medium")
        # Stored alert severity is normalized to lowercase; cap matching is
        # case-insensitive on the way in.
        self._vulnerability("HIGH")
        _status, body = self._admit()
        self.assertEqual(body["reasons"], ["severity_exceeded"])

    def test_severity_at_or_below_cap_passes(self) -> None:
        self._policy(max_severity="medium")
        self._vulnerability("medium")
        self._vulnerability("low")
        _status, body = self._admit()
        self.assertEqual(body["reasons"], [])

    def test_low_cap_rejects_every_alert_level(self) -> None:
        for level in ("low", "medium", "high", "critical"):
            resource_id = self._create(
                f"{ord(level[0]):x}".ljust(64, "0"), level
            )
            self._policy(resource_id, max_severity="low")
            self._vulnerability(level, resource_id)
            _status, body = self._admit(resource_id)
            if level == "low":
                self.assertEqual(body["reasons"], [], level)
            else:
                self.assertEqual(body["reasons"], ["severity_exceeded"], level)

    # --- Combined ordering -------------------------------------------------

    def test_multiple_reasons_follow_state_evidence_license_severity(self) -> None:
        self._policy(
            evidence_requirements=["sbom", "license", "provenance"],
            allowed_licenses=["MIT"],
            max_severity="low",
        )
        self._vulnerability("critical")
        _status, body = self._admit()
        self.assertIs(body["allowed"], False)
        self.assertEqual(
            body["reasons"],
            [
                "no_sbom",
                "no_license",
                "no_provenance",
                "license_denied",
                "severity_exceeded",
            ],
        )

    def test_decision_is_read_only(self) -> None:
        self._policy(
            evidence_requirements=["sbom"],
            allowed_licenses=["MIT"],
            max_severity="high",
        )
        status, _h, before = call_json(
            "GET", f"/resources/{self.resource_id}/policies"
        )
        self.assertEqual(status, "200 OK")
        self._admit()
        self._admit()
        status, _h, after = call_json(
            "GET", f"/resources/{self.resource_id}/policies"
        )
        self.assertEqual(after, before)

    def _release(self, resource_id: str) -> None:
        # Promotion requires assembled content and healthy dependencies.
        resource = None
        _s, _h, listing = call_json("GET", "/resources")
        for item in listing["resources"]:
            if item["id"] == resource_id:
                resource = item
        self.assertIsNotNone(resource)
        digest = str(resource["digest"])
        self._upload_empty_content(resource_id, digest)
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/lifecycle",
            {"state": "released"},
        )
        self.assertEqual(status, "200 OK", body)

    def _upload_empty_content(self, resource_id: str, digest: str) -> None:
        environ: dict[str, object] = {
            "REQUEST_METHOD": "POST",
            "PATH_INFO": f"/resources/{resource_id}/chunks/0",
            "QUERY_STRING": "",
            "CONTENT_LENGTH": "0",
            "CONTENT_TYPE": "application/octet-stream",
            "HTTP_X_TOTAL_CHUNKS": "1",
            "HTTP_X_CONTENT_DIGEST": digest,
            "wsgi.input": io.BytesIO(b""),
        }
        captured: dict[str, object] = {}
        chunks = application(
            environ,
            lambda s, h: captured.update(status=s, headers=h),
        )
        b"".join(chunks)
        self.assertEqual(captured["status"], "201 Created", captured)
        environ = {
            "REQUEST_METHOD": "POST",
            "PATH_INFO": f"/resources/{resource_id}/assemble",
            "QUERY_STRING": "",
            "CONTENT_LENGTH": "0",
            "wsgi.input": io.BytesIO(b""),
        }
        captured = {}
        chunks = application(
            environ,
            lambda s, h: captured.update(status=s, headers=h),
        )
        b"".join(chunks)
        self.assertEqual(captured["status"], "201 Created", captured)


if __name__ == "__main__":
    unittest.main()
