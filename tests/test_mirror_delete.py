from __future__ import annotations

import hashlib
import io
import json
import unittest
from unittest import mock

from provenance_api.app import application, reset_state
from provenance_api.mirrors import MirrorFetchError

LAYER_A = b"alpha-layer-bytes"
DIGEST_A = hashlib.sha256(LAYER_A).hexdigest()

UPSTREAM = "https://registry.example.invalid"

POLICY = {
    "algorithm": "hmac-sha256",
    "keys": ["key-one", "key-two"],
    "cover_digest": True,
}


def call(
    method: str,
    path: str,
    body: bytes = b"",
    *,
    headers: dict[str, str] | None = None,
    query_string: str | None = None,
) -> tuple[str, list[tuple[str, str]], bytes]:
    environ: dict[str, object] = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "CONTENT_LENGTH": str(len(body)),
        "wsgi.input": io.BytesIO(body),
    }
    for key, value in (headers or {}).items():
        environ[key] = value
    if query_string is not None:
        environ["QUERY_STRING"] = query_string
    captured: dict[str, object] = {}

    def start_response(status: str, resp_headers: list[tuple[str, str]]) -> None:
        captured["status"] = status
        captured["headers"] = resp_headers

    parts = application(environ, start_response)
    return str(captured["status"]), list(captured["headers"]), b"".join(parts)


def call_json(
    method: str,
    path: str,
    body: bytes = b"",
    **kwargs: object,
) -> tuple[str, list[tuple[str, str]], dict[str, object]]:
    status, headers, raw = call(method, path, body, **kwargs)  # type: ignore[arg-type]
    return status, headers, json.loads(raw.decode("utf-8"))


def register(name: str = "primary") -> dict[str, object]:
    status, _h, body = call_json(
        "POST",
        "/mirrors",
        json.dumps({"name": name, "upstream": UPSTREAM}).encode("utf-8"),
        headers={"CONTENT_TYPE": "application/json"},
    )
    assert status == "201 Created", (status, body)
    return body


def register_policy(mirror_id: str) -> None:
    status, _h, _body = call_json(
        "POST",
        f"/mirrors/{mirror_id}/signature-policy",
        json.dumps(POLICY).encode("utf-8"),
        headers={"CONTENT_TYPE": "application/json"},
    )
    assert status == "201 Created", status


def patch_fetch(data: bytes | None = None, error: MirrorFetchError | None = None):
    if error is not None:
        return mock.patch(
            "provenance_api.app.fetch_upstream_layer", side_effect=error
        )
    return mock.patch(
        "provenance_api.app.fetch_upstream_layer", return_value=data
    )


def cache_status() -> dict[str, object]:
    _s, _h, body = call_json("GET", "/cache/status")
    return body


class MirrorDeleteTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def test_delete_returns_200_with_compact_echo(self) -> None:
        mirror = register()
        status, headers, raw = call("DELETE", f"/mirrors/{mirror['id']}")
        self.assertEqual(status, "200 OK")
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )
        body = json.loads(raw)
        self.assertEqual(
            body,
            {
                "id": mirror["id"],
                "name": "primary",
                "upstream": UPSTREAM,
            },
        )
        # Same key order as the registration echo, compact JSON, one
        # trailing newline.
        self.assertEqual(
            raw,
            b'{"id":"%s","name":"primary","upstream":"%s"}\n'
            % (str(mirror["id"]).encode(), UPSTREAM.encode()),
        )

    def test_deleted_mirror_is_gone_everywhere(self) -> None:
        mirror = register()
        mirror_id = str(mirror["id"])
        call("DELETE", f"/mirrors/{mirror_id}")
        for method, path in (
            ("GET", f"/mirrors/{mirror_id}"),
            ("DELETE", f"/mirrors/{mirror_id}"),
            ("GET", f"/mirrors/{mirror_id}/signature-policy"),
            ("DELETE", f"/mirrors/{mirror_id}/signature-policy"),
            ("POST", f"/mirrors/{mirror_id}/pull/{DIGEST_A}"),
        ):
            _s, _h, body = call_json(method, path)
            self.assertEqual(body["error"], "mirror_not_found", (method, path))
        _s, _h, body = call_json("GET", "/mirrors")
        self.assertEqual(body, {"mirrors": []})

    def test_delete_cascades_signature_policy(self) -> None:
        mirror = register()
        mirror_id = str(mirror["id"])
        register_policy(mirror_id)
        status, _h, body = call_json("DELETE", f"/mirrors/{mirror_id}")
        self.assertEqual(status, "200 OK")
        # The echo still only carries the three mirror fields.
        self.assertEqual(set(body), {"id", "name", "upstream"})
        status, _h, body = call_json(
            "GET", f"/mirrors/{mirror_id}/signature-policy"
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "mirror_not_found")

    def test_same_name_can_be_registered_again_after_delete(self) -> None:
        mirror = register()
        call("DELETE", f"/mirrors/{mirror['id']}")
        again = register()
        self.assertNotEqual(again["id"], mirror["id"])
        status, _h, body = call_json("GET", f"/mirrors/{again['id']}")
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["name"], "primary")

    def test_delete_keeps_cache_entries_and_counters(self) -> None:
        mirror = register()
        with patch_fetch(LAYER_A):
            status, _h, raw = call(
                "POST", f"/mirrors/{mirror['id']}/pull/{DIGEST_A}"
            )
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, LAYER_A)
        before = cache_status()
        self.assertEqual(before["entries"], 1)
        # Pulls never touch the hit/miss counters.
        self.assertEqual(before["hits"], 0)
        self.assertEqual(before["misses"], 0)

        status, _h, _body = call_json("DELETE", f"/mirrors/{mirror['id']}")
        self.assertEqual(status, "200 OK")
        self.assertEqual(cache_status(), before)
        status, _h, cached = call("GET", f"/cache/layers/{DIGEST_A}")
        self.assertEqual(status, "200 OK")
        self.assertEqual(cached, LAYER_A)

    def test_delete_unknown_mirror_returns_404_and_changes_nothing(self) -> None:
        mirror = register()
        status, _h, body = call_json("DELETE", "/mirrors/missing")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "mirror_not_found")
        _s, _h, listing = call_json("GET", "/mirrors")
        self.assertEqual(listing, {"mirrors": [mirror]})

    def test_double_delete_returns_404(self) -> None:
        mirror = register()
        status, _h, _body = call_json("DELETE", f"/mirrors/{mirror['id']}")
        self.assertEqual(status, "200 OK")
        status, _h, body = call_json("DELETE", f"/mirrors/{mirror['id']}")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "mirror_not_found")

    def test_delete_rejects_body_and_query_parameters(self) -> None:
        mirror = register()
        status, _h, body = call_json(
            "DELETE", f"/mirrors/{mirror['id']}", b"{}"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        status, _h, body = call_json(
            "DELETE", f"/mirrors/{mirror['id']}", query_string="x=1"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        # Nothing was deleted by the rejected requests.
        status, _h, _body = call_json("GET", f"/mirrors/{mirror['id']}")
        self.assertEqual(status, "200 OK")

    def test_delete_rejects_invalid_id(self) -> None:
        register()
        for path in ("/mirrors//", "/mirrors/a/b"):
            status, _h, body = call_json("DELETE", path)
            self.assertEqual(status, "400 Bad Request", path)
            self.assertEqual(body["error"], "invalid_request")
        _s, _h, listing = call_json("GET", "/mirrors")
        self.assertEqual(len(listing["mirrors"]), 1)

    def test_method_not_allowed_has_allow_header(self) -> None:
        mirror = register()
        for method in ("PUT", "PATCH", "POST"):
            status, headers, body = call_json(
                method, f"/mirrors/{mirror['id']}"
            )
            self.assertEqual(status, "405 Method Not Allowed")
            self.assertIn(("Allow", "DELETE, GET"), headers)
            self.assertEqual(body["error"], "method_not_allowed")


class MirrorPolicyDeleteTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def test_delete_returns_200_with_full_policy_echo(self) -> None:
        mirror = register()
        register_policy(str(mirror["id"]))
        status, headers, raw = call(
            "DELETE", f"/mirrors/{mirror['id']}/signature-policy"
        )
        self.assertEqual(status, "200 OK")
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )
        body = json.loads(raw)
        self.assertEqual(
            body,
            {
                "id": mirror["id"],
                "algorithm": "hmac-sha256",
                "keys": ["key-one", "key-two"],
                "cover_digest": True,
            },
        )
        self.assertEqual(list(body), ["id", "algorithm", "keys", "cover_digest"])
        self.assertEqual(
            raw,
            json.dumps(body, separators=(",", ":")).encode("utf-8") + b"\n",
        )

    def test_delete_keeps_mirror_registered(self) -> None:
        mirror = register()
        register_policy(str(mirror["id"]))
        call("DELETE", f"/mirrors/{mirror['id']}/signature-policy")
        status, _h, body = call_json("GET", f"/mirrors/{mirror['id']}")
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["id"], mirror["id"])
        status, _h, body = call_json(
            "GET", f"/mirrors/{mirror['id']}/signature-policy"
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "mirror_policy_not_found")

    def test_pull_reverts_to_unsigned_behavior_after_policy_delete(self) -> None:
        mirror = register()
        register_policy(str(mirror["id"]))
        # With the policy in place an unsigned pull is rejected.
        with patch_fetch(LAYER_A):
            status, _h, body = call_json(
                "POST", f"/mirrors/{mirror['id']}/pull/{DIGEST_A}"
            )
        self.assertEqual(status, "403 Forbidden")
        self.assertEqual(body["error"], "signature_missing")

        status, _h, _body = call_json(
            "DELETE", f"/mirrors/{mirror['id']}/signature-policy"
        )
        self.assertEqual(status, "200 OK")
        # Immediately afterwards the pull behaves as if no policy existed.
        with patch_fetch(LAYER_A):
            status, _h, raw = call(
                "POST", f"/mirrors/{mirror['id']}/pull/{DIGEST_A}"
            )
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, LAYER_A)

    def test_policy_can_be_registered_again_after_delete(self) -> None:
        mirror = register()
        register_policy(str(mirror["id"]))
        call("DELETE", f"/mirrors/{mirror['id']}/signature-policy")
        changed = dict(POLICY, keys=["other-key"])
        status, _h, body = call_json(
            "POST",
            f"/mirrors/{mirror['id']}/signature-policy",
            json.dumps(changed).encode("utf-8"),
            headers={"CONTENT_TYPE": "application/json"},
        )
        self.assertEqual(status, "201 Created")
        self.assertEqual(body["keys"], ["other-key"])

    def test_delete_without_policy_returns_404(self) -> None:
        mirror = register()
        status, _h, body = call_json(
            "DELETE", f"/mirrors/{mirror['id']}/signature-policy"
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "mirror_policy_not_found")

    def test_double_delete_returns_404(self) -> None:
        mirror = register()
        register_policy(str(mirror["id"]))
        status, _h, _body = call_json(
            "DELETE", f"/mirrors/{mirror['id']}/signature-policy"
        )
        self.assertEqual(status, "200 OK")
        status, _h, body = call_json(
            "DELETE", f"/mirrors/{mirror['id']}/signature-policy"
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "mirror_policy_not_found")

    def test_delete_on_unknown_mirror_returns_404(self) -> None:
        status, _h, body = call_json(
            "DELETE", "/mirrors/missing/signature-policy"
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "mirror_not_found")

    def test_delete_rejects_body_and_query_parameters(self) -> None:
        mirror = register()
        register_policy(str(mirror["id"]))
        status, _h, body = call_json(
            "DELETE", f"/mirrors/{mirror['id']}/signature-policy", b"{}"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        status, _h, body = call_json(
            "DELETE",
            f"/mirrors/{mirror['id']}/signature-policy",
            query_string="x=1",
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        # The policy survived both rejected requests.
        status, _h, _body = call_json(
            "GET", f"/mirrors/{mirror['id']}/signature-policy"
        )
        self.assertEqual(status, "200 OK")

    def test_delete_rejects_invalid_id(self) -> None:
        mirror = register()
        register_policy(str(mirror["id"]))
        for path in (
            "/mirrors//signature-policy",
            "/mirrors/a/b/signature-policy",
        ):
            status, _h, body = call_json("DELETE", path)
            self.assertEqual(status, "400 Bad Request", path)
            self.assertEqual(body["error"], "invalid_request")
        status, _h, _body = call_json(
            "GET", f"/mirrors/{mirror['id']}/signature-policy"
        )
        self.assertEqual(status, "200 OK")

    def test_method_not_allowed_has_allow_header(self) -> None:
        mirror = register()
        for method in ("PUT", "PATCH"):
            status, headers, body = call_json(
                method, f"/mirrors/{mirror['id']}/signature-policy"
            )
            self.assertEqual(status, "405 Method Not Allowed")
            self.assertIn(("Allow", "DELETE, GET, POST"), headers)
            self.assertEqual(body["error"], "method_not_allowed")


if __name__ == "__main__":
    unittest.main()
