from __future__ import annotations

import io
import json
import unittest
from unittest import mock

from provenance_api.app import application, reset_state
from provenance_api.cross_references import CrossReferenceError

UPSTREAM = "https://repo.example.invalid"
REMOTE_ID = "remote-42"
REMOTE_NAME = "remote-model"
REMOTE_CATEGORY = "Model"
DIGEST = "a" * 64
OTHER_DIGEST = "f" * 64
SOURCE = "https://repo.example.invalid/sources/remote-42"

REFERENCE_BODY = {
    "repository": "partner",
    "upstream": UPSTREAM,
    "remote_id": REMOTE_ID,
    "digest": DIGEST,
}


def call(
    method: str,
    path: str,
    body: bytes = b"",
    *,
    headers: dict[str, str] | None = None,
    query_string: str | None = None,
    omit_length: bool = False,
) -> tuple[str, list[tuple[str, str]], bytes]:
    environ: dict[str, object] = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "wsgi.input": io.BytesIO(body),
    }
    if not omit_length:
        environ["CONTENT_LENGTH"] = str(len(body))
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


def call_json(method: str, path: str, body: bytes = b"", **kwargs: object):
    status, headers, raw = call(method, path, body, **kwargs)  # type: ignore[arg-type]
    return status, headers, json.loads(raw.decode("utf-8"))


def register_local(
    name: str = "local-a",
    category: str = "code",
    digest: str = "b" * 64,
    source: str | None = None,
) -> str:
    payload: dict[str, object] = {
        "name": name,
        "category": category,
        "digest": digest,
    }
    if source is not None:
        payload["source"] = source
    status, _h, body = call_json(
        "POST",
        "/resources",
        json.dumps(payload).encode("utf-8"),
        headers={"CONTENT_TYPE": "application/json"},
    )
    assert status == "201 Created", (status, body)
    return str(body["id"])


def remote_raw(
    *,
    name: str = REMOTE_NAME,
    category: str = REMOTE_CATEGORY,
    digest: str = DIGEST,
    source: str = SOURCE,
) -> bytes:
    return json.dumps(
        {"name": name, "category": category, "digest": digest, "source": source},
        separators=(",", ":"),
    ).encode("utf-8")


def patch_resolve(
    *,
    name: str = REMOTE_NAME,
    category: str = REMOTE_CATEGORY,
    digest: str = DIGEST,
    source: str = SOURCE,
):
    from provenance_api.cross_references import Resolution

    resolution = Resolution(
        name=name,
        category=category.lower(),
        digest=digest.lower(),
        source=source,
        raw=remote_raw(name=name, category=category, digest=digest, source=source),
    )
    return mock.patch(
        "provenance_api.app.resolve_remote", return_value=resolution
    )


def post_reference(resource_id: str, body: object = None) -> None:
    payload = REFERENCE_BODY if body is None else body
    with patch_resolve(**_resolve_kwargs(payload)):
        status, _h, response = call_json(
            "POST",
            f"/resources/{resource_id}/cross-references",
            json.dumps(payload).encode("utf-8"),
            headers={"CONTENT_TYPE": "application/json"},
        )
    assert status == "201 Created", (status, response)


def _resolve_kwargs(payload: object) -> dict[str, str]:
    assert isinstance(payload, dict)
    return {
        "digest": str(payload["digest"]),
        "name": REMOTE_NAME if payload["digest"] == DIGEST else "other-remote",
        "source": SOURCE
        if payload["digest"] == DIGEST
        else "https://repo.example.invalid/other",
    }


def patch_fetch(raw: bytes | None = None, *, error: Exception | None = None):
    if error is not None:
        return mock.patch(
            "provenance_api.cross_references.fetch_remote_resource",
            side_effect=error,
        )
    return mock.patch(
        "provenance_api.cross_references.fetch_remote_resource",
        return_value=raw if raw is not None else remote_raw(),
    )


def verify(resource_id: str, body: bytes = b"", **kwargs: object):
    return call_json(
        "POST",
        f"/resources/{resource_id}/cross-references/verify",
        body,
        **kwargs,
    )


class CrossReferenceVerifySuccessTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def test_no_references_returns_empty_results_with_newline(self) -> None:
        resource_id = register_local()
        status, headers, raw = call(
            "POST", f"/resources/{resource_id}/cross-references/verify"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b'{"results":[]}\n')
        self.assertEqual(
            [name for name, _value in headers],
            ["Content-Type", "Content-Length"],
        )

    def test_matched_result_shape_and_key_order(self) -> None:
        resource_id = register_local()
        post_reference(resource_id)
        with patch_fetch() as fetch:
            status, _h, body = verify(resource_id)
        self.assertEqual(status, "200 OK")
        self.assertEqual(set(body), {"results"})
        (result,) = body["results"]
        self.assertEqual(
            list(result),
            [
                "resource_id",
                "repository",
                "upstream",
                "remote_id",
                "digest",
                "status",
                "remote",
                "local_id",
            ],
        )
        self.assertEqual(result["resource_id"], resource_id)
        self.assertEqual(result["repository"], "partner")
        self.assertEqual(result["upstream"], UPSTREAM)
        self.assertEqual(result["remote_id"], REMOTE_ID)
        self.assertEqual(result["digest"], DIGEST)
        self.assertEqual(result["status"], "matched")
        self.assertEqual(
            result["remote"],
            {
                "name": REMOTE_NAME,
                "category": "model",
                "digest": DIGEST,
                "source": SOURCE,
            },
        )
        self.assertIsInstance(result["local_id"], str)
        self.assertTrue(result["local_id"])
        # The verify path fetches directly; it never goes through the
        # registration resolver (and therefore never writes the cache).
        fetch.assert_called_once()
        args = fetch.call_args.args
        self.assertEqual(args, (UPSTREAM, REMOTE_ID))

    def test_remote_document_uses_registered_remote_id_encoding(self) -> None:
        resource_id = register_local()
        payload = dict(REFERENCE_BODY, remote_id="a b", digest="c" * 64)
        post_reference(resource_id, payload)
        from provenance_api import cross_references

        response = mock.MagicMock()
        response.status = 200
        response.getcode.return_value = 200
        response.read.return_value = remote_raw(
            name="other-remote", digest="c" * 64
        )
        response.__enter__.return_value = response
        response.__exit__.return_value = False
        with mock.patch.object(
            cross_references.urllib.request, "urlopen", return_value=response
        ) as urlopen:
            status, _h, body = verify(resource_id)
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["results"][0]["status"], "matched")
        request = urlopen.call_args.args[0]
        self.assertEqual(
            request.full_url, f"{UPSTREAM}/resources/a%20b"
        )

    def test_category_is_normalized_but_name_is_case_sensitive(self) -> None:
        resource_id = register_local()
        post_reference(resource_id)
        # Uppercase category normalizes to the stored lowercase form.
        with patch_fetch(remote_raw(category="MODEL")):
            status, _h, body = verify(resource_id)
        self.assertEqual(
            body["results"][0]["remote"]["category"], "model"
        )
        self.assertEqual(body["results"][0]["status"], "matched")
        # A case-only name difference is an identity mismatch.
        with patch_fetch(remote_raw(name=REMOTE_NAME.upper())):
            status, _h, body = verify(resource_id)
        self.assertEqual(body["results"][0]["status"], "identity_mismatch")

    def test_source_difference_still_matches_and_remote_is_echoed(self) -> None:
        resource_id = register_local()
        post_reference(resource_id)
        with patch_fetch(remote_raw(source="https://elsewhere.example/x")):
            status, _h, body = verify(resource_id)
        result = body["results"][0]
        self.assertEqual(result["status"], "matched")
        self.assertEqual(
            result["remote"]["source"], "https://elsewhere.example/x"
        )


class CrossReferenceVerifyStatusTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.resource_id = register_local()
        post_reference(self.resource_id)
        self.local_id = self._registered_local_id()

    def _registered_local_id(self) -> str:
        status, _h, summary = call_json("GET", "/")
        assert status == "200 OK"
        return str(summary[0]["local_id"])

    def test_remote_unreachable(self) -> None:
        error = CrossReferenceError(
            "remote_unreachable", "x", http_status=502
        )
        with patch_fetch(error=error):
            status, _h, body = verify(self.resource_id)
        self.assertEqual(status, "200 OK")
        result = body["results"][0]
        self.assertEqual(result["status"], "remote_unreachable")
        self.assertIsNone(result["remote"])
        self.assertEqual(result["local_id"], self.local_id)

    def test_resolution_failed_on_malformed_document(self) -> None:
        with patch_fetch(b"not json"):
            status, _h, body = verify(self.resource_id)
        result = body["results"][0]
        self.assertEqual(result["status"], "resolution_failed")
        self.assertIsNone(result["remote"])

    def test_remote_digest_mismatch(self) -> None:
        with patch_fetch(remote_raw(digest=OTHER_DIGEST)):
            status, _h, body = verify(self.resource_id)
        result = body["results"][0]
        self.assertEqual(result["status"], "remote_digest_mismatch")
        # A valid document is still surfaced; the registered digest is
        # echoed, not the remote one.
        self.assertEqual(result["remote"]["digest"], OTHER_DIGEST)
        self.assertEqual(result["digest"], DIGEST)

    def test_local_resource_missing_after_deregistration(self) -> None:
        status, _h, _b = call(
            "DELETE", f"/resources/{self.local_id}"
        )
        self.assertEqual(status, "200 OK")
        with patch_fetch():
            status, _h, body = verify(self.resource_id)
        result = body["results"][0]
        self.assertEqual(result["status"], "local_resource_missing")
        # The registered local_id survives deregistration.
        self.assertEqual(result["local_id"], self.local_id)
        self.assertIsNotNone(result["remote"])

    def test_identity_mismatch_on_remote_name_change(self) -> None:
        with patch_fetch(remote_raw(name="brand-new-name")):
            status, _h, body = verify(self.resource_id)
        self.assertEqual(
            body["results"][0]["status"], "identity_mismatch"
        )

    def test_identity_mismatch_on_remote_category_change(self) -> None:
        with patch_fetch(remote_raw(category="dataset")):
            status, _h, body = verify(self.resource_id)
        self.assertEqual(
            body["results"][0]["status"], "identity_mismatch"
        )

    def test_status_precedence_unreachable_beats_everything(self) -> None:
        # Local target deregistered, but the unreachable upstream decides
        # the status first.
        call("DELETE", f"/resources/{self.local_id}")
        error = CrossReferenceError(
            "remote_unreachable", "x", http_status=502
        )
        with patch_fetch(error=error):
            status, _h, body = verify(self.resource_id)
        self.assertEqual(
            body["results"][0]["status"], "remote_unreachable"
        )

    def test_status_precedence_digest_beats_local_checks(self) -> None:
        call("DELETE", f"/resources/{self.local_id}")
        with patch_fetch(remote_raw(digest=OTHER_DIGEST)):
            status, _h, body = verify(self.resource_id)
        self.assertEqual(
            body["results"][0]["status"], "remote_digest_mismatch"
        )

    def test_references_verified_independently_in_registration_order(
        self,
    ) -> None:
        second_body = dict(
            REFERENCE_BODY,
            repository="other-partner",
            remote_id="remote-7",
            digest="d" * 64,
        )
        post_reference(self.resource_id, second_body)

        good_raw = remote_raw(
            name="other-remote",
            digest="d" * 64,
            source="https://repo.example.invalid/other",
        )

        def fake_fetch(upstream: str, remote_id: str) -> bytes:
            if remote_id == REMOTE_ID:
                raise CrossReferenceError(
                    "remote_unreachable", "x", http_status=502
                )
            return good_raw

        with mock.patch(
            "provenance_api.cross_references.fetch_remote_resource",
            side_effect=fake_fetch,
        ):
            status, _h, body = verify(self.resource_id)
        self.assertEqual(status, "200 OK")
        results = body["results"]
        self.assertEqual(len(results), 2)
        self.assertEqual(
            [r["remote_id"] for r in results], [REMOTE_ID, "remote-7"]
        )
        self.assertEqual(results[0]["status"], "remote_unreachable")
        self.assertIsNone(results[0]["remote"])
        self.assertEqual(results[1]["status"], "matched")
        self.assertEqual(results[1]["digest"], "d" * 64)


class CrossReferenceVerifySideEffectTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.resource_id = register_local()
        post_reference(self.resource_id)

    def test_verify_writes_nothing(self) -> None:
        status, _h, before = call_json("GET", "/resources")
        n_resources = len(before["resources"])
        status, _h, refs_before = call_json(
            "GET", f"/resources/{self.resource_id}/cross-references"
        )
        status, _h, edges_before = call_json("GET", "/graph")
        # Registration writes the cache itself; verification must leave
        # that exact state untouched.
        status, _h, cached_before = call("GET", f"/cache/layers/{DIGEST}")
        self.assertEqual(status, "200 OK")

        with patch_fetch():
            status, _h, body = verify(self.resource_id)
        self.assertEqual(status, "200 OK")

        status, _h, cached_after = call("GET", f"/cache/layers/{DIGEST}")
        self.assertEqual(cached_after, cached_before)
        status, _h, after = call_json("GET", "/resources")
        self.assertEqual(len(after["resources"]), n_resources)
        status, _h, refs_after = call_json(
            "GET", f"/resources/{self.resource_id}/cross-references"
        )
        self.assertEqual(refs_after, refs_before)
        status, _h, edges_after = call_json("GET", "/graph")
        self.assertEqual(edges_after, edges_before)

    def test_verify_recomputes_from_current_data_each_call(self) -> None:
        with patch_fetch(error=CrossReferenceError(
            "remote_unreachable", "x", http_status=502
        )):
            status, _h, body = verify(self.resource_id)
        self.assertEqual(
            body["results"][0]["status"], "remote_unreachable"
        )
        with patch_fetch():
            status, _h, body = verify(self.resource_id)
        self.assertEqual(body["results"][0]["status"], "matched")


class CrossReferenceVerifyRequestTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.resource_id = register_local()

    def test_non_empty_body_returns_400_without_fetching(self) -> None:
        with patch_fetch(error=AssertionError("must not fetch")) as fetch:
            status, _h, body = verify(
                self.resource_id, b"x",
                headers={"CONTENT_TYPE": "application/json"},
            )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")
        fetch.assert_not_called()

    def test_malformed_content_length_returns_400(self) -> None:
        environ: dict[str, object] = {
            "REQUEST_METHOD": "POST",
            "PATH_INFO": (
                f"/resources/{self.resource_id}/cross-references/verify"
            ),
            "CONTENT_LENGTH": "abc",
            "wsgi.input": io.BytesIO(b""),
        }
        captured: dict[str, object] = {}

        def start_response(status, headers):
            captured["status"] = status
            captured["headers"] = headers

        raw = b"".join(application(environ, start_response))
        self.assertEqual(captured["status"], "400 Bad Request")
        self.assertEqual(json.loads(raw)["error"], "invalid_request")

    def test_omitted_and_zero_length_bodies_are_accepted(self) -> None:
        status, _h, body = verify(self.resource_id, omit_length=True)
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, {"results": []})
        status, _h, body = verify(
            self.resource_id, headers={"CONTENT_LENGTH": "0"}
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, {"results": []})

    def test_query_parameters_return_400(self) -> None:
        status, _h, body = verify(
            self.resource_id, query_string="x=1"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_empty_id_returns_400(self) -> None:
        status, _h, body = call_json(
            "POST", "/resources//cross-references/verify"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_id_with_separator_returns_400(self) -> None:
        status, _h, body = call_json(
            "POST", "/resources/a/b/cross-references/verify"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_unknown_resource_returns_404_without_fetching(self) -> None:
        with patch_fetch(error=AssertionError("must not fetch")) as fetch:
            status, _h, body = verify("missing")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")
        fetch.assert_not_called()

    def test_other_methods_return_405_with_allow_post(self) -> None:
        path = f"/resources/{self.resource_id}/cross-references/verify"
        for method in ("GET", "PUT", "DELETE", "PATCH"):
            status, headers, raw = call(method, path)
            self.assertEqual(status, "405 Method Not Allowed", method)
            self.assertIn(("Allow", "POST"), headers)
            self.assertEqual(
                json.loads(raw)["error"], "method_not_allowed"
            )


if __name__ == "__main__":
    unittest.main()
