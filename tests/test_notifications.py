from __future__ import annotations

import io
import json
import unittest

from provenance_api.app import application, reset_state

DIGEST_A = "a" * 64


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
        "wsgi.input": io.BytesIO(payload),
        "CONTENT_LENGTH": str(len(payload)),
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
    status, headers, raw = call(method, path, body, query_string=query_string)
    return status, headers, json.loads(raw.decode("utf-8"))


def notification_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "channel": "email",
        "target": "alerts@example.invalid",
        "message": "risk level changed",
    }
    payload.update(overrides)
    return payload


class NotificationTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        _s, _h, body = call_json(
            "POST",
            "/resources",
            {"name": "r", "category": "code", "digest": DIGEST_A},
        )
        self.resource_id = str(body["id"])

    def _register(
        self, resource_id: str | None = None, **overrides: object
    ) -> tuple[str, list[tuple[str, str]], dict[str, object]]:
        return call_json(
            "POST",
            f"/resources/{resource_id or self.resource_id}/notifications",
            notification_payload(**overrides),
        )

    # --- Registration ------------------------------------------------------

    def test_register_returns_201_and_echoes(self) -> None:
        status, headers, body = self._register()

        self.assertEqual(status, "201 Created")
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )
        self.assertEqual(body["channel"], "email")
        self.assertEqual(body["target"], "alerts@example.invalid")
        self.assertEqual(body["message"], "risk level changed")
        self.assertTrue(body["id"])

    def test_each_submission_creates_an_independent_record(self) -> None:
        _s, _h, first = self._register()
        _s, _h, second = self._register()

        self.assertNotEqual(first["id"], second["id"])

        _s, _h, listing = call_json(
            "GET", f"/resources/{self.resource_id}/notifications"
        )
        self.assertEqual(len(listing["notifications"]), 2)

    def test_max_length_fields_are_accepted(self) -> None:
        status, _h, body = self._register(
            channel="c" * 64, target="t" * 256, message="m" * 2048
        )

        self.assertEqual(status, "201 Created")
        self.assertEqual(body["channel"], "c" * 64)
        self.assertEqual(body["target"], "t" * 256)
        self.assertEqual(body["message"], "m" * 2048)

    def test_unicode_length_is_counted_in_code_points(self) -> None:
        status, _h, body = self._register(message="界" * 2048)

        self.assertEqual(status, "201 Created")
        self.assertEqual(body["message"], "界" * 2048)

    # --- Query -------------------------------------------------------------

    def test_empty_listing_is_success(self) -> None:
        status, _h, body = call_json(
            "GET", f"/resources/{self.resource_id}/notifications"
        )

        self.assertEqual(status, "200 OK")
        self.assertEqual(body, {"notifications": []})

    def test_listing_preserves_submission_order(self) -> None:
        self._register(message="first")
        self._register(message="second", channel="webhook")
        self._register(message="third")

        _s, _h, body = call_json(
            "GET", f"/resources/{self.resource_id}/notifications"
        )

        messages = [item["message"] for item in body["notifications"]]
        self.assertEqual(messages, ["first", "second", "third"])

    def test_listing_is_scoped_per_resource(self) -> None:
        _s, _h, other = call_json(
            "POST",
            "/resources",
            {"name": "other", "category": "code", "digest": "b" * 64},
        )
        other_id = str(other["id"])
        self._register()
        self._register(other_id, message="for other")

        _s, _h, body = call_json(
            "GET", f"/resources/{other_id}/notifications"
        )

        self.assertEqual(len(body["notifications"]), 1)
        self.assertEqual(body["notifications"][0]["message"], "for other")

    # --- Validation errors -------------------------------------------------

    def test_missing_body_returns_400(self) -> None:
        status, _h, body = call_json(
            "POST", f"/resources/{self.resource_id}/notifications"
        )

        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_undecodable_body_returns_400(self) -> None:
        status, _h, body = call_json(
            "POST",
            f"/resources/{self.resource_id}/notifications",
            b"\xff\xfe{}",
        )

        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_non_object_body_returns_400(self) -> None:
        status, _h, body = call_json(
            "POST", f"/resources/{self.resource_id}/notifications", "[1,2]"
        )

        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_missing_field_returns_400(self) -> None:
        for field in ("channel", "target", "message"):
            payload = notification_payload()
            del payload[field]
            status, _h, body = call_json(
                "POST", f"/resources/{self.resource_id}/notifications", payload
            )
            self.assertEqual(status, "400 Bad Request", field)
            self.assertEqual(body["error"], "invalid_request", field)

    def test_unknown_field_returns_400(self) -> None:
        status, _h, body = self._register(priority="high")

        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_wrong_type_returns_400(self) -> None:
        for field in ("channel", "target", "message"):
            status, _h, body = self._register(**{field: 42})
            self.assertEqual(status, "400 Bad Request", field)
            self.assertEqual(body["error"], "invalid_request", field)

    def test_empty_value_returns_400(self) -> None:
        for field in ("channel", "target", "message"):
            status, _h, body = self._register(**{field: ""})
            self.assertEqual(status, "400 Bad Request", field)
            self.assertEqual(body["error"], "invalid_request", field)

    def test_overlong_value_returns_400(self) -> None:
        cases = (
            {"channel": "c" * 65},
            {"target": "t" * 257},
            {"message": "m" * 2049},
        )
        for overrides in cases:
            status, _h, body = self._register(**overrides)
            self.assertEqual(status, "400 Bad Request", overrides)
            self.assertEqual(body["error"], "invalid_request", overrides)

    def test_failed_registration_writes_nothing(self) -> None:
        self._register(channel="")
        self._register(message="m" * 2049)

        _s, _h, body = call_json(
            "GET", f"/resources/{self.resource_id}/notifications"
        )
        self.assertEqual(body, {"notifications": []})

    # --- Routing and resource errors ---------------------------------------

    def test_unknown_resource_returns_404_for_post_and_get(self) -> None:
        status, _h, body = self._register("no-such-resource")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

        status, _h, body = call_json(
            "GET", "/resources/no-such-resource/notifications"
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

    def test_invalid_payload_returns_400_even_for_unknown_resource(self) -> None:
        status, _h, body = self._register("no-such-resource", channel="")

        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_id_with_separator_returns_400(self) -> None:
        status, _h, body = call_json("GET", "/resources/a/b/notifications")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

        status, _h, body = call_json(
            "POST", "/resources/a/b/notifications", notification_payload()
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_query_parameters_return_400(self) -> None:
        status, _h, body = call_json(
            "GET",
            f"/resources/{self.resource_id}/notifications",
            query_string="channel=email",
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

        status, _h, body = call_json(
            "POST",
            f"/resources/{self.resource_id}/notifications",
            notification_payload(),
            query_string="channel=email",
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_unsupported_methods_return_405(self) -> None:
        for method in ("PUT", "DELETE", "PATCH"):
            status, headers, body = call_json(
                method, f"/resources/{self.resource_id}/notifications"
            )
            self.assertEqual(status, "405 Method Not Allowed")
            self.assertEqual(body["error"], "method_not_allowed")
            self.assertIn(("Allow", "GET, POST"), headers)


if __name__ == "__main__":
    unittest.main()
