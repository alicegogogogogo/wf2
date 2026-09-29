from __future__ import annotations

import io
import json
import unittest

from provenance_api.app import application, reset_state

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64


def call(
    method: str,
    path: str,
    body: bytes | str | dict[str, object] | None = None,
    *,
    query_string: str | None = None,
    content_length: int | str | None | object = "auto",
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
    # ``"auto"`` mirrors the length of the payload; ``None`` omits the
    # header entirely; any other value is sent verbatim (e.g. 0 for an
    # explicit zero length, or a malformed value).
    if content_length == "auto":
        environ["CONTENT_LENGTH"] = str(len(payload))
    elif content_length is not None:
        environ["CONTENT_LENGTH"] = str(content_length)
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
    content_length: int | str | None | object = "auto",
) -> tuple[str, list[tuple[str, str]], dict[str, object]]:
    status, headers, raw = call(
        method,
        path,
        body,
        query_string=query_string,
        content_length=content_length,
    )
    return status, headers, json.loads(raw.decode("utf-8"))


def notification_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "channel": "email",
        "target": "alerts@example.invalid",
        "message": "risk level changed",
    }
    payload.update(overrides)
    return payload


class NotificationDeleteTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        _s, _h, body = call_json(
            "POST",
            "/resources",
            {"name": "r", "category": "code", "digest": DIGEST_A},
        )
        self.resource_id = str(body["id"])

    def _resource(self, name: str, digest: str) -> str:
        _s, _h, body = call_json(
            "POST",
            "/resources",
            {"name": name, "category": "code", "digest": digest},
        )
        return str(body["id"])

    def _register(
        self, resource_id: str | None = None, **overrides: object
    ) -> dict[str, object]:
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id or self.resource_id}/notifications",
            notification_payload(**overrides),
        )
        assert status == "201 Created", body
        return body

    def _delete(
        self,
        resource_id: str,
        notification_id: str,
        **kwargs: object,
    ) -> tuple[str, list[tuple[str, str]], dict[str, object]]:
        return call_json(
            "DELETE",
            f"/resources/{resource_id}/notifications/{notification_id}",
            **kwargs,
        )

    # --- Success -----------------------------------------------------------

    def test_delete_returns_200_and_echoes_record(self) -> None:
        record = self._register()

        status, headers, body = self._delete(
            self.resource_id, str(record["id"])
        )

        self.assertEqual(status, "200 OK")
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )
        self.assertEqual(body, record)
        # Same fixed key order as a registration response, no wrapper.
        self.assertEqual(
            list(body), ["id", "channel", "target", "message"]
        )

    def test_response_body_is_compact_json_with_single_newline(self) -> None:
        record = self._register(message="界multi-byte")

        _s, _h, raw = call(
            "DELETE",
            f"/resources/{self.resource_id}/notifications/{record['id']}",
        )

        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        self.assertNotIn(b" ", raw.rstrip(b"\n"))
        self.assertEqual(
            raw,
            json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode(
                "utf-8"
            )
            + b"\n",
        )

    def test_delete_removes_the_record(self) -> None:
        first = self._register(message="first")
        second = self._register(message="second")
        third = self._register(message="third")

        status, _h, _b = self._delete(self.resource_id, str(second["id"]))
        self.assertEqual(status, "200 OK")

        _s, _h, listing = call_json(
            "GET", f"/resources/{self.resource_id}/notifications"
        )
        self.assertEqual(
            [item["id"] for item in listing["notifications"]],
            [first["id"], third["id"]],
        )

    def test_other_records_of_the_same_resource_remain(self) -> None:
        record = self._register()

        self._delete(self.resource_id, str(record["id"]))

        remaining = self._register(message="after")
        _s, _h, listing = call_json(
            "GET", f"/resources/{self.resource_id}/notifications"
        )
        self.assertEqual(
            [item["id"] for item in listing["notifications"]],
            [remaining["id"]],
        )

    # --- 404 cases ---------------------------------------------------------

    def test_unknown_notification_id_returns_404(self) -> None:
        self._register()
        status, _h, body = self._delete(self.resource_id, "deadbeef" * 4)

        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "notification_not_found")

    def test_notification_of_other_resource_returns_404(self) -> None:
        other_id = self._resource("other", DIGEST_B)
        record = self._register(other_id, message="for other")

        status, _h, body = self._delete(self.resource_id, str(record["id"]))

        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "notification_not_found")
        # The record itself stays put under its real owner.
        _s, _h, listing = call_json(
            "GET", f"/resources/{other_id}/notifications"
        )
        self.assertEqual(len(listing["notifications"]), 1)

    def test_repeated_delete_returns_404(self) -> None:
        record = self._register()

        first, _h, _b = self._delete(self.resource_id, str(record["id"]))
        self.assertEqual(first, "200 OK")
        second, _h, body = self._delete(self.resource_id, str(record["id"]))
        self.assertEqual(second, "404 Not Found")
        self.assertEqual(body["error"], "notification_not_found")

    def test_failed_delete_changes_no_state(self) -> None:
        self._register(message="one")
        self._register(message="two")

        for notification_id in ("deadbeef" * 4, "does-not-exist"):
            status, _h, _b = self._delete(
                self.resource_id, notification_id
            )
            self.assertEqual(status, "404 Not Found")

        _s, _h, listing = call_json(
            "GET", f"/resources/{self.resource_id}/notifications"
        )
        self.assertEqual(
            [item["message"] for item in listing["notifications"]],
            ["one", "two"],
        )

    def test_unknown_resource_reports_resource_not_found(self) -> None:
        status, _h, body = self._delete("no-such-resource", "anything")

        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

    # --- 400 cases ---------------------------------------------------------

    def test_empty_notification_id_returns_400(self) -> None:
        status, _h, body = call_json(
            "DELETE",
            f"/resources/{self.resource_id}/notifications/",
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_notification_id_with_separator_returns_400(self) -> None:
        # A literal slash is still inside the id segment after routing;
        # the item handler rejects it as a bad request.
        status, _h, body = call_json(
            "DELETE",
            f"/resources/{self.resource_id}/notifications/a/b",
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

        status, _h, body = call_json(
            "DELETE",
            f"/resources/{self.resource_id}/notifications/a\\b",
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_resource_id_with_separator_returns_400(self) -> None:
        status, _h, body = call_json(
            "DELETE", "/resources/a/b/notifications/nid"
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_query_parameters_return_400(self) -> None:
        record = self._register()
        status, _h, body = self._delete(
            self.resource_id,
            str(record["id"]),
            query_string="channel=email",
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

        # The record survives the rejected request.
        _s, _h, listing = call_json(
            "GET", f"/resources/{self.resource_id}/notifications"
        )
        self.assertEqual(len(listing["notifications"]), 1)

    def test_declared_non_empty_body_returns_400(self) -> None:
        record = self._register()
        status, _h, body = self._delete(
            self.resource_id,
            str(record["id"]),
            body=b"{}",
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

        _s, _h, listing = call_json(
            "GET", f"/resources/{self.resource_id}/notifications"
        )
        self.assertEqual(len(listing["notifications"]), 1)

    def test_malformed_content_length_returns_400(self) -> None:
        record = self._register()
        status, _h, body = self._delete(
            self.resource_id,
            str(record["id"]),
            body=b"",
            content_length="abc",
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_explicit_zero_length_body_is_accepted(self) -> None:
        record = self._register()
        status, _h, _b = self._delete(
            self.resource_id,
            str(record["id"]),
            body=b"",
            content_length=0,
        )
        self.assertEqual(status, "200 OK")

    def test_omitted_content_length_is_accepted(self) -> None:
        record = self._register()
        status, _h, _b = self._delete(
            self.resource_id,
            str(record["id"]),
            body=None,
            content_length=None,
        )
        self.assertEqual(status, "200 OK")

    # --- 405 ---------------------------------------------------------------

    def test_other_methods_return_405_with_delete_only_allow(self) -> None:
        record = self._register()
        path = f"/resources/{self.resource_id}/notifications/{record['id']}"
        for method in ("GET", "POST", "PUT", "PATCH"):
            status, headers, body = call_json(method, path)
            self.assertEqual(status, "405 Method Not Allowed", method)
            self.assertEqual(body["error"], "method_not_allowed", method)
            self.assertEqual(
                headers_dict(headers)["Allow"], "DELETE", method
            )

        # Nothing was deleted by the rejected methods.
        _s, _h, listing = call_json(
            "GET", f"/resources/{self.resource_id}/notifications"
        )
        self.assertEqual(len(listing["notifications"]), 1)

    # --- Derived views -----------------------------------------------------

    def test_global_summary_and_channel_filter_shrink(self) -> None:
        other_id = self._resource("other", DIGEST_B)
        first = self._register(channel="email", message="first")
        gone = self._register(channel="webhook", message="gone")
        keep = self._register(other_id, channel="email", message="keep")

        self._delete(self.resource_id, str(gone["id"]))

        _s, _h, summary = call_json("GET", "/notifications")
        self.assertEqual(
            [item["id"] for item in summary],
            [first["id"], keep["id"]],
        )
        for entry in summary:
            self.assertNotEqual(entry["id"], gone["id"])

        _s, _h, webhook = call_json(
            "GET", "/notifications", query_string="channel=webhook"
        )
        self.assertEqual(webhook, [])

        _s, _h, emails = call_json(
            "GET", "/notifications", query_string="channel=email"
        )
        self.assertEqual(
            [item["id"] for item in emails], [first["id"], keep["id"]]
        )

    def test_usage_views_shrink_and_redetermine_first_appearance(self) -> None:
        # Two resources; the earliest webhook entry disappears so a later
        # entry takes first-appearance position, and one channel/target/
        # pair loses every notification and vanishes altogether.
        other_id = self._resource("other", DIGEST_B)
        third_id = self._resource("third", DIGEST_C)

        webhook_first = self._register(
            channel="webhook", target="https://a.example", message="w1"
        )
        email_keep = self._register(
            channel="email", target="alerts@example.invalid", message="e1"
        )
        only_pair = self._register(
            other_id, channel="sms", target="+1-555", message="s1"
        )
        webhook_second = self._register(
            third_id, channel="webhook", target="https://b.example", message="w2"
        )

        # Before deletion the webhook group lists both ids and the sms
        # group exists.
        _s, _h, usage = call_json("GET", "/notification-usage")
        self.assertEqual(
            [entry["channel"] for entry in usage],
            ["webhook", "email", "sms"],
        )

        self._delete(self.resource_id, str(webhook_first["id"]))
        self._delete(other_id, str(only_pair["id"]))

        _s, _h, usage = call_json("GET", "/notification-usage")
        self.assertEqual(
            [entry["channel"] for entry in usage],
            ["email", "webhook"],
        )
        webhook = next(entry for entry in usage if entry["channel"] == "webhook")
        self.assertEqual(webhook["notifications"], [webhook_second["id"]])
        self.assertEqual(webhook["notification_count"], 1)
        self.assertEqual(webhook["targets"], ["https://b.example"])
        self.assertEqual(webhook["resources"], [third_id])
        self.assertEqual(webhook["resource_count"], 1)
        email = next(entry for entry in usage if entry["channel"] == "email")
        self.assertEqual(email["notifications"], [email_keep["id"]])

        _s, _h, targets = call_json("GET", "/notification-targets")
        self.assertEqual(
            [entry["target"] for entry in targets],
            ["alerts@example.invalid", "https://b.example"],
        )
        target = next(
            entry
            for entry in targets
            if entry["target"] == "https://b.example"
        )
        self.assertEqual(target["notifications"], [webhook_second["id"]])
        self.assertEqual(target["channels"], ["webhook"])
        self.assertEqual(target["resources"], [third_id])

        _s, _h, pairs = call_json("GET", "/notification-channel-targets")
        self.assertEqual(
            [(entry["channel"], entry["target"]) for entry in pairs],
            [
                ("email", "alerts@example.invalid"),
                ("webhook", "https://b.example"),
            ],
        )
        pair = pairs[1]
        self.assertEqual(pair["notifications"], [webhook_second["id"]])
        self.assertEqual(pair["resources"], [third_id])

    def test_delete_does_not_touch_other_resource_state(self) -> None:
        other_id = self._resource("other", DIGEST_B)
        record = self._register(other_id)

        # Deleting via the owning path leaves the resource itself intact.
        self._delete(other_id, str(record["id"]))

        status, _h, body = call_json("GET", f"/resources/{other_id}")
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["id"], other_id)
        _s, _h, listing = call_json(
            "GET", f"/resources/{other_id}/notifications"
        )
        self.assertEqual(listing, {"notifications": []})


def headers_dict(headers: list[tuple[str, str]]) -> dict[str, str]:
    return {name: value for name, value in headers}


if __name__ == "__main__":
    unittest.main()
