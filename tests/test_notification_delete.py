from __future__ import annotations

import io
import json
import unittest

from provenance_api.app import application, reset_state

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64

FOUR_KEYS = ["id", "channel", "target", "message"]


def call(
    method: str,
    path: str,
    body: bytes = b"",
    *,
    headers: dict[str, str] | None = None,
    query_string: str | None = None,
    omit_content_length: bool = False,
) -> tuple[str, list[tuple[str, str]], bytes]:
    environ: dict[str, object] = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "wsgi.input": io.BytesIO(body),
    }
    if not omit_content_length:
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


def call_json(
    method: str,
    path: str,
    body: bytes = b"",
    **kwargs: object,
) -> tuple[str, list[tuple[str, str]], dict[str, object]]:
    status, headers, raw = call(method, path, body, **kwargs)  # type: ignore[arg-type]
    return status, headers, json.loads(raw.decode("utf-8"))


def create_resource(name: str = "r", digest: str = DIGEST_A) -> str:
    status, _h, body = call_json(
        "POST",
        "/resources",
        json.dumps({"name": name, "category": "code", "digest": digest}).encode(
            "utf-8"
        ),
        headers={"CONTENT_TYPE": "application/json"},
    )
    assert status == "201 Created", (status, body)
    return str(body["id"])


def register_notification(
    resource_id: str,
    *,
    channel: str = "email",
    target: str = "alerts@example.invalid",
    message: str = "risk level changed",
) -> dict[str, object]:
    status, _h, body = call_json(
        "POST",
        f"/resources/{resource_id}/notifications",
        json.dumps(
            {"channel": channel, "target": target, "message": message}
        ).encode("utf-8"),
        headers={"CONTENT_TYPE": "application/json"},
    )
    assert status == "201 Created", (status, body)
    return body


def item_path(resource_id: str, notification_id: str) -> str:
    return f"/resources/{resource_id}/notifications/{notification_id}"


def delete_notification(
    resource_id: str, notification_id: str, **kwargs: object
):
    return call_json(
        "DELETE", item_path(resource_id, notification_id), **kwargs
    )


class NotificationDeleteSuccessTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.resource_id = create_resource()
        self.record = register_notification(self.resource_id)
        self.notification_id = str(self.record["id"])

    def test_delete_returns_200_and_echoes_four_fields_in_order(self) -> None:
        status, headers, raw = call(
            "DELETE", item_path(self.resource_id, self.notification_id)
        )
        self.assertEqual(status, "200 OK")
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )
        body = json.loads(raw)
        self.assertEqual(list(body), FOUR_KEYS)
        self.assertEqual(body, self.record)
        # Compact UTF-8 JSON ending in exactly one newline, no wrapper field.
        self.assertEqual(
            raw,
            (
                json.dumps(body, separators=(",", ":"), ensure_ascii=False)
            ).encode("utf-8") + b"\n",
        )
        self.assertEqual(raw.count(b"\n"), 1)

    def test_delete_removes_only_the_target_record(self) -> None:
        other = register_notification(
            self.resource_id, target="other@example.invalid"
        )
        status, _h, body = delete_notification(
            self.resource_id, self.notification_id
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["id"], self.notification_id)

        status, _h, listing = call_json(
            "GET", f"/resources/{self.resource_id}/notifications"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            [n["id"] for n in listing["notifications"]], [other["id"]]
        )

    def test_deleted_notification_leaves_every_summary(self) -> None:
        other_resource = create_resource("other", DIGEST_B)
        surviving = register_notification(other_resource)

        status, _h, _b = delete_notification(
            self.resource_id, self.notification_id
        )
        self.assertEqual(status, "200 OK")

        # Global summary keeps only the surviving record, with no shadow.
        status, _h, summary = call_json("GET", "/notifications")
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            [(n["resource_id"], n["id"]) for n in summary],
            [(other_resource, surviving["id"])],
        )

        # The channel filter is recomputed from the remaining records too.
        status, _h, filtered = call_json(
            "GET", "/notifications", query_string="channel=email"
        )
        self.assertEqual([n["id"] for n in filtered], [surviving["id"]])
        status, _h, filtered_sms = call_json(
            "GET", "/notifications", query_string="channel=sms"
        )
        self.assertEqual(filtered_sms, [])

    def test_delete_does_not_touch_the_resource(self) -> None:
        status, _h, _b = delete_notification(
            self.resource_id, self.notification_id
        )
        self.assertEqual(status, "200 OK")
        status, _h, resource = call_json(
            "GET", f"/resources/{self.resource_id}"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(resource["id"], self.resource_id)

    def test_registration_after_delete_keeps_submission_order(self) -> None:
        second = register_notification(
            self.resource_id, target="second@example.invalid"
        )
        status, _h, _b = delete_notification(
            self.resource_id, self.notification_id
        )
        self.assertEqual(status, "200 OK")
        third = register_notification(
            self.resource_id, target="third@example.invalid"
        )
        status, _h, listing = call_json(
            "GET", f"/resources/{self.resource_id}/notifications"
        )
        self.assertEqual(
            [n["id"] for n in listing["notifications"]],
            [second["id"], third["id"]],
        )


class NotificationDeleteUsageViewTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.r1 = create_resource("r1", DIGEST_A)
        self.r2 = create_resource("r2", DIGEST_B)
        # First-appearance order across resources:
        # r1: (email, a@x), (sms, b@x); r2: (email, a@x)
        self.email_r1 = register_notification(
            self.r1, channel="email", target="a@x"
        )
        self.sms_r1 = register_notification(
            self.r1, channel="sms", target="b@x"
        )
        self.email_r2 = register_notification(
            self.r2, channel="email", target="a@x"
        )

    def test_views_contract_then_shrink_and_reorder(self) -> None:
        def view(path: str) -> list[dict[str, object]]:
            status, _h, body = call_json("GET", path)
            assert status == "200 OK"
            return body  # type: ignore[return-value]

        # Baseline: email opens first, then sms.
        usage = view("/notification-usage")
        self.assertEqual([entry["channel"] for entry in usage], ["email", "sms"])
        targets = view("/notification-targets")
        self.assertEqual([entry["target"] for entry in targets], ["a@x", "b@x"])
        pairs = view("/notification-channel-targets")
        self.assertEqual(
            [(entry["channel"], entry["target"]) for entry in pairs],
            [("email", "a@x"), ("sms", "b@x")],
        )

        status, _h, _b = delete_notification(
            self.r1, str(self.email_r1["id"])
        )
        self.assertEqual(status, "200 OK")

        # sms now provides the earliest surviving notification; email
        # survives through r2 and keeps just that one id.
        usage = view("/notification-usage")
        self.assertEqual(
            [(e["channel"], e["notifications"], e["targets"], e["resources"])
             for e in usage],
            [
                ("sms", [self.sms_r1["id"]], ["b@x"], [self.r1]),
                ("email", [self.email_r2["id"]], ["a@x"], [self.r2]),
            ],
        )
        self.assertEqual(
            [(e["channel"], e["notification_count"], e["resource_count"])
             for e in usage],
            [("sms", 1, 1), ("email", 1, 1)],
        )

        targets = view("/notification-targets")
        self.assertEqual(
            [(e["target"], e["notifications"], e["channels"], e["resources"])
             for e in targets],
            [
                ("b@x", [self.sms_r1["id"]], ["sms"], [self.r1]),
                ("a@x", [self.email_r2["id"]], ["email"], [self.r2]),
            ],
        )

        pairs = view("/notification-channel-targets")
        self.assertEqual(
            [
                (e["channel"], e["target"], e["notifications"], e["resources"])
                for e in pairs
            ],
            [
                ("sms", "b@x", [self.sms_r1["id"]], [self.r1]),
                ("email", "a@x", [self.email_r2["id"]], [self.r2]),
            ],
        )

        # Deleting the last notification of a group drops the entry
        # altogether; deleting the final record empties every view.
        status, _h, _b = call_json(
            "DELETE", item_path(self.r1, str(self.sms_r1["id"]))
        )
        self.assertEqual(status, "200 OK")
        usage = view("/notification-usage")
        self.assertEqual([e["channel"] for e in usage], ["email"])
        status, _h, _b = call_json(
            "DELETE", item_path(self.r2, str(self.email_r2["id"]))
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(view("/notification-usage"), [])
        self.assertEqual(view("/notification-targets"), [])
        self.assertEqual(view("/notification-channel-targets"), [])


class NotificationDeleteNotFoundTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.resource_id = create_resource()
        self.record = register_notification(self.resource_id)
        self.other_resource = create_resource("other", DIGEST_B)
        self.other_record = register_notification(self.other_resource)

    def test_unknown_notification_returns_404(self) -> None:
        status, _h, body = delete_notification(
            self.resource_id, "missing-id"
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "notification_not_found")
        self.assertEqual(set(body), {"error", "message"})

    def test_notification_of_other_resource_returns_404(self) -> None:
        # The id exists, but not under this resource.
        status, _h, body = delete_notification(
            self.resource_id, str(self.other_record["id"])
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "notification_not_found")
        # The notification is untouched and still belongs to its owner.
        status, _h, listing = call_json(
            "GET", f"/resources/{self.other_resource}/notifications"
        )
        self.assertEqual(
            [n["id"] for n in listing["notifications"]],
            [self.other_record["id"]],
        )

    def test_repeat_delete_is_consistent(self) -> None:
        status, _h, first = delete_notification(
            self.resource_id, str(self.record["id"])
        )
        self.assertEqual(status, "200 OK")
        status, _h, second = delete_notification(
            self.resource_id, str(self.record["id"])
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(second["error"], "notification_not_found")
        status, _h, third = delete_notification(
            self.resource_id, str(self.record["id"])
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(third["error"], "notification_not_found")

    def test_missing_resource_precedes_notification_lookup(self) -> None:
        status, _h, body = call_json(
            "DELETE", f"/resources/missing/notifications/{self.record['id']}"
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

    def test_failed_delete_leaves_every_record(self) -> None:
        status, _h, _b = delete_notification(self.resource_id, "missing")
        self.assertEqual(status, "404 Not Found")
        status, _h, summary = call_json("GET", "/notifications")
        self.assertEqual(
            sorted(n["id"] for n in summary),
            sorted([self.record["id"], self.other_record["id"]]),
        )


class NotificationDeleteRequestValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.resource_id = create_resource()
        self.record = register_notification(self.resource_id)
        self.item_path = item_path(
            self.resource_id, str(self.record["id"])
        )

    def _assert_notification_still_present(self) -> None:
        status, _h, listing = call_json(
            "GET", f"/resources/{self.resource_id}/notifications"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            [n["id"] for n in listing["notifications"]], [self.record["id"]]
        )

    def test_empty_path_segments_return_400(self) -> None:
        paths = [
            f"/resources/{self.resource_id}/notifications/",
            f"/resources/{self.resource_id}/notifications//",
            f"/resources//notifications/{self.record['id']}",
        ]
        for path in paths:
            with self.subTest(path=path):
                status, _h, body = call_json("DELETE", path)
                self.assertEqual(status, "400 Bad Request", path)
                self.assertEqual(body["error"], "invalid_request")
        self._assert_notification_still_present()

    def test_separator_segments_return_400(self) -> None:
        paths = [
            f"/resources/{self.resource_id}/notifications/a/b",
            f"/resources/{self.resource_id}/notifications/a%2Fb",
            f"/resources/{self.resource_id}/notifications/a%5Cb",
            f"/resources/{self.resource_id}/notifications/a%2fb",
            f"/resources/a/b/notifications/{self.record['id']}",
        ]
        for path in paths:
            with self.subTest(path=path):
                status, _h, body = call_json("DELETE", path)
                self.assertEqual(status, "400 Bad Request", path)
                self.assertEqual(body["error"], "invalid_request")
        self._assert_notification_still_present()

    def test_percent_encoded_segment_is_decoded_before_matching(self) -> None:
        # The id segment is percent-decoded like the other item paths:
        # encoding a hex character resolves to the same stored id, while a
        # double-encoded slash decodes to "%2F" and never matches.
        nid = str(self.record["id"])
        encoded = "%" + format(ord(nid[0]), "02X") + nid[1:]
        status, _h, body = call_json(
            "DELETE", f"/resources/{self.resource_id}/notifications/{encoded}"
        )
        self.assertEqual(status, "200 OK", body)
        self.assertEqual(body["id"], nid)

        record = register_notification(self.resource_id)
        status, _h, body = call_json(
            "DELETE",
            f"/resources/{self.resource_id}/notifications/{record['id']}%252F",
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "notification_not_found")

    def test_query_parameters_return_400(self) -> None:
        for query in ("x=1", "x=", "a=b&c=d"):
            with self.subTest(query=query):
                status, _h, body = call_json(
                    "DELETE", self.item_path, query_string=query
                )
                self.assertEqual(status, "400 Bad Request", query)
                self.assertEqual(body["error"], "invalid_request")
        self._assert_notification_still_present()

    def test_declared_non_empty_body_returns_400(self) -> None:
        status, _h, body = call("DELETE", self.item_path, b"x")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(json.loads(body)["error"], "invalid_request")
        self._assert_notification_still_present()

    def test_malformed_content_length_returns_400(self) -> None:
        status, _h, body = call(
            "DELETE",
            self.item_path,
            headers={"CONTENT_LENGTH": "abc"},
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(json.loads(body)["error"], "invalid_request")
        self._assert_notification_still_present()

    def test_empty_bodies_are_accepted(self) -> None:
        # Explicit zero length.
        status, _h, _b = call(
            "DELETE",
            self.item_path,
            headers={"CONTENT_LENGTH": "0"},
        )
        self.assertEqual(status, "200 OK")
        # An omitted header on a repeat delete is a well-shaped 404.
        status, _h, body = call_json(
            "DELETE", self.item_path, omit_content_length=True
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "notification_not_found")
        status, _h, body = call_json(
            "DELETE",
            self.item_path,
            headers={"CONTENT_LENGTH": ""},
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "notification_not_found")


class NotificationDeleteMethodTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.resource_id = create_resource()
        self.record = register_notification(self.resource_id)
        self.item_path = item_path(
            self.resource_id, str(self.record["id"])
        )

    def test_only_delete_and_put_are_allowed(self) -> None:
        for method in ("GET", "POST", "PATCH", "HEAD"):
            with self.subTest(method=method):
                status, headers, body = call_json(method, self.item_path)
                self.assertEqual(status, "405 Method Not Allowed", method)
                allow = [value for key, value in headers if key == "Allow"]
                # The item path also answers PUT updates; the Allow header
                # names PUT alone, while DELETE stays fully supported.
                self.assertEqual(allow, ["PUT"])
                self.assertEqual(body["error"], "method_not_allowed")

    def test_non_delete_with_query_still_returns_405(self) -> None:
        # Method is decided before the request shape is examined.
        status, headers, body = call_json(
            "GET", self.item_path, query_string="x=1"
        )
        self.assertEqual(status, "405 Method Not Allowed")
        self.assertIn(("Allow", "PUT"), headers)
        self.assertEqual(body["error"], "method_not_allowed")

    def test_non_delete_does_not_delete(self) -> None:
        status, _h, _b = call_json("POST", self.item_path)
        self.assertEqual(status, "405 Method Not Allowed")
        status, _h, listing = call_json(
            "GET", f"/resources/{self.resource_id}/notifications"
        )
        self.assertEqual(
            [n["id"] for n in listing["notifications"]], [self.record["id"]]
        )


if __name__ == "__main__":
    unittest.main()
