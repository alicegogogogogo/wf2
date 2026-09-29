from __future__ import annotations

import io
import json
import unittest

from provenance_api.app import application, reset_state

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64

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


def notification_body(
    *,
    channel: str = "sms",
    target: str = "new@example.invalid",
    message: str = "updated message",
) -> bytes:
    return json.dumps(
        {"channel": channel, "target": target, "message": message}
    ).encode("utf-8")


def item_path(resource_id: str, notification_id: str) -> str:
    return f"/resources/{resource_id}/notifications/{notification_id}"


def update_notification(
    resource_id: str, notification_id: str, body: bytes | None = None, **kwargs: object
):
    return call_json(
        "PUT",
        item_path(resource_id, notification_id),
        notification_body() if body is None else body,
        headers={"CONTENT_TYPE": "application/json"},
        **kwargs,
    )


class NotificationUpdateSuccessTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.resource_id = create_resource()
        self.record = register_notification(self.resource_id)
        self.notification_id = str(self.record["id"])

    def test_update_returns_200_and_echoes_four_fields_in_order(self) -> None:
        status, headers, raw = call(
            "PUT",
            item_path(self.resource_id, self.notification_id),
            notification_body(),
            headers={"CONTENT_TYPE": "application/json"},
        )
        self.assertEqual(status, "200 OK")
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )
        body = json.loads(raw)
        self.assertEqual(list(body), FOUR_KEYS)
        self.assertEqual(body["id"], self.notification_id)
        self.assertEqual(body["channel"], "sms")
        self.assertEqual(body["target"], "new@example.invalid")
        self.assertEqual(body["message"], "updated message")
        # Compact UTF-8 JSON ending in exactly one newline, no wrapper field.
        self.assertEqual(
            raw,
            (
                json.dumps(body, separators=(",", ":"), ensure_ascii=False)
            ).encode("utf-8") + b"\n",
        )
        self.assertEqual(raw.count(b"\n"), 1)

    def test_update_changes_the_record_in_place_without_a_new_one(self) -> None:
        status, _h, body = update_notification(
            self.resource_id, self.notification_id
        )
        self.assertEqual(status, "200 OK")

        status, _h, listing = call_json(
            "GET", f"/resources/{self.resource_id}/notifications"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(listing["notifications"]), 1)
        self.assertEqual(listing["notifications"][0], body)

    def test_update_keeps_submission_position(self) -> None:
        middle = register_notification(
            self.resource_id, target="middle@example.invalid", message="m"
        )
        last = register_notification(
            self.resource_id, target="last@example.invalid", message="l"
        )
        status, _h, body = update_notification(
            self.resource_id, str(middle["id"])
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["id"], middle["id"])

        status, _h, listing = call_json(
            "GET", f"/resources/{self.resource_id}/notifications"
        )
        self.assertEqual(
            [n["id"] for n in listing["notifications"]],
            [self.notification_id, middle["id"], last["id"]],
        )

    def test_identical_resubmission_is_200_and_creates_no_record(self) -> None:
        same = json.dumps(
            {
                "channel": self.record["channel"],
                "target": self.record["target"],
                "message": self.record["message"],
            }
        ).encode("utf-8")
        status, _h, body = update_notification(
            self.resource_id, self.notification_id, same
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, self.record)

        status, _h, again = update_notification(
            self.resource_id, self.notification_id, same
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(again, self.record)

        status, _h, listing = call_json(
            "GET", f"/resources/{self.resource_id}/notifications"
        )
        self.assertEqual(
            [n["id"] for n in listing["notifications"]], [self.notification_id]
        )

    def test_channel_and_target_are_echoed_verbatim(self) -> None:
        body = notification_body(channel=" EmAiL ", target=" Alerts@X ")
        status, _h, updated = update_notification(
            self.resource_id, self.notification_id, body
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(updated["channel"], " EmAiL ")
        self.assertEqual(updated["target"], " Alerts@X ")

    def test_max_length_fields_are_accepted(self) -> None:
        body = notification_body(
            channel="c" * 64, target="t" * 256, message="界" * 2048
        )
        status, _h, updated = update_notification(
            self.resource_id, self.notification_id, body
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(updated["channel"], "c" * 64)
        self.assertEqual(updated["target"], "t" * 256)
        self.assertEqual(updated["message"], "界" * 2048)

    def test_update_does_not_touch_the_resource(self) -> None:
        status, _h, _b = update_notification(
            self.resource_id, self.notification_id
        )
        self.assertEqual(status, "200 OK")
        status, _h, resource = call_json(
            "GET", f"/resources/{self.resource_id}"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(resource["id"], self.resource_id)


class NotificationUpdateSummaryTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.resource_id = create_resource()
        self.other_resource = create_resource("other", DIGEST_B)
        self.record = register_notification(
            self.resource_id, channel="email", target="a@x"
        )
        self.notification_id = str(self.record["id"])

    def test_resource_query_and_global_summary_reflect_new_values(self) -> None:
        status, _h, body = update_notification(
            self.resource_id,
            self.notification_id,
            notification_body(channel="sms", target="b@x", message="m2"),
        )
        self.assertEqual(status, "200 OK")

        status, _h, listing = call_json(
            "GET", f"/resources/{self.resource_id}/notifications"
        )
        self.assertEqual(listing["notifications"], [body])

        status, _h, summary = call_json("GET", "/notifications")
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(summary), 1)
        self.assertEqual(summary[0]["id"], self.notification_id)
        self.assertEqual(summary[0]["channel"], "sms")
        self.assertEqual(summary[0]["target"], "b@x")

        # The old channel filter loses the record; the new one gains it.
        status, _h, filtered = call_json(
            "GET", "/notifications", query_string="channel=email"
        )
        self.assertEqual(filtered, [])
        status, _h, filtered = call_json(
            "GET", "/notifications", query_string="channel=sms"
        )
        self.assertEqual([n["id"] for n in filtered], [self.notification_id])


class NotificationUpdateUsageViewTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.r1 = create_resource("r1", DIGEST_A)
        self.r2 = create_resource("r2", DIGEST_B)
        # First-appearance order across resources:
        # r1: (email, a@x), (sms, b@x); r2: (email, a@x)
        self.email_r1 = register_notification(
            self.r1, channel="email", target="a@x", message="one"
        )
        self.sms_r1 = register_notification(
            self.r1, channel="sms", target="b@x", message="two"
        )
        self.email_r2 = register_notification(
            self.r2, channel="email", target="a@x", message="three"
        )

    def _view(self, path: str) -> list[dict[str, object]]:
        status, _h, body = call_json("GET", path)
        assert status == "200 OK"
        return body  # type: ignore[return-value]

    def test_views_regroup_and_redetermine_first_appearance(self) -> None:
        # Move r1's email record onto a brand-new (webhook, c@x) group.
        status, _h, _b = update_notification(
            self.r1,
            str(self.email_r1["id"]),
            notification_body(channel="webhook", target="c@x"),
        )
        self.assertEqual(status, "200 OK")

        usage = self._view("/notification-usage")
        # sms keeps r1's earliest slot, webhook takes email's old opening
        # position, email survives only through r2.
        self.assertEqual(
            [(e["channel"], e["notifications"], e["targets"], e["resources"])
             for e in usage],
            [
                ("webhook", [self.email_r1["id"]], ["c@x"], [self.r1]),
                ("sms", [self.sms_r1["id"]], ["b@x"], [self.r1]),
                ("email", [self.email_r2["id"]], ["a@x"], [self.r2]),
            ],
        )
        self.assertEqual(
            [(e["channel"], e["notification_count"], e["resource_count"])
             for e in usage],
            [("webhook", 1, 1), ("sms", 1, 1), ("email", 1, 1)],
        )

        targets = self._view("/notification-targets")
        self.assertEqual(
            [(e["target"], e["notifications"], e["channels"], e["resources"])
             for e in targets],
            [
                ("c@x", [self.email_r1["id"]], ["webhook"], [self.r1]),
                ("b@x", [self.sms_r1["id"]], ["sms"], [self.r1]),
                ("a@x", [self.email_r2["id"]], ["email"], [self.r2]),
            ],
        )

        pairs = self._view("/notification-channel-targets")
        self.assertEqual(
            [
                (e["channel"], e["target"], e["notifications"], e["resources"])
                for e in pairs
            ],
            [
                ("webhook", "c@x", [self.email_r1["id"]], [self.r1]),
                ("sms", "b@x", [self.sms_r1["id"]], [self.r1]),
                ("email", "a@x", [self.email_r2["id"]], [self.r2]),
            ],
        )

    def test_case_and_whitespace_only_differences_stay_separate(self) -> None:
        status, _h, _b = update_notification(
            self.r1,
            str(self.email_r1["id"]),
            notification_body(channel="EMAIL", target=" a@x "),
        )
        self.assertEqual(status, "200 OK")

        usage = self._view("/notification-usage")
        self.assertEqual(
            [e["channel"] for e in usage], ["EMAIL", "sms", "email"]
        )
        pairs = self._view("/notification-channel-targets")
        self.assertEqual(
            [(e["channel"], e["target"]) for e in pairs],
            [("EMAIL", " a@x "), ("sms", "b@x"), ("email", "a@x")],
        )

    def test_merge_into_existing_group_extends_its_lists(self) -> None:
        # r1's email record changes target but keeps channel email, joining
        # r2's channel group without reordering the group itself.
        status, _h, _b = update_notification(
            self.r1,
            str(self.email_r1["id"]),
            notification_body(channel="email", target="d@x"),
        )
        self.assertEqual(status, "200 OK")

        usage = self._view("/notification-usage")
        self.assertEqual(
            [(e["channel"], e["notifications"], e["targets"], e["resources"])
             for e in usage],
            [
                (
                    "email",
                    [self.email_r1["id"], self.email_r2["id"]],
                    ["d@x", "a@x"],
                    [self.r1, self.r2],
                ),
                ("sms", [self.sms_r1["id"]], ["b@x"], [self.r1]),
            ],
        )

        pairs = self._view("/notification-channel-targets")
        self.assertEqual(
            [
                (e["channel"], e["target"], e["notifications"], e["resources"])
                for e in pairs
            ],
            [
                (
                    "email",
                    "d@x",
                    [self.email_r1["id"]],
                    [self.r1],
                ),
                ("sms", "b@x", [self.sms_r1["id"]], [self.r1]),
                ("email", "a@x", [self.email_r2["id"]], [self.r2]),
            ],
        )


class NotificationUpdateNotFoundTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.resource_id = create_resource()
        self.record = register_notification(self.resource_id)
        self.other_resource = create_resource("other", DIGEST_B)
        self.other_record = register_notification(self.other_resource)

    def test_unknown_notification_returns_404(self) -> None:
        status, _h, body = update_notification(self.resource_id, "missing-id")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "notification_not_found")
        self.assertEqual(set(body), {"error", "message"})

    def test_notification_of_other_resource_returns_404(self) -> None:
        status, _h, body = update_notification(
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

    def test_deleted_notification_returns_404(self) -> None:
        status, _h, _b = call_json(
            "DELETE", item_path(self.resource_id, str(self.record["id"]))
        )
        self.assertEqual(status, "200 OK")
        status, _h, body = update_notification(
            self.resource_id, str(self.record["id"])
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "notification_not_found")

    def test_missing_resource_precedes_notification_lookup(self) -> None:
        status, _h, body = update_notification(
            "missing-resource", str(self.record["id"])
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

    def test_failed_update_leaves_every_record(self) -> None:
        status, _h, _b = update_notification(self.resource_id, "missing")
        self.assertEqual(status, "404 Not Found")
        status, _h, summary = call_json("GET", "/notifications")
        self.assertEqual(
            sorted(n["id"] for n in summary),
            sorted([self.record["id"], self.other_record["id"]]),
        )


class NotificationUpdateRequestValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.resource_id = create_resource()
        self.record = register_notification(self.resource_id)
        self.item_path = item_path(
            self.resource_id, str(self.record["id"])
        )

    def _assert_notification_unchanged(self) -> None:
        status, _h, listing = call_json(
            "GET", f"/resources/{self.resource_id}/notifications"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(listing["notifications"], [self.record])

    def _put(self, body: bytes = b"", **kwargs: object):
        return call("PUT", self.item_path, body, **kwargs)  # type: ignore[arg-type]

    def test_empty_body_returns_400(self) -> None:
        status, _h, raw = self._put(b"")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(json.loads(raw)["error"], "invalid_request")
        # An omitted Content-Length reads as an empty body as well.
        status, _h, raw = self._put(b"", omit_content_length=True)
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(json.loads(raw)["error"], "invalid_request")
        self._assert_notification_unchanged()

    def test_undecodable_body_returns_400(self) -> None:
        status, _h, raw = self._put(b"\xff\xfe{}")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(json.loads(raw)["error"], "invalid_request")
        self._assert_notification_unchanged()

    def test_malformed_json_returns_400(self) -> None:
        status, _h, raw = self._put(b"{not json")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(json.loads(raw)["error"], "invalid_request")
        self._assert_notification_unchanged()

    def test_non_object_body_returns_400(self) -> None:
        for body in (b"[1,2]", b'"hello"', b"42", b"null", b"true"):
            with self.subTest(body=body):
                status, _h, raw = self._put(body)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(json.loads(raw)["error"], "invalid_request")
        self._assert_notification_unchanged()

    def test_missing_field_returns_400(self) -> None:
        for field in ("channel", "target", "message"):
            payload = json.loads(notification_body())
            del payload[field]
            status, _h, raw = self._put(json.dumps(payload).encode("utf-8"))
            self.assertEqual(status, "400 Bad Request", field)
            self.assertEqual(json.loads(raw)["error"], "invalid_request", field)
        self._assert_notification_unchanged()

    def test_unknown_field_returns_400(self) -> None:
        body = notification_body() + b""
        payload = json.loads(body)
        payload["priority"] = "high"
        status, _h, raw = self._put(json.dumps(payload).encode("utf-8"))
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(json.loads(raw)["error"], "invalid_request")
        self._assert_notification_unchanged()

    def test_wrong_type_returns_400(self) -> None:
        for field in ("channel", "target", "message"):
            payload = json.loads(notification_body())
            payload[field] = 42
            status, _h, raw = self._put(json.dumps(payload).encode("utf-8"))
            self.assertEqual(status, "400 Bad Request", field)
            self.assertEqual(json.loads(raw)["error"], "invalid_request", field)
        self._assert_notification_unchanged()

    def test_empty_value_returns_400(self) -> None:
        for field in ("channel", "target", "message"):
            payload = json.loads(notification_body())
            payload[field] = ""
            status, _h, raw = self._put(json.dumps(payload).encode("utf-8"))
            self.assertEqual(status, "400 Bad Request", field)
            self.assertEqual(json.loads(raw)["error"], "invalid_request", field)
        self._assert_notification_unchanged()

    def test_overlong_value_returns_400(self) -> None:
        cases = (
            {"channel": "c" * 65},
            {"target": "t" * 257},
            {"message": "m" * 2049},
        )
        for overrides in cases:
            payload = json.loads(notification_body())
            payload.update(overrides)
            status, _h, raw = self._put(json.dumps(payload).encode("utf-8"))
            self.assertEqual(status, "400 Bad Request", overrides)
            self.assertEqual(json.loads(raw)["error"], "invalid_request")
        self._assert_notification_unchanged()

    def test_invalid_body_returns_400_even_for_unknown_notification(self) -> None:
        status, _h, body = call_json(
            "PUT",
            item_path(self.resource_id, "missing-id"),
            b"",
            headers={"CONTENT_TYPE": "application/json"},
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_empty_path_segments_return_400(self) -> None:
        paths = [
            f"/resources/{self.resource_id}/notifications/",
            f"/resources/{self.resource_id}/notifications//",
            f"/resources//notifications/{self.record['id']}",
        ]
        for path in paths:
            with self.subTest(path=path):
                status, _h, raw = self._put_path(path)
                self.assertEqual(status, "400 Bad Request", path)
                self.assertEqual(json.loads(raw)["error"], "invalid_request")
        self._assert_notification_unchanged()

    def test_separator_segments_return_400(self) -> None:
        paths = [
            f"/resources/{self.resource_id}/notifications/a/b",
            f"/resources/{self.resource_id}/notifications/a%2Fb",
            f"/resources/{self.resource_id}/notifications/a%5Cb",
            f"/resources/a/b/notifications/{self.record['id']}",
        ]
        for path in paths:
            with self.subTest(path=path):
                status, _h, raw = self._put_path(path)
                self.assertEqual(status, "400 Bad Request", path)
                self.assertEqual(json.loads(raw)["error"], "invalid_request")
        self._assert_notification_unchanged()

    def _put_path(self, path: str):
        return call(
            "PUT",
            path,
            notification_body(),
            headers={"CONTENT_TYPE": "application/json"},
        )

    def test_percent_encoded_segment_is_decoded_before_matching(self) -> None:
        nid = str(self.record["id"])
        encoded = "%" + format(ord(nid[0]), "02X") + nid[1:]
        status, _h, body = call_json(
            "PUT",
            f"/resources/{self.resource_id}/notifications/{encoded}",
            notification_body(),
            headers={"CONTENT_TYPE": "application/json"},
        )
        self.assertEqual(status, "200 OK", body)
        self.assertEqual(body["id"], nid)

    def test_query_parameters_return_400(self) -> None:
        for query in ("x=1", "x=", "a=b&c=d"):
            with self.subTest(query=query):
                status, _h, body = call_json(
                    "PUT",
                    self.item_path,
                    notification_body(),
                    headers={"CONTENT_TYPE": "application/json"},
                    query_string=query,
                )
                self.assertEqual(status, "400 Bad Request", query)
                self.assertEqual(body["error"], "invalid_request")
        self._assert_notification_unchanged()

    def test_malformed_content_length_is_400_not_an_update(self) -> None:
        # A declared non-empty body that cannot be framed is rejected; the
        # record stays as registered.
        status, _h, raw = call(
            "PUT",
            self.item_path,
            b"",
            headers={"CONTENT_LENGTH": "abc"},
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(json.loads(raw)["error"], "invalid_request")
        self._assert_notification_unchanged()


class NotificationUpdateMethodTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.resource_id = create_resource()
        self.record = register_notification(self.resource_id)
        self.item_path = item_path(
            self.resource_id, str(self.record["id"])
        )

    def test_only_put_and_delete_are_allowed(self) -> None:
        for method in ("GET", "POST", "PATCH", "HEAD"):
            with self.subTest(method=method):
                status, headers, body = call_json(method, self.item_path)
                self.assertEqual(status, "405 Method Not Allowed", method)
                self.assertEqual(
                    [value for key, value in headers if key == "Allow"],
                    ["PUT"],
                )
                self.assertEqual(body["error"], "method_not_allowed")

    def test_non_allowed_method_with_query_still_returns_405(self) -> None:
        # Method is decided before the request shape is examined.
        status, headers, body = call_json(
            "GET", self.item_path, query_string="x=1"
        )
        self.assertEqual(status, "405 Method Not Allowed")
        self.assertIn(("Allow", "PUT"), headers)
        self.assertEqual(body["error"], "method_not_allowed")

    def test_delete_still_removes_the_record(self) -> None:
        status, _h, body = call_json("DELETE", self.item_path)
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["id"], self.record["id"])
        status, _h, body = call_json(
            "PUT",
            self.item_path,
            notification_body(),
            headers={"CONTENT_TYPE": "application/json"},
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "notification_not_found")


if __name__ == "__main__":
    unittest.main()
