from __future__ import annotations

import io
import json
import unittest

from provenance_api.app import application, reset_state
from provenance_api.notifications import (
    NotificationStore,
    NotificationValidationError,
)

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64

FOUR_KEYS = ["id", "channel", "target", "message"]


def call(
    method: str,
    path: str,
    body: bytes | str | dict[str, object] | None = None,
    *,
    query_string: str | None = None,
    content_type: str | None = "application/json",
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
        "wsgi.input": io.BytesIO(payload),
    }
    if not omit_content_length:
        environ["CONTENT_LENGTH"] = str(len(payload))
    if content_type is not None:
        environ["CONTENT_TYPE"] = content_type
    for key, value in (headers or {}).items():
        environ[key] = value
    captured: dict[str, object] = {}

    def start_response(status: str, resp_headers: list[tuple[str, str]]) -> None:
        captured["status"] = status
        captured["headers"] = resp_headers

    parts = application(environ, start_response)
    return str(captured["status"]), list(captured["headers"]), b"".join(parts)


def call_json(
    method: str,
    path: str,
    body: bytes | str | dict[str, object] | None = None,
    *,
    query_string: str | None = None,
) -> tuple[str, list[tuple[str, str]], dict[str, object]]:
    status, headers, raw = call(method, path, body, query_string=query_string)
    return status, headers, json.loads(raw.decode("utf-8"))


def create_resource(name: str = "r", digest: str = DIGEST_A) -> str:
    status, _h, body = call_json(
        "POST",
        "/resources",
        {"name": name, "category": "code", "digest": digest},
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
        {"channel": channel, "target": target, "message": message},
    )
    assert status == "201 Created", (status, body)
    return body


def notification_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "channel": "email",
        "target": "alerts@example.invalid",
        "message": "risk level changed",
    }
    payload.update(overrides)
    return payload


def item_path(resource_id: str, notification_id: str) -> str:
    return f"/resources/{resource_id}/notifications/{notification_id}"


def update(
    resource_id: str,
    notification_id: str,
    body: object,
    *,
    query_string: str | None = None,
):
    return call_json(
        "PUT",
        item_path(resource_id, notification_id),
        body if isinstance(body, (dict, bytes, str)) else {},
        query_string=query_string,
    )


class NotificationUpdateSuccessTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.resource_id = create_resource()
        self.record = register_notification(self.resource_id)
        self.notification_id = str(self.record["id"])

    def test_update_returns_200_echoing_full_record(self) -> None:
        status, headers, raw = call(
            "PUT",
            item_path(self.resource_id, self.notification_id),
            {
                "channel": "sms",
                "target": "+1-555-0100",
                "message": "new message",
            },
        )
        self.assertEqual(status, "200 OK")
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )
        body = json.loads(raw)
        self.assertEqual(list(body), FOUR_KEYS)
        self.assertEqual(
            body,
            {
                "id": self.notification_id,
                "channel": "sms",
                "target": "+1-555-0100",
                "message": "new message",
            },
        )
        # Compact UTF-8 JSON ending in exactly one newline, no wrapper field.
        self.assertEqual(
            raw,
            (
                json.dumps(body, separators=(",", ":"), ensure_ascii=False)
            ).encode("utf-8") + b"\n",
        )
        self.assertEqual(raw.count(b"\n"), 1)

        # The stored record matches the echo exactly.
        status, _h, listing = call_json(
            "GET", f"/resources/{self.resource_id}/notifications"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(listing["notifications"], [body])

    def test_update_keeps_id_and_submission_position(self) -> None:
        second = register_notification(
            self.resource_id,
            channel="sms",
            target="b@x",
            message="second",
        )
        third = register_notification(
            self.resource_id,
            channel="webhook",
            target="c@x",
            message="third",
        )

        status, _h, body = update(
            self.resource_id,
            str(second["id"]),
            notification_payload(
                channel="pager", target="z@x", message="changed"
            ),
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["id"], second["id"])

        status, _h, listing = call_json(
            "GET", f"/resources/{self.resource_id}/notifications"
        )
        self.assertEqual(
            [n["id"] for n in listing["notifications"]],
            [self.notification_id, second["id"], third["id"]],
        )
        middle = listing["notifications"][1]
        self.assertEqual(middle["channel"], "pager")
        self.assertEqual(middle["target"], "z@x")
        self.assertEqual(middle["message"], "changed")

    def test_identical_resubmit_is_200_and_creates_no_record(self) -> None:
        payload = notification_payload()
        status, _h, first = update(
            self.resource_id, self.notification_id, payload
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(first, self.record)
        status, _h, second = update(
            self.resource_id, self.notification_id, payload
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(second, self.record)

        status, _h, listing = call_json(
            "GET", f"/resources/{self.resource_id}/notifications"
        )
        self.assertEqual(
            [n["id"] for n in listing["notifications"]],
            [self.notification_id],
        )

    def test_max_length_values_are_accepted(self) -> None:
        payload = notification_payload(
            channel="c" * 64, target="t" * 256, message="界" * 2048
        )
        status, _h, body = update(
            self.resource_id, self.notification_id, payload
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["channel"], "c" * 64)
        self.assertEqual(body["target"], "t" * 256)
        self.assertEqual(body["message"], "界" * 2048)

    def test_channel_and_target_are_echoed_verbatim(self) -> None:
        for channel, target in (
            ("Email", "Alerts@Example.invalid"),
            (" email ", "\ttarget@x\n"),
        ):
            with self.subTest(channel=channel, target=target):
                status, _h, body = update(
                    self.resource_id,
                    self.notification_id,
                    notification_payload(channel=channel, target=target),
                )
                self.assertEqual(status, "200 OK")
                self.assertEqual(body["channel"], channel)
                self.assertEqual(body["target"], target)


class NotificationUpdateViewTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.r1 = create_resource("r1", DIGEST_A)
        self.r2 = create_resource("r2", DIGEST_B)
        self.r3 = create_resource("r3", DIGEST_C)
        # r1: (email, a@x, m1), (sms, b@x, m2); r2: (email, a@x, m3).
        self.email_r1 = register_notification(
            self.r1, channel="email", target="a@x", message="m1"
        )
        self.sms_r1 = register_notification(
            self.r1, channel="sms", target="b@x", message="m2"
        )
        self.email_r2 = register_notification(
            self.r2, channel="email", target="a@x", message="m3"
        )

    def test_resource_query_and_global_summary_follow_new_values(self) -> None:
        status, _h, _b = update(
            self.r1,
            str(self.email_r1["id"]),
            notification_payload(
                channel="sms", target="c@x", message="new"
            ),
        )
        self.assertEqual(status, "200 OK")

        status, _h, listing = call_json(
            "GET", f"/resources/{self.r1}/notifications"
        )
        self.assertEqual(status, "200 OK")
        by_id = {n["id"]: n for n in listing["notifications"]}
        updated = by_id[str(self.email_r1["id"])]
        self.assertEqual(updated["channel"], "sms")
        self.assertEqual(updated["target"], "c@x")
        self.assertEqual(updated["message"], "new")

        status, _h, summary = call_json("GET", "/notifications")
        self.assertEqual(status, "200 OK")
        rows = {
            (n["resource_id"], n["id"]): (n["channel"], n["target"])
            for n in summary
        }
        self.assertEqual(
            rows[(self.r1, str(self.email_r1["id"]))], ("sms", "c@x")
        )
        self.assertEqual(
            rows[(self.r1, str(self.sms_r1["id"]))], ("sms", "b@x")
        )
        self.assertEqual(
            rows[(self.r2, str(self.email_r2["id"]))], ("email", "a@x")
        )

        # The summary order is resource order then (unchanged) submission
        # position; the updated record stays first within r1.
        self.assertEqual(
            [(n["resource_id"], n["id"]) for n in summary],
            [
                (self.r1, str(self.email_r1["id"])),
                (self.r1, str(self.sms_r1["id"])),
                (self.r2, str(self.email_r2["id"])),
            ],
        )

        # The global channel filter matches the new value and not the old.
        status, _h, filtered = call_json(
            "GET", "/notifications", query_string="channel=sms"
        )
        self.assertEqual(
            sorted(n["id"] for n in filtered),
            sorted([str(self.email_r1["id"]), str(self.sms_r1["id"])]),
        )
        status, _h, filtered_old = call_json(
            "GET", "/notifications", query_string="channel=email"
        )
        self.assertEqual(
            [n["id"] for n in filtered_old], [str(self.email_r2["id"])]
        )

    def test_usage_views_regroup_and_reorder(self) -> None:
        def view(path: str) -> list[dict[str, object]]:
            status, _h, body = call_json("GET", path)
            assert status == "200 OK"
            return body  # type: ignore[return-value]

        # Move r1's first notification onto the sms/c@x pair. Email now
        # survives only through r2, whose record comes later, so sms opens
        # the channel and target orders first.
        status, _h, _b = update(
            self.r1,
            str(self.email_r1["id"]),
            notification_payload(channel="sms", target="c@x"),
        )
        self.assertEqual(status, "200 OK")

        usage = view("/notification-usage")
        self.assertEqual(
            [
                (
                    e["channel"],
                    e["notifications"],
                    e["targets"],
                    e["resources"],
                )
                for e in usage
            ],
            [
                (
                    "sms",
                    [str(self.email_r1["id"]), str(self.sms_r1["id"])],
                    ["c@x", "b@x"],
                    [self.r1],
                ),
                (
                    "email",
                    [str(self.email_r2["id"])],
                    ["a@x"],
                    [self.r2],
                ),
            ],
        )
        self.assertEqual(
            [(e["channel"], e["notification_count"], e["resource_count"])
             for e in usage],
            [("sms", 2, 1), ("email", 1, 1)],
        )

        targets = view("/notification-targets")
        self.assertEqual(
            [
                (e["target"], e["notifications"], e["channels"], e["resources"])
                for e in targets
            ],
            [
                (
                    "c@x",
                    [str(self.email_r1["id"])],
                    ["sms"],
                    [self.r1],
                ),
                (
                    "b@x",
                    [str(self.sms_r1["id"])],
                    ["sms"],
                    [self.r1],
                ),
                (
                    "a@x",
                    [str(self.email_r2["id"])],
                    ["email"],
                    [self.r2],
                ),
            ],
        )

        pairs = view("/notification-channel-targets")
        self.assertEqual(
            [
                (e["channel"], e["target"], e["notifications"], e["resources"])
                for e in pairs
            ],
            [
                (
                    "sms",
                    "c@x",
                    [str(self.email_r1["id"])],
                    [self.r1],
                ),
                (
                    "sms",
                    "b@x",
                    [str(self.sms_r1["id"])],
                    [self.r1],
                ),
                (
                    "email",
                    "a@x",
                    [str(self.email_r2["id"])],
                    [self.r2],
                ),
            ],
        )

        # Moving the last notification out of a group drops that entry;
        # moving the remaining r2 record onto sms empties the email group.
        status, _h, _b = update(
            self.r1,
            str(self.sms_r1["id"]),
            notification_payload(channel="sms", target="c@x"),
        )
        self.assertEqual(status, "200 OK")
        pairs = view("/notification-channel-targets")
        self.assertEqual(
            [(e["channel"], e["target"]) for e in pairs],
            [("sms", "c@x"), ("email", "a@x")],
        )

        status, _h, _b = update(
            self.r2,
            str(self.email_r2["id"]),
            notification_payload(channel="sms", target="c@x"),
        )
        self.assertEqual(status, "200 OK")
        targets = view("/notification-targets")
        self.assertEqual([e["target"] for e in targets], ["c@x"])
        pairs = view("/notification-channel-targets")
        self.assertEqual(
            [(e["channel"], e["target"]) for e in pairs], [("sms", "c@x")]
        )
        usage = view("/notification-usage")
        self.assertEqual(
            [
                (
                    e["channel"],
                    e["notifications"],
                    e["targets"],
                    e["resources"],
                )
                for e in usage
            ],
            [
                (
                    "sms",
                    [
                        str(self.email_r1["id"]),
                        str(self.sms_r1["id"]),
                        str(self.email_r2["id"]),
                    ],
                    ["c@x"],
                    [self.r1, self.r2],
                )
            ],
        )

    def test_case_and_whitespace_only_differences_split_groups(self) -> None:
        # Change only the case of the channel: the updated record leaves the
        # lowercase group and opens an uppercase group of its own.
        status, _h, _b = update(
            self.r1,
            str(self.email_r1["id"]),
            notification_payload(channel="EMAIL", target="a@x"),
        )
        self.assertEqual(status, "200 OK")
        usage = call_json("GET", "/notification-usage")[2]
        # The updated record keeps its first submission slot within r1, so
        # the new uppercase group opens before sms and lowercase email.
        self.assertEqual(
            [(e["channel"], e["notifications"]) for e in usage],
            [
                ("EMAIL", [str(self.email_r1["id"])]),
                ("sms", [str(self.sms_r1["id"])]),
                ("email", [str(self.email_r2["id"])]),
            ],
        )

        # A whitespace-only difference in the target opens a new target group
        # and leaves the verbatim value untouched. The record stays first in
        # r1, so the new target opens the order.
        status, _h, _b = update(
            self.r1,
            str(self.email_r1["id"]),
            notification_payload(channel="email", target=" a@x"),
        )
        self.assertEqual(status, "200 OK")
        targets = call_json("GET", "/notification-targets")[2]
        self.assertEqual(
            [(e["target"], e["notifications"]) for e in targets],
            [
                (" a@x", [str(self.email_r1["id"])]),
                ("b@x", [str(self.sms_r1["id"])]),
                ("a@x", [str(self.email_r2["id"])]),
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
        status, _h, body = update(
            self.resource_id, "missing-id", notification_payload()
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "notification_not_found")
        self.assertEqual(set(body), {"error", "message"})

    def test_notification_of_other_resource_returns_404(self) -> None:
        status, _h, body = update(
            self.resource_id,
            str(self.other_record["id"]),
            notification_payload(channel="sms"),
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "notification_not_found")
        # Neither notification is touched.
        status, _h, listing = call_json(
            "GET", f"/resources/{self.other_resource}/notifications"
        )
        self.assertEqual(listing["notifications"], [self.other_record])
        status, _h, listing = call_json(
            "GET", f"/resources/{self.resource_id}/notifications"
        )
        self.assertEqual(listing["notifications"], [self.record])

    def test_deleted_notification_returns_404(self) -> None:
        status, _h, _b = call_json(
            "DELETE", item_path(self.resource_id, str(self.record["id"]))
        )
        self.assertEqual(status, "200 OK")
        status, _h, body = update(
            self.resource_id, str(self.record["id"]), notification_payload()
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "notification_not_found")

    def test_missing_resource_precedes_notification_lookup(self) -> None:
        status, _h, body = update(
            "missing", str(self.record["id"]), notification_payload()
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "resource_not_found")

    def test_failed_update_leaves_every_record(self) -> None:
        status, _h, _b = update(
            self.resource_id, "missing", notification_payload(channel="sms")
        )
        self.assertEqual(status, "404 Not Found")
        status, _h, summary = call_json("GET", "/notifications")
        self.assertEqual(
            sorted(n["id"] for n in summary),
            sorted([str(self.record["id"]), str(self.other_record["id"])]),
        )
        # The target record keeps its registered channel.
        status, _h, listing = call_json(
            "GET", f"/resources/{self.resource_id}/notifications"
        )
        self.assertEqual(
            listing["notifications"][0]["channel"], self.record["channel"]
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

    def test_missing_or_unreadable_body_returns_400(self) -> None:
        for raw_body in (b"", "x", "{", json.dumps([]), json.dumps("x")):
            with self.subTest(raw_body=raw_body):
                status, _h, raw = call("PUT", self.item_path, raw_body)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(json.loads(raw)["error"], "invalid_request")
        self._assert_notification_unchanged()

    def test_missing_unknown_and_typed_wrong_fields_are_400(self) -> None:
        long_channel = "c" * 65
        long_target = "t" * 257
        long_message = "m" * 2049
        cases = (
            ("missing channel", {k: v for k, v in notification_payload().items() if k != "channel"}),
            ("missing target", {k: v for k, v in notification_payload().items() if k != "target"}),
            ("missing message", {k: v for k, v in notification_payload().items() if k != "message"}),
            ("unknown field", {**notification_payload(), "priority": 1}),
            ("channel null", {**notification_payload(), "channel": None}),
            ("channel typed", {**notification_payload(), "channel": 7}),
            ("channel empty", {**notification_payload(), "channel": ""}),
            ("channel too long", {**notification_payload(), "channel": long_channel}),
            ("target null", {**notification_payload(), "target": None}),
            ("target typed", {**notification_payload(), "target": 9}),
            ("target empty", {**notification_payload(), "target": ""}),
            ("target too long", {**notification_payload(), "target": long_target}),
            ("message null", {**notification_payload(), "message": None}),
            ("message typed", {**notification_payload(), "message": 4}),
            ("message empty", {**notification_payload(), "message": ""}),
            ("message too long", {**notification_payload(), "message": long_message}),
        )
        for label, payload in cases:
            with self.subTest(label):
                status, _h, body = call_json("PUT", self.item_path, payload)
                self.assertEqual(status, "400 Bad Request", label)
                self.assertEqual(body["error"], "invalid_request")
        self._assert_notification_unchanged()

    def test_invalid_payload_returns_400_even_for_unknown_resource(self) -> None:
        status, _h, body = call_json(
            "PUT",
            item_path("missing-resource", str(self.record["id"])),
            notification_payload(channel=""),
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")

    def test_empty_or_separator_ids_are_400(self) -> None:
        base = f"/resources/{self.resource_id}/notifications"
        for path in (
            f"{base}/",
            f"{base}//",
            f"{base}/a/b",
            f"{base}/a%2Fb",
            f"{base}/a%5Cb",
            f"{base}/a%2fb",
            f"/resources//notifications/{self.record['id']}",
            f"/resources/a/b/notifications/{self.record['id']}",
        ):
            with self.subTest(path=path):
                status, _h, raw = call(
                    "PUT", path, notification_payload()
                )
                self.assertEqual(status, "400 Bad Request", path)
                self.assertEqual(json.loads(raw)["error"], "invalid_request")
        self._assert_notification_unchanged()

    def test_percent_encoded_segment_is_decoded_before_matching(self) -> None:
        nid = str(self.record["id"])
        encoded = "%" + format(ord(nid[0]), "02X") + nid[1:]
        status, _h, body = call_json(
            "PUT",
            f"/resources/{self.resource_id}/notifications/{encoded}",
            notification_payload(channel="sms"),
        )
        self.assertEqual(status, "200 OK", body)
        self.assertEqual(body["id"], nid)
        self.assertEqual(body["channel"], "sms")

    def test_query_parameters_return_400(self) -> None:
        for query in ("x=1", "x=", "a=b&c=d"):
            with self.subTest(query=query):
                status, _h, body = call_json(
                    "PUT",
                    self.item_path,
                    notification_payload(channel="sms"),
                    query_string=query,
                )
                self.assertEqual(status, "400 Bad Request", query)
                self.assertEqual(body["error"], "invalid_request")
        self._assert_notification_unchanged()

    def test_malformed_content_length_returns_400(self) -> None:
        status, _h, body = call(
            "PUT",
            self.item_path,
            notification_payload(),
            headers={"CONTENT_LENGTH": "abc"},
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(json.loads(body)["error"], "invalid_request")
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
                status, headers, body = call_json(
                    method, self.item_path, notification_payload()
                )
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")
                self.assertEqual(
                    [value for name, value in headers if name == "Allow"],
                    ["PUT"],
                )

    def test_method_decided_before_request_shape(self) -> None:
        status, headers, body = call_json(
            "GET", self.item_path, query_string="x=1"
        )
        self.assertEqual(status, "405 Method Not Allowed")
        self.assertIn(("Allow", "PUT"), headers)
        self.assertEqual(body["error"], "method_not_allowed")

    def test_disallowed_method_does_not_change_record(self) -> None:
        status, _h, _b = call_json("POST", self.item_path, b"")
        self.assertEqual(status, "405 Method Not Allowed")
        status, _h, listing = call_json(
            "GET", f"/resources/{self.resource_id}/notifications"
        )
        self.assertEqual(listing["notifications"], [self.record])

    def test_delete_still_works_alongside_put(self) -> None:
        status, _h, body = call_json("DELETE", self.item_path)
        self.assertEqual(status, "200 OK")
        self.assertEqual(body["id"], self.record["id"])
        status, _h, body = call_json(
            "PUT", self.item_path, notification_payload()
        )
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "notification_not_found")


class NotificationStoreUpdateTests(unittest.TestCase):
    def test_store_update_replaces_in_place(self) -> None:
        store = NotificationStore()
        first = store.add(
            "r",
            {"channel": "email", "target": "a@x", "message": "m1"},
        )
        second = store.add(
            "r",
            {"channel": "sms", "target": "b@x", "message": "m2"},
        )
        foreign = store.add(
            "other",
            {"channel": "email", "target": "a@x", "message": "m3"},
        )

        updated = store.update(
            "r",
            first.id,
            {"channel": "pager", "target": "z@x", "message": "new"},
        )
        self.assertIsNotNone(updated)
        assert updated is not None
        self.assertEqual(updated.id, first.id)
        self.assertEqual(updated.channel, "pager")
        self.assertEqual(updated.target, "z@x")
        self.assertEqual(updated.message, "new")
        self.assertEqual([r.id for r in store.list_for("r")], [first.id, second.id])
        self.assertEqual(store.list_for("r")[0], updated)
        # The other resource's record is untouched.
        self.assertEqual(store.list_for("other"), [foreign])

        # An identical payload is accepted and stays one record.
        again = store.update(
            "r",
            first.id,
            {"channel": "pager", "target": "z@x", "message": "new"},
        )
        self.assertIsNotNone(again)
        self.assertEqual(len(store.list_for("r")), 2)

    def test_store_update_invalid_payload_raises_without_change(self) -> None:
        store = NotificationStore()
        record = store.add(
            "r",
            {"channel": "email", "target": "a@x", "message": "m1"},
        )
        for payload in (
            [],
            {"target": "a@x", "message": "m"},
            {"channel": "email", "target": "a@x", "message": "m", "x": 1},
            {"channel": "", "target": "a@x", "message": "m"},
            {"channel": 7, "target": "a@x", "message": "m"},
        ):
            with self.subTest(payload=payload):
                with self.assertRaises(NotificationValidationError):
                    store.update("r", record.id, payload)
        self.assertEqual(store.list_for("r"), [record])

    def test_store_unknown_foreign_and_missing_resource_return_none(self) -> None:
        store = NotificationStore()
        record = store.add(
            "r",
            {"channel": "email", "target": "a@x", "message": "m1"},
        )
        foreign = store.add(
            "other",
            {"channel": "email", "target": "a@x", "message": "m2"},
        )
        payload = {"channel": "sms", "target": "c@x", "message": "m3"}
        self.assertIsNone(store.update("r", "missing", payload))
        self.assertIsNone(store.update("r", foreign.id, payload))
        self.assertIsNone(store.update("missing", record.id, payload))
        # Nothing changed.
        self.assertEqual(store.list_for("r"), [record])
        self.assertEqual(store.list_for("other"), [foreign])


if __name__ == "__main__":
    unittest.main()
