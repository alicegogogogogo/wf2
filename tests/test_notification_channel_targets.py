from __future__ import annotations

import io
import json
import unittest

from provenance_api.app import application, reset_state

PATH = "/notification-channel-targets"

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64

KEYS = (
    "channel",
    "target",
    "notifications",
    "notification_count",
    "resources",
    "resource_count",
)


def call(
    method: str,
    path: str = PATH,
    body: bytes | str | dict[str, object] | None = None,
    *,
    query_string: str | None = None,
    content_type: str | None = None,
    content_length: int | str | None = None,
    omit_content_length: bool = False,
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
        environ["CONTENT_LENGTH"] = (
            str(len(payload)) if content_length is None else str(content_length)
        )
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
    path: str = PATH,
    body: bytes | str | dict[str, object] | None = None,
    *,
    query_string: str | None = None,
    content_length: int | str | None = None,
    omit_content_length: bool = False,
) -> tuple[str, list[tuple[str, str]], object]:
    status, headers, raw = call(
        method,
        path,
        body,
        query_string=query_string,
        content_length=content_length,
        omit_content_length=omit_content_length,
    )
    return status, headers, json.loads(raw.decode("utf-8"))


class NotificationChannelTargetsTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def _create(self, digest: str, name: str) -> str:
        _s, _h, body = call_json(
            "POST",
            "/resources",
            {"name": name, "category": "code", "digest": digest},
        )
        return str(body["id"])  # type: ignore[index]

    def _notify(
        self,
        resource_id: str,
        channel: str = "email",
        target: str = "alerts@example.invalid",
        message: str = "hello",
    ) -> str:
        status, _h, body = call_json(
            "POST",
            f"/resources/{resource_id}/notifications",
            {"channel": channel, "target": target, "message": message},
        )
        assert status == "201 Created", body
        return str(body["id"])  # type: ignore[index]

    def _usage(self, query_string: str | None = None) -> list[dict[str, object]]:
        status, headers, raw = call("GET", PATH, query_string=query_string)
        self.assertEqual(status, "200 OK")
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )
        self.assertTrue(raw.endswith(b"\n"))
        decoded = json.loads(raw)
        self.assertIsInstance(decoded, list)
        return decoded  # type: ignore[return-value]

    # --- Shape -------------------------------------------------------------

    def test_empty_when_no_resources(self) -> None:
        status, headers, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )

    def test_empty_when_no_notifications(self) -> None:
        self._create(DIGEST_A, "r1")
        self._create(DIGEST_B, "r2")
        self.assertEqual(self._usage(), [])

    def test_entry_has_exactly_six_keys_in_fixed_order(self) -> None:
        resource_id = self._create(DIGEST_A, "r1")
        self._notify(resource_id, message="风险等级变化")

        status, _h, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        text = raw.decode("utf-8").rstrip("\n")
        # Compact UTF-8: no added whitespace and non-ASCII is not escaped.
        self.assertNotIn(" ", text)

        usage = json.loads(text)
        self.assertEqual(len(usage), 1)
        self.assertEqual(tuple(usage[0]), KEYS)

        positions = [text.index(f'"{key}"') for key in KEYS]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(usage[0]["channel"], "email")
        self.assertEqual(usage[0]["target"], "alerts@example.invalid")

    def test_compact_body_ends_with_single_newline(self) -> None:
        resource_id = self._create(DIGEST_A, "r1")
        self._notify(resource_id)
        _status, _h, raw = call("GET", PATH)
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))

    # --- Grouping and ordering --------------------------------------------

    def test_one_entry_per_pair_in_first_appearance_order(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")

        # Submissions deliberately arrive in non-group order; the first
        # appearance walk (r1 before r2, submission order within r1)
        # fixes the entry order.
        n_r2 = self._notify(r2, channel="webhook", target="b@example.invalid")
        n_r1_first = self._notify(r1, channel="email", target="one@example.invalid")
        n_r1_second = self._notify(r1, channel="sms", target="two@example.invalid")
        n_r1_third = self._notify(
            r1, channel="email", target="one@example.invalid"
        )

        usage = self._usage()
        self.assertEqual(
            [(item["channel"], item["target"]) for item in usage],
            [
                ("email", "one@example.invalid"),
                ("sms", "two@example.invalid"),
                ("webhook", "b@example.invalid"),
            ],
        )
        self.assertEqual(usage[0]["notifications"], [n_r1_first, n_r1_third])
        self.assertEqual(usage[0]["notification_count"], 2)
        self.assertEqual(usage[1]["notifications"], [n_r1_second])
        self.assertEqual(usage[2]["notifications"], [n_r2])

    def test_same_target_under_different_channels_stays_separate(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        email_id = self._notify(r1, channel="email", target="ops@example.invalid")
        sms_id = self._notify(r1, channel="sms", target="ops@example.invalid")

        usage = self._usage()
        self.assertEqual(
            [(item["channel"], item["target"]) for item in usage],
            [("email", "ops@example.invalid"), ("sms", "ops@example.invalid")],
        )
        self.assertEqual(usage[0]["notifications"], [email_id])
        self.assertEqual(usage[1]["notifications"], [sms_id])

    def test_notifications_keep_traversal_order_without_deduplication(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        first = self._notify(r1, channel="email", message="m")
        # An identical submission creates an independent record: both ids
        # show up and the count counts them one by one.
        second = self._notify(r1, channel="email", message="m")

        entry = self._usage()[0]
        self.assertEqual(entry["notifications"], [first, second])
        self.assertEqual(entry["notification_count"], 2)

    def test_channel_and_target_matching_is_case_and_whitespace_sensitive(
        self,
    ) -> None:
        r1 = self._create(DIGEST_A, "r1")
        self._notify(r1, channel="email", target="ops@example.invalid")
        self._notify(r1, channel="sms", target="Ops@example.invalid")
        self._notify(r1, channel="email", target=" ops@example.invalid")
        self._notify(r1, channel="Email", target="ops@example.invalid")
        self._notify(r1, channel=" email", target="ops@example.invalid")

        usage = {
            (item["channel"], item["target"]): item for item in self._usage()
        }
        self.assertEqual(
            set(usage),
            {
                ("email", "ops@example.invalid"),
                ("sms", "Ops@example.invalid"),
                ("email", " ops@example.invalid"),
                ("Email", "ops@example.invalid"),
                (" email", "ops@example.invalid"),
            },
        )

    def test_resources_deduplicated_in_registration_order(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        r3 = self._create(DIGEST_C, "r3")

        # Submissions arrive out of resource order; the resource list
        # still follows resource registration order, while notifications
        # follow traversal order (r1, r2, then r3).
        n_r3 = self._notify(r3, channel="email", target="shared@example.invalid")
        n_r1_a = self._notify(r1, channel="email", target="shared@example.invalid")
        n_r1_b = self._notify(r1, channel="email", target="shared@example.invalid")
        n_r2 = self._notify(r2, channel="email", target="shared@example.invalid")

        entry = self._usage()[0]
        self.assertEqual(entry["channel"], "email")
        self.assertEqual(entry["target"], "shared@example.invalid")
        self.assertEqual(entry["resources"], [r1, r2, r3])
        self.assertEqual(entry["resource_count"], 3)
        # The notification list, by contrast, is traversal order.
        self.assertEqual(
            entry["notifications"], [n_r1_a, n_r1_b, n_r2, n_r3]
        )
        self.assertEqual(entry["notification_count"], 4)

    # --- Recomputation -----------------------------------------------------

    def test_recomputes_after_new_registration(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        first = self._notify(r1, channel="email", message="one")

        entry = self._usage()[0]
        self.assertEqual(entry["notifications"], [first])
        self.assertEqual(entry["resources"], [r1])

        second = self._notify(r1, channel="sms", target="alerts@example.invalid")
        r2 = self._create(DIGEST_B, "r2")
        third = self._notify(
            r2, channel="webhook", target="other@example.invalid"
        )

        usage = self._usage()
        self.assertEqual(
            [(item["channel"], item["target"]) for item in usage],
            [
                ("email", "alerts@example.invalid"),
                ("sms", "alerts@example.invalid"),
                ("webhook", "other@example.invalid"),
            ],
        )
        self.assertEqual(usage[0]["notifications"], [first])
        self.assertEqual(usage[1]["notifications"], [second])
        self.assertEqual(usage[2]["notifications"], [third])
        self.assertEqual(usage[2]["resources"], [r2])

    def test_deregistration_shrinks_lists_and_removes_empty_pair(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        r3 = self._create(DIGEST_C, "r3")

        # r2-only pair vanishes entirely; the shared pair spans r1-r3.
        only_r2 = self._notify(
            r2, channel="webhook", target="r2-only@example.invalid"
        )
        shared_r1 = self._notify(
            r1, channel="email", target="shared@example.invalid"
        )
        shared_r2 = self._notify(
            r2, channel="webhook", target="shared@example.invalid"
        )
        shared_r3 = self._notify(
            r3, channel="email", target="shared@example.invalid"
        )

        status, _h, _b = call("DELETE", f"/resources/{r2}")
        self.assertEqual(status, "200 OK")

        usage = self._usage()
        self.assertEqual(
            [(item["channel"], item["target"]) for item in usage],
            [("email", "shared@example.invalid")],
        )
        entry = usage[0]
        self.assertNotIn(only_r2, entry["notifications"])
        self.assertNotIn(shared_r2, entry["notifications"])
        self.assertEqual(entry["notifications"], [shared_r1, shared_r3])
        self.assertEqual(entry["resources"], [r1, r3])
        self.assertEqual(entry["resource_count"], 2)
        self.assertEqual(entry["notification_count"], 2)

    def test_deregistration_redetermines_entry_positions(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        r3 = self._create(DIGEST_C, "r3")

        self._notify(r1, target="only-r1@example.invalid")
        self._notify(r2, channel="sms", target="shared@example.invalid")
        self._notify(r3, channel="sms", target="shared@example.invalid")

        self.assertEqual(
            [(item["channel"], item["target"]) for item in self._usage()],
            [
                ("email", "only-r1@example.invalid"),
                ("sms", "shared@example.invalid"),
            ],
        )

        status, _h, _b = call("DELETE", f"/resources/{r1}")
        self.assertEqual(status, "200 OK")

        # The "only-r1" pair vanishes; the shared pair takes the leading
        # slot rather than keeping the old second slot.
        usage = self._usage()
        self.assertEqual(
            [(item["channel"], item["target"]) for item in usage],
            [("sms", "shared@example.invalid")],
        )
        self.assertEqual(usage[0]["resources"], [r2, r3])

    def test_view_is_read_only(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        self._notify(r1)
        first_status, _h, first = call("GET", PATH)
        second_status, _h, second = call("GET", PATH)
        self.assertEqual(first_status, second_status)
        self.assertEqual(first, second)

    def test_existing_notification_entry_points_unchanged(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        kept = self._notify(r1, channel="email", target="a@example.invalid")
        other = self._notify(r2, channel="webhook", target="b@example.invalid")

        self._usage()
        self._usage()

        status, _h, body = call_json("GET", f"/resources/{r1}/notifications")
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            [item["id"] for item in body["notifications"]],  # type: ignore[index]
            [kept],
        )

        status, _h, body = call_json("GET", "/notifications")
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            [(item["resource_id"], item["id"]) for item in body],  # type: ignore[index]
            [(r1, kept), (r2, other)],
        )

        status, _h, body = call_json("GET", "/notification-usage")
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            [item["channel"] for item in body],  # type: ignore[index]
            ["email", "webhook"],
        )

        status, _h, body = call_json("GET", "/notification-targets")
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            [item["target"] for item in body],  # type: ignore[index]
            ["a@example.invalid", "b@example.invalid"],
        )

    # --- Errors ------------------------------------------------------------

    def test_non_get_methods_return_405_with_allow_get(self) -> None:
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            with self.subTest(method=method):
                status, headers, body = call_json(method, PATH)
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")
                allow_values = [
                    value for name, value in headers if name == "Allow"
                ]
                self.assertEqual(allow_values, ["GET"])

    def test_any_or_repeated_query_parameters_rejected(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        self._notify(r1)
        for query in ("x=1", "channel=email", "x=1&y=2", "x=1&x=2"):
            with self.subTest(query=query):
                status, _h, body = call_json("GET", PATH, query_string=query)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_non_empty_or_malformed_body_rejected(self) -> None:
        for kwargs in (
            {"body": b"{}"},
            {"body": b"not json"},
            {"body": b"", "content_length": 3},
            {"body": b"", "content_length": "abc"},
        ):
            with self.subTest(kwargs=kwargs):
                status, _h, raw = call("GET", PATH, **kwargs)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(json.loads(raw)["error"], "invalid_request")
                self.assertTrue(raw.endswith(b"\n"))

    def test_empty_body_accepted(self) -> None:
        # Omitted Content-Length, an explicit zero length and an empty
        # string (as some WSGI servers seed it) are all treated as empty.
        for kwargs in (
            {"omit_content_length": True},
            {"content_length": 0},
            {"content_length": ""},
        ):
            with self.subTest(kwargs=kwargs):
                status, _h, raw = call("GET", PATH, body=b"", **kwargs)
                self.assertEqual(status, "200 OK")
                self.assertEqual(raw, b"[]\n")

    def test_error_body_uses_existing_shape(self) -> None:
        status, _h, raw = call("GET", PATH, query_string="x=1")
        self.assertEqual(status, "400 Bad Request")
        self.assertTrue(raw.endswith(b"\n"))
        text = raw.decode("utf-8").rstrip("\n")
        decoded = json.loads(text)
        self.assertEqual(set(decoded), {"error", "message"})
        self.assertEqual(decoded["error"], "invalid_request")
        self.assertEqual(
            text,
            json.dumps(decoded, ensure_ascii=False, separators=(",", ":")),
        )


if __name__ == "__main__":
    unittest.main()
