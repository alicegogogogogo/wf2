from __future__ import annotations

import io
import json
import unittest

from provenance_api.app import application, reset_state

PATH = "/notification-usage"

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64


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


class NotificationUsageTests(unittest.TestCase):
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
        body = json.loads(raw)
        self.assertIsInstance(body, list)
        return body  # type: ignore[return-value]

    # --- Empty -------------------------------------------------------------

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

    # --- Shape -------------------------------------------------------------

    def test_one_entry_per_channel_with_six_fixed_keys_in_order(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        self._notify(r1, channel="email", target="a@example.invalid")
        self._notify(r1, channel="webhook", target="https://example.invalid/hook")

        usage = self._usage()
        self.assertEqual([entry["channel"] for entry in usage], ["email", "webhook"])
        for entry in usage:
            self.assertEqual(
                list(entry),
                [
                    "channel",
                    "notifications",
                    "notification_count",
                    "targets",
                    "resources",
                    "resource_count",
                ],
            )

    def test_key_order_visible_in_raw_body(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        self._notify(r1, target="运维群组")

        _status, _h, raw = call("GET", PATH)
        text = raw.decode("utf-8").rstrip("\n")
        # Compact UTF-8: no added whitespace and non-ASCII is not escaped.
        self.assertNotIn(" ", text)
        self.assertIn("运维群组", text)
        positions = [text.index(f'"{key}"') for key in (
            "channel",
            "notifications",
            "notification_count",
            "targets",
            "resources",
            "resource_count",
        )]
        self.assertEqual(positions, sorted(positions))

    # --- Grouping and ordering --------------------------------------------

    def test_entries_follow_first_appearance_in_registration_traversal(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")

        # Submissions happen in the opposite order: pager (on r2) is
        # recorded first, then email on r1. The traversal still visits r1
        # first, so the email entry must unfold first.
        n_pager = self._notify(r2, channel="pager", message="b")
        n_email = self._notify(r1, channel="email", message="a")

        usage = self._usage()
        self.assertEqual(
            [entry["channel"] for entry in usage], ["email", "pager"]
        )
        self.assertEqual(usage[0]["notifications"], [n_email])
        self.assertEqual(usage[0]["notification_count"], 1)
        self.assertEqual(usage[1]["notifications"], [n_pager])
        self.assertEqual(usage[1]["notification_count"], 1)

    def test_notifications_keep_submission_order_and_are_not_deduplicated(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        first = self._notify(r1, channel="email", target="a@example.invalid")
        # An identical submission is still an independent record.
        duplicate = self._notify(r1, channel="email", target="a@example.invalid")
        second = self._notify(r2, channel="email", target="b@example.invalid")

        usage = self._usage()
        self.assertEqual(len(usage), 1)
        entry = usage[0]
        self.assertEqual(entry["channel"], "email")
        self.assertEqual(
            entry["notifications"], [first, duplicate, second]
        )
        self.assertEqual(entry["notification_count"], 3)

    def test_targets_deduplicated_by_first_appearance_verbatim(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        self._notify(r1, channel="email", target="b@example.invalid")
        self._notify(r1, channel="email", target="a@example.invalid")
        # Repeated target keeps the original first-appearance slot.
        self._notify(r2, channel="email", target="b@example.invalid")
        self._notify(r2, channel="email", target="a@example.invalid")

        entry = self._usage()[0]
        self.assertEqual(
            entry["targets"], ["b@example.invalid", "a@example.invalid"]
        )

    def test_channels_and_targets_are_case_and_whitespace_sensitive(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        self._notify(r1, channel="email", target="ops@example.invalid")
        self._notify(r1, channel="Email", target="Ops@example.invalid")
        self._notify(r1, channel=" email", target=" ops@example.invalid")

        usage = self._usage()
        self.assertEqual(
            [entry["channel"] for entry in usage],
            ["email", "Email", " email"],
        )
        by_channel = {entry["channel"]: entry for entry in usage}
        self.assertEqual(by_channel["email"]["targets"], ["ops@example.invalid"])
        self.assertEqual(by_channel["Email"]["targets"], ["Ops@example.invalid"])
        self.assertEqual(
            by_channel[" email"]["targets"], [" ops@example.invalid"]
        )

    def test_resources_deduplicated_in_registration_order(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        r3 = self._create(DIGEST_C, "r3")
        # r2 and r1 submit before r3; repeated notifications on one
        # resource must list that resource only once.
        self._notify(r2, channel="email", target="b@example.invalid")
        self._notify(r3, channel="email", target="c@example.invalid")
        self._notify(r1, channel="email", target="a@example.invalid")
        self._notify(r1, channel="email", target="a2@example.invalid")

        entry = self._usage()[0]
        # The traversal is resource registration order, not submission order.
        self.assertEqual(entry["resources"], [r1, r2, r3])
        self.assertEqual(entry["resource_count"], 3)

    def test_resources_without_notifications_are_skipped_silently(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        self._create(DIGEST_B, "r2")
        self._notify(r1, channel="email")

        entry = self._usage()[0]
        self.assertEqual(entry["resources"], [r1])
        self.assertEqual(entry["resource_count"], 1)

    # --- Recomputation -----------------------------------------------------

    def test_recomputes_after_new_registration(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        first = self._notify(r1, message="one")
        self.assertEqual(
            [entry["notifications"] for entry in self._usage()], [[first]]
        )
        second = self._notify(r1, message="two")
        self.assertEqual(
            [entry["notifications"] for entry in self._usage()],
            [[first, second]],
        )

    def test_resource_deregistration_shrinks_and_removes_channels(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        r3 = self._create(DIGEST_C, "r3")
        n1 = self._notify(r1, channel="email", target="a@example.invalid")
        n2 = self._notify(r2, channel="pager", target="b@example.invalid")
        n3 = self._notify(r3, channel="email", target="c@example.invalid")

        status, _h, _b = call("DELETE", f"/resources/{r2}")
        self.assertEqual(status, "200 OK")

        usage = self._usage()
        # pager lost all its notifications and disappears altogether;
        # email keeps only r3's record and its target/resource lists.
        self.assertEqual([entry["channel"] for entry in usage], ["email"])
        entry = usage[0]
        self.assertEqual(entry["notifications"], [n1, n3])
        self.assertEqual(entry["notification_count"], 2)
        self.assertEqual(entry["targets"], ["a@example.invalid", "c@example.invalid"])
        self.assertEqual(entry["resources"], [r1, r3])
        self.assertEqual(entry["resource_count"], 2)
        # The removed notification id and resource leave no residue.
        self.assertNotIn(n2, entry["notifications"])
        self.assertNotIn(r2, entry["resources"])

    def test_entry_order_redetermined_from_remaining_records(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        self._notify(r1, channel="pager")
        self._notify(r2, channel="email")
        self.assertEqual(
            [entry["channel"] for entry in self._usage()], ["pager", "email"]
        )

        status, _h, _b = call("DELETE", f"/resources/{r1}")
        self.assertEqual(status, "200 OK")

        # With pager gone, email is redetermined as the first entry rather
        # than keeping a stale slot.
        self.assertEqual(
            [entry["channel"] for entry in self._usage()], ["email"]
        )

    def test_view_is_read_only(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        self._notify(r1)
        first_status, _h, first = call("GET", PATH)
        second_status, _h, second = call("GET", PATH)
        self.assertEqual(first_status, second_status)
        self.assertEqual(first, second)

    def test_existing_endpoints_unchanged(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        n1 = self._notify(r1, message="kept")

        self._usage()

        # The per-resource listing is untouched.
        status, _h, body = call_json(
            "GET", f"/resources/{r1}/notifications"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            [item["id"] for item in body["notifications"]],  # type: ignore[index]
            [n1],
        )
        # The flat global summary is untouched.
        status, _h, body = call_json("GET", "/notifications")
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            [item["id"] for item in body],  # type: ignore[iterable]
            [n1],
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
        for query in ("bogus=1", "x=", "channel=email", "a=1&a=2"):
            with self.subTest(query=query):
                status, _h, body = call_json("GET", PATH, query_string=query)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    def test_non_empty_body_rejected_without_reading_data(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        self._notify(r1)
        for kwargs in (
            {"body": b"{}"},
            {"body": b"", "content_length": 3},
            {"body": b"", "content_length": "abc"},
        ):
            with self.subTest(kwargs=kwargs):
                status, _h, raw = call("GET", PATH, **kwargs)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(
                    json.loads(raw)["error"], "invalid_request"
                )
                self.assertTrue(raw.endswith(b"\n"))
        # A rejected request leaves the data untouched.
        self.assertEqual(len(self._usage()), 1)

    def test_empty_body_accepted(self) -> None:
        # Omitted Content-Length, an explicit zero length and an
        # empty-string length (as some WSGI servers seed it) are all fine.
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
        # Compact separators: re-dumping with the service's separators
        # reproduces the body byte-for-byte.
        self.assertEqual(
            text,
            json.dumps(decoded, ensure_ascii=False, separators=(",", ":")),
        )


if __name__ == "__main__":
    unittest.main()
