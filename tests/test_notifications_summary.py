from __future__ import annotations

import io
import json
import unittest

from provenance_api.app import application, reset_state

PATH = "/notifications"

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


class GlobalNotificationsSummaryTests(unittest.TestCase):
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

    def _summary(self, query_string: str | None = None) -> list[dict[str, object]]:
        status, headers, raw = call("GET", PATH, query_string=query_string)
        self.assertEqual(status, "200 OK")
        self.assertIn(
            ("Content-Type", "application/json; charset=utf-8"), headers
        )
        self.assertTrue(raw.endswith(b"\n"))
        body = json.loads(raw)
        self.assertIsInstance(body, list)
        return body  # type: ignore[return-value]

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
        self.assertEqual(self._summary(), [])

    def test_record_has_resource_id_first_then_notification_fields(self) -> None:
        resource_id = self._create(DIGEST_A, "r1")
        self._notify(resource_id, message="风险等级变化")

        status, _h, raw = call("GET", PATH)
        self.assertEqual(status, "200 OK")
        text = raw.decode("utf-8").rstrip("\n")
        # Compact UTF-8: no added whitespace and non-ASCII is not escaped.
        self.assertNotIn(" ", text)
        self.assertIn("风险等级变化", text)
        self.assertLess(text.index('"resource_id"'), text.index('"id"'))
        self.assertLess(text.index('"id"'), text.index('"channel"'))
        self.assertLess(text.index('"channel"'), text.index('"target"'))
        self.assertLess(text.index('"target"'), text.index('"message"'))

    # --- Ordering ----------------------------------------------------------

    def test_groups_follow_resource_registration_order(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")

        # Notifications are submitted in the opposite group order; the
        # summary must still unfold the r1 group first.
        n_r2 = self._notify(r2, message="b")
        n_r1_first = self._notify(r1, message="one")
        n_r1_second = self._notify(r1, message="two")

        summary = self._summary()
        self.assertEqual(
            [(item["resource_id"], item["id"]) for item in summary],
            [(r1, n_r1_first), (r1, n_r1_second), (r2, n_r2)],
        )
        self.assertEqual(
            set(summary[0]),
            {"resource_id", "id", "channel", "target", "message"},
        )
        self.assertEqual(summary[0]["message"], "one")
        self.assertEqual(summary[1]["message"], "two")
        self.assertEqual(summary[2]["resource_id"], r2)

    def test_resources_without_notifications_are_skipped_silently(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        self._create(DIGEST_B, "r2")
        notification_id = self._notify(r1)

        summary = self._summary()
        self.assertEqual(
            [(item["resource_id"], item["id"]) for item in summary],
            [(r1, notification_id)],
        )

    # --- Channel filter ----------------------------------------------------

    def test_channel_filter_matches_exactly(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        keep = self._notify(r1, channel="email", message="one")
        self._notify(r1, channel="webhook", message="two")
        other = self._notify(r2, channel="email", message="three")

        summary = self._summary("channel=email")
        self.assertEqual(
            [(item["resource_id"], item["id"]) for item in summary],
            [(r1, keep), (r2, other)],
        )

    def test_channel_filter_is_case_sensitive_and_untrimmed(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        self._notify(r1, channel="email")
        self.assertEqual(self._summary("channel=Email"), [])
        self.assertEqual(self._summary("channel=EMAIL"), [])
        self.assertEqual(self._summary("channel=%20email"), [])
        self.assertEqual(self._summary("channel=email%20"), [])

    def test_channel_filter_without_hits_returns_empty_array(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        self._notify(r1, channel="email")
        status, _h, raw = call("GET", PATH, query_string="channel=pager")
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

    def test_unknown_or_repeated_or_empty_channel_rejected(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        self._notify(r1, channel="email")
        for query in (
            "bogus=1",
            "x=",
            "channel=email&bogus=1",
            "channel=email&channel=email",
            "channel=email&channel=webhook",
            "channel=",
        ):
            with self.subTest(query=query):
                status, _h, body = call_json("GET", PATH, query_string=query)
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")

    # --- Recomputation -----------------------------------------------------

    def test_recomputes_after_new_registration(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        first = self._notify(r1, message="one")
        self.assertEqual([i["id"] for i in self._summary()], [first])
        second = self._notify(r1, message="two")
        self.assertEqual([i["id"] for i in self._summary()], [first, second])

    def test_resource_deregistration_removes_its_entries_keeps_rest(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        r2 = self._create(DIGEST_B, "r2")
        r3 = self._create(DIGEST_C, "r3")
        n1 = self._notify(r1)
        n2 = self._notify(r2)
        n3 = self._notify(r3)

        status, _h, _b = call("DELETE", f"/resources/{r2}")
        self.assertEqual(status, "200 OK")

        summary = self._summary()
        self.assertEqual(
            [(item["resource_id"], item["id"]) for item in summary],
            [(r1, n1), (r3, n3)],
        )
        self.assertNotIn(
            (r2, n2), [(i["resource_id"], i["id"]) for i in summary]
        )

    def test_view_is_read_only(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        self._notify(r1)
        first_status, _h, first = call("GET", PATH)
        second_status, _h, second = call("GET", PATH)
        self.assertEqual(first_status, second_status)
        self.assertEqual(first, second)

    def test_per_resource_views_unchanged(self) -> None:
        r1 = self._create(DIGEST_A, "r1")
        notification_id = self._notify(r1, message="kept")

        # The global summary does not disturb the per-resource listing.
        self._summary()
        status, _h, body = call_json(
            "GET", f"/resources/{r1}/notifications"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            [item["id"] for item in body["notifications"]],  # type: ignore[index]
            [notification_id],
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

    def test_non_empty_body_rejected(self) -> None:
        # A declared positive length is rejected even when GET carries no body.
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

    def test_empty_body_accepted(self) -> None:
        # Omitted Content-Length and an explicit zero length are both fine.
        status, _h, raw = call("GET", PATH, omit_content_length=True)
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

        status, _h, raw = call("GET", PATH, body=b"", content_length=0)
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

        # An empty-string Content-Length (as some WSGI servers seed it) is
        # treated the same as an omitted header.
        status, _h, raw = call("GET", PATH, body=b"", content_length="")
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
