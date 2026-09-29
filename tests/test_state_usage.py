from __future__ import annotations

import hashlib
import io
import json
import os
import socket
import subprocess
import sys
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from provenance_api.app import application, reset_state

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64

PATH = "/state-usage"
REPO_ROOT = Path(__file__).resolve().parents[1]


def call(
    method: str,
    path: str,
    body: bytes | str | dict[str, object] | None = None,
    *,
    headers: dict[str, str] | None = None,
    query_string: str | None = None,
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
        "CONTENT_TYPE": "application/json",
        "wsgi.input": io.BytesIO(payload),
    }
    for key, value in (headers or {}).items():
        environ[key] = value
    if not omit_content_length:
        environ["CONTENT_LENGTH"] = (
            str(len(payload)) if content_length is None else str(content_length)
        )
    captured: dict[str, object] = {}

    def start_response(status: str, resp_headers: list[tuple[str, str]]) -> None:
        captured["status"] = status
        captured["headers"] = resp_headers

    chunks = application(environ, start_response)
    return str(captured["status"]), list(captured["headers"]), b"".join(chunks)


def call_json(
    method: str,
    path: str,
    body: bytes | str | dict[str, object] | None = None,
    **kwargs: object,
) -> tuple[str, list[tuple[str, str]], object]:
    status, resp_headers, raw = call(method, path, body, **kwargs)  # type: ignore[arg-type]
    return status, resp_headers, json.loads(raw.decode("utf-8"))


class StateUsageTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def _create(
        self,
        name: str,
        digest: str = DIGEST_A,
        *,
        category: str = "code",
    ) -> str:
        status, _h, body = call_json(
            "POST",
            "/resources",
            {"name": name, "category": category, "digest": digest},
        )
        self.assertEqual(status, "201 Created")
        return str(body["id"])  # type: ignore[index]

    def _create_releasable(
        self, name: str, *, category: str = "code", data: bytes | None = None
    ) -> tuple[str, str, bytes]:
        """Register a resource whose digest matches its assembled content."""

        content = data if data is not None else b"content-for-" + name.encode()
        digest = hashlib.sha256(content).hexdigest()
        resource_id = self._create(name, digest, category=category)
        return resource_id, digest, content

    def _transition(
        self, resource_id: str, state: str, reason: str | None = None
    ) -> None:
        payload: dict[str, object] = {"state": state}
        if reason is not None:
            payload["reason"] = reason
        status, _h, body = call_json(
            "POST", f"/resources/{resource_id}/lifecycle", payload
        )
        self.assertEqual(status, "200 OK", body)

    def _assemble_single_chunk(self, resource_id: str, data: bytes) -> None:
        digest = hashlib.sha256(data).hexdigest()
        chunk_headers = {
            "CONTENT_TYPE": "application/octet-stream",
            "HTTP_X_TOTAL_CHUNKS": "1",
            "HTTP_X_CONTENT_DIGEST": digest,
        }
        status, _h, body = call(
            "POST",
            f"/resources/{resource_id}/chunks/0",
            data,
            headers=chunk_headers,
        )
        self.assertEqual(status, "201 Created", body)
        status, _h, body = call_json(
            "POST", f"/resources/{resource_id}/assemble"
        )
        self.assertEqual(status, "201 Created", body)

    def _release(self, resource_id: str, data: bytes) -> None:
        self._assemble_single_chunk(resource_id, data)
        self._transition(resource_id, "released")

    def _usage(self, **kwargs: object):
        return call("GET", PATH, **kwargs)

    def _usage_json(self, body: object = None, **kwargs: object):
        status, resp_headers, parsed = call_json("GET", PATH, body, **kwargs)
        return status, resp_headers, parsed

    # --- Empty registry ------------------------------------------------------

    def test_empty_registry_is_empty_array_success(self) -> None:
        status, headers, raw = self._usage()
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            headers[0], ("Content-Type", "application/json; charset=utf-8")
        )
        self.assertEqual(raw, b"[]\n")

    # --- Entry shape and ordering -------------------------------------------

    def test_one_entry_per_state_in_first_appearance_order(self) -> None:
        # New resources default to staged; the first quarantined resource
        # introduces the second entry; entries must follow first
        # appearance in registration order, never the fixed state order.
        s1 = self._create("s-one", DIGEST_A)
        q1 = self._create("q-one", DIGEST_B)
        s2 = self._create("s-two", DIGEST_C)
        self._transition(q1, "quarantined", reason="suspect")

        _s, _h, body = self._usage_json()
        self.assertEqual(  # type: ignore[index]
            [entry["state"] for entry in body], ["staged", "quarantined"]
        )
        entries = {  # type: ignore[union-attr]
            entry["state"]: entry for entry in body
        }
        self.assertEqual(entries["staged"]["resources"], [s1, s2])
        self.assertEqual(entries["staged"]["resource_count"], 2)
        self.assertEqual(entries["staged"]["names"], ["s-one", "s-two"])
        self.assertEqual(entries["staged"]["digests"], [DIGEST_A, DIGEST_C])
        self.assertEqual(entries["quarantined"]["resources"], [q1])
        self.assertEqual(entries["quarantined"]["resource_count"], 1)
        self.assertEqual(entries["quarantined"]["names"], ["q-one"])
        self.assertEqual(entries["quarantined"]["digests"], [DIGEST_B])

    def test_entry_key_order_is_fixed(self) -> None:
        self._create("a")
        released, _d, data = self._create_releasable("b")
        self._release(released, data)
        _s, _h, body = self._usage_json()
        for entry in body:  # type: ignore[union-attr]
            self.assertEqual(
                list(entry),
                [
                    "state",
                    "resources",
                    "resource_count",
                    "names",
                    "digests",
                ],
            )

    def test_state_is_echoed_lowercase_verbatim(self) -> None:
        self._create("a")
        q = self._create("b", DIGEST_B)
        self._transition(q, "quarantined", reason="why")
        w, _d, data = self._create_releasable("c")
        self._release(w, data)
        self._transition(w, "withdrawn", reason="recall")
        _s, _h, body = self._usage_json()
        self.assertEqual(  # type: ignore[index]
            [entry["state"] for entry in body],
            ["staged", "quarantined", "withdrawn"],
        )
        for entry in body:  # type: ignore[union-attr]
            self.assertEqual(entry["state"], entry["state"].lower())

    def test_names_deduplicated_but_case_and_whitespace_preserved(self) -> None:
        # The same exact name on two staged resources appears once; a
        # case- or whitespace-only variant stays a separate entry.
        one = self._create("Model", DIGEST_A)
        two = self._create("Model", DIGEST_B)
        three = self._create(" model ", DIGEST_C)

        _s, _h, body = self._usage_json()
        entry = body[0]  # type: ignore[index]
        self.assertEqual(entry["state"], "staged")
        self.assertEqual(entry["resources"], [one, two, three])
        self.assertEqual(entry["resource_count"], 3)
        self.assertEqual(entry["names"], ["Model", " model "])
        self.assertEqual(entry["digests"], [DIGEST_A, DIGEST_B, DIGEST_C])

    def test_digests_deduplicated_and_lowercased_in_first_appearance_order(
        self,
    ) -> None:
        first = self._create("one", DIGEST_A)
        second = self._create("two", "A" * 64)
        third = self._create("three", DIGEST_B)

        _s, _h, body = self._usage_json()
        entry = body[0]  # type: ignore[index]
        self.assertEqual(entry["resources"], [first, second, third])
        self.assertEqual(entry["resource_count"], 3)
        self.assertEqual(entry["names"], ["one", "two", "three"])
        self.assertEqual(entry["digests"], [DIGEST_A, DIGEST_B])

    def test_resource_count_matches_resources_length(self) -> None:
        self._create("a1", DIGEST_A)
        q = self._create("a2", DIGEST_B)
        self._transition(q, "quarantined", reason="r")
        r, _d, data = self._create_releasable("a3")
        self._release(r, data)
        _s, _h, body = self._usage_json()
        for entry in body:  # type: ignore[union-attr]
            self.assertEqual(
                entry["resource_count"], len(entry["resources"])
            )

    # --- Recomputation after transitions, registration, deletion ------------

    def test_recompute_after_registration(self) -> None:
        a = self._create("a", DIGEST_A)
        _s, _h, body = self._usage_json()
        self.assertEqual(  # type: ignore[index]
            [entry["state"] for entry in body], ["staged"]
        )

        a2 = self._create("a2", DIGEST_B)
        b, _d, data = self._create_releasable("b")
        self._release(b, data)

        _s, _h, body = self._usage_json()
        self.assertEqual(  # type: ignore[index]
            [entry["state"] for entry in body], ["staged", "released"]
        )
        entries = {  # type: ignore[union-attr]
            entry["state"]: entry for entry in body
        }
        self.assertEqual(entries["staged"]["resources"], [a, a2])
        self.assertEqual(entries["staged"]["names"], ["a", "a2"])
        self.assertEqual(entries["staged"]["digests"], [DIGEST_A, DIGEST_B])
        self.assertEqual(entries["released"]["resources"], [b])

    def test_transition_migrates_resource_between_entries(self) -> None:
        r1 = self._create("r1", DIGEST_A)
        r2, _d, r2_data = self._create_releasable("r2")
        self._transition(r1, "quarantined", reason="hold")

        _s, _h, body = self._usage_json()
        self.assertEqual(  # type: ignore[index]
            [entry["state"] for entry in body], ["quarantined", "staged"]
        )
        entries = {  # type: ignore[union-attr]
            entry["state"]: entry for entry in body
        }
        self.assertEqual(entries["quarantined"]["resources"], [r1])
        self.assertEqual(entries["staged"]["resources"], [r2])

        # Moving the only staged resource away drops the staged entry.
        # Withdrawn is reachable only through released.
        self._release(r2, r2_data)
        self._transition(r2, "withdrawn", reason="recall")
        _s, _h, body = self._usage_json()
        self.assertEqual(  # type: ignore[index]
            [entry["state"] for entry in body],
            ["quarantined", "withdrawn"],
        )
        self.assertNotIn(
            "staged", [entry["state"] for entry in body]
        )

        # A transition back restores the resource to staged; first
        # appearance order is redetermined from registration order, so
        # staged takes the front position again.
        self._transition(r1, "staged")
        _s, _h, body = self._usage_json()
        self.assertEqual(  # type: ignore[index]
            [entry["state"] for entry in body], ["staged", "withdrawn"]
        )
        entries = {  # type: ignore[union-attr]
            entry["state"]: entry for entry in body
        }
        self.assertEqual(entries["staged"]["resources"], [r1])
        self.assertEqual(entries["staged"]["names"], ["r1"])
        self.assertEqual(entries["staged"]["digests"], [DIGEST_A])
        self.assertEqual(entries["withdrawn"]["resources"], [r2])

    def test_entry_disappears_when_state_loses_every_resource(self) -> None:
        a = self._create("a", DIGEST_A)
        b, _d, data = self._create_releasable("b")
        self._release(b, data)

        status, _h, _raw = call("DELETE", f"/resources/{b}")
        self.assertEqual(status, "200 OK")

        _s, _h, body = self._usage_json()
        self.assertEqual(  # type: ignore[index]
            [entry["state"] for entry in body], ["staged"]
        )
        self.assertEqual(body[0]["resources"], [a])  # type: ignore[index]

    def test_delete_first_resource_redetermines_entry_order(self) -> None:
        # r1 is staged at registration position 1, r2 quarantined at
        # position 2, r3 staged at position 3. Deleting r1 makes
        # quarantined the earliest surviving state, so its entry moves to
        # the front rather than keeping a stale slot.
        first_staged = self._create("a-one", DIGEST_A)
        q = self._create("b-one", DIGEST_B)
        self._transition(q, "quarantined", reason="hold")
        second_staged = self._create("a-two", DIGEST_C)

        status, _h, _raw = call("DELETE", f"/resources/{first_staged}")
        self.assertEqual(status, "200 OK")

        _s, _h, body = self._usage_json()
        self.assertEqual(  # type: ignore[index]
            [entry["state"] for entry in body], ["quarantined", "staged"]
        )
        self.assertEqual(body[0]["resources"], [q])  # type: ignore[index]
        staged_entry = body[1]  # type: ignore[index]
        self.assertEqual(staged_entry["resources"], [second_staged])
        self.assertEqual(staged_entry["resource_count"], 1)
        self.assertEqual(staged_entry["names"], ["a-two"])
        self.assertEqual(staged_entry["digests"], [DIGEST_C])

    def test_names_and_digests_shrink_with_transition_and_deletion(self) -> None:
        only = self._create("only", DIGEST_A)
        other = self._create("other", DIGEST_B)

        # Moving ``only`` away leaves the staged group with just ``other``.
        self._transition(only, "quarantined", reason="hold")
        _s, _h, body = self._usage_json()
        staged = next(  # type: ignore[union-attr]
            entry for entry in body if entry["state"] == "staged"
        )
        self.assertEqual(staged["resources"], [other])
        self.assertEqual(staged["names"], ["other"])
        self.assertEqual(staged["digests"], [DIGEST_B])

        # Deleting the moved resource shrinks the quarantined group too.
        status, _h, _raw = call("DELETE", f"/resources/{only}")
        self.assertEqual(status, "200 OK")
        _s, _h, body = self._usage_json()
        self.assertEqual(  # type: ignore[index]
            [entry["state"] for entry in body], ["staged"]
        )

    def test_view_is_read_only(self) -> None:
        self._create("a", DIGEST_A)
        q = self._create("b", DIGEST_B)
        self._transition(q, "quarantined", reason="hold")

        self._usage()
        self._usage()

        _s, _h, listing = call_json("GET", "/resources")
        self.assertEqual(len(listing["resources"]), 2)  # type: ignore[index]
        _s, _h, lifecycle = call_json("GET", "/lifecycle")
        self.assertEqual(len(lifecycle), 2)  # type: ignore[arg-type]
        _s, _h, body = self._usage_json()
        self.assertEqual(len(body), 2)  # type: ignore[arg-type]

    def test_existing_views_are_unchanged(self) -> None:
        a = self._create("a", DIGEST_A, category="code")
        self._create("a", DIGEST_B, category="model")
        self._create("b", DIGEST_A, category="dataset")

        _s, _h, lifecycle = call_json("GET", "/lifecycle")
        self.assertEqual(  # type: ignore[union-attr]
            [entry["id"] for entry in lifecycle],
            [resource["id"] for resource in _listing_ids()],
        )
        for entry in lifecycle:  # type: ignore[union-attr]
            self.assertEqual(list(entry), ["id", "state", "reason"])

        _s, _h, category_body = call_json("GET", "/category-usage")
        self.assertEqual(  # type: ignore[index]
            [entry["category"] for entry in category_body],
            ["code", "model", "dataset"],
        )
        for entry in category_body:  # type: ignore[union-attr]
            self.assertEqual(
                list(entry),
                ["category", "resources", "resource_count", "names", "digests"],
            )

        _s, _h, digest_body = call_json("GET", "/digest-usage")
        for entry in digest_body:  # type: ignore[union-attr]
            self.assertEqual(
                list(entry),
                ["digest", "resources", "resource_count", "names"],
            )

        _s, _h, name_body = call_json("GET", "/name-usage")
        for entry in name_body:  # type: ignore[union-attr]
            self.assertEqual(
                list(entry),
                ["name", "resources", "resource_count", "digests", "categories"],
            )

        _s, _h, source_body = call_json("GET", "/source-usage")
        for entry in source_body:  # type: ignore[union-attr]
            self.assertEqual(
                list(entry),
                ["source", "resources", "resource_count", "names", "categories"],
            )

        # The state-usage view itself reports all three resources as staged.
        _s, _h, state_body = self._usage_json()
        self.assertEqual(len(state_body), 1)  # type: ignore[arg-type]
        self.assertEqual(state_body[0]["state"], "staged")  # type: ignore[index]
        self.assertEqual(state_body[0]["resource_count"], 3)  # type: ignore[index]
        self.assertIn(a, state_body[0]["resources"])  # type: ignore[index]

    # --- Response body -------------------------------------------------------

    def test_body_is_compact_json_with_single_trailing_newline(self) -> None:
        rid = self._create("a", DIGEST_A)
        _s, _h, raw = self._usage()
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        self.assertEqual(
            raw,
            b'[{"state":"staged","resources":["'
            + rid.encode("ascii")
            + b'"],"resource_count":1,"names":["a"],"digests":["'
            + DIGEST_A.encode("ascii")
            + b'"]}]\n',
        )

    def test_non_ascii_name_is_utf8_encoded(self) -> None:
        rid = self._create("状态-α", DIGEST_A)
        _s, _h, raw = self._usage()
        expected_name = "状态-α".encode("utf-8")
        self.assertEqual(
            raw,
            b'[{"state":"staged","resources":["'
            + rid.encode("ascii")
            + b'"],"resource_count":1,"names":["'
            + expected_name
            + b'"],"digests":["'
            + DIGEST_A.encode("ascii")
            + b'"]}]\n',
        )

    def test_no_persistence_files_created(self) -> None:
        before = {
            str(p.relative_to(REPO_ROOT))
            for p in REPO_ROOT.rglob("*")
            if ".git" not in p.parts and p.is_file()
        }
        self._create("a", DIGEST_A)
        self._usage()
        after = {
            str(p.relative_to(REPO_ROOT))
            for p in REPO_ROOT.rglob("*")
            if ".git" not in p.parts and p.is_file()
        }
        self.assertEqual(before, after)

    # --- Validation ----------------------------------------------------------

    def test_query_parameters_are_bad_request(self) -> None:
        self._create("a", DIGEST_A)
        for query_string in (
            "bogus=1",
            "=",
            "x=&y=2",
            "x=1&x=2",
            "state=staged",
            "foo",
        ):
            with self.subTest(query_string=query_string):
                status, _h, body = call_json(
                    "GET", PATH, query_string=query_string
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(body["error"], "invalid_request")  # type: ignore[index]

    def test_declared_non_empty_body_is_bad_request(self) -> None:
        self._create("a", DIGEST_A)
        status, _h, body = call_json("GET", PATH, b"{}")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")  # type: ignore[index]

        # The rejected request changed nothing.
        _s, _h, usage = self._usage_json()
        self.assertEqual(len(usage), 1)  # type: ignore[arg-type]

    def test_malformed_content_length_is_bad_request(self) -> None:
        status, _h, body = call_json("GET", PATH, content_length="abc")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(body["error"], "invalid_request")  # type: ignore[index]

    def test_bad_request_does_not_read_business_data(self) -> None:
        self._create("a", DIGEST_A)
        status, _h, _raw = call("GET", PATH, b'{"not": "consumed"}')
        self.assertEqual(status, "400 Bad Request")

    def test_omitted_length_header_is_accepted(self) -> None:
        status, _h, raw = self._usage(omit_content_length=True)
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

    def test_explicit_zero_length_body_is_accepted(self) -> None:
        self._create("a", DIGEST_A)
        status, _h, body = self._usage_json(b"")
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(body), 1)  # type: ignore[arg-type]

    # --- Method handling -----------------------------------------------------

    def test_other_methods_return_405_with_allow_get(self) -> None:
        for method in ("POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
            with self.subTest(method=method):
                status, headers, body = call_json(method, PATH)
                self.assertEqual(status, "405 Method Not Allowed")
                self.assertEqual(body["error"], "method_not_allowed")  # type: ignore[index]
                self.assertEqual(
                    [value for name, value in headers if name == "Allow"],
                    ["GET"],
                )

    def test_non_get_method_with_query_and_body_still_returns_405(self) -> None:
        status, headers, body = call_json(
            "DELETE", PATH, query_string="x=1"
        )
        self.assertEqual(status, "405 Method Not Allowed")
        self.assertEqual(body["error"], "method_not_allowed")  # type: ignore[index]
        self.assertEqual(
            [value for name, value in headers if name == "Allow"], ["GET"]
        )

    def test_subpath_is_not_the_usage_view(self) -> None:
        status, _h, body = call_json("GET", PATH + "/anything")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(body["error"], "not_found")  # type: ignore[index]


def _listing_ids() -> list[dict[str, object]]:
    status, _h, body = call_json("GET", "/resources")
    assert status == "200 OK"
    return body["resources"]  # type: ignore[return-value]


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


class StateUsageRestartTests(unittest.TestCase):
    """Spin up real server processes to prove restart clears the data.

    The state-usage view is computed purely from process memory: data
    registered in one process must not survive that process exiting, and
    a freshly started process must answer the view with an empty array.
    """

    def _start_server(self) -> tuple[subprocess.Popen[bytes], int]:
        port = _free_port()
        env = dict(os.environ)
        repo_root = str(REPO_ROOT)
        env["PYTHONPATH"] = (
            repo_root + os.pathsep + env["PYTHONPATH"]
            if env.get("PYTHONPATH")
            else repo_root
        )
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "provenance_api",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
            ],
            cwd=repo_root,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            self._wait_until_ready(port, proc)
        except Exception:
            proc.terminate()
            proc.wait(timeout=10)
            raise
        return proc, port

    def _wait_until_ready(
        self, port: int, proc: subprocess.Popen[bytes], timeout: float = 10.0
    ) -> None:
        deadline = time.monotonic() + timeout
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError("server process exited before becoming ready")
            try:
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/health", timeout=0.5
                ) as response:
                    if response.status == 200:
                        return
            except (urllib.error.URLError, ConnectionError, OSError) as exc:
                last_error = exc
            time.sleep(0.05)
        raise RuntimeError(f"server did not become ready: {last_error}")

    @staticmethod
    def _request(
        port: int,
        method: str,
        path: str,
        payload: bytes = b"",
        headers: dict[str, str] | None = None,
    ) -> tuple[int, bytes]:
        request = urllib.request.Request(  # noqa: S310 - loopback test server
            f"http://127.0.0.1:{port}{path}",
            data=payload if payload else None,
            method=method,
            headers=headers or {},
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    @staticmethod
    def _stop(proc: subprocess.Popen[bytes]) -> None:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)

    def test_state_usage_resets_across_a_real_process_restart(self) -> None:
        # First process: register a resource, finish and assemble a
        # single chunk (required for promotion) and move it to released
        # so the view carries a non-default state.
        proc, port = self._start_server()
        try:
            data = b"restart-probe"
            digest = hashlib.sha256(data).hexdigest()
            status, raw = self._request(
                port,
                "POST",
                "/resources",
                json.dumps(
                    {
                        "name": "restart-probe",
                        "category": "artifact",
                        "digest": digest,
                    }
                ).encode("utf-8"),
                {"Content-Type": "application/json"},
            )
            self.assertEqual(status, 201, raw)
            resource_id = str(json.loads(raw)["id"])

            status, raw = self._request(
                port,
                "POST",
                f"/resources/{resource_id}/chunks/0",
                data,
                {
                    "Content-Type": "application/octet-stream",
                    "X-Total-Chunks": "1",
                    "X-Content-Digest": digest,
                },
            )
            self.assertEqual(status, 201, raw)
            status, raw = self._request(
                port, "POST", f"/resources/{resource_id}/assemble"
            )
            self.assertEqual(status, 201, raw)
            status, raw = self._request(
                port,
                "POST",
                f"/resources/{resource_id}/lifecycle",
                json.dumps({"state": "released"}).encode("utf-8"),
                {"Content-Type": "application/json"},
            )
            self.assertEqual(status, 200, raw)

            status, raw = self._request(port, "GET", PATH)
            self.assertEqual(status, 200)
            self.assertTrue(raw.endswith(b"\n"))
            self.assertFalse(raw.endswith(b"\n\n"))
            body = json.loads(raw.decode("utf-8"))
            self.assertEqual(len(body), 1)
            self.assertEqual(body[0]["state"], "released")
            self.assertEqual(body[0]["resources"], [resource_id])
            self.assertEqual(body[0]["resource_count"], 1)
        finally:
            self._stop(proc)

        # A brand new process starts from empty memory: the same view is
        # an empty-array success response, with no trace of the previous
        # process's resource or lifecycle state.
        proc, port = self._start_server()
        try:
            status, raw = self._request(port, "GET", PATH)
            self.assertEqual(status, 200)
            self.assertEqual(raw, b"[]\n")
        finally:
            self._stop(proc)


if __name__ == "__main__":
    unittest.main()
