from __future__ import annotations

import hashlib
import http.client
import io
import json
import os
import pathlib
import subprocess
import sys
import time
import unittest

from provenance_api.app import (
    application,
    lifecycle_store,
    reset_state,
)

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_DATA = hashlib.sha256(b"data").hexdigest()
DIGEST_OTHER = hashlib.sha256(b"other").hexdigest()

PATH = "/state-usage"


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
        "wsgi.input": io.BytesIO(payload),
    }
    for key, value in (headers or {}).items():
        environ[key] = value
    if not omit_content_length:
        environ["CONTENT_LENGTH"] = (
            str(len(payload)) if content_length is None else str(content_length)
        )
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
    **kwargs: object,
) -> tuple[str, list[tuple[str, str]], object]:
    status, headers, raw = call(method, path, body, **kwargs)  # type: ignore[arg-type]
    return status, headers, json.loads(raw.decode("utf-8"))


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

    def _assemble(self, resource_id: str, data: bytes = b"data") -> None:
        digest = hashlib.sha256(data).hexdigest()
        headers = {
            "CONTENT_TYPE": "application/octet-stream",
            "HTTP_X_TOTAL_CHUNKS": "1",
            "HTTP_X_CONTENT_DIGEST": digest,
        }
        status, _h, body = call(
            "POST", f"/resources/{resource_id}/chunks/0", data, headers=headers
        )
        self.assertEqual(status, "201 Created", body)
        status, _h, body = call_json(
            "POST", f"/resources/{resource_id}/assemble"
        )
        self.assertEqual(status, "201 Created", body)

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

    def _release(self, resource_id: str) -> None:
        self._assemble(resource_id)
        self._transition(resource_id, "released")

    def _usage(self, **kwargs: object):
        return call("GET", PATH, **kwargs)

    def _usage_json(self, body: object = None, **kwargs: object):
        status, headers, parsed = call_json("GET", PATH, body, **kwargs)
        return status, headers, parsed

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
        # The first resource leaves staged immediately, so quarantined
        # appears before staged in registration-order walk; the result
        # must follow [quarantined, staged], never the fixed state order.
        q1 = self._create("q-one", DIGEST_B)
        self._transition(q1, "quarantined", "suspect")
        s1 = self._create("s-one", DIGEST_A)

        _s, _h, body = self._usage_json()
        self.assertEqual(  # type: ignore[index]
            [entry["state"] for entry in body], ["quarantined", "staged"]
        )
        entries = {  # type: ignore[union-attr]
            entry["state"]: entry for entry in body
        }
        self.assertEqual(entries["quarantined"]["resources"], [q1])
        self.assertEqual(entries["quarantined"]["resource_count"], 1)
        self.assertEqual(entries["quarantined"]["names"], ["q-one"])
        self.assertEqual(entries["quarantined"]["digests"], [DIGEST_B])
        self.assertEqual(entries["staged"]["resources"], [s1])
        self.assertEqual(entries["staged"]["resource_count"], 1)
        self.assertEqual(entries["staged"]["names"], ["s-one"])
        self.assertEqual(entries["staged"]["digests"], [DIGEST_A])

    def test_all_four_states_in_first_appearance_not_fixed_order(self) -> None:
        # Build an appearance order deliberately different from the fixed
        # staged/released/withdrawn/quarantined sequence:
        # quarantined, released, withdrawn, staged.
        q1 = self._create("q", DIGEST_A, category="artifact")
        self._transition(q1, "quarantined", "suspect")

        r1 = self._create("rel", DIGEST_DATA, category="model")
        self._release(r1)

        w1 = self._create("w", DIGEST_DATA, category="dataset")
        self._release(w1)
        self._transition(w1, "withdrawn", "obsolete")

        s1 = self._create("s", DIGEST_B, category="code")

        _s, _h, body = self._usage_json()
        self.assertEqual(  # type: ignore[index]
            [entry["state"] for entry in body],
            ["quarantined", "released", "withdrawn", "staged"],
        )
        entries = {  # type: ignore[union-attr]
            entry["state"]: entry for entry in body
        }
        self.assertEqual(entries["quarantined"]["resources"], [q1])
        self.assertEqual(entries["released"]["resources"], [r1])
        self.assertEqual(entries["withdrawn"]["resources"], [w1])
        self.assertEqual(entries["staged"]["resources"], [s1])

    def test_entry_key_order_is_fixed(self) -> None:
        self._create("a")
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

    def test_state_is_echoed_as_lowercase_verbatim(self) -> None:
        rid = self._create("a", DIGEST_DATA)
        self._release(rid)
        _s, _h, body = self._usage_json()
        self.assertEqual(  # type: ignore[index]
            [entry["state"] for entry in body], ["released"]
        )

    def test_names_deduplicated_but_case_and_whitespace_preserved(self) -> None:
        # All three stay staged, i.e. in the same state group: the exact
        # name appears once, but case and surrounding whitespace matter.
        one = self._create("Model", DIGEST_A, category="model")
        two = self._create("Model", DIGEST_B, category="model")
        three = self._create("model", DIGEST_C, category="model")

        _s, _h, body = self._usage_json()
        entry = body[0]  # type: ignore[index]
        self.assertEqual(entry["state"], "staged")
        self.assertEqual(entry["resources"], [one, two, three])
        self.assertEqual(entry["resource_count"], 3)
        self.assertEqual(entry["names"], ["Model", "model"])
        self.assertEqual(entry["digests"], [DIGEST_A, DIGEST_B, DIGEST_C])

    def test_digests_deduplicated_and_lowercased_in_first_appearance_order(
        self,
    ) -> None:
        # The same digest submitted once lowercase and once uppercase
        # creates two resources (different names) in the same state; the
        # digest appears once, in lowercase.
        first = self._create("one", DIGEST_A, category="dataset")
        second = self._create("two", "A" * 64, category="dataset")
        third = self._create("three", DIGEST_B, category="dataset")

        _s, _h, body = self._usage_json()
        entry = body[0]  # type: ignore[index]
        self.assertEqual(entry["resources"], [first, second, third])
        self.assertEqual(entry["resource_count"], 3)
        self.assertEqual(entry["names"], ["one", "two", "three"])
        self.assertEqual(entry["digests"], [DIGEST_A, DIGEST_B])

    def test_resource_count_matches_resources_length(self) -> None:
        q1 = self._create("q1", DIGEST_A)
        self._transition(q1, "quarantined", "suspect")
        self._create("s1", DIGEST_B, category="model")
        self._create("s2", DIGEST_C, category="dataset")
        _s, _h, body = self._usage_json()
        for entry in body:  # type: ignore[union-attr]
            self.assertEqual(
                entry["resource_count"], len(entry["resources"])
            )

    # --- Recomputation after submissions, transitions, deregistration --------

    def test_recompute_after_registration(self) -> None:
        a = self._create("a")
        _s, _h, body = self._usage_json()
        self.assertEqual(  # type: ignore[index]
            [entry["state"] for entry in body], ["staged"]
        )

        # A new resource in the same default state extends that group.
        a2 = self._create("a2", DIGEST_B)
        _s, _h, body = self._usage_json()
        entries = {  # type: ignore[union-attr]
            entry["state"]: entry for entry in body
        }
        self.assertEqual(list(entries), ["staged"])
        self.assertEqual(entries["staged"]["resources"], [a, a2])

    def test_state_transition_migrates_resource_between_entries(self) -> None:
        r1 = self._create("r1", DIGEST_DATA, category="model")
        r2 = self._create("r2")

        # Both start in the single staged entry.
        _s, _h, body = self._usage_json()
        self.assertEqual(len(body), 1)  # type: ignore[arg-type]
        self.assertEqual(body[0]["state"], "staged")  # type: ignore[index]
        self.assertEqual(body[0]["resources"], [r1, r2])  # type: ignore[index]

        # r1 moves to released; both entries now exist.
        self._release(r1)
        _s, _h, body = self._usage_json()
        self.assertEqual(  # type: ignore[index]
            [entry["state"] for entry in body], ["released", "staged"]
        )
        entries = {  # type: ignore[union-attr]
            entry["state"]: entry for entry in body
        }
        self.assertEqual(entries["released"]["resources"], [r1])
        self.assertEqual(entries["staged"]["resources"], [r2])

        # r2 moves staged -> quarantined; the staged entry disappears
        # altogether because it no longer holds any resource.
        self._transition(r2, "quarantined", "suspect")
        _s, _h, body = self._usage_json()
        self.assertEqual(  # type: ignore[index]
            [entry["state"] for entry in body], ["released", "quarantined"]
        )
        entries = {  # type: ignore[union-attr]
            entry["state"]: entry for entry in body
        }
        self.assertEqual(entries["released"]["resources"], [r1])
        self.assertEqual(entries["quarantined"]["resources"], [r2])

        # r2 returns to staged; its entry comes back, positioned after
        # released by first appearance in registration order.
        self._transition(r2, "staged")
        _s, _h, body = self._usage_json()
        self.assertEqual(  # type: ignore[index]
            [entry["state"] for entry in body], ["released", "staged"]
        )
        entries = {  # type: ignore[union-attr]
            entry["state"]: entry for entry in body
        }
        self.assertEqual(entries["staged"]["resources"], [r2])

    def test_entry_disappears_when_state_loses_every_resource(self) -> None:
        q = self._create("q", DIGEST_A)
        self._transition(q, "quarantined", "suspect")
        s = self._create("s", DIGEST_B)

        status, _h, _raw = call("DELETE", f"/resources/{q}")
        self.assertEqual(status, "200 OK")

        _s, _h, body = self._usage_json()
        self.assertEqual(  # type: ignore[index]
            [entry["state"] for entry in body], ["staged"]
        )
        self.assertEqual(body[0]["resources"], [s])  # type: ignore[index]

    def test_transitions_redetermine_first_appearance_order(self) -> None:
        # r1 quarantined first, r2 staged, r3 released: order is
        # [quarantined, staged, released], not the fixed state order.
        r1 = self._create("r1", DIGEST_A)
        self._transition(r1, "quarantined", "suspect")
        r2 = self._create("r2", DIGEST_B)
        r3 = self._create("r3", DIGEST_DATA, category="model")
        self._release(r3)

        _s, _h, body = self._usage_json()
        self.assertEqual(  # type: ignore[index]
            [entry["state"] for entry in body],
            ["quarantined", "staged", "released"],
        )

        # r1 returns to staged: walk is now r1 staged, r2 staged,
        # r3 released, so the quarantined entry vanishes and staged
        # leads.
        self._transition(r1, "staged")
        _s, _h, body = self._usage_json()
        self.assertEqual(  # type: ignore[index]
            [entry["state"] for entry in body], ["staged", "released"]
        )
        entries = {  # type: ignore[union-attr]
            entry["state"]: entry for entry in body
        }
        self.assertEqual(entries["staged"]["resources"], [r1, r2])
        self.assertEqual(entries["released"]["resources"], [r3])

    def test_delete_first_resource_redetermines_entry_order(self) -> None:
        # released holds registration positions 1 and 3, staged position
        # 2. Deleting the first released resource redetermines order
        # from the remaining registry: staged is now earlier than the
        # surviving released resource.
        first_released = self._create("a-one", DIGEST_DATA, category="code")
        self._release(first_released)
        staged = self._create("b-one", DIGEST_B, category="model")
        second_released = self._create(
            "a-two", DIGEST_DATA, category="dataset"
        )
        self._release(second_released)

        status, _h, _raw = call("DELETE", f"/resources/{first_released}")
        self.assertEqual(status, "200 OK")

        _s, _h, body = self._usage_json()
        self.assertEqual(  # type: ignore[index]
            [entry["state"] for entry in body], ["staged", "released"]
        )
        self.assertEqual(body[0]["resources"], [staged])  # type: ignore[index]
        entry_released = body[1]  # type: ignore[index]
        self.assertEqual(entry_released["resources"], [second_released])
        self.assertEqual(entry_released["resource_count"], 1)
        self.assertEqual(entry_released["names"], ["a-two"])
        self.assertEqual(entry_released["digests"], [DIGEST_DATA])

    def test_names_and_digests_shrink_with_moved_and_deleted_resources(
        self,
    ) -> None:
        # staged carries "only"/DIGEST_A and "other"/DIGEST_B; moving the
        # first resource away shrinks the staged group's lists.
        first = self._create("only", DIGEST_A)
        second = self._create("other", DIGEST_B)
        self._transition(first, "quarantined", "suspect")

        _s, _h, body = self._usage_json()
        entries = {  # type: ignore[union-attr]
            entry["state"]: entry for entry in body
        }
        self.assertEqual(entries["staged"]["resources"], [second])
        self.assertEqual(entries["staged"]["names"], ["other"])
        self.assertEqual(entries["staged"]["digests"], [DIGEST_B])
        self.assertEqual(entries["quarantined"]["resources"], [first])
        self.assertEqual(entries["quarantined"]["names"], ["only"])
        self.assertEqual(entries["quarantined"]["digests"], [DIGEST_A])

        status, _h, _raw = call("DELETE", f"/resources/{first}")
        self.assertEqual(status, "200 OK")

        _s, _h, body = self._usage_json()
        self.assertEqual(  # type: ignore[index]
            [entry["state"] for entry in body], ["staged"]
        )

    # --- Read-only behavior --------------------------------------------------

    def test_view_is_read_only_and_materializes_no_records(self) -> None:
        self._create("a")
        self._create("b", DIGEST_B)

        self._usage()
        self._usage()

        # Default staged resources are grouped without storing a record.
        self.assertEqual(lifecycle_store._records, {})

        _s, _h, listing = call_json("GET", "/resources")
        self.assertEqual(len(listing["resources"]), 2)  # type: ignore[index]
        _s, _h, body = self._usage_json()
        self.assertEqual(len(body), 1)  # type: ignore[arg-type]

    def test_existing_usage_views_are_unchanged(self) -> None:
        self._create("a", DIGEST_A, category="code")
        self._create("a", DIGEST_B, category="model")
        self._create("b", DIGEST_A, category="dataset")

        _s, _h, category_body = call_json("GET", "/category-usage")
        self.assertEqual(  # type: ignore[index]
            [entry["category"] for entry in category_body],
            ["code", "model", "dataset"],
        )
        for entry in category_body:  # type: ignore[union-attr]
            self.assertEqual(
                list(entry),
                [
                    "category",
                    "resources",
                    "resource_count",
                    "names",
                    "digests",
                ],
            )

        _s, _h, digest_body = call_json("GET", "/digest-usage")
        self.assertEqual(  # type: ignore[index]
            [entry["digest"] for entry in digest_body], [DIGEST_A, DIGEST_B]
        )
        _s, _h, name_body = call_json("GET", "/name-usage")
        self.assertEqual(  # type: ignore[index]
            [entry["name"] for entry in name_body], ["a", "b"]
        )
        _s, _h, source_body = call_json("GET", "/source-usage")
        self.assertEqual(  # type: ignore[index]
            [entry["source"] for entry in source_body], [None]
        )

    def test_lifecycle_reads_and_summary_are_unchanged(self) -> None:
        rid = self._create("r", DIGEST_DATA)
        self._release(rid)

        status, _h, raw = call("GET", f"/resources/{rid}/lifecycle")
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            raw,
            f'{{"id":"{rid}","state":"released","reason":null}}\n'.encode(),
        )

        _s, _h, summary = call_json("GET", "/lifecycle")
        self.assertEqual(  # type: ignore[index]
            summary,
            [{"id": rid, "state": "released", "reason": None}],
        )

    # --- Response body -------------------------------------------------------

    def test_body_is_compact_json_with_single_trailing_newline(self) -> None:
        rid = self._create("a")
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
        rid = self._create("状态-α")
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
        root = pathlib.Path(__file__).resolve().parents[1]
        before = {
            str(p.relative_to(root))
            for p in root.rglob("*")
            if ".git" not in p.parts and p.is_file()
        }
        self._create("a")
        self._usage()
        after = {
            str(p.relative_to(root))
            for p in root.rglob("*")
            if ".git" not in p.parts and p.is_file()
        }
        self.assertEqual(before, after)

    # --- Validation ----------------------------------------------------------

    def test_query_parameters_are_bad_request(self) -> None:
        self._create("a")
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
        self._create("a")
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
        self._create("a")
        status, _h, _raw = call("GET", PATH, b'{"not": "consumed"}')
        self.assertEqual(status, "400 Bad Request")

    def test_omitted_length_header_is_accepted(self) -> None:
        status, _h, raw = self._usage(omit_content_length=True)
        self.assertEqual(status, "200 OK")
        self.assertEqual(raw, b"[]\n")

    def test_explicit_zero_length_body_is_accepted(self) -> None:
        self._create("a")
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


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]


def _free_port() -> int:
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _http(
    port: int,
    method: str,
    path: str,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    request_headers = dict(headers or {})
    conn.request(method, path, body=body, headers=request_headers)
    response = conn.getresponse()
    data = response.read()
    response_headers = {name: value for name, value in response.getheaders()}
    conn.close()
    return response.status, response_headers, data


class StateUsageRestartTests(unittest.TestCase):
    """A genuine new OS process must start with empty in-memory state."""

    def _start_server(self, port: int) -> subprocess.Popen[str]:
        env = dict(os.environ)
        env["PYTHONPATH"] = (
            str(REPO_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
        )
        env["PYTHONIOENCODING"] = "utf-8"
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
            cwd=str(REPO_ROOT),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.addCleanup(self._stop_server, proc)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                _out, err = proc.communicate()
                self.fail(f"server process exited early:\n{err}")
            try:
                status, _h, _raw = _http(port, "GET", "/health")
            except OSError:
                time.sleep(0.1)
                continue
            self.assertEqual(status, 200)
            return proc
        self.fail("server did not become ready in time")
        return proc  # pragma: no cover - fail() raises

    @staticmethod
    def _stop_server(proc: subprocess.Popen[str]) -> None:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:  # pragma: no cover
                proc.kill()
                proc.wait(timeout=10)
        # Reap and close the captured stdout/stderr pipes.
        proc.communicate()

    def test_state_usage_resets_across_a_real_process_restart(self) -> None:
        port_a = _free_port()
        server_a = self._start_server(port_a)

        # Populate the first process: r1 released, r2 staged.
        status, _h, raw = _http(
            port_a,
            "POST",
            "/resources",
            json.dumps(
                {
                    "name": "r1",
                    "category": "artifact",
                    "digest": DIGEST_DATA,
                }
            ).encode("utf-8"),
            {"Content-Type": "application/json"},
        )
        self.assertEqual(status, 201, raw)
        r1 = json.loads(raw.decode("utf-8"))["id"]

        status, _h, raw = _http(
            port_a,
            "POST",
            f"/resources/{r1}/chunks/0",
            b"data",
            {
                "Content-Type": "application/octet-stream",
                "X-Total-Chunks": "1",
                "X-Content-Digest": DIGEST_DATA,
            },
        )
        self.assertEqual(status, 201, raw)
        status, _h, raw = _http(
            port_a, "POST", f"/resources/{r1}/assemble", b""
        )
        self.assertEqual(status, 201, raw)
        status, _h, raw = _http(
            port_a,
            "POST",
            f"/resources/{r1}/lifecycle",
            json.dumps({"state": "released"}).encode("utf-8"),
            {"Content-Type": "application/json"},
        )
        self.assertEqual(status, 200, raw)

        status, _h, raw = _http(
            port_a,
            "POST",
            "/resources",
            json.dumps(
                {
                    "name": "r2",
                    "category": "code",
                    "digest": DIGEST_B,
                }
            ).encode("utf-8"),
            {"Content-Type": "application/json"},
        )
        self.assertEqual(status, 201, raw)
        r2 = json.loads(raw.decode("utf-8"))["id"]

        status, _h, raw = _http(port_a, "GET", "/state-usage")
        self.assertEqual(status, 200)
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        before = json.loads(raw.decode("utf-8"))
        self.assertEqual(
            [entry["state"] for entry in before], ["released", "staged"]
        )
        self.assertEqual(before[0]["resources"], [r1])
        self.assertEqual(before[0]["names"], ["r1"])
        self.assertEqual(before[0]["digests"], [DIGEST_DATA])
        self.assertEqual(before[1]["resources"], [r2])
        self.assertEqual(before[1]["names"], ["r2"])
        self.assertEqual(before[1]["digests"], [DIGEST_B])

        # Stop the process for real; its in-memory registry and lifecycle
        # records must not survive anywhere.
        self._stop_server(server_a)

        # A brand new process answers with an empty array on the very
        # first query: the released/staged entries from the old process
        # leave no residue.
        port_b = _free_port()
        self._start_server(port_b)

        status, headers, raw = _http(port_b, "GET", "/state-usage")
        self.assertEqual(status, 200)
        self.assertEqual(
            headers.get("Content-Type"), "application/json; charset=utf-8"
        )
        self.assertEqual(raw, b"[]\n")

        # The underlying registry and the lifecycle summary are empty too.
        status, _h, raw = _http(port_b, "GET", "/lifecycle")
        self.assertEqual(status, 200)
        self.assertEqual(raw, b"[]\n")

        status, _h, raw = _http(port_b, "GET", "/resources")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw.decode("utf-8"))["resources"], [])

        # New registrations in the fresh process start at the default
        # staged state, as if nothing had ever existed.
        status, _h, raw = _http(
            port_b,
            "POST",
            "/resources",
            json.dumps(
                {
                    "name": "fresh",
                    "category": "code",
                    "digest": DIGEST_C,
                }
            ).encode("utf-8"),
            {"Content-Type": "application/json"},
        )
        self.assertEqual(status, 201, raw)
        fresh = json.loads(raw.decode("utf-8"))["id"]

        status, _h, raw = _http(port_b, "GET", "/state-usage")
        self.assertEqual(status, 200)
        after = json.loads(raw.decode("utf-8"))
        self.assertEqual(
            after,
            [
                {
                    "state": "staged",
                    "resources": [fresh],
                    "resource_count": 1,
                    "names": ["fresh"],
                    "digests": [DIGEST_C],
                }
            ],
        )


if __name__ == "__main__":
    unittest.main()
