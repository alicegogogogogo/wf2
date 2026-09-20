from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from typing import Any

StartResponse = Callable[[str, list[tuple[str, str]]], Any]


def _json_response(
    start_response: StartResponse, status: str, payload: dict[str, object]
) -> Iterable[bytes]:
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    start_response(
        status,
        [
            ("Content-Type", "application/json; charset=utf-8"),
            ("Content-Length", str(len(body))),
        ],
    )
    return [body]


def application(environ: dict[str, Any], start_response: StartResponse) -> Iterable[bytes]:
    method = str(environ.get("REQUEST_METHOD", "GET")).upper()
    path = str(environ.get("PATH_INFO", "/"))

    if method == "GET" and path == "/health":
        return _json_response(start_response, "200 OK", {"status": "ok"})

    return _json_response(
        start_response,
        "404 Not Found",
        {"error": "not_found", "message": "The requested resource does not exist."},
    )

