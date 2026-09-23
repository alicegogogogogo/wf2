from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from typing import Any

from .resources import Resource, ResourceStore, ResourceValidationError

StartResponse = Callable[[str, list[tuple[str, str]]], Any]

#: Process-local storage; records are not persisted across restarts.
store = ResourceStore()


def _json_response(
    start_response: StartResponse,
    status: str,
    payload: dict[str, object],
    *,
    extra_headers: list[tuple[str, str]] | None = None,
    trailing_newline: bool = False,
) -> Iterable[bytes]:
    body = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    if trailing_newline:
        body += b"\n"
    headers = [
        ("Content-Type", "application/json; charset=utf-8"),
        ("Content-Length", str(len(body))),
    ]
    if extra_headers:
        headers.extend(extra_headers)
    start_response(status, headers)
    return [body]


def _error(
    start_response: StartResponse,
    status: str,
    code: str,
    message: str,
    *,
    allowed: str | None = None,
    trailing_newline: bool = True,
) -> Iterable[bytes]:
    headers = []
    if allowed is not None:
        headers.append(("Allow", allowed))
    return _json_response(
        start_response,
        status,
        {"error": code, "message": message},
        extra_headers=headers,
        trailing_newline=trailing_newline,
    )


def _resource_response(
    start_response: StartResponse, status: str, resource: Resource
) -> Iterable[bytes]:
    return _json_response(
        start_response,
        status,
        resource.to_dict(),
        trailing_newline=True,
    )


def _read_body(environ: dict[str, Any]) -> bytes:
    try:
        length = int(environ.get("CONTENT_LENGTH") or 0)
    except (TypeError, ValueError):
        length = 0
    if length <= 0:
        return b""
    return environ["wsgi.input"].read(length)


def _handle_resources_post(
    environ: dict[str, Any], start_response: StartResponse
) -> Iterable[bytes]:
    raw = _read_body(environ)
    if not raw:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            "Request body is empty.",
        )
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            "Request body must be valid UTF-8 JSON.",
        )

    try:
        created, existing = store.add(payload)
    except ResourceValidationError as exc:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            exc.message,
        )

    if existing is not None:
        # Never overwrite or merge with the original record.
        return _error(
            start_response,
            "409 Conflict",
            "duplicate_resource",
            "A resource with the same category, name and digest already exists.",
        )

    assert created is not None
    return _resource_response(start_response, "201 Created", created)


def _handle_resource_item(
    method: str, raw_id: str, start_response: StartResponse
) -> Iterable[bytes]:
    if method != "GET":
        return _error(
            start_response,
            "405 Method Not Allowed",
            "method_not_allowed",
            f"Method {method} is not allowed for this path.",
            allowed="GET",
        )

    if not raw_id:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            "Resource id must not be empty.",
        )
    if "/" in raw_id or "\\" in raw_id:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            "Resource id must not contain path separators.",
        )

    resource = store.get(raw_id)
    if resource is None:
        return _error(
            start_response,
            "404 Not Found",
            "resource_not_found",
            "No resource exists with the requested id.",
        )

    return _resource_response(start_response, "200 OK", resource)


def application(
    environ: dict[str, Any], start_response: StartResponse
) -> Iterable[bytes]:
    try:
        method = str(environ.get("REQUEST_METHOD", "GET")).upper()
        path = str(environ.get("PATH_INFO", "/"))

        if method == "GET" and path == "/health":
            # Kept byte-for-byte compatible with the documented baseline.
            return _json_response(start_response, "200 OK", {"status": "ok"})

        if path == "/resources":
            if method == "GET":
                return _json_response(
                    start_response,
                    "200 OK",
                    {"resources": [r.to_dict() for r in store.list_all()]},
                    trailing_newline=True,
                )
            if method == "POST":
                return _handle_resources_post(environ, start_response)
            return _error(
                start_response,
                "405 Method Not Allowed",
                "method_not_allowed",
                f"Method {method} is not allowed for this path.",
                allowed="GET, POST",
            )

        if path.startswith("/resources/"):
            return _handle_resource_item(
                method, path[len("/resources/"):], start_response
            )

        # Unknown paths and undeclared methods on /health stay as before.
        return _json_response(
            start_response,
            "404 Not Found",
            {"error": "not_found", "message": "The requested resource does not exist."},
        )
    except Exception:  # pragma: no cover - defensive boundary
        # Clients must only ever see agreed statuses, never a stack trace.
        return _error(
            start_response,
            "500 Internal Server Error",
            "internal_error",
            "An unexpected error occurred.",
        )
