from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from collections.abc import Callable, Iterable
from typing import Any
from urllib.parse import parse_qsl

from .resources import (
    Resource,
    ResourceStore,
    ResourceValidationError,
    normalize_category,
    normalize_digest,
)

StartResponse = Callable[[str, list[tuple[str, str]]], Any]

#: Process-local storage; records are not persisted across restarts.
store = ResourceStore()

#: Pagination defaults and bounds for GET /resources.
DEFAULT_LIMIT = 50
MAX_LIMIT = 100

#: Process-local cursor secret; cursors are meaningless after a restart.
_CURSOR_SECRET = secrets.token_bytes(32)

_LIST_PARAMS = frozenset({"category", "name", "digest", "limit", "cursor"})


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


def _encode_cursor(
    filters: tuple[str | None, str | None, str | None], limit: int, offset: int
) -> str:
    payload = json.dumps(
        {"f": list(filters), "l": limit, "o": offset},
        separators=(",", ":"),
    ).encode("utf-8")
    token = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    signature = hmac.new(
        _CURSOR_SECRET, token.encode("ascii"), hashlib.sha256
    ).hexdigest()
    return f"{token}.{signature}"


def _decode_cursor(
    raw: str,
) -> tuple[tuple[str | None, str | None, str | None], int, int] | None:
    """Return ``(filters, limit, offset)`` or ``None`` if the cursor is invalid."""

    token, separator, signature = raw.partition(".")
    if not separator or not token or not signature:
        return None
    expected = hmac.new(
        _CURSOR_SECRET, token.encode("ascii"), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return None
    try:
        padded = token + "=" * (-len(token) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    filters_raw = payload.get("f")
    limit = payload.get("l")
    offset = payload.get("o")
    if (
        not isinstance(filters_raw, list)
        or len(filters_raw) != 3
        or any(not (f is None or isinstance(f, str)) for f in filters_raw)
        or not isinstance(limit, int)
        or isinstance(limit, bool)
        or not isinstance(offset, int)
        or isinstance(offset, bool)
        or limit < 1
        or offset < 0
    ):
        return None
    filters = (filters_raw[0], filters_raw[1], filters_raw[2])
    return filters, limit, offset


def _invalid_list_request(
    start_response: StartResponse, message: str
) -> Iterable[bytes]:
    return _error(start_response, "400 Bad Request", "invalid_request", message)


def _handle_resources_list(
    environ: dict[str, Any], start_response: StartResponse
) -> Iterable[bytes]:
    query = str(environ.get("QUERY_STRING", "") or "")
    pairs = parse_qsl(query, keep_blank_values=True)
    if not pairs:
        # No filtering or pagination: keep the original response shape.
        return _json_response(
            start_response,
            "200 OK",
            {"resources": [r.to_dict() for r in store.list_all()]},
            trailing_newline=True,
        )

    params: dict[str, str] = {}
    for key, value in pairs:
        if key not in _LIST_PARAMS:
            return _invalid_list_request(
                start_response, f"Unknown query parameter: {key!r}."
            )
        if key in params:
            return _invalid_list_request(
                start_response, f"Duplicate query parameter: {key!r}."
            )
        params[key] = value

    category: str | None = None
    if "category" in params:
        category = normalize_category(params["category"])
        if category is None:
            return _invalid_list_request(
                start_response, "Category filter is empty or not a known category."
            )

    name: str | None = None
    if "name" in params:
        if params["name"] == "":
            return _invalid_list_request(
                start_response, "Name filter must not be empty."
            )
        # Exact match: no folding, trimming or partial matching.
        name = params["name"]

    digest: str | None = None
    if "digest" in params:
        digest = normalize_digest(params["digest"])
        if digest is None:
            return _invalid_list_request(
                start_response,
                "Digest filter must be a 64-character hexadecimal string.",
            )

    limit = DEFAULT_LIMIT
    if "limit" in params:
        raw_limit = params["limit"]
        if not raw_limit or not raw_limit.isascii() or not raw_limit.isdigit():
            return _invalid_list_request(
                start_response, "Limit must be a decimal positive integer."
            )
        limit = int(raw_limit)
        if limit < 1 or limit > MAX_LIMIT:
            return _invalid_list_request(
                start_response,
                f"Limit must be between 1 and {MAX_LIMIT}.",
            )

    filters = (category, name, digest)
    offset = 0
    if "cursor" in params:
        decoded = _decode_cursor(params["cursor"])
        if decoded is None:
            return _invalid_list_request(
                start_response, "Cursor is invalid or was not issued by this process."
            )
        cursor_filters, cursor_limit, offset = decoded
        if cursor_filters != filters or cursor_limit != limit:
            return _invalid_list_request(
                start_response,
                "Cursor does not match the requested filters and limit.",
            )

    matched = [
        resource
        for resource in store.list_all()
        if (category is None or resource.category == category)
        and (name is None or resource.name == name)
        and (digest is None or resource.digest == digest)
    ]
    page = matched[offset : offset + limit]
    next_offset = offset + limit
    next_cursor = (
        _encode_cursor(filters, limit, next_offset)
        if next_offset < len(matched)
        else None
    )
    return _json_response(
        start_response,
        "200 OK",
        {
            "resources": [r.to_dict() for r in page],
            "next_cursor": next_cursor,
        },
        trailing_newline=True,
    )


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
                return _handle_resources_list(environ, start_response)
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
