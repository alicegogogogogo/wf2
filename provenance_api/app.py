from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl

from .resources import (
    CATEGORIES,
    DependencyError,
    Resource,
    ResourceStore,
    ResourceValidationError,
)

StartResponse = Callable[[str, list[tuple[str, str]]], Any]

#: Process-local storage; records are not persisted across restarts.
store = ResourceStore()

#: Listing defaults and bounds.
DEFAULT_LIMIT = 50
MAX_LIMIT = 100
_LIST_PARAMS = frozenset({"category", "name", "digest", "limit", "cursor"})
_CATEGORY_VALUES = frozenset(CATEGORIES)
_DIGEST_PATTERN = re.compile(r"[0-9a-fA-F]{64}")
_POSITIVE_INT_PATTERN = re.compile(r"[1-9][0-9]*")

#: Random per-process key so cursors cannot be forged and never survive a
#: restart; nothing here is persisted to disk.
_cursor_key = os.urandom(32)


class ListQueryError(ValueError):
    """A list request contained invalid query parameters or cursor."""


@dataclass(frozen=True, slots=True)
class ListQuery:
    category: str | None
    name: str | None
    digest: str | None
    limit: int
    offset: int
    paged: bool


def _cursor_signature(
    category: str, name: str, digest: str, limit: int, offset: int
) -> bytes:
    mac = hmac.new(_cursor_key, b"list-cursor-v1", hashlib.sha256)
    for part in (category, name, digest, str(limit)):
        encoded = part.encode("utf-8")
        mac.update(len(encoded).to_bytes(4, "big"))
        mac.update(encoded)
    mac.update(offset.to_bytes(8, "big"))
    return mac.digest()


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64decode(token: str) -> bytes:
    return base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))


def _encode_cursor(
    category: str, name: str, digest: str, limit: int, offset: int
) -> str:
    return _b64encode(str(offset).encode("ascii")) + "." + _b64encode(
        _cursor_signature(category, name, digest, limit, offset)
    )


def _decode_cursor(
    raw: str, category: str, name: str, digest: str, limit: int
) -> int:
    """Return the offset encoded by a cursor.

    Raises :class:`ListQueryError` when the cursor is forged, corrupted or
    was issued for different filter conditions or limit.
    """

    token_b64, dot, sig_b64 = raw.partition(".")
    if not dot or not token_b64 or not sig_b64:
        raise ListQueryError("Cursor is malformed.")
    try:
        token = _b64decode(token_b64)
        sig = _b64decode(sig_b64)
    except (binascii.Error, ValueError):
        raise ListQueryError("Cursor is malformed.") from None

    if not token.isdigit() or token.startswith(b"0") or int(token) <= 0:
        raise ListQueryError("Cursor is malformed.")
    offset = int(token)

    expected = _cursor_signature(category, name, digest, limit, offset)
    if not hmac.compare_digest(sig, expected):
        raise ListQueryError("Cursor is not valid for this request.")
    return offset


def parse_list_query(query_string: str) -> ListQuery:
    """Parse and validate the query string for ``GET /resources``."""

    pairs = parse_qsl(query_string, keep_blank_values=True, strict_parsing=False)
    seen: set[str] = set()
    raw_values: dict[str, str] = {}
    for key, value in pairs:
        if key not in _LIST_PARAMS:
            raise ListQueryError(f"Unknown query parameter: {key!r}.")
        if key in seen:
            raise ListQueryError(f"Query parameter {key!r} must not be repeated.")
        seen.add(key)
        raw_values[key] = value

    category: str | None = None
    if "category" in raw_values:
        value = raw_values["category"]
        if value == "":
            raise ListQueryError("Category must not be empty.")
        if value.lower() not in _CATEGORY_VALUES:
            allowed = ", ".join(CATEGORIES)
            raise ListQueryError(
                f"Category must be one of: {allowed} (case-insensitive)."
            )
        category = value.lower()

    name: str | None = None
    if "name" in raw_values:
        value = raw_values["name"]
        # Exact, case-sensitive comparison; no trimming or folding.
        if value == "":
            raise ListQueryError("Name must not be empty.")
        name = value

    digest: str | None = None
    if "digest" in raw_values:
        value = raw_values["digest"]
        if _DIGEST_PATTERN.fullmatch(value) is None:
            raise ListQueryError(
                "Digest must be a 64-character hexadecimal string."
            )
        digest = value.lower()

    limit = DEFAULT_LIMIT
    if "limit" in raw_values:
        value = raw_values["limit"]
        if _POSITIVE_INT_PATTERN.fullmatch(value) is None:
            raise ListQueryError(
                f"Limit must be a positive integer no greater than {MAX_LIMIT}."
            )
        limit = int(value)
        if limit > MAX_LIMIT:
            raise ListQueryError(
                f"Limit must be a positive integer no greater than {MAX_LIMIT}."
            )

    offset = 0
    if "cursor" in raw_values:
        value = raw_values["cursor"]
        if value == "":
            raise ListQueryError("Cursor is malformed.")
        offset = _decode_cursor(
            value, category or "", name or "", digest or "", limit
        )

    paged = bool(seen)
    return ListQuery(
        category=category,
        name=name,
        digest=digest,
        limit=limit,
        offset=offset,
        paged=paged,
    )


def _handle_resources_get(
    environ: dict[str, Any], start_response: StartResponse
) -> Iterable[bytes]:
    try:
        query = parse_list_query(str(environ.get("QUERY_STRING", "")))
    except ListQueryError as exc:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            str(exc),
        )

    if not query.paged:
        # No filtering or pagination parameters: preserve the original shape.
        return _json_response(
            start_response,
            "200 OK",
            {"resources": [r.to_dict() for r in store.list_all()]},
            trailing_newline=True,
        )

    matched = store.query(
        category=query.category, name=query.name, digest=query.digest
    )
    page = matched[query.offset : query.offset + query.limit]
    next_offset = query.offset + len(page)
    next_cursor: str | None = None
    if next_offset < len(matched):
        next_cursor = _encode_cursor(
            query.category or "",
            query.name or "",
            query.digest or "",
            query.limit,
            next_offset,
        )

    return _json_response(
        start_response,
        "200 OK",
        {"resources": [r.to_dict() for r in page], "next_cursor": next_cursor},
        trailing_newline=True,
    )


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


def _validate_path_id(raw_id: str) -> str | None:
    """Return a stable error message for an invalid path id, else ``None``."""

    if not raw_id:
        return "Resource id must not be empty."
    if "/" in raw_id or "\\" in raw_id:
        return "Resource id must not contain path separators."
    return None


def _query_parameter_error(environ: dict[str, Any]) -> str | None:
    """Reject any query parameter on endpoints that declare none."""

    query_string = str(environ.get("QUERY_STRING", ""))
    if parse_qsl(query_string, keep_blank_values=True):
        return "This endpoint does not accept query parameters."
    return None


def _handle_dependencies_post(
    environ: dict[str, Any], raw_id: str, start_response: StartResponse
) -> Iterable[bytes]:
    id_error = _validate_path_id(raw_id)
    if id_error is not None:
        return _error(
            start_response, "400 Bad Request", "invalid_request", id_error
        )

    query_error = _query_parameter_error(environ)
    if query_error is not None:
        return _error(
            start_response, "400 Bad Request", "invalid_request", query_error
        )

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

    if not isinstance(payload, dict):
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            "Request body must be a JSON object.",
        )
    unknown_fields = set(payload) - {"dependency_id"}
    if unknown_fields:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            f"Unknown field: {sorted(unknown_fields)[0]!r}.",
        )
    if "dependency_id" not in payload:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            "Missing required field: 'dependency_id'.",
        )
    dependency_id = payload["dependency_id"]
    if not isinstance(dependency_id, str) or not dependency_id:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            "Field 'dependency_id' must be a non-empty string.",
        )
    if "/" in dependency_id or "\\" in dependency_id:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            "Field 'dependency_id' must not contain path separators.",
        )

    # Both endpoints must already be registered; never auto-create.
    if store.get(raw_id) is None:
        return _error(
            start_response,
            "404 Not Found",
            "resource_not_found",
            "No resource exists with the requested id.",
        )
    if store.get(dependency_id) is None:
        return _error(
            start_response,
            "404 Not Found",
            "resource_not_found",
            "No resource exists with dependency_id.",
        )

    try:
        store.add_dependency(raw_id, dependency_id)
    except DependencyError as exc:
        return _error(
            start_response,
            "409 Conflict",
            exc.code,
            exc.message,
        )

    return _json_response(
        start_response,
        "201 Created",
        {"resource_id": raw_id, "dependency_id": dependency_id},
        trailing_newline=True,
    )


def _handle_dependencies_get(
    environ: dict[str, Any], raw_id: str, start_response: StartResponse
) -> Iterable[bytes]:
    id_error = _validate_path_id(raw_id)
    if id_error is not None:
        return _error(
            start_response, "400 Bad Request", "invalid_request", id_error
        )
    query_error = _query_parameter_error(environ)
    if query_error is not None:
        return _error(
            start_response, "400 Bad Request", "invalid_request", query_error
        )
    if store.get(raw_id) is None:
        return _error(
            start_response,
            "404 Not Found",
            "resource_not_found",
            "No resource exists with the requested id.",
        )
    return _json_response(
        start_response,
        "200 OK",
        {"dependencies": store.list_dependencies(raw_id)},
        trailing_newline=True,
    )


def _handle_dependencies(
    method: str,
    environ: dict[str, Any],
    raw_id: str,
    start_response: StartResponse,
) -> Iterable[bytes]:
    if method == "POST":
        return _handle_dependencies_post(environ, raw_id, start_response)
    if method == "GET":
        return _handle_dependencies_get(environ, raw_id, start_response)
    return _error(
        start_response,
        "405 Method Not Allowed",
        "method_not_allowed",
        f"Method {method} is not allowed for this path.",
        allowed="GET, POST",
    )


class _BodyReadError(ValueError):
    """The raw request body could not be read exactly as declared."""


def _read_exact_body(environ: dict[str, Any]) -> bytes:
    """Read exactly ``Content-Length`` raw bytes from the request body.

    Raises :class:`_BodyReadError` when the length header is missing or
    invalid, the stream cannot be read, or fewer bytes than declared are
    available. An explicitly declared empty body is legal.
    """

    raw_length = environ.get("CONTENT_LENGTH")
    if raw_length is None or str(raw_length) == "":
        raise _BodyReadError("A Content-Length header is required.")
    try:
        length = int(str(raw_length))
    except (TypeError, ValueError):
        raise _BodyReadError(
            "Content-Length must be a non-negative integer."
        ) from None
    if length < 0:
        raise _BodyReadError("Content-Length must be a non-negative integer.")
    try:
        body = environ["wsgi.input"].read(length)
    except Exception:
        raise _BodyReadError("Failed to read the request body.") from None
    if len(body) != length:
        raise _BodyReadError(
            "Request body is incomplete: fewer bytes than declared."
        )
    return body


def _handle_verify_post(
    environ: dict[str, Any], raw_id: str, start_response: StartResponse
) -> Iterable[bytes]:
    id_error = _validate_path_id(raw_id)
    if id_error is not None:
        # Reject before touching any business data or the request body.
        return _error(
            start_response, "400 Bad Request", "invalid_request", id_error
        )
    query_error = _query_parameter_error(environ)
    if query_error is not None:
        return _error(
            start_response, "400 Bad Request", "invalid_request", query_error
        )

    media_type = (
        str(environ.get("CONTENT_TYPE", "")).split(";", 1)[0].strip().lower()
    )
    if media_type != "application/octet-stream":
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            "Content-Type must be application/octet-stream.",
        )

    try:
        body = _read_exact_body(environ)
    except _BodyReadError as exc:
        return _error(
            start_response, "400 Bad Request", "invalid_request", str(exc)
        )

    resource = store.get(raw_id)
    if resource is None:
        return _error(
            start_response,
            "404 Not Found",
            "resource_not_found",
            "No resource exists with the requested id.",
        )

    # Lowercase SHA-256 hex digest, compared verbatim against registration.
    digest = hashlib.sha256(body).hexdigest()
    return _json_response(
        start_response,
        "200 OK",
        {"id": resource.id, "digest": digest, "valid": digest == resource.digest},
        trailing_newline=True,
    )


def _handle_verify(
    method: str,
    environ: dict[str, Any],
    raw_id: str,
    start_response: StartResponse,
) -> Iterable[bytes]:
    if method != "POST":
        return _error(
            start_response,
            "405 Method Not Allowed",
            "method_not_allowed",
            f"Method {method} is not allowed for this path.",
            allowed="POST",
        )
    return _handle_verify_post(environ, raw_id, start_response)


def _handle_impact(
    method: str,
    environ: dict[str, Any],
    raw_id: str,
    start_response: StartResponse,
) -> Iterable[bytes]:
    if method != "GET":
        return _error(
            start_response,
            "405 Method Not Allowed",
            "method_not_allowed",
            f"Method {method} is not allowed for this path.",
            allowed="GET",
        )

    id_error = _validate_path_id(raw_id)
    if id_error is not None:
        return _error(
            start_response, "400 Bad Request", "invalid_request", id_error
        )
    query_error = _query_parameter_error(environ)
    if query_error is not None:
        return _error(
            start_response, "400 Bad Request", "invalid_request", query_error
        )
    if store.get(raw_id) is None:
        return _error(
            start_response,
            "404 Not Found",
            "resource_not_found",
            "No resource exists with the requested id.",
        )
    return _json_response(
        start_response,
        "200 OK",
        {"resources": store.list_impact(raw_id)},
        trailing_newline=True,
    )


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
                return _handle_resources_get(environ, start_response)
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
            suffix = path[len("/resources/"):]
            head, separator, tail = suffix.partition("/")
            if separator and tail == "dependencies":
                return _handle_dependencies(
                    method, environ, head, start_response
                )
            if separator and tail == "impact":
                return _handle_impact(
                    method, environ, head, start_response
                )
            if suffix.endswith("/verify"):
                # Everything before the final "/verify" is the id; embedded
                # separators make it invalid and are rejected with 400.
                raw_id = suffix[: -len("/verify")]
                return _handle_verify(
                    method, environ, raw_id, start_response
                )
            # Any other suffix keeps the baseline item semantics (embedded
            # separators are rejected by the item handler).
            return _handle_resource_item(
                method, suffix, start_response
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
