from __future__ import annotations

import json
import re
import threading
from collections.abc import Callable, Iterable
from typing import Any

StartResponse = Callable[[str, list[tuple[str, str]]], Any]

# Public business scope: code, AI models, datasets and build artifacts.
_CATEGORIES = ("code", "model", "dataset", "build-artifact")
_DIGEST_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")
_KNOWN_FIELDS = {"name", "category", "digest", "origin"}


class _RequestError(Exception):
    """A client-facing error with a stable code; never leaks internals."""

    def __init__(self, status: str, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


class _ResourceStore:
    """In-memory registry; records are process-local and vanish on stop."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: list[dict[str, Any]] = []
        self._by_id: dict[str, dict[str, Any]] = {}
        self._keys: set[tuple[str, str, str]] = set()
        self._sequence = 0

    def add(
        self, name: str, category: str, digest: str, origin: str | None
    ) -> dict[str, Any] | None:
        key = (category, name, digest)
        with self._lock:
            if key in self._keys:
                return None
            self._sequence += 1
            record: dict[str, Any] = {
                "id": f"res-{self._sequence:06d}",
                "name": name,
                "category": category,
                "digest": digest,
            }
            if origin is not None:
                record["origin"] = origin
            self._keys.add(key)
            self._by_id[record["id"]] = record
            self._records.append(record)
            return dict(record)

    def get(self, resource_id: str) -> dict[str, Any] | None:
        with self._lock:
            record = self._by_id.get(resource_id)
            return dict(record) if record is not None else None

    def list(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(record) for record in self._records]


_STORE = _ResourceStore()


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


def _resource_response(
    start_response: StartResponse,
    status: str,
    payload: object,
    extra_headers: list[tuple[str, str]] | None = None,
) -> Iterable[bytes]:
    body = (
        json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        + "\n"
    ).encode("utf-8")
    headers = [
        ("Content-Type", "application/json; charset=utf-8"),
        ("Content-Length", str(len(body))),
    ]
    if extra_headers:
        headers.extend(extra_headers)
    start_response(status, headers)
    return [body]


def _resource_error(
    start_response: StartResponse,
    status: str,
    code: str,
    message: str,
    extra_headers: list[tuple[str, str]] | None = None,
) -> Iterable[bytes]:
    return _resource_response(
        start_response, status, {"error": code, "message": message}, extra_headers
    )


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite number {value!r} is not allowed")


def _read_json_object(environ: dict[str, Any]) -> dict[str, Any]:
    try:
        length = int(str(environ.get("CONTENT_LENGTH") or "0"))
    except (TypeError, ValueError):
        length = 0
    stream = environ.get("wsgi.input")
    if length <= 0 or stream is None:
        raise _RequestError(
            "400 Bad Request", "invalid_json", "Request body is missing."
        )
    try:
        raw = stream.read(length)
        text = raw.decode("utf-8")
        data = json.loads(text, parse_constant=_reject_constant)
    except Exception:
        raise _RequestError(
            "400 Bad Request",
            "invalid_json",
            "Request body must be a single JSON object.",
        ) from None
    if not isinstance(data, dict):
        raise _RequestError(
            "400 Bad Request",
            "invalid_json",
            "Request body must be a single JSON object.",
        )
    return data


def _validate_resource(data: dict[str, Any]) -> tuple[str, str, str, str | None]:
    unknown = sorted(set(data) - _KNOWN_FIELDS)
    if unknown:
        raise _RequestError(
            "400 Bad Request",
            "unknown_field",
            f"Unknown field: {unknown[0]}.",
        )
    for field in ("name", "category", "digest"):
        if field not in data:
            raise _RequestError(
                "400 Bad Request",
                "missing_field",
                f"Field '{field}' is required.",
            )
    name = data["name"]
    if not isinstance(name, str) or not name.strip():
        raise _RequestError(
            "400 Bad Request",
            "invalid_field",
            "Field 'name' must be a non-empty string.",
        )
    category = data["category"]
    if not isinstance(category, str):
        raise _RequestError(
            "400 Bad Request",
            "invalid_field",
            "Field 'category' must be a string.",
        )
    category = category.lower()
    if category not in _CATEGORIES:
        raise _RequestError(
            "400 Bad Request",
            "invalid_category",
            "Field 'category' must be one of: code, model, dataset, build-artifact.",
        )
    digest = data["digest"]
    if not isinstance(digest, str) or not _DIGEST_PATTERN.fullmatch(digest):
        raise _RequestError(
            "400 Bad Request",
            "invalid_digest",
            "Field 'digest' must be a 64-character hexadecimal string.",
        )
    digest = digest.lower()
    origin = data.get("origin")
    if origin is not None and not isinstance(origin, str):
        raise _RequestError(
            "400 Bad Request",
            "invalid_field",
            "Field 'origin' must be a string.",
        )
    return name, category, digest, origin


def _handle_collection(
    method: str, environ: dict[str, Any], start_response: StartResponse
) -> Iterable[bytes]:
    if method == "GET":
        return _resource_response(start_response, "200 OK", _STORE.list())
    if method == "POST":
        try:
            data = _read_json_object(environ)
            name, category, digest, origin = _validate_resource(data)
        except _RequestError as exc:
            return _resource_error(start_response, exc.status, exc.code, exc.message)
        record = _STORE.add(name, category, digest, origin)
        if record is None:
            return _resource_error(
                start_response,
                "409 Conflict",
                "duplicate_resource",
                "A resource with the same category, name and digest already exists.",
            )
        return _resource_response(start_response, "201 Created", record)
    return _resource_error(
        start_response,
        "405 Method Not Allowed",
        "method_not_allowed",
        "Method not allowed on /resources.",
        [("Allow", "GET, POST")],
    )


def _handle_item(
    method: str, resource_id: str, start_response: StartResponse
) -> Iterable[bytes]:
    if method != "GET":
        return _resource_error(
            start_response,
            "405 Method Not Allowed",
            "method_not_allowed",
            "Method not allowed on /resources/{id}.",
            [("Allow", "GET")],
        )
    if not resource_id or "/" in resource_id:
        return _resource_error(
            start_response,
            "400 Bad Request",
            "invalid_id",
            "Resource id must be non-empty and must not contain path separators.",
        )
    record = _STORE.get(resource_id)
    if record is None:
        return _resource_error(
            start_response,
            "404 Not Found",
            "not_found",
            "The requested resource does not exist.",
        )
    return _resource_response(start_response, "200 OK", record)


def application(environ: dict[str, Any], start_response: StartResponse) -> Iterable[bytes]:
    try:
        method = str(environ.get("REQUEST_METHOD", "GET")).upper()
        path = str(environ.get("PATH_INFO", "/"))

        if method == "GET" and path == "/health":
            return _json_response(start_response, "200 OK", {"status": "ok"})

        if path == "/resources":
            return _handle_collection(method, environ, start_response)

        if path.startswith("/resources/"):
            return _handle_item(method, path[len("/resources/"):], start_response)

        return _json_response(
            start_response,
            "404 Not Found",
            {"error": "not_found", "message": "The requested resource does not exist."},
        )
    except Exception:
        return _json_response(
            start_response,
            "500 Internal Server Error",
            {"error": "internal_error", "message": "The request could not be processed."},
        )
