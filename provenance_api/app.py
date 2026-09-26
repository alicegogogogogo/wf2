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

from .advisories import advisory_detail, advisory_fixes, summarize_advisories
from .cache import CacheError, LayerCacheStore
from .component_fixes import recommended_fix_version
from .content import ContentError, ContentStore
from .cross_references import (
    CrossReferenceError,
    CrossReferenceStore,
    CrossReferenceValidationError,
    build_cross_reference_fields,
    resolve_remote,
)
from .lifecycle import (
    BLOCKING_STATES,
    MAX_REASON_LENGTH,
    REASON_REQUIRED_STATES,
    STATE_VALUES,
    LifecycleError,
    LifecycleRecord,
    LifecycleStore,
)
from .mirror_policies import (
    MirrorPolicy,
    MirrorPolicyError,
    MirrorPolicyStore,
    MirrorPolicyValidationError,
    build_mirror_policy_fields,
)
from .mirrors import (
    Mirror,
    MirrorFetchError,
    MirrorStore,
    MirrorValidationError,
    ProbeStore,
    fetch_upstream_layer,
    probe_upstream,
)
from .notifications import (
    NotificationStore,
    NotificationValidationError,
    build_notification_fields,
)
from .policies import (
    DefaultPolicyStore,
    PolicyError,
    PolicyStore,
    PolicyValidationError,
    build_policy_fields,
    evaluate_policy,
)
from .provenance import (
    ProvenanceError,
    ProvenanceStore,
    ProvenanceValidationError,
    build_provenance_fields,
)
from .resources import (
    CATEGORIES,
    DependencyError,
    Resource,
    ResourceStore,
    ResourceValidationError,
)
from .risk import compute_risk_score, risk_level
from .sbom import (
    SbomError,
    SbomStore,
    SbomValidationError,
    build_license_fields,
    build_sbom_fields,
)
from .signatures import (
    SignatureError,
    SignatureStore,
    SignatureValidationError,
    build_signature_fields,
    compute_signature,
)
from .vulnerabilities import (
    SEVERITY_VALUES,
    VulnerabilityError,
    VulnerabilityStore,
    VulnerabilityValidationError,
    build_batch_fields,
    build_vulnerability_fields,
    max_severity,
)
from .vulnerability_exceptions import (
    VulnerabilityExceptionError,
    VulnerabilityExceptionStore,
    VulnerabilityExceptionValidationError,
    build_exception_fields,
)

StartResponse = Callable[[str, list[tuple[str, str]]], Any]

#: Process-local storage; records are not persisted across restarts.
store = ResourceStore()

#: Process-local chunk sessions and finalized content; also never persisted.
content_store = ContentStore()

#: Process-local lifecycle states; cleared on restart like everything else.
lifecycle_store = LifecycleStore()

#: Process-local vulnerability alerts; cleared on restart like the rest.
vulnerability_store = VulnerabilityStore()

#: Process-local vulnerability alert exemptions; cleared on restart like
#: the rest, and never persisted.
vulnerability_exception_store = VulnerabilityExceptionStore()

#: Process-local SBOM documents and license declarations; never persisted.
sbom_store = SbomStore()

#: Process-local build provenance records; never persisted.
provenance_store = ProvenanceStore()

#: Process-local admission policies and their read-only decisions; never
#: persisted and never materialized as records.
policy_store = PolicyStore()

#: Process-local global default admission policy; a single record consulted
#: only for resources without their own policy, never persisted.
default_policy_store = DefaultPolicyStore()

#: Process-local notification records; cleared on restart like the rest.
notification_store = NotificationStore()

#: Process-local image layer cache; entries and counters never persisted.
cache_store = LayerCacheStore()

#: Process-local image mirror registry; cleared on restart like everything.
mirror_store = MirrorStore()

#: Process-local mirror signature policies; cleared on restart like the
#: rest, and never persisted.
mirror_policy_store = MirrorPolicyStore()

#: Process-local latest mirror probe results; only the most recent result
#: per mirror is kept, nothing is persisted and the cache is never touched.
mirror_probe_store = ProbeStore()

#: Process-local cross-repository references; cleared on restart like the
#: rest.
cross_reference_store = CrossReferenceStore()

#: Process-local content signatures; cleared on restart like everything
#: else; verification is always computed on the fly and never recorded.
signature_store = SignatureStore()


def reset_state() -> None:
    """Clear every in-process store (test and tooling helper)."""

    store.reset()
    content_store.reset()
    lifecycle_store.reset()
    vulnerability_store.reset()
    vulnerability_exception_store.reset()
    sbom_store.reset()
    provenance_store.reset()
    policy_store.reset()
    default_policy_store.reset()
    notification_store.reset()
    cache_store.reset()
    mirror_store.reset()
    mirror_policy_store.reset()
    mirror_probe_store.reset()
    cross_reference_store.reset()
    signature_store.reset()

#: Listing defaults and bounds.
DEFAULT_LIMIT = 50
MAX_LIMIT = 100
_LIST_PARAMS = frozenset({"category", "name", "digest", "limit", "cursor"})
_CATEGORY_VALUES = frozenset(CATEGORIES)
_DIGEST_PATTERN = re.compile(r"[0-9a-fA-F]{64}")
_POSITIVE_INT_PATTERN = re.compile(r"[1-9][0-9]*")
_NON_NEGATIVE_INT_PATTERN = re.compile(r"0|[1-9][0-9]*")
_OCTET_STREAM_CONTENT_TYPE = "application/octet-stream"
_TOTAL_CHUNKS_HEADER = "HTTP_X_TOTAL_CHUNKS"
_CONTENT_DIGEST_HEADER = "HTTP_X_CONTENT_DIGEST"
_TOTAL_CHUNKS_HEADER_NAME = "X-Total-Chunks"
_CONTENT_DIGEST_HEADER_NAME = "X-Content-Digest"
_KEY_ID_HEADER = "HTTP_X_KEY_ID"
_SIGNATURE_HEADER = "HTTP_X_SIGNATURE"
_SIGNED_DIGEST_HEADER = "HTTP_X_SIGNED_DIGEST"
_KEY_ID_HEADER_NAME = "X-Key-Id"
_SIGNATURE_HEADER_NAME = "X-Signature"
_SIGNED_DIGEST_HEADER_NAME = "X-Signed-Digest"

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


def _parse_severity_query(
    query_string: str,
) -> tuple[str | None, str | None]:
    """Parse the optional, single ``severity`` query parameter.

    Shared by the three advisory views and the per-resource alert listing:
    only ``severity`` is accepted, it must appear at most once, and its
    value must be one of the four levels (matched case-insensitively and
    normalized to lowercase). Returns ``(severity, None)`` -- with
    ``None`` when the parameter is absent -- or ``(None, message)`` for an
    unknown parameter, a repeated ``severity``, an empty value or an
    illegal level. The error messages are the stable, byte-for-byte
    wording every caller already answered with.
    """

    pairs = parse_qsl(
        query_string, keep_blank_values=True, strict_parsing=False
    )
    severity: str | None = None
    for key, value in pairs:
        if key != "severity":
            return None, f"Unknown query parameter: {key!r}."
        if severity is not None:
            return None, "Query parameter 'severity' must not be repeated."
        if value == "" or value.lower() not in SEVERITY_VALUES:
            return None, (
                "Severity must be one of: critical, high, medium, low "
                "(case-insensitive)."
            )
        severity = value.lower()
    return severity, None


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
    payload: object,
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


def _remove_resource_cascade(resource_id: str) -> None:
    """Remove every record keyed by ``resource_id`` across all stores.

    Alerts, exemptions, SBOM and license data, provenance, policies,
    signatures, notifications, lifecycle state, chunk sessions with their
    assembled bytes, cross-repository references and dependency edges all
    disappear with the resource; derived read-only views (advisory
    summaries, component views, admission previews, risk scores) are
    computed on the fly and therefore reflect the removal immediately.
    Mirror sources, cache entries and other resources are never touched.
    """

    vulnerability_store.remove_resource(resource_id)
    vulnerability_exception_store.remove_resource(resource_id)
    sbom_store.remove_resource(resource_id)
    provenance_store.remove_resource(resource_id)
    policy_store.remove_resource(resource_id)
    signature_store.remove_resource(resource_id)
    notification_store.remove_resource(resource_id)
    lifecycle_store.remove(resource_id)
    content_store.remove(resource_id)
    cross_reference_store.remove_resource(resource_id)
    store.remove(resource_id)


def _handle_resource_item(
    method: str,
    environ: dict[str, Any],
    raw_id: str,
    start_response: StartResponse,
) -> Iterable[bytes]:
    if method not in ("GET", "DELETE"):
        return _error(
            start_response,
            "405 Method Not Allowed",
            "method_not_allowed",
            f"Method {method} is not allowed for this path.",
            allowed="DELETE, GET",
        )

    id_error = _validate_path_id(raw_id)
    if id_error is not None:
        return _error(
            start_response, "400 Bad Request", "invalid_request", id_error
        )

    if method == "GET":
        resource = store.get(raw_id)
        if resource is None:
            return _error(
                start_response,
                "404 Not Found",
                "resource_not_found",
                "No resource exists with the requested id.",
            )
        return _resource_response(start_response, "200 OK", resource)

    # DELETE: a bodyless, parameterless request that unregisters the
    # resource and cascades to every record stored under its id.
    query_error = _query_parameter_error(environ)
    if query_error is not None:
        return _error(
            start_response, "400 Bad Request", "invalid_request", query_error
        )
    body_error = _bodyless_request_error(environ)
    if body_error is not None:
        return _error(
            start_response, "400 Bad Request", "invalid_request", body_error
        )

    resource = store.get(raw_id)
    if resource is None:
        return _error(
            start_response,
            "404 Not Found",
            "resource_not_found",
            "No resource exists with the requested id.",
        )

    _remove_resource_cascade(raw_id)
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


def _handle_dependency_item(
    method: str,
    environ: dict[str, Any],
    raw_id: str,
    raw_dependency_id: str,
    start_response: StartResponse,
) -> Iterable[bytes]:
    if method != "DELETE":
        return _error(
            start_response,
            "405 Method Not Allowed",
            "method_not_allowed",
            f"Method {method} is not allowed for this path.",
            allowed="DELETE",
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
    body_error = _bodyless_request_error(environ)
    if body_error is not None:
        return _error(
            start_response, "400 Bad Request", "invalid_request", body_error
        )

    if (
        not raw_dependency_id
        or "/" in raw_dependency_id
        or "\\" in raw_dependency_id
    ):
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            "Dependency id must not be empty or contain path separators.",
        )

    if store.get(raw_id) is None:
        return _error(
            start_response,
            "404 Not Found",
            "resource_not_found",
            "No resource exists with the requested id.",
        )

    # Only the one direct edge is removed; both resources, every other
    # edge and all derived records stay exactly as they are.
    try:
        store.remove_dependency(raw_id, raw_dependency_id)
    except DependencyError as exc:
        return _error(
            start_response, "404 Not Found", exc.code, exc.message
        )

    return _json_response(
        start_response,
        "200 OK",
        {"resource_id": raw_id, "dependency_id": raw_dependency_id},
        trailing_newline=True,
    )


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


def _handle_dependency_vulnerability_impact(
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

    # Read-only, computed on the fly: the start resource comes first, then
    # every reachable dependency in the same registration order the
    # dependency query uses; each resource appears exactly once and nothing
    # is recorded.
    impacts: list[dict[str, object]] = []
    for resource_id in [raw_id, *store.list_dependencies(raw_id)]:
        alerts = vulnerability_store.list_for(resource_id)
        impacts.append(
            {
                "resource_id": resource_id,
                "advisory_count": len(alerts),
                "max_severity": max_severity(
                    alert.severity for alert in alerts
                ),
            }
        )

    return _json_response(
        start_response,
        "200 OK",
        {"impacts": impacts},
        trailing_newline=True,
    )


def _read_declared_body(environ: dict[str, Any]) -> tuple[bytes | None, str | None]:
    """Read exactly the declared request body for content verification.

    Returns ``(body, None)`` on success or ``(None, message)`` when the
    ``Content-Length`` header is missing or malformed, the stream cannot be
    read, or fewer bytes than declared are available. An explicitly declared
    length of zero is a valid empty body, not a missing one.
    """

    raw_length = environ.get("CONTENT_LENGTH")
    if not isinstance(raw_length, str):
        return None, "Content-Length header is required."
    if _NON_NEGATIVE_INT_PATTERN.fullmatch(raw_length) is None:
        return None, "Content-Length header must be a non-negative integer."
    length = int(raw_length)

    try:
        body = environ["wsgi.input"].read(length)
    except Exception:
        return None, "Request body could not be read."
    if not isinstance(body, (bytes, bytearray)) or len(body) != length:
        return None, "Request body is incomplete."
    return bytes(body), None


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

    content_type = str(environ.get("CONTENT_TYPE", ""))
    if content_type.lower() != _OCTET_STREAM_CONTENT_TYPE:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            "Content-Type must be application/octet-stream.",
        )

    body, body_error = _read_declared_body(environ)
    if body_error is not None:
        return _error(
            start_response, "400 Bad Request", "invalid_request", body_error
        )
    assert body is not None

    resource = store.get(raw_id)
    if resource is None:
        return _error(
            start_response,
            "404 Not Found",
            "resource_not_found",
            "No resource exists with the requested id.",
        )

    digest = hashlib.sha256(body).hexdigest()
    return _json_response(
        start_response,
        "200 OK",
        {"id": resource.id, "digest": digest, "valid": digest == resource.digest},
        trailing_newline=True,
    )


def _chunk_status_response(
    start_response: StartResponse,
    status: str,
    resource_id: str,
    index: int,
    total: int,
    digest: str,
    received: int,
) -> Iterable[bytes]:
    return _json_response(
        start_response,
        status,
        {
            "id": resource_id,
            "index": index,
            "total_chunks": total,
            "received_chunks": received,
            "digest": digest,
        },
        trailing_newline=True,
    )


def _handle_chunk(
    method: str,
    environ: dict[str, Any],
    raw_id: str,
    raw_index: str,
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

    # The chunk index is part of the path and must be a non-negative decimal
    # integer; anything else (including separators) is a bad request.
    if _NON_NEGATIVE_INT_PATTERN.fullmatch(raw_index) is None:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            "Chunk index must be a non-negative decimal integer.",
        )
    index = int(raw_index)

    content_type = str(environ.get("CONTENT_TYPE", ""))
    if content_type.lower() != _OCTET_STREAM_CONTENT_TYPE:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            "Content-Type must be application/octet-stream.",
        )

    raw_total = environ.get(_TOTAL_CHUNKS_HEADER)
    if not isinstance(raw_total, str) or not raw_total:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            f"{_TOTAL_CHUNKS_HEADER_NAME} header is required.",
        )
    if _POSITIVE_INT_PATTERN.fullmatch(raw_total) is None:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            f"{_TOTAL_CHUNKS_HEADER_NAME} header must be a positive integer.",
        )
    total = int(raw_total)
    if index >= total:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            "Chunk index must be smaller than the total chunk count.",
        )

    raw_digest = environ.get(_CONTENT_DIGEST_HEADER)
    if not isinstance(raw_digest, str) or _DIGEST_PATTERN.fullmatch(
        raw_digest
    ) is None:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            f"{_CONTENT_DIGEST_HEADER_NAME} header must be a 64-character "
            "hexadecimal digest.",
        )
    digest = raw_digest.lower()

    body, body_error = _read_declared_body(environ)
    if body_error is not None:
        return _error(
            start_response, "400 Bad Request", "invalid_request", body_error
        )
    assert body is not None

    resource = store.get(raw_id)
    if resource is None:
        return _error(
            start_response,
            "404 Not Found",
            "resource_not_found",
            "No resource exists with the requested id.",
        )

    if content_store.is_complete(raw_id):
        return _error(
            start_response,
            "409 Conflict",
            "content_already_complete",
            "Content for this resource is already complete.",
        )

    try:
        created, received = content_store.add_chunk(
            raw_id, total, digest, resource.digest, index, body
        )
    except ContentError as exc:
        return _error(
            start_response, "409 Conflict", exc.code, exc.message
        )

    return _chunk_status_response(
        start_response,
        "201 Created" if created else "200 OK",
        raw_id,
        index,
        total,
        digest,
        received,
    )


def _handle_chunks_status(
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

    # Read-only: no session is created when upload has not started.
    status = content_store.session_status(raw_id)
    if status is None:
        return _error(
            start_response,
            "409 Conflict",
            "chunks_not_started",
            "No chunk upload has been started for this resource.",
        )

    return _json_response(
        start_response,
        "200 OK",
        {
            "id": raw_id,
            "digest": status.digest,
            "total_chunks": status.total,
            "received_chunks": status.received_chunks,
            "missing_chunks": list(status.missing_chunks),
            "complete": status.complete,
            "size": status.size,
        },
        trailing_newline=True,
    )


def _handle_assemble(
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

    try:
        digest, size = content_store.assemble(raw_id)
    except ContentError as exc:
        return _error(
            start_response, "409 Conflict", exc.code, exc.message
        )

    return _json_response(
        start_response,
        "201 Created",
        {"id": raw_id, "digest": digest, "size": size},
        trailing_newline=True,
    )


def _handle_content(
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

    try:
        body = content_store.get_content(raw_id)
    except ContentError as exc:
        return _error(
            start_response, "409 Conflict", exc.code, exc.message
        )

    # The finalized artifact is returned as raw bytes only: no JSON wrapper
    # and no trailing newline.
    start_response(
        "200 OK",
        [
            ("Content-Type", "application/octet-stream"),
            ("Content-Length", str(len(body))),
        ],
    )
    return [body]


def _lifecycle_response(
    start_response: StartResponse,
    status: str,
    resource_id: str,
    record: LifecycleRecord,
) -> Iterable[bytes]:
    return _json_response(
        start_response,
        status,
        {"id": resource_id, "state": record.state, "reason": record.reason},
        trailing_newline=True,
    )


def _handle_lifecycle_get(
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
    return _lifecycle_response(
        start_response, "200 OK", raw_id, lifecycle_store.get(raw_id)
    )


def _handle_lifecycle_post(
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
    unknown_fields = set(payload) - {"state", "reason"}
    if unknown_fields:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            f"Unknown field: {sorted(unknown_fields)[0]!r}.",
        )
    if "state" not in payload:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            "Missing required field: 'state'.",
        )
    target = payload["state"]
    if not isinstance(target, str) or target not in STATE_VALUES:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            "Field 'state' must be one of: staged, released, withdrawn, "
            "quarantined (case-sensitive).",
        )

    reason: str | None = None
    if "reason" in payload:
        value = payload["reason"]
        if not isinstance(value, str):
            return _error(
                start_response,
                "400 Bad Request",
                "invalid_request",
                "Field 'reason' must be a string.",
            )
        if value == "":
            return _error(
                start_response,
                "400 Bad Request",
                "invalid_request",
                "Field 'reason' must not be empty.",
            )
        if len(value) > MAX_REASON_LENGTH:
            return _error(
                start_response,
                "400 Bad Request",
                "invalid_request",
                f"Field 'reason' must not exceed {MAX_REASON_LENGTH} "
                "Unicode code points.",
            )
        reason = value
    if target in REASON_REQUIRED_STATES and reason is None:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            f"Field 'reason' is required when the target state is "
            f"{target!r}.",
        )

    if store.get(raw_id) is None:
        return _error(
            start_response,
            "404 Not Found",
            "resource_not_found",
            "No resource exists with the requested id.",
        )

    current = lifecycle_store.get(raw_id)
    if (current.state, target) == ("staged", "released"):
        # Promotion requires assembled content and healthy dependencies.
        if not content_store.is_complete(raw_id):
            return _error(
                start_response,
                "409 Conflict",
                "content_not_complete",
                "Content for this resource is not complete.",
            )
        for dependency_id in store.list_dependencies(raw_id):
            if lifecycle_store.get(dependency_id).state in BLOCKING_STATES:
                return _error(
                    start_response,
                    "409 Conflict",
                    "dependency_blocked",
                    "A dependency of this resource is withdrawn or "
                    "quarantined.",
                )

    try:
        record = lifecycle_store.apply(current, target, reason)
    except LifecycleError as exc:
        return _error(
            start_response, "409 Conflict", exc.code, exc.message
        )

    # ``apply`` returns the very same record for an idempotent repeat; only a
    # real transition is stored, so a repeat never adds a record.
    if record is not current:
        lifecycle_store.set(raw_id, record)
    return _lifecycle_response(start_response, "200 OK", raw_id, record)


def _handle_lifecycle(
    method: str,
    environ: dict[str, Any],
    raw_id: str,
    start_response: StartResponse,
) -> Iterable[bytes]:
    if method == "GET":
        return _handle_lifecycle_get(environ, raw_id, start_response)
    if method == "POST":
        return _handle_lifecycle_post(environ, raw_id, start_response)
    return _error(
        start_response,
        "405 Method Not Allowed",
        "method_not_allowed",
        f"Method {method} is not allowed for this path.",
        allowed="GET, POST",
    )


def _handle_release_blockers(
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

    # Read-only, computed on the fly from the very same promotion checks as
    # the staged -> released transition, but never short-circuiting: both
    # reason codes and every blocked dependency are reported. Nothing is
    # recorded and no existing state is touched.
    content_complete = content_store.is_complete(raw_id)
    reasons: list[str] = []
    if not content_complete:
        reasons.append("content_not_complete")

    blockers: list[dict[str, str]] = []
    for dependency_id in store.list_dependencies(raw_id):
        state = lifecycle_store.get(dependency_id).state
        if state in BLOCKING_STATES:
            blockers.append({"resource_id": dependency_id, "state": state})
    if blockers:
        reasons.append("dependency_blocked")

    return _json_response(
        start_response,
        "200 OK",
        {
            "id": raw_id,
            "blocked": bool(reasons),
            "reasons": reasons,
            "blockers": blockers,
            "content_complete": content_complete,
        },
        trailing_newline=True,
    )


def _handle_vulnerabilities_post(
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

    try:
        # Validate the whole body before touching any store, so a bad request
        # can never leave a partial record and always answers 400 (even for a
        # resource that does not exist).
        build_vulnerability_fields(payload)
    except VulnerabilityValidationError as exc:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            exc.message,
        )

    if store.get(raw_id) is None:
        return _error(
            start_response,
            "404 Not Found",
            "resource_not_found",
            "No resource exists with the requested id.",
        )

    try:
        record = vulnerability_store.add(raw_id, payload)
    except VulnerabilityError as exc:
        return _error(
            start_response, "409 Conflict", exc.code, exc.message
        )

    return _json_response(
        start_response,
        "201 Created",
        record.to_dict(),
        trailing_newline=True,
    )


def _handle_vulnerabilities_batch(
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

    try:
        # Validate the whole batch before touching any store, so a bad
        # request can never leave a partial record and always answers 400
        # (even for a resource that does not exist). The normalized fields
        # are handed to the store, which performs only the duplicate-key
        # check and the atomic write; element validation lives here alone.
        fields = build_batch_fields(payload)
    except VulnerabilityValidationError as exc:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            exc.message,
        )

    if store.get(raw_id) is None:
        return _error(
            start_response,
            "404 Not Found",
            "resource_not_found",
            "No resource exists with the requested id.",
        )

    try:
        records = vulnerability_store.add_batch(raw_id, fields)
    except VulnerabilityError as exc:
        return _error(
            start_response, "409 Conflict", exc.code, exc.message
        )

    return _json_response(
        start_response,
        "201 Created",
        {"vulnerabilities": [record.to_dict() for record in records]},
        trailing_newline=True,
    )


def _handle_vulnerabilities_get(
    environ: dict[str, Any], raw_id: str, start_response: StartResponse
) -> Iterable[bytes]:
    id_error = _validate_path_id(raw_id)
    if id_error is not None:
        return _error(
            start_response, "400 Bad Request", "invalid_request", id_error
        )

    # Only the optional ``severity`` parameter is accepted; unknown or
    # repeated parameters, including a repeated ``severity``, are rejected.
    severity, severity_error = _parse_severity_query(
        str(environ.get("QUERY_STRING", ""))
    )
    if severity_error is not None:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            severity_error,
        )

    if store.get(raw_id) is None:
        return _error(
            start_response,
            "404 Not Found",
            "resource_not_found",
            "No resource exists with the requested id.",
        )

    records = vulnerability_store.list_for(raw_id, severity)
    return _json_response(
        start_response,
        "200 OK",
        {"vulnerabilities": [record.to_dict() for record in records]},
        trailing_newline=True,
    )


def _handle_vulnerabilities(
    method: str,
    environ: dict[str, Any],
    raw_id: str,
    start_response: StartResponse,
) -> Iterable[bytes]:
    if method == "POST":
        return _handle_vulnerabilities_post(environ, raw_id, start_response)
    if method == "GET":
        return _handle_vulnerabilities_get(environ, raw_id, start_response)
    return _error(
        start_response,
        "405 Method Not Allowed",
        "method_not_allowed",
        f"Method {method} is not allowed for this path.",
        allowed="GET, POST",
    )


def _handle_vulnerability_item_put(
    environ: dict[str, Any],
    raw_id: str,
    raw_vulnerability_id: str,
    start_response: StartResponse,
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
        # Validate the whole body before touching any store, so a bad request
        # can never leave a partial update and always answers 400 (even for
        # a resource or alert that does not exist).
        build_vulnerability_fields(payload)
    except VulnerabilityValidationError as exc:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            exc.message,
        )

    if store.get(raw_id) is None:
        return _error(
            start_response,
            "404 Not Found",
            "resource_not_found",
            "No resource exists with the requested id.",
        )

    try:
        record = vulnerability_store.update(
            raw_id, raw_vulnerability_id, payload
        )
    except VulnerabilityValidationError as exc:
        # The body is well formed but its advisory/component pair does not
        # match the alert identified by the path: the pair is the alert's
        # identity and cannot be changed.
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            exc.message,
        )
    except VulnerabilityError as exc:
        return _error(
            start_response, "404 Not Found", exc.code, exc.message
        )

    return _json_response(
        start_response,
        "200 OK",
        record.to_dict(),
        trailing_newline=True,
    )


def _handle_vulnerability_item(
    method: str,
    environ: dict[str, Any],
    raw_id: str,
    raw_vulnerability_id: str,
    start_response: StartResponse,
) -> Iterable[bytes]:
    if method not in ("DELETE", "PUT"):
        return _error(
            start_response,
            "405 Method Not Allowed",
            "method_not_allowed",
            f"Method {method} is not allowed for this path.",
            allowed="PUT",
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

    if (
        not raw_vulnerability_id
        or "/" in raw_vulnerability_id
        or "\\" in raw_vulnerability_id
    ):
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            "Vulnerability id must not be empty or contain path separators.",
        )

    if method == "PUT":
        return _handle_vulnerability_item_put(
            environ, raw_id, raw_vulnerability_id, start_response
        )

    body_error = _bodyless_request_error(environ)
    if body_error is not None:
        return _error(
            start_response, "400 Bad Request", "invalid_request", body_error
        )

    if store.get(raw_id) is None:
        return _error(
            start_response,
            "404 Not Found",
            "resource_not_found",
            "No resource exists with the requested id.",
        )

    try:
        record = vulnerability_store.remove(raw_id, raw_vulnerability_id)
    except VulnerabilityError as exc:
        return _error(
            start_response, "404 Not Found", exc.code, exc.message
        )

    return _json_response(
        start_response,
        "200 OK",
        record.to_dict(),
        trailing_newline=True,
    )


def _handle_vulnerability_exceptions_post(
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

    # Validate the whole body before touching any store, so a bad request
    # can never leave a partial exemption.
    try:
        build_exception_fields(payload)
    except VulnerabilityExceptionValidationError as exc:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            exc.message,
        )

    if store.get(raw_id) is None:
        return _error(
            start_response,
            "404 Not Found",
            "resource_not_found",
            "No resource exists with the requested id.",
        )

    # The exemption must verbatim match one of the resource's alerts; the
    # store rejects duplicates and missing alerts without recording anything.
    try:
        record = vulnerability_exception_store.add(
            raw_id, payload, vulnerability_store.list_for(raw_id)
        )
    except VulnerabilityExceptionError as exc:
        http_status = (
            "404 Not Found"
            if exc.code == "vulnerability_not_found"
            else "409 Conflict"
        )
        return _error(
            start_response, http_status, exc.code, exc.message
        )

    return _json_response(
        start_response,
        "201 Created",
        record.to_dict(),
        trailing_newline=True,
    )


def _handle_vulnerability_exceptions_get(
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

    records = vulnerability_exception_store.list_for(raw_id)
    return _json_response(
        start_response,
        "200 OK",
        {"exceptions": [record.to_dict() for record in records]},
        trailing_newline=True,
    )


def _handle_vulnerability_exception_item(
    method: str,
    environ: dict[str, Any],
    raw_id: str,
    raw_exception_id: str,
    start_response: StartResponse,
) -> Iterable[bytes]:
    if method != "DELETE":
        return _error(
            start_response,
            "405 Method Not Allowed",
            "method_not_allowed",
            f"Method {method} is not allowed for this path.",
            allowed="DELETE",
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
    body_error = _bodyless_request_error(environ)
    if body_error is not None:
        return _error(
            start_response, "400 Bad Request", "invalid_request", body_error
        )

    if not raw_exception_id or "/" in raw_exception_id or "\\" in raw_exception_id:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            "Exception id must not be empty or contain path separators.",
        )

    if store.get(raw_id) is None:
        return _error(
            start_response,
            "404 Not Found",
            "resource_not_found",
            "No resource exists with the requested id.",
        )

    try:
        record = vulnerability_exception_store.remove(raw_id, raw_exception_id)
    except VulnerabilityExceptionError as exc:
        return _error(
            start_response, "404 Not Found", exc.code, exc.message
        )

    return _json_response(
        start_response,
        "200 OK",
        record.to_dict(),
        trailing_newline=True,
    )


def _handle_vulnerability_exceptions(
    method: str,
    environ: dict[str, Any],
    raw_id: str,
    start_response: StartResponse,
) -> Iterable[bytes]:
    if method == "POST":
        return _handle_vulnerability_exceptions_post(
            environ, raw_id, start_response
        )
    if method == "GET":
        return _handle_vulnerability_exceptions_get(
            environ, raw_id, start_response
        )
    return _error(
        start_response,
        "405 Method Not Allowed",
        "method_not_allowed",
        f"Method {method} is not allowed for this path.",
        allowed="GET, POST",
    )


def _handle_sbom_post(
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

    # Validate the whole body before touching any store, so a bad request
    # can never leave a partial document.
    try:
        build_sbom_fields(payload)
    except SbomValidationError as exc:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            exc.message,
        )

    if store.get(raw_id) is None:
        return _error(
            start_response,
            "404 Not Found",
            "resource_not_found",
            "No resource exists with the requested id.",
        )

    try:
        document, created = sbom_store.add_sbom(raw_id, payload)
    except SbomError as exc:
        return _error(
            start_response, "409 Conflict", exc.code, exc.message
        )

    return _json_response(
        start_response,
        "201 Created" if created else "200 OK",
        document.to_dict(raw_id),
        trailing_newline=True,
    )


def _handle_sbom_get(
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

    document = sbom_store.get_sbom(raw_id)
    if document is None:
        return _error(
            start_response,
            "404 Not Found",
            "sbom_not_found",
            "No SBOM document is recorded for this resource.",
        )

    return _json_response(
        start_response,
        "200 OK",
        document.to_dict(raw_id),
        trailing_newline=True,
    )


def _handle_sbom(
    method: str,
    environ: dict[str, Any],
    raw_id: str,
    start_response: StartResponse,
) -> Iterable[bytes]:
    if method == "POST":
        return _handle_sbom_post(environ, raw_id, start_response)
    if method == "GET":
        return _handle_sbom_get(environ, raw_id, start_response)
    return _error(
        start_response,
        "405 Method Not Allowed",
        "method_not_allowed",
        f"Method {method} is not allowed for this path.",
        allowed="GET, POST",
    )


def _handle_license_post(
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

    from .sbom import build_license_fields

    try:
        build_license_fields(payload)
    except SbomValidationError as exc:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            exc.message,
        )

    if store.get(raw_id) is None:
        return _error(
            start_response,
            "404 Not Found",
            "resource_not_found",
            "No resource exists with the requested id.",
        )

    try:
        record, created = sbom_store.add_license(raw_id, payload)
    except SbomError as exc:
        return _error(
            start_response, "409 Conflict", exc.code, exc.message
        )

    return _json_response(
        start_response,
        "201 Created" if created else "200 OK",
        record.to_dict(raw_id),
        trailing_newline=True,
    )


def _handle_license_get(
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

    record = sbom_store.get_license(raw_id)
    if record is None:
        return _error(
            start_response,
            "404 Not Found",
            "license_not_found",
            "No license is declared for this resource.",
        )

    return _json_response(
        start_response,
        "200 OK",
        record.to_dict(raw_id),
        trailing_newline=True,
    )


def _handle_license(
    method: str,
    environ: dict[str, Any],
    raw_id: str,
    start_response: StartResponse,
) -> Iterable[bytes]:
    if method == "POST":
        return _handle_license_post(environ, raw_id, start_response)
    if method == "GET":
        return _handle_license_get(environ, raw_id, start_response)
    return _error(
        start_response,
        "405 Method Not Allowed",
        "method_not_allowed",
        f"Method {method} is not allowed for this path.",
        allowed="GET, POST",
    )


def _handle_provenance_post(
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

    # Validate the whole body before touching any store, so a bad request
    # can never leave a partial record.
    try:
        build_provenance_fields(payload)
    except ProvenanceValidationError as exc:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            exc.message,
        )

    if store.get(raw_id) is None:
        return _error(
            start_response,
            "404 Not Found",
            "resource_not_found",
            "No resource exists with the requested id.",
        )

    try:
        record, created = provenance_store.add(raw_id, payload)
    except ProvenanceError as exc:
        return _error(
            start_response, "409 Conflict", exc.code, exc.message
        )

    return _json_response(
        start_response,
        "201 Created" if created else "200 OK",
        record.to_dict(raw_id),
        trailing_newline=True,
    )


def _handle_provenance_get(
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

    record = provenance_store.get(raw_id)
    if record is None:
        return _error(
            start_response,
            "404 Not Found",
            "provenance_not_found",
            "No provenance is registered for this resource.",
        )

    return _json_response(
        start_response,
        "200 OK",
        record.to_dict(raw_id),
        trailing_newline=True,
    )


def _handle_provenance(
    method: str,
    environ: dict[str, Any],
    raw_id: str,
    start_response: StartResponse,
) -> Iterable[bytes]:
    if method == "POST":
        return _handle_provenance_post(environ, raw_id, start_response)
    if method == "GET":
        return _handle_provenance_get(environ, raw_id, start_response)
    return _error(
        start_response,
        "405 Method Not Allowed",
        "method_not_allowed",
        f"Method {method} is not allowed for this path.",
        allowed="GET, POST",
    )


def _handle_policies_post(
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

    # Validate the whole body before touching any store, so a bad request
    # can never leave a partial policy.
    try:
        build_policy_fields(payload)
    except PolicyValidationError as exc:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            exc.message,
        )

    if store.get(raw_id) is None:
        return _error(
            start_response,
            "404 Not Found",
            "resource_not_found",
            "No resource exists with the requested id.",
        )

    try:
        record, created = policy_store.add(raw_id, payload)
    except PolicyError as exc:
        return _error(
            start_response, "409 Conflict", exc.code, exc.message
        )

    return _json_response(
        start_response,
        "201 Created" if created else "200 OK",
        record.to_dict(raw_id),
        trailing_newline=True,
    )


def _handle_policies_get(
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

    record = policy_store.get(raw_id)
    if record is None:
        return _error(
            start_response,
            "404 Not Found",
            "policy_not_found",
            "No policy is registered for this resource.",
        )

    return _json_response(
        start_response,
        "200 OK",
        record.to_dict(raw_id),
        trailing_newline=True,
    )


def _handle_policies(
    method: str,
    environ: dict[str, Any],
    raw_id: str,
    start_response: StartResponse,
) -> Iterable[bytes]:
    if method == "POST":
        return _handle_policies_post(environ, raw_id, start_response)
    if method == "GET":
        return _handle_policies_get(environ, raw_id, start_response)
    return _error(
        start_response,
        "405 Method Not Allowed",
        "method_not_allowed",
        f"Method {method} is not allowed for this path.",
        allowed="GET, POST",
    )


def _handle_default_policy_post(
    environ: dict[str, Any], start_response: StartResponse
) -> Iterable[bytes]:
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

    # Validate the whole body before touching the store, so a bad request
    # can never leave a partial policy.
    try:
        build_policy_fields(payload)
    except PolicyValidationError as exc:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            exc.message,
        )

    try:
        record, created = default_policy_store.add(payload)
    except PolicyError as exc:
        return _error(
            start_response, "409 Conflict", exc.code, exc.message
        )

    # The echo is the policy content alone; no resource identifier exists
    # for the global default.
    return _json_response(
        start_response,
        "201 Created" if created else "200 OK",
        record.to_policy_dict(),
        trailing_newline=True,
    )


def _handle_default_policy_get(
    environ: dict[str, Any], start_response: StartResponse
) -> Iterable[bytes]:
    query_error = _query_parameter_error(environ)
    if query_error is not None:
        return _error(
            start_response, "400 Bad Request", "invalid_request", query_error
        )
    body_error = _bodyless_request_error(environ)
    if body_error is not None:
        return _error(
            start_response, "400 Bad Request", "invalid_request", body_error
        )

    record = default_policy_store.get()
    if record is None:
        return _error(
            start_response,
            "404 Not Found",
            "policy_not_found",
            "No global default policy is registered.",
        )

    return _json_response(
        start_response,
        "200 OK",
        record.to_policy_dict(),
        trailing_newline=True,
    )


def _handle_default_policy(
    method: str,
    environ: dict[str, Any],
    start_response: StartResponse,
) -> Iterable[bytes]:
    if method == "POST":
        return _handle_default_policy_post(environ, start_response)
    if method == "GET":
        return _handle_default_policy_get(environ, start_response)
    return _error(
        start_response,
        "405 Method Not Allowed",
        "method_not_allowed",
        f"Method {method} is not allowed for this path.",
        allowed="GET, POST",
    )


def _admission_body_error(environ: dict[str, Any]) -> str | None:
    """Reject an admission request that declares or carries a body."""

    raw_length = environ.get("CONTENT_LENGTH")
    if raw_length is None:
        return None
    if (
        not isinstance(raw_length, str)
        or _NON_NEGATIVE_INT_PATTERN.fullmatch(raw_length) is None
        or int(raw_length) > 0
    ):
        return "This endpoint does not accept a request body."
    return None


def _bodyless_request_error(environ: dict[str, Any]) -> str | None:
    """Reject a bodyless endpoint (cache DELETE) that declares a body.

    Unlike admission, this also treats an empty-string ``Content-Length``
    as no body: a real WSGI server seeds ``CONTENT_LENGTH`` with ``''``
    for requests that omit the header entirely (e.g. curl's bodyless
    DELETE), so only a declared positive or malformed length is rejected.
    An explicit ``Content-Length: 0`` is an empty body and is accepted.
    """

    raw_length = environ.get("CONTENT_LENGTH")
    if raw_length is None or raw_length == "":
        return None
    if (
        not isinstance(raw_length, str)
        or _NON_NEGATIVE_INT_PATTERN.fullmatch(raw_length) is None
        or int(raw_length) > 0
    ):
        return "This endpoint does not accept a request body."
    return None


def _handle_admission(
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
    body_error = _admission_body_error(environ)
    if body_error is not None:
        return _error(
            start_response, "400 Bad Request", "invalid_request", body_error
        )

    if store.get(raw_id) is None:
        return _error(
            start_response,
            "404 Not Found",
            "resource_not_found",
            "No resource exists with the requested id.",
        )

    policy = policy_store.get(raw_id)
    if policy is None:
        # Resources without their own policy fall back to the single
        # global default policy; the evaluation itself is unchanged.
        policy = default_policy_store.get()
    if policy is None:
        return _error(
            start_response,
            "404 Not Found",
            "policy_not_found",
            "No policy is registered for this resource.",
        )

    license_record = sbom_store.get_license(raw_id)
    allowed, reasons = evaluate_policy(
        policy,
        lifecycle_state=lifecycle_store.get(raw_id).state,
        has_sbom=sbom_store.get_sbom(raw_id) is not None,
        has_license=license_record is not None,
        has_provenance=provenance_store.get(raw_id) is not None,
        has_signature=signature_store.get(raw_id) is not None,
        license_spdx_id=(
            license_record.spdx_id if license_record is not None else None
        ),
        severities=[
            alert.severity for alert in vulnerability_store.list_for(raw_id)
        ],
    )

    return _json_response(
        start_response,
        "200 OK",
        {"id": raw_id, "allowed": allowed, "reasons": reasons},
        trailing_newline=True,
    )


def _handle_admission_preview(
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

    policy = policy_store.get(raw_id)
    if policy is None:
        # Same fallback as the admission evaluation: the global default
        # policy applies when the resource has none of its own.
        policy = default_policy_store.get()
    if policy is None:
        return _error(
            start_response,
            "404 Not Found",
            "policy_not_found",
            "No policy is registered for this resource.",
        )

    # The decision is identical to the admission evaluation except that
    # alerts verbatim matching a registered exemption do not count toward
    # the severity ceiling. Matching follows the exemption rule exactly:
    # advisory and component compared byte-for-byte, case-sensitive.
    exempted_keys = vulnerability_exception_store.exempted_keys(raw_id)
    active_severities: list[str] = []
    exempted_count = 0
    for alert in vulnerability_store.list_for(raw_id):
        if (alert.advisory, alert.component) in exempted_keys:
            exempted_count += 1
        else:
            active_severities.append(alert.severity)

    license_record = sbom_store.get_license(raw_id)
    allowed, reasons = evaluate_policy(
        policy,
        lifecycle_state=lifecycle_store.get(raw_id).state,
        has_sbom=sbom_store.get_sbom(raw_id) is not None,
        has_license=license_record is not None,
        has_provenance=provenance_store.get(raw_id) is not None,
        has_signature=signature_store.get(raw_id) is not None,
        license_spdx_id=(
            license_record.spdx_id if license_record is not None else None
        ),
        severities=active_severities,
    )

    return _json_response(
        start_response,
        "200 OK",
        {
            "id": raw_id,
            "allowed": allowed,
            "reasons": reasons,
            "exempted_count": exempted_count,
        },
        trailing_newline=True,
    )


def _handle_risk(
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

    # Read-only, computed on the fly: the score is never recorded anywhere.
    license_record = sbom_store.get_license(raw_id)
    policy = policy_store.get(raw_id)
    if policy is None:
        # Without a resource policy the license allowlist comes from the
        # global default policy, if one is registered.
        policy = default_policy_store.get()
    score = compute_risk_score(
        severities=[
            alert.severity for alert in vulnerability_store.list_for(raw_id)
        ],
        has_sbom=sbom_store.get_sbom(raw_id) is not None,
        has_license=license_record is not None,
        has_provenance=provenance_store.get(raw_id) is not None,
        has_signature=signature_store.get(raw_id) is not None,
        lifecycle_state=lifecycle_store.get(raw_id).state,
        license_allowlist=(
            policy.license_allowlist if policy is not None else ()
        ),
        license_spdx_id=(
            license_record.spdx_id if license_record is not None else None
        ),
    )

    return _json_response(
        start_response,
        "200 OK",
        {"id": raw_id, "score": score, "level": risk_level(score)},
        trailing_newline=True,
    )


def _handle_component_risks(
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

    document = sbom_store.get_sbom(raw_id)
    if document is None:
        return _error(
            start_response,
            "404 Not Found",
            "sbom_not_found",
            "No SBOM document is recorded for this resource.",
        )

    # Read-only, computed on the fly: an alert hits a component only when
    # the names are byte-for-byte identical (case-sensitive, no trimming);
    # versions and digests are never compared. Nothing is recorded.
    alerts = vulnerability_store.list_for(raw_id)
    components = [
        {
            "name": component.name,
            "version": component.version,
            "digest": component.digest,
            "advisories": [
                {"id": alert.id, "severity": alert.severity}
                for alert in alerts
                if alert.component == component.name
            ],
        }
        for component in document.components
    ]

    return _json_response(
        start_response,
        "200 OK",
        {"components": components},
        trailing_newline=True,
    )


def _handle_component_fixes(
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

    document = sbom_store.get_sbom(raw_id)
    if document is None:
        return _error(
            start_response,
            "404 Not Found",
            "sbom_not_found",
            "No SBOM document is recorded for this resource.",
        )

    # Read-only, computed on the fly: like component-risks, an alert hits a
    # component only when the names are byte-for-byte identical
    # (case-sensitive, no trimming); versions and summaries never take part.
    # The recommendation is the greatest numeric fixed version among the
    # hits; non-numeric candidates and missing ones are ignored, and nothing
    # is ever recorded.
    alerts = vulnerability_store.list_for(raw_id)
    fixes: list[dict[str, object]] = []
    for component in document.components:
        hits = [
            alert
            for alert in alerts
            if alert.component == component.name
        ]
        fixes.append(
            {
                "name": component.name,
                "version": component.version,
                "recommended_version": recommended_fix_version(
                    alert.fixed_version for alert in hits
                ),
                "advisory_count": len(hits),
            }
        )

    return _json_response(
        start_response,
        "200 OK",
        {"fixes": fixes},
        trailing_newline=True,
    )


def _handle_notifications_post(
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

    # Validate the whole body before touching any store, so a bad request
    # can never leave a partial record and always answers 400 (even for a
    # resource that does not exist).
    try:
        build_notification_fields(payload)
    except NotificationValidationError as exc:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            exc.message,
        )

    if store.get(raw_id) is None:
        return _error(
            start_response,
            "404 Not Found",
            "resource_not_found",
            "No resource exists with the requested id.",
        )

    record = notification_store.add(raw_id, payload)
    return _json_response(
        start_response,
        "201 Created",
        record.to_dict(),
        trailing_newline=True,
    )


def _handle_notifications_get(
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

    records = notification_store.list_for(raw_id)
    return _json_response(
        start_response,
        "200 OK",
        {"notifications": [record.to_dict() for record in records]},
        trailing_newline=True,
    )


def _handle_notifications(
    method: str,
    environ: dict[str, Any],
    raw_id: str,
    start_response: StartResponse,
) -> Iterable[bytes]:
    if method == "POST":
        return _handle_notifications_post(environ, raw_id, start_response)
    if method == "GET":
        return _handle_notifications_get(environ, raw_id, start_response)
    return _error(
        start_response,
        "405 Method Not Allowed",
        "method_not_allowed",
        f"Method {method} is not allowed for this path.",
        allowed="GET, POST",
    )


def _handle_cache_layer_post(
    environ: dict[str, Any], raw_digest: str, start_response: StartResponse
) -> Iterable[bytes]:
    # The path digest is validated before anything else so a malformed
    # digest is rejected without reading the request body.
    if _DIGEST_PATTERN.fullmatch(raw_digest) is None:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            "Layer digest must be a 64-character hexadecimal string.",
        )
    digest = raw_digest.lower()

    query_error = _query_parameter_error(environ)
    if query_error is not None:
        return _error(
            start_response, "400 Bad Request", "invalid_request", query_error
        )

    content_type = str(environ.get("CONTENT_TYPE", ""))
    if content_type.lower() != _OCTET_STREAM_CONTENT_TYPE:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            "Content-Type must be application/octet-stream.",
        )

    body, body_error = _read_declared_body(environ)
    if body_error is not None:
        return _error(
            start_response, "400 Bad Request", "invalid_request", body_error
        )
    assert body is not None

    try:
        created, entries = cache_store.put(digest, body)
    except CacheError as exc:
        return _error(
            start_response, "409 Conflict", exc.code, exc.message
        )

    return _json_response(
        start_response,
        "201 Created" if created else "200 OK",
        {"digest": digest, "size": len(body), "entries": entries},
        trailing_newline=True,
    )


def _handle_cache_layer_get(
    environ: dict[str, Any], raw_digest: str, start_response: StartResponse
) -> Iterable[bytes]:
    if _DIGEST_PATTERN.fullmatch(raw_digest) is None:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            "Layer digest must be a 64-character hexadecimal string.",
        )
    digest = raw_digest.lower()

    query_error = _query_parameter_error(environ)
    if query_error is not None:
        return _error(
            start_response, "400 Bad Request", "invalid_request", query_error
        )

    data = cache_store.get(digest)
    if data is None:
        return _error(
            start_response,
            "404 Not Found",
            "cache_miss",
            "No layer is cached for the requested digest.",
        )

    # A hit returns the raw cached bytes only: no JSON wrapper and no
    # trailing newline.
    start_response(
        "200 OK",
        [
            ("Content-Type", "application/octet-stream"),
            ("Content-Length", str(len(data))),
        ],
    )
    return [data]


def _handle_cache_layer_delete(
    environ: dict[str, Any], raw_digest: str, start_response: StartResponse
) -> Iterable[bytes]:
    # Same ordering as a write: the path digest is rejected before the
    # request body is ever considered.
    if _DIGEST_PATTERN.fullmatch(raw_digest) is None:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            "Layer digest must be a 64-character hexadecimal string.",
        )
    digest = raw_digest.lower()

    query_error = _query_parameter_error(environ)
    if query_error is not None:
        return _error(
            start_response, "400 Bad Request", "invalid_request", query_error
        )

    # Deletion carries no body; a declared non-empty or malformed body is
    # rejected without being read.
    body_error = _bodyless_request_error(environ)
    if body_error is not None:
        return _error(
            start_response, "400 Bad Request", "invalid_request", body_error
        )

    try:
        size, entries = cache_store.remove(digest)
    except CacheError as exc:
        # Deleting a missing or already deleted digest is a miss.
        return _error(
            start_response, "404 Not Found", exc.code, exc.message
        )

    return _json_response(
        start_response,
        "200 OK",
        {"digest": digest, "size": size, "entries": entries},
        trailing_newline=True,
    )


def _handle_cache_layer(
    method: str,
    environ: dict[str, Any],
    raw_digest: str,
    start_response: StartResponse,
) -> Iterable[bytes]:
    if method == "POST":
        return _handle_cache_layer_post(environ, raw_digest, start_response)
    if method == "GET":
        return _handle_cache_layer_get(environ, raw_digest, start_response)
    if method == "DELETE":
        return _handle_cache_layer_delete(environ, raw_digest, start_response)
    return _error(
        start_response,
        "405 Method Not Allowed",
        "method_not_allowed",
        f"Method {method} is not allowed for this path.",
        allowed="DELETE, GET, POST",
    )


def _handle_cache_root(
    method: str, environ: dict[str, Any], start_response: StartResponse
) -> Iterable[bytes]:
    if method != "DELETE":
        return _error(
            start_response,
            "405 Method Not Allowed",
            "method_not_allowed",
            f"Method {method} is not allowed for this path.",
            allowed="DELETE",
        )

    query_error = _query_parameter_error(environ)
    if query_error is not None:
        return _error(
            start_response, "400 Bad Request", "invalid_request", query_error
        )

    body_error = _bodyless_request_error(environ)
    if body_error is not None:
        return _error(
            start_response, "400 Bad Request", "invalid_request", body_error
        )

    # Clearing an already empty cache is an idempotent success with zero
    # counts; the hit/miss counters are deliberately preserved.
    removed, freed_bytes = cache_store.clear()
    return _json_response(
        start_response,
        "200 OK",
        {"removed": removed, "freed_bytes": freed_bytes},
        trailing_newline=True,
    )


def _handle_cache_status(
    method: str, environ: dict[str, Any], start_response: StartResponse
) -> Iterable[bytes]:
    if method != "GET":
        return _error(
            start_response,
            "405 Method Not Allowed",
            "method_not_allowed",
            f"Method {method} is not allowed for this path.",
            allowed="GET",
        )

    query_error = _query_parameter_error(environ)
    if query_error is not None:
        return _error(
            start_response, "400 Bad Request", "invalid_request", query_error
        )

    # Read-only: reporting never changes entries, usage or counters.
    status = cache_store.status()
    return _json_response(
        start_response,
        "200 OK",
        {
            "entries": status.entries,
            "used_bytes": status.used_bytes,
            "quota": status.quota,
            "hits": status.hits,
            "misses": status.misses,
        },
        trailing_newline=True,
    )


def _handle_mirrors_get(
    environ: dict[str, Any], start_response: StartResponse
) -> Iterable[bytes]:
    query_error = _query_parameter_error(environ)
    if query_error is not None:
        return _error(
            start_response, "400 Bad Request", "invalid_request", query_error
        )

    # Mirrors are returned in registration order; an empty registry is a
    # valid empty array.
    return _json_response(
        start_response,
        "200 OK",
        {"mirrors": [mirror.to_dict() for mirror in mirror_store.list_all()]},
        trailing_newline=True,
    )


def _handle_mirrors_post(
    environ: dict[str, Any], start_response: StartResponse
) -> Iterable[bytes]:
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

    # Validate the whole body before touching the store, so a bad request
    # can never leave a partial mirror.
    try:
        created, existing = mirror_store.add(payload)
    except MirrorValidationError as exc:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            exc.message,
        )

    if existing is not None:
        # Names are globally unique; the original mirror is never overwritten.
        return _error(
            start_response,
            "409 Conflict",
            "duplicate_mirror",
            "A mirror with the same name already exists.",
        )

    assert created is not None
    return _json_response(
        start_response, "201 Created", created.to_dict(), trailing_newline=True
    )


def _mirror_id_error(raw_id: str) -> str | None:
    """Return a stable error message for an invalid mirror id, else ``None``."""

    if not raw_id:
        return "Mirror id must not be empty."
    if "/" in raw_id or "\\" in raw_id:
        return "Mirror id must not contain path separators."
    return None


def _handle_mirror_item_get(
    environ: dict[str, Any], raw_id: str, start_response: StartResponse
) -> Iterable[bytes]:
    id_error = _mirror_id_error(raw_id)
    if id_error is not None:
        return _error(
            start_response, "400 Bad Request", "invalid_request", id_error
        )

    query_error = _query_parameter_error(environ)
    if query_error is not None:
        return _error(
            start_response, "400 Bad Request", "invalid_request", query_error
        )

    mirror = mirror_store.get(raw_id)
    if mirror is None:
        return _error(
            start_response,
            "404 Not Found",
            "mirror_not_found",
            "No mirror exists with the requested id.",
        )

    return _json_response(
        start_response, "200 OK", mirror.to_dict(), trailing_newline=True
    )


def _handle_mirror_item_delete(
    environ: dict[str, Any], raw_id: str, start_response: StartResponse
) -> Iterable[bytes]:
    id_error = _mirror_id_error(raw_id)
    if id_error is not None:
        return _error(
            start_response, "400 Bad Request", "invalid_request", id_error
        )

    query_error = _query_parameter_error(environ)
    if query_error is not None:
        return _error(
            start_response, "400 Bad Request", "invalid_request", query_error
        )

    # Deletion carries no body; a declared non-empty or malformed body is
    # rejected without being read and without touching any state.
    body_error = _bodyless_request_error(environ)
    if body_error is not None:
        return _error(
            start_response, "400 Bad Request", "invalid_request", body_error
        )

    mirror = mirror_store.remove(raw_id)
    if mirror is None:
        return _error(
            start_response,
            "404 Not Found",
            "mirror_not_found",
            "No mirror exists with the requested id.",
        )

    # Deleting a mirror also drops its signature policy; the echo still
    # only carries the mirror fields. Cache entries, counters and every
    # other record are deliberately left alone.
    mirror_policy_store.remove(raw_id)
    mirror_probe_store.discard(raw_id)

    return _json_response(
        start_response, "200 OK", mirror.to_dict(), trailing_newline=True
    )


def _handle_mirror_item(
    method: str,
    environ: dict[str, Any],
    raw_id: str,
    start_response: StartResponse,
) -> Iterable[bytes]:
    if method == "GET":
        return _handle_mirror_item_get(environ, raw_id, start_response)
    if method == "DELETE":
        return _handle_mirror_item_delete(environ, raw_id, start_response)
    return _error(
        start_response,
        "405 Method Not Allowed",
        "method_not_allowed",
        f"Method {method} is not allowed for this path.",
        allowed="DELETE, GET",
    )


def _handle_mirror_signature_policy_post(
    environ: dict[str, Any], raw_id: str, start_response: StartResponse
) -> Iterable[bytes]:
    if not raw_id or "/" in raw_id or "\\" in raw_id:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            "Mirror id must not be empty or contain path separators.",
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

    # Validate the whole body before touching any store, so a bad request
    # can never leave a partial policy.
    try:
        build_mirror_policy_fields(payload)
    except MirrorPolicyValidationError as exc:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            exc.message,
        )

    if mirror_store.get(raw_id) is None:
        return _error(
            start_response,
            "404 Not Found",
            "mirror_not_found",
            "No mirror exists with the requested id.",
        )

    try:
        policy, created = mirror_policy_store.add(raw_id, payload)
    except MirrorPolicyError as exc:
        return _error(
            start_response, "409 Conflict", exc.code, exc.message
        )

    return _json_response(
        start_response,
        "201 Created" if created else "200 OK",
        policy.to_dict(raw_id),
        trailing_newline=True,
    )


def _handle_mirror_signature_policy_get(
    environ: dict[str, Any], raw_id: str, start_response: StartResponse
) -> Iterable[bytes]:
    if not raw_id or "/" in raw_id or "\\" in raw_id:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            "Mirror id must not be empty or contain path separators.",
        )
    query_error = _query_parameter_error(environ)
    if query_error is not None:
        return _error(
            start_response, "400 Bad Request", "invalid_request", query_error
        )

    if mirror_store.get(raw_id) is None:
        return _error(
            start_response,
            "404 Not Found",
            "mirror_not_found",
            "No mirror exists with the requested id.",
        )

    policy = mirror_policy_store.get(raw_id)
    if policy is None:
        return _error(
            start_response,
            "404 Not Found",
            "mirror_policy_not_found",
            "No signature policy is registered for this mirror.",
        )

    return _json_response(
        start_response,
        "200 OK",
        policy.to_dict(raw_id),
        trailing_newline=True,
    )


def _handle_mirror_signature_policy_delete(
    environ: dict[str, Any], raw_id: str, start_response: StartResponse
) -> Iterable[bytes]:
    if not raw_id or "/" in raw_id or "\\" in raw_id:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            "Mirror id must not be empty or contain path separators.",
        )
    query_error = _query_parameter_error(environ)
    if query_error is not None:
        return _error(
            start_response, "400 Bad Request", "invalid_request", query_error
        )

    # Deletion carries no body; a declared non-empty or malformed body is
    # rejected without being read and without touching any state.
    body_error = _bodyless_request_error(environ)
    if body_error is not None:
        return _error(
            start_response, "400 Bad Request", "invalid_request", body_error
        )

    if mirror_store.get(raw_id) is None:
        return _error(
            start_response,
            "404 Not Found",
            "mirror_not_found",
            "No mirror exists with the requested id.",
        )

    # Only the policy is removed; the mirror itself stays registered.
    policy = mirror_policy_store.remove(raw_id)
    if policy is None:
        return _error(
            start_response,
            "404 Not Found",
            "mirror_policy_not_found",
            "No signature policy is registered for this mirror.",
        )

    return _json_response(
        start_response,
        "200 OK",
        policy.to_dict(raw_id),
        trailing_newline=True,
    )


def _handle_mirror_signature_policy(
    method: str,
    environ: dict[str, Any],
    raw_id: str,
    start_response: StartResponse,
) -> Iterable[bytes]:
    if method == "POST":
        return _handle_mirror_signature_policy_post(
            environ, raw_id, start_response
        )
    if method == "GET":
        return _handle_mirror_signature_policy_get(
            environ, raw_id, start_response
        )
    if method == "DELETE":
        return _handle_mirror_signature_policy_delete(
            environ, raw_id, start_response
        )
    return _error(
        start_response,
        "405 Method Not Allowed",
        "method_not_allowed",
        f"Method {method} is not allowed for this path.",
        allowed="DELETE, GET, POST",
    )


def _mirror_signature_failure(
    policy: MirrorPolicy,
    environ: dict[str, Any],
    digest: str,
    *,
    strict_headers: bool,
) -> tuple[str, str, str] | None:
    """Check the pull/prefetch signature headers against ``policy``.

    This is the single signature determination shared by the single-digest
    pull and the batch prefetch. It returns ``(status, code, message)`` for
    the first failed check in the mandated order -- missing headers, key
    trust, digest coverage, signature value -- or ``None`` when every check
    passes. The signature is recomputed with the existing convention: the
    key id bytes are the key and the lowercase signed digest text is the
    message.

    ``strict_headers`` selects the only part where the two chains differ:

    * The single-digest pull passes ``True``. Malformed header values
      (an empty ``X-Key-Id``/``X-Signature`` or an ``X-Signed-Digest``
      that is not a 64-character hexadecimal string) are request errors
      answered ``400 invalid_request`` before any of the four signature
      determinations run.
    * The batch prefetch passes ``False``. It reports only the four
      signature determination codes, all answered per item on the batch:
      an empty or untrusted key reports ``key_not_trusted`` regardless of
      the other headers, a malformed signed digest can never cover the
      pulled layer and so reports ``digest_uncovered`` (when coverage is
      enforced), and any other malformed value simply cannot match the
      recomputed signature and reports ``signature_invalid``. When several
      conditions fail at once the earliest one in the fixed order -- key
      trust -- wins.
    """

    key_id = environ.get(_KEY_ID_HEADER)
    signature = environ.get(_SIGNATURE_HEADER)
    signed_digest = environ.get(_SIGNED_DIGEST_HEADER)
    if key_id is None or signature is None or signed_digest is None:
        return (
            "403 Forbidden",
            "signature_missing",
            f"This mirror requires the {_KEY_ID_HEADER_NAME}, "
            f"{_SIGNATURE_HEADER_NAME} and {_SIGNED_DIGEST_HEADER_NAME} "
            "headers.",
        )

    if strict_headers:
        # Single-digest pull only: illegal header values are rejected as
        # bad requests before key trust, coverage or value are examined.
        if not isinstance(key_id, str) or not key_id:
            return (
                "400 Bad Request",
                "invalid_request",
                f"{_KEY_ID_HEADER_NAME} header must be a non-empty string.",
            )
        if not isinstance(signature, str) or not signature:
            return (
                "400 Bad Request",
                "invalid_request",
                f"{_SIGNATURE_HEADER_NAME} header must be a non-empty string.",
            )
        if (
            not isinstance(signed_digest, str)
            or _DIGEST_PATTERN.fullmatch(signed_digest) is None
        ):
            return (
                "400 Bad Request",
                "invalid_request",
                f"{_SIGNED_DIGEST_HEADER_NAME} header must be a 64-character "
                "hexadecimal string.",
            )
        normalized_digest = signed_digest.lower()

        if key_id not in policy.keys:
            return (
                "403 Forbidden",
                "key_not_trusted",
                "The key id is not trusted by the mirror signature policy.",
            )
    else:
        # Prefetch: key trust comes before any value-level comparison, so
        # an empty or otherwise untrusted key reports key_not_trusted
        # regardless of what the other headers look like.
        if not isinstance(key_id, str) or key_id not in policy.keys:
            return (
                "403 Forbidden",
                "key_not_trusted",
                "The key id is not trusted by the mirror signature policy.",
            )
        # A non-string signed digest can never cover the pulled layer and
        # cannot match a recomputed signature; fold it into an empty
        # normalized value instead of raising.
        normalized_digest = (
            signed_digest.lower() if isinstance(signed_digest, str) else ""
        )

    if policy.cover_digest and normalized_digest != digest:
        # Under prefetch a malformed signed digest lands here as uncovered
        # rather than as a malformed request.
        return (
            "403 Forbidden",
            "digest_uncovered",
            "The signed digest does not cover the pulled layer digest.",
        )

    if strict_headers:
        try:
            provided = signature.lower().encode("ascii")
        except UnicodeEncodeError:
            provided = b""
        expected = compute_signature(policy.algorithm, key_id, normalized_digest)
    else:
        try:
            provided = (
                signature.lower().encode("ascii")
                if isinstance(signature, str)
                else b""
            )
            # A non-hex/non-ASCII signed digest (only possible when coverage
            # is not enforced) simply cannot match the recomputed signature.
            expected = compute_signature(
                policy.algorithm, key_id, normalized_digest
            )
        except UnicodeEncodeError:
            return (
                "403 Forbidden",
                "signature_invalid",
                "The signature does not match the recomputed value.",
            )

    # The comparison ignores case; the recomputed value is already
    # lowercase hexadecimal.
    if not hmac.compare_digest(expected.encode("ascii"), provided):
        return (
            "403 Forbidden",
            "signature_invalid",
            "The signature does not match the recomputed value.",
        )

    return None


def _raw_layer_response(
    start_response: StartResponse, data: bytes
) -> Iterable[bytes]:
    # Raw layer bytes only: same headers as an artifact/cache read, no JSON
    # wrapper and no trailing newline.
    start_response(
        "200 OK",
        [
            ("Content-Type", "application/octet-stream"),
            ("Content-Length", str(len(data))),
        ],
    )
    return [data]


def _pull_one_layer(
    mirror: Mirror,
    policy: MirrorPolicy | None,
    environ: dict[str, Any],
    digest: str,
    *,
    strict_signature_headers: bool = True,
) -> tuple[bytes | None, tuple[str, str, str] | None]:
    """Run the single-digest pull chain for one normalized digest.

    Returns ``(data, None)`` on success -- a counter-free cache hit or a
    fresh upstream fetch that has been verified and cached -- or
    ``(None, (status, code, message))`` for the first failure. Fetch,
    digest, signature and quota errors all become the stable error tuple
    instead of propagating; a failure never writes the cache. The batch
    prefetch passes ``strict_signature_headers=False`` so each item uses
    the prefetch signature precedence (determination codes only, no 400
    for malformed header values), while the single pull keeps the strict
    request-error gate.
    """

    # A cache hit is served straight from storage; pulling must not change
    # the cache counters, so the counter-free accessor is used.
    cached = cache_store.peek(digest)
    if cached is not None:
        if policy is not None:
            # The signature gate applies to cached bytes too: a failed
            # check returns nothing and changes nothing.
            failure = _mirror_signature_failure(
                policy,
                environ,
                digest,
                strict_headers=strict_signature_headers,
            )
            if failure is not None:
                return None, failure
        return cached, None

    try:
        data = fetch_upstream_layer(mirror.upstream, digest)
    except MirrorFetchError as exc:
        return None, ("502 Bad Gateway", exc.code, exc.message)

    # Only bytes that hash to the requested digest may enter the cache.
    if hashlib.sha256(data).hexdigest() != digest:
        return None, (
            "502 Bad Gateway",
            "mirror_digest_mismatch",
            "Upstream layer bytes do not match the requested digest.",
        )

    if policy is not None:
        # The layer content is ready; the signature gate runs before the
        # cache write so a failed check neither serves bytes nor caches.
        failure = _mirror_signature_failure(
            policy,
            environ,
            digest,
            strict_headers=strict_signature_headers,
        )
        if failure is not None:
            return None, failure

    try:
        # The digest was just verified, so ``put`` can only fail on quota;
        # either way the cache is left unchanged.
        cache_store.put(digest, data)
    except CacheError as exc:
        return None, ("409 Conflict", exc.code, exc.message)

    return data, None


def _handle_mirror_pull(
    method: str,
    environ: dict[str, Any],
    raw_id: str,
    raw_digest: str,
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

    if not raw_id or "/" in raw_id or "\\" in raw_id:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            "Mirror id must not be empty or contain path separators.",
        )
    if _DIGEST_PATTERN.fullmatch(raw_digest) is None:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            "Layer digest must be a 64-character hexadecimal string.",
        )
    digest = raw_digest.lower()

    query_error = _query_parameter_error(environ)
    if query_error is not None:
        return _error(
            start_response, "400 Bad Request", "invalid_request", query_error
        )

    mirror = mirror_store.get(raw_id)
    if mirror is None:
        return _error(
            start_response,
            "404 Not Found",
            "mirror_not_found",
            "No mirror exists with the requested id.",
        )

    # Without a registered policy the pull behaves exactly as before and
    # any signature headers are ignored.
    policy = mirror_policy_store.get(raw_id)

    data, failure = _pull_one_layer(mirror, policy, environ, digest)
    if failure is not None:
        return _error(start_response, *failure)
    assert data is not None
    return _raw_layer_response(start_response, data)


def _parse_prefetch_digests(
    raw: bytes,
) -> tuple[list[str] | None, str | None]:
    """Validate a prefetch body and return the normalized lowercase digests.

    The body must be a JSON object whose only field is ``digests``: a
    non-empty array of distinct 64-character hexadecimal strings. Returns
    ``(digests, None)`` or ``(None, message)`` for the first violation; a
    rejected body never reaches the pull chain or the cache.
    """

    if not raw:
        return None, "Request body is empty."
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, "Request body must be valid UTF-8 JSON."

    if not isinstance(payload, dict):
        return None, "Request body must be a JSON object."

    unknown_fields = set(payload) - {"digests"}
    if unknown_fields:
        return None, f"Unknown field: {sorted(unknown_fields)[0]!r}."

    if "digests" not in payload:
        return None, "Missing required field: 'digests'."

    raw_digests = payload["digests"]
    if not isinstance(raw_digests, list):
        return None, "Field 'digests' must be an array."
    if not raw_digests:
        return None, "Field 'digests' must not be empty."

    digests: list[str] = []
    seen: set[str] = set()
    for element in raw_digests:
        if not isinstance(element, str):
            return None, "Field 'digests' elements must be strings."
        if _DIGEST_PATTERN.fullmatch(element) is None:
            return None, (
                "Field 'digests' elements must be 64-character hexadecimal "
                "strings."
            )
        digest = element.lower()
        if digest in seen:
            return None, "Field 'digests' elements must not repeat."
        seen.add(digest)
        digests.append(digest)

    return digests, None


def _handle_mirror_prefetch(
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

    if not raw_id or "/" in raw_id or "\\" in raw_id:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            "Mirror id must not be empty or contain path separators.",
        )

    query_error = _query_parameter_error(environ)
    if query_error is not None:
        return _error(
            start_response, "400 Bad Request", "invalid_request", query_error
        )

    digests, body_error = _parse_prefetch_digests(_read_body(environ))
    if body_error is not None:
        return _error(
            start_response, "400 Bad Request", "invalid_request", body_error
        )
    assert digests is not None

    mirror = mirror_store.get(raw_id)
    if mirror is None:
        return _error(
            start_response,
            "404 Not Found",
            "mirror_not_found",
            "No mirror exists with the requested id.",
        )

    # Without a registered policy the prefetch behaves exactly as a pull
    # without one and any signature headers are ignored; with a policy the
    # same signature headers are checked against every pulled digest.
    policy = mirror_policy_store.get(raw_id)

    # Each digest reuses the existing single-digest chain independently: a
    # failure only marks that item, so later digests keep processing and a
    # cache already written for an earlier item is never rolled back.
    results: list[dict[str, object]] = []
    for digest in digests:
        # Classify before the chain runs; the counter-free peek does not
        # touch hit/miss counters and the chain itself peeks again.
        was_cached = cache_store.peek(digest) is not None
        data, failure = _pull_one_layer(
            mirror,
            policy,
            environ,
            digest,
            strict_signature_headers=False,
        )
        if failure is not None:
            results.append(
                {"digest": digest, "status": "failed", "size": 0,
                 "error": failure[1]}
            )
            continue
        assert data is not None
        results.append(
            {
                "digest": digest,
                "status": "cached" if was_cached else "fetched",
                "size": len(data),
            }
        )

    # Per-item failures never fail the batch: the overall answer is 200.
    return _json_response(
        start_response,
        "200 OK",
        {"id": raw_id, "results": results},
        trailing_newline=True,
    )


def _handle_mirror_probe_post(
    environ: dict[str, Any], mirror: Mirror, start_response: StartResponse
) -> Iterable[bytes]:
    # A probe POST carries no body; a declared positive or malformed body
    # is rejected without performing the attempt.
    body_error = _bodyless_request_error(environ)
    if body_error is not None:
        return _error(
            start_response, "400 Bad Request", "invalid_request", body_error
        )

    # One real connection attempt against the registered upstream address;
    # reachable and unreachable are both ordinary HTTP 200 business
    # outcomes. The result overwrites the previous probe for this mirror
    # and touches neither cache entries nor counters.
    result = probe_upstream(mirror.upstream)
    mirror_probe_store.set(mirror.id, result)
    return _json_response(
        start_response,
        "200 OK",
        result.to_dict(mirror.id),
        trailing_newline=True,
    )


def _handle_mirror_probe_get(
    raw_id: str, start_response: StartResponse
) -> Iterable[bytes]:
    # GET only reads the most recent probe result; it never performs an
    # attempt and writes no state.
    result = mirror_probe_store.get(raw_id)
    if result is None:
        return _error(
            start_response,
            "404 Not Found",
            "probe_not_found",
            "No probe has been performed for this mirror.",
        )
    return _json_response(
        start_response,
        "200 OK",
        result.to_dict(raw_id),
        trailing_newline=True,
    )


def _handle_mirror_probe(
    method: str,
    environ: dict[str, Any],
    raw_id: str,
    start_response: StartResponse,
) -> Iterable[bytes]:
    if method not in ("GET", "POST"):
        return _error(
            start_response,
            "405 Method Not Allowed",
            "method_not_allowed",
            f"Method {method} is not allowed for this path.",
            allowed="GET, POST",
        )

    if not raw_id or "/" in raw_id or "\\" in raw_id:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            "Mirror id must not be empty or contain path separators.",
        )

    query_error = _query_parameter_error(environ)
    if query_error is not None:
        return _error(
            start_response, "400 Bad Request", "invalid_request", query_error
        )

    mirror = mirror_store.get(raw_id)
    if mirror is None:
        return _error(
            start_response,
            "404 Not Found",
            "mirror_not_found",
            "No mirror exists with the requested id.",
        )

    if method == "POST":
        return _handle_mirror_probe_post(environ, mirror, start_response)
    return _handle_mirror_probe_get(raw_id, start_response)


def _handle_mirrors(
    method: str,
    environ: dict[str, Any],
    start_response: StartResponse,
) -> Iterable[bytes]:
    if method == "GET":
        return _handle_mirrors_get(environ, start_response)
    if method == "POST":
        return _handle_mirrors_post(environ, start_response)
    return _error(
        start_response,
        "405 Method Not Allowed",
        "method_not_allowed",
        f"Method {method} is not allowed for this path.",
        allowed="GET, POST",
    )


def _handle_cross_references_post(
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

    # Validate the whole body before touching any store or contacting the
    # upstream, so a bad request can never leave a partial reference.
    try:
        repository, upstream, remote_id, digest = (
            build_cross_reference_fields(payload)
        )
    except CrossReferenceValidationError as exc:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            exc.message,
        )

    if store.get(raw_id) is None:
        return _error(
            start_response,
            "404 Not Found",
            "resource_not_found",
            "No resource exists with the requested id.",
        )

    try:
        # Local, pre-flight conflicts are rejected before the upstream is
        # ever contacted.
        cross_reference_store.check_prerequisites(
            repository, upstream, remote_id
        )
    except CrossReferenceError as exc:
        return _error(
            start_response,
            f"{exc.http_status} Conflict",
            exc.code,
            exc.message,
        )

    try:
        # Fetch /resources/<remote_id> from the upstream and validate the
        # reported metadata and digest.
        resolution = resolve_remote(upstream, remote_id, digest)
    except CrossReferenceError as exc:
        return _error(
            start_response,
            f"{exc.http_status} Bad Gateway",
            exc.code,
            exc.message,
        )

    try:
        # Resolve the local identity and pre-validate the dependency edge
        # (self loop, duplicate edge, cycle) without mutating anything.
        plan = cross_reference_store.plan(
            store,
            resource_id=raw_id,
            repository=repository,
            upstream=upstream,
            remote_id=remote_id,
            digest=digest,
            resolution=resolution,
        )
    except CrossReferenceError as exc:
        return _error(
            start_response,
            f"{exc.http_status} Conflict",
            exc.code,
            exc.message,
        )

    try:
        # The metadata bytes are content-addressed by the verified digest;
        # identical bytes are idempotent, differing bytes under the same
        # digest are a conflict and abort the resolution.
        cache_store.put_verified(digest, resolution.raw)
    except CacheError as exc:
        return _error(
            start_response, "409 Conflict", exc.code, exc.message
        )

    # Only now do references, resources and edges come into existence.
    try:
        record, _dependency = cross_reference_store.commit(store, plan)
    except DependencyError as exc:
        # The edge was pre-validated by ``plan``; this only guards against
        # an unexpected graph change between planning and committing.
        return _error(
            start_response, "409 Conflict", exc.code, exc.message
        )
    return _json_response(
        start_response,
        "201 Created",
        record.to_dict(),
        trailing_newline=True,
    )


def _handle_cross_references_get(
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
    records = cross_reference_store.list_for(raw_id)
    return _json_response(
        start_response,
        "200 OK",
        {"cross_references": [record.to_dict() for record in records]},
        trailing_newline=True,
    )


def _handle_cross_references(
    method: str,
    environ: dict[str, Any],
    raw_id: str,
    start_response: StartResponse,
) -> Iterable[bytes]:
    if method == "POST":
        return _handle_cross_references_post(environ, raw_id, start_response)
    if method == "GET":
        return _handle_cross_references_get(environ, raw_id, start_response)
    return _error(
        start_response,
        "405 Method Not Allowed",
        "method_not_allowed",
        f"Method {method} is not allowed for this path.",
        allowed="GET, POST",
    )


def _handle_signatures_post(
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

    # Validate the whole body before touching any store, so a bad request
    # can never leave a partial signature.
    try:
        build_signature_fields(payload)
    except SignatureValidationError as exc:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            exc.message,
        )

    if store.get(raw_id) is None:
        return _error(
            start_response,
            "404 Not Found",
            "resource_not_found",
            "No resource exists with the requested id.",
        )

    try:
        record, created = signature_store.add(raw_id, payload)
    except SignatureError as exc:
        return _error(
            start_response, "409 Conflict", exc.code, exc.message
        )

    return _json_response(
        start_response,
        "201 Created" if created else "200 OK",
        record.to_dict(raw_id),
        trailing_newline=True,
    )


def _handle_signatures_get(
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

    record = signature_store.get(raw_id)
    if record is None:
        return _error(
            start_response,
            "404 Not Found",
            "signature_not_found",
            "No content signature is registered for this resource.",
        )

    return _json_response(
        start_response,
        "200 OK",
        record.to_dict(raw_id),
        trailing_newline=True,
    )


def _handle_signatures(
    method: str,
    environ: dict[str, Any],
    raw_id: str,
    start_response: StartResponse,
) -> Iterable[bytes]:
    if method == "POST":
        return _handle_signatures_post(environ, raw_id, start_response)
    if method == "GET":
        return _handle_signatures_get(environ, raw_id, start_response)
    return _error(
        start_response,
        "405 Method Not Allowed",
        "method_not_allowed",
        f"Method {method} is not allowed for this path.",
        allowed="GET, POST",
    )


def _handle_signature_verify(
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

    # Read-only: verification takes no request body and derives every input
    # from the stored record, so it never reads the request stream.
    resource = store.get(raw_id)
    if resource is None:
        return _error(
            start_response,
            "404 Not Found",
            "resource_not_found",
            "No resource exists with the requested id.",
        )

    registered = signature_store.get(raw_id)
    if registered is None:
        return _error(
            start_response,
            "404 Not Found",
            "signature_not_found",
            "No content signature is registered for this resource.",
        )

    # The signed digest must be the resource's registered digest.
    if registered.digest != resource.digest:
        return _error(
            start_response,
            "409 Conflict",
            "signed_digest_mismatch",
            "The signature digest does not match the resource digest.",
        )

    # Recompute the HMAC from the stored fields and compare it with the
    # registered signature value; nothing about this check is recorded.
    expected = compute_signature(
        registered.algorithm, registered.key_id, registered.digest
    )
    valid = hmac.compare_digest(expected, registered.signature)
    return _json_response(
        start_response,
        "200 OK",
        {"id": raw_id, "valid": valid},
        trailing_newline=True,
    )


def _handle_advisories(
    method: str,
    environ: dict[str, Any],
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

    # The view is read-only: a declared non-empty (or malformed) body is a
    # bad request without consulting any business data. An omitted header
    # and an explicit zero length are accepted as an empty body.
    body_error = _bodyless_request_error(environ)
    if body_error is not None:
        return _error(
            start_response, "400 Bad Request", "invalid_request", body_error
        )

    # Only the optional ``severity`` parameter is accepted; unknown or
    # repeated parameters, including a repeated ``severity``, are rejected.
    severity, severity_error = _parse_severity_query(
        str(environ.get("QUERY_STRING", ""))
    )
    if severity_error is not None:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            severity_error,
        )

    advisories = summarize_advisories(store, vulnerability_store, severity)
    return _json_response(
        start_response,
        "200 OK",
        advisories,
        trailing_newline=True,
    )


def _handle_advisory_item(
    method: str,
    environ: dict[str, Any],
    raw_advisory: str,
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

    # The view is read-only: a declared non-empty (or malformed) body is a
    # bad request without consulting any business data. An omitted header
    # and an explicit zero length are accepted as an empty body.
    body_error = _bodyless_request_error(environ)
    if body_error is not None:
        return _error(
            start_response, "400 Bad Request", "invalid_request", body_error
        )

    # The advisory identifier is matched verbatim; only its shape is
    # validated here, never its existence.
    if not raw_advisory:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            "Advisory id must not be empty.",
        )
    if "/" in raw_advisory or "\\" in raw_advisory:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            "Advisory id must not contain path separators.",
        )

    # Only the optional ``severity`` parameter is accepted; unknown or
    # repeated parameters, including a repeated ``severity``, are rejected.
    severity, severity_error = _parse_severity_query(
        str(environ.get("QUERY_STRING", ""))
    )
    if severity_error is not None:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            severity_error,
        )

    detail = advisory_detail(store, vulnerability_store, raw_advisory, severity)
    return _json_response(
        start_response,
        "200 OK",
        detail,
        trailing_newline=True,
    )


def _handle_advisory_fixes(
    method: str,
    environ: dict[str, Any],
    raw_advisory: str,
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

    # The view is read-only: a declared non-empty (or malformed) body is a
    # bad request without consulting any business data. An omitted header
    # and an explicit zero length are accepted as an empty body.
    body_error = _bodyless_request_error(environ)
    if body_error is not None:
        return _error(
            start_response, "400 Bad Request", "invalid_request", body_error
        )

    # The advisory identifier is matched verbatim; only its shape is
    # validated here, never its existence.
    if not raw_advisory:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            "Advisory id must not be empty.",
        )
    if "/" in raw_advisory or "\\" in raw_advisory:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            "Advisory id must not contain path separators.",
        )

    # Only the optional ``severity`` parameter is accepted; unknown or
    # repeated parameters, including a repeated ``severity``, are rejected.
    severity, severity_error = _parse_severity_query(
        str(environ.get("QUERY_STRING", ""))
    )
    if severity_error is not None:
        return _error(
            start_response,
            "400 Bad Request",
            "invalid_request",
            severity_error,
        )

    fixes = advisory_fixes(store, vulnerability_store, raw_advisory, severity)
    return _json_response(
        start_response,
        "200 OK",
        fixes,
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

        if path == "/advisories":
            return _handle_advisories(method, environ, start_response)

        if path.startswith("/advisories/"):
            # The identifier segment is validated by the handler; an
            # embedded separator or an empty segment is a bad request. A
            # trailing "/fixes" segment selects the per-advisory component
            # fix view instead of the alert detail view.
            tail = path[len("/advisories/"):]
            if tail.endswith("/fixes"):
                return _handle_advisory_fixes(
                    method, environ, tail[: -len("/fixes")], start_response
                )
            return _handle_advisory_item(
                method, environ, tail, start_response
            )

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

        if path == "/policies":
            return _handle_default_policy(method, environ, start_response)

        if path == "/cache":
            return _handle_cache_root(method, environ, start_response)

        if path == "/cache/status":
            return _handle_cache_status(method, environ, start_response)

        if path.startswith("/cache/layers/"):
            return _handle_cache_layer(
                method, environ, path[len("/cache/layers/"):], start_response
            )

        if path == "/mirrors":
            return _handle_mirrors(method, environ, start_response)

        if path.startswith("/mirrors/"):
            suffix = path[len("/mirrors/"):]
            marker = "/pull/"
            marker_index = suffix.find(marker)
            if marker_index >= 0:
                # Split on the pull marker even when the id segment embeds a
                # separator, so the pull handler can reject the id as a bad
                # request instead of treating the path as an unknown item.
                return _handle_mirror_pull(
                    method,
                    environ,
                    suffix[:marker_index],
                    suffix[marker_index + len(marker):],
                    start_response,
                )
            if suffix.endswith("/pull"):
                # A pull always names a digest; an empty segment is invalid.
                return _handle_mirror_pull(
                    method,
                    environ,
                    suffix[: -len("/pull")],
                    "",
                    start_response,
                )
            if suffix.endswith("/prefetch"):
                # Split on the prefetch marker even when the id segment
                # embeds a separator, so the handler can reject the id as a
                # bad request instead of treating the path as an unknown
                # item.
                return _handle_mirror_prefetch(
                    method,
                    environ,
                    suffix[: -len("/prefetch")],
                    start_response,
                )
            if suffix.endswith("/probe"):
                # Split on the probe marker even when the id segment embeds
                # a separator, so the handler can reject the id as a bad
                # request instead of treating the path as an unknown item.
                return _handle_mirror_probe(
                    method,
                    environ,
                    suffix[: -len("/probe")],
                    start_response,
                )
            if suffix.endswith("/signature-policy"):
                # Split on the policy marker even when the id segment embeds
                # a separator, so the handler can reject the id as a bad
                # request instead of treating the path as an unknown item.
                return _handle_mirror_signature_policy(
                    method,
                    environ,
                    suffix[: -len("/signature-policy")],
                    start_response,
                )
            head, separator, _tail = suffix.partition("/")
            if not separator:
                return _handle_mirror_item(
                    method, environ, head, start_response
                )
            # Any other suffix embeds a separator in the id segment; the
            # item handler rejects it without touching any state.
            return _handle_mirror_item(
                method, environ, suffix, start_response
            )

        if path.startswith("/resources/"):
            suffix = path[len("/resources/"):]
            head, separator, tail = suffix.partition("/")
            if separator and tail == "dependencies":
                return _handle_dependencies(
                    method, environ, head, start_response
                )
            if separator and tail.startswith("dependencies/"):
                return _handle_dependency_item(
                    method,
                    environ,
                    head,
                    tail[len("dependencies/"):],
                    start_response,
                )
            if separator and tail == "impact":
                return _handle_impact(
                    method, environ, head, start_response
                )
            if separator and tail == "dependency-vulnerability-impact":
                return _handle_dependency_vulnerability_impact(
                    method, environ, head, start_response
                )
            if separator and tail == "verify":
                return _handle_verify(
                    method, environ, head, start_response
                )
            if separator and tail == "assemble":
                return _handle_assemble(
                    method, environ, head, start_response
                )
            if separator and tail == "content":
                return _handle_content(
                    method, environ, head, start_response
                )
            if separator and tail == "lifecycle":
                return _handle_lifecycle(
                    method, environ, head, start_response
                )
            if separator and tail == "release-blockers":
                return _handle_release_blockers(
                    method, environ, head, start_response
                )
            if separator and tail == "vulnerabilities/batch":
                return _handle_vulnerabilities_batch(
                    method, environ, head, start_response
                )
            if separator and tail == "vulnerabilities":
                return _handle_vulnerabilities(
                    method, environ, head, start_response
                )
            if separator and tail.startswith("vulnerabilities/"):
                return _handle_vulnerability_item(
                    method,
                    environ,
                    head,
                    tail[len("vulnerabilities/"):],
                    start_response,
                )
            if separator and tail == "vulnerability-exceptions":
                return _handle_vulnerability_exceptions(
                    method, environ, head, start_response
                )
            if separator and tail.startswith("vulnerability-exceptions/"):
                return _handle_vulnerability_exception_item(
                    method,
                    environ,
                    head,
                    tail[len("vulnerability-exceptions/"):],
                    start_response,
                )
            if separator and tail == "sbom":
                return _handle_sbom(
                    method, environ, head, start_response
                )
            if separator and tail == "license":
                return _handle_license(
                    method, environ, head, start_response
                )
            if separator and tail == "provenance":
                return _handle_provenance(
                    method, environ, head, start_response
                )
            if separator and tail == "policies":
                return _handle_policies(
                    method, environ, head, start_response
                )
            if separator and tail == "admission":
                return _handle_admission(
                    method, environ, head, start_response
                )
            if separator and tail == "admission-preview":
                return _handle_admission_preview(
                    method, environ, head, start_response
                )
            if separator and tail == "risk":
                return _handle_risk(
                    method, environ, head, start_response
                )
            if separator and tail == "component-risks":
                return _handle_component_risks(
                    method, environ, head, start_response
                )
            if separator and tail == "component-fixes":
                return _handle_component_fixes(
                    method, environ, head, start_response
                )
            if separator and tail == "notifications":
                return _handle_notifications(
                    method, environ, head, start_response
                )
            if separator and tail == "cross-references":
                return _handle_cross_references(
                    method, environ, head, start_response
                )
            if separator and tail == "signatures/verify":
                return _handle_signature_verify(
                    method, environ, head, start_response
                )
            if separator and tail == "signatures":
                return _handle_signatures(
                    method, environ, head, start_response
                )
            if separator and tail == "chunks/status":
                return _handle_chunks_status(
                    method, environ, head, start_response
                )
            if separator and tail.startswith("chunks/"):
                return _handle_chunk(
                    method, environ, head, tail[len("chunks/"):],
                    start_response,
                )
            if separator and tail == "chunks":
                # The collection itself cannot be addressed: a chunk index is
                # required, so POST is a bad request and other methods 405.
                return _handle_chunk(
                    method, environ, head, "", start_response
                )
            if separator and suffix.endswith("/verify"):
                # The id segment itself contained a path separator; let the
                # verify handler reject it without reading business data.
                return _handle_verify(
                    method, environ, suffix[: -len("/verify")], start_response
                )
            if separator and suffix.endswith("/chunks/status"):
                # Fallback for a separator inside the id segment so the
                # status handler rejects it without creating any state.
                return _handle_chunks_status(
                    method,
                    environ,
                    suffix[: -len("/chunks/status")],
                    start_response,
                )
            if separator and "/chunks/" in suffix:
                # Same fallback for chunk paths with a separator in the id.
                malformed_id, _, raw_index = suffix.rpartition("/chunks/")
                return _handle_chunk(
                    method, environ, malformed_id, raw_index, start_response
                )
            if separator and suffix.endswith("/assemble"):
                return _handle_assemble(
                    method, environ, suffix[: -len("/assemble")], start_response
                )
            if separator and suffix.endswith("/content"):
                return _handle_content(
                    method, environ, suffix[: -len("/content")], start_response
                )
            if separator and suffix.endswith("/lifecycle"):
                return _handle_lifecycle(
                    method,
                    environ,
                    suffix[: -len("/lifecycle")],
                    start_response,
                )
            if separator and suffix.endswith("/release-blockers"):
                # Fallback for a separator inside the id segment so the
                # handler rejects it without reading any business data.
                return _handle_release_blockers(
                    method,
                    environ,
                    suffix[: -len("/release-blockers")],
                    start_response,
                )
            if separator and suffix.endswith("/vulnerabilities/batch"):
                # Fallback for a separator inside the id segment so the
                # handler rejects it without recording any alert.
                return _handle_vulnerabilities_batch(
                    method,
                    environ,
                    suffix[: -len("/vulnerabilities/batch")],
                    start_response,
                )
            if separator and suffix.endswith("/vulnerabilities"):
                # Fallback for a separator inside the id segment so the
                # handler rejects it without recording any alert.
                return _handle_vulnerabilities(
                    method,
                    environ,
                    suffix[: -len("/vulnerabilities")],
                    start_response,
                )
            if separator and "/vulnerabilities/" in suffix:
                # Fallback for a separator inside the id segment of an alert
                # item path so the handler rejects it without removing any
                # alert.
                malformed_id, _, raw_vulnerability_id = suffix.rpartition(
                    "/vulnerabilities/"
                )
                return _handle_vulnerability_item(
                    method,
                    environ,
                    malformed_id,
                    raw_vulnerability_id,
                    start_response,
                )
            if separator and "/vulnerability-exceptions/" in suffix:
                # Fallback for a separator inside the id segment of an
                # exception item path so the handler rejects it without
                # removing any exemption.
                malformed_id, _, raw_exception_id = suffix.rpartition(
                    "/vulnerability-exceptions/"
                )
                return _handle_vulnerability_exception_item(
                    method,
                    environ,
                    malformed_id,
                    raw_exception_id,
                    start_response,
                )
            if separator and suffix.endswith("/vulnerability-exceptions"):
                # Fallback for a separator inside the id segment so the
                # handler rejects it without recording any exemption.
                return _handle_vulnerability_exceptions(
                    method,
                    environ,
                    suffix[: -len("/vulnerability-exceptions")],
                    start_response,
                )
            if separator and suffix.endswith("/sbom"):
                # Fallback for a separator inside the id segment so the
                # handler rejects it without recording any document.
                return _handle_sbom(
                    method,
                    environ,
                    suffix[: -len("/sbom")],
                    start_response,
                )
            if separator and suffix.endswith("/license"):
                # Fallback for a separator inside the id segment so the
                # handler rejects it without recording any license.
                return _handle_license(
                    method,
                    environ,
                    suffix[: -len("/license")],
                    start_response,
                )
            if separator and suffix.endswith("/provenance"):
                # Fallback for a separator inside the id segment so the
                # handler rejects it without recording any provenance.
                return _handle_provenance(
                    method,
                    environ,
                    suffix[: -len("/provenance")],
                    start_response,
                )
            if separator and suffix.endswith("/policies"):
                # Fallback for a separator inside the id segment so the
                # handler rejects it without recording any policy.
                return _handle_policies(
                    method,
                    environ,
                    suffix[: -len("/policies")],
                    start_response,
                )
            if separator and suffix.endswith("/admission"):
                # Same fallback so a separator in the id is rejected
                # without performing an evaluation.
                return _handle_admission(
                    method,
                    environ,
                    suffix[: -len("/admission")],
                    start_response,
                )
            if separator and suffix.endswith("/admission-preview"):
                # Same fallback so a separator in the id is rejected
                # without computing a preview.
                return _handle_admission_preview(
                    method,
                    environ,
                    suffix[: -len("/admission-preview")],
                    start_response,
                )
            if separator and suffix.endswith("/risk"):
                # Fallback for a separator inside the id segment so the
                # handler rejects it without computing any score.
                return _handle_risk(
                    method,
                    environ,
                    suffix[: -len("/risk")],
                    start_response,
                )
            if separator and suffix.endswith("/component-risks"):
                # Fallback for a separator inside the id segment so the
                # handler rejects it without computing any component risk.
                return _handle_component_risks(
                    method,
                    environ,
                    suffix[: -len("/component-risks")],
                    start_response,
                )
            if separator and suffix.endswith("/component-fixes"):
                # Fallback for a separator inside the id segment so the
                # handler rejects it without computing any fix recommendation.
                return _handle_component_fixes(
                    method,
                    environ,
                    suffix[: -len("/component-fixes")],
                    start_response,
                )
            if separator and suffix.endswith("/notifications"):
                # Fallback for a separator inside the id segment so the
                # handler rejects it without recording any notification.
                return _handle_notifications(
                    method,
                    environ,
                    suffix[: -len("/notifications")],
                    start_response,
                )
            if separator and suffix.endswith(
                "/dependency-vulnerability-impact"
            ):
                # Fallback for a separator inside the id segment so the
                # handler rejects it without computing any impact.
                return _handle_dependency_vulnerability_impact(
                    method,
                    environ,
                    suffix[: -len("/dependency-vulnerability-impact")],
                    start_response,
                )
            if separator and "/dependencies/" in suffix:
                # Fallback for a separator inside the id segment of a
                # dependency item path so the handler rejects it without
                # removing any edge.
                malformed_id, _, raw_dependency_id = suffix.rpartition(
                    "/dependencies/"
                )
                return _handle_dependency_item(
                    method,
                    environ,
                    malformed_id,
                    raw_dependency_id,
                    start_response,
                )
            if separator and suffix.endswith("/cross-references"):
                # Fallback for a separator inside the id segment so the
                # handler rejects it without resolving anything.
                return _handle_cross_references(
                    method,
                    environ,
                    suffix[: -len("/cross-references")],
                    start_response,
                )
            if separator and suffix.endswith("/signatures/verify"):
                # Fallback for a separator inside the id segment so the
                # verify handler rejects it without checking any record.
                return _handle_signature_verify(
                    method,
                    environ,
                    suffix[: -len("/signatures/verify")],
                    start_response,
                )
            if separator and suffix.endswith("/signatures"):
                # Fallback for a separator inside the id segment so the
                # handler rejects it without recording any signature.
                return _handle_signatures(
                    method,
                    environ,
                    suffix[: -len("/signatures")],
                    start_response,
                )
            # Any other suffix keeps the baseline item semantics (embedded
            # separators are rejected by the item handler).
            return _handle_resource_item(
                method, environ, suffix, start_response
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
