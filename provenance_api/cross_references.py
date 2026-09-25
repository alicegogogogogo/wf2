"""Cross-repository references and remote resource metadata resolution.

A cross-reference declares that a local resource corresponds to a resource
identified by ``remote_id`` in a remote ``repository`` reached at an
absolute ``http``/``https`` ``upstream`` address. Registering a reference
resolves the remote resource by fetching its metadata, verifying the
expected content ``digest``, and then reusing (or creating) the matching
local resource and linking it into the dependency graph.

Records live in current-process memory only and are lost on restart;
nothing is ever written to a file. Batching and concurrency are out of
scope.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlsplit

from .resources import CATEGORIES

#: Fetch timeout in seconds for contacting an upstream repository.
DEFAULT_FETCH_TIMEOUT = 10.0

_DIGEST_PATTERN = re.compile(r"[0-9a-fA-F]{64}")
_ALLOWED_FIELDS = frozenset({"repository", "upstream", "remote_id", "digest"})
_REQUIRED_FIELDS = ("repository", "upstream", "remote_id", "digest")
_CATEGORY_VALUES = frozenset(CATEGORIES)


class CrossReferenceValidationError(ValueError):
    """A cross-reference payload failed field-level validation."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class RemoteResolutionError(Exception):
    """Remote metadata could not be fetched or interpreted.

    ``code`` is the stable, client-facing error code:
    ``remote_unreachable`` for connection/timeout/non-200 failures and
    ``resolution_failed`` for malformed metadata.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class RemoteResource:
    """The validated metadata of a remotely resolved resource."""

    name: str
    category: str
    digest: str
    source: str | None


@dataclass(frozen=True, slots=True)
class CrossReference:
    """A single cross-repository reference record."""

    resource_id: str
    repository: str
    upstream: str
    remote_id: str
    digest: str

    def to_dict(self) -> dict[str, object]:
        # Fixed key order; ``resource_id`` is the local anchor resource.
        return {
            "repository": self.repository,
            "upstream": self.upstream,
            "remote_id": self.remote_id,
            "digest": self.digest,
            "resource_id": self.resource_id,
        }


def _require_name(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise CrossReferenceValidationError(f"{label} must be a string.")
    if not value.strip():
        raise CrossReferenceValidationError(f"{label} must not be empty.")
    return value


def _require_remote_id(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise CrossReferenceValidationError(
            "Remote id must be a non-empty string."
        )
    if "/" in value or "\\" in value:
        raise CrossReferenceValidationError(
            "Remote id must not contain path separators."
        )
    return value


def _build_upstream(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise CrossReferenceValidationError(
            "Upstream must be a non-empty string."
        )
    parts = urlsplit(value)
    # A network location is required and no query component is allowed; only
    # http and https are supported.
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise CrossReferenceValidationError(
            "Upstream must be an absolute http or https URL."
        )
    if parts.query:
        raise CrossReferenceValidationError(
            "Upstream must not contain query parameters."
        )
    return value


def build_cross_reference_fields(
    payload: object,
) -> tuple[str, str, str, str]:
    """Validate a decoded JSON payload and return normalized field values."""

    if not isinstance(payload, dict):
        raise CrossReferenceValidationError(
            "Request body must be a JSON object."
        )

    unknown_fields = set(payload) - _ALLOWED_FIELDS
    if unknown_fields:
        raise CrossReferenceValidationError(
            f"Unknown field: {sorted(unknown_fields)[0]!r}."
        )

    for field in _REQUIRED_FIELDS:
        if field not in payload:
            raise CrossReferenceValidationError(
                f"Missing required field: {field!r}."
            )

    repository = _require_name(payload["repository"], "Repository")
    upstream = _build_upstream(payload["upstream"])
    remote_id = _require_remote_id(payload["remote_id"])

    digest_raw = payload["digest"]
    if not isinstance(digest_raw, str) or _DIGEST_PATTERN.fullmatch(
        digest_raw
    ) is None:
        raise CrossReferenceValidationError(
            "Digest must be a 64-character hexadecimal string."
        )
    digest = digest_raw.lower()

    return repository, upstream, remote_id, digest


def _resource_url(upstream: str, remote_id: str) -> str:
    # Same trailing-slash joining rule as mirror pulls.
    return upstream.rstrip("/") + "/resources/" + remote_id


def parse_remote_metadata(raw: bytes, expected_digest: str) -> RemoteResource:
    """Validate remote metadata bytes and return normalized fields.

    Raises :class:`RemoteResolutionError` with code ``resolution_failed``
    when the body is not valid UTF-8 JSON, is missing a field, uses a wrong
    type or an illegal digest, or names a different digest than expected.
    """

    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise RemoteResolutionError(
            "resolution_failed",
            "Upstream returned malformed resource metadata.",
        ) from None

    if not isinstance(payload, dict):
        raise RemoteResolutionError(
            "resolution_failed",
            "Upstream returned malformed resource metadata.",
        )

    name = payload.get("name")
    if not isinstance(name, str) or not name:
        raise RemoteResolutionError(
            "resolution_failed",
            "Upstream metadata field 'name' is missing or invalid.",
        )

    category_raw = payload.get("category")
    if not isinstance(category_raw, str) or not category_raw:
        raise RemoteResolutionError(
            "resolution_failed",
            "Upstream metadata field 'category' is missing or invalid.",
        )
    category = category_raw.lower()
    if category not in _CATEGORY_VALUES:
        raise RemoteResolutionError(
            "resolution_failed",
            "Upstream metadata field 'category' is invalid.",
        )

    digest_raw = payload.get("digest")
    if not isinstance(digest_raw, str) or _DIGEST_PATTERN.fullmatch(
        digest_raw
    ) is None:
        raise RemoteResolutionError(
            "resolution_failed",
            "Upstream metadata field 'digest' is missing or invalid.",
        )
    digest = digest_raw.lower()
    if digest != expected_digest:
        raise RemoteResolutionError(
            "remote_digest_mismatch",
            "Upstream resource digest does not match the expected digest.",
        )

    source = payload.get("source")
    if source is not None and (not isinstance(source, str) or not source):
        raise RemoteResolutionError(
            "resolution_failed",
            "Upstream metadata field 'source' is invalid.",
        )

    return RemoteResource(
        name=name, category=category, digest=digest, source=source
    )


def fetch_remote_resource(
    upstream: str,
    remote_id: str,
    expected_digest: str,
    *,
    timeout: float = DEFAULT_FETCH_TIMEOUT,
) -> tuple[RemoteResource, bytes]:
    """Fetch and validate metadata for ``/resources/<remote_id>``.

    Returns the validated :class:`RemoteResource` together with the raw
    response body, so the caller can cache it under the resource digest.
    Raises :class:`RemoteResolutionError` with code
    ``remote_unreachable`` when the upstream cannot be contacted, times out
    or answers a non-200 status; ``resolution_failed`` for malformed
    metadata; and ``remote_digest_mismatch`` when the remote digest differs
    from the expected one.
    """

    url = _resource_url(upstream, remote_id)
    request = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if getattr(response, "status", response.getcode()) != 200:
                raise RemoteResolutionError(
                    "remote_unreachable",
                    "Upstream repository did not return the resource.",
                )
            raw = response.read()
    except RemoteResolutionError:
        raise
    except urllib.error.HTTPError as exc:
        raise RemoteResolutionError(
            "remote_unreachable",
            "Upstream repository did not return the resource.",
        ) from exc
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise RemoteResolutionError(
            "remote_unreachable",
            "Upstream repository could not be reached.",
        ) from exc

    return parse_remote_metadata(raw, expected_digest), raw


class CrossReferenceStore:
    """Process-local, insertion-ordered cross-reference storage.

    A repository name is globally bound to a single upstream address: the
    same name registered again with a different upstream is a conflict. The
    pair ``(repository, remote_id)`` identifies a unique reference.
    """

    def __init__(self) -> None:
        self._references: list[CrossReference] = []
        # (repository, remote_id) -> index into ``_references``.
        self._key_to_index: dict[tuple[str, str], int] = {}
        # repository name -> upstream address it is bound to.
        self._repository_upstream: dict[str, str] = {}

    def reset(self) -> None:
        self._references = []
        self._key_to_index = {}
        self._repository_upstream = {}

    def upstream_for(self, repository: str) -> str | None:
        """Return the upstream bound to ``repository``, if registered."""

        return self._repository_upstream.get(repository)

    def list_for(self, resource_id: str) -> list[CrossReference]:
        """Return a resource's references in registration order."""

        return [
            reference
            for reference in self._references
            if reference.resource_id == resource_id
        ]

    def find(
        self, repository: str, remote_id: str
    ) -> CrossReference | None:
        index = self._key_to_index.get((repository, remote_id))
        if index is None:
            return None
        return self._references[index]

    def add(
        self,
        resource_id: str,
        repository: str,
        upstream: str,
        remote_id: str,
        digest: str,
    ) -> CrossReference:
        """Store a validated reference record.

        Binds ``repository`` to ``upstream`` on first use. Duplicate
        ``(repository, remote_id)`` pairs and a mismatched upstream for a
        known repository are the caller's responsibility (see :meth:`find`
        and :meth:`upstream_for`); records are never overwritten.
        """

        reference = CrossReference(
            resource_id=resource_id,
            repository=repository,
            upstream=upstream,
            remote_id=remote_id,
            digest=digest,
        )
        self._key_to_index[(repository, remote_id)] = len(self._references)
        self._repository_upstream.setdefault(repository, upstream)
        self._references.append(reference)
        return reference
