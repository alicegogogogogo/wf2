"""Process-local mirror registry and upstream layer fetching.

Mirrors are named, globally unique upstream HTTP(S) addresses that can serve
image layers by digest. Registration is validated up front; a duplicate name
is rejected without overwriting the original mirror. Pulling a layer asks the
existing layer cache first *without* touching its hit/miss counters and, on a
miss, fetches ``<upstream without trailing slash>/layers/<digest>`` from the
registered address, verifies the SHA-256 and only then writes the cache.

Everything lives in the current process memory: mirrors are lost on restart
and nothing is ever written to a file. There is intentionally no deletion,
no update and no concurrency locking.
"""

from __future__ import annotations

import hashlib
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from urllib.parse import urlsplit

from .cache import CacheError

_ALLOWED_FIELDS = frozenset({"name", "upstream"})


class MirrorValidationError(ValueError):
    """A mirror registration payload failed field-level validation."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class MirrorError(ValueError):
    """A mirror pull could not proceed.

    ``code`` is the stable, client-facing error code.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class Mirror:
    """A single registered mirror source."""

    id: str
    name: str
    upstream: str

    def to_dict(self) -> dict[str, object]:
        return {"id": self.id, "name": self.name, "upstream": self.upstream}


def _is_absolute_http_url(value: str) -> bool:
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https"):
        return False
    # An absolute http(s) URL must carry a network location; anything else
    # (a bare host parsed as a path, a missing host, a fragment) is rejected.
    return bool(parts.netloc)


def build_mirror_fields(payload: object) -> tuple[str, str]:
    """Validate a decoded JSON payload and return ``(name, upstream)``."""

    if not isinstance(payload, dict):
        raise MirrorValidationError("Request body must be a JSON object.")

    unknown_fields = set(payload) - _ALLOWED_FIELDS
    if unknown_fields:
        raise MirrorValidationError(
            f"Unknown field: {sorted(unknown_fields)[0]!r}."
        )

    for field in ("name", "upstream"):
        if field not in payload:
            raise MirrorValidationError(
                f"Missing required field: {field!r}."
            )

    name = payload["name"]
    if not isinstance(name, str) or not name:
        raise MirrorValidationError("Field 'name' must be a non-empty string.")

    upstream = payload["upstream"]
    if not isinstance(upstream, str) or not upstream:
        raise MirrorValidationError(
            "Field 'upstream' must be a non-empty string."
        )
    if not _is_absolute_http_url(upstream):
        raise MirrorValidationError(
            "Field 'upstream' must be an absolute http or https URL."
        )

    return name, upstream


class MirrorStore:
    """Process-local, insertion-ordered mirror storage."""

    def __init__(self) -> None:
        self._mirrors: list[Mirror] = []
        self._by_id: dict[str, Mirror] = {}

    def reset(self) -> None:
        self._mirrors = []
        self._by_id = {}

    def list_all(self) -> list[Mirror]:
        """Return every mirror in registration order."""

        return list(self._mirrors)

    def get(self, mirror_id: str) -> Mirror | None:
        return self._by_id.get(mirror_id)

    def add(self, payload: object) -> tuple[Mirror | None, Mirror | None]:
        """Validate and register a mirror.

        Returns ``(created, None)`` on success or ``(None, existing)`` when
        the name is already registered; the original mirror is kept.
        """

        name, upstream = build_mirror_fields(payload)
        for mirror in self._mirrors:
            if mirror.name == name:
                return None, mirror

        mirror = Mirror(id=uuid.uuid4().hex, name=name, upstream=upstream)
        self._mirrors.append(mirror)
        self._by_id[mirror.id] = mirror
        return mirror, None


def fetch_layer(upstream: str, digest: str) -> bytes:
    """Fetch one layer's raw bytes from an upstream mirror.

    The upstream address has trailing slashes stripped and ``/layers/<digest>``
    appended. Raises :class:`MirrorError` with code ``mirror_fetch_failed``
    when the upstream cannot be reached or answers anything other than HTTP
    200; the caller treats that as a bad gateway without touching the cache.
    """

    url = upstream.rstrip("/") + "/layers/" + digest
    request = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            status = getattr(response, "status", None) or response.getcode()
            if status != 200:
                raise MirrorError(
                    "mirror_fetch_failed",
                    "The upstream mirror did not answer with HTTP 200.",
                )
            return response.read()
    except MirrorError:
        raise
    except (urllib.error.URLError, OSError, ValueError) as exc:
        # HTTPError (non-2xx answers) is a URLError subclass and lands here.
        raise MirrorError(
            "mirror_fetch_failed",
            "The upstream mirror could not be reached or returned an "
            "invalid response.",
        ) from exc


def pull_layer(cache_store: object, mirror: Mirror, digest: str) -> bytes:
    """Return a layer through the cache, fetching the upstream on a miss.

    A cache hit returns the stored bytes directly. Neither a hit nor a miss
    changes the cache hit/miss counters. On a miss the upstream is contacted,
    the received bytes must hash to ``digest`` (otherwise
    ``mirror_digest_mismatch``) and the write must fit the quota
    (otherwise ``cache_quota_exceeded``); in every failure case the cache is
    left unchanged.
    """

    cached = cache_store.peek(digest)  # type: ignore[attr-defined]
    if cached is not None:
        return cached

    data = fetch_layer(mirror.upstream, digest)
    if hashlib.sha256(data).hexdigest() != digest:
        raise MirrorError(
            "mirror_digest_mismatch",
            "Upstream layer bytes do not match the requested digest.",
        )

    try:
        # The digest was just verified and the digest was absent from the
        # cache, so only a quota rejection is possible here.
        cache_store.put(digest, data)  # type: ignore[attr-defined]
    except CacheError as exc:
        if exc.code == "cache_quota_exceeded":
            raise MirrorError(
                "cache_quota_exceeded",
                "Storing this layer would exceed the cache quota.",
            ) from None
        raise MirrorError(
            "mirror_fetch_failed",
            "The fetched layer could not be cached.",
        ) from exc
    return data
