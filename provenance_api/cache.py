"""Process-local image layer cache with a byte quota and hit/miss counters.

Layers are addressed by their SHA-256 digest: a write is accepted only when
the received bytes hash to the digest in the path and the configured quota
still has room. Re-submitting the same bytes for a cached digest is an
idempotent no-op; different bytes under an already cached digest are a
conflict. Reads bump the hit or miss counters; the status snapshot is
read-only and never changes any counter.

A write can be rehearsed with a read-only pre-check: the same digest,
conflict and quota rules are evaluated against the submitted bytes and a
single decision code is returned, but no entry is stored and no counter,
usage figure or quota figure changes.

A single layer can be removed by digest, or the whole cache cleared at
once; either operation frees the entry bytes (so quota headroom returns)
but never touches the hit/miss counters. Removing a digest that is not
cached is a ``cache_miss``; clearing an empty cache is an idempotent
no-op.

Everything lives in the current process memory: entries and counters are
lost on restart and nothing is ever written to a file. There is
intentionally no eviction, no cross-layer batching and no concurrency
locking.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

#: Default cache quota in bytes (1 MiB) when ``--cache-quota`` is not given.
DEFAULT_CACHE_QUOTA = 1048576


class CacheError(ValueError):
    """A layer write could not proceed.

    ``code`` is the stable, client-facing error code.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class CacheStatus:
    """Read-only snapshot of the cache: entries, usage, quota, counters."""

    entries: int
    used_bytes: int
    quota: int
    hits: int
    misses: int


class LayerCacheStore:
    """In-process layer cache keyed by lowercase hex digest."""

    def __init__(self, quota: int = DEFAULT_CACHE_QUOTA) -> None:
        self._quota = quota
        self._layers: dict[str, bytes] = {}
        self._used = 0
        self._hits = 0
        self._misses = 0

    @property
    def quota(self) -> int:
        return self._quota

    def configure(self, quota: int) -> None:
        """Set the quota in bytes; existing entries and counters are kept."""

        self._quota = quota

    def reset(self) -> None:
        """Clear entries and counters and restore the default quota."""

        self._quota = DEFAULT_CACHE_QUOTA
        self._layers = {}
        self._used = 0
        self._hits = 0
        self._misses = 0

    def put(self, digest: str, data: bytes) -> tuple[bool, int]:
        """Verify and cache one layer.

        ``digest`` is the 64-character lowercase hex digest from the path.
        Returns ``(created, entries)`` where ``created`` is ``True`` when a
        new entry was stored (HTTP 201) and ``False`` when the same bytes
        were submitted again (HTTP 200, idempotent); ``entries`` is the
        number of cached layers after the call. Raises :class:`CacheError`
        for:

        - ``digest_mismatch`` when the bytes do not hash to ``digest``
          (nothing is stored);
        - ``cache_conflict`` when the digest is already cached with
          different bytes (the original entry is kept);
        - ``cache_quota_exceeded`` when storing would push the used bytes
          over the quota (the cache is left unchanged).
        """

        if hashlib.sha256(data).hexdigest() != digest:
            raise CacheError(
                "digest_mismatch",
                "Layer bytes do not match the digest in the path.",
            )
        return self.put_verified(digest, data)

    def put_verified(self, digest: str, data: bytes) -> tuple[bool, int]:
        """Store bytes whose digest the caller has already verified.

        Unlike :meth:`put`, no SHA-256 comparison is performed here: the
        caller guarantees ``data`` belongs to ``digest``. The conflict,
        idempotence and quota semantics are otherwise identical: equal
        bytes under an existing digest are an idempotent no-op, different
        bytes raise ``cache_conflict`` and an over-quota write raises
        ``cache_quota_exceeded`` with the cache unchanged.
        """

        existing = self._layers.get(digest)
        if existing is not None:
            if existing != data:
                raise CacheError(
                    "cache_conflict",
                    "A different layer is already cached for this digest.",
                )
            return False, len(self._layers)

        if self._used + len(data) > self._quota:
            raise CacheError(
                "cache_quota_exceeded",
                "Storing this layer would exceed the cache quota.",
            )

        self._layers[digest] = data
        self._used += len(data)
        return True, len(self._layers)

    def check(self, digest: str, data: bytes) -> str:
        """Rehearse a write without storing anything, returning a decision.

        Applies the very same rules as :meth:`put` -- digest match first,
        then the cached-entry comparison, then the quota -- and reports the
        single outcome as a stable code:

        - ``digest_mismatch`` when the bytes do not hash to ``digest``
          (judged on the submitted bytes alone);
        - ``already_cached`` when the same bytes are already cached for
          ``digest`` (a rewrite would be an idempotent no-op);
        - ``cache_conflict`` when ``digest`` is cached with different
          bytes (a write would collide with the kept entry);
        - ``cache_quota_exceeded`` when storing would push the used bytes
          over the quota;
        - ``writable`` when none of the above applies and a write would
          be accepted.

        When several conditions coincide, the first one in this order
        wins. The check is strictly read-only: entries, hit/miss counters,
        used bytes and quota headroom are all left untouched.
        """

        if hashlib.sha256(data).hexdigest() != digest:
            return "digest_mismatch"
        existing = self._layers.get(digest)
        if existing is not None:
            return "already_cached" if existing == data else "cache_conflict"
        if self._used + len(data) > self._quota:
            return "cache_quota_exceeded"
        return "writable"

    def get(self, digest: str) -> bytes | None:
        """Return the cached bytes, counting a hit, or ``None`` on a miss."""

        data = self._layers.get(digest)
        if data is None:
            self._misses += 1
            return None
        self._hits += 1
        return data

    def peek(self, digest: str) -> bytes | None:
        """Return the cached bytes without touching hit/miss counters.

        Used by mirror pulls, which must answer a cache hit without changing
        the reported counters.
        """

        return self._layers.get(digest)

    def remove(self, digest: str) -> tuple[int, int]:
        """Delete one cached layer, returning ``(size, entries)``.

        ``size`` is the number of bytes freed by the removal and
        ``entries`` is the number of cached layers remaining afterwards.
        The used-byte total drops immediately, so a later write is judged
        against the reduced usage. Raises :class:`CacheError` with code
        ``cache_miss`` when no layer is cached for ``digest``; the cache
        is left unchanged (so deleting an already deleted digest keeps
        failing with ``cache_miss``). Hit/miss counters are never
        touched.
        """

        existing = self._layers.pop(digest, None)
        if existing is None:
            raise CacheError(
                "cache_miss",
                "No layer is cached for the requested digest.",
            )
        self._used -= len(existing)
        return len(existing), len(self._layers)

    def clear(self) -> tuple[int, int]:
        """Remove every cached layer, returning ``(removed, freed_bytes)``.

        ``removed`` is the number of entries dropped and ``freed_bytes``
        is the total number of bytes they occupied. Clearing an empty
        cache is an idempotent no-op: both counts are ``0`` and repeated
        calls never raise. Hit/miss counters and the configured quota
        are preserved.
        """

        removed = len(self._layers)
        freed = self._used
        self._layers = {}
        self._used = 0
        return removed, freed

    def status(self) -> CacheStatus:
        """Return a read-only snapshot; never mutates entries or counters."""

        return CacheStatus(
            entries=len(self._layers),
            used_bytes=self._used,
            quota=self._quota,
            hits=self._hits,
            misses=self._misses,
        )
