"""Process-local image layer cache with a byte quota.

Layers are addressed by their SHA-256 digest and stored as raw bytes. The
cache enforces a total byte quota configured at startup; writes that would
exceed the quota are refused and the cache is left untouched. Read hits and
misses are counted for the status endpoint.

Everything lives in the current process memory: entries and counters are
lost on restart and nothing is ever written to a file.
"""

from __future__ import annotations

from dataclasses import dataclass

#: Default total byte quota when ``--cache-quota`` is not given.
DEFAULT_CACHE_QUOTA = 1048576


class CacheError(ValueError):
    """A cache write could not proceed.

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


class CacheStore:
    """In-process layer cache keyed by lowercase hex digest."""

    def __init__(self, quota: int = DEFAULT_CACHE_QUOTA) -> None:
        self._quota = quota
        self._layers: dict[str, bytes] = {}
        self._used_bytes = 0
        self._hits = 0
        self._misses = 0

    def reset(self) -> None:
        """Clear entries and counters and restore the default quota."""

        self._layers = {}
        self._used_bytes = 0
        self._hits = 0
        self._misses = 0
        self._quota = DEFAULT_CACHE_QUOTA

    @property
    def quota(self) -> int:
        return self._quota

    def set_quota(self, quota: int) -> None:
        self._quota = quota

    def put(self, digest: str, data: bytes) -> tuple[bool, int]:
        """Store one layer under ``digest``.

        Returns ``(created, entries)`` where ``created`` is ``True`` when a
        new entry was stored and ``False`` when the very same bytes were
        submitted again (idempotent retry, nothing changes); ``entries`` is
        the number of cached layers after the call. Raises
        :class:`CacheError` with ``cache_conflict`` when the digest already
        holds different bytes, or ``cache_quota_exceeded`` when storing the
        layer would push usage past the quota; in both cases the cache is
        left exactly as it was.
        """

        existing = self._layers.get(digest)
        if existing is not None:
            if existing != data:
                raise CacheError(
                    "cache_conflict",
                    "A different layer is already cached for this digest.",
                )
            return False, len(self._layers)

        if self._used_bytes + len(data) > self._quota:
            raise CacheError(
                "cache_quota_exceeded",
                "Storing this layer would exceed the cache quota.",
            )

        self._layers[digest] = data
        self._used_bytes += len(data)
        return True, len(self._layers)

    def get(self, digest: str) -> bytes | None:
        """Return the cached bytes, counting a hit or a miss."""

        data = self._layers.get(digest)
        if data is None:
            self._misses += 1
            return None
        self._hits += 1
        return data

    def status(self) -> CacheStatus:
        """Return a read-only snapshot; never mutates entries or counters."""

        return CacheStatus(
            entries=len(self._layers),
            used_bytes=self._used_bytes,
            quota=self._quota,
            hits=self._hits,
            misses=self._misses,
        )
