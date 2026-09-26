"""Process-local image mirror registry and upstream layer fetching.

A mirror record pairs a globally unique ``name`` with an absolute
``http``/``https`` ``upstream`` base address. Records are kept in insertion
order and never persisted. Pulling a layer through a mirror never happens in
this module: it only knows how to fetch the raw bytes of
``<upstream>/layers/<digest>`` so the caller can verify the digest and decide
whether to populate the shared layer cache.

Everything lives in the current process memory: mirrors are lost on restart
and nothing is ever written to a file.
"""

from __future__ import annotations

import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

#: Fetch timeout in seconds for contacting an upstream mirror.
DEFAULT_FETCH_TIMEOUT = 10.0

#: Probe timeout in seconds for contacting an upstream mirror.
DEFAULT_PROBE_TIMEOUT = DEFAULT_FETCH_TIMEOUT

_ALLOWED_FIELDS = frozenset({"name", "upstream"})
_REQUIRED_FIELDS = ("name", "upstream")


class MirrorValidationError(ValueError):
    """A mirror registration payload failed field-level validation."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class MirrorFetchError(Exception):
    """The upstream could not deliver a layer.

    ``code`` is the stable, client-facing error code.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class Mirror:
    """A single registered image mirror."""

    id: str
    name: str
    upstream: str

    def to_dict(self) -> dict[str, object]:
        return {"id": self.id, "name": self.name, "upstream": self.upstream}


@dataclass(frozen=True, slots=True)
class ProbeResult:
    """The most recent upstream probe outcome for one mirror.

    Successful probes carry the upstream status code and a non-negative
    latency in milliseconds; failed probes carry ``None`` for both. The
    stable ``probe_failed`` error code is reported on the wire for
    unreachable mirrors.
    """

    reachable: bool
    status_code: int | None
    latency_ms: int | None

    def to_dict(self, mirror_id: str) -> dict[str, object]:
        result: dict[str, object] = {
            "id": mirror_id,
            "reachable": self.reachable,
            "status_code": self.status_code,
            "latency_ms": self.latency_ms,
        }
        if not self.reachable:
            result["error"] = "probe_failed"
        return result


class ProbeStore:
    """Process-local storage of the latest probe result per mirror.

    Only the most recent result of each mirror is kept and a new probe
    overwrites the previous one. Results are never persisted to disk and
    are lost on restart; probe state never touches cache entries, counters
    or any other record.
    """

    def __init__(self) -> None:
        self._results: dict[str, ProbeResult] = {}

    def reset(self) -> None:
        self._results = {}

    def get(self, mirror_id: str) -> ProbeResult | None:
        return self._results.get(mirror_id)

    def set(self, mirror_id: str, result: ProbeResult) -> None:
        self._results[mirror_id] = result

    def discard(self, mirror_id: str) -> None:
        self._results.pop(mirror_id, None)


def _require_non_empty_string(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise MirrorValidationError(f"{label} must be a string.")
    if not value.strip():
        raise MirrorValidationError(f"{label} must not be empty.")
    return value


def _build_upstream(value: object) -> str:
    upstream = _require_non_empty_string(value, "Upstream")
    parts = urlsplit(upstream)
    # A network location is required so relative addresses or bare schemes
    # are rejected; only http and https are supported.
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise MirrorValidationError(
            "Upstream must be an absolute http or https URL."
        )
    return upstream


def build_mirror_fields(payload: object) -> tuple[str, str]:
    """Validate a decoded JSON payload and return ``(name, upstream)``."""

    if not isinstance(payload, dict):
        raise MirrorValidationError("Request body must be a JSON object.")

    unknown_fields = set(payload) - _ALLOWED_FIELDS
    if unknown_fields:
        raise MirrorValidationError(
            f"Unknown field: {sorted(unknown_fields)[0]!r}."
        )

    for field in _REQUIRED_FIELDS:
        if field not in payload:
            raise MirrorValidationError(
                f"Missing required field: {field!r}."
            )

    name = _require_non_empty_string(payload["name"], "Name")
    upstream = _build_upstream(payload["upstream"])
    return name, upstream


class MirrorStore:
    """Process-local, insertion-ordered mirror storage with unique names."""

    def __init__(self) -> None:
        self._mirrors: list[Mirror] = []
        self._by_id: dict[str, Mirror] = {}
        self._name_to_id: dict[str, str] = {}

    def reset(self) -> None:
        self._mirrors = []
        self._by_id = {}
        self._name_to_id = {}

    def list_all(self) -> list[Mirror]:
        return list(self._mirrors)

    def get(self, mirror_id: str) -> Mirror | None:
        return self._by_id.get(mirror_id)

    def add(
        self, payload: object
    ) -> tuple[Mirror | None, Mirror | None]:
        """Validate and store a mirror.

        Returns ``(created, None)`` on success or ``(None, existing)`` when
        the name is already registered; the original mirror is never
        overwritten.
        """

        name, upstream = build_mirror_fields(payload)
        existing_id = self._name_to_id.get(name)
        if existing_id is not None:
            return None, self._by_id[existing_id]

        mirror = Mirror(id=uuid.uuid4().hex, name=name, upstream=upstream)
        self._mirrors.append(mirror)
        self._by_id[mirror.id] = mirror
        self._name_to_id[name] = mirror.id
        return mirror, None

    def remove(self, mirror_id: str) -> Mirror | None:
        """Remove and return the mirror with ``mirror_id``, else ``None``.

        The name is released together with the record, so a later
        registration may reuse it; a missing or already removed id
        changes nothing.
        """

        mirror = self._by_id.pop(mirror_id, None)
        if mirror is None:
            return None
        self._mirrors = [
            entry for entry in self._mirrors if entry.id != mirror_id
        ]
        del self._name_to_id[mirror.name]
        return mirror


def _layer_url(upstream: str, digest: str) -> str:
    return upstream.rstrip("/") + "/layers/" + digest


def _url_open(request: urllib.request.Request, *, timeout: float):
    """Open a request through this module's own network entry point.

    Both layer fetches and upstream probes call this thin wrapper instead
    of touching the process-global ``urllib.request.urlopen`` directly.
    Tests therefore substitute only this module-level name for a single
    call; replacing it never affects any other module's network access or
    leaks across test cases.
    """

    return urllib.request.urlopen(request, timeout=timeout)


def fetch_upstream_layer(
    upstream: str,
    digest: str,
    *,
    timeout: float = DEFAULT_FETCH_TIMEOUT,
) -> bytes:
    """Fetch ``<upstream>/layers/<digest>`` and return the raw bytes.

    Raises :class:`MirrorFetchError` with code ``mirror_fetch_failed`` when
    the upstream cannot be contacted or answers a non-200 status. The
    digest comparison is the caller's responsibility.
    """

    url = _layer_url(upstream, digest)
    request = urllib.request.Request(url, method="GET")
    try:
        with _url_open(request, timeout=timeout) as response:
            if getattr(response, "status", response.getcode()) != 200:
                raise MirrorFetchError(
                    "mirror_fetch_failed",
                    "Upstream mirror did not return the layer.",
                )
            return response.read()
    except urllib.error.HTTPError as exc:
        if exc.code == 200:  # pragma: no cover - urlopen never raises on 200
            return exc.read()
        raise MirrorFetchError(
            "mirror_fetch_failed",
            "Upstream mirror did not return the layer.",
        ) from exc
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise MirrorFetchError(
            "mirror_fetch_failed",
            "Upstream mirror could not be reached.",
        ) from exc


def probe_upstream(
    upstream: str,
    *,
    timeout: float = DEFAULT_PROBE_TIMEOUT,
) -> ProbeResult:
    """Probe the registered ``upstream`` address once.

    Issues a GET to the registered upstream base address (with no extra
    path appended) and records the attempt latency. Any HTTP response
    that completes the connection attempt -- including non-2xx statuses,
    which are normal upstream answers -- counts as reachable. Connection
    failures and timeouts count as unreachable; the failed attempt reports
    no status code and no latency. The response body is not consumed
    beyond what is needed to complete the attempt.
    """

    request = urllib.request.Request(upstream, method="GET")
    start = time.monotonic()
    try:
        with _url_open(request, timeout=timeout) as response:
            latency_ms = max(0, int((time.monotonic() - start) * 1000))
            status_code = getattr(response, "status", response.getcode())
            try:
                # Drain the response so the connection can be released;
                # the body itself is irrelevant to reachability.
                response.read()
            except OSError:
                # Headers were already received, so the upstream answered:
                # a body read failure does not turn this into unreachable.
                pass
    except urllib.error.HTTPError as exc:
        latency_ms = max(0, int((time.monotonic() - start) * 1000))
        try:
            exc.read()
        except OSError:
            pass
        finally:
            exc.close()
        status_code = exc.code
    except (urllib.error.URLError, OSError, ValueError):
        return ProbeResult(reachable=False, status_code=None, latency_ms=None)
    return ProbeResult(
        reachable=True, status_code=status_code, latency_ms=latency_ms
    )
