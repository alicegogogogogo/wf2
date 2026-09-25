"""Process-local upstream probe results for registered image mirrors.

A probe performs a single connection attempt against a mirror's registered
upstream base address and records the outcome. Results live only in process
memory: a restart clears every result, nothing is ever written to a file, and
probing never touches the shared layer cache or its counters.
"""

from __future__ import annotations

import time
import urllib.error
import urllib.request
from dataclasses import dataclass

#: Probe timeout in seconds for contacting an upstream mirror.
DEFAULT_PROBE_TIMEOUT = 10.0

#: Stable error code reported when an upstream cannot be reached.
PROBE_FAILED = "probe_failed"


@dataclass(frozen=True, slots=True)
class ProbeResult:
    """The most recent probe outcome for a mirror."""

    id: str
    reachable: bool
    status_code: int | None
    latency_ms: int | None

    def to_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "id": self.id,
            "reachable": self.reachable,
            "status_code": self.status_code,
            "latency_ms": self.latency_ms,
        }
        if not self.reachable:
            result["error"] = PROBE_FAILED
        return result


class MirrorProbeStore:
    """Process-local storage of at most the latest result per mirror."""

    def __init__(self) -> None:
        self._results: dict[str, ProbeResult] = {}

    def reset(self) -> None:
        self._results = {}

    def get(self, mirror_id: str) -> ProbeResult | None:
        return self._results.get(mirror_id)

    def set(self, mirror_id: str, result: ProbeResult) -> None:
        """Record ``result`` for ``mirror_id``, overwriting the last one."""

        self._results[mirror_id] = result

    def remove(self, mirror_id: str) -> None:
        """Drop any result recorded for ``mirror_id``."""

        self._results.pop(mirror_id, None)


def probe_upstream(
    upstream: str,
    mirror_id: str,
    *,
    timeout: float = DEFAULT_PROBE_TIMEOUT,
) -> ProbeResult:
    """Make one connection attempt against ``upstream`` and record timing.

    Any complete HTTP response -- including error statuses such as 404 --
    counts as reachable; connection failures and timeouts count as failed.
    """

    request = urllib.request.Request(upstream, method="GET")
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status_code = getattr(response, "status", response.getcode())
        return ProbeResult(
            id=mirror_id,
            reachable=True,
            status_code=int(status_code),
            latency_ms=max(0, int((time.monotonic() - started) * 1000)),
        )
    except urllib.error.HTTPError as exc:
        # An HTTP error response still means the upstream answered; close
        # the response to release the underlying connection.
        code = exc.code
        exc.close()
        return ProbeResult(
            id=mirror_id,
            reachable=True,
            status_code=int(code),
            latency_ms=max(0, int((time.monotonic() - started) * 1000)),
        )
    except (urllib.error.URLError, OSError, ValueError):
        return ProbeResult(
            id=mirror_id,
            reachable=False,
            status_code=None,
            latency_ms=max(0, int((time.monotonic() - started) * 1000)),
        )
