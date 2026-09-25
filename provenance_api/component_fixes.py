"""On-the-fly component fix recommendations for registered resources.

For every component recorded in a resource's SBOM, the fix view joins the
resource's vulnerability alerts by component name (exact, case-sensitive,
no trimming) and recommends the greatest non-empty fixed version among the
matching alerts. The recommendation is computed at request time and never
recorded: nothing here is persisted and a restart clears every input just
like the rest of the in-process state.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

#: One or more ASCII decimal digits; Unicode digit characters (e.g.
#: superscripts) deliberately do not count as a numeric segment.
_DECIMAL_SEGMENT = re.compile(r"[0-9]+\Z")


def numeric_version_segments(version: str) -> tuple[int, ...] | None:
    """Split a dotted-decimal version into numeric segments.

    Returns ``None`` when the version is not purely dot-separated decimal
    segments (an empty segment or any non-digit run disqualifies the whole
    candidate). Segments are compared numerically, so leading zeros do not
    matter.
    """

    segments: list[int] = []
    for raw_segment in version.split("."):
        if _DECIMAL_SEGMENT.fullmatch(raw_segment) is None:
            return None
        segments.append(int(raw_segment))
    return tuple(segments)


def compare_numeric_versions(left: str, right: str) -> int:
    """Compare two dotted-decimal versions.

    Shorter segment lists are padded with zero segments before alignment,
    so ``1.2`` and ``1.2.0`` compare equal. Both inputs must already have
    passed :func:`numeric_version_segments`.
    """

    left_segments = numeric_version_segments(left)
    right_segments = numeric_version_segments(right)
    # This helper is only called for candidates that were already validated;
    # guard defensively rather than crash a read-only view.
    if left_segments is None or right_segments is None:
        raise ValueError("Version contains a non-numeric segment.")
    width = max(len(left_segments), len(right_segments))
    for index in range(width):
        lhs = left_segments[index] if index < len(left_segments) else 0
        rhs = right_segments[index] if index < len(right_segments) else 0
        if lhs != rhs:
            return -1 if lhs < rhs else 1
    return 0


def recommended_fix_version(fixed_versions: Iterable[str | None]) -> str | None:
    """Return the greatest valid dotted-decimal fixed version.

    ``None`` entries and versions containing any non-numeric segment are
    ignored entirely and never participate in the maximum. Returns ``None``
    when no usable candidate exists.
    """

    best: str | None = None
    for candidate in fixed_versions:
        if candidate is None or numeric_version_segments(candidate) is None:
            continue
        if best is None or compare_numeric_versions(candidate, best) > 0:
            best = candidate
    return best
