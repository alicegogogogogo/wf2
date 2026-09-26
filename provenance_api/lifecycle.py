"""In-process lifecycle states for registered resources.

Every resource starts in ``staged`` and can be promoted to ``released``
once its content is assembled and its dependencies are healthy, or be
withdrawn or quarantined with a recorded reason. Only the current state
and reason are kept, in the current process memory only: nothing is
persisted and a restart resets every resource to ``staged``.
"""

from __future__ import annotations

from dataclasses import dataclass

#: The fixed set of lifecycle states; names are case-sensitive.
STATES: tuple[str, ...] = ("staged", "released", "withdrawn", "quarantined")
STATE_VALUES = frozenset(STATES)

#: Target states that always require a non-empty reason.
REASON_REQUIRED_STATES = frozenset({"withdrawn", "quarantined"})

#: Maximum reason length, counted in Unicode code points.
MAX_REASON_LENGTH = 1024

#: Permitted state transitions. ``("staged", "released")`` is additionally
#: gated on assembled content and healthy dependencies by the caller.
_ALLOWED_TRANSITIONS = frozenset(
    {
        ("staged", "released"),
        ("staged", "quarantined"),
        ("released", "withdrawn"),
        ("released", "quarantined"),
        ("withdrawn", "staged"),
        ("quarantined", "staged"),
    }
)

#: States that block a dependent resource from being released.
BLOCKING_STATES = frozenset({"withdrawn", "quarantined"})


class LifecycleError(ValueError):
    """A lifecycle transition could not be applied.

    ``code`` is the stable, client-facing error code.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class LifecycleRecord:
    """The current lifecycle state of one resource."""

    state: str
    reason: str | None


class LifecycleStore:
    """Process-local current lifecycle state per resource id."""

    def __init__(self) -> None:
        self._records: dict[str, LifecycleRecord] = {}

    def reset(self) -> None:
        self._records = {}

    def remove(self, resource_id: str) -> None:
        """Drop any recorded state for a resource.

        Afterwards the resource id reads as the default ``staged`` state
        again; an unknown id is a no-op.
        """

        self._records.pop(resource_id, None)

    def get(self, resource_id: str) -> LifecycleRecord:
        """Return the current record; resources default to ``staged``."""

        return self._records.get(
            resource_id, LifecycleRecord(state="staged", reason=None)
        )

    def set(self, resource_id: str, record: LifecycleRecord) -> None:
        self._records[resource_id] = record

    def apply(
        self, current: LifecycleRecord, target: str, reason: str | None
    ) -> LifecycleRecord:
        """Compute the record for a requested transition.

        Resubmitting the current state with the current reason is an
        idempotent no-op and returns the record unchanged. Any other
        same-state request (a reason change) and any transition outside
        the permitted set raises :class:`LifecycleError` with code
        ``invalid_state_transition``; the caller leaves state untouched.
        """

        if target == current.state:
            if reason == current.reason:
                return current
            raise LifecycleError(
                "invalid_state_transition",
                "The recorded reason must not be changed.",
            )
        if (current.state, target) not in _ALLOWED_TRANSITIONS:
            raise LifecycleError(
                "invalid_state_transition",
                f"Transition from {current.state!r} to {target!r} is not "
                "allowed.",
            )
        return LifecycleRecord(state=target, reason=reason)
