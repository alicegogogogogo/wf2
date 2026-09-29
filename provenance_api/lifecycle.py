"""In-process lifecycle states for registered resources.

Every resource starts in ``staged`` and can be promoted to ``released``
once its content is assembled and its dependencies are healthy, or be
withdrawn or quarantined with a recorded reason. Only the current state
and reason are kept, in the current process memory only: nothing is
persisted and a restart resets every resource to ``staged``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from dataclasses import dataclass

if TYPE_CHECKING:
    from .resources import Resource

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

    def state_usage(
        self, resources: list[Resource]
    ) -> list[dict[str, object]]:
        """Group the given resources by their current lifecycle state.

        Resources default to ``staged`` via :meth:`get`, so a resource that
        never left the default state is grouped without materializing a
        record; this method therefore never stores anything. One entry per
        state that currently holds at least one resource, ordered by the
        state's first appearance while walking the resources in resource
        registration order; the groups themselves are never reordered. The
        order is redetermined from the remaining resources on every call,
        so after a deregistration or a state transition each surviving
        entry takes the position of its earliest surviving resource rather
        than keeping a stale slot, and a state whose last resource moved
        away or was removed disappears altogether. Each entry carries the
        five fixed keys ``state``, ``resources``, ``resource_count``,
        ``names`` and ``digests`` in that order. The state is the stored
        lowercase value (one of the four fixed states), echoed verbatim.
        ``resources`` lists the ids of the resources in that state in
        resource registration order; the registry never holds a resource
        twice, so every id appears exactly once and ``resource_count`` is
        that list's length. ``names`` collects those resources' names,
        deduplicated in resource registration order and echoed verbatim:
        no case folding and no whitespace trimming. ``digests`` collects
        the resources' normalized digests, deduplicated by first
        appearance in resource registration order and listed in the
        stored lowercase form. Everything is derived on the fly from the
        current registry and lifecycle records.
        """

        order: list[str] = []
        resources_by_state: dict[str, list[str]] = {}
        names_by_state: dict[str, list[str]] = {}
        seen_names: dict[str, set[str]] = {}
        digests_by_state: dict[str, list[str]] = {}
        seen_digests: dict[str, set[str]] = {}

        for resource in resources:
            state = self.get(resource.id).state
            if state not in resources_by_state:
                order.append(state)
                resources_by_state[state] = []
                names_by_state[state] = []
                seen_names[state] = set()
                digests_by_state[state] = []
                seen_digests[state] = set()
            # The registry holds each resource record exactly once, so
            # every id appended here is unique by construction.
            resources_by_state[state].append(resource.id)
            # Names are deduplicated verbatim: case and surrounding
            # whitespace are significant.
            if resource.name not in seen_names[state]:
                seen_names[state].add(resource.name)
                names_by_state[state].append(resource.name)
            # Digests are stored in their canonical lowercase form.
            if resource.digest not in seen_digests[state]:
                seen_digests[state].add(resource.digest)
                digests_by_state[state].append(resource.digest)

        return [
            {
                "state": state,
                "resources": resources_by_state[state],
                "resource_count": len(resources_by_state[state]),
                "names": names_by_state[state],
                "digests": digests_by_state[state],
            }
            for state in order
        ]

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
