"""In-process lifecycle states for registered resources.

Every resource starts in ``staged``. The current state and the business
reason recorded with the last transition live only in this process: a
restart clears them and nothing is ever written to a file.

The state set is fixed and compared case-sensitively: ``staged``,
``released``, ``withdrawn`` and ``quarantined``. Allowed transitions:

- ``staged`` -> ``released`` (only when content assembly is complete and
  no reachable dependency is withdrawn or quarantined);
- ``staged`` -> ``quarantined`` (non-empty reason required);
- ``released`` -> ``withdrawn`` or ``quarantined`` (non-empty reason
  required);
- ``withdrawn`` -> ``staged`` and ``quarantined`` -> ``staged`` (a
  quarantined resource must pass through ``staged`` before it can be
  released again).

Submitting the current state with the same reason is an idempotent
no-op; any other jump, or resubmitting the current state with a
different reason, is refused with ``invalid_state_transition`` and
leaves the state unchanged.
"""

from __future__ import annotations

#: The fixed lifecycle state set, compared case-sensitively.
STATES: tuple[str, ...] = ("staged", "released", "withdrawn", "quarantined")
STATE_VALUES = frozenset(STATES)

#: State every resource starts in; also the default reported before any
#: transition has been recorded.
DEFAULT_STATE = "staged"

#: Targets that must carry a non-empty business reason.
REASON_REQUIRED_TARGETS = frozenset({"withdrawn", "quarantined"})

#: States that block a dependent resource from being released.
BLOCKED_STATES = frozenset({"withdrawn", "quarantined"})

#: Maximum reason length in Unicode code points.
MAX_REASON_LENGTH = 1024

#: Legal transitions; anything not listed here is ``invalid_state_transition``.
_ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    "staged": frozenset({"released", "quarantined"}),
    "released": frozenset({"withdrawn", "quarantined"}),
    "withdrawn": frozenset({"staged"}),
    "quarantined": frozenset({"staged"}),
}


class LifecycleError(ValueError):
    """A lifecycle transition could not be applied.

    ``code`` is the stable, client-facing error code.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class LifecycleStore:
    """Process-local current-state records keyed by resource id."""

    def __init__(self) -> None:
        # resource id -> (state, reason recorded with the last transition)
        self._records: dict[str, tuple[str, str | None]] = {}

    def reset(self) -> None:
        self._records = {}

    def get(self, resource_id: str) -> tuple[str, str | None]:
        """Return the current ``(state, reason)``; defaults to staged/empty."""

        return self._records.get(resource_id, (DEFAULT_STATE, None))

    def is_blocked(self, resource_id: str) -> bool:
        """Whether the resource is currently withdrawn or quarantined."""

        state, _ = self.get(resource_id)
        return state in BLOCKED_STATES

    def apply(
        self,
        resource_id: str,
        target: str,
        reason: str | None,
        *,
        content_complete: bool,
        blocked_dependency: bool,
    ) -> bool:
        """Attempt a transition to ``target`` with ``reason``.

        ``target`` must be a declared state and ``reason`` must already
        satisfy the field-level rules (non-empty when required, length
        checked by the caller). ``content_complete`` and
        ``blocked_dependency`` describe the resource's assembly state and
        whether any reachable dependency is withdrawn or quarantined.

        Returns ``True`` when a new state was recorded and ``False`` for
        an idempotent resubmission of the current state and reason.
        Raises :class:`LifecycleError` with ``invalid_state_transition``,
        ``content_not_complete`` or ``dependency_blocked``; a failed
        attempt never changes the stored state.
        """

        current, current_reason = self.get(resource_id)

        if target == current:
            if reason == current_reason:
                # Idempotent resubmission: no new record is added.
                return False
            raise LifecycleError(
                "invalid_state_transition",
                "Resubmitting the current state with a different reason is "
                "not allowed.",
            )

        if target not in _ALLOWED_TRANSITIONS[current]:
            raise LifecycleError(
                "invalid_state_transition",
                f"Transition from {current!r} to {target!r} is not allowed.",
            )

        if current == "staged" and target == "released":
            if not content_complete:
                raise LifecycleError(
                    "content_not_complete",
                    "Content for this resource is not complete.",
                )
            if blocked_dependency:
                raise LifecycleError(
                    "dependency_blocked",
                    "A dependency of this resource is withdrawn or "
                    "quarantined.",
                )

        self._records[resource_id] = (target, reason)
        return True
