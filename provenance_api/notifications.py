"""In-process notification registrations for registered resources.

A notification record carries a delivery channel, a target on that
channel and a message. Every POST creates a new, independent record:
records are never deduplicated, updated or deleted, and they are kept
per resource strictly in submission order. Nothing is persisted:
stopping or restarting the service clears every record, and no files
are written.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

#: Length caps, counted in Unicode code points.
MAX_CHANNEL_LENGTH = 64
MAX_TARGET_LENGTH = 256
MAX_MESSAGE_LENGTH = 2048

#: Fields accepted by the registration request; anything else is rejected.
_ALLOWED_FIELDS = frozenset({"channel", "target", "message"})
_REQUIRED_FIELDS = ("channel", "target", "message")


class NotificationValidationError(ValueError):
    """A registration payload failed field-level validation."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


@dataclass(frozen=True, slots=True)
class Notification:
    """A single notification record registered against a resource."""

    id: str
    channel: str
    target: str
    message: str

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "channel": self.channel,
            "target": self.target,
            "message": self.message,
        }


def _required_string(value: object, field: str, limit: int) -> str:
    """Validate a required non-empty string bounded by ``limit`` code points."""

    label = field.capitalize()
    if not isinstance(value, str):
        raise NotificationValidationError(f"Field {field!r} must be a string.")
    if not value:
        raise NotificationValidationError(
            f"Field {field!r} must not be empty."
        )
    if len(value) > limit:
        raise NotificationValidationError(
            f"{label} must not exceed {limit} Unicode code points."
        )
    return value


def build_notification_fields(payload: object) -> tuple[str, str, str]:
    """Validate a decoded notification payload and return normalized values.

    Returns ``(channel, target, message)``. All three are required
    non-empty strings bounded by their per-field code point limits.
    """

    if not isinstance(payload, dict):
        raise NotificationValidationError("Request body must be a JSON object.")

    unknown_fields = set(payload) - _ALLOWED_FIELDS
    if unknown_fields:
        raise NotificationValidationError(
            f"Unknown field: {sorted(unknown_fields)[0]!r}."
        )

    for field in _REQUIRED_FIELDS:
        if field not in payload:
            raise NotificationValidationError(
                f"Missing required field: {field!r}."
            )

    channel = _required_string(payload["channel"], "channel", MAX_CHANNEL_LENGTH)
    target = _required_string(payload["target"], "target", MAX_TARGET_LENGTH)
    message = _required_string(
        payload["message"], "message", MAX_MESSAGE_LENGTH
    )

    return channel, target, message


class NotificationStore:
    """Process-local, submission-ordered notification storage per resource."""

    def __init__(self) -> None:
        # resource id -> notifications in submission order.
        self._records: dict[str, list[Notification]] = {}

    def reset(self) -> None:
        self._records = {}

    def add(
        self, resource_id: str, channel: str, target: str, message: str
    ) -> Notification:
        """Append a new, independent notification record for ``resource_id``."""

        record = Notification(
            id=uuid.uuid4().hex,
            channel=channel,
            target=target,
            message=message,
        )
        self._records.setdefault(resource_id, []).append(record)
        return record

    def list_for(self, resource_id: str) -> list[Notification]:
        """Return a resource's notifications in submission order."""

        return list(self._records.get(resource_id, ()))
