"""In-process notification registration for registered resources.

A notification record pairs a channel with a target and a message. Every
submission creates an independent record: records are never deduplicated,
updated or deleted, and are kept per resource in submission order. Nothing
here is persisted: stopping or restarting the service clears every
notification, and no files are written.
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
    """A notification payload failed field-level validation."""

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
    """Validate a decoded JSON payload and return ``(channel, target, message)``.

    All three fields are required non-empty strings bounded by their
    respective length caps; unknown fields are rejected.
    """

    if not isinstance(payload, dict):
        raise NotificationValidationError(
            "Request body must be a JSON object."
        )

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

    channel = _required_string(
        payload["channel"], "channel", MAX_CHANNEL_LENGTH
    )
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

    def remove_resource(self, resource_id: str) -> None:
        """Remove every notification recorded for a resource.

        An unknown id is a no-op.
        """

        self._records.pop(resource_id, None)

    def add(self, resource_id: str, payload: object) -> Notification:
        """Validate and append a notification for ``resource_id``.

        Every call creates an independent record; identical submissions are
        never merged or deduplicated. Raises
        :class:`NotificationValidationError` for an invalid payload.
        """

        channel, target, message = build_notification_fields(payload)
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

    def usage_by_channel(
        self, resource_ids: list[str]
    ) -> list[dict[str, object]]:
        """Summarize all notifications grouped by their channel.

        The resources are walked in resource registration order and the
        notifications of each resource in their submission order, so a
        channel entry is opened by the first notification encountered for
        it and the entries unfold by that first appearance; the groups are
        never reordered. The order is redetermined from the remaining
        records on every call, so deregistering a resource (which takes
        its notifications with it) lets each surviving entry take the
        position of its earliest surviving notification rather than
        keeping a stale slot, and a channel whose last notification
        disappears is omitted altogether. Each entry carries the six
        fixed keys ``channel``, ``notifications``, ``notification_count``,
        ``targets``, ``resources`` and ``resource_count`` in that order.
        The channel is echoed verbatim: no case folding and no whitespace
        trimming, so values that differ only in case or surrounding
        whitespace stay separate groups. ``notifications`` lists the
        notification ids in submission order with no deduplication or
        merging, and ``notification_count`` counts them one by one.
        ``targets`` lists the targets deduplicated by first appearance
        and echoed verbatim. ``resources`` lists the owning resource ids
        deduplicated in resource registration order, each once, and
        ``resource_count`` is that list's length. Everything is derived
        on the fly from the current records.
        """

        order: list[str] = []
        notifications: dict[str, list[str]] = {}
        targets: dict[str, list[str]] = {}
        seen_targets: dict[str, set[str]] = {}
        resources: dict[str, list[str]] = {}
        seen_resources: dict[str, set[str]] = {}

        for resource_id in resource_ids:
            for record in self._records.get(resource_id, ()):
                channel = record.channel
                if channel not in notifications:
                    order.append(channel)
                    notifications[channel] = []
                    targets[channel] = []
                    seen_targets[channel] = set()
                    resources[channel] = []
                    seen_resources[channel] = set()
                notifications[channel].append(record.id)
                if record.target not in seen_targets[channel]:
                    seen_targets[channel].add(record.target)
                    targets[channel].append(record.target)
                if resource_id not in seen_resources[channel]:
                    seen_resources[channel].add(resource_id)
                    resources[channel].append(resource_id)

        return [
            {
                "channel": channel,
                "notifications": notifications[channel],
                "notification_count": len(notifications[channel]),
                "targets": targets[channel],
                "resources": resources[channel],
                "resource_count": len(resources[channel]),
            }
            for channel in order
        ]

    def usage_by_target(
        self, resource_ids: list[str]
    ) -> list[dict[str, object]]:
        """Summarize all notifications grouped by their target.

        The resources are walked in resource registration order and the
        notifications of each resource in their submission order, so a
        target entry is opened by the first notification encountered for
        it and the entries unfold by that first appearance; the groups are
        never reordered. The order is redetermined from the remaining
        records on every call, so deregistering a resource (which takes
        its notifications with it) lets each surviving entry take the
        position of its earliest surviving notification rather than
        keeping a stale slot, and a target whose last notification
        disappears is omitted altogether. Each entry carries the six
        fixed keys ``target``, ``notifications``, ``notification_count``,
        ``channels``, ``resources`` and ``resource_count`` in that order.
        The target is echoed verbatim: no case folding and no whitespace
        trimming, so values that differ only in case or surrounding
        whitespace stay separate groups. ``notifications`` lists the
        notification ids in traversal order with no deduplication or
        merging, and ``notification_count`` counts them one by one.
        ``channels`` lists the channels deduplicated by first appearance,
        echoed verbatim with no case folding or sorting. ``resources``
        lists the owning resource ids deduplicated in resource
        registration order, each once, and ``resource_count`` is that
        list's length. Everything is derived on the fly from the current
        records.
        """

        order: list[str] = []
        notifications: dict[str, list[str]] = {}
        channels: dict[str, list[str]] = {}
        seen_channels: dict[str, set[str]] = {}
        resources: dict[str, list[str]] = {}
        seen_resources: dict[str, set[str]] = {}

        for resource_id in resource_ids:
            for record in self._records.get(resource_id, ()):
                target = record.target
                if target not in notifications:
                    order.append(target)
                    notifications[target] = []
                    channels[target] = []
                    seen_channels[target] = set()
                    resources[target] = []
                    seen_resources[target] = set()
                notifications[target].append(record.id)
                if record.channel not in seen_channels[target]:
                    seen_channels[target].add(record.channel)
                    channels[target].append(record.channel)
                if resource_id not in seen_resources[target]:
                    seen_resources[target].add(resource_id)
                    resources[target].append(resource_id)

        return [
            {
                "target": target,
                "notifications": notifications[target],
                "notification_count": len(notifications[target]),
                "channels": channels[target],
                "resources": resources[target],
                "resource_count": len(resources[target]),
            }
            for target in order
        ]
