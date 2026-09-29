"""In-process notification registration for registered resources.

A notification record pairs a channel with a target and a message. Every
submission creates an independent record: records are never deduplicated
and are kept per resource in submission order. A single record can be
updated in place through its notification id, keeping that id and its
submission position while its channel, target and message are replaced;
it can also be removed explicitly through that id. Otherwise a record
only disappears when its resource is deregistered. Nothing here is
persisted: stopping or restarting the service clears every
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

    def remove_one(
        self, resource_id: str, notification_id: str
    ) -> Notification | None:
        """Remove and return one notification of ``resource_id`` by its id.

        Lookup is scoped to ``resource_id``: an id that is unknown, belongs
        to another resource or was already removed answers ``None`` and
        leaves every stored notification untouched. On success the record
        is dropped from the resource's list while the surviving records
        keep their submission order; every derived view is recomputed from
        what remains, so the removed id can never linger there.
        """

        records = self._records.get(resource_id)
        if records is None:
            return None
        index = next(
            (
                position
                for position, record in enumerate(records)
                if record.id == notification_id
            ),
            None,
        )
        if index is None:
            return None
        return records.pop(index)

    def update(
        self, resource_id: str, notification_id: str, payload: object
    ) -> Notification | None:
        """Update one notification of ``resource_id`` in place by its id.

        The payload has the same shape as a registration and is fully
        validated by :func:`build_notification_fields` before any lookup,
        so a bad payload raises :class:`NotificationValidationError`
        before a single record is touched. All three fields are replaced
        with the validated values.

        Lookup is scoped to ``resource_id``: an id that is unknown,
        belongs to another resource or was already removed answers
        ``None`` and leaves every stored notification untouched. On
        success the record keeps the same id and stays at its submission
        position; only the channel, target and message can change, so the
        resource's submission order is undisturbed while every derived
        view is recomputed from the new values on its next call. An
        identical resubmission simply replaces the record with an equal
        one and is answered ``200`` without creating a new record.
        """

        channel, target, message = build_notification_fields(payload)

        records = self._records.get(resource_id)
        if records is None:
            return None
        index = next(
            (
                position
                for position, record in enumerate(records)
                if record.id == notification_id
            ),
            None,
        )
        if index is None:
            return None

        updated = Notification(
            id=records[index].id,
            channel=channel,
            target=target,
            message=message,
        )
        records[index] = updated
        return updated

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

    def usage_by_channel_target(
        self, resource_ids: list[str]
    ) -> list[dict[str, object]]:
        """Summarize all notifications grouped by their channel/target pair.

        The resources are walked in resource registration order and the
        notifications of each resource in their submission order, so a
        pair entry is opened by the first notification encountered for it
        and the entries unfold by that first appearance; the groups are
        never reordered. The order is redetermined from the remaining
        records on every call, so deregistering a resource (which takes
        its notifications with it) lets each surviving entry take the
        position of its earliest surviving notification rather than
        keeping a stale slot, and a pair whose last notification
        disappears is omitted altogether. Each entry carries the six
        fixed keys ``channel``, ``target``, ``notifications``,
        ``notification_count``, ``resources`` and ``resource_count`` in
        that order. The channel and target are echoed verbatim: no case
        folding and no whitespace trimming, so values that differ only
        in case or surrounding whitespace stay separate groups.
        ``notifications`` lists the notification ids in traversal order
        with no deduplication or merging, and ``notification_count``
        counts them one by one. ``resources`` lists the owning resource
        ids deduplicated in resource registration order, each once, and
        ``resource_count`` is that list's length. Everything is derived
        on the fly from the current records.
        """

        order: list[tuple[str, str]] = []
        notifications: dict[tuple[str, str], list[str]] = {}
        resources: dict[tuple[str, str], list[str]] = {}
        seen_resources: dict[tuple[str, str], set[str]] = {}

        for resource_id in resource_ids:
            for record in self._records.get(resource_id, ()):
                key = (record.channel, record.target)
                if key not in notifications:
                    order.append(key)
                    notifications[key] = []
                    resources[key] = []
                    seen_resources[key] = set()
                notifications[key].append(record.id)
                if resource_id not in seen_resources[key]:
                    seen_resources[key].add(resource_id)
                    resources[key].append(resource_id)

        return [
            {
                "channel": channel,
                "target": target,
                "notifications": notifications[(channel, target)],
                "notification_count": len(notifications[(channel, target)]),
                "resources": resources[(channel, target)],
                "resource_count": len(resources[(channel, target)]),
            }
            for channel, target in order
        ]
