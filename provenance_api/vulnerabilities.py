"""In-process security vulnerability registration for registered resources.

A vulnerability record pairs an advisory identifier with the affected
component, a severity level, a summary and an optional fixed version.
Records are kept per resource in submission order and are never persisted:
stopping or restarting the service clears every alert, and no files are
written. Alerts can be registered one at a time or as an atomic batch, and
a single alert can later be deleted; updates and concurrency are
intentionally out of scope.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from dataclasses import dataclass

#: The four allowed severity levels; input is case-insensitive but the level
#: is always stored and rendered in lowercase. The tuple is ordered from
#: highest to lowest severity.
SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low")
SEVERITY_VALUES = frozenset(SEVERITIES)

#: Rank of each severity level; a lower number means a higher severity.
_SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}

#: Length caps, counted in Unicode code points.
MAX_ADVISORY_LENGTH = 256
MAX_COMPONENT_LENGTH = 256
MAX_SUMMARY_LENGTH = 2048
MAX_FIXED_VERSION_LENGTH = 256

#: Fields accepted by the registration request; anything else is rejected.
_ALLOWED_FIELDS = frozenset(
    {"advisory", "component", "severity", "summary", "fixed_version"}
)
_REQUIRED_FIELDS = ("advisory", "component", "severity", "summary")

#: Maximum number of alerts accepted by a single batch registration.
MAX_BATCH_SIZE = 100


class VulnerabilityValidationError(ValueError):
    """A registration payload failed field-level validation."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class VulnerabilityError(ValueError):
    """A vulnerability operation could not proceed.

    ``code`` is the stable, client-facing error code.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class Vulnerability:
    """A single vulnerability alert recorded against a resource."""

    id: str
    advisory: str
    component: str
    severity: str
    summary: str
    fixed_version: str | None

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "advisory": self.advisory,
            "component": self.component,
            "severity": self.severity,
            "summary": self.summary,
            "fixed_version": self.fixed_version,
        }


def _required_string(value: object, field: str, limit: int) -> str:
    """Validate a required non-empty string bounded by ``limit`` code points."""

    label = field.capitalize()
    if not isinstance(value, str):
        raise VulnerabilityValidationError(f"Field {field!r} must be a string.")
    if not value:
        raise VulnerabilityValidationError(
            f"Field {field!r} must not be empty."
        )
    if len(value) > limit:
        raise VulnerabilityValidationError(
            f"{label} must not exceed {limit} Unicode code points."
        )
    return value


def build_vulnerability_fields(
    payload: object,
) -> tuple[str, str, str, str, str | None]:
    """Validate a decoded JSON payload and return normalized field values.

    Returns ``(advisory, component, severity, summary, fixed_version)``.
    Severity is matched case-insensitively and normalized to lowercase.
    ``fixed_version`` is ``None`` when omitted.
    """

    if not isinstance(payload, dict):
        raise VulnerabilityValidationError(
            "Request body must be a JSON object."
        )

    unknown_fields = set(payload) - _ALLOWED_FIELDS
    if unknown_fields:
        raise VulnerabilityValidationError(
            f"Unknown field: {sorted(unknown_fields)[0]!r}."
        )

    for field in _REQUIRED_FIELDS:
        if field not in payload:
            raise VulnerabilityValidationError(
                f"Missing required field: {field!r}."
            )

    advisory = _required_string(
        payload["advisory"], "advisory", MAX_ADVISORY_LENGTH
    )
    component = _required_string(
        payload["component"], "component", MAX_COMPONENT_LENGTH
    )

    severity_raw = payload["severity"]
    if not isinstance(severity_raw, str) or not severity_raw:
        raise VulnerabilityValidationError(
            "Field 'severity' must be one of: critical, high, medium, low "
            "(case-insensitive)."
        )
    severity = severity_raw.lower()
    if severity not in SEVERITY_VALUES:
        raise VulnerabilityValidationError(
            "Field 'severity' must be one of: critical, high, medium, low "
            "(case-insensitive)."
        )

    summary = _required_string(
        payload["summary"], "summary", MAX_SUMMARY_LENGTH
    )

    fixed_version: str | None = None
    if "fixed_version" in payload:
        value = payload["fixed_version"]
        if not isinstance(value, str):
            raise VulnerabilityValidationError(
                "Field 'fixed_version' must be a string."
            )
        if not value:
            raise VulnerabilityValidationError(
                "Field 'fixed_version' must not be empty."
            )
        if len(value) > MAX_FIXED_VERSION_LENGTH:
            raise VulnerabilityValidationError(
                f"Fixed version must not exceed {MAX_FIXED_VERSION_LENGTH} "
                "Unicode code points."
            )
        fixed_version = value

    return advisory, component, severity, summary, fixed_version


def build_batch_fields(
    payload: object,
) -> list[tuple[str, str, str, str, str | None]]:
    """Validate a decoded batch payload and return normalized field values.

    The top level must be a JSON object with exactly one field,
    ``vulnerabilities``: a non-empty array of at most
    :data:`MAX_BATCH_SIZE` elements, each validated exactly like a single
    registration payload. Returns one normalized field tuple per element,
    in array order.
    """

    if not isinstance(payload, dict):
        raise VulnerabilityValidationError(
            "Request body must be a JSON object."
        )

    unknown_fields = set(payload) - {"vulnerabilities"}
    if unknown_fields:
        raise VulnerabilityValidationError(
            f"Unknown field: {sorted(unknown_fields)[0]!r}."
        )
    if "vulnerabilities" not in payload:
        raise VulnerabilityValidationError(
            "Missing required field: 'vulnerabilities'."
        )

    items = payload["vulnerabilities"]
    if not isinstance(items, list):
        raise VulnerabilityValidationError(
            "Field 'vulnerabilities' must be an array."
        )
    if not items:
        raise VulnerabilityValidationError(
            "Field 'vulnerabilities' must not be empty."
        )
    if len(items) > MAX_BATCH_SIZE:
        raise VulnerabilityValidationError(
            f"Field 'vulnerabilities' must not exceed {MAX_BATCH_SIZE} "
            "entries."
        )

    return [build_vulnerability_fields(item) for item in items]


def max_severity(severities: Iterable[str]) -> str | None:
    """Return the highest severity among ``severities``, else ``None``.

    Comparison is case-insensitive and follows the fixed ordering
    critical > high > medium > low; the result is always lowercase.
    """

    best: str | None = None
    for severity in severities:
        normalized = severity.lower()
        if best is None or _SEVERITY_RANK[normalized] < _SEVERITY_RANK[best]:
            best = normalized
    return best


class VulnerabilityStore:
    """Process-local, submission-ordered vulnerability storage per resource."""

    def __init__(self) -> None:
        # resource id -> alerts in submission order.
        self._records: dict[str, list[Vulnerability]] = {}
        # resource id -> (advisory, component) duplicates already seen.
        self._keys: dict[str, set[tuple[str, str]]] = {}
        # Every alert across every resource, in global submission order;
        # used by views that aggregate beyond a single resource.
        self._sequence: list[tuple[str, Vulnerability]] = []

    def reset(self) -> None:
        self._records = {}
        self._keys = {}
        self._sequence = []

    def add(self, resource_id: str, payload: object) -> Vulnerability:
        """Validate and append a vulnerability alert for ``resource_id``.

        Raises :class:`VulnerabilityValidationError` for an invalid payload
        or :class:`VulnerabilityError` with code ``duplicate_vulnerability``
        when the same advisory identifier and component pair is already
        recorded for the resource; the original alert is left untouched.
        """

        advisory, component, severity, summary, fixed_version = (
            build_vulnerability_fields(payload)
        )
        key = (advisory, component)
        resource_keys = self._keys.setdefault(resource_id, set())
        if key in resource_keys:
            raise VulnerabilityError(
                "duplicate_vulnerability",
                "An alert with the same advisory and component already "
                "exists for this resource.",
            )

        record = Vulnerability(
            id=uuid.uuid4().hex,
            advisory=advisory,
            component=component,
            severity=severity,
            summary=summary,
            fixed_version=fixed_version,
        )
        self._records.setdefault(resource_id, []).append(record)
        resource_keys.add(key)
        self._sequence.append((resource_id, record))
        return record

    def add_batch(
        self, resource_id: str, payloads: object
    ) -> list[Vulnerability]:
        """Validate and atomically append a batch of alerts for ``resource_id``.

        ``payloads`` must be the decoded ``vulnerabilities`` array of a
        batch request. The elements are treated as submitted in array
        order: on success every alert is recorded in that order and the
        new records are returned in the same order. The batch is atomic —
        raises :class:`VulnerabilityValidationError` when any element is
        invalid, or :class:`VulnerabilityError` with code
        ``duplicate_vulnerability`` when an advisory/component pair repeats
        inside the batch or already exists for the resource; in both cases
        nothing is recorded.
        """

        assert isinstance(payloads, list)
        fields = [build_vulnerability_fields(item) for item in payloads]

        existing = self._keys.get(resource_id, ())
        seen: set[tuple[str, str]] = set()
        for advisory, component, _severity, _summary, _fixed in fields:
            key = (advisory, component)
            if key in existing or key in seen:
                raise VulnerabilityError(
                    "duplicate_vulnerability",
                    "An alert with the same advisory and component already "
                    "exists for this resource.",
                )
            seen.add(key)

        # Validation and duplicate checks are complete; only now mutate.
        records = [
            Vulnerability(
                id=uuid.uuid4().hex,
                advisory=advisory,
                component=component,
                severity=severity,
                summary=summary,
                fixed_version=fixed_version,
            )
            for advisory, component, severity, summary, fixed_version in fields
        ]
        resource_records = self._records.setdefault(resource_id, [])
        resource_keys = self._keys.setdefault(resource_id, set())
        for record in records:
            resource_records.append(record)
            resource_keys.add((record.advisory, record.component))
            self._sequence.append((resource_id, record))
        return records

    def remove(
        self, resource_id: str, vulnerability_id: str
    ) -> Vulnerability:
        """Remove and return a single alert identified by ``vulnerability_id``.

        Lookup is scoped to ``resource_id``: an id that is unknown, belongs
        to another resource, or was already removed raises
        :class:`VulnerabilityError` with code ``vulnerability_not_found``
        and leaves every stored alert untouched. On success the alert is
        dropped from the resource's records (preserving the submission order
        of the rest) and from the global sequence, and its
        ``(advisory, component)`` pair is released so the same pair can be
        registered again afterwards.
        """

        records = self._records.get(resource_id)
        if records is None:
            raise VulnerabilityError(
                "vulnerability_not_found",
                "No vulnerability alert exists with the requested id.",
            )
        index = next(
            (
                position
                for position, record in enumerate(records)
                if record.id == vulnerability_id
            ),
            None,
        )
        if index is None:
            raise VulnerabilityError(
                "vulnerability_not_found",
                "No vulnerability alert exists with the requested id.",
            )

        record = records.pop(index)
        resource_keys = self._keys.get(resource_id)
        if resource_keys is not None:
            resource_keys.discard((record.advisory, record.component))
        self._sequence = [
            (owner_id, alert)
            for owner_id, alert in self._sequence
            if alert is not record
        ]
        return record

    def list_all(self) -> list[tuple[str, Vulnerability]]:
        """Return every alert across resources in global submission order.

        Each entry pairs the resource id the alert was recorded against with
        the alert itself.
        """

        return list(self._sequence)

    def list_for(
        self, resource_id: str, severity: str | None = None
    ) -> list[Vulnerability]:
        """Return a resource's alerts in submission order.

        With ``severity`` set (already normalized to lowercase), only alerts
        at that level are returned; the relative submission order is kept.
        """

        records = self._records.get(resource_id, ())
        if severity is None:
            return list(records)
        return [record for record in records if record.severity == severity]
