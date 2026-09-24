"""In-process security vulnerability (advisory) registry.

Vulnerabilities are registered against an already-registered resource.
They are kept strictly in submission order and only the current process
memory is used: stopping or restarting the service clears every alert,
no files are written and no cross-process synchronization is promised.
Bulk, update, delete and concurrency semantics are intentionally out of
scope.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

#: The fixed set of severity levels; accepted case-insensitively, stored
#: and rendered in lowercase.
SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low")
SEVERITY_VALUES = frozenset(SEVERITIES)

#: Field length bounds, counted in Unicode code points.
MAX_ADVISORY_ID_LENGTH = 256
MAX_COMPONENT_LENGTH = 256
MAX_SUMMARY_LENGTH = 2048
MAX_FIX_VERSION_LENGTH = 256

_ALLOWED_FIELDS = frozenset(
    {"advisory_id", "component", "severity", "summary", "fix_version"}
)
_REQUIRED_FIELDS = ("advisory_id", "component", "severity", "summary")


class VulnerabilityValidationError(ValueError):
    """A registration payload failed field-level validation."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class VulnerabilityDuplicateError(ValueError):
    """The same advisory id and component already exist for a resource.

    ``code`` is the stable, client-facing error code.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.code = "duplicate_vulnerability"
        self.message = message


@dataclass(frozen=True, slots=True)
class Vulnerability:
    """A single registered security alert."""

    id: str
    advisory_id: str
    component: str
    severity: str
    summary: str
    fix_version: str | None

    def to_dict(self) -> dict[str, object]:
        # Stable key order: identifier followed by the five business fields.
        return {
            "id": self.id,
            "advisory_id": self.advisory_id,
            "component": self.component,
            "severity": self.severity,
            "summary": self.summary,
            "fix_version": self.fix_version,
        }


class VulnerabilityStore:
    """Process-local, submission-ordered vulnerability storage.

    Entries are grouped by the id of the resource they were registered
    against. Within one resource, a ``(advisory_id, component)`` pair is
    unique; the same pair on different resources (or a different pair on
    the same resource) is a separate alert.
    """

    def __init__(self) -> None:
        self._entries: dict[str, list[Vulnerability]] = {}
        # resource id -> {(advisory_id, component)}
        self._keys: dict[str, set[tuple[str, str]]] = {}

    def reset(self) -> None:
        self._entries = {}
        self._keys = {}

    def list_for(
        self, resource_id: str, severity: str | None = None
    ) -> list[Vulnerability]:
        """Return a resource's alerts in submission order.

        When ``severity`` is given it must already be normalized to a
        lowercase legal level; matching is then exact against stored
        values.
        """

        entries = self._entries.get(resource_id, ())
        if severity is None:
            return list(entries)
        return [entry for entry in entries if entry.severity == severity]

    def add(self, resource_id: str, payload: object) -> Vulnerability:
        """Validate and store a vulnerability for ``resource_id``.

        Raises :class:`VulnerabilityValidationError` for any malformed
        payload and :class:`VulnerabilityDuplicateError` when the same
        advisory id and component are already registered for the resource;
        in the duplicate case the original alert is left untouched.
        """

        advisory_id, component, severity, summary, fix_version = (
            build_vulnerability_fields(payload)
        )

        keys = self._keys.setdefault(resource_id, set())
        key = (advisory_id, component)
        if key in keys:
            raise VulnerabilityDuplicateError(
                "A vulnerability with the same advisory id and component "
                "already exists for this resource."
            )

        entry = Vulnerability(
            id=uuid.uuid4().hex,
            advisory_id=advisory_id,
            component=component,
            severity=severity,
            summary=summary,
            fix_version=fix_version,
        )
        self._entries.setdefault(resource_id, []).append(entry)
        keys.add(key)
        return entry


def build_vulnerability_fields(
    payload: object,
) -> tuple[str, str, str, str, str | None]:
    """Validate a decoded JSON payload and return normalized field values."""

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

    advisory_id = _require_non_empty_string(
        payload["advisory_id"], "Advisory id", MAX_ADVISORY_ID_LENGTH
    )
    component = _require_non_empty_string(
        payload["component"], "Component", MAX_COMPONENT_LENGTH
    )

    severity_raw = payload["severity"]
    if not isinstance(severity_raw, str) or not severity_raw:
        raise VulnerabilityValidationError(
            "Severity must be a non-empty string."
        )
    severity = severity_raw.lower()
    if severity not in SEVERITY_VALUES:
        allowed = ", ".join(SEVERITIES)
        raise VulnerabilityValidationError(
            f"Severity must be one of: {allowed} (case-insensitive)."
        )

    summary = _require_non_empty_string(
        payload["summary"], "Summary", MAX_SUMMARY_LENGTH
    )

    fix_version: str | None = None
    if "fix_version" in payload:
        value = payload["fix_version"]
        if value is None:
            raise VulnerabilityValidationError(
                "Field 'fix_version' must not be null when provided."
            )
        fix_version = _require_non_empty_string(
            value, "Fix version", MAX_FIX_VERSION_LENGTH
        )

    return advisory_id, component, severity, summary, fix_version


def _require_non_empty_string(
    value: object, label: str, max_length: int
) -> str:
    if not isinstance(value, str):
        raise VulnerabilityValidationError(f"{label} must be a string.")
    if not value:
        raise VulnerabilityValidationError(f"{label} must not be empty.")
    if len(value) > max_length:
        raise VulnerabilityValidationError(
            f"{label} must not exceed {max_length} Unicode code points."
        )
    return value
