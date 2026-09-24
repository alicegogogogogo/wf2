"""In-process license declarations for registered resources.

Each registered resource may carry a single license declaration consisting
of a required non-empty SPDX identifier and an optional non-empty source.
Declarations are never persisted: stopping or restarting the service clears
every declaration, and no files are written.
"""

from __future__ import annotations

from dataclasses import dataclass

#: Fields accepted by the declaration request; anything else is rejected.
_ALLOWED_FIELDS = frozenset({"spdx_id", "source"})


class LicenseValidationError(ValueError):
    """A license declaration payload failed field-level validation."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class LicenseError(ValueError):
    """A license operation could not proceed.

    ``code`` is the stable, client-facing error code.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class LicenseRecord:
    """The single license declaration recorded for a resource."""

    id: str
    spdx_id: str
    source: str | None

    def to_dict(self) -> dict[str, object]:
        return {"id": self.id, "spdx_id": self.spdx_id, "source": self.source}


def build_license_fields(payload: object) -> tuple[str, str | None]:
    """Validate a decoded JSON payload and return ``(spdx_id, source)``."""

    if not isinstance(payload, dict):
        raise LicenseValidationError("Request body must be a JSON object.")

    unknown_fields = set(payload) - _ALLOWED_FIELDS
    if unknown_fields:
        raise LicenseValidationError(
            f"Unknown field: {sorted(unknown_fields)[0]!r}."
        )

    if "spdx_id" not in payload:
        raise LicenseValidationError("Missing required field: 'spdx_id'.")
    spdx_id = payload["spdx_id"]
    if not isinstance(spdx_id, str) or not spdx_id:
        raise LicenseValidationError(
            "Field 'spdx_id' must be a non-empty string."
        )

    source: str | None = None
    if "source" in payload:
        value = payload["source"]
        # An explicit null is a type error; the field is simply omitted to
        # express "no source".
        if not isinstance(value, str) or not value:
            raise LicenseValidationError(
                "Field 'source' must be a non-empty string when provided."
            )
        source = value

    return spdx_id, source


class LicenseStore:
    """Process-local storage holding at most one license declaration per id."""

    def __init__(self) -> None:
        self._records: dict[str, LicenseRecord] = {}

    def reset(self) -> None:
        self._records = {}

    def get(self, resource_id: str) -> LicenseRecord | None:
        return self._records.get(resource_id)

    def submit(
        self, resource_id: str, spdx_id: str, source: str | None
    ) -> tuple[LicenseRecord, bool]:
        """Submit a license declaration for ``resource_id``.

        Returns ``(record, created)`` where ``created`` is ``True`` for a new
        declaration (HTTP 201) and ``False`` for an idempotent resubmission
        of the exact same content (HTTP 200). A different declaration while
        one already exists raises :class:`LicenseError` with code
        ``license_conflict``; the stored declaration is left unchanged.
        """

        existing = self._records.get(resource_id)
        if existing is not None:
            if existing.spdx_id == spdx_id and existing.source == source:
                return existing, False
            raise LicenseError(
                "license_conflict",
                "A different license is already declared for this resource.",
            )

        record = LicenseRecord(id=resource_id, spdx_id=spdx_id, source=source)
        self._records[resource_id] = record
        return record, True
