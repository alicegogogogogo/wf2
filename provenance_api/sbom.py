"""In-process SBOM (software bill of materials) documents for resources.

Each registered resource may carry a single SBOM document in one of two
formats (``spdx`` or ``cyclonedx``) together with an ordered component list.
Components are kept in submission order; repeating the same
name/version/digest triple is rejected. Documents are never persisted:
stopping or restarting the service clears every document, and no files are
written.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

#: The two accepted SBOM format identifiers; matched case-sensitively.
FORMATS: tuple[str, ...] = ("spdx", "cyclonedx")
FORMAT_VALUES = frozenset(FORMATS)

_DIGEST_PATTERN = re.compile(r"[0-9a-fA-F]{64}")

#: Fields accepted by the registration request; anything else is rejected.
_ALLOWED_FIELDS = frozenset({"format", "components"})
#: Every component must carry exactly these three non-empty string fields.
_COMPONENT_FIELDS = ("name", "version", "digest")
_COMPONENT_FIELD_SET = frozenset(_COMPONENT_FIELDS)


class SbomValidationError(ValueError):
    """An SBOM registration payload failed field-level validation."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class SbomError(ValueError):
    """An SBOM operation could not proceed.

    ``code`` is the stable, client-facing error code.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class Component:
    """One component entry of an SBOM document."""

    name: str
    version: str
    digest: str

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "version": self.version,
            "digest": self.digest,
        }


@dataclass(frozen=True, slots=True)
class SbomDocument:
    """The single SBOM document recorded for a resource."""

    id: str
    format: str
    components: tuple[Component, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "format": self.format,
            "components": [component.to_dict() for component in self.components],
        }


def _require_component(value: object, index: int) -> Component:
    if not isinstance(value, dict):
        raise SbomValidationError(
            f"Component at index {index} must be a JSON object."
        )
    unknown_fields = set(value) - _COMPONENT_FIELD_SET
    if unknown_fields:
        raise SbomValidationError(
            f"Unknown field in component at index {index}: "
            f"{sorted(unknown_fields)[0]!r}."
        )
    fields: dict[str, str] = {}
    for field in _COMPONENT_FIELDS:
        if field not in value:
            raise SbomValidationError(
                f"Component at index {index} is missing required field "
                f"{field!r}."
            )
        raw = value[field]
        if not isinstance(raw, str):
            label = field.capitalize()
            raise SbomValidationError(
                f"{label} of component at index {index} must be a string."
            )
        if not raw:
            label = field.capitalize()
            raise SbomValidationError(
                f"{label} of component at index {index} must not be empty."
            )
        fields[field] = raw

    digest = fields["digest"]
    if _DIGEST_PATTERN.fullmatch(digest) is None:
        raise SbomValidationError(
            f"Digest of component at index {index} must be a 64-character "
            "hexadecimal string."
        )
    # Digests are rendered in lowercase regardless of input casing.
    fields["digest"] = digest.lower()
    return Component(
        name=fields["name"], version=fields["version"], digest=fields["digest"]
    )


def build_sbom_fields(payload: object) -> tuple[str, tuple[Component, ...]]:
    """Validate a decoded JSON payload and return normalized values.

    Returns ``(format, components)``; component digests are lowercased and
    submission order is preserved.
    """

    if not isinstance(payload, dict):
        raise SbomValidationError("Request body must be a JSON object.")

    unknown_fields = set(payload) - _ALLOWED_FIELDS
    if unknown_fields:
        raise SbomValidationError(
            f"Unknown field: {sorted(unknown_fields)[0]!r}."
        )

    if "format" not in payload:
        raise SbomValidationError("Missing required field: 'format'.")
    format_value = payload["format"]
    if not isinstance(format_value, str) or format_value not in FORMAT_VALUES:
        raise SbomValidationError(
            "Field 'format' must be one of: spdx, cyclonedx."
        )

    if "components" not in payload:
        raise SbomValidationError("Missing required field: 'components'.")
    raw_components = payload["components"]
    if not isinstance(raw_components, list):
        raise SbomValidationError("Field 'components' must be an array.")

    components = tuple(
        _require_component(value, index)
        for index, value in enumerate(raw_components)
    )
    return format_value, components


class SbomStore:
    """Process-local storage holding at most one SBOM document per resource."""

    def __init__(self) -> None:
        self._documents: dict[str, SbomDocument] = {}

    def reset(self) -> None:
        self._documents = {}

    def get(self, resource_id: str) -> SbomDocument | None:
        return self._documents.get(resource_id)

    def submit(
        self,
        resource_id: str,
        format_value: str,
        components: tuple[Component, ...],
    ) -> tuple[SbomDocument, bool]:
        """Submit an SBOM document for ``resource_id``.

        Returns ``(document, created)`` where ``created`` is ``True`` for a
        new document (HTTP 201) and ``False`` for an idempotent resubmission
        of the exact same document (HTTP 200). Raises :class:`SbomError`
        with code ``duplicate_component`` when the submitted list repeats a
        name/version/digest triple, or ``sbom_conflict`` when a different
        document is already recorded; stored data is never modified.
        """

        # A repeated triple is invalid whether or not a document exists.
        seen: set[tuple[str, str, str]] = set()
        for component in components:
            triple = (component.name, component.version, component.digest)
            if triple in seen:
                raise SbomError(
                    "duplicate_component",
                    "The same name, version and digest component appears "
                    "more than once.",
                )
            seen.add(triple)

        existing = self._documents.get(resource_id)
        if existing is not None:
            if existing.format == format_value and existing.components == components:
                return existing, False
            raise SbomError(
                "sbom_conflict",
                "A different SBOM document is already recorded for this "
                "resource.",
            )

        document = SbomDocument(
            id=resource_id, format=format_value, components=components
        )
        self._documents[resource_id] = document
        return document, True
