"""In-process SBOM documents and license declarations for resources.

Each resource keeps at most one SBOM document and at most one license
declaration. SBOM components are preserved in submission order together
with their name, version and lowercase 64-character hexadecimal digest.
Nothing here is persisted: stopping or restarting the service clears
every document and license, and no files are written.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

#: The two accepted SBOM document formats; input is case-sensitive.
FORMATS: tuple[str, ...] = ("spdx", "cyclonedx")
FORMAT_VALUES = frozenset(FORMATS)

#: A component digest is exactly 64 hexadecimal characters; mixed case is
#: accepted but the digest is always stored and rendered in lowercase.
_DIGEST_PATTERN = re.compile(r"[0-9a-fA-F]{64}")

#: Fields accepted by the SBOM registration request; anything else is
#: rejected. Both fields are required (``components`` may be an empty list).
_SBOM_ALLOWED_FIELDS = frozenset({"format", "components"})

#: Fields accepted by the license registration request; ``source`` is
#: optional and is rendered as ``null`` when omitted.
_LICENSE_ALLOWED_FIELDS = frozenset({"spdx_id", "source"})


class SbomValidationError(ValueError):
    """An SBOM or license payload failed field-level validation."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class SbomError(ValueError):
    """An SBOM or license operation could not proceed.

    ``code`` is the stable, client-facing error code.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class SbomComponent:
    """A single SBOM component identified by name, version and digest."""

    name: str
    version: str
    digest: str

    def to_dict(self) -> dict[str, object]:
        return {"name": self.name, "version": self.version, "digest": self.digest}


@dataclass(frozen=True, slots=True)
class SbomDocument:
    """The single SBOM document recorded against a resource."""

    format: str
    components: tuple[SbomComponent, ...]

    def to_dict(self, resource_id: str) -> dict[str, object]:
        return {
            "id": resource_id,
            "format": self.format,
            "components": [component.to_dict() for component in self.components],
        }


@dataclass(frozen=True, slots=True)
class LicenseRecord:
    """The single license declaration recorded against a resource."""

    spdx_id: str
    source: str | None

    def to_dict(self, resource_id: str) -> dict[str, object]:
        return {"id": resource_id, "spdx_id": self.spdx_id, "source": self.source}


def _require_non_empty_string(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise SbomValidationError(f"{label} must be a string.")
    if not value:
        raise SbomValidationError(f"{label} must not be empty.")
    return value


def build_sbom_fields(payload: object) -> tuple[str, tuple[SbomComponent, ...]]:
    """Validate a decoded SBOM payload and return normalized values.

    Returns ``(format, components)``. ``format`` must be ``spdx`` or
    ``cyclonedx`` (case-sensitive); ``components`` must be a list (possibly
    empty) of objects whose ``name``, ``version`` and ``digest`` are
    non-empty strings, with ``digest`` normalized to lowercase. Components
    are returned in their submitted order.
    """

    if not isinstance(payload, dict):
        raise SbomValidationError("Request body must be a JSON object.")

    unknown_fields = set(payload) - _SBOM_ALLOWED_FIELDS
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

    components: list[SbomComponent] = []
    for position, raw_component in enumerate(raw_components):
        if not isinstance(raw_component, dict):
            raise SbomValidationError(
                f"Component at index {position} must be a JSON object."
            )
        component_unknown = set(raw_component) - {"name", "version", "digest"}
        if component_unknown:
            raise SbomValidationError(
                f"Unknown field: {sorted(component_unknown)[0]!r}."
            )
        for field in ("name", "version", "digest"):
            if field not in raw_component:
                raise SbomValidationError(
                    f"Component at index {position} is missing required "
                    f"field: {field!r}."
                )
        name = _require_non_empty_string(
            raw_component["name"], "Component field 'name'"
        )
        version = _require_non_empty_string(
            raw_component["version"], "Component field 'version'"
        )
        raw_digest = raw_component["digest"]
        if (
            not isinstance(raw_digest, str)
            or _DIGEST_PATTERN.fullmatch(raw_digest) is None
        ):
            raise SbomValidationError(
                "Component field 'digest' must be a 64-character "
                "hexadecimal string."
            )
        components.append(
            SbomComponent(name=name, version=version, digest=raw_digest.lower())
        )

    return format_value, tuple(components)


def build_license_fields(payload: object) -> tuple[str, str | None]:
    """Validate a decoded license payload and return ``(spdx_id, source)``."""

    if not isinstance(payload, dict):
        raise SbomValidationError("Request body must be a JSON object.")

    unknown_fields = set(payload) - _LICENSE_ALLOWED_FIELDS
    if unknown_fields:
        raise SbomValidationError(
            f"Unknown field: {sorted(unknown_fields)[0]!r}."
        )

    if "spdx_id" not in payload:
        raise SbomValidationError("Missing required field: 'spdx_id'.")
    spdx_id = _require_non_empty_string(payload["spdx_id"], "Field 'spdx_id'")

    source: str | None = None
    if "source" in payload:
        source = _require_non_empty_string(payload["source"], "Field 'source'")

    return spdx_id, source


class SbomStore:
    """Process-local storage of at most one SBOM and license per resource."""

    def __init__(self) -> None:
        self._sboms: dict[str, SbomDocument] = {}
        self._licenses: dict[str, LicenseRecord] = {}

    def reset(self) -> None:
        self._sboms = {}
        self._licenses = {}

    # --- SBOM --------------------------------------------------------------

    def add_sbom(
        self, resource_id: str, payload: object
    ) -> tuple[SbomDocument, bool]:
        """Validate and record the SBOM document for ``resource_id``.

        Returns ``(document, created)`` where ``created`` is ``True`` for a
        first registration (HTTP 201) and ``False`` for an idempotent repeat
        of the exact same document (HTTP 200).

        Raises :class:`SbomValidationError` for an invalid payload,
        :class:`SbomError` with code ``duplicate_component`` when the
        submitted components repeat a name/version/digest triple, or
        ``sbom_conflict`` when a different document is already recorded;
        the stored document is never modified.
        """

        format_value, components = build_sbom_fields(payload)

        seen: set[tuple[str, str, str]] = set()
        for component in components:
            triple = (component.name, component.version, component.digest)
            if triple in seen:
                raise SbomError(
                    "duplicate_component",
                    "An identical component (same name, version and "
                    "digest) is listed more than once.",
                )
            seen.add(triple)

        document = SbomDocument(format=format_value, components=components)

        existing = self._sboms.get(resource_id)
        if existing is not None:
            if existing == document:
                return existing, False
            raise SbomError(
                "sbom_conflict",
                "A different SBOM document is already recorded for this "
                "resource.",
            )

        self._sboms[resource_id] = document
        return document, True

    def get_sbom(self, resource_id: str) -> SbomDocument | None:
        return self._sboms.get(resource_id)

    # --- License -----------------------------------------------------------

    def add_license(
        self, resource_id: str, payload: object
    ) -> tuple[LicenseRecord, bool]:
        """Validate and record the license declaration for ``resource_id``.

        Returns ``(record, created)`` with ``created`` ``False`` for an
        idempotent repeat of the same declaration (HTTP 200). A different
        declaration raises :class:`SbomError` with code
        ``license_conflict``; the stored declaration is left untouched.
        """

        spdx_id, source = build_license_fields(payload)
        record = LicenseRecord(spdx_id=spdx_id, source=source)

        existing = self._licenses.get(resource_id)
        if existing is not None:
            if existing == record:
                return existing, False
            raise SbomError(
                "license_conflict",
                "A different license is already declared for this resource.",
            )

        self._licenses[resource_id] = record
        return record, True

    def get_license(self, resource_id: str) -> LicenseRecord | None:
        return self._licenses.get(resource_id)
