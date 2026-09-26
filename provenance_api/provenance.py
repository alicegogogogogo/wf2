"""In-process build provenance records for registered resources.

Each resource keeps at most one provenance record describing a single
build: the builder, a build number, a source summary digest and a list of
materials. Digests are normalized to lowercase and materials keep their
submission order. Nothing here is persisted: stopping or restarting the
service clears every record, no signatures are verified, and promotion
rules are unaffected.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

#: A digest is exactly 64 hexadecimal characters; mixed case is accepted
#: but the digest is always stored and rendered in lowercase.
_DIGEST_PATTERN = re.compile(r"[0-9a-fA-F]{64}")

#: Text fields are non-empty and bounded by 256 Unicode code points.
MAX_TEXT_LENGTH = 256

#: Fields accepted by the registration request; anything else is rejected.
_ALLOWED_FIELDS = frozenset(
    {"builder", "build_number", "source_digest", "materials"}
)
_REQUIRED_FIELDS = ("builder", "build_number", "source_digest", "materials")
_MATERIAL_FIELDS = frozenset({"name", "digest"})


class ProvenanceValidationError(ValueError):
    """A provenance payload failed field-level validation."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class ProvenanceError(ValueError):
    """A provenance operation could not proceed.

    ``code`` is the stable, client-facing error code.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class Material:
    """A single build material identified by name and digest."""

    name: str
    digest: str

    def to_dict(self) -> dict[str, object]:
        return {"name": self.name, "digest": self.digest}


@dataclass(frozen=True, slots=True)
class ProvenanceRecord:
    """The single build provenance record stored for a resource."""

    builder: str
    build_number: str
    source_digest: str
    materials: tuple[Material, ...]

    def to_dict(self, resource_id: str) -> dict[str, object]:
        return {
            "id": resource_id,
            "builder": self.builder,
            "build_number": self.build_number,
            "source_digest": self.source_digest,
            "materials": [material.to_dict() for material in self.materials],
        }


def _required_text(value: object, label: str) -> str:
    """Validate a required non-empty string of at most 256 code points."""

    if not isinstance(value, str):
        raise ProvenanceValidationError(f"{label} must be a string.")
    if not value:
        raise ProvenanceValidationError(f"{label} must not be empty.")
    if len(value) > MAX_TEXT_LENGTH:
        raise ProvenanceValidationError(
            f"{label} must not exceed {MAX_TEXT_LENGTH} Unicode code points."
        )
    return value


def _require_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST_PATTERN.fullmatch(value) is None:
        raise ProvenanceValidationError(
            f"{label} must be a 64-character hexadecimal string."
        )
    return value.lower()


def build_provenance_fields(
    payload: object,
) -> tuple[str, str, str, tuple[Material, ...]]:
    """Validate a decoded provenance payload and return normalized values.

    Returns ``(builder, build_number, source_digest, materials)``. The
    source and material digests are normalized to lowercase and materials
    are returned in their submitted order (an empty material list is
    allowed). Repeated materials (same name and normalized digest) are a
    validation error.
    """

    if not isinstance(payload, dict):
        raise ProvenanceValidationError("Request body must be a JSON object.")

    unknown_fields = set(payload) - _ALLOWED_FIELDS
    if unknown_fields:
        raise ProvenanceValidationError(
            f"Unknown field: {sorted(unknown_fields)[0]!r}."
        )

    for field in _REQUIRED_FIELDS:
        if field not in payload:
            raise ProvenanceValidationError(
                f"Missing required field: {field!r}."
            )

    builder = _required_text(payload["builder"], "Field 'builder'")
    build_number = _required_text(
        payload["build_number"], "Field 'build_number'"
    )
    source_digest = _require_digest(
        payload["source_digest"], "Field 'source_digest'"
    )

    raw_materials = payload["materials"]
    if not isinstance(raw_materials, list):
        raise ProvenanceValidationError("Field 'materials' must be an array.")

    materials: list[Material] = []
    seen: set[tuple[str, str]] = set()
    for position, raw_material in enumerate(raw_materials):
        if not isinstance(raw_material, dict):
            raise ProvenanceValidationError(
                f"Material at index {position} must be a JSON object."
            )
        material_unknown = set(raw_material) - _MATERIAL_FIELDS
        if material_unknown:
            raise ProvenanceValidationError(
                f"Unknown field: {sorted(material_unknown)[0]!r}."
            )
        for field in ("name", "digest"):
            if field not in raw_material:
                raise ProvenanceValidationError(
                    f"Material at index {position} is missing required "
                    f"field: {field!r}."
                )
        name = _required_text(
            raw_material["name"], "Material field 'name'"
        )
        digest = _require_digest(
            raw_material["digest"], "Material field 'digest'"
        )
        key = (name, digest)
        if key in seen:
            raise ProvenanceValidationError(
                "A material with the same name and digest is listed more "
                "than once."
            )
        seen.add(key)
        materials.append(Material(name=name, digest=digest))

    return builder, build_number, source_digest, tuple(materials)


class ProvenanceStore:
    """Process-local storage of at most one provenance record per resource."""

    def __init__(self) -> None:
        self._records: dict[str, ProvenanceRecord] = {}

    def reset(self) -> None:
        self._records = {}

    def remove_resource(self, resource_id: str) -> None:
        """Remove any provenance record for a resource.

        An unknown id is a no-op.
        """

        self._records.pop(resource_id, None)

    def add(
        self, resource_id: str, payload: object
    ) -> tuple[ProvenanceRecord, bool]:
        """Validate and record the provenance for ``resource_id``.

        Returns ``(record, created)`` where ``created`` is ``True`` for a
        first registration (HTTP 201) and ``False`` for an idempotent repeat
        of the exact same normalized content (HTTP 200).

        Raises :class:`ProvenanceValidationError` for an invalid payload or
        :class:`ProvenanceError` with code ``provenance_conflict`` when a
        different record is already stored; the stored record is never
        overwritten.
        """

        builder, build_number, source_digest, materials = (
            build_provenance_fields(payload)
        )
        record = ProvenanceRecord(
            builder=builder,
            build_number=build_number,
            source_digest=source_digest,
            materials=materials,
        )

        existing = self._records.get(resource_id)
        if existing is not None:
            if existing == record:
                return existing, False
            raise ProvenanceError(
                "provenance_conflict",
                "A different provenance record is already registered for "
                "this resource.",
            )

        self._records[resource_id] = record
        return record, True

    def get(self, resource_id: str) -> ProvenanceRecord | None:
        return self._records.get(resource_id)
