"""In-process resource registry and registration validation."""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass

#: The four resource categories exposed by the service.
CATEGORIES: tuple[str, ...] = ("code", "model", "dataset", "artifact")
_CATEGORY_VALUES = frozenset(CATEGORIES)

_DIGEST_PATTERN = re.compile(r"[0-9a-fA-F]{64}")
_ALLOWED_FIELDS = frozenset({"name", "category", "digest", "source"})
_REQUIRED_FIELDS = ("name", "category", "digest")


class ResourceValidationError(ValueError):
    """A registration payload failed field-level validation."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


@dataclass(frozen=True, slots=True)
class Resource:
    """A single registered resource record."""

    id: str
    name: str
    category: str
    digest: str
    source: str | None

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "digest": self.digest,
            "source": self.source,
        }


def normalize_category(value: object) -> str | None:
    """Return the canonical lowercase category, or ``None`` if invalid."""

    if not isinstance(value, str):
        return None
    candidate = value.lower()
    if candidate not in _CATEGORY_VALUES:
        return None
    return candidate


def normalize_digest(value: object) -> str | None:
    """Return the canonical lowercase digest, or ``None`` if malformed."""

    if not isinstance(value, str) or _DIGEST_PATTERN.fullmatch(value) is None:
        return None
    # Hexadecimal digests are case-insensitive; compare them canonically.
    return value.lower()


def _require_non_empty_string(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise ResourceValidationError(f"{label} must be a string.")
    if not value.strip():
        raise ResourceValidationError(f"{label} must not be empty.")
    return value


def build_resource_fields(
    payload: object,
) -> tuple[str, str, str, str | None]:
    """Validate a decoded JSON payload and return normalized field values."""

    if not isinstance(payload, dict):
        raise ResourceValidationError("Request body must be a JSON object.")

    unknown_fields = set(payload) - _ALLOWED_FIELDS
    if unknown_fields:
        raise ResourceValidationError(
            f"Unknown field: {sorted(unknown_fields)[0]!r}."
        )

    for field in _REQUIRED_FIELDS:
        if field not in payload:
            raise ResourceValidationError(
                f"Missing required field: {field!r}."
            )

    name = _require_non_empty_string(payload["name"], "Name")

    category_raw = payload["category"]
    if not isinstance(category_raw, str):
        raise ResourceValidationError("Category must be a string.")
    category = category_raw.lower()
    if category not in _CATEGORY_VALUES:
        allowed = ", ".join(CATEGORIES)
        raise ResourceValidationError(
            f"Category must be one of: {allowed} (case-insensitive)."
        )

    digest_raw = payload["digest"]
    if not isinstance(digest_raw, str) or _DIGEST_PATTERN.fullmatch(
        digest_raw
    ) is None:
        raise ResourceValidationError(
            "Digest must be a 64-character hexadecimal string."
        )
    # Hexadecimal digests are case-insensitive; store them canonically.
    digest = digest_raw.lower()

    source: str | None = None
    if "source" in payload:
        source = _require_non_empty_string(payload["source"], "Source")

    return name, category, digest, source


class ResourceStore:
    """Process-local, insertion-ordered resource storage."""

    def __init__(self) -> None:
        self._resources: list[Resource] = []
        self._by_id: dict[str, Resource] = {}
        self._key_to_id: dict[tuple[str, str, str], str] = {}

    def reset(self) -> None:
        self._resources.clear()
        self._resources = []
        self._by_id = {}
        self._key_to_id = {}

    def list_all(self) -> list[Resource]:
        return list(self._resources)

    def get(self, resource_id: str) -> Resource | None:
        return self._by_id.get(resource_id)

    def add(
        self, payload: object
    ) -> tuple[Resource | None, Resource | None]:
        """Validate and store a resource.

        Returns ``(created, None)`` on success or ``(None, existing)`` when
        the same category, name and digest are already registered.
        """

        name, category, digest, source = build_resource_fields(payload)
        key = (category, name, digest)
        existing_id = self._key_to_id.get(key)
        if existing_id is not None:
            return None, self._by_id[existing_id]

        resource = Resource(
            id=uuid.uuid4().hex,
            name=name,
            category=category,
            digest=digest,
            source=source,
        )
        self._resources.append(resource)
        self._by_id[resource.id] = resource
        self._key_to_id[key] = resource.id
        return resource, None
