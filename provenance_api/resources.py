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


class DependencyError(ValueError):
    """A dependency relation could not be established.

    ``code`` is the stable, client-facing error code.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
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
        # resource id -> ids it directly depends on, and the reverse view.
        self._dependencies: dict[str, set[str]] = {}
        self._dependents: dict[str, set[str]] = {}

    def reset(self) -> None:
        self._resources.clear()
        self._resources = []
        self._by_id = {}
        self._key_to_id = {}
        self._dependencies = {}
        self._dependents = {}

    def list_all(self) -> list[Resource]:
        return list(self._resources)

    def query(
        self,
        *,
        category: str | None = None,
        name: str | None = None,
        digest: str | None = None,
    ) -> list[Resource]:
        """Return matching resources in creation order.

        ``category`` is compared case-insensitively, ``name`` is an exact
        string match and ``digest`` is compared against the stored lowercase
        form. Multiple conditions are AND-ed together.
        """

        if category is None and name is None and digest is None:
            return list(self._resources)

        matches: list[Resource] = []
        for resource in self._resources:
            if category is not None and resource.category != category.lower():
                continue
            if name is not None and resource.name != name:
                continue
            if digest is not None and resource.digest != digest:
                continue
            matches.append(resource)
        return matches

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
        self._dependencies[resource.id] = set()
        self._dependents[resource.id] = set()
        return resource, None

    # --- Dependencies ------------------------------------------------------

    def _reachable(self, start: str, graph: dict[str, set[str]]) -> set[str]:
        """Transitive closure of ``start`` through ``graph`` (start excluded)."""

        seen: set[str] = set()
        stack = list(graph.get(start, ()))
        while stack:
            node = stack.pop()
            if node in seen:
                continue
            seen.add(node)
            stack.extend(graph.get(node, ()))
        return seen

    def _registration_order(self, ids: set[str]) -> list[str]:
        return [r.id for r in self._resources if r.id in ids]

    def add_dependency(self, resource_id: str, dependency_id: str) -> None:
        """Record that ``resource_id`` depends on ``dependency_id``.

        Both resources must already be registered. Raises
        :class:`DependencyError` with code ``duplicate_dependency`` when the
        same-direction relation already exists, or ``dependency_cycle`` for a
        self loop or a relation that would introduce a cycle; in either case
        the graph is left unchanged.
        """

        if resource_id == dependency_id:
            raise DependencyError(
                "dependency_cycle", "A resource must not depend on itself."
            )

        existing = self._dependencies.get(resource_id, ())
        if dependency_id in existing:
            raise DependencyError(
                "duplicate_dependency",
                "This dependency relation already exists.",
            )

        # Adding resource_id -> dependency_id creates a cycle whenever
        # dependency_id can already reach resource_id.
        if resource_id in self._reachable(dependency_id, self._dependencies):
            raise DependencyError(
                "dependency_cycle",
                "This dependency would introduce a cycle.",
            )

        self._dependencies[resource_id].add(dependency_id)
        self._dependents[dependency_id].add(resource_id)

    def list_dependencies(self, resource_id: str) -> list[str]:
        """Return every reachable dependency id in registration order."""

        return self._registration_order(
            self._reachable(resource_id, self._dependencies)
        )

    def list_impact(self, resource_id: str) -> list[str]:
        """Return ids that directly or transitively depend on ``resource_id``.

        The start resource itself is excluded; results are in registration
        order.
        """

        return self._registration_order(
            self._reachable(resource_id, self._dependents)
        )
