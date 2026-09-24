"""In-process resource registry, registration validation and dependency graph."""

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
_DEPENDENCY_FIELDS = frozenset({"dependency_id"})


class ResourceValidationError(ValueError):
    """A registration payload failed field-level validation."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class DependencyValidationError(ValueError):
    """A dependency payload failed field-level validation."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class DuplicateDependencyError(Exception):
    """The same directed dependency edge was already registered."""


class DependencyCycleError(Exception):
    """The proposed edge is a self-loop or would close a cycle."""


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


@dataclass(frozen=True, slots=True)
class Dependency:
    """A directed edge: a resource depends on another resource."""

    resource_id: str
    dependency_id: str

    def to_dict(self) -> dict[str, object]:
        return {"resource_id": self.resource_id, "dependency_id": self.dependency_id}


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


def build_dependency_fields(payload: object) -> str:
    """Validate a decoded dependency payload and return the dependency id."""

    if not isinstance(payload, dict):
        raise DependencyValidationError("Request body must be a JSON object.")

    unknown_fields = set(payload) - _DEPENDENCY_FIELDS
    if unknown_fields:
        raise DependencyValidationError(
            f"Unknown field: {sorted(unknown_fields)[0]!r}."
        )
    if "dependency_id" not in payload:
        raise DependencyValidationError(
            "Missing required field: 'dependency_id'."
        )

    dependency_id = payload["dependency_id"]
    if not isinstance(dependency_id, str):
        raise DependencyValidationError("dependency_id must be a string.")
    if not dependency_id:
        raise DependencyValidationError("dependency_id must not be empty.")
    if "/" in dependency_id or "\\" in dependency_id:
        raise DependencyValidationError(
            "dependency_id must not contain path separators."
        )
    return dependency_id


class ResourceStore:
    """Process-local, insertion-ordered resource storage."""

    def __init__(self) -> None:
        self._resources: list[Resource] = []
        self._by_id: dict[str, Resource] = {}
        self._key_to_id: dict[tuple[str, str, str], str] = {}
        #: Outgoing edges keyed by the depending resource, in edge insertion
        #: order; the values are sets for O(1) duplicate checks.
        self._dependencies: dict[str, set[str]] = {}
        #: Reverse edges keyed by the depended-on resource.
        self._dependents: dict[str, set[str]] = {}
        self._edge_keys: set[tuple[str, str]] = set()

    def reset(self) -> None:
        self._resources.clear()
        self._resources = []
        self._by_id = {}
        self._key_to_id = {}
        self._dependencies = {}
        self._dependents = {}
        self._edge_keys = set()

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
        return resource, None

    # -- Dependency graph ---------------------------------------------------

    def add_dependency(
        self, resource_id: str, dependency_id: str
    ) -> Dependency:
        """Add a directed edge ``resource_id -> dependency_id``.

        Both endpoints must already be registered; callers are responsible
        for verifying existence. Raises
        :class:`DuplicateDependencyError` for an existing edge in the same
        direction and :class:`DependencyCycleError` for a self-loop or any
        edge that would close a cycle. Failed calls never mutate the graph.
        """

        if resource_id == dependency_id:
            raise DependencyCycleError("A resource cannot depend on itself.")

        key = (resource_id, dependency_id)
        if key in self._edge_keys:
            raise DuplicateDependencyError(
                "This dependency relationship already exists."
            )

        if self._reaches(dependency_id, resource_id):
            raise DependencyCycleError(
                "This dependency would create a cycle."
            )

        dependency = Dependency(resource_id, dependency_id)
        self._edge_keys.add(key)
        self._dependencies.setdefault(resource_id, set()).add(dependency_id)
        self._dependents.setdefault(dependency_id, set()).add(resource_id)
        return dependency

    def _reaches(self, source_id: str, target_id: str) -> bool:
        """Return whether ``target_id`` is reachable from ``source_id``."""

        stack = [source_id]
        seen: set[str] = {source_id}
        while stack:
            current = stack.pop()
            if current == target_id:
                return True
            for neighbour in self._dependencies.get(current, ()):
                if neighbour not in seen:
                    seen.add(neighbour)
                    stack.append(neighbour)
        return False

    def list_dependencies(self, resource_id: str) -> list[Resource]:
        """Return all transitive dependencies in registration order.

        Every reachable resource is reported at most once and the origin
        itself is never included.
        """

        return self._reachable(resource_id, self._dependencies)

    def list_impact(self, resource_id: str) -> list[Resource]:
        """Return resources directly or indirectly depending on the origin.

        Traversal follows reverse edges; results are ordered by resource
        registration order and the origin itself is never included.
        """

        return self._reachable(resource_id, self._dependents)

    def _reachable(
        self, origin_id: str, adjacency: dict[str, set[str]]
    ) -> list[Resource]:
        reachable: set[str] = set()
        stack: list[str] = [origin_id]
        while stack:
            current = stack.pop()
            for neighbour in adjacency.get(current, ()):
                if neighbour not in reachable:
                    reachable.add(neighbour)
                    stack.append(neighbour)
        # Stable output regardless of graph insertion or set iteration.
        return [r for r in self._resources if r.id in reachable]
