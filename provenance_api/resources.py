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

#: Maximum number of dependency edges accepted in one batch registration.
MAX_DEPENDENCY_BATCH_SIZE = 100


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


def build_dependency_batch_fields(
    payload: object, *, reject_duplicates: bool = False
) -> list[str]:
    """Validate a decoded dependency batch payload, returning the id list.

    The top level must be a JSON object carrying exactly one field,
    ``dependencies``: a non-empty array of at most
    :data:`MAX_DEPENDENCY_BATCH_SIZE` non-empty strings, none containing a
    path separator (``/`` or ``\\``). The ids are returned in their
    submitted order.

    When ``reject_duplicates`` is set (the batch-removal path), an id
    repeated inside the array is rejected here like every other shape
    error, so the request fails before any business data is read. The
    batch-registration path leaves the flag clear: its repeat check is
    ordered after self loops (but before existing-edge and cycle checks)
    in :meth:`ResourceStore.add_dependencies` so that, e.g., a
    self-referential repeated entry reports the cycle rather than the
    repeat. Existence and graph conflicts are likewise checked later so
    their error codes keep precedence.
    """

    if not isinstance(payload, dict):
        raise ResourceValidationError("Request body must be a JSON object.")

    unknown_fields = set(payload) - {"dependencies"}
    if unknown_fields:
        raise ResourceValidationError(
            f"Unknown field: {sorted(unknown_fields)[0]!r}."
        )
    if "dependencies" not in payload:
        raise ResourceValidationError(
            "Missing required field: 'dependencies'."
        )

    items = payload["dependencies"]
    if not isinstance(items, list):
        raise ResourceValidationError(
            "Field 'dependencies' must be an array."
        )
    if not items:
        raise ResourceValidationError(
            "Field 'dependencies' must not be empty."
        )
    if len(items) > MAX_DEPENDENCY_BATCH_SIZE:
        raise ResourceValidationError(
            f"Field 'dependencies' must not exceed "
            f"{MAX_DEPENDENCY_BATCH_SIZE} entries."
        )

    dependency_ids: list[str] = []
    seen: set[str] = set()
    for position, item in enumerate(items):
        if not isinstance(item, str) or not item:
            raise ResourceValidationError(
                f"Dependency at index {position} must be a non-empty string."
            )
        if "/" in item or "\\" in item:
            raise ResourceValidationError(
                f"Dependency at index {position} must not contain path "
                "separators."
            )
        if reject_duplicates and item in seen:
            raise ResourceValidationError(
                "A dependency must not be listed more than once in the "
                "same batch."
            )
        seen.add(item)
        dependency_ids.append(item)

    return dependency_ids


class ResourceStore:
    """Process-local, insertion-ordered resource storage."""

    def __init__(self) -> None:
        self._resources: list[Resource] = []
        self._by_id: dict[str, Resource] = {}
        self._key_to_id: dict[tuple[str, str, str], str] = {}
        # resource id -> ids it directly depends on, and the reverse view.
        # Insertion-ordered dicts stand in for ordered sets: membership stays
        # O(1) while iteration remembers the order in which each relation was
        # established, which the global graph snapshot reports.
        self._dependencies: dict[str, dict[str, None]] = {}
        self._dependents: dict[str, dict[str, None]] = {}

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
        self._dependencies[resource.id] = {}
        self._dependents[resource.id] = {}
        return resource, None

    def add_remote(
        self,
        *,
        name: str,
        category: str,
        digest: str,
        source: str | None,
        resource_id: str | None = None,
    ) -> Resource:
        """Store a resource resolved from a remote repository.

        The caller has already validated the fields and matched the digest
        against the registry, so the record is constructed directly; the
        same uniqueness key is enforced defensively. When ``resource_id``
        is given it is reused (the caller already minted it during
        planning); otherwise a fresh id is generated.
        """

        key = (category, name, digest)
        existing_id = self._key_to_id.get(key)
        if existing_id is not None:
            return self._by_id[existing_id]

        resource = Resource(
            id=resource_id if resource_id is not None else uuid.uuid4().hex,
            name=name,
            category=category,
            digest=digest,
            source=source,
        )
        self._resources.append(resource)
        self._by_id[resource.id] = resource
        self._key_to_id[key] = resource.id
        self._dependencies[resource.id] = {}
        self._dependents[resource.id] = {}
        return resource

    def discard(self, resource_id: str) -> None:
        """Remove a resource that has no edges yet.

        Used to roll back a resource created during an aborted operation.
        Only safe for resources with no dependencies or dependents.
        """

        resource = self._by_id.pop(resource_id, None)
        if resource is None:
            return
        self._resources = [r for r in self._resources if r.id != resource_id]
        self._key_to_id.pop(
            (resource.category, resource.name, resource.digest), None
        )
        self._dependencies.pop(resource_id, None)
        self._dependents.pop(resource_id, None)

    def remove(self, resource_id: str) -> Resource | None:
        """Remove a resource and every dependency edge touching it.

        Returns the removed record, or ``None`` when the id is unknown.
        Edges the resource started and edges pointing at it disappear
        from both graph views; every other resource and edge is left
        untouched. The id is never reused by later registrations.
        """

        resource = self._by_id.pop(resource_id, None)
        if resource is None:
            return None
        self._resources = [r for r in self._resources if r.id != resource_id]
        self._key_to_id.pop(
            (resource.category, resource.name, resource.digest), None
        )
        for dependency_id in self._dependencies.pop(resource_id, ()):
            dependents = self._dependents.get(dependency_id)
            if dependents is not None:
                dependents.pop(resource_id, None)
        for dependent_id in self._dependents.pop(resource_id, ()):
            dependencies = self._dependencies.get(dependent_id)
            if dependencies is not None:
                dependencies.pop(resource_id, None)
        return resource

    # --- Dependencies ------------------------------------------------------

    def _reachable(
        self, start: str, graph: dict[str, dict[str, None]]
    ) -> set[str]:
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

    def check_dependency(self, resource_id: str, dependency_id: str) -> None:
        """Validate an edge without mutating the graph.

        Raises :class:`DependencyError` with code ``duplicate_dependency``
        when the same-direction relation already exists, or
        ``dependency_cycle`` for a self loop or a relation that would
        introduce a cycle.
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

    def add_dependency(self, resource_id: str, dependency_id: str) -> None:
        """Record that ``resource_id`` depends on ``dependency_id``.

        Both resources must already be registered. Raises
        :class:`DependencyError` with code ``duplicate_dependency`` when the
        same-direction relation already exists, or ``dependency_cycle`` for a
        self loop or a relation that would introduce a cycle; in either case
        the graph is left unchanged.
        """

        self.check_dependency(resource_id, dependency_id)
        self._dependencies[resource_id][dependency_id] = None
        self._dependents[dependency_id][resource_id] = None

    def add_dependencies(
        self, resource_id: str, dependency_ids: list[str]
    ) -> None:
        """Atomically record several edges out of ``resource_id``.

        Both the start and every depended-upon resource must already be
        registered (the caller checks existence); ``dependency_ids`` must
        come from :func:`build_dependency_batch_fields`, so it is a
        non-empty list of non-empty, separator-free strings in submission
        order. Conflict precedence is a fixed rule order, not the
        submission position: the whole batch is first screened for self
        loops, then for repeats inside the batch, then for existing
        same-direction edges, and finally for edges that would introduce a
        cycle. When several entries hit different rules at once, only the
        foremost rule is reported; within one rule the earliest submission
        position wins. A self loop or an introduced cycle raises
        :class:`DependencyError` with code ``dependency_cycle`` and an
        existing edge raises one with code ``duplicate_dependency`` (both
        409); an id repeated inside the batch raises
        :class:`ResourceValidationError` (400 ``invalid_request``), but
        only when no entry is a self loop, which is screened first.
        Every edge in the batch shares the same origin, so an accepted
        edge can never feed a path back to the start that did not already
        exist; cycle detection therefore uses the committed graph exactly
        like :meth:`check_dependency`. The whole batch is atomic: a
        failure leaves the graph exactly as it was; on success every edge is
        established in submission order.
        """

        existing = self._dependencies.get(resource_id, ())

        # Each pass is read-only; the graph is touched only once every rule
        # has passed, which makes the precedence independent of where in
        # the batch each conflict sits and guarantees all-or-nothing
        # behavior.
        for dependency_id in dependency_ids:
            if dependency_id == resource_id:
                raise DependencyError(
                    "dependency_cycle",
                    "A resource must not depend on itself.",
                )

        seen: set[str] = set()
        for dependency_id in dependency_ids:
            if dependency_id in seen:
                raise ResourceValidationError(
                    "A dependency must not be listed more than once in the "
                    "same batch."
                )
            seen.add(dependency_id)

        for dependency_id in dependency_ids:
            if dependency_id in existing:
                raise DependencyError(
                    "duplicate_dependency",
                    "This dependency relation already exists.",
                )

        for dependency_id in dependency_ids:
            if resource_id in self._reachable(
                dependency_id, self._dependencies
            ):
                raise DependencyError(
                    "dependency_cycle",
                    "This dependency would introduce a cycle.",
                )

        # Every check passed; only now mutate, preserving submission order
        # in the ordered edge dicts.
        for dependency_id in dependency_ids:
            self._dependencies[resource_id][dependency_id] = None
            self._dependents[dependency_id][resource_id] = None

    def has_dependency(self, resource_id: str, dependency_id: str) -> bool:
        """Return whether the direct edge ``resource_id -> dependency_id`` exists."""

        return dependency_id in self._dependencies.get(resource_id, ())

    def remove_dependency(self, resource_id: str, dependency_id: str) -> bool:
        """Remove only the direct edge from ``resource_id`` to ``dependency_id``.

        Returns ``True`` when the edge existed and was removed, ``False``
        when there was no such direct edge. Neither resource record nor any
        other edge is touched; transitive relations that survive through
        other paths are left to be recomputed by the read views.
        """

        dependencies = self._dependencies.get(resource_id)
        if dependencies is None or dependency_id not in dependencies:
            return False
        del dependencies[dependency_id]
        dependents = self._dependents.get(dependency_id)
        if dependents is not None:
            dependents.pop(resource_id, None)
        return True

    def remove_dependencies(
        self, resource_id: str, dependency_ids: list[str]
    ) -> None:
        """Atomically remove several direct edges out of ``resource_id``.

        The start resource must already be registered (the caller checks
        existence); ``dependency_ids`` comes from
        :func:`build_dependency_batch_fields` with duplicate rejection on,
        so it is a non-empty list of distinct, non-empty, separator-free
        strings in submission order. Every listed direct edge must
        currently exist; the first submission position without such an
        edge raises :class:`DependencyError` with code
        ``dependency_not_found`` and no edge is removed, so a repeat of a
        failed request reports the same missing relation. Only when every
        edge is present are they all removed; resource records and every
        other edge are left untouched, and transitive relations that
        survive through other paths are recomputed by the read views.
        """

        dependencies = self._dependencies.get(resource_id)
        if dependencies is None:
            raise DependencyError(
                "dependency_not_found",
                "No direct dependency relation exists from this resource "
                "to the requested dependency.",
            )
        # Read-only pass first: a missing entry must never leave the batch
        # half-deleted. The first absent position wins, in submission order.
        for dependency_id in dependency_ids:
            if dependency_id not in dependencies:
                raise DependencyError(
                    "dependency_not_found",
                    "No direct dependency relation exists from this "
                    "resource to the requested dependency.",
                )

        # Every edge exists; remove them all after the checks.
        for dependency_id in dependency_ids:
            del dependencies[dependency_id]
            dependents = self._dependents.get(dependency_id)
            if dependents is not None:
                dependents.pop(resource_id, None)

    def list_dependencies(self, resource_id: str) -> list[str]:
        """Return every reachable dependency id in registration order."""

        return self._registration_order(
            self._reachable(resource_id, self._dependencies)
        )

    def shortest_path(self, start: str, end: str) -> list[str] | None:
        """Return the shortest directed path from ``start`` to ``end``.

        The path follows dependency edges in their direction (the start
        resource depends on the end resource) and is reported as the list
        of node ids, ``start`` first and ``end`` last, with no repeated
        nodes. ``start == end`` yields the single-node path. Returns
        ``None`` when ``end`` is not reachable from ``start``. Among
        equally short paths the one whose nodes come earliest in
        registration order -- compared from the second node onward -- is
        picked, so the answer is stable.
        """

        if start == end:
            return [start]

        # Hops from every node to ``end`` along the edge direction,
        # computed as a breadth-first walk over the reverse graph.
        dist: dict[str, int] = {end: 0}
        queue = [end]
        for node in queue:
            for predecessor in self._dependents.get(node, ()):
                if predecessor not in dist:
                    dist[predecessor] = dist[node] + 1
                    queue.append(predecessor)
        if start not in dist:
            return None

        order = {
            resource.id: index
            for index, resource in enumerate(self._resources)
        }
        path = [start]
        current = start
        while current != end:
            remaining = dist[current]
            # Every candidate continues on a shortest path; taking the
            # earliest-registered one at each step yields the stable pick.
            current = min(
                (
                    successor
                    for successor in self._dependencies.get(current, ())
                    if dist.get(successor) == remaining - 1
                ),
                key=lambda node: order[node],
            )
            path.append(current)
        return path

    def all_shortest_paths(
        self, start: str, end: str
    ) -> list[list[str]] | None:
        """Return every shortest directed path from ``start`` to ``end``.

        Each path follows dependency edges in their direction (the start
        resource depends on the end resource) and is reported as the list
        of node ids, ``start`` first and ``end`` last, with no repeated
        nodes. ``start == end`` yields the single single-node path.
        Returns ``None`` when ``end`` is not reachable from ``start``.
        The paths are ordered stably: by the second node's registration
        order first, then by each subsequent node's registration order.
        """

        if start == end:
            return [[start]]

        # Hops from every node to ``end`` along the edge direction,
        # computed as a breadth-first walk over the reverse graph.
        dist: dict[str, int] = {end: 0}
        queue = [end]
        for node in queue:
            for predecessor in self._dependents.get(node, ()):
                if predecessor not in dist:
                    dist[predecessor] = dist[node] + 1
                    queue.append(predecessor)
        if start not in dist:
            return None

        # Enumerate every shortest path: from each node only the successors
        # exactly one hop closer to ``end`` can continue a shortest path.
        # The graph is a DAG, so the walk always terminates.
        paths: list[list[str]] = []
        stack: list[tuple[str, list[str]]] = [(start, [start])]
        while stack:
            node, path = stack.pop()
            if node == end:
                paths.append(path)
                continue
            remaining = dist[node]
            for successor in self._dependencies.get(node, ()):
                if dist.get(successor) == remaining - 1:
                    stack.append((successor, [*path, successor]))

        order = {
            resource.id: index
            for index, resource in enumerate(self._resources)
        }
        paths.sort(
            key=lambda path: tuple(order[node] for node in path[1:])
        )
        return paths

    def list_impact(self, resource_id: str) -> list[str]:
        """Return ids that directly or transitively depend on ``resource_id``.

        The start resource itself is excluded; results are in registration
        order.
        """

        return self._registration_order(
            self._reachable(resource_id, self._dependents)
        )

    # --- Graph snapshot ------------------------------------------------------

    def list_direct_dependencies(self, resource_id: str) -> list[str]:
        """Return the ids ``resource_id`` directly depends on.

        Only direct outbound edges, in the order the relations were
        established; the transitive closure is left to
        :meth:`list_dependencies`.
        """

        return list(self._dependencies.get(resource_id, ()))

    def list_direct_dependents(self, resource_id: str) -> list[str]:
        """Return the ids that directly depend on ``resource_id``.

        Only direct inbound edges, in the order the relations were
        established; the transitive closure is left to :meth:`list_impact`.
        """

        return list(self._dependents.get(resource_id, ()))

    def list_edges(self) -> list[tuple[str, str]]:
        """Return every direct edge as ``(resource_id, dependency_id)``.

        Edges are grouped by the start resource's registration order; within
        one start resource they follow the order in which each relation was
        established. Manually registered and cross-reference-resolved edges
        are reported alike, since both flow through
        :meth:`add_dependency`.
        """

        return [
            (resource.id, dependency_id)
            for resource in self._resources
            for dependency_id in self._dependencies.get(resource.id, ())
        ]

    def graph_stats(self) -> dict[str, object]:
        """Compute whole-graph statistics from the current registry.

        Counts nodes and direct edges, lists isolated resources, ranks
        resources by out/in degree and measures the longest dependency
        chain (in nodes). Manually registered and cross-reference-resolved
        edges are counted alike, since both flow through
        :meth:`add_dependency`. Everything is derived on the fly.
        """

        ids = [resource.id for resource in self._resources]
        out_degree = {
            resource_id: len(self._dependencies.get(resource_id, ()))
            for resource_id in ids
        }
        in_degree = {
            resource_id: len(self._dependents.get(resource_id, ()))
            for resource_id in ids
        }

        isolated = [
            resource_id
            for resource_id in ids
            if out_degree[resource_id] == 0 and in_degree[resource_id] == 0
        ]

        # The graph is a DAG (cycles are rejected at registration time), so
        # the longest chain is the maximum successor-path depth. The
        # iterative postorder walk avoids any recursion limit on long
        # chains; ``depth`` counts nodes, so an isolated node scores one.
        depth: dict[str, int] = {}
        for root in ids:
            stack: list[tuple[str, bool]] = [(root, False)]
            while stack:
                node, expanded = stack.pop()
                if node in depth:
                    continue
                successors = self._dependencies.get(node, ())
                if not expanded:
                    stack.append((node, True))
                    for successor in successors:
                        if successor not in depth:
                            stack.append((successor, False))
                    continue
                depth[node] = (
                    1
                    if not successors
                    else 1 + max(depth[successor] for successor in successors)
                )
        max_depth = max((depth[resource_id] for resource_id in ids), default=0)

        def ranking(counts: dict[str, int]) -> list[dict[str, object]]:
            # ``sorted`` is stable, so equal degrees keep registration order.
            ordered = sorted(
                (
                    (resource_id, counts[resource_id])
                    for resource_id in ids
                    if counts[resource_id] > 0
                ),
                key=lambda item: -item[1],
            )
            return [
                {"resource_id": resource_id, "degree": degree}
                for resource_id, degree in ordered
            ]

        return {
            "nodes": len(ids),
            "edges": sum(out_degree.values()),
            "isolated": isolated,
            "out_degree": ranking(out_degree),
            "in_degree": ranking(in_degree),
            "max_depth": max_depth,
        }

    def dependency_closure_summary(self) -> list[dict[str, object]]:
        """Summarize dependency closure size per registered resource.

        One entry per resource, in registration order, each with the fixed
        key order ``id``, ``direct_count``, ``closure_count`` and
        ``max_chain``. ``direct_count`` counts the resource's own outbound
        edges (manual and cross-reference-resolved edges alike);
        ``closure_count`` is the deduplicated reachable dependency count
        excluding the resource itself (zero for an empty closure);
        ``max_chain`` is the longest outgoing path counted in nodes and
        including the start resource, so a resource without dependencies
        scores one. Everything is derived on the fly.
        """

        ids = [resource.id for resource in self._resources]

        # The graph is a DAG (cycles are rejected at registration time), so
        # the longest chain is the maximum successor-path depth. The
        # iterative postorder walk avoids any recursion limit on long
        # chains; ``depth`` counts nodes, so a resource without
        # dependencies scores one.
        depth: dict[str, int] = {}
        for root in ids:
            stack: list[tuple[str, bool]] = [(root, False)]
            while stack:
                node, expanded = stack.pop()
                if node in depth:
                    continue
                successors = self._dependencies.get(node, ())
                if not expanded:
                    stack.append((node, True))
                    for successor in successors:
                        if successor not in depth:
                            stack.append((successor, False))
                    continue
                depth[node] = (
                    1
                    if not successors
                    else 1 + max(depth[successor] for successor in successors)
                )

        return [
            {
                "id": resource_id,
                "direct_count": len(
                    self._dependencies.get(resource_id, ())
                ),
                "closure_count": len(
                    self._reachable(resource_id, self._dependencies)
                ),
                "max_chain": depth[resource_id],
            }
            for resource_id in ids
        ]

    # --- Dependency usage -----------------------------------------------------

    def dependency_usage(self) -> list[dict[str, object]]:
        """Summarize, per depended-upon resource, who depends on it.

        One entry per resource with at least one dependent, in resource
        registration order, each with the fixed key order ``id``,
        ``dependents``, ``dependent_count`` and ``max_dependent_chain``.
        ``dependents`` lists every resource that directly or transitively
        depends on the resource, deduplicated and ordered by resource
        registration order, and ``dependent_count`` is that list's length.
        ``max_dependent_chain`` is the longest path from any dependent to
        the resource, counted in nodes with both ends included; a resource
        that is only directly depended on scores two. Manually registered
        and cross-reference-resolved edges are counted alike; everything is
        derived on the fly.
        """

        ids = [resource.id for resource in self._resources]

        # The graph is a DAG (cycles are rejected at registration time), so
        # the longest path ending at each node is computed over the reverse
        # graph with an iterative postorder walk that avoids any recursion
        # limit on long chains. ``height`` counts nodes of the longest path
        # ending at the node, so a node without inbound edges scores one
        # and a node only directly depended on scores two.
        height: dict[str, int] = {}
        for root in ids:
            stack: list[tuple[str, bool]] = [(root, False)]
            while stack:
                node, expanded = stack.pop()
                if node in height:
                    continue
                predecessors = self._dependents.get(node, ())
                if not expanded:
                    stack.append((node, True))
                    for predecessor in predecessors:
                        if predecessor not in height:
                            stack.append((predecessor, False))
                    continue
                height[node] = (
                    1
                    if not predecessors
                    else 1
                    + max(height[predecessor] for predecessor in predecessors)
                )

        usage: list[dict[str, object]] = []
        for resource_id in ids:
            # Resources nobody depends on get no entry, regardless of
            # whether they themselves depend on something else.
            if not self._dependents.get(resource_id):
                continue
            dependents = self._registration_order(
                self._reachable(resource_id, self._dependents)
            )
            usage.append(
                {
                    "id": resource_id,
                    "dependents": dependents,
                    "dependent_count": len(dependents),
                    "max_dependent_chain": height[resource_id],
                }
            )
        return usage

    # --- Digest usage --------------------------------------------------------

    def digest_usage(self) -> list[dict[str, object]]:
        """Group the registered resources by their normalized digest.

        One entry per digest, ordered by the digest's first appearance in
        resource registration order; the groups themselves are never
        reordered. The order is redetermined from the remaining resources
        on every call, so after a deregistration each surviving entry --
        including the one immediately following the deleted first
        occurrence -- takes the position of its earliest surviving
        resource rather than keeping a stale slot, and a digest whose last
        resource is removed disappears altogether. Each entry carries the
        four fixed keys ``digest``, ``resources``, ``resource_count`` and
        ``names`` in that order. The digest is the stored canonical
        lowercase 64-character form, echoed verbatim. ``resources`` lists
        the ids of the resources carrying that digest in resource
        registration order, each one once. ``resource_count`` is that
        list's length. ``names`` collects those resources' names,
        deduplicated in resource registration order and echoed verbatim:
        no case folding and no whitespace trimming, so names differing
        only by case or surrounding whitespace stay separate entries.
        Everything is derived on the fly from the current registry.
        """

        order: list[str] = []
        resources_by_digest: dict[str, list[str]] = {}
        seen_resources: dict[str, set[str]] = {}
        names_by_digest: dict[str, list[str]] = {}
        seen_names: dict[str, set[str]] = {}

        for resource in self._resources:
            digest = resource.digest
            if digest not in resources_by_digest:
                order.append(digest)
                resources_by_digest[digest] = []
                seen_resources[digest] = set()
                names_by_digest[digest] = []
                seen_names[digest] = set()
            if resource.id not in seen_resources[digest]:
                seen_resources[digest].add(resource.id)
                resources_by_digest[digest].append(resource.id)
            # Names are deduplicated verbatim: case and surrounding
            # whitespace are significant.
            if resource.name not in seen_names[digest]:
                seen_names[digest].add(resource.name)
                names_by_digest[digest].append(resource.name)

        return [
            {
                "digest": digest,
                "resources": resources_by_digest[digest],
                "resource_count": len(resources_by_digest[digest]),
                "names": names_by_digest[digest],
            }
            for digest in order
        ]

    # --- Name usage ----------------------------------------------------------

    def name_usage(self) -> list[dict[str, object]]:
        """Group the registered resources by their registration name.

        One entry per name, ordered by the name's first appearance in
        resource registration order; the groups themselves are never
        reordered. The order is redetermined from the remaining
        resources on every call, so after a deregistration each
        surviving entry takes the position of its earliest surviving
        resource rather than keeping a stale slot, and a name whose
        last resource is removed disappears altogether. Each entry
        carries the five fixed keys ``name``, ``resources``,
        ``resource_count``, ``digests`` and ``categories`` in that
        order. The name is echoed verbatim: no case folding and no
        whitespace trimming, so names differing only by case or
        surrounding whitespace stay separate groups. ``resources``
        lists the ids of the resources carrying that name in resource
        registration order, each one once, and ``resource_count`` is
        that list's length. ``digests`` collects those resources'
        canonical lowercase digests, deduplicated in order of first
        appearance and listed lowercase. ``categories`` collects
        those resources' categories, deduplicated in resource
        registration order and listed lowercase (they are already
        stored canonically). Everything is derived on the fly from
        the current registry.
        """

        order: list[str] = []
        resources_by_name: dict[str, list[str]] = {}
        seen_resources: dict[str, set[str]] = {}
        digests_by_name: dict[str, list[str]] = {}
        seen_digests: dict[str, set[str]] = {}
        categories_by_name: dict[str, list[str]] = {}
        seen_categories: dict[str, set[str]] = {}

        for resource in self._resources:
            name = resource.name
            if name not in resources_by_name:
                order.append(name)
                resources_by_name[name] = []
                seen_resources[name] = set()
                digests_by_name[name] = []
                seen_digests[name] = set()
                categories_by_name[name] = []
                seen_categories[name] = set()
            if resource.id not in seen_resources[name]:
                seen_resources[name].add(resource.id)
                resources_by_name[name].append(resource.id)
            # Digests are stored canonically lowercase; dedupe in the
            # order they first appear among this name's resources.
            if resource.digest not in seen_digests[name]:
                seen_digests[name].add(resource.digest)
                digests_by_name[name].append(resource.digest)
            # Categories are stored canonically lowercase; dedupe in
            # resource registration order.
            if resource.category not in seen_categories[name]:
                seen_categories[name].add(resource.category)
                categories_by_name[name].append(resource.category)

        return [
            {
                "name": name,
                "resources": resources_by_name[name],
                "resource_count": len(resources_by_name[name]),
                "digests": digests_by_name[name],
                "categories": categories_by_name[name],
            }
            for name in order
        ]
