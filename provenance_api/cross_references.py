"""Cross-repository references and remote resource resolution.

A cross-reference hangs off a locally registered resource (the
*dependent*) and points at a resource living in another repository. A
record carries four client-supplied keys:

- ``repository`` names the remote repository; the first time a repository
  name is seen it is bound to the ``upstream`` address;
- ``upstream`` is the absolute ``http``/``https`` base address of the
  remote repository;
- ``remote_id`` identifies the resource within that repository;
- ``digest`` is the 64-character hexadecimal SHA-256 digest the caller
  expects the remote resource to have.

On registration the remote repository is contacted at
``<upstream>/resources/<remote_id>`` and the returned metadata must carry
``name``, ``category``, ``digest`` and ``source``. The reported digest is
compared against the expected one. On success a local resource is
created (or an identical existing one reused) and a same-direction
dependency edge from the local resource to the resolved one is
established, so resolved edges participate in the existing dependency
topology and impact analysis.

Registration is staged so every detectable failure happens before any
state changes:

1. :meth:`CrossReferenceStore.check_prerequisites` rejects a repository
   bound to a different upstream and a repeated ``(repository,
   remote_id)`` pair;
2. the remote repository is contacted and its metadata validated;
3. :meth:`CrossReferenceStore.plan` resolves the local identity (reuse or
   create) and pre-validates the dependency edge (self loop, duplicate
   edge, cycle);
4. the caller writes the resolved metadata to the shared layer cache
   (which may still raise ``cache_conflict``);
5. :meth:`CrossReferenceStore.commit` creates the resource, adds the edge
   and stores the reference record atomically.

Everything lives in the current process memory: records, bindings,
resources and edges are lost on restart and nothing is written to a
file. Batching and concurrency are intentionally out of scope.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from urllib.parse import quote, urlsplit

from .resources import (
    CATEGORIES,
    DependencyError,
    Resource,
    ResourceStore,
)

#: Fetch timeout in seconds for contacting an upstream repository.
DEFAULT_FETCH_TIMEOUT = 10.0

_DIGEST_PATTERN = re.compile(r"[0-9a-fA-F]{64}")
_ALLOWED_FIELDS = frozenset(
    {"repository", "upstream", "remote_id", "digest"}
)
_REQUIRED_FIELDS = ("repository", "upstream", "remote_id", "digest")
_CATEGORY_VALUES = frozenset(CATEGORIES)
#: Keys a remote ``/resources/<id>`` document must contain.
_REMOTE_FIELDS = ("name", "category", "digest", "source")


class CrossReferenceValidationError(ValueError):
    """A registration payload failed field-level validation."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class CrossReferenceError(Exception):
    """A cross-reference could not be established.

    ``code`` is the stable, client-facing error code and ``http_status``
    the status line the HTTP layer should answer with.
    """

    def __init__(self, code: str, message: str, *, http_status: int) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = http_status


@dataclass(frozen=True, slots=True)
class CrossReference:
    """A single registered cross-repository reference."""

    resource_id: str
    repository: str
    upstream: str
    remote_id: str
    digest: str

    def to_dict(self) -> dict[str, object]:
        # ``resource_id`` first, then the four registration keys in their
        # documented order.
        return {
            "resource_id": self.resource_id,
            "repository": self.repository,
            "upstream": self.upstream,
            "remote_id": self.remote_id,
            "digest": self.digest,
        }


def _require_non_empty_string(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise CrossReferenceValidationError(f"{label} must be a string.")
    if not value.strip():
        raise CrossReferenceValidationError(f"{label} must not be empty.")
    return value


def _build_upstream(value: object) -> str:
    upstream = _require_non_empty_string(value, "Upstream")
    parts = urlsplit(upstream)
    # A network location is required so relative addresses or bare schemes
    # are rejected; only http and https are supported.
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise CrossReferenceValidationError(
            "Upstream must be an absolute http or https URL."
        )
    return upstream


def build_cross_reference_fields(
    payload: object,
) -> tuple[str, str, str, str]:
    """Validate a decoded JSON payload and return normalized field values."""

    if not isinstance(payload, dict):
        raise CrossReferenceValidationError(
            "Request body must be a JSON object."
        )

    unknown_fields = set(payload) - _ALLOWED_FIELDS
    if unknown_fields:
        raise CrossReferenceValidationError(
            f"Unknown field: {sorted(unknown_fields)[0]!r}."
        )

    for field in _REQUIRED_FIELDS:
        if field not in payload:
            raise CrossReferenceValidationError(
                f"Missing required field: {field!r}."
            )

    repository = _require_non_empty_string(
        payload["repository"], "Repository"
    )
    upstream = _build_upstream(payload["upstream"])
    remote_id = _require_non_empty_string(payload["remote_id"], "Remote id")
    if "/" in remote_id or "\\" in remote_id:
        raise CrossReferenceValidationError(
            "Remote id must not contain path separators."
        )

    digest_raw = payload["digest"]
    if not isinstance(digest_raw, str) or _DIGEST_PATTERN.fullmatch(
        digest_raw
    ) is None:
        raise CrossReferenceValidationError(
            "Digest must be a 64-character hexadecimal string."
        )
    # Hexadecimal digests are case-insensitive; compare canonically.
    digest = digest_raw.lower()

    return repository, upstream, remote_id, digest


def _remote_resource_url(upstream: str, remote_id: str) -> str:
    # Mirror the mirror-source joining rule (trailing slash stripped) and
    # percent-encode the remote id segment.
    return (
        upstream.rstrip("/")
        + "/resources/"
        + quote(remote_id, safe="")
    )


def fetch_remote_resource(
    upstream: str,
    remote_id: str,
    *,
    timeout: float = DEFAULT_FETCH_TIMEOUT,
) -> bytes:
    """GET ``<upstream>/resources/<remote_id>`` and return the raw body.

    Raises :class:`CrossReferenceError` with code ``remote_unreachable``
    when the upstream cannot be contacted, times out or answers a non-200
    status.
    """

    url = _remote_resource_url(upstream, remote_id)
    request = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if getattr(response, "status", response.getcode()) != 200:
                raise CrossReferenceError(
                    "remote_unreachable",
                    "Upstream repository did not return the resource.",
                    http_status=502,
                )
            return response.read()
    except CrossReferenceError:
        raise
    except urllib.error.HTTPError as exc:
        exc.close()
        raise CrossReferenceError(
            "remote_unreachable",
            "Upstream repository did not return the resource.",
            http_status=502,
        ) from exc
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise CrossReferenceError(
            "remote_unreachable",
            "Upstream repository could not be reached.",
            http_status=502,
        ) from exc


def parse_remote_metadata(raw: bytes) -> dict[str, object]:
    """Decode and shape-check the remote resource document.

    Returns the decoded JSON object with ``category`` and ``digest``
    normalized to lowercase. Raises :class:`CrossReferenceError` with code
    ``resolution_failed`` when the body is not decodable JSON, is not an
    object, misses one of ``name``/``category``/``digest``/``source``,
    carries a wrong field type, an invalid category or digest, or a null
    or empty value.
    """

    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CrossReferenceError(
            "resolution_failed",
            "Upstream resource metadata could not be decoded.",
            http_status=502,
        ) from exc

    if not isinstance(payload, dict):
        raise CrossReferenceError(
            "resolution_failed",
            "Upstream resource metadata must be a JSON object.",
            http_status=502,
        )

    for field in _REMOTE_FIELDS:
        if field not in payload:
            raise CrossReferenceError(
                "resolution_failed",
                f"Upstream metadata is missing field {field!r}.",
                http_status=502,
            )

    name = payload["name"]
    if not isinstance(name, str) or not name:
        raise CrossReferenceError(
            "resolution_failed",
            "Upstream metadata field 'name' must be a non-empty string.",
            http_status=502,
        )

    category_raw = payload["category"]
    if not isinstance(category_raw, str) or not category_raw:
        raise CrossReferenceError(
            "resolution_failed",
            "Upstream metadata field 'category' must be a non-empty string.",
            http_status=502,
        )
    category = category_raw.lower()
    if category not in _CATEGORY_VALUES:
        raise CrossReferenceError(
            "resolution_failed",
            "Upstream metadata field 'category' is not a valid category.",
            http_status=502,
        )

    digest_raw = payload["digest"]
    if not isinstance(digest_raw, str) or _DIGEST_PATTERN.fullmatch(
        digest_raw
    ) is None:
        raise CrossReferenceError(
            "resolution_failed",
            "Upstream metadata field 'digest' must be a 64-character "
            "hexadecimal string.",
            http_status=502,
        )
    digest = digest_raw.lower()

    source = payload["source"]
    if not isinstance(source, str) or not source:
        raise CrossReferenceError(
            "resolution_failed",
            "Upstream metadata field 'source' must be a non-empty string.",
            http_status=502,
        )

    return {
        "name": name,
        "category": category,
        "digest": digest,
        "source": source,
    }


@dataclass(frozen=True, slots=True)
class Resolution:
    """The validated outcome of contacting the upstream repository."""

    name: str
    category: str
    digest: str
    source: str
    raw: bytes


def resolve_remote(upstream: str, remote_id: str, expected_digest: str) -> Resolution:
    """Fetch and validate the remote resource, enforcing its digest.

    Error codes, all surfaced as HTTP 502 by the caller:

    - ``remote_unreachable``: connection failure, timeout or non-200;
    - ``resolution_failed``: undecodable or malformed metadata;
    - ``remote_digest_mismatch``: reported digest differs from
      ``expected_digest``.
    """

    raw = fetch_remote_resource(upstream, remote_id)
    metadata = parse_remote_metadata(raw)
    digest = str(metadata["digest"])
    if digest != expected_digest:
        raise CrossReferenceError(
            "remote_digest_mismatch",
            "Upstream resource digest does not match the expected digest.",
            http_status=502,
        )
    return Resolution(
        name=str(metadata["name"]),
        category=str(metadata["category"]),
        digest=digest,
        source=str(metadata["source"]),
        raw=raw,
    )


@dataclass(frozen=True, slots=True)
class _Plan:
    """The validated, not-yet-committed outcome of a registration."""

    resource_id: str
    repository: str
    upstream: str
    remote_id: str
    digest: str
    dependency: Resource
    create_resource: bool


class CrossReferenceStore:
    """Process-local, insertion-ordered cross-reference storage.

    Besides the records themselves the store keeps the binding of each
    repository name to its upstream address and a ``(repository,
    remote_id)`` uniqueness index. All state is kept in memory and lost on
    restart.
    """

    def __init__(self) -> None:
        self._records: list[CrossReference] = []
        self._repository_upstream: dict[str, str] = {}
        self._pairs: set[tuple[str, str]] = set()

    def reset(self) -> None:
        self._records = []
        self._repository_upstream = {}
        self._pairs = set()

    def remove_resource(self, resource_id: str) -> None:
        """Remove every reference registered by a resource.

        The derived indexes (repository bindings and uniqueness pairs) are
        rebuilt from the remaining records, so constraints implied by other
        resources' references are preserved. Local resources created while
        resolving the removed references are deliberately kept.
        """

        self._records = [
            record
            for record in self._records
            if record.resource_id != resource_id
        ]
        self._repository_upstream = {}
        self._pairs = set()
        for record in self._records:
            self._repository_upstream.setdefault(
                record.repository, record.upstream
            )
            self._pairs.add((record.repository, record.remote_id))

    def list_for(self, resource_id: str) -> list[CrossReference]:
        """Return a resource's references in registration order."""

        return [
            record
            for record in self._records
            if record.resource_id == resource_id
        ]

    def check_prerequisites(
        self,
        repository: str,
        upstream: str,
        remote_id: str,
    ) -> None:
        """Validate conflicts detectable before contacting the upstream.

        Raises :class:`CrossReferenceError` (HTTP 409) for a repository
        name bound to a different upstream (``repository_conflict``) or a
        repeated ``(repository, remote_id)`` pair
        (``duplicate_reference``). Nothing is mutated.
        """

        bound = self._repository_upstream.get(repository)
        if bound is not None and bound != upstream:
            raise CrossReferenceError(
                "repository_conflict",
                "Repository is already registered with a different upstream.",
                http_status=409,
            )
        if (repository, remote_id) in self._pairs:
            raise CrossReferenceError(
                "duplicate_reference",
                "This remote resource is already referenced from that "
                "repository.",
                http_status=409,
            )

    def plan(
        self,
        resource_store: ResourceStore,
        *,
        resource_id: str,
        repository: str,
        upstream: str,
        remote_id: str,
        digest: str,
        resolution: Resolution,
    ) -> _Plan:
        """Resolve the local identity and pre-validate the dependency edge.

        Raises :class:`CrossReferenceError` (HTTP 409) for:

        - ``identity_conflict``: a local resource with the resolved digest
          has a different name or category;
        - ``duplicate_dependency``: the same-direction edge already exists;
        - ``dependency_cycle``: a self loop or an edge that would close a
          cycle.

        No state is mutated: the returned plan tells :meth:`commit`
        whether to create the local resource.
        """

        # Reuse only a resource whose digest, name and category all match.
        dependency: Resource | None = None
        mismatched = False
        for candidate in resource_store.query(digest=resolution.digest):
            if (
                candidate.name == resolution.name
                and candidate.category == resolution.category
            ):
                dependency = candidate
                break
            mismatched = True
        if dependency is None:
            if mismatched:
                raise CrossReferenceError(
                    "identity_conflict",
                    "A local resource with the same digest has a different "
                    "name or category.",
                    http_status=409,
                )
            # Constructed only for the edge pre-check; committed later by
            # ``commit`` through ``ResourceStore.add_remote``.
            dependency = Resource(
                id=uuid.uuid4().hex,
                name=resolution.name,
                category=resolution.category,
                digest=resolution.digest,
                source=resolution.source,
            )
            create_resource = True
        else:
            create_resource = False

        try:
            # Pure validation: raises for a self loop, an existing
            # same-direction edge or a would-be cycle without mutating the
            # graph.
            resource_store.check_dependency(resource_id, dependency.id)
        except DependencyError as exc:
            raise CrossReferenceError(
                exc.code, exc.message, http_status=409
            ) from exc

        return _Plan(
            resource_id=resource_id,
            repository=repository,
            upstream=upstream,
            remote_id=remote_id,
            digest=digest,
            dependency=dependency,
            create_resource=create_resource,
        )

    def commit(
        self, resource_store: ResourceStore, plan: _Plan
    ) -> tuple[CrossReference, Resource]:
        """Create the resource, add the edge and store the reference.

        The plan's edge was pre-validated by :meth:`plan`; if the graph
        write still fails (it cannot without concurrent mutation), the
        freshly created resource is rolled back so the registry is left
        untouched.
        """

        if plan.create_resource:
            dependency = resource_store.add_remote(
                name=plan.dependency.name,
                category=plan.dependency.category,
                digest=plan.dependency.digest,
                source=plan.dependency.source,
                resource_id=plan.dependency.id,
            )
        else:
            dependency = plan.dependency

        try:
            resource_store.add_dependency(plan.resource_id, dependency.id)
        except DependencyError:
            if plan.create_resource:
                resource_store.discard(dependency.id)
            raise

        record = CrossReference(
            resource_id=plan.resource_id,
            repository=plan.repository,
            upstream=plan.upstream,
            remote_id=plan.remote_id,
            digest=plan.digest,
        )
        self._records.append(record)
        self._repository_upstream.setdefault(plan.repository, plan.upstream)
        self._pairs.add((plan.repository, plan.remote_id))
        return record, dependency
