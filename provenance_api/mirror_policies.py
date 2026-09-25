"""Process-local signature policies for registered image mirrors.

Each mirror keeps at most one signature policy naming the HMAC algorithm,
the trusted key identifiers and whether the signature must cover the layer
digest. Policies live only in process memory: a restart clears every
record, and pull-time verification is always recomputed from the request
headers against the stored policy.
"""

from __future__ import annotations

from dataclasses import dataclass

#: The two supported HMAC algorithms; matching is case-sensitive.
ALGORITHMS: tuple[str, ...] = ("hmac-sha256", "hmac-sha512")

#: Fields accepted by the registration request; anything else is rejected.
_ALLOWED_FIELDS = frozenset({"algorithm", "keys", "cover_digest"})
_REQUIRED_FIELDS = ("algorithm", "keys", "cover_digest")


class MirrorPolicyValidationError(ValueError):
    """A signature policy payload failed field-level validation."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class MirrorPolicyError(ValueError):
    """A signature policy operation could not proceed.

    ``code`` is the stable, client-facing error code.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class MirrorPolicy:
    """The single signature policy stored for a mirror."""

    algorithm: str
    keys: tuple[str, ...]
    cover_digest: bool

    def to_dict(self, mirror_id: str) -> dict[str, object]:
        return {
            "id": mirror_id,
            "algorithm": self.algorithm,
            "keys": list(self.keys),
            "cover_digest": self.cover_digest,
        }


def build_mirror_policy_fields(
    payload: object,
) -> tuple[str, tuple[str, ...], bool]:
    """Validate a decoded policy payload and return normalized values.

    Returns ``(algorithm, keys, cover_digest)``. The key list keeps its
    submitted order and is stored verbatim; it must be a non-empty array
    of distinct non-empty strings.
    """

    if not isinstance(payload, dict):
        raise MirrorPolicyValidationError(
            "Request body must be a JSON object."
        )

    unknown_fields = set(payload) - _ALLOWED_FIELDS
    if unknown_fields:
        raise MirrorPolicyValidationError(
            f"Unknown field: {sorted(unknown_fields)[0]!r}."
        )

    for field in _REQUIRED_FIELDS:
        if field not in payload:
            raise MirrorPolicyValidationError(
                f"Missing required field: {field!r}."
            )

    algorithm = payload["algorithm"]
    if not isinstance(algorithm, str) or algorithm not in ALGORITHMS:
        allowed = ", ".join(ALGORITHMS)
        raise MirrorPolicyValidationError(
            f"Field 'algorithm' must be one of: {allowed} (case-sensitive)."
        )

    raw_keys = payload["keys"]
    if not isinstance(raw_keys, list):
        raise MirrorPolicyValidationError("Field 'keys' must be an array.")
    if not raw_keys:
        raise MirrorPolicyValidationError("Field 'keys' must not be empty.")
    keys: list[str] = []
    for element in raw_keys:
        if not isinstance(element, str):
            raise MirrorPolicyValidationError(
                "Field 'keys' elements must be strings."
            )
        if not element:
            raise MirrorPolicyValidationError(
                "Field 'keys' elements must not be empty."
            )
        if element in keys:
            raise MirrorPolicyValidationError(
                "Field 'keys' elements must not repeat."
            )
        keys.append(element)

    cover_digest = payload["cover_digest"]
    if not isinstance(cover_digest, bool):
        raise MirrorPolicyValidationError(
            "Field 'cover_digest' must be a boolean."
        )

    return algorithm, tuple(keys), cover_digest


class MirrorPolicyStore:
    """Process-local storage of at most one signature policy per mirror."""

    def __init__(self) -> None:
        self._policies: dict[str, MirrorPolicy] = {}

    def reset(self) -> None:
        self._policies = {}

    def get(self, mirror_id: str) -> MirrorPolicy | None:
        return self._policies.get(mirror_id)

    def remove(self, mirror_id: str) -> MirrorPolicy | None:
        """Remove and return the policy for ``mirror_id``, else ``None``.

        A missing or already removed policy changes nothing.
        """

        return self._policies.pop(mirror_id, None)

    def add(
        self, mirror_id: str, payload: object
    ) -> tuple[MirrorPolicy, bool]:
        """Validate and record the signature policy for ``mirror_id``.

        Returns ``(policy, created)`` where ``created`` is ``True`` for a
        first registration (HTTP 201) and ``False`` for an idempotent
        repeat of the exact same content (HTTP 200).

        Raises :class:`MirrorPolicyValidationError` for an invalid payload
        or :class:`MirrorPolicyError` with code ``mirror_policy_conflict``
        when a different policy is already stored; the stored policy is
        never overwritten.
        """

        algorithm, keys, cover_digest = build_mirror_policy_fields(payload)
        policy = MirrorPolicy(
            algorithm=algorithm, keys=keys, cover_digest=cover_digest
        )

        existing = self._policies.get(mirror_id)
        if existing is not None:
            if existing == policy:
                return existing, False
            raise MirrorPolicyError(
                "mirror_policy_conflict",
                "A different signature policy is already registered for "
                "this mirror.",
            )

        self._policies[mirror_id] = policy
        return policy, True
