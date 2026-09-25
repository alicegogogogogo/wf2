"""Process-local signature policies for registered image mirrors.

Each mirror keeps at most one signature policy. A policy names the HMAC
``algorithm`` pull signatures must use, the non-empty set of trusted
``keys`` (key identifiers) and whether ``cover_digest`` requires the
signed digest to cover the pulled layer digest. Nothing here is
persisted: stopping or restarting the service clears every policy.

Pull verification recomputes the signature with the existing content
signature convention: the key is the UTF-8 byte sequence of the key
identifier and the signed message is the lowercase signed-digest text.
"""

from __future__ import annotations

import hmac
import re
from dataclasses import dataclass

from .signatures import compute_signature

#: The two supported HMAC algorithms; comparison is case-sensitive.
ALGORITHMS: tuple[str, ...] = ("hmac-sha256", "hmac-sha512")

#: Hexadecimal output length of each supported algorithm, used to
#: validate the ``X-Signature`` pull header.
_SIGNATURE_HEX_LENGTHS = {"hmac-sha256": 64, "hmac-sha512": 128}
_SIGNATURE_HEX_PATTERNS = {
    algorithm: re.compile(r"[0-9a-fA-F]{%d}" % length)
    for algorithm, length in _SIGNATURE_HEX_LENGTHS.items()
}

#: A signed digest is exactly 64 hexadecimal characters; mixed case is
#: accepted but the comparison always uses the lowercase form.
_DIGEST_PATTERN = re.compile(r"[0-9a-fA-F]{64}")

#: Fields accepted by the registration request; anything else is rejected.
_ALLOWED_FIELDS = frozenset({"algorithm", "keys", "cover_digest"})
_REQUIRED_FIELDS = ("algorithm", "keys", "cover_digest")


class MirrorPolicyValidationError(ValueError):
    """A mirror signature policy payload failed field-level validation."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class MirrorPolicyError(ValueError):
    """A mirror signature policy operation could not proceed.

    ``code`` is the stable, client-facing error code.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class MirrorSignaturePolicy:
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


def build_mirror_policy_fields(payload: object) -> tuple[str, tuple[str, ...], bool]:
    """Validate a decoded policy payload and return normalized values.

    Returns ``(algorithm, keys, cover_digest)``. The algorithm is
    case-sensitive, the keys keep their submission order and the digest
    coverage flag must be a JSON boolean.
    """

    if not isinstance(payload, dict):
        raise MirrorPolicyValidationError("Request body must be a JSON object.")

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
    seen_keys: set[str] = set()
    for item in raw_keys:
        if not isinstance(item, str) or not item:
            raise MirrorPolicyValidationError(
                "Field 'keys' must only contain non-empty strings."
            )
        if item in seen_keys:
            raise MirrorPolicyValidationError(
                "Field 'keys' must not repeat a value."
            )
        seen_keys.add(item)
        keys.append(item)

    cover_digest = payload["cover_digest"]
    if not isinstance(cover_digest, bool):
        raise MirrorPolicyValidationError(
            "Field 'cover_digest' must be a boolean."
        )

    return algorithm, tuple(keys), cover_digest


def check_pull_signature(
    policy: MirrorSignaturePolicy,
    key_id: str | None,
    signature: str | None,
    signed_digest: str | None,
    digest: str,
) -> tuple[str, str, str] | None:
    """Check the pull signature headers against ``policy``.

    ``key_id``, ``signature`` and ``signed_digest`` are the raw header
    values, or ``None`` when the corresponding header is absent.
    ``digest`` is the verified lowercase layer digest. Returns ``None``
    when the pull may proceed, otherwise a ``(status, code, message)``
    triple describing the single failure. The checks fire in a fixed
    order — missing headers, header shape, key trust, digest coverage,
    signature — and stop at the first hit.
    """

    if key_id is None or signature is None or signed_digest is None:
        return (
            "403 Forbidden",
            "signature_missing",
            "The X-Key-Id, X-Signature and X-Signed-Digest headers are "
            "required.",
        )

    if not key_id:
        return (
            "400 Bad Request",
            "invalid_request",
            "X-Key-Id header must not be empty.",
        )
    if _DIGEST_PATTERN.fullmatch(signed_digest) is None:
        return (
            "400 Bad Request",
            "invalid_request",
            "X-Signed-Digest header must be a 64-character hexadecimal "
            "string.",
        )
    if _SIGNATURE_HEX_PATTERNS[policy.algorithm].fullmatch(signature) is None:
        expected_length = _SIGNATURE_HEX_LENGTHS[policy.algorithm]
        return (
            "400 Bad Request",
            "invalid_request",
            f"X-Signature header must be a {expected_length}-character "
            "hexadecimal string matching the policy algorithm.",
        )

    if key_id not in policy.keys:
        return (
            "403 Forbidden",
            "key_not_trusted",
            "The key id is not trusted by the mirror signature policy.",
        )

    normalized_digest = signed_digest.lower()
    if policy.cover_digest and normalized_digest != digest:
        return (
            "403 Forbidden",
            "digest_uncovered",
            "The signed digest does not cover the pulled layer digest.",
        )

    expected = compute_signature(policy.algorithm, key_id, normalized_digest)
    if not hmac.compare_digest(expected, signature.lower()):
        return (
            "403 Forbidden",
            "signature_invalid",
            "The signature does not match the recomputed value.",
        )

    return None


class MirrorSignaturePolicyStore:
    """Process-local storage of at most one signature policy per mirror."""

    def __init__(self) -> None:
        self._records: dict[str, MirrorSignaturePolicy] = {}

    def reset(self) -> None:
        self._records = {}

    def add(
        self, mirror_id: str, payload: object
    ) -> tuple[MirrorSignaturePolicy, bool]:
        """Validate and record the signature policy for ``mirror_id``.

        Returns ``(policy, created)`` where ``created`` is ``True`` for a
        first registration (HTTP 201) and ``False`` for an idempotent
        resubmission of the exact same content (HTTP 200). A different
        policy raises :class:`MirrorPolicyError` with code
        ``mirror_policy_conflict`` and the stored record is never
        overwritten.
        """

        algorithm, keys, cover_digest = build_mirror_policy_fields(payload)
        record = MirrorSignaturePolicy(
            algorithm=algorithm, keys=keys, cover_digest=cover_digest
        )

        existing = self._records.get(mirror_id)
        if existing is not None:
            if existing == record:
                return existing, False
            raise MirrorPolicyError(
                "mirror_policy_conflict",
                "A different signature policy is already registered for "
                "this mirror.",
            )

        self._records[mirror_id] = record
        return record, True

    def get(self, mirror_id: str) -> MirrorSignaturePolicy | None:
        return self._records.get(mirror_id)
