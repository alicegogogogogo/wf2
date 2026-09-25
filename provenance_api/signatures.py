"""In-process content signature records for registered resources.

Each resource keeps at most one signature record: who signed, the HMAC
algorithm, the key identifier, the signature value and the digest that was
signed. Digests and signature values are normalized to lowercase. Nothing
here is persisted: stopping or restarting the service clears every record.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass

#: A digest is exactly 64 hexadecimal characters; mixed case is accepted
#: but the digest is always stored and rendered in lowercase.
_DIGEST_PATTERN = re.compile(r"[0-9a-fA-F]{64}")

#: A signature value is hexadecimal; the expected length depends on the
#: algorithm (64 characters for HMAC-SHA256, 128 for HMAC-SHA512).
_HEX_PATTERN = re.compile(r"[0-9a-fA-F]+")

#: Text fields are non-empty and bounded by 256 Unicode code points.
MAX_TEXT_LENGTH = 256

#: The only signature algorithms accepted by the service.
ALGORITHMS: tuple[str, ...] = ("hmac-sha256", "hmac-sha512")
_ALGORITHM_VALUES = frozenset(ALGORITHMS)

#: Hexadecimal signature length per algorithm.
_SIGNATURE_LENGTHS = {"hmac-sha256": 64, "hmac-sha512": 128}

#: Fields accepted by the registration request; anything else is rejected.
_ALLOWED_FIELDS = frozenset(
    {"signer", "algorithm", "key_id", "signature", "digest"}
)
_REQUIRED_FIELDS = ("signer", "algorithm", "key_id", "signature", "digest")


class SignatureValidationError(ValueError):
    """A signature payload failed field-level validation."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class SignatureError(ValueError):
    """A signature operation could not proceed.

    ``code`` is the stable, client-facing error code.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class SignatureRecord:
    """The single signature record stored for a resource."""

    signer: str
    algorithm: str
    key_id: str
    signature: str
    digest: str

    def to_dict(self, resource_id: str) -> dict[str, object]:
        return {
            "id": resource_id,
            "signer": self.signer,
            "algorithm": self.algorithm,
            "key_id": self.key_id,
            "signature": self.signature,
            "digest": self.digest,
        }


def compute_signature(algorithm: str, key_id: str, digest: str) -> str:
    """Recompute the expected signature for a record.

    The signature is the hexadecimal HMAC of the lowercase digest text,
    keyed with the UTF-8 bytes of ``key_id``; the hash is SHA-256 for
    ``hmac-sha256`` and SHA-512 for ``hmac-sha512``.
    """

    digestmod = hashlib.sha256 if algorithm == "hmac-sha256" else hashlib.sha512
    return hmac.new(
        key_id.encode("utf-8"), digest.encode("ascii"), digestmod
    ).hexdigest()


def _required_text(value: object, label: str) -> str:
    """Validate a required non-empty string of at most 256 code points."""

    if not isinstance(value, str):
        raise SignatureValidationError(f"{label} must be a string.")
    if not value:
        raise SignatureValidationError(f"{label} must not be empty.")
    if len(value) > MAX_TEXT_LENGTH:
        raise SignatureValidationError(
            f"{label} must not exceed {MAX_TEXT_LENGTH} Unicode code points."
        )
    return value


def build_signature_fields(payload: object) -> SignatureRecord:
    """Validate a decoded signature payload and return the normalized record.

    The digest and signature are normalized to lowercase; the signature
    length must match the declared algorithm.
    """

    if not isinstance(payload, dict):
        raise SignatureValidationError("Request body must be a JSON object.")

    unknown_fields = set(payload) - _ALLOWED_FIELDS
    if unknown_fields:
        raise SignatureValidationError(
            f"Unknown field: {sorted(unknown_fields)[0]!r}."
        )

    for field in _REQUIRED_FIELDS:
        if field not in payload:
            raise SignatureValidationError(
                f"Missing required field: {field!r}."
            )

    signer = _required_text(payload["signer"], "Field 'signer'")

    algorithm = payload["algorithm"]
    if not isinstance(algorithm, str) or algorithm not in _ALGORITHM_VALUES:
        allowed = ", ".join(ALGORITHMS)
        raise SignatureValidationError(
            f"Field 'algorithm' must be one of: {allowed} (case-sensitive)."
        )

    key_id = _required_text(payload["key_id"], "Field 'key_id'")

    signature_raw = payload["signature"]
    expected_length = _SIGNATURE_LENGTHS[algorithm]
    if (
        not isinstance(signature_raw, str)
        or len(signature_raw) != expected_length
        or _HEX_PATTERN.fullmatch(signature_raw) is None
    ):
        raise SignatureValidationError(
            f"Field 'signature' must be a {expected_length}-character "
            f"hexadecimal string for {algorithm}."
        )
    signature = signature_raw.lower()

    digest_raw = payload["digest"]
    if not isinstance(digest_raw, str) or _DIGEST_PATTERN.fullmatch(
        digest_raw
    ) is None:
        raise SignatureValidationError(
            "Field 'digest' must be a 64-character hexadecimal string."
        )
    digest = digest_raw.lower()

    return SignatureRecord(
        signer=signer,
        algorithm=algorithm,
        key_id=key_id,
        signature=signature,
        digest=digest,
    )


class SignatureStore:
    """Process-local storage of at most one signature record per resource."""

    def __init__(self) -> None:
        self._records: dict[str, SignatureRecord] = {}

    def reset(self) -> None:
        self._records = {}

    def add(
        self, resource_id: str, payload: object
    ) -> tuple[SignatureRecord, bool]:
        """Validate and record the signature for ``resource_id``.

        Returns ``(record, created)`` where ``created`` is ``True`` for a
        first registration (HTTP 201) and ``False`` for an idempotent repeat
        of the exact same normalized content (HTTP 200).

        Raises :class:`SignatureValidationError` for an invalid payload or
        :class:`SignatureError` with code ``signature_conflict`` when a
        different record is already stored; the stored record is never
        overwritten.
        """

        record = build_signature_fields(payload)

        existing = self._records.get(resource_id)
        if existing is not None:
            if existing == record:
                return existing, False
            raise SignatureError(
                "signature_conflict",
                "A different signature record is already registered for "
                "this resource.",
            )

        self._records[resource_id] = record
        return record, True

    def get(self, resource_id: str) -> SignatureRecord | None:
        return self._records.get(resource_id)
