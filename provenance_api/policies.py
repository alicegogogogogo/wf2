"""In-process admission policies and admission evaluation for resources.

Each resource keeps at most one policy. A policy names a non-empty policy
name, the evidence it requires (a build provenance record, an SBOM document
and/or a license declaration), an allowlist of SPDX license identifiers
(which may be empty) and a maximum vulnerability severity; anything more
severe than the cap blocks admission. Policies, like every other record,
live only in process memory: stopping or restarting the service clears
them, no files are written, signatures are not verified and promotion
rules are unaffected.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from .lifecycle import BLOCKING_STATES

#: The evidence kinds a policy may require; the values are case-sensitive
#: and match the ``no_sbom``/``no_license``/``no_provenance`` reason codes.
EVIDENCE_TYPES: tuple[str, ...] = ("provenance", "sbom", "license")
EVIDENCE_VALUES = frozenset(EVIDENCE_TYPES)

#: The four public severity levels, ordered from most to least severe. The
#: cap is matched case-insensitively and stored in lowercase.
SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low")
SEVERITY_VALUES = frozenset(SEVERITIES)
SEVERITY_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}

#: The policy name is non-empty and bounded by 256 Unicode code points.
MAX_NAME_LENGTH = 256

#: Fields accepted by the registration request; anything else is rejected.
#: The SPDX list answers to two documented spellings; exactly one may be
#: present, and the accepted spelling is echoed back unchanged.
LICENSE_KEY = "allowed_licenses"
LICENSE_KEY_ALIAS = "license_allowlist"
LICENSE_KEYS = (LICENSE_KEY, LICENSE_KEY_ALIAS)
_ALLOWED_FIELDS = frozenset(
    {"name", "evidence_requirements", "max_severity", *LICENSE_KEYS}
)

#: Admission reason codes, in the fixed reporting order.
STATE_BLOCKED = "state_blocked"
LICENSE_DENIED = "license_denied"
SEVERITY_EXCEEDED = "severity_exceeded"
_EVIDENCE_REASONS = (
    ("sbom", "no_sbom"),
    ("license", "no_license"),
    ("provenance", "no_provenance"),
)


class PolicyValidationError(ValueError):
    """A policy payload failed field-level validation."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class PolicyError(ValueError):
    """A policy operation could not proceed.

    ``code`` is the stable, client-facing error code.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class PolicyRecord:
    """The single admission policy stored for a resource."""

    name: str
    evidence_requirements: tuple[str, ...]
    allowed_licenses: tuple[str, ...]
    max_severity: str
    license_key: str = LICENSE_KEY

    def to_dict(self, resource_id: str) -> dict[str, object]:
        return {
            "id": resource_id,
            "name": self.name,
            "evidence_requirements": list(self.evidence_requirements),
            self.license_key: list(self.allowed_licenses),
            "max_severity": self.max_severity,
        }


def build_policy_fields(
    payload: object,
) -> tuple[str, tuple[str, ...], tuple[str, ...], str, str]:
    """Validate a decoded policy payload and return normalized values.

    Returns ``(name, evidence_requirements, allowed_licenses,
    max_severity, license_key)``. Evidence kinds and SPDX identifiers keep
    their submitted order; the severity cap is normalized to lowercase.
    The SPDX list spelling (``allowed_licenses`` or ``license_allowlist``)
    is detected and returned so the response can echo it unchanged.
    """

    if not isinstance(payload, dict):
        raise PolicyValidationError("Request body must be a JSON object.")

    unknown_fields = set(payload) - _ALLOWED_FIELDS
    if unknown_fields:
        raise PolicyValidationError(
            f"Unknown field: {sorted(unknown_fields)[0]!r}."
        )

    for field in ("name", "evidence_requirements", "max_severity"):
        if field not in payload:
            raise PolicyValidationError(
                f"Missing required field: {field!r}."
            )
    present_license_keys = [key for key in LICENSE_KEYS if key in payload]
    if not present_license_keys:
        raise PolicyValidationError(
            f"Missing required field: {LICENSE_KEY!r}."
        )
    if len(present_license_keys) > 1:
        raise PolicyValidationError(
            "The SPDX license list must be given under a single field name."
        )
    license_key = present_license_keys[0]

    name = payload["name"]
    if not isinstance(name, str):
        raise PolicyValidationError("Field 'name' must be a string.")
    if not name:
        raise PolicyValidationError("Field 'name' must not be empty.")
    if len(name) > MAX_NAME_LENGTH:
        raise PolicyValidationError(
            f"Name must not exceed {MAX_NAME_LENGTH} Unicode code points."
        )

    raw_evidence = payload["evidence_requirements"]
    if not isinstance(raw_evidence, list):
        raise PolicyValidationError(
            "Field 'evidence_requirements' must be an array."
        )
    evidence: list[str] = []
    seen_evidence: set[str] = set()
    for item in raw_evidence:
        if not isinstance(item, str) or item not in EVIDENCE_VALUES:
            raise PolicyValidationError(
                "Each evidence requirement must be one of: provenance, "
                "sbom, license."
            )
        if item in seen_evidence:
            raise PolicyValidationError(
                "An evidence requirement is listed more than once."
            )
        seen_evidence.add(item)
        evidence.append(item)

    raw_licenses = payload[license_key]
    if not isinstance(raw_licenses, list):
        raise PolicyValidationError(
            f"Field {license_key!r} must be an array."
        )
    licenses: list[str] = []
    seen_licenses: set[str] = set()
    for item in raw_licenses:
        if not isinstance(item, str) or not item:
            raise PolicyValidationError(
                "Each allowed license must be a non-empty SPDX identifier."
            )
        if item in seen_licenses:
            raise PolicyValidationError(
                "An SPDX identifier is listed more than once."
            )
        seen_licenses.add(item)
        licenses.append(item)

    raw_cap = payload["max_severity"]
    if not isinstance(raw_cap, str) or not raw_cap:
        raise PolicyValidationError(
            "Field 'max_severity' must be one of: critical, high, medium, "
            "low (case-insensitive)."
        )
    max_severity = raw_cap.lower()
    if max_severity not in SEVERITY_VALUES:
        raise PolicyValidationError(
            "Field 'max_severity' must be one of: critical, high, medium, "
            "low (case-insensitive)."
        )

    return (
        name,
        tuple(evidence),
        tuple(licenses),
        max_severity,
        license_key,
    )


def evaluate_admission(
    policy: PolicyRecord,
    *,
    state: str,
    has_sbom: bool,
    has_license: bool,
    spdx_id: str | None,
    has_provenance: bool,
    severities: Iterable[str],
) -> list[str]:
    """Run the single read-only admission decision for a resource.

    Returns the matched reason codes in the fixed order (state, evidence,
    license, severity). A withdrawn or quarantined resource is rejected
    immediately with ``state_blocked`` and no further checks run. An empty
    list means admission is allowed.
    """

    if state in BLOCKING_STATES:
        return [STATE_BLOCKED]

    reasons: list[str] = []

    available = {
        "sbom": has_sbom,
        "license": has_license,
        "provenance": has_provenance,
    }
    required = set(policy.evidence_requirements)
    for kind, code in _EVIDENCE_REASONS:
        if kind in required and not available[kind]:
            reasons.append(code)

    if policy.allowed_licenses and (
        spdx_id is None or spdx_id not in policy.allowed_licenses
    ):
        reasons.append(LICENSE_DENIED)

    cap = SEVERITY_RANK[policy.max_severity]
    for severity in severities:
        if SEVERITY_RANK[severity] > cap:
            reasons.append(SEVERITY_EXCEEDED)
            break

    return reasons


class PolicyStore:
    """Process-local storage of at most one admission policy per resource."""

    def __init__(self) -> None:
        self._records: dict[str, PolicyRecord] = {}

    def reset(self) -> None:
        self._records = {}

    def add(
        self, resource_id: str, payload: object
    ) -> tuple[PolicyRecord, bool]:
        """Validate and record the policy for ``resource_id``.

        Returns ``(record, created)`` where ``created`` is ``True`` for a
        first registration (HTTP 201) and ``False`` for a resubmission of
        the same normalized content (HTTP 200). Different content raises
        :class:`PolicyError` with code ``policy_conflict``; the stored
        record is never overwritten.
        """

        name, evidence, licenses, max_severity, license_key = (
            build_policy_fields(payload)
        )
        record = PolicyRecord(
            name=name,
            evidence_requirements=evidence,
            allowed_licenses=licenses,
            max_severity=max_severity,
            license_key=license_key,
        )

        existing = self._records.get(resource_id)
        if existing is not None:
            # Normalized content equality ignores the SPDX list spelling,
            # so a repeat under either key is idempotent and the stored
            # record (and its wire key) is echoed unchanged.
            if (
                existing.name == record.name
                and existing.evidence_requirements == record.evidence_requirements
                and existing.allowed_licenses == record.allowed_licenses
                and existing.max_severity == record.max_severity
            ):
                return existing, False
            raise PolicyError(
                "policy_conflict",
                "A different admission policy is already registered for "
                "this resource.",
            )

        self._records[resource_id] = record
        return record, True

    def get(self, resource_id: str) -> PolicyRecord | None:
        return self._records.get(resource_id)
