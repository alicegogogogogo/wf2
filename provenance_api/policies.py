"""In-process admission policies for registered resources.

Each resource keeps at most one policy. A policy names a non-empty
display name, the evidence it requires (``sbom``, ``license``,
``provenance`` and/or ``signature``), an allowlist of accepted SPDX
license identifiers (which may be empty) and the maximum accepted
vulnerability severity. Nothing here is persisted: stopping or
restarting the service clears every policy and every admission result;
no files are written.

Admission is a single read-only decision per resource. A resource in a
withdrawn or quarantined lifecycle state is denied with
``state_blocked`` before anything else is checked. Missing required
evidence contributes ``no_sbom``, ``no_license``, ``no_provenance`` or
``no_signature``; a registered signature record counts as present
evidence regardless of whether it would verify. A non-empty allowlist
that does not contain the resource's declared SPDX identifier
contributes ``license_denied``. Any recorded alert above the policy's
severity ceiling contributes ``severity_exceeded``. When several
groups fire, their codes are ordered as state, evidence, license and
then severity.
"""

from __future__ import annotations

from dataclasses import dataclass

#: The fixed set of evidence a policy may require; order also fixes the
#: stable order in which missing-evidence reason codes are reported.
EVIDENCE: tuple[str, ...] = ("sbom", "license", "provenance", "signature")
EVIDENCE_VALUES = frozenset(EVIDENCE)

#: The four public severity levels, from most to least severe. Severity
#: comparison is case-insensitive; the value is stored in lowercase.
SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low")
SEVERITY_VALUES = frozenset(SEVERITIES)
_SEVERITY_RANK = {severity: index for index, severity in enumerate(SEVERITIES)}

#: A policy name is non-empty and bounded by 256 Unicode code points.
MAX_NAME_LENGTH = 256

#: Fields accepted by the registration request; all four are required.
_ALLOWED_FIELDS = frozenset(
    {"name", "evidence_requirements", "license_allowlist", "max_severity"}
)
_REQUIRED_FIELDS = (
    "name",
    "evidence_requirements",
    "license_allowlist",
    "max_severity",
)

#: Evidence requirement key -> reason code reported when it is missing.
_EVIDENCE_REASON = {
    "provenance": "no_provenance",
    "sbom": "no_sbom",
    "license": "no_license",
    "signature": "no_signature",
}


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
    license_allowlist: tuple[str, ...]
    max_severity: str

    def to_dict(self, resource_id: str) -> dict[str, object]:
        return {
            "id": resource_id,
            "name": self.name,
            "evidence_requirements": list(self.evidence_requirements),
            "license_allowlist": list(self.license_allowlist),
            "max_severity": self.max_severity,
        }


def build_policy_fields(
    payload: object,
) -> tuple[str, tuple[str, ...], tuple[str, ...], str]:
    """Validate a decoded policy payload and return normalized values.

    Returns ``(name, evidence_requirements, license_allowlist,
    max_severity)``. Evidence and SPDX identifiers keep their submission
    order and must not repeat; the allowlist may be empty. The severity
    ceiling is normalized to lowercase.
    """

    if not isinstance(payload, dict):
        raise PolicyValidationError("Request body must be a JSON object.")

    unknown_fields = set(payload) - _ALLOWED_FIELDS
    if unknown_fields:
        raise PolicyValidationError(
            f"Unknown field: {sorted(unknown_fields)[0]!r}."
        )

    for field in _REQUIRED_FIELDS:
        if field not in payload:
            raise PolicyValidationError(
                f"Missing required field: {field!r}."
            )

    name = payload["name"]
    if not isinstance(name, str):
        raise PolicyValidationError("Field 'name' must be a string.")
    if not name:
        raise PolicyValidationError("Field 'name' must not be empty.")
    if len(name) > MAX_NAME_LENGTH:
        raise PolicyValidationError(
            f"Field 'name' must not exceed {MAX_NAME_LENGTH} Unicode code points."
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
                "Field 'evidence_requirements' must only contain: "
                "provenance, sbom, license, signature."
            )
        if item in seen_evidence:
            raise PolicyValidationError(
                "Field 'evidence_requirements' must not repeat a value."
            )
        seen_evidence.add(item)
        evidence.append(item)

    raw_allowlist = payload["license_allowlist"]
    if not isinstance(raw_allowlist, list):
        raise PolicyValidationError(
            "Field 'license_allowlist' must be an array."
        )
    allowlist: list[str] = []
    seen_license: set[str] = set()
    for item in raw_allowlist:
        if not isinstance(item, str) or not item:
            raise PolicyValidationError(
                "Field 'license_allowlist' must only contain non-empty "
                "SPDX identifier strings."
            )
        if item in seen_license:
            raise PolicyValidationError(
                "Field 'license_allowlist' must not repeat a value."
            )
        seen_license.add(item)
        allowlist.append(item)

    raw_severity = payload["max_severity"]
    if not isinstance(raw_severity, str) or not raw_severity:
        raise PolicyValidationError(
            "Field 'max_severity' must be one of: critical, high, medium, low."
        )
    max_severity = raw_severity.lower()
    if max_severity not in SEVERITY_VALUES:
        raise PolicyValidationError(
            "Field 'max_severity' must be one of: critical, high, medium, low."
        )

    return name, tuple(evidence), tuple(allowlist), max_severity


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
        first registration (HTTP 201) and ``False`` for an idempotent
        resubmission of the exact same content (HTTP 200). A different
        policy raises :class:`PolicyError` with code ``policy_conflict``
        and the stored record is never overwritten.
        """

        name, evidence, allowlist, max_severity = build_policy_fields(payload)
        record = PolicyRecord(
            name=name,
            evidence_requirements=evidence,
            license_allowlist=allowlist,
            max_severity=max_severity,
        )

        existing = self._records.get(resource_id)
        if existing is not None:
            if existing == record:
                return existing, False
            raise PolicyError(
                "policy_conflict",
                "A different policy is already registered for this resource.",
            )

        self._records[resource_id] = record
        return record, True

    def get(self, resource_id: str) -> PolicyRecord | None:
        return self._records.get(resource_id)


def evaluate_policy(
    policy: PolicyRecord,
    *,
    lifecycle_state: str,
    has_sbom: bool,
    has_license: bool,
    has_provenance: bool,
    has_signature: bool,
    license_spdx_id: str | None,
    severities: "list[str]",
) -> tuple[bool, list[str]]:
    """Run the read-only admission decision for one resource.

    Returns ``(allowed, reasons)``. A blocked lifecycle state short-
    circuits every other check. Otherwise missing evidence, a denied
    license and excessive severity are collected together and ordered
    as state, evidence (sbom, license, provenance, signature), license,
    severity.

    ``severities`` are the stored lowercase severity levels of every
    alert recorded against the resource; comparison against the ceiling
    is case-insensitive. ``has_signature`` only reflects whether a
    signature record is registered; verification never participates.
    """

    if lifecycle_state in ("withdrawn", "quarantined"):
        return False, ["state_blocked"]

    reasons: list[str] = []

    present = {
        "provenance": has_provenance,
        "sbom": has_sbom,
        "license": has_license,
        "signature": has_signature,
    }
    for item in EVIDENCE:
        if item in policy.evidence_requirements and not present[item]:
            reasons.append(_EVIDENCE_REASON[item])

    if policy.license_allowlist and license_spdx_id not in policy.license_allowlist:
        reasons.append("license_denied")

    ceiling = _SEVERITY_RANK[policy.max_severity]
    for severity in severities:
        if _SEVERITY_RANK[severity.lower()] < ceiling:
            reasons.append("severity_exceeded")
            break

    return not reasons, reasons
