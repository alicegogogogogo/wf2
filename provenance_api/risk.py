"""On-the-fly risk scoring for registered resources.

The risk score is computed at request time from the resource's recorded
vulnerability alerts, its SBOM / license / provenance / signature
evidence, its lifecycle state and its admission policy's license
allowlist. Nothing is
persisted: the score is never materialized as a record, and a restart
clears every input just like the rest of the in-process state.
"""

from __future__ import annotations

#: Points added per recorded alert, keyed by severity level. Severity
#: comparison is case-insensitive.
SEVERITY_POINTS: dict[str, int] = {
    "critical": 40,
    "high": 25,
    "medium": 10,
    "low": 5,
}

#: Points added for each missing evidence item (SBOM, license,
#: provenance, signature). A registered signature record counts as
#: present whether or not it would verify.
MISSING_EVIDENCE_POINTS = 5

#: Points added when the resource is withdrawn or quarantined.
BLOCKED_STATE_POINTS = 20

#: Points added when a non-empty license allowlist does not cover the
#: resource's declared license (or no license is declared at all).
LICENSE_DENIED_POINTS = 10

#: The total score is capped at this value.
MAX_SCORE = 100

#: Blocking lifecycle states, mirroring the lifecycle module's set.
BLOCKING_STATES = frozenset({"withdrawn", "quarantined"})

#: Score thresholds for the four risk levels, from lowest to highest.
LEVELS: tuple[str, ...] = ("low", "medium", "high", "critical")


def risk_level(score: int) -> str:
    """Map a capped score to its level: below 25 ``low``, below 50
    ``medium``, below 75 ``high``, otherwise ``critical``."""

    if score < 25:
        return "low"
    if score < 50:
        return "medium"
    if score < 75:
        return "high"
    return "critical"


def compute_risk_score(
    *,
    severities: list[str],
    has_sbom: bool,
    has_license: bool,
    has_provenance: bool,
    has_signature: bool,
    lifecycle_state: str,
    license_allowlist: tuple[str, ...] | list[str],
    license_spdx_id: str | None,
) -> int:
    """Compute the capped 0-100 risk score for one resource.

    ``severities`` are the severity levels of every alert recorded against
    the resource (matched case-insensitively); ``license_allowlist`` is the
    resource policy's allowlist (empty when no policy is registered or the
    policy imposes no license restriction).
    """

    score = 0
    for severity in severities:
        score += SEVERITY_POINTS[severity.lower()]

    for present in (has_sbom, has_license, has_provenance, has_signature):
        if not present:
            score += MISSING_EVIDENCE_POINTS

    if lifecycle_state in BLOCKING_STATES:
        score += BLOCKED_STATE_POINTS

    if license_allowlist and license_spdx_id not in license_allowlist:
        score += LICENSE_DENIED_POINTS

    return min(score, MAX_SCORE)
