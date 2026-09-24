"""On-demand risk scoring for registered resources.

A risk score is computed afresh from the resource's current security
alerts, recorded evidence, lifecycle state and (optionally) admission
policy. No score is ever stored.

Scoring rules:

* each security alert contributes 40/25/10/5 points for
  critical/high/medium/low severity (case-insensitive comparison);
* each missing piece of evidence (SBOM, license, build provenance)
  contributes 5 points;
* a withdrawn or quarantined lifecycle state contributes 20 points;
* when the policy's license allowlist is non-empty, a missing license
  or one outside the allowlist contributes 10 points;
* the total is capped at 100.

Levels are fixed bands: below 25 is ``low``, below 50 is ``medium``,
below 75 is ``high`` and anything else is ``critical``.
"""

from __future__ import annotations

#: Points contributed by an alert at each severity, most severe first.
_SEVERITY_POINTS = {
    "critical": 40,
    "high": 25,
    "medium": 10,
    "low": 5,
}

#: Points contributed per missing piece of evidence.
MISSING_EVIDENCE_POINTS = 5

#: Points contributed by a withdrawn or quarantined lifecycle state.
BLOCKED_STATE_POINTS = 20

#: Points contributed when a non-empty allowlist denies the license.
LICENSE_DENIED_POINTS = 10

#: Inclusive maximum score.
MAX_SCORE = 100


def _level_for(score: int) -> str:
    if score < 25:
        return "low"
    if score < 50:
        return "medium"
    if score < 75:
        return "high"
    return "critical"


def calculate_score(
    *,
    severities: list[str] | tuple[str, ...],
    has_sbom: bool,
    has_license: bool,
    has_provenance: bool,
    lifecycle_state: str,
    license_spdx_id: str | None = None,
    license_allowlist: list[str] | tuple[str, ...] | None = None,
) -> int:
    """Compute the capped integer risk score for one resource.

    ``severities`` are the stored lowercase severity levels of every
    alert recorded against the resource; comparison is case-insensitive.
    ``license_allowlist`` is the policy allowlist (``None`` or empty
    means no license restriction); when non-empty, a missing license or
    an identifier absent from it is a policy breach.
    """

    score = 0
    for severity in severities:
        score += _SEVERITY_POINTS[severity.lower()]

    if not has_sbom:
        score += MISSING_EVIDENCE_POINTS
    if not has_license:
        score += MISSING_EVIDENCE_POINTS
    if not has_provenance:
        score += MISSING_EVIDENCE_POINTS

    if lifecycle_state in ("withdrawn", "quarantined"):
        score += BLOCKED_STATE_POINTS

    if license_allowlist and license_spdx_id not in license_allowlist:
        # A missing license already costs the evidence points; the
        # policy breach is an independent penalty.
        score += LICENSE_DENIED_POINTS

    return min(score, MAX_SCORE)


def risk_level(score: int) -> str:
    """Return the fixed band for a (already capped) score."""

    return _level_for(score)
