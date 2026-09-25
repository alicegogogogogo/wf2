"""On-the-fly, component-level correlation of SBOM components with alerts.

The view pairs each component recorded in a resource's SBOM with the
security alerts registered against that same resource. Matching is a
verbatim, case-sensitive string equality between the alert component
name and the SBOM component name: no normalization, no whitespace
trimming, no fuzzy matching and no version or digest comparison.

Components are emitted in SBOM submission order; a component without a
matching alert is still emitted with an empty ``advisories`` list. Each
component's advisories keep the resource alerts' registration order and
are neither deduplicated nor merged. Like the risk score, this view is
computed at request time and is never materialized as a record.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .sbom import SbomComponent
    from .vulnerabilities import Vulnerability


def build_component_risks(
    components: tuple[SbomComponent, ...], alerts: list[Vulnerability]
) -> list[dict[str, object]]:
    """Return one risk view per SBOM component.

    ``components`` are the SBOM components in submission order; ``alerts``
    are the resource's vulnerability alerts in registration order. An
    alert matches a component only when its component name equals the
    SBOM component name character for character (case-sensitive, with no
    trimming); version and digest never participate in the match.
    """

    result: list[dict[str, object]] = []
    for component in components:
        advisories = [
            {"id": alert.id, "severity": alert.severity}
            for alert in alerts
            if alert.component == component.name
        ]
        result.append(
            {
                "name": component.name,
                "version": component.version,
                "digest": component.digest,
                "advisories": advisories,
            }
        )
    return result
